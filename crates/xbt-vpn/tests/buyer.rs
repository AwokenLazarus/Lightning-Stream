//! The whole path on this machine, with no TUN device and no root: a phone (a client TCP/IP stack and
//! a WireGuard client in the test) → the buyer's WireGuard endpoint → the buyer's stack and router →
//! the iroh link → a seller's exit → a server. A download arrives whole and is metered at the device
//! and the exit; with no exit, nothing gets out (the kill switch); a device past its limit is cut off.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket as StdUdp};
use std::sync::Arc;
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use bytes::Bytes;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use xbt_iroh_link::{Hints, Link, Options, Relays, ALPN_VPN, ALPN_VPN_HOP, ALPN_VPN_SEALED};
use xbt_vpn::buyer::{Buyer, Device as BuyerDevice};
use xbt_vpn::exit::{serve_buyer, ExitConfig};
use xbt_vpn::hop::{serve_hop, serve_sealed, HopConfig, SealedBuyers};
use xbt_vpn::filter::Policy;
use xbt_vpn::meter::Meter;
use xbt_vpn::router::{ExitInfo, FirstHop, Mode, Requirements, Router};
use xbt_vpn::wg::{keypair, WgEndpoint, WgPeer};

fn lan_ip() -> IpAddr {
    let s = StdUdp::bind("0.0.0.0:0").unwrap();
    s.connect("192.0.2.1:9").unwrap();
    s.local_addr().unwrap().ip()
}

fn tcp_server(n: usize) -> SocketAddr {
    let l = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut c = c;
                let chunk = vec![0x5au8; 65536];
                let mut left = n;
                while left > 0 {
                    let k = left.min(chunk.len());
                    if std::io::Write::write_all(&mut c, &chunk[..k]).is_err() {
                        return;
                    }
                    left -= k;
                }
            });
        }
    });
    SocketAddr::new(lan_ip(), port)
}

#[derive(Default)]
struct Queue {
    rx: std::collections::VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
}
struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut Vec<Vec<u8>>);
impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut b = vec![0u8; len];
        let r = f(&mut b);
        self.0.push(b);
        r
    }
}
impl Device for Queue {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: SInstant) -> Option<(Rx, Tx<'_>)> {
        let p = self.rx.pop_front()?;
        Some((Rx(p), Tx(&mut self.tx)))
    }
    fn transmit(&mut self, _: SInstant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = 1280;
        c
    }
}

const PHONE_IP: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 2);

struct Setup {
    _links: Vec<Arc<Link>>,
    exit_id: Option<String>,
    buyer: Arc<Buyer>,
    exit_meter: Arc<Meter>,
    wg_addr: SocketAddr,
    endpoint_public: [u8; 32],
    phone_private: [u8; 32],
    rt: tokio::runtime::Handle,
}

/// An exit (or none), the buyer's link, router, stack and WireGuard endpoint with one phone.
fn setup(seed: u8, with_exit: bool, phone_limit: Option<u64>) -> Setup {
    setup_with(seed, with_exit, phone_limit, None)
}

fn setup_with(seed: u8, with_exit: bool, phone_limit: Option<u64>, requirements: Option<Requirements>) -> Setup {
    let opts = |serving| Options { relays: Relays::None, serving, private: false, lookup: None };
    let mut links = Vec::new();
    let exit_meter = Arc::new(Meter::default());
    let buyer_link = Link::start_alpn([seed + 1; 32], opts(false), ALPN_VPN).unwrap();
    let mut router = Router::new(Mode::Best, None);
    let mut exit_id = None;
    if with_exit {
        let exit = Link::start_alpn([seed; 32], opts(true), ALPN_VPN).unwrap();
        let cfg = Arc::new(ExitConfig { policy: Policy { allow_non_public: true, ..Policy::default() }, ..ExitConfig::default() });
        let m = exit_meter.clone();
        exit.accept_with(move |conn| serve_buyer(conn, cfg.clone(), m.clone()));
        let id = exit.endpoint_id();
        let direct = exit.hints(Duration::from_secs(1)).direct.into_iter().filter(|a| a.is_ipv4()).collect();
        buyer_link.learn(&id, Hints { relays: vec![], direct }).unwrap();
        exit_id = Some(id.clone());
        router.upsert(ExitInfo { id, region: "XX".into(), price_msat_per_gb: 2000, rtt_ms: None, mbit_s: None, healthy: true, ..ExitInfo::default() });
        links.push(exit);
    }
    let (phone_private, phone_public) = keypair();
    let (endpoint_private, endpoint_public) = keypair();
    let dev = Arc::new(BuyerDevice { name: "phone".into(), meter: Meter::default(), limit_bytes: phone_limit, requirements });
    let buyer = Buyer::new(buyer_link.clone(), router, HashMap::from([(IpAddr::V4(PHONE_IP), dev)]), None);
    let wg = WgEndpoint::new(endpoint_private, &[WgPeer { public: phone_public, tunnel_ip: PHONE_IP }]);
    let rt = buyer_link.runtime();
    let (to_stack, from_devices) = mpsc::channel::<Bytes>(4096);
    let (to_devices, from_stack) = mpsc::unbounded_channel::<Bytes>();
    let sock = rt.block_on(UdpSocket::bind("127.0.0.1:0")).unwrap();
    let wg_addr = sock.local_addr().unwrap();
    rt.spawn(buyer.clone().run(from_devices, to_devices));
    rt.spawn(wg.run(sock, to_stack, from_stack));
    links.push(buyer_link);
    Setup { _links: links, exit_id, buyer, exit_meter, wg_addr, endpoint_public, phone_private, rt }
}

/// The phone: downloads from `to` through WireGuard until the server closes or `deadline` passes.
async fn phone_download(s: &Setup, to: SocketAddr, deadline: Duration) -> usize {
    phone_download_until(s, to, deadline, usize::MAX).await
}

/// [`phone_download`], stopping as soon as `want` bytes have arrived.
async fn phone_download_until(s: &Setup, to: SocketAddr, deadline: Duration, want: usize) -> usize {
    phone_fetch(s, to, deadline, want).await.0
}

/// What a phone's download saw: the bytes, and whether the far end closed (its FIN arrived), with the
/// time it took.
async fn phone_fetch(s: &Setup, to: SocketAddr, deadline: Duration, want: usize) -> (usize, bool, Duration) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut tunn = Tunn::new(StaticSecret::from(s.phone_private), PublicKey::from(s.endpoint_public), None, None, 7, None);
    let (mut out, mut inb) = (vec![0u8; 70000], vec![0u8; 70000]);
    if let TunnResult::WriteToNetwork(b) = tunn.format_handshake_initiation(&mut out, false) {
        sock.send_to(b, s.wg_addr).await.unwrap();
    }
    let mut dev = Queue::default();
    let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut dev, SInstant::now());
    iface.update_ip_addrs(|a| {
        a.push(IpCidr::new(IpAddress::v4(10, 66, 0, 2), 32)).unwrap();
    });
    iface.routes_mut().add_default_ipv4_route(Ipv4Address::new(10, 66, 0, 1)).unwrap();
    let mut sockets = SocketSet::new(vec![]);
    let h = sockets.add(tcp::Socket::new(tcp::SocketBuffer::new(vec![0; 1 << 20]), tcp::SocketBuffer::new(vec![0; 1 << 16])));
    let IpAddr::V4(v4) = to.ip() else { panic!() };
    let o = v4.octets();
    // each connection from its own port, as a phone's are: a second one is not taken for the first
    static NEXT_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(40000);
    let port = NEXT_PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    sockets.get_mut::<tcp::Socket>(h).connect(iface.context(), (IpAddress::v4(o[0], o[1], o[2], o[3]), to.port()), port).unwrap();
    let (start, mut got, mut buf) = (Instant::now(), 0usize, vec![0u8; 1 << 16]);
    let (mut seen_open, mut fin) = (false, false);
    while start.elapsed() < deadline {
        iface.poll(SInstant::now(), &mut dev, &mut sockets);
        for p in dev.tx.drain(..) {
            if let TunnResult::WriteToNetwork(b) = tunn.encapsulate(&p, &mut out) {
                sock.send_to(b, s.wg_addr).await.unwrap();
            }
        }
        let ts = sockets.get_mut::<tcp::Socket>(h);
        while ts.can_recv() {
            got += ts.recv_slice(&mut buf).unwrap();
        }
        seen_open |= ts.state() == tcp::State::Established;
        if seen_open && !ts.may_recv() && !ts.can_recv() {
            fin = true;
            break;
        }
        if (seen_open && !ts.is_open()) || got >= want {
            break;
        }
        if let TunnResult::WriteToNetwork(b) = tunn.update_timers(&mut out) {
            sock.send_to(b, s.wg_addr).await.unwrap();
        }
        while let Ok(Ok((n, _))) = tokio::time::timeout(Duration::from_millis(if dev.rx.is_empty() { 5 } else { 0 }), sock.recv_from(&mut inb)).await {
            let mut res = tunn.decapsulate(None, &inb[..n], &mut out);
            loop {
                match res {
                    TunnResult::WriteToNetwork(b) => {
                        sock.send_to(b, s.wg_addr).await.unwrap();
                        res = tunn.decapsulate(None, &[], &mut out);
                        continue;
                    }
                    TunnResult::WriteToTunnelV4(p, _) => dev.rx.push_back(p.to_vec()),
                    _ => {}
                }
                break;
            }
            if dev.rx.len() > 256 {
                break;
            }
        }
    }
    (got, fin, start.elapsed())
}

#[test]
fn a_phone_downloads_through_wireguard_the_buyer_and_an_exit() {
    let n = 4 << 20;
    let to = tcp_server(n);
    let s = setup(80, true, None);
    let got = s.rt.block_on(phone_download(&s, to, Duration::from_secs(60)));
    assert_eq!(got, n, "every byte arrived");
    let phone = s.buyer.device(IpAddr::V4(PHONE_IP)).unwrap();
    assert_eq!(phone.meter.counts().down_bytes, n as u64, "metered at the device");
    assert_eq!(s.exit_meter.counts().down_bytes, n as u64, "and at the exit");
}

#[test]
fn a_download_the_server_ends_by_closing_ends_on_the_phone_too() {
    // the server sends 1 MiB and closes: the phone must see the end (the FIN), not wait for its deadline
    let n = 1 << 20;
    let to = tcp_server(n);
    let s = setup(81, true, None);
    let (got, fin, took) = s.rt.block_on(phone_fetch(&s, to, Duration::from_secs(30), usize::MAX));
    assert_eq!(got, n, "every byte arrived");
    assert!(fin, "the phone saw the server close (took {took:?})");
    assert!(took < Duration::from_secs(10), "and promptly: {took:?}");
}

/// A trace page like 1.1.1.1's: it answers with the address the request came from.
fn trace_page() -> SocketAddr {
    let l = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut c = c;
                let peer = c.peer_addr().unwrap().ip();
                let mut req = [0u8; 1024];
                let _ = std::io::Read::read(&mut c, &mut req);
                let body = format!("fl=1\nip={peer}\nloc=ZZ\n");
                let _ = std::io::Write::write_all(&mut c, format!("HTTP/1.0 200 OK\r\n\r\n{body}").as_bytes());
            });
        }
    });
    SocketAddr::new(lan_ip(), port)
}

#[test]
fn an_exits_region_is_verified_from_its_egress_address_read_through_it() {
    use xbt_vpn::region::{GeoTable, RegionCheck};
    let s = setup(82, true, None);
    let id = s.exit_id.clone().unwrap();
    s.buyer.set_egress_echo(trace_page(), "trace.test", "/cdn-cgi/trace");
    assert_eq!(s.rt.block_on(s.buyer.verify_region(&id, "DE")), RegionCheck::Unknown, "no table, nothing verified");
    // the table puts the exit's egress (this machine's address) in Germany
    let ip = lan_ip();
    s.buyer.set_geo(GeoTable::from_csv(&format!("{ip},{ip},DE\n")));
    assert_eq!(s.rt.block_on(s.buyer.verify_region(&id, "DE")), RegionCheck::Verified);
    assert_eq!(s.rt.block_on(s.buyer.verify_region(&id, "JP")), RegionCheck::Elsewhere("DE".into()), "a claim elsewhere is caught");
    // an owner in Japan reaching a "German" exit in a millisecond: faster than light allows
    s.buyer.set_home_country(Some("JP".into()));
    assert_eq!(s.rt.block_on(s.buyer.verify_region(&id, "DE")), RegionCheck::TooFast);
}

#[test]
fn with_no_exit_nothing_gets_out() {
    let to = tcp_server(1 << 20);
    let s = setup(90, false, None);
    let got = s.rt.block_on(phone_download(&s, to, Duration::from_secs(4)));
    assert_eq!(got, 0);
    assert!(s.buyer.refused.load(std::sync::atomic::Ordering::Relaxed) > 0, "the flow was refused, not sent outside");
}

#[test]
fn a_device_past_its_limit_is_cut_off() {
    let n = 8 << 20;
    let to = tcp_server(n);
    let s = setup(100, true, Some(1 << 20));
    let got = s.rt.block_on(phone_download(&s, to, Duration::from_secs(20)));
    assert!(got < n, "the download stopped at the limit ({got} bytes)");
    let used = s.buyer.device(IpAddr::V4(PHONE_IP)).unwrap().meter.counts().total_bytes();
    // the limit is checked between reads of up to 64 KiB, so at most one read past it
    assert!(used <= (1 << 20) + 64 * 1024, "used {used}");
}

#[test]
fn a_device_whose_policy_no_exit_meets_is_blocked_and_told_why() {
    let to = tcp_server(1 << 20);
    // the phone wants an exit verified to be in Germany; the only exit is not
    let req = Requirements { region: Some("DE".into()), ..Requirements::default() };
    let s = setup_with(160, true, None, Some(req));
    let got = s.rt.block_on(phone_download(&s, to, Duration::from_secs(4)));
    assert_eq!(got, 0, "nothing is relaxed: the traffic is blocked");
    let why = s.rt.block_on(s.buyer.why_blocked(IpAddr::V4(PHONE_IP)));
    assert_eq!(why.as_deref(), Some("No exit is verified to be in DE."));
}

#[test]
fn a_policy_change_ends_live_flows_on_an_exit_that_no_longer_qualifies() {
    let n = 64 << 20;
    let to = tcp_server(n);
    let s = Arc::new(setup(170, true, None));
    let exit = s.exit_id.clone().unwrap();
    let s2 = s.clone();
    // part-way through a long download, the buyer excludes the exit it is on
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(1500));
        let req = Requirements { exclude: vec![exit], ..Requirements::default() };
        let gone = s2.rt.block_on(s2.buyer.set_requirements(None, req));
        assert_eq!(gone.len(), 1);
    });
    let got = s.rt.block_on(phone_download(&s, to, Duration::from_secs(30)));
    assert!(got > 0 && got < n, "the flow ran, then ended when its exit stopped qualifying ({got} bytes)");
}

/// Lists an exit that has gone away (its key is known, but nothing answers at its address) as the
/// best exit, so the router picks it first. Returns its id.
fn add_gone_exit(s: &Setup, seed: u8) -> String {
    let opts = Options { relays: Relays::None, serving: false, private: false, lookup: None };
    let gone = Link::start_alpn([seed; 32], opts, ALPN_VPN).unwrap();
    let id = gone.endpoint_id();
    let buyer_link = s._links.last().unwrap();
    // an address where nothing answers: the exit's machine is off
    buyer_link.learn(&id, Hints { relays: vec![], direct: vec!["127.0.0.1:9".parse().unwrap()] }).unwrap();
    let best = ExitInfo { id: id.clone(), region: "XX".into(), price_msat_per_gb: 1000, rtt_ms: Some(1.0), mbit_s: Some(10_000.0), healthy: true, ..ExitInfo::default() };
    s.rt.block_on(s.buyer.upsert_exit(best));
    id
}

#[test]
fn an_exit_that_went_away_is_refused_quickly_and_the_next_one_used() {
    let n = 1 << 20;
    let to = tcp_server(n);
    let s = setup(180, true, None);
    let gone = add_gone_exit(&s, 185);
    let t = Instant::now();
    let got = s.rt.block_on(phone_download_until(&s, to, Duration::from_secs(30), n));
    let took = t.elapsed();
    assert_eq!(got, n, "the download went through the next exit");
    // one connect deadline for the gone exit, then the working one, not the link's own long timeout
    assert!(took < xbt_vpn::buyer::CONNECT_WAIT + Duration::from_secs(5), "took {took:?}");
    assert!(s.rt.block_on(s.buyer.failed_exits()).contains(&gone), "the gone exit is marked failed");
    assert_eq!(s.rt.block_on(s.buyer.why_blocked(IpAddr::V4(PHONE_IP))), None, "an exit still qualifies");
}

#[test]
fn when_every_qualifying_exit_is_gone_the_device_is_told_why() {
    let to = tcp_server(1 << 20);
    let s = setup(190, false, None);
    add_gone_exit(&s, 195);
    let t = Instant::now();
    let got = s.rt.block_on(phone_download(&s, to, Duration::from_secs(12)));
    assert_eq!(got, 0, "nothing gets out");
    let why = s.rt.block_on(s.buyer.why_blocked(IpAddr::V4(PHONE_IP)));
    assert_eq!(why.as_deref(), Some("The exit that meets these rules isn't answering right now. Stream keeps trying it."));
    assert!(t.elapsed() < Duration::from_secs(14));
}

/// A phone whose policy asks for two hops: its WireGuard flows go through the buyer's stack, sealed
/// for an exit and carried by a first hop run by another operator. Returns the setup and what the exit
/// saw connect to it.
fn setup_two_hop(seed: u8) -> (Setup, Arc<std::sync::Mutex<Vec<String>>>, String) {
    let opts = |serving| Options { relays: Relays::None, serving, private: false, lookup: None };
    let exit_secret = [seed; 32];
    let exit = Link::start_alpns(exit_secret, opts(true), ALPN_VPN, &[ALPN_VPN, ALPN_VPN_SEALED]).unwrap();
    let hop = Link::start_alpns([seed + 1; 32], opts(true), ALPN_VPN_HOP, &[ALPN_VPN_HOP]).unwrap();
    let buyer_link = Link::start_alpn([seed + 2; 32], opts(false), ALPN_VPN).unwrap();
    let exit_meter = Arc::new(Meter::default());
    let exit_saw = Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let cfg = Arc::new(ExitConfig { policy: Policy { allow_non_public: true, ..Policy::default() }, ..ExitConfig::default() });
        let (m, b, saw, tls) = (exit_meter.clone(), Arc::new(SealedBuyers::default()), exit_saw.clone(), xbt_vpn::sealed::exit_config(&exit_secret));
        exit.accept_with(move |conn| {
            saw.lock().unwrap().push(hex::encode(conn.remote_id().as_bytes()));
            let (cfg, m, b, tls) = (cfg.clone(), m.clone(), b.clone(), tls.clone());
            async move {
                if conn.alpn() == ALPN_VPN_SEALED {
                    serve_sealed(conn, cfg, m, tls, b).await
                } else {
                    serve_buyer(conn, cfg, m).await
                }
            }
        });
    }
    {
        let (h, cfg) = (hop.clone(), Arc::new(HopConfig::default()));
        hop.accept_with(move |conn| serve_hop(h.clone(), conn, cfg.clone(), Arc::new(Meter::default())));
    }
    let (exit_id, hop_id) = (exit.endpoint_id(), hop.endpoint_id());
    let direct = |l: &Link| Hints { relays: vec![], direct: l.hints(Duration::from_secs(1)).direct.into_iter().filter(|a| a.is_ipv4()).collect() };
    hop.learn(&exit_id, direct(&exit)).unwrap();
    buyer_link.learn(&hop_id, direct(&hop)).unwrap();
    let mut router = Router::with_requirements(Requirements { two_hop: true, ..Requirements::default() });
    router.upsert(ExitInfo { id: exit_id.clone(), operator: "op-exit".into(), region: "XX".into(), price_msat_per_gb: 2000, healthy: true, two_hop: true, ..ExitInfo::default() });
    router.set_first_hops(vec![FirstHop { id: hop_id.clone(), operator: "op-hop".into() }]);
    let (phone_private, phone_public) = keypair();
    let (endpoint_private, endpoint_public) = keypair();
    let dev = Arc::new(BuyerDevice { name: "phone".into(), meter: Meter::default(), limit_bytes: None, requirements: None });
    let buyer = Buyer::new(buyer_link.clone(), router, HashMap::from([(IpAddr::V4(PHONE_IP), dev)]), None);
    let wg = WgEndpoint::new(endpoint_private, &[WgPeer { public: phone_public, tunnel_ip: PHONE_IP }]);
    let rt = buyer_link.runtime();
    let (to_stack, from_devices) = mpsc::channel::<Bytes>(4096);
    let (to_devices, from_stack) = mpsc::unbounded_channel::<Bytes>();
    let sock = rt.block_on(UdpSocket::bind("127.0.0.1:0")).unwrap();
    let wg_addr = sock.local_addr().unwrap();
    rt.spawn(buyer.clone().run(from_devices, to_devices));
    rt.spawn(wg.run(sock, to_stack, from_stack));
    let s = Setup { _links: vec![exit, hop, buyer_link], exit_id: Some(exit_id), buyer, exit_meter, wg_addr, endpoint_public, phone_private, rt };
    (s, exit_saw, hop_id)
}

#[test]
fn a_phones_flow_takes_two_hops_and_the_exit_never_sees_the_buyer() {
    let n = 2 << 20;
    let to = tcp_server(n);
    let (s, exit_saw, hop_id) = setup_two_hop(200);
    let got = s.rt.block_on(phone_download_until(&s, to, Duration::from_secs(30), n));
    assert_eq!(got, n, "every byte arrived through the first hop and the exit");
    assert_eq!(s.exit_meter.counts().down_bytes, n as u64, "the exit carried and metered it");
    // the exit was reached only by the first hop's link: the buyer's link never connected to it
    assert_eq!(*exit_saw.lock().unwrap(), vec![hop_id]);
    assert_eq!(s.rt.block_on(s.buyer.why_blocked(IpAddr::V4(PHONE_IP))), None);
}

// --- paid tunnels -------------------------------------------------------------------------------

/// A wallet that pays nothing but joins tunnels as the signer does: asked for an `xbt402_pay` with
/// `upgrade`, it opens the upgrade at the exit's tunnel endpoint, hands the stream to the buyer's
/// socket (its head line first), and carries the bytes both ways. With `cut_after`, it ends a tunnel
/// once that many bytes have passed (a limit reached, a seller fault). Counts the tunnels it opened.
struct FakeWallet {
    wallet: xbt_vpn::paid::Wallet,
    opened: Arc<std::sync::atomic::AtomicUsize>,
    carried: Arc<std::sync::atomic::AtomicU64>,
    /// What each call asked the wallet for.
    asked: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    _dir: tempdir_lite::Dir,
}

mod tempdir_lite {
    pub struct Dir(pub std::path::PathBuf);
    impl Dir {
        pub fn new(tag: &str) -> Dir {
            let d = std::env::temp_dir().join(format!("xbt-vpn-{tag}-{}-{:?}", std::process::id(), std::time::Instant::now()));
            let d = std::path::PathBuf::from(d.to_string_lossy().replace([' ', '{', '}', ':', ','], ""));
            std::fs::create_dir_all(&d).unwrap();
            Dir(d)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn fake_wallet(exit_at: SocketAddr, cut_after: Option<u64>) -> FakeWallet {
    fake_wallet_with(exit_at, cut_after, false)
}

/// `die_at_once`: each tunnel answers 101 and ends at once, as a seller that takes the opening's
/// price and carries nothing would.
fn fake_wallet_with(exit_at: SocketAddr, cut_after: Option<u64>, die_at_once: bool) -> FakeWallet {
    use std::io::{BufRead, Read, Write};
    use std::sync::atomic::Ordering;
    let dir = tempdir_lite::Dir::new("wallet");
    let (sock, streams) = (dir.0.join("signer.sock"), dir.0.join("streams"));
    std::fs::create_dir_all(&streams).unwrap();
    let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let carried = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
    let l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let (o, c, sdir, a) = (opened.clone(), carried.clone(), streams.clone(), asked.clone());
    std::thread::spawn(move || {
        for conn in l.incoming().flatten() {
            let (o, c, sdir, a) = (o.clone(), c.clone(), sdir.clone(), a.clone());
            std::thread::spawn(move || {
                let mut rd = std::io::BufReader::new(conn.try_clone().unwrap());
                let mut line = String::new();
                rd.read_line(&mut line).unwrap();
                let req: serde_json::Value = serde_json::from_str(&line).unwrap();
                let p = &req["params"];
                a.lock().unwrap().push(p.clone());
                assert_eq!(p["upgrade"], true, "{p}");
                let mut up = std::net::TcpStream::connect(exit_at).unwrap();
                up.write_all(b"GET /vpn/tunnel HTTP/1.1\r\nHost: shop\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").unwrap();
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    up.read_exact(&mut b).unwrap();
                    head.push(b[0]);
                }
                assert!(head.starts_with(b"HTTP/1.1 101"), "{}", String::from_utf8_lossy(&head));
                assert!(String::from_utf8_lossy(&head).contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
                o.fetch_add(1, Ordering::SeqCst);
                let mut to_buyer = std::os::unix::net::UnixStream::connect(sdir.join(p["stream_to"].as_str().unwrap())).unwrap();
                to_buyer.write_all(b"{\"status\":101,\"headers\":[]}\n").unwrap();
                if die_at_once {
                    let _ = to_buyer.shutdown(std::net::Shutdown::Both);
                    let _ = up.shutdown(std::net::Shutdown::Both);
                    let mut conn = conn;
                    let _ = conn.write_all(b"{\"id\":1,\"result\":{\"status\":101,\"ended\":\"the seller ended it\"}}\n");
                    return;
                }
                // this tunnel's own count, for where it is cut; `c` counts every tunnel's bytes
                let mine = Arc::new(std::sync::atomic::AtomicU64::new(0));
                let pipe = move |mut from: Box<dyn Read + Send>, mut to: Box<dyn Write + Send>, c: Arc<std::sync::atomic::AtomicU64>, mine: Arc<std::sync::atomic::AtomicU64>, stop: Box<dyn Fn() + Send>| {
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        let n = match from.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if to.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        c.fetch_add(n as u64, Ordering::SeqCst);
                        let total = mine.fetch_add(n as u64, Ordering::SeqCst) + n as u64;
                        if cut_after.is_some_and(|cut| total >= cut) {
                            break;
                        }
                    }
                    stop();
                };
                let (u2, b2) = (up.try_clone().unwrap(), to_buyer.try_clone().unwrap());
                let (u3, b3) = (up.try_clone().unwrap(), to_buyer.try_clone().unwrap());
                let stop = move || {
                    let _ = u3.shutdown(std::net::Shutdown::Both);
                    let _ = b3.shutdown(std::net::Shutdown::Both);
                };
                let (u4, b4) = (up.try_clone().unwrap(), to_buyer.try_clone().unwrap());
                let stop2 = move || {
                    let _ = u4.shutdown(std::net::Shutdown::Both);
                    let _ = b4.shutdown(std::net::Shutdown::Both);
                };
                let (c2, m2) = (c.clone(), mine.clone());
                let t = std::thread::spawn(move || pipe(Box::new(b2), Box::new(u2), c2, m2, Box::new(stop2)));
                pipe(Box::new(up), Box::new(to_buyer), c, mine, Box::new(stop));
                let _ = t.join();
                let mut conn = conn;
                let _ = conn.write_all(b"{\"id\":1,\"result\":{\"status\":101,\"ended\":\"the tunnel ended\"}}\n");
            });
        }
    });
    let wallet = xbt_vpn::paid::Wallet { signer: sock, stream_dir: streams, task: "vpn".into(), max_sats: 10_000 };
    FakeWallet { wallet, opened, carried, asked, _dir: dir }
}

/// A priced exit's tunnel endpoint, as its shop's gateway would reach it.
fn paid_exit(rt: &tokio::runtime::Handle, meter: Arc<Meter>) -> SocketAddr {
    let cfg = Arc::new(ExitConfig { policy: Policy { allow_non_public: true, ..Policy::default() }, ..ExitConfig::default() });
    let l = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
    let at = l.local_addr().unwrap();
    rt.spawn(xbt_vpn::paid::serve_tunnel_endpoint(l, move |c| xbt_vpn::exit::serve(c, cfg.clone(), meter.clone())));
    at
}

fn priced(id: &str) -> ExitInfo {
    ExitInfo { id: id.into(), region: "XX".into(), price_msat_per_gb: 2_000_000, healthy: true, ..ExitInfo::default() }
}

#[test]
fn a_phone_downloads_through_a_paid_tunnel_its_wallet_opens() {
    let n = 2 << 20;
    let to = tcp_server(n);
    let s = setup(83, false, None);
    let meter = Arc::new(Meter::default());
    let at = paid_exit(&s.rt, meter.clone());
    let w = fake_wallet(at, None);
    s.buyer.set_wallet(Some(w.wallet.clone()));
    s.buyer.set_tunnel("paid-exit", Some(format!("http://{at}/vpn/tunnel")), 2_000_000);
    s.rt.block_on(s.buyer.upsert_exit(priced("paid-exit")));
    let got = s.rt.block_on(phone_download(&s, to, Duration::from_secs(60)));
    assert_eq!(got, n, "every byte arrived through the tunnel");
    assert_eq!(meter.counts().down_bytes, n as u64, "metered at the exit");
    assert_eq!(w.opened.load(std::sync::atomic::Ordering::SeqCst), 1, "one tunnel for the device");
    assert!(w.carried.load(std::sync::atomic::Ordering::SeqCst) >= n as u64, "and the wallet carried (and would pay for) every byte");
}

#[test]
fn a_paid_tunnel_is_paid_no_more_than_the_price_its_exit_announced() {
    let to = tcp_server(64 << 10);
    let s = setup(110, false, None);
    let at = paid_exit(&s.rt, Arc::new(Meter::default()));
    let w = fake_wallet(at, None);
    s.buyer.set_wallet(Some(w.wallet.clone()));
    s.buyer.set_tunnel("paid-exit", Some(format!("http://{at}/vpn/tunnel")), 2_000_000);
    s.rt.block_on(s.buyer.upsert_exit(priced("paid-exit")));
    assert_eq!(s.rt.block_on(phone_download(&s, to, Duration::from_secs(20))), 64 << 10);
    // the wallet is told the announced price: its 402 asking more is paid nothing
    let asked = w.asked.lock().unwrap().clone();
    assert_eq!(asked[0]["price_ceiling"], serde_json::json!({"request_msat": 0, "gib_msat": 2_000_000}), "{asked:?}");
}

#[test]
fn a_tunnel_that_dies_as_it_opens_is_not_paid_for_again_and_again() {
    let to = tcp_server(64 << 10);
    let s = setup(112, false, None);
    let at = paid_exit(&s.rt, Arc::new(Meter::default()));
    let w = fake_wallet_with(at, None, true);
    s.buyer.set_wallet(Some(w.wallet.clone()));
    s.buyer.set_tunnel("paid-exit", Some(format!("http://{at}/vpn/tunnel")), 2_000_000);
    s.rt.block_on(s.buyer.upsert_exit(priced("paid-exit")));
    for _ in 0..4 {
        let _ = s.rt.block_on(phone_download(&s, to, Duration::from_secs(3)));
    }
    // the first opening is paid; the exit is then held off, not opened (and paid) once a flow
    assert_eq!(w.opened.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(s.buyer.is_held_off("paid-exit"));
}

#[test]
fn a_priced_exits_region_is_checked_only_when_a_device_asks_for_it() {
    let req = Requirements { region: Some("DE".into()), ..Requirements::default() };
    let s = setup_with(114, false, None, Some(req));
    assert!(s.buyer.region_wanted(&ExitInfo { region: "DE".into(), ..priced("de") }));
    assert!(!s.buyer.region_wanted(&ExitInfo { region: "FR".into(), ..priced("fr") }), "nobody asked for France");
    let plain = setup(116, false, None);
    assert!(!plain.buyer.region_wanted(&priced("any")), "no device names a region: nothing to pay to check");
}

#[test]
fn a_paid_tunnel_that_ends_is_opened_again_for_the_next_flow() {
    let to = tcp_server(4 << 20);
    let s = setup(84, false, None);
    let at = paid_exit(&s.rt, Arc::new(Meter::default()));
    // the wallet ends the first tunnel part way (its limit, say)
    let w = fake_wallet(at, Some(1 << 20));
    s.buyer.set_wallet(Some(w.wallet.clone()));
    s.buyer.set_tunnel("paid-exit", Some(format!("http://{at}/vpn/tunnel")), 2_000_000);
    s.rt.block_on(s.buyer.upsert_exit(priced("paid-exit")));
    let first = s.rt.block_on(phone_download(&s, to, Duration::from_secs(20)));
    assert!(first > 0 && first < 4 << 20, "the first download is cut where its tunnel ended: {first}");
    let again = s.rt.block_on(phone_download_until(&s, to, Duration::from_secs(30), 512 << 10));
    assert!(again >= 512 << 10, "the next flow gets a new tunnel: {again}");
    assert_eq!(w.opened.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[test]
fn a_priced_exit_is_not_used_without_a_wallet_to_pay_it() {
    let to = tcp_server(1 << 20);
    let s = setup(85, false, None);
    let at = paid_exit(&s.rt, Arc::new(Meter::default()));
    s.buyer.set_tunnel("paid-exit", Some(format!("http://{at}/vpn/tunnel")), 2_000_000);
    s.rt.block_on(s.buyer.upsert_exit(priced("paid-exit")));
    let got = s.rt.block_on(phone_download(&s, to, Duration::from_secs(8)));
    assert_eq!(got, 0, "nothing gets out unpaid");
}
