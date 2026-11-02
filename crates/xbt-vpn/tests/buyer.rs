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
    // a free exit reached over the link: no gate, nothing paid
    let mut gate = xbt_vpn::holds::CheckGate::default();
    let mut check = |region: &str| s.rt.block_on(s.buyer.check_region(&mut gate, &ExitInfo { id: id.clone(), region: region.into(), ..ExitInfo::default() })).unwrap();
    assert_eq!(check("DE"), RegionCheck::Unknown, "no table, nothing verified");
    // the table puts the exit's egress (this machine's address) in Germany
    let ip = lan_ip();
    s.buyer.set_geo(GeoTable::from_csv(&format!("{ip},{ip},DE\n")));
    assert_eq!(check("DE"), RegionCheck::Verified);
    assert_eq!(check("JP"), RegionCheck::Elsewhere("DE".into()), "a claim elsewhere is caught");
    // an owner in Japan reaching a "German" exit in a millisecond: faster than light allows
    s.buyer.set_home_country(Some("JP".into()));
    assert_eq!(check("DE"), RegionCheck::TooFast);
    assert_eq!(gate.spent_today(), 0);
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
    /// The sats that left it: the tickets it bought ([`fake_wallet_selling`]).
    left: Arc<std::sync::atomic::AtomicU64>,
    /// A file to read as each call comes in (a region checks' gate), and what it held then.
    watch: Arc<std::sync::Mutex<Option<std::path::PathBuf>>>,
    seen_on_call: Arc<std::sync::Mutex<Vec<String>>>,
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
    fake_wallet_full(exit_at, cut_after, die_at_once, None, Ends::Answers)
}

/// How a fake wallet behaves around a tunnel, past the plain case.
#[derive(Clone, Copy, PartialEq)]
enum Ends {
    /// It answers when the tunnel ends, as the signer does.
    Answers,
    /// Its answer when the tunnel ends is an error.
    Errs,
    /// It never answers once the tunnel has ended.
    Silent,
    /// It pays and never hands the tunnel over.
    NeverOpens,
    /// It takes this long to open the tunnel (from no credit: buying the ticket first).
    OpensAfter(Duration),
    /// It answers this (the call's `result`) before the tunnel opens, the ticket bought.
    AnswersFirst(&'static str),
}

/// A wallet with no credit at the exit's shop, whose tickets are `ticket` sats: each tunnel buys
/// one, as the signer does, and only if it fits the call's `max_sats` (else the call is refused
/// before anything is paid); its answer when the tunnel ends says what left (`charged_sats`).
fn fake_wallet_selling(exit_at: SocketAddr, ticket: u64) -> FakeWallet {
    fake_wallet_full(exit_at, None, false, Some(ticket), Ends::Answers)
}

fn fake_wallet_full(exit_at: SocketAddr, cut_after: Option<u64>, die_at_once: bool, ticket: Option<u64>, ends: Ends) -> FakeWallet {
    use std::io::{BufRead, Read, Write};
    use std::sync::atomic::Ordering;
    let dir = tempdir_lite::Dir::new("wallet");
    let (sock, streams) = (dir.0.join("signer.sock"), dir.0.join("streams"));
    std::fs::create_dir_all(&streams).unwrap();
    let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let carried = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
    let left = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let watch: Arc<std::sync::Mutex<Option<std::path::PathBuf>>> = Arc::new(std::sync::Mutex::new(None));
    let seen_on_call = Arc::new(std::sync::Mutex::new(Vec::new()));
    let l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let (o, c, sdir, a, lt, wt, so) = (opened.clone(), carried.clone(), streams.clone(), asked.clone(), left.clone(), watch.clone(), seen_on_call.clone());
    std::thread::spawn(move || {
        for conn in l.incoming().flatten() {
            let (o, c, sdir, a, lt, wt, so) = (o.clone(), c.clone(), sdir.clone(), a.clone(), lt.clone(), wt.clone(), so.clone());
            std::thread::spawn(move || {
                let mut rd = std::io::BufReader::new(conn.try_clone().unwrap());
                let mut line = String::new();
                rd.read_line(&mut line).unwrap();
                let req: serde_json::Value = serde_json::from_str(&line).unwrap();
                let p = &req["params"];
                if let Some(f) = wt.lock().unwrap().clone() {
                    so.lock().unwrap().push(std::fs::read_to_string(f).unwrap_or_default());
                }
                a.lock().unwrap().push(p.clone());
                assert_eq!(p["upgrade"], true, "{p}");
                // the ticket is bought first, within the call's max_sats
                let charged = match ticket {
                    Some(t) if t > p["max_sats"].as_u64().unwrap() => {
                        let mut conn = conn;
                        let _ = conn.write_all(b"{\"id\":1,\"result\":{\"verdict\":\"deny\",\"rule\":\"max_sats\",\"reason\":\"a ticket is more than the call's max_sats\"}}\n");
                        return;
                    }
                    Some(t) => {
                        lt.fetch_add(t, Ordering::SeqCst);
                        format!(",\"charged_sats\":{t}")
                    }
                    None => String::new(),
                };
                match ends {
                    Ends::NeverOpens => {
                        std::thread::sleep(Duration::from_secs(600));
                        return;
                    }
                    Ends::OpensAfter(d) => std::thread::sleep(d),
                    Ends::AnswersFirst(result) => {
                        let mut conn = conn;
                        let _ = conn.write_all(format!("{{\"id\":1,\"result\":{result}}}\n").as_bytes());
                        return;
                    }
                    _ => {}
                }
                let mut up = std::net::TcpStream::connect(exit_at).unwrap();
                // as the shop's gateway joins it: with the secret the two share
                up.write_all(format!("GET /vpn/tunnel HTTP/1.1\r\nHost: shop\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{}: {TUNNEL_TEST_SECRET}\r\n\r\n", xbt_vpn::paid::TUNNEL_HEADER).as_bytes()).unwrap();
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
                    let _ = conn.write_all(format!("{{\"id\":1,\"result\":{{\"status\":101,\"ended\":\"the seller ended it\"{charged}}}}}\n").as_bytes());
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
                match ends {
                    Ends::Errs => {
                        let _ = conn.write_all(b"{\"id\":1,\"error\":{\"message\":\"the signer stopped\"}}\n");
                    }
                    Ends::Silent => std::thread::sleep(Duration::from_secs(600)),
                    _ => {
                        let _ = conn.write_all(format!("{{\"id\":1,\"result\":{{\"status\":101,\"ended\":\"the tunnel ended\"{charged}}}}}\n").as_bytes());
                    }
                }
            });
        }
    });
    let wallet = xbt_vpn::paid::Wallet { signer: sock, stream_dir: streams, task: "vpn".into(), max_sats: 10_000, max_charge_sats: None };
    FakeWallet { wallet, opened, carried, asked, left, watch, seen_on_call, _dir: dir }
}

/// The secret a test exit and its (fake) shop gateway share.
const TUNNEL_TEST_SECRET: &str = "5ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7";

/// A priced exit's tunnel endpoint, as its shop's gateway would reach it.
fn paid_exit(rt: &tokio::runtime::Handle, meter: Arc<Meter>) -> SocketAddr {
    let cfg = Arc::new(ExitConfig { policy: Policy { allow_non_public: true, ..Policy::default() }, ..ExitConfig::default() });
    let l = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
    let at = l.local_addr().unwrap();
    rt.spawn(xbt_vpn::paid::serve_tunnel_endpoint(l, || Some(TUNNEL_TEST_SECRET.to_string()), move |c| xbt_vpn::exit::serve(c, cfg.clone(), meter.clone())));
    at
}

/// A wallet that refuses every tunnel as the exit's terms are above its announced price, counting
/// how often it was asked.
fn refusing_wallet() -> (xbt_vpn::paid::Wallet, Arc<std::sync::atomic::AtomicUsize>, tempdir_lite::Dir) {
    use std::io::{BufRead, Write};
    let dir = tempdir_lite::Dir::new("refusing");
    let (sock, streams) = (dir.0.join("signer.sock"), dir.0.join("streams"));
    std::fs::create_dir_all(&streams).unwrap();
    let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let a = asked.clone();
    std::thread::spawn(move || {
        for conn in l.incoming().flatten() {
            a.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut line = String::new();
            let _ = std::io::BufReader::new(conn.try_clone().unwrap()).read_line(&mut line);
            let mut conn = conn;
            let _ = conn.write_all(b"{\"id\":1,\"result\":{\"verdict\":\"deny\",\"rule\":\"price_ceiling\",\"reason\":\"the seller asks more than the price it was shown\"}}\n");
        }
    });
    (xbt_vpn::paid::Wallet { signer: sock, stream_dir: streams, task: "vpn".into(), max_sats: 10_000, max_charge_sats: None }, asked, dir)
}

#[test]
fn an_exit_that_asked_more_than_it_announced_is_used_again_only_once_it_announces_more() {
    let to = tcp_server(64 << 10);
    let s = setup(118, false, None);
    let (w, asked, _d) = refusing_wallet();
    s.buyer.set_wallet(Some(w));
    s.buyer.set_tunnel("paid-exit", Some("http://127.0.0.1:9/vpn/tunnel".into()), 2_000_000, "op");
    s.rt.block_on(s.buyer.upsert_exit(priced("paid-exit")));
    let _ = s.rt.block_on(phone_download(&s, to, Duration::from_secs(3)));
    assert!(s.buyer.is_held_off("paid-exit"), "terms above its announcement: held off");
    let n = asked.load(std::sync::atomic::Ordering::SeqCst);
    // announcing the same price again (or less) doesn't end the hold: that is the bait
    s.buyer.set_tunnel("paid-exit", Some("http://127.0.0.1:9/vpn/tunnel".into()), 2_000_000, "op");
    s.buyer.set_tunnel("paid-exit", Some("http://127.0.0.1:9/vpn/tunnel".into()), 1_000_000, "op");
    assert!(s.buyer.is_held_off("paid-exit"));
    let _ = s.rt.block_on(phone_download(&s, to, Duration::from_secs(2)));
    assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), n, "a held exit isn't asked (or paid) again");
    // an honest exit raising its price: used again
    s.buyer.set_tunnel("paid-exit", Some("http://127.0.0.1:9/vpn/tunnel".into()), 3_000_000, "op");
    assert!(!s.buyer.is_held_off("paid-exit"), "it now announces more than it did: used again");
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
    s.buyer.set_tunnel("paid-exit", Some(format!("http://{at}/vpn/tunnel")), 2_000_000, "op");
    s.rt.block_on(s.buyer.upsert_exit(priced("paid-exit")));
    let got = s.rt.block_on(phone_download(&s, to, Duration::from_secs(60)));
    assert_eq!(got, n, "every byte arrived through the tunnel");
    assert_eq!(meter.counts().down_bytes, n as u64, "metered at the exit");
    assert_eq!(w.opened.load(std::sync::atomic::Ordering::SeqCst), 1, "one tunnel for the device");
    assert!(w.carried.load(std::sync::atomic::Ordering::SeqCst) >= n as u64, "and the wallet carried (and would pay for) every byte");
}

#[test]
fn a_device_shows_the_exit_it_goes_out_through_and_what_its_tunnel_has_cost() {
    let n = 2 << 20;
    let to = tcp_server(n);
    let s = setup(86, false, None);
    assert_eq!(s.buyer.device_use(IpAddr::V4(PHONE_IP)), (None, 0), "nothing used yet");
    let at = paid_exit(&s.rt, Arc::new(Meter::default()));
    let w = fake_wallet(at, None);
    s.buyer.set_wallet(Some(w.wallet.clone()));
    s.buyer.set_tunnel("paid-exit", Some(format!("http://{at}/vpn/tunnel")), 2_000_000, "op");
    s.rt.block_on(s.buyer.upsert_exit(priced("paid-exit")));
    assert_eq!(s.rt.block_on(phone_download(&s, to, Duration::from_secs(60))), n);
    let (exit, used) = s.buyer.device_use(IpAddr::V4(PHONE_IP));
    assert_eq!(exit.as_deref(), Some("paid-exit"));
    // its bytes both ways at the announced 2,000,000 msat a GiB: at least the download, and not much more
    let floor = xbt_vpn::buyer::cost_msat(n as u64, 2_000_000);
    assert!(used >= floor && used <= floor + floor / 10 + 1_000, "used {used} msat for {n} bytes (floor {floor})");
    let line = xbt_vpn::service::with_use(serde_json::json!({"id": "x"}), exit.as_deref(), used);
    assert_eq!(line["exit"], "paid-exit");
    assert_eq!(line["used_msat"], used);
}

#[test]
fn a_paid_tunnel_is_paid_no_more_than_the_price_its_exit_announced() {
    let to = tcp_server(64 << 10);
    let s = setup(110, false, None);
    let at = paid_exit(&s.rt, Arc::new(Meter::default()));
    let w = fake_wallet(at, None);
    s.buyer.set_wallet(Some(w.wallet.clone()));
    s.buyer.set_tunnel("paid-exit", Some(format!("http://{at}/vpn/tunnel")), 2_000_000, "op");
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
    s.buyer.set_tunnel("paid-exit", Some(format!("http://{at}/vpn/tunnel")), 2_000_000, "op");
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
    s.buyer.set_tunnel("paid-exit", Some(format!("http://{at}/vpn/tunnel")), 2_000_000, "op");
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
    s.buyer.set_tunnel("paid-exit", Some(format!("http://{at}/vpn/tunnel")), 2_000_000, "op");
    s.rt.block_on(s.buyer.upsert_exit(priced("paid-exit")));
    let got = s.rt.block_on(phone_download(&s, to, Duration::from_secs(8)));
    assert_eq!(got, 0, "nothing gets out unpaid");
}

/// A buyer whose phone's policy asks for Germany, a priced exit there under `operator` whose tunnel
/// is opened by `w`, and the trace page and table that put the exit's egress in Germany.
fn region_check_setup(seed: u8) -> (Setup, SocketAddr) {
    use xbt_vpn::region::GeoTable;
    let s = setup_with(seed, false, None, Some(Requirements { region: Some("DE".into()), ..Requirements::default() }));
    let at = paid_exit(&s.rt, Arc::new(Meter::default()));
    s.buyer.set_egress_echo(trace_page(), "trace.test", "/cdn-cgi/trace");
    let ip = lan_ip();
    s.buyer.set_geo(GeoTable::from_csv(&format!("{ip},{ip},DE\n")));
    (s, at)
}

fn german_exit(s: &Setup, at: SocketAddr, id: &str, price: u64) -> ExitInfo {
    let e = ExitInfo { id: id.into(), region: "DE".into(), operator: format!("op-{id}"), price_msat_per_gb: price, ..priced(id) };
    s.buyer.set_tunnel(&e.id, Some(format!("http://{at}/vpn/tunnel")), e.price_msat_per_gb, &e.operator);
    s.rt.block_on(s.buyer.upsert_exit(e.clone()));
    e
}

/// A region check of a priced exit is charged at most `REGION_CHECK_MAX_SATS`, and no more than one
/// ticket of the exit's shop (`REGION_CHECK_TICKET_SATS`) may leave the wallet for it: a cap of 20
/// sats on what may leave would never buy a ticket, so an exit the buyer holds no credit with could
/// never be checked; the tunnel's own 10,000 would let each check strand five tickets.
/// From no credit at the exit's shop, the check buys its ticket, verifies the region, and the gate
/// counts what left as the wallet answered.
#[test]
fn a_region_check_from_no_credit_buys_one_ticket_verifies_and_counts_what_left() {
    use std::sync::atomic::Ordering;
    use xbt_vpn::buyer::{REGION_CHECK_MAX_SATS, REGION_CHECK_TICKET_SATS};
    use xbt_vpn::holds::CheckGate;
    use xbt_vpn::region::RegionCheck;
    let (s, at) = region_check_setup(120);
    let w = fake_wallet_selling(at, 1_000);
    s.buyer.set_wallet(Some(w.wallet.clone()));
    let e = german_exit(&s, at, "paid-exit", 2_000_000);
    let mut gate = CheckGate::default();
    assert_eq!(s.rt.block_on(s.buyer.check_region(&mut gate, &e)), Some(RegionCheck::Verified));
    assert_eq!(w.left.load(Ordering::SeqCst), 1_000);
    assert_eq!(gate.spent_today(), 1_000, "what left, by the wallet's answer");
    let asked = w.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 1, "one paid tunnel: {asked:?}");
    assert_eq!((asked[0]["max_sats"].as_u64(), asked[0]["max_charge_sats"].as_u64()),
               (Some(REGION_CHECK_TICKET_SATS), Some(REGION_CHECK_MAX_SATS)), "{asked:?}");
}

/// Where the wallet's answer doesn't say what left (it says nothing of it, it is an error, it never
/// comes), or the tunnel never opens though the wallet may have paid: the check counts its most.
#[test]
fn a_region_check_whose_cost_is_not_known_counts_its_most() {
    use xbt_vpn::buyer::{CheckWaits, REGION_CHECK_TICKET_SATS};
    use xbt_vpn::holds::CheckGate;
    use xbt_vpn::region::RegionCheck;
    let short = CheckWaits { open: Duration::from_secs(2), read: Duration::from_secs(5), answer: Duration::from_secs(2) };
    for (seed, ends, ticket, verified) in [(130, Ends::Answers, None, true), (132, Ends::Errs, Some(700), true),
                                           (134, Ends::Silent, Some(700), true), (136, Ends::NeverOpens, Some(700), false)] {
        let (s, at) = region_check_setup(seed);
        s.buyer.set_check_waits(short);
        let w = fake_wallet_full(at, None, false, ticket, ends);
        s.buyer.set_wallet(Some(w.wallet.clone()));
        let e = german_exit(&s, at, "paid-exit", 2_000_000);
        let mut gate = CheckGate::default();
        let t0 = Instant::now();
        let got = s.rt.block_on(s.buyer.check_region(&mut gate, &e));
        assert_eq!(got == Some(RegionCheck::Verified), verified, "seed {seed}: {got:?}");
        assert_eq!(gate.spent_today(), REGION_CHECK_TICKET_SATS, "seed {seed}: what left is not known: its most is counted");
        assert!(t0.elapsed() < Duration::from_secs(20), "seed {seed}: the waits are bounded: {:?}", t0.elapsed());
    }
}

/// A wallet with no credit at the exit's shop may take a while to open the tunnel (it buys the
/// ticket first): the opening has its own bound, so a slow one still leaves the check's reads their
/// whole time, and the check verifies and counts what left.
#[test]
fn a_slow_opening_from_no_credit_still_verifies() {
    use xbt_vpn::buyer::CheckWaits;
    use xbt_vpn::holds::CheckGate;
    use xbt_vpn::region::RegionCheck;
    let (s, at) = region_check_setup(138);
    // the opening takes longer than the reads may
    s.buyer.set_check_waits(CheckWaits { open: Duration::from_secs(10), read: Duration::from_secs(2), answer: Duration::from_secs(5) });
    let w = fake_wallet_full(at, None, false, Some(800), Ends::OpensAfter(Duration::from_secs(3)));
    s.buyer.set_wallet(Some(w.wallet.clone()));
    let e = german_exit(&s, at, "paid-exit", 2_000_000);
    let mut gate = CheckGate::default();
    assert_eq!(s.rt.block_on(s.buyer.check_region(&mut gate, &e)), Some(RegionCheck::Verified));
    assert_eq!(gate.spent_today(), 800);
}

/// The wallet's answer tells of a seller's fault or a payment it did not count before the tunnel
/// opens: what left is not known, and the check counts its most.
#[test]
fn a_region_check_answered_with_a_seller_fault_counts_its_most() {
    use xbt_vpn::buyer::{CheckWaits, REGION_CHECK_TICKET_SATS};
    use xbt_vpn::holds::CheckGate;
    use xbt_vpn::region::RegionCheck;
    let answers = [
        r#"{"verdict":"deny","rule":"ticket_seller_fault","reason":"the session with this seller was stopped: it charged past the call's limit","rail":"ticket","charged_sats":0}"#,
        r#"{"verdict":"pending","rail":"ticket","charged_sats":0}"#,
        r#"{"verdict":"deny","rule":"ticket","reason":"the release was not confirmed","rail":"ticket","charged_sats":0,"unconfirmed_release":"ab12"}"#,
        r#"{"verdict":"allow","status":101,"charged_sats":0,"seller_fault":"it charged past the call's limit"}"#,
    ];
    for (i, answer) in answers.into_iter().enumerate() {
        let (s, at) = region_check_setup(140 + 2 * i as u8);
        s.buyer.set_check_waits(CheckWaits { open: Duration::from_secs(5), read: Duration::from_secs(5), answer: Duration::from_secs(2) });
        let w = fake_wallet_full(at, None, false, Some(700), Ends::AnswersFirst(answer));
        s.buyer.set_wallet(Some(w.wallet.clone()));
        let e = german_exit(&s, at, "paid-exit", 2_000_000);
        let mut gate = CheckGate::default();
        assert_eq!(s.rt.block_on(s.buyer.check_region(&mut gate, &e)), Some(RegionCheck::Unknown), "answer {i}");
        assert_eq!(gate.spent_today(), REGION_CHECK_TICKET_SATS, "answer {i}: a seller's fault says nothing true of what left: its most is counted");
    }
}

/// The wallet refuses the tunnel having paid for it (a prepaid ticket with no final answer yet, which
/// its `charged_sats` counts): the check counts what the answer says left, not nothing and not its most.
#[test]
fn a_region_check_refused_with_a_pending_ticket_counts_what_the_answer_says() {
    use xbt_vpn::buyer::CheckWaits;
    use xbt_vpn::holds::CheckGate;
    let (s, at) = region_check_setup(170);
    s.buyer.set_check_waits(CheckWaits { open: Duration::from_secs(5), read: Duration::from_secs(5), answer: Duration::from_secs(2) });
    let answer = r#"{"verdict":"deny","rule":"ticket_prepay_pending","reason":"no final answer yet","rail":"ticket","charged_sats":1003}"#;
    let w = fake_wallet_full(at, None, false, Some(700), Ends::AnswersFirst(answer));
    s.buyer.set_wallet(Some(w.wallet.clone()));
    let e = german_exit(&s, at, "paid-exit", 2_000_000);
    let mut gate = CheckGate::default();
    s.rt.block_on(s.buyer.check_region(&mut gate, &e));
    assert_eq!(gate.spent_today(), 1003);
    assert!(xbt_vpn::paid::left_sats(&serde_json::from_str(answer).unwrap()) == Some(1003));
}

/// A check's most is counted, and on disk, before its tunnel is asked for: the wallet, called, finds
/// it reserved in the gate's file; once done, the file counts what left.
#[test]
fn a_region_checks_cost_is_on_disk_before_the_wallet_is_asked() {
    use xbt_vpn::buyer::REGION_CHECK_TICKET_SATS;
    use xbt_vpn::holds::CheckGate;
    use xbt_vpn::region::RegionCheck;
    let (s, at) = region_check_setup(150);
    let w = fake_wallet_selling(at, 900);
    s.buyer.set_wallet(Some(w.wallet.clone()));
    let e = german_exit(&s, at, "paid-exit", 2_000_000);
    let dir = tempdir_lite::Dir::new("gate");
    let file = dir.0.join("region-checks.json");
    *w.watch.lock().unwrap() = Some(file.clone());
    let mut gate = CheckGate::load(&file);
    assert_eq!(s.rt.block_on(s.buyer.check_region(&mut gate, &e)), Some(RegionCheck::Verified));
    let seen = w.seen_on_call.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    let then: serde_json::Value = serde_json::from_str(&seen[0]).unwrap_or_else(|_| panic!("no gate on disk when the wallet was asked: {seen:?}"));
    assert_eq!(then["reserved"][0], "paid-exit", "reserved before the wallet was asked: {then}");
    assert_eq!(then["spent"][1].as_u64(), Some(REGION_CHECK_TICKET_SATS), "its most counted: {then}");
    let after: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert!(after["reserved"].is_null(), "{after}");
    assert_eq!(after["spent"][1].as_u64(), Some(900), "settled to what left: {after}");
}

/// A check whose cost can't be kept on disk is not paid for: the wallet is never asked.
#[test]
fn a_region_check_whose_cost_cannot_be_kept_never_asks_the_wallet() {
    use xbt_vpn::holds::CheckGate;
    let (s, at) = region_check_setup(152);
    let w = fake_wallet_selling(at, 900);
    s.buyer.set_wallet(Some(w.wallet.clone()));
    let e = german_exit(&s, at, "paid-exit", 2_000_000);
    let dir = tempdir_lite::Dir::new("gate");
    let mut gate = CheckGate::load(&dir.0.join("missing-dir").join("region-checks.json"));
    assert_eq!(s.rt.block_on(s.buyer.check_region(&mut gate, &e)), None);
    assert!(w.asked.lock().unwrap().is_empty(), "the wallet was asked: {:?}", w.asked.lock().unwrap());
    assert_eq!((gate.spent_today(), w.left.load(std::sync::atomic::Ordering::SeqCst)), (0, 0));
}

/// Ten priced exits announced under ten fresh operator keys (so no operator's failures stop them),
/// each in the region the phone's policy asks for, each shop's ticket 1,500 sats and the buyer with
/// credit at none: the checks buy tickets, and the day's checks move no more than the day's budget
/// out of the wallet, counted by what the wallet answered. An exit no policy would take is not
/// checked at all, one announced free but given a paid tunnel is paid for under the same gate, and
/// one whose ticket is more than a check may move is refused before paying.
#[test]
fn ten_fresh_exits_cannot_spend_past_the_days_region_check_budget() {
    use std::sync::atomic::Ordering;
    use xbt_vpn::buyer::REGION_CHECK_TICKET_SATS;
    use xbt_vpn::holds::{CheckGate, CHECK_SATS_PER_DAY};
    use xbt_vpn::region::RegionCheck;
    let (s, at) = region_check_setup(126);
    let w = fake_wallet_selling(at, 1_500);
    s.buyer.set_wallet(Some(w.wallet.clone()));
    let mut gate = CheckGate::default();
    // not wanted: nobody asked for France
    let fr = ExitInfo { region: "FR".into(), ..german_exit(&s, at, "fr", 2_000_000) };
    assert_eq!(s.rt.block_on(s.buyer.check_region(&mut gate, &fr)), None);
    assert!(w.asked.lock().unwrap().is_empty(), "an exit no policy would take is never paid to check");
    let mut results = Vec::new();
    for i in 0..10 {
        // one announced free, its tunnel paid all the same
        let e = german_exit(&s, at, &format!("sybil{i}"), if i == 0 { 0 } else { 2_000_000 });
        results.push(s.rt.block_on(s.buyer.check_region(&mut gate, &e)));
    }
    let left = w.left.load(Ordering::SeqCst);
    assert!(left <= CHECK_SATS_PER_DAY, "{left} sats left for a day's region checks, the budget is {CHECK_SATS_PER_DAY}");
    // 0 + 2,000 fits 4,000, then 1,500 + 2,000, then 3,000 + 2,000 does not: two checks, 3,000 sats
    assert_eq!(left, 3_000);
    assert_eq!(gate.spent_today(), left, "the gate counts what left");
    assert_eq!(results.iter().filter(|r| **r == Some(RegionCheck::Verified)).count(), 2, "{results:?}");
    assert_eq!(results.iter().filter(|r| r.is_none()).count(), 8, "{results:?}");
    assert!(w.asked.lock().unwrap().iter().all(|p| p["max_sats"].as_u64() == Some(REGION_CHECK_TICKET_SATS)));
    // a shop whose ticket is more than a check may move: refused before anything is paid, and the
    // check counts nothing against the day
    let (s2, at2) = region_check_setup(128);
    let big = fake_wallet_selling(at2, REGION_CHECK_TICKET_SATS + 1);
    s2.buyer.set_wallet(Some(big.wallet.clone()));
    let e = german_exit(&s2, at2, "big", 2_000_000);
    let mut gate = CheckGate::default();
    assert_eq!(s2.rt.block_on(s2.buyer.check_region(&mut gate, &e)), Some(RegionCheck::Unknown));
    assert_eq!((big.left.load(Ordering::SeqCst), gate.spent_today()), (0, 0));
}
