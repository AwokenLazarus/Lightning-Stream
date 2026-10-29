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
use xbt_iroh_link::{Hints, Link, Options, Relays, ALPN_VPN};
use xbt_vpn::buyer::{Buyer, Device as BuyerDevice};
use xbt_vpn::exit::{serve_buyer, ExitConfig};
use xbt_vpn::filter::Policy;
use xbt_vpn::meter::Meter;
use xbt_vpn::router::{ExitInfo, Mode, Router};
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
    buyer: Arc<Buyer>,
    exit_meter: Arc<Meter>,
    wg_addr: SocketAddr,
    endpoint_public: [u8; 32],
    phone_private: [u8; 32],
    rt: tokio::runtime::Handle,
}

/// An exit (or none), the buyer's link, router, stack and WireGuard endpoint with one phone.
fn setup(seed: u8, with_exit: bool, phone_limit: Option<u64>) -> Setup {
    let opts = |serving| Options { relays: Relays::None, serving, private: false, lookup: None };
    let mut links = Vec::new();
    let exit_meter = Arc::new(Meter::default());
    let buyer_link = Link::start_alpn([seed + 1; 32], opts(false), ALPN_VPN).unwrap();
    let mut router = Router::new(Mode::Best, None);
    if with_exit {
        let exit = Link::start_alpn([seed; 32], opts(true), ALPN_VPN).unwrap();
        let cfg = Arc::new(ExitConfig { policy: Policy { allow_non_public: true, ..Policy::default() }, ..ExitConfig::default() });
        let m = exit_meter.clone();
        exit.accept_with(move |conn| serve_buyer(conn, cfg.clone(), m.clone()));
        let id = exit.endpoint_id();
        let direct = exit.hints(Duration::from_secs(1)).direct.into_iter().filter(|a| a.is_ipv4()).collect();
        buyer_link.learn(&id, Hints { relays: vec![], direct }).unwrap();
        router.upsert(ExitInfo { id, region: "XX".into(), price_msat_per_gb: 2000, rtt_ms: None, mbit_s: None, healthy: true });
        links.push(exit);
    }
    let (phone_private, phone_public) = keypair();
    let (endpoint_private, endpoint_public) = keypair();
    let dev = Arc::new(BuyerDevice { name: "phone".into(), meter: Meter::default(), limit_bytes: phone_limit });
    let buyer = Buyer::new(buyer_link.clone(), router, HashMap::from([(IpAddr::V4(PHONE_IP), dev)]));
    let wg = WgEndpoint::new(endpoint_private, &[WgPeer { public: phone_public, tunnel_ip: PHONE_IP }]);
    let rt = buyer_link.runtime();
    let (to_stack, from_devices) = mpsc::channel::<Bytes>(4096);
    let (to_devices, from_stack) = mpsc::unbounded_channel::<Bytes>();
    let sock = rt.block_on(UdpSocket::bind("127.0.0.1:0")).unwrap();
    let wg_addr = sock.local_addr().unwrap();
    rt.spawn(buyer.clone().run(from_devices, to_devices));
    rt.spawn(wg.run(sock, to_stack, from_stack));
    links.push(buyer_link);
    Setup { _links: links, buyer, exit_meter, wg_addr, endpoint_public, phone_private, rt }
}

/// The phone: downloads from `to` through WireGuard until the server closes or `deadline` passes.
async fn phone_download(s: &Setup, to: SocketAddr, deadline: Duration) -> usize {
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
    sockets.get_mut::<tcp::Socket>(h).connect(iface.context(), (IpAddress::v4(o[0], o[1], o[2], o[3]), to.port()), 40000).unwrap();
    let (start, mut got, mut buf) = (Instant::now(), 0usize, vec![0u8; 1 << 16]);
    let mut seen_open = false;
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
        if seen_open && !ts.is_open() {
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
    got
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
