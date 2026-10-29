//! A buyer's flows through a seller's exit to servers on this machine, no relay: a TCP download
//! arrives whole and is metered; UDP is answered; the seller's own network and blocked ports are
//! refused; the speed limit holds.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use xbt_iroh_link::{Hints, Link, LinkConnection, Options, Relays, ALPN_VPN};
use xbt_vpn::exit::{serve_buyer, ExitConfig};
use xbt_vpn::filter::Policy;
use xbt_vpn::flow::{open_tcp, recv_udp, send_udp, Opened};
use xbt_vpn::meter::Meter;

/// This machine's address on its network.
fn lan_ip() -> IpAddr {
    let s = UdpSocket::bind("0.0.0.0:0").unwrap();
    s.connect("192.0.2.1:9").unwrap();
    s.local_addr().unwrap().ip()
}

/// A server that sends `n` bytes to each connection, then closes it.
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

/// A UDP server that answers each datagram with the same bytes reversed.
fn udp_server() -> SocketAddr {
    let s = UdpSocket::bind("0.0.0.0:0").unwrap();
    let port = s.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = s.recv_from(&mut buf) {
            buf[..n].reverse();
            let _ = s.send_to(&buf[..n], from);
        }
    });
    SocketAddr::new(lan_ip(), port)
}

/// An exit with this config and a buyer's connection to it, on loopback with no relay.
fn to_exit(seed: u8, cfg: ExitConfig) -> (Arc<Link>, Arc<Link>, Arc<Meter>, LinkConnection) {
    let opts = |serving| Options { relays: Relays::None, serving, private: false, lookup: None };
    let exit = Link::start_alpn([seed; 32], opts(true), ALPN_VPN).unwrap();
    let buyer = Link::start_alpn([seed + 1; 32], opts(false), ALPN_VPN).unwrap();
    let meter = Arc::new(Meter::default());
    let (cfg, m) = (Arc::new(cfg), meter.clone());
    exit.accept_with(move |conn| serve_buyer(conn, cfg.clone(), m.clone()));
    let id = exit.endpoint_id();
    let direct = exit.hints(Duration::from_secs(1)).direct.into_iter().filter(|a| a.is_ipv4()).collect();
    buyer.learn(&id, Hints { relays: vec![], direct }).unwrap();
    let conn = buyer.connect_conn(&id).unwrap();
    (exit, buyer, meter, conn)
}

/// Exits for tests on one machine reach this machine's own network; a real exit never does.
fn test_policy() -> Policy {
    Policy { allow_non_public: true, ..Policy::default() }
}

#[test]
fn a_tcp_download_crosses_the_exit_whole_and_is_metered() {
    let n = 8 << 20;
    let to = tcp_server(n);
    let (_e, buyer, meter, conn) = to_exit(30, ExitConfig { policy: test_policy(), ..ExitConfig::default() });
    let got = buyer.runtime().block_on(async {
        let (opened, _send, mut recv) = open_tcp(&conn, to).await.unwrap();
        assert_eq!(opened, Opened::Yes);
        recv.read_to_end(64 << 20).await.unwrap().len()
    });
    assert_eq!(got, n, "every byte arrived");
    assert_eq!(meter.counts().down_bytes, n as u64, "metered exactly");
}

#[test]
fn a_real_exit_never_reaches_the_sellers_own_network() {
    let to = tcp_server(1024);
    // the default config refuses this machine's directly reached networks, whatever their range
    let (_e, buyer, meter, conn) = to_exit(40, ExitConfig::default());
    let opened = buyer.runtime().block_on(async { open_tcp(&conn, to).await.unwrap().0 });
    assert_eq!(opened, Opened::Refused);
    assert_eq!(meter.counts().dropped, 1);
}

#[test]
fn a_blocked_port_is_refused_and_an_unreachable_one_says_so() {
    let to = tcp_server(1024);
    let mut policy = test_policy();
    policy.blocked_ports.insert(to.port());
    let (_e, buyer, _m, conn) = to_exit(50, ExitConfig { policy, connect_timeout: Duration::from_secs(2), ..ExitConfig::default() });
    buyer.runtime().block_on(async {
        assert_eq!(open_tcp(&conn, to).await.unwrap().0, Opened::Refused);
        // nothing listens on port 9 here
        let closed = SocketAddr::new(to.ip(), 9);
        assert_eq!(open_tcp(&conn, closed).await.unwrap().0, Opened::Unreachable);
    });
}

#[test]
fn udp_is_carried_and_answered() {
    let to = udp_server();
    let (_e, buyer, meter, conn) = to_exit(60, ExitConfig { policy: test_policy(), ..ExitConfig::default() });
    buyer.runtime().block_on(async {
        for i in 0..5u8 {
            send_udp(&conn, 7, to, &[i, 1, 2, 3]).unwrap();
            let (flow, back) = tokio::time::timeout(Duration::from_secs(5), recv_udp(&conn)).await.expect("an answer").unwrap();
            assert_eq!((flow, back.to_vec()), (7, vec![3, 2, 1, i]));
        }
    });
    let c = meter.counts();
    assert_eq!((c.up_bytes, c.down_bytes), (20, 20));
}

#[test]
fn the_speed_limit_holds() {
    let n = 3 << 20;
    let to = tcp_server(n);
    let cfg = ExitConfig { policy: test_policy(), buyer_bytes_per_sec: Some(1 << 20), ..ExitConfig::default() };
    let (_e, buyer, _m, conn) = to_exit(70, cfg);
    let took = buyer.runtime().block_on(async {
        let start = Instant::now();
        let (_, _s, mut recv) = open_tcp(&conn, to).await.unwrap();
        assert_eq!(recv.read_to_end(64 << 20).await.unwrap().len(), n);
        start.elapsed()
    });
    // one second's worth is in hand at the start, so 3 MiB at 1 MiB/s takes about two seconds
    assert!(took >= Duration::from_millis(1800), "took {took:?}");
}
