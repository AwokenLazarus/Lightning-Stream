//! Two link endpoints on this machine, no relay: packets cross the tunnel both ways, in datagrams
//! and on the stream, and a packet bigger than the tunnel MTU is refused.

use std::time::Duration;

use xbt_iroh_link::{Hints, Link, Options, Relays, ALPN_VPN};
use xbt_vpn::tunnel::{Tunnel, TUNNEL_MTU};

fn key(b: u8) -> [u8; 32] {
    [b; 32]
}

fn pair(seed: u8) -> (std::sync::Arc<Link>, std::sync::Arc<Link>, String) {
    let opts = |serving| Options { relays: Relays::None, serving, private: false, lookup: None };
    let exit = Link::start_alpn(key(seed), opts(true), ALPN_VPN).unwrap();
    let buyer = Link::start_alpn(key(seed + 1), opts(false), ALPN_VPN).unwrap();
    let id = exit.endpoint_id();
    let mut hints = exit.hints(Duration::from_secs(1));
    hints.direct.retain(|a| a.ip().is_loopback() || a.is_ipv4());
    buyer.learn(&id, Hints { relays: vec![], direct: hints.direct }).unwrap();
    (exit, buyer, id)
}

fn echo_exit(exit: &std::sync::Arc<Link>) {
    exit.accept_with(|conn| async move {
        let Ok(t) = Tunnel::accept(conn).await else { return };
        while let Ok(p) = t.recv().await {
            let mut back = p.to_vec();
            back.reverse();
            let _ = t.send(&back).await;
        }
    });
}

fn round_trip(allow_datagrams: bool, seed: u8) {
    let (exit, buyer, id) = pair(seed);
    echo_exit(&exit);
    let conn = buyer.connect_conn(&id).unwrap();
    buyer.runtime().block_on(async {
        let t = Tunnel::open(conn, allow_datagrams).await.unwrap();
        for len in [20usize, 600, TUNNEL_MTU] {
            let p: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            t.send(&p).await.unwrap();
            let back = tokio::time::timeout(Duration::from_secs(5), t.recv()).await.expect("an answer").unwrap();
            let mut expect = p.clone();
            expect.reverse();
            assert_eq!(back.to_vec(), expect, "a {len}-byte packet came back whole");
        }
        let too_big = vec![0u8; TUNNEL_MTU + 1];
        assert_eq!(t.send(&too_big).await.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
        let sent = t.sent();
        if allow_datagrams {
            assert!(sent.in_datagrams + sent.on_stream == 3);
        } else {
            assert_eq!((sent.in_datagrams, sent.on_stream), (0, 3), "stream mode never uses datagrams");
        }
    });
}

#[test]
fn packets_cross_the_tunnel_in_datagrams() {
    round_trip(true, 10);
}

#[test]
fn packets_cross_the_tunnel_on_the_stream() {
    round_trip(false, 20);
}
