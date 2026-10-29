//! Two hops on this machine, no relay: a buyer's flow sealed for an exit and carried by a first hop.
//! The download arrives whole; the exit sees the first hop's link, never the buyer's; a buyer that
//! expects another exit key never gets a session; the exit refuses a stream that is not sealed.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use xbt_iroh_link::{Hints, Link, LinkConnection, Options, Relays, ALPN_VPN, ALPN_VPN_HOP, ALPN_VPN_SEALED};
use xbt_vpn::exit::{serve_buyer, ExitConfig};
use xbt_vpn::filter::Policy;
use xbt_vpn::flow::{open_tcp_on, Opened};
use xbt_vpn::hop::{open_sealed, serve_hop, serve_sealed, HopConfig, SealedBuyers};
use xbt_vpn::meter::Meter;
use xbt_vpn::sealed;

fn lan_ip() -> IpAddr {
    let s = UdpSocket::bind("0.0.0.0:0").unwrap();
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

fn direct(l: &Link) -> Hints {
    Hints { relays: vec![], direct: l.hints(Duration::from_secs(1)).direct.into_iter().filter(|a| a.is_ipv4()).collect() }
}

struct Three {
    _links: Vec<Arc<Link>>,
    exit_secret: [u8; 32],
    exit_id: String,
    hop_id: String,
    /// The links that connected to the exit, as the exit saw them.
    exit_saw: Arc<Mutex<Vec<String>>>,
    exit_meter: Arc<Meter>,
    hop_meter: Arc<Meter>,
    buyers: Arc<SealedBuyers>,
    /// The buyer's connection to the first hop.
    to_hop: LinkConnection,
    rt: tokio::runtime::Handle,
}

/// An exit (serving its own buyers and sealed ones), a first hop, and a buyer connected to the hop.
fn three(seed: u8) -> Three {
    let opts = |serving| Options { relays: Relays::None, serving, private: false, lookup: None };
    let exit_secret = [seed; 32];
    let exit = Link::start_alpns(exit_secret, opts(true), ALPN_VPN, &[ALPN_VPN, ALPN_VPN_SEALED]).unwrap();
    let hop = Link::start_alpns([seed + 1; 32], opts(true), ALPN_VPN_HOP, &[ALPN_VPN_HOP]).unwrap();
    let buyer = Link::start_alpn([seed + 2; 32], opts(false), ALPN_VPN).unwrap();

    let cfg = Arc::new(ExitConfig { policy: Policy { allow_non_public: true, ..Policy::default() }, ..ExitConfig::default() });
    let (exit_meter, buyers, exit_saw) = (Arc::new(Meter::default()), Arc::new(SealedBuyers::default()), Arc::new(Mutex::new(Vec::new())));
    let tls = sealed::exit_config(&exit_secret);
    {
        let (m, b, saw) = (exit_meter.clone(), buyers.clone(), exit_saw.clone());
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
    let hop_meter = Arc::new(Meter::default());
    {
        let (h, m, cfg) = (hop.clone(), hop_meter.clone(), Arc::new(HopConfig::default()));
        hop.accept_with(move |conn| serve_hop(h.clone(), conn, cfg.clone(), m.clone()));
    }
    let (exit_id, hop_id) = (exit.endpoint_id(), hop.endpoint_id());
    // the hop finds the exit (in use, from the exit's listing on Nostr); the buyer finds the hop
    hop.learn(&exit_id, direct(&exit)).unwrap();
    buyer.learn(&hop_id, direct(&hop)).unwrap();
    let rt = buyer.runtime();
    let to_hop = rt.block_on(buyer.connect_conn_alpn(&hop_id, ALPN_VPN_HOP)).unwrap();
    Three { _links: vec![exit, hop, buyer], exit_secret, exit_id, hop_id, exit_saw, exit_meter, hop_meter, buyers, to_hop, rt }
}

#[test]
fn a_sealed_flow_through_a_first_hop_arrives_whole_and_the_exit_sees_only_the_hop() {
    let t = three(80);
    let n = 3_000_000;
    let to = tcp_server(n);
    let exit_public = sealed::public_of(&t.exit_secret);
    assert_eq!(hex::encode(exit_public), t.exit_id, "an exit's link key is the key it seals with");
    let got = t.rt.block_on(async {
        let mut flow = open_sealed(&t.to_hop, &exit_public, &[], sealed::buyer_config(&[33; 32], &exit_public)).await.unwrap();
        assert_eq!(open_tcp_on(&mut flow, to).await.unwrap(), Opened::Yes);
        let mut all = Vec::new();
        flow.read_to_end(&mut all).await.unwrap();
        all.len()
    });
    assert_eq!(got, n);
    // the exit was reached by the hop's link only: the buyer's link never connected to it
    assert_eq!(*t.exit_saw.lock().unwrap(), vec![t.hop_id.clone()]);
    // the exit metered the flow; the hop counted somewhat more (the TLS session's own bytes)
    let (exit_down, hop_down) = (t.exit_meter.counts().down_bytes, t.hop_meter.counts().down_bytes);
    assert_eq!(exit_down, n as u64);
    assert!(hop_down >= n as u64, "the hop carried {hop_down} bytes");
    assert_eq!(t.buyers.len(), 1, "the exit knows one sealed buyer, by its key");
}

#[test]
fn a_buyer_expecting_another_exit_key_gets_no_session() {
    let t = three(90);
    let wrong = sealed::public_of(&[1; 32]);
    let exit_public = sealed::public_of(&t.exit_secret);
    let r = t.rt.block_on(async {
        // the hop is asked for the real exit, but the buyer expects another key: no session
        open_sealed(&t.to_hop, &exit_public, &[], sealed::buyer_config(&[34; 32], &wrong)).await.map(|_| ())
    });
    assert!(r.is_err());
}

#[test]
fn an_exit_refuses_a_stream_that_is_not_sealed() {
    let t = three(100);
    let to = tcp_server(10);
    let exit_public = sealed::public_of(&t.exit_secret);
    let read = t.rt.block_on(async {
        // write the hop's header for the exit, then a plain flow header instead of a TLS session
        let (mut send, mut recv) = t.to_hop.open_bi().await.unwrap();
        let mut h = b"XH0".to_vec();
        h.extend_from_slice(&exit_public);
        h.push(0);
        send.write_all(&h).await.unwrap();
        let mut plain = b"XF0\x01".to_vec();
        if let IpAddr::V4(v4) = to.ip() {
            plain.push(4);
            plain.extend_from_slice(&v4.octets());
        }
        plain.extend_from_slice(&to.port().to_be_bytes());
        send.write_all(&plain).await.unwrap();
        let mut buf = Vec::new();
        tokio::time::timeout(Duration::from_secs(25), tokio::io::AsyncReadExt::read_to_end(&mut recv, &mut buf)).await.ok().and_then(|r| r.ok()).map(|_| buf)
    });
    // the exit answers nothing a plain flow could use: no "opened" byte, no data
    assert!(read.unwrap_or_default().first() != Some(&0u8));
    assert_eq!(t.exit_meter.counts().down_bytes, 0);
}
