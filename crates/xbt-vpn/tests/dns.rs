//! With private exits, a device's DNS is answered by the buyer's own resolver over DNS-over-TLS
//! through the tunnel: the question never reaches the exit as DNS. Where DNS-over-TLS is blocked, the
//! buyer falls back to DNS-over-HTTPS (HTTP/2), and keeps using it.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket as StdUdp};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use xbt_iroh_link::{Hints, Link, Options, Relays, ALPN_VPN};
use xbt_vpn::buyer::{Buyer, Device, EncryptedDns};
use xbt_vpn::exit::{serve_buyer, ExitConfig};
use xbt_vpn::filter::Policy;
use xbt_vpn::meter::Meter;
use xbt_vpn::router::{ExitInfo, Mode, Router};

fn lan_ip() -> IpAddr {
    let s = StdUdp::bind("0.0.0.0:0").unwrap();
    s.connect("192.0.2.1:9").unwrap();
    s.local_addr().unwrap().ip()
}

fn sum16(data: &[u8], mut acc: u32) -> u32 {
    for c in data.chunks(2) {
        acc += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// An IPv4 UDP packet with valid checksums.
fn udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let (IpAddr::V4(s), IpAddr::V4(d)) = (src.ip(), dst.ip()) else { panic!() };
    let ulen = 8 + payload.len();
    let mut u = Vec::with_capacity(ulen);
    u.extend_from_slice(&src.port().to_be_bytes());
    u.extend_from_slice(&dst.port().to_be_bytes());
    u.extend_from_slice(&(ulen as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(payload);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&s.octets());
    pseudo.extend_from_slice(&d.octets());
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&(ulen as u16).to_be_bytes());
    let c = fold(sum16(&u, sum16(&pseudo, 0)));
    u[6..8].copy_from_slice(&c.to_be_bytes());
    let mut ip = vec![0x45, 0, 0, 0, 0, 1, 0, 0, 64, 17, 0, 0];
    ip[2..4].copy_from_slice(&((20 + ulen) as u16).to_be_bytes());
    ip.extend_from_slice(&s.octets());
    ip.extend_from_slice(&d.octets());
    let hc = fold(sum16(&ip, 0));
    ip[10..12].copy_from_slice(&hc.to_be_bytes());
    ip.extend_from_slice(&u);
    ip
}

/// A DNS-over-TLS server for `dot.test` that answers every question with its first byte flipped,
/// counting the questions.
fn dot_server() -> (SocketAddr, rustls::RootCertStore, Arc<AtomicUsize>) {
    let ck = rcgen::generate_simple_self_signed(vec!["dot.test".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ck.cert.der().clone()).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(ck.signing_key.serialize_der().into());
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![ck.cert.der().clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let port = l.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let c2 = count.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let l = tokio::net::TcpListener::from_std(l).unwrap();
            while let Ok((tcp, _)) = l.accept().await {
                let (acceptor, c2) = (acceptor.clone(), c2.clone());
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                    let mut len = [0u8; 2];
                    if tls.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
                    if tls.read_exact(&mut q).await.is_err() {
                        return;
                    }
                    c2.fetch_add(1, Ordering::SeqCst);
                    q[0] ^= 0xff;
                    let mut a = len.to_vec();
                    a.extend_from_slice(&q);
                    let _ = tls.write_all(&a).await;
                    let _ = tls.flush().await;
                });
            }
        });
    });
    (SocketAddr::new(lan_ip(), port), roots, count)
}

#[test]
fn a_private_exits_buyer_answers_dns_itself_and_the_exit_never_sees_it() {
    let (dot, roots, asked) = dot_server();
    let opts = |serving| Options { relays: Relays::None, serving, private: false, lookup: None };
    let exit = Link::start_alpn([150; 32], opts(true), ALPN_VPN).unwrap();
    let exit_meter = Arc::new(Meter::default());
    // a test exit reaches this machine's network (where the test resolver is); a real one never does
    let cfg = Arc::new(ExitConfig { policy: Policy { allow_non_public: true, ..Policy::default() }, ..ExitConfig::default() });
    let m = exit_meter.clone();
    exit.accept_with(move |conn| serve_buyer(conn, cfg.clone(), m.clone()));
    let buyer_link = Link::start_alpn([151; 32], opts(false), ALPN_VPN).unwrap();
    let id = exit.endpoint_id();
    let direct = exit.hints(Duration::from_secs(1)).direct.into_iter().filter(|a| a.is_ipv4()).collect();
    buyer_link.learn(&id, Hints { relays: vec![], direct }).unwrap();
    let mut router = Router::new(Mode::Best, None);
    router.upsert(ExitInfo { id, region: "XX".into(), price_msat_per_gb: 2000, rtt_ms: None, mbit_s: None, healthy: true, ..ExitInfo::default() });
    let phone: IpAddr = Ipv4Addr::new(10, 66, 0, 2).into();
    let dev = Arc::new(Device { name: "phone".into(), meter: Meter::default(), limit_bytes: None, requirements: None });
    let dns = EncryptedDns::with_roots(dot, "dot.test", roots).unwrap();
    let buyer = Buyer::new(buyer_link.clone(), router, HashMap::from([(phone, dev)]), Some(dns));
    let rt = buyer_link.runtime();
    let (to_stack, from_devices) = mpsc::channel::<Bytes>(64);
    let (to_devices, mut from_stack) = mpsc::unbounded_channel::<Bytes>();
    rt.spawn(buyer.run(from_devices, to_devices));

    // the phone asks a public resolver's plain DNS, as a device would
    let query = [0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1];
    let src = SocketAddr::new(phone, 51000);
    let asked_resolver: SocketAddr = "203.0.113.53:53".parse().unwrap();
    let answer = rt.block_on(async {
        to_stack.send(Bytes::from(udp_packet(src, asked_resolver, &query))).await.unwrap();
        let p = tokio::time::timeout(Duration::from_secs(20), from_stack.recv()).await.expect("an answer").unwrap();
        let ihl = usize::from(p[0] & 0x0f) * 4;
        p[ihl + 8..].to_vec()
    });
    assert_eq!(answer[0], query[0] ^ 0xff, "answered by the buyer's own resolver over TLS");
    assert_eq!(&answer[1..], &query[1..]);
    assert_eq!(asked.load(Ordering::SeqCst), 1);
    // the exit carried only the encrypted connection to the buyer's resolver: no DNS datagram
    let c = exit_meter.counts();
    assert_eq!(c.dropped, 0, "nothing was sent to the address the phone asked");
    assert!(c.up_bytes > query.len() as u64, "the exit saw TLS, not the question");
}

/// A DNS-over-HTTPS server for `dot.test` speaking HTTP/2 only, answering POST `/dns-query` with the
/// question's first byte flipped, counting the questions.
fn doh_server() -> (SocketAddr, rustls::RootCertStore, Arc<AtomicUsize>) {
    let ck = rcgen::generate_simple_self_signed(vec!["dot.test".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ck.cert.der().clone()).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(ck.signing_key.serialize_der().into());
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![ck.cert.der().clone()], key)
        .unwrap();
    // HTTP/2 only, like a resolver that refuses HTTP/1.1
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let port = l.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let c2 = count.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let l = tokio::net::TcpListener::from_std(l).unwrap();
            while let Ok((tcp, _)) = l.accept().await {
                let (acceptor, c2) = (acceptor.clone(), c2.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else { return };
                    let Ok(mut h2c) = h2::server::handshake(tls).await else { return };
                    while let Some(Ok((req, mut respond))) = h2c.accept().await {
                        let ok = req.method() == http::Method::POST && req.uri().path() == "/dns-query";
                        let mut body = req.into_body();
                        let mut q = Vec::new();
                        while let Some(Ok(chunk)) = body.data().await {
                            let _ = body.flow_control().release_capacity(chunk.len());
                            q.extend_from_slice(&chunk);
                        }
                        if !ok || q.len() < 12 {
                            let _ = respond.send_response(http::Response::builder().status(400).body(()).unwrap(), true);
                            continue;
                        }
                        c2.fetch_add(1, Ordering::SeqCst);
                        q[0] ^= 0xff;
                        let resp = http::Response::builder().status(200).header("content-type", "application/dns-message").body(()).unwrap();
                        if let Ok(mut send) = respond.send_response(resp, false) {
                            let _ = send.send_data(Bytes::from(q), true);
                        }
                    }
                });
            }
        });
    });
    (SocketAddr::new(lan_ip(), port), roots, count)
}

/// An address on this machine where nothing listens: DNS-over-TLS "blocked" (refused at once).
fn closed_port() -> SocketAddr {
    let l = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    SocketAddr::new(lan_ip(), port)
}

#[test]
fn where_dns_over_tls_is_blocked_the_buyer_asks_over_https_and_keeps_doing_so() {
    let (doh, roots, asked) = doh_server();
    let opts = |serving| Options { relays: Relays::None, serving, private: false, lookup: None };
    let exit = Link::start_alpn([152; 32], opts(true), ALPN_VPN).unwrap();
    let cfg = Arc::new(ExitConfig { policy: Policy { allow_non_public: true, ..Policy::default() }, ..ExitConfig::default() });
    let m = Arc::new(Meter::default());
    exit.accept_with(move |conn| serve_buyer(conn, cfg.clone(), m.clone()));
    let buyer_link = Link::start_alpn([153; 32], opts(false), ALPN_VPN).unwrap();
    let id = exit.endpoint_id();
    let direct = exit.hints(Duration::from_secs(1)).direct.into_iter().filter(|a| a.is_ipv4()).collect();
    buyer_link.learn(&id, Hints { relays: vec![], direct }).unwrap();
    let mut router = Router::new(Mode::Best, None);
    router.upsert(ExitInfo { id, region: "XX".into(), price_msat_per_gb: 2000, healthy: true, ..ExitInfo::default() });
    let phone: IpAddr = Ipv4Addr::new(10, 66, 0, 2).into();
    let dev = Arc::new(Device { name: "phone".into(), meter: Meter::default(), limit_bytes: None, requirements: None });
    // DNS-over-TLS goes to a port nothing answers on; DNS-over-HTTPS to the test server
    let dns = EncryptedDns::with_roots(closed_port(), "dot.test", roots).unwrap().with_https(doh, "/dns-query");
    let buyer = Buyer::new(buyer_link.clone(), router, HashMap::from([(phone, dev)]), Some(dns));
    let rt = buyer_link.runtime();
    let (to_stack, from_devices) = mpsc::channel::<Bytes>(64);
    let (to_devices, mut from_stack) = mpsc::unbounded_channel::<Bytes>();
    rt.spawn(buyer.run(from_devices, to_devices));

    let asked_resolver: SocketAddr = "203.0.113.53:53".parse().unwrap();
    let mut ask = |id: u8, port: u16| {
        let query = [id, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1];
        let src = SocketAddr::new(phone, port);
        let start = std::time::Instant::now();
        let answer = rt.block_on(async {
            to_stack.send(Bytes::from(udp_packet(src, asked_resolver, &query))).await.unwrap();
            let p = tokio::time::timeout(Duration::from_secs(20), from_stack.recv()).await.expect("an answer").unwrap();
            let ihl = usize::from(p[0] & 0x0f) * 4;
            p[ihl + 8..].to_vec()
        });
        assert_eq!(answer[0], query[0] ^ 0xff, "answered by the resolver over HTTPS");
        assert_eq!(&answer[1..], &query[1..]);
        start.elapsed()
    };
    let first = ask(0xab, 51000);
    assert_eq!(asked.load(Ordering::SeqCst), 1);
    // once DNS-over-TLS has failed, later questions go straight to HTTPS: no wait on TLS first
    let second = ask(0xac, 51001);
    assert_eq!(asked.load(Ordering::SeqCst), 2);
    assert!(second < Duration::from_secs(3), "the second question did not wait on DNS-over-TLS ({second:?}, first {first:?})");
}
