//! A buyer's link reaches a seller's local HTTP service through the seller's link, offline: no relay,
//! direct addresses only.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use xbt_iroh_link::{host_for, Hints, Link, Relays};

fn secret() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::getrandom(&mut s).unwrap();
    s
}

/// A local HTTP/1.1 service that answers every request with `size` bytes and keeps the connection.
fn service(size: usize) -> u16 {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            let peer = c.peer_addr().unwrap().ip();
            assert!(peer.is_loopback() && peer != std::net::IpAddr::from(Ipv4Addr::LOCALHOST), "a buyer's streams come from its own loopback address, not {peer}");
            std::thread::spawn(move || {
                let mut r = BufReader::new(c.try_clone().unwrap());
                let mut w = c;
                let body = vec![b'x'; size];
                loop {
                    let mut line = String::new();
                    // request line and headers, up to the empty line
                    loop {
                        line.clear();
                        if r.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        if line == "\r\n" {
                            break;
                        }
                    }
                    let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n");
                    if w.write_all(head.as_bytes()).and_then(|_| w.write_all(&body)).is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

fn get(port: u16, host: &str, size: usize) -> Duration {
    let t = Instant::now();
    let mut c = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    write!(c, "GET /film HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").unwrap();
    // the head, then exactly the body: the stand-in service keeps the connection open
    let mut out = Vec::new();
    let mut buf = [0u8; 65536];
    let head_end = loop {
        let n = c.read(&mut buf).unwrap();
        assert!(n > 0, "the link closed before the answer's head");
        out.extend_from_slice(&buf[..n]);
        if let Some(i) = out.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    assert!(out.starts_with(b"HTTP/1.1 200 OK"));
    let mut body = out.len() - head_end;
    while body < size {
        let n = c.read(&mut buf).unwrap();
        assert!(n > 0, "the link closed after {body} of {size} bytes");
        body += n;
    }
    assert_eq!(body, size);
    t.elapsed()
}

#[test]
fn a_buyer_reaches_a_sellers_local_service_by_its_key_alone() {
    let size = 8 << 20;
    let upstream = service(size);
    let seller = Link::start(secret(), Relays::None, true).unwrap();
    seller.serve(([127, 0, 0, 1], upstream).into());
    let hints = seller.hints(Duration::from_millis(200));
    assert!(!hints.direct.is_empty(), "the seller found no address of its own");

    let buyer = Link::start(secret(), Relays::None, false).unwrap();
    buyer.learn(&seller.endpoint_id(), Hints { relays: vec![], direct: hints.direct }).unwrap();

    // by its link host name, as an HTTP client's resolver would
    let host = host_for(&seller.endpoint_id()).unwrap();
    let addrs = buyer.resolve(&format!("{host}:80")).unwrap().unwrap();
    let port = addrs[0].port();
    assert_eq!(buyer.resolve("example.com:80").map(|_| ()), None, "other names are not the link's");

    // a shop with no web address, once its transport document is verified
    let shop = format!("{}{}", "a".repeat(52), xbt_iroh_link::SHOP_SUFFIX);
    assert!(buyer.resolve(&format!("{shop}:80")).unwrap().is_err(), "an unbound shop never goes to DNS");
    buyer.bind_shop(&shop, &seller.endpoint_id()).unwrap();
    assert_eq!(buyer.resolve(&format!("{shop}:80")).unwrap().unwrap()[0].port(), port);

    // several requests over the one link; the first one pays for the handshake
    let first = get(port, &host, size);
    let mut rest = Duration::ZERO;
    for _ in 0..5 {
        rest += get(port, &host, size);
    }
    eprintln!("8 MiB over the link: first {first:?}, then {:?} each", rest / 5);
}

#[test]
fn a_key_that_is_not_32_bytes_is_refused() {
    let buyer = Link::start(secret(), Relays::None, false).unwrap();
    assert!(buyer.local_port("abcd").is_err());
    assert!(buyer.resolve("tooshort.link.invalid:80").unwrap().is_err());
}

#[test]
fn a_shop_on_several_keys_is_reached_through_one_that_answers() {
    let size = 1 << 20;
    let upstream = service(size);
    // one gateway on two keys; a third key the shop's document names is gone (never started)
    let a = Link::start(secret(), Relays::None, true).unwrap();
    let b = Link::start(secret(), Relays::None, true).unwrap();
    for l in [&a, &b] {
        l.serve(([127, 0, 0, 1], upstream).into());
    }
    let gone = Link::start(secret(), Relays::None, true).unwrap().endpoint_id();
    let shop = format!("{}{}", "b".repeat(52), xbt_iroh_link::SHOP_SUFFIX);
    for _ in 0..4 {
        let buyer = Link::start(secret(), Relays::None, false).unwrap();
        for l in [&a, &b] {
            buyer.learn(&l.endpoint_id(), Hints { relays: vec![], direct: l.hints(Duration::from_millis(200)).direct }).unwrap();
        }
        buyer.bind_shop_links(&shop, &[gone.clone(), a.endpoint_id(), b.endpoint_id()]).unwrap();
        let port = buyer.resolve(&format!("{shop}:80")).unwrap().unwrap()[0].port();
        get(port, &shop, size);
        get(port, &shop, size);
        // the same keys keep the port; another list is a new binding
        buyer.bind_shop_links(&shop, &[b.endpoint_id(), gone.clone(), a.endpoint_id()]).unwrap();
        assert_eq!(buyer.resolve(&format!("{shop}:80")).unwrap().unwrap()[0].port(), port);
        assert!(buyer.bind_shop_links(&shop, &[]).is_err());
    }
}
