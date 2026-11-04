//! Which relay carries which direction of a relayed session (`docs/PAID-RELAYS.md`, "Who pays"):
//! a shop homed on one relay, a buyer homed on another, both private (relays only, no address
//! lookup), and a recording meter behind each relay. It prints what each relay carried, from whom
//! to whom. As run on 2026-11-04 the shop's answers went back through the shop's own home relay,
//! the one the buyer's requests came in on: iroh answers on the relay it heard from a peer on when
//! it knows no other relay for it. That is the case the paid meter charges to the sender
//! (`crate::paid`): the receiver didn't choose that relay, the sender did.
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iroh_relay::server::{self as relay, RelayConfig, ServerConfig};
use xbt_iroh_link::{Hints, Link, Options, Relays};
use xbt_stream_relay::meter::{Free, Gate, Meter};

const MB: u64 = 1_000_000;

fn secret() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::getrandom(&mut s).expect("random bytes");
    s
}

/// A sender and a receiver, by key.
type Pair = ([u8; 32], [u8; 32]);

/// Carries everything and records the bytes per (sender, receiver).
#[derive(Debug, Default)]
struct Recorder {
    free: Free,
    seen: Mutex<HashMap<Pair, u64>>,
}

impl Meter for Recorder {
    fn admit(&self, key: &[u8; 32]) -> Result<(), String> {
        self.free.admit(key)
    }
    fn ended(&self, key: &[u8; 32]) {
        self.free.ended(key)
    }
    fn connected(&self) -> usize {
        self.free.connected()
    }
    fn forward(&self, src: &[u8; 32], dst: &[u8; 32], len: usize) -> xbt_stream_relay::meter::Forward {
        *self.seen.lock().unwrap().entry((*src, *dst)).or_insert(0) += len as u64;
        xbt_stream_relay::meter::Forward::Yes
    }
}

impl Recorder {
    fn bytes(&self, src: &[u8; 32], dst: &[u8; 32]) -> u64 {
        self.seen.lock().unwrap().get(&(*src, *dst)).copied().unwrap_or(0)
    }
}

async fn start_relay(meter: Arc<dyn Meter>) -> (relay::Server, String) {
    let mut rc = RelayConfig::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    rc.access = Arc::new(Gate(meter));
    let mut sc = ServerConfig::default();
    sc.relay = Some(rc);
    let s = relay::Server::spawn(sc).await.expect("the relay starts");
    let url = format!("http://{}", s.http_addr().expect("http"));
    (s, url)
}

/// Answers any request with `n` bytes, `n` from `?bytes=`.
fn service() -> SocketAddr {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let addr = l.local_addr().expect("addr");
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut r = BufReader::new(c.try_clone().expect("clone"));
                let mut w = c;
                let mut first = String::new();
                if r.read_line(&mut first).unwrap_or(0) == 0 {
                    return;
                }
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                }
                let n: usize = first.split("bytes=").nth(1).and_then(|s| s.split(' ').next()).and_then(|s| s.parse().ok()).unwrap_or(0);
                let _ = w.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {n}\r\nConnection: close\r\n\r\n").as_bytes());
                let _ = w.write_all(&vec![7u8; n]);
            });
        }
    });
    addr
}

fn download(port: u16, bytes: u64) -> u64 {
    let Ok(mut c) = TcpStream::connect((Ipv4Addr::LOCALHOST, port)) else { return 0 };
    let _ = c.set_read_timeout(Some(Duration::from_secs(10)));
    if write!(c, "GET /film?bytes={bytes} HTTP/1.1\r\nHost: shop\r\n\r\n").is_err() {
        return 0;
    }
    let mut all = Vec::new();
    let _ = c.read_to_end(&mut all);
    let body = all.windows(4).position(|w| w == b"\r\n\r\n").map(|i| all.len() - i - 4).unwrap_or(0);
    body as u64
}

fn key_of(l: &Link) -> [u8; 32] {
    hex::decode(l.endpoint_id()).unwrap().try_into().unwrap()
}

#[test]
fn which_relay_carries_each_direction() {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let (shop_rec, buyer_rec) = (Arc::new(Recorder::default()), Arc::new(Recorder::default()));
    let (_s1, shop_relay) = rt.block_on(start_relay(shop_rec.clone()));
    let (_s2, buyer_relay) = rt.block_on(start_relay(buyer_rec.clone()));
    let opts = |url: &str, serving| Options { relays: Relays::Ours(vec![url.to_string()]), serving, private: true, lookup: None };
    let shop = Link::start_with(secret(), opts(&shop_relay, true)).expect("shop link");
    shop.serve(service());
    let _ = shop.hints(Duration::from_secs(15));
    let buyer = Link::start_with(secret(), opts(&buyer_relay, false)).expect("buyer link");
    let _ = buyer.hints(Duration::from_secs(15));
    let k = shop.endpoint_id();
    buyer.learn(&k, Hints { relays: vec![shop_relay.clone()], direct: vec![] }).expect("learn");
    let port = buyer.local_port(&k).expect("port");
    let end = Instant::now() + Duration::from_secs(60);
    let mut got = 0;
    while got != 2 * MB && Instant::now() < end {
        got = download(port, 2 * MB);
    }
    assert_eq!(got, 2 * MB, "the download went through");
    let (s, b) = (key_of(&shop), key_of(&buyer));
    let report = [("shop's relay", &shop_rec), ("buyer's relay", &buyer_rec)].map(|(n, r)| {
        format!("{n}: buyer->shop {} B, shop->buyer {} B", r.bytes(&b, &s), r.bytes(&s, &b))
    });
    eprintln!("ROUTES: {}", report.join("; "));
    // the answers (2 MB) are carried by one of the two relays: say which
    let via_buyer_home = buyer_rec.bytes(&s, &b) >= 2 * MB;
    let via_shop_home = shop_rec.bytes(&s, &b) >= 2 * MB;
    eprintln!("ROUTES: shop->buyer via the buyer's home relay: {via_buyer_home}; via the shop's: {via_shop_home}");
    assert!(shop_rec.bytes(&b, &s) > 0, "the buyer's requests reach the shop through the shop's home relay");
    assert!(via_buyer_home || via_shop_home);
}
