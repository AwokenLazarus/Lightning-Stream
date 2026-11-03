//! A paid relay end to end, on this machine (`docs/PAID-RELAYS.md`): a real iroh relay with the paid
//! meter behind its access control, a shop and a buyer whose links reach each other only through it,
//! and the shop's payer buying credit through a stand-in for its wallet (which here credits the relay
//! directly, as the operator's gateway does once a ticket has paid for the request).
//!
//! It shows that the shop pays for the bytes the relay carried for it and no more, that the relay
//! stops carrying for the shop when it stops paying and carries again when it pays, and that a free
//! relay is unaffected.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh_relay::server::{self as relay, RelayConfig, ServerConfig};
use serde_json::{json, Value};
use xbt_iroh_link::relay_pay::{self, Bounds, Fetch, PaidRelay, RelayPayer, Step, Wallet};
use xbt_iroh_link::{Hints, Link, Options, Relays};
use xbt_stream_relay::credit::{self, TOKEN_HEADER};
use xbt_stream_relay::meter::{Free, Gate, Meter};
use xbt_stream_relay::paid::{Paid, PaidSettings};

const TOKEN: &str = "test-credit-token-0123456789abcdef";
const MB: u64 = 1_000_000;
const GRACE: u64 = 256 * 1024;

fn secret() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::getrandom(&mut s).expect("random bytes");
    s
}

/// Answers `GET /film?bytes=N` with N bytes.
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
                let n: u64 = first.split("bytes=").nth(1).and_then(|s| s.split(' ').next()).and_then(|s| s.parse().ok()).unwrap_or(0);
                if w.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {n}\r\nConnection: close\r\n\r\n").as_bytes()).is_err() {
                    return;
                }
                let block = vec![7u8; 16 << 10];
                let mut left = n;
                while left > 0 {
                    let k = left.min(block.len() as u64) as usize;
                    if w.write_all(&block[..k]).is_err() {
                        return;
                    }
                    left -= k as u64;
                }
            });
        }
    });
    addr
}

/// Fetch `bytes` through the buyer's link port: how many body bytes arrived before the end or a stall.
fn download(port: u16, bytes: u64, stall: Duration) -> u64 {
    let Ok(mut c) = TcpStream::connect((Ipv4Addr::LOCALHOST, port)) else { return 0 };
    let _ = c.set_read_timeout(Some(stall));
    if write!(c, "GET /film?bytes={bytes} HTTP/1.1\r\nHost: shop\r\n\r\n").is_err() {
        return 0;
    }
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match c.read(&mut b) {
            Ok(1) => head.push(b[0]),
            _ => return 0,
        }
    }
    let mut got = 0u64;
    let mut buf = vec![0u8; 64 << 10];
    while got < bytes {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n as u64,
        }
    }
    got
}

/// One HTTP request to the credit API: status and JSON body.
fn http(addr: SocketAddr, method: &str, target: &str, token: bool, body: &str) -> (u16, Value) {
    let mut c = TcpStream::connect(addr).expect("credit API");
    let tok = if token { format!("{TOKEN_HEADER}: {TOKEN}\r\n") } else { String::new() };
    write!(c, "{method} {target} HTTP/1.1\r\nHost: relay\r\n{tok}Content-Length: {}\r\n\r\n{body}", body.len()).unwrap();
    let mut out = String::new();
    c.read_to_string(&mut out).unwrap();
    let code = out.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    let body = out.split_once("\r\n\r\n").map(|x| x.1).unwrap_or("");
    (code, serde_json::from_str(body).unwrap_or(Value::Null))
}

fn path_of(url: &str) -> String {
    let rest = url.split_once("://").map(|x| x.1).unwrap_or(url);
    rest.find('/').map(|i| rest[i..].to_string()).unwrap_or_else(|| "/".into())
}

/// The shop's wallet: pays (here, credits the relay the way its gateway route would) while allowed.
struct StandInWallet {
    api: SocketAddr,
    allow: Arc<AtomicBool>,
    credit_msat: u64,
}

impl Wallet for StandInWallet {
    fn pay(&self, params: &Value) -> Result<Value, String> {
        if !self.allow.load(Ordering::SeqCst) {
            return Ok(json!({"verdict": "deny", "rule": "task_budget", "reason": "the most for relays today is spent"}));
        }
        assert_eq!(params["method"], "POST");
        assert_eq!(params["task"], relay_pay::DEFAULT_TASK);
        let (code, v) = http(self.api, "POST", &path_of(params["url"].as_str().unwrap()), true, params["body"].as_str().unwrap());
        assert_eq!(code, 200, "{v}");
        Ok(json!({"verdict": "allow", "status": 200, "price_msat": self.credit_msat.to_string()}))
    }
}

struct Get(SocketAddr);

impl Fetch for Get {
    fn get(&self, url: &str) -> Result<Value, String> {
        match http(self.0, "GET", &path_of(url), false, "") {
            (200, v) => Ok(v),
            (c, v) => Err(format!("{c}: {v}")),
        }
    }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// A plain-HTTP relay on loopback behind `meter`.
async fn start_relay(meter: Arc<dyn Meter>) -> (relay::Server, String) {
    let mut rc = RelayConfig::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    rc.access = Arc::new(Gate(meter));
    let mut sc = ServerConfig::default();
    sc.relay = Some(rc);
    let s = relay::Server::spawn(sc).await.expect("the relay starts");
    let url = format!("http://{}", s.http_addr().expect("http"));
    (s, url)
}

/// A shop serving the stand-in service and a buyer reaching it, both through `url` only.
fn shop_and_buyer(url: &str, shop_secret: [u8; 32]) -> (Arc<Link>, Arc<Link>, u16) {
    let opts = |serving| Options { relays: Relays::Ours(vec![url.to_string()]), serving, private: true, lookup: None };
    let shop = Link::start_with(shop_secret, opts(true)).expect("shop link");
    shop.serve(service());
    let _ = shop.hints(Duration::from_secs(15));
    let buyer = Link::start_with(secret(), opts(false)).expect("buyer link");
    let k = shop.endpoint_id();
    buyer.learn(&k, Hints { relays: vec![url.to_string()], direct: vec![] }).expect("learn");
    let port = buyer.local_port(&k).expect("port");
    (shop, buyer, port)
}

/// A download that may need a few tries while the links come up.
fn download_retrying(port: u16, bytes: u64, within: Duration) -> u64 {
    let end = Instant::now() + within;
    loop {
        let got = download(port, bytes, Duration::from_secs(10));
        if got == bytes || Instant::now() > end {
            return got;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[test]
fn a_shop_pays_for_what_is_carried_and_stops_being_carried_when_it_stops_paying() {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    // 1,000,000 msat a GB (1 msat a KB) and 2,000-msat credits: one credit is 2 MB. Nothing free.
    let terms = PaidSettings { enabled: true, msat_per_gb: 1_000_000, credit_msat: 2_000, grace_bytes: GRACE, free_bytes_per_day: 0,
                               inbound_pct: 100, inbound_allowance_bytes: MB, credit_token: TOKEN.into() };
    let paid = Arc::new(Paid::new(terms.clone()));
    let (_srv, url) = rt.block_on(start_relay(paid.clone()));
    let api = credit::spawn(paid.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();

    let shop_secret = secret();
    let shop_key: [u8; 32] = hex::decode(relay_pay::link_key_hex(&shop_secret)).unwrap().try_into().unwrap();
    let allow = Arc::new(AtomicBool::new(true));
    let wallet = StandInWallet { api, allow: allow.clone(), credit_msat: terms.credit_msat };
    let bounds = Bounds { max_msat_per_gb: 1_000_000, max_credit_msat: 2_000, max_sats: 10, low_water_bytes: MB, ..Bounds::default() };
    let announced = PaidRelay { relay: url.clone(), credit: format!("http://{api}"), msat_per_gb: 1_000_000 };
    let mut payer = RelayPayer::new(announced, bounds, wallet, Get(api));

    // the shop buys its first credit before it is reached
    assert!(matches!(payer.step(&shop_secret, now()), Step::Paid { balance, .. } if balance == 2 * MB as i64));

    // a buyer fetches 1 MB through the relay
    let (_shop, _buyer, port) = shop_and_buyer(&url, shop_secret);
    assert_eq!(download_retrying(port, MB, Duration::from_secs(60)), MB, "the paid relay carries the shop's traffic");
    let a = paid.account_raw(&shop_key).unwrap();
    eprintln!("after 1 MB: {a:?}");
    // the shop was charged for what was carried: the body and the link's own overhead, and no more
    assert!(a.charged_out >= MB && a.charged_out < MB + MB / 4, "charged out {}", a.charged_out);
    assert!(a.charged_in < MB / 4, "charged in {}", a.charged_in);
    assert_eq!(a.balance, a.credited_bytes as i64 - (a.charged_out + a.charged_in) as i64);
    assert_eq!(payer.paid_msat, terms.credit_msat);

    // the shop stops paying (its spending rule is used up), and the buyer asks for 3 MB more
    allow.store(false, Ordering::SeqCst);
    assert!(matches!(payer.step(&shop_secret, now()), Step::Refused(_)), "below the low water mark, but refused");
    let got = download(port, 3 * MB, Duration::from_secs(8));
    let a = paid.account_raw(&shop_key).unwrap();
    eprintln!("after the credit ran out: got {got}, {a:?}");
    assert!(got < 3 * MB, "the relay stopped carrying for the shop: {got} bytes arrived");
    assert!(a.refused_bytes > 0, "packets were refused");
    assert!(a.balance >= -(GRACE as i64), "never past the grace: {}", a.balance);
    // what it carried for the shop is what was bought, plus at most the grace
    assert!(a.charged_out + a.charged_in <= a.credited_bytes + GRACE);
    assert_eq!(payer.paid_msat, terms.credit_msat, "nothing more was paid");

    // it pays again: the relay carries again
    allow.store(true, Ordering::SeqCst);
    let mut p2 = RelayPayer::new(payer.relay.clone(), payer.bounds.clone(),
                                 StandInWallet { api, allow: allow.clone(), credit_msat: terms.credit_msat }, Get(api));
    assert!(matches!(p2.step(&shop_secret, now()), Step::Paid { .. }));
    assert!(paid.forward(&shop_key, &[0; 32], 1_000), "carried again once paid");
    assert_eq!(download_retrying(port, MB / 2, Duration::from_secs(60)), MB / 2, "the buyer is served again");
}

#[test]
fn a_free_relay_is_unaffected() {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let free = Arc::new(Free::default());
    let (_srv, url) = rt.block_on(start_relay(free.clone()));
    let (_shop, _buyer, port) = shop_and_buyer(&url, secret());
    assert_eq!(download_retrying(port, 4 * MB, Duration::from_secs(60)), 4 * MB, "a free relay carries everything, without payment");
    assert!(free.connected() >= 2);
}
