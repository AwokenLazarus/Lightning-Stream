//! Paid relays end to end, on this machine (`docs/PAID-RELAYS.md`): real iroh relays with the paid
//! meter behind their access control, a shop and a buyer whose links reach each other only through
//! them, and each app's payer buying credit for its own home relay through a stand-in for its wallet
//! (which here credits the relay directly, as the operator's gateway does once a ticket has paid for
//! the request).
//!
//! It shows that each app pays only the relay it chose as home, to the byte, that nobody pays
//! within the free allowance, that traffic past an app's credit waits at the relay and goes on, not
//! lost, when the next credit comes, that an app whose budget is spent is told what was dropped, that
//! a shop that moves its home stops paying the old one, and that a free relay is unaffected.
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
use xbt_stream_relay::meter::Forward;
use xbt_stream_relay::paid::{credit_msat, Paid, PaidSettings};

const TOKEN: &str = "test-credit-token-0123456789abcdef";
const MB: u64 = 1_000_000;
const GRACE: u64 = 256 * 1024;
const KB: u64 = 1_000;

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
        assert_eq!(params["price_ceiling"]["request_msat"], self.credit_msat, "one credit at the relay's own price");
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
    homed(url, shop_secret, url, secret())
}

/// A shop homed on `shop_home` and a buyer homed on `buyer_home`, relays only: the buyer reaches the
/// shop at its home.
fn homed(shop_home: &str, shop_secret: [u8; 32], buyer_home: &str, buyer_secret: [u8; 32]) -> (Arc<Link>, Arc<Link>, u16) {
    let opts = |url: &str, serving| Options { relays: Relays::Ours(vec![url.to_string()]), serving, private: true, lookup: None };
    let shop = Link::start_with(shop_secret, opts(shop_home, true)).expect("shop link");
    shop.serve(service());
    let _ = shop.hints(Duration::from_secs(15));
    let buyer = Link::start_with(buyer_secret, opts(buyer_home, false)).expect("buyer link");
    let _ = buyer.hints(Duration::from_secs(15));
    let k = shop.endpoint_id();
    buyer.learn(&k, Hints { relays: vec![shop_home.to_string()], direct: vec![] }).expect("learn");
    let port = buyer.local_port(&k).expect("port");
    (shop, buyer, port)
}

fn key(secret: &[u8; 32]) -> [u8; 32] {
    hex::decode(relay_pay::link_key_hex(secret)).unwrap().try_into().unwrap()
}

/// A paid relay on loopback with its credit API, at `terms`.
fn paid_relay(rt: &tokio::runtime::Runtime, terms: &PaidSettings) -> (relay::Server, String, Arc<Paid>, SocketAddr) {
    let paid = Arc::new(Paid::new(terms.clone()));
    let (srv, url) = rt.block_on(start_relay(paid.clone()));
    let api = credit::spawn(paid.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    (srv, url, paid, api)
}

/// An app's payer for its home relay `url`, paying through a stand-in wallet while `allow`.
fn payer_for(url: &str, api: SocketAddr, terms: &PaidSettings, allow: Arc<AtomicBool>) -> RelayPayer<StandInWallet, Get> {
    let wallet = StandInWallet { api, allow, credit_msat: terms.credit_msat() };
    let bounds = Bounds { max_msat_per_gb: terms.msat_per_gb, max_credit_msat: terms.credit_msat(), max_sats: 10, low_water_bytes: MB, ..Bounds::default() };
    RelayPayer::new(PaidRelay { relay: url.to_string(), credit: format!("http://{api}"), msat_per_gb: terms.msat_per_gb }, bounds, wallet, Get(api))
}

/// 1,000,000 msat a GB (1 msat a KB), 2 MB credits (2 sats each), `free` bytes a day free.
fn terms(free: u64) -> PaidSettings {
    PaidSettings { enabled: true, msat_per_gb: 1_000_000, credit_bytes: 2 * MB, grace_bytes: GRACE, free_bytes_per_day: free, credit_token: TOKEN.into() }
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
fn the_shop_pays_its_home_relay_to_the_byte_within_its_credit_and_traffic_waits_for_the_next() {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let t = terms(256 * KB);
    let (_srv, url, paid, api) = paid_relay(&rt, &t);
    let shop_secret = secret();
    let shop_key = key(&shop_secret);

    // the free allowance: before the shop pays anything, a small download goes through on it
    let (_shop, _buyer, port) = shop_and_buyer(&url, shop_secret);
    assert_eq!(download_retrying(port, 50 * KB, Duration::from_secs(60)), 50 * KB, "carried free");
    assert!(paid.account_raw(&shop_key).is_none(), "nothing paid, no account");
    let free0 = paid.totals()["free_bytes"].as_u64().unwrap();
    eprintln!("COUNTS free tier: {} bytes carried free, {}", free0, paid.totals());
    assert!(free0 > 50 * KB);

    // the shop declares its home and buys its first credit
    let allow = Arc::new(AtomicBool::new(true));
    let mut payer = payer_for(&url, api, &t, allow.clone());
    assert!(matches!(payer.step(&shop_secret, now()), Step::Paid { balance, .. } if balance == 2 * MB as i64));
    assert_eq!(payer.paid_msat, 2_000, "2 MB at 1 msat a KB");

    // a 1 MB download: past the free allowances, the shop pays for what it receives here, and for
    // its answers to a buyer who isn't homed here (it chose this relay; the buyer didn't)
    assert_eq!(download_retrying(port, MB, Duration::from_secs(60)), MB);
    let a = paid.account_raw(&shop_key).unwrap();
    eprintln!("COUNTS after 1 MB: {a:?}; totals {}", paid.totals());
    assert_eq!(a.balance, a.credited_bytes as i64 - (a.charged_in + a.charged_out) as i64, "to the byte");
    assert_eq!(a.credited_msat, credit_msat(a.credited_bytes, t.msat_per_gb), "to the msat");
    assert!(a.charged_in + a.charged_out > MB - 256 * KB && a.charged_in + a.charged_out < MB + MB / 4,
            "the body and the link's overhead, less the free allowance: {}", a.charged_in + a.charged_out);
    eprintln!("COUNTS msat for 1 MB: {} msat charged (in {} B, out {} B)", credit_msat(a.charged_in + a.charged_out, t.msat_per_gb), a.charged_in, a.charged_out);

    // its budget is spent: the next download outruns its credit and waits at the relay; the next
    // credit comes while it waits, and the download completes, nothing lost
    allow.store(false, Ordering::SeqCst);
    assert!(matches!(payer.step(&shop_secret, now()), Step::Refused(_)), "below the low water mark, but refused");
    let left = a.balance.max(0) as u64;
    let want = left + GRACE + 600 * KB;
    let dl = std::thread::spawn(move || download(port, want, Duration::from_secs(30)));
    let end = Instant::now() + Duration::from_secs(60);
    while !paid.account_raw(&shop_key).is_some_and(|a| a.balance <= -(GRACE as i64) + 64 * KB as i64) && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_secs(2));
    let waiting = paid.account(&shop_key).unwrap();
    eprintln!("COUNTS waiting: {waiting}");
    assert_eq!(waiting["waiting"], true, "its traffic waits for the next credit");
    assert_eq!(waiting["dropped_bytes"], 0, "nothing dropped while it waits");
    allow.store(true, Ordering::SeqCst);
    let mut payer = payer_for(&url, api, &t, allow.clone());
    assert!(matches!(payer.step(&shop_secret, now()), Step::Paid { .. }), "the waiting traffic buys the next credit");
    assert_eq!(dl.join().unwrap(), want, "the download that waited completes");
    let a = paid.account_raw(&shop_key).unwrap();
    eprintln!("COUNTS after the wait: {a:?}");
    assert_eq!(a.dropped_bytes, 0);
    assert!(a.balance >= -(GRACE as i64), "never past the grace");
    assert_eq!(a.balance, a.credited_bytes as i64 - (a.charged_in + a.charged_out) as i64);

    // no credit at all: what waits too long is dropped, counted and told, and the connection stays up
    allow.store(false, Ordering::SeqCst);
    let mut payer = payer_for(&url, api, &t, allow.clone());
    let _ = payer.step(&shop_secret, now());
    let got = download(port, 3 * MB, Duration::from_secs(15));
    let a = paid.account(&shop_key).unwrap();
    eprintln!("COUNTS budget spent: got {got} of {} bytes; {a}", 3 * MB);
    assert!(got < 3 * MB);
    assert!(a["dropped_bytes"].as_u64().unwrap() > 0, "dropped, and the account says so");
    let k = relay_pay::link_key_hex(&shop_secret);
    let _ = payer.step(&shop_secret, now());
    assert!(payer.accounts[&k].dropped_bytes > 0 && payer.accounts[&k].waiting, "the shop's payer reads it, for its owner");
    allow.store(true, Ordering::SeqCst);
    let mut payer = payer_for(&url, api, &t, allow.clone());
    assert!(matches!(payer.step(&shop_secret, now()), Step::Paid { .. }));
    assert_eq!(download_retrying(port, MB / 2, Duration::from_secs(60)), MB / 2, "the buyer is served again");
}

#[test]
fn each_app_pays_only_its_own_home_relay() {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let t = terms(0);
    let (_s1, shop_home, shop_relay, shop_api) = paid_relay(&rt, &t);
    let (_s2, buyer_home, buyer_relay, buyer_api) = paid_relay(&rt, &t);
    let (shop_secret, buyer_secret) = (secret(), secret());
    let (sk, bk) = (key(&shop_secret), key(&buyer_secret));
    let allow = Arc::new(AtomicBool::new(true));
    let mut shop_payer = payer_for(&shop_home, shop_api, &t, allow.clone());
    let mut buyer_payer = payer_for(&buyer_home, buyer_api, &t, allow.clone());
    for _ in 0..2 {
        assert!(matches!(shop_payer.step(&shop_secret, now()), Step::Paid { .. }));
        assert!(matches!(buyer_payer.step(&buyer_secret, now()), Step::Paid { .. }));
    }
    let (_shop, _buyer, port) = homed(&shop_home, shop_secret, &buyer_home, buyer_secret);
    assert_eq!(download_retrying(port, 2 * MB, Duration::from_secs(60)), 2 * MB);
    let (s_at_s, b_at_b) = (shop_relay.account_raw(&sk).unwrap(), buyer_relay.account_raw(&bk).unwrap());
    eprintln!("COUNTS shop at its home: {s_at_s:?}");
    eprintln!("COUNTS buyer at its home: {b_at_b:?}");
    eprintln!("COUNTS totals: shop's relay {}; buyer's relay {}", shop_relay.totals(), buyer_relay.totals());
    // nobody has an account, or pays, at a relay it didn't choose
    assert!(shop_relay.account_raw(&bk).is_none() && buyer_relay.account_raw(&sk).is_none());
    assert_eq!(shop_relay.totals()["unpaid_bytes"], 0);
    assert_eq!(buyer_relay.totals()["unpaid_bytes"], 0);
    // the buyer's requests are the shop's to pay at the shop's home
    assert!(s_at_s.charged_in > 0);
    // the 2 MB of answers were paid by whoever chose the relay that carried them
    let answers = b_at_b.charged_in + s_at_s.charged_out;
    assert!(answers >= 2 * MB, "the answers were paid for: {answers}");
    for a in [&s_at_s, &b_at_b] {
        assert_eq!(a.balance, a.credited_bytes as i64 - (a.charged_in + a.charged_out) as i64);
    }
}

#[test]
fn a_shop_that_moves_its_home_pays_the_new_one_and_not_the_old() {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let t = terms(0);
    let (_s1, old_home, old_relay, old_api) = paid_relay(&rt, &t);
    let (_s2, new_home, new_relay, new_api) = paid_relay(&rt, &t);
    let shop_secret = secret();
    let sk = key(&shop_secret);
    let allow = Arc::new(AtomicBool::new(true));
    let mut p1 = payer_for(&old_home, old_api, &t, allow.clone());
    assert!(matches!(p1.step(&shop_secret, now()), Step::Paid { .. }));
    let (shop, buyer, port) = shop_and_buyer(&old_home, shop_secret);
    assert_eq!(download_retrying(port, MB, Duration::from_secs(60)), MB);
    let before = old_relay.account_raw(&sk).unwrap();
    drop((shop, buyer));
    // the switch: the same key, homed on the new relay, which its payer now pays
    let mut p2 = payer_for(&new_home, new_api, &t, allow.clone());
    assert!(matches!(p2.step(&shop_secret, now()), Step::Paid { .. }));
    let (_shop, _buyer, port) = shop_and_buyer(&new_home, shop_secret);
    assert_eq!(download_retrying(port, MB, Duration::from_secs(60)), MB);
    let (after_old, at_new) = (old_relay.account_raw(&sk).unwrap(), new_relay.account_raw(&sk).unwrap());
    eprintln!("COUNTS old home before {before:?}, after {after_old:?}; new home {at_new:?}");
    assert_eq!((after_old.charged_in, after_old.charged_out), (before.charged_in, before.charged_out), "the old home charged nothing more");
    assert!(at_new.charged_in + at_new.charged_out >= MB, "the new home carried, and was paid for, the second download");
    assert_eq!(old_relay.forward(&[0; 32], &sk, 1_000), Forward::Yes, "still homed there for a while: carried, on the shop's old credit");
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
