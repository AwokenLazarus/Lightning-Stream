//! A whole rental in one process: the stand-in pool as the buyer's gateway, the hasher and the
//! buyer over a real link on loopback, and stand-in miners. The plan's three pass lines:
//! receipts agree with slices; a stopped payment stops the hash within one slice; a stopped hash
//! stops the payments. Each runs with the lab's rail over the link, and with slices paid the
//! wallet's way: one paid request per slice through a stand-in for the wallet's signer and the
//! hasher's gateway, which passes each request to the hasher's slice endpoint.

use secp256k1::PublicKey;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use xbt_hashlink::listing::{self, Hashrate};
use xbt_hashlink::meter::share_work;
use xbt_hashlink::msg::Terms;
use xbt_hashlink::rail::{LabBuyer, LabSeller, SignerPayer};
use xbt_hashlink::{buyer, hasher, noise, standin};

const DIFF: f64 = 0.25;
const SHARES_PER_SLICE: u128 = 8;
/// The tests pick free ports by binding and letting go: one test at a time, so no two pick the same.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

/// `N` distinct free ports: all bound at once before any is let go, so none is picked twice. They
/// come from below the kernel's ephemeral range (on Linux 32768 and up by default): a port the
/// kernel hands out itself can be taken, between being let go and bound again, as the source port
/// of any outgoing connection on the machine.
fn ports<const N: usize>() -> [String; N] {
    loop {
        let mut b = [0u8; 2];
        getrandom::getrandom(&mut b).unwrap();
        let base = 20_000 + u16::from_le_bytes(b) % 12_000;
        let ls: Vec<TcpListener> =
            (0..N as u16).filter_map(|i| TcpListener::bind(("127.0.0.1", base + i * 7)).ok()).collect();
        if ls.len() == N {
            return std::array::from_fn(|i| ls[i].local_addr().unwrap().to_string());
        }
    }
}

fn wait_for(addr: &str) {
    for _ in 0..200 {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("{addr} never came up");
}

fn terms() -> Terms {
    Terms { slice_work: SHARES_PER_SLICE * share_work(DIFF), price_msat: 5_000, grace_ms: 1500 }
}

fn tempdir() -> PathBuf {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).unwrap();
    let d = std::env::temp_dir().join(format!("hashlink-{}", hex::encode(b)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The wallet's signer and the hasher's gateway in one: `xbt402_pay` POSTs the body to the
/// hasher's slice endpoint and answers as the signer does (status 200, verdict allow), and
/// counts what it was asked; `ticket_stop` is recorded.
fn fake_wallet(dir: &std::path::Path, slices: String, calls: Arc<Mutex<Vec<Value>>>) -> PathBuf {
    let sock = dir.join("signer.sock");
    let l = UnixListener::bind(&sock).unwrap();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(c) = c else { continue };
            let mut line = String::new();
            BufReader::new(c.try_clone().unwrap()).read_line(&mut line).unwrap();
            let req: Value = serde_json::from_str(&line).unwrap();
            let p = &req["params"];
            calls.lock().unwrap().push(req.clone());
            let result = match req["method"].as_str() {
                Some("xbt402_pay") => {
                    let url = p["url"].as_str().unwrap();
                    let path = &url[url.find("/hashrate").unwrap()..];
                    let body = p["body"].as_str().unwrap();
                    let mut s = TcpStream::connect(&slices).unwrap();
                    write!(s, "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
                    let mut out = String::new();
                    s.read_to_string(&mut out).unwrap();
                    let status: u64 = out.split_whitespace().nth(1).unwrap().parse().unwrap();
                    json!({"verdict": "allow", "rail": "ticket", "status": status, "session": "s1", "charged_sats": if status == 200 { 5 } else { 0 }})
                }
                _ => json!({"ok": true}),
            };
            let mut w = c;
            writeln!(w, "{}", json!({"id": 1, "result": result})).unwrap();
        }
    });
    sock
}

struct Run {
    hasher: Value,
    buyer: Value,
    pool: Value,
    miners_done_ms: u64,
    wallet_calls: Vec<Value>,
}

fn rental(stop_paying_after: Option<u64>, miner_secs: u64, wallet: bool) -> Run {
    let _serial = serial();
    let [pool_a, link_a, miners_a, slices_a] = ports::<4>();
    let dir = tempdir();
    let pool_report = dir.join("pool.json");
    {
        let (a, r) = (pool_a.clone(), pool_report.clone());
        thread::spawn(move || {
            standin::pool(standin::PoolConfig { listen: a, diff: DIFF, job_every: Duration::from_millis(700), report: Some(r) })
        });
    }
    wait_for(&pool_a);
    let hk = noise::fresh_key();
    let hpub = PublicKey::from_secret_key(secp256k1::SECP256K1, &hk);
    let h = {
        let cfg = hasher::Config {
            miners: miners_a.clone(),
            link: link_a.clone(),
            key: hk,
            terms: terms(),
            report: None,
            slices: wallet.then(|| slices_a.clone()),
            fallback: None,
            rentable: None,
        };
        thread::spawn(move || hasher::run(cfg, Box::<LabSeller>::default()).unwrap())
    };
    wait_for(&link_a);
    let calls: Arc<Mutex<Vec<Value>>> = Arc::default();
    let payer = wallet.then(|| SignerPayer {
        sock: fake_wallet(&dir, slices_a.clone(), calls.clone()),
        url: "https://hasher.example/hashrate".into(),
        task: "hashrate".into(),
        max_sats: 600,
        session: None,
    });
    let b = {
        let cfg = buyer::Config {
            hasher: link_a.clone(),
            hasher_key: hpub,
            key: noise::fresh_key(),
            upstream: pool_a.clone(),
            user: "buyer.rented".into(),
            terms: terms(),
            rental: "rental-1".into(),
            listing: "lab".into(),
            stop_paying_after,
            idle: Duration::from_secs(3),
            duration: Some(Duration::from_secs(120)),
            report: None,
            payer,
            miners: 0,
            budget_msat: None,
            cut: None,
            live: None,
        };
        thread::spawn(move || buyer::run(cfg, Box::<LabBuyer>::default()).unwrap())
    };
    thread::sleep(Duration::from_millis(300));
    let miners: Vec<_> = (0..2)
        .map(|i| {
            let a = miners_a.clone();
            thread::spawn(move || {
                standin::miner(standin::MinerConfig {
                    pool: a,
                    user: format!("hasher.m{i}"),
                    max_rate: 8.0,
                    bad_every: 7,
                    duration: Some(Duration::from_secs(miner_secs)),
                    reconnect: false,
                    extranonce_subscribe: false,
                })
            })
        })
        .collect();
    for m in miners {
        let _ = m.join().unwrap();
    }
    let miners_done_ms = xbt_hashlink::now_ms();
    let buyer = b.join().unwrap();
    let hasher = h.join().unwrap();
    // the stand-in pool rewrites its report every 500 ms: wait past one rewrite, then for the file,
    // which on a loaded machine may not be there yet
    thread::sleep(Duration::from_millis(700));
    let pool = (0..200)
        .find_map(|_| {
            let got = std::fs::read(&pool_report).ok().and_then(|b| serde_json::from_slice(&b).ok());
            if got.is_none() {
                thread::sleep(Duration::from_millis(50));
            }
            got
        })
        .expect("the stand-in pool wrote its report within 10 s");
    let wallet_calls = calls.lock().unwrap().clone();
    Run { hasher, buyer, pool, miners_done_ms, wallet_calls }
}

fn w(v: &Value) -> u128 {
    v.as_str().unwrap().parse().unwrap()
}

fn paid_then_stopped(wallet: bool) {
    let r = rental(None, 10, wallet);
    let s = terms().slice_work;
    let paid = r.hasher["paid"].as_u64().unwrap();
    assert!(paid >= 3, "only {paid} slices: {}", r.hasher);
    // receipts agree with slices: every slice paid, every receipt matching the hasher's own count
    assert_eq!(r.buyer["released"].as_u64().unwrap(), paid);
    assert_eq!(r.hasher["receiptsAgree"].as_u64().unwrap(), paid);
    assert_eq!(r.hasher["receiptsDisagree"].as_u64().unwrap(), 0);
    assert_eq!(r.hasher["meter"], r.buyer["meter"]);
    // the gateway saw only the buyer's name, and at least the work both meters counted
    let users = r.pool["users"].as_object().unwrap();
    assert_eq!(users.keys().collect::<Vec<_>>(), vec!["buyer.rented"]);
    assert!(w(&r.pool["work"]) >= w(&r.hasher["meter"]["work"]));
    assert!(r.buyer["meter"]["rejected"].as_u64().unwrap() > 0, "bad shares are counted as rejected");
    // a stopped hash stops the payments: nothing paid after the miners stopped
    let pays = r.buyer["pays"].as_array().unwrap();
    let last_pay = pays.last().unwrap()["atMs"].as_u64().unwrap();
    assert!(last_pay <= r.miners_done_ms + 1500);
    assert_eq!(r.buyer["closed"], "no accepted work");
    assert!(w(&r.hasher["meter"]["work"]) < (paid as u128 + 1) * s);
    if wallet {
        // one paid request per slice, in order, each with its receipt; then the session stopped
        let pays: Vec<_> = r.wallet_calls.iter().filter(|c| c["method"] == "xbt402_pay").collect();
        assert_eq!(pays.len() as u64, paid);
        for (i, c) in pays.iter().enumerate() {
            assert!(c["params"]["url"].as_str().unwrap().ends_with(&format!("/rental-1/{}", i + 1)));
            assert_eq!(c["params"]["task"], "hashrate");
            let receipt: Value = serde_json::from_str(c["params"]["body"].as_str().unwrap()).unwrap();
            assert_eq!(receipt["slice"], i as u64 + 1);
        }
        assert!(r.buyer["pays"].as_array().unwrap().iter().all(|p| p["ok"] == true));
        assert_eq!(r.wallet_calls.last().unwrap()["method"], "ticket_stop");
    } else {
        assert_eq!(r.buyer["events"].as_array().unwrap().iter().filter(|e| e["ev"] == "cancelled").count(), 2);
    }
}

fn unpaid_stops(wallet: bool) {
    let r = rental(Some(2), 20, wallet);
    let s = terms().slice_work;
    let stop = &r.hasher["stopped"];
    assert_eq!(stop["reason"], "unpaid", "{}", r.hasher);
    assert_eq!(r.hasher["paid"].as_u64().unwrap(), 2);
    // work past the end of the first unpaid slice is at most one slice: the grace time ends it,
    // or the end of a second unpaid slice does (here a slice is quicker than the grace time)
    let past = w(&stop["work"]).saturating_sub(3 * s);
    assert!(past <= s, "{past} past the unpaid slice, slice {s}");
    // the gateway's own count stops there too (it may have answered a few shares in flight)
    assert!(w(&r.pool["work"]) < 4 * s + 4 * share_work(DIFF));
    assert!(r.buyer["closed"].as_str().unwrap().starts_with("hasher closed"));
}

#[test]
fn a_paid_rental_then_the_hash_stops() {
    paid_then_stopped(false);
}

#[test]
fn a_stopped_payment_stops_the_hash_within_one_slice() {
    unpaid_stops(false);
}

#[test]
fn paid_by_the_wallet_then_the_hash_stops() {
    paid_then_stopped(true);
}

#[test]
fn unpaid_by_the_wallet_stops_the_hash() {
    unpaid_stops(true);
}

#[test]
fn a_slice_the_hasher_did_not_count_is_refused() {
    // the hasher's endpoint, before any work: a receipt for slice 1 is refused (409), so a gateway
    // in front of it charges nothing
    let _serial = serial();
    let [link_a, miners_a, slices_a] = ports::<3>();
    let hk = noise::fresh_key();
    let hpub = PublicKey::from_secret_key(secp256k1::SECP256K1, &hk);
    let cfg = hasher::Config {
        miners: miners_a,
        link: link_a.clone(),
        key: hk,
        terms: terms(),
        report: None,
        slices: Some(slices_a.clone()),
        fallback: None,
        rentable: None,
    };
    thread::spawn(move || hasher::run(cfg, Box::<LabSeller>::default()));
    wait_for(&link_a);
    let bk = noise::fresh_key();
    let mut l = xbt_hashlink::link::dial(&link_a, bk, hpub).unwrap();
    l.tx.send(&xbt_hashlink::msg::Msg::Hello { rental: "r9".into(), listing: "l".into(), terms: terms(), miners: 0 }).unwrap();
    assert!(matches!(l.rx.recv().unwrap(), Some(xbt_hashlink::msg::Msg::Welcome { .. })));
    let receipt = xbt_hashlink::meter::Receipt { rental: "r9".into(), slice: 1, work: terms().slice_work, accepted: 8, rejected: 0, at_ms: 1 }.sign(&bk);
    let post = |path: &str, body: &str| {
        let mut s = TcpStream::connect(&slices_a).unwrap();
        write!(s, "POST {path} HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    };
    let t0 = std::time::Instant::now();
    assert!(post("/hashrate/r9/1", &receipt.to_string()).starts_with("HTTP/1.1 409"));
    assert!(t0.elapsed() >= Duration::from_secs(3), "it waits for the link's verdict first");
    assert!(post("/hashrate/other/1", &receipt.to_string()).starts_with("HTTP/1.1 409"));
    assert!(post("/hashrate/r9/1", "not json").starts_with("HTTP/1.1 409"));
}

#[test]
fn the_buyer_finds_the_hasher_on_nostr() {
    let relay = xbt_nostr::standin::StandinRelay::start().unwrap();
    let link = noise::fresh_key();
    let h = Hashrate {
        name: "lab hasher".into(),
        algorithm: "blake2b".into(),
        hashrate_hs: 4_000_000_000_000,
        link_addr: "127.0.0.1:1".into(),
        link_key: PublicKey::from_secret_key(secp256k1::SECP256K1, &link),
        pay_url: "https://hasher.example/hashrate".into(),
        pay_node: "02".to_string() + &"aa".repeat(32),
        terms: terms(),
        capacity: listing::Capacity { miners: 2, free_miners: 2, free_hs: 1_000_000 },
    };
    let nostr = xbt_nostr::event::Keys::generate();
    let ev = h.event(&link, &nostr, xbt_nostr::now()).unwrap();
    let said = listing::publish(std::slice::from_ref(&relay.url), &ev);
    assert_eq!(said[0]["ok"], true, "{said:?}");
    // a forgery: another Nostr key re-signing the hasher's tags
    let forged = xbt_nostr::event::Event::sign(&xbt_nostr::event::Keys::generate(), xbt_nostr::now(), listing::KIND, ev.tags.clone(), String::new());
    listing::publish(std::slice::from_ref(&relay.url), &forged);
    let (found, refused) = listing::find(std::slice::from_ref(&relay.url), xbt_nostr::now());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, h);
    assert_eq!(refused, 1);
}
