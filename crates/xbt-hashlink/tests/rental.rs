//! A whole rental in one process: the stand-in pool as the buyer's gateway, the hasher and the
//! buyer over a real link on loopback, and stand-in miners. The plan's three pass lines:
//! receipts agree with slices; a stopped payment stops the hash within one slice; a stopped hash
//! stops the payments.

use secp256k1::PublicKey;
use serde_json::Value;
use std::net::TcpListener;
use std::thread;
use std::time::Duration;
use xbt_hashlink::meter::share_work;
use xbt_hashlink::msg::Terms;
use xbt_hashlink::rail::{LabBuyer, LabSeller};
use xbt_hashlink::{buyer, hasher, noise, standin};

const DIFF: f64 = 0.25;
const SHARES_PER_SLICE: u128 = 8;

fn port() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().to_string()
}

fn wait_for(addr: &str) {
    for _ in 0..200 {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("{addr} never came up");
}

fn terms() -> Terms {
    Terms { slice_work: SHARES_PER_SLICE * share_work(DIFF), price_msat: 5_000, grace_ms: 1500 }
}

struct Run {
    hasher: Value,
    buyer: Value,
    pool: Value,
    miners_done_ms: u64,
}

fn rental(stop_paying_after: Option<u64>, miner_secs: u64) -> Run {
    let (pool_a, link_a, miners_a) = (port(), port(), port());
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
        let cfg = hasher::Config { miners: miners_a.clone(), link: link_a.clone(), key: hk, terms: terms(), report: None };
        thread::spawn(move || hasher::run(cfg, Box::<LabSeller>::default()).unwrap())
    };
    wait_for(&link_a);
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
    thread::sleep(Duration::from_millis(700));
    let pool = serde_json::from_slice(&std::fs::read(&pool_report).unwrap()).unwrap();
    Run { hasher, buyer, pool, miners_done_ms }
}

fn tempdir() -> std::path::PathBuf {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).unwrap();
    let d = std::env::temp_dir().join(format!("hashlink-{}", hex::encode(b)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn w(v: &Value) -> u128 {
    v.as_str().unwrap().parse().unwrap()
}

#[test]
fn a_paid_rental_then_the_hash_stops() {
    let r = rental(None, 10);
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
    // a stopped hash stops the payments: nothing paid after the miners stopped, the rest cancelled
    let last_pay = r.buyer["pays"].as_array().unwrap().last().unwrap()["atMs"].as_u64().unwrap();
    assert!(last_pay <= r.miners_done_ms + 500);
    assert_eq!(r.buyer["closed"], "no accepted work");
    assert!(w(&r.hasher["meter"]["work"]) < (paid as u128 + 1) * s);
}

#[test]
fn a_stopped_payment_stops_the_hash_within_one_slice() {
    let r = rental(Some(2), 20);
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
