//! One hashmaker, four miners, a fallback and several hashtakers, in one process: the hashmaker's own
//! stand-in pool is the fallback, each hashtaker has a stand-in pool of its own (its DATUM Gateway).
//! Miners are stand-ins that connect again when asked (`client.reconnect`), or take a new
//! extranonce (`mining.set_extranonce`), as real ones do.
//!
//! * three hashtakers take one miner each; the fourth hashes for the fallback throughout;
//! * one hashtaker takes three; the fourth stays on the fallback;
//! * a hashtaker that stops paying loses only its own miner, which goes back to the fallback;
//! * moving a miner (either way) leaves no gap in its shares longer than one job.

use secp256k1::PublicKey;
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};
use xbt_hashlink::hashmaker::{self, Hashmaker};
use xbt_hashlink::meter::share_work;
use xbt_hashlink::msg::Terms;
use xbt_hashlink::rail::{LabHashtaker, LabSeller};
use xbt_hashlink::{hashtaker, noise, standin};

const DIFF: f64 = 0.25;
const JOB_MS: u64 = 2000;
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

/// `N` distinct free ports below the kernel's ephemeral range (see tests/rental.rs).
fn ports<const N: usize>() -> [String; N] {
    loop {
        let mut b = [0u8; 2];
        getrandom::getrandom(&mut b).unwrap();
        let base = 20_000 + u16::from_le_bytes(b) % 12_000;
        let ls: Vec<TcpListener> = (0..N as u16).filter_map(|i| TcpListener::bind(("127.0.0.1", base + i * 7)).ok()).collect();
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

fn tempdir() -> PathBuf {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).unwrap();
    let d = std::env::temp_dir().join(format!("hashlink-several-{}", hex::encode(b)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn terms() -> Terms {
    Terms { slice_work: 6 * share_work(DIFF), price_msat: 5_000, grace_ms: 2500 }
}

struct Pool {
    addr: String,
    report: PathBuf,
}

impl Pool {
    fn start(dir: &std::path::Path, name: &str) -> Pool {
        let [addr] = ports::<1>();
        let report = dir.join(format!("{name}.json"));
        let (a, r) = (addr.clone(), report.clone());
        thread::spawn(move || standin::pool(standin::PoolConfig { listen: a, diff: DIFF, job_every: Duration::from_millis(JOB_MS), report: Some(r) }));
        wait_for(&addr);
        Pool { addr, report }
    }

    /// Accepted shares by user, as the pool's last report has them.
    fn users(&self) -> BTreeMap<String, u64> {
        thread::sleep(Duration::from_millis(700));
        let v: Value = (0..100)
            .find_map(|_| {
                let got = std::fs::read(&self.report).ok().and_then(|b| serde_json::from_slice(&b).ok());
                if got.is_none() {
                    thread::sleep(Duration::from_millis(50));
                }
                got
            })
            .unwrap_or_default();
        v["users"].as_object().map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_u64().unwrap_or(0))).collect()).unwrap_or_default()
    }
}

struct Rig {
    hashmaker: Hashmaker,
    link: String,
    hpub: PublicKey,
    fallback: Pool,
    dir: PathBuf,
    miners: Vec<thread::JoinHandle<standin::MinerResult>>,
}

/// The hashmaker with its fallback, and `n` miners (`ext`: those that take a new extranonce) running
/// `secs` seconds at up to `rate` shares a second. Returns once every miner hashes for the fallback.
fn rig(n: usize, ext: &[bool], secs: u64, rate: f64) -> Rig {
    rig_from(n, ext, secs, rate, false)
}

/// [`rig`], each miner connecting from an address of its own (127.0.0.2, 127.0.0.3, ...) with `own`,
/// as miners on a LAN do, or all from one address as behind one router.
fn rig_from(n: usize, ext: &[bool], secs: u64, rate: f64, own: bool) -> Rig {
    let dir = tempdir();
    let fallback = Pool::start(&dir, "fallback");
    let [link, miners_a] = ports::<2>();
    let hk = noise::fresh_key();
    let hpub = PublicKey::from_secret_key(secp256k1::SECP256K1, &hk);
    let hashmaker = Hashmaker::start(
        hashmaker::Config {
            miners: miners_a.clone(),
            link: link.clone(),
            key: hk,
            terms: terms(),
            report: None,
            slices: None,
            fallback: Some(fallback.addr.clone()),
            rentable: None,
        },
        Box::new(|| Box::<LabSeller>::default()),
    )
    .unwrap();
    wait_for(&link);
    let miners = (0..n)
        .map(|i| {
            let (a, e) = (miners_a.clone(), ext.get(i).copied().unwrap_or(false));
            thread::spawn(move || {
                standin::miner(standin::MinerConfig {
                    pool: a,
                    user: format!("m{i}"),
                    max_rate: rate,
                    bad_every: 0,
                    duration: Some(Duration::from_secs(secs)),
                    reconnect: true,
                    extranonce_subscribe: e,
                    bind: own.then(|| std::net::IpAddr::from([127, 0, (2 + i / 250) as u8, (2 + i % 250) as u8])),
                })
                .unwrap()
            })
        })
        .collect();
    // every miner placed on the fallback, with work accepted there
    let t0 = Instant::now();
    loop {
        let s = hashmaker.status();
        let ok = s["miners"].as_array().is_some_and(|m| m.len() == n && m.iter().all(|m| m["connected"] == true && m["work"] != "0"));
        if ok {
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(20), "miners never all hashed at the fallback: {s}");
        thread::sleep(Duration::from_millis(100));
    }
    Rig { hashmaker, link, hpub, fallback, dir, miners }
}

/// A hashtaker taking `miners` miners into its own pool for `secs`, paying (or stopping after a slice).
fn hashtaker(rig: &Rig, name: &str, miners: u32, secs: u64, stop_paying_after: Option<u64>) -> (Pool, thread::JoinHandle<Value>) {
    hashtaker_idle(rig, name, miners, secs, stop_paying_after, Duration::from_secs(4))
}

/// [`hashtaker`], ending the rental after `idle` without accepted work.
fn hashtaker_idle(rig: &Rig, name: &str, miners: u32, secs: u64, stop_paying_after: Option<u64>, idle: Duration) -> (Pool, thread::JoinHandle<Value>) {
    let pool = Pool::start(&rig.dir, name);
    let cfg = hashtaker::Config {
        hashmaker: rig.link.clone(),
        hashmaker_key: rig.hpub,
        key: noise::fresh_key(),
        upstream: pool.addr.clone(),
        user: format!("{name}.rented"),
        terms: terms(),
        rental: name.into(),
        listing: "lab".into(),
        stop_paying_after,
        idle,
        duration: Some(Duration::from_secs(secs)),
        report: None,
        payer: None,
        miners,
        budget_msat: None,
        cut: None,
        live: None,
    };
    (pool, thread::spawn(move || hashtaker::run(cfg, Box::<LabHashtaker>::default()).unwrap()))
}

fn finished(h: &Hashmaker, id: &str) -> Value {
    wait_finished(h, &[id]);
    h.finished().into_iter().find(|r| r["rental"] == id).unwrap()
}

fn wait_finished(h: &Hashmaker, ids: &[&str]) {
    let t0 = Instant::now();
    while !ids.iter().all(|id| h.finished().iter().any(|r| r["rental"] == *id)) {
        assert!(t0.elapsed() < Duration::from_secs(30), "rentals never ended: {}", h.status());
        thread::sleep(Duration::from_millis(100));
    }
}

fn rented_names(r: &Value) -> Vec<String> {
    r["miners"].as_array().unwrap().iter().map(|m| m.as_str().unwrap().to_string()).collect()
}

fn check_paid(r: &Value, b: &Value) {
    let paid = r["paid"].as_u64().unwrap();
    assert!(paid >= 1, "nothing paid: {r}");
    assert_eq!(r["receiptsAgree"].as_u64().unwrap(), paid, "{r}");
    assert_eq!(r["receiptsDisagree"].as_u64().unwrap(), 0);
    assert_eq!(b["released"].as_u64().unwrap(), paid, "hashtaker {b}\nhashmaker {r}");
    assert_eq!(r["meter"], b["meter"], "both sides count the same work");
}

#[test]
fn three_hashtakers_take_one_miner_each_and_the_fourth_stays_on_the_fallback() {
    let _s = serial();
    let rig = rig(4, &[], 60, 6.0);
    let before = rig.fallback.users();
    let hashtakers: Vec<_> = (0..3).map(|i| hashtaker(&rig, &format!("hashtaker{i}"), 1, 12, None)).collect();
    let mut reports = Vec::new();
    let mut pools = Vec::new();
    for (p, b) in hashtakers {
        reports.push(b.join().unwrap());
        pools.push(p);
    }
    wait_finished(&rig.hashmaker, &["hashtaker0", "hashtaker1", "hashtaker2"]);
    let mut taken = Vec::new();
    for (i, b) in reports.iter().enumerate() {
        let r = finished(&rig.hashmaker, &format!("hashtaker{i}"));
        let names = rented_names(&r);
        assert_eq!(names.len(), 1, "one miner each: {r}");
        taken.extend(names);
        check_paid(&r, b);
        // the hashtaker's pool saw only the hashtaker's own name
        let users = pools[i].users();
        assert_eq!(users.keys().collect::<Vec<_>>(), vec![&format!("hashtaker{i}.rented")], "{users:?}");
        assert!(users.values().sum::<u64>() > 0);
    }
    taken.sort();
    taken.dedup();
    assert_eq!(taken.len(), 3, "three different miners: {taken:?}");
    // the fourth hashed at the fallback all along, and every miner is back there afterwards
    let free = ["m0", "m1", "m2", "m3"].into_iter().find(|m| !taken.contains(&m.to_string())).unwrap();
    let after = rig.fallback.users();
    assert!(after[free] > before[free], "the free miner kept hashing at the fallback: {before:?} {after:?}");
    thread::sleep(Duration::from_secs(4));
    let again = rig.fallback.users();
    for m in &taken {
        assert!(again[m] > after.get(m).copied().unwrap_or(0), "{m} back at the fallback after its rental: {after:?} {again:?}\n{}", rig.hashmaker.status());
    }
    let s = rig.hashmaker.status();
    assert!(s["miners"].as_array().unwrap().iter().all(|m| m["rentedTo"].is_null()), "{s}");
    rig.hashmaker.shutdown();
    for m in rig.miners {
        m.join().unwrap();
    }
}

#[test]
fn one_hashtaker_takes_three_and_the_fourth_stays_on_the_fallback() {
    let _s = serial();
    let rig = rig(4, &[], 40, 6.0);
    let (pool, b) = hashtaker(&rig, "big", 3, 10, None);
    // while it runs: three rented, one on the fallback (asked until then: a busy machine takes longer)
    let t0 = Instant::now();
    let s = loop {
        let s = rig.hashmaker.status();
        let n = s["miners"].as_array().unwrap().iter().filter(|m| m["rentedTo"] == "big").count();
        // the free count follows the rentals a moment later: wait for both
        if (n == 3 && s["capacity"]["freeMiners"] == 1) || t0.elapsed() > Duration::from_secs(30) {
            break s;
        }
        thread::sleep(Duration::from_millis(200));
    };
    let rented: Vec<&Value> = s["miners"].as_array().unwrap().iter().filter(|m| m["rentedTo"] == "big").collect();
    assert_eq!(rented.len(), 3, "{s}");
    assert_eq!(s["capacity"]["freeMiners"], 1, "{s}");
    let b = b.join().unwrap();
    wait_finished(&rig.hashmaker, &["big"]);
    let r = finished(&rig.hashmaker, "big");
    assert_eq!(rented_names(&r).len(), 3);
    check_paid(&r, &b);
    let work: Vec<u128> = r["unitWork"].as_object().unwrap().values().map(|w| w.as_str().unwrap().parse().unwrap()).collect();
    assert_eq!(work.len(), 3, "all three miners did work for the hashtaker: {r}");
    assert!(pool.users().contains_key("big.rented"));
    rig.hashmaker.shutdown();
    for m in rig.miners {
        m.join().unwrap();
    }
}

#[test]
fn a_hashtaker_that_stops_paying_loses_only_its_own_miner() {
    let _s = serial();
    let rig = rig(2, &[], 60, 6.0);
    let (_pa, a) = hashtaker(&rig, "payer", 1, 25, None);
    let (_pb, b) = hashtaker(&rig, "stopper", 1, 25, Some(1));
    let b = b.join().unwrap();
    assert!(b["closed"].as_str().unwrap().starts_with("hashmaker closed: unpaid"), "{b}");
    let stopped = finished(&rig.hashmaker, "stopper");
    assert_eq!(stopped["stopped"]["reason"], "unpaid");
    let lost = rented_names(&stopped)[0].clone();
    // the other rental goes on meanwhile, and the stopper's miner hashes at the fallback again
    let mid = rig.fallback.users();
    thread::sleep(Duration::from_secs(3));
    let s = rig.hashmaker.status();
    assert!(s["rentals"].as_array().unwrap().iter().any(|r| r["rental"] == "payer"), "the paying rental goes on: {s}");
    let later = rig.fallback.users();
    assert!(later[&lost] > mid.get(&lost).copied().unwrap_or(0), "{lost} back at the fallback: {mid:?} {later:?}");
    let a = a.join().unwrap();
    wait_finished(&rig.hashmaker, &["payer"]);
    check_paid(&finished(&rig.hashmaker, "payer"), &a);
    rig.hashmaker.shutdown();
    for m in rig.miners {
        m.join().unwrap();
    }
}

#[test]
fn moving_a_miner_leaves_no_gap_longer_than_one_job() {
    let _s = serial();
    // m0 connects again when asked; m1 takes a new extranonce on the same connection
    let rig = rig(2, &[false, true], 18, 12.0);
    let (pool, b) = hashtaker(&rig, "both", 2, 8, None);
    let b = b.join().unwrap();
    wait_finished(&rig.hashmaker, &["both"]);
    let r = finished(&rig.hashmaker, "both");
    check_paid(&r, &b);
    assert!(pool.users()["both.rented"] > 0);
    // the miners' own time runs out before the hashmaker stops (which would make them connect again)
    let res: Vec<standin::MinerResult> = rig.miners.into_iter().map(|m| m.join().unwrap()).collect();
    rig.hashmaker.shutdown();
    // to the rental and back: m0 connected three times, m1 once, with two new extranonces
    assert!(res[0].sessions >= 3, "{:?}", res[0]);
    assert_eq!(res[1].sessions, 1, "{:?}", res[1]);
    assert!(res[1].extranonce_changes >= 2, "{:?}", res[1]);
    for m in &res {
        assert!(m.max_gap_ms < JOB_MS, "a gap of {} ms between accepted shares, a job is {JOB_MS} ms: {m:?}", m.max_gap_ms);
        assert!(m.rejected * 10 <= m.accepted, "few rejected shares around the switches: {m:?}");
    }
}

/// Miners behind one address (a farm behind one router, or containers) that are moved into rentals
/// together each connect again once to go in and once to come back, and the rentals get their work:
/// a returning miner is placed by its worker name, not by whichever miner from that address asked first.
#[test]
fn miners_behind_one_address_move_once_each_way() {
    let _s = serial();
    let secs = 12;
    let rig = rig(8, &[], secs + 25, 6.0);
    let hashtakers: Vec<_> = (0..2).map(|i| hashtaker_idle(&rig, &format!("one{i}"), 4, secs, None, Duration::from_secs(20))).collect();
    let mut got = Vec::new();
    for (i, (pool, b)) in hashtakers.into_iter().enumerate() {
        let b = b.join().unwrap();
        let r = finished(&rig.hashmaker, &format!("one{i}"));
        assert_eq!(rented_names(&r).len(), 4, "{r}");
        check_paid(&r, &b);
        got.push(pool.users()[&format!("one{i}.rented")]);
    }
    rig.hashmaker.shutdown();
    let res: Vec<standin::MinerResult> = rig.miners.into_iter().map(|m| m.join().unwrap()).collect();
    for m in &res {
        // the first connection, one into the rental, one back to the fallback, and one more when the
        // app stops at the end and the miner tries again
        assert!(m.sessions <= 4, "a miner connected {} times: {res:?}", m.sessions);
    }
    // 4 miners at 6 shares a second; the rental's first seconds go to taking a ticket
    for g in got {
        assert!(g * 10 >= 4 * secs * 6 * 6, "a rental's pool got {g} shares of {} at most", 4 * secs * 6);
    }
}

/// CPU seconds this process has used, from /proc (Linux).
fn cpu_secs() -> f64 {
    let s = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let f: Vec<&str> = s.rsplit_once(')').map(|(_, r)| r.split_whitespace().collect()).unwrap_or_default();
    let tick = |i: usize| f.get(i).and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.0);
    (tick(11) + tick(12)) / 100.0
}

/// A load test, run by name only (`--ignored`): HASH_LOAD_TAKERS hashtakers (default 10) take
/// HASH_LOAD_EACH miners each (default 3) from one hashmaker at once, for HASH_LOAD_SECS seconds
/// (default 30). Each rental is paid in full with receipts that agree, no miner is rented twice,
/// and no miner's shares stop for longer than a job. Prints one line of JSON: the rentals, the
/// slices paid, the shares, the largest gap and the CPU this process used.
#[test]
#[ignore]
fn many_hashtakers_at_once_on_one_hashmaker() {
    let _s = serial();
    let env = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
    let (n, each, secs) = (env("HASH_LOAD_TAKERS", 10) as usize, env("HASH_LOAD_EACH", 3) as u32, env("HASH_LOAD_SECS", 30));
    let miners = n * each as usize + 2;
    // miners each with an address of their own, as on a LAN (behind one address, see the test above)
    let rig = rig_from(miners, &[], secs + 40, 6.0, true);
    let (c0, t0) = (cpu_secs(), Instant::now());
    // the binary's own idle time (60 s), not the 4 s of the tests above: with many rentals starting at once, a
    // miner's first share at its new pool can take longer than 4 s on a loaded machine
    let hashtakers: Vec<_> = (0..n).map(|i| hashtaker_idle(&rig, &format!("load{i}"), each, secs, None, Duration::from_secs(60))).collect();
    let mut taken = Vec::new();
    let mut paid = 0;
    let mut rental_shares = Vec::new();
    for (i, (pool, b)) in hashtakers.into_iter().enumerate() {
        let b = b.join().unwrap();
        let r = finished(&rig.hashmaker, &format!("load{i}"));
        let names = rented_names(&r);
        assert_eq!(names.len(), each as usize, "{each} miners for load{i}: {r}");
        check_paid(&r, &b);
        paid += r["paid"].as_u64().unwrap();
        let got = pool.users()[&format!("load{i}.rented")];
        assert!(got > 0, "load{i}'s pool got shares");
        rental_shares.push(got);
        taken.extend(names);
    }
    let fallback_shares: u64 = rig.fallback.users().values().sum();
    let (cpu, wall) = (cpu_secs() - c0, t0.elapsed().as_secs_f64());
    let rented = taken.len();
    taken.sort();
    taken.dedup();
    assert_eq!(taken.len(), rented, "no miner rented twice: {taken:?}");
    rig.hashmaker.shutdown();
    let res: Vec<standin::MinerResult> = rig.miners.into_iter().map(|m| m.join().unwrap()).collect();
    let gap = res.iter().map(|m| m.max_gap_ms).max().unwrap_or(0);
    let (acc, rej) = (res.iter().map(|m| m.accepted).sum::<u64>(), res.iter().map(|m| m.rejected).sum::<u64>());
    // what a rental's pool would get if each rented miner hashed for it the whole rental, at the miners' rate
    let expected = each as u64 * secs * 6;
    let sessions = res.iter().map(|m| m.sessions).max().unwrap_or(0);
    println!(
        "{}",
        serde_json::json!({"hashtakers": n, "miners": miners, "rented": rented, "slices_paid": paid, "shares_accepted": acc, "shares_rejected": rej,
                           "max_gap_ms": gap, "job_ms": JOB_MS,
                           "rental_shares_min": rental_shares.iter().min(), "rental_shares_max": rental_shares.iter().max(),
                           "rental_shares_expected": expected, "fallback_shares": fallback_shares, "max_miner_sessions": sessions, "cpu_s": (cpu * 100.0).round() / 100.0, "wall_s": wall.round(), "cores": (cpu / wall * 100.0).round() / 100.0})
    );
    assert!(gap < JOB_MS, "a miner's shares stopped for {gap} ms, a job is {JOB_MS} ms");
    assert!(rej * 10 <= acc, "few rejected shares: {rej} of {acc}");
}
