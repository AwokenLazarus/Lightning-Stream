//! The hashrate link over iroh: the same rentals as over TCP, with the hashtaker reaching the
//! hashmaker by its iroh key instead of an address it forwarded. Offline: no relay, direct addresses
//! on loopback (the relay runs are the ignored measurement at the end).
//!
//! * a rental over iroh pays every slice and both meters' proven counts agree, as over TCP;
//! * one hashtaker app's link reaches the hashmaker again for a second rental;
//! * a miner moved into a rental over iroh and back loses no more than a job;
//! * a rental over iroh whose link drops for a moment carries on, every slice paid once, and the two
//!   sides' proven counts agree once what the link lost has been sent again;
//! * shares lost with the link are sent again and counted once;
//! * verdicts lost with the link change no count, and a payment lost with it is paid once all the same,
//!   the two sides' books equal;
//! * a rental whose link goes silent, with no close and no end of stream, ends on both sides within
//!   a bound, the books equal and the tickets given back;
//! * a hashtaker back before the hashmaker noticed the drop carries on;
//! * a byte changed on the way (what a relay could try) breaks the link instead of a job or a share;
//! * (ignored) the round trip of a share, over TCP and over iroh, direct and through relays.

use secp256k1::PublicKey;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use xbt_hashlink::hashmaker::{self, Hashmaker};
use xbt_hashlink::listing::IrohLink;
use xbt_hashlink::meter::share_work;
use xbt_hashlink::msg::{Msg, Terms};
use xbt_hashlink::over_iroh::{self, Dialer, Link, Relays};
use xbt_hashlink::rail::{Hash, HashtakerRail, LabHashtaker, LabSeller, SellerRail};
use xbt_hashlink::{hashtaker, link, noise, order, standin};

/// About 4096 hashes a share: the chain's own format, at a difficulty a CPU reaches.
const DIFF: f64 = 1.0 / (1u64 << 20) as f64;
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
    let d = std::env::temp_dir().join(format!("hashlink-iroh-{}", hex::encode(b)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn terms() -> Terms {
    Terms { slice_work: 6 * share_work(DIFF), price_msat: 300_000, grace_ms: 2500, start_slices: 0 }
}

struct Pool {
    addr: String,
    report: PathBuf,
}

impl Pool {
    fn start(dir: &std::path::Path, name: &str, job_ms: u64) -> Pool {
        let [addr] = ports::<1>();
        let report = dir.join(format!("{name}.json"));
        let (a, r) = (addr.clone(), report.clone());
        thread::spawn(move || standin::pool(standin::PoolConfig { listen: a, diff: DIFF, job_every: Duration::from_millis(job_ms), report: Some(r) }));
        wait_for(&addr);
        Pool { addr, report }
    }

    /// The pool's last report.
    fn report(&self) -> Value {
        thread::sleep(Duration::from_millis(700));
        (0..100)
            .find_map(|_| {
                let got = std::fs::read(&self.report).ok().and_then(|b| serde_json::from_slice(&b).ok());
                if got.is_none() {
                    thread::sleep(Duration::from_millis(50));
                }
                got
            })
            .unwrap_or_default()
    }

    fn users(&self) -> BTreeMap<String, u64> {
        let v = self.report();
        v["users"].as_object().map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_u64().unwrap_or(0))).collect()).unwrap_or_default()
    }
}

/// A hashmaker (with a fallback when `fallback`), its link served over iroh as well, and the iroh
/// link a listing would name. Direct addresses on loopback stand in for the relay.
struct Rig {
    hashmaker: Hashmaker,
    hpub: PublicKey,
    iroh: IrohLink,
    _link: std::sync::Arc<Link>,
    /// The link listener's TCP address (for the run over TCP).
    link: String,
    dir: PathBuf,
    miners_addr: String,
}

fn rig(fallback: bool, relays: Relays) -> Rig {
    rig_with(fallback, relays, Box::new(|| Box::<LabSeller>::default()))
}

fn rig_with(fallback: bool, relays: Relays, rails: hashmaker::Rails) -> Rig {
    let dir = tempdir();
    let [link, miners_addr] = ports::<2>();
    let hk = noise::fresh_key();
    let hpub = PublicKey::from_secret_key(secp256k1::SECP256K1, &hk);
    let fb = fallback.then(|| Pool::start(&dir, "fallback", JOB_MS).addr);
    let hashmaker = Hashmaker::start(
        hashmaker::Config { miners: miners_addr.clone(), link: link.clone(), key: hk, terms: terms(), report: None, slices: None, fallback: fb, rentable: None, min_slice_time: hashmaker::MIN_SLICE_TIME },
        rails,
    )
    .unwrap();
    wait_for(&link);
    let offline = matches!(relays, Relays::None);
    let l = over_iroh::serve(&hk, relays, &link).unwrap();
    let mut iroh = over_iroh::advertise(&l, Duration::from_secs(10));
    if offline {
        // no relay to meet at: the listing would name the direct addresses
        iroh.direct = l.hints(Duration::from_millis(200)).direct.iter().map(|a| a.to_string()).collect();
        assert!(!iroh.direct.is_empty(), "the hashmaker's link found no address of its own");
    }
    Rig { hashmaker, hpub, iroh, _link: l, link, dir, miners_addr }
}

fn miner(addr: &str, name: &str, secs: u64, rate: f64, reconnect: bool, ext: bool) -> thread::JoinHandle<standin::MinerResult> {
    let (a, u) = (addr.to_string(), name.to_string());
    thread::spawn(move || {
        standin::miner(standin::MinerConfig {
            pool: a,
            user: u,
            max_rate: rate,
            bad_every: 0,
            duration: Some(Duration::from_secs(secs)),
            reconnect,
            extranonce_subscribe: ext,
            bind: None,
        })
        .unwrap()
    })
}

/// A hashtaker renting `miners` miners for `secs` into `pool`, reaching the hashmaker at `addr`.
fn hashtaker(rig: &Rig, addr: String, pool: &Pool, name: &str, miners: u32, secs: u64) -> thread::JoinHandle<Value> {
    let cfg = hashtaker::Config {
        hashmaker: addr,
        hashmaker_key: rig.hpub,
        key: noise::fresh_key(),
        upstream: pool.addr.clone(),
        user: format!("{name}.rented"),
        terms: terms(),
        rental: name.into(),
        listing: "lab".into(),
        stop_paying_after: None,
        idle: Duration::from_secs(4),
        duration: Some(Duration::from_secs(secs)),
        report: None,
        payer: None,
        miners,
        budget_msat: None,
        cut: None,
        live: None,
        gateway_api: None,
        allow_unblinded: true,
    };
    thread::spawn(move || hashtaker::run(cfg, Box::<LabHashtaker>::default()).unwrap())
}

/// A rental's report once it ended: at the latest when the hashmaker's own limit on a silent link runs
/// out, so a rental still going past that is a rental that does not end.
fn finished(h: &Hashmaker, id: &str) -> Value {
    let t0 = Instant::now();
    loop {
        if let Some(r) = h.finished().into_iter().find(|r| r["rental"] == id) {
            return r;
        }
        assert!(t0.elapsed() < hashmaker::QUIET_LIMIT + Duration::from_secs(15), "rental {id} never ended: {}", h.status());
        thread::sleep(Duration::from_millis(100));
    }
}

/// Slices paid after the hashtaker came back: the rental carried on, not just survived.
fn paid_after_resume(r: &Value) -> usize {
    let evs = r["events"].as_array().unwrap();
    let Some(back) = evs.iter().rev().find(|e| e["ev"] == "hashtaker back, rental resumed") else { return 0 };
    let at = back["atMs"].as_u64().unwrap();
    evs.iter().filter(|e| e["ev"] == "pay" && e["ok"] == true && e["atMs"].as_u64().unwrap() >= at).count()
}

fn work_of(v: &Value) -> u128 {
    v["meter"]["work"].as_str().unwrap().parse().unwrap()
}

/// The two sides' proven counts are the same, each its own: for a rental that ended with no share on its way.
fn check_counts_agree(r: &Value, b: &Value) {
    assert_eq!(r["meter"]["work"], b["meter"]["work"], "both sides prove the same work\nhashtaker {b}\nhashmaker {r}");
    assert_eq!(r["meter"]["proven"], b["meter"]["proven"], "hashtaker {b}\nhashmaker {r}");
}

/// Is another slice due by the renter's rule, at this count, with shares of this size?
fn due(terms: &Terms, proven: u128, largest_share: u128, paid: u64) -> bool {
    order::Standing { proven, largest_share, paid, start_slices: terms.start_slices, slice_work: terms.slice_work, price_msat: terms.price_msat,
                      // the step without its 30 s cap: the renter's rate isn't in its receipts, and the cap only lowers it
                      msat_a_second: f64::INFINITY, buy_secs: 0.0 }.pay_next()
}

/// Every slice paid once and when the rule said. The hashtaker's count is the hashmaker's but for shares on
/// their way when the hashtaker ended the rental, which it never read: a few at most, and the hashmaker is
/// never the one behind.
fn check_paid(r: &Value, b: &Value) {
    let (s, sw) = (terms().slice_work, share_work(DIFF));
    let paid = r["paid"].as_u64().unwrap();
    assert!(paid >= 1, "nothing paid: {r}");
    assert_eq!(b["released"].as_u64().unwrap(), paid, "hashtaker {b}\nhashmaker {r}");
    for rc in b["receipts"].as_array().unwrap() {
        let (slice, work) = (rc["slice"].as_u64().unwrap(), rc["work"].as_str().unwrap().parse().unwrap());
        assert!(due(&terms(), work, sw, slice - 1), "slice {slice} paid when it wasn't due: {rc}");
    }
    let (m, t) = (work_of(r), work_of(b));
    assert!(m >= t && m - t <= s / 2, "the two proven counts, {m} and {t}, slice {s}\nhashtaker {b}\nhashmaker {r}");
    assert!(m <= order::paid_work(paid, 0, s), "proven work stayed within what was paid: {r}");
}

#[test]
fn a_rental_over_iroh_pays_every_slice_and_a_second_one_reaches_it_again() {
    let _s = serial();
    let rig = rig(true, Relays::None);
    let m = miner(&rig.miners_addr, "m0", 30, 12.0, true, false);
    // the miner on the fallback first
    let t0 = Instant::now();
    while !rig.hashmaker.status()["miners"].as_array().is_some_and(|m| m.len() == 1 && m[0]["work"] != "0") {
        assert!(t0.elapsed() < Duration::from_secs(20), "the miner never hashed at the fallback");
        thread::sleep(Duration::from_millis(100));
    }
    let dialer = Dialer::start(Relays::None).unwrap();
    for (i, name) in ["first", "second"].iter().enumerate() {
        let pool = Pool::start(&rig.dir, name, JOB_MS);
        let addr = dialer.address_for(&rig.iroh).unwrap();
        assert!(addr.starts_with("127.0.0.1:"), "a loopback address leads through the link: {addr}");
        let b = hashtaker(&rig, addr, &pool, name, 1, 6).join().unwrap();
        let r = finished(&rig.hashmaker, name);
        check_paid(&r, &b);
        assert!(pool.users()[&format!("{name}.rented")] > 0, "rental {i}: the hashtaker's pool got the work");
    }
    rig.hashmaker.shutdown();
    let _ = m.join();
}

#[test]
fn moving_a_miner_over_iroh_leaves_no_gap_longer_than_one_job() {
    let _s = serial();
    let rig = rig(true, Relays::None);
    // m0 connects again when asked; m1 takes a new extranonce on the same connection
    let ms = [miner(&rig.miners_addr, "m0", 18, 12.0, true, false), miner(&rig.miners_addr, "m1", 18, 12.0, true, true)];
    let t0 = Instant::now();
    while !rig.hashmaker.status()["miners"].as_array().is_some_and(|m| m.len() == 2 && m.iter().all(|m| m["work"] != "0")) {
        assert!(t0.elapsed() < Duration::from_secs(20), "miners never all hashed at the fallback");
        thread::sleep(Duration::from_millis(100));
    }
    let dialer = Dialer::start(Relays::None).unwrap();
    let pool = Pool::start(&rig.dir, "both", JOB_MS);
    let b = hashtaker(&rig, dialer.address_for(&rig.iroh).unwrap(), &pool, "both", 2, 8).join().unwrap();
    let r = finished(&rig.hashmaker, "both");
    check_paid(&r, &b);
    let res: Vec<standin::MinerResult> = ms.into_iter().map(|m| m.join().unwrap()).collect();
    rig.hashmaker.shutdown();
    for m in &res {
        assert!(m.max_gap_ms < JOB_MS, "a gap of {} ms between accepted shares, a job is {JOB_MS} ms", m.max_gap_ms);
        assert!(m.rejected * 10 <= m.accepted, "few rejected shares around the switches: {} of {}", m.rejected, m.accepted);
    }
}

/// The link drops for a moment while a rental runs over iroh: the hashtaker dials again through its
/// iroh link and resumes, and the rental runs to its end with every slice paid once and both proven
/// counts the same once what the link lost has been sent again. The drop is a TCP relay in front of the
/// hashtaker's way into its iroh link that closes every connection through it, as a network going away
/// does. The miner stops first, so that no share is on its way when the rental ends and the counts must
/// be equal to the share. (Buyer and hashmaker disagreeing on money after this drop started the proof work.)
#[test]
fn a_rental_over_iroh_whose_link_drops_carries_on_with_every_slice_paid_once() {
    let _s = serial();
    let rig = rig(true, Relays::None);
    let m = miner(&rig.miners_addr, "m0", 18, 12.0, true, false);
    let t0 = Instant::now();
    while !rig.hashmaker.status()["miners"].as_array().is_some_and(|m| m.len() == 1 && m[0]["work"] != "0") {
        assert!(t0.elapsed() < Duration::from_secs(20), "the miner never hashed at the fallback");
        thread::sleep(Duration::from_millis(100));
    }
    let dialer = Dialer::start(Relays::None).unwrap();
    let through = dialer.address_for(&rig.iroh).unwrap();
    let [front] = ports::<1>();
    let open: std::sync::Arc<Mutex<Vec<TcpStream>>> = Default::default();
    {
        let (l, o, to) = (TcpListener::bind(&front).unwrap(), open.clone(), through.clone());
        thread::spawn(move || {
            for c in l.incoming() {
                let Ok(a) = c else { continue };
                let Ok(b) = TcpStream::connect(&to) else { continue };
                o.lock().unwrap().extend([a.try_clone().unwrap(), b.try_clone().unwrap()]);
                for (mut x, mut y) in [(a.try_clone().unwrap(), b.try_clone().unwrap()), (b, a)] {
                    thread::spawn(move || {
                        let _ = std::io::copy(&mut x, &mut y);
                        let _ = y.shutdown(std::net::Shutdown::Both);
                    });
                }
            }
        });
    }
    let pool = Pool::start(&rig.dir, "dropped", JOB_MS);
    let h = hashtaker(&rig, front.clone(), &pool, "dropped", 1, 60);
    // let a few slices go by, then drop every connection on the way
    thread::sleep(Duration::from_secs(5));
    let dropped = {
        let mut g = open.lock().unwrap();
        let n = g.len();
        for s in g.drain(..) {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        n
    };
    assert!(dropped >= 2, "a link was open to drop");
    let b = h.join().unwrap();
    // shown only on a failure: a rental the hashmaker never sees end says nothing of this side otherwise
    eprintln!("hashtaker ended, the link's path {:?}: {b}", dialer.path(&rig.iroh));
    let r = finished(&rig.hashmaker, "dropped");
    assert_eq!(b["closed"], "no proven work", "it ended when the miner stopped, not when the link dropped: hashtaker {b}\nhashmaker {r}");
    check_paid(&r, &b);
    check_counts_agree(&r, &b);
    eprintln!("{} shares counted from being sent again", b["resentCounted"]);
    assert!(paid_after_resume(&r) >= 1, "the rental carried on after the link came back: hashtaker {b}\nhashmaker {r}");
    assert!(open.lock().unwrap().len() >= 2, "the hashtaker dialed again through its iroh link");
    assert!(pool.users()["dropped.rented"] > 0, "the work reached the hashtaker's pool");
    rig.hashmaker.shutdown();
    let _ = m.join();
}

/// What each side's rail moved: the price of every ticket the hashtaker released, and of every one
/// the hashmaker settled.
#[derive(Default)]
struct Books {
    locked_msat: AtomicU64,
    released_msat: AtomicU64,
    cancelled_msat: AtomicU64,
    settled_msat: AtomicU64,
}

struct BuyerBook(LabHashtaker, Arc<Books>);

impl HashtakerRail for BuyerBook {
    fn lock(&mut self, slice: u64, price_msat: u64) -> Result<Hash, String> {
        self.1.locked_msat.fetch_add(price_msat, Ordering::SeqCst);
        self.0.lock(slice, price_msat)
    }

    fn release(&mut self, slice: u64) -> Result<[u8; 32], String> {
        let p = self.0.release(slice)?;
        self.1.released_msat.fetch_add(terms().price_msat, Ordering::SeqCst);
        Ok(p)
    }

    fn cancel(&mut self, slice: u64) {
        self.1.cancelled_msat.fetch_add(terms().price_msat, Ordering::SeqCst);
        self.0.cancel(slice)
    }
}

struct SellerBook(LabSeller, Arc<Books>);

impl SellerRail for SellerBook {
    fn held(&mut self, slice: u64, hash: &Hash, price_msat: u64) -> bool {
        self.0.held(slice, hash, price_msat)
    }

    fn settle(&mut self, slice: u64, preimage: &[u8; 32]) -> Result<(), String> {
        self.0.settle(slice, preimage)?;
        self.1.settled_msat.fetch_add(terms().price_msat, Ordering::SeqCst);
        Ok(())
    }
}

/// A TCP relay in front of the hashtaker's way into its iroh link. It can lose what either side sends
/// with the connection left open, and close what it carries: what a link's last moments do to
/// whatever was on its way, and what a stalled road does to a link that never hears it end.
struct Front {
    addr: String,
    open: Arc<Mutex<Vec<TcpStream>>>,
    /// What the hashtaker sends is lost.
    lose: Arc<AtomicBool>,
    /// What the hashmaker sends is lost.
    lose_down: Arc<AtomicBool>,
    /// The end of one side's connection is not passed on to the other.
    keep: Arc<AtomicBool>,
    /// A connection made now brings this many bytes from the hashmaker and loses the rest.
    down_limit: Arc<AtomicUsize>,
    /// Connections are closed as they come.
    refuse: Arc<AtomicBool>,
}

impl Front {
    fn start(to: String) -> Front {
        let [addr] = ports::<1>();
        let f = Front {
            addr: addr.clone(),
            open: Default::default(),
            lose: Default::default(),
            lose_down: Default::default(),
            keep: Default::default(),
            down_limit: Arc::new(AtomicUsize::new(usize::MAX)),
            refuse: Default::default(),
        };
        let l = TcpListener::bind(&addr).unwrap();
        let (o, lose, lose_down, keep, limit, refuse) = (f.open.clone(), f.lose.clone(), f.lose_down.clone(), f.keep.clone(), f.down_limit.clone(), f.refuse.clone());
        thread::spawn(move || {
            for c in l.incoming() {
                let Ok(mut a) = c else { continue };
                if refuse.load(Ordering::SeqCst) {
                    continue;
                }
                let Ok(mut b) = TcpStream::connect(&to) else { continue };
                o.lock().unwrap().extend([a.try_clone().unwrap(), b.try_clone().unwrap()]);
                let (mut a2, mut b2) = (a.try_clone().unwrap(), b.try_clone().unwrap());
                let (ld, k, room) = (lose_down.clone(), keep.clone(), limit.load(Ordering::SeqCst));
                thread::spawn(move || {
                    let (mut buf, mut seen) = ([0u8; 16 << 10], 0usize);
                    // on until the hashmaker's side ends, whatever became of the other
                    while let Ok(n) = b2.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        let pass = n.min(room.saturating_sub(seen));
                        seen += n;
                        if !ld.load(Ordering::SeqCst) && pass > 0 {
                            let _ = a2.write_all(&buf[..pass]);
                        }
                    }
                    if !k.load(Ordering::SeqCst) {
                        let _ = a2.shutdown(std::net::Shutdown::Both);
                    }
                });
                let (lo, k) = (lose.clone(), keep.clone());
                thread::spawn(move || {
                    let mut buf = [0u8; 16 << 10];
                    while let Ok(n) = a.read(&mut buf) {
                        if n == 0 || (!lo.load(Ordering::SeqCst) && b.write_all(&buf[..n]).is_err()) {
                            break;
                        }
                    }
                    if !k.load(Ordering::SeqCst) {
                        let _ = b.shutdown(std::net::Shutdown::Both);
                    }
                });
            }
        });
        f
    }

    /// Close everything open and carry what comes next again: the hashtaker's new link is whole.
    fn cut(&self) {
        let mut g = self.open.lock().unwrap();
        let open: Vec<TcpStream> = g.drain(..).collect();
        for s in open {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        self.lose.store(false, Ordering::SeqCst);
        self.lose_down.store(false, Ordering::SeqCst);
    }

    /// The road goes silent both ways: nothing arrives, and no side hears that anything ended.
    fn stall(&self) {
        self.keep.store(true, Ordering::SeqCst);
        self.lose.store(true, Ordering::SeqCst);
        self.lose_down.store(true, Ordering::SeqCst);
    }

    /// The hashtaker's side of what is open closes; the hashmaker's stays up and hears nothing.
    fn cut_hashtakers_side(&self) {
        self.keep.store(true, Ordering::SeqCst);
        let open: Vec<TcpStream> = self.open.lock().unwrap().drain(..).collect();
        for s in open.iter().step_by(2) {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }
}

/// A rental through a [`Front`], with both sides' books, up to its first few slices paid.
struct Dropping {
    rig: Rig,
    books: Arc<Books>,
    front: Front,
    pool: Pool,
    live: Arc<Mutex<Value>>,
    h: Option<thread::JoinHandle<Value>>,
    /// Kept for as long as the rental: the miner hashes on, and the link stays up under the relay.
    _miner: thread::JoinHandle<standin::MinerResult>,
    _dialer: Dialer,
}

impl Dropping {
    fn start(name: &str, secs: u64) -> Dropping {
        Dropping::start_with(name, secs, 12.0, None, 90)
    }

    /// `verdicts_after`: the hashtaker's gateway takes this long to answer, through a stand-in. The miner
    /// hashes for `miner_secs`.
    fn start_with(name: &str, secs: u64, rate: f64, verdicts_after: Option<Duration>, miner_secs: u64) -> Dropping {
        Dropping::start_on(name, secs, rate, miner_secs, &|pool: &str| verdicts_after.map_or(pool.to_string(), |d| slow_gateway(pool.to_string(), d)))
    }

    /// As [`Dropping::start_with`], the hashtaker's gateway what `upstream` makes of the pool's address.
    fn start_on(name: &str, secs: u64, rate: f64, miner_secs: u64, upstream: &dyn Fn(&str) -> String) -> Dropping {
        let books: Arc<Books> = Default::default();
        let b2 = books.clone();
        let rig = rig_with(true, Relays::None, Box::new(move || Box::new(SellerBook(LabSeller::default(), b2.clone()))));
        let miner = miner(&rig.miners_addr, "m0", miner_secs, rate, true, false);
        let t0 = Instant::now();
        while !rig.hashmaker.status()["miners"].as_array().is_some_and(|m| m.len() == 1 && m[0]["work"] != "0") {
            assert!(t0.elapsed() < Duration::from_secs(20), "the miner never hashed at the fallback");
            thread::sleep(Duration::from_millis(100));
        }
        let dialer = Dialer::start(Relays::None).unwrap();
        let front = Front::start(dialer.address_for(&rig.iroh).unwrap());
        let pool = Pool::start(&rig.dir, name, JOB_MS);
        let live: Arc<Mutex<Value>> = Default::default();
        let cfg = hashtaker::Config {
            hashmaker: front.addr.clone(),
            hashmaker_key: rig.hpub,
            key: noise::fresh_key(),
            upstream: upstream(&pool.addr),
            user: format!("{name}.rented"),
            terms: terms(),
            rental: name.into(),
            listing: "lab".into(),
            stop_paying_after: None,
            idle: Duration::from_secs(4),
            duration: Some(Duration::from_secs(secs)),
            report: None,
            payer: None,
            miners: 1,
            budget_msat: None,
            cut: None,
            live: Some(live.clone()),
            gateway_api: None,
            allow_unblinded: true,
        };
        let rail = Box::new(BuyerBook(LabHashtaker::default(), books.clone()));
        let h = thread::spawn(move || hashtaker::run(cfg, rail).unwrap());
        let d = Dropping { rig, books, front, pool, live, h: Some(h), _miner: miner, _dialer: dialer };
        d.wait_paid(2);
        d
    }

    fn maker(&self, k: &str) -> Value {
        self.rig.hashmaker.status()["rentals"][0][k].clone()
    }

    fn paid(&self) -> u64 {
        self.maker("paid").as_u64().unwrap_or(0)
    }

    fn wait_paid(&self, n: u64) {
        let t0 = Instant::now();
        while self.paid() < n {
            assert!(t0.elapsed() < Duration::from_secs(20), "{n} slices not paid: {}", self.rig.hashmaker.status());
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// The hashtaker's report, as soon as it ended and no later than `bound` from now.
    fn hashtaker_ended_within(&mut self, bound: Duration) -> Value {
        let h = self.h.take().unwrap();
        let t0 = Instant::now();
        while !h.is_finished() {
            assert!(t0.elapsed() < bound, "the hashtaker has not ended {} s on; its last report: {}", bound.as_secs(), self.live.lock().unwrap());
            thread::sleep(Duration::from_millis(50));
        }
        eprintln!("the hashtaker ended within {} ms", t0.elapsed().as_millis());
        h.join().unwrap()
    }
}

/// A stand-in for a gateway a moment away: what it answers arrives `after` later.
fn slow_gateway(to: String, after: Duration) -> String {
    let [addr] = ports::<1>();
    let l = TcpListener::bind(&addr).unwrap();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(a) = c else { continue };
            let Ok(b) = TcpStream::connect(&to) else { continue };
            let (mut a2, mut b2) = (a.try_clone().unwrap(), b.try_clone().unwrap());
            thread::spawn(move || {
                let _ = std::io::copy(&mut a2, &mut b2);
                let _ = b2.shutdown(std::net::Shutdown::Both);
            });
            let (mut a3, mut b3) = (a, b);
            let (s, r) = std::sync::mpsc::channel::<(Instant, Vec<u8>)>();
            thread::spawn(move || {
                let mut buf = [0u8; 16 << 10];
                while let Ok(n) = b3.read(&mut buf) {
                    if n == 0 || s.send((Instant::now() + after, buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
            });
            thread::spawn(move || {
                for (at, bytes) in r {
                    thread::sleep(at.saturating_duration_since(Instant::now()));
                    if a3.write_all(&bytes).is_err() {
                        break;
                    }
                }
                let _ = a3.shutdown(std::net::Shutdown::Both);
            });
        }
    });
    addr
}

/// A gateway in front of `to` whose sessions open now can all be closed at once (it starting again): returns its
/// address and the switch.
fn closing_gateway(to: String) -> (String, Arc<AtomicBool>) {
    let [addr] = ports::<1>();
    let l = TcpListener::bind(&addr).unwrap();
    let close: Arc<AtomicBool> = Arc::default();
    let open: Arc<Mutex<Vec<TcpStream>>> = Arc::default();
    {
        let (close, open) = (close.clone(), open.clone());
        thread::spawn(move || loop {
            if close.swap(false, Ordering::SeqCst) {
                for s in open.lock().unwrap().drain(..) {
                    let _ = s.shutdown(std::net::Shutdown::Both);
                }
            }
            thread::sleep(Duration::from_millis(5));
        });
    }
    let kept = open.clone();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(a) = c else { continue };
            let Ok(b) = TcpStream::connect(&to) else { continue };
            kept.lock().unwrap().extend([a.try_clone().unwrap(), b.try_clone().unwrap()]);
            let (mut a2, mut b2) = (a.try_clone().unwrap(), b.try_clone().unwrap());
            thread::spawn(move || {
                let _ = std::io::copy(&mut a2, &mut b2);
                let _ = b2.shutdown(std::net::Shutdown::Both);
            });
            let (mut a3, mut b3) = (a, b);
            thread::spawn(move || {
                let _ = std::io::copy(&mut b3, &mut a3);
                let _ = a3.shutdown(std::net::Shutdown::Both);
            });
        }
    });
    (addr, close)
}

/// What each side's rail did, once a rental is over: what left the hashtaker reached the hashmaker, and
/// every ticket not released went back to the hashtaker.
fn check_books(books: &Books, b: &Value, r: &Value) {
    let [locked, released, cancelled, settled] =
        [&books.locked_msat, &books.released_msat, &books.cancelled_msat, &books.settled_msat].map(|a| a.load(Ordering::SeqCst));
    eprintln!("books: locked {locked}, released {released}, cancelled {cancelled}, settled {settled} msat");
    assert_eq!(released, settled, "what left the hashtaker is what reached the hashmaker\nhashtaker {b}\nhashmaker {r}");
    assert_eq!(locked, released + cancelled, "every ticket released or given back\nhashtaker {b}");
    assert!(cancelled > 0, "tickets were still locked when it ended: {b}");
    assert_eq!(b["locked"], json!([]), "none left locked: {b}");
    assert_eq!(b["spentMsat"], r["earnedMsat"], "both sides' sums\nhashtaker {b}\nhashmaker {r}");
    assert_eq!(settled, r["paid"].as_u64().unwrap() * terms().price_msat, "each slice paid once: {r}");
}

/// The link goes silent after a resume: no close, no end of stream, and neither side can tell. The
/// hashtaker ends on its limit for no proven work (the app's is 180 s), and the hashmaker with its miner
/// still hashing once a share that doesn't fit goes unpaid; the miner goes back to the fallback, the books
/// are equal and the unused tickets go back. tests/hostile.rs has the limit with no shares going up.
#[test]
fn a_link_silent_after_a_resume_ends_the_rental_on_both_sides_with_the_books_equal() {
    let _s = serial();
    let mut d = Dropping::start("silent", 120);
    d.front.cut();
    // carrying on after the resume, then silent just after a payment, with none on its way
    let t0 = Instant::now();
    while d.maker("events").as_array().is_none_or(|e| !e.iter().any(|e| e["ev"] == "hashtaker back, rental resumed")) {
        assert!(t0.elapsed() < Duration::from_secs(20), "no resume: {}", d.rig.hashmaker.status());
        thread::sleep(Duration::from_millis(20));
    }
    let paid = d.paid();
    d.wait_paid(paid + 2);
    d.front.stall();
    let stalled = Instant::now();
    let b = d.hashtaker_ended_within(Duration::from_secs(20));
    assert_eq!(b["closed"], "no proven work", "{b}");
    let r = finished(&d.rig.hashmaker, "silent");
    let took = stalled.elapsed();
    eprintln!("the hashmaker ended {} ms after the link went silent", took.as_millis());
    assert_eq!(r["stopped"]["reason"], "unpaid", "{r}");
    assert_eq!(r["stopped"]["unpaidWork"], "0", "{r}");
    assert!(took < hashmaker::QUIET_LIMIT + Duration::from_secs(10), "{} s: {r}", took.as_secs());
    check_books(&d.books, &b, &r);
    assert!(paid_after_resume(&r) >= 2, "{r}");
    let t0 = Instant::now();
    while d.rig.hashmaker.status()["miners"][0]["rentedTo"] != Value::Null {
        assert!(t0.elapsed() < Duration::from_secs(10), "the miner is not free again: {}", d.rig.hashmaker.status());
        thread::sleep(Duration::from_millis(100));
    }
    d.rig.hashmaker.shutdown();
}

/// The link goes silent while the hashtaker waits for the welcome on its way back: the hashmaker got
/// the `resume`, and its answer never comes. The hashtaker ends within the time it had to come back.
#[test]
fn a_hashtaker_waiting_for_the_welcome_on_a_silent_link_ends_within_its_time_to_come_back() {
    let _s = serial();
    let mut d = Dropping::start("nowelcome", 120);
    // the 50 bytes are the handshake's act two: the link is made, and nothing more arrives on it
    d.front.down_limit.store(50, Ordering::SeqCst);
    d.front.cut();
    // the deadline to come back is four fifths of the grace time; its last dial may start just before
    let b = d.hashtaker_ended_within(Duration::from_millis(terms().grace_ms) + Duration::from_secs(15));
    assert!(b["closed"].as_str().unwrap().starts_with("link lost"), "{b}");
    let r = finished(&d.rig.hashmaker, "nowelcome");
    check_books(&d.books, &b, &r);
    d.rig.hashmaker.shutdown();
}

/// The hashtaker's side of the link closes and the hashmaker's stays up and quiet, so the hashtaker
/// says `resume` to a hashmaker that has not noticed anything. It is the same hashtaker by its key:
/// the rental carries on, every slice paid once.
#[test]
fn a_hashtaker_back_before_the_hashmaker_noticed_the_drop_carries_on() {
    let _s = serial();
    let mut d = Dropping::start("unnoticed", 12);
    d.front.cut_hashtakers_side();
    let b = d.hashtaker_ended_within(Duration::from_secs(25));
    let r = finished(&d.rig.hashmaker, "unnoticed");
    assert_eq!(b["closed"], "rental time over", "it was not ended by the drop: hashtaker {b}\nhashmaker {r}");
    check_books(&d.books, &b, &r);
    check_paid(&r, &b);
    assert!(paid_after_resume(&r) >= 1, "the rental carried on: {r}");
    assert!(d.pool.users()["unnoticed.rented"] > 0);
    d.rig.hashmaker.shutdown();
}

/// A slice paid into the loss, and the lock made when it was paid gone with it. Both are sent again, or
/// the slice after next has nothing to be checked against, and the rental stops. No share goes past what's
/// paid, so no more than this can be paid into a loss; the hashmaker's short clock for a share that doesn't
/// fit starts soon after, and this share rate leaves the time to see the payment go and drop the link.
#[test]
fn locks_lost_with_their_payments_are_sent_again_with_them() {
    let _s = serial();
    let mut d = Dropping::start_with("locks", 22, 4.0, None, 90);
    d.front.lose.store(true, Ordering::SeqCst);
    let t0 = Instant::now();
    loop {
        let (tr, mp) = (d.live.lock().unwrap()["released"].as_u64().unwrap_or(0), d.paid());
        if tr > mp {
            eprintln!("the hashtaker {tr} released, the hashmaker {mp} paid, when the link drops");
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(20), "{}", d.live.lock().unwrap());
        thread::sleep(Duration::from_millis(25));
    }
    d.front.cut();
    let b = d.hashtaker_ended_within(Duration::from_secs(40));
    let r = finished(&d.rig.hashmaker, "locks");
    assert_eq!(b["closed"], "rental time over", "hashtaker {b}\nhashmaker {r}");
    // the payment sent again, the next, and the one whose lock was lost
    assert!(paid_after_resume(&r) >= 3, "the lost lock's slice was paid too: hashtaker {b}\nhashmaker {r}");
    check_books(&d.books, &b, &r);
    check_paid(&r, &b);
    d.rig.hashmaker.shutdown();
}

/// The hashtaker's gateway answers a moment late, so when the link drops verdicts are still on their
/// way to the hashtaker. They never reach it, and a verdict sets no work: the two sides still prove the
/// same, whatever verdicts each has heard.
#[test]
fn verdicts_arriving_after_the_drop_leave_both_sides_counting_the_same() {
    let _s = serial();
    let mut d = Dropping::start_with("late", 14, 12.0, Some(Duration::from_millis(150)), 90);
    d.front.cut();
    let b = d.hashtaker_ended_within(Duration::from_secs(30));
    let r = finished(&d.rig.hashmaker, "late");
    assert_eq!(b["closed"], "rental time over", "hashtaker {b}\nhashmaker {r}");
    check_books(&d.books, &b, &r);
    check_paid(&r, &b);
    assert!(paid_after_resume(&r) >= 1, "{r}");
    d.rig.hashmaker.shutdown();
}

/// What the hashmaker sends is lost for a moment, so shares it counted never reach the hashtaker, and then
/// the link drops. It sends them again on the new link, and the hashtaker checks them and counts each
/// once: the two proven counts come back together, to the share (the miner stops before the rental does,
/// so none is on its way at the end). Each goes on to the gateway on its session of before the drop.
#[test]
fn shares_lost_with_the_link_are_sent_again_and_counted_once() {
    let _s = serial();
    let mut d = Dropping::start_with("resent", 60, 12.0, None, 14);
    d.front.lose_down.store(true, Ordering::SeqCst);
    // a share counted after that was written after it, so the road loses it; what's paid ahead covers one
    let before = d.maker("meter")["proven"].as_u64().unwrap_or(0);
    let t0 = Instant::now();
    while d.maker("meter")["proven"].as_u64().unwrap_or(0) < before + 1 {
        assert!(t0.elapsed() < Duration::from_secs(10), "{}", d.rig.hashmaker.status());
        thread::sleep(Duration::from_millis(2));
    }
    d.front.cut();
    let b = d.hashtaker_ended_within(Duration::from_secs(40));
    let r = finished(&d.rig.hashmaker, "resent");
    assert_eq!(b["closed"], "no proven work", "it ended when the miner stopped: hashtaker {b}\nhashmaker {r}");
    let resent = b["resentCounted"].as_u64().unwrap();
    eprintln!("{resent} shares counted from being sent again");
    assert!(resent >= 1, "a share lost with the link was counted from being sent again: hashtaker {b}\nhashmaker {r}");
    check_counts_agree(&r, &b);
    check_paid(&r, &b);
    check_books(&d.books, &b, &r);
    // the same shares aren't counted twice, nor said against: a resend that was counted already is no repeat
    assert_eq!(b["meter"]["repeats"], 0, "{b}");
    assert_eq!(b["meter"]["refused"], 0, "{b}");
    // the shares sent again went on to the gateway, on their session of before the drop, for their verdicts: it took
    // every share both sides counted
    let pool = d.pool.report();
    let proven = b["meter"]["proven"].as_u64().unwrap();
    assert_eq!(pool["accepted"].as_u64().unwrap(), proven, "pool {pool}\nhashtaker {b}");
    d.rig.hashmaker.shutdown();
}

/// Shares the hashmaker counted are lost with the link, and the hashtaker's gateway starts again as the link drops, so
/// the hashtaker can't send them on when they come again: it doesn't count them. After the resume each side says its
/// count, and the hashmaker's comes down to the hashtaker's: both books end equal, the hashmaker is paid for no less
/// than its gateway took, and the hashtaker pays for nothing it didn't prove. Without the count after the resume the
/// hashmaker stayed ahead (the over_iroh 9-against-18 the review found).
#[test]
fn shares_the_hashtaker_could_not_send_on_after_a_drop_come_off_the_hashmakers_count() {
    let _s = serial();
    let gate: Arc<Mutex<Option<Arc<AtomicBool>>>> = Arc::default();
    let g2 = gate.clone();
    let mut d = Dropping::start_on("resync", 40, 12.0, 14, &move |pool: &str| {
        let (addr, close) = closing_gateway(pool.to_string());
        *g2.lock().unwrap() = Some(close);
        addr
    });
    d.front.lose_down.store(true, Ordering::SeqCst);
    let before = d.maker("meter")["proven"].as_u64().unwrap_or(0);
    let t0 = Instant::now();
    while d.maker("meter")["proven"].as_u64().unwrap_or(0) < before + 2 {
        assert!(t0.elapsed() < Duration::from_secs(10), "{}", d.rig.hashmaker.status());
        thread::sleep(Duration::from_millis(2));
    }
    // the gateway starts again as the link drops: the sessions the shares sent again would go on are gone
    gate.lock().unwrap().as_ref().unwrap().store(true, Ordering::SeqCst);
    d.front.cut();
    let b = d.hashtaker_ended_within(Duration::from_secs(40));
    let r = finished(&d.rig.hashmaker, "resync");
    eprintln!("MEASURED resync: hashmaker lowered {} after the resume; hashtaker refused {} sent again; counts {} / {}", r["loweredAfterResumes"],
              b["resendsRefused"], r["meter"]["work"], b["meter"]["work"]);
    assert!(b["resendsRefused"].as_u64().unwrap() >= 1, "a share the hashtaker couldn't send on: {b}");
    assert!(r["loweredAfterResumes"].as_str().unwrap().parse::<u128>().unwrap() > 0, "{r}");
    check_counts_agree(&r, &b);
    check_paid(&r, &b);
    // the hashmaker is paid for no less than the gateway took
    let pool = d.pool.report();
    let took = pool["work"].as_str().unwrap().parse::<u128>().unwrap();
    assert!(took <= xbt_hashlink::order::paid_work(r["paid"].as_u64().unwrap(), 0, terms().slice_work), "pool {pool}\nhashmaker {r}");
    d.rig.hashmaker.shutdown();
}

/// Measured for docs/P2P-HASH.md, not a pass line, on the lab's rail: right after a resume, what the
/// hashtaker sends is lost again, for longer than the grace time, payments sent again with it.
///
/// `cargo test -p xbt-hashlink --test over_iroh measure_a_second -- --ignored --nocapture`
#[test]
#[ignore]
fn measure_a_second_one_way_outage_right_after_a_resume() {
    let _s = serial();
    let mut d = Dropping::start("again", 30);
    d.front.lose.store(true, Ordering::SeqCst);
    let t0 = Instant::now();
    while d.live.lock().unwrap()["released"].as_u64().unwrap_or(0) <= d.paid() {
        assert!(t0.elapsed() < Duration::from_secs(20));
        thread::sleep(Duration::from_millis(25));
    }
    d.front.cut();
    let t0 = Instant::now();
    while d.maker("events").as_array().is_none_or(|e| !e.iter().any(|e| e["ev"] == "hashtaker back, rental resumed")) {
        assert!(t0.elapsed() < Duration::from_secs(10));
        thread::sleep(Duration::from_millis(2));
    }
    d.front.lose.store(true, Ordering::SeqCst);
    let b = d.hashtaker_ended_within(Duration::from_secs(45));
    let r = finished(&d.rig.hashmaker, "again");
    eprintln!(
        "MEASURED released {} slices, paid {}; hashtaker closed {}; hashmaker stopped {}; rail released {} msat settled {} msat",
        b["released"], r["paid"], b["closed"], r["stopped"]["reason"], d.books.released_msat.load(Ordering::SeqCst), d.books.settled_msat.load(Ordering::SeqCst)
    );
    d.rig.hashmaker.shutdown();
}

/// Measured for docs/P2P-HASH.md, not a pass line, on the lab's rail: what the hashtaker sends is lost for
/// good, payments with it, so a share comes that doesn't fit and the hashmaker stops. How long that takes, and
/// what the hashtaker had let go by then that the hashmaker never settled.
///
/// `cargo test -p xbt-hashlink --test over_iroh measure_what -- --ignored --nocapture`
#[test]
#[ignore]
fn measure_what_a_one_way_outage_leaves_unsettled() {
    let _s = serial();
    let mut d = Dropping::start("oneway", 40);
    d.front.lose.store(true, Ordering::SeqCst);
    let t0 = Instant::now();
    while d.rig.hashmaker.finished().is_empty() && t0.elapsed() < Duration::from_secs(30) {
        thread::sleep(Duration::from_millis(50));
    }
    let stopped_after = t0.elapsed();
    d.front.cut();
    let b = d.hashtaker_ended_within(Duration::from_secs(60));
    let r = finished(&d.rig.hashmaker, "oneway");
    eprintln!(
        "MEASURED the hashmaker stopped {} ms after the outage began; released {} slices, paid {}; hashtaker closed {}; hashmaker stopped {}; rail released {} msat settled {} msat",
        stopped_after.as_millis(), b["released"], r["paid"], b["closed"], r["stopped"], d.books.released_msat.load(Ordering::SeqCst), d.books.settled_msat.load(Ordering::SeqCst)
    );
    d.rig.hashmaker.shutdown();
}

/// Up to the moment the link drops the hashtaker goes on hearing verdicts and paying a slice that never
/// reach the hashmaker. A verdict sets no work, so that leaves no count behind; the payment is sent again.
/// Whatever was on its way, each side ends with the same slices paid, and what the hashtaker released is
/// what the hashmaker settled. The share rate leaves the time to see the payment go before a share that
/// doesn't fit, its payment not heard of, runs out the hashmaker's short clock.
#[test]
fn verdicts_and_a_payment_lost_with_the_link_are_counted_and_paid_once_on_both_sides() {
    let _s = serial();
    let books: Arc<Books> = Default::default();
    let b2 = books.clone();
    let rig = rig_with(true, Relays::None, Box::new(move || Box::new(SellerBook(LabSeller::default(), b2.clone()))));
    let m = miner(&rig.miners_addr, "m0", 30, 4.0, true, false);
    let t0 = Instant::now();
    while !rig.hashmaker.status()["miners"].as_array().is_some_and(|m| m.len() == 1 && m[0]["work"] != "0") {
        assert!(t0.elapsed() < Duration::from_secs(20), "the miner never hashed at the fallback");
        thread::sleep(Duration::from_millis(100));
    }
    let dialer = Dialer::start(Relays::None).unwrap();
    let front = Front::start(dialer.address_for(&rig.iroh).unwrap());
    let pool = Pool::start(&rig.dir, "lost", JOB_MS);
    let live: Arc<Mutex<Value>> = Default::default();
    let cfg = hashtaker::Config {
        hashmaker: front.addr.clone(),
        hashmaker_key: rig.hpub,
        key: noise::fresh_key(),
        upstream: pool.addr.clone(),
        user: "lost.rented".into(),
        terms: terms(),
        rental: "lost".into(),
        listing: "lab".into(),
        stop_paying_after: None,
        idle: Duration::from_secs(4),
        duration: Some(Duration::from_secs(14)),
        report: None,
        payer: None,
        miners: 1,
        budget_msat: None,
        cut: None,
        live: Some(live.clone()),
        gateway_api: None,
        allow_unblinded: true,
    };
    let rail = Box::new(BuyerBook(LabHashtaker::default(), books.clone()));
    let h = thread::spawn(move || hashtaker::run(cfg, rail).unwrap());
    let maker = |k: &str| rig.hashmaker.status()["rentals"][0][k].clone();
    let taker = |k: &str| live.lock().unwrap()[k].clone();
    // a few slices go by, on both sides
    let t0 = Instant::now();
    while maker("paid").as_u64().unwrap_or(0) < 2 {
        assert!(t0.elapsed() < Duration::from_secs(20), "no slices paid: {}", rig.hashmaker.status());
        thread::sleep(Duration::from_millis(20));
    }
    // now what the hashtaker sends is lost, until it has heard a verdict the hashmaker hasn't and paid a
    // slice the hashmaker never hears of
    front.lose.store(true, Ordering::SeqCst);
    let t0 = Instant::now();
    let (ahead_shares, ahead_slices) = loop {
        let (ta, ma) = (taker("meter")["accepted"].as_u64().unwrap_or(0), maker("meter")["accepted"].as_u64().unwrap_or(0));
        let (tr, mp) = (taker("released").as_u64().unwrap_or(0), maker("paid").as_u64().unwrap_or(0));
        if ta > ma && tr > mp {
            break (ta - ma, tr - mp);
        }
        assert!(t0.elapsed() < Duration::from_secs(20), "the hashtaker never got ahead: {} vs {}", live.lock().unwrap(), rig.hashmaker.status());
        thread::sleep(Duration::from_millis(50));
    };
    eprintln!("the hashtaker ahead by {ahead_shares} verdicts and {ahead_slices} slices when the link drops");
    front.cut();
    let b = h.join().unwrap();
    let r = finished(&rig.hashmaker, "lost");
    // the two sides' books, read for as long as it could still take them to come together: a rental
    // that ended is over, so what they say now is what they will say
    let t0 = Instant::now();
    let (released, settled) = loop {
        let (a, b) = (books.released_msat.load(Ordering::SeqCst), books.settled_msat.load(Ordering::SeqCst));
        if a == b || t0.elapsed() > Duration::from_secs(10) {
            break (a, b);
        }
        thread::sleep(Duration::from_millis(100));
    };
    eprintln!("books after {} ms: released {released} msat, settled {settled} msat; hashtaker paid {} hashmaker paid {}", t0.elapsed().as_millis(), b["released"], r["paid"]);
    assert_eq!(released, settled, "what left the hashtaker is what reached the hashmaker\nhashtaker {b}\nhashmaker {r}");
    assert_eq!(b["spentMsat"], r["earnedMsat"], "both sides' sums\nhashtaker {b}\nhashmaker {r}");
    assert_eq!(settled, r["paid"].as_u64().unwrap() * terms().price_msat, "each slice paid once: {r}");
    check_paid(&r, &b);
    assert_eq!(b["closed"], "rental time over", "the rental ran to its end, nothing refused: hashtaker {b}\nhashmaker {r}");
    assert_eq!(r["unitWork"]["m0"], r["meter"]["work"], "its miner has all the proven work, with or without verdicts: {r}");
    assert!(pool.users()["lost.rented"] > 0, "the work reached the hashtaker's pool");
    rig.hashmaker.shutdown();
    let _ = m.join();
}

/// A TCP stand-in for whatever carries the link (a relay): it passes bytes both ways, and changes
/// one byte of the hashmaker's side after the handshake when `flip`.
fn carrier(to: String, flip: bool) -> String {
    let [addr] = ports::<1>();
    let l = TcpListener::bind(&addr).unwrap();
    thread::spawn(move || {
        let Ok((a, _)) = l.accept() else { return };
        let b = TcpStream::connect(&to).unwrap();
        let (mut a2, mut b2) = (a.try_clone().unwrap(), b.try_clone().unwrap());
        thread::spawn(move || {
            let _ = std::io::copy(&mut a2, &mut b2);
        });
        // hashmaker to hashtaker: act two (50 bytes) untouched, then the first message changed
        let (mut from, mut to) = (b, a);
        let mut seen = 0usize;
        let mut buf = [0u8; 4096];
        loop {
            let n = match from.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            if flip && seen < 60 && seen + n > 60 {
                buf[60 - seen] ^= 0x01;
            }
            seen += n;
            if to.write_all(&buf[..n]).is_err() {
                return;
            }
        }
    });
    addr
}

#[test]
fn a_byte_changed_on_the_way_breaks_the_link_and_no_message_gets_through() {
    for flip in [false, true] {
        let [listen] = ports::<1>();
        let hk = noise::fresh_key();
        let hpub = PublicKey::from_secret_key(secp256k1::SECP256K1, &hk);
        let l = TcpListener::bind(&listen).unwrap();
        let server = thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let lk = link::answer(s, hk).unwrap();
            let _ = lk.tx.send(&Msg::Up { chan: 1, line: "{\"method\":\"mining.notify\",\"params\":[\"job\"]}".into() });
            thread::sleep(Duration::from_millis(300));
        });
        let via = carrier(listen.clone(), flip);
        let mut lk = link::dial(&via, noise::fresh_key(), hpub).unwrap();
        let got = lk.rx.recv();
        if flip {
            assert!(got.is_err(), "a changed byte must fail the message's authentication, got {got:?}");
        } else {
            assert!(matches!(got, Ok(Some(Msg::Up { chan: 1, .. }))), "untouched, the message arrives: {got:?}");
        }
        server.join().unwrap();
    }
}

/// The round trip of a share, from the miner's submit to the pool's answer, through the hashmaker,
/// the link and the hashtaker: over TCP, over iroh directly, and over iroh through relays.
///
/// `cargo test --release -p xbt-hashlink --test over_iroh share_round_trip -- --ignored --nocapture`
/// (set `HASHLINK_RELAYS=url,url` for the relayed run; it is skipped without).
#[test]
#[ignore]
fn share_round_trip() {
    let _s = serial();
    let secs = 30;
    let mut runs: Vec<(String, Relays, bool)> = vec![("tcp".into(), Relays::None, false), ("iroh direct".into(), Relays::None, true)];
    if let Ok(r) = std::env::var("HASHLINK_RELAYS") {
        let urls: Vec<String> = r.split(',').map(str::to_string).collect();
        runs.push((format!("iroh via {r}"), Relays::Ours(urls), true));
    }
    for (name, relays, over) in runs {
        let rig = rig(false, relays.clone());
        let pool = Pool::start(&rig.dir, "rtt", JOB_MS);
        // over a relay, the hashtaker's link may use relays only (no direct path): what a hashtaker
        // behind a strict router gets
        let dialer = over.then(|| if matches!(relays, Relays::None) { Dialer::start(relays.clone()) } else { Dialer::start_private(relays.clone()) }.unwrap());
        let addr = match &dialer {
            Some(d) => d.address_for(&rig.iroh).unwrap(),
            None => rig.link.clone(),
        };
        let b = hashtaker(&rig, addr, &pool, "rtt", 1, secs + 6);
        thread::sleep(Duration::from_millis(500));
        let m = miner(&rig.miners_addr, "m0", secs, 10.0, false, false).join().unwrap();
        let _ = b.join();
        rig.hashmaker.shutdown();
        let rep = pool.report();
        let q = |x| m.rtt_quantile_us(x).map(|v| format!("{:.2}", v as f64 / 1000.0)).unwrap_or("-".into());
        eprintln!(
            "{name}: {} shares, round trip ms p50 {} p90 {} p99 {} max {}; accepted {}, rejected {} ({})",
            m.share_rtt_us.len(),
            q(0.5),
            q(0.9),
            q(0.99),
            q(1.0),
            m.accepted,
            m.rejected,
            rep["reasons"]
        );
    }
}
