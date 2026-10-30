//! The hashrate link over iroh: the same rentals as over TCP, with the hashtaker reaching the
//! hashmaker by its iroh key instead of an address it forwarded. Offline: no relay, direct addresses
//! on loopback (the relay runs are the ignored measurement at the end).
//!
//! * a rental over iroh pays every slice and both meters agree, as over TCP;
//! * one hashtaker app's link reaches the hashmaker again for a second rental;
//! * a miner moved into a rental over iroh and back loses no more than a job;
//! * a rental over iroh whose link drops for a moment carries on, every slice paid once;
//! * a byte changed on the way (what a relay could try) breaks the link instead of a job or a share;
//! * (ignored) the round trip of a share, over TCP and over iroh, direct and through relays.

use secp256k1::PublicKey;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};
use xbt_hashlink::hashmaker::{self, Hashmaker};
use xbt_hashlink::listing::IrohLink;
use xbt_hashlink::meter::share_work;
use xbt_hashlink::msg::{Msg, Terms};
use xbt_hashlink::over_iroh::{self, Dialer, Link, Relays};
use xbt_hashlink::rail::{LabHashtaker, LabSeller};
use xbt_hashlink::{hashtaker, link, noise, standin};

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
    let d = std::env::temp_dir().join(format!("hashlink-iroh-{}", hex::encode(b)));
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
    let dir = tempdir();
    let [link, miners_addr] = ports::<2>();
    let hk = noise::fresh_key();
    let hpub = PublicKey::from_secret_key(secp256k1::SECP256K1, &hk);
    let fb = fallback.then(|| Pool::start(&dir, "fallback", JOB_MS).addr);
    let hashmaker = Hashmaker::start(
        hashmaker::Config { miners: miners_addr.clone(), link: link.clone(), key: hk, terms: terms(), report: None, slices: None, fallback: fb, rentable: None },
        Box::new(|| Box::<LabSeller>::default()),
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
    };
    thread::spawn(move || hashtaker::run(cfg, Box::<LabHashtaker>::default()).unwrap())
}

fn finished(h: &Hashmaker, id: &str) -> Value {
    let t0 = Instant::now();
    loop {
        if let Some(r) = h.finished().into_iter().find(|r| r["rental"] == id) {
            return r;
        }
        assert!(t0.elapsed() < Duration::from_secs(30), "rental {id} never ended: {}", h.status());
        thread::sleep(Duration::from_millis(100));
    }
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
/// iroh link and resumes, and the rental runs to its end with every slice paid once and both meters
/// agreeing. The drop is a TCP relay in front of the hashtaker's way into its iroh link that closes
/// every connection through it, as a network going away does.
#[test]
fn a_rental_over_iroh_whose_link_drops_carries_on_with_every_slice_paid_once() {
    let _s = serial();
    let rig = rig(true, Relays::None);
    let m = miner(&rig.miners_addr, "m0", 30, 12.0, true, false);
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
    let h = hashtaker(&rig, front.clone(), &pool, "dropped", 1, 14);
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
    let r = finished(&rig.hashmaker, "dropped");
    check_paid(&r, &b);
    assert!(open.lock().unwrap().len() >= 2, "the hashtaker dialed again through its iroh link");
    assert!(pool.users()["dropped.rented"] > 0, "the work reached the hashtaker's pool");
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
