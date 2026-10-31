//! A hashtaker and a hashmaker that are not honest, scripted over the real link against the real app on the
//! other side: what each can make the other do, and what it can take for nothing. Shares here are real
//! hashes of real jobs, at a tiny difficulty, so the check these go through is the one a rental uses.

use secp256k1::{PublicKey, SecretKey};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use xbt_hashlink::hashmaker::{self, Hashmaker};
use xbt_hashlink::meter::{share_work, Receipt};
use xbt_hashlink::msg::{Msg, Terms, PROOF};
use xbt_hashlink::rail::{sha256, LabHashtaker, LabSeller, Payer};
use xbt_hashlink::{hashtaker, link, noise, standin};

const DIFF: f64 = 1.0 / (1u64 << 20) as f64;
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

struct App {
    h: Hashmaker,
    hpub: PublicKey,
    link: String,
    miners: String,
}

fn app(terms: &Terms) -> App {
    app_with(terms, hashmaker::MIN_SLICE_TIME)
}

fn app_with(terms: &Terms, min_slice_time: Duration) -> App {
    app_full(terms, min_slice_time, None)
}

fn app_full(terms: &Terms, min_slice_time: Duration, fallback: Option<String>) -> App {
    let [link, miners] = ports::<2>();
    let hk = noise::fresh_key();
    let h = Hashmaker::start(
        hashmaker::Config { miners: miners.clone(), link: link.clone(), key: hk, terms: terms.clone(), report: None, slices: None, fallback, rentable: None, min_slice_time },
        Box::new(|| Box::<LabSeller>::default()),
    )
    .unwrap();
    wait_for(&link);
    App { h, hpub: PublicKey::from_secret_key(secp256k1::SECP256K1, &hk), link, miners }
}

/// What the scripted hashtaker does with the shares it's given.
#[derive(Clone, Copy, PartialEq)]
enum Verdicts {
    None,
    RejectAll,
    AcceptEvery(u64),
    AcceptAll,
}

/// The scripted hashtaker: it pays when told to, gives out real jobs, and answers shares as told.
struct Buyer {
    tx: link::Sender,
    rx: mpsc::Receiver<Msg>,
    key: SecretKey,
    rental: String,
    chan: Option<u32>,
    shares: u64,
    resent: Vec<String>,
    verdicts: Verdicts,
    diff: f64,
    dues: u64,
    ended: bool,
}

fn connect(addr: &str, key: SecretKey, hpub: PublicKey, rental: &str, first: Msg) -> (Buyer, Msg) {
    let l = link::dial(addr, key, hpub).unwrap();
    l.tx.send(&first).unwrap();
    let (s, r) = mpsc::channel();
    let mut rx = l.rx;
    thread::spawn(move || loop {
        match rx.recv() {
            Ok(Some(m)) => {
                if s.send(m).is_err() {
                    return;
                }
            }
            Ok(None) => {}
            Err(_) => return,
        }
    });
    let reply = r.recv_timeout(Duration::from_secs(10)).unwrap();
    (Buyer { tx: l.tx, rx: r, key, rental: rental.into(), chan: None, shares: 0, resent: Vec::new(), verdicts: Verdicts::None, diff: DIFF, dues: 0, ended: false }, reply)
}

fn hello(id: &str, terms: &Terms) -> Msg {
    Msg::Hello { rental: id.into(), listing: "lab".into(), terms: terms.clone(), miners: 1, proof: Some(PROOF.into()) }
}

fn job_line(k: u64, clean: bool) -> Value {
    standin::notify_line(&format!("j{k}"), k, 1_700_000_000, clean)
}

impl Buyer {
    fn down(&self, chan: u32, v: Value) {
        let _ = self.tx.send(&Msg::Down { chan, line: v.to_string() });
    }

    /// Pay this slice over the link, ahead of its work.
    fn pay(&self, slice: u64) {
        let pre = [slice as u8; 32];
        self.tx.send(&Msg::Lock { slice, hash: hex::encode(sha256(&pre)) }).unwrap();
        let receipt = Receipt { rental: self.rental.clone(), slice, work: 0, accepted: 0, rejected: 0, at_ms: 1 }.sign(&self.key);
        self.tx.send(&Msg::Pay { slice, preimage: hex::encode(pre), receipt }).unwrap();
    }

    /// Read until a miner's channel is open and has its first job.
    fn until_serving(&mut self) {
        let t0 = Instant::now();
        while self.chan.is_none() && t0.elapsed() < Duration::from_secs(10) {
            self.pump(u64::MAX, Duration::from_millis(50));
        }
        self.pump(u64::MAX, Duration::from_millis(300));
        assert!(self.chan.is_some(), "no miner came");
    }

    /// Answer the session's set-up lines and the shares as told, for `wait` or until `n` shares have come.
    fn pump(&mut self, n: u64, wait: Duration) {
        let t0 = Instant::now();
        while self.shares < n && t0.elapsed() < wait {
            let m = match self.rx.recv_timeout(Duration::from_millis(50)) {
                Ok(m) => m,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    self.ended = true;
                    return;
                }
            };
            match m {
                Msg::Open { chan, .. } => self.chan = Some(chan),
                Msg::Ping { n } => {
                    let _ = self.tx.send(&Msg::Pong { n });
                }
                Msg::Close { .. } => {
                    self.ended = true;
                    return;
                }
                Msg::Resend { line, .. } => self.resent.push(line),
                Msg::Due { .. } => self.dues += 1,
                Msg::Up { chan, line } => {
                    let v: Value = serde_json::from_str(&line).unwrap();
                    match v["method"].as_str() {
                        Some("mining.subscribe") => self.down(chan, json!({"id": v["id"], "result": [[], "00000001", 8], "error": null})),
                        Some("mining.authorize") => {
                            self.down(chan, json!({"id": v["id"], "result": true, "error": null}));
                            self.down(chan, json!({"id": null, "method": "mining.set_difficulty", "params": [self.diff]}));
                            self.down(chan, job_line(1, true));
                        }
                        Some("mining.submit") => {
                            self.shares += 1;
                            let ok = match self.verdicts {
                                Verdicts::None => continue,
                                Verdicts::RejectAll => false,
                                Verdicts::AcceptEvery(k) => self.shares.is_multiple_of(k),
                                Verdicts::AcceptAll => true,
                            };
                            self.down(chan, json!({"id": v["id"], "result": ok, "error": if ok { Value::Null } else { json!([23, "low difficulty", null]) }}));
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }
}

/// What the scripted miner sends.
#[derive(Clone, Copy, PartialEq)]
enum Sends {
    /// Real shares at this many times the difficulty it was given.
    Real(f64),
    /// Shares nobody hashed.
    Junk,
    /// One real share, over and over.
    Repeat,
}

/// A miner that sends a share every `gap` once it has a job, up to `shares`, and keeps the answers.
struct Miner {
    answers: Arc<Mutex<Vec<Value>>>,
    jobs: Arc<AtomicU64>,
    s: TcpStream,
}

fn scripted_miner(addr: &str, shares: u64, gap: Duration, sends: Sends) -> Miner {
    let s = TcpStream::connect(addr).unwrap();
    let mut w = s.try_clone().unwrap();
    writeln!(w, "{}", json!({"id": 1, "method": "mining.subscribe", "params": []})).unwrap();
    writeln!(w, "{}", json!({"id": 2, "method": "mining.authorize", "params": ["m0", "x"]})).unwrap();
    let answers: Arc<Mutex<Vec<Value>>> = Arc::default();
    let jobs: Arc<AtomicU64> = Arc::default();
    let state: Arc<Mutex<(String, f64, Option<Value>)>> = Arc::new(Mutex::new((String::new(), 1.0, None)));
    {
        let (answers, jobs, state, r) = (answers.clone(), jobs.clone(), state.clone(), s.try_clone().unwrap());
        thread::spawn(move || {
            let mut r = BufReader::new(r);
            let mut line = String::new();
            while r.read_line(&mut line).is_ok_and(|n| n > 0) {
                let v: Value = serde_json::from_str(line.trim()).unwrap_or(Value::Null);
                let mut g = state.lock().unwrap();
                match v["method"].as_str() {
                    Some("mining.set_difficulty") => g.1 = v["params"][0].as_f64().unwrap(),
                    Some("mining.notify") => {
                        jobs.fetch_add(1, Ordering::SeqCst);
                        g.2 = Some(v);
                    }
                    _ if v["id"] == 1 => g.0 = v["result"][1].as_str().unwrap_or("").to_string(),
                    _ if v["id"].as_u64().is_some_and(|i| i >= 100) => answers.lock().unwrap().push(v),
                    _ => {}
                }
                line.clear();
            }
        });
    }
    thread::spawn(move || {
        let mut sent = 0u64;
        let mut en2 = 0u64;
        let mut repeat = None;
        while sent < shares {
            let (en1, d, job) = state.lock().unwrap().clone();
            let Some(job) = job.filter(|_| !en1.is_empty()) else {
                thread::sleep(Duration::from_millis(10));
                continue;
            };
            en2 += 1;
            let id = job["params"][0].clone();
            let ntime = job["params"][7].clone();
            let line = match sends {
                Sends::Junk => json!({"id": 100 + sent, "method": "mining.submit", "params": ["m0", id, format!("{en2:016x}"), ntime, "ffffffff"]}),
                Sends::Real(factor) => {
                    let (e2, n) = standin::find_share(&job, &en1, 8, d * factor, en2).unwrap();
                    json!({"id": 100 + sent, "method": "mining.submit", "params": ["m0", id, e2, ntime, n]})
                }
                Sends::Repeat => {
                    let (e2, n) = repeat.get_or_insert_with(|| standin::find_share(&job, &en1, 8, d, en2).unwrap()).clone();
                    json!({"id": 100 + sent, "method": "mining.submit", "params": ["m0", id, e2, ntime, n]})
                }
            };
            if writeln!(w, "{line}").is_err() {
                return;
            }
            sent += 1;
            thread::sleep(gap);
        }
    });
    Miner { answers, jobs, s }
}

/// The app's one lock is free: its status answers, on another thread, within 2 s.
fn app_answers(h: &Hashmaker) -> Value {
    let status = h.status_fn();
    let (s, r) = mpsc::channel();
    thread::spawn(move || {
        let _ = s.send(status());
    });
    r.recv_timeout(Duration::from_secs(2)).expect("the app gave no answer within 2 s: its lock is held")
}

fn rental_where(h: &Hashmaker, what: &str, mut ok: impl FnMut(&Value) -> bool) -> Value {
    let t0 = Instant::now();
    loop {
        let r = app_answers(h)["rentals"][0].clone();
        if ok(&r) {
            return r;
        }
        assert!(t0.elapsed() < Duration::from_secs(20), "{what}: {r}");
        thread::sleep(Duration::from_millis(20));
    }
}

fn finished(h: &Hashmaker, id: &str, within: Duration) -> Value {
    let t0 = Instant::now();
    loop {
        if let Some(r) = h.finished().into_iter().find(|r| r["rental"] == id) {
            return r;
        }
        assert!(t0.elapsed() < within, "rental {id} still on after {} s: {}", within.as_secs(), app_answers(h));
        thread::sleep(Duration::from_millis(50));
    }
}

/// Keep a scripted hashtaker's link read until its rental ends.
fn run_until_ended(a: &App, b: &mut Buyer, id: &str, within: Duration) -> Value {
    let t0 = Instant::now();
    while !b.ended && t0.elapsed() < within && !a.h.finished().iter().any(|r| r["rental"] == id) {
        b.pump(u64::MAX, Duration::from_millis(100));
    }
    finished(&a.h, id, Duration::from_secs(5))
}

// --- a hashtaker that cheats ---------------------------------------------------------------------------

/// No first payment: no miner moves, none is reserved, and the rental ends on the grace time.
#[test]
fn a_hello_with_no_payment_gets_no_miner_reserves_none_and_ends_on_time() {
    let _s = serial();
    let terms = Terms { slice_work: 8 * share_work(DIFF), price_msat: 5_000, grace_ms: 2_000, start_slices: 0 };
    let a = app(&terms);
    let m = scripted_miner(&a.miners, 4, Duration::from_millis(20), Sends::Real(1.0));
    thread::sleep(Duration::from_millis(300));
    let (mut b, w) = connect(&a.link, noise::fresh_key(), a.hpub, "free", hello("free", &terms));
    assert!(matches!(w, Msg::Welcome { .. }), "{w:?}");
    let t0 = Instant::now();
    let c = a.h.capacity();
    assert_eq!((c.miners, c.free_miners), (1, 1), "nothing is reserved for a rental that hasn't paid");
    let r = run_until_ended(&a, &mut b, "free", Duration::from_secs(10));
    assert_eq!(r["stopped"]["reason"], "no first payment", "{r}");
    assert!(t0.elapsed() < Duration::from_secs(4), "{} ms", t0.elapsed().as_millis());
    assert!(b.chan.is_none(), "no channel was opened");
    assert_eq!(b.shares, 0);
    assert_eq!(m.jobs.load(Ordering::SeqCst), 0, "no job reached the miner");
    a.h.shutdown();
}

/// What a renter says about shares sets nothing: whatever its verdicts, proven work is counted, the rental runs to
/// what's paid, and the next share waits on the clock and goes no further.
#[test]
fn verdicts_set_nothing_and_a_rental_stops_as_proven_work_passes_paid() {
    let _s = serial();
    let sw = share_work(DIFF);
    for verdicts in [Verdicts::None, Verdicts::RejectAll, Verdicts::AcceptEvery(5), Verdicts::AcceptAll] {
        let terms = Terms { slice_work: 4 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
        let a = app(&terms);
        let (mut b, _) = connect(&a.link, noise::fresh_key(), a.hpub, "r", hello("r", &terms));
        b.verdicts = verdicts;
        b.pay(1);
        b.pay(2);
        let _m = scripted_miner(&a.miners, 400, Duration::from_millis(5), Sends::Real(1.0));
        let r = run_until_ended(&a, &mut b, "r", Duration::from_secs(30));
        assert_eq!(r["stopped"]["reason"], "unpaid", "{r}");
        assert_eq!(r["paid"], 2, "{r}");
        assert_eq!(r["meter"]["work"], (8 * sw).to_string(), "two slices of 4 shares and no more: {}", r["meter"]);
        assert_eq!(r["stopped"]["unpaidWork"], "0", "no share past what's paid: {r}");
        assert_eq!(b.shares, 8, "the one that didn't fit never reached the renter");
        a.h.shutdown();
    }
}

/// A share that doesn't fit waits for payment and isn't lost if payment comes inside the clock.
#[test]
fn a_share_waiting_for_payment_goes_on_when_it_comes() {
    let _s = serial();
    let sw = share_work(DIFF);
    let terms = Terms { slice_work: 2 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
    let a = app(&terms);
    let (mut b, _) = connect(&a.link, noise::fresh_key(), a.hpub, "r", hello("r", &terms));
    b.pay(1);
    let _m = scripted_miner(&a.miners, 3, Duration::from_millis(50), Sends::Real(1.0));
    b.pump(2, Duration::from_secs(15));
    assert_eq!(b.shares, 2);
    thread::sleep(Duration::from_millis(400));
    let r = rental_where(&a.h, "the third share proven and waiting", |r| r["meter"]["work"] == (2 * sw).to_string());
    assert_eq!(r["stopped"], Value::Null);
    b.pay(2);
    b.pump(3, Duration::from_secs(5));
    assert_eq!(b.shares, 3, "it went on once paid");
    rental_where(&a.h, "the third share counted", |r| r["meter"]["work"] == (3 * sw).to_string());
    thread::sleep(Duration::from_millis(2300));
    assert!(a.h.finished().is_empty(), "nothing waits, so no clock runs: {:?}", a.h.finished());
    a.h.shutdown();
}

/// A start fee buys no work: miners don't move till it and a slice have arrived, and what fits is what's past it.
#[test]
fn a_start_fee_is_paid_first_and_buys_no_work() {
    let _s = serial();
    let sw = share_work(DIFF);
    let terms = Terms { slice_work: 2 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 2 };
    let a = app(&terms);
    let (mut b, _) = connect(&a.link, noise::fresh_key(), a.hpub, "r", hello("r", &terms));
    b.pay(1);
    b.pay(2);
    let _m = scripted_miner(&a.miners, 8, Duration::from_millis(30), Sends::Real(1.0));
    b.pump(u64::MAX, Duration::from_millis(1500));
    assert!(b.chan.is_none(), "the fee alone moves no miner");
    b.pay(3);
    let r = run_until_ended(&a, &mut b, "r", Duration::from_secs(20));
    assert_eq!(r["stopped"]["reason"], "unpaid", "{r}");
    assert_eq!(b.shares, 2, "one slice's worth");
    assert_eq!(r["meter"]["work"], (2 * sw).to_string(), "{r}");
    assert_eq!(r["earnedMsat"], 15_000, "{r}");
    a.h.shutdown();
}

/// The simulation's "first step then walks", over and over with a new key each time: each rental pays its start
/// fee and its first slice, gets no more work than that slice, and the hashmaker's miners go home. A new key buys
/// nothing that the last one didn't pay for.
#[test]
fn a_renter_walking_after_its_first_step_with_new_keys_gets_no_work_it_did_not_pay_for() {
    let _s = serial();
    let sw = share_work(DIFF);
    let terms = Terms { slice_work: 4 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 1 };
    let a = app(&terms);
    for k in 0..3 {
        let id = format!("walk{k}");
        let (mut b, _) = connect(&a.link, noise::fresh_key(), a.hpub, &id, hello(&id, &terms));
        b.verdicts = Verdicts::AcceptAll;
        b.pay(1);
        b.pay(2);
        let m = scripted_miner(&a.miners, 50, Duration::from_millis(5), Sends::Real(1.0));
        let r = run_until_ended(&a, &mut b, &id, Duration::from_secs(20));
        eprintln!("{id}: stopped {} with {} shares forwarded, {} earned", r["stopped"]["reason"], b.shares, r["earnedMsat"]);
        assert_eq!(r["stopped"]["reason"], "unpaid", "{r}");
        assert_eq!(r["earnedMsat"], 10_000, "the fee and one slice: {r}");
        assert_eq!(r["meter"]["work"], (4 * sw).to_string(), "one slice of work and no more: {r}");
        assert_eq!(r["stopped"]["unpaidWork"], "0", "{r}");
        assert_eq!(b.shares, 4);
        let _ = m.s.shutdown(std::net::Shutdown::Both);
        thread::sleep(Duration::from_millis(300));
    }
    a.h.shutdown();
}

/// A renter that stops paying partway: the share that doesn't fit waits on the clock, then the rental stops. Measured
/// from the first share held to the end, against the simulation's 2 s clock.
#[test]
fn measure_a_renter_stopping_partway_ends_within_the_clock() {
    let _s = serial();
    let sw = share_work(DIFF);
    let terms = Terms { slice_work: 4 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
    let a = app(&terms);
    let (mut b, _) = connect(&a.link, noise::fresh_key(), a.hpub, "part", hello("part", &terms));
    b.verdicts = Verdicts::AcceptAll;
    for i in 1..=3 {
        b.pay(i);
    }
    let _m = scripted_miner(&a.miners, 200, Duration::from_millis(20), Sends::Real(1.0));
    b.pump(12, Duration::from_secs(20));
    assert_eq!(b.shares, 12);
    let t0 = Instant::now();
    let r = run_until_ended(&a, &mut b, "part", Duration::from_secs(10));
    let took = t0.elapsed();
    eprintln!("measure: the last paid share forwarded, then the rental ended {} ms later: {}", took.as_millis(), r["stopped"]["reason"]);
    assert_eq!(r["stopped"]["reason"], "unpaid", "{r}");
    assert_eq!(b.shares, 12, "nothing past what's paid");
    assert!(took < xbt_hashlink::order::WAIT_FOR_PAYMENT + Duration::from_millis(1500), "{} ms", took.as_millis());
    a.h.shutdown();
}

/// The renter's side of the bargain, from a finished rental: no work past what's paid, nothing served unpaid, and what's
/// paid and unused within the step (546 sat, one share, or what was delivered, whichever is most).
fn bargain_kept(r: &Value, terms: &Terms, share: u128) {
    let paid = r["paid"].as_u64().unwrap();
    let work: u128 = r["meter"]["work"].as_str().unwrap().parse().unwrap();
    let paid_work = xbt_hashlink::order::paid_work(paid, terms.start_slices, terms.slice_work);
    assert_eq!(r["stopped"]["unpaidWork"], "0", "nothing served unpaid: {r}");
    assert!(work <= paid_work, "no work past what's paid: {r}");
    let msat = |w: u128| (w * terms.price_msat as u128 / terms.slice_work) as u64;
    let unused = msat(paid_work - work);
    let step = xbt_hashlink::order::FIRST_STEP_MSAT.max(msat(share)).max(msat(work));
    assert!(unused <= step, "paid and unused {unused} msat over the step {step}: {r}");
}

/// Resume, over and over, as a renter that pays as it goes: one resume a paid slice. The resume limit (8 more than the
/// slices paid) is never in reach, so the rental runs to the end of what's paid, and stops there unpaid.
#[test]
fn a_resume_loop_under_the_limit_ends_unpaid_with_the_bargain_kept() {
    let _s = serial();
    let sw = share_work(DIFF);
    let terms = Terms { slice_work: 20 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
    let a = app(&terms);
    let bk = noise::fresh_key();
    let (mut b, _) = connect(&a.link, bk, a.hpub, "loop", hello("loop", &terms));
    for i in 1..=4 {
        b.pay(i);
    }
    let stop: Arc<AtomicBool> = Arc::default();
    let (ma, st2) = (a.miners.clone(), stop.clone());
    let miner = thread::spawn(move || {
        let _ = standin::miner(standin::MinerConfig { pool: ma, user: "m0".into(), max_rate: 40.0, bad_every: 0, duration: Some(Duration::from_secs(60)), reconnect: true, extranonce_subscribe: false, bind: None });
        st2.store(true, Ordering::SeqCst);
    });
    let mut most_resent = 0;
    // three resumes, each once some work has come
    for _ in 0..3 {
        b.pump(b.shares + 10, Duration::from_secs(15));
        let (mut nb, w) = connect(&a.link, bk, a.hpub, "loop", Msg::Resume { rental: "loop".into() });
        assert!(matches!(w, Msg::Welcome { .. }), "{w:?}");
        nb.pump(u64::MAX, Duration::from_millis(100));
        most_resent = most_resent.max(nb.resent.len());
        b = nb;
    }
    let r = run_until_ended(&a, &mut b, "loop", Duration::from_secs(40));
    stop.store(true, Ordering::SeqCst);
    eprintln!("3 resumes, up to {most_resent} shares resent, stopped {}: {}", r["stopped"]["reason"], r["meter"]);
    assert_eq!(r["stopped"]["reason"], "unpaid", "{r}");
    assert_eq!(r["paid"], 4, "{r}");
    assert!(most_resent >= 1);
    bargain_kept(&r, &terms, sw);
    a.h.shutdown();
    drop(miner);
}

/// Resume past the limit, as a renter whose paid work can't be used up in the time: the limit comes first, and the
/// rental ends on it with the bargain kept.
#[test]
fn a_resume_loop_past_the_limit_ends_on_it_with_the_bargain_kept() {
    let _s = serial();
    let sw = share_work(DIFF);
    // ten slices of 2000 shares each: far more than the miner sends here
    let terms = Terms { slice_work: 2000 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
    let a = app(&terms);
    let bk = noise::fresh_key();
    let (b, _) = connect(&a.link, bk, a.hpub, "limit", hello("limit", &terms));
    for i in 1..=10 {
        b.pay(i);
    }
    rental_where(&a.h, "paid", |r| r["paid"] == 10);
    let stop: Arc<AtomicBool> = Arc::default();
    let (ma, st2) = (a.miners.clone(), stop.clone());
    let miner = thread::spawn(move || {
        let _ = standin::miner(standin::MinerConfig { pool: ma, user: "m0".into(), max_rate: 40.0, bad_every: 0, duration: Some(Duration::from_secs(60)), reconnect: true, extranonce_subscribe: false, bind: None });
        st2.store(true, Ordering::SeqCst);
    });
    let mut welcomed = 0;
    let mut keep = Vec::new();
    for _ in 0..30 {
        let (nb, w) = connect(&a.link, bk, a.hpub, "limit", Msg::Resume { rental: "limit".into() });
        if !matches!(w, Msg::Welcome { .. }) {
            break;
        }
        welcomed += 1;
        keep.push(nb);
        thread::sleep(Duration::from_millis(150));
    }
    let r = finished(&a.h, "limit", Duration::from_secs(5));
    stop.store(true, Ordering::SeqCst);
    assert_eq!(r["stopped"]["reason"], "too many resumes", "{r}");
    assert_eq!(r["paid"], 10, "{r}");
    assert_eq!(welcomed, 8 + 10, "8, and one for each slice paid");
    bargain_kept(&r, &terms, sw);
    a.h.shutdown();
    drop(miner);
}

/// A renter that pays exactly one slice, drops and resumes, and pays no more: it gets that slice's work and no
/// more, on whichever link, and the rental ends with nothing served unpaid.
#[test]
fn a_renter_resuming_after_one_paid_slice_gets_that_slice_and_no_more() {
    let _s = serial();
    let sw = share_work(DIFF);
    let terms = Terms { slice_work: 6 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
    let a = app(&terms);
    let bk = noise::fresh_key();
    let (mut b, _) = connect(&a.link, bk, a.hpub, "one", hello("one", &terms));
    b.pay(1);
    let stop: Arc<AtomicBool> = Arc::default();
    let (ma, st2) = (a.miners.clone(), stop.clone());
    let miner = thread::spawn(move || {
        let _ = standin::miner(standin::MinerConfig { pool: ma, user: "m0".into(), max_rate: 10.0, bad_every: 0, duration: Some(Duration::from_secs(30)), reconnect: true, extranonce_subscribe: false, bind: None });
        st2.store(true, Ordering::SeqCst);
    });
    // a few of the paid shares, then the link drops and the renter comes back
    b.pump(3, Duration::from_secs(15));
    let before = b.shares;
    b.tx.shutdown();
    rental_where(&a.h, "suspended", |r| r["suspended"] == true);
    let (mut nb, w) = connect(&a.link, bk, a.hpub, "one", Msg::Resume { rental: "one".into() });
    assert!(matches!(w, Msg::Welcome { .. }), "{w:?}");
    let r = run_until_ended(&a, &mut nb, "one", Duration::from_secs(25));
    stop.store(true, Ordering::SeqCst);
    eprintln!("one slice: {before} shares before the drop, {} after, {} sent again; stopped {}: {}", nb.shares, nb.resent.len(), r["stopped"]["reason"], r["meter"]);
    assert_eq!(r["paid"], 1, "{r}");
    assert_eq!(r["stopped"]["reason"], "unpaid", "{r}");
    assert_eq!(r["stopped"]["unpaidWork"], "0", "nothing served unpaid: {r}");
    assert_eq!(r["meter"]["work"], (6 * sw).to_string(), "the one slice's work, across both links: {r}");
    assert_eq!(before + nb.shares, 6, "every share the renter got, on either link, was paid for");
    a.h.shutdown();
    drop(miner);
}

/// Each `resume` moves a rental's miners to the fallback and back: past a few, it ends.
#[test]
fn resumes_with_nothing_to_show_end_the_rental() {
    let _s = serial();
    let terms = Terms { slice_work: 60 * share_work(DIFF), price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
    let a = app(&terms);
    let bk = noise::fresh_key();
    let (b, _) = connect(&a.link, bk, a.hpub, "r", hello("r", &terms));
    b.pay(1);
    rental_where(&a.h, "paid", |r| r["paid"] == 1);
    let mut said = Vec::new();
    for _ in 0..12 {
        let (_again, w) = connect(&a.link, bk, a.hpub, "r", Msg::Resume { rental: "r".into() });
        let welcome = matches!(w, Msg::Welcome { .. });
        said.push(welcome);
        if !welcome {
            break;
        }
    }
    // the scenario paid one slice: 8, and one for it. The ninth-plus-one is refused before any welcome
    let paid = app_answers(&a.h)["finished"][0]["paid"].as_u64().unwrap_or(0) as usize;
    assert_eq!(paid, 1, "the scenario pays exactly one slice");
    assert_eq!(said.iter().filter(|w| **w).count(), 8 + paid, "{said:?}, {paid} paid");
    let r = finished(&a.h, "r", Duration::from_secs(3));
    assert_eq!(r["stopped"]["reason"], "too many resumes", "{r}");
    a.h.shutdown();
}

/// A fallback pool, its report read back.
fn fallback_pool() -> (String, std::path::PathBuf) {
    start_pool(Duration::from_millis(700))
}

/// A renter that says `paying` and never pays: the hashmaker waits 10 s at the most, its miner on its own pool meanwhile,
/// then stops with nothing served unpaid.
#[test]
fn a_renter_saying_paying_and_never_paying_ends_within_the_wait_with_the_miners_on_the_fallback() {
    let _s = serial();
    let sw = share_work(DIFF);
    let terms = Terms { slice_work: 2 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
    let (fb, fb_report) = fallback_pool();
    let a = app_full(&terms, hashmaker::MIN_SLICE_TIME, Some(fb));
    let (mut b, _) = connect(&a.link, noise::fresh_key(), a.hpub, "say", hello("say", &terms));
    b.verdicts = Verdicts::AcceptAll;
    b.pay(1);
    let stop: Arc<AtomicBool> = Arc::default();
    let (ma, st2) = (a.miners.clone(), stop.clone());
    let miner = thread::spawn(move || {
        let _ = standin::miner(standin::MinerConfig { pool: ma, user: "m0".into(), max_rate: 10.0, bad_every: 0, duration: Some(Duration::from_secs(40)), reconnect: true, extranonce_subscribe: false, bind: None });
        st2.store(true, Ordering::SeqCst);
    });
    let t0 = Instant::now();
    while b.dues == 0 && t0.elapsed() < Duration::from_secs(20) {
        b.pump(u64::MAX, Duration::from_millis(50));
    }
    assert!(b.dues > 0, "a share waited for payment");
    let before = pool_report(&fb_report)["accepted"].as_u64().unwrap_or(0);
    b.tx.send(&Msg::Paying).unwrap();
    let said = Instant::now();
    rental_where(&a.h, "waiting", |r| r["waitingForPayment"] == true);
    let r = run_until_ended(&a, &mut b, "say", Duration::from_secs(20));
    let took = said.elapsed();
    let after = pool_report(&fb_report)["accepted"].as_u64().unwrap_or(0);
    stop.store(true, Ordering::SeqCst);
    eprintln!("measure: said paying, never paid: stopped {} {} ms on; the fallback took {} shares meanwhile", r["stopped"]["reason"], took.as_millis(), after - before);
    assert_eq!(r["stopped"]["reason"], "unpaid", "{r}");
    assert!(took <= hashmaker_wait() + Duration::from_millis(1500), "{} ms", took.as_millis());
    assert_eq!(r["stopped"]["unpaidWork"], "0", "{r}");
    assert!(after > before, "the miner hashed for the hashmaker's own pool during the wait");
    a.h.shutdown();
    drop(miner);
}

fn hashmaker_wait() -> Duration {
    xbt_hashlink::order::WAIT_FOR_PAYING
}

/// A renter that says `paying` and pays each time, past the limit of waits an hour: the rental ends on it.
#[test]
fn a_renter_saying_paying_past_the_limit_ends() {
    let _s = serial();
    let sw = share_work(DIFF);
    let terms = Terms { slice_work: 2 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
    let (fb, _) = fallback_pool();
    let a = app_full(&terms, hashmaker::MIN_SLICE_TIME, Some(fb));
    let (mut b, _) = connect(&a.link, noise::fresh_key(), a.hpub, "lim", hello("lim", &terms));
    b.verdicts = Verdicts::AcceptAll;
    b.pay(1);
    let stop: Arc<AtomicBool> = Arc::default();
    let (ma, st2) = (a.miners.clone(), stop.clone());
    let miner = thread::spawn(move || {
        let _ = standin::miner(standin::MinerConfig { pool: ma, user: "m0".into(), max_rate: 10.0, bad_every: 0, duration: Some(Duration::from_secs(120)), reconnect: true, extranonce_subscribe: false, bind: None });
        st2.store(true, Ordering::SeqCst);
    });
    let (mut paid, mut said) = (1u64, 0usize);
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(110) && a.h.finished().is_empty() && !b.ended {
        let dues = b.dues;
        b.pump(u64::MAX, Duration::from_millis(50));
        if b.dues > dues && rental_where(&a.h, "on", |_| true)["waitingForPayment"] == false {
            b.tx.send(&Msg::Paying).unwrap();
            said += 1;
            thread::sleep(Duration::from_millis(300));
            paid += 1;
            b.pay(paid);
        }
    }
    let r = finished(&a.h, "lim", Duration::from_secs(5));
    stop.store(true, Ordering::SeqCst);
    eprintln!("said paying {said} times, paid {paid}: stopped {}", r["stopped"]["reason"]);
    assert_eq!(r["stopped"]["reason"], "too many waits for payment", "{r}");
    assert_eq!(r["paymentWaits"].as_u64().unwrap_or(0) as usize, xbt_hashlink::order::PAYING_WAITS_AN_HOUR, "{r}");
    assert_eq!(r["stopped"]["unpaidWork"], "0", "{r}");
    a.h.shutdown();
    drop(miner);
}

/// A wallet whose ticket buys take `buy` each: it keeps the credit a ticket left, and pays each slice through the
/// hashmaker's paid-slice endpoint as the gateway would pass it on.
struct SlowPayer {
    slices: String,
    price_msat: u64,
    ticket_msat: u64,
    credit_msat: u64,
    buy: Duration,
}

impl Payer for SlowPayer {
    fn caps_for(&mut self, ticket_msat: u64) {
        self.ticket_msat = ticket_msat;
    }

    fn pay(&mut self, rental: &str, slice: u64, receipt: &Value) -> Result<Value, String> {
        let mut bought = 0;
        if self.credit_msat < self.price_msat {
            thread::sleep(self.buy);
            bought = self.ticket_msat.max(self.price_msat);
            self.credit_msat += bought;
        }
        let body = receipt.to_string();
        let mut c = TcpStream::connect(&self.slices).map_err(|e| e.to_string())?;
        write!(c, "POST /hashrate/{rental}/{slice} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}", body.len()).map_err(|e| e.to_string())?;
        let mut out = String::new();
        let _ = std::io::Read::read_to_string(&mut c, &mut out);
        if !out.starts_with("HTTP/1.1 200") {
            return Err(format!("slice {slice}: {}", out.lines().last().unwrap_or("")));
        }
        self.credit_msat -= self.price_msat;
        Ok(json!({"verdict": "allow", "charged_sats": bought.div_ceil(1000)}))
    }

    fn stop(&mut self) -> Option<Value> {
        None
    }
}

/// An honest renter whose every ticket buy takes 8 s, on a large miner: at first its step lasts less than a buy, so it
/// says `paying` and the hashmaker waits with the miner on its own pool; as delivered work grows, its step outlasts the
/// buys. Over three minutes on the real link it keeps running, with nothing served unpaid, never more paid ahead than
/// the step, and no more waits than the hour allows.
#[test]
fn an_honest_renter_with_slow_ticket_buys_keeps_a_large_miner_running() {
    let _s = serial();
    let sw = share_work(DIFF);
    // 20 sat a slice of 2 shares, the miner at 20 shares a second: 200 sat a second, the 546 sat step 2.7 s
    let terms = Terms { slice_work: 2 * sw, price_msat: 20_000, grace_ms: 10_000, start_slices: 0 };
    let (fb, fb_report) = fallback_pool();
    let [link, miners, slices] = ports::<3>();
    let hk = noise::fresh_key();
    let h = Hashmaker::start(
        hashmaker::Config { miners: miners.clone(), link: link.clone(), key: hk, terms: terms.clone(), report: None, slices: Some(slices.clone()), fallback: Some(fb),
                            rentable: None, min_slice_time: hashmaker::MIN_SLICE_TIME },
        Box::new(|| Box::<LabSeller>::default()),
    )
    .unwrap();
    wait_for(&link);
    let hpub = PublicKey::from_secret_key(secp256k1::SECP256K1, &hk);
    let (pool, _) = start_pool(Duration::from_secs(5));
    let stop: Arc<AtomicBool> = Arc::default();
    let (ma, st2) = (miners.clone(), stop.clone());
    let miner = thread::spawn(move || {
        let _ = standin::miner(standin::MinerConfig { pool: ma, user: "m0".into(), max_rate: 20.0, bad_every: 0, duration: Some(Duration::from_secs(200)), reconnect: true, extranonce_subscribe: false, bind: None });
        st2.store(true, Ordering::SeqCst);
    });
    let live: Arc<Mutex<Value>> = Arc::default();
    let mut cfg = taker_config(&link, hpub, &terms, &pool, "slow", 60);
    cfg.duration = Some(Duration::from_secs(180));
    cfg.live = Some(live.clone());
    cfg.payer = Some(Box::new(SlowPayer { slices, price_msat: terms.price_msat, ticket_msat: 0, credit_msat: 0, buy: Duration::from_secs(8) }));
    let taker = thread::spawn(move || hashtaker::run(cfg, Box::<LabHashtaker>::default()).unwrap());
    // what's paid ahead, sampled, against the step at that moment
    let mut worst = 0i64;
    while !taker.is_finished() {
        thread::sleep(Duration::from_millis(500));
        let v = live.lock().unwrap().clone();
        let (paid, work) = (v["paidSlices"].as_u64().unwrap_or(0) as i64, v["meter"]["work"].as_str().and_then(|w| w.parse::<i64>().ok()).unwrap_or(0));
        let ahead = paid * terms.price_msat as i64 - work * terms.price_msat as i64 / terms.slice_work as i64;
        let step = (work * terms.price_msat as i64 / terms.slice_work as i64).clamp(546_000, 30 * 200_000);
        worst = worst.max(ahead - step);
    }
    let r = taker.join().unwrap();
    stop.store(true, Ordering::SeqCst);
    let hz = h.wait_finished(1, Duration::from_secs(20)).into_iter().next().expect("the hashmaker's report");
    let fb_took = pool_report(&fb_report)["accepted"].as_u64().unwrap_or(0);
    eprintln!("measure: 8 s ticket buys, large miner: closed {}, {} paid, {} waits, fallback took {fb_took} shares, most past the step {worst} msat, dues {}: {}",
              r["closed"], r["paidSlices"], hz["paymentWaits"], r["dues"], hz["stopped"]);
    assert_eq!(r["closed"], "rental time over", "{r}");
    assert_eq!(hz["stopped"]["unpaidWork"], "0", "{hz}");
    assert!(hz["paymentWaits"].as_u64().unwrap() as usize <= xbt_hashlink::order::PAYING_WAITS_AN_HOUR, "{hz}");
    assert!(worst <= 0, "never more paid ahead than the step: {worst} msat over");
    assert!(r["paidSlices"].as_u64().unwrap() > 100, "it kept running: {r}");
    if hz["paymentWaits"].as_u64().unwrap() > 0 {
        assert!(fb_took > 0, "the miner hashed for the hashmaker's own pool during the waits");
    }
    h.shutdown();
    drop(miner);
}

/// A share nobody hashed goes no further, and the miner hears so from the app: the renter is not asked.
#[test]
fn a_share_nobody_hashed_is_not_sent_on_and_the_miner_gets_a_rejection() {
    let _s = serial();
    let sw = share_work(DIFF);
    let terms = Terms { slice_work: 1000 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
    let a = app(&terms);
    let (mut b, _) = connect(&a.link, noise::fresh_key(), a.hpub, "r", hello("r", &terms));
    b.pay(1);
    let m = scripted_miner(&a.miners, 6, Duration::from_millis(10), Sends::Junk);
    let t0 = Instant::now();
    while m.answers.lock().unwrap().len() < 6 && t0.elapsed() < Duration::from_secs(10) {
        b.pump(u64::MAX, Duration::from_millis(50));
    }
    let answers = m.answers.lock().unwrap().clone();
    assert_eq!(answers.len(), 6, "{answers:?}");
    assert!(answers.iter().all(|v| v["result"] == false && v["error"][0] == 23), "{answers:?}");
    assert_eq!(b.shares, 0, "none reached the renter");
    let r = rental_where(&a.h, "refused", |r| r["meter"]["refused"] == 6);
    assert_eq!((r["meter"]["work"].as_str(), r["meter"]["proven"].as_u64()), (Some("0"), Some(0)), "{r}");
    let _ = m.s.shutdown(std::net::Shutdown::Both);
    a.h.shutdown();
}

/// A share repeated is counted once, and the repeats go no further.
#[test]
fn a_repeated_share_counts_once() {
    let _s = serial();
    let sw = share_work(DIFF);
    let terms = Terms { slice_work: 1000 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
    let a = app(&terms);
    let (mut b, _) = connect(&a.link, noise::fresh_key(), a.hpub, "r", hello("r", &terms));
    b.pay(1);
    let m = scripted_miner(&a.miners, 5, Duration::from_millis(10), Sends::Repeat);
    let t0 = Instant::now();
    while m.answers.lock().unwrap().iter().filter(|v| v["result"] == false).count() < 4 && t0.elapsed() < Duration::from_secs(10) {
        b.pump(u64::MAX, Duration::from_millis(50));
    }
    let r = rental_where(&a.h, "counted", |r| r["meter"]["repeats"] == 4);
    assert_eq!(r["meter"]["work"], sw.to_string(), "{r}");
    assert_eq!(b.shares, 1);
    a.h.shutdown();
}

/// A miner set a target harder than the difficulty it was told is paid less than its work. Its shares bunch
/// low under their target, and the rental ends on it.
#[test]
fn shares_harder_than_the_difficulty_end_the_rental() {
    let _s = serial();
    let sw = share_work(DIFF);
    let terms = Terms { slice_work: 1000 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
    let a = app(&terms);
    let (mut b, _) = connect(&a.link, noise::fresh_key(), a.hpub, "hard", hello("hard", &terms));
    b.verdicts = Verdicts::AcceptAll;
    b.pay(1);
    let _m = scripted_miner(&a.miners, 80, Duration::ZERO, Sends::Real(3.0));
    let r = run_until_ended(&a, &mut b, "hard", Duration::from_secs(60));
    assert_eq!(r["stopped"]["reason"], "shares harder than the difficulty said", "{r}");
    assert!(r["meter"]["proven"].as_u64().unwrap() <= 64, "{}", r["meter"]);
    a.h.shutdown();
}

/// A slice paid and no jobs to work on, or jobs too fast to finish any: proven work never reaches what's paid,
/// so the miners' time is what runs out.
#[test]
fn a_slice_paid_with_no_jobs_or_jobs_too_fast_to_work_ends_on_its_paid_time() {
    let _s = serial();
    let sw = share_work(DIFF);
    for (case, jobs_a_second) in [("no jobs", 0u64), ("19 clean jobs a second", 19)] {
        let terms = Terms { slice_work: 1000 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
        // a second a slice, four times over
        let a = app_with(&terms, Duration::from_secs(1));
        let (mut b, _) = connect(&a.link, noise::fresh_key(), a.hpub, "r", hello("r", &terms));
        b.pay(1);
        let _m = scripted_miner(&a.miners, 0, Duration::ZERO, Sends::Real(1.0));
        let t0 = Instant::now();
        let (mut k, mut chan) = (10u64, None);
        while t0.elapsed() < Duration::from_secs(12) && a.h.finished().is_empty() && !b.ended {
            b.pump(u64::MAX, Duration::from_millis(50));
            chan = chan.or(b.chan);
            if let (Some(c), true) = (chan, jobs_a_second > 0) {
                k += 1;
                b.down(c, job_line(k, true));
            }
        }
        let r = finished(&a.h, "r", Duration::from_secs(3));
        eprintln!("{case}: stopped {} after {} ms, served {} ms", r["stopped"]["reason"], t0.elapsed().as_millis(), r["servedMs"]);
        assert_eq!(r["stopped"]["reason"], "paid time used up", "{case}: {r}");
        assert!(t0.elapsed() < Duration::from_secs(7), "{case}: {} ms", t0.elapsed().as_millis());
        a.h.shutdown();
    }
}

/// Faster than any rental needs, for long enough: jobs.
#[test]
fn clean_jobs_flooded_end_the_rental() {
    let _s = serial();
    let sw = share_work(DIFF);
    let terms = Terms { slice_work: 1000 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
    let a = app(&terms);
    let (mut b, _) = connect(&a.link, noise::fresh_key(), a.hpub, "r", hello("r", &terms));
    b.pay(1);
    let _m = scripted_miner(&a.miners, 0, Duration::ZERO, Sends::Real(1.0));
    let t0 = Instant::now();
    let mut k = 10u64;
    while t0.elapsed() < Duration::from_secs(20) && a.h.finished().is_empty() && !b.ended {
        b.pump(u64::MAX, Duration::from_millis(5));
        if let Some(c) = b.chan {
            for _ in 0..2 {
                k += 1;
                b.down(c, job_line(k, true));
            }
        }
    }
    let r = finished(&a.h, "r", Duration::from_secs(3));
    assert_eq!(r["stopped"]["reason"], "too many jobs", "{r}");
    a.h.shutdown();
}

/// Faster than any rental needs, for long enough: shares, at a difficulty low enough to flood the app.
#[test]
fn shares_flooded_at_a_tiny_difficulty_end_the_rental() {
    let _s = serial();
    let d = 1.0 / (1u64 << 31) as f64;
    let terms = Terms { slice_work: 1 << 40, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
    let a = app(&terms);
    let (mut b, _) = connect(&a.link, noise::fresh_key(), a.hpub, "r", hello("r", &terms));
    b.pay(1);
    b.diff = d;
    let _m = scripted_miner(&a.miners, 500_000, Duration::ZERO, Sends::Real(1.0));
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(40) && a.h.finished().is_empty() && !b.ended {
        b.pump(u64::MAX, Duration::from_millis(20));
    }
    let r = finished(&a.h, "r", Duration::from_secs(3));
    eprintln!("stopped {} after {} ms: {}", r["stopped"]["reason"], t0.elapsed().as_millis(), r["meter"]);
    assert_eq!(r["stopped"]["reason"], "too many shares", "{r}");
    a.h.shutdown();
}

/// Lines a rental can't be checked through end it, on the first one: no miner hashes on a job nobody can prove.
#[test]
fn a_line_that_cannot_be_checked_ends_the_rental_before_a_miner_hashes_on_it() {
    let _s = serial();
    let sw = share_work(DIFF);
    let mut bad_prev = job_line(5, true);
    bad_prev["params"][1] = json!("ff".repeat(32));
    let mut branches = job_line(6, true);
    branches["params"][4] = json!(["00"]);
    let mut short = job_line(7, true);
    short["params"][2] = json!("00");
    let extranonce = json!({"id": null, "method": "mining.set_extranonce", "params": ["00000002", 8]});
    let no_difficulty = json!({"id": null, "method": "mining.set_difficulty", "params": [0.0]});
    for (line, why) in [
        (bad_prev, "a job this app can't check"),
        (branches, "a job this app can't check"),
        (short, "a job this app can't check"),
        (no_difficulty, "a job this app can't check"),
        (extranonce, "the hashtaker changed the extranonce"),
    ] {
        let terms = Terms { slice_work: 1000 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
        let a = app(&terms);
        let (mut b, _) = connect(&a.link, noise::fresh_key(), a.hpub, "r", hello("r", &terms));
        b.pay(1);
        let m = scripted_miner(&a.miners, 0, Duration::ZERO, Sends::Real(1.0));
        b.until_serving();
        let jobs_before = m.jobs.load(Ordering::SeqCst);
        b.down(b.chan.unwrap(), line.clone());
        let r = run_until_ended(&a, &mut b, "r", Duration::from_secs(5));
        assert_eq!(r["stopped"]["reason"], why, "{line}: {r}");
        assert_eq!(m.jobs.load(Ordering::SeqCst), jobs_before, "{line}: it never reached the miner");
        a.h.shutdown();
    }
}

/// At 2^47 hashes a slice, 131,072 (four slices a share) is taken and anything over it ends the rental at once.
#[test]
fn the_difficulty_limit_is_four_slices_a_share() {
    let _s = serial();
    let terms = Terms { slice_work: 1 << 47, price_msat: 40_000, grace_ms: 45_000, start_slices: 0 };
    let a = app(&terms);
    let (b, _) = connect(&a.link, noise::fresh_key(), a.hpub, "edge", hello("edge", &terms));
    b.pay(1);
    b.down(1, json!({"id": null, "method": "mining.set_difficulty", "params": [131072.0]}));
    thread::sleep(Duration::from_millis(500));
    assert!(a.h.finished().is_empty(), "131,072 is taken");
    b.down(1, json!({"id": null, "method": "mining.set_difficulty", "params": [131073.0]}));
    let r = finished(&a.h, "edge", Duration::from_secs(3));
    assert_eq!(r["stopped"]["reason"], "a difficulty too high for the slice", "{r}");
    a.h.shutdown();
}

/// One difficulty past anything honest ends that rental, and the app and another rental's miner go on.
#[test]
fn a_huge_difficulty_ends_that_rental_and_the_app_and_other_rentals_go_on() {
    let _s = serial();
    let sw = share_work(DIFF);
    let terms = Terms { slice_work: 4 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
    let a = app(&terms);
    let (mut b, _) = connect(&a.link, noise::fresh_key(), a.hpub, "bad", hello("bad", &terms));
    b.pay(1);
    let _m = scripted_miner(&a.miners, 1, Duration::ZERO, Sends::Real(1.0));
    b.pump(1, Duration::from_secs(15));
    let chan = b.chan.unwrap();
    // an honest rental beside it, on a miner of its own
    let [pool_a] = ports::<1>();
    let pa = pool_a.clone();
    thread::spawn(move || standin::pool(standin::PoolConfig { listen: pa, diff: DIFF, job_every: Duration::from_millis(700), report: None }));
    wait_for(&pool_a);
    let ma = a.miners.clone();
    let _honest_miner = thread::spawn(move || {
        standin::miner(standin::MinerConfig { pool: ma, user: "other".into(), max_rate: 8.0, bad_every: 0, duration: Some(Duration::from_secs(30)), reconnect: true, extranonce_subscribe: false, bind: None })
    });
    thread::sleep(Duration::from_millis(500));
    let cfg = taker_config(&a.link, a.hpub, &terms, &pool_a, "honest", 20);
    let honest = thread::spawn(move || hashtaker::run(cfg, Box::<LabHashtaker>::default()).unwrap());
    let paid = |h: &Hashmaker| app_answers(h)["rentals"].as_array().unwrap().iter().find(|r| r["rental"] == "honest").map_or(0, |r| r["paid"].as_u64().unwrap());
    let t0 = Instant::now();
    while paid(&a.h) < 2 {
        assert!(t0.elapsed() < Duration::from_secs(20), "the honest rental did not start: {}", app_answers(&a.h));
        thread::sleep(Duration::from_millis(50));
    }
    b.down(chan, json!({"id": null, "method": "mining.set_difficulty", "params": [1e20]}));
    let r = finished(&a.h, "bad", Duration::from_secs(5));
    assert_eq!(r["stopped"]["reason"], "a difficulty too high for the slice", "{r}");
    app_answers(&a.h);
    let then = paid(&a.h);
    let t0 = Instant::now();
    while paid(&a.h) < then + 2 {
        assert!(t0.elapsed() < Duration::from_secs(10), "the honest rental stopped: {}", app_answers(&a.h));
        thread::sleep(Duration::from_millis(50));
    }
    a.h.stop_rental("honest");
    let _ = honest.join();
    a.h.shutdown();
}

/// Not the rental's key: refused at a `resume`, nothing changes.
#[test]
fn a_resume_with_someone_elses_key_is_refused() {
    let _s = serial();
    let terms = Terms { slice_work: 4 * share_work(DIFF), price_msat: 5_000, grace_ms: 30_000, start_slices: 0 };
    let a = app(&terms);
    let (b, _) = connect(&a.link, noise::fresh_key(), a.hpub, "r", hello("r", &terms));
    b.pay(1);
    rental_where(&a.h, "paid", |r| r["paid"] == 1);
    let (_x, w) = connect(&a.link, noise::fresh_key(), a.hpub, "r", Msg::Resume { rental: "r".into() });
    assert!(matches!(w, Msg::Close { .. }), "{w:?}");
    assert_eq!(app_answers(&a.h)["rentals"][0]["suspended"], false);
    a.h.shutdown();
}

/// A hashtaker gone silent (its link stalled, or it no longer answers): the limit for a quiet link.
#[test]
fn a_rental_with_a_silent_hashtaker_ends_on_the_limit_for_a_quiet_link() {
    let _s = serial();
    let terms = Terms { slice_work: 4 * share_work(DIFF), price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
    let a = app(&terms);
    let (b, w) = connect(&a.link, noise::fresh_key(), a.hpub, "quiet", hello("quiet", &terms));
    assert!(matches!(w, Msg::Welcome { .. }), "{w:?}");
    b.pay(1);
    rental_where(&a.h, "paid", |r| r["ready"] == true);
    let t0 = Instant::now();
    let r = finished(&a.h, "quiet", hashmaker::QUIET_LIMIT + Duration::from_secs(10));
    let took = t0.elapsed();
    assert_eq!(r["stopped"]["reason"], "link quiet", "{r}");
    assert!(took >= hashmaker::QUIET_LIMIT - Duration::from_secs(2), "{} s", took.as_secs());
    a.h.shutdown();
}

/// A hashtaker that doesn't prove shares would pay by verdicts, so it's refused: the hello comes back closed.
#[test]
fn a_hello_with_no_proof_is_refused_and_no_money_moves() {
    let _s = serial();
    let terms = Terms { slice_work: 4 * share_work(DIFF), price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
    let a = app(&terms);
    let old = Msg::Hello { rental: "old".into(), listing: "lab".into(), terms: terms.clone(), miners: 1, proof: None };
    let (_b, w) = connect(&a.link, noise::fresh_key(), a.hpub, "old", old);
    let Msg::Close { reason, .. } = w else { panic!("{w:?}") };
    assert!(reason.contains(PROOF), "{reason}");
    assert!(app_answers(&a.h)["rentals"].as_array().unwrap().is_empty());
    a.h.shutdown();
}

// --- a hashmaker that cheats -------------------------------------------------------------------------

fn taker_config(link: &str, hpub: PublicKey, terms: &Terms, upstream: &str, rental: &str, idle_s: u64) -> hashtaker::Config {
    hashtaker::Config {
        hashmaker: link.into(),
        hashmaker_key: hpub,
        key: noise::fresh_key(),
        upstream: upstream.into(),
        user: "honest".into(),
        terms: terms.clone(),
        rental: rental.into(),
        listing: "lab".into(),
        stop_paying_after: None,
        idle: Duration::from_secs(idle_s),
        duration: Some(Duration::from_secs(45)),
        report: None,
        payer: None,
        miners: 1,
        budget_msat: None,
        cut: None,
        live: None,
        gateway_api: None,
        allow_unblinded: true,
    }
}

/// The scripted hashmaker's end of a link, once a real hashtaker has said hello to it.
struct Maker {
    tx: link::Sender,
    rx: mpsc::Receiver<Msg>,
    pays: Vec<u64>,
    session: Option<(String, usize)>,
    diff: f64,
    job: Option<Value>,
    verdicts: VecDeque<Value>,
}

fn scripted_maker(proof: Option<&str>) -> (String, PublicKey, mpsc::Receiver<Maker>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let hk = noise::fresh_key();
    let proof = proof.map(str::to_string);
    let (s, r) = mpsc::channel();
    thread::spawn(move || {
        let lk = link::answer(l.accept().unwrap().0, hk).unwrap();
        let (tx, mut rx) = (lk.tx, lk.rx);
        let Ok(Some(Msg::Hello { rental, terms, .. })) = rx.recv() else { panic!("no hello") };
        tx.send(&Msg::Welcome { rental, terms_hash: hex::encode(terms.hash()), proof }).unwrap();
        // a reader of its own: a bounded read that runs out breaks the link
        let (from, lines) = mpsc::channel();
        thread::spawn(move || loop {
            match rx.recv() {
                Ok(Some(m)) => {
                    if from.send(m).is_err() {
                        return;
                    }
                }
                Ok(None) => {}
                Err(_) => return,
            }
        });
        let rx = lines;
        let _ = s.send(Maker { tx, rx, pays: Vec::new(), session: None, diff: 1.0, job: None, verdicts: VecDeque::new() });
    });
    (addr, PublicKey::from_secret_key(secp256k1::SECP256K1, &hk), r)
}

impl Maker {
    /// Read what the hashtaker sends for up to `wait`, or until `done` says so.
    fn read(&mut self, wait: Duration, mut done: impl FnMut(&Maker) -> bool) -> bool {
        let t0 = Instant::now();
        while t0.elapsed() < wait {
            if done(self) {
                return true;
            }
            match self.rx.recv_timeout(Duration::from_millis(50)) {
                Ok(Msg::Pay { slice, .. }) => self.pays.push(slice),
                Ok(Msg::Ping { n }) => {
                    let _ = self.tx.send(&Msg::Pong { n });
                }
                Ok(Msg::Down { line, .. }) => {
                    let v: Value = serde_json::from_str(&line).unwrap();
                    match v["method"].as_str() {
                        Some("mining.set_difficulty") => self.diff = v["params"][0].as_f64().unwrap(),
                        Some("mining.notify") => self.job = Some(v),
                        _ if v["id"] == 1 => self.session = Some((v["result"][1].as_str().unwrap().to_string(), v["result"][2].as_u64().unwrap() as usize)),
                        _ if v["id"].as_u64().is_some_and(|i| i >= 100) => self.verdicts.push_back(v),
                        _ => {}
                    }
                }
                Ok(Msg::Close { .. }) | Err(mpsc::RecvTimeoutError::Disconnected) => return false,
                _ => {}
            }
        }
        false
    }

    /// Open a channel, as a miner on it would: the session's first lines and its first job.
    fn open(&mut self, chan: u32) {
        assert!(self.read(Duration::from_secs(5), |m| !m.pays.is_empty()), "the first slice was not paid");
        self.tx.send(&Msg::Open { chan, worker: "m0".into() }).unwrap();
        self.tx.send(&Msg::Up { chan, line: json!({"id": 1, "method": "mining.subscribe", "params": []}).to_string() }).unwrap();
        self.tx.send(&Msg::Up { chan, line: json!({"id": 2, "method": "mining.authorize", "params": ["m0", "x"]}).to_string() }).unwrap();
        assert!(self.read(Duration::from_secs(10), |m| m.job.is_some() && m.session.is_some()), "no job");
    }

    /// A real share of the channel's job, at its difficulty.
    fn share(&self, id: u64) -> String {
        let job = self.job.as_ref().unwrap();
        let (en1, size) = self.session.as_ref().unwrap();
        let (e2, n) = standin::find_share(job, en1, *size, self.diff, id).unwrap();
        json!({"id": id, "method": "mining.submit", "params": ["m0", job["params"][0], e2, job["params"][7], n]}).to_string()
    }
}

fn start_pool(job_every: Duration) -> (String, std::path::PathBuf) {
    let [addr] = ports::<1>();
    let dir = std::env::temp_dir().join(format!("hostile-pool-{}-{}", std::process::id(), addr.replace([':', '.'], "-")));
    let report = dir.with_extension("json");
    let (a, rp) = (addr.clone(), report.clone());
    thread::spawn(move || standin::pool(standin::PoolConfig { listen: a, diff: DIFF, job_every, report: Some(rp) }));
    wait_for(&addr);
    (addr, report)
}

fn pool_report(p: &std::path::Path) -> Value {
    thread::sleep(Duration::from_millis(700));
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

/// Shares nobody hashed: nothing is counted, nothing reaches the gateway, nothing more is paid, and the
/// rental ends. The miner's rejection comes from the hashtaker's end.
#[test]
fn a_hashmaker_inventing_shares_gets_nothing_for_them() {
    let _s = serial();
    let sw = share_work(DIFF);
    let terms = Terms { slice_work: 4 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
    let (pool, report) = start_pool(Duration::from_secs(30));
    let (addr, hpub, got) = scripted_maker(Some(PROOF));
    let cfg = taker_config(&addr, hpub, &terms, &pool, "r", 30);
    let taker = thread::spawn(move || hashtaker::run(cfg, Box::<LabHashtaker>::default()).unwrap());
    let mut m = got.recv_timeout(Duration::from_secs(5)).unwrap();
    m.open(7);
    let job = m.job.clone().unwrap();
    for i in 0..40u64 {
        // the wrong nonce, and a real share of another session's extranonce
        let line = if i % 2 == 0 {
            json!({"id": 100 + i, "method": "mining.submit", "params": ["m0", job["params"][0], format!("{i:016x}"), job["params"][7], "ffffffff"]})
        } else {
            let (e2, n) = standin::find_share(&job, "99999999", 8, m.diff, i).unwrap();
            json!({"id": 100 + i, "method": "mining.submit", "params": ["m0", job["params"][0], e2, job["params"][7], n]})
        };
        if m.tx.send(&Msg::Up { chan: 7, line: line.to_string() }).is_err() {
            break;
        }
    }
    m.read(Duration::from_secs(5), |_| false);
    let r = taker.join().unwrap();
    eprintln!("closed {}: {}", r["closed"], r["meter"]);
    assert_eq!(r["closed"], "shares that don't prove", "{r}");
    assert_eq!(r["meter"]["work"], "0", "{r}");
    assert_eq!(r["released"], 1, "only the first slice was ever paid: {r}");
    assert_eq!(m.pays, vec![1]);
    assert!(m.verdicts.iter().all(|v| v["result"] == false), "{:?}", m.verdicts);
    assert_eq!(pool_report(&report)["accepted"], 0);
}

/// One real share sent over and over counts once, reaches the gateway once.
#[test]
fn a_hashmaker_repeating_a_real_share_is_paid_for_it_once() {
    let _s = serial();
    let sw = share_work(DIFF);
    let terms = Terms { slice_work: 4 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
    let (pool, report) = start_pool(Duration::from_secs(30));
    let (addr, hpub, got) = scripted_maker(Some(PROOF));
    let cfg = taker_config(&addr, hpub, &terms, &pool, "r", 30);
    let taker = thread::spawn(move || hashtaker::run(cfg, Box::<LabHashtaker>::default()).unwrap());
    let mut m = got.recv_timeout(Duration::from_secs(5)).unwrap();
    m.open(7);
    let line = m.share(100);
    for _ in 0..20 {
        if m.tx.send(&Msg::Up { chan: 7, line: line.clone() }).is_err() {
            break;
        }
    }
    m.read(Duration::from_secs(4), |_| false);
    let r = taker.join().unwrap();
    assert_eq!(r["closed"], "shares that don't prove", "{r}");
    assert_eq!(r["meter"]["work"], sw.to_string(), "{r}");
    assert_eq!(pool_report(&report)["accepted"], 1);
}

/// A hashmaker holding every share back, so that a winner goes stale: paid in full unless this catches it. Two
/// windows of 32 shares, each all older than a job's quarter life, and the rental ends.
#[test]
fn a_hashmaker_holding_shares_back_is_caught_by_their_age() {
    let _s = serial();
    let sw = share_work(DIFF);
    let terms = Terms { slice_work: 1000 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
    let (pool, _report) = start_pool(Duration::from_secs(60));
    let (addr, hpub, got) = scripted_maker(Some(PROOF));
    let cfg = taker_config(&addr, hpub, &terms, &pool, "r", 60);
    let taker = thread::spawn(move || hashtaker::run(cfg, Box::<LabHashtaker>::default()).unwrap());
    let mut m = got.recv_timeout(Duration::from_secs(5)).unwrap();
    m.open(7);
    let lines: Vec<String> = (0..70).map(|i| m.share(100 + i)).collect();
    // held for longer than the 10 s floor: pings answered, nothing else
    let n = m.tx.clone();
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(11) {
        m.read(Duration::from_millis(200), |_| false);
        let _ = n.send(&Msg::Ping { n: 1 });
    }
    for l in lines {
        if m.tx.send(&Msg::Up { chan: 7, line: l }).is_err() {
            break;
        }
    }
    m.read(Duration::from_secs(3), |_| false);
    let r = taker.join().unwrap();
    eprintln!("closed {}: {}", r["closed"], r["meter"]);
    assert_eq!(r["closed"], "shares arrive too old", "{r}");
    assert_eq!(r["meter"]["proven"], 64, "{r}");
}

/// Sitting on the job before a new block: useless work, and credited. The first share late on it could be
/// firmware finishing up; the second ends the rental, long before a window of verdicts would.
#[test]
fn a_hashmaker_on_a_superseded_job_is_stopped_at_its_second_share() {
    let _s = serial();
    let sw = share_work(DIFF);
    let terms = Terms { slice_work: 1000 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
    // a gateway that says clean_jobs: a new block each second
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let up = l.local_addr().unwrap().to_string();
    thread::spawn(move || {
        let (c, _) = l.accept().unwrap();
        let mut w = c.try_clone().unwrap();
        let w2 = c.try_clone().unwrap();
        let mut r = BufReader::new(c);
        let mut line = String::new();
        while r.read_line(&mut line).is_ok_and(|n| n > 0) {
            let v: Value = serde_json::from_str(line.trim()).unwrap();
            let id = v["id"].clone();
            match v["method"].as_str() {
                Some("mining.subscribe") => writeln!(w, "{}", json!({"id": id, "result": [[], "00000001", 8], "error": null})).unwrap(),
                Some("mining.authorize") => {
                    writeln!(w, "{}", json!({"id": id, "result": true, "error": null})).unwrap();
                    writeln!(w, "{}", json!({"id": null, "method": "mining.set_difficulty", "params": [DIFF]})).unwrap();
                    writeln!(w, "{}", job_line(1, true)).unwrap();
                    let mut w3 = w2.try_clone().unwrap();
                    thread::spawn(move || {
                        thread::sleep(Duration::from_millis(1200));
                        let _ = writeln!(w3, "{}", job_line(2, true));
                    });
                }
                _ => writeln!(w, "{}", json!({"id": id, "result": true, "error": null})).unwrap(),
            }
            line.clear();
        }
    });
    let (addr, hpub, got) = scripted_maker(Some(PROOF));
    let cfg = taker_config(&addr, hpub, &terms, &up, "r", 30);
    let taker = thread::spawn(move || hashtaker::run(cfg, Box::<LabHashtaker>::default()).unwrap());
    let mut m = got.recv_timeout(Duration::from_secs(5)).unwrap();
    m.open(7);
    let first_job = m.job.clone().unwrap();
    let old: Vec<String> = (0..3).map(|i| m.share(100 + i)).collect();
    // past the new job, and past what could be on its way
    m.read(Duration::from_millis(3600), |_| false);
    assert_ne!(m.job.as_ref().unwrap()["params"][0], first_job["params"][0], "the new job came");
    for l in old {
        let _ = m.tx.send(&Msg::Up { chan: 7, line: l });
    }
    m.read(Duration::from_secs(3), |_| false);
    let r = taker.join().unwrap();
    eprintln!("closed {}: {}", r["closed"], r["meter"]);
    assert_eq!(r["closed"], "shares on an old job", "{r}");
    assert_eq!(r["meter"]["proven"], 2, "{r}");
}

/// Shares that prove and are rejected: the gateway has moved on from them, or the hashmaker chose which to send
/// late. Eight in a row, or below 3 in 4 accepted over 64, and the rental ends.
#[test]
fn a_gateway_rejecting_most_shares_ends_the_rental_from_the_hashtakers_side() {
    let _s = serial();
    let sw = share_work(DIFF);
    let terms = Terms { slice_work: 1000 * sw, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 };
    // a gateway that turns down every share
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let up = l.local_addr().unwrap().to_string();
    thread::spawn(move || {
        let (c, _) = l.accept().unwrap();
        let mut w = c.try_clone().unwrap();
        let mut r = BufReader::new(c);
        let mut line = String::new();
        while r.read_line(&mut line).is_ok_and(|n| n > 0) {
            let v: Value = serde_json::from_str(line.trim()).unwrap();
            let id = v["id"].clone();
            let out = match v["method"].as_str() {
                Some("mining.subscribe") => vec![json!({"id": id, "result": [[], "00000001", 8], "error": null})],
                Some("mining.authorize") => vec![
                    json!({"id": id, "result": true, "error": null}),
                    json!({"id": null, "method": "mining.set_difficulty", "params": [DIFF]}),
                    job_line(1, true),
                ],
                _ => vec![json!({"id": id, "result": false, "error": [21, "stale", null]})],
            };
            for o in out {
                let _ = writeln!(w, "{o}");
            }
            line.clear();
        }
    });
    let (addr, hpub, got) = scripted_maker(Some(PROOF));
    let cfg = taker_config(&addr, hpub, &terms, &up, "r", 30);
    let taker = thread::spawn(move || hashtaker::run(cfg, Box::<LabHashtaker>::default()).unwrap());
    let mut m = got.recv_timeout(Duration::from_secs(5)).unwrap();
    m.open(7);
    for i in 0..70 {
        let l = m.share(100 + i);
        if m.tx.send(&Msg::Up { chan: 7, line: l }).is_err() {
            break;
        }
    }
    m.read(Duration::from_secs(5), |_| false);
    let r = taker.join().unwrap();
    assert_eq!(r["closed"], "the gateway accepted too few shares", "{r}");
    assert_eq!(r["meter"]["rejected"], 8, "eight in a row, without waiting for a window: {r}");
}

/// A hashmaker that takes the first payment and does nothing: the renter is out that and no more.
#[test]
fn a_hashmaker_that_takes_the_first_slice_and_vanishes_gets_no_second() {
    let _s = serial();
    let sw = share_work(DIFF);
    let terms = Terms { slice_work: 4 * sw, price_msat: 5_000, grace_ms: 1_000, start_slices: 0 };
    let (pool, _report) = start_pool(Duration::from_secs(30));
    let (addr, hpub, got) = scripted_maker(Some(PROOF));
    let cfg = taker_config(&addr, hpub, &terms, &pool, "r", 2);
    let taker = thread::spawn(move || hashtaker::run(cfg, Box::<LabHashtaker>::default()).unwrap());
    let mut m = got.recv_timeout(Duration::from_secs(5)).unwrap();
    m.read(Duration::from_secs(10), |_| false);
    let r = taker.join().unwrap();
    assert_eq!(r["closed"], "no proven work", "{r}");
    assert_eq!(r["released"], 1, "{r}");
    assert_eq!(m.pays, vec![1]);
}

/// A hashmaker that doesn't prove shares is refused before any money moves.
#[test]
fn a_hashtaker_refuses_a_hashmaker_that_does_not_prove_shares() {
    let _s = serial();
    let terms = Terms { slice_work: 4 * share_work(DIFF), price_msat: 5_000, grace_ms: 1_000, start_slices: 0 };
    let (pool, _report) = start_pool(Duration::from_secs(30));
    let (addr, hpub, got) = scripted_maker(None);
    let cfg = taker_config(&addr, hpub, &terms, &pool, "r", 2);
    let e = hashtaker::run(cfg, Box::<LabHashtaker>::default()).unwrap_err();
    assert!(e.contains(PROOF), "{e}");
    let mut m = got.recv_timeout(Duration::from_secs(5)).unwrap();
    m.read(Duration::from_millis(500), |_| false);
    assert!(m.pays.is_empty());
}

/// An older hashmaker: its welcome hashes the terms as it knew them and says no proof. The renter is told it needs
/// updating, not that no welcome came.
#[test]
fn a_hashtaker_tells_an_older_hashmaker_needs_updating() {
    let terms = Terms { slice_work: 4 * share_work(DIFF), price_msat: 5_000, grace_ms: 1_000, start_slices: 0 };
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let hk = noise::fresh_key();
    thread::spawn(move || {
        let mut lk = link::answer(l.accept().unwrap().0, hk).unwrap();
        let Ok(Some(Msg::Hello { rental, .. })) = lk.rx.recv() else { return };
        // the hash of the terms without the start fee, as an older version computes it
        let _ = lk.tx.send(&Msg::Welcome { rental, terms_hash: "00".repeat(32), proof: None });
        thread::sleep(Duration::from_millis(500));
    });
    let hpub = PublicKey::from_secret_key(secp256k1::SECP256K1, &hk);
    let e = hashtaker::run(taker_config(&addr, hpub, &terms, "127.0.0.1:1", "r", 2), Box::<LabHashtaker>::default()).unwrap_err();
    assert!(e.contains("needs updating") && e.contains(PROOF), "{e}");
}

/// With no way to check a gateway's blinding, and nobody asking to rent without it, a rental doesn't start.
#[test]
fn a_rental_with_no_way_to_check_blinding_does_not_start() {
    let terms = Terms { slice_work: 4 * share_work(DIFF), price_msat: 5_000, grace_ms: 1_000, start_slices: 0 };
    let mut cfg = taker_config("127.0.0.1:1", PublicKey::from_secret_key(secp256k1::SECP256K1, &noise::fresh_key()), &terms, "127.0.0.1:1", "r", 2);
    cfg.allow_unblinded = false;
    let e = hashtaker::run(cfg, Box::<LabHashtaker>::default()).unwrap_err();
    assert!(e.contains("blinding"), "{e}");
}
