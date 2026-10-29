//! The hashtaker's side: dial the hashmaker, open one Stratum V1 session to the hashtaker's own gateway for
//! each of the hashmaker's miners, carry the lines both ways (the gateway credits the hashtaker: its
//! user name replaces the miner's), meter the gateway's verdicts, and pay each finished slice by
//! releasing its ticket with a signed work receipt. Two tickets are kept locked ahead.
//!
//! A channel's meter is let go only after its upstream session has ended and its last verdict
//! was sent on: the hashtaker then says `shut`, and the hashmaker lets the channel go at that same
//! point, so both count the same work to the end. When the hashtaker ends the rental it says how many
//! slices it counted.

use crate::link::{self, Sender};
use crate::meter::{Event, Meter, Receipt};
use crate::msg::{Msg, Terms};
use crate::rail::{HashtakerRail, SignerPayer};
use crate::{now_ms, sv1};
use secp256k1::{PublicKey, SecretKey};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

pub struct Config {
    /// The hashmaker's link address and static key (from its listing).
    pub hashmaker: String,
    pub hashmaker_key: PublicKey,
    pub key: SecretKey,
    /// The hashtaker's own gateway (Stratum V1), and the user name it credits.
    pub upstream: String,
    pub user: String,
    pub terms: Terms,
    pub rental: String,
    pub listing: String,
    /// Lab: stop paying after this many slices (to show the hashmaker stopping).
    pub stop_paying_after: Option<u64>,
    /// End the rental when no work has been accepted for this long.
    pub idle: Duration,
    /// End the rental after this long.
    pub duration: Option<Duration>,
    pub report: Option<PathBuf>,
    /// Slices paid by the wallet through the hashmaker's gateway; without it, over the link (the
    /// lab's stand-in rail).
    pub payer: Option<SignerPayer>,
    /// How many of the hashmaker's miners to rent (0: as many as are free).
    pub miners: u32,
    /// The most the rental may cost: it ends once that much is paid.
    pub budget_msat: Option<u64>,
    /// Set to end the rental now (the app's Cut button).
    pub cut: Option<Arc<AtomicBool>>,
    /// The report, kept current (twice a second) for the app's pages.
    pub live: Option<Arc<Mutex<Value>>>,
}

/// Tickets kept locked ahead of the work.
const AHEAD: u64 = 2;

struct St {
    terms: Terms,
    rental: String,
    key: SecretKey,
    meter: Meter,
    locked: BTreeSet<u64>,
    released: u64,
    done: Vec<(u128, u64)>,
    receipts: Vec<Value>,
    upstreams: HashMap<u32, TcpStream>,
    rail: Box<dyn HashtakerRail>,
    stop_paying_after: Option<u64>,
    last_work: Instant,
    rate: Option<Value>,
    pays: Vec<Value>,
    events: Vec<Value>,
    closed: Option<String>,
    /// Slices for the wallet to pay, in order (with the wallet's payer; none over the link).
    queue: Option<mpsc::Sender<(u64, Value)>>,
    /// The wallet refused or failed a slice: no later slice is asked for.
    pay_failed: bool,
    budget_msat: Option<u64>,
    /// The hashes of the tickets locked over the link, sent again after the link comes back.
    lock_hashes: BTreeMap<u64, String>,
    /// The last payments sent over the link, sent again after it comes back (the hashmaker takes
    /// each slice once, so one that did arrive is not paid twice).
    sent_pays: Vec<(u64, String, Value)>,
}

impl St {
    fn lock_ahead(&mut self, tx: &Sender) {
        if self.queue.is_some() {
            return;
        }
        let want = self.released + AHEAD;
        let next = self.locked.last().copied().unwrap_or(self.released).max(self.released) + 1;
        for slice in next..=want {
            match self.rail.lock(slice, self.terms.price_msat) {
                Ok(h) => {
                    self.locked.insert(slice);
                    self.lock_hashes.insert(slice, hex::encode(h));
                    let _ = tx.send(&Msg::Lock { slice, hash: hex::encode(h) });
                }
                Err(e) => {
                    self.events.push(json!({"ev": "lock failed", "slice": slice, "why": e, "atMs": now_ms()}));
                    return;
                }
            }
        }
    }

    /// After an accepted share: record finished slices and pay them.
    fn settle_up(&mut self, tx: &Sender) {
        let s = self.terms.slice_work;
        while self.meter.work >= (self.done.len() as u128 + 1) * s {
            let w = self.meter.work;
            self.done.push((w, now_ms()));
        }
        while (self.released as usize) < self.done.len() {
            let slice = self.released + 1;
            if self.stop_paying_after.is_some_and(|n| slice > n) {
                return;
            }
            if self.budget_msat.is_some_and(|b| slice * self.terms.price_msat > b) {
                return;
            }
            let receipt = Receipt {
                rental: self.rental.clone(),
                slice,
                work: self.done[slice as usize - 1].0,
                accepted: self.meter.accepted,
                rejected: self.meter.rejected,
                at_ms: now_ms(),
            }
            .sign(&self.key);
            if let Some(q) = &self.queue {
                if self.pay_failed || q.send((slice, receipt.clone())).is_err() {
                    return;
                }
                self.receipts.push(receipt);
                self.released = slice;
                continue;
            }
            let Ok(pre) = self.rail.release(slice) else { return };
            self.locked.remove(&slice);
            self.lock_hashes.remove(&slice);
            self.sent_pays.push((slice, hex::encode(pre), receipt.clone()));
            if self.sent_pays.len() > AHEAD as usize + 2 {
                self.sent_pays.remove(0);
            }
            let _ = tx.send(&Msg::Pay { slice, preimage: hex::encode(pre), receipt: receipt.clone() });
            self.receipts.push(receipt);
            self.pays.push(json!({"slice": slice, "atMs": now_ms()}));
            self.released = slice;
            self.lock_ahead(tx);
        }
    }

    /// Slices paid: by the wallet (its answers), or released over the link.
    fn paid_slices(&self) -> u64 {
        if self.queue.is_some() || !self.pays.is_empty() && self.pays.iter().any(|p| p.get("ok").is_some()) {
            self.pays.iter().filter(|p| p["ok"] == true).count() as u64
        } else {
            self.released
        }
    }

    fn report(&self) -> Value {
        json!({
            "role": "buyer", "rental": self.rental, "terms": self.terms.to_json(), "meter": self.meter.to_json(),
            "slicesDone": self.done.iter().map(|(w, t)| json!({"work": w.to_string(), "atMs": t})).collect::<Vec<_>>(),
            "released": self.released, "locked": self.locked, "pays": self.pays, "receipts": self.receipts,
            "lastRate": self.rate, "closed": self.closed, "payFailed": self.pay_failed, "events": self.events,
            "paidSlices": self.paid_slices(), "spentMsat": self.paid_slices() * self.terms.price_msat,
            "miners": self.upstreams.len(), "budgetMsat": self.budget_msat,
        })
    }
}

fn write_report(path: &Option<PathBuf>, v: &Value) {
    if let Some(p) = path {
        let tmp = p.with_extension("tmp");
        if std::fs::write(&tmp, serde_json::to_vec_pretty(v).unwrap_or_default()).is_ok() {
            let _ = std::fs::rename(&tmp, p);
        }
    }
}

/// Run one rental to its end and return the report. `rail` makes, releases and cancels the
/// tickets; whatever is still locked at the end is cancelled.
pub fn run(cfg: Config, rail: Box<dyn HashtakerRail>) -> Result<Value, String> {
    let link::Link { tx, mut rx, .. } = link::dial(&cfg.hashmaker, cfg.key, cfg.hashmaker_key).map_err(|e| e.to_string())?;
    tx.send(&Msg::Hello { rental: cfg.rental.clone(), listing: cfg.listing.clone(), terms: cfg.terms.clone(), miners: cfg.miners })
        .map_err(|e| e.to_string())?;
    match rx.recv().map_err(|e| e.to_string())? {
        Some(Msg::Welcome { terms_hash, .. }) if terms_hash == hex::encode(cfg.terms.hash()) => {}
        Some(Msg::Close { reason, .. }) => return Err(format!("hashmaker refused: {reason}")),
        _ => return Err("no welcome".into()),
    }
    eprintln!("hashtaker: rental {} with hashmaker {}", cfg.rental, cfg.hashmaker);
    let st = Arc::new(Mutex::new(St {
        terms: cfg.terms.clone(),
        rental: cfg.rental.clone(),
        key: cfg.key,
        meter: Meter::default(),
        locked: BTreeSet::new(),
        released: 0,
        done: Vec::new(),
        receipts: Vec::new(),
        upstreams: HashMap::new(),
        rail,
        stop_paying_after: cfg.stop_paying_after,
        last_work: Instant::now(),
        rate: None,
        pays: Vec::new(),
        events: Vec::new(),
        closed: None,
        queue: None,
        pay_failed: false,
        budget_msat: cfg.budget_msat,
        lock_hashes: BTreeMap::new(),
        sent_pays: Vec::new(),
    }));
    lock(&st).lock_ahead(&tx);

    // the wallet's payer, one slice at a time, off the relay's path
    let stopped_session: Arc<Mutex<Option<Value>>> = Arc::default();
    let redial = Redial { hashmaker: cfg.hashmaker.clone(), key: cfg.key, hashmaker_key: cfg.hashmaker_key, rental: cfg.rental.clone(), terms: cfg.terms.clone() };
    let payer_thread = cfg.payer.map(|mut p| {
        let (qtx, qrx) = mpsc::channel::<(u64, Value)>();
        lock(&st).queue = Some(qtx);
        let (st, rental, out) = (st.clone(), cfg.rental.clone(), stopped_session.clone());
        std::thread::spawn(move || {
            for (slice, receipt) in qrx {
                if lock(&st).pay_failed {
                    continue;
                }
                let t0 = Instant::now();
                let r = p.pay(&rental, slice, &receipt);
                let mut g = lock(&st);
                let ms = t0.elapsed().as_millis() as u64;
                match r {
                    Ok(v) => g.pays.push(json!({"slice": slice, "atMs": now_ms(), "ms": ms, "ok": true, "wallet": v})),
                    Err(why) => {
                        g.pay_failed = true;
                        g.pays.push(json!({"slice": slice, "atMs": now_ms(), "ms": ms, "ok": false, "why": why}));
                    }
                }
            }
            *out.lock().unwrap_or_else(|p| p.into_inner()) = p.stop();
        })
    });

    // ticker: idle, duration, report
    {
        let st = st.clone();
        let tx = tx.clone();
        let report = cfg.report.clone();
        let (idle, duration, cut, live) = (cfg.idle, cfg.duration, cfg.cut.clone(), cfg.live.clone());
        let t0 = Instant::now();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(500));
            let mut g = lock(&st);
            if let Some(l) = &live {
                *l.lock().unwrap_or_else(|p| p.into_inner()) = g.report();
            }
            if g.closed.is_some() {
                return;
            }
            let spent = g.released * g.terms.price_msat;
            let why = if cut.as_ref().is_some_and(|c| c.load(Ordering::Relaxed)) {
                Some("cut by the hashtaker")
            } else if g.budget_msat.is_some_and(|b| spent + g.terms.price_msat > b) {
                // the next piece could not be paid: end before the hashmaker does it
                Some("budget used up")
            } else if g.last_work.elapsed() > idle {
                Some("no accepted work")
            } else if duration.is_some_and(|d| t0.elapsed() > d) {
                Some("rental time over")
            } else {
                None
            };
            if let Some(why) = why {
                g.closed = Some(why.to_string());
                let slices = g.done.len() as u64;
                let _ = tx.send(&Msg::Close { reason: why.into(), slices: Some(slices) });
                tx.shutdown();
                return;
            }
            write_report(&report, &g.report());
        });
    }

    loop {
        let m = match rx.recv() {
            Ok(Some(m)) => m,
            Ok(None) => continue,
            Err(e) => {
                if lock(&st).closed.is_none() {
                    // a link that dropped is made again within the grace time, and the rental carries on
                    if let Some(back) = come_back(&redial, &tx, &st, &e.to_string()) {
                        rx = back;
                        continue;
                    }
                }
                let mut g = lock(&st);
                if g.closed.is_none() {
                    g.closed = Some(format!("link lost: {e}"));
                }
                break;
            }
        };
        match m {
            Msg::Open { chan, worker } => {
                let up = TcpStream::connect(&cfg.upstream);
                let mut g = lock(&st);
                g.events.push(json!({"ev": "open", "chan": chan, "worker": worker, "ok": up.is_ok(), "atMs": now_ms()}));
                match up.and_then(|u| u.try_clone().map(|w| (u, w))) {
                    Ok((u, w)) => {
                        g.upstreams.insert(chan, w);
                        let (st, tx) = (st.clone(), tx.clone());
                        std::thread::spawn(move || upstream(chan, u, st, tx));
                    }
                    Err(_) => {
                        g.meter.close(chan);
                        let _ = tx.send(&Msg::Shut { chan });
                    }
                }
            }
            Msg::Up { chan, line } => {
                let Some(v) = sv1::parse(&line) else { continue };
                let mut g = lock(&st);
                g.meter.up(chan, &v);
                let out = sv1::with_user(&v, &cfg.user).unwrap_or_else(|| line.trim_end().to_string());
                if let Some(u) = g.upstreams.get_mut(&chan) {
                    if u.write_all(format!("{out}\n").as_bytes()).is_err() {
                        g.upstreams.remove(&chan);
                        let _ = tx.send(&Msg::Shut { chan });
                    }
                }
            }
            Msg::Shut { chan } => {
                // the miner is gone: close its upstream session; the channel is let go (and the
                // hashmaker told) when that session's last verdict has been read
                let mut g = lock(&st);
                if let Some(u) = g.upstreams.remove(&chan) {
                    let _ = u.shutdown(std::net::Shutdown::Both);
                }
            }
            Msg::Rate { hs, miners } => lock(&st).rate = Some(json!({"hs": hs, "miners": miners, "atMs": now_ms()})),
            Msg::Ping { n } => {
                let _ = tx.send(&Msg::Pong { n });
            }
            Msg::Close { reason, .. } => {
                // the hashmaker answers our own close with one of its own: the first reason stands
                lock(&st).closed.get_or_insert_with(|| format!("hashmaker closed: {reason}"));
                break;
            }
            _ => {}
        }
    }
    // the wallet's payer: the slices asked for are paid, or found failed, before the session ends
    let payer = lock(&st).queue.take();
    drop(payer);
    if let Some(h) = payer_thread {
        let _ = h.join();
    }
    let mut g = lock(&st);
    if let Some(stop) = stopped_session.lock().unwrap_or_else(|p| p.into_inner()).take() {
        g.events.push(json!({"ev": "wallet session stopped", "result": stop, "atMs": now_ms()}));
    }
    for slice in std::mem::take(&mut g.locked) {
        g.rail.cancel(slice);
        g.events.push(json!({"ev": "cancelled", "slice": slice, "atMs": now_ms()}));
    }
    for (_, u) in g.upstreams.drain() {
        let _ = u.shutdown(std::net::Shutdown::Both);
    }
    tx.shutdown();
    let r = g.report();
    write_report(&cfg.report, &r);
    if let Some(l) = &cfg.live {
        *l.lock().unwrap_or_else(|p| p.into_inner()) = r.clone();
    }
    Ok(r)
}

/// What dialling the hashmaker again needs.
struct Redial {
    hashmaker: String,
    key: SecretKey,
    hashmaker_key: PublicKey,
    rental: String,
    terms: Terms,
}

/// The link dropped: the old upstream sessions end (the hashmaker has let their channels go and
/// opens new ones), and the hashmaker is dialled again, with growing pauses, until most of its
/// grace time is gone. On its welcome, every clone of `tx` sends on the new link, and the locks and
/// the last payments are sent again. `None`: not back in time, or the hashmaker refused.
fn come_back(cfg: &Redial, tx: &Sender, st: &Arc<Mutex<St>>, why: &str) -> Option<link::Receiver> {
    let deadline = Instant::now() + Duration::from_millis(cfg.terms.grace_ms) * 4 / 5;
    {
        let mut g = lock(st);
        g.events.push(json!({"ev": "link lost, dialling again", "why": why, "atMs": now_ms()}));
        let ups: Vec<(u32, TcpStream)> = g.upstreams.drain().collect();
        for (chan, u) in ups {
            let _ = u.shutdown(std::net::Shutdown::Both);
            g.meter.close(chan);
        }
    }
    let mut pause = Duration::from_millis(250);
    while Instant::now() + pause < deadline {
        std::thread::sleep(pause);
        pause = (pause * 2).min(Duration::from_secs(2));
        if lock(st).closed.is_some() {
            return None;
        }
        let Ok(link::Link { tx: new_tx, rx: mut new_rx, .. }) = link::dial(&cfg.hashmaker, cfg.key, cfg.hashmaker_key) else { continue };
        if new_tx.send(&Msg::Resume { rental: cfg.rental.clone() }).is_err() {
            continue;
        }
        match new_rx.recv() {
            Ok(Some(Msg::Welcome { terms_hash, .. })) if terms_hash == hex::encode(cfg.terms.hash()) => {
                tx.adopt(new_tx);
                let mut g = lock(st);
                g.events.push(json!({"ev": "rental resumed", "atMs": now_ms()}));
                let released = g.released;
                for (slice, hash) in g.lock_hashes.clone() {
                    if slice > released {
                        let _ = tx.send(&Msg::Lock { slice, hash });
                    }
                }
                for (slice, preimage, receipt) in g.sent_pays.clone() {
                    let _ = tx.send(&Msg::Pay { slice, preimage, receipt });
                }
                return Some(new_rx);
            }
            Ok(Some(Msg::Close { reason, .. })) => {
                lock(st).events.push(json!({"ev": "resume refused", "why": reason, "atMs": now_ms()}));
                return None;
            }
            _ => continue,
        }
    }
    None
}

fn lock(st: &Mutex<St>) -> std::sync::MutexGuard<'_, St> {
    st.lock().unwrap_or_else(|p| p.into_inner())
}

fn upstream(chan: u32, u: TcpStream, st: Arc<Mutex<St>>, tx: Sender) {
    let mut r = BufReader::new(u);
    let mut line = String::new();
    loop {
        line.clear();
        match r.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let Some(v) = sv1::parse(&line) else { continue };
        let mut g = st.lock().unwrap_or_else(|p| p.into_inner());
        if g.closed.is_some() {
            break;
        }
        // meter, send, then pay: the hashmaker reads the verdict before the payment for it
        let ev = g.meter.down(chan, &v);
        if tx.send(&Msg::Down { chan, line: line.trim_end().to_string() }).is_err() {
            break;
        }
        if let Some(Event::Accepted(_)) = ev {
            g.last_work = Instant::now();
            g.settle_up(&tx);
        }
    }
    // this channel's last verdict has been read and sent: both sides let it go here
    let mut g = st.lock().unwrap_or_else(|p| p.into_inner());
    g.upstreams.remove(&chan);
    g.meter.close(chan);
    let _ = tx.send(&Msg::Shut { chan });
}
