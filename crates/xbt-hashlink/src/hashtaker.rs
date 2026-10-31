//! The hashtaker's side: dial the hashmaker, open one Stratum V1 session to the hashtaker's own gateway for
//! each of the hashmaker's miners, and carry the lines both ways (the gateway credits the hashtaker: its
//! user name replaces the miner's). Every share's hash is checked here too ([`crate::meter`]), and only one
//! it proves goes on to the gateway. This side pays by its own count, as [`crate::order`] says, each payment
//! with a signed receipt saying what that count was.
//!
//! The hashmaker chooses which shares reach here, so this side also watches for shares held back: it ends
//! the rental if its gateway accepts too few of them, or if they keep arriving too old.
//!
//! A channel's meter is let go only after its upstream session has ended and its last verdict was sent on:
//! the hashtaker then says `shut`. A dropped link is another matter: the channels' job tables stay until the
//! next drop, so that shares the hashmaker sends again can still be checked.

use crate::blind;
use crate::link::{self, Sender};
use crate::meter::{Meter, Receipt};
use crate::msg::{Msg, Terms, PROOF};
use crate::order;
use crate::rail::{sha256, HashtakerRail, SignerPayer};
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
    /// End the rental when no work has been proven for this long.
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
    /// The local API of the hashtaker's gateway, where each job is opened and checked for its blinding.
    pub gateway_api: Option<String>,
    /// Rent onto jobs that aren't blinded, where a hashmaker could drop the shares that win (a lab's own
    /// pool). Off, a rental refuses any job it can't show is blinded.
    pub allow_unblinded: bool,
}

/// Tickets kept locked ahead of the work.
const AHEAD: u64 = 2;
/// Job keys kept for the report.
const KEYS_REPORTED: usize = 1024;
/// Refused shares a rental stands before it asks how they compare with the proven ones.
const REFUSED_LEEWAY: u64 = 8;

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
    /// Channels of the link that last dropped: their job tables wait for shares sent again.
    retired: BTreeSet<u32>,
    /// Shares counted from the hashmaker's sending them again after a drop.
    resent_counted: u64,
    /// Jobs its gateway showed to be blinded.
    jobs_shown_blinded: u64,
    /// The gateway's word for whose key its last job has.
    blinding: Option<String>,
    /// Each job key hash seen, with the previous block its job was on.
    keys_seen: Vec<(String, String)>,
    first_proven: Option<Instant>,
    /// The hashmaker said a share waits for payment, how many times, and its last count when it did.
    dues: u64,
    last_due: Option<(u128, u64)>,
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

    /// End the rental from this side.
    fn end(&mut self, why: &str, tx: &Sender) {
        self.closed = Some(why.to_string());
        let _ = tx.send(&Msg::Close { reason: why.into(), slices: Some(self.done.len() as u64) });
        tx.shutdown();
    }

    /// The largest share a live channel could send now.
    fn largest_share(&self) -> u128 {
        self.meter.largest_share(self.upstreams.keys().copied())
    }

    /// What this rental stands at for [`crate::order`], by this side's own count.
    fn standing(&self) -> order::Standing {
        // the output, in money, since the first proof
        let msat_a_second = self.first_proven.map_or(0.0, |t| {
            let seconds = t.elapsed().as_secs_f64();
            if seconds < 1.0 {
                0.0
            } else {
                self.meter.work as f64 / self.terms.slice_work as f64 * self.terms.price_msat as f64 / seconds
            }
        });
        order::Standing {
            proven: self.meter.work,
            largest_share: self.largest_share(),
            paid: self.released,
            start_slices: self.terms.start_slices,
            slice_work: self.terms.slice_work,
            price_msat: self.terms.price_msat,
            msat_a_second,
        }
    }

    /// Note slices' worth of proven work reached, and pay whatever [`order::pay_next`] says is due.
    fn settle_up(&mut self, tx: &Sender) {
        // nothing more once this side has ended it, whatever is still on its way
        if self.closed.is_some() {
            return;
        }
        let s = self.terms.slice_work;
        while self.meter.work >= (self.done.len() as u128 + 1) * s {
            let w = self.meter.work;
            self.done.push((w, now_ms()));
        }
        while self.standing().pay_next() {
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
                work: self.meter.work,
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
            "latencyMs": self.meter.latency_json(),
            "slicesDone": self.done.iter().map(|(w, t)| json!({"work": w.to_string(), "atMs": t})).collect::<Vec<_>>(),
            "released": self.released, "locked": self.locked, "pays": self.pays, "receipts": self.receipts,
            "lastRate": self.rate, "closed": self.closed, "payFailed": self.pay_failed, "events": self.events,
            "resentCounted": self.resent_counted, "jobsShownBlinded": self.jobs_shown_blinded, "blinding": self.blinding,
            "keysSeen": self.keys_seen.iter().map(|(k, p)| json!({"keyHash": k, "prevblock": p})).collect::<Vec<_>>(),
            "dues": self.dues, "lastDue": self.last_due.map(|(w, p)| json!({"work": w.to_string(), "paid": p})),
            "paidSlices": self.paid_slices(), "spentMsat": self.paid_slices() * self.terms.price_msat,
            "miners": self.upstreams.len(), "budgetMsat": self.budget_msat,
            // what left the wallet for the rental (tickets bought whole, with their fees), and what its stop
            // said stays with the seller as credit: a ticket bought for a small rental is more than it uses
            "walletMovedSats": self.pays.iter().filter_map(|p| p["wallet"]["charged_sats"].as_u64()).sum::<u64>(),
            "leftWithSellerMsat": self.events.iter().rev().find(|e| e["ev"] == "wallet session stopped")
                .and_then(|e| e["result"]["http"]["left_with_seller_msat"].as_str()).and_then(|s| s.parse::<u64>().ok()),
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
    if cfg.gateway_api.is_none() && !cfg.allow_unblinded {
        return Err("nothing to check this gateway's blinding with: a hashmaker could drop the shares that win".into());
    }
    let link::Link { tx, mut rx, .. } = link::dial(&cfg.hashmaker, cfg.key, cfg.hashmaker_key).map_err(|e| e.to_string())?;
    tx.send(&Msg::Hello { rental: cfg.rental.clone(), listing: cfg.listing.clone(), terms: cfg.terms.clone(), miners: cfg.miners, proof: Some(PROOF.into()) })
        .map_err(|e| e.to_string())?;
    match rx.recv_within(link::HANDSHAKE_TIMEOUT).map_err(|e| e.to_string())? {
        Some(Msg::Welcome { terms_hash, proof, .. }) if terms_hash == hex::encode(cfg.terms.hash()) => {
            if proof.as_deref() != Some(PROOF) {
                tx.shutdown();
                return Err(format!("this hashmaker doesn't prove shares ({PROOF}): it needs updating"));
            }
        }
        // an older hashmaker's terms hash differently and it says no proof: name the cause, not the hash
        Some(Msg::Welcome { proof: None, .. }) => {
            tx.shutdown();
            return Err(format!("this hashmaker needs updating (it doesn't prove shares, {PROOF})"));
        }
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
        retired: BTreeSet::new(),
        resent_counted: 0,
        jobs_shown_blinded: 0,
        blinding: None,
        keys_seen: Vec::new(),
        first_proven: None,
        dues: 0,
        last_due: None,
    }));
    lock(&st).lock_ahead(&tx);
    let blind_check = if cfg.allow_unblinded { None } else { cfg.gateway_api.clone().map(|a| Arc::new(blind::Check::new(a))) };

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
                // the ticket this payment may buy: the step the rental has earned, by this side's own count now
                p.caps_for(lock(&st).standing().ticket_msat());
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
    lock(&st).settle_up(&tx);

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
            let (s, largest) = (g.terms.slice_work, g.largest_share());
            // the next slice can't be paid: end as the last paid one runs out, before the hashmaker does it
            let no_more = g.budget_msat.is_some_and(|b| (g.released + 1) * g.terms.price_msat > b);
            let why = if cut.as_ref().is_some_and(|c| c.load(Ordering::Relaxed)) {
                Some("cut by the hashtaker")
            } else if no_more && !order::fits(g.meter.work, largest.max(1), g.released, g.terms.start_slices, s) {
                Some("budget used up")
            } else if g.pay_failed && g.paid_slices() == 0 {
                Some("the first slice could not be paid")
            } else if g.last_work.elapsed() > idle {
                Some("no proven work")
            } else if duration.is_some_and(|d| t0.elapsed() > d) {
                Some("rental time over")
            } else {
                None
            };
            if let Some(why) = why {
                g.end(why, &tx);
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
        // this side ended it: whatever else was on its way is not read
        if lock(&st).closed.is_some() {
            break;
        }
        match m {
            Msg::Open { chan, worker } => {
                let up = TcpStream::connect(&cfg.upstream);
                let mut g = lock(&st);
                g.events.push(json!({"ev": "open", "chan": chan, "worker": worker, "ok": up.is_ok(), "atMs": now_ms()}));
                match up.and_then(|u| u.try_clone().map(|w| (u, w))) {
                    Ok((u, w)) => {
                        g.upstreams.insert(chan, w);
                        let (st, tx, check) = (st.clone(), tx.clone(), blind_check.clone());
                        std::thread::spawn(move || upstream(chan, u, st, tx, check));
                    }
                    Err(_) => {
                        g.meter.close(chan);
                        let _ = tx.send(&Msg::Shut { chan });
                    }
                }
            }
            Msg::Up { chan, line } => {
                let Some(v) = sv1::parse(&line) else { continue };
                let is_share = sv1::submit_job(&v).is_some();
                if is_share {
                    // read under the lock, hashed outside it
                    let claim = lock(&st).meter.claim(chan, &v);
                    let proved = claim.and_then(|c| {
                        let h = c.hash();
                        lock(&st).meter.commit(&c, h)
                    });
                    let mut g = lock(&st);
                    match proved {
                        Ok(p) if p.old => {
                            g.end("shares arrive too old", &tx);
                            continue;
                        }
                        Ok(p) if p.old_job => {
                            g.end("shares on an old job", &tx);
                            continue;
                        }
                        Ok(_) => {
                            g.last_work = Instant::now();
                            g.first_proven.get_or_insert_with(Instant::now);
                        }
                        Err(why) => {
                            let answer = why.rejection(v.get("id").unwrap_or(&Value::Null));
                            let _ = tx.send(&Msg::Down { chan, line: answer.to_string() });
                            // the odd one is a job change in flight; many are shares nobody hashed
                            if g.meter.refused > REFUSED_LEEWAY + g.meter.proven / 8 {
                                g.end("shares that don't prove", &tx);
                            }
                            continue;
                        }
                    }
                } else {
                    lock(&st).meter.note_up(chan, &v);
                }
                let mut g = lock(&st);
                let out = sv1::with_user(&v, &cfg.user).unwrap_or_else(|| line.trim_end().to_string());
                if let Some(u) = g.upstreams.get_mut(&chan) {
                    if u.write_all(format!("{out}\n").as_bytes()).is_err() {
                        g.upstreams.remove(&chan);
                        let _ = tx.send(&Msg::Shut { chan });
                    }
                }
                if is_share {
                    g.settle_up(&tx);
                }
            }
            Msg::Due { work, paid } => {
                // a nudge: what's due is by this side's own count
                let mut g = lock(&st);
                g.dues += 1;
                g.last_due = Some((work, paid));
                g.settle_up(&tx);
            }
            Msg::Resend { chan, line } => {
                // counted once if it proves; its gateway session ended with the old link
                let Some(v) = sv1::parse(&line) else { continue };
                let mut g = lock(&st);
                if g.meter.resent(chan, &v).is_some() {
                    g.resent_counted += 1;
                    g.last_work = Instant::now();
                    g.settle_up(&tx);
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

/// The link dropped: the old upstream sessions end (the hashmaker has let their channels go and opens new
/// ones), and the hashmaker is dialled again, with growing pauses, until most of its grace time is gone. On its
/// welcome, every clone of `tx` sends on the new link, and the locks and the last payments are sent again. A dial
/// or a welcome that does not come is given up at the deadline, whatever the road does. `None`: not back in
/// time, or the hashmaker refused.
fn come_back(cfg: &Redial, tx: &Sender, st: &Arc<Mutex<St>>, why: &str) -> Option<link::Receiver> {
    let deadline = Instant::now() + Duration::from_millis(cfg.terms.grace_ms) * 4 / 5;
    {
        let mut g = lock(st);
        g.events.push(json!({"ev": "link lost, dialling again", "why": why, "atMs": now_ms()}));
        for chan in std::mem::take(&mut g.retired) {
            g.meter.close(chan);
        }
        g.retired = g.meter.channels().into_iter().collect();
        for (_, u) in g.upstreams.drain() {
            let _ = u.shutdown(std::net::Shutdown::Both);
        }
    }
    let mut pause = Duration::from_millis(250);
    while Instant::now() + pause < deadline {
        std::thread::sleep(pause);
        pause = (pause * 2).min(Duration::from_secs(1));
        if lock(st).closed.is_some() {
            return None;
        }
        let left = || deadline.saturating_duration_since(Instant::now()).min(link::HANDSHAKE_TIMEOUT);
        let Ok(link::Link { tx: new_tx, rx: mut new_rx, .. }) = link::dial_within(&cfg.hashmaker, cfg.key, cfg.hashmaker_key, left()) else { continue };
        if new_tx.send(&Msg::Resume { rental: cfg.rental.clone() }).is_err() {
            continue;
        }
        match new_rx.recv_within(left()) {
            Ok(Some(Msg::Welcome { terms_hash, proof, .. })) if terms_hash == hex::encode(cfg.terms.hash()) && proof.as_deref() == Some(PROOF) => {
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
                    // its lock may have been lost with the link too; a slice already paid ignores both
                    if let Ok(p) = hex::decode(&preimage) {
                        let _ = tx.send(&Msg::Lock { slice, hash: hex::encode(sha256(&p)) });
                    }
                    let _ = tx.send(&Msg::Pay { slice, preimage, receipt });
                }
                g.settle_up(tx);
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

fn upstream(chan: u32, u: TcpStream, st: Arc<Mutex<St>>, tx: Sender, check: Option<Arc<blind::Check>>) {
    let mut r = BufReader::new(u);
    let mut line = String::new();
    loop {
        line.clear();
        match r.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let Some(v) = sv1::parse(&line) else { continue };
        // a job the gateway can't show to be blinded goes no further: one is enough to lose a block. The gateway
        // is asked with no lock held, and this channel's lines stay in order
        let shown = match (&check, sv1::method(&v) == Some("mining.notify")) {
            (Some(c), true) => {
                let d = st.lock().unwrap_or_else(|p| p.into_inner()).meter.diff_now(chan);
                Some(c.job_seen(&v, d))
            }
            _ => None,
        };
        let mut g = st.lock().unwrap_or_else(|p| p.into_inner());
        if g.closed.is_some() {
            break;
        }
        match shown {
            Some(Ok(seen)) => {
                g.jobs_shown_blinded += 1;
                g.blinding = Some(seen.mode.clone());
                // each key and the block it was used after, once: what shows a key never outlives its block
                let rec = (seen.key_hash, seen.prevblock);
                if g.keys_seen.len() < KEYS_REPORTED && !g.keys_seen.contains(&rec) {
                    g.keys_seen.push(rec);
                }
            }
            Some(Err(why)) => {
                g.events.push(json!({"ev": "a job not shown to be blinded", "why": why, "atMs": now_ms()}));
                g.end("the gateway's jobs aren't blinded", &tx);
                break;
            }
            None => {}
        }
        // the gateway's jobs are for hashing and for checking, or the rental can't go on
        if sv1::method(&v) == Some("mining.set_extranonce") {
            g.end("the gateway changed the extranonce", &tx);
            break;
        }
        if let Err(why) = g.meter.down(chan, &v) {
            g.events.push(json!({"ev": "a line that can't be checked", "why": why, "atMs": now_ms()}));
            g.end("a job this app can't check", &tx);
            break;
        }
        if tx.send(&Msg::Down { chan, line: line.trim_end().to_string() }).is_err() {
            break;
        }
        if g.meter.verdicts_low {
            g.end("the gateway accepted too few shares", &tx);
            break;
        }
        // a new difficulty changes what's due
        g.settle_up(&tx);
    }
    // this channel's last verdict has been read and sent: it's let go here, unless a dropped link took it, when
    // its job table waits for shares sent again
    let mut g = st.lock().unwrap_or_else(|p| p.into_inner());
    if !g.retired.contains(&chan) {
        g.upstreams.remove(&chan);
        g.meter.close(chan);
        let _ = tx.send(&Msg::Shut { chan });
    }
}

#[cfg(test)]
mod come_back_tests {
    use super::*;
    use crate::rail::LabHashtaker;
    use std::net::TcpListener;

    fn terms() -> Terms {
        Terms { slice_work: 1 << 32, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 }
    }

    fn state() -> Arc<Mutex<St>> {
        Arc::new(Mutex::new(St {
            terms: terms(),
            rental: "r".into(),
            key: crate::noise::fresh_key(),
            meter: Meter::default(),
            locked: BTreeSet::new(),
            released: 0,
            done: Vec::new(),
            receipts: Vec::new(),
            upstreams: HashMap::new(),
            rail: Box::<LabHashtaker>::default(),
            stop_paying_after: None,
            last_work: Instant::now(),
            rate: None,
            pays: Vec::new(),
            events: Vec::new(),
            closed: None,
            queue: None,
            pay_failed: false,
            budget_msat: None,
            lock_hashes: BTreeMap::new(),
            sent_pays: Vec::new(),
            retired: BTreeSet::new(),
            resent_counted: 0,
            jobs_shown_blinded: 0,
            blinding: None,
            keys_seen: Vec::new(),
            first_proven: None,
            dues: 0,
            last_due: None,
        }))
    }

    /// A link made and left: the sender `come_back` is given.
    fn a_link(key: SecretKey, hk: SecretKey) -> (Sender, std::thread::JoinHandle<link::Link>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let peer = std::thread::spawn(move || link::answer(l.accept().unwrap().0, hk).unwrap());
        let hpub = PublicKey::from_secret_key(secp256k1::SECP256K1, &hk);
        (link::dial(&addr, key, hpub).unwrap().tx, peer)
    }

    /// Something that answers the dial and drips bytes, each within a read's timeout: the whole of a dial
    /// and of the wait for a welcome is held to the time to come back, not each read of it.
    #[test]
    fn a_road_that_drips_bytes_does_not_hold_a_return_past_its_time() {
        use std::io::Write as _;
        let (key, hk) = (crate::noise::fresh_key(), crate::noise::fresh_key());
        let (tx, _peer) = a_link(key, hk);
        let st = state();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            for _ in 0..1000 {
                if s.write_all(&[0u8]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(400));
            }
        });
        // four fifths of this is a deadline of 1 s
        let cfg = Redial { hashmaker: addr, key, hashmaker_key: PublicKey::from_secret_key(secp256k1::SECP256K1, &hk), rental: "r".into(), terms: Terms { grace_ms: 1_250, ..terms() } };
        let t0 = Instant::now();
        assert!(come_back(&cfg, &tx, &st, "test").is_none());
        assert!(t0.elapsed() < Duration::from_secs(3), "{} ms against a deadline of 1 s", t0.elapsed().as_millis());
    }

    /// The job tables stay across a drop and go at the next one, and a share sent again is counted once.
    #[test]
    fn a_share_sent_again_after_a_drop_is_checked_and_counted_once() {
        let (key, hk) = (crate::noise::fresh_key(), crate::noise::fresh_key());
        let (tx, _peer) = a_link(key, hk);
        let st = state();
        let d = 1.0 / (1u64 << 20) as f64;
        let notify = crate::standin::notify_line("a", 1, 1_700_000_000, false);
        let (e2, nonce) = crate::standin::find_share(&notify, "00000001", 8, d, 1).unwrap();
        let share = json!({"id": 5, "method": "mining.submit", "params": ["u", "a", e2, format!("{:08x}", 1_700_000_000u32), nonce]});
        {
            let mut g = lock(&st);
            g.meter.note_up(7, &json!({"id": 1, "method": "mining.subscribe", "params": []}));
            g.meter.down(7, &json!({"id": 1, "result": [[], "00000001", 8], "error": null})).unwrap();
            g.meter.down(7, &json!({"id": null, "method": "mining.set_difficulty", "params": [d]})).unwrap();
            g.meter.down(7, &notify).unwrap();
        }
        let cfg = Redial { hashmaker: "127.0.0.1:1".into(), key, hashmaker_key: PublicKey::from_secret_key(secp256k1::SECP256K1, &hk), rental: "r".into(), terms: Terms { grace_ms: 1, ..terms() } };
        assert!(come_back(&cfg, &tx, &st, "test").is_none());
        let mut g = lock(&st);
        assert_eq!(g.meter.resent(7, &share), Some(crate::meter::share_work(d)));
        assert_eq!(g.meter.resent(7, &share), None, "once");
        assert_eq!((g.meter.proven, g.meter.refused), (1, 0));
        drop(g);
        // a later drop lets that channel go
        assert!(come_back(&cfg, &tx, &st, "test").is_none());
        assert!(come_back(&cfg, &tx, &st, "test").is_none());
        let mut bad = share.clone();
        bad["id"] = json!(6);
        assert_eq!(lock(&st).meter.resent(7, &bad), None);
        assert!(lock(&st).meter.channels().is_empty());
    }

    /// A slice due as a link comes back is paid on the new link.
    #[test]
    fn a_slice_due_on_return_is_paid_on_the_new_link() {
        let (key, hk) = (crate::noise::fresh_key(), crate::noise::fresh_key());
        let (tx, _peer) = a_link(key, hk);
        let st = state();
        {
            let mut g = lock(&st);
            g.key = key;
            g.lock_ahead(&tx);
            g.meter.work = terms().slice_work;
            g.released = 0;
        }
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let t = terms();
        let maker = std::thread::spawn(move || {
            let mut lk = link::answer(l.accept().unwrap().0, hk).unwrap();
            let Ok(Some(Msg::Resume { .. })) = lk.rx.recv() else { panic!("no resume") };
            lk.tx.send(&Msg::Welcome { rental: "r".into(), terms_hash: hex::encode(t.hash()), proof: Some(PROOF.into()) }).unwrap();
            let mut paid = None;
            while let Ok(Some(m)) = lk.rx.recv_within(Duration::from_secs(5)) {
                if let Msg::Pay { slice, .. } = m {
                    paid = Some(slice);
                    break;
                }
            }
            paid
        });
        let cfg = Redial { hashmaker: addr, key, hashmaker_key: PublicKey::from_secret_key(secp256k1::SECP256K1, &hk), rental: "r".into(), terms: terms() };
        assert!(come_back(&cfg, &tx, &st, "test").is_some());
        assert_eq!(maker.join().unwrap(), Some(1), "slice 1 is paid on the new link");
        assert!(lock(&st).released >= 1);
    }
}
