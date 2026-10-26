//! The hasher's side: a Stratum V1 endpoint for the hasher's miners, and any number of rentals.
//!
//! Every miner the hasher's app serves is a unit, named by its worker name (`mining.authorize`).
//! A miner not in a rental hashes for the hasher's own pool or DATUM Gateway, the fallback: the
//! hasher points each miner at the app once and never changes its settings again. A rental takes
//! whole miners, so four miners can go to four buyers, two to each of two, or three to one buyer
//! while the fourth stays on the fallback. Each rental has its own link, meter, receipts and
//! tickets; when one ends, for whatever reason, only its miners go back to the fallback.
//!
//! Moving a miner between the fallback and a rental (either way):
//! * a miner that asked for `mining.set_extranonce` keeps its connection. The app opens the new
//!   upstream session itself (the miner's own subscribe and authorize, replayed), hands the miner
//!   the new extranonce, and sends the new jobs with `clean_jobs` set. Shares for the old
//!   upstream's jobs still go to the old upstream, which is kept for a short drain;
//! * any other miner is asked to connect again (`client.reconnect` to the app's own address) and
//!   placed by its worker name when it does.
//!
//! Within a rental the hasher meters the buyer's verdicts itself, takes a locked ticket before
//! serving a slice (the lab's rail over the link), and ends the rental when a finished slice is
//! not paid within the grace time, or as soon as a second slice finishes unpaid. When the buyer
//! ends it, the buyer says how many slices it counted, and only slices both sides counted are
//! billed.

use crate::link::{self, Sender};
use crate::listing::Capacity;
use crate::meter::{Event, Meter, Receipt};
use crate::msg::{Msg, Terms};
use crate::rail::{sha256, Hash, SellerRail};
use crate::{now_ms, sv1};
use secp256k1::{PublicKey, SecretKey};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct Config {
    /// Where the hasher's miners connect (Stratum V1, the hasher's LAN).
    pub miners: String,
    /// Where buyers' apps connect (the link).
    pub link: String,
    pub key: SecretKey,
    pub terms: Terms,
    /// A JSON report, rewritten every second and at the end.
    pub report: Option<PathBuf>,
    /// Where the hasher's gateway passes on paid slices (`POST <route>/<rental>/<slice>`). With
    /// it, slices are paid through the gateway's tickets; without it, over the link (the lab's
    /// stand-in rail), and a rental is served only once its first ticket is locked.
    pub slices: Option<String>,
    /// The hasher's own pool or DATUM Gateway (Stratum V1): every miner not in a rental hashes
    /// there. Without one (the lab), a miner waits for a rental and is let go when it ends.
    pub fallback: Option<String>,
    /// At most this many miners rented out at once (`None`: all of them).
    pub rentable: Option<u32>,
}

/// A rental's miners make tickets for one seller's rail each: one per rental.
pub type Rails = Box<dyn FnMut() -> Box<dyn SellerRail> + Send>;

const PING_EVERY: Duration = Duration::from_secs(15);
const QUIET_LIMIT: Duration = Duration::from_secs(60);
const RATE_WINDOW: Duration = Duration::from_secs(60);
const LOCK_WAIT: Duration = Duration::from_secs(10);
/// How long a miner's connection waits for its worker name before it is placed by address.
const AUTHORIZE_WAIT: Duration = Duration::from_secs(5);
/// An old upstream session is kept this long after a switch, for shares of its jobs.
const DRAIN: Duration = Duration::from_secs(10);
/// After `client.reconnect`, the miner's connection is closed this long later if still open.
const RECONNECT_CLOSE: Duration = Duration::from_millis(1500);
const JOBS_KEPT: usize = 64;
const FINISHED_KEPT: usize = 50;

enum SlotKind {
    Fallback { w: TcpStream },
    Rental { rental: String, chan: u32 },
}

/// One upstream session a miner's connection uses: the fallback, or a channel of a rental.
struct Slot {
    kind: SlotKind,
    /// Job ids this upstream sent: a share for one of them goes back to it.
    jobs: VecDeque<String>,
    /// Being let go after a switch: verdicts still reach the miner, new jobs do not.
    draining_until: Option<Instant>,
    /// Ids of the requests the app made itself on this session (their answers stay here).
    swallow: Vec<String>,
    /// The app's own subscribe: its answer becomes `mining.set_extranonce` for the miner.
    sub_id: Option<String>,
    /// The next job is sent with `clean_jobs`: the miner drops the old upstream's work.
    fresh: bool,
}

struct Conn {
    unit: Option<String>,
    peer: String,
    w: TcpStream,
    /// The address the miner dialled: where `client.reconnect` sends it.
    local: String,
    slots: BTreeMap<u64, Slot>,
    active: Option<u64>,
    /// Lines from the miner before any upstream took them.
    held: Vec<String>,
    subscribe: Option<Value>,
    authorize: Option<Value>,
    configure: Option<Value>,
    /// The miner asked for `mining.set_extranonce`.
    extranonce: bool,
    /// Verdicts of the fallback (the miner's hashrate while it is not rented).
    fb_meter: Meter,
    /// Asked to connect again: closed at this time if still open.
    close_at: Option<Instant>,
    /// A placement or switch is under way for this connection.
    busy: bool,
}

#[derive(Default)]
struct Unit {
    peer: String,
    rental: Option<String>,
    conn: Option<u64>,
    /// Accepted work, fallback and rentals together (for the hashrate).
    work: u128,
    samples: VecDeque<(Instant, u128)>,
    earned_msat: u64,
    methods: BTreeMap<String, u64>,
    seen_ms: u64,
}

impl Unit {
    fn hashrate(&self) -> f64 {
        match (self.samples.front(), self.samples.back()) {
            (Some((t0, w0)), Some((t1, w1))) if t1 > t0 => (w1 - w0) as f64 / (*t1 - *t0).as_secs_f64(),
            _ => 0.0,
        }
    }
}

struct Rental {
    terms: Terms,
    id: String,
    buyer: PublicKey,
    tx: Sender,
    /// Miners asked for (0: as many as are free).
    want: u32,
    units: BTreeSet<String>,
    /// Channel → (connection, slot) for every miner session of this rental, until the buyer's
    /// `shut` for it (its last verdict).
    chans: HashMap<u32, (u64, u64)>,
    chan_unit: HashMap<u32, String>,
    meter: Meter,
    unit_work: BTreeMap<String, u128>,
    locks: BTreeMap<u64, Hash>,
    paid: u64,
    /// Own meter's work and time when each slice finished (index = slice - 1).
    done: Vec<(u128, u64)>,
    receipts: Vec<Value>,
    agree: u64,
    disagree: u64,
    due_since: Option<Instant>,
    lock_missing_since: Option<Instant>,
    /// Miners are served (with the lab's rail, once the first ticket is locked).
    ready: bool,
    /// The buyer ended it: billed are the slices both sides counted; payments for them may still
    /// arrive until the deadline.
    closing: Option<(Instant, u64, String)>,
    stopped: Option<Value>,
    last_heard: Instant,
    last_ping: Instant,
    ping_n: u64,
    rate: VecDeque<(Instant, u128)>,
    events: Vec<Value>,
    started_ms: u64,
    rail: Box<dyn SellerRail>,
}

impl Rental {
    fn note(&mut self, ev: Value) {
        if self.events.len() < 10_000 {
            self.events.push(ev);
        }
    }

    fn completed(&self) -> u64 {
        (self.meter.work / self.terms.slice_work) as u64
    }

    fn hashrate(&mut self) -> f64 {
        let now = Instant::now();
        self.rate.push_back((now, self.meter.work));
        while self.rate.front().is_some_and(|(t, _)| now - *t > Duration::from_secs(30)) {
            self.rate.pop_front();
        }
        match (self.rate.front(), self.rate.back()) {
            (Some((t0, w0)), Some((t1, w1))) if t1 > t0 => (w1 - w0) as f64 / (*t1 - *t0).as_secs_f64(),
            _ => 0.0,
        }
    }

    /// What each of its miners earned so far: the paid slices' price, shared by accepted work.
    fn earnings(&self) -> BTreeMap<String, u64> {
        let total: u128 = self.unit_work.values().sum();
        let paid_msat = self.paid as u128 * self.terms.price_msat as u128;
        self.unit_work
            .iter()
            .map(|(u, w)| (u.clone(), (paid_msat * w).checked_div(total).unwrap_or(0) as u64))
            .collect()
    }

    fn report(&self) -> Value {
        json!({
            "role": "hasher", "rental": self.id, "buyer": hex::encode(self.buyer.serialize()),
            "terms": self.terms.to_json(), "meter": self.meter.to_json(),
            "miners": self.units.iter().collect::<Vec<_>>(), "want": self.want, "startedMs": self.started_ms,
            "unitWork": self.unit_work.iter().map(|(u, w)| (u.clone(), Value::from(w.to_string()))).collect::<serde_json::Map<_, _>>(),
            "slicesDone": self.done.iter().map(|(w, t)| json!({"work": w.to_string(), "atMs": t})).collect::<Vec<_>>(),
            "paid": self.paid, "earnedMsat": self.paid * self.terms.price_msat,
            "receiptsAgree": self.agree, "receiptsDisagree": self.disagree,
            "receipts": self.receipts, "stopped": self.stopped, "closing": self.closing.as_ref().map(|c| c.2.clone()),
            "events": self.events,
        })
    }
}

struct Hub {
    terms: Terms,
    fallback: Option<String>,
    rentable: Option<u32>,
    /// Rentals are taken (off: miners all hash for the fallback, new buyers are told so).
    open: bool,
    over_link: bool,
    units: BTreeMap<String, Unit>,
    conns: HashMap<u64, Conn>,
    rentals: BTreeMap<String, Rental>,
    finished: VecDeque<Value>,
    next: u64,
    rails: Rails,
    methods: BTreeMap<String, u64>,
    shutdown: bool,
}

type Shared = Arc<Mutex<Hub>>;

fn lock(h: &Mutex<Hub>) -> std::sync::MutexGuard<'_, Hub> {
    h.lock().unwrap_or_else(|p| p.into_inner())
}

fn write_report(path: &Option<PathBuf>, v: &Value) {
    if let Some(p) = path {
        let tmp = p.with_extension("tmp");
        if std::fs::write(&tmp, serde_json::to_vec_pretty(v).unwrap_or_default()).is_ok() {
            let _ = std::fs::rename(&tmp, p);
        }
    }
}

fn send_line(w: &mut TcpStream, line: &str) -> bool {
    w.write_all(format!("{}\n", line.trim_end()).as_bytes()).is_ok()
}

impl Hub {
    fn rented(&self) -> u32 {
        self.units.values().filter(|u| u.rental.is_some()).count() as u32
    }

    fn capacity(&self) -> Capacity {
        let live: Vec<&Unit> = self.units.values().filter(|u| u.conn.is_some()).collect();
        let cap = self.rentable.unwrap_or(u32::MAX);
        let room = cap.saturating_sub(self.rented()) as usize;
        let mut free: Vec<&&Unit> = live.iter().filter(|u| u.rental.is_none()).collect();
        free.truncate(if self.open { room } else { 0 });
        Capacity {
            miners: live.len() as u32,
            free_miners: free.len() as u32,
            free_hs: free.iter().map(|u| u.hashrate() as u64).sum(),
        }
    }

    /// Where a unit's miner should hash now: a ready rental, or the fallback (`None`).
    fn target(&self, unit: &str) -> Option<String> {
        let r = self.units.get(unit)?.rental.as_ref()?;
        self.rentals.get(r).filter(|r| r.ready && r.closing.is_none() && r.stopped.is_none()).map(|r| r.id.clone())
    }

    fn slot_rental(&self, conn: u64, slot: u64) -> Option<String> {
        match &self.conns.get(&conn)?.slots.get(&slot)?.kind {
            SlotKind::Rental { rental, .. } => Some(rental.clone()),
            SlotKind::Fallback { .. } => None,
        }
    }

    /// Free miners, taken by rentals that want more, oldest rental first.
    fn allocate(&mut self) -> bool {
        if !self.open {
            return false;
        }
        let mut changed = false;
        let cap = self.rentable.unwrap_or(u32::MAX);
        let ids: Vec<String> = self.rentals.iter().filter(|(_, r)| r.closing.is_none() && r.stopped.is_none()).map(|(k, _)| k.clone()).collect();
        let mut order: Vec<(u64, String)> = ids.into_iter().map(|k| (self.rentals[&k].started_ms, k)).collect();
        order.sort();
        for (_, id) in order {
            loop {
                if self.rented() >= cap {
                    return changed;
                }
                let r = &self.rentals[&id];
                if r.want > 0 && r.units.len() as u32 >= r.want {
                    break;
                }
                let free = self.units.iter().find(|(_, u)| u.rental.is_none() && u.conn.is_some_and(|c| self.conns.get(&c).is_some_and(|c| c.close_at.is_none())))
                    .map(|(k, _)| k.clone());
                let Some(name) = free else { break };
                self.units.get_mut(&name).unwrap().rental = Some(id.clone());
                let r = self.rentals.get_mut(&id).unwrap();
                r.units.insert(name.clone());
                r.note(json!({"ev": "miner taken", "miner": name, "atMs": now_ms()}));
                changed = true;
            }
        }
        changed
    }

    /// A rental ends: its miners go back to the fallback, its report is kept.
    fn finish(&mut self, id: &str, reason: &str, tell: bool) {
        let Some(mut r) = self.rentals.remove(id) else { return };
        let s = r.terms.slice_work;
        let billable = r.closing.as_ref().map(|c| c.1).unwrap_or(r.done.len() as u64);
        let unpaid = (billable.saturating_sub(r.paid)) as f64;
        let unbilled = (r.done.len() as u64).saturating_sub(billable);
        r.stopped = Some(json!({
            "reason": reason, "atMs": now_ms(), "work": r.meter.work.to_string(), "paid": r.paid,
            "unpaidWork": r.meter.work.saturating_sub(r.paid as u128 * s).to_string(),
            "unpaidSlices": r.meter.work.saturating_sub(r.paid as u128 * s) as f64 / s as f64,
            "billedSlices": billable, "unpaidBilledSlices": unpaid, "unbilledSlices": unbilled,
        }));
        if tell {
            let _ = r.tx.send(&Msg::Close { reason: reason.to_string(), slices: None });
        }
        r.tx.shutdown();
        for (u, e) in r.earnings() {
            if let Some(unit) = self.units.get_mut(&u) {
                unit.earned_msat += e;
            }
        }
        for u in &r.units {
            if let Some(unit) = self.units.get_mut(u) {
                if unit.rental.as_deref() == Some(id) {
                    unit.rental = None;
                }
            }
        }
        if self.finished.len() == FINISHED_KEPT {
            self.finished.pop_front();
        }
        self.finished.push_back(r.report());
    }

    /// The rental's own reasons to end: no payment, no ticket, a quiet link.
    fn stop_unpaid(&mut self, id: &str, reason: &str) {
        self.finish(id, reason, true);
    }
}

/// The hasher's app: running until [`Hasher::shutdown`].
pub struct Hasher {
    hub: Shared,
    report: Option<PathBuf>,
    down: Arc<AtomicBool>,
}

impl Hasher {
    /// Listen for miners, buyers and (with `slices`) paid slices, and serve until shut down.
    pub fn start(cfg: Config, rails: Rails) -> Result<Hasher, String> {
        let link_l = TcpListener::bind(&cfg.link).map_err(|e| format!("link listen {}: {e}", cfg.link))?;
        let miners_l = TcpListener::bind(&cfg.miners).map_err(|e| format!("miner listen {}: {e}", cfg.miners))?;
        let slices_l = match &cfg.slices {
            Some(a) => Some(TcpListener::bind(a).map_err(|e| format!("slice listen {a}: {e}"))?),
            None => None,
        };
        eprintln!(
            "hasher: link {} (key {}), miners {}, fallback {}",
            cfg.link,
            hex::encode(PublicKey::from_secret_key(secp256k1::SECP256K1, &cfg.key).serialize()),
            cfg.miners,
            cfg.fallback.as_deref().unwrap_or("none")
        );
        let hub: Shared = Arc::new(Mutex::new(Hub {
            terms: cfg.terms.clone(),
            fallback: cfg.fallback.clone(),
            rentable: cfg.rentable,
            open: true,
            over_link: cfg.slices.is_none(),
            units: BTreeMap::new(),
            conns: HashMap::new(),
            rentals: BTreeMap::new(),
            finished: VecDeque::new(),
            next: 1,
            rails,
            methods: BTreeMap::new(),
            shutdown: false,
        }));
        let down = Arc::new(AtomicBool::new(false));
        if let Some(l) = slices_l {
            let (h, d) = (hub.clone(), down.clone());
            std::thread::spawn(move || serve_slices(l, h, d));
        }
        {
            let (h, d) = (hub.clone(), down.clone());
            std::thread::spawn(move || {
                for conn in miners_l.incoming() {
                    if d.load(Ordering::Relaxed) {
                        return;
                    }
                    let Ok(conn) = conn else { continue };
                    let h = h.clone();
                    std::thread::spawn(move || serve_miner(conn, h));
                }
            });
        }
        {
            let (h, d, key) = (hub.clone(), down.clone(), cfg.key);
            std::thread::spawn(move || {
                for s in link_l.incoming() {
                    if d.load(Ordering::Relaxed) {
                        return;
                    }
                    let Ok(s) = s else { continue };
                    let h = h.clone();
                    std::thread::spawn(move || serve_buyer(s, key, h));
                }
            });
        }
        {
            let (h, d, report) = (hub.clone(), down.clone(), cfg.report.clone());
            std::thread::spawn(move || ticker(h, d, report));
        }
        Ok(Hasher { hub, report: cfg.report, down })
    }

    /// Everything: the miners, the rentals going on and the last ones that ended.
    pub fn status(&self) -> Value {
        status(&lock(&self.hub))
    }

    pub fn capacity(&self) -> Capacity {
        lock(&self.hub).capacity()
    }

    /// End a rental now, as the hasher (the buyer is told; its miners go back to the fallback).
    pub fn stop_rental(&self, id: &str) -> bool {
        let mut g = lock(&self.hub);
        if !g.rentals.contains_key(id) {
            return false;
        }
        g.finish(id, "stopped by the hasher", true);
        true
    }

    /// New terms for rentals made from now on (a rental keeps the terms it was made with).
    pub fn set_terms(&self, t: Terms) {
        lock(&self.hub).terms = t;
    }

    pub fn set_fallback(&self, f: Option<String>) {
        lock(&self.hub).fallback = f;
    }

    pub fn set_rentable(&self, n: Option<u32>) {
        lock(&self.hub).rentable = n;
    }

    /// Take rentals or not. Off: rentals going on end, every miner hashes for the fallback.
    pub fn set_open(&self, open: bool) {
        let mut g = lock(&self.hub);
        g.open = open;
        if !open {
            let ids: Vec<String> = g.rentals.keys().cloned().collect();
            for id in ids {
                g.finish(&id, "the hasher stopped renting", true);
            }
        }
    }

    /// Reports of rentals that ended, oldest first.
    pub fn finished(&self) -> Vec<Value> {
        lock(&self.hub).finished.iter().cloned().collect()
    }

    /// Wait until `n` rentals have ended (or `timeout`); their reports.
    pub fn wait_finished(&self, n: usize, timeout: Duration) -> Vec<Value> {
        let t0 = Instant::now();
        loop {
            let f = self.finished();
            if f.len() >= n || t0.elapsed() > timeout {
                return f;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// End every rental, let every miner go, and stop.
    pub fn shutdown(&self) {
        self.down.store(true, Ordering::Relaxed);
        let mut g = lock(&self.hub);
        g.shutdown = true;
        let ids: Vec<String> = g.rentals.keys().cloned().collect();
        for id in ids {
            g.finish(&id, "the hasher's app stopped", true);
        }
        for (_, c) in g.conns.drain() {
            let _ = c.w.shutdown(std::net::Shutdown::Both);
            for (_, s) in c.slots {
                if let SlotKind::Fallback { w } = s.kind {
                    let _ = w.shutdown(std::net::Shutdown::Both);
                }
            }
        }
        write_report(&self.report, &status(&g));
    }
}

/// Serve one rental: wait for the first buyer, serve the miners until that rental ends, and
/// return its report (the lab's single rental, without a fallback).
pub fn run(cfg: Config, rail: Box<dyn SellerRail>) -> Result<Value, String> {
    let mut first = Some(rail);
    let h = Hasher::start(cfg, Box::new(move || first.take().unwrap_or_else(|| Box::<crate::rail::LabSeller>::default())))?;
    let r = loop {
        if let Some(r) = h.finished().into_iter().next() {
            break r;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    h.shutdown();
    Ok(r)
}

fn status(g: &Hub) -> Value {
    let mut live_earn: BTreeMap<String, u64> = BTreeMap::new();
    for r in g.rentals.values() {
        for (u, e) in r.earnings() {
            *live_earn.entry(u).or_default() += e;
        }
    }
    let miners: Vec<Value> = g
        .units
        .iter()
        .map(|(name, u)| {
            json!({
                "name": name, "peer": u.peer, "connected": u.conn.is_some(), "hashrateHs": u.hashrate(),
                "rentedTo": u.rental, "earnedMsat": u.earned_msat + live_earn.get(name).copied().unwrap_or(0),
                "work": u.work.to_string(), "seenMs": u.seen_ms, "methods": u.methods,
            })
        })
        .collect();
    let c = g.capacity();
    json!({
        "role": "hasher", "open": g.open, "fallback": g.fallback, "rentable": g.rentable, "terms": g.terms.to_json(),
        "capacity": {"miners": c.miners, "freeMiners": c.free_miners, "freeHs": c.free_hs.to_string()},
        "miners": miners, "rentals": g.rentals.values().map(Rental::report).collect::<Vec<_>>(),
        "finished": g.finished, "methods": g.methods,
    })
}

// --- buyers ------------------------------------------------------------------------------------

fn serve_buyer(s: TcpStream, key: SecretKey, hub: Shared) {
    let Ok(link::Link { tx, mut rx, remote }) = link::answer(s, key) else { return };
    let (id, want, terms) = match rx.recv() {
        Ok(Some(Msg::Hello { rental, terms, miners, .. })) => {
            let g = lock(&hub);
            let why = if !g.open {
                Some("this hasher is not renting out miners now".to_string())
            } else if terms != g.terms {
                Some("terms differ from the listing".to_string())
            } else if g.rentals.contains_key(&rental) || g.finished.iter().any(|f| f["rental"] == rental.as_str()) {
                Some("that rental id is taken".to_string())
            } else {
                // a hasher whose miners are all rented says so; one with no miners yet waits
                let c = g.capacity();
                (c.miners > 0 && c.free_miners == 0).then(|| "no miners free now".to_string())
            };
            if let Some(why) = why {
                let _ = tx.send(&Msg::Close { reason: why, slices: None });
                tx.shutdown();
                return;
            }
            (rental, miners, terms)
        }
        _ => {
            tx.shutdown();
            return;
        }
    };
    if tx.send(&Msg::Welcome { rental: id.clone(), terms_hash: hex::encode(terms.hash()) }).is_err() {
        return;
    }
    eprintln!("hasher: rental {id} from buyer {} ({} miners asked)", hex::encode(remote.serialize()), if want == 0 { "any".into() } else { want.to_string() });
    {
        let mut g = lock(&hub);
        let rail = (g.rails)();
        let ready = !g.over_link;
        g.rentals.insert(id.clone(), Rental {
            terms,
            id: id.clone(),
            buyer: remote,
            tx: tx.clone(),
            want,
            units: BTreeSet::new(),
            chans: HashMap::new(),
            chan_unit: HashMap::new(),
            meter: Meter::default(),
            unit_work: BTreeMap::new(),
            locks: BTreeMap::new(),
            paid: 0,
            done: Vec::new(),
            receipts: Vec::new(),
            agree: 0,
            disagree: 0,
            due_since: None,
            lock_missing_since: None,
            ready,
            closing: None,
            stopped: None,
            last_heard: Instant::now(),
            last_ping: Instant::now(),
            ping_n: 0,
            rate: VecDeque::new(),
            events: Vec::new(),
            started_ms: now_ms(),
            rail,
        });
        g.allocate();
    }
    loop {
        let m = match rx.recv() {
            Ok(Some(m)) => m,
            Ok(None) => continue,
            Err(e) => {
                let mut g = lock(&hub);
                if g.rentals.get(&id).is_some_and(|r| r.closing.is_none()) {
                    g.finish(&id, &format!("link lost: {e}"), false);
                }
                return;
            }
        };
        let mut g = lock(&hub);
        let Some(r) = g.rentals.get_mut(&id) else { return };
        r.last_heard = Instant::now();
        match m {
            Msg::Down { chan, line } => {
                let Some(v) = sv1::parse(&line) else { continue };
                let ev = r.meter.down(chan, &v);
                if let Some(Event::Accepted(w)) = ev {
                    let u = r.chan_unit.get(&chan).cloned();
                    if let Some(u) = &u {
                        *r.unit_work.entry(u.clone()).or_default() += w;
                    }
                    if let Some(unit) = u.and_then(|u| g.units.get_mut(&u)) {
                        unit.work += w;
                    }
                    let r = g.rentals.get_mut(&id).unwrap();
                    let s = r.terms.slice_work;
                    while r.meter.work >= (r.done.len() as u128 + 1) * s {
                        let w = r.meter.work;
                        r.done.push((w, now_ms()));
                    }
                    if r.closing.is_none() {
                        if r.completed() > r.paid && r.due_since.is_none() {
                            r.due_since = Some(Instant::now());
                        }
                        if r.completed() >= r.paid + 2 {
                            g.stop_unpaid(&id, "unpaid");
                            return;
                        }
                    }
                }
                let r = g.rentals.get_mut(&id).unwrap();
                if let Some(&(conn, slot)) = r.chans.get(&chan) {
                    down_line(&mut g, conn, slot, &v, &line);
                }
            }
            Msg::Lock { slice, hash } => {
                let Some(h) = hex::decode(&hash).ok().and_then(|h| Hash::try_from(h).ok()) else { continue };
                let price = r.terms.price_msat;
                if slice > r.paid && r.rail.held(slice, &h, price) {
                    r.locks.insert(slice, h);
                    if r.locks.contains_key(&(r.paid + 1)) {
                        r.lock_missing_since = None;
                        r.ready = true;
                    }
                    r.note(json!({"ev": "locked", "slice": slice, "atMs": now_ms()}));
                }
            }
            Msg::Pay { slice, preimage, receipt } => {
                let ok = pay(r, slice, &preimage, &receipt);
                r.note(json!({"ev": "pay", "slice": slice, "ok": ok.is_ok(), "why": ok.as_ref().err(), "atMs": now_ms()}));
            }
            Msg::Shut { chan } => {
                // the buyer's last verdict for this channel has been read: both meters let it go here
                r.meter.close(chan);
                r.chan_unit.remove(&chan);
                if let Some((conn, slot)) = r.chans.remove(&chan) {
                    drop_slot(&mut g, conn, slot);
                }
            }
            Msg::Ping { n } => {
                let _ = r.tx.send(&Msg::Pong { n });
            }
            Msg::Close { reason, slices } => {
                // only slices both sides counted are billed; payments for them may still be on the way
                let billable = slices.map(|n| n.min(r.done.len() as u64)).unwrap_or(r.paid);
                r.note(json!({"ev": "buyer closed", "reason": reason, "buyerSlices": slices, "billable": billable, "atMs": now_ms()}));
                let grace = Duration::from_millis(r.terms.grace_ms);
                r.closing = Some((Instant::now() + grace, billable, format!("buyer closed: {reason}")));
                r.due_since = None;
                let units: Vec<String> = r.units.iter().cloned().collect();
                for u in units {
                    if let Some(unit) = g.units.get_mut(&u) {
                        if unit.rental.as_deref() == Some(id.as_str()) {
                            unit.rental = None;
                        }
                    }
                }
                return;
            }
            _ => {}
        }
    }
}

/// A slice paid over the link (the lab's rail): the preimage of the ticket locked for it.
fn pay(r: &mut Rental, slice: u64, preimage: &str, receipt: &Value) -> Result<(), String> {
    if slice != r.paid + 1 {
        return Err(format!("expected slice {}", r.paid + 1));
    }
    let p: [u8; 32] = hex::decode(preimage).ok().and_then(|p| p.try_into().ok()).ok_or("bad preimage")?;
    if r.locks.get(&slice) != Some(&sha256(&p)) {
        return Err("preimage does not match the locked ticket".into());
    }
    check_receipt(r, slice, receipt)?;
    r.rail.settle(slice, &p)?;
    r.locks.remove(&slice);
    credit(r, slice, receipt);
    r.lock_missing_since = (!r.locks.contains_key(&(r.paid + 1))).then(Instant::now);
    Ok(())
}

fn check_receipt(r: &Rental, slice: u64, receipt: &Value) -> Result<(), String> {
    if slice != r.paid + 1 {
        return Err(format!("expected slice {}", r.paid + 1));
    }
    let rc = Receipt::verify(receipt, &r.buyer).ok_or("bad receipt signature")?;
    if rc.rental != r.id || rc.slice != slice {
        return Err("receipt for another rental or slice".into());
    }
    if r.done.len() < slice as usize {
        return Err(format!("slice {slice} is not done by this side's count"));
    }
    if let Some((_, billable, _)) = &r.closing {
        if slice > *billable {
            return Err(format!("slice {slice} is past the {billable} the buyer counted"));
        }
    }
    Ok(())
}

fn credit(r: &mut Rental, slice: u64, receipt: &Value) {
    let own = r.done.get(slice as usize - 1).map(|(w, _)| *w);
    if own.map(|w| w.to_string()).as_deref() == receipt.get("work").and_then(Value::as_str) {
        r.agree += 1;
    } else {
        r.disagree += 1;
    }
    r.receipts.push(receipt.clone());
    r.paid = slice;
    r.due_since = (r.closing.is_none() && r.completed() > r.paid).then(Instant::now);
}

// --- the ticker --------------------------------------------------------------------------------

fn ticker(hub: Shared, down: Arc<AtomicBool>, report: Option<PathBuf>) {
    let mut last_rate = Instant::now();
    let mut last_report = Instant::now();
    loop {
        std::thread::sleep(Duration::from_millis(200));
        if down.load(Ordering::Relaxed) {
            return;
        }
        let mut switches = Vec::new();
        {
            let mut g = lock(&hub);
            // each rental's own clock
            let ids: Vec<String> = g.rentals.keys().cloned().collect();
            for id in ids {
                let r = g.rentals.get_mut(&id).unwrap();
                if let Some((deadline, billable, why)) = r.closing.clone() {
                    if r.paid >= billable || Instant::now() > deadline {
                        g.finish(&id, &why, false);
                    }
                    continue;
                }
                let grace = Duration::from_millis(r.terms.grace_ms);
                let why = if r.due_since.is_some_and(|t| t.elapsed() > grace) {
                    Some("unpaid")
                } else if r.lock_missing_since.is_some_and(|t| t.elapsed() > grace) {
                    Some("no ticket locked")
                } else if r.last_heard.elapsed() > QUIET_LIMIT {
                    Some("link quiet")
                } else {
                    None
                };
                if let Some(why) = why {
                    g.stop_unpaid(&id, why);
                    continue;
                }
                let r = g.rentals.get_mut(&id).unwrap();
                if r.last_ping.elapsed() > PING_EVERY {
                    r.last_ping = Instant::now();
                    r.ping_n += 1;
                    let _ = r.tx.send(&Msg::Ping { n: r.ping_n });
                }
            }
            g.allocate();
            // every miner where it belongs
            let now = Instant::now();
            let conn_ids: Vec<u64> = g.conns.keys().copied().collect();
            for c in conn_ids {
                let conn = g.conns.get(&c).unwrap();
                if conn.close_at.is_some_and(|t| now > t) {
                    let _ = conn.w.shutdown(std::net::Shutdown::Both);
                    continue;
                }
                if conn.busy || conn.close_at.is_some() {
                    continue;
                }
                let Some(unit) = conn.unit.clone() else { continue };
                let Some(active) = conn.active else { continue };
                let want = g.target(&unit);
                let have = g.slot_rental(c, active);
                if want == have {
                    continue;
                }
                if want.is_some() || g.fallback.is_some() {
                    g.conns.get_mut(&c).unwrap().busy = true;
                    switches.push((c, want));
                } else {
                    // no fallback (the lab): a miner whose rental ended is let go
                    let conn = g.conns.get(&c).unwrap();
                    let _ = conn.w.shutdown(std::net::Shutdown::Both);
                }
            }
            // old upstream sessions let go after their drain
            for c in g.conns.keys().copied().collect::<Vec<_>>() {
                let drained: Vec<u64> =
                    g.conns[&c].slots.iter().filter(|(_, s)| s.draining_until.is_some_and(|t| now > t)).map(|(k, _)| *k).collect();
                for s in drained {
                    release_slot(&mut g, c, s);
                }
            }
            // the hashrate of each miner
            if last_rate.elapsed() > Duration::from_secs(5) {
                last_rate = Instant::now();
                for u in g.units.values_mut() {
                    let w = u.work;
                    u.samples.push_back((now, w));
                    while u.samples.front().is_some_and(|(t, _)| now - *t > RATE_WINDOW) {
                        u.samples.pop_front();
                    }
                }
                let ids: Vec<String> = g.rentals.keys().cloned().collect();
                for id in ids {
                    let r = g.rentals.get_mut(&id).unwrap();
                    let hs = r.hashrate();
                    let miners = r.chans.len() as u32;
                    let _ = r.tx.send(&Msg::Rate { hs, miners });
                }
            }
            if last_report.elapsed() > Duration::from_secs(1) {
                last_report = Instant::now();
                write_report(&report, &status(&g));
            }
        }
        for (c, target) in switches {
            let h = hub.clone();
            std::thread::spawn(move || switch(&h, c, target));
        }
    }
}

// --- miners ------------------------------------------------------------------------------------

fn serve_miner(conn: TcpStream, hub: Shared) {
    let peer = conn.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
    let local = conn.local_addr().map(|a| a.to_string()).unwrap_or_default();
    let Ok(w) = conn.try_clone() else { return };
    let _ = conn.set_nodelay(true);
    let id = {
        let mut g = lock(&hub);
        if g.shutdown {
            return;
        }
        let id = g.next;
        g.next += 1;
        g.conns.insert(id, Conn {
            unit: None,
            peer: peer.clone(),
            w,
            local,
            slots: BTreeMap::new(),
            active: None,
            held: Vec::new(),
            subscribe: None,
            authorize: None,
            configure: None,
            extranonce: false,
            fb_meter: Meter::default(),
            close_at: None,
            busy: true,
        });
        id
    };
    {
        let h = hub.clone();
        std::thread::spawn(move || place(&h, id));
    }
    let mut r = BufReader::new(conn);
    let mut line = String::new();
    loop {
        line.clear();
        match r.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let Some(v) = sv1::parse(&line) else { continue };
        let mut g = lock(&hub);
        if !up_line(&mut g, id, &v, line.trim_end()) {
            break;
        }
    }
    let mut g = lock(&hub);
    gone(&mut g, id);
}

/// A line from a miner: remembered (subscribe, authorize, configure), then sent to the upstream
/// whose job it names, or the active one, or held until one is there.
fn up_line(g: &mut Hub, id: u64, v: &Value, line: &str) -> bool {
    let Some(c) = g.conns.get_mut(&id) else { return false };
    match sv1::method(v) {
        Some("mining.subscribe") => c.subscribe = Some(v.clone()),
        Some("mining.authorize") => c.authorize = Some(v.clone()),
        Some("mining.configure") => c.configure = Some(v.clone()),
        Some("mining.extranonce.subscribe") => c.extranonce = true,
        _ => {}
    }
    if let Some(m) = sv1::method(v) {
        *g.methods.entry(m.to_string()).or_default() += 1;
        let c = g.conns.get(&id).unwrap();
        if let Some(u) = c.unit.clone() {
            if let Some(unit) = g.units.get_mut(&u) {
                *unit.methods.entry(m.to_string()).or_default() += 1;
                unit.seen_ms = now_ms();
            }
        }
    }
    let c = g.conns.get_mut(&id).unwrap();
    let slot = match sv1::submit_job(v) {
        Some(job) => c.slots.iter().find(|(_, s)| s.jobs.contains(&job)).map(|(k, _)| *k).or(c.active),
        None => c.active,
    };
    let Some(slot) = slot else {
        if c.held.len() < 64 {
            c.held.push(line.to_string());
        }
        return true;
    };
    to_slot(g, id, slot, v, line)
}

fn to_slot(g: &mut Hub, id: u64, slot: u64, v: &Value, line: &str) -> bool {
    let Some(c) = g.conns.get_mut(&id) else { return false };
    let Some(s) = c.slots.get_mut(&slot) else { return true };
    match &mut s.kind {
        SlotKind::Fallback { w } => {
            c.fb_meter.up(slot as u32, v);
            if !send_line(w, line) {
                // the fallback went away: place the miner again
                if c.active == Some(slot) {
                    c.active = None;
                }
                c.slots.remove(&slot);
            }
            true
        }
        SlotKind::Rental { rental, chan } => {
            let (rental, chan) = (rental.clone(), *chan);
            if let Some(r) = g.rentals.get_mut(&rental) {
                r.meter.up(chan, v);
                let _ = r.tx.send(&Msg::Up { chan, line: line.to_string() });
            }
            true
        }
    }
}

/// A line from one of a miner's upstreams.
fn down_line(g: &mut Hub, id: u64, slot: u64, v: &Value, line: &str) {
    let Some(c) = g.conns.get_mut(&id) else { return };
    let Some(s) = c.slots.get_mut(&slot) else { return };
    if let Some(key) = sv1::id_key(v) {
        if s.swallow.contains(&key) {
            if s.sub_id.as_deref() == Some(key.as_str()) {
                // the new session's extranonce, for the miner
                let res = v.get("result");
                let en1 = res.and_then(|r| r.get(1)).and_then(Value::as_str);
                let size = res.and_then(|r| r.get(2)).and_then(Value::as_u64);
                if let (Some(en1), Some(size)) = (en1, size) {
                    let set = json!({"id": null, "method": "mining.set_extranonce", "params": [en1, size]});
                    let _ = send_line(&mut c.w, &set.to_string());
                }
            }
            return;
        }
    }
    if sv1::dropped_down(v) {
        return;
    }
    let draining = s.draining_until.is_some();
    if let Some(job) = sv1::notify_job(v) {
        if draining {
            return;
        }
        if s.jobs.len() == JOBS_KEPT {
            s.jobs.pop_front();
        }
        s.jobs.push_back(job);
        if s.fresh {
            s.fresh = false;
            let mut v = v.clone();
            if let Some(p) = v.get_mut("params").and_then(Value::as_array_mut) {
                if p.len() >= 9 {
                    p[8] = Value::Bool(true);
                }
            }
            let _ = send_line(&mut c.w, &v.to_string());
            return;
        }
    } else if draining && !sv1::is_response(v) {
        return;
    }
    let _ = send_line(&mut c.w, line);
}

/// A miner's connection ended.
fn gone(g: &mut Hub, id: u64) {
    let Some(c) = g.conns.remove(&id) else { return };
    if let Some(u) = &c.unit {
        if let Some(unit) = g.units.get_mut(u) {
            if unit.conn == Some(id) {
                unit.conn = None;
            }
        }
    }
    for (_, s) in c.slots {
        match s.kind {
            SlotKind::Fallback { w } => {
                let _ = w.shutdown(std::net::Shutdown::Both);
            }
            SlotKind::Rental { rental, chan } => {
                // the buyer closes its upstream and answers with its own `shut` (its last verdict)
                if let Some(r) = g.rentals.get_mut(&rental) {
                    r.chans.remove(&chan);
                    let _ = r.tx.send(&Msg::Shut { chan });
                }
            }
        }
    }
}

/// An upstream session ended from the far side.
fn drop_slot(g: &mut Hub, id: u64, slot: u64) {
    let Some(c) = g.conns.get_mut(&id) else { return };
    if let Some(s) = c.slots.remove(&slot) {
        if let SlotKind::Fallback { w } = s.kind {
            let _ = w.shutdown(std::net::Shutdown::Both);
        }
    }
    if c.active == Some(slot) {
        // the miner's own upstream went away: the miner connects again and is placed afresh
        c.active = None;
        ask_reconnect(c);
    }
}

/// Let an upstream session go (after a switch's drain).
fn release_slot(g: &mut Hub, id: u64, slot: u64) {
    let Some(c) = g.conns.get_mut(&id) else { return };
    let Some(s) = c.slots.get_mut(&slot) else { return };
    match &s.kind {
        SlotKind::Fallback { w } => {
            let _ = w.shutdown(std::net::Shutdown::Both);
            c.slots.remove(&slot);
        }
        SlotKind::Rental { rental, chan } => {
            let (rental, chan) = (rental.clone(), *chan);
            c.slots.remove(&slot);
            // the buyer closes that upstream and answers with its own `shut`: the channel's
            // verdicts until then still count for the rental, and reach no miner
            if let Some(r) = g.rentals.get_mut(&rental) {
                r.chans.remove(&chan);
                let _ = r.tx.send(&Msg::Shut { chan });
            }
        }
    }
}

fn ask_reconnect(c: &mut Conn) {
    let (host, port) = c.local.rsplit_once(':').map(|(h, p)| (h.trim_matches(['[', ']']).to_string(), p.parse::<u64>().unwrap_or(0))).unwrap_or_default();
    let m = json!({"id": null, "method": "client.reconnect", "params": [host, port, 0]});
    let _ = send_line(&mut c.w, &m.to_string());
    c.close_at = Some(Instant::now() + RECONNECT_CLOSE);
}

/// Place a new connection: name it by its worker name, then give it its upstream.
fn place(hub: &Shared, id: u64) {
    let t0 = Instant::now();
    loop {
        {
            let mut g = lock(hub);
            let Some(c) = g.conns.get(&id) else { return };
            if c.authorize.is_some() || t0.elapsed() > AUTHORIZE_WAIT {
                let worker = c.authorize.as_ref().and_then(sv1::authorize_user).unwrap_or_else(|| c.peer.clone());
                let peer = c.peer.clone();
                // two live connections under one worker name are two miners
                let mut name = worker.clone();
                let mut n = 1;
                while g.units.get(&name).is_some_and(|u| u.conn.is_some_and(|o| o != id && g.conns.get(&o).is_some_and(|c| c.close_at.is_none()))) {
                    n += 1;
                    name = format!("{worker} #{n}");
                }
                let unit = g.units.entry(name.clone()).or_default();
                unit.conn = Some(id);
                unit.peer = peer;
                unit.seen_ms = now_ms();
                g.conns.get_mut(&id).unwrap().unit = Some(name);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    {
        let mut g = lock(hub);
        g.allocate();
    }
    // the first upstream: a ready rental, the fallback, or (the lab) a wait for a rental
    let t0 = Instant::now();
    loop {
        let (target, fallback) = {
            let g = lock(hub);
            let Some(c) = g.conns.get(&id) else { return };
            (g.target(c.unit.as_deref().unwrap_or("")), g.fallback.clone())
        };
        let ok = match (&target, &fallback) {
            (Some(r), _) => attach(hub, id, Some(r.clone()), false),
            (None, Some(_)) => attach(hub, id, None, false),
            (None, None) => {
                if t0.elapsed() > LOCK_WAIT {
                    let mut g = lock(hub);
                    if let Some(c) = g.conns.get(&id) {
                        let _ = c.w.shutdown(std::net::Shutdown::Both);
                    }
                    gone(&mut g, id);
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
                {
                    let mut g = lock(hub);
                    g.allocate();
                }
                continue;
            }
        };
        if ok {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
        if !lock(hub).conns.contains_key(&id) {
            return;
        }
    }
    if let Some(c) = lock(hub).conns.get_mut(&id) {
        c.busy = false;
    }
}

/// Give connection `id` a new upstream: a channel of `rental`, or the fallback. With `replay`
/// the app subscribes and authorizes on it itself (a switch by `mining.set_extranonce`);
/// otherwise the miner's held lines go there (a new connection). Returns whether it took.
fn attach(hub: &Shared, id: u64, rental: Option<String>, replay: bool) -> bool {
    // the fallback's connection is made outside the lock
    let fb = match &rental {
        None => {
            let Some(addr) = lock(hub).fallback.clone() else { return false };
            match TcpStream::connect(&addr) {
                Ok(s) => Some(s),
                Err(e) => {
                    eprintln!("hasher: fallback {addr}: {e}");
                    return false;
                }
            }
        }
        Some(_) => None,
    };
    let mut g = lock(hub);
    if !g.conns.contains_key(&id) {
        return false;
    }
    let slot_id = g.next;
    g.next += 1;
    let kind = match (&rental, fb) {
        (Some(r), _) => {
            let unit = g.conns[&id].unit.clone().unwrap_or_default();
            let Some(rr) = g.rentals.get_mut(r) else { return false };
            let chan = slot_id as u32;
            rr.chans.insert(chan, (id, slot_id));
            rr.chan_unit.insert(chan, unit.clone());
            rr.note(json!({"ev": "miner", "chan": chan, "miner": unit, "atMs": now_ms()}));
            if rr.tx.send(&Msg::Open { chan, worker: unit }).is_err() {
                return false;
            }
            SlotKind::Rental { rental: r.clone(), chan }
        }
        (None, Some(s)) => {
            let Ok(w) = s.try_clone() else { return false };
            let h = hub.clone();
            std::thread::spawn(move || fallback_reader(s, h, id, slot_id));
            SlotKind::Fallback { w }
        }
        (None, None) => return false,
    };
    let c = g.conns.get_mut(&id).unwrap();
    let mut slot = Slot { kind, jobs: VecDeque::new(), draining_until: None, swallow: Vec::new(), sub_id: None, fresh: replay };
    let mut lines = Vec::new();
    if replay {
        let n = slot_id;
        let with_id = |v: &Option<Value>, tag: &str, swallow: &mut Vec<String>| {
            v.as_ref().map(|v| {
                let mut v = v.clone();
                let i = format!("xh-{tag}-{n}");
                v["id"] = Value::String(i.clone());
                swallow.push(Value::String(i).to_string());
                v.to_string()
            })
        };
        if let Some(l) = with_id(&c.configure, "c", &mut slot.swallow) {
            lines.push(l);
        }
        if let Some(l) = with_id(&c.subscribe, "s", &mut slot.swallow) {
            slot.sub_id = slot.swallow.last().cloned();
            lines.push(l);
        }
        if let Some(l) = with_id(&c.authorize, "a", &mut slot.swallow) {
            lines.push(l);
        }
    } else {
        lines = std::mem::take(&mut c.held);
    }
    let old = c.active.replace(slot_id);
    c.slots.insert(slot_id, slot);
    if let Some(o) = old {
        if let Some(s) = c.slots.get_mut(&o) {
            s.draining_until = Some(Instant::now() + DRAIN);
        }
    }
    for l in lines {
        if let Some(v) = sv1::parse(&l) {
            to_slot(&mut g, id, slot_id, &v, &l);
        }
    }
    true
}

/// Move a placed connection to `target` (a rental, or the fallback).
fn switch(hub: &Shared, id: u64, target: Option<String>) {
    let ext = {
        let mut g = lock(hub);
        let Some(c) = g.conns.get_mut(&id) else { return };
        let ext = c.extranonce && c.subscribe.is_some();
        if !ext {
            // ask the miner to connect again; it is placed by its worker name when it does
            ask_reconnect(c);
            c.busy = false;
            return;
        }
        ext
    };
    let ok = ext && attach(hub, id, target, true);
    let mut g = lock(hub);
    if let Some(c) = g.conns.get_mut(&id) {
        if !ok {
            ask_reconnect(c);
        }
        c.busy = false;
    }
}

fn fallback_reader(s: TcpStream, hub: Shared, id: u64, slot: u64) {
    let mut r = BufReader::new(s);
    let mut line = String::new();
    loop {
        line.clear();
        match r.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let Some(v) = sv1::parse(&line) else { continue };
        let mut g = lock(&hub);
        let Some(c) = g.conns.get_mut(&id) else { return };
        if !c.slots.contains_key(&slot) {
            return;
        }
        if let Some(Event::Accepted(w)) = c.fb_meter.down(slot as u32, &v) {
            if let Some(u) = c.unit.clone() {
                if let Some(unit) = g.units.get_mut(&u) {
                    unit.work += w;
                }
            }
        }
        down_line(&mut g, id, slot, &v, line.trim_end());
    }
    let mut g = lock(&hub);
    drop_slot(&mut g, id, slot);
}

// --- paid slices (behind the hasher's gateway) ---------------------------------------------------

/// The hasher's paid-slice endpoint, behind its gateway: the gateway passes on only a request it
/// has been paid for, and charges it only when this answers below 400. So a slice is credited
/// here exactly when its price was taken: the body is the buyer's signed work receipt for it.
fn serve_slices(l: TcpListener, hub: Shared, down: Arc<AtomicBool>) {
    for conn in l.incoming() {
        if down.load(Ordering::Relaxed) {
            return;
        }
        let Ok(mut conn) = conn else { continue };
        let hub = hub.clone();
        std::thread::spawn(move || {
            let _ = conn.set_read_timeout(Some(Duration::from_secs(10)));
            let Some((method, path, body)) = read_request(&mut conn) else { return };
            let (code, out) = slice_request(&hub, &method, &path, &body);
            let body = out.to_string();
            let _ = conn.write_all(
                format!("HTTP/1.1 {code} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", if code == 200 { "OK" } else { "Conflict" }, body.len())
                    .as_bytes(),
            );
        });
    }
}

fn slice_request(hub: &Mutex<Hub>, method: &str, path: &str, body: &[u8]) -> (u16, Value) {
    let parts: Vec<&str> = path.split('?').next().unwrap_or("").trim_matches('/').split('/').collect();
    let (rental, slice) = match parts.as_slice() {
        [.., r, s] => (r.to_string(), s.parse::<u64>().ok()),
        _ => (String::new(), None),
    };
    let (Some(slice), "POST") = (slice, method) else {
        return (404, json!({"error": "POST <route>/<rental>/<slice>"}));
    };
    let Ok(receipt) = serde_json::from_slice::<Value>(body) else {
        return (409, json!({"error": "the body is not a receipt"}));
    };
    // the link may bring the verdict that finished the slice a moment after the payment
    let t0 = Instant::now();
    loop {
        let mut g = lock(hub);
        let Some(r) = g.rentals.get_mut(&rental) else {
            return (409, json!({"error": "no such rental going on"}));
        };
        match check_receipt(r, slice, &receipt) {
            Err(why) if why.contains("not done") && t0.elapsed() < Duration::from_secs(3) => {}
            Err(why) => {
                r.note(json!({"ev": "paid slice refused", "slice": slice, "why": why, "atMs": now_ms()}));
                return (409, json!({"error": why}));
            }
            Ok(()) => {
                credit(r, slice, &receipt);
                r.note(json!({"ev": "paid slice", "slice": slice, "atMs": now_ms()}));
                return (200, json!({"ok": true, "rental": rental, "slice": slice}));
            }
        }
        drop(g);
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A request line, headers and body (by Content-Length, or chunked).
pub fn read_request(conn: &mut TcpStream) -> Option<(String, String, Vec<u8>)> {
    let mut r = BufReader::new(conn.try_clone().ok()?);
    let mut line = String::new();
    r.read_line(&mut line).ok()?;
    let mut it = line.split_whitespace();
    let (method, path) = (it.next()?.to_string(), it.next()?.to_string());
    let (mut len, mut chunked) = (0usize, false);
    loop {
        let mut h = String::new();
        r.read_line(&mut h).ok()?;
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        let (k, v) = h.split_once(':')?;
        match k.trim().to_ascii_lowercase().as_str() {
            "content-length" => len = v.trim().parse().ok()?,
            "transfer-encoding" => chunked = v.trim().eq_ignore_ascii_case("chunked"),
            _ => {}
        }
    }
    let mut body = Vec::new();
    if chunked {
        loop {
            let mut sz = String::new();
            r.read_line(&mut sz).ok()?;
            let n = usize::from_str_radix(sz.trim().split(';').next()?, 16).ok()?;
            let mut chunk = vec![0u8; n + 2];
            r.read_exact(&mut chunk).ok()?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
            if body.len() > 64 << 10 {
                return None;
            }
        }
    } else if len <= 64 << 10 {
        body.resize(len, 0);
        r.read_exact(&mut body).ok()?;
    } else {
        return None;
    }
    Some((method, path, body))
}
