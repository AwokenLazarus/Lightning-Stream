//! The hasher's side: a Stratum V1 endpoint for the hasher's miners, every line carried over the
//! link to the buyer, every job and verdict carried back. It meters the buyer's verdicts itself,
//! takes a locked ticket before serving a slice, and stops serving when a finished slice is not
//! paid within the grace time, or as soon as a second slice finishes unpaid.

use crate::link::{self, Sender};
use crate::meter::{Event, Meter, Receipt};
use crate::msg::{Msg, Terms};
use crate::rail::{sha256, Hash, SellerRail};
use crate::{now_ms, sv1};
use secp256k1::{PublicKey, SecretKey};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct Config {
    /// Where the hasher's miners connect (Stratum V1, the hasher's LAN).
    pub miners: String,
    /// Where the buyer's app connects (the link).
    pub link: String,
    pub key: SecretKey,
    pub terms: Terms,
    /// A JSON report, rewritten every second and at the end.
    pub report: Option<PathBuf>,
    /// Where the hasher's gateway passes on paid slices (`POST <route>/<rental>/<slice>`). With
    /// it, slices are paid through the gateway's tickets; without it, over the link (the lab's
    /// stand-in rail), and a slice is served only once its ticket is locked.
    pub slices: Option<String>,
}

const PING_EVERY: Duration = Duration::from_secs(15);
const QUIET_LIMIT: Duration = Duration::from_secs(60);
const RATE_WINDOW: Duration = Duration::from_secs(30);
const LOCK_WAIT: Duration = Duration::from_secs(10);

struct St {
    terms: Terms,
    rental: String,
    buyer: PublicKey,
    meter: Meter,
    locks: BTreeMap<u64, Hash>,
    paid: u64,
    /// Own meter's work and time when each slice finished (index = slice - 1).
    done: Vec<(u128, u64)>,
    receipts: Vec<Value>,
    agree: u64,
    disagree: u64,
    due_since: Option<Instant>,
    lock_missing_since: Option<Instant>,
    /// Slices are paid over the link, on tickets locked over the link.
    over_link: bool,
    stopped: Option<Value>,
    miners: HashMap<u32, TcpStream>,
    next_chan: u32,
    rate: VecDeque<(Instant, u128)>,
    last_heard: Instant,
    events: Vec<Value>,
    /// Stratum methods seen from the miners (which extensions they use).
    methods: BTreeMap<String, u64>,
    rail: Box<dyn SellerRail>,
}

impl St {
    fn note(&mut self, ev: Value) {
        if self.events.len() < 10_000 {
            self.events.push(ev);
        }
    }

    fn completed(&self) -> u64 {
        (self.meter.work / self.terms.slice_work) as u64
    }

    fn stop(&mut self, tx: &Sender, reason: &str) {
        if self.stopped.is_some() {
            return;
        }
        let s = self.terms.slice_work;
        let unpaid = self.meter.work.saturating_sub(self.paid as u128 * s);
        self.stopped = Some(json!({
            "reason": reason, "atMs": now_ms(), "work": self.meter.work.to_string(),
            "paid": self.paid, "unpaidWork": unpaid.to_string(),
            "unpaidSlices": unpaid as f64 / s as f64,
        }));
        let _ = tx.send(&Msg::Close { reason: reason.to_string() });
        for (_, m) in self.miners.drain() {
            let _ = m.shutdown(std::net::Shutdown::Both);
        }
        tx.shutdown();
    }

    fn hashrate(&mut self) -> f64 {
        let now = Instant::now();
        self.rate.push_back((now, self.meter.work));
        while self.rate.front().is_some_and(|(t, _)| now - *t > RATE_WINDOW) {
            self.rate.pop_front();
        }
        match (self.rate.front(), self.rate.back()) {
            (Some((t0, w0)), Some((t1, w1))) if t1 > t0 => (w1 - w0) as f64 / (*t1 - *t0).as_secs_f64(),
            _ => 0.0,
        }
    }

    fn report(&self) -> Value {
        json!({
            "role": "hasher", "rental": self.rental, "buyer": hex::encode(self.buyer.serialize()),
            "terms": self.terms.to_json(), "meter": self.meter.to_json(),
            "slicesDone": self.done.iter().map(|(w, t)| json!({"work": w.to_string(), "atMs": t})).collect::<Vec<_>>(),
            "paid": self.paid, "receiptsAgree": self.agree, "receiptsDisagree": self.disagree,
            "receipts": self.receipts, "stopped": self.stopped, "methods": self.methods, "events": self.events,
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

/// Serve one rental: wait for the buyer, serve the hasher's miners until the rental ends, and
/// return the report.
pub fn run(cfg: Config, rail: Box<dyn SellerRail>) -> Result<Value, String> {
    let link_l = TcpListener::bind(&cfg.link).map_err(|e| format!("link listen {}: {e}", cfg.link))?;
    let miners_l = TcpListener::bind(&cfg.miners).map_err(|e| format!("miner listen {}: {e}", cfg.miners))?;
    let slices_l = match &cfg.slices {
        Some(a) => Some(TcpListener::bind(a).map_err(|e| format!("slice listen {a}: {e}"))?),
        None => None,
    };
    eprintln!(
        "hasher: link {} (key {}), miners {}",
        cfg.link,
        hex::encode(PublicKey::from_secret_key(secp256k1::SECP256K1, &cfg.key).serialize()),
        cfg.miners
    );
    // the first connection that completes the handshake and says hello on the listed terms
    let (tx, mut rx, remote, rental) = loop {
        let (s, _) = link_l.accept().map_err(|e| e.to_string())?;
        let Ok(link::Link { tx, mut rx, remote }) = link::answer(s, cfg.key) else { continue };
        match rx.recv() {
            Ok(Some(Msg::Hello { rental, terms, .. })) if terms == cfg.terms => break (tx, rx, remote, rental),
            Ok(Some(Msg::Hello { .. })) => {
                let _ = tx.send(&Msg::Close { reason: "terms differ from the listing".into() });
            }
            _ => {}
        }
        tx.shutdown();
    };
    tx.send(&Msg::Welcome { rental: rental.clone(), terms_hash: hex::encode(cfg.terms.hash()) })
        .map_err(|e| e.to_string())?;
    eprintln!("hasher: rental {rental} from buyer {}", hex::encode(remote.serialize()));

    let st = Arc::new(Mutex::new(St {
        terms: cfg.terms.clone(),
        rental,
        buyer: remote,
        meter: Meter::default(),
        locks: BTreeMap::new(),
        paid: 0,
        done: Vec::new(),
        receipts: Vec::new(),
        agree: 0,
        disagree: 0,
        due_since: None,
        lock_missing_since: None,
        over_link: cfg.slices.is_none(),
        stopped: None,
        miners: HashMap::new(),
        next_chan: 1,
        rate: VecDeque::new(),
        last_heard: Instant::now(),
        events: Vec::new(),
        methods: BTreeMap::new(),
        rail,
    }));

    if let Some(l) = slices_l {
        let st = st.clone();
        std::thread::spawn(move || serve_slices(l, st));
    }

    // miners
    {
        let st = st.clone();
        let tx = tx.clone();
        std::thread::spawn(move || {
            for conn in miners_l.incoming() {
                let Ok(conn) = conn else { continue };
                let st = st.clone();
                let tx = tx.clone();
                std::thread::spawn(move || serve_miner(conn, st, tx));
            }
        });
    }

    // ticker: grace, keepalive, rate, report
    {
        let st = st.clone();
        let tx = tx.clone();
        let report = cfg.report.clone();
        std::thread::spawn(move || {
            let mut last_ping = Instant::now();
            let mut last_rate = Instant::now();
            let mut n = 0;
            loop {
                std::thread::sleep(Duration::from_millis(200));
                let mut g = lock(&st);
                if g.stopped.is_some() {
                    write_report(&report, &g.report());
                    return;
                }
                let grace = Duration::from_millis(g.terms.grace_ms);
                if g.due_since.is_some_and(|t| t.elapsed() > grace) {
                    g.stop(&tx, "unpaid");
                } else if g.lock_missing_since.is_some_and(|t| t.elapsed() > grace) {
                    g.stop(&tx, "no ticket locked");
                } else if g.last_heard.elapsed() > QUIET_LIMIT {
                    g.stop(&tx, "link quiet");
                }
                if last_ping.elapsed() > PING_EVERY {
                    last_ping = Instant::now();
                    n += 1;
                    let _ = tx.send(&Msg::Ping { n });
                }
                if last_rate.elapsed() > Duration::from_secs(5) {
                    last_rate = Instant::now();
                    let hs = g.hashrate();
                    let miners = g.miners.len() as u32;
                    let _ = tx.send(&Msg::Rate { hs, miners });
                    write_report(&report, &g.report());
                }
            }
        });
    }

    loop {
        let m = match rx.recv() {
            Ok(Some(m)) => m,
            Ok(None) => continue,
            Err(e) => {
                lock(&st).stop(&tx, &format!("link lost: {e}"));
                break;
            }
        };
        let mut g = lock(&st);
        g.last_heard = Instant::now();
        match m {
            Msg::Down { chan, line } => {
                let Some(v) = sv1::parse(&line) else { continue };
                if let Some(Event::Accepted(_)) = g.meter.down(chan, &v) {
                    let s = g.terms.slice_work;
                    while g.meter.work >= (g.done.len() as u128 + 1) * s {
                        let w = g.meter.work;
                        g.done.push((w, now_ms()));
                    }
                    if g.completed() > g.paid && g.due_since.is_none() {
                        g.due_since = Some(Instant::now());
                    }
                    if g.completed() >= g.paid + 2 {
                        g.stop(&tx, "unpaid");
                        continue;
                    }
                }
                if sv1::dropped_down(&v) {
                    continue;
                }
                if let Some(m) = g.miners.get_mut(&chan) {
                    if m.write_all(format!("{}\n", line.trim_end()).as_bytes()).is_err() {
                        g.miners.remove(&chan);
                    }
                }
            }
            Msg::Lock { slice, hash } => {
                let Some(h) = hex::decode(&hash).ok().and_then(|h| Hash::try_from(h).ok()) else { continue };
                let price = g.terms.price_msat;
                if slice > g.paid && g.rail.held(slice, &h, price) {
                    g.locks.insert(slice, h);
                    if g.locks.contains_key(&(g.paid + 1)) {
                        g.lock_missing_since = None;
                    }
                    g.note(json!({"ev": "locked", "slice": slice, "atMs": now_ms()}));
                }
            }
            Msg::Pay { slice, preimage, receipt } => {
                let ok = pay(&mut g, slice, &preimage, &receipt);
                g.note(json!({"ev": "pay", "slice": slice, "ok": ok.is_ok(), "why": ok.as_ref().err(), "atMs": now_ms()}));
            }
            Msg::Shut { chan } => {
                if let Some(m) = g.miners.remove(&chan) {
                    let _ = m.shutdown(std::net::Shutdown::Both);
                }
                g.meter.close(chan);
            }
            Msg::Ping { n } => {
                let _ = tx.send(&Msg::Pong { n });
            }
            Msg::Close { reason } => {
                g.stop(&tx, &format!("buyer closed: {reason}"));
                break;
            }
            _ => {}
        }
    }
    let g = lock(&st);
    let r = g.report();
    write_report(&cfg.report, &r);
    Ok(r)
}

/// A slice paid over the link (the lab's rail): the preimage of the ticket locked for it.
fn pay(g: &mut St, slice: u64, preimage: &str, receipt: &Value) -> Result<(), String> {
    if slice != g.paid + 1 {
        return Err(format!("expected slice {}", g.paid + 1));
    }
    let p: [u8; 32] = hex::decode(preimage).ok().and_then(|p| p.try_into().ok()).ok_or("bad preimage")?;
    if g.locks.get(&slice) != Some(&sha256(&p)) {
        return Err("preimage does not match the locked ticket".into());
    }
    check_receipt(g, slice, receipt)?;
    g.rail.settle(slice, &p)?;
    g.locks.remove(&slice);
    credit(g, slice, receipt);
    g.lock_missing_since = (!g.locks.contains_key(&(g.paid + 1))).then(Instant::now);
    Ok(())
}

fn check_receipt(g: &mut St, slice: u64, receipt: &Value) -> Result<(), String> {
    if slice != g.paid + 1 {
        return Err(format!("expected slice {}", g.paid + 1));
    }
    let r = Receipt::verify(receipt, &g.buyer).ok_or("bad receipt signature")?;
    if r.rental != g.rental || r.slice != slice {
        return Err("receipt for another rental or slice".into());
    }
    if g.done.len() < slice as usize {
        return Err(format!("slice {slice} is not done by this side's count"));
    }
    Ok(())
}

fn credit(g: &mut St, slice: u64, receipt: &Value) {
    let own = g.done.get(slice as usize - 1).map(|(w, _)| *w);
    if own.map(|w| w.to_string()).as_deref() == receipt.get("work").and_then(Value::as_str) {
        g.agree += 1;
    } else {
        g.disagree += 1;
    }
    g.receipts.push(receipt.clone());
    g.paid = slice;
    g.due_since = (g.completed() > g.paid).then(Instant::now);
}

/// The hasher's paid-slice endpoint, behind its gateway: the gateway passes on only a request it
/// has been paid for, and charges it only when this answers below 400. So a slice is credited
/// here exactly when its price was taken: the body is the buyer's signed work receipt for it.
fn serve_slices(l: TcpListener, st: Arc<Mutex<St>>) {
    for conn in l.incoming() {
        let Ok(mut conn) = conn else { continue };
        let st = st.clone();
        std::thread::spawn(move || {
            let _ = conn.set_read_timeout(Some(Duration::from_secs(10)));
            let Some((method, path, body)) = read_request(&mut conn) else { return };
            let (code, out) = slice_request(&st, &method, &path, &body);
            let body = out.to_string();
            let _ = conn.write_all(
                format!("HTTP/1.1 {code} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", if code == 200 { "OK" } else { "Conflict" }, body.len())
                    .as_bytes(),
            );
        });
    }
}

fn slice_request(st: &Mutex<St>, method: &str, path: &str, body: &[u8]) -> (u16, Value) {
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
        let mut g = lock(st);
        if g.rental != rental {
            return (409, json!({"error": "another rental"}));
        }
        let r = check_receipt(&mut g, slice, &receipt);
        match r {
            Err(why) if why.contains("not done") && t0.elapsed() < Duration::from_secs(3) => {}
            Err(why) => {
                g.note(json!({"ev": "paid slice refused", "slice": slice, "why": why, "atMs": now_ms()}));
                return (409, json!({"error": why}));
            }
            Ok(()) => {
                credit(&mut g, slice, &receipt);
                g.note(json!({"ev": "paid slice", "slice": slice, "atMs": now_ms()}));
                return (200, json!({"ok": true, "rental": rental, "slice": slice}));
            }
        }
        drop(g);
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A request line, headers and body (by Content-Length, or chunked).
fn read_request(conn: &mut TcpStream) -> Option<(String, String, Vec<u8>)> {
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

fn lock(st: &Mutex<St>) -> std::sync::MutexGuard<'_, St> {
    st.lock().unwrap_or_else(|p| p.into_inner())
}

fn serve_miner(conn: TcpStream, st: Arc<Mutex<St>>, tx: Sender) {
    let peer = conn.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    // a slice is served only once its ticket is locked
    let t0 = Instant::now();
    let chan = loop {
        {
            let mut g = lock(&st);
            if g.stopped.is_some() {
                return;
            }
            if !g.over_link || g.locks.contains_key(&(g.paid + 1)) {
                let Ok(w) = conn.try_clone() else { return };
                let chan = g.next_chan;
                g.next_chan += 1;
                g.miners.insert(chan, w);
                g.note(json!({"ev": "miner", "chan": chan, "peer": peer, "atMs": now_ms()}));
                if tx.send(&Msg::Open { chan, worker: format!("miner-{chan}") }).is_err() {
                    return;
                }
                break chan;
            }
        }
        if t0.elapsed() > LOCK_WAIT {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let _ = conn.set_nodelay(true);
    let mut r = BufReader::new(conn);
    let mut line = String::new();
    loop {
        line.clear();
        match r.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let Some(v) = sv1::parse(&line) else { continue };
        let mut g = lock(&st);
        if g.stopped.is_some() || !g.miners.contains_key(&chan) {
            break;
        }
        if let Some(worker) = sv1::authorize_user(&v) {
            g.note(json!({"ev": "authorize", "chan": chan, "worker": worker, "atMs": now_ms()}));
        }
        if let Some(m) = sv1::method(&v) {
            *g.methods.entry(m.to_string()).or_default() += 1;
        }
        g.meter.up(chan, &v);
        if tx.send(&Msg::Up { chan, line: line.trim_end().to_string() }).is_err() {
            break;
        }
    }
    let mut g = lock(&st);
    if g.miners.remove(&chan).is_some() {
        let _ = tx.send(&Msg::Shut { chan });
    }
    g.note(json!({"ev": "miner gone", "chan": chan, "atMs": now_ms()}));
}
