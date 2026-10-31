//! `xbt-hashlink hashtaker`: the hashtaker's side as a service, for the app's Rent page. It finds hashmakers'
//! listings on Nostr, rents whole miners from them into the hashtaker's own DATUM Gateway (the pool is
//! chosen there, not here), pays each slice through the wallet's signer under its policy, and keeps
//! every rental's live state for the app. Several rentals can run at once.
//!
//! A hashmaker whose listing names an iroh link is reached over it (no port forward on either side;
//! `--iroh off` turns it off, `--iroh-relays` names relays); one naming only a TCP address, over TCP.
//!
//! Control page: `GET /status`, `GET /offers`, `POST /rent {"linkKey", "miners", "budgetSats",
//! "minutes"}` (or `{"linkKey", "trial": true}`: one slice, to try a hashmaker first), `POST /cut
//! {"rental"}`, `POST /datum {"addr", "api"?}`, `POST /attest {"rental"}` (publish a signed delivery record
//! of a rental that ended, if the hashtaker chooses to).
//!
//! The app comes with its own gateway, the Stream Gateway (DATUM-compatible), on `127.0.0.1:23339` beside
//! this service (`--bundled-gateway`, else that address when `--datum-candidates` lists it). Its API is
//! `--gateway-api`. An install that saved another gateway before the app had one is moved to it once, at
//! start: those gateways can't open their jobs, so every rental to them would be refused. The address it was
//! moved from is kept and shown, and `POST /datum` with it goes back, for good.
//!
//! Each offer carries its hashmaker's delivery history, read from the records and summaries on the
//! relays ([`xbt_hashlink::trust`]).

use crate::http;
use secp256k1::{PublicKey, SecretKey};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use xbt_hashlink::hashtaker;
use xbt_hashlink::listing::{self, Hashrate};
use xbt_hashlink::over_iroh::{self, Dialer};
use xbt_hashlink::rail::{LabHashtaker, SignerPayer};
use xbt_hashlink::trust;

const OFFERS_FRESH: Duration = Duration::from_secs(20);
/// How long the delivery records read from the relays are kept before they are read again.
const HISTORY_FRESH: Duration = Duration::from_secs(60);
/// A test slice's time limit: a few times what one slice should take at the advertised speed,
/// within these bounds.
const TRIAL_MIN_MINUTES: u64 = 5;
const TRIAL_MAX_MINUTES: u64 = 60;
const KEPT: usize = 50;

struct Rental {
    hashmaker: String,
    hashmaker_key: PublicKey,
    /// The speed the listing advertised for the machines rented.
    advertised_hs: u64,
    /// A test slice (one slice, to try the hashmaker first).
    trial: bool,
    /// What publishing its delivery record did, once asked for.
    attested: Option<Value>,
    started_ms: u64,
    miners: u32,
    budget_sats: u64,
    minutes: u64,
    live: Arc<Mutex<Value>>,
    cut: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
}

struct R {
    key: SecretKey,
    datum: String,
    /// The API of the gateway chosen on the app's page, when it gave one.
    datum_api: Option<String>,
    /// The gateway that comes with the app (its Stratum address), when this box has one.
    bundled: Option<String>,
    /// `--upstream`, whose API `--gateway-api` names too.
    upstream_flag: Option<String>,
    /// The gateway this install was moved from at the upgrade that brought the bundled one.
    moved_from: Option<String>,
    user: String,
    gateway_api: Option<String>,
    allow_unblinded: bool,
    relays: Vec<String>,
    signer: Option<PathBuf>,
    task: String,
    expect_node: Option<String>,
    state: Option<PathBuf>,
    offers: Option<(Instant, Vec<(Hashrate, String)>)>,
    /// Each listing's Nostr author, by link key (a hashmaker's summary counts only from it).
    authors: HashMap<String, String>,
    /// The delivery records and summaries on the relays, as last read.
    history: Option<(Instant, Vec<xbt_nostr::event::Event>)>,
    rentals: BTreeMap<String, Rental>,
    /// The iroh link to hashmakers, started at the first rental that needs it; `None` inside when it
    /// is turned off or did not start.
    iroh: Option<Option<Arc<Dialer>>>,
    iroh_off: bool,
    iroh_relays: Option<String>,
    /// Failed first steps in a row, by seller's link key: kept across restarts.
    failed_first: BTreeMap<String, u32>,
    /// What the upstream's jobs show, as last looked at, and for which upstream.
    shown: Option<(String, xbt_hashlink::blind::Shown, u64)>,
}

/// A gateway's API port when nothing says otherwise.
const GATEWAY_API_PORT: u16 = 7152;
/// Where the Stream Gateway that comes with the app listens for Stratum, on every platform.
pub const BUNDLED_STRATUM: &str = "127.0.0.1:23339";
/// How often an upstream's jobs are looked at again.
const LOOK_EVERY: Duration = Duration::from_secs(60);

impl R {
    /// Where this upstream's jobs are opened: as configured, or the gateway's API on the same host.
    fn api(&self) -> Option<String> {
        api_of(&self.datum, self.datum_api.as_deref(), self.bundled.as_deref(), self.upstream_flag.as_deref(), self.gateway_api.as_deref())
    }

    /// A rental ended: a failed first step counts against its seller, and anything else clears the count.
    fn note_rental_end(&mut self, seller: &str, report: &Value) {
        if xbt_hashlink::order::failed_first_step(report) {
            *self.failed_first.entry(seller.to_string()).or_default() += 1;
        } else {
            self.failed_first.remove(seller);
        }
        if let Some(d) = &self.state {
            let _ = std::fs::write(d.join("failed-first-steps.json"), serde_json::to_vec(&self.failed_first).unwrap_or_default());
        }
    }

    fn refused_seller(&self, seller: &str) -> bool {
        self.failed_first.get(seller).is_some_and(|n| *n >= xbt_hashlink::order::FAILED_FIRST_STEPS)
    }
}

/// A gateway's API: the one saved with it; `--gateway-api` for the bundled gateway and for `--upstream`
/// (or for whichever gateway, when neither is known); else its host's port 7152.
fn api_of(datum: &str, saved: Option<&str>, bundled: Option<&str>, upstream_flag: Option<&str>, flag_api: Option<&str>) -> Option<String> {
    if let Some(a) = saved.filter(|a| !a.is_empty()) {
        return Some(a.to_string());
    }
    let flagged = (bundled.is_none() && upstream_flag.is_none()) || bundled == Some(datum) || upstream_flag == Some(datum);
    if let Some(a) = flag_api.filter(|_| flagged) {
        return Some(a.to_string());
    }
    let host = datum.rsplit_once(':').map(|(h, _)| h)?;
    Some(format!("{host}:{GATEWAY_API_PORT}"))
}

/// The gateway that comes with the app: `--bundled-gateway`, else [`BUNDLED_STRATUM`] when the candidates list it.
fn bundled_of(f: &HashMap<String, String>, candidates: &[String]) -> Option<String> {
    f.get("bundled-gateway").filter(|b| !b.is_empty() && b.as_str() != "off").cloned().or_else(|| {
        if f.get("bundled-gateway").map(String::as_str) == Some("off") {
            return None;
        }
        candidates.iter().find(|c| c.as_str() == BUNDLED_STRATUM).cloned()
    })
}

/// Which gateway to start with, from `renter.json` as saved and `--upstream`: `(datum, its API, moved from,
/// renter.json to write)`. A gateway set before this app came with one (saved without `chosen`, or named by
/// `--upstream` in an install's settings) is left for the bundled one, once: it can't open its jobs, and every
/// rental to it would be refused. A gateway chosen on the page since then is kept.
fn start_with(saved: Option<&Value>, upstream: &str, bundled: Option<&str>) -> (String, Option<String>, Option<String>, Option<Value>) {
    let s = |k: &str| saved.and_then(|v| v[k].as_str()).map(str::to_string).filter(|x| !x.is_empty());
    let (datum, api, chosen, moved) = (s("datum"), s("api"), saved.is_some_and(|v| v["chosen"] == true), s("movedFrom"));
    let set = datum.clone().or_else(|| Some(upstream.to_string()).filter(|u| !u.is_empty() && u != "auto"));
    match (set, bundled) {
        (Some(d), Some(b)) if d != b && !chosen => {
            let now = json!({"datum": b, "movedFrom": d, "movedAtMs": xbt_hashlink::now_ms()});
            (b.to_string(), None, Some(d), Some(now))
        }
        _ if datum.is_some() => (datum.unwrap_or_default(), api, moved, None),
        _ => (upstream.to_string(), None, None, None),
    }
}

/// Can a Stratum endpoint be reached (a TCP connection within a second)?
fn reachable(addr: &str) -> bool {
    addr.to_socket_addrs().ok().and_then(|mut a| a.next()).is_some_and(|a| TcpStream::connect_timeout(&a, Duration::from_secs(1)).is_ok())
}

pub fn run(f: &HashMap<String, String>) -> Result<(), String> {
    let state = f.get("state").map(PathBuf::from);
    let saved = state.as_ref().and_then(|d| std::fs::read(d.join("renter.json")).ok()).and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    let candidates = f.get("datum-candidates").map(|c| super::relays(c)).unwrap_or_default();
    let bundled = bundled_of(f, &candidates);
    let upstream_flag = f.get("upstream").cloned().filter(|u| !u.is_empty() && u != "auto");
    let (mut datum, datum_api, moved_from, write) = start_with(saved.as_ref(), f.get("upstream").map(String::as_str).unwrap_or(""), bundled.as_deref());
    if let (Some(w), Some(d)) = (&write, &state) {
        let _ = std::fs::write(d.join("renter.json"), w.to_string());
        eprintln!("hashtaker: rented work now goes to the Stream Gateway that comes with this app, at {datum}; the gateway saved before is kept, to go back to");
    }
    if datum.is_empty() || datum == "auto" {
        // the gateway that comes with the app, else a DATUM-compatible gateway on this box that answers at a known address
        datum = bundled.clone().or_else(|| candidates.iter().find(|a| reachable(a)).cloned()).unwrap_or_default();
    }
    let failed_first = state.as_ref().and_then(|d| std::fs::read(d.join("failed-first-steps.json")).ok()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    let r = Arc::new(Mutex::new(R {
        shown: None,
        failed_first,
        key: crate::hashmaker_service::key_file(super::need(f, "key")?)?,
        datum,
        datum_api,
        bundled,
        upstream_flag,
        moved_from,
        user: f.get("user").cloned().unwrap_or_else(|| "rented".into()),
        gateway_api: f.get("gateway-api").cloned(),
        allow_unblinded: f.contains_key("allow-unblinded"),
        relays: f.get("relays").map(|r| super::relays(r)).unwrap_or_default(),
        signer: f.get("signer").map(PathBuf::from),
        task: f.get("task").cloned().unwrap_or_else(|| "hashrate".into()),
        expect_node: f.get("expect-node").cloned(),
        state,
        offers: None,
        authors: HashMap::new(),
        history: None,
        rentals: BTreeMap::new(),
        iroh: None,
        iroh_off: f.get("iroh").map(String::as_str) == Some("off"),
        iroh_relays: f.get("iroh-relays").cloned(),
    }));
    let addr = super::need(f, "control")?.to_string();
    let token = f.get("control-token-file").map(|p| http::token(p)).transpose()?;
    {
        // what the upstream's jobs show, kept current for the renter's page: a pool that adds a key shows here by
        // itself, and no list says so
        let r = r.clone();
        std::thread::spawn(move || loop {
            look_at_upstream(&r);
            std::thread::sleep(LOOK_EVERY);
        });
    }
    http::serve(&addr, token, Arc::new(move |method, path, body| handle(&r, &candidates, method, path, body)))?;
    eprintln!("hashtaker: control page on {addr}");
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn lock(r: &Mutex<R>) -> std::sync::MutexGuard<'_, R> {
    r.lock().unwrap_or_else(|p| p.into_inner())
}

/// What must be paid before the miners move: the start fee and a slice.
fn first_payment_msat(t: &xbt_hashlink::msg::Terms) -> u64 {
    t.price_msat.saturating_mul(t.start_slices.saturating_add(1))
}

fn offer_json(h: &Hashrate, event: &str) -> Value {
    json!({
        "name": h.name, "algorithm": h.algorithm, "linkKey": hex::encode(h.link_key.serialize()), "linkAddr": h.link_addr,
        "directLink": h.iroh.is_some(),
        "priceMsat": h.terms.price_msat, "sliceWork": h.terms.slice_work.to_string(), "graceMs": h.terms.grace_ms,
        "startSlices": h.terms.start_slices, "proves": h.proves(),
        "hashrateHs": h.hashrate_hs.to_string(), "payUrl": h.pay_url, "payNode": h.pay_node,
        "miners": h.capacity.miners, "freeMiners": h.capacity.free_miners, "freeHs": h.capacity.free_hs.to_string(), "event": event,
        // what a trial may leave the wallet for: a ticket of the first step and its fee limit.
        // A longer rental's tickets grow as they are earned, so no figure stands for them
        "trialMayBuyTicketUpToSats": xbt_hashlink::rail::caps_at(xbt_hashlink::order::FIRST_STEP_MSAT, h.terms.price_msat, Some(h.terms.price_msat.saturating_mul(h.terms.start_slices + 1)), None).0,
    })
}

fn offers(r: &Mutex<R>, fresh: bool) -> Vec<(Hashrate, String)> {
    {
        let g = lock(r);
        if let Some((t, o)) = &g.offers {
            if !fresh && t.elapsed() < OFFERS_FRESH {
                return o.clone();
            }
        }
    }
    let (relays, node) = {
        let g = lock(r);
        (g.relays.clone(), g.expect_node.clone())
    };
    let (found, _) = listing::find(&relays, xbt_nostr::now());
    let found: Vec<_> = found.into_iter().filter(|(h, _)| h.algorithm == "blake2b" && node.as_ref().is_none_or(|n| *n == h.pay_node)).collect();
    let mut g = lock(r);
    for (h, e) in &found {
        g.authors.insert(hex::encode(h.link_key.serialize()), e.pubkey.clone());
    }
    let o: Vec<(Hashrate, String)> = found.into_iter().map(|(h, e)| (h, e.id)).collect();
    g.offers = Some((Instant::now(), o.clone()));
    o
}

/// The delivery records and hashmakers' summaries on the relays (read at most once a minute).
fn history_events(r: &Mutex<R>) -> Vec<xbt_nostr::event::Event> {
    {
        let g = lock(r);
        if let Some((t, e)) = &g.history {
            if t.elapsed() < HISTORY_FRESH {
                return e.clone();
            }
        }
    }
    let relays = lock(r).relays.clone();
    let (events, _) = xbt_nostr::oneshot::query(&relays, &trust::filter(500), Duration::from_secs(10));
    lock(r).history = Some((Instant::now(), events.clone()));
    events
}

/// A listing's advertised speed for each machine: its free machines' speed shared out, or its
/// whole speed shared by its machines.
fn per_miner_hs(h: &Hashrate) -> u64 {
    let c = &h.capacity;
    if c.free_miners > 0 && c.free_hs > 0 {
        c.free_hs / c.free_miners as u64
    } else if c.miners > 0 {
        h.hashrate_hs / c.miners as u64
    } else {
        h.hashrate_hs
    }
}

/// A test slice's time limit: three times what one slice takes at the advertised speed, in minutes.
fn trial_minutes(slice_work: u128, hs: u64) -> u64 {
    if hs == 0 {
        return TRIAL_MAX_MINUTES;
    }
    let secs = (slice_work as f64 / hs as f64) * 3.0;
    ((secs / 60.0).ceil() as u64).clamp(TRIAL_MIN_MINUTES, TRIAL_MAX_MINUTES)
}

/// The bundled gateway, for the renter's page: whether it runs (its API answers), whether it has work from the
/// node (it hands out a job), and whether its jobs are masked. Looked at closely only while it is the one in use.
fn bundled_status(addr: &str, api: Option<&str>, in_use: bool, stratum: Option<bool>, blinding: Option<&Value>) -> Value {
    let running = api.is_some_and(reachable);
    let stratum = stratum.unwrap_or_else(|| reachable(addr));
    if !in_use {
        return json!({"addr": addr, "api": api, "inUse": false, "running": running || stratum, "node": null, "masking": false,
                      "state": if running || stratum { "not in use" } else { "not running" }, "mode": null});
    }
    // a job came back (masked or not): the gateway has a template, so it reaches the node
    let job = blinding.and_then(|b| b["state"].as_str()).map(|s| s != "can't be checked");
    let node = match (running || stratum, job) {
        (false, _) => Value::Null,
        (true, Some(j)) => json!(j),
        (true, None) => json!(false),
    };
    let masking = blinding.is_some_and(|b| b["state"] == "blinded");
    let state = if !running && !stratum {
        "not running"
    } else if node != json!(true) {
        "waiting for the node"
    } else if !masking {
        "not masking"
    } else {
        "masking"
    };
    json!({"addr": addr, "api": api, "inUse": in_use, "running": running || stratum, "node": node, "masking": masking, "state": state,
           "mode": blinding.filter(|_| masking).and_then(|b| b["why"].as_str())})
}

/// Look at what the upstream's jobs show, with no lock held for it.
fn look_at_upstream(r: &Mutex<R>) -> Option<xbt_hashlink::blind::Shown> {
    let (datum, api, user) = {
        let g = lock(r);
        (g.datum.clone(), g.api(), g.user.clone())
    };
    if datum.is_empty() {
        lock(r).shown = None;
        return None;
    }
    let shown = xbt_hashlink::blind::probe(&datum, api.as_deref(), &user);
    lock(r).shown = Some((datum, shown.clone(), xbt_hashlink::now_ms()));
    Some(shown)
}

fn handle(r: &Arc<Mutex<R>>, candidates: &[String], method: &str, path: &str, body: &[u8]) -> (u16, Value) {
    let b: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    match (method, path.split('?').next().unwrap_or("")) {
        ("GET", "/status") => {
            let g = lock(r);
            let datum = g.datum.clone();
            let rentals: Vec<Value> = g
                .rentals
                .iter()
                .rev()
                .map(|(id, x)| {
                    let live = x.live.lock().unwrap_or_else(|p| p.into_inner()).clone();
                    let result = if live.get("meter").is_some() { trust::trial_result(&live, x.started_ms, xbt_hashlink::now_ms(), x.advertised_hs) } else { Value::Null };
                    json!({
                        "rental": id, "hasher": x.hashmaker, "startedMs": x.started_ms, "miners": x.miners, "budgetSats": x.budget_sats,
                        "minutes": x.minutes, "ended": x.done.load(Ordering::Relaxed), "live": live,
                        "trial": x.trial, "advertisedHs": x.advertised_hs.to_string(), "result": result, "attested": x.attested,
                    })
                })
                .collect();
            drop(g);
            let found: Vec<&String> = candidates.iter().filter(|a| reachable(a)).collect();
            // looked at again when the renter's page asks and the last look is old or of another gateway
            let stale = lock(r).shown.as_ref().is_none_or(|(d, _, at)| *d != datum || xbt_hashlink::now_ms().saturating_sub(*at) > LOOK_EVERY.as_millis() as u64);
            if stale && !datum.is_empty() && reachable(&datum) {
                look_at_upstream(r);
            }
            let blinding = lock(r).shown.as_ref().filter(|(for_datum, ..)| *for_datum == datum).map(|(_, shown, at)| {
                let mut v = shown.to_json();
                v["checkedMs"] = json!(at);
                v
            });
            let datum_reachable = !datum.is_empty() && reachable(&datum);
            let (bundled, moved_from, api) = {
                let g = lock(r);
                let bundled_api = g.bundled.as_deref().and_then(|b| api_of(b, None, g.bundled.as_deref(), g.upstream_flag.as_deref(), g.gateway_api.as_deref()));
                (g.bundled.clone().map(|b| (b, bundled_api)), g.moved_from.clone(), g.api())
            };
            let bundled = bundled.map(|(b, bapi)| {
                let in_use = b == datum;
                bundled_status(&b, bapi.as_deref(), in_use, if in_use { Some(datum_reachable) } else { None }, if in_use { blinding.as_ref() } else { None })
            });
            (200, json!({
                "role": "renter", "datum": {"addr": datum, "api": api, "reachable": datum_reachable, "found": found, "movedFrom": moved_from},
                "bundled": bundled, "blinding": blinding,
                "relays": lock(r).relays.len(), "wallet": lock(r).signer.is_some(), "rentals": rentals,
            }))
        }
        ("GET", "/offers") => {
            let o = offers(r, path.contains("fresh=1"));
            let events = history_events(r);
            let authors = lock(r).authors.clone();
            let list: Vec<Value> = o
                .iter()
                .map(|(h, e)| {
                    let mut v = offer_json(h, e);
                    let author = authors.get(&hex::encode(h.link_key.serialize())).cloned().unwrap_or_default();
                    v["history"] = trust::aggregate(&h.link_key, &author, per_miner_hs(h), &events);
                    v["perMinerHs"] = json!(per_miner_hs(h).to_string());
                    v
                })
                .collect();
            (200, json!({"offers": list}))
        }
        ("POST", "/attest") => attest(r, &b),
        ("POST", "/datum") => {
            let a = b["addr"].as_str().unwrap_or("").trim().to_string();
            if a.is_empty() || !a.contains(':') {
                return (400, json!({"error": "the address is host:port"}));
            }
            let api = b["api"].as_str().map(str::trim).filter(|x| !x.is_empty()).map(str::to_string);
            if api.as_ref().is_some_and(|x| !x.contains(':')) {
                return (400, json!({"error": "the gateway's API address is host:port"}));
            }
            let mut g = lock(r);
            g.datum = a.clone();
            g.datum_api = api.clone();
            // chosen here: kept across restarts and upgrades
            g.moved_from = None;
            // a look at another gateway's jobs is not this one's
            g.shown = None;
            if let Some(d) = &g.state {
                let _ = std::fs::create_dir_all(d);
                let mut saved = json!({"datum": a, "chosen": true});
                if let Some(x) = &api {
                    saved["api"] = json!(x);
                }
                let _ = std::fs::write(d.join("renter.json"), saved.to_string());
            }
            (200, json!({"ok": true, "datum": a, "reachable": reachable(&a), "bundled": g.bundled.as_deref() == Some(a.as_str())}))
        }
        ("POST", "/cut") => {
            let id = b["rental"].as_str().unwrap_or("");
            match lock(r).rentals.get(id) {
                Some(x) => {
                    x.cut.store(true, Ordering::Relaxed);
                    (200, json!({"ok": true}))
                }
                None => (404, json!({"error": "no such rental"})),
            }
        }
        ("POST", "/rent") => rent(r, &b),
        _ => (404, json!({"error": "GET /status, GET /offers, POST /rent, POST /cut, POST /datum, POST /attest"})),
    }
}

fn rent(r: &Arc<Mutex<R>>, b: &Value) -> (u16, Value) {
    let key_hex = b["linkKey"].as_str().unwrap_or("");
    let trial = b["trial"] == true;
    if lock(r).refused_seller(key_hex) {
        return (409, json!({"error": "this hashmaker took your first payment twice and delivered little: this app won't pay it again"}));
    }
    let mut miners = b["miners"].as_u64().unwrap_or(1).clamp(1, 1000) as u32;
    let mut budget_sats = b["budgetSats"].as_u64().unwrap_or(0);
    let mut minutes = b["minutes"].as_u64().unwrap_or(60).clamp(1, 7 * 24 * 60);
    if budget_sats == 0 && !trial {
        return (400, json!({"error": "set a budget: the most this rental may cost, in sats"}));
    }
    let datum = lock(r).datum.clone();
    if datum.is_empty() {
        return (400, json!({"error": "no gateway set: rented hashrate goes to your own gateway"}));
    }
    if !reachable(&datum) {
        return (400, json!({"error": format!("your gateway at {datum} does not answer")}));
    }
    // looked at again now: this is the money's last chance to stay home
    let allow_unblinded = lock(r).allow_unblinded;
    if !allow_unblinded {
        match look_at_upstream(r) {
            Some(shown) if !shown.may_rent() => return (409, json!({"error": shown.words(), "blinding": shown.to_json()})),
            _ => {}
        }
    }
    let pick = |o: Vec<(Hashrate, String)>| o.into_iter().find(|(h, _)| hex::encode(h.link_key.serialize()) == key_hex);
    let Some((h, event)) = pick(offers(r, false)).or_else(|| pick(offers(r, true))) else {
        return (404, json!({"error": "that hashmaker's listing is no longer on the relays"}));
    };
    if !h.proves() {
        return (400, json!({"error": "this hashmaker's app doesn't prove the work it sells: it needs updating"}));
    }
    if trial {
        // one machine, one slice: the budget is one slice's price with the start fee, and the time a few slices' worth
        miners = 1;
        budget_sats = first_payment_msat(&h.terms).div_ceil(1000);
        minutes = trial_minutes(h.terms.slice_work, per_miner_hs(&h));
    }
    let advertised_hs = per_miner_hs(&h).saturating_mul(miners as u64);
    if first_payment_msat(&h.terms) > budget_sats.saturating_mul(1000) {
        return (400, json!({"error": if h.terms.start_slices > 0 { "the budget is less than the start fee and one slice" } else { "the budget is less than one slice" }}));
    }
    // over iroh when the listing offers it (no port forward needed on the hashmaker's side), else over
    // TCP to the address it names
    let addr = match &h.iroh {
        Some(i) => match dialer(r) {
            Some(d) => match d.address_for(i) {
                Ok(a) => a,
                Err(e) => return (502, json!({"error": format!("the direct link to that hashmaker did not open: {e}")})),
            },
            None if !h.link_addr.is_empty() => h.link_addr.clone(),
            None => return (502, json!({"error": "that hashmaker is reached only over a direct link, and this app's direct link is off or did not start"})),
        },
        None => h.link_addr.clone(),
    };
    let id = format!("r{}", xbt_hashlink::now_ms());
    let live = Arc::new(Mutex::new(json!({"closed": null})));
    let cut = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let (key, user, signer, task, gateway_api, allow_unblinded) = {
        let g = lock(r);
        (g.key, g.user.clone(), g.signer.clone(), g.task.clone(), g.api(), g.allow_unblinded)
    };
    // the first ticket, the first step's: later ones grow as they are earned, inside the budget
    let first_ticket = xbt_hashlink::rail::caps_at(xbt_hashlink::order::FIRST_STEP_MSAT, h.terms.price_msat, Some(budget_sats.saturating_mul(1000)), None).1.unwrap_or(0);
    let payer = signer.map(|sock| SignerPayer::new(sock, h.pay_url.clone(), task, h.terms.price_msat, Some(budget_sats), None,
                                                   std::time::Duration::from_millis(h.terms.grace_ms / 2)));
    let cfg = hashtaker::Config {
        hashmaker: addr,
        hashmaker_key: h.link_key,
        key,
        upstream: datum,
        user,
        terms: h.terms.clone(),
        rental: id.clone(),
        listing: event,
        stop_paying_after: None,
        idle: Duration::from_secs(180),
        duration: Some(Duration::from_secs(minutes * 60)),
        report: None,
        payer: payer.map(|p| Box::new(p) as Box<dyn xbt_hashlink::rail::Payer>),
        miners,
        budget_msat: Some(budget_sats * 1000),
        cut: Some(cut.clone()),
        live: Some(live.clone()),
        gateway_api: gateway_api.clone(),
        allow_unblinded,
    };
    {
        let mut g = lock(r);
        if g.rentals.len() >= KEPT {
            if let Some(old) = g.rentals.iter().find(|(_, x)| x.done.load(Ordering::Relaxed)).map(|(k, _)| k.clone()) {
                g.rentals.remove(&old);
            }
        }
        g.rentals.insert(id.clone(), Rental {
            hashmaker: h.name.clone(),
            hashmaker_key: h.link_key,
            advertised_hs,
            trial,
            attested: None,
            started_ms: xbt_hashlink::now_ms(),
            miners,
            budget_sats,
            minutes,
            live: live.clone(),
            cut,
            done: done.clone(),
        });
    }
    let hashmaker_key: PublicKey = h.link_key;
    let service = r.clone();
    std::thread::spawn(move || {
        let res = hashtaker::run(cfg, Box::<LabHashtaker>::default());
        match res {
            Err(e) => *live.lock().unwrap_or_else(|p| p.into_inner()) = json!({"closed": format!("could not start: {e}")}),
            Ok(report) => lock(&service).note_rental_end(&hex::encode(hashmaker_key.serialize()), &report),
        }
        done.store(true, Ordering::Relaxed);
        eprintln!("hashtaker: rental with {} ended", hex::encode(hashmaker_key.serialize()));
    });
    // the rental may buy the shop's ticket: what of it the slices do not use stays with that shop as credit
    (200, json!({"ok": true, "rental": id, "trial": trial, "budgetSats": budget_sats, "minutes": minutes, "mayBuyTicketUpToSats": first_ticket}))
}

/// Publish the signed delivery record of a rental that ended (the hashtaker's choice, per rental).
fn attest(r: &Arc<Mutex<R>>, b: &Value) -> (u16, Value) {
    let id = b["rental"].as_str().unwrap_or("").to_string();
    let (key, relays, x) = {
        let g = lock(r);
        let Some(x) = g.rentals.get(&id) else { return (404, json!({"error": "no such rental"})) };
        if !x.done.load(Ordering::Relaxed) {
            return (400, json!({"error": "the rental has not ended yet"}));
        }
        let live = x.live.lock().unwrap_or_else(|p| p.into_inner()).clone();
        (g.key, g.relays.clone(), (live, x.started_ms, x.hashmaker_key, x.advertised_hs, x.trial))
    };
    if relays.is_empty() {
        return (400, json!({"error": "no Nostr relays are set"}));
    }
    let (live, started, maker, adv, trial) = x;
    let me = PublicKey::from_secret_key(secp256k1::SECP256K1, &key);
    let Some(a) = trust::attestation_of(&live, &id, started, &me, &maker, adv, trial, xbt_nostr::now()) else {
        return (400, json!({"error": "this rental has nothing to record"}));
    };
    if a.paid_slices == 0 {
        return (400, json!({"error": "nothing was paid in this rental, so there is nothing to record"}));
    }
    let ev = match a.event(&key, xbt_nostr::now()) {
        Ok(e) => e,
        Err(e) => return (500, json!({"error": e})),
    };
    let out = listing::publish(&relays, &ev);
    let ok = out.iter().any(|o| o["ok"] == true);
    let result = json!({"ok": ok, "relays": out, "commit": a.commit, "atMs": xbt_hashlink::now_ms()});
    if let Some(x) = lock(r).rentals.get_mut(&id) {
        x.attested = Some(result.clone());
    }
    // read again next time: the new record is on the relays now
    lock(r).history = None;
    (if ok { 200 } else { 502 }, result)
}

/// The iroh link to hashmakers, started once.
fn dialer(r: &Mutex<R>) -> Option<Arc<Dialer>> {
    let mut g = lock(r);
    if g.iroh.is_none() {
        let d = if g.iroh_off {
            None
        } else {
            match Dialer::start(over_iroh::relays(g.iroh_relays.as_deref())) {
                Ok(d) => Some(Arc::new(d)),
                Err(e) => {
                    eprintln!("hashtaker: the iroh link did not start: {e}");
                    None
                }
            }
        };
        g.iroh = Some(d);
    }
    g.iroh.clone().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test_slice_takes_a_few_slices_time_within_bounds() {
        // a slice of 2^47 hashes at 4 TH/s takes about 35 s: three of them is under the floor
        assert_eq!(trial_minutes(1 << 47, 4_000_000_000_000), TRIAL_MIN_MINUTES);
        // at 0.1 TH/s about 23 minutes a slice: three of them is past the ceiling
        assert_eq!(trial_minutes(1 << 47, 100_000_000_000), TRIAL_MAX_MINUTES);
        assert_eq!(trial_minutes(1 << 47, 1_000_000_000_000), 8);
        assert_eq!(trial_minutes(1 << 47, 0), TRIAL_MAX_MINUTES);
    }

    const B: Option<&str> = Some(BUNDLED_STRATUM);

    /// An install from before the app had its own gateway is moved to it once, at start, and keeps the address it
    /// had, to go back to; one chosen on the page since is kept; a box without the bundled gateway is left as it was.
    #[test]
    fn an_old_gateway_is_left_for_the_bundled_one_once_and_a_chosen_one_is_kept() {
        // saved by 0.1.x: stock upstream, no `chosen`
        let old = json!({"datum": "datum_web_1:23334"});
        let (d, api, moved, write) = start_with(Some(&old), "auto", B);
        assert_eq!((d.as_str(), api, moved.as_deref()), (BUNDLED_STRATUM, None, Some("datum_web_1:23334")));
        let w = write.expect("renter.json is rewritten");
        assert_eq!(w["datum"], BUNDLED_STRATUM);
        assert_eq!(w["movedFrom"], "datum_web_1:23334");
        assert!(w.get("chosen").is_none());
        // the next start keeps it there and still knows where it came from, with nothing to write
        let (d, _, moved, write) = start_with(Some(&w), "auto", B);
        assert_eq!((d.as_str(), moved.as_deref(), write), (BUNDLED_STRATUM, Some("datum_web_1:23334"), None));
        // "use it again" on the page saves it as chosen: kept from then on
        let chosen = json!({"datum": "datum_web_1:23334", "chosen": true, "api": "datum_web_1:7152"});
        let (d, api, moved, write) = start_with(Some(&chosen), "auto", B);
        assert_eq!((d.as_str(), api.as_deref(), moved, write), ("datum_web_1:23334", Some("datum_web_1:7152"), None, None));
        // a Linux install whose settings name its own gateway (--upstream) moves the same way
        let (d, _, moved, write) = start_with(None, "127.0.0.1:23334", B);
        assert_eq!((d.as_str(), moved.as_deref()), (BUNDLED_STRATUM, Some("127.0.0.1:23334")));
        assert!(write.is_some());
        // a fresh install: the bundled gateway (auto finds it first)
        assert_eq!(start_with(None, "auto", B).0, "auto");
        assert_eq!(start_with(None, BUNDLED_STRATUM, B), (BUNDLED_STRATUM.to_string(), None, None, None));
        // no bundled gateway on this box: nothing moves
        assert_eq!(start_with(Some(&old), "auto", None), ("datum_web_1:23334".to_string(), None, None, None));
        assert_eq!(start_with(None, "10.0.0.5:23334", None).0, "10.0.0.5:23334");
    }

    #[test]
    fn the_bundled_gateway_is_found_by_its_address_or_named() {
        let f = |kv: &[(&str, &str)]| kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<HashMap<_, _>>();
        let c = vec!["127.0.0.1:23339".to_string(), "datum_web_1:23334".to_string()];
        assert_eq!(bundled_of(&f(&[]), &c).as_deref(), Some(BUNDLED_STRATUM));
        assert_eq!(bundled_of(&f(&[]), &c[1..]), None);
        assert_eq!(bundled_of(&f(&[("bundled-gateway", "127.0.0.1:24000")]), &c).as_deref(), Some("127.0.0.1:24000"));
        assert_eq!(bundled_of(&f(&[("bundled-gateway", "off")]), &c), None);
    }

    /// `--gateway-api` is the bundled gateway's API (7153 on Linux); another gateway's is its own host's 7152, or the
    /// one saved with it.
    #[test]
    fn each_gateway_is_opened_on_its_own_api() {
        let linux = Some("127.0.0.1:7153");
        assert_eq!(api_of(BUNDLED_STRATUM, None, B, None, linux).as_deref(), Some("127.0.0.1:7153"));
        assert_eq!(api_of(BUNDLED_STRATUM, None, B, None, None).as_deref(), Some("127.0.0.1:7152"));
        assert_eq!(api_of("192.0.2.7:23334", None, B, None, linux).as_deref(), Some("192.0.2.7:7152"));
        assert_eq!(api_of("192.0.2.7:23334", Some("192.0.2.7:7160"), B, None, linux).as_deref(), Some("192.0.2.7:7160"));
        // the gateway --upstream names keeps --gateway-api, as before; so does any, on a box with neither known
        assert_eq!(api_of("192.0.2.7:23334", None, B, Some("192.0.2.7:23334"), Some("192.0.2.7:9000")).as_deref(), Some("192.0.2.7:9000"));
        assert_eq!(api_of("192.0.2.7:23334", None, None, None, Some("192.0.2.7:9000")).as_deref(), Some("192.0.2.7:9000"));
    }

    #[test]
    fn the_bundled_gateways_state_reads_from_what_answers_and_what_its_jobs_show() {
        // nothing listens on these
        let dead = bundled_status("127.0.0.1:1", Some("127.0.0.1:1"), true, Some(false), None);
        assert_eq!((dead["state"].as_str(), &dead["running"], &dead["node"]), (Some("not running"), &json!(false), &Value::Null));
        // its Stratum answers, and it gave no job: it has no work from the node yet
        let waiting = bundled_status("127.0.0.1:1", Some("127.0.0.1:1"), true, Some(true),
                                     Some(&json!({"state": "can't be checked", "why": "127.0.0.1:23339 gave no job to look at"})));
        assert_eq!((waiting["state"].as_str(), &waiting["node"], &waiting["masking"]), (Some("waiting for the node"), &json!(false), &json!(false)));
        let masked = bundled_status("127.0.0.1:1", Some("127.0.0.1:1"), true, Some(true), Some(&json!({"state": "blinded", "why": "solo"})));
        assert_eq!((masked["state"].as_str(), &masked["node"], &masked["masking"], masked["mode"].as_str()), (Some("masking"), &json!(true), &json!(true), Some("solo")));
        let unmasked = bundled_status("127.0.0.1:1", Some("127.0.0.1:1"), true, Some(true), Some(&json!({"state": "not blinded", "why": "its key is null"})));
        assert_eq!((unmasked["state"].as_str(), &unmasked["node"]), (Some("not masking"), &json!(true)));
        let other = bundled_status("127.0.0.1:1", Some("127.0.0.1:1"), false, None, None);
        assert_eq!((other["state"].as_str(), &other["inUse"]), (Some("not running"), &json!(false)));
    }

    /// The page's switch: choosing a gateway saves it as chosen (kept across upgrades) and forgets the move.
    #[test]
    fn choosing_a_gateway_on_the_page_keeps_it() {
        let dir = std::env::temp_dir().join(format!("hashtaker-choose-{}-{}", std::process::id(), xbt_hashlink::now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let r = Arc::new(Mutex::new(R {
            key: SecretKey::from_slice(&[7u8; 32]).unwrap(),
            datum: BUNDLED_STRATUM.into(),
            datum_api: None,
            bundled: Some(BUNDLED_STRATUM.into()),
            upstream_flag: None,
            moved_from: Some("datum_web_1:23334".into()),
            user: "rented".into(),
            gateway_api: None,
            allow_unblinded: false,
            relays: vec![],
            signer: None,
            task: "hashrate".into(),
            expect_node: None,
            state: Some(dir.clone()),
            offers: None,
            authors: HashMap::new(),
            history: None,
            rentals: BTreeMap::new(),
            iroh: None,
            iroh_off: true,
            iroh_relays: None,
            failed_first: BTreeMap::new(),
            shown: None,
        }));
        let (code, v) = handle(&r, &[], "POST", "/datum", br#"{"addr": "datum_web_1:23334"}"#);
        assert_eq!((code, &v["bundled"]), (200, &json!(false)));
        let saved: Value = serde_json::from_slice(&std::fs::read(dir.join("renter.json")).unwrap()).unwrap();
        assert_eq!(saved, json!({"datum": "datum_web_1:23334", "chosen": true}));
        assert!(lock(&r).moved_from.is_none());
        assert_eq!(start_with(Some(&saved), "auto", B).0, "datum_web_1:23334", "kept at the next start");
        // and back: the bundled gateway, chosen
        let (code, v) = handle(&r, &[], "POST", "/datum", format!(r#"{{"addr": "{BUNDLED_STRATUM}"}}"#).as_bytes());
        assert_eq!((code, &v["bundled"]), (200, &json!(true)));
        assert_eq!(lock(&r).api().as_deref(), Some("127.0.0.1:7152"));
        assert_eq!(handle(&r, &[], "POST", "/datum", br#"{"addr": "x:1", "api": "nocolon"}"#).0, 400);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
