//! `xbt-hashlink hashtaker`: the hashtaker's side as a service, for the app's Rent page. It finds hashmakers'
//! listings on Nostr, rents whole miners from them into the hashtaker's own DATUM Gateway (the pool is
//! chosen there, not here), pays each slice through the wallet's signer under its policy, and keeps
//! every rental's live state for the app. Several rentals can run at once.
//!
//! A hashmaker whose listing names an iroh link is reached over it (no port forward on either side;
//! `--iroh off` turns it off, `--iroh-relays` names relays); one naming only a TCP address, over TCP.
//!
//! Control page: `GET /status`, `GET /offers`, `POST /rent {"linkKey", "miners", "budgetSats",
//! "minutes", "once"}` (or `{"linkKey", "trial": true, "once"}`: one slice, to try a hashmaker first; a request
//! sent again with the same `once` starts nothing and answers what the first did), `POST /cut
//! {"rental"}`, `POST /datum {"addr"}`, `POST /attest {"rental"}` (publish a signed delivery record
//! of a rental that ended, if the hashtaker chooses to).
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
/// How long a Rent request's mark is remembered, and how long a request sent again waits for the first.
const ONCE_KEPT: Duration = Duration::from_secs(600);
const ONCE_WAIT: Duration = Duration::from_secs(60);

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
    /// Rent requests by their mark (`once`): the answer of the one that started a rental, or `None` while it
    /// is starting. A request sent again gets that answer and starts nothing.
    onces: HashMap<String, (Instant, Option<(u16, Value)>)>,
}

/// A gateway's API port when nothing says otherwise.
const GATEWAY_API_PORT: u16 = 7152;
/// How often an upstream's jobs are looked at again.
const LOOK_EVERY: Duration = Duration::from_secs(60);

impl R {
    /// Where this upstream's jobs are opened: as configured, or the gateway's API on the same host.
    fn api(&self) -> Option<String> {
        self.gateway_api.clone().or_else(|| {
            let host = self.datum.rsplit_once(':').map(|(h, _)| h)?;
            Some(format!("{host}:{GATEWAY_API_PORT}"))
        })
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

/// Can a Stratum endpoint be reached (a TCP connection within a second)?
fn reachable(addr: &str) -> bool {
    addr.to_socket_addrs().ok().and_then(|mut a| a.next()).is_some_and(|a| TcpStream::connect_timeout(&a, Duration::from_secs(1)).is_ok())
}

pub fn run(f: &HashMap<String, String>) -> Result<(), String> {
    let state = f.get("state").map(PathBuf::from);
    let saved = state.as_ref().and_then(|d| std::fs::read(d.join("renter.json")).ok()).and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    let mut datum = saved.as_ref().and_then(|v| v["datum"].as_str().map(str::to_string)).unwrap_or_else(|| f.get("upstream").cloned().unwrap_or_default());
    if datum.is_empty() || datum == "auto" {
        // a DATUM Gateway on this box, if one answers at a known address
        datum = f.get("datum-candidates").map(|c| super::relays(c)).unwrap_or_default().into_iter().find(|a| reachable(a)).unwrap_or_default();
    }
    let failed_first = state.as_ref().and_then(|d| std::fs::read(d.join("failed-first-steps.json")).ok()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    let r = Arc::new(Mutex::new(R {
        shown: None,
        onces: HashMap::new(),
        failed_first,
        key: crate::hashmaker_service::key_file(super::need(f, "key")?)?,
        datum,
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
    let candidates = f.get("datum-candidates").map(|c| super::relays(c)).unwrap_or_default();
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

/// The delivery records and summaries on the relays for the hashmakers on show (read at most once a minute).
fn history_events(r: &Mutex<R>, offers: &[(Hashrate, String)]) -> Vec<xbt_nostr::event::Event> {
    {
        let g = lock(r);
        if let Some((t, e)) = &g.history {
            if t.elapsed() < HISTORY_FRESH {
                return e.clone();
            }
        }
    }
    let (relays, authors) = {
        let g = lock(r);
        (g.relays.clone(), g.authors.clone())
    };
    let shown: Vec<(PublicKey, String)> = offers.iter().map(|(h, _)| (h.link_key, authors.get(&hex::encode(h.link_key.serialize())).cloned().unwrap_or_default())).collect();
    let events = records_for(&relays, &shown);
    lock(r).history = Some((Instant::now(), events.clone()));
    events
}

/// Each of [`trust::filters`] asked on its own, at once: a relay's newest answer to one hashmaker's filter can't be
/// pushed out by records about another.
fn records_for(relays: &[String], hashmakers: &[(PublicKey, String)]) -> Vec<xbt_nostr::event::Event> {
    let mut seen = std::collections::BTreeSet::new();
    std::thread::scope(|s| {
        let asks: Vec<_> = trust::filters(hashmakers).into_iter().map(|f| s.spawn(move || xbt_nostr::oneshot::query(relays, &f, Duration::from_secs(10)).0)).collect();
        asks.into_iter().flat_map(|a| a.join().unwrap_or_default()).filter(|e| seen.insert(e.id.clone())).collect()
    })
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
            (200, json!({
                "role": "renter", "datum": {"addr": datum, "reachable": !datum.is_empty() && reachable(&datum), "found": found}, "blinding": blinding,
                "relays": lock(r).relays.len(), "wallet": lock(r).signer.is_some(), "rentals": rentals,
            }))
        }
        ("GET", "/offers") => {
            let o = offers(r, path.contains("fresh=1"));
            let events = history_events(r, &o);
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
            let mut g = lock(r);
            g.datum = a.clone();
            if let Some(d) = &g.state {
                let _ = std::fs::create_dir_all(d);
                let _ = std::fs::write(d.join("renter.json"), json!({"datum": a}).to_string());
            }
            (200, json!({"ok": true, "datum": a, "reachable": reachable(&a)}))
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
        ("POST", "/rent") => rent_once(r, &b),
        _ => (404, json!({"error": "GET /status, GET /offers, POST /rent, POST /cut, POST /datum, POST /attest"})),
    }
}

/// [`rent`], once for each mark (`once`, set by the app's Rent form): the same request sent again, while the first
/// is starting or after, answers what the first did and starts no second rental, so no second start fee is paid.
/// A request that started nothing leaves its mark free, to be tried again.
fn rent_once(r: &Arc<Mutex<R>>, b: &Value) -> (u16, Value) {
    once(r, b, || rent(r, b))
}

/// [`rent_once`] with what starts the rental given: `start` runs at most once for a mark at a time.
fn once(r: &Mutex<R>, b: &Value, start: impl FnOnce() -> (u16, Value)) -> (u16, Value) {
    let Some(once) = b["once"].as_str().filter(|o| !o.is_empty() && o.len() <= 128).map(str::to_string) else { return start() };
    let t0 = Instant::now();
    loop {
        let mut g = lock(r);
        g.onces.retain(|_, (at, _)| at.elapsed() < ONCE_KEPT);
        match g.onces.get(&once) {
            Some((_, Some(answer))) => return answer.clone(),
            Some((_, None)) if t0.elapsed() < ONCE_WAIT => {}
            Some((_, None)) => return (409, json!({"error": "this rental is still starting: look at your rentals"})),
            None => {
                g.onces.insert(once.clone(), (Instant::now(), None));
                break;
            }
        }
        drop(g);
        std::thread::sleep(Duration::from_millis(50));
    }
    let answer = start();
    let mut g = lock(r);
    if answer.0 == 200 {
        g.onces.insert(once, (Instant::now(), Some(answer.clone())));
    } else {
        g.onces.remove(&once);
    }
    answer
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
        return (400, json!({"error": "no DATUM Gateway set: rented hashrate goes to your own DATUM Gateway"}));
    }
    if !reachable(&datum) {
        return (400, json!({"error": format!("your DATUM Gateway at {datum} does not answer")}));
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

    use std::net::TcpListener;
    use xbt_hashlink::hashmaker::{self, Hashmaker};
    use xbt_hashlink::listing::Capacity;
    use xbt_hashlink::meter::share_work;
    use xbt_hashlink::msg::{Terms, PROOF};
    use xbt_hashlink::rail::LabSeller;
    use xbt_hashlink::{noise, standin};

    /// About 4096 hashes a share: a difficulty a CPU reaches.
    const DIFF: f64 = 1.0 / (1u64 << 20) as f64;

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
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("{addr} never came up");
    }

    fn pool() -> String {
        let [addr] = ports::<1>();
        let a = addr.clone();
        std::thread::spawn(move || standin::pool(standin::PoolConfig { listen: a, diff: DIFF, job_every: Duration::from_millis(2000), report: None }));
        wait_for(&addr);
        addr
    }

    /// A hashmaker with its fallback and two miners hashing there, and its listing as the renter's
    /// service would have found it on the relays (a start fee of one slice).
    fn hashmaker_with_two_miners() -> (Hashmaker, Hashrate) {
        let terms = Terms { slice_work: 6 * share_work(DIFF), price_msat: 300_000, grace_ms: 2500, start_slices: 1 };
        let fallback = pool();
        let [link, miners] = ports::<2>();
        let hk = noise::fresh_key();
        let h = Hashmaker::start(
            hashmaker::Config {
                miners: miners.clone(),
                link: link.clone(),
                key: hk,
                terms: terms.clone(),
                report: None,
                slices: None,
                fallback: Some(fallback),
                rentable: None,
                min_slice_time: hashmaker::MIN_SLICE_TIME,
            },
            Box::new(|| Box::<LabSeller>::default()),
        )
        .unwrap();
        wait_for(&link);
        for i in 0..2 {
            let a = miners.clone();
            std::thread::spawn(move || {
                standin::miner(standin::MinerConfig {
                    pool: a,
                    user: format!("m{i}"),
                    max_rate: 4.0,
                    bad_every: 0,
                    duration: Some(Duration::from_secs(40)),
                    reconnect: true,
                    extranonce_subscribe: false,
                    bind: None,
                })
            });
        }
        let t0 = Instant::now();
        while !h.status()["miners"].as_array().is_some_and(|m| m.len() == 2 && m.iter().all(|m| m["connected"] == true && m["work"] != "0")) {
            assert!(t0.elapsed() < Duration::from_secs(20), "the miners never hashed at the fallback: {}", h.status());
            std::thread::sleep(Duration::from_millis(100));
        }
        let listing = Hashrate {
            name: "lab".into(),
            algorithm: "blake2b".into(),
            hashrate_hs: 1,
            link_addr: link,
            link_key: PublicKey::from_secret_key(secp256k1::SECP256K1, &hk),
            iroh: None,
            pay_url: String::new(),
            pay_node: String::new(),
            terms,
            proof: Some(PROOF.into()),
            capacity: Capacity { miners: 2, free_miners: 2, free_hs: 2 },
        };
        (h, listing)
    }

    /// The renter's service, its DATUM Gateway a stand-in pool, the listing already read from the relays.
    fn renter(listing: Hashrate) -> Arc<Mutex<R>> {
        let r = bare();
        {
            let mut g = lock(&r);
            g.datum = pool();
            g.offers = Some((Instant::now(), vec![(listing, "ev".into())]));
        }
        r
    }

    fn bare() -> Arc<Mutex<R>> {
        Arc::new(Mutex::new(R {
            shown: None,
            onces: HashMap::new(),
            failed_first: BTreeMap::new(),
            key: noise::fresh_key(),
            datum: String::new(),
            user: "rented".into(),
            gateway_api: None,
            allow_unblinded: true,
            relays: Vec::new(),
            signer: None,
            task: "hashrate".into(),
            expect_node: None,
            state: None,
            offers: None,
            authors: HashMap::new(),
            history: None,
            rentals: BTreeMap::new(),
            iroh: None,
            iroh_off: true,
            iroh_relays: None,
        }))
    }

    /// A Rent sent again while the first is still starting waits for it and starts nothing; one that started
    /// nothing leaves its mark free; one with no mark is never held back.
    #[test]
    fn a_rent_still_starting_is_not_started_again() {
        use std::sync::atomic::AtomicUsize;
        let r = bare();
        let starts = AtomicUsize::new(0);
        let start = |code: u16| {
            starts.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(300));
            (code, json!({"rental": "r1"}))
        };
        let b = json!({"once": "m1"});
        let answers: Vec<(u16, Value)> = std::thread::scope(|s| {
            let x: Vec<_> = (0..3).map(|_| s.spawn(|| once(&r, &b, || start(200)))).collect();
            x.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(starts.load(Ordering::SeqCst), 1, "three at once, one started");
        assert!(answers.iter().all(|a| *a == (200, json!({"rental": "r1"}))), "{answers:?}");
        assert_eq!(once(&r, &b, || start(200)).0, 200);
        assert_eq!(starts.load(Ordering::SeqCst), 1, "and once more after");
        // a start that failed frees its mark for a retry
        let f = json!({"once": "m2"});
        assert_eq!(once(&r, &f, || start(400)).0, 400);
        assert_eq!(once(&r, &f, || start(200)).0, 200);
        assert_eq!(starts.load(Ordering::SeqCst), 3);
        // no mark: each is its own request
        once(&r, &json!({}), || start(200));
        once(&r, &json!({}), || start(200));
        assert_eq!(starts.load(Ordering::SeqCst), 5);
    }

    /// The same Rent sent twice (a double click, a browser sending the form again, two at once): one
    /// rental, one start fee. Both answers name that rental.
    #[test]
    fn a_rent_sent_twice_starts_one_rental_and_pays_one_start_fee() {
        let (h, listing) = hashmaker_with_two_miners();
        let terms = listing.terms.clone();
        let key = hex::encode(listing.link_key.serialize());
        let r = renter(listing);
        let body = json!({"linkKey": key, "miners": 1, "budgetSats": 20000, "minutes": 1, "once": "f00d"}).to_string();
        // two at once, then once more after both answered
        let answers: Vec<(u16, Value)> = std::thread::scope(|s| {
            let a = s.spawn(|| handle(&r, &[], "POST", "/rent", body.as_bytes()));
            let b = s.spawn(|| handle(&r, &[], "POST", "/rent", body.as_bytes()));
            vec![a.join().unwrap(), b.join().unwrap()]
        });
        let again = handle(&r, &[], "POST", "/rent", body.as_bytes());
        for (code, v) in answers.iter().chain([&again]) {
            assert_eq!(*code, 200, "{v}");
        }
        let id = answers[0].1["rental"].as_str().unwrap().to_string();
        assert!(answers.iter().chain([&again]).all(|(_, v)| v["rental"] == id.as_str()), "every answer names the one rental: {answers:?} {again:?}");
        assert_eq!(lock(&r).rentals.len(), 1);
        // the hashmaker serves it: its start fee and first slice paid, miners moved
        let t0 = Instant::now();
        while !h.status()["rentals"].as_array().is_some_and(|a| a.iter().any(|x| x["paid"].as_u64().unwrap_or(0) > terms.start_slices)) {
            assert!(t0.elapsed() < Duration::from_secs(20), "the rental never started: {}", h.status());
            std::thread::sleep(Duration::from_millis(100));
        }
        std::thread::sleep(Duration::from_secs(2));
        let live = h.status()["rentals"].as_array().cloned().unwrap_or_default();
        assert_eq!(live.len(), 1, "one rental at the hashmaker, the second miner still on the fallback: {live:?}");
        // cut it, and look at the money: one rental paid, one start fee among it
        handle(&r, &[], "POST", "/cut", json!({"rental": id}).to_string().as_bytes());
        let t0 = Instant::now();
        while h.finished().is_empty() || !h.status()["rentals"].as_array().is_some_and(|a| a.is_empty()) {
            assert!(t0.elapsed() < Duration::from_secs(30), "the rental never ended: {}", h.status());
            std::thread::sleep(Duration::from_millis(100));
        }
        let fin = h.finished();
        assert_eq!(fin.len(), 1, "{fin:?}");
        let paid = fin[0]["paid"].as_u64().unwrap();
        assert!(paid > terms.start_slices, "{}", fin[0]);
        assert_eq!(fin.iter().map(|x| x["earnedMsat"].as_u64().unwrap()).sum::<u64>(), paid * terms.price_msat, "all the money went to the one rental");
        let report = lock(&r).rentals[&id].live.lock().unwrap().clone();
        assert_eq!(report["paidSlices"].as_u64(), Some(paid), "both sides count the same slices paid: {report}");
    }

    fn record(taker: &SecretKey, maker: &PublicKey, rental: &str, ended: u64) -> xbt_nostr::event::Event {
        let t = PublicKey::from_secret_key(secp256k1::SECP256K1, taker);
        trust::Attestation {
            hashmaker: *maker,
            hashtaker: t,
            commit: trust::commit(rental, &t, maker),
            paid_slices: 2,
            paid_msat: 10_000,
            slice_work: 1 << 47,
            work: 2 << 47,
            duration_s: 600,
            accepted: 50,
            rejected: 0,
            stale: 0,
            advertised_hs: 4_000_000_000_000,
            delivered_hs: 4_000_000_000_000,
            latency_ms_p50: None,
            receipts_hash: "h".into(),
            trial: false,
            ended_at: ended,
        }
        .event(taker, ended)
        .unwrap()
    }

    /// Records about other hashmakers, as many as anyone cares to publish and all newer, don't hide a
    /// hashmaker's own from its offer.
    #[test]
    fn a_flood_of_records_about_others_hides_no_hashmakers_own() {
        let relay = xbt_nostr::standin::StandinRelay::start().unwrap();
        let relays = vec![relay.url.clone()];
        let (a, b) = (noise::fresh_key(), noise::fresh_key());
        let (a, b) = (PublicKey::from_secret_key(secp256k1::SECP256K1, &a), PublicKey::from_secret_key(secp256k1::SECP256K1, &b));
        let real = record(&noise::fresh_key(), &a, "real", 3_600);
        xbt_nostr::oneshot::publish(&relays, &real, Duration::from_secs(5));
        let junk_key = noise::fresh_key();
        for i in 0..520u64 {
            let ev = record(&junk_key, &b, &format!("junk{i}"), 7_200 + i);
            xbt_nostr::oneshot::publish(&relays, &ev, Duration::from_secs(5));
        }
        assert_eq!(relay.events(trust::KIND).len(), 521, "the relay keeps them all");
        let shown = [(a, String::new()), (b, String::new())];
        let events = records_for(&relays, &shown);
        let h = trust::aggregate(&a, "", 4_000_000_000_000, &events);
        assert_eq!((h["records"].as_u64(), h["keys"].as_u64()), (Some(1), Some(1)), "the hashmaker's own record is there: {h}");
        // and the flood itself is one key's: at most a few counted, one line shown
        let h = trust::aggregate(&b, "", 4_000_000_000_000, &events);
        assert_eq!((h["keys"].as_u64(), h["counted"].as_u64(), h["recent"].as_array().map(Vec::len)), (Some(1), Some(trust::PER_KEY as u64), Some(1)), "{h}");
    }

    /// A gateway that says nothing for `delay` after each connection opens, then carries everything both ways.
    fn slow_to_answer(to: String, delay: Duration) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let Ok(up) = TcpStream::connect(&to) else { continue };
                let (mut c2, mut up2) = (c.try_clone().unwrap(), up.try_clone().unwrap());
                let (mut c, mut up) = (c, up);
                std::thread::spawn(move || std::io::copy(&mut c, &mut up));
                std::thread::spawn(move || {
                    std::thread::sleep(delay);
                    std::io::copy(&mut up2, &mut c2)
                });
            }
        });
        addr
    }

    /// The seconds before the first accepted share (connecting, moving the miners, a slow gateway) are not taken
    /// from a rental's time, and the money holds: every slice paid once, no work past what was paid.
    #[test]
    fn a_rentals_time_starts_at_its_first_accepted_share() {
        let (h, listing) = hashmaker_with_two_miners();
        let terms = listing.terms.clone();
        let (delay, duration) = (Duration::from_secs(4), Duration::from_secs(3));
        let cfg = hashtaker::Config {
            hashmaker: listing.link_addr.clone(),
            hashmaker_key: listing.link_key,
            key: noise::fresh_key(),
            upstream: slow_to_answer(pool(), delay),
            user: "late.rented".into(),
            terms: terms.clone(),
            rental: "late".into(),
            listing: "lab".into(),
            stop_paying_after: None,
            idle: Duration::from_secs(30),
            duration: Some(duration),
            report: None,
            payer: None,
            miners: 1,
            budget_msat: None,
            cut: None,
            live: None,
            gateway_api: None,
            allow_unblinded: true,
        };
        let t0 = xbt_hashlink::now_ms();
        let report = hashtaker::run(cfg, Box::<LabHashtaker>::default()).unwrap();
        let ended = xbt_hashlink::now_ms();
        assert_eq!(report["closed"], "rental time over", "{report}");
        let first = report["firstAcceptedMs"].as_u64().unwrap_or_else(|| panic!("no share was accepted: {report}"));
        assert!(first >= t0 + delay.as_millis() as u64, "the gateway said nothing for {delay:?}: {first} from {t0}");
        assert!(ended >= first + duration.as_millis() as u64, "the rental ran its {duration:?} from the first accepted share: {first} to {ended}");
        assert!(ended < first + duration.as_millis() as u64 + 3000, "and stopped then: {first} to {ended}");
        // the money: each slice paid once, as both sides count them, and no work served past what was paid
        let t1 = Instant::now();
        while h.finished().is_empty() {
            assert!(t1.elapsed() < Duration::from_secs(30), "the hashmaker never ended it: {}", h.status());
            std::thread::sleep(Duration::from_millis(100));
        }
        let fin = &h.finished()[0];
        let paid = fin["paid"].as_u64().unwrap();
        assert!(paid > terms.start_slices, "{fin}");
        assert_eq!(report["paidSlices"].as_u64(), Some(paid), "{report} / {fin}");
        let served: u128 = fin["meter"]["work"].as_str().unwrap().parse().unwrap();
        assert!(served <= xbt_hashlink::order::paid_work(paid, terms.start_slices, terms.slice_work), "served {served} past what {paid} slices pay for: {fin}");
    }

}
