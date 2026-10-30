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
    let r = Arc::new(Mutex::new(R {
        key: crate::hashmaker_service::key_file(super::need(f, "key")?)?,
        datum,
        user: f.get("user").cloned().unwrap_or_else(|| "rented".into()),
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
    http::serve(&addr, token, Arc::new(move |method, path, body| handle(&r, &candidates, method, path, body)))?;
    eprintln!("hashtaker: control page on {addr}");
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn lock(r: &Mutex<R>) -> std::sync::MutexGuard<'_, R> {
    r.lock().unwrap_or_else(|p| p.into_inner())
}

fn offer_json(h: &Hashrate, event: &str) -> Value {
    json!({
        "name": h.name, "algorithm": h.algorithm, "linkKey": hex::encode(h.link_key.serialize()), "linkAddr": h.link_addr,
        "directLink": h.iroh.is_some(),
        "priceMsat": h.terms.price_msat, "sliceWork": h.terms.slice_work.to_string(), "graceMs": h.terms.grace_ms,
        "hashrateHs": h.hashrate_hs.to_string(), "payUrl": h.pay_url, "payNode": h.pay_node,
        "miners": h.capacity.miners, "freeMiners": h.capacity.free_miners, "freeHs": h.capacity.free_hs.to_string(), "event": event,
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
            (200, json!({
                "role": "renter", "datum": {"addr": datum, "reachable": !datum.is_empty() && reachable(&datum), "found": found},
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
        ("POST", "/rent") => rent(r, &b),
        _ => (404, json!({"error": "GET /status, GET /offers, POST /rent, POST /cut, POST /datum, POST /attest"})),
    }
}

fn rent(r: &Arc<Mutex<R>>, b: &Value) -> (u16, Value) {
    let key_hex = b["linkKey"].as_str().unwrap_or("");
    let trial = b["trial"] == true;
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
    let pick = |o: Vec<(Hashrate, String)>| o.into_iter().find(|(h, _)| hex::encode(h.link_key.serialize()) == key_hex);
    let Some((h, event)) = pick(offers(r, false)).or_else(|| pick(offers(r, true))) else {
        return (404, json!({"error": "that hashmaker's listing is no longer on the relays"}));
    };
    if trial {
        // one machine, one slice: the budget is one slice's price, and the time a few slices' worth
        miners = 1;
        budget_sats = h.terms.price_msat.div_ceil(1000);
        minutes = trial_minutes(h.terms.slice_work, per_miner_hs(&h));
    }
    let advertised_hs = per_miner_hs(&h).saturating_mul(miners as u64);
    if h.terms.price_msat > budget_sats * 1000 {
        return (400, json!({"error": "the budget is less than one slice"}));
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
    let (key, user, signer, task) = {
        let g = lock(r);
        (g.key, g.user.clone(), g.signer.clone(), g.task.clone())
    };
    // the offer's price per slice is the most the wallet pays the shop for one ([`SignerPayer::ceiling`])
    let ceiling = Some(xbt_hashlink::rail::slice_ceiling(h.terms.price_msat));
    let payer = signer.map(|sock| SignerPayer { sock, url: h.pay_url.clone(), task, max_sats: budget_sats, session: None, ceiling,
                                                       wait_for_signer: std::time::Duration::from_millis(h.terms.grace_ms / 2) });
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
        payer,
        miners,
        budget_msat: Some(budget_sats * 1000),
        cut: Some(cut.clone()),
        live: Some(live.clone()),
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
    std::thread::spawn(move || {
        let res = hashtaker::run(cfg, Box::<LabHashtaker>::default());
        if let Err(e) = res {
            *live.lock().unwrap_or_else(|p| p.into_inner()) = json!({"closed": format!("could not start: {e}")});
        }
        done.store(true, Ordering::Relaxed);
        eprintln!("hashtaker: rental with {} ended", hex::encode(hashmaker_key.serialize()));
    });
    (200, json!({"ok": true, "rental": id, "trial": trial, "budgetSats": budget_sats, "minutes": minutes}))
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
}
