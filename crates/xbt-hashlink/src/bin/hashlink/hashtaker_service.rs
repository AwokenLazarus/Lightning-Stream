//! `xbt-hashlink hashtaker`: the hashtaker's side as a service, for the app's Rent page. It finds hashmakers'
//! listings on Nostr, rents whole miners from them into the hashtaker's own DATUM Gateway (the pool is
//! chosen there, not here), pays each slice through the wallet's signer under its policy, and keeps
//! every rental's live state for the app. Several rentals can run at once.
//!
//! Control page: `GET /status`, `GET /offers`, `POST /rent {"linkKey", "miners", "budgetSats",
//! "minutes"}`, `POST /cut {"rental"}`, `POST /datum {"addr"}`.

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
use xbt_hashlink::rail::{LabHashtaker, SignerPayer};

const OFFERS_FRESH: Duration = Duration::from_secs(20);
const KEPT: usize = 50;

struct Rental {
    hashmaker: String,
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
    rentals: BTreeMap<String, Rental>,
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
        rentals: BTreeMap::new(),
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
    let o: Vec<(Hashrate, String)> = found
        .into_iter()
        .filter(|(h, _)| h.algorithm == "blake2b" && node.as_ref().is_none_or(|n| *n == h.pay_node))
        .map(|(h, e)| (h, e.id))
        .collect();
    lock(r).offers = Some((Instant::now(), o.clone()));
    o
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
                    json!({
                        "rental": id, "hasher": x.hashmaker, "startedMs": x.started_ms, "miners": x.miners, "budgetSats": x.budget_sats,
                        "minutes": x.minutes, "ended": x.done.load(Ordering::Relaxed), "live": live,
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
            (200, json!({"offers": o.iter().map(|(h, e)| offer_json(h, e)).collect::<Vec<_>>()}))
        }
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
        _ => (404, json!({"error": "GET /status, GET /offers, POST /rent, POST /cut, POST /datum"})),
    }
}

fn rent(r: &Arc<Mutex<R>>, b: &Value) -> (u16, Value) {
    let key_hex = b["linkKey"].as_str().unwrap_or("");
    let miners = b["miners"].as_u64().unwrap_or(1).clamp(1, 1000) as u32;
    let budget_sats = b["budgetSats"].as_u64().unwrap_or(0);
    let minutes = b["minutes"].as_u64().unwrap_or(60).clamp(1, 7 * 24 * 60);
    if budget_sats == 0 {
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
    if h.terms.price_msat > budget_sats * 1000 {
        return (400, json!({"error": "the budget is less than one slice"}));
    }
    let id = format!("r{}", xbt_hashlink::now_ms());
    let live = Arc::new(Mutex::new(json!({"closed": null})));
    let cut = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let (key, user, signer, task) = {
        let g = lock(r);
        (g.key, g.user.clone(), g.signer.clone(), g.task.clone())
    };
    let payer = signer.map(|sock| SignerPayer { sock, url: h.pay_url.clone(), task, max_sats: budget_sats, session: None });
    let cfg = hashtaker::Config {
        hashmaker: h.link_addr.clone(),
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
    (200, json!({"ok": true, "rental": id}))
}
