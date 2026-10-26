//! `xbt-hashlink hasher --fallback ...`: the hasher's side as a service. Miners not rented hash at
//! the fallback; any number of buyers rent whole miners; the listing on Nostr says what is free
//! and is published again when that changes. The app writes the settings file (`--config`), and
//! reads the state from the control page.
//!
//! Settings file (JSON; every key optional, a flag gives the default):
//! `{"enabled": true, "fallback": "host:port", "priceSat": 40, "sliceWork": "140737488355328",
//!   "graceMs": 45000, "rentable": 3, "name": "My miners", "linkPublic": "host:port",
//!   "payUrl": "https://shop.example/hashrate", "payNode": "02…", "minersPublic": "host:port"}`
//!
//! Without `payNode`, the node is read from the hasher's gateway (`--gateway`, its `/services`).
//! A missing `--key` or `--nostr-key` file is made at the first start.

use crate::http;
use secp256k1::SecretKey;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use xbt_hashlink::hasher::{self, Hasher};
use xbt_hashlink::listing::Capacity;
use xbt_hashlink::msg::Terms;
use xbt_hashlink::rail::LabSeller;

/// A listing is published again at most this often when what is free changes.
const REPUBLISH_MIN: Duration = Duration::from_secs(15);
/// And at least this often, so relays keep it.
const REPUBLISH_MAX: Duration = Duration::from_secs(1800);

#[derive(Clone, Debug, PartialEq)]
struct Settings {
    enabled: bool,
    fallback: Option<String>,
    terms: Terms,
    rentable: Option<u32>,
    name: String,
    /// Where buyers' apps reach the link, where slices are paid and the node paid, as published.
    link_public: Option<String>,
    pay_url: Option<String>,
    pay_node: Option<String>,
    /// The address the hasher's miners use (shown by the app).
    miners_public: Option<String>,
}

fn defaults(f: &HashMap<String, String>) -> Result<Settings, String> {
    Ok(Settings {
        enabled: !f.contains_key("config"),
        fallback: f.get("fallback").cloned().filter(|a| !a.is_empty()),
        terms: Terms {
            slice_work: super::num(f, "slice-work", Some(1u128 << 47))?,
            price_msat: super::num(f, "price-msat", Some(40_000))?,
            grace_ms: super::num(f, "grace-ms", Some(45_000))?,
        },
        rentable: f.get("rentable").map(|v| v.parse()).transpose().map_err(|_| "--rentable")?,
        name: f.get("name").cloned().unwrap_or_else(|| "Hashrate".into()),
        link_public: f.get("link-public").cloned(),
        pay_url: f.get("pay-url").cloned(),
        pay_node: f.get("pay-node").cloned(),
        miners_public: f.get("miners-public").cloned(),
    })
}

fn read_settings(path: &Option<PathBuf>, base: &Settings) -> Settings {
    let Some(v) = path.as_ref().and_then(|p| std::fs::read(p).ok()).and_then(|b| serde_json::from_slice::<Value>(&b).ok()) else {
        return base.clone();
    };
    let mut s = base.clone();
    if let Some(e) = v.get("enabled").and_then(Value::as_bool) {
        s.enabled = e;
    }
    if let Some(f) = v.get("fallback").and_then(Value::as_str) {
        s.fallback = Some(f.trim().to_string()).filter(|f| !f.is_empty());
    }
    if let Some(p) = v.get("priceSat").and_then(Value::as_u64) {
        s.terms.price_msat = p * 1000;
    }
    if let Some(w) = v.get("sliceWork").and_then(Value::as_str).and_then(|w| w.parse().ok()).filter(|w: &u128| *w > 0) {
        s.terms.slice_work = w;
    }
    if let Some(g) = v.get("graceMs").and_then(Value::as_u64) {
        s.terms.grace_ms = g;
    }
    match v.get("rentable") {
        Some(Value::Null) => s.rentable = None,
        Some(n) => s.rentable = n.as_u64().and_then(|n| u32::try_from(n).ok()),
        None => {}
    }
    if let Some(n) = v.get("name").and_then(Value::as_str).filter(|n| !n.trim().is_empty()) {
        s.name = n.trim().to_string();
    }
    let text = |k: &str| v.get(k).and_then(Value::as_str).map(|t| t.trim().to_string()).filter(|t| !t.is_empty());
    s.link_public = text("linkPublic").or(s.link_public);
    s.pay_url = text("payUrl").or(s.pay_url);
    s.pay_node = text("payNode").or(s.pay_node);
    s.miners_public = text("minersPublic").or(s.miners_public);
    s
}

/// The node a gateway's tickets pay (`payTo` of its `/services`).
fn gateway_node(base: &str) -> Option<String> {
    let rest = base.trim_end_matches('/').strip_prefix("http://")?;
    let (host, path) = (rest, "/services");
    let mut s = std::net::TcpStream::connect(host).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    use std::io::{Read, Write};
    s.write_all(format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes()).ok()?;
    let mut buf = Vec::new();
    s.take(256 * 1024).read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    let body = text.split_once("\r\n\r\n")?.1;
    serde_json::from_str::<Value>(body).ok()?.get("payTo")?.as_str().map(str::to_string)
}

/// A key file: read, or made (mode 0600) when it is not there yet.
pub fn key_file(path: &str) -> Result<SecretKey, String> {
    if !std::path::Path::new(path).exists() {
        let k = xbt_hashlink::noise::fresh_key();
        super::write_secret(path, &hex::encode(k.secret_bytes()))?;
    }
    super::read_key(path)
}

fn mtime(p: &Option<PathBuf>) -> Option<SystemTime> {
    p.as_ref().and_then(|p| std::fs::metadata(p).ok()).and_then(|m| m.modified().ok())
}

pub fn run(f: &HashMap<String, String>, key: SecretKey) -> Result<(), String> {
    if let Some(n) = f.get("nostr-key") {
        key_file(n)?;
    }
    let path = f.get("config").map(PathBuf::from);
    let base = defaults(f)?;
    let mut settings = read_settings(&path, &base);
    let h = Arc::new(Hasher::start(
        hasher::Config {
            miners: super::need(f, "miners")?.into(),
            link: super::need(f, "link")?.into(),
            key,
            terms: settings.terms.clone(),
            report: f.get("report").map(PathBuf::from),
            slices: f.get("slices").cloned(),
            fallback: settings.fallback.clone(),
            rentable: settings.rentable,
        },
        Box::new(|| Box::<LabSeller>::default()),
    )?);
    h.set_open(settings.enabled && settings.fallback.is_some());
    let published: Arc<Mutex<Value>> = Arc::new(Mutex::new(Value::Null));
    let shared = Arc::new(Mutex::new(settings.clone()));
    if let Some(addr) = f.get("control") {
        let (h, published, shared) = (h.clone(), published.clone(), shared.clone());
        let miners_default = f.get("miners").cloned().unwrap_or_default();
        let listing = f.contains_key("relays");
        let token = f.get("control-token-file").map(|p| http::token(p)).transpose()?;
        http::serve(addr, token, Arc::new(move |method, path, _body| {
            let s = shared.lock().unwrap_or_else(|p| p.into_inner()).clone();
            match (method, path.split('?').next().unwrap_or("")) {
                ("GET", "/status") => {
                    let mut v = h.status();
                    v["settings"] = json!({
                        "enabled": s.enabled, "fallback": s.fallback, "priceSat": s.terms.price_msat / 1000,
                        "sliceWork": s.terms.slice_work.to_string(), "graceMs": s.terms.grace_ms, "rentable": s.rentable, "name": s.name,
                        "linkPublic": s.link_public, "payUrl": s.pay_url, "payNode": s.pay_node,
                    });
                    v["minersAddress"] = json!(s.miners_public.clone().unwrap_or_else(|| miners_default.clone()));
                    v["listing"] = if listing { published.lock().unwrap_or_else(|p| p.into_inner()).clone() } else { json!({"relays": "none set"}) };
                    (200, v)
                }
                ("POST", p) if p.starts_with("/stop/") => {
                    let id = &p["/stop/".len()..];
                    if h.stop_rental(id) {
                        (200, json!({"ok": true, "stopped": id}))
                    } else {
                        (404, json!({"error": "no such rental going on"}))
                    }
                }
                _ => (404, json!({"error": "GET /status, POST /stop/RENTAL"})),
            }
        }))?;
    }
    eprintln!("hasher: serving; renting {}", if settings.enabled && settings.fallback.is_some() { "on" } else { "off" });
    let mut seen = mtime(&path);
    let mut last_cap: Option<(Capacity, bool, Terms, String)> = None;
    let mut last_pub = Instant::now() - REPUBLISH_MAX;
    loop {
        std::thread::sleep(Duration::from_secs(2));
        let m = mtime(&path);
        if m != seen {
            seen = m;
            let next = read_settings(&path, &base);
            if next != settings {
                eprintln!("hasher: new settings: renting {}, fallback {}", if next.enabled { "on" } else { "off" }, next.fallback.as_deref().unwrap_or("none"));
                h.set_terms(next.terms.clone());
                h.set_fallback(next.fallback.clone());
                h.set_rentable(next.rentable);
                h.set_open(next.enabled && next.fallback.is_some());
                settings = next;
                *shared.lock().unwrap_or_else(|p| p.into_inner()) = settings.clone();
            }
        }
        let Some(r) = f.get("relays") else { continue };
        let renting = settings.enabled && settings.fallback.is_some();
        let cap = if renting { h.capacity() } else { Capacity { free_miners: 0, free_hs: 0, ..h.capacity() } };
        let now = (cap, renting, settings.terms.clone(), settings.name.clone());
        let changed = last_cap.as_ref().is_none_or(|l| {
            // a hashrate that moves a little is not news
            let (a, b) = (l.0.free_hs as f64, cap.free_hs as f64);
            l.0.miners != cap.miners || l.0.free_miners != cap.free_miners || l.1 != renting || l.2 != now.2 || l.3 != now.3 || (a - b).abs() > a.max(b) * 0.25
        });
        if (changed && last_pub.elapsed() > REPUBLISH_MIN) || last_pub.elapsed() > REPUBLISH_MAX {
            if cap.miners == 0 && last_cap.is_none() && last_pub.elapsed() < REPUBLISH_MAX {
                // nothing to say yet: no miner has connected
                continue;
            }
            last_pub = Instant::now();
            let mut fl = f.clone();
            fl.insert("name".into(), settings.name.clone());
            if settings.pay_node.is_none() {
                if let Some(n) = f.get("gateway").and_then(|g| gateway_node(g)) {
                    settings.pay_node = Some(n);
                    *shared.lock().unwrap_or_else(|p| p.into_inner()) = settings.clone();
                }
            }
            for (k, v) in [("link-public", &settings.link_public), ("pay-url", &settings.pay_url), ("pay-node", &settings.pay_node)] {
                match v {
                    Some(v) => {
                        fl.insert(k.into(), v.clone());
                    }
                    None => {
                        *published.lock().unwrap_or_else(|p| p.into_inner()) =
                            json!({"ok": false, "why": format!("not published: {k} is not set yet"), "atMs": xbt_hashlink::now_ms()});
                        last_cap = Some(now.clone());
                    }
                }
            }
            if fl.get("link-public").is_none() || fl.get("pay-url").is_none() || fl.get("pay-node").is_none() {
                continue;
            }
            let res = super::listing_of(&fl, &key_of(f)?, &settings.terms, cap).and_then(|l| super::publish(&fl, r, &key_of(f)?, &l).map(|_| l));
            *published.lock().unwrap_or_else(|p| p.into_inner()) = match &res {
                Ok(l) => json!({"ok": true, "atMs": xbt_hashlink::now_ms(), "freeMiners": l.capacity.free_miners, "miners": l.capacity.miners}),
                Err(e) => json!({"ok": false, "why": e, "atMs": xbt_hashlink::now_ms()}),
            };
            last_cap = Some(now);
        }
    }
}

fn key_of(f: &HashMap<String, String>) -> Result<SecretKey, String> {
    super::read_key(super::need(f, "key")?)
}
