//! `xbt-hashlink hashmaker --fallback ...`: the hashmaker's side as a service. Miners not rented hash at
//! the fallback; any number of hashtakers rent whole miners; the listing on Nostr says what is free
//! and is published again when that changes. The app writes the settings file (`--config`), and
//! reads the state from the control page.
//!
//! Settings file (JSON; every key optional, a flag gives the default):
//! `{"enabled": true, "fallback": "host:port", "priceSat": 40, "sliceWork": "140737488355328",
//!   "graceMs": 45000, "rentable": 3, "name": "My miners", "linkPublic": "host:port",
//!   "payUrl": "https://shop.example/hashrate", "payNode": "02…", "minersPublic": "host:port"}`
//!
//! `linkPublic` is the address hashtakers outside this network reach the link at (a port forward or a
//! tunnel). Without it no listing goes to the relays: an address only the LAN can reach would send
//! hashtakers nowhere. `--link-lan` is the address shown for hashtakers on the same network.
//!
//! Without `payNode`, the node is read from the hashmaker's gateway (`--gateway`, its `/services`).
//! A missing `--key` or `--nostr-key` file is made at the first start.

use crate::http;
use secp256k1::SecretKey;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use xbt_hashlink::hashmaker::{self, Hashmaker};
use xbt_hashlink::listing::Capacity;
use xbt_hashlink::msg::Terms;
use xbt_hashlink::rail::LabSeller;

/// A change in what is for rent (miners, free miners, renting on or off, the terms, the name, or
/// where hashtakers reach and pay the hashmaker) is published again after at least this long since the last publish.
const REPUBLISH_CAPACITY: Duration = Duration::from_secs(60);
/// A change in the measured hashrate alone is news only when it moves more than this share of the
/// published value, and is published at most this often: public relays rate-limit.
const REPUBLISH_HASHRATE: Duration = Duration::from_secs(600);
const HASHRATE_MOVE: f64 = 0.20;
/// And at least this often, so relays keep it (as the gateway's listing).
const REPUBLISH_MAX: Duration = Duration::from_secs(6 * 3600);

/// What a published listing said, to compare the next one against.
#[derive(Clone, Debug, PartialEq)]
struct Said {
    cap: Capacity,
    renting: bool,
    terms: Terms,
    name: String,
    /// Where hashtakers reach the link and pay for the work: an owner setting the address hashtakers
    /// use is news, not a wait for the long timer.
    link_public: Option<String>,
    pay_url: Option<String>,
    pay_node: Option<String>,
}

/// Whether to publish now, `since` after the last attempt (`ok`: whether it was taken).
fn due(last: Option<(&Said, bool)>, now: &Said, since: Duration) -> bool {
    let Some((l, ok)) = last else {
        // the first: once a miner is there to offer
        return now.cap.miners > 0;
    };
    if since >= REPUBLISH_MAX || (!ok && since >= REPUBLISH_CAPACITY) {
        return true;
    }
    let what = l.cap.miners != now.cap.miners
        || l.cap.free_miners != now.cap.free_miners
        || l.renting != now.renting
        || l.terms != now.terms
        || l.name != now.name
        || l.link_public != now.link_public
        || l.pay_url != now.pay_url
        || l.pay_node != now.pay_node;
    if what {
        return since >= REPUBLISH_CAPACITY;
    }
    let (a, b) = (l.cap.free_hs as f64, now.cap.free_hs as f64);
    (a - b).abs() > a.max(1.0) * HASHRATE_MOVE && since >= REPUBLISH_HASHRATE
}

#[derive(Clone, Debug, PartialEq)]
struct Settings {
    enabled: bool,
    fallback: Option<String>,
    terms: Terms,
    rentable: Option<u32>,
    name: String,
    /// Where hashtakers' apps reach the link, where slices are paid and the node paid, as published.
    link_public: Option<String>,
    pay_url: Option<String>,
    pay_node: Option<String>,
    /// The address the hashmaker's miners use (shown by the app).
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
    let h = Arc::new(Hashmaker::start(
        hashmaker::Config {
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
        let link_lan = f.get("link-lan").cloned().or_else(|| f.get("link").cloned()).unwrap_or_default();
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
                    v["linkLan"] = json!(link_lan);
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
    eprintln!("hashmaker: serving; renting {}", if settings.enabled && settings.fallback.is_some() { "on" } else { "off" });
    let mut seen = mtime(&path);
    let mut last: Option<(Said, bool)> = None;
    let mut last_pub = Instant::now();
    loop {
        std::thread::sleep(Duration::from_secs(2));
        let m = mtime(&path);
        if m != seen {
            seen = m;
            let next = read_settings(&path, &base);
            if next != settings {
                eprintln!("hashmaker: new settings: renting {}, fallback {}", if next.enabled { "on" } else { "off" }, next.fallback.as_deref().unwrap_or("none"));
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
        // the node is asked before comparing, so learning it is not itself a change to publish
        if settings.pay_node.is_none() {
            if let Some(n) = f.get("gateway").and_then(|g| gateway_node(g)) {
                settings.pay_node = Some(n);
                *shared.lock().unwrap_or_else(|p| p.into_inner()) = settings.clone();
            }
        }
        let now = Said { cap, renting, terms: settings.terms.clone(), name: settings.name.clone(),
                         link_public: settings.link_public.clone(), pay_url: settings.pay_url.clone(), pay_node: settings.pay_node.clone() };
        if !due(last.as_ref().map(|(s, ok)| (s, *ok)), &now, last_pub.elapsed()) {
            continue;
        }
        // no public address hashtakers can reach: no listing on public relays (one naming an address
        // only the LAN can reach would send hashtakers nowhere)
        let missing = [
            ("link-public", &settings.link_public, "Add the address hashtakers use to reach your miners (it needs a port forward or a tunnel). Until then your offer is not published; hashtakers on your own network can still use this box's address."),
            ("pay-url", &settings.pay_url, "Set your shop's public address on the Sell page first."),
            ("pay-node", &settings.pay_node, "Your shop's Lightning node is not known yet."),
        ]
        .into_iter()
        .find(|(_, v, _)| v.is_none());
        if let Some((k, _, why)) = missing {
            let was = published.lock().unwrap_or_else(|p| p.into_inner()).clone();
            if was.get("missing").and_then(Value::as_str) != Some(k) {
                eprintln!("hashmaker: listing not published: {k} is not set");
            }
            *published.lock().unwrap_or_else(|p| p.into_inner()) = json!({"ok": false, "missing": k, "why": why, "atMs": xbt_hashlink::now_ms()});
            // asked again only when something changes, or after the long timer
            last = Some((now, true));
            last_pub = Instant::now();
            continue;
        }
        let mut fl = f.clone();
        fl.insert("name".into(), settings.name.clone());
        for (k, v) in [("link-public", &settings.link_public), ("pay-url", &settings.pay_url), ("pay-node", &settings.pay_node)] {
            if let Some(v) = v {
                fl.insert(k.into(), v.clone());
            }
        }
        let res = super::listing_of(&fl, &key_of(f)?, &settings.terms, cap).and_then(|l| super::publish(&fl, r, &key_of(f)?, &l).map(|_| l));
        *published.lock().unwrap_or_else(|p| p.into_inner()) = match &res {
            Ok(l) => json!({"ok": true, "atMs": xbt_hashlink::now_ms(), "freeMiners": l.capacity.free_miners, "miners": l.capacity.miners}),
            Err(e) => json!({"ok": false, "why": e, "atMs": xbt_hashlink::now_ms()}),
        };
        last = Some((now, res.is_ok()));
        last_pub = Instant::now();
    }
}

fn key_of(f: &HashMap<String, String>) -> Result<SecretKey, String> {
    super::read_key(super::need(f, "key")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn said(miners: u32, free: u32, hs: u64) -> Said {
        Said { cap: Capacity { miners, free_miners: free, free_hs: hs }, renting: true, terms: Terms { slice_work: 1 << 47, price_msat: 40_000, grace_ms: 45_000 }, name: "m".into(),
              link_public: None, pay_url: Some("https://box.example/hashrate".into()), pay_node: Some("02aa".into()) }
    }
    const S: fn(u64) -> Duration = Duration::from_secs;

    #[test]
    fn a_wobbling_hashrate_is_not_republished() {
        let last = said(1, 1, 4_000_000_000_000);
        // 2.9 TH/s against 4.0 published: a 27% move, but only ten minutes after the last publish
        let now = said(1, 1, 2_900_000_000_000);
        assert!(!due(Some((&last, true)), &now, S(30)));
        assert!(!due(Some((&last, true)), &now, S(599)));
        assert!(due(Some((&last, true)), &now, S(600)));
        // a move under 20% waits for the long timer
        let small = said(1, 1, 3_500_000_000_000);
        assert!(!due(Some((&last, true)), &small, S(3 * 3600)));
        assert!(due(Some((&last, true)), &small, S(6 * 3600)));
    }

    #[test]
    fn what_is_for_rent_is_republished_after_a_minute() {
        let last = said(1, 1, 4_000_000_000_000);
        let rented = said(1, 0, 0);
        assert!(!due(Some((&last, true)), &rented, S(59)));
        assert!(due(Some((&last, true)), &rented, S(60)));
        let mut off = last.clone();
        off.renting = false;
        assert!(due(Some((&last, true)), &off, S(60)));
        let mut priced = last.clone();
        priced.terms.price_msat = 50_000;
        assert!(due(Some((&last, true)), &priced, S(60)));
    }

    #[test]
    fn setting_the_address_hashtakers_use_is_published_after_a_minute() {
        // the owner adds the address after the "not set" check: published within the minute, not the long timer
        let last = said(1, 1, 4_000_000_000_000);
        let mut set = last.clone();
        set.link_public = Some("203.0.113.7:23341".into());
        assert!(!due(Some((&last, true)), &set, S(30)));
        assert!(due(Some((&last, true)), &set, S(60)));
        let mut moved = set.clone();
        moved.pay_url = Some("https://other.example/hashrate".into());
        assert!(due(Some((&set, true)), &moved, S(60)));
        let mut node = set.clone();
        node.pay_node = Some("02bb".into());
        assert!(due(Some((&set, true)), &node, S(60)));
        assert!(!due(Some((&set, true)), &set.clone(), S(3600)), "unchanged: the long timer");
    }

    #[test]
    fn the_first_waits_for_a_miner_and_a_refusal_is_retried_after_a_minute() {
        assert!(!due(None, &said(0, 0, 0), S(0)));
        assert!(due(None, &said(1, 1, 1), S(0)));
        let last = said(1, 1, 4_000_000_000_000);
        assert!(!due(Some((&last, false)), &last, S(30)));
        assert!(due(Some((&last, false)), &last, S(60)));
        assert!(!due(Some((&last, true)), &last, S(3600)));
    }

    #[test]
    fn six_wobbles_in_two_minutes_publish_once() {
        // what the box saw: the measured rate moving every 20 s
        let rates = [4.1e12, 2.9e12, 3.8e12, 2.6e12, 4.4e12, 3.0e12, 3.9e12];
        let mut last: Option<(Said, bool)> = None;
        let mut since = S(0);
        let mut published = 0;
        for r in rates {
            let now = said(1, 1, r as u64);
            if due(last.as_ref().map(|(s, ok)| (s, *ok)), &now, since) {
                published += 1;
                last = Some((now, true));
                since = S(0);
            }
            since += S(20);
        }
        assert_eq!(published, 1);
    }
}
