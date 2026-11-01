//! `xbt-hashlink hashmaker --fallback ...`: the hashmaker's side as a service. Miners not rented hash at
//! the fallback; any number of hashtakers rent whole miners; the listing on Nostr says what is free
//! and is published again when that changes. The app writes the settings file (`--config`), and
//! reads the state from the control page.
//!
//! Settings file (JSON; every key optional, a flag gives the default):
//! `{"enabled": true, "fallback": "host:port", "priceSat": 404, "sliceWork": "35184372088832", "startSlices": 2,
//!   "graceMs": 45000, "rentable": 3, "name": "My miners", "linkPublic": "host:port",
//!   "payUrl": "https://shop.example/hashrate", "payNode": "02…", "minersPublic": "host:port",
//!   "priceSeenMs": 1790000000000, "holdNew": false, "awaitSpeed": false}`
//!
//! **The price is the app's.** It alone can read the difficulty (through the signer, which this service,
//! open to the internet, has no way to reach), so it works out `priceSat`, `sliceWork` and `startSlices`
//! and writes the same price into the gateway's route. Here they are only read, and:
//! * a rental keeps the terms it was made with ([`Hashmaker::set_terms`]);
//! * no price yet, a live price the app stopped confirming (`priceSeenMs`, [`PRICE_MAX_AGE_MS`]), or
//!   `holdNew` (a new price waiting for the rentals going on to end) takes no new rental, and leaves the
//!   ones going on alone;
//! * a listing goes out only when the gateway charges what its terms say ([`route_price_msat`]).
//!
//! Hashtakers reach the link over iroh by default (`--iroh off` turns it off; `--iroh-relays` names
//! relays, `none` for direct only): the listing names the link's iroh key and relay, and no port
//! forward is needed. `linkPublic` is, besides, an address hashtakers outside this network reach the
//! link at over plain TCP (a port forward or a tunnel), for hashtakers on apps from before the iroh
//! link. With neither, no listing goes to the relays: an address only the LAN can reach would send
//! hashtakers nowhere. `--link-lan` is the address shown for hashtakers on the same network.
//!
//! Without `payNode`, the node is read from the hashmaker's gateway (`--gateway`, its `/services`).
//!
//! With relays and a Nostr key set, the hashmaker also publishes a signed summary of the rentals it
//! served (by the same commitments the hashtakers' delivery records use, [`xbt_hashlink::trust`]),
//! at most every ten minutes after a rental ends. It is kept in `hash-summary.json` beside the
//! settings file, so it survives a restart.
//! A missing `--key` or `--nostr-key` file is made at the first start.

use crate::http;
use secp256k1::SecretKey;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use xbt_hashlink::hashmaker::{self, Hashmaker};
use xbt_hashlink::listing::{self, Capacity, IrohLink};
use xbt_hashlink::msg::Terms;
use xbt_hashlink::over_iroh;
use xbt_hashlink::rail::LabSeller;
use xbt_hashlink::trust;

/// A change in what is for rent (miners, free miners, renting on or off, the terms, the name, or
/// where hashtakers reach and pay the hashmaker) is published again after at least this long since the last publish.
const REPUBLISH_CAPACITY: Duration = Duration::from_secs(60);
/// A change in the measured hashrate alone is news only when it moves more than this share of the
/// published value, and is published at most this often: public relays rate-limit.
const REPUBLISH_HASHRATE: Duration = Duration::from_secs(600);
const HASHRATE_MOVE: f64 = 0.20;
/// And at least this often, so relays keep it (as the gateway's listing).
const REPUBLISH_MAX: Duration = Duration::from_secs(6 * 3600);

/// A slice's work when neither the flag nor the app says: about one share of an S11 (4 TH/s).
const DEFAULT_SLICE_WORK: u128 = 1 << 45;
/// A live price the app has not confirmed for this long takes no new rental. The difficulty moves only
/// every 2016 blocks, so this rides out a node or a signer restarting.
const PRICE_MAX_AGE_MS: u64 = 3_600_000;
/// The gateway's route for paid slices (the app writes it, `hash_route`).
const HASH_ROUTE: &str = "/hashrate/";

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
    /// The iroh link's key and relay: a new relay is news too.
    iroh: Option<IrohLink>,
    pay_url: Option<String>,
    pay_node: Option<String>,
    /// The app has sized the slice to a measured miner: until then there is no listing.
    sized: bool,
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
        || l.iroh != now.iroh
        || l.pay_url != now.pay_url
        || l.pay_node != now.pay_node
        || l.sized != now.sized;
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
    /// A new price waits for the rentals going on to end: no new rental till then.
    hold_new: bool,
    /// The app has not measured a miner to size the slice to yet.
    await_speed: bool,
    /// When the app last confirmed a live price against the chain. None: a price the owner typed.
    price_seen_ms: Option<u64>,
}

/// Why no new rental is taken now, if so. The rentals going on are not touched by any of these.
fn paused(s: &Settings, now_ms: u64) -> Option<&'static str> {
    if s.terms.price_msat == 0 {
        Some("no price yet")
    } else if s.await_speed {
        Some("no miner measured yet")
    } else if s.hold_new {
        Some("a new price waits for the rentals going on to end")
    } else if s.price_seen_ms.is_some_and(|t| now_ms.saturating_sub(t) > PRICE_MAX_AGE_MS) {
        Some("the live price has not been confirmed for over an hour")
    } else {
        None
    }
}

/// The miners rentals may take now: none while [`paused`]. ([`Hashmaker::set_open`] would end the rentals going on.)
fn rentable_now(s: &Settings, now_ms: u64) -> Option<u32> {
    if paused(s, now_ms).is_some() {
        Some(0)
    } else {
        s.rentable
    }
}

fn defaults(f: &HashMap<String, String>) -> Result<Settings, String> {
    Ok(Settings {
        enabled: !f.contains_key("config"),
        fallback: f.get("fallback").cloned().filter(|a| !a.is_empty()),
        terms: Terms {
            slice_work: super::num(f, "slice-work", Some(DEFAULT_SLICE_WORK))?,
            // with a settings file the app says the price (0: none yet, and no rental); without one, the flag must
            price_msat: super::num(f, "price-msat", f.contains_key("config").then_some(0))?,
            grace_ms: super::num(f, "grace-ms", Some(45_000))?,
            start_slices: super::num(f, "start-slices", Some(0))?,
        },
        rentable: f.get("rentable").map(|v| v.parse()).transpose().map_err(|_| "--rentable")?,
        name: f.get("name").cloned().unwrap_or_else(|| "Hashrate".into()),
        link_public: f.get("link-public").cloned(),
        pay_url: f.get("pay-url").cloned(),
        pay_node: f.get("pay-node").cloned(),
        miners_public: f.get("miners-public").cloned(),
        hold_new: false,
        await_speed: false,
        price_seen_ms: None,
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
        s.terms.price_msat = p.saturating_mul(1000);
    }
    if let Some(n) = v.get("startSlices").and_then(Value::as_u64) {
        s.terms.start_slices = n;
    }
    s.hold_new = v.get("holdNew").and_then(Value::as_bool).unwrap_or(false);
    s.await_speed = v.get("awaitSpeed").and_then(Value::as_bool).unwrap_or(false);
    s.price_seen_ms = v.get("priceSeenMs").and_then(Value::as_u64);
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

/// A gateway's `/services`.
fn gateway_services(base: &str) -> Option<Value> {
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
    serde_json::from_str::<Value>(body).ok()
}

/// The node a gateway's tickets pay (`payTo` of its `/services`).
fn gateway_node(base: &str) -> Option<String> {
    gateway_services(base)?.get("payTo")?.as_str().map(str::to_string)
}

/// What a gateway charges for a paid slice now, from its `/services`.
fn route_price_msat(services: &Value) -> Option<u64> {
    services.get("routes")?.as_array()?.iter().find(|r| r.get("path").and_then(Value::as_str) == Some(HASH_ROUTE))?.pointer("/price/requestMsat")?.as_str()?.parse().ok()
}

/// What a listing still lacks, and why, in the owner's words.
fn missing(s: &Settings, reach: &Option<String>) -> Option<(&'static str, &'static str)> {
    if s.terms.price_msat == 0 {
        return Some(("price", "There is no price yet: the app has not been able to read today's difficulty from your XBT node."));
    }
    if s.await_speed {
        return Some(("speed", "Your offer is published once a miner has hashed for a couple of minutes: its pieces of work are sized to its speed."));
    }
    [
        ("link", reach, "Your miners cannot be reached from outside yet: the direct link has not found our relay. Check this box's internet connection; your offer is published once it has."),
        ("pay-url", &s.pay_url, "Set your shop's public address on the Sell page first."),
        ("pay-node", &s.pay_node, "Your shop's Lightning node is not known yet."),
    ]
    .into_iter()
    .find(|(_, v, _)| v.is_none())
    .map(|(k, _, why)| (k, why))
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
            rentable: rentable_now(&settings, xbt_hashlink::now_ms()),
            min_slice_time: hashmaker::MIN_SLICE_TIME,
        },
        Box::new(|| Box::<LabSeller>::default()),
    )?);
    h.set_open(settings.enabled && settings.fallback.is_some());
    // the link over iroh: hashtakers reach it by key, through our relay or directly, with no port
    // forward; the Noise handshake inside each stream is the same as over TCP
    let iroh = if f.get("iroh").map(String::as_str) == Some("off") {
        None
    } else {
        match over_iroh::serve(&key, over_iroh::relays(f.get("iroh-relays").map(String::as_str)), super::need(f, "link")?) {
            Ok(l) => Some(l),
            Err(e) => {
                eprintln!("hashmaker: the iroh link did not start ({e}); hashtakers reach the link over TCP only");
                None
            }
        }
    };
    let published: Arc<Mutex<Value>> = Arc::new(Mutex::new(Value::Null));
    let shared = Arc::new(Mutex::new(settings.clone()));
    if let Some(addr) = f.get("control") {
        let (h, published, shared) = (h.clone(), published.clone(), shared.clone());
        let miners_default = f.get("miners").cloned().unwrap_or_default();
        let link_lan = f.get("link-lan").cloned().or_else(|| f.get("link").cloned()).unwrap_or_default();
        let iroh = iroh.clone();
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
                        "startSlices": s.terms.start_slices, "holdNew": s.hold_new,
                    });
                    v["paused"] = json!(paused(&s, xbt_hashlink::now_ms()));
                    v["minersAddress"] = json!(s.miners_public.clone().unwrap_or_else(|| miners_default.clone()));
                    v["linkLan"] = json!(link_lan);
                    v["iroh"] = match &iroh {
                        Some(l) => json!({"id": l.endpoint_id(), "relays": over_iroh::advertise(l, Duration::ZERO).relays}),
                        None => Value::Null,
                    };
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
    let mut rentable = rentable_now(&settings, xbt_hashlink::now_ms());
    let mut last: Option<(Said, bool)> = None;
    let mut last_pub = Instant::now();
    let mut served = Served::load(path.as_ref().map(|p| p.with_file_name("hash-summary.json")));
    loop {
        std::thread::sleep(Duration::from_secs(2));
        if let (Some(r), Some(n)) = (f.get("relays"), f.get("nostr-key")) {
            served.tick(&h, &key, n, r);
        }
        let m = mtime(&path);
        if m != seen {
            seen = m;
            let next = read_settings(&path, &base);
            if next != settings {
                // a price confirmed again is no news
                if (&next.terms, next.enabled, &next.fallback) != (&settings.terms, settings.enabled, &settings.fallback) {
                    eprintln!("hashmaker: new settings: renting {}, fallback {}, {} msat a slice of {}", if next.enabled { "on" } else { "off" },
                              next.fallback.as_deref().unwrap_or("none"), next.terms.price_msat, next.terms.slice_work);
                }
                h.set_terms(next.terms.clone());
                h.set_fallback(next.fallback.clone());
                h.set_open(next.enabled && next.fallback.is_some());
                settings = next;
                *shared.lock().unwrap_or_else(|p| p.into_inner()) = settings.clone();
            }
        }
        // as time goes too: a live price that nothing confirms stops taking rentals
        let want = rentable_now(&settings, xbt_hashlink::now_ms());
        if want != rentable {
            if let Some(why) = paused(&settings, xbt_hashlink::now_ms()) {
                eprintln!("hashmaker: no new rentals: {why}");
            }
            h.set_rentable(want);
            rentable = want;
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
        // the relay the link is found through, once one has answered (a link with no relay yet is
        // not offered: a listing naming no way to reach it would send hashtakers nowhere)
        let iroh_now = iroh.as_ref().map(|l| over_iroh::advertise(l, Duration::from_secs(10))).filter(|i| !i.relays.is_empty() || !i.direct.is_empty());
        let now = Said { cap, renting, terms: settings.terms.clone(), name: settings.name.clone(),
                         link_public: settings.link_public.clone(), iroh: iroh_now.clone(), pay_url: settings.pay_url.clone(), pay_node: settings.pay_node.clone(),
                         sized: !settings.await_speed };
        if !due(last.as_ref().map(|(s, ok)| (s, *ok)), &now, last_pub.elapsed()) {
            continue;
        }
        // no public address hashtakers can reach: no listing on public relays (one naming an address
        // only the LAN can reach would send hashtakers nowhere)
        let reach = iroh_now.as_ref().map(|i| i.id.clone()).or_else(|| settings.link_public.clone());
        if let Some((k, why)) = missing(&settings, &reach) {
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
        // the listing says what a slice costs, and the gateway charges it: a gateway that has not taken a new price
        // yet (it restarts for it) charges another, so the listing waits, and is tried again in a minute
        if let Some(g) = f.get("gateway") {
            let charged = gateway_services(g).as_ref().and_then(route_price_msat);
            if charged != Some(settings.terms.price_msat) {
                eprintln!("hashmaker: listing not published: the gateway charges {charged:?} msat a slice, the terms say {}", settings.terms.price_msat);
                *published.lock().unwrap_or_else(|p| p.into_inner()) = json!({"ok": false, "missing": "route-price", "why": "Your shop is starting with its new price. Your offer is published once it charges that price.", "atMs": xbt_hashlink::now_ms()});
                last = Some((now, false));
                last_pub = Instant::now();
                continue;
            }
        }
        let mut fl = f.clone();
        fl.insert("name".into(), settings.name.clone());
        for (k, v) in [("link-public", &settings.link_public), ("pay-url", &settings.pay_url), ("pay-node", &settings.pay_node)] {
            if let Some(v) = v {
                fl.insert(k.into(), v.clone());
            }
        }
        if let Some(i) = &iroh_now {
            fl.insert("iroh-id".into(), i.id.clone());
            fl.insert("iroh-relays".into(), i.relays.join(","));
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

/// The rentals this hashmaker served, kept in a file so its signed summary survives a restart, and
/// published as that summary (at most every ten minutes, when a rental has ended since).
struct Served {
    file: Option<PathBuf>,
    rentals: std::collections::BTreeMap<String, trust::Served>,
    dirty: bool,
    last: Option<Instant>,
}

impl Served {
    const EVERY: Duration = Duration::from_secs(600);

    fn load(file: Option<PathBuf>) -> Served {
        let rentals = file
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| trust::Summary::from_json(&v))
            .map(|s| s.rentals.into_iter().map(|r| (r.commit.clone(), r)).collect())
            .unwrap_or_default();
        Served { file, rentals, dirty: false, last: None }
    }

    fn tick(&mut self, h: &Hashmaker, key: &SecretKey, nostr_file: &str, relays: &str) {
        let me = secp256k1::PublicKey::from_secret_key(secp256k1::SECP256K1, key);
        for fin in h.finished() {
            let ended = fin.pointer("/stopped/atMs").and_then(Value::as_u64).unwrap_or_else(xbt_hashlink::now_ms) / 1000;
            if let Some(s) = trust::served_of(&fin, &me, ended) {
                if !self.rentals.contains_key(&s.commit) {
                    self.rentals.insert(s.commit.clone(), s);
                    self.dirty = true;
                }
            }
        }
        if !self.dirty || self.last.is_some_and(|t| t.elapsed() < Self::EVERY) {
            return;
        }
        let summary = trust::Summary { hashmaker: me, rentals: self.rentals.values().cloned().collect() };
        if let Some(p) = &self.file {
            let _ = std::fs::write(p, summary.to_json().to_string());
        }
        let Ok(nostr) = super::read_key(nostr_file).map(xbt_nostr::event::Keys::new) else { return };
        self.last = Some(Instant::now());
        match summary.event(&nostr, xbt_nostr::now()) {
            Ok(ev) => {
                let said = listing::publish(&super::relays(relays), &ev);
                if said.iter().any(|s| s["ok"] == true) {
                    self.dirty = false;
                }
                eprintln!("hashmaker: delivery summary ({} rentals) published: {}", summary.rentals.len(), Value::from(said));
            }
            Err(e) => eprintln!("hashmaker: delivery summary not published: {e}"),
        }
    }
}

fn key_of(f: &HashMap<String, String>) -> Result<SecretKey, String> {
    super::read_key(super::need(f, "key")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn said(miners: u32, free: u32, hs: u64) -> Said {
        Said { cap: Capacity { miners, free_miners: free, free_hs: hs }, renting: true, terms: Terms { slice_work: 1 << 47, price_msat: 40_000, grace_ms: 45_000, start_slices: 0 }, name: "m".into(),
              link_public: None, iroh: None, pay_url: Some("https://box.example/hashrate".into()), pay_node: Some("02aa".into()), sized: true }
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
        // the iroh link finding (another) relay is news the same way
        let mut relayed = set.clone();
        relayed.iroh = Some(IrohLink { id: "ab".repeat(32), relays: vec!["https://relay.example".into()], direct: vec![] });
        assert!(!due(Some((&set, true)), &relayed, S(30)));
        assert!(due(Some((&set, true)), &relayed, S(60)));
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

    fn settings(file: Value) -> Settings {
        let d = std::env::temp_dir().join(format!("hashmaker-service-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("settings.json");
        std::fs::write(&p, file.to_string()).unwrap();
        let flags = HashMap::from([("config".to_string(), p.display().to_string())]);
        read_settings(&Some(p), &defaults(&flags).unwrap())
    }

    #[test]
    fn with_no_price_from_the_app_nothing_is_for_rent_and_no_40_sat_default_is_left() {
        let s = settings(json!({"enabled": true, "fallback": "pool:3333"}));
        assert_eq!((s.terms.price_msat, s.terms.slice_work), (0, 1 << 45));
        assert_eq!(paused(&s, 1), Some("no price yet"));
        assert_eq!(rentable_now(&s, 1), Some(0));
        assert_eq!(missing(&s, &Some("x".into())).map(|m| m.0), Some("price"));
        // by hand, without a settings file, the flag must say it
        assert!(defaults(&HashMap::new()).is_err());
    }

    #[test]
    fn the_terms_are_what_the_app_wrote() {
        let s = settings(json!({"enabled": true, "fallback": "pool:3333", "priceSat": 404, "sliceWork": "35184372088832", "startSlices": 2}));
        assert_eq!(s.terms, Terms { slice_work: 1 << 45, price_msat: 404_000, grace_ms: 45_000, start_slices: 2 });
        assert_eq!(paused(&s, u64::MAX), None, "a typed price has nothing to go stale");
    }

    #[test]
    fn a_live_price_nobody_confirms_stops_new_rentals_and_says_why() {
        let s = settings(json!({"enabled": true, "fallback": "pool:3333", "priceSat": 404, "priceSeenMs": 1_000, "rentable": 3}));
        assert_eq!(rentable_now(&s, 1_000 + PRICE_MAX_AGE_MS), Some(3));
        assert_eq!(rentable_now(&s, 1_001 + PRICE_MAX_AGE_MS), Some(0));
        assert!(paused(&s, 1_001 + PRICE_MAX_AGE_MS).unwrap().contains("not been confirmed"));
    }

    #[test]
    fn a_new_price_waiting_takes_no_new_rental_and_a_slice_not_sized_yet_is_not_listed() {
        let held = settings(json!({"priceSat": 404, "holdNew": true, "rentable": 3}));
        assert_eq!(rentable_now(&held, 1), Some(0));
        assert_eq!(missing(&held, &Some("x".into())).map(|m| m.0), Some("pay-url"), "listed, as nothing free");
        let new = settings(json!({"priceSat": 404, "awaitSpeed": true}));
        assert_eq!(rentable_now(&new, 1), Some(0));
        assert_eq!(missing(&new, &Some("x".into())).map(|m| m.0), Some("speed"));
        // once it is sized, that is news at once, whatever the terms
        let (mut a, mut b) = (said(1, 1, 1), said(1, 1, 1));
        a.sized = false;
        b.sized = true;
        assert!(due(Some((&a, true)), &b, S(60)));
    }

    #[test]
    fn the_price_a_gateway_charges_is_read_from_its_services() {
        // as the gateway writes it (Price::terms)
        let v = json!({"payTo": "02aa", "routes": [{"path": "/films/", "price": {"requestMsat": "5"}},
                                                    {"path": "/hashrate/", "methods": ["POST"], "price": {"requestMsat": "404000", "byteMsat": "0", "perBytes": "1", "secondMsat": "0"}}]});
        assert_eq!(route_price_msat(&v), Some(404_000));
        assert_eq!(route_price_msat(&json!({"routes": [{"path": "/films/", "price": {"requestMsat": "5"}}]})), None, "no route: no price");
        assert_eq!(route_price_msat(&json!({})), None);
    }

    #[test]
    fn a_speed_that_wobbles_does_not_change_the_terms_or_publish_more() {
        let terms = said(1, 1, 1).terms;
        let last = said(1, 1, 4_000_000_000_000);
        for hs in [2_900_000_000_000, 4_400_000_000_000, 3_300_000_000_000] {
            let now = said(1, 1, hs);
            assert_eq!(now.terms, terms);
            assert!(!due(Some((&last, true)), &now, S(120)), "{hs}");
        }
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
