//! Sell (`XBT_UI_SELL=1`): the gateway's setup inside the one Lightning Stream app, for an owner
//! who is not a technician. What the owner sells is a list of services, each a kind (a media
//! server, an AI model, another web service), the address this box reaches it at, and a price in
//! sats. The page keeps that list in `sell.json` in the UI's data dir, and writes the gateway's
//! `config.json` from it: one route per service, each to its own upstream, and a signed
//! `listing/1` that names them all. Settings the page does not show (tickets, the lottery,
//! timings, a route's methods and headers) are kept from the config as it was.
//!
//! The words on the page are plain; the gateway's own terms stay under "Advanced".
use std::collections::HashMap;
use std::path::PathBuf;

use serde_json::{json, Map, Value};
use xbt_gateway::config::{Config as GatewayConfig, MAINNET_ACK, MAINNET_NOTICE, MAX_NOSTR_RELAYS};
use xbt_gateway::node::{checked_macaroon, INFO_OPS, INVOICE_OPS};

use crate::setup::{decode_macaroon, pin_card, pin_cert, write_shared, GATEWAY_CONNECTIONS, GW_CONFIG, GW_INFO, GW_INVOICES, GW_SIGN, MAINNET_CAPS, TEST_CAPS};
use crate::node_keys::{SIGN_ENTITY_OPS, SIGN_OPS};
use super::{App, Ctx};
use crate::html::{esc, json_block};
use crate::server::Resp;

pub const SELL_FILE: &str = "sell.json";
pub const MAX_SERVICES: usize = 16;
const MIB: u64 = 1_048_576;
const GB: u64 = 1_000_000_000;

/// The kinds an owner picks from, with the words, the listing's kind, and the suggested price.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Media,
    /// A folder on this box, served by the app itself ([`crate::files`]).
    Files,
    Ai,
    Web,
    Other,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "media" => Some(Kind::Media),
            "files" => Some(Kind::Files),
            "ai" => Some(Kind::Ai),
            "web" => Some(Kind::Web),
            "other" => Some(Kind::Other),
            _ => None,
        }
    }
    pub fn id(self) -> &'static str {
        match self {
            Kind::Media => "media",
            Kind::Files => "files",
            Kind::Ai => "ai",
            Kind::Web => "web",
            Kind::Other => "other",
        }
    }
    pub fn words(self) -> &'static str {
        match self {
            Kind::Media => "Media server",
            Kind::Files => "Files",
            Kind::Ai => "AI model",
            Kind::Web => "Web service or API",
            Kind::Other => "Something else",
        }
    }
    /// How the status names the service when it cannot be reached.
    fn thing(self) -> &'static str {
        match self {
            Kind::Media => "your media server",
            Kind::Files => "your shared folder",
            Kind::Ai => "your AI model",
            Kind::Web | Kind::Other => "your service",
        }
    }
    fn listing_kind(self) -> &'static str {
        match self {
            Kind::Media => "video",
            Kind::Files => "files",
            Kind::Ai => "ai",
            Kind::Web | Kind::Other => "api",
        }
    }
    fn from_listing(k: &str) -> Self {
        match k {
            "video" => Kind::Media,
            "ai" => Kind::Ai,
            "files" => Kind::Files,
            _ => Kind::Web,
        }
    }
    /// The suggested price: (sats, unit).
    pub fn suggested(self) -> (&'static str, Unit) {
        match self {
            Kind::Media => ("20", Unit::Mib),
            // a film of a few GB for a few thousand sats
            Kind::Files => ("1000", Unit::Gb),
            // a few sats for a reply of a few hundred tokens
            Kind::Ai => ("10", Unit::Tokens),
            Kind::Web | Kind::Other => ("1", Unit::Request),
        }
    }
    fn example(self) -> &'static str {
        match self {
            Kind::Media => "http://jellyfin:8096",
            Kind::Files => "nothing: the app serves the folder itself",
            Kind::Ai => "http://ollama:11434",
            Kind::Web | Kind::Other => "http://my-app:8080",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    Mib,
    /// 1,000,000,000 bytes sent.
    Gb,
    Request,
    Second,
    /// 1,000 tokens an AI model writes (an OpenAI-compatible service).
    Tokens,
}

impl Unit {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "mib" => Some(Unit::Mib),
            "gb" => Some(Unit::Gb),
            "request" => Some(Unit::Request),
            "second" => Some(Unit::Second),
            "tokens" => Some(Unit::Tokens),
            _ => None,
        }
    }
    pub fn id(self) -> &'static str {
        match self {
            Unit::Mib => "mib",
            Unit::Gb => "gb",
            Unit::Request => "request",
            Unit::Second => "second",
            Unit::Tokens => "tokens",
        }
    }
    fn words(self) -> &'static str {
        match self {
            Unit::Mib => "a MiB of data sent",
            Unit::Gb => "a GB of data sent",
            Unit::Request => "a request",
            Unit::Second => "a second",
            Unit::Tokens => "1,000 tokens the model writes",
        }
    }
    fn short(self) -> &'static str {
        match self {
            Unit::Mib => "a MiB",
            Unit::Gb => "a GB",
            Unit::Request => "a request",
            Unit::Second => "a second",
            Unit::Tokens => "per 1,000 tokens",
        }
    }
}

/// One thing the owner sells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    /// Where this box reaches it: `http://host:port`.
    pub address: String,
    /// The price in millisats a unit.
    pub price_msat: u64,
    pub unit: Unit,
    /// Priced by the token: millisats per 1,000 tokens of the question (input); 0, the default: free.
    pub input_msat: u64,
    pub paused: bool,
    /// The gateway routes it is sold under (Advanced). The first is the listing's.
    pub paths: Vec<String>,
    /// Pass requests on without the route's path.
    pub strip: bool,
    /// What buyers can pick, as `(title, link)`.
    pub titles: Vec<(String, String)>,
    /// Buyers may open the service's own web page inside their app (docs/SELLER-APPS.md).
    pub app: Option<OfferApp>,
    /// How many buyers and streams it takes at once (the routes' `capacity`, docs/CAPACITY.md).
    pub capacity: xbt_gateway::config::Capacity,
}

/// A service's own web page, sold to buyers who open it inside their app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferApp {
    /// What the page sees as `/`: a path ending in `/`. Requests under it go to the service.
    pub base: String,
    /// Where it opens, under `base`.
    pub entry: String,
    /// A header the shop adds to every request of the page (`Name: value`): the seller's guest
    /// login, for a service that needs one. Empty: none.
    pub login: String,
    /// Paths of the app buyers may not open (its admin, other users'), as the app sees them.
    pub deny: Vec<String>,
    /// When not empty, the only paths of the app buyers may open; where a path is under entries of
    /// both lists, the longer one decides (docs/SELLER-APPS.md).
    pub allow: Vec<String>,
    /// The page's live connections (WebSockets) are carried, paid for by the byte.
    pub live: bool,
    /// Each buyer gets a Jellyfin account of their own, seeing these libraries (their ids), made
    /// with the seller's API key kept beside the gateway's (docs/BUYER-ACCOUNTS.md). `None`: no
    /// accounts.
    pub accounts: Option<Vec<String>>,
}

impl OfferApp {
    /// A path of the app (as the app sees it) as the shop's route sees it: under `base`.
    fn shop_path(&self, p: &str) -> String {
        format!("{}{}", self.base.trim_end_matches('/'), if p.starts_with('/') { p.to_string() } else { format!("/{p}") })
    }
}

/// The paths a seller lists for an app, one per line or comma-separated: each starts with `/`.
fn app_paths(text: &str) -> Result<Vec<String>, String> {
    let mut out = vec![];
    for p in text.split(['\n', ',']).map(str::trim).filter(|p| !p.is_empty()) {
        if !p.starts_with('/') || p.len() > 400 || p.contains(['?', '#', '%', ' ', '\\']) {
            return Err(format!("{p} is not a path: it starts with / and has no spaces."));
        }
        if out.len() >= 60 {
            return Err("At most 60 paths.".into());
        }
        out.push(p.to_string());
    }
    Ok(out)
}

/// The file beside the gateway's config that holds an offer's Jellyfin API key: read by the
/// gateway only, never shown again.
pub(crate) fn app_key_name(id: &str) -> String {
    format!("app-key-{}.key", id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect::<String>())
}

/// A Jellyfin API key as the seller pastes it: letters and digits.
fn api_key(s: &str) -> Result<String, String> {
    let k = s.trim();
    if k.len() < 16 || k.len() > 128 || !k.bytes().all(|c| c.is_ascii_alphanumeric()) {
        return Err("That is not a Jellyfin API key: make one in Jellyfin under Dashboard, API Keys, and paste it here.".into());
    }
    Ok(k.to_string())
}

/// A Jellyfin's libraries as `(id, name)`, asked at `address` with the seller's key. `Err`: what
/// the seller is told.
pub(crate) fn jellyfin_libraries(address: &str, key: &str) -> Result<Vec<(String, String)>, String> {
    let url = format!("{}/Library/VirtualFolders", address.trim_end_matches('/'));
    let agent = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(5)).build();
    let text = match agent.get(&url).set("X-Emby-Token", key).call() {
        Ok(r) => r.into_string().map_err(|e| format!("Jellyfin's answer could not be read: {e}"))?,
        Err(ureq::Error::Status(401 | 403, _)) => return Err("Jellyfin did not accept that API key: make one under Dashboard, API Keys, and paste it here.".into()),
        Err(ureq::Error::Status(code, _)) => return Err(format!("Jellyfin at {address} answered {code}: is this its address?")),
        Err(_) => return Err(format!("Jellyfin did not answer at {address}.")),
    };
    let v: Value = serde_json::from_str(&text).map_err(|_| format!("{address} did not answer as Jellyfin does: is this its address?"))?;
    let libs: Vec<(String, String)> = v.as_array().into_iter().flatten()
        .filter_map(|f| Some((f.get("ItemId")?.as_str()?.to_string(), f.get("Name").and_then(Value::as_str).unwrap_or("").to_string())))
        .filter(|(id, _)| !id.is_empty() && id.len() <= 64 && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'))
        .collect();
    if libs.is_empty() {
        return Err("That Jellyfin has no libraries yet: add one, then save again.".into());
    }
    Ok(libs)
}

/// Request headers a web app needs passed to its service: its cookies, its login and its
/// requests' own marks. The gateway passes no other beyond the always-forwarded ones.
const APP_HEADERS: [&str; 7] = ["cookie", "authorization", "x-emby-authorization", "x-mediabrowser-token", "x-requested-with", "x-csrf-token", "x-api-key"];

/// The gateway's settings as the Sell page shows them: every `upstream_headers` value (an app's
/// login, the files key) is replaced, so a screenshot of the page gives none of them away.
fn hide_header_values(mut c: Value) -> Value {
    fn walk(v: &mut Value) {
        match v {
            Value::Object(m) => {
                for (k, x) in m.iter_mut() {
                    if k == "upstream_headers" {
                        if let Value::Object(h) = x {
                            for val in h.values_mut() {
                                *val = Value::String("(hidden)".into());
                            }
                        }
                    } else {
                        walk(x);
                    }
                }
            }
            Value::Array(a) => a.iter_mut().for_each(walk),
            _ => {}
        }
    }
    walk(&mut c);
    c
}

/// A login header written `Name: value`, as the gateway's `upstream_headers` takes it.
fn login_header(s: &str) -> Result<Option<(String, String)>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let (k, v) = s.split_once(':').ok_or("Write the login header as Name: value, like Authorization: MediaBrowser Token=…")?;
    let (k, v) = (k.trim(), v.trim());
    if k.is_empty() || !k.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') || v.is_empty() || v.len() > 4096
        || !v.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
        return Err("Write the login header as Name: value, in plain characters.".into());
    }
    if ["host", "cookie", "content-length", "connection", "transfer-encoding", "upgrade"].contains(&k.to_ascii_lowercase().as_str()) || k.to_ascii_lowercase().starts_with("payment-") {
        return Err(format!("{k} cannot be the login header."));
    }
    Ok(Some((k.to_string(), v.to_string())))
}

/// A route's settings for a web app: the methods and headers a page uses, a body it may send, and
/// the service's own compressed pages. A route that is not an app's loses them.
fn app_route(m: &mut Map<String, Value>, app: Option<&OfferApp>, key_file: &str) {
    let Some(app) = app else {
        m.remove("accept_gzip");
        m.remove("upstream_headers");
        m.remove("deny_paths");
        m.remove("allow_paths");
        m.remove("websocket");
        m.remove("accounts");
        return;
    };
    // a buyer is known only by a paid session: a free route has no accounts
    match app.accounts.as_ref().filter(|l| !l.is_empty() && !m.contains_key("free")) {
        Some(libraries) => {
            m.insert("accounts".into(), json!({"kind": "jellyfin", "admin_key_file": key_file, "libraries": libraries}));
        }
        None => {
            m.remove("accounts");
        }
    }
    let paths = |list: &[String]| json!(list.iter().map(|p| app.shop_path(p)).collect::<Vec<_>>());
    if app.deny.is_empty() {
        m.remove("deny_paths");
    } else {
        m.insert("deny_paths".into(), paths(&app.deny));
    }
    if app.allow.is_empty() {
        m.remove("allow_paths");
    } else {
        m.insert("allow_paths".into(), paths(&app.allow));
    }
    // a live connection is paid for by the byte: a route priced by the second or the token cannot carry one
    let by_byte = m.get("price").and_then(Value::as_object).is_none_or(|p| !p.keys().any(|k| k.contains("second") || k.contains("1k")));
    if app.live && by_byte {
        m.insert("websocket".into(), json!(true));
    } else {
        m.remove("websocket");
    }
    m.insert("methods".into(), json!(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]));
    let body = m.get("max_body").and_then(Value::as_u64).unwrap_or(0).max(MIB);
    m.insert("max_body".into(), json!(body));
    let mut fw: Vec<String> = m.get("forward_headers").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
    for h in APP_HEADERS {
        if !fw.iter().any(|x| x.eq_ignore_ascii_case(h)) {
            fw.push(h.to_string());
        }
    }
    m.insert("forward_headers".into(), json!(fw));
    m.insert("accept_gzip".into(), json!(true));
    match login_header(&app.login).ok().flatten() {
        Some((k, v)) => {
            m.insert("upstream_headers".into(), json!({k: v}));
        }
        None => {
            m.remove("upstream_headers");
        }
    }
}

impl Offer {
    /// Its price as a buyer reads it: "20 sat a MiB", "10 sat per 1,000 tokens".
    fn price_words(&self) -> String {
        match self.unit {
            Unit::Tokens => xbt402::tokens::price_text(self.input_msat, self.price_msat),
            u => format!("{} sat {}", msat_to_sats(self.price_msat), u.short()),
        }
    }
}

/// The relays a direct link names unless the owner chose others: the project's own first.
pub const DEFAULT_LINK_RELAYS: [&str; 1] = ["https://iroh.lazarus-xbt.xyz"];
/// Where the gateway says how its direct link is doing.
pub const LINK_STATUS_PATH: &str = "/.well-known/lightning-stream-link.json";

/// The shop and its offers: `sell.json`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Shop {
    pub name: String,
    /// Buyers reach the shop over a direct link (`docs/DIRECT-LINKS.md`): no web address, no
    /// certificate, no port forward. `public_url` is then empty.
    pub direct: bool,
    /// The direct link always goes through a relay, so buyers never learn this box's IP address.
    pub private: bool,
    pub public_url: String,
    pub proxies: String,
    pub network: String,
    pub mainnet_ok: bool,
    pub caps: Option<(u64, u64, u64)>,
    pub offers: Vec<Offer>,
}

/// Sats as the owner types them (`20`, `0.5`, `1,000`) in millisats.
pub fn sats_to_msat(s: &str) -> Result<u64, String> {
    let t: String = s.trim().chars().filter(|c| *c != ',' && *c != ' ').collect();
    let (whole, frac) = t.split_once('.').unwrap_or((&t, ""));
    let ok = !t.is_empty() && whole.bytes().all(|c| c.is_ascii_digit()) && frac.bytes().all(|c| c.is_ascii_digit()) && frac.len() <= 3
        && !(whole.is_empty() && frac.is_empty());
    if !ok {
        return Err("The price is a number of sats, like 20 or 0.5.".into());
    }
    let w: u64 = if whole.is_empty() { 0 } else { whole.parse().map_err(|_| "That price is too large.".to_string())? };
    let f: u64 = format!("{frac:0<3}").parse().unwrap_or(0);
    w.checked_mul(1000).and_then(|m| m.checked_add(f)).ok_or_else(|| "That price is too large.".into())
}

/// Millisats as sats for the page: `20`, `0.5`.
pub fn msat_to_sats(m: u64) -> String {
    if m.is_multiple_of(1000) {
        (m / 1000).to_string()
    } else {
        format!("{}.{:03}", m / 1000, m % 1000).trim_end_matches('0').to_string()
    }
}

fn slug(name: &str) -> String {
    let mut s = String::new();
    for c in name.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() {
            s.push(c);
        } else if !s.ends_with('-') && !s.is_empty() {
            s.push('-');
        }
    }
    let s = s.trim_end_matches('-').chars().take(32).collect::<String>();
    if s.is_empty() { "service".into() } else { s }
}

/// A service's address: `http://host[:port][/path]`, which the gateway can pass requests to.
fn check_address(a: &str, kind: Kind) -> Result<String, String> {
    let a = a.trim().trim_end_matches('/');
    if a.is_empty() {
        return Err(format!("Paste the address of {} on this box, like {}.", kind.thing(), kind.example()));
    }
    if a.starts_with("https://") {
        return Err(format!("Use the plain http:// address of {} on this box (the one other apps on the box use), not its https one.", kind.thing()));
    }
    if !a.starts_with("http://") || a.len() <= 7 || a.contains(['?', '#', '@', ' ', '\\']) {
        return Err(format!("That is not an address this box can reach. It looks like {}.", kind.example()));
    }
    Ok(a.to_string())
}

fn offer_json(o: &Offer) -> Value {
    let mut v = json!({"id": o.id, "name": o.name, "kind": o.kind.id(), "address": o.address, "price_msat": o.price_msat, "unit": o.unit.id(), "input_msat": o.input_msat,
           "paused": o.paused, "paths": o.paths, "strip": o.strip,
           "titles": o.titles.iter().map(|(t, u)| json!({"title": t, "url": u})).collect::<Vec<_>>()});
    if o.capacity.is_set() {
        let c = o.capacity;
        v["capacity"] = json!({"max_buyers": c.max_buyers, "max_streams": c.max_streams, "max_streams_per_buyer": c.max_streams_per_buyer, "max_mbit": c.max_mbit});
    }
    if let Some(a) = &o.app {
        v["app"] = json!({"base": a.base, "entry": a.entry, "login": a.login, "deny": a.deny, "allow": a.allow, "live": a.live});
        if let Some(l) = &a.accounts {
            v["app"]["accounts"] = json!(l);
        }
    }
    v
}

fn offer_of(v: &Value) -> Option<Offer> {
    let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    Some(Offer {
        id: s("id"),
        name: s("name"),
        kind: Kind::parse(&s("kind"))?,
        address: s("address"),
        price_msat: v.get("price_msat").and_then(Value::as_u64)?,
        unit: Unit::parse(&s("unit"))?,
        input_msat: v.get("input_msat").and_then(Value::as_u64).unwrap_or(0),
        paused: v.get("paused").and_then(Value::as_bool).unwrap_or(false),
        paths: v.get("paths").and_then(Value::as_array).map(|a| a.iter().filter_map(|p| p.as_str().map(str::to_string)).collect()).unwrap_or_default(),
        strip: v.get("strip").and_then(Value::as_bool).unwrap_or(false),
        titles: v.get("titles").and_then(Value::as_array).map(|a| a.iter().filter_map(|t| {
            Some((t.get("title")?.as_str()?.to_string(), t.get("url")?.as_str()?.to_string()))
        }).collect()).unwrap_or_default(),
        app: v.get("app").filter(|a| a.is_object()).map(|a| {
            let t = |k: &str| a.get(k).and_then(Value::as_str).unwrap_or("").to_string();
            let list = |k: &str| a.get(k).and_then(Value::as_array).map(|x| x.iter().filter_map(|p| p.as_str().map(str::to_string)).collect()).unwrap_or_default();
            // an app saved before live connections were carried has them on
            OfferApp { base: t("base"), entry: t("entry"), login: t("login"), deny: list("deny"), allow: list("allow"), live: a.get("live").and_then(Value::as_bool).unwrap_or(true),
                       accounts: a.get("accounts").filter(|l| l.is_array()).map(|_| list("accounts")) }
        }).filter(|a| a.base.starts_with('/') && a.base.ends_with('/')),
        capacity: {
            let c = v.get("capacity");
            let n = |k: &str| c.and_then(|c| c.get(k)).and_then(Value::as_u64).filter(|n| (1..=1_000_000).contains(n)).map(|n| n as u32);
            xbt_gateway::config::Capacity { max_buyers: n("max_buyers"), max_streams: n("max_streams"), max_streams_per_buyer: n("max_streams_per_buyer"), max_mbit: n("max_mbit") }
        },
    })
}

/// A route's `capacity` as the gateway takes it: a free route counts no buyers.
fn route_capacity(m: &mut Map<String, Value>, c: &xbt_gateway::config::Capacity, free: bool) {
    let c = xbt_gateway::config::Capacity { max_buyers: if free { None } else { c.max_buyers }, ..*c };
    if c.is_set() {
        let mut o = Map::new();
        for (k, v) in [("max_buyers", c.max_buyers), ("max_streams", c.max_streams), ("max_streams_per_buyer", c.max_streams_per_buyer), ("max_mbit", c.max_mbit)] {
            if let Some(v) = v {
                o.insert(k.into(), json!(v));
            }
        }
        m.insert("capacity".into(), Value::Object(o));
    } else {
        m.remove("capacity");
    }
}

impl Shop {
    pub fn to_json(&self) -> Value {
        let mut v = json!({"name": self.name, "direct": self.direct, "private": self.private, "public_url": self.public_url, "proxies": self.proxies, "network": self.network,
                           "mainnet_ok": self.mainnet_ok, "offers": self.offers.iter().map(offer_json).collect::<Vec<_>>()});
        if let Some((a, b, c)) = self.caps {
            v["caps"] = json!([a, b, c]);
        }
        v
    }

    pub fn from_json(v: &Value) -> Self {
        let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let caps = v.get("caps").and_then(Value::as_array).and_then(|a| Some((a.first()?.as_u64()?, a.get(1)?.as_u64()?, a.get(2)?.as_u64()?)));
        let b = |k: &str| v.get(k).and_then(Value::as_bool).unwrap_or(false);
        Shop { name: s("name"), direct: b("direct"), private: b("private"), public_url: s("public_url"), proxies: s("proxies"), network: s("network"),
               mainnet_ok: v.get("mainnet_ok").and_then(Value::as_bool).unwrap_or(false), caps,
               offers: v.get("offers").and_then(Value::as_array).map(|a| a.iter().filter_map(offer_of).collect()).unwrap_or_default() }
    }

    /// A shop read from a gateway config the page did not write (a hand-written one, or the
    /// gateway page of an earlier version): its routes grouped into offers by service and price.
    pub fn import(c: &Value) -> Self {
        let s = |p: &str| c.pointer(p).and_then(Value::as_str).unwrap_or("").to_string();
        let listing = c.get("listing").cloned().unwrap_or(Value::Null);
        let sections: Vec<Value> = listing.get("services").and_then(Value::as_array).cloned().unwrap_or_default();
        let top_up = s("/upstream");
        let mut offers: Vec<Offer> = vec![];
        for r in c.get("routes").and_then(Value::as_array).into_iter().flatten() {
            let path = r.get("path").and_then(Value::as_str).unwrap_or("/").to_string();
            let address = r.get("upstream").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| top_up.clone());
            let p = r.get("price").cloned().unwrap_or(json!({}));
            let n = |k: &str| p.get(k).and_then(Value::as_u64).unwrap_or(0);
            let input_msat = n("per_1k_input_msat");
            let (unit, msat) = if n("per_1k_output_msat") > 0 || input_msat > 0 {
                (Unit::Tokens, n("per_1k_output_msat"))
            } else if n("byte_msat") > 0 && n("per_bytes") == GB {
                (Unit::Gb, n("byte_msat"))
            } else if n("byte_msat") > 0 {
                // to the msat a MiB
                (Unit::Mib, n("byte_msat").saturating_mul(MIB) / n("per_bytes").max(1))
            } else if n("second_msat") > 0 {
                (Unit::Second, n("second_msat"))
            } else {
                (Unit::Request, n("request_msat"))
            };
            let strip = r.get("strip_prefix").and_then(Value::as_bool).unwrap_or(false);
            if let Some(o) = offers.iter_mut().find(|o| o.address == address && o.unit == unit && o.price_msat == msat && o.input_msat == input_msat && o.strip == strip) {
                o.paths.push(path);
                continue;
            }
            let section = sections.iter().find(|x| x.get("path").and_then(Value::as_str) == Some(path.as_str()));
            let kind_s = section.and_then(|x| x.get("kind")).or(listing.get("kind")).and_then(Value::as_str).unwrap_or("api");
            let kind = Kind::from_listing(kind_s);
            let name = section.and_then(|x| x.get("name")).and_then(Value::as_str).map(str::to_string)
                .unwrap_or_else(|| if offers.is_empty() { s("/listing/name") } else { String::new() });
            let items = section.and_then(|x| x.get("items")).or(if offers.is_empty() { listing.get("items") } else { None });
            let titles = items.and_then(Value::as_array).map(|a| a.iter().filter_map(|i| {
                Some((i.get("title")?.as_str()?.to_string(), i.get("url")?.as_str()?.to_string()))
            }).collect()).unwrap_or_default();
            offers.push(Offer { id: format!("s{}", offers.len() + 1), name: if name.is_empty() { kind.words().into() } else { name }, kind, address,
                                price_msat: msat, unit, input_msat, paused: false, paths: vec![path], strip, titles, app: None, capacity: Default::default() });
        }
        let caps = c.get("caps").and_then(|k| Some((k.get("max_sessions")?.as_u64()?, k.get("sessions_per_address")?.as_u64()?,
                                                    k.get("max_held_tickets")?.as_u64()?)));
        let proxies = c.pointer("/http/forwarded_address/proxies").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default();
        let direct = c.get("link").is_some_and(Value::is_object) && !s("/public_url").starts_with("https://");
        let private = c.pointer("/link/private").and_then(Value::as_bool).unwrap_or(false);
        Shop { name: s("/listing/name"), direct, private, public_url: if direct { String::new() } else { s("/public_url") }, proxies, network: s("/network"),
               mainnet_ok: s("/chain") == "main" && s("/mainnet_ack") == MAINNET_ACK, caps, offers }
    }

    /// A path no other offer uses: `/` for a media server, whose web app sees the shop's root, while no
    /// other offer has it; `/<name>/` for anything else, so that a media server added later still finds `/`.
    fn free_path(&self, name: &str, kind: Kind, except: &str) -> String {
        let used = |p: &str| {
            self.offers.iter().filter(|o| o.id != except).any(|o| o.paths.iter().any(|x| x == p) || o.app.as_ref().is_some_and(|a| a.base == p))
        };
        if kind == Kind::Media && !used("/") {
            return "/".into();
        }
        let base = slug(name);
        let mut p = format!("/{base}/");
        let mut i = 2;
        while used(&p) || p == "/x402/" || p == "/.well-known/" || p == "/services/" {
            p = format!("/{base}-{i}/");
            i += 1;
        }
        p
    }
}

/// What the page shows as the one status of the shop, in words: (class, headline, what to do).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub class: &'static str,
    pub headline: String,
    pub next: String,
}

/// The ticket a new shop sells: 900 sat, so that with its fee limit it stays under 1,000 sat.
const DEFAULT_TICKET_MSAT: u64 = 900_000;

impl App {
    fn shop_path(&self) -> PathBuf {
        self.cfg.data_dir.join(SELL_FILE)
    }

    fn gateway_now(&self) -> Option<Value> {
        std::fs::read_to_string(self.cfg.gw.dir.join(GW_CONFIG)).ok().and_then(|t| serde_json::from_str(&t).ok())
    }

    /// The shop: `sell.json`, else what the gateway's config says, else empty.
    pub fn shop(&self) -> Shop {
        if let Some(v) = std::fs::read_to_string(self.shop_path()).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()) {
            return Shop::from_json(&v);
        }
        let mut s = self.gateway_now().map(|c| Shop::import(&c)).unwrap_or_default();
        if s.proxies.is_empty() {
            s.proxies = self.cfg.gw.proxies.join(", ");
        }
        s
    }

    fn save_shop(&self, shop: &Shop) -> Result<(), String> {
        let text = serde_json::to_string_pretty(&shop.to_json()).map_err(|e| e.to_string())? + "\n";
        let tmp = self.cfg.data_dir.join(format!(".{SELL_FILE}.{}", hex::encode(crate::random_bytes::<6>())));
        std::fs::create_dir_all(&self.cfg.data_dir).and_then(|_| std::fs::write(&tmp, text)).and_then(|_| std::fs::rename(&tmp, self.shop_path()))
            .map_err(|e| {
                let _ = std::fs::remove_file(&tmp);
                format!("Your shop could not be saved: {e}")
            })
    }

    /// The address a proxy or tunnel forwards buyers to: this app's selling port on the box.
    fn selling_port(&self) -> String {
        let host = self.cfg.gw.health_url.as_deref().and_then(|u| u.strip_prefix("http://")).and_then(|r| r.split(['/', ':']).next())
            .filter(|h| !h.is_empty()).unwrap_or("this box");
        format!("http://{host}:{}", self.cfg.gw.port)
    }

    /// Ask the shop's public address from here, as a buyer would: its signed listing, checked against
    /// its own terms, or else a 402 at one of its routes. (A box may not reach its own public address
    /// on some home networks; a tunnel's always works.)
    fn check_public(&self, shop: &Shop) -> Result<String, String> {
        let url = shop.public_url.trim_end_matches('/');
        if !url.starts_with("https://") {
            return Err("Save the https:// address buyers find you at first.".into());
        }
        match xbt402::listing::fetch(url, crate::app::services_page::get_page) {
            Ok(l) => return Ok(format!("Buyers can reach you: {url} answers with your signed list ({} service{}).",
                                       l.services.len(), if l.services.len() == 1 { "" } else { "s" })),
            Err(e) if e.contains("could not reach") => return Err(format!("Buyers can't reach {url} yet: {e}. Check the tunnel or proxy that leads there.")),
            Err(_) => {}
        }
        let first = shop.offers.iter().filter(|o| !o.paused).flat_map(|o| o.paths.clone()).next().unwrap_or_else(|| "/".into());
        match crate::app::services_page::get_page(&format!("{url}{first}")) {
            Ok(p) if p.status == 402 => Ok(format!("Buyers can reach you: {url} answers and asks for payment.")),
            Ok(p) => Err(format!("{url} answers, but not as your shop does (HTTP {}): check that it leads to {}.", p.status, self.selling_port())),
            Err(e) => Err(format!("Buyers can't reach {url} yet: {e}. Check the tunnel or proxy that leads there.")),
        }
    }

    /// Media servers and AI models on this box that answer: the usual names of the apps on Umbrel
    /// and StartOS, and the ones the box names (`XBT_UI_LOCAL_SERVICES`). Asked in parallel, briefly.
    fn found_services(&self) -> Vec<(String, String)> {
        let mut c: Vec<(String, String)> = self.cfg.local_services.clone();
        for (n, u) in KNOWN_SERVICES {
            if !c.iter().any(|(_, x)| x == u) {
                c.push((n.to_string(), u.to_string()));
            }
        }
        std::thread::scope(|s| {
            let hs: Vec<_> = c.iter().map(|(n, u)| s.spawn(move || answers(u).then(|| (n.clone(), u.clone())))).collect();
            hs.into_iter().filter_map(|h| h.join().ok().flatten()).collect()
        })
    }

    fn keys_stored(&self) -> bool {
        self.cfg.gw.dir.join(GW_INVOICES).is_file() && self.cfg.gw.dir.join(GW_INFO).is_file()
    }

    fn chain(&self) -> String {
        self.signer.call("health", json!({})).ok().and_then(|h| h.get("chain").and_then(Value::as_str).map(str::to_string)).unwrap_or_default()
    }

    /// The gateway config the shop describes, on top of the one there is (whatever the page does
    /// not show is kept). `Err`: what is still missing, in a sentence.
    pub fn shop_config(&self, shop: &Shop, chain: &str) -> Result<Value, String> {
        let gw = &self.cfg.gw;
        let rest = gw.node_rest.clone().ok_or("This box did not say where its Lightning node is. Reinstall the app, or ask for help.")?;
        if !self.keys_stored() {
            return Err("Connect your Lightning node first (step 1).".into());
        }
        let public_url = if shop.direct { String::new() } else { shop.public_url.trim().trim_end_matches('/').to_string() };
        if public_url.is_empty() && !shop.direct {
            return Err("Say how buyers reach you.".into());
        }
        let local = ["http://127.0.0.1", "http://[::1]", "http://localhost"].iter()
            .any(|p| public_url == *p || public_url.strip_prefix(p).is_some_and(|r| r.starts_with(':')));
        if !shop.direct && !public_url.starts_with("https://") && !local {
            return Err("Buyers reach you at an https:// address. Put the address of your box's secure link here.".into());
        }
        let active: Vec<&Offer> = shop.offers.iter().filter(|o| !o.paused).collect();
        let main = chain == "main";
        if main && !shop.mainnet_ok {
            return Err("Confirm you are ready to take real payments.".into());
        }
        let mut c: Map<String, Value> = self.gateway_now().and_then(|v| v.as_object().cloned()).unwrap_or_default();
        let old_routes: Vec<Value> = c.get("routes").and_then(Value::as_array).cloned().unwrap_or_default();
        // a direct shop listens where the app reaches it: its own loopback when the app runs beside it
        // (Linux), the app's private network otherwise (Umbrel, StartOS: the port is published nowhere)
        let app_beside = gw.health_url.as_deref().and_then(crate::services::http_origin)
            .is_none_or(|o| o.starts_with("http://127.") || o.starts_with("http://localhost") || o.starts_with("http://[::1]"));
        let open = public_url.starts_with("https://") || (shop.direct && !app_beside);
        c.insert("listen".into(), json!(if open { format!("0.0.0.0:{}", gw.port) } else { format!("127.0.0.1:{}", gw.port) }));
        crate::setup::keep_health_token(&mut c, None);
        // a shop that moves keeps answering at its old address, for the buyers that saved it
        let mut aliases: Vec<String> = c.get("public_aliases").and_then(Value::as_array).into_iter().flatten()
            .filter_map(Value::as_str).map(str::to_string).collect();
        if let Some(old) = c.get("public_url").and_then(Value::as_str).map(|u| u.trim_end_matches('/').to_string()) {
            if old != public_url && !aliases.contains(&old) {
                aliases.insert(0, old);
            }
        }
        let scheme = |u: &str| u.split("://").next().unwrap_or("").to_string();
        aliases.retain(|a| *a != public_url && scheme(a) == scheme(&public_url));
        aliases.truncate(xbt_gateway::config::MAX_ALIASES);
        if aliases.is_empty() {
            c.remove("public_aliases");
        } else {
            c.insert("public_aliases".into(), json!(aliases));
        }
        if shop.direct {
            // the gateway names itself by its Nostr key and serves over its link: no address to write
            c.remove("public_url");
            c.remove("public_aliases");
            let mut link = c.get("link").cloned().filter(Value::is_object).unwrap_or(json!({}));
            if link.get("relays").and_then(Value::as_array).is_none_or(|a| a.is_empty()) {
                link["relays"] = json!(DEFAULT_LINK_RELAYS);
            }
            link["private"] = json!(shop.private);
            c.insert("link".into(), link);
        } else {
            c.insert("public_url".into(), json!(public_url));
        }
        // every route names its own service
        c.remove("upstream");
        c.insert("state_dir".into(), json!(gw.state_dir));
        c.insert("chain".into(), json!(if main { "main" } else { "regtest" }));
        if main {
            c.insert("mainnet_ack".into(), json!(MAINNET_ACK));
            c.remove("network");
        } else {
            c.remove("mainnet_ack");
            if shop.network.trim().is_empty() {
                return Err("This is a test chain: set its network id under Advanced.".into());
            }
            c.insert("network".into(), json!(shop.network.trim()));
        }
        let mut node = c.get("node").cloned().filter(Value::is_object).unwrap_or(json!({}));
        node["rest"] = json!(rest);
        node["macaroon"] = json!(gw.dir.join(GW_INVOICES).display().to_string());
        node["info_macaroon"] = json!(gw.dir.join(GW_INFO).display().to_string());
        if let Some(cert) = &gw.node_tls_cert {
            node["tls_cert"] = json!(cert.display().to_string());
        }
        c.insert("node".into(), node);
        let proxies: Vec<String> = shop.proxies.split([',', ' ']).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect();
        let (ms, spa, mh) = shop.caps.unwrap_or(if main { (MAINNET_CAPS.0.into(), MAINNET_CAPS.1.into(), MAINNET_CAPS.2.into()) }
                                                else { (TEST_CAPS.0.into(), TEST_CAPS.1.into(), TEST_CAPS.2.into()) });
        // behind a proxy that does not say who the buyer is, every buyer is one address: that cap is off
        let spa = if public_url.starts_with("https://") && proxies.is_empty() { 0 } else { spa };
        let mut caps = c.get("caps").cloned().filter(Value::is_object).unwrap_or(json!({}));
        caps["max_sessions"] = json!(ms);
        caps["sessions_per_address"] = json!(spa);
        caps["max_held_tickets"] = json!(mh);
        c.insert("caps".into(), caps);
        // a buyer whose call cannot take a whole ticket may ask for a smaller one, down to the smallest a held
        // ticket may be (546 sat), unless the owner set another floor
        let mut tickets = c.get("tickets").cloned().filter(Value::is_object).unwrap_or(json!({}));
        // a ticket and its routing-fee limit stay under the buyer's starter rules' "ask me first"
        // line (1,000 sat on mainnet), so a new buyer can pay without signing anything more
        if tickets.get("ticket_msat").is_none() {
            tickets["ticket_msat"] = json!(DEFAULT_TICKET_MSAT);
        }
        if tickets.get("min_ticket_msat").is_none() {
            let size = tickets.get("ticket_msat").and_then(Value::as_u64).unwrap_or(1_000_000);
            tickets["min_ticket_msat"] = json!(546_000u64.min(size));
        }
        c.insert("tickets".into(), tickets);
        if proxies.is_empty() && public_url.starts_with("https://") {
            // as for the sessions above: the proxy's connections are every buyer's, so the gateway's cap on
            // connections from one address is off, and its total is the bound
            c.insert("http".into(), json!({"per_address": 0}));
        } else if proxies.is_empty() {
            c.remove("http");
        } else {
            c.insert("http".into(), json!({"forwarded_address": {"header": "x-forwarded-for", "proxies": proxies}}));
        }
        let mut routes = vec![];
        let mut sections = vec![];
        // the shared folder's key: the route of a Files service adds it to every request ([`crate::files`])
        let files_key = if active.iter().any(|o| o.kind == Kind::Files) { Some(crate::files::key(&self.cfg.data_dir.join("secrets"))?) } else { None };
        for o in &active {
            let key_file = gw.dir.join(app_key_name(&o.id)).display().to_string();
            let price = match o.unit {
                Unit::Mib => json!({"byte_msat": o.price_msat, "per_bytes": MIB}),
                Unit::Gb => json!({"byte_msat": o.price_msat, "per_bytes": GB}),
                Unit::Request => json!({"request_msat": o.price_msat}),
                Unit::Second => json!({"second_msat": o.price_msat}),
                Unit::Tokens if o.input_msat > 0 => json!({"per_1k_output_msat": o.price_msat, "per_1k_input_msat": o.input_msat}),
                Unit::Tokens => json!({"per_1k_output_msat": o.price_msat}),
            };
            let free = o.price_msat == 0 && o.input_msat == 0;
            for p in &o.paths {
                // what the page does not show of a route (methods, headers, body size) is kept
                let mut r = old_routes.iter().find(|r| r.get("path").and_then(Value::as_str) == Some(p.as_str())).cloned()
                    .filter(Value::is_object).unwrap_or_else(|| match o.kind {
                        Kind::Media | Kind::Files => json!({}),
                        // a model or a web service is asked with a body
                        Kind::Ai | Kind::Web | Kind::Other => json!({"methods": ["GET", "HEAD", "POST"], "max_body": MIB}),
                    });
                let m = r.as_object_mut().expect("an object");
                m.insert("path".into(), json!(p));
                m.insert("upstream".into(), json!(o.address));
                if free {
                    m.remove("price");
                    m.insert("free".into(), json!(true));
                } else {
                    m.remove("free");
                    m.insert("price".into(), price.clone());
                }
                if o.strip && p.ends_with('/') && p != "/" {
                    m.insert("strip_prefix".into(), json!(true));
                } else {
                    m.remove("strip_prefix");
                }
                app_route(m, o.app.as_ref().filter(|a| a.base == *p), &key_file);
                if let (Kind::Files, Some(k)) = (o.kind, &files_key) {
                    // the folder answers GET and HEAD of a file, only with the key, and sees paths from its own root
                    m.insert("methods".into(), json!(["GET", "HEAD"]));
                    m.insert("upstream_headers".into(), json!({crate::files::KEY_HEADER: k}));
                    if p != "/" {
                        m.insert("strip_prefix".into(), json!(true));
                    }
                }
                route_capacity(m, &o.capacity, free);
                // one service to a buyer, however many routes: counted once over them (docs/CAPACITY.md)
                if (1..=64).contains(&o.id.len()) {
                    m.insert("service".into(), json!(o.id));
                }
                routes.push(r);
            }
            // the service's own web page, under a route of its own where its base is not one of the service's paths
            if let Some(a) = o.app.as_ref().filter(|a| !o.paths.contains(&a.base)) {
                let mut r = old_routes.iter().find(|r| r.get("path").and_then(Value::as_str) == Some(a.base.as_str())).cloned()
                    .filter(Value::is_object).unwrap_or_else(|| json!({}));
                let m = r.as_object_mut().expect("an object");
                m.insert("path".into(), json!(a.base));
                m.insert("upstream".into(), json!(o.address));
                if free {
                    m.remove("price");
                    m.insert("free".into(), json!(true));
                } else {
                    m.remove("free");
                    m.insert("price".into(), price.clone());
                }
                if o.strip && a.base != "/" {
                    m.insert("strip_prefix".into(), json!(true));
                } else {
                    m.remove("strip_prefix");
                }
                app_route(m, Some(a), &key_file);
                route_capacity(m, &o.capacity, free);
                // one service to a buyer, however many routes: counted once over them (docs/CAPACITY.md)
                if (1..=64).contains(&o.id.len()) {
                    m.insert("service".into(), json!(o.id));
                }
                routes.push(r);
            }
            let base = public_url.clone();
            // deprecated for a media server: its films were listed for the app's built-in player, which is gone. A
            // media server saved before keeps its list for a release, for older buyers' apps; saving it again clears it
            let mut items: Vec<Value> = o.titles.iter().map(|(t, u)| {
                // an item at one of the shop's earlier addresses is listed at its address now
                let moved = aliases.iter().any(|a| crate::services::same_origin(u, a));
                let url = if u.starts_with('/') { format!("{base}{u}") }
                          else if moved { crate::services::rebase(u, &base).unwrap_or_else(|| u.clone()) } else { u.clone() };
                json!({"title": t, "url": url})
            }).collect();
            // a Files service lists what is in its folder now, each file with its size
            if let (Kind::Files, Some(p)) = (o.kind, o.paths.first()) {
                let at = if p.ends_with('/') { p.clone() } else { format!("{p}/") };
                items = crate::files::shared_dir(&self.cfg.files).map(|d| crate::files::list(&d)).unwrap_or_default().into_iter().map(|(rel, size)| {
                    json!({"title": rel, "url": format!("{base}{at}{}", crate::files::url_path(&rel)), "credit": crate::files::size_words(size)})
                }).collect();
            }
            if let Some(p) = o.paths.first() {
                sections.push(json!({"name": o.name, "kind": o.kind.listing_kind(), "path": p, "items": items}));
            }
            if let Some(a) = &o.app {
                sections.push(json!({"name": o.name, "kind": "app", "path": a.base, "items": [{"title": format!("Open {}", o.name), "url": format!("{base}{}", a.entry)}]}));
            }
        }
        // pieces of work from this box's miners, when renting them out is on
        if let Some(r) = self.hash_route() {
            routes.retain(|x| x.get("path") != r.get("path"));
            // listed beside the other services; its price is the route's
            let name = self.hash_settings()["name"].as_str().map(str::trim).filter(|n| !n.is_empty()).unwrap_or("Hashrate").to_string();
            sections.push(json!({"name": name, "kind": "hashrate", "path": r["path"], "items": []}));
            routes.push(r);
        }
        // this box's VPN exit, when it is offered: buyers' wallets open paid tunnels here (announced on Nostr with the exit)
        // and listed, so a shop that sells only its exit still has a listing: a shop reached by its key is
        // found, and reached (its transport document travels with the listing), through nothing else.
        // Kind "api", which every app reads: a buyer's VPN service opens the tunnel, not Browse
        if let Some(r) = self.vpn_route() {
            routes.retain(|x| x.get("path") != r.get("path"));
            sections.push(json!({"name": "VPN exit", "kind": "api", "path": r["path"], "items": []}));
            routes.push(r);
        }
        c.insert("routes".into(), Value::Array(routes));
        if sections.is_empty() {
            c.remove("listing");
        } else {
            let name = if shop.name.trim().is_empty() { "Lightning Stream seller".to_string() } else { shop.name.trim().to_string() };
            c.insert("listing".into(), json!({"name": name, "updated": crate::html::utc(crate::now()).chars().take(10).collect::<String>(),
                                              "services": sections}));
        }
        // the shop on Nostr, on the app's relays (first) and any the config already named, so a new
        // install is found there too; publishing written off by hand stays off
        // a direct shop is found on Nostr only: its listing goes there whatever else
        let listed = c.contains_key("listing") && (public_url.starts_with("https://") || shop.direct);
        let mut nostr = c.get("nostr").cloned().filter(Value::is_object);
        if listed && !self.cfg.nostr_relays.is_empty() {
            let mut n = nostr.unwrap_or(json!({}));
            let mut relays = self.cfg.nostr_relays.clone();
            for r in n["relays"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                if !relays.iter().any(|x| x == r) {
                    relays.push(r.to_string());
                }
            }
            relays.truncate(MAX_NOSTR_RELAYS);
            n["relays"] = json!(relays);
            if n.get("publish").is_none() {
                n["publish"] = json!(true);
            }
            nostr = Some(n);
        } else if let Some(n) = nostr.as_mut().filter(|_| !listed) {
            // nothing to publish: the gateway refuses publish without a listing. Left out, not written
            // false: absent is off to the gateway, and a false here would read as written off by hand,
            // so a shop saved before its first service would never be published once it had one
            if let Some(m) = n.as_object_mut() {
                m.remove("publish");
            }
        }
        match nostr {
            Some(n) => c.insert("nostr".into(), n),
            None => c.remove("nostr"),
        };
        let v = Value::Object(c);
        GatewayConfig::from_json(&v).map_err(|e| format!("These settings do not work together: {e}"))?;
        Ok(v)
    }

    /// Hashrate is paid at the shop's address: a shop that moves takes its hashrate payments along.
    fn follow_public_url(&self, shop: &Shop) -> Result<(), String> {
        let mut v = self.hash_settings();
        let base = shop.public_url.trim_end_matches('/');
        if v.get("payUrl").and_then(Value::as_str).is_none() || base.is_empty() {
            return Ok(());
        }
        let pay = format!("{base}/hashrate");
        if v["payUrl"] != pay {
            v["payUrl"] = json!(pay);
            crate::app::hashrate::write_settings(&self.cfg.hash.settings, &v)?;
        }
        Ok(())
    }

    /// Save the shop, and the gateway's config when the shop is complete. `Ok`: the words for
    /// the owner.
    pub(crate) fn commit(&self, shop: &Shop, done: &str) -> Result<String, String> {
        self.save_shop(shop)?;
        match self.shop_config(shop, &self.chain()) {
            Ok(cfg) => {
                let text = serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())? + "\n";
                write_shared(&self.cfg.gw.dir, GW_CONFIG, text.as_bytes())?;
                Ok(format!("{done} Your shop restarts with it in a few seconds."))
            }
            Err(missing) => Ok(format!("{done} Not selling yet: {missing}")),
        }
    }

    /// At start: write the gateway's config again when the shop, as this version describes it,
    /// differs from the one there is (an update that lists more, or lists it otherwise, takes
    /// effect without the owner pressing Save). The listing's date alone is no change. `None`:
    /// the signer did not say its chain yet; ask again.
    pub fn refresh_shop_config(&self) -> Option<&'static str> {
        let chain = self.chain();
        if chain.is_empty() {
            return None;
        }
        let Ok(new) = self.shop_config(&self.shop(), &chain) else { return Some("not complete") };
        let undated = |v: &Value| {
            let mut v = v.clone();
            if let Some(l) = v.get_mut("listing").and_then(Value::as_object_mut) {
                l.remove("updated");
            }
            v
        };
        let path = self.cfg.gw.dir.join(GW_CONFIG);
        let old = std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok());
        if old.as_ref().map(undated) == Some(undated(&new)) {
            return Some("unchanged");
        }
        let Ok(text) = serde_json::to_string_pretty(&new) else { return Some("not written") };
        match write_shared(&self.cfg.gw.dir, GW_CONFIG, (text + "\n").as_bytes()) {
            Ok(()) => Some("written"),
            Err(_) => Some("not written"),
        }
    }

    fn reachable(address: &str) -> bool {
        crate::app::http_get(&format!("{address}/")).is_ok_and(|(code, _)| code > 0)
    }

    /// What the gateway says about its direct link (`/.well-known/lightning-stream-link.json` on its
    /// own address): its shop key, its link and whether its node vouches for it.
    pub(crate) fn link_status(&self) -> Option<Value> {
        let base = self.cfg.gw.health_url.as_deref()?;
        let origin = crate::services::http_origin(base)?;
        match crate::app::http_get(&format!("{origin}{LINK_STATUS_PATH}")) {
            Ok((200, body)) => serde_json::from_str(&body).ok(),
            _ => None,
        }
    }

    /// What each route carries now, by path, from the gateway's `/services` (only routes with a
    /// `capacity` say). Empty when the gateway is not running or cannot be asked.
    fn live_capacity(&self) -> HashMap<String, Value> {
        let Some(origin) = self.cfg.gw.health_url.as_deref().and_then(crate::services::http_origin) else { return HashMap::new() };
        let Ok((200, body)) = crate::app::http_get(&format!("{origin}{}", xbt_gateway::config::SERVICES_PATH)) else { return HashMap::new() };
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        v.get("routes").and_then(Value::as_array).into_iter().flatten()
            .filter_map(|r| Some((r.get("path")?.as_str()?.to_string(), r.get("capacity").filter(|c| c.is_object())?.clone())))
            .collect()
    }

    /// The shop key to share, and how the direct link is doing, in plain words.
    fn shop_key_card(&self) -> String {
        let Some(v) = self.link_status() else {
            return "<section class=\"card\"><h2>Your shop key</h2><p>It shows here once your shop has started. Save above, then come back in a few seconds.</p></section>".into();
        };
        let t = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let npub = t("npub");
        let state = if !t("sign_error").is_empty() {
            // no sign key: the node can't vouch until the owner gives one (StartOS: pasted, see step 1)
            let paste = if self.cfg.gw.dir.join(GW_SIGN).is_file() { "" } else {
                " Make a link signing key in your Lightning node's app (permission <code>message:write</code> only) and paste it under \
                 Advanced settings, Replace the node keys."
            };
            format!("<p><span class=\"pill warn\">Not yet reachable</span> Your Lightning node has not vouched for this shop's link: {}. \
                     Buyers' apps refuse a link their seller's node has not vouched for.{paste}</p>", esc(&t("sign_error")))
        } else if v.get("signed_until").and_then(Value::as_u64).is_some() {
            let how = if v.get("private").and_then(Value::as_bool).unwrap_or(false) { "through a relay only (private)" } else { "directly when the networks allow, through a relay when not" };
            format!("<p><span class=\"pill good\">Reachable</span> Buyers' apps connect {how}, encrypted end to end.</p>")
        } else {
            "<p><span class=\"pill warn\">Starting</span> Your shop is getting its link ready. This takes a few seconds.</p>".into()
        };
        format!("<section class=\"card\"><h2>Your shop key</h2><p>Share this with buyers. They paste it in their app under Sellers, or find your shop on Browse.</p>\
                 <p><code class=\"key\" id=\"shop-key\">{}</code></p><button type=\"button\" class=\"secondary\" data-copy=\"shop-key\">Copy</button>{state}\
                 <details><summary>Advanced: the link</summary><ul class=\"small\"><li>Link key <code>{}</code></li><li>Relays: {}</li>\
                 <li>Your node's word for it holds until {}</li></ul></details></section>",
                esc(&npub), esc(&t("endpoint_id")),
                esc(&v.get("relays").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default()),
                v.get("signed_until").and_then(Value::as_i64).map(|u| esc(&crate::html::utc(u))).unwrap_or_else(|| "not yet".into()))
    }

    /// Where buyers find the shop, in a sentence.
    fn where_buyers_find(&self, shop: &Shop) -> String {
        if !shop.direct {
            return format!("Buyers can find you at {}.", shop.public_url.trim_end_matches('/'));
        }
        match self.link_status().and_then(|v| v.get("npub").and_then(Value::as_str).map(str::to_string)) {
            Some(npub) => format!("Buyers find you by your shop key {npub}, on Browse in their app, or when you share it."),
            None => "Buyers find you by your shop key, on Browse in their app. It shows here once your shop has started.".into(),
        }
    }

    /// How the gateway reaches the shared folder of a Files service ([`crate::files`]).
    pub(crate) fn files_upstream(&self) -> String {
        if !self.cfg.files.upstream.is_empty() {
            return self.cfg.files.upstream.trim_end_matches('/').to_string();
        }
        match *self.files_addr.lock().unwrap_or_else(|p| p.into_inner()) {
            Some(a) => format!("http://{a}"),
            None => format!("http://{}", self.cfg.files.bind),
        }
    }

    /// The shop's one status, and each offer's (by id).
    pub fn shop_status(&self, shop: &Shop, chain: &str) -> (Status, HashMap<String, Status>) {
        let st = |class: &'static str, h: &str, n: &str| Status { class, headline: h.into(), next: n.into() };
        let mut each = HashMap::new();
        // in parallel: a service that does not answer costs its wait once, not once per service
        let probes: Vec<(String, bool)> = std::thread::scope(|s| {
            let hs: Vec<_> = shop.offers.iter().filter(|o| !o.paused).map(|o| s.spawn(move || (o.id.clone(), Self::reachable(&o.address)))).collect();
            hs.into_iter().filter_map(|h| h.join().ok()).collect()
        });
        for o in &shop.offers {
            let up = probes.iter().any(|(id, ok)| id == &o.id && *ok);
            let files_error = if o.kind == Kind::Files { self.files_error.lock().unwrap_or_else(|p| p.into_inner()).clone() } else { None };
            each.insert(o.id.clone(), if o.paused {
                st("warn", "Paused", "Buyers cannot buy it. Resume it to sell again.")
            } else if let Some(e) = files_error {
                // its address answering is no sign of the folder: another program may hold it
                st("bad", "Your shared folder isn't served", &format!(
                    "The app could not serve it at {} ({e}): another program uses that address. Stop that program, \
                     or give the folder another port (on Linux: LS_FILES_PORT in the app's .env, then run install.sh again), \
                     and restart the app.", self.cfg.files.bind))
            } else if !up {
                st("bad", &format!("Can't reach {}", o.kind.thing()), &format!("Check that {} is running and that its address is right.", o.kind.thing()))
            } else {
                st("ok", "Selling", "")
            });
        }
        let overall = match self.shop_config(shop, chain) {
            Err(missing) => st("warn", "Not selling yet", &missing),
            Ok(_) if shop.offers.is_empty() => st("warn", "Not selling yet", "Add something to sell."),
            Ok(_) if shop.offers.iter().all(|o| o.paused) => st("warn", "Paused", "Everything is paused. Resume a service to sell again."),
            Ok(_) => match self.cfg.gw.health() {
                Some(Ok((200, _))) | None => {
                    if each.values().any(|s| s.class == "bad") {
                        st("bad", "Selling, with a problem", "One of your services can't be reached: see below.")
                    } else {
                        st("ok", "Selling", &self.where_buyers_find(shop))
                    }
                }
                _ => st("bad", "Starting, or stopped", "Your shop is not answering yet. It starts by itself in a few seconds; if this stays, restart the app."),
            },
        };
        (overall, each)
    }

    /// For Home: the shop's state in a pill and a sentence, without asking each service (that is
    /// the Sell page's job): (pill class, headline, next step).
    pub(crate) fn sell_summary(&self) -> (&'static str, String, String) {
        let shop = self.shop();
        let live = shop.offers.iter().filter(|o| !o.paused).count();
        match self.shop_config(&shop, &self.chain()) {
            Err(_) if !self.keys_stored() => ("warn", "Not selling yet".into(), "Open Sell to connect your Lightning node and add what you sell.".into()),
            Err(missing) => ("warn", "Not selling yet".into(), missing),
            Ok(_) if shop.offers.is_empty() => ("warn", "Not selling yet".into(), "Add a service to sell: a media server, an AI model or another web service.".into()),
            Ok(_) if live == 0 => ("warn", "Paused".into(), "Everything is paused. Resume a service to sell again.".into()),
            Ok(_) => ("good", format!("Selling {live} service{}", if live == 1 { "" } else { "s" }),
                      self.where_buyers_find(&shop)),
        }
    }

    // --- the page --------------------------------------------------------------------------------

    pub(crate) fn sell_page(&self, ctx: &Ctx, q: &HashMap<String, String>) -> Resp {
        self.sell_html(ctx, q.get("edit").map(String::as_str), None)
    }

    fn sell_html(&self, ctx: &Ctx, edit: Option<&str>, sent: Option<(&HashMap<String, String>, String)>) -> Resp {
        let gw = &self.cfg.gw;
        let shop = self.shop();
        let chain = self.chain();
        let main = chain == "main";
        let (status, each) = self.shop_status(&shop, &chain);
        let csrf = App::csrf_input(ctx);
        let mut b = format!("<section class=\"status {}\" aria-live=\"polite\"><p class=\"status-head\">{}</p>{}</section>",
                            status.class, esc(&status.headline), if status.next.is_empty() { String::new() } else { format!("<p>{}</p>", esc(&status.next)) });
        if let Some((_, e)) = &sent {
            b.push_str(&App::error_box(e));
        }

        // step 1: the node, once
        let keys = self.keys_stored();
        if !keys {
            b.push_str(&format!("<section class=\"card step-card\"><h2>1. Connect your Lightning node</h2>\
                <p>Buyers pay you through your Lightning node. Make these keys in your node's app and paste them here. The first two let this \
                app ask for payments and read the time on the network. The third, optional, lets your node vouch for your shop's link, so \
                buyers can reach you directly through their app. None of them can spend your money.</p>\
                <form method=\"post\" action=\"./sell\">{csrf}<input type=\"hidden\" name=\"action\" value=\"connect\">\
                <label>First key: payment requests<textarea name=\"invoices_macaroon\" rows=\"3\" class=\"mono\" autocomplete=\"off\" required></textarea></label>\
                <label>Second key: network time<textarea name=\"info_macaroon\" rows=\"3\" class=\"mono\" autocomplete=\"off\" required></textarea></label>\
                <label>Third key: link signing <small>(needed to be reached directly through the app)</small><textarea name=\"sign_macaroon\" rows=\"3\" class=\"mono\" autocomplete=\"off\"></textarea></label>\
                <details><summary>How do I make them?</summary><p>In your Lightning node's app (Lightning Fork), open the page called <em>Macaroons</em> \
                and make three, each with exactly these permissions:</p><ul><li>First key: <code>{}</code></li><li>Second key: <code>{}</code></li>\
                <li>Third key: <code>{}</code> (or <code>{}</code>). It lets your node vouch for your shop's link, so buyers' apps can check it is yours. \
                It signs messages and does nothing else. Without it your shop can sell only at an https address of its own.</li></ul>\
                <p class=\"hint\">Give each its own root key, so you can revoke it alone. The app refuses a key with more permissions than these.</p></details>\
                <button>Connect</button></form></section>", INVOICE_OPS.join(" "), INFO_OPS.join(" "), SIGN_ENTITY_OPS.join(" "), SIGN_OPS.join(" ")));
        }
        b.push_str(&pin_card(&csrf, gw.node_pin, gw.node_rest.as_deref(), gw.node_tls_cert.as_deref(), "./sell"));

        // the shop
        // a new shop, and any shop without a web address, is reached directly
        let direct = shop.direct || shop.public_url.trim().is_empty();
        let pv = |k: &str, d: &str| sent.as_ref().filter(|(f, _)| f.get("action").map(String::as_str) == Some("shop"))
            .and_then(|(f, _)| f.get(k).cloned()).unwrap_or_else(|| d.to_string());
        b.push_str(&format!("<section class=\"card\"><h2>{}Your shop</h2><form method=\"post\" action=\"./sell\">{csrf}\
            <input type=\"hidden\" name=\"action\" value=\"shop\">\
            <label>Shop name, as buyers see it<input name=\"name\" value=\"{}\" maxlength=\"200\" placeholder=\"My shop\"></label>\
            <fieldset class=\"reach\" id=\"shop-reach\"><legend>How buyers reach you</legend>\
            <label class=\"check\"><input type=\"radio\" name=\"reach\" value=\"direct\"{}> <span><strong>Directly, through the app</strong> (recommended)<br>\
            <span class=\"hint\">No web address, no certificate, no port forward. Buyers find you by your shop key.</span></span></label>\
            <label class=\"check\"><input type=\"checkbox\" name=\"private\" value=\"1\"{}> <span>Private: always go through a relay, so buyers never see \
            this box's internet address. A little slower.</span></label>\
            <p class=\"hint\">Either way, what you sell is encrypted all the way from this box to the buyer's app. A relay sees internet addresses and how much \
            is sent, never what.</p>\
            <details{}><summary>Advanced: use my own https address instead</summary>\
            <label class=\"check\"><input type=\"radio\" name=\"reach\" value=\"web\"{}> <span>At my own https address</span></label>\
            <label>Your https address<input name=\"public_url\" type=\"url\" inputmode=\"url\" value=\"{}\" pattern=\"https://.+|http://(127\\.0\\.0\\.1|localhost|\\[::1\\])(:[0-9]+)?\" \
            title=\"The https:// address of your box's secure link, like https://films.example.com\" placeholder=\"https://films.example.com\"></label>\
            <p class=\"hint\">The public https:// address that leads to this app's selling port ({}). Buyers' apps pay and connect there. \
            Ways to make one:</p><ol>\
            <li><strong>Cloudflare Tunnel</strong> (an app in the Umbrel App Store, and a free Cloudflare account with your own domain): make a public \
            hostname, like <code>films.example.com</code>, that points at <code>{}</code>.</li>\
            <li><strong>Another tunnel app</strong> that offers a public https address for a service on this box (several VPN and \
            remote-access apps do): point it at <code>{}</code>.</li>\
            <li><strong>Your own domain and proxy</strong> (for example the Nginx Proxy Manager app): a proxy host with a certificate, forwarding \
            to <code>{}</code>.</li></ol><p class=\"hint\">The app never makes a public address by itself: what is on the internet stays your choice.</p></details></fieldset>{}\
            <button class=\"secondary\">Save</button></form>{}</section>",
            if keys { "" } else { "2. " }, esc(&pv("name", &shop.name)),
            if direct { " checked" } else { "" }, if shop.private { " checked" } else { "" }, if direct { "" } else { " open" }, if direct { "" } else { " checked" },
            esc(&pv("public_url", &shop.public_url)), gw.port,
            esc(&self.selling_port()), esc(&self.selling_port()), esc(&self.selling_port()),
            if main {
                let mut n = String::from("<div class=\"flash warn\"><p><strong>This is real money.</strong> Start with low prices and the low \
                    limits under Advanced.</p><details><summary>Read the limits</summary><ul>");
                for l in MAINNET_NOTICE {
                    n.push_str(&format!("<li>{}</li>", esc(l.trim_start_matches("- "))));
                }
                n.push_str("</ul></details></div>");
                format!("{n}<label class=\"check\"><input type=\"checkbox\" name=\"mainnet_ok\" value=\"1\"{}> I understand, and I am ready to take real payments</label>",
                        if shop.mainnet_ok { " checked" } else { "" })
            } else {
                String::new()
            },
            if shop.public_url.starts_with("https://") {
                format!("<form method=\"post\" action=\"./sell\" class=\"row\">{csrf}<input type=\"hidden\" name=\"action\" value=\"check_public\">\
                         <button class=\"secondary\">Check that buyers can reach {}</button></form>", esc(shop.public_url.trim_start_matches("https://")))
            } else {
                String::new()
            }));
        if shop.direct {
            b.push_str(&self.shop_key_card());
        }

        // what is sold
        b.push_str(&format!("<h2>{}Your services</h2>", if keys { "" } else { "3. " }));
        if shop.offers.is_empty() {
            b.push_str("<p class=\"empty\">Nothing yet. Add your first service below.</p>");
        }
        let live = if shop.offers.iter().any(|o| o.capacity.is_set()) { self.live_capacity() } else { HashMap::new() };
        for o in &shop.offers {
            let s = each.get(&o.id).cloned().unwrap_or(Status { class: "warn", headline: "Unknown".into(), next: String::new() });
            let now = o.paths.first().and_then(|p| live.get(p)).map(capacity_words).unwrap_or_default();
            let mut next_hint = if s.next.is_empty() { String::new() } else { format!("<p class=\"hint {}\">{}</p>", s.class, esc(&s.next)) };
            // the app's built-in player is gone: a media server is used through its own web app
            if o.kind == Kind::Media && (o.app.is_none() || !o.titles.is_empty()) {
                next_hint.push_str("<p class=\"hint warn\">Buyers' apps no longer have a player of their own: they use your media server's own web app. \
                    Edit this service and save it to share it that way. A list of films is no longer needed.</p>");
            }
            next_hint.push_str(&now);
            let btn = |action: &str, label: &str, class: &str| format!("<form method=\"post\" action=\"./sell\">{csrf}<input type=\"hidden\" name=\"action\" value=\"{action}\">\
                <input type=\"hidden\" name=\"id\" value=\"{}\"><button{class}>{label}</button></form>", esc(&o.id));
            b.push_str(&format!("<section class=\"card offer\"><div class=\"offer-head\"><h3>{}</h3><span class=\"pill {}\">{}</span></div>\
                <p>{} &middot; <strong>{}</strong>{}</p>{}<div class=\"row\"><a class=\"button-link\" href=\"./sell?edit={}#service-form\">Edit</a>{}{}</div></section>",
                esc(&o.name), s.class, esc(&s.headline), o.kind.words(), o.price_words(),
                if o.kind == Kind::Files {
                    let n = crate::files::shared_dir(&self.cfg.files).map(|d| crate::files::list(&d).len()).unwrap_or(0);
                    format!(" &middot; {n} file{} in the folder", if n == 1 { "" } else { "s" })
                } else if o.titles.is_empty() { String::new() } else { format!(" &middot; {} to choose from", o.titles.len()) },
                next_hint,
                crate::services::urlenc(&o.id),
                if o.paused { btn("resume", "Resume", "") } else { btn("pause", "Pause", " class=\"secondary\"") }
                    + &if o.kind == Kind::Files { btn("files_refresh", "Update the file list", " class=\"secondary\"") } else { String::new() },
                btn("remove", "Remove", " class=\"danger\"")));
        }

        // add or edit: the page's main action
        let editing = edit.and_then(|id| shop.offers.iter().find(|o| o.id == id));
        let from_form = sent.as_ref().filter(|(f, _)| f.get("action").map(String::as_str) == Some("service")).map(|(f, _)| *f);
        let fv = |k: &str, d: String| from_form.and_then(|f| f.get(k).cloned()).unwrap_or(d);
        // buyers' own accounts: the key is never shown again, and the libraries are the service's own list, asked with it
        let saved_libs = editing.and_then(|o| o.app.as_ref()).and_then(|a| a.accounts.clone());
        let saved_key = editing.and_then(|o| std::fs::read_to_string(self.cfg.gw.dir.join(app_key_name(&o.id))).ok()).map(|t| t.trim().to_string()).filter(|t| !t.is_empty());
        let libraries = match (editing, &saved_key, &saved_libs) {
            (Some(o), Some(k), Some(chosen)) => match jellyfin_libraries(&o.address, k) {
                Ok(libs) => format!("<fieldset><legend>Libraries buyers see</legend>{}</fieldset>",
                                    libs.iter().map(|(id, name)| format!("<label class=\"check\"><input type=\"checkbox\" name=\"app_lib_{}\" value=\"1\"{}> {}</label>",
                                                                         esc(id), if chosen.contains(id) { " checked" } else { "" }, esc(if name.is_empty() { id } else { name })))
                                        .collect::<String>()),
                Err(e) => format!("<p class=\"hint\">{}</p>", esc(&e)),
            },
            _ => "<p class=\"hint\">Buyers see every library. Once saved, you can choose which here.</p>".into(),
        };
        // how many buyers and streams at once: off unless set; a hint for a media server
        let cap = editing.map(|o| o.capacity).unwrap_or_default();
        // the whole shop's limits, which a seller meets before any service's: said in plain words beside them
        let shop_buyers = shop.caps.map(|c| c.0).unwrap_or(u64::from(if main { MAINNET_CAPS.0 } else { TEST_CAPS.0 }));
        let shop_conns = self.gateway_now().and_then(|c| c.pointer("/http/connections").and_then(Value::as_u64)).unwrap_or(GATEWAY_CONNECTIONS);
        let shop_limits = format!("Your whole shop serves up to {shop_buyers} buyers at once and {shop_conns} open connections (each film, download or live \
            connection holds one while it is open), whatever you set here. Change the buyers under Advanced settings below.");
        let cap_val = |k: &str, v: Option<u32>| esc(&fv(k, v.map(|n| n.to_string()).unwrap_or_default()));
        let capacity_html = format!("<details class=\"capacity\" id=\"capacity\"{}><summary>How many buyers at once</summary>\
            <p class=\"hint\">So that one buyer too many does not slow everyone down. Leave a box empty for no limit. A buyer turned away pays nothing, \
            sees that your shop is busy, and can try again; no one already watching is cut off.</p>\
            <label>Most buyers at once<input name=\"cap_buyers\" value=\"{}\" inputmode=\"numeric\" pattern=\"[0-9]*\" placeholder=\"no limit\"></label>\
            <label>Most streams at once <small>(films, live connections, long downloads, over all buyers)</small><input name=\"cap_streams\" value=\"{}\" inputmode=\"numeric\" pattern=\"[0-9]*\" placeholder=\"no limit\"></label>\
            <details><summary>Advanced</summary>\
            <label>Most streams for one buyer<input name=\"cap_streams_buyer\" value=\"{}\" inputmode=\"numeric\" pattern=\"[0-9]*\" placeholder=\"no limit\"></label>\
            <label>Most Mbit/s together <small>(no new stream starts above it)</small><input name=\"cap_mbit\" value=\"{}\" inputmode=\"numeric\" pattern=\"[0-9]*\" placeholder=\"no limit\"></label></details>\
            <p class=\"hint\">For a media server such as Jellyfin on a small box, 5 buyers and 3 streams is a good start; each 4K film your server has to convert can use several processor cores.</p>\
            <p class=\"hint\">{}</p></details>",
            if cap.is_set() { " open" } else { "" },
            cap_val("cap_buyers", cap.max_buyers), cap_val("cap_streams", cap.max_streams),
            cap_val("cap_streams_buyer", cap.max_streams_per_buyer), cap_val("cap_mbit", cap.max_mbit), shop_limits);
        let accounts_html = format!("<label class=\"check\"><input type=\"checkbox\" name=\"app_accounts\" value=\"1\"{}> Each buyer gets their own Jellyfin account: \
            their own watch history, and where they stopped</label>\
            <details{}><summary>Buyers' accounts</summary>\
            <label>Your Jellyfin API key <small>({})</small><input name=\"app_key\" type=\"password\" autocomplete=\"off\" class=\"mono\"></label>\
            <p class=\"hint\">Make one in Jellyfin under Dashboard, API Keys. The shop makes each buyer's account with it. It stays on this box, \
            beside the shop's own keys, and is never shown again. Buyers who stay anonymous use the guest login below, if you give one.</p>{libraries}</details>",
            if fv("app_accounts", if saved_libs.is_some() { "1".into() } else { String::new() }) == "1" { " checked" } else { "" },
            if saved_libs.is_some() && saved_key.is_none() { " open" } else { "" },
            if saved_key.is_some() { "saved: leave empty to keep it" } else { "Dashboard, API Keys" });
        let kind = Kind::parse(&fv("kind", editing.map(|o| o.kind.id().to_string()).unwrap_or_else(|| "media".into()))).unwrap_or(Kind::Media);
        let (sug_price, sug_unit) = kind.suggested();
        let unit = Unit::parse(&fv("unit", editing.map(|o| o.unit).unwrap_or(sug_unit).id().to_string())).unwrap_or(sug_unit);
        let kinds: String = [Kind::Media, Kind::Files, Kind::Ai, Kind::Web, Kind::Other].iter().map(|k| {
            let (p, u) = k.suggested();
            // a media server is named by the apps it means: it is shared as its own web app
            let what = match k {
                Kind::Media => "Jellyfin, Plex: shared as a web app · ",
                Kind::Files => "a folder on this box, to download or open in a player · ",
                _ => "",
            };
            format!("<label class=\"choice\"><input type=\"radio\" name=\"kind\" value=\"{}\"{}><span><strong>{}</strong><small>{what}suggested {} sat {}</small></span></label>",
                    k.id(), if *k == kind { " checked" } else { "" }, k.words(), p, u.short())
        }).collect();
        // Files: where the folder is. With a folder the box shares with the app (Umbrel's Downloads,
        // read-only), the owner picks one under it; otherwise it is the app's own folder.
        let files_where = match &self.cfg.files.root {
            Some(root) => {
                let now = std::fs::read_to_string(&self.cfg.files.choice).unwrap_or_default().trim().trim_matches('/').to_string();
                let options: String = crate::files::folders(root).iter().map(|f| {
                    let label = if f.is_empty() { "All of it".to_string() } else { f.clone() };
                    format!("<option value=\"{}\"{}>{}</option>", esc(f), if *f == now { " selected" } else { "" }, esc(&label))
                }).collect();
                let words = esc(&self.cfg.files.root_words);
                if options.is_empty() {
                    format!("<p class=\"hint\">Files reads {words}, which this box doesn't share with the app right now.</p>")
                } else {
                    format!("<p class=\"hint\">Put files in {words}, then choose the folder here. Stream only reads it: \
                        it never changes or deletes your files.</p><label>Which folder <small>(for Files)</small>\
                        <select name=\"files_folder\">{options}</select></label>")
                }
            }
            None => format!("<p class=\"hint\">Put files in the folder, <code>{}</code>.</p>", esc(&self.cfg.files.dir.display().to_string())),
        };
        let units: String = [Unit::Mib, Unit::Gb, Unit::Request, Unit::Second, Unit::Tokens].iter()
            .map(|u| format!("<option value=\"{}\"{}>{}</option>", u.id(), if *u == unit { " selected" } else { "" }, u.words())).collect();
        let titles = editing.map(|o| o.titles.iter().map(|(t, u)| format!("{t} | {u}")).collect::<Vec<_>>().join("\n")).unwrap_or_default();
        b.push_str(&format!("<section class=\"card primary\" id=\"service-form\"><h2>{}</h2><form method=\"post\" action=\"./sell\">{csrf}\
            <input type=\"hidden\" name=\"action\" value=\"service\"><input type=\"hidden\" name=\"id\" value=\"{}\">\
            <fieldset class=\"choices\"><legend>What is it?</legend>{kinds}</fieldset>\
            <p class=\"hint\">A media server is shared as its own web app: buyers use your Jellyfin or Plex in their browser or app, \
            each with their own account if you like, up to 4K, like a streaming service. They pay your price for what it loads.</p>\
            <p class=\"hint\">Files shares a folder on this box with no media server: buyers see each file's name, size \
            and price, and download it or open it in their own player (VLC, mpv, a TV app), paid as it arrives. Price it per GB. \
            Save the service (or press Update the file list) to list what is in the folder.</p>{files_where}\
            <label>Its address on this box <small>(not for Files)</small><input name=\"address\" value=\"{}\" pattern=\"http://[^ ?#@]+\" inputmode=\"url\" class=\"mono\" \
            list=\"found-services\" title=\"The http:// address other apps on this box use, like {}\" placeholder=\"{}\"></label>{}\
            <div class=\"price-row\"><label>Price in sats<input name=\"price\" value=\"{}\" required inputmode=\"decimal\" pattern=\"[0-9][0-9,]*(\\.[0-9]{{1,3}})?|\\.[0-9]{{1,3}}\" \
            title=\"A number of sats, like 20 or 0.5\"></label><label>for each<select name=\"unit\">{units}</select></label></div>\
            <label>Also charge for the question (tokens in) <small>(optional: sats per 1,000 tokens; empty is free)</small>\
            <input name=\"input_price\" value=\"{}\" inputmode=\"decimal\" pattern=\"[0-9][0-9,]*(\\.[0-9]{{1,3}})?|\\.[0-9]{{1,3}}\" title=\"A number of sats, like 2 or 0.5\"></label>\
            <p class=\"hint\">Only for an AI model priced per 1,000 tokens. Usually left empty: buyers then pay for what the model writes.</p>\
            <label>Name, as buyers see it <small>(optional)</small><input name=\"name\" value=\"{}\" maxlength=\"120\" placeholder=\"{}\"></label>\
            <label class=\"check\"><input type=\"checkbox\" name=\"app\" value=\"1\"{}> Buyers can open its own web page inside their app</label>\
            <p class=\"hint\">They use it as they would on your network, and pay your price for what it loads. Give buyers a guest account of their own \
            in the service, never yours.</p>{}\
            <details><summary>Its web page</summary>\
            <label>What the page sees as <code>/</code> <small>(empty: chosen for you)</small><input name=\"app_base\" value=\"{}\" class=\"mono\" placeholder=\"{}\"></label>\
            <label>Where it opens <small>(empty: the same)</small><input name=\"app_entry\" value=\"{}\" class=\"mono\" placeholder=\"/web/\"></label>\
            <label>A guest login the shop adds to every request <small>(optional, <code>Name: value</code>)</small>\
            <input name=\"app_login\" value=\"{}\" class=\"mono\" autocomplete=\"off\" placeholder=\"Authorization: MediaBrowser Token=…\"></label>\
            <p class=\"hint\">For a service whose page asks for a login. It goes from your shop to the service only, never to buyers.</p>\
            <label class=\"check\"><input type=\"checkbox\" name=\"app_live\" value=\"1\"{}> Live updates (WebSockets), paid for by what they carry</label>\
            <label>Paths buyers may not open, one per line <small>(its admin and settings, other users')</small>\
            <textarea name=\"app_deny\" rows=\"4\" class=\"mono\" placeholder=\"/System/&#10;/Sessions\">{}</textarea></label>\
            <label>Only these paths <small>(optional, one per line)</small><textarea name=\"app_allow\" rows=\"3\" class=\"mono\">{}</textarea></label>\
            <p class=\"hint\">Paths as the page sees them. Where a path is under entries of both lists, the longer one decides: \
            <code>/</code> in the second list and <code>/Users</code> in the first refuse <code>/Users</code> but serve the rest.</p></details>\
            <details><summary>Advanced</summary>\
            <label>Items to list for buyers (files, models…), one per line: <code>name | link</code><textarea name=\"titles\" rows=\"4\" class=\"mono\">{}</textarea></label>\
            <p class=\"hint\">A link may start with <code>/</code>: it is then on your shop's address.</p>\
            <label>Paths it is sold under, comma-separated (empty: chosen for you)<input name=\"paths\" value=\"{}\" class=\"mono\"></label>\
            <label class=\"check\"><input type=\"checkbox\" name=\"strip\" value=\"1\"{}> Pass requests on without that path</label></details>\
            {}<div class=\"row\"><button{}>{}</button>{}</div></form></section>",
            if editing.is_some() { "Change this service" } else { "Add a service" },
            esc(editing.map(|o| o.id.as_str()).unwrap_or("")),
            esc(&fv("address", editing.map(|o| o.address.clone()).unwrap_or_default())), kind.example(), kind.example(), found_html(&self.found_services()),
            esc(&fv("price", editing.map(|o| msat_to_sats(o.price_msat)).unwrap_or_else(|| sug_price.to_string()))),
            esc(&fv("input_price", editing.filter(|o| o.input_msat > 0).map(|o| msat_to_sats(o.input_msat)).unwrap_or_default())),
            esc(&fv("name", editing.map(|o| o.name.clone()).unwrap_or_default())), kind.words(),
            if fv("app", editing.map(|o| if o.app.is_some() { "1" } else { "" }.to_string()).unwrap_or_default()) == "1" { " checked" } else { "" },
            accounts_html,
            esc(&fv("app_base", editing.and_then(|o| o.app.as_ref()).map(|a| a.base.clone()).unwrap_or_default())),
            if kind == Kind::Media { "/" } else { "the path it is sold under" },
            esc(&fv("app_entry", editing.and_then(|o| o.app.as_ref()).filter(|a| a.entry != a.base).map(|a| a.entry.clone()).unwrap_or_default())),
            esc(&fv("app_login", editing.and_then(|o| o.app.as_ref()).map(|a| a.login.clone()).unwrap_or_default())),
            if editing.and_then(|o| o.app.as_ref()).is_none_or(|a| a.live) { " checked" } else { "" },
            esc(&fv("app_deny", editing.and_then(|o| o.app.as_ref()).map(|a| a.deny.join("\n")).unwrap_or_default())),
            esc(&fv("app_allow", editing.and_then(|o| o.app.as_ref()).map(|a| a.allow.join("\n")).unwrap_or_default())),
            esc(&fv("titles", titles)),
            esc(&fv("paths", editing.map(|o| o.paths.join(", ")).unwrap_or_default())),
            if fv("strip", editing.map(|o| if o.strip { "1" } else { "" }.to_string()).unwrap_or_else(|| "1".into())) == "1" { " checked" } else { "" },
            capacity_html,
            if keys { "" } else { " class=\"secondary\"" }, if editing.is_some() { "Save changes" } else { "Add and start selling" },
            if editing.is_some() { "<a href=\"./sell\">Cancel</a>" } else { "" }));

        // advanced
        let (ms, spa, mh) = shop.caps.unwrap_or(if main { (MAINNET_CAPS.0.into(), MAINNET_CAPS.1.into(), MAINNET_CAPS.2.into()) }
                                                else { (TEST_CAPS.0.into(), TEST_CAPS.1.into(), TEST_CAPS.2.into()) });
        let facts = format!("<p class=\"small\">Chain: {}. Lightning node: {}.</p>", if chain.is_empty() { "unknown".into() } else { esc(&chain) },
                            gw.node_rest.as_deref().map(|r| format!("found at <code>{}</code>", esc(r))).unwrap_or_else(|| "not given by this box".into()));
        b.push_str(&format!("<details class=\"card advanced\"><summary>Advanced settings</summary>\
            <form method=\"post\" action=\"./sell\">{csrf}<input type=\"hidden\" name=\"action\" value=\"advanced\">\
            <label>Buyers at once<input name=\"max_sessions\" value=\"{ms}\" inputmode=\"numeric\" pattern=\"[0-9]+\"></label>\
            <label>Buyers at once from one address<input name=\"sessions_per_address\" value=\"{spa}\" inputmode=\"numeric\" pattern=\"[0-9]+\"></label>\
            <label>Payments held open at once (1,000 sat each, on your inbound channels)<input name=\"max_held_tickets\" value=\"{mh}\" inputmode=\"numeric\" pattern=\"[0-9]+\"></label>\
            <label>Your proxy's addresses, whose word on the buyer's address the shop believes (comma-separated)<input name=\"proxies\" value=\"{}\" class=\"mono\"></label>\
            <label>Test chain only: its network id<input name=\"network\" value=\"{}\" class=\"mono\" placeholder=\"bip122:…\"></label>\
            <button>Save advanced settings</button></form>\
            {}{}\
            <form method=\"post\" action=\"./sell\">{csrf}<input type=\"hidden\" name=\"action\" value=\"connect\"><h3>Replace the node keys</h3>\
            <label>Payment requests key<textarea name=\"invoices_macaroon\" rows=\"2\" class=\"mono\" autocomplete=\"off\"></textarea></label>\
            <label>Network time key<textarea name=\"info_macaroon\" rows=\"2\" class=\"mono\" autocomplete=\"off\"></textarea></label>\
            <label>Link signing key <small>(<code>message:write</code> only)</small><textarea name=\"sign_macaroon\" rows=\"2\" class=\"mono\" autocomplete=\"off\"></textarea></label>\
            <button class=\"secondary\">Replace</button></form>\
            {}</details>",
            esc(&shop.proxies), esc(&shop.network),
            facts,
            if main { format!("<p class=\"small\">On mainnet keep these low: {} buyers, {} per address, {} held payments.</p>", MAINNET_CAPS.0, MAINNET_CAPS.1, MAINNET_CAPS.2) } else { String::new() },
            self.gateway_now().map(|c| format!("<details><summary>The settings the shop reads</summary>{}</details>", json_block(&hide_header_values(c)))).unwrap_or_default()));
        self.page("Sell", ctx, b)
    }

    pub(crate) fn sell_post(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let g = |k: &str| f.get(k).map(|s| s.trim().to_string()).unwrap_or_default();
        let mut shop = self.shop();
        let action = g("action");
        let result: Result<String, String> = match action.as_str() {
            "pin_cert" => {
                let gw = &self.cfg.gw;
                pin_cert(gw.node_pin, gw.node_rest.as_deref(), gw.node_tls_cert.as_deref(), &g("fingerprint"))
            }
            "connect" => (|| {
                let mut macs = vec![];
                // the link signing key is optional: without it the node never vouches for the shop's direct
                // link, so the shop sells at a web address only (the shop key card says so)
                let sign = g("sign_macaroon");
                if !sign.is_empty() {
                    let what = "The link signing key";
                    let mac = decode_macaroon(&sign).map_err(|_| format!("{what} is not a key: copy it again, whole."))?;
                    sign_key_fits(&mac).map_err(|e| format!("{what} does not fit: {e}"))?;
                    macs.push((GW_SIGN, mac));
                }
                for (field, file, ops, what) in [("invoices_macaroon", GW_INVOICES, &INVOICE_OPS[..], "The payment requests key"),
                                                 ("info_macaroon", GW_INFO, &INFO_OPS[..], "The network time key")] {
                    let text = g(field);
                    if text.is_empty() {
                        if self.cfg.gw.dir.join(file).is_file() {
                            continue;
                        }
                        return Err(format!("{what} is missing: paste it from your Lightning node app."));
                    }
                    let mac = decode_macaroon(&text).map_err(|_| format!("{what} is not a key: copy it again, whole."))?;
                    checked_macaroon(&mac, what, ops, true).map_err(|e| format!("{what} does not fit: {e}"))?;
                    macs.push((file, mac));
                }
                if macs.is_empty() {
                    return Err("Paste at least one key to replace.".into());
                }
                let only_sign = macs.iter().all(|(file, _)| *file == GW_SIGN);
                for (file, mac) in macs {
                    write_shared(&self.cfg.gw.dir, file, &mac)?;
                }
                let words = self.commit(&shop, "Your Lightning node is connected.")?;
                // the gateway reads the sign key itself at its next look at the link: nothing restarts for it
                Ok(if only_sign {
                    words.replace(" Your shop restarts with it in a few seconds.", " Your node vouches for your shop's link within a minute, with no restart.")
                } else {
                    words
                })
            })(),
            "shop" => {
                shop.name = g("name").chars().take(200).collect();
                // without a choice (an older page), a typed https address means a web shop
                shop.direct = match g("reach").as_str() { "direct" => true, "web" => false, _ => g("public_url").trim().is_empty() };
                shop.private = shop.direct && g("private") == "1";
                shop.public_url = if shop.direct { String::new() } else { g("public_url").trim_end_matches('/').to_string() };
                shop.mainnet_ok = g("mainnet_ok") == "1";
                if !shop.direct && shop.public_url.is_empty() {
                    Err("Paste your https:// address, or choose to be reached directly through the app.".into())
                } else if !shop.public_url.is_empty() && !shop.public_url.starts_with("https://") && !shop.public_url.starts_with("http://127.0.0.1")
                    && !shop.public_url.starts_with("http://localhost") && !shop.public_url.starts_with("http://[::1]") {
                    Err("Buyers reach you at an https:// address, like https://films.example.com.".into())
                } else {
                    self.commit(&shop, "Saved.").and_then(|words| self.follow_public_url(&shop).map(|()| words))
                }
            }
            "check_public" => self.check_public(&shop),
            "service" => (|| {
                let kind = Kind::parse(&g("kind")).ok_or("Pick what it is: a media server, files, an AI model, or another web service.")?;
                // a folder is served by the app itself: its address is the app's, never typed
                let address = if kind == Kind::Files { self.files_upstream() } else { check_address(&g("address"), kind)? };
                // the folder the owner picked under the box's shared one: held to it, kept for the server
                if kind == Kind::Files && self.cfg.files.root.is_some() {
                    crate::files::save_choice(&self.cfg.files, &g("files_folder"))?;
                }
                let price_msat = sats_to_msat(&g("price"))?;
                let unit = Unit::parse(&g("unit")).ok_or("Pick what the price is for.")?;
                let input_msat = if g("input_price").trim().is_empty() { 0 } else { sats_to_msat(&g("input_price"))? };
                if input_msat > 0 && unit != Unit::Tokens {
                    return Err("A price for the question is for a price per 1,000 tokens: pick that, or leave the question free.".into());
                }
                let name = { let n: String = g("name").chars().take(120).collect(); if n.is_empty() { kind.words().to_string() } else { n } };
                let mut titles = vec![];
                for (i, line) in g("titles").lines().map(str::trim).filter(|l| !l.is_empty()).enumerate() {
                    let (t, u) = line.rsplit_once('|').map(|(t, u)| (t.trim(), u.trim()))
                        .ok_or_else(|| format!("Line {} of the list has no link: write it as name | link.", i + 1))?;
                    if t.is_empty() || !(u.starts_with('/') || u.starts_with("http://") || u.starts_with("https://")) {
                        return Err(format!("Line {} of the list: write it as name | link, where the link starts with https:// or /.", i + 1));
                    }
                    titles.push((t.to_string(), u.to_string()));
                }
                // films listed for the built-in player, which buyers' apps no longer have: a media server is its web app;
                // a folder lists what is in it, read again each time the shop is saved
                if matches!(kind, Kind::Media | Kind::Files) {
                    titles.clear();
                }
                let id = g("id");
                if id.is_empty() && shop.offers.len() >= MAX_SERVICES {
                    return Err(format!("A shop sells at most {MAX_SERVICES} services."));
                }
                let new_id = if id.is_empty() { format!("s{}", hex::encode(crate::random_bytes::<4>())) } else { id.clone() };
                let mut paths: Vec<String> = g("paths").split(',').map(str::trim).filter(|p| !p.is_empty()).map(str::to_string).collect();
                for p in &paths {
                    if !p.starts_with('/') || p.contains(['?', '#', '%', ' ', '\\']) || p.contains("//") {
                        return Err(format!("The path {p} is not a path: it starts with / and has no spaces."));
                    }
                    if shop.offers.iter().any(|o| o.id != new_id && o.paths.contains(p)) {
                        return Err(format!("Another service is already sold under {p}."));
                    }
                }
                if paths.is_empty() {
                    paths = match shop.offers.iter().find(|o| o.id == new_id) {
                        Some(o) if !o.paths.is_empty() => o.paths.clone(),
                        _ => vec![shop.free_path(&name, kind, &new_id)],
                    };
                }
                let mut accounts_key: Option<String> = None;
                // a media server is sold as its own web app: buyers use it as they would at home, with no player of
                // the app's own
                let app = if kind == Kind::Files {
                    None
                } else if g("app") == "1" || kind == Kind::Media {
                    // a media server's page uses paths all over the service (Jellyfin: /web/, /Users/, /Items/…); an AI model's or a web app's, its own path
                    let base = match g("app_base").trim() {
                        "" if kind == Kind::Media => "/".to_string(),
                        "" => paths.first().cloned().unwrap_or_else(|| "/".into()),
                        b => format!("{}/", b.trim_end_matches('/')),
                    };
                    if !base.starts_with('/') || base.contains(['?', '#', '%', ' ', '\\']) || base.contains("//") {
                        return Err(format!("{base} is not a path: it starts with / and has no spaces."));
                    }
                    if let Some(o) = shop.offers.iter().filter(|o| o.id != new_id).find(|o| o.paths.contains(&base) || o.app.as_ref().is_some_and(|a| a.base == base)) {
                        return Err(format!("{} already uses {base}, so {name} cannot have it. Edit one of them: give it another path \
                                            (Paths it is sold under, and What the page sees as /, under its web page and Advanced).", o.name));
                    }
                    let entry = match g("app_entry").trim() {
                        "" => base.clone(),
                        e if e.starts_with('/') && !e.contains(['#', ' ', '\\']) && !e.contains("//") => e.to_string(),
                        e => return Err(format!("{e} is not a path: it starts with / and has no spaces.")),
                    };
                    if !entry.starts_with(&base) {
                        return Err(format!("Where the page opens ({entry}) is under what it sees as / ({base})."));
                    }
                    let login = g("app_login").trim().to_string();
                    login_header(&login)?;
                    let (deny, allow) = (app_paths(&g("app_deny"))?, app_paths(&g("app_allow"))?);
                    // each buyer an account of their own: the seller's key is checked against the service, and its
                    // libraries listed; none ticked is all of them
                    let accounts = if g("app_accounts") == "1" {
                        if price_msat == 0 && input_msat == 0 {
                            return Err("Buyers get accounts of their own only on a priced service: a buyer is known by what they paid.".into());
                        }
                        let saved = std::fs::read_to_string(self.cfg.gw.dir.join(app_key_name(&new_id))).ok().map(|t| t.trim().to_string()).filter(|t| !t.is_empty());
                        let key = match (g("app_key"), saved) {
                            (k, _) if !k.is_empty() => api_key(&k)?,
                            (_, Some(k)) => k,
                            _ => return Err("Paste your Jellyfin API key, so the shop can make each buyer's account.".into()),
                        };
                        let libs = jellyfin_libraries(&address, &key)?;
                        let ticked: Vec<String> = libs.iter().filter(|(id, _)| f.get(&format!("app_lib_{id}")).is_some_and(|v| v == "1")).map(|(id, _)| id.clone()).collect();
                        accounts_key = Some(key);
                        Some(if ticked.is_empty() { libs.into_iter().map(|(id, _)| id).collect() } else { ticked })
                    } else {
                        None
                    };
                    Some(OfferApp { base, entry, login, deny, allow, live: g("app_live") == "1", accounts })
                } else {
                    None
                };
                let limit = |k: &str, what: &str| -> Result<Option<u32>, String> {
                    let t = g(k);
                    let t = t.trim();
                    if t.is_empty() {
                        return Ok(None);
                    }
                    t.parse::<u32>().ok().filter(|n| (1..=1_000_000).contains(n)).map(Some)
                        .ok_or_else(|| format!("{what} is a whole number from 1, or empty for no limit."))
                };
                let capacity = xbt_gateway::config::Capacity {
                    max_buyers: limit("cap_buyers", "Most buyers at once")?,
                    max_streams: limit("cap_streams", "Most streams at once")?,
                    max_streams_per_buyer: limit("cap_streams_buyer", "Most streams for one buyer")?,
                    max_mbit: limit("cap_mbit", "Most Mbit/s together")?,
                };
                let strip = g("strip") == "1" || kind == Kind::Files;
                let offer = Offer { id: new_id.clone(), name, kind, address, price_msat, unit, input_msat, paused: false, paths, strip, titles, app, capacity };
                match shop.offers.iter_mut().find(|o| o.id == new_id) {
                    Some(o) => {
                        let paused = o.paused;
                        *o = Offer { paused, ..offer };
                    }
                    None if !id.is_empty() => return Err("That service is gone: add it again.".into()),
                    None => shop.offers.push(offer),
                }
                // the key goes beside the gateway's config before the route that names it; a service without accounts keeps none
                let key_name = app_key_name(&new_id);
                match &accounts_key {
                    Some(k) => crate::setup::write_shared(&self.cfg.gw.dir, &key_name, format!("{k}\n").as_bytes())?,
                    None => {
                        crate::setup::remove_shared(&self.cfg.gw.dir, &key_name)?;
                    }
                }
                self.commit(&shop, if id.is_empty() { "Added." } else { "Changes saved." })
            })(),
            "files_refresh" => self.commit(&shop, "The file list is updated: buyers see what is in the folder now."),
            "pause" | "resume" | "remove" => {
                let id = g("id");
                match shop.offers.iter().position(|o| o.id == id) {
                    None => Err("That service is gone already.".into()),
                    Some(i) => {
                        let what = match action.as_str() {
                            "pause" => { shop.offers[i].paused = true; "Paused: buyers cannot buy it until you resume it." }
                            "resume" => { shop.offers[i].paused = false; "Resumed." }
                            _ => {
                                // unchecked: its key, where buyers had accounts, goes with it; one left behind names no route
                                let _ = crate::setup::remove_shared(&self.cfg.gw.dir, &app_key_name(&shop.offers[i].id));
                                shop.offers.remove(i);
                                "Removed."
                            }
                        };
                        self.commit(&shop, what)
                    }
                }
            }
            "advanced" => (|| {
                let n = |k: &str| g(k).parse::<u64>().map_err(|_| "Each number under Advanced is a whole number.".to_string());
                shop.caps = Some((n("max_sessions")?, n("sessions_per_address")?, n("max_held_tickets")?));
                shop.proxies = g("proxies");
                shop.network = g("network");
                self.commit(&shop, "Advanced settings saved.")
            })(),
            _ => Err("Unknown action.".into()),
        };
        match result {
            Ok(m) => {
                self.flash(ctx, true, m);
                Resp::redirect("./sell")
            }
            Err(e) if action == "service" || action == "shop" => self.sell_html(ctx, f.get("id").map(String::as_str).filter(|s| !s.is_empty()), Some((f, e))),
            Err(e) => {
                self.flash(ctx, false, e);
                Resp::redirect("./sell")
            }
        }
    }
}

/// The usual addresses of media servers and AI models on Umbrel (`<app id>_<service>_1`) and
/// StartOS (`<package>.startos`, `<package>.embassy`). An address that does not resolve is not offered.
const KNOWN_SERVICES: &[(&str, &str)] = &[
    ("Jellyfin", "http://jellyfin_server_1:8096"),
    ("Jellyfin", "http://jellyfin_jellyfin_1:8096"),
    ("Jellyfin", "http://jellyfin.startos:8096"),
    ("Jellyfin", "http://jellyfin.embassy:8096"),
    ("Plex", "http://plex_server_1:32400"),
    ("Navidrome", "http://navidrome_server_1:4533"),
    ("Audiobookshelf", "http://audiobookshelf_web_1:80"),
    ("Ollama", "http://ollama_ollama_1:11434"),
    ("Ollama", "http://ollama.startos:11434"),
    ("Open WebUI", "http://open-webui_web_1:8080"),
    ("LlamaGPT", "http://llama-gpt_llama-gpt-api_1:8000"),
];

/// The link signing key signs messages and does nothing else: lnd's `message:write` (what Lightning
/// Fork's dashboard bakes), SignMessage's URI permission (what node-keys bakes), or both. Anything
/// more is refused by name, and so is a key whose permissions cannot be read.
fn sign_key_fits(mac: &[u8]) -> Result<(), String> {
    let m = xbt402::macaroon::parse(mac)?;
    let need = SIGN_ENTITY_OPS.join(" ");
    if !m.readable() {
        return Err(format!("its permissions cannot be read (not this node's identifier): bake one with only {need}"));
    }
    // readable: at least one permission, so with nothing outside the two, one of them is there
    let allowed: Vec<&str> = SIGN_ENTITY_OPS.iter().chain(SIGN_OPS.iter()).copied().collect();
    match m.outside(&allowed).as_slice() {
        [] => Ok(()),
        more => Err(format!("it also grants {}: bake one with only {need}", more.join(", "))),
    }
}

/// Whether something listens at `url`'s host and port (a TCP connect, at most 600 ms).
fn answers(url: &str) -> bool {
    use std::net::ToSocketAddrs;
    let hostport = url.trim_start_matches("http://").split('/').next().unwrap_or("");
    let Ok(addrs) = hostport.to_socket_addrs() else { return false };
    addrs.take(2).any(|a| std::net::TcpStream::connect_timeout(&a, std::time::Duration::from_millis(600)).is_ok())
}

/// The services found on this box, as suggestions for the address field and one-click fills.
fn found_html(found: &[(String, String)]) -> String {
    if found.is_empty() {
        return "<p class=\"hint\">On Umbrel and StartOS this is the app's own address on the box, such as <code>http://jellyfin_server_1:8096</code>.</p>".into();
    }
    let mut b = String::from("<datalist id=\"found-services\">");
    for (n, u) in found {
        b.push_str(&format!("<option value=\"{}\">{}</option>", esc(u), esc(n)));
    }
    b.push_str("</datalist><p class=\"hint\">Found on this box: ");
    b.push_str(&found.iter().map(|(n, u)| format!("<button type=\"button\" class=\"link\" data-fill=\"address\" data-value=\"{}\">{} <code>{}</code></button>",
                                                    esc(u), esc(n), esc(u))).collect::<Vec<_>>().join(" · "));
    b.push_str("</p>");
    b
}

/// What a route carries now, in plain words, from its `/services` entry (`capacity`).
fn capacity_words(c: &Value) -> String {
    let n = |k: &str| c.get(k).and_then(Value::as_u64);
    let part = |used: Option<u64>, max: Option<u64>, what: &str| match (used, max) {
        (Some(u), Some(m)) => Some(format!("{u} of {m} {what}")),
        (Some(u), None) => Some(format!("{u} {what}")),
        _ => None,
    };
    let parts: Vec<String> = [part(n("buyers"), n("maxBuyers"), "buyers"), part(n("streams"), n("maxStreams"), "streams")].into_iter().flatten().collect();
    if parts.is_empty() {
        return String::new();
    }
    let busy = c.get("busy").and_then(Value::as_bool) == Some(true);
    format!("<p class=\"hint{}\">Now: {}{}</p>", if busy { " warn" } else { "" }, parts.join(", "),
            if busy { ". Full: new buyers are told to try again shortly." } else { "." })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_settings_shown_hide_every_header_value() {
        let c = json!({"routes": [{"path": "/files/", "upstream_headers": {"x-stream-files-key": "secret1"}},
                                  {"path": "/app/", "upstream_headers": {"x-emby-authorization": "secret2"}, "free": false}],
                       "nostr": {"publish": true}});
        let shown = hide_header_values(c).to_string();
        assert!(!shown.contains("secret1") && !shown.contains("secret2"), "{shown}");
        assert!(shown.contains("x-stream-files-key") && shown.contains("(hidden)") && shown.contains("\"publish\":true"), "{shown}");
    }

    #[test]
    fn sats_are_typed_as_people_write_them() {
        assert_eq!(sats_to_msat("20").unwrap(), 20_000);
        assert_eq!(sats_to_msat(" 1,000 ").unwrap(), 1_000_000);
        assert_eq!(sats_to_msat("0.5").unwrap(), 500);
        assert_eq!(sats_to_msat(".25").unwrap(), 250);
        assert_eq!(sats_to_msat("0").unwrap(), 0);
        for bad in ["", "abc", "1.2345", "-1", "1e3", ".", "99999999999999999999"] {
            assert!(sats_to_msat(bad).is_err(), "{bad}");
        }
        assert_eq!(msat_to_sats(20_000), "20");
        assert_eq!(msat_to_sats(500), "0.5");
        assert_eq!(msat_to_sats(20), "0.02");
    }

    #[test]
    fn an_address_is_one_the_gateway_can_pass_requests_to() {
        assert_eq!(check_address(" http://jellyfin:8096/ ", Kind::Media).unwrap(), "http://jellyfin:8096");
        assert!(check_address("", Kind::Media).unwrap_err().contains("media server"));
        assert!(check_address("https://x", Kind::Ai).unwrap_err().contains("http://"));
        assert!(check_address("jellyfin:8096", Kind::Media).is_err());
        assert!(check_address("http://a?b", Kind::Web).is_err());
    }

    #[test]
    fn a_hand_written_config_reads_as_offers() {
        let c = json!({"public_url": "https://films.example", "upstream": "http://jellyfin:8096", "chain": "main", "mainnet_ack": MAINNET_ACK,
            "routes": [{"path": "/Videos/a/", "price": {"byte_msat": 20, "per_bytes": 1048576}},
                       {"path": "/Videos/b/", "price": {"byte_msat": 20, "per_bytes": 1048576}},
                       {"path": "/ai/", "upstream": "http://ollama:11434", "strip_prefix": true, "price": {"request_msat": 5000}}],
            "listing": {"name": "Films", "kind": "video", "prices": {}, "items": [{"title": "Sintel", "url": "https://films.example/Videos/a/s"}],
                        "licence": "x", "credits": "y", "updated": "z"}});
        let s = Shop::import(&c);
        assert!(s.mainnet_ok);
        assert_eq!(s.offers.len(), 2);
        let films = &s.offers[0];
        assert_eq!((films.kind, films.unit, films.price_msat, films.paths.len(), films.name.as_str()), (Kind::Media, Unit::Mib, 20, 2, "Films"));
        assert_eq!(films.titles, [("Sintel".to_string(), "https://films.example/Videos/a/s".to_string())]);
        let ai = &s.offers[1];
        assert_eq!((ai.address.as_str(), ai.strip, ai.price_msat, ai.unit), ("http://ollama:11434", true, 5000, Unit::Request));
        // and back: the file the page keeps reads as it was written
        assert_eq!(Shop::from_json(&s.to_json()), s);
    }

    #[test]
    fn a_model_priced_by_the_token_reads_and_writes_plainly() {
        let c = json!({"routes": [{"path": "/ai/", "upstream": "http://ollama:11434", "price": {"per_1k_output_msat": 10000}},
                                  {"path": "/big/", "upstream": "http://big:1", "price": {"per_1k_output_msat": 30000, "per_1k_input_msat": 5000}}]});
        let s = Shop::import(&c);
        assert_eq!((s.offers[0].unit, s.offers[0].price_msat, s.offers[0].input_msat), (Unit::Tokens, 10_000, 0));
        assert_eq!(s.offers[0].price_words(), "10 sat per 1,000 tokens");
        assert_eq!((s.offers[1].input_msat, s.offers[1].price_words().as_str()), (5000, "5 sat per 1,000 tokens in, 30 sat per 1,000 tokens out"));
        assert_eq!(Shop::from_json(&s.to_json()), s);
        assert_eq!(Kind::Ai.suggested(), ("10", Unit::Tokens));
    }

    #[test]
    fn new_offers_get_a_path_of_their_own() {
        let mut s = Shop::default();
        // anything but a media server keeps off the root, even first, so that one added later finds it free
        assert_eq!(s.free_path("My files", Kind::Files, "f"), "/my-files/");
        assert_eq!(s.free_path("Model", Kind::Ai, "f"), "/model/");
        assert_eq!(s.free_path("Films", Kind::Media, "a"), "/");
        s.offers.push(Offer { id: "f".into(), name: "My files".into(), kind: Kind::Files, address: "http://127.0.0.1:8486".into(), price_msat: 1, unit: Unit::Gb,
                              input_msat: 0, paused: false, paths: vec!["/my-files/".into()], strip: true, titles: vec![], app: None, capacity: Default::default() });
        assert_eq!(s.free_path("Films", Kind::Media, "a"), "/", "a media server after a folder still gets the root");
        s.offers.push(Offer { id: "a".into(), name: "Films".into(), kind: Kind::Media, address: "http://j:1".into(), unit: Unit::Mib, paths: vec!["/".into()],
                              strip: false, ..s.offers[0].clone() });
        assert_eq!(s.free_path("My AI model!", Kind::Ai, "b"), "/my-ai-model/");
        assert_eq!(s.free_path("Films", Kind::Media, "a"), "/", "an offer keeps the root it has");
        assert_eq!(s.free_path("Plex", Kind::Media, "p"), "/plex/", "a second media server: the root is taken");
        s.offers.push(Offer { id: "b".into(), paths: vec!["/x/".into()], ..s.offers[0].clone() });
        assert_eq!(s.free_path("x", Kind::Web, "c"), "/x-2/");
        assert_eq!(s.free_path("x402", Kind::Web, "c"), "/x402-2/");
        // a web app whose page sees the root holds it as well
        s.offers.push(Offer { id: "w".into(), paths: vec!["/w/".into()],
                              app: Some(OfferApp { base: "/".into(), entry: "/".into(), login: String::new(), deny: vec![], allow: vec![], live: false, accounts: None }),
                              ..s.offers[0].clone() });
        s.offers.retain(|o| o.id != "a");
        assert_eq!(s.free_path("Films", Kind::Media, "a"), "/films/");
    }
}
