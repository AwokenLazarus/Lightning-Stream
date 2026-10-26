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
use xbt_gateway::config::{Config as GatewayConfig, MAINNET_ACK, MAINNET_NOTICE};
use xbt_gateway::node::{checked_macaroon, INFO_OPS, INVOICE_OPS};

use crate::setup::{decode_macaroon, pin_card, pin_cert, write_shared, GW_CONFIG, GW_INFO, GW_INVOICES, MAINNET_CAPS, TEST_CAPS};
use super::{App, Ctx};
use crate::html::{esc, json_block};
use crate::server::Resp;

pub const SELL_FILE: &str = "sell.json";
pub const MAX_SERVICES: usize = 16;
const MIB: u64 = 1_048_576;

/// The kinds an owner picks from, with the words, the listing's kind, and the suggested price.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Media,
    Ai,
    Web,
    Other,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "media" => Some(Kind::Media),
            "ai" => Some(Kind::Ai),
            "web" => Some(Kind::Web),
            "other" => Some(Kind::Other),
            _ => None,
        }
    }
    pub fn id(self) -> &'static str {
        match self {
            Kind::Media => "media",
            Kind::Ai => "ai",
            Kind::Web => "web",
            Kind::Other => "other",
        }
    }
    pub fn words(self) -> &'static str {
        match self {
            Kind::Media => "Media server",
            Kind::Ai => "AI model",
            Kind::Web => "Web service or API",
            Kind::Other => "Something else",
        }
    }
    /// How the status names the service when it cannot be reached.
    fn thing(self) -> &'static str {
        match self {
            Kind::Media => "your media server",
            Kind::Ai => "your AI model",
            Kind::Web | Kind::Other => "your service",
        }
    }
    fn listing_kind(self) -> &'static str {
        match self {
            Kind::Media => "video",
            Kind::Ai => "ai",
            Kind::Web | Kind::Other => "api",
        }
    }
    fn from_listing(k: &str) -> Self {
        match k {
            "video" => Kind::Media,
            "ai" => Kind::Ai,
            "files" => Kind::Other,
            _ => Kind::Web,
        }
    }
    /// The suggested price: (sats, unit).
    pub fn suggested(self) -> (&'static str, Unit) {
        match self {
            Kind::Media => ("20", Unit::Mib),
            // a few sats for a reply of a few hundred tokens
            Kind::Ai => ("10", Unit::Tokens),
            Kind::Web | Kind::Other => ("1", Unit::Request),
        }
    }
    fn example(self) -> &'static str {
        match self {
            Kind::Media => "http://jellyfin:8096",
            Kind::Ai => "http://ollama:11434",
            Kind::Web | Kind::Other => "http://my-app:8080",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    Mib,
    Request,
    Second,
    /// 1,000 tokens an AI model writes (an OpenAI-compatible service).
    Tokens,
}

impl Unit {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "mib" => Some(Unit::Mib),
            "request" => Some(Unit::Request),
            "second" => Some(Unit::Second),
            "tokens" => Some(Unit::Tokens),
            _ => None,
        }
    }
    pub fn id(self) -> &'static str {
        match self {
            Unit::Mib => "mib",
            Unit::Request => "request",
            Unit::Second => "second",
            Unit::Tokens => "tokens",
        }
    }
    fn words(self) -> &'static str {
        match self {
            Unit::Mib => "a MiB of data sent",
            Unit::Request => "a request",
            Unit::Second => "a second",
            Unit::Tokens => "1,000 tokens the model writes",
        }
    }
    fn short(self) -> &'static str {
        match self {
            Unit::Mib => "a MiB",
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

/// The shop and its offers: `sell.json`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Shop {
    pub name: String,
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
    json!({"id": o.id, "name": o.name, "kind": o.kind.id(), "address": o.address, "price_msat": o.price_msat, "unit": o.unit.id(), "input_msat": o.input_msat,
           "paused": o.paused, "paths": o.paths, "strip": o.strip,
           "titles": o.titles.iter().map(|(t, u)| json!({"title": t, "url": u})).collect::<Vec<_>>()})
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
    })
}

impl Shop {
    pub fn to_json(&self) -> Value {
        let mut v = json!({"name": self.name, "public_url": self.public_url, "proxies": self.proxies, "network": self.network,
                           "mainnet_ok": self.mainnet_ok, "offers": self.offers.iter().map(offer_json).collect::<Vec<_>>()});
        if let Some((a, b, c)) = self.caps {
            v["caps"] = json!([a, b, c]);
        }
        v
    }

    pub fn from_json(v: &Value) -> Self {
        let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let caps = v.get("caps").and_then(Value::as_array).and_then(|a| Some((a.first()?.as_u64()?, a.get(1)?.as_u64()?, a.get(2)?.as_u64()?)));
        Shop { name: s("name"), public_url: s("public_url"), proxies: s("proxies"), network: s("network"),
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
                                price_msat: msat, unit, input_msat, paused: false, paths: vec![path], strip, titles });
        }
        let caps = c.get("caps").and_then(|k| Some((k.get("max_sessions")?.as_u64()?, k.get("sessions_per_address")?.as_u64()?,
                                                    k.get("max_held_tickets")?.as_u64()?)));
        let proxies = c.pointer("/http/forwarded_address/proxies").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default();
        Shop { name: s("/listing/name"), public_url: s("/public_url"), proxies, network: s("/network"),
               mainnet_ok: s("/chain") == "main" && s("/mainnet_ack") == MAINNET_ACK, caps, offers }
    }

    /// A path no other offer uses: `/` for the first, `/<name>/` after.
    fn free_path(&self, name: &str, except: &str) -> String {
        let used = |p: &str| self.offers.iter().filter(|o| o.id != except).any(|o| o.paths.iter().any(|x| x == p));
        if !used("/") && self.offers.iter().filter(|o| o.id != except).count() == 0 {
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
        let public_url = shop.public_url.trim().trim_end_matches('/').to_string();
        if public_url.is_empty() {
            return Err("Say where buyers find you.".into());
        }
        let local = ["http://127.0.0.1", "http://[::1]", "http://localhost"].iter()
            .any(|p| public_url == *p || public_url.strip_prefix(p).is_some_and(|r| r.starts_with(':')));
        if !public_url.starts_with("https://") && !local {
            return Err("Buyers reach you at an https:// address. Put the address of your box's secure link here.".into());
        }
        let active: Vec<&Offer> = shop.offers.iter().filter(|o| !o.paused).collect();
        let main = chain == "main";
        if main && !shop.mainnet_ok {
            return Err("Confirm you are ready to take real payments.".into());
        }
        let mut c: Map<String, Value> = self.gateway_now().and_then(|v| v.as_object().cloned()).unwrap_or_default();
        let old_routes: Vec<Value> = c.get("routes").and_then(Value::as_array).cloned().unwrap_or_default();
        c.insert("listen".into(), json!(if public_url.starts_with("https://") { format!("0.0.0.0:{}", gw.port) } else { format!("127.0.0.1:{}", gw.port) }));
        c.insert("public_url".into(), json!(public_url));
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
        if proxies.is_empty() {
            c.remove("http");
        } else {
            c.insert("http".into(), json!({"forwarded_address": {"header": "x-forwarded-for", "proxies": proxies}}));
        }
        let mut routes = vec![];
        let mut sections = vec![];
        for o in &active {
            let price = match o.unit {
                Unit::Mib => json!({"byte_msat": o.price_msat, "per_bytes": MIB}),
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
                        Kind::Media => json!({}),
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
                routes.push(r);
            }
            let base = public_url.clone();
            let items: Vec<Value> = o.titles.iter().map(|(t, u)| {
                let url = if u.starts_with('/') { format!("{base}{u}") } else { u.clone() };
                json!({"title": t, "url": url})
            }).collect();
            if let Some(p) = o.paths.first() {
                sections.push(json!({"name": o.name, "kind": o.kind.listing_kind(), "path": p, "items": items}));
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
        c.insert("routes".into(), Value::Array(routes));
        if sections.is_empty() {
            c.remove("listing");
        } else {
            let name = if shop.name.trim().is_empty() { "Lightning Stream seller".to_string() } else { shop.name.trim().to_string() };
            c.insert("listing".into(), json!({"name": name, "updated": crate::html::utc(crate::now()).chars().take(10).collect::<String>(),
                                              "services": sections}));
        }
        let v = Value::Object(c);
        GatewayConfig::from_json(&v).map_err(|e| format!("These settings do not work together: {e}"))?;
        Ok(v)
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

    fn reachable(address: &str) -> bool {
        crate::app::http_get(&format!("{address}/")).is_ok_and(|(code, _)| code > 0)
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
            each.insert(o.id.clone(), if o.paused {
                st("warn", "Paused", "Buyers cannot buy it. Resume it to sell again.")
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
            Ok(_) => match self.cfg.gw.health_url.as_deref().map(crate::app::http_get) {
                Some(Ok((200, _))) | None => {
                    if each.values().any(|s| s.class == "bad") {
                        st("bad", "Selling, with a problem", "One of your services can't be reached: see below.")
                    } else {
                        st("ok", "Selling", &format!("Buyers can find you at {}.", shop.public_url.trim_end_matches('/')))
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
                      format!("Buyers find you at {}.", shop.public_url.trim_end_matches('/'))),
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
                <p>Buyers pay you through your Lightning node. Make two keys in your node's app and paste them here. They let this app ask \
                for payments and read the time on the network; they cannot spend your money.</p>\
                <form method=\"post\" action=\"./sell\">{csrf}<input type=\"hidden\" name=\"action\" value=\"connect\">\
                <label>First key: payment requests<textarea name=\"invoices_macaroon\" rows=\"3\" class=\"mono\" autocomplete=\"off\" required></textarea></label>\
                <label>Second key: network time<textarea name=\"info_macaroon\" rows=\"3\" class=\"mono\" autocomplete=\"off\" required></textarea></label>\
                <details><summary>How do I make them?</summary><p>In your Lightning node's app (Lightning Fork), open the page called <em>Macaroons</em> \
                and make two, each with exactly these permissions:</p><ul><li>First key: <code>{}</code></li><li>Second key: <code>{}</code></li></ul>\
                <p class=\"hint\">Give each its own root key, so you can revoke it alone. The app refuses a key with more permissions than these.</p></details>\
                <button>Connect</button></form></section>", INVOICE_OPS.join(" "), INFO_OPS.join(" ")));
        }
        b.push_str(&pin_card(&csrf, gw.node_pin, gw.node_rest.as_deref(), gw.node_tls_cert.as_deref(), "./sell"));

        // the shop
        let pv = |k: &str, d: &str| sent.as_ref().filter(|(f, _)| f.get("action").map(String::as_str) == Some("shop"))
            .and_then(|(f, _)| f.get(k).cloned()).unwrap_or_else(|| d.to_string());
        b.push_str(&format!("<section class=\"card\"><h2>{}Your shop</h2><form method=\"post\" action=\"./sell\">{csrf}\
            <input type=\"hidden\" name=\"action\" value=\"shop\">\
            <label>Shop name, as buyers see it<input name=\"name\" value=\"{}\" maxlength=\"200\" placeholder=\"My shop\"></label>\
            <label>Where buyers find you<input name=\"public_url\" type=\"url\" inputmode=\"url\" value=\"{}\" required pattern=\"https://.+|http://(127\\.0\\.0\\.1|localhost|\\[::1\\])(:[0-9]+)?\" \
            title=\"The https:// address of your box's secure link, like https://films.example.com\" placeholder=\"https://films.example.com\"></label>\
            <p class=\"hint\">The public https:// address that leads to this app's selling port ({}). Buyers' apps pay and connect there.</p>\
            <details><summary>I don't have an https address yet</summary><p>Buyers on the internet need a secure address that leads to this \
            app's selling port. Pick one of these, then paste the address above:</p><ol>\
            <li><strong>Cloudflare Tunnel</strong> (an app in the Umbrel App Store, and a free Cloudflare account with your own domain): make a public \
            hostname, like <code>films.example.com</code>, that points at <code>{}</code>.</li>\
            <li><strong>Another tunnel app</strong> that offers a public https address for a service on this box (several VPN and \
            remote-access apps do): point it at <code>{}</code>.</li>\
            <li><strong>Your own domain and proxy</strong> (for example the Nginx Proxy Manager app): a proxy host with a certificate, forwarding \
            to <code>{}</code>.</li></ol><p class=\"hint\">The app never makes a public address by itself: what is on the internet stays your choice.</p></details>{}\
            <button class=\"secondary\">Save</button></form>{}</section>",
            if keys { "" } else { "2. " }, esc(&pv("name", &shop.name)), esc(&pv("public_url", &shop.public_url)), gw.port,
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

        // what is sold
        b.push_str(&format!("<h2>{}Your services</h2>", if keys { "" } else { "3. " }));
        if shop.offers.is_empty() {
            b.push_str("<p class=\"empty\">Nothing yet. Add your first service below.</p>");
        }
        for o in &shop.offers {
            let s = each.get(&o.id).cloned().unwrap_or(Status { class: "warn", headline: "Unknown".into(), next: String::new() });
            let btn = |action: &str, label: &str, class: &str| format!("<form method=\"post\" action=\"./sell\">{csrf}<input type=\"hidden\" name=\"action\" value=\"{action}\">\
                <input type=\"hidden\" name=\"id\" value=\"{}\"><button{class}>{label}</button></form>", esc(&o.id));
            b.push_str(&format!("<section class=\"card offer\"><div class=\"offer-head\"><h3>{}</h3><span class=\"pill {}\">{}</span></div>\
                <p>{} &middot; <strong>{}</strong>{}</p>{}<div class=\"row\"><a class=\"button-link\" href=\"./sell?edit={}#service-form\">Edit</a>{}{}</div></section>",
                esc(&o.name), s.class, esc(&s.headline), o.kind.words(), o.price_words(),
                if o.titles.is_empty() { String::new() } else { format!(" &middot; {} to choose from", o.titles.len()) },
                if s.next.is_empty() { String::new() } else { format!("<p class=\"hint {}\">{}</p>", s.class, esc(&s.next)) },
                crate::services::urlenc(&o.id),
                if o.paused { btn("resume", "Resume", "") } else { btn("pause", "Pause", " class=\"secondary\"") },
                btn("remove", "Remove", " class=\"danger\"")));
        }

        // add or edit: the page's main action
        let editing = edit.and_then(|id| shop.offers.iter().find(|o| o.id == id));
        let from_form = sent.as_ref().filter(|(f, _)| f.get("action").map(String::as_str) == Some("service")).map(|(f, _)| *f);
        let fv = |k: &str, d: String| from_form.and_then(|f| f.get(k).cloned()).unwrap_or(d);
        let kind = Kind::parse(&fv("kind", editing.map(|o| o.kind.id().to_string()).unwrap_or_else(|| "media".into()))).unwrap_or(Kind::Media);
        let (sug_price, sug_unit) = kind.suggested();
        let unit = Unit::parse(&fv("unit", editing.map(|o| o.unit).unwrap_or(sug_unit).id().to_string())).unwrap_or(sug_unit);
        let kinds: String = [Kind::Media, Kind::Ai, Kind::Web, Kind::Other].iter().map(|k| {
            let (p, u) = k.suggested();
            format!("<label class=\"choice\"><input type=\"radio\" name=\"kind\" value=\"{}\"{}><span><strong>{}</strong><small>suggested {} sat {}</small></span></label>",
                    k.id(), if *k == kind { " checked" } else { "" }, k.words(), p, u.short())
        }).collect();
        let units: String = [Unit::Mib, Unit::Request, Unit::Second, Unit::Tokens].iter()
            .map(|u| format!("<option value=\"{}\"{}>{}</option>", u.id(), if *u == unit { " selected" } else { "" }, u.words())).collect();
        let titles = editing.map(|o| o.titles.iter().map(|(t, u)| format!("{t} | {u}")).collect::<Vec<_>>().join("\n")).unwrap_or_default();
        b.push_str(&format!("<section class=\"card primary\" id=\"service-form\"><h2>{}</h2><form method=\"post\" action=\"./sell\">{csrf}\
            <input type=\"hidden\" name=\"action\" value=\"service\"><input type=\"hidden\" name=\"id\" value=\"{}\">\
            <fieldset class=\"choices\"><legend>What is it?</legend>{kinds}</fieldset>\
            <label>Its address on this box<input name=\"address\" value=\"{}\" required pattern=\"http://[^ ?#@]+\" inputmode=\"url\" class=\"mono\" \
            list=\"found-services\" title=\"The http:// address other apps on this box use, like {}\" placeholder=\"{}\"></label>{}\
            <div class=\"price-row\"><label>Price in sats<input name=\"price\" value=\"{}\" required inputmode=\"decimal\" pattern=\"[0-9][0-9,]*(\\.[0-9]{{1,3}})?|\\.[0-9]{{1,3}}\" \
            title=\"A number of sats, like 20 or 0.5\"></label><label>for each<select name=\"unit\">{units}</select></label></div>\
            <label>Also charge for the question (tokens in) <small>(optional: sats per 1,000 tokens; empty is free)</small>\
            <input name=\"input_price\" value=\"{}\" inputmode=\"decimal\" pattern=\"[0-9][0-9,]*(\\.[0-9]{{1,3}})?|\\.[0-9]{{1,3}}\" title=\"A number of sats, like 2 or 0.5\"></label>\
            <p class=\"hint\">Only for an AI model priced per 1,000 tokens. Usually left empty: buyers then pay for what the model writes.</p>\
            <label>Name, as buyers see it <small>(optional)</small><input name=\"name\" value=\"{}\" maxlength=\"120\" placeholder=\"{}\"></label>\
            <details><summary>Advanced</summary>\
            <label>Items to list for buyers (films, files, models…), one per line: <code>name | link</code><textarea name=\"titles\" rows=\"4\" class=\"mono\">{}</textarea></label>\
            <p class=\"hint\">A link may start with <code>/</code>: it is then on your shop's address.</p>\
            <label>Paths it is sold under, comma-separated (empty: chosen for you)<input name=\"paths\" value=\"{}\" class=\"mono\"></label>\
            <label class=\"check\"><input type=\"checkbox\" name=\"strip\" value=\"1\"{}> Pass requests on without that path</label></details>\
            <div class=\"row\"><button{}>{}</button>{}</div></form></section>",
            if editing.is_some() { "Change this service" } else { "Add a service" },
            esc(editing.map(|o| o.id.as_str()).unwrap_or("")),
            esc(&fv("address", editing.map(|o| o.address.clone()).unwrap_or_default())), kind.example(), kind.example(), found_html(&self.found_services()),
            esc(&fv("price", editing.map(|o| msat_to_sats(o.price_msat)).unwrap_or_else(|| sug_price.to_string()))),
            esc(&fv("input_price", editing.filter(|o| o.input_msat > 0).map(|o| msat_to_sats(o.input_msat)).unwrap_or_default())),
            esc(&fv("name", editing.map(|o| o.name.clone()).unwrap_or_default())), kind.words(),
            esc(&fv("titles", titles)),
            esc(&fv("paths", editing.map(|o| o.paths.join(", ")).unwrap_or_default())),
            if fv("strip", editing.map(|o| if o.strip { "1" } else { "" }.to_string()).unwrap_or_else(|| "1".into())) == "1" { " checked" } else { "" },
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
            <button class=\"secondary\">Replace</button></form>\
            {}</details>",
            esc(&shop.proxies), esc(&shop.network),
            facts,
            if main { format!("<p class=\"small\">On mainnet keep these low: {} buyers, {} per address, {} held payments.</p>", MAINNET_CAPS.0, MAINNET_CAPS.1, MAINNET_CAPS.2) } else { String::new() },
            self.gateway_now().map(|c| format!("<details><summary>The settings the shop reads</summary>{}</details>", json_block(&c))).unwrap_or_default()));
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
                for (file, mac) in macs {
                    write_shared(&self.cfg.gw.dir, file, &mac)?;
                }
                self.commit(&shop, "Your Lightning node is connected.")
            })(),
            "shop" => {
                shop.name = g("name").chars().take(200).collect();
                shop.public_url = g("public_url").trim_end_matches('/').to_string();
                shop.mainnet_ok = g("mainnet_ok") == "1";
                if !shop.public_url.is_empty() && !shop.public_url.starts_with("https://") && !shop.public_url.starts_with("http://127.0.0.1")
                    && !shop.public_url.starts_with("http://localhost") && !shop.public_url.starts_with("http://[::1]") {
                    Err("Buyers reach you at an https:// address, like https://films.example.com.".into())
                } else {
                    self.commit(&shop, "Saved.")
                }
            }
            "check_public" => self.check_public(&shop),
            "service" => (|| {
                let kind = Kind::parse(&g("kind")).ok_or("Pick what it is: a media server, an AI model, or another web service.")?;
                let address = check_address(&g("address"), kind)?;
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
                        _ => vec![shop.free_path(&name, &new_id)],
                    };
                }
                let offer = Offer { id: new_id.clone(), name, kind, address, price_msat, unit, input_msat, paused: false, paths, strip: g("strip") == "1", titles };
                match shop.offers.iter_mut().find(|o| o.id == new_id) {
                    Some(o) => {
                        let paused = o.paused;
                        *o = Offer { paused, ..offer };
                    }
                    None if !id.is_empty() => return Err("That service is gone: add it again.".into()),
                    None => shop.offers.push(offer),
                }
                self.commit(&shop, if id.is_empty() { "Added." } else { "Changes saved." })
            })(),
            "pause" | "resume" | "remove" => {
                let id = g("id");
                match shop.offers.iter().position(|o| o.id == id) {
                    None => Err("That service is gone already.".into()),
                    Some(i) => {
                        let what = match action.as_str() {
                            "pause" => { shop.offers[i].paused = true; "Paused: buyers cannot buy it until you resume it." }
                            "resume" => { shop.offers[i].paused = false; "Resumed." }
                            _ => { shop.offers.remove(i); "Removed." }
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(s.free_path("Films", "a"), "/");
        s.offers.push(Offer { id: "a".into(), name: "Films".into(), kind: Kind::Media, address: "http://j:1".into(), price_msat: 1, unit: Unit::Mib, input_msat: 0,
                              paused: false, paths: vec!["/".into()], strip: false, titles: vec![] });
        assert_eq!(s.free_path("My AI model!", "b"), "/my-ai-model/");
        assert_eq!(s.free_path("Films", "a"), "/", "an offer keeps the root when it is the only one");
        s.offers.push(Offer { id: "b".into(), paths: vec!["/x/".into()], ..s.offers[0].clone() });
        assert_eq!(s.free_path("x", "c"), "/x-2/");
        assert_eq!(s.free_path("x402", "c"), "/x402-2/");
    }
}
