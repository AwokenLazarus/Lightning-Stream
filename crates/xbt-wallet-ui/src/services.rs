//! The services file (`XBT_UI_SERVICES`): what Browse lists and a service's page opens.
//!
//! A JSON list. Each service is `{name, kind, seller, price_text, items}`, with an optional
//! `address`: where apps and agents reach that one service (the seller's origin plus the path it is
//! sold under). `kind` is `video`, `files`, `api` or `ai`. Each item is `{title, year, url, credit}`.
//! `seller`, `address` and every item `url` are absolute `http` or `https` URLs. `year` and `credit`
//! may be left out. An example is
//! `examples/services.example.json` in this crate.
//!
//! The Services page writes this file: a seller added by its address is fetched, its signed
//! listing checked ([`xbt402::listing::fetch`]), and each service it lists saved here
//! ([`from_listing`], [`save`]).
use std::path::Path;

use serde_json::{json, Map, Value};

const MAX_BYTES: u64 = 256 * 1024;
const MAX_SERVICES: usize = 200;
const MAX_ITEMS: usize = 400;
const MAX_TEXT: usize = 300;
const MAX_URL: usize = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Video,
    Files,
    Api,
    Ai,
    Hashrate,
}

/// The categories Browse sorts services into. A media server (Jellyfin, Plex) is a web app: the
/// seller's own app, opened inside Lightning Stream. Files are a seller's shared folder, downloaded or
/// opened in the buyer's own player. The app has no player of its own.
pub const CATEGORIES: [(&str, &str); 5] = [("apps", "Web apps"), ("files", "Files"), ("ai", "AI"), ("hashrate", "Hashrate"), ("data", "Data & APIs")];

/// A category's icon, before its name on Browse's chips and on each service's pill: a picture to tell the kinds apart at a
/// glance, hidden from screen readers (the name says it). None for All, or a category it doesn't know.
pub fn icon(id: &str) -> String {
    let i = match id {
        "ai" => "🤖",
        "hashrate" => "⛏️",
        "vpn" => "🔒",
        "files" => "📁",
        "data" => "📊",
        "apps" => "🌐",
        _ => return String::new(),
    };
    format!("<span class=\"icon\" aria-hidden=\"true\">{i}</span>")
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Video => "video",
            Kind::Files => "files",
            Kind::Api => "api",
            Kind::Ai => "ai",
            Kind::Hashrate => "hashrate",
        }
    }

    /// The category's id, as Browse filters by it.
    pub fn category(self) -> &'static str {
        match self {
            Kind::Video => "apps",
            Kind::Ai => "ai",
            Kind::Hashrate => "hashrate",
            Kind::Files => "files",
            Kind::Api => "data",
        }
    }

    /// The category as people read it.
    pub fn category_words(self) -> &'static str {
        CATEGORIES.iter().find(|(id, _)| *id == self.category()).map(|(_, w)| *w).unwrap_or("Other")
    }

    fn parse(v: &Value) -> Result<Self, String> {
        match v.as_str() {
            Some("video") => Ok(Kind::Video),
            Some("files") => Ok(Kind::Files),
            Some("api") => Ok(Kind::Api),
            Some("ai") => Ok(Kind::Ai),
            Some("hashrate") => Ok(Kind::Hashrate),
            Some(o) => Err(format!("kind {o:?} is not video, files, api, ai or hashrate")),
            None => Err("kind must be a string".into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sort {
    Name,
    Price,
}

impl Sort {
    pub fn parse(s: &str) -> Self {
        if s.eq_ignore_ascii_case("price") {
            Sort::Price
        } else {
            Sort::Name
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub title: String,
    pub year: String,
    pub url: String,
    pub credit: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub name: String,
    pub kind: Kind,
    pub seller: String,
    pub price_text: String,
    /// The prices its seller's signed listing named (`request_msat`, `byte_msat`, `per_bytes`, ...):
    /// passed as the wallet's `price_ceiling` when the buyer uses it, so a seller whose terms ask more
    /// than it listed is paid nothing. Null where the service was not chosen from a listing.
    pub prices: Value,
    pub items: Vec<Item>,
    /// Where apps and agents reach this service; empty: the seller's own address.
    pub address: String,
    /// The service's own web page, which the buyer can open inside the app (a listed `app`, see
    /// docs/SELLER-APPS.md): where it opens. Empty: it has none.
    pub app: String,
    /// That page's base: what the page sees as `/`. Empty with `app`.
    pub app_base: String,
}

impl Service {
    /// A short id of the service, from its seller and its name: which of several services listing the
    /// same file the buyer chose, carried with a Download or a player's link.
    pub fn id(&self) -> String {
        use sha2::Digest as _;
        hex::encode(&sha2::Sha256::digest(format!("{}\n{}", self.seller, self.name).as_bytes())[..8])
    }

    /// The wallet's `price_ceiling` for this service: its listing's prices, the most the buyer agreed
    /// to pay. `None` where it was not chosen from a listing.
    pub fn price_ceiling(&self) -> Option<Value> {
        self.prices.is_object().then(|| xbt402::listing::price_ceiling(&self.prices))
    }

    /// The category Browse shows it under: a service with its own web app is a web app (a media
    /// server among them), whatever its listing's kind; an older media listing that names films
    /// (no app) is files, to download or open in a player; an AI model and hashrate keep their own.
    pub fn category(&self) -> &'static str {
        match self.kind {
            Kind::Video | Kind::Api | Kind::Files if !self.app.is_empty() => "apps",
            Kind::Video if !self.items.is_empty() => "files",
            k => k.category(),
        }
    }

    /// Whether its page lists files to download or open in a player.
    pub fn has_files(&self) -> bool {
        self.app.is_empty() && !self.items.is_empty() && matches!(self.kind, Kind::Files | Kind::Video)
    }

    pub fn category_words(&self) -> &'static str {
        CATEGORIES.iter().find(|(id, _)| *id == self.category()).map(|(_, w)| *w).unwrap_or("Other")
    }
}

impl Service {
    /// Where apps and agents reach this service.
    pub fn address(&self) -> &str {
        if self.address.is_empty() { &self.seller } else { &self.address }
    }
}

/// `scheme://host[:port]` of an absolute http(s) URL: lower case, no userinfo, and no port when it
/// is the scheme's default. `None` when `url` is not an absolute http(s) URL.
pub fn http_origin(url: &str) -> Option<String> {
    let lower = url.trim().to_ascii_lowercase();
    let (scheme, rest) = lower.strip_prefix("https://").map(|r| ("https", r)).or_else(|| lower.strip_prefix("http://").map(|r| ("http", r)))?;
    if rest.is_empty() {
        return None;
    }
    let netloc = rest.split(['/', '?', '#']).next().unwrap_or("");
    let netloc = netloc.rsplit_once('@').map(|(_, host)| host).unwrap_or(netloc);
    if netloc.is_empty() || netloc.contains('@') {
        return None;
    }
    let (host, port) = if let Some(rest) = netloc.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        if host.is_empty() || !host.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
            return None;
        }
        let port = after.strip_prefix(':').unwrap_or("");
        if !after.is_empty() && (after.len() == 1 || !port.chars().all(|c| c.is_ascii_digit()) || port.is_empty()) {
            return None;
        }
        (format!("[{host}]"), port)
    } else {
        if netloc.contains('[') || netloc.contains(']') {
            return None;
        }
        match netloc.rsplit_once(':') {
            Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
                if host.is_empty() {
                    return None;
                }
                (host.to_string(), port)
            }
            Some(_) => return None,
            None => (netloc.to_string(), ""),
        }
    };
    if host.is_empty() || host.contains(' ') {
        return None;
    }
    let default = (scheme == "https" && port == "443") || (scheme == "http" && port == "80");
    if port.is_empty() || default {
        Some(format!("{scheme}://{host}"))
    } else {
        Some(format!("{scheme}://{host}:{port}"))
    }
}

/// Whether two URLs or origins name the same seller origin.
/// `url`'s path and query on `origin` instead of its own: `https://old.example/a?b` onto
/// `https://new.example` is `https://new.example/a?b`. `None` for a URL that is not http(s).
pub fn rebase(url: &str, origin: &str) -> Option<String> {
    http_origin(url)?;
    let rest = url.trim().split_once("://")?.1;
    let tail = rest.find(['/', '?']).map_or("/", |i| &rest[i..]);
    let tail = if tail.starts_with('?') { format!("/{tail}") } else { tail.to_string() };
    Some(format!("{}{tail}", origin.trim_end_matches('/')))
}

pub fn same_origin(a: &str, b: &str) -> bool {
    match (http_origin(a), http_origin(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

fn http_url(s: &str, what: &str) -> Result<(), String> {
    if s.chars().any(|c| c.is_whitespace() || c == '#' || c == '\\' || c.is_control()) {
        return Err(format!("{what}: a URL cannot contain a space, a hash or a backslash"));
    }
    if s.len() > MAX_URL || http_origin(s).is_none() {
        return Err(format!("{what}: must be an absolute http or https URL"));
    }
    Ok(())
}

fn text<'a>(obj: &'a Map<String, Value>, key: &str, what: &str) -> Result<&'a str, String> {
    match obj.get(key).and_then(Value::as_str) {
        Some(s) if !s.trim().is_empty() && s.chars().count() <= MAX_TEXT => Ok(s.trim()),
        Some(_) => Err(format!("{what}: {key} is empty or longer than {MAX_TEXT} characters")),
        None => Err(format!("{what}: missing {key}")),
    }
}

fn year_of(v: Option<&Value>, what: &str) -> Result<String, String> {
    let y = match v {
        None | Some(Value::Null) => return Ok(String::new()),
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        _ => return Err(format!("{what}: year is a string or a number")),
    };
    if y.chars().count() > 16 || y.chars().any(|c| c.is_control()) {
        return Err(format!("{what}: year is empty or not a short year"));
    }
    Ok(y)
}

fn parse_item(v: &Value, what: &str) -> Result<Item, String> {
    let obj = v.as_object().ok_or_else(|| format!("{what}: an item is an object"))?;
    let url = text(obj, "url", what)?.to_string();
    http_url(&url, &format!("{what} url"))?;
    let credit = if obj.contains_key("credit") { text(obj, "credit", what)?.to_string() } else { String::new() };
    Ok(Item { title: text(obj, "title", what)?.to_string(), year: year_of(obj.get("year"), what)?, url, credit })
}

fn parse_service(v: &Value, n: usize) -> Result<Service, String> {
    let what = format!("service {n}");
    let obj = v.as_object().ok_or_else(|| format!("{what}: a service is an object"))?;
    let seller = text(obj, "seller", &what)?.to_string();
    http_url(&seller, &format!("{what} seller"))?;
    let items_v = obj.get("items").and_then(Value::as_array).ok_or_else(|| format!("{what}: items must be a list"))?;
    if items_v.len() > MAX_ITEMS {
        return Err(format!("{what}: more than {MAX_ITEMS} items"));
    }
    let mut items = Vec::with_capacity(items_v.len());
    for (i, item) in items_v.iter().enumerate() {
        items.push(parse_item(item, &format!("{what} item {}", i + 1))?);
    }
    let kind = Kind::parse(obj.get("kind").ok_or_else(|| format!("{what}: missing kind"))?)?;
    let address = if obj.contains_key("address") { text(obj, "address", &what)?.to_string() } else { String::new() };
    if !address.is_empty() {
        http_url(&address, &format!("{what} address"))?;
    }
    let opt_url = |k: &str| -> Result<String, String> {
        let v = if obj.contains_key(k) { text(obj, k, &what)?.to_string() } else { String::new() };
        if !v.is_empty() {
            http_url(&v, &format!("{what} {k}"))?;
            if !same_origin(&v, &seller) {
                return Err(format!("{what}: {k} is not on the seller's own address"));
            }
        }
        Ok(v)
    };
    let (app, app_base) = (opt_url("app")?, opt_url("app_base")?);
    let (app, app_base) = if app.is_empty() || app_base.is_empty() { (String::new(), String::new()) } else { (app, app_base) };
    let prices = obj.get("prices").filter(|p| p.is_object()).cloned().unwrap_or(Value::Null);
    Ok(Service { name: text(obj, "name", &what)?.to_string(), kind, seller, price_text: text(obj, "price_text", &what)?.to_string(), prices, items, address, app,
                 app_base })
}

/// Parse the services file's text.
pub fn parse(text: &str) -> Result<Vec<Service>, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("services file is not JSON: {e}"))?;
    let list = v.as_array().ok_or("services file must be a JSON list")?;
    if list.len() > MAX_SERVICES {
        return Err(format!("services file has more than {MAX_SERVICES} services"));
    }
    // a service of a kind this app does not know (written by a newer app) is left out, not an error
    list.iter().enumerate()
        .filter(|(_, s)| !s.get("kind").and_then(Value::as_str).is_some_and(|k| Kind::parse(&json!(k)).is_err()))
        .map(|(i, s)| parse_service(s, i + 1)).collect()
}

/// Read and parse the services file. The file is read on each page, so an edit is picked up
/// without a restart.
pub fn load(path: &Path) -> Result<Vec<Service>, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("services file: {e}"))?;
    if !meta.is_file() {
        return Err("services file: not a file".into());
    }
    if meta.len() > MAX_BYTES {
        return Err(format!("services file is larger than {} KiB", MAX_BYTES / 1024));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("services file: {e}"))?;
    parse(&text)
}

fn service_json(s: &Service) -> Value {
    let items: Vec<Value> = s.items.iter().map(|i| {
        let mut v = json!({"title": i.title, "url": i.url});
        if !i.year.is_empty() {
            v["year"] = json!(i.year);
        }
        if !i.credit.is_empty() {
            v["credit"] = json!(i.credit);
        }
        v
    }).collect();
    let mut v = json!({"name": s.name, "kind": s.kind.as_str(), "seller": s.seller, "price_text": s.price_text, "items": items});
    if s.prices.is_object() {
        v["prices"] = s.prices.clone();
    }
    if !s.address.is_empty() {
        v["address"] = json!(s.address);
    }
    if !s.app.is_empty() {
        v["app"] = json!(s.app);
        v["app_base"] = json!(s.app_base);
    }
    v
}

/// Write the services file whole: a temp file beside it, then renamed over it.
pub fn save(path: &Path, services: &[Service]) -> Result<(), String> {
    if services.len() > MAX_SERVICES {
        return Err(format!("at most {MAX_SERVICES} services"));
    }
    let text = serde_json::to_string_pretty(&services.iter().map(service_json).collect::<Vec<_>>()).map_err(|e| e.to_string())? + "\n";
    // what this writes, this reads back
    parse(&text)?;
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| format!("services file: {e}"))?;
    let tmp = dir.join(format!(".services.{}.tmp", hex::encode(crate::random_bytes::<6>())));
    let res = std::fs::write(&tmp, text.as_bytes()).and_then(|_| std::fs::rename(&tmp, path));
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res.map_err(|e| format!("services file {}: {e}", path.display()))
}

/// The catalog an agent reads through the wallet's MCP server (`list_services`, `xbt_wallet_mcp::catalog`):
/// Browse's services as this app shows them, each with its category (`kind`: `apps`, `files`, `ai`,
/// `hashrate`, `data`), its seller's name, its price in words and the exact address to pay it at
/// (`pay_address`); a web app's page (`app`); files with each item's address; and for a shop reached by
/// its key the node its entry vouches for now (`node`, from `shops`), which the MCP server matches against
/// the owner's rules. `ai_endpoint`: the box's OpenAI-compatible address for programs, where it serves one.
pub fn catalog(all: &[Service], shops: &std::collections::BTreeMap<String, crate::shops::Shop>, ai_endpoint: Option<&str>, now: u64) -> Value {
    let services: Vec<Value> = all.iter().map(|s| {
        let origin = http_origin(&s.seller).unwrap_or_else(|| s.seller.clone());
        let mut v = json!({"name": s.name, "seller": origin, "seller_name": seller_name(all, &s.seller), "kind": s.category(),
                           "kind_words": s.category_words(), "price_text": s.price_text, "pay_address": s.address()});
        if !s.app.is_empty() {
            v["app"] = json!(s.app);
        }
        if s.has_files() {
            v["items"] = s.items.iter().map(|i| json!({"title": i.title, "url": i.url})).collect::<Vec<_>>().into();
        }
        if let Some(n) = shops.get(&origin).and_then(|sh| crate::shops::node(sh, &origin, now)) {
            v["node"] = json!(n);
        }
        v
    }).collect();
    json!({"version": 1, "ai_endpoint": ai_endpoint, "services": services})
}

/// Write the agents' catalog ([`catalog`]) whole: a temp file beside it, then renamed over it.
pub fn save_catalog(path: &Path, catalog: &Value) -> Result<(), String> {
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| format!("catalog: {e}"))?;
    let tmp = dir.join(format!(".catalog.{}.tmp", hex::encode(crate::random_bytes::<6>())));
    let text = serde_json::to_string_pretty(catalog).map_err(|e| e.to_string())? + "\n";
    let res = std::fs::write(&tmp, text.as_bytes()).and_then(|_| std::fs::rename(&tmp, path));
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res.map_err(|e| format!("catalog {}: {e}", path.display()))
}

/// A price as a person reads it: `20 sat a MiB`, `5 sat a request`, `0.5 sat a second`.
pub fn price_words(prices: &Value) -> String {
    let n = |k: &str| prices.get(k).and_then(|v| v.as_str().and_then(|s| s.parse::<u64>().ok()).or_else(|| v.as_u64())).unwrap_or(0);
    let sat = |msat: u128, per: u128| -> String {
        // msat over `per` units, to a sat with up to three decimals
        let milli = msat * 1000 / per.max(1) / 1000;
        let whole = milli / 1000;
        let frac = milli % 1000;
        if frac == 0 { whole.to_string() } else { format!("{whole}.{:03}", frac).trim_end_matches('0').to_string() }
    };
    let mut parts = vec![];
    if n("request_msat") > 0 {
        parts.push(format!("{} sat a request", sat(u128::from(n("request_msat")), 1)));
    }
    if n("byte_msat") > 0 && n("per_bytes") == 1_000_000_000 {
        parts.push(format!("{} sat a GB", sat(u128::from(n("byte_msat")), 1)));
    } else if n("byte_msat") > 0 {
        let per = u128::from(n("per_bytes").max(1));
        parts.push(format!("{} sat a MiB", sat(u128::from(n("byte_msat")) * 1_048_576, per)));
    }
    if n("second_msat") > 0 {
        parts.push(format!("{} sat a second", sat(u128::from(n("second_msat")), 1)));
    }
    if n("per_1k_input_msat") > 0 || n("per_1k_output_msat") > 0 {
        parts.push(xbt402::tokens::price_text(n("per_1k_input_msat"), n("per_1k_output_msat")));
    }
    if parts.is_empty() { "free".into() } else { parts.join(" + ") }
}

/// What a hashrate service says for its price. Its listing's price per piece of work is not what renting
/// costs: the live offer on the Hashrate page sets that, follows the market, and a piece of work differs in
/// size between sellers. 0.2.11 said "40 sat a piece of work" here beside an offer asking 404.
pub const HASHRATE_PRICE_WORDS: &str = "Live price on the Hashrate page";

/// The services a checked listing lists, as Browse shows them. A seller with one service shows
/// under its own name; with several, each as `seller name: service name`.
pub fn from_listing(l: &xbt402::listing::Listing) -> Vec<Service> {
    let several = l.services.iter().filter(|s| s.kind != "app").count() > 1;
    let seller = l.seller.trim_end_matches('/');
    // a kind this app does not know is left out: shown as something else, it would be bought wrongly
    let mut out: Vec<Service> = l.services.iter().filter_map(|s| Kind::parse(&json!(s.kind)).ok().map(|kind| (s, kind))).map(|(s, kind)| {
        let path = if s.path.is_empty() || s.path == "/" { String::new() } else { s.path.clone() };
        let credit = if s.credits.is_empty() { l.credits.clone() } else { s.credits.clone() };
        let name = if several { format!("{}: {}", l.name, s.name) } else { l.name.clone() };
        Service {
            name: name.chars().take(MAX_TEXT).collect(),
            kind,
            seller: l.seller.clone(),
            price_text: if kind == Kind::Hashrate { HASHRATE_PRICE_WORDS.into() } else { price_words(&s.prices) },
            prices: s.prices.clone(),
            items: s.items.iter().map(|i| Item { title: i.title.clone(), year: i.year.map(|y| y.to_string()).unwrap_or_default(), url: i.url.clone(),
                                                 credit: i.credit.clone().unwrap_or_else(|| credit.clone()).chars().take(MAX_TEXT).collect() }).collect(),
            address: if path.is_empty() { String::new() } else { format!("{}{path}", l.seller.trim_end_matches('/')) },
            app: String::new(),
            app_base: String::new(),
        }
    }).collect();
    // a service's own web page: given to the service of its path (or its name), else listed alone
    for a in l.services.iter().filter(|s| s.kind == "app") {
        let base = format!("{seller}{}", a.path);
        let entry = a.items.first().map(|i| i.url.clone()).filter(|u| same_origin(u, &l.seller) && u.starts_with(&base)).unwrap_or_else(|| base.clone());
        let at = out.iter().position(|o| if a.path.is_empty() || a.path == "/" { o.address.is_empty() } else { o.address == base })
            .or_else(|| out.iter().position(|o| o.name.ends_with(&a.name)));
        match at.and_then(|i| out.get_mut(i)) {
            Some(o) if o.app.is_empty() => {
                o.app = entry;
                o.app_base = base;
                // the app's own price, where it lists one, is what its pages are paid at
                if a.prices.is_object() && !a.prices.as_object().is_some_and(|m| m.is_empty()) {
                    o.prices = a.prices.clone();
                }
            }
            _ => out.push(Service {
                name: (if several { format!("{}: {}", l.name, a.name) } else { a.name.clone() }).chars().take(MAX_TEXT).collect(),
                kind: Kind::Api,
                seller: l.seller.clone(),
                price_text: price_words(&a.prices),
                prices: a.prices.clone(),
                items: vec![],
                address: String::new(),
                app: entry,
                app_base: base,
            }),
        }
    }
    out
}

/// The shop's own name, as its listing names it, from the services the file keeps for the seller at
/// `origin`. [`from_listing`] names a shop's one service after the shop, and each of several services
/// `shop name: service name`, so the name is the part before `: ` that all of several share, else
/// the first service's name. `None`: no service of that seller is kept.
pub fn shop_name(all: &[Service], origin: &str) -> Option<String> {
    let mine: Vec<&str> = all.iter().filter(|s| same_origin(&s.seller, origin)).map(|s| s.name.as_str()).collect();
    let first = *mine.first()?;
    if mine.len() > 1 {
        if let Some((prefix, _)) = first.split_once(": ") {
            let head = format!("{prefix}: ");
            if mine.iter().all(|n| n.starts_with(&head)) {
                return Some(prefix.to_string());
            }
        }
    }
    Some(first.to_string())
}

/// A seller as a person reads it: the shop's name ([`shop_name`]) where the services file keeps it,
/// else its address shortened (a shop reached by its key: that key, `npub1…`). Never the made-up
/// `…shop.invalid` address. The key in full is [`xbt402::shop::display`], for the line under it.
pub fn seller_name(all: &[Service], origin: &str) -> String {
    shop_name(all, origin).unwrap_or_else(|| short_address(origin))
}

/// A seller's address, short: its host, or for a shop reached by its key that key, shortened
/// (`npub1abcdefgh…wxyz`).
pub fn short_address(origin: &str) -> String {
    if let Some(pk) = xbt402::shop::key_of(origin) {
        let npub = xbt402::shop::npub(&pk);
        return format!("{}…{}", &npub[..13], &npub[npub.len() - 4..]);
    }
    http_origin(origin).unwrap_or_else(|| origin.to_string()).trim_start_matches("https://").trim_start_matches("http://").to_string()
}

/// A URL or path as a person reads it: percent-escapes decoded (`%20` a space), `+` left as it is
/// (it is a plus in a path). Text that does not decode to UTF-8 is shown as it came. For display only.
pub fn path_words(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        match (b[i], b.get(i + 1).copied().and_then(hex), b.get(i + 2).copied().and_then(hex)) {
            (b'%', Some(h), Some(l)) => {
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            (c, _, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    match String::from_utf8(out) {
        // a decoded control character is never shown: the escape stays
        Ok(t) if !t.chars().any(char::is_control) => t,
        _ => s.to_string(),
    }
}

/// The first integer in a price line (`"20 sat a MiB"` → 20, `"about 1,200 sat"` → 1200).
pub fn price_num(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && !b[i].is_ascii_digit() {
        i += 1;
    }
    if i == b.len() {
        return None;
    }
    let mut n: u64 = 0;
    let mut any = false;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            any = true;
            n = n.saturating_mul(10).saturating_add(u64::from(b[i] - b'0'));
            i += 1;
        } else if b[i] == b',' && i + 1 < b.len() && b[i + 1].is_ascii_digit() {
            i += 1;
        } else {
            break;
        }
    }
    any.then_some(n)
}

/// Filter by kind (`None`, `""` or `"all"` keeps every kind) and sort.
/// `kind`: a kind (`video`) or a category (`apps`; `media`, from an older link, is `apps`); empty
/// or `all`: every service.
pub fn arrange(mut services: Vec<Service>, kind: Option<&str>, sort: Sort) -> Vec<Service> {
    if let Some(k) = kind.map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty() && s != "all") {
        let k = if k == "media" { "apps".to_string() } else { k };
        services.retain(|s| s.kind.as_str() == k || s.category() == k);
    }
    match sort {
        Sort::Name => services.sort_by(|a, b| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()).then(a.seller.cmp(&b.seller))),
        Sort::Price => services.sort_by(|a, b| price_key(&a.price_text).cmp(&price_key(&b.price_text)).then(a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()))),
    }
    if sort == Sort::Name {
        for s in &mut services {
            s.items.sort_by(|a, b| a.title.to_ascii_lowercase().cmp(&b.title.to_ascii_lowercase()).then(a.url.cmp(&b.url)));
        }
    }
    services
}

fn price_key(s: &str) -> (u8, u64) {
    match price_num(s) {
        Some(n) => (0, n),
        None => (1, 0),
    }
}

/// The service and the item a file URL is, among `services`.
/// The item `url` of the service `id` ([`Service::id`]): the one the buyer chose, where several list it.
pub fn find_item_of<'a>(services: &'a [Service], id: &str, url: &str) -> Option<(&'a Service, &'a Item)> {
    let url = url.trim();
    services.iter().filter(|s| s.id() == id).find_map(|s| s.items.iter().find(|i| i.url == url).map(|i| (s, i)))
}

pub fn find_item<'a>(services: &'a [Service], url: &str) -> Option<(&'a Service, &'a Item)> {
    let url = url.trim();
    if url.is_empty() || url.len() > MAX_URL {
        return None;
    }
    services.iter().find_map(|s| s.items.iter().find(|i| i.url == url).map(|i| (s, i)))
}

/// `./s/~<stream token>.<service id>/` + the file URL ([`crate::app::stream_token`],
/// [`Service::id`]): where the page downloads a file from, for the service the buyer chose. The UI
/// relays it to the connector ([`crate::server`]), so a browser on another device of the network
/// reaches it too (the connector itself listens on loopback only).
pub fn download_src(token: &str, service: &str, item_url: &str) -> Result<String, String> {
    http_url(item_url, "file url")?;
    Ok(format!("./s/~{token}.{service}/{item_url}"))
}

/// Percent-encoding for a query value.
pub fn urlenc(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_url_rebased_keeps_its_path_and_query() {
        assert_eq!(rebase("https://old.example/Videos/a/stream?static=true", "https://new.example").as_deref(),
                   Some("https://new.example/Videos/a/stream?static=true"));
        assert_eq!(rebase("https://old.example", "https://new.example/").as_deref(), Some("https://new.example/"));
        assert_eq!(rebase("https://old.example?x=1", "https://new.example").as_deref(), Some("https://new.example/?x=1"));
        assert_eq!(rebase("ftp://old.example/a", "https://new.example"), None);
    }


    #[test]
    fn a_services_own_web_page_goes_with_it_and_a_page_alone_is_listed_alone() {
        let l = xbt402::listing::Listing {
            name: "Box".into(), kind: "ai".into(), seller: "https://seller.example".into(), receipt_key: String::new(), prices: Default::default(),
            items: vec![], licence: String::new(), credits: String::new(), updated: String::new(),
            services: vec![
                sec("Model", "ai", "/ai/", vec![]),
                sec("Model", "app", "/ai/", vec![("Open", "https://seller.example/ai/")]),
                sec("Game", "app", "/game/", vec![("Open", "https://seller.example/game/play/")]),
                sec("Bad", "app", "/bad/", vec![("Open", "https://elsewhere.example/bad/")]),
            ],
        };
        let all = from_listing(&l);
        // one service of its own: it carries the shop's name, as before
        let model = all.iter().find(|s| s.kind == Kind::Ai).unwrap();
        assert_eq!(model.name, "Box");
        assert_eq!((model.app.as_str(), model.app_base.as_str()), ("https://seller.example/ai/", "https://seller.example/ai/"));
        let game = all.iter().find(|s| s.name.ends_with("Game")).unwrap();
        assert_eq!((game.kind, game.app.as_str(), game.app_base.as_str()), (Kind::Api, "https://seller.example/game/play/", "https://seller.example/game/"));
        // a page that would open somewhere else opens at its own base instead
        assert_eq!(all.iter().find(|s| s.name.ends_with("Bad")).unwrap().app, "https://seller.example/bad/");
        // kept in the services file, and read back
        let back = parse(&serde_json::to_string(&all.iter().map(service_json).collect::<Vec<_>>()).unwrap()).unwrap();
        assert_eq!(back, all);
        // an app on another seller's address is refused in the file
        let mut v = service_json(game);
        v["app"] = json!("https://elsewhere.example/game/");
        assert!(parse(&json!([v]).to_string()).is_err());
    }

    fn sec(name: &str, kind: &str, path: &str, items: Vec<(&str, &str)>) -> xbt402::listing::Section {
        xbt402::listing::Section { name: name.into(), kind: kind.into(), path: path.into(), prices: Default::default(),
            items: items.into_iter().map(|(t, u)| xbt402::listing::Item { title: t.into(), url: u.into(), year: None, credit: None }).collect(),
            licence: String::new(), credits: String::new() }
    }
    use super::*;

    #[test]
    fn a_path_is_shown_decoded() {
        assert_eq!(path_words("/files/My%20film%20(2010).mkv"), "/files/My film (2010).mkv");
        assert_eq!(path_words("/a+b%2"), "/a+b%2");
        assert_eq!(path_words("/x%0Ay"), "/x%0Ay", "no control characters");
        assert_eq!(path_words("/caf%C3%A9"), "/café");
    }

    /// The catalog agents read names each service's category, seller, price and exact address to pay, a web app's page,
    /// and each file's address, and the MCP server's `list_services` reads it as written.
    ///
    /// FAILS before: no catalog was written, and an agent could not find a shop reached by its key.
    #[test]
    fn the_agents_catalog_names_what_to_pay_and_where() {
        let shop = xbt402::shop::origin_for(&[0x5b; 32]);
        let films = Service { name: "Box: Films".into(), kind: Kind::Files, seller: "https://box.example".into(), price_text: "20 sat a MiB".into(), prices: Value::Null,
                              items: vec![Item { title: "A film".into(), year: String::new(), url: "https://box.example/files/a.mkv".into(), credit: String::new() }],
                              address: "https://box.example/files/".into(), app: String::new(), app_base: String::new() };
        let jf = Service { name: "Box: Jellyfin".into(), kind: Kind::Video, seller: "https://box.example".into(), price_text: "20 sat a MiB".into(), prices: Value::Null,
                           items: vec![], address: String::new(), app: "https://box.example/web/".into(), app_base: "https://box.example/".into() };
        let ai = Service { name: "Genesis".into(), kind: Kind::Ai, seller: shop.clone(), price_text: "4 sat per 1,000 tokens".into(), prices: Value::Null,
                           items: vec![], address: format!("{shop}/v1/"), app: String::new(), app_base: String::new() };
        let all = vec![films, jf, ai];
        let c = catalog(&all, &Default::default(), Some("http://box.local:33540/v1"), 0);
        let s = &c["services"];
        assert_eq!((s[0]["kind"].as_str(), s[0]["seller_name"].as_str(), s[0]["pay_address"].as_str()), (Some("files"), Some("Box"), Some("https://box.example/files/")));
        assert_eq!(s[0]["items"][0]["url"], "https://box.example/files/a.mkv");
        assert_eq!((s[1]["kind"].as_str(), s[1]["app"].as_str(), s[1]["pay_address"].as_str()), (Some("apps"), Some("https://box.example/web/"), Some("https://box.example")));
        assert_eq!((s[2]["kind"].as_str(), s[2]["pay_address"].as_str()), (Some("ai"), Some(format!("{shop}/v1/").as_str())));
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("catalog.json");
        save_catalog(&p, &c).unwrap();
        let read = xbt_wallet_mcp::catalog::read_catalog(&p).unwrap();
        let listed = xbt_wallet_mcp::catalog::list(&read, &json!({}), "");
        assert_eq!((listed["services"].as_array().unwrap().len(), listed["allowed"].as_u64()), (3, Some(0)));
        assert_eq!(listed["ai_endpoint"], "http://box.local:33540/v1");
        // the seller's words (an item's title) under the untrusted mark, its address beside them
        let files = &xbt_wallet_mcp::catalog::list(&read, &json!({}), "files")["services"][0];
        assert_eq!((files["untrusted_provider_response"]["item_titles"][0].as_str(), files["items"][0]["url"].as_str()),
                   (Some("A film"), Some("https://box.example/files/a.mkv")), "{files}");
    }

    /// A shop is named by its listing's name (#37 item 16), whatever [`from_listing`] made of its services,
    /// and one reached by its key is never named by its made-up `…shop.invalid` address (items 7, 11, 20).
    ///
    /// FAILS before: Sellers took the first service's name, "Genesis: Films".
    #[test]
    fn a_seller_is_named_by_its_listing_and_a_shop_by_its_key_never_by_its_made_up_address() {
        let shop = xbt402::shop::origin_for(&[4u8; 32]);
        let listing = |name: &str, secs: Vec<xbt402::listing::Section>| xbt402::listing::Listing {
            name: name.into(), kind: "shop".into(), seller: shop.clone(), receipt_key: String::new(), prices: Default::default(), items: vec![],
            licence: String::new(), credits: String::new(), updated: String::new(), services: secs };
        let several = from_listing(&listing("Lightning Stream Genesis", vec![sec("Films", "video", "/films/", vec![]), sec("Notes", "api", "/notes/", vec![]),
                                                                             sec("Films", "app", "/films/", vec![])]));
        assert_eq!(several[0].name, "Lightning Stream Genesis: Films");
        assert_eq!(seller_name(&several, &shop), "Lightning Stream Genesis");
        let one = from_listing(&listing("Genesis: the shop", vec![sec("Films", "video", "/", vec![]), sec("Player", "app", "/play/", vec![])]));
        assert_eq!(seller_name(&one, &shop), "Genesis: the shop", "one service and an app of its own: the listing's name, colon and all");
        // not on the list: its key, short; a web seller: its host
        let npub = xbt402::shop::npub(&[4u8; 32]);
        assert_eq!(seller_name(&[], &shop), format!("{}…{}", &npub[..13], &npub[npub.len() - 4..]));
        assert!(!seller_name(&[], &shop).contains("shop.invalid"));
        assert_eq!(seller_name(&[], "https://Media.Example/x"), "media.example");
    }

    #[test]
    fn the_example_lists_the_three_films() {
        let v = parse(include_str!("../examples/services.example.json")).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!((v[0].kind, v[0].price_text.as_str(), v[0].seller.as_str()), (Kind::Video, "20 sat a MiB", "https://stream.lazarus-xbt.xyz"));
        let titles: Vec<_> = v[0].items.iter().map(|i| i.title.as_str()).collect();
        assert_eq!(titles, ["Big Buck Bunny", "Elephants Dream", "Sintel"]);
        assert!(v[0].items[1].credit.contains("CC BY 2.5"));
        assert!(v[0].items[0].credit.contains("CC BY 3.0") && v[0].items[2].credit.contains("CC BY 3.0"));
        assert_eq!(v[0].items[0].year, "2008");
    }

    #[test]
    fn origins_fold_case_and_default_ports_and_drop_userinfo() {
        assert_eq!(http_origin("HTTPS://Media.Example:443/a"), Some("https://media.example".into()));
        assert_eq!(http_origin("http://u:p@files.example:80/x"), Some("http://files.example".into()));
        assert_eq!(http_origin("http://127.0.0.1:8480"), Some("http://127.0.0.1:8480".into()));
        assert_eq!(http_origin("http://[::1]:8480/s"), Some("http://[::1]:8480".into()));
        assert!(http_origin("ftp://x").is_none() && http_origin("/relative").is_none());
        assert!(same_origin("https://Media.Example:443", "https://media.example/Videos/1"));
        assert!(!same_origin("https://a.example", "https://b.example"));
    }

    #[test]
    fn filter_and_sort_by_name_and_by_the_first_number_in_the_price() {
        let raw = r#"[
            {"name": "Zebra", "kind": "files", "seller": "https://files.example", "price_text": "about 1,200 sat", "items": [
                {"title": "B", "year": "2020", "url": "https://files.example/b", "credit": "cc0"},
                {"title": "A", "year": 2019, "url": "https://files.example/a", "credit": "cc0"}]},
            {"name": "alpha", "kind": "video", "seller": "https://media.example", "price_text": "20 sat a MiB", "items": [
                {"title": "Film", "year": 2008, "url": "https://media.example/v", "credit": "cc"}]},
            {"name": "Mid", "kind": "api", "seller": "https://api.example", "price_text": "ask", "items": []}
        ]"#;
        let by_name = arrange(parse(raw).unwrap(), None, Sort::Name);
        assert_eq!(by_name.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["alpha", "Mid", "Zebra"]);
        assert_eq!(by_name[2].items.iter().map(|i| i.title.as_str()).collect::<Vec<_>>(), ["A", "B"]);
        let by_price = arrange(parse(raw).unwrap(), None, Sort::Price);
        assert_eq!(by_price.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["alpha", "Zebra", "Mid"]);
        assert_eq!(by_price[1].items[0].title, "B", "a price sort leaves the seller's item order");
        let files = arrange(parse(raw).unwrap(), Some("FILES"), Sort::Name);
        assert_eq!(files.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["alpha", "Zebra"], "an older film listing is files too");
        assert_eq!(arrange(parse(raw).unwrap(), Some("video"), Sort::Name).len(), 1, "a kind still names its own");
        assert!(arrange(parse(raw).unwrap(), Some("nope"), Sort::Name).is_empty());
        assert_eq!(price_num("20 sat a MiB"), Some(20));
        assert_eq!(price_num("about 1,200 sat"), Some(1200));
        assert_eq!(price_num("ask"), None);
    }

    #[test]
    fn prices_read_as_people_say_them() {
        use serde_json::json;
        assert_eq!(price_words(&json!({"byte_msat": "20000", "per_bytes": "1048576"})), "20 sat a MiB");
        assert_eq!(price_words(&json!({"byte_msat": "20", "per_bytes": "1048576"})), "0.02 sat a MiB");
        assert_eq!(price_words(&json!({"per_1k_output_msat": "10000"})), "10 sat per 1,000 tokens");
        assert_eq!(price_words(&json!({"per_1k_input_msat": "2000", "per_1k_output_msat": "10000"})), "2 sat per 1,000 tokens in, 10 sat per 1,000 tokens out");
        assert_eq!(price_words(&json!({"request_msat": "500"})), "0.5 sat a request");
        assert_eq!(price_words(&json!({"request_msat": "1000", "second_msat": "2000"})), "1 sat a request + 2 sat a second");
        assert_eq!(price_words(&json!({})), "free");
    }

    #[test]
    fn the_file_the_services_page_writes_reads_back_the_same() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("sub/services.json");
        let v = parse(include_str!("../examples/services.example.json")).unwrap();
        let mut v2 = v.clone();
        v2[0].items[0].year = String::new();
        v2[0].items[0].credit = String::new();
        save(&p, &v2).unwrap();
        assert_eq!(load(&p).unwrap(), v2);
        assert_eq!(std::fs::read_dir(p.parent().unwrap()).unwrap().count(), 1, "no temp file left");
    }

    #[test]
    fn a_bad_service_is_refused_whole() {
        assert!(parse(r#"{"name": "x"}"#).is_err());
        assert!(parse(r#"[{"name": "x", "kind": "video", "seller": "https://a.example", "price_text": "1", "items": [
            {"title": "t", "year": 1, "url": "javascript:alert(1)", "credit": "c"}]}]"#).is_err());
        // a kind a newer app wrote is left out; the services this app knows are still read
        let mixed = parse(r#"[{"name": "x", "kind": "other", "seller": "https://a.example", "price_text": "1", "items": []},
                             {"name": "y", "kind": "ai", "seller": "https://a.example", "price_text": "1", "items": []}]"#).unwrap();
        assert_eq!(mixed.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["y"]);
        assert!(parse(r#"[{"name": "x", "kind": 7, "seller": "https://a.example", "price_text": "1", "items": []}]"#).is_err());
        assert!(parse(r#"[{"name": "<b>", "kind": "video", "seller": "https://a.example", "price_text": "1 sat", "items": []}]"#).is_ok());
    }
}
