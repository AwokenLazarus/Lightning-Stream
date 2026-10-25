//! The services file (`XBT_UI_SERVICES`): what Browse lists and what the player may open.
//!
//! A JSON list. Each service is `{name, kind, seller, price_text, items}`. `kind` is `video`,
//! `files` or `api`. Each item is `{title, year, url, credit}`. `seller` and every item `url` are
//! absolute `http` or `https` URLs. An example is `examples/services.example.json` in this crate.
use std::path::Path;

use serde_json::{Map, Value};

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
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Video => "video",
            Kind::Files => "files",
            Kind::Api => "api",
        }
    }

    fn parse(v: &Value) -> Result<Self, String> {
        match v.as_str() {
            Some("video") => Ok(Kind::Video),
            Some("files") => Ok(Kind::Files),
            Some("api") => Ok(Kind::Api),
            Some(o) => Err(format!("kind {o:?} is not video, files or api")),
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
    pub items: Vec<Item>,
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
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        _ => return Err(format!("{what}: missing year")),
    };
    if y.is_empty() || y.chars().count() > 16 || y.chars().any(|c| c.is_control()) {
        return Err(format!("{what}: year is empty or not a short year"));
    }
    Ok(y)
}

fn parse_item(v: &Value, what: &str) -> Result<Item, String> {
    let obj = v.as_object().ok_or_else(|| format!("{what}: an item is an object"))?;
    let url = text(obj, "url", what)?.to_string();
    http_url(&url, &format!("{what} url"))?;
    Ok(Item { title: text(obj, "title", what)?.to_string(), year: year_of(obj.get("year"), what)?, url, credit: text(obj, "credit", what)?.to_string() })
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
    Ok(Service { name: text(obj, "name", &what)?.to_string(), kind, seller, price_text: text(obj, "price_text", &what)?.to_string(), items })
}

/// Parse the services file's text.
pub fn parse(text: &str) -> Result<Vec<Service>, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("services file is not JSON: {e}"))?;
    let list = v.as_array().ok_or("services file must be a JSON list")?;
    if list.len() > MAX_SERVICES {
        return Err(format!("services file has more than {MAX_SERVICES} services"));
    }
    list.iter().enumerate().map(|(i, s)| parse_service(s, i + 1)).collect()
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
pub fn arrange(mut services: Vec<Service>, kind: Option<&str>, sort: Sort) -> Vec<Service> {
    if let Some(k) = kind.map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty() && s != "all") {
        services.retain(|s| s.kind.as_str() == k);
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

pub fn find_item<'a>(services: &'a [Service], url: &str) -> Option<(&'a Service, &'a Item)> {
    let url = url.trim();
    if url.is_empty() || url.len() > MAX_URL {
        return None;
    }
    services.iter().find_map(|s| s.items.iter().find(|i| i.url == url).map(|i| (s, i)))
}

/// Origins to match against `ticket_status`: the item's URL, then the service's seller when it
/// differs. A session is keyed by the URL the connector paid.
pub fn pay_origins(service: &Service, item: &Item) -> Vec<String> {
    let mut out = Vec::new();
    for u in [&item.url, &service.seller] {
        if let Some(o) = http_origin(u) {
            if !out.iter().any(|x| x == &o) {
                out.push(o);
            }
        }
    }
    out
}

/// `connector` + `/s/` + the item URL. `connector` is `XBT_UI_CONNECTOR` (no trailing slash kept).
pub fn player_src(connector: &str, item_url: &str) -> Result<String, String> {
    let base = connector.trim().trim_end_matches('/');
    http_url(base, "XBT_UI_CONNECTOR")?;
    http_url(item_url, "item url")?;
    Ok(format!("{base}/s/{item_url}"))
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
    use super::*;

    #[test]
    fn the_example_lists_the_three_films() {
        let v = parse(include_str!("../examples/services.example.json")).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!((v[0].kind, v[0].price_text.as_str(), v[0].seller.as_str()), (Kind::Video, "20 sat a MiB", "https://media.lazarus-xbt.xyz"));
        let titles: Vec<_> = v[0].items.iter().map(|i| i.title.as_str()).collect();
        assert_eq!(titles, ["Big Buck Bunny", "Elephants Dream", "Sintel"]);
        assert!(v[0].items[1].credit.contains("CC BY 2.5"));
        assert!(v[0].items[0].credit.contains("CC BY 3.0") && v[0].items[2].credit.contains("CC BY 3.0"));
        assert_eq!(v[0].items[0].year, "2008");
        assert!(player_src("http://127.0.0.1:8480", &v[0].items[0].url).unwrap().ends_with("/stream?static=true"));
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
        assert_eq!(files.len(), 1);
        assert!(arrange(parse(raw).unwrap(), Some("nope"), Sort::Name).is_empty());
        assert_eq!(price_num("20 sat a MiB"), Some(20));
        assert_eq!(price_num("about 1,200 sat"), Some(1200));
        assert_eq!(price_num("ask"), None);
    }

    #[test]
    fn a_bad_service_is_refused_whole() {
        assert!(parse(r#"{"name": "x"}"#).is_err());
        assert!(parse(r#"[{"name": "x", "kind": "video", "seller": "https://a.example", "price_text": "1", "items": [
            {"title": "t", "year": 1, "url": "javascript:alert(1)", "credit": "c"}]}]"#).is_err());
        assert!(parse(r#"[{"name": "x", "kind": "other", "seller": "https://a.example", "price_text": "1", "items": []}]"#).is_err());
        assert!(parse(r#"[{"name": "<b>", "kind": "video", "seller": "https://a.example", "price_text": "1 sat", "items": []}]"#).is_ok());
    }
}
