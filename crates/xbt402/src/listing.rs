//! A seller's listing (`docs/LISTINGS.md`). The same key that signs receipts signs it: ECDSA over
//! a tagged hash of the canonical JSON, which is [`crate::json::dumps_sorted_compact`] of the
//! document with `sig` removed.

use serde_json::{json, Map, Value};
use sha2::Digest;

use crate::json::dumps_sorted_compact;
use crate::wire::{canonical_origin, put_field, tagged, unb64json};
use xbt_primitives::ecdsa;
use xbt_primitives::secp256k1::SecretKey;

/// `version` of a document with one service.
pub const VERSION: &str = "listing/0";
/// `version` of a document with a list of services, each behind a path of its own.
pub const VERSION_1: &str = "listing/1";
/// Where a seller serves it, on its public origin.
pub const PATH: &str = "/.well-known/lightning-stream.json";
/// The tagged-hash tag. One field: the canonical JSON.
const TAG: &str = "xbt402/listing/0";
/// The same construction for `listing/1`.
const TAG_1: &str = "xbt402/listing/1";
/// At most this many services in one listing.
const MAX_SERVICES: usize = 32;

const KINDS: [&str; 3] = ["video", "files", "api"];
const PRICE_KEYS: [&str; 4] = ["request_msat", "byte_msat", "per_bytes", "second_msat"];
/// A fetched document larger than this is refused before it is parsed.
const MAX_BODY: usize = 256 << 10;

/// What the seller writes in its config. The gateway adds `seller` and `receipt_key` and signs.
///
/// A `listing/0` draft has one service, in `kind`, `prices` and `items`, and `services` is empty.
/// A `listing/1` draft lists its services in `services`; `kind`, `prices` and `items` are then the
/// first service's, and `licence` and `credits` may be empty (each service may say its own).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draft {
    pub name: String,
    pub kind: String,
    pub prices: Value,
    pub items: Vec<Item>,
    pub licence: String,
    pub credits: String,
    pub updated: String,
    pub services: Vec<Section>,
}

/// One service of a `listing/1`: what it is, the path it is sold under, and its price.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub kind: String,
    /// The gateway route the service is sold under (`/`, `/ai/`).
    pub path: String,
    pub prices: Value,
    pub items: Vec<Item>,
    /// Empty: the listing's own.
    pub licence: String,
    pub credits: String,
}

/// One catalog entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub title: String,
    pub url: String,
    pub year: Option<u64>,
    pub credit: Option<String>,
}

/// A listing whose signature verified under the receipt key the seller's 402 terms name.
/// `services` is always filled: a `listing/0` is one service under `/`. `kind`, `prices` and
/// `items` are the first service's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    pub name: String,
    pub kind: String,
    pub seller: String,
    pub receipt_key: String,
    pub prices: Value,
    pub items: Vec<Item>,
    pub licence: String,
    pub credits: String,
    pub updated: String,
    pub services: Vec<Section>,
}

/// One HTTP answer, as a reader hands it to [`fetch`].
pub struct Page {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

fn plain(s: &str, max: usize) -> bool {
    !s.is_empty() && s.chars().count() <= max && !s.chars().any(|c| c.is_control())
}

fn http_url(s: &str) -> bool {
    (s.starts_with("https://") || s.starts_with("http://"))
        && s.len() <= 2000
        && !s.chars().any(|c| c.is_whitespace() || c.is_control() || c == '#' || c == '\\')
}

fn obj<'a>(v: &'a Value, what: &str, known: &[&str]) -> Result<&'a Map<String, Value>, String> {
    let m = v.as_object().ok_or_else(|| format!("{what} is an object"))?;
    if let Some(k) = m.keys().find(|k| !known.contains(&k.as_str())) {
        return Err(format!("{what}: unknown key {k:?}"));
    }
    Ok(m)
}

fn req_str<'a>(m: &'a Map<String, Value>, k: &str) -> Result<&'a str, String> {
    match m.get(k) {
        None => Err(format!("{k} is missing")),
        Some(Value::String(s)) if plain(s, 500) => Ok(s),
        Some(Value::String(_)) => Err(format!("{k} is empty, too long, or has a control character")),
        Some(_) => Err(format!("{k} is a string")),
    }
}

/// A config file writes a price as a number. The signed document writes it as a decimal string,
/// the way the rest of the wire writes amounts. Both are the same whole number.
fn whole(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| {
        v.as_str().filter(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) && s.len() <= 20).and_then(|s| s.parse().ok())
    })
}

/// The config's `listing` object: no `seller`, no `receipt_key`, no `sig`. With `services` it is a
/// `listing/1` draft, else a `listing/0` one.
pub fn parse_draft(v: &Value) -> Result<Draft, String> {
    if v.get("services").is_some() {
        return parse_draft_1(v);
    }
    let m = obj(v, "listing", &["name", "kind", "prices", "items", "licence", "credits", "updated"])?;
    let name = req_str(m, "name")?;
    if name.chars().count() > 200 {
        return Err("name is at most 200 characters".into());
    }
    let kind = req_str(m, "kind")?;
    if !KINDS.contains(&kind) {
        return Err("kind is video, files or api".into());
    }
    let prices = price_strings(m.get("prices").ok_or("prices is missing")?)?;
    let items_v = m.get("items").and_then(Value::as_array).ok_or("items is a list")?;
    if items_v.len() > 400 {
        return Err("items has at most 400 entries".into());
    }
    let mut items = Vec::with_capacity(items_v.len());
    for it in items_v {
        items.push(parse_item(it)?);
    }
    let licence = req_str(m, "licence")?;
    let credits = req_str(m, "credits")?;
    let updated = req_str(m, "updated")?;
    if updated.chars().count() > 64 {
        return Err("updated is at most 64 characters".into());
    }
    Ok(Draft { name: name.to_string(), kind: kind.to_string(), prices, items, licence: licence.to_string(), credits: credits.to_string(), updated: updated.to_string(),
               services: vec![] })
}

fn opt_text(m: &Map<String, Value>, k: &str) -> Result<String, String> {
    match m.get(k) {
        None => Ok(String::new()),
        Some(_) => req_str(m, k).map(str::to_string),
    }
}

fn items_of(m: &Map<String, Value>, what: &str) -> Result<Vec<Item>, String> {
    let items_v = m.get("items").and_then(Value::as_array).ok_or_else(|| format!("{what}: items is a list"))?;
    if items_v.len() > 400 {
        return Err(format!("{what}: items has at most 400 entries"));
    }
    items_v.iter().map(parse_item).collect()
}

/// A route path as the gateway writes one: starts with `/`, plain visible ASCII.
fn route_path(s: &str) -> bool {
    s.starts_with('/') && s.len() <= 200 && !s.contains("//") && s.bytes().all(|c| c.is_ascii_graphic() && !b"%?#\\".contains(&c))
        && !s.split('/').any(|x| x == "." || x == "..")
}

fn parse_section(v: &Value, n: usize) -> Result<Section, String> {
    let what = format!("service {n}");
    let m = obj(v, &what, &["name", "kind", "path", "prices", "items", "licence", "credits"])?;
    let name = req_str(m, "name").map_err(|e| format!("{what}: {e}"))?;
    if name.chars().count() > 200 {
        return Err(format!("{what}: name is at most 200 characters"));
    }
    let kind = req_str(m, "kind").map_err(|e| format!("{what}: {e}"))?;
    if !KINDS.contains(&kind) {
        return Err(format!("{what}: kind is video, files or api"));
    }
    let path = req_str(m, "path").map_err(|e| format!("{what}: {e}"))?;
    if !route_path(path) {
        return Err(format!("{what}: path is a route path, starting with /"));
    }
    let prices = price_strings(m.get("prices").ok_or_else(|| format!("{what}: prices is missing"))?)?;
    Ok(Section { name: name.to_string(), kind: kind.to_string(), path: path.to_string(), prices, items: items_of(m, &what)?,
                 licence: opt_text(m, "licence")?, credits: opt_text(m, "credits")? })
}

fn parse_draft_1(v: &Value) -> Result<Draft, String> {
    let m = obj(v, "listing", &["name", "services", "licence", "credits", "updated"])?;
    let name = req_str(m, "name")?;
    if name.chars().count() > 200 {
        return Err("name is at most 200 characters".into());
    }
    let list = m.get("services").and_then(Value::as_array).ok_or("services is a list")?;
    if list.is_empty() || list.len() > MAX_SERVICES {
        return Err(format!("services has 1 to {MAX_SERVICES} entries"));
    }
    let mut services: Vec<Section> = Vec::with_capacity(list.len());
    for (i, s) in list.iter().enumerate() {
        let sec = parse_section(s, i + 1)?;
        if services.iter().any(|o| o.path == sec.path) {
            return Err(format!("service {}: path {} is named twice", i + 1, sec.path));
        }
        services.push(sec);
    }
    let updated = req_str(m, "updated")?;
    if updated.chars().count() > 64 {
        return Err("updated is at most 64 characters".into());
    }
    let first = services[0].clone();
    Ok(Draft { name: name.to_string(), kind: first.kind, prices: first.prices, items: first.items, licence: opt_text(m, "licence")?,
               credits: opt_text(m, "credits")?, updated: updated.to_string(), services })
}

fn section_json(s: &Section) -> Value {
    let mut v = json!({"name": s.name, "kind": s.kind, "path": s.path, "prices": s.prices, "items": s.items.iter().map(item_json).collect::<Vec<_>>()});
    if !s.licence.is_empty() {
        v["licence"] = json!(s.licence);
    }
    if !s.credits.is_empty() {
        v["credits"] = json!(s.credits);
    }
    v
}

fn price_strings(v: &Value) -> Result<Value, String> {
    let m = obj(v, "listing.prices", &PRICE_KEYS)?;
    if m.is_empty() {
        return Err("listing.prices names a price".into());
    }
    let mut out = Map::new();
    for k in PRICE_KEYS {
        if let Some(n) = m.get(k) {
            let n = whole(n).ok_or_else(|| format!("listing.prices.{k} is a whole number"))?;
            if k == "per_bytes" && n == 0 {
                return Err("listing.prices.per_bytes is at least 1".into());
            }
            out.insert(k.to_string(), Value::String(n.to_string()));
        }
    }
    Ok(Value::Object(out))
}

fn parse_item(v: &Value) -> Result<Item, String> {
    let m = obj(v, "an item", &["title", "url", "year", "credit"])?;
    let title = req_str(m, "title")?;
    if title.chars().count() > 300 {
        return Err("title is at most 300 characters".into());
    }
    let url = match m.get("url") {
        Some(Value::String(s)) if http_url(s) => s.as_str(),
        _ => return Err("url starts with http:// or https://".into()),
    };
    let year = match m.get("year") {
        None => None,
        Some(n) => {
            let y = n.as_u64().filter(|y| (1..=9999).contains(y)).ok_or("year is a whole number from 1 to 9999")?;
            Some(y)
        }
    };
    let credit = match m.get("credit") {
        None => None,
        Some(_) => {
            let c = req_str(m, "credit")?;
            if c.chars().count() > 300 {
                return Err("credit is at most 300 characters".into());
            }
            Some(c.to_string())
        }
    };
    Ok(Item { title: title.to_string(), url: url.to_string(), year, credit })
}

fn item_json(i: &Item) -> Value {
    let mut v = json!({"title": i.title, "url": i.url});
    if let Some(y) = i.year {
        v["year"] = json!(y);
    }
    if let Some(c) = &i.credit {
        v["credit"] = json!(c);
    }
    v
}

/// The document before it is signed: `listing/1` when the draft lists services, else `listing/0`.
pub fn document(d: &Draft, seller: &str, receipt_key: &str) -> Value {
    if !d.services.is_empty() {
        let mut v = json!({
            "version": VERSION_1,
            "name": d.name,
            "seller": seller,
            "receipt_key": receipt_key,
            "services": d.services.iter().map(section_json).collect::<Vec<_>>(),
            "updated": d.updated,
        });
        if !d.licence.is_empty() {
            v["licence"] = json!(d.licence);
        }
        if !d.credits.is_empty() {
            v["credits"] = json!(d.credits);
        }
        return v;
    }
    json!({
        "version": VERSION,
        "name": d.name,
        "kind": d.kind,
        "seller": seller,
        "receipt_key": receipt_key,
        "prices": d.prices,
        "items": d.items.iter().map(item_json).collect::<Vec<_>>(),
        "licence": d.licence,
        "credits": d.credits,
        "updated": d.updated,
    })
}

/// The 32 bytes the receipt key signs.
pub fn message(doc: &Value) -> [u8; 32] {
    let mut bare = doc.clone();
    if let Some(o) = bare.as_object_mut() {
        o.remove("sig");
    }
    let v1 = doc.get("version").and_then(Value::as_str) == Some(VERSION_1);
    let mut h = tagged(if v1 { TAG_1 } else { TAG });
    put_field(&mut h, dumps_sorted_compact(&bare).as_bytes());
    h.finalize().into()
}

/// `doc` plus `sig`, hex of the DER signature.
pub fn sign(sk: &SecretKey, doc: &Value) -> Value {
    let mut out = doc.clone();
    if let Some(o) = out.as_object_mut() {
        o.remove("sig");
    }
    let sig = hex::encode(ecdsa::sign(sk, &message(&out)));
    out["sig"] = sig.into();
    out
}

/// Check `doc` against `terms_receipt_key`, the key the seller's 402 terms name. The key inside
/// the document has to be that key, and the signature has to verify under it.
pub fn verify(doc: &Value, terms_receipt_key: &str) -> Result<Listing, String> {
    let m = doc.as_object().ok_or("a listing is an object")?;
    let sig_hex = m.get("sig").and_then(Value::as_str).ok_or("sig is missing")?;
    let sig = hex::decode(sig_hex).map_err(|_| "sig is hex")?;
    let key = m.get("receipt_key").and_then(Value::as_str).ok_or("receipt_key is missing")?;
    if key != terms_receipt_key {
        return Err("the listing's receipt key is not the one the seller's terms name".into());
    }
    let pk = hex::decode(key).map_err(|_| "receipt_key is hex")?;
    if !ecdsa::verify(&pk, &message(doc), &sig) {
        return Err("the signature does not verify".into());
    }
    read_signed(m)
}

fn read_signed(m: &Map<String, Value>) -> Result<Listing, String> {
    let version = m.get("version").and_then(Value::as_str).ok_or("version is missing")?;
    let known: &[&str] = match version {
        VERSION => &["version", "name", "kind", "seller", "receipt_key", "prices", "items", "licence", "credits", "updated", "sig"],
        VERSION_1 => &["version", "name", "seller", "receipt_key", "services", "licence", "credits", "updated", "sig"],
        _ => return Err(format!("version is {VERSION} or {VERSION_1}")),
    };
    if let Some(k) = m.keys().find(|k| !known.contains(&k.as_str())) {
        return Err(format!("unknown key {k:?}"));
    }
    let seller = m.get("seller").and_then(Value::as_str).filter(|s| http_url(s)).ok_or("seller is an http(s) URL")?;
    let receipt_key = m.get("receipt_key").and_then(Value::as_str).filter(|s| s.len() == 66 && s.chars().all(|c| c.is_ascii_hexdigit())).ok_or("receipt_key is 33 bytes of hex")?;
    let draft = parse_draft(&Value::Object(strip_serve(m)))?;
    if (version == VERSION_1) == draft.services.is_empty() {
        return Err("the version does not match the document's shape".into());
    }
    let services = if draft.services.is_empty() {
        vec![Section { name: draft.name.clone(), kind: draft.kind.clone(), path: "/".into(), prices: draft.prices.clone(), items: draft.items.clone(),
                       licence: draft.licence.clone(), credits: draft.credits.clone() }]
    } else {
        draft.services
    };
    Ok(Listing {
        name: draft.name,
        kind: draft.kind,
        seller: seller.to_string(),
        receipt_key: receipt_key.to_string(),
        prices: draft.prices,
        items: draft.items,
        licence: draft.licence,
        credits: draft.credits,
        updated: draft.updated,
        services,
    })
}

/// `parse_draft` does not know the fields the gateway adds. Drop them, and `sig`.
fn strip_serve(m: &Map<String, Value>) -> Map<String, Value> {
    let mut o = m.clone();
    o.remove("version");
    o.remove("seller");
    o.remove("receipt_key");
    o.remove("sig");
    o
}

fn terms_key(page: &Page) -> Result<String, String> {
    if page.status != 402 {
        return Err("the seller did not answer 402".into());
    }
    let header = page.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-REQUIRED")).map(|(_, v)| v.as_str());
    let v = if let Some(h) = header {
        unb64json(h).map_err(|e| e.to_string())?
    } else {
        serde_json::from_str(&page.body).map_err(|_| "the 402 has no terms".to_string())?
    };
    v.get("accepts")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(|e| e.get("extra"))
        .and_then(|e| e.get("receiptKey"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "the 402 terms name no receipt key".into())
}

/// Fetch `seller_url`'s listing and check it against that URL's 402 terms. `get` performs one
/// GET and returns the answer. No directory and no relay is consulted.
pub fn fetch(seller_url: &str, mut get: impl FnMut(&str) -> Result<Page, String>) -> Result<Listing, String> {
    let origin = canonical_origin(seller_url);
    if origin.is_empty() || !http_url(seller_url) {
        return Err("the seller URL starts with http:// or https://".into());
    }
    let listed = get(&format!("{origin}{PATH}"))?;
    if listed.body.len() > MAX_BODY {
        return Err("the listing is too large".into());
    }
    if listed.status != 200 {
        return Err(format!("the listing answered {}", listed.status));
    }
    let doc: Value = serde_json::from_str(&listed.body).map_err(|_| "the listing is not JSON".to_string())?;
    let terms = get(seller_url)?;
    let key = terms_key(&terms)?;
    let listing = verify(&doc, &key)?;
    if canonical_origin(&listing.seller) != origin {
        return Err("the listing names another seller".into());
    }
    Ok(listing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xbt_primitives::hash::sha256;

    fn key() -> (SecretKey, String) {
        let sk = ecdsa::secret_key(&sha256(b"listing-test-key")).unwrap();
        let pk = hex::encode(ecdsa::pubkey(&sk));
        (sk, pk)
    }

    fn draft() -> Draft {
        parse_draft(&json!({
            "name": "Films",
            "kind": "video",
            "prices": {"byte_msat": 20, "per_bytes": 1048576},
            "items": [{"title": "Sintel", "url": "https://media.lazarus-xbt.xyz/Videos/s", "year": 2010, "credit": "(c) Blender Foundation"}],
            "licence": "CC BY 3.0",
            "credits": "(c) Blender Foundation, CC BY 3.0",
            "updated": "2026-10-25",
        }))
        .unwrap()
    }

    #[test]
    fn a_listing_verifies_only_under_the_terms_key() {
        let (sk, pk) = key();
        let doc = sign(&sk, &document(&draft(), "https://media.lazarus-xbt.xyz", &pk));
        let got = verify(&doc, &pk).unwrap();
        assert_eq!(got.name, "Films");
        assert_eq!(got.items[0].year, Some(2010));
        assert_eq!(got.prices["byte_msat"], "20");
        let other = hex::encode(ecdsa::pubkey(&ecdsa::secret_key(&sha256(b"other")).unwrap()));
        assert!(verify(&doc, &other).is_err());
        let mut tampered = doc.clone();
        tampered["name"] = json!("Other");
        assert!(verify(&tampered, &pk).is_err());
        assert!(parse_draft(&json!({"name": "n", "kind": "nope"})).is_err());
    }

    #[test]
    fn a_listing_1_lists_several_services_and_signs_them_all() {
        let (sk, pk) = key();
        let d = parse_draft(&json!({
            "name": "One box",
            "updated": "2026-10-26",
            "credits": "the seller",
            "services": [
                {"name": "Films", "kind": "video", "path": "/films/", "prices": {"byte_msat": 20, "per_bytes": 1048576}, "licence": "CC BY 3.0",
                 "items": [{"title": "Sintel", "url": "https://seller.example/films/s"}]},
                {"name": "Local model", "kind": "api", "path": "/ai/", "prices": {"request_msat": 5000}, "items": []},
            ],
        }))
        .unwrap();
        assert_eq!((d.services.len(), d.kind.as_str()), (2, "video"));
        let doc = sign(&sk, &document(&d, "https://seller.example", &pk));
        assert_eq!(doc["version"], VERSION_1);
        assert!(doc.get("kind").is_none() && doc.get("items").is_none());
        let got = verify(&doc, &pk).unwrap();
        assert_eq!(got.services.iter().map(|s| (s.name.as_str(), s.path.as_str())).collect::<Vec<_>>(), [("Films", "/films/"), ("Local model", "/ai/")]);
        assert_eq!(got.services[1].prices["request_msat"], "5000");
        assert_eq!((got.services[0].licence.as_str(), got.licence.as_str(), got.credits.as_str()), ("CC BY 3.0", "", "the seller"));
        let mut tampered = doc.clone();
        tampered["services"][1]["prices"]["request_msat"] = json!("1");
        assert!(verify(&tampered, &pk).is_err(), "a price is signed");
        // the two versions' digests differ: a document cannot be passed off as the other
        let mut relabelled = doc.clone();
        relabelled["version"] = json!(VERSION);
        assert!(verify(&relabelled, &pk).is_err());
        // a listing/0 reads as one service under /
        let one = verify(&sign(&sk, &document(&draft(), "https://seller.example", &pk)), &pk).unwrap();
        assert_eq!((one.services.len(), one.services[0].path.as_str(), one.services[0].name.as_str()), (1, "/", "Films"));
    }

    #[test]
    fn a_listing_1_refuses_a_bad_service() {
        let base = || json!({"name": "n", "updated": "u", "services": [{"name": "a", "kind": "api", "path": "/a/", "prices": {"request_msat": 1}, "items": []}]});
        assert!(parse_draft(&base()).is_ok());
        for (why, f) in [
            ("no services", Box::new(|v: &mut Value| v["services"] = json!([])) as Box<dyn Fn(&mut Value)>),
            ("path twice", Box::new(|v: &mut Value| { let s = v["services"][0].clone(); v["services"].as_array_mut().unwrap().push(s) })),
            ("bad path", Box::new(|v: &mut Value| v["services"][0]["path"] = json!("a/"))),
            ("dot path", Box::new(|v: &mut Value| v["services"][0]["path"] = json!("/a/../b/"))),
            ("no prices", Box::new(|v: &mut Value| { v["services"][0].as_object_mut().unwrap().remove("prices"); })),
            ("bad kind", Box::new(|v: &mut Value| v["services"][0]["kind"] = json!("mining"))),
            ("stray key", Box::new(|v: &mut Value| v["kind"] = json!("video"))),
        ] {
            let mut v = base();
            f(&mut v);
            assert!(parse_draft(&v).is_err(), "{why}");
        }
    }

    #[test]
    fn fetch_reads_the_listing_and_the_402() {
        let (sk, pk) = key();
        let origin = "https://media.lazarus-xbt.xyz";
        let doc = sign(&sk, &document(&draft(), origin, &pk));
        let body = serde_json::to_string(&doc).unwrap();
        let terms = json!({"accepts": [{"extra": {"receiptKey": pk}}]});
        let terms_body = serde_json::to_string(&terms).unwrap();
        let got = fetch(origin, |url| {
            if url.ends_with(PATH) {
                Ok(Page { status: 200, headers: vec![], body: body.clone() })
            } else if url == origin {
                Ok(Page { status: 402, headers: vec![], body: terms_body.clone() })
            } else {
                Err(format!("unexpected {url}"))
            }
        })
        .unwrap();
        assert_eq!(got.receipt_key, pk);
        let wrong = fetch(origin, |url| {
            if url.ends_with(PATH) {
                Ok(Page { status: 200, headers: vec![], body: body.clone() })
            } else {
                Ok(Page { status: 402, headers: vec![], body: serde_json::to_string(&json!({"accepts": [{"extra": {"receiptKey": "02"}}]})).unwrap() })
            }
        });
        assert!(wrong.is_err());
    }
}
