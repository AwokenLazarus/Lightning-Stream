//! Shops without a web address the owner added (`docs/DIRECT-LINKS.md`): for each, the receipt key
//! its listing names and its signed `transport/1` document, as its Nostr listing carried them. The
//! services file keeps what the shop sells; this file keeps how to reach it and, through its links,
//! which Lightning node it is paid through.
use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Value};

/// What is kept for one shop.
#[derive(Debug, Clone, PartialEq)]
pub struct Shop {
    pub receipt_key: String,
    pub transport: Option<Value>,
    /// When the listing this was taken from was published (unix seconds). `None` for a shop kept by
    /// an app before 0.2.14.
    pub published_at: Option<u64>,
}

/// Every shop in the file at `path`, by origin; none when there is no file.
pub fn load(path: &Path) -> Result<BTreeMap<String, Shop>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let m = v.as_object().ok_or_else(|| format!("{}: not an object", path.display()))?;
    Ok(m.iter()
        .filter(|(origin, _)| xbt402::shop::is_shop(origin))
        .filter_map(|(origin, s)| {
            let receipt_key = s.get("receipt_key")?.as_str()?.to_string();
            Some((origin.clone(), Shop { receipt_key, transport: s.get("transport").filter(|t| !t.is_null()).cloned(),
                                         published_at: s.get("published_at").and_then(Value::as_u64) }))
        })
        .collect())
}

/// Write `shops` to `path`, replacing it whole.
pub fn save(path: &Path, shops: &BTreeMap<String, Shop>) -> Result<(), String> {
    let v: serde_json::Map<String, Value> =
        shops.iter().map(|(o, s)| (o.clone(), json!({"receipt_key": s.receipt_key, "transport": s.transport, "published_at": s.published_at}))).collect();
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&Value::Object(v)).map_err(|e| e.to_string())?).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

/// The Lightning node the shop at `origin` is paid through, from its links, as of `now`.
pub fn node(shop: &Shop, origin: &str, now: u64) -> Option<String> {
    xbt402::transport::node_of(shop.transport.as_ref()?, origin, &shop.receipt_key, now)
}

/// When what is kept of the shop was published: its listing's date, or, for a shop kept by an app
/// before 0.2.14, when its links were signed (the transport document's `updated`, unix seconds).
pub fn published_at(shop: &Shop) -> Option<u64> {
    shop.published_at.or_else(|| shop.transport.as_ref()?.get("updated")?.as_str()?.trim().parse().ok())
}

/// How many days old what is kept of the shop at `origin` is, when it looks offline at `now`: its
/// listing is stale ([`xbt_nostr::market::STALE_S`], the rule Found on Nostr uses) and no Lightning
/// node vouches for any of its links now. `None`: it does not, or its date is not known.
pub fn offline_days(shop: &Shop, origin: &str, now: u64) -> Option<u64> {
    let at = published_at(shop)?;
    (xbt_nostr::market::is_stale(at, now) && node(shop, origin, now).is_none()).then(|| now.saturating_sub(at) / 86_400)
}

/// What a shop that looks offline is said to be, `days` after its listing ([`offline_days`],
/// [`xbt_nostr::market::NostrListing::offline`]).
pub fn offline_words(days: u64) -> String {
    format!("This listing is {days} day{} old and no Lightning node vouches for it any more: the shop looks offline.", if days == 1 { "" } else { "s" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shops_are_kept_and_read_back_and_other_names_are_ignored() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("shops.json");
        assert!(load(&p).unwrap().is_empty());
        let origin = xbt402::shop::origin_for(&[3u8; 32]);
        let mut m = BTreeMap::new();
        m.insert(origin.clone(), Shop { receipt_key: "02ab".into(), transport: Some(json!({"version": "transport/1"})), published_at: Some(5) });
        save(&p, &m).unwrap();
        assert_eq!(load(&p).unwrap(), m);
        std::fs::write(&p, json!({"https://web.example": {"receipt_key": "02"}, origin.clone(): {"receipt_key": "02ab", "transport": null}}).to_string()).unwrap();
        let back = load(&p).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[&origin].transport, None);
        assert_eq!(back[&origin].published_at, None, "kept by an app before 0.2.14");
    }

    /// 0.2.14: a kept shop whose listing is two days old and whose links no node vouches for now looks offline, and
    /// is said to be so in plain words (the orphan test shop of 2026-10-30, whose key was lost with its box).
    #[test]
    fn a_stale_shop_no_node_vouches_for_looks_offline() {
        let origin = xbt402::shop::origin_for(&[3u8; 32]);
        let at = 1_790_000_000;
        let shop = Shop { receipt_key: "02ab".into(), transport: None, published_at: Some(at) };
        assert_eq!(offline_days(&shop, &origin, at + 3600), None, "new enough");
        assert_eq!(offline_days(&shop, &origin, at + 6 * 86_400 + 5), Some(6));
        assert_eq!(offline_words(6), "This listing is 6 days old and no Lightning node vouches for it any more: the shop looks offline.");
        assert_eq!(offline_words(1), "This listing is 1 day old and no Lightning node vouches for it any more: the shop looks offline.");
        // kept by an older app: dated by its links' document, or not at all
        let undated = Shop { published_at: None, ..shop.clone() };
        assert_eq!(offline_days(&undated, &origin, at + 6 * 86_400), None);
        let by_links = Shop { transport: Some(json!({"version": "transport/1", "updated": at.to_string()})), ..undated };
        assert_eq!(published_at(&by_links), Some(at));
        assert_eq!(offline_days(&by_links, &origin, at + 3 * 86_400), Some(3));
    }
}
