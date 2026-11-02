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
            Some((origin.clone(), Shop { receipt_key, transport: s.get("transport").filter(|t| !t.is_null()).cloned() }))
        })
        .collect())
}

/// Write `shops` to `path`, replacing it whole.
pub fn save(path: &Path, shops: &BTreeMap<String, Shop>) -> Result<(), String> {
    let v: serde_json::Map<String, Value> =
        shops.iter().map(|(o, s)| (o.clone(), json!({"receipt_key": s.receipt_key, "transport": s.transport}))).collect();
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&Value::Object(v)).map_err(|e| e.to_string())?).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

/// The Lightning node the shop at `origin` is paid through, from its links, as of `now`.
pub fn node(shop: &Shop, origin: &str, now: u64) -> Option<String> {
    xbt402::transport::node_of(shop.transport.as_ref()?, origin, &shop.receipt_key, now)
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
        m.insert(origin.clone(), Shop { receipt_key: "02ab".into(), transport: Some(json!({"version": "transport/1"})) });
        save(&p, &m).unwrap();
        assert_eq!(load(&p).unwrap(), m);
        std::fs::write(&p, json!({"https://web.example": {"receipt_key": "02"}, origin.clone(): {"receipt_key": "02ab", "transport": null}}).to_string()).unwrap();
        let back = load(&p).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[&origin].transport, None);
    }
}
