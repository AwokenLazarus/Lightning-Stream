//! `list_services`: what an agent may buy. The wallet UI builds Browse's catalog from the sellers the
//! owner added (their signed listings) and writes it for agents as `catalog.json`, beside the shops
//! file (`XBT_SHOPS_FILE`) in the directory the MCP server already reads (`xbt_wallet_ui::services::catalog`).
//! This module reads that file, asks the signer for the owner's rules, and marks each seller allowed or
//! not, as the UI's Browse does. It never pays and never writes.
use std::path::PathBuf;

use serde_json::{json, Value};

/// The largest catalog read, as the UI's services file.
const MAX_BYTES: u64 = 1 << 20;

/// The catalog file: `XBT_MCP_CATALOG`, else `catalog.json` beside the shops file (`XBT_SHOPS_FILE`).
/// `None`: neither is set, and no catalog can be found.
pub fn catalog_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("XBT_MCP_CATALOG") {
        return Some(PathBuf::from(p));
    }
    std::env::var_os("XBT_SHOPS_FILE").map(PathBuf::from).map(|f| f.with_file_name("catalog.json"))
}

/// The catalog as the UI wrote it, or why there is none.
pub fn read_catalog(path: &std::path::Path) -> Result<Value, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.len() > MAX_BYTES {
        return Err(format!("{}: larger than {} KiB", path.display(), MAX_BYTES / 1024));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: not JSON: {e}", path.display()))
}

/// `scheme://host[:port]` of an absolute http(s) URL, lower case, with no port where it is the
/// scheme's default; `None` for anything else.
pub fn http_origin(url: &str) -> Option<String> {
    let u = xbt402::wire::request_url(url.trim());
    let scheme = u.scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") || u.host.is_empty() {
        return None;
    }
    let default = (scheme == "http" && u.port == "80") || (scheme == "https" && u.port == "443");
    let port = if u.port.is_empty() || default { String::new() } else { format!(":{}", u.port) };
    Some(format!("{scheme}://{}{port}", u.host.to_ascii_lowercase()))
}

/// Whether the owner's rules `policy` let the wallet pay the seller at `origin`, as the UI's Browse
/// decides it (`xbt_wallet_ui::app::rules_allow`, which a test there holds this to): the seller's address
/// on the list that may be paid with its node on file (`counterparties.<address>.ln_node`), or
/// `ln:<node>` on that list for its node on file or for `node`, the node its shop entry vouches for.
pub fn allowed(policy: &Value, origin: &str, node: Option<&str>) -> bool {
    let Some(o) = http_origin(origin) else { return false };
    let list: Vec<String> = policy.get("allowlist").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str)
        .map(|x| x.trim().to_ascii_lowercase()).collect();
    let on_file = policy.get("counterparties").and_then(Value::as_object).into_iter().flatten()
        .find(|(k, _)| http_origin(k).as_deref() == Some(o.as_str()))
        .and_then(|(_, v)| v.get("ln_node")).and_then(Value::as_str).map(str::trim).filter(|n| !n.is_empty()).map(str::to_ascii_lowercase);
    let listed = list.iter().any(|x| http_origin(x).as_deref() == Some(o.as_str()));
    if listed && on_file.is_some() {
        return true;
    }
    [on_file, node.map(|n| n.trim().to_ascii_lowercase())].into_iter().flatten().any(|n| list.contains(&format!("ln:{n}")))
}

/// The answer of `list_services`: the catalog's services, each marked `allowed` by the owner's rules
/// `policy`; with `kind` (`apps`, `files`, `ai`, `hashrate`, `data`), only those. Each service names the
/// exact address to pass to `xbt402_pay` (`pay_address`, or an item's `url`).
pub fn list(catalog: &Value, policy: &Value, kind: &str) -> Value {
    let kind = kind.trim().to_ascii_lowercase();
    let ai = catalog.get("ai_endpoint").filter(|v| v.is_string()).cloned().unwrap_or(Value::Null);
    let services: Vec<Value> = catalog.get("services").and_then(Value::as_array).into_iter().flatten()
        .filter(|s| kind.is_empty() || s.get("kind").and_then(Value::as_str) == Some(kind.as_str()))
        .map(|s| {
            let mut s = s.clone();
            let seller = s.get("seller").and_then(Value::as_str).unwrap_or("").to_string();
            let node = s.get("node").and_then(Value::as_str).map(str::to_string);
            s["allowed"] = allowed(policy, &seller, node.as_deref()).into();
            if let Some(m) = s.as_object_mut() {
                m.remove("node");
            }
            s
        }).collect();
    let n_allowed = services.iter().filter(|s| s["allowed"] == true).count();
    json!({
        "services": services,
        "allowed": n_allowed,
        "ai_endpoint": ai,
        "how": "Pay for a service with xbt402_pay, passing its pay_address (or a path under it, or one of its items' url) as url. A service marked \
                allowed: false is refused until the owner allows its seller in the wallet's Spending rules. An AI service is easiest through \
                the box's OpenAI-compatible ai_endpoint (where given): it lists its models at <ai_endpoint>/models and pays per call.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seller_is_allowed_as_browse_decides() {
        let node = "02".to_string() + &"ab".repeat(32);
        let p = json!({"allowlist": ["https://Shop.example:443/"], "counterparties": {"https://shop.example": {"ln_node": node}}});
        assert!(allowed(&p, "https://shop.example", None));
        assert!(!allowed(&p, "https://other.example", None));
        // listed with no node on file: not paid
        assert!(!allowed(&json!({"allowlist": ["https://shop.example"]}), "https://shop.example", None));
        // a shop by its key, allowed through its node's ln: line, as its entry vouches for it
        let shop = "http://abc.shop.invalid";
        assert!(allowed(&json!({"allowlist": [format!("ln:{node}")]}), shop, Some(&node)));
        assert!(!allowed(&json!({"allowlist": [format!("ln:{node}")]}), shop, None));
    }

    #[test]
    fn the_list_marks_each_service_and_keeps_its_address() {
        let node = "02".to_string() + &"cd".repeat(32);
        let catalog = json!({"version": 1, "ai_endpoint": "http://box.local:33540/v1", "services": [
            {"name": "Films", "seller": "https://films.example", "seller_name": "Films", "kind": "files", "price_text": "20 sat a MiB",
             "pay_address": "https://films.example/files/", "items": [{"title": "A film", "url": "https://films.example/files/a.mkv"}]},
            {"name": "Model", "seller": "http://k.shop.invalid", "seller_name": "Genesis", "kind": "ai", "price_text": "4 sat per 1,000 tokens",
             "pay_address": "http://k.shop.invalid/v1/", "node": node},
        ]});
        let p = json!({"allowlist": [format!("ln:{node}")]});
        let v = list(&catalog, &p, "");
        assert_eq!((v["services"][0]["allowed"].as_bool(), v["services"][1]["allowed"].as_bool(), v["allowed"].as_u64()), (Some(false), Some(true), Some(1)));
        assert!(v["services"][1].get("node").is_none(), "the vouched node is not shown");
        assert_eq!(v["services"][0]["items"][0]["url"], "https://films.example/files/a.mkv");
        assert_eq!(v["ai_endpoint"], "http://box.local:33540/v1");
        assert_eq!(list(&catalog, &p, "ai")["services"].as_array().unwrap().len(), 1);
        assert!(list(&json!({}), &p, "")["services"].as_array().unwrap().is_empty());
    }
}
