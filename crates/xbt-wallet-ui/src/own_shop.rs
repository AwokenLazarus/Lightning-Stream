//! The owner's own shop, seen from the buying side of the same box.
//!
//! A box cannot buy from itself: its Lightning node cannot pay its own invoices. So a service whose
//! seller is this box's own gateway (the origin its config sells under) is shown as "your shop",
//! and its items play as a free preview straight from the service on the box, through this UI,
//! for the logged-in owner only. Nothing is paid and nothing goes through the gateway. Buyers never
//! see this: the preview is a page of the owner's own UI, behind its login.
use serde_json::Value;

use crate::app::App;
use crate::services;
use crate::setup::GW_CONFIG;

/// The route of the gateway's config that sells `path`: a route path ending in `/` covers what is
/// under it, any other is that path alone; the longest wins, as in the gateway.
fn route_for<'a>(routes: &'a [Value], path: &str) -> Option<&'a Value> {
    routes
        .iter()
        .filter(|r| {
            let p = r["path"].as_str().unwrap_or("");
            !p.is_empty() && if p.ends_with('/') { path.starts_with(p) } else { path == p }
        })
        .max_by_key(|r| r["path"].as_str().map(str::len).unwrap_or(0))
}

/// Where the service on the box answers `item_url`, as the gateway would ask it: the route's own
/// upstream or the config's, the item's path (less the route's path when it says so) and query.
pub fn upstream_url(cfg: &Value, item_url: &str) -> Result<String, String> {
    let shop = cfg["public_url"].as_str().and_then(services::http_origin).ok_or("this box sells nothing yet")?;
    if services::http_origin(item_url).as_deref() != Some(shop.as_str()) {
        return Err("that item is not in your shop".into());
    }
    let after = &item_url.trim()[item_url.trim().find("://").map(|i| i + 3).unwrap_or(0)..];
    let target = after.find('/').map(|i| &after[i..]).unwrap_or("/");
    let (path, query) = target.split_once('?').map(|(p, q)| (p, Some(q))).unwrap_or((target, None));
    let routes = cfg["routes"].as_array().cloned().unwrap_or_default();
    let route = route_for(&routes, path).ok_or("no route of your shop sells that item")?;
    let base = route["upstream"].as_str().or(cfg["upstream"].as_str()).ok_or("your shop names no service for that item")?;
    if !base.starts_with("http://") && !base.starts_with("https://") {
        return Err("your shop's service address is not a web address".into());
    }
    let mut p = path.to_string();
    if route["strip_prefix"] == true {
        let rp = route["path"].as_str().unwrap_or("").trim_end_matches('/');
        p = path.strip_prefix(rp).filter(|r| r.is_empty() || r.starts_with('/')).map(|r| if r.is_empty() { "/".to_string() } else { r.to_string() })
            .unwrap_or(p);
    }
    Ok(format!("{}{}{}", base.trim_end_matches('/'), p, query.map(|q| format!("?{q}")).unwrap_or_default()))
}

impl App {
    /// The gateway's config on this box, if the Sell page wrote one.
    fn own_config(&self) -> Option<Value> {
        if !self.cfg.sell {
            return None;
        }
        std::fs::read_to_string(self.cfg.gw.dir.join(GW_CONFIG)).ok().and_then(|t| serde_json::from_str(&t).ok())
    }

    /// Whether `seller` (an address) is this box's own shop.
    pub fn is_own_shop(&self, seller: &str) -> bool {
        let Some(cfg) = self.own_config() else { return false };
        let own = cfg["public_url"].as_str().and_then(services::http_origin);
        own.is_some() && own == services::http_origin(seller)
    }

    /// Where the free preview of `item_url` (an item of the owner's own shop) comes from.
    pub fn preview_upstream(&self, item_url: &str) -> Result<String, String> {
        upstream_url(&self.own_config().ok_or("this box sells nothing yet")?, item_url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_item_of_the_shop_is_found_on_the_service_it_is_sold_from() {
        let cfg = json!({"public_url": "https://media.example", "upstream": "http://jellyfin:8096",
                         "routes": [{"path": "/Videos/abc/"}, {"path": "/ai/", "upstream": "http://model:8080/", "strip_prefix": true}]});
        assert_eq!(upstream_url(&cfg, "https://media.example/Videos/abc/stream?static=true").unwrap(),
                   "http://jellyfin:8096/Videos/abc/stream?static=true");
        assert_eq!(upstream_url(&cfg, "https://media.example/ai/v1/models").unwrap(), "http://model:8080/v1/models");
        // another seller's item, and a path no route sells, are never fetched
        assert!(upstream_url(&cfg, "https://other.example/Videos/abc/stream").is_err());
        assert!(upstream_url(&cfg, "https://media.example/Videos/zzz/stream").is_err());
        assert!(upstream_url(&json!({"routes": []}), "https://media.example/x").is_err());
    }
}
