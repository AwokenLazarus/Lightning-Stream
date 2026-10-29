//! Where a link is reached, told over Nostr instead of a lookup service of iroh's makers.
//!
//! A seller's link publishes its current addresses and relay as a signed Nostr event: replaceable,
//! one per link key (NIP-78 application data, kind 30078, `d` = `lightning-stream-link:<key>`),
//! sent to the shop's own relays and sent again whenever they change. A buyer resolves a link key
//! by asking those relays for that event, and believes it only from the Nostr key the seller's
//! transport document is bound to ([`NostrLookup::expect`]). A forged event could at worst send a
//! buyer to a wrong address, where the link's own handshake (the key itself) fails.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use iroh::address_lookup::{AddressLookup, EndpointData, EndpointInfo, Error, Item};
use iroh::{EndpointId, RelayUrl};
use n0_future::boxed::BoxStream;
use n0_future::stream::{self, StreamExt};
use serde_json::{json, Value};
use xbt_nostr::event::{Event, Keys};

/// NIP-78: application-specific data, parameterized replaceable.
pub const KIND: u64 = 30078;
const PUBLISH_WAIT: Duration = Duration::from_secs(10);
const QUERY_WAIT: Duration = Duration::from_secs(6);

/// The event's `d` tag for a link key.
pub fn d_tag(id: &EndpointId) -> String {
    format!("lightning-stream-link:{}", hex::encode(id.as_bytes()))
}

/// Publishes a seller's link addresses, and resolves sellers' link keys, over Nostr relays.
pub struct NostrLookup {
    /// The shop's Nostr key, for a seller's link; `None` for a buyer's, which only resolves.
    keys: Option<Keys>,
    relays: Vec<String>,
    /// For each link key, the Nostr key whose word for it is believed.
    authors: Mutex<HashMap<EndpointId, String>>,
    last: Mutex<Option<String>>,
    id: Mutex<Option<EndpointId>>,
}

impl std::fmt::Debug for NostrLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NostrLookup({} relays, publishing: {})", self.relays.len(), self.keys.is_some())
    }
}

impl NostrLookup {
    pub fn new(keys: Option<Keys>, relays: Vec<String>) -> Self {
        Self { keys, relays, authors: Mutex::new(HashMap::new()), last: Mutex::new(None), id: Mutex::new(None) }
    }

    /// The link key whose addresses this lookup publishes (a seller's own).
    pub fn set_own(&self, id: EndpointId) {
        *lock(&self.id) = Some(id);
    }

    /// Believes addresses for `link` only from `nostr_pubkey_hex` (x-only, hex): the key the seller's
    /// transport document is bound to.
    pub fn expect(&self, link: EndpointId, nostr_pubkey_hex: &str) {
        lock(&self.authors).insert(link, nostr_pubkey_hex.to_ascii_lowercase());
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// The event's content: where the link is reached.
fn content(data: &EndpointData) -> String {
    let addrs: Vec<String> = data.ip_addrs().map(|a| a.to_string()).collect();
    let relays: Vec<String> = data.relay_urls().map(|u| u.to_string()).collect();
    json!({"addrs": addrs, "relays": relays}).to_string()
}

/// What a believed event says, as iroh's endpoint info.
pub fn info_from(id: EndpointId, ev: &Event) -> Option<EndpointInfo> {
    let v: Value = serde_json::from_str(&ev.content).ok()?;
    let addrs = v.get("addrs")?.as_array()?.iter().filter_map(|a| a.as_str()?.parse().ok()).take(16).collect();
    let mut info = EndpointInfo::new(id).with_ip_addrs(addrs);
    for r in v.get("relays").and_then(Value::as_array).into_iter().flatten().take(4) {
        if let Some(u) = r.as_str().and_then(|s| s.parse::<RelayUrl>().ok()) {
            info = info.with_relay_url(u);
        }
    }
    Some(info)
}

/// The newest of `events` that is signed, by `author`, for `id`'s `d` tag.
pub fn newest(events: Vec<Event>, author: &str, id: &EndpointId) -> Option<Event> {
    let d = d_tag(id);
    events
        .into_iter()
        .filter(|e| e.kind == KIND && e.pubkey == author && e.tag("d") == Some(d.as_str()) && e.verify())
        .max_by_key(|e| e.created_at)
}

impl AddressLookup for NostrLookup {
    fn publish(&self, data: &EndpointData) {
        let (Some(keys), Some(id)) = (self.keys.as_ref(), *lock(&self.id)) else { return };
        if self.relays.is_empty() {
            return;
        }
        let body = content(data);
        {
            let mut last = lock(&self.last);
            if last.as_deref() == Some(body.as_str()) {
                return;
            }
            *last = Some(body.clone());
        }
        let ev = Event::sign(keys, now(), KIND, vec![vec!["d".into(), d_tag(&id)]], body);
        let relays = self.relays.clone();
        // the relay client blocks: off the endpoint's runtime
        std::thread::spawn(move || {
            let _ = xbt_nostr::oneshot::publish(&relays, &ev, PUBLISH_WAIT);
        });
    }

    fn resolve(&self, id: EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        let author = lock(&self.authors).get(&id).cloned()?;
        if self.relays.is_empty() {
            return None;
        }
        let relays = self.relays.clone();
        let filter = json!({"kinds": [KIND], "authors": [author.clone()], "#d": [d_tag(&id)], "limit": 4});
        let fut = async move {
            let found = tokio::task::spawn_blocking(move || xbt_nostr::oneshot::query(&relays, &filter, QUERY_WAIT).0).await.ok()?;
            let ev = newest(found, &author, &id)?;
            let at = ev.created_at;
            info_from(id, &ev).map(|info| Item::new(info, "nostr", Some(at * 1_000_000)))
        };
        Some(stream::once_future(fut).filter_map(|x| x.map(Ok)).boxed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> EndpointId {
        iroh::SecretKey::from_bytes(&[3u8; 32]).public()
    }

    #[test]
    fn only_the_shops_signed_event_for_this_link_is_believed() {
        let shop = Keys::generate();
        let other = Keys::generate();
        let d = d_tag(&id());
        let body = r#"{"addrs":["203.0.113.7:4000"],"relays":["https://relay.example/"]}"#;
        let good = Event::sign(&shop, 100, KIND, vec![vec!["d".into(), d.clone()]], body.into());
        let newer = Event::sign(&shop, 200, KIND, vec![vec!["d".into(), d.clone()]], body.replace("4000", "4001"));
        let forged = Event::sign(&other, 300, KIND, vec![vec!["d".into(), d.clone()]], body.into());
        let wrong_d = Event::sign(&shop, 400, KIND, vec![vec!["d".into(), "lightning-stream-link:00".into()]], body.into());
        let got = newest(vec![good, newer.clone(), forged, wrong_d], &shop.public_hex(), &id()).unwrap();
        assert_eq!(got.id, newer.id);
        let info = info_from(id(), &got).unwrap();
        assert_eq!(info.ip_addrs().map(|a| a.to_string()).collect::<Vec<_>>(), vec!["203.0.113.7:4001"]);
        assert_eq!(info.relay_urls().count(), 1);
    }
}
