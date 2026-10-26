//! A seller's signed listing (`docs/LISTINGS.md`) on Nostr, as a NIP-99 classified listing (kind
//! 30402), so that any Nostr client that shows classifieds shows it (`docs/NOSTR.md`).
//!
//! The event carries the signed `listing/0` document whole, in the tag `xbt402-listing`, and the
//! receipt key's binding of the event's author to the seller, in the tag `xbt402-bind`. A reader
//! keeps an event only when the event's own signature holds, the listing's signature holds under
//! the receipt key it names, the binding holds under that same key for this author and this seller,
//! and the `d` tag is that seller's origin. The tags a classifieds client reads (`title`,
//! `summary`, `price`, `t`, `r`) and the Markdown `content` are written from the signed document,
//! and a reader of ours never takes anything from them.
//!
//! What this does not tell a reader: that the receipt key is the one the seller's own 402 terms
//! name. Only the seller's URL says that ([`xbt402::listing::fetch`]). A listing read here is
//! therefore shown as unvetted, and checked against the seller before it is kept for good.
use std::collections::HashMap;

use serde_json::{json, Value};
use xbt402::listing::{self, Listing};
use xbt402::wire::canonical_origin;

use crate::event::{tag, Event, Keys};

/// NIP-99: a classified listing, an addressable event (one per author, kind and `d`).
pub const KIND_CLASSIFIED: u64 = 30402;
/// The `t` tag every Lightning Stream listing carries, and the one readers ask relays for.
pub const TOPIC: &str = "lightning-stream";
/// The signed `listing/0` document, compact JSON.
pub const LISTING_TAG: &str = "xbt402-listing";
/// Hex of the receipt key's DER signature binding the author to the seller.
pub const BIND_TAG: &str = "xbt402-bind";
/// The largest listing event written or read. Many relays refuse events above 64 KiB.
pub const MAX_EVENT: usize = 60 * 1024;
/// An event dated further ahead than this is refused: it would outrank every honest update.
pub const MAX_AHEAD_S: u64 = 600;
/// Items written into the Markdown for people; the signed document keeps them all.
const ITEMS_IN_TEXT: usize = 50;

/// A listing read from Nostr whose signatures and binding all held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NostrListing {
    pub listing: Listing,
    /// The event's author, hex of the x-only key.
    pub author: String,
    pub event_id: String,
    pub created_at: u64,
}

fn fmt_sat(msat: u64) -> String {
    if msat.is_multiple_of(1000) {
        return (msat / 1000).to_string();
    }
    let s = format!("{}.{:03}", msat / 1000, msat % 1000);
    s.trim_end_matches('0').to_string()
}

fn unit_of(per_bytes: u64) -> String {
    match per_bytes {
        1 => "byte".into(),
        1024 => "KiB".into(),
        1_048_576 => "MiB".into(),
        1_073_741_824 => "GiB".into(),
        n => format!("piece of {n} bytes"),
    }
}

fn num(prices: &Value, k: &str) -> Option<u64> {
    prices.get(k).and_then(Value::as_str).and_then(|s| s.parse().ok())
}

/// Each price in words, in the order request, bytes, seconds: `[("20", "MiB"), ...]` as sat and
/// unit, the way NIP-99's `price` tag and the app's Browse page write them.
pub fn price_parts(prices: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(m) = num(prices, "request_msat") {
        out.push((fmt_sat(m), "request".into()));
    }
    if let Some(m) = num(prices, "byte_msat") {
        out.push((fmt_sat(m), unit_of(num(prices, "per_bytes").unwrap_or(1))));
    }
    if let Some(m) = num(prices, "second_msat") {
        out.push((fmt_sat(m), "second".into()));
    }
    out
}

/// `"20 sat a MiB"`, or several joined by commas.
pub fn price_text(prices: &Value) -> String {
    let parts: Vec<String> = price_parts(prices).into_iter().map(|(s, u)| format!("{s} sat a {u}")).collect();
    if parts.is_empty() { "free".into() } else { parts.join(", ") }
}

fn markdown(l: &Listing) -> String {
    let mut s = format!("**{}**: {} sold by the piece over Lightning Stream, paid as it arrives.\n\nPrice: {}.\n", l.name, l.kind, price_text(&l.prices));
    if !l.items.is_empty() {
        s.push_str("\nItems:\n");
        for i in l.items.iter().take(ITEMS_IN_TEXT) {
            s.push_str(&format!("- {}", i.title));
            if let Some(y) = i.year {
                s.push_str(&format!(" ({y})"));
            }
            if let Some(c) = &i.credit {
                s.push_str(&format!(", {c}"));
            }
            s.push('\n');
        }
        if l.items.len() > ITEMS_IN_TEXT {
            s.push_str(&format!("- and {} more\n", l.items.len() - ITEMS_IN_TEXT));
        }
    }
    s.push_str(&format!("\nLicence: {}\n\nCredits: {}\n\nOpen it in a Lightning Stream app: {}\n", l.licence, l.credits, l.seller));
    s
}

/// The classified listing for `signed` (the document the gateway serves, with `sig`), by `keys`.
/// `bind_sig` is [`xbt402::listing::bind`] of `keys`' public key and the listing's seller.
pub fn listing_event(keys: &Keys, signed: &Value, bind_sig: &str, created_at: u64) -> Result<Event, String> {
    let l = listing::verify_self(signed)?;
    let seller = canonical_origin(&l.seller);
    if !listing::verify_bind(&l.receipt_key, &keys.public.serialize(), &seller, bind_sig) {
        return Err("the binding is not the receipt key's for this Nostr key and seller".into());
    }
    let mut tags = vec![
        tag("d", &seller),
        tag("title", &l.name),
        tag("summary", &format!("{} over Lightning Stream: {}", l.kind, price_text(&l.prices))),
        tag("published_at", &created_at.to_string()),
        tag("t", TOPIC),
        tag("t", &l.kind),
        tag("r", &l.seller),
        tag("alt", &format!("Lightning Stream listing: {}", l.name)),
    ];
    if let Some((amount, unit)) = price_parts(&l.prices).into_iter().next() {
        tags.push(vec!["price".into(), amount, "SAT".into(), unit]);
    }
    tags.push(tag(LISTING_TAG, &serde_json::to_string(signed).map_err(|e| e.to_string())?));
    tags.push(tag(BIND_TAG, bind_sig));
    let ev = Event::sign(keys, created_at, KIND_CLASSIFIED, tags, markdown(&l));
    let size = ev.to_value().to_string().len();
    if size > MAX_EVENT {
        return Err(format!("the listing event is {size} bytes, more than the {MAX_EVENT} relays are asked to take: list fewer items"));
    }
    Ok(ev)
}

/// The filter that asks a relay for Lightning Stream listings.
pub fn filter(limit: usize) -> Value {
    json!({"kinds": [KIND_CLASSIFIED], "#t": [TOPIC], "limit": limit})
}

/// Check one event, as [`listing_event`] wrote it. `now` is the reader's clock.
pub fn read_event(ev: &Event, now: u64) -> Result<NostrListing, String> {
    if ev.kind != KIND_CLASSIFIED {
        return Err("not a classified listing".into());
    }
    if ev.to_value().to_string().len() > MAX_EVENT {
        return Err("the event is too large".into());
    }
    if !ev.verify() {
        return Err("the event's id or signature does not hold".into());
    }
    if ev.created_at > now.saturating_add(MAX_AHEAD_S) {
        return Err("the event is dated in the future".into());
    }
    if !ev.tags.iter().any(|t| t.len() >= 2 && t[0] == "t" && t[1] == TOPIC) {
        return Err("not a Lightning Stream listing".into());
    }
    let doc: Value = serde_json::from_str(ev.tag(LISTING_TAG).ok_or("no signed listing in the event")?).map_err(|_| "the signed listing is not JSON")?;
    let l = listing::verify_self(&doc)?;
    let seller = canonical_origin(&l.seller);
    if ev.tag("d") != Some(seller.as_str()) {
        return Err("the event's d tag is not the listing's seller".into());
    }
    let author: [u8; 32] = hex::decode(&ev.pubkey).ok().and_then(|b| b.try_into().ok()).ok_or("the author is not a key")?;
    let bind = ev.tag(BIND_TAG).ok_or("the event has no binding to the receipt key")?;
    if !listing::verify_bind(&l.receipt_key, &author, &seller, bind) {
        return Err("the receipt key did not bind this Nostr key to this seller".into());
    }
    Ok(NostrListing { listing: l, author: ev.pubkey.clone(), event_id: ev.id.clone(), created_at: ev.created_at })
}

/// Every good listing among `events`, the newest per receipt key and seller (a seller may move
/// to a new Nostr key; the receipt key bound both), sorted by name. Also how many were refused.
pub fn collect(events: &[Event], now: u64) -> (Vec<NostrListing>, usize) {
    let mut best: HashMap<(String, String), NostrListing> = HashMap::new();
    let mut refused = 0;
    let mut seen = std::collections::HashSet::new();
    for ev in events {
        if !seen.insert(ev.id.clone()) {
            continue;
        }
        match read_event(ev, now) {
            Ok(n) => {
                let k = (n.listing.receipt_key.clone(), canonical_origin(&n.listing.seller));
                let newer = best.get(&k).is_none_or(|o| (n.created_at, &n.event_id) > (o.created_at, &o.event_id));
                if newer {
                    best.insert(k, n);
                }
            }
            Err(_) => refused += 1,
        }
    }
    let mut v: Vec<NostrListing> = best.into_values().collect();
    v.sort_by(|a, b| a.listing.name.to_ascii_lowercase().cmp(&b.listing.name.to_ascii_lowercase()).then(a.listing.seller.cmp(&b.listing.seller)));
    (v, refused)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prices_in_words() {
        assert_eq!(price_text(&json!({"byte_msat": "20000", "per_bytes": "1048576"})), "20 sat a MiB");
        assert_eq!(price_text(&json!({"request_msat": "1500", "second_msat": "250"})), "1.5 sat a request, 0.25 sat a second");
        assert_eq!(price_text(&json!({"byte_msat": "7", "per_bytes": "4096"})), "0.007 sat a piece of 4096 bytes");
        assert_eq!(price_text(&json!({})), "free");
    }
}
