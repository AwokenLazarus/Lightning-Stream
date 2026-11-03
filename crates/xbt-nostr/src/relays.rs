//! Stream relays: the iroh relays that carry a direct link when two routers will not let it punch
//! through (`docs/RUN-A-RELAY.md`). Anyone may run one and announce it on Nostr; an app collects
//! the announcements, probes the relays, and picks a nearby healthy one, keeping the default relay
//! as the last resort.
//!
//! An announcement is a NIP-78 application-data event (kind 30078, addressable: one per author and
//! `d`), with `d` = `lightning-stream-relay:<relay URL>` and the tag `t` = [`TOPIC`]. Its tags carry
//! what the app needs; its `content` is a short note for people and is never read by the app:
//!
//! * `relay`: the relay URL, `https://host[:port]/` (TLS only, no path).
//! * `region`: where it runs, free text such as `us-west` (at most [`MAX_REGION`] characters).
//! * `capacity_mbit`: the operator's estimate of what it can carry, optional.
//! * `udp`: `1` when it also answers QUIC address discovery on UDP (helps hole punching).
//! * `contact`: how to reach the operator, optional (at most [`MAX_CONTACT`] characters).
//! * `expiration` (NIP-40): when the announcement lapses, at most [`MAX_TTL_S`] after it was made;
//!   an operator refreshes it, so a relay nobody tends drops out by itself.
//!
//! A **paid** relay (`docs/PAID-RELAYS.md`) is announced with `t` = [`TOPIC_PAID`] instead of
//! [`TOPIC`], so apps that predate paid relays never see it and never make it their home relay,
//! and with two more tags:
//!
//! * `price_msat_per_gb`: what it charges a shop per GB it carries for it, in msat.
//! * `credit`: the https URL of the priced route on its operator's shop where credit is bought
//!   with Stream tickets (`<credit>/credit`; `<credit>/balance` and `<credit>/terms` are free).
//!
//! An app uses a paid relay only when its owner allows paid relays and the price is within the
//! owner's most per GB ([`Prefs::paid`], [`Prefs::max_msat_per_gb`]); otherwise it is left out
//! like a relay that does not answer, and the free relays (the default last) are the fallback.
//!
//! What an announcement does not prove: that its author runs the relay. Anyone can announce any
//! relay URL. That is acceptable because a relay never sees what it carries (the link is encrypted
//! end to end) and the app ranks relays by what it measures itself, not by what an announcement
//! says; a relay that does not answer, or answers slowly, is not used.
use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};

use crate::event::{tag, Event, Keys};

/// NIP-78: application-specific data, addressable.
pub const KIND_APP_DATA: u64 = 30078;
/// The `t` tag every relay announcement carries, and the one readers ask for.
pub const TOPIC: &str = "lightning-stream-relay";
/// The `t` tag of a paid relay's announcement, in place of [`TOPIC`].
pub const TOPIC_PAID: &str = "lightning-stream-relay-paid";
/// The `d` tag's prefix; the relay URL follows it.
pub const D_PREFIX: &str = "lightning-stream-relay:";
/// The longest an announcement lives before its operator must refresh it.
pub const MAX_TTL_S: u64 = 30 * 86_400;
/// An announcement dated further ahead than this is refused.
pub const MAX_AHEAD_S: u64 = 600;
pub const MAX_REGION: usize = 32;
pub const MAX_CONTACT: usize = 128;
pub const MAX_NOTE: usize = 280;
/// The largest announcement read.
pub const MAX_EVENT: usize = 4 * 1024;
/// A relay that failed this many probes in a row is treated as down.
pub const DOWN_AFTER: u32 = 3;

/// A relay announcement whose signature and fields all held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    pub relay: String,
    pub region: String,
    pub capacity_mbit: Option<u32>,
    pub udp: bool,
    pub contact: String,
    pub note: String,
    pub author: String,
    pub event_id: String,
    pub created_at: u64,
    pub expires: u64,
    /// A paid relay's price; `None` for a free one.
    pub price: Option<RelayPrice>,
}

/// What a paid relay charges, and where credit is bought.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPrice {
    pub msat_per_gb: u64,
    /// The https URL of the seller route (no query, no trailing `/`).
    pub credit: String,
}

/// The most a price per GB may be announced at: 1,000 sats.
pub const MAX_MSAT_PER_GB: u64 = 1_000_000;

impl RelayPrice {
    fn check(&self) -> Result<Self, String> {
        if self.msat_per_gb == 0 || self.msat_per_gb > MAX_MSAT_PER_GB {
            return Err(format!("a paid relay's price is 1 to {MAX_MSAT_PER_GB} msat per GB"));
        }
        let c = self.credit.trim().trim_end_matches('/');
        let rest = c.strip_prefix("https://").ok_or("the credit URL starts with https://")?;
        if rest.is_empty() || c.len() > 256 || c.contains(['?', '#', '@']) || c.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
            return Err("the credit URL is an https URL with no query, at most 256 characters".into());
        }
        Ok(Self { msat_per_gb: self.msat_per_gb, credit: c.to_string() })
    }
}

/// `https://host[:port][/]` in one form: lower-case host, port only when not 443, a single `/`
/// path. Anything else (another scheme, a path, a user name, a query) is refused.
pub fn canonical_relay(url: &str) -> Result<String, String> {
    let rest = url.trim().strip_prefix("https://").ok_or("a relay URL starts with https://")?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty() || rest.contains(['/', '?', '#', '@']) || rest.chars().any(|c| c.is_whitespace()) {
        return Err("a relay URL is https://host[:port] with nothing after it".into());
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => {
            let port: u16 = p.parse().map_err(|_| "the relay's port is not a number")?;
            (h.to_ascii_lowercase(), port)
        }
        _ => (rest.to_ascii_lowercase(), 443),
    };
    if host.is_empty() || !host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '[' | ']' | ':')) {
        return Err("the relay's host name has characters a host name cannot have".into());
    }
    if port == 0 {
        return Err("the relay's port cannot be 0".into());
    }
    Ok(if port == 443 { format!("https://{host}/") } else { format!("https://{host}:{port}/") })
}

/// What an operator announces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub relay: String,
    pub region: String,
    pub capacity_mbit: Option<u32>,
    pub udp: bool,
    pub contact: String,
    pub note: String,
    /// How long the announcement lives, capped at [`MAX_TTL_S`].
    pub ttl_s: u64,
    /// A paid relay's price (announced under [`TOPIC_PAID`]); `None` for a free relay.
    pub price: Option<RelayPrice>,
}

/// The announcement event for `offer`, signed by the operator's Nostr key.
pub fn announcement_event(keys: &Keys, offer: &Offer, now: u64) -> Result<Event, String> {
    let relay = canonical_relay(&offer.relay)?;
    let region = offer.region.trim();
    if region.is_empty() || region.chars().count() > MAX_REGION {
        return Err(format!("the region is 1 to {MAX_REGION} characters"));
    }
    if offer.contact.chars().count() > MAX_CONTACT {
        return Err(format!("the contact is at most {MAX_CONTACT} characters"));
    }
    if offer.note.chars().count() > MAX_NOTE {
        return Err(format!("the note is at most {MAX_NOTE} characters"));
    }
    let ttl = offer.ttl_s.clamp(3600, MAX_TTL_S);
    let price = offer.price.as_ref().map(RelayPrice::check).transpose()?;
    let mut tags = vec![
        tag("d", &format!("{D_PREFIX}{relay}")),
        tag("t", if price.is_some() { TOPIC_PAID } else { TOPIC }),
        tag("relay", &relay),
        tag("region", region),
        tag("udp", if offer.udp { "1" } else { "0" }),
        tag("expiration", &(now + ttl).to_string()),
    ];
    if let Some(c) = offer.capacity_mbit {
        tags.push(tag("capacity_mbit", &c.to_string()));
    }
    if !offer.contact.trim().is_empty() {
        tags.push(tag("contact", offer.contact.trim()));
    }
    if let Some(p) = price {
        tags.push(tag("price_msat_per_gb", &p.msat_per_gb.to_string()));
        tags.push(tag("credit", &p.credit));
    }
    Ok(Event::sign(keys, now, KIND_APP_DATA, tags, offer.note.trim().to_string()))
}

/// The filter that asks a Nostr relay for relay announcements.
pub fn filter(limit: usize) -> Value {
    json!({"kinds": [KIND_APP_DATA], "#t": [TOPIC, TOPIC_PAID], "limit": limit})
}

/// Check one announcement. `now` is the reader's clock.
pub fn read_event(ev: &Event, now: u64) -> Result<Announcement, String> {
    if ev.kind != KIND_APP_DATA {
        return Err("not an application-data event".into());
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
    let topic = |w: &str| ev.tags.iter().any(|t| t.len() >= 2 && t[0] == "t" && t[1] == w);
    let paid = topic(TOPIC_PAID);
    if !paid && !topic(TOPIC) {
        return Err("not a Stream relay announcement".into());
    }
    // a paid relay is never also announced as a free one: an app that predates paid relays would use it
    if paid && topic(TOPIC) {
        return Err("a paid relay's announcement carries the free relays' topic".into());
    }
    let price = if paid {
        let msat_per_gb = ev.tag("price_msat_per_gb").and_then(|s| s.parse::<u64>().ok()).ok_or("a paid relay without a price")?;
        Some(RelayPrice { msat_per_gb, credit: ev.tag("credit").ok_or("a paid relay without a credit URL")?.to_string() }.check()?)
    } else {
        None
    };
    let relay = canonical_relay(ev.tag("relay").ok_or("no relay URL")?)?;
    if ev.tag("d") != Some(format!("{D_PREFIX}{relay}").as_str()) {
        return Err("the event's d tag is not its relay URL".into());
    }
    let expires: u64 = ev.tag("expiration").and_then(|s| s.parse().ok()).ok_or("no expiration")?;
    if expires > ev.created_at.saturating_add(MAX_TTL_S) {
        return Err("the announcement claims to live longer than allowed".into());
    }
    if expires <= now {
        return Err("the announcement has lapsed".into());
    }
    let region = ev.tag("region").unwrap_or("").trim().to_string();
    if region.is_empty() || region.chars().count() > MAX_REGION {
        return Err("the region is missing or too long".into());
    }
    let contact = ev.tag("contact").unwrap_or("").to_string();
    if contact.chars().count() > MAX_CONTACT {
        return Err("the contact is too long".into());
    }
    let capacity_mbit = match ev.tag("capacity_mbit") {
        None => None,
        Some(s) => Some(s.parse::<u32>().map_err(|_| "the capacity is not a number")?),
    };
    let note: String = ev.content.chars().take(MAX_NOTE).collect();
    Ok(Announcement {
        relay, region, capacity_mbit, udp: ev.tag("udp") == Some("1"), contact, note,
        author: ev.pubkey.clone(), event_id: ev.id.clone(), created_at: ev.created_at, expires, price,
    })
}

/// Every good announcement among `events`, the newest per author and relay, sorted by relay URL.
/// Also how many were refused.
pub fn collect(events: &[Event], now: u64) -> (Vec<Announcement>, usize) {
    let mut best: HashMap<(String, String), Announcement> = HashMap::new();
    let mut refused = 0;
    let mut seen = HashSet::new();
    for ev in events {
        if !seen.insert(ev.id.clone()) {
            continue;
        }
        match read_event(ev, now) {
            Ok(a) => {
                let k = (a.author.clone(), a.relay.clone());
                if best.get(&k).is_none_or(|o| (a.created_at, &a.event_id) > (o.created_at, &o.event_id)) {
                    best.insert(k, a);
                }
            }
            Err(_) => refused += 1,
        }
    }
    let mut v: Vec<Announcement> = best.into_values().collect();
    v.sort_by(|a, b| a.relay.cmp(&b.relay).then(a.author.cmp(&b.author)));
    (v, refused)
}

/// What the app measured of one relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Probe {
    /// The round trip of the last probe that answered, in milliseconds.
    pub rtt_ms: Option<u32>,
    /// Probes that failed in a row since the last one that answered.
    pub fail_streak: u32,
    /// The throughput real sessions through this relay reached, in Mbit/s (the best recent
    /// sustained figure the link reported), when there was one.
    pub mbit: Option<u32>,
}

/// What a relay is chosen for: the service the connection carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Purpose {
    /// AI calls, hashrate, pages: the quickest answer wins.
    #[default]
    Latency,
    /// Video, files, VPN exits: the most it can carry wins.
    Throughput,
}

impl Purpose {
    /// The purpose for a service kind as listings name it (`video`, `file`, `vpn`: throughput).
    pub fn for_kind(kind: &str) -> Self {
        match kind {
            "video" | "media" | "file" | "files" | "vpn" | "app" => Self::Throughput,
            _ => Self::Latency,
        }
    }
}

impl Probe {
    pub fn healthy(&self) -> bool {
        self.rtt_ms.is_some() && self.fail_streak < DOWN_AFTER
    }
}

/// The owner's choices about relays.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Prefs {
    /// Relays to try first, in this order (when they answer).
    pub pinned: Vec<String>,
    /// Relays never to use.
    pub blocked: Vec<String>,
    /// The owner's own relays.
    pub own: Vec<String>,
    /// Use only the owner's own relays.
    pub only_own: bool,
    /// Paid relays may be used (the shop pays them, `docs/PAID-RELAYS.md`). Off: they are left out.
    pub paid: bool,
    /// The most per GB a paid relay may charge to be used, in msat.
    pub max_msat_per_gb: u64,
}

/// The relays to use, best first: the first one is the home relay (what iroh's `preferred_relay`
/// is set to), the rest are the relay map. At most `max` (at least 1).
///
/// * Only own: the owner's own relays, the healthy ones first by round trip, then the rest; the
///   default relay is not added (the owner chose).
/// * Otherwise: pinned relays that answer (in pin order), then every other answering relay
///   (announced or own) by round trip, then the default relay last. Relays that did not answer
///   are left out (the caller adds iroh's public relays after the list for address discovery and
///   as a fallback). Blocked relays never appear, the default included. The default relay is
///   always kept within `max` unless blocked.
///
/// Callers pass the result to the iroh link as its relay list in this order (first = home):
/// `OursThenPublic(list)`, or `Ours(list)` when `only_own`, which drops the public relays.
pub fn select(announced: &[Announcement], probes: &HashMap<String, Probe>, prefs: &Prefs, default_relay: &str, max: usize) -> Vec<String> {
    select_for(announced, probes, prefs, default_relay, max, Purpose::Latency)
}

/// [`select`], ranking the answering relays for `purpose`: by round trip for
/// [`Purpose::Latency`]; for [`Purpose::Throughput`] by what real sessions through each reached,
/// then the capacity its announcement claims, then round trip. Only answering relays are ranked,
/// and pins, blocks, only own and the default relay's place work as in [`select`].
pub fn select_for(announced: &[Announcement], probes: &HashMap<String, Probe>, prefs: &Prefs, default_relay: &str, max: usize, purpose: Purpose) -> Vec<String> {
    let max = max.max(1);
    let claimed: HashMap<&str, u32> = announced.iter().filter_map(|a| a.capacity_mbit.map(|c| (a.relay.as_str(), c))).collect();
    let canon = |u: &str| canonical_relay(u).ok();
    let mut blocked: HashSet<String> = prefs.blocked.iter().filter_map(|u| canon(u)).collect();
    // a paid relay the owner doesn't pay for, or not at its price, is as good as blocked; the owner's
    // own relays are never left out for a price (any announcement of them is someone else's word)
    let own_set: HashSet<String> = prefs.own.iter().filter_map(|u| canon(u)).collect();
    let price: HashMap<&str, u64> = announced.iter().filter_map(|a| a.price.as_ref().map(|p| (a.relay.as_str(), p.msat_per_gb))).collect();
    for (u, p) in &price {
        if !own_set.contains(*u) && (!prefs.paid || *p > prefs.max_msat_per_gb) {
            blocked.insert(u.to_string());
        }
    }
    let cost = |u: &str| price.get(u).copied().unwrap_or(0);
    let probe = |u: &str| probes.get(u).copied().unwrap_or_default();
    let by_rtt = |v: &mut Vec<String>| match purpose {
        Purpose::Latency => v.sort_by_key(|u| (probe(u).rtt_ms.unwrap_or(u32::MAX), cost(u), u.clone())),
        // most measured first, then most claimed, then quickest
        Purpose::Throughput => v.sort_by_key(|u| {
            let p = probe(u);
            (std::cmp::Reverse(p.mbit.unwrap_or(0)), std::cmp::Reverse(claimed.get(u.as_str()).copied().unwrap_or(0)), p.rtt_ms.unwrap_or(u32::MAX), cost(u), u.clone())
        }),
    };
    let mut out: Vec<String> = Vec::new();
    let push = |out: &mut Vec<String>, u: String| {
        if !blocked.contains(&u) && !out.contains(&u) {
            out.push(u);
        }
    };
    let own: Vec<String> = prefs.own.iter().filter_map(|u| canon(u)).collect();
    if prefs.only_own && !own.is_empty() {
        let (mut up, mut down): (Vec<String>, Vec<String>) = own.into_iter().partition(|u| probe(u).healthy());
        by_rtt(&mut up);
        down.sort();
        for u in up.into_iter().chain(down) {
            push(&mut out, u);
        }
        out.truncate(max);
        return out;
    }
    let pinned: Vec<String> = prefs.pinned.iter().filter_map(|u| canon(u)).collect();
    for u in pinned.iter().filter(|u| probe(u).healthy()) {
        push(&mut out, u.clone());
    }
    let mut others: Vec<String> = announced.iter().map(|a| a.relay.clone()).chain(own.iter().cloned())
        .filter(|u| probe(u).healthy() && !pinned.contains(u)).collect();
    others.sort();
    others.dedup();
    by_rtt(&mut others);
    for u in others {
        push(&mut out, u);
    }
    let default = canon(default_relay);
    if let Some(d) = &default {
        out.retain(|u| u != d);
        push(&mut out, d.clone());
    }
    if out.len() > max {
        let keep_default = default.as_ref().filter(|d| out.iter().position(|u| u == *d).is_some_and(|i| i >= max));
        out.truncate(max);
        if let Some(d) = keep_default {
            out.pop();
            out.push(d.clone());
        }
    }
    out
}

/// Probe a relay the way an iroh endpoint first reaches it: a WebSocket upgrade on `/relay` with
/// the `iroh-relay-v1` sub-protocol, over TLS. `Ok` with the time to the `101` answer, in
/// milliseconds; the connection is closed right after, so nothing is relayed.
pub fn probe(relay: &str, timeout: std::time::Duration) -> Result<u32, String> {
    let r = canonical_relay(relay)?;
    let wss = format!("wss://{}relay", r.trim_start_matches("https://"));
    let t0 = std::time::Instant::now();
    let ws = crate::ws::WebSocket::connect_with_protocol(&wss, Some(IROH_RELAY_PROTOCOL), timeout).map_err(|e| e.to_string())?;
    let ms = t0.elapsed().as_millis().min(u32::MAX as u128) as u32;
    ws.shutdown();
    Ok(ms)
}

/// The WebSocket sub-protocol iroh relays speak.
pub const IROH_RELAY_PROTOCOL: &str = "iroh-relay-v1";

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn offer(relay: &str) -> Offer {
        Offer { relay: relay.into(), region: "us-west".into(), capacity_mbit: Some(500), udp: true, contact: "ops@example.com".into(),
                note: "A relay for Stream.".into(), ttl_s: 7 * 86_400, price: None }
    }

    fn paid_ann(relay: &str, msat_per_gb: u64) -> Announcement {
        let k = Keys::generate();
        let o = Offer { price: Some(RelayPrice { msat_per_gb, credit: "https://ops.example.com/stream-relay/".into() }), ..offer(relay) };
        read_event(&announcement_event(&k, &o, NOW).unwrap(), NOW).unwrap()
    }

    #[test]
    fn a_paid_relay_is_announced_apart() {
        let k = Keys::generate();
        let o = Offer { price: Some(RelayPrice { msat_per_gb: 2_000, credit: "https://ops.example.com/stream-relay/".into() }), ..offer("https://paid.example.com") };
        let ev = announcement_event(&k, &o, NOW).unwrap();
        // not under the free topic: an app that predates paid relays never reads it
        assert_eq!(ev.tag("t"), Some(TOPIC_PAID));
        let a = read_event(&ev, NOW).unwrap();
        assert_eq!(a.price, Some(RelayPrice { msat_per_gb: 2_000, credit: "https://ops.example.com/stream-relay".into() }));
        assert_eq!(ann("https://free.example.com").price, None);
        // a paid announcement without a price, or also under the free topic, is refused
        let no_price: Vec<_> = ev.tags.iter().filter(|t| t[0] != "price_msat_per_gb").cloned().collect();
        assert!(read_event(&Event::sign(&k, NOW, KIND_APP_DATA, no_price, String::new()), NOW).unwrap_err().contains("price"));
        let mut both = ev.tags.clone();
        both.push(tag("t", TOPIC));
        assert!(read_event(&Event::sign(&k, NOW, KIND_APP_DATA, both, String::new()), NOW).is_err());
        // bad prices and credit URLs are refused when made
        for p in [RelayPrice { msat_per_gb: 0, credit: "https://a.example.com".into() }, RelayPrice { msat_per_gb: 1, credit: "http://a.example.com".into() },
                  RelayPrice { msat_per_gb: MAX_MSAT_PER_GB + 1, credit: "https://a.example.com".into() }] {
            assert!(announcement_event(&k, &Offer { price: Some(p), ..offer("https://a.example.com") }, NOW).is_err());
        }
        assert_eq!(filter(5)["#t"], json!([TOPIC, TOPIC_PAID]));
    }

    #[test]
    fn paid_relays_are_used_only_when_the_owner_pays_and_the_price_is_right() {
        let a = [paid_ann("https://cheap.example.com", 1_000), paid_ann("https://dear.example.com", 9_000), ann("https://free.example.com")];
        let p = probes(&[("https://cheap.example.com", Some(10), 0), ("https://dear.example.com", Some(5), 0), ("https://free.example.com", Some(50), 0)]);
        // by default: no paid relay, the free ones as before
        assert_eq!(select(&a, &p, &Prefs::default(), OURS, 4), vec!["https://free.example.com/", "https://iroh.lazarus-xbt.xyz/"]);
        // paying up to 2 sats a GB: the cheap one, the free ones and ours still behind it as the fallback
        let prefs = Prefs { paid: true, max_msat_per_gb: 2_000, ..Prefs::default() };
        assert_eq!(select(&a, &p, &prefs, OURS, 4), vec!["https://cheap.example.com/", "https://free.example.com/", "https://iroh.lazarus-xbt.xyz/"]);
        // the owner's own relay is never left out for its price
        let prefs = Prefs { own: vec!["https://dear.example.com".into()], ..Prefs::default() };
        assert_eq!(select(&a, &p, &prefs, OURS, 4)[0], "https://dear.example.com/");
        // at the same round trip, the cheaper first
        let b = [paid_ann("https://b.example.com", 1_500), paid_ann("https://a.example.com", 1_800)];
        let p = probes(&[("https://a.example.com", Some(10), 0), ("https://b.example.com", Some(10), 0)]);
        let prefs = Prefs { paid: true, max_msat_per_gb: 2_000, ..Prefs::default() };
        assert_eq!(select(&b, &p, &prefs, OURS, 4)[0], "https://b.example.com/");
    }

    fn ann(relay: &str) -> Announcement {
        let k = Keys::generate();
        read_event(&announcement_event(&k, &offer(relay), NOW).unwrap(), NOW).unwrap()
    }

    #[test]
    fn canonical_urls() {
        assert_eq!(canonical_relay("https://Relay.Example.com").unwrap(), "https://relay.example.com/");
        assert_eq!(canonical_relay("https://relay.example.com:443/").unwrap(), "https://relay.example.com/");
        assert_eq!(canonical_relay("https://relay.example.com:8443").unwrap(), "https://relay.example.com:8443/");
        for bad in ["http://relay.example.com", "https://relay.example.com/x", "https://user@relay.example.com", "https://", "https://a b",
                    "https://relay.example.com:x", "https://relay.example.com?q", "wss://relay.example.com"] {
            assert!(canonical_relay(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn announce_and_read_back() {
        let k = Keys::generate();
        let ev = announcement_event(&k, &offer("https://Relay.Example.com/"), NOW).unwrap();
        let a = read_event(&Event::from_value(&ev.to_value()).unwrap(), NOW + 60).unwrap();
        assert_eq!(a.relay, "https://relay.example.com/");
        assert_eq!((a.region.as_str(), a.capacity_mbit, a.udp), ("us-west", Some(500), true));
        assert_eq!(a.contact, "ops@example.com");
        assert_eq!(a.author, k.public_hex());
        assert_eq!(a.expires, NOW + 7 * 86_400);
        assert_eq!(ev.tag("d"), Some("lightning-stream-relay:https://relay.example.com/"));
    }

    #[test]
    fn bad_announcements_are_refused() {
        let k = Keys::generate();
        let good = announcement_event(&k, &offer("https://relay.example.com"), NOW).unwrap();
        // tampered content breaks the id
        let mut e = good.clone();
        e.content.push('!');
        assert!(read_event(&e, NOW).is_err());
        // re-signed with a d tag that names another relay
        let mut tags = good.tags.clone();
        tags[0] = tag("d", &format!("{D_PREFIX}https://other.example.com/"));
        assert!(read_event(&Event::sign(&k, NOW, KIND_APP_DATA, tags, String::new()), NOW).unwrap_err().contains("d tag"));
        // lapsed, and dated ahead
        assert!(read_event(&good, NOW + 8 * 86_400).unwrap_err().contains("lapsed"));
        let ahead = announcement_event(&k, &offer("https://relay.example.com"), NOW + 3600).unwrap();
        assert!(read_event(&ahead, NOW).unwrap_err().contains("future"));
        // an expiration past the allowed life
        let mut tags = good.tags.clone();
        let i = tags.iter().position(|t| t[0] == "expiration").unwrap();
        tags[i] = tag("expiration", &(NOW + MAX_TTL_S + 1).to_string());
        assert!(read_event(&Event::sign(&k, NOW, KIND_APP_DATA, tags, String::new()), NOW).unwrap_err().contains("longer"));
        // no topic, wrong kind
        let tags: Vec<_> = good.tags.iter().filter(|t| t[0] != "t").cloned().collect();
        assert!(read_event(&Event::sign(&k, NOW, KIND_APP_DATA, tags, String::new()), NOW).is_err());
        assert!(read_event(&Event::sign(&k, NOW, 1, good.tags.clone(), String::new()), NOW).is_err());
        // bad fields are refused when made, too
        let mut o = offer("https://relay.example.com");
        o.region = "x".repeat(MAX_REGION + 1);
        assert!(announcement_event(&k, &o, NOW).is_err());
        assert!(announcement_event(&k, &offer("http://relay.example.com"), NOW).is_err());
    }

    #[test]
    fn collect_keeps_the_newest_per_author_and_relay() {
        let k = Keys::generate();
        let old = announcement_event(&k, &offer("https://relay.example.com"), NOW).unwrap();
        let mut o = offer("https://relay.example.com");
        o.region = "eu-central".into();
        let new = announcement_event(&k, &o, NOW + 10).unwrap();
        let mut junk = new.clone();
        junk.content.push('!');
        junk.id = "ab".repeat(32);
        let (v, refused) = collect(&[old, new.clone(), new, junk], NOW + 20);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].region, "eu-central");
        assert_eq!(refused, 1);
    }

    fn probes(list: &[(&str, Option<u32>, u32)]) -> HashMap<String, Probe> {
        list.iter().map(|(u, rtt, f)| (canonical_relay(u).unwrap(), Probe { rtt_ms: *rtt, fail_streak: *f, mbit: None })).collect()
    }

    const OURS: &str = "https://iroh.lazarus-xbt.xyz";

    #[test]
    fn nearest_healthy_first_then_the_default() {
        let a = [ann("https://far.example.com"), ann("https://near.example.com"), ann("https://dead.example.com")];
        let p = probes(&[("https://far.example.com", Some(180), 0), ("https://near.example.com", Some(20), 0),
                         ("https://dead.example.com", None, 5), (OURS, Some(60), 0)]);
        let v = select(&a, &p, &Prefs::default(), OURS, 5);
        // the default goes last, even when it answers faster than an announced relay; a dead relay is left out
        assert_eq!(v, vec!["https://near.example.com/", "https://far.example.com/", "https://iroh.lazarus-xbt.xyz/"]);
    }

    #[test]
    fn pins_blocks_and_the_default_within_max() {
        let a = [ann("https://a.example.com"), ann("https://b.example.com"), ann("https://c.example.com")];
        let p = probes(&[("https://a.example.com", Some(10), 0), ("https://b.example.com", Some(20), 0), ("https://c.example.com", Some(30), 0)]);
        let prefs = Prefs { pinned: vec!["https://c.example.com".into()], blocked: vec!["https://a.example.com/".into()], ..Prefs::default() };
        let v = select(&a, &p, &prefs, OURS, 2);
        // pinned first; a is blocked; the default keeps its place within max
        assert_eq!(v, vec!["https://c.example.com/", "https://iroh.lazarus-xbt.xyz/"]);
        // blocking the default removes it
        let prefs = Prefs { blocked: vec![OURS.into()], ..Prefs::default() };
        assert!(!select(&a, &p, &prefs, OURS, 5).contains(&"https://iroh.lazarus-xbt.xyz/".to_string()));
        // a pinned relay that does not answer is left out
        let prefs = Prefs { pinned: vec!["https://gone.example.com".into()], ..Prefs::default() };
        let v = select(&a, &p, &prefs, OURS, 10);
        assert!(!v.contains(&"https://gone.example.com/".to_string()));
        assert_eq!(v[0], "https://a.example.com/");
        assert_eq!(v.last().unwrap(), "https://iroh.lazarus-xbt.xyz/");
    }

    #[test]
    fn only_own_ignores_the_rest() {
        let a = [ann("https://a.example.com")];
        let p = probes(&[("https://a.example.com", Some(5), 0), ("https://mine.example.com", Some(50), 0), ("https://mine2.example.com", None, 4)]);
        let prefs = Prefs { own: vec!["https://mine2.example.com".into(), "https://mine.example.com".into()], only_own: true, ..Prefs::default() };
        assert_eq!(select(&a, &p, &prefs, OURS, 5), vec!["https://mine.example.com/", "https://mine2.example.com/"]);
        // only own with none set falls back to the normal choice
        let prefs = Prefs { only_own: true, ..Prefs::default() };
        assert_eq!(select(&a, &p, &prefs, OURS, 5)[0], "https://a.example.com/");
    }

    /// Reaches out to a real relay: `XBT_RELAY_PROBE=https://iroh.example.com cargo test -p xbt-nostr probe_a_real_relay -- --ignored`.
    #[test]
    #[ignore]
    fn probe_a_real_relay() {
        let Ok(url) = std::env::var("XBT_RELAY_PROBE") else { return };
        let ms = probe(&url, std::time::Duration::from_secs(10)).unwrap();
        eprintln!("{url}: {ms} ms");
        assert!(probe("https://example.com", std::time::Duration::from_secs(10)).is_err());
    }

    #[test]
    fn video_ranks_by_throughput_and_ai_by_latency() {
        let mut fat = ann("https://fat.example.com");
        fat.capacity_mbit = Some(1000);
        let mut thin = ann("https://thin.example.com");
        thin.capacity_mbit = Some(100);
        let measured = ann("https://measured.example.com");
        let mut p = probes(&[("https://fat.example.com", Some(90), 0), ("https://thin.example.com", Some(10), 0),
                             ("https://measured.example.com", Some(60), 0)]);
        p.get_mut("https://measured.example.com/").unwrap().mbit = Some(400);
        let a = [fat, thin, measured];
        // latency: the quickest answer first
        assert_eq!(select_for(&a, &p, &Prefs::default(), OURS, 4, Purpose::Latency)[0], "https://thin.example.com/");
        // throughput: what sessions reached beats what is claimed, which beats round trip
        assert_eq!(select_for(&a, &p, &Prefs::default(), OURS, 4, Purpose::Throughput)[..3],
                   ["https://measured.example.com/", "https://fat.example.com/", "https://thin.example.com/"]);
        assert_eq!(Purpose::for_kind("video"), Purpose::Throughput);
        assert_eq!(Purpose::for_kind("ai"), Purpose::Latency);
        assert_eq!(Purpose::for_kind("hashrate"), Purpose::Latency);
    }

    #[test]
    fn nothing_known_is_the_default_alone() {
        assert_eq!(select(&[], &HashMap::new(), &Prefs::default(), OURS, 3), vec!["https://iroh.lazarus-xbt.xyz/"]);
    }
}
