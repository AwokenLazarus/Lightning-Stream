//! Exits announce themselves on Nostr, and buyers find them there.
//!
//! An announcement is a NIP-78 application-data event (kind 30078, addressable: one per author and
//! `d`), with `d` = `lightning-stream-vpn-exit:<exit key>` and `t` = [`TOPIC`]. Its tags say what a
//! buyer's policy is checked against; its `content` is a short note for people, never read by the app:
//!
//! * `exit`: the exit's link key (64 hex), the key a buyer connects to.
//! * `link_sig`: the exit link key's Ed25519 signature over [`binding`], tying this Nostr key to the
//!   exit: only whoever holds the exit's key can announce it.
//! * `region`: the country the operator says the exit is in (two letters). A buyer verifies it
//!   itself ([`crate::region`]) before a policy that names a country uses the exit.
//! * `kind`: `private` or `filtered`; `category` (repeated): what a filtered exit blocks.
//! * `logs`: `0` (no logs of buyers' destinations, the default) or `1`.
//! * `port` (repeated): destination ports the exit refuses.
//! * `two_hop`: `1` when the exit takes buyers through a first hop.
//! * `price_msat_gb`: the price of a GB, in millisatoshis.
//! * `relay`: the iroh relay the exit is reachable through, optional.
//! * `expiration` (NIP-40): at most [`MAX_TTL_S`] after it was made; the exit refreshes it, so an exit
//!   nobody runs drops out by itself.
//!
//! What an announcement proves: that its author holds the exit's key. What it does not prove: the
//! region, the speed or the no-logs claim. The region is verified by the buyer, speed is measured,
//! and the no-logs claim is the operator's word, shown as such.

use serde_json::{json, Value};
use xbt_nostr::event::{tag, Event, Keys};

use crate::router::ExitInfo;

/// NIP-78: application-specific data, addressable.
pub const KIND_APP_DATA: u64 = 30078;
/// The `t` tag every exit announcement carries.
pub const TOPIC: &str = "lightning-stream-vpn-exit";
/// The `d` tag's prefix; the exit's key follows.
pub const D_PREFIX: &str = "lightning-stream-vpn-exit:";
/// The longest an announcement may live: an exit refreshes it well before.
pub const MAX_TTL_S: u64 = 7 * 86_400;
/// How far ahead of the reader's clock an announcement may be dated.
pub const MAX_AHEAD_S: u64 = 600;
/// The largest announcement read.
pub const MAX_EVENT: usize = 4 * 1024;
const MAX_NOTE: usize = 280;
const MAX_LIST: usize = 32;

/// What an exit's operator announces.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExitOffer {
    /// The exit's link key (64 hex).
    pub exit: String,
    pub region: String,
    pub filtered: bool,
    pub categories: Vec<String>,
    pub logs: bool,
    pub blocked_ports: Vec<u16>,
    pub two_hop: bool,
    pub price_msat_per_gb: u64,
    pub relay: Option<String>,
    /// Where a buyer's wallet opens the paid tunnel to this exit: a URL on the operator's Stream
    /// shop (`https://<shop>/vpn/tunnel`), paid as it is used like any of the shop's services.
    pub tunnel: Option<String>,
    pub note: String,
    /// How long the announcement lives, capped at [`MAX_TTL_S`].
    pub ttl_s: u64,
}

/// What the exit's link key signs: the Nostr key that announces it, and the exit's own key.
pub fn binding(nostr_pubkey_hex: &str, exit_hex: &str) -> Vec<u8> {
    format!("lightning-stream-vpn-exit/v1\n{nostr_pubkey_hex}\n{exit_hex}").into_bytes()
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// The announcement for `offer`, signed by the operator's Nostr key, with the exit's link key
/// (`exit_secret`, the seed of its Ed25519 key) vouching for that Nostr key.
pub fn announcement_event(keys: &Keys, exit_secret: &[u8; 32], offer: &ExitOffer, now: u64) -> Result<Event, String> {
    let exit = hex::encode(crate::sealed::public_of(exit_secret));
    if offer.exit != exit {
        return Err("the offer names another exit than the key signing it".into());
    }
    let region = offer.region.trim().to_ascii_uppercase();
    if region.len() != 2 || !region.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err("the region is a two-letter country code".into());
    }
    if offer.categories.len() > MAX_LIST || offer.blocked_ports.len() > MAX_LIST {
        return Err(format!("at most {MAX_LIST} categories and {MAX_LIST} ports"));
    }
    let kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(exit_secret).map_err(|_| "an exit key that is not a key")?;
    let sig = kp.sign(&binding(&keys.public_hex(), &exit));
    let ttl = offer.ttl_s.clamp(3600, MAX_TTL_S);
    let mut tags = vec![
        tag("d", &format!("{D_PREFIX}{exit}")),
        tag("t", TOPIC),
        tag("exit", &exit),
        tag("link_sig", &hex::encode(sig.as_ref())),
        tag("region", &region),
        tag("kind", if offer.filtered { "filtered" } else { "private" }),
        tag("logs", if offer.logs { "1" } else { "0" }),
        tag("two_hop", if offer.two_hop { "1" } else { "0" }),
        tag("price_msat_gb", &offer.price_msat_per_gb.to_string()),
        tag("expiration", &(now + ttl).to_string()),
    ];
    if offer.filtered {
        tags.extend(offer.categories.iter().map(|c| tag("category", c)));
    }
    tags.extend(offer.blocked_ports.iter().map(|p| tag("port", &p.to_string())));
    if let Some(r) = &offer.relay {
        tags.push(tag("relay", r));
    }
    if let Some(t) = &offer.tunnel {
        if !(t.starts_with("https://") || t.starts_with("http://")) || t.len() > 512 {
            return Err("the tunnel is an http(s) URL on the operator's shop".into());
        }
        tags.push(tag("tunnel", t));
    }
    let note: String = offer.note.trim().chars().take(MAX_NOTE).collect();
    Ok(Event::sign(keys, now, KIND_APP_DATA, tags, note))
}

/// The filter that asks a Nostr relay for exit announcements.
pub fn filter(limit: usize) -> Value {
    json!({"kinds": [KIND_APP_DATA], "#t": [TOPIC], "limit": limit})
}

/// An exit announcement whose signatures and fields all held.
#[derive(Clone, Debug, PartialEq)]
pub struct Announced {
    pub exit: ExitInfo,
    /// The iroh relay the exit is reachable through, if it says.
    pub relay: Option<String>,
    /// Where the buyer's wallet opens the paid tunnel ([`ExitOffer::tunnel`]); `None`: the exit
    /// is reached straight over the link, which only a free exit is.
    pub tunnel: Option<String>,
    pub author: String,
    pub created_at: u64,
}

/// Checks one announcement. `now` is the reader's clock. The region comes back unverified: the
/// buyer verifies it itself before a policy that names a country uses the exit.
pub fn read_event(ev: &Event, now: u64) -> Result<Announced, String> {
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
    if !ev.tags.iter().any(|t| t.len() >= 2 && t[0] == "t" && t[1] == TOPIC) {
        return Err("not a Stream exit announcement".into());
    }
    let exit = ev.tag("exit").ok_or("no exit key")?.to_string();
    if !is_hex64(&exit) {
        return Err("the exit key is not 64 lower-case hex".into());
    }
    if ev.tag("d") != Some(format!("{D_PREFIX}{exit}").as_str()) {
        return Err("the event's d tag is not its exit key".into());
    }
    let sig = hex::decode(ev.tag("link_sig").ok_or("no link signature")?).map_err(|_| "the link signature is not hex")?;
    let exit_key = hex::decode(&exit).map_err(|_| "the exit key is not hex")?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &exit_key)
        .verify(&binding(&ev.pubkey, &exit), &sig)
        .map_err(|_| "the exit's key did not vouch for this author")?;
    let expires: u64 = ev.tag("expiration").and_then(|s| s.parse().ok()).ok_or("no expiration")?;
    if expires > ev.created_at.saturating_add(MAX_TTL_S) {
        return Err("the announcement claims to live longer than allowed".into());
    }
    if expires <= now {
        return Err("the announcement has lapsed".into());
    }
    let region = ev.tag("region").unwrap_or("").to_string();
    if region.len() != 2 || !region.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err("the region is not a two-letter country code".into());
    }
    let filtered = match ev.tag("kind") {
        Some("private") => false,
        Some("filtered") => true,
        _ => return Err("the kind is neither private nor filtered".into()),
    };
    let all = |name: &str| ev.tags.iter().filter(|t| t.len() >= 2 && t[0] == name).map(|t| t[1].clone()).collect::<Vec<_>>();
    let categories = all("category");
    let ports: Vec<u16> = all("port").iter().map(|p| p.parse::<u16>().map_err(|_| "a port is not a number")).collect::<Result<_, _>>()?;
    if categories.len() > MAX_LIST || ports.len() > MAX_LIST {
        return Err("too many categories or ports".into());
    }
    let price_msat_per_gb: u64 = ev.tag("price_msat_gb").and_then(|s| s.parse().ok()).ok_or("no price")?;
    let info = ExitInfo {
        id: exit,
        operator: ev.pubkey.clone(),
        region,
        region_verified: false,
        price_msat_per_gb,
        rtt_ms: None,
        mbit_s: None,
        healthy: true,
        filtered,
        categories,
        logs: ev.tag("logs") == Some("1"),
        blocked_ports: ports,
        two_hop: ev.tag("two_hop") == Some("1"),
    };
    let tunnel = ev.tag("tunnel").filter(|t| (t.starts_with("https://") || t.starts_with("http://")) && t.len() <= 512).map(str::to_string);
    Ok(Announced { exit: info, relay: ev.tag("relay").map(str::to_string), tunnel, author: ev.pubkey.clone(), created_at: ev.created_at })
}

/// Every good announcement among `events`, the newest per exit (an exit is announced by whoever its
/// key vouched for last), and how many were refused.
pub fn collect(events: &[Event], now: u64) -> (Vec<Announced>, usize) {
    let mut best: std::collections::HashMap<String, Announced> = std::collections::HashMap::new();
    let mut refused = 0;
    let mut seen = std::collections::HashSet::new();
    for ev in events {
        if !seen.insert(ev.id.clone()) {
            continue;
        }
        match read_event(ev, now) {
            Ok(a) => {
                if best.get(&a.exit.id).is_none_or(|o| a.created_at > o.created_at) {
                    best.insert(a.exit.id.clone(), a);
                }
            }
            Err(_) => refused += 1,
        }
    }
    let mut out: Vec<Announced> = best.into_values().collect();
    out.sort_by(|a, b| a.exit.id.cmp(&b.exit.id));
    (out, refused)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(exit_secret: &[u8; 32]) -> ExitOffer {
        ExitOffer {
            exit: hex::encode(crate::sealed::public_of(exit_secret)),
            region: "de".into(),
            filtered: true,
            categories: vec!["adult".into(), "malware".into()],
            blocked_ports: vec![25, 465],
            price_msat_per_gb: 20_000,
            relay: Some("https://iroh.example/".into()),
            ttl_s: 86_400,
            ..ExitOffer::default()
        }
    }

    #[test]
    fn an_announcement_reads_back_as_the_exit_it_announces() {
        let (keys, secret, now) = (Keys::generate(), [7u8; 32], 1_800_000_000);
        let ev = announcement_event(&keys, &secret, &offer(&secret), now).unwrap();
        let a = read_event(&ev, now).unwrap();
        assert_eq!(a.exit.id, hex::encode(crate::sealed::public_of(&secret)));
        assert_eq!(a.exit.operator, keys.public_hex());
        assert_eq!(a.exit.region, "DE");
        assert!(!a.exit.region_verified, "a region is only ever verified by the buyer");
        assert!(a.exit.filtered && a.exit.categories == ["adult", "malware"] && a.exit.blocked_ports == [25, 465]);
        assert!(!a.exit.logs && !a.exit.two_hop && a.exit.price_msat_per_gb == 20_000);
        assert_eq!(a.relay.as_deref(), Some("https://iroh.example/"));
    }

    #[test]
    fn only_the_exits_own_key_can_announce_it() {
        let (keys, secret, now) = (Keys::generate(), [8u8; 32], 1_800_000_000);
        // signing an offer for another exit's key is refused outright
        let mut other = offer(&secret);
        other.exit = hex::encode(crate::sealed::public_of(&[9u8; 32]));
        assert!(announcement_event(&keys, &secret, &other, now).is_err());
        // a valid announcement re-signed by a different Nostr key no longer has the exit's vouching
        let ev = announcement_event(&keys, &secret, &offer(&secret), now).unwrap();
        let thief = Keys::generate();
        let forged = Event::sign(&thief, ev.created_at, ev.kind, ev.tags.clone(), ev.content.clone());
        assert_eq!(read_event(&forged, now).unwrap_err(), "the exit's key did not vouch for this author");
    }

    #[test]
    fn lapsed_future_or_malformed_announcements_are_refused() {
        let (keys, secret, now) = (Keys::generate(), [10u8; 32], 1_800_000_000);
        let ev = announcement_event(&keys, &secret, &offer(&secret), now).unwrap();
        assert!(read_event(&ev, now + 86_400 + 1).is_err(), "lapsed");
        assert!(read_event(&ev, now - MAX_AHEAD_S - 1).is_err(), "dated in the future");
        let mut bad = offer(&secret);
        bad.region = "Germany".into();
        assert!(announcement_event(&keys, &secret, &bad, now).is_err());
        let retag = |name: &str, value: &str| {
            let tags: Vec<Vec<String>> = ev.tags.iter().map(|t| if t[0] == name { tag(name, value) } else { t.clone() }).collect();
            Event::sign(&keys, ev.created_at, ev.kind, tags, String::new())
        };
        assert!(read_event(&retag("kind", "open"), now).is_err());
        assert!(read_event(&retag("expiration", &(now + MAX_TTL_S + 10).to_string()), now).is_err());
        assert!(read_event(&retag("d", "lightning-stream-vpn-exit:00"), now).is_err());
    }

    #[test]
    fn the_newest_announcement_of_each_exit_is_kept() {
        let (keys, secret, now) = (Keys::generate(), [11u8; 32], 1_800_000_000);
        let old = announcement_event(&keys, &secret, &offer(&secret), now - 100).unwrap();
        let mut cheaper = offer(&secret);
        cheaper.price_msat_per_gb = 10_000;
        let new = announcement_event(&keys, &secret, &cheaper, now).unwrap();
        let junk = Event::sign(&keys, now, KIND_APP_DATA, vec![tag("t", TOPIC)], String::new());
        let (got, refused) = collect(&[old, new.clone(), new, junk], now);
        assert_eq!(refused, 1);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].exit.price_msat_per_gb, 10_000);
    }
}
