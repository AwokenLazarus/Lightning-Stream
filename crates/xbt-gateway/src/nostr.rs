//! The listing on Nostr (`docs/NOSTR.md`): the gateway sends its signed listing to the runner's
//! relays as a NIP-99 classified listing at start and every `nostr.republish_s` after, signed by a
//! Nostr key of its own (`nostr.key` in the state directory) that the receipt key binds to this
//! seller. Nothing is read from the relays, and a relay that refuses or is down is only logged.
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use xbt_nostr::event::{tag, Event, Keys};
use xbt_nostr::market;
use xbt_nostr::oneshot::{self, Outcome};

use crate::config::NostrConfig;
use crate::gateway::Gateway;

/// Each relay gets this long to answer one publish.
pub const PUBLISH_WAIT: Duration = Duration::from_secs(15);

/// The gateway's Nostr key: `nostr.key` in the state directory, made on first use (0600).
pub fn load_key(state_dir: &std::path::Path) -> Result<Keys, String> {
    let sk = xbt402::provider::load_or_create_secret(&state_dir.join("nostr.key")).map_err(|e| e.to_string())?;
    Keys::from_hex(&hex::encode(sk.secret_bytes())).ok_or_else(|| "nostr.key is not a key".into())
}

/// Each relay gets this long to list the gateway's own listings, for [`withdraw_left_behind`].
pub const QUERY_WAIT: Duration = Duration::from_secs(10);

/// Sign the listing as it is now and send it to `relays` once. `now` dates the event. Then withdraw
/// any listing this key left on them for another address ([`withdraw_left_behind`]).
pub fn publish_once(gw: &Gateway, keys: &Keys, relays: &[String], now: u64) -> Result<Vec<Outcome>, String> {
    let doc = gw.listing().ok_or("the gateway has no listing")?;
    let bind = gw.bind_nostr(&keys.public.serialize());
    let ev = market::listing_event_with(keys, &doc, &bind, gw.transport().as_ref(), now)?;
    let out = oneshot::publish(relays, &ev, PUBLISH_WAIT);
    let seller = xbt402::listing::verify_self(&doc).map(|l| xbt402::wire::canonical_origin(&l.seller))?;
    match withdraw_left_behind(keys, relays, &seller, now) {
        Ok(gone) if !gone.is_empty() => eprintln!("xbt-gateway: withdrew this shop's listing at {} on Nostr: it lists itself at {seller} now", gone.join(", ")),
        Ok(_) => {}
        Err(e) => eprintln!("xbt-gateway: an old listing was not withdrawn on Nostr: {e}"),
    }
    Ok(out)
}

/// A shop that changes its address, or how buyers reach it (its web address, then its key when it
/// turns Private), lists itself under the new one: the listing is addressed by its seller, so the old
/// one stayed on the relays beside it, and buyers saw the shop twice, once at an address that no
/// longer sells (#40). This asks `relays` for the listings this key signed, and withdraws those for any
/// other seller than `current` with a NIP-09 deletion signed by the same key. `Ok`: the old sellers
/// withdrawn (none: nothing to do). Asked again at each publish, for a relay that missed it.
pub fn withdraw_left_behind(keys: &Keys, relays: &[String], current: &str, now: u64) -> Result<Vec<String>, String> {
    let (events, _) = oneshot::query(relays, &own_filter(&keys.public_hex()), QUERY_WAIT);
    let old = left_behind(&events, &keys.public_hex(), current, now);
    if old.is_empty() {
        return Ok(vec![]);
    }
    let out = oneshot::publish(relays, &withdrawal_event(keys, &old, now), PUBLISH_WAIT);
    if !out.iter().any(|o| o.result.is_ok()) {
        return Err(out.iter().filter_map(|o| o.result.as_ref().err().map(|e| format!("{}: {e}", o.relay))).collect::<Vec<_>>().join("; "));
    }
    Ok(old.into_iter().map(|(d, _)| d).collect())
}

/// NIP-09: a request to delete events, by their ids (`e`) or their address (`a`).
pub const KIND_DELETION: u64 = 5;

/// The filter that asks a relay for the Lightning Stream listings `author` (hex) signed.
pub fn own_filter(author: &str) -> serde_json::Value {
    serde_json::json!({"kinds": [market::KIND_CLASSIFIED], "authors": [author], "#t": [market::TOPIC], "limit": 50})
}

/// The listings among `events` that `author` signed for another seller than `current` (a canonical
/// origin): what a shop left behind when it moved, or changed how buyers reach it (a web address,
/// then its key). Each by its `d` (the old seller), with the ids of its events, sorted.
pub fn left_behind(events: &[Event], author: &str, current: &str, now: u64) -> Vec<(String, Vec<String>)> {
    let mut old: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for ev in events.iter().filter(|e| e.pubkey == author) {
        let Ok(n) = market::read_event(ev, now) else { continue };
        let d = xbt402::wire::canonical_origin(&n.listing.seller);
        if d != current {
            let ids = old.entry(d).or_default();
            if !ids.contains(&ev.id) {
                ids.push(ev.id.clone());
            }
        }
    }
    old.into_iter().collect()
}

/// A NIP-09 deletion of the listings `old` names ([`left_behind`]), signed by the key that published
/// them: each by its address (`30402:<author>:<d>`, every version up to now) and by its event ids.
pub fn withdrawal_event(keys: &Keys, old: &[(String, Vec<String>)], created_at: u64) -> Event {
    let author = keys.public_hex();
    let mut tags = Vec::new();
    for (d, ids) in old {
        tags.push(tag("a", &format!("{}:{author}:{d}", market::KIND_CLASSIFIED)));
        for id in ids {
            tags.push(tag("e", id));
        }
    }
    tags.push(tag("k", &market::KIND_CLASSIFIED.to_string()));
    let content = "This shop's listing at an address it no longer uses is withdrawn: it lists itself at its new one.".to_string();
    Event::sign(keys, created_at, KIND_DELETION, tags, content)
}

/// Publish now and every `cfg.republish` until the gateway stops.
pub fn spawn(gw: Arc<Gateway>, keys: Keys, cfg: NostrConfig) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new().name("nostr-publish".into()).spawn(move || loop {
        match publish_once(&gw, &keys, &cfg.relays, xbt_nostr::now()) {
            Ok(out) => {
                let ok = out.iter().filter(|o| o.result.is_ok()).count();
                eprintln!("xbt-gateway: listing published on Nostr: {ok} of {} relays took it", out.len());
                for o in out.iter().filter(|o| o.result.is_err()) {
                    eprintln!("xbt-gateway: nostr relay {}: {}", o.relay, o.result.as_ref().unwrap_err());
                }
            }
            Err(e) => eprintln!("xbt-gateway: listing not published on Nostr: {e}"),
        }
        let until = Instant::now() + cfg.republish;
        while Instant::now() < until {
            if gw.stopped() {
                return;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    })
}
