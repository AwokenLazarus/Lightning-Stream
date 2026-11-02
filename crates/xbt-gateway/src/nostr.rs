//! The listing on Nostr (`docs/NOSTR.md`): the gateway sends its signed listing to the runner's
//! relays as a NIP-99 classified listing at start and every `nostr.republish_s` after, signed by a
//! Nostr key of its own (`nostr.key` in the state directory) that the receipt key binds to this
//! seller. Nothing is read from the relays, and a relay that refuses or is down is only logged.
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use xbt_nostr::event::Keys;
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
    let (events, _) = oneshot::query(relays, &market::own_filter(&keys.public_hex()), QUERY_WAIT);
    let old = market::left_behind(&events, &keys.public_hex(), current, now);
    if old.is_empty() {
        return Ok(vec![]);
    }
    let out = oneshot::publish(relays, &market::withdrawal_event(keys, &old, now), PUBLISH_WAIT);
    if !out.iter().any(|o| o.result.is_ok()) {
        return Err(out.iter().filter_map(|o| o.result.as_ref().err().map(|e| format!("{}: {e}", o.relay))).collect::<Vec<_>>().join("; "));
    }
    Ok(old.into_iter().map(|(d, _)| d).collect())
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
