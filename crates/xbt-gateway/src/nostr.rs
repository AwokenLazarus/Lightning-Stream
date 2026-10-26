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

/// Sign the listing as it is now and send it to `relays` once. `now` dates the event.
pub fn publish_once(gw: &Gateway, keys: &Keys, relays: &[String], now: u64) -> Result<Vec<Outcome>, String> {
    let doc = gw.listing().ok_or("the gateway has no listing")?;
    let bind = gw.bind_nostr(&keys.public.serialize());
    let ev = market::listing_event(keys, &doc, &bind, now)?;
    Ok(oneshot::publish(relays, &ev, PUBLISH_WAIT))
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
