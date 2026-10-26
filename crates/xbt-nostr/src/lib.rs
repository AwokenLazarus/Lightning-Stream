//! xbt-nostr: the Nostr pieces Lightning Stream uses, with no wallet in them.
//!
//! * [`event`]: Nostr events (NIP-01), ids and BIP-340 Schnorr signatures. [`nip44`]: NIP-44 v2.
//! * [`ws`]: a minimal RFC 6455 WebSocket over std TCP and rustls. [`relay`]: a pool that keeps a
//!   subscription open on each relay. [`oneshot`]: publish one event, or run one query, and hang up.
//! * [`market`]: a seller's signed listing (`docs/LISTINGS.md`) as a NIP-99 classified listing,
//!   bound to the seller's receipt key, and read back and checked.
//! * [`standin`]: an in-process relay, for the tests.
//!
//! The NWC wallet service (`xbt-nwc`) is built on these. What goes over Nostr and what does not:
//! `docs/NOSTR.md`.
pub mod event;
pub mod market;
pub mod nip44;
pub mod oneshot;
pub mod relay;
pub mod standin;
pub mod ws;

/// Seconds since the epoch.
pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
