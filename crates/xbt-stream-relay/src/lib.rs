//! A Stream relay built into the package (`docs/RUN-A-RELAY.md`). The app's owner switches it on
//! under Settings → Stream relays and enters a domain; this service then:
//!
//! 1. checks, before anything is asked of Let's Encrypt, that the domain points at this box, that
//!    port 443 is free and reachable, and that the certificate budget allows a try ([`preflight`]);
//! 2. runs iroh-relay's server with the defaults of our own relay ([`config`]): rate limits,
//!    connection caps, no client addresses logged, certificates by ACME TLS-ALPN-01 on 443, kept
//!    in a cache;
//! 3. writes what it is doing to a status file the app shows ([`status`]).
//!
//! Who may use the relay, and what it carries, is decided by a [`meter::Meter`]: [`meter::Free`]
//! for a free relay, [`paid::Paid`] for a paid one (`docs/PAID-RELAYS.md`), whose shops buy credit
//! through the credit API ([`credit`]).
pub mod config;
pub mod credit;
pub mod meter;
pub mod paid;
pub mod preflight;
pub mod status;
pub mod stun;
