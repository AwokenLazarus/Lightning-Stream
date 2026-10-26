//! xbt402: what the paid-HTTP schemes of this workspace share, in Rust.
//!
//! Lightning Stream sells HTTP answers for payments on XBT's Lightning network (stream tickets and
//! the lottery, `docs/TICKETS.md`) and for mined work (`xbt-work`). This crate holds the parts
//! they have in common and the ticket and lottery wires themselves:
//!
//! * [`wire`]: the x402 v2 headers, the request digest, URL reading.
//! * [`ticket`]: the stream-ticket wire, draft v0 (`docs/TICKETS.md`): request auth and the signed receipt.
//! * [`lottery`]: the lottery, pay after a win (`docs/TICKETS.md`, section 9): the draw and both sides' bookkeeping of it.
//! * [`offer`]: paying a prepaid ticket or a win by BOLT 12 offer (`docs/TICKETS.md`, section 15): the payer note.
//! * [`scheme`]: the two traits a scheme implements to be sold and paid: [`scheme::ProviderScheme`], [`scheme::SchemePayer`].
//! * [`provider`]: a resource server that sells through its schemes ([`provider::Provider::serve`]).
//! * [`client`]: the payer for those schemes ([`client::Client`]), and [`client::Transport`].
//! * [`maturity`]: coinbase maturity as the node reports it (`getdeploymentinfo`).
//! * [`macaroon`]: a Lightning node's macaroon, read (shared with `xbt-signer`'s Lightning rail).
//! * [`json`]: JSON written as the Python references write it, and integers above 2^64.
//! * [`listing`]: a seller's signed catalog (`docs/LISTINGS.md`).
//!
//! The crate began as the Rust port of the on-chain one-way channel (the x402 `batch-settlement`
//! scheme on XBT: funding, signed states, close, rollover, refund). That channel was frozen on
//! 2026-10-11 and removed in 2026-10; its code is in the repository's history, last at revision
//! `1ad0c48`.
//!
//! Optional features: `http-client` (ureq transport), `http-server` (std::net around the
//! provider), `rpc` (a bitcoind JSON-RPC client).

pub mod client;
pub mod error;
pub mod json;
pub mod listing;
pub mod lottery;
pub mod macaroon;
pub mod maturity;
pub mod offer;
pub mod provider;
pub mod scheme;
pub mod ticket;
pub mod wire;
#[cfg(feature = "rpc")]
pub mod rpc;
#[cfg(any(feature = "http-client", feature = "http-server"))]
pub mod http;

pub use error::{ChannelError, Result};
pub use xbt_primitives;
