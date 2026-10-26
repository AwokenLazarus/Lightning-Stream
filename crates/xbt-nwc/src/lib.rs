//! xbt-nwc: the Lightning Stream app as a Nostr Wallet Connect (NIP-47) wallet service.
//!
//! Another app (a phone wallet, a browser extension, an agent) is given a connection URI; it sends
//! NIP-47 requests over Nostr relays, encrypted with NIP-44 v2, and this service answers them by
//! calling the wallet's signer over its socket, as the MCP server and the connector do. It holds no
//! wallet key and moves no money itself: every payment is the signer's `ln_pay`, under the owner's
//! policy. It only ever spends the owner's own wallet; it holds nobody else's money.
//!
//! * [`nip44`], [`event`], [`ws`], [`relay`], [`standin`]: the Nostr pieces, from `xbt-nostr`.
//! * [`store`]: connections, budgets and payment records (the state file, 0600).
//! * [`service`]: requests to the signer and back. [`admin`]: the socket the wallet UI uses.
//! * [`client`]: the app's side, for the tests.
//!
//! What the service does and refuses, and its security model: `docs/NWC.md`.
pub mod admin;
pub mod client;
pub mod service;
pub mod store;

pub use xbt_nostr::{event, nip44, now, relay, standin, ws};
