//! xbt-signer: the agent wallet's signer (AGP-027; it began as a port of B2's Python signer).
//!
//! A signer process holds every key; the model-facing process (the wallet's MCP server) only calls
//! its Unix socket. It carries the policy engine, the sealed hot key, the anchored signature log,
//! the Lightning rail and the stream-ticket book, with B2's socket protocol and on-disk formats
//! where B2 has them.
//!
//! * [`applog`], [`fsx`]: the append-only logs (AGP-055) and the durable-write steps under every file.
//! * [`keystore`]: AES-256-GCM sealing (keyfile or scrypt passphrase), B2's blob format.
//! * [`sigaudit`], [`anchor`]: the hash-chained signature log and the witness protocol.
//! * [`policy`], [`approval`]: the policy engine and the ed25519 human approvals.
//! * [`node`]: the node RPC (cookie auth, P3 mining guard) and the pruned-node lookups (P6).
//! * [`hot`]: the hot key, its sealed UTXO set, rotation, the balance cap, sweeps.
//! * [`bolt11`], [`ln`]: `rail=ln` (AGP-048): XBT Lightning invoices paid through an LND node under the
//!   same policy, with the chain-identity, bit-512, taproot and pre-split guards.
//! * [`ticket`], [`ticket_rail`]: stream tickets, the buyer's book (`docs/TICKETS.md`): secrets derived from a
//!   sealed seed, many payments locked at once through the same LND node, booked before a secret leaves.
//! * [`ticket_pay`], [`ticket_http`], [`lottery`]: `xbt402_pay`: a seller's 402 read and paid with tickets,
//!   by draws, or with a single Lightning invoice.
//! * [`signer`]: the request handler and the watcher; [`server`]: the socket.
//! * [`admin`]: the web UI's methods (AGP-039): the approval queue, human-signed policy changes, key
//!   enrolment and rotation, backups.
//! * [`client`]: the socket client.
//! * [`legacy`]: what an earlier version's on-chain channels left on disk, read-only. The wallet paid
//!   over an on-chain one-way channel until 2026-10; that rail was removed.
pub mod admin;
pub mod anchor;
pub mod applog;
pub mod client;
pub mod approval;
pub mod bolt11;
pub mod bolt12;
pub mod fsx;
pub mod hot;
pub mod ipc;
pub mod keystore;
pub mod legacy;
pub mod ln;
pub mod ln_funding;
pub mod ln_offer;
pub mod lottery;
pub mod macaroon;
pub mod node;
pub mod policy;
pub mod pyjson;
pub mod sanitize;
pub mod server;
pub mod signer;
pub mod sigaudit;
pub mod ticket;
pub mod ticket_http;
pub mod ticket_pay;
pub mod ticket_rail;

pub use xbt402::{ChannelError as Error, Result};

/// An error with a wire code and a message.
pub fn err(code: &str, msg: impl Into<String>) -> Error {
    Error::new(code, msg)
}
