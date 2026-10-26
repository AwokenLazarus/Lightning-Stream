//! xbt-gateway: the stream-ticket seller gateway (`docs/TICKETS.md`, draft v0). A reverse proxy
//! beside a Lightning node: it answers an unpaid request with ticket terms, registers hold
//! invoices for a buyer's hashes, settles a ticket when its secret arrives, meters the answer and
//! signs a receipt.
//!
//! * [`book`]: sessions, tickets, balances and caps. No IO: every rule is tested on in-memory data.
//! * [`price`]: what a piece costs, per request, per byte and per second.
//! * [`node`]: the seller's Lightning node, over its REST interface with a pinned certificate.
//! * [`store`]: the journal that outlasts the process.
//! * [`upstream`]: the service behind the gateway, and what may reach it.
//! * [`gateway`]: the HTTP handler and the threads that follow the node.
//! * [`config`]: the runner's config file.
//! * [`standin`]: a stand-in node for tests.

/// Why the gateway did not start, or why one of its parts refused its input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The config file, with the key at fault.
    #[error("{0}")]
    Config(String),
    /// A macaroon that is missing a permission, or on mainnet has one too many.
    #[error("{0}")]
    Macaroon(String),
    #[error("the node: {0}")]
    Node(String),
    #[error("the journal: {0}")]
    Journal(String),
    /// The service behind the gateway gave no answer.
    #[error("the service: {0}")]
    Upstream(String),
    #[error("{0}")]
    Start(String),
}

pub mod book;
pub mod config;
pub mod gateway;
pub mod lottery;
pub mod node;
pub mod nostr;
pub mod price;
pub mod standin;
pub mod store;
pub mod upstream;
