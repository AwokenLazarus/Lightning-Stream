//! A light chain backend for XBT: Electrum servers, checked against our own BLAKE2b header chain.
//! The xbt402 client and wallet run on it with no node, on any hardware (AGP-028, a port of B2's
//! `agentwallet/electrum.py`, AGP-024).
//!
//! [`ElectrumBackend`] implements [`xbt402::funding::ChainBackend`], has a typed API
//! ([`ElectrumBackend::tx_out`], [`ElectrumBackend::transaction`], [`ElectrumBackend::spending_tx`],
//! [`ElectrumBackend::unspent`], [`ElectrumBackend::broadcast`], [`ElectrumBackend::watch`], ...), and
//! answers the node RPCs of the client path the way the node does ([`ElectrumBackend::call`]).
//!
//! Trust (the same rules as the Python backend; threat model in `docs/B2_CHAIN_BACKEND.md`):
//!
//! * **Headers**: our own chain from a pinned post-fork checkpoint ([`xbt_primitives::header::HeaderChain`]):
//!   each header's BLAKE2b PoW, nBits (Knots' retarget), linkage, committed height and time are
//!   checked, and the most-work chain any server shows wins. A server cannot move us to a chain with
//!   less work, or below the checkpoint. Servers that answer but cannot serve the checkpoint are the
//!   wrong chain ([`Kind::CheckpointMismatch`]). Knots' header rules hold from the first header
//!   (the ten below the checkpoint are fetched and hash-linked for the median), chunks are checked as
//!   they arrive, and a claimed tip is believed only up to what the time since our tip allows.
//! * **A believable chain** (mainnet, [`Plausibility`]): until the chain reaches the pinned block
//!   964264 (Knots' assumevalid), carries Knots' nMinimumChainWork and is not implausibly short for its
//!   age, every chain answer fails with [`Kind::Implausible`]. Mainnet servers need TLS (`ssl://`),
//!   except on a loopback host.
//! * **Transactions**: a raw tx is accepted only if it re-serializes byte for byte and hashes to the
//!   txid asked for. It counts as confirmed only with a Merkle proof into one of our headers whose
//!   committed transaction count fits the proof (depth `ceil(log2(txcount))`, position below the
//!   count: no 64-byte inner-node forgeries).
//! * **Several servers**: histories and unspent lists are the union over every reachable server
//!   (proofs stop fabrication; the union means one honest server defeats hiding), headers are
//!   cross-checked, broadcasts go to all of them, the fee estimate is their median.
//! * **Mempool facts cannot be proven.** A spend seen only in a mempool never makes an output count
//!   as spent, so a lying server cannot talk the wallet out of a refund.
//! * **Unknown is not absent** (AGP-092). A lookup says "not there" (no such transaction or output,
//!   not in a block, no such coin) only when every configured server answered; if one did not, or is
//!   down, the call fails with [`Kind::Unreachable`]. (`min_servers` is the floor for what is proven.) `tx_out` says "spent" only for a confirmed spend with a proof.
//!
//! * **What one server can cost is bounded.** A line is held, before it is parsed, to the bytes and
//!   JSON values the requests waiting on that connection allow ([`conn::answer_cap`], at most
//!   [`conn::MAX_LINE`]); a server that sends more is dropped. Its part of a sync round ends at
//!   [`Config::sync_deadline`], or at the first answer with fewer headers than asked. A history or
//!   unspent list holds at most [`conn::MAX_HISTORY`] entries, and the transaction cache at most
//!   [`backend::TX_CACHE_BYTES`]. Reaching a server costs one timeout for the TCP connect and the TLS
//!   handshake together. Every request of one call ends at [`Config::call_deadline`], and a call
//!   forces one header sync at most. A server is asked only for the transactions it listed itself:
//!   the first it does not supply, or that cannot belong to the script, ends its list and flags it.
//! * **What the deadline does not cost an honest server** (AGP-097). A scan asks each server for
//!   the script's history once and for the coins' proofs in one batch, however many coins the
//!   script holds. A request is written by one deadline. A request the call's deadline cuts short,
//!   or leaves no time for, fails with [`Kind::Deadline`] and hangs up on nobody and flags nobody:
//!   the deadline is shared by every server, so only a request that goes a whole timeout
//!   unanswered is the server's own. A claim above a server's tip is a lie only against a tip it
//!   reported in the sync the call itself forced, and an error about the method ("Method not
//!   found", JSON-RPC -32601) is never "no such transaction".
//!
//! What a malicious server can still do:
//!
//! * Hide a transaction until another server or a block shows it. If **every** configured server
//!   hides it, it reads as absent: a caller that books a loss on that must ask for the proven spend
//!   ([`ElectrumBackend::spending_tx`] with a confirmed status), not for an empty `tx_out`.
//! * Withhold new blocks (the tip lags: `status()["tip_age_s"]`), lie about fees (unverifiable,
//!   reported as such), and learn which scripts we watch.
//! * Make calls fail or slow, never answer wrongly: by not answering, or by being down, it turns a
//!   "not there" into an error for as long as it is configured, and by listing transactions that pay the script and
//!   supplying them slowly it holds each call that reads that script up to [`Config::call_deadline`].
//!   Both are flagged in `status()["verification_failures"]`; the cure is to remove the server.
//! * An invented transaction that pays the script cannot be told from an unconfirmed payment.
//!
//! "No such transaction" and "not in that block" are read from the server's words
//! ([`backend::NOT_THERE`]); an error worded otherwise counts as no answer. A script with a history longer than
//! [`conn::MAX_HISTORY`], or a transaction above [`conn::MAX_TX_BYTES`], is not answered by this
//! backend.
pub mod backend;
pub mod conn;
pub mod error;
#[cfg(feature = "sim")]
pub mod sim;

pub use backend::{is_loopback_host, parse_checkpoint, scripthash, Config, ElectrumBackend, FeeEstimate, Flag, Plausibility, TxOutInfo,
                  TxStatus, Utxo};
pub use conn::{parse_server, tls_config, Connection, ServerAddr};
pub use error::{ElectrumError, Kind, Result};
