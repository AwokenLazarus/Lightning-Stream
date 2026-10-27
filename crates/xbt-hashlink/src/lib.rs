//! p2p-hash: rented hashrate over Lightning Stream.
//!
//! A hashmaker rents its miners' hashrate to a hashtaker, who points it at the hashtaker's own DATUM Gateway
//! (the hashtaker makes the jobs). The hashmaker's app serves Stratum V1 to its miners on its LAN and
//! carries every line over an encrypted link to the hashtaker's app, which is a Stratum V1 client of
//! the hashtaker's gateway, one upstream session per miner. Both apps meter the work the gateway
//! accepts, by share difficulty, and the hashtaker pays for it slice by slice with Lightning Stream
//! tickets: a ticket is locked before its slice is mined and released when the slice is done.
//! Nobody holds anyone's money, and either side's exposure is about one slice.
//!
//! * [`noise`]: BOLT 8 (Noise_XK over secp256k1), the link's handshake and framing.
//! * [`msg`]: the link's messages.
//! * [`link`]: a framed, encrypted, thread-safe link over TCP.
//! * [`sv1`]: the few Stratum V1 facts the relay and the meter read.
//! * [`meter`]: accepted work, slices, and the hashtaker's signed work receipts.
//! * [`rail`]: how a slice is paid: through the wallet's signer and the hashmaker's gateway (real
//!   tickets), or the lab's stand-in over the link.
//! * [`listing`]: the hashmaker's signed `hashrate` listing on Nostr.
//! * [`hashmaker`]: the hashmaker's side (miners in, link out).
//! * [`hashtaker`]: the hashtaker's side (link in, the hashtaker's gateway out).
//! * [`standin`]: a stand-in pool and miner for the lab, with a toy share hash.

pub mod hashtaker;
pub mod hashmaker;
pub mod link;
pub mod listing;
pub mod meter;
pub mod msg;
pub mod noise;
pub mod rail;
pub mod standin;
pub mod sv1;

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
