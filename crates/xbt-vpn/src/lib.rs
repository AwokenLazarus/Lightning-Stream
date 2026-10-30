//! VPN exits over the iroh link.
//!
//! A buyer's Stream app sends IP packets to a seller's exit over the same encrypted link the rest of
//! Stream uses (`xbt-iroh-link`, protocol [`xbt_iroh_link::ALPN_VPN`]): straight between the two when
//! hole punching works, through a relay otherwise, with no port forward on either side. Packets ride
//! in QUIC datagrams, which are unreliable and unordered like the IP they carry, so a TCP connection
//! inside the tunnel never sits on top of a second retransmitting layer.
//!
//! - [`tunnel`]: the packet tunnel on one link connection.
//! - [`flow`]: the protocol: each TCP connection one QUIC stream, UDP in datagrams with a flow number.
//! - [`exit`]: a seller's exit: a buyer's flows become ordinary connections, with no TUN or NAT.
//! - [`filter`]: which packets an exit carries (blocked ports, IPv6).
//! - [`buyer`]: the buyer's devices' connections ended on the buyer's box and carried to exits.
//! - [`wg`]: the buyer's WireGuard endpoint, which devices and routers add, and their configs and QR codes.
//! - [`router`]: which exit a new flow goes to (best, sticky, or spread with each destination kept on one).
//! - [`region`]: checking an exit's announced region against its egress address, offline.
//! - [`content`]: sites an exit's operator chooses not to carry (by DNS, TLS name, HTTP Host), with no log.
//! - [`hop`]: two hops: a first hop run by someone else joins a buyer's sealed flows to an exit.
//! - [`sealed`]: the TLS session between a buyer and an exit that a first hop cannot read.
//! - [`lists`]: category blocklists (adult, gambling, malware…) an operator ticks, kept up to date.
//! - [`meter`]: bytes carried each way, for payment. It never records where a packet was going.

pub mod announce;
pub mod buyer;
pub mod content;
pub mod exit;
pub mod filter;
pub mod flow;
pub mod hop;
pub mod lists;
pub mod meter;
pub mod mux;
pub mod paid;
pub mod region;
pub mod router;
pub mod sealed;
pub mod service;
pub mod tunnel;
pub mod wg;
