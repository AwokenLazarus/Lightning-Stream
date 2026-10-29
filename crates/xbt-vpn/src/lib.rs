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
//! - [`meter`]: bytes carried each way, for payment. It never records where a packet was going.

pub mod exit;
pub mod filter;
pub mod flow;
pub mod meter;
pub mod tunnel;
