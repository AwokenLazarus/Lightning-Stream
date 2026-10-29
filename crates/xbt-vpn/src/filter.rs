//! Which packets a seller's exit carries.
//!
//! An exit sends strangers' traffic to the internet from the seller's own address, so by default it
//! refuses the ports most used for abuse (outgoing mail on 25) and IPv6 unless the seller turns it on.
//! The filter reads only what it needs to decide (IP version, protocol, destination port) and keeps
//! nothing: no destination is recorded anywhere.

use std::collections::BTreeSet;

/// The transport protocol of a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl Proto {
    fn from_number(n: u8) -> Proto {
        match n {
            6 => Proto::Tcp,
            17 => Proto::Udp,
            1 | 58 => Proto::Icmp,
            n => Proto::Other(n),
        }
    }
}

/// What the filter reads from a packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub v6: bool,
    pub proto: Proto,
    /// The destination port of a TCP or UDP packet; `None` for other protocols and for a fragment
    /// after the first (which carries no transport header).
    pub dst_port: Option<u16>,
}

/// Reads the IP version, protocol and destination port of a packet. `None` if it is not a whole
/// IPv4 or IPv6 header.
pub fn parse(p: &[u8]) -> Option<Packet> {
    match p.first()? >> 4 {
        4 => parse_v4(p),
        6 => parse_v6(p),
        _ => None,
    }
}

fn parse_v4(p: &[u8]) -> Option<Packet> {
    let ihl = usize::from(p[0] & 0x0f) * 4;
    if ihl < 20 || p.len() < ihl {
        return None;
    }
    let proto = Proto::from_number(p[9]);
    let frag_offset = u16::from_be_bytes([p[6], p[7]]) & 0x1fff;
    let dst_port = if frag_offset == 0 { port_at(proto, p, ihl) } else { None };
    Some(Packet { v6: false, proto, dst_port })
}

fn parse_v6(p: &[u8]) -> Option<Packet> {
    if p.len() < 40 {
        return None;
    }
    let mut next = p[6];
    let mut at = 40;
    // hop-by-hop, routing and destination options headers come before the transport header; a
    // fragment header after the first fragment means there is no transport header in this packet
    loop {
        match next {
            0 | 43 | 60 => {
                let len = (usize::from(*p.get(at + 1)?) + 1) * 8;
                next = p[at];
                at += len;
            }
            44 => {
                let off = u16::from_be_bytes([*p.get(at + 2)?, *p.get(at + 3)?]) >> 3;
                next = p[at];
                at += 8;
                if off != 0 {
                    return Some(Packet { v6: true, proto: Proto::from_number(next), dst_port: None });
                }
            }
            _ => break,
        }
        if at > p.len() {
            return None;
        }
    }
    let proto = Proto::from_number(next);
    Some(Packet { v6: true, proto, dst_port: port_at(proto, p, at) })
}

fn port_at(proto: Proto, p: &[u8], at: usize) -> Option<u16> {
    match proto {
        Proto::Tcp | Proto::Udp => Some(u16::from_be_bytes([*p.get(at + 2)?, *p.get(at + 3)?])),
        _ => None,
    }
}

/// Why a packet was not carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Not an IPv4 or IPv6 packet.
    NotIp,
    /// IPv6, and this exit does not carry it.
    Ipv6Off,
    /// A destination port this exit blocks.
    PortBlocked(u16),
    /// The exit carries only listed ports, and this is not one of them.
    PortNotListed(u16),
}

/// An exit's packet policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// TCP and UDP destination ports never carried.
    pub blocked_ports: BTreeSet<u16>,
    /// If set, the only TCP and UDP destination ports carried.
    pub only_ports: Option<BTreeSet<u16>>,
    /// Whether IPv6 is carried (the exit needs IPv6 of its own). Off, the buyer's side routes IPv6
    /// into the tunnel and it is dropped here, so it never leaks around the tunnel.
    pub ipv6: bool,
}

impl Default for Policy {
    /// Outgoing mail (25) blocked, every other port carried, IPv6 off.
    fn default() -> Policy {
        Policy { blocked_ports: BTreeSet::from([25]), only_ports: None, ipv6: false }
    }
}

impl Policy {
    /// Whether this exit carries the packet.
    pub fn check(&self, p: &[u8]) -> Result<(), Refused> {
        let pkt = parse(p).ok_or(Refused::NotIp)?;
        if pkt.v6 && !self.ipv6 {
            return Err(Refused::Ipv6Off);
        }
        if let Some(port) = pkt.dst_port {
            if self.blocked_ports.contains(&port) {
                return Err(Refused::PortBlocked(port));
            }
            if let Some(only) = &self.only_ports {
                if !only.contains(&port) {
                    return Err(Refused::PortNotListed(port));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(proto: u8, dst_port: u16, frag_offset: u16) -> Vec<u8> {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[6..8].copy_from_slice(&frag_offset.to_be_bytes());
        p[9] = proto;
        p[22..24].copy_from_slice(&dst_port.to_be_bytes());
        p
    }

    fn v6(next: u8, ext: &[u8], dst_port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[6] = next;
        p.extend_from_slice(ext);
        let mut tcp = vec![0u8; 8];
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        p.extend_from_slice(&tcp);
        p
    }

    #[test]
    fn reads_the_destination_port_of_tcp_and_udp_over_ipv4() {
        assert_eq!(parse(&v4(6, 443, 0)), Some(Packet { v6: false, proto: Proto::Tcp, dst_port: Some(443) }));
        assert_eq!(parse(&v4(17, 53, 0)), Some(Packet { v6: false, proto: Proto::Udp, dst_port: Some(53) }));
        assert_eq!(parse(&v4(1, 0, 0)).unwrap().dst_port, None);
    }

    #[test]
    fn a_later_fragment_has_no_port() {
        assert_eq!(parse(&v4(6, 25, 185)).unwrap().dst_port, None);
    }

    #[test]
    fn reads_past_ipv6_extension_headers() {
        // a destination options header (8 bytes) before TCP
        let mut ext = vec![0u8; 8];
        ext[0] = 6;
        assert_eq!(parse(&v6(60, &ext, 25)), Some(Packet { v6: true, proto: Proto::Tcp, dst_port: Some(25) }));
        assert_eq!(parse(&v6(6, &[], 443)).unwrap().dst_port, Some(443));
    }

    #[test]
    fn rejects_what_is_not_a_whole_header() {
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&[0x45, 0, 0]), None);
        assert_eq!(parse(&[0x60; 20]), None);
        assert_eq!(parse(&[0x20; 40]), None);
    }

    #[test]
    fn the_default_blocks_mail_and_ipv6_and_carries_the_rest() {
        let p = Policy::default();
        assert_eq!(p.check(&v4(6, 25, 0)), Err(Refused::PortBlocked(25)));
        assert_eq!(p.check(&v4(17, 25, 0)), Err(Refused::PortBlocked(25)));
        assert_eq!(p.check(&v4(6, 443, 0)), Ok(()));
        assert_eq!(p.check(&v4(1, 0, 0)), Ok(()));
        assert_eq!(p.check(&v6(6, &[], 443)), Err(Refused::Ipv6Off));
        assert_eq!(p.check(&[0x10, 0, 0]), Err(Refused::NotIp));
    }

    #[test]
    fn an_ipv6_exit_still_blocks_mail_behind_an_extension_header() {
        let p = Policy { ipv6: true, ..Policy::default() };
        let mut ext = vec![0u8; 8];
        ext[0] = 6;
        assert_eq!(p.check(&v6(60, &ext, 25)), Err(Refused::PortBlocked(25)));
        assert_eq!(p.check(&v6(6, &[], 443)), Ok(()));
    }

    #[test]
    fn a_port_list_carries_only_its_ports() {
        let p = Policy { only_ports: Some(BTreeSet::from([53, 80, 443])), ..Policy::default() };
        assert_eq!(p.check(&v4(6, 443, 0)), Ok(()));
        assert_eq!(p.check(&v4(6, 22, 0)), Err(Refused::PortNotListed(22)));
        assert_eq!(p.check(&v4(6, 25, 0)), Err(Refused::PortBlocked(25)));
    }
}
