//! Which packets a seller's exit carries.
//!
//! An exit sends strangers' traffic to the internet from the seller's own address, so by default it
//! refuses the ports most used for abuse (outgoing mail on 25), IPv6 unless the seller turns it on,
//! and every address that is not the public internet: the seller's own network, loopback, link-local
//! and the like, so a buyer can never reach the seller's machines. The filter reads only what it needs
//! to decide (IP version, destination address, protocol, destination port) and keeps nothing: no
//! destination is recorded anywhere.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    pub dst: IpAddr,
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
    let dst = IpAddr::V4(Ipv4Addr::new(p[16], p[17], p[18], p[19]));
    Some(Packet { v6: false, dst, proto, dst_port })
}

fn parse_v6(p: &[u8]) -> Option<Packet> {
    if p.len() < 40 {
        return None;
    }
    let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).ok()?));
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
                    return Some(Packet { v6: true, dst, proto: Proto::from_number(next), dst_port: None });
                }
            }
            _ => break,
        }
        if at > p.len() {
            return None;
        }
    }
    let proto = Proto::from_number(next);
    Some(Packet { v6: true, dst, proto, dst_port: port_at(proto, p, at) })
}

/// Whether an address is on the public internet: not private, loopback, link-local, shared (carrier
/// NAT), multicast, documentation, benchmarking or reserved space, in IPv4 or IPv6.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_multicast()
                || a.is_broadcast()
                || a.is_unspecified()
                || a.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1]))
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (18..20).contains(&o[1]))
                || o[0] >= 240)
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1))
        }
    }
}

fn port_at(proto: Proto, p: &[u8], at: usize) -> Option<u16> {
    match proto {
        Proto::Tcp | Proto::Udp => Some(u16::from_be_bytes([*p.get(at + 2)?, *p.get(at + 3)?])),
        _ => None,
    }
}

/// A network: an address and its prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Net {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Net {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let m = if self.prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(self.prefix.min(32))) };
                u32::from(n) & m == u32::from(a) & m
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let m = if self.prefix == 0 { 0 } else { u128::MAX << (128 - u32::from(self.prefix.min(128))) };
                u128::from(n) & m == u128::from(a) & m
            }
            _ => false,
        }
    }
}

/// The networks this machine reaches directly (without its gateway), from the kernel's routing
/// tables: the seller's own network, whatever its address range. A home network may use an address
/// range that is not one of the private ones, so an exit refuses these as well.
pub fn local_networks() -> Vec<Net> {
    let mut nets = Vec::new();
    if let Ok(t) = std::fs::read_to_string("/proc/net/route") {
        for line in t.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (Some(dst), Some(gw), Some(mask)) = (f.get(1), f.get(2), f.get(7)) else { continue };
            // the kernel prints each address as a number in this machine's byte order
            let parse = |h: &str| u32::from_str_radix(h, 16).ok().map(|v| Ipv4Addr::from(v.to_ne_bytes()));
            let (Some(dst), Some(gw), Some(mask)) = (parse(dst), parse(gw), parse(mask)) else { continue };
            if gw.is_unspecified() && !mask.is_unspecified() {
                nets.push(Net { addr: IpAddr::V4(dst), prefix: u32::from(mask).count_ones() as u8 });
            }
        }
    }
    if let Ok(t) = std::fs::read_to_string("/proc/net/ipv6_route") {
        for line in t.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (Some(dst), Some(plen), Some(hop)) = (f.first(), f.get(1), f.get(4)) else { continue };
            let (Ok(dst), Ok(plen)) = (u128::from_str_radix(dst, 16), u8::from_str_radix(plen, 16)) else { continue };
            if plen > 0 && hop.chars().all(|c| c == '0') {
                nets.push(Net { addr: IpAddr::V6(Ipv6Addr::from(dst)), prefix: plen });
            }
        }
    }
    nets.dedup();
    nets
}

/// Why a packet was not carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Not an IPv4 or IPv6 packet.
    NotIp,
    /// IPv6, and this exit does not carry it.
    Ipv6Off,
    /// A destination that is not on the public internet (the seller's own network, loopback…).
    NotPublic,
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
    /// Whether destinations off the public internet are carried. Never on a real exit: it would let a
    /// buyer reach the seller's own machines. For tests on one machine only.
    pub allow_non_public: bool,
    /// Networks refused besides the non-public ranges: for a real exit, the networks it reaches
    /// directly ([`local_networks`]), and any a seller adds.
    pub blocked_nets: Vec<Net>,
}

impl Default for Policy {
    /// Outgoing mail (25) blocked, every other port carried, IPv6 off.
    fn default() -> Policy {
        Policy { blocked_ports: BTreeSet::from([25]), only_ports: None, ipv6: false, allow_non_public: false, blocked_nets: Vec::new() }
    }
}

impl Policy {
    /// The default, with this machine's own networks refused too: what a real exit runs with.
    pub fn for_exit() -> Policy {
        Policy { blocked_nets: local_networks(), ..Policy::default() }
    }

    /// Whether this exit carries the packet.
    pub fn check(&self, p: &[u8]) -> Result<(), Refused> {
        let pkt = parse(p).ok_or(Refused::NotIp)?;
        self.check_parts(pkt.v6, pkt.dst, pkt.dst_port)
    }

    /// Whether this exit opens a TCP connection or a UDP flow to `to`.
    pub fn check_dst(&self, to: std::net::SocketAddr) -> Result<(), Refused> {
        self.check_parts(to.is_ipv6(), to.ip(), Some(to.port()))
    }

    fn check_parts(&self, v6: bool, dst: IpAddr, dst_port: Option<u16>) -> Result<(), Refused> {
        let pkt = Packet { v6, dst, proto: Proto::Tcp, dst_port };
        if pkt.v6 && !self.ipv6 {
            return Err(Refused::Ipv6Off);
        }
        if !self.allow_non_public && (!is_public(pkt.dst) || self.blocked_nets.iter().any(|n| n.contains(pkt.dst))) {
            return Err(Refused::NotPublic);
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
        p[16..20].copy_from_slice(&[93, 184, 216, 34]);
        p[22..24].copy_from_slice(&dst_port.to_be_bytes());
        p
    }

    fn v6(next: u8, ext: &[u8], dst_port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[6] = next;
        p[24..26].copy_from_slice(&[0x26, 0x06]);
        p.extend_from_slice(ext);
        let mut tcp = vec![0u8; 8];
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        p.extend_from_slice(&tcp);
        p
    }

    #[test]
    fn reads_the_destination_port_of_tcp_and_udp_over_ipv4() {
        let dst = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(parse(&v4(6, 443, 0)), Some(Packet { v6: false, dst, proto: Proto::Tcp, dst_port: Some(443) }));
        assert_eq!(parse(&v4(17, 53, 0)), Some(Packet { v6: false, dst, proto: Proto::Udp, dst_port: Some(53) }));
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
        assert_eq!(parse(&v6(60, &ext, 25)).map(|p| (p.v6, p.proto, p.dst_port)), Some((true, Proto::Tcp, Some(25))));
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
    fn the_sellers_own_network_is_never_reached() {
        let p = Policy::default();
        for dst in [[192, 168, 1, 20], [10, 0, 0, 1], [172, 16, 5, 5], [127, 0, 0, 1], [169, 254, 1, 1], [100, 64, 0, 1], [0, 0, 0, 0], [255, 255, 255, 255], [224, 0, 0, 1]] {
            let mut pkt = v4(6, 443, 0);
            pkt[16..20].copy_from_slice(&dst);
            assert_eq!(p.check(&pkt), Err(Refused::NotPublic), "{dst:?}");
        }
        let v6p = Policy { ipv6: true, ..Policy::default() };
        for dst in [[0xfd, 0x00], [0xfe, 0x80], [0, 0]] {
            let mut pkt = v6(6, &[], 443);
            pkt[24..40].fill(0);
            pkt[24..26].copy_from_slice(&dst);
            if dst == [0, 0] {
                pkt[39] = 1; // ::1
            }
            assert_eq!(v6p.check(&pkt), Err(Refused::NotPublic), "{dst:?}");
        }
        assert!(is_public("8.8.8.8".parse().unwrap()));
        assert!(!is_public("::ffff:192.168.1.1".parse().unwrap()));
        assert!(is_public("2606:4700::1111".parse().unwrap()));
    }

    #[test]
    fn a_home_network_on_a_public_range_is_refused_too() {
        // some home networks use a range that is not one of the private ones
        let home = Net { addr: "45.67.0.0".parse().unwrap(), prefix: 24 };
        let p = Policy { blocked_nets: vec![home], ..Policy::default() };
        let mut pkt = v4(6, 443, 0);
        pkt[16..20].copy_from_slice(&[45, 67, 0, 37]);
        assert_eq!(p.check(&pkt), Err(Refused::NotPublic));
        pkt[16..20].copy_from_slice(&[45, 68, 0, 37]);
        assert_eq!(p.check(&pkt), Ok(()));
        assert!(Net { addr: "fd00::".parse().unwrap(), prefix: 8 }.contains("fd12::1".parse().unwrap()));
        assert!(!Net { addr: "fd00::".parse().unwrap(), prefix: 8 }.contains("2606::1".parse().unwrap()));
    }

    #[test]
    fn this_machines_own_networks_are_read_from_the_routing_table() {
        // every machine running the tests has a directly reached network or loopback route
        let nets = local_networks();
        assert!(nets.iter().all(|n| n.prefix > 0));
        // this machine's own address on its network is inside one of them
        let s = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        if s.connect("192.0.2.1:9").is_ok() {
            let me = s.local_addr().unwrap().ip();
            assert!(nets.iter().any(|n| n.contains(me)), "{me} in {nets:?}");
        }
    }

    #[test]
    fn a_port_list_carries_only_its_ports() {
        let p = Policy { only_ports: Some(BTreeSet::from([53, 80, 443])), ..Policy::default() };
        assert_eq!(p.check(&v4(6, 443, 0)), Ok(()));
        assert_eq!(p.check(&v4(6, 22, 0)), Err(Refused::PortNotListed(22)));
        assert_eq!(p.check(&v4(6, 25, 0)), Err(Refused::PortBlocked(25)));
    }
}
