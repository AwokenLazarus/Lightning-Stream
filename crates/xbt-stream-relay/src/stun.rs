//! A minimal STUN client (RFC 8489 binding request) to learn this box's public address.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

const MAGIC: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const MAPPED_ADDRESS: u16 = 0x0001;

/// Public STUN servers asked when none are set.
pub const DEFAULT_SERVERS: &[&str] = &["stun.cloudflare.com:3478", "stun.l.google.com:19302"];

/// A binding request with `txid`.
pub fn request(txid: &[u8; 12]) -> [u8; 20] {
    let mut b = [0u8; 20];
    b[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    b[4..8].copy_from_slice(&MAGIC.to_be_bytes());
    b[8..20].copy_from_slice(txid);
    b
}

/// The address a binding success for `txid` reports.
pub fn parse_response(b: &[u8], txid: &[u8; 12]) -> Option<IpAddr> {
    if b.len() < 20 || u16::from_be_bytes([b[0], b[1]]) != BINDING_SUCCESS || u32::from_be_bytes([b[4], b[5], b[6], b[7]]) != MAGIC || &b[8..20] != txid {
        return None;
    }
    let len = u16::from_be_bytes([b[2], b[3]]) as usize;
    let body = b.get(20..20 + len)?;
    let mut i = 0;
    let mut plain = None;
    while i + 4 <= body.len() {
        let t = u16::from_be_bytes([body[i], body[i + 1]]);
        let l = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        let v = body.get(i + 4..i + 4 + l)?;
        if (t == XOR_MAPPED_ADDRESS || t == MAPPED_ADDRESS) && l >= 8 {
            let xor = t == XOR_MAPPED_ADDRESS;
            let ip = match v[1] {
                1 => {
                    let mut a = [v[4], v[5], v[6], v[7]];
                    if xor {
                        for (x, m) in a.iter_mut().zip(MAGIC.to_be_bytes()) {
                            *x ^= m;
                        }
                    }
                    Some(IpAddr::V4(Ipv4Addr::from(a)))
                }
                2 if l >= 20 => {
                    let mut a: [u8; 16] = v[4..20].try_into().ok()?;
                    if xor {
                        let mut key = [0u8; 16];
                        key[..4].copy_from_slice(&MAGIC.to_be_bytes());
                        key[4..].copy_from_slice(txid);
                        for (x, k) in a.iter_mut().zip(key) {
                            *x ^= k;
                        }
                    }
                    Some(IpAddr::V6(Ipv6Addr::from(a)))
                }
                _ => None,
            };
            if xor {
                return ip;
            }
            plain = plain.or(ip);
        }
        i += 4 + l.div_ceil(4) * 4;
    }
    plain
}

/// This box's public IPv4 address, from the first STUN server that answers.
pub fn public_ip(servers: &[String], timeout: Duration) -> Option<IpAddr> {
    let servers: Vec<String> = if servers.is_empty() { DEFAULT_SERVERS.iter().map(|s| s.to_string()).collect() } else { servers.to_vec() };
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(timeout)).ok()?;
    for s in servers {
        let Some(addr) = s.to_socket_addrs().ok().and_then(|mut a| a.find(|x| x.is_ipv4())) else { continue };
        let mut txid = [0u8; 12];
        getrandom::getrandom(&mut txid).expect("OS randomness");
        if sock.send_to(&request(&txid), addr).is_err() {
            continue;
        }
        let mut buf = [0u8; 512];
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            if from == addr {
                if let Some(ip) = parse_response(&buf[..n], &txid) {
                    return Some(ip);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_xor_mapped_address() {
        let txid = [7u8; 12];
        // 203.0.113.7:54321 XOR the magic cookie
        let ip = [203u8, 0, 113, 7];
        let x: Vec<u8> = ip.iter().zip(MAGIC.to_be_bytes()).map(|(a, m)| a ^ m).collect();
        let port = (54321u16 ^ (MAGIC >> 16) as u16).to_be_bytes();
        let mut b = Vec::new();
        b.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        b.extend_from_slice(&12u16.to_be_bytes());
        b.extend_from_slice(&MAGIC.to_be_bytes());
        b.extend_from_slice(&txid);
        b.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
        b.extend_from_slice(&8u16.to_be_bytes());
        b.extend_from_slice(&[0, 1]);
        b.extend_from_slice(&port);
        b.extend_from_slice(&x);
        assert_eq!(parse_response(&b, &txid), Some("203.0.113.7".parse().unwrap()));
        // another transaction's answer is ignored
        assert_eq!(parse_response(&b, &[8u8; 12]), None);
        assert_eq!(request(&txid)[0..2], [0, 1]);
    }
}
