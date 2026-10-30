//! The buyer's WireGuard endpoint: the peer the buyer's devices and router add.
//!
//! Each device has its own key pair and tunnel address, made by the buyer's app and shown once as a
//! config and a QR code; the app keeps only the device's public key. A device's packets come out of
//! WireGuard here and go to the buyer's stack ([`crate::buyer`]); the stack's answers go back to the
//! device they are addressed to. A device may send only from its own tunnel address.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// A device as the endpoint knows it.
#[derive(Clone, Debug)]
pub struct WgPeer {
    pub public: [u8; 32],
    pub tunnel_ip: Ipv4Addr,
}

struct PeerState {
    tunn: Mutex<Tunn>,
    ip: Ipv4Addr,
    addr: Mutex<Option<SocketAddr>>,
}

/// The endpoint's devices.
pub struct WgEndpoint {
    peers: Vec<Arc<PeerState>>,
    by_ip: HashMap<Ipv4Addr, usize>,
}

const BUF: usize = 65536 + 64;
const KEEPALIVE_S: u16 = 25;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A new key pair: (private, public).
pub fn keypair() -> ([u8; 32], [u8; 32]) {
    let mut k = [0u8; 32];
    getrandom(&mut k);
    let s = StaticSecret::from(k);
    (s.to_bytes(), PublicKey::from(&s).to_bytes())
}

fn getrandom(buf: &mut [u8]) {
    let mut f = std::fs::File::open("/dev/urandom").expect("/dev/urandom");
    std::io::Read::read_exact(&mut f, buf).expect("/dev/urandom");
}

/// The public key of a private one.
pub fn public_of(private: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(private)).to_bytes()
}

fn b64(k: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(k)
}

/// A device's WireGuard config: everything on the device goes through the buyer's app (IPv6 too, so
/// it cannot leak around the tunnel), DNS is asked through the tunnel, and the MTU fits the link.
pub fn device_config(device_private: [u8; 32], device_ip: Ipv4Addr, endpoint_public: [u8; 32], endpoint: &str, dns: &str) -> String {
    format!(
        "[Interface]\nPrivateKey = {}\nAddress = {device_ip}/32\nDNS = {dns}\nMTU = 1280\n\n[Peer]\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {endpoint}\nPersistentKeepalive = {KEEPALIVE_S}\n",
        b64(&device_private),
        b64(&endpoint_public),
    )
}

/// A config as a QR code (SVG), for a phone's WireGuard app to scan.
pub fn qr_svg(config: &str) -> Option<String> {
    let code = qrcode::QrCode::new(config.as_bytes()).ok()?;
    Some(code.render::<qrcode::render::svg::Color>().min_dimensions(256, 256).build())
}

impl WgEndpoint {
    /// The endpoint with its private key and its devices.
    pub fn new(private: [u8; 32], peers: &[WgPeer]) -> Arc<WgEndpoint> {
        let mut by_ip = HashMap::new();
        let peers = peers
            .iter()
            .enumerate()
            .map(|(i, p)| {
                by_ip.insert(p.tunnel_ip, i);
                let tunn = Tunn::new(StaticSecret::from(private), PublicKey::from(p.public), None, None, i as u32, None);
                Arc::new(PeerState { tunn: Mutex::new(tunn), ip: p.tunnel_ip, addr: Mutex::new(None) })
            })
            .collect();
        Arc::new(WgEndpoint { peers, by_ip })
    }

    /// Runs the endpoint on `sock`: devices' packets to `to_stack`, the stack's packets from
    /// `from_stack` to the devices.
    pub async fn run(self: Arc<Self>, sock: UdpSocket, to_stack: mpsc::Sender<Bytes>, mut from_stack: mpsc::UnboundedReceiver<Bytes>) {
        let sock = Arc::new(sock);
        let send = {
            let (me, sock) = (self.clone(), sock.clone());
            async move {
                let mut out = vec![0u8; BUF];
                while let Some(p) = from_stack.recv().await {
                    if p.len() < 20 || p[0] >> 4 != 4 {
                        continue;
                    }
                    let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
                    let Some(peer) = me.by_ip.get(&dst).map(|i| me.peers[*i].clone()) else { continue };
                    let Some(to) = *lock(&peer.addr) else { continue };
                    let packet = match lock(&peer.tunn).encapsulate(&p, &mut out) {
                        TunnResult::WriteToNetwork(b) => b.to_vec(),
                        _ => continue,
                    };
                    let _ = sock.send_to(&packet, to).await;
                }
            }
        };
        let timers = {
            let (me, sock) = (self.clone(), sock.clone());
            async move {
                let mut out = vec![0u8; BUF];
                loop {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    for peer in &me.peers {
                        let Some(to) = *lock(&peer.addr) else { continue };
                        let packet = match lock(&peer.tunn).update_timers(&mut out) {
                            TunnResult::WriteToNetwork(b) => b.to_vec(),
                            _ => continue,
                        };
                        let _ = sock.send_to(&packet, to).await;
                    }
                }
            }
        };
        let recv = async move {
            let (mut buf, mut out) = (vec![0u8; BUF], vec![0u8; BUF]);
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else { return };
                let d = &buf[..n];
                if n < 8 {
                    continue;
                }
                // a handshake initiation names no index: try each device; every other message names
                // the receiver's index, which is the device's position
                let candidates: Vec<usize> = match d[0] {
                    1 => (0..self.peers.len()).collect(),
                    _ => vec![(u32::from_le_bytes([d[4], d[5], d[6], d[7]]) >> 8) as usize],
                };
                for i in candidates {
                    let Some(peer) = self.peers.get(i) else { continue };
                    let mut replies = Vec::new();
                    let mut packets = Vec::new();
                    let ok = {
                        let mut t = lock(&peer.tunn);
                        let mut res = t.decapsulate(Some(from.ip()), d, &mut out);
                        let mut ok = false;
                        loop {
                            match res {
                                TunnResult::WriteToNetwork(b) => {
                                    ok = true;
                                    replies.push(b.to_vec());
                                    // a reply can release packets queued during the handshake
                                    res = t.decapsulate(None, &[], &mut out);
                                    continue;
                                }
                                TunnResult::WriteToTunnelV4(p, src) => {
                                    ok = true;
                                    // a device sends only from its own tunnel address
                                    if src == peer.ip {
                                        packets.push(Bytes::copy_from_slice(p));
                                    }
                                }
                                TunnResult::WriteToTunnelV6(..) => ok = true,
                                TunnResult::Done => ok = true,
                                TunnResult::Err(_) => {}
                            }
                            break;
                        }
                        ok
                    };
                    if ok {
                        *lock(&peer.addr) = Some(from);
                        for r in replies {
                            let _ = sock.send_to(&r, from).await;
                        }
                        for p in packets {
                            if to_stack.send(p).await.is_err() {
                                return;
                            }
                        }
                        break;
                    }
                }
            }
        };
        tokio::select! { _ = send => {}, _ = timers => {}, _ = recv => {} }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_config_routes_everything_through_the_app() {
        let (dev, _) = keypair();
        let (_, ep_pub) = keypair();
        let c = device_config(dev, Ipv4Addr::new(10, 66, 0, 2), ep_pub, "192.168.1.5:51820", "9.9.9.9");
        assert!(c.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
        assert!(c.contains("Address = 10.66.0.2/32"));
        assert!(c.contains("DNS = 9.9.9.9"));
        assert!(c.contains("MTU = 1280"));
        assert!(c.contains(&format!("PublicKey = {}", b64(&ep_pub))));
        let svg = qr_svg(&c).unwrap();
        assert!(svg.starts_with("<?xml") || svg.contains("<svg"));
        assert_eq!(public_of(dev).len(), 32);
    }
}
