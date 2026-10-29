//! A seller reached by its key instead of a web address.
//!
//! The seller's gateway and the buyer's wallet talk HTTP to each other as they do over the web, but
//! the bytes travel over an iroh link: QUIC between the two ends, authenticated by their keys and
//! encrypted end to end, connected directly where the two routers allow it (hole punching, or a port
//! the router maps on request) and through a relay where they do not. The relay sees only
//! ciphertext. Neither side needs a certificate, a public web address or a forwarded port.
//!
//! * A seller runs [`Link::serve`]: every stream a buyer opens becomes one TCP connection to the
//!   gateway's own local listener, so the gateway serves, meters and signs exactly as it does for a
//!   request from the web.
//! * A buyer calls [`Link::local_port`] for a seller's key and points its HTTP client at that
//!   loopback port, or gives the client [`Link::resolve`], which maps a seller's link host name
//!   ([`host_for`]) to it. Each TCP connection to the port becomes one stream to the seller.
//! * [`claim`] is how the seller's Lightning node vouches for the key, checked before any byte goes.
//!
//! The link runs its own small async runtime on two threads, so callers stay synchronous.

pub mod claim;

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey};
use sha2::Digest;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// The link's protocol: one HTTP/1.1 exchange (or a WebSocket after its upgrade) per stream.
pub const ALPN: &[u8] = b"xbt-stream/http/1";

/// The suffix of a seller's link host name. `.invalid` never resolves through DNS.
pub const HOST_SUFFIX: &str = ".link.invalid";

/// The suffix of a shop that has no web address: its gateway's Nostr key in base32. The shop's
/// identity (policy, receipts, credit) keys on this host; which link key reaches it is learned from
/// its verified transport document and given to [`Link::bind_shop`].
pub const SHOP_SUFFIX: &str = ".shop.invalid";

/// How the link reaches relays.
#[derive(Clone, Debug)]
pub enum Relays {
    /// No relay: direct connections only.
    None,
    /// The public relays of iroh's makers. For trials only.
    Public,
    /// Relays we name (self-hosted).
    Ours(Vec<String>),
}

/// Where a seller can be found, besides its key: relays and direct addresses it last reported.
#[derive(Clone, Debug, Default)]
pub struct Hints {
    pub relays: Vec<String>,
    pub direct: Vec<SocketAddr>,
}

/// How the link is built.
#[derive(Clone, Debug)]
pub struct Options {
    pub relays: Relays,
    /// A seller's link, which accepts streams; a buyer's link only opens them.
    pub serving: bool,
    /// Private mode: relays only, never a direct path. Neither end learns the other's IP address;
    /// the relay sees both, and the volume, never the content.
    pub private: bool,
}

/// An iroh endpoint and the loopback ports that lead through it.
pub struct Link {
    rt: tokio::runtime::Runtime,
    ep: Endpoint,
    ports: Mutex<HashMap<EndpointId, u16>>,
    hints: Mutex<HashMap<EndpointId, Hints>>,
    shops: Mutex<HashMap<String, String>>,
}

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

impl Link {
    /// Starts the link with this secret key (32 bytes, kept by the caller).
    pub fn start(secret: [u8; 32], relays: Relays, serving: bool) -> io::Result<Arc<Link>> {
        Self::start_with(secret, Options { relays, serving, private: false })
    }

    /// Starts the link with these options.
    pub fn start_with(secret: [u8; 32], opts: Options) -> io::Result<Arc<Link>> {
        let Options { relays, serving, private } = opts;
        if private && matches!(relays, Relays::None) {
            return Err(io_err("private mode needs a relay"));
        }
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_name("iroh-link").enable_all().build()?;
        let relay_mode = match relays {
            Relays::None => RelayMode::Disabled,
            Relays::Public => RelayMode::Default,
            Relays::Ours(urls) => {
                let urls = urls.iter().map(|u| u.parse::<RelayUrl>()).collect::<Result<Vec<_>, _>>().map_err(io_err)?;
                RelayMode::Custom(RelayMap::from_iter(urls))
            }
        };
        let mut b = Endpoint::builder(presets::Minimal).secret_key(SecretKey::from_bytes(&secret)).relay_mode(relay_mode);
        if serving {
            b = b.alpns(vec![ALPN.to_vec()]);
        }
        if private {
            b = b.clear_ip_transports();
        }
        let ep = rt.block_on(b.bind()).map_err(io_err)?;
        Ok(Arc::new(Link { rt, ep, ports: Mutex::new(HashMap::new()), hints: Mutex::new(HashMap::new()), shops: Mutex::new(HashMap::new()) }))
    }

    /// This link's key, as hex: what a seller's listing names and its node vouches for.
    pub fn endpoint_id(&self) -> String {
        hex::encode(self.ep.id().as_bytes())
    }

    /// Where this link can be reached now: its relay and the direct addresses it has found. Waits up
    /// to `wait` for a relay to answer first.
    pub fn hints(&self, wait: std::time::Duration) -> Hints {
        self.rt.block_on(async {
            let _ = tokio::time::timeout(wait, self.ep.online()).await;
        });
        let addr = self.ep.addr();
        Hints {
            relays: addr.relay_urls().map(|u| u.to_string()).collect(),
            direct: addr.ip_addrs().copied().collect(),
        }
    }

    /// A seller's link: every stream a buyer opens is joined to a new TCP connection to `upstream`.
    pub fn serve(self: &Arc<Self>, upstream: SocketAddr) {
        let ep = self.ep.clone();
        self.rt.spawn(async move {
            while let Some(incoming) = ep.accept().await {
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    let from = peer_loopback(conn.remote_id().as_bytes());
                    while let Ok((send, recv)) = conn.accept_bi().await {
                        tokio::spawn(async move {
                            if let Ok(tcp) = connect_from(from, upstream).await {
                                let _ = tcp.set_nodelay(true);
                                join(tcp, send, recv).await;
                            }
                        });
                    }
                });
            }
        });
    }

    /// Remembers where a seller can be found, from its checked listing.
    pub fn learn(&self, endpoint_id_hex: &str, hints: Hints) -> io::Result<()> {
        lock(&self.hints).insert(parse_id(endpoint_id_hex)?, hints);
        Ok(())
    }

    /// A loopback port that leads to the seller with this key: each TCP connection to it becomes one
    /// stream on one link to the seller, opened on first use and opened again if it drops.
    pub fn local_port(self: &Arc<Self>, endpoint_id_hex: &str) -> io::Result<u16> {
        let id = parse_id(endpoint_id_hex)?;
        if let Some(p) = lock(&self.ports).get(&id) {
            return Ok(*p);
        }
        let port = self.forward(endpoint_id_hex, (Ipv4Addr::LOCALHOST, 0).into())?.port();
        lock(&self.ports).insert(id, port);
        Ok(port)
    }

    /// Like [`Link::local_port`], on an address the caller chooses (for a tool or a test that serves
    /// a browser on another machine).
    pub fn forward(self: &Arc<Self>, endpoint_id_hex: &str, listen: SocketAddr) -> io::Result<SocketAddr> {
        let id = parse_id(endpoint_id_hex)?;
        let listener = self.rt.block_on(TcpListener::bind(listen))?;
        let bound = listener.local_addr()?;
        let addr = {
            let h = lock(&self.hints).get(&id).cloned().unwrap_or_default();
            let mut a = EndpointAddr::new(id);
            for r in h.relays.iter().filter_map(|r| r.parse::<RelayUrl>().ok()) {
                a = a.with_relay_url(r);
            }
            for d in h.direct {
                a = a.with_ip_addr(d);
            }
            a
        };
        let ep = self.ep.clone();
        self.rt.spawn(async move {
            let conn: Arc<tokio::sync::Mutex<Option<Connection>>> = Arc::new(tokio::sync::Mutex::new(None));
            while let Ok((tcp, _)) = listener.accept().await {
                let (ep, addr, conn) = (ep.clone(), addr.clone(), conn.clone());
                tokio::spawn(async move {
                    let _ = tcp.set_nodelay(true);
                    let Some((send, recv)) = open(&ep, &addr, &conn).await else { return };
                    join(tcp, send, recv).await;
                });
            }
        });
        Ok(bound)
    }

    /// Whether the link to this seller runs direct or through a relay right now, for display.
    pub fn path(&self, endpoint_id_hex: &str) -> Option<String> {
        let id = parse_id(endpoint_id_hex).ok()?;
        let info = self.rt.block_on(self.ep.remote_info(id))?;
        Some(format!("{info:?}"))
    }

    /// Records that the shop at `shop_host` (`<base32 key>.shop.invalid`) is reached through the link
    /// key `endpoint_id_hex`. Call it only after the shop's transport document has been verified.
    pub fn bind_shop(&self, shop_host: &str, endpoint_id_hex: &str) -> io::Result<()> {
        parse_id(endpoint_id_hex)?;
        let host = shop_host.to_ascii_lowercase();
        if !host.ends_with(SHOP_SUFFIX) {
            return Err(io_err("not a shop host name"));
        }
        lock(&self.shops).insert(host, endpoint_id_hex.to_string());
        Ok(())
    }

    /// For an HTTP client's resolver: a seller's link host name ([`host_for`]), or a shop host bound
    /// with [`Link::bind_shop`], resolves to its loopback port; any other name is `None`, for the
    /// client's usual resolver. An unbound shop host is an error: it never goes to DNS.
    pub fn resolve(self: &Arc<Self>, host_port: &str) -> Option<io::Result<Vec<SocketAddr>>> {
        let host = host_port.rsplit_once(':').map_or(host_port, |(h, _)| h).to_ascii_lowercase();
        let hex = if let Some(label) = host.strip_suffix(HOST_SUFFIX) {
            id_from_label(label)
        } else if host.ends_with(SHOP_SUFFIX) {
            lock(&self.shops).get(&host).cloned().ok_or_else(|| io_err("this shop's link is not known yet"))
        } else {
            return None;
        };
        Some(hex.and_then(|hex| self.local_port(&hex)).map(|p| vec![SocketAddr::from((Ipv4Addr::LOCALHOST, p))]))
    }
}

/// The host name under which a seller's link is addressed: its key in base32 (52 letters, one DNS
/// label) and [`HOST_SUFFIX`]. A URL like `http://<host>/film` then reaches the seller over the link.
pub fn host_for(endpoint_id_hex: &str) -> io::Result<String> {
    let b = hex::decode(endpoint_id_hex).map_err(io_err)?;
    Ok(format!("{}{HOST_SUFFIX}", base32(&b)))
}

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn base32(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn id_from_label(label: &str) -> io::Result<String> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in label.to_ascii_lowercase().bytes() {
        let v = B32.iter().position(|&a| a == c).ok_or_else(|| io_err("not a link host name"))? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if out.len() != 32 {
        return Err(io_err("not a link host name"));
    }
    Ok(hex::encode(out))
}

fn parse_id(hex_id: &str) -> io::Result<EndpointId> {
    let b: [u8; 32] = hex::decode(hex_id).map_err(io_err)?.try_into().map_err(|_| io_err("a link key is 32 bytes"))?;
    EndpointId::from_bytes(&b).map_err(io_err)
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The loopback address a buyer's streams come from at the gateway: `127.x.y.z` from the buyer's
/// key, so the gateway's caps per address count each buyer apart, as they do for buyers on the web.
/// Not 127.0.0.0/24, which local tools use.
fn peer_loopback(key: &[u8; 32]) -> Ipv4Addr {
    let h = sha2::Sha256::digest(key);
    Ipv4Addr::new(127, h[0].max(1), h[1], h[2].max(1))
}

/// Connects to `upstream` from `from` where the system allows it (Linux routes all of 127.0.0.0/8 to
/// loopback), else from wherever it chooses.
async fn connect_from(from: Ipv4Addr, upstream: SocketAddr) -> io::Result<TcpStream> {
    if upstream.ip().is_loopback() {
        let sock = tokio::net::TcpSocket::new_v4()?;
        if sock.bind((from, 0).into()).is_ok() {
            if let Ok(tcp) = sock.connect(upstream).await {
                return Ok(tcp);
            }
        }
    }
    TcpStream::connect(upstream).await
}

/// A stream on the link to `addr`, connecting (again) when there is no live connection.
async fn open(ep: &Endpoint, addr: &EndpointAddr, conn: &tokio::sync::Mutex<Option<Connection>>) -> Option<(SendStream, RecvStream)> {
    let mut c = conn.lock().await;
    if let Some(live) = c.as_ref() {
        if let Ok(s) = live.open_bi().await {
            return Some(s);
        }
    }
    let fresh = ep.connect(addr.clone(), ALPN).await.ok()?;
    let s = fresh.open_bi().await.ok()?;
    *c = Some(fresh);
    Some(s)
}

/// Joins a TCP connection and a stream until both directions have ended.
async fn join(tcp: TcpStream, mut send: SendStream, mut recv: RecvStream) {
    let (mut r, mut w) = tcp.into_split();
    let up = async {
        let _ = tokio::io::copy(&mut r, &mut send).await;
        let _ = send.finish();
    };
    let down = async {
        let _ = tokio::io::copy(&mut recv, &mut w).await;
        let _ = w.shutdown().await;
    };
    tokio::join!(up, down);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_host_name_is_one_dns_label_and_maps_back_to_its_key() {
        let id = "8f".repeat(32);
        let host = host_for(&id).unwrap();
        let label = host.strip_suffix(HOST_SUFFIX).unwrap();
        assert_eq!(label.len(), 52);
        assert_eq!(id_from_label(label).unwrap(), id);
        assert!(id_from_label("short").is_err());
    }
}
