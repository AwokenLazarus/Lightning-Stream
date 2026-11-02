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

/// How the seller's node vouches for the link key: one implementation, in xbt402.
pub use xbt402::claim;
pub mod nostr_lookup;

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey};
use sha2::Digest;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// The link's protocol: one HTTP/1.1 exchange (or a WebSocket after its upgrade) per stream.
pub const ALPN: &[u8] = b"xbt-stream/http/1";

/// The hashrate link's protocol: each stream carries one hashlink connection (its own Noise
/// handshake and messages) between a hashtaker's app and a hashmaker's app.
pub const ALPN_HASHLINK: &[u8] = b"xbt-stream/hashlink/0";

/// The VPN exit's protocol: IP packets in QUIC datagrams (a length-prefixed stream when the path
/// carries no datagrams) between a buyer's app and a seller's exit.
pub const ALPN_VPN: &[u8] = b"xbt-stream/vpn/0";

/// A VPN first hop's protocol (two hops): each stream names an exit, and the hop joins it to a
/// stream on its own connection to that exit, carrying bytes it cannot read.
pub const ALPN_VPN_HOP: &[u8] = b"xbt-stream/vpn-hop/0";

/// An exit's protocol for flows that come through a first hop: each stream is a TLS session between
/// the buyer and the exit (each authenticated by its link key), inside which runs one flow.
pub const ALPN_VPN_SEALED: &[u8] = b"xbt-stream/vpn-sealed/0";

/// A connection on the link, for a protocol that uses it directly (datagrams) rather than through
/// TCP ports.
pub use iroh::endpoint::Connection as LinkConnection;
/// The streams of a [`LinkConnection`].
pub use iroh::endpoint::{RecvStream as LinkRecvStream, SendDatagramError, SendStream as LinkSendStream};

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
    /// Relays we name, with iroh's public relays beside them for when ours cannot be reached.
    OursThenPublic(Vec<String>),
}

/// Our relay: the default.
pub const DEFAULT_RELAY: &str = "https://iroh.lazarus-xbt.xyz";

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
    /// Where links are told and found: over Nostr ([`nostr_lookup`]). `None`: only what the
    /// caller learns ([`Link::learn`]). Never a lookup service of iroh's makers.
    pub lookup: Option<Arc<nostr_lookup::NostrLookup>>,
}

/// An iroh endpoint and the loopback ports that lead through it.
pub struct Link {
    rt: tokio::runtime::Runtime,
    ep: Endpoint,
    ports: Mutex<HashMap<EndpointId, u16>>,
    hints: Mutex<HashMap<EndpointId, Hints>>,
    /// For each shop host, its link keys in this buyer's order, and the port that leads through
    /// them once one is opened.
    shops: Mutex<HashMap<String, ShopKeys>>,
    lookup: Option<Arc<nostr_lookup::NostrLookup>>,
    paths: Arc<Mutex<HashMap<EndpointId, Path>>>,
    detail: AtomicBool,
    /// The protocol this link serves and opens: [`ALPN`] unless started with [`Link::start_alpn`].
    alpn: &'static [u8],
}

/// A shop's link keys in a buyer's order, and the loopback port that leads through them once opened.
type ShopKeys = (Vec<EndpointId>, Option<u16>);

/// The path a connection to a peer runs over now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Path {
    /// Straight between the two ends: the address and the round trip.
    Direct { addr: SocketAddr, rtt_ms: u64 },
    /// Through a relay.
    Relay { url: String, rtt_ms: u64 },
}

impl Path {
    /// "direct" or "relay", with the round trip: what a log may say without naming the peer's address.
    pub fn kind(&self) -> String {
        match self {
            Path::Direct { rtt_ms, .. } => format!("direct, {rtt_ms} ms"),
            Path::Relay { rtt_ms, .. } => format!("relay, {rtt_ms} ms"),
        }
    }
}

/// Watches a connection's selected path until it closes, recording it under the peer's key and
/// saying so on stderr when it changes (`detail`: with the address, for tools; a gateway says only
/// direct or relay).
fn watch(conn: Connection, paths: Arc<Mutex<HashMap<EndpointId, Path>>>, detail: bool) {
    tokio::spawn(async move {
        let peer = conn.remote_id();
        let mut last: Option<Path> = None;
        while conn.close_reason().is_none() {
            let now = conn.paths().iter().find(|p| p.is_selected()).and_then(|p| {
                let rtt_ms = p.rtt().as_millis() as u64;
                match p.remote_addr() {
                    iroh::TransportAddr::Ip(a) => Some(Path::Direct { addr: *a, rtt_ms }),
                    iroh::TransportAddr::Relay(u) => Some(Path::Relay { url: u.to_string(), rtt_ms }),
                    _ => None,
                }
            });
            let changed = !matches!(
                (&last, &now),
                (Some(Path::Direct { .. }), Some(Path::Direct { .. })) | (Some(Path::Relay { .. }), Some(Path::Relay { .. })) | (None, None)
            );
            if let Some(p) = &now {
                lock(&paths).insert(peer, p.clone());
                if changed {
                    let peer_short = &hex::encode(peer.as_bytes())[..12];
                    match (detail, p) {
                        (true, Path::Direct { addr, rtt_ms }) => eprintln!("link: {peer_short} direct {addr} rtt {rtt_ms} ms"),
                        (true, Path::Relay { url, rtt_ms }) => eprintln!("link: {peer_short} relay {url} rtt {rtt_ms} ms"),
                        (false, p) => eprintln!("link: {peer_short} {}", p.kind()),
                    }
                }
            }
            last = now;
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });
}

/// [`watch`], on the link's own runtime (for a caller on another runtime).
fn watch_on(rt: &tokio::runtime::Runtime, conn: Connection, paths: Arc<Mutex<HashMap<EndpointId, Path>>>, detail: bool) {
    let _guard = rt.enter();
    watch(conn, paths, detail);
}

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

impl Link {
    /// Starts the link with this secret key (32 bytes, kept by the caller).
    pub fn start(secret: [u8; 32], relays: Relays, serving: bool) -> io::Result<Arc<Link>> {
        Self::start_with(secret, Options { relays, serving, private: false, lookup: None })
    }

    /// Starts the link with these options.
    pub fn start_with(secret: [u8; 32], opts: Options) -> io::Result<Arc<Link>> {
        Self::start_alpn(secret, opts, ALPN)
    }

    /// Starts a link for another protocol than HTTP (e.g. [`ALPN_HASHLINK`]): its streams are still
    /// joined to TCP connections, but a peer speaking another protocol is refused in the handshake.
    pub fn start_alpn(secret: [u8; 32], opts: Options, alpn: &'static [u8]) -> io::Result<Arc<Link>> {
        Self::start_alpns(secret, opts, alpn, &[alpn])
    }

    /// Like [`Link::start_alpn`], serving several protocols on one endpoint (each accepted
    /// connection's [`LinkConnection::alpn`] says which); `alpn` is the one it opens by default.
    pub fn start_alpns(secret: [u8; 32], opts: Options, alpn: &'static [u8], serve: &[&'static [u8]]) -> io::Result<Arc<Link>> {
        Self::start_bound(secret, opts, alpn, serve, None)
    }

    /// [`Link::start_with`] on a fixed UDP port (`port`, on IPv4 and IPv6) instead of a random one:
    /// a seller that allows inbound UDP there is reached directly by buyers behind a NAT that gives
    /// each destination another port. `None`: random ports, as [`Link::start_with`]. Ignored in
    /// private mode, which binds no IP socket.
    pub fn start_on_port(secret: [u8; 32], opts: Options, port: Option<u16>) -> io::Result<Arc<Link>> {
        Self::start_bound(secret, opts, ALPN, &[ALPN], port)
    }

    /// The IP sockets the link is bound on: their ports are where it is reached directly.
    pub fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.ep.bound_sockets()
    }

    fn start_bound(secret: [u8; 32], opts: Options, alpn: &'static [u8], serve: &[&'static [u8]], port: Option<u16>) -> io::Result<Arc<Link>> {
        let Options { relays, serving, private, lookup } = opts;
        if private && matches!(relays, Relays::None) {
            return Err(io_err("private mode needs a relay"));
        }
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_name("iroh-link").enable_all().build()?;
        let relay_mode = match relays.clone() {
            Relays::None => RelayMode::Disabled,
            Relays::Public => RelayMode::Default,
            Relays::Ours(urls) => RelayMode::Custom(relay_map(&urls)?),
            // ours home whenever it answers (vendor/iroh's preferred relay); the public ones beside
            // it for finding this endpoint's own public address, which ours cannot (no UDP), and
            // as home only when ours does not answer
            Relays::OursThenPublic(urls) => {
                let map = relay_map(&urls)?;
                map.extend(&iroh::defaults::prod::default_relay_map());
                RelayMode::Custom(map)
            }
        };
        let mut b = Endpoint::builder(presets::Minimal).secret_key(SecretKey::from_bytes(&secret)).relay_mode(relay_mode);
        if serving {
            b = b.alpns(serve.iter().map(|a| a.to_vec()).collect());
        }
        if private {
            b = b.clear_ip_transports();
        } else if let Some(port) = port {
            // in place of the unspecified address on a random port, for each family. IPv6 is allowed to
            // fail, as iroh's own default is (a box with no IPv6)
            b = b.bind_addr(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))).map_err(io_err)?;
            b = b.bind_addr_with_opts(SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)), iroh::endpoint::BindOpts::default().set_is_required(false))
                .map_err(io_err)?;
        }
        if let Some(l) = &lookup {
            l.set_own(SecretKey::from_bytes(&secret).public());
            b = b.address_lookup(l.clone());
        }
        // the first relay named is home whenever it answers: a seller on several keys names its
        // relays in another order for each, so that each key keeps its connection on another relay
        if let Relays::OursThenPublic(urls) | Relays::Ours(urls) = &relays {
            if let Some(first) = urls.first().and_then(|u| u.parse::<RelayUrl>().ok()) {
                let mut nr = iroh::NetReportConfig::default();
                nr.preferred_relay = Some(first);
                b = b.net_report_config(nr);
            }
        }
        let ep = rt.block_on(b.bind()).map_err(io_err)?;
        Ok(Arc::new(Link { rt, ep, lookup, ports: Mutex::new(HashMap::new()), hints: Mutex::new(HashMap::new()), shops: Mutex::new(HashMap::new()), paths: Arc::new(Mutex::new(HashMap::new())), detail: AtomicBool::new(false), alpn }))
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

    /// Whether this link is connected to its home relay now: what a seller checks before it names
    /// the key, so that buyers are not sent to a key no relay can reach yet.
    pub fn relay_connected(&self) -> bool {
        use iroh::Watcher;
        self.ep.home_relay_status().get().iter().any(|s| s.is_connected())
    }

    /// A seller's link: every stream a buyer opens is joined to a new TCP connection to `upstream`.
    pub fn serve(self: &Arc<Self>, upstream: SocketAddr) {
        let ep = self.ep.clone();
        let (paths, detail) = (self.paths.clone(), self.detail.load(Ordering::Relaxed));
        self.rt.spawn(async move {
            while let Some(incoming) = ep.accept().await {
                let paths = paths.clone();
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    watch(conn.clone(), paths.clone(), detail);
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

    /// Believes where `endpoint_id_hex` is reached (from Nostr) only from this Nostr key: the one the
    /// seller's verified transport document is bound to.
    pub fn expect_author(&self, endpoint_id_hex: &str, nostr_pubkey_hex: &str) -> io::Result<()> {
        if let Some(l) = &self.lookup {
            l.expect(parse_id(endpoint_id_hex)?, nostr_pubkey_hex);
        }
        Ok(())
    }

    /// The runtime the link runs on, for a protocol that drives connections itself.
    pub fn runtime(&self) -> tokio::runtime::Handle {
        self.rt.handle().clone()
    }

    /// A seller's link that hands each accepted connection to `handler` (after recording its path),
    /// for a protocol that uses the connection directly, such as [`ALPN_VPN`].
    pub fn accept_with<F, Fut>(self: &Arc<Self>, handler: F)
    where
        F: Fn(Connection) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let ep = self.ep.clone();
        let (paths, detail) = (self.paths.clone(), self.detail.load(Ordering::Relaxed));
        let handler = Arc::new(handler);
        self.rt.spawn(async move {
            while let Some(incoming) = ep.accept().await {
                let (paths, handler) = (paths.clone(), handler.clone());
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    watch(conn.clone(), paths, detail);
                    handler(conn).await;
                });
            }
        });
    }

    /// A connection to the peer with this key, for the link's protocol, using the hints learned for
    /// it ([`Link::learn`]) and the address lookup.
    pub fn connect_conn(self: &Arc<Self>, endpoint_id_hex: &str) -> io::Result<Connection> {
        let addr = self.addr_of(parse_id(endpoint_id_hex)?);
        let (ep, alpn) = (self.ep.clone(), self.alpn);
        let (paths, detail) = (self.paths.clone(), self.detail.load(Ordering::Relaxed));
        self.rt.block_on(async move {
            let conn = ep.connect(addr, alpn).await.map_err(io_err)?;
            watch(conn.clone(), paths, detail);
            Ok(conn)
        })
    }

    /// Like [`Link::connect_conn`], from inside a task (it does not block a runtime thread).
    pub async fn connect_conn_async(self: &Arc<Self>, endpoint_id_hex: &str) -> io::Result<Connection> {
        self.connect_conn_alpn(endpoint_id_hex, self.alpn).await
    }

    /// A connection speaking `alpn` (another of the protocols the peer serves).
    pub async fn connect_conn_alpn(self: &Arc<Self>, endpoint_id_hex: &str, alpn: &[u8]) -> io::Result<Connection> {
        let addr = self.addr_of(parse_id(endpoint_id_hex)?);
        let conn = self.ep.connect(addr, alpn).await.map_err(io_err)?;
        watch_on(&self.rt, conn.clone(), self.paths.clone(), self.detail.load(Ordering::Relaxed));
        Ok(conn)
    }

    /// Where this link was told a peer can be found ([`Link::learn`]), for a first hop that has to
    /// find it too.
    pub fn hints_for(&self, endpoint_id_hex: &str) -> Hints {
        parse_id(endpoint_id_hex).ok().and_then(|id| lock(&self.hints).get(&id).cloned()).unwrap_or_default()
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
        let addr = self.addr_of(id);
        let (ep, alpn) = (self.ep.clone(), self.alpn);
        let (paths, detail) = (self.paths.clone(), self.detail.load(Ordering::Relaxed));
        self.rt.spawn(async move {
            let conn: Arc<tokio::sync::Mutex<Option<Connection>>> = Arc::new(tokio::sync::Mutex::new(None));
            while let Ok((tcp, _)) = listener.accept().await {
                let (ep, addr, conn, paths) = (ep.clone(), addr.clone(), conn.clone(), paths.clone());
                tokio::spawn(async move {
                    let _ = tcp.set_nodelay(true);
                    let Some((send, recv)) = open(&ep, &addr, &conn, &paths, detail, alpn).await else { return };
                    join(tcp, send, recv).await;
                });
            }
        });
        Ok(bound)
    }

    /// The path the link to this peer runs over now, once a connection has been made.
    pub fn path(&self, endpoint_id_hex: &str) -> Option<Path> {
        lock(&self.paths).get(&parse_id(endpoint_id_hex).ok()?).cloned()
    }

    /// Path changes are logged with the peer's address (for tools), not only direct or relay.
    pub fn log_path_detail(&self, on: bool) {
        self.detail.store(on, Ordering::Relaxed);
    }

    /// Records that the shop at `shop_host` (`<base32 key>.shop.invalid`) is reached through the link
    /// key `endpoint_id_hex`. Call it only after the shop's transport document has been verified.
    pub fn bind_shop(&self, shop_host: &str, endpoint_id_hex: &str) -> io::Result<()> {
        self.bind_shop_links(shop_host, &[endpoint_id_hex.to_string()])
    }

    /// Records that the shop at `shop_host` is reached through any of these link keys: one gateway
    /// serving on several keys, each with its own connection to its relay, so that the buyers
    /// relayed to it do not all share one. This buyer uses the key [`order`] puts first and the
    /// next when one cannot be reached. Call it only after the shop's transport document has been
    /// verified: every key in it is the one gateway's, vouched for by the node the buyer pays.
    pub fn bind_shop_links(&self, shop_host: &str, endpoint_ids_hex: &[String]) -> io::Result<()> {
        let ids = endpoint_ids_hex.iter().map(|h| parse_id(h)).collect::<io::Result<Vec<_>>>()?;
        if ids.is_empty() {
            return Err(io_err("a shop needs a link key"));
        }
        let host = shop_host.to_ascii_lowercase();
        if !host.ends_with(SHOP_SUFFIX) {
            return Err(io_err("not a shop host name"));
        }
        let ordered = order(&self.ep.id(), &host, ids);
        let mut shops = lock(&self.shops);
        // the same keys keep their port (and its connection); new keys get a new one
        if shops.get(&host).is_none_or(|(had, _)| *had != ordered) {
            shops.insert(host, (ordered, None));
        }
        Ok(())
    }

    /// A loopback port that leads to the shop at `shop_host` through the first of its keys that
    /// answers, in this buyer's order ([`Link::bind_shop_links`]).
    fn shop_port(self: &Arc<Self>, host: &str) -> io::Result<u16> {
        let ids = {
            let shops = lock(&self.shops);
            let (ids, port) = shops.get(host).ok_or_else(|| io_err("this shop's link is not known yet"))?;
            if let Some(p) = port {
                return Ok(*p);
            }
            ids.clone()
        };
        if let [one] = ids.as_slice() {
            let port = self.local_port(&hex::encode(one.as_bytes()))?;
            if let Some(e) = lock(&self.shops).get_mut(host).filter(|(had, _)| *had == ids) {
                e.1 = Some(port);
            }
            return Ok(port);
        }
        let listener = self.rt.block_on(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))?;
        let port = listener.local_addr()?.port();
        let addrs: Vec<EndpointAddr> = ids.iter().map(|id| self.addr_of(*id)).collect();
        let (ep, alpn) = (self.ep.clone(), self.alpn);
        let (paths, detail) = (self.paths.clone(), self.detail.load(Ordering::Relaxed));
        self.rt.spawn(async move {
            let conns: Arc<Vec<tokio::sync::Mutex<Option<Connection>>>> = Arc::new(addrs.iter().map(|_| tokio::sync::Mutex::new(None)).collect());
            // the key in use: the first in order until another answers first
            let at = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let addrs = Arc::new(addrs);
            while let Ok((tcp, _)) = listener.accept().await {
                let (ep, addrs, conns, paths, at) = (ep.clone(), addrs.clone(), conns.clone(), paths.clone(), at.clone());
                tokio::spawn(async move {
                    let _ = tcp.set_nodelay(true);
                    // the key in use first; the next joins in when no stream has come within
                    // RACE_AFTER, or at once when one fails. The first stream wins; an attempt that
                    // ends later still leaves its connection ready for the next request
                    let start = at.load(Ordering::Relaxed);
                    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
                    let launch = |k: usize| {
                        let i = (start + k) % addrs.len();
                        let (ep, addrs, conns, paths, tx) = (ep.clone(), addrs.clone(), conns.clone(), paths.clone(), tx.clone());
                        tokio::spawn(async move {
                            let got = open(&ep, &addrs[i], &conns[i], &paths, detail, alpn).await;
                            let _ = tx.send((i, got));
                        });
                    };
                    launch(0);
                    let (mut launched, mut running) = (1usize, 1usize);
                    while running > 0 {
                        let more = launched < addrs.len();
                        let got = if more { tokio::time::timeout(RACE_AFTER, rx.recv()).await.ok() } else { Some(rx.recv().await) };
                        match got {
                            Some(Some((i, Some((send, recv))))) => {
                                at.store(i, Ordering::Relaxed);
                                join(tcp, send, recv).await;
                                return;
                            }
                            // a key that failed is passed over at once
                            Some(Some((_, None))) => running -= 1,
                            Some(None) => return,
                            // slow: the next key joins in beside it
                            None => {}
                        }
                        if launched < addrs.len() {
                            launch(launched);
                            launched += 1;
                            running += 1;
                        }
                    }
                });
            }
        });
        if let Some(e) = lock(&self.shops).get_mut(host).filter(|(had, _)| *had == ids) {
            e.1 = Some(port);
        }
        Ok(port)
    }

    /// The address to dial for `id`: its key, with the relays and direct addresses learned for it.
    fn addr_of(&self, id: EndpointId) -> EndpointAddr {
        let h = lock(&self.hints).get(&id).cloned().unwrap_or_default();
        let mut a = EndpointAddr::new(id);
        for r in h.relays.iter().filter_map(|r| r.parse::<RelayUrl>().ok()) {
            a = a.with_relay_url(r);
        }
        for d in h.direct {
            a = a.with_ip_addr(d);
        }
        a
    }

    /// For an HTTP client's resolver: a seller's link host name ([`host_for`]), or a shop host bound
    /// with [`Link::bind_shop`], resolves to its loopback port; any other name is `None`, for the
    /// client's usual resolver. An unbound shop host is an error: it never goes to DNS.
    pub fn resolve(self: &Arc<Self>, host_port: &str) -> Option<io::Result<Vec<SocketAddr>>> {
        let host = host_port.rsplit_once(':').map_or(host_port, |(h, _)| h).to_ascii_lowercase();
        let port = if let Some(label) = host.strip_suffix(HOST_SUFFIX) {
            id_from_label(label).and_then(|hex| self.local_port(&hex))
        } else if host.ends_with(SHOP_SUFFIX) {
            self.shop_port(&host)
        } else {
            return None;
        };
        Some(port.map(|p| vec![SocketAddr::from((Ipv4Addr::LOCALHOST, p))]))
    }
}

/// How long a buyer waits for a stream on a shop's link key before trying its next one beside it.
const RACE_AFTER: std::time::Duration = std::time::Duration::from_millis(500);

/// A shop's link keys in the order this buyer (`me`) tries them: by the hash of the buyer's key, the
/// shop and the link key (rendezvous hashing), so buyers spread evenly over a shop's keys, each
/// buyer keeps to the same one, and a key added or removed moves only the buyers it takes or had.
pub fn order(me: &EndpointId, shop_host: &str, mut ids: Vec<EndpointId>) -> Vec<EndpointId> {
    ids.sort_by_cached_key(|id| {
        let mut h = sha2::Sha256::new();
        h.update(b"lightning-stream/link-order/1");
        h.update(me.as_bytes());
        h.update(shop_host.to_ascii_lowercase().as_bytes());
        h.update(id.as_bytes());
        <[u8; 32]>::from(h.finalize())
    });
    ids.dedup();
    ids
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

fn relay_map(urls: &[String]) -> io::Result<RelayMap> {
    let urls = urls.iter().map(|u| u.parse::<RelayUrl>()).collect::<Result<Vec<_>, _>>().map_err(io_err)?;
    Ok(RelayMap::from_iter(urls))
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
async fn open(ep: &Endpoint, addr: &EndpointAddr, conn: &tokio::sync::Mutex<Option<Connection>>,
              paths: &Arc<Mutex<HashMap<EndpointId, Path>>>, detail: bool, alpn: &[u8]) -> Option<(SendStream, RecvStream)> {
    let mut c = conn.lock().await;
    if let Some(live) = c.as_ref() {
        if let Ok(s) = live.open_bi().await {
            return Some(s);
        }
    }
    let fresh = ep.connect(addr.clone(), alpn).await.ok()?;
    watch(fresh.clone(), paths.clone(), detail);
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
    fn buyers_spread_evenly_over_a_shops_keys_and_each_keeps_its_own() {
        let key = |b: u8| SecretKey::from_bytes(&[b; 32]).public();
        let shop = "abc.shop.invalid";
        let keys: Vec<EndpointId> = (1..=4).map(key).collect();
        let mut firsts = [0usize; 4];
        for b in 0..200u8 {
            let me = SecretKey::from_bytes(&[b, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]).public();
            let o = order(&me, shop, keys.clone());
            assert_eq!(o.len(), 4);
            assert_eq!(o, order(&me, &shop.to_ascii_uppercase(), keys.iter().rev().copied().collect()), "the order is the buyer's, not the document's");
            firsts[keys.iter().position(|k| *k == o[0]).unwrap()] += 1;
            // a key taken away moves only the buyers that had it
            let fewer: Vec<EndpointId> = keys[..3].to_vec();
            if o[0] != keys[3] {
                assert_eq!(order(&me, shop, fewer)[0], o[0]);
            }
        }
        assert!(firsts.iter().all(|n| (30..=70).contains(n)), "{firsts:?}");
    }

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
