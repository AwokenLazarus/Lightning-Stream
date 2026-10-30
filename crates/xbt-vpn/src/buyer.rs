//! The buyer's side: the devices' connections ended on the buyer's own box and carried to exits.
//!
//! IP packets from the buyer's devices (through [`crate::wg`]) go into a TCP/IP stack in user space.
//! The link between the devices and this stack is in-process and lossless, which a userspace stack
//! needs. Each TCP connection and UDP flow the stack accepts is given an exit by the [`Router`] and
//! carried there as a flow ([`crate::flow`]).
//!
//! There is no way out except through an exit: a flow with no usable exit, or from a device past its
//! limit, is refused. That is the kill switch: traffic never falls back to the buyer's own
//! connection. IPv6 from devices is refused unless an exit carries it.
//!
//! With private exits (the default), the buyer's app answers every DNS question its devices ask
//! itself, over DNS-over-TLS through the tunnel to a resolver of the buyer's choice
//! ([`EncryptedDns`]), so no DNS question reaches the exit and browsers can use Encrypted
//! ClientHello where sites offer it. With filtered exits, DNS goes to the exit's resolver.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ipstack::{IpStack, IpStackConfig, IpStackStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Mutex};
use xbt_iroh_link::{Link, ALPN_VPN_HOP};

use crate::flow::{open_tcp_on, Carrier, Duplex, Opened};
use crate::hop::open_sealed;
use crate::sealed;
use rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;
use crate::meter::Meter;
use crate::region::{self, GeoTable, RegionCheck};
use crate::router::{ExitInfo, Requirements, Router};
use std::collections::HashSet;
use std::sync::RwLock;
use crate::tunnel::TUNNEL_MTU;

/// One of the buyer's devices (a phone, a laptop, a router): its tunnel address, what it has used,
/// its limit, and the exits it may use.
#[derive(Debug, Default)]
pub struct Device {
    pub name: String,
    pub meter: Meter,
    /// Bytes this device may carry in all, each way counted. `None`: only the wallet's rules limit it.
    pub limit_bytes: Option<u64>,
    /// This device's own saved policy (e.g. a TV: private, Germany). `None`: the buyer's default.
    pub requirements: Option<Requirements>,
}

impl Device {
    pub fn over_limit(&self) -> bool {
        self.limit_bytes.is_some_and(|l| self.meter.counts().total_bytes() >= l)
    }
}

/// The resolver a buyer with private exits asks, over DNS-over-TLS through the tunnel, and over
/// DNS-over-HTTPS (port 443) where the exit's network blocks DNS-over-TLS (port 853), as many home
/// and office networks do.
#[derive(Clone)]
pub struct EncryptedDns {
    pub addr: SocketAddr,
    pub name: ServerName<'static>,
    pub tls: Arc<rustls::ClientConfig>,
    /// DNS-over-HTTPS: the address and the path (`/dns-query`), asked when DNS-over-TLS fails.
    pub https: Option<(SocketAddr, String)>,
    https_tls: Arc<rustls::ClientConfig>,
    /// Set once DNS-over-TLS has failed and HTTPS answered: later questions go straight to HTTPS.
    tls_blocked: Arc<std::sync::atomic::AtomicBool>,
}

impl EncryptedDns {
    /// A resolver checked against Mozilla's roots.
    pub fn new(addr: SocketAddr, name: &str) -> io::Result<EncryptedDns> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_roots(addr, name, roots)
    }

    /// A resolver checked against these roots (a resolver of the buyer's own, or a test's).
    pub fn with_roots(addr: SocketAddr, name: &str, roots: rustls::RootCertStore) -> io::Result<EncryptedDns> {
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut https_tls = tls.clone();
        // DNS-over-HTTPS resolvers speak HTTP/2 (some refuse HTTP/1.1)
        https_tls.alpn_protocols = vec![b"h2".to_vec()];
        let name = ServerName::try_from(name.to_string()).map_err(io::Error::other)?;
        Ok(EncryptedDns { addr, name, tls: Arc::new(tls), https: None, https_tls: Arc::new(https_tls), tls_blocked: Arc::default() })
    }

    /// Also asks over DNS-over-HTTPS at `addr` and `path`, when DNS-over-TLS fails.
    pub fn with_https(mut self, addr: SocketAddr, path: &str) -> EncryptedDns {
        self.https = Some((addr, path.to_string()));
        self
    }

    /// Quad9's public resolver over TLS (it keeps no logs, and blocks known malicious domains); the
    /// buyer can choose another.
    pub fn quad9() -> EncryptedDns {
        Self::new(([9, 9, 9, 9], 853).into(), "dns.quad9.net").expect("a valid name").with_https(([9, 9, 9, 9], 443).into(), "/dns-query")
    }
}

/// How long reaching an exit may take before it counts as gone: a new flow fails over to the next
/// qualifying exit instead of waiting for the link's own, much longer, timeout.
pub const CONNECT_WAIT: Duration = Duration::from_secs(5);
/// How long an exit may take to open a flow on a connection that looks alive. An exit that went away
/// leaves its connection open until the link notices; this catches it first.
pub const OPEN_WAIT: Duration = Duration::from_secs(5);
/// How often exits that failed are tried again, so one that comes back is used again.
pub const PROBE_EVERY: Duration = Duration::from_secs(15);
/// A paid tunnel that ends this soon, having carried less than [`YOUNG_BYTES`], died young: its
/// exit is held off ([`crate::holds::Holds::young`]: 30 s, doubling to an hour, and its operator
/// with it if it does so often) instead of being paid to open again at once.
pub const YOUNG: Duration = Duration::from_secs(10);
pub const YOUNG_BYTES: u64 = 16 * 1024;
/// The most a region check of a priced exit may cost (sats): it reads four small pages.
pub const REGION_CHECK_MAX_SATS: u64 = 20;
/// How long an exit whose terms are above what it announced is not used (bait and switch).
pub use crate::holds::MISPRICED_HOLD;

/// An exit the buyer is connected to, and where its UDP answers go.
struct ExitConn {
    /// The link connection (a free exit, or the first hop), or a paid tunnel through the wallet.
    conn: Carrier,
    udp: Arc<Mutex<HashMap<u32, mpsc::Sender<Bytes>>>>,
    /// Through a first hop (two hops): `conn` is to the hop, and each flow is sealed for the exit.
    sealed: Option<Sealed>,
}

/// What a buyer needs to seal a flow for an exit behind a first hop.
struct Sealed {
    exit: [u8; 32],
    exit_relays: Vec<String>,
    tls: Arc<rustls::ClientConfig>,
}


/// The buyer's devices, router and exit connections.
pub struct Buyer {
    link: Arc<Link>,
    pub router: Mutex<Router>,
    /// Routers for devices with their own policy.
    device_routers: HashMap<IpAddr, Mutex<Router>>,
    /// Exits that stopped meeting a device's policy: that device's live flows on them end.
    disqualified: RwLock<HashSet<(IpAddr, String)>>,
    devices: HashMap<IpAddr, Arc<Device>>,
    dns: Option<EncryptedDns>,
    exits: Mutex<HashMap<String, Arc<ExitConn>>>,
    next_flow: AtomicU32,
    /// The key this buyer shows exits it reaches through a first hop: made for this run, it names
    /// nobody, and exits count and limit flows by it.
    sealed_secret: [u8; 32],
    /// UDP flows refused because two hops carry TCP only.
    pub udp_refused_two_hop: AtomicU64,
    /// Flows refused (no exit, a device over its limit, an exit's refusal).
    pub refused: AtomicU64,
    /// The offline geo-IP table exits' regions are checked against; none means no region is verified.
    geo: RwLock<Option<Arc<GeoTable>>>,
    /// The owner's own country, if they gave it: a lower bound on the distance to an exit's region,
    /// so a round trip too fast for the claimed region is caught. Never looked up from the network.
    home_country: RwLock<Option<String>>,
    /// A plain trace page to read exits' egress address from instead of [`region::EGRESS_SOURCES`]
    /// (address, Host, path): tests only.
    egress_echo: RwLock<Option<(SocketAddr, String, String)>>,
    /// What each exit's last region check found, for the status page: (announced, result, when).
    regions: RwLock<HashMap<String, (String, RegionCheck, std::time::SystemTime)>>,
    /// The owner's wallet, which pays for priced exits; none: only free exits are used.
    wallet: RwLock<Option<Arc<crate::paid::Wallet>>>,
    /// Where each priced exit's paid tunnel opens (its announced `tunnel`), the price it announced
    /// (msat a GB, the most the wallet pays it) and its operator, by exit id.
    tunnels: RwLock<HashMap<String, (String, u64, String)>>,
    /// One opening of a paid tunnel at a time for each key, without holding [`Self::exits`] while
    /// the wallet pays: other devices' and exits' flows go on.
    opening: std::sync::Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Exits (and operators) not to open paid tunnels to for a while, and each exit's openings today.
    holds: std::sync::Mutex<crate::holds::Holds>,
}


impl Buyer {
    /// `devices`: each device's tunnel address and its state. `dns`: the resolver the buyer's app asks
    /// itself (private exits); `None` sends DNS to the exit (filtered exits).
    pub fn new(link: Arc<Link>, router: Router, devices: HashMap<IpAddr, Arc<Device>>, dns: Option<EncryptedDns>) -> Arc<Buyer> {
        let device_routers = devices
            .iter()
            .filter_map(|(ip, d)| {
                let req = d.requirements.clone()?;
                let mut r = Router::with_requirements(req);
                for e in router.exits() {
                    r.upsert(e.clone());
                }
                Some((*ip, Mutex::new(r)))
            })
            .collect();
        Arc::new(Buyer {
            link,
            router: Mutex::new(router),
            device_routers,
            disqualified: RwLock::new(HashSet::new()),
            devices,
            dns,
            exits: Mutex::new(HashMap::new()),
            next_flow: AtomicU32::new(1),
            sealed_secret: rand_secret(),
            udp_refused_two_hop: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            geo: RwLock::new(None),
            home_country: RwLock::new(None),
            egress_echo: RwLock::new(None),
            regions: RwLock::new(HashMap::new()),
            wallet: RwLock::new(None),
            tunnels: RwLock::new(HashMap::new()),
            opening: std::sync::Mutex::new(HashMap::new()),
            holds: std::sync::Mutex::new(crate::holds::Holds::default()),
        })
    }

    /// The wallet that pays for priced exits ([`crate::paid`]).
    pub fn set_wallet(&self, w: Option<crate::paid::Wallet>) {
        *self.wallet.write().unwrap_or_else(|e| e.into_inner()) = w.map(Arc::new);
    }

    /// Where `id`'s paid tunnel opens, the price it announced (msat a GB) and who runs it (its
    /// operator's key); `None`: the exit is reached straight (a free exit). An exit held for asking
    /// more than it announced, which now announces more, is used again ([`crate::holds::Holds::announced`]).
    pub fn set_tunnel(&self, id: &str, url: Option<String>, price_msat_per_gb: u64, operator: &str) {
        let mut t = self.tunnels.write().unwrap_or_else(|e| e.into_inner());
        match url {
            Some(u) => {
                self.holds().announced(id, operator, price_msat_per_gb);
                t.insert(id.to_string(), (u, price_msat_per_gb, operator.to_string()))
            }
            None => t.remove(id),
        };
    }

    fn tunnel_of(&self, id: &str) -> Option<(String, u64, String)> {
        self.tunnels.read().unwrap_or_else(|e| e.into_inner()).get(id).cloned()
    }

    fn holds(&self) -> std::sync::MutexGuard<'_, crate::holds::Holds> {
        self.holds.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn operator_of(&self, id: &str) -> String {
        self.tunnel_of(id).map(|t| t.2).unwrap_or_default()
    }

    /// Whether `id` (or its operator) is held off: tunnels that died young, or terms above an announcement.
    pub fn is_held_off(&self, id: &str) -> bool {
        let op = self.operator_of(id);
        self.holds().held(id, &op, Instant::now())
    }

    /// Opens a paid tunnel to `id` at `url`, paying no more than its announced price (and, for a
    /// one-off check, no more than `max_sats`). An exit whose terms are above its announcement is
    /// held off for a day.
    /// `cap`: what the day's openings are counted by (a device and the exit, or a region check of it).
    async fn open_paid(&self, id: &str, cap: &str, url: &str, price: u64, max_sats: Option<u64>) -> Option<crate::paid::Tunnel> {
        let mut w = (*self.wallet.read().unwrap_or_else(|e| e.into_inner()).clone()?).clone();
        // held off, or opened enough today: each opening pays its head, so none more
        let op = self.operator_of(id);
        {
            let mut h = self.holds();
            let now = Instant::now();
            if h.held(id, &op, now) || !h.may_open(cap, now) {
                return None;
            }
        }
        if let Some(m) = max_sats {
            w.max_sats = w.max_sats.min(m);
        }
        match tokio::time::timeout(crate::paid::OPEN_WAIT, crate::paid::open(&w, url, Some(crate::paid::ceiling(price)))).await {
            Ok(Ok(t)) => {
                // its opening was paid: only now does it count toward the day's cap
                self.holds().opened(cap, Instant::now());
                Some(t)
            }
            Ok(Err(e)) => {
                if e.to_string().contains("price_ceiling") {
                    eprintln!("exit {}…: its terms are above the price it announced; not used for a day", &id[..12.min(id.len())]);
                    self.holds().mispriced(id, &op, price, Instant::now());
                }
                None
            }
            Err(_) => None,
        }
    }

    /// What carries flows to `id` for a one-off use (a region check): its paid tunnel, held to
    /// [`REGION_CHECK_MAX_SATS`], or the link.
    async fn carrier_once(&self, id: &str) -> Option<Carrier> {
        match self.tunnel_of(id) {
            Some(_) if self.is_held_off(id) => None,
            Some((url, price, _)) => Some(Carrier::Tunnel(self.open_paid(id, &format!("check#{id}"), &url, price, Some(REGION_CHECK_MAX_SATS)).await?.mux)),
            None => self.link.connect_conn_async(id).await.ok().map(Carrier::Link),
        }
    }

    /// Whether some device's own policy asks for `e`'s region and would otherwise take it: only
    /// then is a priced exit's region worth paying to check. Its kind, price, and the owner's
    /// exclusions must fit; its speed and health are measured after.
    pub fn region_wanted(&self, e: &ExitInfo) -> bool {
        self.devices.values().filter_map(|d| d.requirements.as_ref()).any(|r| {
            r.region.as_deref().is_some_and(|w| w.eq_ignore_ascii_case(&e.region))
                && r.max_price_msat_per_gb.is_none_or(|p| e.price_msat_per_gb <= p)
                && r.kind.allows(e)
                && !r.exclude.iter().any(|x| x == &e.id || x == &e.operator)
        })
    }

    /// The geo-IP table regions are checked against (see [`crate::region::load_or_fetch`]).
    pub fn set_geo(&self, t: GeoTable) {
        *self.geo.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(t));
    }

    /// The owner's own country (two letters), for the round-trip check; `None` skips that check.
    pub fn set_home_country(&self, cc: Option<String>) {
        *self.home_country.write().unwrap_or_else(|e| e.into_inner()) = cc.map(|c| c.to_ascii_uppercase());
    }

    /// Reads exits' egress addresses from one plain trace page instead of the HTTPS sources (tests).
    pub fn set_egress_echo(&self, addr: SocketAddr, host: &str, path: &str) {
        *self.egress_echo.write().unwrap_or_else(|e| e.into_inner()) = Some((addr, host.into(), path.into()));
    }

    /// The last region check of each exit: (exit id, announced region, result, when).
    pub fn region_results(&self) -> Vec<(String, String, RegionCheck, std::time::SystemTime)> {
        self.regions.read().unwrap_or_else(|e| e.into_inner()).iter().map(|(k, (r, c, t))| (k.clone(), r.clone(), c.clone(), *t)).collect()
    }

    /// One source's answer: the address it saw, read through `conn` (over TLS unless `tls` is None).
    async fn egress_from(conn: &Carrier, to: SocketAddr, host: &str, path: &str, trace: bool, tls: Option<&Arc<rustls::ClientConfig>>) -> Option<std::net::IpAddr> {
        let (Opened::Yes, Some(s)) = conn.open_tcp(to).await.ok()? else { return None };
        let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: lightning-stream\r\nConnection: close\r\n\r\n");
        let mut body = Vec::new();
        match tls {
            Some(cfg) => {
                let name = ServerName::try_from(host.to_string()).ok()?;
                let mut t = TlsConnector::from(cfg.clone()).connect(name, s).await.ok()?;
                t.write_all(req.as_bytes()).await.ok()?;
                let _ = (&mut t).take(16 * 1024).read_to_end(&mut body).await;
            }
            None => {
                let mut s = s;
                s.write_all(req.as_bytes()).await.ok()?;
                let _ = (&mut s).take(16 * 1024).read_to_end(&mut body).await;
            }
        }
        let text = String::from_utf8_lossy(&body);
        let (head, rest) = text.split_once("\r\n\r\n").unwrap_or(("", &text));
        if !head.is_empty() && !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
            return None;
        }
        region::parse_egress(rest, trace)
    }

    /// Checks the region an exit announced: its egress address, read through the exit itself, must
    /// be in that country by the offline table, and the round trip to it must not be faster than the
    /// distance from the owner's country allows. Nothing about the buyer leaves the box: the trace
    /// page sees only the exit's address.
    pub async fn verify_region(self: &Arc<Self>, id: &str, announced: &str) -> RegionCheck {
        let Some(geo) = self.geo.read().unwrap_or_else(|e| e.into_inner()).clone() else { return RegionCheck::Unknown };
        let test_echo = self.egress_echo.read().unwrap_or_else(|e| e.into_inner()).clone();
        let read = async {
            let conn = self.carrier_once(id).await?;
            let egress = match test_echo {
                Some((echo, host, path)) => Self::egress_from(&conn, echo, &host, &path, true, None).await.map(|a| (a, None)),
                None => {
                    // the sources' names are looked up here, by the buyer's own resolver; the requests go through the exit
                    let mut roots = rustls::RootCertStore::empty();
                    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                    let tls = Arc::new(rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                        .with_safe_default_protocol_versions().ok()?.with_root_certificates(roots).with_no_client_auth());
                    // four of the pool, drawn at random for this check; each asked over IPv4 and IPv6
                    let picked = region::pick_sources(region::SOURCES_PER_CHECK, || u64::from_le_bytes(rand_secret()[..8].try_into().unwrap_or([0; 8])));
                    let ask = |n: usize, v6: bool| {
                        let i = picked.get(n).copied();
                        let (conn, tls) = (&conn, &tls);
                        async move {
                            let (at, host, path, trace) = region::EGRESS_SOURCES[i?];
                            let to = tokio::net::lookup_host(at).await.ok()?.find(|a| a.is_ipv6() == v6)?;
                            tokio::time::timeout(Duration::from_secs(15), Self::egress_from(conn, to, host, path, trace, Some(tls))).await.ok().flatten()
                        }
                    };
                    let (a, b, c, d, e, f, g, h) = tokio::join!(ask(0, false), ask(1, false), ask(2, false), ask(3, false),
                                                                ask(0, true), ask(1, true), ask(2, true), ask(3, true));
                    let v6 = region::egress_quorum(&[e, f, g, h], 2).filter(std::net::IpAddr::is_ipv6);
                    region::egress_quorum(&[a, b, c, d], 2).map(|v4| (v4, v6))
                }
            };
            if let Carrier::Tunnel(m) = &conn {
                m.close();
            }
            egress
        };
        let Some((egress, egress_v6)) = tokio::time::timeout(Duration::from_secs(30), read).await.ok().flatten() else { return self.noted(id, announced, RegionCheck::Unknown) };
        let rtt = self.link.path(id).map(|p| match p {
            xbt_iroh_link::Path::Direct { rtt_ms, .. } | xbt_iroh_link::Path::Relay { rtt_ms, .. } => rtt_ms as f64,
        });
        let home = self.home_country.read().unwrap_or_else(|e| e.into_inner()).clone();
        let km = home.and_then(|h| region::km_between(&h, announced));
        let v6 = egress_v6.map(|a| region::check(&geo, announced, a, None, None));
        self.noted(id, announced, region::both_families(region::check(&geo, announced, egress, rtt, km), v6))
    }

    fn noted(&self, id: &str, announced: &str, r: RegionCheck) -> RegionCheck {
        self.regions.write().unwrap_or_else(|e| e.into_inner()).insert(id.to_string(), (announced.to_string(), r.clone(), std::time::SystemTime::now()));
        r
    }

    /// The router that decides for this device: its own policy's, or the buyer's default.
    fn router_for(&self, device: IpAddr) -> &Mutex<Router> {
        self.device_routers.get(&device).unwrap_or(&self.router)
    }

    /// What is known about an exit (a listing, a measurement, a health change), for every policy.
    pub async fn upsert_exit(&self, e: ExitInfo) {
        self.router.lock().await.upsert(e.clone());
        for r in self.device_routers.values() {
            r.lock().await.upsert(e.clone());
        }
    }

    /// Why this device's traffic is blocked, if no exit meets its policy: in plain words, naming the
    /// requirement that has no exit.
    pub async fn why_blocked(&self, device: IpAddr) -> Option<String> {
        self.router_for(device).lock().await.unmet().map(|u| u.0)
    }

    /// A new policy for a device (or the default, for `None`): new flows follow it at once, and live
    /// flows on exits that no longer qualify end. Returns those exits.
    pub async fn set_requirements(&self, device: Option<IpAddr>, req: Requirements) -> Vec<String> {
        let router = device.map_or(&self.router, |d| self.router_for(d));
        let gone = router.lock().await.set_requirements(req);
        let mut dq = self.disqualified.write().unwrap_or_else(|e| e.into_inner());
        let affected: Vec<IpAddr> = match device {
            Some(d) => vec![d],
            None => self.devices.keys().filter(|ip| !self.device_routers.contains_key(ip)).copied().collect(),
        };
        dq.retain(|(d, _)| !affected.contains(d));
        for d in affected {
            for g in &gone {
                dq.insert((d, g.clone()));
            }
        }
        gone
    }

    fn still_qualifies(&self, device: IpAddr, exit: &str) -> bool {
        !self.disqualified.read().unwrap_or_else(|e| e.into_inner()).contains(&(device, exit.to_string()))
    }

    /// Asks the buyer's own resolver one DNS question through an exit: over TLS, or over HTTPS where
    /// the exit's network blocks DNS-over-TLS.
    async fn resolve(self: &Arc<Self>, device: IpAddr, query: &[u8]) -> Option<Vec<u8>> {
        let dns = self.dns.as_ref()?;
        let blocked = dns.tls_blocked.load(Ordering::Relaxed);
        if !blocked || dns.https.is_none() {
            let wait = if dns.https.is_some() { Duration::from_secs(4) } else { Duration::from_secs(10) };
            if let Some(a) = self.resolve_tls(device, dns, query, wait).await {
                return Some(a);
            }
        }
        let (addr, path) = dns.https.as_ref()?;
        let a = self.resolve_https(device, dns, *addr, path, query).await;
        if a.is_some() && !blocked {
            dns.tls_blocked.store(true, Ordering::Relaxed);
        }
        a
    }

    async fn resolve_tls(self: &Arc<Self>, device: IpAddr, dns: &EncryptedDns, query: &[u8], wait: Duration) -> Option<Vec<u8>> {
        let (exit_id, exit) = self.route(device, dns.addr).await?;
        let answer = async {
            let flow = open_flow(&exit, dns.addr).await?;
            let mut tls = TlsConnector::from(dns.tls.clone()).connect(dns.name.clone(), flow).await.ok()?;
            let mut msg = (query.len() as u16).to_be_bytes().to_vec();
            msg.extend_from_slice(query);
            tls.write_all(&msg).await.ok()?;
            let mut len = [0u8; 2];
            tls.read_exact(&mut len).await.ok()?;
            let mut a = vec![0u8; usize::from(u16::from_be_bytes(len))];
            tls.read_exact(&mut a).await.ok()?;
            Some(a)
        };
        let a = tokio::time::timeout(wait, answer).await.ok().flatten();
        self.router_for(device).lock().await.flow_ended(&exit_id);
        a
    }

    async fn resolve_https(self: &Arc<Self>, device: IpAddr, dns: &EncryptedDns, addr: SocketAddr, path: &str, query: &[u8]) -> Option<Vec<u8>> {
        let (exit_id, exit) = self.route(device, addr).await?;
        let answer = async {
            let flow = open_flow(&exit, addr).await?;
            let tls = TlsConnector::from(dns.https_tls.clone()).connect(dns.name.clone(), flow).await.ok()?;
            let host = match &dns.name {
                ServerName::DnsName(n) => n.as_ref().to_string(),
                other => format!("{other:?}"),
            };
            let (mut client, conn) = h2::client::handshake(tls).await.ok()?;
            tokio::spawn(conn);
            let req = http::Request::post(format!("https://{host}{path}"))
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .body(())
                .ok()?;
            let (resp, mut body_out) = client.send_request(req, false).ok()?;
            body_out.send_data(Bytes::copy_from_slice(query), true).ok()?;
            let resp = resp.await.ok()?;
            if resp.status() != http::StatusCode::OK {
                return None;
            }
            let mut body = resp.into_body();
            let mut a = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.ok()?;
                let _ = body.flow_control().release_capacity(chunk.len());
                a.extend_from_slice(&chunk);
                if a.len() > 65535 {
                    return None;
                }
            }
            (a.len() >= 12).then_some(a)
        };
        let a = tokio::time::timeout(Duration::from_secs(10), answer).await.ok().flatten();
        self.router_for(device).lock().await.flow_ended(&exit_id);
        a
    }

    pub fn device(&self, ip: IpAddr) -> Option<Arc<Device>> {
        self.devices.get(&ip).cloned()
    }

    /// The connection to an exit, made on first use. A failed connection marks the exit failed in
    /// the router.
    async fn exit(self: &Arc<Self>, device: IpAddr, id: &str) -> Option<Arc<ExitConn>> {
        let hop = self.router_for(device).lock().await.first_hop_for(id);
        let tunnel = self.tunnel_of(id);
        let key = match (&hop, &tunnel) {
            (Some(h), _) => format!("{}>{id}", h.id),
            // a priced exit: one paid tunnel for each device, so each device's own limit holds
            (None, Some(_)) => format!("{device}#{id}"),
            (None, None) => id.to_string(),
        };
        let mut ex = self.exits.lock().await;
        if let Some(e) = ex.get(&key) {
            if !e.conn.is_closed() {
                return Some(e.clone());
            }
        }
        if let (None, Some((url, price, operator))) = (&hop, tunnel) {
            // the map is not held while the wallet pays: one opening per key, the rest go on
            drop(ex);
            if self.is_held_off(id) {
                self.fail_exit(id).await;
                return None;
            }
            let gate = self.opening.lock().unwrap_or_else(|e| e.into_inner()).entry(key.clone()).or_default().clone();
            let _one = gate.lock().await;
            if let Some(e) = self.exits.lock().await.get(&key).filter(|e| !e.conn.is_closed()) {
                return Some(e.clone());
            }
            let Some(t) = self.open_paid(id, &key, &url, price, None).await else {
                // a priced exit with no wallet to pay it, or one the wallet would not pay: not usable
                self.fail_exit(id).await;
                return None;
            };
            let (mux, opened_at, me, exit_id) = (t.mux.clone(), Instant::now(), self.clone(), id.to_string());
            let conn = Carrier::Tunnel(t.mux);
            // what the wallet said when the tunnel ended (charged, or why it stopped), for the log; a
            // tunnel that died young holds its exit off, so its opening is not paid for again and again
            std::thread::spawn(move || {
                if let Ok(Ok(v)) = t.done.recv() {
                    if let Some(why) = v.get("ended").and_then(serde_json::Value::as_str) {
                        eprintln!("a paid tunnel ended: {why}");
                    }
                }
                if opened_at.elapsed() < YOUNG && mux.received() < YOUNG_BYTES {
                    me.holds().young(&exit_id, &operator, Instant::now());
                } else {
                    me.holds().served(&exit_id);
                }
            });
            let e = Arc::new(ExitConn { conn: conn.clone(), udp: Arc::new(Mutex::new(HashMap::new())), sealed: None });
            spawn_udp_routes(conn, e.udp.clone());
            self.exits.lock().await.insert(key, e.clone());
            return Some(e);
        }
        if let Some(h) = hop {
            // two hops: a connection to the first hop; each flow is sealed for the exit
            let exit: [u8; 32] = hex::decode(id).ok()?.try_into().ok()?;
            let conn = match tokio::time::timeout(CONNECT_WAIT, self.link.connect_conn_alpn(&h.id, ALPN_VPN_HOP)).await {
                Ok(Ok(c)) => c,
                _ => {
                    drop(ex);
                    self.fail_exit(id).await;
                    return None;
                }
            };
            let tls = sealed::buyer_config(&self.sealed_secret, &exit);
            let exit_relays = self.link.hints_for(id).relays;
            let e = Arc::new(ExitConn { conn: Carrier::Link(conn), udp: Arc::new(Mutex::new(HashMap::new())), sealed: Some(Sealed { exit, exit_relays, tls }) });
            ex.insert(key, e.clone());
            return Some(e);
        }
        let conn = match tokio::time::timeout(CONNECT_WAIT, self.link.connect_conn_async(id)).await {
            Ok(Ok(c)) => c,
            _ => {
                drop(ex);
                self.fail_exit(id).await;
                return None;
            }
        };
        let conn = Carrier::Link(conn);
        let e = Arc::new(ExitConn { conn: conn.clone(), udp: Arc::new(Mutex::new(HashMap::new())), sealed: None });
        spawn_udp_routes(conn, e.udp.clone());
        ex.insert(key, e.clone());
        Some(e)
    }

    /// The exit for a new flow and the connection to it; tries the router's next choice if the first
    /// cannot be reached.
    async fn route(self: &Arc<Self>, device: IpAddr, dst: SocketAddr) -> Option<(String, Arc<ExitConn>)> {
        for _ in 0..3 {
            let id = self.router_for(device).lock().await.pick(dst.ip(), Instant::now())?;
            if let Some(e) = self.exit(device, &id).await {
                return Some((id, e));
            }
        }
        None
    }

    /// Marks an exit failed for every policy, and forgets its connections (straight and through any
    /// first hop): no new flow waits on it until a probe finds it answering again.
    async fn fail_exit(&self, id: &str) {
        self.router.lock().await.fail(id);
        for r in self.device_routers.values() {
            r.lock().await.fail(id);
        }
        let suffix = format!(">{id}");
        let gone: Vec<Arc<ExitConn>> = {
            let mut ex = self.exits.lock().await;
            let paid = format!("#{id}");
            let keys: Vec<String> = ex.keys().filter(|k| *k == id || k.ends_with(&suffix) || k.ends_with(&paid)).cloned().collect();
            keys.iter().filter_map(|k| ex.remove(k)).collect()
        };
        for e in gone {
            match &e.conn {
                Carrier::Link(c) => c.close(0u32.into(), b"exit not answering"),
                Carrier::Tunnel(m) => m.close(),
            }
        }
    }

    /// The exits marked failed (by the buyer's default policy).
    pub async fn failed_exits(&self) -> Vec<String> {
        self.router.lock().await.failed()
    }

    /// Marks an exit answering again, for every policy.
    async fn recover_exit(&self, id: &str) {
        self.router.lock().await.recover(id);
        for r in self.device_routers.values() {
            r.lock().await.recover(id);
        }
    }

    /// Tries every failed exit again every [`PROBE_EVERY`]: one that answers is used again.
    async fn probe_failed(self: Arc<Self>) {
        loop {
            tokio::time::sleep(PROBE_EVERY).await;
            let mut failed = self.router.lock().await.failed();
            for r in self.device_routers.values() {
                failed.extend(r.lock().await.failed());
            }
            failed.sort();
            failed.dedup();
            for id in failed {
                if let Ok(Ok(c)) = tokio::time::timeout(CONNECT_WAIT, self.link.connect_conn_async(&id)).await {
                    c.close(0u32.into(), b"probe");
                    self.recover_exit(&id).await;
                }
            }
        }
    }

    /// A TCP flow to `dst` on an exit qualifying for this device: when an exit cannot open it in
    /// [`OPEN_WAIT`] (gone, or refusing), that exit is marked failed and the next one is tried.
    /// `None` if no qualifying exit opens it.
    async fn open_tcp_flow(self: &Arc<Self>, device: IpAddr, dst: SocketAddr) -> Option<(String, Box<dyn Duplex>)> {
        for _ in 0..3 {
            let (exit_id, exit) = self.route(device, dst).await?;
            match tokio::time::timeout(OPEN_WAIT, open_flow(&exit, dst)).await {
                Ok(Some(flow)) => return Some((exit_id, flow)),
                // the exit answered and refused (its policy, or `dst` unreachable from it): not its fault
                Ok(None) if !exit.conn.is_closed() => {
                    self.router_for(device).lock().await.flow_ended(&exit_id);
                    return None;
                }
                // no answer in time, or the connection closed under us: the exit is gone
                _ => {
                    self.router_for(device).lock().await.flow_ended(&exit_id);
                    self.fail_exit(&exit_id).await;
                }
            }
        }
        None
    }

    /// Runs the stack on packets from the devices (`from_devices`) and answers to them (`to_devices`)
    /// until the packet source ends.
    pub async fn run(self: Arc<Self>, from_devices: mpsc::Receiver<Bytes>, to_devices: mpsc::UnboundedSender<Bytes>) {
        let device = PacketPipe { from: from_devices, to: to_devices };
        let mut sc = IpStackConfig::default();
        sc.mtu_unchecked(TUNNEL_MTU as u16).udp_timeout(Duration::from_secs(60));
        let mut stack = IpStack::new(sc, device);
        let probes = tokio::spawn(self.clone().probe_failed());
        while let Ok(s) = stack.accept().await {
            let me = self.clone();
            tokio::spawn(async move {
                match s {
                    IpStackStream::Tcp(t) => me.tcp(t).await,
                    IpStackStream::Udp(u) => me.udp(u).await,
                    _ => {}
                }
            });
        }
        probes.abort();
    }

    fn refuse(&self) {
        self.refused.fetch_add(1, Ordering::Relaxed);
    }

    async fn tcp(self: Arc<Self>, s: ipstack::IpStackTcpStream) {
        let (src, dst) = (s.local_addr(), s.peer_addr());
        let Some(dev) = self.device(src.ip()).filter(|d| !d.over_limit()) else { return self.refuse() };
        let Some((exit_id, flow)) = self.open_tcp_flow(src.ip(), dst).await else { return self.refuse() };
        let (r, w) = tokio::io::split(s);
        let (fr, fw) = tokio::io::split(flow);
        let (d1, d2, d3, d4) = (dev.clone(), dev.clone(), dev.clone(), dev);
        let (me1, me2, e1, e2, ip) = (self.clone(), self.clone(), exit_id.clone(), exit_id.clone(), src.ip());
        tokio::join!(
            pump(r, fw, move |n| d1.meter.up(n), d2, move || me1.still_qualifies(ip, &e1)),
            pump(fr, w, move |n| d3.meter.down(n), d4, move || me2.still_qualifies(ip, &e2))
        );
        self.router_for(src.ip()).lock().await.flow_ended(&exit_id);
    }

    async fn udp(self: Arc<Self>, s: ipstack::IpStackUdpStream) {
        let (src, dst) = (s.local_addr(), s.peer_addr());
        let Some(dev) = self.device(src.ip()).filter(|d| !d.over_limit()) else { return self.refuse() };
        if dst.port() == 53 && self.dns.is_some() {
            return self.answer_dns(s, src.ip(), dev).await;
        }
        let Some((exit_id, exit)) = self.route(src.ip(), dst).await else { return self.refuse() };
        if exit.sealed.is_some() {
            // two hops carry TCP only; QUIC and the like fall back to TCP
            self.udp_refused_two_hop.fetch_add(1, Ordering::Relaxed);
            self.router_for(src.ip()).lock().await.flow_ended(&exit_id);
            return self.refuse();
        }
        let flow = self.next_flow.fetch_add(1, Ordering::Relaxed);
        let (tx, mut rx) = mpsc::channel::<Bytes>(256);
        exit.udp.lock().await.insert(flow, tx);
        let (mut r, mut w) = tokio::io::split(s);
        let out = {
            let (dev, conn) = (dev.clone(), exit.conn.clone());
            async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match r.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if dev.over_limit() {
                                return;
                            }
                            if conn.send_udp(flow, dst, &buf[..n]).is_ok() {
                                dev.meter.up(n);
                            }
                        }
                    }
                }
            }
        };
        let back = async move {
            while let Some(p) = rx.recv().await {
                if w.write_all(&p).await.is_err() {
                    return;
                }
                dev.meter.down(p.len());
            }
        };
        tokio::select! { _ = out => {}, _ = back => {} }
        exit.udp.lock().await.remove(&flow);
        self.router_for(src.ip()).lock().await.flow_ended(&exit_id);
    }
}

impl Buyer {
    /// A device's DNS, answered by the buyer's own resolver whatever address the device asked: no
    /// DNS question reaches the exit.
    async fn answer_dns(self: Arc<Self>, s: ipstack::IpStackUdpStream, device: IpAddr, dev: Arc<Device>) {
        let (mut r, mut w) = tokio::io::split(s);
        let mut buf = vec![0u8; 4096];
        while let Ok(n) = r.read(&mut buf).await {
            if n == 0 || dev.over_limit() {
                return;
            }
            dev.meter.up(n);
            if let Some(a) = self.resolve(device, &buf[..n]).await {
                if w.write_all(&a).await.is_err() {
                    return;
                }
                dev.meter.down(a.len());
            }
        }
    }
}

/// Opens a TCP flow to `dst` on an exit connection: a stream of its own, or a sealed session through
/// a first hop. `None` if the exit refused or could not reach `dst`.
async fn open_flow(exit: &ExitConn, dst: SocketAddr) -> Option<Box<dyn Duplex>> {
    match &exit.sealed {
        Some(s) => {
            let Carrier::Link(conn) = &exit.conn else { return None };
            let mut flow = open_sealed(conn, &s.exit, &s.exit_relays, s.tls.clone()).await.ok()?;
            (open_tcp_on(&mut flow, dst).await.ok()? == Opened::Yes).then(|| Box::new(flow) as Box<dyn Duplex>)
        }
        None => match exit.conn.open_tcp(dst).await.ok()? {
            (Opened::Yes, s) => s,
            _ => None,
        },
    }
}

/// The exit's UDP answers, to the flow each belongs to.
fn spawn_udp_routes(conn: Carrier, routes: Arc<Mutex<HashMap<u32, mpsc::Sender<Bytes>>>>) {
    tokio::spawn(async move {
        while let Ok((flow, payload)) = conn.recv_udp().await {
            if let Some(tx) = routes.lock().await.get(&flow) {
                let _ = tx.try_send(payload);
            }
        }
    });
}

/// A fresh random key, from the operating system.
fn rand_secret() -> [u8; 32] {
    let mut k = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut k).expect("the system's random source");
    k
}

/// Copies one direction of a flow, counting what it carries; stops when the device reaches its limit
/// or its exit stops meeting the device's policy.
async fn pump<R, W>(mut r: R, mut w: W, count: impl Fn(usize), dev: Arc<Device>, qualifies: impl Fn() -> bool)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        if dev.over_limit() || !qualifies() {
            break;
        }
        let n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if w.write_all(&buf[..n]).await.is_err() {
            break;
        }
        count(n);
    }
    let _ = w.shutdown().await;
}

/// The stack's packet device: packets from the devices in, packets to them out, with no loss (the
/// in-process link is what a userspace stack needs).
struct PacketPipe {
    from: mpsc::Receiver<Bytes>,
    to: mpsc::UnboundedSender<Bytes>,
}

impl AsyncRead for PacketPipe {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.from.poll_recv(cx) {
            Poll::Ready(Some(p)) => {
                let n = p.len().min(buf.remaining());
                buf.put_slice(&p[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for PacketPipe {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        // never dropped here: the WireGuard side drains these as fast as it encrypts them
        match self.to.send(Bytes::copy_from_slice(buf)) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

