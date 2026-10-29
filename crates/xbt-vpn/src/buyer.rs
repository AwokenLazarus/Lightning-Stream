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
use xbt_iroh_link::{Link, LinkConnection, ALPN_VPN_HOP};

use crate::flow::{open_tcp, open_tcp_on, recv_udp, send_udp, Opened};
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

/// An exit the buyer is connected to, and where its UDP answers go.
struct ExitConn {
    conn: LinkConnection,
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

/// A flow's stream to its exit, straight or sealed through a first hop.
trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

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
    /// Where an exit's egress address is read: a trace page through the exit (address, Host, path).
    egress_echo: RwLock<(SocketAddr, String, String)>,
}

/// The trace page an exit's egress address is read from, through that exit: 1.1.1.1 prints the
/// address the request came from. Only the exit's address reaches it, never the buyer's.
pub const EGRESS_ECHO: (&str, &str, &str) = ("1.1.1.1:80", "one.one.one.one", "/cdn-cgi/trace");

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
            egress_echo: RwLock::new((EGRESS_ECHO.0.parse().expect("an address"), EGRESS_ECHO.1.into(), EGRESS_ECHO.2.into())),
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

    /// Reads exits' egress addresses from another trace page (tests).
    pub fn set_egress_echo(&self, addr: SocketAddr, host: &str, path: &str) {
        *self.egress_echo.write().unwrap_or_else(|e| e.into_inner()) = (addr, host.into(), path.into());
    }

    /// Checks the region an exit announced: its egress address, read through the exit itself, must
    /// be in that country by the offline table, and the round trip to it must not be faster than the
    /// distance from the owner's country allows. Nothing about the buyer leaves the box: the trace
    /// page sees only the exit's address.
    pub async fn verify_region(self: &Arc<Self>, id: &str, announced: &str) -> RegionCheck {
        let Some(geo) = self.geo.read().unwrap_or_else(|e| e.into_inner()).clone() else { return RegionCheck::Unknown };
        let (echo, host, path) = self.egress_echo.read().unwrap_or_else(|e| e.into_inner()).clone();
        let read = async {
            let conn = self.link.connect_conn_async(id).await.ok()?;
            let (Opened::Yes, mut send, mut recv) = open_tcp(&conn, echo).await.ok()? else { return None };
            let req = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
            send.write_all(req.as_bytes()).await.ok()?;
            let mut body = Vec::new();
            (&mut recv).take(16 * 1024).read_to_end(&mut body).await.ok()?;
            region::parse_trace(&String::from_utf8_lossy(&body))
        };
        let Some(egress) = tokio::time::timeout(Duration::from_secs(20), read).await.ok().flatten() else { return RegionCheck::Unknown };
        let rtt = self.link.path(id).map(|p| match p {
            xbt_iroh_link::Path::Direct { rtt_ms, .. } | xbt_iroh_link::Path::Relay { rtt_ms, .. } => rtt_ms as f64,
        });
        let home = self.home_country.read().unwrap_or_else(|e| e.into_inner()).clone();
        let km = home.and_then(|h| region::km_between(&h, announced));
        region::check(&geo, announced, egress, rtt, km)
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
        let key = match &hop {
            Some(h) => format!("{}>{id}", h.id),
            None => id.to_string(),
        };
        let mut ex = self.exits.lock().await;
        if let Some(e) = ex.get(&key) {
            if e.conn.close_reason().is_none() {
                return Some(e.clone());
            }
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
            let e = Arc::new(ExitConn { conn, udp: Arc::new(Mutex::new(HashMap::new())), sealed: Some(Sealed { exit, exit_relays, tls }) });
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
        let e = Arc::new(ExitConn { conn: conn.clone(), udp: Arc::new(Mutex::new(HashMap::new())), sealed: None });
        // the exit's UDP answers, to the flow each belongs to
        let routes = e.udp.clone();
        tokio::spawn(async move {
            while let Ok((flow, payload)) = recv_udp(&conn).await {
                if let Some(tx) = routes.lock().await.get(&flow) {
                    let _ = tx.try_send(payload);
                }
            }
        });
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
            let keys: Vec<String> = ex.keys().filter(|k| *k == id || k.ends_with(&suffix)).cloned().collect();
            keys.iter().filter_map(|k| ex.remove(k)).collect()
        };
        for e in gone {
            e.conn.close(0u32.into(), b"exit not answering");
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
                Ok(None) if exit.conn.close_reason().is_none() => {
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
                            if send_udp(&conn, flow, dst, &buf[..n]).is_ok() {
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
            let mut flow = open_sealed(&exit.conn, &s.exit, &s.exit_relays, s.tls.clone()).await.ok()?;
            (open_tcp_on(&mut flow, dst).await.ok()? == Opened::Yes).then(|| Box::new(flow) as Box<dyn Duplex>)
        }
        None => match open_tcp(&exit.conn, dst).await.ok()? {
            (Opened::Yes, send, recv) => Some(Box::new(tokio::io::join(recv, send))),
            _ => None,
        },
    }
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

