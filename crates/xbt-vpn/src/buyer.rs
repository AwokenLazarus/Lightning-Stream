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
use xbt_iroh_link::{Link, LinkConnection};

use crate::flow::{open_tcp, recv_udp, send_udp, Opened};
use rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;
use crate::meter::Meter;
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

/// The resolver a buyer with private exits asks, over DNS-over-TLS through the tunnel.
#[derive(Clone)]
pub struct EncryptedDns {
    pub addr: SocketAddr,
    pub name: ServerName<'static>,
    pub tls: Arc<rustls::ClientConfig>,
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
        let name = ServerName::try_from(name.to_string()).map_err(io::Error::other)?;
        Ok(EncryptedDns { addr, name, tls: Arc::new(tls) })
    }

    /// Quad9's public resolver over TLS (it keeps no logs, and blocks known malicious domains); the
    /// buyer can choose another.
    pub fn quad9() -> EncryptedDns {
        Self::new(([9, 9, 9, 9], 853).into(), "dns.quad9.net").expect("a valid name")
    }
}

/// An exit the buyer is connected to, and where its UDP answers go.
struct ExitConn {
    conn: LinkConnection,
    udp: Arc<Mutex<HashMap<u32, mpsc::Sender<Bytes>>>>,
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
    /// Flows refused (no exit, a device over its limit, an exit's refusal).
    pub refused: AtomicU64,
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
            refused: AtomicU64::new(0),
        })
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

    /// Asks the buyer's own resolver one DNS question, over TLS through an exit.
    async fn resolve(self: &Arc<Self>, device: IpAddr, query: &[u8]) -> Option<Vec<u8>> {
        let dns = self.dns.as_ref()?;
        let (exit_id, exit) = self.route(device, dns.addr).await?;
        let answer = async {
            let (opened, send, recv) = open_tcp(&exit.conn, dns.addr).await.ok()?;
            if opened != Opened::Yes {
                return None;
            }
            let mut tls = TlsConnector::from(dns.tls.clone()).connect(dns.name.clone(), tokio::io::join(recv, send)).await.ok()?;
            let mut msg = (query.len() as u16).to_be_bytes().to_vec();
            msg.extend_from_slice(query);
            tls.write_all(&msg).await.ok()?;
            let mut len = [0u8; 2];
            tls.read_exact(&mut len).await.ok()?;
            let mut a = vec![0u8; usize::from(u16::from_be_bytes(len))];
            tls.read_exact(&mut a).await.ok()?;
            Some(a)
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
    async fn exit(self: &Arc<Self>, id: &str) -> Option<Arc<ExitConn>> {
        let mut ex = self.exits.lock().await;
        if let Some(e) = ex.get(id) {
            if e.conn.close_reason().is_none() {
                return Some(e.clone());
            }
        }
        let conn = match self.link.connect_conn_async(id).await {
            Ok(c) => c,
            Err(_) => {
                self.router.lock().await.fail(id);
                return None;
            }
        };
        let e = Arc::new(ExitConn { conn: conn.clone(), udp: Arc::new(Mutex::new(HashMap::new())) });
        // the exit's UDP answers, to the flow each belongs to
        let routes = e.udp.clone();
        tokio::spawn(async move {
            while let Ok((flow, payload)) = recv_udp(&conn).await {
                if let Some(tx) = routes.lock().await.get(&flow) {
                    let _ = tx.try_send(payload);
                }
            }
        });
        ex.insert(id.to_string(), e.clone());
        Some(e)
    }

    /// The exit for a new flow and the connection to it; tries the router's next choice if the first
    /// cannot be reached.
    async fn route(self: &Arc<Self>, device: IpAddr, dst: SocketAddr) -> Option<(String, Arc<ExitConn>)> {
        for _ in 0..3 {
            let id = self.router_for(device).lock().await.pick(dst.ip(), Instant::now())?;
            if let Some(e) = self.exit(&id).await {
                return Some((id, e));
            }
            self.router_for(device).lock().await.fail(&id);
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
    }

    fn refuse(&self) {
        self.refused.fetch_add(1, Ordering::Relaxed);
    }

    async fn tcp(self: Arc<Self>, s: ipstack::IpStackTcpStream) {
        let (src, dst) = (s.local_addr(), s.peer_addr());
        let Some(dev) = self.device(src.ip()).filter(|d| !d.over_limit()) else { return self.refuse() };
        let Some((exit_id, exit)) = self.route(src.ip(), dst).await else { return self.refuse() };
        let opened = open_tcp(&exit.conn, dst).await;
        let (send, recv) = match opened {
            Ok((Opened::Yes, send, recv)) => (send, recv),
            _ => {
                self.router_for(src.ip()).lock().await.flow_ended(&exit_id);
                return self.refuse();
            }
        };
        let (r, w) = tokio::io::split(s);
        let (d1, d2, d3, d4) = (dev.clone(), dev.clone(), dev.clone(), dev);
        let (me1, me2, e1, e2, ip) = (self.clone(), self.clone(), exit_id.clone(), exit_id.clone(), src.ip());
        tokio::join!(
            pump(r, send, move |n| d1.meter.up(n), d2, move || me1.still_qualifies(ip, &e1)),
            pump(recv, w, move |n| d3.meter.down(n), d4, move || me2.still_qualifies(ip, &e2))
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
