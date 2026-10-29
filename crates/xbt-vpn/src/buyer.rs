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
use crate::meter::Meter;
use crate::router::Router;
use crate::tunnel::TUNNEL_MTU;

/// One of the buyer's devices (a phone, a laptop, a router): its tunnel address, what it has used,
/// and its limit.
#[derive(Debug)]
pub struct Device {
    pub name: String,
    pub meter: Meter,
    /// Bytes this device may carry in all, each way counted. `None`: only the wallet's rules limit it.
    pub limit_bytes: Option<u64>,
}

impl Device {
    pub fn over_limit(&self) -> bool {
        self.limit_bytes.is_some_and(|l| self.meter.counts().total_bytes() >= l)
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
    devices: HashMap<IpAddr, Arc<Device>>,
    exits: Mutex<HashMap<String, Arc<ExitConn>>>,
    next_flow: AtomicU32,
    /// Flows refused (no exit, a device over its limit, an exit's refusal).
    pub refused: AtomicU64,
}

impl Buyer {
    /// `devices`: each device's tunnel address and its state.
    pub fn new(link: Arc<Link>, router: Router, devices: HashMap<IpAddr, Arc<Device>>) -> Arc<Buyer> {
        Arc::new(Buyer { link, router: Mutex::new(router), devices, exits: Mutex::new(HashMap::new()), next_flow: AtomicU32::new(1), refused: AtomicU64::new(0) })
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
    async fn route(self: &Arc<Self>, dst: SocketAddr) -> Option<(String, Arc<ExitConn>)> {
        for _ in 0..3 {
            let id = self.router.lock().await.pick(dst.ip(), Instant::now())?;
            if let Some(e) = self.exit(&id).await {
                return Some((id, e));
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
        let Some((exit_id, exit)) = self.route(dst).await else { return self.refuse() };
        let opened = open_tcp(&exit.conn, dst).await;
        let (send, recv) = match opened {
            Ok((Opened::Yes, send, recv)) => (send, recv),
            _ => {
                self.router.lock().await.flow_ended(&exit_id);
                return self.refuse();
            }
        };
        let (r, w) = tokio::io::split(s);
        let (d1, d2, d3, d4) = (dev.clone(), dev.clone(), dev.clone(), dev);
        tokio::join!(pump(r, send, move |n| d1.meter.up(n), d2), pump(recv, w, move |n| d3.meter.down(n), d4));
        self.router.lock().await.flow_ended(&exit_id);
    }

    async fn udp(self: Arc<Self>, s: ipstack::IpStackUdpStream) {
        let (src, dst) = (s.local_addr(), s.peer_addr());
        let Some(dev) = self.device(src.ip()).filter(|d| !d.over_limit()) else { return self.refuse() };
        let Some((exit_id, exit)) = self.route(dst).await else { return self.refuse() };
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
        self.router.lock().await.flow_ended(&exit_id);
    }
}

/// Copies one direction of a flow, counting what it carries; stops when the device reaches its limit.
async fn pump<R, W>(mut r: R, mut w: W, count: impl Fn(usize), dev: Arc<Device>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        if dev.over_limit() {
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
