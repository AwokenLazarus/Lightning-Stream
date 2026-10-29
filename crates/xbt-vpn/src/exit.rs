//! A seller's exit: a buyer's flows become ordinary connections from the exit.
//!
//! The buyer's app sends each TCP connection as its own stream and UDP in datagrams
//! ([`crate::flow`]); the exit opens a real socket to the destination for each and joins the two. It
//! needs no TUN device, no NAT rule and no special capability, so it runs wherever the Stream app
//! does. ICMP (ping) is not carried.
//!
//! Every flow passes the exit's [`Policy`] first (blocked ports, IPv6, never the seller's own
//! network), and the bytes carried are counted by the buyer's [`Meter`], in sizes only. Nothing
//! records a destination.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use xbt_iroh_link::LinkConnection;

use crate::filter::Policy;
use crate::flow::{self, Opened, KIND_UDP_BACK, KIND_UDP_OUT};
use crate::meter::Meter;

/// How an exit treats its buyers.
#[derive(Clone, Debug)]
pub struct ExitConfig {
    pub policy: Policy,
    /// Each buyer's speed limit, each way, in bytes a second. `None`: no limit.
    pub buyer_bytes_per_sec: Option<u64>,
    /// How long the exit waits to reach a destination.
    pub connect_timeout: Duration,
    /// How long a UDP flow lives without a datagram.
    pub udp_idle: Duration,
    /// The most UDP flows one buyer may have open.
    pub max_udp_flows: usize,
}

impl Default for ExitConfig {
    /// [`Policy::for_exit`] (this machine's own networks refused), no speed limit.
    fn default() -> ExitConfig {
        ExitConfig { policy: Policy::for_exit(), buyer_bytes_per_sec: None, connect_timeout: Duration::from_secs(10), udp_idle: Duration::from_secs(60), max_udp_flows: 256 }
    }
}

/// A token bucket: at most `rate` bytes a second, with one second's worth in hand.
pub(crate) struct Bucket {
    rate: f64,
    tokens: f64,
    last: tokio::time::Instant,
}

impl Bucket {
    pub(crate) fn new(rate: u64) -> Bucket {
        Bucket { rate: rate as f64, tokens: rate as f64, last: tokio::time::Instant::now() }
    }

    /// How long to wait before sending `bytes` more.
    fn charge(&mut self, bytes: usize) -> Duration {
        let now = tokio::time::Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * self.rate).min(self.rate);
        self.last = now;
        self.tokens -= bytes as f64;
        if self.tokens < 0.0 { Duration::from_secs_f64(-self.tokens / self.rate) } else { Duration::ZERO }
    }
}

type Shared<T> = Arc<Mutex<T>>;

/// Copies one direction of a flow, counting what it carries and keeping to the buyer's speed limit.
async fn pump<R, W>(mut r: R, mut w: W, count: impl Fn(usize), bucket: Option<Shared<Bucket>>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if let Some(b) = &bucket {
            let wait = b.lock().await.charge(n);
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
        }
        if w.write_all(&buf[..n]).await.is_err() {
            break;
        }
        count(n);
    }
    let _ = w.shutdown().await;
}

/// Serves one buyer's connection until it closes: each TCP flow out as an ordinary connection, and
/// UDP flows as sockets of their own.
pub async fn serve_buyer(conn: LinkConnection, cfg: Arc<ExitConfig>, meter: Arc<Meter>) {
    let (up, down) = match cfg.buyer_bytes_per_sec {
        Some(r) => (Some(Arc::new(Mutex::new(Bucket::new(r)))), Some(Arc::new(Mutex::new(Bucket::new(r))))),
        None => (None, None),
    };
    let udp = tokio::spawn(serve_udp(conn.clone(), cfg.clone(), meter.clone()));
    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        let (cfg, meter, up, down) = (cfg.clone(), meter.clone(), up.clone(), down.clone());
        tokio::spawn(async move {
            let Ok(to) = flow::read_tcp_header(&mut recv).await else { return };
            if cfg.policy.check_dst(to).is_err() {
                meter.drop_one();
                let _ = send.write_all(&[Opened::Refused.byte()]).await;
                let _ = send.finish();
                return;
            }
            let out = match tokio::time::timeout(cfg.connect_timeout, TcpStream::connect(to)).await {
                Ok(Ok(s)) => s,
                _ => {
                    let _ = send.write_all(&[Opened::Unreachable.byte()]).await;
                    let _ = send.finish();
                    return;
                }
            };
            let _ = out.set_nodelay(true);
            if send.write_all(&[Opened::Yes.byte()]).await.is_err() {
                return;
            }
            let (or, ow) = out.into_split();
            let (m1, m2) = (meter.clone(), meter.clone());
            tokio::join!(pump(recv, ow, move |n| m1.up(n), up), pump(or, send, move |n| m2.down(n), down));
        });
    }
    udp.abort();
}

struct UdpFlow {
    sock: Arc<UdpSocket>,
    last: tokio::time::Instant,
    task: tokio::task::JoinHandle<()>,
}

/// The buyer's UDP datagrams: one socket per flow, answers sent back with the flow's number.
async fn serve_udp(conn: LinkConnection, cfg: Arc<ExitConfig>, meter: Arc<Meter>) {
    let flows: Shared<HashMap<u32, UdpFlow>> = Arc::new(Mutex::new(HashMap::new()));
    // close flows that have been idle
    let sweeper = {
        let (flows, idle) = (flows.clone(), cfg.udp_idle);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(idle / 4).await;
                flows.lock().await.retain(|_, f| {
                    let keep = f.last.elapsed() < idle;
                    if !keep {
                        f.task.abort();
                    }
                    keep
                });
            }
        })
    };
    while let Ok(d) = conn.read_datagram().await {
        if d.len() < 5 || d[0] != KIND_UDP_OUT {
            continue;
        }
        let id = u32::from_be_bytes([d[1], d[2], d[3], d[4]]);
        let Some((to, payload)) = flow::take_addr(&d[5..]) else { continue };
        if cfg.policy.check_dst(to).is_err() {
            meter.drop_one();
            continue;
        }
        let mut map = flows.lock().await;
        if !map.contains_key(&id) {
            if map.len() >= cfg.max_udp_flows {
                meter.drop_one();
                continue;
            }
            let bind: SocketAddr = if to.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { (std::net::Ipv6Addr::UNSPECIFIED, 0).into() };
            let Ok(sock) = UdpSocket::bind(bind).await else { continue };
            if sock.connect(to).await.is_err() {
                continue;
            }
            let sock = Arc::new(sock);
            let task = {
                let (sock, conn, meter) = (sock.clone(), conn.clone(), meter.clone());
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    while let Ok(n) = sock.recv(&mut buf).await {
                        let mut b = BytesMut::with_capacity(n + 5);
                        b.put_u8(KIND_UDP_BACK);
                        b.put_u32(id);
                        b.put_slice(&buf[..n]);
                        if conn.send_datagram(b.freeze()).is_ok() {
                            meter.down(n);
                        } else {
                            meter.drop_one();
                        }
                    }
                })
            };
            map.insert(id, UdpFlow { sock, last: tokio::time::Instant::now(), task });
        }
        let f = map.get_mut(&id).expect("just inserted");
        f.last = tokio::time::Instant::now();
        // a flow is bound to its first destination
        if f.sock.peer_addr().ok() != Some(to) {
            meter.drop_one();
            continue;
        }
        if f.sock.send(payload).await.is_ok() {
            meter.up(payload.len());
        }
    }
    sweeper.abort();
    for (_, f) in flows.lock().await.drain() {
        f.task.abort();
    }
}
