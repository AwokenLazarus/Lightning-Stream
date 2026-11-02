//! Two hops: a first hop, run by someone other than the exit, between a buyer and an exit.
//!
//! The buyer opens a stream to the first hop ([`ALPN_VPN_HOP`]) naming an exit; the hop opens a
//! stream on its own connection to that exit ([`ALPN_VPN_SEALED`]) and joins the two. Inside, the
//! buyer and the exit speak TLS 1.3 to each other ([`crate::sealed`]), so:
//! - the hop sees the buyer's address and which exit it asked for, never the destination or the
//!   bytes; it counts bytes and nothing else;
//! - the exit sees the hop's address, never the buyer's, and the destination as with any flow.
//!
//! Two hops carry TCP flows only (a private exit's DNS already goes over TLS); UDP, such as QUIC, is
//! refused, and browsers fall back to TCP.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use xbt_iroh_link::{Hints, Link, LinkConnection, ALPN_VPN_SEALED};

use crate::exit::{tcp_flow, Bucket, ExitConfig, Shared};
use crate::meter::Meter;
use crate::sealed;

const MAGIC: &[u8; 3] = b"XH0";
/// The most relay addresses a buyer may name for the exit.
const MAX_RELAYS: usize = 4;
/// The longest relay address the hop reads.
const MAX_RELAY_LEN: usize = 256;
/// How long a sealed session may take to start.
const HANDSHAKE_WAIT: Duration = Duration::from_secs(20);

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

/// How a first hop treats each buyer.
#[derive(Clone, Debug)]
pub struct HopConfig {
    /// The most streams one buyer may have open through the hop.
    pub max_streams: usize,
    /// Each buyer's speed limit through the hop, each way, in bytes a second.
    pub buyer_bytes_per_sec: Option<u64>,
}

impl Default for HopConfig {
    fn default() -> HopConfig {
        HopConfig { max_streams: 512, buyer_bytes_per_sec: None }
    }
}

/// A first hop's side of one buyer's connection: each stream it opens is joined to a stream on the
/// hop's own connection to the exit it names. The hop never reads past the header.
pub async fn serve_hop(link: Arc<Link>, conn: LinkConnection, cfg: Arc<HopConfig>, meter: Arc<Meter>) {
    let exits: Shared<HashMap<[u8; 32], LinkConnection>> = Arc::new(Mutex::new(HashMap::new()));
    let open = Arc::new(AtomicUsize::new(0));
    let (up, down) = match cfg.buyer_bytes_per_sec {
        Some(r) => (Some(Arc::new(Mutex::new(Bucket::new(r)))), Some(Arc::new(Mutex::new(Bucket::new(r))))),
        None => (None, None),
    };
    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        if open.load(Ordering::Relaxed) >= cfg.max_streams {
            meter.drop_one();
            let _ = send.finish();
            continue;
        }
        let guard = Count::new(open.clone());
        let (link, exits, meter, up, down) = (link.clone(), exits.clone(), meter.clone(), up.clone(), down.clone());
        tokio::spawn(async move {
            let _guard = guard;
            let Ok((exit, relays)) = read_header(&mut recv).await else { return };
            let Some(to_exit) = exit_conn(&link, &exits, exit, relays).await else {
                let _ = send.finish();
                return;
            };
            let Ok((es, er)) = to_exit.open_bi().await else {
                let _ = send.finish();
                return;
            };
            let (m1, m2) = (meter.clone(), meter.clone());
            tokio::join!(splice(recv, es, move |n| m1.up(n), up), splice(er, send, move |n| m2.down(n), down));
        });
    }
}

/// The hop's connection to an exit, made on first use for this buyer.
async fn exit_conn(link: &Arc<Link>, exits: &Shared<HashMap<[u8; 32], LinkConnection>>, exit: [u8; 32], relays: Vec<String>) -> Option<LinkConnection> {
    let mut ex = exits.lock().await;
    if let Some(c) = ex.get(&exit) {
        if c.close_reason().is_none() {
            return Some(c.clone());
        }
    }
    let hex = hex::encode(exit);
    if !relays.is_empty() && link.hints_for(&hex).relays.is_empty() {
        let _ = link.learn(&hex, Hints { relays, direct: vec![] });
    }
    let c = link.connect_conn_alpn(&hex, ALPN_VPN_SEALED).await.ok()?;
    ex.insert(exit, c.clone());
    Some(c)
}

async fn read_header<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<([u8; 32], Vec<String>)> {
    let mut head = [0u8; 3 + 32 + 1];
    r.read_exact(&mut head).await?;
    if &head[..3] != MAGIC {
        return Err(io_err("not a first-hop stream"));
    }
    let exit: [u8; 32] = head[3..35].try_into().map_err(io_err)?;
    let n = usize::from(head[35]).min(MAX_RELAYS);
    let mut relays = Vec::with_capacity(n);
    for _ in 0..n {
        let mut len = [0u8; 2];
        r.read_exact(&mut len).await?;
        let len = usize::from(u16::from_be_bytes(len));
        if len > MAX_RELAY_LEN {
            return Err(io_err("a relay address too long"));
        }
        let mut url = vec![0u8; len];
        r.read_exact(&mut url).await?;
        relays.push(String::from_utf8(url).map_err(io_err)?);
    }
    Ok((exit, relays))
}

fn header(exit: &[u8; 32], relays: &[String]) -> Vec<u8> {
    let relays: Vec<&String> = relays.iter().filter(|r| r.len() <= MAX_RELAY_LEN).take(MAX_RELAYS).collect();
    let mut h = MAGIC.to_vec();
    h.extend_from_slice(exit);
    h.push(relays.len() as u8);
    for r in relays {
        h.extend_from_slice(&(r.len() as u16).to_be_bytes());
        h.extend_from_slice(r.as_bytes());
    }
    h
}

/// Copies one direction without reading what it carries, counting bytes.
async fn splice<R, W>(mut r: R, mut w: W, count: impl Fn(usize), bucket: Option<Shared<Bucket>>)
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

/// A sealed session to the exit `exit` through the first hop `hop`: a stream the buyer's flow runs
/// on, readable only by the buyer and that exit.
pub async fn open_sealed(
    hop: &LinkConnection,
    exit: &[u8; 32],
    exit_relays: &[String],
    tls: Arc<rustls::ClientConfig>,
) -> io::Result<impl AsyncRead + AsyncWrite + Unpin + Send> {
    let (mut send, recv) = hop.open_bi().await.map_err(io_err)?;
    send.write_all(&header(exit, exit_relays)).await.map_err(io_err)?;
    let name = rustls::pki_types::ServerName::try_from(sealed::SEALED_NAME).map_err(io_err)?;
    let s = tokio::time::timeout(HANDSHAKE_WAIT, TlsConnector::from(tls).connect(name, tokio::io::join(recv, send)))
        .await
        .map_err(|_| io_err("the exit did not answer through the first hop"))??;
    Ok(s)
}

/// Each sealed buyer's state at an exit, by the key the buyer showed: flows open, speed limits.
#[derive(Default)]
pub struct SealedBuyers {
    by_key: std::sync::Mutex<HashMap<[u8; 32], Arc<SealedBuyer>>>,
}

struct SealedBuyer {
    open: Arc<AtomicUsize>,
    up: Option<Shared<Bucket>>,
    down: Option<Shared<Bucket>>,
}

impl SealedBuyers {
    fn get(&self, key: [u8; 32], cfg: &ExitConfig) -> Arc<SealedBuyer> {
        let mut m = self.by_key.lock().unwrap_or_else(|e| e.into_inner());
        m.retain(|_, b| Arc::strong_count(b) > 1 || b.open.load(Ordering::Relaxed) > 0);
        m.entry(key)
            .or_insert_with(|| {
                let (up, down) = match cfg.buyer_bytes_per_sec {
                    Some(r) => (Some(Arc::new(Mutex::new(Bucket::new(r)))), Some(Arc::new(Mutex::new(Bucket::new(r))))),
                    None => (None, None),
                };
                Arc::new(SealedBuyer { open: Arc::new(AtomicUsize::new(0)), up, down })
            })
            .clone()
    }

    /// How many buyers' keys the exit is holding state for now.
    pub fn len(&self) -> usize {
        self.by_key.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// An exit's side of a first hop's connection: each stream is one buyer's sealed session, inside
/// which runs one flow, under the same policy, limits and meter as a buyer's own connection. The
/// exit sees only the hop's address.
pub async fn serve_sealed(conn: LinkConnection, cfg: Arc<ExitConfig>, meter: Arc<Meter>, tls: Arc<rustls::ServerConfig>, buyers: Arc<SealedBuyers>) {
    let acceptor = TlsAcceptor::from(tls);
    while let Ok((send, recv)) = conn.accept_bi().await {
        let (cfg, meter, acceptor, buyers) = (cfg.clone(), meter.clone(), acceptor.clone(), buyers.clone());
        tokio::spawn(async move {
            let Ok(Ok(s)) = tokio::time::timeout(HANDSHAKE_WAIT, acceptor.accept(tokio::io::join(recv, send))).await else { return };
            let Some(key) = sealed::buyer_key(s.get_ref().1) else { return };
            let b = buyers.get(key, &cfg);
            if b.open.load(Ordering::Relaxed) >= cfg.max_tcp_flows {
                meter.drop_one();
                return;
            }
            let _guard = Count::new(b.open.clone());
            tcp_flow(s, &cfg, &meter, b.up.clone(), b.down.clone()).await;
        });
    }
}

/// Counts open streams while it lives.
struct Count(Arc<AtomicUsize>);

impl Count {
    fn new(n: Arc<AtomicUsize>) -> Count {
        n.fetch_add(1, Ordering::Relaxed);
        Count(n)
    }
}

impl Drop for Count {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_header_names_the_exit_and_its_relays() {
        let h = header(&[9; 32], &["https://relay.example/".into()]);
        let (exit, relays) = read_header(&mut h.as_slice()).await.unwrap();
        assert_eq!((exit, relays), ([9; 32], vec!["https://relay.example/".to_string()]));
        assert!(read_header(&mut &b"XQ0"[..]).await.is_err());
    }
}
