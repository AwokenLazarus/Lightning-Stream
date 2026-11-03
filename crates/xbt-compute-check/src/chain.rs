//! A machine's link in a compute chain, the first build step after the machine check.
//!
//! The chain's own processes (shards, the relay in front of them, users) keep speaking TCP, on
//! loopback only. The link serves this machine's chain port to the chain's other machines over
//! iroh, and opens one loopback port per other machine that serves, leading to it over iroh. So a
//! chain that runs over plain TCP runs over iroh with each process given loopback addresses, and no
//! change to the engine. A link accepts streams only from the keys of its chain.
//!
//! Every machine writes a card (its key, where it is reached, whether it serves). Whoever starts the
//! chain gathers the cards into one file of machines and hands it to every link.

use std::collections::{BTreeMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use xbt_iroh_link::{Hints, Link, LinkConnection, LinkRecvStream, LinkSendStream, Path as LinkPath};

use crate::probe::Peer;

/// The chain's protocol on the link.
pub const ALPN_CHAIN: &[u8] = b"lightning-compute/chain/1";

/// One machine of a chain, as its link describes it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Card {
    #[serde(flatten)]
    pub peer: Peer,
    /// Whether it serves a chain port (a shard or the relay); a user's machine only opens streams.
    #[serde(default)]
    pub serves: bool,
}

/// Every machine of a chain, by the name the chain's plan gives it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Machines {
    pub machines: BTreeMap<String, Card>,
}

/// What a link counts.
#[derive(Debug, Default)]
pub struct Counters {
    /// Streams joined to the chain port.
    pub streams_in: AtomicU64,
    /// Connections from keys outside the chain, closed at once.
    pub refused: AtomicU64,
    /// Streams dropped because the chain port did not answer in time.
    pub upstream_failed: AtomicU64,
}

/// A link's report: its counters, and the path to each machine it reaches.
#[derive(Debug, Serialize)]
pub struct Report {
    pub id: String,
    pub serving: Option<SocketAddr>,
    pub streams_in: u64,
    pub refused: u64,
    pub upstream_failed: u64,
    pub peers: BTreeMap<String, PeerPath>,
}

#[derive(Debug, Serialize)]
pub struct PeerPath {
    pub port: SocketAddr,
    /// `direct` or `relay`, once a connection has been made.
    pub path: Option<String>,
    pub rtt_ms: Option<u64>,
}

/// Serves `upstream`, this machine's chain port, to the keys in `allowed`: each stream one of them
/// opens becomes a TCP connection to `upstream`, tried again for `patience` while the process
/// behind it starts (as a TCP connect to a process still loading its model would be).
pub fn serve(link: &Arc<Link>, upstream: SocketAddr, allowed: Arc<RwLock<HashSet<String>>>, patience: Duration, counters: Arc<Counters>) {
    link.accept_with(move |conn: LinkConnection| {
        let (allowed, counters) = (allowed.clone(), counters.clone());
        async move {
            let from = hex::encode(conn.remote_id().as_bytes());
            if !allowed.read().map(|a| a.contains(&from)).unwrap_or(false) {
                counters.refused.fetch_add(1, Ordering::Relaxed);
                conn.close(1u32.into(), b"not in this chain");
                return;
            }
            while let Ok((send, recv)) = conn.accept_bi().await {
                let counters = counters.clone();
                tokio::spawn(async move {
                    match connect_patiently(upstream, patience).await {
                        Some(tcp) => {
                            counters.streams_in.fetch_add(1, Ordering::Relaxed);
                            join(tcp, send, recv).await;
                        }
                        // dropping the stream resets it, and the far end's TCP connection with it
                        None => {
                            counters.upstream_failed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
        }
    });
}

async fn connect_patiently(upstream: SocketAddr, patience: Duration) -> Option<TcpStream> {
    let give_up = Instant::now() + patience;
    loop {
        if let Ok(tcp) = TcpStream::connect(upstream).await {
            let _ = tcp.set_nodelay(true);
            return Some(tcp);
        }
        if Instant::now() >= give_up {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Joins a TCP connection and a stream until both directions have ended.
async fn join(tcp: TcpStream, mut send: LinkSendStream, mut recv: LinkRecvStream) {
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

/// Opens a loopback port for every machine of `chain` that serves, other than `me`: each TCP
/// connection to it becomes one stream on one link to that machine. Returns the ports by name.
pub fn forward_all(link: &Arc<Link>, me: &str, chain: &Machines) -> std::io::Result<BTreeMap<String, SocketAddr>> {
    let mut ports = BTreeMap::new();
    for (name, card) in &chain.machines {
        if card.peer.id == me || !card.serves {
            continue;
        }
        link.learn(&card.peer.id, Hints { relays: card.peer.relays.clone(), direct: card.peer.direct.clone() })?;
        ports.insert(name.clone(), link.forward(&card.peer.id, (Ipv4Addr::LOCALHOST, 0).into())?);
    }
    Ok(ports)
}

/// The link's report now.
pub fn report(link: &Link, serving: Option<SocketAddr>, counters: &Counters, chain: &Machines, ports: &BTreeMap<String, SocketAddr>) -> Report {
    let peers = ports
        .iter()
        .map(|(name, port)| {
            let path = chain.machines.get(name).and_then(|c| link.path(&c.peer.id));
            let (kind, rtt_ms) = match path {
                Some(LinkPath::Direct { rtt_ms, .. }) => (Some("direct".to_string()), Some(rtt_ms)),
                Some(LinkPath::Relay { rtt_ms, .. }) => (Some("relay".to_string()), Some(rtt_ms)),
                None => (None, None),
            };
            (name.clone(), PeerPath { port: *port, path: kind, rtt_ms })
        })
        .collect();
    Report {
        id: link.endpoint_id(),
        serving,
        streams_in: counters.streams_in.load(Ordering::Relaxed),
        refused: counters.refused.load(Ordering::Relaxed),
        upstream_failed: counters.upstream_failed.load(Ordering::Relaxed),
        peers,
    }
}
