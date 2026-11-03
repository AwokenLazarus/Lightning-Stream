//! Links between testers, measured over iroh, and the collector they report to.
//!
//! A tester tells the collector what its machine has and asks who else is here. It then measures
//! each of them in turn: round trip, whether the path is direct or through a relay, and speed each
//! way, within a small bound. The collector keeps the records and passes on keys and relays. It
//! writes no addresses. Each stream carries one request: a length-prefixed JSON message, then bytes
//! for the requests that move any.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use xbt_iroh_link::{Hints, Link, LinkConnection, Path as LinkPath};

use crate::{LinkResult, Record, Report};

/// This tool's protocol on the link.
pub const ALPN_CHECK: &[u8] = b"lightning-compute/check/1";

/// Largest control message.
const MAX_MESSAGE: u32 = 256 * 1024;
/// Most bytes a peer sends or takes for one speed test, whatever it is asked.
pub const MAX_TEST_BYTES: u64 = 64 << 20;
/// Most records a collector keeps, so a stranger cannot fill its disk.
const MAX_RECORDS: u64 = 200_000;
/// How many peers a tester is told of, newest first.
const MAX_PEERS: usize = 32;
/// A tester not heard from for this long is not passed on.
const PEER_TTL: Duration = Duration::from_secs(30 * 60);

/// How much a tester measures.
#[derive(Clone, Debug)]
pub struct Limits {
    pub pings: u32,
    pub ping_every: Duration,
    /// Bytes each way per peer.
    pub test_bytes: u64,
    /// Longest time for a speed test one way: a slow line reports what it moved by then.
    pub test_time: Duration,
    pub connect_time: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self { pings: 10, ping_every: Duration::from_millis(500), test_bytes: 16 << 20, test_time: Duration::from_secs(20), connect_time: Duration::from_secs(30) }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Peer {
    pub id: String,
    pub relays: Vec<String>,
    /// Direct addresses: only where the tester asked to share them, for a lab with no relay.
    #[serde(default)]
    pub direct: Vec<SocketAddr>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    Ping,
    /// Send me this many bytes.
    Down { bytes: u64 },
    /// Here come this many bytes.
    Up { bytes: u64 },
    /// Keep my report; who else is here?
    Join { report: Box<Report>, me: Peer },
    /// Keep what I measured.
    Results { links: Vec<LinkResult> },
}

async fn write_message<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, m: &T) -> std::io::Result<()> {
    let body = serde_json::to_vec(m).map_err(std::io::Error::other)?;
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(&body).await
}

async fn read_message<R: AsyncRead + Unpin, T: for<'a> Deserialize<'a>>(r: &mut R) -> std::io::Result<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len);
    if len > MAX_MESSAGE {
        return Err(std::io::Error::other("message too long"));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    serde_json::from_slice(&body).map_err(std::io::Error::other)
}

/// The collector: where testers report. A tester can only speak for its own key.
pub struct Collector {
    out: Mutex<std::fs::File>,
    records: Mutex<u64>,
    peers: Mutex<HashMap<String, (Peer, Instant)>>,
}

impl Collector {
    /// Appends to the file at `path`.
    pub fn open(path: &Path) -> std::io::Result<Arc<Collector>> {
        let out = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        let records = std::fs::read_to_string(path).map_or(0, |t| t.lines().count() as u64);
        Ok(Arc::new(Collector { out: Mutex::new(out), records: Mutex::new(records), peers: Mutex::new(HashMap::new()) }))
    }

    fn keep(&self, r: &Record) {
        let mut n = self.records.lock().unwrap_or_else(|e| e.into_inner());
        if *n >= MAX_RECORDS {
            return;
        }
        let Ok(mut line) = serde_json::to_string(r) else { return };
        line.push('\n');
        let mut f = self.out.lock().unwrap_or_else(|e| e.into_inner());
        if f.write_all(line.as_bytes()).is_ok() {
            *n += 1;
        }
    }

    fn join(&self, from: &str, report: Report, mut me: Peer) -> Vec<Peer> {
        me.id = from.to_string();
        let mut report = report;
        report.id = from.to_string();
        self.keep(&Record::Report(report));
        let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        peers.retain(|_, (_, seen)| now.duration_since(*seen) < PEER_TTL);
        peers.insert(from.to_string(), (me, now));
        let mut others: Vec<_> = peers.iter().filter(|(id, _)| id.as_str() != from).map(|(_, v)| v.clone()).collect();
        others.sort_by_key(|(_, seen)| std::cmp::Reverse(*seen));
        others.into_iter().take(MAX_PEERS).map(|(p, _)| p).collect()
    }

    fn results(&self, from: &str, links: Vec<LinkResult>) {
        for mut l in links.into_iter().take(MAX_PEERS * 4) {
            l.from = from.to_string();
            self.keep(&Record::Link(l));
        }
    }
}

/// Answers requests on `link`: every tester answers probes, and a collector also takes reports.
pub fn serve(link: &Arc<Link>, collector: Option<Arc<Collector>>) {
    link.accept_with(move |conn: LinkConnection| {
        let collector = collector.clone();
        async move {
            let from = hex::encode(conn.remote_id().as_bytes());
            while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                let (collector, from) = (collector.clone(), from.clone());
                tokio::spawn(async move {
                    let Ok(req) = read_message::<_, Request>(&mut recv).await else { return };
                    match req {
                        Request::Ping => {
                            let _ = write_message(&mut send, &true).await;
                        }
                        Request::Down { bytes } => {
                            let block = vec![0x5Au8; 64 * 1024];
                            let mut left = bytes.min(MAX_TEST_BYTES);
                            while left > 0 {
                                let n = left.min(block.len() as u64) as usize;
                                if send.write_all(&block[..n]).await.is_err() {
                                    return;
                                }
                                left -= n as u64;
                            }
                        }
                        Request::Up { bytes } => {
                            let mut left = bytes.min(MAX_TEST_BYTES);
                            let mut block = vec![0u8; 64 * 1024];
                            while left > 0 {
                                match recv.read(&mut block).await {
                                    Ok(Some(n)) if n > 0 => left = left.saturating_sub(n as u64),
                                    _ => return,
                                }
                            }
                            let _ = write_message(&mut send, &true).await;
                        }
                        Request::Join { report, me } => {
                            let Some(c) = &collector else { return };
                            let _ = write_message(&mut send, &c.join(&from, *report, me)).await;
                        }
                        Request::Results { links } => {
                            let Some(c) = &collector else { return };
                            c.results(&from, links);
                            let _ = write_message(&mut send, &true).await;
                        }
                    }
                    let _ = send.finish();
                    // the answer's bytes must arrive before the stream goes
                    let _ = send.stopped().await;
                });
            }
        }
    });
}

async fn ask<T: for<'a> Deserialize<'a>>(conn: &LinkConnection, req: &Request) -> std::io::Result<T> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(std::io::Error::other)?;
    write_message(&mut send, req).await?;
    let _ = send.finish();
    read_message(&mut recv).await
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v.get(v.len() / 2).copied().unwrap_or(0.0)
}

/// Measures one peer: pings first, since a path often starts on the relay and goes direct within
/// seconds; the round trip is the median of the later half, on the path it settled on.
pub async fn measure(link: &Arc<Link>, me: &str, peer: &Peer, limits: &Limits) -> std::io::Result<LinkResult> {
    link.learn(&peer.id, Hints { relays: peer.relays.clone(), direct: peer.direct.clone() })?;
    let conn = tokio::time::timeout(limits.connect_time, link.connect_conn_async(&peer.id)).await.map_err(std::io::Error::other)??;
    let mut rtts = Vec::new();
    for i in 0..limits.pings {
        if i > 0 {
            tokio::time::sleep(limits.ping_every).await;
        }
        let t = Instant::now();
        let _: bool = tokio::time::timeout(limits.connect_time, ask(&conn, &Request::Ping)).await.map_err(std::io::Error::other)??;
        rtts.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    let rtt_ms = median(rtts.split_off(rtts.len() / 2));
    let direct = matches!(link.path(&peer.id), Some(LinkPath::Direct { .. }));
    let down_mbit_s = speed_down(&conn, limits).await;
    let up_mbit_s = speed_up(&conn, limits).await;
    Ok(LinkResult { from: me.to_string(), to: peer.id.clone(), direct, rtt_ms, up_mbit_s, down_mbit_s })
}

fn mbit_s(bytes: u64, t: Instant) -> f64 {
    bytes as f64 * 8.0 / 1e6 / t.elapsed().as_secs_f64().max(1e-6)
}

async fn speed_down(conn: &LinkConnection, limits: &Limits) -> f64 {
    let Ok((mut send, mut recv)) = conn.open_bi().await else { return 0.0 };
    if write_message(&mut send, &Request::Down { bytes: limits.test_bytes }).await.is_err() {
        return 0.0;
    }
    let _ = send.finish();
    let t = Instant::now();
    let mut got = 0u64;
    let mut block = vec![0u8; 64 * 1024];
    let _ = tokio::time::timeout(limits.test_time, async {
        while got < limits.test_bytes {
            match recv.read(&mut block).await {
                Ok(Some(n)) if n > 0 => got += n as u64,
                _ => break,
            }
        }
    }).await;
    mbit_s(got, t)
}

async fn speed_up(conn: &LinkConnection, limits: &Limits) -> f64 {
    let Ok((mut send, mut recv)) = conn.open_bi().await else { return 0.0 };
    if write_message(&mut send, &Request::Up { bytes: limits.test_bytes }).await.is_err() {
        return 0.0;
    }
    let t = Instant::now();
    let block = vec![0xA5u8; 64 * 1024];
    let mut sent = 0u64;
    let done = tokio::time::timeout(limits.test_time, async {
        while sent < limits.test_bytes {
            let n = (limits.test_bytes - sent).min(block.len() as u64) as usize;
            if send.write_all(&block[..n]).await.is_err() {
                return false;
            }
            sent += n as u64;
        }
        let _ = send.finish();
        read_message::<_, bool>(&mut recv).await.is_ok()
    }).await;
    // written is not received: on a timeout this counts what the link's buffers took as well
    if !matches!(done, Ok(true)) {
        let _ = send.reset(0u32.into());
    }
    mbit_s(sent, t)
}

/// What a tester's run did.
#[derive(Debug, Default)]
pub struct Outcome {
    pub links: Vec<LinkResult>,
    pub failed: Vec<String>,
}

/// One tester's run: joins, measures whoever is there, reports, and looks again until `run_for`
/// ends, answering other testers' probes throughout (`serve` must be running on `link`).
pub async fn run_tester(link: Arc<Link>, collector: &str, report: Report, me: Peer, limits: Limits, run_for: Duration, recheck: Duration) -> std::io::Result<Outcome> {
    let conn = tokio::time::timeout(limits.connect_time, link.connect_conn_async(collector)).await.map_err(std::io::Error::other)??;
    let my_id = link.endpoint_id();
    let end = Instant::now() + run_for;
    let mut done: HashSet<String> = HashSet::new();
    let mut out = Outcome::default();
    loop {
        let peers: Vec<Peer> = ask(&conn, &Request::Join { report: Box::new(report.clone()), me: me.clone() }).await?;
        for peer in peers.iter().filter(|p| p.id != my_id) {
            if !done.insert(peer.id.clone()) {
                continue;
            }
            match measure(&link, &my_id, peer, &limits).await {
                Ok(l) => {
                    let _: bool = ask(&conn, &Request::Results { links: vec![l.clone()] }).await?;
                    out.links.push(l);
                }
                Err(_) => out.failed.push(peer.id.clone()),
            }
        }
        if Instant::now() + recheck > end {
            return Ok(out);
        }
        tokio::time::sleep(recheck).await;
    }
}
