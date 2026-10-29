//! Measures the VPN tunnel: two link endpoints in one process (an exit and a buyer), the round trip
//! of small packets and the goodput of full-size ones, in datagrams or on the stream, direct or
//! forced through a relay.
//!
//! ```text
//! xbt-vpn-bench [--relay URL] [--private] [--stream] [--secs N] [--size BYTES]
//! ```
//! `--private` uses relays only (never a direct path); `--stream` sends packets on the control
//! stream instead of datagrams. Prints one JSON object.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use xbt_iroh_link::{Link, Options, Relays, ALPN_VPN, DEFAULT_RELAY};
use xbt_vpn::tunnel::{Tunnel, TUNNEL_MTU};

const PING: u8 = 0xEE;

fn secret() -> [u8; 32] {
    let mut k = [0u8; 32];
    let mut f = std::fs::File::open("/dev/urandom").expect("urandom");
    std::io::Read::read_exact(&mut f, &mut k).expect("urandom");
    k
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let relay = arg(&args, "--relay").unwrap_or_else(|| DEFAULT_RELAY.to_string());
    let private = args.iter().any(|a| a == "--private");
    let stream = args.iter().any(|a| a == "--stream");
    let secs: u64 = arg(&args, "--secs").and_then(|s| s.parse().ok()).unwrap_or(10);
    let size: usize = arg(&args, "--size").and_then(|s| s.parse().ok()).unwrap_or(TUNNEL_MTU).clamp(64, TUNNEL_MTU);

    let opts = |serving| Options { relays: Relays::Ours(vec![relay.clone()]), serving, private, lookup: None };
    let exit = Link::start_alpn(secret(), opts(true), ALPN_VPN)?;
    let (got_pkts, got_bytes) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let (gp, gb) = (got_pkts.clone(), got_bytes.clone());
    exit.accept_with(move |conn| {
        let (gp, gb) = (gp.clone(), gb.clone());
        async move {
            let Ok(t) = Tunnel::accept(conn).await else { return };
            while let Ok(p) = t.recv().await {
                if p.first() == Some(&PING) {
                    let _ = t.send(&p).await;
                } else {
                    gp.fetch_add(1, Ordering::Relaxed);
                    gb.fetch_add(p.len() as u64, Ordering::Relaxed);
                }
            }
        }
    });
    let mut hints = exit.hints(Duration::from_secs(10));
    if private {
        hints.direct.clear();
    }
    let id = exit.endpoint_id();
    let buyer = Link::start_alpn(secret(), opts(false), ALPN_VPN)?;
    buyer.learn(&id, hints)?;
    let conn = buyer.connect_conn(&id)?;

    let report = buyer.runtime().block_on(async {
        let t = Tunnel::open(conn, !stream).await?;
        // let the link settle on its path (it starts on the relay and moves to direct if it can)
        tokio::time::sleep(Duration::from_secs(3)).await;

        let mut rtts = Vec::new();
        for i in 0u32..100 {
            let mut p = vec![PING; 64];
            p[1..5].copy_from_slice(&i.to_be_bytes());
            let start = Instant::now();
            t.send(&p).await?;
            if let Ok(Ok(echo)) = tokio::time::timeout(Duration::from_secs(2), t.recv()).await {
                if echo[1..5] == p[1..5] {
                    rtts.push(start.elapsed().as_secs_f64() * 1000.0);
                }
            }
        }
        rtts.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let pct = |q: f64| rtts.get(((rtts.len() as f64 - 1.0) * q).round() as usize).copied().unwrap_or(f64::NAN);

        let mut p = vec![0u8; size];
        p[0] = 0x45;
        let (mut sent, start) = (0u64, Instant::now());
        while start.elapsed() < Duration::from_secs(secs) {
            p[4..12].copy_from_slice(&sent.to_be_bytes());
            t.send(&p).await?;
            sent += 1;
        }
        let elapsed = start.elapsed().as_secs_f64();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let (rp, rb) = (got_pkts.load(Ordering::Relaxed), got_bytes.load(Ordering::Relaxed));
        let mbit = |bytes: u64| bytes as f64 * 8.0 / elapsed / 1e6;
        Ok::<_, std::io::Error>(serde_json::json!({
            "path": buyer.path(&id).map(|p| p.kind()),
            "sent_in_datagrams": t.sent().in_datagrams,
            "sent_on_stream": t.sent().on_stream,
            "max_datagram_bytes": t.max_datagram_size(),
            "private": private,
            "relay": relay,
            "packet_bytes": size,
            "rtt_ms": { "samples": rtts.len(), "p50": pct(0.5), "p99": pct(0.99) },
            "sent_packets": sent,
            "received_packets": rp,
            "loss_percent": if sent > 0 { 100.0 * (sent.saturating_sub(rp)) as f64 / sent as f64 } else { 0.0 },
            "offered_mbit_s": mbit(sent * size as u64),
            "goodput_mbit_s": mbit(rb),
            "secs": elapsed,
        }))
    })?;
    println!("{report}");
    Ok(())
}
