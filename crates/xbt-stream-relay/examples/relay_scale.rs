//! How much a shop reached only through a relay can deliver, by how many link keys it serves on.
//!
//! ```text
//! relay_scale relay <bind addr>   a relay on plain HTTP, with our relay's per-client limit (6 MB/s)
//! relay_scale run                 sellers and buyers through RELAY, on this machine
//! ```
//!
//! `run` reads its settings from the environment:
//!
//! | Variable | Default | |
//! | --- | --- | --- |
//! | `RELAY` | | the relay's URL (`http://` for a local one, `https://` for a public one) |
//! | `ENDPOINTS` | 1 | link keys the shop serves on, each with its own connection to the relay |
//! | `BUYERS` | 10 | buyers, each with its own link key, spread over the shop's keys in turn |
//! | `MODE` | `film` | `film`: each buyer plays a film at `MBIT` (a player buffering ahead up to 30 s); `bulk`: each reads as fast as it can |
//! | `MBIT` | 8 | a film's bit rate |
//! | `SECS` | 60 | a film's length, or how long bulk reads run |
//! | `ROLE` | `both` | `seller`: only the shop, printing its keys and serving until stopped; `buyer`: only the buyers, of the shop whose keys are in `SHOP_KEYS` (comma-separated), so the two can run on different machines |
//!
//! Every link is private (relays only, never a direct path), as for a seller behind a strict NAT or
//! a VPN. It prints one JSON line: the settings, the delivered rate in total, and the stalls.
//! A stall is a moment the player's buffer runs dry once playing; playback resumes at 1 s of buffer.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh_relay::server::{self as relay, ClientRateLimit, RelayConfig, ServerConfig};
use xbt_iroh_link::{Hints, Link, Options, Relays};

const START_S: f64 = 2.0;
const RESUME_S: f64 = 1.0;
const AHEAD_S: f64 = 30.0;

fn env<T: std::str::FromStr>(k: &str, d: T) -> T {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

fn secret() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::getrandom(&mut s).expect("random bytes");
    s
}

fn run_relay(bind: SocketAddr) {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("runtime");
    rt.block_on(async move {
        let mut limits = relay::Limits::default();
        let mut rx = ClientRateLimit::new(NonZeroU32::new(xbt_stream_relay::config::CLIENT_RX_BYTES_PER_S).expect("non-zero"));
        rx.max_burst_bytes = NonZeroU32::new(xbt_stream_relay::config::CLIENT_RX_BURST_BYTES);
        limits.client_rx = Some(rx);
        let mut rc = RelayConfig::new(bind);
        rc.limits = limits;
        let mut sc = ServerConfig::default();
        sc.relay = Some(rc);
        let s = relay::Server::spawn(sc).await.expect("the relay starts");
        eprintln!("relay on http://{}", s.http_addr().expect("http"));
        std::future::pending::<()>().await;
    });
}

/// Answers `GET /film?bytes=N` with N bytes, on every connection, until the reader goes.
fn service() -> SocketAddr {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let addr = l.local_addr().expect("addr");
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut r = BufReader::new(c.try_clone().expect("clone"));
                let mut w = c;
                loop {
                    let mut first = String::new();
                    if r.read_line(&mut first).unwrap_or(0) == 0 {
                        return;
                    }
                    loop {
                        let mut line = String::new();
                        if r.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        if line == "\r\n" {
                            break;
                        }
                    }
                    let n: u64 = first.split("bytes=").nth(1).and_then(|s| s.split(' ').next()).and_then(|s| s.parse().ok()).unwrap_or(0);
                    if w.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {n}\r\n\r\n").as_bytes()).is_err() {
                        return;
                    }
                    let block = vec![0u8; 64 << 10];
                    let mut left = n;
                    while left > 0 {
                        let k = left.min(block.len() as u64) as usize;
                        if w.write_all(&block[..k]).is_err() {
                            return;
                        }
                        left -= k as u64;
                    }
                }
            });
        }
    });
    addr
}

/// Sends the request and reads up to the end of the head; what came after it is returned.
fn request(port: u16, bytes: u64) -> std::io::Result<(TcpStream, usize)> {
    let mut c = TcpStream::connect((Ipv4Addr::LOCALHOST, port))?;
    c.set_read_timeout(Some(Duration::from_secs(20)))?;
    write!(c, "GET /film?bytes={bytes} HTTP/1.1\r\nHost: shop\r\n\r\n")?;
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if c.read(&mut b)? == 0 {
            return Err(std::io::Error::other("closed before the head"));
        }
        head.push(b[0]);
    }
    Ok((c, 0))
}

#[derive(Default, Debug)]
struct Play {
    received: u64,
    stalls: u32,
    stalled_s: f64,
    done: bool,
    failed: Option<String>,
}

/// One buyer playing a film of `secs` at `mbit`, or reading as fast as it can for `secs` (`bulk`).
fn play(port: u16, mbit: f64, secs: f64, bulk: bool, total: Arc<AtomicU64>, deadline: Instant) -> Play {
    let rate = mbit * 1e6 / 8.0;
    let bytes = if bulk { 1 << 40 } else { (rate * secs) as u64 };
    let mut p = Play::default();
    let (mut c, _) = match request(port, bytes) {
        Ok(x) => x,
        Err(e) => {
            p.failed = Some(e.to_string());
            return p;
        }
    };
    let t0 = Instant::now();
    let mut buf = vec![0u8; 64 << 10];
    // playing since, the media time played before it, and whether the buffer has run dry
    let (mut since, mut played, mut waiting): (Option<Instant>, f64, bool) = (None, 0.0, true);
    let mut stall_from: Option<Instant> = None;
    loop {
        if bulk && t0.elapsed().as_secs_f64() >= secs {
            p.done = true;
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        let have = p.received as f64 / rate;
        let now_played = played + since.map_or(0.0, |s| s.elapsed().as_secs_f64());
        let buffered = have - now_played;
        if !bulk {
            if !waiting && buffered <= 0.0 && p.received < bytes {
                // ran dry
                played = have;
                since = None;
                waiting = true;
                p.stalls += 1;
                stall_from = Some(Instant::now());
            }
            if waiting && (buffered >= if p.stalls == 0 { START_S } else { RESUME_S } || p.received >= bytes) {
                waiting = false;
                since = Some(Instant::now());
                if let Some(f) = stall_from.take() {
                    p.stalled_s += f.elapsed().as_secs_f64();
                }
            }
            if p.received >= bytes {
                p.done = true;
                break;
            }
            if buffered >= AHEAD_S {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        }
        match c.read(&mut buf) {
            Ok(0) => {
                p.failed = Some("closed".into());
                break;
            }
            Ok(n) => {
                p.received += n as u64;
                total.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(e) => {
                p.failed = Some(e.to_string());
                break;
            }
        }
    }
    p
}

fn run() {
    let url: String = std::env::var("RELAY").expect("RELAY: the relay's URL");
    let (endpoints, buyers): (usize, usize) = (env("ENDPOINTS", 1), env("BUYERS", 10));
    let mode: String = env("MODE", "film".to_string());
    let (mbit, secs): (f64, f64) = (env("MBIT", 8.0), env("SECS", 60.0));
    let bulk = mode == "bulk";
    let role: String = env("ROLE", "both".to_string());
    let opts = |serving| Options { relays: Relays::Ours(vec![url.clone()]), serving, private: true, lookup: None };
    // the shop: one gateway (here, the stand-in service), reached on `endpoints` keys
    let (_shop, keys): (Vec<Arc<Link>>, Vec<String>) = if role == "buyer" {
        (vec![], std::env::var("SHOP_KEYS").expect("SHOP_KEYS: the shop's keys").split(',').map(str::to_string).collect())
    } else {
        let upstream = service();
        let shop: Vec<Arc<Link>> = (0..endpoints).map(|_| Link::start_with(secret(), opts(true)).expect("a shop link")).collect();
        for l in &shop {
            l.serve(upstream);
        }
        let homes: Vec<Vec<String>> = shop.iter().map(|l| l.hints(Duration::from_secs(15)).relays).collect();
        eprintln!("shop keys online: {:?}", homes.iter().map(|h| h.len()).collect::<Vec<_>>());
        let keys = shop.iter().map(|l| l.endpoint_id()).collect();
        (shop, keys)
    };
    if role == "seller" {
        println!("{}", keys.join(","));
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }
    let endpoints = keys.len();
    let ports: Vec<(Arc<Link>, u16)> = (0..buyers)
        .map(|i| {
            let b = Link::start_with(secret(), opts(false)).expect("a buyer link");
            let k = &keys[i % endpoints];
            b.learn(k, Hints { relays: vec![url.clone()], direct: vec![] }).expect("learn");
            let port = b.local_port(k).expect("port");
            (b, port)
        })
        .collect();
    // every buyer's link up before the clock starts
    let warm = Instant::now();
    let warmed: Vec<bool> = std::thread::scope(|sc| {
        let hs: Vec<_> = ports.iter().map(|(_, port)| sc.spawn(move || {
            (0..3).any(|_| request(*port, 1024).and_then(|(mut c, _)| { let mut b = [0u8; 1024]; c.read_exact(&mut b) }).is_ok())
        })).collect();
        hs.into_iter().map(|h| h.join().unwrap_or(false)).collect()
    });
    eprintln!("buyers connected: {}/{} in {:.1} s", warmed.iter().filter(|w| **w).count(), buyers, warm.elapsed().as_secs_f64());
    let total = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + Duration::from_secs_f64(secs * 2.0 + 30.0);
    let t0 = Instant::now();
    let sampler = {
        let total = total.clone();
        std::thread::spawn(move || {
            let mut last = 0u64;
            let mut per_s = Vec::new();
            while Instant::now() < deadline {
                std::thread::sleep(Duration::from_secs(1));
                let now = total.load(Ordering::Relaxed);
                if now == u64::MAX {
                    break;
                }
                per_s.push((now - last) as f64 * 8.0 / 1e6);
                last = now;
            }
            per_s
        })
    };
    let plays: Vec<Play> = std::thread::scope(|sc| {
        let hs: Vec<_> = ports.iter().map(|(_, port)| {
            let total = total.clone();
            sc.spawn(move || play(*port, mbit, secs, bulk, total, deadline))
        }).collect();
        hs.into_iter().map(|h| h.join().expect("buyer")).collect()
    });
    let wall = t0.elapsed().as_secs_f64();
    let got = total.swap(u64::MAX, Ordering::Relaxed);
    let per_s = sampler.join().unwrap_or_default();
    let mut sorted: Vec<f64> = per_s.iter().copied().filter(|x| *x > 0.0).collect();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let peak5 = per_s.windows(5).map(|w| w.iter().sum::<f64>() / 5.0).fold(0.0, f64::max);
    let rates: Vec<f64> = plays.iter().map(|p| p.received as f64 * 8.0 / 1e6 / if bulk { secs } else { wall }).collect();
    let out = serde_json::json!({
        "relay": url, "endpoints": endpoints, "buyers": buyers, "mode": mode, "mbit": mbit, "secs": secs,
        "wall_s": (wall * 10.0).round() / 10.0,
        "total_mbit_s": ((got as f64 * 8.0 / 1e6 / if bulk { secs } else { wall }) * 10.0).round() / 10.0,
        "peak5_mbit_s": (peak5 * 10.0).round() / 10.0,
        "median_s_mbit_s": sorted.get(sorted.len() / 2).map(|x| (x * 10.0).round() / 10.0),
        "per_buyer_min_mbit_s": rates.iter().copied().fold(f64::INFINITY, f64::min),
        "per_buyer_max_mbit_s": rates.iter().copied().fold(0.0, f64::max),
        "finished": plays.iter().filter(|p| p.done).count(),
        "failed": plays.iter().filter(|p| p.failed.is_some()).count(),
        "buyers_stalled": plays.iter().filter(|p| p.stalls > 0).count(),
        "stalls": plays.iter().map(|p| p.stalls).sum::<u32>(),
        "stalled_s": (plays.iter().map(|p| p.stalled_s).sum::<f64>() * 10.0).round() / 10.0,
    });
    println!("{out}");
    std::process::exit(0);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("relay") => run_relay(args.get(1).and_then(|a| a.parse().ok()).unwrap_or_else(|| "127.0.0.1:3340".parse().expect("addr"))),
        Some("run") => run(),
        _ => {
            eprintln!("usage: relay_scale relay <bind addr> | relay_scale run (settings in the environment; see the source)");
            std::process::exit(2)
        }
    }
}
