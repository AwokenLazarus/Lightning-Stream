//! A VPN exit, and a test download through one.
//!
//! ```text
//! xbt-vpn exit  [--relay URL] [--speed-limit BYTES_PER_SEC]
//!     Runs an exit with the default policy (port 25 blocked, IPv6 off, never this machine's own
//!     networks). Prints one JSON line: its key and where it can be reached. Then, every 10 s, the
//!     bytes carried (sizes only).
//! xbt-vpn fetch --exit KEY --hints JSON --url http://HOST/PATH [--flows N] [--secs S] [--private] [--relay URL]
//!     Downloads the URL through the exit on N flows at once for S seconds and prints one JSON line:
//!     the path, the bytes and the throughput. A tool for measuring: it looks the host name up
//!     itself; the app's buyer side does DNS through the tunnel.
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use xbt_iroh_link::{Hints, Link, Options, Relays, ALPN_VPN, DEFAULT_RELAY};
use xbt_vpn::exit::{serve_buyer, ExitConfig};
use xbt_vpn::flow::{open_tcp, Opened};
use xbt_vpn::meter::Meter;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn secret() -> [u8; 32] {
    let mut k = [0u8; 32];
    let mut f = std::fs::File::open("/dev/urandom").expect("urandom");
    std::io::Read::read_exact(&mut f, &mut k).expect("urandom");
    k
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let relay = arg(&args, "--relay").unwrap_or_else(|| DEFAULT_RELAY.to_string());
    let private = args.iter().any(|a| a == "--private");
    match args.get(1).map(String::as_str) {
        Some("exit") => exit(&args, relay),
        Some("fetch") => fetch(&args, relay, private),
        _ => {
            eprintln!("usage: xbt-vpn exit [--relay URL] [--speed-limit B/s] | xbt-vpn fetch --exit KEY --hints JSON --url URL [--flows N] [--secs S] [--private]");
            std::process::exit(2)
        }
    }
}

fn exit(args: &[String], relay: String) -> std::io::Result<()> {
    let link = Link::start_alpn(secret(), Options { relays: Relays::Ours(vec![relay]), serving: true, private: false, lookup: None }, ALPN_VPN)?;
    let cfg = Arc::new(ExitConfig { buyer_bytes_per_sec: arg(args, "--speed-limit").and_then(|s| s.parse().ok()), ..ExitConfig::default() });
    let meter = Arc::new(Meter::default());
    let m = meter.clone();
    link.accept_with(move |conn| serve_buyer(conn, cfg.clone(), m.clone()));
    let h = link.hints(Duration::from_secs(10));
    println!("{}", serde_json::json!({ "exit": link.endpoint_id(), "hints": { "relays": h.relays, "direct": h.direct } }));
    loop {
        std::thread::sleep(Duration::from_secs(10));
        let c = meter.counts();
        eprintln!("carried up {} B, down {} B, refused {}", c.up_bytes, c.down_bytes, c.dropped);
    }
}

fn fetch(args: &[String], relay: String, private: bool) -> std::io::Result<()> {
    let exit_id = arg(args, "--exit").expect("--exit KEY");
    let hints: serde_json::Value = serde_json::from_str(&arg(args, "--hints").expect("--hints JSON")).map_err(std::io::Error::other)?;
    let url = arg(args, "--url").expect("--url http://host/path");
    let flows: usize = arg(args, "--flows").and_then(|s| s.parse().ok()).unwrap_or(1);
    let secs: u64 = arg(args, "--secs").and_then(|s| s.parse().ok()).unwrap_or(15);
    let rest = url.strip_prefix("http://").expect("a plain http:// URL");
    let (host, path) = rest.split_once('/').map(|(h, p)| (h.to_string(), format!("/{p}"))).unwrap_or((rest.to_string(), "/".into()));

    let link = Link::start_alpn(secret(), Options { relays: Relays::Ours(vec![relay]), serving: false, private, lookup: None }, ALPN_VPN)?;
    let strings = |k: &str| hints[k].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>();
    let direct = if private { vec![] } else { strings("direct").iter().filter_map(|s| s.parse().ok()).collect() };
    link.learn(&exit_id, Hints { relays: strings("relays"), direct })?;
    let conn = link.connect_conn(&exit_id)?;
    let report = link.runtime().block_on(async {
        let to = tokio::net::lookup_host(format!("{host}:80")).await?.find(|a| a.is_ipv4()).ok_or_else(|| std::io::Error::other("no IPv4 address"))?;
        tokio::time::sleep(Duration::from_secs(3)).await;
        let total = Arc::new(AtomicU64::new(0));
        let start = Instant::now();
        let deadline = start + Duration::from_secs(secs);
        let mut tasks = Vec::new();
        for _ in 0..flows {
            let (conn, total, host, path) = (conn.clone(), total.clone(), host.clone(), path.clone());
            tasks.push(tokio::spawn(async move {
                while Instant::now() < deadline {
                    let Ok((Opened::Yes, mut send, mut recv)) = open_tcp(&conn, to).await else { return };
                    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: xbt-vpn-test\r\n\r\n");
                    if send.write_all(req.as_bytes()).await.is_err() {
                        return;
                    }
                    let mut buf = vec![0u8; 64 * 1024];
                    while Instant::now() < deadline {
                        match recv.read(&mut buf).await {
                            Ok(Some(n)) => {
                                total.fetch_add(n as u64, Ordering::Relaxed);
                            }
                            _ => break,
                        }
                    }
                }
            }));
        }
        for t in tasks {
            let _ = t.await;
        }
        let secs = start.elapsed().as_secs_f64();
        let bytes = total.load(Ordering::Relaxed);
        Ok::<_, std::io::Error>(serde_json::json!({
            "path": link.path(&exit_id).map(|p| p.kind()),
            "private": private,
            "flows": flows,
            "bytes": bytes,
            "secs": secs,
            "mbit_s": bytes as f64 * 8.0 / secs / 1e6,
        }))
    })?;
    println!("{report}");
    Ok(())
}
