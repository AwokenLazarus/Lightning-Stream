//! A VPN exit, and a test download through one.
//!
//! ```text
//! xbt-vpn exit  [--relay URL] [--speed-limit BYTES_PER_SEC]
//!     Runs an exit with the default policy (port 25 blocked, IPv6 off, never this machine's own
//!     networks). Prints one JSON line: its key and where it can be reached. Then, every 10 s, the
//!     bytes carried (sizes only).
//!     It also takes buyers' flows sealed through a first hop (two hops).
//!     With `--categories adult,gambling,…` it is a filtered exit: those category lists (saved in
//!     `--lists DIR`, default ./vpn-lists) are blocked and kept up to date.
//! xbt-vpn lists [--categories adult,…] [--lists DIR]
//!     Fetches the category lists now and prints, per list, the names it holds, the time to load and
//!     the memory used.
//! xbt-vpn hop   [--relay URL]
//!     Runs a first hop: it joins a buyer's sealed flows to the exit each names, reading neither the
//!     destination nor the bytes. Prints its key and where it can be reached, then bytes carried.
//! xbt-vpn buyer --exit KEY --hints JSON --wg-listen ADDR:PORT --wg-endpoint HOST:PORT [--private] [--relay URL]
//!     Runs a buyer's app for one device: a WireGuard endpoint the device adds, the buyer's stack and
//!     router, private DNS (DNS-over-TLS to Quad9 through the exit). Prints the device's WireGuard
//!     config once (keys made for this run), then the device's bytes and refusals every 10 s.
//! xbt-vpn fetch --exit KEY --hints JSON --url http://HOST/PATH [--flows N] [--secs S] [--private] [--relay URL]
//!               [--hop KEY --hop-hints JSON]
//!     Downloads the URL through the exit on N flows at once for S seconds and prints one JSON line:
//!     the path, the bytes and the throughput. A tool for measuring: it looks the host name up
//!     itself; the app's buyer side does DNS through the tunnel. With `--hop`, every flow is sealed for
//!     the exit and goes through that first hop (two hops).
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use xbt_iroh_link::{Hints, Link, LinkConnection, Options, Relays, ALPN_VPN, ALPN_VPN_HOP, ALPN_VPN_SEALED, DEFAULT_RELAY};
use xbt_vpn::content::ContentFilter;
use xbt_vpn::exit::{serve_buyer, ExitConfig, ExitKind};
use xbt_vpn::lists;
use xbt_vpn::flow::{open_tcp, open_tcp_on, Opened};
use xbt_vpn::hop::{open_sealed, serve_hop, serve_sealed, HopConfig, SealedBuyers};
use xbt_vpn::meter::Meter;
use xbt_vpn::sealed;

trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

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
        Some("hop") => hop(relay),
        Some("lists") => lists(&args),
        Some("buyer") => buyer(&args, relay, private),
        Some("fetch") => fetch(&args, relay, private),
        _ => {
            eprintln!("usage: xbt-vpn exit [--relay URL] [--speed-limit B/s] | xbt-vpn hop [--relay URL] | xbt-vpn fetch --exit KEY --hints JSON --url URL [--flows N] [--secs S] [--private] [--hop KEY --hop-hints JSON]");
            std::process::exit(2)
        }
    }
}

fn exit(args: &[String], relay: String) -> std::io::Result<()> {
    let key = secret();
    let link = Link::start_alpns(key, Options { relays: Relays::Ours(vec![relay]), serving: true, private: false, lookup: None }, ALPN_VPN, &[ALPN_VPN, ALPN_VPN_SEALED])?;
    let mut cfg = ExitConfig { buyer_bytes_per_sec: arg(args, "--speed-limit").and_then(|s| s.parse().ok()), ..ExitConfig::default() };
    let cats = categories(args);
    if !cats.is_empty() {
        let filter = ContentFilter { categories: cats.clone(), ..ContentFilter::default() };
        lists::keep_updated(cats, lists_dir(args), filter.lists.clone(), lists::UPDATE_EVERY, lists::catalogue_url);
        cfg.kind = ExitKind::Filtered { filter: Arc::new(filter), resolver: None };
    }
    let cfg = Arc::new(cfg);
    let meter = Arc::new(Meter::default());
    let (m, tls, buyers) = (meter.clone(), sealed::exit_config(&key), Arc::new(SealedBuyers::default()));
    link.accept_with(move |conn| {
        let (cfg, m, tls, buyers) = (cfg.clone(), m.clone(), tls.clone(), buyers.clone());
        async move {
            if conn.alpn() == ALPN_VPN_SEALED {
                serve_sealed(conn, cfg, m, tls, buyers).await
            } else {
                serve_buyer(conn, cfg, m).await
            }
        }
    });
    let h = link.hints(Duration::from_secs(10));
    println!("{}", serde_json::json!({ "exit": link.endpoint_id(), "hints": { "relays": h.relays, "direct": h.direct } }));
    loop {
        std::thread::sleep(Duration::from_secs(10));
        let c = meter.counts();
        eprintln!("carried up {} B, down {} B, refused {}", c.up_bytes, c.down_bytes, c.dropped);
    }
}

fn categories(args: &[String]) -> Vec<String> {
    arg(args, "--categories").map(|c| c.split(',').map(str::trim).filter(|c| lists::category(c).is_some()).map(String::from).collect()).unwrap_or_default()
}

fn lists_dir(args: &[String]) -> std::path::PathBuf {
    arg(args, "--lists").unwrap_or_else(|| "vpn-lists".into()).into()
}

fn rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status").ok().and_then(|s| s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)?.parse().ok())).unwrap_or(0)
}

fn lists(args: &[String]) -> std::io::Result<()> {
    let dir = lists_dir(args);
    let mut ids = categories(args);
    if ids.is_empty() {
        ids = lists::CATEGORIES.iter().map(|c| c.id.to_string()).collect();
    }
    for id in &ids {
        let url = lists::catalogue_url(id).expect("a known category");
        let t = Instant::now();
        let fetched = lists::fetch(id, &url, &dir);
        let fetch_ms = t.elapsed().as_millis();
        let before = rss_kib();
        let t = Instant::now();
        let d = lists::load(std::slice::from_ref(id), &dir);
        println!("{}", serde_json::json!({ "category": id, "fetched": format!("{fetched:?}"), "fetch_ms": fetch_ms, "names": d.len(), "load_ms": t.elapsed().as_millis(), "rss_added_mib": (rss_kib().saturating_sub(before)) / 1024 }));
        drop(d);
    }
    Ok(())
}

fn buyer(args: &[String], relay: String, private: bool) -> std::io::Result<()> {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use xbt_vpn::buyer::{Buyer, Device, EncryptedDns};
    use xbt_vpn::router::{ExitInfo, Mode, Router};
    use xbt_vpn::wg::{device_config, keypair, WgEndpoint, WgPeer};

    let exit_id = arg(args, "--exit").expect("--exit KEY");
    let hints: serde_json::Value = serde_json::from_str(&arg(args, "--hints").expect("--hints JSON")).map_err(std::io::Error::other)?;
    let listen = arg(args, "--wg-listen").expect("--wg-listen ADDR:PORT");
    let endpoint = arg(args, "--wg-endpoint").expect("--wg-endpoint HOST:PORT");
    let link = Link::start_alpn(secret(), Options { relays: Relays::Ours(vec![relay]), serving: false, private, lookup: None }, ALPN_VPN)?;
    let strings = |k: &str| hints[k].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>();
    let direct = if private { vec![] } else { strings("direct").iter().filter_map(|s| s.parse().ok()).collect() };
    link.learn(&exit_id, Hints { relays: strings("relays"), direct })?;

    let mut router = Router::new(Mode::Best, None);
    router.upsert(ExitInfo { id: exit_id, region: "XX".into(), healthy: true, ..ExitInfo::default() });
    const DEVICE_IP: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 2);
    let dev = Arc::new(Device { name: "device".into(), meter: Meter::default(), limit_bytes: None, requirements: None });
    let buyer = Buyer::new(link.clone(), router, HashMap::from([(IpAddr::V4(DEVICE_IP), dev.clone())]), Some(EncryptedDns::quad9()));
    let (device_private, device_public) = keypair();
    let (endpoint_private, endpoint_public) = keypair();
    let wg = WgEndpoint::new(endpoint_private, &[WgPeer { public: device_public, tunnel_ip: DEVICE_IP }]);
    let rt = link.runtime();
    let sock = rt.block_on(tokio::net::UdpSocket::bind(&listen))?;
    let (to_stack, from_devices) = tokio::sync::mpsc::channel(4096);
    let (to_devices, from_stack) = tokio::sync::mpsc::unbounded_channel();
    rt.spawn(buyer.clone().run(from_devices, to_devices));
    rt.spawn(wg.run(sock, to_stack, from_stack));
    print!("{}", device_config(device_private, DEVICE_IP, endpoint_public, &endpoint, "10.66.0.1"));
    use std::io::Write;
    std::io::stdout().flush()?;
    loop {
        std::thread::sleep(Duration::from_secs(10));
        let c = dev.meter.counts();
        eprintln!("device up {} B, down {} B; flows refused {}", c.up_bytes, c.down_bytes, buyer.refused.load(Ordering::Relaxed));
    }
}

fn hop(relay: String) -> std::io::Result<()> {
    let link = Link::start_alpns(secret(), Options { relays: Relays::Ours(vec![relay]), serving: true, private: false, lookup: None }, ALPN_VPN_HOP, &[ALPN_VPN_HOP])?;
    let meter = Arc::new(Meter::default());
    let (l, m, cfg) = (link.clone(), meter.clone(), Arc::new(HopConfig::default()));
    link.accept_with(move |conn| serve_hop(l.clone(), conn, cfg.clone(), m.clone()));
    let h = link.hints(Duration::from_secs(10));
    println!("{}", serde_json::json!({ "hop": link.endpoint_id(), "hints": { "relays": h.relays, "direct": h.direct } }));
    loop {
        std::thread::sleep(Duration::from_secs(10));
        let c = meter.counts();
        eprintln!("carried up {} B, down {} B", c.up_bytes, c.down_bytes);
    }
}

/// How the test's flows reach the exit: a connection of their own, or sealed through a first hop.
#[derive(Clone)]
enum Way {
    Straight(LinkConnection),
    Sealed { hop: LinkConnection, exit: [u8; 32], relays: Vec<String>, tls: Arc<rustls::ClientConfig> },
}

impl Way {
    async fn open(&self, to: std::net::SocketAddr) -> Option<Box<dyn Duplex>> {
        match self {
            Way::Straight(conn) => match open_tcp(conn, to).await.ok()? {
                (Opened::Yes, send, recv) => Some(Box::new(tokio::io::join(recv, send))),
                _ => None,
            },
            Way::Sealed { hop, exit, relays, tls } => {
                let mut s = open_sealed(hop, exit, relays, tls.clone()).await.ok()?;
                (open_tcp_on(&mut s, to).await.ok()? == Opened::Yes).then(|| Box::new(s) as Box<dyn Duplex>)
            }
        }
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
    let hop_id = arg(args, "--hop");
    let (way, via) = match &hop_id {
        Some(hop_id) => {
            let hh: serde_json::Value = serde_json::from_str(&arg(args, "--hop-hints").expect("--hop-hints JSON")).map_err(std::io::Error::other)?;
            let hs = |k: &str| hh[k].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>();
            let hdirect = if private { vec![] } else { hs("direct").iter().filter_map(|s| s.parse().ok()).collect() };
            link.learn(hop_id, Hints { relays: hs("relays"), direct: hdirect })?;
            let hop = link.runtime().block_on(link.connect_conn_alpn(hop_id, ALPN_VPN_HOP))?;
            let exit: [u8; 32] = hex::decode(&exit_id).map_err(std::io::Error::other)?.try_into().map_err(|_| std::io::Error::other("an exit key is 32 bytes"))?;
            let tls = sealed::buyer_config(&secret(), &exit);
            (Way::Sealed { hop, exit, relays: strings("relays"), tls }, hop_id.clone())
        }
        None => (Way::Straight(link.connect_conn(&exit_id)?), exit_id.clone()),
    };
    let report = link.runtime().block_on(async {
        let to = tokio::net::lookup_host(format!("{host}:80")).await?.find(|a| a.is_ipv4()).ok_or_else(|| std::io::Error::other("no IPv4 address"))?;
        tokio::time::sleep(Duration::from_secs(3)).await;
        let total = Arc::new(AtomicU64::new(0));
        let start = Instant::now();
        let deadline = start + Duration::from_secs(secs);
        let mut tasks = Vec::new();
        for _ in 0..flows {
            let (way, total, host, path) = (way.clone(), total.clone(), host.clone(), path.clone());
            tasks.push(tokio::spawn(async move {
                while Instant::now() < deadline {
                    let Some(mut s) = way.open(to).await else { return };
                    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: xbt-vpn-test\r\n\r\n");
                    if s.write_all(req.as_bytes()).await.is_err() || s.flush().await.is_err() {
                        return;
                    }
                    let mut buf = vec![0u8; 64 * 1024];
                    while Instant::now() < deadline {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                total.fetch_add(n as u64, Ordering::Relaxed);
                            }
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
            "path": link.path(&via).map(|p| p.kind()),
            "two_hops": hop_id.is_some(),
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
