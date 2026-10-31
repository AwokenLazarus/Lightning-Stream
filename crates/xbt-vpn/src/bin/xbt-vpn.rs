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
//! xbt-vpn serve [--dir DIR] [--status DIR] [--keys DIR] [--wg-listen ADDR:PORT] [--relay URL] [--nostr wss://…,…] [--region CC] [--home-country CC]
//!     The VPN service the app's pages drive, through files: it reads `devices.json` (the buyer's
//!     devices and their policies) and `exit.json` (this box's exit, if offered) in `--dir` (or
//!     XBT_VPN_DIR; default ./vpn), and writes `endpoint.json` (the WireGuard key devices pair with),
//!     `status.json` and `exit-status.json` in `--status` (or XBT_VPN_STATUS; default the same dir). Its
//!     keys and category lists are kept in `--keys` (or XBT_VPN_KEYS; default the same dir). Devices pair with the WireGuard endpoint on
//!     `--wg-listen` (or XBT_VPN_WG_LISTEN; default 0.0.0.0:51820). Exits are found on the Nostr
//!     relays of `--nostr` (or XBT_VPN_NOSTR_RELAYS, else XBT_UI_NOSTR_RELAYS), and an offered exit is
//!     announced there, in the country `exit.json` gives, else `--region` (or XBT_VPN_REGION;
//!     without one it is not announced). Keys are readable by their owner only. When `devices.json` or
//!     `exit.json` changes the service exits (status 0) to start again with the new settings: run it
//!     under a supervisor that restarts it.
//! xbt-vpn healthcheck [--status DIR]
//!     Exits 0 if `serve` wrote `status.json` in DIR (or XBT_VPN_STATUS, else XBT_VPN_DIR) in the last
//!     30 s (it writes it every 5 s), 1 if not: the image's health check.
//! xbt-vpn fetch --exit KEY --hints JSON --url http://HOST/PATH [--flows N] [--secs S] [--private] [--relay URL]
//!               [--hop KEY --hop-hints JSON]
//!     Downloads the URL through the exit on N flows at once for S seconds and prints one JSON line:
//!     the path, the bytes and the throughput. A tool for measuring: it looks the host name up
//!     itself; the app's buyer side does DNS through the tunnel. With `--hop`, every flow is sealed for
//!     the exit and goes through that first hop (two hops).
//! xbt-vpn fetch --tunnel URL --url http://HOST/PATH [--flows N] [--secs S] [--once] [--max-charge-sats N] [--region-check]
//!     The same through a priced exit's paid tunnel at URL, opened by the wallet of B2_SIGNER_SOCK
//!     and B2_STREAM_DIR (as the app's buyer side opens it). `--once`: each flow downloads the URL
//!     once, to its end. `--region-check`: the tunnel is opened as a region check's (no more than one
//!     ticket may leave the wallet for it, and it is charged no more than 20 sats), and the line adds
//!     the wallet's answer when it ended (`wallet`), the sats that left the wallet (`left_sats`; null
//!     where the answer does not say, which the service's region checks count as the full 2,000) and
//!     the page's first 4 KiB (`page`).
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
        Some("serve") => serve(&args, relay),
        Some("healthcheck") => healthcheck(&args),
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
        let load_ms = t.elapsed().as_millis();
        // 100,000 look-ups of names not in the list, each walking up its domains (the slow case)
        let t = Instant::now();
        let hits = (0..100_000).filter(|i| d.matches(&format!("a.b.n{i}.not-listed.example"))).count();
        let lookup_ns = t.elapsed().as_nanos() / 100_000;
        let set_kib = std::fs::metadata(dir.join(format!("{id}.fst"))).map(|m| m.len() / 1024).unwrap_or(0);
        println!("{}", serde_json::json!({ "category": id, "fetched": format!("{fetched:?}"), "fetch_ms": fetch_ms, "names": d.len(), "load_ms": load_ms, "rss_added_mib": (rss_kib().saturating_sub(before)) / 1024, "set_file_kib": set_kib, "lookup_ns": lookup_ns, "false_hits": hits }));
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
    /// A priced exit's paid tunnel, opened by the wallet.
    Tunnel(xbt_vpn::flow::Carrier),
    Sealed { hop: LinkConnection, exit: [u8; 32], relays: Vec<String>, tls: Arc<rustls::ClientConfig> },
}

impl Way {
    async fn open(&self, to: std::net::SocketAddr) -> Option<Box<dyn Duplex>> {
        match self {
            Way::Straight(conn) => match open_tcp(conn, to).await.ok()? {
                (Opened::Yes, send, recv) => Some(Box::new(tokio::io::join(recv, send))),
                _ => None,
            },
            Way::Tunnel(c) => match c.open_tcp(to).await.ok()? {
                (Opened::Yes, Some(s)) => Some(Box::new(s) as Box<dyn Duplex>),
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
    let once = args.iter().any(|a| a == "--once");
    let tunnel = arg(args, "--tunnel");
    let exit_id = arg(args, "--exit").or_else(|| tunnel.as_ref().map(|_| String::new())).expect("--exit KEY, or --tunnel URL");
    let hints: serde_json::Value = match &tunnel {
        Some(_) => serde_json::json!({}),
        None => serde_json::from_str(&arg(args, "--hints").expect("--hints JSON")).map_err(std::io::Error::other)?,
    };
    let url = arg(args, "--url").expect("--url http://host/path");
    let flows: usize = arg(args, "--flows").and_then(|s| s.parse().ok()).unwrap_or(1);
    let secs: u64 = arg(args, "--secs").and_then(|s| s.parse().ok()).unwrap_or(15);
    let rest = url.strip_prefix("http://").expect("a plain http:// URL");
    let (host, path) = rest.split_once('/').map(|(h, p)| (h.to_string(), format!("/{p}"))).unwrap_or((rest.to_string(), "/".into()));

    let link = Link::start_alpn(secret(), Options { relays: Relays::Ours(vec![relay]), serving: false, private, lookup: None }, ALPN_VPN)?;
    let strings = |k: &str| hints[k].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>();
    let direct = if private { vec![] } else { strings("direct").iter().filter_map(|s| s.parse().ok()).collect() };
    if tunnel.is_none() {
        link.learn(&exit_id, Hints { relays: strings("relays"), direct })?;
    }
    let hop_id = arg(args, "--hop");
    // `--region-check`: the tunnel's wallet as a region check's, and its answer reported in the line
    let region_check = args.iter().any(|a| a == "--region-check");
    let mut checked = None;
    let (way, via, said) = match (&tunnel, &hop_id) {
        (Some(url), _) => {
            let mut w = xbt_vpn::paid::Wallet::from_env().ok_or_else(|| std::io::Error::other("--tunnel needs B2_SIGNER_SOCK and B2_STREAM_DIR"))?;
            // `--max-charge-sats N`: the tunnel is charged no more than N, as a region check's is,
            // while the wallet may still buy the exit's whole ticket within `max_sats`
            if let Some(c) = arg(args, "--max-charge-sats") {
                let c: u64 = c.parse().map_err(|_| std::io::Error::other(format!("--max-charge-sats: not a number: {c}")))?;
                w.max_charge_sats = Some(c.min(w.max_sats));
            }
            // the exit's announced price a GB, if given, is the most the wallet pays it
            let ceiling = arg(args, "--price-msat-gb").and_then(|p| p.parse().ok()).map(xbt_vpn::paid::ceiling);
            let w = if region_check { w.for_region_check() } else { w };
            let t = match link.runtime().block_on(xbt_vpn::paid::open(&w, url, ceiling)) {
                Ok(t) => t,
                Err(e) if region_check => {
                    println!("{}", serde_json::json!({"bytes": 0, "error": e.to_string(), "left_sats": xbt_vpn::paid::left_of(&e)}));
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            if region_check {
                // a region check's answer goes in the line it prints, not after it
                checked = Some((t.mux.clone(), t.done));
                (Way::Tunnel(xbt_vpn::flow::Carrier::Tunnel(t.mux)), String::new(), None)
            } else {
                // what the wallet says when the tunnel ends is printed once it does, before the fetch exits
                (Way::Tunnel(xbt_vpn::flow::Carrier::Tunnel(t.mux)), String::new(), Some(t.done))
            }
        }
        (None, Some(hop_id)) => {
            let hh: serde_json::Value = serde_json::from_str(&arg(args, "--hop-hints").expect("--hop-hints JSON")).map_err(std::io::Error::other)?;
            let hs = |k: &str| hh[k].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>();
            let hdirect = if private { vec![] } else { hs("direct").iter().filter_map(|s| s.parse().ok()).collect() };
            link.learn(hop_id, Hints { relays: hs("relays"), direct: hdirect })?;
            let hop = link.runtime().block_on(link.connect_conn_alpn(hop_id, ALPN_VPN_HOP))?;
            let exit: [u8; 32] = hex::decode(&exit_id).map_err(std::io::Error::other)?.try_into().map_err(|_| std::io::Error::other("an exit key is 32 bytes"))?;
            let tls = sealed::buyer_config(&secret(), &exit);
            (Way::Sealed { hop, exit, relays: strings("relays"), tls }, hop_id.clone(), None)
        }
        (None, None) => (Way::Straight(link.connect_conn(&exit_id)?), exit_id.clone(), None),
    };
    let report = link.runtime().block_on(async {
        let to = tokio::net::lookup_host(format!("{host}:80")).await?.find(|a| a.is_ipv4()).ok_or_else(|| std::io::Error::other("no IPv4 address"))?;
        tokio::time::sleep(Duration::from_secs(3)).await;
        let total = Arc::new(AtomicU64::new(0));
        // a region check's page, kept to show what came back through the exit
        let page = Arc::new(std::sync::Mutex::new(Vec::new()));
        let start = Instant::now();
        let deadline = start + Duration::from_secs(secs);
        let mut tasks = Vec::new();
        for _ in 0..flows {
            let (way, total, host, path, page) = (way.clone(), total.clone(), host.clone(), path.clone(), page.clone());
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
                                if region_check {
                                    let mut p = page.lock().unwrap_or_else(|e| e.into_inner());
                                    let room = (4096 - p.len().min(4096)).min(n);
                                    p.extend_from_slice(&buf[..room]);
                                }
                            }
                        }
                    }
                    if once {
                        return;
                    }
                }
            }));
        }
        for t in tasks {
            let _ = t.await;
        }
        let secs = start.elapsed().as_secs_f64();
        let bytes = total.load(Ordering::Relaxed);
        Ok::<_, std::io::Error>((page, serde_json::json!({
            "path": link.path(&via).map(|p| p.kind()),
            "two_hops": hop_id.is_some(),
            "private": private,
            "flows": flows,
            "bytes": bytes,
            "secs": secs,
            "mbit_s": bytes as f64 * 8.0 / secs / 1e6,
        })))
    })?;
    let (page, mut report) = report;
    if let Some((mux, done)) = checked {
        // the tunnel ended: what the wallet answered, and what left it for the tunnel
        mux.close();
        let answer = done.recv_timeout(xbt_vpn::paid::ANSWER_WAIT).ok().map(|r| r.unwrap_or_else(|e| serde_json::json!({"error": e})));
        report["left_sats"] = answer.as_ref().and_then(xbt_vpn::paid::left_sats).into();
        report["wallet"] = answer.into();
        report["page"] = String::from_utf8_lossy(&page.lock().unwrap_or_else(|e| e.into_inner())).into_owned().into();
    }
    println!("{report}");
    // the tunnel is ended here (a Mux runs on until closed), and the wallet answers once its last receipt is in
    // (its stop waits up to 15 s for it): the runtime drives the close while the answer is waited for
    if let (Way::Tunnel(xbt_vpn::flow::Carrier::Tunnel(m)), Some(done)) = (&way, said) {
        m.close();
        let answer = link.runtime().block_on(async move {
            tokio::task::spawn_blocking(move || done.recv_timeout(Duration::from_secs(30))).await.ok().and_then(Result::ok)
        });
        match answer {
            Some(r) => eprintln!("the wallet: {}", r.map(|v| v.to_string()).unwrap_or_else(|e| e)),
            None => eprintln!("the wallet: no answer within 30 s of the tunnel's end"),
        }
    }
    Ok(())
}

fn arg_or_env(args: &[String], name: &str, envs: &[&str]) -> Option<String> {
    arg(args, name).or_else(|| envs.iter().find_map(|e| std::env::var(e).ok().filter(|v| !v.trim().is_empty())))
}

fn read_json(p: &std::path::Path) -> serde_json::Value {
    std::fs::read(p).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(serde_json::Value::Null)
}

fn mtime(p: &std::path::Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

fn serve(args: &[String], relay: String) -> std::io::Result<()> {
    use base64::Engine;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use xbt_vpn::announce::{self, ExitOffer};
    use xbt_vpn::buyer::{Buyer, Device, EncryptedDns};
    use xbt_vpn::content::LiveLists;
    use xbt_vpn::router::{Requirements, Router};
    use xbt_vpn::service::{self, device_status, devices_from, exit_config, exit_from, write_json};
    use xbt_vpn::wg::{public_of, WgEndpoint, WgPeer};

    // the settings the pages write (read only here), the status written for them, and this service's
    // own keys and lists (by default all three in one dir)
    let dir = std::path::PathBuf::from(arg_or_env(args, "--dir", &["XBT_VPN_DIR"]).unwrap_or_else(|| "vpn".into()));
    let status_dir = arg_or_env(args, "--status", &["XBT_VPN_STATUS"]).map(std::path::PathBuf::from).unwrap_or_else(|| dir.clone());
    let keys_dir = arg_or_env(args, "--keys", &["XBT_VPN_KEYS"]).map(std::path::PathBuf::from).unwrap_or_else(|| dir.clone());
    std::fs::create_dir_all(&status_dir)?;
    std::fs::create_dir_all(&keys_dir)?;
    let wg_listen = arg_or_env(args, "--wg-listen", &["XBT_VPN_WG_LISTEN"]).unwrap_or_else(|| "0.0.0.0:51820".into());
    let nostr: Vec<String> = arg_or_env(args, "--nostr", &["XBT_VPN_NOSTR_RELAYS", "XBT_UI_NOSTR_RELAYS"])
        .map(|v| v.split(',').map(str::trim).filter(|r| r.starts_with("wss://")).map(String::from).collect())
        .unwrap_or_default();
    let region = arg_or_env(args, "--region", &["XBT_VPN_REGION"]).map(|r| r.trim().to_ascii_uppercase()).filter(|r| r.len() == 2);
    // a priced exit is one of the owner's Stream services: buyers' wallets open paid tunnels at this
    // address on the owner's shop, which the shop's gateway joins to this endpoint
    let mut tunnel_url = arg_or_env(args, "--tunnel-url", &["XBT_VPN_TUNNEL_URL"]);
    let tunnel_listen = arg_or_env(args, "--tunnel-listen", &["XBT_VPN_TUNNEL_LISTEN"]).unwrap_or_else(|| "0.0.0.0:51880".into());
    let (devices_path, exit_path) = (dir.join("devices.json"), dir.join("exit.json"));
    // the tunnel secret too: a priced exit is announced only once it has one, so its arrival starts it again
    let secret_path = dir.join(xbt_vpn::paid::TUNNEL_SECRET_FILE);
    let started = (mtime(&devices_path), mtime(&exit_path), mtime(&secret_path));

    // the WireGuard key devices pair with: kept, so devices keep working across restarts
    let wg_secret = service::secret_in(&keys_dir.join("endpoint.key"))?;
    let b64 = |k: &[u8; 32]| base64::engine::general_purpose::STANDARD.encode(k);
    write_json(&status_dir.join("endpoint.json"), &serde_json::json!({ "public_key": b64(&public_of(wg_secret)), "listen": wg_listen }))?;
    let opts = |serving| Options { relays: Relays::Ours(vec![relay.clone()]), serving, private: false, lookup: None };

    // this box's exit, if offered
    let mut own_exit = None;
    let exit_meter = Arc::new(Meter::default());
    let mut _exit_link = None;
    let mut announced = false;
    let mut exit_region = None;
    let mut exit_priced = false;
    if let Some(settings) = exit_from(&read_json(&exit_path)) {
        // the country the owner set on the exit page, else the one the service was started with
        exit_region = settings.country.clone().or(region.clone());
        let region = exit_region.clone();
        let exit_secret = service::secret_in(&keys_dir.join("exit.key"))?;
        let link = Link::start_alpns(exit_secret, opts(true), ALPN_VPN, &[ALPN_VPN, ALPN_VPN_SEALED])?;
        let live = LiveLists::default();
        if settings.filtered && !settings.categories.is_empty() {
            lists::keep_updated(settings.categories.clone(), keys_dir.join("lists"), live.clone(), lists::UPDATE_EVERY, lists::catalogue_url);
        }
        let cfg = Arc::new(exit_config(&settings, live));
        // a priced exit is reached only through paid tunnels: its link carries no flows for free
        let priced = settings.sat_per_gb > 0;
        // the address the exit page found from the owner's shop, unless the service was given one
        if tunnel_url.is_none() {
            tunnel_url = settings.tunnel_url.clone();
        }
        if priced {
            let (cfg, m) = (cfg.clone(), exit_meter.clone());
            let listener = link.runtime().block_on(tokio::net::TcpListener::bind(&tunnel_listen))?;
            // only the shop's gateway opens tunnels: it carries the secret the wallet app wrote with the
            // route, read again for each tunnel. Without a whole one, nobody is let in (fails closed)
            if let Some(why) = xbt_vpn::paid::tunnel_secret_problem(&dir) {
                eprintln!("paid tunnels are refused ({}): {why}", dir.join(xbt_vpn::paid::TUNNEL_SECRET_FILE).display());
            }
            let secret_dir = dir.clone();
            link.runtime().spawn(xbt_vpn::paid::serve_tunnel_endpoint(listener, move || xbt_vpn::paid::tunnel_secret_in(&secret_dir), move |c| xbt_vpn::exit::serve(c, cfg.clone(), m.clone())));
        }
        let (m, buyers, tls) = (exit_meter.clone(), Arc::new(SealedBuyers::default()), sealed::exit_config(&exit_secret));
        link.accept_with(move |conn| {
            let (cfg, m, b, tls) = (cfg.clone(), m.clone(), buyers.clone(), tls.clone());
            async move {
                if priced {
                    return;
                }
                if conn.alpn() == ALPN_VPN_SEALED {
                    serve_sealed(conn, cfg, m, tls, b).await
                } else {
                    serve_buyer(conn, cfg, m).await
                }
            }
        });
        let id = link.endpoint_id();
        // a priced exit is announced only with somewhere to pay it and a secret to let the gateway in
        let tunnel_ready = !priced || (tunnel_url.is_some() && xbt_vpn::paid::tunnel_secret_in(&dir).is_some());
        if let (Some(region), false, true) = (&region, nostr.is_empty(), tunnel_ready) {
            let keys = xbt_nostr::event::Keys::from_hex(&hex::encode(service::secret_in(&keys_dir.join("nostr.key"))?)).ok_or_else(|| std::io::Error::other("a Nostr key that is not a key"))?;
            let offer = ExitOffer {
                exit: id.clone(), region: region.clone(), filtered: settings.filtered, categories: settings.categories.clone(),
                // two hops reach an exit over the link, which a priced exit keeps for paid tunnels: free exits only
                logs: false, blocked_ports: settings.blocked_ports.clone(), two_hop: !priced,
                price_msat_per_gb: settings.sat_per_gb.saturating_mul(1000), relay: Some(relay.clone()),
                tunnel: if priced { tunnel_url.clone() } else { None }, note: String::new(), ttl_s: announce::MAX_TTL_S,
            };
            let ev = announce::announcement_event(&keys, &exit_secret, &offer, xbt_nostr::now()).map_err(std::io::Error::other)?;
            announced = true;
            let nostr = nostr.clone();
            // refreshed every 6 hours: an announcement lives a week, so an exit nobody runs drops out
            std::thread::spawn(move || loop {
                let ev = announce::announcement_event(&keys, &exit_secret, &offer, xbt_nostr::now()).unwrap_or_else(|_| ev.clone());
                let _ = xbt_nostr::oneshot::publish(&nostr, &ev, Duration::from_secs(15));
                std::thread::sleep(Duration::from_secs(6 * 3600));
            });
        }
        own_exit = Some(id);
        exit_priced = priced;
        _exit_link = Some(link);
    }

    // the buyer: the devices of devices.json, each with its own policy
    let entries = devices_from(&read_json(&devices_path));
    let buyer_link = Link::start_alpn(service::secret_in(&keys_dir.join("buyer.key"))?, opts(false), ALPN_VPN)?;
    let rt = buyer_link.runtime();
    let devices: HashMap<IpAddr, Arc<Device>> = entries
        .iter()
        .map(|e| (IpAddr::V4(e.tunnel_ip), Arc::new(Device { name: e.name.clone(), meter: Meter::default(), limit_bytes: None, requirements: Some(e.requirements.clone()) })))
        .collect();
    let peers: Vec<WgPeer> = entries.iter().map(|e| WgPeer { public: e.public, tunnel_ip: e.tunnel_ip }).collect();
    let buyer = Buyer::new(buyer_link.clone(), Router::with_requirements(Requirements::default()), devices, Some(EncryptedDns::quad9()));
    // the owner's wallet pays for priced exits; without one, only free exits are used
    buyer.set_wallet(xbt_vpn::paid::Wallet::from_env());
    let wg = WgEndpoint::new(wg_secret, &peers);
    let sock = rt.block_on(tokio::net::UdpSocket::bind(&wg_listen))?;
    let (to_stack, from_devices) = tokio::sync::mpsc::channel(4096);
    let (to_devices, from_stack) = tokio::sync::mpsc::unbounded_channel();
    rt.spawn(buyer.clone().run(from_devices, to_devices));
    rt.spawn(wg.run(sock, to_stack, from_stack));

    // exits' regions are checked against an offline geo-IP table (DB-IP country lite: the one the app
    // shipped with, or a newer month fetched into the keys dir where a source is set) and, if the owner
    // gave their own country, a round-trip bound
    {
        let (buyer, geo_dir) = (buyer.clone(), keys_dir.join("geo"));
        buyer.set_home_country(arg_or_env(args, "--home-country", &["XBT_VPN_HOME_COUNTRY"]).map(|c| c.trim().to_string()).filter(|c| c.len() == 2));
        let bundled = std::path::PathBuf::from(std::env::var("XBT_VPN_GEO_BUNDLED").unwrap_or_else(|_| xbt_vpn::region::BUNDLED.into()));
        // where newer months are fetched from: none unless the owner sets one (the table that comes with
        // the app is refreshed at each release, so nothing depends on anyone's service)
        let geo_url = std::env::var("XBT_VPN_GEO_URL").unwrap_or_default();
        std::thread::spawn(move || loop {
            match xbt_vpn::region::load(&geo_dir, Some(&bundled), Some(&geo_url)) {
                Ok(t) => buyer.set_geo(t),
                Err(e) => eprintln!("geo-IP table not available ({e}): exits' regions stay unverified"),
            }
            std::thread::sleep(Duration::from_secs(86400));
        });
    }

    // exits, found on Nostr every 10 minutes; each announced region verified, and checked again every 6 h
    {
        let (buyer, link, nostr, own, relay, rt) = (buyer.clone(), buyer_link.clone(), nostr.clone(), own_exit.clone(), relay.clone(), rt.clone());
        let gate_file = keys_dir.join("region-checks.json");
        std::thread::spawn(move || {
            let mut checked: HashMap<String, (String, bool, std::time::Instant)> = HashMap::new();
            // priced exits are paid to have their region checked: only those a device's own policy asks
            // for by region (see Buyer::region_wanted), under one daily budget, one check of an exit a
            // day, none more for an operator whose checks keep failing, the longest seen first
            // kept in the keys dir: the service starting again (at every change of its settings) does
            // not start the day's budget again
            let mut gate = xbt_vpn::holds::CheckGate::load(&gate_file);
            loop {
                if !nostr.is_empty() {
                    let (events, _) = xbt_nostr::oneshot::query(&nostr, &announce::filter(500), Duration::from_secs(15));
                    let (found, _) = announce::collect(&events, xbt_nostr::now());
                    // a priced exit that names no tunnel can't be paid: not used
                    let mut found: Vec<_> = found.into_iter().filter(|a| Some(&a.exit.id) != own.as_ref() && (a.exit.price_msat_per_gb == 0 || a.tunnel.is_some())).collect();
                    let now = std::time::SystemTime::now();
                    found.sort_by_key(|a| gate.seen(&a.exit.id, now));
                    for mut a in found {
                        buyer.set_tunnel(&a.exit.id, a.tunnel.clone(), a.exit.price_msat_per_gb, &a.exit.operator);
                        let relays = vec![a.relay.clone().unwrap_or_else(|| relay.clone())];
                        if link.learn(&a.exit.id, Hints { relays, direct: Vec::new() }).is_err() {
                            continue;
                        }
                        let region = a.exit.region.clone();
                        let stale = checked.get(&a.exit.id).is_none_or(|(r, _, at)| *r != region || at.elapsed() > Duration::from_secs(6 * 3600));
                        let result = if stale && region.len() == 2 { rt.block_on(buyer.check_region(&mut gate, &a.exit)) } else { None };
                        if let Some(result) = result {
                            if result != xbt_vpn::region::RegionCheck::Verified {
                                eprintln!("exit {}…: region {region} not verified ({result:?})", &a.exit.id[..12.min(a.exit.id.len())]);
                            }
                            checked.insert(a.exit.id.clone(), (region, result == xbt_vpn::region::RegionCheck::Verified, std::time::Instant::now()));
                        }
                        a.exit.region_verified = checked.get(&a.exit.id).is_some_and(|c| c.1);
                        rt.block_on(buyer.upsert_exit(a.exit));
                    }
                }
                std::thread::sleep(Duration::from_secs(600));
            }
        });
    }

    println!("{}", serde_json::json!({ "endpoint": b64(&public_of(wg_secret)), "listen": wg_listen, "devices": entries.len(), "exit": own_exit, "announced": announced, "nostr_relays": nostr.len() }));
    loop {
        let rows: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                let ip = IpAddr::V4(e.tunnel_ip);
                let c = buyer.device(ip).map(|d| d.meter.counts());
                let why = rt.block_on(buyer.why_blocked(ip));
                let (exit, used_msat) = buyer.device_use(ip);
                service::with_use(device_status(e, c.as_ref().map_or(0, |c| c.up_bytes), c.as_ref().map_or(0, |c| c.down_bytes), why), exit.as_deref(), used_msat)
            })
            .collect();
        // each exit's region check, in plain words, for the page
        let exits: Vec<serde_json::Value> = buyer.region_results().into_iter().map(|(id, region, r, at)| {
            let words = match &r {
                xbt_vpn::region::RegionCheck::Verified => format!("Checked: its traffic comes out in {region}."),
                xbt_vpn::region::RegionCheck::Elsewhere(cc) => format!("Its traffic comes out in {cc}, not {region}: not used for {region}."),
                xbt_vpn::region::RegionCheck::TooFast => format!("It answers faster than {region} is from here: not used for {region}."),
                xbt_vpn::region::RegionCheck::Unknown => "Not checked yet: no country table, or the address checks didn't agree.".to_string(),
            };
            let secs = at.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            serde_json::json!({ "exit": id, "region": region, "verified": r == xbt_vpn::region::RegionCheck::Verified, "region_check": words, "checked_at": secs })
        }).collect();
        let _ = write_json(&status_dir.join("status.json"), &serde_json::json!({ "devices": rows, "exits": exits }));
        let c = exit_meter.counts();
        let exit_status = match &own_exit {
            Some(id) => serde_json::json!({ "offered": true, "exit": id, "announced": announced, "up_bytes": c.up_bytes, "down_bytes": c.down_bytes, "refused": c.dropped, "blocked": c.blocked,
                "paid": exit_priced,
                "not_announced_because": if announced { None } else if exit_region.is_none() { Some("its country isn't set") }
                    else if exit_priced && tunnel_url.is_none() { Some("the shop's address for paid tunnels isn't set") }
                    else if let Some(why) = xbt_vpn::paid::tunnel_secret_problem(&dir).filter(|_| exit_priced) { Some(why) }
                    else { Some("no Nostr relays are set") },
                "paid_tunnels_closed_because": xbt_vpn::paid::tunnel_secret_problem(&dir).filter(|_| exit_priced) }),
            None => serde_json::json!({ "offered": false }),
        };
        let _ = write_json(&status_dir.join("exit-status.json"), &exit_status);
        if (mtime(&devices_path), mtime(&exit_path), mtime(&secret_path)) != started {
            eprintln!("the settings changed: exiting to start again with them");
            // not 0: a container restarted "on failure" (Umbrel's) is not started again after a clean exit
            std::process::exit(75);
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

fn healthcheck(args: &[String]) -> std::io::Result<()> {
    let dir = arg_or_env(args, "--status", &["XBT_VPN_STATUS", "XBT_VPN_DIR"]).unwrap_or_else(|| "vpn".into());
    let age = mtime(&std::path::Path::new(&dir).join("status.json")).and_then(|t| t.elapsed().ok());
    match age {
        Some(a) if a < Duration::from_secs(30) => Ok(()),
        _ => {
            eprintln!("status.json in {dir} is missing or more than 30 s old");
            std::process::exit(1)
        }
    }
}
