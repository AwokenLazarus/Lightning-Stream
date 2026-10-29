//! `lightning-stream`: the connector service on loopback (see the library).
//!
//!   lightning-stream [serve]     serve (configuration from the environment)
//!   lightning-stream healthcheck GET /health on LS_LISTEN: the image's HEALTHCHECK (it has no
//!                                shell or curl); exit 0 on 200
//!
//! Environment: `LS_LISTEN` (default 127.0.0.1:8480), `B2_SIGNER_SOCK` (the signer's socket),
//! `B2_STREAM_DIR` (the directory the signer streams bodies into: the same for both),
//! `LS_TASK` (the owner's task the calls are paid under), `LS_MAX_SATS` (the most one call may
//! spend; default 2,000). With `LS_AI_LISTEN`, it also serves the AI endpoint (see `start_ai`).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("healthcheck") => std::process::exit(healthcheck()),
        Some("-h") | Some("--help") => {
            println!("usage: lightning-stream [serve] | healthcheck\n\
                      serve reads LS_LISTEN, B2_SIGNER_SOCK, B2_STREAM_DIR, LS_TASK, LS_MAX_SATS");
            return;
        }
        None | Some("serve") => {}
        Some(o) => {
            eprintln!("lightning-stream: unknown command {o} (try --help)");
            std::process::exit(2);
        }
    }
    let listen = env("LS_LISTEN").unwrap_or_else(|| "127.0.0.1:8480".into());
    let (Some(signer), Some(stream_dir), Some(task)) = (env("B2_SIGNER_SOCK"), env("B2_STREAM_DIR"), env("LS_TASK")) else {
        eprintln!("lightning-stream: set B2_SIGNER_SOCK, B2_STREAM_DIR and LS_TASK");
        std::process::exit(2);
    };
    let max_sats = env("LS_MAX_SATS").and_then(|v| v.parse().ok()).unwrap_or(2_000);
    let addr: std::net::SocketAddr = match listen.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("lightning-stream: LS_LISTEN {listen}: {e}");
            std::process::exit(2);
        }
    };
    // loopback only: a program elsewhere would spend the owner's money with no token (the LAN mode
    // of the node-box app comes with per-device tokens)
    if !addr.ip().is_loopback() {
        eprintln!("lightning-stream: LS_LISTEN must be a loopback address");
        std::process::exit(2);
    }
    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("lightning-stream: {addr}: {e}");
            std::process::exit(1);
        }
    };
    if prepare_stream_dir(&stream_dir) != 0 {
        std::process::exit(1);
    }
    let cfg_paths = (PathBuf::from(&signer), PathBuf::from(&stream_dir), task.clone(), max_sats);
    let cfg = lightning_stream::Config { signer: PathBuf::from(signer), stream_dir: PathBuf::from(stream_dir), task, max_sats };
    let signals = match xbt_svc::shutdown::listen() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("lightning-stream: signals: {e}");
            std::process::exit(1);
        }
    };
    let run = match lightning_stream::serve(cfg, listener) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("lightning-stream: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("lightning-stream: listening on {}", run.addr);
    let ai = start_ai(&cfg_paths);
    let sig = signals.wait();
    xbt_svc::shutdown::say_stopping("lightning-stream", sig);
    // the listener stops; answers in flight end, and their sockets close, so the signer stops paying
    let _ = run.stopper().drain(xbt_svc::shutdown::DRAIN);
    if let Some(ai) = ai {
        let _ = ai.stopper().drain(xbt_svc::shutdown::DRAIN);
    }
}

/// The AI endpoint, when `LS_AI_LISTEN` is set: an OpenAI-compatible address for programs on the
/// owner's network, each with a key from `LS_CREDENTIALS` (see `inference_server`). It needs
/// `LS_CREDENTIALS`, `LS_AI_SELLERS` and `LS_AI_STATE`; `LS_AI_HOSTS` (comma-separated) lists the
/// host names it answers to, `LS_AI_FIRST_BYTE_S` how long a seller has for its first byte.
fn start_ai(base: &(PathBuf, PathBuf, String, i64)) -> Option<xbt_svc::http::Running> {
    let listen = env("LS_AI_LISTEN")?;
    let (Some(credentials), Some(sellers), Some(state)) = (env("LS_CREDENTIALS"), env("LS_AI_SELLERS"), env("LS_AI_STATE")) else {
        eprintln!("lightning-stream: LS_AI_LISTEN needs LS_CREDENTIALS, LS_AI_SELLERS and LS_AI_STATE; the AI endpoint is off");
        return None;
    };
    let first_byte = Duration::from_secs(env("LS_AI_FIRST_BYTE_S").and_then(|v| v.parse().ok()).unwrap_or(20));
    let allowed_hosts = env("LS_AI_HOSTS").map(|h| h.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()).unwrap_or_default();
    let (signer, stream_dir, task, max_sats) = base.clone();
    let cfg = lightning_stream::inference_server::Config {
        signer, stream_dir, task, max_sats, credentials: credentials.into(), sellers: sellers.into(), state: state.into(), first_byte, allowed_hosts,
    };
    let listener = match TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("lightning-stream: AI endpoint {listen}: {e}; it is off");
            return None;
        }
    };
    match lightning_stream::inference_server::serve(cfg, listener) {
        Ok(r) => {
            eprintln!("lightning-stream: AI endpoint on {}", r.addr);
            Some(r)
        }
        Err(e) => {
            eprintln!("lightning-stream: AI endpoint: {e}; it is off");
            None
        }
    }
}

/// The stream directory has to be writable by this process: it creates the sockets there. On a
/// package the directory is inside the signer's socket dir, which init gives to the signer's user,
/// and this process is that user.
fn prepare_stream_dir(dir: &str) -> i32 {
    let path = PathBuf::from(dir);
    if let Err(e) = std::fs::create_dir_all(&path) {
        eprintln!("lightning-stream: B2_STREAM_DIR {dir}: {e}");
        return 1;
    }
    if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o750)) {
        eprintln!("lightning-stream: B2_STREAM_DIR {dir} is not owned by this user: {e}");
        return 1;
    }
    0
}

fn healthcheck() -> i32 {
    let listen = env("LS_LISTEN").unwrap_or_else(|| "127.0.0.1:8480".into());
    let addr = match listen.parse::<std::net::SocketAddr>() {
        Ok(mut a) => {
            if a.ip().is_unspecified() {
                let ip = if a.is_ipv6() {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
                } else {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                };
                a.set_ip(ip);
            }
            a
        }
        Err(e) => {
            eprintln!("lightning-stream healthcheck: LS_LISTEN {listen}: {e}");
            return 1;
        }
    };
    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("lightning-stream healthcheck: {addr}: {e}");
            return 1;
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    if stream.write_all(b"GET /health HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n").is_err() {
        eprintln!("lightning-stream healthcheck: could not write the request");
        return 1;
    }
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).unwrap_or(0);
    let text = String::from_utf8_lossy(&buf[..n]);
    let status = text.lines().next().unwrap_or("");
    if status.contains(" 200 ") {
        return 0;
    }
    eprintln!("lightning-stream healthcheck: {status}");
    1
}
