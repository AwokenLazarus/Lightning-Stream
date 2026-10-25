//! `lightning-stream`: the connector service on loopback (see the library).
//!
//! Environment: `LS_LISTEN` (default 127.0.0.1:8480), `B2_SIGNER_SOCK` (the signer's socket),
//! `B2_STREAM_DIR` (the directory the signer streams bodies into: the same for both),
//! `LS_TASK` (the owner's task the calls are paid under), `LS_MAX_SATS` (the most one call may
//! spend; default 2,000).

use std::net::TcpListener;
use std::path::PathBuf;

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

fn main() {
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
    let sig = signals.wait();
    xbt_svc::shutdown::say_stopping("lightning-stream", sig);
    // the listener stops; answers in flight end, and their sockets close, so the signer stops paying
    let _ = run.stopper().drain(xbt_svc::shutdown::DRAIN);
}
