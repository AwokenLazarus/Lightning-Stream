//! Paid tunnels: how a buyer reaches a priced exit.
//!
//! A priced exit is one of its operator's Stream services: a route on their shop that carries
//! WebSockets, priced per byte both ways. The buyer's app asks its own wallet to open it (the
//! signer's `xbt402_pay` with `upgrade`, the same call a web app's WebSocket makes): the wallet
//! pays as the bytes pass, within the owner's spending rules and the tunnel's `max_sats`, and
//! checks the seller's signed count of the open tunnel as it runs (interim receipts). Its byte
//! stream reaches this process on a socket in `B2_STREAM_DIR`, and [`crate::mux`] carries the
//! device's flows on it.
//!
//! At the exit's end the shop's gateway joins the tunnel to the exit's tunnel endpoint
//! ([`serve_tunnel_endpoint`]), which answers the upgrade and serves the flows like a buyer's
//! link connection ([`crate::exit::serve`]).

use std::io::{self, BufRead, BufReader, Read};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::mux::Mux;

/// The buyer's wallet: the signer's socket, the directory both share for streamed answers, and
/// what each tunnel may cost at most before a new one is opened.
#[derive(Clone, Debug)]
pub struct Wallet {
    pub signer: PathBuf,
    pub stream_dir: PathBuf,
    /// The task the owner's spending rules know these payments by.
    pub task: String,
    /// The most one tunnel may cost (sats); a tunnel that reaches it ends, and the next flow opens
    /// another, so the owner's rules are asked again.
    pub max_sats: u64,
}

impl Wallet {
    /// From `B2_SIGNER_SOCK`, `B2_STREAM_DIR`, `XBT_VPN_TASK` and
    /// `XBT_VPN_TUNNEL_MAX_SATS` (default 10,000). The task is the starter policy's `default` unless set,
    /// so a box set up before VPN exits existed pays them within the budget it already has.
    pub fn from_env() -> Option<Wallet> {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        Some(Wallet {
            signer: var("B2_SIGNER_SOCK")?.into(),
            stream_dir: var("B2_STREAM_DIR")?.into(),
            task: var("XBT_VPN_TASK").unwrap_or_else(|| "default".into()),
            max_sats: var("XBT_VPN_TUNNEL_MAX_SATS").and_then(|v| v.parse().ok()).unwrap_or(10_000),
        })
    }
}

/// How long the wallet may take to pay a tunnel's opening and hand over its stream.
pub const OPEN_WAIT: Duration = Duration::from_secs(45);

/// A paid tunnel, open, and what the wallet said when it ended (the receiver gets the signer's
/// answer: what was charged, or why it stopped).
pub struct Tunnel {
    pub mux: Mux,
    pub done: std::sync::mpsc::Receiver<Result<Value, String>>,
}

fn random_hex() -> String {
    let mut b = [0u8; 12];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).expect("the system's random source");
    hex::encode(b)
}

/// Opens a paid tunnel at `url` (the exit's announced `tunnel`). Must run inside a Tokio runtime.
/// `Err`: the wallet refused (its rules, its balance) or the seller did not open it, in words.
pub async fn open(w: &Wallet, url: &str) -> io::Result<Tunnel> {
    let (w, url) = (w.clone(), url.to_string());
    let (std_stream, early, done) = tokio::task::spawn_blocking(move || open_blocking(&w, &url))
        .await
        .map_err(|e| io::Error::other(e.to_string()))??;
    std_stream.set_nonblocking(true)?;
    let stream = tokio::net::UnixStream::from_std(std_stream)?;
    Ok(Tunnel { mux: Mux::new(stream, early, true), done })
}

type Opened = (std::os::unix::net::UnixStream, Vec<u8>, std::sync::mpsc::Receiver<Result<Value, String>>);

fn open_blocking(w: &Wallet, url: &str) -> io::Result<Opened> {
    let name = format!("vpn-{}", random_hex());
    let path = w.stream_dir.join(&name);
    let listener = std::os::unix::net::UnixListener::bind(&path)?;
    listener.set_nonblocking(true)?;
    let mut params = json!({"url": url, "method": "GET", "max_sats": w.max_sats, "task": w.task, "upgrade": true,
                            "stream_to": name, "stream_head": true, "head_headers": true,
                            "headers": [["Sec-WebSocket-Key", random_hex()], ["Sec-WebSocket-Version", "13"]]});
    if let Some(m) = params.as_object_mut() {
        xbt_wallet_mcp::wallet::with_transport(m);
    }
    let (tx, done) = std::sync::mpsc::channel();
    let signer = w.signer.clone();
    std::thread::spawn(move || {
        // open until the tunnel ends: the signer answers then
        let _ = tx.send(xbt_wallet_mcp::wallet::signer_call(&signer, Duration::from_secs(7 * 86_400), "xbt402_pay", &params));
    });
    let started = Instant::now();
    let src = loop {
        match listener.accept() {
            Ok((s, _)) => break s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                let _ = std::fs::remove_file(&path);
                return Err(e);
            }
        }
        if let Ok(d) = done.try_recv() {
            let _ = std::fs::remove_file(&path);
            return Err(io::Error::other(refused(&d)));
        }
        if started.elapsed() > OPEN_WAIT {
            let _ = std::fs::remove_file(&path);
            return Err(io::Error::new(io::ErrorKind::TimedOut, "the wallet did not open the tunnel in time"));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let _ = std::fs::remove_file(&path);
    src.set_nonblocking(false)?;
    src.set_read_timeout(Some(OPEN_WAIT))?;
    let mut r = BufReader::new(src);
    let mut line = String::new();
    (&mut r).take(64 * 1024).read_line(&mut line)?;
    let head: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
    if let Some(why) = head.get("error").and_then(Value::as_str) {
        return Err(io::Error::other(why.to_string()));
    }
    if head.get("status").and_then(Value::as_u64) != Some(101) {
        return Err(io::Error::other(format!("the exit did not open the tunnel (HTTP {})", head.get("status").unwrap_or(&Value::Null))));
    }
    let early = r.buffer().to_vec();
    let src = r.into_inner();
    src.set_read_timeout(None)?;
    Ok((src, early, done))
}

/// The signer's answer to a call that ended before its stream opened, in words.
fn refused(d: &Result<Value, String>) -> String {
    match d {
        Ok(v) => {
            let reason = v.get("reason").and_then(Value::as_str).or_else(|| v.get("error").and_then(Value::as_str)).unwrap_or("no reason given");
            format!("the wallet did not pay for the tunnel ({}: {reason})", v.get("rule").and_then(Value::as_str).unwrap_or("refused"))
        }
        Err(e) => format!("the wallet could not be asked ({e})"),
    }
}

/// The exit's tunnel endpoint: the shop's gateway joins each paid tunnel here. Answers the
/// WebSocket upgrade the gateway passes on, then serves the buyer's flows on the joined stream
/// with `serve` (the exit's own [`crate::exit::serve`]). Each tunnel is one buyer's device.
pub async fn serve_tunnel_endpoint<F, Fut>(listener: tokio::net::TcpListener, serve: F)
where
    F: Fn(crate::flow::Carrier) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let serve = Arc::new(serve);
    while let Ok((s, _)) = listener.accept().await {
        let serve = serve.clone();
        tokio::spawn(async move {
            let _ = s.set_nodelay(true);
            if let Ok((s, early)) = answer_upgrade(s).await {
                serve(crate::flow::Carrier::Tunnel(Mux::new(s, early, false))).await;
            }
        });
    }
}

/// Reads an HTTP/1.1 upgrade request and answers `101`; `Err` (answered 400) for anything else.
/// Returns what followed the request's head.
async fn answer_upgrade(mut s: tokio::net::TcpStream) -> io::Result<(tokio::net::TcpStream, Vec<u8>)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = Vec::with_capacity(4096);
    let end = loop {
        let mut chunk = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(15), s.read(&mut chunk)).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no request"))??;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no request"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > 32 * 1024 {
            return Err(io::Error::other("a request head too large"));
        }
    };
    let raw = String::from_utf8_lossy(&buf[..end]).to_string();
    let head = raw.to_ascii_lowercase();
    // the key as sent: its case matters
    let key = raw.lines().find(|l| l.to_ascii_lowercase().starts_with("sec-websocket-key:")).and_then(|l| l.split_once(':')).map(|(_, v)| v.trim().to_string()).unwrap_or_default();
    if !head.starts_with("get ") || !head.lines().any(|l| l.starts_with("upgrade:") && l.contains("websocket")) {
        let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
        return Err(io::Error::other("not a tunnel"));
    }
    let accept = websocket_accept(&key);
    s.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes()).await?;
    Ok((s, buf[end..].to_vec()))
}

/// `Sec-WebSocket-Accept` for a key (RFC 6455). The tunnel's bytes are not WebSocket frames, but
/// the answer is a proper one, so anything between that checks it is satisfied.
fn websocket_accept(key: &str) -> String {
    use base64::Engine;
    let d = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes());
    base64::engine::general_purpose::STANDARD.encode(d.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_websocket_accept_is_rfc_6455s() {
        // RFC 6455, section 1.3
        assert_eq!(websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }
}
