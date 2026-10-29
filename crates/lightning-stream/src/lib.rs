//! The Lightning Stream app's connector service. A local program (a video player, a download
//! manager, another app) asks it for a seller's URL; it asks the wallet's signer to pay for that
//! URL and stream the body to a socket of its own, and hands the body on to the program as it
//! arrives. It holds no keys and moves no money itself: every payment is the signer's, under the
//! owner's policy. When the program stops reading, the socket closes and the signer stops paying.
//!
//! `GET /s/<seller URL>`: the seller's answer, paid for as it streams.
//! `GET /health`: whether the signer answers.
//!
//! **Not for web pages.** It listens on loopback, so a program elsewhere cannot reach it; but a web
//! page open in a browser on the same machine can (a `<video>` pointed at `127.0.0.1`, or a host
//! name made to resolve to it), and would have the owner pay for what it names. A request that
//! carries what a browser sends with what a page asks for (`Sec-Fetch-*`, `Origin`, `Referer`), or
//! whose `Host` is not a loopback address, is refused. A player, a download manager or the
//! wallet's page (which relays its player's video from its own server) sends none of these. Pages
//! play through the wallet's page, which pays only for its own player.
//!
//! **Seeking.** A client's `Range` header (one range, `bytes=N-` or `bytes=N-M`) goes to the signer
//! as the call's `range`, and the signer sends it to the seller; a `Range` of any other form is
//! ignored and the whole body is asked for, as HTTP lets a server do. Every answer says
//! `Accept-Ranges: bytes` (unless the seller says `none`), so a player knows it may seek. Each seek
//! is a call of its own, paid for the bytes that arrive.
//!
//! **The head before the body.** The signer's answer to `xbt402_pay` comes back on its socket only
//! when the body has ended, too late for the status and headers of a streamed answer. So the
//! connector asks for `stream_head`: the signer writes the seller's head, as it read it, as one
//! line of JSON on the stream socket before the first byte of the body:
//!
//! ```text
//! {"status":206,"content_length":1000,"content_range":"bytes 1000-1999/5000","accept_ranges":"bytes","content_type":"video/mp4"}
//! ```
//!
//! and the connector answers its client with that status, `Content-Range` and `Content-Length`
//! (the body that follows is then framed by its length, so a client sees an answer the wallet
//! stopped as cut short). A head with `error` is an answer the signer will not read (a 206 for
//! another range than was asked): the client gets 502. One socket, one line, no second round trip
//! to the signer and no second request to the seller.

pub mod credentials;
pub mod inference;
pub mod inference_server;

use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt_svc::http::{BodyWriter, Handler, Reply, Request, Response, Streamed};

/// How long a call may wait for the seller's first byte, the payment included.
const FIRST_BYTE: Duration = Duration::from_secs(60);
/// The longest one paid answer is followed (a film).
const LONGEST: Duration = Duration::from_secs(6 * 3600);
/// The longest head line the signer writes before the body.
const HEAD_LINE: u64 = 4096;

pub struct Config {
    /// The signer's socket.
    pub signer: PathBuf,
    /// The directory the signer streams bodies into (`B2_STREAM_DIR`, the same for both).
    pub stream_dir: PathBuf,
    /// The owner's task the calls are paid under.
    pub task: String,
    /// The most one call may spend, in sat.
    pub max_sats: i64,
}

pub struct Connector {
    cfg: Config,
}

impl Connector {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    fn health(&self) -> Response {
        let ok = xbt_wallet_mcp::wallet::signer_call(&self.cfg.signer, Duration::from_secs(5), "ln_status", &json!({})).is_ok();
        json_response(if ok { 200 } else { 503 }, &json!({"signer": ok}))
    }

    /// One paid answer, handed on as it arrives: the seller's status and range from the head line,
    /// then the body.
    fn stream(&self, url: &str, max_sats: i64, range: Option<&str>) -> Reply {
        let name = format!("ls-{}", random_hex());
        let path = self.cfg.stream_dir.join(&name);
        let listener = match listen_stream(&path) {
            Ok(l) => l,
            Err(e) => return Reply::Whole(json_response(500, &json!({"error": format!("stream socket: {e}")}))),
        };
        let _ = listener.set_nonblocking(true);
        // the signer pays and writes the body to the socket; its answer comes when the body has ended
        let (done_tx, done_rx) = mpsc::channel::<Result<Value, String>>();
        let mut params = json!({"url": url, "max_sats": max_sats, "task": self.cfg.task, "stream_to": name, "stream_head": true});
        if let Some(r) = range {
            params["range"] = r.into();
        }
        let signer = self.cfg.signer.clone();
        std::thread::spawn(move || {
            let _ = done_tx.send(xbt_wallet_mcp::wallet::signer_call(&signer, LONGEST, "xbt402_pay", &params));
        });
        // the first bytes, or the signer's answer without any: a refusal, said to the program plainly
        let started = Instant::now();
        let src = loop {
            match listener.accept() {
                Ok((s, _)) => break s,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Reply::Whole(json_response(500, &json!({"error": format!("stream socket: {e}")}))),
            }
            if let Ok(done) = done_rx.try_recv() {
                let _ = std::fs::remove_file(&path);
                return Reply::Whole(refused(done));
            }
            if started.elapsed() > FIRST_BYTE {
                let _ = std::fs::remove_file(&path);
                return Reply::Whole(json_response(504, &json!({"error": "the seller sent nothing within 60 s"})));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let _ = std::fs::remove_file(&path);
        let _ = src.set_nonblocking(false);
        // the seller's head, as the signer read it: one line before the body
        let _ = src.set_read_timeout(Some(FIRST_BYTE));
        let mut src = BufReader::new(src);
        let mut line = String::new();
        let read = (&mut src).take(HEAD_LINE).read_line(&mut line);
        let head: Value = match read {
            Ok(_) if line.ends_with('\n') => serde_json::from_str(&line).unwrap_or(Value::Null),
            _ => Value::Null,
        };
        let _ = src.get_ref().set_read_timeout(None);
        let Some(status) = head.get("status").and_then(Value::as_u64).and_then(|s| u16::try_from(s).ok()).filter(|s| (200..600).contains(s)) else {
            return Reply::Whole(json_response(502, &json!({"error": "the signer sent no head for the answer"})));
        };
        if let Some(why) = head.get("error").and_then(Value::as_str) {
            return Reply::Whole(json_response(502, &json!({"error": why})));
        }
        let mut first = vec![0u8; 64];
        let n = src.read(&mut first).unwrap_or(0);
        first.truncate(n);
        let head_type = head.get("content_type").and_then(Value::as_str).filter(|t| media_type_ok(t)).map(str::to_string);
        let kind = head_type.unwrap_or_else(|| sniff(&first, url).to_string());
        let mut headers = vec![("Content-Type".to_string(), kind), ("Cache-Control".into(), "no-store".into())];
        let seller_ranges = head.get("accept_ranges").and_then(Value::as_str);
        headers.push(("Accept-Ranges".into(), if seller_ranges == Some("none") { "none" } else { "bytes" }.into()));
        if let Some(cr) = head.get("content_range").and_then(Value::as_str).filter(|c| c.len() <= 64 && c.bytes().all(|b| b.is_ascii_graphic() || b == b' ')) {
            headers.push(("Content-Range".into(), cr.into()));
        }
        let length = head.get("content_length").and_then(Value::as_u64);
        let head = first;
        Reply::Stream(Streamed {
            status,
            headers,
            length,
            body: Box::new(move |out: &mut dyn BodyWriter| {
                out.send(&head)?;
                let mut buf = vec![0u8; 64 << 10];
                loop {
                    let n = src.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    // a program that stopped reading: dropping the socket tells the signer to stop paying
                    out.send(&buf[..n])?;
                }
                drop(src);
                // the signer's account of the call, for the log; the body has been handed on already
                let _ = done_rx.recv_timeout(Duration::from_secs(5));
                Ok(())
            }),
        })
    }
}

impl Handler for Connector {
    fn body_limit(&self, _m: &str, _t: &str) -> usize {
        0
    }

    fn handle(&self, req: Request) -> Response {
        match self.reply(req) {
            Reply::Whole(r) => r,
            Reply::Stream(_) => json_response(500, &json!({"error": "a streamed answer where a whole one was asked for"})),
        }
    }

    fn reply(&self, req: Request) -> Reply {
        if req.method != "GET" {
            return Reply::Whole(json_response(405, &json!({"error": "GET only"})));
        }
        if req.target == "/health" {
            return Reply::Whole(self.health());
        }
        if let Some(why) = from_a_page(&req) {
            return Reply::Whole(json_response(403, &json!({"error": why})));
        }
        let Some(url) = req.target.strip_prefix("/s/") else {
            return Reply::Whole(json_response(404, &json!({"error": "ask for /s/<seller URL>"})));
        };
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return Reply::Whole(json_response(400, &json!({"error": "the seller URL starts with https://"})));
        }
        let max_sats = req.header("X-Max-Sats").and_then(|v| v.parse::<i64>().ok()).filter(|n| *n >= 0).unwrap_or(self.cfg.max_sats).min(self.cfg.max_sats);
        let range = req.header("Range").map(str::trim).filter(|r| one_range(r));
        self.stream(url, max_sats, range)
    }
}

/// Why `req` is refused as a web page's ([`crate`]'s "Not for web pages"); `None`: a program's.
pub fn from_a_page(req: &Request) -> Option<&'static str> {
    let has = |k: &str| req.headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(k));
    if req.headers.iter().any(|(n, _)| n.len() > 10 && n[..10].eq_ignore_ascii_case("sec-fetch-")) || has("Origin") || has("Referer") {
        return Some("refused: a web page cannot have this connector pay; play through the wallet's page");
    }
    let host = req.header("Host").unwrap_or("").trim();
    let name = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => host.rsplit_once(':').map_or(host, |(h, _)| h),
    };
    let loopback = name.eq_ignore_ascii_case("localhost") || name.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback());
    (!loopback).then_some("refused: a Host that is not this machine's loopback (a name made to resolve to it)")
}

/// Whether `r` is one byte range the signer takes: `bytes=N-` or `bytes=N-M`, N <= M.
pub fn one_range(r: &str) -> bool {
    let num = |s: &str| (!s.is_empty() && s.len() <= 19 && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse::<u64>().ok()).flatten();
    let Some((a, b)) = r.strip_prefix("bytes=").and_then(|s| s.split_once('-')) else { return false };
    match (num(a), b.is_empty(), num(b)) {
        (Some(_), true, _) => true,
        (Some(a), false, Some(b)) => a <= b,
        _ => false,
    }
}

/// A media type of plain characters (the signer passes on only such a one; checked again here).
fn media_type_ok(t: &str) -> bool {
    !t.is_empty() && t.len() <= 128 && t.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~/;= ".contains(&b))
}

/// A call that ended before any byte came: the wallet's refusal, or the signer's error.
fn refused(done: Result<Value, String>) -> Response {
    match done {
        Ok(v) => {
            let rule = v.get("rule").and_then(Value::as_str).unwrap_or("");
            let reason = v.get("reason").and_then(Value::as_str).unwrap_or("the call ended with no body");
            json_response(402, &json!({"error": reason, "rule": rule}))
        }
        Err(e) => json_response(502, &json!({"error": e})),
    }
}

/// The body's type, from its first bytes, then the URL: for a seller that states no plain `Content-Type`.
pub fn sniff(head: &[u8], url: &str) -> &'static str {
    if head.len() >= 8 && &head[4..8] == b"ftyp" {
        return "video/mp4";
    }
    if head.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        return "video/x-matroska";
    }
    if head.starts_with(b"#EXTM3U") {
        return "application/vnd.apple.mpegurl";
    }
    if head.first() == Some(&0x47) {
        return "video/mp2t";
    }
    if head.starts_with(b"ID3") {
        return "audio/mpeg";
    }
    if head.starts_with(b"{") || head.starts_with(b"[") {
        return "application/json";
    }
    let path = url.split('?').next().unwrap_or("");
    if path.ends_with(".html") || path.ends_with('/') {
        return "text/html";
    }
    "application/octet-stream"
}

fn json_response(status: u16, v: &Value) -> Response {
    Response::text(status, "application/json", v.to_string())
}

/// Bind `path` and make it group-writable. The signer's user connects to it; a process umask would
/// leave the socket owner-only, and the directory's group is that user.
fn listen_stream(path: &Path) -> io::Result<UnixListener> {
    let listener = UnixListener::bind(path)?;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)) {
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(listener)
}

fn random_hex() -> String {
    let mut b = [0u8; 12];
    getrandom::getrandom(&mut b).expect("the system's random source");
    hex::encode(b)
}

/// Serve the connector on `listener`.
pub fn serve(cfg: Config, listener: std::net::TcpListener) -> io::Result<xbt_svc::http::Running> {
    xbt_svc::http::serve(Arc::new(Connector::new(cfg)), listener, 16)
}

#[cfg(test)]
mod tests {
    use super::listen_stream;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_stream_socket_is_group_writable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ls-abc");
        let listener = listen_stream(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660);
        drop(listener);
    }
}
