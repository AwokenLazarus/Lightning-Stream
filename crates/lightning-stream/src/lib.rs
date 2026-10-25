//! The Lightning Stream app's connector service. A local program (a video player, a download
//! manager, another app) asks it for a seller's URL; it asks the wallet's signer to pay for that
//! URL and stream the body to a socket of its own, and hands the body on to the program as it
//! arrives. It holds no keys and moves no money itself: every payment is the signer's, under the
//! owner's policy. When the program stops reading, the socket closes and the signer stops paying.
//!
//! `GET /s/<seller URL>`: the seller's answer, paid for as it streams.
//! `GET /health`: whether the signer answers.

use std::io::{self, Read};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt_svc::http::{BodyWriter, Handler, Reply, Request, Response, Streamed};

/// How long a call may wait for the seller's first byte, the payment included.
const FIRST_BYTE: Duration = Duration::from_secs(60);
/// The longest one paid answer is followed (a film).
const LONGEST: Duration = Duration::from_secs(6 * 3600);

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

    /// One paid answer, handed on as it arrives.
    fn stream(&self, url: &str, max_sats: i64) -> Reply {
        let name = format!("ls-{}", random_hex());
        let path = self.cfg.stream_dir.join(&name);
        let listener = match UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) => return Reply::Whole(json_response(500, &json!({"error": format!("stream socket: {e}")}))),
        };
        let _ = listener.set_nonblocking(true);
        // the signer pays and writes the body to the socket; its answer comes when the body has ended
        let (done_tx, done_rx) = mpsc::channel::<Result<Value, String>>();
        let params = json!({"url": url, "max_sats": max_sats, "task": self.cfg.task, "stream_to": name});
        let signer = self.cfg.signer.clone();
        std::thread::spawn(move || {
            let _ = done_tx.send(xbt_wallet_mcp::wallet::signer_call(&signer, LONGEST, "xbt402_pay", &params));
        });
        // the first bytes, or the signer's answer without any: a refusal, said to the program plainly
        let started = Instant::now();
        let mut src = loop {
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
        let mut head = vec![0u8; 64];
        let n = src.read(&mut head).unwrap_or(0);
        head.truncate(n);
        let kind = sniff(&head, url);
        Reply::Stream(Streamed {
            status: 200,
            headers: vec![("Content-Type".into(), kind.into()), ("Cache-Control".into(), "no-store".into())],
            length: None,
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
        let Some(url) = req.target.strip_prefix("/s/") else {
            return Reply::Whole(json_response(404, &json!({"error": "ask for /s/<seller URL>"})));
        };
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return Reply::Whole(json_response(400, &json!({"error": "the seller URL starts with https://"})));
        }
        let max_sats = req.header("X-Max-Sats").and_then(|v| v.parse::<i64>().ok()).filter(|n| *n >= 0).unwrap_or(self.cfg.max_sats).min(self.cfg.max_sats);
        self.stream(url, max_sats)
    }
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

/// The body's type, from its first bytes, then the URL: the signer does not pass the seller's headers on.
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

fn random_hex() -> String {
    let mut b = [0u8; 12];
    getrandom::getrandom(&mut b).expect("the system's random source");
    hex::encode(b)
}

/// Serve the connector on `listener`.
pub fn serve(cfg: Config, listener: std::net::TcpListener) -> io::Result<xbt_svc::http::Running> {
    xbt_svc::http::serve(Arc::new(Connector::new(cfg)), listener, 16)
}
