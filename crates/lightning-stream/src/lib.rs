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
//! (the body that follows is then framed by its length, or chunked where the head states none; either
//! way a client sees an answer the wallet stopped as cut short, [`whole`]). A head with `error` is an answer the signer will not read (a 206 for
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

mod visit;
pub use visit::Visits;

/// How long a call may wait for the seller's first byte, the payment included.
pub(crate) const FIRST_BYTE: Duration = Duration::from_secs(60);
/// How long a call waits for the signer to begin the answer, or to say why it will not: longer than
/// the signer's own wait for a call's ordinary payment (`xbt402::ticket::ORDINARY_PAY_S`, 60 s,
/// whatever the owner's `ln.timeout_s`, and 5 s more, counted from before the payment is sent) and
/// the lock before it, so that a payment refused at the seller (an invoice that lapsed on a slow
/// route) is told to the buyer in the signer's words, not as a bare timeout.
pub(crate) const FIRST_ANSWER: Duration = Duration::from_secs(90);
// the wallet's own wait for a call's ordinary payment ends first, whatever the owner's policy says
const _: () = assert!(FIRST_ANSWER.as_secs() > xbt402::ticket::ORDINARY_PAY_S as u64 + 5);
/// The longest one paid answer is followed (a film): past the most an owner can set
/// `tickets.max_stream_s` to, so that the wallet ends an answer and says so before this gives up on it.
pub(crate) const LONGEST: Duration = Duration::from_secs(25 * 3600);
/// The longest head line the signer writes before the body.
pub(crate) const HEAD_LINE: u64 = 4096;
/// How long a streamed body's end waits for the signer's account of the call: it takes the session's
/// order first, then asks the seller for the last receipt (5 s a try, given up after 30 s), on a
/// slow link or behind other calls of the session.
pub(crate) const ACCOUNT_WAIT: Duration = Duration::from_secs(120);

/// Whether a streamed answer that has ended was whole (`Ok`). With a length announced its bytes say,
/// and nothing is waited for; with none it is whole only by the signer's account of the call
/// (`account`, asked only then). An answer the wallet ended early, for any reason, or with no account
/// in time, is an error, so that the client sees a body cut short (a `Content-Length` body short of
/// its length, or a chunked one with no last chunk), never a short file that looks whole.
pub(crate) fn whole(length: Option<u64>, sent: u64, account: impl FnOnce() -> Option<Result<Value, String>>) -> io::Result<()> {
    match length {
        Some(l) if sent >= l => return Ok(()),
        // short of what was announced: cut, whatever the account says, and it is not waited for
        Some(l) => return Err(io::Error::other(format!("the answer was cut short after {sent} bytes of {l}"))),
        None => {}
    }
    match account() {
        Some(Ok(v)) if v.get("complete").and_then(Value::as_bool) == Some(true) => Ok(()),
        Some(Ok(v)) => {
            let why = v.get("ended").and_then(Value::as_str).or_else(|| v.get("error").and_then(Value::as_str)).unwrap_or("the wallet stopped reading it");
            Err(io::Error::other(format!("the answer was cut short after {sent} bytes: {why}")))
        }
        Some(Err(e)) => Err(io::Error::other(format!("the answer was cut short after {sent} bytes: {e}"))),
        None => Err(io::Error::other(format!("the answer ended after {sent} bytes and the wallet did not say it was whole"))),
    }
}

/// The connector's paid calls the signer has now, by shop (its origin) and by who made them (a visit's id, `stream` for a
/// program's or a player link's, `ai` for the AI endpoint's). They share one connection with each shop (the signer keeps
/// one session for a shop and the connector's task), which a visit's Stop closes only where no other of them uses it.
/// Kept by the signer they go to (its socket), the shop and the caller.
static FLIGHTS: std::sync::Mutex<Vec<(PathBuf, String, String)>> = std::sync::Mutex::new(Vec::new());

/// The origin of an absolute URL (`https://host:port`): its scheme and authority, without the path.
pub(crate) fn origin_of(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => format!("{scheme}://{}", rest.split(['/', '?', '#']).next().unwrap_or(rest)).to_ascii_lowercase(),
        None => url.to_ascii_lowercase(),
    }
}

/// One paid call of the connector's, counted while it lives ([`FLIGHTS`]).
pub(crate) struct Flight(Option<(PathBuf, String, String)>);

/// A paid call to `url`'s shop by `owner`, through the signer at `signer`, counted until the returned guard is dropped.
pub(crate) fn flight(signer: &Path, url: &str, owner: &str) -> Flight {
    let key = (signer.to_path_buf(), origin_of(url), owner.to_string());
    FLIGHTS.lock().unwrap_or_else(|p| p.into_inner()).push(key.clone());
    Flight(Some(key))
}

impl Drop for Flight {
    fn drop(&mut self) {
        if let Some(key) = self.0.take() {
            let mut all = FLIGHTS.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(i) = all.iter().position(|k| *k == key) {
                all.swap_remove(i);
            }
        }
    }
}

/// Whether a paid call to the shop at `origin` by anyone but `owner` is with the signer at `signer` now.
pub(crate) fn in_flight_besides(signer: &Path, origin: &str, owner: &str) -> bool {
    let origin = origin.to_ascii_lowercase();
    FLIGHTS.lock().unwrap_or_else(|p| p.into_inner()).iter().any(|(s, o, w)| s == signer && *o == origin && w != owner)
}

#[derive(Clone)]
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
    visits: Arc<Visits>,
}

impl Connector {
    pub fn new(cfg: Config) -> Self {
        Self { cfg, visits: Arc::default() }
    }

    fn health(&self) -> Response {
        let ok = xbt_wallet_mcp::wallet::signer_call(&self.cfg.signer, Duration::from_secs(5), "ln_status", &json!({})).is_ok();
        json_response(if ok { 200 } else { 503 }, &json!({"signer": ok}))
    }

    /// One paid answer, handed on as it arrives: the seller's status and range from the head line,
    /// then the body.
    fn stream(&self, url: &str, max_sats: i64, range: Option<&str>, if_range: Option<&str>, ceiling: Option<Value>, max_size: Option<u64>) -> Reply {
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
            // the player's own validator of the copy it has: a changed file comes back whole, and is not spliced on
            if let Some(v) = if_range {
                params["if_range"] = v.into();
            }
        }
        // the seller's listed prices, where the caller chose it from a listing: its terms past them are paid nothing
        if let Some(c) = ceiling {
            params["price_ceiling"] = c;
        }
        // the most bytes the caller was shown the file has: a seller that says it sends more is refused before its body
        if let Some(n) = max_size {
            params["max_size"] = n.into();
        }
        if let Some(m) = params.as_object_mut() {
            xbt_wallet_mcp::wallet::with_transport(m);
        }
        let signer = self.cfg.signer.clone();
        // counted among the connector's calls to the shop while the signer has it ([`in_flight_besides`])
        let flight = flight(&self.cfg.signer, url, "stream");
        std::thread::spawn(move || {
            let _flight = flight;
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
            if started.elapsed() > FIRST_ANSWER {
                let _ = std::fs::remove_file(&path);
                return Reply::Whole(json_response(504, &json!({"error": format!("the seller sent nothing within {} s", FIRST_ANSWER.as_secs())})));
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
        // the seller sent the whole file for a part of it (its copy changed since the player's, or it serves no
        // ranges): the wallet read none of it, and nothing of another copy is spliced onto what the player has
        if head.get("range_ignored") == Some(&Value::Bool(true)) {
            return Reply::Whole(json_response(412, &json!({"error": "ticket_range_ignored: the seller answered the range with the whole file (its copy changed, \
                                                                     or it serves no ranges); none of it was read. Ask again from the start"})));
        }
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
        // the copy's validators, which the player names in `If-Range` when it seeks
        for (k, name) in [("etag", "ETag"), ("last_modified", "Last-Modified")] {
            if let Some(x) = head.get(k).and_then(Value::as_str).filter(|x| x.len() <= 256 && x.bytes().all(|b| (0x20..0x7f).contains(&b))) {
                headers.push((name.into(), x.into()));
            }
        }
        let length = head.get("content_length").and_then(Value::as_u64);
        let head = first;
        Reply::Stream(Streamed {
            status,
            headers,
            length,
            body: Box::new(move |out: &mut dyn BodyWriter| {
                out.send(&head)?;
                let mut sent = head.len() as u64;
                let mut buf = vec![0u8; 64 << 10];
                loop {
                    let n = src.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    // a program that stopped reading: dropping the socket tells the signer to stop paying
                    out.send(&buf[..n])?;
                    sent += n as u64;
                }
                drop(src);
                // the signer's account of the call: an answer it ended early is cut short for the client too
                whole(length, sent, || done_rx.recv_timeout(ACCOUNT_WAIT).ok())
            }),
        })
    }
}

impl Handler for Connector {
    /// Stopping a visit goes past the handler slots: requests stuck on a seller hold them, and the stop
    /// is what frees the buyer of those.
    fn urgent(&self, req: &Request) -> bool {
        req.method == "POST" && req.target.starts_with("/visits/") && req.target.ends_with("/stop")
    }

    fn body_limit(&self, _m: &str, t: &str) -> usize {
        if t.starts_with("/v/") {
            visit::MAX_BODY
        } else if t.starts_with("/visits") {
            4096
        } else {
            0
        }
    }

    fn handle(&self, req: Request) -> Response {
        match self.reply(req) {
            Reply::Whole(r) => r,
            Reply::Stream(_) | Reply::Upgrade(_) => json_response(500, &json!({"error": "a streamed answer where a whole one was asked for"})),
        }
    }

    fn reply(&self, req: Request) -> Reply {
        if let Some(r) = self.visits_reply(&req) {
            return r;
        }
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
        let if_range = req.header("If-Range").map(str::trim).filter(|v| !v.is_empty() && v.len() <= 256);
        // `X-Price-Ceiling`: the listing's prices as the most this call pays. Only ever stricter than none
        let ceiling = req.header("X-Price-Ceiling").filter(|v| v.len() <= 1024).and_then(|v| serde_json::from_str::<Value>(v).ok()).filter(Value::is_object);
        // `X-Max-Size`: the most bytes the caller was shown the resource has (a listed file's size)
        let max_size = req.header("X-Max-Size").and_then(|v| v.trim().parse::<u64>().ok()).filter(|n| *n > 0);
        self.stream(url, max_sats, range, if_range, ceiling, max_size)
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

pub(crate) fn json_response(status: u16, v: &Value) -> Response {
    Response::text(status, "application/json", v.to_string())
}

/// Bind `path` and make it group-writable. The signer's user connects to it; a process umask would
/// leave the socket owner-only, and the directory's group is that user.
pub(crate) fn listen_stream(path: &Path) -> io::Result<UnixListener> {
    let listener = UnixListener::bind(path)?;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)) {
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(listener)
}

pub(crate) fn random_hex() -> String {
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
    use super::{listen_stream, whole};
    use serde_json::{json, Value};
    use std::os::unix::fs::PermissionsExt;

    /// A call's first answer is waited for longer than the wallet waits for the call's payment, so
    /// that a payment refused at the seller is told in the wallet's words, not as a timeout.
    #[test]
    fn a_call_waits_for_its_first_answer_longer_than_the_wallet_waits_for_its_payment() {
        assert!(super::FIRST_ANSWER.as_secs() > u64::from(xbt402::ticket::ORDINARY_PAY_S) + 5);
    }

    #[test]
    fn an_answer_is_whole_by_its_length_or_the_signers_account_and_otherwise_cut() {
        let never = || -> Option<Result<Value, String>> { panic!("all of a stated length needs no account") };
        assert!(whole(Some(10), 10, never).is_ok());
        let said = |v: Value| move || Some(Ok(v));
        // no length stated: the account says
        assert!(whole(None, 10, said(json!({"complete": true}))).is_ok());
        let cut = whole(None, 10, said(json!({"complete": false, "ended": "max_sats"}))).unwrap_err().to_string();
        assert!(cut.contains("max_sats") && cut.contains("10 bytes"), "{cut}");
        // short of a stated length is cut, and no account is waited for
        assert!(whole(Some(20), 10, never).is_err());
        // an error from the signer, or no account in time, is not whole
        assert!(whole(None, 10, || Some(Err("gone".to_string()))).is_err());
        assert!(whole(None, 10, || None).unwrap_err().to_string().contains("did not say"));
    }

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
