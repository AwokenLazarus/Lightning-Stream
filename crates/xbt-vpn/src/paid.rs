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
    /// The most the tunnel itself may be charged, where that is less than `max_sats` (a region check):
    /// the wallet may still buy the exit's whole ticket within `max_sats`, and what the check does
    /// not use stays as credit with that exit's shop for the next tunnel.
    pub max_charge_sats: Option<u64>,
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
            max_charge_sats: None,
        })
    }

    /// This wallet as a region check uses it: no more than [`crate::holds::REGION_CHECK_TICKET_SATS`]
    /// may leave it for the check (one ticket of the exit's shop, for a buyer with no credit there),
    /// and the check is charged no more than [`crate::buyer::REGION_CHECK_MAX_SATS`].
    pub fn for_region_check(&self) -> Wallet {
        let max_sats = self.max_sats.min(crate::holds::REGION_CHECK_TICKET_SATS);
        Wallet { max_sats, max_charge_sats: Some(crate::buyer::REGION_CHECK_MAX_SATS.min(max_sats)), ..self.clone() }
    }
}

/// How long the wallet may take to pay a tunnel's opening and hand over its stream. Shorter than
/// the wallet's own wait for a payment (60 s and 5 more): a tunnel whose first ticket takes longer is
/// given up here and tried again. Nothing is lost: the answer that comes later says what left, and
/// the ticket's credit stays with the seller for the next opening.
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

/// The `price_ceiling` of a tunnel to an exit that announced `price_msat_per_gb`: the shop's route
/// is priced per GiB at that number and nothing per request, so the wallet pays no more than that.
pub fn ceiling(price_msat_per_gb: u64) -> Value {
    json!({"request_msat": 0, "gib_msat": price_msat_per_gb})
}

/// Opens a paid tunnel at `url` (the exit's announced `tunnel`), paying no more than `ceiling` (the
/// price the exit announced, [`ceiling`]). Must run inside a Tokio runtime.
/// `Err`: the wallet refused (its rules, its balance, terms above the ceiling) or the seller did not
/// open it, in words.
pub async fn open(w: &Wallet, url: &str, ceiling: Option<Value>) -> io::Result<Tunnel> {
    let (w, url) = (w.clone(), url.to_string());
    let (std_stream, early, done) = tokio::task::spawn_blocking(move || open_blocking(&w, &url, ceiling))
        .await
        .map_err(|e| io::Error::other(e.to_string()))??;
    std_stream.set_nonblocking(true)?;
    let stream = tokio::net::UnixStream::from_std(std_stream)?;
    Ok(Tunnel { mux: Mux::new(stream, early, true), done })
}

type Opened = (std::os::unix::net::UnixStream, Vec<u8>, std::sync::mpsc::Receiver<Result<Value, String>>);

fn open_blocking(w: &Wallet, url: &str, ceiling: Option<Value>) -> io::Result<Opened> {
    let name = format!("vpn-{}", random_hex());
    let path = w.stream_dir.join(&name);
    let listener = std::os::unix::net::UnixListener::bind(&path)?;
    let_the_signer_in(&path, &w.stream_dir)?;
    listener.set_nonblocking(true)?;
    let mut params = json!({"url": url, "method": "GET", "max_sats": w.max_sats, "task": w.task, "upgrade": true,
                            "stream_to": name, "stream_head": true, "head_headers": true,
                            "headers": [["Sec-WebSocket-Key", random_hex()], ["Sec-WebSocket-Version", "13"]]});
    if let Some(m) = params.as_object_mut() {
        if let Some(c) = ceiling {
            m.insert("price_ceiling".into(), c);
        }
        if let Some(c) = w.max_charge_sats {
            m.insert("max_charge_sats".into(), c.into());
        }
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
            let left = match &d {
                Ok(v) => left_sats(v),
                Err(_) => None,
            };
            return Err(io::Error::other(NotOpened { why: refused(&d), left_sats: left }));
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

/// The signer (another user, in a package) connects to the tunnel's socket to hand over the paid stream,
/// and connecting to a Unix socket needs write on it: a socket bound under the default umask (0755)
/// keeps the signer out, the signer finds "a reader already gone", and the tunnel ends as it opens
/// (a 101 with no bytes). The socket takes the stream dir's group (xbt-streams, which has the signer
/// and this service in it) and 0660: whoever may enter that dir may connect, and no one else.
fn let_the_signer_in(sock: &std::path::Path, dir: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let gid = std::fs::metadata(dir)?.gid();
    if std::fs::metadata(sock)?.gid() != gid {
        // only a group this process is in; otherwise the mode alone has to do
        let _ = std::os::unix::fs::chown(sock, None, Some(gid));
    }
    std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o660))
}

/// A tunnel the wallet did not open: why, in words, and what the wallet's answer says left it for
/// the tunnel (sats; `None`: not known, as when it gave no answer before the opening was given up).
#[derive(Debug)]
pub struct NotOpened {
    pub why: String,
    pub left_sats: Option<u64>,
}

impl std::fmt::Display for NotOpened {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.why)
    }
}

impl std::error::Error for NotOpened {}

/// What left the wallet for a tunnel [`open`] did not open, by the wallet's answer (`None`: not known).
pub fn left_of(e: &io::Error) -> Option<u64> {
    e.get_ref().and_then(|x| x.downcast_ref::<NotOpened>()).and_then(|n| n.left_sats)
}

/// What left the wallet for a call, by its answer: the tickets it released for the call
/// (`charged_sats`: bought for it, or held as credit and spent on it), or nothing where it refused the
/// call before paying (`verdict` deny), and a refusal that says it did pay counts what it says: a
/// prepaid ticket with no final answer yet (`rule` ticket_prepay_pending) is in its `charged_sats`.
/// `None` where the answer says neither, and where it tells of a seller's fault or a payment it did
/// not count (`rule` ticket_seller_fault, `verdict` pending, a `seller_fault` or an
/// `unconfirmed_release`): that count may be less than what left.
pub fn left_sats(v: &Value) -> Option<u64> {
    let says = |k: &str| v.get(k).is_some_and(|x| !x.is_null());
    if v.get("rule").and_then(Value::as_str) == Some("ticket_seller_fault")
        || v.get("verdict").and_then(Value::as_str) == Some("pending")
        || says("seller_fault")
        || says("unconfirmed_release")
    {
        return None;
    }
    match v.get("charged_sats") {
        Some(n) => n.as_u64().or_else(|| n.as_str().and_then(|s| s.parse().ok())).or_else(|| n.as_i64().map(|i| i.max(0) as u64)),
        None => (v.get("verdict").and_then(Value::as_str) == Some("deny")).then_some(0),
    }
}

/// How long a tunnel's end may take to be answered by the wallet: it waits for the seller's last
/// receipt first.
pub const ANSWER_WAIT: Duration = Duration::from_secs(30);

/// What left the wallet for a tunnel, by its answer once the tunnel has ended (`None`: no answer in
/// `wait` ([`ANSWER_WAIT`] in use), an error, or an answer that does not say). Blocks.
pub fn left_after(done: &std::sync::mpsc::Receiver<Result<Value, String>>, wait: Duration) -> Option<u64> {
    done.recv_timeout(wait).ok()?.ok().as_ref().and_then(left_sats)
}

/// The signer's answer to a call that ended before its stream opened, in words.
fn refused(d: &Result<Value, String>) -> String {
    match d {
        Ok(v) => {
            let reason = v.get("reason").and_then(Value::as_str).or_else(|| v.get("error").and_then(Value::as_str)).unwrap_or("no reason given");
            let rule = v.get("rule").and_then(Value::as_str).unwrap_or("refused");
            // a refusal may come after a payment: not "did not pay" where it says something left
            match v.get("charged_sats").and_then(Value::as_i64).filter(|n| *n > 0) {
                Some(n) => format!("the wallet paid {n} sat and the tunnel did not open ({rule}: {reason})"),
                None => format!("the wallet did not pay for the tunnel ({rule}: {reason})"),
            }
        }
        Err(e) => format!("the wallet could not be asked ({e})"),
    }
}

/// The header the shop's gateway sends the tunnel endpoint, with the secret the two share
/// ([`TUNNEL_SECRET_FILE`] in the VPN service's directory): only the gateway, which is paid, opens a
/// tunnel. Another app on the same network cannot.
pub const TUNNEL_HEADER: &str = "X-Stream-Tunnel";
/// The shared secret's file, in the VPN service's directory (the wallet app writes it with the route).
pub const TUNNEL_SECRET_FILE: &str = "tunnel.secret";

/// A new secret for [`TUNNEL_SECRET_FILE`]: 32 random bytes, hex.
pub fn new_tunnel_secret() -> String {
    let mut b = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).expect("the system's random source");
    hex::encode(b)
}

/// Whether `s` is a whole tunnel secret as [`new_tunnel_secret`] makes one: 64 lowercase hex
/// digits. A short or partial file is not one.
pub fn is_tunnel_secret(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Why there is no usable secret in `dir`, in words for the owner; `None` if there is one.
pub fn tunnel_secret_problem(dir: &std::path::Path) -> Option<&'static str> {
    match std::fs::read_to_string(dir.join(TUNNEL_SECRET_FILE)) {
        Ok(s) if is_tunnel_secret(s.trim()) => None,
        Ok(_) => Some("the tunnel secret file is cut short or garbled: the wallet app writes it again when the exit is saved"),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            Some("the VPN service can't read the tunnel secret (written by an older version): restart the app, which gives it to the service")
        }
        Err(_) => Some("no tunnel secret from the wallet app yet: open the Sell page's VPN exit and save it"),
    }
}

/// The secret in `dir`'s [`TUNNEL_SECRET_FILE`], if there is a whole one.
pub fn tunnel_secret_in(dir: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(dir.join(TUNNEL_SECRET_FILE)).ok().map(|s| s.trim().to_string()).filter(|s| is_tunnel_secret(s))
}

/// The exit's tunnel endpoint: the shop's gateway joins each paid tunnel here. Answers the
/// WebSocket upgrade the gateway passes on, then serves the buyer's flows on the joined stream
/// with `serve` (the exit's own [`crate::exit::serve`]). Each tunnel is one buyer's device.
/// `secret` is asked for each upgrade (the file is read again, so a secret written after the
/// service started, or replaced, holds at once): an upgrade that does not carry it in
/// [`TUNNEL_HEADER`] is refused, and while there is none every upgrade is (fails closed).
pub async fn serve_tunnel_endpoint<S, F, Fut>(listener: tokio::net::TcpListener, secret: S, serve: F)
where
    S: Fn() -> Option<String> + Send + Sync + 'static,
    F: Fn(crate::flow::Carrier) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (serve, secret) = (Arc::new(serve), Arc::new(secret));
    while let Ok((s, _)) = listener.accept().await {
        let (serve, secret) = (serve.clone(), secret.clone());
        tokio::spawn(async move {
            let _ = s.set_nodelay(true);
            let want = secret();
            if let Ok((s, early)) = answer_upgrade(s, want.as_deref()).await {
                serve(crate::flow::Carrier::Tunnel(Mux::new(s, early, false))).await;
            }
        });
    }
}

/// Reads an HTTP/1.1 upgrade request and answers `101`; `Err` (answered 400) for anything else.
/// Returns what followed the request's head.
async fn answer_upgrade(mut s: tokio::net::TcpStream, secret: Option<&str>) -> io::Result<(tokio::net::TcpStream, Vec<u8>)> {
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
    // no secret (none written yet, or not a whole one): nobody is let in
    let Some(want) = secret else {
        let _ = s.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
        return Err(io::Error::other("the exit has no tunnel secret yet"));
    };
    {
        let name = format!("{}:", TUNNEL_HEADER.to_ascii_lowercase());
        let given = raw.lines().find(|l| l.to_ascii_lowercase().starts_with(&name)).and_then(|l| l.split_once(':')).map(|(_, v)| v.trim()).unwrap_or("");
        // compared by their digests, so the time taken says nothing about the secret
        let digest = |v: &str| ring::digest::digest(&ring::digest::SHA256, v.as_bytes()).as_ref().to_vec();
        if digest(given) != digest(want) {
            let _ = s.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
            return Err(io::Error::other("not from the shop's gateway"));
        }
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

    #[tokio::test]
    async fn only_the_gateway_with_the_secret_opens_a_tunnel() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = l.local_addr().unwrap();
        let secret = "5".repeat(64);
        let s2 = secret.clone();
        tokio::spawn(serve_tunnel_endpoint(l, move || Some(s2.clone()), |_c| async {}));
        let ask = |extra: String| async move {
            let mut s = tokio::net::TcpStream::connect(at).await.unwrap();
            s.write_all(format!("GET /vpn/tunnel HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: k\r\n{extra}\r\n").as_bytes()).await.unwrap();
            let mut b = [0u8; 12];
            let _ = s.read_exact(&mut b).await;
            String::from_utf8_lossy(&b).to_string()
        };
        // another app on the network, without the secret or with a wrong one: refused
        assert_eq!(ask(String::new()).await, "HTTP/1.1 403");
        assert_eq!(ask(format!("X-Stream-Tunnel: {}\r\n", "t".repeat(32))).await, "HTTP/1.1 403");
        // the shop's gateway, with it: the tunnel opens
        assert_eq!(ask(format!("x-stream-tunnel: {secret}\r\n")).await, "HTTP/1.1 101");
    }

    /// A priced exit with no good secret (none yet, or a short or partial file) answers nobody: it
    /// fails closed, so no app on the box's network rides it unpaid.
    #[tokio::test]
    async fn a_priced_exit_without_a_good_secret_answers_nobody() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = l.local_addr().unwrap();
        tokio::spawn(serve_tunnel_endpoint(l, || None, |_c| async {}));
        let mut s = tokio::net::TcpStream::connect(at).await.unwrap();
        s.write_all(b"GET /vpn/tunnel HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: k\r\n\r\n").await.unwrap();
        let mut b = [0u8; 12];
        let _ = s.read_exact(&mut b).await;
        assert_eq!(String::from_utf8_lossy(&b), "HTTP/1.1 503");
    }

    /// The secret is read for each upgrade: written after the service started (the wallet app
    /// writes it with the shop's route), it holds at once; a short or partial file is no secret.
    #[tokio::test]
    async fn the_secret_is_read_for_each_tunnel_and_must_be_whole() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let d = tempfile::tempdir().unwrap();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = l.local_addr().unwrap();
        let dir = d.path().to_path_buf();
        tokio::spawn(serve_tunnel_endpoint(l, move || tunnel_secret_in(&dir), |_c| async {}));
        let ask = |extra: String| async move {
            let mut s = tokio::net::TcpStream::connect(at).await.unwrap();
            s.write_all(format!("GET /vpn/tunnel HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: k\r\n{extra}\r\n").as_bytes()).await.unwrap();
            let mut b = [0u8; 12];
            let _ = s.read_exact(&mut b).await;
            String::from_utf8_lossy(&b).to_string()
        };
        let secret = new_tunnel_secret();
        assert_eq!(ask(format!("{TUNNEL_HEADER}: {secret}\r\n")).await, "HTTP/1.1 503", "no secret yet: closed");
        // a partial write, half the secret: still no secret
        std::fs::write(d.path().join(TUNNEL_SECRET_FILE), &secret[..32]).unwrap();
        assert_eq!(ask(format!("{TUNNEL_HEADER}: {}\r\n", &secret[..32])).await, "HTTP/1.1 503", "a short secret is none");
        std::fs::write(d.path().join(TUNNEL_SECRET_FILE), &secret).unwrap();
        assert_eq!(ask(format!("{TUNNEL_HEADER}: {secret}\r\n")).await, "HTTP/1.1 101", "written after start, it holds at once");
        assert_eq!(ask(String::new()).await, "HTTP/1.1 403");
    }

    #[test]
    fn why_there_is_no_secret_is_said_plainly() {
        let d = tempfile::tempdir().unwrap();
        assert!(tunnel_secret_problem(d.path()).unwrap().contains("no tunnel secret"));
        std::fs::write(d.path().join(TUNNEL_SECRET_FILE), "abc").unwrap();
        assert!(tunnel_secret_problem(d.path()).unwrap().contains("cut short"));
        std::fs::write(d.path().join(TUNNEL_SECRET_FILE), new_tunnel_secret()).unwrap();
        assert_eq!(tunnel_secret_problem(d.path()), None);
    }

    #[test]
    fn the_websocket_accept_is_rfc_6455s() {
        // RFC 6455, section 1.3
        assert_eq!(websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }
    #[test]
    fn the_tunnels_socket_lets_the_signer_in_by_the_stream_dirs_group() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = std::env::temp_dir().join(format!("vpn-sock-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("vpn-x");
        let _l = std::os::unix::net::UnixListener::bind(&p).unwrap();
        let_the_signer_in(&p, &d).unwrap();
        let m = std::fs::metadata(&p).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o660, "the group (the signer) may connect, others may not");
        assert_eq!(m.gid(), std::fs::metadata(&d).unwrap().gid());
        std::fs::remove_dir_all(&d).unwrap();
    }

}
