//! One Electrum server: newline-delimited JSON-RPC over TCP or TLS (rustls), with batching,
//! notifications, reconnect on demand and subscriptions re-sent after a reconnect.
//!
//! A reader thread per connection blocks on the socket and routes each answer to the request that
//! waits for it (by id); notifications go to the `Notify` hook. Requests are written from the
//! caller's thread. A server that stops answering within the timeout is dropped; the next request
//! reconnects.
//!
//! Every request has an answer cap known from its method ([`answer_cap`]): the bytes of its line
//! and the JSON values in it. A line is checked against what the pending requests allow before it
//! is parsed, complete or not, and a server that sends more is dropped (AGP-081, review E1: a line
//! used to be parsed whatever its id, and a dense one costs many times its size as a tree).
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use serde_json::{json, Value};

use crate::error::{err, ElectrumError, Kind, Result};

/// The protocol range we speak: electrs refuses < 1.8 on a chain with 164-byte v2 headers.
pub const PROTOCOL: [&str; 2] = ["1.4", "1.8"];
pub const CLIENT_NAME: &str = "xbt-electrum";
/// No line from a server is longer than this, whatever was asked.
pub const MAX_LINE: usize = 8 << 20;
/// The headers one `blockchain.block.headers` request may ask for (electrs' maximum).
pub const MAX_HEADERS: u64 = 2016;
/// The largest raw transaction fetched. Above it a server's answer is over its cap: the transaction
/// is not learnt from this backend (every standard transaction is at most 400,000 bytes).
pub const MAX_TX_BYTES: usize = 1_000_000;
/// The entries of one `get_history` or `listunspent` answer. A script with more is not answered by
/// this backend.
pub const MAX_HISTORY: usize = 10_000;

/// How large one line from a server may be: its bytes, and the JSON values in it ([`values_in`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cap {
    pub bytes: usize,
    pub values: usize,
}

/// What a line may hold with nothing asked: a tip or script notification.
const IDLE: Cap = Cap { bytes: 16 << 10, values: 64 };
/// An answer that is a number, a short string or a small object, or an error.
const SMALL: Cap = Cap { bytes: 16 << 10, values: 64 };

/// The largest legitimate answer to `method` with `params`, JSON-RPC envelope included.
pub fn answer_cap(method: &str, params: &Value) -> Cap {
    match method {
        "blockchain.block.headers" => {
            let n = params.get(1).and_then(Value::as_u64).unwrap_or(0).min(MAX_HEADERS) as usize;
            Cap { bytes: 4096 + 2 * xbt_primitives::header::V2_SIZE * n, values: SMALL.values }
        }
        "blockchain.transaction.get" => Cap { bytes: 2 * MAX_TX_BYTES + 1024, values: SMALL.values },
        "blockchain.transaction.get_merkle" => Cap { bytes: 8192, values: 128 },
        "blockchain.scripthash.get_history" | "blockchain.scripthash.listunspent" => {
            Cap { bytes: 4096 + 160 * MAX_HISTORY, values: 16 + 6 * MAX_HISTORY }
        }
        _ => SMALL,
    }
}

/// An upper bound on the JSON values in `line`, without parsing it: every value but the first
/// follows a `,`, `[` or `{`. Bytes inside strings count too, which only makes the bound higher
/// (legitimate answers are hex strings and small objects).
pub fn values_in(line: &[u8]) -> usize {
    1 + line.iter().filter(|b| matches!(b, b',' | b'[' | b'{')).count()
}

/// `(server url, method, params)` for every notification a server pushes.
pub type Notify = Arc<dyn Fn(&str, &str, &Value) + Send + Sync>;

/// Where a server is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAddr {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

/// `tcp://host:port`, `ssl://host:port` (or `tls://`), or Electrum's `host:port:t` / `host:port:s`.
pub fn parse_server(url: &str) -> Result<ServerAddr> {
    let bad = || ElectrumError::new(Kind::BadRequest, format!("bad Electrum server {url:?}: use tcp://host:port or ssl://host:port"));
    let (tls, rest) = if let Some((scheme, rest)) = url.split_once("://") {
        match scheme {
            "tcp" => (false, rest),
            "ssl" | "tls" => (true, rest),
            _ => return Err(bad()),
        }
    } else {
        let (hp, t) = url.rsplit_once(':').ok_or_else(bad)?;
        match t {
            "t" => (false, hp),
            "s" => (true, hp),
            _ => return Err(bad()),
        }
    };
    let rest = rest.trim_end_matches('/');
    let (host, port) = rest.rsplit_once(':').ok_or_else(bad)?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port.parse().map_err(|_| bad())?;
    if host.is_empty() || port == 0 {
        return Err(bad());
    }
    Ok(ServerAddr { host: host.to_string(), port, tls })
}

/// The TLS client settings: the Mozilla roots (webpki-roots, compiled in, so every target
/// verifies the same way) plus any extra CA certificates (PEM) for self-hosted servers.
pub fn tls_config(extra_ca_pem: &[&Path]) -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    for p in extra_ca_pem {
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(p)
            .map_err(|e| ElectrumError::new(Kind::BadRequest, format!("CA file {}: {e}", p.display())))?
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| ElectrumError::new(Kind::BadRequest, format!("CA file {}: {e}", p.display())))?;
        if certs.is_empty() {
            return err(Kind::BadRequest, format!("CA file {}: no certificates", p.display()));
        }
        for c in certs {
            roots.add(c).map_err(|e| ElectrumError::new(Kind::BadRequest, format!("CA file {}: {e}", p.display())))?;
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| ElectrumError::new(Kind::BadRequest, e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

enum Link {
    Plain(TcpStream),
    Tls(TcpStream, Box<rustls::ClientConnection>),
}

impl Link {
    fn sock(&self) -> &TcpStream {
        match self {
            Link::Plain(s) | Link::Tls(s, _) => s,
        }
    }

    /// Write `line`, all of it, by `deadline`.
    ///
    /// The rule (AGP-097): **a request is written by one deadline, however slowly the server
    /// reads.** The socket's write timeout is per write, and a write that moved one byte is a
    /// success: a server that reads a little at a time held a large line (a broadcast) for one
    /// timeout per write, with the connection's lock taken, so nothing was read from it either.
    /// Each write here gets what is left of the deadline. An error leaves a line half written:
    /// the caller hangs up.
    fn send(&mut self, line: &[u8], deadline: Instant) -> io::Result<()> {
        fn left(s: &TcpStream, deadline: Instant) -> io::Result<()> {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "the request was not written by its deadline"));
            }
            s.set_write_timeout(Some(left))
        }
        match self {
            Link::Plain(s) => {
                let mut rest = line;
                while !rest.is_empty() {
                    left(s, deadline)?;
                    match s.write(rest) {
                        Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                        Ok(n) => rest = &rest[n..],
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(e),
                    }
                }
                Ok(())
            }
            Link::Tls(s, c) => {
                // rustls takes plaintext only while its buffer of unsent records has room (64 kB),
                // so a line is handed over in pieces, each sent before the next (AGP-106: handed
                // over whole, a line above the buffer was refused before a byte was sent, and no
                // transaction above about 32 kB could be broadcast over TLS).
                let mut rest = line;
                while !rest.is_empty() {
                    let n = c.writer().write(rest)?;
                    rest = &rest[n..];
                    if n == 0 && !c.wants_write() {
                        return Err(io::ErrorKind::WriteZero.into());
                    }
                    while c.wants_write() {
                        left(s, deadline)?;
                        c.write_tls(s)?;
                    }
                }
                Ok(())
            }
        }
    }
}

/// Requests given up at a call's deadline that one connection keeps a slot for.
pub const MAX_GIVEN_UP: usize = 16;

type Pending = Arc<Mutex<HashMap<u64, (SyncSender<Value>, Cap)>>>;

/// What one line may hold now: [`IDLE`] plus the caps of the requests waiting (a server may answer
/// a batch as one line), at most [`MAX_LINE`] bytes.
fn allowance(pending: &Pending) -> Cap {
    let p = lock(pending);
    let sum = p.values().fold(IDLE, |a, (_, c)| Cap { bytes: a.bytes.saturating_add(c.bytes), values: a.values.saturating_add(c.values) });
    Cap { bytes: sum.bytes.min(MAX_LINE), values: sum.values }
}

/// The rule (AGP-106): **a connection keeps a slot for at most [`MAX_GIVEN_UP`] requests nobody
/// waits for.** Each slot adds its answer's cap to what the next line may hold ([`allowance`]), and
/// a server that answers what it is given a whole timeout for, and never the requests of a call's
/// last moments, kept one more per call without end. `ids` are given up now; past the bound the
/// oldest is forgotten. Its answer, if it still comes, is held to what the other requests allow: a
/// small one is dropped unread as before, a large one drops the server like any line nobody asked
/// for.
fn give_up(pending: &Pending, given_up: &Mutex<VecDeque<u64>>, ids: impl Iterator<Item = u64>) {
    let mut p = lock(pending);
    let mut g = lock(given_up);
    g.extend(ids);
    g.retain(|id| p.contains_key(id)); // answered meanwhile: its slot is gone already
    while g.len() > MAX_GIVEN_UP {
        if let Some(old) = g.pop_front() {
            p.remove(&old);
        }
    }
}

struct Live {
    link: Arc<Mutex<Link>>,
    pending: Pending,
    /// The requests in `pending` whose caller stopped waiting at a deadline, oldest first.
    given_up: Arc<Mutex<VecDeque<u64>>>,
    /// Cleared by the reader when the server hangs up.
    alive: Arc<AtomicBool>,
    /// Why the reader dropped the server, when it was for what the server sent.
    fault: Arc<Mutex<Option<String>>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// One server connection. Cheap to share (`Arc`); every method takes `&self`.
pub struct Connection {
    pub url: String,
    pub addr: ServerAddr,
    timeout: Duration,
    tls: Option<Arc<rustls::ClientConfig>>,
    notify: Option<Notify>,
    ids: AtomicU64,
    live: Mutex<Option<Live>>,
    connecting: Mutex<()>,
    subs: Mutex<Vec<(String, Value)>>,
    info: Mutex<(String, String)>,
}

impl Connection {
    /// `tls` is required for an `ssl://` server (see [`tls_config`]).
    pub fn new(url: &str, timeout: Duration, tls: Option<Arc<rustls::ClientConfig>>, notify: Option<Notify>) -> Result<Self> {
        let addr = parse_server(url)?;
        if addr.tls && tls.is_none() {
            return err(Kind::BadRequest, format!("{url}: a TLS server needs a TLS config"));
        }
        Ok(Self {
            url: url.to_string(),
            addr,
            timeout,
            tls,
            notify,
            ids: AtomicU64::new(1),
            live: Mutex::new(None),
            connecting: Mutex::new(()),
            subs: Mutex::new(Vec::new()),
            info: Mutex::new((String::new(), String::new())),
        })
    }

    pub fn connected(&self) -> bool {
        lock(&self.live).as_ref().map(|l| l.alive.load(Ordering::SeqCst)).unwrap_or(false)
    }

    /// (server software, negotiated protocol) from `server.version`.
    pub fn server_info(&self) -> (String, String) {
        lock(&self.info).clone()
    }

    fn unreachable(&self, what: impl std::fmt::Display) -> ElectrumError {
        ElectrumError::new(Kind::Unreachable, format!("{}: {what}", self.url))
    }

    /// How long is left until `deadline`; an error once it has passed.
    fn left(&self, deadline: Instant, what: &str) -> Result<Duration> {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(self.unreachable(format!("{what}: not finished by its deadline")));
        }
        Ok(left)
    }

    fn open_socket(&self, deadline: Instant) -> Result<TcpStream> {
        let addrs = (self.addr.host.as_str(), self.addr.port).to_socket_addrs().map_err(|e| self.unreachable(e))?;
        let mut last = None;
        for a in addrs {
            match TcpStream::connect_timeout(&a, self.left(deadline, "connect")?) {
                Ok(s) => return Ok(s),
                Err(e) => last = Some(e),
            }
        }
        Err(self.unreachable(last.map(|e| e.to_string()).unwrap_or_else(|| "no address".into())))
    }

    /// The TLS handshake, read by read against one deadline. (`complete_io` would wait a full read
    /// timeout for every byte: a server that trickles a record holds it for hours, AGP-092.)
    fn handshake(&self, c: &mut rustls::ClientConnection, s: &mut TcpStream, deadline: Instant) -> Result<()> {
        let tls = |e: &dyn std::fmt::Display| self.unreachable(format!("TLS: {e}"));
        while c.is_handshaking() || c.wants_write() {
            let left = self.left(deadline, "TLS handshake")?;
            s.set_read_timeout(Some(left)).and_then(|_| s.set_write_timeout(Some(left))).map_err(|e| self.unreachable(e))?;
            if c.wants_write() {
                c.write_tls(s).map_err(|e| tls(&e))?;
                continue;
            }
            match c.read_tls(s) {
                Ok(0) => return Err(tls(&"the server hung up during the handshake")),
                Ok(_) => {
                    c.process_new_packets().map_err(|e| tls(&e))?;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(tls(&e)),
            }
        }
        Ok(())
    }

    /// Connect (if not connected), negotiate the protocol, and re-send the subscriptions.
    pub fn connect(&self) -> Result<()> {
        self.connect_until(None)
    }

    /// [`connect`](Self::connect) that gives up at `until`. Rule (AGP-092): reaching a server costs
    /// at most one timeout for the TCP connect and the TLS handshake together, then one for
    /// `server.version` and one for the subscriptions, whatever the server sends and however slowly.
    pub fn connect_until(&self, until: Option<Instant>) -> Result<()> {
        let _g = lock(&self.connecting);
        if self.connected() {
            return Ok(());
        }
        self.close(); // a link the server hung up on
        let deadline = Instant::now() + self.timeout;
        let deadline = until.map_or(deadline, |u| u.min(deadline));
        let sock = self.open_socket(deadline)?;
        let _ = sock.set_nodelay(true);
        let link = if self.addr.tls {
            let cfg = self.tls.clone().expect("checked in new");
            let name = ServerName::try_from(self.addr.host.clone()).map_err(|e| ElectrumError::new(Kind::BadRequest, e.to_string()))?;
            let mut c = rustls::ClientConnection::new(cfg, name).map_err(|e| self.unreachable(e))?;
            let mut s = sock;
            self.handshake(&mut c, &mut s, deadline)?;
            Link::Tls(s, Box::new(c))
        } else {
            Link::Plain(sock)
        };
        link.sock().set_write_timeout(Some(self.timeout)).map_err(|e| self.unreachable(e))?;
        link.sock().set_read_timeout(None).map_err(|e| self.unreachable(e))?;
        let reader = link.sock().try_clone().map_err(|e| self.unreachable(e))?;
        let link = Arc::new(Mutex::new(link));
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let alive = Arc::new(AtomicBool::new(true));
        let fault = Arc::new(Mutex::new(None));
        {
            let (link, pending, notify, url, alive, fault) =
                (link.clone(), pending.clone(), self.notify.clone(), self.url.clone(), alive.clone(), fault.clone());
            std::thread::Builder::new()
                .name(format!("electrum:{url}"))
                .spawn(move || {
                    if let Some(why) = read_loop(reader, link, pending.clone(), notify, url) {
                        *lock(&fault) = Some(why);
                    }
                    alive.store(false, Ordering::SeqCst);
                    lock(&pending).clear(); // waiters see Disconnected, with the fault already set
                })
                .map_err(|e| self.unreachable(e))?;
        }
        *lock(&self.live) = Some(Live { link, pending, given_up: Arc::new(Mutex::new(VecDeque::new())), alive, fault });
        let hello = (|| -> Result<()> {
            // exchange_until() never reconnects: we hold `connecting`
            let v = self.exchange_until(&[("server.version".to_string(), json!([CLIENT_NAME, PROTOCOL]))], until)?.pop().expect("one")?;
            let a = v.as_array().filter(|a| a.len() == 2).ok_or_else(|| self.unreachable("server.version: malformed answer"))?;
            *lock(&self.info) = (a[0].as_str().unwrap_or("").to_string(), a[1].as_str().unwrap_or("").to_string());
            let subs = lock(&self.subs).clone();
            if !subs.is_empty() {
                for r in self.exchange_until(&subs, until)? {
                    r?;
                }
            }
            Ok(())
        })();
        if let Err(e) = hello {
            self.close();
            return Err(e);
        }
        Ok(())
    }

    /// Drop the connection; requests in flight fail, the next request reconnects.
    pub fn close(&self) {
        let l = lock(&self.live).take();
        if let Some(l) = l {
            let _ = lock(&l.link).sock().shutdown(Shutdown::Both);
            lock(&l.pending).clear();
        }
    }

    /// One request.
    pub fn request(&self, method: &str, params: Value) -> Result<Value> {
        let mut r = self.batch(&[(method.to_string(), params)])?;
        r.pop().expect("one answer per request")
    }

    /// Several requests in one JSON-RPC batch (one write, one round trip). The outer error is the
    /// connection failing; each inner result is that request's own answer or JSON-RPC error.
    pub fn batch(&self, reqs: &[(String, Value)]) -> Result<Vec<Result<Value>>> {
        self.batch_until(reqs, None)
    }

    /// [`batch`](Self::batch) that waits no longer than `until` (and never longer than the timeout).
    pub fn batch_until(&self, reqs: &[(String, Value)], until: Option<Instant>) -> Result<Vec<Result<Value>>> {
        if reqs.is_empty() {
            return Ok(Vec::new());
        }
        if !self.connected() {
            self.connect_until(until)?;
        }
        self.exchange_until(reqs, until)
    }

    fn exchange_until(&self, reqs: &[(String, Value)], until: Option<Instant>) -> Result<Vec<Result<Value>>> {
        if reqs.is_empty() {
            return Ok(Vec::new());
        }
        let (link, pending, given_up, fault) = {
            let g = lock(&self.live);
            let l = g.as_ref().ok_or_else(|| self.unreachable("not connected"))?;
            (l.link.clone(), l.pending.clone(), l.given_up.clone(), l.fault.clone())
        };
        // The rule (AGP-097): a server is hung up on only for a request that went a whole timeout
        // unanswered. A request the caller's deadline leaves no time for is not sent, and one the
        // deadline cuts short is given up without closing: the time was used up elsewhere (by
        // another server, as a rule), and hanging up would fail every other request on this
        // connection and cost a reconnect. Before, both ended as a timeout: the honest server was
        // dropped and flagged.
        if until.is_some_and(|u| Instant::now() >= u) {
            return err(Kind::Deadline, format!("{}: the call's deadline came before {} was sent", self.url, reqs[0].0));
        }
        let mut waits: Vec<(u64, Receiver<Value>)> = Vec::with_capacity(reqs.len());
        let mut msgs = Vec::with_capacity(reqs.len());
        {
            let mut p = lock(&pending);
            for (method, params) in reqs {
                let id = self.ids.fetch_add(1, Ordering::Relaxed);
                let (tx, rx) = sync_channel(1);
                p.insert(id, (tx, answer_cap(method, params)));
                waits.push((id, rx));
                msgs.push(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
            }
        }
        let mut line = if msgs.len() == 1 { msgs.pop().unwrap().to_string() } else { Value::Array(msgs).to_string() };
        line.push('\n');
        let own = Instant::now() + self.timeout;
        let deadline = until.map_or(own, |u| u.min(own));
        let sent = lock(&link).send(line.as_bytes(), deadline); // the guard must be gone before close()
        if let Err(e) = sent {
            self.close();
            return Err(self.unreachable(e));
        }
        let mut out = Vec::with_capacity(waits.len());
        let mut waits = waits.into_iter();
        while let Some((id, rx)) = waits.next() {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(msg) => out.push(answer(&msg)),
                Err(RecvTimeoutError::Timeout) if deadline < own => {
                    // Cut short by the caller's deadline, not by the timeout. The requests stay
                    // pending, so an answer that still comes is within what the connection allows
                    // and is dropped unread; they go when the connection does, or when
                    // MAX_GIVEN_UP newer ones are kept.
                    give_up(&pending, &given_up, std::iter::once(id).chain(waits.map(|(id, _)| id)));
                    return err(Kind::Deadline, format!("{}: the call's deadline came before the answer to {}", self.url, reqs[out.len()].0));
                }
                Err(RecvTimeoutError::Timeout) => {
                    lock(&pending).remove(&id);
                    self.close();
                    return Err(self.unreachable(format!("{} timed out", reqs[out.len()].0)));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    self.close();
                    let why = lock(&fault).clone();
                    return Err(self.unreachable(why.as_deref().unwrap_or("connection closed")));
                }
            }
        }
        Ok(out)
    }

    /// Subscribe (and remember it, so a reconnect subscribes again). Returns the first answer.
    pub fn subscribe(&self, method: &str, params: Value) -> Result<Value> {
        {
            let mut s = lock(&self.subs);
            if !s.iter().any(|(m, p)| m == method && p == &params) {
                s.push((method.to_string(), params.clone()));
            }
        }
        self.request(method, params)
    }

    /// Subscribe to those of `reqs` this connection is not subscribed to yet, in one batch.
    pub fn subscribe_many(&self, reqs: &[(String, Value)], until: Option<Instant>) -> Result<Vec<Result<Value>>> {
        let new: Vec<(String, Value)> = {
            let mut s = lock(&self.subs);
            let new: Vec<_> = reqs.iter().filter(|r| !s.contains(r)).cloned().collect();
            s.extend(new.iter().cloned());
            new
        };
        self.batch_until(&new, until)
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.close();
    }
}

/// JSON-RPC 2.0: the server has no such method.
const METHOD_NOT_FOUND: i64 = -32601;

fn answer(msg: &Value) -> Result<Value> {
    if let Some(e) = msg.get("error").filter(|e| !e.is_null()) {
        let mut m = e.get("message").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| e.to_string());
        // An error about the method says nothing about what was asked for. The backend reads "not
        // there" from the words of an error and skips any that names the method
        // (`backend::says_not_there`), so the code's meaning is put in words when the server's
        // own leave it out (AGP-097).
        if e.get("code").and_then(Value::as_i64) == Some(METHOD_NOT_FOUND) && !m.to_ascii_lowercase().contains("method") {
            m = format!("method not found: {m}");
        }
        return err(Kind::Server, m);
    }
    Ok(msg.get("result").cloned().unwrap_or(Value::Null))
}

fn dispatch(msg: Value, pending: &Pending, notify: &Option<Notify>, url: &str) {
    match msg {
        Value::Array(items) => {
            for m in items {
                dispatch(m, pending, notify, url);
            }
        }
        Value::Object(_) => {
            if let Some(id) = msg.get("id").and_then(Value::as_u64) {
                if let Some((tx, _)) = lock(pending).remove(&id) {
                    let _ = tx.try_send(msg);
                }
            } else if let (Some(method), Some(n)) = (msg.get("method").and_then(Value::as_str), notify) {
                let params = msg.get("params").cloned().unwrap_or(Value::Null);
                n(url, method, &params);
            }
        }
        _ => {}
    }
}

/// Why `line` (complete, or the start of one still arriving) is more than the requests waiting allow.
fn over_cap(line: &[u8], pending: &Pending) -> Option<String> {
    let allow = allowance(pending);
    if line.len() > allow.bytes {
        return Some(format!("a line over the limit: more than the {} bytes its requests allow", allow.bytes));
    }
    let values = values_in(line);
    (values > allow.values).then(|| format!("a line over the limit: {values} JSON values where its requests allow {}", allow.values))
}

/// Read until the server hangs up or is dropped. Returns why, when it was dropped for what it sent.
fn read_loop(mut sock: TcpStream, link: Arc<Mutex<Link>>, pending: Pending, notify: Option<Notify>, url: String) -> Option<String> {
    let mut raw = vec![0u8; 1 << 16];
    let mut plain = vec![0u8; 1 << 16];
    let mut buf: Vec<u8> = Vec::new();
    let mut fault = None;
    'outer: loop {
        let n = match sock.read(&mut raw) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        {
            let mut l = lock(&link);
            match &mut *l {
                Link::Plain(_) => buf.extend_from_slice(&raw[..n]),
                Link::Tls(s, c) => {
                    let mut rd = &raw[..n];
                    while !rd.is_empty() {
                        if c.read_tls(&mut rd).is_err() || c.process_new_packets().is_err() {
                            break 'outer;
                        }
                        loop {
                            match c.reader().read(&mut plain) {
                                Ok(0) => break 'outer, // close_notify
                                Ok(k) => buf.extend_from_slice(&plain[..k]),
                                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                                Err(_) => break 'outer,
                            }
                        }
                    }
                    while c.wants_write() {
                        if c.write_tls(s).is_err() {
                            break 'outer;
                        }
                    }
                }
            }
        }
        let mut start = 0;
        while let Some(i) = buf[start..].iter().position(|&b| b == b'\n') {
            let line = &buf[start..start + i];
            start += i + 1;
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            // before it is parsed: its size and shape against what was asked
            fault = over_cap(line, &pending);
            if fault.is_some() {
                break 'outer;
            }
            match serde_json::from_slice::<Value>(line) {
                Ok(v) => dispatch(v, &pending, &notify, &url),
                Err(_) => break 'outer, // not JSON-RPC: drop the server
            }
        }
        buf.drain(..start);
        // a line still arriving is held to the same limit, so it is never buffered whole
        fault = over_cap(&buf, &pending);
        if fault.is_some() {
            break;
        }
    }
    let _ = lock(&link).sock().shutdown(Shutdown::Both);
    fault
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AGP-097: JSON-RPC's "no such method" is told by its code whatever the server's words, so
    /// that the backend never reads it as "no such transaction".
    #[test]
    fn a_method_not_found_error_says_so_whatever_its_words() {
        let e = |code: i64, m: &str| answer(&json!({"id": 1, "error": {"code": code, "message": m}})).unwrap_err();
        for words in ["not found", "missing", "unknown request", ""] {
            let got = e(-32601, words);
            assert!(got.kind == Kind::Server && got.msg.to_ascii_lowercase().contains("method"), "{words:?} -> {:?}", got.msg);
        }
        assert_eq!(e(-32601, "Method not found").msg, "Method not found");
        // any other code: the server's own words, untouched
        assert_eq!(e(2, "No such mempool or blockchain transaction").msg, "No such mempool or blockchain transaction");
    }

    /// AGP-106 (the fourth audit's LIGHT 6): requests given up at a call's deadline keep a slot so
    /// that a late answer is within what the connection allows. A server that answers what it is
    /// given a whole timeout for, and never the requests it sees at the end of a call, kept one
    /// more per call without end, and each adds a history's worth of JSON values to what its next
    /// line may hold.
    #[test]
    fn requests_given_up_at_the_deadline_do_not_add_up_without_bound() {
        use std::io::{BufRead, BufReader};
        use std::net::TcpListener;
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            for line in BufReader::new(c.try_clone().unwrap()).lines() {
                let Ok(line) = line else { break };
                let req: Value = serde_json::from_str(&line).unwrap();
                let result = match req["method"].as_str() {
                    Some("server.version") => json!(["never", "1.4"]),
                    Some("server.ping") => Value::Null,
                    _ => continue, // get_history: never answered
                };
                let _ = c.write_all(format!("{}\n", json!({"id": req["id"], "result": result})).as_bytes());
            }
        });
        let c = Connection::new(&format!("tcp://{addr}"), Duration::from_secs(2), None, None).unwrap();
        c.connect().unwrap();
        let ask = [("blockchain.scripthash.get_history".to_string(), json!(["00".repeat(32)]))];
        for _ in 0..60 {
            let cut = c.batch_until(&ask, Some(Instant::now() + Duration::from_millis(5))).unwrap_err();
            assert_eq!(cut.kind, Kind::Deadline);
            assert_eq!(c.request("server.ping", json!([])).unwrap(), Value::Null, "the connection answers and stays");
        }
        let pending = lock(&c.live).as_ref().unwrap().pending.clone();
        let one = answer_cap("blockchain.scripthash.get_history", &json!(["00"]));
        let kept = lock(&pending).len();
        let allow = allowance(&pending);
        println!("AGP-106 measure: after 60 calls cut short on one connection: {kept} requests pending, a line may hold {} JSON values", allow.values);
        assert!(c.connected());
        assert!(kept <= MAX_GIVEN_UP, "{kept} pending requests nobody waits for");
        assert!(allow.values <= IDLE.values + MAX_GIVEN_UP * one.values);
    }

    #[test]
    fn answer_caps_fit_the_largest_legitimate_answer() {
        // 2016 v2 headers as hex, with the envelope and the count/max fields
        let headers = answer_cap("blockchain.block.headers", &json!([1, 2016]));
        let answer = json!({"jsonrpc": "2.0", "id": u64::MAX, "result": {"count": 2016, "max": 2016, "hex": "00".repeat(164 * 2016)}});
        assert!(answer.to_string().len() <= headers.bytes && values_in(answer.to_string().as_bytes()) <= headers.values);
        assert_eq!(answer_cap("blockchain.block.headers", &json!([1, 1_000_000])), headers, "the count is clamped");
        assert!(answer_cap("blockchain.block.headers", &json!([1, 1])).bytes < 8192);
        // a transaction of MAX_TX_BYTES
        let tx = json!({"jsonrpc": "2.0", "id": u64::MAX, "result": "00".repeat(MAX_TX_BYTES)}).to_string();
        assert!(tx.len() <= answer_cap("blockchain.transaction.get", &json!(["00"])).bytes);
        // MAX_HISTORY entries of a history (mempool entries carry a fee) and of an unspent list
        let entry = json!({"tx_hash": "ab".repeat(32), "height": 4_294_967_295u32, "fee": 2_100_000_000_000_000u64});
        let hist = json!({"jsonrpc": "2.0", "id": u64::MAX, "result": vec![entry; MAX_HISTORY]}).to_string();
        let cap = answer_cap("blockchain.scripthash.get_history", &json!(["00"]));
        assert!(hist.len() <= cap.bytes && values_in(hist.as_bytes()) <= cap.values, "{} bytes, {} values", hist.len(), values_in(hist.as_bytes()));
        let utxo = json!({"tx_hash": "ab".repeat(32), "tx_pos": 4_294_967_295u32, "height": 4_294_967_295u32, "value": 2_100_000_000_000_000u64});
        let unspent = json!({"jsonrpc": "2.0", "id": u64::MAX, "result": vec![utxo; MAX_HISTORY]}).to_string();
        assert!(unspent.len() <= cap.bytes && values_in(unspent.as_bytes()) <= cap.values);
        // a Merkle branch for a block of 65,535 transactions
        let proof = json!({"jsonrpc": "2.0", "id": u64::MAX, "result": {"block_height": 4_294_967_295u32, "pos": 65_535, "merkle": vec!["ab".repeat(32); 16]}}).to_string();
        let cap = answer_cap("blockchain.transaction.get_merkle", &json!(["00", 1]));
        assert!(proof.len() <= cap.bytes && values_in(proof.as_bytes()) <= cap.values);
        // every batch the backend sends fits one line
        assert!(4 * headers.bytes + IDLE.bytes <= MAX_LINE);
    }

    #[test]
    fn values_in_never_undercounts() {
        for doc in [json!(1), json!([]), json!([0, 0, 0]), json!([[], [], []]), json!({"a": 1, "b": [1, {"c": "x,[{"}]}), json!("a,b")] {
            fn count(v: &Value) -> usize {
                1 + match v {
                    Value::Array(a) => a.iter().map(count).sum(),
                    Value::Object(o) => o.values().map(count).sum(),
                    _ => 0,
                }
            }
            assert!(values_in(doc.to_string().as_bytes()) >= count(&doc), "{doc}");
        }
    }

    #[test]
    fn server_urls() {
        assert_eq!(parse_server("tcp://127.0.0.1:50001").unwrap(), ServerAddr { host: "127.0.0.1".into(), port: 50001, tls: false });
        assert_eq!(parse_server("ssl://electrum.example:50002").unwrap(), ServerAddr { host: "electrum.example".into(), port: 50002, tls: true });
        assert!(parse_server("host:1:s").unwrap().tls);
        assert!(!parse_server("host:1:t").unwrap().tls);
        assert_eq!(parse_server("tcp://[::1]:5").unwrap().host, "::1");
        for bad in ["http://h:1", "tcp://h", "tcp://:1", "h:1", "h:x:t", "tcp://h:0", "tcp://h:99999"] {
            assert!(parse_server(bad).is_err(), "{bad}");
        }
    }
}
