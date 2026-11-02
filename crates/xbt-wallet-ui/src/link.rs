//! The signer socket (B2's protocol: one newline-delimited JSON request per connection): a Unix
//! socket path, or `tcp://127.0.0.1:PORT`.
//!
//! Reads are kept a little ([`SignerLink::call`]): within one GET request a read is asked once
//! however many parts of the page want it (the menu's badge, the page, the node's state), and the
//! slow-changing reads in [`KEPT`] serve the next pages for `keep` too. Anything else asked of the
//! signer (a payment, an approval, a rule change, a stop) forgets them all, and so does every POST to
//! the app ([`crate::server`]): what a page shows after an action is asked afresh.
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct SignerLink {
    pub sock: PathBuf,
    pub timeout: Duration,
    /// How long a read in [`KEPT`] serves later requests (zero: within its own request only).
    pub keep: Duration,
    cache: Arc<Mutex<HashMap<String, Kept>>>,
}

#[derive(Debug, Clone)]
struct Kept {
    at: Instant,
    /// The request that asked it.
    request: u64,
    answer: Result<Value, String>,
}

/// Reads: what a GET may take from the cache. Asking anything else forgets the cache.
pub const READS: &[&str] = &["approvals", "balance", "channel_reports", "channels", "health", "history", "identity_get", "keystore_status",
                             "ln_status", "mining_tip", "node_status", "policy_get", "seller_blocks", "signatures", "ticket_status"];

/// The reads that change slowly (the node's state, balances and channels, the rules, the keys), kept
/// for [`SignerLink::keep`] across requests. The others (approvals waiting, the live connections, the
/// records) are kept within one request only.
pub const KEPT: &[&str] = &["balance", "channel_reports", "channels", "health", "keystore_status", "ln_status", "mining_tip", "node_status",
                            "policy_get", "seller_blocks"];

trait Conn: Read + Write {}
impl<T: Read + Write> Conn for T {}

impl SignerLink {
    pub fn new(sock: PathBuf, timeout: Duration) -> Self {
        Self { sock, timeout, keep: Duration::ZERO, cache: Default::default() }
    }

    /// Keep the slow-changing reads ([`KEPT`]) for `keep` across requests.
    pub fn keeping(mut self, keep: Duration) -> Self {
        self.keep = keep;
        self
    }

    /// Forget every kept answer.
    pub fn forget(&self) {
        self.cache.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }

    fn connect(&self) -> std::io::Result<Box<dyn Conn>> {
        let s = self.sock.to_string_lossy();
        if let Some(a) = s.strip_prefix("tcp://") {
            let c = std::net::TcpStream::connect(a)?;
            c.set_read_timeout(Some(self.timeout))?;
            c.set_write_timeout(Some(self.timeout))?;
            return Ok(Box::new(c));
        }
        #[cfg(unix)]
        {
            let c = std::os::unix::net::UnixStream::connect(&self.sock)?;
            c.set_read_timeout(Some(self.timeout))?;
            c.set_write_timeout(Some(self.timeout))?;
            Ok(Box::new(c))
        }
        #[cfg(not(unix))]
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "use tcp://127.0.0.1:PORT for the signer socket"))
    }

    /// The signer's result, or its error message (or why it could not be reached). A read in a GET
    /// request is answered from the cache when it can be (see the module's notes).
    pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let read = READS.contains(&method);
        if !read {
            self.forget();
        }
        // only a GET reads the cache: a POST changes things, and asks what it reads afresh
        let request = crate::perf::current().filter(|(_, get)| *get && read).map(|(id, _)| id);
        let key = request.map(|_| format!("{method} {params}"));
        if let (Some(id), Some(key)) = (request, &key) {
            let kept = KEPT.contains(&method);
            let hit = self.cache.lock().unwrap_or_else(|p| p.into_inner()).get(key)
                .filter(|k| k.request == id || kept && k.answer.is_ok() && k.at.elapsed() < self.keep).map(|k| k.answer.clone());
            if let Some(a) = hit {
                crate::perf::signer(Duration::ZERO, true);
                return a;
            }
        }
        let t = Instant::now();
        let answer = self.ask(method, params);
        crate::perf::signer(t.elapsed(), false);
        if let (Some(id), Some(key)) = (request, key) {
            let mut c = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            // what neither this request nor a later one can use goes
            let keep = self.keep;
            c.retain(|_, k| k.request == id || k.answer.is_ok() && k.at.elapsed() < keep);
            c.insert(key, Kept { at: t, request: id, answer: answer.clone() });
        }
        answer
    }

    fn ask(&self, method: &str, params: Value) -> Result<Value, String> {
        let io = |e: std::io::Error| format!("the signer at {} is unreachable: {e}", self.sock.display());
        let mut c = self.connect().map_err(io)?;
        let line = serde_json::to_string(&json!({"id": 1, "method": method, "params": params})).map_err(|e| e.to_string())?;
        c.write_all(format!("{line}\n").as_bytes()).map_err(io)?;
        let mut out = String::new();
        BufReader::new(c).read_line(&mut out).map_err(io)?;
        let resp: Value = serde_json::from_str(out.trim()).map_err(|e| format!("the signer's answer is not JSON: {e}"))?;
        if let Some(e) = resp.get("error").filter(|e| !e.is_null()) {
            return Err(e.get("message").and_then(Value::as_str).unwrap_or("error").to_string());
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }
}
