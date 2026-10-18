//! The signer socket: newline-delimited JSON, `{"id", "method", "params"}` →
//! `{"id", "result"}` or `{"id", "error": {"message"}}` (B2's protocol). Mode 0600 on Unix.
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};

use crate::anchor::serve_conn;
use crate::ipc::{Listener, Stream};
use crate::signer::Signer;
use crate::{err, Result};

/// A running signer socket; stops accepting when dropped.
pub struct Running {
    pub sock_path: std::path::PathBuf,
    stop: Arc<AtomicBool>,
    /// The requests being answered and the watcher's tick: a stop lets them finish ([`Running::finish`]).
    drain: Arc<xbt_svc::shutdown::Drain>,
}

impl Running {
    /// Stop (SIGTERM): no new connection, no new request on an open one (it is told the signer is
    /// stopping), no new watcher tick; what is running gets `bound` to finish, and the socket is
    /// removed. Nothing is flushed here because nothing waits to be: every ledger row, anchor and
    /// book entry is written and fsynced before the step that depends on it (the book before a
    /// secret leaves), so a request cut short at the bound leaves what a kill would. True: none
    /// was left running.
    pub fn finish(&self, bound: std::time::Duration) -> bool {
        self.stop.store(true, Ordering::SeqCst);
        let _ = Stream::connect(&self.sock_path);
        let done = self.drain.finish(bound);
        let _ = std::fs::remove_file(&self.sock_path);
        done
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = Stream::connect(&self.sock_path);
    }
}

fn handle(signer: &Signer, req: &Value) -> Result<Value> {
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    signer.handle(method, req.get("params").unwrap_or(&json!({})))
}

/// The socket's mode: `B2_SIGNER_SOCK_MODE` (octal, default 600). 660 lets the signer's group (the
/// MCP's container, AGP-038) connect; never wider than 660.
pub fn sock_mode() -> Result<u32> {
    let raw = std::env::var("B2_SIGNER_SOCK_MODE").unwrap_or_default();
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(0o600);
    }
    match u32::from_str_radix(raw, 8) {
        Ok(m) if m & !0o660 == 0 => Ok(m),
        _ => Err(err("config", format!("B2_SIGNER_SOCK_MODE={raw}: an octal mode within 660"))),
    }
}

/// Bind `sock` and serve it on background threads, with the watcher when `watch` is set.
pub fn spawn(signer: Arc<Signer>, sock: &Path, watch: bool) -> Result<Running> {
    let listener = Listener::bind(sock, sock_mode()?).map_err(|e| err("io", format!("{}: {e}", sock.display())))?;
    let stop = Arc::new(AtomicBool::new(false));
    let drain = Arc::new(xbt_svc::shutdown::Drain::default());
    if watch && signer.watch_interval > 0.0 {
        let (s, st, d) = (signer.clone(), stop.clone(), drain.clone());
        std::thread::Builder::new().name("expiry-watcher".into()).spawn(move || s.watch_loop_in(st, &d)).map_err(|e| err("io", e.to_string()))?;
    }
    let (st, d) = (stop.clone(), drain.clone());
    std::thread::Builder::new().name("signer-accept".into()).spawn(move || loop {
        let conn = listener.accept();
        if st.load(Ordering::SeqCst) {
            break;
        }
        if let Ok(conn) = conn {
            let (s, d) = (signer.clone(), d.clone());
            std::thread::spawn(move || serve_conn(conn, |req| match d.enter() {
                Some(_busy) => handle(&s, req),
                None => Err(err("stopping", "the signer is stopping")),
            }));
        }
    }).map_err(|e| err("io", e.to_string()))?;
    Ok(Running { sock_path: sock.into(), stop, drain })
}

/// Serve until a stop signal (the binary), then stop as [`Running::finish`] says. `signals` was
/// made before the process started any thread ([`xbt_svc::shutdown::listen`]).
pub fn serve(signer: Arc<Signer>, signals: xbt_svc::shutdown::Signals) -> Result<()> {
    let sock = signer.sock_path.clone();
    let r = spawn(signer, &sock, true)?;
    println!("signer listening on {}", sock.display());
    let sig = signals.wait();
    xbt_svc::shutdown::say_stopping("xbt-signer", sig);
    let drained = r.finish(xbt_svc::shutdown::DRAIN);
    xbt_svc::shutdown::say_stopped("xbt-signer", drained);
    Ok(())
}
