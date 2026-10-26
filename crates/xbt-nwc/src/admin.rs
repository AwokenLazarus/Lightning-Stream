//! The admin socket: how the wallet UI makes, lists and revokes connections. The signer's protocol
//! (one JSON request per line, `{"id", "method", "params"}` → `{"id", "result"}` or
//! `{"id", "error": {"message"}}`) on a Unix socket, mode 0600 by default (`NWC_ADMIN_SOCK_MODE`, at
//! most 0660, for a UI that runs as another user in the same group).
//!
//! Whoever can reach this socket can make a connection, and so spend what the owner's policy lets
//! the signer spend: the same reach as the signer's socket itself, which a process that can
//! connect here can usually connect to as well. Nothing here widens what the policy allows.
//!
//! | method | params | result |
//! |---|---|---|
//! | `nwc_status` | | the relays (connected, last error, notices), counts, defaults |
//! | `nwc_list` | | every connection without its secret: budget, spent in 24 h and in all, expiry, methods, relays |
//! | `nwc_create` | `name`, `budget_sats_per_day`, `expires_at` or `expires_in_s` (0: never), `methods`, `relays` | `{connection, uri}`: the URI is given here only |
//! | `nwc_revoke` | `id` | `{revoked: true}` |
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};
use xbt_signer::anchor::serve_conn;
use xbt_signer::err;
use xbt_signer::ipc::{Listener, Stream};

use crate::service::Service;

/// `NWC_ADMIN_SOCK_MODE` (octal, default 600; never wider than 660).
pub fn sock_mode() -> Result<u32, String> {
    let raw = std::env::var("NWC_ADMIN_SOCK_MODE").unwrap_or_default();
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(0o600);
    }
    match u32::from_str_radix(raw, 8) {
        Ok(m) if m & !0o660 == 0 => Ok(m),
        _ => Err(format!("NWC_ADMIN_SOCK_MODE={raw}: an octal mode within 660")),
    }
}

pub fn handle(svc: &Service, req: &Value) -> xbt_signer::Result<Value> {
    let p = req.get("params").cloned().unwrap_or(json!({}));
    match req.get("method").and_then(Value::as_str).unwrap_or("") {
        "nwc_status" => Ok(svc.status()),
        "nwc_list" => Ok(svc.list()),
        "nwc_create" => svc.create(&p).map_err(|e| err("nwc", e)),
        "nwc_revoke" => svc.revoke(p.get("id").and_then(Value::as_str).unwrap_or("")).map_err(|e| err("nwc", e)),
        other => Err(err("unknown_method", format!("unknown method {other}"))),
    }
}

/// The running admin socket; stops accepting when dropped.
pub struct Running {
    pub path: std::path::PathBuf,
    stop: Arc<AtomicBool>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = Stream::connect(&self.path);
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn spawn(svc: Arc<Service>, path: &Path, mode: u32) -> Result<Running, String> {
    let l = Listener::bind(path, mode).map_err(|e| format!("{}: {e}", path.display()))?;
    let stop = Arc::new(AtomicBool::new(false));
    let st = stop.clone();
    std::thread::Builder::new().name("nwc-admin".into()).spawn(move || loop {
        let conn = l.accept();
        if st.load(Ordering::SeqCst) {
            break;
        }
        if let Ok(c) = conn {
            let s = svc.clone();
            std::thread::spawn(move || serve_conn(c, |req| handle(&s, req)));
        }
    }).map_err(|e| e.to_string())?;
    Ok(Running { path: path.into(), stop })
}
