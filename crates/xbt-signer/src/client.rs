//! The signer socket's client: one request per connection, one line each way.
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

use crate::ipc::Stream;
use crate::pyjson::dumps;
use crate::{err, Result};

/// One request per connection, like B2's `SignerClient`.
#[derive(Debug, Clone)]
pub struct SignerClient {
    pub sock_path: PathBuf,
    pub timeout: Duration,
}

impl SignerClient {
    pub fn new(sock: &Path) -> Self {
        let t = std::env::var("B2_SIGNER_TIMEOUT").ok().and_then(|v| v.parse::<f64>().ok()).unwrap_or(60.0);
        Self { sock_path: sock.into(), timeout: Duration::from_secs_f64(t) }
    }

    /// The raw result, or `signer_error` with the signer's message.
    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let io = |e: std::io::Error| err("signer_unreachable", format!("{}: {e}", self.sock_path.display()));
        let mut s = Stream::connect(&self.sock_path).map_err(io)?;
        s.set_timeouts(Some(self.timeout));
        s.write_all(format!("{}\n", dumps(&json!({"id": 1, "method": method, "params": params}))).as_bytes()).map_err(io)?;
        let mut line = String::new();
        BufReader::new(s).read_line(&mut line).map_err(io)?;
        let resp: Value = serde_json::from_str(line.trim()).map_err(|e| err("signer_error", e.to_string()))?;
        if let Some(e) = resp.get("error").filter(|e| !e.is_null()) {
            return Err(err("signer_error", e.get("message").and_then(Value::as_str).unwrap_or("error").to_string()));
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }
}
