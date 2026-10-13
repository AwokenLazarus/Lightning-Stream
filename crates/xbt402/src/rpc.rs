//! bitcoind JSON-RPC (feature `rpc`) over blocking HTTP with basic auth (user/password or the
//! node's `.cookie`): what a tool that reads the chain from its own node needs.
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::{json, Value};

use crate::error::{fail, ChannelError, Result};

/// A JSON-RPC connection to one node (optionally one of its wallets).
#[derive(Clone)]
pub struct Rpc {
    url: String,
    auth: String,
    agent: ureq::Agent,
}

impl Rpc {
    pub fn new(url: &str, user: &str, password: &str) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            auth: format!("Basic {}", B64.encode(format!("{user}:{password}"))),
            agent: ureq::AgentBuilder::new().timeout(Duration::from_secs(60)).build(),
        }
    }

    /// Credentials from a node's cookie file (`<datadir>/regtest/.cookie`).
    pub fn from_cookie(url: &str, cookie_path: &std::path::Path) -> Result<Self> {
        let c = std::fs::read_to_string(cookie_path).map_err(|e| ChannelError::new("rpc_error", format!("cookie: {e}")))?;
        let (u, p) = c.trim().split_once(':').ok_or_else(|| ChannelError::new("rpc_error", "bad cookie"))?;
        Ok(Self::new(url, u, p))
    }

    /// The same node, addressing wallet `name`.
    pub fn wallet(&self, name: &str) -> Self {
        let base = self.url.split("/wallet/").next().unwrap_or(&self.url);
        Self { url: format!("{base}/wallet/{name}"), auth: self.auth.clone(), agent: self.agent.clone() }
    }

    /// Call `method`; an RPC error becomes `rpc_error` with the node's message.
    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc": "1.0", "id": "xbt402", "method": method, "params": params});
        let resp = match self.agent.post(&self.url).set("Authorization", &self.auth).set("Content-Type", "application/json")
            .send_string(&body.to_string())
        {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return fail("rpc_error", e.to_string()),
        };
        let text = resp.into_string().map_err(|e| ChannelError::new("rpc_error", e.to_string()))?;
        let v: Value = crate::json::parse(&text).map_err(|e| ChannelError::new("rpc_error", e.to_string()))?;
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            return fail("rpc_error", err.get("message").and_then(Value::as_str).unwrap_or("error").to_string());
        }
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    }
}
