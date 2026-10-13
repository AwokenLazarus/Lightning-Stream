//! The resource-server side of x402 for the schemes this workspace sells through a
//! [`ProviderScheme`](crate::scheme::ProviderScheme) (pay with work, `xbt-work`): the 402 that
//! lists what each scheme asks, the schemes' own control endpoints, and a paid call (the scheme
//! checks and debits, the handler answers, the scheme settles).
//!
//! [`Provider::serve`] is transport-independent: give it the method, path, headers and body of a
//! request and send back what it returns. The `http-server` feature serves it on std::net.
//!
//! Until 2026-10 this module was the provider of the on-chain one-way channel (`batch-settlement`),
//! which offered a scheme beside its own. The channel was removed; what is here is the part every
//! scheme used. The stream-ticket seller is its own server (`xbt-gateway`).
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use serde_json::{json, Value};
use xbt_primitives::secp256k1::SecretKey;

use crate::error::{ChannelError, Result};
use crate::json::dumps;
use crate::scheme::ProviderScheme;
use crate::wire::{b64json, unb64json, MAX_BODY};

/// The header the HTTP server sets to the TCP peer's IP address. A client-sent header of this name
/// never reaches the service.
pub const PEER_HEADER: &str = "X-Xbt402-Peer";

/// A response for the transport to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(status: u16, headers: Vec<(String, String)>, body: impl Into<Vec<u8>>) -> Self {
        Self { status, headers, body: body.into() }
    }

    fn text(status: u16, s: &str) -> Self {
        Self::new(status, vec![], s.as_bytes().to_vec())
    }

    /// The first header named `name` (any case).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// `handler(method, path, body)`: the paid API itself.
pub type Handler = Box<dyn Fn(&str, &str, &[u8]) -> HttpResponse + Send + Sync>;
/// `price(method, path)`: the per-call maximum in sats, which each scheme turns into its own amount.
pub type PriceFn = Box<dyn Fn(&str, &str) -> u64 + Send + Sync>;

/// Provider settings.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub max_body: usize,
    /// Request-body bound of one path (the path without its query), in place of `max_body`.
    pub route_max_body: HashMap<String, usize>,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self { max_body: MAX_BODY, route_max_body: HashMap::new() }
    }
}

/// A resource server that sells its handler's answers through the schemes it was given.
pub struct Provider {
    pub cfg: ProviderConfig,
    price: PriceFn,
    handler: Handler,
    schemes: Vec<Arc<dyn ProviderScheme>>,
}

fn path_key(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
}

/// A service's signing secret kept in `path` (review C4): read it, or create it (64 hex chars,
/// mode 0600 on Unix, never overwritten). What the service signed with it is checked against its
/// public key, so a service that starts with a new one is another seller to every buyer. On Unix
/// a file readable by group or others is refused.
pub fn load_or_create_secret(path: &Path) -> Result<SecretKey> {
    let bad = |m: String| ChannelError::new("key_file", format!("{}: {m}", path.display()));
    if let Some(d) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(d).map_err(|e| bad(e.to_string()))?;
    }
    if !path.exists() {
        // written whole under a private name, then linked into place: never a torn key, never an
        // overwrite of a key another starter linked first
        let mut name = path.as_os_str().to_owned();
        name.push(format!(".new.{}", std::process::id()));
        let tmp = std::path::PathBuf::from(name);
        let sk = SecretKey::from_slice(&random32()).map_err(|e| bad(e.to_string()))?;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let written = o.open(&tmp).and_then(|mut f| {
            use std::io::Write as _;
            writeln!(f, "{}", hex::encode(sk.secret_bytes()))?;
            f.sync_all()
        });
        let linked = written.and_then(|_| std::fs::hard_link(&tmp, path));
        let _ = std::fs::remove_file(&tmp);
        match linked {
            Ok(()) => {
                let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
                std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(|e| bad(e.to_string()))?;
                return Ok(sk);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(bad(e.to_string())),
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path).map_err(|e| bad(e.to_string()))?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(bad(format!("mode {:o} lets others read the key: chmod 600", mode & 0o777)));
        }
    }
    let text = std::fs::read_to_string(path).map_err(|e| bad(e.to_string()))?;
    let raw = hex::decode(text.trim()).map_err(|_| bad("not a hex secret".into()))?;
    SecretKey::from_slice(&raw).map_err(|_| bad("not a secp256k1 secret".into()))
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("OS randomness");
    b
}

impl Provider {
    pub fn new(cfg: ProviderConfig, price: PriceFn, handler: Handler) -> Self {
        Self { cfg, price, handler, schemes: vec![] }
    }

    /// Sell through `s` too: its offer is listed in an unpaid 402, in the order the schemes were
    /// given, and a call paid with it is served.
    pub fn with_scheme(mut self, s: Arc<dyn ProviderScheme>) -> Self {
        self.schemes.push(s);
        self
    }

    /// Request-body bound for this path: `max_body` wins, then a route option, then the default.
    pub fn body_limit(&self, path: &str, max_body: Option<usize>) -> usize {
        if let Some(n) = max_body {
            return n.max(1);
        }
        self.cfg.route_max_body.get(path_key(path)).copied().unwrap_or(self.cfg.max_body)
    }

    /// The 402 of a call that came with no payment this provider serves: what each scheme asks.
    fn payment_required(&self, method: &str, path: &str, url: &str, price: u64, error: &str) -> HttpResponse {
        let accepts: Vec<Value> = self.schemes.iter().filter_map(|s| s.requirements(method, path, price)).collect();
        required_response(&json!({"x402Version": 2, "error": error, "resource": {"url": url}, "accepts": accepts}))
    }

    /// Serve one HTTP request. `url` is the absolute URL for the 402's `resource.url` (defaults
    /// to the path); `max_body` overrides the configured body bound.
    pub fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str,
                 max_body: Option<usize>) -> HttpResponse {
        if body.len() > self.body_limit(path, max_body) {
            return HttpResponse::text(400, "bad request framing or body over MAX_BODY");
        }
        if crate::wire::no_fragment(path).is_err() {
            // before anything is authenticated or routed (AGP-081, review T2)
            return HttpResponse::text(400, "request target with a # fragment");
        }
        for s in &self.schemes {
            if let Some(r) = s.control(method, path, headers, body) {
                return r;
            }
        }
        let url = if url.is_empty() { path } else { url };
        let price = (self.price)(method, path);
        let Some(hdr) = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-SIGNATURE")).map(|(_, v)| v) else {
            return self.payment_required(method, path, url, price, "payment_required");
        };
        let Ok(pp) = unb64json(hdr) else { return self.payment_required(method, path, url, price, "bad_payload") };
        if !pp.get("accepted").is_some_and(Value::is_object) || !pp.get("payload").is_some_and(Value::is_object) {
            return self.payment_required(method, path, url, price, "bad_payload");
        }
        let scheme = pp.pointer("/accepted/scheme").and_then(Value::as_str);
        let Some(s) = scheme.and_then(|sc| self.schemes.iter().find(|s| s.scheme() == sc)) else {
            return self.payment_required(method, path, url, price, "unsupported_scheme_or_network");
        };
        // the scheme verifies and debits, the handler runs, the scheme settles
        let charge = match s.authorize(&pp, method, path, body, price, url) {
            Ok(c) => c,
            Err(doc) => return required_response(&doc),
        };
        let mut resp = (self.handler)(method, path, body);
        if resp.headers.iter().any(|(k, v)| k.contains(['\r', '\n', '\0']) || v.contains(['\r', '\n', '\0'])) {
            resp = HttpResponse::text(500, "handler returned a header with CR/LF");
        }
        let sr = charge.settle(resp.status);
        resp.headers.push(("PAYMENT-RESPONSE".into(), b64json(&sr)));
        resp
    }
}

/// A PaymentRequired document as a 402.
fn required_response(body: &Value) -> HttpResponse {
    HttpResponse::new(402, vec![("PAYMENT-REQUIRED".into(), b64json(body)), ("Content-Type".into(), "application/json".into())],
                      dumps(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_keys() {
        assert_eq!(path_key("/a?b=1"), "/a");
        assert_eq!(path_key("/a"), "/a");
    }
}
