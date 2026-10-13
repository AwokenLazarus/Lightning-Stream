//! The paying side of x402 for the schemes this workspace pays through a
//! [`SchemePayer`](crate::scheme::SchemePayer) (pay with work, `xbt-work`), over any [`Transport`].
//!
//! A [`Client`] sends the request with the payment its payer has ready for that seller; on a 402
//! it hands the offer of a scheme it pays to that scheme's payer, sends the request again with
//! what the payer answers, and has the payer check the receipt. An answer below 400 to a request
//! that carried a payment is taken only with its `PAYMENT-RESPONSE`.
//!
//! Until 2026-10 this module was the payer SDK of the on-chain one-way channel
//! (`batch-settlement`), which paid with another scheme where a 402 offered it. The channel was
//! removed; what is here is the part every scheme used. The wallet's ticket payer is its own code
//! (`xbt-signer`).
use std::sync::Arc;

use serde_json::Value;

use crate::error::{fail, ChannelError, Result};
use crate::provider::HttpResponse;
use crate::scheme::SchemePayer;
use crate::wire::unb64json;

/// How the client talks HTTP. Header names in the response may be any case.
pub trait Transport: Send + Sync {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse>;

    /// [`request`](Self::request), given up with an error when no whole answer came `within` that
    /// long, for a caller whose wait has its own bound (AGP-105). The default has no bound but the transport's own, so a caller
    /// that needs the bound also measures the time; `http::UreqTransport` keeps it.
    fn request_within(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)], _within: std::time::Duration) -> Result<HttpResponse> {
        self.request(method, url, body, headers)
    }
}

/// Client settings.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// CAIP-2 network id (`bip122:...`): an offer on another network is not taken.
    pub network: String,
}

impl ClientConfig {
    pub fn new(network: &str) -> Self {
        Self { network: network.into() }
    }
}

/// What an embedder adds to one paid call (AGP-059): its own request headers.
///
/// ```
/// # use xbt402::client::CallOpts;
/// let headers = [("X-CMP-Payer".to_string(), "…".to_string())];
/// let opts = CallOpts::new().headers(&headers);
/// # let _ = opts;
/// ```
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct CallOpts<'a> {
    /// Sent with every request of the call (the first try and the paid retry after a 402). A
    /// `PAYMENT-SIGNATURE` header, an empty name or a CR/LF/NUL is refused (`bad_header`).
    pub headers: &'a [(String, String)],
}

impl<'a> CallOpts<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn headers(mut self, headers: &'a [(String, String)]) -> Self {
        self.headers = headers;
        self
    }

    fn checked_headers(&self) -> Result<&'a [(String, String)]> {
        for (k, v) in self.headers {
            if k.is_empty() || k.eq_ignore_ascii_case("PAYMENT-SIGNATURE") || k.contains(['\r', '\n', '\0']) || v.contains(['\r', '\n', '\0']) {
                return fail("bad_header", format!("extra header {k:?} is not allowed"));
            }
        }
        Ok(self.headers)
    }
}

/// The payer.
pub struct Client {
    pub cfg: ClientConfig,
    transport: Box<dyn Transport>,
    /// The schemes this client pays with, in its order of choice.
    payers: Vec<Arc<dyn SchemePayer>>,
}

/// `("https://host:port", "/path?query")` of a URL. The origin of an absolute URL is the one the
/// request binding reads ([`canonical_origin`](crate::wire::canonical_origin): lowercase, no
/// userinfo, no default port), so every spelling of one seller is one key in a payer's book
/// (AGP-096). Anything else is split at its third `/`, as the reference splits it.
pub fn split_url(url: &str) -> (String, String) {
    let origin = crate::wire::canonical_origin(url);
    if !origin.is_empty() {
        return (origin, crate::wire::request_url(url).target);
    }
    let parts: Vec<&str> = url.split('/').collect();
    let origin = parts[..parts.len().min(3)].join("/");
    let path = format!("/{}", if parts.len() > 3 { parts[3..].join("/") } else { String::new() });
    (origin, path)
}

/// The PAYMENT-RESPONSE of the answer to a request that carried a payment (AGP-081, review T4c). A
/// success without one is refused: with the receipt stripped on the way, any body passed as the
/// paid answer. An answer of 400 or above may have none (the provider's own failures carry no
/// receipt): it goes back as it is and nothing is adopted from it.
fn paid_response(r: &HttpResponse) -> Result<Option<Value>> {
    match r.header("PAYMENT-RESPONSE") {
        Some(h) => unb64json(h).map(Some),
        None if r.status < 400 => fail("bad_receipt", format!("paid call returned no receipt (HTTP {})", r.status)),
        None => Ok(None),
    }
}

impl Client {
    pub fn new(cfg: ClientConfig, transport: Box<dyn Transport>) -> Self {
        Self { cfg, transport, payers: vec![] }
    }

    /// Pay with this scheme whenever a 402 offers it; it checks the PAYMENT-RESPONSE of the calls
    /// it paid. Of two schemes a 402 offers, the one given first pays.
    pub fn with_payer(mut self, p: Arc<dyn SchemePayer>) -> Self {
        self.payers.push(p);
        self
    }

    /// One paid HTTP request.
    pub fn request(&mut self, method: &str, url: &str, body: &[u8]) -> Result<HttpResponse> {
        self.request_with(method, url, body, &CallOpts::new())
    }

    /// [`request`](Self::request) with the embedder's own headers (AGP-059).
    pub fn request_with(&mut self, method: &str, url: &str, body: &[u8], opts: &CallOpts<'_>) -> Result<HttpResponse> {
        // AGP-105: before anything is signed or sent, and whatever the transport
        let url = &crate::wire::sendable_url(url)?;
        let (origin, path) = split_url(url);
        let extra = opts.checked_headers()?;
        let with_extra = |mut h: Vec<(String, String)>| {
            h.extend_from_slice(extra);
            h
        };
        let mut hdrs = vec![];
        let mut used: Option<Arc<dyn SchemePayer>> = None;
        for p in &self.payers {
            if let Some(h) = p.upfront(&origin, method, &path, body)? {
                hdrs = h;
                used = Some(p.clone());
                break;
            }
        }
        // a payment went with the request: its answer is taken only with its receipt
        let paid = !hdrs.is_empty();
        let r = self.transport.request(method, url, body, &with_extra(hdrs))?;
        if r.status == 402 {
            let pr = unb64json(r.header("PAYMENT-REQUIRED").ok_or_else(|| ChannelError::new("bad_offer", "402 without PAYMENT-REQUIRED"))?)?;
            let offered = |sc: &str| pr.get("accepts").and_then(Value::as_array).into_iter().flatten()
                .find(|a| a.get("scheme").and_then(Value::as_str) == Some(sc) && a.get("network").and_then(Value::as_str) == Some(&self.cfg.network))
                .cloned();
            let Some((p, acc)) = self.payers.iter().find_map(|p| offered(p.scheme()).map(|a| (p.clone(), a))) else {
                return fail("no_scheme", format!("the 402 offers no scheme this client pays on {}", self.cfg.network));
            };
            let h = p.answer(self.transport.as_ref(), &origin, &acc, &pr, method, &path, body)?;
            let r = self.transport.request(method, url, body, &with_extra(h))?;
            if let Some(resp) = paid_response(&r)? {
                p.check(&origin, &resp, method, &path, body)?;
            }
            return Ok(r);
        }
        let resp = if paid { paid_response(&r)? } else { r.header("PAYMENT-RESPONSE").map(unb64json).transpose()? };
        if let (Some(resp), Some(p)) = (resp, &used) {
            p.check(&origin, &resp, method, &path, body)?;
        }
        Ok(r)
    }
}
