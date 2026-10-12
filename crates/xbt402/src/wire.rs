//! The x402 v2 `batch-settlement` wire (XBT channel binding; `xbt-channel` accepted as an alias): PAYMENT-REQUIRED / PAYMENT-SIGNATURE / PAYMENT-RESPONSE,
//! request authentication, receipts, and the `/x402/verify|settle|supported` facilitator bodies.
//!
//! ```text
//! 402 + PAYMENT-REQUIRED: base64(PaymentRequired)      (the same JSON in the body)
//! PaymentRequired = {x402Version: 2, error?, resource: {url}, accepts: [PaymentRequirements]}
//! pay:    PAYMENT-SIGNATURE: base64({x402Version: 2, accepted, payload: {chan, seq, cum, sig?, auth}})
//!         auth = HMAC-SHA256(K, "xbt402/auth|chan|seq|cum|sig|" + request_digest_v2)
//!         request_digest_v2 = tagged_hash("xbt402/req/v2", length-prefixed method, scheme, host, port, target, body)
//! result: PAYMENT-RESPONSE: base64(SettlementResponse {success, transaction: "", network, payer,
//!         amount: "", extra: {chargedAmount, receipt}})
//! ```
//!
//! Values that are signed or MACed are formatted exactly as the Python reference does, and every
//! header is built with [`crate::json`], so they are byte-identical to it. The typed structs
//! below are for applications; the protocol code works on `serde_json::Value` so a message's
//! unknown fields and key order survive a round trip.
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use xbt_primitives::hash::tagged_hash;

use crate::error::{fail, ChannelError, Result};
use crate::json::{dumps_compact, py_str};

/// x402 scheme id: the XBT network binding of upstream `batch-settlement`.
pub const SCHEME: &str = "batch-settlement";
/// One-release input alias. Servers and clients accept this on the wire; they emit [`SCHEME`].
pub const SCHEME_ALIAS: &str = "xbt-channel";
/// Reserved x402 extra key: this binding's transfer method.
pub const ASSET_TRANSFER_METHOD: &str = "channel";
pub const X402_VERSION: u64 = 2;

/// True for the canonical scheme or the one-release `xbt-channel` alias.
pub fn scheme_accepted(s: Option<&str>) -> bool {
    matches!(s, Some(SCHEME) | Some(SCHEME_ALIAS))
}
/// Default request-body bound.
pub const MAX_BODY: usize = 1 << 20;
pub const FACILITATOR_VERIFY: &str = "/x402/verify";
pub const FACILITATOR_SETTLE: &str = "/x402/settle";
pub const FACILITATOR_SUPPORTED: &str = "/x402/supported";
pub const OPEN_PATH: &str = "/x402/xbt-channel/open";
pub const CLOSE_PATH: &str = "/x402/xbt-channel/close";
pub const ROLLOVER_PATH: &str = "/x402/xbt-channel/rollover";
pub const TERMS_PATH: &str = "/x402/xbt-channel/terms";
pub use xbt_primitives::network::{network_id, XBT_MAINNET};

/// `base64(json.dumps(obj, separators=(",", ":")))`.
pub fn b64json(v: &Value) -> String {
    B64.encode(dumps_compact(v))
}

/// Inverse of [`b64json`].
pub fn unb64json(s: &str) -> Result<Value> {
    let raw = B64.decode(s.trim()).map_err(|_| ChannelError::new("bad_payload", "not base64"))?;
    crate::json::parse_slice(&raw).map_err(|_| ChannelError::new("bad_payload", "not JSON"))
}

/// The v1 binding `sha256(method | target | body)` hex. Its fields run together and it binds no
/// origin (review T2); xbt402 and, since AGP-074, the xbt-work scheme use [`request_digest_v2`]. Kept
/// for the comparison in `examples/binding_bench.rs` and the collision test.
pub fn request_digest_v1(method: &str, target: &str, body: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(method.as_bytes());
    h.update(b"|");
    h.update(target.as_bytes());
    h.update(b"|");
    h.update(body);
    hex::encode(h.finalize())
}

/// Where a request went, as [`request_digest_v2`] binds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestUrl {
    /// Lowercase; empty for a bare target.
    pub scheme: String,
    /// Lowercase, an IPv6 literal in brackets, no port; empty for a bare target.
    pub host: String,
    /// Decimal with no leading zeros, or the scheme's default (80 for http, 443 for https).
    pub port: String,
    /// Path and query exactly as sent; `/` when the URL has no path.
    pub target: String,
}

/// `(scheme, rest)` of an absolute URL `scheme://rest`. The scheme is the whole string before the
/// first `://` and is spelled as RFC 3986 spells one (a letter, then letters, digits, `+`, `-`,
/// `.`). Anything else is a bare target, whatever its query holds (AGP-090, review T2): the split
/// used to be at the first `://` anywhere, so `/a?next=http://h/x` was read as scheme `/a?next=http`
/// and host `h`, both lowercased, and shared a digest with `/A?next=HTTP://H/x`. One function for
/// [`request_url`], [`url_origin`] and [`seller_url`], so the three agree on what is absolute.
fn split_scheme(url: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    let mut b = scheme.bytes();
    let spelled = b.next().is_some_and(|c| c.is_ascii_alphabetic()) && b.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'));
    spelled.then_some((scheme, rest))
}

/// Split `scheme://host[:port]target` (userinfo and a fragment are dropped). Anything else is a
/// bare target, bound byte for byte: it binds no origin, which only matches a payer that bound
/// none either.
pub fn request_url(url: &str) -> RequestUrl {
    let Some((scheme, rest)) = split_scheme(url) else {
        return RequestUrl { scheme: String::new(), host: String::new(), port: String::new(), target: url.to_string() };
    };
    let rest = rest.split('#').next().unwrap_or("");
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let (host, port) = match authority.find(']') {
        Some(i) if authority.starts_with('[') => (&authority[..=i], authority[i + 1..].strip_prefix(':').unwrap_or("")),
        _ => authority.rsplit_once(':').unwrap_or((authority, "")),
    };
    let scheme = scheme.to_ascii_lowercase();
    let digits = !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit());
    let port = match (digits.then(|| port.parse::<u16>().ok()).flatten(), scheme.as_str()) {
        (Some(p), _) => p.to_string(),
        (None, "http") if port.is_empty() => "80".into(),
        (None, "https") if port.is_empty() => "443".into(),
        _ => port.to_string(),
    };
    let target = if tail.starts_with('/') { tail.to_string() } else { format!("/{tail}") };
    RequestUrl { scheme, host: host.to_ascii_lowercase(), port, target }
}

/// Refuse a URL or request target that holds a `#` (AGP-081, review T2). [`request_url`] drops a
/// fragment, so a payment for `/a` would authenticate `/a#b` too, and a server routes on the target
/// as it arrives. Payer and provider both call this before anything is signed, sent or served; the
/// digest and its published vectors are unchanged.
pub fn no_fragment(url: &str) -> Result<()> {
    if url.contains('#') {
        return fail("bad_request", "a URL with a # fragment is outside the request binding: not paid and not served");
    }
    Ok(())
}

/// `scheme://authority` of an absolute URL, or `""` for a bare target.
pub fn url_origin(url: &str) -> &str {
    match split_scheme(url) {
        Some((scheme, rest)) => &url[..scheme.len() + 3 + rest.find(['/', '?', '#']).unwrap_or(rest.len())],
        None => "",
    }
}

/// The origin of an absolute URL as [`request_url`] reads it: lowercase scheme and host, no
/// userinfo, and no port when it is the scheme's default. `""` for a bare target.
///
/// The rule (AGP-096, audit item 18): **one seller is one origin, however a caller spells it.**
/// The request binding has always read `HTTPS://API.example:443` and `https://u@api.example` as
/// `https://api.example`, while a payer's channel book was keyed by the spelling, so one seller
/// could be funded once per spelling. A payer keys its book by this string
/// ([`split_url`](crate::client::split_url)).
pub fn canonical_origin(url: &str) -> String {
    let u = request_url(url);
    if u.scheme.is_empty() {
        return String::new();
    }
    let default = matches!((u.scheme.as_str(), u.port.as_str()), ("http", "80") | ("https", "443"));
    if u.port.is_empty() || default {
        format!("{}://{}", u.scheme, u.host)
    } else {
        format!("{}://{}:{}", u.scheme, u.host, u.port)
    }
}

/// The URL a payer hands its transport for `url`, built from what [`request_url`] read.
///
/// The rule (AGP-105, fourth audit item 1): **the host a payer keys its book by, checks an
/// allowlist on and binds a payment to is the host the request is sent to.** [`request_url`]
/// decides the host; a transport parses the string again with its own parser (ureq uses the `url`
/// crate), and `http://a.example\@b.example/x` is host `b.example` to the first and `a.example`
/// to the second: B's channel paid and A was sent the payment. So no transport is given the
/// caller's string. It gets `scheme://[userinfo@]host[:port]target` put together from the parsed
/// parts, and a URL is refused when those parts are not spelled in the one way every parser reads
/// alike:
///
/// - not `scheme://...` (a bare target names no host; `http:\\h` and `http:/h` name one to a WHATWG parser);
/// - a backslash, a `#`, whitespace or a control character anywhere (a WHATWG parser reads `\`
///   as `/`, and drops tabs and newlines before it parses);
/// - a second `@`, or userinfo with a character outside RFC 3986's set for it;
/// - an empty host, or a host with a character other than a letter, digit, `.`, `-` or `_` (so no
///   percent-encoding and no non-ASCII name: a parser decodes or maps those);
/// - a host whose last label is a number and that is not a dotted quad as `Ipv4Addr` prints it
///   (`127.1`, `2130706433` and `0x7f.0.0.1` are 127.0.0.1 to a transport);
/// - a bracketed host that is not an IPv6 address as `Ipv6Addr` prints it;
/// - a port that is not a decimal number below 65536.
///
/// Case, a default port, a port's leading zeros and a trailing dot are not refused: both readings
/// agree on them. `http::UreqTransport` calls this on every request, and the payers call
/// it before anything is signed, funded or probed.
pub fn sendable_url(url: &str) -> Result<String> {
    let refuse = |why: &str| Err(ChannelError::new("bad_request", format!("the URL {why}: its host could be read two ways, so nothing is paid or sent")));
    if url.chars().any(|c| c == '\\' || c == '#' || c.is_whitespace() || c.is_control()) {
        return refuse("has a backslash, a #, a space or a control character");
    }
    let Some((_, rest)) = split_scheme(url) else {
        return refuse("is not scheme://host");
    };
    let authority = &rest[..rest.find(['/', '?']).unwrap_or(rest.len())];
    let (userinfo, hostport) = match authority.split_once('@') {
        Some((_, h)) if h.contains('@') => return refuse("has a second @"),
        Some((u, _)) if !u.bytes().all(|c| c.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:%".contains(&c)) => return refuse("has userinfo outside RFC 3986"),
        Some((u, h)) => (format!("{u}@"), h),
        None => (String::new(), authority),
    };
    let u = request_url(url);
    // `request_url` takes a bracketed host up to its `]` and a port only after `]:`
    if hostport.starts_with('[') && !hostport.split_once(']').is_some_and(|(_, after)| after.is_empty() || after.starts_with(':')) {
        return refuse("has something other than a port after a bracketed host");
    }
    if !host_spelled_one_way(&u.host) {
        return refuse("has a host that is not a plain name or an address in its usual form");
    }
    if !(u.port.is_empty() || u.port.bytes().all(|c| c.is_ascii_digit()) && u.port.parse::<u16>().is_ok()) {
        return refuse("has a port that is not a number below 65536");
    }
    let origin = canonical_origin(url);
    Ok(format!("{}://{userinfo}{}{}", u.scheme, &origin[u.scheme.len() + 3..], u.target))
}

/// A host as [`request_url`] returns it that every URL parser reads as written: see [`sendable_url`].
fn host_spelled_one_way(host: &str) -> bool {
    if let Some(v6) = host.strip_prefix('[') {
        return v6.strip_suffix(']').is_some_and(|a| a.parse::<std::net::Ipv6Addr>().is_ok_and(|ip| ip.to_string() == a));
    }
    if host.is_empty() || !host.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'-' | b'_')) {
        return false;
    }
    // the WHATWG rule for "this host is an IPv4 address": its last label is a number
    let last = host.strip_suffix('.').unwrap_or(host).rsplit('.').next().unwrap_or("");
    let number = !last.is_empty() && last.bytes().all(|c| c.is_ascii_digit()) || last.strip_prefix("0x").is_some_and(|h| h.bytes().all(|c| c.is_ascii_hexdigit()));
    !number || host.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| ip.to_string() == host)
}

/// `LE64(len(x)) ‖ x`: every field of a v2 digest or receipt, so no two field lists hash alike.
pub(crate) fn put_field(h: &mut Sha256, x: &[u8]) {
    h.update((x.len() as u64).to_le_bytes());
    h.update(x);
}

pub(crate) fn tagged(tag: &str) -> Sha256 {
    let t = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h
}

/// Which request a payment or receipt is for (AGP-068, review T2): hex of
/// `tagged_hash("xbt402/req/v2", f(method) ‖ f(scheme) ‖ f(host) ‖ f(port) ‖ f(target) ‖ f(body))`,
/// `f(x) = LE64(len(x)) ‖ x`, the URL split by [`request_url`]. `url` is the absolute URL the payer
/// sent the request to; the server rebuilds it from its public scheme, the `Host` header and the
/// request target.
pub fn request_digest_v2(method: &str, url: &str, body: &[u8]) -> String {
    let u = request_url(url);
    let mut h = tagged("xbt402/req/v2");
    for f in [method.as_bytes(), u.scheme.as_bytes(), u.host.as_bytes(), u.port.as_bytes(), u.target.as_bytes(), body] {
        put_field(&mut h, f);
    }
    hex::encode(h.finalize())
}

/// The message `payload.auth` MACs.
pub fn auth_message(chan: &str, seq: &str, cum: &str, sig: &str, req: &str) -> String {
    ["xbt402/auth", chan, seq, cum, sig, req].join("|")
}

/// `payload.auth`: binds one paid request to the channel, a fresh seq and the state it carries.
/// `seq` and `cum` are formatted as Python's `str()` does (so a JSON number and its decimal
/// string MAC the same); `sig` None is the empty string.
pub fn request_auth(key: &[u8; 32], chan: &str, seq: Option<&Value>, cum: Option<&Value>, sig: Option<&str>, req: &str) -> String {
    let msg = auth_message(chan, &py_str(seq), &py_str(cum), sig.unwrap_or(""), req);
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(msg.as_bytes());
    hex::encode(m.finalize().into_bytes())
}

/// Constant-time comparison of two MACs.
pub fn auth_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The fields a receipt signs, in order (AGP-068 adds the answer's `status` and `bodyHash`).
pub const RECEIPT_FIELDS: [&str; 8] = ["chan", "seq", "cum", "charged", "spentMsat", "req", "status", "bodyHash"];

/// `tagged_hash("xbt402/receipt/v2", f(chan) ‖ f(seq) ‖ … ‖ f(bodyHash))` over [`RECEIPT_FIELDS`],
/// each formatted as Python's `str()`, `f(x) = LE64(len(x)) ‖ x`.
pub fn receipt_message(r: &Value) -> [u8; 32] {
    let mut h = tagged("xbt402/receipt/v2");
    for k in RECEIPT_FIELDS {
        put_field(&mut h, py_str(r.get(k)).as_bytes());
    }
    h.finalize().into()
}

/// `bodyHash` of a receipt: hex `sha256` of the answer's body exactly as sent.
pub fn body_hash(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

/// What the payer signs to close: `tagged_hash("xbt402/close", chan)`.
pub fn close_message(chan: &str) -> [u8; 32] {
    tagged_hash("xbt402/close", chan.as_bytes())
}

/// x402 facilitator reasons for the protocol's own codes.
pub fn upstream_code(code: &str) -> String {
    match code {
        "unsupported_scheme_or_network" => "invalid_batch_settlement_xbt_scheme_or_network".into(),
        "bad_payload" => "invalid_batch_settlement_xbt_payload".into(),
        "bad_auth" => "invalid_batch_settlement_xbt_auth".into(),
        "channel_closing" => "invalid_batch_settlement_xbt_closing".into(),
        "bad_sig" => "invalid_batch_settlement_xbt_signature".into(),
        "wrong_network" => "invalid_network".into(),
        "close_failed" => "unexpected_settle_error".into(),
        "" => "invalid_batch_settlement_xbt_payload".into(),
        other => format!("invalid_batch_settlement_xbt_{other}"),
    }
}

/// A short snake_case identifier: the only provider-chosen string an error code may be.
pub fn safe_code(code: &str) -> bool {
    !code.is_empty() && code.len() <= 40 && code.bytes().all(|c| c == b'_' || c.is_ascii_lowercase())
        && code.bytes().any(|c| c.is_ascii_lowercase())
}

/// The URL a seller names for one of its own endpoints (`openUrl`, `chunkUrl`), held to `origin`
/// (`scheme://host[:port]`, the allowlisted one). The seller chooses this string, so it is never
/// just appended: `@evil.example/open` after the origin is another host. Accepted: a path that
/// starts with exactly one `/`, or an absolute URL on `origin`; no backslash, whitespace or
/// control character either way, and no `#` ([`no_fragment`]). Returns `origin` + path.
pub fn seller_url(origin: &str, given: &str) -> Result<String> {
    let refuse = |why: &str| Err(ChannelError::new("seller_url", format!("the seller's URL {why}; refused before any request")));
    if given.chars().any(|c| c == '\\' || c == '#' || c.is_whitespace() || c.is_control()) {
        return refuse("has a backslash, a #, a space or a control character");
    }
    let origin = origin.trim_end_matches('/');
    let path = match given.strip_prefix(origin) {
        Some(rest) if split_scheme(given).is_some() => rest,
        _ if split_scheme(given).is_some() => return refuse("is on another origin"),
        _ => given,
    };
    if !path.starts_with('/') || path.starts_with("//") {
        return refuse("is not a path on its own origin");
    }
    Ok(format!("{origin}{path}"))
}

/// PAYMENT-RESPONSE as an x402 v2 SettlementResponse around a signed receipt.
pub fn settlement_response(receipt: &Value, network: &str, payer: &str, success: bool) -> Value {
    let mut extra = Map::new();
    extra.insert("chargedAmount".into(), receipt.get("charged").cloned().unwrap_or(Value::Null));
    extra.insert("receipt".into(), receipt.clone());
    let mut m = Map::new();
    m.insert("success".into(), success.into());
    m.insert("transaction".into(), "".into());
    m.insert("network".into(), network.into());
    m.insert("payer".into(), payer.into());
    m.insert("amount".into(), "".into());
    m.insert("extra".into(), Value::Object(extra));
    Value::Object(m)
}

/// The signed channel receipt inside a PAYMENT-RESPONSE SettlementResponse.
pub fn receipt_of(resp: &Value) -> Result<&Value> {
    let r = resp.get("extra").and_then(|e| e.get("receipt")).filter(|r| r.is_object());
    let r = match r {
        Some(r) if scheme_accepted(r.get("scheme").and_then(Value::as_str)) => r,
        _ => return fail("bad_receipt", "PAYMENT-RESPONSE carries no batch-settlement receipt in extra.receipt"),
    };
    if py_str(resp["extra"].get("chargedAmount")) != py_str(r.get("charged")) {
        return fail("bad_receipt", "extra.chargedAmount differs from the signed receipt");
    }
    Ok(r)
}

/// Body of POST /x402/verify and /x402/settle.
pub fn facilitator_request(accepted: &Value, payload: &Value) -> Value {
    let mut pp = Map::new();
    pp.insert("x402Version".into(), X402_VERSION.into());
    pp.insert("accepted".into(), accepted.clone());
    pp.insert("payload".into(), payload.clone());
    let mut m = Map::new();
    m.insert("x402Version".into(), X402_VERSION.into());
    m.insert("paymentPayload".into(), Value::Object(pp));
    m.insert("paymentRequirements".into(), accepted.clone());
    Value::Object(m)
}

/// `{x402Version: 2, accepted, payload}`: what PAYMENT-SIGNATURE carries (base64).
pub fn payment_payload(accepted: &Value, payload: &Value) -> Value {
    let mut m = Map::new();
    m.insert("x402Version".into(), X402_VERSION.into());
    m.insert("accepted".into(), accepted.clone());
    m.insert("payload".into(), payload.clone());
    Value::Object(m)
}

// --- typed views for applications ---------------------------------------------------------------

/// `PaymentRequirements.extra` for the XBT `batch-settlement` channel binding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelExtra {
    pub min_capacity: String,
    pub max_capacity: String,
    pub min_expiry_blocks: u32,
    pub max_expiry_blocks: u32,
    pub close_margin_blocks: u32,
    pub min_conf: u32,
    pub close_fee_sat: String,
    pub open_url: String,
    pub close_url: String,
    pub billing: String,
    pub derivation: String,
    /// v1.2: absent means "payer".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_fee_payer: Option<String>,
    /// Anything else (conditional offers, route terms, /terms fields), kept in order.
    #[serde(flatten)]
    pub other: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String,
    pub amount: String,
    pub asset: String,
    pub pay_to: String,
    pub max_timeout_seconds: u64,
    pub extra: ChannelExtra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequired {
    pub x402_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub resource: Resource,
    pub accepts: Vec<PaymentRequirements>,
    /// The provider's view of an existing channel (on refusals).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<Value>,
}

/// `payload` of PAYMENT-SIGNATURE.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SchemePayload {
    pub chan: String,
    pub seq: u64,
    pub cum: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashlock: Option<String>,
    pub auth: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    pub scheme: String,
    pub chan: String,
    pub seq: u64,
    pub cum: String,
    pub charged: String,
    pub spent_msat: String,
    pub owed_msat: String,
    pub credit_msat: String,
    pub expiry: u32,
    pub req: String,
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlementResponse {
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    pub transaction: String,
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub is_valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalid_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportedKind {
    pub x402_version: u64,
    pub scheme: String,
    pub network: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SupportedResponse {
    pub kinds: Vec<SupportedKind>,
    pub extensions: Vec<Value>,
    pub signers: Map<String, Value>,
}

/// `channel` of an open request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenChannel {
    pub txid: String,
    pub vout: u32,
    pub capacity: u64,
    pub expiry: u32,
    pub payer_pub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer_spk: Option<String>,
    pub redeem_script: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_fee_payer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenResponse {
    pub chan: String,
    pub expiry: u32,
    pub max_cum: String,
    pub confirmations: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_fee_payer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_cum: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseResponse {
    pub chan: String,
    pub txid: String,
    pub cum: String,
    pub unpaid_msat: String,
}

#[cfg(test)]
mod tests {
    /// AGP-080 X1: whatever a seller writes, the URL built from it starts with the origin and a
    /// `/`, so its host is the origin's.
    #[test]
    fn x1_a_seller_url_is_held_to_its_origin() {
        let o = "https://api.example:8443";
        for good in ["/x402/xbt-channel/open", "/c/{i}?a=b", "https://api.example:8443/x402/open", "/"] {
            let u = seller_url(o, good).unwrap();
            assert!(u.starts_with("https://api.example:8443/"), "{good} -> {u}");
        }
        assert_eq!(seller_url("https://api.example:8443/", "/open").unwrap(), "https://api.example:8443/open");
        for bad in ["@evil.example/open", "//evil.example/open", ".evil.example/open", ":9/open", "open", "", "https://evil.example/open",
                    "https://api.example:8443@evil.example/open", "https://api.example:8443.evil.example/open", "https://api.example:84430/open",
                    "http://api.example:8443/open", "/open\\@evil.example", "/a b", "/a\tb", "/a\nHost: evil", "\\\\evil.example/open",
                    "javascript://api.example/open", "https://api.example:8443"] {
            let r = seller_url(o, bad);
            assert_eq!(r.as_ref().err().map(|e| e.code.as_str()), Some("seller_url"), "{bad:?} -> {r:?}");
        }
        // every prefix an attacker can put after the origin: the result never leaves it
        for lead in ["@", ".", ":", "-", "%2f", "\\", "?", "#", "x"] {
            if let Ok(u) = seller_url(o, &format!("{lead}evil.example/open")) {
                assert!(u.starts_with("https://api.example:8443/"), "{lead}: {u}");
            }
        }
    }

    use super::*;
    use serde_json::json;

    #[test]
    fn codes_and_digests() {
        assert_eq!(upstream_code("bad_sig"), "invalid_batch_settlement_xbt_signature");
        assert_eq!(upstream_code("stale_amount"), "invalid_batch_settlement_xbt_stale_amount");
        assert!(scheme_accepted(Some(SCHEME)) && scheme_accepted(Some(SCHEME_ALIAS)));
        assert!(!scheme_accepted(Some("exact")));
        assert!(safe_code("bad_sig") && !safe_code("Bad") && !safe_code("a b") && !safe_code("__"));
        assert_eq!(request_digest_v1("", "", b""), hex::encode(Sha256::digest(b"||")));
        let v = json!({"a": 1});
        assert_eq!(unb64json(&b64json(&v)).unwrap(), v);
        let r = json!({"chan": "c", "seq": 3, "cum": "5", "charged": "1", "spentMsat": "2", "req": "r", "status": 200, "bodyHash": "bh"});
        let mut pre = Vec::new();
        for f in ["c", "3", "5", "1", "2", "r", "200", "bh"] {
            pre.extend((f.len() as u64).to_le_bytes());
            pre.extend(f.as_bytes());
        }
        assert_eq!(receipt_message(&r), tagged_hash("xbt402/receipt/v2", &pre));
        assert_eq!(body_hash(b"x"), hex::encode(Sha256::digest(b"x")));
    }

    fn v2_preimage(fields: [&[u8]; 6]) -> Vec<u8> {
        let mut pre = Vec::new();
        for f in fields {
            pre.extend((f.len() as u64).to_le_bytes());
            pre.extend(f);
        }
        pre
    }

    #[test]
    fn request_digest_v2_is_the_tagged_hash_of_length_prefixed_fields() {
        let want = tagged_hash("xbt402/req/v2", &v2_preimage([b"POST", b"https", b"api.example", b"8443", b"/v1/q?a=1", b"{}"]));
        assert_eq!(request_digest_v2("POST", "https://api.example:8443/v1/q?a=1", b"{}"), hex::encode(want));
        // a bare target binds no origin; a close's payload binds the empty request
        let bare = tagged_hash("xbt402/req/v2", &v2_preimage([b"GET", b"", b"", b"", b"/v1/q", b""]));
        assert_eq!(request_digest_v2("GET", "/v1/q", b""), hex::encode(bare));
        let empty = tagged_hash("xbt402/req/v2", &v2_preimage([b"", b"", b"", b"", b"", b""]));
        assert_eq!(request_digest_v2("", "", b""), hex::encode(empty));
    }

    #[test]
    fn request_urls_are_canonical() {
        let u = |s: &str| {
            let r = request_url(s);
            (r.scheme, r.host, r.port, r.target)
        };
        let t = |a: &str, b: &str, c: &str, d: &str| (a.to_string(), b.to_string(), c.to_string(), d.to_string());
        assert_eq!(u("HTTPS://API.Example/v1/Q?A=1"), t("https", "api.example", "443", "/v1/Q?A=1"));
        assert_eq!(u("https://api.example:443/x"), u("https://api.example/x"));
        assert_eq!(u("http://h"), t("http", "h", "80", "/"));
        assert_eq!(u("http://h?q=1"), t("http", "h", "80", "/?q=1"));
        assert_eq!(u("http://user:pw@h:08080/p#frag"), t("http", "h", "8080", "/p"));
        assert_eq!(u("http://[::1]:8402/p"), t("http", "[::1]", "8402", "/p"));
        assert_eq!(u("http://[::1]/p"), t("http", "[::1]", "80", "/p"));
        assert_eq!(u("/v1/q"), t("", "", "", "/v1/q"));
        assert_eq!(url_origin("https://h:1/p?q"), "https://h:1");
        assert_eq!(url_origin("https://h"), "https://h");
        assert_eq!(url_origin("/p"), "");
    }

    #[test]
    fn no_two_requests_share_a_v2_digest() {
        // the reviewer's pair, and the same request at another scheme, host or port
        assert_ne!(request_digest_v2("GET", "/q?a|b", b""), request_digest_v2("GET", "/q?a", b"b|"));
        assert_eq!(request_digest_v1("GET", "/q?a|b", b""), request_digest_v1("GET", "/q?a", b"b|"), "the v1 collision");
        let base = request_digest_v2("GET", "https://api.example/v1/q", b"");
        for other in ["http://api.example/v1/q", "https://evil.example/v1/q", "https://api.example:8443/v1/q", "https://api.example/v1/q?"] {
            assert_ne!(base, request_digest_v2("GET", other, b""), "{other}");
        }
        // every way of cutting one byte string into (method, target, body) hashes differently
        let s = b"GET|/a|b|c";
        let mut seen = std::collections::HashSet::new();
        for i in 0..=s.len() {
            for j in i..=s.len() {
                let (m, t, b) = (&s[..i], &s[i..j], &s[j..]);
                let d = request_digest_v2(std::str::from_utf8(m).unwrap(), std::str::from_utf8(t).unwrap(), b);
                assert!(seen.insert(d), "cut at {i},{j} collides");
            }
        }
    }

    /// AGP-096: every spelling the request binding reads as one origin is one origin, and
    /// nothing else is.
    #[test]
    fn an_origin_has_one_spelling() {
        for same in ["https://api.example", "HTTPS://API.Example", "https://api.example:443", "https://api.example:0443/x?y", "https://u:p@api.example/",
                     "https://api.example?q=1", "https://api.example#f"] {
            assert_eq!(canonical_origin(same), "https://api.example", "{same}");
            // the binding agrees: the same request under each spelling has one digest
            let u = request_url(same);
            assert_eq!((u.scheme.as_str(), u.host.as_str(), u.port.as_str()), ("https", "api.example", "443"), "{same}");
        }
        for (url, origin) in [("http://api.example/x", "http://api.example"), ("http://api.example:80", "http://api.example"),
                              ("https://api.example:80/x", "https://api.example:80"), ("http://api.example:443", "http://api.example:443"),
                              ("https://api.example:8443/x", "https://api.example:8443"), ("https://api.example.evil.test", "https://api.example.evil.test"),
                              ("https://api.example./x", "https://api.example."), ("http://[::1]:8080/x", "http://[::1]:8080"), ("http://[::1]/x", "http://[::1]"),
                              ("coap+tcp://H:1/x", "coap+tcp://h:1"), ("ws://h", "ws://h"), ("https://api.example:x/y", "https://api.example:x"),
                              ("https://evil.test/https://api.example", "https://evil.test")] {
            assert_eq!(canonical_origin(url), origin, "{url}");
        }
        for bare in ["/a?next=http://h/x", "api.example/x", "", "://h/x"] {
            assert_eq!(canonical_origin(bare), "", "{bare:?}");
        }
        // two URLs have one canonical origin exactly when the binding gives them one scheme, host and port
        let urls = ["https://a.example", "https://A.example:443", "http://a.example", "https://a.example:444", "https://b.example", "https://u@a.example"];
        for a in urls {
            for b in urls {
                let (x, y) = (request_url(a), request_url(b));
                assert_eq!(canonical_origin(a) == canonical_origin(b), (x.scheme, x.host, x.port) == (y.scheme, y.host, y.port), "{a} {b}");
            }
        }
    }

    /// What the transport's parser (the `url` crate, as ureq uses it) reads as the origin.
    fn transport_origin(u: &str) -> Option<String> {
        let p = url::Url::parse(u).ok()?;
        let host = p.host_str()?;
        Some(p.port().map_or(format!("{}://{host}", p.scheme()), |port| format!("{}://{host}:{port}", p.scheme())))
    }

    #[test]
    fn a_sendable_url_is_the_parsed_one_and_the_rest_is_refused() {
        // AGP-105 (fourth audit item 1): accepted spellings, and what the transport is given
        for (url, sent) in [("http://b.example/x", "http://b.example/x"), ("HTTP://B.Example:80/x?y=1", "http://b.example/x?y=1"),
                            ("https://api.example:0443", "https://api.example/"), ("https://api.example:/x", "https://api.example/x"),
                            ("https://u:p@api.example:8443/x", "https://u:p@api.example:8443/x"), ("http://b.example?q", "http://b.example/?q"),
                            ("http://b.example./x", "http://b.example./x"), ("http://my_host-1.test:8402/x", "http://my_host-1.test:8402/x"),
                            ("http://127.0.0.1:22000/x", "http://127.0.0.1:22000/x"), ("http://[::1]:8080/x", "http://[::1]:8080/x"),
                            ("http://[::ffff:10.0.0.5]/x", "http://[::ffff:10.0.0.5]/x"), ("http://x.onion/a/@b", "http://x.onion/a/@b")] {
            assert_eq!(sendable_url(url).as_deref(), Ok(sent), "{url}");
            assert_eq!(canonical_origin(sent), canonical_origin(url), "{url}");
        }
        // refused: every spelling the audit and the task name, and the forms a WHATWG parser reads as absolute
        for url in ["http://a.example\\@b.example/x", "http://a.example\\.b.example/x", "http://b.example/x\\y", "http:\\\\b.example/x", "http:/b.example/x",
                    "http:b.example/x", "/x", "b.example/x", "", " http://b.example/x", "http://b.example/x y", "http://b.example/\tx", "http://a.example\t@b.example/x",
                    "http://b.example\n/x", "http://b.example/x\u{0}", "http://b.example/x\u{a0}y", "http://a.example@b.example@c.example/x", "http://a.example#@b.example/x",
                    "http://b.example/x#f", "http://u<@b.example/x", "http:///b.example/x", "http://@/x", "http://%62.example/x", "http://b.exa%6dple/x",
                    "http://\u{ff42}.example/x", "http://b\u{e9}.example/x", "http://b.example:x/x", "http://b.example:65536/x", "http://b.example:80:80/x",
                    "http://b.example:-1/x", "http://127.1/x", "http://2130706433/x", "http://0x7f.0.0.1/x", "http://0x7f000001/x", "http://017700000001/x",
                    "http://127.0.0.01/x", "http://127.0.0.1./x", "http://1.2.3.4.5/x", "http://a.0x/x", "http://[0:0:0:0:0:0:0:1]/x", "http://[::1]x/x",
                    "http://[::1%25eth0]/x", "http://[::FFFF:1.2.3.4]:x/", "http://[b.example]/x", "http://[::1/x", "http://b.example]/x", "http://b,example/x",
                    "http://b.example|/x", "http://b^example/x", "http://b example/x"] {
            let r = sendable_url(url);
            assert_eq!(r.as_ref().map_err(|e| e.code.as_str()), Err("bad_request"), "{url:?}");
        }
    }

    #[test]
    fn the_transports_parser_reads_every_sendable_url_as_the_book_does() {
        // every authority of up to 5 of these characters, and each inside a longer URL: when the
        // URL is accepted, the `url` crate reads the string the transport is given as the same
        // scheme, host and port as `canonical_origin` (the book key and the allowlist) reads the
        // caller's string. 2 * (7^1 + ... + 7^5) * ... cases; the alphabet holds every character
        // class the rule names.
        let alphabet = ["a", "B", "1", ".", ":", "@", "\\", "%61", "[", "]", "?", "/", "0x", "-", "_", "\t", "#", "80", "::"];
        let mut all = vec![String::new()];
        let mut from = 0;
        for _ in 0..4 {
            let to = all.len();
            for i in from..to {
                for a in alphabet {
                    all.push(format!("{}{a}", all[i]));
                }
            }
            from = to;
        }
        let (mut accepted, mut refused) = (0, 0);
        for mid in &all {
            for url in [format!("http://{mid}"), format!("http://{mid}/p?q"), format!("HTTPS://h.test{mid}/p"), format!("http://{mid}b.example:8080/x"), format!("http://[::1]{mid}")] {
                match sendable_url(&url) {
                    Ok(sent) => {
                        accepted += 1;
                        assert_eq!(transport_origin(&sent), Some(canonical_origin(&url)), "{url:?} is sent as {sent:?}");
                        assert_eq!(request_digest_v2("GET", &sent, b""), request_digest_v2("GET", &url, b""), "{url:?}: the binding is of what is sent");
                        assert_eq!(sendable_url(&sent).as_deref(), Ok(sent.as_str()), "{url:?}: what is sent is itself sendable, unchanged");
                    }
                    Err(_) => refused += 1,
                }
            }
        }
        assert!(accepted > 1_000 && refused > 100_000, "{accepted} accepted, {refused} refused");
    }

    #[test]
    fn a_bare_target_is_bound_byte_for_byte() {
        // AGP-090 (review T2): the pairs the audit found under one digest
        for (a, b) in [("/A?next=http://h/x", "/a?next=http://h/x"), ("/a?next=http://H/x", "/a?next=http://h/x"),
                       ("/a?next=http://user@h/x", "/a?next=http://h/x"), ("/a?next=http://h:080/x", "/a?next=http://h:80/x")] {
            assert_ne!(request_digest_v2("GET", a, b""), request_digest_v2("GET", b, b""), "{a} {b}");
        }
        let u = request_url("/a?next=http://H:080/x");
        assert_eq!((u.scheme.as_str(), u.host.as_str(), u.port.as_str(), u.target.as_str()), ("", "", "", "/a?next=http://H:080/x"));
        for bare in ["/a?next=http://h/x", "?x=a://b", "://h/x", "1a://h/x", "a b://h/x", ""] {
            assert_eq!(url_origin(bare), "", "{bare:?}");
        }
        // an absolute URL is split as before, a `://` in its query included
        let u = request_url("HTTP://Api.Example:080/a?next=http://H/x");
        assert_eq!((u.scheme.as_str(), u.host.as_str(), u.port.as_str(), u.target.as_str()), ("http", "api.example", "80", "/a?next=http://H/x"));
        assert_eq!(url_origin("coap+tcp://h:1/x?y=z://w"), "coap+tcp://h:1");
        // a seller's path whose query holds a URL is a path on its own origin; another scheme is not
        assert_eq!(seller_url("https://a.example", "/open?next=http://h/x").unwrap(), "https://a.example/open?next=http://h/x");
        assert!(seller_url("https://a.example", "x+y://evil.example/open").is_err());
    }

    #[test]
    fn no_two_bare_targets_are_split_alike() {
        // every string of up to 6 of these characters that starts with `/`: the digest's fields are
        // length-prefixed, so two targets share a digest exactly when they split into the same fields
        let alphabet = ['/', ':', 'a', 'A', '?', '@', '0'];
        let mut all = vec![String::from("/")];
        let mut from = 0;
        for _ in 0..5 {
            let end = all.len();
            for i in from..end {
                for c in alphabet {
                    let mut t = all[i].clone();
                    t.push(c);
                    all.push(t);
                }
            }
            from = end;
        }
        let split: std::collections::HashSet<_> = all.iter().map(|t| {
            let u = request_url(t);
            (u.scheme, u.host, u.port, u.target)
        }).collect();
        assert_eq!(split.len(), all.len());
        assert!(all.iter().any(|t| t.contains("://")));
    }
}
