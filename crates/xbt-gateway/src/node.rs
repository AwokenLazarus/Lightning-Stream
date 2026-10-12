//! The seller's Lightning node, as the gateway uses it: make, watch, settle and cancel hold
//! invoices, and read the block height. [`LndRest`] speaks the node's REST interface over TLS
//! pinned to the node's own certificate; [`crate::standin::StandIn`] is the node of the tests.
//!
//! Two macaroons, each refused on mainnet when it grants more than its list:
//! [`INVOICE_OPS`] for every invoice call, and [`INFO_OPS`] for the one call that tells the block
//! height. The invoice permissions cannot read the height (the node answers `permission denied`),
//! and the rule that no ticket is settled inside 24 blocks of its expiry cannot be kept without it.
//! Neither can send coins, pay, open a channel or bake a macaroon.
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE as B64URL};
use base64::Engine;
use serde_json::{json, Value};
use xbt402::macaroon::Macaroon;

use crate::Error;

/// What the invoice macaroon holds, and all it may hold on mainnet.
pub const INVOICE_OPS: [&str; 2] = ["invoices:read", "invoices:write"];
/// What the height macaroon holds, and all it may hold on mainnet.
pub const INFO_OPS: [&str; 1] = ["info:read"];

pub type Hash = [u8; 32];

/// Why a call on the node gave no answer to act on.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum NodeError {
    /// The node answered and said no: nothing changed on it.
    #[error("the node refused: {0}")]
    Refused(String),
    /// No answer, or one that cannot be read: the call may or may not have happened.
    #[error("the node gave no answer: {0}")]
    Unreachable(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvoiceState {
    /// Made, not paid.
    Open,
    /// Paid and held: a locked ticket.
    Accepted,
    Settled,
    Canceled,
}

/// A hold invoice as the node has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invoice {
    pub state: InvoiceState,
    /// What the held or settled HTLCs carry, in msat.
    pub paid_msat: u64,
    /// The earliest block height at which a held HTLC of this invoice expires.
    pub expiry_height: Option<u32>,
    /// The latest height at which the node accepted an HTLC of this invoice: the chain was at
    /// least this high.
    pub accept_height: Option<u32>,
}

impl Invoice {
    pub fn is_final(&self) -> bool {
        matches!(self.state, InvoiceState::Settled | InvoiceState::Canceled)
    }
}

/// What the node says of itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    /// The node id, 33 bytes hex: the payee of every ticket.
    pub pubkey: String,
    pub height: u32,
    pub synced: bool,
    /// The node's network names (`mainnet`, `regtest`, ...).
    pub networks: Vec<String>,
    /// The node advertises feature bit 512: an XBT Lightning build.
    pub blake2b: bool,
}

pub trait Node: Send + Sync {
    /// Register a hold invoice for `hash`; the BOLT 11 invoice.
    fn add_hold(
        &self,
        hash: &Hash,
        msat: u64,
        cltv_blocks: u32,
        expiry_s: u32,
    ) -> Result<String, NodeError>;
    /// Release a held invoice with its preimage. `Ok` also for an invoice that was settled before:
    /// success alone does not show the invoice was held until now.
    fn settle(&self, preimage: &[u8; 32]) -> Result<(), NodeError>;
    fn cancel(&self, hash: &Hash) -> Result<(), NodeError>;
    /// `Ok(None)`: the node has no such invoice.
    fn lookup(&self, hash: &Hash) -> Result<Option<Invoice>, NodeError>;
    /// Follow one invoice: `on` gets its state now and every change, until it returns false or the
    /// invoice is final (`Ok`), or the stream breaks (`Err`).
    fn watch(&self, hash: &Hash, on: &mut dyn FnMut(Invoice) -> bool) -> Result<(), NodeError>;
    fn info(&self) -> Result<Info, NodeError>;
}

/// Why a macaroon is not the narrow one, if it is not: permissions outside `allowed`, or
/// permissions that cannot be read. An allowlist, as the wallet's Lightning rail keeps one.
pub fn beyond(m: &Macaroon, allowed: &[&str]) -> Option<String> {
    let need = allowed.join(" ");
    if !m.readable() {
        return Some(format!("its permissions cannot be read (not this node's identifier): bake one with only {need}"));
    }
    let excess: Vec<&str> = m
        .ops
        .iter()
        .map(String::as_str)
        .filter(|o| !allowed.contains(o))
        .collect();
    (!excess.is_empty())
        .then(|| format!("it grants {}: bake one with only {need}", excess.join(", ")))
}

/// A macaroon file checked against its list: every permission of `allowed` must be there, and on
/// mainnet nothing else. Off mainnet a wider one is taken and the reason returned as a warning.
pub fn checked_macaroon(
    bytes: &[u8],
    what: &str,
    allowed: &[&str],
    mainnet: bool,
) -> Result<Option<String>, Error> {
    check_macaroon(bytes, what, allowed, mainnet).map_err(Error::Macaroon)
}

fn check_macaroon(
    bytes: &[u8],
    what: &str,
    allowed: &[&str],
    mainnet: bool,
) -> Result<Option<String>, String> {
    let m = xbt402::macaroon::parse(bytes).map_err(|e| format!("{what}: {e}"))?;
    let wide = beyond(&m, allowed);
    if m.readable() {
        if let Some(missing) = allowed.iter().find(|a| !m.ops.iter().any(|o| o == *a)) {
            return Err(format!(
                "{what} lacks {missing}: bake one with {}",
                allowed.join(" ")
            ));
        }
    }
    match wide {
        Some(why) if mainnet => Err(format!("{what} is refused on mainnet: {why}")),
        w => Ok(w.map(|why| format!("{what}: {why}"))),
    }
}

/// A TLS verifier that accepts exactly one certificate: the node's own `tls.cert` (self-signed, so
/// there is no CA path to check). The handshake signatures are still verified.
#[derive(Debug)]
struct PinnedCert {
    der: Vec<u8>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.der.as_slice() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "the node's TLS certificate is not the pinned tls.cert".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            m,
            c,
            d,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            m,
            c,
            d,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The first certificate in a PEM file, as DER.
fn pem_cert_der(pem: &str) -> Result<Vec<u8>, String> {
    let start = pem
        .find("-----BEGIN CERTIFICATE-----")
        .ok_or("tls.cert: no PEM certificate")?;
    let body = &pem[start + 27..];
    let end = body
        .find("-----END CERTIFICATE-----")
        .ok_or("tls.cert: unterminated PEM")?;
    let b64: String = body[..end].chars().filter(|c| !c.is_whitespace()).collect();
    B64.decode(b64)
        .map_err(|_| "tls.cert: bad base64".to_string())
}

/// Whether `base` is plain `http://` to a loopback address written as an address (a name, even
/// `localhost`, is whatever the resolver says).
fn http_loopback(base: &str) -> bool {
    let u = xbt402::wire::request_url(base);
    let host = u.host.trim_start_matches('[').trim_end_matches(']');
    u.scheme == "http"
        && host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|a| a.is_loopback())
}

/// The node's REST interface.
pub struct LndRest {
    base: String,
    invoice_macaroon: String,
    info_macaroon: String,
    /// Unary calls: a deadline on every read.
    agent: ureq::Agent,
    /// Invoice streams: silent for as long as nothing happens to the invoice.
    streams: ureq::Agent,
}

impl std::fmt::Debug for LndRest {
    /// The address only: a macaroon is never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LndRest({})", self.base)
    }
}

/// A stream that says nothing for this long is opened again: a connection that died without a
/// word must not leave a ticket unwatched.
const STREAM_SILENCE: Duration = Duration::from_secs(120);

impl LndRest {
    /// `base` is `https://host:port` with the node's `tls.cert` (plain `http://` only to a loopback
    /// address). The macaroons are file contents, checked by the caller ([`checked_macaroon`]).
    pub fn new(
        base: &str,
        invoice_macaroon: &[u8],
        info_macaroon: &[u8],
        tls_cert: Option<&Path>,
    ) -> Result<Self, Error> {
        Self::build(base, invoice_macaroon, info_macaroon, tls_cert).map_err(Error::Node)
    }

    fn build(
        base: &str,
        invoice_macaroon: &[u8],
        info_macaroon: &[u8],
        tls_cert: Option<&Path>,
    ) -> Result<Self, String> {
        let base = xbt402::wire::sendable_url(base.trim().trim_end_matches('/'))
            .map_err(|e| format!("node.rest: {e}"))?;
        let base = base.trim_end_matches('/').to_string();
        let tls = if base.starts_with("https://") {
            let cert = tls_cert.ok_or("an https node needs its tls.cert (node.tls_cert)")?;
            let pem = std::fs::read_to_string(cert)
                .map_err(|e| format!("tls.cert {}: {e}", cert.display()))?;
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedCert {
                    der: pem_cert_der(&pem)?,
                    provider,
                }))
                .with_no_client_auth();
            Some(Arc::new(cfg))
        } else if http_loopback(&base) {
            None
        } else {
            return Err("node.rest must be https (plain http only to a loopback address)".into());
        };
        // No redirect is followed: the macaroon would go with it, past the pinned certificate.
        let build = |read: Duration| {
            let b = ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(5))
                .timeout_read(read)
                .redirects(0);
            match &tls {
                Some(cfg) => b.tls_config(cfg.clone()).build(),
                None => b.build(),
            }
        };
        Ok(Self {
            base,
            invoice_macaroon: hex::encode(invoice_macaroon),
            info_macaroon: hex::encode(info_macaroon),
            agent: build(Duration::from_secs(15)),
            streams: build(STREAM_SILENCE),
        })
    }

    fn call(
        &self,
        agent: &ureq::Agent,
        macaroon: &str,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<ureq::Response, NodeError> {
        let req = agent
            .request(method, &format!("{}{path}", self.base))
            .set("Grpc-Metadata-macaroon", macaroon);
        let sent = match body {
            Some(b) => req
                .set("Content-Type", "application/json")
                .send_string(&b.to_string()),
            None => req.call(),
        };
        match sent {
            Ok(r) if (300..400).contains(&r.status()) => Err(NodeError::Unreachable(format!(
                "HTTP {}: a redirect, which is never followed",
                r.status()
            ))),
            Ok(r) => Ok(r),
            Err(ureq::Error::Status(code, r)) => {
                let text = read_capped(r.into_reader(), 64 << 10).unwrap_or_default();
                let v = serde_json::from_str::<Value>(&text).unwrap_or(Value::Null);
                let msg = message_of(&v).unwrap_or_else(|| text.chars().take(200).collect());
                // 5xx without the node's own JSON error is a proxy or a starting node: no answer
                if code >= 500 && message_of(&v).is_none() {
                    return Err(NodeError::Unreachable(format!("HTTP {code}: {msg}")));
                }
                Err(NodeError::Refused(msg))
            }
            Err(e) => Err(NodeError::Unreachable(e.to_string())),
        }
    }

    fn unary(
        &self,
        macaroon: &str,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, NodeError> {
        let r = self.call(&self.agent, macaroon, method, path, body)?;
        let text = read_capped(r.into_reader(), 1 << 20).map_err(NodeError::Unreachable)?;
        serde_json::from_str(&text)
            .map_err(|e| NodeError::Unreachable(format!("answer is not JSON: {e}")))
    }
}

fn read_capped(r: impl Read, cap: u64) -> Result<String, String> {
    let mut s = String::new();
    r.take(cap)
        .read_to_string(&mut s)
        .map_err(|e| e.to_string())?;
    Ok(s)
}

/// The message of a REST error: `{"message"}` (unary) or `{"error": {"message"}}` (a stream).
fn message_of(v: &Value) -> Option<String> {
    let e = v.get("error").filter(|e| e.is_object()).unwrap_or(v);
    e.get("message").and_then(Value::as_str).map(str::to_string)
}

/// A number the node writes as a JSON number or a decimal string. `None`: absent or not a number,
/// which is never read as zero.
fn num(v: Option<&Value>) -> Option<u64> {
    match v? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) if !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) => {
            s.parse().ok()
        }
        _ => None,
    }
}

/// An invoice from the node's JSON. An answer without a state it knows is an error, not "open".
pub fn invoice_of(v: &Value) -> Result<Invoice, NodeError> {
    let bad = |what: &str| NodeError::Unreachable(format!("invoice answer: {what}"));
    let state = match v.get("state").and_then(Value::as_str) {
        Some("OPEN") => InvoiceState::Open,
        Some("ACCEPTED") => InvoiceState::Accepted,
        Some("SETTLED") => InvoiceState::Settled,
        Some("CANCELED") => InvoiceState::Canceled,
        _ => return Err(bad("no state")),
    };
    let mut inv = Invoice {
        state,
        paid_msat: 0,
        expiry_height: None,
        accept_height: None,
    };
    let htlcs = v
        .get("htlcs")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    for h in htlcs {
        let live = match (state, h.get("state").and_then(Value::as_str)) {
            (InvoiceState::Accepted, Some("ACCEPTED"))
            | (InvoiceState::Settled, Some("SETTLED")) => true,
            (_, Some(_)) => false,
            (_, None) => return Err(bad("an HTLC without a state")),
        };
        if !live {
            continue;
        }
        let amt = num(h.get("amt_msat")).ok_or_else(|| bad("an HTLC without an amount"))?;
        inv.paid_msat = inv
            .paid_msat
            .checked_add(amt)
            .ok_or_else(|| bad("HTLC amounts overflow"))?;
        let expiry = num(h.get("expiry_height"))
            .and_then(|e| u32::try_from(e).ok())
            .ok_or_else(|| bad("an HTLC without an expiry height"))?;
        inv.expiry_height = Some(inv.expiry_height.map_or(expiry, |e| e.min(expiry)));
        if let Some(a) = num(h.get("accept_height")).and_then(|a| u32::try_from(a).ok()) {
            inv.accept_height = Some(inv.accept_height.map_or(a, |x| x.max(a)));
        }
    }
    if state == InvoiceState::Accepted && inv.expiry_height.is_none() {
        return Err(bad("held, with no held HTLC"));
    }
    Ok(inv)
}

impl Node for LndRest {
    fn add_hold(
        &self,
        hash: &Hash,
        msat: u64,
        cltv_blocks: u32,
        expiry_s: u32,
    ) -> Result<String, NodeError> {
        let body = json!({"hash": B64.encode(hash), "value_msat": msat.to_string(), "cltv_expiry": cltv_blocks.to_string(), "expiry": expiry_s.to_string()});
        let v = self.unary(
            &self.invoice_macaroon,
            "POST",
            "/v2/invoices/hodl",
            Some(&body),
        )?;
        match v.get("payment_request").and_then(Value::as_str) {
            Some(inv) if !inv.is_empty() => Ok(inv.to_string()),
            _ => Err(NodeError::Unreachable(
                "no payment_request in the answer".into(),
            )),
        }
    }

    fn settle(&self, preimage: &[u8; 32]) -> Result<(), NodeError> {
        self.unary(
            &self.invoice_macaroon,
            "POST",
            "/v2/invoices/settle",
            Some(&json!({"preimage": B64.encode(preimage)})),
        )
        .map(|_| ())
    }

    fn cancel(&self, hash: &Hash) -> Result<(), NodeError> {
        self.unary(
            &self.invoice_macaroon,
            "POST",
            "/v2/invoices/cancel",
            Some(&json!({"payment_hash": B64.encode(hash)})),
        )
        .map(|_| ())
    }

    fn lookup(&self, hash: &Hash) -> Result<Option<Invoice>, NodeError> {
        match self.unary(
            &self.invoice_macaroon,
            "GET",
            &format!("/v2/invoices/lookup?payment_hash={}", B64URL.encode(hash)),
            None,
        ) {
            Ok(v) => invoice_of(&v).map(Some),
            Err(NodeError::Refused(m)) if m.contains("unable to locate invoice") => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn watch(&self, hash: &Hash, on: &mut dyn FnMut(Invoice) -> bool) -> Result<(), NodeError> {
        let r = self.call(
            &self.streams,
            &self.invoice_macaroon,
            "GET",
            &format!("/v2/invoices/subscribe/{}", B64URL.encode(hash)),
            None,
        )?;
        let mut lines = BufReader::new(r.into_reader().take(16 << 20));
        let mut line = String::new();
        loop {
            line.clear();
            match lines.read_line(&mut line) {
                Ok(0) => return Err(NodeError::Unreachable("the invoice stream ended".into())),
                Ok(_) => {}
                Err(e) => return Err(NodeError::Unreachable(e.to_string())),
            }
            if line.trim().is_empty() {
                continue;
            }
            let v: Value = serde_json::from_str(&line)
                .map_err(|e| NodeError::Unreachable(format!("invoice stream: {e}")))?;
            let Some(result) = v.get("result") else {
                return Err(NodeError::Refused(
                    message_of(&v).unwrap_or_else(|| "invoice stream: no result".into()),
                ));
            };
            let inv = invoice_of(result)?;
            if !on(inv) || inv.is_final() {
                return Ok(());
            }
        }
    }

    fn info(&self) -> Result<Info, NodeError> {
        let v = self.unary(&self.info_macaroon, "GET", "/v1/getinfo", None)?;
        let bad = |what: &str| NodeError::Unreachable(format!("getinfo: {what}"));
        let pubkey = v
            .get("identity_pubkey")
            .and_then(Value::as_str)
            .filter(|k| k.len() == 66)
            .ok_or_else(|| bad("no identity_pubkey"))?;
        let height = num(v.get("block_height"))
            .and_then(|h| u32::try_from(h).ok())
            .ok_or_else(|| bad("no block_height"))?;
        let networks = v
            .get("chains")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|c| c.get("network").and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        Ok(Info {
            pubkey: pubkey.to_string(),
            height,
            synced: v.get("synced_to_chain") == Some(&Value::Bool(true)),
            networks,
            blake2b: v
                .get("features")
                .and_then(Value::as_object)
                .is_some_and(|f| f.contains_key("512")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xbt402::macaroon::lnd_macaroon_for_tests as lnd_macaroon;

    #[test]
    fn a_macaroon_is_taken_only_with_its_own_permissions_on_mainnet() {
        let exact = lnd_macaroon(&[("invoices", &["read", "write"])], &[]);
        assert_eq!(checked_macaroon(&exact, "m", &INVOICE_OPS, true), Ok(None));
        let info = lnd_macaroon(&[("info", &["read"])], &[]);
        assert_eq!(checked_macaroon(&info, "m", &INFO_OPS, true), Ok(None));
        // wider: refused on mainnet, a warning elsewhere
        for wide in [
            lnd_macaroon(
                &[("invoices", &["read", "write"]), ("info", &["read"])],
                &[],
            ),
            lnd_macaroon(
                &[("invoices", &["read", "write"]), ("offchain", &["write"])],
                &[],
            ),
            lnd_macaroon(
                &[("invoices", &["read", "write"]), ("onchain", &["write"])],
                &[],
            ),
            lnd_macaroon(
                &[
                    ("invoices", &["read", "write"]),
                    ("macaroon", &["generate"]),
                ],
                &[],
            ),
            lnd_macaroon(
                &[
                    ("invoices", &["read", "write"]),
                    ("uri", &["/lnrpc.Lightning/SendCoins"]),
                ],
                &[],
            ),
        ] {
            let e = checked_macaroon(&wide, "the invoice macaroon", &INVOICE_OPS, true)
                .unwrap_err()
                .to_string();
            assert!(
                e.contains("refused on mainnet")
                    && e.contains("bake one with only invoices:read invoices:write"),
                "{e}"
            );
            assert!(checked_macaroon(&wide, "m", &INVOICE_OPS, false)
                .unwrap()
                .unwrap()
                .contains("it grants"));
        }
        // narrower cannot work anywhere
        let read_only = lnd_macaroon(&[("invoices", &["read"])], &[]);
        for mainnet in [true, false] {
            assert!(checked_macaroon(&read_only, "m", &INVOICE_OPS, mainnet)
                .unwrap_err()
                .to_string()
                .contains("lacks invoices:write"));
        }
        // unreadable permissions: nothing can be concluded, so mainnet refuses
        let unreadable = lnd_macaroon(&[], &[]);
        assert!(checked_macaroon(&unreadable, "m", &INVOICE_OPS, true)
            .unwrap_err()
            .to_string()
            .contains("cannot be read"));
        assert!(checked_macaroon(b"junk", "m", &INVOICE_OPS, false).is_err());
    }

    #[test]
    fn an_invoice_is_read_strictly() {
        let held = json!({"state": "ACCEPTED", "htlcs": [
            {"state": "ACCEPTED", "amt_msat": "600000", "expiry_height": 187, "accept_height": 144},
            {"state": "ACCEPTED", "amt_msat": "400000", "expiry_height": 185, "accept_height": 145},
            {"state": "CANCELED", "amt_msat": "999", "expiry_height": 1, "accept_height": 999}]});
        assert_eq!(
            invoice_of(&held).unwrap(),
            Invoice {
                state: InvoiceState::Accepted,
                paid_msat: 1_000_000,
                expiry_height: Some(185),
                accept_height: Some(145)
            }
        );
        assert_eq!(
            invoice_of(&json!({"state": "OPEN", "htlcs": []}))
                .unwrap()
                .state,
            InvoiceState::Open
        );
        assert_eq!(
            invoice_of(&json!({"state": "CANCELED"})).unwrap().state,
            InvoiceState::Canceled
        );
        for bad in [
            json!({}),
            json!({"state": "open"}),
            json!({"state": "ACCEPTED", "htlcs": []}),
            json!({"state": "ACCEPTED", "htlcs": [{"state": "ACCEPTED", "amt_msat": "1", "expiry_height": "x"}]}),
            json!({"state": "ACCEPTED", "htlcs": [{"state": "ACCEPTED", "expiry_height": 5}]}),
            json!({"state": "ACCEPTED", "htlcs": [{"amt_msat": "1", "expiry_height": 5}]}),
            json!({"state": "ACCEPTED", "htlcs": [{"state": "ACCEPTED", "amt_msat": "18446744073709551615", "expiry_height": 5}, {"state": "ACCEPTED", "amt_msat": "1", "expiry_height": 5}]}),
        ] {
            assert!(invoice_of(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_node_is_reached_over_pinned_tls_or_loopback_only() {
        for bad in [
            "http://node.example:8080",
            "http://localhost:8080",
            "http://192.0.2.1:8080",
            "ftp://127.0.0.1",
            "http://127.1:8080",
        ] {
            assert!(LndRest::new(bad, b"", b"", None).is_err(), "{bad}");
        }
        assert!(LndRest::new("https://127.0.0.1:8080", b"", b"", None)
            .unwrap_err()
            .to_string()
            .contains("tls.cert"));
        assert!(LndRest::new("http://127.0.0.1:8080/", b"", b"", None).is_ok());
        assert!(LndRest::new("http://[::1]:8080", b"", b"", None).is_ok());
    }
}
