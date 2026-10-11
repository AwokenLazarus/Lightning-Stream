//! The payer (spec §4.5, §8, §9.3, §11): an `xbt-work` payer for the xbt402
//! [`Client`](xbt402::client::Client) ([`Client::with_payer`](xbt402::client::Client::with_payer)).
//!
//! On a 402 that offers `xbt-work` it takes an invoice (once per origin), tells the caller the
//! username to mine as ([`WorkPayer::prepare`]), fetches the latest receipt through the blinded
//! relay (or the Prime's direct query), verifies it under the advertised (and optionally pinned)
//! Prime key, and presents it with a fresh `n` and the request-bound `auth`. Each PAYMENT-RESPONSE
//! is checked: the invoice, the request digest, the charge within the quote, and `spentWork`
//! growing by exactly `charged`.
//!
//! Limits of this rail against someone between payer and provider (AGP-081, the closure audit of
//! review T2 and T4), where it is below the channel rail:
//!
//! * The request binding is taken over the bare target (as the XBT-053 vectors are): it
//!   holds the method, path, query and body, and no scheme, host or port. A header captured on its
//!   way to one origin authenticates, once, at any other origin that holds this invoice's key.
//! * The PAYMENT-RESPONSE is not signed and covers neither the answer's status nor its body. The
//!   client requires one on every call paid with work (xbt402's `Client`), and it must name this
//!   invoice and request and move `spentWork` by `charged`, but whoever can alter the answer can
//!   alter it too. What was paid for is checked by the provider's balance, not by this receipt.
//!
//! Run this rail over TLS to the provider. Raising it to the channel rail's level is a change to
//! the xbt-work spec (a signed receipt with status and bodyHash, an origin in the binding).
//!
//! AGP-091, two rules of this payer:
//!
//! * **A lost answer costs that answer and no other.** The provider debits a call before it
//!   answers, so after an answer is lost its `spentWork` is ahead of what this payer last saw.
//!   Each PAYMENT-RESPONSE names the `n` of the call it answers; `spentWork` must have grown by
//!   `charged` and by no more than the quotes of the earlier calls that are still unanswered
//!   ([`Session::unanswered`]). Before, it had to grow by exactly `charged`, and after one lost
//!   answer every later call was debited and its answer thrown away. An answer whose `n` is not
//!   an open call of this payer (an earlier answer played again) is refused.
//! * **The payer fetches a receipt only where it said it would, or at the provider's own origin.**
//!   The provider writes `receiptUrl` and `relayUrl` into the invoice. The payer's own
//!   [`PayerConfig::relay_url`] and [`PayerConfig::receipt_url`] come first; a URL only the invoice
//!   names is used when it is on the provider's origin or on one of
//!   [`PayerConfig::allow_origins`], and refused (`provider_url`) before any request otherwise.
//!   Before, the payer sent a GET to whatever URL the invoice named.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use serde_json::Value;
use xbt402::client::{split_url, Transport};
use xbt402::error::{ChannelError, Result as XResult};
use xbt402::json::{dumps, obj, py_str, py_u64};
use xbt402::scheme::SchemePayer;
use xbt402::wire::{b64json, payment_payload, unb64json};

use crate::auth::{auth_tag, request_digest};
use crate::error::{fail, Result, WorkError};
use crate::grammar::{valid_identity, valid_invoice};
use crate::receipt::{pubkey_from_hex, Signed};
use crate::{SCHEME, INVOICE_PATH};

/// One origin's invoice and receipt state.
#[derive(Debug, Clone)]
pub struct Session {
    /// The xbt-work PaymentRequirements answered.
    pub accepted: Value,
    /// The invoice document (holds `authKey`).
    pub invoice: Value,
    /// Last `n` used.
    pub n: u64,
    pub best: Option<Signed>,
    /// Work the provider reports spent (from the last PAYMENT-RESPONSE).
    pub spent: u64,
    /// Refusal of the last paid call, if any.
    pub last_error: Option<String>,
    /// Calls sent and not answered yet: (`n`, the quote in work units), lowest `n` first. The
    /// provider may have debited any of them.
    pub unanswered: Vec<(u64, u64)>,
}

/// The most unanswered calls a session lists one by one; older ones are folded into the oldest
/// entry kept (their quotes still count, their `n` no longer answers).
const MAX_UNANSWERED: usize = 256;

impl Session {
    pub fn invoice_id(&self) -> &str {
        self.invoice.get("invoice").and_then(Value::as_str).unwrap_or("")
    }

    pub fn identity(&self) -> &str {
        self.invoice.get("identity").and_then(Value::as_str).unwrap_or("")
    }

    fn auth_key(&self) -> Vec<u8> {
        self.invoice.get("authKey").and_then(Value::as_str).and_then(|h| hex::decode(h).ok()).unwrap_or_default()
    }

    /// Work credited by the best receipt held.
    pub fn credited(&self) -> u64 {
        self.best.as_ref().map(|b| b.receipt.cum_work).unwrap_or(0)
    }

    pub fn amount(&self) -> u64 {
        py_u64(self.accepted.get("amount")).unwrap_or(0)
    }

    /// The stratum username to mine as: the worker-field form (§4.3, RECOMMENDED).
    pub fn username(&self, worker: &str) -> String {
        format!("{}.pw-{}.{worker}", self.identity(), self.invoice_id())
    }
}

/// Payer settings.
#[derive(Debug, Clone, Default)]
pub struct PayerConfig {
    pub network: String,
    /// Most work units a call may cost.
    pub max_amount: u64,
    /// The Prime key this payer's own gateway pins (§7: SHOULD check `primePubkey` against it).
    pub pinned_prime: Option<String>,
    /// The blinded relay this payer fetches receipts from. It comes before anything the invoice
    /// names.
    pub relay_url: Option<String>,
    /// The Prime's receipt query this payer uses when it has no relay (as the provider's
    /// `receipt_url`: the payer adds `?identity=…&invoice=…`). It comes before the invoice's.
    pub receipt_url: Option<String>,
    /// Origins (`scheme://host[:port]`) besides the provider's own on which a `relayUrl` or
    /// `receiptUrl` named only by the invoice is fetched.
    pub allow_origins: Vec<String>,
    /// Where sessions are kept (they hold each invoice's `authKey`). None: memory only.
    pub state_path: Option<PathBuf>,
}

pub struct WorkPayer {
    pub cfg: PayerConfig,
    sessions: Mutex<HashMap<String, Session>>,
}

fn xerr(e: WorkError) -> ChannelError {
    ChannelError::new(&e.code, e.msg)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Check the payer's DATUM gateway configuration (its JSON config file) before mining for an
/// invoice (AGP-065). The gateway must pass the stratum username to the Prime unchanged
/// (`datum.pool_pass_full_users`, default true): with it off, the gateway sends
/// `<mining.pool_address>.<username>`, the Prime credits the gateway's own address, and no receipt
/// ever names the provider's identity.
pub fn check_gateway_config(cfg: &Value) -> Result<()> {
    match cfg.pointer("/datum/pool_pass_full_users") {
        None | Some(Value::Bool(true)) => Ok(()),
        Some(Value::Bool(false)) => fail("gateway_config", "datum.pool_pass_full_users is false: the Prime would credit the gateway's pool_address, \
                                                            not the invoice; set it to true"),
        Some(_) => fail("gateway_config", "datum.pool_pass_full_users is not a boolean"),
    }
}

impl WorkPayer {
    pub fn new(cfg: PayerConfig) -> Result<Self> {
        let p = Self { cfg, sessions: Mutex::new(HashMap::new()) };
        p.load()?;
        Ok(p)
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Session>> {
        self.sessions.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn session(&self, origin: &str) -> Option<Session> {
        self.lock().get(origin).cloned()
    }

    /// Check an offer: our network, a sane Prime key (the pinned one when pinned), amount in budget.
    fn check_offer(&self, acc: &Value) -> Result<()> {
        if acc.get("scheme").and_then(Value::as_str) != Some(SCHEME) || acc.get("network").and_then(Value::as_str) != Some(&self.cfg.network) {
            return fail("bad_offer", "not an xbt-work offer on our network");
        }
        let amount = py_u64(acc.get("amount")).ok_or_else(|| WorkError::new("bad_offer", "amount"))?;
        if self.cfg.max_amount > 0 && amount > self.cfg.max_amount {
            return fail("too_expensive", format!("{amount} work units > max {}", self.cfg.max_amount));
        }
        let pk = acc.pointer("/extra/primePubkey").and_then(Value::as_str).unwrap_or("");
        pubkey_from_hex(pk).map_err(|e| WorkError::new("bad_offer", e.0))?;
        if let Some(pin) = &self.cfg.pinned_prime {
            if pin.get(..64) != pk.get(..64) {
                return fail("bad_offer", "primePubkey is not the Prime key our gateway pins");
            }
        }
        if !acc.get("payTo").and_then(Value::as_str).is_some_and(valid_identity) {
            return fail("bad_offer", "payTo outside the identity grammar");
        }
        Ok(())
    }

    /// Take an invoice for `origin` from the offer `acc` (POST extra.invoiceUrl), unless a session
    /// for the same payTo exists. A session whose invoice expired with no work on it (after one
    /// more receipt fetch) is replaced: the provider no longer accepts it (AGP-065).
    pub fn open(&self, t: &dyn Transport, origin: &str, acc: &Value) -> Result<Session> {
        self.check_offer(acc)?;
        let same = |s: &Session| s.accepted.get("payTo") == acc.get("payTo") && s.accepted.pointer("/extra/primePubkey") == acc.pointer("/extra/primePubkey");
        let stale = |s: &Session| s.credited() == 0 && s.invoice.get("expiresAt").and_then(Value::as_u64).is_some_and(|e| e < now_secs());
        if self.session(origin).is_some_and(|s| same(&s) && stale(&s)) {
            // the expired invoice may still hold work the payer has not fetched yet
            let _ = self.refresh(t, origin);
        }
        if let Some(s) = self.lock().get_mut(origin) {
            if same(s) && !stale(s) {
                s.accepted = acc.clone();
                return Ok(s.clone());
            }
        }
        // the seller names this URL: it stays on the seller's origin (AGP-080 X1)
        let url = xbt402::wire::seller_url(origin, acc.pointer("/extra/invoiceUrl").and_then(Value::as_str).unwrap_or(INVOICE_PATH)).map_err(WorkError::from)?;
        let r = t.request("POST", &url, b"", &[])?;
        if r.status != 200 {
            return fail(if r.status == 429 { "too_many_invoices" } else { "provider_error" }, format!("invoice: HTTP {}", r.status));
        }
        let inv = xbt402::json::parse_slice(&r.body).map_err(|_| WorkError::new("provider_error", "invoice is not JSON"))?;
        let ok = inv.get("invoice").and_then(Value::as_str).is_some_and(valid_invoice)
            && inv.get("identity") == acc.get("payTo")
            && inv.get("authKey").and_then(Value::as_str).and_then(|h| hex::decode(h).ok()).is_some_and(|k| k.len() == 32)
            && inv.get("primePubkey").and_then(Value::as_str).and_then(|p| p.get(..64)) == acc.pointer("/extra/primePubkey").and_then(Value::as_str).and_then(|p| p.get(..64));
        if !ok {
            return fail("bad_offer", "invoice does not match the offer (identity, key or Prime)");
        }
        let s = Session { accepted: acc.clone(), invoice: inv, n: 0, best: None, spent: 0, last_error: None, unanswered: vec![] };
        self.lock().insert(origin.to_string(), s.clone());
        self.save()?;
        Ok(s)
    }

    /// GET `url`, and on a 402 that offers xbt-work take an invoice: the session to mine for.
    pub fn prepare(&self, t: &dyn Transport, url: &str) -> Result<Session> {
        // AGP-105: the session is keyed by the host the request is sent to (`wire::sendable_url`)
        let url = &xbt402::wire::sendable_url(url).map_err(WorkError::from)?;
        let (origin, _) = split_url(url);
        let r = t.request("GET", url, b"", &[])?;
        if r.status != 402 {
            return fail("no_offer", format!("HTTP {} (not a 402)", r.status));
        }
        let pr = unb64json(r.header("PAYMENT-REQUIRED").unwrap_or("")).map_err(WorkError::from)?;
        let acc = pr.get("accepts").and_then(Value::as_array).into_iter().flatten()
            .find(|a| a.get("scheme").and_then(Value::as_str) == Some(SCHEME)).cloned()
            .ok_or_else(|| WorkError::new("no_scheme", "the 402 does not offer xbt-work"))?;
        self.open(t, &origin, &acc)
    }

    /// A URL only the invoice names, held to where this payer fetches (AGP-091): `http(s)`, no
    /// userinfo, backslash, `#`, whitespace or control character, and on the provider's own origin
    /// or one of [`PayerConfig::allow_origins`].
    fn provider_named(&self, origin: &str, what: &str, url: &str) -> Result<String> {
        let refuse = |why: String| fail("provider_url", format!("the invoice's {what} {why}; refused before any request"));
        if url.chars().any(|c| c == '\\' || c == '#' || c == '@' || c.is_whitespace() || c.is_control()) {
            return refuse("has a backslash, a #, an @, a space or a control character".into());
        }
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return refuse("is not an http(s) URL".into());
        }
        let (its, _) = split_url(url);
        // the origin ends at the first `/`, `?` or `#`: a query straight after the host is not part of it
        let its = its.split('?').next().unwrap_or("").to_string();
        let same = |o: &str| o.trim_end_matches('/').eq_ignore_ascii_case(&its);
        if same(origin) || self.cfg.allow_origins.iter().any(|o| same(o)) {
            return Ok(url.to_string());
        }
        refuse(format!("is on {its}, which is neither the provider's origin nor one this payer allows (set this payer's own relay or receipt URL, or allow that origin)"))
    }

    /// Fetch the latest receipt for `origin`'s invoice, verify it and keep it if it is newer.
    /// Returns the best receipt held. Where from: this payer's own relay, else its own receipt
    /// query, else the invoice's `relayUrl`, else the invoice's `receiptUrl`, the last two only
    /// through `WorkPayer::provider_named`.
    pub fn refresh(&self, t: &dyn Transport, origin: &str) -> Result<Option<Signed>> {
        let s = self.session(origin).ok_or_else(|| WorkError::new("no_session", origin.to_string()))?;
        let (ident, inv) = (s.identity().to_string(), s.invoice_id().to_string());
        let named = |k: &str| s.invoice.get(k).and_then(Value::as_str).map(str::to_string);
        let (relay, query) = match (&self.cfg.relay_url, &self.cfg.receipt_url, named("relayUrl")) {
            (Some(r), _, _) => (Some(r.clone()), None),
            (None, Some(q), _) => (None, Some(format!("{q}?identity={ident}&invoice={inv}"))),
            (None, None, Some(r)) => (Some(self.provider_named(origin, "relayUrl", &r)?), None),
            (None, None, None) => (None, Some(self.provider_named(origin, "receiptUrl", &named("receiptUrl").unwrap_or_default())?)),
        };
        let doc = match (relay, query) {
            (Some(r), _) => crate::relay::fetch(t, &r, &ident, &inv)?,
            (None, url) => {
                let r = t.request("GET", &url.unwrap_or_default(), b"", &[])?;
                if r.status != 200 {
                    return fail("prime_error", format!("receipt query: HTTP {}", r.status));
                }
                Some(xbt402::json::parse_slice(&r.body).map_err(|_| WorkError::new("prime_error", "not JSON"))?)
            }
        };
        let Some(doc) = doc else { return Ok(s.best) };
        let signed = Signed::from_doc(&doc).map_err(WorkError::from)?;
        let pk = pubkey_from_hex(s.accepted.pointer("/extra/primePubkey").and_then(Value::as_str).unwrap_or(""))?;
        if !signed.verify(&pk) {
            return fail("bad_sig", "fetched receipt not signed by the Prime key");
        }
        if signed.receipt.identity != ident || signed.receipt.invoice != inv {
            return fail("bad_receipt", "fetched receipt is for another identity or invoice");
        }
        let mut m = self.lock();
        let sess = m.get_mut(origin).expect("session");
        if sess.best.as_ref().is_none_or(|b| signed.receipt.seq > b.receipt.seq) {
            sess.best = Some(signed);
        }
        let best = sess.best.clone();
        drop(m);
        self.save()?;
        Ok(best)
    }

    /// The PAYMENT-SIGNATURE for one request, paying with `receipt_doc` (the Prime's document
    /// without `sig`) and `sig`, with the next `n`. `auth` covers the values presented, so a caller
    /// may present an older or altered receipt (the refusal checks do).
    pub fn header_with(&self, origin: &str, receipt_doc: &Value, sig_hex: &str, method: &str, path: &str, body: &[u8]) -> Result<String> {
        let mut m = self.lock();
        let s = m.get_mut(origin).ok_or_else(|| WorkError::new("no_session", origin.to_string()))?;
        s.n += 1;
        // sent from here on, answered or not: the provider may debit it
        s.unanswered.push((s.n, s.amount()));
        if s.unanswered.len() > MAX_UNANSWERED {
            let (_, oldest) = s.unanswered.remove(0);
            s.unanswered[0].1 = s.unanswered[0].1.saturating_add(oldest);
        }
        let rr = receipt_doc.get("receipt");
        let num = |k: &str| rr.and_then(|r| r.get(k)).and_then(|v| py_u64(Some(v))).unwrap_or(0);
        let invoice = py_str(receipt_doc.get("invoice"));
        let auth = auth_tag(&s.auth_key(), if valid_invoice(&invoice) { &invoice } else { s.invoice_id() }, s.n, num("seq"), num("cum_work"),
                            &request_digest(method, path, body))?;
        let pl = obj([("receipt", receipt_doc.clone()), ("sig", sig_hex.into()), ("n", s.n.into()), ("auth", auth.into())]);
        let h = b64json(&payment_payload(&s.accepted, &pl));
        drop(m);
        self.save()?;
        Ok(h)
    }

    /// The PAYMENT-SIGNATURE paying with the best receipt held.
    pub fn header(&self, origin: &str, method: &str, path: &str, body: &[u8]) -> Result<String> {
        let s = self.session(origin).ok_or_else(|| WorkError::new("no_session", origin.to_string()))?;
        let b = s.best.ok_or_else(|| WorkError::new("insufficient_work", "no receipt yet: mine first"))?;
        self.header_with(origin, &b.receipt.to_doc(), &hex::encode(b.sig), method, path, body)
    }

    /// Check a PAYMENT-RESPONSE (§9.3) and adopt its spentWork.
    pub fn check_response(&self, origin: &str, resp: &Value, method: &str, path: &str, body: &[u8]) -> Result<()> {
        let mut m = self.lock();
        let s = m.get_mut(origin).ok_or_else(|| WorkError::new("no_session", origin.to_string()))?;
        let r = resp.pointer("/extra/receipt").filter(|r| r.get("scheme").and_then(Value::as_str) == Some(SCHEME))
            .ok_or_else(|| WorkError::new("bad_receipt", "PAYMENT-RESPONSE carries no xbt-work receipt"))?;
        let bad = |w: &str| fail("bad_receipt", w.to_string());
        if resp.get("network").and_then(Value::as_str) != Some(&self.cfg.network) || resp.get("payer").and_then(Value::as_str) != Some(s.invoice_id()) {
            return bad("PAYMENT-RESPONSE is for another network or invoice");
        }
        if r.get("invoice").and_then(Value::as_str) != Some(s.invoice_id()) {
            return bad("receipt is for another invoice");
        }
        if py_str(resp.pointer("/extra/chargedAmount")) != py_str(r.get("charged")) {
            return bad("extra.chargedAmount differs from receipt.charged");
        }
        if py_str(r.get("req")) != request_digest(method, path, body) {
            return bad("receipt is for another request");
        }
        let num = |k: &str| r.get(k).and_then(|v| v.as_str()).and_then(|v| v.parse::<u64>().ok());
        // creditedWork may exceed the receipt we presented: the provider also pulls receipts
        // from the relay itself (§11), so it is informational here
        let (Some(charged), Some(spent), Some(_credited)) = (num("charged"), num("spentWork"), num("creditedWork")) else {
            return bad("receipt amounts are not decimal strings");
        };
        if charged > s.amount() {
            return bad("charged more than the quote");
        }
        // the call this answers (a provider that names none answers the last one sent)
        let n = match r.get("n") {
            None => s.n,
            Some(n) => n.as_u64().ok_or_else(|| WorkError::new("bad_receipt", "receipt n is not an integer"))?,
        };
        if !s.unanswered.iter().any(|(open, _)| *open == n) {
            return bad("receipt answers no call of ours that is still open");
        }
        // calls sent before this one whose answers never came: the provider debited them or not
        let lost = s.unanswered.iter().filter(|(open, _)| *open < n).fold(0u64, |a, (_, q)| a.saturating_add(*q));
        let Some(least) = s.spent.checked_add(charged) else { return bad("spentWork overflows") };
        if spent < least || spent > least.saturating_add(lost) {
            return bad("spentWork did not grow by charged (and by no more than the calls still unanswered)");
        }
        s.spent = spent;
        s.unanswered.retain(|(open, _)| *open > n);
        drop(m);
        self.save()
    }

    // --- durable sessions ----------------------------------------------------------------------

    fn save(&self) -> Result<()> {
        let Some(path) = &self.cfg.state_path else { return Ok(()) };
        let m = self.lock();
        let doc: serde_json::Map<String, Value> = m.iter().map(|(o, s)| {
            (o.clone(), obj([("accepted", s.accepted.clone()), ("invoice", s.invoice.clone()), ("n", s.n.into()),
                             ("best", s.best.as_ref().map(Signed::to_doc).unwrap_or(Value::Null)), ("spent", s.spent.into()),
                             ("unanswered", s.unanswered.iter().map(|(n, q)| Value::from(vec![*n, *q])).collect::<Vec<_>>().into())]))
        }).collect();
        crate::fsx::write_private(path, dumps(&Value::Object(doc)).as_bytes()).map_err(|e| WorkError::new("state_io", e.to_string()))
    }

    fn load(&self) -> Result<()> {
        let Some(path) = &self.cfg.state_path else { return Ok(()) };
        let Ok(raw) = std::fs::read(path) else { return Ok(()) };
        let v = xbt402::json::parse_slice(&raw).map_err(|_| WorkError::new("bad_state", "not JSON"))?;
        // The rule (AGP-106): **a saved session is found under every spelling of its origin.**
        // Sessions are asked for under the canonical origin (`split_url`: lowercase host, no
        // default port); a file written before AGP-096 has them under the URL's own spelling, so
        // each key is read as the origin it spells and written back that way at the next save.
        // Two keys that spell one origin are two invoices for one seller, and only one can be the
        // session: neither is dropped here, the file is refused as it is and the owner chooses.
        let mut m = HashMap::new();
        let mut spelled: HashMap<String, &String> = HashMap::new();
        for (o, s) in v.as_object().into_iter().flatten() {
            let origin = split_url(o).0;
            if let Some(other) = spelled.insert(origin.clone(), o) {
                return fail("bad_state", format!("the saved sessions `{other}` and `{o}` are both for {origin}: keep one of them in {} \
                                                  (the one with work left to spend) and start again", path.display()));
            }
            let best = match s.get("best") {
                Some(b) if !b.is_null() => Some(Signed::from_doc(b)?),
                _ => None,
            };
            m.insert(origin, Session { accepted: s["accepted"].clone(), invoice: s["invoice"].clone(), n: py_u64(s.get("n")).unwrap_or(0),
                                          best, spent: py_u64(s.get("spent")).unwrap_or(0), last_error: None,
                                          unanswered: s.get("unanswered").and_then(Value::as_array).into_iter().flatten()
                                              .filter_map(|e| Some((e.get(0)?.as_u64()?, e.get(1)?.as_u64()?))).collect() });
        }
        *self.lock() = m;
        Ok(())
    }
}

impl SchemePayer for WorkPayer {
    fn scheme(&self) -> &str {
        SCHEME
    }

    fn upfront(&self, origin: &str, method: &str, path: &str, body: &[u8]) -> XResult<Option<Vec<(String, String)>>> {
        match self.session(origin) {
            Some(s) if s.best.is_some() => Ok(Some(vec![("PAYMENT-SIGNATURE".into(), self.header(origin, method, path, body).map_err(xerr)?)])),
            _ => Ok(None),
        }
    }

    fn answer(&self, t: &dyn Transport, origin: &str, accepted: &Value, pr: &Value, method: &str, path: &str, body: &[u8])
              -> XResult<Vec<(String, String)>> {
        let s = self.open(t, origin, accepted).map_err(xerr)?;
        if let Some(sess) = self.lock().get_mut(origin) {
            sess.last_error = pr.get("error").and_then(Value::as_str).filter(|e| *e != "payment_required").map(str::to_string);
        }
        // the provider's view of this invoice, when it said
        if let Some(w) = pr.get("work").filter(|w| w.get("invoice").and_then(Value::as_str) == Some(s.invoice_id())) {
            if let Some(sp) = w.get("spentWork").and_then(|v| py_u64(Some(v))) {
                if let Some(sess) = self.lock().get_mut(origin) {
                    sess.spent = sess.spent.max(sp);
                    // the provider's own count: every call sent before this refusal is settled in it
                    sess.unanswered.clear();
                }
            }
        }
        // §13.1: the provider holds receipted work beyond its caps on unaudited credit (or while the
        // Prime owes it carry) until audited coinbases have paid for it. Paying again now cannot succeed.
        if let Some(code) = pr.get("error").and_then(Value::as_str).filter(|c| matches!(*c, "credit_cap" | "carry_cap" | "carry_growing")) {
            let held = pr.pointer("/work/heldWork").and_then(|v| py_u64(Some(v))).unwrap_or(0);
            return Err(ChannelError::new(code, format!("the provider holds {held} receipted work units uncredited until audited pool \
                                                        blocks have paid for its open credit ({code}); retry later")));
        }
        let best = self.refresh(t, origin).map_err(xerr)?;
        let s = self.session(origin).expect("session");
        if best.as_ref().map(|b| b.receipt.cum_work).unwrap_or(0).saturating_sub(s.spent) < s.amount() {
            return Err(ChannelError::new("insufficient_work", format!("receipted {} work units, {} spent, a call costs {}: mine as {}",
                                                                       s.credited(), s.spent, s.amount(), s.username("<worker>"))));
        }
        Ok(vec![("PAYMENT-SIGNATURE".into(), self.header(origin, method, path, body).map_err(xerr)?)])
    }

    fn check(&self, origin: &str, resp: &Value, method: &str, path: &str, body: &[u8]) -> XResult<()> {
        self.check_response(origin, resp, method, path, body).map_err(xerr)
    }
}
