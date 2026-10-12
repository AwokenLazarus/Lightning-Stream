//! Stream tickets, the wallet pays a seller over HTTP (`docs/TICKETS.md` sections 1 to 4 and 11):
//! `xbt402_pay` chooses the rail, and for a ticket entry the signer itself fetches the seller's
//! terms, opens a session, locks a pool, releases a ticket when the balance with that seller runs
//! out, reads the answer as it arrives, checks every receipt, refills and stops.
//!
//! The book ([`crate::ticket`], [`crate::ticket_rail`]) decides what may be locked and released and
//! books it; [`crate::ticket_http`] reads the seller's messages. This module is the IO between
//! them, and holds no rule about money of its own beyond the order of its steps.
//!
//! **Each rule, and every place that could break it:**
//!
//! | Rule | Where it is kept |
//! |---|---|
//! | No request leaves for a host the owner did not allow. | [`Signer::xbt402_pay`]: the URL is read once ([`xbt402::wire::sendable_url`]), and its origin is on the allowlist, or the call names a task that pays any seller, before the first byte is sent. Every later URL of the session is that origin plus a path ([`xbt402::wire::seller_url`]). |
//! | Who the seller is comes from the signer's own reading. | The terms are the `accepts` entry of the 402 the signer itself fetched from that origin; the caller passes a URL and nothing else. |
//! | A secret leaves only for a ticket the seller has shown locked, one at a time. | [`Signer::ticket_release_one`]: the seller's signed `status` lists the ticket `ACCEPTED` before the book releases it; the session's `paying` lock is held until the seller's signed answer to that secret has been read. |
//! | A secret that has left is spent, whatever comes back. | The book booked it before it existed here ([`Signer::ticket_release_locked`]); this module never asks for it again. It keeps the secret in memory only to send the same one again, never another. |
//! | Nothing a seller says is booked. | The ledger rows are the book's. A seller's totals only move the wallet's count of the balance, and only where [`crate::ticket_http::Account::absorb`] finds them inside the wallet's own. |
//! | A ticket is released for an answer only when the balance does not cover its next piece. | [`Stream::due_bytes`] and [`Stream::due_time`], on the bytes and seconds this module counted itself. |
//! | A call uses at most `max_sats`, by the wallet's own count, and ends within the owner's `max_answer_s`. | [`Signer::ticket_request`] refuses a head price above it; [`Stream::over`] cuts the body where its price reaches it or its time is up. |
//!
//! Locks: a session's `busy` (one paid request at a time), then `paying` (one secret at a time),
//! then `link` (one HTTP exchange at a time, in `seq` order), then `money`. The wallet's spend lock
//! is taken with none of `link` and `money` held, and never while a seller is being waited for.
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use xbt402::wire::{b64json, payment_payload, request_digest_v2, safe_code, seller_url, sendable_url, unb64json};
use zeroize::Zeroizing;

use crate::ln::LnPolicy;
use crate::policy::normalize_dest;
use crate::pyjson::{py_int, str_or_empty};
use crate::sanitize::{untrusted, UNTRUSTED_KEY};
use crate::session::{body_cap, origin_of};
use crate::signer::{deny, with, Signer};
use crate::ticket::{sats_ceil, Admit, SState, SellerSession, TicketPolicy};
use crate::ticket_http::{offers, Account, Due, Offer, PayTerms, Price, Receipt};
use crate::{err, Result};

/// The most of a session endpoint's answer that is read.
const SMALL_BODY: u64 = 1 << 20;
/// How long the wallet looks for the last receipt of an answer that was sent as it arrived.
const FINAL_WAIT: Duration = Duration::from_secs(2);
/// How long a stop waits for the wallet's own node to show the cancelled tickets failed.
pub const CANCEL_WAIT: Duration = Duration::from_secs(5);
/// Refusals of `ticket_open` that mean "not this rail": the next entry of the 402 is tried.
const NEXT_RAIL: [&str; 9] = ["ticket_disabled", "ln_disabled", "ticket_task", "ticket_admission", "ticket_terms", "ticket_feature_512", "ticket_network",
                              "ticket_size", "ticket_blocks"];

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn refusal(rule: &str, reason: impl Into<String>) -> Value {
    with(deny(rule, reason), json!({"rail": "ticket", "charged_sats": 0}))
}

// --- HTTP as this module needs it ---------------------------------------------------------------------

/// The head of an answer, and its body still to be read.
pub struct WireAnswer {
    pub status: u16,
    /// Header names in upper case.
    pub headers: Vec<(String, String)>,
    /// `Content-Length`, when the answer states one.
    pub length: Option<u64>,
    /// The body as it arrives. A body cut short ends in an error or before `length`.
    pub body: Box<dyn Read + Send>,
}

impl WireAnswer {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// The whole body when it is at most `cap` bytes. `Err`: longer, or cut short.
    fn read_small(self, cap: u64) -> Result<Vec<u8>> {
        let mut out = vec![];
        self.body.take(cap + 1).read_to_end(&mut out).map_err(|e| err("transport_error", e.to_string()))?;
        if out.len() as u64 > cap {
            return Err(err("response_too_large", format!("an answer above {cap} bytes where a short one was expected")));
        }
        if self.length.is_some_and(|n| n != out.len() as u64) {
            return Err(err("response_truncated", "the answer was cut short"));
        }
        Ok(out)
    }
}

/// How the ticket payer talks HTTP: one request, answered as soon as its head has arrived, the
/// body left to be read. No redirect is followed.
pub trait TicketWire: Send + Sync {
    fn send(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)], read_timeout: Duration) -> Result<WireAnswer>;
}

/// [`TicketWire`] over ureq. No overall deadline (an answer may be long); a connect, a read and a
/// write each have one.
#[derive(Default)]
pub struct UreqWire {
    agents: Mutex<HashMap<u64, ureq::Agent>>,
}

impl TicketWire for UreqWire {
    fn send(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)], read_timeout: Duration) -> Result<WireAnswer> {
        // ureq parses the string again, so it is given only what `request_url` read
        let url = sendable_url(url)?;
        let secs = read_timeout.as_secs().clamp(1, 3600);
        let agent = lock(&self.agents).entry(secs).or_insert_with(|| {
            ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(10)).timeout_read(Duration::from_secs(secs)).timeout_write(Duration::from_secs(secs))
                .redirects(0).build()
        }).clone();
        let mut req = agent.request(method, &url).set("Accept-Encoding", "identity");
        for (k, v) in headers {
            req = req.set(k, v);
        }
        let resp = match if body.is_empty() && matches!(method, "GET" | "HEAD") { req.call() } else { req.send_bytes(body) } {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(err("transport_error", e.to_string())),
        };
        let status = resp.status();
        let headers: Vec<(String, String)> = resp.headers_names().into_iter().filter_map(|n| resp.header(&n).map(|v| (n.to_ascii_uppercase(), v.to_string()))).collect();
        let bodiless = method.eq_ignore_ascii_case("HEAD") || matches!(status, 100..=199 | 204 | 304);
        let length = if bodiless { Some(0) } else { resp.header("Content-Length").and_then(|s| s.parse::<u64>().ok()) };
        let body: Box<dyn Read + Send> = if bodiless { Box::new(std::io::empty()) } else { Box::new(resp.into_reader()) };
        Ok(WireAnswer { status, headers, length, body })
    }
}

// --- where an answer's body goes ----------------------------------------------------------------------

/// The body of an answer as it arrives: counted, hashed, its first bytes kept for the agent, and
/// all of it written to `B2_BODY_DIR` when that is set and the body is longer than the preview.
struct Sink {
    hash: Sha256,
    bytes: u64,
    preview: Vec<u8>,
    cap: usize,
    file: Option<(std::fs::File, PathBuf)>,
    file_error: Option<String>,
}

impl Sink {
    fn new() -> Self {
        Self { hash: Sha256::new(), bytes: 0, preview: vec![], cap: body_cap(), file: None, file_error: None }
    }

    fn put(&mut self, chunk: &[u8]) {
        use std::io::Write;
        self.hash.update(chunk);
        self.bytes += chunk.len() as u64;
        let room = self.cap.saturating_sub(self.preview.len());
        let over = chunk.len() > room;
        if over && self.file.is_none() && self.file_error.is_none() {
            if let Ok(dir) = std::env::var("B2_BODY_DIR") {
                let path = PathBuf::from(dir).join(format!("ticket-{}.bin", crate::policy::token_urlsafe()));
                let made = std::fs::create_dir_all(path.parent().unwrap_or(std::path::Path::new("."))).and_then(|()| std::fs::File::create(&path))
                    .and_then(|mut f| f.write_all(&self.preview).map(|()| f));
                match made {
                    Ok(f) => self.file = Some((f, path)),
                    Err(e) => self.file_error = Some(e.to_string()),
                }
            }
        }
        if let Some((f, _)) = &mut self.file {
            if let Err(e) = f.write_all(chunk) {
                self.file_error = Some(e.to_string());
                self.file = None;
            }
        }
        self.preview.extend_from_slice(&chunk[..chunk.len().min(room)]);
    }

    /// `(digest, fields for the reply, the preview as text)`.
    fn done(self) -> (String, Value, String) {
        let digest = hex::encode(self.hash.finalize());
        let mut v = json!({"bytes": self.bytes, "body_digest": digest});
        if let Some((_, path)) = &self.file {
            v["saved_to"] = path.to_string_lossy().into();
        }
        if let Some(e) = &self.file_error {
            v["save_error"] = e.clone().into();
        }
        (digest, v, String::from_utf8_lossy(&self.preview).into_owned())
    }
}

// --- a session with one seller ------------------------------------------------------------------------

/// The seller's side of the session: what authenticates a request and orders it.
struct Link {
    /// Empty until the seller's first lock answer.
    seller_sid: String,
    key: Zeroizing<[u8; 32]>,
    next_seq: u64,
}

#[derive(Default)]
struct Money {
    acct: Account,
    /// Tickets the seller's own signed `status` has shown `ACCEPTED`.
    ready: HashSet<String>,
    /// A secret that has left the book and that the seller has not confirmed taking: sent again,
    /// the same one, until it has. `(hash, secret)`.
    pending: Option<(String, Zeroizing<String>)>,
    /// Why this session releases nothing more.
    fault: Option<String>,
}

/// A ticket session the wallet pays over HTTP. In memory only: a signer that starts again stops
/// every session (the book's rule) and has the seller's id and key on disk for the cancel.
pub(crate) struct HttpSession {
    pub origin: String,
    /// The book's session, and the owner's task it was opened under.
    pub sid: String,
    task: String,
    pub terms: PayTerms,
    /// The URL of the session endpoints: the origin and the terms' path.
    base: String,
    busy: Mutex<()>,
    paying: Mutex<()>,
    link: Mutex<Link>,
    money: Mutex<Money>,
    /// An answer priced as it goes is open: the seller's `spentMsat` moves between receipts.
    streaming: AtomicBool,
    refilling: AtomicBool,
    /// The wallet's clock at the last paid request.
    used: Mutex<f64>,
    /// Why the last attempt to fill the pool locked nothing: what a release that finds the pool
    /// empty reports.
    unfilled: Mutex<Option<Value>>,
}

impl HttpSession {
    fn fault(&self) -> Option<String> {
        lock(&self.money).fault.clone()
    }

    fn balance(&self) -> u64 {
        lock(&self.money).acct.balance()
    }

    /// What the seller's signed receipts say was released in this session, as far as the wallet
    /// took them.
    fn credited(&self) -> u64 {
        lock(&self.money).acct.acked_msat
    }

    fn public(&self) -> Value {
        let m = lock(&self.money);
        json!({"session": self.sid, "origin": self.origin, "released_msat": m.acct.sent_msat.to_string(), "credited_msat": m.acct.acked_msat.to_string(),
               "spent_msat": m.acct.spent_msat.to_string(), "balance_msat": m.acct.balance().to_string(), "unconfirmed_release": m.pending.as_ref().map(|p| p.0.clone()),
               "fault": m.fault, "answer_open": self.streaming.load(Ordering::SeqCst)})
    }
}

/// One seller's place in the signer: at most one session, opened by one call at a time.
#[derive(Default)]
pub(crate) struct Slot {
    open: Mutex<Option<Arc<HttpSession>>>,
}

/// What trying one rail came to.
enum Tried {
    Done(Value),
    /// Not this rail, and why: the next entry of the 402 is tried.
    Next(String),
}

/// One `xbt402_pay` call, as the ticket rail sees it.
struct Call<'a> {
    url: &'a str,
    origin: &'a str,
    method: &'a str,
    body: &'a [u8],
    max_sats: i64,
    task: std::result::Result<String, String>,
}

/// What one call released: the hashes, and the sats the book put in the ledger for them.
#[derive(Default)]
struct Spent {
    hashes: Vec<String>,
    booked_sats: i64,
}

/// The pacing of one answer that is priced as it goes: when the next ticket is due.
struct Stream {
    price: Price,
    /// The seller's `spentMsat` before this request.
    base_spent: u64,
    /// Before the request was sent, so that the seconds counted here are never fewer than the seller's.
    started: Instant,
    max_msat: u64,
    /// The longest the answer stays open (the owner's `tickets.max_answer_s`).
    max_open: Duration,
}

impl Stream {
    /// Why the wallet reads no further, if it does not: the call's `max_sats` is used up by its
    /// own count, or the answer has been open for as long as the owner allows.
    fn over(&self, bytes: u64) -> Option<String> {
        // a body with a price of its own only: one paid for at its head costs nothing more however long it is
        if self.price.metered() && self.cost(bytes) >= self.max_msat {
            return Some("max_sats: the call's limit is used up".into());
        }
        (self.started.elapsed() >= self.max_open).then(|| format!("max_answer_s: the answer has been open for {} s", self.max_open.as_secs()))
    }

    /// Seconds of the answer that have started, by this clock.
    fn seconds(&self) -> u64 {
        if self.price.second_msat == 0 { 0 } else { self.started.elapsed().as_secs().saturating_add(1) }
    }

    /// What the request has cost with `bytes` of its body here: the terms' rule on this module's
    /// own counts. A price that does not fit is the largest, which every cap refuses.
    fn cost(&self, bytes: u64) -> u64 {
        self.price.cost(bytes, self.seconds()).unwrap_or(u64::MAX)
    }

    /// What the tickets released so far leave for this request, in msat (`credited`: all the
    /// seller has credited the session).
    fn avail(&self, credited: u64) -> u64 {
        credited.saturating_sub(self.base_spent)
    }

    /// What does not depend on the body's size: the request and the seconds started.
    fn fixed(&self) -> u64 {
        self.price.request_msat.saturating_add(self.price.for_seconds(self.seconds()).unwrap_or(u64::MAX))
    }

    /// A body priced by its size: everything the released tickets pay for has arrived, so the
    /// balance does not cover one more byte.
    fn due_bytes(&self, credited: u64, bytes: u64) -> bool {
        self.price.byte_msat > 0 && bytes >= self.price.bytes_for(self.avail(credited).saturating_sub(self.fixed()))
    }

    /// A body priced by the second: the balance does not cover the second that starts next.
    fn due_time(&self, credited: u64) -> bool {
        self.price.second_msat > 0 && self.avail(credited) < self.fixed().saturating_add(self.price.second_msat)
    }
}

impl Signer {
    fn ticket_net(&self) -> Result<String> {
        Ok(crate::node::network(&*self.node, &self.chain, None)?.replacen("bip122:", "lightning:", 1))
    }

    fn ticket_read_timeout(tp: &TicketPolicy) -> Duration {
        Duration::from_secs(tp.read_timeout_s.clamp(1, 3600) as u64)
    }

    /// The task a call is paid under: the one it names, or the owner's only task, or the one named
    /// `default`. `Err`: what the caller must say.
    fn ticket_task_for(tp: &TicketPolicy, named: &str) -> std::result::Result<String, String> {
        if !named.is_empty() {
            return if tp.tasks.contains_key(named) { Ok(named.into()) } else { Err(format!("the owner's policy names no task {named:?} (tickets.tasks)")) };
        }
        match tp.tasks.len() {
            0 => Err("the owner's policy names no task (tickets.tasks): tickets are paid only under a task with a budget".into()),
            1 => Ok(tp.tasks.keys().next().cloned().unwrap_or_default()),
            _ if tp.tasks.contains_key("default") => Ok("default".into()),
            _ => Err(format!("the owner's policy has {} tasks and none is named \"default\": pass task", tp.tasks.len())),
        }
    }

    /// Whether the owner's policy, as it is now, lets a request leave for `origin` under `task`: the
    /// origin is on the allowlist, or the task pays any seller. Asked before every request this
    /// module sends: the first of a call, and each one of a session after it, so that a seller the
    /// owner has since taken off the list is not sent another byte.
    fn ticket_may_reach(&self, origin: &str, task: &str) -> bool {
        self.engine.allowlist().iter().any(|a| a == origin) || self.ticket_policy().tasks.get(task).is_some_and(|t| t.admit == Admit::Any)
    }

    // --- the entry: one function chooses the rail ---------------------------------------------------

    /// `xbt402_pay`. With stream tickets off in the owner's policy this is the frozen channel
    /// path, unchanged. With them on, the signer asks the seller once without paying, and pays by
    /// the first of these the 402 offers and the policy allows:
    ///
    /// 1. a ticket entry (`scheme: "ticket"` on this Lightning network);
    /// 2. a single Lightning payment (`scheme: "exact"` with a BOLT 11 invoice), as `ln_pay` pays one;
    /// 3. the on-chain channel entry, unless the owner turned it off (`channel_rail: false`);
    ///
    /// and otherwise reports what each entry would have needed. A rail is passed over only for a
    /// reason that makes it unusable for this seller (off, not admitted, terms outside the owner's
    /// bounds); a budget or a cap that is used up refuses the call and tries no other rail.
    pub(crate) fn xbt402_pay(&self, p: &Value) -> Value {
        let tp = self.ticket_policy();
        let cfg = self.config();
        let max_sats = match p.get("max_sats").filter(|v| !v.is_null()) {
            None => Some(0),
            Some(v) => py_int(Some(v)),
        };
        let url = sendable_url(&str_or_empty(p.get("url"))).ok();
        let origin = url.as_deref().and_then(|u| origin_of(u).ok()).map(|o| normalize_dest(&o)).filter(|o| !o.is_empty());
        // tickets off, a free-only call (max_sats 0) or arguments the channel path refuses: its own answer, as before
        let (Some(max_sats), Some(url), Some(origin)) = (max_sats.filter(|m| *m > 0 && tp.enabled), url, origin) else {
            return self.xbt402_pay_channel(p, &cfg);
        };
        let method = Some(str_or_empty(p.get("method")).to_uppercase()).filter(|m| !m.is_empty()).unwrap_or_else(|| "GET".into());
        let raw: Vec<u8> = match p.get("body") {
            Some(Value::String(s)) => s.clone().into_bytes(),
            Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_u64().map(|b| b as u8)).collect(),
            _ => vec![],
        };
        let task = Self::ticket_task_for(&tp, &str_or_empty(p.get("task")));
        // the owner's word before any request leaves: an allowlisted origin, or a task that pays any seller
        let listed = self.engine.allowlist().contains(&origin);
        if !self.ticket_may_reach(&origin, task.as_deref().unwrap_or("")) {
            return deny("allowlist", format!("destination not on allowlist: {origin} (and the call names no task that pays any seller)"));
        }
        let (lightning, chain) = match (self.ticket_net(), self.session.network()) {
            (Ok(l), Ok(c)) => (l, c),
            (Err(e), _) | (_, Err(e)) => return deny("xbt402", e.msg),
        };
        let probe = match self.ticket_wire.send(&method, &url, &raw, &[], Self::ticket_read_timeout(&tp)) {
            Ok(a) => a,
            Err(e) => return deny("xbt402", format!("the seller gave no answer: {}", e.msg)),
        };
        if probe.status != 402 {
            let status = probe.status;
            let mut sink = Sink::new();
            let ended = read_all(probe, &mut sink);
            let (_, stored, text) = sink.done();
            return with(with(json!({"verdict": "allow", "rule": "free", "rail": "none", "status": status, "charged_sats": 0, "note": "no 402 (already free or error)",
                                    "complete": ended.is_none(), UNTRUSTED_KEY: untrusted(&text, Value::Null)}), stored),
                        json!({"ended": ended}));
        }
        let Some(pr) = probe.header("PAYMENT-REQUIRED").and_then(|h| unb64json(h).ok()) else {
            return deny("xbt402", "402 without a readable PAYMENT-REQUIRED");
        };
        drop(probe);
        let call = Call { url: &url, origin: &origin, method: &method, body: &raw, max_sats, task };
        let mut passed: Vec<Value> = vec![];
        for offer in offers(&pr, &lightning, &chain) {
            let rail = offer.rail();
            let tried = match &offer {
                Offer::Ticket(acc) => self.ticket_pay(&call, acc, &lightning),
                Offer::Lightning(_) if !listed => Tried::Next("the seller is not on the owner's allowlist: only a ticket task that pays any seller reaches it".into()),
                Offer::Lightning(acc) => self.ln_exact_pay(&call, acc, &tp),
                Offer::Channel(_) if !listed => Tried::Next("the seller is not on the owner's allowlist: only a ticket task that pays any seller reaches it".into()),
                Offer::Channel(_) if !cfg.channel_rail => Tried::Next("the owner's policy has turned the on-chain channel off (channel_rail)".into()),
                Offer::Channel(_) => Tried::Done(self.xbt402_pay_channel(p, &cfg)),
            };
            match tried {
                Tried::Done(mut v) => {
                    if !passed.is_empty() {
                        v["rails_passed_over"] = json!(passed);
                    }
                    return v;
                }
                Tried::Next(why) => passed.push(json!({"rail": rail, "why": why})),
            }
        }
        let offered: Vec<Value> = pr.get("accepts").and_then(Value::as_array).into_iter().flatten()
            .map(|a| json!({"scheme": str_or_empty(a.get("scheme")).chars().take(40).collect::<String>(),
                            "network": str_or_empty(a.get("network")).chars().take(80).collect::<String>()})).take(16).collect();
        with(deny("no_rail", "the seller's 402 offers no way to pay that this wallet's policy allows: see rails_passed_over for what each entry needs"),
             json!({"charged_sats": 0, "rails_passed_over": passed, "offered": offered,
                    "wallet": {"lightning": lightning, "chain": chain, "tickets": tp.enabled, "ln": LnPolicy::from_map(&cfg.ln).enabled, "channel_rail": cfg.channel_rail}}))
    }

    /// The frozen on-chain channel path of `xbt402_pay`, under the wallet's spend lock as before.
    fn xbt402_pay_channel(&self, p: &Value, cfg: &crate::policy::PolicyConfig) -> Value {
        if !cfg.channel_rail {
            return deny("channel_rail", "the owner's policy has turned the on-chain channel off (channel_rail): xbt402_pay funds no channel and signs no state");
        }
        let _g = self.lock();
        self.xbt402_pay_locked(p)
    }

    /// A single Lightning payment the seller's 402 asks for: `extra.invoice`, paid as `ln_pay` pays
    /// an invoice (every rule of the Lightning rail), then the request again with the preimage.
    fn ln_exact_pay(&self, c: &Call, acc: &Value, tp: &TicketPolicy) -> Tried {
        if !LnPolicy::from_map(&self.config().ln).enabled {
            return Tried::Next("the Lightning rail is off in this policy (ln.enabled)".into());
        }
        let invoice = str_or_empty(acc.get("extra").and_then(|x| x.get("invoice")));
        let inv = match crate::bolt11::decode(invoice.trim()) {
            Ok(i) => i,
            Err(e) => return Tried::Next(format!("the entry's invoice is not a BOLT 11 invoice: {e}")),
        };
        // the entry and its invoice are one offer said twice: where they differ, neither is paid
        if inv.payee_hex() != str_or_empty(acc.get("payTo")) || inv.amount_msat.is_none() || inv.amount_msat != crate::ticket::outside_u64(acc.get("amount")) {
            return Tried::Next("the entry's invoice does not pay its payTo its amount".into());
        }
        let paid = {
            let _g = self.lock();
            self.ln_pay_locked(&json!({"invoice": invoice.trim(), "max_sats": c.max_sats}))
        };
        if paid["verdict"] != "allow" {
            return match str_or_empty(paid.get("rule")).as_str() {
                "allowlist" | "ln_disabled" | "ln_feature_512" | "ln_chain" => Tried::Next(str_or_empty(paid.get("reason"))),
                _ => Tried::Done(paid),
            };
        }
        let header = b64json(&payment_payload(acc, &json!({"preimage": paid["preimage"]})));
        let mut out = with(json!({"verdict": "allow", "rule": "ok", "rail": "ln"}),
                           json!({"charged_sats": paid["charged_sats"], "payment_hash": paid["payment_hash"], "dest": paid["dest"], "fee_msat": paid["fee_msat"]}));
        match self.ticket_wire.send(c.method, c.url, c.body, &[("PAYMENT-SIGNATURE".into(), header)], Self::ticket_read_timeout(tp)) {
            Ok(ans) => {
                out["status"] = ans.status.into();
                let mut sink = Sink::new();
                let ended = read_all(ans, &mut sink);
                let (_, stored, text) = sink.done();
                out = with(with(out, stored), json!({"complete": ended.is_none(), "ended": ended, UNTRUSTED_KEY: untrusted(&text, Value::Null)}));
            }
            // paid, and booked by the Lightning rail: said plainly
            Err(e) => out = with(out, json!({"status": null, "note": format!("the invoice was paid and the seller then gave no answer: {}", e.msg)})),
        }
        Tried::Done(out)
    }

    // --- the ticket rail ----------------------------------------------------------------------------

    /// Pay one request with tickets: read the entry, find or open the session with this seller,
    /// send the request.
    fn ticket_pay(&self, c: &Call, acc: &Value, lightning: &str) -> Tried {
        let terms = match PayTerms::parse(acc, lightning) {
            Ok(t) => t,
            Err((rule, why)) => return Tried::Next(format!("{rule}: {why}")),
        };
        if terms.release != "with-request" {
            return Tried::Next("the entry releases after-verify, which this wallet does not do: it releases a ticket before the piece it pays for".into());
        }
        let base = match seller_url(c.origin, &terms.session_path) {
            Ok(b) => b,
            Err(e) => return Tried::Next(e.msg),
        };
        // the session key comes back in the first lock answer: on a plain connection a listener has it, and with it the balance
        if !private_channel(c.origin) {
            return Tried::Next("tickets are paid over https, or over http to this machine only (127.0.0.1, ::1, localhost): on a plain connection a \
                                listener learns the session key".into());
        }
        let slot = lock(&self.ticket_http).entry(c.origin.to_string()).or_default().clone();
        // the session with this seller, or why there is none
        let found: std::result::Result<Arc<HttpSession>, Tried> = 'open: {
            let mut open = lock(&slot.open);
            // this place may have been forgotten while this call waited for it (its last session ended): it is put back,
            // unless another call has made a new one meanwhile
            {
                let mut map = lock(&self.ticket_http);
                match map.get(c.origin) {
                    Some(s) if Arc::ptr_eq(s, &slot) => {}
                    Some(_) => break 'open Err(Tried::Done(refusal("ticket_busy", "another call is opening a session with this seller: call again"))),
                    None => {
                        map.insert(c.origin.to_string(), slot.clone());
                    }
                }
            }
            // a session the book no longer holds open (stopped by the agent, idle, a fault) is gone
            if let Some(h) = open.as_ref().filter(|h| h.fault().is_some() || !self.ticket_session(&h.sid).is_some_and(|s| s.state == SState::Open)).cloned() {
                *open = None;
                self.ticket_http_stop(&h, "its session ended", Duration::ZERO);
            }
            match open.as_ref() {
                Some(h) if !h.terms.same_seller(&terms) => {
                    let h = h.clone();
                    *open = None;
                    let stopped = self.ticket_http_stop(&h, "the seller's terms changed", Duration::ZERO);
                    break 'open Err(Tried::Done(with(refusal("ticket_terms_changed", "the seller's 402 now names another node, receipt key, ticket or session path than the \
                                                                              session was opened on: the session was stopped and nothing was paid; call again to \
                                                                              pay on the new terms, if the owner's policy allows them"), json!({"stopped": stopped}))));
                }
                Some(h) => Ok(h.clone()),
                None => {
                    let task = match &c.task {
                        Ok(t) => t.clone(),
                        Err(why) => break 'open Err(Tried::Next(why.clone())),
                    };
                    let o = {
                        let _g = self.lock();
                        self.ticket_open_locked(&json!({"terms": acc, "task": &task, "origin": c.origin}))
                    };
                    if o["verdict"] != "allow" {
                        let rule = str_or_empty(o.get("rule"));
                        break 'open Err(if NEXT_RAIL.contains(&rule.as_str()) { Tried::Next(format!("{rule}: {}", str_or_empty(o.get("reason")))) } else { Tried::Done(o) });
                    }
                    let h = Arc::new(HttpSession { origin: c.origin.into(), sid: str_or_empty(o.get("session")), task: task.clone(), terms: terms.clone(), base, busy: Mutex::new(()),
                                                   paying: Mutex::new(()), link: Mutex::new(Link { seller_sid: String::new(), key: Zeroizing::new([0u8; 32]), next_seq: 0 }),
                                                   money: Mutex::new(Money::default()), streaming: AtomicBool::new(false), refilling: AtomicBool::new(false),
                                                   used: Mutex::new(self.engine.now()), unfilled: Mutex::new(None) });
                    // the first pool, before the call goes on
                    match self.ticket_fill(&h) {
                        Ok(n) if n > 0 => {}
                        Ok(_) => {
                            let stopped = self.ticket_http_stop(&h, "no ticket could be locked", Duration::ZERO);
                            break 'open Err(Tried::Done(with(refusal("ticket_lock", "no ticket was locked with this seller: its invoices did not pass the wallet's checks, or the \
                                                                             node found no route"), json!({"stopped": stopped}))));
                        }
                        Err(d) => {
                            let stopped = self.ticket_http_stop(&h, "the first lock failed", Duration::ZERO);
                            break 'open Err(Tried::Done(with(d, json!({"stopped": stopped}))));
                        }
                    }
                    *open = Some(h.clone());
                    Ok(h)
                }
            }
        };
        let hs = match found {
            Ok(hs) => hs,
            Err(tried) => {
                if lock(&self.ticket_http).get(c.origin).is_some_and(|s| Arc::ptr_eq(s, &slot)) {
                    self.ticket_slot_drop(c.origin);
                }
                return tried;
            }
        };
        let out = {
            let _busy = lock(&hs.busy);
            self.ticket_request(&hs, c, &terms.price)
        };
        // the pool is filled again behind the call
        self.ticket_refill_later(&hs);
        Tried::Done(out)
    }

    /// The first lock of a session, or a refill: ask the book which hashes the pool wants, the
    /// seller for their invoices, and the book to check and pay them. `Ok`: tickets locked.
    fn ticket_fill(&self, hs: &HttpSession) -> std::result::Result<usize, Value> {
        let out = self.ticket_fill_once(hs);
        if let Err(d) = &out {
            *lock(&hs.unfilled) = Some(d.clone());
        }
        out
    }

    fn ticket_fill_once(&self, hs: &HttpSession) -> std::result::Result<usize, Value> {
        // the wallet's own node first: no hash goes to a seller that the node could not then pay for
        self.ticket_can_lock(&hs.terms.terms.payee)?;
        let offer = {
            let _g = self.lock();
            self.ticket_offer_locked(&json!({"session": hs.sid}))
        };
        if offer["verdict"] != "allow" {
            return Err(offer);
        }
        let hashes: Vec<Value> = offer["hashes"].as_array().cloned().unwrap_or_default();
        if hashes.is_empty() {
            return Ok(0);
        }
        let mut body = json!({"version": xbt402::ticket::VERSION, "hashes": hashes});
        // a size of the wallet's choosing is asked for only where the terms let it choose
        let size = self.ticket_session(&hs.sid).map(|s| s.ticket_msat).unwrap_or(hs.terms.terms.ticket_msat);
        if hs.terms.terms.min_ticket_msat.is_some() && size != hs.terms.terms.ticket_msat {
            body["ticketMsat"] = size.to_string().into();
        }
        if !self.ticket_may_reach(&hs.origin, &hs.task) {
            return Err(deny("allowlist", format!("destination not on allowlist: {}", hs.origin)));
        }
        let first = lock(&hs.link).seller_sid.is_empty();
        let answer = if first {
            let url = format!("{}/lock", hs.base);
            let raw = body.to_string().into_bytes();
            let sent = self.ticket_wire.send("POST", &url, &raw, &[("Content-Type".into(), "application/json".into())], Self::ticket_read_timeout(&self.ticket_policy()));
            let (status, v) = match sent.and_then(|a| Ok((a.status, a.read_small(SMALL_BODY)?))) {
                Ok((status, raw)) => (status, serde_json::from_slice::<Value>(&raw).unwrap_or(Value::Null)),
                Err(e) => return Err(refusal("ticket_seller", format!("the seller gave no answer to the first lock: {}", e.msg))),
            };
            if status != 200 {
                let code = Some(str_or_empty(v.get("error"))).filter(|c| safe_code(c)).unwrap_or_default();
                return Err(refusal("ticket_seller", format!("the seller refused the first lock: HTTP {status} {code}")));
            }
            let (seller_sid, key) = (str_or_empty(v.get("session")), str_or_empty(v.get("key")));
            let key: Option<[u8; 32]> = xbt402::ticket::hex32(&key);
            let (true, Some(key)) = (seller_sid.len() == 32 && seller_sid.bytes().all(|c| c.is_ascii_hexdigit()), key) else {
                return Err(refusal("ticket_seller", "the seller's first lock answer names no session id and key"));
            };
            // on disk before anything is paid: a wallet that starts again can still ask for the cancel
            if let Err(e) = self.ticket_set_http(&hs.sid, SellerSession { id: seller_sid.clone(), key, base: hs.base.clone() }) {
                return Err(refusal("ticket", e.msg));
            }
            let mut link = lock(&hs.link);
            link.seller_sid = seller_sid;
            link.key = Zeroizing::new(key);
            v
        } else {
            body["session"] = lock(&hs.link).seller_sid.clone().into();
            match self.ticket_call(hs, "lock", &body, true) {
                Ok((200, v, _)) => v,
                Ok((status, v, _)) => {
                    let code = Some(str_or_empty(v.get("error"))).filter(|c| safe_code(c)).unwrap_or_default();
                    return Err(refusal("ticket_seller", format!("the seller refused the lock: HTTP {status} {code}")));
                }
                Err(e) => return Err(refusal("ticket_seller", format!("the seller gave no answer to the lock: {}", e.msg))),
            }
        };
        // the invoices are the seller's word: every check of them is the book's (`ticket_lock`)
        let tickets: Vec<Value> = answer.get("tickets").and_then(Value::as_array).cloned().unwrap_or_default();
        if tickets.is_empty() {
            return Ok(0);
        }
        let locked = self.ticket_lock(&json!({"session": hs.sid, "tickets": tickets}));
        let n = locked.get("locked").and_then(Value::as_u64).unwrap_or(0) as usize;
        // why the book did not pay one of them: its first refusal, by its own rule. Kept for a release that finds the pool empty
        let why_not = locked.get("refused").and_then(Value::as_array).and_then(|a| a.first()).map(|first| {
            let (rule, why) = (str_or_empty(first.get("rule")), str_or_empty(first.get("reason")));
            with(refusal(if rule.is_empty() { "ticket_lock" } else { rule.as_str() }, format!("a ticket could not be locked with this seller: {why}")),
                 json!({"session": hs.sid, "refused": locked["refused"].as_array().map(Vec::len)}))
        });
        *lock(&hs.unfilled) = why_not.clone();
        if n == 0 {
            if let Some(d) = why_not {
                return Err(d);
            }
            if locked["verdict"] == "deny" && locked.get("rule").is_some_and(|r| r != "ticket_refused") {
                return Err(locked);
            }
        }
        Ok(n)
    }

    /// Fill the pool behind a call, one refill of a session at a time.
    fn ticket_refill_later(&self, hs: &Arc<HttpSession>) {
        let want = self.ticket_store().ok().and_then(|g| g.as_ref().and_then(|st| st.book.sessions.get(&hs.sid).map(|s| st.book.want(s, self.engine.now())))).unwrap_or(0);
        if want == 0 || hs.fault().is_some() || hs.refilling.swap(true, Ordering::SeqCst) {
            return;
        }
        let (Some(me), hs2) = (self.me.get().and_then(std::sync::Weak::upgrade), hs.clone()) else {
            hs.refilling.store(false, Ordering::SeqCst);
            return;
        };
        let spawned = std::thread::Builder::new().name("ticket-refill".into()).spawn(move || {
            // a refusal here is the next release's to report: it finds no ticket and says why
            let _ = me.ticket_fill(&hs2);
            hs2.refilling.store(false, Ordering::SeqCst);
        });
        if spawned.is_err() {
            hs.refilling.store(false, Ordering::SeqCst);
        }
    }

    /// One authenticated request to a session endpoint, in `seq` order. Returns the status, the
    /// JSON body and the receipt (or why there is none). With `absorb`, a valid receipt's totals
    /// are taken into the wallet's count before the next request of the session can be sent.
    fn ticket_call(&self, hs: &HttpSession, what: &str, body: &Value, absorb: bool) -> Result<(u16, Value, std::result::Result<Receipt, String>)> {
        if !self.ticket_may_reach(&hs.origin, &hs.task) {
            return Err(err("allowlist", format!("destination not on allowlist: {}", hs.origin)));
        }
        let url = format!("{}/{what}", hs.base);
        let raw = body.to_string().into_bytes();
        let timeout = Self::ticket_read_timeout(&self.ticket_policy());
        for _ in 0..3 {
            let mut link = lock(&hs.link);
            if link.seller_sid.is_empty() {
                return Err(err("ticket_session", "the session has no seller side yet"));
            }
            let (seq, digest) = (link.next_seq, request_digest_v2("POST", &url, &raw));
            let auth = xbt402::ticket::request_auth(&link.key, &link.seller_sid, seq, "", "", &digest);
            let header = b64json(&payment_payload(&hs.terms.accepted, &json!({"session": link.seller_sid, "seq": seq, "auth": auth})));
            let ans = self.ticket_wire.send("POST", &url, &raw, &[("Content-Type".into(), "application/json".into()), ("PAYMENT-SIGNATURE".into(), header)], timeout)?;
            // the seq is used up once the request has left, answered or not
            link.next_seq = seq.saturating_add(1);
            let (status, payment_response) = (ans.status, ans.header("PAYMENT-RESPONSE").map(str::to_string));
            let v: Value = serde_json::from_slice(&ans.read_small(SMALL_BODY)?).unwrap_or(Value::Null);
            let receipt = Receipt::read(payment_response.as_deref(), &hs.terms.receipt_key, &link.seller_sid, seq, &digest, status);
            if receipt.is_err() && status == 402 && v.get("error").and_then(Value::as_str) == Some("bad_seq") {
                // the seller expects another seq (it lost its last counters, or an answer of ours was lost): adopted,
                // which costs nothing, since a seq only orders requests
                if let Some(n) = v.get("nextSeq").and_then(Value::as_u64) {
                    link.next_seq = n;
                    continue;
                }
            }
            if let (true, Ok(r)) = (absorb, &receipt) {
                let mut m = lock(&hs.money);
                let due = if hs.streaming.load(Ordering::SeqCst) { Due::Balance } else { Due::AtMost(0) };
                let outstanding = m.pending.is_some();
                if let Err(why) = m.acct.absorb(r, 0, due, outstanding) {
                    m.fault.get_or_insert(why);
                }
            }
            return Ok((status, v, receipt));
        }
        Err(err("ticket_seller", "the seller keeps answering bad_seq"))
    }

    /// The seller's signed `status`: its tickets by state into `ready`, and the body.
    fn ticket_status_of(&self, hs: &HttpSession, absorb: bool) -> std::result::Result<Value, String> {
        match self.ticket_call(hs, "status", &json!({}), absorb) {
            Ok((200, v, Ok(_))) => {
                let mut m = lock(&hs.money);
                for t in v.get("tickets").and_then(Value::as_array).into_iter().flatten() {
                    let hash = str_or_empty(t.get("hash"));
                    if t.get("state").and_then(Value::as_str) == Some("ACCEPTED") {
                        m.ready.insert(hash);
                    } else {
                        m.ready.remove(&hash);
                    }
                }
                Ok(v)
            }
            Ok((status, _, Ok(_))) => Err(format!("the seller answered status with HTTP {status}")),
            Ok((status, _, Err(why))) => Err(format!("the seller's answer to status (HTTP {status}) has no valid receipt: {why}")),
            Err(e) => Err(e.msg),
        }
    }

    /// Mark the session faulty and stop it: nothing more is released to this seller in it.
    fn ticket_fault(&self, hs: &HttpSession, why: &str) -> Value {
        lock(&hs.money).fault.get_or_insert_with(|| why.to_string());
        self.ticket_audit("ticket_seller_fault", json!({"session": hs.sid, "origin": hs.origin, "dest": format!("ln:{}", hs.terms.terms.payee), "reason": why}));
        let stopped = self.ticket_http_stop(hs, &format!("seller fault: {why}"), Duration::ZERO);
        with(refusal("ticket_seller_fault", format!("the session with this seller was stopped: {why}")), json!({"session": hs.sid, "stopped": stopped}))
    }

    /// Release one ticket of the session to the seller. In order: the seller's own signed word
    /// that the ticket is locked; the book's release (every rule of the owner, and the spend in
    /// the ledger); the secret to the seller; the seller's signed word that it took it. `Err`: the
    /// refusal, with no secret out unless it says so.
    fn ticket_release_one(&self, hs: &HttpSession, spent: &mut Spent) -> std::result::Result<(), Value> {
        let _paying = lock(&hs.paying);
        if let Some(why) = hs.fault() {
            return Err(self.ticket_fault(hs, &why));
        }
        if !self.ticket_session(&hs.sid).is_some_and(|s| s.state == SState::Open) {
            return Err(refusal("ticket_session", "the session was stopped: nothing more is released for it"));
        }
        // the owner's list as it is now: no ticket is booked for a seller no request may reach any more
        if !self.ticket_may_reach(&hs.origin, &hs.task) {
            return Err(refusal("allowlist", format!("destination not on allowlist: {}", hs.origin)));
        }
        // a secret that has left and was not confirmed goes first, the same one: that is this release
        if lock(&hs.money).pending.is_some() {
            return self.ticket_deliver(hs);
        }
        let tp = self.ticket_policy();
        let mut next = self.ticket_next(&hs.sid).0;
        if next.is_none() {
            // the pool is empty (a refill has not come back, or every ticket is too old): filled here, once
            while hs.refilling.swap(true, Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(20));
            }
            let filled = self.ticket_fill(hs);
            hs.refilling.store(false, Ordering::SeqCst);
            filled?;
            next = self.ticket_next(&hs.sid).0;
        }
        let Some(hash) = next else {
            // the book says why nothing can be released (a stopped session, a task the owner removed, no ticket). It is
            // asked for a ticket that cannot exist, so that it cannot release one a refill locked in this instant.
            // Where the pool is empty because the last fill was refused, that refusal is the reason
            let r = {
                let _g = self.lock();
                self.ticket_release_locked(&json!({"session": hs.sid, "hash": "none"}))
            };
            let unfilled = lock(&hs.unfilled).clone().filter(|_| r["rule"] == "ticket_none");
            return Err(if r["verdict"] == "allow" { refusal("ticket", "the book released a ticket this payer did not ask for") } else { unfilled.unwrap_or(r) });
        };
        // 1. the seller's own word, bounded
        let deadline = Instant::now() + Duration::from_millis(tp.ready_wait_ms.clamp(0, 600_000) as u64);
        let mut wait = Duration::from_millis(10);
        while !lock(&hs.money).ready.contains(&hash) {
            if let Err(why) = self.ticket_status_of(hs, true) {
                return Err(refusal("ticket_seller", format!("{why}: no secret was released")));
            }
            if lock(&hs.money).ready.contains(&hash) {
                break;
            }
            // stopped meanwhile (its tickets are being cancelled, so the seller will never show this one locked)
            if !self.ticket_session(&hs.sid).is_some_and(|s| s.state == SState::Open) {
                return Err(refusal("ticket_session", "the session was stopped: nothing more is released for it"));
            }
            if Instant::now() >= deadline {
                return Err(with(refusal("ticket_not_ready", format!("the seller has not shown the ticket locked on its node within {} ms: no secret was released",
                                                                     tp.ready_wait_ms)), json!({"session": hs.sid, "hash": hash})));
            }
            std::thread::sleep(wait);
            wait = (wait * 2).min(Duration::from_millis(100));
        }
        if let Some(why) = hs.fault() {
            return Err(self.ticket_fault(hs, &why));
        }
        // 2. the book: booked, then the secret exists here
        let r = {
            let _g = self.lock();
            self.ticket_release_locked(&json!({"session": hs.sid, "hash": hash}))
        };
        if r["verdict"] != "allow" {
            return Err(r);
        }
        let Some(secret) = r.get("ticket_secret").and_then(Value::as_str) else { return Err(refusal("ticket", "the book released no secret")) };
        {
            let mut m = lock(&hs.money);
            let ticket_msat = crate::ticket::outside_u64(r.get("ticket_msat")).unwrap_or(0);
            m.acct.released(ticket_msat);
            m.pending = Some((hash.clone(), Zeroizing::new(secret.to_string())));
            m.ready.remove(&hash);
        }
        spent.hashes.push(hash);
        spent.booked_sats = spent.booked_sats.saturating_add(py_int(r.get("charged_sats")).unwrap_or(0));
        // 3. and 4.
        self.ticket_deliver(hs)
    }

    /// Send the secret that has left the book and is not confirmed, and read the seller's signed
    /// answer to it. The same secret is sent again when the seller says its ticket is not locked
    /// yet or gives no answer that can be believed; no other secret is sent meanwhile.
    fn ticket_deliver(&self, hs: &HttpSession) -> std::result::Result<(), Value> {
        let Some((hash, secret)) = lock(&hs.money).pending.as_ref().map(|(h, s)| (h.clone(), s.clone())) else { return Ok(()) };
        let mut wait = Duration::from_millis(50);
        for _ in 0..5 {
            let taken = match self.ticket_call(hs, "release", &json!({"secrets": [secret.as_str()]}), true) {
                Ok((200, v, Ok(_))) => {
                    let has = |k: &str| v.get(k).and_then(Value::as_array).into_iter().flatten().any(|x| x.as_str() == Some(hash.as_str()) || x.get("hash").and_then(Value::as_str) == Some(hash.as_str()));
                    if has("released") {
                        Some(true)
                    } else {
                        let code = v.get("refused").and_then(Value::as_array).into_iter().flatten().find(|x| x.get("hash").and_then(Value::as_str) == Some(hash.as_str()))
                            .map(|x| str_or_empty(x.get("error"))).filter(|c| safe_code(c)).unwrap_or_default();
                        match code.as_str() {
                            // the seller's node does not show it held at this instant: the same secret again
                            "ticket_not_locked" | "node_unavailable" => None,
                            // taken before (an answer of ours was lost): the totals say whether it was credited
                            "ticket_used" => Some(true),
                            _ => {
                                lock(&hs.money).pending = None;
                                return Err(self.ticket_fault(hs, &format!("the seller refused a released ticket ({code}); its secret has left and stays booked until \
                                                                           the wallet's node shows the ticket failed")));
                            }
                        }
                    }
                }
                // no answer that can be believed: the seller's signed status decides
                _ => match self.ticket_status_of(hs, true) {
                    Ok(_) => {
                        let m = lock(&hs.money);
                        (m.acct.acked_msat == m.acct.sent_msat).then_some(true)
                    }
                    Err(why) => return Err(with(refusal("ticket_seller", format!("{why}: one released ticket is unconfirmed; the same secret is sent again by the next call")),
                                                json!({"session": hs.sid, "unconfirmed_release": hash}))),
                },
            };
            if let Some(why) = hs.fault() {
                return Err(self.ticket_fault(hs, &why));
            }
            if taken == Some(true) {
                let mut m = lock(&hs.money);
                m.pending = None;
                if m.acct.acked_msat != m.acct.sent_msat {
                    let why = format!("the wallet released {} msat and the seller credits {}", m.acct.sent_msat, m.acct.acked_msat);
                    drop(m);
                    return Err(self.ticket_fault(hs, &why));
                }
                return Ok(());
            }
            std::thread::sleep(wait);
            wait = (wait * 2).min(Duration::from_millis(400));
        }
        Err(with(refusal("ticket_not_locked", "the seller keeps saying a released ticket is not locked on its node: its secret has left and stays booked; the \
                                               same secret is sent again by the next call"), json!({"session": hs.sid, "unconfirmed_release": hash})))
    }

    /// One paid request of a session: the balance topped up by whole tickets, the request, its
    /// receipt, its body as it arrives.
    fn ticket_request(&self, hs: &Arc<HttpSession>, c: &Call, price: &Price) -> Value {
        let tp = self.ticket_policy();
        let max_msat = (c.max_sats.max(0) as u64).saturating_mul(1000);
        let dest = format!("ln:{}", hs.terms.terms.payee);
        let mut spent = Spent::default();
        let about = |hs: &HttpSession, spent: &Spent| {
            json!({"rail": "ticket", "session": hs.sid, "dest": dest, "origin": hs.origin, "charged_sats": spent.booked_sats, "tickets_released": spent.hashes.len(),
                   "balance_msat": hs.balance().to_string(), "credited_msat": hs.credited().to_string(), "tickets": self.ticket_session_counts(&hs.sid)})
        };
        let fail = |hs: &HttpSession, spent: &Spent, d: Value| with(d, about(hs, spent));
        let Some(reserve) = price.reserve() else { return fail(hs, &spent, refusal("ticket_terms", "the route's price does not fit an amount")) };
        if reserve > max_msat {
            return fail(hs, &spent, deny("max_sats", format!("quoted {} sats > max_sats {}", sats_ceil(reserve), c.max_sats)));
        }
        if let Some(why) = hs.fault() {
            return fail(hs, &spent, self.ticket_fault(hs, &why));
        }
        *lock(&hs.used) = self.engine.now();
        let started = Instant::now();
        let mut short = 0;
        let (seq, digest, ans, head) = loop {
            // whole tickets until the seller's balance covers what it wants before it serves
            let mut rounds = 0;
            while hs.balance() < reserve || lock(&hs.money).pending.is_some() {
                rounds += 1;
                if rounds > 64 {
                    return fail(hs, &spent, refusal("ticket_terms", "the route's price needs more than 64 tickets before it is served"));
                }
                if let Err(d) = self.ticket_release_one(hs, &mut spent) {
                    return fail(hs, &spent, d);
                }
            }
            let mut link = lock(&hs.link);
            let (seq, digest) = (link.next_seq, request_digest_v2(c.method, c.url, c.body));
            let auth = xbt402::ticket::request_auth(&link.key, &link.seller_sid, seq, "", "", &digest);
            let header = b64json(&payment_payload(&hs.terms.accepted, &json!({"session": link.seller_sid, "seq": seq, "auth": auth})));
            let ans = match self.ticket_wire.send(c.method, c.url, c.body, &[("PAYMENT-SIGNATURE".into(), header)], Self::ticket_read_timeout(&tp)) {
                Ok(a) => a,
                // no secret travels with a request, so a lost answer costs what the seller charged the balance, if anything
                Err(e) => {
                    link.next_seq = seq.saturating_add(1);
                    return fail(hs, &spent, with(refusal("ticket_seller", format!("the seller gave no answer to the paid request: {}", e.msg)), json!({"status": null})));
                }
            };
            link.next_seq = seq.saturating_add(1);
            let receipt = Receipt::read(ans.header("PAYMENT-RESPONSE"), &hs.terms.receipt_key, &link.seller_sid, seq, &digest, ans.status);
            let head = match receipt {
                Ok(r) => r,
                Err(why) => {
                    let status = ans.status;
                    let v: Value = ans.read_small(SMALL_BODY).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
                    if status == 402 && v.get("error").and_then(Value::as_str) == Some("bad_seq") && short < 2 {
                        if let Some(n) = v.get("nextSeq").and_then(Value::as_u64) {
                            link.next_seq = n;
                            short += 1;
                            continue;
                        }
                    }
                    drop(link);
                    let code = Some(str_or_empty(v.get("error"))).filter(|c| safe_code(c)).unwrap_or_default();
                    // an answer nobody signed. A server error may be a proxy's; anything else is the seller serving or
                    // refusing without a receipt, or someone answering in its place: the session ends, and nothing was
                    // released on that answer's word
                    if status >= 500 {
                        return fail(hs, &spent, with(refusal("ticket_seller", format!("the seller answered HTTP {status} without a receipt")), json!({"status": status})));
                    }
                    let d = self.ticket_fault(hs, &format!("an answer to a paid request (HTTP {status} {code}) without a valid receipt: {why}"));
                    return fail(hs, &spent, with(d, json!({"status": status})));
                }
            };
            // the receipt's totals, before the next request of the session can be sent
            let metered = head.body_hash.is_empty() && ans.status < 400;
            let (charged_max, due) = match ans.status {
                s if s >= 400 => (0, Due::AtMost(0)),
                _ if metered => (price.request_msat.saturating_add(price.second_msat), Due::Balance),
                _ => (price.request_msat, Due::AtMost(price.request_msat)),
            };
            {
                let mut m = lock(&hs.money);
                if let Err(why) = m.acct.absorb(&head, charged_max, due, false) {
                    m.fault.get_or_insert(why);
                }
                if metered && m.fault.is_none() {
                    hs.streaming.store(true, Ordering::SeqCst);
                }
            }
            drop(link);
            if let Some(why) = hs.fault() {
                return fail(hs, &spent, with(self.ticket_fault(hs, &why), json!({"status": ans.status})));
            }
            if matches!(ans.status, 402 | 503) {
                let status = ans.status;
                let v: Value = ans.read_small(SMALL_BODY).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
                let code = Some(str_or_empty(v.get("error"))).filter(|c| safe_code(c)).unwrap_or_default();
                // signed by the seller: its balance is what it says, and the loop releases one ticket more if that is short
                if code == "balance_short" && short < 2 && hs.balance() < reserve {
                    short += 1;
                    continue;
                }
                return fail(hs, &spent, with(refusal("ticket_refused", format!("the seller refused the paid request: HTTP {status} {code}; nothing was charged for it")),
                                             json!({"status": status, "seller_code": code})));
            }
            break (seq, digest, ans, head);
        };
        let status = ans.status;
        let mut out = json!({"verdict": "allow", "rule": "ok", "status": status});
        let mut sink = Sink::new();
        let (price_msat, receipt_note) = if !hs.streaming.load(Ordering::SeqCst) {
            // a whole answer: paid for at its head, its body hashed against the receipt
            let length = ans.length;
            let ended = read_all(ans, &mut sink);
            let complete = ended.is_none() && length.is_none_or(|n| n == sink.bytes);
            let digest_now = hex::encode(sink.hash.clone().finalize());
            let note = if !complete {
                json!({"signed": true, "body": "cut short"})
            } else if digest_now != head.body_hash {
                let why = "the body is not the one the receipt signs";
                out["seller_fault"] = self.ticket_fault(hs, why)["reason"].clone();
                json!({"signed": true, "body": "differs from the receipt"})
            } else {
                json!({"signed": true, "body": "as signed"})
            };
            out = with(out, json!({"complete": complete, "ended": ended}));
            (head.charged, note)
        } else {
            let (m, note) = self.ticket_stream(hs, price, &head, seq, &digest, ans, started, max_msat, &mut sink, &mut spent);
            out = with(out, m);
            let price_msat = out.get("price_msat").and_then(|v| crate::ticket::outside_u64(Some(v))).unwrap_or(0);
            (price_msat, note)
        };
        let (_, stored, text) = sink.done();
        out = with(with(out, stored), about(hs, &spent));
        out["price_msat"] = price_msat.to_string().into();
        out["receipt"] = receipt_note;
        out["released"] = json!(spent.hashes);
        out["ms"] = json!((started.elapsed().as_secs_f64() * 10_000.0).round() / 10.0);
        out[UNTRUSTED_KEY] = untrusted(&text, head.raw);
        *lock(&hs.used) = self.engine.now();
        out
    }

    /// The body of an answer that is priced as it goes: read as it arrives, a ticket released each
    /// time the balance no longer covers the next piece, and stopped (the connection closed) when
    /// the book refuses a release or the call's `max_sats` is used up. Then the seller's last
    /// receipt for the answer, checked against what was counted here. Returns fields for the reply
    /// and what the receipt check found.
    #[allow(clippy::too_many_arguments)]
    fn ticket_stream(&self, hs: &Arc<HttpSession>, price: &Price, head: &Receipt, seq: u64, digest: &str, ans: WireAnswer, started: Instant, max_msat: u64,
                     sink: &mut Sink, spent: &mut Spent) -> (Value, Value) {
        let base_spent = lock(&hs.money).acct.spent_msat.saturating_sub(head.charged);
        let st = Stream { price: *price, base_spent, started, max_msat, max_open: Duration::from_secs(self.ticket_policy().max_answer_s.clamp(1, 86_400) as u64) };
        let length = ans.length;
        let mut body = ans.body;
        // shared with the timer of an answer priced by the second: how far the body is, and why it stopped
        let state: Mutex<(u64, Option<String>, bool)> = Mutex::new((0, None, false));
        let wake = Condvar::new();
        let spent_cell = Mutex::new(std::mem::take(spent));
        // one more ticket for this answer, or the reason there is none
        let pay = |bytes: u64| -> Option<String> {
            if let Some(why) = st.over(bytes) {
                return Some(why);
            }
            match self.ticket_release_one(hs, &mut lock(&spent_cell)) {
                Ok(()) => {
                    self.ticket_refill_later(hs);
                    None
                }
                Err(d) => Some(format!("{}: {}", str_or_empty(d.get("rule")), str_or_empty(d.get("reason")))),
            }
        };
        let credited = || lock(&hs.money).acct.acked_msat;
        let mut read_error: Option<String> = None;
        std::thread::scope(|scope| {
            if price.second_msat > 0 {
                // an answer priced by the second is paid by the clock: the next second's ticket goes shortly before it starts
                scope.spawn(|| loop {
                    let mut s = lock(&state);
                    if s.2 || s.1.is_some() {
                        return;
                    }
                    // paid for in the last fifth of the second before it
                    let into = u64::from(st.started.elapsed().subsec_millis());
                    if into >= 800 && st.due_time(credited()) {
                        let bytes = s.0;
                        drop(s);
                        if let Some(why) = pay(bytes) {
                            lock(&state).1.get_or_insert(why);
                            return;
                        }
                        continue;
                    }
                    let nap = Duration::from_millis(if into < 800 { 800 - into } else { 1_800 - into });
                    s = wake.wait_timeout(s, nap).unwrap_or_else(|p| p.into_inner()).0;
                    drop(s);
                });
            }
            let mut buf = vec![0u8; 64 << 10];
            loop {
                if lock(&state).1.is_some() {
                    break;
                }
                let n = match body.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        read_error = Some(e.to_string());
                        break;
                    }
                };
                sink.put(&buf[..n]);
                let bytes = sink.bytes;
                lock(&state).0 = bytes;
                if length.is_some_and(|l| bytes >= l) {
                    break;
                }
                if let Some(why) = st.over(bytes) {
                    lock(&state).1.get_or_insert(why);
                    break;
                }
                // by bytes: everything the released tickets pay for has arrived, so the next one is due
                if st.due_bytes(credited(), bytes) {
                    if let Some(why) = pay(bytes) {
                        lock(&state).1.get_or_insert(why);
                        break;
                    }
                }
            }
            lock(&state).2 = true;
            wake.notify_all();
        });
        // the connection is closed here: a seller that was still sending stops within what the balance covers
        drop(body);
        *spent = std::mem::take(&mut lock(&spent_cell));
        let stopped = lock(&state).1.clone();
        let complete = stopped.is_none() && read_error.is_none() && length.is_none_or(|l| l == sink.bytes);
        let ended = match (&stopped, &read_error) {
            (Some(why), _) => Some(format!("stopped by the wallet: {why}")),
            (None, Some(e)) => Some(format!("cut short by the seller: {e}")),
            (None, None) if !complete => Some("cut short by the seller".to_string()),
            _ => None,
        };
        let secs = if price.second_msat > 0 { started.elapsed().as_secs().saturating_add(2) } else { 0 };
        let own_cost = price.cost(sink.bytes, secs).unwrap_or(u64::MAX);
        let own_digest = hex::encode(sink.hash.clone().finalize());
        // the last receipt of this answer, from the seller's signed status
        let deadline = Instant::now() + FINAL_WAIT;
        let mut last: Option<Receipt> = None;
        let mut why_none = String::from("the seller's status did not list it");
        loop {
            match self.ticket_call(hs, "status", &json!({}), false) {
                Ok((200, v, Ok(own))) => {
                    let found = v.get("responses").and_then(Value::as_array).into_iter().flatten()
                        .filter_map(|r| Receipt::verify(r, &hs.terms.receipt_key, &lock(&hs.link).seller_sid).ok())
                        .find(|r| r.for_request(seq, digest, c_status(head)).is_ok() && !r.body_hash.is_empty());
                    let done = found.is_some() || Instant::now() >= deadline;
                    if done {
                        hs.streaming.store(false, Ordering::SeqCst);
                        let mut m = lock(&hs.money);
                        // a whole body: the seller's totals rose by at most its price by the terms; one that was cut: by at most the balance
                        let due = if complete { Due::AtMost(own_cost.saturating_sub(head.charged)) } else { Due::Balance };
                        let outstanding = m.pending.is_some();
                        if let Err(why) = m.acct.absorb(&own, 0, due, outstanding) {
                            m.fault.get_or_insert(why);
                        }
                        last = found;
                        break;
                    }
                }
                Ok((status, _, _)) => {
                    why_none = format!("the seller answered status with HTTP {status} or no valid receipt");
                    if Instant::now() >= deadline {
                        break;
                    }
                }
                Err(e) => {
                    why_none = e.msg;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(40));
        }
        hs.streaming.store(false, Ordering::SeqCst);
        let mut fault = hs.fault();
        let note = match &last {
            None => json!({"signed": false, "last": Value::Null, "why": why_none}),
            Some(r) => {
                if complete && r.body_hash != own_digest {
                    fault.get_or_insert("the last receipt signs another body than the one that arrived".into());
                }
                if complete && r.charged > own_cost {
                    fault.get_or_insert(format!("the last receipt charges {} msat for an answer that costs {own_cost} by the seller's terms", r.charged));
                }
                json!({"signed": true, "last": r.raw, "body": if !complete { "cut short" } else if r.body_hash == own_digest { "as signed" } else { "differs from the receipt" }})
            }
        };
        // the price of the answer: the seller's signed charge where it stands inside the wallet's own count, else that count
        let price_msat = last.as_ref().map(|r| r.charged).filter(|c| *c <= own_cost || !complete).unwrap_or_else(|| st.cost(sink.bytes));
        let mut m = json!({"complete": complete, "ended": ended, "price_msat": price_msat.to_string()});
        if let Some(why) = fault {
            m["seller_fault"] = self.ticket_fault(hs, &why)["reason"].clone();
        }
        (m, note)
    }

    // --- stop ---------------------------------------------------------------------------------------

    /// Forget a seller's place when it holds no session, so that the places kept are those of
    /// open sessions (which the owner's `tickets.max_sellers` bounds) and of calls in progress.
    fn ticket_slot_drop(&self, origin: &str) {
        let mut map = lock(&self.ticket_http);
        let empty = map.get(origin).is_some_and(|slot| slot.open.try_lock().is_ok_and(|open| open.is_none()));
        if empty {
            map.remove(origin);
        }
    }

    /// Stop a session the wallet pays over HTTP: the book releases and locks nothing more for it,
    /// the seller is asked to cancel what is locked, and the wallet's own node is watched for up
    /// to `wait` until those tickets show failed. The wallet believes its node, not the answer.
    pub(crate) fn ticket_http_stop(&self, hs: &HttpSession, why: &str, wait: Duration) -> Value {
        {
            let slot = lock(&self.ticket_http).get(&hs.origin).cloned();
            if let Some(slot) = slot {
                if let Ok(mut open) = slot.open.try_lock() {
                    if open.as_ref().is_some_and(|h| h.sid == hs.sid) {
                        *open = None;
                    }
                }
            }
            self.ticket_slot_drop(&hs.origin);
        }
        let stopped = {
            let _g = self.lock();
            self.ticket_stop_locked(&json!({"session": hs.sid, "why": why}))
        };
        let asked: Vec<String> = stopped.get("cancel").and_then(Value::as_array).into_iter().flatten().filter_map(|h| h.as_str().map(str::to_string)).collect();
        let mut sent = false;
        if !asked.is_empty() && !lock(&hs.link).seller_sid.is_empty() {
            sent = matches!(self.ticket_call(hs, "cancel", &json!({"hashes": "all"}), false), Ok((200, _, _)));
        }
        let still = self.ticket_wait_cancelled(&hs.sid, if sent { wait } else { Duration::ZERO });
        json!({"session": hs.sid, "why": why, "cancel_asked": asked.len(), "cancel_sent": sent, "still_locked": still, "account": hs.public()})
    }

    /// Reconcile with the wallet's node until no ticket of the session is locked and unreleased, or
    /// `wait` has passed. Returns the hashes still locked.
    fn ticket_wait_cancelled(&self, sid: &str, wait: Duration) -> Vec<String> {
        let deadline = Instant::now() + wait;
        loop {
            {
                let _g = self.lock();
                self.ticket_reconcile_locked();
            }
            let left: Vec<String> = match self.ticket_store() {
                Ok(g) => g.as_ref().map(|st| st.book.of_session(sid).into_iter().filter(|t| t.state.unreleased()).map(|t| t.hash.clone()).collect()).unwrap_or_default(),
                Err(_) => vec![],
            };
            if left.is_empty() || Instant::now() >= deadline {
                return left;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The open HTTP session of a book session, if this process has one.
    fn ticket_http_of(&self, sid: &str) -> Option<Arc<HttpSession>> {
        let slots: Vec<Arc<Slot>> = lock(&self.ticket_http).values().cloned().collect();
        slots.iter().find_map(|s| lock(&s.open).as_ref().filter(|h| h.sid == sid).cloned())
    }

    /// `ticket_stop`: stop a session. Where the wallet itself speaks to the seller, it also asks
    /// for the cancel and reports what its own node then shows; otherwise it names the tickets for
    /// the caller to have cancelled, as before.
    pub(crate) fn ticket_stop(&self, p: &Value) -> Value {
        let sid = str_or_empty(p.get("session"));
        if let Some(hs) = self.ticket_http_of(&sid) {
            let done = self.ticket_http_stop(&hs, "stopped by the caller", CANCEL_WAIT);
            let _g = self.lock();
            return with(self.ticket_stop_locked(&json!({"session": sid})), json!({"http": done}));
        }
        // a session of an earlier run of this wallet, whose seller is on record: the cancel is asked for once more
        if let Some(s) = self.ticket_session(&sid).filter(|s| s.http.is_some()) {
            let done = self.ticket_cancel_recorded(&s, CANCEL_WAIT);
            let _g = self.lock();
            return with(self.ticket_stop_locked(&json!({"session": sid})), json!({"http": done}));
        }
        let _g = self.lock();
        self.ticket_stop_locked(p)
    }

    /// Ask the seller of a session on record to cancel all its tickets: for a session this process
    /// did not open (the wallet started again). The answer is not checked: the node's word is.
    fn ticket_cancel_recorded(&self, s: &crate::ticket::Session, wait: Duration) -> Value {
        let Some(http) = &s.http else { return Value::Null };
        {
            let _g = self.lock();
            self.ticket_stop_locked(&json!({"session": s.id}));
        }
        // the URL is the one the wallet fetched terms from when it opened the session, and the owner must still allow its origin
        let origin = origin_of(&http.base).map(|o| normalize_dest(&o)).unwrap_or_default();
        let allowed = !origin.is_empty() && (normalize_dest(&s.origin) == origin) && seller_url(&origin, &http.base).is_ok() && self.ticket_may_reach(&origin, &s.task);
        let mut sent = false;
        if allowed {
            let net = self.ticket_net().unwrap_or_default();
            let accepted = json!({"scheme": xbt402::ticket::SCHEME, "network": net});
            let url = format!("{}/cancel", http.base);
            let raw = json!({"hashes": "all"}).to_string().into_bytes();
            let mut seq = 0u64;
            for _ in 0..2 {
                let digest = request_digest_v2("POST", &url, &raw);
                let auth = xbt402::ticket::request_auth(&http.key, &http.id, seq, "", "", &digest);
                let header = b64json(&payment_payload(&accepted, &json!({"session": http.id, "seq": seq, "auth": auth})));
                let Ok(ans) = self.ticket_wire.send("POST", &url, &raw, &[("Content-Type".into(), "application/json".into()), ("PAYMENT-SIGNATURE".into(), header)],
                                                    Duration::from_secs(10)) else { break };
                let status = ans.status;
                let v: Value = ans.read_small(SMALL_BODY).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
                match (status, v.get("nextSeq").and_then(Value::as_u64)) {
                    (200, _) => {
                        sent = true;
                        break;
                    }
                    // the seq this wallet used last was lost with its memory: the seller says which is next
                    (402, Some(n)) if v.get("error").and_then(Value::as_str) == Some("bad_seq") => seq = n,
                    _ => break,
                }
            }
        }
        let still = self.ticket_wait_cancelled(&s.id, if sent { wait } else { Duration::ZERO });
        self.ticket_audit("ticket_cancel_asked", json!({"session": s.id, "dest": format!("ln:{}", s.payee), "sent": sent, "still_locked": still.len()}));
        json!({"session": s.id, "cancel_sent": sent, "still_locked": still})
    }

    /// The watcher's part: sessions idle for longer than the owner's `tickets.http_idle_s` are
    /// stopped and their tickets cancelled, and the sellers of sessions an earlier run of this
    /// wallet left locked are asked, once per start, to cancel them. Holds no lock of the wallet
    /// while a seller is waited for.
    pub(crate) fn ticket_http_tick(&self) -> Vec<Value> {
        let mut out = vec![];
        let tp = self.ticket_policy();
        let now = self.engine.now();
        let slots: Vec<Arc<Slot>> = lock(&self.ticket_http).values().cloned().collect();
        for slot in slots {
            let Ok(open) = slot.open.try_lock() else { continue };
            let Some(hs) = open.as_ref().cloned() else { continue };
            drop(open);
            let idle = now - *lock(&hs.used);
            let Ok(_busy) = hs.busy.try_lock() else { continue };
            if idle > tp.http_idle_s.max(1) as f64 {
                out.push(json!({"ticket_idle_stop": self.ticket_http_stop(&hs, &format!("idle for {idle:.0} s"), Duration::ZERO)}));
            }
        }
        for s in self.ticket_stopping_with_seller() {
            if self.ticket_http_of(&s.id).is_some() || !lock(&self.ticket_cancel_tried).insert(s.id.clone()) {
                continue;
            }
            out.push(json!({"ticket_cancel_asked": self.ticket_cancel_recorded(&s, Duration::ZERO)}));
        }
        out
    }

    /// What the wallet counts for each session it pays over HTTP: for `ticket_status` and `channels`.
    pub(crate) fn ticket_http_public(&self) -> Vec<Value> {
        let slots: Vec<Arc<Slot>> = lock(&self.ticket_http).values().cloned().collect();
        slots.iter().filter_map(|s| s.open.try_lock().ok().and_then(|o| o.as_ref().map(|h| h.public()))).collect()
    }
}

/// Whether what travels to `origin` (`scheme://host[:port]`, lower case) cannot be read on the way:
/// https, or http to this machine.
fn private_channel(origin: &str) -> bool {
    let u = xbt402::wire::request_url(origin);
    u.scheme == "https" || (u.scheme == "http" && (u.host == "localhost" || u.host == "[::1]" || u.host.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| ip.is_loopback())))
}

fn c_status(head: &Receipt) -> u16 {
    u16::try_from(head.status).unwrap_or(0)
}

/// Read a body to its end into `sink`. `Some`: why it ended early.
fn read_all(ans: WireAnswer, sink: &mut Sink) -> Option<String> {
    let length = ans.length;
    let mut body = ans.body;
    let mut buf = vec![0u8; 64 << 10];
    loop {
        match body.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => sink.put(&buf[..n]),
            Err(e) => return Some(format!("cut short: {e}")),
        }
    }
    length.filter(|l| *l != sink.bytes).map(|l| format!("cut short: {} of {l} bytes", sink.bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ticket_is_due_only_when_the_balance_does_not_cover_the_next_piece() {
        let per_mib = Price { request_msat: 2500, byte_msat: 200_000, per_bytes: 1 << 20, second_msat: 0 };
        let st = Stream { price: per_mib, base_spent: 10_000, started: Instant::now(), max_msat: u64::MAX, max_open: Duration::from_secs(50) };
        // one ticket of 1,000 sat credited on top of the 10 sat spent before: 1,000,000 - 2,500 msat of bytes
        let credited = 1_010_000;
        let limit = per_mib.bytes_for(1_000_000 - 2500);
        assert!(!st.due_bytes(credited, 0) && !st.due_bytes(credited, limit - 1));
        assert!(st.due_bytes(credited, limit), "everything the ticket pays for has arrived");
        assert!(!st.due_bytes(credited + 1_000_000, limit), "the next ticket covers the next byte");
        assert!(!st.due_time(credited), "not priced by time");
        assert_eq!(st.cost(1 << 20), 202_500);
        // by the second: due when the next second is not covered
        let per_s = Price { request_msat: 0, byte_msat: 0, per_bytes: 1, second_msat: 100_000 };
        let st = Stream { price: per_s, base_spent: 0, started: Instant::now(), max_msat: u64::MAX, max_open: Duration::from_secs(50) };
        assert_eq!(st.seconds(), 1, "the first second has started");
        assert!(st.due_time(100_000), "one second paid, the second is not");
        assert!(!st.due_time(200_000) && !st.due_bytes(100_000, 1 << 30));
        // a price that does not fit is due at once and costs the most there is
        let huge = Stream { price: Price { request_msat: u64::MAX, byte_msat: 1, per_bytes: 1, second_msat: 0 }, base_spent: 0, started: Instant::now(), max_msat: 5, max_open: Duration::from_secs(50) };
        assert_eq!(huge.cost(1), u64::MAX);
        assert!(huge.due_bytes(1_000_000, 0));
        assert!(huge.over(0).is_some_and(|w| w.starts_with("max_sats")), "and is over any limit");
        // a long body paid for at its head is not cut where the call's limit equals its price
        let flat = Stream { price: Price { request_msat: 5_000, byte_msat: 0, per_bytes: 1, second_msat: 0 }, base_spent: 0, started: Instant::now(), max_msat: 5_000,
                            max_open: Duration::from_secs(50) };
        assert!(flat.over(1 << 30).is_none());
        let long = Stream { price: per_mib, base_spent: 0, started: Instant::now() - Duration::from_secs(3), max_msat: u64::MAX, max_open: Duration::from_secs(2) };
        assert!(long.over(0).is_some_and(|w| w.starts_with("max_answer_s")) && st.over(0).is_none());
    }

    #[test]
    fn tickets_are_paid_over_https_or_to_this_machine_only() {
        for ok in ["https://seller.example", "https://seller.example:8443", "http://127.0.0.1:8402", "http://127.9.9.9", "http://localhost:80", "http://[::1]:8402"] {
            assert!(private_channel(ok), "{ok}");
        }
        for no in ["http://seller.example", "http://10.0.0.5:8402", "http://127.0.0.1.example", "http://[::2]", "ftp://127.0.0.1", "http://localhost.example", ""] {
            assert!(!private_channel(no), "{no}");
        }
    }

    #[test]
    fn the_task_of_a_call_is_named_or_the_only_one_or_default() {
        let tp = |names: &[&str]| {
            let tasks: serde_json::Map<String, Value> = names.iter().map(|n| (n.to_string(), json!({"budget_sats": 1}))).collect();
            TicketPolicy::from_map(json!({"enabled": true, "tasks": tasks}).as_object().unwrap())
        };
        assert_eq!(Signer::ticket_task_for(&tp(&["film"]), ""), Ok("film".into()));
        assert_eq!(Signer::ticket_task_for(&tp(&["film", "default"]), ""), Ok("default".into()));
        assert_eq!(Signer::ticket_task_for(&tp(&["film", "swarm"]), "swarm"), Ok("swarm".into()));
        assert!(Signer::ticket_task_for(&tp(&["film", "swarm"]), "").is_err());
        assert!(Signer::ticket_task_for(&tp(&["film"]), "other").is_err());
        assert!(Signer::ticket_task_for(&tp(&[]), "").is_err());
    }

    #[test]
    fn a_body_is_counted_hashed_and_previewed_as_it_arrives() {
        let mut s = Sink::new();
        s.cap = 4;
        s.put(b"abc");
        s.put(b"defg");
        let (digest, v, text) = s.done();
        assert_eq!((v["bytes"].as_u64(), text.as_str()), (Some(7), "abcd"));
        assert_eq!(digest, hex::encode(Sha256::digest(b"abcdefg")));
    }
}
