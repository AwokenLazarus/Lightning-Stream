//! Stream tickets, the wallet pays a seller over HTTP (`docs/TICKETS.md` sections 1 to 4 and 12):
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
//! | No ticket is released into a session whose last answer the seller has not closed. | [`Signer::ticket_release_one`] waits for the answer's last receipt in the seller's signed `status` (5 s a call, the session given up after 30 s). A seller waiting for a refill of an answer the wallet stopped reading would take the next ticket for bytes nobody reads. |
//! | A call uses at most `max_sats`, by the wallet's own count, and ends within the owner's `max_answer_s`. | [`Signer::ticket_request`] refuses a head price above it; [`Stream::over`] cuts the body where its price reaches it or its time is up. |
//! | Held tickets first; a prepaid one only where none can be held. | [`Signer::ticket_release_one`] buys a prepaid ticket only when the session has no held ticket to release and the book says it pays that way now ([`crate::ticket::Session::prepaid_now`]: a pool of none, or a wait after a lock that found no slot). The purchase itself is the book's ([`Signer::ticket_prepay`]), one at a time. |
//! | A seller that says `slots_short` is waited for. | [`Signer::ticket_lock_call`] sets the session's wait from the seller's `retryAfter` and offers it no hash until then. |
//! | A session that can release nothing more is ended, and said so. | [`Signer::ticket_forgotten`]: the seller's unsigned `session_unknown` to a lock or a `status` stops the session, as an unsigned answer to a paid request does. [`Signer::ticket_release_one`]: a ticket the seller has not shown after `ready_wait_ms` that the wallet's own node carries on no channel ([`Signer::ticket_stranded`]) stops it too. Neither releases or books anything. |
//! | An invoice that will not be paid gives its place with the seller back. | [`Signer::ticket_fill_once`] asks the seller to cancel the invoices a lock round refused or failed, and [`Signer::ticket_cancel_dead`] those of tickets that failed after their round, each once. The answer is not read. |
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
use xbt402::ticket::protocol_code;
use xbt402::wire::{b64json, payment_payload, request_digest_v2, seller_url, sendable_url, unb64json};
use zeroize::Zeroizing;

use crate::ln::LnPolicy;
use crate::policy::normalize_dest;
use crate::pyjson::{py_int, str_or_empty};
use crate::sanitize::{untrusted, UNTRUSTED_KEY};
use crate::signer::{deny, with, Signer};
use crate::ticket::{sats_ceil, Admit, SState, SellerSession, Terms, TicketPolicy, HOLD_SHORT, ROUTE_FULL};
use crate::ticket_http::{offers, Account, Due, Offer, PayTerms, Price, Receipt};
use crate::{err, Result};

mod draws;
pub(crate) use draws::DrawSession;

/// The most of a session endpoint's answer that is read.
const SMALL_BODY: u64 = 1 << 20;
/// How long the wallet looks for the last receipt of an answer that was sent as it arrived.
const FINAL_WAIT: Duration = Duration::from_secs(2);
/// How long a release waits for the seller to close an answer the wallet stopped reading, and how
/// long after that stop the session is given up if the seller never closes it.
const TAIL_WAIT: Duration = Duration::from_secs(5);
const TAIL_GIVE_UP: Duration = Duration::from_secs(30);
/// How long a stop waits for the wallet's own node to show the cancelled tickets failed.
pub const CANCEL_WAIT: Duration = Duration::from_secs(5);
/// Refusals of `ticket_open` that mean "not this rail": the next entry of the 402 is tried.
const NEXT_RAIL: [&str; 12] = ["ticket_disabled", "ln_disabled", "ticket_task", "ticket_admission", "ticket_terms", "ticket_feature_512", "ticket_network",
                               "ticket_size", "ticket_blocks", "ticket_dust", "ticket_slots", ROUTE_FULL];

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
        self.body.take(cap + 1).read_to_end(&mut out).map_err(|e| err("transport_error", format!("the answer could not be read ({:?})", e.kind())))?;
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
            // a fixed wording: ureq's own quotes the URL (the seller's session path) and a malformed status
            Err(e) => return Err(err("transport_error", xbt402::http::transport_words(&e))),
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
    /// An answer priced as it goes that ended here and that the seller has not closed yet (its
    /// last receipt is not in `status`): the seller may still be waiting to send more of it, and
    /// would on the next ticket. Nothing is released into the session until it is closed.
    tail: Option<Tail>,
}

/// An answer the seller has not closed: which request it answered, and when the wallet stopped reading.
struct Tail {
    seq: u64,
    digest: String,
    status: u16,
    since: Instant,
}

/// A ticket session the wallet pays over HTTP. In memory only: a signer that starts again stops
/// every session (the book's rule) and has the seller's id and key on disk for the cancel.
pub(crate) struct HttpSession {
    pub origin: String,
    /// The book's session, and the owner's task it was opened under.
    pub sid: String,
    task: String,
    pub terms: PayTerms,
    /// The seller's terms for prepaid tickets, where its 402 listed them beside the entry the
    /// session was opened on.
    prepaid: Option<Terms>,
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
    /// Hashes of this session's tickets the seller was asked to cancel because their payment had
    /// failed: each is asked for once.
    cancel_asked: Mutex<HashSet<String>>,
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
               "fault": m.fault, "answer_open": self.streaming.load(Ordering::SeqCst), "answer_unclosed": m.tail.is_some()})
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
    /// SHA-256 of each piece of the answer's body, hex, where the caller knows them (a file whose
    /// piece hashes it already holds): a piece paid by a draw gets its value only if it matches.
    piece_hashes: Vec<String>,
}

/// What one call released: the hashes, the sats the book put in the ledger for them, and how many
/// of them were prepaid tickets.
#[derive(Default)]
struct Spent {
    hashes: Vec<String>,
    booked_sats: i64,
    prepaid: usize,
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

/// The x402 scheme name of the on-chain channel this wallet once paid: recognised in a 402 only to
/// say that it is no longer a rail here.
const CHANNEL_SCHEME: &str = "batch-settlement";

/// The most of a seller's text an answer to the agent carries, in bytes (`B2_BODY_CAP`).
pub fn body_cap() -> usize {
    std::env::var("B2_BODY_CAP").ok().and_then(|v| v.parse().ok()).unwrap_or(12_000)
}

/// `scheme://netloc` of an absolute URL. A URL with a `#` is refused (AGP-081, review T2: the
/// request binding does not cover a fragment).
pub fn origin_of(url: &str) -> Result<String> {
    if url.contains('#') {
        return Err(err("dest", "a URL with a # fragment is not paid: the fragment is outside the request binding"));
    }
    let (scheme, rest) = url.split_once("://").ok_or_else(|| err("dest", "xbt402_pay needs an absolute URL"))?;
    let netloc = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    if scheme.is_empty() || netloc.is_empty() || !scheme.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) {
        return Err(err("dest", "xbt402_pay needs an absolute URL"));
    }
    Ok(format!("{}://{netloc}", scheme.to_ascii_lowercase()))
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

    /// `xbt402_pay`. The signer asks the seller once without paying, and pays by the first of these
    /// the 402 offers and the policy allows:
    ///
    /// 1. a ticket entry (`scheme: "ticket"` on this Lightning network), or the lottery entry beside
    ///    it, where the owner turned tickets on;
    /// 2. a single Lightning payment (`scheme: "exact"` with a BOLT 11 invoice), as `ln_pay` pays one;
    ///
    /// and otherwise reports what each entry would have needed. A rail is passed over only for a
    /// reason that makes it unusable for this seller (off, not admitted, terms outside the owner's
    /// bounds); a budget or a cap that is used up refuses the call and tries no other rail.
    ///
    /// With `max_sats` 0 the call pays nothing: an answer that is not a 402 is handed back, and a
    /// 402 is refused. (Until 2026-10 a third entry, the on-chain channel, was paid here, and a call
    /// with tickets off went to it; that rail was removed.)
    pub(crate) fn xbt402_pay(&self, p: &Value) -> Value {
        let tp = self.ticket_policy();
        let cfg = self.config();
        let max_sats = match p.get("max_sats").filter(|v| !v.is_null()) {
            None => 0,
            Some(v) => match py_int(Some(v)) {
                Some(n) if n >= 0 => n,
                Some(_) => return deny("amount", "max_sats must be >= 0"),
                None => return deny("amount", "max_sats must be an integer"),
            },
        };
        let asked = str_or_empty(p.get("url"));
        let origin = match origin_of(&asked) {
            Ok(o) => normalize_dest(&o),
            Err(e) => return deny("dest", e.msg),
        };
        let Some(url) = sendable_url(&asked).ok().filter(|_| !origin.is_empty()) else {
            return deny("dest", "xbt402_pay needs an absolute http or https URL");
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
        let (lightning, chain) = match (self.ticket_net(), self.network()) {
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
        let piece_hashes: Vec<String> = p.get("piece_sha256").and_then(Value::as_array).into_iter().flatten().take(1 << 20)
            .map(|h| h.as_str().unwrap_or("").to_ascii_lowercase()).collect();
        if max_sats == 0 {
            return with(deny("max_sats", "the seller asks to be paid and this call may spend nothing (max_sats 0)"), json!({"charged_sats": 0}));
        }
        let call = Call { url: &url, origin: &origin, method: &method, body: &raw, max_sats, task, piece_hashes };
        let mut passed: Vec<Value> = vec![];
        let mut ways = offers(&pr, &lightning);
        // tickets or draws first: one rule ([`crate::lottery::choose`]); the other is tried after it
        if self.draws_first(&call, &ways, &lightning, &tp) {
            if let Some(i) = ways.iter().position(|o| matches!(o, Offer::Lottery(_))) {
                let l = ways.remove(i);
                ways.insert(0, l);
            }
        }
        for offer in ways {
            let rail = offer.rail();
            let tried = match &offer {
                Offer::Ticket(..) | Offer::Lottery(_) if !tp.enabled => Tried::Next("stream tickets are off in this policy (tickets.enabled)".into()),
                Offer::Lottery(acc) => self.lottery_pay(&call, acc, &lightning),
                Offer::Ticket(acc, prepaid) => self.ticket_pay(&call, acc, prepaid.as_ref(), &lightning),
                Offer::Lightning(_) if !listed => Tried::Next("the seller is not on the owner's allowlist: only a ticket task that pays any seller reaches it".into()),
                Offer::Lightning(acc) => self.ln_exact_pay(&call, acc, &tp),
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
        // what the 402 offers, in the wallet's words: a scheme it knows by name, and whether the network is one of its own
        let offered: Vec<Value> = pr.get("accepts").and_then(Value::as_array).into_iter().flatten()
            .map(|a| {
                let scheme = a.get("scheme").and_then(Value::as_str);
                let scheme = if scheme == Some(xbt402::ticket::SCHEME) { xbt402::ticket::SCHEME } else if scheme == Some(xbt402::lottery::SCHEME) { xbt402::lottery::SCHEME }
                             else if scheme == Some("exact") { "exact" }
                             else if matches!(scheme, Some(CHANNEL_SCHEME | "xbt-channel")) { CHANNEL_SCHEME } else { "other" };
                let network = match a.get("network").and_then(Value::as_str) {
                    Some(n) if n == lightning => "this wallet's Lightning network",
                    Some(n) if n == chain => "this wallet's chain",
                    _ => "other",
                };
                json!({"scheme": scheme, "network": network})
            }).take(16).collect();
        if offered.iter().any(|o| o["scheme"] == CHANNEL_SCHEME) {
            passed.push(json!({"rail": "channel", "why": "the seller offers the on-chain channel, which this wallet no longer has"}));
        }
        with(deny("no_rail", "the seller's 402 offers no way to pay that this wallet's policy allows: see rails_passed_over for what each entry needs"),
             json!({"charged_sats": 0, "rails_passed_over": passed, "offered": offered,
                    "wallet": {"lightning": lightning, "chain": chain, "tickets": tp.enabled, "ln": LnPolicy::from_map(&cfg.ln).enabled}}))
    }

    /// Whether this seller is paid by draws before tickets are tried: what [`crate::lottery::choose`]
    /// says of the two entries of its 402, the owner's policy, the call's limit, whether a held
    /// ticket fits, and the session that is open with it, if one is.
    fn draws_first(&self, c: &Call, ways: &[Offer], lightning: &str, tp: &TicketPolicy) -> bool {
        let draw = ways.iter().find_map(|o| match o {
            Offer::Lottery(acc) => crate::lottery::DrawTerms::parse(acc, lightning).ok(),
            _ => None,
        });
        let ticket = ways.iter().find_map(|o| match o {
            Offer::Ticket(acc, _) => Terms::parse(acc, lightning).ok(),
            _ => None,
        });
        let Some(draw) = draw else { return false };
        let task = c.task.as_deref().unwrap_or("");
        let payee = draw.payee.clone();
        crate::lottery::choose(&crate::lottery::Choice {
            ticket_entry: ticket.is_some(), lottery_entry: true, lottery_on: tp.lottery.enabled,
            meter: tp.tasks.get(task).map_or(crate::lottery::Meter::Auto, |t| t.meter),
            // a session this process pays this origin by draws is the one that is open; else what the book holds open with the seller's node
            open: if lock(&self.draw_http).contains_key(c.origin) { Some(true) } else { self.ticket_open_kind(&payee, c.origin) },
            dearest_msat: draw.dearest_piece().unwrap_or(u64::MAX), ticket_msat: ticket.as_ref().map_or(u64::MAX, |t| t.ticket_msat),
            expect_msat: (c.max_sats.max(0) as u64).saturating_mul(1000), held_fits: ticket.is_some() && self.ticket_held_fits(task),
            stay_tickets: tp.lottery.stay_tickets.max(1) as u64 })
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
    fn ticket_pay(&self, c: &Call, acc: &Value, prepaid_acc: Option<&Value>, lightning: &str) -> Tried {
        let terms = match PayTerms::parse(acc, lightning) {
            Ok(t) => t,
            Err((rule, why)) => return Tried::Next(format!("{rule}: {why}")),
        };
        // the entry for prepaid tickets counts only as the same seller's second way to be paid: the same
        // node, receipt key, endpoints and release. Anything else is no offer, and the held entry stands alone
        let prepaid: Option<(Terms, &Value)> = prepaid_acc.and_then(|a| PayTerms::parse(a, lightning).ok().map(|t| (t, a)))
            .filter(|(p, _)| p.terms.payee == terms.terms.payee && p.receipt_key == terms.receipt_key && p.session_path == terms.session_path && p.release == terms.release)
            .map(|(p, a)| (p.terms, a));
        let prepaid_terms = prepaid.as_ref().map(|(t, _)| t.clone());
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
                Some(h) if !h.terms.same_seller(&terms) || h.prepaid != prepaid_terms => {
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
                        self.ticket_open_locked(&json!({"terms": acc, "prepaid_terms": prepaid.as_ref().map(|(_, a)| *a), "task": &task, "origin": c.origin}))
                    };
                    if o["verdict"] != "allow" {
                        let rule = str_or_empty(o.get("rule"));
                        break 'open Err(if NEXT_RAIL.contains(&rule.as_str()) { Tried::Next(format!("{rule}: {}", str_or_empty(o.get("reason")))) } else { Tried::Done(o) });
                    }
                    let h = Arc::new(HttpSession { origin: c.origin.into(), sid: str_or_empty(o.get("session")), task: task.clone(), terms: terms.clone(),
                                                   prepaid: prepaid_terms.clone(), base, busy: Mutex::new(()),
                                                   paying: Mutex::new(()), link: Mutex::new(Link { seller_sid: String::new(), key: Zeroizing::new([0u8; 32]), next_seq: 0 }),
                                                   money: Mutex::new(Money::default()), streaming: AtomicBool::new(false), refilling: AtomicBool::new(false),
                                                   used: Mutex::new(self.engine.now()), unfilled: Mutex::new(None),
                                                   cancel_asked: Mutex::new(HashSet::new()) });
                    // the first pool, before the call goes on. A session that holds nothing, or that found no slot
                    // and waits, goes on where the seller offers prepaid tickets: the call buys one when it needs it
                    let filled = self.ticket_fill(&h);
                    let prepaid_now = self.ticket_session(&h.sid).is_some_and(|s| s.prepaid_now(self.engine.now()));
                    match filled {
                        Ok(n) if n > 0 => {}
                        _ if prepaid_now => {}
                        Ok(_) => {
                            // nothing was locked. Where the session waits (a lock found no slot, now or in the session
                            // before this one), that is the reason, and when to come back
                            let now = self.engine.now();
                            let wait = self.ticket_session(&h.sid).filter(|s| now < s.hold_until || s.pool == 0);
                            let stopped = self.ticket_http_stop(&h, "no ticket could be locked", Duration::ZERO);
                            if let Some(s) = wait {
                                let why = if s.hold_why.is_empty() { "ticket_slots".to_string() } else { s.hold_why.clone() };
                                break 'open Err(Tried::Done(with(refusal(&why, format!("no ticket is locked with this seller for another {:.0} s: a lock found no free slot \
                                                                                        on the way to it, and its terms offer no prepaid tickets", (s.hold_until - now).max(0.0))),
                                                                 json!({"stopped": stopped, "retry_after_s": (s.hold_until - now).max(0.0).ceil(), "slot_fails": s.slot_fails}))));
                            }
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
        self.ticket_cancel_dead(hs);
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
        // a round that ends before any invoice was judged gives its hashes up, so that the next round can offer new ones
        let offered: Vec<String> = hashes.iter().filter_map(|h| h.as_str().map(str::to_string)).collect();
        let unoffer = |why: &str| {
            // unchecked: a hash that stays offered only lapses later, and the round's own refusal is what the caller is told
            let _ = self.ticket_unoffer(&hs.sid, &offered, why);
        };
        let mut body = json!({"version": xbt402::ticket::VERSION, "hashes": hashes});
        // a size of the wallet's choosing is asked for only where the terms let it choose
        let size = self.ticket_session(&hs.sid).map(|s| s.ticket_msat).unwrap_or(hs.terms.terms.ticket_msat);
        if hs.terms.terms.min_ticket_msat.is_some() && size != hs.terms.terms.ticket_msat {
            body["ticketMsat"] = size.to_string().into();
        }
        let answer = match self.ticket_lock_call(hs, body) {
            Ok(v) => v,
            Err(d) => {
                unoffer(&str_or_empty(d.get("reason")));
                return Err(d);
            }
        };
        // the invoices are the seller's word: every check of them is the book's (`ticket_lock`)
        let tickets: Vec<Value> = answer.get("tickets").and_then(Value::as_array).cloned().unwrap_or_default();
        if tickets.is_empty() {
            unoffer("the seller issued no invoice");
            return Ok(0);
        }
        let locked = self.ticket_lock(&json!({"session": hs.sid, "tickets": tickets}));
        let n = locked.get("locked").and_then(Value::as_u64).unwrap_or(0) as usize;
        // why the book did not pay one of them: its first refusal, by its own rule. Kept for a release that finds the pool empty
        let why_not = locked.get("refused").and_then(Value::as_array).and_then(|a| a.first()).map(|first| {
            let (rule, why) = (str_or_empty(first.get("rule")), str_or_empty(first.get("reason")));
            let mut v = with(refusal(if rule.is_empty() { "ticket_lock" } else { rule.as_str() }, format!("a ticket could not be locked with this seller: {why}")),
                             json!({"session": hs.sid, "refused": locked["refused"].as_array().map(Vec::len)}));
            // what the wallet's node said, where the refusal was its error: untrusted text, kept as the book gave it
            if let Some(said) = first.get(crate::ln::UNTRUSTED_LN_KEY) {
                v[crate::ln::UNTRUSTED_LN_KEY] = said.clone();
            }
            v
        });
        *lock(&hs.unfilled) = why_not.clone();
        // an invoice the wallet's own node could not be asked about was not judged either, and one that was refused for
        // lack of a slot or for dust is refused whoever issued it: their hashes are given up now, and the session's
        // wait (set by the book) keeps new ones from being offered at once
        let unasked: Vec<String> = locked.get("refused").and_then(Value::as_array).into_iter().flatten()
            .filter(|r| matches!(r.get("rule").and_then(Value::as_str), Some("ln_backend" | "ticket_slots" | "ticket_dust")))
            .filter_map(|r| r.get("hash").and_then(Value::as_str).map(str::to_string)).collect();
        if !unasked.is_empty() {
            let _ = self.ticket_unoffer(&hs.sid, &unasked, "its invoice was not paid: the wallet's node could not be asked, or no slot was free for it");
        }
        // invoices the seller issued and that will not be paid (refused here, or failed on the way) take places under
        // the seller's cap on held tickets until they lapse: it is asked to cancel them now. Unchecked: a seller that
        // does not answer cancels them itself when they lapse, and no money depends on it
        let dead: Vec<Value> = locked.get("refused").and_then(Value::as_array).into_iter().flatten().filter_map(|r| r.get("hash").cloned())
            .chain(locked.get("tickets").and_then(Value::as_array).into_iter().flatten().filter(|t| t["state"] == "failed").filter_map(|t| t.get("hash").cloned()))
            .filter(|h| h.as_str().is_some_and(|h| xbt402::ticket::hex32(h).is_some())).collect();
        if !dead.is_empty() && dead.len() <= hs.terms.terms.max_tickets as usize {
            let _ = self.ticket_call(hs, "cancel", &json!({"hashes": dead}), true);
            lock(&hs.cancel_asked).extend(dead.iter().filter_map(|h| h.as_str().map(str::to_string)));
        }
        if n == 0 {
            if let Some(d) = why_not {
                return Err(d);
            }
            if locked["verdict"] == "deny" && locked.get("rule").is_some_and(|r| r != "ticket_refused") {
                // the round was refused as a whole, before any invoice was judged (the wallet's own node, most often)
                unoffer("the lock round was refused before its invoices were judged");
                return Err(locked);
            }
        }
        Ok(n)
    }

    /// Ask the seller to cancel the invoices of this session's tickets whose payment failed after
    /// its lock round was over (the wallet's node went away as it sent them, and said so only when
    /// it was back): a lock round asks for the invoices that failed in it, and these failed
    /// later. Until the seller cancels such an invoice or it lapses, it takes a place under the
    /// seller's `maxTickets`, and with 2 places a session whose two sends died could lock nothing
    /// (`too_many_tickets`) for as long. Each hash is asked for once. Unchecked, like the cancel of
    /// a lock round: a seller that does not answer cancels them itself when they lapse, and no
    /// money depends on it.
    fn ticket_cancel_dead(&self, hs: &HttpSession) {
        if lock(&hs.link).seller_sid.is_empty() {
            return;
        }
        let dead: Vec<String> = {
            let asked = lock(&hs.cancel_asked);
            self.ticket_dead_invoices(&hs.sid).into_iter().filter(|h| !asked.contains(h)).take(hs.terms.terms.max_tickets.max(1) as usize).collect()
        };
        if dead.is_empty() {
            return;
        }
        let _ = self.ticket_call(hs, "cancel", &json!({"hashes": dead}), true);
        lock(&hs.cancel_asked).extend(dead);
    }

    /// The seller answered a request of the session with `session_unknown` and no receipt: it has
    /// forgotten the session (a gateway drops one that holds nothing and has been quiet, as this
    /// one is after the wallet's node was away for that long). Nothing more can be locked or
    /// released in it, so it is stopped here, and the next call opens another. Returns what the
    /// caller is told. Like every answer nobody signed, this one moves no money: a session that is
    /// stopped releases nothing, and what was released in it stays booked until the wallet's own
    /// node says what became of it.
    fn ticket_forgotten(&self, hs: &HttpSession, status: u16, v: &Value) -> Option<String> {
        if status != 402 || protocol_code(v.get("error")) != "session_unknown" {
            return None;
        }
        let why = "the seller has forgotten the session";
        lock(&hs.money).fault.get_or_insert_with(|| why.to_string());
        self.ticket_http_stop(hs, why, Duration::ZERO);
        Some(format!("{why} (HTTP 402 session_unknown): the session was stopped, and the next call opens another"))
    }

    /// The rule a refusal carries when the seller's `status` could not be had: the session ended
    /// with it ([`Signer::ticket_forgotten`]), or the seller gave no answer that can be believed.
    fn status_rule(hs: &HttpSession) -> &'static str {
        if hs.fault().is_some() { "ticket_session_ended" } else { "ticket_seller" }
    }

    /// One `lock` request to the seller: the first of a session, which makes the seller's side of it
    /// (its id and key are written to the book before anything is paid), or a later, authenticated
    /// one. `Ok`: the seller's answer. A seller that answers `slots_short` is not failing: the
    /// session locks nothing until its `retryAfter` has passed, and the refusal says so.
    fn ticket_lock_call(&self, hs: &HttpSession, mut body: Value) -> std::result::Result<Value, Value> {
        if !self.ticket_may_reach(&hs.origin, &hs.task) {
            return Err(deny("allowlist", format!("destination not on allowlist: {}", hs.origin)));
        }
        let refused = |status: u16, v: &Value| {
            let code = protocol_code(v.get("error"));
            if status == 402 && code == "slots_short" {
                let wait = v.get("retryAfter").and_then(Value::as_u64).unwrap_or(crate::ticket::SLOT_WAIT_S as u64).clamp(1, crate::ticket::SLOT_WAIT_MAX_S as u64);
                // unchecked: without the wait in the book the next round asks again and is told the same
                let _ = self.ticket_hold(&hs.sid, wait, "ticket_slots_short");
                return with(refusal("ticket_slots_short", format!("the seller holds as many tickets as its channels allow and asks buyers to wait {wait} s: \
                                                                   no ticket is locked with it until then")), json!({"retry_after_s": wait, "session": hs.sid}));
            }
            if let Some(gone) = self.ticket_forgotten(hs, status, v) {
                return with(refusal("ticket_session_ended", gone), json!({"session": hs.sid}));
            }
            refusal("ticket_seller", format!("the seller refused the lock: HTTP {status} {code}"))
        };
        if !lock(&hs.link).seller_sid.is_empty() {
            body["session"] = lock(&hs.link).seller_sid.clone().into();
            return match self.ticket_call(hs, "lock", &body, true) {
                Ok((200, v, _)) => Ok(v),
                Ok((status, v, _)) => Err(refused(status, &v)),
                Err(e) => Err(refusal("ticket_seller", format!("the seller gave no answer to the lock: {}", e.msg))),
            };
        }
        let url = format!("{}/lock", hs.base);
        let raw = body.to_string().into_bytes();
        let sent = self.ticket_wire.send("POST", &url, &raw, &[("Content-Type".into(), "application/json".into())], Self::ticket_read_timeout(&self.ticket_policy()));
        let (status, v) = match sent.and_then(|a| Ok((a.status, a.read_small(SMALL_BODY)?))) {
            Ok((status, raw)) => (status, serde_json::from_slice::<Value>(&raw).unwrap_or(Value::Null)),
            Err(e) => return Err(refusal("ticket_seller", format!("the seller gave no answer to the first lock: {}", e.msg))),
        };
        if status != 200 {
            return Err(refused(status, &v));
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
        Ok(v)
    }

    /// Buy one prepaid ticket for the session and show the seller its preimage: the seller's
    /// invoice for a hash of its own, every check and rule of the book ([`Signer::ticket_prepay`]),
    /// the payment, then `release` with the preimage the wallet's node got for it. Called with the
    /// session's `paying` lock held, so one is bought at a time.
    fn ticket_buy_prepaid(&self, hs: &HttpSession, spent: &mut Spent) -> std::result::Result<(), Value> {
        // the wallet's own node first: no invoice is asked for that the node could not then pay
        self.ticket_can_lock(&hs.terms.terms.payee)?;
        let body = json!({"version": xbt402::ticket::VERSION, "settle": xbt402::ticket::SETTLE_ON_ARRIVAL, "count": 1});
        let answer = self.ticket_lock_call(hs, body)?;
        let Some(first) = answer.get("tickets").and_then(Value::as_array).and_then(|a| a.first()) else {
            return Err(refusal("ticket_seller", "the seller issued no invoice for a prepaid ticket"));
        };
        let r = self.ticket_prepay(&json!({"session": hs.sid, "hash": first.get("hash"), "invoice": first.get("invoice")}));
        if r["verdict"] == "pending" {
            // booked, and neither paid nor failed by the node's word: nothing more is paid in this session
            return Err(self.ticket_fault(hs, "the payment of a prepaid ticket has no final answer from the wallet's node: it is booked as spent until the node shows it failed"));
        }
        if r["verdict"] != "allow" {
            return Err(r);
        }
        let (Some(secret), hash) = (r.get("ticket_secret").and_then(Value::as_str), str_or_empty(r.get("hash"))) else {
            return Err(refusal("ticket", "the book paid a prepaid ticket and returned no preimage"));
        };
        {
            let mut m = lock(&hs.money);
            m.acct.released(crate::ticket::outside_u64(r.get("ticket_msat")).unwrap_or(0));
            m.pending = Some((hash.clone(), Zeroizing::new(secret.to_string())));
        }
        spent.hashes.push(hash);
        spent.prepaid += 1;
        spent.booked_sats = spent.booked_sats.saturating_add(py_int(r.get("charged_sats")).unwrap_or(0));
        self.ticket_deliver(hs)
    }

    /// How many hashes the session's pool wants now, by the book (0 when the book cannot be read:
    /// nothing is offered on a guess).
    fn ticket_want(&self, sid: &str) -> usize {
        self.ticket_store().ok().and_then(|g| g.as_ref().and_then(|st| st.book.sessions.get(sid).map(|s| st.book.want(s, self.engine.now())))).unwrap_or(0)
    }

    /// Fill the pool behind a call, one refill of a session at a time.
    fn ticket_refill_later(&self, hs: &Arc<HttpSession>) {
        if self.ticket_want(&hs.sid) == 0 || hs.fault().is_some() || hs.refilling.swap(true, Ordering::SeqCst) {
            return;
        }
        let (Some(me), hs2) = (self.me.get().and_then(std::sync::Weak::upgrade), hs.clone()) else {
            hs.refilling.store(false, Ordering::SeqCst);
            return;
        };
        let spawned = std::thread::Builder::new().name("ticket-refill".into()).spawn(move || {
            // a refusal here is the next release's to report: it finds no ticket and says why. A release that came
            // while a round was out has left the pool at its mark again (with a pool of 2, every release does):
            // another round, a few at most, and none after a round that locked nothing
            for _ in 0..4 {
                if !matches!(me.ticket_fill(&hs2), Ok(n) if n > 0) || me.ticket_want(&hs2.sid) == 0 {
                    break;
                }
            }
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
                let due = if hs.streaming.load(Ordering::SeqCst) || m.tail.is_some() { Due::Balance } else { Due::AtMost(0) };
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
                // the seller has closed the answer the wallet stopped reading: its last receipt is listed
                let closed = m.tail.as_ref().is_some_and(|t| {
                    let sid = lock(&hs.link).seller_sid.clone();
                    v.get("responses").and_then(Value::as_array).into_iter().flatten().filter_map(|r| Receipt::verify(r, &hs.terms.receipt_key, &sid).ok())
                        .any(|r| r.for_request(t.seq, &t.digest, t.status).is_ok() && !r.body_hash.is_empty())
                });
                if closed {
                    m.tail = None;
                }
                Ok(v)
            }
            Ok((status, _, Ok(_))) => Err(format!("the seller answered status with HTTP {status}")),
            Ok((status, v, Err(why))) => Err(self.ticket_forgotten(hs, status, &v)
                                                 .unwrap_or_else(|| format!("the seller's answer to status (HTTP {status}) has no valid receipt: {why}"))),
            Err(e) => Err(e.msg),
        }
    }

    /// Mark the session faulty and stop it: nothing more is released to this seller in it.
    fn ticket_fault(&self, hs: &HttpSession, why: &str) -> Value {
        lock(&hs.money).fault.get_or_insert_with(|| why.to_string());
        // with the wallet's count as it stood, for the owner who has to judge the seller
        self.ticket_audit("ticket_seller_fault", json!({"session": hs.sid, "origin": hs.origin, "dest": format!("ln:{}", hs.terms.terms.payee), "reason": why,
                                                        "account": hs.public()}));
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
        // an answer the wallet stopped reading and the seller has not closed: a ticket released now would wake it, and
        // the seller would charge for bytes nobody reads. Its last receipt in `status` is the seller's word that it is closed
        let open_since = lock(&hs.money).tail.as_ref().map(|t| t.since);
        if let Some(since) = open_since {
            let deadline = Instant::now() + TAIL_WAIT;
            loop {
                if let Err(why) = self.ticket_status_of(hs, true) {
                    return Err(refusal(Self::status_rule(hs), format!("{why}: no secret was released")));
                }
                if lock(&hs.money).tail.is_none() {
                    break;
                }
                if since.elapsed() >= TAIL_GIVE_UP {
                    let stopped = self.ticket_http_stop(hs, "the seller never closed the answer the wallet stopped reading", Duration::ZERO);
                    return Err(with(refusal("ticket_answer_open", "the seller never closed the answer the wallet stopped reading: the session was stopped and no \
                                                                   secret was released; call again"), json!({"session": hs.sid, "stopped": stopped})));
                }
                if Instant::now() >= deadline {
                    return Err(with(refusal("ticket_answer_open", "the seller has not yet closed the answer the wallet stopped reading: no secret was released \
                                                                   into it; call again"), json!({"session": hs.sid})));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            if let Some(why) = hs.fault() {
                return Err(self.ticket_fault(hs, &why));
            }
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
            next = self.ticket_next(&hs.sid).0;
            if next.is_none() {
                // no held ticket, and none to be had now. Where the session holds nothing, or waits after a lock that
                // found no slot, the seller's prepaid tickets are the way to pay; a seller that offers none is
                // waited for, and after three rounds without a slot the session ends
                let now = self.engine.now();
                if let Some(s) = self.ticket_session(&hs.sid).filter(|s| s.state == SState::Open) {
                    if s.prepaid_now(now) {
                        return self.ticket_buy_prepaid(hs, spent);
                    }
                    if s.pool == 0 {
                        let why = if s.hold_why.is_empty() { ROUTE_FULL.to_string() } else { s.hold_why.clone() };
                        let stopped = self.ticket_http_stop(hs, &format!("{why}: no ticket can be held with this seller, and it offers no prepaid ones"), Duration::ZERO);
                        return Err(with(refusal(if HOLD_SHORT.contains(&why.as_str()) { ROUTE_FULL } else { "ticket_none" },
                                                format!("no ticket can be held with this seller ({why}) and its terms offer no prepaid tickets: the session was stopped; \
                                                         pay it another way, or again later")),
                                        json!({"session": hs.sid, "stopped": stopped, "retry_after_s": (s.hold_until - now).max(0.0).ceil()})));
                    }
                    if now < s.hold_until {
                        filled?;
                        return Err(with(refusal(if s.hold_why.is_empty() { "ticket_slots" } else { s.hold_why.as_str() },
                                                format!("no ticket is locked with this seller for another {:.0} s: the last lock found no free slot on the way, and \
                                                         the seller's terms offer no prepaid tickets", s.hold_until - now)),
                                        json!({"session": hs.sid, "retry_after_s": (s.hold_until - now).ceil()})));
                    }
                }
            }
            filled?;
        }
        let Some(mut hash) = next else {
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
                return Err(refusal(Self::status_rule(hs), format!("{why}: no secret was released")));
            }
            if lock(&hs.money).ready.contains(&hash) {
                break;
            }
            // the ticket may have failed since it was chosen: one that finds no slot at a later hop is in flight on the
            // wallet's node for a moment before the refusal is back. The node is asked, and the book's next ticket taken
            {
                let _g = self.lock();
                self.ticket_reconcile_locked();
            }
            match self.ticket_next(&hs.sid).0 {
                Some(h) if h == hash => {}
                Some(h) => {
                    hash = h;
                    continue;
                }
                None => {
                    let now = self.engine.now();
                    let s = self.ticket_session(&hs.sid).filter(|s| s.state == SState::Open);
                    if s.as_ref().is_some_and(|s| s.prepaid_now(now)) {
                        return self.ticket_buy_prepaid(hs, spent);
                    }
                    let wait = s.map_or(0.0, |s| (s.hold_until - now).max(0.0));
                    return Err(with(refusal("ticket_slots", "the ticket that was to be released failed on its way to the seller, as a channel without a free slot \
                                                             fails one: no secret was released"), json!({"session": hs.sid, "retry_after_s": wait.ceil()})));
                }
            }
            // stopped meanwhile (its tickets are being cancelled, so the seller will never show this one locked)
            if !self.ticket_session(&hs.sid).is_some_and(|s| s.state == SState::Open) {
                return Err(refusal("ticket_session", "the session was stopped: nothing more is released for it"));
            }
            if Instant::now() >= deadline {
                // a ticket the wallet's own node calls in flight and has on none of its channels (a node that was
                // killed as it sent it) never arrives: the seller will not show it, and it is the session's oldest,
                // so every release of the session would wait here. The session ends, and the next call opens
                // another; the ticket stays locked in the book for as long as the node calls it in flight
                if self.ticket_stranded(&hash) {
                    let stopped = self.ticket_http_stop(hs, "a ticket of the session is on none of the wallet's channels", Duration::ZERO);
                    return Err(with(refusal("ticket_session_ended", "a ticket of this session is on none of the channels of the wallet's Lightning node, though the node \
                                                                     calls its payment in flight: the seller cannot be shown it, so the session was stopped and no \
                                                                     secret was released; the next call opens another session"),
                                    json!({"session": hs.sid, "hash": hash, "stopped": stopped})));
                }
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
                            .map(|x| protocol_code(x.get("error"))).unwrap_or_default();
                        match code {
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
                    // (a session that was stopped here sends nothing again: the ticket stays booked until the wallet's node says what became of it)
                    Err(why) if hs.fault().is_some() => return Err(with(refusal(Self::status_rule(hs), format!("{why}: one released ticket is unconfirmed and stays booked until \
                                                                                                               the wallet's node shows what became of it")),
                                                                        json!({"session": hs.sid, "unconfirmed_release": hash}))),
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
                   "tickets_prepaid": spent.prepaid,
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
                    let code = protocol_code(v.get("error"));
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
                // an earlier answer the seller has not closed can still be charged or given back beside this one
                let due = if m.tail.is_some() { Due::Balance } else { due };
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
                let code = protocol_code(v.get("error"));
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
        let mut seller_last = Value::Null;
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
            let (m, note, last) = self.ticket_stream(hs, price, &head, seq, &digest, ans, started, max_msat, &mut sink, &mut spent);
            seller_last = last;
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
        if !seller_last.is_null() {
            out[UNTRUSTED_KEY]["last_receipt"] = seller_last;
        }
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
                     sink: &mut Sink, spent: &mut Spent) -> (Value, Value, Value) {
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
                        read_error = Some(format!("{:?}", e.kind()));
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
        if last.is_none() {
            lock(&hs.money).tail = Some(Tail { seq, digest: digest.to_string(), status: c_status(head), since: Instant::now() });
        }
        hs.streaming.store(false, Ordering::SeqCst);
        let mut fault = hs.fault();
        let mut seller_last = Value::Null;
        let note = match &last {
            None => json!({"signed": false, "last": Value::Null, "why": why_none}),
            Some(r) => {
                if complete && r.body_hash != own_digest {
                    fault.get_or_insert("the last receipt signs another body than the one that arrived".into());
                }
                if complete && r.charged > own_cost {
                    fault.get_or_insert(format!("the last receipt charges {} msat for an answer that costs {own_cost} by the seller's terms", r.charged));
                }
                // the receipt as the wallet read it: its numbers. The seller's own object is under the untrusted field.
                seller_last = r.raw.clone();
                json!({"signed": true, "last": {"seq": r.seq, "releasedMsat": r.released_msat.to_string(), "spentMsat": r.spent_msat.to_string(),
                                                "charged": r.charged.to_string(), "status": r.status},
                       "body": if !complete { "cut short" } else if r.body_hash == own_digest { "as signed" } else { "differs from the receipt" }})
            }
        };
        // the price of the answer: the seller's signed charge where it stands inside the wallet's own count, else that count
        let price_msat = last.as_ref().map(|r| r.charged).filter(|c| *c <= own_cost || !complete).unwrap_or_else(|| st.cost(sink.bytes));
        let mut m = json!({"complete": complete, "ended": ended, "price_msat": price_msat.to_string()});
        if let Some(why) = fault {
            m["seller_fault"] = self.ticket_fault(hs, &why)["reason"].clone();
        }
        (m, note, seller_last)
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
    /// `wait` has passed. Returns the hashes still locked; `Null` when the book could not be read,
    /// which is not "none".
    fn ticket_wait_cancelled(&self, sid: &str, wait: Duration) -> Value {
        let deadline = Instant::now() + wait;
        loop {
            {
                let _g = self.lock();
                self.ticket_reconcile_locked();
            }
            let left: Option<Vec<String>> = match self.ticket_store() {
                Ok(g) => g.as_ref().map(|st| st.book.of_session(sid).into_iter().filter(|t| t.state.unreleased()).map(|t| t.hash.clone()).collect()),
                Err(_) => None,
            };
            if left.as_ref().is_none_or(Vec::is_empty) || Instant::now() >= deadline {
                return left.map_or(Value::Null, |l| json!(l));
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
        // a session that pays by draws holds nothing: it is stopped, and the seller told
        if let Some(done) = self.draw_stop_by_id(&sid) {
            let _g = self.lock();
            return with(self.ticket_stop_locked(&json!({"session": sid})), json!({"http": done}));
        }
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
        self.ticket_audit("ticket_cancel_asked", json!({"session": s.id, "dest": format!("ln:{}", s.payee), "sent": sent, "still_locked": still.as_array().map(Vec::len)}));
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
        out.extend(self.draw_http_tick());
        out
    }

    /// What the wallet counts for each session it pays over HTTP: for `ticket_status` and `channels`.
    pub(crate) fn ticket_http_public(&self) -> Vec<Value> {
        let slots: Vec<Arc<Slot>> = lock(&self.ticket_http).values().cloned().collect();
        let mut out: Vec<Value> = slots.iter().filter_map(|s| s.open.try_lock().ok().and_then(|o| o.as_ref().map(|h| h.public()))).collect();
        out.extend(self.draw_http_public());
        out
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
            Err(e) => return Some(format!("cut short: {:?}", e.kind())),
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
