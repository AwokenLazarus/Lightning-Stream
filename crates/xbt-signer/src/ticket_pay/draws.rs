//! The lottery, the wallet pays a seller by draws over HTTP (`docs/TICKETS.md`, section 9): the
//! signer opens a session, sends the request, gives a value for every piece that arrived, checks
//! the seller's reveal, works out every draw itself, and pays a win with the seller's invoice
//! through the ticket rail. Nothing is locked with the seller at any time.
//!
//! The draw is [`xbt402::lottery`]'s; what may be paid is the book's ([`crate::ticket_rail`]); the
//! owner's bounds and the choice between tickets and draws are [`crate::lottery`]'s. This module is
//! the IO between them.
//!
//! **Each rule, and every place that could break it:**
//!
//! | Rule | Where it is kept |
//! |---|---|
//! | A win is one the signer worked out itself. | [`Signer::draw_round`] is the only caller of [`xbt402::lottery::Buyer::absorb`], and a payment needs the [`Win`] that makes ([`Signer::lottery_pay_win`]). The agent passes a URL and a limit; no message of a seller's and no argument of a caller's says "this won". |
//! | A value follows the piece it is for, and is random. | [`Signer::draw_stream`] and [`Signer::draw_request`] queue a piece only when all of it has arrived (and, where the caller gave its hash, checked out); [`Signer::draw_round`] makes each value from the operating system's random source at that moment. |
//! | One value per draw, ever. | [`xbt402::lottery::Buyer::issue`] numbers draws and keeps each value until a reveal covers it; a round that got no answer sends the same values again. A session lives in this process only: a signer that starts again has no session to resend into. |
//! | A seller that takes values and reveals nothing gets no more. | [`xbt402::lottery::Buyer::issue`] refuses beyond `tickets.lottery.ahead` values without a checked reveal; the session ends as faulty. |
//! | A win that is handed out has a payer. | Every caller of [`Signer::draw_round`] gives the wins it returns to [`Signer::draw_pay`], the round that names void pieces through [`Signer::draw_pay_late`], which puts back as owed what a halted call does not pay. |
//! | A win is paid once, by its own invoice, after every check of an invoice. | [`Signer::draw_pay`]: a draw is handed to the payer once (`State::handed`); the book refuses a second payment for a win and a second payment for a hash; the invoice must name the seller's node, the session's win size and its CLTV delta, carry bit 512 and a payment secret, and not be expired. |
//! | What is booked is what the node paid. | The ledger rows are the book's, written before a payment is sent and made exact when the node shows it settled. A seller's `wonMsat` or `paidMsat` moves nothing. |
//! | A call uses at most its charge cap (`max_charge_sats`, else `max_sats`) by the wallet's own count, and pays at most the luck cap above it. | [`Signer::draw_stream`] stops reading when the pieces it gave values for cost that cap, or when the wins of the call reach [`xbt402::lottery::luck_cap_msat`]; the task's budget and the caps per seller refuse a payment whatever the draws did. |
//! | At most 8 payments are with the router at once. | Every win goes through [`crate::ticket_rail::Pace`], with every ticket. |
//! | A win the seller's answer stands still for is paid before the wins no seller waits for. | [`Signer::draw_hurry`], by the wallet's own count against the seller's terms (`maxUnpaidWins`, `gracePieces`): while an answer is being read, and for a request the seller refused `win_unpaid`. A seller's word moves no payment forward. |
//! | No request leaves for a host the owner did not allow, and none over a channel others can read. | [`Signer::ticket_may_reach`] before every request; `private_channel` before a session is opened (the session key comes back in the open's answer). |
//!
//! Locks: a session's `busy` (one paid request at a time), then `link` (one HTTP exchange at a
//! time, in `seq` order), then `state`. The wallet's spend lock is taken with none of them held.
use xbt402::lottery::{self, Buyer, DrawError, Kind, Piece, PieceId, Win};

use super::*;
use crate::keystore::random_bytes;
use crate::lottery::DrawTerms;

/// Refusals of opening a session of draws that mean "not this way": the next entry of the 402 is tried.
const NEXT_WAY: [&str; 10] = ["lottery_disabled", "ticket_disabled", "ln_disabled", "ticket_task", "ticket_admission", "lottery_terms", "ticket_feature_512",
                              "ticket_network", "lottery_win_size", "ticket_blocks"];
/// How often a round is tried again when the seller gave no answer or did not know a piece yet.
const ROUND_TRIES: usize = 6;
/// How long the last pieces of an answer wait for the seller to know them.
const ROUND_WAIT: Duration = Duration::from_millis(40);
/// How long the drawer goes on once the answer has ended: for the reveals of the values still open
/// and the invoices of the wins owed. A seller that gives neither in this time is given up on.
const DONE_WAIT: Duration = Duration::from_secs(60);
/// How long a call waits behind an answer open on its session of draws: under the 60 s a caller of
/// the signer's socket waits.
const QUEUE_WAIT: Duration = Duration::from_secs(50);
/// An answer open this long may run for hours: a call behind it is told at once, and does not hold
/// its caller, and a handler of the connector's, for [`QUEUE_WAIT`].
const LONG_HOLD: Duration = Duration::from_secs(30);
/// How long a stop waits for the answer open on its session of draws to end.
const STOP_WAIT: Duration = Duration::from_secs(15);
/// How long a call waits for the seller's next invoice of a win whose last one is about to lapse or has:
/// the seller makes the next one only when its node shows the first cancelled, and the wallet refuses an
/// invoice within 5 s of its end. An invoice with longer to live than this is not waited for.
const OWED_WAIT: Duration = Duration::from_secs(10);
const OWED_POLL: Duration = Duration::from_millis(250);
/// How many of a win's invoices, and of a session's, the wallet asks to have cancelled after failed payments.
/// Past these it waits for them to lapse: a seller's node that fails every payment is not asked for ever.
const CANCELS_PER_WIN: u32 = 4;
/// How many times a win is refused for a seller that has been without a route for a whole window (not while
/// another payment to it waits for one) before the call gives up on that seller.
const NO_ROUTE_PER_WIN: u32 = 3;
const CANCELS_PER_SESSION: u32 = 32;
/// How many of a win's invoices, and of a session's, may run out in the wallet's queue before it stops asking.
const LAPSES_PER_WIN: u32 = 4;
const LAPSES_PER_SESSION: u32 = 32;

fn refused(rule: &str, reason: impl Into<String>) -> Value {
    with(deny(rule, reason), json!({"rail": "lottery", "charged_sats": 0}))
}

/// A seller's signed receipt of a lottery session, after its signature and its session were checked.
#[derive(Debug, Clone)]
struct DrawReceipt {
    seq: u64,
    charged: u64,
    status: u64,
    req: String,
    /// Empty on the head of an answer that is sent as it arrives.
    body_hash: String,
    raw: Value,
}

impl DrawReceipt {
    fn verify(r: &Value, key: &[u8], session: &str) -> std::result::Result<Self, String> {
        if !r.is_object() {
            return Err("no receipt".into());
        }
        let sig = hex::decode(str_or_empty(r.get("sig"))).map_err(|_| "the receipt's signature is not hex".to_string())?;
        if !xbt_primitives::ecdsa::verify(key, &lottery::receipt_message(r), &sig) {
            return Err("the receipt is not signed by the receipt key of the seller's terms".into());
        }
        if str_or_empty(r.get("scheme")) != lottery::SCHEME || str_or_empty(r.get("session")) != session {
            return Err("the receipt is for another session".into());
        }
        let num = |k: &str| crate::ticket::outside_u64(r.get(k)).ok_or(format!("the receipt's {k} is not a whole number"));
        Ok(Self { seq: num("seq")?, charged: num("charged")?, status: num("status")?, req: str_or_empty(r.get("req")), body_hash: str_or_empty(r.get("bodyHash")),
                  raw: r.clone() })
    }

    /// The receipt of the answer to one request: for this `seq`, this request digest and the
    /// status the answer came with, or it is an answer to another request.
    fn read(header: Option<&str>, key: &[u8], session: &str, seq: u64, digest: &str, status: u16) -> std::result::Result<Self, String> {
        let sr = unb64json(header.ok_or("the answer has no PAYMENT-RESPONSE")?).map_err(|_| "PAYMENT-RESPONSE is not base64 JSON".to_string())?;
        let r = Self::verify(sr.get("extra").and_then(|e| e.get("receipt")).unwrap_or(&Value::Null), key, session)?;
        if r.seq != seq || r.req != digest {
            return Err("the receipt is for another request".into());
        }
        if r.status != u64::from(status) {
            return Err(format!("the receipt is for status {}, the answer came with {status}", r.status));
        }
        Ok(r)
    }
}

/// What the wallet counts of one session of draws. All of it is its own: no number of the seller's.
#[derive(Default)]
struct State {
    /// None until the seller has answered the open.
    buyer: Option<Buyer>,
    /// Wins the wallet found that no payer has taken yet (the seller sent no invoice for them).
    owed: Vec<Win>,
    /// Wins that were handed to the payer, by their draw, and whether the payer came back with a payment that
    /// was not final yet. None is handed again while its payment is being made, or is in the book and has not
    /// failed.
    handed: HashMap<u64, (Win, bool)>,
    /// Invoices the payer has been given, each by 16 bytes of its SHA-256: one is looked at once, whatever
    /// became of it. One entry for every try of a win, so at most as many as the session has rounds.
    tried: HashSet<[u8; 16]>,
    /// The draws of the wins a payer has now: it has not come back with what became of the payment.
    paying: HashSet<u64>,
    draws: u64,
    wins: u64,
    wins_paid: u64,
    /// The price of every piece a value was given for, in msat, and what the wins paid booked, in sats.
    used_msat: u64,
    paid_sats: i64,
    /// Invoices of this seller's that the wallet's checks refused (another payee, another amount, no bit 512).
    bad_invoices: u32,
    /// Invoices that came with less time left than any prepaid invoice must have: no queue of the wallet's
    /// had a part in that, and each counts against the seller.
    dead_on_arrival: HashSet<[u8; 16]>,
    /// How many of a win's invoices, and of the session's, ran out in the wallet's queue.
    lapses: HashMap<u64, u32>,
    lapsed: u32,
    /// How many times a win was refused for no route to the seller.
    no_route: HashMap<u64, u32>,
    /// How many invoices the seller has been asked to cancel, by win and in all, and that it will not
    /// (one of an earlier version, or at its own limit).
    cancels: HashMap<u64, u32>,
    cancels_asked: u32,
    no_cancel: bool,
    /// Wins whose invoice ran out or whose payment failed: their next invoice goes before the wins no seller
    /// waits for. Behind them it can run out too: on an 8 GB lab, a win lapsed twice waiting behind wins of 100 sellers.
    again: HashSet<u64>,
    /// When the wallet first had each win to pay, on its clock: the seller's grace for it runs from about then,
    /// and the gate pays the win in that order ([`crate::ticket_rail::Pace::enter_for`]).
    seen_at: HashMap<u64, f64>,
    /// Invoices to ask the seller to cancel, before its list is next asked for.
    to_cancel: Vec<(u64, String)>,
    /// When the latest invoice of a win that is owed again ends: the seller's next one comes after that.
    next_invoice_after: f64,
    /// Why this session draws no more.
    fault: Option<String>,
}

/// A session the wallet pays by draws. In memory only: a signer that starts again has stopped
/// every session (the book's rule), and a win it had not paid stays unpaid.
pub(crate) struct DrawSession {
    pub origin: String,
    /// The book's session, and the owner's task it was opened under.
    pub sid: String,
    task: String,
    terms: DrawTerms,
    win_msat: u64,
    /// The URL of the session endpoints: the origin and the terms' path.
    base: String,
    busy: Mutex<()>,
    /// A stop has begun: the answer open now ends here, no new value is given, and no new request starts.
    ending: AtomicBool,
    /// When the answer open now started: a call behind one open a while is told at once ([`LONG_HOLD`]).
    answer_since: Mutex<Option<Instant>>,
    link: Mutex<Link>,
    state: Mutex<State>,
    /// The wallet's clock at the last paid request.
    used: Mutex<f64>,
}

impl DrawSession {
    fn fault(&self) -> Option<String> {
        lock(&self.state).fault.clone()
    }

    pub(crate) fn public(&self) -> Value {
        let s = lock(&self.state);
        json!({"session": self.sid, "origin": self.origin, "rail": "lottery", "win_msat": self.win_msat.to_string(), "draws": s.draws, "wins": s.wins,
               "wins_paid": s.wins_paid, "wins_owed": s.owed.len(), "price_msat": s.used_msat.to_string(), "paid_sats": s.paid_sats, "fault": s.fault})
    }
}

/// The session's turn, within `wait`. `behind_answer`: a call, which gives up at once on an answer
/// that has been open past [`LONG_HOLD`]; a stop waits its time out.
fn turn_of(ds: &DrawSession, wait: Duration, behind_answer: bool) -> Option<MutexGuard<'_, ()>> {
    let until = Instant::now() + wait;
    loop {
        match ds.busy.try_lock() {
            Ok(g) => return Some(g),
            Err(std::sync::TryLockError::Poisoned(p)) => return Some(p.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => {}
        }
        let long = behind_answer && lock(&ds.answer_since).is_some_and(|t| t.elapsed() >= LONG_HOLD);
        if long || Instant::now() >= until {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// What a session remembers of an invoice it has handed to the payer.
fn invoice_mark(invoice: &str) -> [u8; 16] {
    let mut m = [0u8; 16];
    m.copy_from_slice(&Sha256::digest(invoice.as_bytes())[..16]);
    m
}

/// The refusals of wins a call's reply lists: more than this are not listed.
const UNPAID_LISTED: usize = 64;
/// A seller whose invoices fail the wallet's checks this many times is not asked for another.
const BAD_INVOICES_MAX: u32 = 3;

/// What one round of values came to.
struct Round {
    /// Wins found, each with the seller's invoice for it where it sent one.
    wins: Vec<(Win, Option<String>)>,
    /// The seller did not answer, or did not know a piece yet: the same values are sent again.
    again: bool,
    /// Pieces given no value in this round: as many values wait for a reveal as the owner's
    /// `tickets.lottery.ahead` allows. They go back to the front of what is pending.
    left: Vec<Piece>,
}

/// What one call counted: for its reply.
#[derive(Default)]
struct Counted {
    price_msat: u64,
    draws: u64,
    wins: u64,
    wins_paid: u64,
    paid_sats: i64,
    fee_msat: u64,
    /// Wins that were not paid, each with the refusal's rule.
    unpaid: Vec<Value>,
    /// Why the wallet asked for no more pieces, if it stopped.
    stop: Option<String>,
    /// No further value is given in this call: a win could not be paid inside the owner's bounds,
    /// or the call's wins reached its luck cap. Pieces that arrived get no draw from here on.
    halt: bool,
}

impl Signer {
    /// The open session of draws of a book session, if this process has one.
    fn draw_http_of(&self, sid: &str) -> Option<Arc<DrawSession>> {
        lock(&self.draw_http).values().find(|d| d.sid == sid).cloned()
    }

    /// What the wallet counts for each session it pays by draws: for `ticket_status`.
    pub(crate) fn draw_http_public(&self) -> Vec<Value> {
        lock(&self.draw_http).values().map(|d| d.public()).collect()
    }

    /// Pay one request by draws: read the entry, find or open the session with this seller, send
    /// the request, and give a value for every piece that arrives.
    pub(super) fn lottery_pay(&self, c: &Call, acc: &Value, lightning: &str) -> Tried {
        let terms = match DrawTerms::parse(acc, lightning) {
            Ok(t) => t,
            Err((rule, why)) => return Tried::Next(format!("{rule}: {why}")),
        };
        // a seller caught over-charging is paid no draw until the owner lifts the block
        let rk = hex::encode(&terms.receipt_key);
        if let Some(b) = self.seller_blocks.get(&crate::seller_block::Seller { payee: &terms.payee, receipt_key: &rk, origin: c.origin }) {
            return Tried::Done(with(deny("seller_blocked", format!("this seller was caught charging more than it delivered ({}) and is blocked: \
                                                                   the owner can unblock it on the Spending rules page",
                                                                  b["reason"].as_str().unwrap_or_default())), json!({"seller_blocked": b["id"]})));
        }
        if !private_channel(c.origin) {
            return Tried::Next("draws are paid over https, or over http to this machine only (127.0.0.1, ::1, localhost): on a plain connection a \
                                listener learns the session key".into());
        }
        for attempt in 0..2 {
            let existing = lock(&self.draw_http).get(c.origin).cloned();
            // a session the book no longer holds open (stopped by the agent, idle, a fault) is gone
            let existing = match existing {
                Some(d) if d.fault().is_some() || !self.ticket_session(&d.sid).is_some_and(|s| s.state == SState::Open) => {
                    self.draw_stop(&d, "its session ended", false);
                    None
                }
                other => other,
            };
            let ds = match existing {
                Some(d) if !d.terms.same_seller(&terms) => {
                    let stopped = self.draw_stop(&d, "the seller's terms changed", true);
                    return Tried::Done(with(refused("ticket_terms_changed", "the seller's 402 now names another node, receipt key, win size or session path than the \
                                                                             session was opened on: the session was stopped and nothing was paid; call again to pay on the \
                                                                             new terms, if the owner's policy allows them"), json!({"stopped": stopped})));
                }
                Some(d) => d,
                None => match self.draw_open(c, acc, &terms) {
                    Ok(d) => d,
                    Err(tried) => return tried,
                },
            };
            let out = {
                // one answer at a time on a session of draws, and one streamed on may run for hours: a call behind it is
                // told so, in the time a caller waits, and not left queued
                let Some(_busy) = turn_of(&ds, QUEUE_WAIT, true) else {
                    return Tried::Done(refused("ticket_busy", "another answer from this seller is open on a session of draws, which takes one at a time: call again when it ends"));
                };
                if ds.ending.load(Ordering::SeqCst) {
                    return Tried::Done(refused("ticket_busy", "the session with this seller is being stopped: nothing was asked of the seller in it; call again"));
                }
                self.draw_request(&ds, c, &terms.price)
            };
            // a seller that has forgotten the session (it went quiet, or the seller started again without its journal): this one is over, and
            // the call is made once more on a new one. Nothing was served for the request that found it gone
            if out.get("rule").and_then(Value::as_str) == Some("lottery_session_ended") && attempt == 0 {
                continue;
            }
            return Tried::Done(out);
        }
        Tried::Done(refused("lottery_session_ended", "the seller forgot the session twice in a row: call again"))
    }

    /// Open a session of draws: the book's rules first, then the seller's `open`, then the seller's
    /// side into the book. Nothing is paid.
    fn draw_open(&self, c: &Call, acc: &Value, terms: &DrawTerms) -> std::result::Result<Arc<DrawSession>, Tried> {
        let task = c.task.clone().map_err(Tried::Next)?;
        let base = seller_url(c.origin, &terms.session_path).map_err(|e| Tried::Next(e.msg))?;
        let o = {
            let _g = self.lock();
            self.lottery_open_locked(&json!({"terms": acc, "task": &task, "origin": c.origin, "expect_sats": c.charge_sats}))
        };
        if o["verdict"] != "allow" {
            let rule = str_or_empty(o.get("rule"));
            return Err(if NEXT_WAY.contains(&rule.as_str()) { Tried::Next(format!("{rule}: {}", str_or_empty(o.get("reason")))) } else { Tried::Done(o) });
        }
        let sid = str_or_empty(o.get("session"));
        let win_msat = crate::ticket::outside_u64(o.get("win_msat")).unwrap_or(0);
        let ds = Arc::new(DrawSession { origin: c.origin.into(), sid: sid.clone(), task, terms: terms.clone(), win_msat, base, busy: Mutex::new(()), ending: AtomicBool::new(false), answer_since: Mutex::new(None),
                                        link: Mutex::new(Link::new(String::new(), [0u8; 32], 0)),
                                        state: Mutex::new(State::default()), used: Mutex::new(self.engine.now()) });
        let give_up = |why: String| {
            let stopped = self.draw_stop(&ds, &why, false);
            Tried::Done(with(refused("lottery_open", format!("no session of draws was opened with this seller: {why}")), json!({"stopped": stopped})))
        };
        // the seller's side: its name for the session, the session key and the anchor of its chain
        // `canCancel`: this wallet asks the seller to cancel a failed win's invoice (`cancel`), so its next one comes at once and
        // the seller may give invoices that outlive the grace. A seller before 0.2.0 ignores it
        let body = json!({"version": lottery::VERSION, "winMsat": win_msat.to_string(), "canCancel": true}).to_string().into_bytes();
        let url = format!("{}/open", ds.base);
        let ans = match self.wire("POST", &url, &body, &[("Content-Type".into(), "application/json".into())], Self::ticket_read_timeout(&self.ticket_policy())) {
            Ok(a) => a,
            Err(e) => return Err(give_up(format!("the seller gave no answer to the open: {}", e.msg))),
        };
        let status = ans.status;
        let v: Value = ans.read_small(SMALL_BODY).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
        if status != 200 {
            return Err(give_up(format!("the seller refused the open: HTTP {status} {}", protocol_code(v.get("error")))));
        }
        let seller_sid = str_or_empty(v.get("session"));
        let key: Option<[u8; 32]> = xbt402::ticket::hex32(&str_or_empty(v.get("key")));
        let anchor = xbt402::ticket::hex32(&str_or_empty(v.get("anchor")));
        let (Some(key), Some(anchor)) = (key, anchor) else { return Err(give_up("the open's answer has no session key or no anchor".into())) };
        // the size and the chain are the ones the terms and the wallet said, or the draws would be at other odds
        if crate::ticket::outside_u64(v.get("winMsat")) != Some(win_msat) || v.get("chainDraws").and_then(Value::as_u64) != Some(u64::from(terms.chain_draws)) {
            return Err(give_up("the open's answer names another win size or chain length than was asked for".into()));
        }
        let buyer = match Buyer::new(&seller_sid, win_msat, anchor, terms.chain_draws) {
            Ok(b) => b,
            Err(e) => return Err(give_up(format!("the open's answer cannot be drawn on: {e}"))),
        };
        // into the book before the first value: the seller's name for the session is what a win is checked against
        if let Err(e) = self.lottery_bind(&sid, &seller_sid, &hex::encode(anchor)) {
            return Err(give_up(e.msg));
        }
        *lock(&ds.link) = Link::new(seller_sid, key, 0);
        lock(&ds.state).buyer = Some(buyer);
        let mut map = lock(&self.draw_http);
        if map.contains_key(c.origin) {
            drop(map);
            return Err(give_up("another call opened a session with this seller meanwhile: call again".into()));
        }
        map.insert(c.origin.to_string(), ds.clone());
        Ok(ds)
    }

    /// One authenticated request of the session, in `seq` order: the status, the receipt (or why
    /// there is none), and the answer with its body still to be read. `Err`: no answer came.
    /// `extra`: the headers beside the payment's (a session endpoint's `Content-Type`, the call's `Range`).
    fn draw_send(&self, ds: &DrawSession, method: &str, url: &str, body: &[u8], extra: Vec<(String, String)>)
                 -> Result<(u64, String, WireAnswer, std::result::Result<DrawReceipt, String>)> {
        if !self.ticket_may_reach(&ds.origin, &ds.task) {
            return Err(err("allowlist", format!("destination not on allowlist: {}", ds.origin)));
        }
        let timeout = Self::ticket_read_timeout(&self.ticket_policy());
        let mut link = lock(&ds.link);
        let (seq, digest) = (link.next_seq, request_digest_v2(method, url, body));
        let auth = lottery::request_auth(&link.key, &link.seller_sid, seq, &digest);
        let mut headers = vec![("PAYMENT-SIGNATURE".to_string(), b64json(&payment_payload(&ds.terms.accepted, &json!({"session": link.seller_sid, "seq": seq, "auth": auth}))))];
        headers.extend(extra);
        let sent = self.wire(method, url, body, &headers, timeout);
        // the seq is used up once the request has left, answered or not; but not by a 408, which the seller's HTTP
        // layer gives before any of its handlers sees the request ([`unsigned_and_no_fault`]): the next request takes it
        // again (`link` is held, so no other has)
        let late = sent.as_ref().is_ok_and(|a| a.status == 408);
        link.next_seq = if late { seq } else { seq.saturating_add(1) };
        let ans = sent?;
        let receipt = DrawReceipt::read(ans.header("PAYMENT-RESPONSE"), &ds.terms.receipt_key, &link.seller_sid, seq, &digest, ans.status);
        Ok((seq, digest, ans, receipt))
    }

    /// A request to a session endpoint, with the seller's `nextSeq` adopted where it expects another.
    fn draw_call(&self, ds: &DrawSession, what: &str, body: &Value) -> Result<(u16, Value, std::result::Result<DrawReceipt, String>)> {
        let url = format!("{}/{what}", ds.base);
        let raw = body.to_string().into_bytes();
        let mut late = 0;
        for _ in 0..4 {
            let (_, _, ans, receipt) = self.draw_send(ds, "POST", &url, &raw, vec![("Content-Type".into(), "application/json".into())])?;
            let status = ans.status;
            let v: Value = serde_json::from_slice(&ans.read_small(SMALL_BODY)?).unwrap_or(Value::Null);
            // the seller's HTTP layer gave up on it (408): nothing was served, and the same request goes once more
            if receipt.is_err() && status == 408 && late == 0 {
                late += 1;
                continue;
            }
            if receipt.is_err() && status == 402 && v.get("error").and_then(Value::as_str) == Some("bad_seq") {
                // a seq only orders requests: the seller's is adopted, which costs nothing
                if let Some(n) = v.get("nextSeq").and_then(Value::as_u64) {
                    lock(&ds.link).next_seq = n;
                    continue;
                }
            }
            return Ok((status, v, receipt));
        }
        Err(err("ticket_seller", "the seller keeps answering bad_seq"))
    }

    /// Mark the session faulty and stop it: no further value is given and no further win is looked for.
    fn draw_fault(&self, ds: &DrawSession, why: &str) -> Value {
        lock(&ds.state).fault.get_or_insert_with(|| why.to_string());
        self.ticket_audit("lottery_seller_fault", json!({"session": ds.sid, "origin": ds.origin, "dest": format!("ln:{}", ds.terms.payee), "reason": why,
                                                         "account": ds.public()}));
        let stopped = self.draw_stop(ds, &format!("seller fault: {why}"), false);
        with(refused("lottery_seller_fault", format!("the session with this seller was stopped: {why}")), json!({"session": ds.sid, "stopped": stopped}))
    }

    /// Stop a session of draws: it leaves this process's sessions, the book stops it, and with
    /// `tell` the seller is told to forget it. There is nothing to cancel: nothing was held.
    pub(crate) fn draw_stop(&self, ds: &DrawSession, why: &str, tell: bool) -> Value {
        {
            let mut map = lock(&self.draw_http);
            if map.get(&ds.origin).is_some_and(|d| d.sid == ds.sid) {
                map.remove(&ds.origin);
            }
        }
        let told = tell && !lock(&ds.link).seller_sid.is_empty() && matches!(self.draw_call(ds, "close", &json!({})), Ok((200, _, _)));
        {
            let _g = self.lock();
            self.ticket_stop_locked(&json!({"session": ds.sid, "why": why}));
        }
        json!({"session": ds.sid, "why": why, "seller_told": told, "account": ds.public()})
    }

    /// `ticket_stop` for a session of draws, if `sid` is one this process pays.
    pub(super) fn draw_stop_by_id(&self, sid: &str) -> Option<Value> {
        let ds = self.draw_http_of(sid)?;
        // said before any lock: the answer open now sees it, and ends
        ds.ending.store(true, Ordering::SeqCst);
        // its wins already drawn are paid as it ends; a stop does not wait on that past STOP_WAIT
        let _busy = turn_of(&ds, STOP_WAIT, false);
        Some(self.draw_stop(&ds, "stopped by the caller", true))
    }

    /// The watcher's round for sessions of draws: one that has been idle is stopped.
    pub(super) fn draw_http_tick(&self) -> Vec<Value> {
        let tp = self.ticket_policy();
        let now = self.engine.now();
        let all: Vec<Arc<DrawSession>> = lock(&self.draw_http).values().cloned().collect();
        let mut out = vec![];
        for ds in all {
            let idle = now - *lock(&ds.used);
            let Ok(_busy) = ds.busy.try_lock() else { continue };
            if idle > tp.http_idle_s.max(1) as f64 {
                out.push(json!({"lottery_idle_stop": self.draw_stop(&ds, &format!("idle for {idle:.0} s"), true)}));
            }
        }
        out
    }

    /// Give a value for each of `pieces`, send every value no reveal covers yet, check the seller's
    /// reveal and work out every draw it covers. `Err`: the session is faulty (the refusal), and
    /// was stopped. This is the only place a [`Win`] comes from.
    fn draw_round(&self, ds: &DrawSession, pieces: &[Piece], voids: &[PieceId], ask: bool, counted: &Mutex<Counted>) -> std::result::Result<Round, Value> {
        self.draw_cancel_failed(ds);
        let ahead = self.ticket_policy().lottery.ahead.max(1) as u64;
        let mut left: Vec<Piece> = vec![];
        let values: Vec<Value> = {
            let mut s = lock(&ds.state);
            let st = &mut *s;
            let Some(buyer) = st.buyer.as_mut() else { return Err(refused("lottery_session", "the session has no seller side yet")) };
            for id in voids {
                buyer.void(*id);
            }
            for p in pieces {
                // no more values beyond the last reveal than the owner allows, however many pieces came at once: the rest
                // wait for the next round, which this one's reveal makes room for
                if buyer.open().count() as u64 >= ahead {
                    left.push(*p);
                    continue;
                }
                // fresh random bytes of the wallet's own, made now: after the piece arrived, and from nothing the seller has seen
                match buyer.issue(*p, random_bytes::<32>(), ahead) {
                    Ok(_) => {
                        st.draws += 1;
                        st.used_msat = st.used_msat.saturating_add(p.amount_msat);
                        let mut c = lock(counted);
                        c.draws += 1;
                        c.price_msat = c.price_msat.saturating_add(p.amount_msat);
                    }
                    Err(e) => {
                        drop(s);
                        return Err(self.draw_fault(ds, &format!("no value could be given for a piece: {e}")));
                    }
                }
            }
            buyer.open().map(|(d, p, v)| json!({"draw": d, "seq": p.id.seq, "kind": p.id.kind.name(), "k": p.id.k, "amountMsat": p.amount_msat.to_string(),
                                                "value": hex::encode(v)})).collect()
        };
        // with nothing to send, the seller is asked only where the caller wants its list of unpaid wins (`ask`)
        if values.is_empty() && voids.is_empty() && !ask {
            return Ok(Round { wins: vec![], again: false, left });
        }
        let void: Vec<Value> = voids.iter().map(|id| json!({"seq": id.seq, "kind": id.kind.name(), "k": id.k})).collect();
        let (status, v, receipt) = match self.draw_call(ds, "draw", &json!({"values": values, "void": void})) {
            Ok(x) => x,
            // no answer: the values are kept, and the same ones are sent again
            Err(_) => return Ok(Round { wins: vec![], again: true, left }),
        };
        if let Err(why) = &receipt {
            let code = protocol_code(v.get("error"));
            if unsigned_and_no_fault(status) {
                return Ok(Round { wins: vec![], again: true, left });
            }
            if code == "session_unknown" {
                self.draw_stop(ds, "the seller has forgotten the session", false);
                return Err(refused("lottery_session_ended", "the seller has forgotten this session: it ended, and the pieces it was served last have no draw"));
            }
            return Err(self.draw_fault(ds, &format!("an answer to a draw (HTTP {status} {code}) without a valid receipt: {why}")));
        }
        if status != 200 {
            return Err(self.draw_fault(ds, &format!("the seller refused a draw request: HTTP {status} {}", protocol_code(v.get("error")))));
        }
        // the reveal, checked against the chain; every draw it covers, worked out here
        let mut found: Vec<Win> = vec![];
        if let Some(reveal) = v.get("reveal").and_then(Value::as_str) {
            let Some(reveal) = xbt402::ticket::hex32(reveal) else { return Err(self.draw_fault(ds, "the seller's reveal is not 32 bytes")) };
            let drawn = v.get("drawn").and_then(Value::as_u64).unwrap_or(0);
            let absorbed = lock(&ds.state).buyer.as_mut().map(|b| b.absorb(drawn, &reveal));
            match absorbed {
                Some(Ok(outcomes)) => found.extend(outcomes.into_iter().filter_map(|o| o.win)),
                Some(Err(e)) => return Err(self.draw_fault(ds, &format!("the seller's reveal failed the wallet's check ({}): {e}", e.code()))),
                None => {}
            }
        }
        let refusal = v.get("refused").filter(|r| !r.is_null()).map(|r| protocol_code(r.get("error")));
        let again = match refusal {
            None => false,
            // the seller marks a piece when its last bytes leave, and the wallet may have them a moment earlier
            Some(code) if code == DrawError::PieceUnknown.code() => true,
            Some(code) => return Err(self.draw_fault(ds, &format!("the seller refused a value the wallet gave for a piece it received: {code}"))),
        };
        // pieces waited for room, and the seller took every value and revealed none of them: it gets no more
        if !left.is_empty() && !again && lock(&ds.state).buyer.as_ref().is_some_and(|b| b.open().count() as u64 >= ahead) {
            return Err(self.draw_fault(ds, &format!("the seller has {ahead} values and reveals for none of them: no value is given for a further piece")));
        }
        // the seller's list of unpaid wins: an invoice counts only for a draw the wallet itself found won
        // a win that was handed to the payer and whose payment the book now shows failed (a payment that was not
        // final when the payer stopped waiting, and that the wallet's node then failed or never had) is owed again
        let listed: Vec<u64> = v.get("wins").and_then(Value::as_array).into_iter().flatten().filter_map(|w| w.get("draw").and_then(Value::as_u64)).take(64).collect();
        let lapsed: Vec<u64> = {
            let s = lock(&ds.state);
            listed.iter().copied().filter(|d| s.handed.get(d).is_some_and(|(_, not_final)| *not_final)).collect()
        };
        let lapsed: Vec<u64> = lapsed.into_iter().filter(|d| !self.lottery_win_live(&ds.sid, *d)).collect();
        let mut s = lock(&ds.state);
        for d in lapsed {
            if let Some((w, _)) = s.handed.remove(&d) {
                s.owed.push(w);
            }
        }
        s.wins += found.len() as u64;
        lock(counted).wins += found.len() as u64;
        s.owed.extend(found);
        let mut invoices: Vec<(u64, String)> = vec![];
        let mut lied: Option<String> = None;
        for w in v.get("wins").and_then(Value::as_array).into_iter().flatten().take(64) {
            let (Some(draw), invoice) = (w.get("draw").and_then(Value::as_u64), w.get("invoice").and_then(Value::as_str)) else { continue };
            let mine = s.owed.iter().any(|o| o.draw() == draw);
            if !mine && !s.handed.contains_key(&draw) {
                lied.get_or_insert(format!("the seller lists draw {draw} as a win that no reveal it gave shows: the wallet pays only wins it can check"));
                continue;
            }
            match invoice {
                // an invoice the payer has had before is not looked at again: its payment is in the book, or its checks refused it
                Some(inv) if s.tried.contains(&invoice_mark(inv)) => {}
                Some(inv) if mine && invoices.iter().any(|(d, _)| *d == draw) => {
                    // booked exactly: the first invoice of a win is the one that is looked at, a second is refused unread
                    self.ticket_audit("lottery_win_refused", json!({"session": ds.sid, "dest": format!("ln:{}", ds.terms.payee), "win": draw,
                                                                    "rule": "lottery_win_paid", "reason": "a second invoice for one win in one answer",
                                                                    "invoice_bytes": inv.len()}));
                }
                Some(inv) if mine => invoices.push((draw, inv.chars().take(4096).collect())),
                _ => {}
            }
        }
        let mut wins = vec![];
        let owed = std::mem::take(&mut s.owed);
        for w in owed {
            match invoices.iter().find(|(d, _)| *d == w.draw()) {
                Some((d, inv)) => {
                    s.handed.insert(*d, (w.clone(), false));
                    s.tried.insert(invoice_mark(inv));
                    if crate::bolt11::decode(inv).is_ok_and(|i| (i.expires_at() as f64) - self.engine.now() < crate::ticket::PREPAID_EXPIRY_MARGIN_S) {
                        s.dead_on_arrival.insert(invoice_mark(inv));
                    }
                    wins.push((w, Some(inv.clone())));
                }
                // no invoice yet: the win stays owed, and the seller's next answer may bring one
                None => s.owed.push(w),
            }
        }
        drop(s);
        if let Some(why) = lied {
            self.ticket_audit("lottery_win_refused", json!({"session": ds.sid, "dest": format!("ln:{}", ds.terms.payee), "rule": "lottery_win", "reason": why}));
            // what was honestly won in this answer is still paid; the session then ends
            for (w, inv) in &wins {
                if let Some(inv) = inv {
                    self.draw_pay(ds, w, inv, false, counted);
                }
            }
            return Err(self.draw_fault(ds, &why));
        }
        Ok(Round { wins, again, left })
    }

    /// Pay one win with the seller's invoice for it, through the ticket rail. What the payment
    /// booked goes into the session's and the call's counts; a refusal is noted with its rule, and
    /// a refusal by the owner's bounds stops the call asking for more. `first`: the seller stands
    /// still for this win already.
    fn draw_pay(&self, ds: &DrawSession, win: &Win, invoice: &str, first: bool, counted: &Mutex<Counted>) {
        // a seller blocked since the draw (another session of it over-charged) is paid no win
        let rk = hex::encode(&ds.terms.receipt_key);
        if self.seller_blocks.get(&crate::seller_block::Seller { payee: &ds.terms.payee, receipt_key: &rk, origin: &ds.origin }).is_some() {
            let _ = self.draw_fault(ds, "the seller is blocked for over-charging: no win is paid to it");
            return;
        }
        let (first, due) = {
            let mut s = lock(&ds.state);
            s.paying.insert(win.draw());
            let now = self.engine.now();
            let seen = *s.seen_at.entry(win.draw()).or_insert(now);
            (first || s.again.contains(&win.draw()), seen + f64::from(ds.terms.grace_seconds))
        };
        // the seller's offer first, where its terms name one, with the note that names this session and draw; its
        // invoice where the offer cannot be fetched
        let (key, seller_session) = {
            let link = lock(&ds.link);
            (Zeroizing::new(*link.key), link.seller_sid.clone())
        };
        let by = xbt402::offer::entry_offer(&ds.terms.accepted)
            .filter(|_| !seller_session.is_empty())
            .map(|offer| crate::ticket_rail::OfferWay { offer, key: &key, seller_session: &seller_session });
        let out = self.lottery_pay_win(&ds.sid, win, invoice, first, by.as_ref(), Some(due));
        let charged = py_int(out.get("charged_sats")).unwrap_or(0).max(0);
        let rule = str_or_empty(out.get("rule"));
        // the book holds this invoice's payment failed, with nothing of it in flight on the wallet's node
        // its payment failed with nothing in flight, or the wallet held it back for lack of time and never sent it:
        // either way the seller's next invoice is wanted at once
        let unsent = rule == "ticket_expiry" && out.get("unsent") == Some(&Value::Bool(true));
        let failed_hash = (rule == "lottery_win_failed" || unsent).then(|| crate::bolt11::decode(invoice).ok().map(|i| i.payment_hash_hex())).flatten()
            .filter(|h| out.get("hash").and_then(Value::as_str) == Some(h.as_str()));
        if let Some(hash) = failed_hash {
            self.draw_cancel_later(ds, win, hash);
        }
        let mut s = lock(&ds.state);
        s.paying.remove(&win.draw());
        let mut c = lock(counted);
        match out.get("verdict").and_then(Value::as_str) {
            Some("allow") => {
                // paid: its place in the gate's order is no longer needed, and a long session keeps no entry per win
                s.seen_at.remove(&win.draw());
                s.wins_paid += 1;
                s.paid_sats = s.paid_sats.saturating_add(charged);
                c.wins_paid += 1;
                c.paid_sats = c.paid_sats.saturating_add(charged);
                // an earlier try of this win that came to nothing is no longer news
                c.unpaid.retain(|u| u.get("draw").and_then(Value::as_u64) != Some(win.draw()));
                c.fee_msat = c.fee_msat.saturating_add(crate::ticket::outside_u64(out.get("fee_msat")).unwrap_or(0));
            }
            // booked, and the node's word decides later: counted as paid for what it booked. Should the node then
            // show it failed, the win is owed again ([`Signer::draw_round`] asks the book)
            Some("pending") => {
                s.paid_sats = s.paid_sats.saturating_add(charged);
                c.paid_sats = c.paid_sats.saturating_add(charged);
                if c.unpaid.len() < UNPAID_LISTED {
                    c.unpaid.push(json!({"draw": win.draw(), "rule": rule, "booked_sats": charged}));
                }
                if let Some(h) = s.handed.get_mut(&win.draw()) {
                    h.1 = true;
                }
                // one the node shows paid without the preimage that proves it: nothing more is paid in the call
                if rule.ends_with("_unproven") {
                    c.stop.get_or_insert(format!("{rule}: the wallet's node shows a win paid without the preimage of its hash"));
                    c.halt = true;
                }
            }
            // the book has a payment for this win already: it is paid, or being paid, and this invoice is not
            _ if rule == "lottery_win_paid" => {
                s.seen_at.remove(&win.draw());
            }
            _ => {
                // whatever such an answer booked left all the same (an answer that books says pending; this one is for
                // any that did not)
                s.paid_sats = s.paid_sats.saturating_add(charged);
                c.paid_sats = c.paid_sats.saturating_add(charged);
                // not paid. An invoice the checks refused, or a payment that failed, leaves the win open for the seller's
                // next invoice; anything else is the owner's bound, and the call asks for no more pieces
                // an invoice that lapsed while its win waited its turn at the wallet's gate is no fault of the seller's, and
                // no bound of the owner's: the seller's next invoice pays the same win. (One that came nearly dead
                // is still the seller's doing, and an "invoice too long" is not one that ran out.)
                let lapsed = !s.dead_on_arrival.contains(&invoice_mark(invoice)) && matches!(rule.as_str(), "ln_expired" | "ticket_expiry")
                    && crate::bolt11::decode(invoice).is_ok_and(|i| {
                        let (life, left) = (i.expires_at() as f64 - i.timestamp as f64, i.expires_at() as f64 - self.engine.now());
                        left < self.ticket_pace.send_margin(life)
                    });
                if lapsed {
                    s.lapsed += 1;
                    let this_win = s.lapses.entry(win.draw()).or_default();
                    *this_win += 1;
                    if *this_win > LAPSES_PER_WIN || s.lapsed > LAPSES_PER_SESSION {
                        let why = format!("{} of this seller's invoices ran out before their wins could be paid", s.lapsed);
                        s.fault.get_or_insert(why);
                        c.stop.get_or_insert("lottery_invoices_lapse: the seller's invoices for wins keep running out before they can be paid".into());
                        c.halt = true;
                    }
                }
                let retry = rule == "ln_expired" || rule == "lottery_win_failed" || rule.starts_with("ticket_") && !matches!(rule.as_str(), "ticket_task_budget" | "ticket_seller_cap" | "ticket_task"
                    | "ticket_admission" | "ticket_rate_limit" | "ticket_sync" | "ticket_book" | "ticket_disabled" | "ticket_session");
                // the wallet's own nodes gave no answer for a moment: nothing was booked and nothing was sent, so
                // the same invoice is good the next time the seller lists it
                let not_now = matches!(rule.as_str(), "ln_backend" | "ln_no_safe_channel" | "ln_no_route" | "ln_unavailable");
                if c.unpaid.len() < UNPAID_LISTED {
                    c.unpaid.push(json!({"draw": win.draw(), "rule": rule}));
                }
                if not_now {
                    s.tried.remove(&invoice_mark(invoice));
                }
                // a seller the wallet's node has no route to, win after win: the call ends with that reason, and the
                // win stays owed for a later call
                if rule == "ln_no_route" && out.get("route_ran_out") == Some(&Value::Bool(true)) {
                    let n = s.no_route.entry(win.draw()).or_default();
                    *n += 1;
                    if *n >= NO_ROUTE_PER_WIN {
                        c.stop.get_or_insert(format!("ln_no_route: the wallet's node has found no route to the seller for any of {n} tries of a win"));
                        c.halt = true;
                    }
                }
                // an invoice the wallet's checks refused is the seller's doing. After three, the session is over: a
                // seller that cannot make an invoice for its own node at its own win size is not asked again
                if retry && !lapsed && rule != "lottery_win_failed" {
                    s.bad_invoices += 1;
                    if s.bad_invoices >= BAD_INVOICES_MAX {
                        let why = format!("{} invoices of this seller failed the wallet's checks (the last: {rule})", s.bad_invoices);
                        s.fault.get_or_insert(why);
                        c.stop.get_or_insert(format!("lottery_seller_fault: the seller's invoices for wins fail the wallet's checks ({rule})"));
                        c.halt = true;
                    }
                }
                if retry || not_now {
                    // owed again: another invoice of the seller's for it is looked at, never one that was booked
                    if let Some((w, _)) = s.handed.remove(&win.draw()) {
                        s.owed.push(w);
                    }
                    if retry {
                        s.again.insert(win.draw());
                        let ends = crate::bolt11::decode(invoice).map_or(0.0, |i| i.expires_at() as f64);
                        s.next_invoice_after = s.next_invoice_after.max(ends);
                    }
                } else {
                    // the session stopped (its caller, a fault), or the owner's bounds, or the wallet's node (one just
                    // started is not on its chain yet): this call asks for no more. Nothing was booked or sent, so the
                    // win is owed again, with its invoice, for a later call of the session: a win left handed has no
                    // payer, and its seller would refuse every later call for it (`win_unpaid`)
                    if rule == "ticket_session" {
                        c.stop.get_or_insert("ticket_session: the session was stopped".to_string());
                    } else {
                        c.stop.get_or_insert(format!("{rule}: a win could not be paid inside the owner's bounds"));
                    }
                    c.halt = true;
                    s.tried.remove(&invoice_mark(invoice));
                    if let Some((w, _)) = s.handed.remove(&win.draw()) {
                        s.owed.push(w);
                    }
                }
            }
        }
    }

    /// Remembers that the invoice `hash` of a win that is about to be owed again should be cancelled
    /// by the seller, which [`Self::draw_round`] asks for before it asks for the seller's list.
    fn draw_cancel_later(&self, ds: &DrawSession, win: &Win, hash: String) {
        let mut s = lock(&ds.state);
        let asked = s.cancels.get(&win.draw()).copied().unwrap_or(0);
        if s.no_cancel || asked >= CANCELS_PER_WIN || s.cancels_asked >= CANCELS_PER_SESSION {
            return;
        }
        s.cancels.insert(win.draw(), asked + 1);
        s.cancels_asked += 1;
        s.to_cancel.push((win.draw(), hash));
    }

    /// Asks the seller to cancel the invoices of wins whose payment failed, signed as every call of the
    /// session is: its next invoice for each then comes at once, not when the first has lapsed, which on a
    /// seller of 60 s is long after its answer has stopped waiting. No invoice is paid again. A seller
    /// that cannot, or will not any more, is not asked again, and the win waits for the lapse as before.
    fn draw_cancel_failed(&self, ds: &DrawSession) {
        let asks = std::mem::take(&mut lock(&ds.state).to_cancel);
        for (draw, hash) in asks {
            let said = self.draw_call(ds, "cancel", &json!({"draw": draw, "hash": hash}));
            let cancelled = said.as_ref().is_ok_and(|(status, v, _)| *status == 200 && v.get("cancelled") == Some(&Value::Bool(true)));
            let mut s = lock(&ds.state);
            if cancelled {
                s.next_invoice_after = self.engine.now();
            } else if said.as_ref().map_or(true, |(status, v, _)| *status != 200 || v.get("refused").is_some()) {
                s.no_cancel = true;
            }
        }
    }

    /// Asks the seller's list and pays what it brings for the wins that are owed: a few times, and
    /// for up to [`OWED_WAIT`] where the seller's next invoice is due by then. Without that wait, a win
    /// whose invoice ran out at the gate stayed unpaid when its answer had already ended, for a next
    /// call that may never come, and that call was refused `win_unpaid`.
    fn draw_pay_owed(&self, ds: &DrawSession, first: bool, counted: &Mutex<Counted>) -> std::result::Result<(), Value> {
        // up to the invoice's end where the measured time on the way kept it from being sent (`Pace::send_margin`)
        let wait = OWED_WAIT.max(Duration::from_secs_f64(self.ticket_pace.send_margin(f64::MAX) + 5.0));
        let until = Instant::now() + wait;
        let unsettled = || !lock(&ds.state).owed.is_empty() && ds.fault().is_none() && !lock(counted).halt;
        for tries in 1.. {
            if !unsettled() {
                break;
            }
            let r = self.draw_round(ds, &[], &[], true, counted)?;
            for (w, inv) in &r.wins {
                if let Some(inv) = inv {
                    self.draw_pay(ds, w, inv, first, counted);
                }
            }
            if !unsettled() {
                break;
            }
            let due = lock(&ds.state).next_invoice_after - self.engine.now() < wait.as_secs_f64();
            let waits = due && lock(&ds.state).next_invoice_after > 0.0 && Instant::now() < until;
            if tries >= 3 && !waits {
                break;
            }
            std::thread::sleep(if waits { OWED_POLL } else { ROUND_WAIT });
        }
        // kept while a win is owed: the session's next call is what its seller's next invoice is for
        let mut s = lock(&ds.state);
        if s.owed.is_empty() {
            s.next_invoice_after = 0.0;
        }
        Ok(())
    }

    /// What a request refused for values or a win does: one round even with no win owed, since it
    /// sends the values that are open, and then what [`Self::draw_pay_owed`] does.
    fn draw_pay_owed_or_round(&self, ds: &DrawSession, counted: &Mutex<Counted>) -> std::result::Result<(), Value> {
        let r = self.draw_round(ds, &[], &[], true, counted)?;
        for (w, inv) in &r.wins {
            if let Some(inv) = inv {
                self.draw_pay(ds, w, inv, true, counted);
            }
        }
        self.draw_pay_owed(ds, true, counted)
    }

    /// The wins of a round that was made after the answer had ended (the round that names void
    /// pieces): each is paid with its invoice, as [`Signer::draw_pay`] pays one. Where the call
    /// gives no more values (`Counted::halt`: an owner's bound refused a win, or the call's wins
    /// passed its luck cap) or the session is faulty, nothing more is paid in it: the win goes back
    /// to the wins that are owed, its invoice unread, and the session's next call pays it when the
    /// seller lists it again. Either way no win [`Signer::draw_round`] handed out is left with no
    /// payer: a win that is handed and not paid is never asked for again, and the seller waits
    /// for it for good.
    fn draw_pay_late(&self, ds: &DrawSession, wins: Vec<(Win, Option<String>)>, counted: &Mutex<Counted>) {
        for (w, inv) in wins {
            let Some(inv) = inv else { continue };
            if ds.fault().is_some() || lock(counted).halt {
                let mut s = lock(&ds.state);
                if let Some((w, _)) = s.handed.remove(&w.draw()) {
                    s.owed.push(w);
                }
                s.tried.remove(&invoice_mark(&inv));
                continue;
            }
            self.draw_pay(ds, &w, &inv, false, counted);
        }
    }

    /// The wins of this session that the seller's answer stands still for, by the wallet's own
    /// count against the seller's terms: they go through the gate before the wins no seller waits
    /// for. A seller serves on beside `maxUnpaidWins` unpaid wins, and beside a win for
    /// `gracePieces` pieces after it; beyond either its answer stands still, for 15 s at the
    /// gateway as shipped (`refill_wait`), and is then cut short. So from `maxUnpaidWins` unpaid on, the oldest go first, as
    /// many as bring the count below it: the next win would stop the seller, and a win waiting behind a hundred others' would
    /// not be paid within those 15 s (seen on a loaded lab: two wins at the count, a third found, and the answer cut); and a
    /// win goes first when the pieces the wallet has
    /// given values for since it are within the seller's `window` of `gracePieces` (the seller is
    /// that many pieces ahead of the wallet's values at the most). Called while an answer is being
    /// read: of an answer that is over, no piece waits for a payment.
    fn draw_hurry(&self, ds: &DrawSession) {
        let first: Vec<u64> = {
            let s = lock(&ds.state);
            if s.paying.is_empty() {
                return;
            }
            let mut unpaid: Vec<u64> = s.owed.iter().map(Win::draw).chain(s.paying.iter().copied()).collect();
            unpaid.sort_unstable();
            // at the seller's count already, not only past it: the next win would stand it still
            let above = (unpaid.len() + 1).saturating_sub(ds.terms.max_unpaid_wins as usize);
            let issued = s.buyer.as_ref().map_or(0, Buyer::issued);
            let far = u64::from(ds.terms.grace_pieces).saturating_sub(u64::from(ds.terms.window));
            unpaid.iter().enumerate().filter(|(i, d)| *i < above || issued.saturating_sub(**d) >= far).map(|(_, d)| *d).filter(|d| s.paying.contains(d)).collect()
        };
        if !first.is_empty() {
            self.ticket_pace.hurry(&ds.sid, &first);
        }
    }

    /// One paid request of a session of draws: the request, its receipt, its body as it arrives,
    /// a value for every piece, and every win paid.
    fn draw_request(&self, ds: &Arc<DrawSession>, c: &Call, price: &Price) -> Value {
        let tp = self.ticket_policy();
        // what the answer may use: its charge cap (`max_charge_sats`, at most `max_sats`)
        let max_msat = (c.charge_sats.max(0) as u64).saturating_mul(1000);
        let dest = format!("ln:{}", ds.terms.payee);
        let counted = Mutex::new(Counted::default());
        let about = |ds: &DrawSession, counted: &Mutex<Counted>| {
            let c = lock(counted);
            json!({"rail": "lottery", "session": ds.sid, "dest": dest, "origin": ds.origin, "win_msat": ds.win_msat.to_string(), "charged_sats": c.paid_sats,
                   "price_msat": c.price_msat.to_string(), "draws": c.draws, "wins": c.wins, "wins_paid": c.wins_paid, "wins_unpaid": c.unpaid,
                   "fee_msat": c.fee_msat.to_string(), "session_totals": ds.public()})
        };
        let fail = |ds: &DrawSession, d: Value| with(d, about(ds, &counted));
        if price.request_msat > max_msat {
            return fail(ds, deny("max_sats", format!("quoted {} sats > the call's charge cap of {} sats", sats_ceil(price.request_msat), c.charge_sats)));
        }
        // every piece of this route below the session's win, at odds the owner allows: a route of the same seller may cost more than the one the session was opened on
        let dearest = price.request_msat.max(price.second_msat).max(price.for_bytes(ds.terms.piece_bytes).unwrap_or(u64::MAX));
        if lottery::Odds::new(dearest.max(1), ds.win_msat).is_ok_and(|o| !o.at_most(1, tp.lottery.max_odds_den.max(2) as u64)) || dearest >= ds.win_msat {
            return fail(ds, refused("lottery_odds", format!("a piece of this route costs up to {dearest} msat, which on this session's win of {} msat is above the owner's \
                                                             largest odds (1 in {}): stop the session and call again, and the wallet sizes a new one or pays with tickets",
                                                            ds.win_msat, tp.lottery.max_odds_den)));
        }
        if let Some(why) = ds.fault() {
            return fail(ds, self.draw_fault(ds, &why));
        }
        *lock(&ds.used) = self.engine.now();
        self.lottery_touch(&ds.sid);
        let started = Instant::now();
        let mut tries = 0;
        let mut late = false;
        let (seq, digest, ans, head) = loop {
            tries += 1;
            let (seq, digest, ans, receipt) = match self.draw_send(ds, c.method, c.url, c.body, c.headers()) {
                Ok(x) => x,
                // it may have reached the seller, and be served yet (`request_sent`, as on the ticket rail)
                Err(e) => return fail(ds, with(refused("ticket_seller", format!("the seller gave no answer to the request: {}", e.msg)),
                                               json!({"status": null, "request_sent": true}))),
            };
            let head = match receipt {
                Ok(r) => r,
                Err(why) => {
                    let status = ans.status;
                    let v: Value = ans.read_small(SMALL_BODY).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
                    let code = protocol_code(v.get("error"));
                    if status == 402 && code == "bad_seq" && tries <= 2 {
                        if let Some(n) = v.get("nextSeq").and_then(Value::as_u64) {
                            lock(&ds.link).next_seq = n;
                            continue;
                        }
                    }
                    // the seller's HTTP layer gave up on it (408) before anything served it: once more, with its seq
                    if status == 408 && !late {
                        late = true;
                        continue;
                    }
                    if unsigned_and_no_fault(status) {
                        // a 408 comes before anything serves the request; behind a proxy's 5xx it may have been served
                        return fail(ds, with(refused("ticket_seller", format!("the seller answered HTTP {status} without a receipt")),
                                             json!({"status": status, "request_sent": status != 408})));
                    }
                    if status == 402 && code == "session_unknown" {
                        self.draw_stop(ds, "the seller has forgotten the session", false);
                        return fail(ds, with(refused("lottery_session_ended", "the seller has forgotten this session: it ended; nothing was served for this request"),
                                             json!({"status": status, "request_sent": false})));
                    }
                    let d = self.draw_fault(ds, &format!("an answer to a request (HTTP {status} {code}) without a valid receipt: {why}"));
                    return fail(ds, with(d, json!({"status": status})));
                }
            };
            if matches!(ans.status, 402 | 503) {
                let status = ans.status;
                let v: Value = ans.read_small(SMALL_BODY).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
                let code = protocol_code(v.get("error"));
                // signed by the seller: it waits for values or for a win's payment. A round sends what is open and pays
                // what its answer lists for wins the wallet found; then the request once more
                if matches!(code, "win_unpaid" | "value_missing") && tries <= 2 {
                    // the seller serves this request when they are paid: they go first
                    if let Err(d) = self.draw_pay_owed_or_round(ds, &counted) {
                        return fail(ds, d);
                    }
                    if lock(&counted).stop.is_none() {
                        continue;
                    }
                }
                // the seller takes no more voids in this session (pieces of answers this wallet stopped reading): the
                // session is over, and the call is made once more on a new one
                if code == "too_many_voids" {
                    self.draw_stop(ds, "the seller takes no more voids in this session", true);
                    return fail(ds, with(refused("lottery_session_ended", "the seller ended this session: too many of its pieces were given no value; nothing was served \
                                                                           for this request"), json!({"status": status, "seller_code": code, "request_sent": false})));
                }
                // the seller waits for wins this wallet will not pay again: each has a payment in its book that has not
                // failed (its node cannot say what became of it). Such a session cannot go on. It ends, and the next
                // call opens another; the payment stays booked until the node says
                if code == "win_unpaid" {
                    let listed: Vec<u64> = v.get("session").and_then(|x| x.get("wins")).and_then(Value::as_array).into_iter().flatten()
                        .filter_map(|w| w.get("draw").and_then(Value::as_u64)).take(64).collect();
                    let handed: Vec<u64> = {
                        let st = lock(&ds.state);
                        listed.iter().copied().filter(|d| st.handed.contains_key(d)).collect()
                    };
                    if !listed.is_empty() && handed.len() == listed.len() && handed.iter().all(|d| self.lottery_win_live(&ds.sid, *d)) {
                        let stopped = self.draw_stop(ds, "a win's payment is not final on the wallet's node", true);
                        return fail(ds, with(refused("lottery_win_in_doubt", "the seller waits for a win whose payment this wallet has booked and its node has neither                                                                               completed nor failed: it is not paid a second time. The session was ended; call again"),
                                             json!({"status": status, "seller_code": code, "stopped": stopped, "request_sent": false})));
                    }
                }
                // refused unserved, and signed so (`request_sent` false: another seller may serve it)
                return fail(ds, with(refused("lottery_refused", format!("the seller refused the request: HTTP {status} {code}; no piece was served for it")),
                                     json!({"status": status, "seller_code": code, "request_sent": false})));
            }
            break (seq, digest, ans, head);
        };
        let mut ans = ans;
        let status = ans.status;
        let mut out = json!({"verdict": "allow", "rule": "ok", "status": status});
        let mut sink = Sink::for_call(c);
        let (head_fields, not_read) = c.head(&mut ans, &mut sink);
        // the wallet's own refusal of an answer larger than the size the call named: read no further, but the
        // request was served, and its own piece is drawn for as the ticket rail charges it
        let size_refused = super::larger_than_shown(status, &head_fields, c.max_size).is_some();
        out = with(out, head_fields);
        if status >= 400 {
            // an error of the service, passed on: no piece, and no draw
            let ended = read_all(ans, &mut sink);
            out = with(out, json!({"complete": ended.is_none(), "ended": ended}));
        } else if head.charged > price.request_msat {
            let why = format!("the seller charged {} msat for a request whose price by its terms is {}", head.charged, price.request_msat);
            return fail(ds, with(self.draw_fault(ds, &why), json!({"status": status})));
        } else {
            let Some(req) = xbt402::ticket::hex32(&digest) else { return fail(ds, refused("ticket", "a request digest that is not 32 bytes")) };
            // a 206 for another range than was asked: nothing of it is read, and its pieces are named void
            if let Some(why) = not_read {
                lock(&counted).stop.get_or_insert(why);
            }
            let m = self.draw_stream(ds, c, price, &head, seq, req, ans, max_msat, &mut sink, &counted, size_refused);
            out = with(out, m);
        }
        let (_, stored, text) = sink.done();
        out = with(with(out, stored), about(ds, &counted));
        super::range_ignored(&mut out, c);
        out["ms"] = json!((started.elapsed().as_secs_f64() * 10_000.0).round() / 10.0);
        out[UNTRUSTED_KEY] = untrusted(&text, head.raw);
        *lock(&ds.used) = self.engine.now();
        out
    }

    /// The body of an answer paid by draws: read as it arrives and cut into the terms' pieces; a
    /// value is given for each piece once all of it is here (and its hash matched, where the
    /// caller gave one), for the request's own piece at once, and for each second as it starts.
    /// A second thread sends the values, checks the reveals and pays the wins, so that reading
    /// never waits for a payment. Returns fields for the reply.
    #[allow(clippy::too_many_arguments)]
    fn draw_stream(&self, ds: &Arc<DrawSession>, c: &Call, price: &Price, head: &DrawReceipt, seq: u64, req: [u8; 32], ans: WireAnswer, max_msat: u64, sink: &mut Sink,
                   counted: &Mutex<Counted>, size_refused: bool) -> Value {
        let tp = self.ticket_policy();
        let piece_bytes = ds.terms.piece_bytes.max(1);
        let by_bytes = price.byte_msat > 0;
        let (open_s, limit) = super::open_limit(&tp, false, sink.out.is_some(), price.second_msat > 0);
        let max_open = Duration::from_secs(open_s.clamp(1, 86_400) as u64);
        let mut progress = super::Progress::new(&tp, limit);
        let luck_cap = lottery::luck_cap_msat(max_msat, ds.win_msat, tp.lottery.luck_tenths.max(0) as u64);
        let batch = (tp.lottery.ahead.max(1) as usize).div_ceil(2);
        let piece = |kind: Kind, k: u64, amount_msat: u64| Piece { id: PieceId { seq, kind, k }, req, amount_msat };
        let length = ans.length;
        let whole = !head.body_hash.is_empty();
        let closer = ans.closer;
        let mut body = ans.body;
        // pieces that are here and have no value yet, voids, whether the reader is done, and why the wallet stopped
        struct Shared {
            pending: Vec<Piece>,
            void: Vec<PieceId>,
            done: bool,
        }
        let shared = Mutex::new(Shared { pending: vec![], void: vec![], done: false });
        let wake = Condvar::new();
        // the request's own piece. Of an answer sent as it arrives it is served when the head is, and the body has
        // pieces of its own; of an answer paid whole at its head it is the body too, and its value waits for that
        if price.request_msat > 0 && !whole {
            lock(&shared).pending.push(piece(Kind::Request, 0, price.request_msat));
        }
        let head_at = Instant::now();
        *lock(&ds.answer_since) = Some(head_at);
        let stop_now = |why: String| {
            lock(counted).stop.get_or_insert(why);
        };
        let stopped = || {
            if ds.ending.load(Ordering::SeqCst) {
                lock(counted).stop.get_or_insert_with(|| "ticket_session: the session was stopped".to_string());
            }
            lock(counted).stop.is_some() || ds.fault().is_some()
        };
        let mut read_error: Option<String> = None;
        let mut mismatch: Option<u64> = None;
        std::thread::scope(|scope| {
            // stopped, its connection ends here: the read returns now, not after a quiet seller's own wait
            if let Some(close) = &closer {
                let (shared, stopped) = (&shared, &stopped);
                scope.spawn(move || loop {
                    if lock(shared).done {
                        return;
                    }
                    if stopped() {
                        close();
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                });
            }
            // the drawer: values out, reveals checked, wins paid
            scope.spawn(|| {
                let mut seconds = 0u64;
                let mut tries = 0;
                let mut done_at: Option<Instant> = None;
                loop {
                    let (pieces, voids, done) = {
                        let mut s = lock(&shared);
                        // a second is a piece when it starts, by this clock, which started after the seller's
                        while price.second_msat > 0 && !s.done && seconds <= head_at.elapsed().as_secs() {
                            s.pending.push(piece(Kind::Second, seconds, price.second_msat));
                            seconds += 1;
                        }
                        if s.pending.len() < batch && s.void.is_empty() && !s.done && tries == 0 {
                            // not a batch yet: wait for more, but not long, since the seller serves only a window ahead
                            s = wake.wait_timeout(s, Duration::from_millis(20)).unwrap_or_else(|p| p.into_inner()).0;
                        }
                        // a stop has begun: no new value is given, and what has none yet is named as void at the end
                        if ds.ending.load(Ordering::SeqCst) {
                            s.pending.clear();
                        }
                        // while a round is being sent again, no new value is given: what is open goes first
                        let pieces = if tries == 0 { std::mem::take(&mut s.pending) } else { vec![] };
                        (pieces, std::mem::take(&mut s.void), s.done)
                    };
                    // a win the seller stands still for, or is about to: said on every round, since a payer may not have
                    // reached the gate when its win became one
                    if !done {
                        self.draw_hurry(ds);
                    } else if done_at.get_or_insert_with(Instant::now).elapsed() > DONE_WAIT {
                        stop_now(format!("the seller neither revealed the values still open nor sent the invoices of the wins owed in the {} s after the answer ended",
                                         DONE_WAIT.as_secs()));
                        return;
                    }
                    let open_n = || lock(&ds.state).buyer.as_ref().map_or(0, |b| b.open().count());
                    let open_before = open_n();
                    let open = open_before > 0;
                    if pieces.is_empty() && voids.is_empty() && !open {
                        if done && lock(&shared).pending.is_empty() {
                            return;
                        }
                        // a win that is owed (the seller sent no invoice for it yet, or a try came to nothing before
                        // anything was sent): the seller is asked for its list again. Without this the answer stands
                        // still, the seller waiting for the payment and the wallet for the next piece
                        if !lock(&ds.state).owed.is_empty() && ds.fault().is_none() && !lock(counted).halt {
                            if let Ok(r) = self.draw_round(ds, &[], &[], true, counted) {
                                for (w, inv) in r.wins {
                                    if let Some(inv) = inv {
                                        scope.spawn(move || self.draw_pay(ds, &w, &inv, false, counted));
                                    }
                                }
                            }
                            std::thread::sleep(Duration::from_millis(100));
                        }
                        continue;
                    }
                    if ds.fault().is_some() || lock(counted).halt {
                        return;
                    }
                    // what the call's wins have come to: above the luck cap no further value is given, and what is not
                    // drawn for owes no win
                    if lock(counted).wins.saturating_mul(ds.win_msat) > luck_cap {
                        let mut cn = lock(counted);
                        cn.stop.get_or_insert(format!("lottery_luck_cap: the wins of this call come to more than {} sat, the most a call charged at most {} sat is let to pay by luck",
                                                      luck_cap / 1000, c.charge_sats));
                        cn.halt = true;
                        return;
                    }
                    match self.draw_round(ds, &pieces, &voids, false, counted) {
                        Ok(r) => {
                            // after the answer has ended, a round that gave nothing, found no win and saw no open value
                            // revealed is no progress: an answer of 200 with nothing new is tried a few times, not forever
                            let stuck = done && pieces.is_empty() && voids.is_empty() && r.wins.is_empty() && open_n() >= open_before;
                            if !r.left.is_empty() {
                                let mut s = lock(&shared);
                                s.pending.splice(0..0, r.left);
                            }
                            for (w, inv) in r.wins {
                                if let Some(inv) = inv {
                                    // paid beside the reading: a payment takes a quarter second through a hop
                                    scope.spawn(move || self.draw_pay(ds, &w, &inv, false, counted));
                                }
                            }
                            tries = if r.again || stuck { tries + 1 } else { 0 };
                            if tries > 0 {
                                if tries > ROUND_TRIES {
                                    stop_now(if stuck { "the seller answers and reveals none of the values still open".into() }
                                             else { "the seller did not take the values for the last pieces".into() });
                                    return;
                                }
                                std::thread::sleep(ROUND_WAIT);
                            }
                        }
                        Err(d) => {
                            let mut cn = lock(counted);
                            cn.stop.get_or_insert(format!("{}: {}", str_or_empty(d.get("rule")), str_or_empty(d.get("reason"))));
                            cn.halt = true;
                            return;
                        }
                    }
                }
            });
            // the reader
            let mut buf = vec![0u8; 64 << 10];
            let mut piece_hash = Sha256::new();
            let mut next_k = 0u64;
            let finish_piece = |k: u64, from: u64, to: u64, digest: [u8; 32], mismatch: &mut Option<u64>| {
                let amount = lottery::bytes_amount(|n| price.for_bytes(n), from, to).unwrap_or(u64::MAX);
                if amount == 0 {
                    return;
                }
                let p = piece(Kind::Bytes, k, amount);
                let mut s = lock(&shared);
                // where the caller named the piece's hash, a piece that does not match gets a void and no value
                match c.piece_hashes.get(k as usize) {
                    Some(want) if *want != hex::encode(digest) => {
                        s.void.push(p.id);
                        mismatch.get_or_insert(k);
                    }
                    _ => s.pending.push(p),
                }
                drop(s);
                wake.notify_all();
            };
            let mut touched = Instant::now();
            loop {
                if stopped() || mismatch.is_some() {
                    break;
                }
                // an answer that brings no win for a while still uses its session: the book must not take it for idle
                if touched.elapsed() >= Duration::from_secs(crate::ticket_rail::TOUCH_EVERY_S) {
                    touched = Instant::now();
                    *lock(&ds.used) = self.engine.now();
                    self.lottery_touch(&ds.sid);
                }
                if head_at.elapsed() >= max_open {
                    stop_now(format!("{limit}: the answer has been open for {} s", max_open.as_secs()));
                    break;
                }
                // the call's limit, by the wallet's own count of what has arrived: it reads no further, and draws for what it has
                let seconds = if price.second_msat > 0 { head_at.elapsed().as_secs().saturating_add(1) } else { 0 };
                if price.metered() && price.cost(sink.bytes, seconds).unwrap_or(u64::MAX) >= max_msat {
                    stop_now("max_sats: the call's charge cap is used up".into());
                    break;
                }
                let asked = Instant::now();
                let n = match body.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        read_error = Some(format!("{:?}", e.kind()));
                        break;
                    }
                };
                if let Some(why) = progress.read(asked.elapsed(), n as u64) {
                    stop_now(why);
                }
                let mut off = 0;
                while off < n {
                    let have = sink.bytes;
                    // past the size the buyer was shown (a body that stated no size): read no further
                    if c.max_size.is_some_and(|most| have >= most) {
                        stop_now(super::PASSED_SHOWN.into());
                        break;
                    }
                    let mut take = if by_bytes { ((n - off) as u64).min(piece_bytes - have % piece_bytes) as usize } else { n - off };
                    if let Some(most) = c.max_size {
                        take = take.min(usize::try_from(most - have).unwrap_or(usize::MAX));
                    }
                    sink.put(&buf[off..off + take]);
                    if sink.gone {
                        stop_now(super::READER_GONE.into());
                        break;
                    }
                    off += take;
                    if by_bytes {
                        piece_hash.update(&buf[off - take..off]);
                        if sink.bytes.is_multiple_of(piece_bytes) {
                            let digest: [u8; 32] = std::mem::take(&mut piece_hash).finalize().into();
                            finish_piece(next_k, sink.bytes - piece_bytes, sink.bytes, digest, &mut mismatch);
                            next_k += 1;
                        }
                    }
                }
                if sink.gone || stopped() || length.is_some_and(|l| sink.bytes >= l) {
                    break;
                }
            }
            // the last, short piece: only of a body that came to its end, so that both sides count the same bytes
            let complete = !stopped() && mismatch.is_none() && read_error.is_none() && length.is_none_or(|l| l == sink.bytes);
            if complete && by_bytes && !sink.bytes.is_multiple_of(piece_bytes) {
                let digest: [u8; 32] = std::mem::take(&mut piece_hash).finalize().into();
                finish_piece(next_k, next_k * piece_bytes, sink.bytes, digest, &mut mismatch);
            }
            // an answer paid whole at its head: its one piece has arrived when the body has, and is the one the receipt signs
            if whole && complete && price.request_msat > 0 && hex::encode(sink.hash.clone().finalize()) == head.body_hash {
                lock(&shared).pending.push(piece(Kind::Request, 0, price.request_msat));
            }
            // one the wallet itself did not read, its size past what the buyer was shown: the request was served all
            // the same, and its piece is drawn for (the ticket rail charges the request's price for it), not named void
            if whole && size_refused && price.request_msat > 0 {
                lock(&shared).pending.push(piece(Kind::Request, 0, price.request_msat));
            }
            lock(&shared).done = true;
            wake.notify_all();
            // the reader's socket too: its client is done now, not after the rounds still to come with a slow seller
            sink.out = None;
        });
        *lock(&ds.answer_since) = None;
        // the connection is closed here: a seller that was still sending stops within its window
        drop(body);
        // wins the seller had sent no invoice for, or whose last one ran out: it is asked for its list, and what it lists is paid
        let _ = self.draw_pay_owed(ds, false, counted);
        let stop = lock(counted).stop.clone();
        let complete = stop.is_none() && mismatch.is_none() && read_error.is_none() && length.is_none_or(|l| l == sink.bytes);
        // an answer that did not arrive whole: the seller may hold pieces of it open that will get no value (it
        // marks a piece when its last bytes leave, and they did not arrive; or the wallet stopped giving values).
        // They are named as void, so that they do not fill the seller's window for the session's next request.
        // And of any answer priced by the second: the seller counts its seconds on its own clock, which started a
        // moment before the wallet's, so it may have begun one second more than the wallet gave a value for
        if (!complete || price.second_msat > 0) && ds.fault().is_none() {
            let ahead = u64::from(ds.terms.window).min(1024) + 1;
            let secs = if price.second_msat > 0 { head_at.elapsed().as_secs() + 1 } else { 0 };
            let mut ids: Vec<PieceId> = vec![];
            if !complete && price.request_msat > 0 && !(whole && size_refused) {
                ids.push(PieceId { seq, kind: Kind::Request, k: 0 });
            }
            if !complete && by_bytes {
                ids.extend((0..sink.bytes / piece_bytes + ahead).map(|k| PieceId { seq, kind: Kind::Bytes, k }));
            }
            ids.extend((0..secs + if secs > 0 { ahead } else { 0 }).map(|k| PieceId { seq, kind: Kind::Second, k }));
            let open: Vec<PieceId> = {
                let st = lock(&ds.state);
                ids.into_iter().filter(|id| st.buyer.as_ref().is_some_and(|b| !b.knows(*id))).collect()
            };
            for chunk in open.chunks(64) {
                // the values no reveal covered yet go with the voids, and the seller's answer may show that one of them
                // won, or bring the invoice of a win that was owed: such a win is paid here like any other of the call
                match self.draw_round(ds, &[], chunk, false, counted) {
                    Ok(r) => self.draw_pay_late(ds, r.wins, counted),
                    Err(_) => break,
                }
            }
        }
        let ended = match (&stop, mismatch, &read_error) {
            (_, Some(k), _) => Some(format!("stopped by the wallet: piece {k} is not the one whose hash the caller named; no value was given for it")),
            (Some(why), _, _) => Some(format!("stopped by the wallet: {why}")),
            (None, None, Some(e)) => Some(format!("cut short by the seller: {e}")),
            (None, None, None) if !complete => Some("cut short by the seller".to_string()),
            _ => None,
        };
        let mut m = json!({"complete": complete, "ended": ended});
        if let Some(k) = mismatch {
            m["piece_mismatch"] = k.into();
        }
        // an answer paid at its head carries its hash in the head's receipt: the body is the one that was signed, or the session ends
        if whole && complete {
            let own = hex::encode(sink.hash.clone().finalize());
            if own != head.body_hash {
                m["seller_fault"] = self.draw_fault(ds, "the body is not the one the receipt signs")["reason"].clone();
            }
            m["receipt"] = json!({"signed": true, "body": if own == head.body_hash { "as signed" } else { "differs from the receipt" }});
        } else {
            m["receipt"] = json!({"signed": true, "body": if complete { "sent as it arrived" } else { "cut short" }});
        }
        m
    }
}
