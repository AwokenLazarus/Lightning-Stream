//! Visits: a seller's own web page, used inside the app, paid for as it loads under a limit the
//! owner set for the visit (docs/SELLER-APPS.md).
//!
//! `POST /visits` `{"base": "<seller URL ending in />", "limit_sats": N}` → `{"visit": id}`.
//! `GET /visits/<id>`: what the visit has spent of its limit (`spent_sats`, the shares of the requests
//! running now in it whole), its limit, and whether it has ended; and, by the signer's word on each
//! answer that has ended, what the seller charged for them (`used_msat`) and what the wallet paid
//! over Lightning for tickets in this visit (`paid_sats`: prepaid, what is not used stays as credit
//! with the seller).
//! `POST /visits/<id>/stop`: end it; its next request is refused.
//! `POST /visits/<id>/limit` `{"limit_sats": N}`: raise its limit to N (never lower it); a visit that
//! ended at its limit goes on (the report's `limit_reached` says it may), one the buyer stopped does not.
//! `<any method> /v/<id>/<path>`: one request of the page, sent to `base` + `path` and paid.
//!
//! **The limit, exactly.** A page asks for many things at once. Each request of a visit holds a share
//! of what is left of the limit while it runs (an eighth of the limit, at most [`ANSWER_SHARE`]; a
//! WebSocket [`SOCKET_SHARE`], and the visit's WebSockets together at most half of the limit), so that
//! a page's requests run side by side, and is sent with its share as the most its answer may charge: the seller is
//! told that figure and stops the answer there, and the signer buys tickets for it within it,
//! before its head or as its body arrives. The shares held at once never add up to more than the
//! limit, so answers running side by side cannot together spend past it; when one ends, only what
//! it cost stays spent; where the signer has not said what it cost (an answer that never started),
//! all of the share stays spent until it does (for good, where it says nothing within
//! [`SETTLE_WAIT`]), and where the signer could not be reached at all, none of it. A request that finds no share free waits for one; one whose
//! answer or ticket does not fit in its share asks once more with room for a ticket beside it, and
//! then runs alone once the others have ended or stopped (an open WebSocket, or an answer whose cost
//! the signer has yet to say, holds no answer it must wait for), and no new share is handed out
//! while it waits. A path the seller serves free (its `/services` says so) is asked for with no
//! share and `max_sats` 0: nothing can be paid for it, and where it is no longer free the request
//! goes the paid way. A range is asked for in
//! parts of at most [`RANGE_CHUNK`], as a player asks for its next part, so that no answer needs
//! more than its share.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt_svc::http::{BodyWriter, Reply, Request, Response, Streamed};

use crate::{flight, in_flight_besides, origin_of, listen_stream, one_range, random_hex, whole, Config, Connector, FIRST_ANSWER, FIRST_BYTE, HEAD_LINE, LONGEST};

/// The largest limit a visit may have, in sats.
const MAX_LIMIT: i64 = 10_000_000;
/// The most visits open at once; an idle one ends after [`IDLE`].
const MAX_VISITS: usize = 32;
const IDLE: Duration = Duration::from_secs(30 * 60);
/// The largest request body of a page passed on.
pub const MAX_BODY: usize = 1 << 20;
/// Why a visit ended when its limit is spent: the one ending a raise of the limit undoes ([`Visit::raise`]).
const LIMIT_REACHED: &str = "This visit's spending limit is reached.";
/// The buyer's own spending rules (policy.json) a payment can be refused by, by their rule names
/// (`xbt_signer::policy::OWNER_LIMIT_RULES`): a refusal by one of them is the buyer's own limit, which no
/// later request of the visit gets past, never the seller's doing.
const OWNER_LIMIT_RULES: [&str; 10] = ["max_per_tx", "split_bypass", "daily_budget", "weekly_budget", "per_counterparty", "per_counterparty_daily", "velocity",
                                       "human_threshold", "ticket_task_budget", "ticket_seller_cap"];

/// Whether the signer's answer `v` is a refusal by one of the buyer's own spending rules ([`OWNER_LIMIT_RULES`]).
fn owner_limit(v: &Value) -> bool {
    v.get("rule").and_then(Value::as_str).is_some_and(|r| OWNER_LIMIT_RULES.contains(&r))
}

/// How long a request waits for a share.
const TURN_WAIT: Duration = Duration::from_secs(120);
/// How long the request that tops the visit's credit up waits for room for a ticket ([`Visit::take_lane`]).
const LANE_WAIT: Duration = Duration::from_secs(15);
/// An answer open this long may run for hours (a film): a request waiting to run alone does not wait for it.
const LONG_OPEN: Duration = Duration::from_secs(30);
/// How long a request whose answer has stopped waits for the signer to say what it cost, past which
/// all of its share stays spent ([`Visit::settle`]). After the stop the signer may still, one after
/// another: wait for the seller's next byte (its `tickets.read_timeout_s`, at most an hour) before it
/// ends a call whose answer is gone; finish a ticket being paid beside the reading (the wait for a
/// ready seller, a minute, and the Lightning payment, at most [`xbt402::ticket::ORDINARY_PAY_S`] and
/// 5 s more); and wait for the answer's last receipt, at most 10 s and a second since each `status` call
/// is cut to what is left of that wait. Then its reply, within [`FIRST_BYTE`] twice. That is what
/// it usually takes at most, not a bound: a release waiting on other answers' releases, a refill, or
/// a seller that answers byte by byte can take longer. A signer that takes longer leaves the share
/// spent, the safe side: the visit's budget is held, no money moves. The share is counted apart while
/// it waits, so nothing else waits for it.
const SETTLE_WAIT: Duration = Duration::from_secs(3600 + 60 + xbt402::ticket::ORDINARY_PAY_S as u64 + 5 + 11 + 2 * FIRST_BYTE.as_secs());
/// The most of a visit's limit one WebSocket holds while it is open: counted as spent until it
/// ends, then only what it cost. It is held for as long as the page is open (a media server's
/// live connection after sign-in), so it is small and has no room for a ticket: a socket pays from
/// the credit the page's requests bought, and the visit's sockets together hold at most half of
/// the limit ([`Visit::reserve_socket`]), so that they never starve the page's requests.
const SOCKET_SHARE: i64 = 50;
/// The most of a visit's limit one request holds while it runs for its answer, a part of a range
/// ([`RANGE_CHUNK`]) at the prices sellers ask. A request's share is an eighth of the limit, at
/// least [`MIN_SHARE`] and at most this ([`Visit::answer_share`]), so that a page's many requests run
/// side by side; a request whose answer or ticket does not fit asks again with room for a ticket
/// beside its share, then alone.
const ANSWER_SHARE: i64 = 1_000;
/// The least share of a request, where the limit is small.
const MIN_SHARE: i64 = 10;
/// How long after the buyer's stop a page's small report still goes ([`Visit::take_grace`]): a media server's frame
/// sends "playback stopped" (Jellyfin's `POST /Sessions/Playing/Stopped`) as it closes, a moment after the stop.
const STOP_GRACE: Duration = Duration::from_secs(2);
/// The largest body of a request let through in that grace.
const GRACE_BODY: usize = 64 << 10;
/// How long a stop waits for the requests let through in its grace before it closes the shop's connection.
const GRACE_WAIT: Duration = Duration::from_secs(10);
/// How long a stop waits, after closing the shop's connection, for the signer's word on the requests that were running,
/// so that the visit's report is final ([`Visit::report`]'s `settled`). The signer ends a stopped connection's answers
/// within its own wait for them (15 s), and says what each cost.
const STOP_SETTLE_WAIT: Duration = Duration::from_secs(30);
/// The largest `/services` document of a seller read for its free routes.
const SERVICES_MAX: u64 = 256 << 10;
/// The longest part of a range a request asks for: `bytes=N-` and longer ranges become
/// `bytes=N-(N+RANGE_CHUNK-1)`, and the page's player asks for the next part as it plays.
const RANGE_CHUNK: u64 = 4 << 20;

/// A `Range` with its length bounded to `chunk`: `bytes=N-` and `bytes=N-M` longer than `chunk`
/// become `bytes=N-(N+chunk-1)`. One that is not a single range from a start is kept as it is.
fn bounded_range(r: &str, chunk: u64) -> String {
    let parts = r.strip_prefix("bytes=").and_then(|s| s.split_once('-'))
        .and_then(|(a, b)| Some((a.parse::<u64>().ok()?, if b.is_empty() { None } else { Some(b.parse::<u64>().ok()?) })));
    match parts {
        Some((a, b)) if b.is_none_or(|b| b >= a && b - a >= chunk) => format!("bytes={a}-{}", a.saturating_add(chunk - 1)),
        _ => r.to_string(),
    }
}

/// The WebSocket's own request headers, passed to the seller beside [`PASSED`].
const SOCKET_HEADERS: [&str; 4] = ["sec-websocket-key", "sec-websocket-version", "sec-websocket-protocol", "sec-websocket-extensions"];

/// Request headers of a page that go to the seller. The seller's gateway passes on only those its
/// route names; the signer refuses the wallet's own and the hop-by-hop ones.
const PASSED: [&str; 13] = ["accept", "accept-language", "content-type", "if-modified-since", "if-none-match", "if-range", "authorization", "cookie",
                            "x-emby-authorization", "x-mediabrowser-token", "x-requested-with", "x-csrf-token", "x-api-key"];

#[derive(Default)]
struct State {
    /// What the visit has spent, the shares of the requests running now in it whole.
    spent: i64,
    /// The shares of the requests running now: part of `spent` until each ends.
    held: i64,
    /// The part of `held` that open WebSockets hold: they end when the page does, so a request
    /// waiting to run alone does not wait for them.
    sockets: i64,
    /// The part of `held` of requests that have stopped and wait for the signer's word on what they
    /// cost ([`Visit::settle`]): they hold no answer open, so a request waiting to run alone does not
    /// wait for them either, and what is left of the limit beside them is its.
    settling: i64,
    /// The part of `settling` of WebSockets that have closed: still counted within the sockets' half
    /// of the limit until the signer says what they cost, so that a page whose live connection keeps
    /// reconnecting does not park share after share beside it.
    socket_settling: i64,
    /// What one of the seller's tickets books, fee included, as a refusal named it: a request asked
    /// again after a refusal has room for one beside its share, so that it can buy the ticket it needs.
    ticket: i64,
    /// The seller's routes, from its `/services` ([`Visit::learn_routes`]): a path on a free one is
    /// asked for unpaid. `None` until read, and again once a path taken for free was not.
    routes: Option<Vec<SellerRoute>>,
    /// Counts each [`Visit::forget_routes`]: a read of the routes begun before one is not kept.
    routes_gen: u64,
    /// A read of the seller's routes is under way ([`spawn_read_routes`]): no second one is started.
    routes_reading: bool,
    /// What the seller charged for the visit's answers that have ended, by the signer's word
    /// (`price_msat`): what the visit used, whether from tickets bought in it or from credit.
    used_msat: u64,
    /// What the wallet paid over Lightning for tickets in this visit, by the signer's word
    /// (`charged_sats`): prepaid, so it may be more than was used.
    paid: i64,
    ended: Option<String>,
    calls: u64,
    last: Option<Instant>,
    /// Requests waiting to run alone ([`Visit::reserve_alone`]): no new share is handed out while
    /// one waits, so that the running ones can end and it gets its turn.
    alone: u32,
    /// The stream sockets of the answers open now: a stop shuts them, which is what stops the signer
    /// paying ([`Visit::stop`]).
    streams: HashMap<u64, OpenStream>,
    next_stream: u64,
    /// The buyer stopped the visit (`ended` says so too, or the limit it reached first).
    stopped: bool,
    /// The session's credit with the seller after the latest call that said (`balance_msat`): below
    /// [`Visit::credit_floor`], the next request takes the lane ([`Visit::take_lane`]).
    credit_msat: Option<u64>,
    /// A request holds the lane: it runs with room for a ticket and tops the credit up before it leaves.
    lane: bool,
    /// The buyer's own spending rules refused a payment of the visit (a ticket for a request, or a top-up): the rule,
    /// the signer's words and the owner's limit (`limit_sats`). The visit ends with it ([`Visit::policy_stop`]), and each
    /// later request is refused with it, not asked of the seller.
    policy: Option<Value>,
    /// When the buyer stopped the visit: for [`STOP_GRACE`] after it, a page's small `POST` (a media server's "playback
    /// stopped" report as its frame closes) still goes, on the credit the shop holds and within the visit's limit.
    stopped_at: Option<Instant>,
    /// Requests let through in that grace that have not ended: the shop's connection is closed after them.
    grace_open: u32,
    /// The tickets the wallet paid for in this visit, by the signer's word on each call (`tickets_released`).
    tickets: u64,
    /// A stop is being carried out ([`Connector::finish_stop`]): the shop's connection closed where no other open visit
    /// uses it, and the requests that were running settled.
    closing: bool,
    /// Whether that stop closed the shop's connection (`None`: not decided yet, or no stop).
    connection_closed: Option<bool>,
    /// The signer's sessions with the shop this visit's calls were paid in, as their answers named them (`session`): the
    /// one connection a Stop closes, where nothing else uses it.
    sessions: Vec<String>,
}

/// A route of the seller, as its `/services` names it.
struct SellerRoute {
    path: String,
    free: bool,
    methods: Vec<String>,
}

/// An answer open now in a visit.
struct OpenStream {
    socket: UnixStream,
    /// The share it holds, where it holds one apart from [`State::sockets`].
    share: i64,
    opened: Instant,
    /// Let through in the grace after a stop ([`STOP_GRACE`]): a stop does not shut it.
    grace: bool,
}

impl State {
    /// The shares of answers that have been open a while: a film may run for hours, so a request
    /// waiting to run alone does not wait for them ([`Visit::reserve_alone`]).
    fn long_open(&self) -> i64 {
        self.streams.values().filter(|o| o.opened.elapsed() >= LONG_OPEN).map(|o| o.share).sum()
    }
}

/// What a share is for ([`Visit::reserve_as`]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Answer,
    /// A request waiting to run alone ([`Visit::reserve_alone`]).
    Alone,
    /// A WebSocket ([`Visit::reserve_socket`]).
    Socket,
}

pub struct Visit {
    /// Its id, as its requests' calls are counted among the connector's ([`crate::flight`]).
    id: String,
    base: String,
    /// The visit's limit: raised by the buyer while it is open ([`Visit::raise`]), never lowered.
    limit: std::sync::atomic::AtomicI64,
    /// The seller's listed prices as the most each of the visit's calls pays (`price_ceiling`, from
    /// the listing the buyer chose the app from): a seller whose terms ask more is paid nothing.
    ceiling: Option<Value>,
    state: Mutex<State>,
    turn: Condvar,
}

impl Visit {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The visit is stopped: no new request, and every answer open now ends here, so that nothing
    /// more is paid for it.
    fn stop(&self) {
        let mut s = self.lock();
        if !s.stopped {
            s.stopped_at = Some(Instant::now());
        }
        s.stopped = true;
        s.ended.get_or_insert_with(|| "Stopped.".into());
        s.streams.retain(|_, open| {
            if open.grace {
                return true;
            }
            let _ = open.socket.shutdown(std::net::Shutdown::Both);
            false
        });
        drop(s);
        self.turn.notify_all();
    }

    /// Whether the buyer stopped the visit: a call waiting to begin gives up ([`start_call`]).
    fn is_stopped(&self) -> bool {
        self.lock().stopped
    }

    /// Whether `req`, coming after the buyer's stop, is a small report of the page that still goes ([`STOP_GRACE`]): a
    /// `POST` of at most [`GRACE_BODY`] bytes, no range, within the grace. It is then counted among the grace's requests.
    fn take_grace(&self, req: &Request) -> bool {
        let mut s = self.lock();
        let small_post = req.method.eq_ignore_ascii_case("POST") && req.body.len() <= GRACE_BODY && req.header("Range").is_none();
        let ok = s.stopped && s.policy.is_none() && small_post && s.stopped_at.is_some_and(|t| t.elapsed() < STOP_GRACE);
        if ok {
            s.grace_open += 1;
        }
        ok
    }

    /// A share for a request let through in the grace: an ordinary one, of what is left of the limit, at once or not at
    /// all. The visit has ended, so [`Visit::reserve`] hands none out.
    fn reserve_grace(&self) -> Option<i64> {
        let mut s = self.lock();
        let share = (self.limit() - s.spent).min(self.answer_share());
        (share >= 1).then(|| {
            s.spent += share;
            s.held += share;
            share
        })
    }

    /// A request let through in the grace has ended.
    fn grace_done(&self) {
        let mut s = self.lock();
        s.grace_open = s.grace_open.saturating_sub(1);
        drop(s);
        self.turn.notify_all();
    }

    /// An answer's stream socket, for [`Visit::stop`] to shut until the guard is dropped; one that
    /// arrives after a stop is shut at once. `share`: what it holds apart from a WebSocket's.
    fn track(self: &Arc<Self>, src: &UnixStream, share: i64) -> Tracked {
        self.track_as(src, share, false)
    }

    /// [`Visit::track`]; `grace`: a request let through in the grace after a stop, which the stop leaves to end.
    fn track_as(self: &Arc<Self>, src: &UnixStream, share: i64, grace: bool) -> Tracked {
        let open = src.try_clone().ok();
        let mut s = self.lock();
        s.next_stream += 1;
        let id = s.next_stream;
        if let Some(socket) = open {
            if s.stopped && !grace {
                let _ = socket.shutdown(std::net::Shutdown::Both);
            } else {
                s.streams.insert(id, OpenStream { socket, share, opened: Instant::now(), grace });
            }
        }
        Tracked { visit: Arc::clone(self), id }
    }

    fn limit(&self) -> i64 {
        self.limit.load(Ordering::SeqCst)
    }

    /// The seller's origin (`https://host:port`), as the signer names a connection with it.
    fn origin(&self) -> String {
        origin_of(&self.base)
    }

    /// Whether the visit holds the shop's connection open: not ended, or ended at its limit and waiting for its owner
    /// to raise it.
    fn holds_open(&self) -> bool {
        let s = self.lock();
        s.ended.is_none() || (s.ended.as_deref() == Some(LIMIT_REACHED) && !s.stopped)
    }

    /// The buyer raises the visit's limit to `to` sat, more than it was (at most what a visit may have):
    /// a visit that ended at its limit goes on, its page as it was; one the buyer stopped does not.
    fn raise(&self, to: i64) -> Result<(), String> {
        let mut s = self.lock();
        if s.stopped || s.ended.as_deref().is_some_and(|e| e != LIMIT_REACHED) {
            return Err("This visit has ended. Open the app again.".into());
        }
        if !(self.limit() + 1..=MAX_LIMIT).contains(&to) {
            return Err(format!("A visit's limit is raised, to at most {MAX_LIMIT} sat."));
        }
        // under the state's lock: no share is handed out against the old limit after this
        self.limit.store(to, Ordering::SeqCst);
        s.ended = None;
        drop(s);
        self.turn.notify_all();
        Ok(())
    }

    fn report(&self) -> Value {
        let s = self.lock();
        // settled: every request of the visit has ended and the signer has said what each cost (and a stop has been carried
        // out), so `used_msat`, `paid_sats` and `tickets_bought` are final for what has run
        let settled = s.held == 0 && !s.closing && s.grace_open == 0;
        json!({"base": self.base, "limit_sats": self.limit(), "spent_sats": s.spent, "held_sats": s.held, "used_msat": s.used_msat, "paid_sats": s.paid,
               "tickets_bought": s.tickets, "settled": settled, "connection_closed": s.connection_closed,
               "ended": s.ended, "limit_reached": s.ended.as_deref() == Some(LIMIT_REACHED) && !s.stopped, "calls": s.calls, "policy_refused": s.policy})
    }

    /// The buyer's own spending rules refused a payment of this visit (`v`, the signer's refusal, or a call's
    /// `top_up_refused`): the visit ends with that rule's words, which the owner's log gets too, and its later requests
    /// are refused with it ([`Visit::policy_refusal`]) instead of asking the seller again and again. Another
    /// refusal is left as it is. `true`: ended for it.
    fn policy_stop(&self, v: &Value) -> bool {
        if !owner_limit(v) {
            return false;
        }
        let rule = v.get("rule").and_then(Value::as_str).unwrap_or("");
        let reason = v.get("reason").or(v.get("error")).and_then(Value::as_str).unwrap_or("");
        let limit = v.get("limit_sats").and_then(Value::as_i64);
        let mut s = self.lock();
        if s.policy.is_none() {
            eprintln!("lightning-stream: a visit ended: your spending rules refused a payment ({rule}{}): {reason}",
                      limit.map(|l| format!(", your limit {l} sat")).unwrap_or_default());
        }
        s.policy = Some(json!({"rule": rule, "reason": reason, "limit_sats": limit}));
        // the words the visit ends with: in plain words; the page that shows them names the shop and the field
        let words = match rule {
            "per_counterparty_daily" => "You've reached today's spending limit for this shop in your spending rules.",
            "per_counterparty" | "ticket_seller_cap" => "You've reached this week's spending limit for this shop in your spending rules.",
            "daily_budget" => "You've reached today's spending limit in your spending rules.",
            "weekly_budget" => "You've reached this week's spending limit in your spending rules.",
            _ => "Your spending rules refused the next payment of this visit.",
        };
        if s.ended.is_none() || s.ended.as_deref() == Some(LIMIT_REACHED) {
            s.ended = Some(format!("{words} Raise it in Settings → Spending rules."));
        }
        drop(s);
        self.turn.notify_all();
        true
    }

    /// A request of a visit that the buyer's own spending rules ended: refused with that rule and the visit's words, as
    /// the connector's own refusal (`None`: the visit did not end so). The seller's page sees this answer: the owner's
    /// limit and the wallet's sums stay out of it (the wallet's pages read them from the visit's report).
    fn policy_refusal(&self) -> Option<Response> {
        let s = self.lock();
        let p = s.policy.as_ref()?;
        Some(json_response(402, &json!({"error": s.ended, "rule": p["rule"]})))
    }

    /// The signer's final word on one call that held `share`: what the seller charged for its answer and what was
    /// paid for tickets for it, counted for the visit's report.
    /// The signer's session a call's answer `v` names, kept for the visit's Stop ([`State::sessions`]).
    fn note_session(&self, v: &Value) {
        if let Some(sid) = v.get("session").and_then(Value::as_str).filter(|s| !s.is_empty() && s.len() <= 128) {
            let mut s = self.lock();
            if !s.sessions.iter().any(|x| x == sid) && s.sessions.len() < 8 {
                s.sessions.push(sid.to_string());
            }
        }
    }

    fn account(&self, v: &Value, share: i64) {
        self.note_session(v);
        let num = |k: &str| v.get(k).and_then(|n| n.as_u64().or_else(|| n.as_str().and_then(|s| s.parse().ok())));
        // what the answer took from the credit: the seller's signed charge where it is more than the wallet's own count (an
        // answer cut short or left by the page, whose bytes on their way were charged), so that what the visit says it used
        // is what the connection's credit fell by
        // Only where the signer found no fault with the seller (a charge past the call's cap is one), and no more than the
        // call's own cap (its share) past the wallet's count: a seller's word is not taken for more than the call allowed
        let signed = v.pointer("/receipt/last/charged").and_then(|n| n.as_u64().or_else(|| n.as_str().and_then(|s| s.parse().ok())))
            .filter(|_| v.get("seller_fault").is_none_or(Value::is_null));
        let price = num("price_msat").unwrap_or(0);
        let used = price.max(signed.unwrap_or(0).min(price.saturating_add(share.max(0).unsigned_abs().saturating_mul(1000))));
        let charged = num("charged_sats").unwrap_or(0);
        // a top-up the buyer's own rules refused: the request went on, and the visit ends with that rule's words
        // (or a ticket for the answer, which stopped where the credit ended: `policy_refused`)
        if let Some(t) = v.get("top_up_refused").or(v.get("policy_refused")).filter(|t| t.is_object()) {
            self.policy_stop(t);
        }
        let mut s = self.lock();
        s.used_msat = s.used_msat.saturating_add(used);
        s.paid = s.paid.saturating_add(i64::try_from(charged).unwrap_or(0));
        if let Some(b) = num("balance_msat") {
            s.credit_msat = Some(b);
        }
        // what one ticket of the seller books, from what the tickets released for this call came to
        if let Some(n) = num("tickets_released").filter(|n| *n > 0) {
            s.ticket = s.ticket.max(i64::try_from(charged / n).unwrap_or(0));
            s.tickets = s.tickets.saturating_add(n);
        }
    }

    /// The credit the visit keeps ahead of its requests: what the answers running now may still draw (their shares,
    /// each the most its answer may charge) and one request's share more, at most a ticket, and never more than what is
    /// left of the visit's limit for its answers. Below it, a request may cut short where the credit ends, its own share
    /// too small for the next ticket. Above it, nothing is bought ahead: the credit covers every answer that could be
    /// running, and the visit buys only when that is no longer so.
    ///
    /// (Before 0.2.7 it was four shares whatever was running: a 1,000 sat visit topped up below 500 sat of credit while
    /// signing in, a ticket its page never needed.)
    fn credit_floor(&self, s: &State, ticket: i64) -> i64 {
        let running = (s.held - s.settling).max(0);
        let left = (self.limit() - s.spent + s.held).max(0);
        running.saturating_add(self.answer_share()).min(ticket).min(left).max(1)
    }

    /// The lane, where the credit is low: a share with room for a ticket, and the credit to top up to
    /// (`top_up_sats`) before the request leaves. One request holds it at a time. It goes first, as a
    /// request waiting to run alone does: no new share is handed out while it waits for that much of
    /// the limit to be free, which the requests running now give back as they end; past [`LANE_WAIT`]
    /// it runs on an ordinary share instead. `None`: an ordinary share.
    fn take_lane(&self) -> Option<(i64, i64)> {
        let mut s = self.lock();
        // a ticket of a size the visit has not seen yet: room for half of the limit, which the top-up spends only where a
        // ticket fits (the signer releases none past the call's limit)
        let ticket = if s.ticket > 0 { s.ticket } else { self.limit() / 2 };
        let credit = s.credit_msat?;
        let floor = self.credit_floor(&s, ticket);
        let most = self.answer_share().saturating_add(ticket);
        if ticket <= 0 || s.lane || s.alone > 0 || s.ended.is_some() || credit >= floor.unsigned_abs() * 1000 || most > self.limit() - s.spent + s.held - s.sockets - s.settling - s.long_open() {
            return None;
        }
        s.lane = true;
        s.alone += 1;
        let until = Instant::now() + LANE_WAIT;
        while s.ended.is_none() && self.limit() - s.spent < most && Instant::now() < until {
            let left = until.saturating_duration_since(Instant::now()).min(Duration::from_secs(1));
            s = self.turn.wait_timeout(s, left).unwrap_or_else(|p| p.into_inner()).0;
        }
        s.alone -= 1;
        let got = s.ended.is_none() && self.limit() - s.spent >= most;
        // the credit heard of is spent on this decision: the next request waits for the signer's word after the top-up (or
        // after the requests running now), not the same low figure, so that it does not take the lane again on it and hold
        // every request up behind it
        s.credit_msat = None;
        if got {
            s.spent += most;
            s.held += most;
        } else {
            s.lane = false;
        }
        drop(s);
        self.turn.notify_all();
        got.then_some((most, floor))
    }

    /// The lane's request has its answer, or none: the lane is free.
    fn lane_done(&self) {
        self.lock().lane = false;
        self.turn.notify_all();
    }

    /// A request's share of the limit: an eighth of it, at least [`MIN_SHARE`] and at most
    /// [`ANSWER_SHARE`]. A 1,000 sat visit runs eight requests at once.
    fn answer_share(&self) -> i64 {
        (self.limit() / 8).clamp(MIN_SHARE, ANSWER_SHARE)
    }

    /// A request's share asked again after its answer or ticket did not fit: its share and room for
    /// one of the seller's tickets, where a refusal named what one books.
    fn ticket_share(&self) -> i64 {
        self.answer_share().saturating_add(self.lock().ticket)
    }

    /// Hold up to `most` of what is left of the limit for one request, waiting for a running one to
    /// give its share back where none is free. `Err`: the visit has ended, its limit is spent (with
    /// nothing running that could give some back), or the wait was too long.
    fn reserve(&self, most: i64) -> Result<i64, String> {
        self.reserve_as(most, Kind::Answer)
    }

    /// A request's share ([`Visit::answer_share`]).
    fn reserve_answer(&self) -> Result<i64, String> {
        self.reserve(self.answer_share())
    }

    /// A WebSocket's share, counted as the sockets' ([`State::sockets`]) as it is handed out: at most
    /// [`SOCKET_SHARE`], and the visit's sockets together at most half of the limit, so that the
    /// rest is always the page's requests'. `Err` at once where the sockets hold that half already.
    fn reserve_socket(&self) -> Result<i64, String> {
        self.reserve_as(SOCKET_SHARE, Kind::Socket)
    }

    fn reserve_as(&self, most: i64, kind: Kind) -> Result<i64, String> {
        let mut s = self.lock();
        let until = Instant::now() + TURN_WAIT;
        loop {
            if let Some(e) = &s.ended {
                return Err(e.clone());
            }
            // a request waiting to run alone goes first: no share is handed out past it
            if kind != Kind::Alone && s.alone > 0 {
                let now = Instant::now();
                if now >= until {
                    return Err("The page asked for too much at once: try again.".into());
                }
                s = self.turn.wait_timeout(s, until - now).unwrap_or_else(|p| p.into_inner()).0;
                continue;
            }
            let mut most = most;
            if kind == Kind::Socket {
                let room = self.limit() / 2 - s.sockets - s.socket_settling;
                if room < 1 {
                    return Err("This page has too many live connections open at once.".into());
                }
                most = most.min(room);
            }
            let share = (self.limit() - s.spent).min(most);
            if share >= 1 {
                s.spent += share;
                s.held += share;
                if kind == Kind::Socket {
                    s.sockets += share;
                }
                return Ok(share);
            }
            if s.held == 0 {
                s.ended = Some(LIMIT_REACHED.into());
                return Err(s.ended.clone().unwrap_or_default());
            }
            let now = Instant::now();
            if now >= until {
                return Err("The page asked for too much at once: try again.".into());
            }
            s = self.turn.wait_timeout(s, until - now).unwrap_or_else(|p| p.into_inner()).0;
        }
    }

    /// Hold up to `most` of what is left once no other request holds a share: what a request whose
    /// share was too small for a ticket waits for, the most it can then have. `Err` as for
    /// [`Visit::reserve`].
    fn reserve_alone(&self, most: i64) -> Result<i64, String> {
        let mut s = self.lock();
        s.alone += 1;
        let until = Instant::now() + TURN_WAIT;
        let mut timed_out = false;
        while s.held > s.sockets + s.settling + s.long_open() && s.ended.is_none() {
            let now = Instant::now();
            if now >= until {
                timed_out = true;
                break;
            }
            // an answer open now becomes a long one without a word: looked at again in a while
            s = self.turn.wait_timeout(s, (until - now).min(Duration::from_secs(1))).unwrap_or_else(|p| p.into_inner()).0;
        }
        drop(s);
        let got = if timed_out { Err("The page asked for too much at once: try again.".into()) } else { self.reserve_as(most, Kind::Alone) };
        self.lock().alone -= 1;
        self.turn.notify_all();
        got
    }

    /// A request that held `share` was refused because a ticket did not fit in it: where nothing
    /// else is running and no more than that share is left, nothing more can be bought in this
    /// visit, and it ends. `true`: ended.
    fn spent_out(&self, share: i64) -> bool {
        let mut s = self.lock();
        if s.held == 0 && self.limit() - s.spent <= share {
            s.ended.get_or_insert_with(|| LIMIT_REACHED.into());
            return true;
        }
        false
    }

    /// A request that held `share` was refused, its call's reply `v`: what it was charged stays
    /// spent, and what a ticket of the seller's books, where the reply names it, is kept.
    fn refused(self: &Arc<Self>, share: i64, f: Failed) {
        let Failed { v, done, unknown } = f;
        self.note_session(&v);
        self.policy_stop(&v);
        if let Some(t) = v.get("ticket_booking_sats").and_then(Value::as_i64) {
            let mut s = self.lock();
            s.ticket = s.ticket.max(t);
        }
        if let Some(c) = v.get("charged_sats").and_then(Value::as_i64) {
            self.account(&v, share);
            return self.release(share, c);
        }
        match done {
            // the signer is still at the call, and may still book tickets for it: the share stays spent until it says
            // what it charged (nothing said: all of it)
            Some(done) => {
                let visit = self.clone();
                std::thread::spawn(move || visit.settle(share, Some(done), false));
            }
            // the signer's answer never came (the call to it failed or timed out): what it charged is not known, and
            // all of the share stays spent
            None if unknown => self.release(share, share),
            None => self.release(share, 0),
        }
    }

    /// A WebSocket's share ([`Visit::reserve_socket`]) is no longer an open socket's: it did not open.
    fn socket_closed(&self, share: i64) {
        let mut s = self.lock();
        s.sockets -= share;
        drop(s);
        self.turn.notify_all();
    }

    /// The seller's routes from its `/services` document, read since the `gen`th forgetting
    /// ([`State::routes_gen`]): which of them are free, for which methods. A read begun before the
    /// routes were last forgotten is not kept. `true`: kept.
    fn learn_routes(&self, services: &Value, gen: u64) -> bool {
        let Some(all) = services.get("routes").and_then(Value::as_array) else { return false };
        let routes: Vec<SellerRoute> = all.iter().take(256).filter_map(|r| {
            let path = r.get("path")?.as_str()?.to_string();
            let methods = r.get("methods").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str)
                .map(str::to_ascii_uppercase).collect();
            path.starts_with('/').then_some(SellerRoute { path, free: r.get("free").and_then(Value::as_bool) == Some(true), methods })
        }).collect();
        let mut s = self.lock();
        if s.routes_gen != gen {
            return false;
        }
        s.routes = Some(routes);
        true
    }

    /// Whether `url` asked for with `method` is on a free route of the seller, as its gateway takes a
    /// path: the longest route whose path ends in `/` and starts the URL's path, or that is the whole
    /// path. A path taken for free that is not is refused by the signer before anything is paid
    /// (`max_sats` 0), and then goes the paid way.
    fn is_free(&self, url: &str, method: &str) -> bool {
        if !matches!(method, "GET" | "HEAD") {
            return false;
        }
        let path = url.split_once("://").and_then(|(_, rest)| rest.find('/').map(|i| &rest[i..])).unwrap_or("/");
        let path = path.split(['?', '#']).next().unwrap_or("/");
        // a path the gateway may read otherwise once decoded or normalized goes the paid way
        if path.contains(['%', '\\']) || path.split('/').any(|seg| seg == "." || seg == "..") {
            return false;
        }
        let s = self.lock();
        let Some(routes) = &s.routes else { return false };
        routes.iter().filter(|r| if r.path.ends_with('/') { path.starts_with(r.path.as_str()) } else { path == r.path })
            .max_by_key(|r| r.path.len()).is_some_and(|r| r.free && r.methods.iter().any(|m| m == method))
    }

    /// A path taken for free was not: the seller's routes are read again before any is taken for free.
    fn forget_routes(&self) {
        let mut s = self.lock();
        s.routes = None;
        s.routes_gen += 1;
    }

    /// A request that held `share` has stopped (a WebSocket's, `socket`: and closed): what the signer
    /// says it charged (`done`), within [`SETTLE_WAIT`], stays spent, all of the share where it says
    /// nothing. Its share is counted apart while it waits ([`State::settling`]).
    fn settle(&self, share: i64, done: Option<mpsc::Receiver<Result<Value, String>>>, socket: bool) {
        self.settle_begin(share, socket);
        self.settle_end(share, done, socket);
    }

    /// The first half of [`Visit::settle`], at once: the share is counted apart.
    fn settle_begin(&self, share: i64, socket: bool) {
        let mut s = self.lock();
        s.settling += share;
        if socket {
            s.sockets -= share;
            s.socket_settling += share;
        }
        drop(s);
        self.turn.notify_all();
    }

    /// The second half of [`Visit::settle`]: the wait for the signer's word, and the release.
    fn settle_end(&self, share: i64, done: Option<mpsc::Receiver<Result<Value, String>>>, socket: bool) {
        let reply = done.and_then(|d| d.recv_timeout(SETTLE_WAIT).ok()).and_then(Result::ok);
        if let Some(v) = &reply {
            self.account(v, share);
        }
        let charged = reply.and_then(|v| v.get("charged_sats").and_then(Value::as_i64)).unwrap_or(share);
        let mut s = self.lock();
        s.settling -= share;
        if socket {
            s.socket_settling -= share;
        }
        drop(s);
        self.release(share, charged);
    }

    /// A request that held `share` has ended, having cost `charged`: only that stays spent. A signer
    /// that says it charged more than the share it was allowed (or anything for a free path, share 0)
    /// is not hidden: all of it stays spent, it is logged, and the visit ends.
    fn release(&self, share: i64, charged: i64) {
        let charged = charged.max(0);
        let mut s = self.lock();
        s.spent = s.spent - share + charged;
        s.held -= share;
        if charged > share {
            eprintln!("lightning-stream: the wallet says a request of a visit cost {charged} sat, past the {share} sat it was allowed: counted, and the visit ends");
            s.ended.get_or_insert_with(|| "The wallet spent past this visit's share for a request: the visit has ended.".into());
        }
        drop(s);
        self.turn.notify_all();
    }
}

#[derive(Default)]
pub struct Visits {
    open: Mutex<HashMap<String, Arc<Visit>>>,
}

impl Visits {
    fn get(&self, id: &str) -> Option<Arc<Visit>> {
        self.open.lock().unwrap_or_else(|p| p.into_inner()).get(id).cloned()
    }

    /// Whether a visit other than `id` to the shop at `origin` holds its connection open ([`Visit::holds_open`]).
    fn other_open(&self, origin: &str, id: &str) -> bool {
        let all: Vec<(String, Arc<Visit>)> = self.open.lock().unwrap_or_else(|p| p.into_inner()).iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        all.iter().any(|(k, v)| k != id && v.origin() == origin && v.holds_open())
    }

    fn open(&self, base: String, limit: i64, ceiling: Option<Value>) -> Result<String, String> {
        let mut m = self.open.lock().unwrap_or_else(|p| p.into_inner());
        m.retain(|_, v| {
            let s = v.lock();
            // an answer still open keeps its visit, however long ago it was asked for, so that a stop finds it
            // and one at its limit waits for the buyer to raise it, as an open one does
            let waiting = s.ended.is_none() || (s.ended.as_deref() == Some(LIMIT_REACHED) && !s.stopped);
            // and one whose stop is still being carried out is kept for its report
            !s.streams.is_empty() || s.closing || (waiting && s.last.is_none_or(|t| t.elapsed() < IDLE))
        });
        if m.len() >= MAX_VISITS {
            return Err("too many visits open".into());
        }
        let id = random_hex();
        m.insert(id.clone(), Arc::new(Visit { id: id.clone(), base, limit: limit.into(), ceiling, state: Mutex::new(State { last: Some(Instant::now()), ..State::default() }), turn: Condvar::new() }));
        Ok(id)
    }
}


/// The base of a visit: an absolute http(s) URL ending in `/`, of visible characters.
fn base_ok(b: &str) -> bool {
    (b.starts_with("https://") || b.starts_with("http://")) && b.ends_with('/') && b.len() <= 2000 && b.bytes().all(|c| c.is_ascii_graphic())
        && !b.contains(['?', '#', '\\'])
}

impl Connector {
    pub(crate) fn visits_reply(&self, req: &Request) -> Option<Reply> {
        let t = req.target.as_str();
        if t == "/visits" {
            if req.method != "POST" {
                return Some(Reply::Whole(json_response(405, &json!({"error": "POST a visit"}))));
            }
            let v: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let base = v.get("base").and_then(Value::as_str).unwrap_or("").to_string();
            let limit = v.get("limit_sats").and_then(Value::as_i64).unwrap_or(0);
            if !base_ok(&base) || !(1..=MAX_LIMIT).contains(&limit) {
                return Some(Reply::Whole(json_response(400, &json!({"error": "a visit is a seller URL ending in / and a limit of 1 sat or more"}))));
            }
            let ceiling = v.get("price_ceiling").filter(|c| c.is_object()).cloned();
            return Some(Reply::Whole(match self.visits.open(base, limit, ceiling) {
                Ok(id) => {
                    // the seller's free routes, read beside the page's first requests (which go the paid way until then)
                    if let Some(visit) = self.visits.get(&id) {
                        spawn_read_routes(&self.cfg, &visit);
                    }
                    json_response(200, &json!({"visit": id}))
                }
                Err(e) => json_response(503, &json!({"error": e})),
            }));
        }
        if let Some(rest) = t.strip_prefix("/visits/") {
            if let Some(id) = rest.strip_suffix("/limit") {
                let Some(v) = self.visits.get(id) else {
                    return Some(Reply::Whole(json_response(404, &json!({"error": "no such visit"}))));
                };
                if req.method != "POST" {
                    return Some(Reply::Whole(json_response(405, &json!({"error": "POST a new limit"}))));
                }
                // asked by the wallet on this box, never by a page: a browser's request (it names its `Origin`) or a form's (not
                // JSON) is refused, so that no page can raise what the owner may spend
                let json_body = req.header("Content-Type").is_some_and(|t| t.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/json"));
                if req.header("Origin").is_some() || !json_body {
                    return Some(Reply::Whole(json_response(403, &json!({"error": "a visit's limit is raised by the wallet, as JSON"}))));
                }
                let to = serde_json::from_slice::<Value>(&req.body).ok().and_then(|b| b.get("limit_sats").and_then(Value::as_i64)).unwrap_or(0);
                return Some(Reply::Whole(match v.raise(to) {
                    Ok(()) => json_response(200, &v.report()),
                    Err(e) => json_response(409, &json!({"error": e})),
                }));
            }
            let (id, stop) = match rest.strip_suffix("/stop") {
                Some(id) => (id, true),
                None => (rest, false),
            };
            let Some(v) = self.visits.get(id) else {
                return Some(Reply::Whole(json_response(404, &json!({"error": "no such visit"}))));
            };
            if stop {
                if req.method != "POST" {
                    return Some(Reply::Whole(json_response(405, &json!({"error": "POST to stop"}))));
                }
                let first = !v.is_stopped();
                v.stop();
                if first {
                    v.lock().closing = true;
                    let (cfg, visits, visit) = (self.cfg.clone(), self.visits.clone(), v.clone());
                    std::thread::spawn(move || finish_stop(&cfg, &visits, &visit));
                }
            }
            return Some(Reply::Whole(json_response(200, &v.report())));
        }
        let rest = t.strip_prefix("/v/")?;
        let (id, path) = rest.split_once('/').unwrap_or((rest, ""));
        let Some(visit) = self.visits.get(id) else {
            return Some(Reply::Whole(json_response(404, &json!({"error": "This visit has ended. Open the app again."}))));
        };
        Some(self.visit_call(visit, path, req))
    }

    /// One request of a page, paid for within a share of the visit's limit.
    fn visit_call(&self, visit: Arc<Visit>, path: &str, req: &Request) -> Reply {
        let t0 = Instant::now();
        if req.header("Upgrade").is_some_and(|u| u.eq_ignore_ascii_case("websocket")) {
            return self.visit_socket(visit, path, req);
        }
        if let Some(r) = visit.policy_refusal() {
            return Reply::Whole(r);
        }
        // a small report of the page just after the buyer's stop (a media server's "playback stopped" as its frame
        // closes) still goes, on the shop's credit and within the visit's limit; nothing else does
        let grace = visit.lock().ended.is_some() && visit.take_grace(req);
        {
            let mut s = visit.lock();
            if let (Some(e), false) = (&s.ended, grace) {
                return Reply::Whole(json_response(402, &json!({"error": e, "rule": "visit"})));
            }
            s.calls += 1;
            s.last = Some(Instant::now());
        }
        if grace {
            return self.visit_grace_call(visit, path, req);
        }
        let url = format!("{}{path}", visit.base);
        let headers: Vec<Value> = req.headers.iter().filter(|(k, _)| PASSED.contains(&k.to_ascii_lowercase().as_str()))
            .take(24).map(|(k, v)| json!([k, v])).collect();
        // a range in parts, each paid for within one share
        let range = req.header("Range").map(str::trim).filter(|r| one_range(r)).map(|r| bounded_range(r, RANGE_CHUNK));
        let method = req.method.to_ascii_uppercase();
        let body = if req.body.is_empty() { None } else {
            use base64::Engine as _;
            Some(base64::engine::general_purpose::STANDARD.encode(&req.body))
        };
        let call_as = |max_sats: i64, known_terms: bool| -> Result<Started, Failed> {
            // a page's many reads are paid on the terms the seller stated for their route, without asking each one's price
            let mut params = json!({"url": url, "method": method, "max_sats": max_sats, "task": self.cfg.task, "headers": headers, "head_headers": true,
                                    "known_terms": known_terms});
            if let Some(b) = &body {
                params["body_b64"] = b.clone().into();
            }
            if let Some(c) = &visit.ceiling {
                params["price_ceiling"] = c.clone();
            }
            if let Some(r) = &range {
                params["range"] = r.clone().into();
            }
            if let Some(m) = params.as_object_mut() {
                xbt_wallet_mcp::wallet::with_transport(m);
            }
            self.start_in(&visit, params, false)
        };
        let call = |max_sats: i64| call_as(max_sats, true);
        // the lane: room for a ticket, and the credit topped up before the request leaves
        let call_topped = |max_sats: i64, top_up: i64| -> Result<Started, Failed> {
            let mut params = json!({"url": url, "method": method, "max_sats": max_sats, "task": self.cfg.task, "headers": headers, "head_headers": true,
                                    "known_terms": true, "top_up_sats": top_up});
            if let Some(b) = &body {
                params["body_b64"] = b.clone().into();
            }
            if let Some(c) = &visit.ceiling {
                params["price_ceiling"] = c.clone();
            }
            if let Some(r) = &range {
                params["range"] = r.clone().into();
            }
            if let Some(m) = params.as_object_mut() {
                xbt_wallet_mcp::wallet::with_transport(m);
            }
            self.start_in(&visit, params, false)
        };
        let max_sats = |f: &Failed| f.v.get("rule").and_then(Value::as_str) == Some("max_sats");
        // a path the seller serves free: asked for as it is (the signer asks it unpaid, as for a price, and is answered),
        // with nothing to spend and no share held. Sent on another route's terms it would be refused unpaid and asked
        // again, and the terms the signer kept for the seller forgotten
        let free = if visit.is_free(&url, &method) {
            match call_as(0, false) {
                Ok(s) => Some(s),
                // not free now: the paid way, and the seller's routes read again before a path is taken for free
                Err(f) if max_sats(&f) => {
                    visit.forget_routes();
                    spawn_read_routes(&self.cfg, &visit);
                    None
                }
                Err(f) => return Reply::Whole(refusal(&f.v)),
            }
        } else {
            None
        };
        let lane = if free.is_none() { visit.take_lane() } else { None };
        let laned = match lane {
            Some((share, top_up)) => {
                let got = call_topped(share, top_up);
                visit.lane_done();
                match got {
                    Ok(s) => Some((s, share)),
                    // its room was too small after all (a ticket dearer than the visit knew): the ordinary way, which learns it
                    Err(f) if max_sats(&f) => {
                        visit.refused(share, f);
                        None
                    }
                    Err(f) => {
                        let v = f.v.clone();
                        visit.refused(share, f);
                        return Reply::Whole(refusal(&v));
                    }
                }
            }
            None => None,
        };
        let (started, share) = if let Some(s) = free { (s, 0) } else if let Some(x) = laned { x } else {
            // a share of what is left: the most this answer may charge, tickets bought for it included
            let share = match visit.reserve_answer() {
                Ok(n) => n,
                Err(e) => return Reply::Whole(json_response(402, &json!({"error": e, "rule": "visit"}))),
            };
            match call(share) {
                Ok(s) => (s, share),
                Err(f) if max_sats(&f) => {
                    // the answer or a ticket did not fit in the share: the refusal named what one books. Asked again with
                    // room for one beside the share; where that is still too small, with all that is left once the others
                    // have ended
                    visit.refused(share, f);
                    if visit.spent_out(share) {
                        return Reply::Whole(json_response(402, &json!({"error": LIMIT_REACHED, "rule": "visit"})));
                    }
                    let again = match visit.reserve(visit.ticket_share()) {
                        Ok(n) => n,
                        Err(e) => return Reply::Whole(json_response(402, &json!({"error": e, "rule": "visit"}))),
                    };
                    match call(again) {
                        Ok(s) => (s, again),
                        Err(f) if max_sats(&f) => {
                            visit.refused(again, f);
                            let share = match visit.reserve_alone(i64::MAX) {
                                Ok(n) => n,
                                Err(e) => return Reply::Whole(json_response(402, &json!({"error": e, "rule": "visit"}))),
                            };
                            match call(share) {
                                Ok(s) => (s, share),
                                Err(f) => {
                                    let v = f.v.clone();
                                    let out = max_sats(&f);
                                    visit.refused(share, f);
                                    if out && visit.spent_out(share) {
                                        return Reply::Whole(json_response(402, &json!({"error": LIMIT_REACHED, "rule": "visit"})));
                                    }
                                    return Reply::Whole(refusal(&v));
                                }
                            }
                        }
                        Err(f) => {
                            let v = f.v.clone();
                            visit.refused(again, f);
                            return Reply::Whole(refusal(&v));
                        }
                    }
                }
                Err(f) => {
                    let v = f.v.clone();
                    visit.refused(share, f);
                    return Reply::Whole(refusal(&v));
                }
            }
        };
        if std::env::var_os("XBT_TRACE_WIRE").is_some() {
            let status = started.head.get("status").and_then(Value::as_u64).unwrap_or(502);
            let p: String = path.split('?').next().unwrap_or("/").chars().take(60).collect();
            eprintln!("visit: {} {p} {status} {} ms", req.method, t0.elapsed().as_millis());
        }
        answer_reply(visit, started, share, false)
    }

    /// One request of a page let through in the grace after the buyer's stop ([`Visit::take_grace`]): on an ordinary
    /// share of what is left of the limit, drawing only on the credit the shop holds (`credit_only`: no ticket is bought
    /// for it), and refused at once where no share is left.
    fn visit_grace_call(&self, visit: Arc<Visit>, path: &str, req: &Request) -> Reply {
        let Some(share) = visit.reserve_grace() else {
            visit.grace_done();
            return Reply::Whole(json_response(402, &json!({"error": LIMIT_REACHED, "rule": "visit"})));
        };
        let headers: Vec<Value> = req.headers.iter().filter(|(k, _)| PASSED.contains(&k.to_ascii_lowercase().as_str()))
            .take(24).map(|(k, v)| json!([k, v])).collect();
        let mut params = json!({"url": format!("{}{path}", visit.base), "method": "POST", "max_sats": share, "task": self.cfg.task, "headers": headers,
                                "head_headers": true, "known_terms": true, "credit_only": true});
        if !req.body.is_empty() {
            use base64::Engine as _;
            params["body_b64"] = base64::engine::general_purpose::STANDARD.encode(&req.body).into();
        }
        if let Some(c) = &visit.ceiling {
            params["price_ceiling"] = c.clone();
        }
        if let Some(m) = params.as_object_mut() {
            xbt_wallet_mcp::wallet::with_transport(m);
        }
        match self.start_in(&visit, params, true) {
            Ok(started) => answer_reply(visit, started, share, true),
            Err(f) => {
                let v = f.v.clone();
                visit.refused(share, f);
                visit.grace_done();
                Reply::Whole(refusal(&v))
            }
        }
    }
}

/// A paid request's answer handed on to the page as it arrives, its share settled however it ends; `grace`: one let
/// through after the buyer's stop, which the stop leaves to end and which is counted done when it has.
fn answer_reply(visit: Arc<Visit>, started: Started, share: i64, grace: bool) -> Reply {
    let Started { head, first, src, done } = started;
    let status = head.get("status").and_then(Value::as_u64).and_then(|s| u16::try_from(s).ok()).unwrap_or(502);
    let mut out_headers: Vec<(String, String)> = vec![];
    for h in head.get("headers").and_then(Value::as_array).into_iter().flatten() {
        if let (Some(k), Some(v)) = (h.get(0).and_then(Value::as_str), h.get(1).and_then(Value::as_str)) {
            // what frames the body is this answer's own
            if !["content-length", "transfer-encoding", "connection", "keep-alive", "content-encoding"].contains(&k.to_ascii_lowercase().as_str()) {
                out_headers.push((k.to_string(), v.to_string()));
            }
        }
    }
    if !out_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
        if let Some(t) = head.get("content_type").and_then(Value::as_str) {
            out_headers.push(("Content-Type".into(), t.into()));
        }
    }
    let length = head.get("content_length").and_then(Value::as_u64);
    let tracked = visit.track_as(&src, share, grace);
    let mut settle = Settle { visit, share, tracked: Some(tracked), src: Some(src), done: Some(done), grace };
    Reply::Stream(Streamed {
        status,
        headers: out_headers,
        length,
        body: Box::new(move |out: &mut dyn BodyWriter| {
            out.send(&first)?;
            let mut sent = first.len() as u64;
            let mut buf = vec![0u8; 64 << 10];
            while let Some(src) = settle.src.as_mut() {
                let n = src.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                out.send(&buf[..n])?;
                sent += n as u64;
            }
            drop(settle.src.take());
            // the signer's account, where the length does not say: an answer it ended early is cut short for the page too
            let r = whole(length, sent, || settle.account());
            // the owner's log says why a page saw an answer cut short (its status and the wallet's words; no URL)
            if let Err(e) = &r {
                eprintln!("lightning-stream: a page's answer (HTTP {status}) was cut short: {e}");
            }
            r
        }),
    })
}

impl Connector {
    /// A page's WebSocket: paid for as its bytes pass, both ways, from a share of the visit's limit
    /// held while it is open ([`SOCKET_SHARE`]).
    fn visit_socket(&self, visit: Arc<Visit>, path: &str, req: &Request) -> Reply {
        if req.method != "GET" {
            return Reply::Whole(json_response(400, &json!({"error": "a WebSocket opens with a GET"})));
        }
        {
            let mut s = visit.lock();
            s.calls += 1;
            s.last = Some(Instant::now());
        }
        let share = match visit.reserve_socket() {
            Ok(n) => n,
            Err(e) => return Reply::Whole(json_response(402, &json!({"error": e, "rule": "visit"}))),
        };
        let headers: Vec<Value> = req.headers.iter()
            .filter(|(k, _)| { let l = k.to_ascii_lowercase(); PASSED.contains(&l.as_str()) || SOCKET_HEADERS.contains(&l.as_str()) })
            .take(24).map(|(k, v)| json!([k, v])).collect();
        let mut params = json!({"url": format!("{}{path}", visit.base), "method": "GET", "max_sats": share, "task": self.cfg.task, "headers": headers,
                            "head_headers": true, "upgrade": true});
        if let Some(c) = &visit.ceiling {
            params["price_ceiling"] = c.clone();
        }
        if let Some(m) = params.as_object_mut() {
            xbt_wallet_mcp::wallet::with_transport(m);
        }
        let Started { head, first, src, done } = match self.start_in(&visit, params, false) {
            Ok(s) => s,
            Err(f) => {
                let v = f.v.clone();
                visit.socket_closed(share);
                visit.refused(share, f);
                return Reply::Whole(refusal(&v));
            }
        };
        // from here the share is settled however the socket ends, also where the page's side never opens
        // (the 101 could not be written to it) or its join panics: the run below is then never called
        let hold = SocketHold { visit: visit.clone(), share, done: Some(done) };
        let status = head.get("status").and_then(Value::as_u64).unwrap_or(502);
        if status != 101 {
            drop(src);
            // nothing said of what it charged: all of the share stays spent
            hold.settle();
            return Reply::Whole(json_response(502, &json!({"error": format!("the seller did not open the WebSocket (HTTP {status})")})));
        }
        let headers: Vec<(String, String)> = head.get("headers").and_then(Value::as_array).into_iter().flatten()
            .filter_map(|h| Some((h.get(0)?.as_str()?.to_string(), h.get(1)?.as_str()?.to_string())))
            .filter(|(k, _)| k.to_ascii_lowercase().starts_with("sec-websocket-"))
            .chain(std::iter::once(("Upgrade".to_string(), "websocket".to_string())))
            .collect();
        let tracked = visit.track(&src, 0);
        Reply::Upgrade(xbt_svc::http::Upgraded {
            headers,
            run: Box::new(move |client, early| {
                join_socket(client, early, src, first);
                drop(tracked);
                hold.settle();
            }),
        })
    }

    /// Ask the signer to pay for one request and stream its answer: the head line and the first
    /// bytes, or `Err` with the signer's answer when it ended before any byte came (a refusal).
    #[cfg(test)]
    fn start(&self, params: Value) -> Result<Started, Failed> {
        start_call(&self.cfg, params)
    }

    /// [`Connector::start`] for a request of `visit`: given up while it waits to begin, where the visit is stopped (unless it
    /// is let through in the grace after the stop, `grace`).
    fn start_in(&self, visit: &Visit, params: Value, grace: bool) -> Result<Started, Failed> {
        start_call_until(&self.cfg, params, Some(&visit.id), &|| !grace && visit.is_stopped())
    }
}

/// A WebSocket's share, from the seller's 101 until it is settled: by [`SocketHold::settle`] when the
/// socket ends, or, where that never comes (the page's side never opened, a panic), when it is
/// dropped, the wait for the signer's word then on a thread of its own.
struct SocketHold {
    visit: Arc<Visit>,
    share: i64,
    done: Option<mpsc::Receiver<Result<Value, String>>>,
}

impl SocketHold {
    fn settle(mut self) {
        let done = self.done.take();
        self.visit.settle(self.share, done, true);
        self.share = 0;
    }
}

impl Drop for SocketHold {
    fn drop(&mut self) {
        if self.share == 0 {
            return;
        }
        let (visit, share, done) = (self.visit.clone(), self.share, self.done.take());
        visit.settle_begin(share, true);
        std::thread::spawn(move || visit.settle_end(share, done, true));
    }
}

/// The rest of a buyer's stop, behind its answer: once the requests let through in the stop's grace have ended, the shop's
/// connection is closed where no other open visit uses it (`others`), as Stop on Live connections closes it. That ends at
/// the signer what the visit's own stop could not reach: answers whose page side is gone but whose seller still sends
/// (and charges) the bytes on their way, a call still paying for a ticket before its head, a top-up, a WebSocket held
/// open. Their shares are then settled by the signer's word on each, waited for up to [`STOP_SETTLE_WAIT`], so that the
/// visit's report (`settled`) says what it used and what was paid in it.
fn finish_stop(cfg: &Config, visits: &Visits, visit: &Visit) {
    let until = Instant::now() + GRACE_WAIT;
    let mut s = visit.lock();
    while (s.stopped_at.is_some_and(|t| t.elapsed() < STOP_GRACE) || s.grace_open > 0) && Instant::now() < until {
        s = visit.turn.wait_timeout(s, Duration::from_millis(100)).unwrap_or_else(|p| p.into_inner()).0;
    }
    let sessions = s.sessions.clone();
    drop(s);
    // decided now, just before it is closed: another open visit to the shop, or a call of the connector's to it besides
    // this visit's own (a visit opened since the stop, the AI endpoint's answer, a player link's film), uses the same
    // connection, and keeps it. Only this visit's own session is closed, never the shop's sessions of other tasks
    let origin = visit.origin();
    let others = visits.other_open(&origin, &visit.id) || in_flight_besides(&cfg.signer, &origin, &visit.id);
    let closed = !others && !sessions.is_empty() && sessions.iter().all(|sid| {
        let r = xbt_wallet_mcp::wallet::signer_call(&cfg.signer, Duration::from_secs(90), "ticket_stop",
                                                    &json!({"session": sid, "why": "the buyer stopped the visit"}));
        match r {
            Ok(v) => v.get("verdict").and_then(Value::as_str).is_some_and(|d| d == "allow" || d == "partial"),
            Err(e) => {
                eprintln!("lightning-stream: a stopped visit's connection with the shop could not be closed: {e}");
                false
            }
        }
    });
    let until = Instant::now() + STOP_SETTLE_WAIT;
    let mut s = visit.lock();
    s.connection_closed = Some(closed);
    while s.held > 0 && Instant::now() < until {
        s = visit.turn.wait_timeout(s, Duration::from_millis(100)).unwrap_or_else(|p| p.into_inner()).0;
    }
    s.closing = false;
    drop(s);
    visit.turn.notify_all();
}

/// [`read_routes`] on a thread of its own, unless a read is under way already.
fn spawn_read_routes(cfg: &Config, visit: &Arc<Visit>) {
    {
        let mut s = visit.lock();
        if s.routes_reading {
            return;
        }
        s.routes_reading = true;
    }
    let (cfg, visit) = (cfg.clone(), visit.clone());
    std::thread::spawn(move || {
        // a read begun before the routes were forgotten is not kept: read again, a few times at most
        for _ in 0..3 {
            let gen = visit.lock().routes_gen;
            if read_routes(&cfg, &visit, gen) || visit.lock().routes_gen == gen {
                break;
            }
        }
        visit.lock().routes_reading = false;
    });
}

/// The seller's routes, from its `/services` (unsigned, read unpaid: `max_sats` 0), for the visit to
/// ask for a path on a free one unpaid ([`Visit::learn_routes`]). Nothing read, nothing learned: the
/// page's requests go the paid way, as before. `true`: learned.
fn read_routes(cfg: &Config, visit: &Visit, gen: u64) -> bool {
    let Some((scheme, rest)) = visit.base.split_once("://") else { return false };
    let host = rest.split('/').next().unwrap_or(rest);
    let mut params = json!({"url": format!("{scheme}://{host}/services"), "method": "GET", "max_sats": 0, "task": cfg.task});
    if let Some(m) = params.as_object_mut() {
        xbt_wallet_mcp::wallet::with_transport(m);
    }
    let Ok(Started { head, first, src, done: _ }) = start_call(cfg, params) else { return false };
    if head.get("status").and_then(Value::as_u64) != Some(200) {
        return false;
    }
    let _ = src.set_read_timeout(Some(FIRST_BYTE));
    let mut body = first;
    if (&src).take(SERVICES_MAX.saturating_sub(body.len() as u64)).read_to_end(&mut body).is_err() {
        return false;
    }
    serde_json::from_slice::<Value>(&body).is_ok_and(|v| visit.learn_routes(&v, gen))
}

/// [`Connector::start`].
fn start_call(cfg: &Config, params: Value) -> Result<Started, Failed> {
    start_call_until(cfg, params, None, &|| false)
}

/// [`start_call`], given up where `stopped` says so while it waits for the signer to begin the answer (the visit was
/// stopped): the stream socket goes, so the answer has no reader, and the signer's word on the call is still waited for
/// ([`Visit::settle`]), the share held until it comes.
/// `owner`: the visit whose call it is, counted among the connector's calls to the shop while the signer has it.
fn start_call_until(cfg: &Config, mut params: Value, owner: Option<&str>, stopped: &dyn Fn() -> bool) -> Result<Started, Failed> {
    let name = format!("ls-{}", random_hex());
    let path = cfg.stream_dir.join(&name);
    let listener = listen_stream(&path).map_err(|e| Failed { v: json!({"error": format!("stream socket: {e}")}), done: None, unknown: false })?;
    let _ = listener.set_nonblocking(true);
    params["stream_to"] = name.into();
    params["stream_head"] = true.into();
    let (tx, done) = mpsc::channel::<Result<Value, String>>();
    let signer = cfg.signer.clone();
    // the signer could not be reached: nothing was sent, and nothing charged
    let unsent = Arc::new(AtomicBool::new(false));
    let u = unsent.clone();
    let flight = owner.map(|o| flight(&cfg.signer, params["url"].as_str().unwrap_or(""), o));
    std::thread::spawn(move || {
        let _flight = flight;
        let r = xbt_wallet_mcp::wallet::signer_call_sent(&signer, LONGEST, "xbt402_pay", &params).map_err(|(sent, e)| {
            u.store(!sent, Ordering::SeqCst);
            e
        });
        let _ = tx.send(r);
    });
    let started = Instant::now();
    let src = loop {
        match listener.accept() {
            Ok((s, _)) => break s,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                let _ = std::fs::remove_file(&path);
                return Err(Failed { v: json!({"error": format!("stream socket: {e}")}), done: Some(done), unknown: false });
            }
        }
        if let Ok(d) = done.try_recv() {
            let _ = std::fs::remove_file(&path);
            let unknown = d.is_err() && !unsent.load(Ordering::SeqCst);
            return Err(Failed { v: d.unwrap_or_else(|e| json!({"error": e})), done: None, unknown });
        }
        if stopped() {
            let _ = std::fs::remove_file(&path);
            return Err(Failed { v: json!({"error": "Stopped."}), done: Some(done), unknown: false });
        }
        if started.elapsed() > FIRST_ANSWER {
            let _ = std::fs::remove_file(&path);
            return Err(Failed { v: json!({"error": format!("the seller sent nothing within {} s", FIRST_ANSWER.as_secs())}), done: Some(done), unknown: false });
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let _ = std::fs::remove_file(&path);
    let _ = src.set_nonblocking(false);
    let _ = src.set_read_timeout(Some(FIRST_BYTE));
    let mut r = BufReader::new(src);
    let mut line = String::new();
    let ok = (&mut r).take(HEAD_LINE * 16).read_line(&mut line).is_ok() && line.ends_with('\n');
    let head: Value = if ok { serde_json::from_str(&line).unwrap_or(Value::Null) } else { Value::Null };
    if head.get("status").is_none() {
        return Err(Failed { v: json!({"error": "the signer sent no head for the answer"}), done: Some(done), unknown: false });
    }
    if let Some(why) = head.get("error").and_then(Value::as_str) {
        return Err(Failed { v: json!({"error": why}), done: Some(done), unknown: false });
    }
    let first = r.buffer().to_vec();
    let src = r.into_inner();
    let _ = src.set_read_timeout(None);
    Ok(Started { head, first, src, done })
}

/// A call that ended before any byte of its answer came: the signer's answer, or why there is none;
/// and the signer's final reply still to come, where the call may still be going.
struct Failed {
    v: Value,
    done: Option<mpsc::Receiver<Result<Value, String>>>,
    /// The signer's answer never came: the call to it failed or timed out, so what it charged is not
    /// known.
    unknown: bool,
}

struct Started {
    head: Value,
    first: Vec<u8>,
    src: UnixStream,
    done: mpsc::Receiver<Result<Value, String>>,
}

/// When an answer has been handed on (or its reader has gone): the stream is closed, so the signer
/// stops paying, then what the signer charged stays spent and the rest of the share goes back.
/// An answer's place in [`State::streams`], for as long as it is open.
struct Tracked {
    visit: Arc<Visit>,
    id: u64,
}

impl Drop for Tracked {
    fn drop(&mut self) {
        self.visit.lock().streams.remove(&self.id);
        self.visit.turn.notify_all();
    }
}

struct Settle {
    visit: Arc<Visit>,
    share: i64,
    tracked: Option<Tracked>,
    src: Option<UnixStream>,
    done: Option<mpsc::Receiver<Result<Value, String>>>,
    /// Let through in the grace after a stop: counted done once settled.
    grace: bool,
}

impl Settle {
    /// The signer's account of the call, within [`SETTLE_WAIT`]: the one wait for it, whose answer
    /// the settling that follows reads.
    fn account(&mut self) -> Option<Result<Value, String>> {
        let done = self.done.take()?;
        let account = done.recv_timeout(SETTLE_WAIT).ok()?;
        let (tx, rx) = mpsc::channel();
        let _ = tx.send(account.clone());
        self.done = Some(rx);
        Some(account)
    }
}

impl Drop for Settle {
    fn drop(&mut self) {
        drop(self.src.take());
        drop(self.tracked.take());
        // the signer's count of what left the wallet for this answer; nothing known is the whole share, kept spent
        self.visit.settle(self.share, self.done.take(), false);
        if self.grace {
            self.visit.grace_done();
        }
    }
}

/// A client's upgraded connection joined to the signer's stream socket, both ways, until either
/// side ends; what each sent before the join goes first.
fn join_socket(client: std::net::TcpStream, early: Vec<u8>, signer: UnixStream, first: Vec<u8>) {
    use std::io::Write as _;
    let (Ok(mut c2), Ok(mut s2)) = (client.try_clone(), signer.try_clone()) else { return };
    let (mut c1, mut s1) = (client, signer);
    std::thread::scope(|scope| {
        scope.spawn(move || {
            if s2.write_all(&early).is_ok() {
                let _ = io::copy(&mut c1, &mut s2);
            }
            let _ = s2.shutdown(std::net::Shutdown::Both);
            let _ = c1.shutdown(std::net::Shutdown::Both);
        });
        if c2.write_all(&first).is_ok() {
            let _ = io::copy(&mut s1, &mut c2);
        }
        let _ = c2.shutdown(std::net::Shutdown::Both);
        let _ = s1.shutdown(std::net::Shutdown::Both);
    });
}

/// The connector's own answer, marked so the app port tells it from the seller's.
fn json_response(status: u16, v: &Value) -> Response {
    let mut r = crate::json_response(status, v);
    r.headers.push(("X-LS-Refusal".into(), "1".into()));
    r
}

/// A call the signer refused, or could not make, before any byte came.
fn refusal(v: &Value) -> Response {
    let reason = v.get("reason").or(v.get("error")).and_then(Value::as_str).unwrap_or("the call ended with no answer");
    let rule = v.get("rule").and_then(Value::as_str).unwrap_or("");
    // the page only sees a status; the owner's log says why (no URL, no header, nothing of the buyer's)
    eprintln!("lightning-stream: a page's request was refused: {}{reason}", if rule.is_empty() { String::new() } else { format!("{rule}: ") });
    // the seller's service is full: nothing was charged, and the page may try again
    if rule == "seller_busy" {
        let retry = v.pointer("/busy/retryAfter").and_then(Value::as_u64).unwrap_or(30).clamp(1, 3600);
        let mut r = json_response(503, &json!({"error": reason, "rule": rule}));
        r.headers.push(("Retry-After".into(), retry.to_string()));
        return r;
    }
    // the seller's page sees this answer: a refusal by the buyer's own spending rules names the rule, never the owner's
    // limit or the wallet's sums with this and other sellers (the wallet's pages read those from the visit's report)
    let reason = if owner_limit(v) { "Your spending rules refused this payment." } else { reason };
    json_response(if rule.is_empty() { 502 } else { 402 }, &json!({"error": reason, "rule": rule}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn visit(limit: i64) -> Arc<Visit> {
        Arc::new(Visit { id: String::new(), base: String::new(), limit: limit.into(), ceiling: None, state: Mutex::new(State::default()), turn: Condvar::new() })
    }

    /// The buyer's own spending rules refuse a payment of the visit (here the cap on a day's spend with one shop): the
    /// visit ends with that rule's words, its report says the rule and the limit, and each later request is refused
    /// with them at once, not asked of the seller. A top-up the rules refused, said in a call's answer that went on,
    /// ends it the same way. Any other refusal leaves the visit open.
    ///
    /// FAILS before: the refusal was passed on and the visit went on, each request asking again; a refused top-up
    /// was not read at all, and the page saw the seller's refusals that followed (`too_many_sessions`).
    #[test]
    fn a_payment_the_buyers_own_rules_refuse_ends_the_visit_with_the_rule() {
        let v = visit(1_000);
        let share = v.reserve_answer().unwrap();
        v.refused(share, Failed { v: json!({"rule": "ticket_seller", "reason": "the seller refused the lock: HTTP 402 too_many_tickets", "charged_sats": 0}),
                                  done: None, unknown: false });
        assert!(v.policy_refusal().is_none() && v.report()["ended"].is_null(), "a seller's refusal does not end the visit: {}", v.report());
        let share = v.reserve_answer().unwrap();
        v.refused(share, Failed { v: json!({"rule": "per_counterparty_daily", "reason": "today's spend with this seller 5203 exceeds its daily cap 5000",
                                            "limit_sats": 5000, "charged_sats": 0}), done: None, unknown: false });
        let r = v.report();
        assert_eq!((r["policy_refused"]["rule"].as_str(), r["policy_refused"]["limit_sats"].as_i64()), (Some("per_counterparty_daily"), Some(5000)), "{r}");
        let ended = r["ended"].as_str().unwrap_or("");
        assert!(ended.contains("today's spending limit for this shop") && ended.contains("Settings → Spending rules"), "{r}");
        assert!(!r.to_string().contains("too_many"), "{r}");
        let refused = v.policy_refusal().expect("later requests are refused with the rule");
        assert_eq!(refused.status, 402);
        let body: Value = serde_json::from_slice(&refused.body).unwrap();
        assert_eq!(body["rule"].as_str(), Some("per_counterparty_daily"), "{body}");
        // the seller's page is told the rule, never the owner's limit or the wallet's sums
        assert!(body.get("limit_sats").is_none() && !body.to_string().contains("5203") && !body.to_string().contains("5000"), "{body}");
        let page = refusal(&json!({"rule": "per_counterparty_daily", "reason": "today's spend with this seller 5203 exceeds its daily cap 5000", "limit_sats": 5000}));
        let body: Value = serde_json::from_slice(&page.body).unwrap();
        assert!(!body.to_string().contains("5203") && !body.to_string().contains("5000") && body.get("limit_sats").is_none(), "{body}");
        assert!(v.raise(2_000).is_err(), "a higher visit limit does not get past the owner's rules");
        // a top-up refused by the rules, in the answer of a call that went on
        let v = visit(1_000);
        v.account(&json!({"price_msat": "1000", "charged_sats": 0, "top_up_refused": {"rule": "daily_budget", "reason": "daily spend 25003 exceeds budget 25000",
                                                                                         "limit_sats": 25000}}), 125);
        let r = v.report();
        assert_eq!(r["policy_refused"]["rule"].as_str(), Some("daily_budget"), "{r}");
        assert!(r["ended"].as_str().unwrap_or("").contains("today's spending limit"), "{r}");
    }

    /// A film may run for hours: a request waiting to run alone does not wait for an answer that has
    /// been open a while, as it does not for a WebSocket.
    #[test]
    fn a_request_that_runs_alone_does_not_wait_for_a_long_open_answer() {
        let v = visit(100_000);
        let film = v.reserve(ANSWER_SHARE).unwrap();
        let (a, _b) = UnixStream::pair().unwrap();
        let _open = v.track(&a, film);
        v.lock().streams.values_mut().for_each(|o| o.opened = Instant::now() - LONG_OPEN);
        let t = Instant::now();
        assert_eq!(v.reserve_alone(i64::MAX).unwrap(), 100_000 - film);
        assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    }

    /// A visit with an answer still open stays, however long ago it was last asked for, so that a stop
    /// finds it; the stop shuts the answer's socket, which is what stops the signer paying. With nothing
    /// open, it goes as before.
    #[test]
    fn an_open_answer_keeps_its_visit_for_a_stop_to_find() {
        use std::io::Read as _;
        let long_ago = || Some(Instant::now() - 2 * IDLE);
        let visits = Visits::default();
        let id = visits.open("https://a.example/".into(), 1_000, None).unwrap();
        let v = visits.get(&id).unwrap();
        let (a, mut b) = UnixStream::pair().unwrap();
        let open = v.track(&a, 100);
        v.lock().last = long_ago();
        visits.open("https://b.example/".into(), 1_000, None).unwrap();
        assert!(visits.get(&id).is_some(), "the visit went with its answer still open");
        v.stop();
        b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(b.read(&mut [0u8; 8]).unwrap(), 0, "the stop did not shut the answer's socket");
        // an answer that arrives after the stop is shut at once
        let (c, mut d) = UnixStream::pair().unwrap();
        let late = v.track(&c, 100);
        d.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(d.read(&mut [0u8; 8]).unwrap(), 0);
        drop((open, late));
        visits.open("https://c.example/".into(), 1_000, None).unwrap();
        assert!(visits.get(&id).is_none(), "a stopped visit with nothing open stays");
    }

    /// A page's WebSocket holds its share as long as the page is open: a request waiting to run
    /// alone does not wait for it, and the requests behind it are not held up for it.
    #[test]
    fn a_request_that_runs_alone_does_not_wait_for_an_open_websocket() {
        let v = visit(100_000);
        let ws = v.reserve_socket().unwrap();
        let page = v.reserve(ANSWER_SHARE).unwrap();
        let t = Instant::now();
        std::thread::scope(|s| {
            let alone = s.spawn(|| v.reserve_alone(i64::MAX));
            std::thread::sleep(Duration::from_millis(200));
            // the page's request ends; the socket stays open
            v.release(page, 10);
            let got = alone.join().unwrap().unwrap();
            assert_eq!(got, 100_000 - ws - 10);
        });
        assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
        // and once it has its share, the next requests get theirs as before
        assert!(v.lock().alone == 0);
    }

    /// `f` on a thread of its own, or `None` where it took longer than `d`: a request that waits for a
    /// share waits up to [`TURN_WAIT`], which a test does not.
    fn within<T: Send + 'static>(d: Duration, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(d).ok()
    }

    /// The wallet's suggested 1,000 sat visit, with the seller's ticket (909 sat booked) known: a
    /// page's requests each hold a share of it at once, as a web app's first load asks for dozens.
    ///
    /// FAILS before: the first request's share had room for a ticket beside it, 1,000 + 909, which is
    /// all of the limit, and each other request waited for it to end: a page of a hundred requests
    /// over a slow link loaded one at a time.
    #[test]
    fn a_small_visits_requests_run_side_by_side_once_a_ticket_is_known() {
        let v = visit(1_000);
        v.lock().ticket = 909;
        let w = v.clone();
        let shares = within(Duration::from_secs(5), move || (0..8).map(|_| w.reserve_answer()).collect::<Vec<_>>())
            .expect("a request waited for another's share");
        assert!(shares.iter().all(|s| matches!(s, Ok(n) if *n >= MIN_SHARE)), "{shares:?}");
        let s = v.lock();
        assert!(s.spent <= 1_000 && s.held == s.spent, "{} {}", s.spent, s.held);
    }

    /// A WebSocket held open after sign-in does not hold up the page's other requests: it holds a
    /// small share, and the visit's sockets together at most half of the limit.
    ///
    /// FAILS before: the socket held 1,000 sat and room for a ticket, all of a 1,000 sat visit, for
    /// as long as it was open, and every request after it waited two minutes and was refused.
    #[test]
    fn an_open_websocket_does_not_hold_up_the_pages_requests() {
        let v = visit(1_000);
        v.lock().ticket = 909;
        let ws = v.reserve_socket().unwrap();
        assert!((1..=SOCKET_SHARE).contains(&ws), "{ws}");
        let w = v.clone();
        let got = within(Duration::from_secs(5), move || w.reserve_answer()).expect("the request waited behind the WebSocket").unwrap();
        assert!(got >= MIN_SHARE, "{got}");
        // more sockets: refused at once past half of the limit, and the page's requests still get theirs
        let w = v.clone();
        let opened = within(Duration::from_secs(5), move || (0..100).map_while(|_| w.reserve_socket().ok()).count()).expect("a socket waited");
        assert!(opened < 100, "{opened}");
        assert!(v.lock().sockets <= 500, "{}", v.lock().sockets);
        let w = v.clone();
        assert!(within(Duration::from_secs(5), move || w.reserve_answer()).expect("the request waited behind the WebSockets").is_ok());
    }

    /// However many requests and WebSockets run at once, the shares held never add up to more than
    /// the limit, and what stays spent is what they were charged, at most the limit.
    #[test]
    fn the_limit_holds_however_many_requests_and_sockets_run_at_once() {
        use std::sync::atomic::AtomicI64;
        let v = visit(1_000);
        v.lock().ticket = 909;
        let charged = AtomicI64::new(0);
        std::thread::scope(|sc| {
            for t in 0..16 {
                let (v, charged) = (&v, &charged);
                sc.spawn(move || {
                    for i in 0..300 {
                        let socket = (t + i) % 5 == 0;
                        let Ok(n) = (if socket { v.reserve_socket() } else { v.reserve_answer() }) else {
                            if v.lock().ended.is_some() {
                                break;
                            }
                            continue;
                        };
                        {
                            let s = v.lock();
                            assert!(s.spent <= 1_000 && s.held <= s.spent && s.sockets <= s.held, "{} {} {}", s.spent, s.held, s.sockets);
                        }
                        std::thread::sleep(Duration::from_micros(200));
                        let c = n.min(1 + (i as i64 % 3));
                        if socket {
                            v.socket_closed(n);
                        }
                        charged.fetch_add(c, Ordering::SeqCst);
                        v.release(n, c);
                    }
                });
            }
        });
        let s = v.lock();
        assert_eq!((s.spent, s.held, s.sockets), (charged.load(Ordering::SeqCst), 0, 0));
        assert!(s.spent <= 1_000, "{}", s.spent);
    }

    /// A path on a route the seller's `/services` names free is taken for free, as its gateway takes
    /// the path: the longest route that holds it, for the methods it names. Nothing read, or the
    /// routes forgotten: nothing is.
    ///
    /// FAILS before: a visit knew nothing of free routes, and sent a free path paid, on another
    /// route's terms.
    #[test]
    fn a_path_on_a_free_route_of_the_seller_is_taken_for_free() {
        let v = visit(1_000);
        let at = |p: &str| format!("https://s.example{p}");
        assert!(!v.is_free(&at("/web/main.js"), "GET"), "nothing read yet");
        assert!(v.learn_routes(&json!({"routes": [{"path": "/web/", "free": true, "methods": ["GET", "HEAD"]},
                                          {"path": "/web/paid/", "free": false, "methods": ["GET"]},
                                          {"path": "/", "free": false, "methods": ["GET", "POST"]},
                                          {"path": "/robots.txt", "free": true, "methods": ["GET"]}]}), 0));
        assert!(v.is_free(&at("/web/main.js?v=1"), "GET"));
        assert!(v.is_free(&at("/web/index.html"), "HEAD"));
        assert!(!v.is_free(&at("/web/main.js"), "POST"));
        assert!(!v.is_free(&at("/web/paid/a.js"), "GET"), "a longer paid route holds it");
        assert!(!v.is_free(&at("/Users/Me"), "GET"));
        assert!(v.is_free(&at("/robots.txt"), "GET"));
        assert!(!v.is_free(&at("/robots.txt/x"), "GET"));
        assert!(!v.is_free(&at("/web/../Users"), "GET"));
        assert!(!v.is_free(&at("/web/%2e%2e/Users"), "GET"));
        v.forget_routes();
        assert!(!v.is_free(&at("/web/main.js"), "GET"));
    }

    /// A WebSocket whose page side never opens (the 101 could not be written to it, so the server drops
    /// the upgrade's run uncalled) still has its share settled: what the signer says it cost stays
    /// spent, and the rest goes back.
    ///
    /// FAILS before: the share was settled only inside the run, and stayed held for good: the visit's
    /// "limit reached" never came, and its requests waited two minutes each.
    #[test]
    fn a_websockets_share_is_settled_when_its_page_side_never_opens() {
        use std::io::{BufRead as _, Read as _, Write as _};
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("signer.sock");
        let l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let streams = dir.path().to_path_buf();
        std::thread::spawn(move || {
            let (mut conn, _) = l.accept().unwrap();
            let mut line = String::new();
            BufReader::new(conn.try_clone().unwrap()).read_line(&mut line).unwrap();
            let p: Value = serde_json::from_str(&line).unwrap();
            let mut out = UnixStream::connect(streams.join(p["params"]["stream_to"].as_str().unwrap())).unwrap();
            writeln!(out, "{}", json!({"status": 101, "headers": [["Sec-WebSocket-Accept", "x"]]})).unwrap();
            // the socket's stream ends when the connector lets it go
            let _ = out.read(&mut [0u8; 1]);
            writeln!(conn, "{}", json!({"id": 1, "result": {"verdict": "allow", "status": 101, "charged_sats": 3}})).unwrap();
        });
        let c = Connector::new(crate::Config { signer: sock, stream_dir: dir.path().to_path_buf(), task: "t".into(), max_sats: 10 });
        let v = visit(1_000);
        let req = Request { method: "GET".into(), target: "/v/x/socket".into(), headers: vec![("Upgrade".into(), "websocket".into())], body: vec![], peer: None };
        let reply = c.visit_socket(v.clone(), "socket", &req);
        assert!(matches!(reply, Reply::Upgrade(_)));
        let held = v.lock().held;
        assert!(held >= 1, "{held}");
        // as the server does where the 101 cannot be written: the run is dropped, never called
        drop(reply);
        let t = Instant::now();
        loop {
            let s = v.lock();
            if s.held == 0 {
                assert_eq!((s.spent, s.sockets, s.settling), (3, 0, 0));
                break;
            }
            drop(s);
            assert!(t.elapsed() < Duration::from_secs(5), "the socket's share is still held");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Closed WebSockets whose cost the signer has yet to say still count within the sockets' half of
    /// the limit: a live connection that keeps reconnecting does not park share after share and
    /// starve the page's requests.
    ///
    /// FAILS before: a closed socket's share left the sockets' count as it began settling, so new
    /// sockets took the whole limit and the page's next request waited.
    #[test]
    fn closed_websockets_waiting_for_their_cost_count_within_the_sockets_half() {
        let v = visit(1_000);
        let w = v.clone();
        let (opened, keep) = within(Duration::from_secs(10), move || {
            let mut keep = vec![];
            while let Ok(share) = w.reserve_socket() {
                // closed at once, the signer's word on its cost still to come
                let (tx, rx) = mpsc::channel::<Result<Value, String>>();
                let w2 = w.clone();
                std::thread::spawn(move || w2.settle(share, Some(rx), true));
                keep.push(tx);
                std::thread::sleep(Duration::from_millis(20));
                if keep.len() > 40 {
                    break;
                }
            }
            (keep.len(), keep)
        }).expect("a socket waited for a share");
        assert!(opened <= 10, "{opened}");
        let w = v.clone();
        assert!(within(Duration::from_secs(5), move || w.reserve_answer()).expect("the request waited behind the sockets").is_ok());
        drop(keep);
    }

    /// A signer that says a request cost more than the share it was allowed is not hidden: all of it
    /// stays spent and the visit ends.
    ///
    /// FAILS before: what it said was cut to the share.
    #[test]
    fn a_charge_past_its_share_is_counted_and_ends_the_visit() {
        let v = visit(1_000);
        let share = v.reserve_answer().unwrap();
        v.release(share, share + 7);
        let s = v.lock();
        assert_eq!((s.spent, s.held), (share + 7, 0));
        assert!(s.ended.is_some());
    }

    /// A visit of 1 sat has no half of its limit for a WebSocket: it is refused, and the page's
    /// requests have the sat.
    ///
    /// FAILS before: the socket took the visit's one sat.
    #[test]
    fn a_one_sat_visit_opens_no_websocket() {
        assert!(visit(1).reserve_socket().is_err());
        assert_eq!(visit(1).reserve_answer(), Ok(1));
    }

    /// A read of the seller's routes begun before they were forgotten (a path taken for free was
    /// not) is not kept: the routes it read may be those the seller has just changed.
    #[test]
    fn a_read_of_the_routes_begun_before_they_were_forgotten_is_not_kept() {
        let v = visit(1_000);
        let doc = json!({"routes": [{"path": "/web/", "free": true, "methods": ["GET"]}]});
        let before = v.lock().routes_gen;
        v.forget_routes();
        assert!(!v.learn_routes(&doc, before));
        assert!(!v.is_free("https://s.example/web/a.js", "GET"));
        let now = v.lock().routes_gen;
        assert!(v.learn_routes(&doc, now));
        assert!(v.is_free("https://s.example/web/a.js", "GET"));
    }

    /// An answer that has stopped and waits for the signer to say what it cost holds no answer open:
    /// a request waiting to run alone goes on beside it, with what is left of the limit past its
    /// share, and the share is settled when the signer says (all of it, where it says nothing).
    ///
    /// FAILS before: the request waiting to run alone waited for the signer's word, up to its
    /// [`TURN_WAIT`], and the page froze.
    #[test]
    fn a_request_that_runs_alone_does_not_wait_for_an_answer_being_settled() {
        let v = visit(100_000);
        let page = v.reserve(ANSWER_SHARE).unwrap();
        let (tx, done) = mpsc::channel::<Result<Value, String>>();
        std::thread::scope(|s| {
            let settling = s.spawn(|| v.settle(page, Some(done), false));
            std::thread::sleep(Duration::from_millis(100));
            let t = Instant::now();
            let got = v.reserve_alone(i64::MAX).unwrap();
            assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
            assert_eq!(got, 100_000 - page);
            v.release(got, 0);
            tx.send(Ok(json!({"charged_sats": 12}))).unwrap();
            settling.join().unwrap();
        });
        let s = v.lock();
        assert_eq!((s.spent, s.held, s.settling), (12, 0, 0));
    }

    /// The visit's report says what its answers used and what was paid for tickets, apart from the
    /// shares held while requests run: during an answer the limit is all held, and after it only
    /// what it charged stays, though what it used came from credit bought earlier.
    ///
    /// FAILS before: the report had only `spent_sats`, the whole limit while an answer ran and 0
    /// once it ended on credit, with nothing of the 65 sat it used.
    #[test]
    fn the_report_says_what_was_used_and_what_was_paid() {
        let v = visit(559);
        let share = v.reserve(ANSWER_SHARE).unwrap();
        let r = v.report();
        assert_eq!((r["spent_sats"].as_i64(), r["held_sats"].as_i64(), r["used_msat"].as_u64(), r["paid_sats"].as_i64()), (Some(559), Some(559), Some(0), Some(0)));
        let (tx, done) = mpsc::channel::<Result<Value, String>>();
        tx.send(Ok(json!({"charged_sats": 0, "price_msat": "64870"}))).unwrap();
        v.settle(share, Some(done), false);
        let r = v.report();
        assert_eq!((r["spent_sats"].as_i64(), r["held_sats"].as_i64(), r["used_msat"].as_u64(), r["paid_sats"].as_i64()), (Some(0), Some(0), Some(64_870), Some(0)));
        // a ticket bought for the next answer: paid, and what it used
        let share = v.reserve(ANSWER_SHARE).unwrap();
        let (tx, done) = mpsc::channel::<Result<Value, String>>();
        tx.send(Ok(json!({"charged_sats": 559, "price_msat": 1_000}))).unwrap();
        v.settle(share, Some(done), false);
        let r = v.report();
        assert_eq!((r["used_msat"].as_u64(), r["paid_sats"].as_i64()), (Some(65_870), Some(559)));
    }

    /// A film outruns a small limit: the buyer raises it, and the visit that ended at its limit goes on,
    /// with the new limit for its requests. A limit is never lowered, and a stopped visit stays stopped.
    ///
    /// FAILS before: a visit's limit was fixed; at its end the frame closed and the film stopped.
    #[test]
    fn a_visit_that_reached_its_limit_goes_on_once_the_buyer_raises_it() {
        let v = visit(100);
        let a = v.reserve(100).unwrap();
        v.release(a, 100);
        assert_eq!(v.reserve(10).unwrap_err(), LIMIT_REACHED);
        assert_eq!(v.report()["limit_reached"], true);
        assert!(v.raise(100).is_err() && v.raise(50).is_err() && v.raise(MAX_LIMIT + 1).is_err());
        v.raise(1_000).unwrap();
        assert_eq!((v.report()["limit_reached"].as_bool(), v.report()["limit_sats"].as_i64()), (Some(false), Some(1_000)));
        assert_eq!(v.reserve(10_000), Ok(900));
        v.stop();
        assert!(v.raise(2_000).is_err(), "a stopped visit stays stopped");
        assert_eq!(v.report()["limit_reached"], false);
    }

    /// What a visit used is what the seller's signed receipt charged where that is more than the
    /// wallet's own count: an answer cut short, or left by the page, was charged for the bytes on
    /// their way, and that is what the connection's credit fell by.
    ///
    /// FAILS before: the visit counted only the wallet's count (`price_msat`), and its bar said 85 sat
    /// used where the connection's credit had fallen by about 164.
    #[test]
    fn what_a_visit_used_is_what_the_seller_charged_where_that_is_more() {
        let v = visit(1_000);
        v.account(&json!({"price_msat": "40000", "charged_sats": 0, "receipt": {"signed": true, "last": {"charged": "79000"}}}), 125);
        v.account(&json!({"price_msat": "5000", "charged_sats": 0, "receipt": {"signed": true, "last": {"charged": "5000"}}}), 125);
        v.account(&json!({"price_msat": "1000", "charged_sats": 0}), 125);
        assert_eq!(v.lock().used_msat, 85_000);
        // a charge the signer found at fault (past the call's cap, say) is not taken: the wallet's own count is
        v.account(&json!({"price_msat": "2000", "charged_sats": 0, "seller_fault": "charged past the cap",
                          "receipt": {"signed": true, "last": {"charged": "900000"}}}), 125);
        assert_eq!(v.lock().used_msat, 87_000);
        // and one past the call's own cap is taken only as far as that cap past the wallet's count
        // (FAILS before: the seller's word was taken whole, fault or not)
        v.account(&json!({"price_msat": "1000", "charged_sats": 0, "receipt": {"signed": true, "last": {"charged": "900000"}}}), 10);
        assert_eq!(v.lock().used_msat, 87_000 + 1_000 + 10_000);
    }

    /// Where a call says the session's credit is low, the next request takes the lane: room for a
    /// ticket and a top-up, one request at a time, within the limit. With credit enough, or nothing
    /// said of it, or no room in the limit, it does not.
    ///
    /// FAILS before: there was no lane, and a request whose answer outran the credit was cut.
    #[test]
    fn one_request_at_a_time_tops_the_credit_up_where_it_is_low() {
        let v = visit(1_000);
        assert!(v.take_lane().is_none(), "nothing is known of the credit yet");
        v.account(&json!({"price_msat": "100000", "charged_sats": 600, "tickets_released": 1, "balance_msat": "900000"}), 725);
        assert_eq!(v.lock().ticket, 600);
        assert!(v.take_lane().is_none(), "the credit is ample");
        // spent 600 of 1,000: room for a share and a ticket (725) is not there
        v.lock().spent = 600;
        v.account(&json!({"price_msat": "100000", "charged_sats": 0, "balance_msat": "50000"}), 125);
        assert!(v.take_lane().is_none(), "no room in the limit for a ticket");
        v.lock().spent = 0;
        let (most, top) = v.take_lane().expect("the credit is low: the lane");
        // the credit kept ahead is what could be drawn now (nothing runs: one request's share), not four shares
        assert_eq!((most, top), (125 + 600, 125));
        assert!(v.take_lane().is_none(), "one request holds the lane");
        assert_eq!(v.lock().spent, most);
        v.lane_done();
        // the lane is free again, but the low credit it was taken on is old news: no request takes it again until a call
        // says what the credit is now (FAILS before: the next request took the lane on the same figure, and the one after)
        assert!(v.take_lane().is_none(), "the lane was taken again on the credit it was taken on");
        v.release(most, 600);
        let st = v.lock();
        assert_eq!((st.spent, st.held, st.lane), (600, 0, false));
    }

    /// A call whose signer answer never came (the call to the signer failed or timed out) may have
    /// been charged: all of its share stays spent.
    ///
    /// FAILS before: it was taken for a refusal that charged nothing, and the share went back.
    #[test]
    fn a_call_the_signer_never_answered_keeps_its_share_spent() {
        let v = visit(10_000);
        let share = v.reserve(ANSWER_SHARE).unwrap();
        v.refused(share, Failed { v: json!({"error": "the signer did not answer"}), done: None, unknown: true });
        let s = v.lock();
        assert_eq!((s.spent, s.held), (share, 0));
        drop(s);
        // and one the signer refused before anything was sent gives it back
        let other = v.reserve(ANSWER_SHARE).unwrap();
        v.refused(other, Failed { v: json!({"rule": "max_sats"}), done: None, unknown: false });
        assert_eq!(v.lock().spent, share);
    }

    /// A call that never reached the signer (its socket could not be reached) sent nothing and was
    /// charged nothing: its share goes back.
    ///
    /// FAILS before: any failed call to the signer kept all of its share spent.
    #[test]
    fn a_call_that_never_reached_the_signer_gives_its_share_back() {
        let dir = tempfile::tempdir().unwrap();
        let c = Connector::new(crate::Config { signer: dir.path().join("no-signer.sock"), stream_dir: dir.path().to_path_buf(), task: "t".into(), max_sats: 10 });
        let Err(f) = c.start(json!({"url": "https://example.invalid/"})) else { panic!("the call went") };
        assert!(!f.unknown, "{}", f.v);
        let v = visit(10_000);
        let share = v.reserve(ANSWER_SHARE).unwrap();
        v.refused(share, f);
        assert_eq!(v.lock().spent, 0);
    }
}
