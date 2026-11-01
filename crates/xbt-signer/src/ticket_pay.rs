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
//! | A call is charged at most its charge cap (`max_charge_sats`, else `max_sats`), by the wallet's own count, moves at most `max_sats` (whole tickets with their fees), and ends within the owner's limit for an answer read that way ([`open_limit`]: `max_answer_s`, `max_stream_s` or `max_socket_s`). | [`Signer::ticket_request`] refuses a head price above the charge cap, and [`Spent::room`] any ticket past `max_sats`; [`Stream::over`] cuts the body where its price reaches the charge cap or its time is up. |
//! | Held tickets first; a prepaid one only where none can be held, or before any is. | [`Signer::ticket_release_one`] buys a prepaid ticket only when the session has no held ticket to release and the book says it pays that way now ([`crate::ticket::Session::prepaid_now`]: a pool of none, a wait after a lock that found no slot, or a session whose first ticket is a prepaid one: a seller the owner has not named, or one that answered `prepaid_first`). The purchase itself is the book's ([`Signer::ticket_prepay`]), one at a time. |
//! | A seller that says `slots_short` is waited for. | [`Signer::ticket_lock_call`] sets the session's wait from the seller's `retryAfter` and offers it no hash until then. |
//! | A session that can release nothing more is ended, and said so. | [`Signer::ticket_forgotten`]: the seller's unsigned `session_unknown` to a lock or a `status` stops the session, as an unsigned answer to a paid request does. [`Signer::ticket_release_one`]: a ticket the seller has not shown after `ready_wait_ms` that the wallet's own node carries on no channel ([`Signer::ticket_stranded`]) stops it too. Neither releases or books anything. |
//! | An invoice that will not be paid gives its place with the seller back. | [`Signer::ticket_fill_once`] asks the seller to cancel the invoices a lock round refused or failed, and [`Signer::ticket_cancel_dead`] those of tickets that failed after their round, each once. The answer is not read. |
//!
//! **Requests side by side.** A web app asks a seller for many things at once, and keeps some open
//! (a film, a WebSocket). They go side by side in one session and draw on one balance:
//!
//! * **Seqs.** A request holds `link` only to take its `seq` ([`Signer::seq_take`]); it is sent,
//!   and its head read, with no lock held, so a request slow to be answered holds up nothing. The
//!   seller takes seqs only in order, and requests go out on their own connections: one that
//!   arrives before a seq it follows is answered `bad_seq` and sent again once that one is on its
//!   way, or takes over a seq no request holds ([`Signer::seq_bad`]).
//! * **Receipts out of order.** Receipts are read in another order than the seller signed them, and
//!   the seller's spend can fall (it gives back a charge that bought nothing), so figures do not
//!   order them. The wallet's own steps do: a receipt for a request sent after the wallet last took
//!   the seller's totals is newer, and its spend is taken even where it is lower ([`Money::epoch`]).
//!   One for a request sent before may be older: with less than the wallet holds, its own figures
//!   are checked (its charge against its price) and its totals passed over ([`Money::take`]).
//! * **What the seller may have spent.** Every request may be charged from the moment it is sent
//!   until its answer's last receipt is read, at most its call's limit ([`Money::open`], by the
//!   request's own id); one whose answer was lost, for a while after ([`Money::lost`]). Each
//!   answer's charge is believed by one rule however its last receipt comes, as it ends, late or
//!   never ([`Bound`]): one that arrived whole, up to what it cost; one cut short, up to what was
//!   read and what could have been on its way, or the credit it could have drawn
//!   ([`Stream::cut_bound`]). A
//!   receipt's spend is taken only inside the spend at the last quiet point, plus what the wallet
//!   counted since, plus what the open requests may still add; and where nothing is open, only
//!   inside what the seller's own receipts charged the answers closed since. A seller cannot drain
//!   the balance behind a WebSocket kept open: it may add at most that call's limit.
//! * **Credit.** Each answer counts what it draws into [`Money::consumed`] (its bytes, its seconds
//!   as they start; an answer by the token holds back the most it may cost in [`Money::reserved`]
//!   until its end, then draws what it cost), and finds a ticket
//!   due on what is left after what the others drew since it started. An answer that closes with a
//!   charge above the wallet's count (bytes the seller sent that nobody read) adds the difference.
//! * **Releases.** A release re-asks whether it is still due once it holds `paying`: two answers
//!   that find one due at once release one. It waits for an answer the seller has not closed
//!   without holding `paying`, and only if that answer was left before the release's own answer
//!   opened ([`Signer::ticket_release_one`]); one never found closed is closed by the wallet, as
//!   charged the most it may, after [`TAIL_GIVE_UP`].
//!
//! One session rather than one per request: one ticket's credit serves the whole page, where a
//! session per request would lock a ticket for each request in flight and spread the credit thin.
//!
//! Locks, in this order and never the other way: a session's `calls` (held shared by each request
//! in progress; taken alone, without waiting, by a move or an idle stop), then `paying` (one secret
//! at a time), then `link` (the seqs: never held across a send), then `money`. Debug builds check
//! the order ([`lock_paying`], [`lock_link`]). The wallet's spend lock is taken with none of `link`
//! and `money` held, and never while a seller is being waited for.
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use xbt402::ticket::protocol_code;
use xbt402::wire::{b64json, payment_payload, request_digest_v2, seller_url, sendable_url, unb64json};
use zeroize::Zeroizing;

use crate::ln::LnPolicy;
use crate::policy::normalize_dest;
use crate::keystore::write_private;
use crate::pyjson::{py_int, str_or_empty};
use crate::sanitize::{untrusted, UNTRUSTED_KEY};
use crate::signer::{deny, with, Signer};
use crate::ticket::{sats_ceil, Admit, SState, SellerSession, SellerTls, TState, Terms, TicketPolicy, HOLD_SHORT, PROGRESS_FLOOR_BYTES, ROUTE_FULL, TIP_UNKNOWN};
use crate::ticket_http::{offers, Account, Offer, PayTerms, Price, PriceCeiling, Receipt};
use crate::{err, Result};

mod draws;
pub(crate) use draws::DrawSession;

/// The most of a session endpoint's answer that is read.
const SMALL_BODY: u64 = 1 << 20;
/// Hashes for one request each, as many as a seller's cap on tickets lets one name: a longer list is
/// refused whole.
fn in_parts<T>(list: &[T], cap: u32) -> std::slice::Chunks<'_, T> {
    list.chunks((cap as usize).max(1))
}

/// How long a call waits for a seller's signed `status` at a takeover: each try, and how many.
const RESUME_STATUS_WAIT: Duration = Duration::from_secs(5);
const RESUME_STATUS_TRIES: usize = 3;
/// How many stopped seller sessions of one seller a new session asks about its credit.
const RESUME_MOST_ASKED: usize = 4;
/// How long calls to a seller that will not say what an earlier session left with it are refused, so
/// that nothing is bought beside that credit, before one starts fresh and names what is left behind.
const RESUME_UNANSWERED_S: f64 = 120.0;
const RESUME_RETRY_AFTER_S: u64 = 5;

/// What a takeover came to ([`Signer::ticket_resume`]).
enum Resumed {
    Taken,
    Fresh,
    /// The seller would not say: the call is refused with this, and nothing is bought.
    Wait(Value),
}

/// What one seller session came to at a takeover.
enum Asked {
    Taken,
    No,
    Unanswered,
}

/// How long the watcher waits to present a late prepaid ticket again after a seller gave no answer
/// that settles it: the first time, doubling up to the most.
const LATE_SHOW_FIRST_WAIT_S: f64 = 60.0;
const LATE_SHOW_MOST_WAIT_S: f64 = 3600.0;
/// How long the wallet looks for the last receipt of an answer that was sent as it arrived.
const FINAL_WAIT: Duration = Duration::from_secs(2);
/// [`FINAL_WAIT`] for an answer that arrived whole: the seller has sent all of it, and its last
/// receipt is only slow to show (a status beside many other requests).
const FINAL_WAIT_WHOLE: Duration = Duration::from_secs(10);
/// How long a release waits for the seller to close an answer the wallet stopped reading, and how
/// long after that stop the wallet closes it itself, as charged the most its call allowed, if the
/// seller never lists it closed.
const TAIL_WAIT: Duration = Duration::from_secs(5);
const TAIL_GIVE_UP: Duration = Duration::from_secs(30);
/// How long a stop waits for the wallet's own node to show the cancelled tickets failed.
pub const CANCEL_WAIT: Duration = Duration::from_secs(5);
/// How long a stop waits for the session's open streams to end and take their last receipts: past
/// a closed answer's wait for its last receipt (FINAL_WAIT for one cut short), with room to spare.
pub const STOP_STREAMS_WAIT: Duration = Duration::from_secs(15);
/// Refusals of `ticket_open` that mean "not this rail": the next entry of the 402 is tried.
const NEXT_RAIL: [&str; 14] = ["ticket_disabled", "ticket_mainnet", "ln_disabled", "ticket_task", "ticket_admission", "ticket_terms", "ticket_feature_512", "ticket_network",
                               "ticket_size", "ticket_blocks", "ticket_dust", "ticket_slots", ROUTE_FULL, "ticket_prepaid_first"];

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

thread_local! {
    /// `order` locks of sessions this thread holds ([`lock_order`]).
    static ORDER_HELD: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    /// How many session `money` locks this thread holds (debug builds): [`lock_link`] checks it.
    static MONEY_HELD: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    /// How many session `link` locks this thread holds (debug builds): [`lock_paying`] checks it.
    static LINK_HELD: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// A held `money` lock of a session, counted for the lock-order check.
struct MoneyGuard<'a>(MutexGuard<'a, Money>);

impl std::ops::Deref for MoneyGuard<'_> {
    type Target = Money;
    fn deref(&self) -> &Money {
        &self.0
    }
}

impl std::ops::DerefMut for MoneyGuard<'_> {
    fn deref_mut(&mut self) -> &mut Money {
        &mut self.0
    }
}

impl Drop for MoneyGuard<'_> {
    fn drop(&mut self) {
        MONEY_HELD.with(|n| n.set(n.get().saturating_sub(1)));
    }
}

/// How often a release that waits asks again, at first and at most: a slow node is not asked harder for being slow.
const PAUSE_POLL_FIRST: Duration = Duration::from_millis(50);
const PAUSE_POLL_MOST: Duration = Duration::from_millis(500);
/// How long the seller may have been quiet before a ticket due for its answer is asked after that answer: until then
/// the seller has just sent a byte of it, and a `status` for each ticket would be a round trip for nothing.
const QUIET_BEFORE_ASKING: Duration = Duration::from_secs(1);
/// How many releases running may find the seller has not shown a ticket, with no byte delivered between them, before
/// the session ends: asking costs a seller that never shows one nothing, and costs the buyer a pause each time.
const STALLS_MOST: usize = 3;
/// How far past the call's deadline the last receipt of its answer is waited for. The call's deadline is the owner's
/// `tickets.max_answer_s`, 50 s as shipped, so that the caller's 60 s are not spent.
const FINAL_PAST_CALL: Duration = Duration::from_secs(5);
/// How long past the call's deadline a secret that has left is asked after: it has left, and is delivered again by the
/// next release if this is not the end of it, so the caller is not kept for it.
const DELIVER_PAST_CALL: Duration = Duration::from_secs(2);
/// The least a fill is waited for, however little of the pause is left.
const FILL_MOMENT: Duration = Duration::from_secs(1);
/// How long a stop made inside a release is waited for: it goes on behind, and the answer ends here.
const STOP_INSIDE_WAIT: Duration = Duration::from_secs(2);

/// A session's `refilling` flag, taken: one refill at a time. Cleared when dropped, however the
/// refill ended.
struct Refilling<H: std::ops::Deref<Target = T>, T: RefillFlag + ?Sized>(H);

/// What holds a refill flag: a session.
trait RefillFlag {
    fn refill_flag(&self) -> &AtomicBool;
}

impl RefillFlag for HttpSession {
    fn refill_flag(&self) -> &AtomicBool {
        &self.refilling
    }
}

impl<H: std::ops::Deref<Target = T>, T: RefillFlag + ?Sized> Refilling<H, T> {
    fn take(hs: H) -> Option<Self> {
        (!hs.refill_flag().swap(true, Ordering::SeqCst)).then(|| Self(hs))
    }
}

impl<H: std::ops::Deref<Target = T>, T: RefillFlag + ?Sized> Drop for Refilling<H, T> {
    fn drop(&mut self) {
        self.0.refill_flag().store(false, Ordering::SeqCst);
    }
}

/// What a release is for, and how long it may take.
struct Due<'a> {
    /// When the answer or the request it is for began: an answer the wallet stopped reading before that holds it back.
    opened: Instant,
    /// Since when whatever is waiting for this ticket has been waiting: for an answer by the byte, the last byte of it,
    /// since the seller's own wait began about then; `None`, nothing is waiting but the call, and its pause begins when
    /// its turn comes under `paying`. Every wait of the release ends within `tickets.ready_wait_ms` of this, all together.
    waiting_since: Option<Instant>,
    /// When the call must have its answer.
    call_by: Instant,
    /// Whether the ticket is still due, asked again under `paying` and just before the book.
    still_due: &'a dyn Fn() -> bool,
    /// The open answer it pays for, as the seller's signed `status` would list it once it has ended: seq, digest, status.
    answer: Option<(u64, &'a str, u16)>,
}

impl Due<'_> {
    /// When every wait of this release ends, its turn having come at `turn`.
    fn pause_by(&self, tp: &TicketPolicy, turn: Instant) -> Instant {
        (self.waiting_since.unwrap_or(turn) + Duration::from_millis(tp.ready_wait_ms.clamp(0, 600_000) as u64)).min(self.call_by)
    }
}

/// A session's `money`.
fn lock_money(hs: &HttpSession) -> MoneyGuard<'_> {
    let g = lock(&hs.money);
    MONEY_HELD.with(|n| n.set(n.get() + 1));
    MoneyGuard(g)
}

/// A held `link` lock of a session, counted for the lock-order check.
struct LinkGuard<'a>(MutexGuard<'a, Link>);

impl std::ops::Deref for LinkGuard<'_> {
    type Target = Link;
    fn deref(&self) -> &Link {
        &self.0
    }
}

impl std::ops::DerefMut for LinkGuard<'_> {
    fn deref_mut(&mut self) -> &mut Link {
        &mut self.0
    }
}

impl Drop for LinkGuard<'_> {
    fn drop(&mut self) {
        LINK_HELD.with(|n| n.set(n.get().saturating_sub(1)));
    }
}

/// A session's `link`. Taken with `money` held, the two could deadlock against a request (which
/// holds `link` and then takes `money`): debug builds refuse it.
fn lock_link(hs: &HttpSession) -> LinkGuard<'_> {
    debug_assert_eq!(MONEY_HELD.with(std::cell::Cell::get), 0, "lock order: a session's link is taken before its money, never with it held");
    let g = lock(&hs.link);
    LINK_HELD.with(|n| n.set(n.get() + 1));
    LinkGuard(g)
}

/// A session's `paying`, given up at `by`: the releases ahead each pause for themselves, and a call behind enough of them
/// has its caller to answer. Taken before `order`, `link` and `money`, never with any of them held. Debug builds refuse it otherwise.
fn lock_paying_by(hs: &HttpSession, by: Instant) -> Option<MutexGuard<'_, ()>> {
    debug_assert_eq!(ORDER_HELD.with(std::cell::Cell::get), 0, "lock order: a session's paying is taken before its order, never with it held");
    debug_assert_eq!(LINK_HELD.with(std::cell::Cell::get), 0, "lock order: a session's paying is taken before its link, never with it held");
    debug_assert_eq!(MONEY_HELD.with(std::cell::Cell::get), 0, "lock order: a session's paying is taken before its money, never with it held");
    loop {
        match hs.paying.try_lock() {
            Ok(g) => return Some(g),
            Err(std::sync::TryLockError::Poisoned(p)) => return Some(p.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) if Instant::now() >= by => return None,
            Err(std::sync::TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

/// A held `order` lock of a session, counted for the lock-order check.
struct OrderGuard<'a>(#[allow(dead_code)] MutexGuard<'a, ()>);

impl Drop for OrderGuard<'_> {
    fn drop(&mut self) {
        ORDER_HELD.with(|n| n.set(n.get().saturating_sub(1)));
    }
}

/// A session's `order`, where its seller takes only the next seq (no `seqWindow` in its terms):
/// held by a request from its seq to its answer's head, so that its requests reach the seller one
/// at a time, in order. `None` where the seller takes requests side by side. Taken after `paying`
/// and before `link` and `money`; debug builds refuse it otherwise.
fn lock_order(hs: &HttpSession) -> Option<OrderGuard<'_>> {
    if hs.terms.seq_window > 1 {
        return None;
    }
    debug_assert_eq!(LINK_HELD.with(std::cell::Cell::get), 0, "lock order: a session's order is taken before its link, never with it held");
    debug_assert_eq!(MONEY_HELD.with(std::cell::Cell::get), 0, "lock order: a session's order is taken before its money, never with it held");
    let g = lock(&hs.order);
    ORDER_HELD.with(|n| n.set(n.get() + 1));
    Some(OrderGuard(g))
}

/// How long a seq is taken to be on its way to the seller. One sent longer ago that has no answer
/// yet has arrived, its answer slow to come (a long poll, a model slow to its first word), or was
/// lost: it no longer holds the window of the seqs sent after it ([`Signer::seq_take`]).
const SEQ_ARRIVED: Duration = Duration::from_secs(1);

/// How long a request waits for the seller to take the requests sent before it, whose seqs come
/// first: they went out on other connections, and the seller takes seqs only in order.
const SEQ_WAIT: Duration = Duration::from_secs(10);

fn refusal(rule: &str, reason: impl Into<String>) -> Value {
    with(deny(rule, reason), json!({"rail": "ticket", "charged_sats": 0}))
}

/// Why nothing more is released into a session being stopped ([`HttpSession::ending`]).
fn answer_closed_refusal(hs: &HttpSession) -> Value {
    with(refusal("ticket_answer_closed", "the seller has ended the answer this ticket was for: no secret was released"),
         json!({"session": hs.sid}))
}

/// Why a session the seller has forgotten was stopped ([`Signer::ticket_forgotten`]).
const FORGOTTEN_WHY: &str = "the seller has forgotten the session";

fn stopping_refusal() -> Value {
    refusal("ticket_session", "the session is being stopped: no ticket is released")
}

/// Whether a route's terms ask to know who the buyer is: the route gives each buyer an account
/// (docs/BUYER-ACCOUNTS.md).
fn identify_asked(accepted: &Value) -> bool {
    accepted["extra"]["identify"] == true
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
    /// Ends the connection the body arrives on, from any thread: a read waiting on a quiet seller
    /// returns at once. `None`: a wire with no such handle, whose body ends only as its seller ends it.
    pub closer: Option<Closer>,
}

/// [`WireAnswer::closer`].
pub type Closer = Arc<dyn Fn() + Send + Sync>;

/// Shut this process's TCP connection from `local` to `peer`, wherever its socket is held (ureq
/// keeps an answer's to itself): found among the open files by its two addresses, which no other
/// connection shares while it is open.
fn shut_connection(local: std::net::SocketAddr, peer: std::net::SocketAddr) {
    use std::os::fd::{BorrowedFd, RawFd};
    let Ok(dir) = std::fs::read_dir("/proc/self/fd").or_else(|_| std::fs::read_dir("/dev/fd")) else { return };
    for fd in dir.flatten().filter_map(|e| e.file_name().to_str()?.parse::<RawFd>().ok()) {
        // SAFETY: borrowed for these calls only. A descriptor closed meanwhile fails them; one reused
        // meanwhile by another file is not a socket between these two addresses, and is left alone
        let fd = unsafe { BorrowedFd::borrow_raw(fd) };
        let s = socket2::SockRef::from(&fd);
        if s.local_addr().ok().and_then(|a| a.as_socket()) == Some(local) && s.peer_addr().ok().and_then(|a| a.as_socket()) == Some(peer) {
            let _ = s.shutdown(std::net::Shutdown::Both);
            return;
        }
    }
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

    /// [`WireAnswer::read_small`], the whole of it read by `deadline`: past it, the answer is cut
    /// off however slowly its bytes still come.
    fn read_small_by(self, cap: u64, deadline: Instant) -> Result<Vec<u8>> {
        let WireAnswer { status, headers, length, body, closer } = self;
        WireAnswer { status, headers, length, body: Box::new(ByDeadline { inner: body, deadline }), closer }.read_small(cap)
    }
}

/// A body read no later than its deadline: a read that would start past it fails as a timeout.
struct ByDeadline {
    inner: Box<dyn Read + Send>,
    deadline: Instant,
}

impl Read for ByDeadline {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "the answer took longer than its deadline"));
        }
        self.inner.read(buf)
    }
}

/// How the ticket payer talks HTTP: one request, answered as soon as its head has arrived, the
/// body left to be read. No redirect is followed.
/// A seller's answer to a request to upgrade (a WebSocket): the answer, whose body is what the
/// seller sends after the head, and when it said `101`, the half of the connection that writes to
/// it. Dropping the writer ends the stream toward the seller.
pub struct WireUpgrade {
    pub answer: WireAnswer,
    pub writer: Option<Box<dyn Write + Send>>,
}

pub trait TicketWire: Send + Sync {
    /// The request asking `url` to become a WebSocket (`GET`, with `Connection: Upgrade` and
    /// `Upgrade: websocket` added to `headers`), its certificate checked as [`TicketWire::send_with`]
    /// checks one. Whatever carries a seller's connection (TCP and TLS, a QUIC stream) implements
    /// this to carry its WebSockets; one that does not refuses, and the call is refused.
    fn upgrade(&self, url: &str, headers: &[(String, String)], read_timeout: Duration, tls: Option<&SellerTls>) -> Result<WireUpgrade> {
        let _ = (url, headers, read_timeout, tls);
        Err(err("transport_error", "this connection to the seller cannot carry a WebSocket"))
    }

    fn send(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)], read_timeout: Duration) -> Result<WireAnswer>;

    /// [`TicketWire::send`], with an https seller's certificate checked against `tls` in place of
    /// the public certificate authorities (`None`: the public ones). The signer passes `Some` only
    /// for a seller the owner names, with an entry in `tickets.seller_tls` ([`Signer`]'s
    /// `seller_tls_for`). A wire that cannot do this keeps the public ones: stricter, never wider.
    fn send_with(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)], read_timeout: Duration, tls: Option<&SellerTls>)
                 -> Result<WireAnswer> {
        let _ = tls;
        self.send(method, url, body, headers, read_timeout)
    }

    /// [`TicketWire::send_with`], the whole request (its head included) held to `overall`, where
    /// each read alone is held only to `read_timeout`: a seller that sends a byte at a time does not
    /// hold the call past it. A wire that cannot do this sends as [`TicketWire::send_with`] does;
    /// the body is held to the same deadline as it is read ([`WireAnswer::read_small_by`]).
    #[allow(clippy::too_many_arguments)]
    fn send_by(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)], read_timeout: Duration, tls: Option<&SellerTls>,
               overall: Duration) -> Result<WireAnswer> {
        let _ = overall;
        self.send_with(method, url, body, headers, read_timeout, tls)
    }

    /// Learns that `origin` is reached over an iroh link (`link`, from the seller's checked
    /// transport document), believing where the link is from Nostr only from `nostr_author`. A
    /// wire that has no links refuses: the seller is then not reached at all.
    fn learn_link(&self, origin: &str, link: &xbt402::transport::Link, nostr_author: Option<&str>) -> Result<()> {
        let _ = (origin, link, nostr_author);
        Err(err("transport_error", "this wallet reaches sellers by web address only"))
    }

    /// [`TicketWire::learn_link`] for a seller on several link keys (all from its checked document):
    /// a wire that can spreads its buyers over them, with the others as fallbacks; one that cannot
    /// uses the first.
    fn learn_links(&self, origin: &str, links: &[xbt402::transport::Link], nostr_author: Option<&str>) -> Result<()> {
        let first = links.first().ok_or_else(|| err("transport_error", "the seller's transport document names no link"))?;
        self.learn_link(origin, first, nostr_author)
    }
}

/// With `XBT_TRACE_WIRE` set, one line on stderr per request to a seller: the method, the path, its
/// status (or `err`) and how long its head took. For finding which steps a slow link makes slow.
fn wire_trace(method: &str, url: &str, status: Option<u16>, t0: Instant) {
    if std::env::var_os("XBT_TRACE_WIRE").is_none() {
        return;
    }
    let path = url.split_once("://").and_then(|(_, rest)| rest.find('/').map(|i| &rest[i..])).unwrap_or("/");
    let path: String = path.split('?').next().unwrap_or("/").chars().take(60).collect();
    let status = status.map_or_else(|| "err".to_string(), |s| s.to_string());
    eprintln!("wire: {method} {path} {status} {} ms", t0.elapsed().as_millis());
}

/// [`TicketWire`] over ureq. No overall deadline (an answer may be long); a connect, a read and a
/// write each have one.
#[derive(Default)]
pub struct UreqWire {
    /// By read timeout, and the trust: "" the public authorities (ureq's own, the Mozilla roots),
    /// else what [`seller_tls_key`] says of a `tickets.seller_tls` entry as it is now; "link" for a
    /// seller reached over the iroh link.
    agents: Mutex<HashMap<(u64, String), ureq::Agent>>,
    /// Where the link's key is kept (`<root>/link.key`); `None`: no links.
    root: Option<std::path::PathBuf>,
    /// The iroh link, started the first time a seller is reached by key.
    link: Mutex<Option<Arc<xbt_iroh_link::Link>>>,
}

/// Nostr relays a buyer asks where a seller's link is reached (`xbt_iroh_link::nostr_lookup`).
const LINK_LOOKUP_RELAYS: [&str; 3] = ["wss://relay.kilombino.com", "wss://nos.lol", "wss://relay.damus.io"];

impl UreqWire {
    /// One request, as [`TicketWire::send_with`] sends it; `overall`: a deadline for the whole of
    /// it, head and body, where each read alone is held only to `read_timeout`.
    #[allow(clippy::too_many_arguments)]
    fn send_req(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)], read_timeout: Duration, tls: Option<&SellerTls>,
                overall: Option<Duration>) -> Result<WireAnswer> {
        // ureq parses the string again, so it is given only what `request_url` read
        let url = sendable_url(url)?;
        let secs = read_timeout.as_secs().clamp(1, 3600);
        let (key, roots) = match tls {
            Some(t) => seller_tls_key(t)?,
            None => (String::new(), vec![]),
        };
        // a seller reached by key: its name resolves to the link's loopback port, and the link
        // carries the bytes end to end encrypted (an http URL: no TLS on top of it)
        let link = if link_host(&url) { Some(self.link()?) } else { None };
        let key = if link.is_some() { "link".to_string() } else { key };
        let tls_config = match tls {
            Some(t) if link.is_none() && !lock(&self.agents).contains_key(&(secs, key.clone())) => Some(seller_tls_config(t, roots)?),
            _ => None,
        };
        let agent = lock(&self.agents).entry((secs, key)).or_insert_with(|| {
            let b = ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(10)).timeout_read(Duration::from_secs(secs)).timeout_write(Duration::from_secs(secs))
                .redirects(0);
            let b = match link {
                Some(l) => b.resolver(move |hp: &str| match l.resolve(hp) {
                    Some(r) => r,
                    None => std::net::ToSocketAddrs::to_socket_addrs(hp).map(|a| a.collect()),
                }),
                None => b,
            };
            match tls_config {
                Some(c) => b.tls_config(c).build(),
                None => b.build(),
            }
        }).clone();
        let mut req = agent.request(method, &url).set("Accept-Encoding", "identity");
        if let Some(t) = overall {
            req = req.timeout(t);
        }
        for (k, v) in headers {
            req = req.set(k, v);
        }
        let resp = match if body.is_empty() && matches!(method, "GET" | "HEAD") { req.call() } else { req.send_bytes(body) } {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            // a fixed wording: ureq's own quotes the URL (the seller's session path) and a malformed status
            // the wallet's own wait running out (its read timeout or the call's deadline) is said as its own kind: the
            // seller may be slow, not gone, and is held as one still answering ([`WIRE_TIMEOUT`])
            Err(e) if wire_timed_out(&e) => return Err(err(WIRE_TIMEOUT, "the seller did not answer within the wallet's wait")),
            Err(e) => return Err(err("transport_error", xbt402::http::transport_words(&e))),
        };
        let status = resp.status();
        let headers: Vec<(String, String)> = resp.headers_names().into_iter().filter_map(|n| resp.header(&n).map(|v| (n.to_ascii_uppercase(), v.to_string()))).collect();
        let bodiless = method.eq_ignore_ascii_case("HEAD") || matches!(status, 100..=199 | 204 | 304);
        let length = if bodiless { Some(0) } else { resp.header("Content-Length").and_then(|s| s.parse::<u64>().ok()) };
        let (local, peer) = (resp.local_addr(), resp.remote_addr());
        let closer: Option<Closer> = (!bodiless).then(|| Arc::new(move || shut_connection(local, peer)) as Closer);
        let body: Box<dyn Read + Send> = if bodiless { Box::new(std::io::empty()) } else { Box::new(resp.into_reader()) };
        Ok(WireAnswer { status, headers, length, body, closer })
    }

    /// A TCP connection to a seller's `host`:`port`, as ureq's own calls reach it: a seller's link
    /// host (one reached by key) through the iroh link's local port, any other host as named.
    fn connect(&self, host: &str, port: u16) -> Result<std::net::TcpStream> {
        let bad = |e: std::io::Error| err("transport_error", e.to_string());
        let link = if link_host(&format!("http://{host}/")) { Some(self.link()?) } else { None };
        let addr = match link.as_ref().and_then(|l| l.resolve(&format!("{host}:{port}"))) {
            Some(addrs) => addrs.map_err(bad)?.into_iter().next(),
            None => std::net::ToSocketAddrs::to_socket_addrs(&(host, port)).map_err(bad)?.next(),
        }
        .ok_or_else(|| err("transport_error", "the seller's host resolves to nothing"))?;
        std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(10)).map_err(bad)
    }

    /// A wire that can also reach sellers by key, with the link's key kept under `root`.
    pub fn with_root(root: &std::path::Path) -> Self {
        Self { root: Some(root.to_path_buf()), ..Self::default() }
    }

    fn link(&self) -> Result<Arc<xbt_iroh_link::Link>> {
        let mut l = lock(&self.link);
        if let Some(l) = l.as_ref() {
            return Ok(l.clone());
        }
        let root = self.root.as_ref().ok_or_else(|| err("transport_error", "this wallet reaches sellers by web address only"))?;
        let secret = xbt402::provider::load_or_create_secret(&root.join("link.key")).map_err(|e| err("transport_error", e.to_string()))?;
        // private mode for the buyer: relays only (the platform sets it; the app's switch is the seller's)
        let private = std::env::var("XBT_LINK_PRIVATE").is_ok_and(|v| v == "1");
        let lookup = Some(Arc::new(xbt_iroh_link::nostr_lookup::NostrLookup::new(None, LINK_LOOKUP_RELAYS.iter().map(|r| r.to_string()).collect())));
        let opts = xbt_iroh_link::Options {
            relays: xbt_iroh_link::Relays::OursThenPublic(vec![xbt_iroh_link::DEFAULT_RELAY.into()]),
            serving: false,
            private,
            lookup,
        };
        let started = xbt_iroh_link::Link::start_with(secret.secret_bytes(), opts).map_err(|e| err("transport_error", format!("link: {e}")))?;
        *l = Some(started.clone());
        Ok(started)
    }
}

/// A shop's receipt key and transport document from the app's shops file (`XBT_SHOPS_FILE`: an
/// object of origin to `{receipt_key, transport}`, which the app writes when a shop is added).
fn shop_entry(origin: &str) -> Option<(String, Value)> {
    let path = std::env::var_os("XBT_SHOPS_FILE")?;
    let text = std::fs::read_to_string(path).ok()?;
    let all: Value = serde_json::from_str(&text).ok()?;
    let e = all.get(origin)?;
    Some((e.get("receipt_key")?.as_str()?.to_string(), e.get("transport")?.clone()))
}

/// A host reached over the link: a seller's link name, or a shop without a web address.
fn link_host(url: &str) -> bool {
    let host = xbt402::wire::request_url(url).host.to_ascii_lowercase();
    host.ends_with(xbt_iroh_link::HOST_SUFFIX) || host.ends_with(xbt_iroh_link::SHOP_SUFFIX)
}

/// A TLS verifier that accepts exactly one certificate, by the SHA-256 of its DER (a seller's own
/// self-signed one on a LAN). The handshake signature is still verified with the certificate's key.
#[derive(Debug)]
struct PinnedSha256 {
    pin: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedSha256 {
    fn verify_server_cert(&self, end_entity: &rustls::pki_types::CertificateDer<'_>, _i: &[rustls::pki_types::CertificateDer<'_>],
                          _n: &rustls::pki_types::ServerName<'_>, _o: &[u8], _now: rustls::pki_types::UnixTime)
                          -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let got: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if got == self.pin {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("the seller's certificate is not the one the owner pinned (tickets.seller_tls)".into()))
        }
    }

    fn verify_tls12_signature(&self, m: &[u8], c: &rustls::pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct)
                              -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, m: &[u8], c: &rustls::pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct)
                              -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Every certificate in a PEM text, as DER.
fn pem_certs(pem: &str) -> Vec<Vec<u8>> {
    use base64::Engine as _;
    pem.split("-----BEGIN CERTIFICATE-----").skip(1).filter_map(|b| {
        let body = &b[..b.find("-----END CERTIFICATE-----")?];
        base64::engine::general_purpose::STANDARD.decode(body.chars().filter(|c| !c.is_whitespace()).collect::<String>()).ok()
    }).collect()
}

/// A `tickets.seller_tls` entry as it is now: the CA file's certificates (read again for every
/// request, so that a changed file is what the next request uses), or the pin. The cache key, and
/// the certificates to trust.
fn seller_tls_key(tls: &SellerTls) -> Result<(String, Vec<Vec<u8>>)> {
    match tls {
        SellerTls::CaFile(p) => {
            let pem = std::fs::read_to_string(p).map_err(|e| err("seller_tls", format!("the owner's CA file for this seller ({}): {e}", p.display())))?;
            let certs = pem_certs(&pem);
            if certs.is_empty() {
                return Err(err("seller_tls", format!("the owner's CA file for this seller ({}) holds no PEM certificate", p.display())));
            }
            Ok((format!("ca:{}", hex::encode(Sha256::digest(certs.concat()))), certs))
        }
        SellerTls::CertSha256(pin) => Ok((format!("pin:{}", hex::encode(pin)), vec![])),
    }
}

/// The TLS client config for a named seller's entry: its CA file's certificates as the only roots,
/// or the one pinned certificate.
fn seller_tls_config(tls: &SellerTls, roots: Vec<Vec<u8>>) -> Result<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let b = rustls::ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions()
        .map_err(|e| err("seller_tls", e.to_string()))?;
    let cfg = match tls {
        SellerTls::CaFile(_) => {
            let mut store = rustls::RootCertStore::empty();
            for der in roots {
                store.add(rustls::pki_types::CertificateDer::from(der)).map_err(|e| err("seller_tls", format!("the owner's CA file for this seller: {e}")))?;
            }
            b.with_root_certificates(store).with_no_client_auth()
        }
        SellerTls::CertSha256(pin) => b.dangerous().with_custom_certificate_verifier(Arc::new(PinnedSha256 { pin: *pin, provider })).with_no_client_auth(),
    };
    Ok(Arc::new(cfg))
}

/// One TLS connection shared by the two directions of a WebSocket: each takes it in turn, and a
/// read gives it back every [`TLS_TURN`] so that a write is never kept waiting by a quiet seller.
type SharedTls = Arc<Mutex<rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>>>;
const TLS_TURN: Duration = Duration::from_millis(50);

struct TlsReader(SharedTls);
struct TlsWriter(SharedTls);

impl Read for TlsReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            match lock(&self.0).read(buf) {
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => std::thread::sleep(Duration::from_millis(1)),
                r => return r,
            }
        }
    }
}

impl Write for TlsWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut t = lock(&self.0);
        t.write_all(buf)?;
        t.flush()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        lock(&self.0).flush()
    }
}

impl Drop for TlsWriter {
    fn drop(&mut self) {
        let mut t = lock(&self.0);
        t.conn.send_close_notify();
        let _ = t.flush();
        let _ = t.sock.shutdown(std::net::Shutdown::Write);
    }
}

/// The write half of a plain connection: dropping it ends the stream toward the seller.
struct TcpWriter(std::net::TcpStream);

impl Write for TcpWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl Drop for TcpWriter {
    fn drop(&mut self) {
        let _ = self.0.shutdown(std::net::Shutdown::Write);
    }
}

/// The TLS client config for a WebSocket to an https seller: the named seller's own entry, or the
/// public authorities as ureq trusts them.
fn upgrade_tls_config(tls: Option<&SellerTls>) -> Result<Arc<rustls::ClientConfig>> {
    if let Some(t) = tls {
        let (_, roots) = seller_tls_key(t)?;
        return seller_tls_config(t, roots);
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut store = rustls::RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions()
        .map_err(|e| err("transport_error", e.to_string()))?
        .with_root_certificates(store)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// An HTTP answer's head: its status, its headers (names in upper case), and the bytes after it.
type AnswerHead = (u16, Vec<(String, String)>, Vec<u8>);

/// Read an HTTP answer's head from `r`.
fn read_answer_head(r: &mut dyn Read) -> Result<AnswerHead> {
    let mut buf = vec![];
    let mut tmp = [0u8; 2048];
    let end = loop {
        let n = r.read(&mut tmp).map_err(|e| err("transport_error", format!("the seller's answer: {e}")))?;
        if n == 0 {
            return Err(err("transport_error", "the seller closed before its answer"));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > 32 << 10 {
            return Err(err("transport_error", "the seller's answer head is too long"));
        }
    };
    let early = buf.split_off(end + 4);
    let text = String::from_utf8_lossy(&buf[..end]).to_string();
    let mut lines = text.split("\r\n");
    let status = lines.next().and_then(|l| l.split(' ').nth(1)).and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| err("transport_error", "the seller's answer has no status"))?;
    let headers = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_uppercase(), v.trim().to_string())).collect();
    Ok((status, headers, early))
}

impl TicketWire for UreqWire {
    fn upgrade(&self, url: &str, headers: &[(String, String)], read_timeout: Duration, tls: Option<&SellerTls>) -> Result<WireUpgrade> {
        let url = sendable_url(url)?;
        let u = url::Url::parse(&url).map_err(|e| err("transport_error", e.to_string()))?;
        let https = u.scheme() == "https";
        let host = u.host_str().ok_or_else(|| err("transport_error", "the seller's URL has no host"))?.to_string();
        let port = u.port_or_known_default().unwrap_or(if https { 443 } else { 80 });
        let target = match u.query() {
            Some(q) => format!("{}?{q}", u.path()),
            None => u.path().to_string(),
        };
        let sock = self.connect(&host, port)?;
        let _ = sock.set_read_timeout(Some(read_timeout));
        let _ = sock.set_write_timeout(Some(read_timeout));
        let host_header = match u.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.clone(),
        };
        let mut head = format!("GET {target} HTTP/1.1\r\nHost: {host_header}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nAccept-Encoding: identity\r\n");
        for (k, v) in headers {
            if !k.bytes().chain(v.bytes()).any(|c| matches!(c, b'\r' | b'\n' | 0)) {
                head.push_str(&format!("{k}: {v}\r\n"));
            }
        }
        head.push_str("\r\n");
        // the answer's body: a 101's is the stream from the seller; anything else's, as long as it says, or to its end
        let finish = |status: u16, headers: Vec<(String, String)>, early: Vec<u8>, rest: Box<dyn Read + Send>, writer: Box<dyn Write + Send>| {
            let length = headers.iter().find(|(k, _)| k == "CONTENT-LENGTH").and_then(|(_, v)| v.parse::<u64>().ok());
            let body: Box<dyn Read + Send> = Box::new(std::io::Cursor::new(early).chain(rest));
            let (body, writer) = if status == 101 {
                (body, Some(writer))
            } else {
                (match length {
                    Some(n) => Box::new(body.take(n)) as Box<dyn Read + Send>,
                    None => body,
                }, None)
            };
            WireUpgrade { answer: WireAnswer { status, headers, length: if status == 101 { None } else { length }, body, closer: None }, writer }
        };
        if !https {
            let mut s = sock;
            s.write_all(head.as_bytes()).map_err(|e| err("transport_error", e.to_string()))?;
            let (status, headers, early) = read_answer_head(&mut s)?;
            let _ = s.set_read_timeout(None);
            let w = s.try_clone().map_err(|e| err("transport_error", e.to_string()))?;
            return Ok(finish(status, headers, early, Box::new(s), Box::new(TcpWriter(w))));
        }
        let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(|e| err("transport_error", e.to_string()))?;
        let conn = rustls::ClientConnection::new(upgrade_tls_config(tls)?, name).map_err(|e| err("transport_error", e.to_string()))?;
        let mut t = rustls::StreamOwned::new(conn, sock);
        t.write_all(head.as_bytes()).map_err(|e| err("transport_error", format!("TLS with the seller: {e}")))?;
        let (status, headers, early) = read_answer_head(&mut t)?;
        // the two directions take the connection in turn: a read lets go of it every TLS_TURN
        let _ = t.sock.set_read_timeout(Some(TLS_TURN));
        let shared: SharedTls = Arc::new(Mutex::new(t));
        Ok(finish(status, headers, early, Box::new(TlsReader(shared.clone())), Box::new(TlsWriter(shared))))
    }


    fn send(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)], read_timeout: Duration) -> Result<WireAnswer> {
        self.send_with(method, url, body, headers, read_timeout, None)
    }

    fn send_with(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)], read_timeout: Duration, tls: Option<&SellerTls>)
                 -> Result<WireAnswer> {
        self.send_req(method, url, body, headers, read_timeout, tls, None)
    }

    fn send_by(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)], read_timeout: Duration, tls: Option<&SellerTls>,
               overall: Duration) -> Result<WireAnswer> {
        self.send_req(method, url, body, headers, read_timeout, tls, Some(overall))
    }

    fn learn_link(&self, origin: &str, link: &xbt402::transport::Link, nostr_author: Option<&str>) -> Result<()> {
        self.learn_links(origin, std::slice::from_ref(link), nostr_author)
    }

    fn learn_links(&self, origin: &str, links: &[xbt402::transport::Link], nostr_author: Option<&str>) -> Result<()> {
        let l = self.link()?;
        let bad = |e: std::io::Error| err("transport_error", format!("link: {e}"));
        for link in links {
            let direct = link.direct.iter().filter_map(|a| a.parse().ok()).collect();
            l.learn(&link.endpoint_id, xbt_iroh_link::Hints { relays: link.relays.clone(), direct }).map_err(bad)?;
            if let Some(a) = nostr_author {
                l.expect_author(&link.endpoint_id, a).map_err(bad)?;
            }
        }
        let host = xbt402::wire::request_url(origin).host;
        if host.to_ascii_lowercase().ends_with(xbt_iroh_link::SHOP_SUFFIX) {
            let ids: Vec<String> = links.iter().map(|k| k.endpoint_id.clone()).collect();
            l.bind_shop_links(&host, &ids).map_err(bad)?;
        }
        Ok(())
    }
}

// --- where an answer's body goes ----------------------------------------------------------------------

/// The body of an answer as it arrives: counted, hashed, its first bytes kept for the agent, and
/// all of it written to `B2_BODY_DIR` when that is set and the body is longer than the preview,
/// unless it is streamed to a caller (`stream_to`: a tunnel, a film), who keeps what it wants.
struct Sink {
    hash: Sha256,
    bytes: u64,
    preview: Vec<u8>,
    cap: usize,
    file: Option<(std::fs::File, PathBuf)>,
    file_error: Option<String>,
    /// Where the body goes as it arrives, for a caller that streams it on (a player): the socket
    /// the call named in `stream_to`.
    out: Option<std::os::unix::net::UnixStream>,
    /// The reader at `out` went away: the call reads no further.
    gone: bool,
    /// The most bytes the buyer was shown the body has (the call's `max_size`): a body that states no
    /// size is taken to there and no further.
    most: Option<u64>,
    /// The body went past `most`: the call reads no further ([`PASSED_SHOWN`]).
    passed: bool,
}

impl Sink {
    fn new() -> Self {
        Self { hash: Sha256::new(), bytes: 0, preview: vec![], cap: body_cap(), file: None, file_error: None, out: None, gone: false, most: None, passed: false }
    }

    /// A sink for `c`: one that streams to the call's socket where it named one. A socket that
    /// cannot be reached is a reader already gone.
    fn for_call(c: &Call) -> Self {
        Self::streaming_to(c.stream_to.as_deref())
    }

    /// The socket's other direction, for a WebSocket: what the reader there sends on to the seller.
    fn back_channel(&self) -> Option<std::os::unix::net::UnixStream> {
        self.out.as_ref()?.try_clone().ok()
    }

    /// A sink that streams to the socket at `path`, where one is named; one that cannot be
    /// reached is a reader already gone.
    fn streaming_to(path: Option<&std::path::Path>) -> Self {
        let mut s = Self::new();
        if let Some(path) = path {
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(u) => s.out = Some(u),
                Err(_) => s.gone = true,
            }
        }
        s
    }

    /// The head of the answer as the first line on the socket, before any byte of the body: for a
    /// caller that asked for it (`stream_head`), which hands the seller's status and range on to
    /// its own client before the body. Not counted or hashed: it is the wallet's line, not the
    /// seller's bytes.
    fn head(&mut self, head: &Value) {
        use std::io::Write;
        if let Some(out) = self.out.as_mut() {
            if writeln!(out, "{head}").is_err() {
                self.out = None;
                self.gone = true;
            }
        }
    }

    /// The reader at the socket is still there: reached, and not closed since. For a caller that
    /// never writes on its socket (`stream_paid`): whatever it might have written is read and lost.
    fn reader_there(&mut self) -> bool {
        use std::io::Read;
        if self.gone {
            return false;
        }
        let Some(out) = self.out.as_mut() else { return true };
        if out.set_nonblocking(true).is_err() {
            return true;
        }
        let there = match out.read(&mut [0u8; 1]) {
            Ok(0) => false,
            Ok(_) => true,
            Err(e) => e.kind() == std::io::ErrorKind::WouldBlock,
        };
        let _ = out.set_nonblocking(false);
        if !there {
            self.out = None;
            self.gone = true;
        }
        there
    }

    fn put(&mut self, chunk: &[u8]) {
        use std::io::Write;
        // past the size the buyer was shown: what fits is taken, and the call reads no further
        let chunk = match self.most {
            Some(most) if self.bytes.saturating_add(chunk.len() as u64) > most => {
                self.passed = true;
                &chunk[..usize::try_from(most.saturating_sub(self.bytes)).unwrap_or(0).min(chunk.len())]
            }
            _ => chunk,
        };
        if let Some(out) = self.out.as_mut() {
            if out.write_all(chunk).is_err() {
                self.out = None;
                self.gone = true;
            }
        }
        self.hash.update(chunk);
        self.bytes += chunk.len() as u64;
        let room = self.cap.saturating_sub(self.preview.len());
        let over = chunk.len() > room;
        // a body streamed to a caller is the caller's: a tunnel's hours of traffic are never written to disk here
        let streamed = self.out.is_some() || self.gone;
        if over && !streamed && self.file.is_none() && self.file_error.is_none() {
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
    /// Seqs of requests on their way to the seller, taken, sent and not yet answered, and when each
    /// was taken. Requests go out side by side on their own connections and arrive in another
    /// order; the seller takes each seq once within its window (`seqWindow`). One refused as past
    /// the window is sent again once this says the earlier ones are on their way, or takes over
    /// the earliest seq where none is.
    sent: HashMap<u64, Instant>,
}

impl Link {
    fn new(seller_sid: String, key: [u8; 32], next_seq: u64) -> Self {
        Self { seller_sid, key: Zeroizing::new(key), next_seq, sent: HashMap::new() }
    }
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
    /// The fault is the seller's word contradicting the wallet's count (a charge or a spend past what
    /// the wallet can account for): over-charging, for which the seller is blocked
    /// ([`crate::seller_block`]). Not set by a fault of another kind (a node that gives no final
    /// answer, a seller that forgot the session).
    overcharged: bool,
    /// The receipt that over-charged, kept with the block as its evidence.
    evidence: Option<Value>,
    /// Answers priced as they go that ended here and that the seller has not closed yet (their
    /// last receipt is not in `status`): the seller may still be waiting to send more of them, and
    /// would on the next ticket. Nothing is released into the session until all are closed.
    tails: Vec<Tail>,
    /// What every answer of the session has cost by the wallet's own count, in msat: each head's
    /// charge, and the body of an answer priced as it goes as it arrives. Answers run side by side
    /// in one session and draw on one balance; this is how each sees what the others drew.
    consumed: u64,
    /// `consumed` when the seller's totals were last taken ([`Money::take`]).
    absorbed_mark: u64,
    /// Requests the seller may still charge, by the request's own id ([`Money::request_id`], not
    /// its seq: a seq can pass from one request to another): the most each may still add to the
    /// session's spend (its call's limit, less what the wallet counted for it). From the moment the
    /// request is sent until the seller's last receipt for its answer is read.
    open: HashMap<u64, u64>,
    /// Requests whose answer was lost (the connection failed after the request left): the seller
    /// may still charge each, up to what could have arrived of it ([`uncounted_most`]), until a
    /// quiet point at least [`LOST_GRACE`] later.
    lost: HashMap<u64, (u64, Instant)>,
    /// What lost requests not priced by the token have been allowed in all this session: capped at
    /// [`LOST_CAP_TICKETS`] tickets, so losing many requests does not add up ([`Money::lose`]).
    lost_allowed: u64,
    /// Lost requests the wallet stopped waiting for (its own timeout): an honest seller on a slow path
    /// may still serve them, so they are neither clipped by the cap nor counted as lost requests charged.
    lost_waited: HashSet<u64>,
    /// Quiet points at which the seller's spend had risen by what lost requests allowed: each a
    /// lost request it charged. [`LOST_CHARGED_MOST`] of them is over-charging.
    lost_charged: u32,
    /// The ids handed out to requests so far.
    requests: u64,
    /// What answers priced by the token hold back until their end: the most each may still cost
    /// beyond its head. Kept apart from `consumed` (what was drawn), which never falls. Held until
    /// the answer ends, whatever totals are taken meanwhile, so the wallet may buy more ahead beside
    /// a long reply than it ends up needing: credit that stays the session's, never past a limit.
    reserved: u64,
    /// What answers priced by the token held back and did not draw, summed over the session: as each
    /// ends, the part of its hold its tokens did not come to. Credit that comes back to the answers
    /// beside it while they run, and that a seller may push one of them ahead on ([`Bound`]).
    freed: u64,
    /// How many times the seller's totals were taken (or what it said was released rose). A request
    /// sent while this was `e` is answered
    /// by a receipt the seller signed after every receipt taken up to `e`: one for a request sent
    /// at the current epoch is newer than the totals held, whatever its spend says ([`Money::take`]).
    epoch: u64,
    /// The seller's `spentMsat` at the last quiet point (nothing open, no tail), `consumed` then,
    /// and what the seller's receipts charged the answers closed since: the bounds of
    /// [`Money::take`].
    quiet_spent: u64,
    quiet_consumed: u64,
    accepted: u64,
}

impl Money {
    /// The seller's totals were taken: what the wallet counts from here on is on top of them.
    fn absorbed(&mut self) {
        self.absorbed_mark = self.consumed;
    }

    /// The seller's totals taken as the start of the count: nothing open, nothing owed.
    fn anchor(&mut self) {
        self.absorbed();
        self.quiet_spent = self.acct.spent_msat;
        self.quiet_consumed = self.consumed;
        self.accepted = 0;
    }

    /// An answer of the session is closed: its request `seq` adds nothing more to the seller's
    /// spend, and the seller charged it `charged` by its own signed receipt (at most its call's
    /// limit), where the wallet counted `counted` for it. A charge above the count (bytes the seller
    /// sent of an answer the wallet stopped reading, or a request whose answer was lost) is the
    /// seller's word for what it spent, and goes into the count.
    fn close(&mut self, rid: u64, charged: u64, counted: u64) -> bool {
        let open = self.open.remove(&rid).is_some();
        if open {
            self.accepted = self.accepted.saturating_add(charged);
            self.consumed = self.consumed.saturating_add(charged.saturating_sub(counted));
        }
        open
    }

    /// [`Money::close`] for an answer judged by `bound`: a reply by the token cut before its counts
    /// was counted at all it held ([`Money::end_hold`]); where its seller's last receipt charges
    /// less, the rest comes back to the answers beside it ([`Money::freed`]), as for a reply that
    /// ended.
    fn close_by(&mut self, rid: u64, charged: u64, counted: u64, bound: &Bound) {
        if self.close(rid, charged, counted) && bound.quoted.is_some() {
            self.freed = self.freed.saturating_add(counted.saturating_sub(charged));
        }
    }

    /// A receipt's totals into the wallet's count. Answers run side by side, so receipts are read in
    /// another order than the seller signed them: one older than the totals already taken (a lower
    /// `releasedMsat` or `spentMsat`) only had its own figures checked, and is otherwise passed over
    /// (`Ok(false)`), but for a `releasedMsat` above the one held: the seller's spend can fall (it
    /// gives back what bought nothing), its released total only rises. A newer one is taken if its
    /// spend is inside what the wallet can account for: the spend at the last quiet point, what the
    /// wallet counted since, and what the requests
    /// still open may add, each at most its call's limit. Where nothing is open, the spend since the
    /// last quiet point is at most what the seller's receipts charged the answers closed since.
    /// `charged_max`: the most this receipt may say its request was charged. `outstanding`: a secret
    /// has left whose taking the seller has not yet confirmed. `Err`: the seller's word contradicts
    /// the wallet's count; nothing of it is taken.
    fn take(&mut self, r: &Receipt, charged_max: u64, outstanding: bool, sent_epoch: Option<u64>) -> std::result::Result<bool, String> {
        self.take_checked(r, charged_max, outstanding, sent_epoch)
    }

    /// An over-charging fault of [`Money::take`]: a charge or a spend past what the wallet can
    /// account for. The seller is blocked for it ([`Money::overcharged`]); a contradiction in what
    /// was released only stops the session.
    fn overcharge(&mut self, r: &Receipt, why: String) -> std::result::Result<bool, String> {
        self.overcharged = true;
        self.evidence.get_or_insert_with(|| r.raw.clone());
        Err(why)
    }

    fn take_checked(&mut self, r: &Receipt, charged_max: u64, outstanding: bool, sent_epoch: Option<u64>) -> std::result::Result<bool, String> {
        if r.charged > charged_max {
            return self.overcharge(r, format!("the seller charged {} msat for a request whose price by its terms is at most {charged_max}", r.charged));
        }
        if r.spent_msat > r.released_msat {
            return self.overcharge(r, format!("the seller says {} msat were spent of {} released", r.spent_msat, r.released_msat));
        }
        if r.released_msat > self.acct.sent_msat {
            return Err(format!("the seller says {} msat were released, the wallet released {}", r.released_msat, self.acct.sent_msat));
        }
        // newer than the totals held, by the order of the wallet's own steps: the request it answers left after
        // they were taken. Its spend is taken even where it is lower (the seller gave back a charge that bought nothing)
        let newer = sent_epoch == Some(self.epoch);
        if newer && r.released_msat < self.acct.acked_msat {
            return Err(format!("the seller credited {} msat released and now {}", self.acct.acked_msat, r.released_msat));
        }
        if !newer && (r.released_msat < self.acct.acked_msat || r.spent_msat < self.acct.spent_msat) {
            // no telling which the seller signed first: a lower spend may be the older receipt. What it says was
            // released only rises, and confirms the tickets it names. A rise is a receipt that may be newer than a request
            // already sent: that one's is no longer known to be newer
            if r.released_msat > self.acct.acked_msat {
                self.acct.acked_msat = r.released_msat;
                self.epoch = self.epoch.saturating_add(1);
            }
            return Ok(false);
        }
        let acked = self.acct.acked_msat.max(r.released_msat);
        if !outstanding && acked != self.acct.sent_msat {
            return Err(format!("the wallet released {} msat and the seller credits {}", self.acct.sent_msat, acked));
        }
        let counted = self.consumed.saturating_sub(self.quiet_consumed);
        let open: u64 = self.open.values().chain(self.lost.values().map(|(m, _)| m)).fold(0u64, |a, b| a.saturating_add(*b));
        let ceiling = self.quiet_spent.saturating_add(counted).saturating_add(open);
        if r.spent_msat > ceiling {
            return self.overcharge(r, format!("the seller's spentMsat is {} msat, more than the {ceiling} the wallet can account for: {} at the last quiet point, {counted} counted \
                                since, and at most {open} more for the requests still open", r.spent_msat, self.quiet_spent));
        }
        let quiet = self.open.is_empty() && self.tails.is_empty() && self.lost.values().all(|(_, at)| at.elapsed() >= LOST_GRACE);
        // a lost request may have been charged up to what could have arrived of it ([`uncounted_most`]). All of that is
        // allowed here, once, even where the seller charged it less: the quiet point after it checks the spend no tighter
        let lost: u64 = self.lost.values().fold(0u64, |a, (m, _)| a.saturating_add(*m));
        // only lost requests whose connection failed count: one the wallet stopped waiting for may be an honest slow seller's
        if quiet && self.lost.keys().any(|k| !self.lost_waited.contains(k)) && r.spent_msat > self.quiet_spent.saturating_add(self.accepted) {
            // the seller charged lost requests: rare for an honest one, and counted
            self.lost_charged = self.lost_charged.saturating_add(1);
            if self.lost_charged >= LOST_CHARGED_MOST {
                return self.overcharge(r, format!("the seller charged for requests whose answers never arrived, {} times in this session", self.lost_charged));
            }
        }
        if quiet && r.spent_msat > self.quiet_spent.saturating_add(self.accepted).saturating_add(lost) {
            return self.overcharge(r, format!("the seller's spentMsat rose by {} msat since the last quiet point, and its own receipts charged the answers closed since {}",
                               r.spent_msat.saturating_sub(self.quiet_spent), self.accepted));
        }
        self.acct.acked_msat = acked;
        self.acct.spent_msat = r.spent_msat;
        self.epoch = self.epoch.saturating_add(1);
        if quiet {
            self.lost.clear();
            self.lost_waited.clear();
            self.anchor();
        } else {
            self.absorbed();
        }
        Ok(true)
    }

    /// What the seller holds for the session by the wallet's best count: its last signed balance,
    /// less what the answers drew since. Never more than the signed balance.
    fn est_balance(&self) -> u64 {
        self.acct.balance().saturating_sub(self.consumed.saturating_sub(self.absorbed_mark)).saturating_sub(self.reserved)
    }

    /// A new request's id, for [`Money::open`].
    fn request_id(&mut self) -> u64 {
        self.requests = self.requests.saturating_add(1);
        self.requests
    }

    /// The request `rid` left and its answer was lost: the seller may have taken it, and may charge
    /// it up to `most` (what could have arrived of it, [`uncounted_most`]), as late as its own queue
    /// lets it. Kept in the bounds until a quiet point [`LOST_GRACE`] after; a spend past them then
    /// is the seller's fault.
    fn lose(&mut self, rid: u64, most: u64, quoted: bool, waited: bool, ticket_msat: u64) {
        if self.open.remove(&rid).is_some() {
            if waited {
                self.lost_waited.insert(rid);
            }
            // a reply held at its quote keeps it, and so does one the wallet stopped waiting for; any other lost
            // request shares the session's cap
            let most = if quoted || waited {
                most
            } else {
                let room = ticket_msat.saturating_mul(LOST_CAP_TICKETS).saturating_sub(self.lost_allowed);
                let most = most.min(room);
                self.lost_allowed = self.lost_allowed.saturating_add(most);
                most
            };
            self.lost.insert(rid, (most, Instant::now()));
        }
    }

    /// An answer ending that held `held` back while it ran (one by the token), having drawn `had`
    /// by the wallet's count and costing `cost` past its head: what it has drawn now, and what of
    /// its hold comes back to the answers beside it ([`Money::freed`]). One cut short before its
    /// final counts (`cut_uncounted`) keeps all it held as drawn and frees nothing: its seller may
    /// yet be believed for all of it ([`Bound::quoted`]), and no answer beside it may count on the
    /// same credit.
    fn end_hold(&mut self, held: u64, had: u64, cost: u64, cut_uncounted: bool) -> u64 {
        let drawn = if cut_uncounted { cost.max(held) } else { cost }.max(had);
        self.reserved = self.reserved.saturating_sub(held);
        if !cut_uncounted {
            self.freed = self.freed.saturating_add(held.saturating_sub(drawn - had));
        }
        drawn
    }

    /// The answers left unclosed for [`TAIL_GIVE_UP`], closed as charged the most they may by the
    /// wallet's count: what is left of their call's limit, but no more than the wallet believes of
    /// any charge for them ([`Bound`]). How many.
    fn give_up(&mut self) -> usize {
        let mut gone = 0;
        let mut i = 0;
        // one at a time: each closed adds to the count what the next is judged against ([`Bound::most`])
        while i < self.tails.len() {
            if self.tails[i].since.elapsed() < TAIL_GIVE_UP {
                i += 1;
                continue;
            }
            let t = self.tails.remove(i);
            let left = self.open.get(&t.rid).copied().unwrap_or(0);
            let most = t.bound.most(self);
            self.close_by(t.rid, t.counted.saturating_add(left).min(most.max(t.counted)), t.counted, &t.bound);
            gone += 1;
        }
        gone
    }
}

/// An answer the seller has not closed: which request it answered, when the wallet stopped reading,
/// and what the wallet counted for it.
struct Tail {
    /// The request's id ([`Money::open`]) and its seq, by which its last receipt is found.
    rid: u64,
    seq: u64,
    digest: String,
    status: u16,
    since: Instant,
    counted: u64,
    /// What the wallet believes of a charge for it, when its last receipt is listed or never is.
    bound: Bound,
}

/// What the wallet believes of a seller's charge for one answer, however its last receipt reaches
/// it: as the answer ends, later in `status`, or never ([`Money::give_up`]). One rule for every way
/// an answer closes, so that none of them believes more than another:
/// - one that arrived whole: up to what it cost by the wallet's own count, and its receipt must
///   sign the body that arrived and charge no more than that;
/// - one priced by the token and cut short after its final counts (`usage` with no choices) or its
///   end (`[DONE]`) were read: up to what it cost by those counts, and a few tokens more
///   ([`TOKEN_SLACK`]); cut before them: up to what its terms quote for it at most (its request and
///   the most its tokens may come to, which it held back while it ran, and still holds as drawn),
///   and a charge past that quote is the seller's fault;
/// - one priced by its size and cut short: up to what the wallet read and what could be on its way
///   ([`CUT_SLACK`]), or the credit it could have drawn, whichever is more ([`Stream::cut_bound`]);
///   and, as it is closed, no more than that credit as it stands then ([`Share`]), so that answers
///   cut side by side are not each believed up to the same credit.
///
/// Never past the call's limit, and a charge past that is the seller's fault.
#[derive(Clone)]
struct Bound {
    most: u64,
    max_msat: u64,
    /// An answer that arrived whole: what it cost by the wallet's count, and its body's hash.
    whole: Option<(u64, String)>,
    /// One priced by its size and cut short: what it is judged against again as it is closed.
    share: Option<Share>,
    /// One priced by the token and cut short before its counts: the most its terms quote for it. A
    /// charge past it is the seller's fault.
    quoted: Option<u64>,
}

/// An answer priced by its size and cut short, as [`Bound::most`] judges it when it is closed: the
/// credit the session has left for it then, by the same count as while it ran (what the wallet
/// released, less what the other answers drew since it started, the charges believed of those closed
/// meanwhile among them), with [`CUT_SLACK`] priced on top. What was read and [`CUT_SLACK`] more is
/// always believed. Each answer closed adds what its seller was believed past the wallet's count to
/// the count ([`Money::close`]), so a second answer cut beside it is judged with that drawn.
#[derive(Clone, Copy)]
struct Share {
    base_spent: u64,
    mark_consumed: u64,
    own: u64,
    /// What was read and [`CUT_SLACK`] more, priced; and [`CUT_SLACK`] priced.
    read: u64,
    slack: u64,
}

impl Bound {
    /// The most believed of a charge for the answer, with the session's count as it stands (`m`,
    /// under the money lock the answer is closed under).
    fn most(&self, m: &Money) -> u64 {
        match self.share {
            None => self.most,
            Some(s) => {
                // the others' draw since it started, as `ticket_stream` counts it (this one holds nothing back now);
                // against what the wallet released, the most the seller can have credited
                let others = m.consumed.saturating_sub(s.mark_consumed).saturating_sub(s.own).saturating_add(m.reserved);
                let left = m.acct.sent_msat.saturating_sub(others).saturating_sub(s.base_spent);
                self.most.min(s.read.max(left.saturating_add(s.slack)))
            }
        }
    }

    /// What the answer's request may still add to the seller's spend once it has ended, where the
    /// wallet counted `counted` for it ([`Money::open`]): its fixed bound past that count. Fixed, not
    /// its share of the session's credit as it stands when it ends: that grows as answers beside it
    /// end, and an honest charge believed as it is closed must still have been allowed before.
    fn allowance(&self, counted: u64) -> u64 {
        self.most.saturating_sub(counted)
    }

    /// Whether the answer's last receipt `r` charges more than the answer costs (one that arrived
    /// whole) or its terms quote (a reply held at its quote): over-charging, for which the seller is
    /// blocked. A receipt that signs another body is a fault, not over-charging.
    fn overcharges(&self, r: &Receipt) -> bool {
        self.whole.as_ref().is_some_and(|(cost, _)| r.charged > *cost) || self.quoted.is_some_and(|q| r.charged > q)
    }

    /// The charge believed of the answer's last receipt `r`, and the seller's fault in it other
    /// than the call's limit (which `over_cap` words, keeping the receipt as evidence).
    fn judge(&self, r: &Receipt, m: &Money) -> (u64, Option<String>) {
        let fault = self.whole.as_ref().and_then(|(cost, digest)| {
            if r.body_hash != *digest {
                Some("the last receipt signs another body than the one that arrived".to_string())
            } else if r.charged > *cost {
                Some(format!("the last receipt charges {} msat for an answer that costs {cost} by the seller's terms", r.charged))
            } else {
                None
            }
        }).or_else(|| self.quoted.filter(|q| r.charged > *q).map(|q| {
            format!("the last receipt charges {} msat for a reply its terms quote at {q} at most", r.charged)
        }));
        (r.charged.min(self.most(m)), fault)
    }
}

/// Tokens of output past what an answer priced by the token cost by its counts that a seller's
/// charge for it is believed, where it was cut after its counts or its end were read: the events
/// counted after the counts, and any the two sides split differently.
const TOKEN_SLACK: u64 = 64;

/// An event of a streamed answer that says the answer has ended (`data: [DONE]`).
fn is_done_event(bytes: &[u8]) -> bool {
    String::from_utf8_lossy(bytes).lines().filter_map(|l| l.strip_prefix("data:")).any(|d| d.trim() == "[DONE]")
}

/// What may be on its way to the wallet when it stops reading an answer, past what it read: the
/// seller's socket buffer and the wallet's (a few MiB each where they grow to fit a fast link), and
/// a proxy's or relay's between them. A seller's charge for an answer cut short is believed up to
/// what the wallet read and this much more, priced, or up to the credit the answer could have
/// drawn and this much more, whichever is more ([`Stream::cut_bound`]).
const CUT_SLACK: u64 = (16 << 20) + PROXY_SLACK;

/// The error code of a request the wallet stopped waiting for (its own read timeout or deadline),
/// as against one whose connection failed: an honest seller on a slow path may still serve it.
pub(crate) const WIRE_TIMEOUT: &str = "timeout";

/// Whether a failed request ended on the wallet's own wait: an I/O error of kind `TimedOut` (or
/// `WouldBlock`, which a socket read timeout gives on some systems) under ureq's transport error.
fn wire_timed_out(e: &ureq::Error) -> bool {
    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
    while let Some(s) = src {
        if let Some(io) = s.downcast_ref::<std::io::Error>() {
            return matches!(io.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock);
        }
        src = s.source();
    }
    false
}

/// How long a request whose answer was lost is held as one the seller may still charge: longer than
/// any answer is waited for, so that the seller has served or dropped it by then.
const LOST_GRACE: Duration = Duration::from_secs(120);

/// The most that lost requests not priced by the token may be allowed in all, over a session, in
/// tickets: a seller that drops many requests is believed for no more than this for all of them.
const LOST_CAP_TICKETS: u64 = 1;

/// How many lost requests a seller may charge in one session before that is over-charging: a lost
/// answer is rare, and a seller that keeps charging for answers that never arrive is blocked.
const LOST_CHARGED_MOST: u32 = 3;

/// The most a request may add to the seller's spend past what the wallet has counted of it, by its
/// price, never past its call's limit (`max_msat`), so that a seller that inflates its spend while
/// an answer is open, or charges a request whose answer never came, takes no more than this:
/// - by the token: its quote (`reserve`), the most an honest gateway charges the reply in all;
/// - by the second: its call's limit (the seconds a seller may count are not the wallet's to know);
/// - by the byte or the request: its request, [`CUT_SLACK`] of bytes on their way (sent by the seller,
///   not yet read here), and, while it is answered (`streaming`) and priced by the byte, two tickets:
///   what the wallet pays ahead of what it has read, which an honest seller behind a buffering proxy
///   may push on. A request whose answer never came (`streaming` false) is held to its request and
///   the bytes that could have been on their way: a seller whose connection drops before its answer
///   reaches the wallet is paid only for what could have arrived.
///
/// `counted`: what the wallet has counted of the answer so far (its head and its body).
fn uncounted_most(price: &Price, reserve: u64, max_msat: u64, ticket_msat: u64, counted: u64, streaming: bool) -> u64 {
    let most = if price.tokens.active() {
        reserve.saturating_sub(counted)
    } else if price.second_msat > 0 {
        max_msat.saturating_sub(counted)
    } else {
        let slack = price.cost(CUT_SLACK, 0).map_or(u64::MAX, |c| c.saturating_sub(price.request_msat));
        // a price with no part by the byte charges nothing as its body runs: nothing is paid ahead of it
        let ahead = if streaming && price.byte_msat > 0 { ticket_msat.saturating_mul(2) } else { 0 };
        price.request_msat.saturating_sub(counted).saturating_add(slack).saturating_add(ahead)
    };
    most.min(max_msat.saturating_sub(counted))
}

/// A ticket session the wallet pays over HTTP. In memory only: a signer that starts again stops
/// every session (the book's rule) and has the seller's id and key on disk for the cancel.
pub(crate) struct HttpSession {
    pub origin: String,
    /// The book's session, and the owner's task it was opened under.
    pub sid: String,
    task: String,
    pub terms: PayTerms,
    /// The seller charged one answer past its call's limit ([`Signer::over_cap`]): over-charging, set
    /// where the `money` lock may be held already, so not in [`Money::overcharged`].
    over_cap: AtomicBool,
    /// The receipt that charged past the call's limit ([`Signer::over_cap`]).
    evidence: Mutex<Option<Value>>,
    /// The seller's terms for prepaid tickets, where its 402 listed them beside the entry the
    /// session was opened on.
    prepaid: Option<Terms>,
    /// The seller's BOLT 12 offer for its prepaid tickets (`extra.offer` of that entry), if it
    /// names one: a prepaid ticket is paid by it first (`docs/TICKETS.md` section 15).
    offer: Option<String>,
    /// The URL of the session endpoints: the origin and the terms' path.
    base: String,
    /// The address the session was opened for (its path and query), named in the first lock so that a
    /// seller whose route there is full sells nothing to a buyer it would not serve.
    visit: String,
    /// Held shared by every paid request in progress, so that requests run side by side; taken
    /// alone (and never waited for) by what may only happen with none in progress: moving the
    /// session to another address, stopping it as idle.
    calls: RwLock<()>,
    paying: Mutex<()>,
    /// With a seller that takes only the next seq, held by a request from its seq to its head
    /// ([`lock_order`]).
    order: Mutex<()>,
    /// Lock order: `paying`, `order`, `link`, `money`, never the other way ([`lock_paying`],
    /// [`lock_order`], [`lock_link`], [`lock_money`]).
    link: Mutex<Link>,
    money: Mutex<Money>,
    /// How many answers priced as they go are open: the seller's `spentMsat` moves between receipts.
    streaming: AtomicUsize,
    /// The session is being stopped: an open stream (a WebSocket, a VPN tunnel) ends now, so its last
    /// receipt is taken before what the session leaves with the seller is told ([`Signer::ticket_http_stop`]).
    ending: AtomicBool,
    refilling: AtomicBool,
    /// Releases running that found the seller had not shown a ticket, with no byte delivered between them.
    stalls: AtomicUsize,
    /// The wallet's clock at the last paid request.
    used: Mutex<f64>,
    /// Why the last attempt to fill the pool locked nothing: what a release that finds the pool
    /// empty reports.
    unfilled: Mutex<Option<Value>>,
    /// The seller has signed a receipt with the key of its terms, and the book has the key.
    key_on_record: AtomicBool,
    /// Hashes of this session's tickets the seller was asked to cancel because their payment had
    /// failed: each is asked for once.
    cancel_asked: Mutex<HashSet<String>>,
    /// The seller refused a lock of this session `too_many_tickets`: when the call ends, the session's
    /// unreleased tickets are cancelled and it is stopped ([`Signer::ticket_cap_full`]).
    cap_full: AtomicBool,
    /// The session ended because the seller had forgotten it ([`Signer::ticket_forgotten`]), and for no fault of the
    /// seller's before: a resume refused by that alone is made again in another session. One the seller is at fault
    /// for (a receipt that does not hold, a charge above what arrived) is never made again.
    forgotten: AtomicBool,
}

impl HttpSession {
    fn fault(&self) -> Option<String> {
        lock_money(self).fault.clone()
    }

    fn balance(&self) -> u64 {
        lock_money(self).acct.balance()
    }

    /// What the seller's signed receipts say was released in this session, as far as the wallet
    /// took them.
    fn credited(&self) -> u64 {
        lock_money(self).acct.acked_msat
    }

    fn public(&self) -> Value {
        // the seller's id for the session (never its key): two sessions of the wallet that took over the same
        // balance name the same one, and the seller's totals are for it
        let seller_session = lock_link(self).seller_sid.clone();
        let m = lock_money(self);
        json!({"session": self.sid, "seller_session": seller_session, "origin": self.origin, "released_msat": m.acct.sent_msat.to_string(), "credited_msat": m.acct.acked_msat.to_string(),
               "spent_msat": m.acct.spent_msat.to_string(), "balance_msat": m.acct.balance().to_string(), "unconfirmed_release": m.pending.as_ref().map(|p| p.0.clone()),
               "fault": m.fault, "answer_open": self.streaming.load(Ordering::SeqCst) > 0, "answers_open": self.streaming.load(Ordering::SeqCst),
               "answer_unclosed": !m.tails.is_empty()})
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
    /// When the call must have its answer: the caller's limit is what `tickets.max_answer_s` is below.
    by: Instant,
    url: &'a str,
    origin: &'a str,
    method: &'a str,
    body: &'a [u8],
    max_sats: i64,
    task: std::result::Result<String, String>,
    /// SHA-256 of each piece of the answer's body, hex, where the caller knows them (a file whose
    /// piece hashes it already holds): a piece paid by a draw gets its value only if it matches.
    piece_hashes: Vec<String>,
    /// A socket in `B2_STREAM_DIR` the body is streamed to as it arrives (`stream_to`).
    stream_to: Option<PathBuf>,
    /// The head of the answer goes to that socket first, as one line of JSON (`stream_head`).
    stream_head: bool,
    /// With `stream_head`, on the ticket rail: the socket is opened, and `{"paid":true}` written as
    /// its first line, once the request's tickets are paid and before the request leaves for the
    /// seller (`stream_paid`), so that a caller that times the seller counts from there and not
    /// from a payment that took long over a slow route. The head line follows it. Where the wallet
    /// pays again after that line (the seller's balance ran short), `{"paying":true}` comes first and
    /// `{"paid":true}` again before the request is sent again. A caller gone by then (its socket
    /// closed, or never reached) is sent nothing more: the request does not leave, and the answer
    /// says `ticket_caller_gone` with `request_sent` false, so that it may go to another seller
    /// without being paid twice.
    stream_paid: bool,
    /// The byte range asked for (`range`), sent as the `Range` header of every request for the URL.
    range: Option<ByteRange>,
    /// The validator of the copy the range continues (`if_range`: the `ETag` or `Last-Modified` of the
    /// answer it follows), sent as `If-Range` with it: a seller whose copy has changed since sends the whole
    /// body, which the wallet does not read, rather than the rest of another file.
    if_range: Option<String>,
    /// The caller's own request headers (`headers`, [`caller_headers`]), sent on every request of
    /// the call for its URL: a seller's web app asks with its cookies, its login and its formats.
    extra: Vec<(String, String)>,
    /// With `stream_head`: the head line carries the seller's response headers too
    /// (`head_headers`, [`passed_headers`]), for a caller that hands the answer on to a browser.
    head_headers: bool,
    /// The request asks to become a WebSocket (`upgrade`): after a `101` the call carries the
    /// stream both ways through `stream_to`, every byte either way paid for as the body's are.
    upgrade: bool,
    /// The call may draw only on the credit the seller already holds for the session and buys no
    /// ticket (`credit_only`): a web app's other requests while one of them buys. Its charge cap
    /// (`charge_sats`) stays the most the answer may charge, which the seller is told.
    credit_only: bool,
    /// The most the answer itself may charge (`max_charge_sats`), at most `max_sats`: a small check
    /// (a VPN exit's region, a hashrate trial) may buy the seller's whole ticket within `max_sats`
    /// and still be charged only its own use, the rest staying as credit with that seller.
    charge_sats: i64,
    /// The most bytes the caller was shown the resource has (`max_size`, a listed file's size): sent
    /// to the seller ([`xbt402::ticket::MAX_SIZE_HEADER`]), and an answer that states more is not read.
    max_size: Option<u64>,
}

impl Call<'_> {
    /// The headers every request of the call for its URL carries beside the payment's.
    fn headers(&self) -> Vec<(String, String)> {
        let mut h: Vec<(String, String)> = self.range.iter().map(|r| ("Range".to_string(), r.header())).collect();
        h.extend(self.range.and(self.if_range.clone()).map(|v| ("If-Range".to_string(), v)));
        h.extend(self.extra.iter().cloned());
        h.extend(self.max_size.map(|n| (xbt402::ticket::MAX_SIZE_HEADER.to_string(), n.to_string())));
        h
    }

    /// The answer's head, read ([`answer_head`]); with `stream_head`, the first line on the socket.
    /// `Some`: why its body is not read.
    fn head(&self, ans: &mut WireAnswer, sink: &mut Sink) -> (Value, Option<String>) {
        head_to(ans, self.range, self.max_size, self.stream_head, self.head_headers, sink)
    }
}

/// Why an answer whose head states more bytes in all than `most` is not read: the total in a
/// `206`'s `Content-Range`, or the `Content-Length` of any other `2xx` (the rule the seller and the
/// app judge by too). `None`: within it, nothing stated, or not a `2xx`.
fn larger_than_shown(status: u16, head: &Value, most: Option<u64>) -> Option<String> {
    let most = most?;
    let total = match status {
        206 => head.get("content_range").and_then(Value::as_str).and_then(|cr| cr.rsplit_once('/')).and_then(|(_, t)| t.parse::<u64>().ok()),
        200..=299 => head.get("content_length").and_then(Value::as_u64),
        _ => None,
    }?;
    (total > most).then(|| format!("the seller's answer is {total} bytes, more than the {most} the buyer was shown; nothing of it is read"))
}

/// [`answer_head`], and with `line` the head as the first line on the sink's socket (with `error`:
/// why the body is not read, where it is not). An answer larger than `most` ([`larger_than_shown`])
/// is not read.
fn head_to(ans: &mut WireAnswer, range: Option<ByteRange>, most: Option<u64>, line: bool, with_headers: bool, sink: &mut Sink) -> (Value, Option<String>) {
    let (head, refused) = answer_head(ans, range);
    let refused = refused.or_else(|| larger_than_shown(ans.status, &head, most));
    // the file's body (a 2xx) is read to the size shown and no further; an error's is the seller's own
    if (200..300).contains(&ans.status) {
        sink.most = most;
    }
    if line {
        let mut l = head.clone();
        if let Some(why) = &refused {
            l["error"] = why.clone().into();
        }
        if with_headers {
            l["headers"] = passed_headers(&ans.headers);
        }
        sink.head(&l);
    }
    (head, refused)
}

/// Why a call is refused when the seller's 402 offers nothing the wallet may pay.
const NO_RAIL: &str = "the seller's 402 offers no way to pay that this wallet's policy allows: see rails_passed_over for what each entry needs";

/// The most caller headers one call carries, and the longest value of one.
const CALLER_HEADERS: usize = 32;
const HEADER_VALUE: usize = 4096;

/// Request headers a caller may not set: the wallet's own (the payment, the range it asks for
/// itself), what frames the request, and what a proxy must not relay.
const CALLER_REFUSED: [&str; 16] = ["host", "content-length", "transfer-encoding", "connection", "keep-alive", "upgrade", "te", "trailer", "expect",
                                    "proxy-authorization", "proxy-connection", "range", "via", "forwarded", "accept-encoding", "payment-signature"];

/// The caller's request headers (`headers`: a list of `[name, value]`), as they may go to the
/// seller: a name of token characters that is not one of [`CALLER_REFUSED`] (nor `payment-*` or
/// `x-forwarded-*`), a value of visible characters and spaces, at most [`CALLER_HEADERS`] of them.
/// `Err`: why the call is refused. The seller's gateway passes on only the ones its route names.
pub(crate) fn caller_headers(v: Option<&Value>) -> std::result::Result<Vec<(String, String)>, String> {
    let Some(v) = v.filter(|v| !v.is_null()) else { return Ok(vec![]) };
    let list = v.as_array().ok_or("headers is a list of [name, value]")?;
    if list.len() > CALLER_HEADERS {
        return Err(format!("at most {CALLER_HEADERS} headers"));
    }
    let token = |s: &str| !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
    let mut out = Vec::with_capacity(list.len());
    for h in list {
        let (Some(k), Some(val)) = (h.get(0).and_then(Value::as_str), h.get(1).and_then(Value::as_str)) else {
            return Err("headers is a list of [name, value]".into());
        };
        let lk = k.to_ascii_lowercase();
        if !token(k) {
            return Err(format!("header name {k:?} is not a plain token"));
        }
        // `x-xbt402-*` are the wallet's to the seller (the call's limit, the size shown, the price line):
        // a caller's own would stand beside them, and a seller may read either
        if CALLER_REFUSED.contains(&lk.as_str()) || lk.starts_with("payment-") || lk.starts_with("x-forwarded-") || lk.starts_with("x-xbt402-") {
            return Err(format!("header {k} is the wallet's own, or not one a proxy passes on"));
        }
        if val.len() > HEADER_VALUE || !val.bytes().all(|b| b.is_ascii_graphic() || b == b' ' || b == b'\t') {
            return Err(format!("header {k}: the value is too long or not plain text"));
        }
        out.push((k.to_string(), val.to_string()));
    }
    Ok(out)
}

/// Response headers that are not handed on to a caller that asked for them: what frames the body
/// (the caller frames its own), the payment's, and the hop-by-hop ones.
const NOT_PASSED: [&str; 9] = ["content-length", "transfer-encoding", "connection", "keep-alive", "upgrade", "te", "trailer", "proxy-authenticate", "alt-svc"];

/// The seller's response headers, as the head line carries them for a caller that asked
/// (`head_headers`): `[name, value]` pairs, without [`NOT_PASSED`] or `payment-*`, values of plain
/// characters, at most 64 of them. What they say is the seller's, untrusted: the caller hands them
/// on, it reads no money from them.
pub(crate) fn passed_headers(headers: &[(String, String)]) -> Value {
    let v: Vec<Value> = headers.iter()
        .filter(|(k, _)| { let l = k.to_ascii_lowercase(); !NOT_PASSED.contains(&l.as_str()) && !l.starts_with("payment-") })
        .filter(|(k, v)| k.len() <= 64 && v.len() <= HEADER_VALUE && v.bytes().all(|b| b.is_ascii_graphic() || b == b' ' || b == b'\t'))
        .take(64)
        .map(|(k, v)| json!([k, v]))
        .collect();
    Value::Array(v)
}

/// What one call released: the hashes, the sats the book put in the ledger for them, and how many
/// of them were prepaid tickets. `limit_sats` is the call's `max_sats`: no ticket is released or
/// bought for the call that could take what the book puts in the ledger above it ([`Spent::room`]).
#[derive(Default)]
struct Spent {
    hashes: Vec<String>,
    booked_sats: i64,
    prepaid: usize,
    limit_sats: Option<i64>,
    /// The call's charge cap (`max_charge_sats`, else its `max_sats`): a prepaid ticket bought for
    /// it is sized to it where the seller lets the wallet choose ([`Signer::ticket_prepaid_size`]).
    charge_sats: Option<i64>,
    /// No ticket may be released for the call (its `credit_only`).
    credit_only: bool,
    /// What the tickets released for the call come to, in msat: the credit its own answer may have
    /// drawn past what the session had when it started ([`Stream::cut_bound`]).
    released_msat: u64,
    /// A request the seller may serve, or charge, has left for it (`request_sent` in the answer):
    /// not one the seller refused unserved and signed so (a 402, 503 or `identify_first`).
    sent: bool,
}

impl Spent {
    /// What is left of the call's `max_sats`, in sats: `None` where it has none.
    fn left(&self) -> Option<i64> {
        self.limit_sats.map(|l| l.saturating_sub(self.booked_sats).max(0))
    }

    /// Whether one more ticket of `face` sats, booked at most `booking` (its fee limit included),
    /// keeps the call inside its `max_sats`. A seller's ticket is one size: where that size is
    /// above what is left of the limit, the call pays nothing more and says so.
    fn room(&self, next: Option<(i64, i64)>, prepaid: bool) -> std::result::Result<(), Value> {
        let (Some(limit), Some((face, booking))) = (self.limit_sats, next) else { return Ok(()) };
        if self.booked_sats.saturating_add(booking) <= limit {
            return Ok(());
        }
        let kind = if prepaid { "prepaid ticket" } else { "ticket" };
        let fee = booking.saturating_sub(face);
        let left = limit.saturating_sub(self.booked_sats).max(0);
        let reason = if self.booked_sats == 0 {
            format!("the smallest {kind} this seller sells is {face} sat (up to {fee} sat more in routing fees), over this call's limit of {limit} sat: nothing was paid; \
                     call again with max_sats of at least {booking}")
        } else {
            format!("the next {kind} of this seller is {face} sat (up to {fee} sat more in routing fees), and only {left} sat of this call's limit of {limit} sat is \
                     left: no more was paid")
        };
        Err(with(deny("max_sats", reason), json!({"ticket_sats": face, "ticket_booking_sats": booking, "max_sats": limit})))
    }
}

/// The pacing of one answer that is priced as it goes: when the next ticket is due.
/// How far ahead of the last paid byte the next ticket of a body priced by its size is released:
/// more than a proxy holds back of an answer that pauses ([`Stream::due_bytes`]).
const PROXY_SLACK: u64 = 64 << 10;

/// An answer priced as it goes, counted among its session's open ones for as long as this lives:
/// however the request ends, it is no longer counted once dropped.
struct Streaming<'a>(&'a AtomicUsize);

impl<'a> Streaming<'a> {
    fn new(n: &'a AtomicUsize) -> Self {
        n.fetch_add(1, Ordering::SeqCst);
        Self(n)
    }
}

impl Drop for Streaming<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Where an answer starts in its session: what the stream of it counts from.
struct Mark {
    /// The seller's `spentMsat` before the answer's head.
    base_spent: u64,
    /// The session's [`Money::consumed`] with the head of this answer in it.
    consumed: u64,
    /// The answer is priced as it goes, and counted among the session's open ones.
    metered: bool,
}

/// How long an answer paid as it arrives stays open, and which of the owner's limits that is. A
/// WebSocket: as long as its page keeps it. An answer streamed on to its caller as it arrives (a film,
/// a download, an AI stream): as long as it delivers. Any other is read whole for a caller that waits
/// 60 s for it; and one priced by the second is held to that too, streamed or not, since its clock
/// bills whether bytes come or not.
fn open_limit(tp: &TicketPolicy, socket: bool, streamed: bool, by_the_second: bool) -> (i64, &'static str) {
    if socket {
        (tp.max_socket_s, "max_socket_s")
    } else if streamed && !by_the_second {
        (tp.max_stream_s, "max_stream_s")
    } else {
        (tp.max_answer_s, "max_answer_s")
    }
}

/// Whether a streamed answer still delivers: past `tickets.stream_floor_after_s`, at least
/// [`PROGRESS_FLOOR_BYTES`] in each `tickets.read_timeout_s` the wallet spends waiting on its seller.
/// Only that waiting counts: time the wallet holds the answer up itself (its reader stalled, a ticket
/// being paid) is not the seller's.
struct Progress {
    window: Duration,
    after: Duration,
    /// Only an answer held open by `max_stream_s`.
    on: bool,
    opened: Instant,
    waited: Duration,
    got: u64,
}

impl Progress {
    fn new(tp: &TicketPolicy, limit: &str) -> Self {
        Self { window: Signer::ticket_read_timeout(tp), after: Duration::from_secs(tp.stream_floor_after_s.max(0) as u64), on: limit == "max_stream_s",
               opened: Instant::now(), waited: Duration::ZERO, got: 0 }
    }

    /// A read of the seller's answer took `took` and brought `n` bytes. `Some`: why the answer ends here.
    fn read(&mut self, took: Duration, n: u64) -> Option<String> {
        if !self.on {
            return None;
        }
        self.waited += took;
        self.got = self.got.saturating_add(n);
        if self.waited < self.window {
            return None;
        }
        let short = self.got < PROGRESS_FLOOR_BYTES;
        (self.waited, self.got) = (Duration::ZERO, 0);
        (short && self.opened.elapsed() >= self.after).then(|| {
            format!("max_stream_s: fewer than {PROGRESS_FLOOR_BYTES} bytes arrived in {} s", self.window.as_secs())
        })
    }
}

struct Stream {
    price: Price,
    /// The seller's `spentMsat` before this request.
    base_spent: u64,
    /// Before the request was sent, so that the seconds counted here are never fewer than the seller's.
    started: Instant,
    max_msat: u64,
    /// The longest the answer stays open ([`open_limit`]), and which of the owner's limits that is.
    max_open: Duration,
    limit: &'static str,
}

impl Stream {
    /// Why the wallet reads no further, if it does not: the call's charge cap (`max_charge_sats`,
    /// else its `max_sats`) is used up by its own count, or the answer has been open for as long as
    /// the owner allows.
    fn over(&self, bytes: u64) -> Option<String> {
        // a body with a price of its own only: one paid for at its head costs nothing more however long it is
        if self.price.metered() && self.cost(bytes) >= self.max_msat {
            return Some("max_sats: the call's charge cap is used up".into());
        }
        (self.started.elapsed() >= self.max_open).then(|| format!("{}: the answer has been open for {} s", self.limit, self.max_open.as_secs()))
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

    /// The credit released so far already covers all the request may be charged (its charge cap):
    /// no ticket more is due for it, whatever its body does. Without this a capped call at a seller
    /// of small tickets bought a second one as the body neared the end of the first, which it could
    /// never be charged for.
    fn capped(&self, credited: u64) -> bool {
        self.avail(credited) >= self.max_msat
    }

    /// What does not depend on the body's size: the request and the seconds started.
    fn fixed(&self) -> u64 {
        self.price.request_msat.saturating_add(self.price.for_seconds(self.seconds()).unwrap_or(u64::MAX))
    }

    /// How many bytes of the body the released tickets pay for.
    fn covered(&self, credited: u64) -> u64 {
        self.price.bytes_for(self.avail(credited).saturating_sub(self.fixed()))
    }

    /// A body priced by its size: all but the last [`PROXY_SLACK`] bytes the released tickets pay
    /// for have arrived (at most a quarter of them), and the body goes on past what they pay for.
    /// Not every paid byte: a proxy between the two (a TLS proxy, a CDN) can hold back the tail of
    /// an answer that pauses, and the seller pauses where the balance runs out, so a wallet that
    /// waited for every paid byte would wait for bytes the seller is waiting to be paid to push.
    fn due_bytes(&self, credited: u64, bytes: u64, length: Option<u64>) -> bool {
        if self.price.byte_msat == 0 || self.capped(credited) {
            return false;
        }
        let covered = self.covered(credited);
        if length.is_some_and(|l| l <= covered) {
            return false;
        }
        bytes.saturating_add(PROXY_SLACK.min(covered / 4)) >= covered
    }

    /// [`Stream::due_bytes`], `lead` bytes earlier: far enough ahead that a ticket paid now arrives
    /// before the body reaches the end of what is paid for, so a payment that takes a second or two
    /// does not hold the body up. `lead` is the caller's, and at most half of what one ticket covers.
    fn due_bytes_ahead(&self, credited: u64, bytes: u64, length: Option<u64>, lead: u64) -> bool {
        if self.price.byte_msat == 0 || self.capped(credited) {
            return false;
        }
        let covered = self.covered(credited);
        if length.is_some_and(|l| l <= covered) {
            return false;
        }
        self.due_bytes(credited, bytes, length) || bytes.saturating_add(lead) >= covered
    }

    /// A body priced by the second: the balance does not cover the second that starts next.
    fn due_time(&self, credited: u64) -> bool {
        self.price.second_msat > 0 && !self.capped(credited) && self.avail(credited) < self.fixed().saturating_add(self.price.second_msat)
    }

    /// The most the seller may charge an answer cut short after `read` bytes both ways and `secs`
    /// seconds, by the wallet's count: what was read and what could be on its way ([`CUT_SLACK`]),
    /// priced; or `credit`, the credit the answer could have drawn (what the session had for it when
    /// it started, and the tickets its own call released), with [`CUT_SLACK`] priced on top for the
    /// bytes of other answers counted on both sides as it started. Whichever is more: a seller
    /// pushes ahead as far as the credit goes, and a proxy between the two can hold all of that.
    /// Not the session's whole credit at the stop: a seller that held the other answers back and cut
    /// this one would have it charged all their credit too. Never past the call's limit.
    fn cut_bound(&self, read: u64, secs: u64, credit: u64) -> u64 {
        let read = self.price.cost(read.saturating_add(CUT_SLACK), secs).unwrap_or(u64::MAX);
        let slack = self.price.cost(CUT_SLACK, 0).unwrap_or(u64::MAX);
        read.max(credit.saturating_add(slack)).min(self.max_msat)
    }
}

/// A WebSocket's way to the seller: what the reader at the socket sends, passed on as it comes,
/// counted in `up`. Ends when either side ends; dropping `writer` ends the stream toward the seller.
fn forward_up(mut from: std::os::unix::net::UnixStream, mut writer: Box<dyn Write + Send>, up: &AtomicU64) {
    let mut buf = vec![0u8; 16 << 10];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if writer.write_all(&buf[..n]).and_then(|()| writer.flush()).is_err() {
                    break;
                }
                up.fetch_add(n as u64, Ordering::SeqCst);
            }
        }
    }
    drop(writer);
    let _ = from.shutdown(std::net::Shutdown::Read);
}

/// The sellers the owner stays anonymous at (docs/BUYER-ACCOUNTS.md), in the wallet's run directory.
const IDENTITY_FILE: &str = "identity.json";

/// How long a ticket's payment is taken to last before one of the answer has been timed: a
/// Lightning payment across a route or two.
const FIRST_PAY_S: f64 = 3.0;

/// Why a call stopped reading when the program it streams to stopped reading first.
const READER_GONE: &str = "stopped by the buyer: the reader the body was streamed to went away";
/// Why the wallet read no further of a body that went past the size the buyer was shown (`max_size`).
const PASSED_SHOWN: &str = "stopped by the wallet: the answer passed the size the buyer was shown";

/// An answer without a receipt that blames nobody, and stops no session. A 408 is the seller's HTTP
/// layer giving up on a request that did not reach it in time, before any handler sees it: nothing
/// is served or charged, and its seq is not used up; a wallet on a slow disk or short of memory sends
/// one late, and sends it once more. A server error may be a proxy's, and the request may have been
/// served behind it: its seq is taken as used, and it is not sent again. Neither moves money, and a
/// seller gains nothing by either: the wallet goes on holding what it holds.
fn unsigned_and_no_fault(status: u16) -> bool {
    status >= 500 || status == 408
}

/// The socket a call streams its body to (`stream_to`): a name in `B2_STREAM_DIR`, which the
/// operator sets for a local program that hands the body on (a player). A name, never a path, so a
/// call reaches no socket outside that directory.
fn stream_socket(v: Option<&Value>) -> std::result::Result<Option<PathBuf>, String> {
    let Some(name) = v.and_then(Value::as_str).filter(|s| !s.is_empty()) else { return Ok(None) };
    if name.len() > 64 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') || name.starts_with('.') {
        return Err("stream_to is a socket name of letters, digits, '-', '_' and '.', in B2_STREAM_DIR".into());
    }
    let dir = std::env::var("B2_STREAM_DIR").map_err(|_| "stream_to needs B2_STREAM_DIR, the directory of the sockets a body may be streamed to".to_string())?;
    Ok(Some(PathBuf::from(dir).join(name)))
}

/// One byte range a call asks for (`range`): `bytes=N-` (from byte N to the end) or `bytes=N-M`
/// (bytes N to M, both included), and nothing else: no list of ranges, no suffix range, no spaces.
/// It is sent as the `Range` header of every request of the call to the seller; what is paid is
/// still what arrives, by the wallet's own count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRange {
    pub first: u64,
    pub last: Option<u64>,
}

/// 1 to 19 ASCII digits (any of them fits a u64).
fn digits(s: &str) -> Option<u64> {
    (!s.is_empty() && s.len() <= 19 && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse().ok()).flatten()
}

impl ByteRange {
    pub fn parse(s: &str) -> Option<Self> {
        let (first, last) = s.strip_prefix("bytes=")?.split_once('-')?;
        let first = digits(first)?;
        let last = if last.is_empty() { None } else { Some(digits(last)?) };
        last.is_none_or(|l| first <= l).then_some(Self { first, last })
    }

    /// The `Range` header's value.
    pub fn header(&self) -> String {
        match self.last {
            Some(l) => format!("bytes={}-{l}", self.first),
            None => format!("bytes={}-", self.first),
        }
    }
}

fn byte_range(v: Option<&Value>) -> std::result::Result<Option<ByteRange>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => ByteRange::parse(s).map(Some).ok_or_else(|| "range is one byte range, bytes=N- or bytes=N-M with N <= M".to_string()),
        Some(_) => Err("range is a string, bytes=N- or bytes=N-M".into()),
    }
}

/// `Content-Range: bytes A-B/T` (T a number, or `*`), as `(A, B, T)`.
fn content_range(s: &str) -> Option<(u64, u64, Option<u64>)> {
    let (span, total) = s.trim().strip_prefix("bytes ")?.split_once('/')?;
    let (a, b) = span.split_once('-')?;
    let (a, b) = (digits(a)?, digits(b)?);
    let total = if total == "*" { None } else { Some(digits(total)?) };
    (a <= b && total.is_none_or(|t| b < t)).then_some((a, b, total))
}

/// A seller's `Content-Type` as it is passed on: a media type of plain characters, else nothing.
fn plain_media_type(s: &str) -> Option<String> {
    let ok = !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~/;= ".contains(&b));
    ok.then(|| s.to_string())
}

/// The head of a seller's answer, in the wallet's words: its status, `Content-Length`,
/// `Content-Range`, `Accept-Ranges` and `Content-Type`, each only as the wallet could read it
/// (a range in numbers it parsed, a type of plain characters). These go into the call's answer and,
/// for a call that asked for it (`stream_head`), as the first line on its socket.
///
/// `Err` (with the head as far as it was read): an answer of 206 whose `Content-Range` is not the
/// range the call asked for, or that cannot be read, or whose `Content-Length` disagrees with it.
/// The body of such an answer is not read, nor that of a 200 to a call that asked for a range from
/// past the first byte: the seller sends the whole body, ignoring the range or (where the call named
/// `if_range`) because its copy has changed, and reading it would buy again the bytes the caller
/// already has. A 200 to a range from byte 0 is a whole answer, read as any other. (Until 0.1.20 a
/// 200 to any range was read, and metered, like any other.)
///
/// A 206 that states no `Content-Length` is read to the end of its range and no further: `length`
/// is set from its `Content-Range`.
fn answer_head(ans: &mut WireAnswer, asked: Option<ByteRange>) -> (Value, Option<String>) {
    let mut v = json!({"status": ans.status});
    if let Some(n) = ans.length.filter(|_| !matches!(ans.status, 100..=199 | 204 | 304)) {
        v["content_length"] = n.into();
    }
    match ans.header("Accept-Ranges").map(|s| s.trim().to_ascii_lowercase()) {
        Some(a) if a == "bytes" || a == "none" => v["accept_ranges"] = a.into(),
        _ => {}
    }
    if let Some(t) = ans.header("Content-Type").and_then(plain_media_type) {
        v["content_type"] = t.into();
    }
    // what a caller that goes on later from where this answer ended names in `if_range`
    for (k, name) in [("etag", "ETag"), ("last_modified", "Last-Modified")] {
        if let Some(x) = ans.header(name).map(str::trim).filter(|x| !x.is_empty() && x.len() <= 256 && x.bytes().all(|b| (0x20..0x7f).contains(&b))) {
            v[k] = x.into();
        }
    }
    let cr = ans.header("Content-Range").map(str::to_string);
    let refuse = |v: Value, why: String| (v, Some(why));
    match ans.status {
        // the whole body to a range from its first byte (the app's player asks bytes=0-... first): a whole answer,
        // paid as it is read and ended where the caller stops, its head and its receipt the whole body's
        200 if asked.is_some_and(|r| r.first == 0) => {}
        // the whole body to a call that asked for part of it: the bytes before the range would be bought again
        200 if asked.is_some() => {
            v["range_ignored"] = true.into();
            // the connection ends here, before a byte of the body is read: what the seller's socket can still take is all
            // it costs (the OS's buffers and what is on its way, docs/LIMITS.md)
            if let Some(close) = &ans.closer {
                close();
            }
            return refuse(v, format!("the seller answered the range asked for ({}) with the whole body", asked.map(|r| r.header()).unwrap_or_default()));
        }
        206 => {
            let Some((a, b, total)) = cr.as_deref().and_then(content_range) else {
                return refuse(v, "the seller's 206 has no Content-Range the wallet can read".into());
            };
            if let Some(r) = asked {
                if a != r.first || r.last.is_some_and(|l| b > l) {
                    return refuse(v, format!("the seller's 206 is for bytes {a}-{b}, not the range asked for ({})", r.header()));
                }
            }
            let span = b - a + 1;
            if ans.length.is_some_and(|n| n != span) {
                return refuse(v, format!("the seller's 206 states a Content-Length of {} for a range of {span} bytes", ans.length.unwrap_or(0)));
            }
            ans.length = Some(span);
            v["content_length"] = span.into();
            v["content_range"] = match total {
                Some(t) => format!("bytes {a}-{b}/{t}"),
                None => format!("bytes {a}-{b}/*"),
            }.into();
        }
        416 => {
            if let Some(t) = cr.as_deref().and_then(|s| s.trim().strip_prefix("bytes */")).and_then(digits) {
                v["content_range"] = format!("bytes */{t}").into();
            }
        }
        _ => {}
    }
    (v, None)
}

/// A call whose range the seller answered with the whole body ([`answer_head`]): said by its own rule,
/// with what it cost, which is what the route charges for an answer it does not read.
fn range_ignored(out: &mut Value, c: &Call<'_>) {
    if out.get("range_ignored") != Some(&Value::Bool(true)) {
        return;
    }
    let msat = out.get("price_msat").and_then(|v| crate::ticket::outside_u64(Some(v))).unwrap_or(0);
    out["rule"] = "ticket_range_ignored".into();
    out["complete"] = false.into();
    out["reason"] = format!("the seller ignored the range asked for ({}) and sent the whole body: none of it was read, so the bytes the caller already \
                             has were not bought again; this call cost {msat} msat", c.range.map(|r| r.header()).unwrap_or_default()).into();
}

/// The x402 scheme name of the on-chain channel this wallet once paid: recognised in a 402 only to
/// say that it is no longer a rail here.
const CHANNEL_SCHEME: &str = "batch-settlement";

/// The most of a seller's text an answer to the agent carries, in bytes (`B2_BODY_CAP`).
pub fn body_cap() -> usize {
    std::env::var("B2_BODY_CAP").ok().and_then(|v| v.parse().ok()).unwrap_or(12_000)
}

/// Whether `ip` is an address of the public internet: not unspecified, loopback, private, shared
/// (carrier NAT), link-local, documentation, benchmarking, multicast, broadcast or reserved. An
/// IPv4 address written inside IPv6 (mapped, or the NAT64 prefix) is judged as that IPv4 address.
pub fn public_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip.to_canonical() {
        IpAddr::V4(a) => {
            let [x, y, z, _] = a.octets();
            !(x == 0 || x == 10 || x == 127 || x >= 224
              || (x == 100 && (64..128).contains(&y)) || (x == 169 && y == 254) || (x == 172 && (16..32).contains(&y)) || (x == 192 && y == 168)
              || (x == 192 && y == 0 && (z == 0 || z == 2)) || (x == 198 && (y == 18 || y == 19)) || (x == 198 && y == 51 && z == 100)
              || (x == 203 && y == 0 && z == 113))
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                return public_ip(IpAddr::V4(std::net::Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8)));
            }
            // only the global unicast block, less documentation and the discard and transition ranges inside it
            (s[0] & 0xe000) == 0x2000 && !(s[0] == 0x2001 && s[1] == 0x0db8) && !(s[0] == 0x2001 && s[1] < 0x0200) && s[0] != 0x2002
        }
    }
}

/// Whether a request may leave for `origin`, a seller the owner has not named, before anything
/// is sent to it: the origin is https, and every address its host has is public
/// ([`public_ip`]). A task that admits any seller is what an agent has when it is told to go and
/// find sellers, so a URL it was handed must not make the wallet a client of the machine's own
/// services or of its private network. `Err`: why not.
///
/// The name is looked up here and again by the HTTP client when it connects: a name whose
/// answer changes between the two (DNS rebinding) is not caught by this check.
pub fn stranger_reachable(origin: &str) -> std::result::Result<(), String> {
    use std::net::ToSocketAddrs;
    let Some(netloc) = origin.strip_prefix("https://") else {
        return Err("a seller the owner has not named is reached over https only".into());
    };
    let (host, port) = match netloc.strip_prefix('[') {
        Some(rest) => match rest.split_once(']') {
            Some((h, "")) => (h, 443),
            Some((h, p)) => (h, p.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()).ok_or("the URL's port is not a number")?),
            None => return Err("the URL's host is not an address".into()),
        },
        None => match netloc.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().map_err(|_| "the URL's port is not a number")?),
            None => (netloc, 443),
        },
    };
    if host.is_empty() || host.contains('@') {
        return Err("the URL names no host".into());
    }
    let addrs: Vec<std::net::SocketAddr> = (host, port).to_socket_addrs().map_err(|e| format!("its host could not be looked up ({:?})", e.kind()))?.collect();
    if addrs.is_empty() {
        return Err("its host has no address".into());
    }
    if let Some(a) = addrs.iter().find(|a| !public_ip(a.ip())) {
        return Err(format!("its host has the address {}, which is not an address of the public internet (private, loopback, link-local or reserved)", a.ip()));
    }
    Ok(())
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
        // the chain's id: an entry for Lightning on it says so in `extra.layer` ([`xbt402::ticket::on_network`])
        crate::node::network(&*self.node, &self.chain, None)
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

    /// What a request to `url` checks the seller's https against: the owner's `tickets.seller_tls`
    /// entry for its origin while that origin is on the allowlist (a named seller), and otherwise
    /// nothing but the public certificate authorities (`None`). Asked before every request, as
    /// [`Signer::ticket_may_reach`] is: a seller taken off the list loses its entry with it.
    pub(crate) fn seller_tls_for(&self, url: &str) -> Option<SellerTls> {
        let origin = normalize_dest(&origin_of(url).ok()?);
        if !origin.starts_with("https://") || !self.engine.allowlist().contains(&origin) {
            return None;
        }
        self.ticket_policy().seller_tls.get(&origin).cloned()
    }

    /// Every request this module sends to a seller: [`TicketWire::send_with`] with
    /// [`Signer::seller_tls_for`] its URL.
    /// [`TicketWire::upgrade`], with the seller's certificate checked as [`Signer::wire`] checks it.
    fn wire_upgrade(&self, url: &str, headers: &[(String, String)], read_timeout: Duration) -> Result<WireUpgrade> {
        let tls = self.seller_tls_for(url);
        self.ticket_wire.upgrade(url, headers, read_timeout, tls.as_ref())
    }

    /// A WebSocket the seller gives without payment: its head to the socket, then both directions
    /// joined until either side ends it. Nothing is paid.
    fn free_websocket(&self, mut ans: WireAnswer, writer: Box<dyn Write + Send>, stream_to: Option<&std::path::Path>, stream_head: bool, head_headers: bool) -> Value {
        let mut sink = Sink::streaming_to(stream_to);
        let (head, _) = head_to(&mut ans, None, None, stream_head, head_headers, &mut sink);
        let up = AtomicU64::new(0);
        let (back, stopper) = (sink.back_channel(), sink.back_channel());
        let ended = std::thread::scope(|scope| {
            match back {
                Some(b) => {
                    scope.spawn(|| forward_up(b, writer, &up));
                }
                None => drop(writer),
            }
            let ended = read_all(ans, &mut sink);
            // the seller ended it: the reader's side ends too, and with it the way back
            if let Some(s) = &stopper {
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
            ended
        });
        let (_, stored, _) = sink.done();
        with(with(with(json!({"verdict": "allow", "rule": "free", "rail": "none", "status": 101, "charged_sats": 0, "note": "a WebSocket the seller gives free",
                              "complete": ended.is_none(), "bytes_up": up.load(Ordering::SeqCst)}), stored), json!({"ended": ended})), head)
    }

    pub(crate) fn wire(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)], read_timeout: Duration) -> Result<WireAnswer> {
        let tls = self.seller_tls_for(url);
        let t0 = Instant::now();
        let r = self.ticket_wire.send_with(method, url, body, headers, read_timeout, tls.as_ref());
        wire_trace(method, url, r.as_ref().map(|a| a.status).ok(), t0);
        r
    }

    /// [`Signer::wire`], the whole request held to `overall` ([`TicketWire::send_by`]).
    fn wire_by(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)], read_timeout: Duration, overall: Duration) -> Result<WireAnswer> {
        let tls = self.seller_tls_for(url);
        let t0 = Instant::now();
        let r = self.ticket_wire.send_by(method, url, body, headers, read_timeout, tls.as_ref(), overall);
        wire_trace(method, url, r.as_ref().map(|a| a.status).ok(), t0);
        r
    }

    /// Whether the owner's policy, as it is now, lets a request leave for `origin` under `task`: the
    /// origin is on the allowlist, or the task pays any seller. Asked before every request this
    /// module sends: the first of a call, and each one of a session after it, so that a seller the
    /// owner has since taken off the list is not sent another byte.
    fn ticket_may_reach(&self, origin: &str, task: &str) -> bool {
        self.engine.allowlist().iter().any(|a| a == origin) || self.ticket_policy().tasks.get(task).is_some_and(|t| t.admit == Admit::Any)
    }

    /// Keep the terms of a seller's 402 for the route it names, where its gateway checks them
    /// (`termsChecked`): every ticket entry names the same route, and there is no draw entry (draws
    /// are always asked for). At most 64 routes a seller and 64 sellers.
    fn route_terms_keep(&self, origin: &str, pr: &Value) {
        let entries: Vec<&Value> = pr.get("accepts").and_then(Value::as_array).into_iter().flatten().collect();
        // a seller that offers draws on a route: what was kept of its other routes may leave out the draw entry they
        // are offered now, and none of it is used again until each is asked
        if entries.iter().any(|e| e.get("scheme").and_then(Value::as_str) == Some(xbt402::lottery::SCHEME)) {
            lock(&self.route_terms).remove(origin);
            return;
        }
        if entries.iter().any(|e| e.get("scheme").and_then(Value::as_str) != Some(xbt402::ticket::SCHEME)) {
            return;
        }
        let routes: HashSet<&str> = entries.iter().filter(|e| e["extra"]["termsChecked"] == true).filter_map(|e| e["extra"]["route"].as_str()).collect();
        let [route] = routes.into_iter().collect::<Vec<_>>()[..] else { return };
        if !route.starts_with('/') || entries.iter().any(|e| e["extra"]["termsChecked"] != true || e["extra"]["route"] != route) {
            return;
        }
        let mut all = lock(&self.route_terms);
        if all.len() >= 64 && !all.contains_key(origin) {
            all.clear();
        }
        let mine = all.entry(origin.to_string()).or_default();
        if mine.len() >= 64 && !mine.contains_key(route) {
            mine.clear();
        }
        mine.insert(route.to_string(), pr.clone());
    }

    /// Whether terms kept for a route of `origin` are those of the session open with it: the same node,
    /// receipt key, ticket and endpoints. Terms kept from before the session was opened again on others
    /// would stop it as a seller whose terms changed; the price is asked instead.
    fn route_terms_fit(&self, origin: &str, pr: &Value, lightning: &str) -> bool {
        let Some(slot) = lock(&self.ticket_http).get(origin).cloned() else { return false };
        let Ok(open) = slot.open.try_lock() else { return false };
        let Some(h) = open.as_ref() else { return false };
        offers(pr, lightning).into_iter().any(|o| match o {
            Offer::Ticket(acc, prepaid) => {
                let prepaid = prepaid.and_then(|a| PayTerms::parse(&a, lightning).ok()).map(|p| p.terms);
                PayTerms::parse(&acc, lightning).is_ok_and(|t| h.terms.same_seller(&t)) && prepaid == h.prepaid
            }
            _ => false,
        })
    }

    /// The terms kept for the route of `url` at `origin`, the route the seller's gateway would take
    /// it on among those it has stated: the longest whose path ends in `/` and starts the URL's path,
    /// or that is the whole path.
    fn route_terms_for(&self, origin: &str, url: &str) -> Option<Value> {
        let path = url.split_once("://").and_then(|(_, rest)| rest.find('/').map(|i| &rest[i..])).unwrap_or("/");
        let path = path.split(['?', '#']).next().unwrap_or("/");
        let all = lock(&self.route_terms);
        all.get(origin)?.iter()
            .filter(|(r, _)| if r.ends_with('/') { path.starts_with(r.as_str()) } else { path == r.as_str() })
            .max_by_key(|(r, _)| r.len()).map(|(_, pr)| pr.clone())
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
    ///
    /// `range` ([`ByteRange`]) asks for part of the body, as a player that seeks does: it goes as
    /// the `Range` header on the unpaid request and the paid one. Nothing about the price changes:
    /// a body priced by the byte is paid for the bytes that arrive, and the seller's receipt signs
    /// the body it sent, which for a 206 is that part. The answer carries the seller's `status`,
    /// `content_range`, `content_length`, `accept_ranges` and `content_type` as the wallet read
    /// them ([`answer_head`]); with `stream_to` and `stream_head`, the same head is the first line
    /// on the socket, before the body.
    ///
    /// A caller that hands the answer on to a browser (a seller's own web page, docs/SELLER-APPS.md)
    /// sends the page's own request headers (`headers`, [`caller_headers`]) and, with
    /// `head_headers`, gets the seller's response headers in the head line ([`passed_headers`]).
    pub(crate) fn xbt402_pay(&self, p: &Value) -> Value {
        let origin = p.get("url").and_then(Value::as_str).and_then(|u| origin_of(u).ok()).map(|o| normalize_dest(&o));
        let forget = || {
            if let Some(o) = &origin {
                lock(&self.route_terms).remove(o);
            }
        };
        // a session stopped because the seller's terms changed: what was kept of its routes' terms is not its terms now either
        let stopped_on_new_terms = |v: &Value| v.get("rule").and_then(Value::as_str) == Some("ticket_terms_changed");
        // only a caller that asks for it (`known_terms`: a page of a web app, many small reads) is paid on terms it
        // was told before; any other call asks the seller's price first, and sees there what the seller says now
        let known = p.get("known_terms").and_then(Value::as_bool) == Some(true);
        // the whole call has one deadline, the try on new terms below included
        let call_by = Instant::now() + Duration::from_secs(self.ticket_policy().max_answer_s.clamp(1, 86_400) as u64);
        let first = self.xbt402_pay_as(p, known, call_by);
        if stopped_on_new_terms(&first) {
            forget();
        }
        // paid on terms the seller stated for another of its routes, and refused unpaid: asked properly, once
        if first.get("seller_code").and_then(Value::as_str) != Some("terms_changed") {
            return first;
        }
        forget();
        // what the first try booked (a ticket released to make up the balance, say) is this call's too: the second
        // may spend only what is left of the call's limit, and the answer counts both
        let booked = py_int(first.get("charged_sats")).unwrap_or(0).max(0);
        let released = first.get("tickets_released").and_then(Value::as_u64).unwrap_or(0);
        let mut again = p.clone();
        if booked > 0 {
            if let Some(m) = py_int(p.get("max_sats").filter(|v| !v.is_null())) {
                again["max_sats"] = (m - booked).max(0).into();
            }
        }
        let mut v = self.xbt402_pay_as(&again, false, call_by);
        if stopped_on_new_terms(&v) {
            forget();
        }
        if booked > 0 {
            v["charged_sats"] = (py_int(v.get("charged_sats")).unwrap_or(0) + booked).into();
        }
        if released > 0 || v.get("tickets_released").is_some() {
            v["tickets_released"] = (v.get("tickets_released").and_then(Value::as_u64).unwrap_or(0) + released).into();
        }
        v
    }

    /// [`Signer::xbt402_pay`]; `known_terms`: a request on a route whose terms the seller stated in this
    /// session may be paid without asking its price first ([`Signer::route_terms`]).
    fn xbt402_pay_as(&self, p: &Value, known_terms: bool, call_by: Instant) -> Value {
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
        let raw: Vec<u8> = match (p.get("body"), p.get("body_b64").and_then(Value::as_str)) {
            (_, Some(b)) => {
                use base64::Engine as _;
                match base64::engine::general_purpose::STANDARD.decode(b) {
                    Ok(v) => v,
                    Err(_) => return deny("body", "body_b64 is not base64"),
                }
            }
            (Some(Value::String(s)), None) => s.clone().into_bytes(),
            (Some(Value::Array(a)), None) => a.iter().filter_map(|x| x.as_u64().map(|b| b as u8)).collect(),
            _ => vec![],
        };
        let task = Self::ticket_task_for(&tp, &str_or_empty(p.get("task")));
        let stream_to = match stream_socket(p.get("stream_to")) {
            Ok(s) => s,
            Err(why) => return deny("stream_to", why),
        };
        let stream_head = stream_to.is_some() && p.get("stream_head").and_then(Value::as_bool) == Some(true);
        let range = match byte_range(p.get("range")) {
            Ok(r) => r,
            Err(why) => return deny("range", why),
        };
        let piece_hashes: Vec<String> = p.get("piece_sha256").and_then(Value::as_array).into_iter().flatten().take(1 << 20)
            .map(|h| h.as_str().unwrap_or("").to_ascii_lowercase()).collect();
        if range.is_some() && method != "GET" {
            return deny("range", "range is for a GET");
        }
        let if_range = match p.get("if_range").filter(|v| !v.is_null()) {
            None => None,
            Some(v) => match v.as_str().filter(|s| !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| (0x20..0x7f).contains(&b))) {
                Some(s) if range.is_some() => Some(s.to_string()),
                Some(_) => return deny("if_range", "if_range goes with a range"),
                None => return deny("if_range", "if_range is the ETag or Last-Modified of the answer the range continues, in visible characters"),
            },
        };
        // the caller's piece hashes are of the whole body, from its first byte: a part of it would be judged against the wrong pieces
        if range.is_some() && !piece_hashes.is_empty() {
            return deny("range", "range and piece_sha256 do not go together: the pieces are counted from the body's first byte");
        }
        let extra = match caller_headers(p.get("headers")) {
            Ok(h) => h,
            Err(why) => return deny("headers", why),
        };
        let head_headers = stream_head && p.get("head_headers").and_then(Value::as_bool) == Some(true);
        let stream_paid = stream_head && p.get("stream_paid").and_then(Value::as_bool) == Some(true);
        // the price the buyer was shown where it chose this seller: terms above it are paid nothing
        let ceiling = match PriceCeiling::parse(p.get("price_ceiling")) {
            Ok(c) => c,
            Err(why) => return deny("price_ceiling", why),
        };
        let upgrade = p.get("upgrade").and_then(Value::as_bool) == Some(true);
        let credit_only = p.get("credit_only").and_then(Value::as_bool) == Some(true);
        let charge_sats = match p.get("max_charge_sats").filter(|v| !v.is_null()) {
            None => max_sats,
            Some(v) => match py_int(Some(v)) {
                Some(n) if n > 0 => n.min(max_sats),
                Some(_) => return deny("amount", "max_charge_sats must be > 0"),
                None => return deny("amount", "max_charge_sats must be an integer"),
            },
        };
        // the most bytes the caller was shown the resource has: a larger answer is refused before its body
        let max_size = match p.get("max_size").filter(|v| !v.is_null()) {
            None => None,
            Some(v) => match v.as_u64().filter(|n| *n > 0) {
                Some(n) => Some(n),
                None => return deny("max_size", "max_size is a number of bytes, above 0"),
            },
        };
        if upgrade && (stream_to.is_none() || method != "GET" || range.is_some()) {
            return deny("upgrade", "a WebSocket (upgrade) is a GET with stream_to, and no range");
        }
        let mut range_headers: Vec<(String, String)> = range.iter().map(|r| ("Range".to_string(), r.header())).collect();
        range_headers.extend(extra.iter().cloned());
        range_headers.extend(max_size.map(|n| (xbt402::ticket::MAX_SIZE_HEADER.to_string(), n.to_string())));
        // the owner's word before any request leaves: an allowlisted origin, or a task that pays any seller
        let listed = self.engine.allowlist().contains(&origin);
        if !self.ticket_may_reach(&origin, task.as_deref().unwrap_or("")) {
            return deny("allowlist", format!("destination not on allowlist: {origin} (and the call names no task that pays any seller)"));
        }
        // a seller reached by key: its transport document (from its listing), checked before a byte
        // goes. The node is the one the owner allowed for this seller, else the one that signed
        // given by the caller, or, for a shop with no web address, read from the app's shops file
        let from_file = (p.get("transport").is_none_or(Value::is_null) && xbt402::shop::is_shop(&origin)).then(|| shop_entry(&origin)).flatten();
        let doc = p.get("transport").filter(|v| !v.is_null()).or(from_file.as_ref().map(|(_, d)| d));
        if let Some(doc) = doc {
            let rk = match &from_file {
                Some((rk, _)) => rk.clone(),
                None => str_or_empty(p.get("receipt_key")),
            };
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
            let node = cfg.counterparties.get(&origin).and_then(|c| c.get("ln_node")).and_then(Value::as_str).map(str::to_string)
                .or_else(|| xbt402::transport::node_of(doc, &origin, &rk, now));
            let links = node.map(|n| xbt402::transport::verified_iroh_links(doc, &origin, &rk, &n, now)).unwrap_or_default();
            if links.is_empty() {
                return deny("transport", "the seller's transport document does not check out (its receipt key, its node's signature, or its expiry)");
            }
            let author = xbt402::shop::key_of(&origin).map(hex::encode);
            if let Err(e) = self.ticket_wire.learn_links(&origin, &links, author.as_deref()) {
                return deny("transport", e.msg);
            }
        } else if xbt402::shop::is_shop(&origin) {
            return deny("transport", "a shop without a web address is reached through its transport document: pass `transport` and `receipt_key` from its listing, or add the shop in the app (XBT_SHOPS_FILE)");
        }
        // a seller the owner has not named, reached through a task that admits any: https and a public address,
        // before the first byte leaves (the owner may widen this for a lab: tickets.unlisted_private)
        if !listed && !tp.unlisted_private {
            if let Err(why) = stranger_reachable(&origin) {
                return deny("dest_private", format!("{origin} is not on the allowlist, and {why}: nothing was sent to it"));
            }
        }
        let (lightning, chain) = match (self.ticket_net(), self.network()) {
            (Ok(l), Ok(c)) => (l, c),
            (Err(e), _) | (_, Err(e)) => return deny("xbt402", e.msg),
        };
        // the session open with this seller, named in the ask of the price: a seller whose route is full
        // goes on serving a buyer it serves there (docs/CAPACITY.md)
        let named0 = self.ticket_seller_sid(&origin, false);
        // a plain read on a route whose terms this seller stated, with a session open: paid without asking
        let known = (known_terms && named0.is_some() && matches!(method.as_str(), "GET" | "HEAD") && raw.is_empty() && !upgrade)
            .then(|| self.route_terms_for(&origin, &url)).flatten()
            .filter(|pr| self.route_terms_fit(&origin, pr, &lightning));
        let pr = match known {
            Some(pr) => pr,
            None => {
                let mut named = named0;
                let mut probe = loop {
                    let mut headers = range_headers.clone();
                    if let Some(sid) = &named {
                        headers.push(("PAYMENT-SESSION".into(), sid.clone()));
                    }
                    let probe = if upgrade {
                        // a WebSocket is asked for as one from the start: a free one is joined at once, a paid one is a 402 like any
                        match self.wire_upgrade(&url, &headers, Self::ticket_read_timeout(&tp)) {
                            Ok(WireUpgrade { answer, writer: Some(writer) }) if answer.status == 101 => return self.free_websocket(answer, writer, stream_to.as_deref(), stream_head, head_headers),
                            Ok(u) => Ok(u.answer),
                            Err(e) => Err(e),
                        }
                    } else {
                        self.wire(&method, &url, &raw, &headers, Self::ticket_read_timeout(&tp).min(call_by.saturating_duration_since(Instant::now()).max(Duration::from_secs(1))))
                    };
                    let probe = match probe {
                        Ok(a) => a,
                        Err(e) => return deny("xbt402", format!("the seller gave no answer: {}", e.msg)),
                    };
                    // busy while another call was opening the session with this seller (a page's first parts at
                    // once): asked again as that session's buyer, once it is open
                    if probe.status == 503 && named.is_none() {
                        named = self.ticket_seller_sid(&origin, true);
                        if named.is_some() {
                            continue;
                        }
                    }
                    break probe;
                };
                // a seller whose service is full turns a new visit away before it is sold anything
                if probe.status == 503 {
                    let v: Value = probe.read_small(SMALL_BODY).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
                    // refused unserved: another seller may serve the request (`request_sent` false)
                    if let Some(d) = seller_busy(&v) {
                        return d;
                    }
                    return with(deny("xbt402", "the seller's service is unavailable (HTTP 503); nothing was paid"),
                                json!({"status": 503, "charged_sats": 0, "request_sent": false}));
                }
                if probe.status != 402 {
                    let status = probe.status;
                    // as on the paid paths: a socket that cannot be reached is a reader already gone, and nothing is read for it
                    let mut sink = Sink::streaming_to(stream_to.as_deref());
                    let (head, refused) = head_to(&mut probe, range, max_size, stream_head, head_headers, &mut sink);
                    let ended = match refused {
                        Some(why) => Some(format!("not read: {why}")),
                        None => read_all(probe, &mut sink),
                    };
                    let (_, stored, text) = sink.done();
                    return with(with(with(json!({"verdict": "allow", "rule": "free", "rail": "none", "status": status, "charged_sats": 0, "note": "no 402 (already free or error)",
                                                 "complete": ended.is_none(), UNTRUSTED_KEY: untrusted(&text, Value::Null)}), stored),
                                     json!({"ended": ended})), head);
                }
                let Some(pr) = probe.header("PAYMENT-REQUIRED").and_then(|h| unb64json(h).ok()) else {
                    return deny("xbt402", "402 without a readable PAYMENT-REQUIRED");
                };
                drop(probe);
                // a GET's terms only: a HEAD's leave out the draw entry a GET would be offered
                if method == "GET" {
                    self.route_terms_keep(&origin, &pr);
                }
                pr
            }
        };
        if max_sats == 0 {
            return with(deny("max_sats", "the seller asks to be paid and this call may spend nothing (max_sats 0)"), json!({"charged_sats": 0}));
        }
        let call = Call { by: call_by, url: &url, origin: &origin, method: &method, body: &raw, max_sats, task, piece_hashes, stream_to, stream_head, stream_paid, range, if_range, extra, head_headers, upgrade, credit_only, charge_sats, max_size };
        let mut passed: Vec<Value> = vec![];
        let mut ways = offers(&pr, &lightning);
        // a route that gives each buyer an account is paid with tickets only: draws serve no buyer as its account
        // (docs/BUYER-ACCOUNTS.md), so a seller from before that rule that offers them there is not paid by them
        if ways.iter().any(|o| matches!(o, Offer::Ticket(acc, _) if identify_asked(acc))) {
            ways.retain(|o| !matches!(o, Offer::Lottery(_)));
        }
        // tickets or draws first: one rule ([`crate::lottery::choose`]); the other is tried after it
        if self.draws_first(&call, &ways, &lightning, &tp) {
            if let Some(i) = ways.iter().position(|o| matches!(o, Offer::Lottery(_))) {
                let l = ways.remove(i);
                ways.insert(0, l);
            }
        }
        let mut above: Option<String> = None;
        for offer in ways {
            let rail = offer.rail();
            if let Some(why) = ceiling.as_ref().and_then(|c| offer.entries().into_iter().find_map(|a| c.over(a))) {
                passed.push(json!({"rail": rail, "why": format!("price_ceiling: {why}")}));
                above.get_or_insert(why);
                continue;
            }
            let tried = match &offer {
                Offer::Ticket(..) | Offer::Lottery(_) if !tp.enabled => Tried::Next(tp.mainnet_off.clone().unwrap_or_else(|| "stream tickets are off in this policy (tickets.enabled)".into())),
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
        // a seller asking more than the buyer was shown is refused as that, not as having no way to be paid
        if let Some(why) = above {
            return with(deny("price_ceiling", format!("the seller's terms are above the price the buyer was shown ({why}): nothing was paid")),
                        json!({"charged_sats": 0, "rails_passed_over": passed}));
        }
        // what the 402 offers, in the wallet's words: a scheme it knows by name, and whether the network is one of its own
        let offered: Vec<Value> = pr.get("accepts").and_then(Value::as_array).into_iter().flatten()
            .map(|a| {
                let scheme = a.get("scheme").and_then(Value::as_str);
                let scheme = if scheme == Some(xbt402::ticket::SCHEME) { xbt402::ticket::SCHEME } else if scheme == Some(xbt402::lottery::SCHEME) { xbt402::lottery::SCHEME }
                             else if scheme == Some("exact") { "exact" }
                             else if matches!(scheme, Some(CHANNEL_SCHEME | "xbt-channel")) { CHANNEL_SCHEME } else { "other" };
                let network = match a.get("network").and_then(Value::as_str) {
                    _ if xbt402::ticket::on_network(a, &lightning) => "this wallet's Lightning network",
                    Some(n) if n == chain => "this wallet's chain",
                    _ => "other",
                };
                json!({"scheme": scheme, "network": network})
            }).take(16).collect();
        if offered.iter().any(|o| o["scheme"] == CHANNEL_SCHEME) {
            passed.push(json!({"rail": "channel", "why": "the seller offers the on-chain channel, which this wallet no longer has"}));
        }
        // one way to pay, passed over for one reason: that reason, in its own words, is what the call says
        let why = match passed.as_slice() {
            [one] => one["why"].as_str().and_then(|w| w.split_once(": ")).filter(|(r, _)| !r.is_empty() && r.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
                .map(|(_, w)| w.to_string()).unwrap_or_else(|| NO_RAIL.to_string()),
            _ => NO_RAIL.to_string(),
        };
        with(deny("no_rail", why),
             json!({"charged_sats": 0, "rails_passed_over": passed, "offered": offered,
                    "wallet": {"lightning": lightning, "chain": chain, "tickets": tp.enabled, "tickets_off": tp.mainnet_off, "ln": LnPolicy::from_map(&cfg.ln).enabled}}))
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
            Offer::Ticket(acc, prepaid) => Terms::parse(acc, lightning).ok().map(|t| (t, prepaid.is_some())),
            _ => None,
        });
        let prepaid_entry = ticket.as_ref().is_some_and(|(t, beside)| *beside || t.settle == crate::ticket::Settle::OnArrival);
        let ticket = ticket.map(|(t, _)| t);
        let Some(draw) = draw else { return false };
        let task = c.task.as_deref().unwrap_or("");
        let payee = draw.payee.clone();
        // what the answer is expected to use: its charge cap, not what may leave for a ticket
        let expect_msat = (c.charge_sats.max(0) as u64).saturating_mul(1000);
        // the win a session would be opened with, as the book sizes it
        let listed = self.ticket_listed(&self.config(), &draw.payee, c.origin);
        let win_msat = crate::lottery::win_size(&draw, &tp.lottery, listed, expect_msat, self.ln_direct_to(&draw.payee)).unwrap_or(0);
        crate::lottery::choose(&crate::lottery::Choice {
            ticket_entry: ticket.is_some(), lottery_entry: true, lottery_on: tp.lottery.enabled,
            meter: tp.tasks.get(task).map_or(crate::lottery::Meter::Auto, |t| t.meter),
            // a session this process pays this origin by draws is the one that is open; else what the book holds open with the seller's node
            open: if lock(&self.draw_http).contains_key(c.origin) { Some(true) } else { self.ticket_open_kind(&payee, c.origin) },
            dearest_msat: draw.dearest_piece().unwrap_or(u64::MAX), ticket_msat: ticket.as_ref().map_or(u64::MAX, |t| t.ticket_msat),
            expect_msat, held_fits: ticket.is_some() && self.ticket_held_fits(task),
            stay_tickets: tp.lottery.stay_tickets.max(1) as u64, prepaid_entry, win_msat, min_wins: tp.lottery.min_expected_wins.max(0) as u64 })
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
            self.ln_pay_locked(&json!({"invoice": invoice.trim(), "max_sats": c.charge_sats}))
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
        let mut headers = c.headers();
        headers.push(("PAYMENT-SIGNATURE".into(), header));
        match self.wire(c.method, c.url, c.body, &headers, Self::ticket_read_timeout(tp)) {
            Ok(mut ans) => {
                let mut sink = Sink::for_call(c);
                let (head, refused) = c.head(&mut ans, &mut sink);
                let ended = match refused {
                    Some(why) => Some(format!("not read: {why}")),
                    None => read_all(ans, &mut sink),
                };
                let (_, stored, text) = sink.done();
                out = with(with(with(out, head), stored), json!({"complete": ended.is_none(), "ended": ended, UNTRUSTED_KEY: untrusted(&text, Value::Null)}));
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
        self.ticket_pay_in(c, acc, prepaid_acc, lightning, true)
    }

    /// [`Signer::ticket_pay`]. `again`: a resume (a call with a `range`) whose session ended under it before anything
    /// of it went out (the seller's places full, [`Signer::ticket_cap_full`], or the session forgotten by the seller) is
    /// made once more in another session.
    fn ticket_pay_in(&self, c: &Call, acc: &Value, prepaid_acc: Option<&Value>, lightning: &str, again: bool) -> Tried {
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
        // a seller caught charging more than it delivered gets no new session until the owner lifts the block
        let rk = hex::encode(&terms.receipt_key);
        let who = crate::seller_block::Seller { payee: &terms.terms.payee, receipt_key: &rk, origin: c.origin };
        if let Some(b) = self.seller_blocks.get(&who) {
            return Tried::Done(with(deny("seller_blocked", format!("this seller was caught charging more than it delivered ({}) and is blocked: \
                                                                       the owner can unblock it on the Spending rules page",
                                                                      b["reason"].as_str().unwrap_or_default())),
                                    json!({"seller_blocked": b["id"]})));
        }
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
            // a seller that gave no word about its earlier session a moment ago: a call that queued behind that wait, or came
            // straight after it, is told the same at once, and is not made to wait as long again, each behind the last
            if open.is_none() {
                let said = lock(&self.ticket_unanswered).get(c.origin).filter(|(at, _)| self.engine.now() - at < RESUME_RETRY_AFTER_S as f64).map(|(_, d)| d.clone());
                if let Some(d) = said {
                    break 'open Err(Tried::Done(d));
                }
            }
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
            // a session being stopped is kept here while the book holds it open (its open answers are taking their last
            // receipts, and what it leaves with the seller is not yet known): the request finds it ending and the caller
            // is told to call again, rather than a new session opening beside it without that credit
            // a session the book no longer holds open (stopped by the agent, idle, a fault) is gone
            if let Some(h) = open.as_ref().filter(|h| h.fault().is_some() || !self.ticket_session(&h.sid).is_some_and(|s| s.state == SState::Open)).cloned() {
                *open = None;
                // one stopped for over-charging blocks its seller, however its fault was found
                let (overcharged, evidence) = {
                    let m = lock_money(&h);
                    (m.overcharged || h.over_cap.load(Ordering::SeqCst), m.evidence.clone().or_else(|| lock(&h.evidence).clone()))
                };
                if overcharged {
                    self.seller_block(&h, &h.fault().unwrap_or_else(|| "over-charging".into()), evidence);
                }
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
                    // the same seller (its node and receipt key) open under another address, an alias of this shop or
                    // the one it moved from: that session is stopped, and the new one takes over its balance
                    if let Err(busy) = self.ticket_http_move(c.origin, &terms) {
                        break 'open Err(Tried::Done(busy));
                    }
                    let task = match &c.task {
                        Ok(t) => t.clone(),
                        Err(why) => break 'open Err(Tried::Next(why.clone())),
                    };
                    let o = {
                        let _g = self.lock();
                        self.ticket_open_locked(&json!({"terms": acc, "prepaid_terms": prepaid.as_ref().map(|(_, a)| *a), "task": &task, "origin": c.origin,
                                                                 "fit_sats": c.max_sats.max(0), "charge_sats": c.charge_sats.max(0)}))
                    };
                    if o["verdict"] != "allow" {
                        let rule = str_or_empty(o.get("rule"));
                        break 'open Err(if NEXT_RAIL.contains(&rule.as_str()) { Tried::Next(format!("{rule}: {}", str_or_empty(o.get("reason")))) } else { Tried::Done(o) });
                    }
                    // the offer of the prepaid entry: the one beside the held entry, or the entry itself where the
                    // seller sells prepaid tickets only
                    let prepaid_only = acc.get("extra").and_then(|e| e.get("settle")).and_then(Value::as_str) == Some(xbt402::ticket::SETTLE_ON_ARRIVAL);
                    let offer = match &prepaid {
                        Some((_, a)) => xbt402::offer::entry_offer(a),
                        None if prepaid_only => xbt402::offer::entry_offer(acc),
                        None => None,
                    }
                    .map(str::to_string);
                    let h = Arc::new(HttpSession { origin: c.origin.into(), sid: str_or_empty(o.get("session")), task: task.clone(), terms: terms.clone(),
                                                   over_cap: AtomicBool::new(false), evidence: Mutex::new(None),
                                                   prepaid: prepaid_terms.clone(), offer, base, visit: c.url.strip_prefix(c.origin).unwrap_or("/").to_string(), calls: RwLock::new(()),
                                                   paying: Mutex::new(()), order: Mutex::new(()), link: Mutex::new(Link::new(String::new(), [0u8; 32], 0)),
                                                   money: Mutex::new(Money::default()), streaming: AtomicUsize::new(0), ending: AtomicBool::new(false), refilling: AtomicBool::new(false), stalls: AtomicUsize::new(0),
                                                   used: Mutex::new(self.engine.now()), unfilled: Mutex::new(None), key_on_record: AtomicBool::new(false),
                                                   cancel_asked: Mutex::new(HashSet::new()), cap_full: AtomicBool::new(false),
                                                   forgotten: AtomicBool::new(false) });
                    // a balance the wallet left with this seller in a session it stopped (a restart, or an idle stop) is
                    // used first, not left there while a new ticket is bought
                    // and where it could not be taken over because the seller has yet to follow a prepaid ticket of that session,
                    // nothing is bought beside it. The session ends here with no seller side, so that the next call still finds
                    // the earlier one to take over
                    let resumed = match self.ticket_resume(&h) {
                        Resumed::Taken => true,
                        Resumed::Fresh => false,
                        Resumed::Wait(d) => {
                            lock(&self.ticket_unanswered).insert(c.origin.to_string(), (self.engine.now(), d.clone()));
                            let stopped = self.ticket_http_stop(&h, crate::ticket::RESUME_WAIT_WHY, Duration::ZERO);
                            break 'open Err(Tried::Done(with(d, json!({"stopped": stopped}))));
                        }
                    };
                    if !resumed {
                        if let Some(d) = self.ticket_prepaid_unfollowed(&h.terms.terms.payee, &h.sid) {
                            let stopped = self.ticket_http_stop(&h, crate::ticket::PREPAY_FOLLOW_WHY, Duration::ZERO);
                            break 'open Err(Tried::Done(with(d, json!({"stopped": stopped}))));
                        }
                    }
                    // the first pool, before the call goes on. A session that holds nothing, or that found no slot
                    // and waits, goes on where the seller offers prepaid tickets: the call buys one when it needs it
                    let filled = self.ticket_fill_by(&h, c.by, ());
                    let prepaid_now = self.ticket_session(&h.sid).is_some_and(|s| s.prepaid_now(self.engine.now()));
                    match filled {
                        Ok(n) if n > 0 => {}
                        // the seller's route is full: it sells this new buyer nothing, and the session ends unused
                        Err(d) if d["rule"] == "seller_busy" => {
                            let stopped = self.ticket_http_stop(&h, "the seller is busy", Duration::ZERO);
                            break 'open Err(Tried::Done(with(d, json!({"stopped": stopped}))));
                        }
                        _ if prepaid_now => {}
                        // a session that took over a balance with the seller pays from it: a first lock that failed (the
                        // seller still counting the earlier session's tickets, say) is tried again behind the call
                        _ if resumed => {}
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
        let mut out = {
            // shared: other requests to this seller run beside this one
            let _call = hs.calls.read().unwrap_or_else(|p| p.into_inner());
            self.ticket_request(&hs, c, &terms)
        };
        let nothing = refused_before_it_left(&out);
        // only where the cap is what ended or refused this call: one that was served all the same (on credit taken over,
        // say) goes on in its session, and the pool's next round asks again
        let by_the_cap = ["ended", "reason"].iter().any(|k| out.get(*k).and_then(Value::as_str).is_some_and(|s| s.contains("too_many_tickets")));
        let mut stopped = Value::Null;
        if hs.cap_full.swap(false, Ordering::SeqCst) && by_the_cap {
            hs.cap_full.store(true, Ordering::SeqCst);
            match self.ticket_cap_full(&hs) {
                Some(s) => stopped = s,
                None => {
                    self.ticket_refill_later(&hs);
                    return Tried::Done(out);
                }
            }
        }
        // the session ended under a resume (a call that goes on from a byte, `range`), before anything of it went out: the
        // seller's places for it were full (stopped just above), or the seller had forgotten it (`ticket_session_ended`,
        // stopped as it was told, and for that alone). A resume after a channel's outage meets either. It is made again,
        // once, in the session the next call would open. A session ended for the seller's fault (a receipt that does not
        // hold, a charge above what arrived) or stranded is never made again: the call says why. Any other call refused
        // so is told why, and the next opens another, as before
        // (the call that hears `session_unknown` is refused `ticket_session_ended`; one beside it, a refill say, may hear it
        // first and stop the session, and this call is then refused as the session stops, `ticket_session`)
        let forgotten = matches!(out.get("rule").and_then(Value::as_str), Some("ticket_session_ended" | "ticket_session")) && hs.forgotten.load(Ordering::SeqCst);
        let ended_under_it = !stopped.is_null() || forgotten;
        if ended_under_it && nothing && again && c.range.is_some() {
            self.ticket_audit("ticket_session_again", json!({"session": hs.sid, "dest": format!("ln:{}", hs.terms.terms.payee),
                                                             "why": str_or_empty(out.get("rule"))}));
            return match self.ticket_pay_in(c, acc, prepaid_acc, lightning, false) {
                Tried::Done(mut v) => {
                    if v.is_object() && !stopped.is_null() {
                        v["session_stopped"] = stopped;
                    }
                    Tried::Done(v)
                }
                next => next,
            };
        }
        if !stopped.is_null() {
            if out.is_object() {
                out["session_stopped"] = stopped;
            }
            return Tried::Done(out);
        }
        // the pool is filled again behind the call
        self.ticket_refill_later(&hs);
        Tried::Done(out)
    }

    /// The seller refused a lock of the session `too_many_tickets`, and the call has ended: the places it gives the
    /// session are taken, and every later call to it would be refused the same until those tickets lapse (after a
    /// channel's outage, by tickets whose payment is still on its way, or failed without the wallet hearing). The
    /// session is stopped, its seller asked to cancel its tickets that were never released, and the next call (a
    /// resume of the same file) opens another. `None`: left as it is (said in the audit).
    ///
    /// The seller is never left unpaid for what it served. A ticket whose secret has left (released), or may have
    /// (retired), is never named for a cancel; and where the wallet's own count has the session drawing more than the
    /// tickets released so far cover, nothing is cancelled and the session is kept: its next call releases what is owed
    /// first, as any call does. Nor is a session stopped under an answer still being read beside this call.
    fn ticket_cap_full(&self, hs: &Arc<HttpSession>) -> Option<Value> {
        let owed = {
            let m = lock_money(hs);
            m.consumed.saturating_sub(m.absorbed_mark).saturating_add(m.reserved).saturating_sub(m.acct.balance())
        };
        let streaming = hs.streaming.load(Ordering::SeqCst);
        if owed > 0 || streaming > 0 {
            self.ticket_audit("ticket_cap_full_kept", json!({"session": hs.sid, "dest": format!("ln:{}", hs.terms.terms.payee), "owed_msat": owed.to_string(),
                                                            "streaming": streaming}));
            return None;
        }
        hs.cap_full.store(false, Ordering::SeqCst);
        let why = "the seller holds as many tickets as it gives the session (too_many_tickets): those never released were cancelled, and the \
                   next call opens another session";
        Some(self.ticket_http_stop_with(hs, why, CANCEL_WAIT, false))
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
        self.ticket_can_lock(&hs.terms.terms.payee, &hs.sid)?;
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
        if lock_link(hs).seller_sid.is_empty() {
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
        let why = FORGOTTEN_WHY;
        let first = {
            let mut m = lock_money(hs);
            let first = m.fault.is_none();
            m.fault.get_or_insert_with(|| why.to_string());
            first
        };
        // the session ends for this alone only if nothing was wrong with it before, and no stop of another (the caller's
        // own, a budget's) had begun: a resume is never made again past a stop someone asked for
        if first && !hs.ending.load(Ordering::SeqCst) {
            hs.forgotten.store(true, Ordering::SeqCst);
        }
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
    /// The seller's id of the session open with `origin`, if one is. While a call is opening one: none,
    /// or with `wait`, the one it opened.
    fn ticket_seller_sid(&self, origin: &str, wait: bool) -> Option<String> {
        let slot = lock(&self.ticket_http).get(origin).cloned()?;
        let open = if wait { lock(&slot.open) } else { slot.open.try_lock().ok()? };
        let sid = lock_link(open.as_ref()?).seller_sid.clone();
        (!sid.is_empty()).then_some(sid)
    }

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
            // the seller issues held tickets only to a session that has paid it something: the session's next
            // ticket is a prepaid one, and it holds after that (the seller's word moves no money: it only orders
            // the wallet's own steps, each under the owner's rules)
            if status == 402 && code == "prepaid_first" {
                return match self.ticket_paid_first(&hs.sid) {
                    Ok(true) => with(refusal("ticket_prepaid_first", "the seller issues held tickets after one prepaid ticket has been paid: the session buys \
                                                                       one first"), json!({"session": hs.sid})),
                    Ok(false) => refusal("ticket_seller", "the seller issues held tickets only after a prepaid one, and its terms offer none"),
                    Err(e) => refusal("ticket", e.msg),
                };
            }
            // the seller's service is full: nothing was sold
            if let Some(d) = (status == 503).then(|| seller_busy(v)).flatten() {
                return d;
            }
            // every place the seller gives the session is taken (after an outage, by tickets whose payment is still on
            // its way or failed without the wallet hearing yet): dealt with once the call has ended
            if status == 402 && code == "too_many_tickets" {
                hs.cap_full.store(true, Ordering::SeqCst);
            }
            refusal("ticket_seller", format!("the seller refused the lock: HTTP {status} {code}"))
        };
        if !lock_link(hs).seller_sid.is_empty() {
            body["session"] = lock_link(hs).seller_sid.clone().into();
            return match self.ticket_call(hs, "lock", &body, true) {
                Ok((200, v, _)) => Ok(v),
                Ok((status, v, _)) => Err(refused(status, &v)),
                Err(e) => Err(refusal("ticket_seller", format!("the seller gave no answer to the lock: {}", e.msg))),
            };
        }
        let url = format!("{}/lock", hs.base);
        body["path"] = hs.visit.clone().into();
        let raw = body.to_string().into_bytes();
        // the read timeout for the whole of it, head and body, as every session call ([`Signer::ticket_call_within`])
        let timeout = Self::ticket_read_timeout(&self.ticket_policy());
        let by = Instant::now() + timeout;
        let sent = self.wire_by("POST", &url, &raw, &[("Content-Type".into(), "application/json".into())], timeout, timeout);
        let (status, v) = match sent.and_then(|a| Ok((a.status, a.read_small_by(SMALL_BODY, by)?))) {
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
        if let Err(e) = self.ticket_set_http(&hs.sid, SellerSession { id: seller_sid.clone(), key, base: hs.base.clone(), receipt_key: String::new(), identified: false }) {
            return Err(refusal("ticket", e.msg));
        }
        {
            let mut link = lock_link(hs);
            link.seller_sid = seller_sid;
            link.key = Zeroizing::new(key);
        }
        // a seller that gives its buyers accounts asks to recognise them: told who this wallet is to it, unless the owner said not to
        if self.identify_wanted(hs) {
            if let Err(why) = self.ticket_identify(hs) {
                self.engine.audit.append(json!({"type": "identify_failed", "origin": hs.origin, "why": why}));
            }
        }
        Ok(v)
    }

    /// Whether to tell this seller who this wallet is: its terms ask (`identify`), and the owner has
    /// not chosen to stay anonymous there (docs/BUYER-ACCOUNTS.md).
    fn identify_wanted(&self, hs: &HttpSession) -> bool {
        identify_asked(&hs.terms.accepted) && !self.anonymous_at(&hs.origin, &hs.terms.terms.payee)
    }

    /// The sellers the owner stays anonymous at, by origin (`identity.json`).
    pub(crate) fn anonymous_origins(&self) -> Vec<String> {
        std::fs::read_to_string(self.run.join(IDENTITY_FILE)).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|v| v.get("anonymous").and_then(Value::as_array).cloned()).unwrap_or_default()
            .iter().filter_map(|o| o.as_str().map(normalize_dest)).collect()
    }

    fn anonymous_at(&self, origin: &str, payee: &str) -> bool {
        // a choices file that is there and cannot be read keeps the wallet anonymous everywhere: failing closed
        self.identity_damaged() || self.anonymous_listed(origin, Some(payee))
    }

    /// Whether the owner chose to stay anonymous at this shop. "This shop" is the seller: its address
    /// as chosen, or any other address of the same node, as the sessions on the book show them. An
    /// address no session has reached yet is known only by itself.
    pub(crate) fn anonymous_listed(&self, origin: &str, payee: Option<&str>) -> bool {
        let list = self.anonymous_origins();
        let origin = normalize_dest(origin);
        if list.contains(&origin) {
            return true;
        }
        if list.is_empty() {
            return false;
        }
        let seen = self.ticket_sellers_seen();
        let nodes: HashSet<&str> = seen.iter().filter(|(o, _)| normalize_dest(o) == origin).map(|(_, p)| p.as_str()).chain(payee).collect();
        seen.iter().any(|(o, p)| nodes.contains(p.as_str()) && list.contains(&normalize_dest(o)))
    }

    /// The owner's choices file is there and cannot be read as one (`identity.json`).
    pub(crate) fn identity_damaged(&self) -> bool {
        let path = self.run.join(IDENTITY_FILE);
        match std::fs::read_to_string(&path) {
            Ok(t) => serde_json::from_str::<Value>(&t).ok().and_then(|v| v.get("anonymous").and_then(Value::as_array).map(|a| a.iter().all(Value::is_string))) != Some(true),
            Err(e) => e.kind() != std::io::ErrorKind::NotFound,
        }
    }


    /// `identity_set`: stay anonymous at a seller (`anonymous: true`), or let it recognise this
    /// wallet. Read again by every session that opens after it.
    pub(crate) fn identity_set(&self, p: &Value) -> Value {
        let origin = match origin_of(&str_or_empty(p.get("origin"))) {
            Ok(o) => normalize_dest(&o),
            Err(e) => return deny("dest", e.msg),
        };
        let Some(anonymous) = p.get("anonymous").and_then(Value::as_bool) else {
            return deny("identity", "anonymous is true or false");
        };
        const WHY: &str = "the owner chose to stay anonymous at this seller";
        let written = {
            let _one = lock(&self.identity_write);
            // not written over: the choices it holds would be lost, and every seller would know the wallet again
            if self.identity_damaged() {
                Err(format!("{IDENTITY_FILE} is there and cannot be read, so this choice was not saved: the wallet stays anonymous at every seller until it is mended or removed"))
            } else {
                let mut all = self.anonymous_origins();
                if anonymous {
                    all.retain(|o| o != &origin);
                    all.push(origin.clone());
                } else {
                    // the shop is the seller: every address of it the choice was made under
                    let seen = self.ticket_sellers_seen();
                    let nodes: HashSet<&str> = seen.iter().filter(|(o, _)| normalize_dest(o) == origin).map(|(_, n)| n.as_str()).collect();
                    let same: HashSet<String> = seen.iter().filter(|(_, n)| nodes.contains(n.as_str())).map(|(o, _)| normalize_dest(o)).collect();
                    all.retain(|o| o != &origin && !same.contains(o));
                }
                all.sort();
                write_private(&self.run.join(IDENTITY_FILE), &json!({"anonymous": all}).to_string()).map(|()| all).map_err(|e| e.msg)
            }
        };
        // a session open with that seller now (at this address or another of the same seller) may have told it who the
        // wallet is: stopped, so that nothing more is served through it as the owner's account. Whether the choice could
        // be saved or not: the owner asked for it, and the wallet stays anonymous either way
        let stopped = if anonymous { self.ticket_stop_sessions_at(&origin, WHY) } else { vec![] };
        let about = json!({"sessions_stopped": stopped.len(), "stopped": stopped});
        match written {
            Ok(all) => with(json!({"ok": true, "anonymous": all}), about),
            Err(why) => with(deny("identity", why), about),
        }
    }

    /// Stop the sessions open with the seller at `origin`, and with the same seller under any other
    /// address: its node, as a session open there now or one on the book says. What each stop left.
    fn ticket_stop_sessions_at(&self, origin: &str, why: &str) -> Vec<Value> {
        let slots: Vec<Arc<Slot>> = lock(&self.ticket_http).values().cloned().collect();
        let open: Vec<Arc<HttpSession>> = slots.iter().filter_map(|slot| slot.open.lock().unwrap_or_else(|p| p.into_inner()).clone()).collect();
        let mut payees: HashSet<String> = open.iter().filter(|h| normalize_dest(&h.origin) == origin).map(|h| h.terms.terms.payee.clone()).collect();
        payees.extend(self.ticket_sellers_seen().into_iter().filter(|(o, _)| normalize_dest(o) == origin).map(|(_, payee)| payee));
        open.iter().filter(|h| payees.contains(&h.terms.terms.payee)).map(|h| {
            let r = self.ticket_http_stop(h, why, Duration::ZERO);
            json!({"session": r["session"], "origin": h.origin, "left_with_seller_msat": r["left_with_seller_msat"], "cancel_asked": r["cancel_asked"], "still_locked": r["still_locked"]})
        }).collect()
    }

    /// Tell the seller who this wallet is to it, for this session: its key for this seller alone,
    /// and a signature over the seller's receipt key and this session's id (`identify`).
    fn ticket_identify(&self, hs: &HttpSession) -> std::result::Result<(), String> {
        let receipt_key = hex::encode(&hs.terms.receipt_key);
        let sk = self.buyer_key(&receipt_key).map_err(|e| e.msg)?;
        let session = lock_link(hs).seller_sid.clone();
        let msg = xbt402::ticket::buyer_message(&receipt_key, &session);
        let secp = xbt402::xbt_primitives::secp256k1::Secp256k1::signing_only();
        let pubkey = xbt402::xbt_primitives::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let body = json!({"buyer": hex::encode(pubkey.serialize()), "sig": hex::encode(xbt402::xbt_primitives::ecdsa::sign(&sk, &msg))});
        // on disk before it goes: an answer that is lost, refused or cut by a crash may still have told the seller
        self.ticket_mark_identified(&hs.sid).map_err(|e| format!("the wallet could not note that it tells this seller who it is, so it did not: {}", e.msg))?;
        match self.ticket_call(hs, "identify", &body, false) {
            Ok((200, _, _)) => Ok(()),
            Ok((status, v, _)) => Err(format!("the seller refused identify: HTTP {status} {}", protocol_code(v.get("error")))),
            Err(e) => Err(e.msg),
        }
    }

    /// Buy one prepaid ticket for the session and show the seller its preimage: the seller's
    /// invoice for a hash of its own, every check and rule of the book ([`Signer::ticket_prepay`]),
    /// the payment, then `release` with the preimage the wallet's node got for it. Called with the
    /// session's `paying` lock held, so one is bought at a time.
    fn ticket_buy_prepaid(&self, hs: &HttpSession, spent: &mut Spent) -> std::result::Result<(), Value> {
        // nothing is paid to a seller found at fault, by this answer or one beside it: asked here, after the node's own
        // check, and again just before the payment
        // or the session is being stopped: nothing more is bought for it
        let at_fault = || hs.fault().map(|why| self.ticket_fault(hs, &why)).or_else(|| hs.ending.load(Ordering::SeqCst).then(stopping_refusal));
        if let Some(d) = at_fault() {
            return Err(d);
        }
        // the call's max_sats bounds what leaves for it, a whole ticket included: a smaller ticket is asked for where
        // the seller's own does not fit and its terms allow one that does, and the call is refused before anything
        // is asked of the seller where none fits
        let size = self.ticket_prepaid_size(&hs.sid, spent.left(), spent.charge_sats);
        spent.room(size.map(|(_, face, booked)| (face, booked)), true)?;
        let asked = size.map(|(m, _, _)| m).filter(|m| self.ticket_session(&hs.sid).is_some_and(|s| s.prepaid_msat != *m));
        // the wallet's own node first: no invoice is asked for that the node could not then pay
        self.ticket_can_lock(&hs.terms.terms.payee, &hs.sid)?;
        if let Some(d) = at_fault() {
            return Err(d);
        }
        // by the seller's offer first, where its terms name one: nothing is asked of the seller but its session
        let by_offer = match &hs.offer {
            Some(offer) if self.ticket_policy().offers => self.ticket_prepay_by_offer(hs, offer, asked),
            _ => None,
        };
        let r = match by_offer {
            Some(r) => r,
            None => {
                let mut body = json!({"version": xbt402::ticket::VERSION, "settle": xbt402::ticket::SETTLE_ON_ARRIVAL, "count": 1});
                // a seller that ignores the size asked for invoices its own, and the book refuses that invoice unpaid
                if let Some(m) = asked {
                    body["ticketMsat"] = m.to_string().into();
                }
                let answer = self.ticket_lock_call(hs, body)?;
                let Some(first) = answer.get("tickets").and_then(Value::as_array).and_then(|a| a.first()) else {
                    return Err(refusal("ticket_seller", "the seller issued no invoice for a prepaid ticket"));
                };
                let mut p = json!({"session": hs.sid, "hash": first.get("hash"), "invoice": first.get("invoice")});
                if let Some(m) = asked {
                    p["ticket_msat"] = m.to_string().into();
                }
                if let Some(d) = at_fault() {
                    return Err(d);
                }
                self.ticket_prepay(&p)
            }
        };
        // what the book booked for the ticket left with the call, however its payment ended: paid, not final yet, or
        // settled without the preimage that proves it (both stay booked as spent). Counted before either is refused, so
        // that the call says it among what it charged. A payment that failed books nothing
        spent.booked_sats = spent.booked_sats.saturating_add(py_int(r.get("charged_sats")).unwrap_or(0));
        if r["verdict"] == "pending" {
            // paid without the preimage that proves it: booked as spent, nothing can be shown to the seller, and nothing more
            // is paid in this session
            if str_or_empty(r.get("rule")).ends_with("_unproven") {
                return Err(self.ticket_fault(hs, "the wallet's node shows a prepaid ticket paid without the preimage of its hash: it is booked as spent, and nothing can be shown to the seller"));
            }
            // booked, and neither paid nor failed by the node's word: nothing more is paid in this session. Not the seller's
            // fault (a preimage slow on its way back through a hop, say): a later session takes up the ticket's credit with
            // this seller once the node shows it paid ([`Signer::ticket_resumable`]), where a fault would strand it. The
            // caller's answer says what is booked for it (`spent`, counted above)
            let why = crate::ticket::PREPAY_PENDING_WHY;
            // the owner's record of it, in case the seller is what holds the payment ([`Signer::ticket_prepaid_overdue_tick`])
            self.ticket_audit("ticket_prepay_pending", json!({"session": hs.sid, "origin": hs.origin, "dest": format!("ln:{}", hs.terms.terms.payee), "hash": str_or_empty(r.get("hash")),
                                                              "reason": why, "account": hs.public()}));
            let stopped = self.ticket_http_stop(hs, why, Duration::ZERO);
            return Err(with(refusal("ticket_prepay_pending", why), json!({"session": hs.sid, "hash": str_or_empty(r.get("hash")), "stopped": stopped})));
        }
        if r["verdict"] != "allow" {
            return Err(r);
        }
        let (Some(secret), hash) = (r.get("ticket_secret").and_then(Value::as_str), str_or_empty(r.get("hash"))) else {
            return Err(refusal("ticket", "the book paid a prepaid ticket and returned no preimage"));
        };
        {
            let mut m = lock_money(hs);
            let ticket_msat = crate::ticket::outside_u64(r.get("ticket_msat")).unwrap_or(0);
            m.acct.released(ticket_msat);
            m.pending = Some((hash.clone(), Zeroizing::new(secret.to_string())));
            spent.released_msat = spent.released_msat.saturating_add(ticket_msat);
        }
        spent.hashes.push(hash);
        spent.prepaid += 1;
        self.ticket_deliver(hs, Instant::now() + Self::ticket_read_timeout(&self.ticket_policy()))
    }

    /// A prepaid ticket by the seller's offer: the seller's side of the session first (a lock by
    /// offer makes it where there is none yet, and issues no invoice), then the payment with the
    /// note that names that session ([`Signer::ticket_pay_by_offer`]). `None`: nothing was paid,
    /// and the ticket is bought by the seller's invoice.
    fn ticket_prepay_by_offer(&self, hs: &HttpSession, offer: &str, msat: Option<u64>) -> Option<Value> {
        if lock_link(hs).seller_sid.is_empty() {
            let body = json!({"version": xbt402::ticket::VERSION, "settle": xbt402::ticket::SETTLE_ON_ARRIVAL, "by": "offer"});
            if let Err(d) = self.ticket_lock_call(hs, body) {
                self.ticket_offer_passed(hs, &str_or_empty(d.get("rule")), str_or_empty(d.get("reason")));
                return None;
            }
        }
        let (key, seller_session) = {
            let link = lock_link(hs);
            (Zeroizing::new(*link.key), link.seller_sid.clone())
        };
        if seller_session.is_empty() {
            self.ticket_offer_passed(hs, "ticket_seller", "the seller's lock by offer named no session".into());
            return None;
        }
        // a seller found at fault meanwhile, or a session being stopped, is paid nothing: the caller asks again and refuses
        if hs.fault().is_some() || hs.ending.load(Ordering::SeqCst) {
            return None;
        }
        let by = crate::ticket_rail::OfferWay { offer, key: &key, seller_session: &seller_session };
        self.ticket_pay_by_offer(&hs.sid, &by, None, false, msat)
    }

    /// The seller's offer left for its invoice before the payment by offer was tried, and why:
    /// written down as [`Signer::ticket_pay_by_offer`] writes its own.
    fn ticket_offer_passed(&self, hs: &HttpSession, rule: &str, why: String) {
        self.ticket_audit("ticket_offer_passed", json!({"session": hs.sid, "dest": format!("ln:{}", hs.terms.terms.payee), "rule": rule, "reason": why,
                                                        "win": Value::Null, "then": "the seller's invoice"}));
    }

    /// How many hashes the session's pool wants now, by the book (0 when the book cannot be read:
    /// nothing is offered on a guess).
    fn ticket_want(&self, sid: &str) -> usize {
        self.ticket_store().ok().and_then(|g| g.as_ref().and_then(|st| st.book.sessions.get(sid).map(|s| st.book.want(s, self.engine.now())))).unwrap_or(0)
    }

    /// Fill the pool behind a call, one refill of a session at a time.
    fn ticket_refill_later(&self, hs: &Arc<HttpSession>) {
        if hs.ending.load(Ordering::SeqCst) || self.ticket_want(&hs.sid) == 0 || hs.fault().is_some() {
            return;
        }
        let Some(guard) = Refilling::take(hs.clone()) else { return };
        let Some(me) = self.me.get().and_then(std::sync::Weak::upgrade) else { return };
        let hs2 = hs.clone();
        // the flag goes with the thread, and is cleared however the thread ends, a panic included
        let _ = std::thread::Builder::new().name("ticket-refill".into()).spawn(move || {
            let _guard = guard;
            // a refusal here is the next release's to report: it finds no ticket and says why. A release that came
            // while a round was out has left the pool at its mark again (with a pool of 2, every release does):
            // another round, a few at most, and none after a round that locked nothing
            for _ in 0..4 {
                if !matches!(me.ticket_fill(&hs2), Ok(n) if n > 0) || me.ticket_want(&hs2.sid) == 0 {
                    break;
                }
            }
        });
    }

    /// A seq for one request to the session's seller, with the seller's session id and key: taken
    /// under `link`, which is let go at once, so that the request goes out beside the others.
    fn seq_take(&self, hs: &HttpSession) -> Result<(u64, String, Zeroizing<[u8; 32]>)> {
        // within the seller's window of the lowest seq on its way, so that the seller can take it
        let until = Instant::now() + SEQ_WAIT;
        let mut link = loop {
            let link = lock_link(hs);
            // a seq out longer than that has reached the seller (its answer is slow to come) or was lost
            let low = link.sent.iter().filter(|(_, at)| at.elapsed() < SEQ_ARRIVED).map(|(s, _)| *s).min();
            if low.is_none_or(|l| link.next_seq < l.saturating_add(hs.terms.seq_window)) || Instant::now() >= until {
                break link;
            }
            drop(link);
            std::thread::sleep(Duration::from_millis(1));
        };
        if link.seller_sid.is_empty() {
            return Err(err("ticket_session", "the session has no seller side yet"));
        }
        let seq = link.next_seq;
        link.next_seq = seq.saturating_add(1);
        link.sent.insert(seq, Instant::now());
        Ok((seq, link.seller_sid.clone(), link.key.clone()))
    }

    /// The seller answered `seq` with `bad_seq` and named the seq it expects (`next`): the seq the
    /// request goes again with. Ahead of `seq`: a fresh one past it (the seller lost its counters,
    /// or an answer of ours was lost: a seq only orders requests, and costs nothing). Behind it, for
    /// a request still on its way: the same, shortly. Behind it, for one that no request holds (it
    /// was given up): that one, taken over. `None`: the same seq, after a short wait.
    fn seq_bad(&self, hs: &HttpSession, seq: u64, next: u64) -> Option<u64> {
        let mut link = lock_link(hs);
        // below the next one, or refused inside the seller's window (taken already: an answer of ours was lost)
        if next > seq || seq - next < hs.terms.seq_window {
            link.sent.remove(&seq);
            let s = link.next_seq.max(next);
            link.next_seq = s.saturating_add(1);
            link.sent.insert(s, Instant::now());
            return Some(s);
        }
        if next < seq && !link.sent.contains_key(&next) {
            link.sent.remove(&seq);
            link.sent.insert(next, Instant::now());
            // the seq given up here is the next one handed out again, where none was handed out after it
            if link.next_seq == seq.saturating_add(1) {
                link.next_seq = seq;
            }
            return Some(next);
        }
        None
    }

    /// The request `seq` has its answer, or will not have one: the seq is no longer on its way.
    fn seq_done(&self, hs: &HttpSession, seq: u64) {
        lock_link(hs).sent.remove(&seq);
    }

    /// One authenticated request to a session endpoint, with its own `seq`. Returns the status, the
    /// JSON body and the receipt (or why there is none). With `absorb`, a valid receipt's totals
    /// are taken into the wallet's count ([`Money::take`]). `link` is held only to take the seq: the
    /// request goes out beside the session's others.
    fn ticket_call(&self, hs: &HttpSession, what: &str, body: &Value, absorb: bool) -> Result<(u16, Value, std::result::Result<Receipt, String>)> {
        self.ticket_call_at(hs, what, body, absorb).map(|(status, v, r, _)| (status, v, r))
    }

    /// [`Signer::ticket_call`], with the epoch of the wallet's count ([`Money::epoch`]) when the
    /// request last left: what orders its receipt against the totals the wallet holds.
    fn ticket_call_at(&self, hs: &HttpSession, what: &str, body: &Value, absorb: bool) -> Result<(u16, Value, std::result::Result<Receipt, String>, u64)> {
        self.ticket_call_within(hs, what, body, absorb, None)
    }

    /// [`Signer::ticket_call_at`], waiting for the seller's answer no longer than `within`
    /// where given (else the owner's `tickets.read_timeout_s`): for the whole of it, head and body,
    /// not only for each read, so a seller that sends a byte at a time is cut off by then.
    fn ticket_call_within(&self, hs: &HttpSession, what: &str, body: &Value, absorb: bool, within: Option<Duration>)
                          -> Result<(u16, Value, std::result::Result<Receipt, String>, u64)> {
        if !self.ticket_may_reach(&hs.origin, &hs.task) {
            return Err(err("allowlist", format!("destination not on allowlist: {}", hs.origin)));
        }
        let url = format!("{}/{what}", hs.base);
        let raw = body.to_string().into_bytes();
        let timeout = within.unwrap_or_else(|| Self::ticket_read_timeout(&self.ticket_policy()));
        let digest = request_digest_v2("POST", &url, &raw);
        // held to the end: the answer is read whole here
        let _order = lock_order(hs);
        let (mut seq, sid, key) = self.seq_take(hs)?;
        let deadline = Instant::now() + SEQ_WAIT;
        // the whole call, head and body and any resend after a bad_seq, by `timeout` from when it first leaves
        let by = Instant::now() + timeout;
        loop {
            let auth = xbt402::ticket::request_auth(&key, &sid, seq, "", "", &digest);
            let header = b64json(&payment_payload(&hs.terms.accepted, &json!({"session": sid, "seq": seq, "auth": auth})));
            let sent_epoch = lock_money(hs).epoch;
            let left = by.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
            let read = self.wire_by("POST", &url, &raw, &[("Content-Type".into(), "application/json".into()), ("PAYMENT-SIGNATURE".into(), header)], timeout, left)
                .and_then(|ans| {
                    let (status, pr) = (ans.status, ans.header("PAYMENT-RESPONSE").map(str::to_string));
                    ans.read_small_by(SMALL_BODY, by).map(|b| (status, pr, serde_json::from_slice::<Value>(&b).unwrap_or(Value::Null)))
                });
            let (status, payment_response, v) = match read {
                Ok(x) => x,
                Err(e) => {
                    // the seq is used up once the request has left, answered or not
                    self.seq_done(hs, seq);
                    return Err(e);
                }
            };
            let receipt = Receipt::read(payment_response.as_deref(), &hs.terms.receipt_key, &sid, seq, &digest, status);
            if receipt.is_err() && status == 402 && v.get("error").and_then(Value::as_str) == Some("bad_seq") && Instant::now() < deadline.min(by) {
                if let Some(n) = v.get("nextSeq").and_then(Value::as_u64) {
                    match self.seq_bad(hs, seq, n) {
                        Some(s) => seq = s,
                        None => std::thread::sleep(Duration::from_millis(10)),
                    }
                    continue;
                }
            }
            self.seq_done(hs, seq);
            if receipt.is_err() && status == 402 && v.get("error").and_then(Value::as_str) == Some("bad_seq") {
                return Err(err("ticket_seller", "the seller keeps answering bad_seq"));
            }
            if receipt.is_ok() && !hs.key_on_record.load(Ordering::SeqCst) && self.ticket_note_receipt_key(&hs.sid, &hex::encode(&hs.terms.receipt_key)) {
                hs.key_on_record.store(true, Ordering::SeqCst);
            }
            if let (true, Ok(r)) = (absorb, &receipt) {
                let mut m = lock_money(hs);
                let outstanding = m.pending.is_some();
                if let Err(why) = m.take(r, 0, outstanding, Some(sent_epoch)) {
                    m.fault.get_or_insert(why);
                }
            }
            return Ok((status, v, receipt, sent_epoch));
        }
    }

    /// Stop a session this process holds open with the seller of `terms` under an origin other than
    /// `origin`, so that a session opened at `origin` takes over its balance ([`Signer::ticket_resume`]).
    /// `Err`: that session is in use by another call right now, which is told to come back.
    fn ticket_http_move(&self, origin: &str, terms: &PayTerms) -> std::result::Result<(), Value> {
        let others: Vec<Arc<Slot>> = lock(&self.ticket_http).iter().filter(|(o, _)| o.as_str() != origin).map(|(_, s)| s.clone()).collect();
        for slot in others {
            // never waited for: a call through the other name may be waiting for this one's place
            let Ok(mut open) = slot.open.try_lock() else {
                return Err(refusal("ticket_busy", "a call to the same seller under another address is opening a session: call again"));
            };
            let Some(h) = open.as_ref().filter(|h| h.terms.same_seller(terms)).cloned() else { continue };
            let Ok(busy) = h.calls.try_write() else {
                return Err(refusal("ticket_busy", "the same seller is being paid under another address right now: call again when that call ends"));
            };
            drop(busy);
            *open = None;
            self.ticket_http_stop(&h, "the same seller is reached under another address", Duration::ZERO);
        }
        Ok(())
    }

    /// Take over the seller side of the newest session the wallet stopped with this seller in the
    /// last day ([`Signer::ticket_resumable_all`]) where the seller still holds a balance in it, at the
    /// address `hs` reaches the seller by now: the seller's `status` must be signed with the receipt
    /// key of its terms now, credit exactly what the wallet's own book says left the wallet in that
    /// seller session, and spend no more than that. Otherwise `hs` starts with nothing of it.
    /// `true`: taken over.
    fn ticket_resume(&self, hs: &HttpSession) -> Resumed {
        let receipt_key = hex::encode(&hs.terms.receipt_key);
        let candidates = self.ticket_resumable_all(&hs.terms.terms.payee, &receipt_key, &hs.origin, &hs.sid);
        let waiting = format!("resume:{}:{receipt_key}", hs.terms.terms.payee);
        let empty = |found: &crate::ticket_rail::Resumable| format!("empty:{}:{}", found.http.id, found.sent);
        // a seller session this process still holds for a session of its own, whatever the book says of that session (an
        // idle stop, with its answer still open): that session's to spend, and its tickets are not this one's to cancel
        let held_here = self.ticket_seller_sessions_held(&hs.sid);
        let mut silent = None;
        let asked = candidates.iter().filter(|found| found.sent > 0 && !held_here.contains(&found.http.id) && !lock(&self.ticket_cancel_tried).contains(&empty(found))).take(RESUME_MOST_ASKED);
        for found in asked {
            match self.ticket_resume_one(hs, found, &receipt_key, &empty(found)) {
                Asked::Taken => {
                    lock(&self.ticket_late_tries).remove(&waiting);
                    return Resumed::Taken;
                }
                Asked::No => {}
                // already waited out, and named: no one is held to it twice. It is asked again each time all the same
                Asked::Unanswered if lock(&self.ticket_cancel_tried).contains(&format!("unanswered:{}", found.http.id)) => {}
                // the same seller: another of its sessions would wait as long
                Asked::Unanswered => {
                    silent = Some(found);
                    break;
                }
            }
        }
        let Some(found) = silent else {
            lock(&self.ticket_late_tries).remove(&waiting);
            return Resumed::Fresh;
        };
        // nothing is bought beside a credit the seller will not speak of, for as long as it may yet speak; then the buyer
        // is not held to it any longer, and the owner's record names what may be left. A later session asks again
        let now = self.engine.now();
        let first = lock(&self.ticket_late_tries).entry(waiting.clone()).or_insert((0, now)).1;
        if now - first < RESUME_UNANSWERED_S {
            return Resumed::Wait(with(refusal("ticket_seller_unanswered", "the seller gave no signed answer about the credit an earlier session left with it: nothing was \
                                                                           bought beside it; call again in a moment"),
                                      json!({"session": hs.sid, "retry_after_s": RESUME_RETRY_AFTER_S})));
        }
        lock(&self.ticket_late_tries).remove(&waiting);
        lock(&self.ticket_cancel_tried).insert(format!("unanswered:{}", found.http.id));
        self.ticket_audit("ticket_left_with_seller", json!({"session": found.newest, "seller_session": found.http.id, "dest": format!("ln:{}", hs.terms.terms.payee),
                                                            "origin": hs.origin, "left_msat": Value::Null, "sent_msat": found.sent.to_string(),
                                                            "why": "the seller gave no signed answer about it: a new session starts beside it, and the next one asks this one first"}));
        Resumed::Fresh
    }

    /// The seller's signed `status` for the seller session `hs` now names, tried a few times within a
    /// bound. `Ok(None)`: the seller has forgotten that session. `Err`: no signed answer.
    fn ticket_resume_status(&self, hs: &HttpSession) -> std::result::Result<Option<Receipt>, ()> {
        for i in 0..RESUME_STATUS_TRIES {
            if i > 0 {
                std::thread::sleep(Duration::from_millis(100 * (1 << i)));
            }
            match self.ticket_call_within(hs, "status", &json!({}), false, Some(RESUME_STATUS_WAIT)) {
                Ok((200, _, Ok(r), _)) => return Ok(Some(r)),
                Ok((_, v, _, _)) if protocol_code(v.get("error")) == "session_unknown" => return Ok(None),
                _ => {}
            }
        }
        Err(())
    }

    fn ticket_resume_one(&self, hs: &HttpSession, found: &crate::ticket_rail::Resumable, receipt_key: &str, empty: &str) -> Asked {
        let sent = found.sent;
        // the seller as it is reached now: its id and key, at this call's address. Its receipt key is on record once it has signed
        let old = SellerSession { base: hs.base.clone(), receipt_key: receipt_key.to_string(), ..found.http.clone() };
        let old_id = old.id.clone();
        // a seller session the wallet said who it is in, where the owner now stays anonymous: the seller still knows
        // the wallet by it, so it is not taken over. Its credit is given up where the owner's choice is known; a choices
        // file that cannot be read only holds it back, since mending the file brings it back
        if old.identified {
            let damaged = self.identity_damaged();
            let listed = !damaged && self.anonymous_listed(&hs.origin, Some(&hs.terms.terms.payee));
            if damaged || listed {
                let given_up = listed && self.ticket_give_up_seller_session(&old.id).is_ok();
                self.ticket_audit("ticket_resume_skipped", json!({"session": hs.sid, "seller_session": old.id, "origin": hs.origin,
                                                                  "dest": format!("ln:{}", hs.terms.terms.payee), "released_msat": sent.to_string(), "credit_given_up": given_up,
                                                                  "why": if damaged { "the owner's choices file cannot be read" } else { "the owner stays anonymous here now, and the seller knows this wallet in that session" }}));
                return Asked::No;
            }
        }
        {
            let mut link = lock_link(hs);
            link.seller_sid = old.id.clone();
            link.key = Zeroizing::new(old.key);
            link.next_seq = 0;
        }
        let forget = || {
            let mut link = lock_link(hs);
            *link = Link::new(String::new(), [0u8; 32], 0);
            drop(link);
            let mut m = lock_money(hs);
            m.acct = Account::default();
            m.epoch = m.epoch.saturating_add(1);
            m.fault = None;
        };
        // a signed answer first: only that shows this is the seller that session paid, whatever key its terms name. Then the
        // prepaid tickets of earlier sessions there that the node settled after their call are shown to it, so that its
        // count is the book's (it credits them when shown, or later by its own sweep)
        // `session_unknown` cannot be signed: from the address the session was opened at, the seller has forgotten it, so
        // it holds nothing to come back for and uses up no more asks. From another, it says nothing of that session
        let forgotten = || {
            if found.http.base != hs.base {
                return Asked::Unanswered;
            }
            if self.ticket_give_up_seller_session(&old_id).is_ok() {
                self.ticket_audit("ticket_seller_forgot", json!({"session": hs.sid, "seller_session": old_id, "origin": hs.origin, "sent_msat": sent.to_string()}));
            }
            Asked::No
        };
        let first = match self.ticket_resume_status(hs) {
            Ok(Some(r)) => r,
            Ok(None) => {
                forget();
                return forgotten();
            }
            Err(()) => {
                forget();
                return Asked::Unanswered;
            }
        };
        let earlier: Vec<String> = found.held.iter().map(|(id, _)| id.clone()).collect();
        self.ticket_show_late_prepaid(Some(hs), Some(&earlier));
        let r = if first.released_msat == sent {
            first
        } else {
            match self.ticket_resume_status(hs) {
                Ok(Some(r)) => r,
                Ok(None) => {
                    forget();
                    return forgotten();
                }
                Err(()) => {
                    forget();
                    return Asked::Unanswered;
                }
            }
        };
        if r.released_msat != sent || r.spent_msat >= r.released_msat {
            // spent to the last msat, and every ticket counted: nothing to ask this seller session again until more is sent
            if r.released_msat == sent {
                lock(&self.ticket_cancel_tried).insert(empty.to_string());
            }
            // short of what the book sent, with a ticket the node settled still not shown to it: that is a credit in the
            // post (the preimage did not reach it, or was not taken for now), and not a reason to buy a second ticket beside it
            let in_the_post = r.released_msat < sent && !self.ticket_late_prepaid(Some(&earlier)).is_empty();
            forget();
            return if in_the_post { Asked::Unanswered } else { Asked::No };
        }
        let balance = r.released_msat - r.spent_msat;
        {
            let mut m = lock_money(hs);
            m.acct = Account { sent_msat: sent, acked_msat: r.released_msat, spent_msat: r.spent_msat };
            m.epoch = m.epoch.saturating_add(1);
            m.anchor();
        }
        // what earlier sessions of this wallet may still hold in that seller session is cancelled by its hashes now,
        // before this session locks there, so that the seller's places for it are free. Answered: the watcher's cancel
        // for those sessions (once per start) is not asked again. Not answered: it is, by the same hashes
        let hashes: Vec<String> = found.held.iter().flat_map(|(_, h)| h.iter().cloned()).collect();
        let answered = in_parts(&hashes, hs.terms.terms.max_tickets)
            .map(|part| matches!(self.ticket_call(hs, "cancel", &json!({"hashes": part}), false), Ok((200, _, _)))).filter(|answered| !answered).count() == 0;
        if answered {
            lock(&self.ticket_cancel_tried).extend(found.held.iter().map(|(id, _)| id.clone()));
        }
        if self.ticket_set_http(&hs.sid, old.clone()).is_err() {
            forget();
            return Asked::No;
        }
        hs.key_on_record.store(true, Ordering::SeqCst);
        // a session waiting for a prepaid ticket before it holds (a seller the owner has not named, or one that holds
        // only after a paid ticket) has what that ticket was to show where this wallet's own node settled a ticket
        // of the seller session it takes over: a payment proved by its preimage, not the seller's word. Unchecked:
        // a session left waiting buys one prepaid ticket, as before, and then holds
        if found.proven {
            let _ = self.ticket_paid_first_met(&hs.sid);
        }
        self.ticket_audit("ticket_resumed", json!({"session": hs.sid, "seller_session": old.id, "origin": hs.origin,
                                                   "dest": format!("ln:{}", hs.terms.terms.payee), "balance_msat": balance}));
        Asked::Taken
    }

    /// The seller's signed `status`: its tickets by state into `ready`, and the body.
    fn ticket_status_of(&self, hs: &HttpSession, absorb: bool) -> std::result::Result<Value, String> {
        self.ticket_status_within(hs, absorb, None)
    }

    /// [`Signer::ticket_status_of`], answered by `by` (a second at least): a release does not spend its call's deadline on
    /// a seller slow to say.
    fn ticket_status_by(&self, hs: &HttpSession, absorb: bool, by: Instant) -> std::result::Result<Value, String> {
        self.ticket_status_within(hs, absorb, Some(by.saturating_duration_since(Instant::now()).max(Duration::from_secs(1))))
    }

    fn ticket_status_within(&self, hs: &HttpSession, absorb: bool, within: Option<Duration>) -> std::result::Result<Value, String> {
        match self.ticket_call_within(hs, "status", &json!({}), false, within) {
            Ok((200, v, Ok(own), sent_epoch)) => {
                // the link before the money, as everywhere (`HttpSession`)
                let sid = lock_link(hs).seller_sid.clone();
                let mut m = lock_money(hs);
                // the seller has closed an answer the wallet stopped reading: its last receipt is listed, and its charge
                // is the seller's word for it. Closed before this status's totals are taken, which count it
                let last: Vec<Receipt> = v.get("responses").and_then(Value::as_array).into_iter().flatten()
                    .filter_map(|r| Receipt::verify(r, &hs.terms.receipt_key, &sid).ok()).filter(|r| !r.body_hash.is_empty()).collect();
                // inside what the wallet can account for, as where the answer's receipt is found as it ends: past the call's
                // limit, the seller's fault; past what could have reached the wallet, believed no further
                // by the same rule as where the answer's receipt is found as it ends ([`Bound`])
                // one at a time: each closed adds to the count what the next is judged against ([`Bound::most`])
                let (mut over, mut wrong) = (None, None);
                let mut overcharged = false;
                let mut i = 0;
                while i < m.tails.len() {
                    let t = &m.tails[i];
                    let Some(r) = last.iter().find(|r| r.for_request(t.seq, &t.digest, t.status).is_ok()) else {
                        i += 1;
                        continue;
                    };
                    let t = m.tails.remove(i);
                    if r.charged > t.bound.max_msat && over.is_none() {
                        over = Some(self.over_cap(hs, r.charged, t.bound.max_msat, &r.raw));
                    }
                    let (charged, why) = t.bound.judge(r, &m);
                    if t.bound.overcharges(r) || r.charged > t.bound.max_msat {
                        overcharged = true;
                        m.evidence.get_or_insert_with(|| r.raw.clone());
                    }
                    if wrong.is_none() {
                        wrong = why;
                    }
                    m.close_by(t.rid, charged, t.counted, &t.bound);
                }
                // over-charging (past the call's limit, past its cost or quote) blocks the seller; a receipt that signs
                // another body only stops the session
                if over.is_some() || overcharged {
                    m.overcharged = true;
                }
                let over = over.or(wrong).map(|why| m.fault.get_or_insert(why).clone());
                // the tickets' states as of this status: only where it is no older than the totals the wallet holds (another
                // answer's newer receipt may have been read first). A status asked for after those totals were taken is
                // newer, whatever its spend says (the seller may have given a charge back)
                let fresh = sent_epoch == m.epoch || (own.released_msat >= m.acct.acked_msat && own.spent_msat >= m.acct.spent_msat);
                if fresh {
                    for t in v.get("tickets").and_then(Value::as_array).into_iter().flatten() {
                        let hash = str_or_empty(t.get("hash"));
                        if t.get("state").and_then(Value::as_str) == Some("ACCEPTED") {
                            m.ready.insert(hash);
                        } else {
                            m.ready.remove(&hash);
                        }
                    }
                }
                // (not where an answer's own receipt is the seller's fault, said above)
                if absorb && over.is_none() {
                    let outstanding = m.pending.is_some();
                    if let Err(why) = m.take(&own, 0, outstanding, Some(sent_epoch)) {
                        m.fault.get_or_insert(why);
                    }
                }
                Ok(v)
            }
            Ok((status, _, Ok(_), _)) => Err(format!("the seller answered status with HTTP {status}")),
            Ok((status, v, Err(why), _)) => Err(self.ticket_forgotten(hs, status, &v)
                                                 .unwrap_or_else(|| format!("the seller's answer to status (HTTP {status}) has no valid receipt: {why}"))),
            Err(e) => Err(e.msg),
        }
    }

    /// The seller's interim receipt of an open answer (a WebSocket) against the wallet's own count of it
    /// ([`crate::ticket_interim`]). `own` is read once the seller's answer is in, so the bytes that passed while it was
    /// asked are counted on the wallet's side too. `Some`: the seller's fault, recorded in the session (nothing more is
    /// released to it) with the receipt in the wallet's log. A status that could not be had, or a receipt that does not
    /// check out, is no newer count: a seller that sent one and then none (by any means) while bytes flow is stale.
    #[allow(clippy::too_many_arguments)]
    fn ticket_interim(&self, hs: &HttpSession, seq: u64, digest: &str, own: &dyn Fn() -> (u64, u64), price: &Price, max_msat: u64,
                      last: &mut Option<crate::ticket_interim::Seen>, polls: &mut crate::ticket_interim::Polls) -> Option<String> {
        let v = self.ticket_status_of(hs, false).ok();
        let (own_up, own_down) = own();
        let sid = lock_link(hs).seller_sid.clone();
        let before = last.as_ref().map(|l| l.part);
        let mut found = None;
        for raw in v.as_ref().and_then(|v| v.get("interim")).and_then(Value::as_array).into_iter().flatten() {
            let Ok(r) = Receipt::verify(raw, &hs.terms.receipt_key, &sid) else { continue };
            if let Err(why) = crate::ticket_interim::check(&r, seq, digest, 101, own_up, own_down, price, max_msat, last) {
                found = Some((why, r.raw));
                break;
            }
        }
        // how the seller answered: a newer count, an answer with none newer, or no answer the wallet could take
        let now = Instant::now();
        if last.as_ref().map(|l| l.part) != before {
            polls.counted();
        } else if v.is_some() {
            polls.answered();
        } else {
            polls.failed(now);
        }
        // a seller counting far too little, newer count after newer count: told once in the wallet's log, never a fault
        // (it charges less, not more)
        if last.as_ref().map(|l| l.part) != before {
            if let Some(words) = last.as_ref().and_then(|l| polls.under(l)) {
                eprintln!("b2-signer: {}: {words}", hs.origin);
                self.ticket_audit("ticket_interim_undercount", json!({"session": hs.sid, "origin": hs.origin, "dest": format!("ln:{}", hs.terms.terms.payee),
                                                                      "reason": words, "own_up": own_up, "own_down": own_down}));
            }
        }
        let found = found.or_else(|| crate::ticket_interim::stale(last, polls, own_up.saturating_add(own_down), now, crate::ticket_interim::stale_after()).map(|w| (w, Value::Null)));
        let (why, receipt) = found?;
        self.ticket_audit("ticket_interim_fault", json!({"session": hs.sid, "origin": hs.origin, "dest": format!("ln:{}", hs.terms.terms.payee),
                                                         "reason": why, "receipt": receipt, "own_up": own_up, "own_down": own_down}));
        Some(lock_money(hs).fault.get_or_insert(why).clone())
    }

    /// Mark the session faulty and stop it: nothing more is released to this seller in it.
    /// A seller's signed charge for one answer above the call's limit: the receipt goes into the audit log as
    /// evidence, and the words for the fault (which stops the session).
    fn over_cap(&self, hs: &HttpSession, charged: u64, max_msat: u64, receipt: &Value) -> String {
        hs.over_cap.store(true, Ordering::SeqCst);
        lock(&hs.evidence).get_or_insert_with(|| receipt.clone());
        self.ticket_audit("ticket_over_cap", json!({"session": hs.sid, "origin": hs.origin, "dest": format!("ln:{}", hs.terms.terms.payee),
                                                    "charged_msat": charged.to_string(), "max_msat": max_msat.to_string(), "receipt": receipt}));
        format!("the seller charged {charged} msat for one answer, more than the {max_msat} msat (the call's charge cap of {} sat) the call allowed and named to it; \
                 it is paid nothing more, and its signed receipt is kept in the wallet's log", max_msat / 1000)
    }

    /// Who the session's seller is, for a block: its node, its receipt key and its origin.
    fn seller_of(hs: &HttpSession) -> (String, String) {
        (hs.terms.terms.payee.clone(), hex::encode(&hs.terms.receipt_key))
    }

    /// Block the session's seller for over-charging, with the evidence ([`crate::seller_block`]).
    fn seller_block(&self, hs: &HttpSession, why: &str, evidence: Option<Value>) {
        let (payee, rk) = Self::seller_of(hs);
        let who = crate::seller_block::Seller { payee: &payee, receipt_key: &rk, origin: &hs.origin };
        let evidence = json!({"receipt": evidence, "account": hs.public()});
        self.seller_blocks.block(&who, why, &hs.sid, self.engine.now(), evidence);
    }

    /// The block on the session's seller, if it is blocked.
    fn seller_blocked(&self, hs: &HttpSession) -> Option<Value> {
        let (payee, rk) = Self::seller_of(hs);
        self.seller_blocks.get(&crate::seller_block::Seller { payee: &payee, receipt_key: &rk, origin: &hs.origin })
    }

    fn ticket_fault(&self, hs: &HttpSession, why: &str) -> Value {
        let (overcharged, evidence) = {
            let mut m = lock_money(hs);
            m.fault.get_or_insert_with(|| why.to_string());
            (m.overcharged || hs.over_cap.load(Ordering::SeqCst), m.evidence.clone().or_else(|| lock(&hs.evidence).clone()))
        };
        // caught charging more than the wallet can account for: no new session with it until the owner lifts the block.
        // The evidence is the audit entry below. A fault of another kind (a node with no final answer, a seller that
        // forgot the session) stops the session and blocks nothing
        if overcharged {
            self.seller_block(hs, why, evidence);
        }
        // with the wallet's count as it stood, for the owner who has to judge the seller
        self.ticket_audit("ticket_seller_fault", json!({"session": hs.sid, "origin": hs.origin, "dest": format!("ln:{}", hs.terms.terms.payee), "reason": why,
                                                        "account": hs.public()}));
        let stopped = self.ticket_http_stop(hs, &format!("seller fault: {why}"), Duration::ZERO);
        with(refusal("ticket_seller_fault", format!("the session with this seller was stopped: {why}")), json!({"session": hs.sid, "stopped": stopped}))
    }

    /// Wait, no later than `deadline`, for a chain node that is not answering: a busy one, or one restarting. A stop ends
    /// the wait. `Err`: the refusal.
    fn ticket_await_chain(&self, hs: &HttpSession, deadline: Instant) -> std::result::Result<(), Value> {
        let mut poll = PAUSE_POLL_FIRST;
        while !self.chain_answers() {
            if hs.ending.load(Ordering::SeqCst) {
                return Err(stopping_refusal());
            }
            if !self.ticket_session(&hs.sid).is_some_and(|s| s.state == SState::Open) {
                return Err(refusal("ticket_session", "the session was stopped: nothing more is released for it"));
            }
            if Instant::now() >= deadline {
                return Err(with(refusal(TIP_UNKNOWN, "the wallet's chain node is not answering, so how long a ticket has left is not known: no secret was \
                                                      released; call again"), json!({"session": hs.sid})));
            }
            std::thread::sleep(poll.min(deadline.saturating_duration_since(Instant::now())));
            poll = (poll * 2).min(PAUSE_POLL_MOST);
        }
        Ok(())
    }

    /// Release one ticket of the session to the seller. In order: the seller's own signed word
    /// that the ticket is locked; the book's release (every rule of the owner, and the spend in
    /// the ledger); the secret to the seller; the seller's signed word that it took it. `Err`: the
    /// refusal, with no secret out unless it says so.
    ///
    /// `due.still_due`: asked again once this release has the session's `paying` lock, and again just before the book.
    /// Requests run side by side and each may find a ticket due at once; the first releases it, and the others, finding
    /// the balance covers them now, release nothing (`Ok`). A secret that has left and is not confirmed is delivered
    /// whatever it says.
    ///
    /// Everything this release waits for, it waits for within one deadline ([`Due::pause_by`]): `tickets.ready_wait_ms`,
    /// 12 s as shipped, under the 15 s a seller as shipped keeps a paused answer open. The ticket may be late from the
    /// wallet's node or from the seller, or the chain node may be quiet; it is the same answer that waits. And no secret
    /// leaves for an answer that has ended ([`Signer::ticket_answer_over`]).
    fn ticket_release_one(&self, hs: &Arc<HttpSession>, spent: &mut Spent, due: &Due) -> std::result::Result<(), Value> {
        let tp = self.ticket_policy();
        let (opened, still_due) = (due.opened, due.still_due);
        // a seller blocked meanwhile (another session of it over-charged) is released nothing more
        if let Some(b) = self.seller_blocked(hs) {
            return Err(with(deny("seller_blocked", format!("this seller was caught charging more than it delivered ({}) and is blocked: nothing more \
                                                            is released to it", b["reason"].as_str().unwrap_or_default())), json!({"seller_blocked": b["id"]})));
        }
        if spent.credit_only {
            // the same rule as a call whose limit is spent: the caller asks again with the right to buy
            return Err(deny("max_sats", "this call draws only on the session's credit (credit_only) and buys no ticket"));
        }
        // an answer the wallet stopped reading and the seller has not closed: a ticket released now would wake it, and
        // the seller would charge for bytes nobody reads. Its last receipt in `status` is the seller's word that it is
        // closed. Waited for before `paying` is taken, so that the answers that go on meanwhile can pay; and only by the
        // answers that opened after it was left (`opened`): one open before it was already drawing on the balance beside
        // it, and goes on within its own call's limit
        let blocking = |m: &Money| m.tails.iter().filter(|t| t.since <= opened).map(|t| t.since).min();
        if blocking(&lock_money(hs)).is_some() {
            let deadline = (Instant::now() + TAIL_WAIT).min(due.call_by);
            loop {
                if let Err(why) = self.ticket_status_by(hs, true, deadline) {
                    return Err(refusal(Self::status_rule(hs), format!("{why}: no secret was released")));
                }
                let Some(since) = blocking(&lock_money(hs)) else { break };
                if since.elapsed() >= TAIL_GIVE_UP {
                    // its last receipt can no longer be listed (a seller keeps a few, and many answers ran beside it), or
                    // the seller never closed it: closed here as charged the most the wallet believes of any charge for
                    // it, judged now ([`Tail::bound`], [`Bound::most`]). The seller's spend is bounded by that; its own
                    // word for the answer is not needed
                    let given_up = lock_money(hs).give_up();
                    if given_up > 0 {
                        self.ticket_audit("ticket_answer_given_up", json!({"session": hs.sid, "origin": hs.origin, "answers": given_up}));
                    }
                    continue;
                }
                if Instant::now() >= deadline {
                    return Err(with(refusal("ticket_answer_open", "the seller has not yet closed the answer the wallet stopped reading: no secret was released \
                                                                   into it; call again"), json!({"session": hs.sid})));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        // in turn, no later than the call's deadline: the release ahead pauses for itself, and this one's pause begins here
        let Some(_paying) = lock_paying_by(hs, due.call_by) else {
            return Err(with(refusal("ticket_busy", "other calls to this seller have been paying for as long as this call may wait: no secret was released; call again"),
                            json!({"session": hs.sid})));
        };
        let turn = Instant::now();
        let pause_by = due.pause_by(&tp, turn);
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
        // a secret that has left and was not confirmed goes first, the same one: that is this release. It is delivered
        // even to a session being stopped: it has left already, and the seller holds it either way
        if lock_money(hs).pending.is_some() {
            return self.ticket_deliver(hs, due.call_by + DELIVER_PAST_CALL);
        }
        // a session being stopped is released nothing more: its open answers end on the credit they have. Asked under
        // `paying`, and again before each step that could release one (the book stays open while a stop waits)
        if hs.ending.load(Ordering::SeqCst) {
            return Err(stopping_refusal());
        }
        // another request released one while this one waited: nothing more is due
        if !still_due() {
            return Ok(());
        }
        let mut next = self.ticket_next(&hs.sid).0;
        if next.is_none() {
            self.ticket_await_chain(hs, pause_by)?;
            next = self.ticket_next(&hs.sid).0;
        }
        if next.is_none() {
            // the pool is empty (a refill has not come back, or every ticket is too old): filled here, once
            let guard = loop {
                if let Some(g) = Refilling::take(hs.clone()) {
                    break Arc::new(g);
                }
                // (a moment at least: the fill behind this release's last try may be about to end)
                if Instant::now() >= pause_by.max(turn + FILL_MOMENT) {
                    return Err(refusal("ticket_busy", "a refill of this session's tickets has not ended: call again"));
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            // the fill asks both nodes and the seller, on a thread of its own ([`Signer::ticket_fill_by`]). A node away for a
            // moment refuses it: asked again, inside the pause, where the seller is waiting for this ticket, or the chain
            // node is what is quiet, or a ticket is on its way that the wallet's own node has yet to say more about. A refusal
            // for any other reason is not one that asking again would change, and costs no wait
            let mut filled = self.ticket_fill_by(hs, pause_by, guard.clone());
            let mut poll = PAUSE_POLL_FIRST;
            while Instant::now() < pause_by && filled.as_ref().err().is_some_and(|d| crate::ticket::NODE_AWAY_RULES.contains(&d["rule"].as_str().unwrap_or_default()))
                  && (due.answer.is_some() || !self.chain_answers() || self.ticket_refresh_coming(&hs.sid, &|| hs.ending.load(Ordering::SeqCst), pause_by)) {
                if hs.ending.load(Ordering::SeqCst) {
                    return Err(stopping_refusal());
                }
                std::thread::sleep(poll.min(pause_by.saturating_duration_since(Instant::now())));
                poll = (poll * 2).min(PAUSE_POLL_MOST);
                filled = self.ticket_fill_by(hs, pause_by, guard.clone());
            }
            drop(guard);
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
                        let stopped = self.ticket_stop_inside(hs, &format!("{why}: no ticket can be held with this seller, and it offers no prepaid ones"));
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
            // a ticket sent and not yet shown locked by the wallet's own node (a loaded node answers the send, or its
            // payment stream breaks, before it lists the HTLC): the pool counts it, so no fill sends another, and the
            // answer would end for want of one that is on its way. It is waited for, the node asked again, inside the
            // pause; a stop ends the wait, and one the node fails is let go by the book. One that has been on its way for
            // longer than any send takes is stranded, and the session cannot go on past it
            let mut poll = PAUSE_POLL_FIRST;
            let mut stranded_asked = false;
            while next.is_none() && self.ticket_refresh_coming(&hs.sid, &|| hs.ending.load(Ordering::SeqCst), pause_by) {
                if hs.ending.load(Ordering::SeqCst) {
                    return Err(stopping_refusal());
                }
                if !self.ticket_session(&hs.sid).is_some_and(|s| s.state == SState::Open) {
                    return Err(refusal("ticket_session", "the session was stopped: nothing more is released for it"));
                }
                if !std::mem::replace(&mut stranded_asked, true) {
                    if let Some(hash) = self.ticket_sending_stranded(&hs.sid, pause_by) {
                        return Err(self.ticket_session_stranded(hs, &hash));
                    }
                }
                if Instant::now() >= pause_by {
                    return Err(with(refusal("ticket_not_ready", "a ticket is on its way and the wallet's node has not shown it locked: no secret was released; call again"),
                                    json!({"session": hs.sid})));
                }
                std::thread::sleep(poll.min(pause_by.saturating_duration_since(Instant::now())));
                poll = (poll * 2).min(PAUSE_POLL_MOST);
                next = self.ticket_next(&hs.sid).0;
            }
        }
        let Some(mut hash) = next else {
            // the book says why nothing can be released (a stopped session, a task the owner removed, no ticket). It is
            // asked for a ticket that cannot exist, so that it cannot release one a refill locked in this instant.
            // Where the pool is empty because the last fill was refused, that refusal is the reason
            let r = {
                let Some(_g) = self.lock_by(due.call_by) else {
                    return Err(with(refusal("ticket_busy", "the wallet's book is held up, by a node that does not answer: no secret was released; call again"),
                                    json!({"session": hs.sid})));
                };
                self.ticket_release_locked(&json!({"session": hs.sid, "hash": "none"}))
            };
            let unfilled = lock(&hs.unfilled).clone().filter(|_| r["rule"] == "ticket_none");
            return Err(if r["verdict"] == "allow" { refusal("ticket", "the book released a ticket this payer did not ask for") } else { unfilled.unwrap_or(r) });
        };
        // 1. the seller's own word, bounded
        let deadline = pause_by;
        let mut wait = Duration::from_millis(10);
        while !lock_money(hs).ready.contains(&hash) {
            let status = match self.ticket_status_by(hs, true, deadline) {
                Ok(v) => v,
                Err(why) => return Err(refusal(Self::status_rule(hs), format!("{why}: no secret was released"))),
            };
            if self.ticket_status_lists_answer(hs, &status, due) {
                return Err(answer_closed_refusal(hs));
            }
            if lock_money(hs).ready.contains(&hash) {
                break;
            }
            // the ticket may have failed since it was chosen: one that finds no slot at a later hop is in flight on the
            // wallet's node for a moment before the refusal is back. The node is asked, and the book's next ticket taken
            self.ticket_refresh_coming(&hs.sid, &|| hs.ending.load(Ordering::SeqCst), deadline);
            match self.ticket_next(&hs.sid).0 {
                Some(h) if h == hash => {}
                Some(h) => {
                    hash = h;
                    continue;
                }
                // no tip to judge the ticket by: it has not failed, and the wait goes on
                None if self.tip_known().is_none() => {}
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
            if hs.ending.load(Ordering::SeqCst) {
                return Err(stopping_refusal());
            }
            if !self.ticket_session(&hs.sid).is_some_and(|s| s.state == SState::Open) {
                return Err(refusal("ticket_session", "the session was stopped: nothing more is released for it"));
            }
            if Instant::now() >= deadline {
                // a ticket the wallet's own node calls in flight and has on none of its channels (a node that was
                // killed as it sent it) never arrives: the seller will not show it, and it is the session's oldest,
                // so every release of the session would wait here. The session ends, and the next call opens
                // another; the ticket stays locked in the book for as long as the node calls it in flight
                let asked_of = self.me.get().and_then(std::sync::Weak::upgrade);
                let h = hash.clone();
                if asked_of.and_then(|me| crate::ticket_rail::within(Instant::now() + STOP_INSIDE_WAIT, move || me.ticket_stranded(&h))).unwrap_or(false) {
                    return Err(self.ticket_session_stranded(hs, &hash));
                }
                let not_ready = with(refusal("ticket_not_ready", format!("the seller has not shown the ticket locked on its node within {} ms of the wait: no secret was released",
                                                                          pause_by.saturating_duration_since(due.waiting_since.unwrap_or(turn)).as_millis())),
                                     json!({"session": hs.sid, "hash": hash}));
                // one to a pause: the pause began when this release's turn came, and a byte delivered since the last clears the count
                return Err(self.ticket_stalled(hs, not_ready));
            }
            std::thread::sleep(wait.min(deadline.saturating_duration_since(Instant::now())));
            wait = (wait * 2).min(PAUSE_POLL_MOST);
        }
        if let Some(why) = hs.fault() {
            return Err(self.ticket_fault(hs, &why));
        }
        // the call's max_sats bounds what leaves for it, a whole ticket included. A held ticket that does not fit
        // gives way to a smaller prepaid one where the seller sells those and one fits
        if let Err(d) = spent.room(self.ticket_next_booking(&hs.sid, &hash), false) {
            let prepaid = self.ticket_prepaid_size(&hs.sid, spent.left(), spent.charge_sats);
            if prepaid.is_some_and(|(_, face, booked)| spent.room(Some((face, booked)), true).is_ok()) {
                return self.ticket_buy_prepaid(hs, spent);
            }
            return Err(d);
        }
        // asked again just before the book: another answer may have found the seller at fault while this one waited for it
        // to show the ticket ready, and nothing more is released to a seller at fault, or into a session being stopped
        if let Some(why) = hs.fault() {
            return Err(self.ticket_fault(hs, &why));
        }
        if hs.ending.load(Ordering::SeqCst) {
            return Err(stopping_refusal());
        }
        // and whether it is still wanted: the waits above may have taken long enough for another answer to have paid it, or
        // for the seller to have closed the answer it was for. A secret that left then would pay for nothing
        if !still_due() {
            return Ok(());
        }
        self.ticket_answer_over(hs, due, pause_by)?;
        // and whether the call still has anyone to tell: its caller gives up not long after this
        if Instant::now() >= due.call_by {
            return Err(with(refusal("ticket_call_deadline", "the call has reached its deadline (tickets.max_answer_s): no secret was released; call again"),
                            json!({"session": hs.sid})));
        }
        // 2. the book: booked, then the secret exists here. Its lock waited for no later than the call's deadline
        let r = {
            let Some(_g) = self.lock_by(due.call_by) else {
                return Err(with(refusal("ticket_busy", "the wallet's book is held up, by a node that does not answer: no secret was released; call again"),
                                json!({"session": hs.sid})));
            };
            self.ticket_release_locked(&json!({"session": hs.sid, "hash": hash}))
        };
        if r["verdict"] != "allow" {
            return Err(r);
        }
        let Some(secret) = r.get("ticket_secret").and_then(Value::as_str) else { return Err(refusal("ticket", "the book released no secret")) };
        {
            let mut m = lock_money(hs);
            let ticket_msat = crate::ticket::outside_u64(r.get("ticket_msat")).unwrap_or(0);
            m.acct.released(ticket_msat);
            m.pending = Some((hash.clone(), Zeroizing::new(secret.to_string())));
            m.ready.remove(&hash);
            spent.released_msat = spent.released_msat.saturating_add(ticket_msat);
        }
        spent.hashes.push(hash);
        spent.booked_sats = spent.booked_sats.saturating_add(py_int(r.get("charged_sats")).unwrap_or(0));
        hs.stalls.store(0, Ordering::SeqCst);
        // 3. and 4.
        self.ticket_deliver(hs, due.call_by + DELIVER_PAST_CALL)
    }

    /// `Err` where the answer this ticket is for is over: asked just before the book, of a ticket whose answer has been
    /// quiet long enough for that. The reader is not reading while a ticket is due, so a close by the
    /// seller is not seen there: the seller's signed `status` says, listing it among the answers that ended.
    fn ticket_answer_over(&self, hs: &HttpSession, due: &Due, pause_by: Instant) -> std::result::Result<(), Value> {
        if due.answer.is_none() || due.waiting_since.is_none_or(|w| w.elapsed() < QUIET_BEFORE_ASKING) {
            return Ok(());
        }
        let status = self.ticket_status_by(hs, true, pause_by).map_err(|why| refusal(Self::status_rule(hs), format!("{why}: no secret was released")))?;
        if self.ticket_status_lists_answer(hs, &status, due) {
            return Err(answer_closed_refusal(hs));
        }
        Ok(())
    }

    /// Whether the seller's signed `status` lists the answer this ticket is for among those that ended.
    fn ticket_status_lists_answer(&self, hs: &HttpSession, status: &Value, due: &Due) -> bool {
        let Some((seq, digest, code)) = due.answer else { return false };
        let sid = lock_link(hs).seller_sid.clone();
        status.get("responses").and_then(Value::as_array).into_iter().flatten()
            .filter_map(|r| Receipt::verify(r, &hs.terms.receipt_key, &sid).ok())
            .any(|r| !r.body_hash.is_empty() && r.for_request(seq, digest, code).is_ok())
    }

    /// The seller has not shown a ticket, again. Past a few of those running with no byte between them, the session ends:
    /// a seller that never shows one holds the buyer up at no cost to itself, a pause at a time.
    fn ticket_stalled(&self, hs: &Arc<HttpSession>, not_ready: Value) -> Value {
        // not the seller's doing where the ticket may not have reached it: a channel of the wallet's node down, the ticket on
        // none of them (a link that dropped and is listing its HTLCs again), or a node that gives no answer. The link's own
        // rules end such a session, by their own reasons ([`Signer::ticket_stranded`])
        if !self.ticket_on_a_way_up(&str_or_empty(not_ready.get("hash"))) {
            return not_ready;
        }
        let n = hs.stalls.fetch_add(1, Ordering::SeqCst) + 1;
        if n < STALLS_MOST {
            return not_ready;
        }
        let stopped = self.ticket_stop_inside(hs, "the seller has not shown the wallet's tickets locked");
        with(refusal("ticket_seller_stalled", format!("the seller has not shown a ticket locked {n} times running, with no byte delivered between them: the session was \
                                                       stopped and no secret was released; the next call opens another")),
             json!({"session": hs.sid, "stopped": stopped}))
    }

    /// A stop made inside a release: it asks the seller and the node, on a thread of its own, and is waited for only a moment.
    /// From the moment it begins nothing more is released; what it comes to is in the session's status if it takes longer.
    fn ticket_stop_inside(&self, hs: &Arc<HttpSession>, why: &str) -> Value {
        hs.ending.store(true, Ordering::SeqCst);
        if why != FORGOTTEN_WHY {
            hs.forgotten.store(false, Ordering::SeqCst);
        }
        let Some(me) = self.me.get().and_then(std::sync::Weak::upgrade) else { return self.ticket_http_stop(hs, why, Duration::ZERO) };
        let (h, w) = (hs.clone(), why.to_string());
        crate::ticket_rail::within(Instant::now() + STOP_INSIDE_WAIT, move || me.ticket_http_stop(&h, &w, Duration::ZERO))
            .unwrap_or_else(|| json!({"session": hs.sid, "why": why, "still_stopping": true}))
    }

    /// [`Signer::ticket_fill`] on a thread of its own, waited for until `by`: a node or a seller that hangs takes that thread,
    /// and it only locks tickets, which is safe to go on behind. `keep` goes with it (the session's refill flag).
    fn ticket_fill_by(&self, hs: &Arc<HttpSession>, by: Instant, keep: impl Send + Sync + 'static) -> std::result::Result<usize, Value> {
        let Some(me) = self.me.get().and_then(std::sync::Weak::upgrade) else { return self.ticket_fill(hs) };
        let h = hs.clone();
        // a moment at least: a fill asked for as the pause runs out says what it came to, rather than being left behind
        crate::ticket_rail::within(by.max(Instant::now() + FILL_MOMENT), move || {
            let _keep = keep;
            me.ticket_fill(&h)
        }).unwrap_or_else(|| Err(with(refusal("ticket_busy", "the wallet's node or the seller has not yet answered for this session's next tickets: no secret was released; call again"),
                                      json!({"session": hs.sid}))))
    }

    /// A ticket of the session that will never reach the seller: the session cannot go on past it, and ends here. The next
    /// call opens another; the ticket stays locked in the book for as long as the node calls it in flight.
    fn ticket_session_stranded(&self, hs: &Arc<HttpSession>, hash: &str) -> Value {
        let stopped = self.ticket_stop_inside(hs, "a ticket of the session is on none of the wallet's channels");
        with(refusal("ticket_session_ended", "a ticket of this session is on none of the channels of the wallet's Lightning node, though the node \
                                              calls its payment in flight: the seller cannot be shown it, so the session was stopped and no \
                                              secret was released; the next call opens another session"),
             json!({"session": hs.sid, "hash": hash, "stopped": stopped}))
    }

    /// Send the secret that has left the book and is not confirmed, and read the seller's signed
    /// answer to it. The same secret is sent again when the seller says its ticket is not locked
    /// yet or gives no answer that can be believed; no other secret is sent meanwhile.
    fn ticket_deliver(&self, hs: &HttpSession, by: Instant) -> std::result::Result<(), Value> {
        let Some((hash, secret)) = lock_money(hs).pending.as_ref().map(|(h, s)| (h.clone(), s.clone())) else { return Ok(()) };
        let mut wait = Duration::from_millis(50);
        for _ in 0..5 {
            let left = by.saturating_duration_since(Instant::now()).max(Duration::from_secs(1));
            let taken = match self.ticket_call_within(hs, "release", &json!({"secrets": [secret.as_str()]}), true, Some(left)).map(|(status, v, r, _)| (status, v, r)) {
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
                                lock_money(hs).pending = None;
                                return Err(self.ticket_fault(hs, &format!("the seller refused a released ticket ({code}); its secret has left and stays booked until \
                                                                           the wallet's node shows the ticket failed")));
                            }
                        }
                    }
                }
                // no answer that can be believed: the seller's signed status decides
                _ => match self.ticket_status_by(hs, true, by) {
                    Ok(_) => {
                        let m = lock_money(hs);
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
                // a prepaid ticket's preimage is with the seller: nothing is left to show it
                self.ticket_late_prepaid_done(std::slice::from_ref(&hash), true);
                let mut m = lock_money(hs);
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
    fn ticket_request(&self, hs: &Arc<HttpSession>, c: &Call, terms: &PayTerms) -> Value {
        let price = &terms.price;
        let tp = self.ticket_policy();
        // what the answer may charge; what may leave for it (a whole ticket included) is `max_sats`, in `spent`
        let max_msat = (c.charge_sats.max(0) as u64).saturating_mul(1000);
        let dest = format!("ln:{}", hs.terms.terms.payee);
        let mut spent = Spent { limit_sats: Some(c.max_sats.max(0)), charge_sats: Some(c.charge_sats.max(0)), credit_only: c.credit_only, ..Spent::default() };
        let about = |hs: &HttpSession, spent: &Spent| {
            json!({"rail": "ticket", "session": hs.sid, "dest": dest, "origin": hs.origin, "charged_sats": spent.booked_sats, "tickets_released": spent.hashes.len(),
                   "tickets_prepaid": spent.prepaid, "request_sent": spent.sent,
                   "balance_msat": hs.balance().to_string(), "credited_msat": hs.credited().to_string(), "tickets": self.ticket_session_counts(&hs.sid)})
        };
        let fail = |hs: &HttpSession, spent: &Spent, d: Value| with(d, about(hs, spent));
        // by the token, the most the request can cost is wanted in the balance before it is served
        let Some(reserve) = price.reserve_for(c.body) else {
            return fail(hs, &spent, refusal("ticket_terms", "the route's price does not fit an amount, or the request is not one the route takes (by the token: a JSON object)"))
        };
        if reserve > max_msat {
            return fail(hs, &spent, deny("max_sats", format!("quoted {} sats > the call's charge cap of {} sats", sats_ceil(reserve), c.charge_sats)));
        }
        // a call that found the session as it was being stopped goes no further in it
        if hs.ending.load(Ordering::SeqCst) {
            return fail(hs, &spent, with(refusal("ticket_busy", "the session with this seller is being stopped: nothing was asked of the seller in it; call \
                                                                 again in a moment"), json!({"retry_after_s": 1})));
        }
        if let Some(why) = hs.fault() {
            return fail(hs, &spent, self.ticket_fault(hs, &why));
        }
        *lock(&hs.used) = self.engine.now();
        self.session_touch(&hs.sid);
        let started = Instant::now();
        let mut short = 0;
        // a WebSocket's way to the seller, once it said 101
        let mut up_writer: Option<Box<dyn Write + Send>> = None;
        let mut identified_again = false;
        // the most a ticket of this seller adds to the balance: how many rounds of releases a head's reserve takes
        let ticket_msat = hs.terms.terms.ticket_msat.max(1);
        let most_rounds = reserve.div_ceil(ticket_msat).saturating_add(2).min(64);
        // the caller's socket, opened once the request is paid for where it asked to be told (`stream_paid`)
        let mut early: Option<Sink> = None;
        // that caller was told the wallet pays again since it was told the request is paid for
        let mut paying_told = false;
        // a caller that asked to be told and is gone (its socket closed, or never reached) gets no answer: the
        // request does not leave, so that one answer is never paid to two sellers
        let caller_gone = || refusal("ticket_caller_gone", "the caller stopped waiting before the request was sent: it was not sent, and what was \
                                                            paid for it stays with the seller as credit");
        let (rid, seq, digest, ans, head, mark, streaming) = loop {
            // whole tickets until the seller's balance covers what it wants before it serves. The balance
            // by the wallet's count: answers open beside this one draw on it as they go
            let mut rounds = 0;
            let short_now = || {
                let m = lock_money(hs);
                m.est_balance() < reserve || m.pending.is_some()
            };
            while short_now() {
                rounds += 1;
                if rounds > most_rounds {
                    // the tickets released for this head were drawn by the answers open beside it as fast as they came
                    let why = if reserve > ticket_msat.saturating_mul(62) { "the route's price needs more than 64 tickets before it is served" }
                              else { "the answers open beside this request drew the tickets released for it before it could be sent: call again" };
                    return fail(hs, &spent, refusal(if reserve > ticket_msat.saturating_mul(62) { "ticket_terms" } else { "ticket_contended" }, why));
                }
                // the caller was told the request is paid for, and the wallet pays again (the seller's balance ran short):
                // said, so that it does not count this payment as the seller's time
                if let Some(s) = early.as_mut().filter(|_| !paying_told) {
                    s.head(&json!({"paying": true}));
                    paying_told = true;
                }
                let due = Due { opened: started, waiting_since: None, call_by: c.by, still_due: &short_now, answer: None };
                if let Err(d) = self.ticket_release_one(hs, &mut spent, &due) {
                    return fail(hs, &spent, d);
                }
            }
            // stopped while this call waited for a ticket (the owner turned anonymous here, say): nothing more goes out on it
            // (`ending` first: a stop sets it before it closes the session on the book)
            if hs.ending.load(Ordering::SeqCst) || !self.ticket_session(&hs.sid).is_some_and(|s| s.state == SState::Open) {
                return fail(hs, &spent, refusal("ticket_session", "the session with this seller was stopped while this call waited: call again"));
            }
            let digest = request_digest_v2(c.method, c.url, c.body);
            let order = lock_order(hs);
            let (mut seq, sid, key) = match self.seq_take(hs) {
                Ok(x) => x,
                Err(e) => return fail(hs, &spent, refusal("ticket_session", e.msg)),
            };
            // from the moment it leaves, the seller may charge this request: at most its price allows before anything
            // of it is counted here ([`uncounted_most`])
            let rid = {
                let mut m = lock_money(hs);
                let rid = m.request_id();
                m.open.insert(rid, uncounted_most(price, reserve, max_msat, ticket_msat, 0, true));
                rid
            };
            let seq_deadline = Instant::now() + SEQ_WAIT;
            let mut late = false;
            let mut sent_epoch;
            let (mut ans, receipt) = loop {
                let auth = xbt402::ticket::request_auth(&key, &sid, seq, "", "", &digest);
                let header = b64json(&payment_payload(&hs.terms.accepted, &json!({"session": sid, "seq": seq, "auth": auth})));
                let mut headers = c.headers();
                headers.push(("PAYMENT-SIGNATURE".into(), header));
                // the most this answer may charge the session's balance: the call's own limit
                if c.charge_sats > 0 {
                    headers.push((xbt402::ticket::MAX_MSAT_HEADER.into(), (c.charge_sats as u64).saturating_mul(1000).to_string()));
                }
                // the price the wallet counts this request at: a seller that checks it refuses another unpaid
                headers.push((xbt402::ticket::PRICE_HEADER.into(),
                              xbt402::ticket::price_line(price.request_msat, price.byte_msat, price.per_bytes, price.second_msat, &price.tokens)));
                // paid for, and its turn to leave: from here the seller's time is the seller's, whatever the payment (or
                // the turn) took. Said again after any payment since the caller was told; and before every send, a caller
                // gone (a request sent again for `bad_seq` may find it gone meanwhile) is sent nothing
                if c.stream_paid {
                    match early.as_mut() {
                        None => {
                            let mut s = Sink::for_call(c);
                            s.head(&json!({"paid": true}));
                            early = Some(s);
                        }
                        Some(s) if paying_told => s.head(&json!({"paid": true})),
                        Some(_) => {}
                    }
                    paying_told = false;
                    if !c.upgrade && early.as_mut().is_some_and(|s| !s.reader_there()) {
                        self.seq_done(hs, seq);
                        lock_money(hs).close(rid, 0, 0);
                        return fail(hs, &spent, with(caller_gone(), json!({"status": null})));
                    }
                }
                spent.sent = true;
                sent_epoch = lock_money(hs).epoch;
                let sent = if c.upgrade {
                    self.wire_upgrade(c.url, &headers, Self::ticket_read_timeout(&tp)).map(|u| {
                        up_writer = u.writer.filter(|_| u.answer.status == 101);
                        u.answer
                    })
                } else {
                    // inside the call's deadline, a second at least: a seller slow to answer is a plain refusal in time
                    let left = c.by.saturating_duration_since(Instant::now()).max(Duration::from_secs(1));
                    self.wire(c.method, c.url, c.body, &headers, Self::ticket_read_timeout(&tp).min(left))
                };
                let ans = match sent {
                    Ok(a) => a,
                    // no secret travels with a request, so a lost answer costs what the seller charged the balance, if
                    // anything: at most what its price asks before it serves, which the count keeps as charged
                    Err(e) => {
                        self.seq_done(hs, seq);
                        // the seller may have it, queued, and charge it later: held as one it may still charge until a quiet
                        // point well after ([`Money::lose`]), but only for what could have arrived: nothing of its answer did
                        // a request the wallet stopped waiting for (its own timeout) may still be served late by an honest
                        // seller: held as one being answered, with what is paid ahead of it. One whose connection failed,
                        // to what could have arrived. Either within the session's cap on lost requests ([`Money::lose`])
                        let timed_out = e.code == WIRE_TIMEOUT;
                        let lost = if price.second_msat > 0 && !price.tokens.active() {
                            price.cost(CUT_SLACK, started.elapsed().as_secs().saturating_add(1)).unwrap_or(u64::MAX).min(max_msat)
                        } else {
                            uncounted_most(price, reserve, max_msat, ticket_msat, 0, timed_out)
                        };
                        lock_money(hs).lose(rid, lost, price.tokens.active(), timed_out, ticket_msat);
                        return fail(hs, &spent, with(refusal("ticket_seller", format!("the seller gave no answer to the paid request: {}", e.msg)), json!({"status": null})));
                    }
                };
                let receipt = Receipt::read(ans.header("PAYMENT-RESPONSE"), &hs.terms.receipt_key, &sid, seq, &digest, ans.status);
                // the seller's HTTP layer gave up on it (408) before anything served or charged it: once more, with its seq
                if receipt.is_err() && ans.status == 408 && !late {
                    late = true;
                    continue;
                }
                if receipt.is_err() && ans.status == 402 && Instant::now() < seq_deadline {
                    let v: Value = ans.read_small(SMALL_BODY).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
                    if v.get("error").and_then(Value::as_str) == Some("bad_seq") {
                        if let Some(n) = v.get("nextSeq").and_then(Value::as_u64) {
                            // an earlier request has not reached the seller yet, or the seller's counters moved: the
                            // same request again, with the seq it takes. The open request moves with it
                            match self.seq_bad(hs, seq, n) {
                                Some(s) => seq = s,
                                None => std::thread::sleep(Duration::from_millis(10)),
                            }
                            // refused unserved, and signed so: it is sent again below, or not at all
                            spent.sent = false;
                            continue;
                        }
                    }
                    break (WireAnswer { status: 402, length: None, headers: vec![], body: Box::new(std::io::Cursor::new(serde_json::to_vec(&v).unwrap_or_default())), closer: None },
                           receipt);
                }
                break (ans, receipt);
            };
            drop(order);
            self.seq_done(hs, seq);
            let head = match receipt {
                Ok(r) => r,
                Err(why) => {
                    // an answer nobody signed charged nothing the wallet can know of
                    lock_money(hs).close(rid, 0, 0);
                    let status = ans.status;
                    let v: Value = ans.read_small(SMALL_BODY).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
                    let code = protocol_code(v.get("error"));
                    if code == "bad_seq" {
                        return fail(hs, &spent, refusal("ticket_seller", "the seller keeps answering bad_seq"));
                    }
                    // an answer nobody signed. A server error may be a proxy's, and a 408 is no one's fault
                    // ([`unsigned_and_no_fault`]); anything else is the seller serving or refusing without a receipt,
                    // or someone answering in its place: the session ends, and nothing was released on that answer's word
                    if unsigned_and_no_fault(status) {
                        // a 408 comes before anything serves the request; behind a proxy's 5xx it may have been served
                        spent.sent = status != 408;
                        return fail(hs, &spent, with(refusal("ticket_seller", format!("the seller answered HTTP {status} without a receipt")), json!({"status": status})));
                    }
                    let d = self.ticket_fault(hs, &format!("an answer to a paid request (HTTP {status} {code}) without a valid receipt: {why}"));
                    return fail(hs, &spent, with(d, json!({"status": status})));
                }
            };
            // the receipt's totals, inside what the wallet can account for ([`Money::take`])
            let metered = head.body_hash.is_empty() && ans.status < 400;
            let charged_max = match ans.status {
                // the seller's refusal of an answer larger than the size this GET or HEAD named (`larger_than_shown`):
                // charged as an answer with no body, at the request's price. Its status is what is judged: a HEAD has
                // no body to carry the code, and an honest gateway charges nothing for the service's own errors
                412 if c.max_size.is_some() && (c.method.eq_ignore_ascii_case("GET") || c.method.eq_ignore_ascii_case("HEAD")) => price.request_msat,
                s if s >= 400 => 0,
                _ if metered => price.request_msat.saturating_add(price.second_msat),
                _ => price.request_msat,
            };
            let (mark, streaming) = {
                let mut m = lock_money(hs);
                // this answer's head is drawn on the balance like any other's
                m.consumed = m.consumed.saturating_add(head.charged);
                if metered {
                    // what it may still add past what is counted of it: by its price, never past its call's limit
                    if let Some(left) = m.open.get_mut(&rid) {
                        *left = uncounted_most(price, reserve, max_msat, ticket_msat, head.charged, true);
                    }
                } else {
                    // a whole answer is paid for at its head: closed by its receipt
                    m.close(rid, head.charged, head.charged);
                }
                // a ticket another request released may be on its way: this head was signed before the seller took it
                let outstanding = m.pending.is_some();
                if let Err(why) = m.take(&head, charged_max, outstanding, Some(sent_epoch)) {
                    m.fault.get_or_insert(why);
                }
                let metered = metered && m.fault.is_none();
                if !metered {
                    m.close(rid, head.charged, head.charged);
                }
                // where this answer starts: the seller's spend before it, by this answer's own receipt, and the wallet's
                // count with its head in
                (Mark { base_spent: head.spent_msat.saturating_sub(head.charged), consumed: m.consumed, metered }, metered.then(|| Streaming::new(&hs.streaming)))
            };
            if let Some(why) = hs.fault() {
                return fail(hs, &spent, with(self.ticket_fault(hs, &why), json!({"status": ans.status})));
            }
            // a seller that gives accounts and has not been told who this wallet is (it restarted, say, or the session
            // opened on a route without accounts): told, and asked again, once. Asked by this request's route or the
            // session's, so a page on a route with accounts never gets the seller's refusal in place of its answer
            if ans.status == 403 && !identified_again && (identify_asked(&terms.accepted) || identify_asked(&hs.terms.accepted)) {
                let headers = ans.headers.clone();
                // an answer that cannot be read may be the seller asking who this wallet is: not handed on as an empty one
                let Ok(body) = ans.read_small(SMALL_BODY) else {
                    return fail(hs, &spent, with(refusal("ticket_refused", "the seller refused the request (HTTP 403) and its answer could not be read: \
                                                                           whether it asks to know who this wallet is first is not known"), json!({"status": 403})));
                };
                let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                if v.get("error").and_then(Value::as_str) == Some("identify_first") {
                    // the owner chose to stay anonymous here, and this service has no guest for such buyers: said in the
                    // wallet's own words, not handed on as the seller's refusal
                    if self.anonymous_at(&hs.origin, &hs.terms.terms.payee) {
                        return fail(hs, &spent, with(refusal("ticket_refused", "this service gives each buyer an account, and this wallet stays anonymous at \
                                                                               this seller (identity): it serves no anonymous buyer. Nothing was charged for this request"),
                                                     json!({"status": 403})));
                    }
                    identified_again = true;
                    // refused unserved, and signed so
                    spent.sent = false;
                    if self.ticket_identify(hs).is_ok() {
                        continue;
                    }
                    return fail(hs, &spent, with(refusal("ticket_refused", "the seller asks to know who this wallet is first, and could not be told"), json!({"status": 403})));
                }
                // any other refusal the seller signed (a path it does not serve, say) is its answer, handed on as it is
                ans = WireAnswer { status: 403, length: Some(body.len() as u64), headers, body: Box::new(std::io::Cursor::new(body)), closer: None };
            }
            if matches!(ans.status, 402 | 503) {
                let status = ans.status;
                let v: Value = ans.read_small(SMALL_BODY).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
                let code = protocol_code(v.get("error"));
                // refused unserved, and signed so: nothing of it is served or charged
                spent.sent = false;
                // signed by the seller: its balance is what it says, and the loop releases one ticket more if that is short
                if code == "balance_short" && short < 4 && hs.balance() < reserve {
                    short += 1;
                    continue;
                }
                // the seller's service is full: the request was not charged, and the session goes on
                if let Some(d) = (status == 503).then(|| seller_busy(&v)).flatten() {
                    return fail(hs, &spent, d);
                }
                return fail(hs, &spent, with(refusal("ticket_refused", format!("the seller refused the paid request: HTTP {status} {code}; nothing was charged for it")),
                                             json!({"status": status, "seller_code": code})));
            }
            break (rid, seq, digest, ans, head, mark, streaming);
        };
        let mut ans = ans;
        let status = ans.status;
        let mut out = json!({"verdict": "allow", "rule": "ok", "status": status});
        let mut sink = early.take().unwrap_or_else(|| Sink::for_call(c));
        // a 206 for another range than was asked is not read: what it has cost is what its head charged
        let (head_fields, not_read) = c.head(&mut ans, &mut sink);
        out = with(out, head_fields);
        let mut seller_last = Value::Null;
        let (price_msat, receipt_note) = if !mark.metered {
            // a whole answer: paid for at its head, its body hashed against the receipt
            let length = ans.length;
            let ended = match &not_read {
                Some(why) => Some(format!("not read: {why}")),
                None => self.read_paid_at_head(hs, ans, &mut sink),
            };
            let complete = ended.is_none() && length.is_none_or(|n| n == sink.bytes);
            let digest_now = hex::encode(sink.hash.clone().finalize());
            let note = if !complete {
                json!({"signed": true, "body": "cut short"})
            } else if digest_now != head.body_hash && c.method.eq_ignore_ascii_case("HEAD") {
                // a HEAD has no body to hash, and a seller may sign the one its GET would have had (an error's)
                json!({"signed": true, "body": "none: a HEAD"})
            } else if digest_now != head.body_hash {
                let why = "the body is not the one the receipt signs";
                out["seller_fault"] = self.ticket_fault(hs, why)["reason"].clone();
                json!({"signed": true, "body": "differs from the receipt"})
            } else {
                json!({"signed": true, "body": "as signed"})
            };
            out = with(out, json!({"complete": complete, "ended": ended}));
            if head.charged > max_msat && out.get("seller_fault").is_none() {
                let why = self.over_cap(hs, head.charged, max_msat, &head.raw);
                out["seller_fault"] = self.ticket_fault(hs, &why)["reason"].clone();
            }
            (head.charged, note)
        } else {
            let tokens = Some(c.body).filter(|b| price.tokens.active() && !b.is_empty())
                .and_then(|b| xbt402::tokens::prepare(b, price.tokens.max_output).ok().map(|p| (b.len() as u64, p.max_output)));
            let (m, note, last) = self.ticket_stream(hs, price, &head, &mark, rid, seq, &digest, ans, started, c.by, max_msat, &mut sink, &mut spent, not_read, tokens, reserve, up_writer);
            drop(streaming);
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
        range_ignored(&mut out, c);
        out["ms"] = json!((started.elapsed().as_secs_f64() * 10_000.0).round() / 10.0);
        out[UNTRUSTED_KEY] = untrusted(&text, head.raw);
        if !seller_last.is_null() {
            out[UNTRUSTED_KEY]["last_receipt"] = seller_last;
        }
        *lock(&hs.used) = self.engine.now();
        self.session_touch(&hs.sid);
        out
    }

    /// The body of an answer paid for at its head: nothing more is paid for it, but a seller that
    /// holds it open holds the call, and the session with its locked tickets, with it. So it has the
    /// limits of any other answer ([`open_limit`], [`Progress`]), a stop ends it whatever the seller
    /// is doing, and its session is marked as used. `Some`: why it ended early.
    fn read_paid_at_head(&self, hs: &Arc<HttpSession>, ans: WireAnswer, sink: &mut Sink) -> Option<String> {
        let tp = self.ticket_policy();
        let (open_s, limit) = open_limit(&tp, false, sink.out.is_some(), false);
        let max_open = Duration::from_secs(open_s.clamp(1, 86_400) as u64);
        let mut progress = Progress::new(&tp, limit);
        let length = ans.length;
        let closer = ans.closer;
        let mut body = ans.body;
        let done = AtomicBool::new(false);
        let (opened, mut touched) = (Instant::now(), Instant::now());
        std::thread::scope(|scope| {
            if let Some(close) = &closer {
                let done = &done;
                scope.spawn(move || loop {
                    if done.load(Ordering::SeqCst) {
                        return;
                    }
                    if hs.ending.load(Ordering::SeqCst) {
                        close();
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                });
            }
            let mut buf = vec![0u8; 64 << 10];
            let ended = loop {
                if hs.ending.load(Ordering::SeqCst) {
                    break Some("ticket_session: the session was stopped".to_string());
                }
                if opened.elapsed() >= max_open {
                    break Some(format!("{limit}: the answer has been open for {} s", max_open.as_secs()));
                }
                if touched.elapsed() >= Duration::from_secs(crate::ticket_rail::TOUCH_EVERY_S) {
                    touched = Instant::now();
                    *lock(&hs.used) = self.engine.now();
                    self.session_touch(&hs.sid);
                }
                let asked = Instant::now();
                let n = match body.read(&mut buf) {
                    Ok(0) => break length.filter(|l| *l != sink.bytes).map(|l| format!("cut short: {} of {l} bytes", sink.bytes)),
                    Ok(n) => n,
                    // a stop shuts the connection: said as the stop, not as the seller's doing
                    Err(_) if hs.ending.load(Ordering::SeqCst) => break Some("ticket_session: the session was stopped".to_string()),
                    Err(e) => break Some(format!("cut short: {:?}", e.kind())),
                };
                let slow = progress.read(asked.elapsed(), n as u64);
                sink.put(&buf[..n]);
                if sink.gone {
                    break Some(READER_GONE.into());
                }
                if sink.passed {
                    break Some(PASSED_SHOWN.into());
                }
                if slow.is_some() {
                    break slow;
                }
            };
            done.store(true, Ordering::SeqCst);
            ended
        })
    }

    /// The body of an answer that is priced as it goes: read as it arrives, a ticket released each
    /// time the balance no longer covers the next piece, and stopped (the connection closed) when
    /// the book refuses a release or the call's `max_sats` is used up. Then the seller's last
    /// receipt for the answer, checked against what was counted here. Returns fields for the reply
    /// and what the receipt check found. With `stop`, nothing of the body is read: the answer
    /// stopped at its head, for that reason.
    #[allow(clippy::too_many_arguments)]
    fn ticket_stream(&self, hs: &Arc<HttpSession>, price: &Price, head: &Receipt, mark: &Mark, rid: u64, seq: u64, digest: &str, ans: WireAnswer, started: Instant, call_by: Instant, max_msat: u64,
                     sink: &mut Sink, spent: &mut Spent, stop: Option<String>, tokens: Option<(u64, u64)>, reserve: u64, up_writer: Option<Box<dyn Write + Send>>)
                     -> (Value, Value, Value) {
        // by the token: the answer counted here as the seller counts it, to check its last receipt
        let event_stream = ans.header("content-type").is_some_and(|v| v.to_ascii_lowercase().starts_with("text/event-stream"));
        let mut sse = xbt402::tokens::Sse::default();
        let (mut counted, mut usage, mut whole_body) = (0u64, xbt402::tokens::Usage::default(), Vec::new());
        // a streamed answer by the token whose final counts (`usage` with no choices) or end (`[DONE]`) were read: its cost
        // is known, cut or not
        let mut counts_read = false;
        let tp = self.ticket_policy();
        let (open_s, limit) = open_limit(&tp, up_writer.is_some(), sink.out.is_some(), price.second_msat > 0);
        // an answer read whole, or by the second, within the call's deadline; one streamed on, or a socket, within its own limit
        let max_open = if limit == "max_answer_s" { call_by.saturating_duration_since(started) } else { Duration::from_secs(open_s.clamp(1, 86_400) as u64) };
        let st = Stream { price: *price, base_spent: mark.base_spent, started, max_msat, max_open, limit };
        // when the last byte of this answer was read: the seller's wait for the next ticket began about then
        let answer_status = ans.status;
        let last_byte = Mutex::new(Instant::now());
        // what this answer has drawn past its head, by this count: added to the session's as it grows, and taken off
        // what the request may still add to the seller's spend ([`Money::open`])
        let own = AtomicU64::new(0);
        let ticket_msat = hs.terms.terms.ticket_msat.max(1);
        // what was drawn only rises: the session's count never falls ([`Money::reserved`] holds what is not drawn yet)
        let set_own = |m: &mut Money, now: u64| {
            let had = own.load(Ordering::SeqCst);
            if now <= had {
                return;
            }
            m.consumed = m.consumed.saturating_add(now - had);
            own.store(now, Ordering::SeqCst);
            if let Some(left) = m.open.get_mut(&rid) {
                *left = uncounted_most(price, reserve, st.max_msat, ticket_msat, head.charged.saturating_add(now), true);
            }
        };
        let account = |cost_now: u64| {
            let add = cost_now.min(st.max_msat).saturating_sub(head.charged);
            let mut m = lock_money(hs);
            if add > own.load(Ordering::SeqCst) {
                set_own(&mut m, add);
            }
        };
        // an answer priced by the token costs what its tokens come to, known only at its end: until then it holds back the
        // most its request may cost past its head, so that the answers beside it do not count on credit it is spending.
        // Held apart from what was drawn ([`Money::reserved`]): an answer that started after it sees it in full
        let held = if tokens.is_some() { reserve.min(st.max_msat).saturating_sub(head.charged) } else { 0 };
        if held > 0 {
            let mut m = lock_money(hs);
            m.reserved = m.reserved.saturating_add(held);
        }
        // what the other answers of the session drew since this one started, by the wallet's count, and what they hold
        // back now
        let others = |m: &Money| m.consumed.saturating_sub(mark.consumed).saturating_sub(own.load(Ordering::SeqCst))
            .saturating_add(m.reserved.saturating_sub(held));
        let length = ans.length;
        let mut body = ans.body;
        let closer = ans.closer;
        // shared with the timer of an answer priced by the second: how far the body is, and why it stopped
        let state: Mutex<(u64, Option<String>, bool)> = Mutex::new((0, stop, false));
        let wake = Condvar::new();
        // what the call had released before its answer started: past it, what it releases is this answer's own credit
        let released_before = spent.released_msat;
        let spent_cell = Mutex::new(std::mem::take(spent));
        // what the seller credited the session, less what the other answers drew since this one started: what is
        // left for this one. What another answer drew counts its seller's word where that is more than the wallet read
        // of it: an answer cut short that the seller charged for bytes nobody read adds that to the count as it closes
        // ([`Money::close`]), so the answers beside it do not count on credit the seller has spent
        let credited = || {
            let m = lock_money(hs);
            m.acct.acked_msat.saturating_sub(others(&m))
        };
        // what the session had for this answer as it started: with the tickets its own call releases, and the holds of
        // answers by the token beside it that end undrawn, the credit it can draw
        let start_avail = st.avail(credited());
        let freed_before = lock_money(hs).freed;
        // one more ticket for this answer, or the reason there is none
        let up_writer_absent = up_writer.is_none();
        // `due`: the caller's own test of whether one is due, on the credit left for this answer
        let pay = |bytes: u64, due: &dyn Fn(u64) -> bool| -> Option<String> {
            if let Some(why) = st.over(bytes) {
                return Some(why);
            }
            // released only if still due once the session's `paying` is held, asked again of the credit left then:
            // another answer may have released one meanwhile, or drawn on or held back what this one found
            let still = || due(credited());
            // an answer by the byte stops at the edge of its credit, and its seller waits from there. One by the second, or
            // a socket, may be quiet for as long as it likes with its seller waiting for nothing
            let waiting_since = Some(if price.second_msat == 0 && up_writer_absent { *lock(&last_byte) } else { Instant::now() });
            let release = Due { opened: st.started, waiting_since, call_by: st.started + st.max_open, still_due: &still, answer: Some((seq, digest, answer_status)) };
            match self.ticket_release_one(hs, &mut lock(&spent_cell), &release) {
                Ok(()) => {
                    self.ticket_refill_later(hs);
                    None
                }
                Err(d) => Some(format!("{}: {}", str_or_empty(d.get("rule")), str_or_empty(d.get("reason")))),
            }
        };
        let mut read_error: Option<String> = None;
        let mut progress = Progress::new(&tp, limit);
        // a ticket being paid beside the reading, what it came to, and how far ahead the next one goes
        let paying = AtomicBool::new(false);
        let paid: Mutex<Option<(Option<String>, bool)>> = Mutex::new(None);
        let mut retry_at_due = false;
        // a WebSocket: what the reader at the socket sends goes to the seller, counted here, and paid
        // for with the bytes that come back. A watcher pays for both as they pass, since bytes on the
        // way out do not wake the reading of the way back
        let ws = up_writer.is_some();
        let up = AtomicU64::new(0);
        let (back, stopper) = if ws { (sink.back_channel(), sink.back_channel()) } else { (None, None) };
        let lead: Mutex<u64> = Mutex::new(0);
        std::thread::scope(|scope| {
            if let Some(w) = up_writer {
                match back {
                    Some(b) => {
                        let (up, wake) = (&up, &wake);
                        scope.spawn(move || {
                            forward_up(b, w, up);
                            wake.notify_all();
                        });
                    }
                    None => drop(w),
                }
                let (pay, credited, state, wake, up, stopper, st, account) = (&pay, &credited, &state, &wake, &up, &stopper, &st, &account);
                // the stream stops: both ways end, and the reading of the way back with them, quiet or not
                let stop = move || {
                    if let Some(st) = stopper {
                        let _ = st.shutdown(std::net::Shutdown::Both);
                    }
                };
                // the seller's signed count of this open answer, checked against the wallet's as it runs: on its own
                // thread, so a slow `status` never holds up the paying of the bytes. A fault found here ends the
                // socket at once, so the buyer's side sees it close (a VPN fails over) even while nothing flows
                scope.spawn(move || {
                    let mut last: Option<crate::ticket_interim::Seen> = None;
                    let mut polls = crate::ticket_interim::Polls::default();
                    let mut next = Instant::now() + crate::ticket_interim::poll_every();
                    loop {
                        {
                            let mut s = lock(state);
                            loop {
                                if s.2 || s.1.is_some() {
                                    return;
                                }
                                let now = Instant::now();
                                if now >= next {
                                    break;
                                }
                                s = wake.wait_timeout(s, next - now).unwrap_or_else(|p| p.into_inner()).0;
                            }
                        }
                        next = Instant::now() + crate::ticket_interim::poll_every();
                        let own = || (up.load(Ordering::SeqCst), lock(state).0);
                        if let Some(why) = self.ticket_interim(hs, seq, digest, &own, price, st.max_msat, &mut last, &mut polls) {
                            lock(state).1.get_or_insert(why);
                            stop();
                            wake.notify_all();
                            return;
                        }
                    }
                });
                scope.spawn(move || loop {
                    let mut s = lock(state);
                    if s.2 {
                        return;
                    }
                    if s.1.is_some() {
                        // stopped elsewhere (a fault, a limit): the socket ends with it
                        stop();
                        return;
                    }
                    // the session is being stopped: the stream ends here, and its last receipt is taken as it closes
                    if hs.ending.load(Ordering::SeqCst) {
                        s.1.get_or_insert_with(|| "ticket_session: the session was stopped".to_string());
                        stop();
                        return;
                    }
                    let total = s.0.saturating_add(up.load(Ordering::SeqCst));
                    account(st.cost(total));
                    let rate = total as f64 / st.started.elapsed().as_secs_f64().max(0.001);
                    let seen = credited();
                    let ahead = ((rate * FIRST_PAY_S) as u64).min(st.covered(seen) / 2);
                    if let Some(why) = st.over(total) {
                        s.1.get_or_insert(why);
                    } else if st.due_bytes_ahead(seen, total, None, ahead) {
                        drop(s);
                        let r = pay(total, &|c| st.due_bytes_ahead(c, total, None, ahead));
                        s = lock(state);
                        if let Some(why) = r {
                            s.1.get_or_insert(why);
                        }
                    }
                    if s.1.is_some() {
                        stop();
                        return;
                    }
                    let _ = wake.wait_timeout(s, Duration::from_millis(20)).unwrap_or_else(|p| p.into_inner());
                });
            }
            if let Some(close) = closer.as_ref().filter(|_| !ws) {
                // an answer read as it arrives waits in its read on a quiet seller (one at the edge of its credit, waiting
                // for a ticket that is not coming): stopped (the session, or a ticket that could not go), its connection
                // ends here, so the read returns now and not after the seller's own wait. A WebSocket's watcher does this
                // for a socket
                let (state, wake, st) = (&state, &wake, &st);
                scope.spawn(move || {
                    let mut s = lock(state);
                    loop {
                        if s.2 {
                            return;
                        }
                        if hs.ending.load(Ordering::SeqCst) {
                            s.1.get_or_insert_with(|| "ticket_session: the session was stopped".to_string());
                        }
                        // the call's deadline: a read on a quiet seller does not go on past it by a whole read timeout
                        if st.started.elapsed() >= st.max_open {
                            s.1.get_or_insert_with(|| format!("{}: the answer has been open for {} s", st.limit, st.max_open.as_secs()));
                        }
                        if s.1.is_some() {
                            break;
                        }
                        s = wake.wait_timeout(s, Duration::from_millis(20)).unwrap_or_else(|p| p.into_inner()).0;
                    }
                    drop(s);
                    close();
                });
            }
            if price.second_msat > 0 {
                // an answer priced by the second is paid by the clock: the next second's ticket goes shortly before it starts
                scope.spawn(|| loop {
                    let mut s = lock(&state);
                    if s.2 || s.1.is_some() {
                        return;
                    }
                    // the session is being stopped: the answer ends here, with the seconds already paid for
                    if hs.ending.load(Ordering::SeqCst) {
                        s.1.get_or_insert_with(|| "ticket_session: the session was stopped".to_string());
                        wake.notify_all();
                        return;
                    }
                    // the seconds started are drawn on the balance as they start, bytes or none
                    account(st.cost(s.0));
                    // the call's charge cap is used up by this clock, bytes or none (or the answer has been open as long
                    // as the owner allows): it ends here. A quiet answer whose credit covers its cap is due no ticket, and
                    // its read would otherwise wait on for the seller
                    if let Some(why) = st.over(s.0) {
                        s.1.get_or_insert(why);
                        wake.notify_all();
                        return;
                    }
                    // paid for in the last fifth of the second before it
                    let into = u64::from(st.started.elapsed().subsec_millis());
                    let seen = credited();
                    if into >= 800 && st.due_time(seen) {
                        let bytes = s.0;
                        drop(s);
                        if let Some(why) = pay(bytes, &|c| st.due_time(c)) {
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
            let mut unpaid: Option<String> = None;
            // why a ticket could not go early, if it has not gone since: the reason, if the seller ends the answer for want of it
            let mut refused_early: Option<String> = None;
            // a long answer keeps its session in use: not idle while bytes still arrive
            let mut touched = Instant::now();
            loop {
                if lock(&state).1.is_some() {
                    break;
                }
                // the session is being stopped: the answer is read no further, and ends as one cut short
                if hs.ending.load(Ordering::SeqCst) {
                    lock(&state).1.get_or_insert_with(|| "ticket_session: the session was stopped".to_string());
                    break;
                }
                if touched.elapsed() >= Duration::from_secs(crate::ticket_rail::TOUCH_EVERY_S) {
                    touched = Instant::now();
                    *lock(&hs.used) = self.engine.now();
                    self.session_touch(&hs.sid);
                }
                let asked = Instant::now();
                let was_paying = paying.load(Ordering::SeqCst);
                let n = match body.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        // the read's timeout is what the call's deadline left: that is what ended it, whichever saw it first
                        if e.kind() != std::io::ErrorKind::UnexpectedEof && st.started.elapsed() + Duration::from_secs(1) >= st.max_open {
                            lock(&state).1.get_or_insert_with(|| format!("{}: the answer has been open for {} s", st.limit, st.max_open.as_secs()));
                        }
                        read_error = Some(format!("{:?}", e.kind()));
                        break;
                    }
                };
                // a seller at the edge of its credit waits for the ticket being paid: that time is not its own
                let took = if was_paying || paying.load(Ordering::SeqCst) { Duration::ZERO } else { asked.elapsed() };
                let slow = progress.read(took, n as u64);
                sink.put(&buf[..n]);
                *lock(&last_byte) = Instant::now();
                hs.stalls.store(0, Ordering::SeqCst);
                if let Some((_, max_output)) = tokens {
                    if event_stream {
                        for ev in sse.feed(&buf[..n]).unwrap_or_default() {
                            counted = counted.saturating_add(ev.tokens).min(max_output);
                            if let Some(u) = ev.usage {
                                usage = u;
                                // counts on a chunk of text (a service that states them as it goes) are not the
                                // reply's cost: only its final ones are
                                counts_read |= ev.final_usage;
                            }
                            if is_done_event(&ev.bytes) {
                                counts_read = true;
                            }
                        }
                    } else if whole_body.len() < xbt402::tokens::MAX_WHOLE {
                        whole_body.extend_from_slice(&buf[..n]);
                    }
                }
                if sink.gone {
                    lock(&state).1.get_or_insert(READER_GONE.into());
                    break;
                }
                let bytes = sink.bytes;
                lock(&state).0 = bytes;
                if !ws {
                    account(st.cost(bytes));
                }
                wake.notify_all();
                if sink.passed {
                    lock(&state).1.get_or_insert(PASSED_SHOWN.into());
                    break;
                }
                if length.is_some_and(|l| bytes >= l) {
                    break;
                }
                if ws {
                    // a WebSocket is paid for by its watcher
                    continue;
                }
                if let Some(why) = st.over(bytes).or(slow) {
                    lock(&state).1.get_or_insert(why);
                    break;
                }
                // by bytes: the next ticket goes a little before what the released ones pay for has all
                // arrived. If it cannot go, what is paid for is still read, and the answer stops there.
                // It is paid beside the reading, not in its way, and early by as much body as arrives
                // while a payment takes: a prepaid ticket is a Lightning payment of a second or more,
                // and a body that waited for it would stall at every ticket. One payment at a time, so
                // the wallet is never more than one ticket ahead of the body
                // a ticket that could not go early (a pool not refilled yet, a seller not ready) is tried
                // again where it is due; only a refusal there ends the answer
                if let Some((r, early)) = lock(&paid).take() {
                    match r {
                        Some(why) if early => {
                            retry_at_due = true;
                            refused_early = Some(why);
                        }
                        r if unpaid.is_none() => {
                            unpaid = r;
                            retry_at_due = false;
                        }
                        _ => {}
                    }
                }
                if unpaid.is_none() && price.second_msat == 0 && !paying.load(Ordering::SeqCst) {
                    let rate = bytes as f64 / st.started.elapsed().as_secs_f64().max(0.001);
                    // before any payment of this answer was timed: what arrives in [`FIRST_PAY_S`], within half of what is paid for
                    let seen = credited();
                    let ahead = match *lock(&lead) {
                        _ if retry_at_due => 0,
                        0 => ((rate * FIRST_PAY_S) as u64).min(st.covered(seen) / 2),
                        l => l,
                    };
                    if st.due_bytes_ahead(seen, bytes, length, ahead) {
                        paying.store(true, Ordering::SeqCst);
                        refused_early = None;
                        let early = !st.due_bytes(seen, bytes, length);
                        let (before, asked) = (st.covered(seen), Instant::now());
                        let (pay, credited, paid, paying, lead_cell, st) = (&pay, &credited, &paid, &paying, &lead, &st);
                        scope.spawn(move || {
                            let r = pay(bytes, &|c| st.due_bytes_ahead(c, bytes, length, ahead));
                            let span = st.covered(credited()).saturating_sub(before);
                            // twice the body that arrived while this payment took, at most half a ticket's worth
                            *lock(lead_cell) = ((rate * asked.elapsed().as_secs_f64() * 2.0) as u64).min(span / 2);
                            *lock(paid) = Some((r, early));
                            paying.store(false, Ordering::SeqCst);
                        });
                    }
                } else if unpaid.is_none() && price.second_msat > 0 {
                    let seen = credited();
                    if st.due_bytes(seen, bytes, length) {
                        unpaid = pay(bytes, &|c| st.due_bytes(c, bytes, length));
                    }
                }
                // a ticket due and still being paid is waited for here, not the seller's next bytes: the seller
                // sends no more until it arrives, and one that cannot go (a session stopped meanwhile) ends the
                // answer now rather than after the seller's own wait. One that could not go early goes again now
                let seen = credited();
                if unpaid.is_none() && price.second_msat == 0 && paying.load(Ordering::SeqCst) && st.due_bytes(seen, bytes, length) {
                    while paying.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    if let Some((r, early)) = lock(&paid).take() {
                        unpaid = if r.is_some() && early { pay(bytes, &|c| st.due_bytes(c, bytes, length)) } else { r };
                        retry_at_due = false;
                    }
                    // one that went no further (it asked again and found the ticket not due, another answer's release having
                    // come meanwhile) and is due now goes now: the seller waits for it, and nothing else would wake the reading
                    if unpaid.is_none() && st.due_bytes(credited(), bytes, length) {
                        unpaid = pay(bytes, &|c| st.due_bytes(c, bytes, length));
                    }
                }
                if let Some(why) = unpaid.as_ref().filter(|_| bytes >= st.covered(credited())) {
                    lock(&state).1.get_or_insert(why.clone());
                    break;
                }
            }
            // a ticket still being paid beside the reading is waited for, and what it came to counted: a
            // seller that ended the answer for want of it ended it for that refusal, early or not
            while paying.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            if let Some((r, _)) = lock(&paid).take() {
                if unpaid.is_none() {
                    unpaid = r;
                }
            }
            // a seller that ended the answer where the paid bytes ran out ended it for the ticket that could not go
            // (not one that finished the body: a body read to its end needed no more tickets)
            if let Some(why) = unpaid.or(refused_early).filter(|_| read_error.is_some() || length.is_some_and(|l| lock(&state).0 < l)) {
                lock(&state).1.get_or_insert(why);
            }
            lock(&state).2 = true;
            wake.notify_all();
            // the way back has ended: so does the way out
            if let Some(st) = &stopper {
                let _ = st.shutdown(std::net::Shutdown::Both);
            }
        });
        // the connection is closed here: a seller that was still sending stops within what the balance covers
        drop(body);
        // and the reader's socket too: its client has the whole body now, not after the seller's last receipt is
        // fetched below, a round trip or more on a slow link (the call's reply still says what the answer cost)
        sink.out = None;
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
        let own_cost = match tokens {
            // a WebSocket's bytes either way
            None => price.cost(sink.bytes.saturating_add(up.load(Ordering::SeqCst)), secs).unwrap_or(u64::MAX),
            Some((body_len, max_output)) => {
                if !event_stream {
                    let (guess, u) = xbt402::tokens::whole(&whole_body);
                    (counted, usage) = (guess.min(max_output), u);
                }
                let t = xbt402::tokens::settle(body_len, max_output, counted, usage);
                price.tokens.cost(t).and_then(|c| c.checked_add(price.request_msat)).unwrap_or(u64::MAX)
            }
        };
        let own_digest = hex::encode(sink.hash.clone().finalize());
        // a reply by the token cut short before its final counts or its end: what it cost is not known, and its seller may
        // still charge it up to what it held back
        let cut_uncounted = tokens.is_some() && !complete && !counts_read;
        // what the answer drew is what it cost by the wallet's count now that it has ended (an answer by the token: its
        // tokens, where the most it could cost was drawn until now)
        let freed_since = {
            let mut m = lock_money(hs);
            let had = own.load(Ordering::SeqCst);
            let cost = own_cost.min(st.max_msat).saturating_sub(head.charged);
            // what it held back is drawn now, as far as it cost, and the rest comes back to the answers beside it; one
            // cut before its counts keeps all it held as drawn ([`Money::end_hold`])
            let drawn = m.end_hold(held, had, cost, cut_uncounted);
            set_own(&mut m, drawn);
            m.freed.saturating_sub(freed_before)
        };
        // what the wallet believes of the seller's charge for this answer, however its last receipt comes ([`Bound`])
        // the most its terms quote for a reply by the token: its request and the most its tokens may come to (what an
        // honest gateway charges at most, and what it held back while it ran)
        let quote = reserve.min(st.max_msat).max(head.charged);
        let bound = if complete {
            Bound { most: own_cost.min(st.max_msat), max_msat, whole: Some((own_cost, own_digest.clone())), share: None, quoted: None }
        } else if tokens.is_some() {
            // cut after its final counts or its end: what they come to, and a few tokens more; before them, the quote,
            // and a charge past it is the seller's fault
            if counts_read {
                let most = own_cost.saturating_add(price.tokens.output_due(counted, TOKEN_SLACK).unwrap_or(u64::MAX)).min(quote);
                Bound { most, max_msat, whole: None, share: None, quoted: None }
            } else {
                Bound { most: quote, max_msat, whole: None, share: None, quoted: Some(quote) }
            }
        } else {
            let read = sink.bytes.saturating_add(up.load(Ordering::SeqCst));
            let credit = start_avail.saturating_add(spent.released_msat.saturating_sub(released_before)).saturating_add(freed_since);
            let slack = price.cost(CUT_SLACK, 0).unwrap_or(u64::MAX);
            let share = Share { base_spent: st.base_spent, mark_consumed: mark.consumed, own: own.load(Ordering::SeqCst),
                                read: price.cost(read.saturating_add(CUT_SLACK), secs).unwrap_or(u64::MAX), slack };
            Bound { most: st.cut_bound(read, secs, credit), max_msat, whole: None, share: Some(share), quoted: None }
        };
        // what the request may still add to the seller's spend, now that it has ended: no more than the most the wallet
        // could believe of any charge for it, not what is left of its call's limit ([`Money::take`]). Nothing, for one
        // that arrived whole or a reply held at its quote; for one cut short, its fixed bound (`most`), never below what
        // its share of the session's credit allows as it is closed ([`Bound::most`]), so an honest charge believed then
        // was inside it
        {
            let mut m = lock_money(hs);
            let counted = head.charged.saturating_add(own.load(Ordering::SeqCst));
            let left = bound.allowance(counted);
            if let Some(l) = m.open.get_mut(&rid) {
                *l = left;
            }
        }
        // the last receipt of this answer, from the seller's signed status. One that arrived whole is waited for longer
        // before it is left unclosed: the seller has sent all of it, and an unclosed answer holds up the session's releases
        let mut deadline = Instant::now() + if complete { FINAL_WAIT_WHOLE } else { FINAL_WAIT };
        // a call with the caller's limit to keep: a few seconds past its deadline at most
        if st.limit == "max_answer_s" {
            deadline = deadline.min((call_by + FINAL_PAST_CALL).max(Instant::now() + Duration::from_secs(1)));
        }
        let mut last: Option<Receipt> = None;
        // what the wallet believed of its charge, as it closed it here
        let mut believed_at = None;
        let mut why_none = String::from("the seller's status did not list it");
        loop {
            // each call no longer than what is left of the wait (a second at least): a seller slow to answer status
            // does not hold the answer open past its deadline by a whole read timeout
            let left = deadline.saturating_duration_since(Instant::now()).max(Duration::from_secs(1));
            match self.ticket_call_within(hs, "status", &json!({}), false, Some(left)) {
                Ok((200, v, Ok(status_r), sent_epoch)) => {
                    let sid = lock_link(hs).seller_sid.clone();
                    let found = v.get("responses").and_then(Value::as_array).into_iter().flatten()
                        .filter_map(|r| Receipt::verify(r, &hs.terms.receipt_key, &sid).ok())
                        .find(|r| r.for_request(seq, digest, c_status(head)).is_ok() && !r.body_hash.is_empty());
                    let done = found.is_some() || Instant::now() >= deadline;
                    if done {
                        let mut m = lock_money(hs);
                        // the answer's last receipt closes it: what the seller charged it is its word, as far as the wallet
                        // believes it ([`Bound`]), and the request adds nothing more to the seller's spend
                        let mut wrong = None;
                        let mut overcharged = false;
                        if let Some(r) = &found {
                            let (believed, why) = bound.judge(r, &m);
                            overcharged = r.charged > max_msat || bound.overcharges(r);
                            if overcharged {
                                m.evidence.get_or_insert_with(|| r.raw.clone());
                            }
                            wrong = if r.charged > max_msat { Some(self.over_cap(hs, r.charged, max_msat, &r.raw)) } else { why };
                            m.close_by(rid, believed, head.charged.saturating_add(own.load(Ordering::SeqCst)), &bound);
                            believed_at = Some(believed);
                        }
                        // the seller's fault is the session's at once, under the same lock: no answer beside this one
                        // releases another ticket to it from then on (one whose secret is already leaving the book, at
                        // most one, still goes: the fault is asked just before the book, not under its lock)
                        if let Some(why) = &wrong {
                            m.overcharged |= overcharged;
                            m.fault.get_or_insert_with(|| why.clone());
                        }
                        let wrong = wrong.is_some();
                        // then the status's totals, inside what the wallet can account for. Not where the answer's own
                        // receipt is the seller's fault: that is said with its numbers below
                        if !wrong {
                            let outstanding = m.pending.is_some();
                            if let Err(why) = m.take(&status_r, 0, outstanding, Some(sent_epoch)) {
                                m.fault.get_or_insert(why);
                            }
                        }
                        last = found;
                        break;
                    }
                }
                Ok((status, _, _, _)) => {
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
        {
            let mut m = lock_money(hs);
            // what this answer drew, by the wallet's count, is now the seller's word (its receipt, taken above) or its
            // own last count: the session's count keeps it
            if last.is_none() {
                m.tails.push(Tail { rid, seq, digest: digest.to_string(), status: c_status(head), since: Instant::now(),
                                    counted: head.charged.saturating_add(own.load(Ordering::SeqCst)), bound: bound.clone() });
            }
        }
        let mut fault = hs.fault();
        let mut seller_last = Value::Null;
        let note = match &last {
            None => json!({"signed": false, "last": Value::Null, "why": why_none}),
            Some(r) => {
                if let (_, Some(why)) = bound.judge(r, &lock_money(hs)) {
                    fault.get_or_insert(why);
                }
                // the receipt as the wallet read it: its numbers. The seller's own object is under the untrusted field.
                seller_last = r.raw.clone();
                json!({"signed": true, "last": {"seq": r.seq, "releasedMsat": r.released_msat.to_string(), "spentMsat": r.spent_msat.to_string(),
                                                "charged": r.charged.to_string(), "status": r.status},
                       "body": if !complete { "cut short" } else if r.body_hash == own_digest { "as signed" } else { "differs from the receipt" }})
            }
        };
        // the call's own limit, which the request named to the seller (X-Xbt402-Max-Msat): a seller that charged past it
        // ignored it, and is paid nothing more. What it took is told with the numbers, and its receipt kept
        if let Some(r) = last.as_ref().filter(|r| r.charged > max_msat) {
            fault.get_or_insert_with(|| self.over_cap(hs, r.charged, max_msat, &r.raw));
        }
        // the price of the answer: the seller's signed charge where it stands inside the wallet's own count, else that count
        // (one cut short: as far as the wallet believed it, but for a charge past the call's limit, which is said as
        // the seller made it, with its fault). The wallet's own count is never past the call's charge cap, which it read
        // no further than: by the second, the seconds since the cut would count on here otherwise
        let price_msat = last.as_ref().map(|r| r.charged).filter(|c| *c <= own_cost || !complete)
            .map(|c| if complete || c > max_msat { c } else { believed_at.map_or(c, |b| c.min(b)) }).unwrap_or_else(|| st.cost(sink.bytes).min(max_msat));
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
        self.ticket_http_stop_with(hs, why, wait, true)
    }

    /// [`Signer::ticket_http_stop`]; `released_too: false` names for the cancel only tickets whose secret never left
    /// (sent, locked, or offered and unpaid): never one released, or retired (that may have been), or settled.
    fn ticket_http_stop_with(&self, hs: &HttpSession, why: &str, wait: Duration, released_too: bool) -> Value {
        // from here no ticket is released in the session, no new call takes it, and its open answers end: a stream
        // (a WebSocket, a VPN tunnel, a body read as it comes) stops reading and takes its last receipt as it closes.
        // The book is told first: it still shows the session open while the streams end, and books nothing more for it
        // (a release, a lock, a prepaid ticket), however far a call had got (past every check of `ending`) when the stop came
        lock(&self.ticket_stopping).insert(hs.sid.clone());
        hs.ending.store(true, Ordering::SeqCst);
        // a stop for any other reason than the seller's forgetting, even one that comes after it: a call refused by the
        // session's end is not made again ([`HttpSession::forgotten`])
        if why != FORGOTTEN_WHY {
            hs.forgotten.store(false, Ordering::SeqCst);
        }
        // a stop that may wait (the caller's own) waits for those last receipts, so that what the session leaves with
        // the seller below counts what the streams drew. Waited for here, holding nothing of the session or its slot
        // (the slot still names the session meanwhile, so that a new call to the seller is told to call again rather
        // than opening another session beside it); a stop with no wait (one made inside an answer, at a fault, or by
        // the wallet itself) does not wait, and one made inside an answer must not: that answer is among the open streams
        if !wait.is_zero() {
            let streams_by = Instant::now() + wait.max(STOP_STREAMS_WAIT);
            while hs.streaming.load(Ordering::SeqCst) > 0 && Instant::now() < streams_by {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
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
        let still_streaming = hs.streaming.load(Ordering::SeqCst) > 0;
        let stopped = {
            let _g = self.lock();
            let stopped = self.ticket_stop_locked(&json!({"session": hs.sid, "why": why}));
            // the book's own state says it from here (kept where the book could not be written: it stays refused)
            if self.ticket_session(&hs.sid).is_none_or(|s| s.state != SState::Open) {
                lock(&self.ticket_stopping).remove(&hs.sid);
            }
            stopped
        };
        let mut asked: Vec<String> = stopped.get("cancel").and_then(Value::as_array).into_iter().flatten().filter_map(|h| h.as_str().map(str::to_string)).collect();
        if !released_too {
            let never_released = |h: &String| self.ticket_store().ok().and_then(|g| g.as_ref().and_then(|st| st.book.tickets.get(h).map(|t| t.state)))
                .is_some_and(|s| matches!(s, TState::Offered | TState::Sending | TState::Locked | TState::Failed));
            asked.retain(never_released);
        }
        let mut sent = false;
        if !asked.is_empty() && !lock_link(hs).seller_sid.is_empty() {
            // by their hashes, never "all" of the seller session: a new session of this wallet may have taken it over by the
            // time this leaves, and its tickets are not this session's to cancel
            sent = in_parts(&asked, hs.terms.terms.max_tickets)
                .map(|part| matches!(self.ticket_call(hs, "cancel", &json!({"hashes": part}), false), Ok((200, _, _)))).filter(|answered| !answered).count() == 0;
        }
        let still = self.ticket_wait_cancelled(&hs.sid, if sent { wait } else { Duration::ZERO });
        // what the seller was paid and did not serve: under one ticket, since a ticket is released only when
        // the balance does not cover the next request. It is the seller's now; the owner sees it here and in the audit.
        // A stream that would not end in time is still drawing: the wallet's own count of it, not only the seller's
        // last receipt, comes off what is told as left
        let left = if still_streaming {
            // one lock of the money for both: `balance` takes it too
            let m = lock_money(hs);
            m.est_balance().min(m.acct.balance())
        } else {
            hs.balance()
        };
        if left > 0 {
            self.ticket_audit("ticket_left_with_seller", json!({"session": hs.sid, "dest": format!("ln:{}", hs.terms.terms.payee), "origin": hs.origin,
                                                                "left_msat": left.to_string(), "why": why}));
        }
        json!({"session": hs.sid, "why": why, "cancel_asked": asked.len(), "cancel_sent": sent, "still_locked": still, "left_with_seller_msat": left.to_string(),
               "account": hs.public()})
    }

    /// Reconcile with the wallet's node until no ticket of the session is locked and unreleased, or
    /// `wait` has passed. Returns the hashes still locked; `Null` when the book could not be read,
    /// which is not "none".
    fn ticket_wait_cancelled(&self, sid: &str, wait: Duration) -> Value {
        let deadline = Instant::now() + wait;
        loop {
            // the node is asked with no lock held: a stop does not hold up the rest of the wallet on a slow node
            self.ticket_refresh_coming(sid, &|| false, deadline.max(Instant::now() + Duration::from_millis(500)));
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

    /// Whether this process may have `sid` open, for the watcher, which waits for no call: a place a
    /// call holds right now (one waiting on a seller's word, say) may be that session's.
    fn ticket_http_maybe_of(&self, sid: &str) -> bool {
        let slots: Vec<Arc<Slot>> = lock(&self.ticket_http).values().cloned().collect();
        slots.iter().any(|s| s.open.try_lock().map_or(true, |open| open.as_ref().is_some_and(|h| h.sid == sid)))
    }

    /// The sessions of this process with a call or an answer open: never idle, whatever the book last
    /// saw of them. Waits for no call.
    pub(crate) fn ticket_sessions_in_use(&self) -> HashSet<String> {
        let slots: Vec<Arc<Slot>> = lock(&self.ticket_http).values().cloned().collect();
        slots.iter().filter_map(|s| s.open.try_lock().ok().and_then(|open| open.as_ref().filter(|h| h.streaming.load(Ordering::SeqCst) > 0 || h.calls.try_write().is_err()).map(|h| h.sid.clone()))).collect()
    }

    /// The seller sessions this process holds for sessions of its own other than `sid`.
    fn ticket_seller_sessions_held(&self, sid: &str) -> HashSet<String> {
        let slots: Vec<Arc<Slot>> = lock(&self.ticket_http).values().cloned().collect();
        slots.iter().filter_map(|s| s.open.try_lock().ok().and_then(|open| open.as_ref().filter(|h| h.sid != sid).map(|h| lock_link(h).seller_sid.clone()))).filter(|id| !id.is_empty()).collect()
    }

    /// `ticket_stop`: stop a session. Where the wallet itself speaks to the seller, it also asks
    /// for the cancel and reports what its own node then shows; otherwise it names the tickets for
    /// the caller to have cancelled, as before.
    /// `forget_credit: true`: what the session leaves with the seller is given up, and no later
    /// session takes it over (a caller that wants to start clean with the seller).
    pub(crate) fn ticket_stop(&self, p: &Value) -> Value {
        if p.get("forget_credit") != Some(&Value::Bool(true)) {
            return self.ticket_stop_inner(p);
        }
        let sid = str_or_empty(p.get("session"));
        // a session already stopped is not stopped again (nor its seller asked again to cancel): only its credit goes
        let stopped = self.ticket_http_of(&sid).is_none() && self.ticket_session(&sid).is_some_and(|s| s.state != SState::Open);
        let out = if stopped { json!({"verdict": "allow", "session": sid, "already_stopped": true}) } else { self.ticket_stop_inner(p) };
        // what is given up, as the seller counts it, for a session stopped earlier (a stop now reports its own): the
        // seller's word, asked of the seller session on record; nothing where it does not answer
        let session = stopped.then(|| self.ticket_session(&sid)).flatten();
        let counts = session.as_ref().and_then(|s| self.ticket_seller_counts(s));
        let left = counts.map(|(left, _)| left);
        match self.ticket_forget_credit(&sid) {
            Ok(()) => {
                self.ticket_audit("ticket_credit_given_up", json!({"session": sid, "left_with_seller_msat": left.map(|m| m.to_string())}));
                with(out, json!({"credit_given_up": true, "left_with_seller_msat": left.map(|m| m.to_string()),
                                 "seller_released_msat": counts.map(|(_, released)| released.to_string()),
                                 "seller_session": session.as_ref().and_then(|s| s.http.as_ref()).map(|h| h.id.clone())}))
            }
            Err(e) => with(out, json!({"credit_given_up": false, "forget_credit": e.msg})),
        }
    }

    fn ticket_stop_inner(&self, p: &Value) -> Value {
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

    /// What the seller says it has credited in the seller session of `s`, as its `status` answers
    /// (`None`: no answer): for the owner's record, unsigned as read here.
    fn ticket_seller_released(&self, s: &crate::ticket::Session) -> Option<u64> {
        let http = s.http.as_ref()?;
        let origin = origin_of(&http.base).map(|o| normalize_dest(&o)).unwrap_or_default();
        if origin.is_empty() || normalize_dest(&s.origin) != origin || seller_url(&origin, &http.base).is_err() || !self.ticket_may_reach(&origin, &s.task) {
            return None;
        }
        let net = self.ticket_net().ok().and_then(|n| xbt402::ticket::legacy_network_id(&n)).unwrap_or_default();
        let accepted = json!({"scheme": xbt402::ticket::SCHEME, "network": net});
        let url = format!("{}/status", http.base);
        let raw = b"{}".to_vec();
        let mut seq = 0u64;
        for _ in 0..2 {
            let auth = xbt402::ticket::request_auth(&http.key, &http.id, seq, "", "", &request_digest_v2("POST", &url, &raw));
            let header = b64json(&payment_payload(&accepted, &json!({"session": http.id, "seq": seq, "auth": auth})));
            let ans = self.wire("POST", &url, &raw, &[("Content-Type".into(), "application/json".into()), ("PAYMENT-SIGNATURE".into(), header)], Duration::from_secs(10)).ok()?;
            let status = ans.status;
            let v: Value = ans.read_small(SMALL_BODY).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
            match (status, v.get("nextSeq").and_then(Value::as_u64)) {
                (200, _) => return v.get("session").and_then(|x| x.get("releasedMsat")).and_then(|x| crate::ticket::outside_u64(Some(x))),
                (_, Some(next)) => seq = next,
                _ => return None,
            }
        }
        None
    }

    /// Names the seller of a prepaid ticket past its invoice's life and the wait for it that has not
    /// credited it: in flight (a hop or the seller holds the payment), or paid (the seller has the
    /// money). Only the owner's record can say so, since the session was stopped as nobody's fault.
    /// Once a ticket, at most.
    fn ticket_prepaid_overdue_tick(&self) {
        for (t, s) in self.ticket_prepaid_overdue() {
            let key = format!("overdue:{}", t.hash);
            let now = self.engine.now();
            if lock(&self.ticket_cancel_tried).contains(&key) || lock(&self.ticket_late_tries).get(&key).is_some_and(|(_, at)| now < *at) {
                continue;
            }
            let released = self.ticket_seller_released(&s);
            // no answer says nothing of its credit: the owner is told so, once, and it is asked again later, doubling, for
            // as long as the credit could be taken over
            if released.is_none() && now - t.done_ts.max(t.sent_ts) <= crate::ticket_rail::LATE_PREPAID_WITHIN_S {
                let mut tries = lock(&self.ticket_late_tries);
                let e = tries.entry(key).or_insert((0, now));
                e.0 = e.0.saturating_add(1);
                e.1 = now + (LATE_SHOW_FIRST_WAIT_S * f64::from(1u32 << e.0.min(16).saturating_sub(1))).min(LATE_SHOW_MOST_WAIT_S);
                let first = e.0 == 1;
                drop(tries);
                if first {
                    self.ticket_audit("ticket_prepay_unanswered", json!({"session": s.id, "origin": s.origin, "dest": format!("ln:{}", t.payee), "hash": t.hash,
                                                                         "reason": "past the wait for a prepaid ticket this seller did not answer: nothing is known of its credit yet, and it is asked again"}));
                }
                continue;
            }
            lock(&self.ticket_cancel_tried).insert(key.clone());
            lock(&self.ticket_late_tries).remove(&key);
            let sent = s.http.as_ref().map_or(0, |h| self.ticket_sent_in(&h.id));
            if released.is_some_and(|r| r >= sent) {
                continue;
            }
            self.ticket_audit("ticket_prepay_overdue", json!({"session": s.id, "origin": s.origin, "dest": format!("ln:{}", t.payee), "hash": t.hash, "invoice_expired": crate::pyjson::ts_value(t.invoice_expires),
                                                              "seller_released_msat": released.map(|r| r.to_string()), "sent_msat": sent.to_string(),
                                                              "reason": if released.is_none() {
                                                                  "a prepaid ticket's seller did not answer for as long as its credit could be taken over: nothing is known of that credit"
                                                              } else if t.state == crate::ticket::TState::Settled {
                                                                  "the wallet's node shows a prepaid ticket paid, and past the wait for it this seller has not credited it: it has the money, and the ticket's credit is not to be had"
                                                              } else {
                                                                  "a prepaid ticket's payment is still in flight past its invoice's life, and this seller has not credited it: a hop on the route, or the seller, holds it"
                                                              }}));
        }
    }

    /// Ask the seller of a session on record to cancel the tickets it may still hold of that session,
    /// by their hashes: for a session this process did not open (the wallet started again). The
    /// answer is not checked: the node's word is.
    fn ticket_cancel_recorded(&self, s: &crate::ticket::Session, wait: Duration) -> Value {
        let Some(http) = &s.http else { return Value::Null };
        {
            let _g = self.lock();
            self.ticket_stop_locked(&json!({"session": s.id}));
        }
        // the URL is the one the wallet fetched terms from when it opened the session, and the owner must still allow its origin
        let origin = origin_of(&http.base).map(|o| normalize_dest(&o)).unwrap_or_default();
        let allowed = !origin.is_empty() && (normalize_dest(&s.origin) == origin) && seller_url(&origin, &http.base).is_ok() && self.ticket_may_reach(&origin, &s.task);
        // this session's own tickets that the seller may hold. Never "all" of the seller session: a new session of this
        // wallet may have taken that seller session over since (`ticket_resume`), and its tickets are not this session's
        // to cancel. At most the seller's cap a request; one that holds nothing asks for nothing
        let hashes: Vec<String> = match self.ticket_store() {
            Ok(g) => g.as_ref().map(|st| st.book.of_session(&s.id).into_iter().filter(|t| t.may_take_a_place(self.engine.now())).map(|t| t.hash.clone()).collect()).unwrap_or_default(),
            Err(_) => vec![],
        };
        let sent = allowed && !hashes.is_empty() && in_parts(&hashes, s.max_tickets)
            .map(|part| matches!(self.ticket_recorded_call(s, "cancel", &json!({"hashes": part})), Some((200, _)))).filter(|answered| !answered).count() == 0;
        let still = self.ticket_wait_cancelled(&s.id, if sent { wait } else { Duration::ZERO });
        self.ticket_audit("ticket_cancel_asked", json!({"session": s.id, "dest": format!("ln:{}", s.payee), "sent": sent, "still_locked": still.as_array().map(Vec::len)}));
        json!({"session": s.id, "cancel_sent": sent, "still_locked": still})
    }

    /// A signed request (`cancel`, `release`) to the seller of a session on record that this process
    /// did not open: at the address it was opened at, which the owner must still allow. The
    /// session's seq went with the earlier process: the seller says which is next, and the request
    /// goes once more with it. The seller's answer, or `None` where nothing was sent or answered.
    fn ticket_recorded_call(&self, s: &crate::ticket::Session, what: &str, body: &Value) -> Option<(u16, Value)> {
        let http = s.http.as_ref()?;
        // the URL is the one the wallet fetched terms from when it opened the session, and the owner must still allow its origin
        let origin = origin_of(&http.base).map(|o| normalize_dest(&o)).unwrap_or_default();
        if origin.is_empty() || normalize_dest(&s.origin) != origin || seller_url(&origin, &http.base).is_err() || !self.ticket_may_reach(&origin, &s.task) {
            return None;
        }
        // the session's entry is not kept across a start: one is written for the request. Under the network's name of
        // before 2026-10, for the release in which a gateway reads both names: a gateway of before reads only that one
        let net = self.ticket_net().ok().and_then(|n| xbt402::ticket::legacy_network_id(&n)).unwrap_or_default();
        let accepted = json!({"scheme": xbt402::ticket::SCHEME, "network": net});
        let url = format!("{}/{what}", http.base);
        let raw = body.to_string().into_bytes();
        let mut seq = 0u64;
        let mut last = None;
        for _ in 0..2 {
            let digest = request_digest_v2("POST", &url, &raw);
            let auth = xbt402::ticket::request_auth(&http.key, &http.id, seq, "", "", &digest);
            let header = b64json(&payment_payload(&accepted, &json!({"session": http.id, "seq": seq, "auth": auth})));
            let Ok(ans) = self.wire("POST", &url, &raw, &[("Content-Type".into(), "application/json".into()), ("PAYMENT-SIGNATURE".into(), header)],
                                    Duration::from_secs(10)) else { break };
            let status = ans.status;
            let v: Value = ans.read_small(SMALL_BODY).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
            let next = v.get("nextSeq").and_then(Value::as_u64);
            let bad_seq = status == 402 && v.get("error").and_then(Value::as_str) == Some("bad_seq");
            last = Some((status, v));
            match (bad_seq, next) {
                // the seq this wallet used last was lost with its memory: the seller says which is next
                (true, Some(n)) => seq = n,
                _ => break,
            }
        }
        last
    }

    /// What the seller of a session on record says that session's seller side still holds: its word,
    /// for a report. `None` where it was not asked (the owner no longer allows it) or did not say.
    fn ticket_seller_balance(&self, s: &crate::ticket::Session) -> Option<u64> {
        self.ticket_seller_counts(s).map(|(balance, _)| balance)
    }

    /// [`Self::ticket_seller_balance`], and all the seller has credited in that seller session.
    fn ticket_seller_counts(&self, s: &crate::ticket::Session) -> Option<(u64, u64)> {
        let (_, v) = self.ticket_recorded_call(s, "status", &json!({})).filter(|(status, _)| *status == 200)?;
        let count = |k: &str| v["session"][k].as_str().and_then(|b| b.parse().ok());
        Some((count("balanceMsat")?, count("releasedMsat")?))
    }

    /// Present to their sellers the preimages of settled prepaid tickets no call was seen to deliver
    /// (a call that ended first, a process stopped before the seller answered): the seller credits a
    /// prepaid ticket when it is shown its preimage (or later, by its own sweep), and a session that
    /// takes the seller session over needs the seller's count to be the wallet's. Through `via` (a
    /// session open on that same seller's session, a takeover: once, for the sessions named), or else
    /// by each session's seller session on record, at the address on record (the watcher: of every
    /// session this process does not have open, whose own delivery is still its to finish).
    ///
    /// What the seller answers for each: taken, now or before, and it is not presented again;
    /// refused for good, or the seller has forgotten the session, or the credit could no longer be
    /// taken over (`LATE_PREPAID_WITHIN_S`), and it is given up; for the moment, or no answer, and
    /// the watcher tries again later and later. No preimage is logged.
    fn ticket_show_late_prepaid(&self, via: Option<&HttpSession>, sessions: Option<&[String]>) -> Vec<Value> {
        let Some(ln) = self.ln.clone() else { return vec![] };
        let now = self.engine.now();
        let mut by: HashMap<String, Vec<(String, String)>> = HashMap::new();
        let mut msat_of: HashMap<String, u64> = HashMap::new();
        for (sid, hash, settled, msat) in self.ticket_late_prepaid(sessions) {
            msat_of.insert(hash.clone(), msat);
            if via.is_none() {
                if now - settled > crate::ticket_rail::LATE_PREPAID_WITHIN_S {
                    self.ticket_late_prepaid_done(std::slice::from_ref(&hash), false);
                    self.ticket_audit("ticket_prepaid_given_up", json!({"session": sid, "payment_hash": hash, "given_up": 1, "msat": msat.to_string(), "why": "its credit can no longer be taken over"}));
                    continue;
                }
                if self.ticket_http_maybe_of(&sid) || lock(&self.ticket_late_tries).get(&hash).is_some_and(|(_, at)| now < *at) {
                    continue;
                }
            }
            let Ok(Some(p)) = ln.lookup(&hash) else { continue };
            let pre = crate::ln::preimage_bytes(&p);
            if crate::ln::preimage_proves(&pre, &hash) {
                by.entry(if via.is_some() { String::new() } else { sid }).or_default().push((hash, hex::encode(&pre)));
            }
        }
        let mut out = vec![];
        for (sid, items) in by {
            let session = self.ticket_session(&sid);
            let most = via.map_or(session.as_ref().map_or(1, |s| s.max_tickets), |h| h.terms.terms.max_tickets);
            for part in in_parts(&items, most) {
                let body = json!({"secrets": part.iter().map(|(_, p)| p.as_str()).collect::<Vec<_>>()});
                // through a takeover's session only a signed answer is taken for an end of the matter: that call is with whoever
                // answers at this address. By the session on record it is with the address that took the payment
                let answer = match via {
                    Some(hs) => self.ticket_call(hs, "release", &body, false).ok().filter(|(_, _, signed)| signed.is_ok()).map(|(status, v, _)| (status, v)),
                    None => session.as_ref().and_then(|s| self.ticket_recorded_call(s, "release", &body)),
                };
                let hashes: Vec<String> = part.iter().map(|(h, _)| h.clone()).collect();
                let (mut shown, mut credited, mut gave_up, mut again) = (vec![], 0usize, vec![], vec![]);
                match &answer {
                    Some((200, v)) => {
                        let listed = |k: &str, h: &str| v.get(k).and_then(Value::as_array).into_iter().flatten()
                            .find(|x| x.as_str() == Some(h) || x.get("hash").and_then(Value::as_str) == Some(h)).cloned();
                        for h in &hashes {
                            if listed("released", h).is_some() {
                                credited += 1;
                                shown.push(h.clone());
                            } else if let Some(no) = listed("refused", h) {
                                match protocol_code(no.get("error")) {
                                    "ticket_used" => shown.push(h.clone()),
                                    "ticket_not_locked" | "node_unavailable" => again.push(h.clone()),
                                    _ => gave_up.push(h.clone()),
                                }
                            } else {
                                again.push(h.clone());
                            }
                        }
                    }
                    Some((_, v)) if protocol_code(v.get("error")) == "session_unknown" => gave_up = hashes.clone(),
                    _ => again = hashes.clone(),
                }
                let about = if sid.is_empty() { via.map(|h| h.sid.clone()).unwrap_or_default() } else { sid.clone() };
                if !shown.is_empty() {
                    self.ticket_late_prepaid_done(&shown, true);
                    let line = json!({"session": about, "shown": shown.len(), "credited_now": credited});
                    self.ticket_audit("ticket_prepaid_shown", line.clone());
                    out.push(json!({"ticket_prepaid_shown": line}));
                }
                if !gave_up.is_empty() {
                    self.ticket_late_prepaid_done(&gave_up, false);
                    let msat: u64 = gave_up.iter().filter_map(|h| msat_of.get(h)).sum();
                    self.ticket_audit("ticket_prepaid_given_up", json!({"session": about, "given_up": gave_up.len(), "msat": msat.to_string(), "why": "the seller will not take its preimage"}));
                }
                let mut tries = lock(&self.ticket_late_tries);
                for h in shown.iter().chain(&gave_up) {
                    tries.remove(h);
                }
                for h in again {
                    let e = tries.entry(h).or_insert((0, now));
                    e.0 = e.0.saturating_add(1);
                    e.1 = now + (LATE_SHOW_FIRST_WAIT_S * f64::from(1u32 << e.0.min(16).saturating_sub(1))).min(LATE_SHOW_MOST_WAIT_S);
                }
            }
        }
        out
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
            let Ok(_none) = hs.calls.try_write() else { continue };
            if idle > tp.http_idle_s.max(1) as f64 {
                out.push(json!({"ticket_idle_stop": self.ticket_http_stop(&hs, &format!("idle for {idle:.0} s"), Duration::ZERO)}));
            }
        }
        for s in self.ticket_stopping_with_seller() {
            if self.ticket_http_maybe_of(&s.id) || !lock(&self.ticket_cancel_tried).insert(s.id.clone()) {
                continue;
            }
            out.push(json!({"ticket_cancel_asked": self.ticket_cancel_recorded(&s, Duration::ZERO)}));
        }
        // the seller is shown what the wallet can prove before it is judged for not having credited it
        out.extend(self.ticket_show_late_prepaid(None, None));
        self.ticket_prepaid_overdue_tick();
        // what the sessions this start stopped left with their sellers, after the late preimages that may add to it: a stop in
        // a running process says this itself, and one that died could not. Asked once; unknown where the seller did not say
        for sid in std::mem::take(&mut *lock(&self.ticket_start_stopped)) {
            let Some(s) = self.ticket_session(&sid).filter(|s| s.http.is_some()) else { continue };
            let left = self.ticket_seller_balance(&s);
            if left != Some(0) {
                let line = json!({"session": s.id, "dest": format!("ln:{}", s.payee), "origin": s.origin, "left_msat": left.map(|m| m.to_string()), "why": s.why});
                self.ticket_audit("ticket_left_with_seller", line.clone());
                out.push(json!({"ticket_left_with_seller": line}));
            }
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
    u.scheme == "https"
        || (u.scheme == "http" && (u.host == "localhost" || u.host == "[::1]" || u.host.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| ip.is_loopback())))
        // a seller reached by key: a `.invalid` name no resolver answers (RFC 6761), reached only over
        // its iroh link, end-to-end encrypted to the key its checked transport document names
        || (u.scheme == "http" && link_host(origin))
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
        if sink.gone {
            return Some(READER_GONE.into());
        }
        if sink.passed {
            return Some(PASSED_SHOWN.into());
        }
    }
    length.filter(|l| *l != sink.bytes).map(|l| format!("cut short: {} of {l} bytes", sink.bytes))
}

/// A seller's `busy` (its service is full: `capacity` in the gateway's config) as the wallet tells
/// it: the rule `seller_busy`, words of the wallet's own, and the counts, read as numbers only and
/// bounded, never the seller's text. `None`: not a `busy` answer.
pub(crate) fn seller_busy(v: &Value) -> Option<Value> {
    if protocol_code(v.get("error")) != "busy" {
        return None;
    }
    let b = v.get("busy");
    let n = |k: &str| b.and_then(|b| b.get(k)).and_then(Value::as_u64).map(|n| n.min(1_000_000));
    let scope = match b.and_then(|b| b.get("scope")).and_then(Value::as_str) {
        Some("buyers") => "buyers",
        Some("streams") => "streams",
        Some("buyer_streams") => "buyer_streams",
        Some("bandwidth") => "bandwidth",
        _ => "service",
    };
    let (in_use, limit, retry) = (n("inUse"), n("limit"), n("retryAfter").unwrap_or(30).clamp(1, 3600));
    let counts = |what: &str| match (in_use, limit) {
        (Some(u), Some(l)) => format!(" ({u} of {l} {what})"),
        _ => String::new(),
    };
    let words = match scope {
        "buyers" => format!("This shop is busy{}. Try again in a moment.", counts("buyers served at once")),
        "streams" => format!("This shop is busy{}. Try again in a moment.", counts("streams in use")),
        "buyer_streams" => format!("You are using as many streams of this shop at once as it allows{}.", counts("for one buyer")),
        "bandwidth" => format!("This shop is busy{}. Try again in a moment.", counts("Mbit/s carried")),
        _ => "This shop is busy. Try again in a moment.".to_string(),
    };
    // turned away unserved, before anything was paid for it: another seller may serve the request (`request_sent` false)
    Some(with(deny("seller_busy", words), json!({"status": 503, "charged_sats": 0, "seller_code": "busy", "request_sent": false,
                                                    "busy": {"scope": scope, "inUse": in_use, "limit": limit, "retryAfter": retry}})))
}

/// Nothing of a call went to the seller or was paid: it was refused before its request left. A request that left may
/// have been charged from the balance the session had, with nothing booked for this call: it is never sent again.
fn refused_before_it_left(out: &Value) -> bool {
    out.get("verdict").and_then(Value::as_str) != Some("allow") && out.get("status").is_none_or(Value::is_null)
        && out.get("request_sent").and_then(Value::as_bool) != Some(true)
        && py_int(out.get("charged_sats")).unwrap_or(0) == 0 && out.get("bytes").is_none_or(|b| b.is_null() || b.as_u64() == Some(0))
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_cancel_names_no_more_at_once_than_the_sellers_cap() {
        let hashes = vec![0u8; 8];
        assert_eq!(super::in_parts(&hashes, 3).map(<[u8]>::len).collect::<Vec<_>>(), vec![3, 3, 2]);
        assert_eq!(super::in_parts(&hashes, 0).len(), 8, "a cap of none still names one at a time");
    }

    /// Only a call refused before its request left is made again (a resume, in another session): one whose request left
    /// may have been charged from the session's balance, with nothing booked for it, and is never sent twice.
    ///
    /// FAILS without `request_sent`: a refusal after the request left, charged nothing of its own, is taken for one
    /// refused before.
    #[test]
    fn only_a_call_refused_before_its_request_left_counts_as_nothing_sent() {
        let refused = json!({"verdict": "deny", "rule": "ticket_session_ended", "charged_sats": 0, "request_sent": false});
        assert!(refused_before_it_left(&refused));
        assert!(refused_before_it_left(&json!({"verdict": "deny", "rule": "ticket_session_ended"})), "said nothing of it: none left");
        let mut left = refused.clone();
        left["request_sent"] = json!(true);
        assert!(!refused_before_it_left(&left), "its request left: {left}");
        for (k, v) in [("verdict", json!("allow")), ("status", json!(200)), ("charged_sats", json!(1)), ("bytes", json!(10))] {
            let mut o = refused.clone();
            o[k] = v;
            assert!(!refused_before_it_left(&o), "{o}");
        }
    }

    #[test]
    fn a_body_streamed_to_a_caller_is_never_written_to_disk_by_the_wallet() {
        let d = tempfile::tempdir().unwrap();
        std::env::set_var("B2_BODY_DIR", d.path());
        let sock = d.path().join("reader.sock");
        let l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let reader = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut all = vec![];
            let _ = std::io::Read::read_to_end(&mut s, &mut all);
            all.len()
        });
        let mut streamed = Sink::streaming_to(Some(&sock));
        let chunk = vec![7u8; 1 << 20];
        for _ in 0..4 {
            streamed.put(&chunk);
        }
        let (_, fields, _) = streamed.done();
        assert!(fields.get("saved_to").is_none_or(Value::is_null), "{fields}");
        assert_eq!(reader.join().unwrap(), 4 << 20, "every byte went to the caller");
        // a body the agent reads itself is still kept where B2_BODY_DIR says
        let mut kept = Sink::new();
        kept.put(&vec![1u8; kept.cap + 1]);
        assert!(kept.done().1["saved_to"].is_string());
        std::env::remove_var("B2_BODY_DIR");
    }

    /// A seller that sends its answer's head a byte every 200 ms: each read is quick, so only a
    /// deadline for the whole request ends it.
    fn dribbling_seller() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf);
                for b in b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n" {
                    if s.write_all(&[*b]).is_err() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        });
        port
    }

    /// FAILS before: a status call was held only to each read, so a seller dribbling its head a byte at a
    /// time held it for as long as it liked (here, about 18 s) while the session's order lock waited.
    #[test]
    fn a_seller_dribbling_its_answer_is_cut_off_at_the_calls_deadline() {
        let port = dribbling_seller();
        let started = Instant::now();
        let r = UreqWire::default().send_by("POST", &format!("http://127.0.0.1:{port}/x402/ticket/status"), b"{}", &[], Duration::from_secs(5), None,
                                            Duration::from_secs(1));
        assert!(r.is_err(), "the answer never finished, so the call fails");
        assert!(started.elapsed() < Duration::from_secs(3), "cut off near its deadline, not after {:?}", started.elapsed());
    }

    /// A body that comes a byte every 200 ms is cut off at its deadline, however short each read.
    #[test]
    fn a_body_dribbled_past_its_deadline_is_cut_off() {
        struct Slow(usize);
        impl Read for Slow {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0 == 0 || buf.is_empty() {
                    return Ok(0);
                }
                std::thread::sleep(Duration::from_millis(200));
                self.0 -= 1;
                buf[0] = b' ';
                Ok(1)
            }
        }
        let ans = WireAnswer { status: 200, headers: vec![], length: None, body: Box::new(Slow(100)), closer: None };
        let started = Instant::now();
        assert!(ans.read_small_by(1 << 20, Instant::now() + Duration::from_secs(1)).is_err());
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    }

    struct Flag(AtomicBool);

    impl RefillFlag for Flag {
        fn refill_flag(&self) -> &AtomicBool {
            &self.0
        }
    }

    /// FAILS before: a refill that panicked left its session's flag set, and every later release
    /// that found the pool empty waited for it forever.
    #[test]
    fn a_refill_that_panics_frees_the_session_for_the_next_one() {
        let f = Arc::new(Flag(AtomicBool::new(false)));
        let g = Refilling::take(f.clone()).expect("free");
        assert!(Refilling::take(&*f).is_none(), "one refill at a time");
        let t = std::thread::spawn(move || {
            let _g = g;
            panic!("a refill that fails as badly as it can");
        });
        assert!(t.join().is_err());
        assert!(Refilling::take(&*f).is_some(), "the flag went with the thread");
    }
    use super::*;

    /// Once the credit released for a request covers its charge cap, no ticket more is due for it,
    /// however far its body goes or however long it runs: it could never be charged for one.
    #[test]
    fn no_ticket_is_due_once_the_credit_covers_the_charge_cap() {
        let per_mib = Price { request_msat: 0, byte_msat: 20_000, per_bytes: 1 << 20, second_msat: 0, tokens: xbt402::tokens::TokenRule::NONE };
        let st = Stream { price: per_mib, base_spent: 5_000, started: Instant::now(), max_msat: 30_000, max_open: Duration::from_secs(50), limit: "max_answer_s" };
        let cap_bytes = per_mib.bytes_for(30_000);
        // 20 sat credited for it, below its 30-sat cap: due near the end of what that pays for, as always
        assert!(st.due_bytes(25_000, cap_bytes, None) && st.due_bytes_ahead(25_000, 0, None, cap_bytes));
        // 30 sat credited, the cap: never, though the body goes on past what the credit pays for
        assert!(!st.due_bytes(35_000, cap_bytes, None) && !st.due_bytes(35_000, 4 * cap_bytes, None));
        assert!(!st.due_bytes_ahead(35_000, cap_bytes, None, cap_bytes));
        // and the body is read no further than the cap
        assert!(st.over(cap_bytes).is_some_and(|w| w.contains("charge cap")) && st.over(cap_bytes / 2).is_none());
        // by the second: the next second is not paid for, but the credit already covers the cap
        let per_s = Price { request_msat: 0, byte_msat: 0, per_bytes: 1, second_msat: 10_000, tokens: xbt402::tokens::TokenRule::NONE };
        let st = Stream { price: per_s, base_spent: 0, started: Instant::now(), max_msat: 15_000, max_open: Duration::from_secs(50), limit: "max_answer_s" };
        assert!(st.due_time(10_000), "one second paid, below the cap");
        assert!(!st.due_time(15_000), "the cap is paid for");
    }

    #[test]
    fn a_ticket_is_due_only_when_the_balance_does_not_cover_the_next_piece() {
        let per_mib = Price { request_msat: 2500, byte_msat: 200_000, per_bytes: 1 << 20, second_msat: 0, tokens: xbt402::tokens::TokenRule::NONE };
        let st = Stream { price: per_mib, base_spent: 10_000, started: Instant::now(), max_msat: u64::MAX, max_open: Duration::from_secs(50), limit: "max_answer_s" };
        // one ticket of 1,000 sat credited on top of the 10 sat spent before: 1,000,000 - 2,500 msat of bytes
        let credited = 1_010_000;
        let limit = per_mib.bytes_for(1_000_000 - 2500);
        // due a little before the last paid byte, by what a proxy may hold back, and not before
        let early = limit - PROXY_SLACK;
        assert!(!st.due_bytes(credited, 0, None) && !st.due_bytes(credited, early - 1, None));
        assert!(st.due_bytes(credited, early, None), "all but the slack of what the ticket pays for has arrived");
        assert!(st.due_bytes(credited, limit, None));
        assert!(!st.due_bytes(credited + 1_000_000, limit, None), "the next ticket covers the next byte");
        // never for a body the balance already covers to its end
        assert!(!st.due_bytes(credited, early, Some(limit)) && st.due_bytes(credited, early, Some(limit + 1)));
        // a small balance: the slack is a quarter of what it covers, not more
        let (small, covered) = (10_000 + 2500 + 800, per_mib.bytes_for(800));
        let at = covered - covered / 4;
        assert!(covered / 4 < PROXY_SLACK && !st.due_bytes(small, at - 1, None) && st.due_bytes(small, at, None));
        assert!(!st.due_time(credited), "not priced by time");
        assert_eq!(st.cost(1 << 20), 202_500);
        // by the second: due when the next second is not covered
        let per_s = Price { request_msat: 0, byte_msat: 0, per_bytes: 1, second_msat: 100_000, tokens: xbt402::tokens::TokenRule::NONE };
        let st = Stream { price: per_s, base_spent: 0, started: Instant::now(), max_msat: u64::MAX, max_open: Duration::from_secs(50), limit: "max_answer_s" };
        assert_eq!(st.seconds(), 1, "the first second has started");
        assert!(st.due_time(100_000), "one second paid, the second is not");
        assert!(!st.due_time(200_000) && !st.due_bytes(100_000, 1 << 30, None));
        // a price that does not fit is due at once and costs the most there is, over even the largest limit
        let huge = Stream { price: Price { request_msat: u64::MAX, byte_msat: 1, per_bytes: 1, second_msat: 0, tokens: xbt402::tokens::TokenRule::NONE }, base_spent: 0, started: Instant::now(), max_msat: u64::MAX, max_open: Duration::from_secs(50), limit: "max_answer_s" };
        assert_eq!(huge.cost(1), u64::MAX);
        assert!(huge.due_bytes(1_000_000, 0, None));
        assert!(huge.over(0).is_some_and(|w| w.starts_with("max_sats")), "and is over any limit");
        // a long body paid for at its head is not cut where the call's limit equals its price
        let flat = Stream { price: Price { request_msat: 5_000, byte_msat: 0, per_bytes: 1, second_msat: 0, tokens: xbt402::tokens::TokenRule::NONE }, base_spent: 0, started: Instant::now(), max_msat: 5_000,
                            max_open: Duration::from_secs(50), limit: "max_answer_s" };
        assert!(flat.over(1 << 30).is_none());
        let long = Stream { price: per_mib, base_spent: 0, started: Instant::now() - Duration::from_secs(3), max_msat: u64::MAX, max_open: Duration::from_secs(2), limit: "max_answer_s" };
        assert!(long.over(0).is_some_and(|w| w.starts_with("max_answer_s")) && st.over(0).is_none());
    }

    #[test]
    fn tickets_are_paid_over_https_or_to_this_machine_only() {
        let by_key = xbt402::shop::origin_for(&[7u8; 32]);
        for ok in ["https://seller.example", "https://seller.example:8443", "http://127.0.0.1:8402", "http://127.9.9.9", "http://localhost:80", "http://[::1]:8402", by_key.as_str()] {
            assert!(private_channel(ok), "{ok}");
        }
        for no in ["http://seller.example", "http://10.0.0.5:8402", "http://127.0.0.1.example", "http://[::2]", "ftp://127.0.0.1", "http://localhost.example", "http://shop.invalid.example", ""] {
            assert!(!private_channel(no), "{no}");
        }
    }

    #[test]
    fn a_seller_nobody_named_is_reached_over_https_at_a_public_address_only() {
        for ip in ["1.1.1.1", "8.8.8.8", "100.128.0.1", "172.32.0.1", "2606:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808"] {
            assert!(public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["0.0.0.0", "10.1.2.3", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "172.31.255.255", "192.168.1.1", "192.0.2.1",
                   "198.18.0.1", "198.51.100.7", "203.0.113.9", "224.0.0.1", "255.255.255.255", "::", "::1", "fc00::1", "fd12::1", "fe80::1", "ff02::1",
                   "2001:db8::1", "2002::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a00:1"] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        assert_eq!(stranger_reachable("https://1.1.1.1"), Ok(()));
        assert_eq!(stranger_reachable("https://[2606:4700::1111]:8443"), Ok(()));
        for no in ["http://1.1.1.1", "https://127.0.0.1:8402", "https://[::1]", "https://10.0.0.5", "https://169.254.169.254", "https://localhost:443",
                   "https://user@1.1.1.1", "https://1.1.1.1:x", "https://[::1", "https://"] {
            assert!(stranger_reachable(no).is_err(), "{no}");
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
    fn a_range_is_one_plain_byte_range_and_a_206_must_answer_it() {
        assert_eq!(ByteRange::parse("bytes=1000-"), Some(ByteRange { first: 1000, last: None }));
        assert_eq!(ByteRange::parse("bytes=0-0").map(|r| r.header()), Some("bytes=0-0".into()));
        for bad in ["bytes=5-2", "bytes=-5", "bytes=1-2,3-4", "bytes= 1-", "Bytes=1-", "bytes=1", "bytes=a-", "bytes=1-2 ", "bytes=00000000000000000001-"] {
            assert_eq!(ByteRange::parse(bad), None, "{bad}");
        }
        assert_eq!(content_range("bytes 10-19/100"), Some((10, 19, Some(100))));
        assert_eq!(content_range("bytes 10-19/*"), Some((10, 19, None)));
        for bad in ["bytes 19-10/100", "bytes 10-100/100", "bytes */100", "10-19/100", "bytes 10-19"] {
            assert_eq!(content_range(bad), None, "{bad}");
        }
        let ans = |status: u16, cr: &str, length: Option<u64>| WireAnswer { status, headers: vec![("CONTENT-RANGE".into(), cr.into())], length, body: Box::new(std::io::empty()), closer: None };
        let asked = ByteRange::parse("bytes=10-");
        let mut a = ans(206, "bytes 10-19/100", None);
        let (v, refused) = answer_head(&mut a, asked);
        assert_eq!((refused, a.length, v["content_range"].as_str()), (None, Some(10), Some("bytes 10-19/100")), "the range's span is the length");
        assert!(answer_head(&mut ans(206, "bytes 0-19/100", Some(20)), asked).1.is_some(), "another start");
        assert!(answer_head(&mut ans(206, "bytes 10-19/100", Some(11)), asked).1.is_some(), "a length that is not the span");
        assert!(answer_head(&mut ans(206, "bytes 10-30/100", Some(21)), ByteRange::parse("bytes=10-20")).1.is_some(), "past the end asked for");
        assert!(answer_head(&mut ans(206, "", Some(5)), None).1.is_some(), "a 206 with no range");
        let closed = Arc::new(AtomicBool::new(false));
        let mut whole_to_a_range = ans(200, "", Some(100));
        let c = closed.clone();
        whole_to_a_range.closer = Some(Arc::new(move || c.store(true, Ordering::SeqCst)));
        let (v, refused) = answer_head(&mut whole_to_a_range, asked);
        assert!(refused.is_some() && v["range_ignored"] == true, "a whole body to a range from byte 10 is not read");
        assert!(closed.load(Ordering::SeqCst), "and its connection is ended at once, before any of it is read");
        let mut whole = ans(200, "", Some(100));
        let (v, refused) = answer_head(&mut whole, ByteRange::parse("bytes=0-"));
        assert!(refused.is_none() && v.get("range_ignored").is_none() && whole.length == Some(100), "from byte 0: the whole body is what was asked");
        let mut start = ans(200, "", Some(100));
        let (v, refused) = answer_head(&mut start, ByteRange::parse("bytes=0-9"));
        assert_eq!((refused, start.length, v["content_length"].as_u64()), (None, Some(100), Some(100)), "from byte 0 to 9: the whole answer, as it states itself");
        assert_eq!(answer_head(&mut ans(416, "bytes */100", Some(0)), asked).0["content_range"], "bytes */100");
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

    #[test]
    fn a_busy_seller_is_told_in_the_wallets_own_words_and_counts_never_its_text() {
        let v = json!({"error": "busy", "detail": "<script>evil</script>", "busy": {"scope": "streams", "inUse": 3, "limit": 3, "retryAfter": 30}});
        let d = seller_busy(&v).unwrap();
        assert_eq!(d["rule"], "seller_busy");
        assert_eq!(d["reason"], "This shop is busy (3 of 3 streams in use). Try again in a moment.");
        assert_eq!((d["charged_sats"].as_u64(), d["busy"]["retryAfter"].as_u64()), (Some(0), Some(30)));
        // a scope the wallet does not know, numbers out of range: still the wallet's words, bounded
        let odd = seller_busy(&json!({"error": "busy", "busy": {"scope": "<x>", "inUse": u64::MAX, "retryAfter": 99999}})).unwrap();
        assert_eq!(odd["reason"], "This shop is busy. Try again in a moment.");
        assert_eq!((odd["busy"]["inUse"].as_u64(), odd["busy"]["retryAfter"].as_u64()), (Some(1_000_000), Some(3600)));
        // not a busy answer
        assert!(seller_busy(&json!({"error": "upstream_unavailable"})).is_none());
    }

    fn receipt(seq: u64, released: u64, spent: u64, charged: u64) -> Receipt {
        Receipt { seq, released_msat: released, spent_msat: spent, charged, status: 200, req: String::new(), body_hash: String::new(), raw: Value::Null }
    }

    fn money(sent: u64) -> Money {
        Money { acct: Account { sent_msat: sent, acked_msat: sent, spent_msat: 0 }, ..Money::default() }
    }

    #[test]
    fn an_older_receipt_is_passed_over_and_a_newer_one_taken() {
        let mut m = money(1_000_000);
        // two pages: the second's receipt (newer totals) is read first
        m.open.insert(1, 50_000);
        m.open.insert(2, 50_000);
        m.consumed += 2500;
        m.close(2, 2500, 2500);
        assert_eq!(m.take(&receipt(2, 1_000_000, 5000, 2500), 2500, false, None), Ok(true));
        m.consumed += 2500;
        m.close(1, 2500, 2500);
        // the first's receipt says less was spent: older, passed over, nothing goes backwards
        assert_eq!(m.take(&receipt(1, 1_000_000, 2500, 2500), 2500, false, None), Ok(false));
        assert_eq!(m.acct.spent_msat, 5000);
        // its own charge is still held to its price
        assert!(m.take(&receipt(1, 1_000_000, 2500, 9999), 2500, false, None).is_err());
    }

    /// The seller gives a charge back when its answer could not be sent (a page the browser
    /// dropped), so its spend can fall between two receipts, while what it says was released only
    /// rises. A receipt passed over for its spend still confirms the tickets it says were released.
    #[test]
    fn a_receipt_passed_over_for_its_spend_still_confirms_what_was_released() {
        let mut m = money(1_000_000);
        m.open.insert(1, 50_000);
        assert_eq!(m.take(&receipt(1, 1_000_000, 30_000, 2500), 50_000, false, None), Ok(true));
        // a ticket released, and on its way
        m.acct.released(1_000_000);
        // the seller took it after giving back 20 sat of an answer it could not send
        assert_eq!(m.take(&receipt(2, 2_000_000, 10_000, 0), 0, true, None), Ok(false));
        assert_eq!((m.acct.acked_msat, m.acct.spent_msat), (2_000_000, 30_000), "released taken, the spend held");
        // a receipt from before the ticket was taken changes nothing
        assert_eq!(m.take(&receipt(1, 1_000_000, 30_000, 2500), 50_000, false, None), Ok(false));
        assert_eq!(m.acct.acked_msat, 2_000_000);
    }

    #[test]
    fn a_spend_past_what_the_open_requests_may_add_is_refused() {
        let mut m = money(1_000_000);
        // a socket open with a call's limit of 40 sat, its head of 2.5 sat counted
        m.open.insert(7, 40_000 - 2500);
        m.consumed += 2500;
        // inside: what was counted, and what it may still add
        assert_eq!(m.take(&receipt(8, 1_000_000, 40_000, 0), 0, false, None), Ok(true));
        // past it: the balance drained
        let e = m.take(&receipt(9, 1_000_000, 1_000_000, 0), 0, false, None).unwrap_err();
        assert!(e.contains("spentMsat"), "{e}");
        assert_eq!(m.acct.spent_msat, 40_000, "nothing of a refused receipt is taken");
    }

    #[test]
    fn at_a_quiet_point_the_spend_is_what_the_receipts_charged() {
        let mut m = money(1_000_000);
        // a film counted at 40 sat by the wallet, charged 30 sat by its last receipt
        m.open.insert(3, 100_000);
        m.consumed += 40_000;
        m.close(3, 30_000, 40_000);
        // nothing open: the seller's spend since the last quiet point is what its receipts charged
        assert!(m.take(&receipt(4, 1_000_000, 40_000, 0), 0, false, None).is_err(), "10 sat more than charged");
        assert_eq!(m.take(&receipt(4, 1_000_000, 30_000, 0), 0, false, None), Ok(true));
        assert_eq!((m.quiet_spent, m.accepted), (30_000, 0), "a new quiet point");
        // a cut answer the seller charged past the wallet's count: the charge goes into the count
        m.open.insert(5, 100_000);
        m.consumed += 20_000;
        m.close(5, 60_000, 20_000);
        assert_eq!(m.consumed, 40_000 + 20_000 + 40_000);
        assert_eq!(m.take(&receipt(6, 1_000_000, 90_000, 0), 0, false, None), Ok(true));
    }

    /// A receipt for a request sent after the totals held were taken is newer, though its spend is
    /// lower (the seller gave a charge back); one for a request sent before them is not.
    ///
    /// FAILS before: both were passed over for their lower spend.
    #[test]
    fn a_receipt_for_a_request_sent_after_the_totals_were_taken_is_newer_whatever_its_spend() {
        let mut m = money(1_000_000);
        m.open.insert(1, 600_000);
        m.open.insert(2, 50_000);
        let before = m.epoch;
        // a page's head while a reply was charged as it ran
        assert_eq!(m.take(&receipt(2, 1_000_000, 500_000, 2500), 2500, false, Some(before)), Ok(true));
        m.close(2, 2500, 2500);
        // a request sent before that, answered with less spent: no telling which came first
        assert_eq!(m.take(&receipt(3, 1_000_000, 400_000, 0), 0, false, Some(before)), Ok(false));
        // the reply settled at less than it ran up: a status asked for since is newer
        let after = m.epoch;
        assert_eq!(m.take(&receipt(4, 1_000_000, 10_000, 0), 0, false, Some(after)), Ok(true));
        assert_eq!(m.acct.spent_msat, 10_000);
        assert_eq!(m.acct.balance(), 990_000, "the charge given back is credit again");
        // still bounded: what was released is never less than what the seller confirmed
        let e = m.take(&receipt(5, 900_000, 10_000, 0), 0, false, Some(m.epoch)).unwrap_err();
        assert!(e.contains("released"), "{e}");
    }

    /// The ids of open requests are their own: a seq taken over by another request leaves both
    /// held, each closed by its own receipt.
    ///
    /// FAILS before (keyed by seq): the second request's entry replaced the first's, and closing
    /// the first dropped what the second may still charge from the bound.
    #[test]
    fn open_requests_are_held_by_their_own_id_not_by_seq() {
        let mut m = money(1_000_000);
        let (a, b) = (m.request_id(), m.request_id());
        assert_ne!(a, b);
        m.open.insert(a, 40_000);
        m.open.insert(b, 40_000);
        m.consumed += 2500;
        m.close(a, 2500, 2500);
        assert_eq!(m.open.get(&b), Some(&40_000), "the other request is still open");
        // the seller may still charge b its 40 sat: inside the bound, not a fault
        assert_eq!(m.take(&receipt(9, 1_000_000, 42_500, 0), 0, false, None), Ok(true));
    }

    /// A request whose answer was lost may still be charged by the seller, up to its limit, for a
    /// while after: no quiet point is taken, and a charge inside its limit is no seller fault.
    ///
    /// FAILS before: it was closed at once at its price, and the seller's later charge for it
    /// was taken for a fault at the next quiet point.
    #[test]
    fn a_lost_request_is_held_as_one_the_seller_may_still_charge() {
        let mut m = money(1_000_000);
        let rid = m.request_id();
        m.open.insert(rid, 40_000);
        m.lose(rid, 40_000, false, false, 1_000_000);
        assert!(m.open.is_empty());
        // the seller served it after all and charged 30 sat: inside what it may, and not a quiet point
        assert_eq!(m.take(&receipt(3, 1_000_000, 30_000, 0), 0, false, None), Ok(true));
        assert_eq!(m.quiet_spent, 0, "no quiet point while the lost request may be charged");
        // past its limit: a fault
        assert!(m.take(&receipt(4, 1_000_000, 50_000, 0), 0, false, None).is_err());
        // once its grace is over, a quiet point is taken and it is forgotten
        m.lost.values_mut().for_each(|(_, at)| *at -= LOST_GRACE);
        assert_eq!(m.take(&receipt(5, 1_000_000, 30_000, 0), 0, false, None), Ok(true));
        assert!(m.lost.is_empty() && m.quiet_spent == 30_000);
    }

    /// Lost requests share one cap over the session (a ticket), so dropping many adds nothing past
    /// it; and a seller that charges lost requests at three quiet points is over-charging.
    ///
    /// FAILS before: each lost request was allowed its own bound, and charging them was never a fault.
    #[test]
    fn lost_requests_share_one_cap_and_charging_them_again_and_again_is_over_charging() {
        let mut m = money(10_000_000);
        for _ in 0..5 {
            let rid = m.request_id();
            m.open.insert(rid, 600_000);
            m.lose(rid, 600_000, false, false, 1_000_000);
        }
        let allowed: u64 = m.lost.values().map(|(a, _)| *a).sum();
        assert_eq!(allowed, 1_000_000, "five lost requests of 600 sat each share one ticket");
        // a reply held at its quote keeps it
        let rid = m.request_id();
        m.open.insert(rid, 300_000);
        m.lose(rid, 300_000, true, false, 1_000_000);
        assert_eq!(m.lost[&rid].0, 300_000);
        // the seller charges lost requests at three quiet points: the third is over-charging
        let mut spent = 0;
        for i in 0..3u64 {
            m.lost.values_mut().for_each(|(_, at)| *at -= LOST_GRACE);
            spent += 10_000;
            let r = m.take(&receipt(10 + i, 10_000_000, spent, 0), 0, false, None);
            if i < 2 {
                assert_eq!(r, Ok(true), "round {i}");
                let rid = m.request_id();
                m.open.insert(rid, 600_000);
                m.lose(rid, 600_000, true, false, 1_000_000);
            } else {
                assert!(r.is_err() && m.overcharged, "{r:?}");
            }
        }
    }

    /// What an answer priced by the token holds back is not drawn: the estimate of the balance
    /// leaves it out while it runs, and what the session counted as drawn never falls.
    #[test]
    fn a_token_answers_hold_is_apart_from_what_was_drawn() {
        let mut m = money(1_000_000);
        m.reserved += 600_000;
        assert_eq!(m.est_balance(), 400_000);
        m.consumed += 10_000;
        m.reserved -= 600_000;
        assert_eq!((m.est_balance(), m.consumed), (990_000, 10_000));
    }

    /// An answer cut short is believed charged up to what could have been on its way when the wallet
    /// stopped reading, or the credit it could have drawn with [`CUT_SLACK`] on top, whichever is
    /// more: a seller that pushed ahead within the credit it was given, into a proxy that held it,
    /// charged honestly. Never past the call's limit.
    #[test]
    fn a_cut_answer_may_be_charged_up_to_the_credit_it_could_draw() {
        // 20 sat a MiB, 10 sat spent before the answer
        let per_mib = Price { request_msat: 0, byte_msat: 20_000, per_bytes: 1 << 20, second_msat: 0, tokens: xbt402::tokens::TokenRule::NONE };
        let st = Stream { price: per_mib, base_spent: 10_000, started: Instant::now(), max_msat: 5_000_000, max_open: Duration::from_secs(50), limit: "max_answer_s" };
        let (read, slack) = (per_mib.cost((1 << 20) + CUT_SLACK, 0).unwrap(), per_mib.cost(CUT_SLACK, 0).unwrap());
        assert!(read < 400_000, "{read}");
        // 1 MiB read, the answer able to draw a ticket of 1,000 sat: all of that, and the slack
        assert_eq!(st.cut_bound(1 << 20, 0, 1_000_000), 1_000_000 + slack);
        // little it could draw (other answers had the rest): what could have been on its way
        assert_eq!(st.cut_bound(1 << 20, 0, 0), read);
        let tight = Stream { max_msat: 500_000, ..st };
        assert_eq!(tight.cut_bound(1 << 20, 0, 1_000_000), 500_000);
    }

    /// Every way an answer closes believes the seller's charge by one rule ([`Bound`]): one that
    /// arrived whole up to what it cost by the wallet's count, its receipt signing the body that
    /// arrived; one cut short up to its bound; none past the call's limit.
    ///
    /// FAILS before: an answer that arrived whole and was closed late or given up was believed up to
    /// its call's limit, and its late receipt was not checked against its cost or its body.
    #[test]
    fn every_way_an_answer_closes_believes_the_same_charge() {
        let m0 = money(3_000_000);
        let whole = Bound { most: 20_000, max_msat: 5_000_000, whole: Some((20_000, "ab".into())), share: None, quoted: None };
        let signed = |charged: u64, body: &str| Receipt { body_hash: body.into(), ..receipt(3, 0, 0, charged) };
        assert_eq!(whole.judge(&signed(20_000, "ab"), &m0), (20_000, None));
        let (taken, why) = whole.judge(&signed(4_999_000, "ab"), &m0);
        assert_eq!(taken, 20_000);
        assert!(why.unwrap().contains("costs 20000"));
        assert!(whole.judge(&signed(20_000, "cd"), &m0).1.unwrap().contains("another body"));
        let cut = Bound { most: 360_000, max_msat: 5_000_000, whole: None, share: None, quoted: None };
        assert_eq!(cut.judge(&signed(4_000_000, ""), &m0), (360_000, None));
        // given up: the same bound
        let mut m = money(3_000_000);
        m.open.insert(7, 4_980_000);
        m.tails.push(Tail { rid: 7, seq: 3, digest: String::new(), status: 200, since: Instant::now() - TAIL_GIVE_UP, counted: 20_000, bound: whole });
        assert_eq!(m.give_up(), 1);
        assert_eq!(m.accepted, 20_000);
    }

    /// An answer whose last receipt is never listed is given up as charged the most it may: what is
    /// left of its call's limit, but no more than could have reached the wallet when it stopped.
    ///
    /// FAILS before: it was closed at all of its call's limit, which the next quiet point then
    /// allowed the seller to have spent.
    #[test]
    fn an_answer_given_up_is_closed_at_no_more_than_could_have_reached_the_wallet() {
        let mut m = money(3_000_000);
        // a cut answer the wallet counted 20 sat for, under a limit of 5,000 sat, of which 360 sat could have reached it
        m.open.insert(7, 4_980_000);
        m.tails.push(Tail { rid: 7, seq: 3, digest: String::new(), status: 200, since: Instant::now(), counted: 20_000, bound: Bound { most: 360_000, max_msat: 5_000_000, whole: None, share: None, quoted: None } });
        assert_eq!(m.give_up(), 0, "not before its time");
        m.tails[0].since -= TAIL_GIVE_UP;
        assert_eq!(m.give_up(), 1);
        assert!(m.tails.is_empty() && m.open.is_empty());
        assert_eq!((m.accepted, m.consumed), (360_000, 340_000));
        // one whose limit leaves less than that: what is left of the limit
        m.open.insert(8, 30_000);
        m.tails.push(Tail { rid: 8, seq: 4, digest: String::new(), status: 200, since: Instant::now() - TAIL_GIVE_UP, counted: 20_000, bound: Bound { most: 360_000, max_msat: 50_000, whole: None, share: None, quoted: None } });
        assert_eq!(m.give_up(), 1);
        assert_eq!((m.accepted, m.consumed), (410_000, 370_000));
    }

    /// Two answers priced by their size, cut side by side as they started on the same credit: each is
    /// believed up to that credit as it stands when it is closed, so the second is judged with what
    /// the seller was believed of the first already drawn, and both together are never believed past
    /// the session's credit and [`CUT_SLACK`] each.
    ///
    /// FAILS before: each was believed up to the credit the session had as it started, the same
    /// for both, so the seller was believed about twice the session's credit.
    #[test]
    fn answers_cut_side_by_side_are_not_each_believed_up_to_the_same_credit() {
        // 1,000 sat released, nothing spent at either head; 1 sat a MiB, so 16 MiB of slack is about 16 sat
        let mut m = money(1_000_000);
        let per_mib = Price { request_msat: 0, byte_msat: 1_000, per_bytes: 1 << 20, second_msat: 0, tokens: xbt402::tokens::TokenRule::NONE };
        let slack = per_mib.cost(CUT_SLACK, 0).unwrap();
        let read = per_mib.cost(CUT_SLACK, 0).unwrap();
        let cut = |rid: u64| Tail { rid, seq: rid, digest: String::new(), status: 200, since: Instant::now(), counted: 0,
                                    bound: Bound { most: 1_000_000 + slack, max_msat: 5_000_000, whole: None,
                                                   share: Some(Share { base_spent: 0, mark_consumed: 0, own: 0, read, slack }), quoted: None } };
        m.open.insert(1, 5_000_000);
        m.open.insert(2, 5_000_000);
        let (a, b) = (cut(1), cut(2));
        // the seller charges each all of the credit: the first is believed so
        let charge = |c: u64| Receipt { ..receipt(1, 1_000_000, c, c) };
        let (first, _) = a.bound.judge(&charge(1_000_000), &m);
        assert_eq!(first, 1_000_000);
        m.close(1, first, 0);
        // the second, with that drawn: only the slack beside it
        let (second, _) = b.bound.judge(&charge(1_000_000), &m);
        assert_eq!(second, read.max(slack));
        assert!(first + second <= 1_000_000 + 2 * slack, "{first} + {second}");
    }

    /// The hold of an answer priced by the token that ends undrawn comes back to the answer beside
    /// it: a seller that pushed that answer ahead on it is believed, where it is judged as closed.
    #[test]
    fn credit_freed_by_a_reply_beside_it_counts_for_a_cut_answer() {
        let mut m = money(1_000_000);
        let b = Bound { most: 5_000_000, max_msat: 5_000_000, whole: None,
                        share: Some(Share { base_spent: 0, mark_consumed: 0, own: 0, read: 10, slack: 10 }), quoted: None };
        // a reply beside it holds 600 sat back: 400 left for this one
        m.reserved = 600_000;
        assert_eq!(b.most(&m), 400_010);
        // it ends having drawn 100 sat of it: 900 left
        m.reserved = 0;
        m.consumed = 100_000;
        assert_eq!(b.most(&m), 900_010);
    }

    /// A reply by the token cut short before its counts keeps its hold as drawn: an answer by its size
    /// cut beside it is not believed for the same credit, and the two together stay inside what was
    /// released (the case a review found: 600 sat held, 10 drawn, 400 left for the answer beside it).
    #[test]
    fn a_reply_cut_before_its_counts_frees_nothing_for_the_answer_beside_it() {
        let mut m = money(1_000_000);
        // the reply holds 600 sat back (it draws nothing while it runs) and its tokens so far come to 10 when it is cut
        m.reserved = 600_000;
        let drawn = m.end_hold(600_000, 0, 10_000, true);
        assert_eq!(drawn, 600_000);
        m.consumed += drawn;
        assert_eq!((m.reserved, m.freed), (0, 0), "nothing freed");
        // the reply is believed up to its quote, and adds nothing past what it holds drawn
        let a = Bound { most: 600_000, max_msat: 5_000_000, whole: None, share: None, quoted: Some(600_000) };
        let (first, why) = a.judge(&Receipt { ..receipt(1, 1_000_000, 600_000, 600_000) }, &m);
        assert_eq!((first, why), (600_000, None));
        // the answer by its size beside it, started before the reply: the seller charges it 990 sat
        let b = Bound { most: 5_000_000, max_msat: 5_000_000, whole: None,
                        share: Some(Share { base_spent: 0, mark_consumed: 0, own: 0, read: 10, slack: 10 }), quoted: None };
        let (second, _) = b.judge(&Receipt { ..receipt(2, 1_000_000, 990_000, 990_000) }, &m);
        assert_eq!(second, 400_010);
        assert!(first + second <= 1_000_000 + 10, "{first} + {second}");
        // a reply whose cost is known (cut after its counts, or whole) still frees what it held and did not draw
        let mut k = money(1_000_000);
        k.reserved = 600_000;
        assert_eq!(k.end_hold(600_000, 0, 10_000, false), 10_000);
        assert_eq!((k.reserved, k.freed), (0, 590_000));
    }

    /// An answer by its size cut short while a reply by the token beside it still held 600 sat back:
    /// its share of the credit was 400 sat then, and grows as the reply ends drawing 10. Its seller,
    /// behind a proxy that took more than [`CUT_SLACK`] ahead, honestly spent 900 sat on it: inside
    /// the share as it is closed, so its spend must have been allowed meanwhile too. No fault.
    ///
    /// FAILS before: the allowance was the share frozen as the answer ended (400 sat), and the spend
    /// was taken for the seller's fault.
    #[test]
    fn a_cut_answer_beside_a_running_reply_is_allowed_its_whole_bound() {
        let mut m = money(1_000_000);
        m.reserved = 600_000;
        let b = Bound { most: 5_000_000, max_msat: 5_000_000, whole: None,
                        share: Some(Share { base_spent: 0, mark_consumed: 0, own: 0, read: 10, slack: 10 }), quoted: None };
        assert_eq!(b.most(&m), 400_010, "its share while the reply holds");
        m.open.insert(1, b.allowance(0));
        // the reply ends, having drawn 10 sat
        m.reserved = 0;
        m.consumed = 10_000;
        assert!(b.most(&m) >= 900_000, "its share once the reply ended: {}", b.most(&m));
        let epoch = Some(m.epoch);
        // the share frozen as the answer ended would have called the honest spend a fault
        let mut frozen = money(1_000_000);
        frozen.consumed = 10_000;
        frozen.open.insert(1, 400_010);
        assert!(frozen.take(&receipt(9, 1_000_000, 900_000, 0), u64::MAX, false, Some(frozen.epoch)).is_err());
        assert_eq!(m.take(&receipt(9, 1_000_000, 900_000, 0), u64::MAX, false, epoch), Ok(true));
    }

    /// A reply cut before its counts, held as drawn at its quote, whose seller's last receipt then
    /// charges it less: the rest comes back to the answers beside it, as for a reply that ended.
    #[test]
    fn a_quoted_reply_closed_below_its_quote_frees_the_rest() {
        let mut m = money(1_000_000);
        let a = Bound { most: 600_000, max_msat: 5_000_000, whole: None, share: None, quoted: Some(600_000) };
        m.open.insert(1, 0);
        m.close_by(1, 40_000, 600_000, &a);
        assert_eq!(m.freed, 560_000);
        // closed once only: a second word for it frees nothing more
        m.close_by(1, 0, 600_000, &a);
        assert_eq!(m.freed, 560_000);
    }

    /// A reply by the token cut before its counts is believed up to what its terms quote for it, not
    /// up to the call's limit, and a charge past the quote is the seller's fault.
    #[test]
    fn a_reply_cut_before_its_counts_is_believed_up_to_its_quote_only() {
        let m = money(1_000_000);
        let quote = 120_000;
        let a = Bound { most: quote, max_msat: 5_000_000, whole: None, share: None, quoted: Some(quote) };
        assert_eq!(a.judge(&Receipt { ..receipt(1, 1_000_000, 100_000, 100_000) }, &m), (100_000, None));
        let (believed, why) = a.judge(&Receipt { ..receipt(1, 1_000_000, 990_000, 990_000) }, &m);
        assert_eq!(believed, quote);
        assert!(why.is_some_and(|w| w.contains("quote")));
    }

    #[test]
    fn a_streaming_count_goes_back_however_the_answer_ends() {
        let n = AtomicUsize::new(0);
        {
            let _a = Streaming::new(&n);
            let _b = Streaming::new(&n);
            assert_eq!(n.load(Ordering::SeqCst), 2);
        }
        assert_eq!(n.load(Ordering::SeqCst), 0);
    }
}
