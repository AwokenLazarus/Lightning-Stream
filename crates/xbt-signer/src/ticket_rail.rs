//! Stream tickets, the buyer's side in the signer (`docs/TICKETS.md`): the book on disk, the
//! payments through the owner's Lightning node, and the socket methods. The rules themselves, and
//! everything that needs no IO, are in [`crate::ticket`].
//!
//! Methods (`ticket_open`, `ticket_offer`, `ticket_lock`, `ticket_release`, `ticket_stop`,
//! `ticket_status`): the caller speaks HTTP to the seller, the signer decides and books. A caller
//! can cause a lock or a release only inside the owner's policy; it can cause neither a payment to
//! an invoice the checks refuse, nor a second release of a secret.
//!
//! **Each rule, and every place that could break it:**
//!
//! | Rule | Where it is kept |
//! |---|---|
//! | A secret leaves only after its spend is in the ledger and its ticket is `released` in the book, and only once. | [`Signer::ticket_release_locked`] is the one place a secret is derived for a caller: ledger row, then book row, then signature log, then the reply; an error at any of them returns no secret. A ticket leaves `locked` there and nowhere returns to it. |
//! | A start cannot be told from a restore, so every start assumes the worst. | [`Signer::ticket_start`]: every ticket the book holds locked and unreleased is `retired` (booked as released, never released by this process), every session is stopped. |
//! | What the node has and the book lacks is the wallet's if it carries the wallet's tag. | [`Signer::ticket_reconcile_locked`] reads the node's payment list from the book's cursor; a tagged payment the book lacks is `retired`. Locks and releases wait until the list has been read to its end once since the start. |
//! | The node decides whether money is locked, moved or back; the book decides whether a secret has left. | [`Signer::ticket_apply`]: `SUCCEEDED` with the preimage settles (exact cost), `FAILED` with no HTLC out un-books, anything else changes nothing in the ledger. |
//! | Budgets count what was released and the fee the node paid, never a number from outside. | The ledger row is [`crate::ticket::booking_sats`] of the book's own ticket at release, and the node's `value_msat + fee_msat` (never below the ticket) at settle. No field of a seller's or a caller's message reaches the ledger. |
//! | An invoice is paid only if it is the session's ticket. | [`Signer::ticket_lock`]: the six checks of the wire draft on the signer's own decode, then the node's decode, then the caps, before the write-ahead row. |
//! | One hash, one payment. | Only an `offered` ticket of the session takes an invoice; the write-ahead row makes it `sending` before the node sees the invoice. A prepaid ticket's hash is refused if the book has it. |
//! | A held ticket is never dust. | [`crate::ticket::sizing`] when a session opens, and [`Signer::ticket_book_sends`] before every lock, on the dust limits of the channels the payment may leave on as the node lists them then. |
//! | Held tickets take at most half of a channel's slots. | [`Signer::ticket_book_sends`], on a channel listing read in that lock round: the book's held tickets against half of the smallest channel, and the payments pending on each channel (whoever's) against half of that channel. A listing that cannot be read is an error and locks nothing. |
//! | A lock that fails for lack of a slot makes the wallet hold less. | [`Signer::ticket_lock`] gives every round's outcome to [`crate::ticket::Session::lock_round`]; [`crate::ticket::Book::want`] offers nothing during the wait. |
//! | At most 8 ticket payments are with the router at once. | [`Pace`]: every send of a ticket, held or prepaid, enters it. |
//! | A prepaid ticket is spent when it is paid, and bought one at a time. | [`Signer::ticket_prepay`]: every rule of a release, the ledger row and the book row (`released`) before the payment is sent; none while an earlier one of the session is not final. |
//!
//! Locks: the wallet's spend lock, then the book's. No lock is held while the node routes a
//! ticket, so a release never waits for a lock round.
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::applog::AppendLog;
use crate::bolt11::{self, Invoice};
use crate::keystore::{random_bytes, write_private};
use crate::ln::{check_invoice, cltv_until, cross_check, htlc_locks, htlcs_in_flight, i64_of, paid_msat, preimage_bytes, preimage_proves, u64_of, HeldSend,
                LnBackend, LnPolicy};
use crate::node;
use crate::policy::{normalize_dest, Payment, PolicyConfig, DAY_S, WEEK_S};
use crate::pyjson::{dumps_indent, py_int, str_or_empty, ts_value};
use crate::sigaudit;
use crate::signer::{deny, with, Signer};
use crate::ticket::{self, booking_sats, check_prepaid_invoice, check_ticket_invoice, ledger_id, sats_ceil, sizing, Admit, Book, Limits, SState, Seed, Session,
                    Settle, TState, TaskPolicy, Terms, Ticket, TicketPolicy, HOLD_SHORT, KEEP_DONE_S, MAX_BATCH, OFFER_TTL_S, ROUTE_FULL, SESSION_IDLE_S,
                    TAG_RECORD};
use crate::{err, Result};

pub const BOOK_FILE: &str = "tickets.jsonl";
pub const SEED_FILE: &str = "ticket_seed.json";
const SEED_AAD: &str = "xbt/ticket-seed";
/// The task name of a ticket found on the node that the book did not hold.
pub const RECOVERED_TASK: &str = "recovered";
/// Payments read from the node's list in one call, and calls in one reconcile.
const LIST_PAGE: u64 = 100;
const LIST_PAGES: usize = 50;
/// Ticket payments with the node's router at once, all sessions together. A channel that carries
/// 30 pending payments took 200 small payments sent 8 at a time without a failure, and failed 139
/// of 200 sent 64 at a time (`docs/TICKETS.md` section 11).
pub const SEND_PARALLEL: usize = 8;

/// The gate every ticket payment passes on its way to the node's router: at most
/// [`SEND_PARALLEL`] are inside at once. Who waits here: the threads of lock rounds and of prepaid
/// purchases, of which the owner's `tickets.max_sellers` bounds the number; each leaves when its
/// send returns, which the Lightning rail's `timeout_s` bounds.
#[derive(Default)]
pub struct Pace {
    inside: Mutex<usize>,
    left: Condvar,
}

pub struct PaceGuard<'a>(&'a Pace);

impl Pace {
    pub fn enter(&self) -> PaceGuard<'_> {
        let mut n = self.inside.lock().unwrap_or_else(|p| p.into_inner());
        while *n >= SEND_PARALLEL {
            n = self.left.wait(n).unwrap_or_else(|p| p.into_inner());
        }
        *n += 1;
        PaceGuard(self)
    }

    /// How many are inside now.
    pub fn inside(&self) -> usize {
        *self.inside.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl Drop for PaceGuard<'_> {
    fn drop(&mut self) {
        let mut n = self.0.inside.lock().unwrap_or_else(|p| p.into_inner());
        *n = n.saturating_sub(1);
        self.0.left.notify_one();
    }
}

/// Whether the node is done with a payment: it succeeded, or failed with no HTLC out.
fn payment_over(p: &Value) -> bool {
    let status = str_or_empty(p.get("status"));
    status == "SUCCEEDED" || (status == "FAILED" && !htlcs_in_flight(p))
}

/// The book on disk: `tickets.jsonl`, an append-only log ([`crate::applog`]) of whole sessions and
/// tickets, folded into a [`Book`]. A change is durable before it is in memory, and before
/// anything is built on it.
pub struct TicketStore {
    log: AppendLog,
    pub book: Book,
    compact_above: usize,
}

impl TicketStore {
    pub fn open(path: &Path) -> Result<Self> {
        let (log, rows) = AppendLog::open(path, "tickets")?;
        let mut book = Book::default();
        for r in &rows {
            book.apply(r)?;
        }
        let compact_above = 2 * rows.len() + 1024;
        Ok(Self { log, book, compact_above })
    }

    /// Write `rows` (one write, one fsync), then apply them. Each row stands alone: a crash that
    /// keeps some of them leaves a book this module accepts.
    pub fn commit(&mut self, rows: &[Value]) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        self.log.append_all(rows)?;
        for r in rows {
            self.book.apply(r)?;
        }
        Ok(())
    }

    /// Rewrite the log as the book's rows when it has grown to twice that and more, without what
    /// ended more than [`KEEP_DONE_S`] ago. A ticket that is not final is never dropped.
    pub fn compact_if_grown(&mut self, now: f64) -> Result<()> {
        if self.log.file_rows <= self.compact_above {
            return Ok(());
        }
        let rows = self.book.snapshot(now - KEEP_DONE_S);
        self.log.compact(&rows)?;
        let mut book = Book::default();
        for r in &rows {
            book.apply(r)?;
        }
        self.book = book;
        self.compact_above = 2 * rows.len() + 1024;
        Ok(())
    }
}

fn refusal(rule: &str, reason: impl Into<String>) -> Value {
    with(deny(rule, reason), json!({"rail": "ticket", "charged_sats": 0}))
}

/// The tags on the last hop of each of a node payment's HTLCs ([`TAG_RECORD`]; base64 over REST).
fn payment_tags(p: &Value) -> Vec<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE as B64URL};
    use base64::Engine as _;
    p.get("htlcs").and_then(Value::as_array).into_iter().flatten()
        .filter_map(|h| h.get("route")?.get("hops")?.as_array()?.last()?.get("custom_records")?.get(TAG_RECORD.to_string())?.as_str().map(str::to_string))
        .filter_map(|s| B64.decode(&s).or_else(|_| B64URL.decode(&s)).or_else(|_| hex::decode(&s)).ok()).collect()
}

/// The node id a node payment's HTLCs end at, when they all end at one.
fn payment_payee(p: &Value) -> Option<String> {
    let mut ends = p.get("htlcs").and_then(Value::as_array)?.iter()
        .filter_map(|h| h.get("route")?.get("hops")?.as_array()?.last()?.get("pub_key")?.as_str().map(str::to_lowercase));
    let first = ends.next()?;
    ends.all(|e| e == first).then_some(first)
}

/// The height the last hop's HTLC of an in-flight payment expires at (0: none known). The earliest
/// of them: the seller must settle before the first.
fn final_expiry(p: &Value) -> i64 {
    p.get("htlcs").and_then(Value::as_array).into_iter().flatten().filter(|h| str_or_empty(h.get("status")) == "IN_FLIGHT")
        .filter_map(|h| h.get("route")?.get("hops")?.as_array()?.last().map(|hop| i64_of(hop.get("expiry")))).filter(|e| *e > 0).min().unwrap_or(0)
}

fn payment_ts(p: &Value) -> Option<f64> {
    let ns = u64_of(p.get("creation_time_ns"));
    if ns > 0 {
        return Some(ns as f64 / 1e9);
    }
    Some(u64_of(p.get("creation_date"))).filter(|s| *s > 0).map(|s| s as f64)
}

/// Sats the ledger holds in the scopes a ticket is checked against.
struct Spent {
    daily: i64,
    weekly: i64,
    task: i64,
    seller: i64,
}

impl Signer {
    fn ticket_path(&self) -> PathBuf {
        self.run.join(BOOK_FILE)
    }

    pub(crate) fn ticket_policy(&self) -> TicketPolicy {
        TicketPolicy::from_map(&self.config().tickets)
    }

    /// The book, opened (and created) when first needed. An error keeps the ticket rail shut and
    /// nothing else.
    pub(crate) fn ticket_store(&self) -> Result<MutexGuard<'_, Option<TicketStore>>> {
        let mut g = self.tickets.lock().unwrap_or_else(|p| p.into_inner());
        if g.is_none() {
            *g = Some(TicketStore::open(&self.ticket_path())?);
        }
        Ok(g)
    }

    /// The hashes of every ticket in the book: an HTLC for one of them is the wallet's own. Empty
    /// when the wallet has no book; a book that cannot be read counts for nothing here, so its
    /// HTLCs are held against the budgets as any other the wallet did not book.
    pub(crate) fn ticket_hashes(&self) -> HashSet<String> {
        if !self.ticket_path().exists() {
            return HashSet::new();
        }
        match self.ticket_store() {
            Ok(g) => g.as_ref().map(|s| s.book.tickets.keys().cloned().collect()).unwrap_or_default(),
            Err(_) => HashSet::new(),
        }
    }

    /// The ticket seed: read from `ticket_seed.json`, or made when the wallet has neither a seed
    /// nor a ticket. A book with tickets and no seed is an error: a new seed could neither know
    /// their secrets nor read their tags.
    fn ticket_seed(&self, book: &Book) -> Result<Arc<Seed>> {
        let mut g = self.ticket_seed.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(s) = &*g {
            return Ok(s.clone());
        }
        let path = self.run.join(SEED_FILE);
        let bytes: [u8; 32] = match std::fs::read_to_string(&path) {
            Ok(text) => {
                let raw: Value = serde_json::from_str(&text).map_err(|e| err("ticket_seed", format!("{SEED_FILE}: {e}")))?;
                let plain = match raw.get("sealed") {
                    Some(blob) => {
                        let ks = self.keystore.as_ref().ok_or_else(|| err("keystore", "the ticket seed is encrypted: set B2_HOT_KEYFILE or B2_HOT_PASSPHRASE"))?;
                        hex::decode(&*ks.open(blob, SEED_AAD)?).ok()
                    }
                    None => hex::decode(str_or_empty(raw.get("plain"))).ok(),
                };
                plain.and_then(|b| b.try_into().ok()).ok_or_else(|| err("ticket_seed", format!("{SEED_FILE} does not hold a 32-byte seed")))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !book.tickets.is_empty() {
                    return Err(err("ticket_seed", format!("{SEED_FILE} is missing and the book holds tickets: restore it with the book")));
                }
                let bytes = random_bytes::<32>();
                let doc = match &self.keystore {
                    Some(ks) => json!({"sealed": ks.seal(hex::encode(bytes).as_bytes(), SEED_AAD, None)?}),
                    None => json!({"plain": hex::encode(bytes)}),
                };
                write_private(&path, &dumps_indent(&doc, 2, false))?;
                bytes
            }
            Err(e) => return Err(err("ticket_seed", format!("{SEED_FILE}: {e}"))),
        };
        let seed = Arc::new(Seed::new(bytes));
        *g = Some(seed.clone());
        Ok(seed)
    }

    /// The rail is on, its book opens, and nothing has halted Lightning payments.
    fn ticket_on(&self) -> std::result::Result<TicketPolicy, Value> {
        let tp = self.ticket_policy();
        if !tp.enabled {
            return Err(refusal("ticket_disabled", "stream tickets are off in this policy (tickets.enabled)"));
        }
        if !LnPolicy::from_map(&self.config().ln).enabled {
            return Err(refusal("ln_disabled", "tickets are paid through the Lightning rail, which is off in this policy (ln.enabled)"));
        }
        if let Some(h) = self.ln_book.halted() {
            self.ln_resume_request(&h);
            return Err(with(refusal("ln_halted", format!("Lightning payments are halted until the human resumes them (the approval queue): {}",
                                                         str_or_empty(h.get("reason")))), json!({"halted": h})));
        }
        Ok(tp)
    }

    /// As [`Self::ticket_on`], and the node's payment list has been read to its end since this
    /// process started: until then the book may lack tickets the node holds.
    fn ticket_synced(&self) -> std::result::Result<TicketPolicy, Value> {
        let tp = self.ticket_on()?;
        if !self.ticket_synced.load(Ordering::SeqCst) {
            self.ticket_reconcile_locked();
            if !self.ticket_synced.load(Ordering::SeqCst) {
                return Err(refusal("ticket_sync", "the wallet has not yet read the Lightning node's payment list since it started: until then \
                                                   it cannot know that its book is whole"));
            }
        }
        Ok(tp)
    }

    pub(crate) fn ticket_audit(&self, kind: &str, fields: Value) {
        self.engine.audit.append(with(json!({"type": kind, "ts": ts_value(self.engine.now())}), fields));
    }

    /// Whether the owner named this seller: its node id on the allowlist (`ln:<node id>`), or an
    /// allowlisted origin whose `counterparties` entry names the node (`ln_node`). The origin is
    /// the caller's word, so it counts only where the owner tied it to this node id.
    fn ticket_listed(&self, cfg: &PolicyConfig, payee: &str, origin: &str) -> bool {
        let allow = cfg.normalized_allowlist();
        if allow.contains(&format!("ln:{payee}")) {
            return true;
        }
        let o = normalize_dest(origin);
        !o.is_empty() && allow.contains(&o)
            && cfg.counterparties.get(&o).and_then(|c| c.get("ln_node")).and_then(Value::as_str).is_some_and(|n| n.trim().eq_ignore_ascii_case(payee))
    }

    /// The owner's caps for one seller under a task: `(tickets locked, sats locked, sats paid, the window of the last)`.
    fn ticket_seller_caps(cfg: &PolicyConfig, tp: &TicketPolicy, task: &TaskPolicy, listed: bool) -> (i64, i64, i64, f64) {
        if listed {
            (tp.seller_max_tickets, tp.seller_max_locked_sats, cfg.per_counterparty_cap_sats, WEEK_S)
        } else {
            (task.unlisted_max_tickets.min(tp.seller_max_tickets), task.unlisted_max_locked_sats.min(tp.seller_max_locked_sats),
             task.unlisted_max_spend_sats.min(cfg.per_counterparty_cap_sats), task.window_s as f64)
        }
    }

    /// What the ledger holds now, in the scopes of one seller under one task. Every row counts
    /// whatever rail wrote it, so a budget is one budget.
    fn ticket_spent(&self, now: f64, task: &str, task_window: f64, dest: &str, seller_window: f64) -> Result<Spent> {
        let mut s = Spent { daily: 0, weekly: 0, task: 0, seller: 0 };
        let add = |slot: &mut i64, n: i64| *slot = slot.saturating_add(n.max(0));
        for p in self.engine.store.payments()? {
            let age = now - p.ts;
            if age <= DAY_S {
                add(&mut s.daily, p.amount_sats);
            }
            if age <= WEEK_S {
                add(&mut s.weekly, p.amount_sats);
            }
            if age <= task_window && ticket::memo_task(&p.memo) == Some(task) {
                add(&mut s.task, p.amount_sats);
            }
            if age <= seller_window && p.dest == dest {
                add(&mut s.seller, p.amount_sats);
            }
        }
        Ok(s)
    }

    /// Put `sats` in the ledger under the ticket's id: a new row dated `ts`, or the row it already
    /// has made that amount. Durable when it returns.
    fn ticket_ledger_put(&self, t: &Ticket, sats: i64, ts: f64) -> Result<()> {
        let id = ledger_id(&t.hash);
        if self.engine.store.amend(&id, Some(sats))? {
            return Ok(());
        }
        let task = if ticket::task_name_ok(&t.task) { t.task.as_str() } else { RECOVERED_TASK };
        self.engine.commit(&Payment { dest: format!("ln:{}", t.payee), amount_sats: sats, memo: ticket::memo(task, &t.session), ts }, &id)
    }

    /// A ticket whose secret may have left without this book knowing: booked as released, never
    /// released by this process.
    fn ticket_retire(&self, st: &mut TicketStore, mut t: Ticket, now: f64, why: &str) -> Result<()> {
        let sats = booking_sats(t.msat, t.fee_limit_msat);
        // the ledger first: a crash between the two leaves the spend counted
        self.ticket_ledger_put(&t, sats, if t.sent_ts > 0.0 { t.sent_ts } else { now })?;
        t.state = TState::Retired;
        t.booked_sats = sats;
        t.note = why.into();
        st.commit(&[t.row()])?;
        self.ticket_audit("ticket_retired", json!({"payment_hash": t.hash, "dest": format!("ln:{}", t.payee), "booked_sats": sats, "reason": why}));
        Ok(())
    }

    /// At every start, before any request: a start cannot be told from a restore of an older
    /// book, in which a ticket the book shows locked may have been released since. So every ticket
    /// that is locked and unreleased is retired, hashes offered and unpaid are dropped, and every
    /// session is stopped. An error shuts the ticket rail (`ticket_status` says why), not the signer.
    pub(crate) fn ticket_start(&self) {
        if !self.ticket_path().exists() {
            return;
        }
        let _g = self.lock();
        let out = (|| -> Result<Value> {
            let mut g = self.ticket_store()?;
            let st = g.as_mut().ok_or_else(|| err("ticket", "no ticket book"))?;
            let now = self.engine.now();
            let live: Vec<Ticket> = st.book.tickets.values().filter(|t| matches!(t.state, TState::Offered | TState::Sending | TState::Locked)).cloned().collect();
            let (mut retired, mut dropped) = (0, 0);
            for mut t in live {
                if t.state == TState::Offered {
                    t.state = TState::Failed;
                    t.done_ts = now;
                    t.note = "offered before a restart of the signer".into();
                    st.commit(&[t.row()])?;
                    dropped += 1;
                } else {
                    self.ticket_retire(st, t, now, "locked before a start of the signer: its secret may have left")?;
                    retired += 1;
                }
            }
            let open: Vec<Session> = st.book.sessions.values().filter(|s| s.state == SState::Open).cloned().collect();
            let stopped = open.len();
            for mut s in open {
                s.state = SState::Stopping;
                s.stopped_ts = now;
                s.why = "the signer restarted".into();
                st.commit(&[s.row()])?;
            }
            st.commit(&[json!({"e": "start", "ts": ts_value(now)})])?;
            Ok(json!({"retired": retired, "offers_dropped": dropped, "sessions_stopped": stopped}))
        })();
        match out {
            Ok(v) => self.ticket_audit("ticket_start", v),
            Err(e) => {
                *self.ticket_error.lock().unwrap_or_else(|p| p.into_inner()) = Some(e.msg.clone());
                self.ticket_audit("ticket_start_failed", json!({"error": e.msg}));
            }
        }
    }

    fn ticket_shut(&self) -> Option<Value> {
        self.ticket_error.lock().unwrap_or_else(|p| p.into_inner()).clone()
            .map(|e| refusal("ticket_book", format!("the ticket book could not be brought up at start, and the rail stays shut until it is: {e}")))
    }

    // --- open, offer --------------------------------------------------------------------------------

    /// `ticket_open`: a session with one seller under one of the owner's tasks. `terms` is the
    /// `accepts` entry of the seller's 402 as the caller received it. Nothing is paid or locked.
    pub(crate) fn ticket_open_locked(&self, p: &Value) -> Value {
        if let Some(d) = self.ticket_shut() {
            return d;
        }
        let tp = match self.ticket_on() {
            Ok(t) => t,
            Err(d) => return d,
        };
        let task_name = str_or_empty(p.get("task"));
        let Some(task) = tp.tasks.get(&task_name) else {
            return refusal("ticket_task", format!("the owner's policy names no task {task_name:?} (tickets.tasks): tickets are paid only under a task with a budget"));
        };
        let amount = |k: &str| match p.get(k).filter(|v| !v.is_null()) {
            None => Ok(None),
            Some(v) => py_int(Some(v)).filter(|n| *n >= 0).map(Some).ok_or_else(|| refusal("amount", format!("{k} must be a non-negative integer"))),
        };
        let (expect_sats, max_sats) = match (amount("expect_sats"), amount("max_sats")) {
            (Ok(e), Ok(m)) => (e, m.unwrap_or(0)),
            (Err(d), _) | (_, Err(d)) => return d,
        };
        let net = match node::network(&*self.node, &self.chain, None) {
            Ok(n) => n.replacen("bip122:", "lightning:", 1),
            Err(e) => return refusal("ticket_network", e.msg),
        };
        let first = match Terms::parse(p.get("terms").unwrap_or(&Value::Null), &net) {
            Ok(t) => t,
            Err((rule, why)) => return refusal(rule, why),
        };
        // a seller that offers both ways lists two entries: the held one is `terms`, and
        // `prepaid_terms` its entry for tickets settled on arrival. One that offers only prepaid
        // tickets has that entry as `terms`. A second entry that is not the same seller's is no offer
        let (held, prepaid) = match first.settle {
            Settle::OnUse => {
                let second = p.get("prepaid_terms").filter(|v| !v.is_null()).and_then(|v| Terms::parse(v, &net).ok())
                    .filter(|t| t.settle == Settle::OnArrival && t.payee == first.payee && t.ticket_blocks == first.ticket_blocks);
                (Some(first.clone()), second)
            }
            Settle::OnArrival => (None, Some(first.clone())),
        };
        let terms = first;
        let prepaid_msat = match &prepaid {
            None => 0,
            Some(t) => match (ticket::prepaid_size(t, &tp), &held) {
                (Ok(m), _) => m,
                // prepaid tickets the owner's bounds refuse are not on offer; with nothing else, the seller is refused
                (Err(_), Some(_)) => 0,
                (Err((rule, why)), None) => return refusal(rule, why),
            },
        };
        let cfg = self.config();
        let origin = str_or_empty(p.get("origin"));
        let listed = self.ticket_listed(&cfg, &terms.payee, &origin);
        if !listed && task.admit != Admit::Any {
            return refusal("ticket_admission", format!("the owner has not named the seller {} and task {task_name:?} pays only named sellers \
                                                        (the allowlist, or tickets.tasks.{task_name}.admit \"any\")", terms.payee));
        }
        let (cap_tickets, cap_locked, _, _) = Self::ticket_seller_caps(&cfg, &tp, task, listed);
        let now = self.engine.now();
        // what the wallet's own channels allow of held tickets, read now; channels that cannot be read are
        // taken to carry 30 pending payments, and every lock reads them again and refuses without a listing
        let limits = if held.is_some() { self.ticket_limits_read().unwrap_or_else(Limits::unseen) } else { Limits::unseen() };
        let out = (|| -> Result<Value> {
            let mut g = self.ticket_store()?;
            let st = g.as_mut().ok_or_else(|| err("ticket", "no ticket book"))?;
            self.ticket_seed(&st.book)?;
            if let Some(s) = st.book.open_with(&terms.payee) {
                return Ok(with(refusal("ticket_session_exists", "a session with this seller is open: stop it first"), json!({"session": s.id})));
            }
            if st.book.open_sessions(None) as i64 >= tp.max_sellers {
                return Ok(refusal("ticket_sellers", format!("{} sessions are open (tickets.max_sellers)", tp.max_sellers)));
            }
            if st.book.open_sessions(Some(&task_name)) as i64 >= task.max_sellers {
                return Ok(refusal("ticket_sellers", format!("task {task_name:?} has {} sessions open (its max_sellers)", task.max_sellers)));
            }
            if st.book.opened_since(now - 60.0) as i64 >= tp.max_new_sellers_per_min {
                return Ok(refusal("ticket_sellers", format!("{} sessions were opened in the last minute (tickets.max_new_sellers_per_min)", tp.max_new_sellers_per_min)));
            }
            let sellers = st.book.open_sessions(Some(&task_name)) + 1;
            let expect_msat = expect_sats.map(|s| (s as u64).saturating_mul(1000));
            // the slot budget: half of the smallest channel, less what the open sessions hold or will lock
            let committed = st.book.pools_open();
            let to_fill = committed.saturating_sub(st.book.locked(|_| true).tickets).max(0);
            let room = limits.room(committed, to_fill);
            // what an earlier session with this seller learnt about its route, if it is recent
            let before = st.book.held_less(&terms.payee, now).cloned();
            let held_size = held.as_ref().map(|t| {
                if let Some(b) = before.as_ref().filter(|b| b.hold_why == ROUTE_FULL && now < b.hold_until) {
                    return Err((ROUTE_FULL, format!("three lock rounds in a row found no slot on the route to this seller: no ticket is held with it for another {:.0} s",
                                                    b.hold_until - now)));
                }
                sizing(t, &tp, sellers, expect_msat, cap_tickets, cap_locked, limits.dust_msat, room)
            });
            // held tickets are the default; where none can be held for lack of a slot or for dust, and the
            // seller offers prepaid tickets, the session holds nothing and buys those one at a time
            let (mut size, mut hold_why) = match held_size {
                Some(Ok(s)) => (s, String::new()),
                Some(Err((rule, _))) if prepaid_msat > 0 && HOLD_SHORT.contains(&rule) => (ticket::Sizing { ticket_msat: prepaid_msat, pool: 0 }, rule.to_string()),
                Some(Err((rule, why))) => return Ok(with(refusal(rule, why), json!({"slots": limits.slots, "held_budget": limits.budget(), "held_now": committed}))),
                None => (ticket::Sizing { ticket_msat: prepaid_msat, pool: 0 }, String::new()),
            };
            // a session that holds tickets goes on where the last one with this seller stopped: its smaller pool,
            // its failed rounds, and what is left of its wait
            let (mut slot_fails, mut hold_until) = (0u32, 0.0f64);
            if let Some(b) = before.filter(|_| size.pool > 0) {
                size.pool = size.pool.min(b.pool.max(1));
                // after a route that was full for three rounds the first failed round is the third again: ten more minutes
                slot_fails = if b.hold_why == ROUTE_FULL { ticket::SLOT_FAILS_MAX - 1 } else { b.slot_fails };
                if now < b.hold_until {
                    (hold_until, hold_why) = (b.hold_until, b.hold_why.clone());
                }
            }
            let lp = LnPolicy::from_map(&cfg.ln);
            let largest = size.ticket_msat.max(prepaid_msat);
            let one = booking_sats(largest, (lp.fee_limit_sats(sats_ceil(largest)).max(0) as u64).saturating_mul(1000));
            // no human can approve a release as it happens: a ticket that would need one is refused here
            if one >= cfg.human_threshold_sats || one > cfg.max_per_tx_sats {
                return Ok(refusal("ticket_size", format!("one ticket with its fee limit is {one} sats: at or above human_threshold_sats {} or above \
                                                          max_per_tx_sats {}", cfg.human_threshold_sats, cfg.max_per_tx_sats)));
            }
            // `tickets.velocity: "session"`: the session is the payment `velocity_max` counts, so one that
            // could never release is refused before it locks anything
            let id = crate::policy::token_urlsafe();
            if tp.velocity == ticket::Velocity::Session && self.engine.velocity_used(&ticket::memo(&task_name, &id))? >= cfg.velocity_max {
                return Ok(refusal("velocity", format!("already {} payments in the last {}s (a ticket session is one payment: tickets.velocity)",
                                                      cfg.velocity_max, cfg.velocity_window_s)));
            }
            let s = Session { id, payee: terms.payee.clone(), origin: origin.chars().take(200).collect(), task: task_name.clone(),
                              listed, ticket_msat: size.ticket_msat, pool: size.pool, max_tickets: terms.max_tickets, ticket_blocks: terms.ticket_blocks,
                              max_sats, state: SState::Open, opened_ts: now, active_ts: now, stopped_ts: 0.0, closed_ts: 0.0, why: String::new(), http: None,
                              prepaid_msat, slot_fails, hold_until, hold_why };
            st.commit(&[s.row()])?;
            self.ticket_audit("ticket_open", json!({"session": s.id, "dest": format!("ln:{}", s.payee), "task": s.task, "listed": listed,
                                                    "ticket_msat": s.ticket_msat.to_string(), "pool": s.pool, "prepaid_msat": s.prepaid_msat.to_string(),
                                                    "hold_why": s.hold_why, "slots": limits.slots}));
            Ok(with(json!({"verdict": "allow", "rail": "ticket"}), s.public()))
        })();
        out.unwrap_or_else(|e| refusal("ticket", e.msg))
    }

    /// `ticket_offer`: the hashes the session's pool wants locked now (none while it is above its
    /// refill mark). The secrets stay here; the caller sends the hashes to the seller.
    pub(crate) fn ticket_offer_locked(&self, p: &Value) -> Value {
        if let Some(d) = self.ticket_shut() {
            return d;
        }
        if let Err(d) = self.ticket_on() {
            return d;
        }
        let sid = str_or_empty(p.get("session"));
        let now = self.engine.now();
        let out = (|| -> Result<Value> {
            let mut g = self.ticket_store()?;
            let st = g.as_mut().ok_or_else(|| err("ticket", "no ticket book"))?;
            let Some(mut s) = st.book.sessions.get(&sid).cloned() else { return Ok(refusal("ticket_session", "no such session")) };
            if s.state != SState::Open {
                return Ok(refusal("ticket_session", format!("the session is {}", s.state.as_str())));
            }
            let seed = self.ticket_seed(&st.book)?;
            // hashes the seller sent no invoice for: their slots are offered again
            let mut rows: Vec<Value> = st.book.of_session(&sid).into_iter().filter(|t| t.state == TState::Offered && now - t.ts > OFFER_TTL_S).map(|t| {
                let mut t = t.clone();
                t.state = TState::Failed;
                t.done_ts = now;
                t.note = "no invoice came for it".into();
                t.row()
            }).collect();
            st.commit(&rows)?;
            rows.clear();
            let want = st.book.want(&s, now);
            let mut hashes = vec![];
            for _ in 0..want {
                let nonce = random_bytes::<16>();
                let hash = hex::encode(seed.hash(&nonce));
                if st.book.tickets.contains_key(&hash) {
                    continue;
                }
                rows.push(Ticket { hash: hash.clone(), nonce, session: sid.clone(), payee: s.payee.clone(), task: s.task.clone(), msat: s.ticket_msat,
                                   fee_limit_msat: 0, state: TState::Offered, ts: now, sent_ts: 0.0, invoice_expires: 0.0, released_ts: 0.0, booked_sats: 0,
                                   cltv_until: 0, final_expiry: 0, fee_msat: 0, done_ts: 0.0, note: String::new(), prepaid: false }.row());
                hashes.push(hash);
            }
            if !hashes.is_empty() {
                s.active_ts = now;
                rows.push(s.row());
            }
            st.commit(&rows)?;
            Ok(json!({"verdict": "allow", "rail": "ticket", "session": sid, "hashes": hashes, "ticket_msat": s.ticket_msat.to_string(),
                      "ticket_blocks": s.ticket_blocks, "payee": s.payee}))
        })();
        out.unwrap_or_else(|e| refusal("ticket", e.msg))
    }

    // --- lock ---------------------------------------------------------------------------------------

    /// `ticket_lock`: check the seller's invoices for hashes of this session and pay those that
    /// pass, through the owner's node. `tickets` is `[{"hash", "invoice"}]` as the seller answered.
    /// Every invoice is the seller's word; so is every field of the request.
    pub(crate) fn ticket_lock(&self, p: &Value) -> Value {
        if let Some(d) = self.ticket_shut() {
            return d;
        }
        let sid = str_or_empty(p.get("session"));
        let items: Vec<Value> = p.get("tickets").and_then(Value::as_array).cloned().unwrap_or_default();
        if items.is_empty() || items.len() > MAX_BATCH {
            return refusal("ticket_request", format!("tickets: 1 to {MAX_BATCH} of {{\"hash\", \"invoice\"}}"));
        }
        let (ln, lp, session) = {
            let _g = self.lock();
            let tp = match self.ticket_synced() {
                Ok(t) => t,
                Err(d) => return d,
            };
            let (ln, lp) = match self.ln_ready() {
                Ok(x) => x,
                Err(d) => return with(d, json!({"rail": "ticket", "charged_sats": 0})),
            };
            let session = match self.ticket_store() {
                Ok(g) => g.as_ref().and_then(|st| st.book.sessions.get(&sid).cloned()),
                Err(e) => return refusal("ticket", e.msg),
            };
            let Some(session) = session.filter(|s| s.state == SState::Open) else { return refusal("ticket_session", "no such open session") };
            if !tp.tasks.contains_key(&session.task) {
                return refusal("ticket_task", format!("the owner's policy no longer names the task {:?}", session.task));
            }
            (ln, lp, session)
        };
        let dest = format!("ln:{}", session.payee);
        // the rail's own checks of the node and of the channels a payment may leave through: no lock held
        if let Err(d) = self.ln_node_checks(&*ln, &lp, &dest, "") {
            return with(d, json!({"rail": "ticket"}));
        }
        let routes = match self.ln_route_checks(&*ln, &lp, &dest, "", false) {
            Ok(r) => r,
            Err(d) => return with(d, json!({"rail": "ticket"})),
        };
        // each invoice as the signer reads it and as the node reads it
        let now = self.engine.now();
        let tp_now = self.ticket_policy();
        let relaxed = LnPolicy { min_expiry_s: 0, max_cltv_blocks: i64::MAX, require_description: false, ..lp.clone() };
        let mut refused: Vec<Value> = vec![];
        let mut refuse = |hash: &str, rule: &str, why: String| {
            self.ticket_audit("ticket_refused", json!({"session": sid, "dest": dest, "payment_hash": hash, "rule": rule, "reason": why}));
            refused.push(json!({"hash": hash, "rule": rule, "reason": why}));
        };
        let mut read: Vec<(String, String, Invoice)> = vec![];
        for it in &items {
            let named = str_or_empty(it.get("hash"));
            let invoice = str_or_empty(it.get("invoice")).trim().to_string();
            let inv = match bolt11::decode(&invoice) {
                Ok(i) => i,
                Err(e) => {
                    refuse(&named, "ticket_invoice", format!("not a valid BOLT 11 invoice: {e}"));
                    continue;
                }
            };
            let hash = inv.payment_hash_hex();
            if !named.is_empty() && named != hash {
                refuse(&named, "ticket_hash", "the invoice is for another payment hash than the one it was returned for".into());
                continue;
            }
            if read.iter().any(|(h, _, _)| *h == hash) {
                refuse(&hash, "ticket_replay", "two invoices for one hash: a hash is paid once".into());
                continue;
            }
            if let Err((rule, why)) = check_invoice(&inv, &self.chain, now, &relaxed, "") {
                refuse(&hash, &rule, why);
                continue;
            }
            if let Err((rule, why)) = check_ticket_invoice(&inv, &session, &tp_now, now) {
                refuse(&hash, rule, why);
                continue;
            }
            match ln.decode(&invoice) {
                Ok(d) => {
                    if let Err(why) = cross_check(&inv, &d) {
                        refuse(&hash, "ln_decode_mismatch", why);
                        continue;
                    }
                }
                Err(e) => {
                    refuse(&hash, "ln_backend", e.msg);
                    continue;
                }
            }
            read.push((hash, invoice, inv));
        }
        // the caps and the write-ahead rows, under the wallet's spend lock
        let booked = {
            let _g = self.lock();
            self.ticket_book_sends(&sid, &read, &lp, &routes.chans, &routes.ids, &mut refuse)
        };
        let sends = match booked {
            Ok(s) => s,
            Err(d) => return d,
        };
        // the node routes them, a few at once (all sessions together: `Pace`); no lock is held
        let mut outcomes: Vec<Result<Value>> = vec![];
        for chunk in sends.chunks(SEND_PARALLEL) {
            outcomes.extend(std::thread::scope(|sc| {
                let hs: Vec<_> = chunk.iter().map(|(_, r)| {
                    let (ln, pace) = (&ln, &self.ticket_pace);
                    sc.spawn(move || {
                        let _inside = pace.enter();
                        ln.send_held(r)
                    })
                }).collect();
                hs.into_iter().map(|h| h.join().unwrap_or_else(|_| Err(err("ln_send", "the send did not return")))).collect::<Vec<_>>()
            }));
        }
        // what the node made of each
        let _g = self.lock();
        let mut tickets = vec![];
        let mut held_less = Value::Null;
        let res = (|| -> Result<()> {
            let mut g = self.ticket_store()?;
            let st = g.as_mut().ok_or_else(|| err("ticket", "no ticket book"))?;
            let (mut locked, mut slot_failed) = (0usize, 0usize);
            for ((hash, _), sent) in sends.iter().zip(outcomes) {
                let pmt = match sent {
                    Ok(p) => Some(p),
                    // did it reach the router? The node's own record says; with no answer it stays `sending`
                    Err(_) => ln.lookup(hash).ok().flatten(),
                };
                if let Some(pmt) = pmt {
                    self.ticket_apply(st, hash, &pmt)?;
                }
                if let Some(t) = st.book.tickets.get(hash) {
                    locked += usize::from(t.state == TState::Locked);
                    // a payment that failed as a full channel does: the node names no slot, only a balance or a route
                    slot_failed += usize::from(t.state == TState::Failed && ticket::slot_failure(&t.note));
                    tickets.push(t.public());
                }
            }
            // a round that found no slot makes the session hold less: one ticket fewer, a wait, then nothing
            if let Some(mut s) = st.book.sessions.get(&sid).filter(|s| s.state == SState::Open).cloned() {
                let had = s.pool;
                if !sends.is_empty() && s.lock_round(locked, slot_failed, self.engine.now()) {
                    st.commit(&[s.row()])?;
                    if slot_failed > 0 {
                        held_less = json!({"slot_failed": slot_failed, "pool_was": had, "pool": s.pool, "slot_fails": s.slot_fails,
                                           "hold_until": ts_value(s.hold_until), "hold_why": s.hold_why});
                        self.ticket_audit("ticket_slot_failure", with(json!({"session": sid, "dest": dest, "locked": locked}), held_less.clone()));
                    }
                }
            }
            Ok(())
        })();
        if let Err(e) = res {
            return refusal("ticket", e.msg);
        }
        let locked = tickets.iter().filter(|t| t["state"] == "locked").count();
        self.ticket_audit("ticket_lock", json!({"session": sid, "dest": dest, "asked": items.len(), "sent": sends.len(), "locked": locked, "refused": refused.len()}));
        let mut out = json!({"verdict": if sends.is_empty() { "deny" } else { "allow" }, "rail": "ticket", "session": sid, "locked": locked, "tickets": tickets,
                             "refused": refused, "charged_sats": 0});
        if !held_less.is_null() {
            out["held_less"] = held_less;
        }
        if sends.is_empty() {
            out = with(out, json!({"rule": "ticket_refused", "reason": "no invoice passed the checks: nothing was paid"}));
        }
        if !routes.warnings.is_empty() {
            out["warnings"] = json!(routes.warnings);
        }
        out
    }

    /// The caps on the book's own counts, then the write-ahead rows (the caller holds the spend
    /// lock). `read` are invoices that passed every check of their content. Returns the sends.
    fn ticket_book_sends(&self, sid: &str, read: &[(String, String, Invoice)], lp: &LnPolicy, chans: &[Value], ids: &[String],
                         refuse: &mut dyn FnMut(&str, &str, String)) -> std::result::Result<Vec<(String, HeldSend)>, Value> {
        let tp = self.ticket_synced()?;
        let cfg = self.config();
        let now = self.engine.now();
        let mut g = self.ticket_store().map_err(|e| refusal("ticket", e.msg))?;
        let st = g.as_mut().ok_or_else(|| refusal("ticket", "no ticket book"))?;
        let Some(mut s) = st.book.sessions.get(sid).filter(|s| s.state == SState::Open).cloned() else { return Err(refusal("ticket_session", "no such open session")) };
        let Some(task) = tp.tasks.get(&s.task) else { return Err(refusal("ticket_task", format!("the owner's policy no longer names the task {:?}", s.task))) };
        // the seller may have left the owner's list since the session opened
        let listed = self.ticket_listed(&cfg, &s.payee, &s.origin);
        if !listed && task.admit != Admit::Any {
            return Err(refusal("ticket_admission", format!("the owner no longer names the seller {} and task {:?} pays only named sellers", s.payee, s.task)));
        }
        let (cap_tickets, cap_locked, cap_spend, seller_window) = Self::ticket_seller_caps(&cfg, &tp, task, listed && s.listed);
        let dest = format!("ln:{}", s.payee);
        let spent = self.ticket_spent(now, &s.task, task.window_s as f64, &dest, seller_window).map_err(|e| refusal("ticket", e.msg))?;
        // HTLCs the node has out that no book of the wallet holds lock funds until they expire: they count against the budgets
        let known: HashSet<&String> = st.book.tickets.keys().collect();
        let ln_book = self.ln_book.all();
        let foreign = htlc_locks(chans, &|h: &str| {
            known.contains(&h.to_string()) || ln_book.get(h).and_then(|r| r.get("state")).and_then(Value::as_str).is_some_and(|x| x == "sending" || x == "settled")
        }).unbooked_sats;
        let seed = self.ticket_seed(&st.book).map_err(|e| refusal("ticket", e.msg))?;
        let (all, in_task, with_seller, in_session) = (st.book.locked(|_| true), st.book.locked(|t| t.task == s.task), st.book.locked(|t| t.payee == s.payee),
                                                       st.book.locked(|t| t.session == s.id));
        let session_booked = st.book.of_session(sid).iter().fold(0i64, |a, t| a.saturating_add(t.booked_sats));
        let fee_limit_msat = (lp.fee_limit_sats(sats_ceil(s.ticket_msat)).max(0) as u64).saturating_mul(1000);
        let (face, each) = (sats_ceil(s.ticket_msat), booking_sats(s.ticket_msat, fee_limit_msat));
        let mut sent_last_hour = st.book.sends_since(now - 3600.0) as i64;
        let (mut n, mut rows, mut sends) = (0i64, vec![], vec![]);
        // the two limits of the channels these payments may leave on, as the node lists them in this round
        let limits = ticket::channel_limits(chans, ids);
        let on_node: HashSet<String> = htlc_locks(chans, &|_| true).list.iter().map(|h| str_or_empty(h.get("payment_hash"))).collect();
        let slot_room = limits.room(all.tickets, st.book.sending_unseen(&|h| on_node.contains(h)));
        let mut held = false;
        // a hash refused for the channel's sake is given up at once: its invoice would be refused whoever issued it
        // again, and the session's wait keeps a new one from being offered straight away
        let give_up = |book: &Book, hash: &str, why: &str| book.tickets.get(hash).filter(|t| t.session == sid && t.state == TState::Offered).map(|t| {
            let mut t = t.clone();
            (t.state, t.done_ts, t.note) = (TState::Failed, now, why.into());
            t.row()
        });
        if s.ticket_msat < limits.dust_msat {
            // the ticket was sized before a channel with a higher dust limit was in the way: none of this size is held
            for (hash, _, _) in read {
                refuse(hash, "ticket_dust", format!("a ticket of {} msat is below {} msat, the dust limit of a channel it may leave on: it would have no output \
                                                     there, and be lost if that channel is force-closed", s.ticket_msat, limits.dust_msat));
                rows.extend(give_up(&st.book, hash, "below the dust limit of a channel it may leave on"));
            }
            (s.pool, s.hold_why, held) = (0, "ticket_dust".into(), true);
        }
        for (hash, invoice, inv) in read {
            if held && s.pool == 0 {
                break;
            }
            if n >= slot_room {
                refuse(hash, "ticket_slots", format!("with this ticket the wallet would hold more than half of the pending payments a channel it may leave on carries \
                                                      ({} of {}; {} held now, room for {} more)", limits.budget(), limits.slots, all.tickets, slot_room));
                rows.extend(give_up(&st.book, hash, "no free slot on the channel it would leave on"));
                // nothing more is offered for a while: a slot frees when a ticket is released or cancelled
                if !held {
                    (s.hold_until, s.hold_why, held) = (now + ticket::SLOT_WAIT_S, "ticket_slots".into(), true);
                }
                continue;
            }
            let (all, in_task, with_seller, in_session) = (all.plus(n + 1, face, each), in_task.plus(n + 1, face, each), with_seller.plus(n + 1, face, each),
                                                           in_session.plus(n + 1, face, each));
            // (what is counted, what it may be at most, the owner's or the seller's name for the bound)
            let caps: [(i64, i64, &str); 12] = [
                (in_session.tickets, i64::from(s.max_tickets), "the seller's maxTickets"),
                (with_seller.tickets, cap_tickets, "the owner's cap on tickets locked with this seller"),
                (with_seller.sats, cap_locked, "the owner's cap on sats locked with this seller"),
                (in_task.tickets, task.max_locked_tickets, "the task's max_locked_tickets"),
                (in_task.sats, task.max_locked_sats, "the task's max_locked_sats"),
                (all.tickets, tp.max_locked_tickets, "tickets.max_locked_tickets"),
                (all.sats, tp.max_locked_sats, "tickets.max_locked_sats"),
                // nothing is locked that could not also be released: what is locked fits what is left of every budget
                (spent.daily.saturating_add(all.booking).saturating_add(foreign), cfg.daily_budget_sats, "daily_budget_sats"),
                (spent.weekly.saturating_add(all.booking).saturating_add(foreign), cfg.weekly_budget_sats, "weekly_budget_sats"),
                (spent.task.saturating_add(in_task.booking), task.budget_sats, "the task's budget_sats"),
                (spent.seller.saturating_add(with_seller.booking), cap_spend, "the owner's cap on sats paid to this seller"),
                (if s.max_sats > 0 { session_booked.saturating_add(in_session.booking) } else { 0 }, if s.max_sats > 0 { s.max_sats } else { 0 },
                 "the session's max_sats"),
            ];
            if let Some((have, cap, name)) = caps.iter().find(|(have, cap, _)| have > cap) {
                refuse(hash, "ticket_cap", format!("with this ticket {have} would be above {name} ({cap})"));
                continue;
            }
            if tp.max_sends_per_hour > 0 && sent_last_hour >= tp.max_sends_per_hour {
                refuse(hash, "ticket_rate_limit", format!("already {} ticket payments sent to the node in the last hour (tickets.max_sends_per_hour)", tp.max_sends_per_hour));
                continue;
            }
            let Some(mut t) = st.book.tickets.get(hash).filter(|t| t.session == sid && t.state == TState::Offered && now - t.ts <= OFFER_TTL_S).cloned() else {
                refuse(hash, "ticket_hash", "not a hash this session offered and has not paid: an invoice for any other hash is an ordinary payment".into());
                continue;
            };
            let Ok(raw) = <[u8; 32]>::try_from(inv.payment_hash.as_slice()) else { continue };
            if seed.hash(&t.nonce) != raw {
                refuse(hash, "ticket_hash", "the book's nonce does not derive this hash".into());
                continue;
            }
            t.state = TState::Sending;
            t.sent_ts = now;
            t.fee_limit_msat = fee_limit_msat;
            t.invoice_expires = inv.expires_at() as f64;
            rows.push(t.row());
            sends.push((hash.clone(), HeldSend { invoice: invoice.clone(), fee_limit_msat: fee_limit_msat.max(1), timeout_s: lp.timeout_s.max(1),
                                                 cltv_limit: tp.max_htlc_blocks, outgoing_chan_ids: ids.to_vec(), tag: seed.tag(&t.nonce, &raw).to_vec() }));
            n += 1;
            sent_last_hour += 1;
        }
        if !sends.is_empty() || held {
            if !sends.is_empty() {
                s.active_ts = now;
            }
            rows.push(s.row());
        }
        // write-ahead: every ticket is `sending` on disk before the node sees its invoice
        st.commit(&rows).map_err(|e| refusal("ticket", e.msg))?;
        Ok(sends)
    }

    // --- release ------------------------------------------------------------------------------------

    /// `ticket_release`: the secret of one locked ticket of the session, booked as spent before it
    /// is returned. This is the only place a secret leaves the signer.
    pub(crate) fn ticket_release_locked(&self, p: &Value) -> Value {
        if let Some(d) = self.ticket_shut() {
            return d;
        }
        let tp = match self.ticket_synced() {
            Ok(t) => t,
            Err(d) => return d,
        };
        let sid = str_or_empty(p.get("session"));
        let cfg = self.config();
        let now = self.engine.now();
        let tip = self.height_safe();
        let out = (|| -> Result<Value> {
            let mut g = self.ticket_store()?;
            let st = g.as_mut().ok_or_else(|| err("ticket", "no ticket book"))?;
            let Some(mut s) = st.book.sessions.get(&sid).filter(|s| s.state == SState::Open).cloned() else {
                return Ok(refusal("ticket_session", "no such open session"));
            };
            let Some(task) = tp.tasks.get(&s.task) else {
                return Ok(refusal("ticket_task", format!("the owner's policy no longer names the task {:?}", s.task)));
            };
            let listed = self.ticket_listed(&cfg, &s.payee, &s.origin) && s.listed;
            if !listed && task.admit != Admit::Any {
                return Ok(refusal("ticket_admission", format!("the owner no longer names the seller {} and task {:?} pays only named sellers", s.payee, s.task)));
            }
            // `hash`: release this ticket and no other (the wallet's own payer names the one the seller has shown locked)
            let named = str_or_empty(p.get("hash"));
            let next = st.book.usable(&sid, tip).filter(|t| named.is_empty() || t.hash == named).cloned();
            let Some(mut t) = next else {
                return Ok(with(refusal("ticket_none", "no locked ticket of this session can be released now: lock more (ticket_offer), and ask the \
                                                       seller to cancel the stale ones"),
                               json!({"session": sid, "stale": st.book.stale(&sid, tip), "want": st.book.want(&s, now)})));
            };
            let dest = format!("ln:{}", s.payee);
            let sats = booking_sats(t.msat, t.fee_limit_msat);
            let (_, _, cap_spend, seller_window) = Self::ticket_seller_caps(&cfg, &tp, task, listed);
            let spent = self.ticket_spent(now, &s.task, task.window_s as f64, &dest, seller_window)?;
            let session_booked = st.book.of_session(&sid).iter().fold(0i64, |a, x| a.saturating_add(x.booked_sats));
            let over = [(spent.task.saturating_add(sats), task.budget_sats, "ticket_task_budget", "the task's budget_sats"),
                        (spent.seller.saturating_add(sats), cap_spend, "ticket_seller_cap", "the owner's cap on sats paid to this seller"),
                        (if s.max_sats > 0 { session_booked.saturating_add(sats) } else { 0 }, s.max_sats.max(0), "max_sats", "the session's max_sats")];
            if let Some((have, cap, rule, name)) = over.iter().find(|(have, cap, _, _)| have > cap) {
                return Ok(refusal(rule, format!("with this ticket's {sats} sats, {have} would be above {name} ({cap})")));
            }
            // the wallet's own rules: per payment, daily and weekly budgets, the counterparty cap, velocity, the human threshold
            let pay = Payment::new(&dest, sats, &ticket::memo(&s.task, &s.id));
            let d = self.engine.evaluate_admitted(&pay, sats)?;
            if !d.allowed() {
                if let Some(tok) = &d.approval_token {
                    self.engine.store.pop_approval(tok)?;
                }
                return Ok(with(with(d.as_value(), json!({"verdict": "deny", "rail": "ticket", "charged_sats": 0, "approval_token": null, "approval_expires": null})),
                               json!({"session": sid})));
            }
            let seed = self.ticket_seed(&st.book)?;
            let secret = seed.secret(&t.nonce);
            if hex::encode(seed.hash(&t.nonce)) != t.hash {
                return Err(err("ticket_seed", "the seed does not derive this ticket's hash: nothing is released"));
            }
            sigaudit::set_rule(&format!("policy:{}", d.rule));
            // 1. the spend, in the ledger
            if !self.engine.commit_once(&pay, &ledger_id(&t.hash))? {
                // a row from a release that died before the book had it: it becomes this booking
                self.engine.store.amend(&ledger_id(&t.hash), Some(sats))?;
            }
            // 2. the ticket, released in the book
            t.state = TState::Released;
            t.released_ts = now;
            t.booked_sats = sats;
            s.active_ts = now;
            st.commit(&[t.row(), s.row()])?;
            // 3. the signature log, which the anchor witness covers: its hash, never the secret
            self.sigaudit.record("ticket_release", &[], "", &dest, json!({"payment_hash": t.hash, "session": sid, "booked_sats": sats}))?;
            self.ticket_audit("ticket_release", json!({"session": sid, "dest": dest, "payment_hash": t.hash, "booked_sats": sats, "task": s.task}));
            let want = st.book.want(&s, now);
            st.compact_if_grown(now)?;
            // 4. only now does the secret exist outside this function
            Ok(json!({"verdict": "allow", "rail": "ticket", "session": sid, "hash": t.hash, "ticket_secret": hex::encode(*secret),
                      "ticket_msat": t.msat.to_string(), "charged_sats": sats, "want": want,
                      "residual_daily_sats": (d.residual_daily_sats - sats).max(0), "residual_weekly_sats": (d.residual_weekly_sats - sats).max(0)}))
        })();
        out.unwrap_or_else(|e| refusal("ticket", e.msg))
    }

    // --- the node's word ----------------------------------------------------------------------------

    /// Bring one ticket of the book to what the node's payment record says (the caller holds the
    /// spend lock). The node decides whether money is locked, moved or back; it is believed about
    /// a settle only with the preimage of the hash.
    fn ticket_apply(&self, st: &mut TicketStore, hash: &str, pmt: &Value) -> Result<()> {
        let Some(mut t) = st.book.tickets.get(hash).cloned() else { return Ok(()) };
        let now = self.engine.now();
        let status = str_or_empty(pmt.get("status"));
        let over = status == "SUCCEEDED" || (status == "FAILED" && !htlcs_in_flight(pmt));
        if t.state == TState::Settled || (t.state == TState::Failed && status == "FAILED") || t.state == TState::Offered {
            return Ok(());
        }
        if t.state == TState::Failed {
            // the book gave it up and the node has it after all: its secret was never released by this
            // book, but the book was wrong about it once, so it is booked until the node is done with it
            self.ticket_retire(st, t.clone(), now, "the node recorded it after the book had given it up")?;
            t = st.book.tickets.get(hash).cloned().ok_or_else(|| err("ticket", "the book lost a ticket"))?;
        }
        let dest = format!("ln:{}", t.payee);
        if !over {
            let (until, fin) = (cltv_until(pmt), final_expiry(pmt));
            let locked = t.state == TState::Sending && htlcs_in_flight(pmt);
            if locked || (until > 0 && until != t.cltv_until) || (fin > 0 && fin != t.final_expiry) {
                if locked {
                    t.state = TState::Locked;
                }
                t.cltv_until = if until > 0 { until } else { t.cltv_until };
                t.final_expiry = if fin > 0 { fin } else { t.final_expiry };
                st.commit(&[t.row()])?;
            }
            return Ok(());
        }
        if status == "FAILED" {
            // nothing was spent: a booking goes, as if the ticket had never been released
            if t.booked_sats > 0 {
                self.engine.store.amend(&ledger_id(hash), None)?;
            }
            let back = t.booked_sats;
            t.note = str_or_empty(pmt.get("failure_reason")).chars().take(80).collect();
            t.state = TState::Failed;
            t.booked_sats = 0;
            t.done_ts = now;
            st.commit(&[t.row()])?;
            self.ticket_audit("ticket_failed", json!({"payment_hash": hash, "dest": dest, "released_sats": back}));
            return Ok(());
        }
        // SUCCEEDED
        let was = t.state;
        let (reported, fee) = paid_msat(pmt);
        let preimage = preimage_bytes(pmt);
        let proven = preimage_proves(&preimage, hash);
        // never below the ticket: the payee was paid at least that; without the preimage nothing proves the cost
        let spent = sats_ceil(reported.max(t.msat).saturating_add(fee));
        let sats = if proven { spent } else { spent.max(t.booked_sats).max(booking_sats(t.msat, t.fee_limit_msat)) };
        self.ticket_ledger_put(&t, sats, if t.released_ts > 0.0 { t.released_ts } else { now })?;
        t.state = TState::Settled;
        t.booked_sats = sats;
        t.fee_msat = fee;
        t.done_ts = now;
        if !proven {
            t.note = "settled without the preimage of its hash".into();
        } else if !was.booked() {
            t.note = "settled without a release by this book".into();
        }
        st.commit(&[t.row()])?;
        if proven {
            // the preimage by its hash, as every settled Lightning payment is logged
            let _ = self.sigaudit.record("ticket_settled", &preimage, "", &dest, json!({"payment_hash": hash, "spent_sats": sats, "fee_msat": fee.to_string()}));
        }
        self.ticket_audit("ticket_settled", json!({"payment_hash": hash, "dest": dest, "spent_sats": sats, "fee_msat": fee.to_string(), "proven": proven,
                                                   "released_by_book": was.booked()}));
        if !proven {
            self.ln_halt(hash, &dest, sats, &format!("the LN node reports the ticket {hash} ({sats} sats to {dest}) as settled without the preimage of its hash"));
        } else if !was.booked() {
            self.ln_halt(hash, &dest, sats, &format!("the ticket {hash} ({sats} sats to {dest}) settled, and this wallet's book never released its secret: \
                                                      the book is older than the node, or the secret is known to someone else"));
        }
        Ok(())
    }

    /// Bring the book to the node (the caller holds the spend lock): every ticket that is not
    /// final by its hash, then the node's payment list from the book's cursor for tickets the book
    /// lacks, then sessions that have run out. Returns what changed.
    pub(crate) fn ticket_reconcile_locked(&self) -> Vec<Value> {
        if !self.ticket_path().exists() || self.ticket_shut().is_some() {
            self.ticket_synced.store(self.ticket_shut().is_none(), Ordering::SeqCst);
            return vec![];
        }
        let Some(ln) = self.ln.clone() else { return vec![] };
        let lp = LnPolicy::from_map(&self.config().ln);
        let now = self.engine.now();
        let mut out = vec![];
        let res = (|| -> Result<()> {
            let mut g = self.ticket_store()?;
            let st = g.as_mut().ok_or_else(|| err("ticket", "no ticket book"))?;
            let mut chans: Option<Option<Vec<Value>>> = None;
            let live: Vec<Ticket> = st.book.tickets.values().filter(|t| t.state.in_flight()).cloned().collect();
            for t in live {
                match ln.lookup(&t.hash) {
                    Ok(Some(pmt)) => self.ticket_apply(st, &t.hash, &pmt)?,
                    // the node never had it: a crash or an error between the write-ahead row and the send. Only
                    // a ticket the node never showed locked is given up, and only once no channel holds an HTLC for it
                    Ok(None) if t.cltv_until == 0 && t.final_expiry == 0 && now - t.sent_ts > lp.timeout_s as f64 + 60.0 => {
                        let cs = chans.get_or_insert_with(|| ln.channels().ok());
                        if cs.as_ref().is_some_and(|cs| htlc_locks(cs, &|h: &str| h == t.hash).booked_sats == 0) {
                            let mut t = t.clone();
                            if t.booked_sats > 0 {
                                self.engine.store.amend(&ledger_id(&t.hash), None)?;
                            }
                            t.state = TState::Failed;
                            t.booked_sats = 0;
                            t.done_ts = now;
                            t.note = "never reached the Lightning node".into();
                            st.commit(&[t.row()])?;
                            self.ticket_audit("ticket_failed", json!({"payment_hash": t.hash, "dest": format!("ln:{}", t.payee), "unseen": true}));
                        }
                    }
                    // a ticket the node once showed and now has no record of stays as it is: booked, if it was
                    Ok(None) => {}
                    Err(e) => out.push(json!({"payment_hash": t.hash, "error": e.msg})),
                }
                if let Some(n) = st.book.tickets.get(&t.hash).filter(|n| n.state != t.state) {
                    out.push(json!({"payment_hash": t.hash, "was": t.state.as_str(), "state": n.state.as_str(), "booked_sats": n.booked_sats}));
                }
            }
            self.ticket_read_list(st, &*ln, &lp, now, &mut out)?;
            // sessions: stopped when idle, closed when every ticket is final
            let sessions: Vec<Session> = st.book.sessions.values().filter(|s| s.state != SState::Closed).cloned().collect();
            for mut s in sessions {
                if s.state == SState::Open && now - s.active_ts > SESSION_IDLE_S {
                    s.state = SState::Stopping;
                    s.stopped_ts = now;
                    s.why = format!("idle for {SESSION_IDLE_S:.0} s");
                    let mut rows: Vec<Value> = st.book.of_session(&s.id).into_iter().filter(|t| t.state == TState::Offered).map(|t| dropped(t, now)).collect();
                    rows.push(s.row());
                    st.commit(&rows)?;
                }
                if s.state == SState::Stopping && st.book.of_session(&s.id).iter().all(|t| t.state.terminal()) {
                    s.state = SState::Closed;
                    s.closed_ts = now;
                    st.commit(&[s.row()])?;
                    out.push(json!({"session": s.id, "state": "closed"}));
                }
            }
            st.compact_if_grown(now)
        })();
        if let Err(e) = res {
            out.push(json!({"error": e.msg}));
        }
        out
    }

    /// The node's payment list from the book's cursor: a payment that carries this wallet's tag
    /// and is not in the book is a ticket the book lost (a restore), booked as released. The
    /// cursor stops before a payment that cannot be judged yet (in flight with no HTLC to read a
    /// tag from). Read to the end of the list, the book is whole (`ticket_synced`).
    fn ticket_read_list(&self, st: &mut TicketStore, ln: &dyn LnBackend, lp: &LnPolicy, now: f64, out: &mut Vec<Value>) -> Result<()> {
        let mut cursor = st.book.cursor;
        let mut stalled = false;
        let mut seed: Option<Arc<Seed>> = None;
        for _ in 0..LIST_PAGES {
            let page = ln.payments_after(cursor, LIST_PAGE)?;
            let n = page.len() as u64;
            for p in &page {
                let index = u64_of(p.get("payment_index"));
                let hash = str_or_empty(p.get("payment_hash")).to_lowercase();
                if index <= cursor || hash.len() != 64 {
                    return Err(err("ln_backend", "ListPayments: a payment without a rising index or a payment hash"));
                }
                let status = str_or_empty(p.get("status"));
                if !st.book.tickets.contains_key(&hash) && status != "FAILED" {
                    let tags = payment_tags(p);
                    if tags.is_empty() && status == "IN_FLIGHT" && !htlcs_in_flight(p) {
                        stalled = true; // no HTLC yet to read a tag from: looked at again next time
                        break;
                    }
                    let Ok(raw) = <[u8; 32]>::try_from(hex::decode(&hash).unwrap_or_default().as_slice()) else { continue };
                    if !tags.is_empty() {
                        let seed = match &seed {
                            Some(s) => s.clone(),
                            None => seed.insert(self.ticket_seed(&st.book)?).clone(),
                        };
                        let mine = tags.iter().find_map(|t| seed.read_tag(t, &raw).map(|n| (n, false)).or_else(|| seed.read_prepaid_tag(t, &raw).map(|n| (n, true))));
                        if let Some((nonce, prepaid)) = mine {
                            self.ticket_recover(st, p, &hash, nonce, prepaid, lp, now)?;
                            out.push(json!({"payment_hash": hash, "recovered": true, "state": st.book.tickets.get(&hash).map(|t| t.state.as_str())}));
                        }
                    }
                }
                cursor = index;
            }
            if stalled || n < LIST_PAGE {
                if cursor != st.book.cursor {
                    st.commit(&[json!({"e": "cursor", "index": cursor.to_string()})])?;
                }
                self.ticket_synced.store(true, Ordering::SeqCst);
                return Ok(());
            }
            st.commit(&[json!({"e": "cursor", "index": cursor.to_string()})])?;
        }
        Ok(()) // more to read than one reconcile reads: the next one goes on from the cursor
    }

    /// A payment on the node that carries this wallet's tag and is not in the book: the book is
    /// older than the node. It is booked as released, dated when the node made it, and then
    /// brought to what the node says of it.
    #[allow(clippy::too_many_arguments)]
    fn ticket_recover(&self, st: &mut TicketStore, p: &Value, hash: &str, nonce: [u8; 16], prepaid: bool, lp: &LnPolicy, now: f64) -> Result<()> {
        // where the money went is what the node's own route says, not what an invoice text says
        let payee = payment_payee(p).or_else(|| bolt11::decode(&str_or_empty(p.get("payment_request"))).ok().map(|i| i.payee_hex())).unwrap_or_default();
        let (msat, _) = paid_msat(p);
        let made = payment_ts(p).unwrap_or(now);
        let fee_limit_msat = (lp.fee_limit_sats(sats_ceil(msat)).max(0) as u64).saturating_mul(1000);
        let t = Ticket { hash: hash.into(), nonce, session: String::new(), payee, task: RECOVERED_TASK.into(), msat, fee_limit_msat, state: TState::Sending,
                         ts: made, sent_ts: made, invoice_expires: 0.0, released_ts: 0.0, booked_sats: 0, cltv_until: 0, final_expiry: 0, fee_msat: 0,
                         done_ts: 0.0, note: String::new(), prepaid };
        self.ticket_audit("ticket_recovered", json!({"payment_hash": hash, "dest": format!("ln:{}", t.payee), "msat": msat.to_string(),
                                                     "status": str_or_empty(p.get("status")),
                                                     "note": "on the node with this wallet's tag and not in its book: the book is older than the node"}));
        self.ticket_retire(st, t, now, "found on the node and not in the book: its secret may have left")?;
        self.ticket_apply(st, hash, p)
    }

    // --- prepaid tickets ----------------------------------------------------------------------------

    /// The limits of the channels a ticket may leave on, read from the node now. `None`: the node
    /// or its channel list could not be read, or no channel is usable.
    fn ticket_limits_read(&self) -> Option<Limits> {
        let ln = self.ln.clone()?;
        let lp = LnPolicy::from_map(&self.config().ln);
        let chans = ln.channels().ok()?;
        let (ids, _) = self.ln_channels(&chans, lp.split(&self.chain));
        (!ids.is_empty()).then(|| ticket::channel_limits(&chans, &ids))
    }

    /// Buy one prepaid ticket of a session: check the seller's invoice, book it as spent, pay it,
    /// and return the payment's preimage, which the seller credits the session for. `invoice` is
    /// the seller's word, and so is its hash: the ticket is an ordinary payment, spent when it
    /// arrives and never had back. So every rule of a release is applied before the payment is
    /// sent, and one is bought at a time. Not a socket method: only the wallet's own payer, which
    /// read the seller's terms itself, calls this.
    pub(crate) fn ticket_prepay(&self, p: &Value) -> Value {
        if let Some(d) = self.ticket_shut() {
            return d;
        }
        let sid = str_or_empty(p.get("session"));
        let invoice = str_or_empty(p.get("invoice")).trim().to_string();
        let (ln, lp, session) = {
            let _g = self.lock();
            let tp = match self.ticket_synced() {
                Ok(t) => t,
                Err(d) => return d,
            };
            let (ln, lp) = match self.ln_ready() {
                Ok(x) => x,
                Err(d) => return with(d, json!({"rail": "ticket", "charged_sats": 0})),
            };
            let session = match self.ticket_store() {
                Ok(g) => g.as_ref().and_then(|st| st.book.sessions.get(&sid).cloned()),
                Err(e) => return refusal("ticket", e.msg),
            };
            let Some(session) = session.filter(|s| s.state == SState::Open) else { return refusal("ticket_session", "no such open session") };
            if !tp.tasks.contains_key(&session.task) {
                return refusal("ticket_task", format!("the owner's policy no longer names the task {:?}", session.task));
            }
            (ln, lp, session)
        };
        let dest = format!("ln:{}", session.payee);
        if let Err(d) = self.ln_node_checks(&*ln, &lp, &dest, "") {
            return with(d, json!({"rail": "ticket"}));
        }
        let routes = match self.ln_route_checks(&*ln, &lp, &dest, "", false) {
            Ok(r) => r,
            Err(d) => return with(d, json!({"rail": "ticket"})),
        };
        // the invoice as the signer reads it and as the node reads it
        let now = self.engine.now();
        let tp_now = self.ticket_policy();
        let relaxed = LnPolicy { min_expiry_s: 0, max_cltv_blocks: i64::MAX, require_description: false, ..lp.clone() };
        let refuse = |hash: &str, rule: &str, why: String| {
            self.ticket_audit("ticket_refused", json!({"session": sid, "dest": dest, "payment_hash": hash, "rule": rule, "reason": why, "prepaid": true}));
            with(refusal(rule, why), json!({"session": sid}))
        };
        let inv = match bolt11::decode(&invoice) {
            Ok(i) => i,
            Err(e) => return refuse("", "ticket_invoice", format!("not a valid BOLT 11 invoice: {e}")),
        };
        let hash = inv.payment_hash_hex();
        let named = str_or_empty(p.get("hash"));
        if !named.is_empty() && named != hash {
            return refuse(&named, "ticket_hash", "the invoice is for another payment hash than the one it was returned for".into());
        }
        if let Err((rule, why)) = check_invoice(&inv, &self.chain, now, &relaxed, "") {
            return refuse(&hash, &rule, why);
        }
        if let Err((rule, why)) = check_prepaid_invoice(&inv, &session, &tp_now, now) {
            return refuse(&hash, rule, why);
        }
        match ln.decode(&invoice) {
            Ok(d) => {
                if let Err(why) = cross_check(&inv, &d) {
                    return refuse(&hash, "ln_decode_mismatch", why);
                }
            }
            Err(e) => return refuse(&hash, "ln_backend", e.msg),
        }
        // every rule of a release, the ledger and the book, under the wallet's spend lock
        let booked = {
            let _g = self.lock();
            self.ticket_book_prepay(&sid, &hash, &invoice, &inv, &lp, &routes.ids)
        };
        let send = match booked {
            Ok(Ok(s)) => s,
            Ok(Err(d)) => return d,
            Err(e) => return refusal("ticket", e.msg),
        };
        // the node routes it; no lock is held. An ordinary payment is over in a moment, and its end is waited for
        let sent = {
            let _inside = self.ticket_pace.enter();
            ln.send_held(&send)
        };
        let mut pmt = match sent {
            Ok(p) => Some(p),
            Err(_) => ln.lookup(&hash).ok().flatten(),
        };
        let deadline = Instant::now() + Duration::from_secs(lp.timeout_s.clamp(1, 600) as u64 + 5);
        while pmt.as_ref().is_none_or(|p| !payment_over(p)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
            if let Ok(Some(p)) = ln.lookup(&hash) {
                pmt = Some(p);
            }
        }
        let _g = self.lock();
        let res = (|| -> Result<Option<Ticket>> {
            let mut g = self.ticket_store()?;
            let st = g.as_mut().ok_or_else(|| err("ticket", "no ticket book"))?;
            if let Some(pmt) = &pmt {
                self.ticket_apply(st, &hash, pmt)?;
            }
            Ok(st.book.tickets.get(&hash).cloned())
        })();
        let t = match res {
            Ok(Some(t)) => t,
            Ok(None) => return refusal("ticket", "the book lost a ticket"),
            Err(e) => return refusal("ticket", e.msg),
        };
        let about = json!({"rail": "ticket", "session": sid, "hash": hash, "prepaid": true, "ticket_msat": t.msat.to_string()});
        match t.state {
            TState::Settled => {
                let preimage = pmt.as_ref().map(preimage_bytes).unwrap_or_default();
                if !preimage_proves(&preimage, &hash) {
                    return with(refusal("ticket_prepay_unproven", "the node shows the prepaid ticket paid without the preimage of its hash: it is booked, and \
                                                                   nothing can be shown to the seller"), with(about, json!({"charged_sats": t.booked_sats})));
                }
                self.ticket_audit("ticket_prepaid", json!({"session": sid, "dest": dest, "payment_hash": hash, "spent_sats": t.booked_sats}));
                // the preimage is what the buyer shows the seller for its credit: it moves no money any more
                with(json!({"verdict": "allow", "ticket_secret": hex::encode(&preimage), "charged_sats": t.booked_sats}), about)
            }
            TState::Failed => with(refusal("ticket_prepay_failed", format!("the payment of the prepaid ticket failed ({}): nothing was spent", t.note)), about),
            // not final within the wait: booked, and the node's word decides later
            _ => with(with(refusal("ticket_prepay_pending", "the payment of the prepaid ticket is not final yet: it is booked as spent until the wallet's node \
                                                             shows it failed"), about), json!({"verdict": "pending", "charged_sats": t.booked_sats})),
        }
    }

    /// The rules and the two rows of a prepaid ticket (the caller holds the spend lock): what
    /// [`Self::ticket_release_locked`] checks of a held ticket's release, then the ledger row, then
    /// the book row, then the signature log. Returns the send; an `Err` inside is the refusal.
    fn ticket_book_prepay(&self, sid: &str, hash: &str, invoice: &str, inv: &Invoice, lp: &LnPolicy, ids: &[String]) -> Result<std::result::Result<HeldSend, Value>> {
        let tp = match self.ticket_synced() {
            Ok(t) => t,
            Err(d) => return Ok(Err(d)),
        };
        let cfg = self.config();
        let now = self.engine.now();
        let mut g = self.ticket_store()?;
        let st = g.as_mut().ok_or_else(|| err("ticket", "no ticket book"))?;
        let Some(mut s) = st.book.sessions.get(sid).filter(|s| s.state == SState::Open).cloned() else { return Ok(Err(refusal("ticket_session", "no such open session"))) };
        if s.prepaid_msat == 0 {
            return Ok(Err(refusal("ticket_terms", "this seller's terms offer no prepaid tickets")));
        }
        let Some(task) = tp.tasks.get(&s.task) else {
            return Ok(Err(refusal("ticket_task", format!("the owner's policy no longer names the task {:?}", s.task))));
        };
        let listed = self.ticket_listed(&cfg, &s.payee, &s.origin) && s.listed;
        if !listed && task.admit != Admit::Any {
            return Ok(Err(refusal("ticket_admission", format!("the owner no longer names the seller {} and task {:?} pays only named sellers", s.payee, s.task))));
        }
        // one hash, one payment; and one prepaid ticket at a time: what is bought ahead cannot be had back
        if st.book.tickets.contains_key(hash) {
            return Ok(Err(refusal("ticket_replay", "the wallet has paid, or is paying, a ticket for this hash: a hash is paid once")));
        }
        if let Some(t) = st.book.prepaid_pending(sid) {
            return Ok(Err(with(refusal("ticket_prepaid_pending", "an earlier prepaid ticket of this session is not final on the wallet's node: the next is bought after it"),
                               json!({"session": sid, "hash": t.hash}))));
        }
        if tp.max_sends_per_hour > 0 && st.book.sends_since(now - 3600.0) as i64 >= tp.max_sends_per_hour {
            return Ok(Err(refusal("ticket_rate_limit", format!("already {} ticket payments sent to the node in the last hour (tickets.max_sends_per_hour)", tp.max_sends_per_hour))));
        }
        let Ok(raw) = <[u8; 32]>::try_from(inv.payment_hash.as_slice()) else { return Ok(Err(refusal("ticket_invoice", "the invoice has no 32-byte payment hash"))) };
        let dest = format!("ln:{}", s.payee);
        let fee_limit_msat = (lp.fee_limit_sats(sats_ceil(s.prepaid_msat)).max(0) as u64).saturating_mul(1000);
        let sats = booking_sats(s.prepaid_msat, fee_limit_msat);
        let (_, _, cap_spend, seller_window) = Self::ticket_seller_caps(&cfg, &tp, task, listed);
        let spent = self.ticket_spent(now, &s.task, task.window_s as f64, &dest, seller_window)?;
        let session_booked = st.book.of_session(sid).iter().fold(0i64, |a, x| a.saturating_add(x.booked_sats));
        let over = [(spent.task.saturating_add(sats), task.budget_sats, "ticket_task_budget", "the task's budget_sats"),
                    (spent.seller.saturating_add(sats), cap_spend, "ticket_seller_cap", "the owner's cap on sats paid to this seller"),
                    (if s.max_sats > 0 { session_booked.saturating_add(sats) } else { 0 }, s.max_sats.max(0), "max_sats", "the session's max_sats")];
        if let Some((have, cap, rule, name)) = over.iter().find(|(have, cap, _, _)| have > cap) {
            return Ok(Err(refusal(rule, format!("with this ticket's {sats} sats, {have} would be above {name} ({cap})"))));
        }
        // the wallet's own rules: per payment, daily and weekly budgets, the counterparty cap, velocity, the human threshold
        let pay = Payment::new(&dest, sats, &ticket::memo(&s.task, &s.id));
        let d = self.engine.evaluate_admitted(&pay, sats)?;
        if !d.allowed() {
            if let Some(tok) = &d.approval_token {
                self.engine.store.pop_approval(tok)?;
            }
            return Ok(Err(with(with(d.as_value(), json!({"verdict": "deny", "rail": "ticket", "charged_sats": 0, "approval_token": null, "approval_expires": null})),
                               json!({"session": sid}))));
        }
        let seed = self.ticket_seed(&st.book)?;
        let nonce = random_bytes::<16>();
        sigaudit::set_rule(&format!("policy:{}", d.rule));
        // 1. the spend, in the ledger: a prepaid ticket is spent when it is paid, used or not
        if !self.engine.commit_once(&pay, &ledger_id(hash))? {
            self.engine.store.amend(&ledger_id(hash), Some(sats))?;
        }
        // 2. the ticket in the book, booked, before the node sees its invoice
        let t = Ticket { hash: hash.to_string(), nonce, session: sid.to_string(), payee: s.payee.clone(), task: s.task.clone(), msat: s.prepaid_msat, fee_limit_msat,
                         state: TState::Released, ts: now, sent_ts: now, invoice_expires: inv.expires_at() as f64, released_ts: now, booked_sats: sats,
                         cltv_until: 0, final_expiry: 0, fee_msat: 0, done_ts: 0.0, note: String::new(), prepaid: true };
        s.active_ts = now;
        st.commit(&[t.row(), s.row()])?;
        // 3. the signature log, which the anchor witness covers
        self.sigaudit.record("ticket_prepay", &[], "", &dest, json!({"payment_hash": hash, "session": sid, "booked_sats": sats}))?;
        self.ticket_audit("ticket_prepay", json!({"session": sid, "dest": dest, "payment_hash": hash, "booked_sats": sats, "task": s.task}));
        Ok(Ok(HeldSend { invoice: invoice.to_string(), fee_limit_msat: fee_limit_msat.max(1), timeout_s: lp.timeout_s.max(1), cltv_limit: tp.max_htlc_blocks,
                         outgoing_chan_ids: ids.to_vec(), tag: seed.prepaid_tag(&nonce, &raw).to_vec() }))
    }

    /// Lock nothing for a session for `secs` seconds (1 to 600), for the reason `why`: a seller that
    /// says it has no slot for a held ticket (`slots_short`) is waited for, not treated as failing.
    /// Returns the time the wait ends.
    pub(crate) fn ticket_hold(&self, sid: &str, secs: u64, why: &str) -> Result<f64> {
        let _g = self.lock();
        let now = self.engine.now();
        let mut g = self.ticket_store()?;
        let st = g.as_mut().ok_or_else(|| err("ticket", "no ticket book"))?;
        let mut s = st.book.sessions.get(sid).cloned().ok_or_else(|| err("ticket_session", "no such session"))?;
        s.hold_until = now + secs.clamp(1, ticket::SLOT_WAIT_MAX_S as u64) as f64;
        s.hold_why = why.chars().take(40).collect();
        st.commit(&[s.row()])?;
        self.ticket_audit("ticket_hold", json!({"session": sid, "dest": format!("ln:{}", s.payee), "why": s.hold_why, "hold_until": ts_value(s.hold_until)}));
        Ok(s.hold_until)
    }

    // --- what the wallet's own payer reads and writes ([`crate::ticket_pay`]) -----------------------

    /// What a lock round checks of the wallet's own side before it looks at an invoice: the rail
    /// is on, the book is whole, and the Lightning node answers, is on this chain and has a
    /// channel a payment may leave through. The payer asks this before it offers a hash to a
    /// seller: a hash that is offered and then cannot be paid keeps its place in the pool until it
    /// lapses, so none is offered while the wallet's own node could not pay it.
    pub(crate) fn ticket_can_lock(&self, payee: &str) -> std::result::Result<(), Value> {
        let (ln, lp) = {
            let _g = self.lock();
            self.ticket_synced()?;
            self.ln_ready().map_err(|d| with(d, json!({"rail": "ticket", "charged_sats": 0})))?
        };
        let dest = format!("ln:{payee}");
        self.ln_node_checks(&*ln, &lp, &dest, "").map_err(|d| with(d, json!({"rail": "ticket"})))?;
        self.ln_route_checks(&*ln, &lp, &dest, "", false).map_err(|d| with(d, json!({"rail": "ticket"})))?;
        Ok(())
    }

    /// A session of the book, as it is now.
    pub(crate) fn ticket_session(&self, sid: &str) -> Option<Session> {
        self.ticket_store().ok()?.as_ref()?.book.sessions.get(sid).cloned()
    }

    /// The hash the session's next release would take at the present height, and how many tickets
    /// of the session are locked and unreleased.
    pub(crate) fn ticket_next(&self, sid: &str) -> (Option<String>, usize) {
        let tip = self.height_safe();
        match self.ticket_store() {
            Ok(g) => match g.as_ref() {
                Some(st) => (st.book.usable(sid, tip).map(|t| t.hash.clone()), st.book.of_session(sid).iter().filter(|t| t.state.unreleased()).count()),
                None => (None, 0),
            },
            Err(_) => (None, 0),
        }
    }

    /// Give up hashes of a session that were offered and whose lock round never came to an invoice
    /// being judged: the seller sent none, or the wallet's own node could not be asked. They can
    /// take no invoice from now on, and their places in the pool are free at once. (A hash whose
    /// invoice the book refused keeps its place until it lapses: asking again would only make the
    /// seller issue again what a cap refuses.)
    pub(crate) fn ticket_unoffer(&self, sid: &str, hashes: &[String], why: &str) -> Result<()> {
        let _g = self.lock();
        let now = self.engine.now();
        let mut g = self.ticket_store()?;
        let st = g.as_mut().ok_or_else(|| err("ticket", "no ticket book"))?;
        let rows: Vec<Value> = hashes.iter().filter_map(|h| st.book.tickets.get(h)).filter(|t| t.session == sid && t.state == TState::Offered).map(|t| {
            let mut t = t.clone();
            t.state = TState::Failed;
            t.done_ts = now;
            t.note = why.chars().take(80).collect();
            t.row()
        }).collect();
        st.commit(&rows)
    }

    /// Write the seller's side of a session into the book: its id, its key and its endpoints. On
    /// disk when this returns, and before any ticket of the session is paid, so that a wallet that
    /// starts again can still ask the seller to cancel what it locked.
    pub(crate) fn ticket_set_http(&self, sid: &str, http: ticket::SellerSession) -> Result<()> {
        let mut g = self.ticket_store()?;
        let st = g.as_mut().ok_or_else(|| err("ticket", "no ticket book"))?;
        let mut s = st.book.sessions.get(sid).cloned().ok_or_else(|| err("ticket_session", "no such session"))?;
        s.http = Some(http);
        st.commit(&[s.row()])
    }

    /// Sessions that are stopping, have a seller side on record and still hold tickets that are
    /// not final: what a wallet that started again asks its sellers to cancel.
    pub(crate) fn ticket_stopping_with_seller(&self) -> Vec<Session> {
        let Ok(g) = self.ticket_store() else { return vec![] };
        let Some(st) = g.as_ref() else { return vec![] };
        st.book.sessions.values().filter(|s| s.state == SState::Stopping && s.http.is_some())
            .filter(|s| st.book.of_session(&s.id).iter().any(|t| t.state.in_flight() && t.state != TState::Released)).cloned().collect()
    }

    /// The tickets of a session by state, and what they have in the ledger: what a paid call and
    /// `channels` report.
    pub(crate) fn ticket_session_counts(&self, sid: &str) -> Value {
        let Ok(g) = self.ticket_store() else { return Value::Null };
        let Some(st) = g.as_ref() else { return Value::Null };
        let ts = st.book.of_session(sid);
        let n = |f: &dyn Fn(TState) -> bool| ts.iter().filter(|t| f(t.state)).count();
        let locked = st.book.locked(|t| t.session == sid);
        json!({"locked": locked.tickets, "locked_sats": locked.sats, "released": n(&|s| s == TState::Released), "retired": n(&|s| s == TState::Retired),
               "prepaid": ts.iter().filter(|t| t.prepaid).count(),
               "settled": n(&|s| s == TState::Settled), "failed": n(&|s| s == TState::Failed),
               "booked_sats": ts.iter().fold(0i64, |a, t| a.saturating_add(t.booked_sats))})
    }

    /// Tickets for `channels` and `balance`: what is locked, what is booked and not yet settled,
    /// and the open sessions. `Null` when the wallet has no ticket book.
    pub(crate) fn ticket_summary(&self) -> Value {
        if !self.ticket_path().exists() {
            return Value::Null;
        }
        let Ok(g) = self.ticket_store() else { return json!({"error": "the ticket book could not be read"}) };
        let Some(st) = g.as_ref() else { return Value::Null };
        let locked = st.book.locked(|_| true);
        let (mut in_flight, mut booked, mut settled_sats) = (0i64, 0i64, 0i64);
        for t in st.book.tickets.values() {
            if t.state.in_flight() {
                in_flight += 1;
            }
            if t.state.booked() {
                booked = booked.saturating_add(t.booked_sats);
            }
            if t.state == TState::Settled {
                settled_sats = settled_sats.saturating_add(t.booked_sats);
            }
        }
        let mut sessions: Vec<&Session> = st.book.sessions.values().filter(|s| s.state != SState::Closed).collect();
        sessions.sort_by(|a, b| a.opened_ts.total_cmp(&b.opened_ts));
        json!({"in_flight": in_flight, "locked_tickets": locked.tickets, "locked_sats": locked.sats, "released_unsettled_sats": booked,
               "settled_sats": settled_sats, "sessions": sessions.iter().map(|s| s.public()).collect::<Vec<_>>()})
    }

    // --- stop, status -------------------------------------------------------------------------------

    /// `ticket_stop`: no more offers, locks or releases for the session. Returns the hashes of its
    /// unreleased tickets, for the caller to ask the seller to cancel; `ticket_status` then shows
    /// each one's end and when. The signer believes its node, not the seller's answer.
    pub(crate) fn ticket_stop_locked(&self, p: &Value) -> Value {
        if let Some(d) = self.ticket_shut() {
            return d;
        }
        let sid = str_or_empty(p.get("session"));
        let now = self.engine.now();
        let out = (|| -> Result<Value> {
            let mut g = self.ticket_store()?;
            let st = g.as_mut().ok_or_else(|| err("ticket", "no ticket book"))?;
            let Some(mut s) = st.book.sessions.get(&sid).cloned() else { return Ok(refusal("ticket_session", "no such session")) };
            let mut rows: Vec<Value> = vec![];
            if s.state == SState::Open {
                s.state = SState::Stopping;
                s.stopped_ts = now;
                s.why = Some(str_or_empty(p.get("why"))).filter(|w| !w.is_empty()).unwrap_or_else(|| "stopped by the caller".into()).chars().take(200).collect();
                rows.extend(st.book.of_session(&sid).into_iter().filter(|t| t.state == TState::Offered).map(|t| dropped(t, now)));
                rows.push(s.row());
                st.commit(&rows)?;
                self.ticket_audit("ticket_stop", json!({"session": sid, "dest": format!("ln:{}", s.payee)}));
            }
            let cancel: Vec<String> = st.book.of_session(&sid).into_iter().filter(|t| t.state.unreleased()).map(|t| t.hash.clone()).collect();
            Ok(with(json!({"verdict": "allow", "rail": "ticket", "cancel": cancel}), s.public()))
        })();
        out.unwrap_or_else(|e| refusal("ticket", e.msg))
    }

    /// `ticket_status`: the book after a reconcile, and whether the node's HTLCs are the book's.
    /// With `session`, that session's tickets one by one. Never a secret or a nonce.
    pub(crate) fn ticket_status_locked(&self, p: &Value) -> Value {
        let tp = self.ticket_policy();
        let mut out = json!({"rail": "ticket", "enabled": tp.enabled, "halted": self.ln_book.halted(),
                             "book_error": self.ticket_error.lock().unwrap_or_else(|p| p.into_inner()).clone()});
        if !self.ticket_path().exists() {
            return with(out, json!({"synced": false, "sessions": [], "tickets": {}, "locked": {"tickets": 0, "sats": 0}, "booked_sats": 0}));
        }
        let reconciled = self.ticket_reconcile_locked();
        let sid = str_or_empty(p.get("session"));
        let chans = self.ln.as_ref().map(|ln| ln.channels());
        let ln_book = self.ln_book.all();
        let res = (|| -> Result<Value> {
            let g = self.ticket_store()?;
            let st = g.as_ref().ok_or_else(|| err("ticket", "no ticket book"))?;
            let mut counts = serde_json::Map::new();
            let mut booked = 0i64;
            for t in st.book.tickets.values() {
                let n = counts.entry(t.state.as_str()).or_insert(json!(0));
                *n = json!(n.as_i64().unwrap_or(0) + 1);
                if t.state.booked() {
                    booked = booked.saturating_add(t.booked_sats);
                }
            }
            let locked = st.book.locked(|_| true);
            let mut sessions: Vec<&Session> = st.book.sessions.values().filter(|s| if sid.is_empty() { s.state != SState::Closed } else { s.id == sid }).collect();
            sessions.sort_by(|a, b| a.opened_ts.total_cmp(&b.opened_ts));
            let mut v = json!({"synced": self.ticket_synced.load(Ordering::SeqCst), "tickets": counts, "locked": {"tickets": locked.tickets, "sats": locked.sats},
                               "booked_sats": booked, "sessions": sessions.iter().map(|s| s.public()).collect::<Vec<_>>(), "cursor": st.book.cursor.to_string(),
                               "caps": {"max_locked_sats": tp.max_locked_sats, "max_locked_tickets": tp.max_locked_tickets}, "reconciled": reconciled});
            if !sid.is_empty() {
                v["session_tickets"] = st.book.of_session(&sid).into_iter().map(Ticket::public).collect();
            }
            // sessions this wallet pays over HTTP: its own count of what each seller holds
            v["paying"] = json!(self.ticket_http_public());
            // the node's own HTLCs against the book: a ticket the node showed locked has one, and every HTLC of the node is in a book
            match &chans {
                Some(Ok(cs)) => {
                    let on_node: HashSet<String> = htlc_locks(cs, &|_| true).list.iter().map(|h| str_or_empty(h.get("payment_hash"))).collect();
                    let mut missing: Vec<&str> = st.book.tickets.values().filter(|t| t.state.in_flight() && t.cltv_until > 0 && !on_node.contains(&t.hash))
                        .map(|t| t.hash.as_str()).collect();
                    let mut extra: Vec<&str> = on_node.iter().filter(|h| !st.book.tickets.get(*h).is_some_and(|t| t.state.in_flight())
                        && !ln_book.get(*h).and_then(|r| r.get("state")).and_then(Value::as_str).is_some_and(|x| x == "sending")).map(String::as_str).collect();
                    missing.sort_unstable();
                    extra.sort_unstable();
                    v["node"] = json!({"htlcs": on_node.len(), "agree": missing.is_empty() && extra.is_empty(), "in_book_not_on_node": missing,
                                       "on_node_not_in_book": extra});
                }
                Some(Err(e)) => v["node"] = json!({"error": e.msg}),
                None => v["node"] = Value::Null,
            }
            Ok(v)
        })();
        match res {
            Ok(v) => {
                out = with(out, v);
                out
            }
            Err(e) => with(out, json!({"synced": false, "error": e.msg})),
        }
    }
}

/// An offered hash of a session that ended: it can no longer take an invoice.
fn dropped(t: &Ticket, now: f64) -> Value {
    let mut t = t.clone();
    t.state = TState::Failed;
    t.done_ts = now;
    t.note = "its session stopped before an invoice was paid".into();
    t.row()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn at_most_eight_ticket_payments_are_with_the_router_at_once() {
        assert_eq!(SEND_PARALLEL, 8);
        let pace = Pace::default();
        let (now, peak) = (AtomicUsize::new(0), AtomicUsize::new(0));
        std::thread::scope(|sc| {
            for _ in 0..64 {
                sc.spawn(|| {
                    let _inside = pace.enter();
                    let n = now.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(n, Ordering::SeqCst);
                    assert!(pace.inside() <= SEND_PARALLEL);
                    std::thread::sleep(Duration::from_millis(5));
                    now.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        assert_eq!((peak.load(Ordering::SeqCst), pace.inside()), (SEND_PARALLEL, 0), "64 sends at once: 8 inside, the rest wait, and all of them leave");
        // a send that panics leaves the gate as well
        let died = std::thread::scope(|sc| sc.spawn(|| {
            let _inside = pace.enter();
            panic!("the send died");
        }).join());
        assert!(died.is_err() && pace.inside() == 0);
    }

    #[test]
    fn a_payment_is_over_when_it_succeeded_or_failed_with_nothing_out() {
        assert!(payment_over(&json!({"status": "SUCCEEDED"})));
        assert!(payment_over(&json!({"status": "FAILED", "htlcs": []})));
        assert!(!payment_over(&json!({"status": "FAILED", "htlcs": [{"status": "IN_FLIGHT"}]})), "its funds are still locked");
        assert!(!payment_over(&json!({"status": "IN_FLIGHT", "htlcs": [{"status": "IN_FLIGHT"}]})));
        assert!(!payment_over(&json!({})), "no status is no end");
    }
}
