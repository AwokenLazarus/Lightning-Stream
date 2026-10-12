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
//! | One hash, one payment. | Only an `offered` ticket of the session takes an invoice; the write-ahead row makes it `sending` before the node sees the invoice. |
//!
//! Locks: the wallet's spend lock, then the book's. No lock is held while the node routes a
//! ticket, so a release never waits for a lock round.
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, MutexGuard};

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
use crate::ticket::{self, booking_sats, check_ticket_invoice, ledger_id, sats_ceil, sizing, Admit, Book, SState, Seed, Session, TState, TaskPolicy, Terms,
                    Ticket, TicketPolicy, KEEP_DONE_S, MAX_BATCH, OFFER_TTL_S, SESSION_IDLE_S, TAG_RECORD};
use crate::{err, Result};

pub const BOOK_FILE: &str = "tickets.jsonl";
pub const SEED_FILE: &str = "ticket_seed.json";
const SEED_AAD: &str = "xbt/ticket-seed";
/// The task name of a ticket found on the node that the book did not hold.
pub const RECOVERED_TASK: &str = "recovered";
/// Payments read from the node's list in one call, and calls in one reconcile.
const LIST_PAGE: u64 = 100;
const LIST_PAGES: usize = 50;
/// Tickets handed to the node's router at once.
const SEND_PARALLEL: usize = 16;

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

    fn ticket_policy(&self) -> TicketPolicy {
        TicketPolicy::from_map(&self.config().tickets)
    }

    /// The book, opened (and created) when first needed. An error keeps the ticket rail shut and
    /// nothing else.
    fn ticket_store(&self) -> Result<MutexGuard<'_, Option<TicketStore>>> {
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

    fn ticket_audit(&self, kind: &str, fields: Value) {
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
        self.engine.commit(&Payment { dest: format!("ln:{}", t.payee), amount_sats: sats, memo: ticket::memo(task), ts }, &id)
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
        let terms = match Terms::parse(p.get("terms").unwrap_or(&Value::Null), &net) {
            Ok(t) => t,
            Err((rule, why)) => return refusal(rule, why),
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
            let size = match sizing(&terms, &tp, sellers, expect_msat, cap_tickets, cap_locked) {
                Ok(s) => s,
                Err((rule, why)) => return Ok(refusal(rule, why)),
            };
            let lp = LnPolicy::from_map(&cfg.ln);
            let one = booking_sats(size.ticket_msat, (lp.fee_limit_sats(sats_ceil(size.ticket_msat)).max(0) as u64).saturating_mul(1000));
            // no human can approve a release as it happens: a ticket that would need one is refused here
            if one >= cfg.human_threshold_sats || one > cfg.max_per_tx_sats {
                return Ok(refusal("ticket_size", format!("one ticket with its fee limit is {one} sats: at or above human_threshold_sats {} or above \
                                                          max_per_tx_sats {}", cfg.human_threshold_sats, cfg.max_per_tx_sats)));
            }
            let s = Session { id: crate::policy::token_urlsafe(), payee: terms.payee.clone(), origin: origin.chars().take(200).collect(), task: task_name.clone(),
                              listed, ticket_msat: size.ticket_msat, pool: size.pool, max_tickets: terms.max_tickets, ticket_blocks: terms.ticket_blocks,
                              max_sats, state: SState::Open, opened_ts: now, active_ts: now, stopped_ts: 0.0, closed_ts: 0.0, why: String::new() };
            st.commit(&[s.row()])?;
            self.ticket_audit("ticket_open", json!({"session": s.id, "dest": format!("ln:{}", s.payee), "task": s.task, "listed": listed,
                                                    "ticket_msat": s.ticket_msat.to_string(), "pool": s.pool}));
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
                                   cltv_until: 0, final_expiry: 0, fee_msat: 0, done_ts: 0.0, note: String::new() }.row());
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
        // the node routes them, several at once; no lock is held
        let mut outcomes: Vec<Result<Value>> = vec![];
        for chunk in sends.chunks(SEND_PARALLEL) {
            outcomes.extend(std::thread::scope(|sc| {
                let hs: Vec<_> = chunk.iter().map(|(_, r)| {
                    let ln = &ln;
                    sc.spawn(move || ln.send_held(r))
                }).collect();
                hs.into_iter().map(|h| h.join().unwrap_or_else(|_| Err(err("ln_send", "the send did not return")))).collect::<Vec<_>>()
            }));
        }
        // what the node made of each
        let _g = self.lock();
        let mut tickets = vec![];
        let res = (|| -> Result<()> {
            let mut g = self.ticket_store()?;
            let st = g.as_mut().ok_or_else(|| err("ticket", "no ticket book"))?;
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
                    tickets.push(t.public());
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
        for (hash, invoice, inv) in read {
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
        if !sends.is_empty() {
            s.active_ts = now;
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
            let Some(mut t) = st.book.usable(&sid, tip).cloned() else {
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
            let pay = Payment::new(&dest, sats, &ticket::memo(&s.task));
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
                        if let Some(nonce) = tags.iter().find_map(|t| seed.read_tag(t, &raw)) {
                            self.ticket_recover(st, p, &hash, nonce, lp, now)?;
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
    fn ticket_recover(&self, st: &mut TicketStore, p: &Value, hash: &str, nonce: [u8; 16], lp: &LnPolicy, now: f64) -> Result<()> {
        // where the money went is what the node's own route says, not what an invoice text says
        let payee = payment_payee(p).or_else(|| bolt11::decode(&str_or_empty(p.get("payment_request"))).ok().map(|i| i.payee_hex())).unwrap_or_default();
        let (msat, _) = paid_msat(p);
        let made = payment_ts(p).unwrap_or(now);
        let fee_limit_msat = (lp.fee_limit_sats(sats_ceil(msat)).max(0) as u64).saturating_mul(1000);
        let t = Ticket { hash: hash.into(), nonce, session: String::new(), payee, task: RECOVERED_TASK.into(), msat, fee_limit_msat, state: TState::Sending,
                         ts: made, sent_ts: made, invoice_expires: 0.0, released_ts: 0.0, booked_sats: 0, cltv_until: 0, final_expiry: 0, fee_msat: 0,
                         done_ts: 0.0, note: String::new() };
        self.ticket_audit("ticket_recovered", json!({"payment_hash": hash, "dest": format!("ln:{}", t.payee), "msat": msat.to_string(),
                                                     "status": str_or_empty(p.get("status")),
                                                     "note": "on the node with this wallet's tag and not in its book: the book is older than the node"}));
        self.ticket_retire(st, t, now, "found on the node and not in the book: its secret may have left")?;
        self.ticket_apply(st, hash, p)
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
                s.why = "stopped by the caller".into();
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
