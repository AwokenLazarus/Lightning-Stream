//! Stream tickets, the buyer's book (`docs/TICKETS.md`): what a ticket is, what the owner allows,
//! and the rules, with no IO. [`crate::ticket_rail`] is the part that talks to the Lightning node
//! and writes the book.
//!
//! A ticket is a Lightning payment locked to a hash whose secret only this signer can derive. The
//! rules kept here, one sentence each:
//!
//! * **A secret is spending.** It leaves the signer only after its ticket's spend is in the ledger
//!   and the ticket is `released` in the book, and it leaves once ([`TState`]).
//! * **A secret is derived, never stored**: `HMAC-SHA256(seed, "xbt/ticket/secret/v0" || nonce)`
//!   from the signer's sealed seed and a random 16-byte nonce the book keeps ([`Seed`]).
//! * **Every ticket payment carries a tag only this seed can make** ([`Seed::tag`]), so a signer
//!   whose book is older than its node (a restore) finds its tickets in the node's payment list.
//! * **One hash, one payment**: a hash is paid at most once ([`TState::Offered`] is the only state
//!   an invoice is accepted in).
//! * **The owner's numbers bound the seller's**: a term above the owner's bound refuses the seller
//!   ([`Terms::parse`], [`sizing`]), and every cap is checked on the book's own counts
//!   ([`Book::locked`]), never on a number a seller or a caller sends.
//! * **A held ticket is never dust**: it is at least 546 sat, and at least the dust limit of either
//!   side of every channel it may leave on ([`sizing`], [`channel_limits`]). A ticket below a
//!   channel's dust limit has no output there and is lost to the miners in a force close.
//! * **Held tickets take at most half of a channel's slots**: with the tickets to lock, the
//!   payments pending on a channel they may leave on stay within half of what it carries, and the
//!   book's held tickets within half of the smallest such channel; a channel that does not say
//!   carries 30 ([`channel_limits`], [`Limits::room`]).
//! * **A lock that fails for lack of a slot makes the wallet hold less**: one ticket fewer, a
//!   wait, and after three rounds none ([`Session::lock_round`]).
//! * **A prepaid ticket is spent when it is paid**: booked before its payment is sent, bought one
//!   at a time, and never counted as held ([`Ticket::prepaid`]).
//!
//! Amounts from outside are parsed into `u64` millisatoshi and converted with checked arithmetic;
//! a sum that does not fit is the largest amount, which every cap then refuses.
use std::collections::{BTreeMap, HashMap};

use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::pyjson::{py_int, str_or_empty, truthy, ts_value};

/// The custom record a ticket payment carries to its last hop: `nonce || mac`. An odd type above
/// 65535, which a receiver that does not know it ignores (BOLT 1: "it's OK to be odd").
pub const TAG_RECORD: u64 = 1_953_063_787;
const _: () = assert!(TAG_RECORD % 2 == 1 && TAG_RECORD >= 65_536);
pub const TAG_LEN: usize = 32;
/// The feature the wire draft's terms must list.
pub const WIRE_VERSION: &str = "ticket/0";
/// The defaults of the pool settings ([`TicketPolicy`] `many_sellers`, `pool`, `pool_many` and
/// `floor_ticket_sats`): this is the one place they live. More sellers than `MANY_SELLERS` in one
/// task: `POOL_MANY` tickets a seller instead of `POOL_FEW`. They are sized for a channel that
/// carries 30 pending payments for everyone who uses it (Core Lightning's default): 2 tickets
/// held with a seller, 1 with each of more than 4. `FLOOR_MSAT` is the smallest ticket that is
/// ever held, whatever the owner's setting says: 546 sat, the larger of the dust limits of the two
/// node implementations on this network.
pub const MANY_SELLERS: usize = 4;
pub const POOL_FEW: u32 = 2;
pub const POOL_MANY: u32 = 1;
pub const FLOOR_MSAT: u64 = xbt402::ticket::MIN_HELD_TICKET_MSAT;
/// The weight of the transaction that claims a received HTLC on a channel without anchors
/// (BOLT 3): there, an HTLC has an output only above the dust limit plus this transaction's fee.
pub const HTLC_SUCCESS_WEIGHT: u64 = 703;
/// The fee rate that fee is taken at, as a multiple of the channel's present one: a ticket must
/// stay above dust while it is held, and the rate can rise meanwhile.
pub const DUST_FEE_MARGIN: u64 = 4;
/// After a lock that failed for lack of a slot the wallet locks nothing with that seller for this
/// long, doubling with each failed round in a row up to [`SLOT_WAIT_MAX_S`].
pub const SLOT_WAIT_S: f64 = 30.0;
pub const SLOT_WAIT_MAX_S: f64 = 600.0;
/// Failed rounds in a row after which the wallet holds no ticket with that seller.
pub const SLOT_FAILS_MAX: u32 = 3;
/// Why a session holds nothing ([`Session::hold_why`]): its route had no slot three rounds in a row.
pub const ROUTE_FULL: &str = "ticket_route_full";
/// Refusals of a held ticket that are no fault of the seller's terms or the owner's budgets, and
/// leave prepaid tickets, or another rail, as the way to pay: no slot, dust, a full route.
pub const HOLD_SHORT: [&str; 4] = ["ticket_slots", "ticket_dust", ROUTE_FULL, "ticket_slots_short"];
/// The default of `tickets.http_idle_s`: a session the wallet pays over HTTP is stopped, and its
/// unused tickets cancelled, after this long without a paid request. Below the gateway's own five
/// minutes, so that the wallet cancels before the seller does.
pub const HTTP_IDLE_S: i64 = 120;
/// The default of `tickets.ready_wait_ms`: how long a release waits for the seller's own word that
/// the ticket is locked on its node.
pub const READY_WAIT_MS: i64 = 3_000;
/// The default of `tickets.max_answer_s`: the longest the wallet keeps an answer that is paid for
/// as it arrives open. Below the 60 seconds a caller of the signer's socket waits by default, so
/// that a call ends, and says where it stopped, before its caller gives up on it.
pub const MAX_ANSWER_S: i64 = 50;
/// The default of `tickets.read_timeout_s`: how long the wallet waits for the next byte of a
/// seller's answer before it gives the answer up.
pub const READ_TIMEOUT_S: i64 = 30;
/// A ticket with this many blocks or fewer before its last hop's expiry is no longer released: the
/// seller refuses it (24, `docs/TICKETS.md` section 3) and one block is ours.
pub const USABLE_MARGIN_BLOCKS: i64 = 25;
/// Hashes offered and not paid lapse after this long, and their slots are offered again.
pub const OFFER_TTL_S: f64 = 120.0;
/// A session with no offer, lock or release for this long is stopped.
pub const SESSION_IDLE_S: f64 = 600.0;
/// Tickets and sessions that ended longer ago than this leave the book at its next compaction.
pub const KEEP_DONE_S: f64 = 86_400.0;
/// The most hashes one offer returns and one lock takes.
pub const MAX_BATCH: usize = 64;

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    // HMAC takes a key of any length: `new_from_slice` cannot fail for SHA-256
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).unwrap_or_else(|_| unreachable!("HMAC-SHA256 takes any key length"));
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// The ticket seed: 32 random bytes, sealed at rest by the signer's keystore.
pub struct Seed(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Seed(..)")
    }
}

impl Seed {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The secret of the ticket with this nonce.
    pub fn secret(&self, nonce: &[u8; 16]) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(hmac(&*self.0, &[b"xbt/ticket/secret/v0", nonce]))
    }

    /// The payment hash of the ticket with this nonce: SHA-256 of its secret.
    pub fn hash(&self, nonce: &[u8; 16]) -> [u8; 32] {
        Sha256::digest(self.secret(nonce).as_slice()).into()
    }

    /// What the payment for `hash` carries in [`TAG_RECORD`]: the nonce and a MAC over both.
    pub fn tag(&self, nonce: &[u8; 16], hash: &[u8; 32]) -> [u8; TAG_LEN] {
        let mac = hmac(&*self.0, &[b"xbt/ticket/tag/v0", nonce, hash]);
        let mut out = [0u8; TAG_LEN];
        out[..16].copy_from_slice(nonce);
        out[16..].copy_from_slice(&mac[..16]);
        out
    }

    /// What the payment of a prepaid ticket carries in [`TAG_RECORD`]. Its hash is the seller's, so
    /// no nonce derives it: the tag is a random nonce and a MAC over both under another label.
    pub fn prepaid_tag(&self, nonce: &[u8; 16], hash: &[u8; 32]) -> [u8; TAG_LEN] {
        let mac = hmac(&*self.0, &[b"xbt/ticket/prepaid-tag/v0", nonce, hash]);
        let mut out = [0u8; TAG_LEN];
        out[..16].copy_from_slice(nonce);
        out[16..].copy_from_slice(&mac[..16]);
        out
    }

    /// The nonce in `tag`, if this seed made it as the tag of a prepaid ticket's payment for this hash.
    pub fn read_prepaid_tag(&self, tag: &[u8], hash: &[u8; 32]) -> Option<[u8; 16]> {
        let nonce: [u8; 16] = tag.get(..16)?.try_into().ok()?;
        (tag.len() == TAG_LEN && self.prepaid_tag(&nonce, hash)[..] == *tag).then_some(nonce)
    }

    /// The nonce in `tag`, if this seed made the tag for this hash and the nonce derives the hash.
    pub fn read_tag(&self, tag: &[u8], hash: &[u8; 32]) -> Option<[u8; 16]> {
        let nonce: [u8; 16] = tag.get(..16)?.try_into().ok()?;
        if tag.len() != TAG_LEN {
            return None;
        }
        let want = self.tag(&nonce, hash);
        // not a secret comparison: the tag is public to the payee; equality is all that matters
        (want[..] == *tag && self.hash(&nonce) == *hash).then_some(nonce)
    }
}

/// msat as whole sats, rounded up: what a ledger row holds. Past `i64`, the largest amount.
pub fn sats_ceil(msat: u64) -> i64 {
    i64::try_from(msat.div_ceil(1000)).unwrap_or(i64::MAX)
}

/// What releasing one ticket books before its fee is known: the ticket and its fee limit.
pub fn booking_sats(ticket_msat: u64, fee_limit_msat: u64) -> i64 {
    sats_ceil(ticket_msat.saturating_add(fee_limit_msat))
}

/// A non-negative integer from outside: a JSON integer or a string of decimal digits, nothing else.
pub fn outside_u64(v: Option<&Value>) -> Option<u64> {
    match v? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) if !s.is_empty() && s.len() <= 20 && s.bytes().all(|c| c.is_ascii_digit()) => s.parse().ok(),
        _ => None,
    }
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// A task name: what a ledger row's memo carries, so it must not need escaping.
pub fn task_name_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}

/// The memo of a ticket's ledger row: the task it was released under and, for a ticket that has
/// one, its session (what [`Velocity::Session`] counts once).
pub fn memo(task: &str, session: &str) -> String {
    if session_name_ok(session) { format!("ticket task={task} session={session}") } else { format!("ticket task={task}") }
}

fn memo_parts(memo: &str) -> Option<(&str, Option<&str>)> {
    let rest = memo.strip_prefix("ticket task=")?;
    let (task, session) = match rest.split_once(" session=") {
        Some((t, s)) => (t, Some(s).filter(|s| session_name_ok(s))),
        None => (rest, None),
    };
    task_name_ok(task).then_some((task, session))
}

/// The task a ledger row's memo names, if it is a ticket's.
pub fn memo_task(memo: &str) -> Option<&str> {
    memo_parts(memo).map(|(t, _)| t)
}

/// The session a ticket's ledger row names (a row from before sessions were named has none).
pub fn memo_session(memo: &str) -> Option<&str> {
    memo_parts(memo).and_then(|(_, s)| s)
}

/// A session id as the book makes them: what a memo can carry without escaping.
pub fn session_name_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// What `velocity_max` counts of ticket payments (policy.json `tickets.velocity`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Velocity {
    /// Every release is one payment: the reading that pays least. With the shipped
    /// `velocity_max` of 8 an hour a wallet releases at most 8 tickets an hour.
    Release,
    /// A session is one payment, counted from its first release for as long as one of its
    /// releases is inside the window: the default. What bounds the releases of a session is then
    /// the budgets, the caps on locked funds and `max_sends_per_hour`.
    Session,
}

/// How many payments `rows` are for `velocity_max`: every row is one, except that under
/// [`Velocity::Session`] the ticket rows of one session are one together. `own_session`: the
/// session of the payment being decided, which is not counted against itself (its earlier
/// releases are that same payment). Rows are `(memo)` of the ledger entries inside the window.
pub fn velocity_count<'a>(memos: impl Iterator<Item = &'a str>, mode: Velocity, own_session: Option<&str>) -> i64 {
    let mut seen: Vec<&str> = vec![];
    let mut n = 0i64;
    for m in memos {
        match (mode, memo_session(m)) {
            (Velocity::Session, Some(s)) if own_session == Some(s) => {}
            (Velocity::Session, Some(s)) => {
                if !seen.contains(&s) {
                    seen.push(s);
                    n = n.saturating_add(1);
                }
            }
            _ => n = n.saturating_add(1),
        }
    }
    n
}

/// The ledger id of a ticket's spend.
pub fn ledger_id(hash: &str) -> String {
    format!("ticket:{hash}")
}

// --- the owner's policy ----------------------------------------------------------------------------

/// Who a task pays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// Only sellers the owner has named: `ln:<node id>` on the allowlist, or an allowlisted origin
    /// whose `counterparties` entry names the node (`ln_node`).
    Listed,
    /// Any seller, inside the task's budget and its caps for a seller the owner has not named.
    Any,
}

/// policy.json `tickets.tasks.<name>`: a kind of spending the owner approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskPolicy {
    /// Sats this task may spend, routing fees included, in any `window_s`.
    pub budget_sats: i64,
    pub window_s: i64,
    /// Sats and tickets this task may have locked and unreleased at once, across all its sellers.
    pub max_locked_sats: i64,
    pub max_locked_tickets: i64,
    /// Sellers this task may have a session with at once.
    pub max_sellers: i64,
    pub admit: Admit,
    /// For a seller the owner has not named: sats paid to it in any `window_s`, and tickets and sats
    /// locked with it at once.
    pub unlisted_max_spend_sats: i64,
    pub unlisted_max_tickets: i64,
    pub unlisted_max_locked_sats: i64,
}

/// policy.json `tickets`: the ticket rail's own settings. The allowlist, the daily and weekly
/// budgets, the per-counterparty cap, velocity and the human threshold are the wallet's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketPolicy {
    pub enabled: bool,
    /// The largest ticket, in sats.
    pub max_ticket_sats: i64,
    /// The longest life of a ticket: the final CLTV delta of its invoice, in blocks.
    pub max_ticket_blocks: i64,
    /// The longest any HTLC of a ticket may lock funds, in blocks from its send (`cltv_limit`).
    pub max_htlc_blocks: i64,
    /// The longest a ticket invoice may stay payable, in seconds.
    pub max_invoice_expiry_s: i64,
    /// The exposure cap: sats and tickets locked and unreleased at once, all sellers and tasks.
    pub max_locked_sats: i64,
    pub max_locked_tickets: i64,
    /// For one named seller: tickets and sats locked at once.
    pub seller_max_tickets: i64,
    pub seller_max_locked_sats: i64,
    /// Sessions open at once, and new ones a minute.
    pub max_sellers: i64,
    pub max_new_sellers_per_min: i64,
    /// Ticket payments handed to the node's router an hour, failed ones included.
    pub max_sends_per_hour: i64,
    /// The pool: unreleased tickets kept with one seller of a few, and with one of more than
    /// `many_sellers` in a task; the smallest ticket the wallet chooses by itself, in sats.
    pub pool: i64,
    pub pool_many: i64,
    pub many_sellers: i64,
    pub floor_ticket_sats: i64,
    /// What `velocity_max` counts ([`Velocity`]).
    pub velocity: Velocity,
    /// The HTTP binding: idle time before a session is stopped, how long a release waits for the
    /// seller to show the ticket locked, how long a read of an answer may wait for its next byte.
    pub http_idle_s: i64,
    pub ready_wait_ms: i64,
    pub read_timeout_s: i64,
    /// The longest an answer that is paid for as it arrives stays open, in seconds.
    pub max_answer_s: i64,
    pub tasks: BTreeMap<String, TaskPolicy>,
}

impl Default for TicketPolicy {
    fn default() -> Self {
        // one seller at the wire's defaults fits (2 tickets of 1,000 sat for 40 blocks, through two
        // hops of 80 blocks and the node's 3), and nothing is paid until the owner names a task.
        // In all, 15 held tickets: half of a channel that carries 30 pending payments
        let half = i64::from(xbt402::ticket::held_budget(xbt402::ticket::DEFAULT_CHANNEL_SLOTS));
        Self { enabled: false, max_ticket_sats: 1_000, max_ticket_blocks: 40, max_htlc_blocks: 204, max_invoice_expiry_s: 3_600,
               max_locked_sats: half * 1_000, max_locked_tickets: half, seller_max_tickets: POOL_FEW as i64,
               seller_max_locked_sats: POOL_FEW as i64 * 1_000, max_sellers: half,
               max_new_sellers_per_min: 30, max_sends_per_hour: 1_200, pool: POOL_FEW as i64, pool_many: POOL_MANY as i64,
               many_sellers: MANY_SELLERS as i64, floor_ticket_sats: (FLOOR_MSAT / 1000) as i64, velocity: Velocity::Session,
               http_idle_s: HTTP_IDLE_S, ready_wait_ms: READY_WAIT_MS, read_timeout_s: READ_TIMEOUT_S, max_answer_s: MAX_ANSWER_S,
               tasks: BTreeMap::new() }
    }
}

pub const TICKET_INT_KEYS: [&str; 19] = ["max_ticket_sats", "max_ticket_blocks", "max_htlc_blocks", "max_invoice_expiry_s", "max_locked_sats",
                                         "max_locked_tickets", "seller_max_tickets", "seller_max_locked_sats", "max_sellers",
                                         "max_new_sellers_per_min", "max_sends_per_hour", "pool", "pool_many", "many_sellers", "floor_ticket_sats",
                                         "http_idle_s", "ready_wait_ms", "read_timeout_s", "max_answer_s"];
pub const TASK_INT_KEYS: [&str; 8] = ["budget_sats", "window_s", "max_locked_sats", "max_locked_tickets", "max_sellers",
                                      "unlisted_max_spend_sats", "unlisted_max_tickets", "unlisted_max_locked_sats"];
/// The longest window a task's budget can be read over: what the ledger keeps.
pub const MAX_TASK_WINDOW_S: i64 = 7 * 86_400;

impl TicketPolicy {
    /// From policy.json `tickets`. A number that is missing takes the default; one that is not a
    /// non-negative integer is 0 here (it refuses, never widens) and an error in [`validate`].
    pub fn from_map(m: &Map<String, Value>) -> Self {
        let d = Self::default();
        let i = |m: &Map<String, Value>, k: &str, dflt: i64| match m.get(k).filter(|v| !v.is_null()) {
            None => dflt,
            Some(v) => py_int(Some(v)).filter(|n| *n >= 0).unwrap_or(0),
        };
        let mut p = Self { enabled: truthy(m.get("enabled")), max_ticket_sats: i(m, "max_ticket_sats", d.max_ticket_sats),
                           max_ticket_blocks: i(m, "max_ticket_blocks", d.max_ticket_blocks), max_htlc_blocks: i(m, "max_htlc_blocks", d.max_htlc_blocks),
                           max_invoice_expiry_s: i(m, "max_invoice_expiry_s", d.max_invoice_expiry_s),
                           max_locked_sats: i(m, "max_locked_sats", d.max_locked_sats), max_locked_tickets: i(m, "max_locked_tickets", d.max_locked_tickets),
                           seller_max_tickets: i(m, "seller_max_tickets", d.seller_max_tickets),
                           seller_max_locked_sats: i(m, "seller_max_locked_sats", d.seller_max_locked_sats), max_sellers: i(m, "max_sellers", d.max_sellers),
                           max_new_sellers_per_min: i(m, "max_new_sellers_per_min", d.max_new_sellers_per_min),
                           max_sends_per_hour: i(m, "max_sends_per_hour", d.max_sends_per_hour), pool: i(m, "pool", d.pool),
                           pool_many: i(m, "pool_many", d.pool_many), many_sellers: i(m, "many_sellers", d.many_sellers),
                           floor_ticket_sats: i(m, "floor_ticket_sats", d.floor_ticket_sats),
                           // left out: the default, a session is one payment. Anything that is not the word
                           // "session" counts every release: a misspelling never widens
                           velocity: match m.get("velocity").filter(|v| !v.is_null()) {
                               None => d.velocity,
                               Some(v) if v.as_str() == Some("session") => Velocity::Session,
                               Some(_) => Velocity::Release,
                           },
                           http_idle_s: i(m, "http_idle_s", d.http_idle_s), ready_wait_ms: i(m, "ready_wait_ms", d.ready_wait_ms),
                           read_timeout_s: i(m, "read_timeout_s", d.read_timeout_s), max_answer_s: i(m, "max_answer_s", d.max_answer_s),
                           tasks: BTreeMap::new() };
        for (name, t) in m.get("tasks").and_then(Value::as_object).into_iter().flatten() {
            let Some(t) = t.as_object() else { continue };
            if !task_name_ok(name) {
                continue;
            }
            // a task's own caps default to the rail's; for a seller the owner has not named, to the
            // smaller pool held (`pool_many`), two tickets' worth locked and four tickets' worth
            // paid in the task's window
            let two = p.max_ticket_sats.saturating_mul(2);
            p.tasks.insert(name.clone(), TaskPolicy {
                budget_sats: i(t, "budget_sats", 0), window_s: i(t, "window_s", 86_400).clamp(1, MAX_TASK_WINDOW_S),
                max_locked_sats: i(t, "max_locked_sats", p.max_locked_sats), max_locked_tickets: i(t, "max_locked_tickets", p.max_locked_tickets),
                max_sellers: i(t, "max_sellers", p.max_sellers),
                admit: if t.get("admit").and_then(Value::as_str) == Some("any") { Admit::Any } else { Admit::Listed },
                unlisted_max_spend_sats: i(t, "unlisted_max_spend_sats", two.saturating_mul(2)), unlisted_max_tickets: i(t, "unlisted_max_tickets", p.pool_many),
                unlisted_max_locked_sats: i(t, "unlisted_max_locked_sats", two) });
        }
        p.max_ticket_sats = p.max_ticket_sats.min(i64::MAX / 1000);
        p
    }

    pub fn max_ticket_msat(&self) -> u64 {
        (self.max_ticket_sats.max(0) as u64).saturating_mul(1000)
    }
}

/// policy.json `tickets` checks for `validate_policy`.
pub fn validate(raw: &Value, errors: &mut Vec<String>, warnings: &mut Vec<String>) {
    let Some(m) = raw.as_object() else {
        errors.push("policy.json tickets: must be an object".into());
        return;
    };
    let ints = |m: &Map<String, Value>, keys: &[&str], at: &str, errors: &mut Vec<String>| {
        for k in keys {
            match m.get(*k).filter(|v| !v.is_null()).map(|v| py_int(Some(v))) {
                None => {}
                Some(None) => errors.push(format!("policy.json {at}.{k}: not an integer")),
                Some(Some(n)) if n < 0 => errors.push(format!("policy.json {at}.{k}: must be >= 0 (got {n})")),
                _ => {}
            }
        }
    };
    ints(m, &TICKET_INT_KEYS, "tickets", errors);
    for k in m.keys() {
        if k != "enabled" && k != "tasks" && k != "velocity" && !TICKET_INT_KEYS.contains(&k.as_str()) {
            warnings.push(format!("policy.json tickets.{k}: unknown key (the signer ignores it)"));
        }
    }
    if let Some(v) = m.get("velocity").filter(|v| !v.is_null()) {
        if !matches!(v.as_str(), Some("release" | "session")) {
            errors.push("policy.json tickets.velocity: must be \"session\" (a ticket session is one payment for velocity_max: the default) or \"release\" (every release is one)".into());
        }
    }
    let p = TicketPolicy::from_map(m);
    if p.pool == 0 || p.pool_many == 0 {
        warnings.push("policy.json tickets.pool or pool_many is 0: no ticket is held".into());
    }
    if p.floor_ticket_sats < (FLOOR_MSAT / 1000) as i64 {
        warnings.push(format!("policy.json tickets.floor_ticket_sats {} is below {} sat: a held ticket is never smaller than that, whatever this says (below a \
                               channel's dust limit it could not be claimed on chain)", p.floor_ticket_sats, FLOOR_MSAT / 1000));
    }
    let half = i64::from(xbt402::ticket::held_budget(xbt402::ticket::DEFAULT_CHANNEL_SLOTS));
    if p.max_locked_tickets > half {
        warnings.push(format!("policy.json tickets.max_locked_tickets {} is above {half}: on a channel that carries 30 pending payments (a channel with a Core \
                               Lightning node) the wallet holds at most {half} whatever this says, half of what the channel carries", p.max_locked_tickets));
    }
    match m.get("tasks") {
        None | Some(Value::Null) => {}
        Some(Value::Object(tasks)) => {
            for (name, t) in tasks {
                let at = format!("tickets.tasks.{name}");
                if !task_name_ok(name) {
                    errors.push(format!("policy.json {at}: a task name is 1 to 32 of a-z, 0-9, '-' and '_'"));
                }
                let Some(t) = t.as_object() else {
                    errors.push(format!("policy.json {at}: must be an object"));
                    continue;
                };
                ints(t, &TASK_INT_KEYS, &at, errors);
                if py_int(t.get("budget_sats")).is_none_or(|b| b <= 0) {
                    errors.push(format!("policy.json {at}.budget_sats: a task needs a budget above 0"));
                }
                if py_int(t.get("window_s")).is_some_and(|w| w <= 0 || w > MAX_TASK_WINDOW_S) {
                    errors.push(format!("policy.json {at}.window_s: 1 to {MAX_TASK_WINDOW_S} (the ledger keeps a week)"));
                }
                if let Some(a) = t.get("admit").filter(|v| !v.is_null()) {
                    if !matches!(a.as_str(), Some("listed" | "any")) {
                        errors.push(format!("policy.json {at}.admit: must be \"listed\" or \"any\""));
                    }
                }
                for k in t.keys() {
                    if k != "admit" && !TASK_INT_KEYS.contains(&k.as_str()) {
                        warnings.push(format!("policy.json {at}.{k}: unknown key (the signer ignores it)"));
                    }
                }
            }
        }
        Some(_) => errors.push("policy.json tickets.tasks: must be an object".into()),
    }
    if p.enabled && p.tasks.is_empty() {
        warnings.push("policy.json tickets: enabled with no task: every ticket session is refused until tickets.tasks names one".into());
    }
    if p.max_htlc_blocks < p.max_ticket_blocks.saturating_add(3) {
        warnings.push(format!("policy.json tickets.max_htlc_blocks {} is below max_ticket_blocks {} + 3: no ticket of that life can be locked",
                              p.max_htlc_blocks, p.max_ticket_blocks));
    }
}

// --- the seller's terms ----------------------------------------------------------------------------

/// The `accepts` entry of a seller's 402, read and bounded (`docs/TICKETS.md` section 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Terms {
    /// The seller's Lightning node id, 66 hex: every invoice must name it as payee.
    pub payee: String,
    pub ticket_msat: u64,
    /// The smallest ticket the seller issues when the buyer asks for a size (absent: one size only).
    pub min_ticket_msat: Option<u64>,
    pub max_tickets: u32,
    pub ticket_blocks: u32,
    pub settle: Settle,
}

/// How a seller's tickets are settled (`settle` in its terms).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settle {
    /// A held payment, settled when its secret is used: it can be had back, and takes a slot.
    OnUse,
    /// An ordinary payment, settled when it arrives (a prepaid ticket): spent when it is paid,
    /// and it holds nothing.
    OnArrival,
}

pub type Refusal = (&'static str, String);

fn refuse<T>(rule: &'static str, msg: impl Into<String>) -> Result<T, Refusal> {
    Err((rule, msg.into()))
}

impl Terms {
    /// Read an `accepts` entry for the network `lightning` (`lightning:<32 hex>`). Everything in
    /// it is the seller's word: what is not exactly what the draft says is refused.
    pub fn parse(acc: &Value, lightning: &str) -> Result<Self, Refusal> {
        let s = |v: &Value, k: &str| str_or_empty(v.get(k));
        if s(acc, "scheme") != "ticket" {
            return refuse("ticket_terms", format!("scheme {:?} is not \"ticket\"", s(acc, "scheme")));
        }
        if s(acc, "network") != lightning {
            return refuse("ticket_network", format!("the terms are for {:?}, this wallet is on {lightning:?}", s(acc, "network")));
        }
        if s(acc, "asset") != "XBT:msat" {
            return refuse("ticket_terms", format!("asset {:?} is not \"XBT:msat\"", s(acc, "asset")));
        }
        let payee = s(acc, "payTo");
        let key_ok = is_hex(&payee, 66) && hex::decode(&payee).is_ok_and(|b| xbt_primitives::secp256k1::PublicKey::from_slice(&b).is_ok());
        if !key_ok {
            return refuse("ticket_terms", "payTo is not a Lightning node id (66 lower-case hex, a compressed public key)");
        }
        let empty = json!({});
        let x = acc.get("extra").filter(|e| e.is_object()).unwrap_or(&empty);
        if s(x, "version") != WIRE_VERSION {
            return refuse("ticket_terms", format!("version {:?} is not {WIRE_VERSION:?}", s(x, "version")));
        }
        if !x.get("features").and_then(Value::as_array).is_some_and(|a| a.iter().any(|f| f.as_u64() == Some(crate::bolt11::FEATURE_BLAKE2B as u64))) {
            return refuse("ticket_feature_512", "the terms do not list feature bit 512: not an XBT Lightning seller");
        }
        let settle = match s(x, "settle").as_str() {
            xbt402::ticket::SETTLE_ON_USE => Settle::OnUse,
            xbt402::ticket::SETTLE_ON_ARRIVAL => Settle::OnArrival,
            other => return refuse("ticket_terms", format!("settle {other:?} is neither \"on-use\" (held tickets) nor \"on-arrival\" (prepaid tickets)")),
        };
        if !matches!(s(x, "release").as_str(), "with-request" | "after-verify") {
            return refuse("ticket_terms", format!("release {:?} is neither \"with-request\" nor \"after-verify\"", s(x, "release")));
        }
        let num = |k: &str| outside_u64(x.get(k)).filter(|n| *n > 0).ok_or(("ticket_terms", format!("{k} is not a positive integer")));
        let ticket_msat = num("ticketMsat")?;
        let min_ticket_msat = match x.get("minTicketMsat").filter(|v| !v.is_null()) {
            None => None,
            Some(_) => Some(num("minTicketMsat")?),
        };
        if min_ticket_msat.is_some_and(|m| m > ticket_msat) {
            return refuse("ticket_terms", "minTicketMsat is above ticketMsat");
        }
        let small = |k: &str| num(k).and_then(|n| u32::try_from(n).map_err(|_| ("ticket_terms", format!("{k} is too large"))));
        Ok(Self { payee, ticket_msat, min_ticket_msat, max_tickets: small("maxTickets")?, ticket_blocks: small("ticketBlocks")?, settle })
    }
}

/// What the wallet's own channels allow of held tickets ([`channel_limits`]): the two limits a
/// ticket meets on the first channel of its route. Nobody can know a remote channel's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The pending payments the smallest of the channels a ticket may leave on carries each way.
    pub slots: u32,
    /// How many more payments may be pending on the fullest of those channels before it is past
    /// half of what it carries. Not above 0 when one already is.
    pub room: i64,
    /// The smallest ticket that has an output on every one of those channels, whichever side
    /// closes it, in msat. Never below [`FLOOR_MSAT`].
    pub dust_msat: u64,
}

impl Limits {
    /// What is assumed of channels that cannot be seen: 30 slots, of which none is known to be
    /// taken, and the larger of the two dust limits.
    pub fn unseen() -> Self {
        let slots = xbt402::ticket::DEFAULT_CHANNEL_SLOTS;
        Self { slots, room: i64::from(xbt402::ticket::held_budget(slots)), dust_msat: FLOOR_MSAT }
    }

    /// The held tickets the wallet may have in all: half of the smallest channel's slots.
    pub fn budget(&self) -> i64 {
        i64::from(xbt402::ticket::held_budget(self.slots))
    }

    /// How many more tickets may be locked now: what is left of the budget after the `held`
    /// tickets the book already has, and what is left of half the fullest channel after the
    /// payments pending on it and the `unseen` tickets on their way to the node.
    pub fn room(&self, held: i64, unseen: i64) -> i64 {
        self.budget().saturating_sub(held).min(self.room.saturating_sub(unseen)).max(0)
    }
}

/// The limits of the channels `ids` among the node's channel list `chans` (`GET /v1/channels`).
/// A channel's slots are the smaller of the two `max_accepted_htlcs` its node reports for it (a
/// Core Lightning node also sends no more than it accepts); its dust limit the larger of the two
/// `dust_limit_sat`, and on a channel that is not an anchor channel the fee of
/// [`HTLC_SUCCESS_WEIGHT`] at [`DUST_FEE_MARGIN`] times its fee rate on top. A number the listing
/// does not give is the cautious one (30 slots, 546 sat), never a large one. No channel named:
/// [`Limits::unseen`].
pub fn channel_limits(chans: &[Value], ids: &[String]) -> Limits {
    let num = |v: Option<&Value>| outside_u64(v);
    let mut out: Option<Limits> = None;
    for c in chans.iter().filter(|c| num(c.get("chan_id")).is_some_and(|id| ids.iter().any(|i| *i == id.to_string()))) {
        let side = |s: &str, k: &str| num(c.get(s).and_then(|x| x.get(k)));
        let slots = match (side("local_constraints", "max_accepted_htlcs"), side("remote_constraints", "max_accepted_htlcs")) {
            (Some(a), Some(b)) if a > 0 && b > 0 => u32::try_from(a.min(b)).unwrap_or(u32::MAX).min(xbt402::ticket::MAX_CHANNEL_SLOTS),
            _ => xbt402::ticket::DEFAULT_CHANNEL_SLOTS,
        };
        let pending = c.get("pending_htlcs").and_then(Value::as_array).map_or(0, |a| a.iter().filter(|h| h.get("incoming") != Some(&Value::Bool(true))).count());
        let room = i64::from(xbt402::ticket::held_budget(slots)).saturating_sub(i64::try_from(pending).unwrap_or(i64::MAX));
        let dust_sat = match (side("local_constraints", "dust_limit_sat"), side("remote_constraints", "dust_limit_sat")) {
            (Some(a), Some(b)) => a.max(b),
            _ => FLOOR_MSAT / 1000,
        };
        // anchors, and the channel types built on them, have HTLC transactions that pay no fee: the dust
        // limit is the threshold at any fee rate. Any other type the listing names has the fee on top
        let kind = c.get("commitment_type").and_then(Value::as_str).map(str::to_ascii_uppercase);
        let anchors = kind.as_deref().is_none_or(|k| k.contains("ANCHOR") || k.contains("SCRIPT_ENFORCED_LEASE") || k.contains("TAPROOT"));
        let fee_sat = if anchors {
            0
        } else {
            num(c.get("fee_per_kw")).unwrap_or(0).saturating_mul(DUST_FEE_MARGIN).saturating_mul(HTLC_SUCCESS_WEIGHT).div_ceil(1000)
        };
        let dust_msat = dust_sat.saturating_add(fee_sat).saturating_mul(1000).max(FLOOR_MSAT);
        out = Some(match out {
            None => Limits { slots, room, dust_msat },
            Some(l) => Limits { slots: l.slots.min(slots), room: l.room.min(room), dust_msat: l.dust_msat.max(dust_msat) },
        });
    }
    out.unwrap_or_else(Limits::unseen)
}

/// A session's pool, decided when it opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sizing {
    pub ticket_msat: u64,
    /// Unreleased tickets the pool is filled to; a refill starts when half of it or fewer are left.
    pub pool: u32,
}

/// The ticket size and pool for a seller: 2 tickets of the seller's size for a task with a few
/// sellers; 1 ticket sized to what the seller is expected to earn for a task with more than
/// [`MANY_SELLERS`]. The seller's terms and the owner's caps bound both. `cap_tickets` and
/// `cap_locked_sats` are the owner's caps for this seller. `dust_msat`: the smallest ticket that
/// may be held on the wallet's channels ([`Limits::dust_msat`]); a ticket is never held below it
/// or below 546 sat (`ticket_dust`). `slot_room`: how many more held tickets the slot budget has
/// room for ([`Limits::room`], less what open sessions will still lock); with none, no ticket is
/// held with this seller (`ticket_slots`).
#[allow(clippy::too_many_arguments)]
pub fn sizing(terms: &Terms, pol: &TicketPolicy, sellers_in_task: usize, expect_msat: Option<u64>, cap_tickets: i64, cap_locked_sats: i64, dust_msat: u64,
              slot_room: i64) -> Result<Sizing, Refusal> {
    let many = sellers_in_task as i64 > pol.many_sellers;
    let floor_msat = (pol.floor_ticket_sats.max(0) as u64).saturating_mul(1000).max(dust_msat).max(FLOOR_MSAT);
    let pool_of = |n: i64| u32::try_from(n.max(0)).unwrap_or(u32::MAX);
    if i64::from(terms.ticket_blocks) > pol.max_ticket_blocks {
        return refuse("ticket_blocks", format!("ticketBlocks {} is above the owner's tickets.max_ticket_blocks {}", terms.ticket_blocks, pol.max_ticket_blocks));
    }
    let owner_max = pol.max_ticket_msat().min((cap_locked_sats.max(0) as u64).saturating_mul(1000));
    let ticket_msat = match terms.min_ticket_msat {
        // one size only: it is inside the owner's bound or the seller is refused
        None if terms.ticket_msat > owner_max => {
            return refuse("ticket_size", format!("ticketMsat {} is above what the owner allows for this seller ({owner_max} msat)", terms.ticket_msat));
        }
        None => terms.ticket_msat,
        Some(min) => {
            let hi = terms.ticket_msat.min(owner_max);
            // never below the floor: a held ticket under a channel's dust limit cannot be claimed on chain
            let lo = min.max(floor_msat);
            if terms.ticket_msat < floor_msat {
                return refuse("ticket_dust", format!("the seller's ticket of {} msat is below {floor_msat} msat, the smallest that may be held: below a \
                                                      channel's dust limit a held payment has no output and is lost if the channel is force-closed", terms.ticket_msat));
            }
            if hi < lo {
                return refuse("ticket_size", format!("the smallest ticket that may be held with this seller ({lo} msat) is above what the owner allows for it ({owner_max} msat)"));
            }
            match expect_msat {
                Some(e) if many => e.div_ceil(u64::from(pool_of(pol.pool_many).max(1))).clamp(lo, hi),
                _ => hi,
            }
        }
    };
    if ticket_msat < floor_msat {
        return refuse("ticket_dust", format!("a ticket of {ticket_msat} msat is below {floor_msat} msat, the smallest that may be held: below a channel's dust \
                                              limit a held payment has no output and is lost if the channel is force-closed"));
    }
    let base = if many { pool_of(pol.pool_many) } else { pool_of(pol.pool) };
    let by_sats = cap_locked_sats.max(0) as u64 / sats_ceil(ticket_msat).max(1) as u64;
    let pool = u64::from(base.min(terms.max_tickets)).min(cap_tickets.max(0) as u64).min(by_sats);
    if pool == 0 {
        return refuse("ticket_seller_cap", "the owner's caps for this seller allow no ticket of this size");
    }
    let pool = pool.min(slot_room.max(0) as u64);
    if pool == 0 {
        return refuse("ticket_slots", "the tickets the wallet holds, or is set to hold, already take what half of its channel's pending payments and the owner's \
                                       caps on held tickets allow: no further ticket is held");
    }
    Ok(Sizing { ticket_msat, pool: pool as u32 })
}

/// The size of a prepaid ticket with this seller, from its `on-arrival` terms: the seller's one
/// size, inside the owner's largest ticket. It is paid at once and never held, so neither a dust
/// limit nor a slot bounds it.
pub fn prepaid_size(terms: &Terms, pol: &TicketPolicy) -> Result<u64, Refusal> {
    if i64::from(terms.ticket_blocks) > pol.max_ticket_blocks {
        return refuse("ticket_blocks", format!("ticketBlocks {} is above the owner's tickets.max_ticket_blocks {}", terms.ticket_blocks, pol.max_ticket_blocks));
    }
    if terms.ticket_msat > pol.max_ticket_msat() {
        return refuse("ticket_size", format!("a prepaid ticket of {} msat is above the owner's tickets.max_ticket_sats ({} msat)", terms.ticket_msat,
                                             pol.max_ticket_msat()));
    }
    if terms.ticket_msat < 1000 {
        return refuse("ticket_size", "a ticket below 1 sat: no node forwards it");
    }
    Ok(terms.ticket_msat)
}

/// Whether a ticket payment's failure, as the node names it, is what a full channel looks like: a
/// channel out of slots is reported as a balance that is short, or as no route (a hop's failure
/// names no cause). The buyer cannot tell a full hop from an empty one, and holds less either way.
pub fn slot_failure(reason: &str) -> bool {
    let r = reason.to_ascii_uppercase();
    ["INSUFFICIENT_BALANCE", "NO_ROUTE", "FAILURE_REASON_ERROR"].iter().any(|k| r.contains(k)) || r == "ERROR"
}

/// How long nothing is locked after the `fails`-th failed round in a row: 30 s, doubling to 10 minutes.
pub fn slot_wait_s(fails: u32) -> f64 {
    (SLOT_WAIT_S * f64::from(2u32.saturating_pow(fails.saturating_sub(1).min(16)))).min(SLOT_WAIT_MAX_S)
}

// --- the book --------------------------------------------------------------------------------------

/// A ticket's life. Money is locked from `Sending` until `Settled` or `Failed`; the spend is in the
/// ledger from `Released` or `Retired` until `Failed` takes it out or `Settled` makes it exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TState {
    /// Its hash went to the seller; no invoice for it has been accepted.
    Offered,
    /// Written ahead of the send: an invoice for it is with the node's router, or about to be.
    Sending,
    /// The node holds an HTLC for it; its secret has not left.
    Locked,
    /// Its secret left the signer. Booked.
    Released,
    /// Locked, and this process cannot know whether its secret left (it was locked before this
    /// start, or found on the node and not in the book). Booked as if it had; never released.
    Retired,
    /// The node shows the payment settled.
    Settled,
    /// The node shows the payment failed with no HTLC out, or it was never sent.
    Failed,
}

impl TState {
    pub fn as_str(self) -> &'static str {
        match self {
            TState::Offered => "offered",
            TState::Sending => "sending",
            TState::Locked => "locked",
            TState::Released => "released",
            TState::Retired => "retired",
            TState::Settled => "settled",
            TState::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "offered" => TState::Offered,
            "sending" => TState::Sending,
            "locked" => TState::Locked,
            "released" => TState::Released,
            "retired" => TState::Retired,
            "settled" => TState::Settled,
            "failed" => TState::Failed,
            _ => return None,
        })
    }

    pub fn terminal(self) -> bool {
        matches!(self, TState::Settled | TState::Failed)
    }

    /// Locked and its secret still in the signer: what the exposure caps count.
    pub fn unreleased(self) -> bool {
        matches!(self, TState::Sending | TState::Locked)
    }

    /// Its spend is in the ledger until the node says otherwise.
    pub fn booked(self) -> bool {
        matches!(self, TState::Released | TState::Retired)
    }

    /// A payment for it may be on the node and not final.
    pub fn in_flight(self) -> bool {
        matches!(self, TState::Sending | TState::Locked | TState::Released | TState::Retired)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ticket {
    pub hash: String,
    pub nonce: [u8; 16],
    /// Its session; empty for a ticket found on the node that the book did not hold.
    pub session: String,
    /// The seller's node id and the task, kept on the ticket so that it outlives its session.
    pub payee: String,
    pub task: String,
    pub msat: u64,
    pub fee_limit_msat: u64,
    pub state: TState,
    /// Offered at; handed to the router at; when its invoice stops being payable.
    pub ts: f64,
    pub sent_ts: f64,
    pub invoice_expires: f64,
    /// When its secret left (0: it has not).
    pub released_ts: f64,
    /// Sats this ticket has in the ledger (0: none).
    pub booked_sats: i64,
    /// The height its HTLC from this node expires at, and the height its last hop's does (0: unknown).
    pub cltv_until: i64,
    pub final_expiry: i64,
    pub fee_msat: u64,
    /// When it settled or failed, and why it failed.
    pub done_ts: f64,
    pub note: String,
    /// A prepaid ticket: an ordinary payment for a hash of the seller's, spent when it is paid.
    /// Booked (`released`) before the payment is sent and never `locked`: no secret of this
    /// wallet's releases it, and its nonce only makes the payment's tag.
    pub prepaid: bool,
}

impl Ticket {
    pub fn row(&self) -> Value {
        let mut r = json!({"e": "ticket", "hash": self.hash, "nonce": hex::encode(self.nonce), "session": self.session, "payee": self.payee, "task": self.task,
               "msat": self.msat.to_string(), "fee_limit_msat": self.fee_limit_msat.to_string(), "state": self.state.as_str(), "ts": ts_value(self.ts),
               "sent_ts": ts_value(self.sent_ts), "invoice_expires": ts_value(self.invoice_expires), "released_ts": ts_value(self.released_ts),
               "booked_sats": self.booked_sats, "cltv_until": self.cltv_until, "final_expiry": self.final_expiry,
               "fee_msat": self.fee_msat.to_string(), "done_ts": ts_value(self.done_ts), "note": self.note});
        // written only when set: a row from before prepaid tickets reads as a held one
        if self.prepaid {
            r["prepaid"] = true.into();
        }
        r
    }

    fn from_row(r: &Value) -> Option<Self> {
        let f = |k: &str| r.get(k).and_then(Value::as_f64);
        let hash = str_or_empty(r.get("hash"));
        let nonce: [u8; 16] = hex::decode(str_or_empty(r.get("nonce"))).ok()?.try_into().ok()?;
        if !is_hex(&hash, 64) {
            return None;
        }
        Some(Self { hash, nonce, session: str_or_empty(r.get("session")), payee: str_or_empty(r.get("payee")), task: str_or_empty(r.get("task")),
                    msat: outside_u64(r.get("msat"))?, fee_limit_msat: outside_u64(r.get("fee_limit_msat"))?,
                    state: TState::parse(&str_or_empty(r.get("state")))?, ts: f("ts")?, sent_ts: f("sent_ts")?, invoice_expires: f("invoice_expires")?,
                    released_ts: f("released_ts")?, booked_sats: py_int(r.get("booked_sats")).filter(|n| *n >= 0)?,
                    cltv_until: py_int(r.get("cltv_until"))?, final_expiry: py_int(r.get("final_expiry"))?, fee_msat: outside_u64(r.get("fee_msat"))?,
                    done_ts: f("done_ts")?, note: str_or_empty(r.get("note")),
                    prepaid: match r.get("prepaid") {
                        None => false,
                        Some(v) => v.as_bool()?,
                    } })
    }

    /// What the reply to a caller shows of a ticket: never its nonce.
    pub fn public(&self) -> Value {
        json!({"hash": self.hash, "state": self.state.as_str(), "msat": self.msat.to_string(), "booked_sats": self.booked_sats,
               "fee_msat": self.fee_msat.to_string(), "cltv_until": self.cltv_until, "final_expiry": self.final_expiry,
               "sent_ts": ts_value(self.sent_ts), "released_ts": ts_value(self.released_ts), "done_ts": ts_value(self.done_ts), "note": self.note,
               "prepaid": self.prepaid})
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SState {
    Open,
    /// No more offers, locks or releases; its unreleased tickets are waited for.
    Stopping,
    /// Every ticket of it has settled or failed.
    Closed,
}

impl SState {
    pub fn as_str(self) -> &'static str {
        match self {
            SState::Open => "open",
            SState::Stopping => "stopping",
            SState::Closed => "closed",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    pub id: String,
    pub payee: String,
    pub origin: String,
    pub task: String,
    /// Whether the owner named this seller (decided at open, from the policy then in force).
    pub listed: bool,
    pub ticket_msat: u64,
    pub pool: u32,
    /// The seller's own terms.
    pub max_tickets: u32,
    pub ticket_blocks: u32,
    /// The caller's own limit on what this session spends, in sats (0: none).
    pub max_sats: i64,
    pub state: SState,
    pub opened_ts: f64,
    /// The last offer, lock or release.
    pub active_ts: f64,
    pub stopped_ts: f64,
    pub closed_ts: f64,
    pub why: String,
    /// The seller's own name for this session and where its endpoints are, when the wallet itself
    /// speaks HTTP to the seller ([`crate::ticket_pay`]). Kept so that a wallet that restarted can
    /// still ask for its tickets to be cancelled.
    pub http: Option<SellerSession>,
    /// The size of a prepaid ticket with this seller, in msat, where its terms offer them
    /// (`settle: "on-arrival"`); 0 where they do not.
    pub prepaid_msat: u64,
    /// Lock rounds in a row that failed for lack of a slot.
    pub slot_fails: u32,
    /// Nothing is locked for this session before this time (0: no wait), and why.
    pub hold_until: f64,
    pub hold_why: String,
}

/// The seller's side of a session the wallet pays over HTTP: the id and the key the seller gave in
/// its first lock answer, and the URL of its session endpoints. The key authenticates requests of
/// this session; it is no ticket secret and releases no money.
#[derive(Clone, PartialEq, Eq)]
pub struct SellerSession {
    pub id: String,
    pub key: [u8; 32],
    pub base: String,
}

impl std::fmt::Debug for SellerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SellerSession {{ id: {:?}, base: {:?}, key: .. }}", self.id, self.base)
    }
}

impl Session {
    pub fn row(&self) -> Value {
        let mut r = json!({"e": "session", "id": self.id, "payee": self.payee, "origin": self.origin, "task": self.task, "listed": self.listed,
               "ticket_msat": self.ticket_msat.to_string(), "pool": self.pool, "max_tickets": self.max_tickets, "ticket_blocks": self.ticket_blocks,
               "max_sats": self.max_sats, "state": self.state.as_str(), "opened_ts": ts_value(self.opened_ts), "active_ts": ts_value(self.active_ts),
               "stopped_ts": ts_value(self.stopped_ts), "closed_ts": ts_value(self.closed_ts), "why": self.why});
        if let Some(h) = &self.http {
            r["http"] = json!({"id": h.id, "key": hex::encode(h.key), "base": h.base});
        }
        // written only when set: a row from before reads as a session that holds and waits for nothing
        if self.prepaid_msat > 0 {
            r["prepaid_msat"] = self.prepaid_msat.to_string().into();
        }
        if self.slot_fails > 0 || self.hold_until > 0.0 || !self.hold_why.is_empty() {
            r["hold"] = json!({"fails": self.slot_fails, "until": ts_value(self.hold_until), "why": self.hold_why});
        }
        r
    }

    /// Whether this session pays with a prepaid ticket now: the seller offers them, and no ticket
    /// is held (a pool of none) or none may be locked for the moment (a wait).
    pub fn prepaid_now(&self, now: f64) -> bool {
        self.prepaid_msat > 0 && (self.pool == 0 || now < self.hold_until)
    }

    /// What a lock round came to: `locked` tickets the node holds, `slot_failed` that failed as a
    /// full channel does ([`slot_failure`]). A failure halves the pool (never below 1) and sets
    /// the wait; the third failed round in a row ends holding with this seller (a pool of none,
    /// [`ROUTE_FULL`]). A round that locked and failed nothing ends the run of failures. Returns
    /// whether anything changed.
    pub fn lock_round(&mut self, locked: usize, slot_failed: usize, now: f64) -> bool {
        if slot_failed == 0 {
            let had = self.slot_fails;
            if locked > 0 {
                self.slot_fails = 0;
            }
            return had != self.slot_fails;
        }
        if locked == 0 {
            self.slot_fails = self.slot_fails.saturating_add(1);
        }
        self.pool = (self.pool / 2).max(1).min(self.pool);
        self.hold_until = now + slot_wait_s(self.slot_fails.max(1));
        self.hold_why = "ticket_slots".into();
        if self.slot_fails >= SLOT_FAILS_MAX {
            self.pool = 0;
            self.hold_until = now + SLOT_WAIT_MAX_S;
            self.hold_why = ROUTE_FULL.into();
        }
        true
    }

    fn from_row(r: &Value) -> Option<Self> {
        let f = |k: &str| r.get(k).and_then(Value::as_f64);
        let u = |k: &str| outside_u64(r.get(k)).and_then(|n| u32::try_from(n).ok());
        let state = match str_or_empty(r.get("state")).as_str() {
            "open" => SState::Open,
            "stopping" => SState::Stopping,
            "closed" => SState::Closed,
            _ => return None,
        };
        let id = str_or_empty(r.get("id"));
        if id.is_empty() {
            return None;
        }
        Some(Self { id, payee: str_or_empty(r.get("payee")), origin: str_or_empty(r.get("origin")), task: str_or_empty(r.get("task")),
                    listed: r.get("listed")?.as_bool()?, ticket_msat: outside_u64(r.get("ticket_msat"))?, pool: u("pool")?, max_tickets: u("max_tickets")?,
                    ticket_blocks: u("ticket_blocks")?, max_sats: py_int(r.get("max_sats")).filter(|n| *n >= 0)?, state, opened_ts: f("opened_ts")?,
                    active_ts: f("active_ts")?, stopped_ts: f("stopped_ts")?, closed_ts: f("closed_ts")?, why: str_or_empty(r.get("why")),
                    http: match r.get("http").filter(|h| !h.is_null()) {
                        None => None,
                        // a row that names a seller session names all of it, or the row is damage
                        Some(h) => Some(SellerSession { id: str_or_empty(h.get("id")), key: hex::decode(str_or_empty(h.get("key"))).ok()?.try_into().ok()?,
                                                        base: str_or_empty(h.get("base")) }),
                    },
                    prepaid_msat: match r.get("prepaid_msat") {
                        None => 0,
                        Some(v) => outside_u64(Some(v))?,
                    },
                    slot_fails: match r.get("hold") {
                        None => 0,
                        Some(h) => outside_u64(h.get("fails")).and_then(|n| u32::try_from(n).ok())?,
                    },
                    hold_until: match r.get("hold") {
                        None => 0.0,
                        Some(h) => h.get("until").and_then(Value::as_f64)?,
                    },
                    hold_why: r.get("hold").map(|h| str_or_empty(h.get("why"))).unwrap_or_default() })
    }

    pub fn public(&self) -> Value {
        json!({"session": self.id, "payee": self.payee, "origin": self.origin, "task": self.task, "listed": self.listed,
               "ticket_msat": self.ticket_msat.to_string(), "pool": self.pool, "state": self.state.as_str(), "opened_ts": ts_value(self.opened_ts),
               "stopped_ts": ts_value(self.stopped_ts), "closed_ts": ts_value(self.closed_ts), "why": self.why, "http": self.http.is_some(),
               "prepaid_msat": self.prepaid_msat.to_string(), "hold_until": ts_value(self.hold_until), "hold_why": self.hold_why,
               "slot_fails": self.slot_fails})
    }
}

/// Tickets and sats locked with their secrets still in the signer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Locked {
    pub tickets: i64,
    /// Their face value, in sats: what the exposure caps count. The route's fee is locked on top
    /// of it, up to each ticket's fee limit.
    pub sats: i64,
    /// What releasing them all would book ([`booking_sats`] each): what is held against the budgets.
    pub booking: i64,
}

impl Locked {
    fn add(&mut self, t: &Ticket) {
        *self = self.plus(1, sats_ceil(t.msat), booking_sats(t.msat, t.fee_limit_msat));
    }

    /// With `n` more tickets of `face` sats that each book `booking`.
    pub fn plus(self, n: i64, face: i64, booking: i64) -> Self {
        Self { tickets: self.tickets.saturating_add(n), sats: self.sats.saturating_add(face.saturating_mul(n)),
               booking: self.booking.saturating_add(booking.saturating_mul(n)) }
    }
}

/// The book: every session and ticket, and how far the node's payment list has been read. It is
/// the fold of the rows of `tickets.jsonl` ([`Book::apply`]); a row is a whole session or ticket,
/// and the last row of an id is its state.
#[derive(Debug, Default)]
pub struct Book {
    pub sessions: HashMap<String, Session>,
    pub tickets: HashMap<String, Ticket>,
    /// The node's payment index up to which every payment has been looked at.
    pub cursor: u64,
    /// When this book last saw a signer start.
    pub started: f64,
}

impl Book {
    /// Apply one row of the log. A row that is none of the book's is damage and refuses the load:
    /// a book is never read as a shorter one.
    pub fn apply(&mut self, row: &Value) -> crate::Result<()> {
        let bad = || crate::err("log", format!("tickets.jsonl: not a ticket book row: {}", row.to_string().chars().take(120).collect::<String>()));
        match row.get("e").and_then(Value::as_str) {
            Some("ticket") => {
                let t = Ticket::from_row(row).ok_or_else(bad)?;
                self.tickets.insert(t.hash.clone(), t);
            }
            Some("session") => {
                let s = Session::from_row(row).ok_or_else(bad)?;
                self.sessions.insert(s.id.clone(), s);
            }
            Some("cursor") => self.cursor = outside_u64(row.get("index")).ok_or_else(bad)?,
            Some("start") => self.started = row.get("ts").and_then(Value::as_f64).ok_or_else(bad)?,
            // a compaction drops what ended long ago
            Some("drop") => {
                for h in row.get("tickets").and_then(Value::as_array).ok_or_else(bad)? {
                    self.tickets.remove(h.as_str().ok_or_else(bad)?);
                }
                for s in row.get("sessions").and_then(Value::as_array).ok_or_else(bad)? {
                    self.sessions.remove(s.as_str().ok_or_else(bad)?);
                }
            }
            _ => return Err(bad()),
        }
        Ok(())
    }

    /// The rows that rebuild this book, without what ended before `keep_from`.
    pub fn snapshot(&self, keep_from: f64) -> Vec<Value> {
        let mut rows = vec![json!({"e": "cursor", "index": self.cursor.to_string()}), json!({"e": "start", "ts": ts_value(self.started)})];
        let mut ss: Vec<&Session> = self.sessions.values().filter(|s| s.state != SState::Closed || s.closed_ts >= keep_from).collect();
        ss.sort_by(|a, b| a.opened_ts.total_cmp(&b.opened_ts).then_with(|| a.id.cmp(&b.id)));
        rows.extend(ss.into_iter().map(Session::row));
        let mut ts: Vec<&Ticket> = self.tickets.values().filter(|t| !t.state.terminal() || t.done_ts >= keep_from).collect();
        ts.sort_by(|a, b| a.ts.total_cmp(&b.ts).then_with(|| a.hash.cmp(&b.hash)));
        rows.extend(ts.into_iter().map(Ticket::row));
        rows
    }

    /// What is locked and unreleased among the tickets `f` selects.
    pub fn locked(&self, f: impl Fn(&Ticket) -> bool) -> Locked {
        let mut l = Locked::default();
        for t in self.tickets.values().filter(|t| t.state.unreleased() && f(t)) {
            l.add(t);
        }
        l
    }

    /// The open session with this seller, if there is one.
    pub fn open_with(&self, payee: &str) -> Option<&Session> {
        self.sessions.values().find(|s| s.state == SState::Open && s.payee == payee)
    }

    pub fn open_sessions(&self, task: Option<&str>) -> usize {
        self.sessions.values().filter(|s| s.state == SState::Open && task.is_none_or(|t| s.task == t)).count()
    }

    /// Sessions opened since `t`.
    pub fn opened_since(&self, t: f64) -> usize {
        self.sessions.values().filter(|s| s.opened_ts >= t).count()
    }

    /// Ticket payments handed to the router since `t`.
    pub fn sends_since(&self, t: f64) -> usize {
        self.tickets.values().filter(|x| x.sent_ts > 0.0 && x.sent_ts >= t).count()
    }

    /// A session's tickets, oldest first.
    pub fn of_session(&self, id: &str) -> Vec<&Ticket> {
        let mut v: Vec<&Ticket> = self.tickets.values().filter(|t| t.session == id).collect();
        v.sort_by(|a, b| a.ts.total_cmp(&b.ts).then_with(|| a.hash.cmp(&b.hash)));
        v
    }

    /// The held tickets the open sessions are set to hold: what they have locked or will lock.
    /// A new session's pool is sized inside what the slot budget has left after these.
    pub fn pools_open(&self) -> i64 {
        self.pools_open_in(None)
    }

    /// As [`Self::pools_open`], for the open sessions of one task.
    pub fn pools_open_in(&self, task: Option<&str>) -> i64 {
        self.sessions.values().filter(|s| s.state == SState::Open && task.is_none_or(|t| s.task == t)).fold(0i64, |a, s| a.saturating_add(i64::from(s.pool)))
    }

    /// The last session with this seller that held less for lack of a slot, if its wait ended
    /// less than [`SLOT_WAIT_MAX_S`] ago or has not ended. What it learnt outlasts it: a new
    /// session with the seller starts with its smaller pool, its count of failed rounds and what
    /// is left of its wait, so that stopping a session and opening another does not try at once
    /// what just failed.
    pub fn held_less(&self, payee: &str, now: f64) -> Option<&Session> {
        self.sessions.values().filter(|s| s.payee == payee && HOLD_SHORT.contains(&s.hold_why.as_str()) && s.hold_why != "ticket_dust")
            .filter(|s| s.hold_until > now - SLOT_WAIT_MAX_S).max_by(|a, b| a.hold_until.total_cmp(&b.hold_until).then_with(|| a.opened_ts.total_cmp(&b.opened_ts)))
    }

    /// A prepaid ticket of the session whose payment is not final: the next is bought only after it.
    pub fn prepaid_pending(&self, session: &str) -> Option<&Ticket> {
        self.tickets.values().find(|t| t.session == session && t.prepaid && !t.state.terminal())
    }

    /// Held tickets on their way to the node that it does not show yet (`on_node`: the payment
    /// hashes pending on its channels): they take a slot each as soon as they arrive.
    pub fn sending_unseen(&self, on_node: &dyn Fn(&str) -> bool) -> i64 {
        i64::try_from(self.tickets.values().filter(|t| t.state == TState::Sending && !on_node(&t.hash)).count()).unwrap_or(i64::MAX)
    }

    /// How many hashes a session's pool wants now: up to its target once half of it or fewer are
    /// unreleased (2 tickets: when 1 is left; 1 ticket: when it is spent), counting hashes offered
    /// and not yet lapsed as on their way. None while the session waits after a lock that found
    /// no slot, and none for a session that holds nothing.
    pub fn want(&self, s: &Session, now: f64) -> usize {
        if s.pool == 0 || now < s.hold_until {
            return 0;
        }
        let (mut have, mut coming) = (0usize, 0usize);
        for t in self.tickets.values().filter(|t| t.session == s.id) {
            match t.state {
                TState::Sending | TState::Locked => have += 1,
                TState::Offered if now - t.ts <= OFFER_TTL_S => coming += 1,
                _ => {}
            }
        }
        let pool = s.pool as usize;
        if have + coming > pool / 2 {
            return 0;
        }
        pool.saturating_sub(have + coming).min(MAX_BATCH)
    }

    /// The ticket a release takes: the oldest locked one of the session that the seller will still
    /// accept at height `tip` (its last hop's expiry more than [`USABLE_MARGIN_BLOCKS`] away).
    pub fn usable(&self, session: &str, tip: i64) -> Option<&Ticket> {
        self.of_session(session).into_iter().find(|t| t.state == TState::Locked && usable_at(t, tip))
    }

    /// Locked tickets of a session that are too close to their expiry to be released.
    pub fn stale(&self, session: &str, tip: i64) -> Vec<String> {
        self.of_session(session).into_iter().filter(|t| t.state == TState::Locked && !usable_at(t, tip)).map(|t| t.hash.clone()).collect()
    }
}

/// Whether a locked ticket can still be released at `tip`. An expiry the node did not report (0)
/// is not usable: the signer releases only what it can see is still locked for long enough.
pub fn usable_at(t: &Ticket, tip: i64) -> bool {
    t.final_expiry > 0 && tip > 0 && t.final_expiry.saturating_sub(tip) > USABLE_MARGIN_BLOCKS
}

// --- the invoice of a ticket -----------------------------------------------------------------------

/// What an invoice must say to be paid as a ticket of this session (`docs/TICKETS.md` section 2).
/// The chain's prefix, feature bit 512 and a non-zero amount are [`crate::ln::check_invoice`]'s.
pub fn check_ticket_invoice(inv: &crate::bolt11::Invoice, s: &Session, pol: &TicketPolicy, now: f64) -> Result<(), Refusal> {
    if inv.payee_hex() != s.payee {
        return refuse("ticket_payee", format!("the invoice pays {}, not the seller's node {}", inv.payee_hex(), s.payee));
    }
    if inv.amount_msat != Some(s.ticket_msat) {
        return refuse("ticket_amount", format!("the invoice is for {:?} msat, a ticket of this session is {} msat", inv.amount_msat, s.ticket_msat));
    }
    if inv.min_final_cltv != u64::from(s.ticket_blocks) {
        return refuse("ticket_blocks", format!("the invoice's final CLTV delta is {}, the terms said {}", inv.min_final_cltv, s.ticket_blocks));
    }
    if i64::try_from(inv.min_final_cltv).unwrap_or(i64::MAX) > pol.max_ticket_blocks {
        return refuse("ticket_blocks", format!("a final CLTV delta of {} is above the owner's tickets.max_ticket_blocks {}", inv.min_final_cltv, pol.max_ticket_blocks));
    }
    if i64::try_from(inv.expiry_s).unwrap_or(i64::MAX) > pol.max_invoice_expiry_s {
        return refuse("ticket_expiry", format!("the invoice stays payable for {} s, above the owner's tickets.max_invoice_expiry_s {}", inv.expiry_s,
                                               pol.max_invoice_expiry_s));
    }
    if (inv.expires_at() as f64) < now + 5.0 {
        return refuse("ticket_expiry", "the invoice has expired, or does within 5 s");
    }
    if inv.payment_secret.is_none() {
        return refuse("ticket_invoice", "the invoice has no payment secret (payment_addr)");
    }
    Ok(())
}

/// What an invoice must say to be paid as a prepaid ticket of this session (`docs/TICKETS.md`
/// section 5): the seller's node, the session's prepaid size and nothing else, the terms' final
/// CLTV delta inside the owner's bound, payable for no longer than the owner allows. Its payment
/// hash is the seller's own. The chain's prefix, feature bit 512 and a non-zero amount are
/// [`crate::ln::check_invoice`]'s.
pub fn check_prepaid_invoice(inv: &crate::bolt11::Invoice, s: &Session, pol: &TicketPolicy, now: f64) -> Result<(), Refusal> {
    if s.prepaid_msat == 0 {
        return refuse("ticket_terms", "this seller's terms offer no prepaid tickets");
    }
    if inv.payee_hex() != s.payee {
        return refuse("ticket_payee", format!("the invoice pays {}, not the seller's node {}", inv.payee_hex(), s.payee));
    }
    if inv.amount_msat != Some(s.prepaid_msat) {
        return refuse("ticket_amount", format!("the invoice is for {:?} msat, a prepaid ticket of this session is {} msat", inv.amount_msat, s.prepaid_msat));
    }
    if inv.min_final_cltv != u64::from(s.ticket_blocks) {
        return refuse("ticket_blocks", format!("the invoice's final CLTV delta is {}, the terms said {}", inv.min_final_cltv, s.ticket_blocks));
    }
    if i64::try_from(inv.min_final_cltv).unwrap_or(i64::MAX) > pol.max_ticket_blocks {
        return refuse("ticket_blocks", format!("a final CLTV delta of {} is above the owner's tickets.max_ticket_blocks {}", inv.min_final_cltv, pol.max_ticket_blocks));
    }
    if i64::try_from(inv.expiry_s).unwrap_or(i64::MAX) > pol.max_invoice_expiry_s {
        return refuse("ticket_expiry", format!("the invoice stays payable for {} s, above the owner's tickets.max_invoice_expiry_s {}", inv.expiry_s,
                                               pol.max_invoice_expiry_s));
    }
    if (inv.expires_at() as f64) < now + 5.0 {
        return refuse("ticket_expiry", "the invoice has expired, or does within 5 s");
    }
    if inv.payment_secret.is_none() {
        return refuse("ticket_invoice", "the invoice has no payment secret (payment_addr)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> Seed {
        Seed::new([7u8; 32])
    }

    /// A node id that is a point on the curve.
    fn node_id() -> String {
        use xbt_primitives::secp256k1::{PublicKey, Secp256k1, SecretKey};
        hex::encode(PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[0x33; 32]).unwrap()).serialize())
    }

    fn terms(ticket_msat: u64, min: Option<u64>, max_tickets: u32) -> Terms {
        Terms { payee: node_id(), ticket_msat, min_ticket_msat: min, max_tickets, ticket_blocks: 40, settle: Settle::OnUse }
    }

    #[test]
    fn a_secret_is_a_function_of_the_seed_and_the_nonce_and_its_tag_is_only_this_seeds() {
        let (a, b) = ([1u8; 16], [2u8; 16]);
        assert_eq!(*seed().secret(&a), *seed().secret(&a), "a restore reproduces it");
        assert_ne!(*seed().secret(&a), *seed().secret(&b));
        assert_ne!(*seed().secret(&a), *Seed::new([8u8; 32]).secret(&a));
        let hash = seed().hash(&a);
        assert_eq!(hash, <[u8; 32]>::from(Sha256::digest(*seed().secret(&a))));
        let tag = seed().tag(&a, &hash);
        assert_eq!(seed().read_tag(&tag, &hash), Some(a));
        assert_eq!(Seed::new([8u8; 32]).read_tag(&tag, &hash), None, "another wallet's tag");
        assert_eq!(seed().read_tag(&tag, &seed().hash(&b)), None, "a tag moved to another payment");
        let mut bent = tag;
        bent[20] ^= 1;
        assert_eq!(seed().read_tag(&bent, &hash), None);
        assert_eq!(seed().read_tag(&tag[..31], &hash), None);
        assert_eq!(seed().read_tag(&[tag.as_slice(), &[0]].concat(), &hash), None);
        // the tag gives nobody the secret: it is the nonce and a MAC, and the secret needs the seed
        assert!(!tag.windows(8).any(|w| seed().secret(&a).windows(8).any(|s| s == w)));
        // a prepaid ticket's hash is the seller's: its tag is this seed's all the same, and is no held ticket's tag
        let theirs = [0x5au8; 32];
        let pt = seed().prepaid_tag(&a, &theirs);
        assert_eq!(seed().read_prepaid_tag(&pt, &theirs), Some(a));
        assert_eq!(seed().read_tag(&pt, &theirs), None, "no nonce of this seed derives the seller's hash");
        assert_eq!(seed().read_prepaid_tag(&tag, &hash), None, "a held ticket's tag is not a prepaid one's");
        assert_eq!(Seed::new([8u8; 32]).read_prepaid_tag(&pt, &theirs), None);
        assert_eq!(seed().read_prepaid_tag(&pt, &hash), None, "moved to another payment");
        assert_eq!(seed().read_prepaid_tag(&pt[..31], &theirs), None);
    }

    #[test]
    fn amounts_from_outside_are_digits_only_and_never_wrap() {
        for bad in [json!(-1), json!(1.5), json!("1e3"), json!(" 1"), json!("+1"), json!(""), json!("0x10"), json!(null), json!([1]),
                    json!("184467440737095516160")] {
            assert_eq!(outside_u64(Some(&bad)), None, "{bad}");
        }
        assert_eq!(outside_u64(Some(&json!("18446744073709551615"))), Some(u64::MAX));
        assert_eq!(outside_u64(Some(&json!(7))), Some(7));
        assert_eq!((sats_ceil(1), sats_ceil(1000), sats_ceil(1001), sats_ceil(u64::MAX)), (1, 1, 2, 18_446_744_073_709_552));
        assert_eq!(booking_sats(u64::MAX, u64::MAX), sats_ceil(u64::MAX));
        assert_eq!(booking_sats(1_000_000, 15_000), 1015);
    }

    fn accepts() -> Value {
        json!({"scheme": "ticket", "network": "lightning:00000000000000000000000000000001", "asset": "XBT:msat", "amount": "2500",
               "payTo": node_id(),
               "extra": {"version": "ticket/0", "features": [512], "ticketMsat": "1000000", "maxTickets": 8, "ticketBlocks": 40,
                         "release": "with-request", "settle": "on-use", "receiptKey": "02", "session": "/x402/ticket"}})
    }

    #[test]
    fn terms_are_read_exactly_as_the_draft_writes_them() {
        let net = "lightning:00000000000000000000000000000001";
        let t = Terms::parse(&accepts(), net).unwrap();
        assert_eq!((t.ticket_msat, t.min_ticket_msat, t.max_tickets, t.ticket_blocks), (1_000_000, None, 8, 40));
        let with = |path: &[&str], v: Value| {
            let mut a = accepts();
            let mut at = &mut a;
            for p in &path[..path.len() - 1] {
                at = &mut at[*p];
            }
            at[path[path.len() - 1]] = v;
            Terms::parse(&a, net).map_err(|e| e.0)
        };
        assert_eq!(with(&["scheme"], json!("xbt-channel")), Err("ticket_terms"));
        assert_eq!(with(&["network"], json!("lightning:00000000000000000000000000000002")), Err("ticket_network"));
        assert_eq!(with(&["network"], json!("bip122:00000000000000000000000000000001")), Err("ticket_network"));
        assert_eq!(with(&["asset"], json!("XBT")), Err("ticket_terms"));
        assert_eq!(with(&["payTo"], json!(node_id()[..64])), Err("ticket_terms"));
        assert_eq!(with(&["payTo"], json!("05".to_string() + &node_id()[2..])), Err("ticket_terms"), "not a point");
        assert_eq!(with(&["payTo"], json!(node_id().to_uppercase())), Err("ticket_terms"), "upper case");
        assert_eq!(with(&["extra", "version"], json!("ticket/1")), Err("ticket_terms"));
        assert_eq!(with(&["extra", "features"], json!([9])), Err("ticket_feature_512"));
        assert_eq!(with(&["extra", "settle"], json!("on-arrival")).map(|t| t.settle), Ok(Settle::OnArrival), "prepaid tickets");
        assert_eq!(t.settle, Settle::OnUse);
        assert_eq!(with(&["extra", "settle"], json!("whenever")), Err("ticket_terms"));
        assert_eq!(with(&["extra", "settle"], Value::Null), Err("ticket_terms"));
        assert_eq!(with(&["extra", "release"], json!("whenever")), Err("ticket_terms"));
        assert!(with(&["extra", "release"], json!("after-verify")).is_ok());
        for bad in [json!("0"), json!("-5"), json!(1.5), json!("1e6"), json!("18446744073709551616"), json!(null)] {
            assert_eq!(with(&["extra", "ticketMsat"], bad.clone()), Err("ticket_terms"), "{bad}");
        }
        assert_eq!(with(&["extra", "maxTickets"], json!(0)), Err("ticket_terms"));
        assert_eq!(with(&["extra", "maxTickets"], json!(4_294_967_296u64)), Err("ticket_terms"));
        assert_eq!(with(&["extra", "ticketBlocks"], json!("forty")), Err("ticket_terms"));
        assert_eq!(with(&["extra", "minTicketMsat"], json!("2000000")), Err("ticket_terms"), "a floor above the size");
        assert_eq!(with(&["extra", "minTicketMsat"], json!("64000")).map(|t| t.min_ticket_msat), Ok(Some(64_000)));
    }

    #[test]
    fn a_pool_is_2_of_the_sellers_size_for_a_few_sellers_and_1_sized_to_earnings_for_many() {
        let pol = TicketPolicy::default();
        let free = Limits::unseen();
        let few = |t: &Terms, n: usize, e: Option<u64>| sizing(t, &pol, n, e, pol.seller_max_tickets, pol.seller_max_locked_sats, free.dust_msat, free.room(0, 0));
        assert_eq!(few(&terms(1_000_000, None, 8), 1, None), Ok(Sizing { ticket_msat: 1_000_000, pool: 2 }));
        assert_eq!(few(&terms(1_000_000, None, 8), 4, None), Ok(Sizing { ticket_msat: 1_000_000, pool: 2 }), "4 sellers are still a few");
        assert_eq!(few(&terms(1_000_000, None, 8), 5, None), Ok(Sizing { ticket_msat: 1_000_000, pool: 1 }), "a seller with one size keeps it");
        assert_eq!(few(&terms(1_000_000, None, 1), 1, None).map(|s| s.pool), Ok(1), "the seller's maxTickets binds");
        assert_eq!(few(&terms(1_000_000, None, 100), 1, None).map(|s| s.pool), Ok(2), "a seller that asks for 100 gets 2");
        // sized to expected earnings, between the floor and the seller's size
        let flex = terms(1_000_000, Some(1_000), 8);
        assert_eq!(few(&flex, 20, Some(700_000)), Ok(Sizing { ticket_msat: 700_000, pool: 1 }));
        assert_eq!(few(&flex, 20, Some(10_000)), Ok(Sizing { ticket_msat: FLOOR_MSAT, pool: 1 }), "never below 546 sat");
        assert_eq!(few(&flex, 20, Some(u64::MAX)), Ok(Sizing { ticket_msat: 1_000_000, pool: 1 }), "never above the seller's size");
        assert_eq!(few(&flex, 20, None), Ok(Sizing { ticket_msat: 1_000_000, pool: 1 }), "no expectation: the seller's size");
        assert_eq!(few(&flex, 3, Some(10_000)), Ok(Sizing { ticket_msat: 1_000_000, pool: 2 }), "a few sellers: the seller's size");
        assert_eq!(few(&terms(1_000_000, Some(800_000), 8), 20, Some(10_000)).map(|s| s.ticket_msat), Ok(800_000), "the seller's floor binds");
        // the owner's bounds
        assert_eq!(few(&terms(5_000_000, None, 8), 1, None).map_err(|e| e.0), Err("ticket_size"), "one size, above the owner's");
        assert_eq!(few(&terms(5_000_000, Some(600_000), 8), 1, None), Ok(Sizing { ticket_msat: 1_000_000, pool: 2 }), "a flexible seller is cut to it");
        assert_eq!(few(&terms(5_000_000, Some(2_000_000), 8), 1, None).map_err(|e| e.0), Err("ticket_size"));
        assert_eq!(few(&Terms { ticket_blocks: 41, ..terms(1_000_000, None, 8) }, 1, None).map_err(|e| e.0), Err("ticket_blocks"));
        // an unnamed seller's caps: 1 ticket, 2,000 sat locked
        assert_eq!(sizing(&terms(1_000_000, None, 8), &pol, 1, None, 1, 2_000, FLOOR_MSAT, 15), Ok(Sizing { ticket_msat: 1_000_000, pool: 1 }));
        assert_eq!(sizing(&terms(1_000_000, None, 8), &pol, 1, None, 8, 1_500, FLOOR_MSAT, 15).map(|s| s.pool), Ok(1), "the locked-sats cap binds");
        assert_eq!(sizing(&terms(1_000_000, None, 8), &pol, 1, None, 8, 999, FLOOR_MSAT, 15).map_err(|e| e.0), Err("ticket_size"));
        assert_eq!(sizing(&terms(1_000_000, None, 8), &pol, 1, None, 0, 8_000, FLOOR_MSAT, 15).map_err(|e| e.0), Err("ticket_seller_cap"));
        assert_eq!(sizing(&terms(1_000_000, None, 8), &pol, 1, None, -5, i64::MIN, FLOOR_MSAT, 15).map_err(|e| e.0), Err("ticket_size"), "negative caps allow nothing");
    }

    #[test]
    fn a_held_ticket_is_never_dust() {
        let pol = TicketPolicy::default();
        let at = |t: &Terms, dust: u64| sizing(t, &pol, 1, None, 2, 2_000, dust, 15).map_err(|e| e.0);
        // 546 sat is the least, whatever the seller offers and whatever the wallet sees
        assert_eq!(at(&terms(546_000, None, 2), FLOOR_MSAT), Ok(Sizing { ticket_msat: 546_000, pool: 2 }));
        assert_eq!(at(&terms(545_999, None, 2), FLOOR_MSAT), Err("ticket_dust"));
        assert_eq!(at(&terms(64_000, None, 2), FLOOR_MSAT), Err("ticket_dust"), "the many-seller ticket of the earlier design");
        assert_eq!(at(&terms(999, None, 2), FLOOR_MSAT), Err("ticket_dust"));
        assert_eq!(at(&terms(64_000, None, 2), 0), Err("ticket_dust"), "a channel that claims no dust limit does not lower the floor");
        // a seller that lets the buyer choose is asked for no less than the floor
        assert_eq!(at(&terms(1_000_000, Some(64_000), 2), FLOOR_MSAT).map(|s| s.ticket_msat), Ok(1_000_000));
        let many = |e: u64| sizing(&terms(1_000_000, Some(64_000), 2), &pol, 9, Some(e), 2, 2_000, FLOOR_MSAT, 15).map(|s| s.ticket_msat);
        assert_eq!((many(64_000), many(600_000)), (Ok(546_000), Ok(600_000)));
        assert_eq!(at(&terms(400_000, Some(64_000), 2), FLOOR_MSAT), Err("ticket_dust"), "its largest ticket is dust");
        // a channel whose dust limit is higher raises it (a channel without anchors at a high fee rate)
        assert_eq!(at(&terms(1_000_000, None, 2), 1_424_000), Err("ticket_dust"));
        assert_eq!(at(&terms(1_000_000, Some(64_000), 2), 1_424_000), Err("ticket_dust"), "its largest ticket is dust on that channel");
        assert_eq!(at(&terms(5_000_000, Some(64_000), 2), 1_424_000), Err("ticket_size"), "the least that may be held is above the owner's largest ticket");
        // the owner's own floor can only raise it
        let high = TicketPolicy::from_map(json!({"floor_ticket_sats": 800}).as_object().unwrap());
        assert_eq!(sizing(&terms(700_000, None, 2), &high, 1, None, 2, 2_000, FLOOR_MSAT, 15).map_err(|e| e.0), Err("ticket_dust"));
        let low = TicketPolicy::from_map(json!({"floor_ticket_sats": 64}).as_object().unwrap());
        assert_eq!(sizing(&terms(64_000, None, 2), &low, 1, None, 2, 2_000, FLOOR_MSAT, 15).map_err(|e| e.0), Err("ticket_dust"));
        let (mut errors, mut warnings) = (vec![], vec![]);
        validate(&json!({"floor_ticket_sats": 64, "max_locked_tickets": 64}), &mut errors, &mut warnings);
        assert!(errors.is_empty() && warnings.iter().any(|w| w.contains("floor_ticket_sats 64 is below 546")), "{warnings:?}");
        assert!(warnings.iter().any(|w| w.contains("max_locked_tickets 64 is above 15")), "an earlier policy is told what it now means: {warnings:?}");
        // a prepaid ticket is paid at once and never held: no floor but the node's 1 sat
        let pre = |msat: u64| prepaid_size(&Terms { settle: Settle::OnArrival, ..terms(msat, None, 2) }, &pol).map_err(|e| e.0);
        assert_eq!((pre(64_000), pre(1_000_000), pre(999), pre(1_000_001)), (Ok(64_000), Ok(1_000_000), Err("ticket_size"), Err("ticket_size")));
        assert_eq!(prepaid_size(&Terms { ticket_blocks: 41, ..terms(64_000, None, 2) }, &pol).map_err(|e| e.0), Err("ticket_blocks"));
    }

    fn chan(id: u64, local: Value, remote: Value, kind: Value, pending_out: usize, pending_in: usize) -> Value {
        let mut htlcs: Vec<Value> = (0..pending_out).map(|n| json!({"incoming": false, "amount": "1000", "hash_lock": format!("o{n}")})).collect();
        htlcs.extend((0..pending_in).map(|n| json!({"incoming": true, "amount": "1000", "hash_lock": format!("i{n}")})));
        let mut c = json!({"chan_id": id.to_string(), "active": true, "fee_per_kw": "253", "pending_htlcs": htlcs});
        for (k, v) in [("local_constraints", local), ("remote_constraints", remote), ("commitment_type", kind)] {
            if !v.is_null() {
                c[k] = v;
            }
        }
        c
    }

    fn side(slots: u64, dust: u64) -> Value {
        json!({"max_accepted_htlcs": slots, "dust_limit_sat": dust.to_string()})
    }

    #[test]
    fn a_channels_slots_are_the_smaller_number_and_held_tickets_take_half() {
        let ids = |v: &[u64]| v.iter().map(u64::to_string).collect::<Vec<_>>();
        // between two Lightning Fork nodes: 483 each way, 354 sat
        let lf = chan(1, side(483, 354), side(483, 354), json!("ANCHORS"), 0, 0);
        assert_eq!(channel_limits(std::slice::from_ref(&lf), &ids(&[1])), Limits { slots: 483, room: 241, dust_msat: FLOOR_MSAT });
        // with a Core Lightning node: the listing says 30 one way and 483 the other, and the channel carries 30 both ways
        let cln = chan(2, side(30, 354), side(483, 546), json!("ANCHORS"), 4, 9);
        let l = channel_limits(std::slice::from_ref(&cln), &ids(&[2]));
        assert_eq!(l, Limits { slots: 30, room: 11, dust_msat: 546_000 }, "15 less the 4 payments pending outwards; inbound ones use the other side's slots");
        assert_eq!((l.budget(), l.room(0, 0), l.room(3, 0), l.room(0, 5), l.room(14, 0), l.room(15, 0), l.room(99, 99)), (15, 11, 11, 6, 1, 0, 0));
        // two channels a ticket may leave on: the smaller budget, the fuller channel, the larger dust limit
        assert_eq!(channel_limits(&[lf.clone(), cln.clone()], &ids(&[1, 2])), Limits { slots: 30, room: 11, dust_msat: 546_000 });
        // a channel the payment may not leave on does not count
        assert_eq!(channel_limits(&[lf.clone(), cln.clone()], &ids(&[1])).slots, 483);
        // a full channel has no room, however much the budget is
        let full = chan(3, side(30, 546), side(30, 546), json!("ANCHORS"), 15, 0);
        assert_eq!(channel_limits(&[full], &ids(&[3])).room(0, 0), 0);
        let over = chan(3, side(30, 546), side(30, 546), json!("ANCHORS"), 22, 0);
        assert_eq!((channel_limits(std::slice::from_ref(&over), &ids(&[3])).room, channel_limits(std::slice::from_ref(&over), &ids(&[3])).room(0, 0)), (-7, 0));
        // a listing that does not say is read as the cautious number, never as 483
        let blind = chan(4, Value::Null, Value::Null, Value::Null, 2, 0);
        assert_eq!(channel_limits(&[blind], &ids(&[4])), Limits { slots: 30, room: 13, dust_msat: FLOOR_MSAT });
        let half_said = chan(5, side(483, 354), json!({"max_accepted_htlcs": "many"}), json!("ANCHORS"), 0, 0);
        assert_eq!(channel_limits(&[half_said], &ids(&[5])).slots, 30);
        let zero = chan(6, side(0, 354), side(483, 354), json!("ANCHORS"), 0, 0);
        assert_eq!(channel_limits(&[zero], &ids(&[6])).slots, 30);
        let huge = chan(7, side(100_000, 354), side(100_000, 354), json!("ANCHORS"), 0, 0);
        assert_eq!(channel_limits(&[huge], &ids(&[7])).slots, 483, "no channel carries more than the protocol's ceiling");
        assert_eq!(channel_limits(&[lf], &[]), Limits::unseen(), "no channel named: nothing is seen");
        assert_eq!(Limits::unseen(), Limits { slots: 30, room: 15, dust_msat: 546_000 });
        // without anchors the HTLC's own transaction pays a fee: 703 weight units at four times the channel's rate on top
        let legacy = |kw: u64| {
            let mut c = chan(8, side(483, 354), side(483, 546), json!("STATIC_REMOTE_KEY"), 0, 0);
            c["fee_per_kw"] = kw.to_string().into();
            channel_limits(&[c], &ids(&[8])).dust_msat
        };
        assert_eq!(legacy(253), (546 + 712) * 1000, "703 * 4 * 253 / 1000, rounded up");
        assert_eq!(legacy(1250), (546 + 3515) * 1000);
        assert_eq!(legacy(u64::MAX), u64::MAX, "a rate that does not fit is the largest floor, which refuses every ticket");
        for anchors in ["ANCHORS", "SCRIPT_ENFORCED_LEASE", "SIMPLE_TAPROOT", "anchors"] {
            let c = chan(9, side(483, 354), side(483, 546), json!(anchors), 0, 0);
            assert_eq!(channel_limits(&[c], &ids(&[9])).dust_msat, 546_000, "{anchors}");
        }
    }

    #[test]
    fn a_lock_that_finds_no_slot_makes_the_session_hold_less_then_wait_then_nothing() {
        for (reason, slot) in [("FAILURE_REASON_INSUFFICIENT_BALANCE", true), ("FAILURE_REASON_NO_ROUTE", true), ("FAILURE_REASON_ERROR", true),
                               ("insufficient_balance", true), ("FAILURE_REASON_TIMEOUT", false), ("FAILURE_REASON_INCORRECT_PAYMENT_DETAILS", false), ("", false)] {
            assert_eq!(slot_failure(reason), slot, "{reason}");
        }
        assert_eq!((slot_wait_s(1), slot_wait_s(2), slot_wait_s(3), slot_wait_s(5), slot_wait_s(6), slot_wait_s(u32::MAX)), (30.0, 60.0, 120.0, 480.0, 600.0, 600.0));
        let mut s = session("s1", 2);
        assert!(!s.lock_round(2, 0, 100.0), "a round that locked what it asked for changes nothing");
        // one of two failed: one ticket from now on, and a wait
        assert!(s.lock_round(1, 1, 100.0));
        assert_eq!((s.pool, s.slot_fails, s.hold_until, s.hold_why.as_str()), (1, 0, 130.0, "ticket_slots"));
        let mut b = Book::default();
        b.sessions.insert(s.id.clone(), s.clone());
        assert_eq!((b.want(&s, 129.0), b.want(&s, 130.0)), (0, 1), "nothing is offered during the wait");
        // the one ticket does not lock either: the wait doubles
        assert!(s.lock_round(0, 1, 130.0));
        assert_eq!((s.pool, s.slot_fails, s.hold_until), (1, 1, 160.0));
        assert!(s.lock_round(0, 1, 160.0));
        assert_eq!((s.pool, s.slot_fails, s.hold_until), (1, 2, 220.0));
        // a round that locks ends the run
        let mut ok = s.clone();
        assert!(ok.lock_round(1, 0, 220.0));
        assert_eq!((ok.pool, ok.slot_fails), (1, 0), "the smaller pool stays: the route is as full as it was");
        // the third failed round in a row: no ticket is held with this seller, for 10 minutes
        assert!(s.lock_round(0, 1, 220.0));
        assert_eq!((s.pool, s.slot_fails, s.hold_until, s.hold_why.as_str()), (0, 3, 820.0, ROUTE_FULL));
        b.sessions.insert(s.id.clone(), s.clone());
        assert_eq!(b.want(&s, 10_000.0), 0, "a pool of none wants nothing, ever");
        assert_eq!((b.held_less("p", 500.0).map(|s| (s.hold_until, s.hold_why.as_str())), b.held_less("other", 500.0)), (Some((820.0, ROUTE_FULL)), None));
        assert_eq!(b.held_less("p", 1419.0).map(|s| s.slot_fails), Some(3), "what a session learnt is kept for 10 minutes after its wait");
        assert_eq!(b.held_less("p", 1420.0), None);
        assert_eq!(b.pools_open(), 0);
        // with prepaid tickets on offer the session pays that way while it waits and once it holds nothing
        let mut p = session("s2", 2);
        p.prepaid_msat = 1_000_000;
        assert!(!p.prepaid_now(100.0), "held tickets are the default");
        p.lock_round(0, 1, 100.0);
        assert!(p.prepaid_now(129.0) && !p.prepaid_now(130.0));
        p.pool = 0;
        assert!(p.prepaid_now(1e9));
        assert!(!session("s3", 0).prepaid_now(0.0), "a seller that offers none");
        // the wait and the offer outlive a restart, and a row from before has neither
        assert_eq!(Session::from_row(&p.row()), Some(p.clone()));
        assert_eq!(Session::from_row(&s.row()), Some(s));
        let mut old = session("s4", 8).row();
        assert!(old.get("hold").is_none() && old.get("prepaid_msat").is_none());
        old["hold"] = json!({"fails": "x"});
        assert_eq!(Session::from_row(&old), None, "a damaged row is refused, not read as no wait");
    }

    #[test]
    fn the_policy_reads_missing_as_the_default_and_wrong_as_zero() {
        assert_eq!(TicketPolicy::from_map(&Map::new()), TicketPolicy::default());
        assert!(!TicketPolicy::default().enabled && TicketPolicy::default().tasks.is_empty(), "shipped: off, and no task to pay under");
        let raw = json!({"enabled": true, "max_ticket_sats": "lots", "max_locked_sats": -5, "max_locked_tickets": 9,
                         "tasks": {"inference": {"budget_sats": 5000, "admit": "any", "window_s": 99_999_999},
                                   "Bad Name": {"budget_sats": 1}, "strict": {"budget_sats": 10, "admit": "everyone"}}});
        let p = TicketPolicy::from_map(raw.as_object().unwrap());
        assert_eq!((p.max_ticket_sats, p.max_locked_sats, p.max_locked_tickets), (0, 0, 9), "a wrong number refuses, it never widens");
        let t = &p.tasks["inference"];
        assert_eq!((t.budget_sats, t.admit, t.window_s, t.max_locked_tickets, t.unlisted_max_tickets), (5000, Admit::Any, MAX_TASK_WINDOW_S, 9, 1));
        assert_eq!(p.tasks["strict"].admit, Admit::Listed, "an unknown admission is the strict one");
        assert!(!p.tasks.contains_key("Bad Name"));
        let (mut errors, mut warnings) = (vec![], vec![]);
        validate(&raw, &mut errors, &mut warnings);
        let has = |list: &[String], s: &str| list.iter().any(|e| e.contains(s));
        assert!(has(&errors, "tickets.max_ticket_sats: not an integer") && has(&errors, "tickets.max_locked_sats: must be >= 0"));
        assert!(has(&errors, "tickets.tasks.Bad Name: a task name") && has(&errors, "strict.admit") && has(&errors, "inference.window_s"));
        let (mut errors, mut warnings) = (vec![], vec![]);
        validate(&json!({"enabled": true, "typo": 1, "tasks": {"t": {}}}), &mut errors, &mut warnings);
        assert!(has(&errors, "tickets.tasks.t.budget_sats: a task needs a budget") && has(&warnings, "tickets.typo: unknown key"));
        let (mut errors, mut warnings) = (vec![], vec![]);
        validate(&json!({"enabled": true}), &mut errors, &mut warnings);
        assert!(errors.is_empty() && has(&warnings, "enabled with no task"));
        assert_eq!(TicketPolicy::from_map(json!({"max_ticket_sats": i64::MAX}).as_object().unwrap()).max_ticket_msat(), (i64::MAX as u64 / 1000) * 1000);
    }

    fn ticket(hash: u8, session: &str, state: TState, ts: f64) -> Ticket {
        Ticket { hash: hex::encode([hash; 32]), nonce: [hash; 16], session: session.into(), payee: "p".into(), task: "t".into(), msat: 1_000_000,
                 fee_limit_msat: 15_000, state, ts, sent_ts: 0.0, invoice_expires: 0.0, released_ts: 0.0, booked_sats: 0, cltv_until: 0,
                 final_expiry: 300, fee_msat: 0, done_ts: 0.0, note: String::new(), prepaid: false }
    }

    fn session(id: &str, pool: u32) -> Session {
        Session { id: id.into(), payee: "p".into(), origin: String::new(), task: "t".into(), listed: true, ticket_msat: 1_000_000, pool, max_tickets: 8,
                  ticket_blocks: 40, max_sats: 0, state: SState::Open, opened_ts: 1.0, active_ts: 1.0, stopped_ts: 0.0, closed_ts: 0.0, why: String::new(),
                  http: None, prepaid_msat: 0, slot_fails: 0, hold_until: 0.0, hold_why: String::new() }
    }

    #[test]
    fn the_sellers_side_of_a_session_is_kept_in_its_row_and_a_damaged_one_refuses_the_row() {
        let mut s = session("s1", 8);
        assert_eq!(Session::from_row(&s.row()), Some(s.clone()), "a row from before the HTTP binding has no seller side");
        s.http = Some(SellerSession { id: "ab".repeat(16), key: [7u8; 32], base: "https://seller.example/x402/ticket".into() });
        let row = s.row();
        assert_eq!(Session::from_row(&row), Some(s.clone()));
        assert_eq!(s.public()["http"], true);
        assert!(!s.public().to_string().contains(&hex::encode([7u8; 32])), "the key is not in what a caller is shown");
        assert!(!format!("{s:?}").contains("0707"), "nor in a debug print");
        let mut bent = row.clone();
        bent["http"]["key"] = "07".into();
        assert_eq!(Session::from_row(&bent), None);
    }

    #[test]
    fn velocity_counts_every_release_unless_the_owner_says_a_session_is_one_payment() {
        let rows = [memo("film", "s1"), memo("film", "s1"), memo("film", "s2"), "xbt402 signed delta".to_string(), memo("recovered", ""), memo("film", "s1")];
        let count = |mode, own| velocity_count(rows.iter().map(String::as_str), mode, own);
        assert_eq!(count(Velocity::Release, None), 6, "every row is a payment");
        assert_eq!(count(Velocity::Release, Some("s1")), 6, "and a release is never free of its own session's rows");
        assert_eq!(count(Velocity::Session, None), 4, "s1 once, s2 once, the channel payment, the ticket without a session");
        assert_eq!(count(Velocity::Session, Some("s1")), 3, "a release of s1 does not count s1 against itself");
        assert_eq!(count(Velocity::Session, Some("s3")), 4, "a new session is one more payment");
        // the setting: a session counts once unless the owner says "release"; a word that is neither counts every release
        let pol = |v: Value| TicketPolicy::from_map(json!({"velocity": v}).as_object().unwrap()).velocity;
        assert_eq!((pol(json!("session")), pol(json!("release")), pol(json!("Session")), pol(json!(true)), pol(Value::Null)),
                   (Velocity::Session, Velocity::Release, Velocity::Release, Velocity::Release, Velocity::Session));
        assert_eq!(TicketPolicy::from_map(&Map::new()).velocity, Velocity::Session, "a policy that does not say: a session is one payment");
        let (mut errors, mut warnings) = (vec![], vec![]);
        validate(&json!({"velocity": "sessions"}), &mut errors, &mut warnings);
        assert!(errors.iter().any(|e| e.contains("tickets.velocity")), "{errors:?}");
    }

    #[test]
    fn the_pool_and_the_floor_are_the_owners_settings_with_one_default_each() {
        let d = TicketPolicy::default();
        assert_eq!((d.pool, d.pool_many, d.many_sellers, d.floor_ticket_sats), (2, 1, 4, 546));
        assert_eq!((d.pool, d.pool_many, d.many_sellers, d.floor_ticket_sats), (POOL_FEW as i64, POOL_MANY as i64, MANY_SELLERS as i64, (FLOOR_MSAT / 1000) as i64));
        assert_eq!((d.seller_max_tickets, d.seller_max_locked_sats, d.max_locked_tickets, d.max_locked_sats, d.max_sellers), (2, 2_000, 15, 15_000, 15),
                   "one seller: 2 tickets; in all: half of a 30-slot channel");
        // an owner whose channels all carry 483: eight tickets a seller, as before
        let pol = TicketPolicy::from_map(json!({"pool": 8, "pool_many": 2, "many_sellers": 8, "floor_ticket_sats": 700}).as_object().unwrap());
        let flex = terms(1_000_000, Some(1_000), 8);
        assert_eq!(sizing(&flex, &pol, 1, None, 8, 8_000, FLOOR_MSAT, 241), Ok(Sizing { ticket_msat: 1_000_000, pool: 8 }));
        assert_eq!(sizing(&flex, &pol, 9, Some(10_000), 8, 8_000, FLOOR_MSAT, 241), Ok(Sizing { ticket_msat: 700_000, pool: 2 }), "more than many_sellers: the floor");
        // the slot budget bounds the pool whatever the owner set, and with no room nothing is held
        assert_eq!(sizing(&flex, &pol, 1, None, 8, 8_000, FLOOR_MSAT, 3).map(|s| s.pool), Ok(3));
        assert_eq!(sizing(&flex, &pol, 1, None, 8, 8_000, FLOOR_MSAT, 0).map_err(|e| e.0), Err("ticket_slots"));
        assert_eq!(sizing(&flex, &pol, 1, None, 8, 8_000, FLOOR_MSAT, -4).map_err(|e| e.0), Err("ticket_slots"));
        let none = TicketPolicy::from_map(json!({"pool": 0}).as_object().unwrap());
        assert_eq!(sizing(&flex, &none, 1, None, 8, 8_000, FLOOR_MSAT, 15).map_err(|e| e.0), Err("ticket_seller_cap"), "a pool of 0 locks nothing");
    }

    #[test]
    fn the_book_is_the_fold_of_its_rows_and_refuses_a_row_that_is_not_one() {
        let mut b = Book::default();
        let s = session("s1", 8);
        b.apply(&s.row()).unwrap();
        let mut t = ticket(1, "s1", TState::Offered, 5.0);
        b.apply(&t.row()).unwrap();
        t.state = TState::Locked;
        t.cltv_until = 400;
        b.apply(&t.row()).unwrap();
        b.apply(&json!({"e": "cursor", "index": "17"})).unwrap();
        b.apply(&json!({"e": "start", "ts": 9.5})).unwrap();
        assert_eq!((b.tickets[&t.hash].clone(), b.sessions["s1"].clone(), b.cursor, b.started), (t.clone(), s, 17, 9.5));
        for bad in [json!({"e": "ticket", "hash": "zz"}), json!({"e": "nope"}), json!({}), json!({"e": "cursor", "index": -1}),
                    json!({"e": "session", "id": "x"}), with_field(&t.row(), "state", json!("spent")), with_field(&t.row(), "booked_sats", json!(-1)),
                    with_field(&t.row(), "msat", json!("1e6")), with_field(&t.row(), "nonce", json!("00"))] {
            assert_eq!(b.apply(&bad).unwrap_err().code, "log", "{bad}");
        }
        // a snapshot rebuilds the same book, without what ended long ago
        let mut done = ticket(2, "s1", TState::Failed, 6.0);
        done.done_ts = 50.0;
        b.apply(&done.row()).unwrap();
        let mut again = Book::default();
        for r in b.snapshot(0.0) {
            again.apply(&r).unwrap();
        }
        assert_eq!((again.tickets.len(), again.sessions.len(), again.cursor, again.started), (2, 1, 17, 9.5));
        assert_eq!(again.tickets, b.tickets);
        let kept: Vec<Value> = b.snapshot(60.0);
        assert!(!kept.iter().any(|r| r["hash"] == done.hash) && kept.iter().any(|r| r["hash"] == t.hash), "a live ticket is never dropped");
        b.apply(&json!({"e": "drop", "tickets": [done.hash], "sessions": []})).unwrap();
        assert!(!b.tickets.contains_key(&done.hash));
    }

    fn with_field(row: &Value, k: &str, v: Value) -> Value {
        let mut r = row.clone();
        r[k] = v;
        r
    }

    #[test]
    fn the_pool_refills_when_half_or_fewer_are_left_and_counts_hashes_on_their_way() {
        // the shipped pool of 2: the next is locked when one is left
        let mut b = Book::default();
        let two = session("s2", 2);
        b.sessions.insert(two.id.clone(), two.clone());
        assert_eq!(b.want(&two, 100.0), 2, "an empty pool wants all of it");
        for i in 0..2 {
            let t = ticket(100 + i, "s2", TState::Locked, 100.0);
            b.tickets.insert(t.hash.clone(), t);
        }
        assert_eq!(b.want(&two, 101.0), 0);
        b.tickets.get_mut(&hex::encode([100u8; 32])).unwrap().state = TState::Released;
        assert_eq!(b.want(&two, 101.0), 1, "1 of 2 left: the next is locked now");
        // a pool of 1 (many sellers): locked again when it is spent
        let one = session("s1x", 1);
        assert_eq!(b.want(&one, 101.0), 1);
        let mut t = ticket(120, "s1x", TState::Locked, 100.0);
        b.tickets.insert(t.hash.clone(), t.clone());
        assert_eq!(b.want(&one, 101.0), 0);
        t.state = TState::Released;
        b.tickets.insert(t.hash.clone(), t);
        assert_eq!(b.want(&one, 101.0), 1);
        // a prepaid ticket is not a held one: it fills no place in a pool
        let mut pre = ticket(121, "s1x", TState::Released, 100.0);
        pre.prepaid = true;
        b.tickets.insert(pre.hash.clone(), pre.clone());
        assert_eq!(b.want(&one, 101.0), 1);
        assert_eq!(b.prepaid_pending("s1x").map(|t| t.hash.clone()), Some(pre.hash.clone()));
        assert_eq!(b.prepaid_pending("s2"), None);
        assert_eq!(Ticket::from_row(&pre.row()), Some(pre.clone()));
        assert!(ticket(1, "s", TState::Locked, 1.0).row().get("prepaid").is_none(), "a held ticket's row is as it was");
        assert_eq!(b.locked(|t| t.session == "s1x"), Locked::default(), "nor is it counted as locked");
        // a larger pool, an owner's choice
        let mut b = Book::default();
        let s = session("s1", 8);
        b.sessions.insert(s.id.clone(), s.clone());
        assert_eq!(b.want(&s, 100.0), 8, "an empty pool wants all of it");
        for i in 0..8 {
            let t = ticket(i, "s1", TState::Offered, 100.0);
            b.tickets.insert(t.hash.clone(), t);
        }
        assert_eq!(b.want(&s, 101.0), 0, "8 hashes are with the seller");
        assert_eq!(b.want(&s, 100.0 + OFFER_TTL_S + 1.0), 8, "offers that lapsed are offered again");
        for t in b.tickets.values_mut() {
            t.state = TState::Locked;
        }
        assert_eq!(b.want(&s, 101.0), 0);
        let hashes: Vec<String> = b.of_session("s1").iter().map(|t| t.hash.clone()).collect();
        for h in &hashes[..3] {
            b.tickets.get_mut(h).unwrap().state = TState::Released;
        }
        assert_eq!(b.want(&s, 101.0), 0, "5 of 8 left: above the mark");
        b.tickets.get_mut(&hashes[3]).unwrap().state = TState::Released;
        assert_eq!(b.want(&s, 101.0), 4, "4 left, half: back to 8");
        b.tickets.get_mut(&hashes[4]).unwrap().state = TState::Released;
        assert_eq!(b.locked(|_| true), Locked { tickets: 3, sats: 3_000, booking: 3 * 1015 });
        assert_eq!(b.locked(|t| t.session == "other"), Locked::default());
        assert_eq!(b.want(&session("s2", 1), 101.0), 1);
        assert_eq!((b.pools_open(), b.pools_open_in(Some("t")), b.pools_open_in(Some("other"))), (8, 8, 0));
        // tickets on their way that the node does not show yet take a slot each when they arrive
        b.tickets.get_mut(&hashes[5]).unwrap().state = TState::Sending;
        b.tickets.get_mut(&hashes[6]).unwrap().state = TState::Sending;
        assert_eq!((b.sending_unseen(&|_| false), b.sending_unseen(&|h| h == hashes[5])), (2, 1));
        let full = Locked { tickets: i64::MAX, sats: i64::MAX, booking: i64::MAX };
        assert_eq!(full.plus(5, i64::MAX, i64::MAX), full, "a sum that does not fit is the largest, never a small one");
    }

    #[test]
    fn a_release_takes_the_oldest_ticket_the_seller_will_still_accept() {
        let mut b = Book::default();
        let (mut old, mut new, mut blind) = (ticket(1, "s1", TState::Locked, 1.0), ticket(2, "s1", TState::Locked, 2.0), ticket(3, "s1", TState::Locked, 0.5));
        old.final_expiry = 125;
        new.final_expiry = 140;
        blind.final_expiry = 0;
        for t in [&old, &new, &blind] {
            b.tickets.insert(t.hash.clone(), t.clone());
        }
        assert_eq!(b.usable("s1", 99).map(|t| t.hash.clone()), Some(old.hash.clone()), "26 blocks left");
        assert_eq!(b.usable("s1", 100).map(|t| t.hash.clone()), Some(new.hash.clone()), "25 left: the seller would refuse it");
        assert_eq!(b.stale("s1", 100), vec![blind.hash.clone(), old.hash.clone()]);
        assert_eq!(b.usable("s1", 115), None);
        assert_eq!(b.usable("s1", 0), None, "our own tip unknown: nothing is released");
        assert_eq!(b.usable("s2", 99), None);
    }

    #[test]
    fn a_task_name_is_what_a_memo_can_carry() {
        assert_eq!(memo_task(&memo("inference-1", "")), Some("inference-1"));
        let m = memo("inference-1", "aB3_-x");
        assert_eq!((memo_task(&m), memo_session(&m)), (Some("inference-1"), Some("aB3_-x")));
        assert_eq!(memo_session(&memo("t", "no spaces")), None, "a session name that would need escaping is not written");
        assert_eq!(memo_session("ticket task=t session=a b"), None);
        for bad in ["", "Has Space", "UPPER", "a=b", &"x".repeat(33)] {
            assert!(!task_name_ok(bad), "{bad}");
        }
        assert_eq!(memo_task("ticket task=a b"), None);
        assert_eq!(memo_task("ln abc"), None);
        assert_eq!(ledger_id("ab"), "ticket:ab");
    }
}
