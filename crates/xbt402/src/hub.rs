//! The xbt402 routing hub (a port of B1 `xbt402/hub.py`, AGP-021/023): one client → hub channel
//! pays many providers through hub-funded hub → provider channels, with adaptor-locked states on
//! both hops.
//!
//! **Experimental:** not production-ready; do not route funds you cannot lose. `xbt402-hub` says
//! so when it starts.
//!
//! ```text
//! client --ch1 (client pays, hub is payee)--> hub --ch2 (hub pays, provider is payee)--> provider
//! ```
//!
//! The hub is two things at once:
//! * a payee on every ch1: an embedded [`Provider`] serves ch1's open/close/facilitator
//!   endpoints, keeps ch1's states in its ledger and closes ch1 at its margin;
//! * a payer on every ch2: [`OutBook`] holds each ch2's key, its highest plain state, the routed
//!   total and the one pending lock. The hub funds ch2 from its own wallet, so a small provider
//!   never opens a channel, and rolls ch2 over at the provider's settle threshold.
//!
//! `POST /x402/route` (a PAYMENT-SIGNATURE on ch1; the JSON body carries the route) runs its checks
//! in this order, and pre-signs nothing on ch2 until all of them pass:
//!
//! | # | check | error |
//! |---|---|---|
//! | 1 | auth: ch1's request HMAC and a fresh seq | `bad_auth` (401) |
//! | 2 | point: T1 = T + r·G | `bad_point` |
//! | 3 | amount: cum = next_cum(routed1, d + f), d ≤ maxLockSat | `bad_amount` |
//! | 4 | pre-verify the ch1 pre-signature under T1 against the exact state tx | `bad_adaptor` |
//! | 5 | fee: a live fee quote this hub signed, f ≥ the carried fee | `route_fee` |
//! | 6 | expiry: route_ok(tip, expiry1, expiry2) or d ≤ maxUnguardedLockSat | `route_expiry` (and `route_blocked` / `bad_invoice`) |
//! | 7 | one lock: none pending on ch1, none on ch2 | `lock_outstanding` |
//!
//! After them (AGP-088): a lock that a ch2 would take under a lockId ch1 still holds written off
//! is refused `lock_held`, with the hub's view of ch1. `POST /x402/route/view` (the same
//! PAYMENT-SIGNATURE, an empty body) answers that view alone.
//!
//! Then it writes the ch1 lock to disk, pre-signs ch2 under T, writes that, sends it to the
//! provider, checks t·G = T, completes ch1 with t + r and answers the client with t + r.
//!
//! The watcher ([`RouteHub::watch_tick`]) opens hub-funded ch2s once confirmed; retries a pending
//! ch2 lock until `revealTimeoutSec`, then writes it off and stops routing to that provider; reads
//! t off any ch2 close that spends a funding with a pending or written-off lock and completes the
//! ch1 lock with t + r; rolls ch2 over once the provider's net payout reaches its settleMultiple ×
//! closeFee or ch2 nears expiry (never while a lock is pending); and closes ch1s at their margin.
//!
//! Money safety (AGP-037, as B1): a ch2's key and params are on disk (state `funding`) before the
//! wallet funds it, and a rollover's next ch2 (`next`) before the rollover request leaves; every
//! non-final ch2 (funded, open, refunded, closing, closed but unconfirmed) is reconciled against the
//! chain each tick (a spent funding is read and its locks' secrets recovered; a provider's close in
//! the mempool makes the ch2 `closing`, a confirmed one `closed` with the real spender (AGP-045); the
//! hub's refund is final once confirmed and rebroadcast while it is not; a provider close that beats
//! it reverts its fee once it confirms, and a mempool close that vanishes restores the refund, fee
//! booked); a `funding` record whose wallet call failed is looked for in the wallet
//! (`gettransaction`), the mempool (`gettxout` incl. the mempool, `getmempoolentry`) and the UTXO set
//! (`scantxoutset`), dropped only when none shows it, and a dropped one whose send the wallet still
//! knows is watched and refunded at expiry if it confirms late (AGP-045); refunds go out at expiry (unsigned) or expiry +
//! `refund_grace_blocks` (signed) at a hub-chosen fee; `close_ch2` checks the provider's reply
//! against the ledger; a provider's /terms are bounded before anything is funded; refills go through
//! the refill hook (default: [`RouteHub::connect`]).
//!
//! Close fees (v1.2): ch2 is payee-pays by default (each provider pays its own settlement), ch1
//! payer-pays (the client), and `extra.routing` advertises both.
//!
//! Make-before-break rollover (AGP-053, as B1): the next ch2 is opened right after the rollover reply,
//! unconfirmed, where the provider takes it (`zeroConf` in its /open reply: the child of its own
//! confirmed hub-bound channel, up to `maxCum` and before `until`), so routing never pauses for a block;
//! the hub keeps within those bounds itself, never rolls an unconfirmed child over, and blocks or drops
//! a child whose rollover left the mempool or was replaced.
//!
//! ch2 identity (AGP-056, as B1; it replaces AGP-044's one live ch2 per payTo): a ch2 belongs to one
//! provider PROCESS, the origin it was funded at, because that process's ledger is the only one that
//! holds the channel and its route sessions. An operator may run several provider processes on one
//! payTo key (cmp merchants): each gets its own ch2, and a lock is forwarded to the origin the client
//! named, on that origin's ch2. One key takes at most `ch2_max_per_pay_to` live ch2s.
//!
//! Settle floor (AGP-056): with locks larger than the provider's threshold every lock rolled the ch2
//! over. A due rollover waits until the ch2 has taken `settle_lock_multiple` × the largest lock
//! routed to that provider, never past the point where another lock of that size would not fit, and
//! not at all once the ch2 has had no lock for `settle_idle` seconds. A rollover child that could
//! not take one more such lock is not made: the ch2 is closed and refilled.
//!
//! Rollover relay (AGP-056): the provider broadcasts the rollover on ITS node. A hub on another node
//! sees it only after P2P relay, so the child is blocked as vanished only if the hub's node showed
//! the rollover before, or still does not `rollover_relay_grace` seconds after it.
//!
//! Make-before-break refill (AGP-057, as B1): a rollover adds no coins, so a ch2 line carries its
//! capacity in locks and is then closed and replaced by a ch2 funded from the wallet, which opens only
//! at minConf (the provider cannot take a wallet funding unconfirmed: its payer could spend it again).
//! The hub therefore funds the origin's NEXT ch2 ahead: once the live ch2's room is under
//! `refill_ahead_locks` × the largest lock routed to that provider ([`OutBook::next_chans`], at most
//! one per origin, counted by `liquidity_cap_sat` with the live one). The live ch2 keeps taking locks,
//! rollovers included; the next one takes over (`ch2_switch`) with the first lock the live one cannot
//! take (exhausted, closed, or an unconfirmed rollover child at the provider's bounds), when the live
//! one is closed as too small to roll over (not before the next one is open, while the live one still
//! takes a lock), or once the live one has had no lock for `settle_idle` seconds. The replaced ch2 is `retired`: the watcher asks the provider to close it and reconciles
//! it like any archived ch2.
//!
//! The zero-conf cap and the watcher (AGP-057): the hub's `confirmed` flag of a rollover child is the
//! watcher's last look. Before a lock is refused on the provider's bounds the hub looks at the chain
//! itself, so a child that confirmed since the last tick is never refused.
//!
//! Lock order: the ch1 ledger may be held while the out book is taken, never the reverse; a
//! provider's busy flag is taken with a timeout (route) or not at all (watcher).
//!
//! What the chain decides, never a provider's answer (AGP-088):
//! * a ch1 lock is the lock of one ch2 (`ch2`, [`is_lock`]): a `t` read off that ch2 completes it,
//!   that ch2's confirmed refund or close without `t` releases it, and nothing else moves it;
//! * "confirmed" is a spend `spend_final_depth` blocks deep ([`RouteHub::spend_depth`], AGP-094),
//!   not `gettxout` answering nothing, and not one block that a reorg can replace;
//! * a ch2 leaves the watcher (`final`) only on a spend in a block: one rolled over on the
//!   provider's 200 is watched, and refunded at its expiry, until that rollover is in a block;
//! * a refill is funded when this node shows the funding spent, and a ch2 counts against
//!   `liquidity_cap_sat` until then ([`committed`]).
//!
//! Returns (AGP-104). Rule R1: no coin of the hub's rests on a key only its state files know.
//! With a return address set ([`RouteHub::set_return_to`]; `xbt402-hub` sets its wallet's):
//! * every ch2 the hub funds, and every rollover's next ch2, names a return address as its
//!   `payerSpk`, so a provider's close pays the hub's remainder there and a refund does too;
//! * a closed ch1's payout, which a close pays to that channel's own payee key, is swept there;
//! * a ch2 from a ledger written before this (its `payerSpk` is its own payer key) is refunded
//!   there, and what a provider's close left on that key is swept there.
//!
//! Rule R2: one signed sweep per output. A sweep is written to the ledger before it is sent, the
//! same bytes are sent again each tick until the chain has them, and it is never signed again at
//! another fee or to another address. Nothing is swept before the spend it depends on is
//! `spend_final_depth` blocks deep, and a sweep is `final` only at that depth itself.
//!
//! Status (AGP-104): [`RouteHub::status`] is where the hub's coins are, in four numbers that add
//! up to what was sent in, plus the fees earned, less what the chain cost.
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use indexmap::IndexMap;
use serde_json::{json, Map, Value};
use xbt_primitives::address::{address_to_spk, segwit_address};
use xbt_primitives::ecdsa;
use xbt_primitives::script::p2wpkh_spk;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::sighash::SIGHASH_ALL_UNIFIED;
use xbt_primitives::tx::{OutPoint, Tx, TxIn, TxOut};

use crate::adaptor::{self, PreSig, Sc};
use crate::channel::{canonical_chan, channel_auth_key, settle_due, sign_p2wpkh, sign_with_type, ChannelParams, FeePayer, DUST, RBF_SEQUENCE};
use crate::client::{Transport, Wallet, WalletSend};
use crate::error::{fail, ChannelError, Result};
use crate::funding::{ChainBackend, FundingPolicy};
use crate::hub_keys::{WrapKey, WRAP_KEY_FILE};
use crate::json::{dumps, py_int, py_str, py_u64, truthy};
use crate::ledger::{ChannelState, Ledger};
use crate::provider::{HttpResponse, Provider, ProviderConfig};
use crate::route::*;
use crate::wire::*;

fn lk<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// ch1's routing counters, the base every lock is quoted on: `routed_sat`, `fee_units`, `fee_paid`.
const COUNTERS: [&str; 3] = ["routed_sat", "fee_units", "fee_paid"];
/// The same counters in a lock's `after` and a hold's `hold`.
const LOCK_COUNTERS: [&str; 3] = ["routed", "units", "paid"];

/// What a lock adds to ch1's counters by itself (AGP-085): `d + f`, its fee units and `f`. None for
/// a lock written before it recorded `unitsBy`.
fn lock_deltas(lock: &Value) -> Option<[u128; 3]> {
    let by = u128_of(lock.get("unitsBy"))?;
    let (d, f) = (py_u64(lock.get("d")).unwrap_or(0) as u128, py_u64(lock.get("f")).unwrap_or(0) as u128);
    Some([d + f, by, f])
}

/// The ch2 a ch1 lock went over, as the lock records it (`ch2`): that ch2's payer key, which a
/// ch2 keeps from its funding to its end and shares with no other.
fn ch2_key(oc: &OutChannel) -> String {
    hex::encode(oc.params.payer_pub)
}

/// AGP-088 rule: a lock on ch1 is the lock of ONE ch2, and only that ch2's fate moves it. It
/// leaves ch1 when a `t` read off that ch2 completes it, or when that ch2 resolves without paying
/// it. So it is found by its lockId AND the ch2 it went over, never by the lockId alone: the
/// lockId is the provider's choice, and two providers (or one provider on two ch2s) can name the
/// same one.
///
/// AGP-094: a lock written before it recorded `ch2` was matched by its provider's origin alone,
/// and one origin can have two ch2s, so two such locks under one lockId were released together by
/// the first ch2 to close. Such a lock is given its `ch2` by [`RouteHub::name_legacy_locks`] at
/// the start and on every tick. Until then (and for one no ch2 record holds any more) it is the
/// lock of a ch2 of its origin that itself holds a lock with that lockId and that point.
fn is_lock(lock: &Value, lock_id: &str, ch2: &OutChannel) -> bool {
    if lock.get("lockId").and_then(Value::as_str) != Some(lock_id) {
        return false;
    }
    match lock.get("ch2").and_then(Value::as_str) {
        Some(k) => k == ch2_key(ch2),
        None => {
            let t = py_str(lock.get("T"));
            let has = |e: &Value| e.get("lockId").and_then(Value::as_str) == Some(lock_id) && py_str(e.get("T")).eq_ignore_ascii_case(&t);
            py_str(lock.get("provider")) == ch2.origin && (ch2.stale.iter().any(has) || (!ch2.pending.is_empty() && has(&Value::Object(ch2.pending.clone()))))
        }
    }
}

/// A ch2 record's lock (`pending`, or one of `stale`) is the lock `lock_id` of `ch1`.
fn is_ch2_lock(lock: &Value, ch1: &str, lock_id: &str) -> bool {
    lock.get("lockId").and_then(Value::as_str) == Some(lock_id) && py_str(lock.get("ch1")) == ch1
}

/// AGP-064 (H2): a lock written off after its ch2 pre-signature left stays in ch1's base until that
/// ch2 resolves. Add what the lock itself adds and record it on the lock (`hold`), so a release
/// takes back exactly that, whatever came after. AGP-085: never the distance to the lock's `after`,
/// which was fixed at admission: a hold released while the lock was in flight would be held again.
/// (A lock from before `unitsBy` is raised to its `after`, as it was.) AGP-088: its lockId leaves
/// ch1's `released` list, which a client reads by lockId: a lock held now is not a released one.
fn hold_in_base(ex: &mut Map<String, Value>, lock: &mut Value) {
    if let (Some(rel), Some(id)) = (ex.get_mut("released").and_then(Value::as_array_mut), lock.get("lockId")) {
        rel.retain(|x| x != id);
    }
    let mut hold = Map::new();
    let by = lock_deltas(lock);
    for (i, (k, a)) in COUNTERS.iter().zip(LOCK_COUNTERS).enumerate() {
        let cur = u128_of(ex.get(*k)).unwrap_or(0);
        let to = match by {
            Some(by) => cur + by[i],
            None => cur.max(u128_of(lock.get("after").and_then(|x| x.get(a))).unwrap_or(0)),
        };
        ex.insert((*k).into(), int_value(to));
        hold.insert(a.into(), int_value(to - cur));
    }
    lock["hold"] = Value::Object(hold);
}

/// The lockIds of ch1's written-off locks that are held in its base.
fn held_ids(ex: &Map<String, Value>) -> Vec<Value> {
    ex.get("stale_locks").and_then(Value::as_array).into_iter().flatten()
        .filter(|s| s.get("hold").is_some_and(Value::is_object)).filter_map(|s| s.get("lockId").cloned()).collect()
}

/// ch1 as the hub counts it, for a client to resync on (`expectCum` is added where a lock was
/// refused for its amount): the held locks, and the last ones released (AGP-064). AGP-088:
/// `secret` is the t + r that completed the lock at `bestCum`, when a lock set it: the proof a
/// client asks for before it counts a lock it gave up as paid (only its completion yields it).
fn ch1_view(st1: &ChannelState) -> Value {
    let ex = &st1.extra;
    let mut v = json!({"bestCum": st1.best_cum, "routedSat": py_u64(ex.get("routed_sat")).unwrap_or(0),
                       "feeUnits": int_value(u128_of(ex.get("fee_units")).unwrap_or(0)), "feePaid": py_u64(ex.get("fee_paid")).unwrap_or(0),
                       "held": held_ids(ex), "released": ex.get("released").cloned().unwrap_or_else(|| json!([]))});
    if let Some(b) = ex.get("best_lock").filter(|b| py_u64(b.get("cum")) == Some(st1.best_cum)) {
        v["secret"] = b.get("secret").cloned().unwrap_or(Value::Null);
    }
    // AGP-094: the written-off locks completed since off a ch2 close, the last 16, each with the
    // t + r that completed it. One completed below ch1's best state is in no other list (it is
    // not held any more, was not released, and is not the best state): without this a client
    // that adopted its hold counted it as held for the life of ch1
    let done: Vec<Value> = ex.get("recovered").and_then(Value::as_array).map(|r| r.iter().rev().take(VIEW_COMPLETED).rev()
        .map(|x| json!({"lockId": x.get("lockId"), "secret": x.get("secret")})).collect()).unwrap_or_default();
    v["completed"] = done.into();
    v
}

/// How many completed written-off locks a view of ch1 lists (the newest).
const VIEW_COMPLETED: usize = 16;

/// Everything a hub operator decides (JSON: [`HubConfig::from_json`]); nothing here is protocol.
///
/// `fee_strategy`: `{"kind": "flat"}` charges `fee_base_msat` + `fee_ppm`; `{"kind":
/// "utilization", "ppm_min", "ppm_max", "base_msat"?}` scales feePpm with the share of
/// `liquidity_cap_sat` already committed to ch2s (a library user may set any callable with
/// [`RouteHub::set_fee_strategy`]). `liquidity_cap_sat` bounds the hub's own coins in live ch2s
/// (0: no cap); rollovers reuse a channel's coins. `ch2_close_fee_payer`: `payee` (default, v1.2:
/// the hub opens ch2s only to providers whose /terms offer payee-pays) or `payer` (the hub pays
/// ch2 closes, v1.1 providers). `ch1_close_fee_payer`: ch1's terms (default `payer`).
#[derive(Debug, Clone, PartialEq)]
pub struct HubConfig {
    pub fee_base_msat: u64,
    pub fee_ppm: u64,
    pub fee_strategy: Value,
    pub quote_ttl: i64,
    pub max_lock_sat: u64,
    pub max_unguarded_lock_sat: u64,
    pub delta: u32,
    /// Seconds.
    pub reveal_timeout: f64,
    pub ch2_capacity: u64,
    pub ch2_expiry_blocks: u32,
    pub liquidity_cap_sat: u64,
    /// ch1 terms (the hub is ch1's payee).
    pub close_fee: u64,
    pub ch1_close_fee_payer: FeePayer,
    pub ch2_close_fee_payer: FeePayer,
    pub close_margin: u32,
    pub rollover_margin: u32,
    pub hrp: String,
    /// `{"min_expiry_blocks", "max_expiry_blocks", ...}`: ch1's funding policy (FundingPolicy fields).
    pub policy: Value,
    /// Bounds on a provider's /terms before the hub funds a ch2 (AGP-037); refused `bad_terms`.
    /// minExpiryBlocks + minConf + closeMarginBlocks must fit, and the expiry is clamped to it (0: 2 × `ch2_expiry_blocks`).
    pub ch2_max_expiry_blocks: u32,
    pub ch2_max_close_fee_sat: u64,
    /// `ch2_close_fee_multiple` × closeFeeSat ≤ capacity.
    pub ch2_close_fee_multiple: u64,
    pub ch2_max_min_conf: u64,
    /// 0: `ch2_capacity`.
    pub ch2_max_min_capacity: u64,
    pub ch2_max_settle_multiple: u64,
    /// A signed ch2 is refunded this many blocks past expiry (an unsigned one at expiry).
    pub refund_grace_blocks: u32,
    pub refund_conf_target: u32,
    /// sat/vB floor of the refund fee (estimatesmartfee × vsize above it).
    pub refund_min_feerate: f64,
    /// A `funding` record the chain never shows is dropped after this many blocks (key kept).
    pub funding_timeout_blocks: u32,
    /// A hub refund still unconfirmed this many blocks after it went out is re-signed at a higher
    /// fee and replaces itself (RBF, AGP-044); 0: never bump.
    pub refund_bump_blocks: u32,
    /// The most a ch2 refund may pay in fees, bumps included (and always dust left over).
    pub refund_max_fee_sat: u64,
    /// AGP-053 (default on): open a rollover's next ch2 at once, unconfirmed, where the provider takes it
    /// (its /open reply carries `zeroConf`), so routing to the provider never pauses for a block
    /// (make-before-break); a provider that refuses is opened at minConf.
    pub zero_conf_rollover: bool,
    /// AGP-056: the live ch2s one payTo key may hold over its origins (provider processes); the next
    /// `connect` is refused `pay_to_limit`. 0: no bound.
    pub ch2_max_per_pay_to: u64,
    /// AGP-056 (k): a due rollover waits until the ch2 has taken k × the largest lock routed to that
    /// provider (0: roll over at the provider's threshold). k = 4: at most one rollover per four of
    /// the largest locks, and with the usual capacity of five such locks (100k / 20k, 200k / 40k) it
    /// is the largest k that still leaves room for one more lock when the rollover is due.
    pub settle_lock_multiple: u64,
    /// Seconds without a lock after which a due ch2 rolls over at the provider's threshold.
    pub settle_idle: f64,
    /// AGP-056: seconds a rollover the hub's own node has not shown yet is given to arrive over P2P
    /// (the provider broadcasts it on its node) before its ch2 is blocked as vanished.
    pub rollover_relay_grace: f64,
    /// AGP-057 (N): fund an origin's next ch2 while the live one still has room, once that room is
    /// under N × the largest lock routed to the provider (0: never; the ch2 is closed and then
    /// refilled, and routing to the provider waits for the refill's minConf). N locks must cover what
    /// the provider is paid while a funding confirms and opens: about the locks of one block interval
    /// plus one watcher tick. The live and the next ch2 both count against `liquidity_cap_sat`, so a
    /// hub that should never pause needs room for one more `ch2_capacity` than it has origins; without
    /// it nothing is funded ahead (`ch2_refill_ahead_failed`) and the refill follows the close.
    pub refill_ahead_locks: u64,
    /// AGP-094: how many blocks deep a spend of a ch2's funding must be before it is "spent for
    /// good": the locks it did not pay leave ch1, and the record leaves the watcher. At least 1.
    /// The default is 6. A hold released on a close one block deep was lost when that block was
    /// replaced by one carrying the provider's other close, the one with `t`, so the depth is what
    /// a provider must be unable to replace: six blocks is the depth this hub already asks before
    /// it trusts a funding (`ch2_max_min_conf`), and waiting costs only time (a hold is at most
    /// one lock, and it is the client's own coins that wait).
    pub spend_final_depth: u32,
    /// AGP-104: the operator's one number (0: unset). It is the liquidity cap (set it or
    /// `liquidity_cap_sat`, not two different values), and with funding ahead on
    /// (`refill_ahead_locks` > 0) a seller is admitted only while its ch2 and one spare
    /// `ch2_capacity` fit under it, so one seller's next ch2 can always be funded ahead.
    pub capital_sat: u64,
}

impl Default for HubConfig {
    fn default() -> Self {
        Self { fee_base_msat: 1_000, fee_ppm: 2_000, fee_strategy: json!({"kind": "flat"}), quote_ttl: 600, max_lock_sat: 20_000,
               max_unguarded_lock_sat: 500, delta: 144, reveal_timeout: 10.0, ch2_capacity: 100_000, ch2_expiry_blocks: 1_153,
               liquidity_cap_sat: 0, close_fee: 600, ch1_close_fee_payer: FeePayer::Payer, ch2_close_fee_payer: FeePayer::Payee,
               close_margin: 144, rollover_margin: 36, hrp: "bcrt".into(), policy: json!({"min_expiry_blocks": 1_008, "max_expiry_blocks": 8_640}),
               ch2_max_expiry_blocks: 0, ch2_max_close_fee_sat: 5_000, ch2_close_fee_multiple: 20, ch2_max_min_conf: 6, ch2_max_min_capacity: 0,
               ch2_max_settle_multiple: 100, refund_grace_blocks: 6, refund_conf_target: 6, refund_min_feerate: 1.0, funding_timeout_blocks: 6,
               refund_bump_blocks: 3, refund_max_fee_sat: 5_000, zero_conf_rollover: true, ch2_max_per_pay_to: 8, settle_lock_multiple: 4,
               settle_idle: 600.0, rollover_relay_grace: 60.0, refill_ahead_locks: 4, spend_final_depth: 6, capital_sat: 0 }
    }
}

const HUB_KEYS: [&str; 39] = ["fee_base_msat", "fee_ppm", "fee_strategy", "quote_ttl", "max_lock_sat", "max_unguarded_lock_sat", "delta",
                              "reveal_timeout", "ch2_capacity", "ch2_expiry_blocks", "liquidity_cap_sat", "close_fee",
                              "ch1_close_fee_payer", "ch2_close_fee_payer", "close_margin", "rollover_margin", "hrp", "policy", "_comment",
                              "ch2_max_expiry_blocks", "ch2_max_close_fee_sat", "ch2_close_fee_multiple", "ch2_max_min_conf",
                              "ch2_max_min_capacity", "ch2_max_settle_multiple", "refund_grace_blocks", "refund_conf_target",
                              "refund_min_feerate", "funding_timeout_blocks", "refund_bump_blocks", "refund_max_fee_sat",
                              "zero_conf_rollover", "ch2_max_per_pay_to", "settle_lock_multiple", "settle_idle", "rollover_relay_grace",
                              "refill_ahead_locks", "spend_final_depth", "capital_sat"];

impl HubConfig {
    /// From the operator's JSON (B1 `HubConfig.from_dict`): unknown keys are refused.
    pub fn from_json(d: &Value) -> Result<Self> {
        let bad = |m: String| ChannelError::new("bad_config", m);
        let m = d.as_object().ok_or_else(|| bad("hub config must be an object".into()))?;
        let unknown: Vec<&String> = m.keys().filter(|k| !HUB_KEYS.contains(&k.as_str())).collect();
        if !unknown.is_empty() {
            return Err(bad(format!("unknown hub config keys: {unknown:?}")));
        }
        let mut c = Self::default();
        let u = |k: &str, dflt: u64| -> Result<u64> {
            match m.get(k) {
                None => Ok(dflt),
                Some(v) => py_u64(Some(v)).ok_or_else(|| bad(format!("{k} must be a non-negative integer"))),
            }
        };
        let u32_ = |k: &str, dflt: u32| -> Result<u32> { u32::try_from(u(k, dflt as u64)?).map_err(|_| bad(format!("{k} out of range"))) };
        c.fee_base_msat = u("fee_base_msat", c.fee_base_msat)?;
        c.fee_ppm = u("fee_ppm", c.fee_ppm)?;
        if let Some(s) = m.get("fee_strategy") {
            c.fee_strategy = s.clone();
        }
        c.quote_ttl = u("quote_ttl", c.quote_ttl as u64)? as i64;
        c.max_lock_sat = u("max_lock_sat", c.max_lock_sat)?;
        c.max_unguarded_lock_sat = u("max_unguarded_lock_sat", c.max_unguarded_lock_sat)?;
        c.delta = u32_("delta", c.delta)?;
        if let Some(v) = m.get("reveal_timeout") {
            c.reveal_timeout = v.as_f64().filter(|x| *x >= 0.0).ok_or_else(|| bad("reveal_timeout must be a number".into()))?;
        }
        c.ch2_capacity = u("ch2_capacity", c.ch2_capacity)?;
        c.ch2_expiry_blocks = u32_("ch2_expiry_blocks", c.ch2_expiry_blocks)?;
        c.liquidity_cap_sat = u("liquidity_cap_sat", c.liquidity_cap_sat)?;
        c.close_fee = u("close_fee", c.close_fee)?;
        let fp = |k: &str, d: FeePayer| -> Result<FeePayer> {
            match m.get(k) {
                None => Ok(d),
                Some(v) => FeePayer::parse(v.as_str().unwrap_or("")).map_err(|_| bad("ch1_close_fee_payer / ch2_close_fee_payer are payer or payee".into())),
            }
        };
        c.ch1_close_fee_payer = fp("ch1_close_fee_payer", c.ch1_close_fee_payer)?;
        c.ch2_close_fee_payer = fp("ch2_close_fee_payer", c.ch2_close_fee_payer)?;
        c.close_margin = u32_("close_margin", c.close_margin)?;
        c.rollover_margin = u32_("rollover_margin", c.rollover_margin)?;
        if let Some(h) = m.get("hrp") {
            c.hrp = h.as_str().ok_or_else(|| bad("hrp".into()))?.to_string();
        }
        if let Some(p) = m.get("policy") {
            if !p.is_object() {
                return Err(bad("policy must be an object".into()));
            }
            c.policy = p.clone();
        }
        c.ch2_max_expiry_blocks = u32_("ch2_max_expiry_blocks", c.ch2_max_expiry_blocks)?;
        c.ch2_max_close_fee_sat = u("ch2_max_close_fee_sat", c.ch2_max_close_fee_sat)?;
        c.ch2_close_fee_multiple = u("ch2_close_fee_multiple", c.ch2_close_fee_multiple)?;
        c.ch2_max_min_conf = u("ch2_max_min_conf", c.ch2_max_min_conf)?;
        c.ch2_max_min_capacity = u("ch2_max_min_capacity", c.ch2_max_min_capacity)?;
        c.ch2_max_settle_multiple = u("ch2_max_settle_multiple", c.ch2_max_settle_multiple)?;
        c.refund_grace_blocks = u32_("refund_grace_blocks", c.refund_grace_blocks)?;
        c.refund_conf_target = u32_("refund_conf_target", c.refund_conf_target)?;
        if let Some(v) = m.get("refund_min_feerate") {
            c.refund_min_feerate = v.as_f64().filter(|x| *x >= 0.0).ok_or_else(|| bad("refund_min_feerate must be a number".into()))?;
        }
        c.funding_timeout_blocks = u32_("funding_timeout_blocks", c.funding_timeout_blocks)?;
        c.refund_bump_blocks = u32_("refund_bump_blocks", c.refund_bump_blocks)?;
        c.refund_max_fee_sat = u("refund_max_fee_sat", c.refund_max_fee_sat)?;
        if let Some(v) = m.get("zero_conf_rollover") {
            c.zero_conf_rollover = v.as_bool().ok_or_else(|| bad("zero_conf_rollover must be true or false".into()))?;
        }
        c.ch2_max_per_pay_to = u("ch2_max_per_pay_to", c.ch2_max_per_pay_to)?;
        c.settle_lock_multiple = u("settle_lock_multiple", c.settle_lock_multiple)?;
        c.refill_ahead_locks = u("refill_ahead_locks", c.refill_ahead_locks)?;
        c.spend_final_depth = u32_("spend_final_depth", c.spend_final_depth)?;
        c.capital_sat = u("capital_sat", c.capital_sat)?;
        for (k, slot) in [("settle_idle", &mut c.settle_idle), ("rollover_relay_grace", &mut c.rollover_relay_grace)] {
            if let Some(v) = m.get(k) {
                *slot = v.as_f64().filter(|x| *x >= 0.0).ok_or_else(|| bad(format!("{k} must be a number")))?;
            }
        }
        c.validate()?;
        Ok(c)
    }

    /// The bounds a config must keep however it was built: [`HubConfig::from_json`] and
    /// [`RouteHub::new`] both check them (AGP-078: a struct literal went around the first).
    pub fn validate(&self) -> Result<()> {
        self.funding_policy()?;
        // AGP-064: a written-off lock holds the client's base and blocks its ch2 until that ch2
        // resolves, so a lock is a small share of a ch2: at most half (the default is a fifth)
        if self.max_lock_sat == 0 || self.max_lock_sat.saturating_mul(2) > self.ch2_capacity {
            return fail("bad_config", format!("max_lock_sat {} must be at most half of ch2_capacity {}", self.max_lock_sat, self.ch2_capacity));
        }
        if self.spend_final_depth == 0 {
            // AGP-094: 0 would call a spend in the mempool final
            return fail("bad_config", "spend_final_depth must be at least 1");
        }
        if self.capital_sat > 0 {
            if self.liquidity_cap_sat > 0 && self.liquidity_cap_sat != self.capital_sat {
                return fail("bad_config", format!("capital_sat {} and liquidity_cap_sat {} differ: set one", self.capital_sat, self.liquidity_cap_sat));
            }
            let need = self.ch2_capacity.saturating_add(self.spare_sat());
            if self.capital_sat < need {
                return fail("bad_config", format!("capital_sat {} holds no seller: one ch2 ({}) and the spare for funding ahead ({}) need {need}",
                                                  self.capital_sat, self.ch2_capacity, self.spare_sat()));
            }
        }
        Ok(())
    }

    /// The hub's own coins in ch2s never pass this (0: no cap): `capital_sat`, else `liquidity_cap_sat`.
    pub fn liquidity_cap(&self) -> u64 {
        if self.capital_sat > 0 { self.capital_sat } else { self.liquidity_cap_sat }
    }

    /// AGP-104: the room `capital_sat` keeps free of first fundings, so a next ch2 can be funded
    /// ahead: one `ch2_capacity` (0 without `capital_sat`, or with funding ahead off).
    pub fn spare_sat(&self) -> u64 {
        if self.capital_sat > 0 && self.refill_ahead_locks > 0 { self.ch2_capacity } else { 0 }
    }

    /// ch1's funding policy: `close_margin` plus the `policy` overrides.
    pub fn funding_policy(&self) -> Result<FundingPolicy> {
        let mut p = FundingPolicy { close_margin: self.close_margin, ..FundingPolicy::default() };
        for (k, v) in self.policy.as_object().into_iter().flatten() {
            let n = py_u64(Some(v)).ok_or_else(|| ChannelError::new("bad_config", format!("policy.{k} must be an integer")))?;
            let n32 = u32::try_from(n).unwrap_or(u32::MAX);
            match k.as_str() {
                "min_capacity" => p.min_capacity = n,
                "max_capacity" => p.max_capacity = n,
                "min_expiry_blocks" => p.min_expiry_blocks = n32,
                "max_expiry_blocks" => p.max_expiry_blocks = n32,
                "close_margin" => p.close_margin = n32,
                "min_conf" => p.min_conf = n32,
                "zero_conf_max" => p.zero_conf_max = n,
                "large_capacity" => p.large_capacity = n,
                "large_min_conf" => p.large_min_conf = n32,
                other => return fail("bad_config", format!("unknown policy key {other:?}")),
            }
        }
        Ok(p)
    }
}

/// One hub → provider channel (ch2); the hub is the payer.
#[derive(Debug, Clone, PartialEq)]
pub struct OutChannel {
    pub origin: String,
    /// The provider operator's payTo (one key may serve many devices).
    pub pay_to: String,
    pub params: ChannelParams,
    /// Payer key (hex). Sealed on disk under the hub's wrap key (AGP-073 K1).
    pub secret: String,
    /// funding -> funded -> open -> closing -> closed | rolled | refunded; funding -> dropped.
    pub state: String,
    /// Highest cumulative state the provider can close with.
    pub signed: u64,
    /// Sum of completed routed amounts (the provider keeps the same total).
    pub routed: u64,
    pub seq: u64,
    /// The one lock: `{lockId, cum, pre, T, d, ch1, at, route}` (empty: none).
    pub pending: Map<String, Value>,
    /// Written-off locks, kept for on-chain recovery.
    pub stale: Vec<Value>,
    pub settle_multiple: u64,
    pub terms: Value,
    pub refund_hex: String,
    /// Why the hub stopped routing to this provider.
    pub blocked: String,
    pub close_txid: String,
    pub rolled_to: String,
    pub opened_at: u32,
    pub scanned_to: u32,
    /// The hub's broadcast refund (AGP-037).
    pub refund_txid: String,
    /// Its fee; 0 again if a provider close won instead.
    pub refund_fee: u64,
    /// The funding's spend is confirmed: nothing left to watch (JSON `final`).
    pub final_: bool,
    /// Write-ahead: the rollover's next ch2 (empty: none).
    pub next: Map<String, Value>,
    /// The wallet's fund call failed: reconciled against the chain.
    pub fund_error: String,
    /// The tip when the current refund version was signed (a bump is due `refund_bump_blocks` later).
    pub refund_at: u32,
    /// Earlier refund versions it replaced, `{txid, fee}`: any of them may still confirm.
    pub refund_prev: Vec<Value>,
    /// The state a `closing` ch2 left (AGP-045): `refunded` is restored if the close vanishes.
    pub close_prev: String,
    /// The funding send the hub knows of (the wallet's), watched while `dropped` (AGP-045).
    pub fund_txid: String,
    pub fund_vout: u32,
    /// The ch2 whose rollover funds this one (AGP-053).
    pub rolled_from: String,
    /// The provider took it unconfirmed (AGP-053): `{parent, maxCum, until, confirmed}` (empty: no).
    pub zero_conf: Map<String, Value>,
    /// The largest lock routed over this ch2 and the ones it was rolled from (AGP-056).
    pub max_lock: u64,
    /// When the last lock on it completed (the settle floor holds only while locks come).
    pub last_lock_at: f64,
    /// When the rollover that funds it was co-signed (AGP-056: relay grace).
    pub rolled_at: f64,
    /// The hub's node has shown that rollover (mempool or a block).
    pub fund_seen: bool,
    /// Replaced by the origin's next ch2 (AGP-057): the watcher has the provider close it.
    pub retired: bool,
    /// AGP-088: the watcher's last look at the unspent funding showed it in a block. With it,
    /// `gettxout` answering nothing later means spent in a block; without it, it may only mean
    /// that the funding (a rollover) is itself unconfirmed.
    pub fund_confirmed: bool,
    /// AGP-088: the hub's own node showed a spender of the funding at the watcher's last look. A
    /// `closing` ch2 without it is closing on the provider's word alone: its coins still count.
    pub spend_seen: bool,
    /// AGP-088: a close was asked for with a refill, and this node did not show the close yet:
    /// the refill follows when the watcher sees it.
    pub refill_owed: bool,
    /// AGP-094: the tip when the watcher first saw this funding spent in a block, for a scan that
    /// does not say how deep the spender is (0: not seen so, or the funding is unspent again).
    pub gone_at: u32,
    /// AGP-104: the sweep of what a close or refund left on this ch2's own payer key (a ch2 from
    /// before it named a return address): `{txid, hex, outpoint, value, fee, swept, dest_spk, at,
    /// gone_at, final, skipped}` (empty: none yet). See [`RouteHub::sweep_tick`].
    pub sweep: Map<String, Value>,
    /// AGP-104: what the spend of this ch2's funding paid its `payer_spk`, read off that
    /// transaction (None: not read).
    pub returned: Option<u64>,
    /// AGP-104: the cumulative amount the provider said it closed with (None: no checked reply).
    pub close_cum: Option<u64>,
    /// AGP-104: what the wallet paid a miner for this ch2's funding (None: the wallet did not say).
    pub fund_fee: Option<u64>,
}

/// AGP-104: this ch2 pays its remainder to its own payer key (it named no return address).
pub fn own_key(p: &ChannelParams) -> bool {
    p.payer_spk == p2wpkh_spk(&p.payer_pub)
}

/// States in which the hub's coins are committed.
pub const LIVE: [&str; 3] = ["funding", "funded", "open"];
/// States the watcher reconciles until `final`. AGP-088: `rolled` too. A ch2 is rolled on the
/// provider's answer or on a rollover in the mempool, and stays watched (and refundable) until
/// that rollover is in a block: no answer takes a funded output away from the watcher.
pub const NONFINAL: [&str; 6] = ["funded", "open", "refunded", "closing", "closed", "rolled"];

/// An archived record the watcher still reconciles: a non-final ch2, or a dropped funding whose
/// send is known (it may confirm late: AGP-045).
pub fn watched(r: &Value) -> bool {
    let st = r.get("state").and_then(Value::as_str).unwrap_or("");
    !truthy(r.get("final")) && (NONFINAL.contains(&st) || (st == "dropped" && !py_str(r.get("fund_txid")).is_empty()))
}

/// The record's refund fee counts: refunded, or refunded and now `closing` on a spender that has
/// not confirmed (un-booked only when that close confirms: AGP-045).
fn refund_booked(state: &str, close_prev: &str) -> bool {
    state == "refunded" || (state == "closing" && close_prev == "refunded")
}

impl OutChannel {
    /// A new ch2 record (no state signed yet).
    #[allow(clippy::too_many_arguments)]
    pub fn fresh(origin: &str, pay_to: &str, params: ChannelParams, secret: &SecretKey, state: &str, settle_multiple: u64, terms: &Value, tip: u32) -> Self {
        Self { origin: origin.into(), pay_to: pay_to.into(), params, secret: hex::encode(secret.secret_bytes()), state: state.into(), signed: 0,
               routed: 0, seq: 0, pending: Map::new(), stale: vec![], settle_multiple, terms: terms.clone(), refund_hex: String::new(),
               blocked: String::new(), close_txid: String::new(), rolled_to: String::new(), opened_at: tip, scanned_to: tip,
               refund_txid: String::new(), refund_fee: 0, final_: false, next: Map::new(), fund_error: String::new(),
               refund_at: 0, refund_prev: vec![], close_prev: String::new(), fund_txid: String::new(), fund_vout: 0,
               rolled_from: String::new(), zero_conf: Map::new(), max_lock: 0, last_lock_at: 0.0, rolled_at: 0.0, fund_seen: false,
               retired: false, fund_confirmed: false, spend_seen: false, refill_owed: false, gone_at: 0, sweep: Map::new(),
               returned: None, close_cum: None, fund_fee: None }
    }

    pub fn to_json(&self) -> Value {
        let mut v = self.to_json_base();
        // AGP-104 (set here: the macro above is at its recursion limit)
        v["sweep"] = Value::Object(self.sweep.clone());
        v["returned"] = self.returned.into();
        v["close_cum"] = self.close_cum.into();
        v["fund_fee"] = self.fund_fee.into();
        v
    }

    fn to_json_base(&self) -> Value {
        json!({"origin": self.origin, "pay_to": self.pay_to, "params": self.params.to_json(), "secret": self.secret, "state": self.state,
               "signed": self.signed, "routed": self.routed, "seq": self.seq, "pending": self.pending, "stale": self.stale,
               "settle_multiple": self.settle_multiple, "terms": self.terms, "refund_hex": self.refund_hex, "blocked": self.blocked,
               "close_txid": self.close_txid, "rolled_to": self.rolled_to, "opened_at": self.opened_at, "scanned_to": self.scanned_to,
               "refund_txid": self.refund_txid, "refund_fee": self.refund_fee, "final": self.final_, "next": self.next, "fund_error": self.fund_error,
               "refund_at": self.refund_at, "refund_prev": self.refund_prev, "close_prev": self.close_prev, "fund_txid": self.fund_txid,
               "fund_vout": self.fund_vout, "rolled_from": self.rolled_from, "zero_conf": self.zero_conf, "max_lock": self.max_lock,
               "last_lock_at": self.last_lock_at, "rolled_at": self.rolled_at, "fund_seen": self.fund_seen, "retired": self.retired,
               "fund_confirmed": self.fund_confirmed, "spend_seen": self.spend_seen, "refill_owed": self.refill_owed, "gone_at": self.gone_at})
    }

    pub fn from_json(v: &Value) -> Result<Self> {
        let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let n = |k: &str| py_u64(v.get(k)).unwrap_or(0);
        Ok(Self { origin: s("origin"), pay_to: s("pay_to"), params: ChannelParams::from_json(&v["params"])?, secret: s("secret"),
                  state: s("state"), signed: n("signed"), routed: n("routed"), seq: n("seq"),
                  pending: v.get("pending").and_then(Value::as_object).cloned().unwrap_or_default(),
                  stale: v.get("stale").and_then(Value::as_array).cloned().unwrap_or_default(), settle_multiple: n("settle_multiple"),
                  terms: v.get("terms").cloned().unwrap_or(Value::Null), refund_hex: s("refund_hex"), blocked: s("blocked"),
                  close_txid: s("close_txid"), rolled_to: s("rolled_to"), opened_at: n("opened_at") as u32, scanned_to: n("scanned_to") as u32,
                  refund_txid: s("refund_txid"), refund_fee: n("refund_fee"), final_: v.get("final").and_then(Value::as_bool).unwrap_or(false),
                  next: v.get("next").and_then(Value::as_object).cloned().unwrap_or_default(), fund_error: s("fund_error"),
                  refund_at: n("refund_at") as u32, refund_prev: v.get("refund_prev").and_then(Value::as_array).cloned().unwrap_or_default(),
                  close_prev: s("close_prev"), fund_txid: s("fund_txid"), fund_vout: n("fund_vout") as u32, rolled_from: s("rolled_from"),
                  zero_conf: v.get("zero_conf").and_then(Value::as_object).cloned().unwrap_or_default(), max_lock: n("max_lock"),
                  last_lock_at: v.get("last_lock_at").and_then(Value::as_f64).unwrap_or(0.0),
                  rolled_at: v.get("rolled_at").and_then(Value::as_f64).unwrap_or(0.0),
                  fund_seen: v.get("fund_seen").and_then(Value::as_bool).unwrap_or(false),
                  retired: v.get("retired").and_then(Value::as_bool).unwrap_or(false),
                  fund_confirmed: v.get("fund_confirmed").and_then(Value::as_bool).unwrap_or(false),
                  spend_seen: v.get("spend_seen").and_then(Value::as_bool).unwrap_or(false),
                  refill_owed: v.get("refill_owed").and_then(Value::as_bool).unwrap_or(false), gone_at: n("gone_at") as u32,
                  sweep: v.get("sweep").and_then(Value::as_object).cloned().unwrap_or_default(),
                  returned: py_u64(v.get("returned")), close_cum: py_u64(v.get("close_cum")), fund_fee: py_u64(v.get("fund_fee")) })
    }

    fn secret_key(&self) -> Result<SecretKey> {
        Sc::from_hex64(&self.secret).and_then(|s| s.secret()).ok_or_else(|| ChannelError::new("bad_state", "ch2 key"))
    }

    fn term_u64(&self, k: &str) -> Option<u64> {
        py_u64(self.terms.get("extra").and_then(|e| e.get(k)))
    }

    /// An unconfirmed rollover child the provider took under its zero-conf bounds (AGP-053).
    pub fn zero_conf_pending(&self) -> bool {
        !self.zero_conf.is_empty() && !truthy(self.zero_conf.get("confirmed"))
    }
}

/// Why a rollover child is blocked while its rollover is in no block and not in the mempool (AGP-053).
pub const ROLLOVER_GONE: &str = "the rollover that funds this ch2 is in no block and not in the mempool";

/// The hub's ch2s, an fsynced JSON file, 0600 (each payer key sealed: AGP-073 K1).
///
/// One ch2 per origin (AGP-056, replacing AGP-044's one live ch2 per payTo): `chans` is keyed by the
/// canonical origin ([`canon_origin`]), one provider PROCESS, because that process's ledger is the
/// only one that holds the channel and its route sessions. An operator may run several provider
/// processes on one payTo key (cmp merchants): each gets its own ch2, and a lock is forwarded to the
/// origin the client named. `next_chans` (AGP-057) holds at most one more per origin: the ch2 funded
/// ahead of the live one running out, which takes its place in `chans` at the switch. `origins` maps
/// every origin the hub connected to the payTo its /terms named (a record, and the per-payTo count:
/// `ch2_max_per_pay_to`).
///
/// On disk (AGP-073 K1) every record's payer key is `secret_sealed` ([`crate::hub_keys`]), never
/// `secret`; in memory the records hold the key as before. A file from before (plaintext keys) is
/// read once and rewritten sealed.
#[derive(Debug, Default)]
pub struct OutBook {
    path: Option<PathBuf>,
    pub chans: IndexMap<String, OutChannel>,
    pub next_chans: IndexMap<String, OutChannel>,
    pub archived: Vec<Value>,
    pub origins: IndexMap<String, String>,
    wrap: Option<WrapKey>,
    sealed: std::cell::RefCell<SealCache>,
    legacy: usize,
}

/// Each key's blob, sealed once: a save seals only keys it has not seen. Never printed.
#[derive(Default)]
struct SealCache(HashMap<String, Value>);

impl std::fmt::Debug for SealCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SealCache({} keys)", self.0.len())
    }
}

/// Every ch2 record in a state file's JSON: the live and next ones, the archive, and the rollover's
/// next ch2 written ahead inside a record.
fn each_record(doc: &mut Value, f: &mut dyn FnMut(&mut Value) -> Result<()>) -> Result<()> {
    let mut one = |r: &mut Value| -> Result<()> {
        f(r)?;
        match r.get_mut("next") {
            Some(n) if n.get("params").is_some() => f(n),
            _ => Ok(()),
        }
    };
    for k in ["chans", "next_chans"] {
        if let Some(m) = doc.get_mut(k).and_then(Value::as_object_mut) {
            for r in m.values_mut() {
                one(r)?;
            }
        }
    }
    if let Some(a) = doc.get_mut("archived").and_then(Value::as_array_mut) {
        for r in a {
            one(r)?;
        }
    }
    Ok(())
}

impl OutBook {
    /// The book in `path` (none yet: empty), its keys opened with `wrap`. A file needs a wrap key.
    /// Refused (`keystore`): a blob that does not open (another wrap key, a changed file), or a key
    /// that is not its record's `payer_pub` (a blob moved to another record).
    pub fn open(path: Option<&Path>, wrap: Option<WrapKey>) -> Result<Self> {
        if path.is_some() && wrap.is_none() {
            return fail("keystore", "a hub state file needs a wrap key (its ch2 keys are sealed)");
        }
        let mut b = Self { path: path.map(Path::to_path_buf), wrap, ..Default::default() };
        let raw = match path.map(std::fs::read) {
            Some(Ok(r)) => Some(r),
            Some(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => None,
            Some(Err(e)) => return fail("ledger_error", format!("{}: {e}", path.map(Path::display).map(|d| d.to_string()).unwrap_or_default())),
            None => None,
        };
        if let Some(raw) = raw {
            let mut v: Value = crate::json::parse_slice(&raw).map_err(|e| ChannelError::new("ledger_error", e.to_string()))?;
            b.unseal_all(&mut v)?;
            for (k, c) in v.get("chans").and_then(Value::as_object).into_iter().flatten() {
                b.chans.insert(k.clone(), OutChannel::from_json(c)?);
            }
            for (k, c) in v.get("next_chans").and_then(Value::as_object).into_iter().flatten() {
                b.next_chans.insert(k.clone(), OutChannel::from_json(c)?);
            }
            b.archived = v.get("archived").and_then(Value::as_array).cloned().unwrap_or_default();
            for r in b.archived.iter_mut().filter(|r| r.get("state").and_then(Value::as_str) == Some("rolled") && r.get("fund_confirmed").is_none()) {
                // a ch2 rolled before AGP-088 was never watched again: it stays as it was (final),
                // not read against the chain from its first block on every tick
                r["final"] = true.into();
            }
            for (o, pt) in v.get("origins").and_then(Value::as_object).into_iter().flatten() {
                b.origins.insert(o.clone(), py_str(Some(pt)));
            }
            if b.legacy > 0 {
                b.save()?;
            }
        }
        Ok(b)
    }

    /// How many plaintext keys the file had when it was opened (now sealed).
    pub fn legacy_sealed(&self) -> usize {
        self.legacy
    }

    fn unseal_all(&mut self, doc: &mut Value) -> Result<()> {
        let (wrap, cache, legacy) = (self.wrap.as_ref(), self.sealed.get_mut(), &mut self.legacy);
        each_record(doc, &mut |r| {
            let Some(o) = r.as_object_mut() else { return Ok(()) };
            if let Some(blob) = o.remove("secret_sealed") {
                let k = wrap.ok_or_else(|| ChannelError::new("keystore", "no wrap key"))?.open(&blob)?;
                cache.0.insert(k.clone(), blob);
                o.insert("secret".into(), k.into());
            } else if o.get("secret").and_then(Value::as_str).is_some_and(|s| !s.is_empty()) {
                *legacy += 1;
            }
            // a key only ever signs for a record still watched: check that one is its own
            let key = o.get("secret").and_then(Value::as_str).filter(|s| !s.is_empty());
            let payer = o.get("params").and_then(|p| p.get("payer_pub")).and_then(Value::as_str);
            if let (Some(k), Some(pp), false) = (key, payer, truthy(o.get("final"))) {
                let sk = Sc::from_hex64(k).and_then(|s| s.secret()).ok_or_else(|| ChannelError::new("keystore", "a ch2 key is not a secret key"))?;
                if !hex::encode(ecdsa::pubkey(&sk)).eq_ignore_ascii_case(pp) {
                    return fail("keystore", format!("the ch2 key of {} is not its payer_pub: a sealed key moved to another record", py_str(o.get("origin"))));
                }
            }
            Ok(())
        })
    }

    /// The file's JSON with every key sealed (a key seen before reuses its blob).
    fn sealed_doc(&self, mut doc: Value) -> Result<Value> {
        let wrap = self.wrap.as_ref().ok_or_else(|| ChannelError::new("keystore", "a hub state file needs a wrap key"))?;
        let mut cache = self.sealed.borrow_mut();
        each_record(&mut doc, &mut |r| {
            let Some(o) = r.as_object_mut() else { return Ok(()) };
            let Some(Value::String(k)) = o.remove("secret") else { return Ok(()) };
            if k.is_empty() {
                return Ok(());
            }
            let blob = match cache.0.get(&k) {
                Some(b) => b.clone(),
                None => {
                    let b = wrap.seal(&k)?;
                    cache.0.insert(k, b.clone());
                    b
                }
            };
            o.insert("secret_sealed".into(), blob);
            Ok(())
        })?;
        Ok(doc)
    }

    /// The origins with a live ch2 (funding, funded or open) to `pay_to`: their own, or the next one
    /// funded ahead of it (AGP-057: an origin counts once).
    pub fn live_keys(&self, pay_to: &str) -> Vec<String> {
        let live = |c: &OutChannel| c.pay_to.eq_ignore_ascii_case(pay_to) && LIVE.contains(&c.state.as_str());
        let mut keys: Vec<String> = self.chans.iter().filter(|(_, c)| live(c)).map(|(k, _)| k.clone()).collect();
        let more: Vec<String> = self.next_chans.iter().filter(|(k, c)| live(c) && !keys.contains(k)).map(|(k, _)| k.clone()).collect();
        keys.extend(more);
        keys
    }

    /// The record of `oc`'s ch2 (same payer key) among the origin's live and next ch2.
    fn slot_mut(&mut self, oc: &OutChannel) -> Option<&mut OutChannel> {
        if self.chans.get(&oc.origin).is_some_and(|c| c.params.payer_pub == oc.params.payer_pub) {
            return self.chans.get_mut(&oc.origin);
        }
        self.next_chans.get_mut(&oc.origin).filter(|c| c.params.payer_pub == oc.params.payer_pub)
    }

    /// The key of the ch2 that serves `origin` (canonical): its own, and no other (AGP-056: the ch2
    /// of another origin under the same payTo is in another process's ledger).
    pub fn key_for(&self, origin: &str) -> Option<String> {
        self.chans.contains_key(origin).then(|| origin.to_string())
    }

    pub fn save(&self) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let chans: Map<String, Value> = self.chans.iter().map(|(k, v)| (k.clone(), v.to_json())).collect();
        let nexts: Map<String, Value> = self.next_chans.iter().map(|(k, v)| (k.clone(), v.to_json())).collect();
        let origins: Map<String, Value> = self.origins.iter().map(|(k, v)| (k.clone(), Value::from(v.as_str()))).collect();
        let doc = self.sealed_doc(json!({"chans": chans, "archived": self.archived, "origins": origins, "next_chans": nexts}))?;
        let io = |e: std::io::Error| ChannelError::new("ledger_error", e.to_string());
        let tmp = path.with_extension("tmp");
        {
            use std::io::Write;
            let mut f = crate::hub_keys::create_private(&tmp).map_err(io)?;
            f.write_all(dumps(&doc).as_bytes()).map_err(io)?;
            f.sync_all().map_err(io)?;
        }
        std::fs::rename(&tmp, path).map_err(io)
    }
}

/// The hub's counters (`stats` in the reference).
#[derive(Debug, Default, Clone)]
pub struct HubStats {
    pub routed: u64,
    pub floor: u64,
    pub refused: HashMap<String, u64>,
    pub lock_ms: Vec<f64>,
    /// ch1 channels holding a lock at each forward (constraint 3: always 1, the forwarded one).
    pub ch1_locks_at_forward: Vec<usize>,
    /// Locks completed after their ch1 closed below them: paid to the provider, not collected
    /// (AGP-064; only an operator's close_now or a margin close past its wait can do that).
    pub uncollected: u64,
}

/// `callable(hub) -> (fee_base_msat, fee_ppm)`.
pub type FeeStrategyFn = Box<dyn Fn(&RouteHub) -> (u64, u64) + Send + Sync>;

/// `refill(hub, origin)`: fund the ch2 that replaces a closed one (an embedder's own path, with its
/// lock and cap). Default: [`RouteHub::connect`].
pub type RefillFn = Box<dyn Fn(&RouteHub, &str) -> Result<()> + Send + Sync>;

/// A refill hook as stored: shared, so a call runs without the hook's lock held (AGP-045).
type SharedRefill = Arc<dyn Fn(&RouteHub, &str) -> Result<()> + Send + Sync>;

/// `refund_to()`: the address a ch2 refund pays (default: the ch2's payer key).
pub type RefundToFn = Box<dyn Fn() -> Result<String> + Send + Sync>;

/// `return_to()`: an address the operator controls, for a coin the hub gets back (AGP-104).
pub type ReturnToFn = RefundToFn;

/// Where a ch2 record lives: the live book (by origin), the origin's next ch2 (AGP-057), or the
/// archive (by index).
#[derive(Clone, Copy, Debug)]
enum Loc<'a> {
    Live(&'a str),
    Next(&'a str),
    Archived(usize),
}

/// A `/x402/route` as parsed: the payment payload, the body's `route`, and from it the lock's
/// amount `d`, its fee `f`, its id and the provider's origin.
struct RouteReq {
    pl: Value,
    rt: Value,
    d: i128,
    f: i128,
    lock_id: String,
    provider: String,
}

/// A provider's busy flag: the route request in flight, or the watcher, owns its ch2.
struct Busy<'a> {
    set: &'a Mutex<HashSet<String>>,
    origin: String,
}

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        lk(self.set).remove(&self.origin);
    }
}

/// The routing hub: a library ([`RouteHub::new`]) and, with [`crate::http`], a service.
pub struct RouteHub {
    pub cfg: HubConfig,
    chain: Arc<dyn ChainBackend>,
    scan: Arc<dyn SpendScan>,
    wallet: Box<dyn Wallet>,
    http: Box<dyn Transport>,
    secret: SecretKey,
    pay_to: String,
    network: String,
    /// ch1's payee: open/close/facilitator endpoints, ledger, watcher.
    pub inbound: Provider,
    out: Mutex<OutBook>,
    busy: Mutex<HashSet<String>>,
    quote: Mutex<Option<FeeQuote>>,
    quote_seq: Mutex<i64>,
    reveal_timeout_bits: AtomicU64,
    fee_strategy: Option<FeeStrategyFn>,
    refill: Mutex<Option<SharedRefill>>,
    refund_to: Mutex<Option<RefundToFn>>,
    return_to: Mutex<Option<ReturnToFn>>,
    /// The tip of the last sweep pass (AGP-104): sweeps are looked at once a block.
    sweep_tip: Mutex<Option<u32>>,
    /// Tests/demo: "" | "receipt" (keep t + r from the client) | "all" (forward nothing).
    pub withhold: Mutex<String>,
    pub events: Mutex<Vec<Value>>,
    pub stats: Mutex<HubStats>,
    /// (chan, tip): a rollover child's unconfirmed open, tried once a block (AGP-053).
    zc_tried: Mutex<HashSet<(String, u32)>>,
    /// The embedder's hook that funds an origin's next ch2 ahead (AGP-057); None: [`RouteHub::connect_next`],
    /// unless the embedder set its own `refill`.
    refill_ahead: Mutex<Option<SharedRefill>>,
    /// (origin, tip): an ahead refill that failed, tried once a block.
    ahead_tried: Mutex<HashSet<(String, u32)>>,
    /// (chan, tip): a retired ch2's close, asked once a block.
    retire_tried: Mutex<HashSet<(String, u32)>>,
    /// (chan, tip): the early close of a ch2 a written-off lock blocks (AGP-073), asked once a block.
    stale_tried: Mutex<HashSet<(String, u32)>>,
    /// Tests: the step at which the hub stops as a crash would ("": never). See [`RouteHub::set_stop`].
    stop_at: Mutex<String>,
    /// AGP-094: the ticks of [`RouteHub::watch`] and the ones that panicked.
    watch_health: crate::provider::WatchHealth,
}

/// How long a watcher tick waits for one busy provider's flag, and for all of them (AGP-053).
const WATCH_WAIT_ONE: Duration = Duration::from_millis(250);
const WATCH_WAIT_BUDGET: Duration = Duration::from_secs(1);

/// The hub's coins in ch2s: every record, live, next or archived, whose funding the hub made or is
/// making and has not seen spent. AGP-088 rule: coins count against `liquidity_cap_sat` until the
/// hub's own node shows them leaving. A provider's answer that it closed frees nothing (`closing`
/// without `spend_seen`), and neither does moving a record to the archive (a retired ch2, a next
/// ch2 adopted there).
fn committed(b: &OutBook) -> u64 {
    let counts = |state: &str, final_: bool, seen: bool| !final_ && (LIVE.contains(&state) || (state == "closing" && !seen));
    let live: u64 = b.chans.values().chain(b.next_chans.values()).filter(|c| counts(&c.state, c.final_, c.spend_seen)).map(|c| c.params.capacity).sum();
    let old: u64 = b.archived.iter()
        .filter(|r| counts(r.get("state").and_then(Value::as_str).unwrap_or(""), truthy(r.get("final")), truthy(r.get("spend_seen"))))
        .map(|r| py_u64(r.get("params").and_then(|p| p.get("capacity"))).unwrap_or(0)).sum();
    live + old
}

/// A lock of `d` needs a state above the ch2's capacity.
fn exhausted(oc: &OutChannel, d: u64) -> bool {
    let need2 = next_cum(oc.routed, d, oc.params.min_amount());
    need2 > oc.signed && need2 > oc.params.max_amount()
}

/// AGP-104: what `tx`, the spend of this ch2's funding, pays the ch2's `payer_spk`.
fn returned_by(tx: &Tx, p: &ChannelParams) -> u64 {
    tx.outputs.iter().filter(|o| o.script_pubkey == p.payer_spk).map(|o| u64::try_from(o.value).unwrap_or(0)).fold(0, u64::saturating_add)
}

/// The vsize of a sweep: one P2WPKH input, one output (the size of the close's CPFP child).
pub const SWEEP_VSIZE: u64 = crate::provider::CPFP_CHILD_VSIZE;
/// A closed ch1 whose payout is not on the chain this many blocks past its expiry is not looked
/// at again: its close never confirmed (the payer's refund took the funding).
pub const SWEEP_GIVE_UP_BLOCKS: u32 = 144;

/// What the chain shows of a sweep written ahead (rule R2).
enum Look {
    /// `spend_final_depth` deep: nothing left to watch.
    Final,
    /// In the mempool or a recent block.
    Wait,
    /// Its input is unspent and this node does not have it: the same bytes go out again.
    Resend,
}

/// A record's sweep is over: `spend_final_depth` deep, or there was nothing to sweep.
fn sweep_done(sw: Option<&Value>) -> bool {
    truthy(sw.and_then(|s| s.get("final")))
}

/// AGP-104: a ch2 record that may hold coins on its own payer key: its funding's spend is final,
/// it was closed by the provider or refunded, and it named no return address.
fn sweepable(c: &OutChannel) -> bool {
    c.final_ && ["closed", "refunded"].contains(&c.state.as_str()) && c.params.funding.is_some() && own_key(&c.params) && !truthy(c.sweep.get("final"))
}

fn err(status: u16, code: &str, detail: &str, extra: Value) -> HttpResponse {
    let mut v = json!({"error": code, "detail": detail});
    for (k, x) in extra.as_object().into_iter().flatten() {
        v[k] = x.clone();
    }
    HttpResponse::new(status, vec![("Content-Type".into(), "application/json".into())], dumps(&v))
}

fn e400(code: &str, detail: &str) -> HttpResponse {
    err(400, code, detail, json!({}))
}

fn ok_json(v: &Value) -> HttpResponse {
    HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], dumps(v))
}

impl RouteHub {
    /// `chain`: the merchant's node (a pruned one works: no txindex anywhere); `scan`: the same node
    /// for [`SpendScan`]; `wallet` funds ch2s; `http` talks to providers; `datadir` holds
    /// `ch1.jsonl` (ch1 ledger) and `ch2.json` (the out book), whose ch2 keys are sealed under
    /// `<datadir>/hub-wrap-key` (made 0600 on first run). [`RouteHub::new_with_wrap_key`] takes the
    /// wrap key from elsewhere (a secrets mount, kept apart from the state).
    #[allow(clippy::too_many_arguments)]
    pub fn new(chain: Arc<dyn ChainBackend>, scan: Arc<dyn SpendScan>, wallet: Box<dyn Wallet>, http: Box<dyn Transport>,
               pay_to_secret: SecretKey, network: &str, datadir: Option<&Path>, cfg: HubConfig) -> Result<Self> {
        Self::new_with_wrap_key(chain, scan, wallet, http, pay_to_secret, network, datadir, cfg, None)
    }

    /// [`RouteHub::new`] with the key that seals the ch2 keys in `ch2.json` (AGP-073 K1). None: the
    /// data dir's `hub-wrap-key`. A state file sealed under another key is refused (`keystore`).
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_wrap_key(chain: Arc<dyn ChainBackend>, scan: Arc<dyn SpendScan>, wallet: Box<dyn Wallet>, http: Box<dyn Transport>,
                             pay_to_secret: SecretKey, network: &str, datadir: Option<&Path>, cfg: HubConfig, wrap: Option<WrapKey>)
                             -> Result<Self> {
        cfg.validate()?;
        if let Some(d) = datadir {
            std::fs::create_dir_all(d).map_err(|e| ChannelError::new("ledger_error", e.to_string()))?;
        }
        let wrap = match (wrap, datadir) {
            (Some(w), _) => Some(w),
            (None, Some(d)) => Some(WrapKey::load_or_create(&d.join(WRAP_KEY_FILE))?),
            (None, None) => None,
        };
        let mut pc = ProviderConfig::new(network);
        pc.close_fee = cfg.close_fee;
        pc.close_margin = cfg.close_margin;
        pc.policy = cfg.funding_policy()?;
        pc.close_fee_payer = cfg.ch1_close_fee_payer;
        let ledger = match datadir {
            Some(d) => Ledger::open(&d.join("ch1.jsonl"))?,
            None => Ledger::in_memory(),
        };
        let inbound = Provider::new(chain.clone(), pay_to_secret, pc, ledger, Box::new(|_, _| 0),
                                    Box::new(|_, _, _| HttpResponse::new(404, vec![], b"not found".to_vec())))?;
        let out = OutBook::open(datadir.map(|d| d.join("ch2.json")).as_deref(), wrap)?;
        let mut events = vec![];
        if out.legacy_sealed() > 0 {
            eprintln!("hub: sealed {} plaintext ch2 keys in ch2.json (AGP-073); older copies of that file (backups) still hold them",
                      out.legacy_sealed());
            events.push(json!({"event": "ch2_keys_sealed", "count": out.legacy_sealed()}));
        }
        let hub = Self { pay_to: hex::encode(ecdsa::pubkey(&pay_to_secret)), cfg, chain, scan, wallet, http, secret: pay_to_secret,
                  network: network.into(), inbound, out: Mutex::new(out), busy: Mutex::new(HashSet::new()), quote: Mutex::new(None),
                  quote_seq: Mutex::new(now_i()), reveal_timeout_bits: AtomicU64::new(0), fee_strategy: None,
                  refill: Mutex::new(None), refund_to: Mutex::new(None), return_to: Mutex::new(None),
                  sweep_tip: Mutex::new(None), withhold: Mutex::new(String::new()), events: Mutex::new(events),
                  stats: Mutex::new(HubStats::default()), zc_tried: Mutex::new(HashSet::new()), refill_ahead: Mutex::new(None),
                  ahead_tried: Mutex::new(HashSet::new()), retire_tried: Mutex::new(HashSet::new()),
                  stale_tried: Mutex::new(HashSet::new()), stop_at: Mutex::new(String::new()),
                  watch_health: crate::provider::WatchHealth::default() };
        // AGP-094: locks a ledger from before AGP-088 holds get their ch2 before anything matches them
        hub.name_legacy_locks();
        Ok(hub)
    }

    /// Seconds a lock may wait for the provider's reveal (starts at `cfg.reveal_timeout`).
    pub fn reveal_timeout(&self) -> f64 {
        match self.reveal_timeout_bits.load(Ordering::Relaxed) {
            0 => self.cfg.reveal_timeout,
            b => f64::from_bits(b),
        }
    }

    pub fn set_reveal_timeout(&self, secs: f64) {
        self.reveal_timeout_bits.store(secs.max(1e-3).to_bits(), Ordering::Relaxed);
    }

    /// Edit the out book and save it (operator tools, tests).
    #[doc(hidden)]
    pub fn with_out<R>(&self, f: impl FnOnce(&mut OutBook) -> R) -> R {
        let mut b = lk(&self.out);
        let r = f(&mut b);
        let _ = b.save();
        r
    }

    /// Replace the default refill ([`RouteHub::connect`]) with an embedder's path (None: back to
    /// `connect`). The hook is looked up at each refill and called without any hub lock held, so it
    /// may be replaced at any time, from the hook itself too (AGP-045).
    pub fn set_refill(&self, f: Option<RefillFn>) {
        *lk(&self.refill) = f.map(SharedRefill::from);
    }

    /// The hook that funds an origin's next ch2 ahead of exhaustion (AGP-057), looked up at each call
    /// (None: back to the default). The default is [`RouteHub::connect_next`], unless the embedder set
    /// its own `refill` (its path, lock and cap): the hub then funds nothing on its own, and the
    /// refill follows the close as before.
    pub fn set_refill_ahead(&self, f: Option<RefillFn>) {
        *lk(&self.refill_ahead) = f.map(SharedRefill::from);
    }

    /// Pay ch2 refunds to this hook's address (default: the ch2's `payerSpk`, which is a return
    /// address when [`set_return_to`](Self::set_return_to) is set, else the ch2's payer key).
    pub fn set_refund_to(&self, f: Option<RefundToFn>) {
        *lk(&self.refund_to) = f;
    }

    /// AGP-104 (rule R1): the hook that names an address the operator controls. With it, every
    /// ch2 funded from now on pays its remainder there, and the watcher sweeps there what closes
    /// left on per-channel keys ([`Self::sweep_tick`]). None (the library's default): as before,
    /// a provider's close pays the ch2's own payer key, a ch1's payout stays on its payee key,
    /// and nothing is swept.
    pub fn set_return_to(&self, f: Option<ReturnToFn>) {
        *lk(&self.return_to) = f;
    }

    /// AGP-104: THE address a coin the hub gets back is paid to, as a script (None: no return
    /// hook). Every return goes through here: a ch2's `payerSpk` at funding and at rollover, a
    /// refund of a ch2 that names its own key, and both sweeps. A later task that returns coins
    /// to a Lightning wallet changes this function's hook and nothing else. Witness v0 only
    /// (P2WPKH or P2WSH): what every provider takes as a `payerSpk` and what a sweep can pay.
    fn return_spk(&self) -> Result<Option<Vec<u8>>> {
        let g = lk(&self.return_to);
        let Some(f) = g.as_ref() else { return Ok(None) };
        let addr = f().map_err(|e| ChannelError::new("return_address", format!("no return address: {e}")))?;
        let spk = address_to_spk(&addr, Some(&self.cfg.hrp)).map_err(|e| ChannelError::new("return_address", format!("return address: {e}")))?;
        if !((spk.len() == 22 || spk.len() == 34) && spk[0] == 0 && spk[1] as usize == spk.len() - 2) {
            return fail("return_address", "the return address must be a witness v0 address (bech32 P2WPKH or P2WSH)");
        }
        Ok(Some(spk))
    }

    /// Replace the configured fee strategy with a callable.
    pub fn set_fee_strategy(&mut self, f: FeeStrategyFn) {
        self.fee_strategy = Some(f);
    }

    pub fn pay_to(&self) -> &str {
        &self.pay_to
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    /// A snapshot of the out book's channels.
    pub fn out_channels(&self) -> IndexMap<String, OutChannel> {
        lk(&self.out).chans.clone()
    }

    /// The ch2 that serves `origin` (AGP-044: the live ch2 of its payTo, which may have been opened
    /// at another origin of the same operator).
    pub fn ch2_for(&self, origin: &str) -> Option<OutChannel> {
        let b = lk(&self.out);
        b.key_for(&canon_origin(origin)).and_then(|k| b.chans.get(&k).cloned())
    }

    pub fn archived(&self) -> Vec<Value> {
        lk(&self.out).archived.clone()
    }

    /// A snapshot of the next ch2s (AGP-057: funded ahead of an origin's live one running out).
    pub fn next_channels(&self) -> IndexMap<String, OutChannel> {
        lk(&self.out).next_chans.clone()
    }

    pub fn set_withhold(&self, mode: &str) {
        *lk(&self.withhold) = mode.to_string();
    }

    fn withholding(&self) -> String {
        lk(&self.withhold).clone()
    }

    /// Tests: stop (error `test_stop`) between two writes, as a crash there would: `release` is
    /// between a written-off lock leaving ch1 and leaving its ch2 record.
    #[doc(hidden)]
    pub fn set_stop(&self, at: &str) {
        *lk(&self.stop_at) = at.to_string();
    }

    fn stop(&self, at: &str) -> Result<()> {
        if *lk(&self.stop_at) == at {
            return fail("test_stop", at);
        }
        Ok(())
    }

    fn event(&self, e: Value) {
        lk(&self.events).push(e);
    }

    /// The hub's own coins in ch2s (funding, funded, open, or closing on the provider's word): every
    /// origin's live one, its next one funded ahead (AGP-057), and each archived one until this
    /// node shows its funding spent (AGP-088).
    pub fn committed_sat(&self) -> u64 {
        committed(&lk(&self.out))
    }

    /// Fees of the hub's own ch2 refunds that spent (or still may spend) their fundings.
    pub fn refund_fees_sat(&self) -> u64 {
        let b = lk(&self.out);
        let live = b.chans.values().filter(|c| refund_booked(&c.state, &c.close_prev)).map(|c| c.refund_fee);
        let old = b.archived.iter().filter(|r| refund_booked(&py_str(r.get("state")), &py_str(r.get("close_prev"))))
            .map(|r| py_u64(r.get("refund_fee")).unwrap_or(0));
        live.chain(old).sum()
    }

    fn configured_fees(&self) -> Result<(u64, u64)> {
        let st = &self.cfg.fee_strategy;
        let kind = st.get("kind").and_then(Value::as_str).unwrap_or("flat");
        match kind {
            "flat" => Ok((self.cfg.fee_base_msat, self.cfg.fee_ppm)),
            "utilization" => {
                let cap = self.cfg.liquidity_cap();
                let uu = if cap > 0 { (self.committed_sat() as f64 / cap as f64).min(1.0) } else { 0.0 };
                let lo = py_u64(st.get("ppm_min")).unwrap_or(self.cfg.fee_ppm);
                let hi = py_u64(st.get("ppm_max")).unwrap_or(self.cfg.fee_ppm);
                let base = py_u64(st.get("base_msat")).unwrap_or(self.cfg.fee_base_msat);
                Ok((base, (lo as f64 + (hi as f64 - lo as f64) * uu) as u64))
            }
            other => fail("bad_config", format!("unknown fee strategy {other:?}")),
        }
    }

    /// The live fee quote, re-signed when it nears expiry or the strategy moves the fees.
    pub fn fee_quote(&self) -> Result<FeeQuote> {
        let now = now_i();
        let (base, ppm) = match &self.fee_strategy {
            Some(f) => f(self),
            None => self.configured_fees()?,
        };
        let mut q = lk(&self.quote);
        let stale = match q.as_ref() {
            None => true,
            Some(x) => x.valid_until - now < self.cfg.quote_ttl / 4 || (x.fee_base_msat, x.fee_ppm) != (base, ppm),
        };
        if stale {
            let mut seq = lk(&self.quote_seq);
            *seq += 1;
            *q = Some(FeeQuote { hub: self.pay_to.clone(), network: self.network.clone(), fee_base_msat: base, fee_ppm: ppm,
                                 max_lock_sat: self.cfg.max_lock_sat, max_unguarded_lock_sat: self.cfg.max_unguarded_lock_sat,
                                 min_in_expiry_delta: self.cfg.delta as u64, reveal_timeout_sec: self.reveal_timeout() as u64, seq: *seq,
                                 issued_at: now, valid_until: now + self.cfg.quote_ttl, sig: String::new() }.sign(&self.secret));
        }
        Ok(q.clone().expect("set above"))
    }

    /// `extra.routing` of the hub's 402.
    pub fn routing_extra(&self) -> Result<Value> {
        let q = self.fee_quote()?;
        let providers: Vec<String> = {
            // every origin whose own ch2 is open and not blocked, or whose next one is open to take over
            // (AGP-057) unless the hub stopped routing to the provider
            let b = lk(&self.out);
            let mut v: Vec<String> = b.chans.iter().filter(|(_, c)| c.state == "open" && c.blocked.is_empty()).map(|(o, _)| o.clone()).collect();
            for (o, _) in b.next_chans.iter().filter(|(_, n)| n.state == "open") {
                let held = b.chans.get(o).is_some_and(|c| !c.blocked.is_empty() && c.blocked != ROLLOVER_GONE);
                if !held && !v.contains(o) {
                    v.push(o.clone());
                }
            }
            v.sort();
            v
        };
        Ok(json!({"feeBaseMsat": q.fee_base_msat, "feePpm": q.fee_ppm, "maxLockSat": q.max_lock_sat,
                  "maxUnguardedLockSat": q.max_unguarded_lock_sat, "minInExpiryDelta": q.min_in_expiry_delta,
                  "revealTimeoutSec": q.reveal_timeout_sec, "routeUrl": HUB_ROUTE_PATH, "quote": q.to_json(),
                  "ch1CloseFeePayer": self.cfg.ch1_close_fee_payer.as_str(), "ch2CloseFeePayer": self.cfg.ch2_close_fee_payer.as_str(),
                  "providers": providers}))
    }

    pub fn body_limit(&self, path: &str, max_body: Option<usize>) -> usize {
        self.inbound.body_limit(path, max_body)
    }

    /// Serve one request: `/x402/route` here, everything else by ch1's provider.
    pub fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str, max_body: Option<usize>) -> HttpResponse {
        if body.len() > self.body_limit(path, max_body) {
            return HttpResponse::new(400, vec![], b"bad request framing or body over MAX_BODY".to_vec());
        }
        if crate::wire::no_fragment(path).is_err() {
            // as the provider does (AGP-081, review T2)
            return HttpResponse::new(400, vec![], b"request target with a # fragment".to_vec());
        }
        if path.split('?').next() == Some(HUB_ROUTE_PATH) {
            let hdr = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-SIGNATURE")).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty());
            if let (true, Some(h)) = (method == "POST", hdr) {
                return self.route(method, &crate::provider::binding_url(url, HUB_ROUTE_PATH), h, body);
            }
            let mut doc = self.inbound.payment_required_doc(if url.is_empty() { path } else { url }, 0, "payment_required", None);
            match self.routing_extra() {
                Ok(r) => doc["accepts"][0]["extra"]["routing"] = r,
                Err(e) => return err(500, &e.code, &e.to_string(), json!({})),
            }
            return self.inbound.required_response(&doc);
        }
        if path.split('?').next() == Some(HUB_VIEW_PATH) {
            let hdr = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-SIGNATURE")).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty());
            return match (method == "POST", hdr) {
                (true, Some(h)) => self.view(method, &crate::provider::binding_url(url, HUB_VIEW_PATH), h, body),
                _ => e400("bad_payload", ""),
            };
        }
        // a rollover spends ch1's funding as a close does (AGP-078): the same sweep before either
        if method == "POST" && [CLOSE_PATH, ROLLOVER_PATH].iter().any(|p| path.split('?').next() == Some(p)) {
            if let Some(ch1) = crate::json::parse_slice(body).ok().and_then(|v| v.get("chan").and_then(Value::as_str).and_then(|c| canonical_chan(c).ok())) {
                self.sweep_orphan_lock(&ch1);
            }
        }
        self.inbound.serve(method, path, headers, body, url, max_body)
    }

    /// A ch1 lock that no route is forwarding and no ch2 has pending: the hub stopped between its
    /// write-ahead and the ch2 one, or between a void's ch2 write and its ch1 write (or the
    /// withholding test hook). Checked under the provider's busy flag, which route() holds from
    /// before it writes the lock until its forward ends. AGP-073: if a ch2 of that provider has the
    /// lock written off, its pre-signature may be out, so it is held in ch1's base as the void would
    /// have held it; otherwise nothing can complete it and it is dropped (AGP-064), so it does not
    /// keep ch1 from closing. Run by the watcher for every ch1 with a lock, and before a ch1 close
    /// or rollover.
    fn sweep_orphan_lock(&self, ch1: &str) -> Option<Value> {
        let rl = self.ch1_state(ch1).and_then(|s| s.extra.get("route_lock").filter(|x| truthy(Some(x))).cloned())?;
        let origin = py_str(rl.get("provider"));
        let _busy = self.acquire(&origin, Duration::ZERO)?;
        let lid = rl.get("lockId").cloned().unwrap_or(Value::Null);
        let written_off = {
            // AGP-088: this ch1's lock, not any lock of that lockId, and wherever its ch2 record is
            // now: one archived with the lock still pending is not an orphan's
            let id = py_str(Some(&lid));
            let mine = |l: &Value| is_ch2_lock(l, ch1, &id);
            let b = lk(&self.out);
            let live = || b.chans.get(&origin).into_iter().chain(b.next_chans.get(&origin));
            let old = || b.archived.iter().filter(|r| py_str(r.get("origin")) == origin && !truthy(r.get("final")));
            if live().any(|c| !c.pending.is_empty() && mine(&Value::Object(c.pending.clone())))
                || old().any(|r| r.get("pending").is_some_and(|p| truthy(Some(p)) && mine(p)))
            {
                return None;
            }
            live().any(|c| !c.final_ && c.stale.iter().any(mine))
                || old().any(|r| r.get("stale").and_then(Value::as_array).is_some_and(|s| s.iter().any(mine)))
        };
        let mut l = self.inbound.ledger_lock();
        let mut st1 = l.channels.get(ch1).cloned()?;
        let mut rl = st1.extra.get("route_lock").filter(|x| x.get("lockId") == Some(&lid)).cloned()?;
        st1.extra.insert("route_lock".into(), Value::Null);
        if written_off {
            rl["voided"] = round3(now_f());
            hold_in_base(&mut st1.extra, &mut rl);
            let mut stale = st1.extra.get("stale_locks").and_then(Value::as_array).cloned().unwrap_or_default();
            stale.push(rl);
            st1.extra.insert("stale_locks".into(), Value::Array(stale));
        }
        self.inbound.save_state(&mut l, &st1).ok()?;
        drop(l);
        let ev = json!({"event": if written_off { "orphan_lock_held" } else { "orphan_lock_dropped" }, "chan": ch1, "lockId": lid,
                        "provider": origin});
        self.event(ev.clone());
        Some(ev)
    }

    fn acquire(&self, origin: &str, timeout: Duration) -> Option<Busy<'_>> {
        let until = Instant::now() + timeout;
        loop {
            if lk(&self.busy).insert(origin.to_string()) {
                return Some(Busy { set: &self.busy, origin: origin.to_string() });
            }
            if Instant::now() >= until {
                return None;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// `POST /x402/route/view` (AGP-088): ch1 as the hub counts it, for the client that holds its
    /// key. Authenticated like a route (the request HMAC and a fresh seq, which is saved before the
    /// answer leaves); it changes nothing else.
    fn view(&self, method: &str, bind: &str, hdr: &str, body: &[u8]) -> HttpResponse {
        let Some(pl) = unb64json(hdr).ok().and_then(|h| h.get("payload").cloned()).filter(Value::is_object) else { return e400("bad_payload", "") };
        let mut l = self.inbound.ledger_lock();
        let cid = pl.get("chan").and_then(Value::as_str).and_then(|c| canonical_chan(c).ok()).filter(|c| l.channels.contains_key(c));
        let Some(cid) = cid else { return e400("unknown_channel", "") };
        let mut st1 = l.channels[&cid].clone();
        if !self.inbound.authentic(&st1, &pl, method, bind, body) {
            return err(401, "bad_auth", "", json!({}));
        }
        st1.seq = py_u64(pl.get("seq")).unwrap_or(st1.seq);
        if let Err(e) = self.inbound.save_state(&mut l, &st1) {
            return err(500, &e.code, &e.to_string(), json!({}));
        }
        ok_json(&ch1_view(&st1))
    }

    // --- POST /x402/route ---------------------------------------------------------------------------

    /// `bind`: the request's URL as [`request_digest_v2`] binds it.
    fn route(&self, method: &str, bind: &str, hdr: &str, body: &[u8]) -> HttpResponse {
        let t0 = Instant::now();
        let parsed = (|| -> Option<RouteReq> {
            let pl = unb64json(hdr).ok()?.get("payload")?.clone();
            let rt = crate::json::parse_slice(body).ok()?.get("route")?.clone();
            if !pl.is_object() || !rt.is_object() {
                return None;
            }
            let (d, f) = (py_int(rt.get("amount"))?, py_int(rt.get("fee"))?);
            let lock_id = py_str(Some(rt.get("lockId")?));
            // no `#`: the lock sent on is bound to `provider + /x402/xbt-channel/lock` (AGP-081, T2)
            let provider = Some(canon_origin(&py_str(Some(rt.get("provider")?)))).filter(|p| crate::wire::no_fragment(p).is_ok())?;
            Some(RouteReq { pl, rt, d, f, lock_id, provider })
        })();
        let Some(req) = parsed else { return e400("bad_payload", "") };
        let pl = &req.pl;
        let mut l = self.inbound.ledger_lock();
        // 1 auth -------------------------------------------------------------------------------------
        let cid = pl.get("chan").and_then(Value::as_str).and_then(|c| canonical_chan(c).ok()).filter(|c| l.channels.contains_key(c));
        let Some(cid) = cid else { return e400("unknown_channel", "") };
        let mut st1 = l.channels[&cid].clone();
        if !self.inbound.authentic(&st1, pl, method, bind, body) {
            return err(401, "bad_auth", "", json!({}));
        }
        st1.seq = py_u64(pl.get("seq")).unwrap_or(st1.seq);
        l.channels.insert(cid.clone(), st1.clone());
        let (oc, lock1, busy) = match self.admit(&mut l, &mut st1, &req) {
            Ok(a) => a,
            Err(refusal) => {
                // AGP-078 (review T4): the seq this request spent is durable before its refusal
                // leaves. Kept only in memory it came back after a restart, and the refused header
                // authenticated again
                if let Err(e) = self.inbound.save_state(&mut l, &st1) {
                    return err(500, &e.code, &e.to_string(), json!({}));
                }
                return refusal;
            }
        };
        let n = l.channels.values().filter(|c| truthy(c.extra.get("route_lock"))).count();
        lk(&self.stats).ch1_locks_at_forward.push(n);
        drop(l);
        let r = self.forward(&cid, &oc, &lock1, &req.rt, t0);
        drop(busy);
        r
    }

    /// Checks 2 to 7 of a `/x402/route` whose auth passed, and the ch1 write-ahead of its lock (the
    /// ledger lock is the caller's). `Ok`: the ch2 the lock goes over, the lock as written on ch1,
    /// and that provider's busy flag. `Err`: the answer to send instead (a refusal, or a completed
    /// lock's answer again); nothing was written.
    fn admit(&self, l: &mut Ledger, st1: &mut ChannelState, req: &RouteReq) -> std::result::Result<(OutChannel, Value, Busy<'_>), HttpResponse> {
        let RouteReq { pl, rt, d, f, lock_id, provider } = req;
        let (d, f) = (*d, *f);
        if let Some(done) = st1.extra.get("route_done").and_then(|d| d.get(lock_id)) {
            // the client lost our answer: the same one again
            return Err(ok_json(done));
        }
        let height = match self.inbound.height() {
            Ok(h) => h,
            Err(e) => return Err(err(500, "node_error", &e.to_string(), json!({}))),
        };
        // AGP-084: a ch1 close or rollover the node errored on can still confirm: no lock above it
        if crate::provider::closing(st1) || height as i64 >= st1.params.expiry as i64 - self.cfg.close_margin as i64 {
            return Err(e400("channel_closing", ""));
        }
        if st1.suspended {
            return Err(e400("unconfirmed", ""));
        }
        // 2 point ------------------------------------------------------------------------------------
        let pts = (|| -> Option<_> {
            let tp = adaptor::dec_hex(rt.get("point")?.as_str()?).ok()?;
            let r = Sc::from_hex_mod_n(rt.get("tweak")?.as_str()?)?;
            let t1 = if truthy(pl.get("point")) { Some(adaptor::dec_hex(pl.get("point")?.as_str()?).ok()?) } else { None };
            Some((tp, r, t1))
        })();
        let Some((tp, r, t1)) = pts else { return Err(e400("bad_point", "points must be compressed secp256k1 points")) };
        if let Some(t1) = &t1 {
            if r.is_zero() || adaptor::add(Some(&tp), adaptor::mul(&r, None).as_ref()) != Some(*t1) {
                return Err(e400("bad_point", "T1 != T + r*G"));
            }
        }
        // 3 amount -----------------------------------------------------------------------------------
        let ex1 = st1.extra.clone();
        let routed1 = py_u64(ex1.get("routed_sat")).unwrap_or(0);
        let fee_units = u128_of(ex1.get("fee_units")).unwrap_or(0);
        let fee_paid = py_u64(ex1.get("fee_paid")).unwrap_or(0);
        let cum = py_int(pl.get("cum")).unwrap_or(-1);
        if d < 1 || f < 0 || d > self.cfg.max_lock_sat as i128 {
            return Err(e400("bad_amount", &format!("lock amount must be in [1, {}]", self.cfg.max_lock_sat)));
        }
        let (d, f) = (d as u64, u64::try_from(f).unwrap_or(u64::MAX / 4));
        let need1 = next_cum(routed1, d.saturating_add(f), st1.params.min_amount());
        let floor1 = need1 <= st1.best_cum;
        // our view of ch1, so a client that gave up a lock we later completed, held or released can resync
        let view = |expect: u64| {
            let mut v = ch1_view(st1);
            v["expectCum"] = expect.into();
            v
        };
        if floor1 {
            if cum != st1.best_cum as i128 || truthy(pl.get("adaptor")) {
                return Err(err(400, "bad_amount", &format!("the dust floor covers this lock: cum {}, no adaptor", st1.best_cum), view(st1.best_cum)));
            }
        } else if cum != need1 as i128 || cum > st1.params.max_amount() as i128 || t1.is_none() {
            return Err(err(400, "bad_amount", &format!("lock pays {cum}, expected {need1}"), view(need1)));
        }
        // 4 pre-verify -------------------------------------------------------------------------------
        let mut pre1: Option<PreSig> = None;
        if !floor1 {
            let Ok(p) = PreSig::from_json(pl.get("adaptor").unwrap_or(&Value::Null)) else { return Err(e400("bad_adaptor", "malformed adaptor")) };
            let z1 = match st1.params.state_tx(need1).and_then(|tx| st1.params.sighash(&tx)) {
                Ok(z) => z,
                Err(_) => return Err(e400("bad_adaptor", "no such state")),
            };
            if !adaptor::preverify(&st1.params.payer_pub, &z1, t1.as_ref().expect("checked in 3"), &p) {
                return Err(e400("bad_adaptor", "pre-signature does not verify under T1"));
            }
            pre1 = Some(p);
        }
        // 5 fee quote --------------------------------------------------------------------------------
        let Ok(q) = FeeQuote::from_json(rt.get("feeQuote").unwrap_or(&Value::Null)) else { return Err(e400("route_fee", "no fee quote")) };
        // any live quote this hub signed is honoured, including one the fee strategy has since moved
        if q.hub != self.pay_to || q.network != self.network || !q.verify() || !q.live(now_f()) {
            return Err(e400("route_fee", "not a live fee quote of this hub"));
        }
        let (f_due, units) = fee_due(&q, d, fee_units, fee_paid);
        if f < f_due {
            return Err(err(400, "route_fee", &format!("fee {f} < {f_due} due under quote {}", q.seq), json!({"feeDue": f_due})));
        }
        // 6 expiry rule ------------------------------------------------------------------------------
        // the provider is the origin the client named: its own ch2, in that process's ledger (AGP-056)
        let key = provider.clone();
        let (oc, nxt) = {
            let b = lk(&self.out);
            (b.chans.get(&key).cloned(), b.next_chans.get(&key).cloned())
        };
        // a rollover's next ch2 is opened (AGP-053) under the busy flag the lock takes below: it is
        // checked again there, once it is open
        let opening = |o: &OutChannel| o.state == "funded" && !o.rolled_from.is_empty() && self.cfg.zero_conf_rollover;
        // the origin's next ch2, funded ahead (AGP-057), takes the lock its live one cannot: decided
        // under the busy flag below
        let spare = nxt.as_ref().is_some_and(|n| n.state == "open");
        if !oc.as_ref().is_some_and(|o| o.state == "open" || opening(o)) && !spare {
            return Err(e400("route_blocked", &self.no_channel(provider, oc.as_ref())));
        }
        if let Some(o) = oc.as_ref().filter(|o| !o.blocked.is_empty() && !(spare && o.blocked == ROLLOVER_GONE)) {
            return Err(e400("route_blocked", &o.blocked));
        }
        let Some(oc) = oc.or(nxt) else { return Err(e400("route_blocked", &self.no_channel(provider, None))) };
        let Ok(inv) = Invoice::from_json(rt.get("invoice").unwrap_or(&Value::Null)) else { return Err(e400("bad_invoice", "")) };
        let rt_point = py_str(rt.get("point"));
        if inv.pay_to != oc.pay_to || !inv.verify() || inv.point.to_lowercase() != rt_point.to_lowercase() || inv.lock_id != *lock_id
            || inv.valid_until_f() < now_f() + self.reveal_timeout().max(0.5) || !inv.accepts_hub(&self.pay_to)
        {
            return Err(e400("bad_invoice", "invoice not signed by the provider for this point, or expiring"));
        }
        if !spare && !route_ok(height, st1.params.expiry, oc.params.expiry, self.cfg.close_margin, self.cfg.delta) && d > self.cfg.max_unguarded_lock_sat {
            return Err(e400("route_expiry", &format!("ch2 outlives ch1 and {d} > maxUnguardedLockSat")));
        }
        // 7 one lock per channel ---------------------------------------------------------------------
        if truthy(ex1.get("route_lock")) {
            return Err(e400("lock_outstanding", "a lock on this ch1 is pending"));
        }
        let Some(busy) = self.acquire(&key, Duration::from_millis(500)) else {
            return Err(e400("lock_outstanding", "a lock on this provider's ch2 is pending"));
        };
        // re-read under the busy flag: the watcher may have rolled this ch2 over meanwhile (AGP-053), so
        // the checks that depend on the channel are made again on the one the lock will use
        let mut oc = lk(&self.out).chans.get(&key).cloned();
        let mut why = self.ch2_refusal(oc.as_ref(), st1, d, height);
        if why.is_some() || !oc.as_ref().is_some_and(|o| !exhausted(o, d)) {
            // AGP-057: the next ch2, funded ahead, takes over with this lock (make-before-break refill)
            match self.switch_for(&key, oc.as_ref(), st1, d, height, why.as_ref().map(|w| w.1.as_str())) {
                Ok(Some(alt)) => (oc, why) = (Some(alt), None),
                Ok(None) => {}
                Err(e) => return Err(err(500, &e.code, &e.to_string(), json!({}))),
            }
        }
        if let Some((code, why)) = why {
            return Err(e400(code, &why));
        }
        let Some(oc) = oc else { return Err(e400("lock_outstanding", "a lock on this provider's ch2 is pending")) };
        // AGP-088: one unresolved lock per lockId on a ch1. The lockId is the provider's choice, and
        // the client is told of its held and released locks by lockId. A ch2 that could take this
        // lock (another provider's, or this provider's next one) does not take it under a lockId
        // that ch1 still holds written off: refused before anything is pre-signed on it, with our
        // view, so a client that lost the first refusal adopts the hold
        if st1.extra.get("stale_locks").and_then(Value::as_array).is_some_and(|s| s.iter().any(|x| x.get("lockId").and_then(Value::as_str) == Some(lock_id.as_str()))) {
            return Err(err(400, "lock_held", "a written-off lock with this lockId is unresolved on this channel", ch1_view(st1)));
        }
        // write-ahead: pre1 (enough to complete ch1 from t on-chain after a crash)
        // cum passed check 3: the best state (floor) or need1
        let lock1 = json!({"lockId": lock_id, "cum": cum as u64, "floor": floor1,
                           "pre": pre1.as_ref().map(PreSig::to_json), "T": rt_point, "T1": pl.get("point").cloned().unwrap_or(Value::Null),
                           "r": r.hex(), "d": d, "f": f, "units": int_value(units), "unitsBy": int_value(units - fee_units), "provider": provider,
                           "ch2": ch2_key(&oc), "at": round3(now_f()),
                           "session": rt.get("session").cloned().unwrap_or(Value::Null),
                           "after": {"routed": routed1 + d + f, "units": int_value(units), "paid": fee_paid + f}});
        st1.extra.insert("route_lock".into(), lock1.clone());
        if let Err(e) = self.inbound.save_state(l, st1) {
            // not written: the caller's save of the spent seq must not write it either
            st1.extra.insert("route_lock".into(), Value::Null);
            return Err(err(500, &e.code, &e.to_string(), json!({})));
        }
        Ok((oc, lock1, busy))
    }

    /// (code, detail) if the ch2 (as read under its busy flag) cannot take a lock of `d` now: another
    /// lock is pending, it is not open (a rollover child the provider did not take unconfirmed), it is blocked, the expiry rule, or (AGP-053) it is an
    /// unconfirmed rollover child past the provider's zero-conf bounds.
    fn ch2_refusal(&self, oc: Option<&OutChannel>, st1: &ChannelState, d: u64, tip: u32) -> Option<(&'static str, String)> {
        let Some(oc) = oc.filter(|o| o.pending.is_empty()) else {
            return Some(("lock_outstanding", "a lock on this provider's ch2 is pending".into()));
        };
        // AGP-064 (H2): a written-off lock's pre-signature may be out. Nothing more over this ch2
        // until it resolves: its close shows whether t was used, its refund that it was not
        if !oc.stale.is_empty() {
            return Some(("route_blocked", "a written-off lock on this ch2 is unresolved".into()));
        }
        if oc.state != "open" {
            return Some(("route_blocked", self.no_channel(&oc.origin, Some(oc))));
        }
        if !oc.blocked.is_empty() {
            return Some(("route_blocked", oc.blocked.clone()));
        }
        let p2 = &oc.params;
        if !route_ok(tip, st1.params.expiry, p2.expiry, self.cfg.close_margin, self.cfg.delta) && d > self.cfg.max_unguarded_lock_sat {
            return Some(("route_expiry", format!("ch2 outlives ch1 and {d} > maxUnguardedLockSat")));
        }
        if oc.zero_conf_pending() {
            let zc = &oc.zero_conf;
            let need2 = next_cum(oc.routed, d, p2.min_amount()).max(oc.signed);
            let max = py_u64(zc.get("maxCum")).unwrap_or(0);
            let (late, over) = (tip as u64 >= py_u64(zc.get("until")).unwrap_or(0), need2 > max);
            if late || over {
                // AGP-057: `confirmed` is the watcher's last look, which a block or a busy tick can be
                // behind. Past a bound, look at the chain before refusing (the provider does the same)
                let confirmed = match self.zero_conf_tick(&oc.origin, oc) {
                    Ok(_) => self.get(Loc::Live(&oc.origin)).is_some_and(|c| c.params.payer_pub == oc.params.payer_pub && !c.zero_conf_pending()),
                    Err(e) => {
                        // the node did not answer: the bounds stand
                        self.watch_error(&oc.origin, "zero_conf", &e);
                        false
                    }
                };
                if !confirmed && late {
                    return Some(("route_blocked", "the rollover funding this ch2 is unconfirmed at the parent's close margin".into()));
                }
                if !confirmed {
                    return Some(("route_blocked", format!("the rollover funding this ch2 is unconfirmed: cum {need2} > the provider's zero-conf cap {max}")));
                }
            }
        }
        None
    }

    /// AGP-057: the origin's live ch2 (`oc`, as read under its busy flag) cannot take a lock of `d`:
    /// `why` is its refusal, None when it is only exhausted. If the origin's next ch2 is open and can
    /// take the lock, it becomes the live one ([`promote`](Self::promote)) and is returned. Never
    /// while a lock is pending on the live one, and never when the hub stopped routing to the PROVIDER
    /// (a lock it did not reveal): a fresh channel does not mend that.
    fn switch_for(&self, key: &str, oc: Option<&OutChannel>, st1: &ChannelState, d: u64, tip: u32, why: Option<&str>) -> Result<Option<OutChannel>> {
        let Some(nxt) = lk(&self.out).next_chans.get(key).filter(|n| n.state == "open").cloned() else { return Ok(None) };
        if oc.is_some_and(|o| !o.pending.is_empty() || (!o.blocked.is_empty() && o.blocked != ROLLOVER_GONE)) {
            return Ok(None);
        }
        if self.ch2_refusal(Some(&nxt), st1, d, tip).is_some() || exhausted(&nxt, d) {
            return Ok(None);
        }
        self.promote(key, why.unwrap_or("exhausted"))
    }

    /// AGP-057: the origin's next ch2 becomes its live one. The caller holds the origin's busy flag, or
    /// the live one takes no lock any more. The ch2 it replaces goes to the archive; while its coins
    /// are still committed (funded, open) it is `retired`: the watcher has the provider close it.
    /// AGP-088: not while a lock is pending on the live one (None): a ch2 keeps its place until its
    /// lock is completed or written off, so the route that sent it still finds it.
    fn promote(&self, origin: &str, why: &str) -> Result<Option<OutChannel>> {
        let (from, nxt) = {
            let mut b = lk(&self.out);
            if b.chans.get(origin).is_some_and(|c| !c.pending.is_empty()) {
                return Ok(None);
            }
            let Some(mut nxt) = b.next_chans.shift_remove(origin) else { return Ok(None) };
            let mut from = String::new();
            if let Some(mut old) = b.chans.get(origin).cloned() {
                if LIVE.contains(&old.state.as_str()) {
                    old.retired = true;
                }
                nxt.max_lock = nxt.max_lock.max(old.max_lock);
                nxt.last_lock_at = nxt.last_lock_at.max(old.last_lock_at);
                from = old.params.channel_id();
                b.archived.push(old.to_json());
            }
            b.chans.insert(origin.into(), nxt.clone());
            b.save()?;
            (from, nxt)
        };
        self.event(json!({"event": "ch2_switch", "provider": origin, "from": from, "to": nxt.params.channel_id(), "why": why}));
        Ok(Some(nxt))
    }

    /// Why there is no open ch2 to `origin`, for the client (AGP-056: a refusal names its cause).
    fn no_channel(&self, origin: &str, oc: Option<&OutChannel>) -> String {
        let Some(oc) = oc else {
            let b = lk(&self.out);
            let other = b.origins.get(origin).and_then(|pt| b.live_keys(pt).into_iter().find(|k| k != origin));
            return match other {
                Some(o) => format!("no open channel to that provider: its payTo has a ch2 at {o}, another provider process (a ch2 serves the origin it was opened at)"),
                None => "no open channel to that provider".into(),
            };
        };
        if oc.state == "funded" && !oc.rolled_from.is_empty() {
            return "no open channel to that provider: its ch2 is a rollover the provider takes once it confirms".into();
        }
        format!("no open channel to that provider: its ch2 is {}", oc.state)
    }

    /// Pre-sign ch2 under T (only now), send it to the provider, settle ch1 with t + r.
    fn forward(&self, ch1: &str, oc: &OutChannel, lock1: &Value, rt: &Value, t0: Instant) -> HttpResponse {
        let d = py_u64(lock1.get("d")).unwrap_or(0);
        if self.withholding() == "all" {
            return err(504, "route_pending", "hub withholding (test)", json!({}));
        }
        let p2 = &oc.params;
        let need2 = next_cum(oc.routed, d, p2.min_amount());
        let t_hex = py_str(lock1.get("T"));
        let mut pre2 = None;
        if need2 > oc.signed {
            if need2 > p2.max_amount() {
                {
                    // the settle floor counts it (AGP-056): this ch2 is rolled over (or refilled) as soon as it is due
                    let mut b = lk(&self.out);
                    if let Some(c) = b.chans.get_mut(&oc.origin).filter(|c| c.params.channel_id() == p2.channel_id()) {
                        c.max_lock = c.max_lock.max(d);
                        let _ = b.save();
                    }
                }
                self.void(Loc::Live(&oc.origin), oc, ch1, &lock1["lockId"], "ch2 exhausted", "");
                return e400("route_failed", "the hub's channel to that provider is exhausted");
            }
            // AGP-094 rule: no request of a client's stops the hub routing to a provider. A lock
            // carries what only the client and the provider can check (`lockAuth`, the session, the
            // amount the client authorised), and a refusal after the pre-signature left writes the
            // lock off and blocks this ch2 (AGP-064). So the provider is asked first, with nothing
            // of the hub's out: what it refuses here costs nothing and leaves the ch2 as it was
            if let Err((code, det)) = self.check_lock(oc, &lock1["lockId"], d, need2, &t_hex, rt) {
                self.void(Loc::Live(&oc.origin), oc, ch1, &lock1["lockId"], &format!("provider refused the check: {code}"), "");
                *lk(&self.stats).refused.entry(code.clone()).or_insert(0) += 1;
                let shown = if safe_code(&code) { code.as_str() } else { "provider_error" };
                let detail = if det.is_empty() { format!("provider refused the lock: {shown}") } else { format!("provider refused the lock: {shown} ({det})") };
                return err(502, "route_failed", &detail, json!({"providerError": code}));
            }
            let signed = (|| -> Result<PreSig> {
                let t = adaptor::dec_hex(&t_hex)?;
                adaptor::presign(&oc.secret_key()?, &p2.sighash(&p2.state_tx(need2)?)?, &t)
            })();
            match signed {
                Ok(p) => pre2 = Some(p),
                Err(e) => {
                    self.void(Loc::Live(&oc.origin), oc, ch1, &lock1["lockId"], "ch2 pre-sign failed", "");
                    return e400("route_failed", &e.to_string());
                }
            }
        }
        let at = now_f();
        let pending = json!({"lockId": lock1["lockId"], "cum": need2.max(oc.signed), "pre": pre2.as_ref().map(PreSig::to_json),
                             "T": t_hex, "d": d, "ch1": ch1, "at": round3(at),
                             "route": {"session": rt.get("session").cloned().unwrap_or(Value::Null), "lockId": lock1["lockId"], "amount": d,
                                       "lockAuth": rt.get("lockAuth").map(|v| py_str(Some(v))).unwrap_or_default(), "hub": self.pay_to}});
        {
            // write-ahead: pre2 before it leaves
            let mut b = lk(&self.out);
            let Some(c) = b.chans.get_mut(&oc.origin).filter(|c| c.params.channel_id() == p2.channel_id()) else {
                drop(b);
                self.void(Loc::Live(&oc.origin), oc, ch1, &lock1["lockId"], "ch2 replaced", "");
                return e400("route_failed", "the hub's channel to that provider changed");
            };
            c.pending = pending.as_object().cloned().unwrap_or_default();
            if let Err(e) = b.save() {
                return err(500, &e.code, &e.to_string(), json!({}));
            }
        }
        // wait for t up to revealTimeoutSec (a provider may hold a lock without answering): then write
        // the lock off, stop routing to that provider, and tell the client, so its ch1 is free again
        let ans = loop {
            let ans = self.send_lock(&oc.origin);
            if ans.is_some() || now_f() - at >= self.reveal_timeout() {
                break ans;
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        let Some(ans) = ans else {
            let view = self.void(Loc::Live(&oc.origin), oc, ch1, &lock1["lockId"], "no reveal within revealTimeoutSec", "the provider did not reveal a lock in time");
            return err(502, "route_failed", "provider did not reveal within revealTimeoutSec", view);
        };
        if let Some(code) = ans.get("error").and_then(Value::as_str) {
            let mut view = self.void(Loc::Live(&oc.origin), oc, ch1, &lock1["lockId"], &format!("provider refused: {code}"), "");
            *lk(&self.stats).refused.entry(code.to_string()).or_insert(0) += 1;
            let shown = if safe_code(code) { code } else { "provider_error" };
            let det = ans.get("detail").and_then(Value::as_str).unwrap_or("");
            let detail = if det.is_empty() { format!("provider refused the lock: {shown}") } else { format!("provider refused the lock: {shown} ({det})") };
            view["providerError"] = code.into();
            return err(502, "route_failed", &detail, view);
        }
        let out = self.settled(ch1, &oc.origin, &ans);
        lk(&self.stats).lock_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
        let Some(out) = out else { return err(504, "route_pending", "provider answer did not open the lock", json!({})) };
        if self.withholding() == "receipt" {
            return err(504, "route_pending", "hub withholding the receipt (test)", json!({}));
        }
        ok_json(&out)
    }

    /// POST the pending ch2 lock (a fresh seq and auth each time: idempotent at the provider).
    /// `Some({secret...})`, `Some({"error": code})` (refused), or None (no answer yet).
    fn send_lock(&self, origin: &str) -> Option<Value> {
        if self.withholding() == "all" {
            return None;
        }
        let (oc, seq) = {
            let mut b = lk(&self.out);
            let c = b.chans.get_mut(origin)?;
            if c.pending.is_empty() {
                return None;
            }
            c.seq += 1;
            let r = (c.clone(), c.seq);
            b.save().ok()?;
            r
        };
        let pend = &oc.pending;
        let mut pl = json!({"chan": oc.params.channel_id(), "seq": seq, "cum": py_str(pend.get("cum")), "point": pend.get("T").cloned().unwrap_or(Value::Null)});
        if truthy(pend.get("pre")) {
            pl["adaptor"] = pend["pre"].clone();
        }
        let (status, doc) = self.post_lock(&oc, pl, pend.get("route").unwrap_or(&Value::Null))?;
        if status == 200 && doc.is_object() && truthy(doc.get("secret")) {
            return Some(doc);
        }
        Self::lock_refusal(status, &doc)
    }

    /// POST `pl` (a ch2 payload with its seq; the auth is added here) and the route terms to the
    /// provider's lock endpoint: the status and the JSON answer, None when there is none.
    fn post_lock(&self, oc: &OutChannel, mut pl: Value, route: &Value) -> Option<(u16, Value)> {
        let (p2, url) = (&oc.params, format!("{}{ROUTE_LOCK_PATH}", oc.origin));
        let body = dumps(&json!({"route": route}));
        let key = channel_auth_key(&oc.secret_key().ok()?, &p2.payee_pub).ok()?;
        pl["auth"] = request_auth(&key, &p2.channel_id(), pl.get("seq"), pl.get("cum"), None, &request_digest_v2("POST", &url, body.as_bytes())).into();
        let hdrs = vec![("PAYMENT-SIGNATURE".to_string(), b64json(&json!({"x402Version": 2, "accepted": oc.terms, "payload": pl}))),
                        ("Content-Type".to_string(), "application/json".to_string())];
        let r = self.http.request("POST", &url, body.as_bytes(), &hdrs).ok()?;
        Some((r.status, crate::json::parse_slice(&r.body).ok()?))
    }

    /// A provider's refusal of a lock (400, 401, 403 with an error code) as `{"error", "detail"}`.
    fn lock_refusal(status: u16, doc: &Value) -> Option<Value> {
        if [400, 401, 403].contains(&status) {
            if let Some(e) = doc.get("error").and_then(Value::as_str) {
                let code: String = e.chars().take(40).collect();
                // the detail is the provider's free text (untrusted): printable ASCII only, bounded
                let det: String = doc.get("detail").and_then(Value::as_str).unwrap_or("").chars().take(160).filter(|c| (' '..='~').contains(c)).collect();
                // B1's str(ChannelError) leads with its code
                let det = det.strip_prefix(code.as_str()).map(|r| r.trim_start_matches([':', ' '])).unwrap_or(&det).to_string();
                return Some(json!({"error": code, "detail": det}));
            }
        }
        None
    }

    /// AGP-094: ask the provider whether it would take the lock `lock_id` of `d` at `need2` on
    /// `oc`, before anything is pre-signed for it: the request the lock itself will be, marked
    /// `check` and without the pre-signature. `Err((code, detail))`: it refused, or did not
    /// answer (`no_answer`). A provider from before the check runs the request as a lock and stops
    /// at the missing pre-signature (`bad_adaptor`), after every check a client's fields can fail:
    /// that is its yes.
    fn check_lock(&self, oc: &OutChannel, lock_id: &Value, d: u64, need2: u64, t_hex: &str, rt: &Value) -> std::result::Result<(), (String, String)> {
        let none = || ("no_answer".to_string(), "the provider did not answer the check".to_string());
        let seq = {
            let mut b = lk(&self.out);
            let c = b.chans.get_mut(&oc.origin).filter(|c| c.params.payer_pub == oc.params.payer_pub).ok_or_else(none)?;
            c.seq = c.seq.checked_add(1).ok_or_else(none)?;
            let seq = c.seq;
            b.save().map_err(|_| none())?;
            seq
        };
        let route = json!({"session": rt.get("session").cloned().unwrap_or(Value::Null), "lockId": lock_id, "amount": d,
                           "lockAuth": rt.get("lockAuth").map(|v| py_str(Some(v))).unwrap_or_default(), "hub": self.pay_to, "check": true});
        let pl = json!({"chan": oc.params.channel_id(), "seq": seq, "cum": need2.to_string(), "point": t_hex});
        let (status, doc) = self.post_lock(oc, pl, &route).ok_or_else(none)?;
        if status == 200 && doc.get("check") == Some(lock_id) {
            return Ok(());
        }
        match Self::lock_refusal(status, &doc) {
            Some(r) if r["error"] == "bad_adaptor" => Ok(()),
            Some(r) => Err((py_str(r.get("error")), py_str(r.get("detail")))),
            None => Err(none()),
        }
    }

    /// The provider revealed t: check it, fold ch2, complete ch1 with t + r.
    fn settled(&self, ch1: &str, origin: &str, ans: &Value) -> Option<Value> {
        let oc = lk(&self.out).chans.get(origin)?.clone();
        let pend = oc.pending.clone();
        if pend.is_empty() || ans.get("lockId") != pend.get("lockId") {
            return None; // settled already (idempotent)
        }
        let t = Sc::from_hex_mod_n(ans.get("secret")?.as_str()?)?.secret()?;
        if Some(adaptor::point_of(&t)) != adaptor::dec_hex(&py_str(pend.get("T"))).ok() {
            return None; // bad_secret: keep the lock pending
        }
        // ch1 first (AGP-073): a stop between the two leaves the ch2 lock pending, which the
        // provider's answer or its close completes again; the other order left a ch1 lock with no
        // ch2 lock, which the watcher's sweep would drop unpaid
        let done = match self.complete_ch1(ch1, &py_str(pend.get("lockId")), &oc, &t, "provider") {
            Ok(d) => d,
            Err(e) => {
                // ch1 did not take the write: the lock stays pending here and is settled again
                self.watch_error(origin, "complete_ch1", &e);
                return None;
            }
        };
        let mut b = lk(&self.out);
        if let Some(c) = b.chans.get_mut(origin).filter(|c| c.params.payer_pub == oc.params.payer_pub && c.pending.get("lockId") == pend.get("lockId")) {
            c.signed = c.signed.max(py_u64(pend.get("cum")).unwrap_or(0));
            let to = c.routed.saturating_add(py_u64(pend.get("d")).unwrap_or(0));
            // AGP-094: the provider's own total after this lock (`routedSat`), when it is below
            // ours, says it answered a lock it had completed before (the same invoice sent again
            // from another ch1): the client paid again, the provider counted once, and so do we.
            // Counting it would put every later lock on this ch2 above what the provider expects
            c.routed = py_u64(ans.get("routedSat")).filter(|r| *r >= c.routed).map_or(to, |r| r.min(to));
            c.max_lock = c.max_lock.max(py_u64(pend.get("d")).unwrap_or(0));
            c.last_lock_at = (now_f() * 1000.0).round() / 1000.0;
            c.pending = Map::new();
            b.save().ok()?;
        }
        done
    }

    /// Complete ch1's lock `lock_id` over the ch2 `ch2` (its current one or a written-off one) with
    /// t + r. A lock it completed already gets the same answer again (a stop between this and the
    /// ch2 write). AGP-088: the lock of THAT ch2 ([`is_lock`]), and only with the t that opens its
    /// own T; a written-off lock of another ch2 under the same lockId stays where it is.
    ///
    /// AGP-094: `Err` is ch1's ledger not taking the write. The lock is then still ch1's, and the
    /// caller leaves it on the ch2 record too, for the next answer or tick: clearing it there
    /// (as before) left a lock on ch1 that nothing would complete.
    fn complete_ch1(&self, ch1: &str, lock_id: &str, ch2: &OutChannel, t: &SecretKey, via: &str) -> Result<Option<Value>> {
        let mut saved = Ok(());
        let done = self.complete_ch1_in(ch1, lock_id, ch2, t, via, &mut saved);
        saved.map(|()| done)
    }

    fn complete_ch1_in(&self, ch1: &str, lock_id: &str, ch2: &OutChannel, t: &SecretKey, via: &str, saved: &mut Result<()>) -> Option<Value> {
        let mut l = self.inbound.ledger_lock();
        let mut st1 = l.channels.get(ch1)?.clone();
        let mut ex = st1.extra.clone();
        let current = ex.get("route_lock").filter(|x| is_lock(x, lock_id, ch2)).cloned();
        let stale_at = ex.get("stale_locks").and_then(Value::as_array).and_then(|s| s.iter().position(|x| is_lock(x, lock_id, ch2)));
        let (lock1, stale) = match (current, stale_at) {
            (Some(x), _) => (x, None),
            (None, Some(i)) => (ex["stale_locks"][i].clone(), Some(i)),
            (None, None) => {
                let done = ex.get("route_done").and_then(|d| d.get(lock_id)).cloned();
                let rec = || ex.get("recovered").and_then(Value::as_array)?.iter().find(|r| r.get("lockId").and_then(Value::as_str) == Some(lock_id)).cloned();
                return done.or_else(rec);
            }
        };
        if adaptor::dec_hex(&py_str(lock1.get("T"))).ok() != Some(adaptor::point_of(t)) {
            return None;
        }
        let r = Sc::from_hex_mod_n(&py_str(lock1.get("r")))?;
        let s1 = Sc::from_secret(t).add(&r);
        let lcum = py_u64(lock1.get("cum")).unwrap_or(0);
        // ch1 closed below this lock (the operator's close_now, or the margin close past its wait):
        // the provider is paid and the client is not charged. Never counted as routed (AGP-064 H1).
        let closed_below = !st1.closed_txid.is_empty() && st1.best_cum < lcum;
        if !truthy(lock1.get("floor")) {
            let pre1 = PreSig::from_json(lock1.get("pre")?).ok()?;
            let mut sig1 = adaptor::adapt(&pre1, &s1.secret()?).ok()?;
            sig1.push(SIGHASH_ALL_UNIFIED);
            if lcum > st1.best_cum && st1.closed_txid.is_empty() {
                self.inbound.payee(&st1).ok()?.accept(lcum, &sig1).ok()?;
                st1.best_cum = lcum;
                st1.best_sig = hex::encode(&sig1);
                // AGP-088: what a client checks before it counts this lock as paid (`ch1_view`)
                ex.insert("best_lock".into(), json!({"cum": lcum, "secret": s1.hex()}));
            }
        }
        let ans = json!({"lockId": lock_id, "secret": s1.hex(), "cum": lcum.max(st1.best_cum).to_string(), "fee": lock1["f"],
                         "amount": lock1["d"], "via": via});
        if let Some(i) = stale {
            // this one lock leaves, by its place: never every lock that carries its lockId
            if let Some(locks) = ex.get_mut("stale_locks").and_then(Value::as_array_mut) {
                locks.remove(i);
            }
            let mut rec = ans.clone();
            rec["at"] = round3(now_f());
            let mut recovered = ex.get("recovered").and_then(Value::as_array).cloned().unwrap_or_default();
            recovered.push(rec);
            ex.insert("recovered".into(), Value::Array(recovered));
            // a held lock is in the base already (AGP-064); one written off before that is counted
            // once it is our best state
            let held = lock1.get("hold").is_some_and(Value::is_object);
            if let Some(aft) = lock1.get("after").filter(|a| a.is_object() && !held) {
                if st1.best_cum == lcum {
                    for (k, a) in COUNTERS.iter().zip(LOCK_COUNTERS) {
                        let v = u128_of(ex.get(*k)).unwrap_or(0).max(u128_of(aft.get(a)).unwrap_or(0));
                        ex.insert((*k).into(), int_value(v));
                    }
                }
            }
        } else if closed_below {
            ex.insert("route_lock".into(), Value::Null);
        } else {
            let d = py_u64(lock1.get("d")).unwrap_or(0);
            let f = py_u64(lock1.get("f")).unwrap_or(0);
            ex.insert("route_lock".into(), Value::Null);
            ex.insert("routed_sat".into(), (py_u64(ex.get("routed_sat")).unwrap_or(0) + d + f).into());
            // AGP-085: by what the lock added, as the two others. `units` was fixed at admission: a
            // hold released since is not in the base any more, and writing `units` would put it back
            let units = match u128_of(lock1.get("unitsBy")) {
                Some(by) => int_value(u128_of(ex.get("fee_units")).unwrap_or(0) + by),
                None => lock1.get("units").cloned().unwrap_or(Value::from(0)),
            };
            ex.insert("fee_units".into(), units);
            ex.insert("fee_paid".into(), (py_u64(ex.get("fee_paid")).unwrap_or(0) + f).into());
            let mut done = ex.get("route_done").and_then(Value::as_object).cloned().unwrap_or_default();
            done.insert(lock_id.to_string(), ans.clone());
            while done.len() > 64 {
                // the recent answers, for client retries
                let first = done.keys().next().cloned().unwrap_or_default();
                done.remove(&first);
            }
            ex.insert("route_done".into(), Value::Object(done));
        }
        st1.extra = ex;
        if let Err(e) = self.stop("complete_ch1").and_then(|()| self.inbound.save_state(&mut l, &st1)) {
            *saved = Err(e);
            return None;
        }
        drop(l);
        if closed_below {
            lk(&self.stats).uncollected += 1;
            self.event(json!({"event": "lock_uncollected", "chan": ch1, "lockId": lock_id, "cum": lcum, "closedAt": st1.best_cum,
                              "close": st1.closed_txid}));
            return Some(ans);
        }
        let mut s = lk(&self.stats);
        s.routed += 1;
        if truthy(lock1.get("floor")) {
            s.floor += 1;
        }
        Some(ans)
    }

    /// Write both locks off: the lock `lock_id` of `ch1`, and the one pending on the ch2 record at
    /// `loc`. If the ch2 pre-signature may have left (that lock was pending on the ch2), they are
    /// kept for on-chain recovery, and ch1's lock stays in its base until that ch2 resolves
    /// (AGP-064 H2): a later lock is quoted above it, so a `t` read off the ch2 close later still
    /// collects, and routing over that ch2 or rolling it over waits. Otherwise nothing can complete
    /// the lock and ch1's is dropped. Returns ch1's view for the client when the lock is held.
    ///
    /// AGP-088: the ch2 record may be anywhere (`loc`: a ch2 that is closing or was replaced keeps
    /// its pending lock until the watcher writes it off), and ch1's `route_lock` is touched only
    /// if it is this lock.
    fn void(&self, loc: Loc<'_>, oc: &OutChannel, ch1: &str, lock_id: &Value, why: &str, block: &str) -> Value {
        let (out, _) = self.upd_raw(loc, oc, |c| {
            let mut out = false;
            if !c.pending.is_empty() {
                // a ch2 already resolved for good (its close or refund confirmed) can pay nothing more
                out = !c.final_ && c.pending.get("lockId") == Some(lock_id) && py_str(c.pending.get("ch1")) == ch1;
                let mut s = Value::Object(std::mem::take(&mut c.pending));
                if block.is_empty() && !truthy(s.get("pre")) {
                    // AGP-094: a lock the provider refused for which nothing was pre-signed (the
                    // ch2's floor covered it) left nothing with the provider to use later: it is
                    // dropped, not written off, and blocks nothing. (One the provider did not
                    // answer in time is kept as before: the provider may have counted it.)
                    out = false;
                } else {
                    s["voided"] = round3(now_f());
                    s["why"] = why.into();
                    c.stale.push(s);
                }
            }
            if !block.is_empty() {
                c.blocked = block.to_string();
            }
            out
        });
        let out = out.unwrap_or(false);
        let id = py_str(Some(lock_id));
        let mut l = self.inbound.ledger_lock();
        let (mut view, mut held) = (json!({}), false);
        if let Some(mut st1) = l.channels.get(ch1).cloned() {
            if let Some(mut rl) = st1.extra.get("route_lock").filter(|x| truthy(Some(x)) && is_lock(x, &id, oc)).cloned() {
                st1.extra.insert("route_lock".into(), Value::Null);
                if out {
                    rl["voided"] = round3(now_f());
                    hold_in_base(&mut st1.extra, &mut rl);
                    let mut stale = st1.extra.get("stale_locks").and_then(Value::as_array).cloned().unwrap_or_default();
                    stale.push(rl);
                    st1.extra.insert("stale_locks".into(), Value::Array(stale));
                    (view, held) = (ch1_view(&st1), true);
                }
                let _ = self.inbound.save_state(&mut l, &st1);
            }
        }
        drop(l);
        self.event(json!({"event": "void", "provider": oc.origin, "lockId": lock_id, "why": why, "blocked": !block.is_empty(), "held": held}));
        view
    }

    /// AGP-064: written-off locks of the ch2 `ch2`, which resolved without paying them (a confirmed
    /// refund, a confirmed close that does not reveal their t). Each `(ch1, lockId)` leaves ch1's
    /// `stale_locks`, and its hold leaves the base: the client is quoted below its best state again
    /// (the floor), so what it paid ahead for that lock pays its next ones. The lockId goes on
    /// ch1's `released` list, the last 64, for the client to resync on.
    ///
    /// AGP-088: only the locks of THAT ch2 ([`is_lock`]), each with its own hold. An error (ch1's
    /// ledger did not take the write) leaves the rest for the next tick: the caller has not
    /// cleared the ch2 record yet.
    fn release_unpaid(&self, locks: &[(String, String)], ch2: &OutChannel) -> Result<Vec<Value>> {
        let mut out = vec![];
        let mut failed = None;
        let mut l = self.inbound.ledger_lock();
        for (ch1, lid) in locks {
            let Some(mut st1) = l.channels.get(ch1).cloned() else { continue };
            let stale = st1.extra.get("stale_locks").and_then(Value::as_array).cloned().unwrap_or_default();
            let (gone, keep): (Vec<Value>, Vec<Value>) = stale.into_iter().partition(|s| is_lock(s, lid, ch2));
            if gone.is_empty() {
                continue;
            }
            st1.extra.insert("stale_locks".into(), Value::Array(keep));
            let mut evs = vec![];
            for s in &gone {
                let mut ev = json!({"event": "lock_released", "chan": ch1, "lockId": lid, "held": false});
                if let Some(hold) = s.get("hold").filter(|h| h.is_object()) {
                    for (k, a) in COUNTERS.iter().zip(LOCK_COUNTERS) {
                        let v = u128_of(st1.extra.get(*k)).unwrap_or(0).saturating_sub(u128_of(hold.get(a)).unwrap_or(0));
                        st1.extra.insert((*k).into(), int_value(v));
                    }
                    let mut rel = st1.extra.get("released").and_then(Value::as_array).cloned().unwrap_or_default();
                    rel.push(lid.as_str().into());
                    if rel.len() > 64 {
                        rel.remove(0);
                    }
                    st1.extra.insert("released".into(), Value::Array(rel));
                    ev["held"] = true.into();
                    ev["hold"] = hold.clone();
                }
                evs.push(ev);
            }
            match self.inbound.save_state(&mut l, &st1) {
                Ok(()) => out.append(&mut evs),
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        drop(l);
        for ev in &out {
            self.event(ev.clone());
        }
        match failed {
            Some(e) => Err(e),
            None => Ok(out),
        }
    }

    /// Release the written-off locks still on `oc` (its ch2 resolved without revealing them) and
    /// clear them from the ch2 record. AGP-088: ch1 first, and the caller makes the record final
    /// only after this. A stop after the ch1 write leaves the ch2 record with its locks, not final,
    /// and the next tick does it again (a lock already released is not found and nothing moves
    /// twice); the other order left a held lock on ch1 that nothing would ever release.
    fn release_stale(&self, loc: Loc<'_>, oc: &OutChannel) -> Result<Vec<Value>> {
        let Some(cur) = self.get(loc).filter(|c| c.params.payer_pub == oc.params.payer_pub && !c.stale.is_empty()) else { return Ok(vec![]) };
        let locks: Vec<(String, String)> = cur.stale.iter().map(|s| (py_str(s.get("ch1")), py_str(s.get("lockId")))).collect();
        let out = self.release_unpaid(&locks, &cur)?;
        self.stop("release")?;
        self.upd(loc, &cur, |c| c.stale.clear())?;
        Ok(out)
    }

    // --- hub-funded ch2 ----------------------------------------------------------------------------

    fn get_json(&self, url: &str) -> Result<(u16, Value)> {
        let r = self.http.request("GET", url, b"", &[])?;
        Ok((r.status, crate::json::parse_slice(&r.body).unwrap_or(Value::Null)))
    }

    fn post_json(&self, url: &str, v: &Value) -> Result<(u16, Value)> {
        let r = self.http.request("POST", url, dumps(v).as_bytes(), &[("Content-Type".into(), "application/json".into())])?;
        Ok((r.status, crate::json::parse_slice(&r.body).unwrap_or(Value::Null)))
    }

    /// Bound a provider's /terms before the hub funds anything (AGP-037): (capacity, blocks) or
    /// `bad_terms`. A provider must not be able to set a ch2 the hub can never use or get back: an
    /// expiry decades away, a close fee that eats the capacity, a minConf never reached. `bad_config`
    /// when `max_lock_sat` is more than half of the capacity it would be funded with (AGP-084).
    pub fn ch2_terms(&self, terms: &Value, capacity: Option<u64>, expiry_blocks: Option<u32>) -> Result<(u64, u32)> {
        let c = &self.cfg;
        let bad = |w: &str| ChannelError::new("bad_terms", format!("malformed /terms: {w}"));
        let ex = terms.get("extra").filter(|e| e.is_object()).ok_or_else(|| bad("extra"))?;
        let pay_to = terms.get("payTo").and_then(Value::as_str).and_then(|h| hex::decode(h).ok()).filter(|b| b.len() == 33);
        pay_to.ok_or_else(|| bad("payTo"))?;
        let num = |k: &str| py_u64(ex.get(k)).ok_or_else(|| bad(k));
        let close_fee = num("closeFeeSat")?;
        let min_cap = num("minCapacity")?;
        let min_conf = if ex.get("minConf").is_some() { num("minConf")? } else { 1 };
        // the payer's rule (funding::open_expiry_floor): the ch2 funding gets minConf plus the
        // provider's own close margin to confirm before the provider's expiry check refuses it
        let lo = crate::funding::open_expiry_floor(num("minExpiryBlocks")?, min_conf, num("closeMarginBlocks")?);
        let hi = num("maxExpiryBlocks")?.saturating_sub(1);
        let mult = if ex.get("settleMultiple").is_some() { num("settleMultiple")? } else { 20 };
        let max_blocks = if c.ch2_max_expiry_blocks > 0 { c.ch2_max_expiry_blocks as u64 } else { 2 * c.ch2_expiry_blocks as u64 };
        let max_min_cap = if c.ch2_max_min_capacity > 0 { c.ch2_max_min_capacity } else { c.ch2_capacity };
        let cap = capacity.unwrap_or(c.ch2_capacity).max(min_cap);
        // AGP-084: AGP-064's bound (a lock is at most half of a ch2) against the capacity this ch2
        // is funded with, which the caller may have chosen below the configured one
        if c.max_lock_sat.saturating_mul(2) > cap {
            return fail("bad_config", format!("max_lock_sat {} must be at most half of this ch2's capacity {cap}", c.max_lock_sat));
        }
        let why = if close_fee > c.ch2_max_close_fee_sat {
            format!("closeFeeSat {close_fee} > ch2_max_close_fee_sat {}", c.ch2_max_close_fee_sat)
        } else if close_fee.saturating_mul(c.ch2_close_fee_multiple) > cap {
            format!("{} x closeFeeSat {close_fee} > capacity {cap}", c.ch2_close_fee_multiple)
        } else if min_cap > max_min_cap {
            format!("minCapacity {min_cap} > ch2_max_min_capacity {max_min_cap}")
        } else if min_conf > c.ch2_max_min_conf {
            format!("minConf {min_conf} > ch2_max_min_conf {}", c.ch2_max_min_conf)
        } else if lo > max_blocks || lo > hi {
            format!("minExpiryBlocks + minConf + closeMarginBlocks = {lo} > max expiry {}", max_blocks.min(hi))
        } else if !(1..=c.ch2_max_settle_multiple).contains(&mult) {
            format!("settleMultiple {mult} outside [1, {}]", c.ch2_max_settle_multiple)
        } else {
            String::new()
        };
        if !why.is_empty() {
            return fail("bad_terms", why);
        }
        let want = expiry_blocks.unwrap_or(c.ch2_expiry_blocks) as u64;
        Ok((cap, want.max(lo).min(hi).min(max_blocks) as u32))
    }

    /// Fund a ch2 to `origin` from the hub's own wallet. It opens (the watcher) once the funding
    /// has the provider's minConf.
    ///
    /// One live ch2 per origin (AGP-056): if this origin already has a live ch2 to the payTo its
    /// /terms name, nothing is funded and that ch2 is returned; if its next ch2 was funded ahead
    /// (AGP-057), that one takes the place of a ch2 that is no longer live. Another origin under the
    /// same payTo is another provider process with its own ledger: it gets its own ch2, up to
    /// `ch2_max_per_pay_to` live ch2s for that key (`pay_to_limit` beyond it; nothing is funded).
    pub fn connect(&self, origin: &str, capacity: Option<u64>, expiry_blocks: Option<u32>) -> Result<OutChannel> {
        let origin = &canon_origin(origin);
        if lk(&self.out).chans.get(origin).is_some_and(|c| c.state == "funding") {
            return fail("ch2_funding", format!("a ch2 to {origin} is being funded (the watcher reconciles it)"));
        }
        let terms = self.terms(origin)?;
        let (cap, blocks) = self.ch2_terms(&terms, capacity, expiry_blocks)?;
        let pay_to = py_str(terms.get("payTo")).to_lowercase();
        let (own, ahead) = {
            let mut b = lk(&self.out);
            b.origins.insert(origin.clone(), pay_to.clone());
            let r = b.chans.get(origin).filter(|c| LIVE.contains(&c.state.as_str()) && c.pay_to.eq_ignore_ascii_case(&pay_to)).cloned();
            let ahead = b.next_chans.get(origin).is_some_and(|c| c.pay_to.eq_ignore_ascii_case(&pay_to));
            b.save()?;
            (r, ahead)
        };
        if let Some(oc) = own {
            if oc.state == "funding" {
                return fail("ch2_funding", format!("a ch2 to {origin} is being funded (the watcher reconciles it)"));
            }
            return Ok(oc);
        }
        if ahead {
            // its next ch2 is funded already (AGP-057): that one replaces the closed one, nothing is funded
            if let Some(nxt) = self.promote(origin, "refill")? {
                return Ok(nxt);
            }
        }
        self.fund_ch2(origin, &terms, cap, self.chain.block_count()? + blocks, false)
    }

    /// GET the provider's /terms: a JSON object with `extra` that offers the close-fee payer this hub
    /// funds ch2s with.
    fn terms(&self, origin: &str) -> Result<Value> {
        let (st, terms) = self.get_json(&format!("{origin}{TERMS_PATH}"))?;
        if st != 200 {
            return fail("provider_error", format!("terms: HTTP {st}"));
        }
        let ex = terms.get("extra").filter(|e| e.is_object()).ok_or_else(|| ChannelError::new("bad_terms", "terms are not a JSON object with extra"))?;
        let offered = ex.get("closeFeePayer").and_then(Value::as_str).unwrap_or("payer");
        if self.cfg.ch2_close_fee_payer == FeePayer::Payee && offered != "payee" {
            return fail("bad_fee_payer", format!("{origin} does not offer payee-pays routed channels (closeFeePayer {offered:?}); \
                                                  set ch2_close_fee_payer payer to fund it"));
        }
        Ok(terms)
    }

    /// Fund the origin's NEXT ch2 from the hub's wallet while its live one still routes (AGP-057: the
    /// default ahead refill). It opens at the provider's minConf (the watcher) and takes over at the
    /// switch. At most one per origin: an origin that has one gets it back and nothing is funded.
    ///
    /// Refused, nothing funded: `no_live_ch2` (the origin has no funded or open ch2: `connect` funds
    /// one), `pay_to_changed` (its /terms now name another payTo than the live ch2's), `liquidity_cap`
    /// (the live and the next ch2 both count), and `connect`'s `bad_terms` / `bad_fee_payer` /
    /// `pay_to_limit`.
    pub fn connect_next(&self, origin: &str, capacity: Option<u64>, expiry_blocks: Option<u32>) -> Result<OutChannel> {
        let origin = &canon_origin(origin);
        let (cur, nxt) = {
            let b = lk(&self.out);
            (b.chans.get(origin).cloned(), b.next_chans.get(origin).cloned())
        };
        if let Some(n) = nxt {
            if n.state == "funding" {
                return fail("ch2_funding", format!("the next ch2 to {origin} is being funded (the watcher reconciles it)"));
            }
            return Ok(n);
        }
        let Some(cur) = cur.filter(|c| c.state == "funded" || c.state == "open") else {
            return fail("no_live_ch2", format!("{origin} has no live ch2 to fund ahead of"));
        };
        let terms = self.terms(origin)?;
        let (cap, blocks) = self.ch2_terms(&terms, capacity, expiry_blocks)?;
        if !py_str(terms.get("payTo")).eq_ignore_ascii_case(&cur.pay_to) {
            return fail("pay_to_changed", format!("{origin} now names another payTo than its live ch2's"));
        }
        self.fund_ch2(origin, &terms, cap, self.chain.block_count()? + blocks, true)
    }

    /// Write-ahead (AGP-037): the ch2's key and params are on disk, state `funding`, before the
    /// wallet runs, and the cap check and that record are one step under the book's lock. `ahead`
    /// (AGP-057): the record is the origin's next ch2 (`next_chans`), beside its live one.
    fn fund_ch2(&self, origin: &str, terms: &Value, cap: u64, expiry: u32, ahead: bool) -> Result<OutChannel> {
        let secret = adaptor::random_secret();
        let pay_to = terms.get("payTo").and_then(Value::as_str).ok_or_else(|| ChannelError::new("bad_offer", "payTo"))?.to_string();
        let ex = terms.get("extra").cloned().unwrap_or(Value::Null);
        let close_fee = py_u64(ex.get("closeFeeSat")).ok_or_else(|| ChannelError::new("bad_offer", "closeFeeSat"))?;
        // AGP-104 (R1): the remainder of this ch2 returns to an address the operator controls. A
        // hook that fails funds nothing: a ch2 is never funded on its own key because the wallet
        // was away
        let ret = self.return_spk()?;
        let mut p = ChannelParams::derive(&hex::decode(&pay_to).map_err(|_| ChannelError::new("bad_offer", "payTo"))?, &ecdsa::pubkey(&secret),
                                          expiry, close_fee, ret, &self.network, self.cfg.ch2_close_fee_payer)?;
        p.capacity = cap;
        let address = segwit_address(&self.cfg.hrp, &p.spk())?;
        // AGP-104: a wallet that cannot fund now (no fee rate) says so before a record exists
        self.wallet.preflight()?;
        self.preflight_ch2(origin, terms, &p)?;
        let tip = self.chain.block_count()?;
        let oc = OutChannel::fresh(origin, &pay_to, p, &secret, "funding", py_u64(ex.get("settleMultiple")).unwrap_or(20), terms, tip);
        {
            let mut b = lk(&self.out);
            let old = b.chans.get(origin).cloned();
            if old.as_ref().is_some_and(|o| o.state == "funding") {
                return fail("ch2_funding", format!("a ch2 to {origin} is being funded"));
            }
            if ahead {
                // at most one live ch2 plus one next per origin (AGP-057), checked with the record's insert
                if b.next_chans.contains_key(origin) {
                    return fail("ch2_funding", format!("a next ch2 to {origin} exists"));
                }
                if !old.as_ref().is_some_and(|o| LIVE.contains(&o.state.as_str()) && o.pay_to.eq_ignore_ascii_case(&pay_to)) {
                    return fail("no_live_ch2", format!("{origin} has no live ch2 to fund ahead of"));
                }
            } else if old.as_ref().is_some_and(|o| LIVE.contains(&o.state.as_str()) && o.pay_to.eq_ignore_ascii_case(&pay_to)) {
                // one live ch2 per origin, checked with the record's insert (two connects racing)
                return fail("ch2_funding", format!("a live ch2 to {origin} exists"));
            } else if old.as_ref().is_some_and(|o| !o.pending.is_empty()) {
                // AGP-088: the ch2 this would replace (its payTo changed, or it is closing) has a
                // lock pending: it keeps its place until that lock is completed or written off
                return fail("lock_pending", format!("a lock is pending on the ch2 to {origin} this would replace"));
            }
            let others: Vec<String> = b.live_keys(&pay_to).into_iter().filter(|k| k != origin).collect();
            let limit = self.cfg.ch2_max_per_pay_to as usize;
            if limit > 0 && others.len() >= limit {
                let some: Vec<&str> = others.iter().take(3).map(String::as_str).collect();
                return fail("pay_to_limit", format!("payTo {}... has {} live ch2s ({}): ch2_max_per_pay_to {limit}",
                                                    pay_to.get(..16).unwrap_or(&pay_to), others.len(), some.join(", ")));
            }
            let limit_sat = self.cfg.liquidity_cap();
            if limit_sat > 0 {
                // AGP-094: nothing is taken off for the ch2 this replaces (its /terms now name
                // another payTo). It goes to the archive unspent and `committed` goes on counting
                // it there, so taking it off here funded one ch2 past the cap
                let c = committed(&b);
                // AGP-104: a first funding leaves `capital_sat`'s spare free; one funded ahead uses it
                let spare = if ahead { 0 } else { self.cfg.spare_sat() };
                if c.saturating_add(cap).saturating_add(spare) > limit_sat {
                    let what = if self.cfg.capital_sat > 0 { "capital_sat" } else { "liquidity_cap_sat" };
                    let kept = if spare > 0 { format!(" + {spare} kept for funding ahead") } else { String::new() };
                    return fail("liquidity_cap", format!("{c} + {cap} sat{kept} > {what} {limit_sat}"));
                }
            }
            if ahead {
                b.next_chans.insert(origin.into(), oc.clone());
            } else {
                if let Some(mut old) = old {
                    if LIVE.contains(&old.state.as_str()) {
                        // (AGP-094) replaced while its coins are committed: the watcher has the
                        // provider close it, as it does a ch2 its next one replaced
                        old.retired = true;
                    }
                    b.archived.push(old.to_json());
                }
                b.chans.insert(origin.into(), oc.clone());
            }
            b.origins.insert(origin.into(), pay_to.to_lowercase());
            b.save()?;
        }
        let loc = if ahead { Loc::Next(origin) } else { Loc::Live(origin) };
        let (txid, vout) = match self.wallet.fund(&address, cap) {
            Ok(r) => r,
            Err(e) => {
                // it may have broadcast: the record stays for the watcher
                let msg: String = e.to_string().chars().take(200).collect();
                self.upd(loc, &oc, |c| c.fund_error = msg.clone())?;
                self.event(json!({"event": "ch2_fund_failed", "provider": origin, "error": msg}));
                return fail("fund_failed", format!("fund hook: {msg} (the watcher reconciles the record)"));
            }
        };
        self.funded(loc, &oc, &txid, vout, cap)?;
        Ok(self.get(loc).unwrap_or(oc))
    }

    /// Ask the provider whether it opens `p` (not funded yet) for this hub before anything is written
    /// or funded (review C2, AGP-073): a refusal after the funding locks the capacity until the refund.
    /// A provider from before the preflight answers `bad_request` (no outpoint), having passed the
    /// terms it checks before the outpoint: that alone lets the funding go ahead.
    fn preflight_ch2(&self, origin: &str, terms: &Value, p: &ChannelParams) -> Result<()> {
        let mut c = json!({"capacity": p.capacity, "expiry": p.expiry, "payerPub": hex::encode(p.payer_pub), "payerSpk": hex::encode(&p.payer_spk),
                           "redeemScript": hex::encode(p.script())});
        if p.close_fee_payer != FeePayer::Payer {
            c["closeFeePayer"] = p.close_fee_payer.as_str().into();
        }
        let body = json!({"x402Version": 2, "network": self.network, "preflight": true, "channel": c, "hub": {"payTo": self.pay_to}});
        let open_url = terms.get("extra").and_then(|e| e.get("openUrl")).and_then(Value::as_str).unwrap_or(OPEN_PATH);
        let (st, doc) = self.post_json(&crate::wire::seller_url(origin, open_url)?, &body)?;
        if st != 200 {
            let code = doc.get("error").and_then(Value::as_str).filter(|c| safe_code(c)).unwrap_or("provider_error");
            if code == "bad_request" {
                return Ok(());
            }
            let det: String = doc.get("detail").and_then(Value::as_str).unwrap_or("").chars().take(160).filter(|c| (' '..='~').contains(c)).collect();
            self.event(json!({"event": "ch2_preflight_refused", "provider": origin, "error": code, "detail": det}));
            return fail(code, format!("{origin} would not open this ch2: {det}"));
        }
        if doc.get("preflight") != Some(&Value::Bool(true)) {
            return fail("bad_open", format!("{origin} did not answer the open preflight"));
        }
        if doc.get("closeFeePayer").and_then(Value::as_str).unwrap_or("payer") != p.close_fee_payer.as_str() {
            return fail("bad_fee_payer", format!("{origin} would open this ch2 with another closeFeePayer"));
        }
        Ok(())
    }

    /// Apply `f` to the record at `loc` that is `oc`'s ch2 (same payer key), and save. None: gone.
    fn upd<R>(&self, loc: Loc<'_>, oc: &OutChannel, f: impl FnOnce(&mut OutChannel) -> R) -> Result<Option<R>> {
        let (r, saved) = self.upd_raw(loc, oc, f);
        saved.map(|()| r)
    }

    /// [`upd`](Self::upd), with what `f` returned even when the save failed (the change is in
    /// memory, and the next save writes it).
    fn upd_raw<R>(&self, loc: Loc<'_>, oc: &OutChannel, f: impl FnOnce(&mut OutChannel) -> R) -> (Option<R>, Result<()>) {
        let mut b = lk(&self.out);
        let r = match loc {
            Loc::Live(origin) => b.chans.get_mut(origin).filter(|c| c.params.payer_pub == oc.params.payer_pub).map(f),
            Loc::Next(origin) => b.next_chans.get_mut(origin).filter(|c| c.params.payer_pub == oc.params.payer_pub).map(f),
            Loc::Archived(i) => match b.archived.get(i).map(OutChannel::from_json) {
                Some(Ok(mut c)) if c.params.payer_pub == oc.params.payer_pub => {
                    let r = f(&mut c);
                    b.archived[i] = c.to_json();
                    Some(r)
                }
                _ => None,
            },
        };
        let saved = b.save();
        (r, saved)
    }

    fn get(&self, loc: Loc<'_>) -> Option<OutChannel> {
        let b = lk(&self.out);
        match loc {
            Loc::Live(origin) => b.chans.get(origin).cloned(),
            Loc::Next(origin) => b.next_chans.get(origin).cloned(),
            Loc::Archived(i) => b.archived.get(i).and_then(|v| OutChannel::from_json(v).ok()),
        }
    }

    fn funded(&self, loc: Loc<'_>, oc: &OutChannel, txid: &str, vout: u32, cap: u64) -> Result<()> {
        let p = oc.params.clone().with_funding(txid, vout, cap)?;
        let refund = p.refund_tx(&oc.secret_key()?, None, None)?.to_hex(); // fallback; the watcher refunds at its own fee
        // AGP-104: what the wallet paid for it, for the status's sum (None: the wallet does not say)
        let fee = self.wallet.send_fee(txid).ok().flatten();
        self.upd(loc, oc, |c| {
            c.params = p;
            c.state = "funded".into();
            c.refund_hex = refund;
            c.fund_txid = txid.to_string();
            c.fund_vout = vout;
            c.fund_fee = fee.or(c.fund_fee);
        })?;
        Ok(())
    }

    /// What the fund wallet knows of sends to this ch2's address (`listtransactions` +
    /// `gettransaction`), the record's own `fund_txid` first. Empty without a wallet view.
    fn wallet_sends(&self, oc: &OutChannel) -> Vec<WalletSend> {
        let Ok(addr) = segwit_address(&self.cfg.hrp, &oc.params.spk()) else { return vec![] };
        let mut txids: Vec<String> = if oc.fund_txid.is_empty() { vec![] } else { vec![oc.fund_txid.clone()] };
        match self.wallet.wallet_sends_to(&addr) {
            Ok(l) => txids.extend(l.into_iter().filter(|t| *t != oc.fund_txid)),
            Err(e) => eprintln!("hub: listtransactions for {}: {e}", oc.origin),
        }
        txids.into_iter().filter_map(|t| match self.wallet.wallet_send(&t, &addr) {
            Ok(Some(w)) => Some(w),
            // not the wallet's (an embedder's own fund hook): the record's own send, still checked on chain
            _ if t == oc.fund_txid => Some(WalletSend { txid: t, vout: oc.fund_vout, sats: 0, confirmations: 0, abandoned: false }),
            _ => None,
        }).collect()
    }

    /// `gettxout` incl. the mempool: the output's sats while it is unspent.
    fn utxo_sats(&self, txid: &str, vout: u32) -> Result<Option<u64>> {
        Ok(self.chain.get_tx_out(txid, vout, true)?.map(|u| u.value))
    }

    /// A `funding` record (the wallet call failed, or the hub stopped mid-fund). Where the funding may
    /// be (AGP-045, not only `scantxoutset`, which sees the confirmed UTXO set only): the sends the
    /// wallet knows (`gettransaction`), each checked with `gettxout` incl. the mempool and
    /// `getmempoolentry`, then `scantxoutset` (a fund hook outside the wallet). Found, in a block or
    /// the mempool -> funded, and the open goes on once it has minConf. Not found within
    /// `funding_timeout_blocks` -> dropped (archived with its key): a send the wallet still knows (not
    /// conflicted or abandoned) is watched while dropped and refunded at expiry if it confirms late; a
    /// genuinely failed send is final.
    fn reconcile_funding(&self, loc: Loc<'_>, origin: &str, oc: &OutChannel, tip: u32) -> Result<Vec<Value>> {
        let mut pending: Option<WalletSend> = None;
        for w in self.wallet_sends(oc) {
            if let Some(sats) = self.utxo_sats(&w.txid, w.vout)?.filter(|s| *s >= DUST) {
                return self.recovered(loc, origin, oc, &w.txid, w.vout, sats);
            }
            if w.failed() {
                continue; // conflicted or abandoned: never confirms
            }
            if pending.is_none() || self.scan.in_mempool(&w.txid).unwrap_or(false) {
                pending = Some(w);
            }
        }
        let hits = match self.scan.scan_spk(&oc.params.spk()) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("hub: scantxoutset for {origin}: {e}");
                vec![]
            }
        };
        if let Some((txid, vout, sats)) = hits.into_iter().find(|h| h.2 >= DUST) {
            return self.recovered(loc, origin, oc, &txid, vout, sats);
        }
        if tip.saturating_sub(oc.opened_at) < self.cfg.funding_timeout_blocks {
            return Ok(vec![]);
        }
        let mut watching = None;
        {
            let mut b = lk(&self.out);
            let next = matches!(loc, Loc::Next(_));
            let cur = if next { b.next_chans.get(origin) } else { b.chans.get(origin) };
            if let Some(mut c) = cur.filter(|c| c.params.payer_pub == oc.params.payer_pub).cloned() {
                c.state = "dropped".into();
                match &pending {
                    // its send may still confirm: keep watching it
                    Some(w) => {
                        c.fund_txid = w.txid.clone();
                        c.fund_vout = w.vout;
                        watching = Some(w.txid.clone());
                    }
                    None => c.final_ = true,
                }
                b.archived.push(c.to_json());
                if next {
                    b.next_chans.shift_remove(origin);
                } else {
                    b.chans.shift_remove(origin);
                }
            }
            b.save()?;
        }
        let mut ev = json!({"event": "ch2_funding_dropped", "provider": origin, "error": oc.fund_error});
        if let Some(t) = watching {
            ev["watching"] = t.into();
        }
        self.event(ev.clone());
        Ok(vec![ev])
    }

    fn recovered(&self, loc: Loc<'_>, origin: &str, oc: &OutChannel, txid: &str, vout: u32, sats: u64) -> Result<Vec<Value>> {
        self.funded(loc, oc, txid, vout, sats)?;
        let chan = self.get(loc).map(|c| c.params.channel_id()).unwrap_or_default();
        let ev = json!({"event": "ch2_funding_recovered", "provider": origin, "chan": chan, "txid": txid});
        self.event(ev.clone());
        Ok(vec![ev])
    }

    /// A dropped funding whose send is known (AGP-045). Its output appears (it confirmed late, or is
    /// back in the mempool) -> funded, in the archive: never opened, refunded at expiry by the
    /// reconcile like any unused ch2 (event `ch2_funding_late`). The wallet says it can never confirm
    /// (conflicted or abandoned) -> final (event `ch2_funding_failed`).
    fn reconcile_dropped(&self, i: usize) -> Result<Vec<Value>> {
        let loc = Loc::Archived(i);
        let Some(oc) = self.get(loc) else { return Ok(vec![]) };
        if let Some(sats) = self.utxo_sats(&oc.fund_txid, oc.fund_vout)?.filter(|s| *s >= DUST) {
            self.funded(loc, &oc, &oc.fund_txid, oc.fund_vout, sats)?;
            let p = self.get(loc).map(|c| c.params).unwrap_or(oc.params);
            let ev = json!({"event": "ch2_funding_late", "provider": oc.origin, "chan": p.channel_id(), "txid": oc.fund_txid,
                            "capacity": sats, "refundAt": p.expiry});
            self.event(ev.clone());
            return Ok(vec![ev]);
        }
        if let Some(w) = self.wallet_sends(&oc).into_iter().find(|w| w.txid == oc.fund_txid && w.failed()) {
            self.upd(loc, &oc, |c| c.final_ = true)?;
            let ev = json!({"event": "ch2_funding_failed", "provider": oc.origin, "txid": oc.fund_txid,
                            "why": if w.abandoned { "abandoned" } else { "conflicted" }});
            self.event(ev.clone());
            return Ok(vec![ev]);
        }
        Ok(vec![])
    }

    fn open(&self, oc: &OutChannel) -> Result<bool> {
        let p = &oc.params;
        let mut c = json!({"txid": p.funding_txid(), "vout": p.funding_vout(), "capacity": p.capacity, "expiry": p.expiry,
                           "payerPub": hex::encode(p.payer_pub), "payerSpk": hex::encode(&p.payer_spk), "redeemScript": hex::encode(p.script())});
        if p.close_fee_payer != FeePayer::Payer {
            c["closeFeePayer"] = p.close_fee_payer.as_str().into();
        }
        let body = json!({"x402Version": 2, "network": self.network, "channel": c,
                          "hub": {"payTo": self.pay_to, "sig": hex::encode(ecdsa::sign(&self.secret, &hub_channel_message(&p.channel_id())))}});
        let open_url = oc.terms.get("extra").and_then(|e| e.get("openUrl")).and_then(Value::as_str).unwrap_or(OPEN_PATH);
        let (st, doc) = self.post_json(&crate::wire::seller_url(&oc.origin, open_url)?, &body)?;
        if st != 200 {
            // said, not only returned (AGP-057): a refused open is why a ch2 stays `funded`
            let why: String = doc.to_string().chars().take(160).filter(|c| (' '..='~').contains(c)).collect();
            eprintln!("hub: open {} at {}: HTTP {st} {why}", p.channel_id(), oc.origin);
            return Ok(false);
        }
        let echoed = doc.get("closeFeePayer").and_then(Value::as_str).unwrap_or("payer");
        let mut b = lk(&self.out);
        let Some(c) = b.slot_mut(oc) else { return Ok(false) };
        if echoed != p.close_fee_payer.as_str() {
            // every state we would sign would fail at the provider: never route over this channel
            c.blocked = format!("the provider opened ch2 with closeFeePayer {echoed:?}");
            b.save()?;
            return Ok(false);
        }
        let mut zc = Map::new();
        if let Some(z) = doc.get("zeroConf").filter(|z| z.is_object()) {
            // AGP-053: the provider took this ch2 unconfirmed (a rollover child), bounded; a malformed
            // bound routes nothing until it confirms
            let (parent, max, until) = (z.get("parent").and_then(Value::as_str), py_u64(z.get("maxCum")), py_u64(z.get("until")));
            let (parent, max, until) = match (parent, max, until) {
                (Some(p), Some(m), Some(u)) => (p.to_string(), m, u),
                _ => (String::new(), 0, 0),
            };
            zc = json!({"parent": parent, "maxCum": max, "until": until, "confirmed": false}).as_object().cloned().unwrap_or_default();
        }
        c.state = "open".into();
        c.zero_conf = zc.clone();
        b.save()?;
        drop(b);
        let mut ev = json!({"event": "ch2_open", "provider": oc.origin, "chan": p.channel_id(), "capacity": p.capacity});
        if !zc.is_empty() {
            ev["zeroConf"] = zc["maxCum"].clone();
        }
        self.event(ev);
        Ok(true)
    }

    /// Open a rollover child before it confirms (AGP-053), at most once a block. Never fails.
    fn open_child(&self, new: Option<OutChannel>, parent: &str) -> bool {
        let Some(new) = new.filter(|n| self.cfg.zero_conf_rollover && n.state == "funded" && n.rolled_from == parent) else { return false };
        let tip = match self.chain.block_count() {
            Ok(t) => t,
            Err(_) => return false,
        };
        {
            let mut tried = lk(&self.zc_tried);
            if !tried.insert((new.params.channel_id(), tip)) {
                return false;
            }
            tried.retain(|(_, t)| *t + 1 >= tip);
        }
        match self.open(&new) {
            Ok(ok) => ok,
            Err(e) => {
                self.event(json!({"event": "ch2_open_failed", "provider": new.origin, "error": e.to_string().chars().take(200).collect::<String>()}));
                false
            }
        }
    }

    /// One tx pays the provider its balance and funds the next ch2 (rollover instead of close).
    /// The next ch2's key is written ahead (`next`), and its funding txid is known before the
    /// request leaves, so a lost answer is finished by the watcher when that tx spends the funding.
    ///
    /// AGP-085: the written-ahead next ch2 outlives every answer. The provider holds the request
    /// signed whatever it answered, so a refusal (400, 401, 403) that came with a broadcast would
    /// leave the next capacity in a script whose key the hub had dropped. A ch2 has ONE next key
    /// while its funding is unspent: a later attempt asks under the same key and expiry, so
    /// whichever attempt the provider broadcasts pays the one script the watcher looks for
    /// ([`Self::next_funded`]). Once that expiry no longer clears the payer's floor the hub asks
    /// for a close instead and still keeps `next`. It goes only when another spend of the funding
    /// confirms ([`Self::reconcile`]).
    pub fn rollover(&self, oc: &OutChannel) -> Result<Value> {
        // AGP-064 (H2): a rollover spends the funding a written-off lock's pre-signature is on, and
        // its secret could no longer be read off a close
        if !oc.pending.is_empty() || !oc.stale.is_empty() {
            return fail("lock_pending", "a lock on this ch2 is pending or written off and unresolved");
        }
        let p = &oc.params;
        let amount = oc.signed;
        let next_cap = p.rollover_next_capacity(amount);
        let min_cap = oc.term_u64("minCapacity").unwrap_or(0);
        let tip = self.chain.block_count()?;
        let (_, blocks) = self.ch2_terms(&oc.terms, None, None)?;
        let expiry = tip + blocks;
        // too small to keep: under the provider's minimum, or (AGP-056) it could not take one more lock of
        // the size this provider is paid in (it would sit exhausted and unsigned until its expiry)
        if next_cap < min_cap.max(p.min_amount()) || (oc.max_lock > 0 && next_cap.saturating_sub(p.payer_fee()) < oc.max_lock.max(p.min_amount())) {
            let waiting = lk(&self.out).next_chans.get(&oc.origin).is_some_and(|n| n.state == "funding" || n.state == "funded");
            if waiting && !exhausted(oc, oc.max_lock.max(1)) {
                // AGP-057: its next ch2 is funded but not open yet, and this one still takes a lock: it is
                // kept until the next one is usable or it is drained (closing it now would pause routing)
                return Ok(json!({"event": "ch2_wait_next", "provider": oc.origin, "chan": p.channel_id()}));
            }
            return self.close_ch2(oc, true);
        }
        // the next ch2 an earlier attempt wrote ahead, as the book has it now (AGP-085)
        let kept = match self.get(Loc::Live(&oc.origin)).filter(|c| c.params.payer_pub == p.payer_pub) {
            Some(c) if !c.next.is_empty() => Some(OutChannel::from_json(&Value::Object(c.next))?),
            Some(_) => None,
            None => return fail("bad_state", "the hub's channel to that provider changed"),
        };
        // AGP-104 (R1): the next ch2 returns where this one does. One written ahead keeps the script
        // every earlier attempt named (the provider may hold any of them); a ch2 on its own key
        // (from before AGP-104) takes a return address for its next one
        let ret = match &kept {
            Some(k) => Some(k.params.payer_spk.clone()),
            None if own_key(p) => self.return_spk()?,
            None => Some(p.payer_spk.clone()),
        };
        let (secret, expiry) = match &kept {
            Some(k) => {
                let floor = crate::funding::open_expiry_floor(oc.term_u64("minExpiryBlocks").unwrap_or(0), oc.term_u64("minConf").unwrap_or(1),
                                                              oc.term_u64("closeMarginBlocks").unwrap_or(0));
                if (k.params.expiry as u64) < tip as u64 + floor {
                    // too old to ask for again, and a second key would leave this one behind: close
                    return self.close_ch2(oc, true);
                }
                (k.secret_key()?, k.params.expiry)
            }
            None => (adaptor::random_secret(), expiry),
        };
        let nxt = ChannelParams::derive(&hex::decode(&oc.pay_to).unwrap_or_default(), &ecdsa::pubkey(&secret), expiry, p.close_fee, ret,
                                        &self.network, p.close_fee_payer)?;
        let tx = p.rollover_tx(amount, &nxt.spk(), next_cap)?;
        let txid = tx.txid();
        let nxt = nxt.with_funding(&txid, 1, next_cap)?;
        let mut new = OutChannel::fresh(&oc.origin, &oc.pay_to, nxt.clone(), &secret, "funded", oc.settle_multiple, &oc.terms, tip);
        new.refund_hex = nxt.refund_tx(&secret, None, None)?.to_hex();
        new.rolled_from = p.channel_id();
        new.max_lock = oc.max_lock;
        new.last_lock_at = oc.last_lock_at;
        new.rolled_at = (now_f() * 1000.0).round() / 1000.0;
        let next = new.to_json().as_object().cloned().unwrap_or_default();
        // write-ahead: the next ch2's key before the request
        if self.upd(Loc::Live(&oc.origin), oc, |c| c.next = next)?.is_none() {
            return fail("bad_state", "the hub's channel to that provider changed");
        }
        let sig = sign_with_type(&oc.secret_key()?, &p.sighash(&tx)?, SIGHASH_ALL_UNIFIED);
        let req = json!({"chan": p.channel_id(), "amount": amount, "sig": hex::encode(sig),
                         "next": {"payerPub": hex::encode(nxt.payer_pub), "payerSpk": hex::encode(&nxt.payer_spk), "expiry": expiry}});
        let (st, doc) = self.post_json(&format!("{}{ROLLOVER_PATH}", oc.origin), &req)
            .map_err(|e| ChannelError::new("provider_error", format!("rollover: {e}")))?;
        if st != 200 {
            // refused, it says: `next` stays (AGP-085), the chain decides
            let code = doc.get("error").and_then(Value::as_str).filter(|c| safe_code(c)).unwrap_or("provider_error");
            return fail(code, doc.to_string().chars().take(200).collect::<String>());
        }
        if py_str(doc.get("txid")).to_lowercase() != txid {
            return fail("bad_rollover_reply", format!("rollover reply {} is not tx {txid}", doc.to_string().chars().take(120).collect::<String>()));
        }
        let cur = self.get(Loc::Live(&oc.origin)).unwrap_or_else(|| oc.clone());
        let ev = self.finish_rollover(Loc::Live(&oc.origin), &cur, amount)?;
        // a hub on the provider's node sees the rollover at once (AGP-056); else the watcher's reconcile looks again
        if let Some(new) = self.get(Loc::Live(&oc.origin)).filter(|c| c.rolled_from == p.channel_id() && !c.fund_seen) {
            if matches!(self.chain.get_tx_out(&txid, 1, true), Ok(Some(_))) {
                self.upd(Loc::Live(&oc.origin), &new, |c| c.fund_seen = true)?;
            }
        }
        // make-before-break (AGP-053): open the next ch2 now, still under this provider's busy flag, so
        // the next lock goes over it; a provider that wants confirmations first refuses, and the watcher
        // opens it at minConf
        self.open_child(self.get(Loc::Live(&oc.origin)), &p.channel_id());
        Ok(ev)
    }

    fn finish_rollover(&self, loc: Loc<'_>, oc: &OutChannel, amount: u64) -> Result<Value> {
        let new = OutChannel::from_json(&Value::Object(oc.next.clone()))?;
        let txid = new.params.funding_txid();
        {
            let mut b = lk(&self.out);
            let mut old = oc.clone();
            old.state = "rolled".into();
            old.rolled_to = format!("{txid}:1");
            old.close_txid = txid.clone();
            old.next = Map::new();
            match loc {
                Loc::Live(origin) if b.chans.get(origin).is_some_and(|c| c.params.payer_pub == oc.params.payer_pub) => {
                    b.archived.push(old.to_json());
                    b.chans.insert(origin.into(), new.clone());
                }
                Loc::Archived(i) if i < b.archived.len() => {
                    b.archived[i] = old.to_json();
                    b.archived.push(new.to_json());
                }
                _ => {
                    b.archived.push(old.to_json());
                    b.archived.push(new.to_json());
                }
            }
            b.save()?;
        }
        let ev = json!({"event": "ch2_rollover", "provider": oc.origin, "txid": txid, "amount": amount, "next": new.params.channel_id(),
                        "nextCapacity": new.params.capacity});
        self.event(ev.clone());
        Ok(ev)
    }

    /// Ask the provider to close ch2 (payer-signed close request); with `refill`, fund a new one
    /// through the refill hook. The provider's reply must match the ledger (AGP-037): a 64-hex
    /// txid, cum = a state the hub signed (its best, or a pending or written-off lock's), and on a
    /// payee-pays ch2 payeeFee = the close fee, payeeNet = cum − payeeFee. Anything else is
    /// `bad_close_reply` and changes nothing: the watcher reads the real close off the chain. A good
    /// reply makes the ch2 `closing` (AGP-045): it is `closed` once the watcher sees the close confirm.
    pub fn close_ch2(&self, oc: &OutChannel, refill: bool) -> Result<Value> {
        self.close_ch2_at(Loc::Live(&oc.origin), oc, refill)
    }

    fn close_ch2_at(&self, loc: Loc<'_>, oc: &OutChannel, refill: bool) -> Result<Value> {
        let p = &oc.params;
        if oc.signed == 0 && oc.stale.is_empty() {
            // nothing signed on this ch2 (e.g. a fresh rollover): nothing to close; the hub's refund
            // (at expiry, by the watcher) returns the coins, or the next routed lock uses it
            let ev = json!({"event": "ch2_idle", "provider": oc.origin, "chan": p.channel_id(), "capacity": p.capacity});
            self.event(ev.clone());
            return Ok(ev);
        }
        let req = json!({"chan": p.channel_id(), "sig": hex::encode(ecdsa::sign(&oc.secret_key()?, &close_message(&p.channel_id())))});
        let close_url = oc.terms.get("extra").and_then(|e| e.get("closeUrl")).and_then(Value::as_str).unwrap_or(CLOSE_PATH);
        let (st, doc) = self.post_json(&crate::wire::seller_url(&oc.origin, close_url)?, &req)
            .map_err(|e| ChannelError::new("provider_error", format!("close: {e}")))?;
        if st != 200 {
            return fail("provider_error", doc.to_string().chars().take(200).collect::<String>());
        }
        let (txid, cum) = self.check_close_reply(oc, &doc)?;
        // AGP-088 rule: the provider's answer frees no coins and starts no funding; this node
        // showing the funding spent does. A hub on the provider's node sees the close at once
        let shown = self.spend_shown(oc);
        self.upd(loc, oc, |c| {
            c.close_prev = std::mem::replace(&mut c.state, "closing".into());
            c.close_txid = txid.clone();
            c.close_cum = Some(cum);
            c.spend_seen = shown;
            // AGP-094: the refill this close owes is in the same write as the close. Written
            // after it, a stop in between left a provider with no ch2 and nothing owed
            c.refill_owed = refill;
        })?;
        self.stop("closing")?;
        let mut ev = json!({"event": "ch2_close", "provider": oc.origin, "chan": p.channel_id(), "txid": txid, "amount": cum,
                            "payeeFee": p.payee_fee(), "payeeNet": cum.saturating_sub(p.payee_fee())});
        // (no new coins: the next ch2 was funded ahead, under the cap, while this one was open)
        let next = if refill { self.promote(&oc.origin, "closed")? } else { None };
        if let Some(nxt) = &next {
            // funded ahead (AGP-057): the next ch2 takes over, nothing more to fund
            ev["next"] = nxt.params.channel_id().into();
        } else if refill && shown {
            if let Err(msg) = self.refill_now(&oc.origin) {
                // the close stands; the refill is reported
                ev["refillError"] = msg.into();
            }
            // done, or refused once (the refill moved this record to the archive: then nothing reads the flag)
            let _ = self.upd(loc, oc, |c| c.refill_owed = false);
        } else if refill {
            // the close is the provider's word so far: the refill stays owed, and the watcher
            // funds it when its reconcile sees the funding spent
            let msg = "deferred: this node does not show the close yet (the refill follows when the watcher sees it)";
            ev["refillError"] = msg.into();
            self.event(json!({"event": "ch2_refill_deferred", "provider": oc.origin, "chan": p.channel_id(), "txid": txid}));
        }
        self.event(ev.clone());
        Ok(ev)
    }

    /// This node shows a spender of `oc`'s funding (mempool or a block). Not: `gettxout` answers
    /// nothing for it, which is also true of a funding that is not there.
    fn spend_shown(&self, oc: &OutChannel) -> bool {
        let (txid, vout) = (oc.params.funding_txid(), oc.params.funding_vout());
        matches!(self.chain.get_tx_out(&txid, vout, true), Ok(None)) && matches!(self.scan.find_spend(&txid, vout, oc.scanned_to), Ok(Some(_)))
    }

    /// Fund the ch2 that replaces a closed one, through the refill hook (default: `connect`). The
    /// error, reported (`ch2_refill_failed`), as text.
    fn refill_now(&self, origin: &str) -> std::result::Result<(), String> {
        let hook = lk(&self.refill).clone(); // looked up now; the lock is released before the call
        let r = match hook {
            Some(f) => f(self, origin),
            None => self.connect(origin, None, None).map(|_| ()),
        };
        r.map_err(|e| {
            let msg: String = e.to_string().chars().take(200).collect();
            self.event(json!({"event": "ch2_refill_failed", "provider": origin, "error": msg}));
            msg
        })
    }

    /// AGP-088: the refill a close left owed (`refill_owed`), now that this node shows that close.
    /// Once, as at the close: a refusal (the cap, the provider's /terms) is reported and not tried
    /// again. Called last by the reconcile: the refill moves this record to the archive.
    fn refill_if_owed(&self, loc: Loc<'_>, oc: &OutChannel) -> Vec<Value> {
        let Loc::Live(origin) = loc else { return vec![] };
        if !self.get(loc).is_some_and(|c| c.params.payer_pub == oc.params.payer_pub && c.refill_owed) {
            return vec![];
        }
        let mut ev = json!({"event": "ch2_refill", "provider": origin, "after": oc.params.channel_id()});
        if let Err(msg) = self.refill_now(origin) {
            ev["refillError"] = msg.into();
        }
        // (AGP-094) cleared after the refill, not before: a stop in between funds it on the next
        // tick, where `connect` finds a ch2 already funded and funds nothing more
        let _ = self.upd(loc, oc, |c| c.refill_owed = false);
        self.event(ev.clone());
        vec![ev]
    }

    fn check_close_reply(&self, oc: &OutChannel, doc: &Value) -> Result<(String, u64)> {
        let p = &oc.params;
        let bad = |why: String| {
            self.event(json!({"event": "ch2_close_bad_reply", "provider": oc.origin, "chan": p.channel_id(), "why": why}));
            ChannelError::new("bad_close_reply", why)
        };
        if !doc.is_object() {
            return Err(bad("not a JSON object".into()));
        }
        let txid = doc.get("txid").and_then(Value::as_str).filter(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()));
        let Some(txid) = txid else {
            return Err(bad(format!("txid {:?}", doc.get("txid").map(|v| v.to_string().chars().take(70).collect::<String>()))));
        };
        let cum = match doc.get("cum") {
            Some(Value::String(c)) => c.parse::<u64>().ok().filter(|_| c.bytes().all(|b| b.is_ascii_digit())),
            Some(Value::Number(n)) => n.as_u64(),
            _ => None,
        };
        let Some(cum) = cum else { return Err(bad(format!("cum {:?}", doc.get("cum").map(|v| v.to_string().chars().take(40).collect::<String>())))) };
        let mut allowed = vec![oc.signed];
        if !oc.pending.is_empty() {
            allowed.push(py_u64(oc.pending.get("cum")).unwrap_or(u64::MAX));
        }
        allowed.extend(oc.stale.iter().map(|s| py_u64(s.get("cum")).unwrap_or(u64::MAX)));
        if !allowed.contains(&cum) {
            return Err(bad(format!("cum {cum} is no state the hub signed (best {})", oc.signed)));
        }
        if let Some(ch) = doc.get("chan") {
            if ch.as_str() != Some(p.channel_id().as_str()) {
                return Err(bad(format!("chan {}", ch.to_string().chars().take(80).collect::<String>())));
            }
        }
        if p.payee_fee() > 0 {
            for (k, want) in [("payeeFee", p.payee_fee()), ("payeeNet", cum.saturating_sub(p.payee_fee()))] {
                if let Some(v) = doc.get(k) {
                    if py_str(Some(v)) != want.to_string() {
                        return Err(bad(format!("{k} {} != {want}", v.to_string().chars().take(30).collect::<String>())));
                    }
                }
            }
        }
        Ok((txid.to_lowercase(), cum))
    }

    // --- refunds -------------------------------------------------------------------------------------

    /// The hub's fee for a ch2 refund: estimatesmartfee(`refund_conf_target`) × vsize, at least
    /// `refund_min_feerate` sat/vB; never the provider's closeFee, never above `refund_max_fee_sat`,
    /// and never below dust left over.
    pub fn refund_fee(&self, p: &ChannelParams, dest: Option<&[u8]>) -> Result<u64> {
        let one = Sc::from_u64(1).secret().ok_or_else(|| ChannelError::new("bad_state", "key"))?;
        let vsize = p.refund_tx(&one, dest, Some(0))?.vsize() + 1; // +1: a 73-byte signature at worst
        let mut rate = self.cfg.refund_min_feerate;
        if let Ok(Some(r)) = self.scan.fee_rate(self.cfg.refund_conf_target) {
            rate = rate.max(r);
        }
        Ok(((rate * vsize as f64).ceil() as u64).min(self.refund_fee_cap(p)))
    }

    fn refund_fee_cap(&self, p: &ChannelParams) -> u64 {
        self.cfg.refund_max_fee_sat.min(p.capacity.saturating_sub(DUST))
    }

    /// The fee of the version that replaces a stuck refund (AGP-044): the current estimate, at least
    /// double the stuck fee, capped. A replacement must pay the stuck fee + 1 sat/vB (BIP125's
    /// incremental relay fee): when the cap leaves less, there is none (the stuck fee is returned).
    fn bumped_fee(&self, oc: &OutChannel, dest: &[u8]) -> Result<u64> {
        let est = self.refund_fee(&oc.params, Some(dest))?;
        let vsize = Tx::parse_hex(&oc.refund_hex).map(|t| t.vsize() as u64 + 1).unwrap_or(0);
        let step = oc.refund_fee + vsize;
        let f = est.max(oc.refund_fee.saturating_mul(2)).max(step).min(self.refund_fee_cap(&oc.params));
        Ok(if f < step { oc.refund_fee } else { f })
    }

    fn refund_due(&self, oc: &OutChannel, tip: u32) -> bool {
        // (AGP-088: `rolled` too. A ch2 rolled on the provider's answer whose rollover never reached
        // the chain is refunded like any ch2)
        if !["funded", "open", "closing", "closed", "rolled"].contains(&oc.state.as_str()) || !oc.pending.is_empty() || oc.params.funding.is_none() {
            return false;
        }
        let grace = if oc.signed >= oc.params.min_amount() { self.cfg.refund_grace_blocks } else { 0 };
        tip as u64 >= oc.params.expiry as u64 + grace as u64
    }

    /// The current refund has waited `refund_bump_blocks` since it was signed.
    fn bump_due(&self, oc: &OutChannel, tip: u32) -> bool {
        !oc.refund_txid.is_empty() && self.cfg.refund_bump_blocks > 0 && tip >= oc.refund_at.saturating_add(self.cfg.refund_bump_blocks)
    }

    /// Refund a ch2 at the hub's fee, or send the refund already signed again; once it has waited
    /// `refund_bump_blocks`, re-sign it at [`bumped_fee`](Self::bumped_fee) (RBF: the hub holds the
    /// payer key and its refunds signal replaceability), paying the same destination. Every version
    /// is written ahead and kept (`refund_prev`) until one confirms.
    fn refund(&self, loc: Loc<'_>, oc: &OutChannel, tip: u32) -> Result<Vec<Value>> {
        let p = &oc.params;
        let prior = !oc.refund_txid.is_empty();
        let bump = self.bump_due(oc, tip);
        let mut out = vec![];
        let (mut hex_, mut txid, mut fee) = (oc.refund_hex.clone(), oc.refund_txid.clone(), oc.refund_fee);
        let mut kind = if prior { "ch2_refund_rebroadcast" } else { "ch2_refund" };
        if !prior || bump {
            let dest = if bump {
                // the same destination as the version it replaces (a refund_to hook may hand out a new address)
                Some(Tx::parse_hex(&oc.refund_hex)?.outputs.first().map(|o| o.script_pubkey.clone()).ok_or_else(|| ChannelError::new("bad_state", "refund tx"))?)
            } else {
                let hooked = match lk(&self.refund_to).as_ref() {
                    Some(f) => Some(address_to_spk(&f()?, Some(&self.cfg.hrp)).map_err(|e| ChannelError::new("bad_address", e.to_string()))?),
                    None => None,
                };
                match hooked {
                    Some(d) => Some(d),
                    // AGP-104 (R1): a ch2 that names its own key (from before it named a return
                    // address) is refunded to one; any other refund pays its `payerSpk`
                    None if own_key(p) => self.return_spk()?,
                    None => None,
                }
            };
            let f = match (bump, dest.as_deref()) {
                (true, Some(d)) => self.bumped_fee(oc, d)?,
                (_, d) => self.refund_fee(p, d)?,
            };
            if bump && f <= oc.refund_fee {
                // at the cap: nothing higher to sign; send what we have and look again in refund_bump_blocks
                self.upd(loc, oc, |c| c.refund_at = tip)?;
                let ev = json!({"event": "ch2_refund_bump_capped", "provider": oc.origin, "chan": p.channel_id(), "txid": txid, "fee": fee,
                                "cap": self.refund_fee_cap(p)});
                self.event(ev.clone());
                out.push(ev);
            } else {
                let tx = p.refund_tx_seq(&oc.secret_key()?, dest.as_deref(), Some(f), RBF_SEQUENCE)?;
                let old = json!({"txid": oc.refund_txid, "fee": oc.refund_fee});
                (hex_, txid, fee) = (tx.to_hex(), tx.txid(), f);
                // write-ahead: every version we may see confirm
                let (h, t) = (hex_.clone(), txid.clone());
                self.upd(loc, oc, |c| {
                    if prior {
                        c.refund_prev.push(old);
                    }
                    c.refund_hex = h;
                    c.refund_txid = t;
                    c.refund_fee = f;
                    c.refund_at = tip;
                })?;
                if bump {
                    kind = "ch2_refund_bump";
                }
            }
        }
        if let Err(e) = self.chain.send_raw_transaction(&hex_) {
            // e.g. the provider's close got there first (the reconcile sees it), or a replacement the
            // node refused (the version it replaces is still tracked)
            let ev = json!({"event": if kind == "ch2_refund_bump" { "ch2_refund_bump_failed" } else { "ch2_refund_failed" },
                            "provider": oc.origin, "chan": p.channel_id(), "txid": txid, "fee": fee,
                            "error": e.to_string().chars().take(200).collect::<String>()});
            self.event(ev.clone());
            out.push(ev);
            return Ok(out);
        }
        self.upd(loc, oc, |c| c.state = "refunded".into())?;
        let mut ev = json!({"event": kind, "provider": oc.origin, "chan": p.channel_id(), "txid": txid, "fee": fee, "signed": oc.signed});
        if kind == "ch2_refund_bump" {
            ev["replaces"] = oc.refund_txid.clone().into();
            ev["feeFrom"] = oc.refund_fee.into();
        }
        self.event(ev.clone());
        out.push(ev);
        Ok(out)
    }

    // --- watcher -----------------------------------------------------------------------------------

    /// AGP-094: give every ch1 lock written before AGP-088 the ch2 it went over (`ch2`), so it is
    /// matched like any other ([`is_lock`]). The ch2 is the unresolved record of the lock's origin
    /// that holds a lock of this ch1 with its lockId and its point; when two do (the same invoice
    /// sent twice, which a hub before AGP-088 admitted), the earlier lock is the earlier record's.
    /// A lock no record holds stays as it is: nothing can move it. Runs when the hub starts and on
    /// every tick (one pass over ch1's ledger, and nothing more once no such lock is left).
    pub fn name_legacy_locks(&self) -> Vec<Value> {
        let unnamed = |x: &Value| truthy(Some(x)) && x.get("ch2").is_none();
        let each = |ex: &Map<String, Value>| -> Vec<Value> {
            ex.get("route_lock").into_iter().chain(ex.get("stale_locks").and_then(Value::as_array).into_iter().flatten()).cloned().collect()
        };
        let chans: Vec<String> = self.inbound.ledger_lock().channels.iter().filter(|(_, s)| each(&s.extra).iter().any(unnamed)).map(|(c, _)| c.clone()).collect();
        if chans.is_empty() {
            return vec![];
        }
        // every unresolved ch2 record: its key, its origin and the locks on it (out book first, then
        // the ledger: never one inside the other in this order)
        let recs: Vec<(String, String, Vec<Value>)> = {
            let b = lk(&self.out);
            let old = b.archived.iter().filter(|r| !truthy(r.get("final"))).filter_map(|r| OutChannel::from_json(r).ok());
            b.chans.values().chain(b.next_chans.values()).cloned().chain(old).map(|c| {
                let mut locks = c.stale.clone();
                if !c.pending.is_empty() {
                    locks.push(Value::Object(c.pending.clone()));
                }
                (ch2_key(&c), c.origin.clone(), locks)
            }).collect()
        };
        let at = |x: &Value| x.get("at").and_then(Value::as_f64).unwrap_or(0.0);
        let mut out = vec![];
        for ch1 in chans {
            let mut l = self.inbound.ledger_lock();
            let Some(mut st1) = l.channels.get(&ch1).cloned() else { continue };
            let mut locks = each(&st1.extra);
            // (lockId, ch2) pairs taken on this ch1 already
            let mut taken: Vec<(String, String)> = locks.iter().filter_map(|x| Some((py_str(x.get("lockId")), x.get("ch2")?.as_str()?.to_string()))).collect();
            let mut order: Vec<usize> = (0..locks.len()).filter(|&i| unnamed(&locks[i])).collect();
            order.sort_by(|&a, &b| at(&locks[a]).total_cmp(&at(&locks[b])));
            let mut named = 0;
            for i in order {
                let (lid, t, origin) = (py_str(locks[i].get("lockId")), py_str(locks[i].get("T")), py_str(locks[i].get("provider")));
                let mut cands: Vec<(f64, &String)> = recs.iter().filter(|(k, o, _)| *o == origin && !taken.contains(&(lid.clone(), k.clone())))
                    .filter_map(|(k, _, ls)| ls.iter().find(|e| is_ch2_lock(e, &ch1, &lid) && py_str(e.get("T")).eq_ignore_ascii_case(&t)).map(|e| (at(e), k)))
                    .collect();
                cands.sort_by(|a, b| a.0.total_cmp(&b.0));
                if let Some((_, k)) = cands.first() {
                    locks[i]["ch2"] = k.as_str().into();
                    taken.push((lid, (*k).clone()));
                    named += 1;
                }
            }
            if named == 0 {
                continue;
            }
            let mut it = locks.into_iter();
            if st1.extra.get("route_lock").is_some() {
                let rl = it.next().unwrap_or(Value::Null);
                st1.extra.insert("route_lock".into(), rl);
            }
            if st1.extra.get("stale_locks").is_some_and(Value::is_array) {
                st1.extra.insert("stale_locks".into(), Value::Array(it.collect()));
            }
            if self.inbound.save_state(&mut l, &st1).is_ok() {
                drop(l);
                let ev = json!({"event": "legacy_locks_named", "chan": ch1, "locks": named});
                self.event(ev.clone());
                out.push(ev);
            }
        }
        out
    }

    /// One watcher pass over every ch2 (then the replaced ones still unsettled in the archive), then
    /// ch1's closes. Errors are per channel and never stop the rest. Returns what it did.
    pub fn watch_tick(&self) -> Vec<Value> {
        let mut acts = vec![];
        let tip = match self.chain.block_count() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("hub watcher: {e}");
                return acts;
            }
        };
        acts.extend(self.name_legacy_locks());
        let origins: Vec<String> = lk(&self.out).chans.keys().cloned().collect();
        let mut skipped = vec![];
        for origin in origins {
            // a route request in flight owns this ch2: never race it for the same lock
            let Some(busy) = self.acquire(&origin, Duration::ZERO) else {
                skipped.push(origin);
                continue;
            };
            match self.watch_out(&origin, tip) {
                Ok(mut a) => acts.append(&mut a),
                Err(e) => self.watch_error(&origin, "watch", &e),
            }
            drop(busy);
        }
        // a provider streaming locks holds its flag most of the time, and a tick in step with its locks
        // could miss every gap (a rollover never due to run, AGP-053): wait for the flag between two
        // locks, within a budget per tick
        let until = Instant::now() + WATCH_WAIT_BUDGET;
        for origin in skipped {
            let left = until.saturating_duration_since(Instant::now());
            let Some(busy) = self.acquire(&origin, left.min(WATCH_WAIT_ONE)) else { continue };
            match self.watch_out(&origin, tip) {
                Ok(mut a) => acts.append(&mut a),
                Err(e) => self.watch_error(&origin, "watch", &e),
            }
            drop(busy);
        }
        // AGP-057: every origin's next ch2 (reconciled, opened at minConf, taking over from a live one
        // that is gone or idle), then the ones due to be funded ahead. Neither needs the origin's busy
        // flag until a switch: a next ch2 takes no lock before it
        let nexts: Vec<String> = lk(&self.out).next_chans.keys().cloned().collect();
        for origin in nexts {
            match self.watch_next(&origin, tip) {
                Ok(mut a) => acts.append(&mut a),
                Err(e) => self.watch_error(&origin, "next", &e),
            }
        }
        let origins: Vec<String> = lk(&self.out).chans.keys().cloned().collect();
        for origin in origins {
            match self.refill_ahead_due(&origin, tip) {
                Ok(mut a) => acts.append(&mut a),
                Err(e) => self.watch_error(&origin, "refill_ahead", &e),
            }
        }
        let archived: Vec<(usize, String, bool)> = lk(&self.out).archived.iter().enumerate()
            .filter(|(_, r)| watched(r))
            .map(|(i, r)| (i, py_str(r.get("origin")), r.get("state").and_then(Value::as_str) == Some("dropped"))).collect();
        for (i, origin, dropped) in archived {
            // replaced ch2s are still the hub's coins, and so is a dropped funding that may confirm late
            let r = if dropped { self.reconcile_dropped(i) } else { self.reconcile(Loc::Archived(i), tip) };
            match r {
                Ok(mut a) => acts.append(&mut a),
                Err(e) => self.watch_error(&origin, "archived", &e),
            }
            if let Some(oc) = self.get(Loc::Archived(i)).filter(|c| c.retired) {
                acts.extend(self.close_retired(i, &oc, tip));
            }
        }
        // AGP-073: the ch1 locks a stop left (before a margin close, so one held is in that close)
        let locked: Vec<String> = self.inbound.ledger_lock().channels.iter()
            .filter(|(_, s)| s.closed_txid.is_empty() && truthy(s.extra.get("route_lock"))).map(|(c, _)| c.clone()).collect();
        for ch1 in locked {
            acts.extend(self.sweep_orphan_lock(&ch1));
        }
        match self.inbound.close_due() {
            Ok(txs) => acts.extend(txs.into_iter().map(|t| json!({"event": "ch1_close", "txid": t}))),
            Err(e) => eprintln!("hub watcher ch1: {e}"),
        }
        // AGP-104 (R1): what closes left on per-channel keys goes to the return address
        acts.extend(self.sweep_tick(tip));
        acts
    }

    /// AGP-057: one origin's next ch2. A `funding` one is reconciled like any (the wallet call failed); a
    /// funded one is checked against the chain and opened at the provider's minConf (never
    /// unconfirmed: a wallet funding is the hub's to spend again). One that is no longer live (refunded
    /// at its expiry, its funding spent) leaves for the archive. It takes over, under the origin's
    /// busy flag, when the live ch2 is gone (closing, closed, refunded, dropped), or when both are open
    /// and the live one has had no lock for `settle_idle` seconds, so two ch2s do not stay committed
    /// to an idle provider.
    fn watch_next(&self, origin: &str, tip: u32) -> Result<Vec<Value>> {
        let loc = Loc::Next(origin);
        let Some(oc) = self.get(loc) else { return Ok(vec![]) };
        if oc.state == "funding" {
            return self.reconcile_funding(loc, origin, &oc, tip);
        }
        let mut out = vec![];
        match self.reconcile(loc, tip) {
            Ok(mut a) => out.append(&mut a),
            Err(e) => self.watch_error(origin, "reconcile", &e),
        }
        let Some(mut oc) = self.get(loc).filter(|c| c.params.payer_pub == oc.params.payer_pub) else { return Ok(out) };
        if oc.state == "funded" {
            let p = &oc.params;
            let min_conf = oc.term_u64("minConf").unwrap_or(1) as u32;
            if self.chain.get_tx_out(&p.funding_txid(), p.funding_vout(), false)?.is_some_and(|u| u.confirmations >= min_conf) && self.open(&oc)? {
                out.push(json!({"event": "ch2_open", "provider": origin, "next": true}));
                oc.state = "open".into();
            }
        }
        if !LIVE.contains(&oc.state.as_str()) {
            let mut b = lk(&self.out);
            if b.next_chans.get(origin).is_some_and(|c| c.params.payer_pub == oc.params.payer_pub) {
                if let Some(c) = b.next_chans.shift_remove(origin) {
                    b.archived.push(c.to_json());
                }
                b.save()?;
            }
            return Ok(out);
        }
        if self.takeover_due(origin).is_some() {
            if let Some(busy) = self.acquire(origin, WATCH_WAIT_ONE) {
                // again, under the flag
                if let Some(why) = self.takeover_due(origin) {
                    if self.promote(origin, &why)?.is_some() {
                        out.push(json!({"event": "ch2_switch", "provider": origin, "why": why}));
                    }
                }
                drop(busy);
            }
        }
        Ok(out)
    }

    /// Why the origin's next ch2 should take over now without a lock asking for it: the live one is
    /// gone, or both are open and the live one is idle.
    fn takeover_due(&self, origin: &str) -> Option<String> {
        let b = lk(&self.out);
        let nxt = b.next_chans.get(origin)?;
        match b.chans.get(origin) {
            None => Some("the live ch2 is gone".into()),
            Some(c) if !LIVE.contains(&c.state.as_str()) => Some(format!("the live ch2 is {}", c.state)),
            Some(c) if c.state == "open" && nxt.state == "open" && c.pending.is_empty() && now_f() - c.last_lock_at >= self.cfg.settle_idle => {
                Some("idle".into())
            }
            _ => None,
        }
    }

    /// AGP-057: fund the origin's next ch2 once its live one's room is under `refill_ahead_locks` × the
    /// largest lock routed to that provider (the room is what a rollover child keeps, less the
    /// provider's minCapacity: a rollover adds no coins). Not for a provider the hub stopped routing
    /// to, nor for one with no lock for `settle_idle` seconds. A refusal (the liquidity cap, the
    /// provider's /terms) is an event and is tried again next block; until a next ch2 is open, the
    /// refill follows the close as before.
    fn refill_ahead_due(&self, origin: &str, tip: u32) -> Result<Vec<Value>> {
        let n = self.cfg.refill_ahead_locks;
        if n == 0 {
            return Ok(vec![]);
        }
        let hook = lk(&self.refill_ahead).clone();
        if hook.is_none() && lk(&self.refill).is_some() {
            return Ok(vec![]); // the embedder's own refill path, lock and cap: nothing funded on our own
        }
        let (room, big, chan) = {
            let b = lk(&self.out);
            let Some(oc) = b.chans.get(origin).filter(|c| c.state == "open" && c.blocked.is_empty() && c.max_lock > 0) else { return Ok(vec![]) };
            if b.next_chans.contains_key(origin) || now_f() - oc.last_lock_at >= self.cfg.settle_idle {
                return Ok(vec![]);
            }
            // what the line still takes: a rollover child keeps capacity - signed, and one under the
            // provider's minCapacity is not made (the ch2 is closed instead)
            let used = oc.signed.max(py_u64(oc.pending.get("cum")).unwrap_or(0));
            let room = oc.params.max_amount().saturating_sub(used).saturating_sub(oc.term_u64("minCapacity").unwrap_or(0));
            (room, oc.max_lock, oc.params.channel_id())
        };
        if room >= n.saturating_mul(big) || lk(&self.ahead_tried).contains(&(origin.to_string(), tip)) {
            return Ok(vec![]);
        }
        let r = match hook {
            Some(f) => f(self, origin),
            None => self.connect_next(origin, None, None).map(|_| ()),
        };
        if let Err(e) = r {
            // reported; the live ch2 goes on, and the refill follows its close
            let mut tried = lk(&self.ahead_tried);
            tried.retain(|(_, t)| *t + 1 >= tip);
            tried.insert((origin.to_string(), tip));
            drop(tried);
            let ev = json!({"event": "ch2_refill_ahead_failed", "provider": origin, "error": e.to_string().chars().take(200).collect::<String>()});
            self.event(ev.clone());
            return Ok(vec![ev]);
        }
        let nxt = self.get(Loc::Next(origin));
        let ev = json!({"event": "ch2_refill_ahead", "provider": origin, "live": chan, "room": room, "maxLock": big,
                        "next": nxt.as_ref().map(|c| c.params.channel_id()).unwrap_or_default(),
                        "capacity": nxt.as_ref().map(|c| c.params.capacity).unwrap_or(0)});
        self.event(ev.clone());
        Ok(vec![ev])
    }

    /// AGP-057: a ch2 its origin's next one replaced (an archived record: it takes no lock any more).
    /// Ask the provider to close it with the best state, once a block until it answers; the close is
    /// then reconciled like any (`closing`, `closed` once confirmed). With nothing signed there is
    /// nothing to close: the hub's refund returns it at its expiry, as for any unused ch2.
    fn close_retired(&self, i: usize, oc: &OutChannel, tip: u32) -> Vec<Value> {
        if oc.state != "open" || !oc.pending.is_empty() || (oc.signed == 0 && oc.stale.is_empty()) {
            return vec![];
        }
        let chan = oc.params.channel_id();
        {
            let mut tried = lk(&self.retire_tried);
            if !tried.insert((chan.clone(), tip)) {
                return vec![];
            }
            tried.retain(|(_, t)| *t + 1 >= tip);
        }
        match self.close_ch2_at(Loc::Archived(i), oc, false) {
            Ok(ev) => vec![ev],
            Err(e) => {
                let ev = json!({"event": "ch2_retire_failed", "provider": oc.origin, "chan": chan, "error": e.to_string().chars().take(200).collect::<String>()});
                self.event(ev.clone());
                vec![ev]
            }
        }
    }

    /// AGP-073: the live ch2 holds a written-off lock (its pre-signature may be out), so it takes no
    /// lock and is not rolled over until that resolves, which left alone is its refund at expiry. Ask
    /// the provider to close it now, once a block until it does: a close that shows t pays the hub on
    /// ch1, one that confirms without t releases the hold. A provider that refused the lock gets a new
    /// ch2 (its next one, funded ahead, takes over at once and the old one is closed as retired); one
    /// the hub stopped routing to (no reveal in time) does not.
    fn close_written_off(&self, origin: &str, oc: &OutChannel, tip: u32) -> Vec<Value> {
        let chan = oc.params.channel_id();
        {
            let mut tried = lk(&self.stale_tried);
            if !tried.insert((chan.clone(), tip)) {
                return vec![];
            }
            tried.retain(|(_, t)| *t + 1 >= tip);
        }
        let refill = oc.blocked.is_empty();
        let failed = |e: &ChannelError| {
            let ev = json!({"event": "ch2_written_off_close_failed", "provider": origin, "chan": chan, "error": e.to_string().chars().take(200).collect::<String>()});
            self.event(ev.clone());
            vec![ev]
        };
        if refill && lk(&self.out).next_chans.get(origin).is_some_and(|n| n.state == "open") {
            return match self.promote(origin, "written_off") {
                Ok(Some(nxt)) => vec![json!({"event": "ch2_switch", "provider": origin, "from": chan, "to": nxt.params.channel_id(), "why": "written_off"})],
                Ok(None) => vec![],
                Err(e) => failed(&e),
            };
        }
        match self.close_ch2(oc, refill) {
            Ok(mut ev) => {
                ev["why"] = "written_off".into();
                vec![ev]
            }
            Err(e) => failed(&e),
        }
    }

    fn watch_error(&self, origin: &str, step: &str, e: &ChannelError) {
        let msg: String = e.to_string().chars().take(200).collect();
        eprintln!("hub watcher {origin} ({step}): {msg}");
        self.event(json!({"event": "ch2_watch_error", "provider": origin, "step": step, "error": msg}));
    }

    fn watch_out(&self, origin: &str, tip: u32) -> Result<Vec<Value>> {
        let mut out = vec![];
        let Some(oc) = self.get(Loc::Live(origin)) else { return Ok(out) };
        if oc.state == "funding" {
            return self.reconcile_funding(Loc::Live(origin), origin, &oc, tip);
        }
        // its own step: a failure here never skips the rest
        match self.reconcile(Loc::Live(origin), tip) {
            Ok(mut a) => out.append(&mut a),
            Err(e) => self.watch_error(origin, "reconcile", &e),
        }
        let Some(oc) = self.get(Loc::Live(origin)).filter(|c| c.params.payer_pub == oc.params.payer_pub) else {
            return Ok(out); // finished a rollover: the next ch2 is watched next tick
        };
        let p = &oc.params;
        if oc.state == "funded" {
            let min_conf = oc.term_u64("minConf").unwrap_or(1) as u32;
            if self.chain.get_tx_out(&p.funding_txid(), p.funding_vout(), false)?.is_some_and(|u| u.confirmations >= min_conf) {
                if self.open(&oc)? {
                    out.push(json!({"event": "ch2_open", "provider": origin}));
                }
            } else if !oc.rolled_from.is_empty() && self.open_child(Some(oc.clone()), &oc.rolled_from) {
                // a rollover child not opened right after the rollover (a lost reply, a restart)
                out.push(json!({"event": "ch2_open", "provider": origin, "zeroConf": true}));
            }
            return Ok(out);
        }
        if oc.state != "open" {
            return Ok(out);
        }
        if !oc.zero_conf.is_empty() {
            out.extend(self.zero_conf_tick(origin, &oc)?);
        }
        if !oc.pending.is_empty() {
            let at = oc.pending.get("at").and_then(Value::as_f64).unwrap_or(0.0);
            let ch1 = py_str(oc.pending.get("ch1"));
            let ans = self.send_lock(origin);
            let settled = ans.as_ref().filter(|a| a.get("secret").is_some()).and_then(|a| self.settled(&ch1, origin, a));
            if now_f() - at < self.reveal_timeout() {
                if ans.as_ref().is_some_and(|a| a.get("secret").is_some()) {
                    out.push(json!({"event": "lock_settled_late", "provider": origin, "ok": settled.is_some()}));
                }
            } else if settled.is_some() {
                out.push(json!({"event": "lock_settled_late", "provider": origin}));
            } else {
                let lid = oc.pending.get("lockId").cloned().unwrap_or(Value::Null);
                self.void(Loc::Live(origin), &oc, &ch1, &lid, "no reveal within revealTimeoutSec", "the provider did not reveal a lock in time");
                out.push(json!({"event": "lock_written_off", "provider": origin}));
            }
            return Ok(out);
        }
        if !oc.stale.is_empty() {
            // AGP-064: no rollover until the written-off locks resolve (the provider's close, or the
            // refund); AGP-073: the hub asks for that close now
            out.extend(self.close_written_off(origin, &oc, tip));
            return Ok(out);
        }
        // settlement: the provider's net payout >= its settleMultiple × closeFee, or near ch2's close
        // margin as the provider counts it (it co-signs only then): roll over. Past expiry the refund
        // took over.
        let due = self.settle_due(&oc);
        let margin = oc.term_u64("closeMarginBlocks").unwrap_or(self.cfg.close_margin as u64) as i64;
        let grace = (self.cfg.rollover_margin as u64).min(oc.term_u64("rolloverGraceBlocks").unwrap_or(self.cfg.rollover_margin as u64)) as i64;
        let near = tip as i64 >= p.expiry as i64 - margin - grace;
        // an unconfirmed rollover child is not rolled over again before it confirms (AGP-053)
        let unconfirmed = self.get(Loc::Live(origin)).is_some_and(|c| c.zero_conf_pending());
        if (due || near) && oc.signed >= p.min_amount() && tip < p.expiry && !unconfirmed {
            out.push(self.rollover(&oc)?);
        }
        Ok(out)
    }

    /// The ch2 is due to roll over: the provider's net payout is at its threshold (settleMultiple ×
    /// closeFee: the least it co-signs) and, while locks keep coming (AGP-056), the ch2 has taken
    /// `settle_lock_multiple` × the largest lock routed to it, so a provider whose locks are larger
    /// than its threshold is not rolled over on every lock. Never later than the point where another
    /// lock of that size would not fit (the ch2 would be exhausted), and at once after `settle_idle`
    /// seconds without a lock.
    fn settle_due(&self, oc: &OutChannel) -> bool {
        let p = &oc.params;
        if !settle_due(p, oc.signed, oc.settle_multiple) {
            return false;
        }
        let (k, big) = (self.cfg.settle_lock_multiple, oc.max_lock);
        if k == 0 || big == 0 {
            return true;
        }
        if now_f() - oc.last_lock_at >= self.cfg.settle_idle {
            return true;
        }
        oc.signed >= k.saturating_mul(big) || oc.signed.saturating_add(big) > p.max_amount()
    }

    /// A ch2 the provider took unconfirmed (AGP-053): confirmed with minConf, or unconfirmed again (a
    /// reorg), and the provider's bounds apply again.
    fn zero_conf_tick(&self, origin: &str, oc: &OutChannel) -> Result<Vec<Value>> {
        let p = &oc.params;
        let min_conf = oc.term_u64("minConf").unwrap_or(1) as u32;
        let now = self.chain.get_tx_out(&p.funding_txid(), p.funding_vout(), false)?.is_some_and(|u| u.confirmations >= min_conf);
        if now == truthy(oc.zero_conf.get("confirmed")) {
            return Ok(vec![]);
        }
        self.upd(Loc::Live(origin), oc, |c| {
            c.zero_conf.insert("confirmed".into(), now.into());
        })?;
        let ev = json!({"event": if now { "ch2_zero_conf_confirmed" } else { "ch2_zero_conf_reorg" }, "provider": oc.origin, "chan": p.channel_id()});
        self.event(ev.clone());
        Ok(vec![ev])
    }

    /// Check one non-final ch2's funding against the chain (AGP-037).
    /// Unspent: refund it when due; rebroadcast our refund if it left the mempool. Spent by the
    /// rollover we wrote ahead: finish it. Spent by our refund: final once confirmed. Spent by
    /// anything else (the provider's close): read the locks' secrets off it; in the mempool it is only
    /// `closing` (AGP-045: the refund fee stays booked), and once it confirms the ch2 is `closed` with
    /// the real txid and the refund fee is taken back if our refund lost. A `closing` ch2 whose spender
    /// left the mempool is `refunded` again if it was (the fee re-booked), else it stays `closing` and
    /// is refunded at expiry unless the close comes back. Spent, spender not found: with locks
    /// outstanding leave it (their secrets are on that tx); without, closing (closed once confirmed),
    /// txid unknown.
    ///
    /// AGP-088: "confirmed" is [`Self::spend_depth`], never `gettxout` answering nothing alone;
    /// a `rolled` ch2 is watched here until its rollover is in a block, and refunded like any other
    /// if that rollover never comes; a lock still pending on a ch2 that is no longer open is written
    /// off; and the locks a confirmed spend did not pay leave ch1 BEFORE the record is final.
    fn reconcile(&self, loc: Loc<'_>, tip: u32) -> Result<Vec<Value>> {
        let mut out = vec![];
        let Some(mut oc) = self.get(loc) else { return Ok(out) };
        if oc.final_ || !NONFINAL.contains(&oc.state.as_str()) || oc.params.funding.is_none() {
            return Ok(out);
        }
        let (txid, vout) = (oc.params.funding_txid(), oc.params.funding_vout());
        let chan = oc.params.channel_id();
        let final_depth = self.cfg.spend_final_depth.max(1);
        // (AGP-094: or on an archived one, which takes no lock and is asked for nothing: a ledger
        // from before AGP-088 can hold a ch2 archived while open with its lock pending. It is
        // written off like the others and closed like a retired ch2)
        let replaced = matches!(loc, Loc::Archived(_));
        if !oc.pending.is_empty() && (oc.state != "open" || replaced) && now_f() - oc.pending.get("at").and_then(Value::as_f64).unwrap_or(0.0) >= self.reveal_timeout() {
            // AGP-088: the watcher asks again for a pending lock only on an open ch2. On any other
            // (closing on the provider's close, a restart in between) nobody would write it off:
            // ch1 kept its lock in flight until its margin, and the ch2 ended with it pending. Its
            // pre-signature may be out, so it is held on ch1 like any written-off lock
            let (ch1, lid) = (py_str(oc.pending.get("ch1")), oc.pending.get("lockId").cloned().unwrap_or(Value::Null));
            self.void(loc, &oc, &ch1, &lid, "its ch2 is no longer open", "");
            if replaced && oc.state == "open" {
                self.upd(loc, &oc, |c| c.retired = true)?;
            }
            out.push(json!({"event": "lock_written_off", "provider": oc.origin, "chan": chan}));
            let Some(cur) = self.get(loc).filter(|c| c.params.payer_pub == oc.params.payer_pub) else { return Ok(out) };
            oc = cur;
        }
        if let Some(u) = self.chain.get_tx_out(&txid, vout, true)? {
            // what the node shows of the unspent funding, kept for the day it is spent (AGP-088)
            let conf = u.confirmations >= 1;
            if oc.fund_confirmed != conf || oc.spend_seen || oc.gone_at != 0 {
                self.upd(loc, &oc, |c| (c.fund_confirmed, c.spend_seen, c.gone_at) = (conf, false, 0))?;
                (oc.fund_confirmed, oc.spend_seen, oc.gone_at) = (conf, false, 0);
            }
            if !oc.rolled_from.is_empty() && !oc.fund_seen {
                // our node shows the rollover (AGP-056)
                self.upd(loc, &oc, |c| c.fund_seen = true)?;
                oc.fund_seen = true;
            }
            if oc.blocked == ROLLOVER_GONE {
                // the rollover is back (AGP-053)
                self.upd(loc, &oc, |c| c.blocked = String::new())?;
                let ev = json!({"event": "ch2_rollover_back", "provider": oc.origin, "chan": chan});
                self.event(ev.clone());
                out.push(ev);
                let Some(cur) = self.get(loc).filter(|c| c.params.payer_pub == oc.params.payer_pub) else { return Ok(out) };
                oc = cur;
            }
            if oc.state == "closing" && (!oc.close_txid.is_empty() || oc.close_prev == "refunded") {
                out.extend(self.close_vanished(loc, &oc)?);
                let Some(cur) = self.get(loc).filter(|c| c.params.payer_pub == oc.params.payer_pub) else { return Ok(out) };
                oc = cur;
            }
            if oc.state == "refunded" || self.refund_due(&oc, tip) {
                // due, or our refund left the mempool: send it (again, or bumped once it waited)
                out.extend(self.refund(loc, &oc, tip)?);
            }
            return Ok(out);
        }
        if !oc.rolled_from.is_empty() && ["funded", "open"].contains(&oc.state.as_str()) {
            if let Some(gone) = self.rollover_gone(loc, &oc)? {
                out.extend(gone);
                return Ok(out);
            }
        }
        if oc.state == "rolled" && !oc.close_txid.is_empty() {
            // the rollover this ch2 was rolled on, in a block by one of its own two outputs: nothing
            // left to watch, and no block is read for it (a rollover whose outputs are both spent
            // again already is found by the scan below)
            for n in 0..2 {
                if self.chain.get_tx_out(&oc.close_txid, n, false)?.is_some_and(|u| u.confirmations >= final_depth) {
                    self.upd(loc, &oc, |c| (c.final_, c.spend_seen) = (true, true))?;
                    return Ok(out);
                }
            }
        }
        let locks = !oc.pending.is_empty() || !oc.stale.is_empty();
        if oc.state == "closing" && !oc.close_txid.is_empty() && !locks && oc.refund_txid.is_empty() && oc.next.is_empty()
            && self.spend_depth(loc, &mut oc, None, tip)? >= final_depth
        {
            // the provider's close as it told us, confirmed: done. (With a next ch2 written ahead the
            // spender is read first, AGP-085: a rollover the provider held may be what confirmed.)
            self.upd(loc, &oc, |c| {
                c.state = "closed".into();
                c.final_ = true;
            })?;
            let ev = json!({"event": "ch2_closed", "provider": oc.origin, "chan": chan, "txid": oc.close_txid, "by": "provider"});
            self.event(ev.clone());
            out.push(ev);
            out.extend(self.refill_if_owed(loc, &oc));
            return Ok(out);
        }
        let found = self.scan.find_spend_at(&txid, vout, oc.scanned_to)?;
        // AGP-094: `confirmed` is "spent for good" (`spend_final_depth` deep): what it gates below
        // (the release of unpaid locks, `final`, a refund fee taken back) is not undone, so none of
        // it happens on a spend a short reorg can replace. Until then a spend in a block is treated
        // as one in the mempool, except that our own refund is not bumped once it is in a block
        let depth = self.spend_depth(loc, &mut oc, found.as_ref(), tip)?;
        let (in_block, confirmed) = (depth >= 1, depth >= final_depth);
        let Some((tx, _)) = found else {
            // a funded one may not be visible yet; with locks, their secrets are on that tx: wait for
            // it. A closing one closes once the spend confirms, unless it was refunded (the spender may
            // be our refund: the fee stays booked until the spender is found)
            if locks || !["open", "closing"].contains(&oc.state.as_str()) {
                return Ok(out);
            }
            if oc.state == "closing" && (!confirmed || oc.close_prev == "refunded") {
                return Ok(out);
            }
            let st = if confirmed { "closed" } else { "closing" };
            let was_open = oc.state == "open";
            let r = self.upd(loc, &oc, |c| {
                if was_open {
                    c.close_prev = "open".into();
                    c.close_txid = String::new();
                }
                c.state = st.into();
                // a funding this node showed confirmed and no longer shows unspent, even counting
                // the mempool, is being spent: its coins no longer count (AGP-088)
                c.spend_seen = c.fund_confirmed;
                c.close_txid.clone()
            })?;
            let ev = json!({"event": format!("ch2_{st}"), "provider": oc.origin, "chan": chan, "txid": r.unwrap_or_default(), "by": "unknown"});
            self.event(ev.clone());
            out.push(ev);
            return Ok(out);
        };
        if !oc.spend_seen {
            // this node shows a spender: the coins are leaving, whatever the provider said (AGP-088)
            self.upd(loc, &oc, |c| c.spend_seen = true)?;
            oc.spend_seen = true;
        }
        let spender = tx.txid();
        if oc.state == "rolled" && spender == oc.close_txid {
            // the rollover this ch2 was rolled on: nothing left to watch once it is in a block
            if confirmed {
                self.upd(loc, &oc, |c| c.final_ = true)?;
            }
            return Ok(out);
        }
        if let Some(amount) = self.next_funded(loc, &oc, &tx)? {
            if locks {
                // AGP-085: a rollover reveals no t. Its locks are unpaid once it confirms, not before (a
                // close that shows t may still replace it in the mempool)
                if !confirmed {
                    return Ok(out);
                }
                out.extend(self.release_rolled(loc, &oc, "rolled over")?);
            }
            let Some(cur) = self.get(loc).filter(|c| c.params.payer_pub == oc.params.payer_pub) else { return Ok(out) };
            out.push(self.finish_rollover(loc, &cur, amount)?);
            return Ok(out);
        }
        let prev_fee = oc.refund_prev.iter().find(|r| r.get("txid").and_then(Value::as_str) == Some(spender.as_str()))
            .map(|r| py_u64(r.get("fee")).unwrap_or(0));
        if spender == oc.refund_txid || prev_fee.is_some() {
            // one of our refund versions
            let fee = prev_fee.unwrap_or(oc.refund_fee);
            let sp = spender.clone();
            // the refund proves the written-off locks unpaid: off ch1 first, then the record is final
            let released = if confirmed { self.release_rolled(loc, &oc, "refunded")? } else { vec![] };
            self.upd(loc, &oc, |c| {
                c.state = "refunded".into();
                c.final_ = confirmed;
                if confirmed {
                    c.next = Map::new(); // the funding went to our refund: no rollover (AGP-085)
                }
                if confirmed && prev_fee.is_some() {
                    // an earlier version won: it is the refund (and the fee) that counts
                    c.refund_txid = sp;
                    c.refund_fee = fee;
                    c.refund_hex = String::new();
                }
            })?;
            if confirmed {
                let ev = json!({"event": "ch2_refund_confirmed", "provider": oc.origin, "chan": chan, "txid": spender,
                                "fee": fee, "versions": oc.refund_prev.len() + 1});
                self.event(ev.clone());
                out.push(ev);
                out.extend(released);
            } else if !in_block && self.bump_due(&oc, tip) {
                // stuck in the mempool: replace it at a higher fee
                if let Some(cur) = self.get(loc).filter(|c| c.params.payer_pub == oc.params.payer_pub) {
                    out.extend(self.refund(loc, &cur, tip)?);
                }
            }
            return Ok(out);
        }
        if locks {
            out.extend(self.secrets_from_close(loc, &oc, &tx)); // the secrets are on it, confirmed or not
        }
        if !confirmed {
            // in the mempool: it may still be replaced or expire, so the ch2 is only closing and a
            // refund fee stays booked until it confirms
            if oc.state == "closing" && oc.close_txid == spender {
                if oc.returned.is_none() {
                    let back = returned_by(&tx, &oc.params);
                    self.upd(loc, &oc, |c| c.returned = Some(back))?;
                }
                out.extend(self.refill_if_owed(loc, &oc));
                return Ok(out);
            }
            let sp = spender.clone();
            let at_risk = refund_booked(&oc.state, &oc.close_prev);
            let back = returned_by(&tx, &oc.params);
            self.upd(loc, &oc, |c| {
                if c.state != "closing" {
                    c.close_prev = std::mem::take(&mut c.state);
                }
                c.state = "closing".into();
                c.close_txid = sp;
                c.returned = Some(back);
            })?;
            let mut ev = json!({"event": "ch2_closing", "provider": oc.origin, "chan": chan, "txid": spender, "by": "provider"});
            if at_risk {
                ev["refundAtRisk"] = oc.refund_txid.clone().into();
            }
            self.event(ev.clone());
            out.push(ev);
            out.extend(self.refill_if_owed(loc, &oc));
            return Ok(out);
        }
        // a confirmed close that did not reveal a lock's t did not pay it: off ch1 first, then final
        let released = self.release_rolled(loc, &oc, "closed")?;
        let lost = if oc.refund_txid.is_empty() { 0 } else { oc.refund_fee };
        let sp = spender.clone();
        let back = returned_by(&tx, &oc.params);
        self.upd(loc, &oc, |c| {
            c.state = "closed".into();
            c.close_txid = sp;
            c.returned = Some(back);
            c.final_ = true;
            c.next = Map::new();
            if lost > 0 {
                c.refund_fee = 0;
            }
        })?;
        let mut ev = json!({"event": "ch2_closed", "provider": oc.origin, "chan": chan, "txid": spender, "by": "provider"});
        if !oc.refund_txid.is_empty() {
            ev["refundLost"] = oc.refund_txid.clone().into();
            ev["refundFeeReverted"] = lost.into();
        }
        self.event(ev.clone());
        out.push(ev);
        out.extend(released);
        out.extend(self.refill_if_owed(loc, &oc));
        Ok(out)
    }

    /// AGP-088 rule: a ch2's funding is spent for good, and its unpaid locks leave ch1, only when
    /// the spend is in a block. `gettxout(funding, include_mempool = false)` answering nothing does
    /// not say so: a node answers nothing for every output of an unconfirmed transaction, and a
    /// rollover's child takes locks before its rollover confirms. So "in a block" needs one of:
    /// the scan found the spender in a block (`found`'s depth); the watcher saw this funding
    /// confirmed while it was unspent (`fund_confirmed`), and now the confirmed set no longer has
    /// it; or an output of the spender is itself in the confirmed set.
    ///
    /// AGP-094 rule: "spent for good" is `spend_final_depth` blocks deep, not one: what is done on
    /// it (a hold given back, a record made final) cannot be taken back when the block is
    /// replaced. This returns how deep the spend is (0: not in a block). The scan's own depth when
    /// it gives one (bitcoind does); else the blocks since the watcher first saw the funding spent
    /// in a block (`gone_at`, written here), which never counts a block the watcher did not see.
    fn spend_depth(&self, loc: Loc<'_>, oc: &mut OutChannel, found: Option<&(Tx, Option<u32>)>, tip: u32) -> Result<u32> {
        let p = &oc.params;
        if self.chain.get_tx_out(&p.funding_txid(), p.funding_vout(), false)?.is_some() {
            return Ok(0); // still in the confirmed set: any spend of it is in the mempool
        }
        let in_block = match found {
            Some((_, Some(depth))) => return Ok(*depth),
            Some((tx, None)) => oc.fund_confirmed || self.tx_deep(tx, None, 1)?,
            None => oc.fund_confirmed,
        };
        if !in_block {
            return Ok(0);
        }
        if oc.gone_at == 0 {
            self.upd(loc, oc, |c| c.gone_at = tip)?;
            oc.gone_at = tip;
        }
        Ok(tip.saturating_sub(oc.gone_at).saturating_add(1))
    }

    /// `tx` is `need` blocks deep: by the depth the scan gave, else by one of its outputs having
    /// that many confirmations in the node's confirmed set.
    fn tx_deep(&self, tx: &Tx, depth: Option<u32>, need: u32) -> Result<bool> {
        if let Some(d) = depth {
            return Ok(d >= need);
        }
        let txid = tx.txid();
        for n in 0..tx.outputs.len() as u32 {
            if self.chain.get_tx_out(&txid, n, false)?.is_some_and(|u| u.confirmations >= need) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The locks on a ch2 whose funding a confirmed spend took without revealing their t (AGP-085: a
    /// rollover; AGP-088: any close or refund, so no ch2 ends with a lock still pending on it): a
    /// pending lock is written off (`why`) and every written-off lock is released. ch1's own lock
    /// in flight, if the route that sent it is gone, is then an orphan and the sweep drops it.
    fn release_rolled(&self, loc: Loc<'_>, oc: &OutChannel, why: &str) -> Result<Vec<Value>> {
        self.upd(loc, oc, |c| {
            if !c.pending.is_empty() {
                let mut s = Value::Object(std::mem::take(&mut c.pending));
                s["voided"] = round3(now_f());
                s["why"] = why.into();
                c.stale.push(s);
            }
        })?;
        self.release_stale(loc, oc)
    }

    /// `tx`, which spent this ch2's funding, is a rollover into the next ch2 written ahead (`next`):
    /// the amount it paid the provider, else None. It is the one last asked for, or (AGP-085) an
    /// earlier attempt under the same key and expiry at another amount: only a transaction the hub
    /// signed pays that script from this funding. The record then takes the outpoint and value that
    /// transaction gave it and a refund for them, before it becomes the ch2.
    fn next_funded(&self, loc: Loc<'_>, oc: &OutChannel, tx: &Tx) -> Result<Option<u64>> {
        if oc.next.is_empty() {
            return Ok(None);
        }
        let Ok(mut new) = OutChannel::from_json(&Value::Object(oc.next.clone())) else { return Ok(None) };
        let spender = tx.txid();
        let cap = match tx.outputs.as_slice() {
            [_, o] if o.script_pubkey == new.params.spk() => Some(u64::try_from(o.value).unwrap_or(0)),
            _ => None,
        };
        // what the provider was paid, read off the transaction on every pass (AGP-088): an earlier
        // attempt adopted on a pass before is at another amount than the one last asked for
        let paid = |cap: u64| oc.params.capacity.saturating_sub(oc.params.payer_fee()).saturating_sub(cap);
        if new.params.funding_txid() == spender {
            return Ok(Some(cap.map(paid).unwrap_or(oc.signed)));
        }
        let Some(cap) = cap else { return Ok(None) };
        let p = new.params.clone().with_funding(&spender, 1, cap)?;
        new.refund_hex = p.refund_tx(&new.secret_key()?, None, None)?.to_hex();
        new.params = p;
        let next = new.to_json().as_object().cloned().unwrap_or_default();
        if self.upd(loc, oc, |c| c.next = next)?.is_none() {
            return Ok(None);
        }
        Ok(Some(paid(cap)))
    }

    /// A rollover child's funding output is not in the UTXO set nor the mempool (AGP-053). The rollover
    /// tx exists (in the mempool, or its output confirmed): None, the usual reconcile (it was spent).
    /// The parent is unspent even counting the mempool: the rollover left the mempool (the provider,
    /// who holds it signed, sends it again), so routing stops (blocked) until it is back. The parent was
    /// spent by another tx (the provider's own close): this ch2 never existed; it is dropped (final)
    /// and any secrets of the parent's written-off locks are read off that close.
    fn rollover_gone(&self, loc: Loc<'_>, oc: &OutChannel) -> Result<Option<Vec<Value>>> {
        let p = &oc.params;
        let txid = p.funding_txid();
        if self.chain.get_tx_out(&txid, p.funding_vout(), false)?.is_some() || self.scan.in_mempool(&txid).unwrap_or(false) {
            if !oc.fund_seen {
                self.upd(loc, oc, |c| c.fund_seen = true)?;
            }
            return Ok(None);
        }
        let Some((ptxid, pvout)) = oc.rolled_from.split_once(':') else { return Ok(None) };
        let pvout: u32 = pvout.parse().map_err(|_| ChannelError::new("bad_state", "rolled_from"))?;
        if self.chain.get_tx_out(ptxid, pvout, true)?.is_some() {
            if oc.blocked == ROLLOVER_GONE {
                return Ok(Some(vec![]));
            }
            // the provider broadcast it on ITS node: ours may not have it yet (AGP-056). Vanished only if
            // our node showed it before, or still does not after the relay grace
            if !oc.fund_seen && now_f() - oc.rolled_at < self.cfg.rollover_relay_grace {
                return Ok(Some(vec![]));
            }
            self.upd(loc, oc, |c| c.blocked = ROLLOVER_GONE.into())?;
            let ev = json!({"event": "ch2_rollover_vanished", "provider": oc.origin, "chan": p.channel_id(), "parent": oc.rolled_from});
            self.event(ev.clone());
            return Ok(Some(vec![ev]));
        }
        let Some((tx, depth)) = self.scan.find_spend_at(ptxid, pvout, oc.opened_at.saturating_sub(6))? else { return Ok(None) };
        let spender = tx.txid();
        if spender == txid {
            return Ok(None);
        }
        if matches!(tx.outputs.as_slice(), [_, o] if o.script_pubkey == p.spk()) {
            // AGP-085: another attempt at the same rollover, into this ch2's script, took the place
            // of the one adopted (one next key per ch2: the provider may hold several attempts). The
            // coins are in this ch2 at another outpoint, and every state signed on the old one is
            // void: it starts again as that transaction's child, and the watcher opens it. Locks out
            // on the old outpoint are unpaid once the replacement confirms; until then it waits
            let mut out = vec![];
            if !oc.pending.is_empty() || !oc.stale.is_empty() {
                // (AGP-088: in a block by its own outputs or its depth, not by the parent's
                // funding answering nothing)
                if !self.tx_deep(&tx, depth, self.cfg.spend_final_depth.max(1))? {
                    return Ok(Some(vec![]));
                }
                out.extend(self.release_rolled(loc, oc, "rollover replaced")?);
            }
            let cap = u64::try_from(tx.outputs[1].value).unwrap_or(0);
            let np = p.clone().with_funding(&spender, 1, cap)?;
            let refund = np.refund_tx(&oc.secret_key()?, None, None)?.to_hex();
            let kept = np.channel_id();
            self.upd(loc, oc, |c| {
                c.params = np;
                c.refund_hex = refund;
                c.state = "funded".into();
                c.zero_conf = Map::new();
                c.fund_seen = true;
                c.blocked = String::new();
                (c.signed, c.routed, c.seq) = (0, 0, 0);
            })?;
            let ev = json!({"event": "ch2_rollover_replaced", "provider": oc.origin, "chan": p.channel_id(), "parent": oc.rolled_from,
                            "spender": spender, "kept": kept});
            self.event(ev.clone());
            out.push(ev);
            return Ok(Some(out));
        }
        let why = format!("the rollover was replaced by {spender}");
        self.upd(loc, oc, |c| {
            c.state = "dropped".into();
            c.final_ = true;
            c.blocked = why;
        })?;
        let ev = json!({"event": "ch2_rollover_replaced", "provider": oc.origin, "chan": p.channel_id(), "parent": oc.rolled_from,
                        "spender": spender});
        self.event(ev.clone());
        let mut out = vec![ev];
        let chan = p.channel_id();
        let parents: Vec<(usize, OutChannel)> = lk(&self.out).archived.iter().enumerate()
            .filter(|(_, r)| py_str(r.get("rolled_to")) == chan && r.get("stale").and_then(Value::as_array).is_some_and(|a| !a.is_empty()))
            .filter_map(|(i, r)| OutChannel::from_json(r).ok().map(|c| (i, c))).collect();
        for (i, parent) in parents {
            out.extend(self.secrets_from_close(Loc::Archived(i), &parent, &tx));
        }
        Ok(Some(out))
    }

    /// A `closing` ch2's funding is unspent again: the close left the mempool (replaced, expired) or
    /// never reached this node. A ch2 that was refunded is refunded again (its fee booked again, and
    /// the refund goes out once more); any other stays `closing` (the hub never routes over it again)
    /// and is refunded at expiry unless the provider's close comes back.
    fn close_vanished(&self, loc: Loc<'_>, oc: &OutChannel) -> Result<Vec<Value>> {
        let state = self.upd(loc, oc, |c| {
            if c.close_prev == "refunded" {
                c.state = "refunded".into();
                c.close_prev = String::new();
            }
            c.close_txid = String::new();
            c.state.clone()
        })?.unwrap_or_else(|| oc.state.clone());
        let mut ev = json!({"event": "ch2_close_vanished", "provider": oc.origin, "chan": oc.params.channel_id(), "txid": oc.close_txid,
                            "state": state});
        if state == "refunded" {
            ev["feeRebooked"] = oc.refund_fee.into();
        }
        self.event(ev.clone());
        Ok(vec![ev])
    }

    fn secrets_from_close(&self, loc: Loc<'_>, oc: &OutChannel, tx: &Tx) -> Vec<Value> {
        let mut out = vec![];
        let mut locks: Vec<Value> = vec![];
        if !oc.pending.is_empty() {
            locks.push(Value::Object(oc.pending.clone()));
        }
        locks.extend(oc.stale.iter().cloned());
        let wit = tx.inputs.first().map(|i| i.witness.clone()).unwrap_or_default();
        for lk1 in locks {
            let Some(pre) = lk1.get("pre").filter(|p| truthy(Some(p))).and_then(|p| PreSig::from_json(p).ok()) else { continue };
            let Ok(tp) = adaptor::dec_hex(&py_str(lk1.get("T"))) else { continue };
            let Some(t) = adaptor::secret_from_witness(&pre, &wit, &tp) else { continue };
            let lid = py_str(lk1.get("lockId"));
            // ch1 first, as in `settled` (AGP-073)
            let ch1 = py_str(lk1.get("ch1"));
            let res = match self.complete_ch1(&ch1, &lid, oc, &t, &format!("ch2 close {}", tx.txid())) {
                Ok(r) => r,
                Err(e) => {
                    // ch1 did not take the write: the lock stays on this record for the next tick
                    self.watch_error(&oc.origin, "complete_ch1", &e);
                    out.push(json!({"event": "secret_from_close", "provider": oc.origin, "lockId": lid, "close": tx.txid(), "ch1_completed": false}));
                    continue;
                }
            };
            let _ = self.upd(loc, oc, |c| {
                c.signed = c.signed.max(py_u64(lk1.get("cum")).unwrap_or(0));
                if !c.pending.is_empty() && is_ch2_lock(&Value::Object(c.pending.clone()), &ch1, &lid) {
                    c.routed += py_u64(lk1.get("d")).unwrap_or(0);
                    c.max_lock = c.max_lock.max(py_u64(lk1.get("d")).unwrap_or(0));
                    c.pending = Map::new();
                }
                c.stale.retain(|s| !is_ch2_lock(s, &ch1, &lid));
            });
            out.push(json!({"event": "secret_from_close", "provider": oc.origin, "lockId": lid, "close": tx.txid(), "ch1_completed": res.is_some()}));
        }
        out
    }


    // --- returns (AGP-104) -----------------------------------------------------------------------

    /// The fee of a sweep now, and the least a sweep ever costs: a refund's rate (the node's
    /// estimate for `refund_conf_target`, at least `refund_min_feerate`) or this node's mempool
    /// floor if higher, on [`SWEEP_VSIZE`], never above `refund_max_fee_sat`.
    fn sweep_fee(&self) -> (u64, u64) {
        let floor = (self.cfg.refund_min_feerate * SWEEP_VSIZE as f64).ceil() as u64;
        let mut rate = self.cfg.refund_min_feerate;
        if let Ok(Some(r)) = self.scan.fee_rate(self.cfg.refund_conf_target) {
            rate = rate.max(r);
        }
        if let Ok(Some(r)) = self.chain.mempool_min_fee() {
            rate = rate.max(r);
        }
        (((rate * SWEEP_VSIZE as f64).ceil() as u64).min(self.cfg.refund_max_fee_sat.max(floor)), floor)
    }

    /// Rule R2: what the chain shows of the sweep `txid` of `outpoint` (`txid:vout`), which was
    /// written ahead. `funding`: the channel funding whose spend put the coin on `outpoint`.
    /// `gone_at` (kept by the caller): the tip when the sweep's own output was first seen spent
    /// again, for a wallet that spends what it was paid before the sweep is deep.
    fn sweep_look(&self, txid: &str, outpoint: &str, funding: (&str, u32), gone_at: &mut u32, tip: u32) -> Result<Look> {
        let depth = self.cfg.spend_final_depth.max(1);
        if self.chain.get_tx_out(txid, 0, false)?.is_some_and(|u| u.confirmations >= depth) {
            return Ok(Look::Final);
        }
        if self.chain.get_tx_out(txid, 0, true)?.is_some() {
            *gone_at = 0;
            return Ok(Look::Wait);
        }
        let (stx, svout) = outpoint.rsplit_once(':').and_then(|(t, n)| Some((t, n.parse::<u32>().ok()?))).ok_or_else(|| ChannelError::new("bad_state", "sweep outpoint"))?;
        if self.chain.get_tx_out(stx, svout, true)?.is_some() {
            // the coin is still where the sweep takes it from: the sweep left the mempool
            *gone_at = 0;
            return Ok(Look::Resend);
        }
        if self.chain.get_tx_out(funding.0, funding.1, true)?.is_some() {
            // the spend the coin came from left the chain (a reorg): it comes back first
            *gone_at = 0;
            return Ok(Look::Wait);
        }
        // the coin left `outpoint` and the sweep's output is not there: only this sweep was ever
        // signed for it, so it confirmed and what it paid was spent on. Counted from here
        if *gone_at == 0 {
            *gone_at = tip;
        }
        Ok(if tip.saturating_sub(*gone_at).saturating_add(1) >= depth { Look::Final } else { Look::Wait })
    }

    /// Change ch1's sweep note (`extra.sweep`: `{gone_at, final, skipped}`) and save it.
    fn ch1_sweep_note(&self, ch1: &str, f: impl FnOnce(&mut Map<String, Value>)) -> Result<()> {
        let mut l = self.inbound.ledger_lock();
        let Some(mut st) = l.channels.get(ch1).cloned() else { return Ok(()) };
        let mut sw = st.extra.get("sweep").and_then(Value::as_object).cloned().unwrap_or_default();
        f(&mut sw);
        st.extra.insert("sweep".into(), Value::Object(sw));
        self.inbound.save_state(&mut l, &st)
    }

    /// AGP-104 (R1): one closed ch1. Its close paid the hub on that channel's own payee key; once
    /// that output is `spend_final_depth` deep it is swept to the return address
    /// ([`Provider::sweep_payee`]: written ahead, then sent), and the sweep is watched until it is
    /// that deep itself. An output under the least a sweep costs plus dust is left (`skipped`).
    fn sweep_ch1(&self, ch1: &str, tip: u32) -> Result<Vec<Value>> {
        let Some(st) = self.ch1_state(ch1) else { return Ok(vec![]) };
        if st.closed_txid.is_empty() || sweep_done(st.extra.get("sweep")) {
            return Ok(vec![]);
        }
        let p = &st.params;
        let ev = |e: Value| {
            self.event(e.clone());
            Ok(vec![e])
        };
        let skip = |why: &str, value: u64| -> Result<Vec<Value>> {
            self.ch1_sweep_note(ch1, |sw| {
                sw.insert("final".into(), true.into());
                sw.insert("skipped".into(), why.into());
            })?;
            ev(json!({"event": "ch1_sweep_skipped", "chan": ch1, "value": value, "why": why}))
        };
        if let Some(i) = st.extra.get("payee_sweep_intent").filter(|i| i.get("hex").and_then(Value::as_str).is_some()) {
            let was = py_u64(st.extra.get("sweep").and_then(|s| s.get("gone_at"))).unwrap_or(0) as u32;
            let mut gone = was;
            let (txid, hex_) = (py_str(i.get("txid")), py_str(i.get("hex")));
            let look = self.sweep_look(&txid, &py_str(i.get("outpoint")), (&p.funding_txid(), p.funding_vout()), &mut gone, tip)?;
            if gone != was {
                self.ch1_sweep_note(ch1, |sw| {
                    sw.insert("gone_at".into(), gone.into());
                })?;
            }
            return match look {
                Look::Wait => Ok(vec![]),
                Look::Final => {
                    self.ch1_sweep_note(ch1, |sw| {
                        sw.insert("final".into(), true.into());
                    })?;
                    ev(json!({"event": "ch1_swept", "chan": ch1, "txid": txid, "swept": i.get("swept"), "fee": i.get("fee")}))
                }
                Look::Resend => match self.chain.send_raw_transaction(&hex_) {
                    Ok(_) => ev(json!({"event": "ch1_sweep_resent", "chan": ch1, "txid": txid})),
                    Err(e) => ev(json!({"event": "ch1_sweep_failed", "chan": ch1, "txid": txid, "error": e.to_string().chars().take(200).collect::<String>()})),
                },
            };
        }
        if st.extra.contains_key("payee_sweep") {
            // swept by an operator's tool before the hub swept (no bytes kept to send again)
            self.ch1_sweep_note(ch1, |sw| {
                sw.insert("final".into(), true.into());
            })?;
            return Ok(vec![]);
        }
        let Some((txid, vout, value)) = self.inbound.payee_output(ch1)? else {
            return skip("the close pays nothing to this channel's key", 0);
        };
        let depth = self.cfg.spend_final_depth.max(1);
        if !self.chain.get_tx_out(&txid, vout, false)?.is_some_and(|u| u.confirmations >= depth) {
            // not six deep yet. Given up only when this node shows no such output at all, long
            // after the payer's refund became valid: one that is there and shallow is waited for
            if tip > p.expiry.saturating_add(SWEEP_GIVE_UP_BLOCKS) && self.chain.get_tx_out(&txid, vout, true)?.is_none() {
                return skip("its close is not on the chain", value);
            }
            return Ok(vec![]);
        }
        let (fee, floor) = self.sweep_fee();
        if value < floor.saturating_add(DUST) {
            return skip("under the cost of a sweep plus dust", value);
        }
        if value < fee.saturating_add(DUST) {
            return Ok(vec![]); // the fee is above what this output bears now: looked at again next block
        }
        let Some(dest) = self.return_spk()? else { return Ok(vec![]) };
        let rec = self.inbound.sweep_payee(ch1, &dest, fee)?;
        ev(json!({"event": "ch1_sweep", "chan": ch1, "txid": rec.get("txid"), "value": value, "fee": fee, "swept": rec.get("swept")}))
    }

    /// AGP-104 (R1): one ch2 record whose close or refund is final and which named no return
    /// address (a ledger from before AGP-104, or a hub that ran without the hook): what that
    /// spend left on the ch2's own payer key is swept to the return address, written ahead and
    /// watched as a ch1's sweep is.
    fn sweep_ch2(&self, loc: Loc<'_>, tip: u32) -> Result<Vec<Value>> {
        let Some(oc) = self.get(loc).filter(sweepable) else { return Ok(vec![]) };
        let p = &oc.params;
        let chan = p.channel_id();
        let ev = |e: Value| {
            self.event(e.clone());
            Ok(vec![e])
        };
        let skip = |why: &str| -> Result<Vec<Value>> {
            self.upd(loc, &oc, |c| {
                c.sweep.insert("final".into(), true.into());
                c.sweep.insert("skipped".into(), why.into());
            })?;
            Ok(vec![])
        };
        if let Some(hex_) = oc.sweep.get("hex").and_then(Value::as_str) {
            let was = py_u64(oc.sweep.get("gone_at")).unwrap_or(0) as u32;
            let mut gone = was;
            let txid = py_str(oc.sweep.get("txid"));
            let look = self.sweep_look(&txid, &py_str(oc.sweep.get("outpoint")), (&p.funding_txid(), p.funding_vout()), &mut gone, tip)?;
            if gone != was {
                self.upd(loc, &oc, |c| {
                    c.sweep.insert("gone_at".into(), gone.into());
                })?;
            }
            return match look {
                Look::Wait => Ok(vec![]),
                Look::Final => {
                    self.upd(loc, &oc, |c| {
                        c.sweep.insert("final".into(), true.into());
                    })?;
                    ev(json!({"event": "ch2_swept", "provider": oc.origin, "chan": chan, "txid": txid, "swept": oc.sweep.get("swept"), "fee": oc.sweep.get("fee")}))
                }
                Look::Resend => match self.chain.send_raw_transaction(hex_) {
                    Ok(_) => ev(json!({"event": "ch2_sweep_resent", "provider": oc.origin, "chan": chan, "txid": txid})),
                    Err(e) => ev(json!({"event": "ch2_sweep_failed", "provider": oc.origin, "chan": chan, "txid": txid,
                                        "error": e.to_string().chars().take(200).collect::<String>()})),
                },
            };
        }
        // what is on its key: an output of the spend the record names
        let depth = self.cfg.spend_final_depth.max(1);
        let mut src: Option<(String, u32, u64)> = None;
        let spenders: Vec<&String> = [&oc.close_txid, &oc.refund_txid].into_iter().filter(|t| !t.is_empty()).collect();
        for t in &spenders {
            for n in 0..3u32 {
                if let Some(u) = self.chain.get_tx_out(t, n, false)?.filter(|u| u.script_pubkey == p.payer_spk && u.confirmations >= depth) {
                    src = Some(((*t).clone(), n, u.value));
                }
            }
        }
        if src.is_none() && oc.state == "closed" && oc.close_txid.is_empty() {
            // closed by a spend this node never showed: one look at the UTXO set for this key
            src = self.scan.scan_spk(&p.payer_spk)?.into_iter().next();
        }
        let Some((stx, svout, value)) = src else { return skip("nothing on its own key") };
        let (fee, floor) = self.sweep_fee();
        if value < floor.saturating_add(DUST) {
            return skip("under the cost of a sweep plus dust");
        }
        if value < fee.saturating_add(DUST) {
            return Ok(vec![]);
        }
        let Some(dest) = self.return_spk()? else { return Ok(vec![]) };
        let op = OutPoint::from_display(&stx, svout).map_err(|_| ChannelError::new("bad_state", "sweep outpoint"))?;
        let mut tx = Tx::new(2, vec![TxIn::new(op, 0xFFFF_FFFD)], vec![TxOut::new((value - fee) as i64, dest.clone())], 0);
        sign_p2wpkh(&oc.secret_key()?, &mut tx, &[TxOut::new(value as i64, p.payer_spk.clone())], 0)?;
        let (txid, hex_) = (tx.txid(), tx.to_hex());
        let rec = json!({"txid": txid, "hex": hex_, "outpoint": format!("{stx}:{svout}"), "value": value, "fee": fee, "swept": value - fee,
                         "dest_spk": hex::encode(&dest), "at": tip});
        // write-ahead (R2): the one sweep of this output, before it is sent
        if self.upd(loc, &oc, |c| c.sweep = rec.as_object().cloned().unwrap_or_default())?.is_none() {
            return Ok(vec![]);
        }
        self.stop("sweep")?;
        if let Err(e) = self.chain.send_raw_transaction(&hex_) {
            return ev(json!({"event": "ch2_sweep_failed", "provider": oc.origin, "chan": chan, "txid": txid,
                             "error": e.to_string().chars().take(200).collect::<String>()}));
        }
        ev(json!({"event": "ch2_sweep", "provider": oc.origin, "chan": chan, "txid": txid, "value": value, "fee": fee, "swept": value - fee}))
    }

    /// AGP-104 (rule R1): sweep what closes left on per-channel keys to the return address, and
    /// watch the sweeps already out (rule R2). Once a block, and only with a return hook set.
    /// Every closed ch1 not yet swept for good, then every ch2 record that named no return
    /// address. Errors are per channel (`sweep_error`) and are tried again next block.
    pub fn sweep_tick(&self, tip: u32) -> Vec<Value> {
        if lk(&self.return_to).is_none() || lk(&self.sweep_tip).replace(tip) == Some(tip) {
            return vec![];
        }
        let mut acts = vec![];
        let ch1s: Vec<String> = self.inbound.ledger_lock().channels.iter()
            .filter(|(_, s)| !s.closed_txid.is_empty() && !sweep_done(s.extra.get("sweep"))).map(|(c, _)| c.clone()).collect();
        for ch1 in ch1s {
            match self.sweep_ch1(&ch1, tip) {
                Ok(mut a) => acts.append(&mut a),
                Err(e) => self.sweep_error("ch1", &ch1, &e),
            }
        }
        let (live, old): (Vec<String>, Vec<usize>) = {
            let b = lk(&self.out);
            (b.chans.iter().filter(|(_, c)| sweepable(c)).map(|(o, _)| o.clone()).collect(),
             b.archived.iter().enumerate().filter(|(_, r)| OutChannel::from_json(r).is_ok_and(|c| sweepable(&c))).map(|(i, _)| i).collect())
        };
        let locs = live.iter().map(|o| Loc::Live(o)).chain(old.into_iter().map(Loc::Archived));
        for loc in locs {
            if let Err(e) = self.sweep_ch2(loc, tip).map(|mut a| acts.append(&mut a)) {
                self.sweep_error("ch2", &self.get(loc).map(|c| c.params.channel_id()).unwrap_or_default(), &e);
            }
        }
        acts
    }

    fn sweep_error(&self, what: &str, chan: &str, e: &ChannelError) {
        let msg: String = e.to_string().chars().take(200).collect();
        eprintln!("hub watcher sweep {what} {chan}: {msg}");
        self.event(json!({"event": "sweep_error", "what": what, "chan": chan, "error": msg}));
    }

    // --- status (AGP-104) ------------------------------------------------------------------------

    /// Where the hub's coins are, for its operator. `wallet_sat`: what the hub's wallet holds
    /// (None: not known; the sums that need it are null).
    ///
    /// Four numbers, each coin in exactly one:
    /// * `capitalSat`: free, in the wallet;
    /// * `inChannelsSat`: the hub's side of its ch2s (the capacity less what it signed to the
    ///   provider), and what a close or refund left on a ch2's own key until its sweep is out;
    /// * `earnedSat`: signed to the hub by clients and not in the wallet yet (open ch1s, and
    ///   closed ones until their sweep is out);
    /// * `stuckSat`: the part of a ch2 a lock without an answer may still take (held, written
    ///   off), each listed in `stuck` with the block by which it resolves.
    ///
    /// Rule: `capitalSat + inChannelsSat + earnedSat + stuckSat = depositsSat + feesEarnedSat −
    /// chainFeesSat − dustSat`, to the sat, between two watcher ticks with nothing in flight.
    /// `feesEarnedSat` is what clients signed to the hub less what the hub signed to providers
    /// (negative while a provider's dust floor is above what its client paid). `chainFeesSat`:
    /// the fundings', refunds' and sweeps' miner fees and the close fees the hub pays.
    /// `dustSat`: left on a channel key because a sweep would cost more than it moves.
    /// `depositsSat` is derived from the others: what the operator sent in, less what was taken
    /// out. `estimated`: a term was not read off the chain or the wallet (a ledger from before
    /// AGP-104, a wallet that does not report fees). `unsettled`: a funding is being reconciled.
    pub fn status(&self, wallet_sat: Option<u64>) -> Value {
        let tip = self.chain.block_count().ok();
        let depth = self.cfg.spend_final_depth.max(1);
        let late = |l: &Map<String, Value>| !l.is_empty() && now_f() - l.get("at").and_then(Value::as_f64).unwrap_or(0.0) >= self.reveal_timeout();
        let (recs, sellers, committed_sat) = {
            let b = lk(&self.out);
            let mut recs: Vec<OutChannel> = b.chans.values().chain(b.next_chans.values()).cloned().collect();
            recs.extend(b.archived.iter().filter_map(|r| OutChannel::from_json(r).ok()));
            let sellers: Vec<Value> = b.chans.iter().map(|(o, c)| {
                let one = |c: &OutChannel| json!({"state": c.state, "chan": c.params.channel_id(), "capacitySat": c.params.capacity, "paidSat": c.signed,
                                                  "roomSat": c.params.max_amount().saturating_sub(c.signed), "expiry": c.params.expiry, "blocked": c.blocked});
                let mut v = one(c);
                v["origin"] = o.as_str().into();
                v["payTo"] = c.pay_to.as_str().into();
                v["next"] = b.next_chans.get(o).map(one).unwrap_or(Value::Null);
                v
            }).collect();
            (recs, sellers, committed(&b))
        };
        // a ch2's coins that a rollover carried into its child
        let carried: HashMap<String, u64> = recs.iter().filter(|c| !c.rolled_from.is_empty() && c.state != "dropped" && c.params.funding.is_some())
            .map(|c| (c.rolled_from.clone(), c.params.capacity)).collect();
        let (mut in_ch, mut stuck_sat, mut out, mut chain, mut dust) = (0u64, 0u64, 0u64, 0u64, 0u64);
        let (mut estimated, mut unsettled, mut sweeps) = (false, false, 0u64);
        let mut stuck: Vec<Value> = vec![];
        // (ch1, lockId) of every lock a ch2 record still holds
        let mut on_ch2: HashSet<(String, String)> = HashSet::new();
        for c in &recs {
            let p = &c.params;
            if !c.final_ {
                let mut locks: Vec<(&Map<String, Value>, &str)> = c.stale.iter().filter_map(Value::as_object).map(|l| (l, "written off")).collect();
                if !c.pending.is_empty() {
                    on_ch2.insert((py_str(c.pending.get("ch1")), py_str(c.pending.get("lockId"))));
                    if late(&c.pending) {
                        locks.push((&c.pending, "no answer"));
                    }
                }
                let grace = if c.signed >= p.min_amount() { self.cfg.refund_grace_blocks } else { 0 };
                let by = if c.gone_at > 0 { c.gone_at.saturating_add(depth - 1) } else { p.expiry.saturating_add(grace).saturating_add(depth) };
                for (l, kind) in locks {
                    on_ch2.insert((py_str(l.get("ch1")), py_str(l.get("lockId"))));
                    stuck.push(json!({"lockId": l.get("lockId"), "seller": c.origin, "amountSat": py_u64(l.get("d")).unwrap_or(0), "kind": kind,
                                      "hubSat": py_u64(l.get("cum")).unwrap_or(0).saturating_sub(c.signed), "resolvesBy": by}));
                }
            }
            if c.state == "funding" || (c.state == "dropped" && !c.final_) {
                unsettled = true; // the wallet may have paid for it: the watcher is finding out
                continue;
            }
            if p.funding.is_none() || c.state == "dropped" {
                continue;
            }
            let (cap, pf) = (p.capacity, p.payer_fee());
            if c.rolled_from.is_empty() {
                match c.fund_fee {
                    Some(f) => chain = chain.saturating_add(f),
                    None => estimated = true,
                }
            }
            if !c.final_ && (["funded", "open"].contains(&c.state.as_str()) || (c.state == "closing" && !c.spend_seen)) {
                // the highest state a lock without an answer could still close this ch2 with
                let waiting = if late(&c.pending) { py_u64(c.pending.get("cum")).unwrap_or(0) } else { 0 };
                let top = c.stale.iter().map(|l| py_u64(l.get("cum")).unwrap_or(0)).fold(waiting, u64::max);
                let mine = cap.saturating_sub(c.signed);
                let held = top.saturating_sub(c.signed).min(mine);
                (stuck_sat, in_ch, out) = (stuck_sat + held, in_ch + (mine - held), out + c.signed);
                continue;
            }
            if let Some(child) = carried.get(&p.channel_id()).filter(|_| ["rolled", "closed", "closing"].contains(&c.state.as_str())) {
                (out, chain) = (out + cap.saturating_sub(*child).saturating_sub(pf), chain + pf);
                continue;
            }
            let (back, on_key) = if refund_booked(&c.state, &c.close_prev) {
                chain += c.refund_fee;
                let dest = Tx::parse_hex(&c.refund_hex).ok().and_then(|t| t.outputs.first().map(|o| o.script_pubkey.clone()));
                (cap.saturating_sub(c.refund_fee), own_key(p) && dest.is_some_and(|d| d == p.payer_spk))
            } else {
                let back = match (c.returned, c.close_cum) {
                    (Some(r), _) => r.min(cap),
                    (None, Some(cum)) => cap.saturating_sub(pf).saturating_sub(cum),
                    (None, None) => {
                        estimated = true;
                        cap.saturating_sub(pf).saturating_sub(c.signed)
                    }
                };
                (out, chain) = (out + cap.saturating_sub(back).saturating_sub(pf), chain + pf);
                (back, own_key(p))
            };
            if on_key && back > 0 {
                if c.sweep.get("txid").is_some_and(Value::is_string) {
                    chain += py_u64(c.sweep.get("fee")).unwrap_or(0);
                } else if truthy(c.sweep.get("final")) {
                    dust += back;
                } else {
                    in_ch += back;
                }
                if !truthy(c.sweep.get("final")) {
                    sweeps += 1;
                }
            }
        }
        let (mut earned, mut inn) = (0u64, 0u64);
        {
            let l = self.inbound.ledger_lock();
            for (ch1, st) in l.channels.iter() {
                let ex = &st.extra;
                // locks on ch1 that no ch2 record holds: an orphan the next tick drops, or a hold nothing releases before ch1 closes
                let lone = |x: &Value| truthy(Some(x)) && !on_ch2.contains(&(ch1.clone(), py_str(x.get("lockId"))));
                if let Some(rl) = ex.get("route_lock").filter(|x| lone(x) && x.as_object().is_some_and(late)) {
                    stuck.push(json!({"lockId": rl.get("lockId"), "seller": rl.get("provider"), "amountSat": py_u64(rl.get("d")).unwrap_or(0), "kind": "orphaned",
                                      "hubSat": 0, "resolvesBy": tip}));
                }
                for s in ex.get("stale_locks").and_then(Value::as_array).into_iter().flatten().filter(|x| lone(x)) {
                    stuck.push(json!({"lockId": s.get("lockId"), "seller": s.get("provider"), "amountSat": py_u64(s.get("d")).unwrap_or(0), "kind": "held",
                                      "hubSat": 0, "resolvesBy": st.params.expiry}));
                }
                if st.closed_txid.is_empty() {
                    (earned, inn) = (earned + st.best_cum, inn + st.best_cum);
                    if st.best_cum > 0 && tip.is_some_and(|t| t > st.params.expiry) {
                        unsettled = true; // past its expiry and not closed: the payer may have refunded it
                    }
                    continue;
                }
                let fee = st.params.payee_fee();
                let v = match ex.get("close_paid").and_then(Value::as_u64) {
                    Some(v) => v,
                    None => {
                        estimated = true;
                        st.params.payee_value(st.best_cum)
                    }
                };
                (inn, chain) = (inn + v + fee, chain + fee);
                let kid = py_u64(ex.get("close_bump").and_then(|b| b.get("fee"))).unwrap_or(0).min(v);
                let done = sweep_done(ex.get("sweep"));
                if let Some(i) = ex.get("payee_sweep_intent").or(ex.get("payee_sweep")) {
                    chain += v.saturating_sub(py_u64(i.get("swept")).unwrap_or(0));
                } else if done {
                    (dust, chain) = (dust + (v - kid), chain + kid);
                } else {
                    (earned, chain) = (earned + (v - kid), chain + kid);
                }
                if !done {
                    sweeps += 1;
                }
            }
        }
        let fees = inn as i128 - out as i128;
        let total = wallet_sat.map(|w| w as i128 + in_ch as i128 + earned as i128 + stuck_sat as i128);
        let deposits = total.map(|t| t - fees + chain as i128 + dust as i128);
        let i = |v: i128| Value::from(v as i64);
        json!({"capitalSat": wallet_sat, "inChannelsSat": in_ch, "earnedSat": earned, "stuckSat": stuck_sat, "totalSat": total.map(i),
               "feesEarnedSat": i(fees), "routedInSat": inn, "routedOutSat": out, "chainFeesSat": chain, "dustSat": dust,
               "depositsSat": deposits.map(i), "estimated": estimated, "unsettled": unsettled, "sweepsPending": sweeps,
               "capitalSetting": Some(self.cfg.capital_sat).filter(|c| *c > 0), "liquidityCapSat": self.cfg.liquidity_cap(), "committedSat": committed_sat,
               "tip": tip, "spendFinalDepth": depth, "stuck": stuck, "sellers": sellers, "payTo": self.pay_to, "network": self.network,
               "returns": lk(&self.return_to).is_some()})
    }

    /// Run [`RouteHub::watch_tick`] every `interval` on a thread until the returned flag is set.
    ///
    /// AGP-094 rule: a tick that panics ends that tick, never the watcher: it is caught, said and
    /// counted ([`Self::watch_health`]), and the next tick runs. The tick writes ahead of every
    /// step, so what a panic leaves is what a crash at that step leaves, and the next tick
    /// finishes it. (ch1's closes run inside the tick under their own catch:
    /// [`Provider::close_due`].)
    pub fn watch(self: &Arc<Self>, interval: Duration) -> Arc<AtomicBool> {
        let stop = Arc::new(AtomicBool::new(false));
        let (hub, flag) = (self.clone(), stop.clone());
        std::thread::Builder::new().name("hub-watcher".into()).spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                std::thread::sleep(interval);
                if flag.load(Ordering::Relaxed) {
                    break;
                }
                if let Err(msg) = hub.watch_health.run(|| hub.watch_tick()) {
                    eprintln!("hub watcher: a tick panicked ({msg}); the next tick runs");
                    hub.event(json!({"event": "watch_panic", "error": msg}));
                }
            }
        }).expect("spawn watcher");
        stop
    }

    /// The watcher for `/healthz`: `{ok, ticks, panics, lastTickAt, lastPanic}` of the hub's own
    /// tick, and `ch1` for the closes of ch1 inside it. `ok` is false from a tick that panicked
    /// until one that did not.
    pub fn watch_health(&self) -> Value {
        let (mut v, ch1) = (self.watch_health.to_json(), self.inbound.watch_health());
        v["ok"] = (v["ok"] == true && ch1["ok"] == true).into();
        v["ch1"] = ch1;
        v
    }

    /// A ch1 as the hub sees it (its ledger row).
    pub fn ch1_state(&self, chan: &str) -> Option<ChannelState> {
        self.inbound.channel_state(chan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A state file's JSON with `n` ch2 records like the hub writes (2 in 5 carry a rollover's next
    /// ch2 inside), plaintext keys.
    fn cost_doc(n: usize) -> Value {
        let rec = |i: usize| {
            let k = format!("{:064x}", i + 1);
            let pub_ = hex::encode(ecdsa::pubkey(&Sc::from_hex64(&k).and_then(|s| s.secret()).unwrap()));
            let extra: Map<String, Value> = (0..16).map(|j| (format!("field{j}"), Value::from(format!("value{j}")))).collect();
            json!({"origin": format!("http://p{i}.test"), "pay_to": "02".repeat(33), "state": "open", "signed": 3000,
                   "params": {"payer_pub": pub_, "payee_pub": "03".repeat(33), "expiry": 2000, "capacity": 100_000,
                              "funding_txid": "ab".repeat(32), "funding_vout": 0, "close_fee": 600},
                   "secret": k, "terms": {"scheme": "batch-settlement", "extra": extra},
                   "refund_hex": "00".repeat(200), "final": false, "pending": {}, "stale": []})
        };
        let (mut chans, mut archived, mut i) = (Map::new(), vec![], 0);
        while i < n {
            let mut r = rec(i);
            i += 1;
            if i % 5 < 2 && i < n {
                r["next"] = rec(i);
                i += 1;
            }
            if chans.len() < n / 3 {
                chans.insert(format!("http://p{i}.test"), r);
            } else {
                archived.push(r);
            }
        }
        json!({"chans": chans, "archived": archived, "origins": {}, "next_chans": {}})
    }

    #[test]
    #[ignore = "a cost figure: cargo test -p xbt402 --release --lib seal_cost -- --ignored --nocapture"]
    fn seal_cost() {
        use std::time::Instant;
        let book = OutBook::open(None, Some(WrapKey::from_bytes([7; 32]))).unwrap();
        let doc = cost_doc(10);
        book.sealed_doc(doc.clone()).unwrap(); // every key sealed once, as after the first write
        let n = 2_000;
        let t = Instant::now();
        for _ in 0..n {
            std::hint::black_box(doc.clone());
        }
        let clone = t.elapsed().as_secs_f64() / n as f64;
        let t = Instant::now();
        for _ in 0..n {
            std::hint::black_box(book.sealed_doc(doc.clone()).unwrap());
        }
        let per_write = t.elapsed().as_secs_f64() / n as f64 - clone;
        let t = Instant::now();
        for _ in 0..n / 10 {
            std::hint::black_box(dumps(&doc));
        }
        let dumps_one = t.elapsed().as_secs_f64() / (n / 10) as f64;
        let wrap = WrapKey::from_bytes([7; 32]);
        let t = Instant::now();
        for i in 0..200 {
            std::hint::black_box(wrap.seal(&format!("{:064x}", i + 1)).unwrap());
        }
        let seal_one = t.elapsed().as_secs_f64() / 200.0;
        let big = book.sealed_doc(cost_doc(100)).unwrap();
        let mut open100 = f64::MAX;
        for _ in 0..3 {
            let mut b = OutBook::open(None, Some(WrapKey::from_bytes([7; 32]))).unwrap();
            let mut d = big.clone();
            let t = Instant::now();
            b.unseal_all(&mut d).unwrap();
            open100 = open100.min(t.elapsed().as_secs_f64());
        }
        println!(
            "seal_cost: per write (10 records, cached) {:.1} us; the write's own dumps {:.1} us; seal one new key {:.1} us; open 100 records {:.1} ms",
            per_write * 1e6,
            dumps_one * 1e6,
            seal_one * 1e6,
            open100 * 1e3
        );
    }

    #[test]
    fn a_ch2_rolled_before_agp088_is_left_final_and_one_rolled_since_is_watched() {
        // `rolled` is now a state the watcher reconciles until the rollover is in a block. A record
        // rolled by a hub from before (it has no `fund_confirmed`) was never watched again, and is
        // not read against the chain from its first block on every tick now
        let dir = std::env::temp_dir().join(format!("xbt-rs-agp088-book-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ch2.json");
        let mut doc = cost_doc(10);
        doc["chans"] = json!({}); // (their params are placeholders: only the archive is read as it is)
        let recs = doc["archived"].as_array_mut().unwrap();
        recs[0]["state"] = "rolled".into();
        recs[1]["state"] = "rolled".into();
        recs[1]["fund_confirmed"] = true.into();
        std::fs::write(&path, dumps(&doc)).unwrap();
        let b = OutBook::open(Some(&path), Some(WrapKey::from_bytes([7; 32]))).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!((watched(&b.archived[0]), watched(&b.archived[1])), (false, true), "{:?}", b.archived);
    }

    #[test]
    fn config_rejects_unknown_keys_and_bad_payers() {
        assert!(HubConfig::from_json(&json!({"fee_ppm": 10, "nope": 1})).is_err());
        assert!(HubConfig::from_json(&json!({"ch2_close_fee_payer": "hub"})).is_err());
        let c = HubConfig::from_json(&json!({"fee_ppm": 10, "reveal_timeout": 2.5, "policy": {"min_expiry_blocks": 10}})).unwrap();
        assert_eq!((c.fee_ppm, c.reveal_timeout), (10, 2.5));
        assert_eq!(c.funding_policy().unwrap().min_expiry_blocks, 10);
        assert!(HubConfig::from_json(&json!({"policy": {"bogus": 1}})).is_err());
    }

    #[test]
    fn max_lock_sat_defaults_small_and_is_at_most_half_of_ch2_capacity() {
        let c = HubConfig::from_json(&json!({})).unwrap();
        assert!(c.max_lock_sat * 5 <= c.ch2_capacity, "{} vs {}", c.max_lock_sat, c.ch2_capacity);
        assert!(HubConfig::from_json(&json!({"max_lock_sat": 0})).is_err());
        let cap = c.ch2_capacity;
        assert!(HubConfig::from_json(&json!({"max_lock_sat": cap / 2})).is_ok());
        assert!(HubConfig::from_json(&json!({"max_lock_sat": cap / 2 + 1})).is_err());
        assert!(HubConfig::from_json(&json!({"max_lock_sat": 1_000, "ch2_capacity": 1_999})).is_err());
    }
}
