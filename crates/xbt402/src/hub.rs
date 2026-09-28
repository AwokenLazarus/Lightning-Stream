//! The xbt402 routing hub (a port of B1 `xbt402/hub.py`, AGP-021/023): one client → hub channel
//! pays many providers through hub-funded hub → provider channels, with adaptor-locked states on
//! both hops.
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
//! Then it writes the ch1 lock to disk, pre-signs ch2 under T, writes that, sends it to the
//! provider, checks t·G = T, completes ch1 with t + r and answers the client with t + r.
//!
//! The watcher ([`RouteHub::watch_tick`]) opens hub-funded ch2s once confirmed; retries a pending
//! ch2 lock until `revealTimeoutSec`, then writes it off and stops routing to that provider; reads
//! t off any ch2 close that spends a funding with a pending or written-off lock and completes the
//! ch1 lock with t + r; rolls ch2 over once the provider's net payout reaches its settleMultiple ×
//! closeFee or ch2 nears expiry (never while a lock is pending); and closes ch1s at their margin.
//!
//! Close fees (v1.2): ch2 is payee-pays by default (each provider pays its own settlement), ch1
//! payer-pays (the client), and `extra.routing` advertises both.
//!
//! Lock order: the ch1 ledger may be held while the out book is taken, never the reverse; a
//! provider's busy flag is taken with a timeout (route) or not at all (watcher).
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use indexmap::IndexMap;
use serde_json::{json, Map, Value};
use xbt_primitives::address::segwit_address;
use xbt_primitives::ecdsa;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::sighash::SIGHASH_ALL_UNIFIED;
use xbt_primitives::tx::Tx;

use crate::adaptor::{self, PreSig, Sc};
use crate::channel::{canonical_chan, channel_auth_key, settle_due, sign_with_type, ChannelParams, FeePayer};
use crate::client::{Transport, Wallet};
use crate::error::{fail, ChannelError, Result};
use crate::funding::{ChainBackend, FundingPolicy};
use crate::json::{dumps, py_int, py_str, py_u64, truthy};
use crate::ledger::{ChannelState, Ledger};
use crate::provider::{HttpResponse, Provider, ProviderConfig};
use crate::route::*;
use crate::wire::*;

fn lk<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

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
}

impl Default for HubConfig {
    fn default() -> Self {
        Self { fee_base_msat: 1_000, fee_ppm: 2_000, fee_strategy: json!({"kind": "flat"}), quote_ttl: 600, max_lock_sat: 50_000,
               max_unguarded_lock_sat: 500, delta: 144, reveal_timeout: 10.0, ch2_capacity: 100_000, ch2_expiry_blocks: 1_100,
               liquidity_cap_sat: 0, close_fee: 600, ch1_close_fee_payer: FeePayer::Payer, ch2_close_fee_payer: FeePayer::Payee,
               close_margin: 144, rollover_margin: 36, hrp: "bcrt".into(), policy: json!({"min_expiry_blocks": 1_008, "max_expiry_blocks": 8_640}) }
    }
}

const HUB_KEYS: [&str; 19] = ["fee_base_msat", "fee_ppm", "fee_strategy", "quote_ttl", "max_lock_sat", "max_unguarded_lock_sat", "delta",
                              "reveal_timeout", "ch2_capacity", "ch2_expiry_blocks", "liquidity_cap_sat", "close_fee",
                              "ch1_close_fee_payer", "ch2_close_fee_payer", "close_margin", "rollover_margin", "hrp", "policy", "_comment"];

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
        c.funding_policy()?;
        Ok(c)
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
    /// Payer key (regtest: stored here; production: a B2-style signer).
    pub secret: String,
    /// funded -> open -> closed | rolled.
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
}

impl OutChannel {
    pub fn to_json(&self) -> Value {
        json!({"origin": self.origin, "pay_to": self.pay_to, "params": self.params.to_json(), "secret": self.secret, "state": self.state,
               "signed": self.signed, "routed": self.routed, "seq": self.seq, "pending": self.pending, "stale": self.stale,
               "settle_multiple": self.settle_multiple, "terms": self.terms, "refund_hex": self.refund_hex, "blocked": self.blocked,
               "close_txid": self.close_txid, "rolled_to": self.rolled_to, "opened_at": self.opened_at, "scanned_to": self.scanned_to})
    }

    pub fn from_json(v: &Value) -> Result<Self> {
        let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let n = |k: &str| py_u64(v.get(k)).unwrap_or(0);
        Ok(Self { origin: s("origin"), pay_to: s("pay_to"), params: ChannelParams::from_json(&v["params"])?, secret: s("secret"),
                  state: s("state"), signed: n("signed"), routed: n("routed"), seq: n("seq"),
                  pending: v.get("pending").and_then(Value::as_object).cloned().unwrap_or_default(),
                  stale: v.get("stale").and_then(Value::as_array).cloned().unwrap_or_default(), settle_multiple: n("settle_multiple"),
                  terms: v.get("terms").cloned().unwrap_or(Value::Null), refund_hex: s("refund_hex"), blocked: s("blocked"),
                  close_txid: s("close_txid"), rolled_to: s("rolled_to"), opened_at: n("opened_at") as u32, scanned_to: n("scanned_to") as u32 })
    }

    fn secret_key(&self) -> Result<SecretKey> {
        Sc::from_hex64(&self.secret).and_then(|s| s.secret()).ok_or_else(|| ChannelError::new("bad_state", "ch2 key"))
    }

    fn term_u64(&self, k: &str) -> Option<u64> {
        py_u64(self.terms.get("extra").and_then(|e| e.get(k)))
    }
}

/// The hub's ch2s, an fsynced JSON file (keys included: regtest only).
#[derive(Debug, Default)]
pub struct OutBook {
    path: Option<PathBuf>,
    pub chans: IndexMap<String, OutChannel>,
    pub archived: Vec<Value>,
}

impl OutBook {
    pub fn open(path: Option<&Path>) -> Result<Self> {
        let mut b = Self { path: path.map(Path::to_path_buf), ..Default::default() };
        if let Some(raw) = path.and_then(|p| std::fs::read(p).ok()) {
            let v: Value = crate::json::parse_slice(&raw).map_err(|e| ChannelError::new("ledger_error", e.to_string()))?;
            for (k, c) in v.get("chans").and_then(Value::as_object).into_iter().flatten() {
                b.chans.insert(k.clone(), OutChannel::from_json(c)?);
            }
            b.archived = v.get("archived").and_then(Value::as_array).cloned().unwrap_or_default();
        }
        Ok(b)
    }

    pub fn save(&self) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let chans: Map<String, Value> = self.chans.iter().map(|(k, v)| (k.clone(), v.to_json())).collect();
        let io = |e: std::io::Error| ChannelError::new("ledger_error", e.to_string());
        let tmp = path.with_extension("tmp");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp).map_err(io)?;
            f.write_all(dumps(&json!({"chans": chans, "archived": self.archived})).as_bytes()).map_err(io)?;
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
}

/// `callable(hub) -> (fee_base_msat, fee_ppm)`.
pub type FeeStrategyFn = Box<dyn Fn(&RouteHub) -> (u64, u64) + Send + Sync>;

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
    /// Tests/demo: "" | "receipt" (keep t + r from the client) | "all" (forward nothing).
    pub withhold: Mutex<String>,
    pub events: Mutex<Vec<Value>>,
    pub stats: Mutex<HubStats>,
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
    /// `ch1.jsonl` (ch1 ledger) and `ch2.json` (the out book).
    #[allow(clippy::too_many_arguments)]
    pub fn new(chain: Arc<dyn ChainBackend>, scan: Arc<dyn SpendScan>, wallet: Box<dyn Wallet>, http: Box<dyn Transport>,
               pay_to_secret: SecretKey, network: &str, datadir: Option<&Path>, cfg: HubConfig) -> Result<Self> {
        if let Some(d) = datadir {
            std::fs::create_dir_all(d).map_err(|e| ChannelError::new("ledger_error", e.to_string()))?;
        }
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
        let out = OutBook::open(datadir.map(|d| d.join("ch2.json")).as_deref())?;
        Ok(Self { pay_to: hex::encode(ecdsa::pubkey(&pay_to_secret)), cfg, chain, scan, wallet, http, secret: pay_to_secret,
                  network: network.into(), inbound, out: Mutex::new(out), busy: Mutex::new(HashSet::new()), quote: Mutex::new(None),
                  quote_seq: Mutex::new(now_i()), reveal_timeout_bits: AtomicU64::new(0), fee_strategy: None, withhold: Mutex::new(String::new()), events: Mutex::new(vec![]),
                  stats: Mutex::new(HubStats::default()) })
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

    pub fn archived(&self) -> Vec<Value> {
        lk(&self.out).archived.clone()
    }

    pub fn set_withhold(&self, mode: &str) {
        *lk(&self.withhold) = mode.to_string();
    }

    fn withholding(&self) -> String {
        lk(&self.withhold).clone()
    }

    fn event(&self, e: Value) {
        lk(&self.events).push(e);
    }

    /// The hub's own coins in live ch2s (funded or open).
    pub fn committed_sat(&self) -> u64 {
        lk(&self.out).chans.values().filter(|c| c.state == "funded" || c.state == "open").map(|c| c.params.capacity).sum()
    }

    fn configured_fees(&self) -> Result<(u64, u64)> {
        let st = &self.cfg.fee_strategy;
        let kind = st.get("kind").and_then(Value::as_str).unwrap_or("flat");
        match kind {
            "flat" => Ok((self.cfg.fee_base_msat, self.cfg.fee_ppm)),
            "utilization" => {
                let cap = self.cfg.liquidity_cap_sat;
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
        let mut providers: Vec<String> = lk(&self.out).chans.iter().filter(|(_, c)| c.state == "open" && c.blocked.is_empty()).map(|(o, _)| o.clone()).collect();
        providers.sort();
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
        if path.split('?').next() == Some(HUB_ROUTE_PATH) {
            let hdr = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-SIGNATURE")).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty());
            if let (true, Some(h)) = (method == "POST", hdr) {
                return self.route(method, HUB_ROUTE_PATH, h, body);
            }
            let mut doc = self.inbound.payment_required_doc(if url.is_empty() { path } else { url }, 0, "payment_required", None);
            match self.routing_extra() {
                Ok(r) => doc["accepts"][0]["extra"]["routing"] = r,
                Err(e) => return err(500, &e.code, &e.to_string(), json!({})),
            }
            return self.inbound.required_response(&doc);
        }
        self.inbound.serve(method, path, headers, body, url, max_body)
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

    // --- POST /x402/route ---------------------------------------------------------------------------

    fn route(&self, method: &str, path: &str, hdr: &str, body: &[u8]) -> HttpResponse {
        let t0 = Instant::now();
        let parsed = (|| -> Option<(Value, Value, i128, i128, String, String)> {
            let pl = unb64json(hdr).ok()?.get("payload")?.clone();
            let rt = crate::json::parse_slice(body).ok()?.get("route")?.clone();
            if !pl.is_object() || !rt.is_object() {
                return None;
            }
            let (d, f) = (py_int(rt.get("amount"))?, py_int(rt.get("fee"))?);
            let lock_id = py_str(Some(rt.get("lockId")?));
            let provider = py_str(Some(rt.get("provider")?)).trim_end_matches('/').to_string();
            Some((pl, rt, d, f, lock_id, provider))
        })();
        let Some((pl, rt, d, f, lock_id, provider)) = parsed else { return e400("bad_payload", "") };
        let mut l = self.inbound.ledger_lock();
        // 1 auth -------------------------------------------------------------------------------------
        let cid = pl.get("chan").and_then(Value::as_str).and_then(|c| canonical_chan(c).ok()).filter(|c| l.channels.contains_key(c));
        let Some(cid) = cid else { return e400("unknown_channel", "") };
        let mut st1 = l.channels[&cid].clone();
        if !self.inbound.authentic(&st1, &pl, method, path, body) {
            return err(401, "bad_auth", "", json!({}));
        }
        st1.seq = py_u64(pl.get("seq")).unwrap_or(st1.seq);
        l.channels.insert(cid.clone(), st1.clone());
        if let Some(done) = st1.extra.get("route_done").and_then(|d| d.get(&lock_id)) {
            // the client lost our answer: the same one again
            return ok_json(done);
        }
        let height = match self.inbound.height() {
            Ok(h) => h,
            Err(e) => return err(500, "node_error", &e.to_string(), json!({})),
        };
        if !st1.closed_txid.is_empty() || height as i64 >= st1.params.expiry as i64 - self.cfg.close_margin as i64 {
            return e400("channel_closing", "");
        }
        if st1.suspended {
            return e400("unconfirmed", "");
        }
        // 2 point ------------------------------------------------------------------------------------
        let pts = (|| -> Option<_> {
            let tp = adaptor::dec_hex(rt.get("point")?.as_str()?).ok()?;
            let r = Sc::from_hex_mod_n(rt.get("tweak")?.as_str()?)?;
            let t1 = if truthy(pl.get("point")) { Some(adaptor::dec_hex(pl.get("point")?.as_str()?).ok()?) } else { None };
            Some((tp, r, t1))
        })();
        let Some((tp, r, t1)) = pts else { return e400("bad_point", "points must be compressed secp256k1 points") };
        if let Some(t1) = &t1 {
            if r.is_zero() || adaptor::add(Some(&tp), adaptor::mul(&r, None).as_ref()) != Some(*t1) {
                return e400("bad_point", "T1 != T + r*G");
            }
        }
        // 3 amount -----------------------------------------------------------------------------------
        let ex1 = st1.extra.clone();
        let routed1 = py_u64(ex1.get("routed_sat")).unwrap_or(0);
        let fee_units = u128_of(ex1.get("fee_units")).unwrap_or(0);
        let fee_paid = py_u64(ex1.get("fee_paid")).unwrap_or(0);
        let cum = py_int(pl.get("cum")).unwrap_or(-1);
        if d < 1 || f < 0 || d > self.cfg.max_lock_sat as i128 {
            return e400("bad_amount", &format!("lock amount must be in [1, {}]", self.cfg.max_lock_sat));
        }
        let (d, f) = (d as u64, u64::try_from(f).unwrap_or(u64::MAX / 4));
        let need1 = next_cum(routed1, d.saturating_add(f), st1.params.min_amount());
        let floor1 = need1 <= st1.best_cum;
        // our view of ch1, so a client that gave up a lock we later completed can resync
        let view = |expect: u64| json!({"expectCum": expect, "bestCum": st1.best_cum, "routedSat": routed1,
                                        "feeUnits": int_value(fee_units), "feePaid": fee_paid});
        if floor1 {
            if cum != st1.best_cum as i128 || truthy(pl.get("adaptor")) {
                return err(400, "bad_amount", &format!("the dust floor covers this lock: cum {}, no adaptor", st1.best_cum), view(st1.best_cum));
            }
        } else if cum != need1 as i128 || cum > st1.params.max_amount() as i128 || t1.is_none() {
            return err(400, "bad_amount", &format!("lock pays {cum}, expected {need1}"), view(need1));
        }
        // 4 pre-verify -------------------------------------------------------------------------------
        let mut pre1: Option<PreSig> = None;
        if !floor1 {
            let Ok(p) = PreSig::from_json(pl.get("adaptor").unwrap_or(&Value::Null)) else { return e400("bad_adaptor", "malformed adaptor") };
            let z1 = match st1.params.state_tx(need1).and_then(|tx| st1.params.sighash(&tx)) {
                Ok(z) => z,
                Err(_) => return e400("bad_adaptor", "no such state"),
            };
            if !adaptor::preverify(&st1.params.payer_pub, &z1, t1.as_ref().expect("checked in 3"), &p) {
                return e400("bad_adaptor", "pre-signature does not verify under T1");
            }
            pre1 = Some(p);
        }
        // 5 fee quote --------------------------------------------------------------------------------
        let Ok(q) = FeeQuote::from_json(rt.get("feeQuote").unwrap_or(&Value::Null)) else { return e400("route_fee", "no fee quote") };
        // any live quote this hub signed is honoured, including one the fee strategy has since moved
        if q.hub != self.pay_to || q.network != self.network || !q.verify() || !q.live(now_f()) {
            return e400("route_fee", "not a live fee quote of this hub");
        }
        let (f_due, units) = fee_due(&q, d, fee_units, fee_paid);
        if f < f_due {
            return err(400, "route_fee", &format!("fee {f} < {f_due} due under quote {}", q.seq), json!({"feeDue": f_due}));
        }
        // 6 expiry rule ------------------------------------------------------------------------------
        let oc = lk(&self.out).chans.get(&provider).cloned();
        let Some(oc) = oc.filter(|o| o.state == "open") else { return e400("route_blocked", "no open channel to that provider") };
        if !oc.blocked.is_empty() {
            return e400("route_blocked", &oc.blocked);
        }
        let Ok(inv) = Invoice::from_json(rt.get("invoice").unwrap_or(&Value::Null)) else { return e400("bad_invoice", "") };
        let rt_point = py_str(rt.get("point"));
        if inv.pay_to != oc.pay_to || !inv.verify() || inv.point.to_lowercase() != rt_point.to_lowercase() || inv.lock_id != lock_id
            || inv.valid_until_f() < now_f() + 0.5 || !inv.accepts_hub(&self.pay_to)
        {
            return e400("bad_invoice", "invoice not signed by the provider for this point, or expiring");
        }
        if !route_ok(height, st1.params.expiry, oc.params.expiry, self.cfg.close_margin, self.cfg.delta) && d > self.cfg.max_unguarded_lock_sat {
            return e400("route_expiry", &format!("ch2 outlives ch1 and {d} > maxUnguardedLockSat"));
        }
        // 7 one lock per channel ---------------------------------------------------------------------
        if truthy(ex1.get("route_lock")) {
            return e400("lock_outstanding", "a lock on this ch1 is pending");
        }
        let Some(busy) = self.acquire(&provider, Duration::from_millis(500)) else {
            return e400("lock_outstanding", "a lock on this provider's ch2 is pending");
        };
        let oc = match lk(&self.out).chans.get(&provider).cloned() {
            Some(o) if o.pending.is_empty() && o.state == "open" => o,
            _ => return e400("lock_outstanding", "a lock on this provider's ch2 is pending"),
        };
        // write-ahead: pre1 (enough to complete ch1 from t on-chain after a crash)
        // cum passed check 3: the best state (floor) or need1
        let lock1 = json!({"lockId": lock_id, "cum": cum as u64, "floor": floor1,
                           "pre": pre1.as_ref().map(PreSig::to_json), "T": rt_point, "T1": pl.get("point").cloned().unwrap_or(Value::Null),
                           "r": r.hex(), "d": d, "f": f, "units": int_value(units), "provider": provider, "at": round3(now_f()),
                           "session": rt.get("session").cloned().unwrap_or(Value::Null),
                           "after": {"routed": routed1 + d + f, "units": int_value(units), "paid": fee_paid + f}});
        st1.extra.insert("route_lock".into(), lock1.clone());
        if let Err(e) = self.inbound.save_state(&mut l, &st1) {
            return err(500, &e.code, &e.to_string(), json!({}));
        }
        let n = l.channels.values().filter(|c| truthy(c.extra.get("route_lock"))).count();
        lk(&self.stats).ch1_locks_at_forward.push(n);
        drop(l);
        let r = self.forward(&cid, &oc, &lock1, &rt, t0);
        drop(busy);
        r
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
                self.void(ch1, &oc.origin, &p2.channel_id(), "ch2 exhausted", "");
                return e400("route_failed", "the hub's channel to that provider is exhausted");
            }
            let signed = (|| -> Result<PreSig> {
                let t = adaptor::dec_hex(&t_hex)?;
                adaptor::presign(&oc.secret_key()?, &p2.sighash(&p2.state_tx(need2)?)?, &t)
            })();
            match signed {
                Ok(p) => pre2 = Some(p),
                Err(e) => {
                    self.void(ch1, &oc.origin, &p2.channel_id(), "ch2 pre-sign failed", "");
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
                self.void(ch1, &oc.origin, &p2.channel_id(), "ch2 replaced", "");
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
            self.void(ch1, &oc.origin, &p2.channel_id(), "no reveal within revealTimeoutSec", "the provider did not reveal a lock in time");
            return err(502, "route_failed", "provider did not reveal within revealTimeoutSec", json!({}));
        };
        if let Some(code) = ans.get("error").and_then(Value::as_str) {
            self.void(ch1, &oc.origin, &p2.channel_id(), &format!("provider refused: {code}"), "");
            *lk(&self.stats).refused.entry(code.to_string()).or_insert(0) += 1;
            return err(502, "route_failed", "provider refused the lock", json!({"providerError": code}));
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
        let (pend, p2) = (&oc.pending, &oc.params);
        let body = dumps(&json!({"route": pend.get("route").cloned().unwrap_or(Value::Null)}));
        let mut pl = json!({"chan": p2.channel_id(), "seq": seq, "cum": py_str(pend.get("cum")), "point": pend.get("T").cloned().unwrap_or(Value::Null)});
        if truthy(pend.get("pre")) {
            pl["adaptor"] = pend["pre"].clone();
        }
        let key = channel_auth_key(&oc.secret_key().ok()?, &p2.payee_pub).ok()?;
        pl["auth"] = request_auth(&key, &p2.channel_id(), pl.get("seq"), pl.get("cum"), None, &request_digest("POST", ROUTE_LOCK_PATH, body.as_bytes())).into();
        let hdrs = vec![("PAYMENT-SIGNATURE".to_string(), b64json(&json!({"x402Version": 2, "accepted": oc.terms, "payload": pl}))),
                        ("Content-Type".to_string(), "application/json".to_string())];
        let r = self.http.request("POST", &format!("{origin}{ROUTE_LOCK_PATH}"), body.as_bytes(), &hdrs).ok()?;
        let doc: Value = crate::json::parse_slice(&r.body).ok()?;
        if r.status == 200 && doc.is_object() && truthy(doc.get("secret")) {
            return Some(doc);
        }
        if [400, 401, 403].contains(&r.status) {
            if let Some(e) = doc.get("error").and_then(Value::as_str) {
                return Some(json!({"error": e.chars().take(40).collect::<String>()}));
            }
        }
        None
    }

    /// The provider revealed t: check it, fold ch2, complete ch1 with t + r.
    fn settled(&self, ch1: &str, origin: &str, ans: &Value) -> Option<Value> {
        let pend = {
            let b = lk(&self.out);
            b.chans.get(origin)?.pending.clone()
        };
        if pend.is_empty() || ans.get("lockId") != pend.get("lockId") {
            return None; // settled already (idempotent)
        }
        let t = Sc::from_hex_mod_n(ans.get("secret")?.as_str()?)?.secret()?;
        if Some(adaptor::point_of(&t)) != adaptor::dec_hex(&py_str(pend.get("T"))).ok() {
            return None; // bad_secret: keep the lock pending
        }
        {
            let mut b = lk(&self.out);
            let c = b.chans.get_mut(origin)?;
            if c.pending.get("lockId") != pend.get("lockId") {
                return None;
            }
            c.signed = c.signed.max(py_u64(pend.get("cum")).unwrap_or(0));
            c.routed += py_u64(pend.get("d")).unwrap_or(0);
            c.pending = Map::new();
            b.save().ok()?;
        }
        self.complete_ch1(ch1, &py_str(pend.get("lockId")), &t, "provider")
    }

    fn complete_ch1(&self, ch1: &str, lock_id: &str, t: &SecretKey, via: &str) -> Option<Value> {
        let mut l = self.inbound.ledger_lock();
        let mut st1 = l.channels.get(ch1)?.clone();
        let mut ex = st1.extra.clone();
        let current = ex.get("route_lock").filter(|x| x.get("lockId").and_then(Value::as_str) == Some(lock_id)).cloned();
        let (lock1, stale) = match current {
            Some(x) => (x, false),
            None => (ex.get("stale_locks").and_then(Value::as_array)?.iter().find(|s| s.get("lockId").and_then(Value::as_str) == Some(lock_id))?.clone(), true),
        };
        let r = Sc::from_hex_mod_n(&py_str(lock1.get("r")))?;
        let s1 = Sc::from_secret(t).add(&r);
        let lcum = py_u64(lock1.get("cum")).unwrap_or(0);
        if !truthy(lock1.get("floor")) {
            let pre1 = PreSig::from_json(lock1.get("pre")?).ok()?;
            let mut sig1 = adaptor::adapt(&pre1, &s1.secret()?).ok()?;
            sig1.push(SIGHASH_ALL_UNIFIED);
            if lcum > st1.best_cum && st1.closed_txid.is_empty() {
                self.inbound.payee(&st1).ok()?.accept(lcum, &sig1).ok()?;
                st1.best_cum = lcum;
                st1.best_sig = hex::encode(&sig1);
            }
        }
        let ans = json!({"lockId": lock_id, "secret": s1.hex(), "cum": lcum.max(st1.best_cum).to_string(), "fee": lock1["f"],
                         "amount": lock1["d"], "via": via});
        if stale {
            let rest: Vec<Value> = ex.get("stale_locks").and_then(Value::as_array).into_iter().flatten()
                .filter(|s| s.get("lockId").and_then(Value::as_str) != Some(lock_id)).cloned().collect();
            ex.insert("stale_locks".into(), Value::Array(rest));
            let mut rec = ans.clone();
            rec["at"] = round3(now_f());
            let mut recovered = ex.get("recovered").and_then(Value::as_array).cloned().unwrap_or_default();
            recovered.push(rec);
            ex.insert("recovered".into(), Value::Array(recovered));
            if let Some(aft) = lock1.get("after").filter(|a| a.is_object()) {
                if st1.best_cum == lcum {
                    // it is our best state now: count it
                    let mx = |k: &str, v: u128| -> Value { int_value(u128_of(ex.get(k)).unwrap_or(0).max(v)) };
                    let routed = mx("routed_sat", u128_of(aft.get("routed")).unwrap_or(0));
                    let units = mx("fee_units", u128_of(aft.get("units")).unwrap_or(0));
                    let paid = mx("fee_paid", u128_of(aft.get("paid")).unwrap_or(0));
                    ex.insert("routed_sat".into(), routed);
                    ex.insert("fee_units".into(), units);
                    ex.insert("fee_paid".into(), paid);
                }
            }
        } else {
            let d = py_u64(lock1.get("d")).unwrap_or(0);
            let f = py_u64(lock1.get("f")).unwrap_or(0);
            ex.insert("route_lock".into(), Value::Null);
            ex.insert("routed_sat".into(), (py_u64(ex.get("routed_sat")).unwrap_or(0) + d + f).into());
            ex.insert("fee_units".into(), lock1.get("units").cloned().unwrap_or(Value::from(0)));
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
        self.inbound.save_state(&mut l, &st1).ok()?;
        drop(l);
        let mut s = lk(&self.stats);
        s.routed += 1;
        if truthy(lock1.get("floor")) {
            s.floor += 1;
        }
        Some(ans)
    }

    /// Write both locks off (kept for on-chain recovery). A later state above them dominates them;
    /// until then a late completion costs the hub at most this one lock.
    fn void(&self, ch1: &str, origin: &str, ch2: &str, why: &str, block: &str) {
        let lock_id;
        {
            let mut b = lk(&self.out);
            let mut id = Value::Null;
            if let Some(c) = b.chans.get_mut(origin).filter(|c| c.params.channel_id() == ch2) {
                if !c.pending.is_empty() {
                    id = c.pending.get("lockId").cloned().unwrap_or(Value::Null);
                    let mut s = Value::Object(std::mem::take(&mut c.pending));
                    s["voided"] = round3(now_f());
                    s["why"] = why.into();
                    c.stale.push(s);
                }
                if !block.is_empty() {
                    c.blocked = block.to_string();
                }
            }
            let _ = b.save();
            lock_id = id;
        }
        let mut l = self.inbound.ledger_lock();
        let mut lid = lock_id;
        if let Some(mut st1) = l.channels.get(ch1).cloned() {
            if let Some(rl) = st1.extra.get("route_lock").filter(|x| truthy(Some(x))).cloned() {
                lid = rl.get("lockId").cloned().unwrap_or(lid);
                let mut s = rl;
                s["voided"] = round3(now_f());
                let mut stale = st1.extra.get("stale_locks").and_then(Value::as_array).cloned().unwrap_or_default();
                stale.push(s);
                st1.extra.insert("stale_locks".into(), Value::Array(stale));
                st1.extra.insert("route_lock".into(), Value::Null);
                let _ = self.inbound.save_state(&mut l, &st1);
            }
        }
        drop(l);
        self.event(json!({"event": "void", "provider": origin, "lockId": lid, "why": why, "blocked": !block.is_empty()}));
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

    /// Fund a ch2 to `origin` from the hub's own wallet. It opens (the watcher) once the funding
    /// has the provider's minConf.
    pub fn connect(&self, origin: &str, capacity: Option<u64>, expiry_blocks: Option<u32>) -> Result<OutChannel> {
        let origin = origin.trim_end_matches('/');
        let (st, terms) = self.get_json(&format!("{origin}{TERMS_PATH}"))?;
        if st != 200 {
            return fail("provider_error", format!("terms: HTTP {st}"));
        }
        let ex = terms.get("extra").cloned().unwrap_or(Value::Null);
        let offered = ex.get("closeFeePayer").and_then(Value::as_str).unwrap_or("payer");
        if self.cfg.ch2_close_fee_payer == FeePayer::Payee && offered != "payee" {
            return fail("bad_fee_payer", format!("{origin} does not offer payee-pays routed channels (closeFeePayer {offered:?}); \
                                                  set ch2_close_fee_payer payer to fund it"));
        }
        let min_cap = py_u64(ex.get("minCapacity")).ok_or_else(|| ChannelError::new("bad_offer", "minCapacity"))?;
        let cap = capacity.unwrap_or(self.cfg.ch2_capacity).max(min_cap);
        let blocks = self.ch2_blocks(&ex, expiry_blocks.unwrap_or(self.cfg.ch2_expiry_blocks))?;
        self.fund_ch2(origin, &terms, cap, self.chain.block_count()? + blocks)
    }

    fn ch2_blocks(&self, ex: &Value, want: u32) -> Result<u32> {
        let lo = py_u64(ex.get("minExpiryBlocks")).ok_or_else(|| ChannelError::new("bad_offer", "minExpiryBlocks"))? + 6;
        let hi = py_u64(ex.get("maxExpiryBlocks")).ok_or_else(|| ChannelError::new("bad_offer", "maxExpiryBlocks"))?.saturating_sub(1);
        Ok((want as u64).max(lo).min(hi) as u32)
    }

    fn fund_ch2(&self, origin: &str, terms: &Value, cap: u64, expiry: u32) -> Result<OutChannel> {
        if self.cfg.liquidity_cap_sat > 0 {
            let freed = lk(&self.out).chans.get(origin).filter(|o| o.state == "funded" || o.state == "open").map(|o| o.params.capacity).unwrap_or(0);
            let committed = self.committed_sat();
            if committed - freed + cap > self.cfg.liquidity_cap_sat {
                return fail("liquidity_cap", format!("{committed} + {cap} sat > liquidity_cap_sat {}", self.cfg.liquidity_cap_sat));
            }
        }
        let secret = adaptor::random_secret();
        let pay_to = terms.get("payTo").and_then(Value::as_str).ok_or_else(|| ChannelError::new("bad_offer", "payTo"))?.to_string();
        let ex = terms.get("extra").cloned().unwrap_or(Value::Null);
        let close_fee = py_u64(ex.get("closeFeeSat")).ok_or_else(|| ChannelError::new("bad_offer", "closeFeeSat"))?;
        let p = ChannelParams::derive(&hex::decode(&pay_to).map_err(|_| ChannelError::new("bad_offer", "payTo"))?, &ecdsa::pubkey(&secret),
                                      expiry, close_fee, None, &self.network, self.cfg.ch2_close_fee_payer)?;
        let (txid, vout) = self.wallet.fund(&segwit_address(&self.cfg.hrp, &p.spk())?, cap)?;
        let p = p.with_funding(&txid, vout, cap)?;
        let tip = self.chain.block_count()?;
        let oc = OutChannel { origin: origin.into(), pay_to, refund_hex: p.refund_tx(&secret, None, None)?.to_hex(), params: p,
                              secret: hex::encode(secret.secret_bytes()), state: "funded".into(), signed: 0, routed: 0, seq: 0,
                              pending: Map::new(), stale: vec![], settle_multiple: py_u64(ex.get("settleMultiple")).unwrap_or(20),
                              terms: terms.clone(), blocked: String::new(), close_txid: String::new(), rolled_to: String::new(),
                              opened_at: tip, scanned_to: tip };
        let mut b = lk(&self.out);
        if let Some(old) = b.chans.get(origin).cloned() {
            b.archived.push(old.to_json());
        }
        b.chans.insert(origin.into(), oc.clone());
        b.save()?;
        Ok(oc)
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
        let (st, doc) = self.post_json(&format!("{}{open_url}", oc.origin), &body)?;
        if st != 200 {
            return Ok(false);
        }
        let echoed = doc.get("closeFeePayer").and_then(Value::as_str).unwrap_or("payer");
        let mut b = lk(&self.out);
        let Some(c) = b.chans.get_mut(&oc.origin).filter(|c| c.params.channel_id() == p.channel_id()) else { return Ok(false) };
        if echoed != p.close_fee_payer.as_str() {
            // every state we would sign would fail at the provider: never route over this channel
            c.blocked = format!("the provider opened ch2 with closeFeePayer {echoed:?}");
            b.save()?;
            return Ok(false);
        }
        c.state = "open".into();
        b.save()?;
        drop(b);
        self.event(json!({"event": "ch2_open", "provider": oc.origin, "chan": p.channel_id(), "capacity": p.capacity}));
        Ok(true)
    }

    /// One tx pays the provider its balance and funds the next ch2 (rollover instead of close).
    pub fn rollover(&self, oc: &OutChannel) -> Result<Value> {
        let p = &oc.params;
        let amount = oc.signed;
        let next_cap = p.rollover_next_capacity(amount);
        let min_cap = oc.term_u64("minCapacity").unwrap_or(0);
        let tip = self.chain.block_count()?;
        let ex = oc.terms.get("extra").cloned().unwrap_or(Value::Null);
        let expiry = tip + self.ch2_blocks(&ex, self.cfg.ch2_expiry_blocks)?;
        if next_cap < min_cap.max(p.min_amount()) {
            return self.close_ch2(oc, true);
        }
        let secret = adaptor::random_secret();
        let nxt = ChannelParams::derive(&hex::decode(&oc.pay_to).unwrap_or_default(), &ecdsa::pubkey(&secret), expiry, p.close_fee, None,
                                        &self.network, p.close_fee_payer)?;
        let tx = p.rollover_tx(amount, &nxt.spk(), next_cap)?;
        let sig = sign_with_type(&oc.secret_key()?, &p.sighash(&tx)?, SIGHASH_ALL_UNIFIED);
        let req = json!({"chan": p.channel_id(), "amount": amount, "sig": hex::encode(sig),
                         "next": {"payerPub": hex::encode(nxt.payer_pub), "payerSpk": hex::encode(&nxt.payer_spk), "expiry": expiry}});
        let (st, doc) = self.post_json(&format!("{}{ROLLOVER_PATH}", oc.origin), &req)?;
        if st != 200 {
            let code = doc.get("error").and_then(Value::as_str).filter(|c| safe_code(c)).unwrap_or("provider_error");
            return fail(code, doc.to_string());
        }
        let txid = py_str(doc.get("txid"));
        let nxt = nxt.with_funding(&txid, 1, next_cap)?;
        let new = OutChannel { origin: oc.origin.clone(), pay_to: oc.pay_to.clone(), refund_hex: nxt.refund_tx(&secret, None, None)?.to_hex(),
                               params: nxt, secret: hex::encode(secret.secret_bytes()), state: "funded".into(), signed: 0, routed: 0, seq: 0,
                               pending: Map::new(), stale: vec![], settle_multiple: oc.settle_multiple, terms: oc.terms.clone(),
                               blocked: String::new(), close_txid: String::new(), rolled_to: String::new(), opened_at: tip, scanned_to: tip };
        {
            let mut b = lk(&self.out);
            let mut old = oc.clone();
            if let Some(c) = b.chans.get(&oc.origin).filter(|c| c.params.channel_id() == p.channel_id()) {
                old = c.clone();
            }
            old.state = "rolled".into();
            old.rolled_to = format!("{txid}:1");
            old.close_txid = txid.clone();
            b.archived.push(old.to_json());
            b.chans.insert(oc.origin.clone(), new.clone());
            b.save()?;
        }
        let ev = json!({"event": "ch2_rollover", "provider": oc.origin, "txid": txid, "amount": amount, "next": new.params.channel_id(),
                        "nextCapacity": next_cap});
        self.event(ev.clone());
        Ok(ev)
    }

    /// Ask the provider to close ch2 (payer-signed close request); with `refill`, fund a new one.
    pub fn close_ch2(&self, oc: &OutChannel, refill: bool) -> Result<Value> {
        let p = &oc.params;
        if oc.signed == 0 {
            // nothing signed on this ch2 (e.g. a fresh rollover): nothing to close; the hub's refund
            // (refund_hex, valid at expiry) returns the coins, or the next routed lock uses it
            let ev = json!({"event": "ch2_idle", "provider": oc.origin, "chan": p.channel_id(), "capacity": p.capacity});
            self.event(ev.clone());
            return Ok(ev);
        }
        let req = json!({"chan": p.channel_id(), "sig": hex::encode(ecdsa::sign(&oc.secret_key()?, &close_message(&p.channel_id())))});
        let close_url = oc.terms.get("extra").and_then(|e| e.get("closeUrl")).and_then(Value::as_str).unwrap_or(CLOSE_PATH);
        let (st, doc) = self.post_json(&format!("{}{close_url}", oc.origin), &req)?;
        if st != 200 {
            return fail("provider_error", doc.to_string());
        }
        let txid = py_str(doc.get("txid"));
        {
            let mut b = lk(&self.out);
            if let Some(c) = b.chans.get_mut(&oc.origin).filter(|c| c.params.channel_id() == p.channel_id()) {
                c.state = "closed".into();
                c.close_txid = txid.clone();
            }
            b.save()?;
        }
        let ev = json!({"event": "ch2_close", "provider": oc.origin, "txid": txid, "amount": py_u64(doc.get("cum")).unwrap_or(0),
                        "chan": p.channel_id()});
        self.event(ev.clone());
        if refill {
            self.connect(&oc.origin, None, None)?;
        }
        Ok(ev)
    }

    // --- watcher -----------------------------------------------------------------------------------

    /// One watcher pass over every ch2, then ch1's closes. Errors are per channel and never stop
    /// the rest. Returns what it did.
    pub fn watch_tick(&self) -> Vec<Value> {
        let mut acts = vec![];
        let tip = match self.chain.block_count() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("hub watcher: {e}");
                return acts;
            }
        };
        let origins: Vec<String> = lk(&self.out).chans.keys().cloned().collect();
        for origin in origins {
            // a route request in flight owns this ch2: never race it for the same lock
            let Some(busy) = self.acquire(&origin, Duration::ZERO) else { continue };
            match self.watch_out(&origin, tip) {
                Ok(mut a) => acts.append(&mut a),
                Err(e) => eprintln!("hub watcher {origin}: {e}"),
            }
            drop(busy);
        }
        match self.inbound.close_due() {
            Ok(txs) => acts.extend(txs.into_iter().map(|t| json!({"event": "ch1_close", "txid": t}))),
            Err(e) => eprintln!("hub watcher ch1: {e}"),
        }
        acts
    }

    fn watch_out(&self, origin: &str, tip: u32) -> Result<Vec<Value>> {
        let mut out = vec![];
        let Some(oc) = lk(&self.out).chans.get(origin).cloned() else { return Ok(out) };
        let p = &oc.params;
        if oc.state == "funded" {
            let min_conf = oc.term_u64("minConf").unwrap_or(1) as u32;
            if self.chain.get_tx_out(&p.funding_txid(), p.funding_vout(), false)?.is_some_and(|u| u.confirmations >= min_conf) && self.open(&oc)? {
                out.push(json!({"event": "ch2_open", "provider": origin}));
            }
            return Ok(out);
        }
        if oc.state != "open" {
            return Ok(out);
        }
        // a spent funding with a pending or written-off lock: read t off the close
        if (!oc.pending.is_empty() || !oc.stale.is_empty()) && self.chain.get_tx_out(&p.funding_txid(), p.funding_vout(), true)?.is_none() {
            if let Some(tx) = self.scan.find_spend(&p.funding_txid(), p.funding_vout(), oc.scanned_to)? {
                out.extend(self.secrets_from_close(&oc, &tx));
                let mut b = lk(&self.out);
                if let Some(c) = b.chans.get_mut(origin).filter(|c| c.params.channel_id() == p.channel_id()) {
                    c.state = "closed".into();
                    c.close_txid = tx.txid();
                }
                b.save()?;
                return Ok(out);
            }
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
                self.void(&ch1, origin, &p.channel_id(), "no reveal within revealTimeoutSec", "the provider did not reveal a lock in time");
                out.push(json!({"event": "lock_written_off", "provider": origin}));
            }
            return Ok(out);
        }
        // settlement: the provider's net payout >= its settleMultiple × closeFee, or near ch2's close
        // margin as the provider counts it (it co-signs only then): roll over
        let due = settle_due(p, oc.signed, oc.settle_multiple);
        let margin = oc.term_u64("closeMarginBlocks").unwrap_or(self.cfg.close_margin as u64) as i64;
        let grace = (self.cfg.rollover_margin as u64).min(oc.term_u64("rolloverGraceBlocks").unwrap_or(self.cfg.rollover_margin as u64)) as i64;
        let near = tip as i64 >= p.expiry as i64 - margin - grace;
        if (due || near) && oc.signed >= p.min_amount() {
            out.push(self.rollover(&oc)?);
        }
        Ok(out)
    }

    fn secrets_from_close(&self, oc: &OutChannel, tx: &Tx) -> Vec<Value> {
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
            {
                let mut b = lk(&self.out);
                if let Some(c) = b.chans.get_mut(&oc.origin).filter(|c| c.params.channel_id() == oc.params.channel_id()) {
                    c.signed = c.signed.max(py_u64(lk1.get("cum")).unwrap_or(0));
                    if c.pending.get("lockId").and_then(Value::as_str) == Some(lid.as_str()) {
                        c.routed += py_u64(lk1.get("d")).unwrap_or(0);
                        c.pending = Map::new();
                    }
                    c.stale.retain(|s| s.get("lockId").and_then(Value::as_str) != Some(lid.as_str()));
                }
                let _ = b.save();
            }
            let res = self.complete_ch1(&py_str(lk1.get("ch1")), &lid, &t, &format!("ch2 close {}", tx.txid()));
            out.push(json!({"event": "secret_from_close", "provider": oc.origin, "lockId": lid, "close": tx.txid(), "ch1_completed": res.is_some()}));
        }
        out
    }

    /// Run [`RouteHub::watch_tick`] every `interval` on a thread until the returned flag is set.
    pub fn watch(self: &Arc<Self>, interval: Duration) -> Arc<AtomicBool> {
        let stop = Arc::new(AtomicBool::new(false));
        let (hub, flag) = (self.clone(), stop.clone());
        std::thread::Builder::new().name("hub-watcher".into()).spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                std::thread::sleep(interval);
                if flag.load(Ordering::Relaxed) {
                    break;
                }
                hub.watch_tick();
            }
        }).expect("spawn watcher");
        stop
    }

    /// A ch1 as the hub sees it (its ledger row).
    pub fn ch1_state(&self, chan: &str) -> Option<ChannelState> {
        self.inbound.channel_state(chan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_rejects_unknown_keys_and_bad_payers() {
        assert!(HubConfig::from_json(&json!({"fee_ppm": 10, "nope": 1})).is_err());
        assert!(HubConfig::from_json(&json!({"ch2_close_fee_payer": "hub"})).is_err());
        let c = HubConfig::from_json(&json!({"fee_ppm": 10, "reveal_timeout": 2.5, "policy": {"min_expiry_blocks": 10}})).unwrap();
        assert_eq!((c.fee_ppm, c.reveal_timeout), (10, 2.5));
        assert_eq!(c.funding_policy().unwrap().min_expiry_blocks, 10);
        assert!(HubConfig::from_json(&json!({"policy": {"bogus": 1}})).is_err());
    }
}
