//! The policy engine (B2 `policy.py`): budgets, allowlist, caps, velocity, split-bypass, the human
//! threshold, and the append-only decision audit. No RPC and no keys here.
//!
//! Decisions are allow / deny / needs_human with B2's rules, reasons and residuals, in B2's order;
//! `tests/policy_conformance.rs` replays a decision table generated from the Python engine
//! (`vectors/b2_policy.json`). The on-disk ledger (`.run/ledger.json`) and audit log
//! (`.run/audit.jsonl`) have B2's formats, so a signer can move between implementations.
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{json, Map, Value};

use crate::keystore::random_bytes;
use crate::pyjson::{dumps_indent, dumps_sorted_compact, now_f64, py_int, ts_value};
use crate::{err, Result};

pub const DAY_S: f64 = 86_400.0;
pub const WEEK_S: f64 = 7.0 * DAY_S;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
    NeedsHuman,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Deny => "deny",
            Verdict::NeedsHuman => "needs_human",
        }
    }
}

/// Python's `urlparse(dest)` → `scheme://netloc` for http(s) dests; bech32 addresses fold case;
/// anything else is stripped.
pub fn normalize_dest(dest: &str) -> String {
    let dest = dest.trim();
    if dest.is_empty() {
        return String::new();
    }
    let lower = dest.to_lowercase();
    if lower.starts_with("bc1") || lower.starts_with("bcrt1") || lower.starts_with("tb1") {
        return lower;
    }
    for scheme in ["http://", "https://"] {
        if let Some(rest) = dest.strip_prefix(scheme) {
            let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            let netloc = &rest[..end];
            if !netloc.is_empty() {
                return format!("{}{netloc}", scheme);
            }
        }
    }
    dest.to_string()
}

/// One payment to decide on.
#[derive(Debug, Clone, Default)]
pub struct Payment {
    pub dest: String,
    pub amount_sats: i64,
    pub memo: String,
    pub ts: f64,
}

impl Payment {
    pub fn new(dest: &str, amount_sats: i64, memo: &str) -> Self {
        Self { dest: dest.into(), amount_sats, memo: memo.into(), ts: 0.0 }
    }

    pub fn normalized(&self, now: f64) -> Self {
        Self { dest: normalize_dest(&self.dest), amount_sats: self.amount_sats, memo: self.memo.clone(),
               ts: if self.ts != 0.0 { self.ts } else { now } }
    }
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub verdict: Verdict,
    pub reason: String,
    pub rule: String,
    pub approval_token: Option<String>,
    pub approval_expires: Option<i64>,
    pub dest: String,
    pub amount_sats: i64,
    pub residual_daily_sats: i64,
    pub residual_weekly_sats: i64,
    pub residual_counterparty_sats: i64,
}

impl Decision {
    pub fn allowed(&self) -> bool {
        self.verdict == Verdict::Allow
    }

    /// B2's `Decision.as_dict()`.
    pub fn as_value(&self) -> Value {
        json!({"verdict": self.verdict.as_str(), "reason": self.reason, "rule": self.rule,
               "approval_token": self.approval_token, "approval_expires": self.approval_expires,
               "dest": self.dest, "amount_sats": self.amount_sats, "residual_daily_sats": self.residual_daily_sats,
               "residual_weekly_sats": self.residual_weekly_sats, "residual_counterparty_sats": self.residual_counterparty_sats})
    }
}

/// B2's `PolicyConfig` (policy.json), defaults included.
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    pub allowlist: Vec<String>,
    pub max_per_tx_sats: i64,
    pub daily_budget_sats: i64,
    pub weekly_budget_sats: i64,
    pub per_counterparty_cap_sats: i64,
    pub velocity_max: i64,
    pub velocity_window_s: i64,
    pub human_threshold_sats: i64,
    pub split_window_s: i64,
    pub approval_ttl_s: i64,
    pub channel_expiry_blocks: i64,
    pub treasury_csv: i64,
    pub counterparties: Map<String, Value>,
    pub refund_enabled: bool,
    pub refund_margin_blocks: i64,
    pub hot_balance_cap_sats: i64,
    pub forward: Map<String, Value>,
    pub routing: Map<String, Value>,
    pub anchor_interval_s: i64,
    pub anchor_required: bool,
    /// `None`: mine on regtest only.
    pub regtest_mine: Option<bool>,
    pub open_wait_s: i64,
    pub open_retry_s: i64,
    pub close_fee_max_sats: i64,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self { allowlist: vec![], max_per_tx_sats: 10_000_000, daily_budget_sats: 50_000_000, weekly_budget_sats: 200_000_000,
               per_counterparty_cap_sats: 30_000_000, velocity_max: 8, velocity_window_s: 3600, human_threshold_sats: 10_000_000,
               split_window_s: 600, approval_ttl_s: 900, channel_expiry_blocks: 1008, treasury_csv: 4320, counterparties: Map::new(),
               refund_enabled: true, refund_margin_blocks: 6, hot_balance_cap_sats: 0, forward: Map::new(), routing: Map::new(),
               anchor_interval_s: 60, anchor_required: false, regtest_mine: None, open_wait_s: 1800, open_retry_s: 60,
               close_fee_max_sats: 2000 }
    }
}

fn py_bool(v: &Value) -> bool {
    crate::pyjson::truthy(Some(v))
}

impl PolicyConfig {
    /// `PolicyConfig.from_dict`: every integer field accepts what Python's `int()` accepts.
    pub fn from_value(raw: &Value) -> Result<Self> {
        let mut c = Self::default();
        let int = |k: &str, slot: &mut i64| -> Result<()> {
            if let Some(v) = raw.get(k) {
                *slot = py_int(Some(v)).ok_or_else(|| err("policy", format!("policy.json {k}: not an integer")))?;
            }
            Ok(())
        };
        int("max_per_tx_sats", &mut c.max_per_tx_sats)?;
        int("daily_budget_sats", &mut c.daily_budget_sats)?;
        int("weekly_budget_sats", &mut c.weekly_budget_sats)?;
        int("per_counterparty_cap_sats", &mut c.per_counterparty_cap_sats)?;
        int("velocity_max", &mut c.velocity_max)?;
        int("velocity_window_s", &mut c.velocity_window_s)?;
        int("human_threshold_sats", &mut c.human_threshold_sats)?;
        int("split_window_s", &mut c.split_window_s)?;
        int("approval_ttl_s", &mut c.approval_ttl_s)?;
        int("channel_expiry_blocks", &mut c.channel_expiry_blocks)?;
        int("treasury_csv", &mut c.treasury_csv)?;
        int("refund_margin_blocks", &mut c.refund_margin_blocks)?;
        int("hot_balance_cap_sats", &mut c.hot_balance_cap_sats)?;
        int("anchor_interval_s", &mut c.anchor_interval_s)?;
        int("open_wait_s", &mut c.open_wait_s)?;
        int("open_retry_s", &mut c.open_retry_s)?;
        int("close_fee_max_sats", &mut c.close_fee_max_sats)?;
        if let Some(v) = raw.get("refund_enabled") {
            c.refund_enabled = py_bool(v);
        }
        if let Some(v) = raw.get("anchor_required") {
            c.anchor_required = py_bool(v);
        }
        if let Some(v) = raw.get("regtest_mine").filter(|v| !v.is_null()) {
            c.regtest_mine = Some(py_bool(v));
        }
        if let Some(Value::Object(m)) = raw.get("forward") {
            c.forward = m.clone();
        }
        if let Some(Value::Object(m)) = raw.get("routing") {
            c.routing = m.clone();
        }
        if let Some(Value::Array(a)) = raw.get("allowlist") {
            c.allowlist = a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect();
        }
        if let Some(Value::Object(m)) = raw.get("counterparties") {
            c.counterparties = m.iter().map(|(k, v)| (normalize_dest(k), v.clone())).collect();
        }
        Ok(c)
    }

    pub fn normalized_allowlist(&self) -> Vec<String> {
        let mut v: Vec<String> = self.allowlist.iter().map(|a| normalize_dest(a)).filter(|a| !a.is_empty()).collect();
        v.sort();
        v.dedup();
        v
    }

    /// The registered payTo pubkey for `dest` (policy `counterparties`).
    pub fn pay_to_for(&self, dest: &str) -> String {
        self.counterparties.get(&normalize_dest(dest)).and_then(|i| i.get("pay_to")).and_then(Value::as_str)
            .map(|s| s.trim().to_string()).unwrap_or_default()
    }
}

/// One committed payment.
#[derive(Debug, Clone)]
pub struct LedgerEntry {
    pub dest: String,
    pub amount_sats: i64,
    pub ts: f64,
    pub txid: String,
    pub memo: String,
}

/// The append-only decision/commit log (`audit.jsonl`).
pub struct AuditLog {
    pub path: PathBuf,
    lock: Mutex<()>,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).map_err(|e| err("io", e.to_string()))?;
        }
        Ok(Self { path: path.into(), lock: Mutex::new(()) })
    }

    pub fn append(&self, event: Value) {
        let line = dumps_sorted_compact(&event);
        let _g = self.lock.lock();
        if let Ok(mut f) = fs::OpenOptions::new().append(true).create(true).open(&self.path) {
            let _ = f.write_all(format!("{line}\n").as_bytes());
            let _ = f.sync_all();
        }
    }

    pub fn read(&self, limit: usize) -> Vec<Value> {
        let text = fs::read_to_string(&self.path).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.len().saturating_sub(limit);
        lines[start..].iter().filter_map(|l| serde_json::from_str(l).ok()).collect()
    }
}

/// Committed payments and pending human approvals (`ledger.json`).
pub struct PolicyStore {
    pub path: PathBuf,
    lock: Mutex<()>,
}

impl PolicyStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).map_err(|e| err("io", e.to_string()))?;
        }
        let s = Self { path: path.into(), lock: Mutex::new(()) };
        if !path.exists() {
            s.write(&json!({"payments": [], "approvals": {}}))?;
        }
        Ok(s)
    }

    fn read(&self) -> Result<Value> {
        let t = fs::read_to_string(&self.path).map_err(|e| err("io", format!("{}: {e}", self.path.display())))?;
        serde_json::from_str(&t).map_err(|e| err("io", format!("{}: {e}", self.path.display())))
    }

    fn write(&self, data: &Value) -> Result<()> {
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, dumps_indent(data, 2, true)).map_err(|e| err("io", e.to_string()))?;
        fs::rename(&tmp, &self.path).map_err(|e| err("io", e.to_string()))
    }

    pub fn payments(&self) -> Result<Vec<LedgerEntry>> {
        let _g = self.lock.lock();
        let d = self.read()?;
        Ok(d.get("payments").and_then(Value::as_array).map(|a| a.iter().map(|e| LedgerEntry {
            dest: e.get("dest").and_then(Value::as_str).unwrap_or("").into(),
            amount_sats: py_int(e.get("amount_sats")).unwrap_or(0),
            ts: e.get("ts").and_then(Value::as_f64).unwrap_or(0.0),
            txid: e.get("txid").and_then(Value::as_str).unwrap_or("").into(),
            memo: e.get("memo").and_then(Value::as_str).unwrap_or("").into(),
        }).collect()).unwrap_or_default())
    }

    pub fn commit(&self, e: &LedgerEntry) -> Result<()> {
        let _g = self.lock.lock();
        let mut d = self.read()?;
        let row = json!({"dest": e.dest, "amount_sats": e.amount_sats, "ts": ts_value(e.ts), "txid": e.txid, "memo": e.memo});
        match d.get_mut("payments").and_then(Value::as_array_mut) {
            Some(a) => a.push(row),
            None => d["payments"] = json!([row]),
        }
        self.write(&d)
    }

    pub fn put_approval(&self, token: &str, payload: Value) -> Result<()> {
        let _g = self.lock.lock();
        let mut d = self.read()?;
        if !d.get("approvals").is_some_and(Value::is_object) {
            d["approvals"] = json!({});
        }
        d["approvals"][token] = payload;
        self.write(&d)
    }

    pub fn pop_approval(&self, token: &str) -> Result<Option<Value>> {
        let _g = self.lock.lock();
        let mut d = self.read()?;
        let out = d.get_mut("approvals").and_then(Value::as_object_mut).and_then(|m| m.remove(token));
        self.write(&d)?;
        Ok(out)
    }

    pub fn get_approval(&self, token: &str) -> Result<Option<Value>> {
        let _g = self.lock.lock();
        Ok(self.read()?.get("approvals").and_then(|a| a.get(token)).cloned())
    }
}

pub type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;

/// `secrets.token_urlsafe(24)`.
pub fn token_urlsafe() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<24>())
}

pub struct PolicyEngine {
    pub config: PolicyConfig,
    pub allowlist: Vec<String>,
    pub store: PolicyStore,
    pub audit: AuditLog,
    pub clock: Clock,
}

impl PolicyEngine {
    pub fn new(config: PolicyConfig, store: PolicyStore, audit: AuditLog, clock: Option<Clock>) -> Self {
        let allowlist = config.normalized_allowlist();
        Self { config, allowlist, store, audit, clock: clock.unwrap_or_else(|| Arc::new(now_f64)) }
    }

    pub fn now(&self) -> f64 {
        (self.clock)()
    }

    fn spent(ledger: &[LedgerEntry], window_s: f64, now: f64, dest: Option<&str>) -> i64 {
        ledger.iter().filter(|p| now - p.ts <= window_s && dest.is_none_or(|d| p.dest == d)).map(|p| p.amount_sats).sum()
    }

    fn count(ledger: &[LedgerEntry], window_s: f64, now: f64) -> i64 {
        ledger.iter().filter(|p| now - p.ts <= window_s).count() as i64
    }

    pub fn evaluate(&self, payment: &Payment, human: bool) -> Result<Decision> {
        let now = self.now();
        let p = payment.normalized(now);
        let cfg = &self.config;
        let ledger = self.store.payments()?;
        let daily = Self::spent(&ledger, DAY_S, now, None);
        let weekly = Self::spent(&ledger, WEEK_S, now, None);
        let cpty = Self::spent(&ledger, WEEK_S, now, Some(&p.dest));
        let rd = (cfg.daily_budget_sats - daily).max(0);
        let rw = (cfg.weekly_budget_sats - weekly).max(0);
        let rc = (cfg.per_counterparty_cap_sats - cpty).max(0);
        let decide = |verdict: Verdict, rule: &str, reason: String, token: Option<String>, expires: Option<i64>| -> Decision {
            self.audit.append(json!({"type": "decision", "verdict": verdict.as_str(), "rule": rule, "reason": reason,
                                     "dest": p.dest, "amount_sats": p.amount_sats, "human": human, "ts": ts_value(now),
                                     "approval_token": token}));
            Decision { verdict, reason, rule: rule.into(), approval_token: token, approval_expires: expires, dest: p.dest.clone(),
                       amount_sats: p.amount_sats, residual_daily_sats: rd, residual_weekly_sats: rw, residual_counterparty_sats: rc }
        };
        use Verdict::*;
        if p.amount_sats <= 0 {
            return Ok(decide(Deny, "amount", "amount_sats must be a positive integer".into(), None, None));
        }
        if p.dest.is_empty() {
            return Ok(decide(Deny, "dest", "destination address required".into(), None, None));
        }
        if !self.allowlist.contains(&p.dest) {
            return Ok(decide(Deny, "allowlist", format!("destination not on allowlist: {}", p.dest), None, None));
        }
        if p.amount_sats > cfg.max_per_tx_sats {
            return Ok(decide(Deny, "max_per_tx", format!("{} sats exceeds max_per_tx {}", p.amount_sats, cfg.max_per_tx_sats), None, None));
        }
        let split_sum = Self::spent(&ledger, cfg.split_window_s as f64, now, Some(&p.dest)) + p.amount_sats;
        if split_sum > cfg.max_per_tx_sats {
            return Ok(decide(Deny, "split_bypass", format!("split window sum {split_sum} would exceed max_per_tx {}", cfg.max_per_tx_sats), None, None));
        }
        if !human && split_sum >= cfg.human_threshold_sats && p.amount_sats < cfg.human_threshold_sats {
            return Ok(decide(Deny, "split_bypass", format!("split window sum {split_sum} evades human_threshold {}", cfg.human_threshold_sats), None, None));
        }
        if daily + p.amount_sats > cfg.daily_budget_sats {
            return Ok(decide(Deny, "daily_budget", format!("daily spend {} exceeds budget {}", daily + p.amount_sats, cfg.daily_budget_sats), None, None));
        }
        if weekly + p.amount_sats > cfg.weekly_budget_sats {
            return Ok(decide(Deny, "weekly_budget", format!("weekly spend {} exceeds budget {}", weekly + p.amount_sats, cfg.weekly_budget_sats), None, None));
        }
        if cpty + p.amount_sats > cfg.per_counterparty_cap_sats {
            return Ok(decide(Deny, "per_counterparty", format!("counterparty spend {} exceeds cap {}", cpty + p.amount_sats, cfg.per_counterparty_cap_sats), None, None));
        }
        if Self::count(&ledger, cfg.velocity_window_s as f64, now) >= cfg.velocity_max {
            return Ok(decide(Deny, "velocity", format!("already {} payments in the last {}s", cfg.velocity_max, cfg.velocity_window_s), None, None));
        }
        if !human && p.amount_sats >= cfg.human_threshold_sats {
            let token = token_urlsafe();
            let expires = (now + cfg.approval_ttl_s as f64) as i64;
            self.store.put_approval(&token, json!({"dest": p.dest, "amount_sats": p.amount_sats, "memo": p.memo, "expires": expires,
                                                   "ts": ts_value(now), "used": false}))?;
            return Ok(decide(NeedsHuman, "human_threshold", format!("{} sats is at or above human_threshold {}", p.amount_sats, cfg.human_threshold_sats),
                             Some(token), Some(expires)));
        }
        Ok(decide(Allow, "ok", "all policy rules passed".into(), None, None))
    }

    pub fn quote(&self, payment: &Payment) -> Result<Decision> {
        self.evaluate(payment, false)
    }

    /// Pop a still-valid unused token. Signature checks happen in the signer.
    pub fn consume_approval(&self, token: &str) -> Result<Option<Payment>> {
        if token.is_empty() {
            return Ok(None);
        }
        let now = self.now();
        let Some(payload) = self.store.get_approval(token)? else {
            self.audit.append(json!({"type": "approval_miss", "token": token, "ts": ts_value(now)}));
            return Ok(None);
        };
        if crate::pyjson::truthy(payload.get("used")) {
            self.audit.append(json!({"type": "approval_replay", "token": token, "ts": ts_value(now)}));
            return Ok(None);
        }
        if (py_int(payload.get("expires")).unwrap_or(0) as f64) < now {
            self.store.pop_approval(token)?;
            self.audit.append(json!({"type": "approval_expired", "token": token, "ts": ts_value(now)}));
            return Ok(None);
        }
        self.store.pop_approval(token)?;
        Ok(Some(Payment { dest: payload.get("dest").and_then(Value::as_str).unwrap_or("").into(),
                          amount_sats: py_int(payload.get("amount_sats")).unwrap_or(0),
                          memo: payload.get("memo").and_then(Value::as_str).unwrap_or("").into(), ts: now }))
    }

    pub fn commit(&self, payment: &Payment, txid: &str) -> Result<()> {
        let now = self.now();
        let p = payment.normalized(now);
        let ts = if p.ts != 0.0 { p.ts } else { now };
        self.store.commit(&LedgerEntry { dest: p.dest.clone(), amount_sats: p.amount_sats, ts, txid: txid.into(), memo: p.memo.clone() })?;
        self.audit.append(json!({"type": "commit", "dest": p.dest, "amount_sats": p.amount_sats, "txid": txid, "ts": ts_value(ts)}));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_like_python() {
        assert_eq!(normalize_dest("  BCRT1QABC "), "bcrt1qabc");
        assert_eq!(normalize_dest("http://h:8/x?y#z"), "http://h:8");
        assert_eq!(normalize_dest("https://h"), "https://h");
        assert_eq!(normalize_dest("https:///x"), "https:///x");
        assert_eq!(normalize_dest("HTTP://h/x"), "HTTP://h/x");
        assert_eq!(normalize_dest(""), "");
    }
}
