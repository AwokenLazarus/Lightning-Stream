//! The signer: owns the node connection, the keys and the policy; the model-facing process talks
//! only to its socket (B2 `signer.py`, method for method; `docs/B2_SIGNER_API.md`).
//!
//! Human approval is cryptographic: the signer holds only an ed25519 public key; `approve`,
//! `sweep_hot` and the recoveries need a signature by it. A boolean `human` in a request is never
//! a capability.
//!
//! AGP-013/016/017 custody: sealed keys, the signature log anchored with a witness (the signer
//! refuses to start when its log fails the anchor check), no mining off regtest, per-chain hrp,
//! pruned-node lookups, rotation, the balance cap and the human sweep.
//!
//! The on-chain one-way channel this signer once paid over was removed in 2026-10: its methods
//! answer `deny/removed` ([`REMOVED_METHODS`]), and what a wallet from before still holds is shown
//! read-only ([`crate::legacy`]).
//!
//! Not ported (see the crate README): the forward rail, the treasury and the presigned vault; their
//! methods answer that they are unavailable. There is no light backend: the chain is read from the
//! signer's own node.
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::Duration;

use serde_json::{json, Value};

use crate::anchor::{AnchorClient, Anchorer};
use crate::approval::{recover_message, sweep_message, verify, verify_approval, x2b};
use crate::hot::{HotWallet, DEFAULT_FEE};
use crate::keystore::KeyStore;
use crate::ln::{LnBackend, LnBook, LndRest};
use crate::node::{self, KnotsRpc, Node};
use crate::policy::{normalize_dest, AuditLog, Clock, Payment, PolicyConfig, PolicyEngine, PolicyStore};
use crate::pyjson::{py_int, str_or_empty, truthy, ts_value};
use crate::sanitize::sanitize;
use crate::sigaudit::{self, check_chain, SigAudit};
use crate::{err, Result};

pub const XBT_SATS: i64 = 100_000_000;

/// Same texts as B2 `sats_from_xbt` (`agentwallet/signer.py`).
pub const ERR_NOT_DECIMAL: &str = "amount_xbt is not a decimal number";
pub const ERR_NOT_FINITE: &str = "amount_xbt must be a finite number";
pub const ERR_NEGATIVE: &str = "amount_xbt must not be negative";
pub const ERR_PRECISION: &str = "amount_xbt has more than 8 decimal places";

/// Exact XBT → sats (B2 `sats_from_xbt`): at most 8 decimal places; refuse negatives, NaN and inf.
/// Scientific notation (`1e-05`) is accepted. Extra precision is an error, never truncated.
pub fn sats_from_xbt(v: Option<&Value>) -> std::result::Result<i64, &'static str> {
    let s = match v {
        None | Some(Value::Null) => "0".to_string(),
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() { i.to_string() } else { crate::pyjson::py_float(n.as_f64().unwrap_or(0.0)) }
        }
        Some(Value::Bool(false)) => "0".to_string(),
        Some(Value::Bool(true)) => "True".to_string(),
        Some(other) => other.to_string(),
    };
    parse_xbt_decimal(&s)
}

fn parse_xbt_decimal(s: &str) -> std::result::Result<i64, &'static str> {
    let s = s.trim();
    if is_non_finite_token(s) {
        return Err(ERR_NOT_FINITE);
    }
    let (neg, rest) = if let Some(r) = s.strip_prefix('-') {
        (true, r)
    } else if let Some(r) = s.strip_prefix('+') {
        (false, r)
    } else {
        (false, s)
    };
    if is_non_finite_token(rest) {
        return Err(ERR_NOT_FINITE);
    }
    let (mant, exp) = match rest.find(['e', 'E']) {
        Some(i) => {
            let e: i32 = rest[i + 1..].parse().map_err(|_| ERR_NOT_DECIMAL)?;
            (&rest[..i], e)
        }
        None => (rest, 0),
    };
    if mant.is_empty() {
        return Err(ERR_NOT_DECIMAL);
    }
    let (whole, frac) = match mant.split_once('.') {
        Some((w, f)) => (w, f),
        None => (mant, ""),
    };
    if !whole.bytes().all(|c| c.is_ascii_digit()) || !frac.bytes().all(|c| c.is_ascii_digit()) {
        return Err(ERR_NOT_DECIMAL);
    }
    if whole.is_empty() && frac.is_empty() {
        return Err(ERR_NOT_DECIMAL);
    }
    let mut digits = String::with_capacity(whole.len() + frac.len() + 1);
    digits.push_str(if whole.is_empty() { "0" } else { whole });
    digits.push_str(frac);
    let power = exp
        .checked_sub(frac.len() as i32)
        .and_then(|p| p.checked_add(8))
        .ok_or(ERR_NOT_DECIMAL)?;
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Ok(0);
    }
    if neg {
        return Err(ERR_NEGATIVE);
    }
    let n: i128 = digits.parse().map_err(|_| ERR_NOT_DECIMAL)?;
    let sats = if power >= 0 {
        let mut v = n;
        for _ in 0..power {
            v = v.checked_mul(10).ok_or(ERR_NOT_DECIMAL)?;
        }
        v
    } else {
        let places = u32::try_from(-power).map_err(|_| ERR_NOT_DECIMAL)?;
        if places > 38 {
            return Err(ERR_PRECISION);
        }
        let div = 10i128.checked_pow(places).ok_or(ERR_PRECISION)?;
        if n % div != 0 {
            return Err(ERR_PRECISION);
        }
        n / div
    };
    i64::try_from(sats).map_err(|_| ERR_NOT_DECIMAL)
}

fn is_non_finite_token(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "nan" | "+nan" | "-nan" | "inf" | "+inf" | "-inf" | "infinity" | "+infinity" | "-infinity"
    )
}

pub fn deny(rule: &str, reason: impl Into<String>) -> Value {
    json!({"verdict": "deny", "rule": rule, "reason": reason.into()})
}

pub(crate) fn with(mut v: Value, extra: Value) -> Value {
    if let (Value::Object(a), Value::Object(b)) = (&mut v, extra) {
        for (k, x) in b {
            a.insert(k, x);
        }
    }
    v
}

fn trunc(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Methods of the on-chain channel, and of the forward rail that rode on its closes. They answer
/// `deny/removed` with a sentence, so a caller written for an earlier version learns why.
pub const REMOVED_METHODS: [&str; 22] = ["fund", "open_channel", "sign_state", "xbt402_sign_state", "xbt402_request_auth", "xbt402_sign_state_a3",
    "xbt402_sign_rollover", "xbt402_new_key", "xbt402_attach", "xbt402_funded", "xbt402_sign_close", "xbt402_sign_refund", "xbt402_sign_conditional",
    "xbt402_mark_closed", "close_channel", "xbt402_refund", "refund_channel", "tx_confirmations", "forward_status", "forward_pending",
    "forward_transfers", "forward_recover"];

/// A witness-v0 address of this chain's hrp (B1 `address_to_spk(addr, hrp)`, P5).
pub fn address_to_spk(addr: &str, hrp: &str) -> Result<Vec<u8>> {
    let spk = xbt_primitives::address::address_to_spk(addr, Some(hrp)).map_err(|e| err("bad_address", e.to_string()))?;
    if spk.first() != Some(&0) {
        return Err(err("bad_address", "only witness v0"));
    }
    Ok(spk)
}

/// How to build a signer (tests inject a node, a clock).
#[derive(Default)]
pub struct SignerOptions {
    pub node: Option<Arc<dyn Node>>,
    pub clock: Option<Clock>,
    /// Overrides `B2_ANCHOR_SOCK`.
    pub anchor: Option<AnchorClient>,
    /// Overrides `B2_HOT_KEYFILE` / `B2_HOT_PASSPHRASE` (the container entry point's secret source, AGP-038).
    pub keystore: Option<Arc<KeyStore>>,
    /// AGP-048: the LN node `rail=ln` pays through (default: `B2_LN_REST` / `B2_LN_MACAROON` / `B2_LN_TLS_CERT`).
    pub ln: Option<Arc<dyn LnBackend>>,
    /// How the ticket payer talks HTTP to sellers (default: [`crate::ticket_pay::UreqWire`]).
    pub ticket_wire: Option<Arc<dyn crate::ticket_pay::TicketWire>>,
}

pub struct Signer {
    pub root: PathBuf,
    pub run: PathBuf,
    /// Live (AGP-039 `policy_set`): read with [`Signer::config`].
    config: RwLock<PolicyConfig>,
    pub engine: Arc<PolicyEngine>,
    pub node: Arc<dyn Node>,
    pub chain: String,
    pub hrp: String,
    pub mining: bool,
    pub sock_path: PathBuf,
    human_pubkey: RwLock<Vec<u8>>,
    pub(crate) spend: Mutex<()>,
    /// AGP-039: what became of an approval token that left the ledger (denied, used, expired).
    pub(crate) approval_outcomes: Mutex<HashMap<String, Value>>,
    /// policy.json as this process read it at start (restart-only keys are compared with it).
    pub(crate) boot_policy: Value,
    pub keystore: Option<Arc<KeyStore>>,
    pub sigaudit: Arc<SigAudit>,
    pub anchor: Anchorer,
    pub hot: Arc<HotWallet>,
    /// On-chain channel records an earlier version left, read once at start and never written.
    pub legacy_channels: crate::legacy::LegacyChannels,
    /// The chain's network id on mainnet, once worked out ([`Signer::network`]).
    net: Mutex<Option<String>>,
    pub watch_interval: f64,
    /// AGP-048 `rail=ln`: the LN node (None: not configured), a configuration error that keeps the
    /// rail shut, and the write-ahead payment book.
    pub ln: Option<Arc<dyn LnBackend>>,
    pub ln_error: Option<String>,
    pub ln_book: LnBook,
    /// AGP-049: channel funding verdicts from our own node, per funding outpoint (final ones only).
    /// Funding verdicts by funding, with the hash of the block each was reached on (AGP-066), kept on
    /// disk too, so a pruned node can still use a channel whose blocks it no longer has.
    pub(crate) ln_funding: crate::ln_funding::Kept,
    /// Stream tickets ([`crate::ticket_rail`]): the book (opened when first needed), what kept it
    /// from coming up at start, the seed once read, and whether the node's payment list has been
    /// read to its end since this process started.
    pub(crate) tickets: Mutex<Option<crate::ticket_rail::TicketStore>>,
    pub(crate) ticket_error: Mutex<Option<String>>,
    pub(crate) ticket_seed: Mutex<Option<Arc<crate::ticket::Seed>>>,
    pub(crate) ticket_synced: std::sync::atomic::AtomicBool,
    /// How many ticket payments are with the node's router at once ([`crate::ticket_rail::Pace`]).
    pub(crate) ticket_pace: crate::ticket_rail::Pace,
    /// Held tickets booked `sending` whose send has not come back yet: waiting their turn in
    /// [`Self::ticket_pace`] or with the node. The node may have no record of one yet, and that
    /// is not a sign it never reached the node.
    pub(crate) ticket_queued: Mutex<std::collections::HashSet<String>>,
    /// Stream tickets over HTTP ([`crate::ticket_pay`]): the transport, one place per seller origin
    /// for its session, the sessions of an earlier run whose cancel was asked for, and this signer
    /// itself (for the thread that refills a pool behind a call).
    pub(crate) ticket_wire: Arc<dyn crate::ticket_pay::TicketWire>,
    pub(crate) ticket_http: Mutex<HashMap<String, Arc<crate::ticket_pay::Slot>>>,
    /// The sessions this process pays by draws, by the seller's origin (`docs/TICKETS.md`, section 9).
    pub(crate) draw_http: Mutex<HashMap<String, Arc<crate::ticket_pay::DrawSession>>>,
    pub(crate) ticket_cancel_tried: Mutex<HashSet<String>>,
    pub(crate) me: std::sync::OnceLock<std::sync::Weak<Signer>>,
    /// AGP-063 W4: the one-time code that enrols the first human key.
    pub(crate) enroll: Mutex<crate::admin::EnrollCode>,
    /// AGP-089: the human-signed messages already used (one signature, one operation).
    pub(crate) used_sigs: crate::admin::UsedSigs,
}

impl Signer {
    /// B2's `Signer(root)`: `root/policy.json`, state in `root/.run`, environment as B2 reads it.
    pub fn new(root: &Path, opts: SignerOptions) -> Result<Arc<Self>> {
        let run = root.join(".run");
        std::fs::create_dir_all(&run).map_err(|e| err("io", format!("{}: {e}", run.display())))?;
        let raw: Value = serde_json::from_str(&std::fs::read_to_string(root.join("policy.json"))
            .map_err(|e| err("io", format!("{}: {e}", root.join("policy.json").display())))?)
            .map_err(|e| err("policy", format!("policy.json: {e}")))?;
        let config = PolicyConfig::from_value(&raw)?;
        let engine = Arc::new(PolicyEngine::new(config.clone(), PolicyStore::open(&run.join("ledger.json"))?,
                                                AuditLog::open(&run.join("audit.jsonl"))?, opts.clock.clone()));
        let backend = std::env::var("B2_CHAIN_BACKEND").unwrap_or_default().trim().to_lowercase();
        if backend == "electrum" && opts.node.is_none() {
            return Err(err("chain", "B2_CHAIN_BACKEND=electrum: this signer has no light backend; it reads the chain from its own node (the node RPC)"));
        }
        let datadir = std::env::var("B2_DATADIR").map(PathBuf::from).unwrap_or_else(|_| root.join(".regtest"));
        let wallet = std::env::var("B2_WALLET").unwrap_or_else(|_| "agent".into());
        let node: Arc<dyn Node> = opts.node.clone().unwrap_or_else(|| Arc::new(KnotsRpc::new(&datadir, &wallet)));
        // P3/P5: the chain decides the hrp and whether this process may ever mine
        let chain = node::detect_chain(&*node)?;
        if config.regtest_mine == Some(true) && !node::mining_allowed(&chain) {
            return Err(err("chain", format!("policy regtest_mine is set but the node is on {chain:?}: refusing to start (only regtest may mine)")));
        }
        let mining = node::mining_allowed(&chain) && config.regtest_mine != Some(false);
        node.set_allow_generate(mining);
        let hrp = node::hrp(&chain)?.to_string();
        let sock_path = std::env::var("B2_SIGNER_SOCK").map(PathBuf::from).unwrap_or_else(|_| run.join("signer.sock"));
        let pub_hex = raw.get("human_pubkey").and_then(Value::as_str).unwrap_or("").trim().to_string();
        let human_pubkey = if pub_hex.is_empty() { vec![] } else { x2b(&pub_hex).ok_or_else(|| err("policy", "human_pubkey is not hex"))? };
        let keystore = match opts.keystore.clone() {
            Some(k) => Some(k),
            None => KeyStore::from_env(Some(&run), true)?.map(Arc::new),
        };
        if keystore.is_none() && !KeyStore::plaintext_allowed() {
            return Err(err("keystore", "the signer's hot key must be encrypted at rest: set B2_HOT_KEYFILE (a 32-byte key file outside the run dir) \
                                        or B2_HOT_PASSPHRASE (B2_HOT_ALLOW_PLAINTEXT=1 for tests)"));
        }
        let sigaudit = Arc::new(SigAudit::open(&run.join("signatures.jsonl"))?);
        let anchor = Anchorer::new(sigaudit.clone(), opts.anchor.clone().or_else(AnchorClient::from_env), config.anchor_interval_s as f64);
        Self::check_anchor_at_start(&anchor, &config)?;
        let hot = Arc::new(HotWallet::open(&run.join("hot.json"), node.clone(), &hrp, keystore.clone(), Some(sigaudit.clone()),
                                           config.hot_balance_cap_sats)?);
        hot.reconcile(std::env::var("B2_HOT_SCAN").map(|v| v != "0").unwrap_or(true));
        let legacy_channels = crate::legacy::LegacyChannels::read(&run.join("channels.json"));
        if let Some(n) = legacy_channels.notice() {
            eprintln!("xbt-signer: {}", n["what_to_do"].as_str().unwrap_or_default());
        }
        // and the test aid for sellers on a LAN, which the owner should not forget is on
        for w in crate::policy::validate_policy(&raw).1.iter().filter(|w| w.contains("on-chain channel") || w.contains("tickets.seller_tls")) {
            eprintln!("xbt-signer: {w}");
        }
        // tickets on, on mainnet, without the owner's acknowledgement: off, and said so at start as well as on each refusal
        if let Some(why) = crate::ticket::TicketPolicy::for_chain(&config.tickets, &chain, chain == "main" && crate::ticket::mainnet_ack_file()).mainnet_off {
            eprintln!("xbt-signer: {why}");
        }
        let watch_interval = std::env::var("B2_WATCH_INTERVAL").ok().and_then(|v| v.parse().ok()).unwrap_or(10.0);
        // an LN misconfiguration shuts only the LN rail (every ln_pay is refused with it)
        let (ln, ln_error) = match opts.ln.clone() {
            Some(b) => (Some(b), None),
            None => match LndRest::from_env() {
                Ok(b) => (b.map(|b| Arc::new(b) as Arc<dyn LnBackend>), None),
                Err(e) => (None, Some(e.msg)),
            },
        };
        let ln_book = LnBook::open(&run.join("ln_payments.json"))?;
        let ln_funding = crate::ln_funding::Kept::open(&run.join(crate::ln_funding::KEPT_FILE));
        let s = Arc::new(Self { root: root.into(), run, config: RwLock::new(config), engine, node, chain, hrp, mining, sock_path,
                                human_pubkey: RwLock::new(human_pubkey), spend: Mutex::new(()), approval_outcomes: Mutex::new(HashMap::new()), boot_policy: raw,
                                keystore, sigaudit, anchor, hot, legacy_channels, net: Mutex::new(None), watch_interval,
                                ln, ln_error, ln_book, ln_funding, tickets: Mutex::new(None),
                                ticket_error: Mutex::new(None), ticket_seed: Mutex::new(None), ticket_synced: std::sync::atomic::AtomicBool::new(false),
                                ticket_pace: crate::ticket_rail::Pace::default(), ticket_queued: Mutex::new(Default::default()),
                                ticket_wire: opts.ticket_wire.clone().unwrap_or_else(|| Arc::new(crate::ticket_pay::UreqWire::default())),
                                ticket_http: Mutex::new(HashMap::new()), draw_http: Mutex::new(HashMap::new()), ticket_cancel_tried: Mutex::new(HashSet::new()), me: std::sync::OnceLock::new(), enroll: Mutex::new(Default::default()),
                                used_sigs: crate::admin::UsedSigs::new(&root.join(".run").join(crate::admin::USED_SIGS_FILE)) });
        let _ = s.me.set(Arc::downgrade(&s));
        // before any request: what the book holds locked is retired (a start may be a restore)
        s.ticket_start();
        if s.human_key().is_empty() {
            s.issue_enroll_code()?;
        } else {
            let _ = std::fs::remove_file(s.run.join(crate::admin::ENROLL_CODE_FILE));
        }
        Ok(s)
    }

    /// Fail closed if the signature log no longer holds the witness's latest anchor.
    fn check_anchor_at_start(anchor: &Anchorer, config: &PolicyConfig) -> Result<()> {
        if !anchor.enabled() {
            if config.anchor_required {
                return Err(err("sigaudit", format!("policy anchor_required: set {} to the anchor witness socket", crate::anchor::ENV_SOCK)));
            }
            return Ok(());
        }
        let chk = match anchor.check() {
            Ok(c) => c,
            Err(e) => {
                if config.anchor_required {
                    return Err(err("sigaudit", format!("policy anchor_required: {}", e.msg)));
                }
                anchor.set_error(&e.msg);
                return Ok(());
            }
        };
        if chk["ok"] != Value::Bool(true) {
            return Err(err("sigaudit", format!("signature log fails its anchor check ({}): refusing to start. \
                                                Keep the log and the witness store as evidence and ask a human.", chk["reason"].as_str().unwrap_or(""))));
        }
        anchor.anchor("signer_start");
        Ok(())
    }

    /// The policy in force now.
    pub fn config(&self) -> PolicyConfig {
        self.config.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub(crate) fn set_config_live(&self, c: PolicyConfig) {
        *self.config.write().unwrap_or_else(|p| p.into_inner()) = c;
    }

    /// The human's ed25519 public key (empty: none enrolled).
    pub fn human_key(&self) -> Vec<u8> {
        self.human_pubkey.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub(crate) fn set_human_key(&self, k: Vec<u8>) {
        *self.human_pubkey.write().unwrap_or_else(|p| p.into_inner()) = k;
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, ()> {
        match self.spend.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// Anchor after a close, refund or sweep. Never fails the operation that triggered it.
    pub(crate) fn anchor_after(&self, reason: &str) {
        if self.anchor.enabled() {
            self.anchor.anchor(reason);
        }
    }

    fn now(&self) -> f64 {
        self.engine.now()
    }

    fn height(&self) -> Result<i64> {
        node::height(&*self.node).map(|h| h as i64)
    }

    pub(crate) fn height_safe(&self) -> i64 {
        self.height().unwrap_or(0)
    }

    /// The chain's network id (`bip122:...`, P4), as a seller's 402 names it. A wrong mainnet anchor
    /// fails: the wallet never pays on a network it cannot name.
    pub fn network(&self) -> Result<String> {
        if self.chain != "regtest" {
            let mut g = self.net.lock().unwrap_or_else(|p| p.into_inner());
            if g.is_none() {
                *g = Some(node::network(&*self.node, &self.chain, None)?);
            }
            return Ok(g.clone().unwrap_or_default());
        }
        Ok(node::height(&*self.node).and_then(|h| node::network(&*self.node, &self.chain, Some(h)))
            .unwrap_or_else(|_| xbt_primitives::network::network_id(&"0".repeat(64))))
    }

    fn mine_safe(&self) {
        if self.mining {
            let _ = mine_blocks(&*self.node, 1);
        }
    }

    /// Handle one request; every signature made meanwhile is logged under its method.
    pub fn handle(&self, method: &str, params: &Value) -> Result<Value> {
        let _ctx = sigaudit::context(Some(method), Some(&format!("method:{method}")));
        let empty = json!({});
        let p = if params.is_object() { params } else { &empty };
        self.dispatch(method, p)
    }

    fn dispatch(&self, method: &str, p: &Value) -> Result<Value> {
        let s = |k: &str| str_or_empty(p.get(k));
        Ok(match method {
            "balance" => {
                let bals = self.node.call("getbalances", json!([])).unwrap_or(json!({}));
                let mine = bals.get("mine").cloned().unwrap_or(json!({}));
                sanitize(json!({"trusted_sats": node::sats(mine.get("trusted")), "untrusted_pending_sats": node::sats(mine.get("untrusted_pending")),
                                "immature_sats": node::sats(mine.get("immature")), "vault": null, "treasury": null,
                                "not_ported": ["vault", "treasury", "forward"], "hot": self.hot.status(), "channels": self.legacy_channels.public(),
                                "legacy_channels": self.legacy_channels.notice()}))
            }
            "quote_payment" => {
                let d = self.engine.quote(&self.payment(p)?)?;
                let mut out = d.as_value();
                out["fee_estimate"] = self.node.call("estimatesmartfee", json!([1])).unwrap_or(Value::Null);
                sanitize(out)
            }
            "pay" => {
                let _g = self.lock();
                sanitize(self.pay_locked(p, false)?)
            }
            "approve" => sanitize(self.approve_signed(p)?),
            "history" => sanitize(json!({"events": self.engine.audit.read(py_int(p.get("limit")).filter(|l| *l > 0).unwrap_or(50) as usize)})),
            "recover_vault" | "fund_treasury" | "recover_treasury" => {
                json!({"ok": false, "reason": format!("{method}: the presigned vault and the treasury are not ported to the Rust signer")})
            }
            "health" => json!({"ok": true, "wallet": self.node.wallet(), "chain": self.chain, "hrp": self.hrp, "mining": self.mining,
                               "implementation": "xbt-signer (Rust)", "legacy_channels": self.legacy_channels.notice()}),
            "chain_backend" => json!({"backend": "rpc"}),
            // whether the XBT node answers now: a signer whose chain is set (B2_CHAIN) starts without it, and says so here
            "node_status" => match node::height(&*self.node) {
                Ok(h) => json!({"reachable": true, "chain": self.chain, "height": h}),
                Err(e) => json!({"reachable": false, "chain": self.chain, "reason": e.msg.chars().take(200).collect::<String>()}),
            },
            "channels" => {
                // `channels` lists what an earlier version's on-chain channel book holds; this version adds none
                let mut out = json!({"channels": self.legacy_channels.public(), "legacy_channels": self.legacy_channels.notice(), "height": self.height_safe()});
                // a wallet with a ticket book also shows its tickets: in flight, locked sats, what was released
                let tickets = self.ticket_summary();
                if !tickets.is_null() {
                    out["tickets"] = with(tickets, json!({"paying": self.ticket_http_public()}));
                }
                sanitize(out)
            }
            "hot_address" => sanitize(self.hot.status()),
            "notice_hot_txid" => {
                // only outputs still unspent: a spent one kept as a coin would make every later sweep fail
                let n = self.hot.scan_from_txid(&s("txid"), true, "")?;
                sanitize(with(self.hot.status(), json!({"noticed": n})))
            }
            // takes the spend lock itself, and only for each lock and release, where an answer may be long (crate::ticket_pay)
            "xbt402_pay" => sanitize(self.xbt402_pay(p)),
            // AGP-048 rail=ln
            "ln_pay" => {
                let _g = self.lock();
                sanitize(self.ln_pay_locked(p))
            }
            "ln_status" => {
                let _g = self.lock();
                sanitize(self.ln_status_locked())
            }
            // read only, and without the spend lock: it answers while a payment is in flight
            "ln_lookup" => sanitize(self.ln_lookup(p)),
            // stream tickets (docs/TICKETS.md): the buyer's book
            "ticket_open" => {
                let _g = self.lock();
                sanitize(self.ticket_open_locked(p))
            }
            "ticket_offer" => {
                let _g = self.lock();
                sanitize(self.ticket_offer_locked(p))
            }
            // takes the spend lock itself, and not while the node routes
            "ticket_lock" => sanitize(self.ticket_lock(p)),
            // not sanitized: the one secret in the reply is the ticket's, booked as spent before the reply exists
            "ticket_release" => {
                let _g = self.lock();
                self.ticket_release_locked(p)
            }
            // takes the spend lock itself, and not while the seller is asked to cancel
            "ticket_stop" => sanitize(self.ticket_stop(p)),
            "ticket_status" => {
                let _g = self.lock();
                sanitize(self.ticket_status_locked(p))
            }
            "watch_tick" => sanitize(json!({"actions": self.watch_tick()})),
            "sweep_hot" => {
                let _g = self.lock();
                sanitize(self.sweep_hot_signed(p))
            }
            "signatures" => {
                let chk = match self.anchor.check() {
                    Ok(c) => c,
                    Err(e) => with(check_chain(&self.sigaudit.path, None), json!({"anchor_error": trunc(&e.msg, 200)})),
                };
                let limit = py_int(p.get("limit")).filter(|l| *l > 0).unwrap_or(50) as usize;
                sanitize(json!({"signatures": self.sigaudit.read(limit), "chain_ok": chk["ok"], "chain": chk, "anchor": self.anchor.status()}))
            }
            "anchor_now" => {
                let reason = if s("reason").is_empty() { "operator".to_string() } else { s("reason") };
                sanitize(json!({"result": self.anchor.anchor(&reason), "anchor": self.anchor.status()}))
            }
            "anchor_status" => sanitize(with(self.anchor.status(), json!({"last_error": self.anchor.last_error()}))),
            "hot_reconcile" => {
                if truthy(p.get("last")) {
                    return Ok(sanitize(with(self.hot.last_reconcile(), self.hot.status())));
                }
                let _g = self.lock();
                let scan = p.get("scan").map(|v| truthy(Some(v))).unwrap_or(true);
                sanitize(with(self.hot.reconcile(scan), self.hot.status()))
            }
            other => match self.admin_dispatch(other, p) {
                Some(r) => r?,
                None if REMOVED_METHODS.contains(&other) => deny("removed", format!("{other} was a method of the on-chain channel, which this wallet no longer has: it opens, pays, closes and refunds none")),
                None => return Err(err("unknown_method", format!("unknown method {other}"))),
            },
        })
    }

    /// Rotate the hot key (the caller holds the spend lock); `rule` names who asked in the signature log.
    pub(crate) fn rotate_locked(&self, rule: &str) -> Result<Value> {
        sigaudit::set_rule(rule);
        let out = self.hot.rotate()?;
        self.engine.audit.append(json!({"type": "hot_rotation", "ts": ts_value(self.now()), "old_address": out["old_address"],
                                        "new_address": out["new_address"], "sweep_txid": out["sweep"].get("txid")}));
        if !out["sweep"].is_null() {
            self.mine_safe();
        }
        self.anchor_after("rotation");
        Ok(sanitize(with(out, self.hot.status())))
    }

    fn payment(&self, p: &Value) -> Result<Payment> {
        let amount = match p.get("amount_sats").filter(|v| !v.is_null()) {
            Some(v) => py_int(Some(v)).ok_or_else(|| err("bad_request", "amount_sats is not an integer"))?,
            None => sats_from_xbt(p.get("amount_xbt")).map_err(|m| err("bad_request", m))?,
        };
        let to = str_or_empty(p.get("to"));
        let to = if to.is_empty() { str_or_empty(p.get("dest")) } else { to };
        Ok(Payment::new(&to, amount, &str_or_empty(p.get("memo"))))
    }

    // --- the watcher, the human sweep ----------------------------------------------------------------

    /// One watcher pass: sweep coins that reached a retired hot key, anchor when due, bring the
    /// Lightning payments and the ticket book to what the node records.
    ///
    /// AGP-095 (audit item 13), the rule: **a panic in one step of a tick ends that step of that
    /// tick, and nothing else.** Release builds check arithmetic (AGP-089), so a number that does
    /// not fit is a panic, and this thread was started once and nothing restarted it, while the
    /// socket went on answering. Each step runs on its own, a step that panics is reported
    /// (`watcher_panic`) and tried again at the next tick, and the steps after it still run. (A
    /// build with `panic = "abort"`, the `release-small` profile, cannot catch a panic: there the
    /// process ends and whatever supervises it starts it again.)
    pub fn watch_tick(&self) -> Vec<Value> {
        let mut actions = vec![];
        if self.height().is_err() {
            return actions;
        }
        self.watch_step("retired_sweep", &mut actions, |actions| {
            let sw = {
                let _g = self.lock();
                let _c = sigaudit::context(Some("watcher"), Some("watcher:retired_sweep"));
                match self.hot.sweep_retired() {
                    Ok(v) => v,
                    Err(e) => Some(json!({"error": trunc(&e.msg, 200)})),
                }
            };
            if let Some(sw) = sw {
                let swept = sw.get("txid").is_some();
                actions.push(json!({"retired_sweep": sw}));
                if swept {
                    self.anchor_after("retired_sweep");
                }
            }
        });
        self.watch_step("anchor", &mut actions, |actions| {
            if self.anchor.due() {
                let r = self.anchor.anchor("periodic");
                if r.get("ok") != Some(&Value::Bool(true)) || !truthy(r.get("unchanged")) {
                    let mut a = json!({});
                    for k in ["ok", "n", "seq", "alert", "reason"] {
                        a[k] = r.get(k).cloned().unwrap_or(Value::Null);
                    }
                    actions.push(json!({"anchor": a}));
                }
            }
        });
        self.watch_step("ln_reconcile", &mut actions, |actions| {
            // AGP-048: a Lightning payment a crash or a timeout left in flight (AGP-049: or one released as
            // never sent, which the node may still record late)
            if self.ln.is_some() && (!self.ln_book.in_flight().is_empty() || !self.ln_book.watched(self.engine.now(), self.height_safe()).is_empty()
                                     || self.ln_book.halted().is_some()) {
                let _g = self.lock();
                let _c = sigaudit::context(Some("watcher"), Some("watcher:ln_reconcile"));
                for r in self.ln_reconcile_locked() {
                    actions.push(json!({"ln_reconcile": r}));
                }
            }
        });
        self.watch_step("ticket_sessions", &mut actions, |actions| {
            // sessions paid over HTTP: the idle ones stopped, and the cancel asked for what an earlier run left locked
            if self.ln.is_some() && self.run.join(crate::ticket_rail::BOOK_FILE).exists() {
                let _c = sigaudit::context(Some("watcher"), Some("watcher:ticket_sessions"));
                actions.extend(self.ticket_http_tick());
            }
        });
                self.watch_step("ticket_reconcile", &mut actions, |actions| {
            // stream tickets: the book is brought to the node's payment records, and the node's list is read for tickets the book lacks
            if self.ln.is_some() && self.ticket_in_use() {
                let _g = self.lock();
                let _c = sigaudit::context(Some("watcher"), Some("watcher:ticket_reconcile"));
                for r in self.ticket_reconcile_locked() {
                    actions.push(json!({"ticket_reconcile": r}));
                }
            }
        });
        actions
    }

    /// One step of a watcher tick, on its own: a panic in it is caught and reported.
    fn watch_step(&self, name: &str, actions: &mut Vec<Value>, step: impl FnOnce(&mut Vec<Value>)) {
        if let Err(p) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| step(&mut *actions))) {
            let why = p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
            actions.push(json!({"watcher_panic": name, "detail": trunc(&why, 200)}));
        }
    }

    fn sweep_hot_signed(&self, p: &Value) -> Value {
        let to = { let t = str_or_empty(p.get("to")); if t.is_empty() { str_or_empty(p.get("address")) } else { t } }.trim().to_string();
        let (Some(amount), Some(expiry), Some(sig)) = (py_int(p.get("amount_sats")).or(Some(0)), py_int(p.get("expiry")).or(Some(0)),
                                                        x2b(&str_or_empty(p.get("signature")))) else {
            return json!({"ok": false, "reason": "bad amount, expiry or signature"});
        };
        let msg = sweep_message(&self.hot.address(), &to, amount, expiry);
        if self.human_key().is_empty() || sig.is_empty() || !verify(&self.human_key(), &msg, &sig) {
            return json!({"ok": false, "reason": "sweep_hot requires a valid human signature"});
        }
        if (expiry as f64) < self.now() {
            return json!({"ok": false, "reason": "sweep signature expired"});
        }
        let spk = match address_to_spk(&to, &self.hrp) {
            Ok(s) => s,
            Err(e) => return json!({"ok": false, "reason": trunc(&e.msg, 200)}),
        };
        // AGP-089: one signature sweeps once (it carried an expiry and no nonce: until its expiry
        // any holder could sweep again, whatever had arrived at the hot key since)
        if let Some(d) = self.check_sig(&msg, p, expiry) {
            return json!({"ok": false, "reason": d["reason"], "rule": d["rule"]});
        }
        sigaudit::set_rule("human:sweep_signature");
        let out = match self.hot.sweep_to(&spk, amount, DEFAULT_FEE) {
            Ok(o) => o,
            Err(e) => return json!({"ok": false, "reason": trunc(&e.msg, 200)}),
        };
        self.engine.audit.append(json!({"type": "hot_sweep", "to": to, "sats": amount, "txid": out["txid"], "ts": ts_value(self.now())}));
        self.anchor_after("human_sweep");
        self.mine_safe();
        with(with(json!({"ok": true, "to": to}), out), self.hot.status())
    }

    // --- payments ---------------------------------------------------------------------------------------

    /// `pay`: coins sent on chain from the node's wallet to an address, under the policy.
    fn pay_locked(&self, p: &Value, human: bool) -> Result<Value> {
        let pay = self.payment(p)?;
        let to = normalize_dest(&pay.dest);
        if to.starts_with("http://") || to.starts_with("https://") {
            // it used to open an on-chain channel with that seller; that rail was removed
            return Ok(deny("dest", "pay sends coins to an XBT address: a seller's URL is paid with xbt402_pay"));
        }
        let d = self.engine.evaluate(&pay, human)?;
        if !d.allowed() {
            return Ok(d.as_value());
        }
        sigaudit::set_rule(&if human { "human:approval_signature".to_string() } else { format!("policy:{}", d.rule) });
        let xbt = format!("{:.8}", pay.amount_sats as f64 / XBT_SATS as f64);
        // AGP-080 K1: booked before the node is asked to send. A crash, or a node that never
        // answers, leaves the payment counted; only the node's own refusal takes it back.
        let ahead = format!("onchain:unconfirmed:{}", crate::policy::token_urlsafe());
        self.engine.commit(&pay, &ahead)?;
        let txid = match self.node.call("sendtoaddress", json!([pay.dest, xbt, pay.memo, "", false])) {
            Ok(t) => t.as_str().unwrap_or("").to_string(),
            Err(e) if e.code == node::REFUSED => {
                self.engine.store.amend(&ahead, None)?;
                return Err(e);
            }
            Err(e) => return Err(err(&e.code, format!("{}; the node may have sent this payment, so it stays in the ledger as {ahead}", e.msg))),
        };
        // the row under the txid first: a crash here counts the payment twice, never not at all. The coins have
        // left: an error from here on is the ledger's, and is said beside the txid, never as a failed payment (a
        // caller told it failed would pay again). The write-ahead row stays and keeps the payment counted.
        let booked = self.engine.commit(&pay, &txid).and_then(|()| self.engine.store.amend(&ahead, None).map(|_| ()));
        let mut out = with(d.as_value(), json!({"txid": txid, "rail": "onchain"}));
        if let Err(e) = booked {
            eprintln!("xbt-signer: the payment {txid} was sent, and its ledger row was not written: {}", e.msg);
            out["ledger_error"] = json!(format!("sent; the ledger keeps it counted as {ahead}: {}", e.msg));
        }
        Ok(out)
    }

    fn approve_signed(&self, p: &Value) -> Result<Value> {
        let token = str_or_empty(p.get("token"));
        let mut dest = { let d = str_or_empty(p.get("dest")); if d.is_empty() { str_or_empty(p.get("to")) } else { d } }.trim().to_string();
        let low = dest.to_lowercase();
        if low.starts_with("bc1") || low.starts_with("bcrt1") || low.starts_with("tb1") {
            dest = low;
        }
        let amount = match p.get("amount_sats").filter(|v| !v.is_null()) {
            Some(v) => py_int(Some(v)).unwrap_or(0),
            None => sats_from_xbt(p.get("amount_xbt")).map_err(|m| err("bad_request", m))?,
        };
        let expiry = py_int(p.get("expiry")).unwrap_or(0);
        let sig_hex = { let s = str_or_empty(p.get("signature")); if s.is_empty() { str_or_empty(p.get("sig")) } else { s } };
        let Some(signature) = x2b(&sig_hex) else { return Ok(deny("approval_sig", "signature is not valid hex")) };
        let human_pubkey = self.human_key();
        if human_pubkey.is_empty() {
            return Ok(deny("approval_sig", "signer has no human public key configured"));
        }
        let now = self.now();
        if signature.is_empty() || !verify_approval(&human_pubkey, &token, &dest, amount, expiry, &signature) {
            self.engine.audit.append(json!({"type": "decision", "verdict": "deny", "rule": "approval_sig", "reason": "missing or invalid human signature",
                                            "dest": dest, "amount_sats": amount, "ts": ts_value(now)}));
            return Ok(deny("approval_sig", "missing or invalid human signature over (token, dest, amount, expiry)"));
        }
        // AGP-089: one approval pays once. The token is read, held and paid under the spend lock,
        // the one lock every payment takes: a second `approve` of the same token (a double click, a
        // retry) waits here and then finds the token held or gone. Reading it before the lock let
        // two calls that waited on another payment both pass the `used` check.
        let g = self.lock();
        let Some(payload) = self.engine.store.get_approval(&token)? else {
            self.engine.audit.append(json!({"type": "approval_miss", "token": token, "ts": ts_value(now)}));
            return Ok(deny("approval", "unknown or already-used approval token"));
        };
        if truthy(payload.get("used")) {
            return Ok(deny("approval_replay", "approval token already used"));
        }
        let stored_exp = py_int(payload.get("expires")).unwrap_or(0);
        if (stored_exp as f64) < now || (expiry as f64) < now {
            self.engine.store.pop_approval(&token)?;
            self.note_expired(&token);
            self.engine.audit.append(json!({"type": "approval_expired", "token": token, "ts": ts_value(now)}));
            return Ok(deny("approval_expired", "approval token expired"));
        }
        if dest != str_or_empty(payload.get("dest")) || amount != py_int(payload.get("amount_sats")).unwrap_or(0) || expiry != stored_exp {
            self.engine.audit.append(json!({"type": "decision", "verdict": "deny", "rule": "approval_bind",
                                            "reason": "signature fields do not match pending approval", "dest": dest, "amount_sats": amount, "ts": ts_value(now)}));
            return Ok(deny("approval_bind", "signature fields do not match the pending approval"));
        }
        if payload.get("kind").and_then(Value::as_str) == Some("ln_resume") {
            drop(g); // it takes the spend lock itself, and moves no funds
            return self.ln_resume(&token, &payload);
        }
        match payload.get("kind").and_then(Value::as_str) {
            Some("ln") => return self.grant_ln(&token, &payload),
            // asked for by a call over the on-chain channel, before that rail was removed: nothing can pay under it
            Some("xbt402") => {
                self.engine.store.pop_approval(&token)?;
                self.note_expired(&token);
                return Ok(deny("removed", "this approval was asked for by a payment over the on-chain channel, which this wallet no longer has; it is dropped"));
            }
            _ => {}
        }
        // AGP-085: the approval is held while the payment runs, not spent before it. On disk it is
        // `used`, so a crash or a failure of unknown fate leaves it used for good (a later approve
        // is `approval_replay`: never a second payment on one approval). It is spent by a payment
        // (`allow`), and given back, valid until its own expiry, when nothing was paid and nothing
        // is booked: the node's own refusal, or a verdict that is not `allow`.
        let _g = g;
        let mut held = payload.clone();
        held["used"] = true.into();
        self.engine.store.put_approval(&token, held)?;
        let pay = Payment { dest: str_or_empty(payload.get("dest")), amount_sats: py_int(payload.get("amount_sats")).unwrap_or(0),
                            memo: str_or_empty(payload.get("memo")), ts: now };
        let booked = |s: &Self| -> Result<i64> { Ok(s.engine.store.payments()?.iter().map(|e| e.amount_sats).sum()) };
        let before = booked(self)?;
        let r = self.pay_locked(&json!({"to": pay.dest, "amount_sats": pay.amount_sats, "memo": pay.memo}), true);
        let unpaid = booked(self)? == before
            && match &r {
                Ok(v) => v["verdict"] != "allow",
                Err(e) => e.code == node::REFUSED,
            };
        if unpaid {
            self.engine.store.put_approval(&token, payload)?;
            return r;
        }
        self.note_used(&token);
        let mut settled = r?;
        self.engine.store.pop_approval(&token)?;
        if settled["verdict"] == "allow" {
            settled["approved"] = true.into();
        }
        Ok(settled)
    }

    /// Unused in the Rust signer (no vault), kept for the message format.
    pub fn recover_message_for(&self, addr: &str, expiry: i64) -> Vec<u8> {
        recover_message(addr, expiry)
    }
}

/// Regtest only (P3): refused unless the node is still regtest.
pub fn mine_blocks(node: &dyn Node, n: u64) -> Result<()> {
    let info = node.call("getblockchaininfo", json!([]))?;
    if info.get("chain").and_then(Value::as_str).unwrap_or("regtest") != "regtest" {
        return Err(err("chain", "the node is no longer regtest: refusing to mine"));
    }
    let addr = node.call("getnewaddress", json!(["mine", "bech32"]))?;
    node.call("generatetoaddress", json!([n, addr]))?;
    Ok(())
}

impl Signer {
    /// Sleep until the next watcher tick; `true` when stopping.
    pub fn watch_loop(self: &Arc<Self>, stop: Arc<std::sync::atomic::AtomicBool>) {
        self.watch_loop_in(stop, &xbt_svc::shutdown::Drain::default())
    }

    /// [`Signer::watch_loop`], each tick counted as work in flight in `drain`: a signer that is told
    /// to stop lets the tick that is running finish, and starts no other.
    pub fn watch_loop_in(self: &Arc<Self>, stop: Arc<std::sync::atomic::AtomicBool>, drain: &xbt_svc::shutdown::Drain) {
        use std::sync::atomic::Ordering;
        loop {
            let steps = ((self.watch_interval * 10.0) as u64).max(1);
            for _ in 0..steps {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let Some(_busy) = drain.enter() else { return };
            // every step of a tick is guarded (`watch_step`); this guards what is left around them,
            // so the thread ends only when the signer stops (AGP-095)
            let tick = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.watch_tick()));
            for a in tick.unwrap_or_else(|_| vec![json!({"watcher_panic": "tick"})]) {
                println!("watcher: {}", crate::pyjson::dumps_sorted_compact(&a));
            }
        }
    }
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer").field("root", &self.root).field("chain", &self.chain).field("mining", &self.mining).finish_non_exhaustive()
    }
}
