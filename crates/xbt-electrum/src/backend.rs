//! The light chain backend: the node calls of the xbt402 client path answered from Electrum
//! servers and verified against our own BLAKE2b header chain (a port of B2 `agentwallet/electrum.py`,
//! AGP-024; the threat model is in the crate docs and `docs/B2_CHAIN_BACKEND.md`).
//!
//! No network read happens under the shared state lock: requests run unlocked and the lock is taken
//! only to read or record what they returned. Servers sync in parallel; header chunks are checked as
//! they arrive (the first bad header ends that server's sync, the valid headers before it count).
//!
//! What one server can cost is bounded (AGP-081, review E1): its part of a sync round ends at
//! [`Config::sync_deadline`] or at the first answer with fewer headers than asked, a history holds
//! at most [`MAX_HISTORY`] entries, transactions are fetched [`TX_BATCH`] at a time, and the
//! transaction cache holds at most [`TX_CACHE_BYTES`].
//!
//! Two rules every lookup keeps (AGP-092):
//!
//! * **Unknown is not absent.** A lookup says "not there" (no such transaction, no such output, not
//!   in a block, no such coin) only when every configured server answered. If one did not answer,
//!   or is down, the call fails with [`Kind::Unreachable`]. "Spent" is said only for a confirmed spend with a proof.
//!   The one place that does not wait for every server is the search for a spend: missing one there
//!   answers "unspent", which a caller can only act on by broadcasting, and the network refuses it.
//! * **A call has a deadline** ([`Config::call_deadline`]): every request made for it ends there, it
//!   forces at most one header sync, whose time is not taken from the call's (AGP-106: the sync
//!   has its own deadline), and a server is asked only for the transactions it listed
//!   itself, in parallel with the others. The first one it cannot supply, or that cannot belong to
//!   the script, ends its part and flags it.
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use xbt402::funding::{ChainBackend, UtxoInfo};
use xbt_primitives::address::segwit_address;
use xbt_primitives::hash::{hex32, sha256};
use xbt_primitives::header::{self, merkle_root_from_proof, parse_header, split_headers, ChainRules, Clock, HeaderChain,
                             MAINNET_CHECKPOINT, U512};
use xbt_primitives::network::Chain;
use xbt_primitives::tx::Tx;

use crate::conn::{tls_config, Connection, Notify, MAX_HEADERS, MAX_HISTORY};
use crate::error::{err, ElectrumError, Kind, Result};

/// Headers per `blockchain.block.headers` request (electrs' maximum).
pub const HEADERS_CHUNK: u32 = MAX_HEADERS as u32;
/// Header chunk requests per JSON-RPC batch while catching up.
pub const CHUNKS_PER_BATCH: u32 = 4;
/// A mainnet tip older than this means every server is behind, or withholding blocks.
pub const STALE_TIP_S: u64 = 3 * 60 * 60;
/// A claimed tip is believed up to one block per this many seconds since our tip's time (a quarter
/// of the target spacing), plus [`HEADERS_CHUNK`]; headers above that are not fetched.
pub const TIP_CAP_SPACING_S: u64 = 150;
/// Node RPCs a light client cannot answer: the node wallet, blocks, mining.
pub const NODE_ONLY: &[&str] = &[
    "getbalances", "getbalance", "sendtoaddress", "listunspent", "createrawtransaction", "fundrawtransaction",
    "signrawtransactionwithwallet", "getnewaddress", "generatetoaddress", "generatetodescriptor", "generateblock",
    "generate", "getblock", "getwalletinfo", "sendmany",
];
/// `blockchain.transaction.get` requests per JSON-RPC batch.
pub const TX_BATCH: usize = 16;
/// Raw bytes of the transactions kept in memory; the oldest are dropped first and fetched again
/// when needed.
pub const TX_CACHE_BYTES: usize = 32 << 20;
const SATS: f64 = 100_000_000.0;
const MAX_FLAGS: usize = 50;

/// Electrum's script hash: SHA-256 of the scriptPubKey, byte-reversed, hex.
pub fn scripthash(spk: &[u8]) -> String {
    let mut h = sha256(spk);
    h.reverse();
    hex::encode(h)
}

fn now_s() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn is_coinbase(tx: &Tx) -> bool {
    tx.inputs.len() == 1 && tx.inputs[0].prevout.txid == [0u8; 32] && tx.inputs[0].prevout.vout == 0xFFFF_FFFF
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// `localhost`, 127.0.0.0/8, `::1` or an IPv4-mapped loopback address.
pub fn is_loopback_host(host: &str) -> bool {
    let h = host.trim_end_matches('.');
    if h.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match h.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => a.is_loopback(),
        Ok(IpAddr::V6(a)) => a.is_loopback() || a.to_ipv4_mapped().map(|m| m.is_loopback()).unwrap_or(false),
        Err(_) => false,
    }
}

/// When the verified chain is believable (see [`HeaderChain::implausible`]): until it is, every
/// chain answer fails with [`Kind::Implausible`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plausibility {
    /// Work the chain must carry above the checkpoint.
    pub min_work_above: U512,
    /// The tip may trail one block per `floor_spacing_s` since the newest pinned block we hold (or
    /// the checkpoint) by at most `floor_slack` blocks.
    pub floor_spacing_s: u64,
    pub floor_slack: u32,
}

impl Plausibility {
    /// Mainnet from `checkpoint`: Knots' nMinimumChainWork less the checkpoint's chainwork (zero for
    /// a checkpoint of unknown chainwork, which still has to reach the pinned block 964264), and a
    /// floor of one block per 600 s with 2016 blocks of slack.
    pub fn mainnet(checkpoint: (u32, &[u8; 32])) -> Self {
        Self {
            min_work_above: header::mainnet_min_work_above(checkpoint).unwrap_or(U512::ZERO),
            floor_spacing_s: 600,
            floor_slack: HEADERS_CHUNK,
        }
    }
}

/// How the backend is set up.
#[derive(Clone)]
pub struct Config {
    /// `ssl://host:port` (certificates verified) or `tcp://host:port`; on mainnet `tcp://` only to a
    /// loopback host.
    pub servers: Vec<String>,
    /// `main` or `regtest` (testnet3, testnet4 and signet have no header rules here and are refused):
    /// a light client does not ask a node.
    pub chain: String,
    /// `(height, block hash)`. Mainnet defaults to 961640, the first BLAKE2b block; other chains must set it.
    pub checkpoint: Option<(u32, String)>,
    /// Where the verified headers persist (re-verified at load).
    pub store_path: Option<PathBuf>,
    /// Per request.
    pub timeout: Duration,
    /// Servers that must answer (default 2 on mainnet, 1 elsewhere; capped at the number configured).
    pub min_servers: Option<usize>,
    /// Re-ask the servers' tips at most this often (a tip notification forces it sooner).
    pub sync_interval: Duration,
    /// Extra CA certificates (PEM) for `ssl://` servers, besides the Mozilla roots.
    pub extra_ca: Vec<PathBuf>,
    /// None: [`Plausibility::mainnet`] on mainnet, no check elsewhere.
    pub plausibility: Option<Plausibility>,
    /// A claimed tip is believed up to one block per this many seconds since our tip's time, plus
    /// [`HEADERS_CHUNK`]. None: [`TIP_CAP_SPACING_S`] on mainnet, no cap elsewhere (regtest mines
    /// blocks as fast as it is asked to).
    pub tip_cap_spacing_s: Option<u64>,
    /// The current unix time (the 2 h future rule, the tip cap, the height floor); None: the system clock.
    pub clock: Option<Clock>,
    /// One server's part of a sync round ends here: the headers it proved by then are kept and it is
    /// flagged. None: four times `timeout`.
    pub sync_deadline: Option<Duration>,
    /// Every request one call makes ends here. The header sync before it, and the one sync a call
    /// may force, have their own deadline and are not counted in it.
    /// None: four times `timeout`.
    pub call_deadline: Option<Duration>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config").field("servers", &self.servers).field("chain", &self.chain)
            .field("checkpoint", &self.checkpoint).field("store_path", &self.store_path).field("timeout", &self.timeout)
            .field("min_servers", &self.min_servers).field("sync_interval", &self.sync_interval)
            .field("extra_ca", &self.extra_ca).field("plausibility", &self.plausibility)
            .field("tip_cap_spacing_s", &self.tip_cap_spacing_s).field("clock", &self.clock.as_ref().map(|_| "custom"))
            .field("sync_deadline", &self.sync_deadline).field("call_deadline", &self.call_deadline).finish()
    }
}

impl Config {
    pub fn new(servers: &[&str], chain: &str) -> Self {
        Self {
            servers: servers.iter().map(|s| s.to_string()).collect(),
            chain: chain.to_string(),
            checkpoint: None,
            store_path: None,
            timeout: Duration::from_secs(15),
            min_servers: None,
            sync_interval: Duration::from_secs(1),
            extra_ca: Vec::new(),
            plausibility: None,
            tip_cap_spacing_s: None,
            clock: None,
            sync_deadline: None,
            call_deadline: None,
        }
    }

    /// B2's environment (`docs/B2_CHAIN_BACKEND.md`): `B2_CHAIN`, `B2_ELECTRUM_SERVERS`,
    /// `B2_ELECTRUM_CHECKPOINT` (`<height>:<hash>`), `B2_ELECTRUM_MIN_SERVERS`, `B2_ELECTRUM_TIMEOUT`,
    /// plus `B2_ELECTRUM_CA` (comma-separated PEM files) and the run dir for the header store.
    pub fn from_env(run_dir: Option<&std::path::Path>) -> Result<Self> {
        let get = |k: &str| std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let chain = get("B2_CHAIN").ok_or_else(|| ElectrumError::new(Kind::BadRequest, "the Electrum backend needs B2_CHAIN (a light client has no node to ask)"))?;
        let servers = split_list(get("B2_ELECTRUM_SERVERS").as_deref());
        if servers.is_empty() {
            return err(Kind::BadRequest, "the Electrum backend needs B2_ELECTRUM_SERVERS");
        }
        let mut c = Config::new(&servers.iter().map(String::as_str).collect::<Vec<_>>(), &chain);
        c.checkpoint = parse_checkpoint(get("B2_ELECTRUM_CHECKPOINT").as_deref())?;
        if let Some(m) = get("B2_ELECTRUM_MIN_SERVERS") {
            c.min_servers = Some(m.parse().map_err(|_| ElectrumError::new(Kind::BadRequest, "B2_ELECTRUM_MIN_SERVERS: a number"))?);
        }
        if let Some(t) = get("B2_ELECTRUM_TIMEOUT") {
            let s: f64 = t.parse().map_err(|_| ElectrumError::new(Kind::BadRequest, "B2_ELECTRUM_TIMEOUT: seconds"))?;
            c.timeout = Duration::from_secs_f64(s.clamp(0.1, 3600.0));
        }
        c.extra_ca = split_list(get("B2_ELECTRUM_CA").as_deref()).into_iter().map(PathBuf::from).collect();
        c.store_path = run_dir.map(|d| d.join(format!("headers-{chain}.bin")));
        Ok(c)
    }
}

fn split_list(v: Option<&str>) -> Vec<String> {
    v.unwrap_or("").split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
}

/// `"<height>:<64-hex block hash>"`.
pub fn parse_checkpoint(v: Option<&str>) -> Result<Option<(u32, String)>> {
    let Some(v) = v.map(str::trim).filter(|v| !v.is_empty()) else { return Ok(None) };
    let (h, bh) = v.split_once(':').unwrap_or((v, ""));
    match (h.parse::<u32>(), bh.len() == 64 && bh.chars().all(|c| c.is_ascii_hexdigit())) {
        (Ok(h), true) => Ok(Some((h, bh.to_ascii_lowercase()))),
        _ => err(Kind::BadRequest, "the checkpoint must be <height>:<64-hex block hash>"),
    }
}

/// Where a transaction is, as far as can be proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxStatus {
    /// A server says it is unconfirmed (unprovable, and never treated as confirmed).
    Mempool,
    /// A Merkle proof ties it to our header at this height.
    Confirmed { height: u32, block_hash: [u8; 32] },
}

/// `gettxout`, verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutInfo {
    pub best_block: String,
    /// 0 for a mempool output.
    pub confirmations: u32,
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    pub coinbase: bool,
}

/// A confirmed, proven, unspent coin of a script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    pub height: u32,
    /// The block the Merkle proof ties it to (display hex).
    pub block_hash: String,
    pub coinbase: bool,
}

/// A fee estimate. Never verifiable: the median over the servers that answered, so one lying
/// server cannot set it alone.
#[derive(Debug, Clone, PartialEq)]
pub struct FeeEstimate {
    /// BTC per kvB; None when no server had an estimate.
    pub feerate: Option<f64>,
    pub blocks: u32,
    pub answers: Vec<f64>,
}

/// What we know about one server (the `status()` report).
#[derive(Debug, Clone, Default)]
pub struct ServerState {
    pub server: String,
    pub proto: String,
    pub tip: Option<u32>,
    pub tip_hash: Option<String>,
    pub on_best_chain: Option<bool>,
    pub errors: u64,
    pub last_error: Option<String>,
}

/// A server answered something that failed verification (or failed to answer).
#[derive(Debug, Clone)]
pub struct Flag {
    pub server: String,
    pub reason: String,
    pub t: u64,
}

struct Signal {
    tip_dirty: AtomicBool,
    changed: Mutex<bool>,
    cv: Condvar,
}

/// The transactions fetched and verified, at most `max` raw bytes of them, oldest out first.
struct TxCache {
    map: HashMap<String, (Tx, usize)>,
    order: VecDeque<String>,
    bytes: usize,
    max: usize,
}

impl TxCache {
    fn new(max: usize) -> Self {
        Self { map: HashMap::new(), order: VecDeque::new(), bytes: 0, max }
    }

    fn get(&self, txid: &str) -> Option<&Tx> {
        self.map.get(txid).map(|(tx, _)| tx)
    }

    fn contains(&self, txid: &str) -> bool {
        self.map.contains_key(txid)
    }

    /// Keep `tx`; returns the txids dropped to make room. A transaction larger than the whole cache
    /// is not kept.
    fn insert(&mut self, txid: String, tx: Tx) -> Vec<String> {
        let size = tx.serialize().len();
        let mut dropped = Vec::new();
        if self.map.contains_key(&txid) || size > self.max {
            return dropped;
        }
        while self.bytes + size > self.max {
            let Some(old) = self.order.pop_front() else { break };
            if let Some((_, n)) = self.map.remove(&old) {
                self.bytes -= n;
                dropped.push(old);
            }
        }
        self.bytes += size;
        self.order.push_back(txid.clone());
        self.map.insert(txid, (tx, size));
        dropped
    }
}

struct Inner {
    headers: HeaderChain,
    last_sync: Option<Instant>,
    watched: BTreeSet<String>,
    txs: TxCache,
    conf: HashMap<String, (u32, [u8; 32])>,
    servers: HashMap<String, ServerState>,
    flags: VecDeque<Flag>,
    /// How many sync rounds were started.
    round: u64,
    /// server url -> the round in which it last reported its tip.
    tip_round: HashMap<String, u64>,
}

impl Inner {
    /// Keep a verified transaction. A transaction dropped for room loses its cached proof with it,
    /// so `conf` never outgrows the transactions held.
    fn cache_tx(&mut self, txid: String, tx: Tx) {
        for old in self.txs.insert(txid, tx) {
            self.conf.remove(&old);
        }
    }

    fn flag(&mut self, url: &str, reason: impl Into<String>) {
        let mut reason: String = reason.into();
        if reason.len() > 200 {
            let mut i = 200;
            while !reason.is_char_boundary(i) {
                i -= 1;
            }
            reason.truncate(i);
        }
        let st = self.servers.entry(url.to_string()).or_default();
        st.errors += 1;
        st.last_error = Some(reason.clone());
        self.flags.push_back(Flag { server: url.to_string(), reason, t: now_s() });
        while self.flags.len() > MAX_FLAGS {
            self.flags.pop_front();
        }
    }

    fn tip_height(&self) -> u32 {
        self.headers.tip_height().unwrap_or(0)
    }

    /// Still on our best chain? (A cached proof into a header that was reorged out must be redone.)
    fn conf_holds(&self, c: &(u32, [u8; 32])) -> bool {
        self.headers.at(c.0).map(|h| h.hash == c.1).unwrap_or(false)
    }
}

/// (the server that claimed it, the height it claimed; 0 or less = its mempool)
type Claims = Vec<(Arc<Connection>, i64)>;

/// A proof to ask a server for: (txid, the height it claimed, our header there).
type ProofAsk = (String, u32, header::Header);

/// One call's budget: its requests end at `until()`, it forces one header sync at most, and it
/// tries once to reach a server that is down.
struct Call {
    /// Where the call's requests end. Moved only by [`Call::give_back`].
    until: Mutex<Instant>,
    synced: AtomicBool,
    /// The sync round this call itself ran when it forced one (0: none, or it found another sync
    /// in flight and ran nothing). Only against a tip a server reported in that round, or a later
    /// one, is a claim above the server's tip a lie (AGP-097).
    round: AtomicU64,
    /// Servers this call could not reach: not tried again in it (a dead server used to cost every
    /// step of a call one timeout).
    gone: Mutex<Vec<String>>,
}

impl Call {
    fn new(until: Instant) -> Self {
        Self { until: Mutex::new(until), synced: AtomicBool::new(false), round: AtomicU64::new(0), gone: Mutex::new(Vec::new()) }
    }

    fn until(&self) -> Instant {
        *lock(&self.until)
    }

    fn over(&self) -> bool {
        Instant::now() >= self.until()
    }

    /// The rule (AGP-106): **the header sync a call forces is not paid for out of the call's
    /// time.** The sync has its own deadline (`sync_deadline`, per server), as long as the call's
    /// at the defaults, so a server that held its part of the sync to that deadline ended the call
    /// with it: the claims of the honest servers were then "not judged" and a lookup of a confirmed
    /// coin failed on every call. A call forces one sync at most ([`Call::synced`]), so this moves
    /// the deadline once, by no more than one sync round takes.
    fn give_back(&self, spent: Duration) {
        let mut u = lock(&self.until);
        *u += spent;
    }
}

/// The union of the servers' histories of one script.
struct Hist {
    claims: HashMap<String, Claims>,
    /// Every configured server gave a usable answer. Without it "not listed" is not known.
    complete: bool,
}

/// What the claims about one transaction came to.
struct Proof {
    status: Option<TxStatus>,
    /// Every claim was checked. Without it "not confirmed" is not known: a server did not answer for
    /// the height it claimed, or claims a block we do not hold.
    checked: bool,
}

/// A transaction and where it is.
struct Located {
    tx: Option<Tx>,
    status: Option<TxStatus>,
    /// Nothing was left unanswered on the way: a status short of confirmed is the servers' answer.
    complete: bool,
}

/// How one server's part of [`ElectrumBackend::supply`] ended.
#[derive(PartialEq)]
enum Supplied {
    All,
    /// It listed a transaction it does not supply, or one that cannot belong to the script (flagged).
    Lied,
    /// It stopped answering, or the call's deadline came first (flagged).
    Silent,
}

/// A server's words for "I have no such transaction" and, asked for a proof, "it is not in that
/// block" (bitcoind's, electrs', ElectrumX's, Fulcrum's).
pub const NOT_THERE: [&str; 6] = ["no such", "not found", "not in block", "not confirmed", "no transaction", "missing"];

/// Did the server say, in its own words, that it has no such transaction (or no such proof)? Any
/// other error is no answer: busy, rate-limited, or a wording not known here, which fails closed.
///
/// An error that speaks of the method is one of those (AGP-097): "Method not found" is JSON-RPC's
/// answer for a method the server does not serve, and two of the words above ("not found",
/// "missing") are in it. Such a server has said nothing about this transaction. The connection
/// puts the error code -32601 into the same words when the server's own do not name the method.
fn says_not_there(e: &ElectrumError) -> bool {
    let m = e.msg.to_ascii_lowercase();
    e.kind == Kind::Server && !m.contains("method") && NOT_THERE.iter().any(|w| m.contains(w))
}

enum SyncFail {
    OffCheckpoint(String),
    Other(String),
}

impl From<ElectrumError> for SyncFail {
    fn from(e: ElectrumError) -> Self {
        SyncFail::Other(e.msg)
    }
}

impl From<xbt_primitives::Error> for SyncFail {
    fn from(e: xbt_primitives::Error) -> Self {
        SyncFail::Other(e.to_string())
    }
}

/// The light backend (see the crate docs). Share it behind an `Arc`; every method takes `&self`.
pub struct ElectrumBackend {
    pub chain: String,
    hrp: &'static str,
    conns: Vec<Arc<Connection>>,
    pub min_servers: usize,
    sync_interval: Duration,
    signal: Arc<Signal>,
    /// The pinned checkpoint (height, display-order hash).
    cp: (u32, [u8; 32]),
    rules: ChainRules,
    plausibility: Option<Plausibility>,
    tip_cap_spacing_s: Option<u64>,
    clock: Clock,
    sync_deadline: Duration,
    call_deadline: Duration,
    /// Held by the one sync in flight; callers with a verified chain do not wait for it.
    sync_gate: Mutex<()>,
    inner: Mutex<Inner>,
}

impl ElectrumBackend {
    pub fn new(cfg: Config) -> Result<Self> {
        if cfg.servers.is_empty() {
            return err(Kind::BadRequest, "no Electrum servers configured");
        }
        let chain = Chain::from_name(&cfg.chain).map_err(|e| ElectrumError::new(Kind::BadRequest, e.to_string()))?;
        let addrs = cfg.servers.iter().map(|u| crate::conn::parse_server(u)).collect::<Result<Vec<_>>>()?;
        if chain == Chain::Main {
            if let Some((u, _)) = cfg.servers.iter().zip(&addrs).find(|(_, a)| !a.tls && !is_loopback_host(&a.host)) {
                return err(Kind::BadRequest, format!("{u}: mainnet needs ssl:// (TLS); plain tcp:// only to a loopback host"));
            }
        }
        let (cp_h, cp_hash) = match cfg.checkpoint.clone() {
            Some(cp) => cp,
            None if chain == Chain::Main => (MAINNET_CHECKPOINT.0, MAINNET_CHECKPOINT.1.to_string()),
            None => return err(Kind::BadRequest, format!("a {} light backend needs a pinned checkpoint", cfg.chain)),
        };
        let cp = (cp_h, hex32(&cp_hash).map_err(|e| ElectrumError::new(Kind::BadRequest, e.to_string()))?);
        let clock: Clock = cfg.clock.clone().unwrap_or_else(|| Arc::new(now_s));
        let headers = HeaderChain::with_clock(&cfg.chain, (cp_h, &cp_hash), cfg.store_path.as_deref(), clock.clone())
            .map_err(|e| ElectrumError::new(Kind::BadRequest, e.to_string()))?;
        let plausibility = cfg.plausibility.clone().or_else(|| (chain == Chain::Main).then(|| Plausibility::mainnet((cp.0, &cp.1))));
        let signal = Arc::new(Signal { tip_dirty: AtomicBool::new(true), changed: Mutex::new(false), cv: Condvar::new() });
        let notify: Notify = {
            let s = signal.clone();
            Arc::new(move |_url: &str, method: &str, _params: &Value| {
                if method == "blockchain.headers.subscribe" {
                    s.tip_dirty.store(true, Ordering::SeqCst);
                }
                *lock(&s.changed) = true;
                s.cv.notify_all();
            })
        };
        let tls = if addrs.iter().any(|a| a.tls) {
            Some(tls_config(&cfg.extra_ca.iter().map(PathBuf::as_path).collect::<Vec<_>>())?)
        } else {
            None
        };
        let conns = cfg.servers.iter()
            .map(|u| Connection::new(u, cfg.timeout, tls.clone(), Some(notify.clone())).map(Arc::new))
            .collect::<Result<Vec<_>>>()?;
        let default_min = if chain == Chain::Main { 2 } else { 1 };
        let min_servers = cfg.min_servers.unwrap_or(default_min).clamp(1, conns.len());
        let servers = conns.iter().map(|c| (c.url.clone(), ServerState::default())).collect();
        Ok(Self {
            chain: cfg.chain.clone(),
            hrp: chain.hrp(),
            conns,
            min_servers,
            sync_interval: cfg.sync_interval,
            signal,
            cp,
            rules: headers.rules.clone(),
            plausibility,
            tip_cap_spacing_s: cfg.tip_cap_spacing_s.or((chain == Chain::Main).then_some(TIP_CAP_SPACING_S)),
            clock,
            sync_deadline: cfg.sync_deadline.unwrap_or(cfg.timeout.saturating_mul(4)),
            call_deadline: cfg.call_deadline.unwrap_or(cfg.timeout.saturating_mul(4)),
            sync_gate: Mutex::new(()),
            inner: Mutex::new(Inner {
                headers,
                last_sync: None,
                watched: BTreeSet::new(),
                txs: TxCache::new(TX_CACHE_BYTES),
                conf: HashMap::new(),
                servers,
                flags: VecDeque::new(),
                round: 0,
                tip_round: HashMap::new(),
            }),
        })
    }

    // --- plumbing ------------------------------------------------------------------------------

    /// The shared state, briefly: never hold it across a request.
    fn st(&self) -> MutexGuard<'_, Inner> {
        lock(&self.inner)
    }

    fn flag(&self, url: &str, reason: impl Into<String>) {
        self.st().flag(url, reason);
    }

    /// `f` on every connection, in parallel.
    fn each<T: Send>(conns: &[Arc<Connection>], f: impl Fn(&Connection) -> T + Sync) -> Vec<T> {
        if conns.len() <= 1 {
            return conns.iter().map(|c| f(c)).collect();
        }
        std::thread::scope(|s| {
            let hs: Vec<_> = conns.iter().map(|c| { let f = &f; s.spawn(move || f(c)) }).collect();
            hs.into_iter().map(|h| h.join().expect("an Electrum worker panicked")).collect()
        })
    }

    /// Did every configured server answer (`answered` of them did)? Only then is "none of them shows
    /// it" an answer. A server that is down has not said so, whether it was down before the call or
    /// dropped in the middle of it: with it left out, one lying server and one failing honest one
    /// would read as "not there".
    fn all_answer(&self, answered: usize) -> bool {
        answered == self.conns.len()
    }

    fn budget(&self) -> Call {
        Call::new(Instant::now() + self.call_deadline)
    }

    /// The connected servers, after one try per call to connect those that are down (no later than
    /// the call's deadline); an error below `min_servers`. `min_servers` is the floor for what is
    /// proven. "Not there" needs more: every configured server ([`Self::all_answer`]).
    fn live(&self, call: &Call) -> Result<Vec<Arc<Connection>>> {
        let until = Some(call.until());
        // a call whose time is over reaches for nobody: a server that is down would only be
        // flagged for a connect it was given no time for
        let down: Vec<Arc<Connection>> = if call.over() {
            Vec::new()
        } else {
            let gone = lock(&call.gone);
            self.conns.iter().filter(|c| !c.connected() && !gone.contains(&c.url)).cloned().collect()
        };
        if !down.is_empty() {
            let watched: Vec<(String, Value)> = self.st().watched.iter()
                .map(|sh| ("blockchain.scripthash.subscribe".to_string(), json!([sh]))).collect();
            let results = Self::each(&down, |c| -> Result<()> {
                c.connect_until(until)?;
                for r in c.subscribe_many(&watched, until)? {
                    r?;
                }
                Ok(())
            });
            let mut i = self.st();
            for (c, r) in down.iter().zip(results) {
                match r {
                    Ok(()) => {
                        let (server, proto) = c.server_info();
                        let st = i.servers.entry(c.url.clone()).or_default();
                        st.server = server;
                        st.proto = proto;
                    }
                    Err(e) => {
                        i.flag(&c.url, format!("unreachable: {e}"));
                        lock(&call.gone).push(c.url.clone());
                    }
                }
            }
        }
        let live: Vec<Arc<Connection>> = self.conns.iter().filter(|c| c.connected()).cloned().collect();
        if live.len() < self.min_servers {
            return err(Kind::TooFewServers, format!("{} of {} Electrum servers reachable; at least {} needed",
                                                    live.len(), self.conns.len(), self.min_servers));
        }
        Ok(live)
    }

    fn ask(&self, c: &Connection, method: &str, params: Value) -> Result<Value> {
        c.request(method, params).map_err(|e| {
            self.flag(&c.url, format!("{method}: {e}"));
            e
        })
    }

    // --- headers -------------------------------------------------------------------------------

    /// Bring our header chain up to the most-work tip any live server shows. Returns our tip.
    /// With a verified chain, a call that finds another sync in flight answers from the chain as it
    /// is rather than wait for it.
    pub fn sync(&self, force: bool) -> Result<u32> {
        self.sync_round(force)?;
        self.believable()
    }

    /// [`Self::sync`] without the answer: the number of the round this call ran, None when none
    /// was due or another sync was in flight (then nothing was run, and the chain is as it was).
    fn sync_round(&self, force: bool) -> Result<Option<u64>> {
        let (ready, due) = {
            let i = self.st();
            (i.headers.ready(), i.last_sync.map(|t| t.elapsed() >= self.sync_interval).unwrap_or(true))
        };
        if force || due || !ready || self.signal.tip_dirty.load(Ordering::SeqCst) {
            let gate = if ready {
                match self.sync_gate.try_lock() {
                    Ok(g) => Some(g),
                    Err(TryLockError::Poisoned(p)) => Some(p.into_inner()),
                    Err(TryLockError::WouldBlock) => None,
                }
            } else {
                Some(lock(&self.sync_gate))
            };
            if let Some(_g) = gate {
                return self.sync_now().map(Some);
            }
        }
        Ok(None)
    }

    /// One sync round; returns its number.
    fn sync_now(&self) -> Result<u64> {
        self.signal.tip_dirty.store(false, Ordering::SeqCst);
        let round = {
            let mut i = self.st();
            i.round += 1;
            i.round
        };
        let live = self.live(&Call::new(Instant::now() + self.sync_deadline))?;
        let results = Self::each(&live, |c| self.sync_from(c, round));
        let mut i = self.st();
        let mut off_chain = Vec::new();
        for (c, r) in live.iter().zip(results) {
            match r {
                Ok(()) => {}
                Err(SyncFail::OffCheckpoint(e)) => {
                    i.flag(&c.url, format!("headers: {e}"));
                    off_chain.push(format!("{}: {e}", c.url));
                }
                Err(SyncFail::Other(e)) => i.flag(&c.url, format!("headers: {e}")),
            }
        }
        i.last_sync = Some(Instant::now());
        if i.headers.ready() {
            let Inner { headers, servers, .. } = &mut *i;
            for st in servers.values_mut() {
                if let (Some(t), Some(th)) = (st.tip, st.tip_hash.as_ref()) {
                    st.on_best_chain = Some(headers.at(t).map(|h| &h.hash_hex() == th).unwrap_or(false));
                }
            }
        } else if !off_chain.is_empty() {
            let cp = hex::encode(self.cp.1);
            return err(Kind::CheckpointMismatch, format!("no server is on the {} checkpoint {}:{}.. ({})",
                                                         self.chain, self.cp.0, &cp[..16], off_chain.join("; ")));
        }
        Ok(round)
    }

    /// Our tip, if the chain can be answered from.
    fn believable(&self) -> Result<u32> {
        let i = self.st();
        if !i.headers.ready() {
            return err(Kind::NotFound, "no Electrum server served the pinned checkpoint");
        }
        if let Some(why) = self.implausible(&i) {
            return err(Kind::Implausible, format!("the verified chain is not believable yet: {why}"));
        }
        Ok(i.tip_height())
    }

    fn implausible(&self, i: &Inner) -> Option<String> {
        let p = self.plausibility.as_ref()?;
        i.headers.implausible(p.min_work_above, Some((p.floor_spacing_s, p.floor_slack)))
    }

    /// `until`: the sync round's deadline, when the call is part of one.
    /// A request of one server's part of a sync round. `until` is that server's own deadline, so
    /// when it cuts a request short the server is hung up on, as at a timeout: this part of the
    /// round ends here whatever it is still sending, and what it still owes would hold the next
    /// round's requests on the same connection. (A call's deadline is shared by every server, and
    /// a request it cuts short hangs up on nobody: `Connection::batch_until`.)
    fn sync_batch(c: &Connection, reqs: &[(String, Value)], until: Option<Instant>) -> Result<Vec<Result<Value>>> {
        c.batch_until(reqs, until).inspect_err(|e| {
            if e.kind == Kind::Deadline {
                c.close();
            }
        })
    }

    fn header_at(&self, c: &Connection, height: u32, until: Option<Instant>) -> std::result::Result<header::Header, SyncFail> {
        let asked = Self::sync_batch(c, &[("blockchain.block.header".to_string(), json!([height]))], until).and_then(|mut r| r.pop().expect("one answer per request"));
        let v = asked.map_err(|e| {
            self.flag(&c.url, format!("blockchain.block.header: {e}"));
            e
        })?;
        let raw = hex::decode(v.as_str().unwrap_or("")).map_err(|_| SyncFail::Other("block.header: not hex".into()))?;
        let h = parse_header(&raw)?;
        if h.height != height {
            return Err(SyncFail::Other(format!("block.header {height} commits height {}", h.height)));
        }
        Ok(h)
    }

    /// The checkpoint header and the headers below it that the median-time rule needs.
    fn fetch_checkpoint(&self, c: &Connection) -> std::result::Result<(), SyncFail> {
        let off = |e: String| SyncFail::OffCheckpoint(e);
        let (cp, n) = (self.cp.0, self.st().headers.prior_needed());
        let raw = match self.header_at(c, cp, None) {
            Ok(h) => h.raw,
            Err(SyncFail::Other(e)) | Err(SyncFail::OffCheckpoint(e)) => return Err(off(e)),
        };
        let mut prior: Vec<Vec<u8>> = Vec::new();
        if n > 0 {
            let a = self.ask(c, "blockchain.block.headers", json!([cp - n, n])).map_err(|e| off(e.msg))?;
            let blob = hex::decode(a.get("hex").and_then(Value::as_str).unwrap_or("")).map_err(|_| off("block.headers: not hex".into()))?;
            prior = split_headers(&blob).map_err(|e| off(e.to_string()))?.into_iter().map(<[u8]>::to_vec).collect();
        }
        let mut i = self.st();
        if !i.headers.ready() {
            i.headers.set_checkpoint(&raw, &prior).map_err(|e| off(e.to_string()))?;
        }
        Ok(())
    }

    fn sync_from(&self, c: &Connection, round: u64) -> std::result::Result<(), SyncFail> {
        // this server's part of the round ends here, whatever it is still sending (AGP-081, review E1)
        let until = Instant::now() + self.sync_deadline;
        let late = |at: u32| SyncFail::Other(format!("sync deadline ({:?}) reached at height {at}: the headers it proved are kept", self.sync_deadline));
        let tip = c.subscribe("blockchain.headers.subscribe", json!([])).map_err(|e| {
            // A server that refuses its tip is of no use on this connection, and the refusal can be
            // the connection's: electrs negotiates protocol 1.4 until it has indexed a v2 header and
            // then refuses headers to that client for good. Hang up; the next round negotiates again.
            if e.kind == Kind::Server {
                c.close();
            }
            SyncFail::Other(e.msg)
        })?;
        let th = tip.get("height").and_then(Value::as_u64).and_then(|h| u32::try_from(h).ok())
            .ok_or_else(|| SyncFail::Other("headers.subscribe: no height".into()))?;
        let tip_raw = hex::decode(tip.get("hex").and_then(Value::as_str).unwrap_or(""))
            .map_err(|_| SyncFail::Other("headers.subscribe: not hex".into()))?;
        let tip_h = parse_header(&tip_raw)?;
        {
            let mut i = self.st();
            let st = i.servers.entry(c.url.clone()).or_default();
            st.tip = Some(th);
            st.tip_hash = Some(tip_h.hash_hex());
            i.tip_round.insert(c.url.clone(), round);
        }
        let cp = self.cp.0;
        if th < cp {
            return Err(SyncFail::OffCheckpoint(format!("server tip {th} is below the checkpoint {cp}")));
        }
        if tip_h.height != th {
            return Err(SyncFail::Other(format!("tip at {th} commits height {}", tip_h.height)));
        }
        let ready = self.st().headers.ready();
        header::check_pow(&tip_h, &self.rules).map_err(|e| {
            // before we hold a chain, a tip outside our powLimit is another chain
            let why = format!("tip at {th}: {e}");
            if ready { SyncFail::Other(why) } else { SyncFail::OffCheckpoint(why) }
        })?;
        if !ready {
            self.fetch_checkpoint(c)?;
        }
        let (ours, our_time, on_ours) = {
            let i = self.st();
            let t = i.headers.tip().map(|h| h.time as u64).unwrap_or(0);
            (i.tip_height(), t, i.headers.at(th).map(|h| h.hash == tip_h.hash).unwrap_or(false))
        };
        if on_ours {
            return Ok(());
        }
        let elapsed = (self.clock)().saturating_sub(our_time);
        let cap = self.tip_cap_spacing_s.map_or(u32::MAX, |s| {
            (ours as u64 + elapsed / s.max(1) + HEADERS_CHUNK as u64).min(u32::MAX as u64) as u32
        });
        let end = th.min(cap);
        if th > cap {
            self.flag(&c.url, format!("headers: claims tip {th}, beyond the plausible {cap}: nothing above it is fetched"));
        }
        // the highest height where the server agrees with us (the checkpoint at worst)
        let (mut h, mut step) = (end.min(ours), 1u32);
        while h > cp {
            if Instant::now() >= until {
                return Err(late(h));
            }
            let theirs = self.header_at(c, h, Some(until))?;
            if self.st().headers.at(h).map(|m| m.hash == theirs.hash).unwrap_or(false) {
                break;
            }
            h = h.saturating_sub(step).max(cp);
            step = step.saturating_mul(2);
        }
        let mut b = self.st().headers.branch(h)?;
        let mut start = h + 1;
        // why the fetch ended early; the headers proven before it are adopted either way
        let mut bad: Option<SyncFail> = None;
        'fetch: while start <= end {
            if Instant::now() >= until {
                bad = Some(late(start - 1));
                break;
            }
            let mut reqs = Vec::new();
            let mut s = start;
            while s <= end && (reqs.len() as u32) < CHUNKS_PER_BATCH {
                let n = HEADERS_CHUNK.min(end - s + 1);
                reqs.push(("blockchain.block.headers".to_string(), json!([s, n])));
                s += n;
            }
            let answers = match Self::sync_batch(c, &reqs, Some(until)) {
                Ok(a) => a,
                Err(e) => {
                    bad = Some(if Instant::now() >= until { late(start - 1) } else { SyncFail::Other(e.msg) });
                    break;
                }
            };
            for (a, (_, asked)) in answers.into_iter().zip(&reqs) {
                let blob = a.map_err(|e| format!("block.headers: {e}")).and_then(|a| {
                    hex::decode(a.get("hex").and_then(Value::as_str).unwrap_or("")).map_err(|_| "block.headers: not hex".to_string())
                });
                let chunk = match blob.as_deref().map_err(|e| SyncFail::Other(e.to_string())).and_then(|b| Ok(split_headers(b)?)) {
                    Ok(c) => c,
                    Err(e) => {
                        bad = Some(e);
                        break 'fetch;
                    }
                };
                let before = b.len();
                let r = b.extend(&chunk);
                start += (b.len() - before) as u32;
                if let Err(e) = r {
                    bad = Some(SyncFail::Other(format!("block.headers: {e} (the headers before it were kept)")));
                    break 'fetch;
                }
                if (chunk.len() as u64) < asked.get(1).and_then(Value::as_u64).unwrap_or(0) {
                    // Fewer than asked, all below the tip it claims: withheld, or trickled to hold the
                    // round. Keep what we have (most work still decides); it is flagged below.
                    break 'fetch;
                }
            }
        }
        if !b.is_empty() {
            self.st().headers.adopt(b)?;
        }
        if let Some(e) = bad {
            return Err(e);
        }
        if start <= end {
            // most work still decides; this server just cannot back the tip it claims
            return Err(SyncFail::Other(format!("withheld headers: served up to {}, claims tip {th}", start - 1)));
        }
        Ok(())
    }

    /// `(height, display hex)` of the pinned checkpoint.
    pub fn checkpoint(&self) -> (u32, String) {
        (self.cp.0, hex::encode(self.cp.1))
    }

    // --- verified transactions -----------------------------------------------------------------

    /// A raw tx counts only if it re-serializes byte for byte and hashes to the txid asked for.
    fn verify_raw(txid: &str, raw: &Value) -> Option<Tx> {
        let s = raw.as_str()?;
        let tx = Tx::parse_hex(s).ok()?;
        (tx.to_hex() == s.to_ascii_lowercase() && tx.txid() == txid).then_some(tx)
    }

    fn cached_tx(&self, txid: &str) -> Option<Tx> {
        self.st().txs.get(txid).cloned()
    }

    /// The transaction, from the cache or the first server that supplies it (all are asked at once).
    /// None only when every server asked said it has no such transaction; if one did not answer,
    /// whether it exists is not known and the call fails.
    fn fetch_tx(&self, call: &Call, txid: &str) -> Result<Option<Tx>> {
        let txid = txid.to_ascii_lowercase();
        if let Some(t) = self.cached_tx(&txid) {
            return Ok(Some(t));
        }
        let live = self.live(call)?;
        // one slot per server: no sender ever waits, whether or not we still listen
        let (send, answers) = sync_channel::<(Arc<Connection>, Result<Value>)>(live.len());
        let mut silent: Vec<String> = Vec::new();
        for c in &live {
            let (conn, send, id, until) = (c.clone(), send.clone(), txid.clone(), call.until());
            let asked = std::thread::Builder::new().name("electrum:get".into()).spawn(move || {
                let a = conn.batch_until(&[("blockchain.transaction.get".to_string(), json!([id]))], Some(until))
                    .and_then(|mut r| r.pop().expect("one answer per request"));
                let _ = send.send((conn, a));
            });
            if asked.is_err() {
                silent.push(c.url.clone());
            }
        }
        drop(send);
        for (c, a) in answers {
            match a {
                Ok(raw) => match Self::verify_raw(&txid, &raw) {
                    Some(tx) => {
                        self.st().cache_tx(txid, tx.clone());
                        return Ok(Some(tx));
                    }
                    // a lie is an answer: it shows that this server does not supply the transaction
                    None => self.flag(&c.url, format!("transaction.get {}: not the transaction asked for", &txid[..16.min(txid.len())])),
                },
                Err(e) if says_not_there(&e) => {}
                // the call ran out of time: no answer, and not the server's doing
                Err(e) if e.kind == Kind::Deadline => silent.push(c.url.clone()),
                Err(e) => {
                    self.flag(&c.url, format!("transaction.get: {e}"));
                    silent.push(c.url.clone());
                }
            }
        }
        if !silent.is_empty() || !self.all_answer(live.len()) {
            let down = self.conns.iter().filter(|c| !live.iter().any(|l| Arc::ptr_eq(l, c))).map(|c| c.url.clone());
            silent.extend(down);
            return err(Kind::Unreachable, format!("whether transaction {}.. exists is not known: no answer from {}",
                                                  &txid[..16.min(txid.len())], silent.join(", ")));
        }
        Ok(None)
    }

    /// Can `tx` not belong to the history of `spk` at all? It pays the script, or spends an output
    /// that does, and then the paying transaction is in the history too. `None`: a possible funder
    /// is listed and not held, so it cannot be told yet.
    fn invented(tx: &Tx, spk: &[u8], hist: &HashMap<String, Claims>, held: &TxCache) -> Option<bool> {
        if tx.outputs.iter().any(|o| o.script_pubkey == spk) {
            return Some(false);
        }
        let mut open = false;
        for inp in &tx.inputs {
            let funder = inp.prevout.txid_hex();
            if !hist.contains_key(&funder) {
                continue;
            }
            match held.get(&funder) {
                Some(f) if f.outputs.get(inp.prevout.vout as usize).is_some_and(|o| o.script_pubkey == spk) => return Some(false),
                Some(_) => {}
                None => open = true,
            }
        }
        (!open).then_some(true)
    }

    /// Fetch the transactions of `listed` that are not held, each from the servers that listed it,
    /// every server in parallel. A server's part ends at the first transaction it does not supply,
    /// at the first that cannot belong to `spk` (when given), and at the call's deadline; each ends
    /// with a flag. Returns the servers that went silent: what only they listed is not known.
    ///
    /// Why from the server that listed it: a transaction no server can supply used to be asked of
    /// every server, on every call, one timeout each (AGP-087: 41 hours for one `gettxout`).
    fn supply(&self, call: &Call, listed: &HashMap<String, Claims>, spk: Option<&[u8]>) -> Vec<String> {
        let mut work: Vec<(Arc<Connection>, Vec<String>)> = Vec::new();
        {
            let i = self.st();
            let mut txids: Vec<&String> = listed.keys().filter(|t| !i.txs.contains(t)).collect();
            txids.sort();
            for t in txids {
                for (c, _) in &listed[t] {
                    match work.iter_mut().find(|(w, _)| Arc::ptr_eq(w, c)) {
                        Some((_, list)) => list.push(t.clone()),
                        None => work.push((c.clone(), vec![t.clone()])),
                    }
                }
            }
        }
        let conns: Vec<Arc<Connection>> = work.iter().map(|(c, _)| c.clone()).collect();
        let ends = Self::each(&conns, |c| {
            let list = work.iter().find(|(w, _)| std::ptr::eq(Arc::as_ptr(w), c)).map(|(_, l)| l.as_slice()).unwrap_or(&[]);
            self.supply_from(call, c, list, listed, spk)
        });
        conns.iter().zip(ends).filter(|(_, e)| *e == Supplied::Silent).map(|(c, _)| c.url.clone()).collect()
    }

    fn supply_from(&self, call: &Call, c: &Connection, list: &[String], listed: &HashMap<String, Claims>, spk: Option<&[u8]>) -> Supplied {
        // one transaction first: a server that invents its list is found out for one request
        let (mut rest, mut size) = (list, 1);
        // Was this server asked for anything in this part? Only then is running into the call's
        // deadline flagged (a list too long, or supplied too slowly). A server whose part began
        // when the time was already used up was never asked, and is not flagged (AGP-097).
        let mut asked = false;
        while !rest.is_empty() {
            let (part, tail) = rest.split_at(size.min(rest.len()));
            (rest, size) = (tail, TX_BATCH);
            let want: Vec<&String> = {
                let i = self.st();
                part.iter().filter(|t| !i.txs.contains(t)).collect()
            };
            if want.is_empty() {
                continue;
            }
            let late = |left: usize| {
                self.flag(&c.url, format!("transaction.get: {left} of the transactions it listed were not supplied by the call deadline ({:?})",
                                          self.call_deadline));
                Supplied::Silent
            };
            if call.over() {
                return if asked { late(want.len() + rest.len()) } else { Supplied::Silent };
            }
            asked = true;
            let reqs: Vec<(String, Value)> = want.iter().map(|t| ("blockchain.transaction.get".to_string(), json!([t]))).collect();
            let answers = match c.batch_until(&reqs, Some(call.until())) {
                Ok(a) => a,
                Err(e) if e.kind == Kind::Deadline => return late(want.len() + rest.len()),
                Err(e) => {
                    self.flag(&c.url, format!("transaction.get: {e}"));
                    return Supplied::Silent;
                }
            };
            let mut i = self.st();
            for (t, a) in want.into_iter().zip(answers) {
                // The rule (AGP-092, kept here since AGP-106): only "I have no such transaction",
                // in the server's words, is an answer. Busy, rate-limited or a wording not known
                // here is no answer: the server went silent for what it listed, and a scan that
                // needs it fails instead of leaving the coin out.
                let raw = match a {
                    Ok(raw) => Some(raw),
                    Err(e) if says_not_there(&e) => None,
                    Err(e) => {
                        i.flag(&c.url, format!("transaction.get: {e}"));
                        return Supplied::Silent;
                    }
                };
                let Some(tx) = raw.and_then(|raw| Self::verify_raw(t, &raw)) else {
                    i.flag(&c.url, format!("lists a transaction it does not supply ({}..): the rest of its list is not asked for", &t[..16.min(t.len())]));
                    return Supplied::Lied;
                };
                if spk.is_some_and(|spk| Self::invented(&tx, spk, listed, &i.txs) == Some(true)) {
                    i.flag(&c.url, format!("get_history lists a transaction that neither pays nor spends the script ({}..): the rest of its list is not asked for",
                                           &t[..16.min(t.len())]));
                    return Supplied::Lied;
                }
                i.cache_tx(t.clone(), tx);
            }
        }
        Supplied::All
    }

    /// txid -> [(server, claimed height)], the union over every live server that answered with at
    /// most [`MAX_HISTORY`] entries, one claim per server and transaction. An error when none did:
    /// an empty history means the servers say there is none.
    fn history(&self, call: &Call, spk: &[u8]) -> Result<Hist> {
        let sh = scripthash(spk);
        let live = self.live(call)?;
        let answers = Self::each(&live, |c| {
            c.batch_until(&[("blockchain.scripthash.get_history".to_string(), json!([sh]))], Some(call.until()))
                .and_then(|mut r| r.pop().expect("one answer per request"))
        });
        let mut out: HashMap<String, Claims> = HashMap::new();
        let mut answered = 0;
        let mut i = self.st();
        for (c, a) in live.iter().zip(answers) {
            let hist = match a {
                Ok(h) => h,
                Err(e) if e.kind == Kind::Deadline => continue, // no answer, and not its doing
                Err(e) => {
                    i.flag(&c.url, format!("get_history: {e}"));
                    continue;
                }
            };
            let Some(hist) = hist.as_array().filter(|h| h.len() <= MAX_HISTORY) else {
                i.flag(&c.url, format!("get_history: not a list of at most {MAX_HISTORY} entries: its answer is not used"));
                continue;
            };
            answered += 1;
            let mut two_heights = false;
            for e in hist {
                match (e.get("tx_hash").and_then(Value::as_str), e.get("height").and_then(Value::as_i64)) {
                    (Some(t), Some(h)) if t.len() == 64 && t.chars().all(|x| x.is_ascii_hexdigit()) => {
                        let claims = out.entry(t.to_ascii_lowercase()).or_default();
                        // One claim per server and transaction. An honest server can list one twice (in
                        // its mempool and in a block, as a block arrives: electrs does), so a block
                        // height replaces a mempool entry and a repeat is dropped. A second block
                        // height is not a claim: each one used to cost a proof request, and a header
                        // sync when above our tip.
                        match claims.iter_mut().find(|(k, _)| Arc::ptr_eq(k, c)) {
                            None => claims.push((c.clone(), h)),
                            Some((_, had)) if *had <= 0 && h > 0 => *had = h,
                            Some((_, had)) if h > 0 && *had != h => two_heights = true,
                            Some(_) => {}
                        }
                    }
                    _ => i.flag(&c.url, "get_history: malformed entry"),
                }
            }
            if two_heights {
                i.flag(&c.url, "get_history lists a transaction at two heights: only the first is used");
            }
        }
        if answered == 0 {
            return err(Kind::Unreachable, "no server answered get_history");
        }
        Ok(Hist { claims: out, complete: self.all_answer(answered) })
    }

    /// Flag the servers behind history entries that were invented (AGP-081, review E1), judged from
    /// the transactions we hold ([`Self::invented`]): an entry whose possible funder is not held is
    /// left alone.
    fn flag_invented(&self, spk: &[u8], hist: &HashMap<String, Claims>) {
        let mut i = self.st();
        let mut liars: Vec<(String, String)> = Vec::new();
        for (t, claims) in hist {
            let Some(tx) = i.txs.get(t) else { continue };
            if Self::invented(tx, spk, hist, &i.txs) == Some(true) {
                liars.extend(claims.iter().map(|(c, _)| (c.url.clone(), t.clone())));
            }
        }
        liars.sort();
        liars.dedup_by(|a, b| a.0 == b.0); // one flag per server
        for (url, t) in liars {
            i.flag(&url, format!("get_history lists a transaction that neither pays nor spends the script ({}..)", &t[..16.min(t.len())]));
        }
    }

    /// A cached proof, if its block is still on our best chain (dropped if it was reorged out).
    fn cached_conf(&self, txid: &str) -> Option<TxStatus> {
        let mut i = self.st();
        let c = i.conf.get(txid).copied()?;
        if i.conf_holds(&c) {
            return Some(TxStatus::Confirmed { height: c.0, block_hash: c.1 });
        }
        i.conf.remove(txid);
        None
    }

    /// Does the server's `get_merkle` answer tie the transaction to our header at `height`?
    fn proves(txid: &[u8; 32], hdr: &header::Header, height: u32, m: &Value) -> std::result::Result<(), String> {
        let branch: Option<Vec<[u8; 32]>> = m.get("merkle").and_then(Value::as_array).and_then(|a| {
            a.iter().map(|x| x.as_str().and_then(|s| hex32(s).ok())).collect()
        });
        let (Some(branch), Some(pos)) = (branch, m.get("pos").and_then(Value::as_u64)) else { return Err("malformed".into()) };
        let root = merkle_root_from_proof(txid, &branch, pos, Some(hdr.txcount as u32)).map_err(|e| e.to_string())?;
        let bh = m.get("block_height").and_then(Value::as_u64).unwrap_or(height as u64);
        if root != hdr.merkle_root || bh != height as u64 {
            return Err("proof does not reach our header".into());
        }
        Ok(())
    }

    /// Ask every server, in one batch each and all servers at once, for the proofs of the claims it
    /// made about `items` at heights we hold a header for, and keep those that hold. Nothing is
    /// judged here: a claim this leaves unproven is asked for again, judged and flagged by
    /// [`Self::confirmed`], one request at a time.
    ///
    /// Why (AGP-097): a scan proved its coins one request after another, each from the first
    /// server that claimed it. With N coins that is N round trips to one server inside one call
    /// deadline, so a server that answers every request well inside the timeout still used the
    /// deadline up, and the scan of an address with many coins failed.
    fn prove_ahead(&self, call: &Call, items: &[(&String, &Claims)]) {
        let mut work: Vec<(Arc<Connection>, Vec<ProofAsk>)> = Vec::new();
        {
            let i = self.st();
            for (txid, claims) in items {
                if i.conf.get(*txid).is_some_and(|c| i.conf_holds(c)) {
                    continue;
                }
                for (c, height) in claims.iter() {
                    let Some((h, hdr)) = u32::try_from(*height).ok().filter(|h| *h > 0).and_then(|h| Some((h, i.headers.at(h)?))) else { continue };
                    let ask = ((*txid).clone(), h, hdr.clone());
                    match work.iter_mut().find(|(w, _)| Arc::ptr_eq(w, c)) {
                        Some((_, list)) => list.push(ask),
                        None => work.push((c.clone(), vec![ask])),
                    }
                }
            }
        }
        let conns: Vec<Arc<Connection>> = work.iter().map(|(c, _)| c.clone()).collect();
        Self::each(&conns, |c| {
            let list = work.iter().find(|(w, _)| std::ptr::eq(Arc::as_ptr(w), c)).map(|(_, l)| l.as_slice()).unwrap_or(&[]);
            for part in list.chunks(TX_BATCH) {
                // proven by another server meanwhile: not asked for again
                let want: Vec<&ProofAsk> = {
                    let i = self.st();
                    part.iter().filter(|(t, _, _)| !i.conf.contains_key(t)).collect()
                };
                if want.is_empty() {
                    continue;
                }
                if call.over() {
                    return;
                }
                let reqs: Vec<(String, Value)> = want.iter().map(|(t, h, _)| ("blockchain.transaction.get_merkle".to_string(), json!([t, h]))).collect();
                let Ok(answers) = c.batch_until(&reqs, Some(call.until())) else { return };
                let mut i = self.st();
                for ((t, h, hdr), a) in want.into_iter().zip(answers) {
                    let held = hex32(t).ok().zip(a.ok()).is_some_and(|(id, m)| Self::proves(&id, hdr, *h, &m).is_ok());
                    // kept only with its transaction, as everywhere (`cache_tx` drops them together)
                    if held && i.txs.contains(t) && i.conf_holds(&(*h, hdr.hash)) {
                        i.conf.insert(t.clone(), (*h, hdr.hash));
                    }
                }
            }
        });
    }

    /// Confirmed once a Merkle proof ties `txid` to our header at a claimed height; Mempool if only
    /// mempool claims remain; no status if no claim holds. `checked` is false when a claim could not
    /// be judged: its server did not answer for it, or it names a block we do not hold after the
    /// call's one forced sync.
    fn confirmed(&self, call: &Call, txid: &str, claims: &[(Arc<Connection>, i64)]) -> Result<Proof> {
        if let Some(st) = self.cached_conf(txid) {
            return Ok(Proof { status: Some(st), checked: true });
        }
        let txid_b = hex32(txid).map_err(|e| ElectrumError::new(Kind::BadRequest, e.to_string()))?;
        let (mut mempool, mut checked) = (false, true);
        for (c, height) in claims {
            if *height <= 0 {
                mempool = true;
                continue;
            }
            let Ok(height) = u32::try_from(*height) else {
                self.flag(&c.url, format!("get_history: a height of {height} for {}..", &txid[..16]));
                continue;
            };
            let mut hdr = self.st().headers.at(height).cloned();
            if hdr.is_none() && !call.synced.swap(true, Ordering::SeqCst) {
                let began = Instant::now();
                let ran = self.sync_round(true);
                call.give_back(began.elapsed());
                let ran = ran?;
                self.believable()?;
                call.round.store(ran.unwrap_or(0), Ordering::SeqCst);
                hdr = self.st().headers.at(height).cloned();
            }
            let Some(hdr) = hdr else {
                // The rule (AGP-097): a claim is a lie only against a tip the server reported after
                // it made the claim. That is a tip it reported in the round this call forced, or
                // in a later one. When the forced sync found another in flight and ran nothing, or
                // the server did not report its tip in our round, the tip we hold for it is older
                // than its claim: a block may have come in between (both servers then list it,
                // truthfully). That is "not known", never "above the tip it reports". Before, the
                // old tip was used, the claim was called a lie and the lookup answered "not there".
                let ours = call.round.load(Ordering::SeqCst);
                let own_tip = {
                    let i = self.st();
                    let fresh = ours != 0 && i.tip_round.get(&c.url).is_some_and(|r| *r >= ours);
                    i.servers.get(&c.url).and_then(|s| s.tip).filter(|_| fresh)
                };
                // above the tip it then reported it is a lie; at or below, a block we could not
                // fetch: not known
                if own_tip.is_some_and(|t| height > t) {
                    self.flag(&c.url, format!("get_history: {}.. at height {height}, above the tip it reports", &txid[..16]));
                } else {
                    checked = false;
                }
                continue;
            };
            if call.over() {
                checked = false;
                continue;
            }
            let asked = c.batch_until(&[("blockchain.transaction.get_merkle".to_string(), json!([txid, height]))], Some(call.until()))
                .and_then(|mut r| r.pop().expect("one answer per request"));
            let m = match asked {
                Ok(m) => m,
                Err(e) if e.kind == Kind::Deadline => {
                    checked = false; // the call ran out of time: unjudged, and not its doing
                    continue;
                }
                Err(e) => {
                    self.flag(&c.url, format!("blockchain.transaction.get_merkle: {e}"));
                    // "not in that block", in its own words, withdraws its claim; busy, gone or silent
                    // leaves the claim unjudged
                    checked &= says_not_there(&e);
                    continue;
                }
            };
            if let Err(why) = Self::proves(&txid_b, &hdr, height, &m) {
                self.flag(&c.url, format!("get_merkle {}@{height}: {why}", &txid[..16]));
                continue;
            }
            let mut i = self.st();
            if !i.conf_holds(&(height, hdr.hash)) {
                checked = false; // reorged out while we asked
                continue;
            }
            i.conf.insert(txid.to_string(), (height, hdr.hash));
            return Ok(Proof { status: Some(TxStatus::Confirmed { height, block_hash: hdr.hash }), checked: true });
        }
        Ok(Proof { status: mempool.then_some(TxStatus::Mempool), checked })
    }

    /// Scripts whose history lists this tx: its outputs (OP_RETURN has no history).
    fn index_spks(tx: &Tx) -> Vec<Vec<u8>> {
        tx.outputs.iter().filter(|o| !o.script_pubkey.is_empty() && o.script_pubkey[0] != 0x6A)
            .take(2).map(|o| o.script_pubkey.clone()).collect()
    }

    fn locate(&self, call: &Call, txid: &str) -> Result<Located> {
        let txid = txid.to_ascii_lowercase();
        let Some(tx) = self.fetch_tx(call, &txid)? else { return Ok(Located { tx: None, status: None, complete: true }) };
        if let Some(st) = self.cached_conf(&txid) {
            return Ok(Located { tx: Some(tx), status: Some(st), complete: true });
        }
        let mut complete = true;
        for spk in Self::index_spks(&tx) {
            let hist = self.history(call, &spk)?;
            complete &= hist.complete;
            if let Some(claims) = hist.claims.get(&txid) {
                let p = self.confirmed(call, &txid, claims)?;
                let proven = matches!(p.status, Some(TxStatus::Confirmed { .. }));
                return Ok(Located { tx: Some(tx), status: p.status, complete: proven || (complete && p.checked) });
            }
        }
        Ok(Located { tx: Some(tx), status: None, complete })
    }

    /// The one error for "a server did not answer, so this is not known".
    fn unknown<T>(txid: &str, what: &str) -> Result<T> {
        err(Kind::Unreachable, format!("{what} {}.. is not known: a server did not answer for it (see the verification failures)",
                                       &txid[..16.min(txid.len())]))
    }

    /// The union of the servers' histories of `spk`, with the transactions it lists fetched and
    /// the invented ones flagged: what the search for a spend reads. One round of requests for a
    /// script, however many of its outputs are then looked at.
    fn spends(&self, call: &Call, spk: &[u8]) -> Result<HashMap<String, Claims>> {
        let hist = self.history(call, spk)?.claims;
        self.supply(call, &hist, Some(spk));
        self.flag_invented(spk, &hist);
        Ok(hist)
    }

    /// (spending txid, its status) from the union of the script's histories ([`Self::spends`]): the
    /// spend parsed from the spending transaction itself. A mempool spend is returned only with
    /// `mempool`.
    ///
    /// This search does not wait for every server (see the module docs): a spend that only a silent
    /// server lists, or whose proof went unanswered, is not reported. Were it an error, one server
    /// could hold a refund back by listing a spend and never proving it.
    fn spender(&self, call: &Call, hist: &HashMap<String, Claims>, txid: &str, vout: u32, mempool: bool) -> Result<Option<(String, TxStatus)>> {
        let mut others: Vec<&String> = hist.keys().filter(|t| t.as_str() != txid).collect();
        others.sort();
        let mut found = None;
        for t in others {
            let Some(stx) = self.cached_tx(t) else { continue }; // not supplied: its server is flagged
            if !stx.inputs.iter().any(|i| i.prevout.txid_hex() == txid && i.prevout.vout == vout) {
                continue;
            }
            match self.confirmed(call, t, &hist[t])?.status {
                Some(st @ TxStatus::Confirmed { .. }) => return Ok(Some((t.clone(), st))),
                Some(TxStatus::Mempool) if mempool => found = Some((t.clone(), TxStatus::Mempool)),
                _ => {}
            }
        }
        Ok(found)
    }

    // --- the typed API -------------------------------------------------------------------------

    pub fn block_count(&self) -> Result<u32> {
        self.sync(false)
    }

    /// Our header at `height` (display hex hash).
    pub fn block_hash(&self, height: u32) -> Result<String> {
        let tip = self.sync(false)?;
        self.st().headers.at(height).map(|h| h.hash_hex()).ok_or_else(|| {
            ElectrumError::new(Kind::NotFound, format!("Block height {height} out of range (verified chain {}..{tip})", self.cp.0))
        })
    }

    /// The transaction and where it is. None if every server asked says it has no such transaction,
    /// or none lists it in a block or a mempool. An error if one of them did not answer.
    pub fn transaction(&self, txid: &str) -> Result<Option<(Tx, TxStatus)>> {
        self.sync(false)?;
        let l = self.locate(&self.budget(), txid)?;
        match (l.tx, l.status) {
            (Some(tx), Some(st)) => Ok(Some((tx, st))),
            (Some(_), None) if !l.complete => Self::unknown(txid, "where transaction"),
            _ => Ok(None),
        }
    }

    /// `gettxout`. An output counts as spent only when a confirmed spend is proven: a spend seen
    /// only in a mempool never hides it (so a lying server cannot talk a payer out of a refund).
    ///
    /// None means one of: a confirmed spend is proven; the transaction has no such output; every
    /// server asked says there is no such transaction, or none lists it; it is unconfirmed and
    /// `include_mempool` is off. When a server did not answer, the last three are not known and the
    /// call fails instead (AGP-092: None used to cover "nobody answered", which callers read as spent).
    pub fn tx_out(&self, txid: &str, vout: u32, include_mempool: bool) -> Result<Option<TxOutInfo>> {
        let txid = txid.to_ascii_lowercase();
        self.sync(false)?;
        let call = self.budget();
        let l = self.locate(&call, &txid)?;
        let Some(tx) = l.tx else { return Ok(None) };
        let Some(out) = tx.outputs.get(vout as usize).cloned() else { return Ok(None) };
        let st = match l.status {
            Some(st) if st != TxStatus::Mempool || include_mempool => st,
            _ if !l.complete => return Self::unknown(&txid, "whether a block holds transaction"),
            _ => return Ok(None),
        };
        let hist = self.spends(&call, &out.script_pubkey)?;
        if self.spender(&call, &hist, &txid, vout, false)?.is_some() {
            return Ok(None);
        }
        let i = self.st();
        let tip = i.tip_height();
        let confirmations = match st {
            TxStatus::Confirmed { height, .. } => (tip + 1).saturating_sub(height),
            TxStatus::Mempool => 0,
        };
        Ok(Some(TxOutInfo {
            best_block: i.headers.tip().map(|h| h.hash_hex()).unwrap_or_default(),
            confirmations,
            value: out.value.max(0) as u64,
            script_pubkey: out.script_pubkey,
            coinbase: is_coinbase(&tx),
        }))
    }

    /// `gettxspendingprevout` for one outpoint: the spending txid, mempool spends included (a
    /// hint for the watcher; [`Self::tx_out`] is what decides).
    pub fn spending_tx(&self, txid: &str, vout: u32) -> Result<Option<(String, TxStatus)>> {
        let txid = txid.to_ascii_lowercase();
        self.sync(false)?;
        let call = self.budget();
        let Some(tx) = self.fetch_tx(&call, &txid)? else { return Ok(None) };
        let Some(out) = tx.outputs.get(vout as usize) else { return Ok(None) };
        let hist = self.spends(&call, &out.script_pubkey)?;
        self.spender(&call, &hist, &txid, vout, true)
    }

    /// Broadcast to every live server. Ok once one accepts it (and answers with its txid).
    pub fn broadcast(&self, hex_tx: &str) -> Result<String> {
        let tx = Tx::parse_hex(hex_tx).map_err(|e| ElectrumError::new(Kind::BadRequest, format!("TX decode failed: {e}")))?;
        let txid = tx.txid();
        let live = self.live(&self.budget())?;
        let answers = Self::each(&live, |c| c.request("blockchain.transaction.broadcast", json!([hex_tx])));
        let (mut errors, mut accepted) = (Vec::new(), false);
        let mut i = self.st();
        for (c, a) in live.iter().zip(answers) {
            match a {
                Ok(v) if v.as_str().map(str::to_ascii_lowercase).as_deref() == Some(txid.as_str()) => accepted = true,
                Ok(_) => i.flag(&c.url, "broadcast answered another txid"),
                Err(e) => errors.push(e),
            }
        }
        if !accepted {
            // every server refused it: the node's reason, as sendrawtransaction gives it
            return Err(errors.into_iter().next().unwrap_or_else(|| ElectrumError::new(Kind::Server, "no server accepted the transaction")));
        }
        i.cache_tx(txid.clone(), tx);
        Ok(txid)
    }

    /// `scantxoutset raw(spk)`: the script's confirmed, proven, unspent coins, from the union of
    /// every server's unspent list. A coin a server lists is left out only on an answer: the server
    /// does not supply its transaction, the output does not pay the script, the claims about it were
    /// checked and none is a proof, or a confirmed spend is proven. If the server went silent
    /// instead, the call fails: a shorter list would read as "no such coin".
    pub fn unspent(&self, spk: &[u8]) -> Result<Vec<Utxo>> {
        Ok(self.unspent_marked(spk)?.0)
    }

    /// [`Self::unspent`], and whether every configured server answered the listing. Every coin
    /// listed is proven either way; without it a coin that is not listed may be one only the missing
    /// server shows. (The shorter list is marked rather than refused: a scan that failed whenever
    /// one server was down would leave a wallet without its coins.)
    ///
    /// The rule (AGP-097): **what a scan asks a server for does not grow with the number of coins
    /// beyond what each coin needs once.** The call's deadline covers the whole scan, and anyone
    /// can add coins to an address by paying it dust. So the script's history, which every coin's
    /// search for a spend reads, is asked for once for the scan ([`Self::spends`]), and the coins'
    /// proofs are asked for in one batch per server ([`Self::prove_ahead`]). Before, every server
    /// was asked for the whole history once per coin and the proofs came one request at a time:
    /// with 20 coins, one honest server a quarter of the timeout late made every scan fail.
    pub fn unspent_marked(&self, spk: &[u8]) -> Result<(Vec<Utxo>, bool)> {
        self.sync(false)?;
        let call = self.budget();
        let sh = scripthash(spk);
        let live = self.live(&call)?;
        let answers = Self::each(&live, |c| {
            c.batch_until(&[("blockchain.scripthash.listunspent".to_string(), json!([sh]))], Some(call.until()))
                .and_then(|mut r| r.pop().expect("one answer per request"))
        });
        let mut claims: HashMap<(String, u32), Claims> = HashMap::new();
        let complete;
        {
            let mut answered = 0;
            let mut i = self.st();
            for (c, a) in live.iter().zip(answers) {
                let list = match a {
                    Ok(l) => l,
                    Err(e) if e.kind == Kind::Deadline => continue,
                    Err(e) => {
                        i.flag(&c.url, format!("listunspent: {e}"));
                        continue;
                    }
                };
                let Some(list) = list.as_array().filter(|l| l.len() <= MAX_HISTORY) else {
                    i.flag(&c.url, format!("listunspent: not a list of at most {MAX_HISTORY} entries: its answer is not used"));
                    continue;
                };
                answered += 1;
                for u in list {
                    match (u.get("tx_hash").and_then(Value::as_str), u.get("tx_pos").and_then(Value::as_u64), u.get("height").and_then(Value::as_i64)) {
                        (Some(t), Some(n), Some(h)) if t.len() == 64 && n <= u32::MAX as u64 => {
                            let cl = claims.entry((t.to_ascii_lowercase(), n as u32)).or_default();
                            if !cl.iter().any(|(k, _)| Arc::ptr_eq(k, c)) {
                                cl.push((c.clone(), h));
                            }
                        }
                        _ => i.flag(&c.url, "listunspent: malformed entry"),
                    }
                }
            }
            if answered == 0 {
                // an empty list means the servers say the script holds nothing
                return err(Kind::Unreachable, "no server answered listunspent");
            }
            complete = self.all_answer(answered);
        }
        let mut keys: Vec<(String, u32)> = claims.keys().cloned().collect();
        keys.sort();
        // who listed each transaction (whatever the output), for `supply`
        let mut listed: HashMap<String, Claims> = HashMap::new();
        for ((t, _), cl) in &claims {
            let all = listed.entry(t.clone()).or_default();
            for (c, h) in cl {
                if !all.iter().any(|(k, _)| Arc::ptr_eq(k, c)) {
                    all.push((c.clone(), *h));
                }
            }
        }
        let silent = self.supply(&call, &listed, None);
        // the proofs of the coins whose transaction we hold and whose output pays the script
        let mut txids: Vec<&String> = listed.keys().collect();
        txids.sort();
        let ahead: Vec<(&String, &Claims)> = {
            let i = self.st();
            txids.into_iter().filter(|t| i.txs.contains(t)).map(|t| (t, &listed[t])).collect()
        };
        self.prove_ahead(&call, &ahead);
        // the script's history, for the search for a spend: asked for once, when a coin needs it
        let mut hist: Option<HashMap<String, Claims>> = None;
        let mut out = Vec::new();
        for (txid, n) in keys {
            let cl = &claims[&(txid.clone(), n)];
            let Some(tx) = self.cached_tx(&txid) else {
                if listed[&txid].iter().any(|(c, _)| silent.contains(&c.url)) {
                    return Self::unknown(&txid, "whether the script holds a coin of transaction");
                }
                continue; // every server that listed it was asked and did not supply it (flagged)
            };
            match tx.outputs.get(n as usize) {
                Some(o) if o.script_pubkey == spk => {}
                _ => {
                    let mut i = self.st();
                    for (c, _) in cl {
                        i.flag(&c.url, "listunspent lists an output that does not pay the script");
                    }
                    continue;
                }
            }
            let p = self.confirmed(&call, &txid, cl)?;
            let Some(TxStatus::Confirmed { height, block_hash }) = p.status else {
                if !p.checked {
                    return Self::unknown(&txid, "whether a block holds transaction");
                }
                continue; // the UTXO set holds confirmed coins only
            };
            let hist = match &hist {
                Some(h) => h,
                None => hist.insert(self.spends(&call, spk)?),
            };
            if self.spender(&call, hist, &txid, n, false)?.is_some() {
                continue;
            }
            out.push(Utxo { txid, vout: n, value: tx.outputs[n as usize].value.max(0) as u64, script_pubkey: spk.to_vec(), height,
                           block_hash: hex::encode(block_hash), coinbase: is_coinbase(&tx) });
        }
        Ok((out, complete))
    }

    /// Unverifiable: the median of the servers' answers.
    pub fn estimate_fee(&self, blocks: u32) -> Result<FeeEstimate> {
        let live = self.live(&self.budget())?;
        let answers = Self::each(&live, |c| c.request("blockchain.estimatefee", json!([blocks])));
        let mut fees = Vec::new();
        let mut any = false;
        let mut i = self.st();
        for (c, a) in live.iter().zip(answers) {
            match a.map(|v| v.as_f64()) {
                Ok(Some(f)) if f.is_finite() => {
                    any = true;
                    if f > 0.0 {
                        fees.push(f);
                    }
                }
                Ok(_) => i.flag(&c.url, "estimatefee: not a number"),
                Err(e) => i.flag(&c.url, format!("estimatefee: {e}")),
            }
        }
        if !any {
            return err(Kind::Unreachable, "no server answered estimatefee");
        }
        fees.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
        let feerate = match fees.len() {
            0 => None,
            n if n % 2 == 1 => Some(fees[n / 2]),
            n => Some((fees[n / 2 - 1] + fees[n / 2]) / 2.0),
        };
        Ok(FeeEstimate { feerate, blocks, answers: fees })
    }

    // --- subscriptions (a watcher wakes on them) -------------------------------------------------

    /// Subscribe every live server to these scripts: a change (a close, a refund, a funding
    /// confirming) wakes [`Self::wait_for_change`]. Returns how many scripts are watched.
    pub fn watch(&self, spks: &[&[u8]]) -> Result<usize> {
        let new: Vec<String> = {
            let i = self.st();
            spks.iter().map(|s| scripthash(s)).filter(|sh| !i.watched.contains(sh)).collect()
        };
        if !new.is_empty() {
            let reqs: Vec<(String, Value)> = new.iter().map(|sh| ("blockchain.scripthash.subscribe".to_string(), json!([sh]))).collect();
            let call = self.budget();
            let until = Some(call.until());
            let live = self.live(&call)?;
            let answers = Self::each(&live, |c| c.subscribe_many(&reqs, until));
            let mut i = self.st();
            for (c, a) in live.iter().zip(answers) {
                match a {
                    Ok(rs) => {
                        for r in rs {
                            if let Err(e) = r {
                                i.flag(&c.url, format!("subscribe: {e}"));
                            }
                        }
                    }
                    Err(e) => i.flag(&c.url, format!("subscribe: {e}")),
                }
            }
            i.watched.extend(new);
        }
        Ok(self.st().watched.len())
    }

    /// Block until a subscribed script or the tip changes, or `timeout`. True if something did.
    pub fn wait_for_change(&self, timeout: Duration) -> bool {
        let g = lock(&self.signal.changed);
        let (mut g, _) = self.signal.cv.wait_timeout_while(g, timeout, |c| !*c).unwrap_or_else(|p| p.into_inner());
        std::mem::replace(&mut *g, false)
    }

    /// Checkpoint, tip, tip age, whether the chain is believable yet (and why not), each server's tip
    /// and whether it is on our best chain, errors, the scripts watched and the last verification failures.
    pub fn status(&self) -> Value {
        let i = self.st();
        let (cp_h, cp) = self.cp;
        let tip = i.headers.tip();
        let tip_age = tip.map(|t| now_s().saturating_sub(t.time as u64));
        let servers: Vec<Value> = self.conns.iter().map(|c| {
            let st = i.servers.get(&c.url).cloned().unwrap_or_default();
            json!({"url": c.url, "connected": c.connected(), "server": st.server, "proto": st.proto, "tip": st.tip,
                   "tip_hash": st.tip_hash, "on_best_chain": st.on_best_chain, "errors": st.errors, "last_error": st.last_error})
        }).collect();
        let flags: Vec<Value> = i.flags.iter().rev().take(10).rev()
            .map(|f| json!({"server": f.server, "reason": f.reason, "t": f.t})).collect();
        let implausible = if i.headers.ready() { self.implausible(&i) } else { None };
        json!({"backend": "electrum", "chain": self.chain, "checkpoint": [cp_h, hex::encode(cp)],
               "tip": tip.map(|_| i.tip_height()), "tip_hash": tip.map(|t| t.hash_hex()), "tip_age_s": tip_age,
               "tip_stale": tip_age.map(|a| self.chain == "main" && a > STALE_TIP_S).unwrap_or(false),
               "implausible": implausible,
               "min_servers": self.min_servers, "watched_scripts": i.watched.len(), "servers": servers,
               "verification_failures": flags})
    }

    /// Every verification failure so far (at most the last 50).
    pub fn flags(&self) -> Vec<Flag> {
        self.st().flags.iter().cloned().collect()
    }

    pub fn close(&self) {
        for c in &self.conns {
            c.close();
        }
    }

    // --- the node-RPC surface (B2's `call`) ------------------------------------------------------

    fn address(&self, spk: &[u8]) -> Option<String> {
        let segwit = matches!(spk.len(), 22 | 34) && matches!(spk[0], 0x00 | 0x51) && spk[1] as usize == spk.len() - 2;
        if segwit { segwit_address(self.hrp, spk).ok() } else { None }
    }

    fn spk_json(&self, spk: &[u8]) -> Value {
        let mut m = Map::new();
        m.insert("hex".into(), hex::encode(spk).into());
        if let Some(a) = self.address(spk) {
            m.insert("address".into(), a.into());
        }
        Value::Object(m)
    }

    fn verbose(&self, tx: &Tx, st: TxStatus, tip: u32) -> Value {
        let cb = is_coinbase(tx);
        let vin: Vec<Value> = tx.inputs.iter().map(|i| if cb {
            json!({"coinbase": hex::encode(&i.script_sig)})
        } else {
            let mut v = json!({"txid": i.prevout.txid_hex(), "vout": i.prevout.vout,
                               "scriptSig": {"hex": hex::encode(&i.script_sig)}, "sequence": i.sequence});
            if !i.witness.is_empty() {
                v["txinwitness"] = i.witness.iter().map(hex::encode).collect::<Vec<_>>().into();
            }
            v
        }).collect();
        let vout: Vec<Value> = tx.outputs.iter().enumerate().map(|(n, o)| {
            json!({"n": n, "value": o.value as f64 / SATS, "scriptPubKey": self.spk_json(&o.script_pubkey)})
        }).collect();
        let mut d = json!({"txid": tx.txid(), "hex": tx.to_hex(), "vin": vin, "vout": vout});
        match st {
            TxStatus::Confirmed { height, block_hash } => {
                d["blockhash"] = hex::encode(block_hash).into();
                d["height"] = height.into();
                d["confirmations"] = (tip + 1).saturating_sub(height).into();
            }
            TxStatus::Mempool => d["confirmations"] = 0.into(),
        }
        d
    }

    /// The node RPCs of the client path, answered as the node answers them (B2's `ElectrumBackend.call`):
    /// getblockchaininfo, getblockcount, getblockhash, getblockheader, gettxout, gettxspendingprevout,
    /// getrawtransaction, sendrawtransaction, scantxoutset (raw descriptors), estimatesmartfee.
    /// Node-only RPCs (the wallet, blocks, mining) are refused with [`Kind::LightBackend`].
    pub fn call(&self, method: &str, params: &Value) -> Result<Value> {
        let m = method.to_ascii_lowercase();
        let p = params.as_array().cloned().unwrap_or_default();
        let arg = |k: usize| p.get(k).cloned().unwrap_or(Value::Null);
        let bad = |what: &str| ElectrumError::new(Kind::BadRequest, format!("{method}: {what}"));
        if NODE_ONLY.contains(&m.as_str()) {
            return err(Kind::LightBackend, format!("{method} needs a full node: not available on the light Electrum backend"));
        }
        match m.as_str() {
            "getblockchaininfo" => {
                let tip = self.sync(false)?;
                let hash = self.block_hash(tip)?;
                Ok(json!({"chain": self.chain, "blocks": tip, "headers": tip, "bestblockhash": hash,
                          "initialblockdownload": false, "pruned": true, "light": true, "backend": "electrum"}))
            }
            "getblockcount" => Ok(self.sync(false)?.into()),
            "getblockhash" => {
                let h = arg(0).as_u64().and_then(|h| u32::try_from(h).ok()).ok_or_else(|| bad("height"))?;
                Ok(self.block_hash(h)?.into())
            }
            "getblockheader" => {
                let hash = hex32(arg(0).as_str().unwrap_or("")).map_err(|_| bad("block hash"))?;
                let verbose = arg(1).as_bool().unwrap_or(true);
                self.sync(false)?;
                let i = self.st();
                let tip = i.tip_height();
                let height = i.headers.height_of(&hash).ok_or_else(|| ElectrumError::new(Kind::NotFound, "Block not found"))?;
                let h = i.headers.at(height).ok_or_else(|| ElectrumError::new(Kind::NotFound, "Block not found"))?;
                if !verbose {
                    return Ok(hex::encode(&h.raw).into());
                }
                let mut root = h.merkle_root;
                root.reverse();
                let mut d = json!({"hash": h.hash_hex(), "height": height, "confirmations": (tip + 1).saturating_sub(height), "time": h.time,
                                   "bits": format!("{:08x}", h.bits), "nTx": h.txcount, "merkleroot": hex::encode(root)});
                if let Some(prev) = height.checked_sub(1).and_then(|ph| i.headers.at(ph)) {
                    d["previousblockhash"] = prev.hash_hex().into();
                }
                Ok(d)
            }
            "gettxout" => {
                let txid = arg(0).as_str().ok_or_else(|| bad("txid"))?.to_string();
                let vout = arg(1).as_u64().and_then(|v| u32::try_from(v).ok()).ok_or_else(|| bad("vout"))?;
                let mempool = arg(2).as_bool().unwrap_or(true);
                Ok(match self.tx_out(&txid, vout, mempool)? {
                    None => Value::Null,
                    Some(o) => json!({"bestblock": o.best_block, "confirmations": o.confirmations, "value": o.value as f64 / SATS,
                                      "scriptPubKey": self.spk_json(&o.script_pubkey), "coinbase": o.coinbase}),
                })
            }
            "gettxspendingprevout" => {
                let mut res = Vec::new();
                for op in arg(0).as_array().cloned().unwrap_or_default() {
                    let txid = op.get("txid").and_then(Value::as_str).ok_or_else(|| bad("txid"))?.to_ascii_lowercase();
                    let vout = op.get("vout").and_then(Value::as_u64).and_then(|v| u32::try_from(v).ok()).ok_or_else(|| bad("vout"))?;
                    let mut row = json!({"txid": txid, "vout": vout});
                    // as the node answers it: the mempool only (a confirmed spend shows as a spent gettxout)
                    if let Some((sp, TxStatus::Mempool)) = self.spending_tx(&txid, vout)? {
                        row["spendingtxid"] = sp.into();
                    }
                    res.push(row);
                }
                Ok(Value::Array(res))
            }
            "getrawtransaction" => {
                let txid = arg(0).as_str().ok_or_else(|| bad("txid"))?.to_string();
                let verbose = match arg(1) {
                    Value::Bool(b) => b,
                    Value::Number(n) => n.as_u64().unwrap_or(0) > 0,
                    _ => false,
                };
                let Some((tx, st)) = self.transaction(&txid)? else {
                    return err(Kind::NotFound, "No such mempool or blockchain transaction");
                };
                if let Some(bh) = arg(2).as_str() {
                    let ok = matches!(st, TxStatus::Confirmed { block_hash, .. } if hex::encode(block_hash) == bh.to_ascii_lowercase());
                    if !ok {
                        return err(Kind::NotFound, "No such transaction found in the provided block");
                    }
                }
                if !verbose {
                    return Ok(tx.to_hex().into());
                }
                let tip = self.st().tip_height();
                Ok(self.verbose(&tx, st, tip))
            }
            "sendrawtransaction" => Ok(self.broadcast(arg(0).as_str().ok_or_else(|| bad("hex"))?)?.into()),
            "scantxoutset" => {
                if arg(0).as_str() != Some("start") {
                    return Err(bad("only 'start'"));
                }
                let mut unspents = Vec::new();
                let (mut total, mut complete) = (0u64, true);
                for desc in arg(1).as_array().cloned().unwrap_or_default() {
                    let d = desc.as_str().map(str::to_string)
                        .or_else(|| desc.get("desc").and_then(Value::as_str).map(str::to_string)).unwrap_or_default();
                    let spk = d.strip_prefix("raw(").and_then(|r| r.strip_suffix(')')).and_then(|h| hex::decode(h).ok())
                        .ok_or_else(|| bad(&format!("the light backend takes raw(<script>) descriptors, not {d:?}")))?;
                    let (coins, every) = self.unspent_marked(&spk)?;
                    complete &= every;
                    for u in coins {
                        // u64 over values a block can hold (any i64 each): proven coins that sum
                        // past it are refused, not added up (AGP-097; it was a panic)
                        total = total.checked_add(u.value).ok_or_else(|| ElectrumError::new(
                            Kind::Implausible, "scantxoutset: the proven coins' values sum past 2^64-1 sats: no total can be given"))?;
                        unspents.push(json!({"txid": u.txid, "vout": u.vout, "scriptPubKey": hex::encode(&u.script_pubkey), "desc": d,
                                             "amount": u.value as f64 / SATS, "coinbase": u.coinbase, "height": u.height,
                                             "blockhash": u.block_hash}));
                    }
                }
                let i = self.st();
                Ok(json!({"success": true, "height": i.tip_height(), "bestblock": i.headers.tip().map(|h| h.hash_hex()),
                          "unspents": unspents, "total_amount": total as f64 / SATS, "complete": complete}))
            }
            "estimatesmartfee" => {
                let blocks = arg(0).as_u64().unwrap_or(1).clamp(1, 1008) as u32;
                let f = self.estimate_fee(blocks)?;
                Ok(match f.feerate {
                    Some(r) => json!({"feerate": r, "blocks": blocks, "source": "electrum (unverified)", "servers": f.answers.len()}),
                    None => json!({"errors": ["Insufficient data or no feerate found"], "blocks": blocks}),
                })
            }
            _ => err(Kind::LightBackend, format!("{method} is not served by the light Electrum backend")),
        }
    }
}

impl ChainBackend for ElectrumBackend {
    fn block_count(&self) -> xbt402::Result<u32> {
        Ok(ElectrumBackend::block_count(self)?)
    }

    fn get_tx_out(&self, txid: &str, vout: u32, include_mempool: bool) -> xbt402::Result<Option<UtxoInfo>> {
        Ok(self.tx_out(txid, vout, include_mempool)?.map(|o| UtxoInfo {
            confirmations: o.confirmations,
            value: o.value,
            script_pubkey: o.script_pubkey,
            coinbase: o.coinbase,
        }))
    }

    fn send_raw_transaction(&self, hex: &str) -> xbt402::Result<String> {
        Ok(self.broadcast(hex)?)
    }

    fn has_transaction(&self, txid: &str) -> xbt402::Result<bool> {
        Ok(self.transaction(txid)?.is_some())
    }
}

#[cfg(test)]
mod tests {
    use xbt_primitives::tx::{OutPoint, TxIn, TxOut};

    use super::*;

    fn tx(n: u32, script_len: usize) -> Tx {
        Tx::new(2, vec![TxIn::new(OutPoint::new([7u8; 32], n), 0)], vec![TxOut::new(1, vec![0x51; script_len])], 0)
    }

    #[test]
    fn the_transaction_cache_drops_the_oldest_at_its_cap() {
        let size = tx(0, 100).serialize().len();
        let mut c = TxCache::new(3 * size);
        for n in 0..3 {
            assert!(c.insert(format!("t{n}"), tx(n, 100)).is_empty());
        }
        assert_eq!(c.insert("t1".into(), tx(1, 100)), Vec::<String>::new(), "held already");
        assert_eq!(c.insert("t3".into(), tx(3, 100)), ["t0"]);
        assert!(!c.contains("t0") && c.get("t3").is_some());
        // a larger one makes room for all of itself; one larger than the cache is not kept
        let big = tx(4, 100 + size - 2); // two more bytes of script length prefix
        assert_eq!(big.serialize().len(), 2 * size);
        assert_eq!(c.insert("big".into(), big), ["t1", "t2"]);
        assert!(c.insert("huge".into(), tx(5, 4 * size)).is_empty() && !c.contains("huge"));
        assert!(c.bytes <= c.max && c.map.len() == c.order.len());
        assert_eq!(c.bytes, c.map.values().map(|(_, n)| n).sum::<usize>());
    }
}
