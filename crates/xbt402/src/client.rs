//! The payer SDK: pays x402 `batch-settlement` (XBT channel) providers over any [`Transport`]. A port of B1
//! `XbtChannelClient`: it opens a channel on the first 402 (funding through a [`Wallet`] hook),
//! signs ever-increasing states (postpay: each call pays for the calls before it), authenticates
//! every request, checks every receipt, keeps the refund, closes cooperatively, buys hash-locked
//! deliverables and rolls a channel over.
//!
//! Budgets: per call (`max_price`), per channel (`capacity`), overall (`budget_sats`) and per day
//! (`daily_budget`).
//!
//! The channel book lives in memory unless a [`ClientLedger`] is injected ([`Client::with_ledger`],
//! AGP-035): then every paid call, close and rollover saves the channels it touched, and a new
//! process restores them. A provider [`Ledger`](crate::ledger::Ledger) and a client ledger are
//! independent values, so one process can sell (a [`Provider`](crate::provider::Provider)) and buy
//! (a [`Client`]) at once.
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use xbt_primitives::address::segwit_address;
use xbt_primitives::ecdsa;
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

use crate::channel::{channel_auth_key, ChannelParams, FeePayer, Payer, DERIVATION, DUST};
use crate::conditional::{decrypt, preimage_from_tx, ConditionalParams};
use crate::error::{fail, ChannelError, Result};
use crate::json::{py_int, py_str, py_u64, truthy};
use crate::provider::HttpResponse;
use crate::signer::StateSigner;
use crate::wire::*;

/// How the client talks HTTP. Header names in the response may be any case.
pub trait Transport: Send + Sync {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse>;
}

/// The only wallet hook: fund `address` with `sats`, return the funding outpoint (display txid,
/// vout). In production this is the B2 agent wallet (policy-checked), so the SDK never holds
/// funding keys.
pub trait Wallet: Send + Sync {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)>;

    /// Fund the channel `params` (unfunded) for the key issued for `origin` at `address`. A signer
    /// wallet checks the channel is its own before it pays (AGP-063 W3). Default: [`Wallet::fund`].
    fn fund_channel(&self, _origin: &str, _params: &ChannelParams, address: &str, sats: u64) -> Result<(String, u32)> {
        self.fund(address, sats)
    }

    /// Txids of the sends this wallet made to `address` (`listtransactions`): how a hub finds a
    /// funding whose `fund` call failed after it broadcast (AGP-045). Default: none known.
    fn wallet_sends_to(&self, _address: &str) -> Result<Vec<String>> {
        Ok(vec![])
    }

    /// The wallet's view of its send `txid` to `address` (`gettransaction`); None when it is not the
    /// wallet's or pays nothing to `address`. Default: none known.
    fn wallet_send(&self, _txid: &str, _address: &str) -> Result<Option<WalletSend>> {
        Ok(None)
    }
}

/// A send the wallet knows (AGP-045): its output to the address and whether it can still confirm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSend {
    pub txid: String,
    pub vout: u32,
    pub sats: u64,
    /// `gettransaction` confirmations: < 0 when the send conflicts with a confirmed tx.
    pub confirmations: i64,
    pub abandoned: bool,
}

impl WalletSend {
    /// Conflicted or abandoned: it never confirms.
    pub fn failed(&self) -> bool {
        self.confirmations < 0 || self.abandoned
    }
}

/// A new payer key: its pubkey, the local secret if the client holds it, the payer change spk.
type FreshKey = (Vec<u8>, Option<SecretKey>, Option<Vec<u8>>);

/// Client settings (the reference's constructor keywords).
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub network: String,
    pub capacity: u64,
    pub expiry_blocks: u32,
    /// Most blocks to expiry this client funds, whatever an offer asks for (AGP-090, review C2:
    /// [`offer_expiry_blocks`](crate::funding::offer_expiry_blocks)). An offer that needs more is
    /// refused before funding.
    pub max_expiry_blocks: u32,
    /// Most a call (or a conditional increment) may cost, in sats.
    pub max_price: u64,
    pub max_close_fee: u64,
    /// Total capacity this client may open.
    pub budget_sats: u64,
    /// Sats signed per 24 h (0 = no limit).
    pub daily_budget: u64,
}

impl ClientConfig {
    pub fn new(network: &str) -> Self {
        Self { network: network.into(), capacity: 200_000, expiry_blocks: 1_008,
               max_expiry_blocks: crate::funding::OWNER_MAX_EXPIRY_BLOCKS as u32, max_price: 1_000, max_close_fee: 2_000,
               budget_sats: 1_000_000, daily_budget: 0 }
    }
}

/// What an embedder adds to one paid call (AGP-059): its own request headers, and the cumulative
/// amount to sign when it meters the channel itself.
///
/// ```
/// # use xbt402::client::CallOpts;
/// let headers = [("X-CMP-Payer".to_string(), "…".to_string())];
/// let opts = CallOpts::new().headers(&headers).cum(1_234);
/// # let _ = opts;
/// ```
///
/// A chosen `cum` replaces only the amount [`Client`] would work out from its receipts; every
/// check still applies. It is refused below the last signed state (`bad_amount`: a state never
/// goes down), above the channel's capacity (`exhausted`), above the receipted spend plus one call
/// at the price pinned at open (`too_expensive`: the client never signs past what receipts show
/// plus the call it is making) and over the daily budget (`budget`). While it is under the
/// channel's minimum state and nothing is signed yet, the call goes out unsigned (cum 0): the
/// client never signs more than was asked.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct CallOpts<'a> {
    /// Sent with every request of the call (the first try and the paid retry after a 402). A
    /// `PAYMENT-SIGNATURE` header, an empty name or a CR/LF/NUL is refused (`bad_header`).
    pub headers: &'a [(String, String)],
    /// The cumulative sats to sign instead of the client's own amount.
    pub cum: Option<u64>,
}

impl<'a> CallOpts<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn headers(mut self, headers: &'a [(String, String)]) -> Self {
        self.headers = headers;
        self
    }

    pub fn cum(mut self, cum: u64) -> Self {
        self.cum = Some(cum);
        self
    }

    fn checked_headers(&self) -> Result<&'a [(String, String)]> {
        for (k, v) in self.headers {
            if k.is_empty() || k.eq_ignore_ascii_case("PAYMENT-SIGNATURE") || k.contains(['\r', '\n', '\0']) || v.contains(['\r', '\n', '\0']) {
                return fail("bad_header", format!("extra header {k:?} is not allowed"));
            }
        }
        Ok(self.headers)
    }
}

/// Called with (refund tx hex, expiry height).
pub type RefundHook = Box<dyn Fn(&str, u32) + Send + Sync>;

/// The chain tip, for channel expiries.
pub type HeightFn = Box<dyn Fn() -> Result<u32> + Send + Sync>;

/// A conditional call signed but not yet delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCond {
    pub hash: [u8; 32],
    pub cipher: Vec<u8>,
    pub amount: u64,
}

/// How far a channel's open has got (AGP-090, review C2). A channel is on the books, and in the
/// ledger, from the moment it has a key: the client used to keep it only once the provider had
/// answered the funded open, so a refusal or a lost answer dropped the only copy of the payer key
/// with the coins already in the channel's script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Stage {
    /// It has a key and terms. Its funding has not left, or the call that sends it has not
    /// answered, or the funded channel is not bound to its key yet (`refund_hex` is empty).
    Keyed,
    /// Funded and bound, the refund held (and handed to `on_refund`). The provider has not
    /// answered the funded open: the next request asks again, and nothing is funded again.
    /// A seller that never opens it leaves it here until its expiry: the embedder broadcasts
    /// `refund_hex` then, and removes the record from [`Client::channels`].
    Funded,
    /// The provider opened it: the only stage a state is signed in.
    #[default]
    Open,
}

impl Stage {
    fn as_str(self) -> &'static str {
        match self {
            Stage::Keyed => "keyed",
            Stage::Funded => "funded",
            Stage::Open => "open",
        }
    }
}

/// One channel to one origin.
#[derive(Debug, Clone)]
pub struct ClientChannel {
    pub payer: Payer,
    pub origin: String,
    /// The PaymentRequirements as received (echoed verbatim in PAYMENT-SIGNATURE).
    pub accepted: Value,
    pub refund_hex: String,
    pub auth_key: [u8; 32],
    /// Sat per call agreed at open: a 402 may not raise it mid-channel.
    pub price: u64,
    /// Charges adopted over the channel's life that no request of ours accounts for: at most one
    /// call (a request sent just before a crash, whose answer and count were both lost).
    pub slack_msat: u64,
    pub seq: u64,
    /// From the last verified receipt.
    pub spent_msat: u64,
    /// Our signature for `payer.signed`, resent until a receipt shows it arrived.
    pub last_sig: String,
    pub pending_cond: Option<PendingCond>,
    /// The provider's best cum per its last receipt.
    pub acked_cum: u64,
    pub receipts: Vec<Value>,
    pub stage: Stage,
    /// What the paid requests the provider has not answered may have cost: one quote each, added
    /// when a request leaves, taken off when the provider refuses it (a 402: not charged), cleared
    /// by a verified receipt (AGP-090, review T4). An answer lost on the way, or one refused for its
    /// receipt, leaves its request here: the provider may have served it, so its spent total may
    /// be ahead of ours by this much (and by what is left of `slack_msat`'s one call).
    pub unanswered_msat: u64,
    /// In [`Client::next_rolled`]: the id of the channel whose rollover pays this one. Every
    /// attempt to roll that channel over pays the same key.
    pub rolled_from: Option<String>,
}

/// Most unresolved records kept per origin: next channels of one channel's rollover attempts
/// ([`Client::next_rolled`]) and stale unfunded opens ([`Client::unfunded`]). Twice the signed
/// spends a provider keeps per channel (AGP-085), so an honest provider's bound is met first.
pub const MAX_KEPT: usize = 16;

/// Receipts kept per channel record in a [`ClientLedger`] (the newest; memory keeps them all).
pub const LEDGER_RECEIPTS: usize = 16;

impl ClientChannel {
    /// The channel's ledger record. A payer key held here is written as its secret (hex): keep
    /// such a ledger private, or let a signer hold the keys (`"key": "signer"`).
    pub fn to_json(&self) -> Value {
        let key = match self.payer.secret() {
            Some(sk) => hex::encode(sk.secret_bytes()),
            None => "signer".into(),
        };
        let pending = self.pending_cond.as_ref().map(|c| json!({"hash": hex::encode(c.hash), "cipher": hex::encode(&c.cipher), "amount": c.amount}));
        let from = self.receipts.len().saturating_sub(LEDGER_RECEIPTS);
        json!({"origin": self.origin, "params": self.payer.params.to_json(), "signed": self.payer.signed, "key": key,
               "accepted": self.accepted, "refund_hex": self.refund_hex, "auth_key": hex::encode(self.auth_key), "price": self.price,
               "slack_msat": self.slack_msat, "seq": self.seq, "spent_msat": self.spent_msat, "last_sig": self.last_sig,
               "pending_cond": pending, "acked_cum": self.acked_cum, "receipts": &self.receipts[from..],
               "stage": self.stage.as_str(), "unanswered_msat": self.unanswered_msat, "rolled_from": self.rolled_from})
    }

    /// Inverse of [`to_json`](Self::to_json). A `"signer"` record needs the signer that holds its
    /// key (the channel is already attached there).
    pub fn from_json(v: &Value, signer: Option<&Arc<dyn StateSigner>>) -> Result<Self> {
        let bad = |k: &str| ChannelError::new("ledger_error", format!("client channel record: {k}"));
        let s = |k: &str| v.get(k).and_then(Value::as_str).ok_or_else(|| bad(k));
        let n = |k: &str| v.get(k).and_then(Value::as_u64).ok_or_else(|| bad(k));
        let h = |x: &str, k: &str| hex::decode(x).map_err(|_| bad(k));
        let params = ChannelParams::from_json(v.get("params").ok_or_else(|| bad("params"))?)?;
        let mut payer = match s("key")? {
            "signer" => Payer::with_backend(params, signer.ok_or_else(|| ChannelError::new("no_signer", "this channel's key is in a signer: call with_signer before with_ledger"))?.clone()),
            k => Payer::new(params, SecretKey::from_slice(&h(k, "key")?).map_err(|_| bad("key"))?)?,
        };
        payer.signed = n("signed")?;
        let pending_cond = match v.get("pending_cond") {
            Some(Value::Null) | None => None,
            Some(c) => Some(PendingCond {
                hash: h(c.get("hash").and_then(Value::as_str).unwrap_or(""), "pending_cond.hash")?.try_into().map_err(|_| bad("pending_cond.hash"))?,
                cipher: h(c.get("cipher").and_then(Value::as_str).unwrap_or(""), "pending_cond.cipher")?,
                amount: c.get("amount").and_then(Value::as_u64).ok_or_else(|| bad("pending_cond.amount"))?,
            }),
        };
        Ok(Self {
            payer,
            origin: s("origin")?.into(),
            accepted: v.get("accepted").cloned().unwrap_or(Value::Null),
            refund_hex: s("refund_hex")?.into(),
            auth_key: h(s("auth_key")?, "auth_key")?.try_into().map_err(|_| bad("auth_key"))?,
            price: n("price")?,
            slack_msat: n("slack_msat")?,
            seq: n("seq")?,
            spent_msat: n("spent_msat")?,
            last_sig: s("last_sig")?.into(),
            pending_cond,
            acked_cum: n("acked_cum")?,
            receipts: v.get("receipts").and_then(Value::as_array).cloned().unwrap_or_default(),
            // a record from before AGP-090 has none of the three: it was written only for a channel
            // the provider had opened, after a receipt or a close, with no parent recorded
            stage: match v.get("stage").map(|s| s.as_str()) {
                None | Some(Some("open")) => Stage::Open,
                Some(Some("funded")) => Stage::Funded,
                Some(Some("keyed")) => Stage::Keyed,
                Some(_) => return Err(bad("stage")),
            },
            unanswered_msat: match v.get("unanswered_msat") {
                None => 0,
                Some(n) => n.as_u64().ok_or_else(|| bad("unanswered_msat"))?,
            },
            rolled_from: v.get("rolled_from").and_then(Value::as_str).map(str::to_string),
        })
    }
}

/// Where a [`Client`] keeps its channel book (AGP-035). Records are JSON under string keys:
/// `"book"` (the budget counters), `"chan <origin>"`, `"rolled <origin>"` (a channel replaced by
/// a rollover, until its successor is opened), `"next <origin>"` (the next channels of rollovers
/// this client signed) and `"unfunded <origin>"` (keys of opens whose funding call failed and that
/// are too old to fund now); `null` removes a key. Implement it over any store;
/// [`FileClientLedger`] and [`MemoryClientLedger`] are provided.
pub trait ClientLedger: Send + Sync {
    /// The latest record per key (no `null`s), in the order the keys were first saved.
    fn load(&self) -> Result<Vec<(String, Value)>>;
    /// Save these records together, durably before returning.
    fn save(&self, records: &[(String, Value)]) -> Result<()>;
}

/// A [`ClientLedger`] in memory (tests, or a caller that persists [`Client::channels`] itself).
#[derive(Debug, Default)]
pub struct MemoryClientLedger(Mutex<indexmap::IndexMap<String, Value>>);

impl ClientLedger for MemoryClientLedger {
    fn load(&self) -> Result<Vec<(String, Value)>> {
        Ok(self.0.lock().unwrap_or_else(|p| p.into_inner()).iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }

    fn save(&self, records: &[(String, Value)]) -> Result<()> {
        let mut m = self.0.lock().unwrap_or_else(|p| p.into_inner());
        for (k, v) in records {
            if v.is_null() {
                m.shift_remove(k);
            } else {
                m.insert(k.clone(), v.clone());
            }
        }
        Ok(())
    }
}

/// A [`ClientLedger`] file: JSON lines `{"k": key, "v": record}`, appended and fsynced per save,
/// replayed and compacted on open (like the provider's [`Ledger`](crate::ledger::Ledger)), and
/// compacted again (a fsynced rewrite, then an atomic rename) once the appended lines outgrow the
/// live records (AGP-044: a [`RoutePayer`](crate::route_client::RoutePayer) saves its meters per
/// call). Created mode 0600 on Unix: records of channels whose keys this client holds carry the
/// payer secret. Locked like the provider's ledger (review C5): a second opener of the same file
/// gets `ledger_locked`.
#[derive(Debug)]
pub struct FileClientLedger {
    path: PathBuf,
    inner: Mutex<LedgerFile>,
    _lock: crate::ledger::FileLock,
}

#[derive(Debug)]
struct LedgerFile {
    file: File,
    recs: indexmap::IndexMap<String, Value>,
    /// Bytes appended since the last compaction, and the size it left.
    appended: u64,
    compacted: u64,
}

/// Compact once this many bytes were appended and they are 4x the live records.
const COMPACT_AFTER: u64 = 1 << 20;

fn ledger_io(e: std::io::Error) -> ChannelError {
    ChannelError::new("ledger_error", e.to_string())
}

fn private_file(path: &Path, append: bool) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    if append {
        o.append(true).create(true);
    } else {
        o.write(true).create(true).truncate(true);
    }
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o.open(path)
}

fn replay(path: &Path) -> Result<indexmap::IndexMap<String, Value>> {
    let mut recs: indexmap::IndexMap<String, Value> = indexmap::IndexMap::new();
    if !path.exists() {
        return Ok(recs);
    }
    for line in BufReader::new(File::open(path).map_err(ledger_io)?).lines() {
        let Ok(line) = line else { break };
        let Ok(v) = crate::json::parse(&line) else { continue };  // a torn last line
        let (Some(k), Some(r)) = (v.get("k").and_then(Value::as_str), v.get("v")) else { continue };
        if r.is_null() {
            recs.shift_remove(k);
        } else {
            recs.insert(k.to_string(), r.clone());
        }
    }
    Ok(recs)
}

/// Rewrite `path` with just `recs` (tmp, fsync, rename, fsync the dir). Returns its size.
fn rewrite(path: &Path, recs: &indexmap::IndexMap<String, Value>) -> Result<u64> {
    let tmp = path.with_extension("tmp");
    let mut n = 0u64;
    {
        let mut f = private_file(&tmp, false).map_err(ledger_io)?;
        for (k, v) in recs {
            let line = format!("{}\n", crate::json::dumps_compact(&json!({"k": k, "v": v})));
            n += line.len() as u64;
            f.write_all(line.as_bytes()).map_err(ledger_io)?;
        }
        f.sync_all().map_err(ledger_io)?;
    }
    std::fs::rename(&tmp, path).map_err(ledger_io)?;
    if let Some(Ok(dir)) = path.parent().map(File::open) {
        let _ = dir.sync_all();
    }
    Ok(n)
}

impl FileClientLedger {
    /// Lock, replay and compact the log at `path` (created if missing).
    pub fn open(path: &Path) -> Result<Self> {
        let lock = crate::ledger::lock_ledger(path)?;
        let recs = replay(path)?;
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d).map_err(ledger_io)?;
        }
        let compacted = rewrite(path, &recs)?;
        let file = private_file(path, true).map_err(ledger_io)?;
        Ok(Self { path: path.to_path_buf(), inner: Mutex::new(LedgerFile { file, recs, appended: 0, compacted }), _lock: lock })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ClientLedger for FileClientLedger {
    fn load(&self) -> Result<Vec<(String, Value)>> {
        Ok(replay(&self.path)?.into_iter().collect())
    }

    fn save(&self, records: &[(String, Value)]) -> Result<()> {
        let mut buf = String::new();
        for (k, v) in records {
            buf.push_str(&crate::json::dumps_compact(&json!({"k": k, "v": v})));
            buf.push('\n');
        }
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.file.write_all(buf.as_bytes()).map_err(ledger_io)?;
        g.file.sync_data().map_err(ledger_io)?;
        for (k, v) in records {
            if v.is_null() {
                g.recs.shift_remove(k);
            } else {
                g.recs.insert(k.clone(), v.clone());
            }
        }
        g.appended += buf.len() as u64;
        if g.appended >= COMPACT_AFTER && g.appended >= 4 * g.compacted {
            // the saves above are durable already: a crash in here leaves the old file or the new one
            let size = rewrite(&self.path, &g.recs)?;
            g.file = private_file(&self.path, true).map_err(ledger_io)?;
            (g.appended, g.compacted) = (0, size);
        }
        Ok(())
    }
}

/// The payer SDK.
pub struct Client {
    pub cfg: ClientConfig,
    transport: Box<dyn Transport>,
    wallet: Box<dyn Wallet>,
    height: HeightFn,
    pub channels: HashMap<String, ClientChannel>,
    pub opened_sats: u64,
    pub day_spent: u64,
    day_start: u64,
    /// Called with (refund hex, expiry) for every channel opened: keep it, broadcast after expiry.
    pub on_refund: Option<RefundHook>,
    /// Channels replaced by a rollover, until their successor is opened at the provider.
    pub pending_rolled: HashMap<String, ClientChannel>,
    /// Rollovers this client signed whose next channel is not the live one yet, per origin (AGP-081,
    /// review C3). A record is saved before its request leaves, because the provider can broadcast
    /// the transaction while the reply is lost or an error. It holds the next channel's key and
    /// refund, or, with a signer, the params the signer binds it with once its node shows the
    /// rollover (`refund_hex` is empty until then). [`adopt_rolled`](Self::adopt_rolled) makes one
    /// the live channel; one whose transaction can no longer confirm is the embedder's to remove.
    pub next_rolled: HashMap<String, Vec<ClientChannel>>,
    /// Channels in [`Stage::Keyed`] whose funding call failed and whose expiry is now too near to
    /// fund, per origin (AGP-090). A wallet's `fund` can fail after it broadcast, so their keys are
    /// kept in case a funding to one of them shows up; at most [`MAX_KEPT`] per origin.
    pub unfunded: HashMap<String, Vec<ClientChannel>>,
    /// AGP-027: where the payer keys live (B2's signer). `None`: this client holds them.
    signer: Option<Arc<dyn StateSigner>>,
    /// AGP-035: where the channel book is saved. `None`: memory only.
    ledger: Option<Box<dyn ClientLedger>>,
    /// AGP-032: other schemes this client pays with, preferred over xbt-channel when offered.
    payers: Vec<Arc<dyn crate::scheme::SchemePayer>>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn random_secret() -> SecretKey {
    crate::signer::random_secret()
}

/// `("https://host:port", "/path?query")` of a URL, as the reference splits it.
pub fn split_url(url: &str) -> (String, String) {
    let parts: Vec<&str> = url.split('/').collect();
    let origin = parts[..parts.len().min(3)].join("/");
    let path = format!("/{}", if parts.len() > 3 { parts[3..].join("/") } else { String::new() });
    (origin, path)
}

fn header<'a>(r: &'a HttpResponse, name: &str) -> Option<&'a str> {
    r.header(name)
}

/// The PAYMENT-RESPONSE of the answer to a request that carried a payment (AGP-081, review T4c). A
/// success without one is refused: with the receipt stripped on the way, any body passed as the
/// paid answer. An answer of 400 or above may have none (the provider's own failures carry no
/// receipt): it goes back as it is and nothing is adopted from it.
fn paid_response(r: &HttpResponse) -> Result<Option<Value>> {
    match header(r, "PAYMENT-RESPONSE") {
        Some(h) => unb64json(h).map(Some),
        None if r.status < 400 => fail("bad_receipt", format!("paid call returned no receipt (HTTP {})", r.status)),
        None => Ok(None),
    }
}

fn ex_u64(ex: &Value, k: &str) -> Result<u64> {
    py_u64(ex.get(k)).ok_or_else(|| ChannelError::new("bad_offer", format!("extra.{k} missing")))
}

impl Client {
    pub fn new(cfg: ClientConfig, transport: Box<dyn Transport>, wallet: Box<dyn Wallet>,
               height: HeightFn) -> Self {
        Self { cfg, transport, wallet, height, channels: HashMap::new(), opened_sats: 0, day_spent: 0, day_start: now(), on_refund: None,
               pending_rolled: HashMap::new(), next_rolled: HashMap::new(), unfunded: HashMap::new(), signer: None, ledger: None, payers: vec![] }
    }

    /// Pay with another scheme (AGP-032, `xbt-work`) whenever a 402 offers it: it is preferred
    /// over opening or using a channel, and it checks the PAYMENT-RESPONSE of the calls it paid.
    pub fn with_payer(mut self, p: Arc<dyn crate::scheme::SchemePayer>) -> Self {
        self.payers.push(p);
        self
    }

    /// Keep the channel book in `ledger` (AGP-035): restore what it holds, then save the channels
    /// each paid call, close and rollover touches. Call [`with_signer`](Self::with_signer) first
    /// when the payer keys live in a signer.
    pub fn with_ledger(mut self, ledger: Box<dyn ClientLedger>) -> Result<Self> {
        for (k, v) in ledger.load()? {
            let n = |f: &str| v.get(f).and_then(Value::as_u64).unwrap_or(0);
            if k == "book" {
                (self.opened_sats, self.day_spent, self.day_start) = (n("opened_sats"), n("day_spent"), n("day_start"));
            } else if let Some(o) = k.strip_prefix("chan ") {
                self.channels.insert(o.to_string(), ClientChannel::from_json(&v, self.signer.as_ref())?);
            } else if let Some(o) = k.strip_prefix("rolled ") {
                self.pending_rolled.insert(o.to_string(), ClientChannel::from_json(&v, self.signer.as_ref())?);
            } else if let Some((next, o)) = k.strip_prefix("next ").map(|o| (true, o)).or_else(|| k.strip_prefix("unfunded ").map(|o| (false, o))) {
                let list = v.as_array().ok_or_else(|| ChannelError::new("ledger_error", "client channel list record: not a list"))?;
                let list = list.iter().map(|c| ClientChannel::from_json(c, self.signer.as_ref())).collect::<Result<Vec<_>>>()?;
                if next { &mut self.next_rolled } else { &mut self.unfunded }.insert(o.to_string(), list);
            }
        }
        self.ledger = Some(ledger);
        Ok(self)
    }

    /// Save the budget counters and `origin`'s channels (every channel when `None`) to the
    /// injected ledger; a no-op without one. The SDK calls it after each operation; call it after
    /// changing [`channels`](Self::channels) by hand.
    pub fn persist(&self, origin: Option<&str>) -> Result<()> {
        let Some(l) = &self.ledger else { return Ok(()) };
        let mut recs = vec![("book".to_string(), json!({"opened_sats": self.opened_sats, "day_spent": self.day_spent, "day_start": self.day_start}))];
        let rec = |c: Option<&ClientChannel>| c.map(ClientChannel::to_json).unwrap_or(Value::Null);
        let list = |l: &Vec<ClientChannel>| Value::Array(l.iter().map(ClientChannel::to_json).collect());
        match origin {
            Some(o) => {
                recs.push((format!("chan {o}"), rec(self.channels.get(o))));
                recs.push((format!("rolled {o}"), rec(self.pending_rolled.get(o))));
                recs.push((format!("next {o}"), self.next_rolled.get(o).map(list).unwrap_or(Value::Null)));
                recs.push((format!("unfunded {o}"), self.unfunded.get(o).map(list).unwrap_or(Value::Null)));
            }
            None => {
                recs.extend(self.channels.iter().map(|(o, c)| (format!("chan {o}"), c.to_json())));
                recs.extend(self.pending_rolled.iter().map(|(o, c)| (format!("rolled {o}"), c.to_json())));
                recs.extend(self.next_rolled.iter().map(|(o, l)| (format!("next {o}"), list(l))));
                recs.extend(self.unfunded.iter().map(|(o, l)| (format!("unfunded {o}"), list(l))));
            }
        }
        l.save(&recs)
    }

    /// Keep only the newest `keep` receipts per channel. A receipt is kept for every call (about
    /// 0.4 KB of JSON, more as a `Value`), so a long-lived payer with many origins trims them now
    /// and then.
    pub fn trim_receipts(&mut self, keep: usize) {
        for ch in self.channels.values_mut() {
            let n = ch.receipts.len().saturating_sub(keep);
            ch.receipts.drain(..n);
        }
    }

    /// Save after an operation on `origin`: the operation's own error wins over the ledger's.
    fn saved<T>(&self, origin: &str, r: Result<T>) -> Result<T> {
        let p = self.persist(Some(origin));
        let v = r?;
        p.map(|_| v)
    }

    /// Keep every payer key in `signer` (B2's signer process): the client asks it for keys,
    /// states, closes, refunds and request auth, and never holds a payer secret itself.
    pub fn with_signer(mut self, signer: Arc<dyn StateSigner>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// A payer key for a new channel to `key_origin`: (pubkey, the local secret if we hold it,
    /// the payer change spk the signer asks for).
    fn fresh_key(&self, key_origin: &str) -> Result<FreshKey> {
        match &self.signer {
            Some(s) => Ok((s.new_key(key_origin)?.to_vec(), None, s.payer_spk()?)),
            None => {
                let sk = random_secret();
                Ok((ecdsa::pubkey(&sk).to_vec(), Some(sk), None))
            }
        }
    }

    /// Bind a funded channel's key: (payer, refund hex, request-auth key; zero with a signer).
    fn bind_key(&self, key_origin: &str, p: ChannelParams, secret: Option<SecretKey>) -> Result<(Payer, String, [u8; 32])> {
        match (&self.signer, secret) {
            (Some(s), _) => {
                s.attach(key_origin, &p)?;
                let refund_hex = s.sign_refund(&p.channel_id())?;
                Ok((Payer::with_backend(p, s.clone()), refund_hex, [0u8; 32]))
            }
            (None, Some(sk)) => {
                let refund_hex = p.refund_tx(&sk, None, None)?.to_hex();
                let auth_key = channel_auth_key(&sk, &p.payee_pub)?;
                Ok((Payer::new(p, sk)?, refund_hex, auth_key))
            }
            (None, None) => fail("bad_key", "no payer key"),
        }
    }

    /// bech32 hrp for funding addresses on this client's network.
    pub fn hrp(&self) -> &'static str {
        if self.cfg.network == XBT_MAINNET { "bc" } else { "bcrt" }
    }

    fn post(&self, url: &str, obj: &Value) -> Result<Value> {
        let r = self.transport.request("POST", url, crate::json::dumps(obj).as_bytes(),
                                       &[("Content-Type".into(), "application/json".into())])?;
        let data: Value = crate::json::parse_slice(&r.body).map_err(|_| ChannelError::new("provider_error", format!("HTTP {} non-JSON", r.status)))?;
        if r.status != 200 {
            // the provider's words go in the message, never in the code an agent reports (L12)
            let code = data.get("error").and_then(Value::as_str).filter(|c| safe_code(c)).unwrap_or("provider_error");
            return fail(code, py_str(data.get("detail")));
        }
        Ok(data)
    }

    fn pick(&self, pr: &Value) -> Result<Value> {
        for acc in pr.get("accepts").and_then(Value::as_array).into_iter().flatten() {
            if scheme_accepted(acc.get("scheme").and_then(Value::as_str)) && acc.get("network").and_then(Value::as_str) == Some(&self.cfg.network) {
                let amount = py_u64(acc.get("amount")).ok_or_else(|| ChannelError::new("bad_offer", "amount"))?;
                if amount > self.cfg.max_price {
                    return fail("too_expensive", format!("{amount} sat > max {}", self.cfg.max_price));
                }
                let ex = acc.get("extra").cloned().unwrap_or(Value::Null);
                if ex_u64(&ex, "closeFeeSat")? > self.cfg.max_close_fee {
                    return fail("bad_offer", "closeFeeSat above our cap");
                }
                if let Some(fp) = ex.get("closeFeePayer") {
                    FeePayer::parse(fp.as_str().unwrap_or("")).map_err(|_| ChannelError::new("bad_offer", "unknown closeFeePayer"))?;
                }
                if ex.get("derivation").and_then(Value::as_str) != Some(DERIVATION) {
                    // before funding: never strand coins
                    return fail("bad_offer", format!("channel binding {}, this client speaks {DERIVATION:?} (payee key v2, request binding v2)", py_str(ex.get("derivation"))));
                }
                return Ok(acc.clone());
            }
        }
        fail("no_scheme", format!("no {SCHEME} offer on {}", self.cfg.network))
    }

    fn expiry_blocks(&self, ex: &Value) -> Result<u32> {
        let blocks = crate::funding::offer_expiry_blocks(ex, self.cfg.expiry_blocks as u64, self.cfg.max_expiry_blocks as u64)?;
        u32::try_from(blocks).map_err(|_| ChannelError::new("bad_offer", "expiry blocks"))
    }

    /// The height a channel opened now on `ex` expires at.
    fn expiry_height(&self, ex: &Value) -> Result<u32> {
        (self.height)()?.checked_add(self.expiry_blocks(ex)?).ok_or_else(|| ChannelError::new("bad_offer", "expiry height"))
    }

    /// What one call on `ch` may cost: the price pinned at open.
    fn quote(ch: &ClientChannel) -> u64 {
        if ch.price > 0 { ch.price } else { py_u64(ch.accepted.get("amount")).unwrap_or(0) }
    }

    /// Bring `origin`'s channel to [`Stage::Open`]. Every open goes through here (a plain call, a
    /// conditional call, a retry after any failure, a restart).
    ///
    /// The rule (AGP-090, review C2): a channel's key is on the books and in the ledger before its
    /// funding leaves, its refund before the provider is asked to open it, and an origin that has
    /// a channel on the books is never funded a second time. The client used to keep a channel
    /// only after the provider answered the funded open: a seller that said yes to the preflight
    /// and no to the open (or an answer lost on the way) left the coins in a script whose only
    /// payer key had been dropped, and every later call funded another channel.
    fn ensure_open(&mut self, origin: &str, acc: &Value) -> Result<()> {
        if !self.channels.contains_key(origin) {
            self.key_channel(origin, acc)?;
        }
        if self.channels[origin].stage == Stage::Keyed {
            self.fund_keyed(origin)?;
        }
        if self.channels[origin].stage == Stage::Funded {
            self.post_open(origin)?;
        }
        Ok(())
    }

    /// Terms, a key and the preflight for a new channel to `origin`, saved before anything is
    /// funded ([`Stage::Keyed`]).
    fn key_channel(&mut self, origin: &str, acc: &Value) -> Result<()> {
        let ex = acc.get("extra").cloned().unwrap_or(Value::Null);
        let fee_payer = FeePayer::parse(ex.get("closeFeePayer").and_then(Value::as_str).unwrap_or("payer"))?;
        let cap = self.cfg.capacity.max(ex_u64(&ex, "minCapacity")?);
        let max_cap = py_u64(ex.get("maxCapacity")).unwrap_or(cap);
        // checked: minCapacity is the seller's number
        if cap > max_cap || self.opened_sats.checked_add(cap).is_none_or(|t| t > self.cfg.budget_sats) {
            return fail("budget", "channel capacity outside provider range or our budget");
        }
        let expiry = self.expiry_height(&ex)?;
        let pay_to = hex::decode(acc.get("payTo").and_then(Value::as_str).unwrap_or("")).map_err(|_| ChannelError::new("bad_offer", "payTo"))?;
        let close_fee = ex_u64(&ex, "closeFeeSat")?;
        let open_url = Self::open_url(origin, acc)?;
        let (pubk, secret, payer_spk) = self.fresh_key(origin)?;
        let mut p = ChannelParams::derive(&pay_to, &pubk, expiry, close_fee, payer_spk, &self.cfg.network, fee_payer)?;
        p.capacity = cap;
        self.preflight(&open_url, &Self::open_terms(&p), fee_payer)?;
        let (payer, auth_key) = match (&self.signer, secret) {
            (Some(s), _) => (Payer::with_backend(p, s.clone()), [0u8; 32]),
            (None, Some(sk)) => {
                let auth_key = channel_auth_key(&sk, &p.payee_pub)?;
                (Payer::new(p, sk)?, auth_key)
            }
            (None, None) => return fail("bad_key", "no payer key"),
        };
        let price = py_u64(acc.get("amount")).unwrap_or(0);
        self.channels.insert(origin.into(), ClientChannel { payer, origin: origin.into(), accepted: acc.clone(), refund_hex: String::new(), auth_key, price,
                                                            slack_msat: 0, seq: 0, spent_msat: 0, last_sig: String::new(), pending_cond: None, acked_cum: 0,
                                                            receipts: vec![], stage: Stage::Keyed, unanswered_msat: 0, rolled_from: None });
        self.persist(Some(origin))
    }

    fn open_url(origin: &str, acc: &Value) -> Result<String> {
        crate::wire::seller_url(origin, acc.get("extra").and_then(|e| e.get("openUrl")).and_then(Value::as_str).unwrap_or(OPEN_PATH))
    }

    /// The `channel` object of an open request (the outpoint too, once `p` is funded).
    fn open_terms(p: &ChannelParams) -> Value {
        let mut c = json!({"capacity": p.capacity, "expiry": p.expiry, "payerPub": hex::encode(p.payer_pub),
                           "payerSpk": hex::encode(&p.payer_spk), "redeemScript": hex::encode(p.script())});
        if p.close_fee_payer != FeePayer::Payer {
            c["closeFeePayer"] = p.close_fee_payer.as_str().into();
        }
        if p.funding.is_some() {
            c["txid"] = p.funding_txid().into();
            c["vout"] = p.funding_vout().into();
        }
        c
    }

    /// Fund the [`Stage::Keyed`] channel of `origin` (unless an earlier call did), bind it to its
    /// key and hold its refund: [`Stage::Funded`], saved before the provider hears of the outpoint.
    fn fund_keyed(&mut self, origin: &str) -> Result<()> {
        let no = || ChannelError::code("no_channel");
        if self.channels.get(origin).ok_or_else(no)?.payer.params.funding.is_none() {
            let (p, ex) = {
                let ch = &self.channels[origin];
                (ch.payer.params.clone(), ch.accepted.get("extra").cloned().unwrap_or(Value::Null))
            };
            let addr = segwit_address(self.hrp(), &p.spk())?;
            // an earlier fund call may have failed after it broadcast: the wallet's own record of
            // a send to this script is used before anything is sent again
            let (txid, vout) = match self.wallet_send_to(&addr, p.capacity)? {
                Some(o) => o,
                None => {
                    if (p.expiry as u64) < ((self.height)()? as u64).saturating_add(crate::funding::offer_expiry_floor(&ex)?) {
                        // too near its expiry to open now. The key stays in the ledger, in case that
                        // earlier call did fund it, and the open starts again with a new key
                        return self.shelve_keyed(origin);
                    }
                    self.wallet.fund_channel(origin, &p, &addr, p.capacity)?
                }
            };
            let funded = p.with_funding(&txid, vout, self.channels[origin].payer.params.capacity)?;
            self.opened_sats = self.opened_sats.saturating_add(funded.capacity);
            self.channels.get_mut(origin).ok_or_else(no)?.payer.params = funded;
            self.persist(Some(origin))?;
        }
        let (p, secret) = {
            let ch = &self.channels[origin];
            (ch.payer.params.clone(), ch.payer.secret().copied())
        };
        let expiry = p.expiry;
        let (payer, refund_hex, auth_key) = self.bind_key(origin, p, secret)?;
        if let Some(cb) = &self.on_refund {
            cb(&refund_hex, expiry);
        }
        let ch = self.channels.get_mut(origin).ok_or_else(no)?;
        (ch.payer, ch.refund_hex, ch.auth_key, ch.stage) = (payer, refund_hex, auth_key, Stage::Funded);
        self.persist(Some(origin))
    }

    /// The live send of `sats` this wallet made to `address`, if it knows one.
    fn wallet_send_to(&self, address: &str, sats: u64) -> Result<Option<(String, u32)>> {
        for txid in self.wallet.wallet_sends_to(address)? {
            if let Some(w) = self.wallet.wallet_send(&txid, address)? {
                if !w.failed() && w.sats == sats {
                    return Ok(Some((w.txid, w.vout)));
                }
            }
        }
        Ok(None)
    }

    /// Move `origin`'s stale [`Stage::Keyed`] channel to [`unfunded`](Self::unfunded) and report
    /// the open as failed; the next call opens with a new key. A signer holds one issued key per
    /// origin and a new one would replace this one, so with a signer the record stays where it is
    /// until the embedder calls [`forget_unfunded`](Self::forget_unfunded).
    fn shelve_keyed(&mut self, origin: &str) -> Result<()> {
        let kept = self.unfunded.get(origin).map_or(0, Vec::len);
        if self.signer.is_some() || kept >= MAX_KEPT {
            return fail("open_unresolved", format!("an earlier open to {origin} never learned whether its funding was sent, and its channel is too near \
                                                    expiry to fund now: once the wallet shows no send to it, call forget_unfunded"));
        }
        if let Some(ch) = self.channels.remove(origin) {
            self.unfunded.entry(origin.to_string()).or_default().push(ch);
        }
        self.persist(Some(origin))?;
        fail("open_unresolved", format!("an earlier open to {origin} was too old to fund; its key is kept, and the next call opens a new channel"))
    }

    /// Drop the channels of `origin` that were never funded: the one in [`Stage::Keyed`] without
    /// an outpoint, and those in [`unfunded`](Self::unfunded). Call it only when the wallet shows
    /// no send to their scripts: their keys go with them. Returns how many were dropped.
    pub fn forget_unfunded(&mut self, origin: &str) -> Result<usize> {
        let mut n = self.unfunded.remove(origin).map_or(0, |l| l.len());
        if self.channels.get(origin).is_some_and(|c| c.stage == Stage::Keyed && c.payer.params.funding.is_none()) {
            self.channels.remove(origin);
            n += 1;
        }
        self.persist(Some(origin)).map(|_| n)
    }

    /// Ask the provider to open the [`Stage::Funded`] channel of `origin`. Asked again on every
    /// call until it answers: a provider that already has the channel (its first answer was lost)
    /// says `duplicate_channel`, which is the yes that never arrived.
    fn post_open(&mut self, origin: &str) -> Result<()> {
        let (url, req, fee_payer) = {
            let ch = self.channels.get(origin).ok_or_else(|| ChannelError::code("no_channel"))?;
            let p = &ch.payer.params;
            (Self::open_url(origin, &ch.accepted)?, json!({"x402Version": 2, "network": self.cfg.network, "channel": Self::open_terms(p)}), p.close_fee_payer)
        };
        match self.post(&url, &req) {
            Ok(r) if r.get("closeFeePayer").and_then(Value::as_str).unwrap_or("payer") != fee_payer.as_str() => {
                // a provider that did not take our terms would refuse every state we sign
                return fail("bad_fee_payer", "the provider opened the channel with another closeFeePayer");
            }
            Ok(_) => {}
            Err(e) if e.code == "duplicate_channel" => {}
            Err(e) => return Err(e),
        }
        if let Some(ch) = self.channels.get_mut(origin) {
            ch.stage = Stage::Open;
        }
        self.persist(Some(origin))
    }

    /// Ask the provider whether it opens a channel on exactly these terms before anything is funded
    /// (review C2): a refusal after funding locks the capacity until expiry. A provider from before
    /// the preflight answers `bad_request` (no outpoint), having passed the terms it checks before
    /// the outpoint: that alone lets the open go ahead.
    fn preflight(&self, open_url: &str, channel: &Value, fee_payer: FeePayer) -> Result<()> {
        let req = json!({"x402Version": 2, "network": self.cfg.network, "preflight": true, "channel": channel});
        match self.post(open_url, &req) {
            Ok(r) if r.get("preflight") != Some(&Value::Bool(true)) => fail("bad_open", "the provider did not answer the open preflight"),
            Ok(r) if r.get("closeFeePayer").and_then(Value::as_str).unwrap_or("payer") != fee_payer.as_str() => {
                fail("bad_fee_payer", "the provider would open the channel with another closeFeePayer")
            }
            Ok(_) => Ok(()),
            Err(e) if e.code == "bad_request" => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// `bind`: where the request goes, `origin + path` ([`request_digest_v2`]); a close's payload
    /// binds the empty request.
    fn auth(ch: &ClientChannel, pl: &mut Value, method: &str, bind: &str, body: &[u8]) -> Result<()> {
        crate::wire::no_fragment(bind)?;
        let req = request_digest_v2(method, bind, body);
        let sig = pl.get("sig").and_then(Value::as_str).map(str::to_string);
        let chan = py_str(pl.get("chan"));
        let a = match ch.payer.backend() {
            // with a signer the ECDH channel key never leaves it
            Some(b) => b.request_auth(&chan, pl.get("seq"), pl.get("cum"), sig.as_deref(), &req)?,
            None => request_auth(&ch.auth_key, &chan, pl.get("seq"), pl.get("cum"), sig.as_deref(), &req),
        };
        pl["auth"] = a.into();
        Ok(())
    }

    fn check_daily(&mut self, sats: u64) -> Result<()> {
        if self.cfg.daily_budget > 0 && now().saturating_sub(self.day_start) > 86_400 {
            self.day_spent = 0;
            self.day_start = now();
        }
        if self.cfg.daily_budget > 0 && self.day_spent + sats > self.cfg.daily_budget {
            return fail("budget", "daily budget exhausted");
        }
        Ok(())
    }

    /// `chosen`: the caller's cumulative amount (AGP-059, [`CallOpts::cum`]), bounded here.
    fn payload(&mut self, origin: &str, price: u64, method: &str, path: &str, body: &[u8], chosen: Option<u64>) -> Result<Value> {
        let ch = self.channels.get(origin).ok_or_else(|| ChannelError::code("no_channel"))?;
        if ch.stage != Stage::Open {
            // one choke point for every signature of a state: none before the provider opened it
            return fail("no_channel", "the channel is not open at the provider yet");
        }
        let billing = ch.accepted.get("extra").and_then(|e| e.get("billing")).and_then(Value::as_str).unwrap_or("postpay");
        let need_msat = ch.spent_msat + if billing == "prepay" { price * 1000 } else { 0 };
        let mut cum = need_msat.div_ceil(1000).max(ch.payer.signed);
        let pmin = ch.payer.params.min_amount();
        if cum > 0 && cum < pmin {
            cum = pmin;
        }
        if let Some(c) = chosen {
            let quote = Self::quote(ch);
            if c < ch.payer.signed {
                return fail("bad_amount", format!("cum {c} is below the last signed state {}", ch.payer.signed));
            }
            if c > ch.payer.params.max_amount() {
                return fail("exhausted", format!("cum {c} is above the channel's capacity for states {}", ch.payer.params.max_amount()));
            }
            let most = ch.spent_msat.div_ceil(1000).saturating_add(quote).max(ch.payer.signed);
            if c > most {
                return fail("too_expensive", format!("cum {c} is above the receipted spend plus one call ({most} sat)"));
            }
            // under the minimum state nothing is signed yet (c >= signed): never round the caller up
            cum = if c < pmin { 0 } else { c };
        }
        let delta = cum - ch.payer.signed;
        self.check_daily(delta)?;
        let ch = self.channels.get_mut(origin).ok_or_else(|| ChannelError::code("no_channel"))?;
        let remaining = ch.payer.params.max_amount() as i128 - ch.payer.signed.max(ch.spent_msat / 1000) as i128;
        if remaining < price as i128 && ch.payer.signed > 0 {
            return fail("exhausted", "channel low: roll it over (Client::rollover) or close and reopen");
        }
        ch.seq += 1;
        if !path.is_empty() {
            // a call (a close charges nothing): the provider may serve it whether or not its
            // answer reaches us, so its quote counts until a receipt says what was charged
            let quote_msat = Self::quote(ch).saturating_mul(1000);
            ch.unanswered_msat = ch.unanswered_msat.saturating_add(quote_msat);
        }
        let mut pl = json!({"chan": ch.payer.params.channel_id(), "seq": ch.seq, "cum": cum.to_string()});
        if cum > ch.payer.signed {
            if cum > ch.payer.params.max_amount() {
                return fail("exhausted", "channel capacity used up: close and reopen");
            }
            let sig = hex::encode(ch.payer.sign_state(cum)?);
            ch.last_sig = sig.clone();
            pl["sig"] = sig.into();
            self.day_spent += delta;
        } else if cum == ch.payer.signed && ch.payer.signed > ch.acked_cum && !ch.last_sig.is_empty() {
            pl["sig"] = ch.last_sig.clone().into();       // signed but not yet seen to arrive
        }
        let ch = &self.channels[origin];
        let bind = if path.is_empty() { String::new() } else { format!("{origin}{path}") };
        Self::auth(ch, &mut pl, method, &bind, body)?;
        Ok(pl)
    }

    fn signature_header(&mut self, origin: &str, method: &str, path: &str, body: &[u8], chosen: Option<u64>) -> Result<Vec<(String, String)>> {
        let accepted = self.channels[origin].accepted.clone();
        let price = py_u64(accepted.get("amount")).unwrap_or(0);
        let pl = self.payload(origin, price, method, path, body, chosen)?;
        Ok(vec![("PAYMENT-SIGNATURE".into(), b64json(&payment_payload(&accepted, &pl)))])
    }

    /// One paid HTTP request. Opens a channel on the first 402 from an origin.
    pub fn request(&mut self, method: &str, url: &str, body: &[u8]) -> Result<HttpResponse> {
        self.request_with(method, url, body, &CallOpts::new())
    }

    /// [`request`](Self::request) with the embedder's own headers and, when it meters the channel
    /// itself, the cumulative amount to sign (AGP-059). See [`CallOpts`] for the bounds.
    pub fn request_with(&mut self, method: &str, url: &str, body: &[u8], opts: &CallOpts<'_>) -> Result<HttpResponse> {
        let r = self.request_inner(method, url, body, opts);
        self.saved(&split_url(url).0, r)
    }

    fn request_inner(&mut self, method: &str, url: &str, body: &[u8], opts: &CallOpts<'_>) -> Result<HttpResponse> {
        crate::wire::no_fragment(url)?;
        let (origin, path) = split_url(url);
        let extra = opts.checked_headers()?;
        let with_extra = |mut h: Vec<(String, String)>| {
            h.extend_from_slice(extra);
            h
        };
        let mut hdrs = vec![];
        let mut used: Option<Arc<dyn crate::scheme::SchemePayer>> = None;
        for p in &self.payers {
            if let Some(h) = p.upfront(&origin, method, &path, body)? {
                hdrs = h;
                used = Some(p.clone());
                break;
            }
        }
        if used.is_none() && self.channels.get(&origin).is_some_and(|c| c.stage == Stage::Open) {
            hdrs = self.signature_header(&origin, method, &path, body, opts.cum)?;
        }
        // a payment went with the request: its answer is taken only with its receipt
        let mut paid = !hdrs.is_empty();
        let on_channel = paid && used.is_none();
        let mut r = self.transport.request(method, url, body, &with_extra(hdrs))?;
        if r.status == 402 {
            if on_channel {
                self.refused(&origin);
            }
            let pr = unb64json(header(&r, "PAYMENT-REQUIRED").ok_or_else(|| ChannelError::new("bad_offer", "402 without PAYMENT-REQUIRED"))?)?;
            let offered = |sc: &str| pr.get("accepts").and_then(Value::as_array).into_iter().flatten()
                .find(|a| a.get("scheme").and_then(Value::as_str) == Some(sc) && a.get("network").and_then(Value::as_str) == Some(&self.cfg.network))
                .cloned();
            if let Some((p, acc)) = self.payers.iter().find_map(|p| offered(p.scheme()).map(|a| (p.clone(), a))) {
                let h = p.answer(self.transport.as_ref(), &origin, &acc, &pr, method, &path, body)?;
                r = self.transport.request(method, url, body, &with_extra(h))?;
                if let Some(resp) = paid_response(&r)? {
                    p.check(&origin, &resp, method, &path, body)?;
                }
                return Ok(r);
            }
            used = None;
            let acc = self.pick(&pr)?;
            self.ensure_open(&origin, &acc)?;
            let ch = self.channels.get_mut(&origin).ok_or_else(|| ChannelError::code("no_channel"))?;
            let amount = py_u64(acc.get("amount")).unwrap_or(0);
            if ch.price > 0 && amount > ch.price {
                return fail("bad_offer", format!("price raised mid-channel: {} -> {amount} sat", ch.price));
            }
            ch.accepted = acc.clone();
            if let Some(chv) = pr.get("channel") {
                // The provider's view of what it charged, unsigned. It may be ahead of our receipts
                // by the requests it never answered, at one quote each (AGP-090, review T4), plus the
                // one call of slack a channel has over its life. The slack alone was the bound, so
                // a second lost answer ended the channel in bad_offer. A request it refused with a
                // 402 is not among them: a provider that serves nothing can claim nothing.
                let claimed = py_u64(chv.get("spentMsat")).unwrap_or(0);
                let extra = claimed.saturating_sub(ch.spent_msat);
                let unproven = extra.saturating_sub(ch.unanswered_msat);
                if unproven > 0 && ch.slack_msat.saturating_add(unproven) > amount.saturating_mul(1000) {
                    return fail("bad_offer", "provider claims charges we have no receipts for");
                }
                ch.unanswered_msat -= extra - unproven;
                ch.slack_msat += unproven;
                ch.spent_msat = ch.spent_msat.max(claimed);
            }
            let hdrs = self.signature_header(&origin, method, &path, body, opts.cum)?;
            r = self.transport.request(method, url, body, &with_extra(hdrs))?;
            if r.status == 402 {
                self.refused(&origin);
            }
            paid = true;
        }
        let resp = if paid { paid_response(&r)? } else { header(&r, "PAYMENT-RESPONSE").map(unb64json).transpose()? };
        if let Some(resp) = resp {
            match &used {
                Some(p) => p.check(&origin, &resp, method, &path, body)?,
                None => self.receipt(&origin, &resp, method, &path, body, (r.status, &r.body), None)?,
            }
        }
        Ok(r)
    }

    /// The provider answered the paid request just sent on `origin`'s channel with a 402: by its
    /// own word it did not charge it.
    fn refused(&mut self, origin: &str) {
        if let Some(ch) = self.channels.get_mut(origin) {
            ch.unanswered_msat = ch.unanswered_msat.saturating_sub(Self::quote(ch).saturating_mul(1000));
        }
    }

    /// Check a PAYMENT-RESPONSE against what we signed and were quoted, and against the answer it
    /// came with (`answer`: status and body), and adopt it. `quote`: what this call may cost (the
    /// price pinned at open, or a conditional amount).
    #[allow(clippy::too_many_arguments)]
    fn receipt(&mut self, origin: &str, resp: &Value, method: &str, path: &str, body: &[u8], answer: (u16, &[u8]),
               quote: Option<u64>) -> Result<()> {
        let network = self.cfg.network.clone();
        let ch = self.channels.get_mut(origin).ok_or_else(|| ChannelError::code("no_channel"))?;
        let pinned = Self::quote(ch);
        let quote = quote.filter(|q| *q > 0).unwrap_or(pinned);
        let r = receipt_of(resp)?.clone();
        if resp.get("network").and_then(Value::as_str) != Some(network.as_str())
            || resp.get("payer").and_then(Value::as_str) != Some(hex::encode(ch.payer.params.payer_pub).as_str())
        {
            return fail("bad_receipt", "PAYMENT-RESPONSE is for another network or payer");
        }
        if py_str(r.get("req")) != request_digest_v2(method, &format!("{origin}{path}"), body) {
            return fail("bad_receipt", "receipt is for another request");
        }
        if py_int(r.get("seq")) != Some(ch.seq as i128) {
            // The receipt of the request we just sent, and of no other (AGP-090, review T4): an
            // identical earlier request has the same digest, so whoever sits between could answer
            // this one with the earlier answer and its genuine receipt.
            return fail("bad_receipt", format!("receipt is for seq {}, this call was seq {}", py_str(r.get("seq")), ch.seq));
        }
        // An answer that has no body by its framing (to a HEAD, or a 204 or 304) is checked on its
        // status: the receipt's bodyHash is of the body the provider did not send (AGP-090).
        let bodiless = answer.1.is_empty() && (method.eq_ignore_ascii_case("HEAD") || matches!(answer.0, 204 | 304));
        if r.get("status").and_then(Value::as_u64) != Some(answer.0 as u64) || (!bodiless && py_str(r.get("bodyHash")) != body_hash(answer.1)) {
            // a truncated or altered answer is not the one the provider signed for
            return fail("bad_receipt", "receipt is for another answer (status or body differs)");
        }
        let sig = hex::decode(py_str(r.get("sig"))).unwrap_or_default();
        if !ecdsa::verify(&ch.payer.params.payee_pub, &receipt_message(&r), &sig) {
            return fail("bad_receipt", "receipt not signed by the channel payee key");
        }
        let (rcum, charged, spent) = (py_int(r.get("cum")).unwrap_or(-1), py_int(r.get("charged")).unwrap_or(-1), py_int(r.get("spentMsat")).unwrap_or(-1));
        if rcum < 0 || charged < 0 || spent < 0 {
            return fail("bad_receipt", "receipt amounts are not non-negative integers");
        }
        if rcum > ch.payer.signed as i128 || charged > quote as i128 {
            return fail("bad_receipt", "provider claims more than we signed or were quoted");
        }
        // The spent total may have grown, since the last receipt we verified, by one quote for each
        // request the provider has not answered: this one and those whose answers were lost on the
        // way (AGP-090, review T4), plus what is left of the channel's one call of slack. It was held
        // to one call, so after one lost answer every later receipt was refused and the provider
        // went on charging for answers the payer threw away. A lost answer is paid for once, like
        // the call it answered; a request the provider refused is not paid for at all.
        let unproven = spent - ch.spent_msat as i128 - ch.unanswered_msat as i128;
        if unproven > 0 && ch.slack_msat as i128 + unproven > pinned as i128 * 1000 {
            return fail("bad_receipt", "provider charged more than the calls we sent");
        }
        let Ok(spent) = u64::try_from(spent) else { return fail("bad_receipt", "receipt amounts are out of range") };
        ch.slack_msat += u64::try_from(unproven).unwrap_or(0);
        ch.spent_msat = spent;
        ch.unanswered_msat = 0;
        ch.acked_cum = ch.acked_cum.max(rcum as u64);
        ch.receipts.push(r);
        Ok(())
    }

    /// Cooperative close; in postpay the final state pays exactly what is owed.
    pub fn close(&mut self, origin: &str) -> Result<Value> {
        self.close_with(origin, &CallOpts::new())
    }

    /// [`close`](Self::close) whose final state is the caller's cumulative amount (AGP-059), under
    /// the bounds of [`CallOpts`]. Its headers are not used: the close is a control request.
    pub fn close_with(&mut self, origin: &str, opts: &CallOpts<'_>) -> Result<Value> {
        let r = self.close_inner(origin, opts.cum);
        self.saved(origin, r)
    }

    fn close_inner(&mut self, origin: &str, chosen: Option<u64>) -> Result<Value> {
        let pl = self.payload(origin, 0, "", "", b"", chosen)?;
        let ch = &self.channels[origin];
        let chan = ch.payer.params.channel_id();
        let sig = hex::encode(ch.payer.sign_close()?);
        let url = crate::wire::seller_url(origin, ch.accepted.get("extra").and_then(|e| e.get("closeUrl")).and_then(Value::as_str).unwrap_or(CLOSE_PATH))?;
        self.post(&url, &json!({"chan": chan, "sig": sig, "payload": pl}))
    }

    /// Roll the channel to `origin` over: one tx pays the provider what is owed and funds a new
    /// channel with the rest; the provider co-signs and broadcasts it. Returns the provider's
    /// answer (`nextChan`, `nextCapacity`); call [`Client::open_rolled`] once it confirms.
    pub fn rollover(&mut self, origin: &str) -> Result<Value> {
        let r = self.rollover_inner(origin);
        self.saved(origin, r)
    }

    fn rollover_inner(&mut self, origin: &str) -> Result<Value> {
        let h = (self.height)()?;
        let ch = self.channels.get(origin).ok_or_else(|| ChannelError::code("no_channel"))?;
        if ch.stage != Stage::Open {
            return fail("no_channel", "the channel is not open at the provider yet");
        }
        let ex = ch.accepted.get("extra").cloned().unwrap_or(Value::Null);
        let expiry = h.checked_add(self.expiry_blocks(&ex)?).ok_or_else(|| ChannelError::new("bad_offer", "expiry height"))?;
        let mut owed = (ch.spent_msat / 1000).max(ch.payer.signed);
        owed = owed.max(ch.payer.params.min_amount());
        let pay_to = hex::decode(ch.accepted.get("payTo").and_then(Value::as_str).unwrap_or("")).map_err(|_| ChannelError::code("bad_offer"))?;
        let next_origin = format!("{origin}/next");
        // One next key per channel (AGP-090, review C3): the provider can broadcast any rollover of
        // this channel that we signed, whatever it answered, for as long as the channel is unspent.
        // So every attempt pays the key of the first. A new key per attempt made a signer, which
        // holds one issued key per origin, replace the key an earlier attempt's transaction pays:
        // that next channel then had no key and no refund.
        let chan = ch.payer.params.channel_id();
        let earlier = self.next_rolled.get(origin).into_iter().flatten().filter(|n| n.rolled_from.as_deref() == Some(chan.as_str())).collect::<Vec<_>>();
        let (next_pub, secret, next_payer_spk) = match earlier.first() {
            Some(n) => (n.payer.params.payer_pub.to_vec(), n.payer.secret().copied(), Some(n.payer.params.payer_spk.clone())),
            None => self.fresh_key(&next_origin)?,
        };
        if earlier.len() >= MAX_KEPT {
            return fail("rollover_unresolved", format!("{MAX_KEPT} rollovers of this channel are signed and none is known to have confirmed: close it instead"));
        }
        let ch = self.channels.get(origin).ok_or_else(|| ChannelError::code("no_channel"))?;
        let p = &ch.payer.params;
        let next = ChannelParams::derive(&pay_to, &next_pub, expiry, p.close_fee, next_payer_spk, &self.cfg.network, p.close_fee_payer)?;
        let next_cap = p.rollover_next_capacity(owed);
        if next_cap < ex_u64(&ex, "minCapacity")? {
            return fail("exhausted", "not enough leftover to roll into a new channel");
        }
        // the txid of the tx we sign (segwit: the witness is not in it), so the next channel we bind
        // is the one that tx funds, never an outpoint the provider names (review C3)
        let txid = p.rollover_tx(owed, &next.spk(), next_cap)?.txid();
        let ch = self.channels.get_mut(origin).ok_or_else(|| ChannelError::code("no_channel"))?;
        if owed > ch.payer.signed {
            // AGP-085: the rollover moves the watermark to `owed`. The plain state for it is signed
            // first and kept, so a close (or a call) after a rollover that failed carries a
            // signature for the cum it names; it pays the provider what the rollover would
            ch.last_sig = hex::encode(ch.payer.sign_state(owed)?);
        }
        let sig = hex::encode(ch.payer.sign_rollover_next(owed, &next, next_cap)?);
        let (accepted, price) = (ch.accepted.clone(), ch.price);
        let body = json!({"chan": chan, "amount": owed, "next": {"payerPub": hex::encode(next.payer_pub), "expiry": expiry,
                          "payerSpk": hex::encode(&next.payer_spk)}, "sig": sig});
        // Before the request leaves (AGP-081, review C3): the provider may broadcast the one tx we
        // signed while its reply is lost or an error. A key of ours is bound and its refund handed
        // out now. A signer binds a next channel only once its node shows the rollover, so its
        // record carries the params to bind it with (take_next, adopt_rolled).
        let np = next.with_funding(&txid, 1, next_cap)?;
        let (payer, refund_hex, auth_key) = match (&self.signer, secret) {
            (Some(s), _) => (Payer::with_backend(np, s.clone()), String::new(), [0u8; 32]),
            (None, secret) => self.bind_key(&next_origin, np, secret)?,
        };
        if let (Some(cb), false) = (&self.on_refund, refund_hex.is_empty()) {
            cb(&refund_hex, expiry);
        }
        let next_ch = ClientChannel { payer, origin: origin.into(), accepted, refund_hex, auth_key, price, slack_msat: 0, seq: 0,
                                      spent_msat: 0, last_sig: String::new(), pending_cond: None, acked_cum: 0, receipts: vec![],
                                      stage: Stage::Open, unanswered_msat: 0, rolled_from: Some(chan.clone()) };
        let list = self.next_rolled.entry(origin.to_string()).or_default();
        // the same attempt again (same amount, same height) is the same transaction: one record
        if !list.iter().any(|n| n.payer.params.funding_txid() == txid) {
            list.push(next_ch);
        }
        self.persist(Some(origin))?;
        let r = self.post(&format!("{origin}{ROLLOVER_PATH}"), &body)?;
        if r.get("txid").and_then(Value::as_str).map(str::to_ascii_lowercase).as_deref() != Some(txid.as_str())
            || r.get("nextChan").and_then(Value::as_str).map(str::to_ascii_lowercase) != Some(format!("{txid}:1"))
            || py_u64(r.get("nextCapacity")) != Some(next_cap)
        {
            return fail("bad_rollover", format!("the provider's rollover differs from the one we signed (tx {txid})"));
        }
        self.take_next(origin, &txid)?;
        Ok(r)
    }

    /// Make the next channel of the rollover `txid` the live one; the channel it replaces waits in
    /// [`pending_rolled`](Self::pending_rolled). A key held by a signer is bound there first.
    fn take_next(&mut self, origin: &str, txid: &str) -> Result<()> {
        let unknown = || ChannelError::new("no_channel", format!("no signed rollover {txid} for {origin}"));
        let list = self.next_rolled.get_mut(origin).ok_or_else(unknown)?;
        let i = list.iter().position(|c| c.payer.params.funding_txid() == txid).ok_or_else(unknown)?;
        if list[i].refund_hex.is_empty() {
            let s = self.signer.as_ref().ok_or_else(|| ChannelError::new("bad_key", "the next channel has no refund and no signer"))?;
            let p = &list[i].payer.params;
            // a channel the signer bound before (the reply to that attach was lost) still signs its refund
            let attached = s.attach(&format!("{origin}/next"), p);
            let refund = match s.sign_refund(&p.channel_id()) {
                Ok(r) => r,
                Err(e) => return Err(attached.err().unwrap_or(e)),
            };
            if let Some(cb) = &self.on_refund {
                cb(&refund, p.expiry);
            }
            list[i].refund_hex = refund;
        }
        let ch = self.channels.get_mut(origin).ok_or_else(|| ChannelError::code("no_channel"))?;
        let mut next_ch = list.remove(i);
        if list.is_empty() {
            self.next_rolled.remove(origin);
        }
        std::mem::swap(ch, &mut next_ch);
        self.pending_rolled.insert(origin.to_string(), next_ch);
        Ok(())
    }

    /// Make the next channel of a rollover this client signed the live one, after a reply that was
    /// lost or an error, once the embedder sees the rollover transaction `txid` on chain (AGP-081,
    /// review C3). Then [`open_rolled`](Self::open_rolled), as after a rollover that answered.
    pub fn adopt_rolled(&mut self, origin: &str, txid: &str) -> Result<()> {
        let r = self.take_next(origin, &txid.to_ascii_lowercase());
        self.saved(origin, r)
    }

    /// Register the rolled-over channel with the provider (its funding must have confirmed).
    pub fn open_rolled(&mut self, origin: &str) -> Result<Value> {
        let r = self.open_rolled_inner(origin);
        self.saved(origin, r)
    }

    fn open_rolled_inner(&mut self, origin: &str) -> Result<Value> {
        let ch = &self.channels[origin];
        let p = &ch.payer.params;
        let c = json!({"txid": p.funding_txid(), "vout": p.funding_vout(), "capacity": p.capacity, "expiry": p.expiry,
                       "payerPub": hex::encode(p.payer_pub), "payerSpk": hex::encode(&p.payer_spk), "redeemScript": hex::encode(p.script())});
        let mut c = c;
        if p.close_fee_payer != FeePayer::Payer {
            c["closeFeePayer"] = p.close_fee_payer.as_str().into();
        }
        let url = crate::wire::seller_url(origin, ch.accepted.get("extra").and_then(|e| e.get("openUrl")).and_then(Value::as_str).unwrap_or(OPEN_PATH))?;
        let r = self.post(&url, &json!({"x402Version": 2, "network": self.cfg.network, "channel": c}))?;
        self.pending_rolled.remove(origin);
        Ok(r)
    }

    /// Pay-on-preimage: sign a hash-locked increment, receive the key, check it, and fold the
    /// increment into a plain state. Returns the response and the decrypted deliverable.
    pub fn request_conditional(&mut self, method: &str, url: &str, body: &[u8]) -> Result<(HttpResponse, Vec<u8>)> {
        let r = self.request_conditional_inner(method, url, body);
        self.saved(&split_url(url).0, r)
    }

    fn request_conditional_inner(&mut self, method: &str, url: &str, body: &[u8]) -> Result<(HttpResponse, Vec<u8>)> {
        crate::wire::no_fragment(url)?;
        let (origin, path) = split_url(url);
        let r = self.transport.request(method, url, body, &[])?;
        if r.status != 402 {
            return fail("bad_offer", "expected a 402 with a hashlock");
        }
        let pr = unb64json(header(&r, "PAYMENT-REQUIRED").ok_or_else(|| ChannelError::code("bad_offer"))?)?;
        let acc = self.pick(&pr)?;
        let extra = acc.get("extra").and_then(|e| e.get("conditional")).cloned().unwrap_or(Value::Null);
        if !truthy(extra.get("hash")) {
            return fail("bad_offer", "no conditional hashlock in the 402");
        }
        let cipher = extra.get("cipher").and_then(Value::as_str).and_then(|c| hex::decode(c).ok())
            .ok_or_else(|| ChannelError::new("bad_offer", "conditional offer carries no ciphertext"))?;
        self.ensure_open(&origin, &acc)?;
        let amount = py_u64(acc.get("amount")).unwrap_or(0);
        {
            let ch = self.channels.get_mut(&origin).ok_or_else(|| ChannelError::code("no_channel"))?;
            if ch.price > 0 && amount > ch.price {
                return fail("bad_offer", format!("price raised mid-channel: {} -> {amount} sat", ch.price));
            }
            ch.accepted = acc.clone();
        }
        let (signed, acked, last) = {
            let ch = &self.channels[&origin];
            (ch.payer.signed, ch.acked_cum, ch.last_sig.clone())
        };
        if signed > acked && !last.is_empty() {
            self.hand_over(&origin, &acc, signed, &last);    // a lost fold first (L9)
        }
        let h: [u8; 32] = extra.get("hash").and_then(Value::as_str).and_then(|x| hex::decode(x).ok()).and_then(|v| v.try_into().ok())
            .ok_or_else(|| ChannelError::new("bad_offer", "hash"))?;
        let cond_amt = py_u64(extra.get("amount")).ok_or_else(|| ChannelError::new("bad_offer", "amount"))?;
        if cond_amt > self.cfg.max_price {
            return fail("too_expensive", format!("conditional {cond_amt} sat > max {}", self.cfg.max_price));
        }
        if cond_amt < DUST {
            return fail("bad_offer", "conditional amount below dust");
        }
        self.check_daily(cond_amt)?;
        let csv = py_u64(extra.get("csvDelta")).unwrap_or(10) as u32;
        let ch = self.channels.get_mut(&origin).ok_or_else(|| ChannelError::code("no_channel"))?;
        let cp = ConditionalParams::new(ch.payer.params.clone(), h, cond_amt, csv)?;
        let uncond = ch.payer.signed;
        let sig = hex::encode(ch.payer.sign_conditional(uncond, &cp)?);
        self.day_spent += cond_amt;
        ch.pending_cond = Some(PendingCond { hash: h, cipher: cipher.clone(), amount: cond_amt });
        ch.seq += 1;
        ch.unanswered_msat = ch.unanswered_msat.saturating_add(cond_amt.saturating_mul(1000));
        let mut pl = json!({"chan": ch.payer.params.channel_id(), "seq": ch.seq, "cum": uncond.to_string(), "hashlock": hex::encode(h), "sig": sig});
        Self::auth(ch, &mut pl, method, &format!("{origin}{path}"), body)?;
        let hdrs = vec![("PAYMENT-SIGNATURE".to_string(), b64json(&payment_payload(&acc, &pl)))];
        let r = self.transport.request(method, url, body, &hdrs)?;
        if r.status == 402 {
            // refused: the provider did not keep the conditional state, and did not charge it
            ch.pending_cond = None;
            ch.unanswered_msat = ch.unanswered_msat.saturating_sub(cond_amt.saturating_mul(1000));
            let code = crate::json::parse_slice(&r.body).ok().and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string))
                .filter(|c| safe_code(c)).unwrap_or_else(|| "refused".into());
            return fail(&code, "conditional call refused");
        }
        let k = crate::json::parse_slice(&r.body).ok().and_then(|v| v.get("preimage").and_then(Value::as_str).and_then(|k| hex::decode(k).ok()))
            .ok_or_else(|| ChannelError::new("no_preimage", format!("HTTP {} without k: recover_conditional reads k from the provider's claim", r.status)))?;
        if sha256(&k) != h {
            return fail("bad_preimage", "provider preimage does not match H");
        }
        if let Some(resp) = paid_response(&r)? {
            // while the hash lock is pending: after a bad_receipt, recover_conditional still reads k
            // from the provider's claim
            self.receipt(&origin, &resp, method, &path, body, (r.status, &r.body), Some(cond_amt))?;
        }
        let plain = decrypt(&cipher, &k);
        // upgrade: fold the increment into a plain state and hand it over now
        let ch = self.channels.get_mut(&origin).ok_or_else(|| ChannelError::code("no_channel"))?;
        ch.pending_cond = None;
        let new_cum = (uncond + cond_amt).max(ch.payer.params.min_amount());
        if new_cum > ch.payer.signed {
            ch.last_sig = hex::encode(ch.payer.sign_state(new_cum)?);
        }
        let last = ch.last_sig.clone();
        self.hand_over(&origin, &acc, new_cum, &last);
        Ok((r, plain))
    }

    /// POST a signed state to /x402/verify; on failure the next paid call carries it again.
    fn hand_over(&mut self, origin: &str, acc: &Value, cum: u64, sig: &str) {
        let chan = self.channels[origin].payer.params.channel_id();
        let req = facilitator_request(acc, &json!({"chan": chan, "cum": cum.to_string(), "sig": sig}));
        if let Ok(v) = self.post(&format!("{origin}{FACILITATOR_VERIFY}"), &req) {
            if v.get("isValid") == Some(&Value::Bool(true)) {
                if let Some(ch) = self.channels.get_mut(origin) {
                    ch.acked_cum = ch.acked_cum.max(cum);
                }
            }
        }
    }

    /// The deliverable of a signed hash lock whose paid response never arrived, from the
    /// provider's claim transaction (which reveals k on-chain).
    pub fn recover_conditional(&self, origin: &str, claim: &Tx) -> Result<Vec<u8>> {
        let pc = self.channels.get(origin).and_then(|c| c.pending_cond.clone())
            .ok_or_else(|| ChannelError::new("no_state", "no pending conditional call on this channel"))?;
        let k = preimage_from_tx(claim, &pc.hash).ok_or_else(|| ChannelError::new("bad_preimage", "this transaction does not reveal k"))?;
        Ok(decrypt(&pc.cipher, &k))
    }
}
