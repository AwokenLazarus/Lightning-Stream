//! `xbt402_pay` inside the signer (B2 `xbt402.py` + `stream.py`): B1's wire, B2's keys.
//!
//! Channels are keyed by HTTP origin. AGP-017: the network id comes from the spec's anchor
//! (block 961640 on mainnet, P4); a mining hook is refused off regtest (P3); a channel is recorded,
//! payer key sealed, before its funding is broadcast (P1) and opened only once the funding has the
//! offer's minConf (P2). The provider's body and receipt come back only under
//! `untrusted_provider_response` (L7); the wallet's own errors never carry provider text (L12).
//!
//! Streamed results (`stream: xbt402-merkle-v1`) are bought here: signed Merkle manifest,
//! verify-then-pay per chunk, hash-locked last chunk (the ciphertext before the signature, M7).
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::channel::DERIVATION;
use xbt402::client::Transport;
use xbt402::conditional::{encrypt, preimage_from_tx};
use xbt402::json::{dumps, py_str};
use xbt402::provider::HttpResponse;
use xbt402::wire::{b64json, body_hash, facilitator_request, receipt_message, receipt_of, request_digest_v2, safe_code, scheme_accepted, seller_url, unb64json, FACILITATOR_VERIFY};
use xbt_primitives::ecdsa;
use xbt_primitives::hash::{sha256, tagged_hash};
use xbt_primitives::tx::Tx;

use crate::channels::{ChannelBook, ChannelRecord};
use crate::hot::{HotWallet, DEFAULT_FEE};
use crate::node::{self, Node};
use crate::pyjson::{now_f64, py_int, truthy};
use crate::sanitize::{untrusted, UNTRUSTED_KEY};
use crate::{err, Result};

pub const PREVIEW_CAP: usize = 2048;
/// AGP-089: the longest a stream's last chunk may stay hash-locked on the seller's word (four weeks).
pub const MAX_COND_CSV_BLOCKS: u32 = 4032;
/// AGP-095: the shortest a channel funded on a seller's offer may last (a day of blocks), unless
/// the owner's `channel_expiry_blocks` asks for less. Each funded channel costs a funding fee and a
/// close or refund fee that no budget counts, so a seller's window does not get one per call.
pub const MIN_OFFER_EXPIRY_BLOCKS: i64 = 144;
const OPEN_POLL_S: f64 = 2.0;

/// Inline preview cap (`B2_BODY_CAP`, default 12,000).
pub fn body_cap() -> usize {
    std::env::var("B2_BODY_CAP").ok().and_then(|v| v.parse().ok()).unwrap_or(12_000)
}

/// A RuntimeError in B2: reported as `deny/xbt402`.
fn rt(msg: impl Into<String>) -> crate::Error {
    err("xbt402", msg)
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

fn pick_accept(pr: &Value, network: &str) -> Result<Value> {
    pr.get("accepts").and_then(Value::as_array).into_iter().flatten()
        .find(|a| scheme_accepted(a.get("scheme").and_then(Value::as_str)) && a.get("network").and_then(Value::as_str) == Some(network))
        .cloned().ok_or_else(|| rt("no batch-settlement offer on this network"))
}

/// Python's `int(v or default)`.
fn or_int(v: Option<&Value>, default: i64) -> Result<i64> {
    if !truthy(v) {
        return Ok(default);
    }
    py_int(v).ok_or_else(|| rt("offer field is not an integer"))
}

fn charged_of(resp: Option<&Value>, default: i64) -> i64 {
    resp.and_then(|r| receipt_of(r).ok()).and_then(|r| py_int(r.get("charged"))).unwrap_or(default)
}

fn log_call(kind: &str, fields: Value) {
    let Ok(path) = std::env::var("B2_CALLS_JSONL") else { return };
    let mut row = json!({"t": (now_f64() * 1000.0).round() / 1000.0, "kind": kind});
    if let Value::Object(m) = fields {
        for (k, v) in m {
            row[&k] = v;
        }
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().append(true).create(true).open(path) {
        use std::io::Write;
        let _ = writeln!(f, "{}", dumps(&row));
    }
}

fn ms_since(t: Instant) -> f64 {
    (t.elapsed().as_secs_f64() * 10_000.0).round() / 10.0
}

/// Persist a body; digest + path. Never truncates the stored bytes.
fn store_body(raw: &[u8], name: &str) -> Value {
    let digest = hex::encode(sha256(raw));
    let Ok(root) = std::env::var("B2_BODY_DIR") else {
        return json!({"body_digest": digest, "bytes": raw.len()});
    };
    let _ = std::fs::create_dir_all(&root);
    let safe: String = name.chars().map(|c| if c.is_alphanumeric() || "-_.".contains(c) { c } else { '_' }).take(80).collect();
    let safe = if safe.is_empty() { digest[..16].to_string() } else { safe };
    let path = Path::new(&root).join(format!("{safe}.bin"));
    let _ = std::fs::write(&path, raw);
    json!({"body_digest": digest, "saved_to": path.to_string_lossy(), "bytes": raw.len()})
}

fn preview(b: &[u8], cap: usize) -> String {
    String::from_utf8_lossy(b).chars().take(cap).collect()
}

fn merge(dst: &mut Value, src: Value) {
    if let (Value::Object(d), Value::Object(s)) = (dst, src) {
        for (k, v) in s {
            d.insert(k, v);
        }
    }
}

pub type MineFn = Arc<dyn Fn(u64) -> Result<()> + Send + Sync>;

/// Commit a signed increase to the policy ledger before the signature is sent.
/// `(dest, delta_sats, chan, cum)`.
pub type SpendBook = Arc<dyn Fn(&str, i64, &str, i64) -> Result<()> + Send + Sync>;

/// The policy's verdict on a signed increase larger than the amount it approved (a channel's
/// dust floor). `(dest, max_sats, delta_sats)`; `Some(deny)` stops the call before anything is signed.
pub type SpendCheck = Arc<dyn Fn(&str, i64, i64) -> Result<Option<Value>> + Send + Sync>;

/// One stream chunk: `Ok((data, charged, chan))`, or `Err((reason, charged, chan))`.
type ChunkStep = std::result::Result<(Vec<u8>, i64, String), (String, i64, String)>;

/// What our own node says about a channel's funding output (AGP-080): the only thing that takes a
/// channel away from the refund watcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FundingSpend {
    /// Still in the UTXO set (mempool included): the channel is not closed.
    Unspent,
    /// Spent only by a transaction in the mempool (named when the node can): not closed yet. That
    /// transaction may never be mined, and then the funding is the refund's again (AGP-095).
    Mempool(String),
    /// Spent in a block, by this transaction when the node could name it (else empty).
    Spent(String),
    /// The node has never shown this output: nothing is proven either way.
    Unknown,
}

/// The longest a channel's coins may be locked, in blocks from now (AGP-063 W3, AGP-089): the
/// policy's `channel_expiry_blocks`, but at least four weeks so a provider's minimum fits. A routed
/// ch1 must outlive the hub's ch2 to a provider, so a routing hub gets twice that. Every path that
/// funds or rolls a channel holds the expiry to this, whoever named it (a seller's offer too).
pub fn max_expiry_blocks(channel_expiry_blocks: i64, hub: bool) -> i64 {
    channel_expiry_blocks.max(4032).saturating_mul(if hub { 2 } else { 1 })
}

/// What one `xbt402_pay` may sign (AGP-089, review W1). The rule: a call never raises what its
/// channel's ledger holds by more than the `max_sats` the policy approved for it, whatever the
/// seller's numbers are. `start` is the ledger when the call began. Every state after the call's
/// first is checked here before it is signed, with checked arithmetic.
#[derive(Debug, Clone, Copy)]
struct CallBudget {
    start: i64,
    max_sats: i64,
}

impl CallBudget {
    /// `cum` may be signed: it is at most `max_sats` above where the call found the ledger.
    fn fits(&self, cum: i64) -> bool {
        cum.checked_sub(self.start).is_some_and(|d| d <= self.max_sats)
    }
}

/// One signer-owned client session.
pub struct Session {
    pub book: Arc<ChannelBook>,
    pub hot: Arc<HotWallet>,
    pub node: Arc<dyn Node>,
    pub transport: Arc<dyn Transport>,
    pub chain: String,
    pub mine: Option<MineFn>,
    pub open_wait_s: f64,
    pub close_fee_max: i64,
    pub refund_margin: i64,
    net: Mutex<Option<String>>,
    spend_book: Mutex<Option<SpendBook>>,
    spend_check: Mutex<Option<SpendCheck>>,
}

/// Send a channel funding whose pending record (payer key, refund terms, the transaction itself) is
/// already on disk. AGP-085: the record is forgotten only when the node itself refused the
/// transaction ([`crate::node::REFUSED`]). Any other failure (a timeout on the send and on the
/// lookup after it) leaves the funding's fate unknown: the node may have it, so the record and its
/// key stay, the inputs count as spent, and the watcher sends the transaction again until the node
/// shows it or refunds the channel at expiry. The error says so.
pub(crate) fn send_funding(hot: &crate::hot::HotWallet, book: &ChannelBook, dest: &str, chan: &str, prep: &crate::hot::Prep) -> Result<()> {
    match hot.broadcast(prep) {
        Ok(_) => hot.commit(prep),
        Err(e) if e.code == crate::node::REFUSED => {
            book.drop_pending(dest, chan)?;
            Err(e)
        }
        Err(e) => {
            hot.commit(prep)?;
            Err(err(&e.code, format!("{}; the node may have taken this funding, so its channel stays pending (sent again by the watcher, refunded at expiry)", e.msg)))
        }
    }
}

impl Session {
    #[allow(clippy::too_many_arguments)]
    pub fn new(book: Arc<ChannelBook>, hot: Arc<HotWallet>, node: Arc<dyn Node>, transport: Arc<dyn Transport>, chain: &str,
               mine: Option<MineFn>, open_wait_s: f64, close_fee_max: i64, refund_margin: i64) -> Result<Self> {
        if mine.is_some() && !node::mining_allowed(chain) {
            return Err(err("chain", format!("a mining hook on {chain:?}: only regtest may mine")));
        }
        Ok(Self { book, hot, node, transport, chain: chain.into(), mine, open_wait_s, close_fee_max, refund_margin, net: Mutex::new(None),
                  spend_book: Mutex::new(None), spend_check: Mutex::new(None) })
    }

    /// The signer sets this so a signed increase is in the policy ledger before it leaves.
    pub fn set_spend_book(&self, book: SpendBook) {
        *self.spend_book.lock().unwrap_or_else(|p| p.into_inner()) = Some(book);
    }

    /// The signer sets this so a dust floor above `max_sats` is held to the budget too.
    pub fn set_spend_check(&self, check: SpendCheck) {
        *self.spend_check.lock().unwrap_or_else(|p| p.into_inner()) = Some(check);
    }

    pub fn height(&self) -> Result<u64> {
        node::height(&*self.node)
    }

    /// The xbt402 network id (P4). A wrong mainnet anchor fails: never pay on a network we can't name.
    pub fn network(&self) -> Result<String> {
        if self.chain != "regtest" {
            let mut g = self.net.lock().map_err(|_| rt("poisoned"))?;
            if g.is_none() {
                *g = Some(node::network(&*self.node, &self.chain, None)?);
            }
            return Ok(g.clone().unwrap_or_default());
        }
        Ok(self.height().and_then(|h| node::network(&*self.node, &self.chain, Some(h)))
            .unwrap_or_else(|_| xbt_primitives::network::network_id(&"0".repeat(64))))
    }

    fn http(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        self.transport.request(method, url, body, headers)
    }

    /// Fund a channel for this offer and open it. Returns the channel's public record, or one with
    /// state "pending" when the funding has not reached the offer's minConf within `open_wait_s`.
    pub fn open_from_offer(&self, dest: &str, acc: &Value, cap_sats: i64, expiry_blocks: i64) -> Result<Value> {
        let extra = acc.get("extra").cloned().unwrap_or(json!({}));
        if extra.get("derivation").and_then(Value::as_str) != Some(DERIVATION) {
            // checked before funding: a mismatch strands the coins (no provider text: L12)
            return Err(rt(format!("provider channel binding (extra.derivation) is not {DERIVATION:?}; refused before funding")));
        }
        let close_fee = or_int(extra.get("closeFeeSat"), 600)?;
        if close_fee < 0 {
            return Err(rt("offer closeFeeSat is negative; refused before funding"));
        }
        if self.close_fee_max > 0 && close_fee > self.close_fee_max {
            return Err(rt(format!("offer closeFeeSat {close_fee} is above this wallet's cap {}; refused before funding", self.close_fee_max)));
        }
        let fee_payer = extra.get("closeFeePayer").map(|v| v.as_str().unwrap_or("?").to_string()).unwrap_or_else(|| "payer".into());
        if fee_payer != "payer" && fee_payer != "payee" {
            return Err(rt("offer closeFeePayer is neither payer nor payee; refused before funding"));
        }
        // payer-pays: we fund our close fee on top of the cap; payee-pays: the payee's output carries it
        let payer_fee = if fee_payer == "payer" { close_fee } else { 0 };
        // min/maxCapacity bound the funding output (cap + our close fee), as B1 checks it (AGP-017)
        // AGP-089: the fee is the seller's number; with `close_fee_max_sats: 0` nothing else bounds it
        let funded = cap_sats.checked_add(payer_fee).filter(|f| *f > 0 && cap_sats > 0)
            .ok_or_else(|| rt("the channel's capacity and the offer's closeFeeSat do not add up to an amount; refused before funding"))?;
        let min_cap = or_int(extra.get("minCapacity"), 0)?;
        let max_cap = or_int(extra.get("maxCapacity"), funded)?;
        // AGP-063 W2: the seller's minCapacity must not raise the owner's per-channel cap.
        // minCapacity bounds the funding output (cap + the payer's close fee).
        if min_cap > funded {
            return Err(err("min_capacity", format!("offer minCapacity {min_cap} exceeds this wallet's per-channel cap {funded}")));
        }
        let cap = cap_sats;
        if funded > max_cap {
            return Err(rt(format!("channel capacity {funded} above provider max {max_cap}")));
        }
        let min_exp = or_int(extra.get("minExpiryBlocks"), 1)?;
        let max_exp = or_int(extra.get("maxExpiryBlocks"), 100_000)?;
        let min_conf = match extra.get("minConf") {
            None => 1,
            Some(v) => py_int(Some(v)).map(|x| x.max(0)).unwrap_or(1),
        };
        // The provider checks `left >= minExpiryBlocks` at its tip when the funded open reaches it,
        // after the funding's minConf confirmations and however long it waited for the first. The
        // allowance for that is the offer's own (xbt402::funding::open_expiry_floor, AGP-076).
        let margin = py_int(extra.get("closeMarginBlocks")).filter(|m| *m >= 0)
            .ok_or_else(|| rt("offer closeMarginBlocks is missing or not a block count; refused before funding"))?;
        let nn = |x: i64| x.max(0) as u64;
        // AGP-089 (review C2): these three are the seller's numbers and they decide how long the
        // owner's coins are locked if the seller then never opens or closes the channel. The
        // owner's bound holds here as on the socket's open paths; refused before the preflight.
        let most = max_expiry_blocks(expiry_blocks, false);
        let floor = xbt402::funding::open_expiry_floor(nn(min_exp), nn(min_conf), nn(margin));
        if floor > nn(most) {
            return Err(err("expiry", format!("the offer needs the channel locked for {floor} blocks (minExpiryBlocks + minConf + closeMarginBlocks); \
                                              this wallet locks a channel for at most {most}; refused before funding")));
        }
        let blocks = xbt402::funding::open_expiry_blocks(nn(expiry_blocks), nn(min_exp), nn(max_exp), nn(min_conf), nn(margin));
        let blocks = i64::try_from(blocks).ok().filter(|b| *b <= most).ok_or_else(|| rt("offer expiry window is not a block count this wallet accepts"))?;
        // AGP-095 (audit item 4), the lower side of the same rule: **how long a channel lasts is
        // the owner's number too.** The offer's `maxExpiryBlocks` caps the window from above, so a
        // seller that offers a window of a block or two and answers the preflight yes got a channel
        // funded that could never be opened and was refunded, on every call, for two fees no budget
        // sees. A channel is funded only if it lasts at least the offer's own floor (below it the
        // seller's own check refuses the open), longer than the refund margin (inside it this
        // wallet never opens), and at least `MIN_OFFER_EXPIRY_BLOCKS` or what the owner asked for.
        let least = i64::try_from(floor).unwrap_or(i64::MAX).max(self.refund_margin.saturating_add(1)).max(expiry_blocks.min(MIN_OFFER_EXPIRY_BLOCKS));
        if blocks < least {
            return Err(err("expiry", format!("the offer's window lets the channel last {blocks} blocks; this wallet funds one only for {least} or more \
                                              (the offer's own floor, the refund margin, and a day or the policy's channel_expiry_blocks); refused before funding")));
        }
        self.hot.check_channel_funding()?; // AGP-013: above the hot-balance cap, a human sweeps first
        let open_height = self.height()? as i64;
        let expiry = open_height.checked_add(blocks).and_then(|e| u32::try_from(e).ok()).ok_or_else(|| rt("the channel's expiry is not a block height"))?;
        let (secret, payer_pub) = self.book.new_payer_key();
        // change at close returns to the signer's hot key, not the per-channel payer key
        let pay_to = hex::decode(acc.get("payTo").and_then(Value::as_str).unwrap_or("")).map_err(|_| rt("offer payTo is not hex"))?;
        let network = acc.get("network").and_then(Value::as_str).unwrap_or("").to_string();
        let fp = xbt402::channel::FeePayer::parse(&fee_payer)?;
        let params = xbt402::channel::ChannelParams::derive(&pay_to, &hex::decode(&payer_pub).unwrap_or_default(), expiry,
                                                            close_fee as u64, Some(self.hot.spk()), &network, fp)?;
        // AGP-080 X1: the seller names this URL; it must stay on the origin the policy allowed
        let open_url = seller_url(dest, extra.get("openUrl").and_then(Value::as_str).unwrap_or(xbt402::wire::OPEN_PATH))?;
        self.preflight(&open_url, &network, &params, funded, &fee_payer)?;
        let prep = self.hot.prepare_fund(&params.spk(), funded, DEFAULT_FEE)?;
        let params = params.with_funding(&prep.txid, 0, funded as u64)?;
        // P1 write-ahead: the payer key is sealed on disk, with everything the refund needs, before
        // the funding exists anywhere but here
        self.book.add_pending(dest, secret, &params, dest, Some(cap), open_height, &open_url, &network, min_conf, &prep.hex)?;
        send_funding(&self.hot, &self.book, dest, &params.channel_id(), &prep)
            .map_err(|e| rt(format!("funding broadcast failed: {}", e.msg.chars().take(300).collect::<String>())))?;
        log_call("funding", json!({"dest": dest, "chan": params.channel_id(), "txid": prep.txid, "capacity": funded, "expiry": expiry,
                                   "min_conf": min_conf}));
        self.complete_open(dest, self.open_wait_s)
    }

    /// review C2: the provider says it opens a channel on exactly these terms before the funding
    /// exists (a refusal after funding locks the coins until expiry). A provider from before the
    /// preflight answers `bad_request` (no outpoint) once the terms it checks first have passed.
    fn preflight(&self, open_url: &str, network: &str, params: &xbt402::channel::ChannelParams, funded: i64, fee_payer: &str) -> Result<()> {
        let mut ch = json!({"capacity": funded, "expiry": params.expiry, "payerPub": hex::encode(params.payer_pub),
                            "payerSpk": hex::encode(&params.payer_spk), "redeemScript": hex::encode(params.script())});
        if fee_payer != "payer" {
            ch["closeFeePayer"] = fee_payer.into();
        }
        let body = json!({"x402Version": 2, "network": network, "preflight": true, "channel": ch});
        let resp = self.http("POST", open_url, dumps(&body).as_bytes(), &[("Content-Type".into(), "application/json".into())])
            .map_err(|_| rt("open preflight failed: provider unreachable; nothing was funded"))?;
        let reply: Option<Value> = serde_json::from_slice(&resp.body).ok();
        if resp.status != 200 {
            let code = reply.as_ref().and_then(|r| r.get("error")).and_then(Value::as_str).filter(|c| safe_code(c)).unwrap_or("");
            if code == "bad_request" {
                return Ok(());
            }
            let tail = if code.is_empty() { String::new() } else { format!(" {code}") };
            return Err(rt(format!("open refused before funding: HTTP {}{tail}; nothing was funded", resp.status)));
        }
        let r = reply.unwrap_or(Value::Null);
        if r.get("preflight") != Some(&Value::Bool(true)) {
            return Err(rt("the provider did not answer the open preflight; nothing was funded"));
        }
        if r.get("closeFeePayer").and_then(Value::as_str).unwrap_or("payer") != fee_payer {
            return Err(rt("the provider would open the channel with another closeFeePayer; nothing was funded"));
        }
        Ok(())
    }

    /// Ask our node whether `rec`'s funding output is spent. Without txindex the spender is looked
    /// for in the mempool, then in the blocks from the funding's own (as the refund does, P6).
    ///
    /// AGP-095 (audit item 17), the rule: **a channel leaves the refund watch only when our node
    /// shows its funding spent in a block.** A close that is only in the mempool is a close that
    /// may never be mined (a fee too low, a conflict, an eviction): taken for "closed, proven" it
    /// ended the watch, and the funding then sat unspent past its expiry with no refund.
    pub fn funding_spend(&self, rec: &ChannelRecord) -> Result<FundingSpend> {
        let vout = rec.funding_vout as u32;
        let utxo = self.node.call("gettxout", json!([rec.funding_txid, rec.funding_vout, true]))?;
        if !utxo.is_null() {
            return Ok(FundingSpend::Unspent);
        }
        // gone with the mempool counted, still there without it: only a mempool transaction spends it
        let confirmed = self.node.call("gettxout", json!([rec.funding_txid, rec.funding_vout, false]))?;
        let in_mempool = node::mempool_spender(&*self.node, &rec.funding_txid, vout);
        if !confirmed.is_null() || in_mempool.is_some() {
            return Ok(FundingSpend::Mempool(in_mempool.unwrap_or_default()));
        }
        let start = if rec.funding_height != 0 { rec.funding_height } else { rec.open_height };
        if let Some(sp) = node::block_spender(&*self.node, &rec.funding_txid, vout, start.max(0) as u64, node::SPENDER_SCAN_MAX) {
            return Ok(FundingSpend::Spent(sp));
        }
        if rec.funding_height != 0 || node::get_tx(&*self.node, &rec.funding_txid, "").is_some() {
            return Ok(FundingSpend::Spent(String::new()));
        }
        Ok(FundingSpend::Unknown)
    }

    /// Confirmations of a channel's funding output; `None` when the node does not have it at all.
    fn funding_confirmations(&self, rec: &ChannelRecord) -> Result<Option<i64>> {
        let r = self.node.call("gettxout", json!([rec.funding_txid, rec.funding_vout, true]))?;
        Ok((!r.is_null()).then(|| py_int(r.get("confirmations")).unwrap_or(0)))
    }

    /// P2: post a pending channel's open once its funding has `min_conf` confirmations (waiting up
    /// to `wait_s`), and mark it open when the provider accepts it (`duplicate_channel` counts).
    /// Otherwise it stays pending, and the watcher retries or refunds it.
    pub fn complete_open(&self, dest: &str, wait_s: f64) -> Result<Value> {
        let Some(rec) = self.book.get(dest) else { return Ok(json!({})) };
        if rec.state == "pending" && rec.open_url.is_empty() {
            // no open_url: a channel with no provider open here. AGP-085: its funding may be of
            // unknown fate (the send and the lookup both failed), so it is sent again while the
            // node does not show it. An external client's channel (signer `fund`) then waits for
            // the client's attach; the signer's own (`open_channel`) is open once it is sent
            let mut seen = self.funding_confirmations(&rec)?.is_some();
            if !seen && !rec.funding_hex.is_empty() {
                seen = self.node.call("sendrawtransaction", json!([rec.funding_hex])).is_ok();
            }
            if seen && rec.origin.is_empty() {
                return Ok(self.book.mark_open(dest)?.public());
            }
            return Ok(rec.public());
        }
        if rec.state != "pending" {
            return Ok(rec.public());
        }
        if origin_of(&rec.open_url).ok().as_deref() != Some(dest) {
            // a record from before AGP-080 may hold a seller URL that leaves the origin
            self.book.note_pending(dest, Some("open URL is off the channel's origin; refunded at expiry"), None)?;
            return Err(err("seller_url", "the recorded open URL is not on the channel's origin; the channel stays pending and is refunded at expiry"));
        }
        let mut confs = self.funding_confirmations(&rec)?;
        if confs.is_none() && !rec.funding_hex.is_empty() && self.node.call("sendrawtransaction", json!([rec.funding_hex])).is_ok() {
            confs = Some(0); // never reached the node, or was evicted: sent again
        }
        if let (Some(c), Some(mine)) = (confs, &self.mine) {
            if c < rec.min_conf {
                mine((rec.min_conf - c) as u64)?; // regtest only (P3)
                confs = self.funding_confirmations(&rec)?;
            }
        }
        let deadline = Instant::now() + Duration::from_secs_f64(wait_s.max(0.0));
        while confs.is_none_or(|c| c < rec.min_conf) && Instant::now() < deadline {
            let left = deadline.saturating_duration_since(Instant::now()).as_secs_f64();
            std::thread::sleep(Duration::from_secs_f64(OPEN_POLL_S.min(left.max(0.05))));
            confs = self.funding_confirmations(&rec)?;
        }
        if confs.is_none_or(|c| c < rec.min_conf) {
            let mut out = rec.public();
            out["confirmations"] = confs.unwrap_or(0).into();
            out["min_conf"] = rec.min_conf.into();
            return Ok(out);
        }
        let confs = confs.unwrap_or(0);
        if confs >= 1 && rec.funding_height == 0 {
            if let Some((h, _)) = node::block_of(&*self.node, &rec.funding_txid, rec.funding_vout as u32) {
                self.book.note_pending(dest, None, Some(h as i64))?;
            }
        }
        if self.height()? as i64 >= rec.expiry - self.refund_margin {
            self.book.note_pending(dest, Some("too close to expiry to open; refunded at expiry"), None)?;
            let mut out = self.book.get(dest).map(|r| r.public()).unwrap_or(json!({}));
            out["confirmations"] = confs.into();
            out["min_conf"] = rec.min_conf.into();
            return Ok(out);
        }
        let mut ch = json!({"txid": rec.funding_txid, "vout": rec.funding_vout, "capacity": rec.funding_sats, "expiry": rec.expiry,
                            "payerPub": rec.payer_pub, "payerSpk": rec.payer_spk, "redeemScript": hex::encode(rec.params()?.script())});
        if rec.close_fee_payer != "payer" {
            ch["closeFeePayer"] = rec.close_fee_payer.clone().into();
        }
        let body = json!({"x402Version": 2, "network": rec.network, "channel": ch});
        let resp = match self.http("POST", &rec.open_url, dumps(&body).as_bytes(), &[("Content-Type".into(), "application/json".into())]) {
            Ok(r) => r,
            Err(_) => {
                self.book.note_pending(dest, Some("open unreachable: ConnectionError"), None)?;
                return Err(rt("open failed: provider unreachable (ConnectionError); the channel stays pending: retried by the watcher, \
                               refunded at expiry if never opened"));
            }
        };
        let st = resp.status;
        let reply: Option<Value> = serde_json::from_slice(&resp.body).ok();
        let mut code = String::new();
        if st != 200 {
            code = reply.as_ref().and_then(|r| r.get("error")).and_then(Value::as_str).unwrap_or("").to_string();
            if !safe_code(&code) {
                code.clear(); // no provider text in the wallet's errors (L12)
            }
        }
        if st == 200 {
            let echoed = reply.as_ref().map(|r| r.get("closeFeePayer").cloned().unwrap_or_else(|| "payer".into()));
            if echoed.as_ref().and_then(Value::as_str) != Some(rec.close_fee_payer.as_str()) {
                // the provider would refuse every state we sign: never mark it open (refunded at expiry)
                self.book.note_pending(dest, Some("open refused: provider opened another closeFeePayer"), None)?;
                return Err(rt("open failed: the provider did not take the offer's closeFeePayer; the channel stays pending and is refunded at expiry"));
            }
        }
        if st == 200 || code == "duplicate_channel" {
            let opened = self.book.mark_open(dest)?;
            log_call("opened", json!({"dest": dest, "chan": opened.chan, "confirmations": confs, "duplicate": st != 200}));
            let mut out = opened.public();
            out["confirmations"] = confs.into();
            return Ok(out);
        }
        let tail = if code.is_empty() { String::new() } else { format!(" {code}") };
        self.book.note_pending(dest, Some(&format!("open refused: HTTP {st}{tail}")), None)?;
        Err(rt(format!("open failed: HTTP {st}{tail}; the channel stays pending: retried by the watcher, refunded at expiry if never opened")))
    }

    /// H3: bind this payload to (method, path, body). The ECDH key stays in the book.
    fn with_auth(&self, payload: &mut Value, method: &str, url: &str, body: &[u8]) -> Result<()> {
        xbt402::wire::no_fragment(url)?;
        let req = request_digest_v2(method, url, body);
        let chan = py_str(payload.get("chan"));
        let sig = payload.get("sig").and_then(Value::as_str).map(str::to_string);
        payload["auth"] = self.book.request_auth(&chan, payload.get("seq"), payload.get("cum"), sig.as_deref(), &req)?.into();
        Ok(())
    }

    fn paid(&self, method: &str, url: &str, body: &[u8], acc: &Value, mut payload: Value) -> Result<(HttpResponse, Option<Value>)> {
        self.with_auth(&mut payload, method, url, body)?;
        let hdr = b64json(&json!({"x402Version": 2, "accepted": acc, "payload": payload}));
        let r = self.http(method, url, body, &[("PAYMENT-SIGNATURE".into(), hdr)])?;
        let receipt = r.header("PAYMENT-RESPONSE").and_then(|h| unb64json(h).ok());
        Ok((r, receipt))
    }

    /// Sats of this channel already in the policy ledger. `-1` means a pre-AGP-063 record:
    /// treat `used_sats` as already booked so an upgrade does not book history again.
    pub fn booked_through(rec: &ChannelRecord) -> i64 {
        rec.booked_through()
    }

    /// Commit any signed amount the ledger does not yet hold, then remember that it does.
    /// The commit is idempotent on `xbt402:{chan}:{cum}`, so a crash between the two steps
    /// books the same increase once. Returns the sats committed by this call.
    fn book_unbooked(&self, dest: &str) -> Result<i64> {
        let Some(rec) = self.book.get(dest) else { return Ok(0) };
        self.book_through(dest, rec.used_sats)
    }

    /// Raise what the ledger holds for this channel to `cum`: the amount a signature about to be
    /// made, or about to leave, commits the channel to (a hash-locked state: its plain amount
    /// plus the locked one). Nothing lowers it: a state the seller holds stays claimable until
    /// the channel closes, and one close claims one state, so a later state inside `cum` rides on
    /// this booking. Returns the sats committed by this call.
    fn book_through(&self, dest: &str, cum: i64) -> Result<i64> {
        let Some(rec) = self.book.get(dest) else { return Ok(0) };
        let delta = cum - Self::booked_through(&rec);
        if delta <= 0 {
            return Ok(0);
        }
        let book = self.spend_book.lock().unwrap_or_else(|p| p.into_inner()).clone()
            .ok_or_else(|| err("xbt402", "signed increase has no ledger booking"))?;
        book(dest, delta, &rec.chan, cum)?;
        self.book.mark_ledger_booked(dest, cum)?;
        Ok(delta)
    }

    /// The payee's own word that it has the state `rec` was just sent with (AGP-089, review T4): a
    /// receipt it signed, for this channel and for the seq of this request, with a `cum` no higher
    /// than the one signed. `rec` is the record as the request left with it. A receipt for an
    /// earlier seq is an earlier answer played again: the seller never saw this request. Returns
    /// the receipt and its `cum`.
    fn receipt_for_state<'a>(rec: &ChannelRecord, resp: &'a Value) -> Result<(&'a Value, i64)> {
        let r = receipt_of(resp).map_err(|e| err("bad_receipt", e.to_string()))?;
        if py_str(r.get("chan")) != rec.chan {
            return Err(err("bad_receipt", "receipt is for another channel"));
        }
        if py_int(r.get("seq")) != Some(rec.seq) {
            return Err(err("bad_receipt", "receipt is for another request of this channel (its seq is not this call's)"));
        }
        let cum = py_int(r.get("cum")).ok_or_else(|| err("bad_receipt", "receipt cum is not an integer"))?;
        if cum < 0 || cum > rec.used_sats {
            return Err(err("bad_receipt", "receipt cum is above the amount this wallet signed"));
        }
        let sig = hex::decode(py_str(r.get("sig"))).unwrap_or_default();
        let payee = hex::decode(&rec.payee_pub).map_err(|_| err("bad_receipt", "channel payee_pub is not hex"))?;
        if !ecdsa::verify(&payee, &receipt_message(r), &sig) {
            return Err(err("bad_receipt", "receipt not signed by the channel payee key"));
        }
        Ok((r, cum))
    }

    /// The seller's receipt: signature, seq and request binding, and a `charged` that is not
    /// negative and not above the quote. The number itself is never what the wallet books.
    pub fn check_seller_receipt(rec: &ChannelRecord, resp: &Value, method: &str, url: &str, body: &[u8], answer: (u16, &[u8]), quote: i64) -> Result<i64> {
        let (r, _) = Self::receipt_for_state(rec, resp)?;
        if py_str(r.get("req")) != request_digest_v2(method, url, body) {
            return Err(err("bad_receipt", "receipt is for another request"));
        }
        if r.get("status").and_then(Value::as_u64) != Some(answer.0 as u64) || py_str(r.get("bodyHash")) != body_hash(answer.1) {
            return Err(err("bad_receipt", "receipt is for another answer (status or body differs)"));
        }
        let charged = py_int(r.get("charged")).ok_or_else(|| err("bad_receipt", "charged is not an integer"))?;
        if charged < 0 {
            return Err(err("bad_receipt", "negative charged"));
        }
        if charged > quote {
            return Err(err("bad_receipt", format!("charged {charged} exceeds the quoted price {quote}")));
        }
        Ok(charged)
    }

    /// Sign the state that pays `price` for this call, inside what the policy approved for it.
    /// `Ok(Err(deny))`: refused before anything was signed.
    fn sign_next(&self, dest: &str, price: i64, max_sats: i64, ledger_before: i64) -> Result<std::result::Result<(ChannelRecord, Vec<u8>), Value>> {
        let rec = self.book.get(dest).ok_or_else(|| rt("channel vanished"))?;
        // The policy approved max_sats. Only a channel's first states may sign more, up to the dust
        // floor every state pays; that floor is booked like the rest.
        let next = self.book.next_cum(dest, price)?;
        let floor = rec.params()?.min_amount() as i64;
        let rise = next.checked_sub(ledger_before).ok_or_else(|| rt("the next state is not an amount"))?;
        if rise > max_sats && next > floor {
            return Ok(Err(json!({"verdict": "deny", "rule": "max_sats", "charged_sats": 0,
                                 "reason": format!("the next state signs {next} sat, {rise} more than the ledger holds; max_sats is {max_sats}")})));
        }
        if rise > max_sats {
            let check = self.spend_check.lock().unwrap_or_else(|p| p.into_inner()).clone();
            if let Some(d) = check.map(|c| c(dest, max_sats, rise)).transpose()?.flatten() {
                return Ok(Err(d));
            }
        }
        self.book.increment(dest, price).map(Ok)
    }

    /// The seller's 402 to a state sent again says, in its own (unsigned) words, that it holds
    /// exactly that state, for exactly that request, and that the state does not pay for this call
    /// (`insufficient_payment`). `rec` is the record as the request left with it. Any other refusal
    /// (closing, unconfirmed, exhausted, a state it does not have) is no reason to sign more.
    fn held_and_short(rec: &ChannelRecord, r: &HttpResponse) -> bool {
        if r.status != 402 {
            return false;
        }
        let Some(pr) = r.header("PAYMENT-REQUIRED").and_then(|h| unb64json(h).ok()) else { return false };
        let ch = pr.get("channel");
        let field = |k: &str| ch.and_then(|c| c.get(k));
        pr.get("error").and_then(Value::as_str) == Some("insufficient_payment")
            && field("chan").and_then(Value::as_str) == Some(rec.chan.as_str())
            && py_int(field("cum")) == Some(rec.used_sats)
            && py_int(field("seq")) == Some(rec.seq)
    }

    /// One call. The provider's body and receipt come back only under `untrusted_provider_response`.
    pub fn pay_once(&self, url: &str, method: &str, body: &[u8], max_sats: i64, expiry_blocks: i64, cap_sats: i64) -> Result<Value> {
        let mut res = self.pay_once_inner(url, method, body, max_sats, expiry_blocks, cap_sats)?;
        if let Value::Object(m) = &mut res {
            if m.contains_key("body") || m.contains_key("receipt") {
                let b = m.remove("body").map(|b| b.as_str().unwrap_or("").to_string()).unwrap_or_default();
                let r = m.remove("receipt").unwrap_or(Value::Null);
                m.insert(UNTRUSTED_KEY.into(), untrusted(&b, r));
            }
        }
        Ok(res)
    }

    fn pay_once_inner(&self, url: &str, method: &str, body: &[u8], max_sats: i64, expiry_blocks: i64, cap_sats: i64) -> Result<Value> {
        // AGP-081 (review T2): before the first request, so nothing is opened or signed for it
        xbt402::wire::no_fragment(url)?;
        let dest = origin_of(url)?;
        let t0 = Instant::now();
        let cap = body_cap();
        let r = self.http(method, url, body, &[])?;
        if r.status != 402 {
            let stored = if r.body.len() > cap { store_body(&r.body, &format!("free-{}", now_f64() as i64)) } else { json!({}) };
            log_call("call", json!({"url": url, "status": r.status, "ms": ms_since(t0), "chargedSat": 0, "chan": null}));
            let mut out = json!({"status": r.status, "charged_sats": 0, "body": preview(&r.body, cap), "note": "no 402 (already free or error)"});
            merge(&mut out, stored);
            return Ok(out);
        }
        let pr = unb64json(r.header("PAYMENT-REQUIRED").ok_or_else(|| rt("402 without PAYMENT-REQUIRED"))?)
            .map_err(|_| rt("402 with an unreadable PAYMENT-REQUIRED"))?;
        let acc = pick_accept(&pr, &self.network()?)?;
        if acc.get("extra").and_then(|e| e.get("forward")).is_some_and(Value::is_object) {
            // the forward rail (B2 forward.py) is not in this signer: refuse before any payment
            return Ok(json!({"verdict": "deny", "rule": "forward_disabled",
                             "reason": "the forward rail is not available in this signer (not ported to the Rust signer)"}));
        }
        let price = py_int(acc.get("amount")).ok_or_else(|| rt("offer amount is not an integer"))?;
        if price < 0 {
            // the seller's number, read signed: a negative one is neither above max_sats nor zero,
            // so a free-only call (max_sats 0) went on to fund a channel (AGP-095, audit item 4)
            return Err(rt("offer amount is negative; nothing was opened or signed"));
        }
        if price > max_sats {
            return Ok(json!({"verdict": "deny", "rule": "max_sats", "reason": format!("quoted {price} > max_sats {max_sats}")}));
        }
        if price == 0 {
            let stored = if r.body.len() > cap { store_body(&r.body, &format!("free-{}", now_f64() as i64)) } else { json!({}) };
            log_call("call", json!({"url": url, "status": r.status, "ms": ms_since(t0), "chargedSat": 0, "chan": null}));
            let mut out = json!({"status": r.status, "charged_sats": 0, "body": preview(&r.body, cap), "note": "zero-priced offer; no channel"});
            merge(&mut out, stored);
            return Ok(out);
        }
        let mut opened = Value::Null;
        let rec = self.book.get(&dest);
        if rec.as_ref().is_none_or(|r| r.state != "open") {
            // a closed or refunded channel is replaced by a new one
            let t1 = Instant::now();
            let rec_pub = if rec.as_ref().is_some_and(|r| r.state == "pending") {
                self.complete_open(&dest, self.open_wait_s)? // funded earlier, not yet open (P1, P2)
            } else {
                self.open_from_offer(&dest, &acc, cap_sats, expiry_blocks)?
            };
            let rec = self.book.get(&dest).ok_or_else(|| rt("channel vanished"))?;
            if rec.state == "pending" {
                return Ok(json!({"verdict": "pending", "rule": "funding_unconfirmed", "chan": rec.chan, "funding_txid": rec.funding_txid,
                                 "confirmations": rec_pub.get("confirmations").cloned().unwrap_or(0.into()), "min_conf": rec.min_conf,
                                 "charged_sats": 0,
                                 "reason": "channel funded; its open waits for the funding to confirm. Call again later: the watcher also \
                                            opens it, and refunds it at expiry if it never opens"}));
            }
            opened = rec_pub;
            opened["funding_txid"] = rec.funding_txid.clone().into();
            opened["funding_sats"] = rec.funding_sats.into();
            log_call("open", json!({"url": url, "chan": rec.chan, "txid": rec.funding_txid, "capacity": rec.funding_sats, "cap": rec.cap_sats,
                                    "ms": ms_since(t1)}));
        }
        let rec = self.book.get(&dest).ok_or_else(|| rt("channel vanished"))?;
        let ledger_before = Self::booked_through(&rec);
        let resend = !rec.last_sig.is_empty() && rec.used_sats > rec.acked_sats;
        let payload = |rec: &ChannelRecord, sig: &[u8]| {
            let mut pl = json!({"chan": rec.chan, "seq": rec.seq, "cum": rec.used_sats.to_string()});
            if !sig.is_empty() {
                pl["sig"] = hex::encode(sig).into();
            }
            pl
        };
        let (mut rec, sig) = if resend {
            self.book.resend_state(&dest)? // same (cum, sig); do not sign a higher one (M3)
        } else {
            match self.sign_next(&dest, price, max_sats, ledger_before)? {
                Ok(signed) => signed,
                Err(deny) => return Ok(deny),
            }
        };
        // AGP-063 W1: book the signed increase before the signature leaves. Never the seller's charged.
        let mut booked = self.book_unbooked(&dest)?;
        let (mut r2, mut receipt) = self.paid(method, url, body, &acc, payload(&rec, &sig))?;
        // AGP-095 (audit item 3). The rule: **one call signs at most one new state, and signs it
        // only when the seller holds the last one**: because a receipt acked it, or because the
        // seller, sent that state again, answers that it has it and that it does not pay for this
        // call. That is what a seller answers once it has served a call whose answer was lost: it
        // charged the call, the wallet has no receipt, and a state that is only ever sent again
        // never covers the next call, so the channel stopped for good. The call is paid once, by
        // the one new state; the 402 is not a receipt and acks nothing.
        if resend && Self::held_and_short(&rec, &r2) {
            let (rec2, sig2) = match self.sign_next(&dest, price, max_sats, ledger_before)? {
                Ok(signed) => signed,
                Err(deny) => return Ok(deny),
            };
            booked += self.book_unbooked(&dest)?;
            (r2, receipt) = self.paid(method, url, body, &acc, payload(&rec2, &sig2))?;
            rec = rec2;
        }
        // AGP-089 (review T4): the state counts as arrived only on the payee's signature over this
        // request's seq. Any other PAYMENT-RESPONSE (none, one for an earlier request, one someone
        // on the path made up) leaves it unacked, so the next call sends the same state again and
        // signs nothing higher.
        if let Some((_, cum)) = receipt.as_ref().and_then(|resp| Self::receipt_for_state(&rec, resp).ok()) {
            self.book.ack_state(&dest, Some(cum))?;
        }
        // The state is paid and booked whatever the receipt says.
        let checked = receipt.as_ref().ok_or_else(|| err("bad_receipt", "paid call returned no receipt"))
            .and_then(|resp| Self::check_seller_receipt(&rec, resp, method, url, body, (r2.status, &r2.body), price));
        let mut receipt_error = None;
        let charged = match checked {
            Ok(c) if r2.status < 400 => c,
            Ok(_) => 0,
            Err(e) if r2.status < 400 => {
                // An answer below 400 is the seller's only with the receipt that covers its status
                // and body: without one, anyone on the path can put any body under a paid call. It
                // is refused and its body is not handed on (as the library client and B2 do).
                log_call("call", json!({"url": url, "status": r2.status, "ms": ms_since(t0), "chargedSat": 0, "chan": rec.chan,
                                        "cum": rec.used_sats, "opened": !opened.is_null(), "refused": "bad_receipt"}));
                return Ok(json!({"verdict": "deny", "rule": "bad_receipt", "status": r2.status, "charged_sats": 0, "booked_sats": booked, "chan": rec.chan,
                                 "cum": rec.used_sats, "opened": opened,
                                 "reason": format!("{}; the answer is not handed on. The state this call signed stays booked and is sent again by the next call",
                                                   e.msg)}));
            }
            Err(e) => {
                if receipt.is_some() {
                    receipt_error = Some(e.msg); // an error answer needs no receipt; a bad one is reported
                }
                0
            }
        };
        log_call("call", json!({"url": url, "status": r2.status, "ms": ms_since(t0), "chargedSat": charged, "chan": rec.chan,
                                "cum": rec.used_sats, "opened": !opened.is_null()}));
        let stored = if r2.body.len() > cap { store_body(&r2.body, &format!("{}-{}", &rec.chan[..rec.chan.len().min(12)], rec.seq)) } else { json!({}) };
        let mut res = json!({"status": r2.status, "charged_sats": charged, "booked_sats": booked, "receipt": receipt, "chan": rec.chan, "cum": rec.used_sats,
                             "opened": opened, "body": preview(&r2.body, cap)});
        if let Some(e) = receipt_error {
            res["receipt_error"] = e.into();
        }
        merge(&mut res, stored);
        let Ok(doc) = serde_json::from_slice::<Value>(&r2.body) else { return Ok(res) };
        if r2.status == 200 && doc.get("stream").and_then(Value::as_str) == Some("xbt402-merkle-v1") {
            res["receipt_scope"] = "manifest call only; chunk payments are in stream.paid_sats".into();
            let s = self.stream(&dest, &acc, &doc, CallBudget { start: ledger_before, max_sats });
            let sc = s.get("stream_charged").and_then(Value::as_i64).unwrap_or(0);
            merge(&mut res, s);
            if let Value::Object(m) = &mut res {
                m.remove("stream_charged");
            }
            res["charged_sats"] = (charged + sc).into();
            let after = self.book.get(&dest).map(|r| Self::booked_through(&r)).unwrap_or(ledger_before);
            res["booked_sats"] = (after - ledger_before).into();
        }
        Ok(res)
    }

    // --- streams (stream.py) -------------------------------------------------------------------------

    /// Buy a stream inside what this call may still sign (`budget`). The manifest's `n` and
    /// `price` are the seller's numbers: their product is checked arithmetic, and each chunk's
    /// state is held to the budget again before it is signed (AGP-089, review W1).
    fn stream(&self, dest: &str, acc: &Value, doc: &Value, budget: CallBudget) -> Value {
        let m = doc.get("manifest").cloned().unwrap_or(json!({}));
        let t0 = Instant::now();
        let pay_to = acc.get("payTo").and_then(Value::as_str).unwrap_or("");
        if let Err(e) = check_manifest(&m, pay_to) {
            return json!({"stream_charged": 0, "stream": {"ok": false, "refused": e}});
        }
        let n = py_int(m.get("n")).unwrap_or(0);
        let price = py_int(m.get("price")).unwrap_or(0);
        if n < 1 || price < 0 {
            return json!({"stream_charged": 0, "stream": {"ok": false, "refused": "manifest has no chunks"}});
        }
        let signed = self.book.get(dest).map(|r| r.used_sats.max(Self::booked_through(&r))).unwrap_or(i64::MAX);
        let left = budget.max_sats.saturating_sub(signed.saturating_sub(budget.start));
        // the last state of the stream is `signed + n * price`; a product or sum that does not fit is refused
        let fits = n.checked_mul(price).and_then(|cost| signed.checked_add(cost)).is_some_and(|end| budget.fits(end));
        if !fits {
            return json!({"stream_charged": 0, "body": "",
                          "stream": {"ok": false, "refused": format!("result costs {n} x {price} sat more; max_sats leaves {left}")}});
        }
        let chunk_url = doc.get("chunkUrl").and_then(Value::as_str).unwrap_or("");
        // AGP-080 X1: every chunk is fetched from the origin that was allowed, wherever the seller points
        let chunk_at = |i: i64| seller_url(dest, &chunk_url.replace("{i}", &i.to_string()));
        if let Err(e) = chunk_at(0) {
            return json!({"stream_charged": 0, "body": "", "stream": {"ok": false, "refused": format!("chunkUrl: {}", e.msg)}});
        }
        let mid = m.get("id").cloned().unwrap_or(Value::Null);
        let (mut parts, mut spent) = (Vec::<u8>::new(), 0i64);
        for i in 0..n - 1 {
            let url = chunk_at(i).unwrap_or_default();
            let t = Instant::now();
            let step = || -> ChunkStep {
                let rec = self.book.fresh_seq(dest).map_err(|e| (e.msg, 0, String::new()))?;
                let (r, receipt) = self.paid("GET", &url, b"", acc, json!({"chan": rec.chan, "seq": rec.seq, "cum": rec.used_sats.to_string()}))
                    .map_err(|e| (e.msg, 0, rec.chan.clone()))?;
                let charged = charged_of(receipt.as_ref(), 0);
                if r.status != 200 {
                    return Err((format!("chunk {i}: HTTP {}", r.status), charged, rec.chan));
                }
                let c: Value = serde_json::from_slice(&r.body).map_err(|_| (format!("chunk {i}: not JSON"), charged, rec.chan.clone()))?;
                let data = check_chunk(&m, &c).map_err(|e| (e, charged, rec.chan.clone()))?;
                Ok((data, charged, rec.chan))
            };
            match step() {
                Err((reason, charged, chan)) => {
                    log_call("refused_chunk", json!({"i": i, "reason": reason, "refusedSat": charged, "chan": chan, "url": url}));
                    return json!({"stream_charged": spent, "body": "",
                                  "stream": {"ok": false, "id": mid, "refused_chunk": i, "reason": reason, "verified_chunks": i, "paid_sats": spent,
                                             "unpaid_refused_sats": charged,
                                             "note": "the wallet never signed a state paying for the bad chunk; buying stopped"}});
                }
                Ok((data, _, _)) => {
                    parts.extend(data);
                    if let Err(e) = self.within(dest, &budget, price) {
                        // refused before signing: nothing was paid for this chunk
                        return json!({"stream_charged": spent, "body": "",
                                      "stream": {"ok": false, "id": mid, "refused_chunk": i, "reason": e.msg, "verified_chunks": i, "paid_sats": spent}});
                    }
                    let paid = self.book.increment(dest, price).and_then(|(rec, sig)| {
                        self.book_unbooked(dest)?;
                        self.verify_post(dest, acc, json!({"chan": rec.chan, "cum": rec.used_sats.to_string(), "sig": hex::encode(sig)}))?;
                        Ok(rec)
                    });
                    match paid {
                        Ok(rec) => {
                            spent += price;
                            log_call("chunk", json!({"i": i, "ms": ms_since(t), "chargedSat": price, "chan": rec.chan, "cum": rec.used_sats}));
                        }
                        Err(e) => {
                            return json!({"stream_charged": spent + price, "body": "",
                                          "stream": {"ok": false, "id": mid, "refused_chunk": i, "reason": e.msg, "verified_chunks": i + 1,
                                                     "paid_sats": spent + price}});
                        }
                    }
                }
            }
        }
        let (pt, final_ms) = match self.final_chunk(dest, doc, &m, &budget) {
            Ok(x) => x,
            Err(e) => {
                let chan = self.book.get(dest).map(|r| r.chan).unwrap_or_default();
                log_call("refused_chunk", json!({"i": n - 1, "reason": e, "refusedSat": 0, "chan": chan}));
                return json!({"stream_charged": spent, "body": "",
                              "stream": {"ok": false, "id": mid, "refused_chunk": n - 1, "reason": e, "verified_chunks": n - 1, "paid_sats": spent}});
            }
        };
        spent += price;
        parts.extend(pt);
        let report = parts;
        let mut stored = store_body(&report, &py_str(m.get("id")));
        let mut path = stored.get("saved_to").and_then(Value::as_str).map(str::to_string);
        if let Some(p) = path.clone().filter(|p| p.ends_with(".bin")) {
            let md = format!("{}.md", &p[..p.len() - 4]);
            if std::fs::rename(&p, &md).is_ok() {
                stored["saved_to"] = md.clone().into();
                path = Some(md);
            }
        }
        let chan = self.book.get(dest).map(|r| r.chan).unwrap_or_default();
        log_call("stream", json!({"id": mid, "n": n, "bytes": report.len(), "sats": spent, "root": m.get("root"), "ms": ms_since(t0),
                                  "final_ms": final_ms, "chan": chan}));
        let text = String::from_utf8_lossy(&report).into_owned();
        let pv: String = text.chars().take(PREVIEW_CAP).collect();
        let digest = stored["body_digest"].as_str().unwrap_or("").to_string();
        let more = format!("\n\u{2026} [{} bytes, sha256 {digest}{}]", report.len(), path.as_ref().map(|p| format!(", saved to {p}")).unwrap_or_default());
        let mut out = json!({"stream_charged": spent, "body": if text.chars().count() > PREVIEW_CAP { format!("{pv}{more}") } else { pv },
                             "stream": {"ok": true, "id": mid, "chunks": n, "bytes": report.len(), "merkle_root": m.get("root"), "paid_sats": spent,
                                        "all_chunks_verified": true, "last_chunk": "hash-locked, key checked", "body_digest": digest}});
        if let Some(p) = path {
            out["stream"]["saved_to"] = p.into();
        }
        merge(&mut out, stored);
        out
    }

    /// AGP-089: the state a charge of `price` would sign is inside this call's budget. Called
    /// before every state a stream signs, so no arithmetic on the seller's numbers decides alone.
    fn within(&self, dest: &str, budget: &CallBudget, price: i64) -> Result<()> {
        let next = self.book.next_cum(dest, price)?;
        if !budget.fits(next) {
            return Err(err("max_sats", format!("the next state signs {next} sat; max_sats {} from {} does not cover it", budget.max_sats, budget.start)));
        }
        Ok(())
    }

    /// Hand the provider a signed state through /x402/verify.
    fn verify_post(&self, dest: &str, acc: &Value, payload: Value) -> Result<()> {
        let r = self.http("POST", &format!("{dest}{FACILITATOR_VERIFY}"), dumps(&facilitator_request(acc, &payload)).as_bytes(),
                          &[("Content-Type".into(), "application/json".into())])?;
        let valid = r.status == 200 && serde_json::from_slice::<Value>(&r.body).ok().and_then(|v| v.get("isValid").cloned()) == Some(Value::Bool(true));
        if !valid {
            return Err(rt(format!("provider refused our payment state (HTTP {})", r.status)));
        }
        Ok(())
    }

    fn final_chunk(&self, dest: &str, doc: &Value, m: &Value, budget: &CallBudget) -> std::result::Result<(Vec<u8>, f64), String> {
        let t = Instant::now();
        let n = py_int(m.get("n")).unwrap_or(0);
        let price = py_int(m.get("price")).unwrap_or(0);
        let last = n.checked_sub(1).filter(|l| *l >= 0).ok_or_else(|| "manifest has no chunks".to_string())?;
        let url = seller_url(dest, &doc.get("chunkUrl").and_then(Value::as_str).unwrap_or("").replace("{i}", &last.to_string())).map_err(|e| e.msg)?;
        let not_offered = || "last chunk is not offered under the manifest's hash lock".to_string();
        let r = self.http("GET", &url, b"", &[]).map_err(|e| e.msg)?;
        let Some(h) = r.header("PAYMENT-REQUIRED").filter(|_| r.status == 402) else { return Err(not_offered()) };
        let net = self.network().map_err(|e| e.msg)?;
        let acc = unb64json(h).ok().and_then(|pr| pick_accept(&pr, &net).ok()).ok_or_else(not_offered)?;
        let cond = acc.get("extra").and_then(|e| e.get("conditional")).cloned().unwrap_or(json!({}));
        if cond.get("hash") != m.get("lock") || py_int(cond.get("amount")).unwrap_or(0) != price {
            return Err(not_offered());
        }
        // M7: the ciphertext comes before the signature
        let cipher = cond.get("cipher").and_then(Value::as_str).and_then(|c| hex::decode(c).ok())
            .ok_or_else(|| "last chunk offer carries no ciphertext; refused before signing".to_string())?;
        if Some(hex::encode(sha256(&cipher)).as_str()) != m.get("finalCt").and_then(Value::as_str) {
            return Err("last chunk offer's ciphertext does not match the committed finalCt; refused before signing".into());
        }
        let hash: [u8; 32] = cond.get("hash").and_then(Value::as_str).and_then(|x| hex::decode(x).ok()).and_then(|v| v.try_into().ok())
            .ok_or_else(not_offered)?;
        // the seller's number: how long the chunk's price stays locked if the key never comes
        let csv = u32::try_from(py_int(cond.get("csvDelta")).unwrap_or(10)).ok().filter(|c| *c <= MAX_COND_CSV_BLOCKS)
            .ok_or_else(|| format!("last chunk offer's csvDelta is not a block count up to {MAX_COND_CSV_BLOCKS}; refused before signing"))?;
        let manifest: serde_json::Map<String, Value> = ["id", "n", "root", "lock", "finalCt", "lastProof"].iter()
            .map(|k| (k.to_string(), m.get(*k).cloned().unwrap_or(Value::Null))).collect();
        let pending = json!({"hash": hex::encode(hash), "cipher": hex::encode(&cipher), "manifest": manifest});
        // AGP-080 W1: the hash-locked state pays the plain amount plus this chunk to whoever holds
        // the key, so the ledger holds both before it is signed. The plain state that folds the
        // lock in then books nothing more; a seller that keeps the signature and withholds the key
        // releases nothing.
        let uncond = self.book.get(dest).map(|r| r.used_sats).ok_or_else(|| "channel vanished".to_string())?;
        let locked = uncond.checked_add(price).filter(|c| price > 0 && budget.fits(*c))
            .ok_or_else(|| "the last chunk's hash-locked state is above what max_sats leaves; refused before signing".to_string())?;
        self.book_through(dest, locked).map_err(|e| e.msg)?;
        let (rec, sig) = self.book.sign_stream_final(dest, hash, price as u64, csv, pending).map_err(|e| e.msg)?;
        let payload = json!({"chan": rec.chan, "seq": rec.seq, "cum": rec.used_sats.to_string(), "hashlock": hex::encode(hash), "sig": hex::encode(&sig)});
        let (r, _) = self.paid("GET", &url, b"", &acc, payload).map_err(|e| e.msg)?;
        if r.status != 200 {
            return Err(format!("conditional purchase of the last chunk failed: HTTP {}; if the provider claims the hash lock, \
                                recover_conditional() opens the chunk", r.status));
        }
        let k = serde_json::from_slice::<Value>(&r.body).ok().and_then(|v| v.get("preimage").and_then(Value::as_str).and_then(|p| hex::decode(p).ok()))
            .ok_or_else(|| "paid response carries no key; if the provider claims the hash lock, recover_conditional() opens the chunk".to_string())?;
        let pt = open_final(m, &cipher, &k)?; // the offered ciphertext, never one the response substitutes
        self.book.clear_pending_cond(dest).map_err(|e| e.msg)?;
        let (rec, sig2) = self.book.increment(dest, price).map_err(|e| e.msg)?;
        self.book_unbooked(dest).map_err(|e| e.msg)?;
        self.verify_post(dest, &acc, json!({"chan": rec.chan, "cum": rec.used_sats.to_string(), "sig": hex::encode(sig2)})).map_err(|e| e.msg)?;
        let ms = ms_since(t);
        log_call("chunk", json!({"i": last, "ms": ms, "chargedSat": price, "chan": rec.chan, "cum": rec.used_sats, "hashlock": hex::encode(hash)}));
        Ok((pt, ms))
    }

    /// The last chunk of a stream whose hash lock was signed but whose paid response never came,
    /// from the provider's claim transaction (which reveals k on-chain).
    pub fn recover_conditional(&self, dest: &str, claim: &Tx) -> Result<Vec<u8>> {
        let pc = self.book.get(dest).map(|r| r.pending_cond).filter(|p| truthy(Some(p)))
            .ok_or_else(|| rt("no pending conditional purchase on this channel"))?;
        let hash: [u8; 32] = hex::decode(pc["hash"].as_str().unwrap_or("")).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| rt("hash"))?;
        let k = preimage_from_tx(claim, &hash).ok_or_else(|| rt("this transaction does not reveal the hash lock's key"))?;
        let pt = open_final(&pc["manifest"], &hex::decode(pc["cipher"].as_str().unwrap_or("")).unwrap_or_default(), &k).map_err(rt)?;
        self.book.clear_pending_cond(dest)?;
        Ok(pt)
    }

    // --- close ------------------------------------------------------------------------------------------

    /// The close's raw hex, if the provider's (untrusted) reply has it: kept only when it is the
    /// reported txid and spends this channel's funding output.
    fn close_hex(reply: Option<&Value>, txid: Option<&str>, rec: &ChannelRecord) -> String {
        let h = reply.and_then(|r| r.get("hex").or_else(|| r.get("closeHex"))).and_then(Value::as_str);
        let (Some(txid), Some(h)) = (txid, h) else { return String::new() };
        if h.len() >= 20_000 {
            return String::new();
        }
        let Ok(tx) = Tx::parse_hex(h) else { return String::new() };
        let spends = tx.inputs.iter().any(|i| i.prevout.txid_hex() == rec.funding_txid && i.prevout.vout as i64 == rec.funding_vout);
        if tx.txid() == txid && spends { h.to_string() } else { String::new() }
    }

    /// AGP-022: one attempt at counting a close's change. With the close's hex, our own node is
    /// handed the tx first.
    pub fn learn_close_change(&self, rec: &ChannelRecord, txid: &str, scan_from: i64, close_hex: &str) -> Value {
        if !close_hex.is_empty() {
            let _ = self.node.call("sendrawtransaction", json!([close_hex]));
        }
        let start = [scan_from, rec.close_scan_from, rec.funding_height, rec.open_height].into_iter().find(|v| *v != 0).unwrap_or(0);
        let t = if txid.is_empty() { rec.closed_txid.as_str() } else { txid };
        match self.hot.learn_close_change(t, (&rec.funding_txid, rec.funding_vout as u32), start.max(0) as u64, crate::hot::CLOSE_SCAN_MAX) {
            Ok(v) => v,
            Err(e) => json!({"status": "pending", "txid": t, "scan_from": start, "added": 0, "error": e.msg.chars().take(160).collect::<String>()}),
        }
    }

    /// Cooperative close through the signer: payer signs `tagged_hash(xbt402/close, chan)`.
    pub fn close_channel(&self, dest: &str) -> Result<Value> {
        let (dest, rec) = match self.book.get(dest) {
            Some(r) => (dest.to_string(), r),
            None => {
                let d = self.book.find_dest(dest).unwrap_or_else(|| dest.to_string());
                let r = self.book.get(&d).ok_or_else(|| rt(format!("no channel for {d}")))?;
                (d, r)
            }
        };
        let sig = self.book.sign_close(&dest)?;
        let origin = if rec.origin.is_empty() { dest.clone() } else { rec.origin.clone() };
        let close_url = format!("{}/x402/xbt-channel/close", origin.trim_end_matches('/'));
        let payload = json!({"chan": rec.chan, "seq": rec.seq, "cum": rec.used_sats.to_string()});
        let body = json!({"chan": rec.chan, "sig": sig, "payload": payload});
        let h0 = self.height().unwrap_or(0) as i64; // AGP-022: no block before this one can hold the close
        let r = self.http("POST", &close_url, dumps(&body).as_bytes(), &[("Content-Type".into(), "application/json".into())])
            .map_err(|_| rt("close failed: provider unreachable"))?;
        if r.status != 200 {
            return Err(rt(format!("close failed: HTTP {}", r.status)));
        }
        let reply: Option<Value> = serde_json::from_slice(&r.body).ok();
        // the provider's reply is untrusted data: only a txid-shaped txid becomes the wallet's own field
        let txid = reply.as_ref().and_then(|r| r.get("txid")).and_then(Value::as_str)
            .filter(|t| t.len() == 64 && t.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))).map(str::to_string);
        let report = Self::close_report(reply.as_ref(), &rec);
        let close_hex = Self::close_hex(reply.as_ref(), txid.as_deref(), &rec);
        if let (Some(mine), Some(_)) = (&self.mine, &txid) {
            let _ = mine(1); // regtest only (P3)
        }
        // the provider broadcast the close on its node; ours may get it later (P2P) or only in a
        // block: learn the change now if we can, then mark the channel closed with the answer
        let change = self.learn_close_change(&rec, txid.as_deref().unwrap_or(""), h0, &close_hex);
        self.book.mark_closed(&dest, txid.as_deref().unwrap_or(""), Some(&change), &close_hex)?;
        // AGP-080 W3: the reply is the provider's word. Only our node showing the funding spent
        // proves the close; until then the record stays with the refund watcher.
        let (proven, spender) = match self.funding_spend(&rec) {
            Ok(FundingSpend::Spent(sp)) => (true, sp),
            _ => (false, String::new()),
        };
        self.book.note_close_proof(&dest, proven, &spender)?;
        let hot_spk = self.hot.spk_hex();
        log_call("close", json!({"dest": dest, "chan": rec.chan, "txid": txid, "cum": rec.used_sats, "change_spk": rec.payer_spk,
                                 "hot_spk": hot_spk, "close_change": change["status"]}));
        Ok(json!({"verdict": "allow", "rail": "xbt402", "dest": dest, "txid": txid, "chan": rec.chan, "cum": rec.used_sats,
                  "change_spk": rec.payer_spk, "hot_spk": hot_spk, "change_to_hot": rec.payer_spk == hot_spk,
                  "close_change": change["status"], "close_proven": proven, "close_report": report,
                  UNTRUSTED_KEY: untrusted(&preview(&r.body, body_cap()), Value::Null)}))
    }

    /// B2 `close_report` (AGP-029, agp-next3 `6090990`): the provider's (untrusted) close amounts, as
    /// integers only, checked against our own state. xbt402 v1.2: `cum` is the gross state we paid,
    /// `unpaidMsat` = spent - cum, and a payee-pays channel adds `payeeFee` (the provider's own close
    /// fee) and `payeeNet`. status: "ok" when the report matches what we signed and owes nothing;
    /// "debt" when the provider says we still owe; "mismatch" when its numbers disagree.
    pub fn close_report(reply: Option<&Value>, rec: &ChannelRecord) -> Value {
        let num = |k: &str| -> Option<i64> {
            match reply.and_then(|r| r.get(k)) {
                Some(Value::Number(n)) => n.as_i64().filter(|v| *v >= 0),
                Some(Value::String(s)) => s.trim().parse::<i64>().ok().filter(|v| *v >= 0),
                _ => None,
            }
        };
        let (cum, unpaid, fee, net) = (num("cum"), num("unpaidMsat"), num("payeeFee"), num("payeeNet"));
        let payee_pays = rec.close_fee_payer == "payee";
        let fee_ok = if payee_pays { fee == Some(rec.close_fee) && net == Some(cum.unwrap_or(0) - rec.close_fee) } else { fee.is_none() && net.is_none() };
        let status = if unpaid.is_some_and(|u| u != 0) {
            "debt"
        } else if cum != Some(rec.used_sats) || unpaid.is_none() || !fee_ok {
            "mismatch"
        } else {
            "ok"
        };
        let mut out = json!({"status": status, "cum": cum, "unpaid_msat": unpaid});
        if payee_pays {
            out["payee_fee"] = fee.into();
            out["payee_net"] = net.into();
        }
        out
    }
}

// --- stream verification (stream.py) ------------------------------------------------------------

fn h(b: &[u8]) -> [u8; 32] {
    sha256(b)
}

pub fn leaf(i: u32, chunk: &[u8]) -> [u8; 32] {
    let mut b = b"leaf".to_vec();
    b.extend(i.to_be_bytes());
    b.extend(h(chunk));
    h(&b)
}

fn node_hash(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut v = b"node".to_vec();
    v.extend(a);
    v.extend(b);
    h(&v)
}

pub fn verify_proof(root_hex: &str, i: i64, chunk: &[u8], proof: &Value) -> bool {
    let Ok(mut i) = u32::try_from(i) else { return false };
    let mut cur = leaf(i, chunk);
    for sib in proof.as_array().into_iter().flatten() {
        let Some(s) = sib.as_str().and_then(|x| hex::decode(x).ok()) else { return false };
        cur = if i % 2 == 0 { node_hash(&cur, &s) } else { node_hash(&s, &cur) };
        i /= 2;
    }
    hex::encode(cur) == root_hex
}

pub fn manifest_message(m: &Value) -> [u8; 32] {
    let keys = ["id", "n", "size", "root", "lock", "finalCt", "price", "payTo"];
    let s: Vec<String> = keys.iter().map(|k| py_str(m.get(*k))).collect();
    tagged_hash("xbt402/stream-manifest", s.join("|").as_bytes())
}

pub fn check_manifest(m: &Value, pay_to: &str) -> std::result::Result<(), String> {
    if m.get("payTo").and_then(Value::as_str) != Some(pay_to) {
        return Err("manifest not from this provider's payTo key".into());
    }
    let good = match (hex::decode(pay_to), m.get("sig").and_then(Value::as_str).and_then(|s| hex::decode(s).ok())) {
        (Ok(pk), Some(sig)) => ecdsa::verify(&pk, &manifest_message(m), &sig),
        _ => false,
    };
    if !good {
        return Err("bad manifest signature".into());
    }
    Ok(())
}

pub fn check_chunk(m: &Value, c: &Value) -> std::result::Result<Vec<u8>, String> {
    let i = py_int(c.get("i")).ok_or("chunk has no index")?;
    let n = py_int(m.get("n")).unwrap_or(0);
    if truthy(c.get("encrypted")) {
        if Some(i) != n.checked_sub(1) {
            return Err(format!("chunk {i}: only the last chunk may be encrypted"));
        }
        let ct = c.get("ct").and_then(Value::as_str).and_then(|x| hex::decode(x).ok()).ok_or(format!("chunk {i}: ct"))?;
        if Some(hex::encode(h(&ct)).as_str()) != m.get("finalCt").and_then(Value::as_str) {
            return Err(format!("chunk {i}: ciphertext does not match the committed finalCt"));
        }
        return Ok(ct);
    }
    let data = c.get("data").and_then(Value::as_str).and_then(|x| hex::decode(x).ok()).ok_or(format!("chunk {i}: data"))?;
    if !verify_proof(m.get("root").and_then(Value::as_str).unwrap_or(""), i, &data, c.get("proof").unwrap_or(&Value::Null)) {
        return Err(format!("chunk {i}: Merkle proof fails against the committed root (tampered)"));
    }
    Ok(data)
}

pub fn open_final(m: &Value, ct: &[u8], key: &[u8]) -> std::result::Result<Vec<u8>, String> {
    if Some(hex::encode(h(ct)).as_str()) != m.get("finalCt").and_then(Value::as_str) {
        return Err("last chunk ciphertext does not match the committed finalCt".into());
    }
    if Some(hex::encode(h(key)).as_str()) != m.get("lock").and_then(Value::as_str) {
        return Err("revealed key does not match the hash lock".into());
    }
    let pt = encrypt(ct, key);
    if !verify_proof(m.get("root").and_then(Value::as_str).unwrap_or(""), py_int(m.get("n")).unwrap_or(0).saturating_sub(1), &pt,
                     m.get("lastProof").unwrap_or(&Value::Null)) {
        return Err("decrypted last chunk fails the Merkle proof (provably bad commitment)".into());
    }
    Ok(pt)
}
