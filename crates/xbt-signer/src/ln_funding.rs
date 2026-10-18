//! AGP-049: a channel's funding, proven from the funding transaction on the signer's own node rather
//! than from the LN node's `unified_sigs` flag. AGP-066 (review L5) corrected the reasoning below and
//! narrowed what counts as a signature.
//!
//! **What must hold.** A channel's commitment, HTLC and close transactions spend its funding output, so
//! they can replay on the SHA-256 chain only if the funding transaction is valid there too (AGP-047 §4.2).
//! A transaction is invalid if any one input is, so it is enough that an input carries a signature its
//! script checks and the SHA-256 chain cannot verify. This module asks for more: every input, and every
//! signature each input's script checks, must be such a signature.
//!
//! **Why 0x21 is such a signature.** Not because the SHA-256 chain rejects the byte: its consensus
//! accepts hash type 0x21 on legacy and segwit v0 inputs (the byte is only non-standard there; taproot
//! does reject it). The protection is the digest. An XBT signer signs a 0x21 signature over the
//! unified message ([`xbt_primitives::sighash::unified_sighash`]: BIP341-shaped, committing to every
//! input's amount and scriptPubKey), while the SHA-256 chain checks the same bytes against its own
//! message (legacy or BIP143 with hash type 0x21). One ECDSA signature valid for two messages under one
//! key would need the two digests to be equal modulo the group order.
//!
//! **Why reading the bytes suffices, without verifying the signatures here.** The funding transaction
//! is read from a block on the signer's own node's best chain, at the position its short channel id
//! names, so that node's consensus has verified every signature each input's script checks against
//! XBT's message for its hash type (or, below an `assumevalid` block, the network that built on it
//! has). What the bytes alone cannot tell is which pushes the script checks: a 0x21-shaped push that
//! the script never checks (`OP_DROP OP_TRUE`, a hash lock) proves nothing. So only spends whose sole
//! condition is signatures are read ([`checked_sighashes`]): P2WPKH, P2SH-P2WPKH, P2PKH, P2WSH or
//! P2SH-P2WSH with a witness script of `<key> CHECKSIG` or `m <keys> n CHECKMULTISIG`, and a taproot key
//! path. Any other input leaves the channel unproven.
//!
//! **What the height does not prove.** A coin confirmed at or above the split is not thereby XBT-only:
//! a transaction valid on both chains (a 0x01 spend of pre-split coins, broadcast on both) has the same
//! txid on each, so its outputs exist on the SHA-256 chain too, however high it confirmed here. Every
//! input's coin must still be confirmed at or above the split height, as an extra, conservative rule
//! (a channel opened after the split never needs older coins).
//!
//! **What a witness signature does not prove (AGP-092).** A segwit or taproot input's signatures are
//! in the witness, and the witness is not part of the txid. So the same funding txid is a valid
//! transaction on the SHA-256 chain, with other signatures in its witnesses, whenever every coin it
//! spends exists there; the 0x21 bytes we read on XBT say nothing about that twin. The rule the proof
//! keeps: **a funding is proven only when its txid cannot be a valid transaction on SHA-256
//! Bitcoin.** That holds when the transaction, or one it descends from through at least one input, is
//! pinned to XBT by something its txid commits to ([`xbt_only`]): it is a coinbase at or above the
//! split, or one of its inputs carries a 0x21 signature in its scriptSig (a P2PKH spend). One pinned
//! input is enough, since a transaction is invalid where one of its coins does not exist. The search
//! goes back through coins confirmed at or above the split (below it every transaction is on both
//! chains) and looks up at most [`ANCESTRY_LOOKUPS`] transactions. A funding with no such ancestor in
//! reach is refused: the owner funds the channel from mined coins, or from coins that passed through
//! a P2PKH address after the split.
//!
//! **What the coinbase pin rests on (AGP-097, read from XBT's consensus code, Knots `61b07b8`).**
//! The scriptSig pin holds by itself: the txid commits to a signature the SHA-256 chain cannot
//! verify. The coinbase pin does not. A coinbase's txid commits to nothing that names the chain: it
//! is the double SHA-256 of the same bytes on both chains (`primitives/transaction.cpp:81-84`), and
//! what consensus asks of a coinbase after the fork is the block's height at the start of its
//! scriptSig (BIP 34, `validation.cpp:4933-4939`), a value of at most subsidy plus fees
//! (`validation.cpp:3107-3110`, the same subsidy schedule) and, at the fork block only, the fork's
//! headline in the scriptSig (`validation.cpp:4576-4583`); payee attestation, where it is active,
//! constrains outputs the SHA-256 chain accepts as they are. So the coinbase of XBT's block H is a
//! valid coinbase for the SHA-256 chain's block H and for no other block there (the height is in
//! it): it is XBT-only exactly when the other chain already has another block at height H and does
//! not reorganise below it. Where it does not yet, whoever mines that block there can mine the same
//! coinbase, which pays the same keys. That takes a block on each chain at one height from one
//! party, or a miner who gives its block's reward to the other coinbase's payees. The signer has
//! no node of the SHA-256 chain to compare heights with, so it cannot check this; the rule is kept as
//! the owner decided it (2026-10-11) and this is its stated limit.
//!
//! The funding transaction's checks: the channel's txid, output, amount and P2WSH. A lookup that fails
//! leaves the channel unproven, and an unproven channel carries no payment. The verdict carries the
//! funding block's hash, which the signer's cache is keyed on, so a reorg proves the channel again.
//!
//! **What the proof reads from the node, and a pruned node without txindex.** Of each transaction it
//! reads (the funding, then the ancestors it searches) it needs the transaction itself and, of every
//! coin that transaction spends, the coin's scriptPubKey, the height it was confirmed at and whether a
//! coinbase made it. All of that is in the transaction's block and that block's undo data, which a node
//! keeps together and prunes together: `getrawtransaction <txid> 2 <block hash>` returns the
//! transaction with each input's `prevout` from the undo data, with no txindex. The funding's block is
//! at its short channel id's height; an ancestor's is at the height its coin's `prevout` gives, on the
//! same best chain. So a pruned node proves a channel for as long as it keeps the blocks the proof
//! reads, which for a newly opened channel are recent. A node that does not give `prevout` (one older
//! than verbosity 2) is asked for the coin's transaction by txid, which needs txindex. Once the blocks
//! are pruned the proof cannot be made again, so the signer keeps every final verdict on disk
//! ([`Kept`]), keyed as its cache is, and a kept verdict stands for as long as its funding block is on
//! the best chain: a reorg that replaced any block the proof read would replace the funding block too,
//! since every one of them is at or below it. Nothing the proof checks is skipped on any node.
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{json, Map, Value};
use xbt_primitives::script::{classify, SpkKind};
use xbt_primitives::tx::{Tx, TxIn};

use crate::node::{self, Node};

/// SIGHASH_ALL | SIGHASH_UNIFIED (0x20).
pub const SIGHASH_UNIFIED_ALL: u8 = 0x21;
/// Transactions [`xbt_only`] looks up before it gives up (one verdict per channel and funding block:
/// the signer caches it).
pub const ANCESTRY_LOOKUPS: usize = 256;

/// The verdict on one channel's funding.
#[derive(Debug, Clone, PartialEq)]
pub enum Funding {
    /// Every input signed 0x21 and confirmed at or above the split, and the txid pinned to XBT by an
    /// ancestor ([`xbt_only`]): the evidence.
    Proven(Value),
    /// The transaction says the channel is unsafe (or is not the channel's): why, and the evidence.
    Refused(String, Value),
    /// The signer's node could not answer (a block the proof reads is pruned, the node down): not cached.
    Unknown(String),
}

impl Funding {
    /// Whether the verdict is final (cacheable per funding outpoint, for as long as its block stands).
    pub fn is_final(&self) -> bool {
        !matches!(self, Funding::Unknown(_))
    }

    /// The hash of the block the verdict was reached on, when it was reached on one.
    pub fn block_hash(&self) -> Option<&str> {
        match self {
            Funding::Proven(ev) | Funding::Refused(_, ev) => ev.get("block_hash").and_then(Value::as_str),
            Funding::Unknown(_) => None,
        }
    }
}

/// A strict (BIP 66 shaped) DER ECDSA signature followed by one sighash byte: the sighash byte.
pub fn der_sighash(item: &[u8]) -> Option<u8> {
    let n = item.len();
    if !(9..=73).contains(&n) || item[0] != 0x30 || item[1] as usize != n - 3 || item[2] != 0x02 {
        return None;
    }
    let rlen = item[3] as usize;
    if rlen == 0 || 5 + rlen >= n || item[4 + rlen] != 0x02 {
        return None;
    }
    let slen = item[5 + rlen] as usize;
    (slen > 0 && rlen + slen + 7 == n).then(|| item[n - 1])
}

/// The data pushes of a push-only script (`None` if it has any other opcode).
pub fn pushes(script: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut out = vec![];
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        i += 1;
        let n = match op {
            0x00 => 0,
            0x01..=0x4b => op as usize,
            0x4c => {
                let n = *script.get(i)? as usize;
                i += 1;
                n
            }
            0x4d => {
                let n = u16::from_le_bytes([*script.get(i)?, *script.get(i + 1)?]) as usize;
                i += 2;
                n
            }
            0x4e => {
                let b = script.get(i..i + 4)?;
                i += 4;
                u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
            }
            _ => return None,
        };
        out.push(script.get(i..i + n)?.to_vec());
        i += n;
    }
    Some(out)
}

const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKMULTISIG: u8 = 0xae;

/// `OP_1`..`OP_16` as a number.
fn small_int(op: u8) -> Option<usize> {
    (0x51..=0x60).contains(&op).then(|| (op - 0x50) as usize)
}

/// How many signatures a witness script checks, if checking them is all it does: `<key> CHECKSIG`
/// (`Some((1, false))`) or `m <keys> n CHECKMULTISIG` (`Some((m, true))`), compressed keys only.
fn sig_only_script(s: &[u8]) -> Option<(usize, bool)> {
    if s.len() == 35 && s[0] == 0x21 && s[34] == OP_CHECKSIG {
        return Some((1, false));
    }
    let (&first, rest) = s.split_first()?;
    let (&last, rest) = rest.split_last()?;
    let (&nop, keys) = rest.split_last()?;
    let (m, n) = (small_int(first)?, small_int(nop)?);
    (last == OP_CHECKMULTISIG && m <= n && keys.len() == 34 * n && keys.chunks(34).all(|k| k[0] == 0x21)).then_some((m, true))
}

/// The sighash bytes of `items`, each of which must be a DER signature.
fn der_all(items: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    items.iter().map(|i| der_sighash(i).ok_or_else(|| "a pushed signature is not a strict DER signature".to_string())).collect()
}

/// A segwit v0 spend of a 20-byte (P2WPKH) or 32-byte (P2WSH) program.
fn witness_v0(witness: &[Vec<u8>], program_len: usize) -> Result<Vec<u8>, String> {
    if program_len == 20 {
        return match witness {
            [sig, key] if key.len() == 33 => der_all(std::slice::from_ref(sig)),
            _ => Err("its P2WPKH witness is not [signature, compressed key]".into()),
        };
    }
    let (script, items) = witness.split_last().ok_or("its P2WSH witness is empty")?;
    let Some((m, multi)) = sig_only_script(script) else {
        return Err("its witness script is not `<key> CHECKSIG` or `m <keys> n CHECKMULTISIG`: its pushes may be data the script never \
                    checks, so a 0x21 byte among them proves nothing".into());
    };
    match (multi, items) {
        (false, [sig]) => der_all(std::slice::from_ref(sig)),
        (true, [dummy, sigs @ ..]) if dummy.is_empty() && sigs.len() == m => der_all(sigs),
        _ => Err(format!("its witness does not hold exactly the {m} signature(s) its script checks")),
    }
}

/// AGP-066 (review L5): the sighash bytes of exactly the signatures an input's script checks, judged by
/// the coin it spends, or why the input cannot be read: only spends whose sole condition is signatures
/// count (the module documentation says why). A taproot key path signature of 64 bytes is
/// SIGHASH_DEFAULT (0x00).
pub fn checked_sighashes(inp: &TxIn, prev_spk: &[u8]) -> Result<Vec<u8>, String> {
    match classify(prev_spk) {
        Some(SpkKind::P2wpkh) => return witness_v0(&inp.witness, 20),
        Some(SpkKind::P2wsh) => return witness_v0(&inp.witness, 32),
        Some(SpkKind::P2tr) => {
            let mut w: &[Vec<u8>] = &inp.witness;
            if w.len() >= 2 && w.last().is_some_and(|a| a.first() == Some(&0x50)) {
                w = &w[..w.len() - 1]; // the annex
            }
            return match w {
                [s] if s.len() == 64 => Ok(vec![0x00]),
                [s] if s.len() == 65 => Ok(vec![s[64]]),
                [_] => Err("its taproot key path signature is not 64 or 65 bytes".into()),
                _ => Err("a taproot script path spend: which pushes its leaf script checks is not read".into()),
            };
        }
        None => {}
    }
    let p2sh = prev_spk.len() == 23 && prev_spk[..2] == [0xa9, 0x14] && prev_spk[22] == 0x87;
    let p2pkh = prev_spk.len() == 25 && prev_spk[..3] == [0x76, 0xa9, 0x14] && prev_spk[23..] == [0x88, OP_CHECKSIG];
    let pushed = pushes(&inp.script_sig).ok_or("its scriptSig is not push-only")?;
    if p2sh {
        return match pushed.as_slice() {
            [r] if r.len() == 22 && r[..2] == [0x00, 0x14] => witness_v0(&inp.witness, 20),
            [r] if r.len() == 34 && r[..2] == [0x00, 0x20] => witness_v0(&inp.witness, 32),
            _ => Err("a P2SH spend that is not P2SH-P2WPKH or P2SH-P2WSH".into()),
        };
    }
    if p2pkh {
        return match pushed.as_slice() {
            [sig, key] if key.len() == 33 || key.len() == 65 => der_all(std::slice::from_ref(sig)),
            _ => Err("its P2PKH scriptSig is not [signature, key]".into()),
        };
    }
    Err("it spends a script the proof cannot read (not P2WPKH, P2WSH, P2TR, P2SH-wrapped segwit or P2PKH)".into())
}

fn height_of_block(node: &dyn Node, blockhash: &str) -> Option<i64> {
    node.call("getblockheader", json!([blockhash])).ok()?.get("height").and_then(Value::as_i64)
}

fn tx_hex(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string).or_else(|| v.get("hex").and_then(Value::as_str).map(str::to_string))
}

fn is_coinbase(tx: &Tx) -> bool {
    tx.inputs.len() == 1 && tx.inputs[0].prevout.txid == [0u8; 32] && tx.inputs[0].prevout.vout == 0xFFFF_FFFF
}

/// What a proof our node cannot make needs of it: said with every such verdict.
pub const NEEDS: &str = "the proof reads the funding's block and the blocks behind it on the signer's node: a pruned node proves a channel while \
                         it still has them (soon after the channel opens), and the signer then keeps the verdict on disk; an unpruned node with \
                         txindex=1 proves it at any time";

/// The coin an input spends, as our node has it: its scriptPubKey, the height of the block that
/// confirmed it (on our node's best chain) and whether a coinbase made it.
#[derive(Debug, Clone, PartialEq)]
pub struct Coin {
    pub spk: Vec<u8>,
    pub height: i64,
    pub coinbase: bool,
}

/// What our node says of the coins a transaction's inputs spend, one per input.
pub type Coins = Vec<Result<Coin, Miss>>;

/// Why our node gave nothing for a lookup.
#[derive(Debug, Clone, PartialEq)]
pub enum Miss {
    /// It answered without it: a pruned block, a transaction it does not index.
    Gone(String),
    /// What it returned is not what was asked for (another txid, another input).
    Bad(String),
    /// It did not answer.
    NoAnswer(String),
}

impl Miss {
    fn of(e: crate::Error) -> Self {
        if e.code == node::REFUSED { Miss::Gone(e.msg) } else { Miss::NoAnswer(e.msg) }
    }

    fn text(&self) -> &str {
        match self {
            Miss::Gone(s) | Miss::Bad(s) | Miss::NoAnswer(s) => s,
        }
    }
}

/// `txid` from our node's block `bh`, and the node's verbose answer: `getrawtransaction <txid> 2 <bh>`,
/// whose inputs carry their `prevout` from the block's undo data. Needs the block, not txindex.
fn in_block(node: &dyn Node, txid: &str, bh: &str) -> Result<(Tx, Value), Miss> {
    let v = node.call("getrawtransaction", json!([txid, 2, bh])).map_err(Miss::of)?;
    if v.is_null() {
        return Err(Miss::Gone(format!("our node has no transaction {txid} in block {bh}")));
    }
    let tx = tx_hex(&v).and_then(|h| Tx::parse_hex(&h).ok()).filter(|t| t.txid() == txid)
        .ok_or_else(|| Miss::Bad(format!("our node's transaction {txid} does not parse to that txid")))?;
    Ok((tx, v))
}

/// `txid`, confirmed at `height` on our node's best chain, and the coins it spends.
fn at_height(node: &dyn Node, txid: &str, height: i64) -> Result<(Tx, Coins), Miss> {
    let h = u64::try_from(height).map_err(|_| Miss::Bad(format!("a coin's height {height} is not a block height")))?;
    let bh = node::block_hash(node, h).map_err(Miss::of)?;
    let (tx, v) = in_block(node, txid, &bh)?;
    let coins = coins(node, &tx, &v);
    Ok((tx, coins))
}

/// The coin `txid:vout`, from our node's copy of its transaction looked up by txid alone: the mempool
/// or txindex. For a node that does not give an input's `prevout`.
fn by_txid(node: &dyn Node, txid: &str, vout: u32) -> Result<Coin, Miss> {
    let v = node.call("getrawtransaction", json!([txid, true])).map_err(Miss::of)?;
    if v.is_null() {
        return Err(Miss::Gone(format!("our node has no transaction {txid}")));
    }
    let prev = tx_hex(&v).and_then(|h| Tx::parse_hex(&h).ok()).filter(|t| t.txid() == txid)
        .ok_or_else(|| Miss::Bad(format!("our node's transaction {txid} does not parse to that txid")))?;
    let spk = prev.outputs.get(vout as usize).map(|o| o.script_pubkey.clone())
        .ok_or_else(|| Miss::Bad(format!("the coin {txid}:{vout} is not in our node's copy of its transaction")))?;
    let height = v.get("blockhash").and_then(Value::as_str).and_then(|b| height_of_block(node, b))
        .ok_or_else(|| Miss::Gone(format!("transaction {txid} has no confirmed block on our node")))?;
    Ok(Coin { spk, height, coinbase: is_coinbase(&prev) })
}

/// The coins `tx`'s inputs spend, one per input; `v` is our node's verbose answer for `tx`. From the
/// input's `prevout` where the node gives one (its block's undo data), else from the coin's own
/// transaction ([`by_txid`]). The node's input must be the transaction's, outpoint for outpoint.
fn coins(node: &dyn Node, tx: &Tx, v: &Value) -> Coins {
    let vin = v.get("vin").and_then(Value::as_array);
    tx.inputs.iter().enumerate().map(|(i, inp)| {
        let (prev_txid, pv) = (inp.prevout.txid_hex(), inp.prevout.vout);
        if let Some(e) = vin.and_then(|a| a.get(i)) {
            if e.get("txid").and_then(Value::as_str) != Some(prev_txid.as_str()) || e.get("vout").and_then(Value::as_u64) != Some(pv as u64) {
                return Err(Miss::Bad(format!("our node's input {i} of {} is not {prev_txid}:{pv}", tx.txid())));
            }
            if let Some(p) = e.get("prevout") {
                let spk = p.get("scriptPubKey").and_then(|s| s.get("hex")).and_then(Value::as_str).and_then(|h| hex::decode(h).ok());
                return match (spk, p.get("height").and_then(Value::as_i64), p.get("generated").and_then(Value::as_bool)) {
                    (Some(spk), Some(height), Some(coinbase)) => Ok(Coin { spk, height, coinbase }),
                    _ => Err(Miss::Bad(format!("our node's prevout of {prev_txid}:{pv} lacks its scriptPubKey, height or coinbase flag"))),
                };
            }
        }
        by_txid(node, &prev_txid, pv)
    }).collect()
}

/// Is `inp` a P2PKH spend whose one signature is 0x21? Then the signature is in the scriptSig, which
/// the txid commits to, and the SHA-256 chain cannot verify it: no transaction with this txid is valid there.
fn pinned_by_script_sig(inp: &TxIn, prev_spk: &[u8]) -> bool {
    let p2pkh = prev_spk.len() == 25 && prev_spk[..3] == [0x76, 0xa9, 0x14] && prev_spk[23..] == [0x88, OP_CHECKSIG];
    p2pkh && inp.witness.is_empty() && checked_sighashes(inp, prev_spk).is_ok_and(|s| s == [SIGHASH_UNIFIED_ALL])
}

/// What pins `funding`'s txid to XBT (the module documentation's rule), searched breadth first from
/// its inputs (`coins`: what each spends): `Ok(Some(evidence))`, `Ok(None)` when [`ANCESTRY_LOOKUPS`]
/// inputs, or every transaction in reach, held no pin, and `Err` when our node could not return a
/// transaction or a coin the search needed and none it could return held a pin (then nothing is
/// concluded). One pin is enough, so a branch our node cannot read (a pruned block) does not stop the
/// search of the others.
pub fn xbt_only(node: &dyn Node, funding: &Tx, coins: Coins, split_height: i64) -> Result<Option<Value>, String> {
    let mut seen: HashSet<String> = HashSet::from([funding.txid()]);
    let mut queue: VecDeque<(Tx, Coins, u32)> = VecDeque::from([(funding.clone(), coins, 0)]);
    let mut looked_up = 0usize;
    let mut missed: Option<String> = None;
    while let Some((tx, coins, depth)) = queue.pop_front() {
        for (i, (inp, coin)) in tx.inputs.iter().zip(coins).enumerate() {
            let (prev_txid, pv) = (inp.prevout.txid_hex(), inp.prevout.vout);
            if looked_up == ANCESTRY_LOOKUPS {
                return Ok(None);
            }
            looked_up += 1;
            let coin = match coin {
                Ok(c) => c,
                Err(Miss::NoAnswer(m)) => return Err(format!("our node did not answer for the coin {prev_txid}:{pv} ({m})")),
                Err(m) => {
                    missed.get_or_insert(format!("the coin {prev_txid}:{pv}: {}", m.text()));
                    continue;
                }
            };
            // whatever the coin's age: the signature is in this transaction's txid
            if pinned_by_script_sig(inp, &coin.spk) {
                return Ok(Some(json!({"pinned_by": "a 0x21 signature in a scriptSig", "txid": tx.txid(), "input": i, "generations": depth,
                                      "looked_up": looked_up})));
            }
            if coin.height < split_height {
                continue; // below the split every transaction is on both chains: nothing behind it helps
            }
            if coin.coinbase {
                return Ok(Some(json!({"pinned_by": "a coinbase at or above the split", "txid": prev_txid, "height": coin.height, "generations": depth + 1,
                                      "looked_up": looked_up})));
            }
            if seen.insert(prev_txid.clone()) {
                match at_height(node, &prev_txid, coin.height) {
                    Ok((prev, c)) => queue.push_back((prev, c, depth + 1)),
                    Err(Miss::NoAnswer(m)) => return Err(format!("our node did not answer for transaction {prev_txid} ({m})")),
                    Err(m) => {
                        missed.get_or_insert(format!("transaction {prev_txid} of block {}: {}", coin.height, m.text()));
                    }
                }
            }
        }
    }
    match missed {
        Some(m) => Err(format!("our node could not return all of the transactions behind the funding ({m}), and none it returned pins the funding \
                                to XBT: {NEEDS}")),
        None => Ok(None),
    }
}

/// Prove (or refuse) one channel's funding: `channel_point` is LND's `txid:vout`, `scid` its short
/// channel id, `capacity` its size in sats.
pub fn check(node: &dyn Node, channel_point: &str, scid: u64, capacity: i64, split_height: i64) -> Funding {
    let Some((txid, vout)) = channel_point.split_once(':').and_then(|(t, v)| Some((t.to_lowercase(), v.parse::<u32>().ok()?))) else {
        return Funding::Refused(format!("channel_point {channel_point:?} is not txid:vout"), Value::Null);
    };
    let (height, pos, out) = ((scid >> 40) as i64, ((scid >> 16) & 0xff_ffff) as usize, (scid & 0xffff) as u32);
    let ev = |extra: Value| {
        let mut e = json!({"txid": txid, "vout": vout, "height": height, "tx_index": pos});
        if let (Some(o), Value::Object(x)) = (e.as_object_mut(), extra) {
            o.extend(x);
        }
        e
    };
    if out != vout {
        return Funding::Refused(format!("the short channel id's output {out} is not the channel point's {vout}"), ev(json!({})));
    }
    let bh = match node::block_hash(node, height as u64) {
        Ok(h) => h,
        Err(e) => return Funding::Unknown(format!("our node has no block {height}: {}", e.msg)),
    };
    let ev = |extra: Value| {
        let mut e = ev(extra);
        e["block_hash"] = bh.clone().into();
        e
    };
    let block = match node.call("getblock", json!([bh, 1])) {
        Ok(b) => b,
        Err(e) => return Funding::Unknown(format!("our node cannot return block {height}, which holds the funding ({}): {NEEDS}", e.msg)),
    };
    let at = block.get("tx").and_then(Value::as_array).and_then(|t| t.get(pos))
        .and_then(|t| t.as_str().map(str::to_string).or_else(|| t.get("txid").and_then(Value::as_str).map(str::to_string)));
    if at.as_deref() != Some(txid.as_str()) {
        return Funding::Refused(format!("our node's block {height} holds {} at position {pos}, not the channel's funding",
                                        at.unwrap_or_else(|| "nothing".into())), ev(json!({})));
    }
    let (tx, verbose) = match in_block(node, &txid, &bh) {
        Ok(t) => t,
        Err(Miss::Bad(why)) => return Funding::Refused(why, ev(json!({}))),
        Err(m) => return Funding::Unknown(format!("our node cannot return the funding transaction {txid} ({}): {NEEDS}", m.text())),
    };
    let Some(o) = tx.outputs.get(vout as usize) else {
        return Funding::Refused(format!("the funding transaction has no output {vout}"), ev(json!({})));
    };
    if o.value != capacity {
        return Funding::Refused(format!("the funding output holds {} sats, the channel says {capacity}", o.value), ev(json!({})));
    }
    if classify(&o.script_pubkey) != Some(SpkKind::P2wsh) {
        return Funding::Refused("the funding output is not a P2WSH 2-of-2".into(), ev(json!({})));
    }
    let coins = coins(node, &tx, &verbose);
    let mut inputs = vec![];
    let mut bad = vec![];
    for (i, (inp, coin)) in tx.inputs.iter().zip(&coins).enumerate() {
        let (prev_txid, pv) = (inp.prevout.txid_hex(), inp.prevout.vout);
        let coin = match coin {
            Ok(c) => c,
            // our node's answer is not about this input: no verdict on the transaction, and none kept
            Err(Miss::Bad(why)) => return Funding::Unknown(format!("input {i} ({prev_txid}:{pv}): {why}")),
            Err(m) => return Funding::Unknown(format!("our node cannot say what coin input {i} ({prev_txid}:{pv}) spends ({}): {NEEDS}", m.text())),
        };
        let sh = checked_sighashes(inp, &coin.spk);
        let shown: Vec<String> = sh.iter().flatten().map(|b| format!("0x{b:02x}")).collect();
        match &sh {
            Err(why) => bad.push(format!("input {i} ({prev_txid}:{pv}): {why}")),
            Ok(s) if s.is_empty() => bad.push(format!("input {i} ({prev_txid}:{pv}) carries no signature we can read")),
            Ok(s) if s.iter().any(|b| *b != SIGHASH_UNIFIED_ALL) => {
                bad.push(format!("input {i} ({prev_txid}:{pv}) is signed {}, not 0x21: the SHA-256 chain may verify it, so the funding \
                                  may replay there", shown.join("/")));
            }
            Ok(_) => {}
        }
        if coin.height < split_height {
            bad.push(format!("input {i} ({prev_txid}:{pv}) was confirmed at {}, below the split {split_height}", coin.height));
        }
        inputs.push(json!({"outpoint": format!("{prev_txid}:{pv}"), "height": coin.height, "sighash": shown}));
    }
    let mut evidence = ev(json!({"inputs": inputs, "source": "the signer's own node"}));
    if !bad.is_empty() {
        return Funding::Refused(bad.join("; "), evidence);
    }
    match xbt_only(node, &tx, coins, split_height) {
        Ok(Some(pin)) => {
            evidence["xbt_only"] = pin;
            Funding::Proven(evidence)
        }
        Ok(None) => Funding::Refused(format!(
            "nothing its txid commits to pins the funding to XBT: its inputs' signatures are in witnesses, which are not part of the txid, and \
             no transaction behind it (back to the split {split_height}, at most {ANCESTRY_LOOKUPS} looked up) is a coinbase or carries a 0x21 \
             signature in a scriptSig. The same txid may be valid on the SHA-256 chain with other signatures: fund the channel from mined coins, or \
             from coins that passed through a P2PKH address after the split"), evidence),
        Err(why) => Funding::Unknown(why),
    }
}

// --- verdicts kept on disk ------------------------------------------------------------------------

/// The file in the signer's run directory that keeps final verdicts ([`Kept`]).
pub const KEPT_FILE: &str = "ln_funding.json";
/// The rules a kept verdict was reached under. A file written under other rules keeps nothing, so
/// its channels are proven again: raise this whenever what [`check`] proves or refuses changes.
pub const KEPT_RULES: u64 = 1;

/// Final verdicts by channel (the signer's key: channel point, short channel id, capacity and split),
/// each with the hash of the block it was reached on, in memory and in [`KEPT_FILE`]. A verdict goes
/// to disk (a synced file renamed into place, then the directory synced) before it is kept in
/// memory, so one that is kept after a restart was durable. A kept verdict holds while its block is
/// our node's block at the channel's height (the module documentation says why that is enough); it is
/// what lets a pruned node use a channel whose blocks it no longer has. A file that cannot be read, or
/// that other rules wrote, keeps nothing and is replaced at the next write.
pub struct Kept {
    path: PathBuf,
    map: Mutex<HashMap<String, (String, Funding)>>,
}

impl Kept {
    pub fn open(path: &Path) -> Self {
        let map = std::fs::read_to_string(path).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .filter(|v| v.get("rules").and_then(Value::as_u64) == Some(KEPT_RULES))
            .and_then(|v| v.get("verdicts").and_then(Value::as_object).cloned())
            .map(|m| m.into_iter().filter_map(|(k, e)| Some((k, read_kept(&e)?))).collect())
            .unwrap_or_default();
        Self { path: path.into(), map: Mutex::new(map) }
    }

    /// The verdict kept for `key`, if it was reached on block `bh`.
    pub fn get(&self, key: &str, bh: &str) -> Option<Funding> {
        self.map.lock().unwrap_or_else(|p| p.into_inner()).get(key).filter(|(h, _)| h == bh).map(|(_, f)| f.clone())
    }

    /// Keep `f`, a final verdict reached on block `bh`: on disk first, then in memory. `Err`: it is not
    /// kept (it still holds for the call that reached it).
    pub fn keep(&self, key: &str, bh: &str, f: &Funding) -> crate::Result<()> {
        if !f.is_final() || f.block_hash() != Some(bh) {
            return Err(crate::err("ln_funding", "only a final verdict reached on that block is kept"));
        }
        let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        let mut next = m.clone();
        next.insert(key.into(), (bh.into(), f.clone()));
        let verdicts: Map<String, Value> = next.iter().map(|(k, (_, f))| (k.clone(), kept_json(f))).collect();
        crate::ln::write_json(&self.path, &json!({"rules": KEPT_RULES, "verdicts": verdicts}))?;
        *m = next;
        Ok(())
    }
}

fn kept_json(f: &Funding) -> Value {
    match f {
        Funding::Proven(ev) => json!({"proven": true, "evidence": ev}),
        Funding::Refused(why, ev) => json!({"proven": false, "reason": why, "evidence": ev}),
        Funding::Unknown(_) => Value::Null,
    }
}

/// A kept verdict and its block hash, if the record is whole: a proven one with its evidence, a
/// refused one with its reason, and the evidence naming a block.
fn read_kept(e: &Value) -> Option<(String, Funding)> {
    let ev = e.get("evidence").filter(|v| v.is_object())?.clone();
    let f = match (e.get("proven").and_then(Value::as_bool)?, e.get("reason").and_then(Value::as_str)) {
        (true, None) => Funding::Proven(ev),
        (false, Some(why)) => Funding::Refused(why.into(), ev),
        _ => return None,
    };
    let bh = f.block_hash().filter(|h| h.len() == 64 && h.bytes().all(|c| c.is_ascii_hexdigit()))?.to_string();
    Some((bh, f))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der(sighash: u8) -> Vec<u8> {
        let mut s = vec![0x30, 0x44, 0x02, 0x20];
        s.extend([1u8; 32]);
        s.extend([0x02, 0x20]);
        s.extend([2u8; 32]);
        s.push(sighash);
        s
    }

    #[test]
    fn reads_sighash_bytes_by_input_kind() {
        assert_eq!(der_sighash(&der(0x21)), Some(0x21));
        assert_eq!(der_sighash(&[0x02; 33]), None, "a pubkey is not a signature");
        assert_eq!(der_sighash(&der(0x21)[..70]), None);
        let wpkh = [0u8, 0x14].iter().copied().chain([7u8; 20]).collect::<Vec<u8>>();
        let wsh = [0u8, 0x20].iter().copied().chain([7u8; 32]).collect::<Vec<u8>>();
        let tr = [0x51u8, 0x20].iter().copied().chain([7u8; 32]).collect::<Vec<u8>>();
        let mut i = TxIn::new(xbt_primitives::tx::OutPoint::new([0; 32], 0), 0);
        let read = |i: &TxIn, spk: &[u8]| checked_sighashes(i, spk);
        i.witness = vec![der(0x21), vec![0x02; 33]];
        assert_eq!(read(&i, &wpkh), Ok(vec![0x21]));
        i.witness = vec![der(0x01), vec![0x02; 33]];
        assert_eq!(read(&i, &wpkh), Ok(vec![0x01]));
        i.witness = vec![vec![0x02; 33], der(0x21)];
        assert!(read(&i, &wpkh).is_err(), "the key is not a signature");
        // 2-of-2 P2WSH: both signatures, never the script
        let ms = [vec![0x52, 0x21], vec![2; 33], vec![0x21], vec![3; 33], vec![0x52, 0xae]].concat();
        i.witness = vec![vec![], der(0x21), der(0x01), ms.clone()];
        assert_eq!(read(&i, &wsh), Ok(vec![0x21, 0x01]));
        i.witness = vec![vec![], der(0x21), ms.clone()];
        assert!(read(&i, &wsh).is_err(), "2-of-2 with one signature");
        let single = [vec![0x21], vec![2; 33], vec![0xac]].concat();
        i.witness = vec![der(0x21), single];
        assert_eq!(read(&i, &wsh), Ok(vec![0x21]));
        // AGP-066: a script that checks no signature, or not only signatures, is not read
        for script in [vec![0x75, 0x51], [vec![0xa8, 0x20], vec![1; 32], vec![0x87]].concat(), [ms.clone(), vec![0x75]].concat()] {
            i.witness = vec![der(0x21), script];
            assert!(read(&i, &wsh).unwrap_err().contains("CHECKSIG"));
        }
        // taproot key path: 64 bytes is SIGHASH_DEFAULT; a script path is not read
        i.witness = vec![vec![5; 64]];
        assert_eq!(read(&i, &tr), Ok(vec![0x00]));
        i.witness = vec![[vec![5; 64], vec![0x21]].concat()];
        assert_eq!(read(&i, &tr), Ok(vec![0x21]));
        i.witness = vec![[vec![5; 64], vec![0x21]].concat(), vec![0x50, 1]];
        assert_eq!(read(&i, &tr), Ok(vec![0x21]), "the annex is not a script path");
        i.witness = vec![[vec![5; 64], vec![0x21]].concat(), vec![0x51], vec![0xc0; 33]];
        assert!(read(&i, &tr).unwrap_err().contains("script path"));
        // legacy P2PKH: the scriptSig's pushes
        i.witness = vec![];
        let sig = der(0x21);
        let p2pkh = [vec![0x76, 0xa9, 0x14], vec![4; 20], vec![0x88, 0xac]].concat();
        i.script_sig = [vec![sig.len() as u8], sig.clone(), vec![33], vec![0x02; 33]].concat();
        assert_eq!(read(&i, &p2pkh), Ok(vec![0x21]));
        assert!(read(&i, &[0x76, 0xa9]).is_err(), "not a script the proof reads");
        // P2SH-P2WPKH: the redeem script pushed, the signature in the witness
        let p2sh = [vec![0xa9, 0x14], vec![1; 20], vec![0x87]].concat();
        i.script_sig = [vec![22u8, 0x00, 0x14], vec![9; 20]].concat();
        i.witness = vec![der(0x21), vec![0x02; 33]];
        assert_eq!(read(&i, &p2sh), Ok(vec![0x21]));
        i.script_sig = [vec![sig.len() as u8], sig].concat();
        assert!(read(&i, &p2sh).is_err(), "legacy P2SH is not read");
    }

    /// Property: whatever the witness, a P2WSH input is read only when its script is a key check, and
    /// then yields exactly the signatures that script checks.
    #[test]
    fn only_signature_only_scripts_are_read() {
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let wsh = [vec![0u8, 0x20], vec![7u8; 32]].concat();
        let mut i = TxIn::new(xbt_primitives::tx::OutPoint::new([0; 32], 0), 0);
        for _ in 0..2_000 {
            let n = (next() % 4) as usize;
            let script: Vec<u8> = (0..(next() % 40) as usize).map(|_| [0x51, 0x52, 0x21, 0xac, 0xae, 0x75, 0x87, 0x02][(next() % 8) as usize]).collect();
            i.witness = (0..n).map(|_| if next() % 2 == 0 { der(0x21) } else { vec![] }).chain([script.clone()]).collect();
            if let Ok(sh) = checked_sighashes(&i, &wsh) {
                let (m, _) = sig_only_script(&script).expect("read only a key-check script");
                assert_eq!(sh.len(), m);
            }
        }
    }
}
