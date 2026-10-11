//! AGP-093 (third closure audit, area LIGHT, the Lightning rail).
//!
//! `hole_*` tests FAIL on `d4c8328`; `evidence_*` tests pass and pin down a stated limit.
//!
//! * Overflow checks are on in every build (AGP-089), so an unchecked `*` or `+` on a number an
//!   invoice or the LN node supplies is now a panic. Two are reachable: the BOLT 11 amount (u128
//!   multiply, before the signature is looked at) and the node's `value_sat` / `fee_sat` and HTLC
//!   amounts. The second runs in the watcher thread, which has no panic guard (`signer.rs`
//!   `watch_loop`): the thread that refunds xbt402 channels at expiry ends with it.
//! * L5 (decision 1 of AGP-092): what the 256-lookup ancestry bound refuses.
use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::{json, Value};
use xbt_primitives::tx::{OutPoint, Tx, TxIn, TxOut};
use xbt_signer::ln_funding::{self, Funding, ANCESTRY_LOOKUPS};
use xbt_signer::node::Node;

// --- bech32, to build an invoice string with a valid checksum -------------------------------------

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ u32::from(*v);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn bech32(hrp: &str, words: &[u8]) -> String {
    let mut v: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|c| c & 31));
    v.extend(words);
    v.extend([0u8; 6]);
    let pm = polymod(&v) ^ 1;
    let mut s = format!("{hrp}1");
    s.extend(words.iter().map(|w| CHARSET[usize::from(*w)] as char));
    s.extend((0..6).map(|i| CHARSET[((pm >> (5 * (5 - i))) & 31) as usize] as char));
    s
}

/// `ln_pay` decodes the caller's invoice before anything else (`ln.rs` `ln_pay_locked`, with the
/// spend lock held). `parse_hrp` reads the amount's digits into a u128 and multiplies by up to
/// 10^11 with a plain `*` (`bolt11.rs:168`): 28 digits or more overflow. That is a string anyone
/// can write (the checksum needs no key, and the amount is read before the signature), so a seller
/// can hand an agent an "invoice" that kills the request's thread, and the whole signer in a
/// `release-small` build (`panic = "abort"`).
#[test]
fn hole_a_bolt11_amount_past_u128_is_refused_not_a_panic() {
    let invoice = bech32(&format!("lnbcrt{}", "9".repeat(30)), &[]);
    let r = std::panic::catch_unwind(|| xbt_signer::bolt11::decode(&invoice));
    println!("AGP-093 measure: bolt11::decode({invoice:?}): {}", match &r {
        Ok(d) => format!("{:?}", d.as_ref().map(|_| "decoded").map_err(|e| e.clone())),
        Err(_) => "panicked".into(),
    });
    assert!(matches!(r, Ok(Err(_))), "decode panicked on the amount (attempt to multiply with overflow)");
}

#[test]
fn control_a_bolt11_amount_past_u64_is_refused() {
    // 20 digits of bitcoin: past u64 msat, inside u128
    let invoice = bech32(&format!("lnbcrt{}", "9".repeat(20)), &[]);
    assert_eq!(xbt_signer::bolt11::decode(&invoice).unwrap_err(), "invoice amount overflows");
}

/// What the LN node reports of a payment is read with plain arithmetic: `paid_msat` multiplies
/// `value_sat` and `fee_sat` by 1000 (`ln.rs:870-871`), `htlc_locks` adds HTLC amounts
/// (`ln.rs:756`). No honest node sends such numbers; a node that does (a bug, a compromise, a
/// proxy in front of it) must be refused, not panic. Why it matters more than one failed request:
/// the payment stays `sending`, so every watcher tick looks it up again and reaches the same line
/// (`signer.rs:918` -> `ln_reconcile_locked` -> `ln_apply` -> `ln_settle` -> `paid_msat`), and
/// `watch_loop` (`signer.rs:1748`) has no panic guard: the watcher thread ends, and with it the
/// automatic refund of every xbt402 channel at expiry, until a restart, after which the first tick
/// ends it again. (The path from the watcher is from reading; the two panics are run here.)
#[test]
fn hole_a_node_answer_with_amounts_out_of_range_is_refused_not_a_panic() {
    let paid = std::panic::catch_unwind(|| {
        xbt_signer::ln::paid_msat(&json!({"status": "SUCCEEDED", "value_sat": "18446744073709551615", "fee_sat": "0"}))
    });
    let htlc = |amt: &str| json!({"incoming": false, "amount": amt, "hash_lock": "aa".repeat(32), "expiration_height": 7000});
    let chans = vec![json!({"chan_id": "1", "pending_htlcs": [htlc("9223372036854775807"), htlc("9223372036854775807")]})];
    let locks = std::panic::catch_unwind(|| xbt_signer::ln::htlc_locks(&chans, &|_| false).unbooked_sats);
    println!("AGP-093 measure: paid_msat(value_sat = u64::MAX): {}; htlc_locks(two HTLCs of i64::MAX): {}",
             if paid.is_err() { "panicked".to_string() } else { format!("{paid:?}") },
             if locks.is_err() { "panicked".to_string() } else { format!("{locks:?}") });
    assert!(paid.is_ok(), "paid_msat panicked (attempt to multiply with overflow)");
    assert!(locks.is_ok(), "htlc_locks panicked (attempt to add with overflow)");
}

// --- L5: a node holding blocks and transactions, as with txindex ----------------------------------

#[derive(Default)]
struct Chain {
    /// txid -> (hex, height)
    txs: Mutex<HashMap<String, (String, u64)>>,
    /// height -> txids by position
    blocks: Mutex<HashMap<u64, Vec<String>>>,
    lookups: Mutex<usize>,
}

fn bhash(h: u64) -> String {
    format!("{:064x}", 0xb10c_0000_0000u64 + h)
}

impl Chain {
    fn place(&self, tx: &Tx, height: u64) -> usize {
        self.txs.lock().unwrap().insert(tx.txid(), (tx.to_hex(), height));
        let mut b = self.blocks.lock().unwrap();
        let blk = b.entry(height).or_default();
        blk.push(tx.txid());
        blk.len() - 1
    }
}

impl Node for Chain {
    fn call(&self, method: &str, p: Value) -> xbt402::Result<Value> {
        let no = |m: &str| Err(xbt402::ChannelError::new("rpc_error", m.to_string()));
        let height_of = |b: &str| u64::from_str_radix(b, 16).ok().and_then(|x| x.checked_sub(0xb10c_0000_0000));
        match method {
            "getblockhash" => Ok(json!(bhash(p[0].as_u64().unwrap_or(0)))),
            "getblockheader" => match height_of(p[0].as_str().unwrap_or("")) {
                Some(h) => Ok(json!({"height": h})),
                None => no("Block not found"),
            },
            "getblock" => {
                let h = height_of(p[0].as_str().unwrap_or("")).unwrap_or(0);
                Ok(json!({"height": h, "tx": self.blocks.lock().unwrap().get(&h).cloned().unwrap_or_default()}))
            }
            "getrawtransaction" => {
                *self.lookups.lock().unwrap() += 1;
                match self.txs.lock().unwrap().get(p[0].as_str().unwrap_or("")) {
                    Some((hex, h)) => Ok(json!({"txid": p[0], "hex": hex, "blockhash": bhash(*h)})),
                    None => no("No such mempool or blockchain transaction"),
                }
            }
            _ => no("not served"),
        }
    }
}

const SPLIT: i64 = 6_000;

fn der(sighash: u8) -> Vec<u8> {
    [vec![0x30, 0x44, 0x02, 0x20], vec![1u8; 32], vec![0x02, 0x20], vec![2u8; 32], vec![sighash]].concat()
}

fn p2wpkh(tag: u8) -> Vec<u8> {
    [vec![0u8, 0x14], vec![tag; 20]].concat()
}

/// A transaction spending output 0 of each of `prevs` with a P2WPKH witness signed 0x21.
fn spend(prevs: &[&Tx], sats: i64, spk: Vec<u8>) -> Tx {
    let mut t = Tx::new(2, prevs.iter().map(|p| TxIn::new(OutPoint::new(p.txid_bytes(), 0), 0xffff_fffd)).collect(), vec![TxOut::new(sats, spk)], 0);
    for i in t.inputs.iter_mut() {
        i.witness = vec![der(0x21), vec![0x02; 33]];
    }
    t
}

fn coinbase(n: u32) -> Tx {
    Tx::new(2, vec![TxIn::new(OutPoint::new([0u8; 32], 0xffff_ffff), n)], vec![TxOut::new(100_000, p2wpkh(0x71))], n)
}

/// A miner's wallet: `n` coinbases above the split, each paid out by its own transaction (a pool
/// payout), the payouts consolidated into one coin, the channel funded from that coin. Every coin
/// behind the funding descends from a coinbase two transactions back.
fn consolidated_miner(n: u32) -> (Chain, Funding, usize) {
    let chain = Chain::default();
    let mut payouts = vec![];
    for k in 0..n {
        let cb = coinbase(k);
        chain.place(&cb, 6_001 + u64::from(k));
        let pay = spend(&[&cb], 100_000, p2wpkh(0x72));
        chain.place(&pay, 6_400);
        payouts.push(pay);
    }
    let all = spend(&payouts.iter().collect::<Vec<_>>(), 100_000, p2wpkh(0x73));
    chain.place(&all, 6_500);
    let funding = spend(&[&all], 100_000, [vec![0u8, 0x20], vec![0x51; 32]].concat());
    let pos = chain.place(&funding, 6_600) as u64;
    let before = *chain.lookups.lock().unwrap();
    let f = ln_funding::check(&chain, &format!("{}:0", funding.txid()), (6_600u64 << 40) | (pos << 16), 100_000, SPLIT);
    let looked = *chain.lookups.lock().unwrap() - before;
    (chain, f, looked)
}

/// Decision 1 of AGP-092, its cost: the search is breadth first with 256 lookups in all, so one
/// wide transaction behind the funding uses them up before the generation that holds the coinbases
/// is reached. A miner who consolidated 255 or more payouts is refused, finally (the verdict is
/// cached for as long as the funding block stands), although every coin is mined. 200 is proven.
/// A limit to write down, not a wrong `Proven`: the bound never proves what is not pinned.
#[test]
fn evidence_l5_a_wide_consolidation_of_mined_coins_is_out_of_the_searchs_reach() {
    let (_c, narrow, looked) = consolidated_miner(200);
    match &narrow {
        Funding::Proven(ev) => assert_eq!((ev["xbt_only"]["pinned_by"].as_str(), ev["xbt_only"]["generations"].as_u64()),
                                          (Some("a coinbase at or above the split"), Some(3)), "{ev}"),
        other => panic!("200 payouts: {other:?}"),
    }
    println!("AGP-093 measure: funding behind a 200-input consolidation: Proven after {looked} getrawtransaction calls");
    let (_c, wide, looked) = consolidated_miner(255);
    println!("AGP-093 measure: funding behind a 255-input consolidation: {} after {looked} getrawtransaction calls",
             match &wide { Funding::Refused(..) => "Refused", Funding::Proven(_) => "Proven", Funding::Unknown(_) => "Unknown" });
    match wide {
        Funding::Refused(why, _) => {
            assert!(why.contains("pins the funding to XBT"), "{why}");
            assert!(why.contains(&ANCESTRY_LOOKUPS.to_string()), "the reason names the bound: {why}");
        }
        other => panic!("255 payouts: {other:?}"),
    }
}

/// L5: one pinned path is enough, and it is the right rule (a transaction is invalid where one of
/// its coins does not exist). A funding with one input from a coinbase and one whose whole history
/// is segwit spends of a pre-split coin is `Proven`.
#[test]
fn evidence_l5_one_pinned_input_proves_a_funding_with_an_unpinned_one_beside_it() {
    let chain = Chain::default();
    let cb = coinbase(1);
    chain.place(&cb, 6_100);
    let old = Tx::new(2, vec![TxIn::new(OutPoint::new([0x31; 32], 0), 0)], vec![TxOut::new(100_000, p2wpkh(0x74))], 9);
    chain.place(&old, 5_000);
    let moved = spend(&[&old], 100_000, p2wpkh(0x75));
    chain.place(&moved, 6_200);
    let funding = spend(&[&moved, &cb], 100_000, [vec![0u8, 0x20], vec![0x51; 32]].concat());
    let pos = chain.place(&funding, 6_600) as u64;
    match ln_funding::check(&chain, &format!("{}:0", funding.txid()), (6_600u64 << 40) | (pos << 16), 100_000, SPLIT) {
        Funding::Proven(ev) => assert_eq!(ev["xbt_only"]["pinned_by"], "a coinbase at or above the split", "{ev}"),
        other => panic!("{other:?}"),
    }
}
