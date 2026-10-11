//! AGP-091, fix wave 4, pay-with-work: the neighbours of the second closure audit's holes (WORK 1,
//! 3 and 6), each on the other paths to the same state. `agp087_work.rs` has the audit's own tests.
//!
//! Every test here uses only what existed before the fix, so the file runs on the audit's branch
//! (`agp-087`, 5521674) as it is. The tests marked FAILED-FIRST fail there; the others pass on both
//! and are evidence that the rule's other half held and still holds.
use std::sync::Arc;

use serde_json::{json, Value};
use xbt402::scheme::ProviderScheme;
use xbt_work::audit::{Deferral, PrimeTerms, WindowStatement};
use xbt_work::auth::{auth_tag, request_digest};
use xbt_work::chain::ChainBlock;
use xbt_work::provider::{Statement, WorkConfig, WorkProvider, WorkScheme};
use xbt_work::receipt::{PrimeKey, WorkReceipt};

const NET: &str = "bip122:00000000000000000000000000000001";
const PROV: &str = "bcrt1q76vavszzsq657n375vk6updhxm0tfay7k28cc3";
const MAIN_BITS: u32 = 0x1a00_f0b5;
const MAIN_V: u64 = 312_500_000;

fn key() -> PrimeKey { PrimeKey::from_seed(70, &[9u8; 32]) }
/// Mainnet-shaped numbers under the shipped defaults: a 150-sat call is 10 work units.
fn config(k: &PrimeKey) -> WorkConfig {
    WorkConfig::new(NET, PROV, 70, &k.pubkey_hex(), "http://prime.test/receipt").shipped(MAIN_BITS, MAIN_V, 150)
}
fn world() -> (PrimeKey, Arc<WorkProvider>) {
    let k = key();
    let wp = Arc::new(WorkProvider::new(config(&k)).unwrap());
    (k, wp)
}
fn receipt(inv: &str, seq: u64, cum: u64, first: u32, last: u32) -> WorkReceipt {
    WorkReceipt { seq, cum_work: cum, shares: seq, first_height: first, last_height: last, difficulty: 1, ..WorkReceipt::zero(70, PROV, inv) }
}
fn credit(k: &PrimeKey, wp: &WorkProvider, inv: &str, seq: u64, cum: u64, first: u32, last: u32) -> u64 {
    wp.accept(&k.sign(&receipt(inv, seq, cum, first, last)).unwrap()).unwrap()
}
fn hash(h: u32) -> String { format!("{h:064x}") }
fn block(height: u32, paid: u64) -> ChainBlock {
    ChainBlock { height, hash: hash(height), value_sats: MAIN_V, paid_sats: paid, bits: MAIN_BITS, prev_bits: MAIN_BITS }
}
fn window_work() -> u64 { PrimeTerms::default().window_target(MAIN_BITS).unwrap() }
fn stmt(height: u32, ws: u32) -> WindowStatement {
    WindowStatement { prime_id: 70, height, block_hash: hash(height), window_start: ws, window_work: window_work(), min_payout: 546, fee_bps: 0 }
}
/// The block's share of `work` units in the window: what an honest Prime pays for them.
fn share(work: u64) -> u64 { (u128::from(MAIN_V) * u128::from(work) / u128::from(window_work())) as u64 }
fn distrust(wp: &WorkProvider) -> Value { wp.report()["distrust"].clone() }
fn frozen(wp: &WorkProvider) -> Value { wp.report()["credit"]["frozen"].clone() }
fn unpaid(wp: &WorkProvider) -> Value { wp.report()["unpaidBlocks"].clone() }

fn payment(inv_doc: &Value, k: &PrimeKey, r: &WorkReceipt, n: u64, path: &str) -> Value {
    let key = hex::decode(inv_doc["authKey"].as_str().unwrap()).unwrap();
    let s = k.sign(r).unwrap();
    let auth = auth_tag(&key, &r.invoice, n, r.seq, r.cum_work, &request_digest("GET", path, b"")).unwrap();
    json!({"x402Version": 2, "accepted": {"scheme": "xbt-work", "network": NET, "payTo": PROV},
           "payload": {"receipt": r.to_doc(), "sig": hex::encode(s.sig), "n": n, "auth": auth}})
}
/// One paid call: Ok, or the refusal's `error`.
fn call(wp: &Arc<WorkProvider>, pay: &Value, path: &str) -> Result<(), String> {
    WorkScheme(wp.clone()).authorize(pay, "GET", path, b"", 150, &format!("http://api.test{path}")).map(|_| ()).map_err(|v| v["error"].as_str().unwrap_or("").to_string())
}
fn state_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("xbt-work-agp091-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ------------------------------------------------------------------------------------------------
// WORK 1. The rule: the Prime is failed only on what the Prime signed for this block.
// ------------------------------------------------------------------------------------------------

/// FAILED-FIRST. However much a coinbase pays the identity, with no statement the block has no
/// verdict: 1 sat, the dust limit, a whole call, the whole block. The amount is whoever mined the
/// block's to choose, so no threshold tells a stranger's block from the Prime's.
#[test]
fn w1_no_payment_makes_a_block_the_primes() {
    for paid in [1u64, 545, 546, 150, 50_000_000, MAIN_V] {
        let (k, wp) = world();
        let i = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
        credit(&k, &wp, &i, 1, 100, 101, 102);
        let o = wp.audit_chain(&block(110, paid), Statement::Missing).unwrap();
        assert!(o.is_none(), "{paid} sat with no statement gave a verdict");
        assert!(distrust(&wp).is_null(), "{paid} sat in a coinbase with no statement distrusted the Prime: {}", distrust(&wp));
        assert_eq!(wp.exposure().0, 100, "{paid} sat with no statement covered credit");
        assert_eq!(wp.report()["audits"], json!([]));
    }
}

/// FAILED-FIRST. The same, with what the Prime's server can hold for a height that is now another
/// pool's block: its own statement for the block that lost the race (another hash), or one for
/// another height. A competing miner that puts dust in each of its coinbases and wins one race
/// against the Prime is all it took.
#[test]
fn w1_a_stale_statement_on_a_strangers_block_does_not_distrust() {
    let other = PrimeKey::from_seed(70, &[7u8; 32]);
    for why in ["the block that lost the race", "another height", "another key"] {
        let (k, wp) = world();
        let i = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
        credit(&k, &wp, &i, 1, 100, 101, 102);
        let sw = match why {
            "the block that lost the race" => k.sign_window(&WindowStatement { block_hash: hash(9110), ..stmt(110, 100) }).unwrap(),
            "another height" => k.sign_window(&WindowStatement { height: 109, ..stmt(110, 100) }).unwrap(),
            _ => other.sign_window(&stmt(110, 100)).unwrap(),
        };
        let o = wp.audit_chain(&block(110, 1), Statement::Found(&sw, &[])).unwrap();
        assert!(o.is_none() && distrust(&wp).is_null(), "{why}: {}", distrust(&wp));
        assert_eq!(wp.exposure().0, 100, "{why}: it covered credit");
    }
}

/// FAILED-FIRST. Every payer's balance survives a stranger's dust: before and after a restart,
/// through `audit_chain` walked once, walked again, and with the block audited out of order.
#[test]
fn w1_a_paid_for_balance_survives_dust_on_every_walk_and_a_restart() {
    let dir = state_dir("w1");
    let k = key();
    let cfg = WorkConfig { state_path: Some(dir.join("work.json")), ..config(&k) };
    let wp = Arc::new(WorkProvider::new(cfg.clone()).unwrap());
    let doc = wp.issue_invoice().unwrap();
    let i = doc["invoice"].as_str().unwrap().to_string();
    let r = receipt(&i, 1, 50, 101, 102);
    assert_eq!(call(&wp, &payment(&doc, &k, &r, 1, "/v1/a"), "/v1/a"), Ok(()));
    assert!(wp.audit(&k.sign_window(&stmt(110, 100)).unwrap(), &[], &block(110, 1000)).unwrap().ok);
    assert_eq!(wp.exposure().0, 0);
    for h in [111u32, 112, 113, 112, 111, 120, 115] {
        assert!(wp.audit_chain(&block(h, 1), Statement::Missing).unwrap().is_none());
    }
    assert_eq!(call(&wp, &payment(&doc, &k, &r, 2, "/v1/b"), "/v1/b"), Ok(()), "{}", distrust(&wp));
    drop(wp);
    let wp = Arc::new(WorkProvider::new(cfg).unwrap());
    assert!(distrust(&wp).is_null());
    assert!(wp.audit_chain(&block(121, 1), Statement::Missing).unwrap().is_none());
    assert_eq!(call(&wp, &payment(&doc, &k, &r, 3, "/v1/c"), "/v1/c"), Ok(()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// FAILED-FIRST (its first half). A Prime gains nothing by paying with no statement: the payment
/// covers nothing, and the block is counted with the unpaid ones. The same block with an honest
/// statement covers what it paid for, so silence is never the better answer.
#[test]
fn w1_a_payment_with_no_statement_covers_nothing_and_is_counted() {
    let (k, wp) = world();
    let i = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
    credit(&k, &wp, &i, 1, 100, 101, 102);
    assert!(wp.audit_chain(&block(110, share(100)), Statement::Missing).unwrap().is_none());
    assert_eq!(wp.exposure().0, 100);
    let u = unpaid(&wp);
    assert_eq!((u["from"].clone(), u["count"].clone()), (json!(110), json!(1)), "{u}");
    // the statement arrives: the block is audited as any other and its payment counts
    let o = wp.audit_chain(&block(110, share(100)), Statement::Found(&k.sign_window(&stmt(110, 100)).unwrap(), &[])).unwrap().unwrap();
    assert!(o.ok);
    assert!(wp.exposure().0 < 100 && distrust(&wp).is_null());
}

/// The rule's other half held and holds: a statement the Prime signed for this very block that the
/// audit refuses fails it, paid or not, and an honest statement on an underpaid block is a failed
/// audit with a fraud proof.
#[test]
fn w1_what_the_prime_signed_for_the_block_still_fails_it() {
    for paid in [0u64, 1, 600] {
        let (k, wp) = world();
        let i = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
        credit(&k, &wp, &i, 1, 100, 101, 102);
        let garbage = k.sign_window(&WindowStatement { window_work: 0, ..stmt(110, 100) }).unwrap();
        assert!(!wp.audit_chain(&block(110, paid), Statement::Found(&garbage, &[])).unwrap().unwrap().ok, "paid {paid}");
        assert_eq!(distrust(&wp)["code"], json!("refused_statement"), "paid {paid}");
    }
    let (k, wp) = world();
    let i = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
    credit(&k, &wp, &i, 1, 800, 101, 102);
    assert!(share(800) > 546);
    let o = wp.audit_chain(&block(110, 1), Statement::Found(&k.sign_window(&stmt(110, 100)).unwrap(), &[])).unwrap().unwrap();
    assert!(!o.ok && o.proof.is_some());
    assert_eq!(distrust(&wp)["code"], json!("wrong_prime"));
}

/// FAILED-FIRST. The admin audit takes any range and does not look for reorgs first. A block that
/// was audited and paid for credit, replaced at its height by another pool's block, must not go on
/// covering that credit once the height is audited again with no statement.
#[test]
fn w1_a_block_replaced_at_its_height_no_longer_covers_credit() {
    let (k, wp) = world();
    let i = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
    credit(&k, &wp, &i, 1, 100, 101, 102);
    assert!(wp.audit(&k.sign_window(&stmt(110, 100)).unwrap(), &[], &block(110, 10_000)).unwrap().ok);
    assert_eq!(wp.exposure().0, 0);
    let replaced = ChainBlock { hash: hash(9110), ..block(110, 0) };
    assert!(wp.audit_chain(&replaced, Statement::Missing).unwrap().is_none());
    assert_eq!(wp.exposure().0, 100, "the coinbase of a block that left the chain still covers credit");
    assert_eq!(wp.audited_blocks(), vec![]);
    // the same block asked about again with no statement keeps its audit: the Prime signed it
    assert!(wp.audit(&k.sign_window(&stmt(111, 100)).unwrap(), &[], &block(111, 10_000)).unwrap().ok);
    assert!(wp.audit_chain(&block(111, 10_000), Statement::Missing).unwrap().is_none());
    assert_eq!((wp.exposure().0, wp.audited_blocks().len()), (0, 1));
}

// ------------------------------------------------------------------------------------------------
// WORK 6. The rule: the unpaid-blocks stop lifts when the Prime paid in full for all unpaid
// credit in a block above the run, or when no credit is unpaid.
// ------------------------------------------------------------------------------------------------

/// A provider with `--max-unpaid-blocks 3`, 800 units (80 calls) of credit at heights 101-102 and
/// three unpaid blocks: stopped.
fn stopped(tag: Option<&str>) -> (PrimeKey, Arc<WorkProvider>, String, WorkConfig) {
    let k = key();
    let mut cfg = WorkConfig { max_unpaid_blocks: Some(3), ..config(&k) };
    if let Some(tag) = tag {
        cfg.state_path = Some(state_dir(tag).join("work.json"));
    }
    let wp = Arc::new(WorkProvider::new(cfg.clone()).unwrap());
    let i = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
    credit(&k, &wp, &i, 1, 800, 101, 102);
    for h in 103..=105 {
        assert!(wp.audit_chain(&block(h, 0), Statement::Missing).unwrap().is_none());
    }
    assert_eq!(frozen(&wp), json!("unpaid_blocks"));
    (k, wp, i, cfg)
}

/// FAILED-FIRST (the first three). No pass that leaves the credit unpaid lifts the stop: 1 sat
/// under a window moved past the credit; a full share of a window that holds a tenth of the
/// credit; a dust payment under an honest window (that one fails the audit outright).
#[test]
fn w6_a_pass_that_leaves_the_credit_unpaid_does_not_lift_the_stop() {
    // 1 sat, window moved past the credit
    let (k, wp, _, _) = stopped(None);
    assert!(wp.audit(&k.sign_window(&stmt(106, 105)).unwrap(), &[], &block(106, 1)).unwrap().ok);
    assert_eq!(frozen(&wp), json!("unpaid_blocks"));
    // a window that holds only new work: 80 units mined at 106, paid in full, the 800 untouched
    let (k, wp, i, _) = stopped(None);
    wp.accept(&k.sign(&receipt(&i, 2, 880, 106, 106)).unwrap()).unwrap();
    // the window starts at 101: the new work's span (102, 106] is inside it, the old credit's is not
    let o = wp.audit(&k.sign_window(&stmt(107, 101)).unwrap(), &[], &block(107, share(80))).unwrap();
    assert!(o.ok && o.proven_work == 80 && o.expected_sats == share(80), "{o:?}");
    assert_eq!(frozen(&wp), json!("unpaid_blocks"), "a block that paid for a tenth of the credit lifted the stop ({} unpaid)", wp.exposure().0);
    // every block the Prime finds from then on, each paying 1 sat
    let (k, wp, _, _) = stopped(None);
    for h in 106..=140 {
        assert!(wp.audit(&k.sign_window(&stmt(h, h - 1)).unwrap(), &[], &block(h, 1)).unwrap().ok);
        assert_eq!(frozen(&wp), json!("unpaid_blocks"), "height {h}");
    }
}

/// FAILED-FIRST. Passes the Prime gets without its coinbase paying do not lift it either: a
/// deferral line for the whole share, and a share below `min_payout`.
#[test]
fn w6_a_deferral_or_the_min_payout_clause_does_not_lift_the_stop() {
    let (k, wp, _, _) = stopped(None);
    let s = stmt(106, 100);
    let line = k.sign_deferral(&Deferral { prime_id: 70, height: 106, block_hash: hash(106), identity: PROV.into(), sats: share(800), reason: "unattested".into() }).unwrap();
    let o = wp.audit(&k.sign_window(&s).unwrap(), &[line], &block(106, 1)).unwrap();
    assert!(o.ok && o.deferred_sats == share(800), "{o:?}");
    assert_eq!(frozen(&wp), json!("unpaid_blocks"), "a deferral line and 1 sat lifted the stop");

    // 80 units of credit: the block's share is below the 546 the terms allow as min_payout
    let k = key();
    let wp = WorkProvider::new(WorkConfig { max_unpaid_blocks: Some(3), ..config(&k) }).unwrap();
    let i = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
    credit(&k, &wp, &i, 1, 80, 101, 102);
    for h in 103..=105 {
        assert!(wp.audit_chain(&block(h, 0), Statement::Missing).unwrap().is_none());
    }
    assert!(share(80) < 546 && share(80) > 2);
    let o = wp.audit(&k.sign_window(&stmt(106, 100)).unwrap(), &[], &block(106, 1)).unwrap();
    assert!(o.ok && o.below_min_sats > 0, "{o:?}");
    assert_eq!(frozen(&wp), json!("unpaid_blocks"), "the min_payout clause and 1 sat lifted the stop");
}

/// FAILED-FIRST. A restart walks the last blocks again. A block that paid in full before the run
/// began, audited again, does not end the run that came after it; and the stop is kept in the state.
#[test]
fn w6_an_older_paying_block_audited_again_does_not_lift_the_stop() {
    let dir = state_dir("w6");
    let k = key();
    let cfg = WorkConfig { max_unpaid_blocks: Some(3), state_path: Some(dir.join("work.json")), ..config(&k) };
    let wp = WorkProvider::new(cfg.clone()).unwrap();
    let i = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
    credit(&k, &wp, &i, 1, 800, 101, 102);
    let (s103, b103) = (k.sign_window(&stmt(103, 100)).unwrap(), block(103, share(800)));
    assert!(wp.audit(&s103, &[], &b103).unwrap().ok);
    let owed = wp.exposure().0;
    assert!(owed > 0 && owed < 800);
    for h in 104..=106 {
        assert!(wp.audit_chain(&block(h, 0), Statement::Missing).unwrap().is_none());
    }
    assert_eq!(frozen(&wp), json!("unpaid_blocks"));
    drop(wp);
    let wp = WorkProvider::new(cfg).unwrap();
    assert_eq!(frozen(&wp), json!("unpaid_blocks"), "the stop did not survive a restart");
    for _ in 0..3 {
        assert!(wp.audit(&s103, &[], &b103).unwrap().ok);
        assert_eq!(frozen(&wp), json!("unpaid_blocks"), "block 103, audited again, lifted a stop set after it");
        for h in 104..=106 {
            assert!(wp.audit_chain(&block(h, 0), Statement::Missing).unwrap().is_none());
        }
    }
    assert_eq!((frozen(&wp), wp.exposure().0), (json!("unpaid_blocks"), owed));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The stop still lifts as it should: at a block above the run that pays its share of all the
/// unpaid credit (the next one an honest Prime finds), and when nothing is unpaid any more.
#[test]
fn w6_the_stop_lifts_when_the_prime_pays_in_full() {
    let (k, wp, i, _) = stopped(None);
    // work receipted while stopped is held
    assert_eq!(wp.accept(&k.sign(&receipt(&i, 2, 900, 106, 106)).unwrap()).unwrap(), 0);
    let o = wp.audit(&k.sign_window(&stmt(107, 100)).unwrap(), &[], &block(107, share(900))).unwrap();
    assert!(o.ok && o.proven_work == 900, "{o:?}");
    assert_eq!((frozen(&wp), unpaid(&wp)), (Value::Null, Value::Null));
    assert_eq!(wp.exposure().1, 0, "the held work is credited once the stop lifts");

    // nothing unpaid: one coinbase pays the whole price of the credit under a window past it
    let (k, wp, _, _) = stopped(None);
    assert!(wp.audit(&k.sign_window(&stmt(106, 105)).unwrap(), &[], &block(106, 800 * 20)).unwrap().ok);
    assert_eq!((wp.exposure().0, frozen(&wp)), (0, Value::Null));
}

// ------------------------------------------------------------------------------------------------
// WORK 3. The rule: issuing an invoice costs the provider no state.
// ------------------------------------------------------------------------------------------------

/// FAILED-FIRST. No number of invoices stops issuance, and none of them costs another payer its
/// invoice: the first one issued still pays after 30,000 more (the old bound was 10,000 unfunded).
#[test]
fn w3_no_number_of_invoices_stops_issuance_or_costs_a_payer_its_invoice() {
    let (k, wp) = world();
    let doc = wp.issue_invoice().unwrap();
    let scheme = WorkScheme(wp.clone());
    for n in 0..30_000 {
        let r = scheme.control("POST", "/x402/xbt-work/invoice", &[], b"").unwrap();
        assert_eq!(r.status, 200, "invoice {n} refused");
    }
    let r = receipt(doc["invoice"].as_str().unwrap(), 1, 50, 101, 102);
    assert_eq!(call(&wp, &payment(&doc, &k, &r, 1, "/v1/a"), "/v1/a"), Ok(()));
}

/// FAILED-FIRST. Issuing writes nothing: the state file is the same bytes after 1,000 invoices
/// (it was rewritten and fsynced for each, by anyone who asked).
#[test]
fn w3_issuing_an_invoice_writes_nothing() {
    let dir = state_dir("w3a");
    let path = dir.join("work.json");
    let k = key();
    let wp = WorkProvider::new(WorkConfig { state_path: Some(path.clone()), ..config(&k) }).unwrap();
    wp.issue_invoice().unwrap();
    let before = std::fs::read(&path).ok();
    for _ in 0..1000 {
        wp.issue_invoice().unwrap();
    }
    assert_eq!(std::fs::read(&path).ok(), before, "the state file changed");
    let _ = std::fs::remove_dir_all(&dir);
}

/// An invoice issued before a restart pays after it, with no call made before the restart.
#[test]
fn w3_an_invoice_issued_before_a_restart_pays_after_it() {
    let dir = state_dir("w3b");
    let k = key();
    let cfg = WorkConfig { state_path: Some(dir.join("work.json")), ..config(&k) };
    let doc = WorkProvider::new(cfg.clone()).unwrap().issue_invoice().unwrap();
    let wp = Arc::new(WorkProvider::new(cfg).unwrap());
    let r = receipt(doc["invoice"].as_str().unwrap(), 1, 50, 101, 102);
    assert_eq!(call(&wp, &payment(&doc, &k, &r, 1, "/v1/a"), "/v1/a"), Ok(()));
    // and its balance, n and key are the record's from then on
    assert_eq!(call(&wp, &payment(&doc, &k, &r, 1, "/v1/a"), "/v1/a"), Err("bad_auth".into()), "n was not consumed");
    assert_eq!(wp.balance(doc["invoice"].as_str().unwrap()), Some((50, 10)));
    let _ = std::fs::remove_dir_all(&dir);
}

/// FAILED-FIRST (its last line: a refused call left a record). Only this provider's identifiers
/// are invoices: a random one, another provider's, and one of
/// this provider's with a character changed are refused as unknown, with a key the caller chose
/// or the key of a real invoice.
#[test]
fn w3_only_this_providers_identifiers_are_invoices() {
    let (k, wp) = world();
    let (_, other) = world();
    let real = wp.issue_invoice().unwrap();
    let foreign = other.issue_invoice().unwrap();
    let id = real["invoice"].as_str().unwrap();
    let mut changed: Vec<u8> = id.bytes().collect();
    changed[7] = if changed[7] == b'a' { b'b' } else { b'a' };
    let changed = String::from_utf8(changed).unwrap();
    for (what, inv) in [("random", "vfer2e5e75t4tv7in42lakx6i4"), ("another provider's", foreign["invoice"].as_str().unwrap()), ("changed", changed.as_str()),
                        ("too short", "abcdefgh"), ("upper case", &id.to_uppercase())] {
        for key_of in [&real, &foreign] {
            let doc = json!({"authKey": key_of["authKey"], "invoice": inv});
            let r = receipt(inv, 1, 50, 101, 102);
            assert_eq!(call(&wp, &payment(&doc, &k, &r, 1, "/v1/a"), "/v1/a"), Err("unknown_invoice".into()), "{what}");
            assert_eq!(wp.accept(&k.sign(&r).unwrap()).unwrap_err().code, "unknown_invoice", "{what}");
        }
    }
    // one invoice's key does not pay with another invoice
    let second = wp.issue_invoice().unwrap();
    let mixed = json!({"authKey": real["authKey"], "invoice": second["invoice"]});
    let r = receipt(second["invoice"].as_str().unwrap(), 1, 50, 101, 102);
    assert_eq!(call(&wp, &payment(&mixed, &k, &r, 1, "/v1/a"), "/v1/a"), Err("bad_auth".into()));
    assert_eq!(wp.balance(second["invoice"].as_str().unwrap()), None, "a refused call left a record");
}

/// FAILED-FIRST (the state file). A caller who holds an invoice and no work cannot make the
/// provider keep anything: a receipt with no work, one with a forged signature, one for another
/// identity, played once or a hundred times, leave no record, no receipt in the book and the state
/// file as it was. (Before, each call rewrote the state: `n` was consumed and saved.)
#[test]
fn w3_a_caller_with_no_work_cannot_make_the_provider_keep_anything() {
    let dir = state_dir("w3c");
    let path = dir.join("work.json");
    let k = key();
    let forger = PrimeKey::from_seed(70, &[3u8; 32]);
    let wp = Arc::new(WorkProvider::new(WorkConfig { state_path: Some(path.clone()), ..config(&k) }).unwrap());
    let before = std::fs::read(&path).ok();
    for n in 1..=100u64 {
        let doc = wp.issue_invoice().unwrap();
        let id = doc["invoice"].as_str().unwrap();
        assert_eq!(call(&wp, &payment(&doc, &k, &WorkReceipt::zero(70, PROV, id), n, "/v1/a"), "/v1/a"), Err("insufficient_work".into()));
        assert_eq!(call(&wp, &payment(&doc, &forger, &receipt(id, 1, 50, 101, 102), n, "/v1/a"), "/v1/a"), Err("bad_sig".into()));
        assert_eq!(wp.balance(id), None);
    }
    let book = wp.book();
    assert!(book.last.is_empty() && book.intervals.is_empty() && book.credited.is_empty(), "the book kept something");
    assert_eq!(std::fs::read(&path).ok(), before, "the state file changed");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The expiry is read from the identifier, to the same effect as the record it replaced: a first
/// receipt past the TTL is taken inside the grace when it shows work, and refused past it.
#[test]
fn w3_expiry_is_read_from_the_identifier() {
    let k = key();
    let grace = Arc::new(WorkProvider::new(WorkConfig { invoice_ttl_secs: 0, ..config(&k) }).unwrap());
    let gone = Arc::new(WorkProvider::new(WorkConfig { invoice_ttl_secs: 0, invoice_grace_secs: 0, ..config(&k) }).unwrap());
    let (dg, dx) = (grace.issue_invoice().unwrap(), gone.issue_invoice().unwrap());
    std::thread::sleep(std::time::Duration::from_millis(2100));
    let (ig, ix) = (dg["invoice"].as_str().unwrap(), dx["invoice"].as_str().unwrap());
    assert_eq!(call(&grace, &payment(&dg, &k, &WorkReceipt::zero(70, PROV, ig), 1, "/v1/a"), "/v1/a"), Err("unknown_invoice".into()), "expired, no work");
    assert_eq!(call(&grace, &payment(&dg, &k, &receipt(ig, 1, 50, 101, 102), 2, "/v1/a"), "/v1/a"), Ok(()), "expired, work, inside the grace");
    assert_eq!(call(&gone, &payment(&dx, &k, &receipt(ix, 1, 50, 101, 102), 1, "/v1/a"), "/v1/a"), Err("unknown_invoice".into()), "past the grace");
    // a retired invoice that was never seen is remembered as retired
    let live = Arc::new(WorkProvider::new(config(&k)).unwrap());
    let d = live.issue_invoice().unwrap();
    live.retire(d["invoice"].as_str().unwrap()).unwrap();
    assert_eq!(call(&live, &payment(&d, &k, &receipt(d["invoice"].as_str().unwrap(), 1, 50, 101, 102), 1, "/v1/a"), "/v1/a"), Err("unknown_invoice".into()));
}

/// State written before this change (invoices kept one by one, each with its own random key, and
/// no secret) keeps its invoices: funded or not, they pay with the key they were issued with.
#[test]
fn w3_state_from_before_agp091_keeps_its_invoices() {
    let dir = state_dir("w3d");
    let path = dir.join("work.json");
    let k = key();
    let far = 4_000_000_000u64;
    let old = json!({"version": 3, "identity": PROV, "audits": [], "distrust": null, "unpaid": null,
                     "invoices": {"vfer2e5e75t4tv7in42lakx6i4": {"key": "11".repeat(32), "n": 4, "spent": 0, "expiresAt": far, "retired": false},
                                  "aaaaaaaaaaaaaaaaaaaaaaaaab": {"key": "22".repeat(32), "n": 0, "spent": 0, "expiresAt": 1, "retired": false}},
                     "carry": {"deferred": 0, "released": 0, "blocks": []}});
    std::fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
    let wp = Arc::new(WorkProvider::new(WorkConfig { state_path: Some(path.clone()), ..config(&k) }).unwrap());
    let doc = json!({"authKey": "11".repeat(32), "invoice": "vfer2e5e75t4tv7in42lakx6i4"});
    let r = receipt("vfer2e5e75t4tv7in42lakx6i4", 1, 50, 101, 102);
    assert_eq!(call(&wp, &payment(&doc, &k, &r, 4, "/v1/a"), "/v1/a"), Err("bad_auth".into()), "its n was forgotten");
    assert_eq!(call(&wp, &payment(&doc, &k, &r, 5, "/v1/a"), "/v1/a"), Ok(()));
    // the one that expired long ago with no work on it is gone, as an issuance would have dropped it
    let dead = json!({"authKey": "22".repeat(32), "invoice": "aaaaaaaaaaaaaaaaaaaaaaaaab"});
    assert_eq!(call(&wp, &payment(&dead, &k, &receipt("aaaaaaaaaaaaaaaaaaaaaaaaab", 1, 50, 101, 102), 1, "/v1/a"), "/v1/a"), Err("unknown_invoice".into()));
    // and the secret new invoices are issued under was written at once
    let fresh = wp.issue_invoice().unwrap();
    drop(wp);
    let wp = Arc::new(WorkProvider::new(WorkConfig { state_path: Some(path), ..config(&k) }).unwrap());
    let r = receipt(fresh["invoice"].as_str().unwrap(), 1, 50, 101, 102);
    assert_eq!(call(&wp, &payment(&fresh, &k, &r, 1, "/v1/b"), "/v1/b"), Ok(()));
    let _ = std::fs::remove_dir_all(&dir);
}
