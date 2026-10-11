//! AGP-097, fix wave 5, pay-with-work: the rules the fixes keep, at the places that could break
//! them. The third audit's own tests for these items are in `agp093_work.rs`; these are the
//! neighbours (other call paths, a restart, state from before, the defaults).
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use xbt402::scheme::ProviderScheme;
use xbt_work::audit::{covers, PrimeTerms, WindowStatement};
use xbt_work::auth::{auth_tag, request_digest};
use xbt_work::chain::ChainBlock;
use xbt_work::provider::{admin_token, Cap, Caps, ServedStatement, Statement, WorkConfig, WorkProvider, WorkScheme};
use xbt_work::receipt::{PrimeKey, WorkReceipt};
use xbt_work::walk::{AuditSource, Walk};
use xbt_work::{Result, WorkError};

const NET: &str = "bip122:00000000000000000000000000000001";
const PROV: &str = "bcrt1q76vavszzsq657n375vk6updhxm0tfay7k28cc3";
const MAIN_BITS: u32 = 0x1a00_f0b5;
/// Twice the difficulty of `MAIN_BITS` (half the target), and half of it.
const MAIN_BITS_X2: u32 = 0x1a00_785a;
const MAIN_BITS_HALF: u32 = 0x1a01_e16a;
const MAIN_V: u64 = 312_500_000;
const PRICE: u64 = 150;

fn key() -> PrimeKey { PrimeKey::from_seed(70, &[9u8; 32]) }
/// The shipped defaults at mainnet-shaped numbers: a 150-sat call is 10 work units.
fn config(k: &PrimeKey) -> WorkConfig {
    WorkConfig::new(NET, PROV, 70, &k.pubkey_hex(), "http://prime.test/receipt").shipped(MAIN_BITS, MAIN_V, PRICE)
}
fn receipt(inv: &str, seq: u64, cum: u64, first: u32, last: u32) -> WorkReceipt {
    WorkReceipt { seq, cum_work: cum, shares: seq, first_height: first, last_height: last, difficulty: 1, ..WorkReceipt::zero(70, PROV, inv) }
}
fn hash(h: u32) -> String { format!("{h:064x}") }
fn block(height: u32, paid: u64) -> ChainBlock {
    ChainBlock { height, hash: hash(height), value_sats: MAIN_V, paid_sats: paid, bits: MAIN_BITS, prev_bits: MAIN_BITS }
}
fn window_work() -> u64 { PrimeTerms::default().window_target(MAIN_BITS).unwrap() }
fn share(work: u64) -> u64 { (u128::from(MAIN_V) * u128::from(work) / u128::from(window_work())) as u64 }
fn stmt(height: u32, block_hash: &str, ws: u32) -> WindowStatement {
    WindowStatement { prime_id: 70, height, block_hash: block_hash.into(), window_start: ws, window_work: window_work(), min_payout: 546, fee_bps: 0 }
}
fn payment(inv_doc: &Value, k: &PrimeKey, r: &WorkReceipt, n: u64, path: &str) -> Value {
    let key = hex::decode(inv_doc["authKey"].as_str().unwrap()).unwrap();
    let s = k.sign(r).unwrap();
    let auth = auth_tag(&key, &r.invoice, n, r.seq, r.cum_work, &request_digest("GET", path, b"")).unwrap();
    json!({"x402Version": 2, "accepted": {"scheme": "xbt-work", "network": NET, "payTo": PROV},
           "payload": {"receipt": r.to_doc(), "sig": hex::encode(s.sig), "n": n, "auth": auth}})
}
fn call(wp: &Arc<WorkProvider>, pay: &Value, path: &str) -> std::result::Result<(), String> {
    WorkScheme(wp.clone()).authorize(pay, "GET", path, b"", PRICE, &format!("http://api.test{path}")).map(|_| ())
        .map_err(|v| v["error"].as_str().unwrap_or("").to_string())
}
fn state_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("xbt-work-agp097-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
/// A colluding pair: the Prime signs work nobody mined and the payer spends it until the provider
/// refuses.
#[derive(Default)]
struct Pair {
    /// (invoice document, the last `n` used on it)
    invoices: Vec<(Value, u64)>,
}

impl Pair {
    fn spend(k: &PrimeKey, wp: &Arc<WorkProvider>, doc: &Value, n: &mut u64) -> u64 {
        let r = receipt(doc["invoice"].as_str().unwrap(), 1, 1_000_000_000, 50, 51);
        let mut served = 0;
        loop {
            *n += 1;
            let path = format!("/v1/{}/{n}", &r.invoice[..8]);
            if call(wp, &payment(doc, k, &r, *n, &path), &path).is_err() {
                return served;
            }
            served += 1;
        }
    }

    /// Calls served on `invoices` new invoices.
    fn take(&mut self, k: &PrimeKey, wp: &Arc<WorkProvider>, invoices: usize) -> u64 {
        (0..invoices).map(|_| {
            let (doc, mut n) = (wp.issue_invoice().unwrap(), 0);
            let served = Self::spend(k, wp, &doc, &mut n);
            self.invoices.push((doc, n));
            served
        }).sum()
    }

    /// Calls served on the invoices it already has (no new work, no new receipt), then on
    /// `invoices` new ones.
    fn more(&mut self, k: &PrimeKey, wp: &Arc<WorkProvider>, invoices: usize) -> u64 {
        let old: u64 = self.invoices.iter_mut().map(|(doc, n)| Self::spend(k, wp, doc, n)).sum();
        old + self.take(k, wp, invoices)
    }
}

// ------------------------------------------------------------------------------------------------
// WORK 1. The rule: work the Prime signed for an invoice of this provider is credited whenever
// its payer first presents it.
// ------------------------------------------------------------------------------------------------

/// What the late first receipt may and may not do, on an invoice long past TTL and grace with no
/// record (it was never in a relay pull): with no work it is unknown, as before; with work under a
/// stranger's signature it is refused and the provider keeps nothing; with the Prime's it pays, by
/// a call after a restart or through the relay; and what was spent stays spent.
#[test]
fn a_first_receipt_with_work_is_taken_at_any_time_and_only_under_the_primes_signature() {
    let dir = state_dir("late");
    let k = key();
    let path = dir.join("work.json");
    let cfg = WorkConfig { state_path: Some(path.clone()), invoice_ttl_secs: 0, invoice_grace_secs: 0, ..config(&k) };
    let wp = Arc::new(WorkProvider::new(cfg.clone()).unwrap());
    let (doc, by_relay, retired) = (wp.issue_invoice().unwrap(), wp.issue_invoice().unwrap(), wp.issue_invoice().unwrap());
    let inv = doc["invoice"].as_str().unwrap().to_string();
    std::thread::sleep(std::time::Duration::from_millis(2100));
    assert!(wp.invoices().is_empty(), "past TTL and grace nothing is pulled for them");
    let before = std::fs::read(&path).unwrap();
    // no work: the invoice expired
    assert_eq!(call(&wp, &payment(&doc, &k, &WorkReceipt::zero(70, PROV, &inv), 1, "/v1/a"), "/v1/a"), Err("unknown_invoice".into()));
    // work, signed by somebody else: refused, and nothing is kept for it
    let stranger = PrimeKey::from_seed(70, &[3u8; 32]);
    let r = receipt(&inv, 1, 25, 101, 102);
    assert_eq!(call(&wp, &payment(&doc, &stranger, &r, 2, "/v1/a"), "/v1/a"), Err("bad_sig".into()));
    assert_eq!(wp.accept(&stranger.sign(&r).unwrap()).unwrap_err().code, "bad_sig");
    assert_eq!((wp.balance(&inv), std::fs::read(&path).unwrap() == before), (None, true), "an unsigned claim of work left a record");
    // the provider restarts; the payer's first call comes now, with the Prime's receipt
    drop(wp);
    let wp = Arc::new(WorkProvider::new(cfg.clone()).unwrap());
    assert_eq!(call(&wp, &payment(&doc, &k, &r, 3, "/v1/a"), "/v1/a"), Ok(()));
    assert_eq!(wp.balance(&inv), Some((25, 10)));
    // the record remembers `n` and what was spent: the same call again, an earlier `n`, and a
    // third call the balance does not cover
    assert_eq!(call(&wp, &payment(&doc, &k, &r, 3, "/v1/a"), "/v1/a"), Err("bad_auth".into()));
    assert_eq!(call(&wp, &payment(&doc, &k, &r, 1, "/v1/a"), "/v1/a"), Err("bad_auth".into()));
    assert_eq!(call(&wp, &payment(&doc, &k, &r, 4, "/v1/b"), "/v1/b"), Ok(()));
    assert_eq!(call(&wp, &payment(&doc, &k, &r, 5, "/v1/c"), "/v1/c"), Err("insufficient_work".into()));
    // and after another restart
    drop(wp);
    let wp = Arc::new(WorkProvider::new(cfg).unwrap());
    assert_eq!(wp.balance(&inv), Some((25, 20)));
    assert_eq!(call(&wp, &payment(&doc, &k, &r, 4, "/v1/b"), "/v1/b"), Err("bad_auth".into()), "a spent call played again after a restart");
    // through the relay or the Prime (`accept`), as late
    let late = by_relay["invoice"].as_str().unwrap();
    assert_eq!(wp.accept(&k.sign(&WorkReceipt::zero(70, PROV, late)).unwrap()).unwrap_err().code, "unknown_invoice");
    assert_eq!(wp.accept(&k.sign(&receipt(late, 2, 40, 101, 103)).unwrap()).unwrap(), 40);
    // an invoice the operator retired before it was ever seen stays retired
    let gone = retired["invoice"].as_str().unwrap();
    wp.retire(gone).unwrap();
    assert_eq!(call(&wp, &payment(&retired, &k, &receipt(gone, 1, 50, 101, 102), 1, "/v1/a"), "/v1/a"), Err("unknown_invoice".into()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A Prime that is distrusted gets no record made by a late receipt either: the call is refused
/// with the reason for the distrust and nothing is kept for the invoice.
#[test]
fn a_distrusted_primes_late_receipt_makes_no_record() {
    let k = key();
    let wp = Arc::new(WorkProvider::new(WorkConfig { invoice_ttl_secs: 0, invoice_grace_secs: 0, ..config(&k) }).unwrap());
    let (doc, other) = (wp.issue_invoice().unwrap(), wp.issue_invoice().unwrap());
    let (inv, o) = (doc["invoice"].as_str().unwrap().to_string(), other["invoice"].as_str().unwrap().to_string());
    // two receipts with one seq, presented by a payer: equivocation
    assert_eq!(call(&wp, &payment(&other, &k, &receipt(&o, 1, 100, 101, 102), 1, "/v1/a"), "/v1/a"), Ok(()));
    assert_eq!(call(&wp, &payment(&other, &k, &receipt(&o, 1, 101, 101, 102), 2, "/v1/a"), "/v1/a"), Err("equivocation".into()));
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert_eq!(call(&wp, &payment(&doc, &k, &receipt(&inv, 1, 50, 101, 102), 1, "/v1/a"), "/v1/a"), Err("equivocation".into()));
    assert_eq!(wp.balance(&inv), None);
}

// ------------------------------------------------------------------------------------------------
// WORK 2. The rule: unpaid credit counts against a cap that follows the price at the price it was
// granted at.
// ------------------------------------------------------------------------------------------------

/// The shipped caps are 100 and 1,000 calls priced without the haircut: 90 and 900 calls. A pair
/// that took 270 of them before the difficulty doubled gets the other 630 after it (765 before
/// this change); when the difficulty falls back it gets none; and a restart at either epoch
/// changes nothing. No coinbase pays anything throughout.
#[test]
fn a_prime_that_never_pays_is_served_the_cap_once_across_epochs_and_restarts() {
    let dir = state_dir("rate");
    let k = key();
    let at = |bits: u32| WorkConfig { state_path: Some(dir.join("work.json")),
                                      ..WorkConfig::new(NET, PROV, 70, &k.pubkey_hex(), "http://prime.test/receipt").shipped(bits, MAIN_V, PRICE) };
    let wp = Arc::new(WorkProvider::new(at(MAIN_BITS)).unwrap());
    let mut pair = Pair::default();
    assert_eq!(pair.take(&k, &wp, 3), 270, "90 calls an invoice");
    assert!(wp.set_epoch(MAIN_BITS_X2, MAIN_V));
    assert_eq!((wp.amount(PRICE).unwrap(), wp.caps().total), (20, Some(18_000)));
    assert_eq!(pair.more(&k, &wp, 12), 630, "the rest of the cap, in calls");
    assert_eq!(wp.exposure().0, 2_700 + 12_600, "balances are not revalued: unpaid work units");
    // a restart on the new tip (the binary reads the epoch from its node when it starts)
    drop(wp);
    let wp = Arc::new(WorkProvider::new(at(MAIN_BITS_X2)).unwrap());
    assert_eq!(pair.more(&k, &wp, 3), 0, "after a restart at the higher difficulty");
    // the difficulty falls back, and further: a call costs fewer units and the cap shrinks with
    // it. No credit is extended. (Credit already given and not spent would buy more calls now:
    // the limit pinned below. Here all of it was spent.)
    for (bits, cost) in [(MAIN_BITS, 10), (MAIN_BITS_HALF, 5)] {
        assert!(wp.set_epoch(bits, MAIN_V));
        assert_eq!(wp.amount(PRICE).unwrap(), cost);
        assert_eq!((pair.more(&k, &wp, 3), wp.exposure().0), (0, 15_300), "at {cost} units a call");
    }
    drop(wp);
    let wp = Arc::new(WorkProvider::new(at(MAIN_BITS_HALF)).unwrap());
    assert_eq!(pair.more(&k, &wp, 3), 0, "after a restart at the lower difficulty");
    // and up again, past where it began
    assert!(wp.set_epoch(MAIN_BITS_X2, MAIN_V));
    assert_eq!(pair.more(&k, &wp, 3), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The limit that stays (§6.3: balances are kept in work units and never revalued). The caps bound
/// the credit a Prime that never pays is given; what that credit buys is decided when it is spent.
/// A pair that takes the whole cap as credit and spends none of it until the difficulty has
/// halved is served twice the cap's calls: 1,800 against 900. It needs the difficulty to fall
/// while the credit is held, and a fall by a factor f gives f times the cap at most.
#[test]
fn limit_credit_held_unspent_buys_more_calls_when_the_difficulty_falls() {
    let k = key();
    let wp = Arc::new(WorkProvider::new(WorkConfig::new(NET, PROV, 70, &k.pubkey_hex(), "http://prime.test/receipt").shipped(MAIN_BITS_X2, MAIN_V, PRICE)).unwrap());
    // the whole cap as credit, nothing spent
    let docs: Vec<Value> = (0..12).map(|_| wp.issue_invoice().unwrap()).collect();
    for d in &docs {
        wp.accept(&k.sign(&receipt(d["invoice"].as_str().unwrap(), 1, 1_000_000_000, 50, 51)).unwrap()).unwrap();
    }
    assert_eq!((wp.exposure().0, wp.amount(PRICE).unwrap()), (18_000, 20));
    assert!(wp.set_epoch(MAIN_BITS, MAIN_V));
    let mut pair = Pair { invoices: docs.into_iter().map(|d| (d, 0)).collect() };
    let served = pair.more(&k, &wp, 3);
    assert_eq!((served, wp.exposure().0), (1_800, 18_000), "no credit beyond the cap was extended; the same units buy twice the calls");
    eprintln!("limit: the whole cap held as credit while the difficulty halves: {served} calls against a cap of 900");
}

/// A payment frees the calls it paid for, at any epoch: with 900 calls unpaid and the difficulty
/// doubled, a coinbase that pays for 4,500 of the 9,000 units frees 450 calls.
#[test]
fn a_coinbase_frees_the_calls_it_paid_for_whatever_the_epoch() {
    let k = key();
    let wp = Arc::new(WorkProvider::new(config(&k)).unwrap());
    let mut pair = Pair::default();
    assert_eq!(pair.take(&k, &wp, 12), 900);
    assert!(wp.set_epoch(MAIN_BITS_X2, MAIN_V));
    assert_eq!(pair.more(&k, &wp, 2), 0);
    // a coinbase that pays the identity what 4,500 units cost at its own difficulty
    let sats = (1..=u64::from(u32::MAX)).find(|s| wp.paid_work(&block(110, *s)).unwrap() >= 4_500).unwrap();
    assert_eq!(wp.paid_work(&block(110, sats)).unwrap(), 4_500, "{sats} sat");
    assert!(wp.audit(&k.sign_window(&stmt(110, &hash(110), 100)).unwrap(), &[], &block(110, sats)).unwrap().ok);
    assert_eq!(pair.more(&k, &wp, 8), 450, "450 of the 900 unpaid calls were paid for");
    assert_eq!(pair.more(&k, &wp, 2), 0);
}

/// A cap set in work units is in work units: it does not move with the epoch, and unpaid credit
/// counts against it unit for unit (at half the difficulty, credit counted at today's rate would
/// be half and the cap would be extended again).
#[test]
fn a_cap_in_work_units_counts_work_units_at_every_epoch() {
    let k = key();
    let cfg = WorkConfig { cap_rule: Some(Caps { invoice: Cap::Off, total: Cap::Work(9_000) }), ..config(&k) };
    let wp = Arc::new(WorkProvider::new(cfg).unwrap());
    let mut pair = Pair::default();
    assert_eq!(pair.take(&k, &wp, 1), 900);
    for (bits, cost) in [(MAIN_BITS_HALF, 5), (MAIN_BITS_X2, 20), (MAIN_BITS, 10)] {
        assert!(wp.set_epoch(bits, MAIN_V));
        assert_eq!((wp.caps().total, wp.amount(PRICE).unwrap(), pair.more(&k, &wp, 2)), (Some(9_000), cost, 0));
    }
}

/// State written before this change keeps no rate with its credit. It loads, the credit counts at
/// the epoch of that start, and from then on at the rate it has.
#[test]
fn credit_kept_without_a_rate_is_taken_at_the_epoch_of_the_first_start() {
    let dir = state_dir("upgrade");
    let k = key();
    let path = dir.join("work.json");
    let cfg = WorkConfig { state_path: Some(path.clone()), ..config(&k) };
    let wp = Arc::new(WorkProvider::new(cfg.clone()).unwrap());
    let mut pair = Pair::default();
    assert_eq!(pair.take(&k, &wp, 12), 900);
    drop(wp);
    // as wave 4 wrote it: [invoice, work]
    let mut v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for c in v["book"]["credits"].as_array_mut().unwrap() {
        assert_eq!(c.as_array().unwrap().len(), 4);
        c.as_array_mut().unwrap().truncate(2);
    }
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    let wp = Arc::new(WorkProvider::new(cfg).unwrap());
    assert_eq!((wp.exposure().0, pair.more(&k, &wp, 2)), (9_000, 0));
    assert!(wp.set_epoch(MAIN_BITS_X2, MAIN_V));
    assert_eq!(pair.more(&k, &wp, 2), 0, "the difficulty doubles after the upgrade");
    // a rate that does not read is refused, not guessed
    drop(wp);
    let mut v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    v["book"]["credits"][0][3] = json!(7);
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    let again = WorkProvider::new(WorkConfig { state_path: Some(path.clone()), ..config(&k) });
    assert_eq!(again.err().map(|e| e.code), Some("bad_state".into()));
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------------------------------------
// WORK 3. The rule: a window start is held only against audits of blocks still in the chain.
// ------------------------------------------------------------------------------------------------

/// (the verdict or the error's code, the distrust code, the height the walk goes over again, the
/// audited blocks)
type Regressed = (std::result::Result<Option<bool>, String>, Value, Option<u32>, Vec<(u32, String)>);

/// Block 111 of branch A audited (window start 100), then a statement for 110 with window start
/// 102: against the record of 111. Returns (the verdict or the error's code, distrust, what the
/// walk is told to go over again, the audited blocks).
fn regressed(hash_at: &dyn Fn(u32) -> Result<Option<String>>) -> Regressed {
    let k = key();
    let wp = WorkProvider::new(config(&k)).unwrap();
    let inv = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
    wp.accept(&k.sign(&receipt(&inv, 1, 800, 104, 105)).unwrap()).unwrap();
    let a111 = ChainBlock { hash: "a".repeat(64), ..block(111, share(800)) };
    assert!(wp.audit_chain_on(&a111, Statement::Found(&k.sign_window(&stmt(111, &a111.hash, 100)).unwrap(), &[]), hash_at).unwrap().unwrap().ok);
    let b110 = ChainBlock { hash: "b".repeat(64), ..block(110, share(800)) };
    let o = wp.audit_chain_on(&b110, Statement::Found(&k.sign_window(&stmt(110, &b110.hash, 102)).unwrap(), &[]), hash_at);
    (o.map(|o| o.map(|o| o.ok)).map_err(|e| e.code), wp.report()["distrust"]["code"].clone(), wp.undone(), wp.audited_blocks())
}

#[test]
fn a_window_start_that_went_backwards_on_one_chain_fails_the_prime() {
    // the node still has branch A's 111: the Prime signed both statements for one chain
    let (verdict, distrust, undone, audited) = regressed(&|h| Ok(Some(if h == 111 { "a".repeat(64) } else { hash(h) })));
    assert_eq!((verdict, distrust, undone), (Ok(Some(false)), json!("refused_statement"), None));
    assert!(audited.contains(&(111, "a".repeat(64))), "the audit it was held against stands: {audited:?}");
}

#[test]
fn an_audit_of_a_block_the_node_no_longer_has_is_undone_and_not_held_against_the_prime() {
    for (what, now) in [("another block at that height", Some("c".repeat(64))), ("no block at that height (a shorter chain for now)", None)] {
        let (verdict, distrust, undone, audited) = regressed(&|_| Ok(now.clone()));
        assert_eq!((verdict, distrust, undone), (Ok(Some(true)), Value::Null, Some(111)), "{what}");
        assert_eq!(audited, vec![(110, "b".repeat(64))], "{what}");
    }
}

/// The node cannot be asked: nothing is concluded. The statement is not audited, the record is
/// not undone, and the Prime is not blamed; the walk stops there and asks again.
#[test]
fn a_node_that_does_not_answer_leaves_the_record_and_the_prime_alone() {
    let asked = Mutex::new(0u32);
    let (verdict, distrust, undone, audited) = regressed(&|_| {
        *asked.lock().unwrap() += 1;
        Err(WorkError::new("rpc", "connection refused"))
    });
    assert_eq!((verdict, distrust, undone, *asked.lock().unwrap()), (Err("rpc".into()), Value::Null, None, 1));
    assert_eq!(audited, vec![(111, "a".repeat(64))]);
}

/// The provider's node and a Prime, in memory, on a chain that can be replaced.
struct Chain {
    k: PrimeKey,
    /// height -> (block hash, sats to the identity, the statement's window start)
    blocks: Mutex<HashMap<u32, (String, u64, u32)>>,
}

impl AuditSource for Chain {
    fn block(&self, height: u32) -> Result<ChainBlock> {
        let b = self.blocks.lock().unwrap();
        let (h, paid, _) = b.get(&height).cloned().unwrap_or((hash(height), 0, 0));
        Ok(ChainBlock { hash: h, ..block(height, paid) })
    }
    fn statement(&self, height: u32) -> Result<Option<ServedStatement>> {
        let b = self.blocks.lock().unwrap();
        Ok(b.get(&height).map(|(h, _, ws)| (self.k.sign_window(&stmt(height, h, *ws)).unwrap(), vec![], json!({}))))
    }
}

/// The whole path, as the binary runs it: the walk has passed 111 (branch A), a reorg replaces 110
/// and 111, and the operator's audit of the new 110 undoes the stale audit of 111. The walk is
/// then past a height that has no audit: it goes back over it, and the honest Prime ends with
/// both blocks of the new branch audited and no distrust.
#[test]
fn the_walk_goes_over_a_height_whose_audit_was_undone() {
    let k = key();
    let wp = WorkProvider::new(config(&k)).unwrap();
    let inv = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
    wp.accept(&k.sign(&receipt(&inv, 1, 800, 104, 105)).unwrap()).unwrap();
    let chain = Chain { k: key(), blocks: Mutex::new(HashMap::from([(111, ("a".repeat(64), share(800), 100))])) };
    let mut walk = Walk::new(109);
    let p = walk.pass(&wp, &chain, 111);
    assert_eq!((p.verdicts, walk.next()), (vec![(111, true)], 112));
    // the reorg: branch B, found later (its window is two blocks on)
    *chain.blocks.lock().unwrap() = HashMap::from([(110, ("b".repeat(64), share(800), 102)), (111, ("c".repeat(64), share(800), 102))]);
    let b110 = chain.block(110).unwrap();
    let (sw, _, _) = chain.statement(110).unwrap().unwrap();
    let o = wp.audit_chain_on(&b110, Statement::Found(&sw, &[]), &|h| chain.hash_at(h)).unwrap();
    assert!(o.is_some_and(|o| o.ok) && wp.report()["distrust"].is_null());
    assert_eq!(wp.audited_blocks(), vec![(110, "b".repeat(64))]);
    // nothing new to walk, and yet the pass audits 111 again
    let p = walk.pass(&wp, &chain, 111);
    assert_eq!((p.verdicts, p.stopped, walk.next()), (vec![(111, true)], None, 112));
    assert_eq!(wp.audited_blocks(), vec![(110, "b".repeat(64)), (111, "c".repeat(64))]);
    assert!(wp.report()["distrust"].is_null());
}

// ------------------------------------------------------------------------------------------------
// WORK 6 and the arithmetic. An epoch no price follows from; sums of numbers from outside.
// ------------------------------------------------------------------------------------------------

/// The node reports `bits` or a block value that no price follows from: the epoch in force stays,
/// new 402s and paid calls are priced as before, and the provider says why.
#[test]
fn an_epoch_no_price_follows_from_does_not_replace_the_one_in_force() {
    let k = key();
    let wp = Arc::new(WorkProvider::new(config(&k)).unwrap());
    let doc = wp.issue_invoice().unwrap();
    let r = receipt(doc["invoice"].as_str().unwrap(), 1, 100, 101, 102);
    for (n, (bits, value)) in [(0x0100_0001u32, MAIN_V), (0x0080_0000, MAIN_V), (0x2100_0001, MAIN_V), (MAIN_BITS_X2, 0)].into_iter().enumerate() {
        assert!(!wp.set_epoch(bits, value), "{bits:08x}, {value}");
        assert!(wp.epoch_error(bits, value).is_some());
        assert_eq!((wp.amount(PRICE).unwrap(), wp.caps().total), (10, Some(9_000)));
        assert!(WorkScheme(wp.clone()).requirements("GET", "/v1/a", PRICE).is_some(), "the next 402 has no xbt-work offer");
        let path = format!("/v1/{n}");
        assert_eq!(call(&wp, &payment(&doc, &k, &r, n as u64 + 1, &path), &path), Ok(()));
    }
    assert!(wp.epoch_error(MAIN_BITS_X2, MAIN_V).is_none() && wp.set_epoch(MAIN_BITS_X2, MAIN_V), "a real epoch is taken");
}

#[test]
fn the_audits_sum_of_what_was_paid_and_deferred_cannot_wrap() {
    assert!(covers(u64::MAX, u64::MAX, u64::MAX) && covers(1, u64::MAX, u64::MAX) && covers(u64::MAX - 1, 0, u64::MAX));
    assert!(!covers(0, 0, 2) && covers(0, 0, 1) && !covers(u64::MAX - 2, 0, u64::MAX));
}

// ------------------------------------------------------------------------------------------------
// WORK 5. The rule: the admin token is in a file only the operator's account can read, or it is
// not used.
// ------------------------------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn an_admin_token_file_others_can_read_is_refused_and_a_link_in_the_way_is_not_followed() {
    use std::os::unix::fs::PermissionsExt;
    let dir = state_dir("token");
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let chmod = |p: &std::path::Path, m: u32| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    // a token file that is there with an open mode: refused, unchanged, and used again once private
    let path = dir.join("admin.token");
    let token = admin_token(&path).unwrap();
    for open in [0o644, 0o640, 0o604, 0o620, 0o602] {
        chmod(&path, open);
        assert_eq!(admin_token(&path).unwrap_err().code, "bad_config", "mode {open:o}");
    }
    assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), token);
    chmod(&path, 0o400);
    assert_eq!(admin_token(&path).unwrap(), token, "read-only for the owner is private");
    // a link where the temporary file goes: the file it points at is not written, and the token
    // file is a new 0600 file
    let (victim, link, fresh) = (dir.join("victim"), dir.join("other.tmp"), dir.join("other.token"));
    std::fs::write(&victim, b"untouched").unwrap();
    chmod(&victim, 0o644);
    std::os::unix::fs::symlink(&victim, &link).unwrap();
    let t = admin_token(&fresh).unwrap();
    assert_eq!((std::fs::read(&victim).unwrap(), mode(&victim)), (b"untouched".to_vec(), 0o644));
    assert_eq!((std::fs::read_to_string(&fresh).unwrap().trim().to_string(), mode(&fresh)), (t, 0o600));
    assert!(std::fs::symlink_metadata(&fresh).unwrap().file_type().is_file());
    // the state file is written the same way: a 0644 `work.tmp` in the way does not open it
    std::fs::write(dir.join("work.tmp"), b"").unwrap();
    chmod(&dir.join("work.tmp"), 0o644);
    let k = key();
    let wp = WorkProvider::new(WorkConfig { state_path: Some(dir.join("work.json")), ..config(&k) }).unwrap();
    wp.issue_invoice().unwrap();
    assert_eq!(mode(&dir.join("work.json")), 0o600, "the state file holds the invoice secret");
    let _ = std::fs::remove_dir_all(&dir);
}
