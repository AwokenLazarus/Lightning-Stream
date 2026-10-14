//! AGP-102, fourth closure audit, pay-with-work (xbt-rs f5a4198). Written by the area auditor; no
//! code was changed.
//!
//! * `holds_*` and `control_*` pass: a bound the audit checked.
//! * `limit_*` pass: they pin a number a reader has to be told.
//! * every other test is named as the rule that should hold and FAILS on f5a4198 (a hole).
//!
//! The test of the relay pull against the shipped relay (its rate limit) needs the relay crate and
//! is in `crates/xbt-work-relay/tests/agp102_work.rs`.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use xbt402::client::Transport;
use xbt402::provider::HttpResponse;
use xbt402::scheme::ProviderScheme;
use xbt_work::audit::{Deferral, PrimeTerms, WindowStatement};
use xbt_work::auth::{auth_tag, request_digest};
use xbt_work::book::{Follows, Rate, ReceiptBook};
use xbt_work::chain::ChainBlock;
use xbt_work::payer::{PayerConfig, WorkPayer};
use xbt_work::provider::{Statement, WorkConfig, WorkProvider, WorkScheme};
use xbt_work::receipt::{PrimeKey, WorkReceipt};

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
fn shipped_at(k: &PrimeKey, bits: u32) -> WorkConfig {
    WorkConfig::new(NET, PROV, 70, &k.pubkey_hex(), "http://prime.test/receipt").shipped(bits, MAIN_V, PRICE)
}
fn config(k: &PrimeKey) -> WorkConfig { shipped_at(k, MAIN_BITS) }
fn receipt(inv: &str, seq: u64, cum: u64, first: u32, last: u32) -> WorkReceipt {
    WorkReceipt { seq, cum_work: cum, shares: seq, first_height: first, last_height: last, difficulty: 1, ..WorkReceipt::zero(70, PROV, inv) }
}
fn hash(h: u32) -> String { format!("{h:064x}") }
fn block(height: u32, paid: u64) -> ChainBlock {
    ChainBlock { height, hash: hash(height), value_sats: MAIN_V, paid_sats: paid, bits: MAIN_BITS, prev_bits: MAIN_BITS }
}
fn window_work() -> u64 { PrimeTerms::default().window_target(MAIN_BITS).unwrap() }
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
    let dir = std::env::temp_dir().join(format!("xbt-work-agp102-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A colluding pair: the Prime signs work nobody mined and the payer spends it until the provider
/// refuses (the rig of `agp097_work.rs`).
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

    fn take(&mut self, k: &PrimeKey, wp: &Arc<WorkProvider>, invoices: usize) -> u64 {
        (0..invoices).map(|_| {
            let (doc, mut n) = (wp.issue_invoice().unwrap(), 0);
            let served = Self::spend(k, wp, &doc, &mut n);
            self.invoices.push((doc, n));
            served
        }).sum()
    }

    fn more(&mut self, k: &PrimeKey, wp: &Arc<WorkProvider>, invoices: usize) -> u64 {
        let old: u64 = self.invoices.iter_mut().map(|(doc, n)| Self::spend(k, wp, doc, n)).sum();
        old + self.take(k, wp, invoices)
    }
}

/// A relay in memory: lookup -> blob. Before it answers it looks at the provider's state file, so a
/// round's requests see every write made between them.
struct Relay {
    blobs: Mutex<HashMap<String, Vec<u8>>>,
    state: Option<std::path::PathBuf>,
    /// (inode, ctime seconds, ctime nanoseconds) of the state file at each request.
    seen: Mutex<Vec<(u64, i64, i64)>>,
}

impl Relay {
    fn new(state: Option<std::path::PathBuf>) -> Self {
        Self { blobs: Mutex::new(HashMap::new()), state, seen: Mutex::new(vec![]) }
    }

    fn put(&self, k: &PrimeKey, r: &WorkReceipt) {
        let blob = xbt_work::relay::seal(xbt402::json::dumps(&k.sign(r).unwrap().to_doc()).as_bytes(), PROV, &r.invoice, None).unwrap();
        self.blobs.lock().unwrap().insert(xbt_work::relay::lookup(PROV, &r.invoice), blob);
    }

    #[cfg(unix)]
    fn look(&self) {
        use std::os::unix::fs::MetadataExt;
        if let Some(m) = self.state.as_ref().and_then(|p| std::fs::metadata(p).ok()) {
            self.seen.lock().unwrap().push((m.ino(), m.ctime(), m.ctime_nsec()));
        }
    }

    #[cfg(not(unix))]
    fn look(&self) {}

    /// How often the state file was replaced between the looks taken since the last call.
    fn replaced(&self) -> usize {
        self.look();
        let mut seen = self.seen.lock().unwrap();
        let n = seen.windows(2).filter(|w| w[0] != w[1]).count();
        seen.clear();
        n
    }
}

impl Transport for Relay {
    fn request(&self, _: &str, url: &str, _: &[u8], _: &[(String, String)]) -> xbt402::error::Result<HttpResponse> {
        self.look();
        Ok(match self.blobs.lock().unwrap().get(url.rsplit('/').next().unwrap_or("")) {
            Some(b) => HttpResponse::new(200, vec![], b.clone()),
            None => HttpResponse::new(404, vec![], b"not found".to_vec()),
        })
    }
}

// ------------------------------------------------------------------------------------------------
// Hole 1. The relay pull writes the whole state once for every invoice the relay still has a
// receipt for, in every round, whether or not anything changed.
// ------------------------------------------------------------------------------------------------

/// `WorkProvider::accept` writes the state whatever the book did with the receipt
/// (`provider.rs:784-786`), and the pull offers it the latest receipt of every invoice that has a
/// record, every round (3 s in the binary, `xbt-work-provider.rs:391, 417`). A record is never
/// dropped (AGP-097's rule 1 rests on that), so a provider that ever had N paying invoices writes
/// its whole state, about 620 bytes an invoice, and fsyncs it N times in every round in which the
/// relay still holds their receipts (the shipped relay keeps one 30 days after its last push).
/// That is N * N * 620 bytes every 3 s for nothing: 250 MB a round at 635 invoices. One pool share
/// makes an invoice. The rule: a round that credits nothing writes nothing. FAILS.
#[cfg(unix)]
#[test]
fn a_pull_round_that_credits_nothing_writes_no_state() {
    let dir = state_dir("pull");
    let k = key();
    let path = dir.join("work.json");
    let cfg = WorkConfig { state_path: Some(path.clone()), relay_url: Some("http://relay.test".into()), ..config(&k) };
    let wp = Arc::new(WorkProvider::new(cfg).unwrap());
    let relay = Relay::new(Some(path.clone()));
    let n: usize = std::env::var("AGP102_WORK_N").ok().and_then(|v| v.parse().ok()).unwrap_or(300);
    for _ in 0..n {
        let inv = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
        let r = receipt(&inv, 1, 1, 101, 101);
        wp.accept(&k.sign(&r).unwrap()).unwrap();
        relay.put(&k, &r);
    }
    let size = std::fs::metadata(&path).unwrap().len();
    relay.replaced();
    // the round the binary runs every 3 s: every receipt is the one the book already holds
    let t = std::time::Instant::now();
    let credited: u64 = wp.refresh(&relay).into_iter().map(|(_, r)| r.unwrap()).sum();
    let (took, writes) = (t.elapsed(), relay.replaced());
    // control: the same round against a relay that has nothing (404 for every lookup)
    let empty = Relay::new(Some(path.clone()));
    let t = std::time::Instant::now();
    wp.refresh(&empty);
    let (took_empty, writes_empty) = (t.elapsed(), empty.replaced());
    eprintln!("pull round, {n} invoices with one receipt each, nothing new: {writes} writes of the {size}-byte state ({} MB) in {took:?}; \
               the same round with nothing on the relay: {writes_empty} writes in {took_empty:?}", writes as u64 * size / 1_000_000);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!((credited, writes_empty), (0, 0), "control: nothing was credited, and a round of 404s writes nothing");
    assert_eq!(writes, 0, "a pull round that credited nothing replaced the {size}-byte state file {writes} times");
}

/// Control for the test above: what a round does credit is on disk when the round is over.
#[test]
fn control_a_pull_round_that_credits_work_keeps_it() {
    let dir = state_dir("pullkeeps");
    let k = key();
    let cfg = WorkConfig { state_path: Some(dir.join("work.json")), relay_url: Some("http://relay.test".into()), ..config(&k) };
    let wp = Arc::new(WorkProvider::new(cfg.clone()).unwrap());
    let relay = Relay::new(None);
    let inv = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
    relay.put(&k, &receipt(&inv, 1, 40, 101, 102));
    assert_eq!(wp.refresh(&relay).into_iter().map(|(_, r)| r.unwrap()).sum::<u64>(), 40);
    drop(wp);
    let wp = WorkProvider::new(cfg).unwrap();
    assert_eq!(wp.balance(&inv), Some((40, 0)));
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------------------------------------
// Question (a). One receipt, every way in: credited once; spent stays spent; another provider.
// ------------------------------------------------------------------------------------------------

/// The work of one receipt through the relay pull, the payer's call, the pull again, a restart, the
/// pull and the call again: credited once, and what was spent stays spent. A provider with the
/// same identity and Prime and its own invoice secret (another instance, or this one after its
/// state was lost) takes neither the call nor the receipt: an identifier is this provider's only
/// under its secret.
#[test]
fn holds_one_receipt_is_credited_once_by_the_pull_the_call_and_after_a_restart_and_nowhere_else() {
    let dir = state_dir("once");
    let k = key();
    let cfg = WorkConfig { state_path: Some(dir.join("work.json")), relay_url: Some("http://relay.test".into()),
                           invoice_ttl_secs: 0, invoice_grace_secs: 0, ..config(&k) };
    let wp = Arc::new(WorkProvider::new(cfg.clone()).unwrap());
    let relay = Relay::new(None);
    let doc = wp.issue_invoice().unwrap();
    let inv = doc["invoice"].as_str().unwrap().to_string();
    let r = receipt(&inv, 3, 100, 101, 102);
    relay.put(&k, &r);
    assert_eq!(wp.refresh(&relay).into_iter().map(|(_, r)| r.unwrap()).sum::<u64>(), 100, "the pull, inside the TTL");
    assert_eq!(call(&wp, &payment(&doc, &k, &r, 1, "/v1/a"), "/v1/a"), Ok(()));
    assert_eq!(wp.balance(&inv), Some((100, 10)), "the call presents the receipt the pull already credited");
    assert_eq!(wp.refresh(&relay).into_iter().map(|(_, r)| r.unwrap()).sum::<u64>(), 0);
    std::thread::sleep(std::time::Duration::from_millis(1100));
    drop(wp);
    let wp = Arc::new(WorkProvider::new(cfg).unwrap());
    assert_eq!(wp.refresh(&relay).into_iter().map(|(_, r)| r.unwrap()).sum::<u64>(), 0, "after a restart, long past the TTL");
    assert_eq!(call(&wp, &payment(&doc, &k, &r, 1, "/v1/a"), "/v1/a"), Err("bad_auth".into()), "the spent call again");
    // an older receipt of the same invoice credits nothing and is no equivocation
    assert_eq!(wp.accept(&k.sign(&receipt(&inv, 2, 60, 101, 102)).unwrap()).unwrap(), 0);
    assert_eq!(call(&wp, &payment(&doc, &k, &r, 2, "/v1/b"), "/v1/b"), Ok(()));
    assert_eq!((wp.balance(&inv), wp.exposure()), (Some((100, 20)), (100, 0)));
    // the same identity and Prime under another invoice secret
    let other = Arc::new(WorkProvider::new(config(&k)).unwrap());
    assert_eq!(call(&other, &payment(&doc, &k, &r, 1, "/v1/a"), "/v1/a"), Err("unknown_invoice".into()));
    assert_eq!(other.accept(&k.sign(&r).unwrap()).unwrap_err().code, "unknown_invoice");
    assert_eq!(other.exposure(), (0, 0));
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------------------------------------
// Question (b). The `Rate` accounting: the numbers of the limits.
// ------------------------------------------------------------------------------------------------

/// AGP-097 stated limit 2 says "twice the cap's calls after a halving". The number is a ratio, not
/// a bound: credit taken at one difficulty and held buys, when it is spent, the cap times
/// (difficulty when granted / difficulty when spent). Two halvings: 3,600 calls against a cap of
/// 900. It does not compound beyond that ratio: once spent, no fall or rise gives the pair more.
#[test]
fn limit_credit_held_through_two_halvings_buys_four_times_the_cap() {
    let k = key();
    let wp = Arc::new(WorkProvider::new(shipped_at(&k, MAIN_BITS_X2)).unwrap());
    let docs: Vec<Value> = (0..12).map(|_| wp.issue_invoice().unwrap()).collect();
    for d in &docs {
        wp.accept(&k.sign(&receipt(d["invoice"].as_str().unwrap(), 1, 1_000_000_000, 50, 51)).unwrap()).unwrap();
    }
    assert_eq!((wp.exposure().0, wp.amount(PRICE).unwrap(), wp.caps().total), (18_000, 20, Some(18_000)), "the whole cap: 900 calls");
    assert!(wp.set_epoch(MAIN_BITS, MAIN_V) && wp.set_epoch(MAIN_BITS_HALF, MAIN_V));
    assert_eq!(wp.amount(PRICE).unwrap(), 5);
    let mut pair = Pair { invoices: docs.into_iter().map(|d| (d, 0)).collect() };
    let served = pair.more(&k, &wp, 3);
    assert_eq!((served, wp.exposure().0), (3_600, 18_000), "no new credit; the same units buy four times the calls");
    // spent: nothing more at this difficulty, at a lower one, or after a rise and another fall
    for bits in [0x1a03_c2d4u32, MAIN_BITS_X2, MAIN_BITS_HALF] {
        assert!(wp.set_epoch(bits, MAIN_V), "{bits:08x}");
        assert_eq!(pair.more(&k, &wp, 3), 0, "{bits:08x}");
    }
    eprintln!("limit: the whole cap held as credit through two halvings of the difficulty: {served} calls against a cap of 900");
}

/// AGP-097 stated limit 3 ("credit unpaid at an upgrade is counted at the epoch of the first
/// start"), in numbers: 900 calls unpaid in state written by wave 4, and the difficulty doubled
/// before the first start of wave 5. The credit has no rate, so it counts as 9,000 units of a cap
/// that is now 18,000: the pair is served 450 calls more, once. Without the upgrade in between the
/// answer is 0 (`agp097_work::a_prime_that_never_pays_is_served_the_cap_once_across_epochs_and_restarts`).
#[test]
fn limit_credit_from_before_the_upgrade_is_served_again_in_part_if_the_epoch_moved_before_the_first_start() {
    let dir = state_dir("upgrade");
    let k = key();
    let path = dir.join("work.json");
    let wp = Arc::new(WorkProvider::new(WorkConfig { state_path: Some(path.clone()), ..config(&k) }).unwrap());
    let mut pair = Pair::default();
    assert_eq!(pair.take(&k, &wp, 12), 900);
    drop(wp);
    // as wave 4 wrote it: [invoice, work]
    let mut v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for c in v["book"]["credits"].as_array_mut().unwrap() {
        c.as_array_mut().unwrap().truncate(2);
    }
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    let wp = Arc::new(WorkProvider::new(WorkConfig { state_path: Some(path.clone()), ..shipped_at(&k, MAIN_BITS_X2) }).unwrap());
    let more = pair.more(&k, &wp, 12);
    assert_eq!(more, 450);
    assert_eq!(pair.more(&k, &wp, 3), 0, "once");
    eprintln!("limit: 900 calls unpaid at the upgrade, the difficulty doubled before the first start: {more} more calls, once");
    let _ = std::fs::remove_dir_all(&dir);
}

/// "Rounded up, against the credit: at most one unit per grant." A grant is one run of credit to
/// one invoice at one rate, so two invoices credited in turn, one work unit at a time, make one
/// grant a unit. 450 calls of unpaid credit made that way (4,500 units at 10 a call) count, once a
/// call costs 11 units, as 9,000 units of a cap of 9,900: 818 calls of 900. Room is left for 81
/// calls where 450 are unpaid. It takes one-unit grants (a tenth of a call here) to matter; whole
/// receipts of many units lose at most a unit each.
#[test]
fn limit_small_grants_count_for_up_to_twice_their_calls_after_the_price_moves() {
    let k = key();
    let (a, b) = ("vfer2e5e75t4tv7in42lakx6i4", "vfer2e5e75t4tv7in42lakx6i5");
    let mut book = ReceiptBook::new(PROV, k.pubkey(), 70);
    (book.caps.total, book.rate, book.follows) = (Some(9_000), Rate { call: 10, sat: 1 << 40 }, (Follows::No, Follows::Calls));
    for i in 1..=2_250u64 {
        for inv in [a, b] {
            assert_eq!(book.accept(&k.sign(&receipt(inv, i, i, 101, 102)).unwrap(), inv).unwrap(), 1);
        }
    }
    assert_eq!((book.credits.len(), book.counted(None, Follows::Calls), book.room(a)), (4_500, 4_500, 4_500));
    (book.caps.total, book.rate.call) = (Some(9_900), 11);
    let (counted, room) = (book.counted(None, Follows::Calls), book.room(a));
    assert_eq!((counted, room), (9_000, 900), "4,950 units at today's rate are counted as 9,000");
    // control: the same credit as one grant to each invoice counts 4,950 (one unit of rounding each)
    let mut whole = ReceiptBook::new(PROV, k.pubkey(), 70);
    (whole.caps.total, whole.rate, whole.follows) = (Some(9_000), Rate { call: 10, sat: 1 << 40 }, (Follows::No, Follows::Calls));
    for inv in [a, b] {
        whole.accept(&k.sign(&receipt(inv, 1, 2_250, 101, 102)).unwrap(), inv).unwrap();
    }
    (whole.caps.total, whole.rate.call) = (Some(9_900), 11);
    assert_eq!((whole.counted(None, Follows::Calls), whole.room(a)), (4_950, 4_950));
    eprintln!("limit: 450 unpaid calls granted one unit at a time count as {} calls of a 900-call cap after a 10% rise; room for {} calls, not 450",
              counted / 11, room / 11);
}

// ------------------------------------------------------------------------------------------------
// The third audit's question 1 (P4's bound), on the wave 5 code.
// ------------------------------------------------------------------------------------------------

/// A Prime colluding with a payer that never gives a statement, on blocks that pay the identity the
/// whole coinbase, across a doubling and two halvings of the difficulty and a restart, with the
/// node form of the audit: served the cap (900 calls at exact pricing) once, never failed or
/// distrusted, nothing covered. The pair spends as it goes: credit held unspent is the limit above.
#[test]
fn holds_p4_a_prime_that_never_gives_a_statement_is_served_the_cap_once_at_every_epoch() {
    let dir = state_dir("p4");
    let k = key();
    let at = |bits: u32| WorkConfig { state_path: Some(dir.join("work.json")), ..shipped_at(&k, bits) };
    let mut wp = Arc::new(WorkProvider::new(at(MAIN_BITS)).unwrap());
    let mut pair = Pair::default();
    let mut served = pair.take(&k, &wp, 12);
    assert_eq!(served, 900);
    let mut h = 100u32;
    for bits in [MAIN_BITS_X2, MAIN_BITS, MAIN_BITS_HALF, MAIN_BITS_X2] {
        for _ in 0..40 {
            h += 1;
            let stmt = match h & 1 {
                0 => Statement::Missing,
                _ => Statement::Unavailable,
            };
            assert!(wp.audit_chain_on(&block(h, MAIN_V), stmt, &|x| Ok(Some(hash(x)))).unwrap().is_none());
        }
        assert!(wp.set_epoch(bits, MAIN_V));
        served += pair.more(&k, &wp, 2);
        drop(wp);
        wp = Arc::new(WorkProvider::new(at(bits)).unwrap());
        served += pair.more(&k, &wp, 2);
    }
    let r = wp.report();
    assert_eq!((served, wp.exposure().0, r["distrust"].clone(), r["credit"]["paidForWork"].clone()), (900, 9_000, Value::Null, json!(0)));
    assert_eq!(r["unpaidBlocks"]["count"], json!(160));
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------------------------------------
// Question (c). `audit_chain` without a node.
// ------------------------------------------------------------------------------------------------

/// What "it loses that block's cover and gains nothing" leaves out for an embedder that calls
/// `audit_chain` (the form with no node): the audit that is undone takes the carry the Prime signed
/// for that block with it. Block 111 passes on a deferral line of 200,000 sat, which is over the
/// shipped cap on owed carry (150,000 sat at 150 sat a call): credit is frozen (`carry_cap`). The
/// Prime then gives, for block 110, a statement whose window start is above the one on record for
/// 111. With no node to ask, the audit of 111 is undone: the carry is gone and so is the freeze,
/// and a 404 for 111 from then on keeps it so. Control: the form `xbt-work-provider` uses, with a
/// node that still has 111, fails and distrusts the Prime and keeps the carry.
#[test]
fn limit_without_a_node_a_conflicting_statement_erases_the_carry_the_prime_signed() {
    let run = |node: bool| {
        let k = key();
        let wp = WorkProvider::new(config(&k)).unwrap();
        let inv = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
        wp.accept(&k.sign(&receipt(&inv, 1, 800, 104, 105)).unwrap()).unwrap();
        let there = |h: u32| -> xbt_work::Result<Option<String>> { Ok(Some(hash(h))) };
        let audit = |b: &ChainBlock, s: Statement<'_>| if node { wp.audit_chain_on(b, s, &there) } else { wp.audit_chain(b, s) };
        let line = k.sign_deferral(&Deferral { prime_id: 70, height: 111, block_hash: hash(111), identity: PROV.into(), sats: 200_000,
                                                reason: "over-budget".into() }).unwrap();
        let o = audit(&block(111, 0), Statement::Found(&k.sign_window(&stmt(111, &hash(111), 100)).unwrap(), &[line])).unwrap().unwrap();
        assert!(o.ok && o.proven_work == 800 && o.expected_sats > 546, "{o:?}");
        assert_eq!((wp.carry().owed(), wp.report()["credit"]["frozen"].clone()), (200_000, json!("carry_cap")));
        let again = audit(&block(110, 0), Statement::Found(&k.sign_window(&stmt(110, &hash(110), 105)).unwrap(), &[])).unwrap();
        let _ = audit(&block(111, 0), Statement::Missing).unwrap();
        let r = wp.report();
        (again.map(|o| o.ok), wp.carry().owed(), r["credit"]["frozen"].clone(), r["distrust"]["code"].clone())
    };
    assert_eq!(run(true), (Some(false), 200_000, json!("carry_cap"), json!("refused_statement")), "control: the node still has 111");
    assert_eq!(run(false), (Some(true), 0, Value::Null, Value::Null), "no node: the audit of 111 and its carry are gone");
}

// ------------------------------------------------------------------------------------------------
// Hole. A number from the provider's node that is summed without a check.
// ------------------------------------------------------------------------------------------------

/// `tools::paid_to` adds the coinbase outputs that pay the identity with `Iterator::sum`
/// (`tools.rs:115`); `coinbase_outputs` next to it saturates (`tools.rs:84`). Two outputs whose
/// values sum past u64 panic (every profile has overflow checks). The values are the node's
/// (`getblock`), so only a broken or hostile node gets here, as with the `bits` of the third
/// audit's item 13. In the binary it is under the audit walk: the round panics, the walk stays at
/// that height and panics again every 2 s, and no later block is audited. FAILS: it panics.
#[cfg(feature = "tools")]
#[test]
fn what_a_coinbase_pays_the_identity_is_summed_without_a_panic() {
    let outs = vec![(PROV.to_string(), u64::MAX), ("bcrt1qother".to_string(), 7), (PROV.to_string(), 1)];
    let quiet = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(|| xbt_work::tools::paid_to(&outs, PROV));
    std::panic::set_hook(quiet);
    assert_eq!(xbt_work::tools::paid_to(&outs[..2], PROV), u64::MAX, "control");
    assert!(r.is_ok(), "paid_to panicked on two outputs to the identity that sum past u64");
}

// ------------------------------------------------------------------------------------------------
// Hole (AGP-096 found-not-fixed 3). The payer's saved sessions and the spelling of the origin.
// ------------------------------------------------------------------------------------------------

/// Since AGP-096 `xbt402::client::split_url` gives the canonical origin (lowercase host, no default
/// port), and that is the key under which the client asks the work payer for its session
/// (`SchemePayer::upfront`, `answer`) and under which `WorkPayer::prepare` saves one. A session
/// file written before, by a payer that spelled its seller `http://API.example:80`, holds the
/// session under that spelling (the old `split_url` kept it). After the upgrade it is not found:
/// the payer takes a new invoice, and the work mined on the old one, which the provider was paid
/// for, is never presented. `WorkPayer::load` (`payer.rs:402-418`) keeps the keys as they are.
/// The rule: a saved session is found under every spelling of its origin. FAILS.
#[test]
fn a_session_saved_under_another_spelling_of_the_origin_is_still_this_sellers_session() {
    let dir = state_dir("payer");
    let k = key();
    let inv = "vfer2e5e75t4tv7in42lakx6i4";
    let session = json!({"accepted": {"scheme": "xbt-work", "network": NET, "amount": "10", "payTo": PROV, "extra": {"primePubkey": k.pubkey_hex()}},
                         "invoice": {"invoice": inv, "identity": PROV, "authKey": "11".repeat(32)},
                         "n": 4, "best": k.sign(&receipt(inv, 5, 500, 101, 102)).unwrap().to_doc(), "spent": 40, "unanswered": []});
    let found = |saved_under: &str, url: &str| {
        let path = dir.join("payer.json");
        std::fs::write(&path, serde_json::to_vec(&json!({saved_under: session.clone()})).unwrap()).unwrap();
        let p = WorkPayer::new(PayerConfig { network: NET.into(), state_path: Some(path), ..Default::default() }).unwrap();
        p.session(&xbt402::client::split_url(url).0).map(|s| (s.credited(), s.spent))
    };
    assert_eq!(found("http://api.example", "http://api.example/v1/a"), Some((500, 40)), "control: one spelling throughout");
    assert_eq!(found("http://api.example", "http://API.example:80/v1/a"), Some((500, 40)), "control: saved canonical, asked for in another spelling");
    let old = found("http://API.example:80", "http://API.example:80/v1/a");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(old, Some((500, 40)), "a session saved as the old client spelled it (500 work units, 40 spent) is not found for the same URL");
}

// ------------------------------------------------------------------------------------------------
// Holes. What the relay pull (`WorkProvider::accept`) does not do that a call does.
// ------------------------------------------------------------------------------------------------

/// One invoice, receipt A (seq 1, 100 work units) credited, then the Prime signs B: the same seq,
/// 200 work units. Returns (the code B was refused with, the distrust code, equivocations on
/// record, whether the payer's next call with a later receipt is served), B having come through
/// the relay pull or in a call.
fn equivocates(by_pull: bool) -> (String, Value, usize, std::result::Result<(), String>) {
    let k = key();
    let wp = Arc::new(WorkProvider::new(WorkConfig { relay_url: Some("http://relay.test".into()), ..config(&k) }).unwrap());
    let relay = Relay::new(None);
    let doc = wp.issue_invoice().unwrap();
    let inv = doc["invoice"].as_str().unwrap().to_string();
    let (a, b) = (receipt(&inv, 1, 100, 101, 102), receipt(&inv, 1, 200, 101, 102));
    relay.put(&k, &a);
    assert_eq!(wp.refresh(&relay).into_iter().map(|(_, r)| r.unwrap()).sum::<u64>(), 100);
    let refused = if by_pull {
        relay.put(&k, &b);
        wp.refresh(&relay).into_iter().find(|(i, _)| *i == inv).unwrap().1.unwrap_err().code
    } else {
        call(&wp, &payment(&doc, &k, &b, 1, "/v1/b"), "/v1/b").unwrap_err()
    };
    let r = wp.report();
    let next = call(&wp, &payment(&doc, &k, &receipt(&inv, 2, 300, 101, 103), 2, "/v1/a"), "/v1/a");
    (refused, r["distrust"]["code"].clone(), r["equivocations"].as_array().unwrap().len(), next)
}

/// "After an equivocation or a failed audit, the Prime's receipts are refused" (README.md:2662;
/// `State::distrust`: "set once the Prime key equivocated"). The distrust is set where a call
/// finds the equivocation (`provider.rs:1338-1340`). `accept`, which the relay pull uses
/// (`provider.rs:778`, `803`), keeps the fraud proof in the book and sets nothing: the Prime goes
/// on being credited and its payers served. Control: the same two receipts with the second in a
/// call. FAILS: no distrust, and the next call is served.
#[test]
fn an_equivocation_the_relay_pull_sees_distrusts_the_prime() {
    assert_eq!(equivocates(false), ("equivocation".into(), json!("equivocation"), 1, Err("equivocation".into())), "control: found by a call");
    let (refused, distrust, proofs, next) = equivocates(true);
    assert_eq!((refused.as_str(), proofs), ("equivocation", 1), "the pull found it and kept the proof");
    assert_eq!((distrust, next), (json!("equivocation"), Err("equivocation".into())), "found by the pull: the Prime is not distrusted and its next receipt pays");
}

/// The same equivocation is found again by every pull round while the relay holds the second
/// receipt, and each round appends the pair to the book's fraud proofs (`book.rs:336-340`): about
/// 0.6 kB more state every 3 s, for good, written with every state write. The rule: one
/// equivocation is recorded once. FAILS: five rounds, five proofs.
#[test]
fn one_equivocation_is_recorded_once_however_often_the_pull_sees_it() {
    let k = key();
    let wp = Arc::new(WorkProvider::new(WorkConfig { relay_url: Some("http://relay.test".into()), ..config(&k) }).unwrap());
    let relay = Relay::new(None);
    let inv = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
    relay.put(&k, &receipt(&inv, 1, 100, 101, 102));
    wp.refresh(&relay);
    relay.put(&k, &receipt(&inv, 1, 200, 101, 102));
    let sizes: Vec<(usize, usize)> = (0..5).map(|_| {
        wp.refresh(&relay);
        let r = wp.report();
        (r["equivocations"].as_array().unwrap().len(), xbt402::json::dumps(&r["equivocations"]).len())
    }).collect();
    eprintln!("equivocations on record, and their bytes, after each of five pull rounds: {sizes:?}");
    assert_eq!(sizes.iter().map(|(n, _)| *n).collect::<Vec<_>>(), vec![1; 5]);
}

/// AGP-097's table for rule 8 has the row "a distrusted Prime's late receipt: no record", tested
/// through a call (`agp097_work::a_distrusted_primes_late_receipt_makes_no_record`). Through the
/// relay pull the same receipt makes the record and is credited against the caps: `accept` does
/// not look at the distrust. The credit cannot be spent (a call is refused with the distrust), so
/// what it costs is the cap's room and the state. The rule: a distrusted Prime's receipt makes no
/// record and no credit, on either path. FAILS.
#[test]
fn a_distrusted_primes_receipt_makes_no_record_through_the_pull_either() {
    let k = key();
    let wp = Arc::new(WorkProvider::new(WorkConfig { relay_url: Some("http://relay.test".into()), ..config(&k) }).unwrap());
    let relay = Relay::new(None);
    let (other, doc) = (wp.issue_invoice().unwrap(), wp.issue_invoice().unwrap());
    let (o, inv) = (other["invoice"].as_str().unwrap().to_string(), doc["invoice"].as_str().unwrap().to_string());
    assert_eq!(call(&wp, &payment(&other, &k, &receipt(&o, 1, 100, 101, 102), 1, "/v1/a"), "/v1/a"), Ok(()));
    assert_eq!(call(&wp, &payment(&other, &k, &receipt(&o, 1, 101, 101, 102), 2, "/v1/a"), "/v1/a"), Err("equivocation".into()));
    assert_eq!((wp.report()["distrust"]["code"].clone(), wp.exposure().0), (json!("equivocation"), 100));
    // control: by a call, as AGP-097 tested it
    assert_eq!(call(&wp, &payment(&doc, &k, &receipt(&inv, 1, 50, 101, 102), 1, "/v1/a"), "/v1/a"), Err("equivocation".into()));
    assert_eq!(wp.balance(&inv), None, "control");
    relay.put(&k, &receipt(&inv, 1, 50, 101, 102));
    wp.refresh(&relay);
    assert_eq!((wp.balance(&inv), wp.exposure().0), (None, 100), "the distrusted Prime's receipt, through the pull, made a record and was credited");
}
