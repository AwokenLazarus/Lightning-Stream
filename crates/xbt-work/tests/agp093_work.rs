//! AGP-093, third closure audit, pay-with-work (xbt-rs f52e235). Written by the area auditor; no
//! code was changed.
//!
//! * `holds_*` pass: they pin a bound the audit checked (above all the P4 bound of AGP-091's
//!   decision 1: a Prime that never gives a statement).
//! * `limit_*` pass: they pin a number a reader has to be told.
//! * every other test is named as the claim that should hold and FAILS on f52e235 (a hole).
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use xbt402::client::Transport;
use xbt402::provider::HttpResponse;
use xbt402::scheme::ProviderScheme;
use xbt_work::audit::{PrimeTerms, WindowStatement};
use xbt_work::auth::{auth_tag, request_digest};
use xbt_work::chain::ChainBlock;
use xbt_work::provider::{admin_token, Amount, ServedStatement, Statement, WorkConfig, WorkProvider, WorkScheme};
use xbt_work::receipt::{PrimeKey, WorkReceipt};
use xbt_work::walk::{AuditSource, Walk};
use xbt_work::{Result, WorkError};

const NET: &str = "bip122:00000000000000000000000000000001";
const PROV: &str = "bcrt1q76vavszzsq657n375vk6updhxm0tfay7k28cc3";
const MAIN_BITS: u32 = 0x1a00_f0b5;
/// Twice the difficulty of `MAIN_BITS` (half the target).
const MAIN_BITS_X2: u32 = 0x1a00_785a;
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
/// One paid call at the shipped price: Ok, or the refusal's `error`.
fn call(wp: &Arc<WorkProvider>, pay: &Value, path: &str) -> std::result::Result<(), String> {
    WorkScheme(wp.clone()).authorize(pay, "GET", path, b"", PRICE, &format!("http://api.test{path}")).map(|_| ())
        .map_err(|v| v["error"].as_str().unwrap_or("").to_string())
}
fn state_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("xbt-work-agp093-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A colluding pair: the Prime signs `cum` work units nobody mined on each of `invoices` invoices
/// and the payer spends them until the provider refuses. Returns (invoice docs, calls served).
fn take_free_calls(k: &PrimeKey, wp: &Arc<WorkProvider>, invoices: usize, cum: u64, tag: &str) -> (Vec<(Value, u64)>, u64) {
    let (mut docs, mut served) = (vec![], 0u64);
    for i in 0..invoices {
        let doc = wp.issue_invoice().unwrap();
        let r = receipt(doc["invoice"].as_str().unwrap(), 1, cum, 50, 51);
        let mut n = 0u64;
        loop {
            n += 1;
            let path = format!("/v1/{tag}/{i}/{n}");
            match call(wp, &payment(&doc, k, &r, n, &path), &path) {
                Ok(()) => served += 1,
                Err(_) => break,
            }
        }
        docs.push((doc, n));
    }
    (docs, served)
}

/// The provider's node and a Prime, in memory, for the walk.
struct Chain {
    /// What each coinbase pays the identity.
    paid: HashMap<u32, u64>,
    /// What the Prime answers: None is 404, Some(why) an answer that is no statement.
    prime: HashMap<u32, Option<&'static str>>,
}

impl AuditSource for Chain {
    fn block(&self, height: u32) -> Result<ChainBlock> {
        Ok(block(height, self.paid.get(&height).copied().unwrap_or(0)))
    }
    fn statement(&self, height: u32) -> Result<Option<ServedStatement>> {
        match self.prime.get(&height).copied().flatten() {
            None => Ok(None),
            Some(why) => Err(WorkError::new("prime", format!("window statement for {height}: {why}"))),
        }
    }
}

// ------------------------------------------------------------------------------------------------
// Decision 1 of AGP-091 (P4): a Prime that is paid for work and never gives a statement.
// ------------------------------------------------------------------------------------------------

/// The P4 bound, pinned. A Prime colluding with a payer signs receipts for work nobody mined, the
/// payer spends them, and the Prime never gives a statement for any block: 404, 5xx and garbage
/// for 300 blocks, on coinbases that pay the identity nothing, 1 sat or the whole block. The Prime
/// is never failed and never distrusted (that is AGP-091's decision 1). What it costs the provider
/// is the total cap on unpaid credit and nothing more: no unit is covered, nothing is released, a
/// restart and an unchanged epoch change nothing, and the next call is refused.
///
/// In numbers, shipped defaults at `--price 150`: 900 calls (135,000 sat) with exact pricing, where
/// the cap is 1,000 calls priced without the 10% haircut; 1,000 calls (150,000 sat) under
/// `--work-units`. The per-invoice cap (100 calls) only makes the pair use ten invoices.
#[test]
fn holds_p4_a_prime_that_never_gives_a_statement_costs_the_total_cap_and_no_more() {
    for (name, amount, calls) in [("exact pricing", None, 900u64), ("--work-units 7", Some(Amount::Fixed(7)), 1000)] {
        let dir = state_dir(&format!("p4-{}", calls));
        let k = key();
        let mut cfg = WorkConfig { state_path: Some(dir.join("work.json")), ..config(&k) };
        if let Some(a) = amount.clone() {
            cfg.amount = a;
        }
        let wp = Arc::new(WorkProvider::new(cfg.clone()).unwrap());
        let cost = wp.amount(PRICE).unwrap();
        let (docs, served) = take_free_calls(&k, &wp, 15, 1_000_000_000, "a");
        assert_eq!(served, calls, "{name}: calls served on receipts nobody mined");
        let owed = wp.exposure().0;
        assert_eq!(owed, calls * cost, "{name}: unpaid credit is the total cap");
        assert_eq!(Some(owed), wp.caps().total, "{name}");

        // 300 blocks, none with a statement: nothing, 1 sat, the whole block; 404, 500, garbage
        let mut chain = Chain { paid: HashMap::new(), prime: HashMap::new() };
        for h in 103..=402u32 {
            chain.paid.insert(h, [0, 1, MAIN_V][h as usize % 3]);
            chain.prime.insert(h, [None, Some("HTTP 500"), Some("window statement is not JSON"), Some("HTTP 503")][h as usize % 4]);
        }
        let mut walk = Walk::new(103);
        for _ in 0..80 {
            let p = walk.pass(&wp, &chain, 402);
            assert!(p.stopped.is_none() && p.verdicts.is_empty(), "{name}: {p:?}");
        }
        assert_eq!(walk.next(), 403, "{name}: the walk went through every block");
        let r = wp.report();
        assert!(r["distrust"].is_null(), "{name}: never distrusted (AGP-091 decision 1): {}", r["distrust"]);
        assert_eq!(r["audits"], json!([]), "{name}: no block has a verdict");
        assert_eq!(r["credit"]["paidForWork"], json!(0), "{name}: nothing a silent coinbase paid covers credit");
        assert_eq!(r["unpaidBlocks"]["count"], json!(300), "{name}: every such block is counted");
        assert_eq!(r["unpaidBlocks"]["paidSats"], json!(100 * (MAIN_V + 1)), "{name}");
        assert!(r["credit"]["frozen"].is_null(), "{name}: --max-unpaid-blocks is off unless set");
        assert_eq!(wp.exposure().0, owed, "{name}: the walk released nothing");

        // nothing more is served: on the same invoices, on new ones, after the same epoch again
        // and after a restart
        assert!(!wp.set_epoch(MAIN_BITS, MAIN_V));
        let more = |wp: &Arc<WorkProvider>, tag: &str| {
            let mut ok = 0;
            for (i, (doc, n)) in docs.iter().enumerate() {
                let r = receipt(doc["invoice"].as_str().unwrap(), 1, 1_000_000_000, 50, 51);
                let path = format!("/v1/{tag}/{i}");
                ok += u64::from(call(wp, &payment(doc, &k, &r, n + 1 + u64::from(tag == "r"), &path), &path).is_ok());
            }
            ok + take_free_calls(&k, wp, 3, 1_000_000_000, tag).1
        };
        assert_eq!(more(&wp, "b"), 0, "{name}: calls served past the cap");
        drop(wp);
        let wp = Arc::new(WorkProvider::new(cfg).unwrap());
        assert_eq!((wp.exposure().0, more(&wp, "r")), (owed, 0), "{name}: after a restart");

        // and an honest payer who mines after that is not served either: its work is held
        let doc = wp.issue_invoice().unwrap();
        let r = receipt(doc["invoice"].as_str().unwrap(), 1, 10 * cost, 403, 404);
        assert_eq!(call(&wp, &payment(&doc, &k, &r, 1, "/v1/honest"), "/v1/honest"), Err("credit_cap".into()), "{name}");
        assert_eq!(wp.exposure(), (owed, 21_000_000_000 - owed + 10 * cost), "{name}: (unpaid, held)");
        eprintln!("P4 bound, {name}: {calls} calls of {cost} work units = {} sat at {PRICE} sat a call, once", calls * PRICE);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The same pair, and time: the cap is in calls and the unpaid credit is kept in work units, so
/// when a call costs more work units (the difficulty rises, or the block value halves) the same
/// unpaid units are fewer calls and the provider extends credit again, with no coinbase having
/// paid for anything. "Loss stays inside the caps" (AGP-091 stated limit 1) should mean the calls
/// served for nothing never exceed the cap. FAILS: 450 more calls at twice the difficulty.
#[test]
fn a_prime_that_never_pays_is_served_the_cap_once_whatever_the_epoch() {
    let k = key();
    let wp = Arc::new(WorkProvider::new(config(&k)).unwrap());
    let (docs, served) = take_free_calls(&k, &wp, 15, 1_000_000_000, "a");
    assert_eq!(served, 900);
    // the difficulty doubles: a call costs 20 work units, the cap is 18,000
    assert!(wp.set_epoch(MAIN_BITS_X2, MAIN_V));
    assert_eq!(wp.amount(PRICE).unwrap(), 20);
    // the pair goes on spending the receipts it has: no new work, no new receipt
    let mut again = 0u64;
    for (i, (doc, last_n)) in docs.iter().enumerate() {
        let r = receipt(doc["invoice"].as_str().unwrap(), 1, 1_000_000_000, 50, 51);
        let mut n = *last_n;
        loop {
            n += 1;
            let path = format!("/v1/b/{i}/{n}");
            match call(&wp, &payment(doc, &k, &r, n, &path), &path) {
                Ok(()) => again += 1,
                Err(_) => break,
            }
        }
    }
    assert_eq!(again, 0, "served {again} more unpaid calls after the difficulty doubled: {} in all against a cap of 1,000 calls, \
                                   and no coinbase paid for one", served + again);
}

// ------------------------------------------------------------------------------------------------
// Stateless invoices (AGP-091 WORK 3): the newest-64 pull list.
// ------------------------------------------------------------------------------------------------

/// A relay in memory: lookup -> blob.
struct Relay(Mutex<HashMap<String, Vec<u8>>>);

impl Transport for Relay {
    fn request(&self, _: &str, url: &str, _: &[u8], _: &[(String, String)]) -> xbt402::error::Result<HttpResponse> {
        Ok(match self.0.lock().unwrap().get(url.rsplit('/').next().unwrap_or("")) {
            Some(b) => HttpResponse::new(200, vec![], b.clone()),
            None => HttpResponse::new(404, vec![], b"not found".to_vec()),
        })
    }
}

/// A payer takes an invoice and mines on it at once; `flood` more invoices are issued after its
/// own (free, anonymous requests); the Prime's receipt is on the relay and the provider pulls, as
/// its loop does every 3 s. The payer makes its first call after the invoice's TTL and grace
/// (shipped: one hour each; 2 s and 1 s here). Returns that call's outcome.
fn slow_payer(flood: usize) -> std::result::Result<(), String> {
    let k = key();
    let cfg = WorkConfig { relay_url: Some("http://relay.test".into()), invoice_ttl_secs: 2, invoice_grace_secs: 1, ..config(&k) };
    let wp = Arc::new(WorkProvider::new(cfg).unwrap());
    let relay = Relay(Mutex::new(HashMap::new()));
    let doc = wp.issue_invoice().unwrap();
    let inv = doc["invoice"].as_str().unwrap().to_string();
    for _ in 0..flood {
        wp.issue_invoice().unwrap();
    }
    // the work is mined and receipted inside the TTL
    let r = receipt(&inv, 1, 100, 101, 102);
    let blob = xbt_work::relay::seal(xbt402::json::dumps(&k.sign(&r).unwrap().to_doc()).as_bytes(), PROV, &inv, None).unwrap();
    relay.0.lock().unwrap().insert(xbt_work::relay::lookup(PROV, &inv), blob);
    for _ in 0..3 {
        wp.refresh(&relay);
    }
    std::thread::sleep(std::time::Duration::from_secs(5));
    call(&wp, &payment(&doc, &k, &r, 1, "/v1/late"), "/v1/late")
}

/// AGP-091's rule for WORK 3 is "no number of requests, from one address or from many, can use up
/// issuance or push another payer's invoice out". The record of an invoice is still made only by
/// the provider's relay pull or by the payer's first call, and the pull asks only for the newest
/// 64 issued. 64 anonymous invoice requests push every earlier invoice out of the pull, and an
/// invoice with no record is unknown once its TTL and grace are over. A payer that mined in time
/// and calls later has paid the provider (its shares are in the pool's blocks) and cannot spend.
/// Control: with nothing issued after it, the same payer is served. FAILS: `unknown_invoice`.
#[test]
fn work_mined_inside_the_ttl_is_credited_whatever_was_issued_after_the_invoice() {
    assert_eq!(slow_payer(0), Ok(()), "control: nothing issued after it");
    assert_eq!(slow_payer(63), Ok(()), "control: 63 issued after it, still in the pull");
    assert_eq!(slow_payer(64), Ok(()), "64 invoices issued after the payer's own: its work, mined in time, is not credited");
}

// ------------------------------------------------------------------------------------------------
// What distrusts a Prime: an audit record of a block that left the chain.
// ------------------------------------------------------------------------------------------------

/// `WorkProvider::audit` holds a statement's window start against every audit on record, and
/// `window_start_regressed` is one of the two refusals that distrust the Prime for good. The
/// records are not checked against the chain there: the audit walk undoes orphaned ones before a
/// pass, the admin audit (`POST /admin/xbt-work/audit`, any range, the tip included) never does.
/// So: the operator audits the tip, block 111 on branch A; a reorg replaces 110 and 111 (branch B,
/// found later, so the honest Prime's window has moved on); the operator audits 110..111 again.
/// The honest statement for B's 110 has a window start above the one recorded for A's 111.
/// Control: with A's record undone first (what the walk does), the same statement passes.
/// FAILS: the honest Prime is distrusted, for good.
#[test]
fn an_audit_record_of_a_block_that_left_the_chain_does_not_distrust_an_honest_prime() {
    let run = |undo_first: bool| {
        let k = key();
        let wp = WorkProvider::new(config(&k)).unwrap();
        let inv = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
        wp.accept(&k.sign(&receipt(&inv, 1, 800, 104, 105)).unwrap()).unwrap();
        // branch A, block 111: audited at the tip, passes
        let a111 = ChainBlock { hash: "a".repeat(64), ..block(111, share(800)) };
        let o = wp.audit_chain(&a111, Statement::Found(&k.sign_window(&stmt(111, &a111.hash, 100)).unwrap(), &[])).unwrap().unwrap();
        assert!(o.ok && o.proven_work == 800);
        if undo_first {
            wp.orphaned(111).unwrap();
        }
        // branch B replaces 110 and 111; its 110 was found after A's 111, the window is two blocks on
        let b110 = ChainBlock { hash: "b".repeat(64), ..block(110, share(800)) };
        let o = wp.audit_chain(&b110, Statement::Found(&k.sign_window(&stmt(110, &b110.hash, 102)).unwrap(), &[])).unwrap();
        (o.map(|o| o.ok), wp.report()["distrust"].clone())
    };
    assert_eq!(run(true), (Some(true), Value::Null), "control: the orphaned audit undone first");
    let (verdict, distrust) = run(false);
    assert!(distrust.is_null() && verdict == Some(true), "an honest statement on the new branch: verdict {verdict:?}, distrust {distrust}");
}

// ------------------------------------------------------------------------------------------------
// Arithmetic on numbers from outside (overflow-checks = true in every release build).
// ------------------------------------------------------------------------------------------------

/// `bits_to_target` refuses a zero mantissa, but a mantissa shifted out by a small exponent
/// (`0x01000001`: 1 >> 16) is a zero target it returns as Ok, and every price, cap and window
/// bound then divides by it (ruint panics). The value comes from the provider's own node
/// (`getblockheader` of the tip, read every 3 s): no consensus-valid block has it, so only a
/// broken or hostile node gets here. In the binary the panic is in the relay-pull thread
/// (`set_epoch`), which is not restarted, after the rule in force was already replaced: every
/// later 402 and paid call then panics too (a 500 each). FAILS: it panics.
#[test]
fn no_bits_value_from_the_node_makes_pricing_panic() {
    let bad = 0x0100_0001u32;
    let quiet = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let price = std::panic::catch_unwind(|| xbt_work::pricing::work_units_for_price(PRICE, bad, MAIN_V, 0, 0).is_ok());
    let window = std::panic::catch_unwind(|| PrimeTerms::default().window_target(bad).is_ok());
    let k = key();
    let wp = Arc::new(WorkProvider::new(config(&k)).unwrap());
    let w2 = wp.clone();
    let epoch = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || w2.set_epoch(bad, MAIN_V)));
    let w3 = wp.clone();
    let after = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || w3.amount(PRICE).is_ok()));
    std::panic::set_hook(quiet);
    assert!(price.is_ok() && window.is_ok() && epoch.is_ok() && after.is_ok(),
            "bits {bad:08x}: work_units_for_price panicked: {}, window_target panicked: {}, set_epoch panicked: {}, the next quote panicked: {}",
            price.is_err(), window.is_err(), epoch.is_err(), after.is_err());
}

/// Numbers a payer, a Prime or a miner chooses, at their limits, through the provider's request
/// path and the audit: nothing panics and nothing wraps. (The node's `bits` is the one above.)
#[test]
fn holds_extreme_numbers_from_a_payer_a_prime_and_a_miner_do_not_panic() {
    let k = key();
    let wp = Arc::new(WorkProvider::new(config(&k)).unwrap());
    let doc = wp.issue_invoice().unwrap();
    let inv = doc["invoice"].as_str().unwrap().to_string();
    // a receipt at the top of every field, presented with n at the top
    let top = WorkReceipt { seq: u64::MAX, cum_work: u64::MAX, shares: u64::MAX, first_height: u32::MAX, last_height: u32::MAX, difficulty: u64::MAX,
                            ..WorkReceipt::zero(70, PROV, &inv) };
    assert_eq!(call(&wp, &payment(&doc, &k, &top, u64::MAX - 1, "/v1/a"), "/v1/a"), Ok(()));
    assert_eq!(call(&wp, &payment(&doc, &k, &top, u64::MAX, "/v1/b"), "/v1/b"), Ok(()));
    assert_eq!(call(&wp, &payment(&doc, &k, &top, u64::MAX, "/v1/c"), "/v1/c"), Err("bad_auth".into()), "n cannot go past the top");
    let other = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
    wp.accept(&k.sign(&WorkReceipt { invoice: other, ..top.clone() }).unwrap()).unwrap();
    assert_eq!(wp.exposure().1, u64::MAX, "held work saturates");
    // statements and blocks at the top: window work, min payout, heights, coinbase value and payout
    for (h, ws, ww, value, paid) in [(u32::MAX, 0u32, u64::MAX, u64::MAX, u64::MAX), (u32::MAX - 1, u32::MAX, 1, u64::MAX, 0), (5, 0, 1, u64::MAX, 1),
                                     (6, 0, u64::MAX, 1, u64::MAX)] {
        let b = ChainBlock { height: h, hash: hash(h), value_sats: value, paid_sats: paid, bits: MAIN_BITS, prev_bits: 0x207f_ffff };
        let s = WindowStatement { prime_id: 70, height: h, block_hash: hash(h), window_start: ws, window_work: ww, min_payout: u64::MAX, fee_bps: 10_000 };
        let d = xbt_work::audit::Deferral { prime_id: 70, height: h, block_hash: hash(h), identity: PROV.into(), sats: u64::MAX, reason: "over-budget".into() };
        let lines = [k.sign_deferral(&d).unwrap(), k.sign_deferral(&d).unwrap()];
        let _ = wp.audit_chain(&b, Statement::Found(&k.sign_window(&s).unwrap(), &lines));
        let _ = wp.audit_chain(&b, Statement::Missing);
        let _ = wp.paid_work(&b);
    }
    let _ = (wp.report(), wp.carry().owed(), wp.exposure());
}

// ------------------------------------------------------------------------------------------------
// The admin token file.
// ------------------------------------------------------------------------------------------------

/// "A file only the operator's account reads" (`admin_request`). `admin_token` writes the token
/// through `fsx::write_private`, which opens `DIR/admin.tmp` with create+truncate: the mode 0600
/// applies only when that call creates the file. With an `admin.tmp` already there (left by a
/// copy or restore of the directory, or put there by whoever can write to it) the token is written
/// into that file as it is and renamed into place with its mode. And a token file that exists is
/// read whatever its mode. FAILS: `admin.token` is 0644.
#[cfg(unix)]
#[test]
fn the_admin_token_file_is_private_whatever_was_in_the_directory() {
    use std::os::unix::fs::PermissionsExt;
    let dir = state_dir("token");
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    // control: an empty directory
    let clean = dir.join("clean.token");
    admin_token(&clean).unwrap();
    assert_eq!(mode(&clean), 0o600);
    let path = dir.join("admin.token");
    std::fs::write(dir.join("admin.tmp"), b"").unwrap();
    std::fs::set_permissions(dir.join("admin.tmp"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let token = admin_token(&path).unwrap();
    assert_eq!(token.len(), 64);
    let m = mode(&path);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(m, 0o600, "the new admin token is in a file of mode {m:o}");
}

// ------------------------------------------------------------------------------------------------
// Limits (these pass and pin a number).
// ------------------------------------------------------------------------------------------------

/// What state the stateless invoices leave: a record, and the invoice's best receipt, for every
/// invoice the Prime ever signed one work unit for, kept for good, pulled from the relay on every
/// round (3 s in the binary, and before every audit pass) and written out whole on every paid
/// call. One pool share makes one. Nothing bounds the count.
#[test]
fn limit_every_invoice_that_ever_had_one_share_is_kept_pulled_and_rewritten_for_ever() {
    let dir = state_dir("growth");
    let k = key();
    let path = dir.join("work.json");
    let cfg = WorkConfig { state_path: Some(path.clone()), relay_url: Some("http://relay.test".into()), invoice_ttl_secs: 1, invoice_grace_secs: 0, ..config(&k) };
    let wp = Arc::new(WorkProvider::new(cfg).unwrap());
    let empty = std::fs::metadata(&path).unwrap().len();
    let n = 400u64;
    for _ in 0..n {
        let inv = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
        wp.accept(&k.sign(&receipt(&inv, 1, 1, 101, 101)).unwrap()).unwrap();
    }
    let per = (std::fs::metadata(&path).unwrap().len() - empty) / n;
    // long past TTL and grace, with a balance too small to spend: still pulled
    std::thread::sleep(std::time::Duration::from_secs(3));
    struct Count(Mutex<u64>);
    impl Transport for Count {
        fn request(&self, _: &str, _: &str, _: &[u8], _: &[(String, String)]) -> xbt402::error::Result<HttpResponse> {
            *self.0.lock().unwrap() += 1;
            Ok(HttpResponse::new(404, vec![], b"".to_vec()))
        }
    }
    let c = Count(Mutex::new(0));
    wp.refresh(&c);
    assert_eq!((wp.invoices().len() as u64, *c.0.lock().unwrap()), (n, n), "every one is pulled on every round");
    assert!(per > 300, "bytes of state per invoice: {per}");
    eprintln!("limit: {n} invoices of one work unit each: {per} bytes of state each, written whole on every paid call; {n} relay requests per pull round");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--max-unpaid-blocks` (off unless set) lifts at a block that pays the block's share of a
/// window holding the unpaid credit: one block of the window's eight and a bit, about 13% of the
/// unpaid calls at their price, which is what that payment covers. It is never cheaper than what
/// it releases, and one sat less does not lift it.
#[test]
fn holds_lifting_the_unpaid_blocks_stop_costs_the_blocks_share_of_all_the_unpaid_credit() {
    for short in [0u64, 2] {
        let k = key();
        let wp = WorkProvider::new(WorkConfig { max_unpaid_blocks: Some(2), ..config(&k) }).unwrap();
        for _ in 0..10 {
            let inv = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
            assert_eq!(wp.accept(&k.sign(&receipt(&inv, 1, 900, 101, 102)).unwrap()).unwrap(), 900);
        }
        for h in [103, 104] {
            wp.audit_chain(&block(h, 0), Statement::Missing).unwrap();
        }
        assert_eq!(wp.report()["credit"]["frozen"], json!("unpaid_blocks"));
        let pay = share(9000) - short;
        let o = wp.audit(&k.sign_window(&stmt(110, &hash(110), 100)).unwrap(), &[], &block(110, pay)).unwrap();
        let covered = 9000 - wp.exposure().0;
        if short == 0 {
            assert!(o.ok && wp.report()["credit"]["frozen"].is_null(), "the block's full share lifts it");
            // 900 unpaid calls at 150 sat are 135,000 sat; the lift cost this much and covered this many
            assert!((19_000..20_500).contains(&pay) && (1_200..1_300).contains(&covered), "paid {pay} sat, covered {covered} work units");
            assert!(covered * PRICE <= pay * 10 + 10 * PRICE, "covered more than was paid for");
            eprintln!("lifting the stop on 900 unpaid calls: {pay} sat in one coinbase, which covers {covered} work units ({} calls)", covered / 10);
        } else {
            // 1 sat short is the audit's rounding tolerance; 2 sat short fails the audit itself
            assert!(!o.ok && wp.report()["credit"]["frozen"] == json!("unpaid_blocks") && covered == 0, "2 sat short of the share: {o:?}");
        }
    }
}
