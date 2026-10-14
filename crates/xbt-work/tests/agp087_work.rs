//! AGP-087, second closure audit, pay-with-work. Adversarial cases against the AGP-079 rule
//! "credit is covered only by what coinbases paid at the provider's own price" and its neighbours.
//!
//! Tests named `holds_*` pass and are evidence that a path is closed. Tests named `limit_*` pass and
//! pin down a behaviour a reader has to be told about. Tests named `hole_*` state the outcome the
//! review asked for and FAIL on main c80ee94: each is a finding of this audit. Nothing here is a fix.
//!
//! AGP-091 fixed the holes; every `hole_*` test passes unchanged. Two tests here asserted the hole
//! itself on a neighbouring path and were changed, each with a comment at the changed lines:
//! `holds_no_answer_to_the_statement_fetch_releases_credit` (its last match arm) and
//! `limit_distrust_is_for_good` (how the Prime gets distrusted).
use std::sync::Arc;

use serde_json::{json, Value};
use xbt402::client::Transport;
use xbt402::provider::{HttpResponse, PEER_HEADER};
use xbt402::scheme::ProviderScheme;
use xbt_work::audit::{PrimeTerms, WindowStatement};
use xbt_work::auth::{auth_tag, request_digest};
use xbt_work::chain::ChainBlock;
use xbt_work::provider::{window_statement, Amount, Caps, Statement, WorkConfig, WorkProvider, WorkScheme};
use xbt_work::receipt::{PrimeKey, WorkReceipt};

const NET: &str = "bip122:00000000000000000000000000000001";
const PROV: &str = "bcrt1q76vavszzsq657n375vk6updhxm0tfay7k28cc3";
const V: u64 = 5_000_000_000;
const TERMS: PrimeTerms = PrimeTerms { window: 8, window_min_work: 8000, window_tolerance_bps: 500, fee_bps: 0, max_min_payout: 546 };
/// regtest: a 150-sat call costs one work unit; the shipped caps are 100 units per invoice, 1000 in total
const REGTEST_BITS: u32 = 0x207f_ffff;
const MAIN_BITS: u32 = 0x1a00_f0b5;
const MAIN_V: u64 = 312_500_000;

fn config(k: &PrimeKey) -> WorkConfig {
    WorkConfig { terms: TERMS, ..WorkConfig::new(NET, PROV, 70, &k.pubkey_hex(), "http://prime.test/receipt") }.shipped(REGTEST_BITS, V, 150)
}
fn world() -> (PrimeKey, WorkProvider) {
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let wp = WorkProvider::new(config(&k)).unwrap();
    (k, wp)
}
fn inv(wp: &WorkProvider) -> String { wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string() }
fn receipt(inv: &str, seq: u64, cum: u64, first: u32, last: u32) -> WorkReceipt {
    WorkReceipt { seq, cum_work: cum, shares: seq, first_height: first, last_height: last, difficulty: 1, ..WorkReceipt::zero(70, PROV, inv) }
}
fn credit(k: &PrimeKey, wp: &WorkProvider, inv: &str, seq: u64, cum: u64, first: u32, last: u32) -> u64 {
    wp.accept(&k.sign(&receipt(inv, seq, cum, first, last)).unwrap()).unwrap()
}
fn hash(h: u32) -> String { format!("{h:064x}") }
fn stmt(height: u32, ws: u32, ww: u64) -> WindowStatement {
    WindowStatement { prime_id: 70, height, block_hash: hash(height), window_start: ws, window_work: ww, min_payout: 546, fee_bps: 0 }
}
fn block(height: u32, paid: u64) -> ChainBlock {
    ChainBlock { height, hash: hash(height), value_sats: V, paid_sats: paid, bits: REGTEST_BITS, prev_bits: REGTEST_BITS }
}
/// Mainnet-shaped numbers under the shipped defaults: a call is 10 work units, the caps 900 and 9,000.
fn main_world() -> (PrimeKey, WorkProvider) {
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let cfg = WorkConfig::new(NET, PROV, 70, &k.pubkey_hex(), "http://prime.test/receipt").shipped(MAIN_BITS, MAIN_V, 150);
    let wp = WorkProvider::new(cfg).unwrap();
    (k, wp)
}
fn mblock(height: u32, paid: u64) -> ChainBlock {
    ChainBlock { height, hash: hash(height), value_sats: MAIN_V, paid_sats: paid, bits: MAIN_BITS, prev_bits: MAIN_BITS }
}
fn mstmt(height: u32, ws: u32) -> WindowStatement {
    stmt(height, ws, PrimeTerms::default().window_target(MAIN_BITS).unwrap())
}
fn total_credited(wp: &WorkProvider) -> u64 { wp.book().credited.values().sum() }
fn paid_for(wp: &WorkProvider) -> u64 { wp.report()["credit"]["paidForWork"].as_u64().unwrap() }

// ------------------------------------------------------------------------------------------------
// The rule holds on these paths
// ------------------------------------------------------------------------------------------------

/// One coinbase payment is counted once however often and by whichever entry its block is audited,
/// and however many invoices hold unpaid credit.
#[test]
fn holds_one_payment_counts_once_across_reaudits_and_invoices() {
    let (k, wp) = main_world();
    let (a, b) = (inv(&wp), inv(&wp));
    credit(&k, &wp, &a, 1, 500, 101, 102);
    credit(&k, &wp, &b, 1, 500, 101, 102);
    let blk = mblock(110, 1500);
    let w = wp.paid_work(&blk).unwrap();
    assert_eq!(w, 96);
    let sw = k.sign_window(&mstmt(110, 109)).unwrap();
    assert!(wp.audit(&sw, &[], &blk).unwrap().ok);
    assert_eq!((paid_for(&wp), wp.exposure().0), (w, 1000 - w));
    for _ in 0..5 {
        assert!(wp.audit(&sw, &[], &blk).unwrap().ok);
        assert!(wp.audit_chain(&blk, Statement::Found(&sw, &[])).unwrap().unwrap().ok);
    }
    assert_eq!((paid_for(&wp), wp.exposure().0), (w, 1000 - w), "a block audited again was paid for again");
    // audited again as if the node now reported less: replaced downwards, not kept
    assert!(wp.audit(&sw, &[], &mblock(110, 0)).unwrap().ok);
    assert_eq!((paid_for(&wp), wp.exposure().0), (0, 1000));
}

/// A settled block (144 below the newest audit) audited again changes nothing, with or without a
/// restart in between; a restart re-audits the last blocks (the binary starts 100 + depth back).
#[test]
fn holds_settled_blocks_and_a_restart_do_not_pay_twice() {
    let dir = std::env::temp_dir().join(format!("xbt-work-agp087-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("work.json");
    let _ = std::fs::remove_file(&path);
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let cfg = WorkConfig { state_path: Some(path.clone()), ..WorkConfig::new(NET, PROV, 70, &k.pubkey_hex(), "http://prime.test/receipt").shipped(MAIN_BITS, MAIN_V, 150) };
    let wp = WorkProvider::new(cfg.clone()).unwrap();
    let i = inv(&wp);
    credit(&k, &wp, &i, 1, 500, 101, 102);
    let (b110, s110) = (mblock(110, 1500), k.sign_window(&mstmt(110, 109)).unwrap());
    let w = wp.paid_work(&b110).unwrap();
    assert!(wp.audit(&s110, &[], &b110).unwrap().ok);
    // a later block that pays nothing settles 110
    let (b300, s300) = (mblock(300, 0), k.sign_window(&mstmt(300, 299)).unwrap());
    assert!(wp.audit(&s300, &[], &b300).unwrap().ok);
    assert_eq!(wp.book().settled_through, 110);
    let before = (paid_for(&wp), wp.exposure());
    // settling forgets the payment together with the credit it covered
    assert_eq!(before, (0, (500 - w, 0)));
    assert!(wp.audit(&s110, &[], &mblock(110, 5000)).unwrap().ok);
    assert_eq!((paid_for(&wp), wp.exposure()), before, "a settled block was paid for again");
    // P6 stated limit: deeper than 144 a reorg takes nothing back
    assert_eq!(wp.orphaned(110).unwrap(), Some(0));
    assert_eq!((paid_for(&wp), wp.exposure()), before);
    drop(wp);
    let again = WorkProvider::new(cfg).unwrap();
    assert_eq!((paid_for(&again), again.exposure()), before);
    for _ in 0..3 {
        assert!(again.audit(&s110, &[], &mblock(110, 5000)).unwrap().ok);
        assert!(again.audit(&s300, &[], &b300).unwrap().ok);
    }
    assert_eq!((paid_for(&again), again.exposure()), before, "a restart and a second walk paid twice");
    let _ = std::fs::remove_dir_all(&dir);
}

struct Answer(u16, Vec<u8>);
impl Transport for Answer {
    fn request(&self, _: &str, _: &str, _: &[u8], _: &[(String, String)]) -> xbt402::error::Result<HttpResponse> {
        Ok(HttpResponse::new(self.0, vec![], self.1.clone()))
    }
}

/// Everything a Prime can answer to the statement fetch either is an error (the audit loop stops
/// at that block and retries it), or fails the audit, or covers nothing.
#[test]
fn holds_no_answer_to_the_statement_fetch_releases_credit() {
    let url = "http://prime.test/window";
    // errors: never "no statement"
    for (status, body) in [(500u16, &b""[..]), (503, b"busy"), (302, b""), (200, b"not json"), (200, b"{}"), (200, b"{\"message\":\"x\",\"sig\":\"00\"}"), (204, b"")] {
        assert!(window_statement(&Answer(status, body.to_vec()), url, 110).is_err(), "HTTP {status} {:?} read as a statement or as none", String::from_utf8_lossy(body));
    }
    assert!(window_statement(&Answer(404, vec![]), url, 110).unwrap().is_none());
    let other = PrimeKey::from_seed(70, &[7u8; 32]);
    for paid in [0u64, 50_000_000] {
        for why in ["none", "another block", "another height", "wrong key", "window_work 0", "valid, window over the credit"] {
            let (k, wp) = world();
            let i = inv(&wp);
            credit(&k, &wp, &i, 1, 100, 101, 102);
            let sw = match why {
                "another block" => Some(k.sign_window(&WindowStatement { block_hash: hash(111), ..stmt(110, 100, 8400) }).unwrap()),
                "another height" => Some(k.sign_window(&WindowStatement { height: 111, ..stmt(110, 100, 8400) }).unwrap()),
                "wrong key" => Some(other.sign_window(&stmt(110, 100, 8400)).unwrap()),
                "window_work 0" => Some(k.sign_window(&stmt(110, 100, 0)).unwrap()),
                "valid, window over the credit" => Some(k.sign_window(&stmt(110, 109, 8400)).unwrap()),
                _ => None,
            };
            // served and parsed as the binary does it
            let served = match &sw {
                Some(sw) => window_statement(&Answer(200, serde_json::to_vec(&sw.line_doc()).unwrap()), url, 110).unwrap(),
                None => window_statement(&Answer(404, vec![]), url, 110).unwrap(),
            };
            let st = match &served {
                Some((sw, d, _)) => Statement::Found(sw, d),
                None => Statement::Missing,
            };
            let o = wp.audit_chain(&block(110, paid), st).unwrap();
            let distrusted = !wp.report()["distrust"].is_null();
            let w = wp.paid_work(&block(110, paid)).unwrap();
            match (why, paid) {
                // the only case that covers anything: a valid statement on a block that paid, and only what it paid for
                ("valid, window over the credit", _) => {
                    assert!(o.unwrap().ok && !distrusted);
                    assert_eq!(wp.exposure().0, 100 - w, "{why}, paid {paid}");
                }
                ("window_work 0", _) => assert!(!o.unwrap().ok && distrusted && wp.exposure().0 == 100, "{why}, paid {paid}"),
                // AGP-091 changed this arm. It was `(_, 0) =>` with a last arm for a paid block
                // that asserted `!o.unwrap().ok && distrusted`: no statement, another block's,
                // another height's or another key's failed the audit when the coinbase paid the
                // identity. That is this file's own `hole_a_third_partys_coinbase_dust_...` at 50
                // million sat instead of 1: the amount is the attacker's to choose. What the test
                // is for holds on both: none of them covers credit.
                _ => assert!(o.is_none() && !distrusted && wp.exposure().0 == 100, "{why}, paid {paid}"),
            }
        }
    }
}

/// New caps at an epoch, the same caps set again, a restart with state: none re-arms the caps.
#[test]
fn holds_caps_are_not_rearmed_by_an_epoch_or_new_invoices() {
    let (k, wp) = world();
    for n in 0..30 {
        let i = inv(&wp);
        credit(&k, &wp, &i, 1, 500, 101, 102);
        if n % 5 == 0 {
            wp.set_caps(wp.cfg.caps).unwrap();
            wp.set_epoch(REGTEST_BITS, V);
        }
    }
    assert_eq!((total_credited(&wp), wp.exposure().0), (1000, 1000));
    // caps cut and restored (difficulty down, then up again)
    wp.set_caps(xbt_work::book::CreditCaps { per_invoice: Some(1), total: Some(1) }).unwrap();
    wp.set_caps(wp.cfg.caps).unwrap();
    assert_eq!((total_credited(&wp), wp.exposure().0), (1000, 1000));
}

/// `Amount::Fixed` with a sats price: a coinbase pays for calls at that price, rounded down.
#[test]
fn holds_fixed_amount_is_paid_at_the_invoice_price_rounded_down() {
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let wp = WorkProvider::new(WorkConfig { amount: Amount::Fixed(7), ..config(&k) }).unwrap();
    assert_eq!(wp.paid_work(&block(110, 149)).unwrap(), 6);
    assert_eq!(wp.paid_work(&block(110, 150)).unwrap(), 7);
    assert_eq!(wp.paid_work(&block(110, 1)).unwrap(), 0);
}

// ------------------------------------------------------------------------------------------------
// Limits a reader has to be told about (these pass)
// ------------------------------------------------------------------------------------------------

/// Rounding at the repo's own mainnet numbers (`1a00f0b5`, 3.125 XBT, 150 sat): a call is 10 work
/// units and one unit is worth 17.5 sat of work, so a passing block that paid 1 sat pays for a
/// tenth of a call. AGP-079's stated limit says "0.09 sat of work on mainnet"; that figure is for
/// `190141c5`, about 190 times lower difficulty.
#[test]
fn limit_one_sat_pays_for_a_tenth_of_a_call_at_mainnet_numbers() {
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let cfg = WorkConfig::new(NET, PROV, 70, &k.pubkey_hex(), "http://prime.test/receipt").shipped(MAIN_BITS, MAIN_V, 150);
    let wp = WorkProvider::new(cfg).unwrap();
    let main = |paid| ChainBlock { height: 110, hash: hash(110), value_sats: MAIN_V, paid_sats: paid, bits: MAIN_BITS, prev_bits: MAIN_BITS };
    assert_eq!(wp.amount(150).unwrap(), 10);
    assert_eq!(wp.paid_work(&main(1)).unwrap(), 1);
    assert_eq!(xbt_work::pricing::value_sats(1, MAIN_BITS, MAIN_V, 0).unwrap(), 17);
    // 150 sat paid in one block covers one call; paid as 150 blocks of 1 sat it covers 15 calls
    assert_eq!(wp.paid_work(&main(150)).unwrap(), 10);
}

/// Two providers that share an identity (or one provider restarted on an empty state) each count
/// the same coinbase output: the sats are paid once and cover credit twice.
#[test]
fn limit_two_books_on_one_identity_count_one_payment_twice() {
    let ((k, p1), (_, p2)) = (main_world(), main_world());
    let blk = mblock(110, 2000);
    let sw = k.sign_window(&mstmt(110, 109)).unwrap();
    for wp in [&p1, &p2] {
        let i = inv(wp);
        credit(&k, wp, &i, 1, 100, 101, 102);
        assert!(wp.audit(&sw, &[], &blk).unwrap().ok);
        assert_eq!(wp.exposure().0, 0);
    }
}

/// Cover is one pool across payers, oldest credit first. An honest payer's work is paid for at
/// its §6.1 value, which at the 10% haircut is 11% more than its credit costs; the surplus pays for
/// whatever credit is older, mined or not. A colluding pair's unmined credit (receipt heights below
/// the window, so the audit expects nothing for it) is covered by the honest payer's coinbases, and
/// the pair can take the same again: "1,000 calls, once" is once per 9,000 calls of honest work.
#[test]
fn limit_an_honest_payers_overpayment_covers_older_unmined_credit() {
    let (k, wp) = main_world();
    let fake = inv(&wp);
    assert_eq!(credit(&k, &wp, &fake, 1, 80, 50, 51), 80);
    let honest = inv(&wp);
    assert_eq!(credit(&k, &wp, &honest, 1, 800, 101, 102), 800);
    let ww = PrimeTerms::default().window_target(MAIN_BITS).unwrap();
    // the Prime pays exactly the honest payer's share in each of the window's eight blocks
    let share = (u128::from(MAIN_V) * 800 / u128::from(ww)) as u64;
    for h in 110..=117 {
        let o = wp.audit(&k.sign_window(&mstmt(h, 100)).unwrap(), &[], &mblock(h, share)).unwrap();
        assert!(o.ok && o.proven_work == 800 && o.expected_sats == share, "{o:?}");
    }
    assert_eq!(wp.exposure().0, 0, "the 80 unmined units are still unpaid");
    assert!(wp.report()["distrust"].is_null());
    // and the pair's next 80 units are credited beside the honest payer's
    assert_eq!(credit(&k, &wp, &fake, 2, 160, 50, 51), 80);
}

/// Nothing takes distrust back: not the failing block leaving the chain, not a restart.
#[test]
fn limit_distrust_is_for_good() {
    let dir = std::env::temp_dir().join(format!("xbt-work-agp087-d-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("work.json");
    let _ = std::fs::remove_file(&path);
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let cfg = WorkConfig { state_path: Some(path.clone()), ..config(&k) };
    let wp = WorkProvider::new(cfg.clone()).unwrap();
    // AGP-091 changed how this test gets a distrusted Prime, not what it asserts about distrust.
    // It was `audit_chain(&block(110, 600), Missing)` and the code `missing_statement`; that no
    // longer distrusts (WORK 1). A statement the Prime signed for the block and the audit refuses does.
    let garbage = k.sign_window(&stmt(110, 100, 0)).unwrap();
    assert!(!wp.audit_chain(&block(110, 600), Statement::Found(&garbage, &[])).unwrap().unwrap().ok);
    assert_eq!(wp.orphaned(110).unwrap(), Some(0));
    assert_eq!(wp.report()["distrust"]["code"], json!("refused_statement"));
    assert!(wp.audit(&k.sign_window(&stmt(111, 110, 8400)).unwrap(), &[], &block(111, V / 8)).unwrap().ok);
    drop(wp);
    let again = WorkProvider::new(cfg).unwrap();
    assert_eq!(again.report()["distrust"]["code"], json!("refused_statement"));
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------------------------------------
// Holes (these FAIL on c80ee94)
// ------------------------------------------------------------------------------------------------

fn payment(inv_doc: &Value, k: &PrimeKey, r: &WorkReceipt, n: u64, method: &str, path: &str) -> Value {
    let key = hex::decode(inv_doc["authKey"].as_str().unwrap()).unwrap();
    let s = k.sign(r).unwrap();
    let auth = auth_tag(&key, &r.invoice, n, r.seq, r.cum_work, &request_digest(method, path, b"")).unwrap();
    json!({"x402Version": 2, "accepted": {"scheme": "xbt-work", "network": NET, "payTo": PROV},
           "payload": {"receipt": r.to_doc(), "sig": hex::encode(s.sig), "n": n, "auth": auth}})
}

/// HOLE (availability; any miner). The provider's identity is public (`payTo` of every 402). A
/// third-party miner adds a 1-sat output to that address in its own coinbase. The honest Prime has
/// no statement for another pool's block and answers 404. The audit reads that as "the Prime paid
/// as the pool but will not say for what", fails it and distrusts the Prime for good: every payer's
/// balance, paid for or not, is refused from then on.
#[test]
fn hole_a_third_partys_coinbase_dust_must_not_distrust_an_honest_prime() {
    let (k, wp) = main_world();
    let wp = Arc::new(wp);
    let scheme = WorkScheme(wp.clone());
    let doc = wp.issue_invoice().unwrap();
    let i = doc["invoice"].as_str().unwrap().to_string();
    let r = receipt(&i, 1, 50, 101, 102);
    // an honest payer's work (5 calls), paid for in full by the Prime's coinbase at 110
    assert!(scheme.authorize(&payment(&doc, &k, &r, 1, "GET", "/v1/a"), "GET", "/v1/a", b"", 150, "http://api.test/v1/a").is_ok());
    assert!(wp.audit(&k.sign_window(&mstmt(110, 100)).unwrap(), &[], &mblock(110, 1000)).unwrap().ok);
    assert_eq!(wp.exposure().0, 0, "the credit is paid for");
    // block 111 is another pool's: its coinbase carries 1 sat to the provider's address; the Prime answers 404
    let _ = wp.audit_chain(&mblock(111, 1), Statement::Missing);
    let refused = scheme.authorize(&payment(&doc, &k, &r, 2, "GET", "/v1/b"), "GET", "/v1/b", b"", 150, "http://api.test/v1/b").err();
    assert!(wp.report()["distrust"].is_null() && refused.is_none(),
            "1 sat in a stranger's coinbase distrusted the Prime ({}) and a paid-for balance of 40 units is refused with {:?}",
            wp.report()["distrust"], refused.map(|v| v["error"].clone()));
}

/// HOLE (config; the binary's documented `--work-units N`). The shipped caps are "100 calls per
/// invoice and 1,000 in total", converted to work units by exact pricing. With `--work-units 1` a
/// call costs 1 unit, but the caps stay at 1,000 priced calls' worth of units: at mainnet numbers
/// 9,000 calls of unpaid credit, not 1,000 (and 1.64 million at `190141c5`).
#[test]
fn hole_the_shipped_cap_is_1000_calls_whatever_a_call_costs() {
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    // what xbt-work-provider builds for `--work-units 1` and no cap flag (xbt-work-provider.rs:307-334)
    let mut cfg = WorkConfig::new(NET, PROV, 70, &k.pubkey_hex(), "http://prime.test/receipt").shipped(MAIN_BITS, MAIN_V, 150);
    cfg.caps = Caps::SHIPPED.at(MAIN_BITS, MAIN_V, 150);
    cfg.amount = Amount::Fixed(1);
    let wp = WorkProvider::new(cfg).unwrap();
    let call = wp.amount(150).unwrap();
    assert_eq!(call, 1);
    // a colluding Prime receipts work nobody mined on as many invoices as it takes; no coinbase pays
    for _ in 0..200 {
        let i = inv(&wp);
        credit(&k, &wp, &i, 1, 1_000_000_000, 101, 102);
    }
    let calls = total_credited(&wp) / call;
    assert!(calls <= 1000, "{calls} calls of unpaid credit under the shipped caps (\"1,000 calls in total\")");
}

/// HOLE (low; only with `--max-unpaid-blocks`). The operator's stop lifts when "a coinbase pays for
/// credit". One sat is enough: a Prime that owes 80 calls pays 1 sat every N-1 blocks and is never
/// stopped (the total cap still binds).
#[test]
fn hole_one_sat_must_not_lift_the_unpaid_blocks_stop() {
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let cfg = WorkConfig { max_unpaid_blocks: Some(3), ..WorkConfig::new(NET, PROV, 70, &k.pubkey_hex(), "http://prime.test/receipt").shipped(MAIN_BITS, MAIN_V, 150) };
    let wp = WorkProvider::new(cfg).unwrap();
    let i = inv(&wp);
    let call = wp.amount(150).unwrap();
    credit(&k, &wp, &i, 1, 80 * call, 101, 102);
    let main = |h: u32, paid| ChainBlock { height: h, hash: hash(h), value_sats: MAIN_V, paid_sats: paid, bits: MAIN_BITS, prev_bits: MAIN_BITS };
    for h in 103..=105 {
        assert!(wp.audit_chain(&main(h, 0), Statement::Missing).unwrap().is_none());
    }
    assert_eq!(wp.report()["credit"]["frozen"], json!("unpaid_blocks"));
    // 1 sat, with a statement whose window starts above the credit (nothing expected: a pass)
    let ww = PrimeTerms::default().window_target(MAIN_BITS).unwrap();
    let s = WindowStatement { prime_id: 70, height: 106, block_hash: hash(106), window_start: 105, window_work: ww, min_payout: 546, fee_bps: 0 };
    assert!(wp.audit(&k.sign_window(&s).unwrap(), &[], &main(106, 1)).unwrap().ok);
    assert_eq!(wp.report()["credit"]["frozen"], json!("unpaid_blocks"),
               "1 sat lifted the stop with {} of {} units still unpaid", wp.exposure().0, 80 * call);
}

fn post_invoice(s: &WorkScheme, peer: &str, forwarded: Option<&str>) -> u16 {
    let mut h = vec![(PEER_HEADER.to_string(), peer.to_string())];
    if let Some(f) = forwarded {
        h.push(("X-Forwarded-For".into(), f.into()));
    }
    s.control("POST", "/x402/xbt-work/invoice", &h, b"").unwrap().status
}

/// HOLE (availability; anonymous client). `xbt-work-provider` binds 127.0.0.1 only, so in any
/// deployment every client arrives from the proxy's address. Without `--trust-forwarded` they all
/// share one bucket of 16 unfunded invoices: 16 requests an hour from anyone stop invoices for all.
#[test]
fn hole_sixteen_requests_must_not_stop_invoices_for_every_client_behind_a_proxy() {
    let (_k, wp) = world();
    let s = WorkScheme(Arc::new(wp));
    for _ in 0..16 {
        assert_eq!(post_invoice(&s, "127.0.0.1", Some("198.51.100.7")), 200);
    }
    assert_eq!(post_invoice(&s, "127.0.0.1", Some("203.0.113.50")), 200, "another client behind the same proxy gets no invoice");
}

/// HOLE (availability; anonymous client with many addresses). With `--trust-forwarded` the limit
/// is per address, and live unfunded invoices are never evicted: 625 addresses (one IPv6 /64 has
/// 2^64) take all 10,000 slots for the hour, and can take them again.
#[test]
fn hole_many_addresses_must_not_fill_max_unfunded() {
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let s = WorkScheme(Arc::new(WorkProvider::new(WorkConfig { trust_forwarded: true, ..config(&k) }).unwrap()));
    let mut issued = 0;
    'fill: for a in 0..700u32 {
        for _ in 0..16 {
            if post_invoice(&s, "127.0.0.1", Some(&format!("2001:db8::{a:x}"))) != 200 {
                break 'fill;
            }
            issued += 1;
        }
    }
    assert_eq!(post_invoice(&s, "127.0.0.1", Some("203.0.113.50")), 200, "an honest client gets no invoice after {issued} anonymous requests");
}
