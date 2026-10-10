//! AGP-077 closure audit: FAILING tests for what the audit found open on main 71714d5 in the
//! coinbase audit (the review's P1 "the Prime controls the audit's inputs", P4). Nothing here is
//! fixed. Each test states the outcome the review asked for and fails until the code has it.
//!
//! The caps are the shipped binary's shape with no flags: credit caps on, `max_owed_carry_sats`
//! and `carry_growth_blocks` off (xbt-work-provider.rs:335-336).
use serde_json::json;
use xbt_work::audit::{Deferral, PrimeTerms, WindowStatement};
use xbt_work::book::CreditCaps;
use xbt_work::chain::ChainBlock;
use xbt_work::provider::{Statement, WorkConfig, WorkProvider};
use xbt_work::receipt::{PrimeKey, WorkReceipt};

const NET: &str = "bip122:00000000000000000000000000000001";
const PROV: &str = "bcrt1q76vavszzsq657n375vk6updhxm0tfay7k28cc3";
const V: u64 = 5_000_000_000;
const TERMS: PrimeTerms = PrimeTerms { window: 8, window_min_work: 8000, window_tolerance_bps: 500, fee_bps: 0, max_min_payout: 546 };
/// what the shipped binary does: caps on, carry caps OFF (max_owed_carry_sats/carry_growth_blocks None)
const CAPS: CreditCaps = CreditCaps { per_invoice: Some(100), total: Some(1000), skipped: 100 };

fn config(k: &PrimeKey) -> WorkConfig {
    WorkConfig { terms: TERMS, caps: CAPS, ..WorkConfig::new(NET, PROV, 70, &k.pubkey_hex(), "http://prime.test/receipt") }
}
fn world() -> (PrimeKey, WorkProvider) {
    let k = PrimeKey::from_seed(70, &[9u8; 32]);
    let wp = WorkProvider::new(config(&k)).unwrap();
    (k, wp)
}
fn inv(wp: &WorkProvider) -> String { wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string() }
fn credit(k: &PrimeKey, wp: &WorkProvider, inv: &str, seq: u64, cum: u64, first: u32, last: u32) -> u64 {
    let r = WorkReceipt { seq, cum_work: cum, shares: seq, first_height: first, last_height: last, difficulty: 1, ..WorkReceipt::zero(70, PROV, inv) };
    wp.accept(&k.sign(&r).unwrap()).unwrap()
}
fn hash(h: u32) -> String { format!("{h:064x}") }
fn stmt(height: u32, ws: u32, ww: u64) -> WindowStatement {
    WindowStatement { prime_id: 70, height, block_hash: hash(height), window_start: ws, window_work: ww, min_payout: 546, fee_bps: 0 }
}
fn block(height: u32, paid: u64) -> ChainBlock {
    ChainBlock { height, hash: hash(height), value_sats: V, paid_sats: paid, bits: 0x207f_ffff, prev_bits: 0x207f_ffff }
}
fn total_credited(wp: &WorkProvider) -> u64 { wp.book().credited.values().sum() }

/// P1: a Prime colluding with a payer signs receipts for work nobody mined, honest-looking
/// statements, and a deferral line for the whole expected payout. Every coinbase pays 0. The
/// credit must stay inside the total cap.
#[test]
fn p1_deferral_lines_do_not_release_credit_no_coinbase_paid_for() {
    let (k, wp) = world();
    let mut h = 100u32;
    for _round in 0..50 {
        let i = inv(&wp);
        let r = WorkReceipt { seq: 1, cum_work: 100, shares: 1, first_height: h + 1, last_height: h + 2, difficulty: 1, ..WorkReceipt::zero(70, PROV, &i) };
        if wp.accept(&k.sign(&r).unwrap()).is_err() {
            break; // refused: the caps bind
        }
        let s = stmt(h + 3, h, 8000);
        let d = Deferral { prime_id: 70, height: h + 3, block_hash: hash(h + 3), identity: PROV.into(), sats: V * 100 / 8000, reason: "over-budget".into() };
        let _ = wp.audit(&k.sign_window(&s).unwrap(), &[k.sign_deferral(&d).unwrap()], &block(h + 3, 0));
        h += 3;
    }
    assert!(total_credited(&wp) <= 1000, "{} units credited over a total cap of 1000 while every coinbase paid 0 (owed carry {} sats, frozen {})",
            total_credited(&wp), wp.carry().owed(), wp.report()["credit"]["frozen"]);
}

/// P4: "a Prime can underpay a block and then 404 its statement". Seven pool blocks pay the
/// identity nothing and have no statement; one later block pays one block's share. The credit was
/// paid in one block of its window, not eight: it must not all be released.
#[test]
fn p4_unpaid_blocks_with_no_statement_do_not_vanish_from_the_audit() {
    let (k, wp) = world();
    let i = inv(&wp);
    credit(&k, &wp, &i, 1, 100, 101, 102);
    for h in 103..=109 {
        let _ = wp.audit_chain(&block(h, 0), Statement::Missing);
    }
    let _ = wp.audit(&k.sign_window(&stmt(110, 100, 8400)).unwrap(), &[], &block(110, V * 100 / 8400));
    assert!(wp.exposure().0 > 0 || !wp.report()["distrust"].is_null(),
            "100 units released (unaudited 0, no distrust) after 7 of 8 pool blocks paid nothing and published no statement");
}

/// P4: a statement the audit refuses, on a block that underpaid the identity, is treated more
/// gently than no statement at all: no verdict, no distrust, and the next pass covers the credit.
#[test]
fn p4_a_refused_statement_on_an_underpaid_block_is_a_failed_audit() {
    let (k, wp) = world();
    let i = inv(&wp);
    credit(&k, &wp, &i, 1, 100, 101, 102);
    let sw = k.sign_window(&stmt(110, 100, 0)).unwrap(); // window_work 0: refused as bad_window
    let _ = wp.audit_chain(&block(110, 5), Statement::Found(&sw, &[]));
    assert!(!wp.report()["distrust"].is_null(), "a block that paid 5 sats with a refused statement left no failed audit and no distrust");
    // control: the same block with no statement does fail
    let (_k2, wp2) = world();
    assert!(!wp2.audit_chain(&block(110, 5), Statement::Missing).unwrap().unwrap().ok);
    let _ = json!(null);
}

/// P4: every kind of statement the audit refuses (no window, another block, a window start that went
/// backwards, another key), on a block that paid the identity, counts as that block having no statement.
#[test]
fn p4_every_refused_statement_on_a_paid_block_distrusts_the_prime() {
    let other = PrimeKey::from_seed(70, &[7u8; 32]);
    for why in ["window_work 0", "another block", "regressed start", "wrong key"] {
        let (k, wp) = world();
        let i = inv(&wp);
        credit(&k, &wp, &i, 1, 100, 101, 102);
        // an audited block below, so a lower window start at 110 is a regression
        wp.audit(&k.sign_window(&stmt(105, 104, 8000)).unwrap(), &[], &block(105, 0)).unwrap();
        let sw = match why {
            "window_work 0" => k.sign_window(&stmt(110, 104, 0)).unwrap(),
            "another block" => k.sign_window(&WindowStatement { block_hash: hash(111), ..stmt(110, 104, 8000) }).unwrap(),
            "regressed start" => k.sign_window(&stmt(110, 100, 8000)).unwrap(),
            _ => other.sign_window(&stmt(110, 104, 8000)).unwrap(),
        };
        let _ = wp.audit_chain(&block(110, 5), Statement::Found(&sw, &[]));
        assert!(!wp.report()["distrust"].is_null(), "{why}: a paid block with a refused statement left no distrust");
        assert!(wp.report()["audits"].as_array().unwrap().iter().any(|a| a["height"] == json!(110) && a["ok"] == json!(false)), "{why}: no failed audit recorded");
    }
}

/// P1: the `min_payout` excuse. Each round's share of a small coinbase is below `min_payout`, so the
/// audit passes with nothing paid. The credit must stay inside the total cap.
#[test]
fn p1_the_min_payout_excuse_does_not_release_credit() {
    let (k, wp) = world();
    let mut h = 100u32;
    for _round in 0..500 {
        let i = inv(&wp);
        let r = WorkReceipt { seq: 1, cum_work: 4, shares: 1, first_height: h + 1, last_height: h + 2, difficulty: 1, ..WorkReceipt::zero(70, PROV, &i) };
        if wp.accept(&k.sign(&r).unwrap()).is_err() {
            break;
        }
        // V = 1,000,000: expected = 500 sats, under the 546 the terms allow
        let small = ChainBlock { value_sats: 1_000_000, ..block(h + 3, 0) };
        let o = wp.audit(&k.sign_window(&stmt(h + 3, h, 8000)).unwrap(), &[], &small).unwrap();
        assert!(o.ok && o.paid_sats == 0, "{o:?}");
        h += 3;
    }
    assert!(total_credited(&wp) <= 1000, "{} units credited over a total cap of 1000 while every coinbase paid 0", total_credited(&wp));
}

/// P1: `window_start` moved forward. One coinbase pays one block's share of the credit (an eighth
/// of what an honest window pays over its eight blocks); the next statements start their window
/// above the credit, so nothing more is ever expected. The credit must not all be released.
#[test]
fn p1_a_window_start_moved_forward_does_not_release_unpaid_credit() {
    let (k, wp) = world();
    let i = inv(&wp);
    credit(&k, &wp, &i, 1, 100, 101, 102);
    assert!(wp.audit(&k.sign_window(&stmt(110, 100, 8400)).unwrap(), &[], &block(110, V * 100 / 8400)).unwrap().ok);
    for h in 111..=117 {
        assert!(wp.audit(&k.sign_window(&stmt(h, h - 1, 8400)).unwrap(), &[], &block(h, 0)).unwrap().ok);
    }
    assert!(wp.exposure().0 > 0, "100 units released after one of eight blocks' shares was paid and the window start jumped over the credit");
}
