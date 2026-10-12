//! AGP-093 third closure audit, Rust wallet (xbt-signer). Written by the auditor; nothing here
//! changes the wallet. Tests named `hole_*` state what the wallet must do and FAIL on `d4c8328`
//! for the reason in their doc comment. Tests named `control_*` pass: the honest path in the same rig.
//!
//! 1. `hole_two_lost_answers_do_not_end_a_postpay_channel`, `hole_one_lost_answer_does_not_end_a_prepay_channel`:
//!    the signer's `xbt402_pay` resends an unacked state for ever once the seller is owed a call.
//! 2. `hole_a_sellers_offer_cannot_make_the_wallet_fund_a_channel_that_expires_at_once`: the offer's
//!    expiry window has an owner's upper bound (AGP-089) and no lower one.
//! 3. `hole_the_watcher_refunds_a_next_channel_nobody_attached`: AGP-089 found-not-fixed 1, with numbers.
//! 4. `hole_rollovers_that_were_refused_do_not_use_up_the_channels_next_slots`: new in wave 4.
//! 5. `hole_a_used_human_signature_stays_used_when_the_clock_goes_back`: new in wave 4.
//! 6. `hole_open_channel_with_a_fee_that_does_not_fit_is_refused_not_a_panic`: socket caller, `close_fee_max_sats: 0`.
//! 7. `hole_a_free_only_call_never_funds_a_channel`: a negative price passes `price > max_sats`.
mod common;

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use common::*;
use serde_json::{json, Value};
use xbt402::channel::ChannelParams;
use xbt402::client::Transport;
use xbt402::wire::{b64json, unb64json, OPEN_PATH, ROLLOVER_PATH};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt_primitives::ecdsa;
use xbt_primitives::hash::sha256;
use xbt_signer::session::{leaf, manifest_message};
use xbt_signer::signer::{Signer, SignerOptions};

type Hook = Box<dyn Fn(&str, &str, &[u8], &[(String, String)]) -> Option<xbt402::Result<HttpResponse>> + Send + Sync>;

struct Hooked {
    web: Arc<Web>,
    hook: Hook,
}

impl Transport for Hooked {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> xbt402::Result<HttpResponse> {
        match (self.hook)(method, url, body, headers) {
            Some(r) => r,
            None => self.web.request(method, url, body, headers),
        }
    }
}

fn hooked(rig: &mut Rig, hook: Hook) {
    let t = Arc::new(Hooked { web: rig.web.clone(), hook });
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(rig.chain.clone()), transport: Some(t), ..Default::default() }).unwrap();
}

fn paid(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-SIGNATURE"))
}

fn ledger(rig: &Rig) -> i64 {
    rig.s.engine.store.payments().unwrap().iter().map(|e| e.amount_sats).sum()
}

fn node_hash(a: &[u8], b: &[u8]) -> [u8; 32] {
    sha256(&[b"node".as_slice(), a, b].concat())
}

fn tree(chunks: &[Vec<u8>]) -> ([u8; 32], Vec<Vec<String>>) {
    let mut level: Vec<[u8; 32]> = chunks.iter().enumerate().map(|(i, c)| leaf(i as u32, c)).collect();
    let mut proofs = vec![vec![]; chunks.len()];
    let mut idx: Vec<usize> = (0..chunks.len()).collect();
    while level.len() > 1 {
        for (p, i) in proofs.iter_mut().zip(idx.iter_mut()) {
            p.push(hex::encode(level[*i ^ 1]));
            *i /= 2;
        }
        level = level.chunks(2).map(|c| node_hash(&c[0], &c[1])).collect();
    }
    (level[0], proofs)
}

fn seller_pay_to() -> Vec<u8> {
    ecdsa::pubkey(&secret("provider payTo")).to_vec()
}

fn provider_with(rig: &Rig, doc: Value, min_capacity: u64, price: u64) {
    let mut cfg = ProviderConfig::new(&rig.chain.network());
    cfg.policy.min_capacity = min_capacity;
    cfg.policy.max_capacity = 10_000;
    cfg.policy.min_expiry_blocks = 1_008;
    cfg.policy.min_conf = 1;
    let body = doc.to_string().into_bytes();
    let p = Provider::new(Arc::new(ProviderChain(rig.chain.clone())), secret("provider payTo"), cfg, Ledger::in_memory(), Box::new(move |_, _| price),
                          Box::new(move |_, _, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], body.clone()))).unwrap();
    rig.web.sites.lock().unwrap().insert(PROVIDER.into(), Arc::new(p));
}

fn lost_rig(billing: &str) -> (Rig, Arc<AtomicU8>) {
    let mut rig = Rig::new(json!({"daily_budget_sats": 60000, "weekly_budget_sats": 60000}), false);
    let mut cfg = ProviderConfig::new(&rig.chain.network());
    (cfg.policy.min_capacity, cfg.policy.max_capacity, cfg.policy.min_expiry_blocks, cfg.policy.min_conf) = (10_000, 10_000, 1_008, 1);
    cfg.billing = billing.into();
    let p = Provider::new(Arc::new(ProviderChain(rig.chain.clone())), secret("provider payTo"), cfg, Ledger::in_memory(), Box::new(|_, _| 500),
                          Box::new(|_, _, _| HttpResponse::new(200, vec![], b"{}".to_vec()))).unwrap();
    rig.web.sites.lock().unwrap().insert(PROVIDER.into(), Arc::new(p));
    rig.fund_hot(1, 12_000);
    let mode = Arc::new(AtomicU8::new(0));
    let (web, m) = (rig.web.clone(), mode.clone());
    hooked(&mut rig, Box::new(move |method, url, body, headers| {
        if paid(headers) && m.load(Ordering::SeqCst) == 1 {
            m.store(0, Ordering::SeqCst);
            let _ = web.request(method, url, body, headers);
            return Some(Err(xbt402::ChannelError::new("transport_error", "connection reset")));
        }
        None
    }));
    (rig, mode)
}

fn roll_rig() -> (Rig, xbt_signer::channels::ChannelRecord, String) {
    let rig = Rig::new(json!({"max_per_tx_sats": 5000, "human_threshold_sats": 5000}), false);
    provider_with(&rig, json!({"ok": true}), 5_000, 600);
    rig.fund_hot(1, 12_000);
    assert_eq!(rig.call("xbt402_pay", json!({"url": URL, "max_sats": 1_000}))["verdict"], "pending");
    rig.chain.mine(1);
    assert_eq!(rig.call("xbt402_pay", json!({"url": URL, "max_sats": 1_000}))["verdict"], "allow");
    let rec = rig.s.book.get(PROVIDER).unwrap();
    let next_origin = format!("{}/next", rec.origin);
    (rig, rec, next_origin)
}


// --- 1. lost answers on the signer's own pay rail ------------------------------------------------

fn pay_status(rig: &Rig) -> (i64, i64) {
    let r = rig.pay();
    (r["status"].as_i64().unwrap_or(0), r["cum"].as_i64().unwrap_or(0))
}

/// Control: after one lost answer a postpay seller serves the same state again on credit, and the
/// channel goes on (one call behind).
#[test]
fn control_one_lost_answer_on_a_postpay_channel_is_served_again() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, mode) = lost_rig("postpay");
    rig.open();
    mode.store(1, Ordering::SeqCst);
    assert_eq!(rig.pay()["verdict"], "deny");
    let after: Vec<(i64, i64)> = (0..3).map(|_| pay_status(&rig)).collect();
    assert!(after.iter().all(|(st, _)| *st == 200), "{after:?}");
}

/// AGP-089 says "neither wallet payer compares a spent total, so neither wedges". The signer's
/// payer wedges another way: a state whose answer was lost stays unacked, the next call sends the
/// same state again (session.rs:662-665, 679), and that is all it ever sends until a receipt for it
/// arrives. A postpay seller serves one such resend on credit; from then on it is owed one call, so
/// after a second lost answer the resend no longer covers what it has charged, it answers 402
/// `insufficient_payment` (provider.rs:1749) with no receipt, the state stays unacked, and every later
/// `xbt402_pay` to this seller repeats that for good. The answers lost were served and charged.
/// The library client was fixed for exactly this in AGP-090 (`t4_two_lost_answers_do_not_end_the_channel`).
///
/// Fails on d4c8328: after the second lost answer every call answers status 402, cum 2500, with
/// `verdict: allow`; `used_sats` 2500, `acked_sats` 2000.
#[test]
fn hole_two_lost_answers_do_not_end_a_postpay_channel() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, mode) = lost_rig("postpay");
    rig.open();
    for _ in 0..2 {
        mode.store(1, Ordering::SeqCst);
        assert_eq!(rig.pay()["verdict"], "deny", "the answer is lost on the way back");
        for _ in 0..3 {
            pay_status(&rig);
        }
    }
    let after: Vec<(i64, i64)> = (0..4).map(|_| pay_status(&rig)).collect();
    let rec = rig.s.book.get(PROVIDER).unwrap();
    assert!(after.iter().any(|(st, _)| *st == 200),
            "two answers were lost (both served and charged by the seller); every call since answers (status, cum) {after:?}; \
             the wallet resends cum {} (acked {}) and never signs a higher state", rec.used_sats, rec.acked_sats);
}

/// The same with a prepay seller, where the first lost answer is enough: a resend never covers a
/// prepaid call.
///
/// Fails on d4c8328: status 402, cum 1000 on every call after one lost answer (`used` 1000, `acked` 546).
#[test]
fn hole_one_lost_answer_does_not_end_a_prepay_channel() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, mode) = lost_rig("prepay");
    rig.open();
    mode.store(1, Ordering::SeqCst);
    assert_eq!(rig.pay()["verdict"], "deny");
    let after: Vec<(i64, i64)> = (0..4).map(|_| pay_status(&rig)).collect();
    let rec = rig.s.book.get(PROVIDER).unwrap();
    assert!(after.iter().any(|(st, _)| *st == 200),
            "one answer was lost; every call since answers (status, cum) {after:?}; the wallet resends cum {} (acked {})", rec.used_sats, rec.acked_sats);
}

// --- 2. the offer's expiry window, lower side -----------------------------------------------------

fn short_window(rig: &mut Rig, max_expiry_blocks: i64) {
    let web = rig.web.clone();
    hooked(rig, Box::new(move |method, url, body, headers| {
        if url == URL && !paid(headers) {
            let r = web.request(method, url, body, headers).unwrap();
            let mut pr = unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap();
            pr["accepts"][0]["extra"]["minExpiryBlocks"] = 1.into();
            pr["accepts"][0]["extra"]["maxExpiryBlocks"] = max_expiry_blocks.into();
            pr["accepts"][0]["extra"]["closeMarginBlocks"] = 0.into();
            return Some(Ok(HttpResponse::new(402, vec![("PAYMENT-REQUIRED".into(), b64json(&pr))], b"".to_vec())));
        }
        if url.ends_with(OPEN_PATH) && String::from_utf8_lossy(body).contains("\"preflight\"") {
            return Some(Ok(HttpResponse::new(200, vec![], json!({"preflight": true}).to_string().into_bytes())));
        }
        None
    }));
}

/// AGP-089 gave `open_from_offer` the owner's upper bound on the expiry (session.rs:303-310). The
/// offer's `maxExpiryBlocks` still caps the window from above with no lower bound
/// (`open_expiry_blocks(..).min(max_expiry - 1)`, xbt402/funding.rs:146): a seller that offers
/// `maxExpiryBlocks: 2` and answers the preflight yes gets a channel funded that expires in one
/// block. It can never be opened (`complete_open` refuses inside `refund_margin_blocks`,
/// session.rs:445), the watcher refunds it, and the next `xbt402_pay` funds the next one. Each
/// round costs the funding fee and the refund fee (600 + 600 sat here), is booked nowhere, and
/// meets no budget, velocity limit or human threshold. The socket's `open_channel` refuses an
/// expiry at or inside `refund_margin_blocks` (signer.rs:1087); this path does not.
///
/// Fails on d4c8328: three calls, three fundings, the hot wallet 3,600 sat lower, 0 sat in the ledger.
#[test]
fn hole_a_sellers_offer_cannot_make_the_wallet_fund_a_channel_that_expires_at_once() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({"hot_balance_cap_sats": 100_000}), false);
    rig.fund_hot(1, 50_000);
    short_window(&mut rig, 2);
    let start = rig.hot_sats();
    let mut funded = vec![];
    for _ in 0..3 {
        let r = rig.pay();
        if let Some(c) = rig.s.book.get(PROVIDER).filter(|c| c.state == "pending") {
            funded.push((c.funding_sats, c.expiry - rig.chain.height() as i64, r["verdict"].to_string()));
        }
        rig.chain.mine(3);
        rig.s.watch_tick(); // refunds it
        rig.chain.mine(1);
    }
    assert!(funded.is_empty(),
            "the wallet funded {} channels (sat, blocks to expiry, answer) {funded:?} on the seller's window; refund_margin_blocks is 6; \
             the hot wallet went {start} -> {} and the policy ledger holds {}", funded.len(), rig.hot_sats(), ledger(&rig));
}

/// Control: the same seller with a window the wallet can use is funded once and not refunded.
#[test]
fn control_an_offer_with_a_usable_window_is_funded_once() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({"hot_balance_cap_sats": 100_000}), false);
    rig.fund_hot(1, 50_000);
    short_window(&mut rig, 2_000);
    assert_eq!(rig.pay()["verdict"], "pending");
    let c = rig.s.book.get(PROVIDER).unwrap();
    assert_eq!(c.expiry - rig.chain.height() as i64, 1_008);
}

// --- 3. and 4. rollovers ---------------------------------------------------------------------------

fn next_for(rig: &Rig, rec: &xbt_signer::channels::ChannelRecord, key: &str, blocks: u64) -> ChannelParams {
    let cur = rec.params().unwrap();
    ChannelParams::derive(&seller_pay_to(), &hex::decode(key).unwrap(), (rig.chain.height() + blocks) as u32, cur.close_fee,
                          Some(hex::decode(rig.hot_spk()).unwrap()), &rig.chain.network(), cur.close_fee_payer).unwrap()
}

fn sign_roll(rig: &Rig, rec: &xbt_signer::channels::ChannelRecord, next: &ChannelParams, amount: u64) -> Value {
    let cap = rec.params().unwrap().rollover_next_capacity(amount);
    rig.call("xbt402_sign_rollover", json!({"chan": rec.chan, "amount": amount, "next_spk": hex::encode(next.spk()), "next_capacity": cap, "next": next.to_json()}))
}

/// AGP-089 "found, not fixed" 1, run. A seller is sent a signed rollover, answers it with an
/// error, and broadcasts it. Wave 4 keeps the next channel's key and terms (`rolled_next`), so the
/// coins are no longer lost. But nothing in the signer acts on them: the watcher, which holds the
/// key, the terms and a node, never looks at the spender of the rolled channel, so the next
/// channel has no record and is not refunded at its expiry. Only a socket caller's `xbt402_attach`
/// with the funded params makes it one. Meanwhile the old record stays `open` and the signer's own
/// `xbt402_pay` signs and books a further state on a funding that is spent.
///
/// Fails on d4c8328: two blocks past the next channel's expiry, 8,800 of the channel's 10,000 sat
/// are still in the next channel's script and the watcher's ticks did nothing.
#[test]
fn hole_the_watcher_refunds_a_next_channel_nobody_attached() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, rec, next_origin) = roll_rig();
    let k1 = rig.call("xbt402_new_key", json!({"origin": next_origin}))["pub"].as_str().unwrap().to_string();
    let next = next_for(&rig, &rec, &k1, 1_014);
    let amount = rec.used_sats as u64;
    let next_cap = rec.params().unwrap().rollover_next_capacity(amount);
    let sig = sign_roll(&rig, &rec, &next, amount);
    assert!(sig["sig"].is_string(), "{sig}");
    // the seller answered the client with an error; it broadcasts the rollover it was sent
    let body = json!({"chan": rec.chan, "amount": amount, "sig": sig["sig"],
                      "next": {"payerPub": hex::encode(next.payer_pub), "expiry": next.expiry, "payerSpk": hex::encode(&next.payer_spk)}});
    let resp = rig.web.request("POST", &format!("{PROVIDER}{ROLLOVER_PATH}"), body.to_string().as_bytes(), &[("Content-Type".into(), "application/json".into())]).unwrap();
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    rig.chain.mine(1);
    assert_eq!(rig.chain.unspent_to(&hex::encode(next.spk())), next_cap as i64, "the rollover is in a block and funds the next channel");
    rig.chain.mine_to(next.expiry as u64 + 2);
    let acts: Vec<Vec<Value>> = (0..3).map(|_| { let a = rig.s.watch_tick(); rig.chain.mine(1); a }).collect();
    let left = rig.chain.unspent_to(&hex::encode(next.spk()));
    let state = rig.s.book.get(PROVIDER).map(|r| (r.state, r.chan == rec.chan));
    assert_eq!(left, 0, "{left} sat are still in the next channel past its expiry {}; the signer holds its key and terms and its watcher did {acts:?}; \
                         the record at this origin is (state, still the rolled channel) {state:?}", next.expiry);
}

/// New in wave 4. `sign_rollover` keeps the next channel's key and adds it to `rolled_next`
/// (signer.rs:1424) before the policy decides on the signature (`booked_increase`, signer.rs:1427).
/// A rollover the policy refuses (above `max_per_tx`, or `needs_human`, or a stale amount) signs
/// nothing and still takes one of the channel's eight slots. After eight such refusals into
/// different next scripts (a client that retries one block later asks for another expiry, so
/// another script) the channel can never be rolled over: `rollover_pending`, "8 rollovers ... are
/// signed and none is attached", with no signature ever made and nothing that could be attached.
///
/// Fails on d4c8328: 0 signatures made, 8 slots used, the ninth (a rollover the policy allows) refused.
#[test]
fn hole_rollovers_that_were_refused_do_not_use_up_the_channels_next_slots() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, rec, next_origin) = roll_rig();
    let k1 = rig.call("xbt402_new_key", json!({"origin": next_origin}))["pub"].as_str().unwrap().to_string();
    let sigs_before = rig.sigs().len();
    let refused: Vec<String> = (0..xbt_signer::channels::MAX_ROLLED_NEXT as u64)
        .map(|i| sign_roll(&rig, &rec, &next_for(&rig, &rec, &k1, 1_014 + i), rec.used_sats as u64 + 6_000)["rule"].as_str().unwrap_or("").to_string()).collect();
    assert!(refused.iter().all(|r| r == "max_per_tx"), "{refused:?}");
    let made = rig.sigs().len() - sigs_before;
    assert_eq!(made, 0);
    let real = sign_roll(&rig, &rec, &next_for(&rig, &rec, &k1, 1_100), rec.used_sats as u64);
    assert!(real["sig"].is_string(),
            "{made} rollover signatures were made; the policy refused {} requests; the channel's record holds {} next channels and a rollover the policy allows answers {real}",
            refused.len(), rig.s.book.get(PROVIDER).unwrap().rolled_next.len());
}

// --- 5. the used-signature file and the clock -------------------------------------------------------

const MIKE: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/// New in wave 4. `UsedSigs::spend` drops every entry whose expiry is below the signer's clock
/// (admin.rs:71), because "the expiry check refuses them from then on". That holds only while the
/// clock never goes back. The clock is the host's wall clock (`PolicyEngine::now`); after a step
/// back (a wrong RTC at boot, an NTP correction, whoever can set the host's time), a signature that
/// was used, then pruned, is inside its window again and is not in the file: it runs a second time.
///
/// Fails on d4c8328: the second sweep with the same signature answers `ok: true`.
#[test]
fn hole_a_used_human_signature_stays_used_when_the_clock_goes_back() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({}), false);
    let t = Arc::new(std::sync::atomic::AtomicI64::new(xbt_signer::pyjson::now_f64() as i64));
    let tc = t.clone();
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(rig.chain.clone()), transport: Some(rig.web.clone()),
                                                   clock: Some(Arc::new(move || tc.load(Ordering::SeqCst) as f64)), ..Default::default() }).unwrap();
    for tag in 1..=3 {
        rig.fund_hot(tag, 5_000);
    }
    let hot = rig.call("hot_address", json!({}))["hot_address"].as_str().unwrap().to_string();
    let now = t.load(Ordering::SeqCst);
    let sweep = |exp: i64| json!({"to": MIKE, "amount_sats": 2_000, "expiry": exp, "signature": sign_human(&xbt_signer::approval::sweep_message(&hot, MIKE, 2_000, exp))});
    let first = sweep(now + 60);
    assert_eq!(rig.call("sweep_hot", first.clone())["ok"], true);
    assert_eq!(rig.call("sweep_hot", first.clone())["rule"], "human_sig_replay", "control: used once");
    // time passes; the human signs another sweep: the first entry is pruned as expired
    t.store(now + 120, Ordering::SeqCst);
    assert_eq!(rig.call("sweep_hot", first.clone())["reason"], "sweep signature expired", "control: refused by its expiry");
    assert_eq!(rig.call("sweep_hot", sweep(now + 400))["ok"], true);
    // the clock steps back inside the first signature's window
    t.store(now + 30, Ordering::SeqCst);
    let again = rig.call("sweep_hot", first);
    assert_ne!(again["ok"], true, "a signature that was used ran again after the clock went back: {} swept to {MIKE} in all",
               rig.chain.unspent_to(&hex::encode(xbt_signer::signer::address_to_spk(MIKE, "bcrt").unwrap())));
}

// --- 6. an unchecked sum on the socket's open_channel ------------------------------------------------

/// `open_from_offer` got checked arithmetic in wave 4; the socket's `open_channel` did not:
/// `let funded = cap + close_fee` (signer.rs:1058) and `open_height + expiry_blocks` (1054). With
/// `close_fee_max_sats: 0` (no cap, the setting AGP-089's own test uses) `open_channel_checked`
/// lets any `close_fee >= 0` through. Overflow checks are on in every profile now, so the sum
/// panics: the request thread dies under `release`, the whole signer under `release-small`
/// (`panic = "abort"`, the profile `dist/` is built with).
///
/// Fails on d4c8328: panicked at signer.rs:1058 "attempt to add with overflow".
#[test]
fn hole_open_channel_with_a_fee_that_does_not_fit_is_refused_not_a_panic() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"close_fee_max_sats": 0, "counterparties": {PROVIDER: {"pay_to": hex::encode(seller_pay_to())}}}), false);
    rig.fund_hot(1, 12_000);
    let s = rig.s.clone();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || s.handle("open_channel", &json!({"dest": PROVIDER, "close_fee": i64::MAX}))));
    // the spend lock was held by the thread that panicked; the signer still answers afterwards
    assert_eq!(rig.call("hot_address", json!({}))["hot_sats"], 12_000);
    assert!(r.is_ok(), "open_channel with close_fee i64::MAX panicked inside the signer (signer.rs:1058: cap + close_fee)");
}

// --- part D: the review's W1 through the raw socket -------------------------------------------------

/// The wallet MCP's `xbt402_pay` in signer mode is one JSON line on this socket (xbt-wallet-mcp
/// wallet.rs:155-171). W1 end to end: a stream whose cost overflows, asked over the socket, signs
/// nothing past the manifest call; a stream that fits is bought and the ledger rises by no more
/// than `max_sats`.
#[cfg(unix)]
#[test]
fn control_w1_over_the_raw_socket_a_stream_stays_inside_max_sats() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    for (n, price) in [(1i64 << 54, 1_024i64), (i64::MAX, 2), (4, 100), (3, i64::MAX / 2), (40, 100)] {
        let mut rig = Rig::new(json!({"max_per_tx_sats": 5000, "human_threshold_sats": 5000}), false);
        rig.fund_hot(1, 12_000);
        let chunks: Vec<Vec<u8>> = (0..16u8).map(|i| vec![i; 8]).collect();
        let (root, proofs) = tree(&chunks);
        let mut m = json!({"id": "s1", "n": n, "size": 128, "root": hex::encode(root), "lock": "00".repeat(32), "finalCt": "00".repeat(32),
                           "price": price, "payTo": hex::encode(seller_pay_to()), "lastProof": []});
        m["sig"] = hex::encode(ecdsa::sign(&secret("provider payTo"), &manifest_message(&m))).into();
        provider_with(&rig, json!({"stream": "xbt402-merkle-v1", "manifest": m, "chunkUrl": "/chunk/{i}"}), 10_000, 600);
        hooked(&mut rig, Box::new(move |_, url, _, _| {
            let i: usize = url.rsplit_once("/chunk/")?.1.parse().ok()?;
            let c = json!({"i": i, "data": hex::encode(chunks.get(i)?), "proof": proofs[i]});
            Some(Ok(HttpResponse::new(200, vec![], c.to_string().into_bytes())))
        }));
        let sock = rig.dir.path().join("signer.sock");
        let _srv = xbt_signer::server::spawn(rig.s.clone(), &sock, false).unwrap();
        let client = xbt_signer::client::SignerClient::new(&sock);
        let ask = json!({"url": URL, "method": "GET", "body": "", "max_sats": 2_000});
        assert_eq!(client.call("xbt402_pay", ask.clone()).unwrap()["verdict"], "pending");
        rig.chain.mine(1);
        for call in 0..3 {
            let before = ledger(&rig);
            let r = client.call("xbt402_pay", ask.clone());
            let rose = ledger(&rig) - before;
            assert!(r.is_ok() && rose <= 2_000, "n {n} price {price} call {call}: the ledger rose by {rose} on a max_sats 2,000 call: {r:?}");
            assert_eq!(rig.s.book.get(PROVIDER).unwrap().used_sats, ledger(&rig), "n {n} price {price}: every signed sat is booked");
        }
        assert_eq!(client.call("health", json!({})).unwrap()["ok"], true);
    }
}

// --- 7. a negative price on a free-only call ---------------------------------------------------------

/// `xbt402_pay` with `max_sats: 0` is "free-only: allowlisted dest, no channel open or update; a >0
/// price is refused in pay_once" (signer.rs:1246-1247). The price is the seller's number and is
/// read signed (`py_int`, session.rs:625): a negative one is neither `> max_sats` nor `== 0`
/// (session.rs:626-629), so the call goes on to `open_from_offer` and funds a channel. No policy
/// evaluation ran for it (the free-only branch returns before `evaluate_booking`).
///
/// Fails on d4c8328: the call answers `pending`, 10,000 sat are in a funding to the seller's script.
#[test]
fn hole_a_free_only_call_never_funds_a_channel() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    let web = rig.web.clone();
    hooked(&mut rig, Box::new(move |method, url, body, headers| {
        if url == URL && !paid(headers) {
            let r = web.request(method, url, body, headers).unwrap();
            let mut pr = unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap();
            pr["accepts"][0]["amount"] = "-1".into();
            return Some(Ok(HttpResponse::new(402, vec![("PAYMENT-REQUIRED".into(), b64json(&pr))], b"".to_vec())));
        }
        None
    }));
    let before = rig.hot_sats();
    let r = rig.call("xbt402_pay", json!({"url": URL, "method": "GET", "body": "", "max_sats": 0}));
    let funded = rig.s.book.get(PROVIDER).map(|c| (c.state, c.funding_sats));
    assert!(funded.is_none(), "a max_sats 0 call answered {} / {} and funded {funded:?}; hot wallet {before} -> {}", r["verdict"], r["rule"], rig.hot_sats());
}
