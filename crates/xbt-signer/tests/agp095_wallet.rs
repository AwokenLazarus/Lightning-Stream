//! AGP-095, fix wave 5, Rust wallet (xbt-signer). The third audit's own tests for these items are in
//! `agp093_wallet_rs.rs` and `agp093_ln.rs`; the tests here cover what the audit had "from
//! reading", the paths beside each named one, and each rule this wave added at its bound.
//! `control_*` tests passed before the fix too: they pin what a rule must not change.
mod common;

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;

use common::*;
use serde_json::{json, Value};
use xbt402::channel::ChannelParams;
use xbt402::client::Transport;
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::wire::{b64json, unb64json, OPEN_PATH, ROLLOVER_PATH};
use xbt_primitives::ecdsa;
use xbt_signer::node::Node;
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

fn sent_payload(headers: &[(String, String)]) -> Value {
    let h = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-SIGNATURE")).map(|(_, v)| v.clone()).unwrap();
    unb64json(&h).unwrap()["payload"].clone()
}

fn ledger(rig: &Rig) -> i64 {
    rig.s.engine.store.payments().unwrap().iter().map(|e| e.amount_sats).sum()
}

fn seller_pay_to() -> Vec<u8> {
    ecdsa::pubkey(&secret("provider payTo")).to_vec()
}

fn provider(rig: &Rig, billing: &str, min_capacity: u64, price: u64) {
    let mut cfg = ProviderConfig::new(&rig.chain.network());
    (cfg.policy.min_capacity, cfg.policy.max_capacity, cfg.policy.min_expiry_blocks, cfg.policy.min_conf) = (min_capacity, 10_000, 1_008, 1);
    cfg.billing = billing.into();
    let p = Provider::new(Arc::new(ProviderChain(rig.chain.clone())), secret("provider payTo"), cfg, Ledger::in_memory(), Box::new(move |_, _| price),
                          Box::new(|_, _, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], b"{\"ok\": true}".to_vec()))).unwrap();
    rig.web.sites.lock().unwrap().insert(PROVIDER.into(), Arc::new(p));
}

/// A prepay seller at 500 sat a call, and a transport that follows `mode` for the next paid request:
/// 1 serves it and loses the answer, 2 loses the request before the seller sees it, 3 answers it
/// with `forged` (and shows the seller nothing).
fn lost_rig(billing: &str, forged: Arc<dyn Fn(&Value) -> HttpResponse + Send + Sync>) -> (Rig, Arc<AtomicU8>) {
    let mut rig = Rig::new(json!({"daily_budget_sats": 60000, "weekly_budget_sats": 60000}), false);
    provider(&rig, billing, 10_000, 500);
    rig.fund_hot(1, 12_000);
    let mode = Arc::new(AtomicU8::new(0));
    let (web, m) = (rig.web.clone(), mode.clone());
    hooked(&mut rig, Box::new(move |method, url, body, headers| {
        if !paid(headers) {
            return None;
        }
        match m.load(Ordering::SeqCst) {
            1 => {
                m.store(0, Ordering::SeqCst);
                let _ = web.request(method, url, body, headers);
                Some(Err(xbt402::ChannelError::new("transport_error", "connection reset")))
            }
            2 => {
                m.store(0, Ordering::SeqCst);
                Some(Err(xbt402::ChannelError::new("transport_error", "connection refused")))
            }
            3 => Some(Ok(forged(&sent_payload(headers)))),
            _ => None,
        }
    }));
    (rig, mode)
}

fn no_forgery() -> Arc<dyn Fn(&Value) -> HttpResponse + Send + Sync> {
    Arc::new(|_| HttpResponse::new(500, vec![], vec![]))
}

fn refusal(error: &str, chan: &Value, cum: &Value, seq: &Value) -> HttpResponse {
    let pr = json!({"x402Version": 2, "error": error, "accepts": [], "channel": {"chan": chan, "cum": cum, "seq": seq, "spentMsat": "0"}});
    HttpResponse::new(402, vec![("PAYMENT-REQUIRED".into(), b64json(&pr))], vec![])
}

// --- item 3: one new state per call, only when the seller holds the last one ------------------------

/// The other half of the rule, and why a state is sent again at all: a request that never reached
/// the seller was not served, so the call after it is paid by the same state. Nothing is signed
/// twice for one call.
#[test]
fn control_a_request_lost_on_the_way_out_is_paid_once() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, mode) = lost_rig("prepay", no_forgery());
    rig.open();
    let before = rig.s.book.get(PROVIDER).unwrap().used_sats;
    mode.store(2, Ordering::SeqCst);
    assert_eq!(rig.pay()["verdict"], "deny");
    let signed = rig.s.book.get(PROVIDER).unwrap().used_sats;
    assert!(signed > before, "the lost request carried a new state");
    let r = rig.pay();
    assert_eq!((r["status"].as_i64(), r["booked_sats"].as_i64()), (Some(200), Some(0)), "the same state pays the call the seller now serves: {r}");
    assert_eq!(rig.s.book.get(PROVIDER).unwrap().used_sats, signed, "one call served, one state signed");
    assert_eq!(ledger(&rig), signed);
}

/// After a lost answer the call that resyncs signs exactly one new state, inside its own
/// `max_sats`, and the ledger holds every signed sat before it leaves. Then the channel goes on
/// at one state a call.
///
/// Failed before the fix: every call after the lost answer was 402 for good (the audit's test);
/// this one also pins what the resync signs.
#[test]
fn a_lost_answer_costs_one_new_state_and_the_channel_goes_on() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, mode) = lost_rig("prepay", no_forgery());
    rig.open();
    mode.store(1, Ordering::SeqCst);
    assert_eq!(rig.pay()["verdict"], "deny", "served, and the answer lost");
    let lost = rig.s.book.get(PROVIDER).unwrap().used_sats;
    let r = rig.pay();
    let rec = rig.s.book.get(PROVIDER).unwrap();
    assert_eq!((r["status"].as_i64(), r["booked_sats"].as_i64()), (Some(200), Some(500)), "{r}");
    assert_eq!((rec.used_sats, rec.acked_sats), (lost + 500, lost + 500), "one state above the one whose answer was lost, acked by its receipt");
    assert_eq!(ledger(&rig), rec.used_sats);
    for _ in 0..3 {
        let before = rig.s.book.get(PROVIDER).unwrap().used_sats;
        assert_eq!(rig.pay()["status"], 200);
        assert_eq!(rig.s.book.get(PROVIDER).unwrap().used_sats, before + 500);
    }
}

/// The 402 is the seller's unsigned word, so anyone on the path can write one. What it can do is
/// bounded by the rule itself: one new state per `xbt402_pay`, each inside that call's `max_sats`
/// and booked. A 402 that does not name this channel's last state and this request, or that
/// refuses for another reason, signs nothing.
///
/// Failed before the fix on the first part only in the sense that nothing was ever signed again;
/// the second part is the bound of the new rule.
#[test]
fn a_402_signs_one_state_only_when_it_names_the_state_just_sent() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    type Forge = fn(&Value) -> HttpResponse;
    let wrong: [(&str, Forge); 5] = [
        ("another reason", |p| refusal("channel_closing", &p["chan"], &p["cum"], &p["seq"])),
        ("a lower cum: the seller does not hold the state", |p| refusal("insufficient_payment", &p["chan"], &json!("546"), &p["seq"])),
        ("another request's seq", |p| refusal("insufficient_payment", &p["chan"], &p["cum"], &json!(1))),
        ("another channel", |p| refusal("insufficient_payment", &json!("00".repeat(32) + ":0"), &p["cum"], &p["seq"])),
        ("no channel in the 402", |_| HttpResponse::new(402, vec![("PAYMENT-REQUIRED".into(), b64json(&json!({"x402Version": 2, "error": "insufficient_payment", "accepts": []})))], vec![])),
    ];
    for (what, forge) in wrong {
        let (rig, mode) = lost_rig("prepay", Arc::new(forge));
        rig.open();
        mode.store(1, Ordering::SeqCst);
        rig.pay();
        let signed = rig.s.book.get(PROVIDER).unwrap().used_sats;
        mode.store(3, Ordering::SeqCst);
        for _ in 0..3 {
            let r = rig.pay();
            assert_eq!(r["booked_sats"].as_i64().unwrap_or(0), 0, "{what}: {r}");
        }
        assert_eq!(rig.s.book.get(PROVIDER).unwrap().used_sats, signed, "{what}: nothing above the unacked state is signed");
        assert_eq!(ledger(&rig), signed, "{what}");
    }
    // a 402 that does name it, from someone who serves nothing: one state per call, never two
    let (rig, mode) = lost_rig("prepay", Arc::new(|p| refusal("insufficient_payment", &p["chan"], &p["cum"], &p["seq"])));
    rig.open();
    mode.store(1, Ordering::SeqCst);
    rig.pay();
    let signed = rig.s.book.get(PROVIDER).unwrap().used_sats;
    mode.store(3, Ordering::SeqCst);
    for call in 1..=4 {
        let before = ledger(&rig);
        let r = rig.pay();
        let rose = ledger(&rig) - before;
        assert_eq!(rose, 500, "call {call}: one state of one price, inside max_sats 500: {r}");
        assert_eq!(rig.s.book.get(PROVIDER).unwrap().used_sats, signed + 500 * call, "call {call}");
        assert_eq!(rig.s.book.get(PROVIDER).unwrap().used_sats, ledger(&rig), "every signed sat is booked");
    }
}

/// The new state is held to the call's `max_sats` like a first one: a resync on a call that may
/// not pay the price signs nothing.
#[test]
fn the_resync_state_is_held_to_the_calls_max_sats() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, mode) = lost_rig("prepay", no_forgery());
    rig.open();
    mode.store(1, Ordering::SeqCst);
    rig.pay();
    let signed = rig.s.book.get(PROVIDER).unwrap().used_sats;
    let r = rig.call("xbt402_pay", json!({"url": URL, "method": "GET", "body": "", "max_sats": 499}));
    assert_eq!((r["verdict"].as_str(), r["rule"].as_str()), (Some("deny"), Some("max_sats")), "{r}");
    assert_eq!(rig.s.book.get(PROVIDER).unwrap().used_sats, signed);
}

// --- item 4: the offer's window, lower side ---------------------------------------------------------

fn window(rig: &mut Rig, min_expiry: i64, max_expiry: i64, amount: Option<&'static str>) {
    let web = rig.web.clone();
    hooked(rig, Box::new(move |method, url, body, headers| {
        if url == URL && !paid(headers) {
            let r = web.request(method, url, body, headers).unwrap();
            let mut pr = unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap();
            pr["accepts"][0]["extra"]["minExpiryBlocks"] = min_expiry.into();
            pr["accepts"][0]["extra"]["maxExpiryBlocks"] = max_expiry.into();
            pr["accepts"][0]["extra"]["closeMarginBlocks"] = 0.into();
            if let Some(a) = amount {
                pr["accepts"][0]["amount"] = a.into();
            }
            return Some(Ok(HttpResponse::new(402, vec![("PAYMENT-REQUIRED".into(), b64json(&pr))], b"".to_vec())));
        }
        if url.ends_with(OPEN_PATH) && String::from_utf8_lossy(body).contains("\"preflight\"") {
            return Some(Ok(HttpResponse::new(200, vec![], json!({"preflight": true}).to_string().into_bytes())));
        }
        None
    }));
}

/// The audit's test offers a window of one block. A window longer than the refund margin (6) and
/// far shorter than anything the owner asked for is the same hole at a slower rate: a channel
/// that lasts 49 blocks, for a funding fee and a refund fee, as often as the seller likes.
///
/// Failed before the fix: funded, 49 blocks to expiry.
#[test]
fn a_window_above_the_refund_margin_and_below_a_day_is_not_funded() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    for max_expiry in [8, 50, 144] {
        let mut rig = Rig::new(json!({"hot_balance_cap_sats": 100_000}), false);
        rig.fund_hot(1, 50_000);
        window(&mut rig, 1, max_expiry, None);
        let before = rig.hot_sats();
        let r = rig.pay();
        assert_eq!((r["verdict"].as_str(), r["rule"].as_str()), (Some("deny"), Some("expiry")), "window {max_expiry}: {r}");
        assert!(rig.s.book.get(PROVIDER).is_none() && rig.hot_sats() == before, "window {max_expiry}: nothing funded");
    }
}

/// At the floor and with an owner who asks for less than a day: funded, as before.
#[test]
fn control_a_day_long_window_and_a_short_channel_the_owner_asked_for_are_funded() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    for (policy_blocks, max_expiry, want) in [(1_008, 145, 144), (100, 2_000, 100), (20, 2_000, 20)] {
        let mut rig = Rig::new(json!({"hot_balance_cap_sats": 100_000, "channel_expiry_blocks": policy_blocks}), false);
        rig.fund_hot(1, 50_000);
        window(&mut rig, 1, max_expiry, None);
        assert_eq!(rig.pay()["verdict"], "pending", "policy {policy_blocks}, window {max_expiry}");
        let c = rig.s.book.get(PROVIDER).unwrap();
        assert_eq!(c.expiry - rig.chain.height() as i64, want);
    }
}

/// A negative price on a call that may pay: refused as an offer, not opened at -1 a call.
///
/// Failed before the fix: `pending`, a channel funded.
#[test]
fn a_negative_price_funds_nothing_on_a_paying_call() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    window(&mut rig, 1_008, 8_640, Some("-1"));
    let r = rig.call("xbt402_pay", json!({"url": URL, "method": "GET", "body": "", "max_sats": 500}));
    assert_eq!(r["verdict"], "deny", "{r}");
    assert!(rig.s.book.get(PROVIDER).is_none(), "{r}");
}

// --- item 15: rollover slots and the unattached next channel ----------------------------------------

fn roll_rig() -> (Rig, xbt_signer::channels::ChannelRecord, String) {
    let rig = Rig::new(json!({"max_per_tx_sats": 5000, "human_threshold_sats": 5000}), false);
    provider(&rig, "prepay", 5_000, 600);
    rig.fund_hot(1, 12_000);
    assert_eq!(rig.call("xbt402_pay", json!({"url": URL, "max_sats": 1_000}))["verdict"], "pending");
    rig.chain.mine(1);
    assert_eq!(rig.call("xbt402_pay", json!({"url": URL, "max_sats": 1_000}))["verdict"], "allow");
    let rec = rig.s.book.get(PROVIDER).unwrap();
    let next_origin = format!("{}/next", rec.origin);
    (rig, rec, next_origin)
}

fn next_for(rig: &Rig, rec: &xbt_signer::channels::ChannelRecord, key: &str, blocks: u64) -> ChannelParams {
    let cur = rec.params().unwrap();
    ChannelParams::derive(&seller_pay_to(), &hex::decode(key).unwrap(), (rig.chain.height() + blocks) as u32, cur.close_fee,
                          Some(hex::decode(rig.hot_spk()).unwrap()), &rig.chain.network(), cur.close_fee_payer).unwrap()
}

fn sign_roll(rig: &Rig, rec: &xbt_signer::channels::ChannelRecord, next: &ChannelParams, amount: u64) -> Value {
    let cap = rec.params().unwrap().rollover_next_capacity(amount);
    rig.call("xbt402_sign_rollover", json!({"chan": rec.chan, "amount": amount, "next_spk": hex::encode(next.spk()), "next_capacity": cap, "next": next.to_json()}))
}

/// The audit's test fills the slots with requests the policy refuses. A request the policy allows
/// and the book then refuses (an amount above the channel's cap) must take no slot either, and
/// its ledger row is taken out again.
///
/// Failed before the fix: 8 slots used, no signature made, the ninth rollover refused.
#[test]
fn a_rollover_the_book_refuses_takes_no_slot_and_leaves_no_ledger_row() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, rec, next_origin) = roll_rig();
    let k1 = rig.call("xbt402_new_key", json!({"origin": next_origin}))["pub"].as_str().unwrap().to_string();
    let (sigs, booked) = (rig.sigs().len(), ledger(&rig));
    let over_cap = rec.cap_sats as u64 + 1;
    for i in 0..xbt_signer::channels::MAX_ROLLED_NEXT as u64 {
        let r = sign_roll(&rig, &rec, &next_for(&rig, &rec, &k1, 1_014 + i), over_cap);
        assert!(r["sig"].is_null(), "an amount above the cap is not signed: {r}");
    }
    assert_eq!((rig.sigs().len(), ledger(&rig)), (sigs, booked), "no signature and no ledger row");
    assert_eq!(rig.s.book.get(PROVIDER).unwrap().rolled_next.len(), 0);
    // a rollover that is signed takes one slot, and asking for the same next channel again takes no second
    let next = next_for(&rig, &rec, &k1, 1_100);
    for _ in 0..2 {
        assert!(sign_roll(&rig, &rec, &next, rec.used_sats as u64)["sig"].is_string());
    }
    assert_eq!(rig.s.book.get(PROVIDER).unwrap().rolled_next.len(), 1);
}

/// The eighth different next channel that is signed is the last; the bound itself did not move.
#[test]
fn control_eight_signed_rollovers_still_fill_the_slots() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, rec, next_origin) = roll_rig();
    let k1 = rig.call("xbt402_new_key", json!({"origin": next_origin}))["pub"].as_str().unwrap().to_string();
    for i in 0..xbt_signer::channels::MAX_ROLLED_NEXT as u64 {
        assert!(sign_roll(&rig, &rec, &next_for(&rig, &rec, &k1, 1_014 + i), rec.used_sats as u64)["sig"].is_string(), "{i}");
    }
    let ninth = sign_roll(&rig, &rec, &next_for(&rig, &rec, &k1, 1_200), rec.used_sats as u64);
    assert_eq!(ninth["rule"], "rollover_pending", "{ninth}");
}

fn broadcast_rollover(rig: &Rig, rec: &xbt_signer::channels::ChannelRecord, next: &ChannelParams) -> ChannelParams {
    let amount = rec.used_sats as u64;
    let sig = sign_roll(rig, rec, next, amount);
    assert!(sig["sig"].is_string(), "{sig}");
    let body = json!({"chan": rec.chan, "amount": amount, "sig": sig["sig"],
                      "next": {"payerPub": hex::encode(next.payer_pub), "expiry": next.expiry, "payerSpk": hex::encode(&next.payer_spk)}});
    let resp = rig.web.request("POST", &format!("{PROVIDER}{ROLLOVER_PATH}"), body.to_string().as_bytes(), &[("Content-Type".into(), "application/json".into())]).unwrap();
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    let reply: Value = serde_json::from_slice(&resp.body).unwrap();
    next.clone().with_funding(reply["txid"].as_str().unwrap(), 1, rec.params().unwrap().rollover_next_capacity(amount)).unwrap()
}

/// The watcher adopts the next channel when the rollover is in a block, not while it is only in
/// the mempool, and well before the next channel's expiry: the record at the origin is then the
/// next channel, open, and `xbt402_attach` by a client that comes later answers that same channel.
///
/// Failed before the fix: the watcher did nothing, at any height.
#[test]
fn the_watcher_adopts_a_rollover_in_a_block_and_a_later_attach_answers_the_same_channel() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, rec, next_origin) = roll_rig();
    let k1 = rig.call("xbt402_new_key", json!({"origin": next_origin.clone()}))["pub"].as_str().unwrap().to_string();
    let funded = broadcast_rollover(&rig, &rec, &next_for(&rig, &rec, &k1, 1_014));
    let acts = rig.s.watch_tick();
    assert!(acts.iter().all(|a| a.get("rollover_adopted").is_none()), "in the mempool only: {acts:?}");
    assert_eq!(rig.s.book.get(PROVIDER).unwrap().chan, rec.chan);
    rig.chain.mine(1);
    let acts = rig.s.watch_tick();
    let now = rig.s.book.get(PROVIDER).unwrap();
    assert_eq!((now.chan.as_str(), now.state.as_str(), now.funding_sats), (funded.channel_id().as_str(), "open", funded.capacity as i64), "{acts:?}");
    assert_eq!(now.expiry, funded.expiry as i64);
    assert!(rig.s.book.records_of(PROVIDER).iter().any(|r| r.chan == rec.chan && r.state == "closed"), "the rolled channel is settled and kept");
    let again = rig.call("xbt402_attach", json!({"origin": next_origin, "params": funded.to_json()}));
    assert_eq!(again["chan"], funded.channel_id(), "{again}");
    // nothing more to adopt, and the channel is refunded at its own expiry
    assert!(rig.s.watch_tick().iter().all(|a| a.get("rollover_adopted").is_none()));
    rig.chain.mine_to(funded.expiry as u64);
    let acts = rig.s.watch_tick();
    assert!(acts.iter().any(|a| a["rule"] == "refund" && a["chan"] == funded.channel_id()), "{acts:?}");
}

/// A close that is not a rollover funds none of the next channels the record names: nothing is
/// adopted, and the record is the closed channel.
#[test]
fn control_a_plain_close_of_a_channel_with_signed_rollovers_adopts_nothing() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, rec, next_origin) = roll_rig();
    let k1 = rig.call("xbt402_new_key", json!({"origin": next_origin}))["pub"].as_str().unwrap().to_string();
    assert!(sign_roll(&rig, &rec, &next_for(&rig, &rec, &k1, 1_014), rec.used_sats as u64)["sig"].is_string());
    assert_eq!(rig.call("close_channel", json!({"counterparty": PROVIDER}))["verdict"], "allow");
    rig.chain.mine(1);
    for _ in 0..2 {
        let acts = rig.s.watch_tick();
        assert!(acts.iter().all(|a| a.get("rollover_adopted").is_none()), "{acts:?}");
    }
    let now = rig.s.book.get(PROVIDER).unwrap();
    assert_eq!((now.chan.as_str(), now.state.as_str()), (rec.chan.as_str(), "closed"));
}

// --- item 17: closed only on a spend in a block -------------------------------------------------------

/// The Rust side of the audit's B2 test (`ACloseOnlyInTheMempool`), which the audit had from
/// reading: a close reaches our mempool, is never mined and leaves it. The funding is unspent at
/// expiry and the watcher must refund it.
///
/// Failed before the fix: the close was "proven" from the mempool, the record left the watcher,
/// and nothing refunded the funding.
#[test]
fn a_close_that_was_only_ever_in_the_mempool_does_not_end_the_refund_watch() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"hot_balance_cap_sats": 100_000}), false);
    rig.fund_hot(1, 30_000);
    let chan = rig.open()["chan"].as_str().unwrap().to_string();
    let rec = rig.s.book.get(PROVIDER).unwrap();
    let before_close = rig.hot_sats();
    let c = rig.call("close_channel", json!({"counterparty": PROVIDER}));
    assert_eq!((c["verdict"].as_str(), c["close_proven"].as_bool()), (Some("allow"), Some(false)), "{c}");
    assert!(rig.hot_sats() > before_close, "the close's change is counted from the mempool on, as before");
    let close = c["txid"].as_str().unwrap().to_string();
    assert!(rig.chain.mempool().contains(&close));
    // no new channel while the old one's funding may still need its refund
    assert_eq!(rig.pay()["rule"], "close_unproven");
    rig.chain.evict(&close);
    rig.chain.mine_to(rec.expiry as u64);
    let acts = rig.s.watch_tick();
    assert!(acts.iter().any(|a| a["rule"] == "refund" && a["chan"] == chan.as_str()), "the funding is unspent at expiry: {acts:?}");
    assert_eq!(rig.channel(&chan)["state"], "refunded");
    // the hot wallet holds what the chain holds for its key: the evicted close's change is not counted
    assert_eq!(rig.hot_sats(), rig.chain.unspent_to(&rig.hot_spk()));
}

/// The refund path itself: at expiry, with a close sitting in the mempool, the channel is neither
/// closed nor refunded; once that close is in a block it is closed, with the spender our node names.
///
/// Failed before the fix: `channel_closed` on the mempool spender.
#[test]
fn at_expiry_a_mempool_close_closes_nothing_until_it_is_in_a_block() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"hot_balance_cap_sats": 100_000}), false);
    rig.fund_hot(1, 30_000);
    rig.open();
    let rec = rig.s.book.get(PROVIDER).unwrap();
    rig.chain.mine_to(rec.expiry as u64);
    // the seller's close reaches our mempool without the wallet having asked for it
    let (payer, payee) = (rec.params().unwrap(), secret("provider payTo"));
    let _ = (payer, payee);
    let body = json!({"chan": rec.chan, "sig": rig.s.book.sign_close(PROVIDER).unwrap(), "payload": {"chan": rec.chan, "seq": rec.seq, "cum": rec.used_sats.to_string()}});
    let resp = rig.web.request("POST", &format!("{PROVIDER}/x402/xbt-channel/close"), body.to_string().as_bytes(), &[("Content-Type".into(), "application/json".into())]).unwrap();
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    let close = serde_json::from_slice::<Value>(&resp.body).unwrap()["txid"].as_str().unwrap().to_string();
    let r = rig.call("xbt402_refund", json!({"counterparty": PROVIDER}));
    assert_eq!((r["rule"].as_str(), r["spender"].as_str()), (Some("close_unconfirmed"), Some(close.as_str())), "{r}");
    assert_eq!(rig.s.book.get(PROVIDER).unwrap().state, "open", "still with the watcher");
    rig.chain.mine(1);
    let r = rig.call("xbt402_refund", json!({"counterparty": PROVIDER}));
    assert_eq!((r["rule"].as_str(), r["closed_txid"].as_str()), (Some("channel_closed"), Some(close.as_str())), "{r}");
}

// --- item 13: the watcher goes on after a panic --------------------------------------------------------

/// A node whose answer to one call panics while `on` is set (a stand-in for any number that does
/// not fit: release builds check arithmetic, so that is a panic).
struct Panicky {
    inner: Arc<FakeChain>,
    on: AtomicBool,
    method: &'static str,
}

impl Node for Panicky {
    fn call(&self, method: &str, params: Value) -> xbt402::Result<Value> {
        if method == self.method && self.on.load(Ordering::SeqCst) {
            panic!("attempt to add with overflow (injected in {method})");
        }
        self.inner.call(method, params)
    }

    fn set_allow_generate(&self, allow: bool) {
        self.inner.set_allow_generate(allow)
    }

    fn wallet(&self) -> String {
        self.inner.wallet()
    }
}

fn panicky_rig(method: &'static str) -> (Rig, Arc<Panicky>, String) {
    let mut rig = Rig::new(json!({"hot_balance_cap_sats": 100_000}), false);
    rig.fund_hot(1, 30_000);
    let chan = rig.open()["chan"].as_str().unwrap().to_string();
    let node = Arc::new(Panicky { inner: rig.chain.clone(), on: AtomicBool::new(false), method });
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(node.clone()), transport: Some(rig.web.clone()), ..Default::default() }).unwrap();
    (rig, node, chan)
}

/// A panic in the refund step of one tick: the tick reports it, the steps after it still run,
/// the signer still answers, and the next tick refunds.
///
/// Failed before the fix: `watch_tick` unwound to its caller.
#[test]
fn a_panic_in_one_step_of_a_tick_ends_only_that_step() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, node, chan) = panicky_rig("sendrawtransaction");
    rig.chain.mine_to(rig.s.book.get(PROVIDER).unwrap().expiry as u64);
    node.on.store(true, Ordering::SeqCst);
    let acts = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rig.s.watch_tick())).expect("the tick itself does not panic");
    assert!(acts.iter().any(|a| a["watcher_panic"] == "refund"), "{acts:?}");
    assert_eq!(rig.call("health", json!({}))["ok"], true, "the spend lock the step held is usable again");
    assert_eq!(rig.channel(&chan)["state"], "open");
    node.on.store(false, Ordering::SeqCst);
    let acts = rig.s.watch_tick();
    assert!(acts.iter().any(|a| a["rule"] == "refund"), "{acts:?}");
    assert_eq!(rig.channel(&chan)["state"], "refunded");
}

/// The watcher thread itself (`watch_loop`): a tick that panics where no step guards it (the
/// height read at the top) does not end the thread. Once the node answers again the channel is
/// refunded by that same thread.
///
/// Failed before the fix: the thread ended with the first panic and nothing was refunded.
#[test]
fn the_watcher_thread_outlives_a_tick_that_panics() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    std::env::set_var("B2_WATCH_INTERVAL", "0.1");
    let (rig, node, chan) = panicky_rig("getblockcount");
    std::env::remove_var("B2_WATCH_INTERVAL");
    assert!(rig.s.watch_interval < 1.0);
    rig.chain.mine_to(rig.s.book.get(PROVIDER).unwrap().expiry as u64);
    node.on.store(true, Ordering::SeqCst);
    let stop = Arc::new(AtomicBool::new(false));
    let (s, st) = (rig.s.clone(), stop.clone());
    let t = std::thread::spawn(move || s.watch_loop(st));
    std::thread::sleep(std::time::Duration::from_millis(700)); // several ticks, each panicking
    assert!(!t.is_finished(), "the watcher thread ended on a panic");
    node.on.store(false, Ordering::SeqCst);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while rig.s.book.get(PROVIDER).unwrap().state != "refunded" && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    stop.store(true, Ordering::SeqCst);
    t.join().unwrap();
    assert_eq!(rig.channel(&chan)["state"], "refunded", "the same thread refunded once the node answered");
}

// --- item 16: the used-signature file's clock -----------------------------------------------------------

const MIKE: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

fn clock_rig() -> (Rig, Arc<std::sync::atomic::AtomicI64>, String) {
    let mut rig = Rig::new(json!({}), false);
    let t = Arc::new(std::sync::atomic::AtomicI64::new(xbt_signer::pyjson::now_f64() as i64));
    let tc = t.clone();
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(rig.chain.clone()), transport: Some(rig.web.clone()),
                                                   clock: Some(Arc::new(move || tc.load(Ordering::SeqCst) as f64)), ..Default::default() }).unwrap();
    for tag in 1..=3 {
        rig.fund_hot(tag, 5_000);
    }
    let hot = rig.call("hot_address", json!({}))["hot_address"].as_str().unwrap().to_string();
    (rig, t, hot)
}

fn sweep(hot: &str, sats: i64, exp: i64) -> Value {
    json!({"to": MIKE, "amount_sats": sats, "expiry": exp, "signature": sign_human(&xbt_signer::approval::sweep_message(hot, MIKE, sats, exp))})
}

/// The rule is about the message's expiry and the highest clock the file has seen, so it also
/// refuses a signature that was never used once the clock has been past its expiry: after a step
/// back nobody can tell it from a used one that was pruned.
///
/// Failed before the fix: the second sweep ran.
#[test]
fn a_signature_is_refused_once_the_clock_has_been_past_its_expiry_used_or_not() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, t, hot) = clock_rig();
    let now = t.load(Ordering::SeqCst);
    let early = sweep(&hot, 1_000, now + 60);
    t.store(now + 120, Ordering::SeqCst);
    assert_eq!(rig.call("sweep_hot", sweep(&hot, 2_000, now + 400))["ok"], true, "this use writes the clock, now + 120");
    t.store(now + 30, Ordering::SeqCst);
    let r = rig.call("sweep_hot", early);
    assert_eq!((r["ok"].as_bool(), r["rule"].as_str()), (Some(false), Some("expired")), "{r}");
    // a signature whose expiry is ahead of every clock seen still works after the step back
    assert_eq!(rig.call("sweep_hot", sweep(&hot, 1_500, now + 500))["ok"], true);
    // and the step back did not lower the stored clock
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(rig.root.join(".run").join(xbt_signer::admin::USED_SIGS_FILE)).unwrap()).unwrap();
    assert_eq!(doc["clock"], now + 120);
}

/// Upgrade: a file written before the clock was kept has no `clock` and loads; one whose `clock`
/// is not a number is unreadable, and unreadable refuses (it is never taken for empty).
#[test]
fn a_used_signature_file_from_before_the_clock_loads_and_a_bad_clock_refuses() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, t, hot) = clock_rig();
    let now = t.load(Ordering::SeqCst);
    let path = rig.root.join(".run").join(xbt_signer::admin::USED_SIGS_FILE);
    std::fs::write(&path, json!({"used": {"ab": now + 50}}).to_string()).unwrap();
    assert_eq!(rig.call("sweep_hot", sweep(&hot, 1_000, now + 60))["ok"], true);
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!((doc["clock"].as_i64(), doc["used"].as_object().map(|u| u.len())), (Some(now), Some(2)), "the old entry is kept until its own expiry");
    std::fs::write(&path, json!({"used": {}, "clock": "soon"}).to_string()).unwrap();
    let r = rig.call("sweep_hot", sweep(&hot, 1_000, now + 70));
    assert_eq!((r["ok"].as_bool(), r["rule"].as_str()), (Some(false), Some("human_sig")), "{r}");
}

// --- item 14: the socket's numbers ----------------------------------------------------------------------

/// `xbt402_sign_conditional` cut a `csv_delta` past u32 to its low bits (4,294,967,306 became 10).
///
/// Failed before the fix: a signature, for a lock of 10 blocks.
#[test]
fn a_csv_delta_that_is_not_a_block_count_is_refused() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    let chan = rig.open()["chan"].as_str().unwrap().to_string();
    let used = rig.s.book.get(PROVIDER).unwrap().used_sats;
    let ask = |csv: i64| rig.call("xbt402_sign_conditional", json!({"chan": chan, "uncond": used, "amount": 600, "hash": "11".repeat(32), "csv_delta": csv}));
    let r = ask((1i64 << 32) + 10);
    assert_eq!(r["rule"], "bad_request", "{r}");
    let ok = ask(10);
    assert!(ok["sig"].is_string(), "control: a block count is signed: {ok}");
}

/// `open_channel` with numbers that do not add up to a height or an amount: refused, with nothing
/// funded (the audit's test has the fee; these are the ones beside it).
#[test]
fn open_channel_numbers_that_do_not_fit_are_refused() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"close_fee_max_sats": 0, "counterparties": {PROVIDER: {"pay_to": hex::encode(seller_pay_to())}}}), false);
    rig.fund_hot(1, 12_000);
    for p in [json!({"dest": PROVIDER, "close_fee": i64::MAX - 5_000}), json!({"dest": PROVIDER, "cap_sats": 5_000, "close_fee": i64::MAX})] {
        let s = rig.s.clone();
        let pp = p.clone();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || s.handle("open_channel", &pp)));
        assert!(matches!(r, Ok(Err(_)) | Ok(Ok(_))), "{p}: panicked");
        assert!(rig.s.book.get(PROVIDER).is_none(), "{p}: nothing is funded");
    }
    assert_eq!(rig.hot_sats(), 12_000);
}
