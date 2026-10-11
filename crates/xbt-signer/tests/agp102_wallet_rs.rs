//! AGP-102, fourth closure audit, area wallet_rs (the Rust agent wallet: xbt-signer and its socket).
//!
//! `hole_*` tests assert a rule and FAIL on 2e745f2. `limit_*` tests pass: they pin, with numbers,
//! what a stated limit costs. `control_*` tests pass: they pin what holds.
//!
//! AGP-107 (close-out): every test here passes or is marked. A test that was still red after fix
//! wave 6 is either a `limit_*` test now (its comment names the item and the sentence of
//! `docs/LIMITS.md` it pins; it passes while the limit holds and fails when someone lifts it) or
//! is ignored with a reason that starts `open:` and names the audit's item; those are listed under
//! "Open items" there.
//!
//! Everything runs in process (the rig's fake node and in-process web): no port is opened.
mod common;

use std::sync::atomic::{AtomicI64, AtomicU8, Ordering};
use std::sync::Arc;

use common::*;
use serde_json::{json, Value};
use xbt402::channel::{ChannelParams, FeePayer};
use xbt402::client::Transport;
use xbt402::conditional::encrypt;
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::wire::{b64json, unb64json, ROLLOVER_PATH};
use xbt_primitives::ecdsa;
use xbt_primitives::hash::sha256;
use xbt_signer::channels::ChannelRecord;
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
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(rig.chain.clone()), transport: Some(t), adaptor: rig.adaptor.clone(), ..Default::default() }).unwrap();
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

/// The next paid request: 1 is served and its answer lost, 2 is lost before the seller sees it,
/// 3 is answered (every time, the seller sees nothing) with a 402 that names the state it carried.
fn faulty(rig: &mut Rig) -> Arc<AtomicU8> {
    let mode = Arc::new(AtomicU8::new(0));
    let (web, m) = (rig.web.clone(), mode.clone());
    hooked(rig, Box::new(move |method, url, body, headers| {
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
            3 => {
                let p = sent_payload(headers);
                let pr = json!({"x402Version": 2, "error": "insufficient_payment", "accepts": [],
                                "channel": {"chan": p["chan"], "cum": p["cum"], "seq": p["seq"], "spentMsat": "0"}});
                Some(Ok(HttpResponse::new(402, vec![("PAYMENT-REQUIRED".into(), b64json(&pr))], vec![])))
            }
            _ => None,
        }
    }));
    mode
}

// =====================================================================================================
// 1. Streams on a seller that bills its chunks through xbt402's own Provider (postpay)
// =====================================================================================================

const PRICE: i64 = 600;
const ECHO: &str = "http://127.0.0.1:33210/agp015/echo";

/// A two-chunk stream `id`: its document, chunk 0, the last chunk's plaintext and key.
fn stream_doc(id: &str, key: [u8; 32]) -> (Value, Value, Vec<u8>) {
    let (c0, c1) = (b"first chunk".to_vec(), format!("the last chunk of {id}").into_bytes());
    let ct = encrypt(&c1, &key);
    let (l0, l1) = (leaf(0, &c0), leaf(1, &c1));
    let root = sha256(&[b"node".as_slice(), &l0, &l1].concat());
    let mut m = json!({"id": id, "n": 2, "size": c0.len() + c1.len(), "root": hex::encode(root), "lock": hex::encode(sha256(&key)),
                       "finalCt": hex::encode(sha256(&ct)), "price": PRICE, "payTo": hex::encode(seller_pay_to()), "lastProof": [hex::encode(l0)]});
    m["sig"] = hex::encode(ecdsa::sign(&secret("provider payTo"), &manifest_message(&m))).into();
    (json!({"stream": "xbt402-merkle-v1", "manifest": m, "chunkUrl": format!("/{id}/chunk/{{i}}")}),
     json!({"i": 0, "data": hex::encode(&c0), "proof": [hex::encode(l1)]}), c1)
}

/// `(id, document, chunk 0, the last chunk's plaintext, its key)`.
type StreamParts = (String, Value, Value, Vec<u8>, [u8; 32]);

/// A stream seller made of this repository's `Provider` and nothing else: postpay (the Provider's
/// default), every path 600 sat, `/s1/doc` and `/s2/doc` answer a stream document, each stream's
/// chunk 0 is an ordinary paid path and its last chunk a hash-locked offer (`offer_conditional`).
/// No hook answers for the seller: every chunk request meets the Provider's own payment check.
fn stream_site(rig: &Rig) {
    let mut cfg = ProviderConfig::new(&rig.chain.network());
    (cfg.policy.min_capacity, cfg.policy.max_capacity, cfg.policy.min_expiry_blocks, cfg.policy.min_conf) = (10_000, 10_000, 1_008, 1);
    assert_eq!(cfg.billing, "postpay");
    let streams: Vec<StreamParts> = [("s1", [7u8; 32]), ("s2", [8u8; 32])].into_iter()
        .map(|(id, k)| { let (d, c0, c1) = stream_doc(id, k); (id.to_string(), d, c0, c1, k) }).collect();
    let served = streams.clone();
    let p = Provider::new(Arc::new(ProviderChain(rig.chain.clone())), secret("provider payTo"), cfg, Ledger::in_memory(), Box::new(|_, _| PRICE as u64),
                          Box::new(move |_, path, _| {
                              let json_ok = |v: &Value| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], v.to_string().into_bytes());
                              for (id, doc, c0, _, _) in &served {
                                  if path == format!("/{id}/doc") {
                                      return json_ok(doc);
                                  }
                                  if path == format!("/{id}/chunk/0") {
                                      return json_ok(c0);
                                  }
                              }
                              json_ok(&json!({"ok": true}))
                          })).unwrap();
    for (id, _, _, c1, k) in &streams {
        p.offer_conditional(&format!("/{id}/chunk/1"), PRICE as u64, c1, Some(*k));
    }
    rig.web.sites.lock().unwrap().insert(PROVIDER.into(), Arc::new(p));
}

fn stream_rig() -> (Rig, Arc<AtomicU8>) {
    let mut rig = Rig::new(json!({"max_per_tx_sats": 5000, "human_threshold_sats": 5000, "daily_budget_sats": 9000, "weekly_budget_sats": 9000}), false);
    stream_site(&rig);
    rig.fund_hot(1, 12_000);
    let mode = faulty(&mut rig);
    let call = |rig: &Rig| rig.call("xbt402_pay", json!({"url": ECHO, "method": "GET", "body": "", "max_sats": 2_000}));
    assert_eq!(call(&rig)["verdict"], "pending");
    rig.chain.mine(1);
    let r = call(&rig);
    assert_eq!((r["verdict"].as_str(), r["status"].as_i64(), r["charged_sats"].as_i64()), (Some("allow"), Some(200), Some(PRICE)), "{r}");
    (rig, mode)
}

fn buy(rig: &Rig, id: &str) -> Value {
    rig.call("xbt402_pay", json!({"url": format!("{PROVIDER}/{id}/doc"), "method": "GET", "body": "", "max_sats": 2_000}))
}

fn plain_call(rig: &Rig) -> Value {
    rig.call("xbt402_pay", json!({"url": ECHO, "method": "GET", "body": "", "max_sats": 2_000}))
}

/// The seller above is one a stream can be bought from: on a channel whose last state the seller
/// acked, the manifest, chunk 0 and the hash-locked last chunk are all delivered and paid, 600 sat
/// each, and the ledger holds exactly what was signed.
#[test]
fn control_a_first_stream_on_a_postpay_channel_is_delivered() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, _) = stream_rig();
    let r = buy(&rig, "s1");
    assert_eq!(r["stream"]["ok"], true, "{r}");
    assert_eq!((r["charged_sats"].as_i64(), r["booked_sats"].as_i64()), (Some(3 * PRICE), Some(3 * PRICE)), "{r}");
    let rec = rig.s.book.get(PROVIDER).unwrap();
    assert_eq!((rec.used_sats, ledger(&rig)), (4 * PRICE, 4 * PRICE));
}

/// AGP-095 found-not-fixed 3, run, and wider than it was written: no answer has to be lost. A
/// stream's last state is handed over through `/x402/verify`, which gives no receipt, so the
/// wallet holds it unacked (`session.rs:1018-1020`). The next call sends that state again
/// (`session.rs:737, 745-746`); a postpay seller serves it on credit, so the wallet is one call
/// behind from then on. A stream bought then has its manifest served on credit and its chunk 0
/// asked with the unchanged state (`session.rs:866-867`), which the seller refuses
/// (`insufficient_payment`: it is owed the manifest), and the stream path takes any chunk answer
/// but 200 for the end of the stream (`session.rs:870-871`). The rule: **a stream is delivered on
/// a channel that has room and budget for it.**
///
/// FAILS on 2e745f2: the second stream ends at chunk 0 with `HTTP 402`; the agent is told
/// `charged_sats: 600` for a manifest and gets no data, on every later stream of that channel.
///
/// AGP-107: open, not a limit. Nothing in this tree sells a stream, so it is Low today; the fix is
/// owed before stream buying is offered (`docs/LIMITS.md`, "Open items").
#[test]
#[ignore = "open: AGP-102 list 1 item 13"]
fn hole_a_second_stream_on_a_postpay_channel_is_delivered() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, _) = stream_rig();
    assert_eq!(buy(&rig, "s1")["stream"]["ok"], true);
    let before = ledger(&rig);
    let r = buy(&rig, "s2");
    println!("second stream: status {} charged_sats {} booked_sats {} stream {}; ledger {} -> {}", r["status"], r["charged_sats"], r["booked_sats"], r["stream"],
             before, ledger(&rig));
    assert_eq!(r["stream"]["ok"], true, "the second stream on the channel ended early: {} (the call was charged {} sat)", r["stream"], r["charged_sats"]);
}

/// The same after one lost answer and no stream before (AGP-095's own wording of the case): the
/// call after the lost one is served on credit, and the stream after that stops at chunk 0.
///
/// FAILS on 2e745f2: `chunk 0: HTTP 402`, 600 sat charged for the manifest.
///
/// AGP-107: open, as the test above.
#[test]
#[ignore = "open: AGP-102 list 1 item 13"]
fn hole_a_stream_is_delivered_on_a_postpay_channel_that_lost_one_answer() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, mode) = stream_rig();
    mode.store(1, Ordering::SeqCst);
    assert_eq!(plain_call(&rig)["verdict"], "deny", "served, and the answer lost");
    let r = plain_call(&rig);
    assert_eq!((r["status"].as_i64(), r["booked_sats"].as_i64()), (Some(200), Some(0)), "the state sent again, served on credit: {r}");
    let r = buy(&rig, "s1");
    println!("stream after one lost answer: status {} charged_sats {} booked_sats {} stream {}", r["status"], r["charged_sats"], r["booked_sats"], r["stream"]);
    assert_eq!(r["stream"]["ok"], true, "the stream ended early: {} (the call was charged {} sat)", r["stream"], r["charged_sats"]);
}

// =====================================================================================================
// 2. The resync (one new state after a naming 402): what its stated limit costs
// =====================================================================================================

fn priced_provider(rig: &Rig, billing: &str) {
    let mut cfg = ProviderConfig::new(&rig.chain.network());
    (cfg.policy.min_capacity, cfg.policy.max_capacity, cfg.policy.min_expiry_blocks, cfg.policy.min_conf) = (10_000, 10_000, 1_008, 1);
    cfg.billing = billing.into();
    let p = Provider::new(Arc::new(ProviderChain(rig.chain.clone())), secret("provider payTo"), cfg, Ledger::in_memory(),
                          Box::new(|_, path| if path.starts_with("/dear") { 900 } else { 500 }),
                          Box::new(|_, _, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], b"{\"ok\": true}".to_vec()))).unwrap();
    rig.web.sites.lock().unwrap().insert(PROVIDER.into(), Arc::new(p));
}

/// AGP-095 stated limit 1, measured for the reader of the public summary. The 402 that makes the
/// wallet sign is unsigned, and it need not come from someone in the middle: a seller that serves
/// nothing and answers every paid call with a 402 naming the state is signed one more price on
/// every call the agent makes. Before wave 5 the wallet sent the same state again for ever, so
/// such a seller held one price in all. The calls answer `verdict: allow`, `status: 402`,
/// `charged_sats: 0`; only `booked_sats` shows the coins. (The same rule was tried in the library
/// client by AGP-101 and left out because it breaks the review's M3,
/// `a_provider_that_refuses_every_call_cannot_claim_them`.)
#[test]
fn limit_a_seller_that_refuses_every_call_by_name_is_signed_one_price_per_call() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({"daily_budget_sats": 60000, "weekly_budget_sats": 60000}), false);
    priced_provider(&rig, "prepay");
    rig.fund_hot(1, 12_000);
    let mode = faulty(&mut rig);
    rig.open();
    let (signed0, ledger0) = (rig.s.book.get(PROVIDER).unwrap().used_sats, ledger(&rig));
    mode.store(3, Ordering::SeqCst);
    let mut seen = vec![];
    for _ in 0..6 {
        let r = rig.pay();
        seen.push((r["verdict"].as_str().unwrap_or("").to_string(), r["status"].as_i64().unwrap_or(0), r["charged_sats"].as_i64().unwrap_or(-1), r["booked_sats"].as_i64().unwrap_or(-1)));
    }
    let rec = rig.s.book.get(PROVIDER).unwrap();
    println!("six calls answered only by a naming 402: {seen:?}; signed {} -> {}, ledger {} -> {}", signed0, rec.used_sats, ledger0, ledger(&rig));
    assert!(seen.iter().all(|s| (s.0.as_str(), s.1, s.2) == ("allow", 402, 0) && s.3 > 0), "{seen:?}");
    // the first state stood at the dust floor (546 for a 500 sat call), so the first rise is 454
    assert_eq!((signed0, rec.used_sats), (546, 500 + 6 * 500), "one price per call, for no answer at all");
    assert_eq!(ledger(&rig), rec.used_sats, "every signed sat is booked");
}

/// Inside the same rule, with nobody lying. A 402 "naming the state" is true of every state the
/// seller has just been sent, whether or not it served the call that state was signed for. So when
/// a request is lost before the seller sees it and the next call costs more than the lost one, the
/// seller (prepay) answers the state sent again with the naming 402, the wallet signs the dearer
/// call on top of the lost one, and the seller ends up holding a state for a call it never served.
/// (With an equal or lower price the state sent again pays the call: AGP-095's control.)
#[test]
fn limit_a_request_the_seller_never_saw_is_paid_for_when_the_next_call_costs_more() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({"daily_budget_sats": 60000, "weekly_budget_sats": 60000}), false);
    priced_provider(&rig, "prepay");
    rig.fund_hot(1, 12_000);
    let mode = faulty(&mut rig);
    rig.open(); // one call of 500, charged 500
    mode.store(2, Ordering::SeqCst);
    assert_eq!(rig.pay()["verdict"], "deny", "the request never reached the seller");
    let r = rig.call("xbt402_pay", json!({"url": format!("{PROVIDER}/dear"), "method": "GET", "body": "", "max_sats": 900}));
    assert_eq!((r["status"].as_i64(), r["charged_sats"].as_i64(), r["booked_sats"].as_i64()), (Some(200), Some(900), Some(900)), "{r}");
    let rec = rig.s.book.get(PROVIDER).unwrap();
    let served = 500 + 900;
    println!("signed {} sat for {} sat of calls the seller served", rec.used_sats, served);
    assert_eq!(rec.used_sats - served, 500, "the seller holds a state 500 sat above what it served: the call it never saw");
    assert_eq!(ledger(&rig), rec.used_sats);
}

// =====================================================================================================
// 3. "A channel leaves the refund watch only when its funding is spent in a block": the attach path
// =====================================================================================================

fn roll_rig() -> (Rig, ChannelRecord, String) {
    let rig = Rig::new(json!({"max_per_tx_sats": 5000, "human_threshold_sats": 5000, "hot_balance_cap_sats": 100_000}), false);
    let mut cfg = ProviderConfig::new(&rig.chain.network());
    (cfg.policy.min_capacity, cfg.policy.max_capacity, cfg.policy.min_expiry_blocks, cfg.policy.min_conf) = (5_000, 10_000, 1_008, 1);
    cfg.billing = "prepay".into();
    let p = Provider::new(Arc::new(ProviderChain(rig.chain.clone())), secret("provider payTo"), cfg, Ledger::in_memory(), Box::new(|_, _| 600),
                          Box::new(|_, _, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], b"{\"ok\": true}".to_vec()))).unwrap();
    rig.web.sites.lock().unwrap().insert(PROVIDER.into(), Arc::new(p));
    rig.fund_hot(1, 12_000);
    assert_eq!(rig.call("xbt402_pay", json!({"url": URL, "max_sats": 1_000}))["verdict"], "pending");
    rig.chain.mine(1);
    assert_eq!(rig.call("xbt402_pay", json!({"url": URL, "max_sats": 1_000}))["verdict"], "allow");
    let rec = rig.s.book.get(PROVIDER).unwrap();
    let next_origin = format!("{}/next", rec.origin);
    (rig, rec, next_origin)
}

fn next_for(rig: &Rig, rec: &ChannelRecord, key: &str, blocks: u64) -> ChannelParams {
    let cur = rec.params().unwrap();
    ChannelParams::derive(&seller_pay_to(), &hex::decode(key).unwrap(), (rig.chain.height() + blocks) as u32, cur.close_fee,
                          Some(hex::decode(rig.hot_spk()).unwrap()), &rig.chain.network(), cur.close_fee_payer).unwrap()
}

/// The wallet signs a rollover into `next` and the seller broadcasts it (it is in the mempool).
fn broadcast_rollover(rig: &Rig, rec: &ChannelRecord, next: &ChannelParams) -> ChannelParams {
    let amount = rec.used_sats as u64;
    let cap = rec.params().unwrap().rollover_next_capacity(amount);
    let sig = rig.call("xbt402_sign_rollover", json!({"chan": rec.chan, "amount": amount, "next_spk": hex::encode(next.spk()), "next_capacity": cap, "next": next.to_json()}));
    assert!(sig["sig"].is_string(), "{sig}");
    let body = json!({"chan": rec.chan, "amount": amount, "sig": sig["sig"],
                      "next": {"payerPub": hex::encode(next.payer_pub), "expiry": next.expiry, "payerSpk": hex::encode(&next.payer_spk)}});
    let resp = rig.web.request("POST", &format!("{PROVIDER}{ROLLOVER_PATH}"), body.to_string().as_bytes(), &[("Content-Type".into(), "application/json".into())]).unwrap();
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    let reply: Value = serde_json::from_slice(&resp.body).unwrap();
    next.clone().with_funding(reply["txid"].as_str().unwrap(), 1, cap).unwrap()
}

/// AGP-095 stated limit 4, run, and worse than its sentence. Wave 5's rule is "a channel leaves
/// the refund watch only when our node shows its funding spent in a block" (`session.rs:389-392`).
/// `xbt402_attach` of a rollover's next channel still takes a spend that is only in the mempool
/// (`signer.rs:1682-1684`), marks the rolled channel closed with `close_unproven` false
/// (`signer.rs:1653`, `close_by_chain`) and archives it (`channels.rs:835`). If that rollover then
/// leaves the mempool unmined, the rolled channel's funding is unspent, in no live record, and the
/// watcher never refunds it. "Its refund is manual" (the README) is also too kind: `xbt402_refund`
/// and `xbt402_sign_refund` look only at live records, so no signer method reaches it.
///
/// On 2e745f2: at the rolled channel's expiry the watcher refunds nothing and the whole funding
/// (10,000 sat here) is still in the channel's script.
///
/// LIMIT (AGP-107; the fourth audit's list 1 item 12, first bullet, "write down"). The audit wrote
/// this test as `hole_..._is_still_refunded_at_its_expiry`; nothing in fix wave 6 changed the
/// attach path, so it is kept as the statement of the limit and its last assertions are turned
/// round. The sentence it pins (`docs/LIMITS.md`, agent wallet): "If a rollover the wallet
/// attached from the mempool is never mined, the channel it would have spent is no longer watched
/// and no wallet method refunds it; its key is kept, and the owner must restore the record by
/// hand. No new channel to that seller can be opened meanwhile." It passes while that holds and
/// fails when the attach waits for a block or the watcher refunds an archived channel: then
/// restore the audit's assertion (a `refund` action for the rolled channel) and drop the sentence.
#[test]
fn limit_a_channel_rolled_by_a_rollover_that_was_only_in_the_mempool_is_not_refunded_by_the_wallet_at_its_expiry() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, rec, next_origin) = roll_rig();
    let k1 = rig.call("xbt402_new_key", json!({"origin": next_origin.clone()}))["pub"].as_str().unwrap().to_string();
    let funded = broadcast_rollover(&rig, &rec, &next_for(&rig, &rec, &k1, 1_100));
    let a = rig.call("xbt402_attach", json!({"origin": next_origin, "params": funded.to_json()}));
    assert_eq!(a["chan"], funded.channel_id(), "the attach of a rollover in the mempool is accepted (the stated limit): {a}");
    // the rollover is never mined and leaves the mempool
    rig.chain.evict(&funded.funding_txid());
    let old_spk = hex::encode(rec.params().unwrap().spk());
    assert_eq!(rig.chain.unspent_to(&old_spk), rec.funding_sats, "the rolled channel's funding is unspent again");
    rig.chain.mine_to(rec.expiry as u64 + 1);
    let acts = rig.s.watch_tick();
    let manual = rig.call("xbt402_refund", json!({"chan": rec.chan}));
    println!("at the rolled channel's expiry: watcher {acts:?}; xbt402_refund by its id: {manual}; still in its script: {} sat", rig.chain.unspent_to(&old_spk));
    // measured beside it: the record at the origin is now the next channel, whose funding never
    // existed. Past its own expiry it is still "open", so the seller gets no new channel either.
    rig.chain.mine_to(funded.expiry as u64 + 1);
    let later = rig.s.watch_tick();
    let pay = rig.call("xbt402_pay", json!({"url": URL, "max_sats": 1_000}));
    let live = rig.s.book.get(PROVIDER).unwrap();
    println!("past the next channel's expiry: watcher {later:?}; record {} is {}; xbt402_pay answers {} / {}", live.chan, live.state, pay["verdict"], pay["rule"]);
    assert!(!acts.iter().chain(later.iter()).any(|x| x["rule"] == "refund" && x["chan"] == rec.chan.as_str()),
            "the limit is lifted: the watcher refunds the rolled channel now ({acts:?}, {later:?})");
    assert_eq!((manual["verdict"].as_str(), manual["rule"].as_str()), (Some("deny"), Some("unknown_channel")), "no wallet method reaches it by its id: {manual}");
    assert_eq!(rig.chain.unspent_to(&old_spk), rec.funding_sats, "the whole funding is in the rolled channel's script past its expiry");
    assert_eq!((live.chan.as_str(), live.state.as_str(), pay["verdict"].as_str()), (funded.channel_id().as_str(), "open", Some("deny")),
               "the record at the origin is the next channel, whose funding never existed, and the seller gets no new channel: {pay}");
}

/// The neighbour of the audit's item 15 (the next channel of a rollover the seller broadcast after
/// refusing it). The watcher adopts it from the record that signed the rollover, and looks only at
/// live records (`channels.rs:1144-1146`, `signer.rs:949`). When that record is closed by the
/// chain (`xbt402_mark_closed`) and a new channel to the seller is funded before the next tick,
/// the record is archived with its `rolled_next`, and the next channel is never adopted or
/// refunded. The rule (AGP-095's): **a channel this signer's signature funded gets a record, and
/// the refund at its expiry, whoever broadcast the transaction.**
///
/// On 2e745f2: the next channel's coins are in its script past its expiry. Low: the window is one
/// watcher interval (10 s) after the rollover's block, and the key is kept.
///
/// LIMIT (AGP-107; the fourth audit's list 1 item 12, second bullet, "write down"). Written by the
/// audit as `hole_..._is_refunded_when_...`; kept as the statement of the limit with its last
/// assertion turned round. The sentence it pins (`docs/LIMITS.md`, agent wallet): "The next
/// channel of a rollover the seller broadcast after refusing it is refunded by the watcher only
/// while the rolled channel is still the wallet's record for that seller; if the rolled channel
/// was marked closed and a new one funded first, the next channel's coins stay in its script past
/// its expiry, with its key kept." It fails when the watcher adopts a next channel from an
/// archived record: then restore the audit's assertion (0 sat left) and drop the sentence.
#[test]
fn limit_the_next_channel_of_a_rollover_is_not_refunded_when_a_new_channel_replaced_the_rolled_one_first() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, rec, next_origin) = roll_rig();
    let k1 = rig.call("xbt402_new_key", json!({"origin": next_origin.clone()}))["pub"].as_str().unwrap().to_string();
    // the seller answers the rollover with an error and broadcasts it all the same; it is mined
    let funded = broadcast_rollover(&rig, &rec, &next_for(&rig, &rec, &k1, 1_014));
    rig.chain.mine(1);
    // before the watcher's next tick: the payer, told its channel is gone, marks it closed and pays again
    let m = rig.call("xbt402_mark_closed", json!({"chan": rec.chan}));
    assert_eq!(m["state"], "closed", "{m}");
    rig.fund_hot(2, 12_000);
    let r = rig.call("xbt402_pay", json!({"url": URL, "max_sats": 1_000}));
    assert_eq!(r["verdict"], "pending", "a new channel to the seller is funded: {r}");
    let next_spk = hex::encode(funded.spk());
    let mut all = rig.s.watch_tick();
    let late = rig.call("xbt402_attach", json!({"origin": next_origin, "params": funded.to_json()}));
    rig.chain.mine_to(funded.expiry as u64 + 1);
    all.extend(rig.s.watch_tick());
    println!("attach of the next channel while the new one is live: {late}; in the next channel's script past its expiry: {} sat", rig.chain.unspent_to(&next_spk));
    assert_eq!((late["verdict"].as_str(), late["rule"].as_str()), (Some("deny"), Some("channel_pending")), "the attach is refused and the key kept: {late}");
    assert_eq!(rig.chain.unspent_to(&next_spk), funded.capacity as i64,
               "the limit is lifted or moved: {} of the next channel's {} sat are in its script past its expiry (watcher {all:?})",
               rig.chain.unspent_to(&next_spk), funded.capacity);
}

// =====================================================================================================
// 4. The signer socket: `xbt402_funded`, attach answered again, two callers on one channel
// =====================================================================================================

/// What a second socket caller can do with a channel another caller's `fund` made. It can learn
/// it (`xbt402_funded`), attach it (the first caller's attach is then answered again), and ask
/// for states. It cannot take anything: every state pays the seller the policy named, a state is
/// never lowered, the same amount is the same signature and is booked once, and each increase
/// passes the policy whoever asks (per-tx limit, budgets, the channel's capacity).
#[test]
fn control_two_callers_on_one_funded_channel_sign_one_rising_state_booked_once_under_the_policy() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"hot_balance_cap_sats": 0}), false);
    rig.fund_hot(1, 30_000);
    let key = rig.call("xbt402_new_key", json!({"origin": PROVIDER}))["pub"].as_str().unwrap().to_string();
    assert_eq!(rig.call("xbt402_new_key", json!({"origin": PROVIDER}))["pub"], key.as_str(), "a second caller is given the same key");
    let p = ChannelParams::derive(&seller_pay_to(), &hex::decode(&key).unwrap(), (rig.chain.height() + 1_153) as u32, 600,
                                  Some(hex::decode(rig.hot_spk()).unwrap()), &rig.chain.network(), FeePayer::Payer).unwrap();
    let f = rig.call("fund", json!({"origin": PROVIDER, "params": p.to_json(), "sats": 10_000}));
    assert!(f["txid"].is_string(), "{f}");
    // caller B knows nothing but the origin
    let learned = rig.call("xbt402_funded", json!({"origin": PROVIDER}));
    let params = learned["funded"]["params"].clone();
    assert!(params.is_object(), "{learned}");
    assert!(!learned.to_string().contains("secret") && learned["funded"].as_object().unwrap().len() == 3, "origin, chan, params and no key: {learned}");
    let b = rig.call("xbt402_attach", json!({"origin": PROVIDER, "params": params}));
    let a = rig.call("xbt402_attach", json!({"origin": PROVIDER, "params": params}));
    assert_eq!((b["chan"].as_str(), a["chan"].as_str()), (f["chan"].as_str(), f["chan"].as_str()), "both are answered the one channel: {a} {b}");
    assert_eq!(rig.call("xbt402_funded", json!({"origin": PROVIDER})), json!({"funded": null}), "attached: no longer answered");
    let chan = f["chan"].as_str().unwrap();
    let sign = |cum: i64| rig.call("xbt402_sign_state", json!({"chan": chan, "cum": cum}));
    let (s1, s2) = (sign(600), sign(600));
    assert!(s1["sig"].is_string() && s1["sig"] == s2["sig"], "the same amount is the same signature: {s1} {s2}");
    assert_eq!(ledger(&rig), 600, "booked once");
    assert_eq!(sign(500)["verdict"], "deny", "never a lower state");
    assert!(sign(1_200)["sig"].is_string());
    assert_eq!(sign(2_201)["rule"], "max_per_tx", "an increase above the per-payment limit (1,000) is refused whoever asks");
    for cum in [2_000, 2_900, 3_800, 4_700, 5_600] {
        assert!(sign(cum)["sig"].is_string(), "{cum}");
    }
    let over = sign(6_400);
    assert_eq!(over["rule"], "daily_budget", "the budget (6,000) holds across both callers: {over}");
    assert_eq!((ledger(&rig), rig.s.book.get(PROVIDER).unwrap().used_sats), (5_600, 5_600));
}

/// The expiry floor at the shipped numbers: the provider's floor is 1,008 + 1 + 144 = 1,153
/// blocks, the policy's default `channel_expiry_blocks` is 1,008, and the channel is funded for
/// 1,153 (`session.rs:311-329`): the floor refuses nothing an honest seller offers.
#[test]
fn control_at_the_shipped_terms_the_pay_rail_funds_a_channel_of_the_offers_floor() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    let r = rig.pay();
    assert_eq!(r["verdict"], "pending", "{r}");
    assert_eq!(rig.s.book.get(PROVIDER).unwrap().expiry - rig.chain.height() as i64, 1_153);
}

// =====================================================================================================
// 5. The human-signature clock
// =====================================================================================================

const MIKE: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/// AGP-095 lists this in its table and not among its limits. `clock` in `human_sigs.json` is the
/// highest host time at which a human signature was used (`admin.rs:90, 96`). One use while the
/// host clock is far ahead (a wrong RTC before NTP corrects it), with a signature whose expiry
/// reaches that far, stores that time. After the clock is right again every human-signed method
/// answers `expired` for any signature that expires before the stored time: the sweep, and
/// `policy_set`, whose expiry the signer itself sets ten minutes ahead (`admin.rs:328`). Nothing
/// on the socket moves `clock` back; the owner must edit or delete the file, and deleting it
/// forgets every used signature. Only the human's own signature writes it: an invalid, expired or
/// replayed one returns before the write (`admin.rs:218-223, 87-93`).
#[test]
fn limit_one_human_signed_use_under_a_host_clock_far_ahead_refuses_the_owners_signatures_afterwards() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({}), false);
    let now = xbt_signer::pyjson::now_f64() as i64;
    let t = Arc::new(AtomicI64::new(now));
    let tc = t.clone();
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(rig.chain.clone()), transport: Some(rig.web.clone()),
                                                   clock: Some(Arc::new(move || tc.load(Ordering::SeqCst) as f64)), ..Default::default() }).unwrap();
    for tag in 1..=3 {
        rig.fund_hot(tag, 5_000);
    }
    let hot = rig.call("hot_address", json!({}))["hot_address"].as_str().unwrap().to_string();
    let sweep = |exp: i64, sig_exp: i64| json!({"to": MIKE, "amount_sats": 2_000, "expiry": exp, "signature": sign_human(&xbt_signer::approval::sweep_message(&hot, MIKE, 2_000, sig_exp))});
    let file = rig.root.join(".run").join("human_sigs.json");
    let clock = || std::fs::read_to_string(&file).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()).and_then(|v| v["clock"].as_i64());
    // nothing but a valid, unused, unexpired human signature writes the clock
    let far = now + 10 * 365 * 86_400;
    t.store(far, Ordering::SeqCst);
    assert_ne!(rig.call("sweep_hot", sweep(far + 60, far + 61))["ok"], true, "a signature that does not verify");
    assert_ne!(rig.call("sweep_hot", sweep(far - 60, far - 60))["ok"], true, "an expired one");
    assert_eq!(clock(), None, "neither wrote the file");
    // one use while the host clock is ten years ahead
    assert_eq!(rig.call("sweep_hot", sweep(far + 60, far + 60))["ok"], true);
    assert_eq!(clock(), Some(far));
    assert_eq!(rig.call("sweep_hot", sweep(far + 60, far + 60))["rule"], "human_sig_replay");
    assert_eq!(clock(), Some(far), "a replay does not move it");
    // the host clock is right again
    t.store(now, Ordering::SeqCst);
    let s = rig.call("sweep_hot", sweep(now + 3_600, now + 3_600));
    assert_eq!((s["ok"].as_bool(), s["rule"].as_str()), (Some(false), Some("expired")), "an hour-long sweep signature: {s}");
    let policy: Value = serde_json::from_str(&std::fs::read_to_string(rig.root.join("policy.json")).unwrap()).unwrap();
    let prep = rig.call("policy_prepare", json!({"policy": policy}));
    assert_eq!(prep["expiry"].as_i64(), Some(now + 600), "{prep}");
    let set = rig.call("policy_set", json!({"text": prep["text"], "prev_sha256": prep["prev_sha256"], "expiry": prep["expiry"],
                                            "signature": sign_human(&hex::decode(prep["message_hex"].as_str().unwrap()).unwrap())}));
    assert_eq!(set["rule"], "expired", "the policy change the signer itself prepared: {set}");
    println!("clock stored {far}, host time {now}: sweep {s}; policy_set {set}");
    assert_eq!(clock(), Some(far), "and nothing on the socket moves it back");
}
