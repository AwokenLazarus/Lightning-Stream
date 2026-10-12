//! AGP-089 (fix wave 4, wallet): the paths beside the ones the AGP-087 audit tests name. Each test
//! states the rule its fix keeps; the ones marked "fails on 5521674" failed there for that reason.
mod common;

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use common::*;
use serde_json::{json, Value};
use xbt402::channel::ChannelParams;
use xbt402::client::Transport;
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::wire::{b64json, unb64json, OPEN_PATH, ROLLOVER_PATH};
use xbt_primitives::ecdsa;
use xbt_signer::approval::{backup_message, canonical_message, sweep_message};
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

fn now() -> i64 {
    xbt_signer::pyjson::now_f64() as i64
}

const MIKE: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

// --- item 16: one human signature, one operation ----------------------------------------------------------

/// Rule: one signed message authorises one operation, once. Fails on 5521674: the second and
/// third `sweep_hot` with the same signature sweep again (the message has an expiry and no nonce).
#[test]
fn one_sweep_signature_sweeps_once_and_a_restart_does_not_forget_it() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 5_000);
    rig.fund_hot(2, 5_000);
    let hot = rig.call("hot_address", json!({}))["hot_address"].as_str().unwrap().to_string();
    let exp = now() + 300;
    let req = json!({"to": MIKE, "amount_sats": 2_000, "expiry": exp, "signature": sign_human(&sweep_message(&hot, MIKE, 2_000, exp))});
    let first = rig.call("sweep_hot", req.clone());
    assert_eq!(first["ok"], true, "{first}");
    let again = rig.call("sweep_hot", req.clone());
    assert_eq!((again["ok"].as_bool(), again["rule"].as_str()), (Some(false), Some("human_sig_replay")), "{again}");
    rig.restart().unwrap();
    let after = rig.call("sweep_hot", req);
    assert_eq!((after["ok"].as_bool(), after["rule"].as_str()), (Some(false), Some("human_sig_replay")), "a restart forgot the used signature: {after}");
    assert_eq!(rig.chain.unspent_to(&hex::encode(xbt_signer::signer::address_to_spk(MIKE, "bcrt").unwrap())), 2_000, "swept once");
    // the human signs again (another expiry): that is a new operation
    let exp2 = exp + 1;
    let r = rig.call("sweep_hot", json!({"to": MIKE, "amount_sats": 2_000, "expiry": exp2, "signature": sign_human(&sweep_message(&hot, MIKE, 2_000, exp2))}));
    assert_eq!(r["ok"], true, "{r}");
}

/// A used-signature file that cannot be read refuses the operation; it is never taken for empty.
#[test]
fn an_unreadable_used_signature_file_refuses_the_operation() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 5_000);
    std::fs::write(rig.root.join(".run").join(xbt_signer::admin::USED_SIGS_FILE), "{ not json").unwrap();
    let hot = rig.call("hot_address", json!({}))["hot_address"].as_str().unwrap().to_string();
    let exp = now() + 300;
    let r = rig.call("sweep_hot", json!({"to": MIKE, "amount_sats": 2_000, "expiry": exp, "signature": sign_human(&sweep_message(&hot, MIKE, 2_000, exp))}));
    assert_eq!(r["ok"], false, "{r}");
    assert!(rig.chain.mempool().is_empty(), "nothing was swept");
}

/// Fails on 5521674: the same `backup_export` signature exports again, under any passphrase the
/// caller names (the signature does not bind it). Now the second export is refused. A request the
/// signer refuses for its passphrase does not cost the signature.
#[test]
fn one_backup_signature_exports_once() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    env_for(dir.path());
    let chain = FakeChain::new("regtest", 6_720);
    let web = Arc::new(Web::default());
    let root = root_with(dir.path(), &runbook_policy(json!({})));
    let ks = Arc::new(xbt_signer::keystore::KeyStore::with_passphrase(b"a wrapping passphrase"));
    let s = Signer::new(&root, SignerOptions { node: Some(chain), transport: Some(web), keystore: Some(ks), ..Default::default() }).unwrap();
    let hot = call(&s, "hot_address", json!({}))["hot_address"].as_str().unwrap().to_string();
    let exp = now() + 300;
    let sig = sign_human(&backup_message(&hot, exp));
    let short = call(&s, "backup_export", json!({"expiry": exp, "signature": sig, "backup_pass": "short"}));
    assert_eq!(short["rule"], "backup_pass", "{short}");
    let first = call(&s, "backup_export", json!({"expiry": exp, "signature": sig, "backup_pass": "the human's passphrase"}));
    assert_eq!(first["ok"], true, "{}", first.to_string().chars().take(200).collect::<String>());
    let replay = call(&s, "backup_export", json!({"expiry": exp, "signature": sig, "backup_pass": "the relaying process's own"}));
    assert_eq!(replay["rule"], "human_sig_replay", "a second export under another passphrase: {}", replay.to_string().chars().take(200).collect::<String>());
}

// --- item 8: a grant is held while its call runs -----------------------------------------------------------

/// Rule: one approval pays once. An xbt402 grant is `used` on disk before its call signs, and is
/// spent by any call that signed, whatever the call then answers. Fails on 5521674: a call that
/// signed and was then refused left the grant, so the same approval covered a second signing call.
#[test]
fn a_grant_whose_call_signed_is_spent_and_one_that_signed_nothing_is_kept() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({"max_per_tx_sats": 5000, "human_threshold_sats": 1000}), false);
    rig.fund_hot(1, 12_000);
    let strip = Arc::new(AtomicU8::new(0));
    let (web, st) = (rig.web.clone(), strip.clone());
    hooked(&mut rig, Box::new(move |method, url, body, headers| {
        if st.load(Ordering::SeqCst) == 1 && paid(headers) {
            let mut r = web.request(method, url, body, headers).unwrap();
            r.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("PAYMENT-RESPONSE"));
            return Some(Ok(r));
        }
        None
    }));
    let ask = json!({"url": URL, "method": "GET", "body": "", "max_sats": 1_000});
    let r = rig.call("xbt402_pay", ask.clone());
    assert_eq!(r["verdict"], "needs_human", "{r}");
    let (tok, exp) = (r["approval_token"].as_str().unwrap().to_string(), r["approval_expires"].as_i64().unwrap());
    let g = rig.call("approve", json!({"token": tok, "dest": PROVIDER, "amount_sats": 1000, "expiry": exp,
                                       "signature": sign_human(&canonical_message(&tok, PROVIDER, 1000, exp))}));
    assert_eq!(g["granted"], true, "{g}");
    // the first call under the grant funds the channel and signs nothing: the grant is kept
    let r = rig.call("xbt402_pay", ask.clone());
    assert_eq!(r["verdict"], "pending", "{r}");
    assert_eq!(rig.call("approval_status", json!({"token": tok}))["state"], "approved", "a call that signed nothing must not cost the approval");
    rig.chain.mine(1);
    // the second signs a state, and the answer comes back without its receipt: refused, and the grant is spent
    strip.store(1, Ordering::SeqCst);
    let r = rig.call("xbt402_pay", ask.clone());
    assert_eq!((r["verdict"].as_str(), r["rule"].as_str()), (Some("deny"), Some("bad_receipt")), "{r}");
    let signed = ledger(&rig);
    assert!(signed > 0, "the state was signed and booked");
    assert_eq!(rig.call("approval_status", json!({"token": tok}))["state"], "used", "the approval covered a call that signed");
    strip.store(0, Ordering::SeqCst);
    let r = rig.call("xbt402_pay", ask);
    assert_eq!(r["verdict"], "needs_human", "one approval, one signing call: {r}");
    assert_eq!(ledger(&rig), signed);
}

// --- item 9: an answer is acked only by the payee's signature over this request ---------------------------

/// Rule: a state counts as arrived only on a receipt the payee signed for this request's seq.
/// Fails on 5521674: any PAYMENT-RESPONSE header acked the state, so an error answer carrying an
/// earlier receipt made the next call sign a higher state instead of sending the same one again.
#[test]
fn an_error_answer_with_an_earlier_receipt_does_not_ack_the_state() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    let mode = Arc::new(AtomicU8::new(0));
    let last = Arc::new(std::sync::Mutex::new(None::<String>));
    let (web, m, l) = (rig.web.clone(), mode.clone(), last.clone());
    hooked(&mut rig, Box::new(move |method, url, body, headers| {
        if !paid(headers) {
            return None;
        }
        if m.load(Ordering::SeqCst) == 1 {
            // the paid request never reaches the seller; an error comes back with the receipt before
            let old = l.lock().unwrap().clone().unwrap();
            return Some(Ok(HttpResponse::new(503, vec![("PAYMENT-RESPONSE".into(), old)], b"busy".to_vec())));
        }
        let r = web.request(method, url, body, headers).unwrap();
        *l.lock().unwrap() = r.header("PAYMENT-RESPONSE").map(str::to_string);
        Some(Ok(r))
    }));
    let first = rig.open();
    let cum0 = first["cum"].as_i64().unwrap();
    mode.store(1, Ordering::SeqCst);
    let a = rig.pay();
    let b = rig.pay();
    assert_eq!((a["status"].as_i64(), b["status"].as_i64()), (Some(503), Some(503)), "{a} {b}");
    assert!(a["receipt_error"].is_string(), "the replayed receipt is reported: {a}");
    assert_eq!(a["cum"], b["cum"], "the unacked state is sent again, not replaced by a higher one: {a} {b}");
    assert!(a["cum"].as_i64().unwrap() > cum0);
    assert_eq!(ledger(&rig), a["cum"].as_i64().unwrap(), "one state signed and booked for the two failed calls");
}

// --- items 3 and 5: the seller's other numbers ---------------------------------------------------------------

/// The offer's `closeFeeSat`, `minConf` and `closeMarginBlocks` are the seller's numbers too. With
/// `close_fee_max_sats: 0` nothing else bounds the fee: a fee that does not fit an amount is
/// refused before funding (5521674 added it to the cap unchecked). A `minConf` or margin that
/// would lock the channel past the owner's bound is refused as `minExpiryBlocks` is.
#[test]
fn an_offer_whose_numbers_do_not_fit_is_refused_before_funding() {
    for (key, value, rule) in [("closeFeeSat", json!(i64::MAX), "xbt402"), ("closeFeeSat", json!(-600), "xbt402"), ("minConf", json!(400_000), "expiry"),
                               ("closeMarginBlocks", json!(i64::MAX), "expiry"), ("minExpiryBlocks", json!(4_100), "expiry")] {
        let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
        let mut rig = Rig::new(json!({"close_fee_max_sats": 0}), false);
        rig.fund_hot(1, 12_000);
        let (web, v) = (rig.web.clone(), value.clone());
        hooked(&mut rig, Box::new(move |method, url, body, headers| {
            if url == URL && !paid(headers) {
                let r = web.request(method, url, body, headers).unwrap();
                let mut pr = unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap();
                pr["accepts"][0]["extra"][key] = v.clone();
                pr["accepts"][0]["extra"]["maxExpiryBlocks"] = i64::MAX.into();
                pr["accepts"][0]["extra"]["maxCapacity"] = i64::MAX.into();
                return Some(Ok(HttpResponse::new(402, vec![("PAYMENT-REQUIRED".into(), b64json(&pr))], b"".to_vec())));
            }
            if url.ends_with(OPEN_PATH) && String::from_utf8_lossy(body).contains("\"preflight\"") {
                return Some(Ok(HttpResponse::new(200, vec![], json!({"preflight": true}).to_string().into_bytes())));
            }
            None
        }));
        let before = rig.hot_sats();
        let s = rig.s.clone();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || s.handle("xbt402_pay", &json!({"url": URL, "max_sats": 500}))));
        let r = r.unwrap_or_else(|_| panic!("{key} = {value}: the signer panicked")).unwrap();
        assert_eq!((r["verdict"].as_str(), r["rule"].as_str()), (Some("deny"), Some(rule)), "{key} = {value}: {r}");
        assert!(rig.s.book.get(PROVIDER).is_none() && rig.hot_sats() == before, "{key} = {value}: nothing is funded");
    }
}

// --- item 6: issued keys ------------------------------------------------------------------------------------

fn seller_pay_to() -> Vec<u8> {
    ecdsa::pubkey(&secret("provider payTo")).to_vec()
}

/// Rule: a key this signer issued is never replaced or dropped. Asking again answers the same
/// key; a channel's rollover signatures may pay at most `MAX_ROLLED_NEXT` different next channels
/// while none is attached; the attach can be asked again; and the next rollover gets its own key.
/// Fails on 5521674 at the first assertion (a second `xbt402_new_key` replaced the key).
#[test]
fn an_issued_key_is_kept_until_its_channel_is_attached() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"max_per_tx_sats": 5000, "human_threshold_sats": 5000}), false);
    // a provider whose minimum capacity leaves room for a rollover's next channel
    let mut cfg = ProviderConfig::new(&rig.chain.network());
    (cfg.policy.min_capacity, cfg.policy.max_capacity, cfg.policy.min_expiry_blocks, cfg.policy.min_conf) = (5_000, 10_000, 1_008, 1);
    let p = Provider::new(Arc::new(ProviderChain(rig.chain.clone())), secret("provider payTo"), cfg, Ledger::in_memory(), Box::new(|_, _| 600),
                          Box::new(|_, _, _| HttpResponse::new(200, vec![], b"{}".to_vec()))).unwrap();
    rig.web.sites.lock().unwrap().insert(PROVIDER.into(), Arc::new(p));
    rig.fund_hot(1, 12_000);
    assert_eq!(rig.call("xbt402_pay", json!({"url": URL, "max_sats": 1_000}))["verdict"], "pending");
    rig.chain.mine(1);
    assert_eq!(rig.call("xbt402_pay", json!({"url": URL, "max_sats": 1_000}))["verdict"], "allow");
    let rec = rig.s.book.get(PROVIDER).unwrap();
    let cur = rec.params().unwrap();
    let next_origin = format!("{}/next", rec.origin);
    let key = |rig: &Rig| rig.call("xbt402_new_key", json!({"origin": next_origin}))["pub"].as_str().unwrap().to_string();
    let k1 = key(&rig);
    assert_eq!(key(&rig), k1, "asking again must answer the key already issued");
    let amount = rec.used_sats as u64;
    let next_cap = cur.rollover_next_capacity(amount);
    let next_at = |blocks: u64| ChannelParams::derive(&seller_pay_to(), &hex::decode(&k1).unwrap(), (rig.chain.height() + blocks) as u32, cur.close_fee,
                                                      Some(hex::decode(rig.hot_spk()).unwrap()), &rig.chain.network(), cur.close_fee_payer).unwrap();
    let sign = |next: &ChannelParams| rig.call("xbt402_sign_rollover", json!({"chan": rec.chan, "amount": amount, "next_spk": hex::encode(next.spk()),
                                                                              "next_capacity": next_cap, "next": next.to_json()}));
    let nexts: Vec<ChannelParams> = (0..xbt_signer::channels::MAX_ROLLED_NEXT as u64).map(|i| next_at(1_014 + i)).collect();
    let sigs: Vec<Value> = nexts.iter().map(&sign).collect();
    assert!(sigs.iter().all(|s| s["sig"].is_string()), "{sigs:?}");
    assert!(sign(&nexts[0])["sig"].is_string(), "a retry into the same next channel is not one more");
    let ninth = sign(&next_at(2_000));
    assert_eq!(ninth["rule"], "rollover_pending", "{ninth}");
    // the provider broadcasts the fifth; that one is attached, twice
    let (next, sig) = (&nexts[4], &sigs[4]);
    let body = json!({"chan": rec.chan, "amount": amount, "sig": sig["sig"],
                      "next": {"payerPub": hex::encode(next.payer_pub), "expiry": next.expiry, "payerSpk": hex::encode(&next.payer_spk)}});
    let resp = rig.web.request("POST", &format!("{PROVIDER}{ROLLOVER_PATH}"), body.to_string().as_bytes(), &[("Content-Type".into(), "application/json".into())]).unwrap();
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    let reply: Value = serde_json::from_slice(&resp.body).unwrap();
    let real = next.clone().with_funding(reply["txid"].as_str().unwrap(), 1, next_cap).unwrap();
    for _ in 0..2 {
        let a = rig.call("xbt402_attach", json!({"origin": next_origin, "params": real.to_json()}));
        assert_eq!(a["chan"], real.channel_id(), "{a}");
    }
    assert!(rig.call("xbt402_sign_refund", json!({"chan": real.channel_id()}))["hex"].is_string());
    assert_ne!(key(&rig), k1, "the next rollover gets a key of its own");
}

// --- item 19: a kept funding nothing proves dead stays ------------------------------------------------------

/// The other half of the dead-funding rule: a kept funding the node does not show stays pending
/// (and its key stays) while nothing proves it can never confirm: here its inputs are unspent.
#[test]
fn a_kept_funding_with_unspent_inputs_stays_pending_past_expiry() {
    struct Silent(Arc<FakeChain>, AtomicU8);
    impl xbt_signer::node::Node for Silent {
        fn call(&self, method: &str, p: Value) -> xbt402::Result<Value> {
            let timeout = || Err(xbt402::ChannelError::new("rpc_error", "timed out reading response"));
            match (method, self.1.load(Ordering::SeqCst)) {
                ("sendrawtransaction", 0) => {
                    self.1.store(1, Ordering::SeqCst);
                    timeout()
                }
                ("gettxout", 1) => {
                    self.1.store(2, Ordering::SeqCst);
                    timeout()
                }
                ("sendrawtransaction", _) => Err(xbt402::ChannelError::new("rpc_refused", r#"{"code":-26,"message":"min relay fee not met"}"#)),
                _ => self.0.call(method, p),
            }
        }
        fn set_allow_generate(&self, allow: bool) {
            self.0.set_allow_generate(allow);
        }
        fn wallet(&self) -> String {
            self.0.wallet()
        }
    }
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    let node = Arc::new(Silent(rig.chain.clone(), AtomicU8::new(0)));
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(node), transport: Some(rig.web.clone()), ..Default::default() }).unwrap();
    assert_eq!(rig.pay()["verdict"], "deny");
    let rec = rig.s.book.get(PROVIDER).unwrap();
    rig.chain.mine_to(rec.expiry as u64 + 1);
    let acts = rig.s.watch_tick();
    assert_eq!(rig.s.book.get(PROVIDER).map(|r| r.state).as_deref(), Some("pending"), "{acts:?}");
    assert!(acts.iter().any(|a| a["rule"] == "funding_unknown"), "{acts:?}");
}
