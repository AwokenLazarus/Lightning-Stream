//! AGP-085: a channel funding forgets its pending record (the payer key, the refund terms) only
//! when the node itself refused the transaction. When the send and the lookup after it both fail,
//! the node may have taken the funding: the record stays, the watcher sends the transaction again
//! and the channel is refunded at expiry like any other. The three funding paths: the signer's own
//! session (`xbt402_pay`), the socket's `open_channel` and an external client's `fund`.
mod common;

use std::sync::{Arc, Mutex};

use common::*;
use serde_json::{json, Value};
use xbt402::channel::{ChannelParams, FeePayer};
use xbt_primitives::ecdsa;
use xbt_signer::node::Node;
use xbt_signer::signer::{Signer, SignerOptions};

/// The rig's node with a wallet that answers `sendtoaddress` (`pay_refuse`: its own JSON-RPC error;
/// `pay_lost`: no answer) and a fault on the funding broadcast: `refuse` (the node's own JSON-RPC error,
/// nothing taken), `lost` (the node takes the transaction; the answer and the lookup after it time
/// out) or `never` (the request never arrives; the lookup times out too).
struct FundNode {
    chain: Arc<FakeChain>,
    mode: Mutex<&'static str>,
}

impl Node for FundNode {
    fn call(&self, method: &str, p: Value) -> xbt402::Result<Value> {
        let mode = *self.mode.lock().unwrap();
        let timeout = || Err(xbt402::ChannelError::new("rpc_error", "timed out reading response"));
        match (method, mode) {
            ("sendrawtransaction", "refuse") | ("sendrawtransaction", "refuse_deaf") => Err(xbt402::ChannelError::new("rpc_refused", r#"{"code":-26,"message":"min relay fee not met"}"#)),
            ("sendrawtransaction", "lost") => {
                self.chain.call(method, p)?;
                timeout()
            }
            ("sendrawtransaction", "never") | ("gettxout", "lost") | ("gettxout", "never") | ("gettxout", "refuse_deaf") | ("sendtoaddress", "pay_lost") => timeout(),
            ("sendtoaddress", "pay_refuse") => Err(xbt402::ChannelError::new("rpc_refused", r#"{"code":-6,"message":"Insufficient funds"}"#)),
            ("sendtoaddress", _) => Ok(json!("5a".repeat(32))),
            _ => self.chain.call(method, p),
        }
    }
    fn set_allow_generate(&self, allow: bool) {
        self.chain.set_allow_generate(allow);
    }
    fn wallet(&self) -> String {
        self.chain.wallet()
    }
}

const PATHS: [&str; 3] = ["xbt402_pay", "open_channel", "fund"];

fn rig_with(mode: &'static str) -> (Rig, Arc<FundNode>) {
    let pay_to = hex::encode(ecdsa::pubkey(&secret("provider payTo")));
    let mut rig = Rig::new(json!({"counterparties": {PROVIDER: {"pay_to": pay_to}}}), false);
    rig.fund_hot(0x11, 14_000);
    let node = Arc::new(FundNode { chain: rig.chain.clone(), mode: Mutex::new(mode) });
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(node.clone()), transport: Some(rig.web.clone()), ..Default::default() }).unwrap();
    (rig, node)
}

/// Ask for a channel funding over `path`; the answer or the error's text.
fn fund_over(rig: &Rig, path: &str) -> Result<Value, String> {
    let p = match path {
        "xbt402_pay" => json!({"url": URL, "method": "GET", "body": "", "max_sats": 500}),
        "open_channel" => json!({"dest": PROVIDER}),
        _ => {
            let payer = hex::decode(rig.call("xbt402_new_key", json!({"origin": PROVIDER}))["pub"].as_str().unwrap()).unwrap();
            let spk = hex::decode(rig.hot_spk()).unwrap();
            let pay_to = ecdsa::pubkey(&secret("provider payTo"));
            let params = ChannelParams::derive(&pay_to, &payer, (rig.chain.height() + 2_000) as u32, 300, Some(spk), &rig.chain.network(), FeePayer::Payer).unwrap();
            json!({"origin": PROVIDER, "params": params.to_json(), "sats": 9_000})
        }
    };
    rig.s.handle(path, &p).map_err(|e| e.msg)
}

fn channels(rig: &Rig) -> Vec<Value> {
    rig.call("channels", json!({}))["channels"].as_array().cloned().unwrap_or_default()
}

/// The fundings in the node's mempool or blocks: transactions paying a channel script we hold.
fn fundings(rig: &Rig) -> Vec<String> {
    let chans = channels(rig);
    rig.chain.sent_txs().iter().map(|t| t.txid()).filter(|t| chans.iter().any(|c| c["funding_txid"] == t.as_str())).collect()
}

#[test]
fn a_funding_of_unknown_fate_keeps_its_pending_record_and_key() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    for path in PATHS {
        let (rig, node) = rig_with("lost");
        let hot = rig.hot_sats();
        let r = fund_over(&rig, path);
        *node.mode.lock().unwrap() = "";
        assert_eq!(rig.chain.sent_txs().len(), 1, "{path}: the node took the funding ({r:?})");
        let chans = channels(&rig);
        let txid = rig.chain.sent_txs()[0].txid();
        assert_eq!(chans.iter().map(|c| (c["state"].as_str().unwrap_or(""), c["funding_txid"].as_str().unwrap_or(""))).collect::<Vec<_>>(),
                   vec![("pending", txid.as_str())], "{path}: the channel the coins are in was forgotten ({r:?})");
        assert!(rig.hot_sats() < hot, "{path}: the funding's inputs are spent");
        // nothing funds a second channel beside it, and the first is finished or refundable
        let again = fund_over(&rig, path);
        assert_eq!(fundings(&rig), vec![txid.clone()], "{path}: {again:?}");
        rig.chain.mine(1);
        match path {
            "xbt402_pay" => assert_eq!(rig.pay()["verdict"], "allow", "{path}"),
            "open_channel" => {
                rig.s.watch_tick();
                assert_eq!(channels(&rig)[0]["state"], "open", "{path}: open once its funding is on the node");
            }
            _ => assert_eq!(channels(&rig)[0]["state"], "pending", "{path}: it waits for the client's attach"),
        }
        assert_eq!(rig.chain.sent_txs().len(), 1, "{path}");
    }
}

#[test]
fn a_funding_the_node_never_received_is_sent_again_by_the_watcher() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    for path in PATHS {
        let (rig, node) = rig_with("never");
        let r = fund_over(&rig, path);
        assert!(rig.chain.sent_txs().is_empty(), "{path}");
        *node.mode.lock().unwrap() = "";
        assert_eq!(channels(&rig).iter().filter(|c| c["state"] == "pending").count(), 1, "{path}: {r:?}");
        rig.s.watch_tick();
        let txid = channels(&rig)[0]["funding_txid"].as_str().unwrap().to_string();
        assert_eq!(rig.chain.sent_txs().iter().map(|t| t.txid()).collect::<Vec<_>>(), vec![txid], "{path}: the pending funding went out");
    }
}

#[test]
fn a_refused_funding_the_node_cannot_be_asked_about_is_kept() {
    // "already known" is a refusal too: without the lookup a refusal does not say the node has nothing
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    for path in PATHS {
        let (rig, node) = rig_with("refuse_deaf");
        let r = fund_over(&rig, path);
        *node.mode.lock().unwrap() = "";
        assert_eq!(channels(&rig).iter().filter(|c| c["state"] == "pending").count(), 1, "{path}: {r:?}");
    }
}

#[test]
fn a_funding_the_node_refused_is_forgotten() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    for path in PATHS {
        let (rig, node) = rig_with("refuse");
        let hot = rig.hot_sats();
        let r = fund_over(&rig, path);
        *node.mode.lock().unwrap() = "";
        assert!(rig.chain.sent_txs().is_empty() && channels(&rig).is_empty(), "{path}: {r:?} {:?}", channels(&rig));
        assert_eq!(rig.hot_sats(), hot, "{path}: nothing was spent");
    }
}

// --- an approval is spent by a payment, not by a refusal ----------------------------------------------

const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/// A payment to `ADDR` that needs the human, and the signed approval for it.
fn approval(mode: &'static str) -> (Rig, Arc<FundNode>, Value) {
    approval_under(mode, json!({"allowlist": [ADDR]}))
}

fn approval_under(mode: &'static str, policy: Value) -> (Rig, Arc<FundNode>, Value) {
    let mut rig = Rig::new(policy, false);
    let node = Arc::new(FundNode { chain: rig.chain.clone(), mode: Mutex::new(mode) });
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(node.clone()), transport: Some(rig.web.clone()), ..Default::default() }).unwrap();
    let r = rig.call("pay", json!({"to": ADDR, "amount_sats": 1000, "memo": "big"}));
    assert_eq!(r["verdict"], "needs_human", "{r}");
    let (tok, exp) = (r["approval_token"].as_str().unwrap().to_string(), r["approval_expires"].as_i64().unwrap());
    let sig = sign_human(&xbt_signer::approval::canonical_message(&tok, ADDR, 1000, exp));
    (rig, node, json!({"token": tok, "dest": ADDR, "amount_sats": 1000, "expiry": exp, "signature": sig}))
}

fn booked(rig: &Rig) -> i64 {
    rig.s.engine.store.payments().unwrap().iter().map(|e| e.amount_sats).sum()
}

#[test]
fn an_approval_the_node_refused_to_pay_is_not_spent() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, node, ok) = approval("pay_refuse");
    assert!(rig.s.handle("approve", &ok).is_err(), "the node refused");
    assert_eq!(booked(&rig), 0);
    *node.mode.lock().unwrap() = "";
    let r = rig.call("approve", ok.clone());
    assert_eq!((r["verdict"].as_str(), r["approved"].as_bool(), r["rail"].as_str()), (Some("allow"), Some(true), Some("onchain")), "the human's approval was spent on a refusal: {r}");
    assert_eq!(booked(&rig), 1000);
    assert_eq!(rig.call("approve", ok)["rule"], "approval", "paid once: the token is gone");
}

#[test]
fn an_approval_whose_payment_is_of_unknown_fate_stays_spent() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, node, ok) = approval("pay_lost");
    assert!(rig.s.handle("approve", &ok).is_err());
    assert_eq!(booked(&rig), 1000, "the node may have paid: booked");
    *node.mode.lock().unwrap() = "";
    assert_eq!(rig.call("approve", ok.clone())["rule"], "approval_replay", "never a second payment on one approval");
    assert_eq!(booked(&rig), 1000);
    let mut rig = rig;
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(node.clone()), transport: Some(rig.web.clone()), ..Default::default() }).unwrap();
    assert_eq!(rig.call("approve", ok)["rule"], "approval_replay", "nor after a restart");
}

#[test]
fn an_approval_the_policy_denied_is_not_spent() {
    // the human approved; the payment is then denied by another rule (the velocity limit filled
    // meanwhile). Nothing was paid, so the approval is still good once the rule lets it through
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, _node, ok) = approval_under("", json!({"allowlist": [ADDR], "velocity_max": 1, "velocity_window_s": 1}));
    assert_eq!(rig.call("pay", json!({"to": ADDR, "amount_sats": 100, "memo": "small"}))["verdict"], "allow");
    let r = rig.call("approve", ok.clone());
    assert_eq!((r["verdict"].as_str(), r["rule"].as_str(), booked(&rig)), (Some("deny"), Some("velocity"), 100), "{r}");
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let r = rig.call("approve", ok);
    assert_eq!((r["verdict"].as_str(), booked(&rig)), (Some("allow"), 1100), "the human's approval was spent on a deny: {r}");
}
