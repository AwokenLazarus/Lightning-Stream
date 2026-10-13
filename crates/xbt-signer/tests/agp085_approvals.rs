//! AGP-085: an approval is spent by a payment, not by a refusal. It is held while its payment runs;
//! the node's own refusal or a verdict that is not `allow` gives it back, and a payment of unknown
//! fate leaves it used for good. (The file's other tests were about channel fundings, which went
//! with the on-chain channel.)
mod common;

use std::sync::{Arc, Mutex};

use common::*;
use serde_json::{json, Value};
use xbt_signer::node::Node;
use xbt_signer::signer::{Signer, SignerOptions};

/// The rig's node with a wallet that answers `sendtoaddress` (`pay_refuse`: its own JSON-RPC error;
/// `pay_lost`: no answer).
struct FundNode {
    chain: Arc<FakeChain>,
    mode: Mutex<&'static str>,
}

impl Node for FundNode {
    fn call(&self, method: &str, p: Value) -> xbt402::Result<Value> {
        let mode = *self.mode.lock().unwrap();
        let timeout = || Err(xbt402::ChannelError::new("rpc_error", "timed out reading response"));
        match (method, mode) {
            ("sendtoaddress", "pay_lost") => timeout(),
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

const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/// A payment to `ADDR` that needs the human, and the signed approval for it.
fn approval(mode: &'static str) -> (Rig, Arc<FundNode>, Value) {
    approval_under(mode, json!({"allowlist": [ADDR]}))
}

fn approval_under(mode: &'static str, policy: Value) -> (Rig, Arc<FundNode>, Value) {
    let mut rig = Rig::new(policy, false);
    let node = Arc::new(FundNode { chain: rig.chain.clone(), mode: Mutex::new(mode) });
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(node.clone()), ..Default::default() }).unwrap();
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
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(node.clone()), ..Default::default() }).unwrap();
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
