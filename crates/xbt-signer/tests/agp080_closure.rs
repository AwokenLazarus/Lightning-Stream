//! AGP-080 (closure audit, wallet), K1: the on-chain `pay` rail books before it sends. (The other
//! tests of that audit were about the on-chain channel, which was removed.)
mod common;

use std::sync::{Arc, Mutex};

use common::*;
use serde_json::{json, Value};
use xbt_signer::node::Node;
use xbt_signer::signer::{Signer, SignerOptions};

/// The policy ledger's total as the log on disk holds it now (payments, with amends applied).
fn ledger_on_disk(root: &std::path::Path) -> i64 {
    let text = std::fs::read_to_string(root.join(".run/ledger.payments.jsonl")).unwrap_or_default();
    let mut rows: Vec<(String, i64)> = vec![];
    for v in text.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()) {
        if let Some(t) = v.get("amend").and_then(Value::as_str) {
            if let Some(i) = rows.iter().rposition(|(id, _)| id == t) {
                match v["amount_sats"].as_i64() {
                    Some(n) => rows[i].1 = n,
                    None => {
                        rows.remove(i);
                    }
                }
            }
        } else if v.get("dest").is_some() {
            rows.push((v["txid"].as_str().unwrap_or("").to_string(), v["amount_sats"].as_i64().unwrap_or(0)));
        }
    }
    rows.iter().map(|(_, a)| a).sum()
}

fn ledger(rig: &Rig) -> i64 {
    rig.s.engine.store.payments().unwrap().iter().map(|e| e.amount_sats).sum()
}

// --- K1: the on-chain pay rail books before it sends -------------------------------------------------------

/// The rig's node, with a wallet that answers `sendtoaddress`.
struct PayNode {
    chain: Arc<FakeChain>,
    root: std::path::PathBuf,
    /// The ledger on disk at each `sendtoaddress`.
    held: Mutex<Vec<i64>>,
    answer: Mutex<xbt402::Result<Value>>,
}

impl Node for PayNode {
    fn call(&self, method: &str, p: Value) -> xbt402::Result<Value> {
        if method == "sendtoaddress" {
            self.held.lock().unwrap().push(ledger_on_disk(&self.root));
            return self.answer.lock().unwrap().clone();
        }
        self.chain.call(method, p)
    }
    fn set_allow_generate(&self, allow: bool) {
        self.chain.set_allow_generate(allow);
    }
    fn wallet(&self) -> String {
        self.chain.wallet()
    }
}

const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

#[test]
fn k1_the_onchain_pay_rail_books_before_it_sends() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({"allowlist": [ADDR]}), false);
    let node = Arc::new(PayNode { chain: rig.chain.clone(), root: rig.root.clone(), held: Mutex::new(vec![]), answer: Mutex::new(Ok(json!("5a".repeat(32)))) });
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(node.clone()), ..Default::default() }).unwrap();
    let r = rig.call("pay", json!({"to": ADDR, "amount_sats": 400, "memo": "m"}));
    assert_eq!((r["verdict"].as_str(), r["rail"].as_str(), r["txid"].as_str()), (Some("allow"), Some("onchain"), Some("5a".repeat(32).as_str())), "{r}");
    assert_eq!(*node.held.lock().unwrap(), vec![400], "the payment was in the ledger when sendtoaddress was called");
    let rows = rig.s.engine.store.payments().unwrap();
    assert_eq!(rows.iter().map(|e| (e.amount_sats, e.txid.as_str())).collect::<Vec<_>>(), vec![(400, "5a".repeat(32).as_str())], "booked once, under the txid");
    // the node refuses: the booking is taken back
    *node.answer.lock().unwrap() = Err(xbt402::ChannelError::new("rpc_refused", r#"{"code":-6,"message":"Insufficient funds"}"#));
    assert!(rig.s.handle("pay", &json!({"to": ADDR, "amount_sats": 300, "memo": "n"})).is_err());
    assert_eq!(ledger(&rig), 400, "a payment the node refused is not booked");
    // the node does not answer: the payment may have gone out, so it stays booked
    *node.answer.lock().unwrap() = Err(xbt402::ChannelError::new("rpc_error", "timed out reading response"));
    assert!(rig.s.handle("pay", &json!({"to": ADDR, "amount_sats": 200, "memo": "o"})).is_err());
    assert_eq!(ledger(&rig), 600, "a payment whose fate is unknown stays booked");
}
