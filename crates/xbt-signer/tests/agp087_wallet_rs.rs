//! AGP-087 (second closure audit, Rust wallet): two `approve` calls of one token that wait on the
//! spend lock pay once. (The audit's other tests in this file were about the on-chain channel,
//! which was removed.)
mod common;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use common::*;
use serde_json::{json, Value};
use xbt_signer::node::Node;
use xbt_signer::signer::{Signer, SignerOptions};

fn ledger(rig: &Rig) -> i64 {
    rig.s.engine.store.payments().unwrap().iter().map(|e| e.amount_sats).sum()
}

const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/// The rig's node with a wallet: `sendtoaddress` with the memo `gate` waits until the gate opens
/// (the caller holds the signer's spend lock meanwhile); every send is noted as `(amount, memo)`.
struct GateNode {
    chain: Arc<FakeChain>,
    open: Mutex<bool>,
    cv: Condvar,
    waiting: AtomicBool,
    n: AtomicUsize,
    sends: Mutex<Vec<(String, String)>>,
}

impl Node for GateNode {
    fn call(&self, method: &str, p: Value) -> xbt402::Result<Value> {
        if method == "sendtoaddress" {
            let (amount, memo) = (p[1].as_str().unwrap_or("").to_string(), p[2].as_str().unwrap_or("").to_string());
            if memo == "gate" {
                self.waiting.store(true, Ordering::SeqCst);
                let mut g = self.open.lock().unwrap();
                while !*g {
                    g = self.cv.wait(g).unwrap();
                }
            }
            self.sends.lock().unwrap().push((amount, memo));
            return Ok(json!(format!("{:064x}", self.n.fetch_add(1, Ordering::SeqCst) + 1)));
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

/// The human signs one approval for one 1,000 sat payment. The UI's request is sent twice (a
/// double click, or a retry after a timeout) while another payment holds the signer's spend lock,
/// which `xbt402_pay` can do for `open_wait_s`. One approval pays once.
///
/// Fails on c80ee94: `approve_signed` reads the token and its `used` flag before it takes the
/// spend lock (signer.rs:1567-1597), so both calls pass the check, and the second writes the hold
/// again and pays again: two payments of 1,000 sat, 2,100 sat booked.
#[test]
fn one_approval_pays_once_when_two_approve_calls_wait_on_the_spend_lock() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({"allowlist": [ADDR]}), false);
    let node = Arc::new(GateNode { chain: rig.chain.clone(), open: Mutex::new(false), cv: Condvar::new(), waiting: AtomicBool::new(false),
                                   n: AtomicUsize::new(0), sends: Mutex::new(vec![]) });
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(node.clone()), ..Default::default() }).unwrap();
    let r = rig.call("pay", json!({"to": ADDR, "amount_sats": 1000, "memo": "big"}));
    assert_eq!(r["verdict"], "needs_human", "{r}");
    let (tok, exp) = (r["approval_token"].as_str().unwrap().to_string(), r["approval_expires"].as_i64().unwrap());
    let ok = json!({"token": tok, "dest": ADDR, "amount_sats": 1000, "expiry": exp,
                    "signature": sign_human(&xbt_signer::approval::canonical_message(&tok, ADDR, 1000, exp))});
    // another payment holds the spend lock
    let s = rig.s.clone();
    let holder = std::thread::spawn(move || s.handle("pay", &json!({"to": ADDR, "amount_sats": 100, "memo": "gate"})).map_err(|e| e.msg));
    while !node.waiting.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(10));
    }
    let approves: Vec<_> = (0..2).map(|_| {
        let (s, ok) = (rig.s.clone(), ok.clone());
        std::thread::spawn(move || s.handle("approve", &ok).map_err(|e| e.msg))
    }).collect();
    std::thread::sleep(Duration::from_millis(600)); // both are past the token check, waiting for the lock
    *node.open.lock().unwrap() = true;
    node.cv.notify_all();
    holder.join().unwrap().unwrap();
    let answers: Vec<_> = approves.into_iter().map(|t| t.join().unwrap()).collect();
    let big = node.sends.lock().unwrap().iter().filter(|(_, memo)| memo == "big").count();
    assert_eq!((big, ledger(&rig)), (1, 1_100), "one approval, {big} payments of 1,000 sat; answers: {answers:?}");
}

