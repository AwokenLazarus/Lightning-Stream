//! AGP-095, fix wave 5, Rust wallet (xbt-signer): the watcher goes on after a panic, and the
//! used-signature file keeps its clock. (The wave's other tests in this file were about the
//! on-chain channel, which was removed; the watcher tests ran on its refund step and now run on
//! the sweep of a retired hot key.)
mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use common::*;
use serde_json::{json, Value};
use xbt_signer::node::Node;
use xbt_signer::signer::{Signer, SignerOptions};

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

/// A coin on a retired hot key, which the watcher's `retired_sweep` step sweeps, behind a node
/// that panics in `method` while `on`.
fn panicky_rig(method: &'static str) -> (Rig, Arc<Panicky>) {
    let mut rig = Rig::new(json!({"hot_balance_cap_sats": 100_000}), false);
    let old_spk = rig.hot_spk();
    rig.fund_hot(1, 30_000);
    rig.rotate_hot_key();
    rig.chain.credit(&"cc".repeat(32), 0, 2_000, &old_spk, true);
    rig.call("notice_hot_txid", json!({"txid": "cc".repeat(32)}));
    let node = Arc::new(Panicky { inner: rig.chain.clone(), on: AtomicBool::new(false), method });
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(node.clone()), ..Default::default() }).unwrap();
    (rig, node)
}

fn retired_sats(rig: &Rig) -> i64 {
    rig.call("hot_address", json!({}))["hot_retired_sats"].as_i64().unwrap()
}

/// A panic in one step of a tick (the sweep of a retired key): the tick reports it, the steps
/// after it still run, the signer still answers, and the next tick sweeps.
///
/// Failed before the fix: `watch_tick` unwound to its caller.
#[test]
fn a_panic_in_one_step_of_a_tick_ends_only_that_step() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (rig, node) = panicky_rig("sendrawtransaction");
    node.on.store(true, Ordering::SeqCst);
    let acts = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rig.s.watch_tick())).expect("the tick itself does not panic");
    assert!(acts.iter().any(|a| a["watcher_panic"] == "retired_sweep"), "{acts:?}");
    assert_eq!(rig.call("health", json!({}))["ok"], true, "the spend lock the step held is usable again");
    assert_eq!(retired_sats(&rig), 2_000);
    node.on.store(false, Ordering::SeqCst);
    let acts = rig.s.watch_tick();
    assert!(acts.iter().any(|a| a["retired_sweep"]["txid"].is_string()), "{acts:?}");
    assert_eq!(retired_sats(&rig), 0);
}

/// The watcher thread itself (`watch_loop`): a tick that panics where no step guards it (the
/// height read at the top) does not end the thread. Once the node answers again the retired key
/// is swept by that same thread.
///
/// Failed before the fix: the thread ended with the first panic and nothing more was done.
#[test]
fn the_watcher_thread_outlives_a_tick_that_panics() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    std::env::set_var("B2_WATCH_INTERVAL", "0.1");
    let (rig, node) = panicky_rig("getblockcount");
    std::env::remove_var("B2_WATCH_INTERVAL");
    assert!(rig.s.watch_interval < 1.0);
    node.on.store(true, Ordering::SeqCst);
    let stop = Arc::new(AtomicBool::new(false));
    let (s, st) = (rig.s.clone(), stop.clone());
    let t = std::thread::spawn(move || s.watch_loop(st));
    std::thread::sleep(std::time::Duration::from_millis(700)); // several ticks, each panicking
    assert!(!t.is_finished(), "the watcher thread ended on a panic");
    assert_eq!(retired_sats(&rig), 2_000);
    node.on.store(false, Ordering::SeqCst);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while retired_sats(&rig) != 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    stop.store(true, Ordering::SeqCst);
    t.join().unwrap();
    assert_eq!(retired_sats(&rig), 0, "the same thread swept once the node answered");
}

const MIKE: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

fn clock_rig() -> (Rig, Arc<std::sync::atomic::AtomicI64>, String) {
    let mut rig = Rig::new(json!({}), false);
    let t = Arc::new(std::sync::atomic::AtomicI64::new(xbt_signer::pyjson::now_f64() as i64));
    let tc = t.clone();
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(rig.chain.clone()),
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

