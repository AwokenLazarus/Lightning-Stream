//! AGP-102, fourth closure audit, area wallet_rs (the Rust agent wallet): a stated limit, pinned
//! with numbers. One human-signed use under a host clock far ahead refuses the owner's signatures
//! afterwards (`docs/LIMITS.md`). (The audit's other tests in this file were about the on-chain
//! channel, which was removed.)
mod common;

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use common::*;
use serde_json::{json, Value};
use xbt_signer::signer::{Signer, SignerOptions};

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
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(rig.chain.clone()),
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
