//! AGP-093, third closure audit, Rust wallet (xbt-signer): a human-signed message that was used
//! stays used when the host's clock goes back. (The audit's other tests in this file were about the
//! on-chain channel, which was removed.)
mod common;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use common::*;
use serde_json::json;
use xbt_signer::signer::{Signer, SignerOptions};

const MIKE: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/// New in wave 4. `UsedSigs::spend` drops every entry whose expiry is below the signer's clock
/// (admin.rs:71), because "the expiry check refuses them from then on". That holds only while the
/// clock never goes back. The clock is the host's wall clock (`PolicyEngine::now`); after a step
/// back (a wrong RTC at boot, an NTP correction, whoever can set the host's time), a signature that
/// was used, then pruned, is inside its window again and is not in the file: it runs a second time.
///
/// Fails on f52e235: the second sweep with the same signature answers `ok: true`.
#[test]
fn hole_a_used_human_signature_stays_used_when_the_clock_goes_back() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({}), false);
    let t = Arc::new(std::sync::atomic::AtomicI64::new(xbt_signer::pyjson::now_f64() as i64));
    let tc = t.clone();
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(rig.chain.clone()),
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

