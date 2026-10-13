//! AGP-089 (fix wave 4, wallet): one human signature authorises one operation (a sweep, a backup
//! export), across restarts, and an unreadable record of used signatures refuses. (The wave's
//! other tests in this file were about the on-chain channel, which was removed.)
mod common;

use std::sync::Arc;

use common::*;
use serde_json::json;
use xbt_signer::approval::{backup_message, sweep_message};
use xbt_signer::signer::{Signer, SignerOptions};

fn now() -> i64 {
    xbt_signer::pyjson::now_f64() as i64
}

const MIKE: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

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
    let root = root_with(dir.path(), &runbook_policy(json!({})));
    let ks = Arc::new(xbt_signer::keystore::KeyStore::with_passphrase(b"a wrapping passphrase"));
    let s = Signer::new(&root, SignerOptions { node: Some(chain), keystore: Some(ks), ..Default::default() }).unwrap();
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

