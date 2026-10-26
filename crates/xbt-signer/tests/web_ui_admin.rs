//! AGP-039: the signer methods behind the web UI, on the test rig (a regtest signer): approve and
//! deny, the human-signed policy change and its live effect, human-key enrolment and rotation, the
//! signed hot-key rotation, the backup export, and what an earlier version's on-chain channels left
//! for the UI to show.
mod common;

use common::*;
use serde_json::{json, Value};
use xbt_signer::approval::{backup_message, canonical_message, deny_message, human_key_message, policy_message, rotate_message};

fn expiry_of(r: &Value) -> i64 {
    r["approval_expires"].as_i64().unwrap()
}

fn approve(rig: &Rig, r: &Value, sig_over: Option<Vec<u8>>) -> Value {
    let token = r["approval_token"].as_str().unwrap();
    let dest = r["dest"].as_str().unwrap();
    let amount = r["amount_sats"].as_i64().unwrap();
    let msg = sig_over.unwrap_or_else(|| canonical_message(token, dest, amount, expiry_of(r)));
    rig.call("approve", json!({"token": token, "dest": dest, "amount_sats": amount, "expiry": expiry_of(r), "signature": sign_human(&msg)}))
}

/// An approval that a payment over the on-chain channel asked for, before that rail was removed,
/// can pay nothing: approving it drops it and says why.
#[test]
fn an_approval_asked_for_by_a_channel_payment_is_dropped_with_the_reason() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    let r = rig.call("pay", json!({"to": ADDR, "amount_sats": 1000, "memo": "m"}));
    assert_eq!(r["verdict"], "needs_human", "{r}");
    let token = r["approval_token"].as_str().unwrap().to_string();
    // as the removed rail left it on disk
    rig.s.engine.store.update_approval(&token, &json!({"kind": "xbt402", "url": "http://127.0.0.1:33210/x", "method": "GET"})).unwrap();
    assert_eq!(rig.call("approvals", json!({}))["approvals"][0]["kind"], "xbt402");
    let ok = approve(&rig, &r, None);
    assert_eq!((ok["verdict"].as_str(), ok["rule"].as_str()), (Some("deny"), Some("removed")), "{ok}");
    assert!(rig.call("approvals", json!({}))["approvals"].as_array().unwrap().is_empty(), "it is gone from the queue");
    assert!(rig.s.engine.store.payments().unwrap().is_empty(), "nothing was paid");
}

#[test]
fn a_pay_token_approved_through_the_queue_pays_at_once_as_in_b2_and_deny_drops_a_token() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    let r = rig.call("pay", json!({"to": ADDR, "amount_sats": 1000, "memo": "m"}));
    assert_eq!(r["verdict"], "needs_human", "{r}");
    let q = rig.call("approvals", json!({}));
    assert_eq!(q["approvals"][0]["kind"], "pay");
    let exp = xbt_signer::pyjson::now_f64() as i64 + 300;
    let tok = r["approval_token"].as_str().unwrap().to_string();
    let d = rig.call("deny_approval", json!({"token": tok, "reason": "not today", "expiry": exp, "signature": sign_human(&deny_message(&tok, exp))}));
    assert_eq!(d["state"], "denied");
    assert_eq!(rig.call("approval_status", json!({"token": r["approval_token"]}))["state"], "denied");
    assert_eq!(approve(&rig, &r, None)["rule"], "approval");
    assert!(rig.call("approvals", json!({}))["approvals"].as_array().unwrap().is_empty());
    assert_eq!(rig.call("deny_approval", json!({"token": "nope"}))["rule"], "approval");
    // B2's approve of a pay token pays at once
    let r = rig.call("pay", json!({"to": ADDR, "amount_sats": 1000, "memo": "m"}));
    let ok = approve(&rig, &r, None);
    assert_eq!(ok["approved"], true, "{ok}");
    assert_eq!(ok["rail"], "onchain", "{ok}");
    assert_eq!(rig.call("approval_status", json!({"token": r["approval_token"]}))["state"], "used");
}

fn sign_policy(rig: &Rig, policy: Value) -> (Value, Value) {
    let prep = rig.call("policy_prepare", json!({"policy": policy}));
    assert_eq!(prep["ok"], true, "{prep}");
    let msg = hex::decode(prep["message_hex"].as_str().unwrap()).unwrap();
    assert_eq!(msg, policy_message(prep["prev_sha256"].as_str().unwrap(), prep["expiry"].as_i64().unwrap(), prep["text"].as_str().unwrap()));
    let set = json!({"text": prep["text"], "prev_sha256": prep["prev_sha256"], "expiry": prep["expiry"], "signature": sign_human(&msg)});
    (prep, set)
}

#[test]
fn a_policy_change_needs_the_human_key_is_validated_like_the_engine_and_applies_live() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    let cur = rig.call("policy_get", json!({}));
    let mut pol = cur["policy"].clone();
    // the engine's own parse error, then the extra checks
    pol["max_per_tx_sats"] = "lots".into();
    let v = rig.call("policy_validate", json!({"policy": pol}));
    assert_eq!(v["errors"][0], "policy.json max_per_tx_sats: not an integer");
    assert_eq!(rig.call("policy_prepare", json!({"policy": pol}))["errors"], v["errors"]);
    pol["max_per_tx_sats"] = 5000.into();
    pol["daily_budget_sats"] = (-1).into();
    pol["counterparties"] = json!({"http://x:1": {"ln_node": "02abcd", "pay_to": "02abcd"}});
    pol["channel_expiry_blocks"] = "soon".into();
    pol["refund_enabled"] = true.into();
    let v = rig.call("policy_validate", json!({"policy": pol}));
    let errs: Vec<String> = v["errors"].as_array().unwrap().iter().map(|e| e.as_str().unwrap().to_string()).collect();
    assert!(errs.contains(&"policy.json daily_budget_sats: must be >= 0 (got -1)".into()), "{errs:?}");
    assert!(errs.iter().any(|e| e.contains("counterparties[http://x:1].ln_node")), "{errs:?}");
    // settings of the removed on-chain channel load with a warning and are ignored, whatever they hold
    let warns: Vec<String> = v["warnings"].as_array().unwrap().iter().map(|e| e.as_str().unwrap().to_string()).collect();
    for k in ["channel_expiry_blocks", "refund_enabled", "counterparties[http://x:1].pay_to"] {
        assert!(warns.iter().any(|w| w.contains(k) && w.contains("on-chain channel") && w.contains("ignores")), "{k}: {warns:?}");
    }
    assert!(!errs.iter().any(|e| e.contains("channel_expiry_blocks")), "{errs:?}");
    // a valid change: raise the human threshold and the hot cap
    pol["daily_budget_sats"] = 6000.into();
    pol["counterparties"] = json!({});
    pol["human_threshold_sats"] = 5000.into();
    pol["hot_balance_cap_sats"] = 20_000.into();
    pol["anchor_interval_s"] = 7.into();
    // the prepared policy keeps the enrolled human key, whatever the form says
    pol["human_pubkey"] = "00".repeat(32).into();
    let (prep, set) = sign_policy(&rig, pol.clone());
    assert!(prep["text"].as_str().unwrap().contains(&hex::encode(human().verifying_key().to_bytes())));
    assert!(prep["diff"].as_array().unwrap().iter().any(|d| d["key"] == "anchor_interval_s" && d["restart"] == true));
    // a bad signature, a tampered text, an expired one
    let mut bad = set.clone();
    bad["signature"] = sign_human(b"something else").into();
    assert_eq!(rig.call("policy_set", bad)["rule"], "human_sig");
    let mut bad = set.clone();
    bad["text"] = prep["text"].as_str().unwrap().replace("5000", "9000").into();
    assert_eq!(rig.call("policy_set", bad)["rule"], "human_sig");
    let r = rig.call("policy_set", set.clone());
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["pending_restart"], json!(["anchor_interval_s"]));
    // live: 1,000 sats no longer needs a human; the hot cap moved
    let q = rig.call("quote_payment", json!({"to": PROVIDER, "amount_xbt": 0.00001}));
    assert_eq!(q["verdict"], "allow", "{q}");
    assert_eq!(rig.call("hot_address", json!({}))["hot_cap_sats"], 20_000);
    assert_eq!(rig.s.config().human_threshold_sats, 5000);
    // the same signed change cannot be replayed: a human signature is used once (AGP-089; before
    // that the refusal was `policy_stale`, since the previous hash had moved)
    assert_eq!(rig.call("policy_set", set)["rule"], "human_sig_replay");
    // the file on disk is the signed text, and the old one is kept
    let text = std::fs::read_to_string(rig.root.join("policy.json")).unwrap();
    assert_eq!(text, prep["text"].as_str().unwrap());
    assert!(rig.root.join("policy.json.prev").exists());
    let hist = rig.call("history", json!({"limit": 50}))["events"].clone();
    assert!(hist.as_array().unwrap().iter().any(|e| e["type"] == "policy_change"));
    // a restart reads the same policy
    let mut rig = rig;
    rig.restart().unwrap();
    assert_eq!(rig.s.config().human_threshold_sats, 5000);
    assert_eq!(rig.call("policy_get", json!({}))["pending_restart"], json!([]));
}

#[test]
fn the_first_human_key_is_enrolled_once_and_later_only_the_old_key_can_hand_over() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"human_pubkey": ""}), false);
    assert_eq!(rig.call("keystore_status", json!({}))["human_key"], false);
    // no human key: nothing human-signed works yet
    let (_, set) = sign_policy(&rig, rig.call("policy_get", json!({}))["policy"].clone());
    assert_eq!(rig.call("policy_set", set)["rule"], "human_key");
    let pubhex = hex::encode(human().verifying_key().to_bytes());
    assert_eq!(rig.call("human_key_enroll", json!({"pubkey": "zz"}))["rule"], "human_key");
    let code = std::fs::read_to_string(rig.root.join(".run/enroll-code")).unwrap().trim().to_string();
    let r = rig.call("human_key_enroll", json!({"pubkey": pubhex, "code": code}));
    assert_eq!(r["ok"], true, "{r}");
    assert!(!rig.root.join(".run/enroll-code").exists(), "the code is spent");
    assert_eq!(rig.call("human_key_enroll", json!({"pubkey": pubhex}))["rule"], "human_key", "trust on first use only");
    // rotate to a new device key, signed by the old one
    let new = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let new_hex = hex::encode(new.verifying_key().to_bytes());
    let exp = xbt_signer::pyjson::now_f64() as i64 + 300;
    let forged = hex::encode(ed25519_dalek::Signer::sign(&new, &human_key_message(&pubhex, &new_hex, exp)).to_bytes());
    assert_eq!(rig.call("human_key_rotate", json!({"pubkey": new_hex, "expiry": exp, "signature": forged}))["rule"], "human_sig");
    let r = rig.call("human_key_rotate", json!({"pubkey": new_hex, "expiry": exp, "signature": sign_human(&human_key_message(&pubhex, &new_hex, exp))}));
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(hex::encode(rig.s.human_key()), new_hex);
    let text = std::fs::read_to_string(rig.root.join("policy.json")).unwrap();
    assert!(text.contains(&new_hex));
    // the old key no longer approves anything
    let (_, set) = sign_policy(&rig, rig.call("policy_get", json!({}))["policy"].clone());
    assert_eq!(rig.call("policy_set", set)["rule"], "human_sig");
}

/// A box's setup page reads the code from a copy the signer writes beside it (0640, the copy dir's
/// group): the owner reads no log. The copy goes when the code is spent.
#[test]
fn the_enrolment_code_has_a_copy_for_the_setup_page_that_goes_once_spent() {
    use std::os::unix::fs::PermissionsExt;
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let t = tempfile::tempdir().unwrap();
    let copy = t.path().join("enroll-code");
    std::env::set_var(xbt_signer::admin::ENROLL_CODE_COPY_ENV, &copy);
    let rig = Rig::new(json!({"human_pubkey": ""}), false);
    std::env::remove_var(xbt_signer::admin::ENROLL_CODE_COPY_ENV);
    let code = std::fs::read_to_string(rig.root.join(".run/enroll-code")).unwrap();
    assert_eq!(std::fs::read_to_string(&copy).unwrap(), code);
    assert_eq!(std::fs::metadata(&copy).unwrap().permissions().mode() & 0o777, 0o640);
    std::env::set_var(xbt_signer::admin::ENROLL_CODE_COPY_ENV, &copy);
    let r = rig.call("human_key_enroll", json!({"pubkey": hex::encode(human().verifying_key().to_bytes()), "code": code.trim()}));
    std::env::remove_var(xbt_signer::admin::ENROLL_CODE_COPY_ENV);
    assert_eq!(r["ok"], true, "{r}");
    assert!(!copy.exists(), "the copy is spent with the code");
}

#[test]
fn the_signed_rotation_and_the_backup_export() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 8_000);
    let old = rig.call("hot_address", json!({}))["hot_address"].as_str().unwrap().to_string();
    let exp = xbt_signer::pyjson::now_f64() as i64 + 300;
    let r = rig.call("rotate_hot_key_signed", json!({"expiry": exp, "signature": sign_human(b"no")}));
    assert_eq!(r["rule"], "human_sig");
    let r = rig.call("rotate_hot_key_signed", json!({"expiry": exp - 1000, "signature": sign_human(&rotate_message(&old, exp - 1000))}));
    assert_eq!(r["rule"], "expired");
    let r = rig.call("rotate_hot_key_signed", json!({"expiry": exp, "signature": sign_human(&rotate_message(&old, exp))}));
    assert_eq!(r["old_address"], old.as_str(), "{r}");
    assert_ne!(r["new_address"], old.as_str());
    assert!(rig.sigs().iter().any(|s| s["rule"] == "human:rotate_signature"), "the sweep to the new key is logged as the human's");
    // backup
    let hot = rig.call("hot_address", json!({}))["hot_address"].as_str().unwrap().to_string();
    let sig = sign_human(&backup_message(&hot, exp));
    assert_eq!(rig.call("backup_export", json!({"expiry": exp, "signature": sig, "backup_pass": "short"}))["rule"], "backup_pass");
    assert_eq!(rig.call("backup_export", json!({"expiry": exp, "signature": sign_human(&backup_message(&old, exp)),
                                                 "backup_pass": "correct horse battery"}))["rule"], "human_sig");
    let r = rig.call("backup_export", json!({"expiry": exp, "signature": sig, "backup_pass": "correct horse battery"}));
    assert_eq!(r["ok"], true, "{r}");
    let doc: Value = serde_json::from_str(r["backup_json"].as_str().unwrap()).unwrap();
    for f in ["policy.json", ".run/hot.json", ".run/hot_utxos.json", ".run/ledger.json", ".run/ledger.payments.jsonl", ".run/signatures.jsonl"] {
        assert!(doc["files"].get(f).is_some(), "backup holds {f}: {:?}", doc["files"].as_object().unwrap().keys().collect::<Vec<_>>());
    }
    let key = std::fs::read(rig.dir.path().join("keys/hot.key")).unwrap();
    let opened = xbt_signer::keystore::KeyStore::with_passphrase(b"correct horse battery")
        .open(&doc["wrapping_sealed"], "xbt-agentwallet-backup-wrapping").unwrap();
    let want = if key.len() == 32 { key } else { hex::decode(String::from_utf8(key).unwrap().trim()).unwrap() };
    assert_eq!(*opened, want, "the backup's wrapping secret opens with the backup passphrase");
    assert!(xbt_signer::keystore::KeyStore::with_passphrase(b"wrong horse battery").open(&doc["wrapping_sealed"], "xbt-agentwallet-backup-wrapping").is_err());
}

/// A wallet that was upgraded with an on-chain channel still open: the UI is shown the record and
/// the close reports the earlier version kept, the owner is told what to do, and nothing is written.
#[test]
fn what_an_earlier_versions_channels_left_is_shown_and_never_written() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({}), false);
    let run = rig.root.join(".run");
    let book = r#"{"channels": {"http://127.0.0.1:33210": {"state": "open", "dest": "http://127.0.0.1:33210", "chan": "c1", "cap_sats": 9400, "used_sats": 546, "expiry": 7728}}, "archived": []}"#;
    std::fs::write(run.join("channels.json"), book).unwrap();
    std::fs::write(run.join("channel_keys.json"), r#"{"sealed": {"ct": "00"}}"#).unwrap();
    std::fs::write(run.join("close_reports.json"), r#"{"c0": {"report": {"status": "ok"}, "cum": 546}}"#).unwrap();
    rig.restart().unwrap();
    let reps = rig.call("channel_reports", json!({}));
    assert_eq!(reps["reports"]["c0"]["report"]["status"], "ok", "{reps}");
    assert_eq!(reps["legacy_channels"]["unsettled"], 1, "{reps}");
    let ch = rig.call("channels", json!({}));
    assert_eq!((ch["channels"][0]["chan"].as_str(), ch["channels"][0]["legacy"].as_bool()), (Some("c1"), Some(true)), "{ch}");
    assert!(ch["legacy_channels"]["what_to_do"].as_str().unwrap().contains("cannot close or refund"));
    assert_eq!(rig.call("health", json!({}))["legacy_channels"]["unsettled"], 1);
    for m in ["close_channel", "xbt402_refund"] {
        assert_eq!(rig.call(m, json!({"counterparty": PROVIDER}))["rule"], "removed");
    }
    rig.call("watch_tick", json!({}));
    assert_eq!(std::fs::read_to_string(run.join("channels.json")).unwrap(), book, "the book is left as it was");
    assert_eq!(std::fs::read_to_string(run.join("channel_keys.json")).unwrap(), r#"{"sealed": {"ct": "00"}}"#);
}
