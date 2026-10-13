//! AGP-063 (review W): a process on the agent socket cannot refuse or rotate for the human (W3),
//! nor enrol its own approval key (W4). (W1 and W2, and the rest of W3, were about the on-chain
//! channel, which was removed.)
mod common;

use common::*;
use serde_json::{json, Value};

fn rule(v: &Value) -> &str {
    v["rule"].as_str().unwrap_or("")
}

#[test]
fn w3_rotate_hot_key_and_deny_approval_need_the_human_signature() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"allowlist": ["bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"]}), false);
    rig.fund_hot(1, 12_000);
    let hot = rig.hot_spk();
    assert_eq!(rule(&rig.call("rotate_hot_key", json!({}))), "human_sig");
    assert_eq!(rig.hot_spk(), hot, "not rotated");
    let to = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let r = rig.call("pay", json!({"to": to, "amount_sats": 1000, "memo": "at the human threshold"}));
    assert_eq!(r["verdict"], "needs_human", "{r}");
    let tok = r["approval_token"].as_str().unwrap().to_string();
    assert_eq!(rule(&rig.call("deny_approval", json!({"token": tok}))), "human_sig");
    assert_eq!(rig.call("approval_status", json!({"token": tok}))["state"], "pending", "the agent cannot refuse for the human");
    let exp = xbt_signer::pyjson::now_f64() as i64 + 300;
    let d = rig.call("deny_approval", json!({"token": tok, "expiry": exp, "signature": sign_human(&xbt_signer::approval::deny_message(&tok, exp))}));
    assert_eq!(d["state"], "denied", "{d}");
    assert_ne!(rig.rotate_hot_key()["new_address"], Value::Null);
    assert_ne!(rig.hot_spk(), hot);
}

#[test]
fn w4_the_first_human_key_needs_the_one_time_code() {
    use std::os::unix::fs::PermissionsExt;
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"human_pubkey": ""}), false);
    let f = rig.root.join(".run/enroll-code");
    assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
    let first = std::fs::read_to_string(&f).unwrap().trim().to_string();
    let pubhex = hex::encode(human().verifying_key().to_bytes());
    assert_eq!(rule(&rig.call("human_key_enroll", json!({"pubkey": pubhex}))), "enroll_code", "trust on first use is gone");
    for _ in 1..xbt_signer::admin::ENROLL_CODE_TRIES {
        assert_eq!(rule(&rig.call("human_key_enroll", json!({"pubkey": pubhex, "code": "0000-0000-0000"}))), "enroll_code");
    }
    let second = std::fs::read_to_string(&f).unwrap().trim().to_string();
    assert_ne!(first, second, "a new code after the tries run out");
    assert_eq!(rule(&rig.call("human_key_enroll", json!({"pubkey": pubhex, "code": first}))), "enroll_code", "the old code is dead");
    let r = rig.call("human_key_enroll", json!({"pubkey": pubhex, "code": second.to_lowercase().replace('-', "")}));
    assert_eq!(r["ok"], true, "{r}");
    assert!(!f.exists());
}
