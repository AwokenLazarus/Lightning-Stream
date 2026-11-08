//! Simple mode's PIN approvals (`xbt_signer::pin`) on the test rig: the box key enrolled with the
//! enrolment code or handed over by the current key, a signed policy change approved with the PIN, wrong
//! PINs counted and locking (also across a restart), the lock's end, a PIN change, the offline reset, and
//! the gate that keeps the model-facing process from trying PINs.
mod common;

use common::*;
use serde_json::{json, Value};
use xbt_signer::approval::human_key_message;

fn now() -> i64 {
    xbt_signer::pyjson::now_f64() as i64
}

/// A policy change signed with the PIN: (what `policy_set` answers).
fn policy_change_with_pin(rig: &Rig, pin: &str, extra: &Value) -> (Value, Value) {
    static N: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(5000);
    let mut pol = rig.call("policy_get", json!({}))["policy"].clone();
    pol["max_per_tx_sats"] = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst).into();
    let prep = rig.call("policy_prepare", json!({"policy": pol}));
    assert_eq!(prep["ok"], true, "{prep}");
    let mut p = json!({"pin": pin, "message": prep["message_hex"]});
    if let (Some(o), Some(e)) = (p.as_object_mut(), extra.as_object()) {
        o.extend(e.clone());
    }
    let signed = rig.call("approve_with_pin", p);
    if signed["ok"] != true {
        return (signed, Value::Null);
    }
    let set = rig.call("policy_set", json!({"text": prep["text"], "prev_sha256": prep["prev_sha256"], "expiry": prep["expiry"],
                                             "signature": signed["signature"]}));
    (signed, set)
}

fn enrol_with_code(rig: &Rig, pin: &str) -> String {
    let prep = rig.call("pin_prepare", json!({}));
    assert_eq!((prep["ok"].as_bool(), prep["needs"].as_str()), (Some(true), Some("code")), "{prep}");
    let code = std::fs::read_to_string(rig.root.join(".run/enroll-code")).unwrap().trim().to_string();
    let r = rig.call("pin_set", json!({"pin": pin, "code": code}));
    assert_eq!(r["ok"], true, "{r}");
    prep["pubkey"].as_str().unwrap().to_string()
}

#[test]
fn the_first_approval_key_is_the_box_key_enrolled_with_the_code_and_a_policy_change_is_approved_with_the_pin() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"human_pubkey": ""}), false);
    assert_eq!(rig.call("pin_status", json!({}))["set"], false);
    assert_eq!(rig.call("pin_set", json!({"pin": "48"}))["rule"], "pin", "too short");
    assert_eq!(rig.call("pin_set", json!({"pin": "4821"}))["rule"], "pin", "nothing prepared yet");
    let prep = rig.call("pin_prepare", json!({}));
    assert_eq!(rig.call("pin_prepare", json!({}))["pubkey"], prep["pubkey"], "prepared once");
    assert_eq!(rig.call("pin_set", json!({"pin": "4821", "code": "WRONG-CODE-0000"}))["rule"], "enroll_code");
    let pubkey = enrol_with_code(&rig, "4821");
    assert_eq!(hex::encode(rig.s.human_key()), pubkey, "the box key is the human key");
    let st = rig.call("pin_status", json!({}));
    assert_eq!((st["set"].as_bool(), st["enrolled"].as_bool()), (Some(true), Some(true)), "{st}");
    assert!(!std::fs::read_to_string(rig.root.join(".run/pin-approver.json")).unwrap().contains("4821"), "no PIN in plain text");
    // the round trip: the PIN signs the policy message, policy_set checks it as any human signature
    let (signed, set) = policy_change_with_pin(&rig, "4821", &json!({}));
    assert_eq!(signed["ok"], true, "{signed}");
    assert_eq!(set["ok"], true, "{set}");
    assert!(rig.call("policy_get", json!({}))["policy"]["max_per_tx_sats"].as_i64().unwrap() >= 5000);
    // only approval messages are signed
    let r = rig.call("approve_with_pin", json!({"pin": "4821", "message": hex::encode(b"sign anything\n")}));
    assert_eq!(r["rule"], "pin", "{r}");
    assert_eq!(rig.call("pin_set", json!({"pin": "1111"}))["rule"], "pin", "a PIN is set once; it is changed with the current one");
}

#[test]
fn wrong_pins_lock_approvals_also_after_a_restart_and_the_lock_ends() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({"human_pubkey": ""}), false);
    enrol_with_code(&rig, "4821");
    for left in [4, 3, 2, 1] {
        let (r, _) = policy_change_with_pin(&rig, "0000", &json!({}));
        assert_eq!(r["rule"], "pin_wrong", "{r}");
        assert!(r["reason"].as_str().unwrap().contains(&format!("{left} tr")), "{r}");
    }
    let (r, _) = policy_change_with_pin(&rig, "0000", &json!({}));
    assert_eq!(r["rule"], "pin_locked", "the 5th wrong PIN locks: {r}");
    let (r, _) = policy_change_with_pin(&rig, "4821", &json!({}));
    assert_eq!(r["rule"], "pin_locked", "even the right PIN waits: {r}");
    rig.restart().unwrap();
    let (r, _) = policy_change_with_pin(&rig, "4821", &json!({}));
    assert_eq!(r["rule"], "pin_locked", "a restart does not lift the lock: {r}");
    assert_eq!(rig.call("pin_status", json!({}))["failures"], 5);
    // the 10 minutes pass (the tries file as the lock leaves it, its end moved back)
    let tries = rig.root.join(".run/pin-tries.json");
    std::fs::write(&tries, json!({"failures": 5, "locked_until": now() - 1}).to_string()).unwrap();
    let (r, set) = policy_change_with_pin(&rig, "4821", &json!({}));
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(set["ok"], true, "{set}");
    assert_eq!(rig.call("pin_status", json!({}))["failures"], 0, "a right PIN clears the count");
    // an unreadable tries file locks rather than counting from zero
    std::fs::write(&tries, "not json").unwrap();
    assert_eq!(policy_change_with_pin(&rig, "4821", &json!({})).0["rule"], "pin_locked");
}

#[test]
fn a_browser_key_hands_over_to_the_box_key_with_one_signature() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    let old = hex::encode(human().verifying_key().to_bytes());
    let prep = rig.call("pin_prepare", json!({}));
    assert_eq!((prep["needs"].as_str(), prep["old_pub"].as_str()), (Some("signature"), Some(old.as_str())), "{prep}");
    let new = prep["pubkey"].as_str().unwrap().to_string();
    let exp = now() + 300;
    assert_eq!(rig.call("pin_set", json!({"pin": "4821", "expiry": exp}))["rule"], "human_sig", "no handover signature");
    let r = rig.call("pin_set", json!({"pin": "4821", "expiry": exp, "signature": sign_human(&human_key_message(&old, &new, exp))}));
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(hex::encode(rig.s.human_key()), new);
    // the browser key approves nothing any more; the PIN does
    let mut pol = rig.call("policy_get", json!({}))["policy"].clone();
    pol["max_per_tx_sats"] = 4321.into();
    let p = rig.call("policy_prepare", json!({"policy": pol}));
    let msg = hex::decode(p["message_hex"].as_str().unwrap()).unwrap();
    let old_set = rig.call("policy_set", json!({"text": p["text"], "prev_sha256": p["prev_sha256"], "expiry": p["expiry"], "signature": sign_human(&msg)}));
    assert_eq!(old_set["rule"], "human_sig", "{old_set}");
    assert_eq!(policy_change_with_pin(&rig, "4821", &json!({})).1["ok"], true);
}

#[test]
fn the_pin_is_changed_with_the_current_one_and_reset_on_the_box() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({"human_pubkey": ""}), false);
    enrol_with_code(&rig, "4821");
    assert_eq!(rig.call("pin_change", json!({"pin": "1111", "new_pin": "2468"}))["rule"], "pin_wrong");
    assert_eq!(rig.call("pin_status", json!({}))["failures"], 1, "a wrong current PIN is a wrong try");
    assert_eq!(rig.call("pin_change", json!({"pin": "4821", "new_pin": "24"}))["rule"], "pin");
    assert_eq!(rig.call("pin_change", json!({"pin": "4821", "new_pin": "246813"}))["ok"], true);
    assert_eq!(policy_change_with_pin(&rig, "4821", &json!({})).0["rule"], "pin_wrong", "the old PIN is gone");
    assert_eq!(policy_change_with_pin(&rig, "246813", &json!({})).1["ok"], true);
    // forgotten: reset on the box with the signer stopped, then a new code and a new PIN
    let said = xbt_signer::pin::reset_offline(&rig.root, &rig.root.join(".run")).unwrap();
    assert!(said.contains("no longer the approval key"), "{said}");
    assert!(!rig.root.join(".run/pin-approver.json").exists() && !rig.root.join(".run/pin-tries.json").exists());
    rig.restart().unwrap();
    assert!(rig.s.human_key().is_empty());
    assert_eq!(rig.call("pin_status", json!({}))["set"], false);
    let fresh = enrol_with_code(&rig, "1357");
    assert_eq!(hex::encode(rig.s.human_key()), fresh);
    assert_eq!(policy_change_with_pin(&rig, "1357", &json!({})).1["ok"], true);
}

#[test]
fn a_reset_keeps_a_browser_key_that_is_not_the_pins() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    let said = xbt_signer::pin::reset_offline(&rig.root, &rig.root.join(".run")).unwrap();
    assert!(said.contains("is kept"), "{said}");
    assert!(std::fs::read_to_string(rig.root.join("policy.json")).unwrap().contains(&hex::encode(human().verifying_key().to_bytes())));
}

/// The socket is shared with the model-facing process: PIN calls need the gate the signer writes for the UI.
#[test]
fn pin_calls_need_the_uis_gate_where_the_box_gives_the_ui_one() {
    use std::os::unix::fs::PermissionsExt;
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let t = tempfile::tempdir().unwrap();
    std::env::set_var(xbt_signer::admin::ENROLL_CODE_COPY_ENV, t.path().join("enroll-code"));
    let rig = Rig::new(json!({"human_pubkey": ""}), false);
    let gate_file = t.path().join(xbt_signer::pin::PIN_GATE_FILE);
    let gate = std::fs::read_to_string(&gate_file).unwrap().trim().to_string();
    assert_eq!(gate.len(), 64);
    assert_eq!(std::fs::metadata(&gate_file).unwrap().permissions().mode() & 0o777, 0o640);
    let no_gate = rig.call("pin_prepare", json!({}));
    let wrong = rig.call("pin_prepare", json!({"gate": "0".repeat(64)}));
    let prep = rig.call("pin_prepare", json!({"gate": gate}));
    let code = std::fs::read_to_string(rig.root.join(".run/enroll-code")).unwrap().trim().to_string();
    let set = rig.call("pin_set", json!({"pin": "4821", "code": code, "gate": gate}));
    let (no_gate_sign, _) = policy_change_with_pin(&rig, "4821", &json!({}));
    let (signed, done) = policy_change_with_pin(&rig, "4821", &json!({"gate": gate}));
    std::env::remove_var(xbt_signer::admin::ENROLL_CODE_COPY_ENV);
    assert_eq!(no_gate["rule"], "pin_gate", "{no_gate}");
    assert_eq!(wrong["rule"], "pin_gate", "{wrong}");
    assert_eq!(prep["ok"], true, "{prep}");
    assert_eq!(set["ok"], true, "{set}");
    assert_eq!(no_gate_sign["rule"], "pin_gate", "{no_gate_sign}");
    assert_eq!(rig.call("pin_status", json!({}))["failures"], 0, "a call without the gate tries no PIN");
    assert_eq!((signed["ok"].as_bool(), done["ok"].as_bool()), (Some(true), Some(true)), "{signed} {done}");
}
