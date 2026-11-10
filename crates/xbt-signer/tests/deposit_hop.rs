//! The first deposit's hop, through the signer: the box's deposit address, the coins found there, and the
//! forwarding transaction the owner signs for.
#[path = "common/mod.rs"]
mod common;

use common::*;
use serde_json::json;
use xbt_signer::approval::deposit_forward_message;

const TO: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/// A deposit at the box's address is found by a scan and sent on, whole, to the address the owner signed for:
/// once, with every signature in the signer's log, and never on a signature made for another address.
#[test]
fn a_deposit_is_found_and_forwarded_once_on_the_owner_s_signature() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    let st = rig.call("deposit_status", json!({}));
    let (addr, script) = (st["address"].as_str().unwrap().to_string(), st["script"].as_str().unwrap().to_string());
    assert!(st["ok"] == true && st["scanned"] == false && (addr.starts_with('m') || addr.starts_with('n')), "{st}");
    assert!(script.starts_with("76a914") && script.ends_with("88ac"), "a pay-to-public-key-hash script: {script}");
    assert_ne!(script, rig.hot_spk(), "not the hot wallet's own script");

    let exp = xbt_signer::pyjson::now_f64() as i64 + 600;
    let sig = sign_human(&deposit_forward_message(&addr, TO, exp));
    // nothing has arrived: nothing to forward, and the signature is not used up
    let r = rig.call("deposit_forward", json!({"to": TO, "expiry": exp, "signature": sig}));
    assert!(r["ok"] == false && r["reason"].as_str().unwrap().contains("no confirmed deposit"), "{r}");

    rig.chain.credit(&hex::encode([0x51; 32]), 0, 250_000, &script, true);
    let st = rig.call("deposit_status", json!({"scan": true}));
    assert_eq!((st["scanned"].as_bool(), st["confirmed_sats"].as_i64(), st["coins"].as_array().map(Vec::len)), (Some(true), Some(250_000), Some(1)), "{st}");

    // a signature for one address does not send to another, and no signature sends nothing
    let other = "bcrt1qmine";
    let r = rig.call("deposit_forward", json!({"to": other, "expiry": exp, "signature": sig}));
    assert!(r["ok"] == false && r["reason"].as_str().unwrap().contains("human signature"), "{r}");
    let r = rig.call("deposit_forward", json!({"to": TO, "expiry": exp, "signature": ""}));
    assert_eq!(r["ok"], false, "{r}");
    // an expired signature is refused
    let old = exp - 10_000;
    let r = rig.call("deposit_forward", json!({"to": TO, "expiry": old, "signature": sign_human(&deposit_forward_message(&addr, TO, old))}));
    assert!(r["ok"] == false && r["reason"].as_str().unwrap().contains("expired"), "{r}");

    let r = rig.call("deposit_forward", json!({"to": TO, "expiry": exp, "signature": sig}));
    assert_eq!(r["ok"], true, "{r}");
    let fee = st["fee_sats"].as_i64().unwrap();
    assert_eq!((r["sats"].as_i64(), r["fee_sats"].as_i64(), r["inputs"].as_i64()), (Some(250_000 - fee), Some(fee), Some(1)), "{r}");
    let sigs = rig.sigs();
    let last = sigs.last().unwrap();
    assert_eq!((last["kind"].as_str(), last["rule"].as_str()), (Some("deposit_forward"), Some("human:deposit_forward_signature")), "{last}");
    assert_eq!(last["txid"], r["txid"], "{last}");
    let hist = rig.call("history", json!({"limit": 50})).to_string();
    assert!(hist.contains("deposit_forward"), "in the wallet's history: {hist}");

    // the same signature again sends nothing
    rig.chain.credit(&hex::encode([0x52; 32]), 0, 100_000, &script, true);
    let again = rig.call("deposit_forward", json!({"to": TO, "expiry": exp, "signature": sig}));
    assert_eq!(again["ok"], false, "one signature forwards once: {again}");
}
