//! Format compatibility with B2 (Python) custody files, `vectors/b2_custody.json` (made by B2's own
//! code): the Rust signer opens B2's sealed blobs (key file and scrypt passphrase), hot.json with a
//! retired key and the sealed UTXO set, reads B2's channels.json as records it only lists, and checks
//! B2's signature log against B2's witness store, then extends both.
mod common;

use std::sync::Arc;

use common::*;
use serde_json::{json, Value};
use xbt_signer::anchor::AnchorStore;
use xbt_signer::hot::HotWallet;
use xbt_signer::keystore::KeyStore;
use xbt_signer::sigaudit::{check_chain, SigAudit};

fn vectors() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/b2_custody.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn keyfile(v: &Value) -> KeyStore {
    KeyStore::with_key(hex::decode(v["keyfile_hex"].as_str().unwrap()).unwrap().try_into().unwrap())
}

#[test]
fn opens_b2_sealed_blobs() {
    let v = vectors();
    assert_eq!(keyfile(&v).open(&v["blobs"]["keyfile"], "b2/test").unwrap().as_slice(), b"hello rust");
    let kp = KeyStore::with_passphrase(v["passphrase"].as_str().unwrap().as_bytes());
    assert_eq!(kp.open(&v["blobs"]["passphrase"], "b2/test").unwrap().as_slice(), b"hello rust");
    assert!(KeyStore::with_passphrase(b"wrong").open(&v["blobs"]["passphrase"], "b2/test").is_err());
    assert!(keyfile(&v).open(&v["blobs"]["keyfile"], "b2/hot-key").is_err(), "the AAD binds the blob to its file");
}

#[test]
fn opens_b2_hot_wallet_and_lists_its_channel_book_without_writing_it() {
    let v = vectors();
    let d = tempfile::tempdir().unwrap();
    let w = |name: &str, x: &Value| std::fs::write(d.path().join(name), x.to_string()).unwrap();
    w("hot.json", &v["hot"]["hot.json"]);
    w("hot_utxos.json", &v["hot"]["hot_utxos.json"]);
    w("channels.json", &v["channels"]["channels.json"]);
    w("channel_keys.json", &v["channels"]["channel_keys.json"]);
    let ks = Arc::new(keyfile(&v));
    let chain = FakeChain::new("regtest", 6_720);
    let hot = HotWallet::open(&d.path().join("hot.json"), chain.clone(), "bcrt", Some(ks.clone()), None, 0).unwrap();
    assert_eq!(hot.address(), v["hot"]["current_address"].as_str().unwrap());
    assert_eq!(hot.balance_sats(), v["hot"]["hot_sats"].as_i64().unwrap());
    let st = hot.status();
    assert_eq!((st["hot_retired_keys"].as_i64(), st["hot_retired_sats"].as_i64()), (Some(1), Some(700)));
    assert!(hot.key_spks().len() == 2);
    // a wrong wrapping key cannot open it
    assert!(HotWallet::open(&d.path().join("hot.json"), chain.clone(), "bcrt", Some(Arc::new(KeyStore::with_key([1; 32]))), None, 0).is_err());

    // B2's channel book is read, listed without a key, and left byte for byte as it was
    let before = (std::fs::read(d.path().join("channels.json")).unwrap(), std::fs::read(d.path().join("channel_keys.json")).unwrap());
    let legacy = xbt_signer::legacy::LegacyChannels::read(&d.path().join("channels.json"));
    let rows = legacy.public();
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0]["dest"].as_str(), rows[0]["chan"].as_str(), rows[0]["state"].as_str(), rows[0]["cap_sats"].as_i64(), rows[0]["used_sats"].as_i64()),
               (Some("http://127.0.0.1:33210"), v["channels"]["chan"].as_str(), Some("open"), Some(9400), Some(546)));
    assert!(xbt_signer::sanitize::assert_no_key_material(&json!(rows)).is_ok());
    assert_eq!(legacy.unsettled(), 1);
    assert!(legacy.notice().unwrap()["what_to_do"].as_str().unwrap().contains(xbt_signer::legacy::LAST_WITH_CHANNEL));
    assert_eq!((std::fs::read(d.path().join("channels.json")).unwrap(), std::fs::read(d.path().join("channel_keys.json")).unwrap()), before);
}

#[test]
fn checks_and_extends_b2_signature_log_and_witness_store() {
    let v = vectors();
    let d = tempfile::tempdir().unwrap();
    let log = d.path().join("signatures.jsonl");
    std::fs::write(&log, v["log"]["signatures.jsonl"].as_str().unwrap()).unwrap();
    std::fs::create_dir_all(d.path().join("anchor")).unwrap();
    std::fs::write(d.path().join("anchor/anchors.jsonl"), v["log"]["anchors.jsonl"].as_str().unwrap()).unwrap();
    let store = AnchorStore::open(&d.path().join("anchor")).unwrap();
    let latest = store.latest();
    assert_eq!(latest["n"], 2);
    let c = check_chain(&log, Some(&latest));
    assert_eq!((c["ok"].as_bool(), c["lines"].as_i64(), c["unanchored_lines"].as_i64()), (Some(true), Some(3), Some(1)), "{c}");
    // the Rust signer appends to B2's log and anchors the new lines with the same store
    let a = SigAudit::open(&log).unwrap();
    a.record("refund", b"sig", "c:0", "", json!({"rule": "watcher:auto_refund"})).unwrap();
    let lines = a.raw_lines();
    let new: Vec<String> = lines[2..].iter().map(|l| String::from_utf8(l.clone()).unwrap()).collect();
    let head = xbt_signer::sigaudit::sha256_hex(lines.last().unwrap());
    let r = store.submit(4, &head, &new, "rust");
    assert_eq!((r["ok"].as_bool(), r["n"].as_i64()), (Some(true), Some(4)), "{r}");
    assert_eq!(check_chain(&log, Some(&store.latest()))["ok"], true);
    // a line of B2's log edited afterwards fails both checks
    let text = std::fs::read_to_string(&log).unwrap().replacen("channel_state", "channel_statf", 1);
    std::fs::write(&log, text).unwrap();
    assert_eq!(check_chain(&log, Some(&store.latest()))["ok"], false);
}
