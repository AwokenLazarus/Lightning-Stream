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

/// The node behind the open key, in memory: what it was asked, in order.
#[derive(Default)]
struct FakeOpen {
    calls: std::sync::Mutex<Vec<String>>,
    unreachable: std::sync::atomic::AtomicBool,
}

impl xbt_signer::ln_open::OpenBackend for FakeOpen {
    fn new_address(&self) -> xbt402::Result<String> {
        let mut c = self.calls.lock().unwrap();
        c.push("address".into());
        Ok(TO.to_string())
    }
    fn connect(&self, pubkey: &str, host: &str) -> xbt402::Result<()> {
        if self.unreachable.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(xbt_signer::err("ln_backend", "dial tcp: i/o timeout"));
        }
        self.calls.lock().unwrap().push(format!("connect {pubkey}@{host}"));
        Ok(())
    }
    fn open(&self, pubkey: &str, txid: &str, vout: u32) -> xbt402::Result<String> {
        self.calls.lock().unwrap().push(format!("open {pubkey} {txid}:{vout}"));
        Ok("ff".repeat(32))
    }
    fn pending(&self) -> xbt402::Result<Vec<serde_json::Value>> {
        Ok(vec![])
    }
}

/// With the open key: the deposit goes only to an address the node gave, and one channel opens, to the peer the
/// owner signed for, from that forwarded deposit alone, once it has a confirmation.
#[test]
fn with_the_open_key_the_deposit_goes_to_the_node_and_one_channel_opens_from_it() {
    use xbt_signer::approval::channel_open_message;
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    env_for(dir.path());
    let chain = FakeChain::new("regtest", 6_720);
    let root = root_with(dir.path(), &runbook_policy(json!({})));
    let node = std::sync::Arc::new(FakeOpen::default());
    let s = xbt_signer::signer::Signer::new(&root, xbt_signer::signer::SignerOptions { node: Some(chain.clone()), ln_open: Some(node.clone()), ..Default::default() }).unwrap();
    let st = call(&s, "deposit_status", json!({}));
    let (addr, script) = (st["address"].as_str().unwrap().to_string(), st["script"].as_str().unwrap().to_string());
    chain.credit(&hex::encode([0x71; 32]), 0, 250_000, &script, true);
    let exp = xbt_signer::pyjson::now_f64() as i64 + 600;

    // an address the node did not give is refused, even signed for
    let r = call(&s, "deposit_forward", json!({"to": TO, "expiry": exp, "signature": sign_human(&deposit_forward_message(&addr, TO, exp))}));
    assert!(r["ok"] == false && r["reason"].as_str().unwrap().contains("not an address your Lightning node gave"), "{r}");
    let a = call(&s, "funding_address", json!({}));
    assert_eq!((a["ok"].as_bool(), a["address"].as_str()), (Some(true), Some(TO)), "{a}");
    let exp2 = exp + 1;
    let f = call(&s, "deposit_forward", json!({"to": TO, "expiry": exp2, "signature": sign_human(&deposit_forward_message(&addr, TO, exp2))}));
    assert_eq!(f["ok"], true, "{f}");
    let fwd = f["txid"].as_str().unwrap().to_string();

    let peer = format!("02{}", "ab".repeat(32));
    let host = "203.0.113.7:9735";
    let open = |txid: &str, peer: &str, exp: i64| call(&s, "channel_open", json!({"peer": peer, "host": host, "forward_txid": txid, "expiry": exp,
        "signature": sign_human(&channel_open_message(peer, host, txid, exp))}));
    // not before the forwarded deposit confirms
    let r = open(&fwd, &peer, exp);
    assert!(r["ok"] == false && r["wait"] == true, "{r}");
    chain.mine(1);
    let st = call(&s, "funding_status", json!({}));
    assert!(st["open_key"] == true && st["forwards"][0]["txid"] == fwd.as_str() && st["forwards"][0]["confirmations"] == 1, "{st}");
    // never from a coin the signer did not forward; never on a signature for another peer
    let r = open(&hex::encode([0x71; 32]), &peer, exp);
    assert!(r["ok"] == false && r["reason"].as_str().unwrap().contains("not a deposit this app forwarded"), "{r}");
    let other = format!("03{}", "cd".repeat(32));
    let r = call(&s, "channel_open", json!({"peer": other, "host": host, "forward_txid": fwd, "expiry": exp,
        "signature": sign_human(&channel_open_message(&peer, host, &fwd, exp))}));
    assert!(r["ok"] == false && r["reason"].as_str().unwrap().contains("human signature"), "{r}");
    // a peer that cannot be reached: nothing opened, and the same signature works once it can
    node.unreachable.store(true, std::sync::atomic::Ordering::SeqCst);
    let r = open(&fwd, &peer, exp);
    assert!(r["ok"] == false && r["retry"] == true, "{r}");
    node.unreachable.store(false, std::sync::atomic::Ordering::SeqCst);
    let r = open(&fwd, &peer, exp);
    assert_eq!((r["ok"].as_bool(), r["funding_txid"].as_str()), (Some(true), Some("ff".repeat(32).as_str())), "{r}");
    assert_eq!(*node.calls.lock().unwrap(), vec!["address".to_string(), format!("connect {peer}@{host}"), format!("open {peer} {fwd}:0")]);
    // once: not with the same signature, not with a new one
    assert_eq!(open(&fwd, &peer, exp)["ok"], false);
    let r = open(&fwd, &peer, exp + 5);
    assert!(r["ok"] == false && r["reason"].as_str().unwrap().contains("already opened"), "{r}");
    assert!(call(&s, "history", json!({"limit": 50})).to_string().contains("channel_open"));
    let st = call(&s, "funding_status", json!({}));
    assert_eq!(st["forwards"][0]["channel"]["funding_txid"].as_str(), Some("ff".repeat(32).as_str()), "{st}");
}

/// Without the open key nothing opens, and the owner is told why.
#[test]
fn without_the_open_key_no_address_is_given_and_no_channel_opens() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    let a = rig.call("funding_address", json!({}));
    assert!(a["ok"] == false && a["open_key"] == false, "{a}");
    assert_eq!(rig.call("funding_status", json!({}))["open_key"], false);
    let exp = xbt_signer::pyjson::now_f64() as i64 + 600;
    let peer = format!("02{}", "ab".repeat(32));
    let r = rig.call("channel_open", json!({"peer": peer, "host": "203.0.113.7:9735", "forward_txid": "00".repeat(32), "expiry": exp,
        "signature": sign_human(&xbt_signer::approval::channel_open_message(&peer, "203.0.113.7:9735", &"00".repeat(32), exp))}));
    assert!(r["ok"] == false && r["reason"].as_str().unwrap().contains("no key to open channels"), "{r}");
}
