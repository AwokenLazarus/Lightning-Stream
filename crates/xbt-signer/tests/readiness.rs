//! AGP-017 mainnet readiness P3-P6 (mirrors B2 tests/test_mainnet_readiness.py; P1 and P2 were
//! about channel fundings and went with the on-chain channel).
mod common;

use common::*;
use serde_json::json;
use xbt_signer::node::Node;

#[test]
fn p3_p4_p5_mainnet_never_mines_uses_961640_and_bc_addresses() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::build(json!({"regtest_mine": null}), false, "main");
    let h = rig.call("health", json!({}));
    assert_eq!((h["chain"].as_str(), h["hrp"].as_str(), h["mining"].as_bool()), (Some("main"), Some("bc"), Some(false)));
    assert!(rig.call("hot_address", json!({}))["hot_address"].as_str().unwrap().starts_with("bc1q"));
    assert_eq!(rig.s.network().unwrap(), xbt402::wire::XBT_MAINNET);
    assert!(!rig.chain.allow_generate.load(std::sync::atomic::Ordering::SeqCst), "the RPC guard stays closed");
    // a sweep to another network's address is refused; one to bc1 is accepted
    rig.fund_hot(1, 3_000);
    let hot = rig.call("hot_address", json!({}))["hot_address"].as_str().unwrap().to_string();
    let exp = xbt_signer::pyjson::now_f64() as i64 + 600;
    for (to, ok) in [("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", false), ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", true)] {
        let sig = sign_human(&xbt_signer::approval::sweep_message(&hot, to, 2_400, exp));
        let r = rig.call("sweep_hot", json!({"to": to, "amount_sats": 2_400, "expiry": exp, "signature": sig}));
        assert_eq!(r["ok"], ok, "{to}: {r}");
    }
    drop(rig);
    // a mining policy on mainnet refuses to start
    let d = tempfile::tempdir().unwrap();
    env_for(d.path());
    let chain = FakeChain::new("main", 962_000);
    let root = root_with(d.path(), &runbook_policy(json!({"regtest_mine": true})));
    let e = signer(&root, &chain, None).unwrap_err();
    assert!(e.msg.contains("refusing to start (only regtest may mine)"), "{}", e.msg);
    // the RPC client refuses generate until the chain is known to be regtest (before any network I/O)
    let rpc = xbt_signer::node::KnotsRpc::new(d.path(), "agent");
    assert!(rpc.call("generatetoaddress", json!([1, "x"])).unwrap_err().msg.contains("mining is for regtest only"));
    assert!(rpc.call("dumpprivkey", json!(["x"])).unwrap_err().msg.contains("refuses"));
}

#[test]
fn p3_regtest_mines_only_when_the_policy_lets_it_and_keeps_block_101() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"regtest_mine": null}), false);
    assert_eq!(rig.call("health", json!({}))["mining"], true);
    assert_eq!(rig.s.network().unwrap(), rig.chain.network());
    rig.fund_hot(1, 12_000);
    // with mining on, the signer confirms its own sweep (regtest demos)
    let r = rig.rotate_hot_key();
    assert!(r["sweep"]["txid"].is_string(), "{r}");
    assert!(rig.chain.st.lock().unwrap().mined_by_signer >= 1);
}

#[test]
fn b2_chain_must_agree_with_the_node() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let d = tempfile::tempdir().unwrap();
    env_for(d.path());
    std::env::set_var("B2_CHAIN", "main");
    let chain = FakeChain::new("regtest", 6_720);
    let e = signer(&root_with(d.path(), &runbook_policy(json!({}))), &chain, None).unwrap_err();
    std::env::remove_var("B2_CHAIN");
    assert!(e.msg.contains("B2_CHAIN"), "{}", e.msg);
}

#[test]
fn p6_the_signer_never_asks_for_txindex() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    let old_spk = rig.hot_spk();
    rig.fund_hot(1, 12_000);
    rig.rotate_hot_key();
    rig.chain.credit(&"cc".repeat(32), 0, 2_000, &old_spk, true);
    rig.call("notice_hot_txid", json!({"txid": "cc".repeat(32)}));
    rig.chain.mine(2);
    rig.call("watch_tick", json!({}));
    rig.call("hot_reconcile", json!({}));
    // every getrawtransaction call either hit the mempool or named a block
    let calls = rig.chain.st.lock().unwrap().calls.clone();
    assert!(!calls.iter().any(|c| c == "getrawtransaction_txindex"));
    assert!(calls.iter().all(|c| ["getblockchaininfo", "getblockcount", "getblockhash", "getblockheader", "getblock", "sendrawtransaction", "gettxout",
                                  "getrawtransaction", "gettxspendingprevout", "scantxoutset", "getbalances", "estimatesmartfee"].contains(&c.as_str())),
            "{calls:?}");
}
