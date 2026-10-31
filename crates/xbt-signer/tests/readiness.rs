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

/// A node that does not answer (stopped, or not set up yet).
struct Away;

impl Node for Away {
    fn call(&self, _method: &str, _params: serde_json::Value) -> xbt402::Result<serde_json::Value> {
        Err(xbt_signer::err("rpc", "Connection Failed: Connect error: Connection refused (os error 111)"))
    }
}

/// With its chain said (B2_CHAIN, as the packages set it), the signer starts while its XBT node is
/// away, and `node_status` says the node does not answer: the app's page explains it, and nothing
/// restarts in a loop. Without the chain said and no node, it still refuses to start.
#[test]
fn with_its_chain_said_the_signer_starts_without_its_node_and_says_so() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let d = tempfile::tempdir().unwrap();
    env_for(d.path());
    let root = root_with(d.path(), &runbook_policy(json!({})));
    let opts = || xbt_signer::signer::SignerOptions { node: Some(std::sync::Arc::new(Away)), ..Default::default() };
    let Err(e) = xbt_signer::signer::Signer::new(&root, opts()) else { panic!("no chain, no node: no start") };
    assert!(e.msg.contains("B2_CHAIN"), "{}", e.msg);
    std::env::set_var("B2_CHAIN", "main");
    let s = xbt_signer::signer::Signer::new(&root, opts());
    std::env::remove_var("B2_CHAIN");
    let s = s.unwrap_or_else(|e| panic!("{}: {}", e.code, e.msg));
    assert_eq!(call(&s, "health", json!({}))["chain"], "main");
    let n = call(&s, "node_status", json!({}));
    assert_eq!((n["reachable"].as_bool(), n["chain"].as_str()), (Some(false), Some("main")), "{n}");
    assert!(n["reason"].as_str().unwrap().contains("Connection refused"), "{n}");
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

/// Many Umbrel and StartOS nodes are pruned. When the node can't give `getblockstats` for the tip (it answers
/// with an error, as Knots does for a block it no longer has), `mining_tip` still says the subsidy: the chain's
/// own schedule at the tip's height, which is what `getblockstats` would have said. The difficulty is still the
/// node's, so the hashmaker's market price comes out the same as on a full node.
#[test]
fn a_pruned_node_without_getblockstats_still_gives_the_tips_subsidy() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::build(json!({"regtest_mine": null}), false, "main");
    // a piece of 2^45 hashes at 100%: subsidy × work / (difficulty × 2^32), as Sell → Hashrate prices it
    let price = |v: &serde_json::Value| (v["subsidySats"].as_u64().unwrap() as f64 * 2f64.powi(45) / (v["difficulty"].as_f64().unwrap() * 4_294_967_296.0)).round();
    let full = rig.call("mining_tip", json!({}));
    assert_eq!((full["height"].as_u64(), full["subsidySats"].as_u64(), full["subsidyFrom"].as_str()), (Some(962_000), Some(312_500_000), Some("getblockstats")), "{full}");
    assert!(full["subsidyError"].is_null(), "{full}");
    assert_eq!(price(&full), 404.0);

    // pruned: getblockstats fails, and the subsidy is the schedule's at the tip; the price is the same
    rig.chain.st.lock().unwrap().subsidy = Some(None);
    let pruned = rig.call("mining_tip", json!({}));
    assert_eq!((pruned["reachable"].as_bool(), pruned["height"].as_u64(), pruned["subsidySats"].as_u64(), pruned["subsidyFrom"].as_str()),
               (Some(true), Some(962_000), Some(312_500_000), Some("schedule")), "{pruned}");
    assert!(pruned["subsidyError"].as_str().unwrap().contains("not available (pruned data)"), "{pruned}");
    assert_eq!((pruned["difficulty"].clone(), pruned["syncing"].clone()), (full["difficulty"].clone(), json!(false)));
    assert_eq!(price(&pruned), 404.0);
    assert!(rig.chain.st.lock().unwrap().calls.iter().any(|c| c == "getblockstats"), "the node is asked first");

    // the schedule follows the height: at the next halving the reward and the price halve
    rig.chain.st.lock().unwrap().height = 1_050_000;
    let after = rig.call("mining_tip", json!({}));
    assert_eq!((after["subsidySats"].as_u64(), after["subsidyFrom"].as_str()), (Some(156_250_000), Some("schedule")), "{after}");
    assert_eq!(price(&after), 202.0);

    // a node that answers getblockstats again is taken at its word
    rig.chain.st.lock().unwrap().subsidy = Some(Some(156_250_000));
    let back = rig.call("mining_tip", json!({}));
    assert_eq!((back["subsidySats"].as_u64(), back["subsidyFrom"].as_str()), (Some(156_250_000), Some("getblockstats")), "{back}");

    // a node that does not answer at all gives no subsidy and no price (nothing is made up)
    rig.chain.st.lock().unwrap().down = true;
    let away = rig.call("mining_tip", json!({}));
    assert_eq!((away["reachable"].as_bool(), away.get("subsidySats")), (Some(false), None), "{away}");
}

/// On regtest the schedule halves every 150 blocks, as Knots' regtest does.
#[test]
fn a_pruned_regtest_node_gives_the_regtest_schedule() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    {
        let mut c = rig.chain.st.lock().unwrap();
        c.subsidy = Some(None);
        c.height = 1_000;
    }
    let t = rig.call("mining_tip", json!({}));
    assert_eq!((t["subsidySats"].as_u64(), t["subsidyFrom"].as_str()), (Some(78_125_000), Some("schedule")), "{t}");
}
