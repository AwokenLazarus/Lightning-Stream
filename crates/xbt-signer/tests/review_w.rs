//! AGP-063 W1 and W2: the seller does not decide the budget, and minCapacity cannot raise the cap.
mod common;

use std::sync::Arc;

use common::*;
use serde_json::{json, Value};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::wire::{receipt_message, request_digest, settlement_response, SCHEME};
use xbt_primitives::ecdsa;
use xbt_signer::channels::ChannelRecord;
use xbt_signer::session::Session;

fn ledger_sum(rig: &Rig) -> i64 {
    let path = rig.root.join(".run/ledger.payments.jsonl");
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    text.lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v.get("dest").is_some())
        .map(|v| v["amount_sats"].as_i64().unwrap_or(0))
        .sum()
}

fn provider(chain: &Arc<FakeChain>, min_capacity: u64, charge: i64) -> Arc<Provider> {
    let mut cfg = ProviderConfig::new(&chain.network());
    cfg.policy.min_capacity = min_capacity;
    cfg.policy.max_capacity = min_capacity;
    cfg.policy.min_expiry_blocks = 1_008;
    cfg.policy.min_conf = 1;
    Arc::new(Provider::new(Arc::new(ProviderChain(chain.clone())), secret("provider payTo"), cfg, Ledger::in_memory(),
                           Box::new(|_, _| 500),
                           Box::new(|_, p, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())],
                                                                  json!({"echo": p}).to_string().into_bytes()))).unwrap()
        .with_charge(Box::new(move |_, _, _, _| charge)))
}

#[test]
fn w1_a_seller_reporting_zero_still_books_the_signed_delta() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    let hostile = provider(&rig.chain, 10_000, 0);
    rig.web.sites.lock().unwrap().insert(PROVIDER.into(), hostile);
    rig.fund_hot(1, 12_000);
    let r = rig.open();
    assert_eq!(r["verdict"], "allow", "{r}");
    assert_eq!(r["charged_sats"], 0, "the seller's receipt said nothing was charged: {r}");
    let booked = r["booked_sats"].as_i64().unwrap();
    let cum = r["cum"].as_i64().unwrap();
    assert!(booked > 0 && booked == cum, "the wallet books what it signed ({cum}), not the receipt: {r}");
    assert_eq!(ledger_sum(&rig), booked, "the policy ledger holds the signed delta");
}

#[test]
fn w1_w2_a_huge_min_capacity_and_a_zero_receipt_are_stopped_by_the_owners_cap() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({}), false);
    let hostile = provider(&rig.chain, 1_000_000_000, 0);
    rig.web.sites.lock().unwrap().insert(PROVIDER.into(), hostile);
    rig.fund_hot(1, 12_000);
    let before = rig.hot_sats();
    let r = rig.pay();
    assert_eq!((r["verdict"].as_str(), r["rule"].as_str()), (Some("deny"), Some("min_capacity")), "{r}");
    assert!(r["reason"].as_str().unwrap_or("").contains("minCapacity"), "{r}");
    assert_eq!(ledger_sum(&rig), 0, "nothing was booked");
    assert_eq!(rig.hot_sats(), before, "the inflated channel was not funded");
    assert!(rig.call("channels", json!({}))["channels"].as_array().unwrap().is_empty());
}

#[test]
fn w1_a_negative_or_oversized_charged_is_refused() {
    let sk = secret("payee");
    let pk = ecdsa::pubkey(&sk);
    let mut rec = ChannelRecord::default();
    rec.chan = "chan".into();
    rec.payee_pub = hex::encode(pk);
    rec.used_sats = 546;
    let url = URL;
    let req = request_digest("GET", "/agp015/echo", b"");
    let resp = |charged: &str| {
        let mut r = json!({"scheme": SCHEME, "chan": "chan", "seq": "1", "cum": "546", "charged": charged, "spentMsat": "0", "req": req});
        r["sig"] = hex::encode(ecdsa::sign(&sk, &receipt_message(&r))).into();
        settlement_response(&r, "net", &hex::encode(pk), true)
    };
    let neg = Session::check_seller_receipt(&rec, &resp("-5"), "GET", url, b"", 500).unwrap_err();
    assert_eq!(neg.code, "bad_receipt");
    assert!(neg.msg.contains("negative"), "{}", neg.msg);
    let over = Session::check_seller_receipt(&rec, &resp("9000"), "GET", url, b"", 500).unwrap_err();
    assert!(over.msg.contains("exceeds"), "{}", over.msg);
    assert_eq!(Session::check_seller_receipt(&rec, &resp("0"), "GET", url, b"", 500).unwrap(), 0);
}
