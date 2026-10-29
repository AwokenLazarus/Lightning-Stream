//! A seller reached by key (`docs/DIRECT-LINKS.md`): before a byte goes to it, `xbt402_pay` checks
//! the seller's transport document (signed by its receipt key, each link vouched for by its node
//! until an expiry), and only then tells the wire where the link is. Here the wire only records
//! what it was told: a good document is learned, with the shop's own Nostr key as the only author
//! believed for where the link is; a document with a bad signature, an expired link, another
//! receipt key or another node is refused with nothing learned; a shop without a web address and
//! no document is refused too.
mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use serde_json::{json, Value};
use xbt402::transport::{self, Link};
use xbt_primitives::secp256k1::{PublicKey, Secp256k1, SecretKey};
use xbt_signer::signer::{Signer, SignerOptions};
use xbt_signer::ticket_pay::{TicketWire, WireAnswer};

const EP: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// What the signer told the wire: (origin, endpoint id, the Nostr author believed).
type Learned = (String, String, Option<String>);

/// A wire that sends nothing and records each link it is told of.
#[derive(Default)]
struct Rec {
    learned: Mutex<Vec<Learned>>,
}

impl TicketWire for Rec {
    fn send(&self, _: &str, _: &str, _: &[u8], _: &[(String, String)], _: Duration) -> xbt402::Result<WireAnswer> {
        Err(xbt402::ChannelError::new("transport_error", "this test sends nothing"))
    }

    fn learn_link(&self, origin: &str, link: &Link, nostr_author: Option<&str>) -> xbt402::Result<()> {
        self.learned.lock().unwrap().push((origin.into(), link.endpoint_id.clone(), nostr_author.map(str::to_string)));
        Ok(())
    }
}

fn keypair(b: u8) -> (SecretKey, String) {
    let sk = SecretKey::from_slice(&[b; 32]).unwrap();
    (sk, hex::encode(PublicKey::from_secret_key(&Secp256k1::new(), &sk).serialize()))
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// A link to `seller`, vouched for by `node` until `expires`.
fn link(seller: &str, expires: u64, node: &SecretKey) -> Link {
    Link { kind: "iroh".into(), endpoint_id: EP.into(), relays: vec!["https://relay.example".into()], direct: vec!["192.0.2.1:4433".into()], expires,
           node_sig: xbt402::claim::sign(xbt402::claim::claim_text(EP, seller, expires).as_bytes(), node) }
}

/// A shop known by its Nostr key: its origin, its receipt key pair, its node pair.
struct Shop {
    origin: String,
    author: String,
    receipt: (SecretKey, String),
    node: (SecretKey, String),
}

fn shop() -> Shop {
    let nostr = [0x42u8; 32];
    Shop { origin: xbt402::shop::origin_for(&nostr), author: hex::encode(nostr), receipt: keypair(7), node: keypair(9) }
}

impl Shop {
    fn doc(&self, links: &[Link]) -> Value {
        transport::sign(&self.receipt.0, &transport::document(&self.origin, &self.receipt.1, links, "2026-10-29"))
    }
}

/// A signer whose owner allowed `shop`, paid through its node, with the given wire.
fn signer(dir: &std::path::Path, shop: &Shop, wire: &Arc<Rec>) -> Arc<Signer> {
    let pol = runbook_policy(json!({"allowlist": [PROVIDER, ADDR, shop.origin],
                                    "counterparties": {shop.origin.clone(): {"ln_node": shop.node.1}},
                                    "tickets": {"enabled": true, "tasks": {"film": {"budget_sats": 5_000}}}}));
    let root = root_with(dir, &pol);
    let chain = FakeChain::new("regtest", 6_720);
    Signer::new(&root, SignerOptions { node: Some(chain), ticket_wire: Some(wire.clone()), ..Default::default() }).unwrap()
}

fn pay(s: &Signer, shop: &Shop, doc: Option<Value>, receipt_key: &str) -> Value {
    let mut p = json!({"url": format!("{}/film", shop.origin), "max_sats": 1_000, "task": "film", "receipt_key": receipt_key});
    if let Some(d) = doc {
        p["transport"] = d;
    }
    call(s, "xbt402_pay", p)
}

fn refused_for_transport(v: &Value) -> bool {
    v["verdict"] == "deny" && v["rule"] == "transport"
}

#[test]
fn a_good_document_is_learned_with_the_shops_own_key_as_the_author() {
    let dir = tempfile::tempdir().unwrap();
    let _env = env_lock();
    env_for(dir.path());
    let shop = shop();
    let wire = Arc::new(Rec::default());
    let s = signer(dir.path(), &shop, &wire);
    let v = pay(&s, &shop, Some(shop.doc(&[link(&shop.origin, now() + 3_600, &shop.node.0)])), &shop.receipt.1);
    assert!(!refused_for_transport(&v), "a good document was refused: {v}");
    let learned = wire.learned.lock().unwrap().clone();
    assert_eq!(learned, vec![(shop.origin.clone(), EP.to_string(), Some(shop.author.clone()))]);
}

#[test]
fn a_bad_signature_an_expired_link_another_receipt_key_or_another_node_is_refused_and_nothing_is_learned() {
    let dir = tempfile::tempdir().unwrap();
    let _env = env_lock();
    env_for(dir.path());
    let shop = shop();
    let wire = Arc::new(Rec::default());
    let s = signer(dir.path(), &shop, &wire);
    let good = link(&shop.origin, now() + 3_600, &shop.node.0);

    // the document changed after the receipt key signed it
    let mut tampered = shop.doc(std::slice::from_ref(&good));
    tampered["transport"][0]["endpoint_id"] = json!("2".repeat(64));
    // the node's word for the link has run out
    let expired = shop.doc(&[link(&shop.origin, now() - 60, &shop.node.0)]);
    // another node vouches for the link than the one the owner pays this seller through
    let other_node = shop.doc(&[link(&shop.origin, now() + 3_600, &keypair(8).0)]);
    // signed by a receipt key that is not the shop's
    let (rk_other, rk_other_pub) = keypair(5);
    let other_key = transport::sign(&rk_other, &transport::document(&shop.origin, &rk_other_pub, std::slice::from_ref(&good), "2026-10-29"));

    for (what, doc, rk) in [("tampered", tampered, shop.receipt.1.clone()), ("expired", expired, shop.receipt.1.clone()),
                            ("other node", other_node, shop.receipt.1.clone()), ("other receipt key", other_key, shop.receipt.1.clone())] {
        let v = pay(&s, &shop, Some(doc), &rk);
        assert!(refused_for_transport(&v), "{what}: not refused for its transport: {v}");
    }
    // the shop's own document, checked against a receipt key the call names wrongly
    let v = pay(&s, &shop, Some(shop.doc(std::slice::from_ref(&good))), &rk_other_pub);
    assert!(refused_for_transport(&v), "a wrong receipt key in the call: {v}");
    assert!(wire.learned.lock().unwrap().is_empty(), "a refused document was learned");
}

#[test]
fn a_shop_without_a_web_address_and_no_document_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let _env = env_lock();
    env_for(dir.path());
    let shop = shop();
    let wire = Arc::new(Rec::default());
    let s = signer(dir.path(), &shop, &wire);
    std::env::remove_var("XBT_SHOPS_FILE");
    let v = pay(&s, &shop, None, &shop.receipt.1);
    assert!(refused_for_transport(&v), "a shop by key with no transport document: {v}");
    assert!(wire.learned.lock().unwrap().is_empty());
}

#[test]
fn a_shop_added_in_the_app_is_read_from_the_shops_file() {
    let dir = tempfile::tempdir().unwrap();
    let _env = env_lock();
    env_for(dir.path());
    let shop = shop();
    let wire = Arc::new(Rec::default());
    let s = signer(dir.path(), &shop, &wire);
    let file = dir.path().join("shops.json");
    let doc = shop.doc(&[link(&shop.origin, now() + 3_600, &shop.node.0)]);
    std::fs::write(&file, json!({shop.origin.clone(): {"receipt_key": shop.receipt.1, "transport": doc}}).to_string()).unwrap();
    std::env::set_var("XBT_SHOPS_FILE", &file);
    let v = call(&s, "xbt402_pay", json!({"url": format!("{}/film", shop.origin), "max_sats": 1_000, "task": "film"}));
    std::env::remove_var("XBT_SHOPS_FILE");
    assert!(!refused_for_transport(&v), "the shops file's document was refused: {v}");
    assert_eq!(wire.learned.lock().unwrap().len(), 1);
}
