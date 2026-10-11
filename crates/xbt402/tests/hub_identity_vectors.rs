//! AGP-109: `vectors/hub_identity.json`. A statement signed by a real Lightning Fork node, the
//! macaroons that node baked, and the cases a second implementation wrote and checks
//! (`scripts/hub_identity_vectors.py`): this crate must agree with it on every one.
use serde_json::Value;
use xbt402::hub_identity::{recover_node_id, verify, Statement};
use xbt402::macaroon;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/hub_identity.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("vectors/hub_identity.json")).expect("JSON")
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("{k} in {v}"))
}

#[test]
fn a_signature_made_by_a_real_lightning_fork_node_verifies() {
    let v = vectors();
    let r = &v["real_node"];
    let (node, text, sig, net, payto, until) = (s(r, "nodeId"), s(r, "statement"), s(r, "signature"), s(r, "network"), s(r, "payto"), r["until"].as_u64().unwrap());
    // the node's own answer to `lncli signmessage`, and the key `lncli getinfo` shows
    assert_eq!(recover_node_id(text.as_bytes(), sig).unwrap(), node);
    assert_eq!(recover_node_id(s(&r["plain"], "message").as_bytes(), s(&r["plain"], "signature")).unwrap(), node);
    let st = verify(text, sig, node, net, payto, until - 86_400).unwrap();
    assert_eq!(st, Statement { network: net.into(), payto: payto.into(), until });
    // run out; another key; another network; and every byte of the text and of the signature
    assert!(verify(text, sig, node, net, payto, until).unwrap_err().msg.contains("ran out"));
    assert!(verify(text, sig, node, net, &payto.replace("0279", "0379"), until - 1).is_err());
    assert!(verify(text, sig, node, "bip122:other", payto, until - 1).unwrap_err().msg.contains("network"));
    for i in 0..text.len() {
        let mut b = text.as_bytes().to_vec();
        b[i] ^= 1;
        if let Ok(t) = String::from_utf8(b) {
            assert!(verify(&t, sig, node, net, payto, until - 1).is_err(), "text byte {i}");
        }
    }
    for i in 0..sig.len() {
        let mut b = sig.as_bytes().to_vec();
        b[i] = if b[i] == b'y' { b'b' } else { b'y' };
        assert!(verify(text, &String::from_utf8(b).unwrap(), node, net, payto, until - 1).is_err(), "signature char {i}");
    }
}

#[test]
fn every_case_as_the_second_implementation_has_it() {
    let v = vectors();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 26 && cases.iter().any(|c| c["ok"] == true) && cases.iter().any(|c| c["ok"] == false));
    for c in cases {
        let got = verify(s(c, "statement"), s(c, "signature"), s(c, "nodeId"), s(c, "network"), s(c, "payto"), c["now"].as_u64().unwrap());
        assert_eq!(got.is_ok(), c["ok"].as_bool().unwrap(), "{}: {got:?}", s(c, "name"));
    }
}

#[test]
fn rule_m1_on_macaroons_a_real_node_baked() {
    let v = vectors();
    let macs = v["macaroons"].as_array().unwrap();
    assert_eq!(macs.len(), 6);
    for m in macs {
        let parsed = macaroon::parse(&hex::decode(s(m, "hex")).unwrap()).unwrap_or_else(|e| panic!("{}: {e}", s(m, "name")));
        assert!(parsed.readable(), "{}", s(m, "name"));
        match (s(m, "mainnet"), parsed.beyond_hub()) {
            ("used", None) => assert!(parsed.ops.len() == 2, "{:?}", parsed.ops),
            ("refused", Some(why)) => assert!(why.contains(s(m, "names")), "{}: {why}", s(m, "name")),
            (want, got) => panic!("{}: {want}, and the rule says {got:?} ({:?})", s(m, "name"), parsed.ops),
        }
    }
}
