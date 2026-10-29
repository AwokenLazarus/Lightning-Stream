//! How a buyer reaches a seller other than by its web address (`docs/DIRECT-LINKS.md`).
//!
//! A `transport/1` document sits beside the seller's listing, signed by the same receipt key the
//! same way, and lists the links the seller can be reached by. Each link carries the seller's
//! Lightning node's signature over the link's key, so a buyer knows, before sending a byte, that
//! the far end of the link is the node it pays. It is a document of its own and not a field of the
//! listing, because apps before it refuse a listing with a field they do not know.
//!
//! The node's signature is lnd's SignMessage over a fixed text; checking it is the link crate's
//! job, so [`verify`] takes that check as a function and this crate stays free of the link.

use serde_json::{json, Map, Value};
use sha2::Digest;

use crate::json::dumps_sorted_compact;
use crate::wire::{put_field, tagged};
use xbt_primitives::ecdsa;
use xbt_primitives::secp256k1::SecretKey;

/// `version` of the document.
pub const VERSION: &str = "transport/1";
/// Where a seller with a web address also serves it.
pub const PATH: &str = "/.well-known/lightning-stream-transport.json";
/// The Nostr tag that carries it in a listing event.
pub const TAG_NAME: &str = "transport";
const TAG: &str = "xbt402/transport/1";
const MAX_LINKS: usize = 8;
const MAX_RELAYS: usize = 8;
const MAX_DIRECT: usize = 16;
/// A fetched document larger than this is refused before it is parsed.
pub const MAX_BODY: usize = 16 << 10;

/// One link to the seller: its kind (`iroh`), its key, where to look for it, until when the
/// node's word for it holds, and that word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub kind: String,
    pub endpoint_id: String,
    pub relays: Vec<String>,
    pub direct: Vec<String>,
    pub expires: u64,
    pub node_sig: String,
}

/// A checked document: whose it is and the links whose node signature held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transport {
    pub seller: String,
    pub receipt_key: String,
    pub links: Vec<Link>,
    pub updated: String,
}

/// The node-signature check: `(endpoint_id_hex, seller, expires, node_sig, node_pubkey_hex, now)`.
pub type NodeCheck<'a> = &'a dyn Fn(&str, &str, u64, &str, &str, u64) -> bool;

fn link_json(l: &Link) -> Value {
    json!({"kind": l.kind, "endpoint_id": l.endpoint_id, "relays": l.relays, "direct": l.direct,
           "expires": l.expires, "node_sig": l.node_sig})
}

/// The document before it is signed.
pub fn document(seller: &str, receipt_key: &str, links: &[Link], updated: &str) -> Value {
    json!({"version": VERSION, "seller": seller, "receipt_key": receipt_key,
           "transport": links.iter().map(link_json).collect::<Vec<_>>(), "updated": updated})
}

/// The 32 bytes the receipt key signs.
pub fn message(doc: &Value) -> [u8; 32] {
    let mut bare = doc.clone();
    if let Some(o) = bare.as_object_mut() {
        o.remove("sig");
    }
    let mut h = tagged(TAG);
    put_field(&mut h, dumps_sorted_compact(&bare).as_bytes());
    h.finalize().into()
}

/// `doc` plus `sig`, hex of the DER signature by the receipt key.
pub fn sign(sk: &SecretKey, doc: &Value) -> Value {
    let mut out = doc.clone();
    if let Some(o) = out.as_object_mut() {
        o.remove("sig");
    }
    out["sig"] = hex::encode(ecdsa::sign(sk, &message(&out))).into();
    out
}

fn hexkey(s: &str, bytes: usize) -> bool {
    s.len() == bytes * 2 && s.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

fn strings(v: Option<&Value>, max: usize, what: &str, ok: impl Fn(&str) -> bool) -> Result<Vec<String>, String> {
    let a = match v {
        None => return Ok(vec![]),
        Some(Value::Array(a)) => a,
        Some(_) => return Err(format!("{what} is a list")),
    };
    if a.len() > max {
        return Err(format!("{what} has more than {max} entries"));
    }
    a.iter()
        .map(|x| x.as_str().filter(|s| ok(s)).map(str::to_string).ok_or_else(|| format!("{what} has an entry that is not one")))
        .collect()
}

fn read_link(v: &Value) -> Result<Link, String> {
    let m = v.as_object().ok_or("a link is an object")?;
    let known = ["kind", "endpoint_id", "relays", "direct", "expires", "node_sig"];
    if let Some(k) = m.keys().find(|k| !known.contains(&k.as_str())) {
        return Err(format!("link: unknown key {k:?}"));
    }
    let kind = m.get("kind").and_then(Value::as_str).filter(|s| !s.is_empty() && s.len() <= 16).ok_or("link kind is missing")?;
    let endpoint_id = m.get("endpoint_id").and_then(Value::as_str).filter(|s| hexkey(s, 32)).ok_or("endpoint_id is 32 bytes of lower-case hex")?;
    let relays = strings(m.get("relays"), MAX_RELAYS, "relays", |s| s.starts_with("https://") && s.len() <= 200 && !s.chars().any(char::is_whitespace))?;
    let direct = strings(m.get("direct"), MAX_DIRECT, "direct", |s| s.parse::<std::net::SocketAddr>().is_ok())?;
    let expires = m.get("expires").and_then(Value::as_u64).ok_or("expires is a whole number")?;
    let node_sig = m.get("node_sig").and_then(Value::as_str).filter(|s| !s.is_empty() && s.len() <= 200).ok_or("node_sig is missing")?;
    Ok(Link { kind: kind.into(), endpoint_id: endpoint_id.into(), relays, direct, expires, node_sig: node_sig.into() })
}

/// Check `doc`: it is `seller`'s, signed by `receipt_key` (the key the seller's listing and terms
/// name), and keep only the links `node_pubkey`, the node the buyer pays, vouches for now. Links of
/// a kind this app does not know are dropped, not refused, so a seller may add new kinds.
pub fn verify(doc: &Value, seller: &str, receipt_key: &str, node_pubkey: &str, now: u64, node_check: NodeCheck) -> Result<Transport, String> {
    let m: &Map<String, Value> = doc.as_object().ok_or("a transport document is an object")?;
    let known = ["version", "seller", "receipt_key", "transport", "updated", "sig"];
    if let Some(k) = m.keys().find(|k| !known.contains(&k.as_str())) {
        return Err(format!("unknown key {k:?}"));
    }
    if m.get("version").and_then(Value::as_str) != Some(VERSION) {
        return Err(format!("version is {VERSION}"));
    }
    let doc_seller = m.get("seller").and_then(Value::as_str).ok_or("seller is missing")?;
    let origin = crate::wire::canonical_origin(seller);
    if origin.is_empty() || crate::wire::canonical_origin(doc_seller) != origin {
        return Err("the transport document is another seller's".into());
    }
    let key = m.get("receipt_key").and_then(Value::as_str).ok_or("receipt_key is missing")?;
    if key != receipt_key {
        return Err("the transport document is signed by another key than the seller's listing".into());
    }
    let sig = hex::decode(m.get("sig").and_then(Value::as_str).ok_or("sig is missing")?).map_err(|_| "sig is hex")?;
    let pk = hex::decode(key).map_err(|_| "receipt_key is hex")?;
    if !ecdsa::verify(&pk, &message(doc), &sig) {
        return Err("the signature does not verify".into());
    }
    let list = m.get("transport").and_then(Value::as_array).ok_or("transport is a list")?;
    if list.len() > MAX_LINKS {
        return Err(format!("more than {MAX_LINKS} links"));
    }
    let mut links = vec![];
    for v in list {
        let l = read_link(v)?;
        if l.kind == "iroh" && l.expires > now && node_check(&l.endpoint_id, doc_seller, l.expires, &l.node_sig, node_pubkey, now) {
            links.push(l);
        }
    }
    Ok(Transport {
        seller: doc_seller.to_string(),
        receipt_key: key.to_string(),
        links,
        updated: m.get("updated").and_then(Value::as_str).unwrap_or_default().to_string(),
    })
}

/// The first iroh link of `doc` that `node_pubkey` vouches for, for a buyer about to dial: what the
/// signer calls before it binds the shop's name to a link. `None` when there is none, or the
/// document does not check out; the buyer then uses the seller's web address, if it has one.
pub fn verified_iroh(doc: &Value, seller: &str, receipt_key: &str, node_pubkey: &str, now: u64, node_check: NodeCheck) -> Option<Link> {
    verify(doc, seller, receipt_key, node_pubkey, now, node_check).ok()?.links.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use xbt_primitives::secp256k1::{PublicKey, Secp256k1};

    const NODE: &str = "02c86d8dd97ac82338edece395f29369253894033464315c8d9e086a8cafe3a3b6";
    const EP: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn key() -> (SecretKey, String) {
        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        (sk, hex::encode(pk.serialize()))
    }

    fn link(expires: u64) -> Link {
        Link { kind: "iroh".into(), endpoint_id: EP.into(), relays: vec!["https://relay.example".into()], direct: vec!["192.0.2.1:4433".into()],
               expires, node_sig: "goodsig".into() }
    }

    // stands in for the link crate's lnd SignMessage check: only NODE's "goodsig" holds
    fn check(_ep: &str, _seller: &str, _exp: u64, sig: &str, node: &str, _now: u64) -> bool {
        sig == "goodsig" && node == NODE
    }

    fn signed(seller: &str, links: &[Link]) -> (Value, String) {
        let (sk, pk) = key();
        (sign(&sk, &document(seller, &pk, links, "2026-10-29")), pk)
    }

    #[test]
    fn a_signed_document_gives_its_vouched_links() {
        let seller = "http://abc.shop.invalid";
        let (doc, pk) = signed(seller, &[link(2_000)]);
        let t = verify(&doc, seller, &pk, NODE, 1_000, &check).unwrap();
        assert_eq!(t.links, vec![link(2_000)]);
        assert_eq!(verified_iroh(&doc, seller, &pk, NODE, 1_000, &check), Some(link(2_000)));
    }

    #[test]
    fn a_link_another_node_vouches_for_or_one_expired_is_dropped() {
        let seller = "https://shop.example";
        let mut other = link(2_000);
        other.node_sig = "forged".into();
        let (doc, pk) = signed(seller, &[link(500), other]);
        assert!(verify(&doc, seller, &pk, NODE, 1_000, &check).unwrap().links.is_empty());
        assert_eq!(verified_iroh(&doc, seller, &pk, NODE, 1_000, &check), None);
        let (doc, pk) = signed(seller, &[link(2_000)]);
        assert!(verify(&doc, seller, &pk, "03ffff", 1_000, &check).unwrap().links.is_empty());
    }

    #[test]
    fn another_sellers_or_another_keys_document_or_a_changed_one_is_refused() {
        let (doc, pk) = signed("https://shop.example", &[link(2_000)]);
        assert!(verify(&doc, "https://other.example", &pk, NODE, 1_000, &check).is_err());
        let other_pk = "03".to_string() + &"a".repeat(64);
        assert!(verify(&doc, "https://shop.example", &other_pk, NODE, 1_000, &check).is_err());
        let mut changed = doc.clone();
        changed["transport"][0]["endpoint_id"] = json!("2".repeat(64));
        assert!(verify(&changed, "https://shop.example", &pk, NODE, 1_000, &check).is_err());
        let mut extra = doc.clone();
        extra["port"] = json!(1);
        assert!(verify(&extra, "https://shop.example", &pk, NODE, 1_000, &check).is_err());
    }

    #[test]
    fn a_kind_this_app_does_not_know_is_skipped_not_refused() {
        let mut tor = link(2_000);
        tor.kind = "tor".into();
        let (doc, pk) = signed("https://shop.example", &[tor, link(2_000)]);
        assert_eq!(verify(&doc, "https://shop.example", &pk, NODE, 1_000, &check).unwrap().links, vec![link(2_000)]);
    }

    #[test]
    fn malformed_links_are_refused() {
        let mut bad = link(2_000);
        bad.endpoint_id = "ABCD".into();
        let (doc, pk) = signed("https://shop.example", &[bad]);
        assert!(verify(&doc, "https://shop.example", &pk, NODE, 1_000, &check).is_err());
        let mut bad = link(2_000);
        bad.relays = vec!["http://plain.example".into()];
        let (doc, pk) = signed("https://shop.example", &[bad]);
        assert!(verify(&doc, "https://shop.example", &pk, NODE, 1_000, &check).is_err());
    }
}
