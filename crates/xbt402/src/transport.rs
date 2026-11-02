//! How a buyer reaches a seller other than by its web address (`docs/DIRECT-LINKS.md`).
//!
//! A `transport/1` document sits beside the seller's listing, signed by the same receipt key the
//! same way, and lists the links the seller can be reached by. Each link carries the seller's
//! Lightning node's signature over the link's key, so a buyer knows, before sending a byte, that
//! the far end of the link is the node it pays. It is a document of its own and not a field of the
//! listing, because apps before it refuse a listing with a field they do not know.
//!
//! The node's signature is lnd's SignMessage over a fixed text ([`crate::claim`]).

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
pub fn verify(doc: &Value, seller: &str, receipt_key: &str, node_pubkey: &str, now: u64) -> Result<Transport, String> {
    let all = checked(doc, seller, receipt_key)?;
    let links = all.links.into_iter()
        .filter(|l| l.kind == "iroh" && crate::claim::verify(&l.endpoint_id, &all.seller, l.expires, &l.node_sig, node_pubkey, now).is_ok())
        .collect();
    Ok(Transport { links, ..all })
}

/// The node a shop without a web address is paid through: the node that vouches for its first
/// iroh link that has not expired. Such a shop has no web address whose terms could name its node,
/// and its listing names none, so its links say it: whoever holds the shop's receipt key chose
/// that node, as a seller with a web address chooses the node its terms name.
pub fn node_of(doc: &Value, seller: &str, receipt_key: &str, now: u64) -> Option<String> {
    let all = checked(doc, seller, receipt_key).ok()?;
    all.links.iter().filter(|l| l.kind == "iroh" && l.expires > now).find_map(|l| {
        let text = crate::claim::claim_text(&l.endpoint_id, &all.seller, l.expires);
        crate::claim::recover(text.as_bytes(), &l.node_sig).ok().map(|pk| hex::encode(pk.serialize()))
    })
}

/// The signature, the seller and the shape: every link is read, none is vouched for yet.
fn checked(doc: &Value, seller: &str, receipt_key: &str) -> Result<Transport, String> {
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
    let links = list.iter().map(read_link).collect::<Result<Vec<_>, _>>()?;
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
pub fn verified_iroh(doc: &Value, seller: &str, receipt_key: &str, node_pubkey: &str, now: u64) -> Option<Link> {
    verify(doc, seller, receipt_key, node_pubkey, now).ok()?.links.into_iter().next()
}

/// Every iroh link of `doc` that `node_pubkey` vouches for: one gateway serving on several keys, so
/// that buyers relayed to it do not all share one relay connection. A buyer spreads over them in its
/// own order (`xbt_iroh_link::order`) and falls back to the next. Empty when there is none.
pub fn verified_iroh_links(doc: &Value, seller: &str, receipt_key: &str, node_pubkey: &str, now: u64) -> Vec<Link> {
    verify(doc, seller, receipt_key, node_pubkey, now).map(|t| t.links).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim;
    use xbt_primitives::secp256k1::{PublicKey, Secp256k1};

    const EP: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn keypair(b: u8) -> (SecretKey, String) {
        let sk = SecretKey::from_slice(&[b; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        (sk, hex::encode(pk.serialize()))
    }

    // the seller's node
    fn node() -> (SecretKey, String) {
        keypair(9)
    }

    fn link(seller: &str, expires: u64, signer: &SecretKey) -> Link {
        Link { kind: "iroh".into(), endpoint_id: EP.into(), relays: vec!["https://relay.example".into()], direct: vec!["192.0.2.1:4433".into()],
               expires, node_sig: claim::sign(claim::claim_text(EP, seller, expires).as_bytes(), signer) }
    }

    fn signed(seller: &str, links: &[Link]) -> (Value, String) {
        let (sk, pk) = keypair(7);
        (sign(&sk, &document(seller, &pk, links, "2026-10-29")), pk)
    }

    #[test]
    fn a_signed_document_gives_the_links_its_node_vouches_for() {
        let seller = "http://abc.shop.invalid";
        let (nk, np) = node();
        let l = link(seller, 2_000, &nk);
        let (doc, pk) = signed(seller, std::slice::from_ref(&l));
        assert_eq!(verify(&doc, seller, &pk, &np, 1_000).unwrap().links, vec![l.clone()]);
        assert_eq!(verified_iroh(&doc, seller, &pk, &np, 1_000), Some(l.clone()));
        assert_eq!(verified_iroh_links(&doc, seller, &pk, &np, 1_000), vec![l]);
        assert_eq!(node_of(&doc, seller, &pk, 1_000), Some(np));
    }

    #[test]
    fn a_link_another_node_vouches_for_or_one_expired_is_dropped() {
        let seller = "https://shop.example";
        let (nk, np) = node();
        let (other, _) = keypair(8);
        let (doc, pk) = signed(seller, &[link(seller, 500, &nk), link(seller, 2_000, &other)]);
        assert!(verify(&doc, seller, &pk, &np, 1_000).unwrap().links.is_empty());
        assert_eq!(verified_iroh(&doc, seller, &pk, &np, 1_000), None);
        // the link signed for another seller does not vouch for this one
        let (doc, pk) = signed(seller, &[link("https://other.example", 2_000, &nk)]);
        assert!(verify(&doc, seller, &pk, &np, 1_000).unwrap().links.is_empty());
        assert_ne!(node_of(&doc, seller, &pk, 1_000), Some(np));
    }

    #[test]
    fn another_sellers_or_another_keys_document_or_a_changed_one_is_refused() {
        let seller = "https://shop.example";
        let (nk, np) = node();
        let (doc, pk) = signed(seller, &[link(seller, 2_000, &nk)]);
        assert!(verify(&doc, "https://other.example", &pk, &np, 1_000).is_err());
        assert!(verify(&doc, seller, &keypair(5).1, &np, 1_000).is_err());
        let mut changed = doc.clone();
        changed["transport"][0]["endpoint_id"] = json!("2".repeat(64));
        assert!(verify(&changed, seller, &pk, &np, 1_000).is_err());
        let mut extra = doc.clone();
        extra["port"] = json!(1);
        assert!(verify(&extra, seller, &pk, &np, 1_000).is_err());
        assert_eq!(node_of(&changed, seller, &pk, 1_000), None);
    }

    #[test]
    fn a_shop_on_several_keys_gives_every_key_its_node_vouches_for() {
        let seller = "http://abc.shop.invalid";
        let (nk, np) = node();
        let (other, _) = keypair(8);
        let keyed = |ep: &str, signer: &SecretKey| Link {
            endpoint_id: ep.into(),
            node_sig: claim::sign(claim::claim_text(ep, seller, 2_000).as_bytes(), signer),
            ..link(seller, 2_000, &nk)
        };
        let (a, b, c) = (keyed(&"1".repeat(64), &nk), keyed(&"2".repeat(64), &other), keyed(&"3".repeat(64), &nk));
        let (doc, pk) = signed(seller, &[a.clone(), b, c.clone()]);
        assert_eq!(verified_iroh_links(&doc, seller, &pk, &np, 1_000), vec![a.clone(), c]);
        assert_eq!(verified_iroh(&doc, seller, &pk, &np, 1_000), Some(a), "an app before several keys takes the first");
        assert!(verified_iroh_links(&doc, seller, &pk, &np, 3_000).is_empty());
    }

    #[test]
    fn a_kind_this_app_does_not_know_is_skipped_not_refused() {
        let seller = "https://shop.example";
        let (nk, np) = node();
        let mut tor = link(seller, 2_000, &nk);
        tor.kind = "tor".into();
        let l = link(seller, 2_000, &nk);
        let (doc, pk) = signed(seller, &[tor, l.clone()]);
        assert_eq!(verify(&doc, seller, &pk, &np, 1_000).unwrap().links, vec![l]);
    }

    #[test]
    fn malformed_links_are_refused() {
        let seller = "https://shop.example";
        let (nk, np) = node();
        let mut bad = link(seller, 2_000, &nk);
        bad.endpoint_id = "ABCD".into();
        let (doc, pk) = signed(seller, &[bad]);
        assert!(verify(&doc, seller, &pk, &np, 1_000).is_err());
        let mut bad = link(seller, 2_000, &nk);
        bad.relays = vec!["http://plain.example".into()];
        let (doc, pk) = signed(seller, &[bad]);
        assert!(verify(&doc, seller, &pk, &np, 1_000).is_err());
    }
}
