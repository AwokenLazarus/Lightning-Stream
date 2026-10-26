//! Listings on Nostr against the in-process stand-in relay: published, read back, checked, and
//! refused when any one signature or the binding does not hold.
use std::time::Duration;

use serde_json::{json, Value};
use xbt402::listing;
use xbt_nostr::event::{Event, Keys};
use xbt_nostr::market::{self, KIND_CLASSIFIED};
use xbt_nostr::oneshot;
use xbt_nostr::standin::StandinRelay;
use xbt_primitives::ecdsa;
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;

const SELLER: &str = "https://media.example";
const T: Duration = Duration::from_secs(5);

fn receipt(seed: &[u8]) -> (SecretKey, String) {
    let sk = ecdsa::secret_key(&sha256(seed)).unwrap();
    let pk = hex::encode(ecdsa::pubkey(&sk));
    (sk, pk)
}

fn signed(sk: &SecretKey, pk: &str, seller: &str, name: &str) -> Value {
    let d = listing::parse_draft(&json!({
        "name": name,
        "kind": "video",
        "prices": {"byte_msat": 20000, "per_bytes": 1048576},
        "items": [{"title": "Sintel", "url": format!("{seller}/v/sintel"), "year": 2010, "credit": "(c) Blender Foundation, CC BY 3.0"}],
        "licence": "CC BY 3.0",
        "credits": "Blender Foundation",
        "updated": "2026-10-26",
    }))
    .unwrap();
    listing::sign(sk, &listing::document(&d, seller, pk))
}

fn event(keys: &Keys, sk: &SecretKey, pk: &str, seller: &str, name: &str, at: u64) -> Event {
    let doc = signed(sk, pk, seller, name);
    let bind = listing::bind(sk, &keys.public.serialize(), seller);
    market::listing_event(keys, &doc, &bind, at).unwrap()
}

fn now() -> u64 {
    xbt_nostr::now()
}

/// Re-sign an event after changing it, as a forger with their own Nostr key would.
fn resign(keys: &Keys, ev: &Event, tags: Vec<Vec<String>>) -> Event {
    Event::sign(keys, ev.created_at, ev.kind, tags, ev.content.clone())
}

fn set_tag(tags: &[Vec<String>], name: &str, value: &str) -> Vec<Vec<String>> {
    tags.iter().map(|t| if t[0] == name { vec![name.to_string(), value.to_string()] } else { t.clone() }).collect()
}

#[test]
fn a_listing_is_published_read_back_and_checked() {
    let relay = StandinRelay::start().unwrap();
    let relays = vec![relay.url.clone()];
    let keys = Keys::generate();
    let (sk, pk) = receipt(b"seller");
    let ev = event(&keys, &sk, &pk, SELLER, "Films", now());
    // what an ordinary classifieds client reads
    assert_eq!(ev.kind, KIND_CLASSIFIED);
    assert_eq!(ev.tag("d"), Some(SELLER));
    assert_eq!(ev.tag("title"), Some("Films"));
    assert!(ev.tags.iter().any(|t| t == &["price", "20", "SAT", "MiB"]));
    assert!(ev.content.contains("Sintel (2010)") && ev.content.contains("20 sat a MiB"));

    let out = oneshot::publish(&relays, &ev, T);
    assert_eq!(out[0].result, Ok(()));
    let (events, outcomes) = oneshot::query(&relays, &market::filter(100), T);
    assert_eq!(outcomes[0].result, Ok(()));
    let (got, refused) = market::collect(&events, now());
    assert_eq!((got.len(), refused), (1, 0));
    assert_eq!(got[0].listing.name, "Films");
    assert_eq!(got[0].listing.receipt_key, pk);
    assert_eq!(got[0].author, keys.public_hex());
    assert_eq!(got[0].listing.items[0].title, "Sintel");
}

#[test]
fn an_update_replaces_the_listing_and_a_new_nostr_key_is_the_same_seller() {
    let relay = StandinRelay::start().unwrap();
    let relays = vec![relay.url.clone()];
    let (sk, pk) = receipt(b"seller");
    let k1 = Keys::generate();
    let t = now() - 100;
    oneshot::publish(&relays, &event(&k1, &sk, &pk, SELLER, "Films", t), T);
    oneshot::publish(&relays, &event(&k1, &sk, &pk, SELLER, "Films, more", t + 10), T);
    let (events, _) = oneshot::query(&relays, &market::filter(100), T);
    assert_eq!(events.len(), 1, "an addressable event: the relay keeps the newest");
    // the seller moves to a new Nostr key: the receipt key binds that one too, and the newest wins
    let k2 = Keys::generate();
    oneshot::publish(&relays, &event(&k2, &sk, &pk, SELLER, "Films, moved", t + 20), T);
    let (events, _) = oneshot::query(&relays, &market::filter(100), T);
    let (got, _) = market::collect(&events, now());
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].listing.name.as_str(), got[0].author.as_str()), ("Films, moved", k2.public_hex().as_str()));
}

#[test]
fn forged_listings_and_bindings_are_refused() {
    let relay = StandinRelay::start().unwrap();
    let relays = vec![relay.url.clone()];
    let (sk, pk) = receipt(b"seller");
    let keys = Keys::generate();
    let good = event(&keys, &sk, &pk, SELLER, "Films", now());
    let forger = Keys::generate();

    // the listing changed after the receipt key signed it
    let mut doc: Value = serde_json::from_str(good.tag(market::LISTING_TAG).unwrap()).unwrap();
    doc["name"] = json!("Free films");
    let tampered = resign(&keys, &good, set_tag(&good.tags, market::LISTING_TAG, &doc.to_string()));
    assert!(market::read_event(&tampered, now()).unwrap_err().contains("signature"));

    // someone else republishes the seller's genuine listing under their own Nostr key, with the
    // seller's binding (for the seller's key) or none
    let stolen = resign(&forger, &good, good.tags.clone());
    assert!(market::read_event(&stolen, now()).unwrap_err().contains("bind"));
    let unbound: Vec<Vec<String>> = good.tags.iter().filter(|t| t[0] != market::BIND_TAG).cloned().collect();
    assert!(market::read_event(&resign(&keys, &good, unbound), now()).unwrap_err().contains("binding"));

    // a listing and binding of the forger's own receipt key, with another seller's origin as d
    let (fsk, fpk) = receipt(b"forger");
    let forger2 = Keys::generate();
    let theirs = event(&forger2, &fsk, &fpk, "https://forger.example", "Films", now());
    let as_seller = resign(&forger2, &theirs, set_tag(&theirs.tags, "d", SELLER));
    assert!(market::read_event(&as_seller, now()).unwrap_err().contains("d tag"));

    // a binding of the right keys for another seller
    let other_bind = listing::bind(&sk, &keys.public.serialize(), "https://other.example");
    let wrong_seller = resign(&keys, &good, set_tag(&good.tags, market::BIND_TAG, &other_bind));
    assert!(market::read_event(&wrong_seller, now()).is_err());

    // the event's own signature, and a date far ahead
    let mut bad_sig = good.clone();
    bad_sig.content.push('!');
    assert!(market::read_event(&bad_sig, now()).is_err());
    let ahead = Event::sign(&keys, now() + 3600, good.kind, good.tags.clone(), good.content.clone());
    assert!(market::read_event(&ahead, now()).unwrap_err().contains("future"));

    // published with the forgeries of other Nostr keys (one by the seller's own key would replace
    // its listing on any relay, and only the holder of that key can write it), only the genuine
    // one is kept
    for ev in [&good, &stolen, &as_seller] {
        oneshot::publish(&relays, ev, T);
    }
    let (events, _) = oneshot::query(&relays, &market::filter(100), T);
    let (got, refused) = market::collect(&events, now());
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].event_id, good.id);
    assert_eq!(refused, 2);
}

#[test]
fn the_writer_refuses_a_binding_that_does_not_hold() {
    let (sk, pk) = receipt(b"seller");
    let keys = Keys::generate();
    let doc = signed(&sk, &pk, SELLER, "Films");
    let for_other_key = listing::bind(&sk, &Keys::generate().public.serialize(), SELLER);
    assert!(market::listing_event(&keys, &doc, &for_other_key, now()).is_err());
}

#[test]
fn a_dead_relay_costs_its_timeout_and_the_others_answer() {
    let relay = StandinRelay::start().unwrap();
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("ws://{}", l.local_addr().unwrap())
    };
    let relays = vec![dead.clone(), relay.url.clone()];
    let (sk, pk) = receipt(b"seller");
    let keys = Keys::generate();
    let out = oneshot::publish(&relays, &event(&keys, &sk, &pk, SELLER, "Films", now()), Duration::from_secs(2));
    assert!(out.iter().any(|o| o.relay == dead && o.result.is_err()));
    assert!(out.iter().any(|o| o.relay == relay.url && o.result.is_ok()));
    let (events, _) = oneshot::query(&relays, &market::filter(10), Duration::from_secs(2));
    assert_eq!(events.len(), 1);
}
