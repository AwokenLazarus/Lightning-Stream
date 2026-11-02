//! The gateway's listing on Nostr, against the in-process stand-in relay: what a buyer's app reads
//! back is the listing the gateway serves, under the key its 402 terms name.
#![allow(dead_code)]
mod common;

use std::time::Duration;

use common::*;
use serde_json::json;
use xbt_gateway::nostr;
use xbt_nostr::market;
use xbt_nostr::oneshot;
use xbt_nostr::standin::StandinRelay;

fn with_listing(v: &mut serde_json::Value) {
    v["listing"] = json!({
        "name": "Films",
        "kind": "video",
        "prices": {"byte_msat": 20000, "per_bytes": 1048576},
        "items": [{"title": "Sintel", "url": "https://media.example/Videos/s", "year": 2010, "credit": "(c) Blender Foundation"}],
        "licence": "CC BY 3.0",
        "credits": "(c) Blender Foundation, CC BY 3.0",
        "updated": "2026-10-26",
    });
}

#[test]
fn the_gateway_publishes_its_listing_bound_to_its_receipt_key() {
    let relay = StandinRelay::start().unwrap();
    let relays = vec![relay.url.clone()];
    let (rig, dir) = start(&with_listing);
    let keys = nostr::load_key(dir.path()).unwrap();
    assert_eq!(nostr::load_key(dir.path()).unwrap().public_hex(), keys.public_hex(), "the key is kept");

    let out = nostr::publish_once(&rig.gw, &keys, &relays, xbt_nostr::now()).unwrap();
    assert_eq!(out[0].result, Ok(()));
    let (events, _) = oneshot::query(&relays, &market::filter(10), Duration::from_secs(5));
    let (got, refused) = market::collect(&events, xbt_nostr::now());
    assert_eq!((got.len(), refused), (1, 0));
    let l = &got[0];
    assert_eq!(l.author, keys.public_hex());
    assert_eq!(l.listing.receipt_key, rig.gw.terms().receipt_key);
    assert_eq!(l.listing.seller, rig.origin);
    // the same document the well-known URL serves
    let served = http(&rig.addr, "GET", "/.well-known/lightning-stream.json", &[], b"", None);
    let ev = &relay.events(market::KIND_CLASSIFIED)[0];
    assert_eq!(serde_json::from_str::<serde_json::Value>(ev.tag(market::LISTING_TAG).unwrap()).unwrap(), served.json());
}

#[test]
fn without_a_listing_nothing_is_published() {
    let relay = StandinRelay::start().unwrap();
    let (rig, dir) = start(&|_| {});
    let keys = nostr::load_key(dir.path()).unwrap();
    assert!(nostr::publish_once(&rig.gw, &keys, std::slice::from_ref(&relay.url), xbt_nostr::now()).is_err());
    assert!(relay.events(market::KIND_CLASSIFIED).is_empty());
}

/// #40: a shop that moves (here a new web address; turning Private moves it to its key's address the
/// same way) lists itself under the new address, and withdraws the listing it left at the old one with
/// a NIP-09 deletion signed by the same key. A buyer's app reads only the shop as it is now, also from
/// a relay that keeps deleted events.
///
/// FAILS before: the old listing stayed, nothing withdrew it, and Found on Nostr listed the shop twice.
#[test]
fn a_shop_that_moves_withdraws_its_old_listing() {
    let relay = StandinRelay::start().unwrap();
    let relays = vec![relay.url.clone()];
    let (rig, dir) = start(&with_listing);
    let keys = nostr::load_key(dir.path()).unwrap();
    let now = xbt_nostr::now();
    nostr::publish_once(&rig.gw, &keys, &relays, now - 10).unwrap();
    assert!(relay.events(nostr::KIND_DELETION).is_empty(), "nothing to withdraw while the shop has not moved");
    let old_id = relay.events(market::KIND_CLASSIFIED)[0].id.clone();
    let (node, service, clock) = rig.stop();
    let moved = start_on(dir.path(), node, service, clock, &|v| {
        with_listing(v);
        v["public_url"] = json!("http://moved.test:8402");
    });
    let out = nostr::publish_once(&moved.gw, &keys, &relays, now).unwrap();
    assert_eq!(out[0].result, Ok(()));
    let del = relay.events(nostr::KIND_DELETION);
    assert_eq!(del.len(), 1, "{del:?}");
    let d = &del[0];
    assert!(d.verify() && d.pubkey == keys.public_hex(), "signed by the shop's own Nostr key");
    let tags = |n: &str| d.tags.iter().filter(|t| t[0] == n).map(|t| t[1].clone()).collect::<Vec<_>>();
    assert_eq!(tags("a"), [format!("30402:{}:http://gateway.test:8402", keys.public_hex())]);
    assert_eq!(tags("e"), [old_id]);
    assert_eq!(tags("k"), ["30402"]);
    // the stand-in keeps both listings, as a relay that ignores deletions does: the reader keeps the newest
    let (events, _) = oneshot::query(&relays, &market::filter(10), Duration::from_secs(5));
    assert_eq!(events.len(), 2);
    let (got, _) = market::collect(&events, xbt_nostr::now());
    let newest = got.iter().max_by_key(|l| l.created_at).unwrap();
    assert_eq!(newest.listing.seller, "http://moved.test:8402", "the wallet keeps only the newest of one key's listings");
    // the listing at the new address is never withdrawn
    assert!(!d.tags.iter().any(|t| t.get(1).is_some_and(|v| v.contains("moved.test"))));
}
