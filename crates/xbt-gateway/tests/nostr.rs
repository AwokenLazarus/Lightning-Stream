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
