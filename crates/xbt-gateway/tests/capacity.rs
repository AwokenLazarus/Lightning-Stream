//! A route's `capacity` (docs/CAPACITY.md): a route that serves as many buyers, or carries as many
//! long answers, as its seller lets it turns a new one away with a 503 `busy`, before anything is
//! sold or charged for it, and goes on serving the buyers it has.

mod common;

use std::time::Duration;

use common::*;
use serde_json::{json, Value};

/// The rig with `capacity` set on the route at `path`.
fn rig_with(path: &str, capacity: Value) -> (Rig, tempfile::TempDir) {
    let path = path.to_string();
    start(&move |c| {
        for r in c["routes"].as_array_mut().unwrap() {
            if r["path"] == path.as_str() {
                r["capacity"] = capacity.clone();
            }
        }
    })
}

#[test]
fn a_route_full_of_buyers_turns_a_new_one_away_before_it_buys_or_pays_anything() {
    let (rig, _dir) = rig_with("/whole/", json!({"max_buyers": 1}));
    // the first buyer is served
    let mut a = Buyer::new(&rig, 1);
    let sa = a.lock(&rig, 2);
    let got = a.get("/whole/100", Some(&sa[0]));
    assert_eq!(got.status, 200, "{}", got.error());

    // a new visit asking the price is told the shop is busy, and given no terms to buy with
    let unpaid = http(&rig.addr, "GET", "/whole/100", &[], b"", None);
    assert_eq!(unpaid.status, 503);
    assert_eq!(unpaid.header("Retry-After"), Some("30"));
    assert!(unpaid.header("PAYMENT-REQUIRED").is_none());
    let v = unpaid.json();
    assert_eq!(v["error"], "busy");
    assert_eq!(v["busy"]["scope"], "buyers");
    assert_eq!((v["busy"]["inUse"].as_u64(), v["busy"]["limit"].as_u64()), (Some(1), Some(1)));

    // a second buyer with a ticket already held is turned away with the ticket's secret untaken:
    // the ticket stays held, nothing of it is the seller's, and the session is charged nothing
    let mut b = Buyer::new(&rig, 2);
    let sb = b.lock(&rig, 1);
    let refused = b.get("/whole/100", Some(&sb[0]));
    assert_eq!(refused.status, 503, "{}", String::from_utf8_lossy(&refused.body));
    assert_eq!(refused.json()["error"], "busy");
    b.wait_state(&sb, "ACCEPTED");
    assert_eq!(b.balance(), 0);

    // the buyer served goes on
    let again = a.get("/whole/100", Some(&sa[1]));
    assert_eq!(again.status, 200, "{}", again.error());
}

#[test]
fn a_route_carrying_as_many_streams_as_it_takes_starts_no_new_one_and_charges_nothing_for_it() {
    let (rig, _dir) = rig_with("/timed/", json!({"max_streams": 1}));
    // the first buyer's stream: 400 KiB at 8 KiB every 100 ms, about 5 s
    let mut a = Buyer::new(&rig, 1);
    let sa = a.lock(&rig, 2);
    let sig = a.sign("GET", "/timed/409600", b"", Some(&sa[0]), None);
    let addr = rig.addr.clone();
    let streaming = std::thread::spawn(move || http(&addr, "GET", "/timed/409600", &[("PAYMENT-SIGNATURE", &sig)], b"", None));
    wait_for("the first stream to be open", || {
        let s = http(&rig.addr, "GET", "/services", &[], b"", None).json();
        s["routes"].as_array().unwrap().iter().any(|r| r["path"] == "/timed/" && r["capacity"]["streams"] == 1)
    });

    // the shop says it is full, where buyers' apps read it
    let services = http(&rig.addr, "GET", "/services", &[], b"", None).json();
    let timed = services["routes"].as_array().unwrap().iter().find(|r| r["path"] == "/timed/").unwrap().clone();
    assert_eq!(timed["capacity"]["busy"], true);
    assert_eq!(timed["capacity"]["maxStreams"], 1);

    // a second buyer's stream is not started; what it paid stays its credit, nothing is charged
    let mut b = Buyer::new(&rig, 2);
    let sb = b.lock(&rig, 1);
    let refused = b.get("/timed/8192", Some(&sb[0]));
    assert_eq!(refused.status, 503, "{}", String::from_utf8_lossy(&refused.body));
    assert_eq!(refused.json()["busy"]["scope"], "streams");
    let credit = b.balance();
    assert!(credit > 0, "the ticket is credit of the session");

    // the first stream is never cut off to make room
    let first = streaming.join().unwrap();
    assert_eq!(first.status, 200);
    assert_eq!(first.body.len(), 409600);

    // with it ended, the second buyer is served from its credit
    std::thread::sleep(Duration::from_millis(100));
    let served = b.get("/timed/8192", None);
    assert_eq!(served.status, 200, "{}", served.error());
    assert!(b.balance() < credit);
}

#[test]
fn a_route_with_no_capacity_reports_none_and_turns_no_one_away() {
    let (rig, _dir) = start(&|_| {});
    let services = http(&rig.addr, "GET", "/services", &[], b"", None).json();
    assert!(services["routes"].as_array().unwrap().iter().all(|r| r.get("capacity").is_none()));
    let unpaid = http(&rig.addr, "GET", "/whole/100", &[], b"", None);
    assert_eq!(unpaid.status, 402);
}

#[test]
fn a_capacity_the_gateway_cannot_keep_is_refused_when_the_config_is_read() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = |cap: Value, free: bool| {
        let mut c = config(dir.path(), "http://127.0.0.1:1", &|_| {});
        let mut route = json!({"path": "/x/", "capacity": cap});
        if free {
            route["free"] = true.into();
        } else {
            route["price"] = json!({"request_msat": 1000});
        }
        c["routes"] = json!([route]);
        xbt_gateway::config::Config::from_json(&c)
    };
    assert!(cfg(json!({"max_buyers": 2, "max_streams": 3}), false).is_ok());
    assert!(cfg(json!({"max_buyers": 0}), false).is_err());
    assert!(cfg(json!({"max_people": 2}), false).is_err());
    // a free route has no buyers to count
    assert!(cfg(json!({"max_buyers": 2}), true).is_err());
    assert!(cfg(json!({"max_streams": 2}), true).is_ok());
}
