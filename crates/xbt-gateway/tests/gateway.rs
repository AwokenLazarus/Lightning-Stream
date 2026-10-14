//! The seller gateway through its own listener, with a stand-in node and a real service behind
//! it. Each test names the rule it holds the gateway to; `scripts/gateway_regtest.sh` holds the
//! shipped binary to the same rules on Lightning Fork nodes.
mod common;

use std::time::{Duration, Instant};

use common::*;
use serde_json::{json, Value};
use xbt402::ticket::ticket_hash;
use xbt402::wire::unb64json;
use xbt_gateway::node::{Channel, InvoiceState, Node};
use xbt_gateway::standin::StandIn;

const KEY: fn(&Rig) -> String = |r| r.gw.terms().receipt_key.clone();

#[test]
fn an_unpaid_request_gets_the_terms_and_reaches_nothing() {
    let (rig, _d) = start(&|_| {});
    let got = http(&rig.addr, "GET", "/files/1000", &[], b"", None);
    assert_eq!(got.status, 402);
    let pr = unb64json(got.header("PAYMENT-REQUIRED").unwrap()).unwrap();
    assert_eq!(pr, got.json());
    let a = &pr["accepts"][0];
    assert_eq!(
        (
            a["scheme"].as_str(),
            a["network"].as_str(),
            a["asset"].as_str()
        ),
        (Some("ticket"), Some(NET), Some("XBT:msat"))
    );
    assert_eq!(a["payTo"], "02".repeat(33));
    let x = &a["extra"];
    assert_eq!(
        (
            x["version"].as_str(),
            x["ticketMsat"].as_str(),
            x["maxTickets"].as_u64(),
            x["ticketBlocks"].as_u64()
        ),
        (Some("ticket/0"), Some("1000000"), Some(8), Some(40))
    );
    assert_eq!(
        (
            x["release"].as_str(),
            x["settle"].as_str(),
            x["session"].as_str()
        ),
        (Some("with-request"), Some("on-use"), Some("/x402/ticket"))
    );
    assert_eq!(
        x["price"],
        json!({"requestMsat": "0", "byteMsat": "1000", "perBytes": "1048576", "secondMsat": "0"})
    );
    assert_eq!(x["receiptKey"], KEY(&rig));
    assert_eq!(pr["resource"]["url"], "http://gateway.test:8402/files/1000");
    assert_eq!(
        http(&rig.addr, "GET", "/verify/10", &[], b"", None).json()["accepts"][0]["extra"]
            ["release"],
        "after-verify"
    );
    // a path with no route, a method the route does not take: never the service
    assert_eq!(
        http(&rig.addr, "GET", "/elsewhere", &[], b"", None).status,
        404
    );
    assert_eq!(
        http(&rig.addr, "DELETE", "/api", &[], b"", None).status,
        405
    );
    assert_eq!(
        http(&rig.addr, "POST", "/files/10", &[], b"", None).status,
        405
    );
    assert_eq!(rig.hits(), 0);
    // a free route is served to anyone
    let free = http(&rig.addr, "GET", "/files/free/5000", &[], b"", None);
    assert_eq!(
        (free.status, free.body.len(), free.complete),
        (200, 5000, true)
    );
    // what is sold, for anyone who asks
    let s = http(&rig.addr, "GET", "/services", &[], b"", None).json();
    assert_eq!(
        (
            s["signed"].as_bool(),
            s["payTo"].as_str().map(str::len),
            s["routes"].as_array().map(Vec::len)
        ),
        (Some(false), Some(66), Some(13))
    );
}

#[test]
fn a_paid_request_is_settled_served_and_receipted() {
    let (rig, _d) = start(&|_| {});
    let mut b = Buyer::new(&rig, 1);
    let secrets = b.lock(&rig, 2);
    assert_eq!(rig.node.count(InvoiceState::Accepted), 2);
    // the secret rides in the request
    let got = b.get("/api", Some(&secrets[0]));
    assert_eq!(got.status, 200, "{}", String::from_utf8_lossy(&got.body));
    assert_eq!(got.json()["target"], "/api");
    let r = got.receipt(&KEY(&rig));
    assert_eq!(
        (
            r["releasedMsat"].as_str(),
            r["spentMsat"].as_str(),
            r["charged"].as_str(),
            r["status"].as_u64()
        ),
        (Some("1000000"), Some("2500"), Some("2500"), Some(200))
    );
    assert_eq!(r["bodyHash"], xbt402::wire::body_hash(&got.body));
    assert_eq!(
        r["req"],
        xbt402::wire::request_digest_v2("GET", "http://gateway.test:8402/api", b"")
    );
    assert_eq!(
        (r["session"].as_str(), r["seq"].as_u64()),
        (Some(b.session.as_str()), Some(b.seq - 1))
    );
    assert_eq!(
        rig.node.state_of(&ticket_hash(&secrets[0])),
        Some(InvoiceState::Settled)
    );
    // the balance pays the next ones: no secret, no call on the node
    let settles = rig.node.calls("settle");
    for n in 2..=4u64 {
        let got = b.get("/api", None);
        assert_eq!(got.status, 200);
        assert_eq!(got.receipt(&KEY(&rig))["spentMsat"], (2500 * n).to_string());
    }
    assert_eq!(rig.node.calls("settle"), settles);
    assert_eq!(
        rig.node.calls("lookup"),
        0,
        "the node's stream told the state: no lookup per request"
    );
    assert_eq!(b.balance(), 990_000);
    // a body goes through, bound to the payment
    let body = br#"{"q": 1}"#;
    let sig = b.sign("POST", "/api", body, None, None);
    let got = http(
        &rig.addr,
        "POST",
        "/api",
        &[
            ("PAYMENT-SIGNATURE", &sig),
            ("Content-Type", "application/json"),
        ],
        body,
        None,
    );
    assert_eq!(
        (got.status, got.json()["body"].as_str()),
        (200, Some(r#"{"q": 1}"#))
    );
    // every used ticket was held when it was settled, and settled within a second of arriving
    assert!(rig
        .node
        .settles()
        .iter()
        .all(|s| s.was_held && s.blocks_left > 24));
    let stats = rig.gw.stats();
    assert_eq!(stats.settled, 1);
    assert!(stats.settle_max_us < 1_000_000, "{stats:?}");
}

#[test]
fn nothing_is_served_on_a_ticket_that_is_not_accepted() {
    let (rig, _d) = start(&|_| {});
    let mut b = Buyer::new(&rig, 1);
    let secrets = b.fresh_secrets(3);
    assert_eq!(b.lock_raw(&secrets).status, 200);
    // issued, never paid: the secret buys nothing
    let got = b.get("/api", Some(&secrets[0]));
    assert_eq!(
        (got.status, got.error().as_str()),
        (402, "ticket_not_locked")
    );
    got.receipt(&KEY(&rig));
    // paid less than the ticket
    assert!(rig.node.pay_msat(&ticket_hash(&secrets[1]), Some(999_999)));
    b.wait_state(&secrets[1..2], "ACCEPTED");
    assert_eq!(
        b.get("/api", Some(&secrets[1])).error(),
        "ticket_not_locked"
    );
    // cancelled by the node after the gateway saw it held: the settle is refused, nothing is served
    assert!(rig.node.pay(&ticket_hash(&secrets[2])));
    b.wait_state(&secrets[2..], "ACCEPTED");
    rig.node.set_down(true);
    rig.node.set_down(false);
    // (the streams are broken and not yet back, so the gateway still believes ACCEPTED)
    assert!(rig.node.cancel(&ticket_hash(&secrets[2])).is_ok());
    let got = b.get("/api", Some(&secrets[2]));
    assert!(
        matches!(got.error().as_str(), "ticket_not_locked" | "ticket_unknown"),
        "{}",
        got.error()
    );
    // a secret that is no ticket's
    assert_eq!(b.get("/api", Some(&[0x77; 32])).error(), "ticket_unknown");
    assert_eq!(rig.hits(), 0, "the service was never asked");
    assert!(rig.node.settles().is_empty(), "no settle call succeeded");
    assert_eq!(b.balance(), 0);
}

#[test]
fn no_ticket_is_settled_inside_24_blocks_of_its_expiry() {
    let (rig, _d) = start(&|_| {});
    let mut b = Buyer::new(&rig, 1);
    // locked at 100 with a delta of 40: the HTLC expires at 143, usable while more than 24 are left
    let secrets = b.lock(&rig, 4);
    rig.height(118);
    assert_eq!(
        b.get("/api", Some(&secrets[0])).status,
        200,
        "25 blocks left"
    );
    rig.height(119);
    // (the janitor may already have given the ticket back: then it is unknown, and as unusable)
    let got = b.get("/api", Some(&secrets[1]));
    assert!(
        got.status == 402 && matches!(got.error().as_str(), "ticket_expiring" | "ticket_unknown"),
        "24 blocks left: {}",
        got.error()
    );
    let refused = b.release(&secrets[2..3]).json()["refused"][0]["error"].clone();
    assert!(
        refused == "ticket_expiring" || refused == "ticket_unknown",
        "{refused}"
    );
    // the gateway gives back what it can no longer use, before the node's own cancel at 18
    wait_for("the unusable tickets cancelled", || {
        rig.node.count(InvoiceState::Canceled) == 3
    });
    assert_eq!(
        rig.node
            .settles()
            .iter()
            .map(|s| s.blocks_left)
            .collect::<Vec<_>>(),
        vec![25]
    );
}

#[test]
fn no_ticket_is_settled_without_a_fresh_block_height() {
    // the janitor asks once at the start and then not again within this test
    let (rig, _d) = start(
        &|v| v["times"] = json!({"height_max_age_secs": 1, "tick_ms": 5000, "upstream_wait_secs": 2, "refill_wait_ms": 300}),
    );
    let mut b = Buyer::new(&rig, 1);
    let s = b.lock(&rig, 1);
    std::thread::sleep(Duration::from_millis(1200));
    assert_eq!(
        rig.gw.stats().height,
        None,
        "a height older than its limit is no height"
    );
    let got = b.get("/api", Some(&s[0]));
    assert_eq!(
        (got.status, got.error().as_str()),
        (503, "node_unavailable")
    );
    assert_eq!(
        (rig.node.calls("settle"), rig.hits()),
        (0, 0),
        "no settle and no service without a height: {:?} {:?}",
        rig.node.settles(),
        rig.gw.stats()
    );
    // the node is asked again: the same secret is good
    rig.gw.tick();
    assert_eq!(b.get("/api", Some(&s[0])).status, 200);
    // a node that is not there gives no height either
    let t = b.lock(&rig, 1);
    rig.node.set_down(true);
    std::thread::sleep(Duration::from_millis(1200));
    rig.gw.tick();
    assert_eq!(rig.gw.stats().height, None);
    assert_eq!(b.get("/api", Some(&t[0])).error(), "node_unavailable");
    assert_eq!(rig.node.settles().len(), 1);
}

#[test]
fn a_hostile_buyer_gets_nothing_it_did_not_pay_for() {
    let (rig, _d) = start(&|_| {});
    let mut a = Buyer::new(&rig, 1);
    let mut b = Buyer::new(&rig, 2);
    let sa = a.lock(&rig, 2);
    let sb = b.lock(&rig, 2);
    assert_eq!(a.get("/api", Some(&sa[0])).status, 200);
    let paid_hits = rig.hits();
    // a replayed request: the same header again
    let sig = a.sign("GET", "/api", b"", None, None);
    assert_eq!(
        http(
            &rig.addr,
            "GET",
            "/api",
            &[("PAYMENT-SIGNATURE", &sig)],
            b"",
            None
        )
        .status,
        200
    );
    let replay = http(
        &rig.addr,
        "GET",
        "/api",
        &[("PAYMENT-SIGNATURE", &sig)],
        b"",
        None,
    );
    assert_eq!(
        (
            replay.status,
            replay.error().as_str(),
            replay.json()["nextSeq"].as_u64()
        ),
        (402, "bad_seq", Some(a.seq))
    );
    // a replayed secret under a fresh seq
    let got = a.get("/api", Some(&sa[0]));
    assert_eq!((got.status, got.error().as_str()), (402, "ticket_used"));
    // another buyer's secret: not this session's ticket, and the other buyer's ticket is untouched
    let got = a.get("/api", Some(&sb[0]));
    assert_eq!(got.error(), "ticket_unknown");
    assert_eq!(
        rig.node.state_of(&ticket_hash(&sb[0])),
        Some(InvoiceState::Accepted)
    );
    // another buyer's ticket hash in a lock: the node has one invoice per hash
    let again = a.lock_raw(&sb);
    assert_eq!(
        (again.status, again.error().as_str()),
        (402, "too_many_tickets")
    );
    // a payment for one request does not pay another: target, method, body, host
    let sig = a.sign("GET", "/api", b"", None, None);
    for (m, t, body) in [
        ("GET", "/api?x=1", &b""[..]),
        ("POST", "/api", b""),
        ("POST", "/api", b"x"),
        ("GET", "/whole/10", b""),
    ] {
        let got = http(&rig.addr, m, t, &[("PAYMENT-SIGNATURE", &sig)], body, None);
        assert_eq!(
            (got.status, got.error().as_str()),
            (401, "bad_auth"),
            "{m} {t}"
        );
    }
    // the right request still works: a bad MAC used up nothing
    assert_eq!(
        http(
            &rig.addr,
            "GET",
            "/api",
            &[("PAYMENT-SIGNATURE", &sig)],
            b"",
            None
        )
        .status,
        200
    );
    // another session's key
    let forged = Buyer {
        session: a.session.clone(),
        seq: a.seq,
        ..Buyer::new(&rig, 9)
    };
    let sig = forged.sign_at(a.seq, "GET", "/api", b"", None, None);
    assert_eq!(
        http(
            &rig.addr,
            "GET",
            "/api",
            &[("PAYMENT-SIGNATURE", &sig)],
            b"",
            None
        )
        .error(),
        "bad_auth"
    );
    // an unknown session, two headers, a header that is not the wire's
    let ghost = Buyer {
        session: "ab".repeat(16),
        ..Buyer::new(&rig, 9)
    };
    let sig = ghost.sign_at(0, "GET", "/api", b"", None, None);
    let got = http(
        &rig.addr,
        "GET",
        "/api",
        &[("PAYMENT-SIGNATURE", &sig)],
        b"",
        None,
    );
    assert_eq!((got.status, got.error().as_str()), (402, "session_unknown"));
    assert_eq!(
        http(
            &rig.addr,
            "GET",
            "/api",
            &[("PAYMENT-SIGNATURE", &sig), ("payment-signature", &sig)],
            b"",
            None
        )
        .status,
        400
    );
    for junk in [
        "",
        "!!",
        "e30=",
        &xbt402::wire::b64json(
            &json!({"x402Version": 2, "accepted": {"scheme": "ticket", "network": "lightning:other"}, "payload": {}}),
        ),
    ] {
        assert_eq!(
            http(
                &rig.addr,
                "GET",
                "/api",
                &[("PAYMENT-SIGNATURE", junk)],
                b"",
                None
            )
            .status,
            400,
            "{junk}"
        );
    }
    // out of balance: asked for more than was released
    let mut poor = Buyer::new(&rig, 3);
    poor.lock(&rig, 1);
    let got = poor.get("/api", None);
    assert_eq!((got.status, got.error().as_str()), (402, "balance_short"));
    assert_eq!(got.json()["session"]["balanceMsat"], "0");
    // through all of it the service saw exactly the paid requests
    assert_eq!(rig.hits(), paid_hits + 2);
    assert_eq!(rig.node.settles().len(), 1);
    assert_eq!(a.balance(), 1_000_000 - 3 * 2500);
    assert_eq!(b.balance(), 0);
}

#[test]
fn locks_and_sessions_are_capped_and_a_flood_stops_at_the_caps() {
    let (rig, _d) = start(&|v| {
        v["caps"] = json!({"max_sessions": 5, "sessions_per_address": 3, "inbound_slots": 483})
    });
    // one address: three sessions
    let mut buyers: Vec<Buyer> = vec![];
    for i in 0..3 {
        let mut b = Buyer::new(&rig, i);
        let s = b.fresh_secrets(20);
        let got = b.lock_raw(&s[..8]);
        assert_eq!(got.json()["tickets"].as_array().unwrap().len(), 8);
        // more than the terms allow in one request is a bad request, not a bigger lock
        assert_eq!(b.lock_raw(&s).status, 400);
        // a full session gets no more
        let more = b.lock_raw(&s[8..10]);
        assert_eq!(
            (more.status, more.error().as_str()),
            (402, "too_many_tickets")
        );
        buyers.push(b);
    }
    for i in 0..50u8 {
        let mut b = Buyer::new(&rig, 100 + i);
        let s = b.fresh_secrets(1);
        let got = b.lock_raw(&s);
        assert_eq!(
            (got.status, got.error().as_str()),
            (402, "too_many_sessions")
        );
    }
    assert_eq!(
        rig.node.invoices(),
        24,
        "a refused lock asks the node for nothing"
    );
    assert_eq!(rig.gw.stats().held_tickets, 24);
    assert_eq!(rig.gw.stats().sessions, 3);
    // unpaid tickets are given up when their invoices lapse, and the sessions with them
    rig.advance(76);
    rig.gw.tick();
    wait_for("the unpaid tickets cancelled", || {
        rig.node.count(InvoiceState::Canceled) == 24
    });
    rig.gw.tick();
    assert_eq!(
        (rig.gw.stats().held_tickets, rig.gw.stats().sessions),
        (0, 0)
    );
    // junk bodies cost nothing
    for body in [
        "",
        "[]",
        "{}",
        r#"{"version": "ticket/0"}"#,
        r#"{"version": "ticket/0", "hashes": []}"#,
        r#"{"version": "ticket/0", "hashes": ["zz"]}"#,
        r#"{"version": "ticket/1", "hashes": ["00"]}"#,
    ] {
        assert_eq!(
            http(
                &rig.addr,
                "POST",
                "/x402/ticket/lock",
                &[],
                body.as_bytes(),
                None
            )
            .status,
            400,
            "{body}"
        );
    }
    let big = "x".repeat(20_000);
    assert_eq!(
        http(
            &rig.addr,
            "POST",
            "/x402/ticket/lock",
            &[],
            big.as_bytes(),
            None
        )
        .status,
        413
    );
    // a lock naming a session without its key
    let h = hex::encode([1u8; 32]);
    let body =
        json!({"version": "ticket/0", "session": "ab".repeat(16), "hashes": [h]}).to_string();
    assert_eq!(
        http(
            &rig.addr,
            "POST",
            "/x402/ticket/lock",
            &[],
            body.as_bytes(),
            None
        )
        .status,
        400
    );
    assert_eq!(rig.node.invoices(), 24);
}

#[test]
fn a_buyer_that_goes_quiet_has_its_tickets_cancelled() {
    let (rig, _d) = start(&|_| {});
    let mut b = Buyer::new(&rig, 1);
    let secrets = b.lock(&rig, 3);
    assert_eq!(b.get("/api", Some(&secrets[0])).status, 200);
    rig.advance(300);
    rig.gw.tick();
    assert_eq!(rig.node.count(InvoiceState::Accepted), 2, "not idle yet");
    rig.advance(1);
    rig.gw.tick();
    wait_for("the idle buyer's tickets cancelled", || {
        rig.node.count(InvoiceState::Canceled) == 2
    });
    // the balance it paid for is still there
    assert_eq!(b.get("/api", None).status, 200);
    assert_eq!(b.get("/api", Some(&secrets[1])).error(), "ticket_unknown");
    // a buyer that locks and never releases is closed sooner
    let mut c = Buyer::new(&rig, 2);
    c.lock(&rig, 2);
    rig.advance(61);
    rig.gw.tick();
    wait_for("the unused session's tickets cancelled", || {
        rig.node.count(InvoiceState::Canceled) == 4
    });
    // and the buyer's own stop: cancel some, then all
    let mut d = Buyer::new(&rig, 3);
    let s = d.lock(&rig, 3);
    let got = d.call(
        "cancel",
        &json!({"hashes": [hex::encode(ticket_hash(&s[0]))]}),
    );
    assert_eq!(
        got.json()["cancelled"],
        json!([hex::encode(ticket_hash(&s[0]))])
    );
    got.receipt(&KEY(&rig));
    assert_eq!(
        d.call("cancel", &json!({"hashes": "all"})).json()["cancelled"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(rig.node.count(InvoiceState::Accepted), 0);
    // a cancel of someone else's ticket cancels nothing
    let mut e = Buyer::new(&rig, 4);
    let se = e.lock(&rig, 1);
    assert_eq!(
        d.call(
            "cancel",
            &json!({"hashes": [hex::encode(ticket_hash(&se[0]))]})
        )
        .json()["cancelled"],
        json!([])
    );
    assert_eq!(
        rig.node.state_of(&ticket_hash(&se[0])),
        Some(InvoiceState::Accepted)
    );
}

/// Fetch `target` (per byte) releasing one ticket at a time as the balance runs down, and stop
/// reading after `stop_after` bytes. Returns what arrived and how many tickets were released.
fn fetch_paying(
    rig: &Rig,
    b: &mut Buyer,
    target: &str,
    secrets: &[[u8; 32]],
    stop_after: Option<usize>,
) -> (Got, usize) {
    let first = b.sign("GET", target, b"", Some(&secrets[0]), None);
    let (addr, t) = (rig.addr.clone(), target.to_string());
    let hits = rig.hits();
    let reader = std::thread::spawn(move || {
        http(
            &addr,
            "GET",
            &t,
            &[("PAYMENT-SIGNATURE", &first)],
            b"",
            stop_after,
        )
    });
    // the requests of one session go one after another: the next when this one has been taken
    wait_for("the request to be taken", || rig.hits() > hits);
    let mut released = 1;
    while !reader.is_finished() {
        if released < secrets.len() && b.balance() < 300_000 {
            assert_eq!(
                b.release(&secrets[released..released + 1]).json()["released"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
            released += 1;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    (reader.join().unwrap(), released)
}

#[test]
fn a_body_priced_per_byte_is_paid_as_it_arrives() {
    // 1,000 msat per MiB and 100,000-msat tickets: one ticket pays for 100 MiB at this price, so a
    // 100 MB body would need one; price it 200 times dearer to make the body need many
    let (rig, _d) = start(&|v| {
        v["routes"][0]["price"] = json!({"byte_msat": 200_000, "per_bytes": 1_048_576});
        v["tickets"] = json!({"ticket_msat": 2_000_000, "max_tickets": 8});
    });
    let mut b = Buyer::new(&rig, 1);
    let size = 100_000_000usize;
    // 100 MB at 200,000 msat per MiB: 19,073,487 msat, ten 2,000-sat tickets
    let need = 19_073_487u64;
    let first = b.lock(&rig, 8);
    let (got, mut released) = {
        // refill while it streams: lock more when few are left
        let target = format!("/files/{size}");
        let sig = b.sign("GET", &target, b"", Some(&first[0]), None);
        let addr = rig.addr.clone();
        let hits = rig.hits();
        let reader = std::thread::spawn(move || {
            http(
                &addr,
                "GET",
                &target,
                &[("PAYMENT-SIGNATURE", &sig)],
                b"",
                None,
            )
        });
        wait_for("the request to be taken", || rig.hits() > hits);
        let mut pool: Vec<[u8; 32]> = first[1..].to_vec();
        let mut released = 1;
        while !reader.is_finished() {
            if b.balance() < 600_000 {
                if pool.is_empty() {
                    pool = b.lock(&rig, 4);
                }
                let s = pool.remove(0);
                assert_eq!(
                    b.release(&[s]).json()["released"].as_array().unwrap().len(),
                    1,
                    "release"
                );
                released += 1;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        (reader.join().unwrap(), released)
    };
    assert_eq!(
        (got.status, got.body.len(), got.complete),
        (200, size, true)
    );
    assert!(
        got.body
            .iter()
            .enumerate()
            .step_by(9973)
            .all(|(i, c)| *c == pattern(i)),
        "the body is the service's, byte for byte"
    );
    // the head's receipt says it is a stream; the last receipt is in `status`
    let sr = unb64json(got.header("PAYMENT-RESPONSE").unwrap()).unwrap();
    assert_eq!(sr["extra"]["stream"], true);
    let st = b.status();
    let last = st["responses"].as_array().unwrap().last().unwrap().clone();
    check_receipt(&last, &KEY(&rig));
    assert_eq!(
        (
            last["charged"].as_str(),
            last["bytes"].as_u64(),
            last["complete"].as_bool()
        ),
        (
            Some(need.to_string().as_str()),
            Some(size as u64),
            Some(true)
        )
    );
    assert_eq!(last["bodyHash"], xbt402::wire::body_hash(&got.body));
    assert_eq!(st["session"]["spentMsat"], need.to_string());
    // paid as it arrived: never more than what was released, and ten tickets were enough
    assert!(released >= 10, "{released}");
    assert_eq!(
        st["session"]["releasedMsat"],
        (released as u64 * 2_000_000).to_string()
    );
    assert!(
        released as u64 * 2_000_000 - need < 2 * 2_000_000,
        "released {released} tickets for {need} msat"
    );
    assert_eq!(rig.node.settles().len(), released);
    assert!(rig.node.settles().iter().all(|s| s.was_held));

    // stop half way: the buyer stops releasing and stops reading
    let mut c = Buyer::new(&rig, 2);
    let secrets = c.lock(&rig, 8);
    let (got, n) = fetch_paying(&rig, &mut c, &format!("/files/{size}"), &secrets[..5], None);
    released = n;
    assert_eq!(released, 5);
    assert!(!got.complete, "the body stops when the tickets stop");
    let paid_for = 5 * 2_000_000u64;
    // what arrived is what five tickets pay for, to the byte: floor(10,000,000 * 2^20 / 200,000)
    assert_eq!(got.body.len() as u64, paid_for * 1_048_576 / 200_000);
    let st = c.status();
    assert_eq!(
        (
            st["session"]["spentMsat"].as_str(),
            st["session"]["balanceMsat"].as_str()
        ),
        (Some("10000000"), Some("0"))
    );
    let last = st["responses"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(
        (last["complete"].as_bool(), last["bytes"].as_u64()),
        (Some(false), Some(got.body.len() as u64))
    );
    // the three tickets it never released are still its own: locked, and cancelled on request
    assert_eq!(
        rig.node.count(InvoiceState::Accepted),
        3 + rig.gw.stats().held_tickets - 3
    );
    assert_eq!(
        c.call("cancel", &json!({"hashes": "all"})).json()["cancelled"]
            .as_array()
            .unwrap()
            .len(),
        3
    );

    // stop reading: nothing more is charged than what was sent, within one ticket
    let mut d = Buyer::new(&rig, 3);
    let secrets = d.lock(&rig, 8);
    let (got, n) = fetch_paying(
        &rig,
        &mut d,
        &format!("/files/{size}"),
        &secrets,
        Some(20_000_000),
    );
    wait_for("the response to end", || {
        d.status()["responses"]
            .as_array()
            .is_some_and(|r| !r.is_empty())
    });
    let st = d.status();
    let last = st["responses"].as_array().unwrap().last().unwrap().clone();
    let sent = last["bytes"].as_u64().unwrap();
    let spent: u64 = st["session"]["spentMsat"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        sent >= got.body.len() as u64 && sent < 20_000_000 + 8_000_000,
        "sent {sent}: the socket's buffers and no more"
    );
    assert_eq!(
        spent,
        (sent as u128 * 200_000).div_ceil(1_048_576) as u64,
        "charged for the bytes sent, exactly"
    );
    assert!(
        n as u64 * 2_000_000 - spent < 2 * 2_000_000,
        "released {n} tickets, spent {spent}"
    );
}

#[test]
fn a_body_of_unknown_length_and_a_cut_one_are_metered_the_same() {
    let (rig, _d) = start(&|_| {});
    let mut b = Buyer::new(&rig, 1);
    let s = b.lock(&rig, 1);
    let got = b.get("/chunked/3000000", Some(&s[0]));
    assert_eq!(
        (got.status, got.body.len(), got.complete),
        (200, 3_000_000, true)
    );
    assert!(got.header("Transfer-Encoding").is_some());
    // 3,000,000 bytes at 1,000 msat per MiB: ceil(2861.02) = 2862
    assert_eq!(b.status()["session"]["spentMsat"], "2862");
    // HEAD: the request's price only, no body, nothing metered, and the length the service stated
    let sig = b.sign("HEAD", "/files/1000", b"", None, None);
    let got = http(
        &rig.addr,
        "HEAD",
        "/files/1000",
        &[("PAYMENT-SIGNATURE", &sig)],
        b"",
        None,
    );
    assert_eq!(
        (got.status, got.body.len(), got.header("Content-Length")),
        (200, 0, Some("1000"))
    );
    assert_eq!(got.receipt(&KEY(&rig))["charged"], "0");
    assert_eq!(b.status()["session"]["spentMsat"], "2862");
    // an answer that has no body by its status: the request's price, and no second of a body
    let got = b.get("/status/304", None);
    assert_eq!((got.status, got.body.len()), (304, 0));
    assert_eq!(got.receipt(&KEY(&rig))["charged"], "2500");
    let mut c = Buyer::new(&rig, 2);
    let s = c.lock(&rig, 1);
    assert_eq!(c.get("/timed/8192", Some(&s[0])).status, 200);
    let sig = c.sign("HEAD", "/timed/8192", b"", None, None);
    let got = http(
        &rig.addr,
        "HEAD",
        "/timed/8192",
        &[("PAYMENT-SIGNATURE", &sig)],
        b"",
        None,
    );
    assert_eq!(
        got.receipt(&KEY(&rig))["charged"],
        "0",
        "no second for a HEAD"
    );
    assert_eq!(c.status()["session"]["spentMsat"], "100000");
    // no answer is left counted as open: with nothing locked, neither session takes a place
    wait_for("the sessions to be counted out", || {
        rig.gw.stats().active_sessions == 0
    });
}

#[test]
fn a_body_priced_per_second_is_paid_second_by_second() {
    let (rig, _d) = start(&|_| {});
    let mut b = Buyer::new(&rig, 1);
    let s = b.lock(&rig, 1);
    // 24 KiB at 8 KiB per 100 ms: open for about 0.3 s, one started second
    let got = b.get("/timed/24576", Some(&s[0]));
    assert_eq!(
        (got.status, got.body.len(), got.complete),
        (200, 24_576, true)
    );
    assert_eq!(
        got.receipt(&KEY(&rig))["charged"],
        "100000",
        "the first second, at the head"
    );
    assert_eq!(b.status()["session"]["spentMsat"], "100000");
    // about 1.3 s: two started seconds
    let got = b.get("/timed/106496", None);
    assert_eq!((got.body.len(), got.complete), (106_496, true));
    assert_eq!(b.status()["session"]["spentMsat"], "300000");
    // a balance that covers 7 more seconds: the response ends when the seconds are no longer paid
    let t = Instant::now();
    let got = b.get("/timed/8000000", None);
    assert!(!got.complete);
    assert_eq!(b.status()["session"]["spentMsat"], "1000000");
    let open = t.elapsed();
    assert!(
        open >= Duration::from_secs(7) && open < Duration::from_secs(9),
        "{open:?}"
    );
    // nothing left for a first second
    assert_eq!(b.get("/timed/8192", None).error(), "balance_short");
}

#[test]
fn the_buyer_does_not_pay_when_the_service_gives_nothing() {
    let (rig, _d) = start(&|_| {});
    let mut b = Buyer::new(&rig, 1);
    let s = b.lock(&rig, 1);
    assert_eq!(b.get("/api", Some(&s[0])).status, 200);
    let spent = |b: &mut Buyer| {
        b.status()["session"]["spentMsat"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(spent(&mut b), "2500");
    // errors are passed on, capped, and not charged
    for code in [404u16, 500, 503] {
        let got = b.get(&format!("/status/{code}"), None);
        assert_eq!((got.status, got.body.len()), (code, 65_536));
        assert_eq!(got.receipt(&KEY(&rig))["charged"], "0");
    }
    // a service that is too slow to start its answer
    let t = Instant::now();
    let got = b.get("/hang", None);
    assert_eq!(
        (got.status, got.error().as_str()),
        (502, "upstream_unavailable")
    );
    assert!(t.elapsed() < Duration::from_secs(4), "{:?}", t.elapsed());
    // a service that stops in the middle of a body the receipt would have covered
    assert_eq!(b.get("/cut", None).status, 502);
    // a service that asks for payment itself is not relayed
    assert_eq!(b.get("/pay", None).status, 502);
    assert_eq!(spent(&mut b), "2500", "nothing was charged for any of them");
    // a redirect is passed on, not followed, and is an answer like any other
    let hits = rig.hits();
    let got = b.get("/moved", None);
    assert_eq!((got.status, got.header("Location")), (302, Some("/api")));
    assert_eq!(rig.hits(), hits + 1, "the gateway did not follow it");
    assert_eq!(spent(&mut b), "5000");
    // the service is down altogether
    let (node, service, clock) = rig.stop();
    service.0.stopper().stop();
    for t in service.0.threads {
        let _ = t.join();
    }
    let dead = (start_service().0, service.1);
    dead.0.stopper().stop();
    let dir = tempfile::tempdir().unwrap();
    let rig = start_on(dir.path(), node, dead, clock, &|_| {});
    let mut c = Buyer::new(&rig, 2);
    let s = c.lock(&rig, 1);
    let got = c.get("/api", Some(&s[0]));
    assert_eq!(
        (got.status, got.error().as_str()),
        (502, "upstream_unavailable")
    );
    assert_eq!(got.receipt(&KEY(&rig))["charged"], "0");
    // the ticket was released and is the buyer's balance: not lost, not spent
    assert_eq!(c.balance(), 1_000_000);
}

#[test]
fn only_what_the_runner_allowed_reaches_the_service_and_nothing_it_says_is_money() {
    let (rig, _d) = start(&|_| {});
    let mut b = Buyer::new(&rig, 1);
    let s = b.lock(&rig, 1);
    let sig = b.sign("GET", "/api", b"", Some(&s[0]), None);
    let sent = [
        ("PAYMENT-SIGNATURE", sig.as_str()),
        ("Authorization", "Bearer buyer"),
        ("Cookie", "a=b"),
        ("X-Forwarded-For", "10.9.8.7"),
        ("Via", "1.1 buyer"),
        ("X-Trace", "t1"),
        ("X-Other", "o"),
        ("Accept", "application/json"),
        ("Accept-Encoding", "gzip"),
        ("Range", "bytes=0-1"),
    ];
    assert_eq!(http(&rig.addr, "GET", "/api", &sent, b"", None).status, 200);
    let seen = rig.service.seen.lock().unwrap().last().unwrap().clone();
    let mut names: Vec<String> = seen
        .headers
        .iter()
        .map(|(k, _)| k.to_ascii_lowercase())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "accept",
            "accept-encoding",
            "host",
            "range",
            "user-agent",
            "via",
            "x-trace"
        ],
        "{:?}",
        seen.headers
    );
    assert_eq!(seen.header("accept-encoding"), Some("identity"));
    assert_eq!(
        seen.header("via"),
        Some("1.1 xbt-gateway"),
        "the gateway's own, not the buyer's"
    );
    assert_ne!(seen.header("host"), Some("gateway.test:8402"));
    // what the service says about payment does not reach the buyer, and is not read
    let got = b.get("/money", None);
    assert_eq!(
        (
            got.status,
            got.header("X-Kept"),
            got.header("Ticket-Units"),
            got.header("Payment-Required")
        ),
        (200, Some("yes"), None, None)
    );
    assert_eq!(got.receipt(&KEY(&rig))["charged"], "2500");
    assert_eq!(
        got.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-RESPONSE"))
            .count(),
        1
    );
    // a request body on a route that takes none, and one over the route's limit
    let sig = b.sign("GET", "/whole/10", b"x", None, None);
    assert_eq!(
        http(
            &rig.addr,
            "GET",
            "/whole/10",
            &[("PAYMENT-SIGNATURE", &sig)],
            b"x",
            None
        )
        .status,
        413
    );
    let big = vec![b'x'; 5000];
    assert_eq!(http(&rig.addr, "POST", "/api", &[], &big, None).status, 413);
}

#[test]
fn a_target_that_could_be_read_two_ways_is_refused_before_the_service() {
    let (rig, _d) = start(&|_| {});
    let mut b = Buyer::new(&rig, 1);
    let s = b.lock(&rig, 1);
    assert_eq!(b.get("/api", Some(&s[0])).status, 200);
    let hits = rig.hits();
    // a priced path reached through a free one, or spelled so that no priced route matches
    for target in [
        "/files/free/../100",
        "/files/free/%2e%2e/100",
        "/files/free/..%2f100",
        "/files/free//100",
        "/files/./free/1",
        "/files/free\\..\\100",
        "//files/free/1",
        "/files/fr%65e/%2E%2E/1",
    ] {
        let got = http(&rig.addr, "GET", target, &[], b"", None);
        assert_eq!(
            (got.status, got.error().as_str()),
            (400, "bad_target"),
            "{target}"
        );
    }
    // an escaped letter is the same path: the priced route, not a way around it
    let got = http(&rig.addr, "GET", "/%66iles/100", &[], b"", None);
    assert_eq!(
        got.status, 402,
        "an escaped spelling of a priced path is priced"
    );
    let got = http(&rig.addr, "GET", "/files/fre%65/100", &[], b"", None);
    assert_ne!(got.status, 402, "and of a free path is free");
    assert_eq!(
        rig.hits(),
        hits + 1,
        "it went to the service, spelled as it arrived"
    );
    assert_eq!(
        rig.service.seen.lock().unwrap().last().unwrap().target,
        "/files/fre%65/100"
    );
    // another case is another path: no route, not served
    assert_eq!(
        http(&rig.addr, "GET", "/FILES/free/100", &[], b"", None).status,
        404
    );
}

#[test]
fn tickets_locked_before_a_restart_are_still_good() {
    let dir = tempfile::tempdir().unwrap();
    let clock = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1_000_000));
    let rig = start_on(
        dir.path(),
        std::sync::Arc::new(StandIn::new(100)),
        start_service(),
        clock,
        &|_| {},
    );
    let mut b = Buyer::new(&rig, 1);
    let s = b.lock(&rig, 4);
    assert_eq!(b.get("/api", Some(&s[0])).status, 200);
    assert_eq!(b.get("/api", None).status, 200);
    let key = KEY(&rig);
    // the gateway restarts: same state directory, same node
    let (node, service, clock) = rig.stop();
    // while it was away one ticket was settled on the node by its own earlier call, one was cancelled
    node.settle(&s[1]).unwrap();
    node.cancel(&ticket_hash(&s[2])).unwrap();
    let rig = start_on(dir.path(), node, service, clock, &|_| {});
    b.addr = rig.addr.clone();
    let st = b.status();
    // the session, its key, its seq and what it spent are back; what the node settled is credited
    assert_eq!(
        (
            st["session"]["releasedMsat"].as_str(),
            st["session"]["spentMsat"].as_str()
        ),
        (Some("2000000"), Some("5000"))
    );
    assert_eq!(st["tickets"].as_array().unwrap().len(), 1, "{st}");
    b.wait_state(&s[3..], "ACCEPTED");
    let got = b.get("/api", Some(&s[3]));
    assert_eq!(got.status, 200);
    assert_eq!(got.receipt(&key)["releasedMsat"], "3000000");
    // a used secret is still used, a cancelled ticket is gone
    assert!(matches!(
        b.get("/api", Some(&s[0])).error().as_str(),
        "ticket_unknown" | "ticket_used"
    ));
    assert_eq!(b.get("/api", Some(&s[2])).error(), "ticket_unknown");
    assert!(rig
        .node
        .settles()
        .iter()
        .filter(|x| x.hash == ticket_hash(&s[3]))
        .all(|x| x.was_held));
    assert_eq!(
        rig.node.settles().iter().filter(|x| !x.was_held).count(),
        0,
        "no settle of a ticket that was not held"
    );

    // the node restarts with tickets locked: its streams break, the tickets are still good after
    let t = b.lock(&rig, 2);
    rig.node.set_down(true);
    let got = b.get("/api", Some(&t[0]));
    assert_eq!(
        (got.status, got.error().as_str()),
        (503, "node_unavailable")
    );
    assert_eq!(
        http(
            &rig.addr,
            "POST",
            "/x402/ticket/lock",
            &[],
            json!({"version": "ticket/0", "hashes": [hex::encode([3u8; 32])]})
                .to_string()
                .as_bytes(),
            None
        )
        .status,
        503
    );
    // the balance still pays while the node is away
    assert_eq!(b.get("/api", None).status, 200);
    rig.node.set_down(false);
    rig.gw.tick();
    let got = b.get("/api", Some(&t[0]));
    assert_eq!(got.status, 200, "{}", String::from_utf8_lossy(&got.body));
    assert_eq!(b.get("/api", Some(&t[1])).status, 200);
    assert_eq!(rig.gw.stats().sessions, 1);
}

#[test]
fn a_settle_whose_answer_is_lost_is_not_served_and_is_credited_when_the_node_reports_it() {
    let (rig, _d) = start(&|_| {});
    let mut b = Buyer::new(&rig, 1);
    let s = b.lock(&rig, 1);
    rig.node.lose_next_settle_answer();
    let hits = rig.hits();
    let got = b.get("/api", Some(&s[0]));
    assert_eq!(
        (got.status, got.error().as_str()),
        (503, "node_unavailable")
    );
    assert_eq!(
        rig.hits(),
        hits,
        "not served on a settle that was not confirmed"
    );
    // the node did settle: its stream says so, and the buyer has its balance
    wait_for("the credit", || rig.gw.stats().held_tickets == 0);
    assert_eq!(b.balance(), 1_000_000);
    assert_eq!(b.get("/api", None).status, 200);
    // presenting the secret again buys nothing more
    assert!(matches!(
        b.get("/api", Some(&s[0])).error().as_str(),
        "ticket_used"
    ));
    assert_eq!(b.balance(), 1_000_000 - 2500);
}

#[test]
fn a_stream_that_has_fallen_behind_costs_one_lookup_and_no_wrong_answer() {
    let (rig, _d) = start(&|_| {});
    let mut b = Buyer::new(&rig, 1);
    let secrets = b.fresh_secrets(3);
    assert_eq!(b.lock_raw(&secrets).status, 200);
    b.wait_state(&secrets, "OPEN");
    // the node holds the payments, and its streams have not said so yet
    rig.node.hold_streams(true);
    for s in &secrets[..2] {
        assert!(rig.node.pay(&ticket_hash(s)));
    }
    assert_eq!(
        b.status()["tickets"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|t| t["state"] == "OPEN")
            .count(),
        3
    );
    let got = b.get("/api", Some(&secrets[0]));
    assert_eq!(got.status, 200, "{}", String::from_utf8_lossy(&got.body));
    assert_eq!(rig.node.calls("lookup"), 1);
    // an unpaid one is still unpaid, on the node's own word
    assert_eq!(
        b.get("/api", Some(&secrets[2])).error(),
        "ticket_not_locked"
    );
    assert_eq!(rig.node.calls("lookup"), 2);
    // a ticket the node took and then cancelled, all behind the stream's back: gone, on the node's word
    let lookups = rig.node.calls("lookup");
    assert!(rig.node.cancel(&ticket_hash(&secrets[1])).is_ok());
    let got = b.get("/api", Some(&secrets[1]));
    assert_eq!((got.status, got.error().as_str()), (402, "ticket_unknown"));
    assert_eq!(rig.node.calls("lookup"), lookups + 1);
    assert_eq!(rig.node.settles().len(), 1, "the one that was held, once");
    assert!(rig.node.settles()[0].was_held);
    // a secret that is no ticket of this session costs the node nothing
    let lookups = rig.node.calls("lookup");
    assert_eq!(b.get("/api", Some(&[0x55; 32])).error(), "ticket_unknown");
    assert_eq!(rig.node.calls("lookup"), lookups);
    rig.node.hold_streams(false);
}

#[test]
fn a_checkable_route_serves_one_piece_before_its_secret_and_no_second() {
    let (rig, _d) = start(&|_| {});
    let mut b = Buyer::new(&rig, 1);
    let s = b.lock(&rig, 3);
    let h: Vec<_> = s.iter().map(ticket_hash).collect();
    let get = |b: &mut Buyer, secret: Option<&[u8; 32]>, pledge: Option<&[u8; 32]>| {
        let sig = b.sign("GET", "/verify/1000", b"", secret, pledge);
        http(
            &rig.addr,
            "GET",
            "/verify/1000",
            &[("PAYMENT-SIGNATURE", &sig)],
            b"",
            None,
        )
    };
    // a piece on a pledged ticket: served, nothing settled yet
    let got = get(&mut b, None, Some(&h[0]));
    assert_eq!((got.status, got.body.len()), (200, 1000));
    assert!(rig.node.settles().is_empty());
    let r = got.receipt(&KEY(&rig));
    assert_eq!(
        (r["releasedMsat"].as_str(), r["spentMsat"].as_str()),
        (Some("0"), Some("400000"))
    );
    // a second piece on the same pledge fits in one ticket; a third does not
    assert_eq!(get(&mut b, None, Some(&h[0])).status, 200);
    let got = get(&mut b, None, Some(&h[0]));
    assert_eq!((got.status, got.error().as_str()), (402, "balance_short"));
    // no second pledge while the first is owed
    assert_eq!(get(&mut b, None, Some(&h[1])).error(), "pledge_outstanding");
    // the pledged ticket cannot be cancelled away from under the debt
    assert_eq!(
        b.call("cancel", &json!({"hashes": "all"})).json()["cancelled"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    // the buyer verified its pieces: the secret of the first ticket, and the next pledge would follow
    let got = b.release(&s[..1]);
    assert_eq!(got.json()["released"], json!([hex::encode(h[0])]));
    let r = got.receipt(&KEY(&rig));
    assert_eq!(
        (r["releasedMsat"].as_str(), r["spentMsat"].as_str()),
        (Some("1000000"), Some("800000"))
    );
    assert_eq!(rig.node.settles().len(), 1);
    // what is left of the ticket is not enough for another piece, and there is no pledge now
    assert_eq!(get(&mut b, None, None).error(), "balance_short");
    // a pledge on a route that takes the secret with the request is a bad request
    let sig = b.sign("GET", "/api", b"", None, Some(&h[1]));
    assert_eq!(
        http(
            &rig.addr,
            "GET",
            "/api",
            &[("PAYMENT-SIGNATURE", &sig)],
            b"",
            None
        )
        .status,
        400
    );
    // a buyer that never sends the secret: one ticket's worth at most, and nothing more on credit
    let mut c = Buyer::new(&rig, 2);
    let sc = c.lock(&rig, 1);
    let hc = ticket_hash(&sc[0]);
    let sig = c.sign("GET", "/verify/1000", b"", None, Some(&hc));
    assert_eq!(
        http(
            &rig.addr,
            "GET",
            "/verify/1000",
            &[("PAYMENT-SIGNATURE", &sig)],
            b"",
            None
        )
        .status,
        200
    );
    rig.height(125);
    assert_eq!(
        rig.node.state_of(&hc),
        Some(InvoiceState::Canceled),
        "the node cancelled the held ticket itself"
    );
    wait_for("the cancel to be seen", || rig.gw.stats().held_tickets == 0);
    let st = c.status();
    assert_eq!(
        (
            st["session"]["spentMsat"].as_str(),
            st["session"]["releasedMsat"].as_str()
        ),
        (Some("400000"), Some("0")),
        "the seller is out one piece"
    );
    let sig = c.sign("GET", "/verify/1000", b"", None, None);
    assert_eq!(
        http(
            &rig.addr,
            "GET",
            "/verify/1000",
            &[("PAYMENT-SIGNATURE", &sig)],
            b"",
            None
        )
        .error(),
        "balance_short"
    );
}

#[test]
fn thousands_of_requests_from_one_buyer_are_bounded_by_what_it_paid() {
    let (rig, _d) = start(&|_| {});
    let mut b = Buyer::new(&rig, 1);
    let s = b.lock(&rig, 1);
    assert_eq!(b.get("/api", Some(&s[0])).status, 200);
    // 1,000,000 msat at 2,500 msat a request: 400 requests, the first already made
    let mut served = 1;
    for _ in 0..450 {
        if b.get("/api", None).status == 200 {
            served += 1;
        }
    }
    assert_eq!(served, 400);
    assert_eq!(b.balance(), 0);
    // (a request whose answer the service failed to finish is asked again and charged once)
    assert!(rig.hits() >= 400);
    let _: Value = b.status();
}

/// The shipped caps: nothing set under `tickets` and `caps` but the per-address cap, which the
/// tests' one address would meet first.
fn shipped(v: &mut Value) {
    v["tickets"] = json!({});
    v["caps"] = json!({"sessions_per_address": 0});
}

#[test]
fn held_tickets_stop_at_half_of_a_30_slot_channel_and_the_next_buyer_is_told_to_wait() {
    let (rig, _d) = start(&shipped);
    // the terms: two ways to pay, the held one first, 2 tickets a session
    let pr = http(&rig.addr, "GET", "/api", &[], b"", None).json();
    let ways: Vec<(&str, u64)> = pr["accepts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["extra"]["settle"].as_str().unwrap(),
                a["extra"]["maxTickets"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(ways, vec![("on-use", 2), ("on-arrival", 2)]);
    // seven buyers hold 2 each: 14 of the 15
    let mut buyers: Vec<Buyer> = vec![];
    for i in 0..7u8 {
        let mut b = Buyer::new(&rig, i + 1);
        let s = b.fresh_secrets(3);
        assert_eq!(
            b.lock_raw(&s).status,
            400,
            "more than a session holds is a bad request"
        );
        b.lock(&rig, 2);
        buyers.push(b);
    }
    assert_eq!(rig.gw.stats().held_tickets, 14);
    // the eighth gets the place that is left
    let mut eighth = Buyer::new(&rig, 8);
    let s = eighth.fresh_secrets(2);
    let got = eighth.lock_raw(&s);
    assert_eq!(
        (got.status, got.json()["tickets"].as_array().unwrap().len()),
        (200, 1)
    );
    assert_eq!(
        (rig.gw.stats().held_tickets, rig.gw.stats().max_held),
        (15, 15)
    );
    // the ninth is told to wait, has no session, and the node was asked for nothing
    let asked = rig.node.invoices();
    let mut ninth = Buyer::new(&rig, 9);
    let s = ninth.fresh_secrets(2);
    let got = ninth.lock_raw(&s);
    assert_eq!(
        (got.status, got.json()),
        (402, json!({"error": "slots_short", "retryAfter": 30}))
    );
    assert_eq!((rig.node.invoices(), rig.gw.stats().sessions), (asked, 8));
    // a session that has released one of its two is told the same when it asks for the next:
    // signed, so that the buyer knows it is the seller that says so
    let secrets = buyers[0].fresh_secrets(1);
    let first = secret_of(1, 4);
    assert_eq!(
        buyers[0].release(&[first]).json()["released"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // its released place went to nobody yet: it gets it back
    let again = buyers[0].lock_raw(&secrets);
    assert_eq!(again.status, 200);
    let mut tenth = Buyer::new(&rig, 10);
    let s = tenth.fresh_secrets(1);
    assert_eq!(tenth.lock_raw(&s).error(), "slots_short");
    // the eighth, with one of two, asks for its second while the cap is full
    let s = eighth.fresh_secrets(1);
    let got = eighth.lock_raw(&s);
    assert_eq!((got.status, got.error().as_str()), (402, "slots_short"));
    assert_eq!(got.json()["retryAfter"], 30);
    let r = got.receipt(&KEY(&rig));
    assert_eq!(r["charged"], "0");
    // the buyer who was told to wait pays without a held ticket instead
    let got = ninth.lock_prepaid(1);
    assert_eq!(got.status, 200, "{}", got.json());
    assert_eq!(
        (rig.gw.stats().held_tickets, rig.gw.stats().prepaid_tickets),
        (15, 1)
    );
}

#[test]
fn a_prepaid_ticket_is_credited_once_when_its_preimage_is_presented_after_it_was_paid() {
    let (rig, _d) = start(&shipped);
    let mut b = Buyer::new(&rig, 1);
    let got = b.lock_prepaid(1);
    assert_eq!(got.status, 200, "{}", got.json());
    let j = got.json();
    let tickets = j["tickets"].as_array().unwrap();
    assert_eq!(tickets.len(), 1);
    let hash = xbt402::ticket::hex32(tickets[0]["hash"].as_str().unwrap()).unwrap();
    assert!(tickets[0]["invoice"]
        .as_str()
        .is_some_and(|i| !i.is_empty()));
    assert_eq!(
        (
            rig.node.calls("add_invoice"),
            rig.node.calls("add_hold"),
            rig.gw.stats().held_tickets
        ),
        (1, 0, 0),
        "an ordinary invoice, and nothing held"
    );
    let st = b.status();
    assert_eq!(st["tickets"][0]["settle"], "on-arrival");
    assert_eq!(st["tickets"][0]["state"], "OPEN");
    // nothing is credited before the node shows it paid, whatever is presented
    assert_eq!(rig.node.paid_preimage(&hash), None);
    let guess = [9u8; 32];
    let refused = b.release(&[guess]).json();
    assert_eq!(refused["refused"][0]["error"], "ticket_unknown");
    assert_eq!(b.balance(), 0);
    assert_eq!(b.get("/api", None).error(), "balance_short");
    // the buyer pays; its node hands it the preimage
    assert!(rig.node.pay(&hash));
    let preimage = rig.node.paid_preimage(&hash).unwrap();
    assert_eq!(ticket_hash(&preimage), hash);
    let settles = rig.node.calls("settle");
    let got = b.release(&[preimage]);
    assert_eq!(got.json()["released"], json!([hex::encode(hash)]));
    assert_eq!(got.receipt(&KEY(&rig))["releasedMsat"], "1000000");
    assert_eq!(
        rig.node.calls("settle"),
        settles,
        "no settle call: there was nothing held"
    );
    // once
    assert_eq!(
        b.release(&[preimage]).json()["refused"][0]["error"],
        "ticket_used"
    );
    assert_eq!(b.balance(), 1_000_000);
    // and it pays for requests like any released ticket
    let got = b.get("/api", None);
    assert_eq!(got.status, 200);
    assert_eq!(b.balance(), 1_000_000 - 2500);
    // one that was issued and never paid: presented, it buys nothing; the janitor gives it up
    let got = b.lock_prepaid(2).json();
    let unpaid: Vec<[u8; 32]> = got["tickets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| xbt402::ticket::hex32(t["hash"].as_str().unwrap()).unwrap())
        .collect();
    assert_eq!(unpaid.len(), 2);
    assert_eq!(b.lock_prepaid(1).error(), "too_many_tickets");
    // one of the two is paid and never presented: the janitor credits it all the same
    assert!(rig.node.pay(&unpaid[0]));
    rig.advance(76);
    rig.gw.tick();
    wait_for("the paid one credited and the unpaid one cancelled", || {
        rig.gw.stats().prepaid_tickets == 0
    });
    assert_eq!(rig.node.state_of(&unpaid[1]), Some(InvoiceState::Canceled));
    assert_eq!(b.balance(), 2_000_000 - 2500);
}

#[test]
fn a_prepaid_ticket_outlives_a_restart_and_a_seller_can_offer_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let only_prepaid = |v: &mut Value| {
        // no held ticket is offered, so a ticket below the dust limit is no dust
        v["tickets"] = json!({"ticket_msat": 64_000, "settle": ["on-arrival"]});
        v["caps"] = json!({"sessions_per_address": 0});
        v["routes"] = json!([{"path": "/api", "price": {"request_msat": 2500}}]);
    };
    let rig = start_on(
        dir.path(),
        std::sync::Arc::new(StandIn::new(100)),
        start_service(),
        std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1_000_000)),
        &only_prepaid,
    );
    let pr = http(&rig.addr, "GET", "/api", &[], b"", None).json();
    assert_eq!(pr["accepts"].as_array().unwrap().len(), 1);
    assert_eq!(pr["accepts"][0]["extra"]["settle"], "on-arrival");
    assert_eq!(pr["accepts"][0]["extra"]["ticketMsat"], "64000");
    let mut b = Buyer::new(&rig, 1);
    // a held ticket is not on offer
    let s = b.fresh_secrets(1);
    assert_eq!(b.lock_raw(&s).status, 400);
    let j = b.lock_prepaid(1).json();
    let hash = xbt402::ticket::hex32(j["tickets"][0]["hash"].as_str().unwrap()).unwrap();
    let (session, key, seq) = (b.session.clone(), b.key, b.seq);
    // the gateway restarts with the invoice unpaid; the buyer pays meanwhile
    let (node, service, clock) = rig.stop();
    assert!(node.pay(&hash));
    let rig = start_on(dir.path(), node, service, clock, &only_prepaid);
    assert_eq!(
        rig.gw.stats().prepaid_tickets,
        0,
        "read from the node at start, and credited"
    );
    let mut b = Buyer::new(&rig, 1);
    (b.session, b.key, b.seq) = (session, key, seq);
    assert_eq!(b.balance(), 64_000);
    let preimage = rig.node.paid_preimage(&hash).unwrap();
    assert_eq!(
        b.release(&[preimage]).json()["refused"][0]["error"],
        "ticket_used",
        "credited at the start, from the node's word: the balance is there, and it is not credited twice"
    );
    assert_eq!(b.get("/api", None).status, 200);
}

#[test]
fn a_gateway_given_a_channels_macaroon_sizes_itself_and_waits_while_a_channel_is_half_full() {
    let dir = tempfile::tempdir().unwrap();
    let node = std::sync::Arc::new(StandIn::new(100));
    // two inbound channels: one with a Lightning Fork node (483), one with a Core Lightning node (30)
    node.set_channels(Some(vec![
        Channel {
            slots: 483,
            pending_in: 3,
        },
        Channel {
            slots: 30,
            pending_in: 0,
        },
    ]));
    let sized = |v: &mut Value| {
        v["tickets"] = json!({});
        v["caps"] = json!({"sessions_per_address": 0, "inbound_slots": 483});
        v["node"]["channels_macaroon"] = json!("unused");
    };
    let rig = start_on(
        dir.path(),
        node,
        start_service(),
        std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1_000_000)),
        &sized,
    );
    assert_eq!(
        rig.gw.stats().max_held,
        15,
        "half of the smallest channel, whatever the config assumed"
    );
    let mut b = Buyer::new(&rig, 1);
    b.lock(&rig, 2);
    // the 30-slot channel is half full of pending payments (anyone's): nothing more is issued
    rig.node.set_channels(Some(vec![
        Channel {
            slots: 483,
            pending_in: 3,
        },
        Channel {
            slots: 30,
            pending_in: 15,
        },
    ]));
    let mut c = Buyer::new(&rig, 2);
    let s = c.fresh_secrets(1);
    let got = c.lock_raw(&s);
    assert_eq!((got.status, got.error().as_str()), (402, "slots_short"));
    assert_eq!(rig.gw.stats().sessions, 1);
    // it empties: issued again
    rig.node.set_channels(Some(vec![
        Channel {
            slots: 483,
            pending_in: 3,
        },
        Channel {
            slots: 30,
            pending_in: 14,
        },
    ]));
    assert_eq!(c.lock_raw(&s).status, 200);
    // the smaller channel closes: the cap follows the channels that are left
    rig.node.set_channels(Some(vec![Channel {
        slots: 483,
        pending_in: 3,
    }]));
    let s = c.fresh_secrets(1);
    assert_eq!(c.lock_raw(&s).status, 200);
    assert_eq!(rig.gw.stats().max_held, 241);
    // no channel at all: no held ticket
    rig.node.set_channels(Some(vec![]));
    let mut d = Buyer::new(&rig, 3);
    let s = d.fresh_secrets(1);
    assert_eq!(d.lock_raw(&s).error(), "slots_short");
    assert_eq!(rig.gw.stats().max_held, 0);
    // the list cannot be read: the config's own cap, never a wider one
    rig.node.set_channels(None);
    assert_eq!(d.lock_raw(&s).status, 200);
    assert_eq!(
        rig.gw.stats().max_held,
        241,
        "caps.inbound_slots 483 in this config"
    );
    // and a gateway whose macaroon does not work does not start
    let dir2 = tempfile::tempdir().unwrap();
    let cfg = config(dir2.path(), "http://127.0.0.1:9", &sized);
    let started = xbt_gateway::gateway::Gateway::start(
        xbt_gateway::config::Config::from_json(&cfg).unwrap(),
        std::sync::Arc::new(StandIn::new(100)),
        receipt_secret(),
        Box::new(|| 1),
    );
    assert!(started.is_err_and(|e| e.to_string().contains("channels")));
}

#[test]
fn a_lock_the_caps_refuse_does_not_ask_the_node_for_its_channels() {
    let dir = tempfile::tempdir().unwrap();
    let node = std::sync::Arc::new(StandIn::new(100));
    node.set_channels(Some(vec![Channel {
        slots: 483,
        pending_in: 0,
    }]));
    // a gateway that reads its channels, with room for two sessions of two tickets
    let rig = start_on(
        dir.path(),
        node,
        start_service(),
        std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1_000_000)),
        &|v| {
            v["tickets"] = json!({"max_tickets": 2});
            v["caps"] = json!({"sessions_per_address": 0, "inbound_slots": 483, "max_sessions": 2});
            v["node"]["channels_macaroon"] = json!("unused");
        },
    );
    let read = || rig.node.calls("channels");
    let at_start = read();
    let mut a = Buyer::new(&rig, 1);
    a.lock(&rig, 2);
    let mut b = Buyer::new(&rig, 2);
    b.lock(&rig, 1);
    let after_locks = read();
    assert_eq!(after_locks, at_start + 2, "a lock that is served reads the channels once");
    // every session place is taken: 50 first locks, authenticated by nobody, are refused on the book alone
    for n in 0..50u8 {
        let mut flood = Buyer::new(&rig, 100 + n);
        let s = flood.fresh_secrets(1);
        let got = flood.lock_raw(&s);
        assert_eq!((got.status, got.error().as_str()), (402, "too_many_sessions"));
    }
    assert_eq!(read(), after_locks, "a lock the session caps refuse asks the node for nothing");
    assert_eq!(rig.node.invoices(), 3);
    // a session at its own cap of tickets: refused as before, and again without the channel list
    let more = a.fresh_secrets(1);
    assert_eq!(a.lock_raw(&more).error(), "too_many_tickets");
    assert_eq!(read(), after_locks);
    // a lock for a session that is not authenticated never gets as far as either
    let mut forged = Buyer::new(&rig, 9);
    forged.session = a.session.clone();
    forged.seq = a.seq;
    let s = forged.fresh_secrets(1);
    assert_eq!(forged.lock_raw(&s).status, 401);
    assert_eq!(read(), after_locks);
    // one that the caps let through still reads them: b has room for one more ticket
    let s = b.fresh_secrets(1);
    assert_eq!(b.lock_raw(&s).status, 200);
    assert_eq!(read(), after_locks + 1);
}

#[test]
fn a_cancel_the_node_says_yes_to_moves_the_book_only_to_what_a_lookup_then_shows() {
    let (rig, _d) = start(&|_| {});
    let mut b = Buyer::new(&rig, 1);
    let s = b.lock(&rig, 3);
    let hashes: Vec<String> = s.iter().map(|x| hex::encode(ticket_hash(x))).collect();
    // ticket 0 is settled on the node and the gateway does not know: the settle's answer was lost,
    // and the node's stream has fallen behind
    rig.node.hold_streams(true);
    rig.node.lose_next_settle_answer();
    let got = b.release(&s[..1]);
    assert_eq!(got.json()["refused"][0]["error"], "node_unavailable");
    assert_eq!(rig.node.state_of(&ticket_hash(&s[0])), Some(InvoiceState::Settled));
    assert_eq!(b.balance(), 0, "nothing is credited on a settle with no answer");
    // a node that answers yes to the cancel of a settled invoice. The gateway does not take the
    // yes for "cancelled": it looks, finds the ticket settled, and credits it
    rig.node.cancel_answers_yes_for_settled();
    let got = b.call("cancel", &json!({"hashes": [hashes[0]]}));
    assert_eq!(got.status, 200);
    assert_eq!(got.json()["cancelled"], json!([]), "a settled ticket is not reported cancelled");
    assert_eq!(got.json()["session"]["releasedMsat"], "1000000", "and what the node holds for the seller is the buyer's credit");
    assert_eq!(b.balance(), 1_000_000);
    // an honest yes: the lookup shows the ticket cancelled, and it leaves the book
    let got = b.call("cancel", &json!({"hashes": [hashes[1]]}));
    assert_eq!(got.json()["cancelled"], json!([hashes[1]]));
    assert_eq!(rig.node.state_of(&ticket_hash(&s[1])), Some(InvoiceState::Canceled));
    // a yes, and then no answer to the lookup: the ticket stays in the book as it was, to be asked about again
    rig.node.lose_next_lookup_answer();
    let got = b.call("cancel", &json!({"hashes": [hashes[2]]}));
    assert_eq!(got.json()["cancelled"], json!([]));
    assert_eq!(b.status()["tickets"].as_array().unwrap().len(), 1, "still the session's ticket");
    let got = b.call("cancel", &json!({"hashes": [hashes[2]]}));
    assert_eq!(got.json()["cancelled"], json!([hashes[2]]));
    assert_eq!(rig.gw.stats().held_tickets, 0);
    rig.node.hold_streams(false);
    assert_eq!(b.balance(), 1_000_000, "one ticket credited, once");
}
