//! Prepaid tickets paid by BOLT 12 offer through the gateway's own listener (`docs/TICKETS.md`,
//! section 15), with the stand-in node: the offer in the terms, a session made without an invoice,
//! and a paid offer invoice credited to the session its payer note names, and to no other, once.
mod common;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use common::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use xbt402::offer::{note, Purpose};
use xbt_gateway::node::Hash;
use xbt_gateway::standin::StandIn;

const TICKET: u64 = 1_000_000;

fn offers(v: &mut Value) {
    v["offers"] = json!({"enabled": true, "description": "a test shop"});
}

fn now(rig: &Rig) -> u64 {
    rig.clock.load(Ordering::SeqCst)
}

/// A session made by a lock that pays by offer: no invoice, the session and its key.
fn by_offer(rig: &Rig, tag: u8) -> Buyer {
    let mut b = Buyer::new(rig, tag);
    let got = http(&rig.addr, "POST", "/x402/ticket/lock", &[], json!({"version": "ticket/0", "settle": "on-arrival", "by": "offer"}).to_string().as_bytes(), None);
    assert_eq!(got.status, 200, "{}", String::from_utf8_lossy(&got.body));
    let j = got.json();
    assert_eq!((j["tickets"].as_array().map(Vec::len), j["offer"].as_str()), (Some(0), rig.gw_offer().as_deref()), "{j}");
    b.session = j["session"].as_str().unwrap().to_string();
    b.key = xbt402::ticket::hex32(j["key"].as_str().unwrap()).unwrap();
    b
}

trait OfferRig {
    fn gw_offer(&self) -> Option<String>;
}

impl OfferRig for Rig {
    /// The offer the gateway's 402 names for prepaid tickets.
    fn gw_offer(&self) -> Option<String> {
        let j = http(&self.addr, "GET", "/api", &[], b"", None).json();
        j["accepts"].as_array().unwrap().iter().find(|a| a["extra"]["settle"] == "on-arrival").and_then(|a| a["extra"]["offer"].as_str()).map(str::to_string)
    }
}

fn ticket_note(b: &Buyer, nonce: u8) -> String {
    note(&b.key, &b.session, Purpose::Ticket, TICKET, &[nonce; 16])
}

fn hash_of(p: &[u8; 32]) -> Hash {
    Sha256::digest(p).into()
}

#[test]
fn the_offer_is_made_once_at_the_start_and_named_in_the_prepaid_terms_only() {
    let (rig, dir) = start(&offers);
    let offer = rig.gw_offer().expect("the prepaid entry names the offer");
    assert!(offer.starts_with("lno1"), "{offer}");
    let j = http(&rig.addr, "GET", "/api", &[], b"", None).json();
    let held = j["accepts"].as_array().unwrap().iter().find(|a| a["extra"]["settle"] == "on-use").unwrap();
    assert!(held["extra"].get("offer").is_none(), "a held ticket is a hold invoice, never an offer: {held}");
    assert_eq!(rig.node.calls("create_offer"), 1);
    assert_eq!(http(&rig.addr, "GET", "/x402/ticket/health", &[], b"", None).json()["offer"], offer);
    // the same fields make the same offer: a restart names the offer buyers already hold
    let (node, service, clock) = rig.stop();
    let again = start_on(dir.path(), node, service, clock, &offers);
    assert_eq!(again.gw_offer().as_deref(), Some(offer.as_str()));
    // a runner who did not turn offers on names none, and its node is asked for none
    let (plain, _d) = start(&|_| {});
    assert_eq!(plain.gw_offer(), None);
    assert_eq!(plain.node.calls("create_offer"), 0);
    // a node that makes no offer: the gateway does not start on terms it cannot be paid on
    struct NoOffers(StandIn);
    impl xbt_gateway::node::Node for NoOffers {
        fn add_hold(&self, h: &Hash, m: u64, c: u32, e: u32) -> Result<String, xbt_gateway::node::NodeError> { self.0.add_hold(h, m, c, e) }
        fn add_invoice(&self, p: &[u8; 32], m: u64, c: u32, e: u32) -> Result<String, xbt_gateway::node::NodeError> { self.0.add_invoice(p, m, c, e) }
        fn settle(&self, p: &[u8; 32]) -> Result<(), xbt_gateway::node::NodeError> { self.0.settle(p) }
        fn cancel(&self, h: &Hash) -> Result<(), xbt_gateway::node::NodeError> { self.0.cancel(h) }
        fn lookup(&self, h: &Hash) -> Result<Option<xbt_gateway::node::Invoice>, xbt_gateway::node::NodeError> { self.0.lookup(h) }
        fn watch(&self, h: &Hash, on: &mut dyn FnMut(xbt_gateway::node::Invoice) -> bool) -> Result<(), xbt_gateway::node::NodeError> { self.0.watch(h, on) }
        fn info(&self) -> Result<xbt_gateway::node::Info, xbt_gateway::node::NodeError> { self.0.info() }
    }
    let d = tempfile::tempdir().unwrap();
    let svc = start_service();
    let cfg = config(d.path(), &format!("http://{}", svc.0.addr), &offers);
    let started = xbt_gateway::gateway::Gateway::start(xbt_gateway::config::Config::from_json(&cfg).unwrap(), Arc::new(NoOffers(StandIn::new(100))), receipt_secret(), Box::new(|| 1));
    assert!(started.err().unwrap().to_string().contains("made no BOLT 12 offer"));
    // offers beside no way they pay is a config that is refused
    let mut held_only = config(d.path(), "http://127.0.0.1:1", &offers);
    held_only["tickets"]["settle"] = json!(["on-use"]);
    assert!(xbt_gateway::config::Config::from_json(&held_only).unwrap_err().to_string().contains("offers"));
}

#[test]
fn a_lock_to_pay_by_offer_makes_a_session_and_asks_the_node_for_no_invoice() {
    let (rig, _d) = start(&offers);
    let mut b = by_offer(&rig, 1);
    assert_eq!(rig.node.invoices(), 0, "no invoice was made");
    // the session is a session: its requests are authenticated, and a later lock by offer is one of them
    assert_eq!(b.balance(), 0);
    let body = json!({"version": "ticket/0", "settle": "on-arrival", "by": "offer", "session": b.session}).to_string();
    let sig = b.sign("POST", "/x402/ticket/lock", body.as_bytes(), None, None);
    let got = http(&rig.addr, "POST", "/x402/ticket/lock", &[("PAYMENT-SIGNATURE", &sig)], body.as_bytes(), None);
    b.used(&got);
    assert_eq!((got.status, got.json()["tickets"].as_array().map(Vec::len)), (200, Some(0)));
    got.receipt(&rig.gw.terms().receipt_key);
    // a lock by offer that also names a count, or one for held tickets, is no such lock
    for bad in [json!({"version": "ticket/0", "settle": "on-arrival", "by": "offer", "count": 1}), json!({"version": "ticket/0", "by": "offer", "hashes": []}),
                json!({"version": "ticket/0", "settle": "on-arrival", "by": "invoice"})] {
        assert_eq!(http(&rig.addr, "POST", "/x402/ticket/lock", &[], bad.to_string().as_bytes(), None).status, 400, "{bad}");
    }
    // a seller whose terms name no offer takes no lock by offer
    let (plain, _d2) = start(&|_| {});
    let got = http(&plain.addr, "POST", "/x402/ticket/lock", &[], json!({"version": "ticket/0", "settle": "on-arrival", "by": "offer"}).to_string().as_bytes(), None);
    assert_eq!(got.status, 400);
}

#[test]
fn a_paid_offer_invoice_with_a_good_note_credits_its_session_once_and_no_other() {
    let (rig, _d) = start(&offers);
    let mut a = by_offer(&rig, 1);
    let mut other = by_offer(&rig, 2);
    let p = rig.node.pay_by_offer(Some(&ticket_note(&a, 1)), TICKET, now(&rig));
    // the buyer shows its preimage, as for any prepaid ticket: the node's word credits it
    let got = a.release(&[p]);
    assert_eq!(got.status, 200, "{}", String::from_utf8_lossy(&got.body));
    let r = got.receipt(&rig.gw.terms().receipt_key);
    assert_eq!((got.json()["released"][0].as_str(), r["releasedMsat"].as_str()), (Some(hex::encode(hash_of(&p)).as_str()), Some("1000000")), "{}", got.json());
    assert_eq!((a.balance(), other.balance()), (TICKET, 0), "the session the note names, and no other");
    // shown again: used, and nothing more is credited
    assert_eq!(a.release(&[p]).json()["refused"][0]["error"], "ticket_used");
    // another session showing that preimage gets nothing for it
    assert_eq!(other.release(&[p]).json()["refused"][0]["error"], "ticket_unknown");
    assert_eq!((a.balance(), other.balance()), (TICKET, 0));
    // and the balance pays requests
    assert_eq!(a.get("/api", None).status, 200);
    assert_eq!(a.balance(), TICKET - 2500);
}

#[test]
fn a_payment_by_offer_nobody_shows_is_credited_by_the_janitor() {
    let (rig, _d) = start(&offers);
    let mut a = by_offer(&rig, 1);
    rig.node.pay_by_offer(Some(&ticket_note(&a, 1)), TICKET, now(&rig));
    wait_for("the janitor's credit", || a.balance() == TICKET);
    assert!(rig.node.calls("offer_invoices") >= 1);
}

#[test]
fn a_note_that_is_wrong_replayed_or_late_credits_nothing() {
    let (rig, dir) = start(&offers);
    let mut a = by_offer(&rig, 1);
    let mut b = by_offer(&rig, 2);
    let t = now(&rig);
    let forged = note(&a.key, &b.session, Purpose::Ticket, TICKET, &[1; 16]);
    let short = note(&a.key, &a.session, Purpose::Ticket, TICKET - 1, &[2; 16]);
    let win = note(&a.key, &a.session, Purpose::Win(1), TICKET, &[3; 16]);
    let cases: Vec<(&str, Option<String>, u64, u64)> = vec![
        ("b's session under a's key", Some(forged), TICKET, t),
        ("an amount that is not the ticket's", Some(short), TICKET, t),
        ("a win's note for a ticket session", Some(win), TICKET, t),
        ("a note that is not one", Some("ticket for session".into()), TICKET, t),
        ("no note", None, TICKET, t),
        ("paid short of the ticket", Some(ticket_note(&a, 4)), TICKET - 1, t),
        ("issued more than a day ago", Some(ticket_note(&a, 5)), TICKET, t - 86_401),
    ];
    for (what, n, paid, at) in &cases {
        let p = rig.node.pay_by_offer(n.as_deref(), *paid, *at);
        for buyer in [&mut a, &mut b] {
            let got = buyer.release(&[p]);
            assert_eq!(got.json()["refused"][0]["error"], "ticket_unknown", "{what}: {}", got.json());
        }
        assert_eq!((a.balance(), b.balance()), (0, 0), "{what}");
    }
    // a good note credits once; the same note on a second paid invoice credits nothing
    let good = ticket_note(&a, 9);
    let first = rig.node.pay_by_offer(Some(&good), TICKET, t);
    assert_eq!(a.release(&[first]).json()["released"].as_array().map(Vec::len), Some(1));
    let replay = rig.node.pay_by_offer(Some(&good), TICKET, t);
    assert_eq!(a.release(&[replay]).json()["refused"][0]["error"], "ticket_unknown");
    assert_eq!(a.balance(), TICKET);
    // an invoice that was fetched and never paid credits nothing
    let open = rig.node.issue_offer_invoice(Some(&ticket_note(&a, 10)), t);
    assert_eq!(a.release(&[open]).json()["refused"][0]["error"], "ticket_unknown");
    // a restart keeps what was credited by offer, and with it the refusal of the replay
    let seq = a.seq;
    let (node, service, clock) = rig.stop();
    let rig = start_on(dir.path(), node, service, clock, &offers);
    a.addr = rig.addr.clone();
    a.seq = seq;
    let again = rig.node.pay_by_offer(Some(&good), TICKET, t);
    assert_eq!(a.release(&[again]).json()["refused"][0]["error"], "ticket_unknown");
    assert_eq!(a.release(&[first]).json()["released"].as_array().map(Vec::len), Some(1), "its own payment is still answered for");
    assert_eq!(a.balance(), TICKET, "credited once, across the restart");
    let journal = std::fs::read_to_string(dir.path().join(xbt_gateway::gateway::OFFERS_JOURNAL)).unwrap();
    assert_eq!(journal.lines().count(), 1, "one payment credited by offer: {journal}");
}

#[test]
fn the_node_away_is_said_as_such_and_the_payment_is_credited_when_it_is_back() {
    let (rig, _d) = start(&offers);
    let mut a = by_offer(&rig, 1);
    rig.node.set_down(true);
    let p = rig.node.pay_by_offer(Some(&ticket_note(&a, 1)), TICKET, now(&rig));
    let got = a.release(&[p]);
    assert_eq!(got.json()["refused"][0]["error"], "node_unavailable", "{}", got.json());
    rig.node.set_down(false);
    wait_for("the credit once the node is back", || a.release(&[p]).json()["released"].as_array().is_some_and(|r| r.len() == 1) || a.balance() == TICKET);
    assert_eq!(a.balance(), TICKET);
}
