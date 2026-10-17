//! The lottery through the gateway's own listener (`docs/TICKETS.md`, section 9), with a stand-in
//! node and a real service behind it. The buyer here is `xbt402::lottery::Buyer`, the same checks
//! the wallet's signer makes. Each test names the rule it holds the gateway to;
//! `scripts/lottery_regtest.sh` holds the shipped binaries to the same rules on Lightning Fork nodes.
mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use serde_json::{json, Value};
use xbt402::lottery::{self, Kind, Outcome, Piece, PieceId};
use xbt402::ticket::hex32;
use xbt402::wire::{b64json, request_digest_v2, unb64json};
use xbt402::xbt_primitives::ecdsa;
use xbt_gateway::node::{Hash, InvoiceState};

const PIECE: u64 = 65_536;

/// The tests' lottery: wins of 4,000 msat, so that a 2,500-msat page wins five times in eight
/// and a test meets wins without thousands of draws. A runner who wanted that says
/// `max_odds_den: 1`, as here; the shipped rule (a piece is a quarter of a win at the most) has
/// its own test.
fn lottery(v: &mut Value) {
    v["lottery"] = json!({"win_msat": 4000, "min_win_msat": 2000, "window": 3, "piece_bytes": PIECE, "grace_seconds": 10, "grace_pieces": 4,
                          "max_unpaid_wins": 2, "chain_draws": 4096, "sessions_per_address": 0, "max_sessions": 8, "max_voids": 2, "max_odds_den": 1});
    // a megabyte for 16,000 msat: a piece of 64 KiB costs 1,000 msat, a quarter of a win
    v["routes"][0]["price"] = json!({"byte_msat": 16000, "per_bytes": 1048576});
    for r in v["routes"].as_array_mut().unwrap() {
        if r["path"] == "/timed/" {
            r["price"] = json!({"second_msat": 1000});
        }
    }
}

fn check_draw_receipt(r: &Value, key: &str) {
    let sig = hex::decode(r["sig"].as_str().unwrap()).unwrap();
    assert!(ecdsa::verify(&hex::decode(key).unwrap(), &lottery::receipt_message(r), &sig), "bad receipt signature: {r}");
    assert_eq!(r["scheme"], "lottery");
}

fn receipt_of(got: &Got, key: &str) -> Value {
    let sr = unb64json(got.header("PAYMENT-RESPONSE").expect("no PAYMENT-RESPONSE")).unwrap();
    let r = sr["extra"]["receipt"].clone();
    check_draw_receipt(&r, key);
    r
}

/// A buyer in a lottery session: the wire, and the draw's own checks.
struct Drawer {
    addr: String,
    origin: String,
    session: String,
    key: [u8; 32],
    seq: u64,
    receipt_key: String,
    win_msat: u64,
    draws: lottery::Buyer,
    values: u64,
    tag: u8,
    /// Every outcome it worked out, and the wins among them it has not paid.
    outcomes: Vec<Outcome>,
    owed: Vec<u64>,
}

impl Drawer {
    fn open_raw(rig: &Rig, body: &Value) -> Got {
        http(&rig.addr, "POST", "/x402/lottery/open", &[], body.to_string().as_bytes(), None)
    }

    fn open(rig: &Rig, tag: u8) -> Self {
        Self::open_sized(rig, tag, None)
    }

    fn open_sized(rig: &Rig, tag: u8, win_msat: Option<&str>) -> Self {
        let got = Self::open_raw(rig, &json!({"version": "lottery/0", "winMsat": win_msat}));
        assert_eq!(got.status, 200, "{}", String::from_utf8_lossy(&got.body));
        let j = got.json();
        let session = j["session"].as_str().unwrap().to_string();
        let win_msat: u64 = j["winMsat"].as_str().unwrap().parse().unwrap();
        let anchor = hex32(j["anchor"].as_str().unwrap()).unwrap();
        let draws = lottery::Buyer::new(&session, win_msat, anchor, j["chainDraws"].as_u64().unwrap() as u32).unwrap();
        Self {
            addr: rig.addr.clone(),
            origin: rig.origin.clone(),
            key: hex32(j["key"].as_str().unwrap()).unwrap(),
            session,
            seq: 0,
            receipt_key: rig.gw.terms().receipt_key.clone(),
            win_msat,
            draws,
            values: 0,
            tag,
            outcomes: vec![],
            owed: vec![],
        }
    }

    fn sign_at(&self, seq: u64, method: &str, target: &str, body: &[u8]) -> String {
        let digest = request_digest_v2(method, &format!("{}{target}", self.origin), body);
        let auth = lottery::request_auth(&self.key, &self.session, seq, &digest);
        b64json(&json!({"x402Version": 2, "accepted": {"scheme": "lottery", "network": NET, "extra": {"layer": "lightning"}},
                        "payload": {"session": self.session, "seq": seq, "auth": auth}}))
    }

    fn digest(&self, method: &str, target: &str, body: &[u8]) -> [u8; 32] {
        hex32(&request_digest_v2(method, &format!("{}{target}", self.origin), body)).unwrap()
    }

    /// One request of the session; its `seq` is used up if the answer carries a receipt.
    fn send(&mut self, method: &str, target: &str, body: &[u8]) -> (u64, Got) {
        let seq = self.seq;
        let sig = self.sign_at(seq, method, target, body);
        let got = http(&self.addr, method, target, &[("PAYMENT-SIGNATURE", &sig)], body, None);
        if got.header("PAYMENT-RESPONSE").is_some() {
            self.seq += 1;
        }
        (seq, got)
    }

    fn get(&mut self, target: &str) -> (u64, Got) {
        self.send("GET", target, b"")
    }

    fn call(&mut self, what: &str, body: &Value) -> Got {
        self.send("POST", &format!("/x402/lottery/{what}"), body.to_string().as_bytes()).1
    }

    fn fresh_value(&mut self) -> [u8; 32] {
        self.values += 1;
        let mut v = [self.tag; 32];
        v[..8].copy_from_slice(&self.values.to_be_bytes());
        // not a constant in its first bytes only: hash it
        xbt402::ticket::ticket_hash(&v)
    }

    fn piece(&self, seq: u64, target: &str, kind: Kind, k: u64, amount_msat: u64) -> Piece {
        Piece { id: PieceId { seq, kind, k }, req: self.digest("GET", target, b""), amount_msat }
    }

    /// Give a value for each of `pieces` and send them: the seller's answer, checked. A win is
    /// noted as owed, never paid here.
    fn draw(&mut self, pieces: &[Piece]) -> Value {
        for p in pieces {
            let v = self.fresh_value();
            self.draws.issue(*p, v, 64).unwrap();
        }
        self.send_open()
    }

    /// Send every value no reveal covers yet, and take the answer.
    fn send_open(&mut self) -> Value {
        let values: Vec<Value> = self
            .draws
            .open()
            .map(|(d, p, v)| json!({"draw": d, "seq": p.id.seq, "kind": p.id.kind.name(), "k": p.id.k, "amountMsat": p.amount_msat.to_string(), "value": hex::encode(v)}))
            .collect();
        let got = self.call("draw", &json!({"values": values}));
        assert_eq!(got.status, 200, "{}", String::from_utf8_lossy(&got.body));
        receipt_of(&got, &self.receipt_key);
        let j = got.json();
        self.absorb(&j);
        j
    }

    fn absorb(&mut self, j: &Value) {
        let Some(reveal) = j["reveal"].as_str() else { return };
        let out = self.draws.absorb(j["drawn"].as_u64().unwrap(), &hex32(reveal).unwrap()).unwrap();
        for o in out {
            if let Some(w) = &o.win {
                self.owed.push(w.draw());
            }
            self.outcomes.push(o);
        }
    }

    fn hash_in(j: &Value, draw: u64) -> Hash {
        let w = j["wins"].as_array().unwrap().iter().find(|w| w["draw"].as_u64() == Some(draw)).unwrap_or_else(|| panic!("no invoice for win {draw}: {j}"));
        hex32(w["invoice"].as_str().unwrap().strip_prefix("lnbcrt-standin-").unwrap()).unwrap()
    }

    /// The hash of the invoice the seller sent for a win this buyer worked out itself.
    fn invoice_hash(&self, j: &Value, draw: u64) -> Hash {
        assert!(self.owed.contains(&draw), "the seller invoices a draw this buyer did not find won: {j}");
        Self::hash_in(j, draw)
    }

    /// Pay every win owed, on the node, as its invoice in `j` says.
    fn pay_all(&mut self, rig: &Rig, j: &Value) {
        for d in std::mem::take(&mut self.owed) {
            assert!(rig.node.pay(&Self::hash_in(j, d)), "the win's invoice is open on the node");
        }
    }

    fn status(&mut self) -> Value {
        let got = self.call("status", &json!({}));
        assert_eq!(got.status, 200, "{}", String::from_utf8_lossy(&got.body));
        receipt_of(&got, &self.receipt_key);
        got.json()
    }
}

/// A GET whose body is read as it arrives: `seen` is the bytes received so far.
fn stream_get(addr: String, target: String, sig: String, seen: Arc<AtomicUsize>) -> std::thread::JoinHandle<Got> {
    std::thread::spawn(move || {
        let mut s = TcpStream::connect(&addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        s.write_all(format!("GET {target} HTTP/1.1\r\nHost: gateway.test:8402\r\nPAYMENT-SIGNATURE: {sig}\r\n\r\n").as_bytes()).unwrap();
        let mut raw = Vec::new();
        let mut buf = [0u8; 16384];
        let split = loop {
            if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                break i;
            }
            match s.read(&mut buf) {
                Ok(0) | Err(_) => panic!("no response head: {:?}", String::from_utf8_lossy(&raw)),
                Ok(n) => raw.extend_from_slice(&buf[..n]),
            }
        };
        let head = String::from_utf8_lossy(&raw[..split]).into_owned();
        let mut lines = head.split("\r\n");
        let status: u16 = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
        let headers: Vec<(String, String)> = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
        let length = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.parse::<usize>().ok()).expect("a body with a length");
        let mut body = raw[split + 4..].to_vec();
        seen.store(body.len(), Ordering::SeqCst);
        while body.len() < length {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => body.extend_from_slice(&buf[..n]),
            }
            seen.store(body.len(), Ordering::SeqCst);
        }
        let complete = body.len() >= length;
        Got { status, headers, body, complete }
    })
}

#[test]
fn the_402_offers_the_lottery_last_and_only_where_every_piece_costs_less_than_a_win() {
    let (rig, _d) = start(&lottery);
    let got = http(&rig.addr, "GET", "/api", &[], b"", None);
    assert_eq!(got.status, 402);
    let j = got.json();
    let accepts = j["accepts"].as_array().unwrap();
    assert_eq!(accepts.iter().map(|a| a["scheme"].as_str().unwrap()).collect::<Vec<_>>(), ["ticket", "ticket", "lottery"], "held, prepaid, and the lottery last");
    let l = &accepts[2];
    assert_eq!((l["amount"].as_str(), l["network"].as_str(), l["payTo"].as_str()), (Some("2500"), Some(NET), Some(rig.gw.terms().pay_to.as_str())));
    let e = &l["extra"];
    assert_eq!((e["version"].as_str(), e["winMsat"].as_str(), e["minWinMsat"].as_str(), e["pay"].as_str(), e["release"].as_str()),
               (Some("lottery/0"), Some("4000"), Some("2000"), Some("on-win"), Some("after-answer")));
    assert_eq!((e["window"].as_u64(), e["graceSeconds"].as_u64(), e["gracePieces"].as_u64(), e["maxUnpaidWins"].as_u64()), (Some(3), Some(10), Some(4), Some(2)));
    assert_eq!((e["chainDraws"].as_u64(), e["pieceBytes"].as_str(), e["session"].as_str()), (Some(4096), Some("65536"), Some("/x402/lottery")));
    assert_eq!(e["receiptKey"].as_str(), Some(rig.gw.terms().receipt_key.as_str()));
    assert_eq!(e["price"]["requestMsat"], "2500");
    assert_eq!(unb64json(got.header("PAYMENT-REQUIRED").unwrap()).unwrap(), j, "the header is the body");
    // a checkable route priced at 400,000 msat a piece: dearer than a win, so tickets only
    let dear = http(&rig.addr, "GET", "/verify/10", &[], b"", None).json();
    assert!(dear["accepts"].as_array().unwrap().iter().all(|a| a["scheme"] == "ticket"));
    // the list of what is sold says which routes take draws
    let s = http(&rig.addr, "GET", "/services", &[], b"", None).json();
    assert_eq!(s["lottery"]["winMsat"], "4000");
    let by = |p: &str| s["routes"].as_array().unwrap().iter().find(|r| r["path"] == p).unwrap()["lottery"].clone();
    assert_eq!((by("/api"), by("/verify/"), by("/files/free/")), (json!(true), json!(false), json!(false)));
    assert_eq!(rig.hits(), 0, "nothing reached the service");
    // a seller that does not offer the lottery has no entry and no endpoint
    let (plain, _d2) = start(&|_| {});
    let j = http(&plain.addr, "GET", "/api", &[], b"", None).json();
    assert!(j["accepts"].as_array().unwrap().iter().all(|a| a["scheme"] == "ticket"));
    assert_eq!(Drawer::open_raw(&plain, &json!({"version": "lottery/0"})).status, 404);
}

#[test]
fn a_page_is_paid_by_draws_and_a_win_is_paid_when_the_node_says_so() {
    let (rig, _d) = start(&lottery);
    let mut b = Drawer::open(&rig, 1);
    assert_eq!((rig.node.invoices(), b.win_msat), (0, 4000), "opening a session asks the node for nothing");
    let (mut served, mut wins, mut paid) = (0u64, 0u64, 0u64);
    for n in 0..40u64 {
        let (seq, got) = b.get("/api");
        assert_eq!(got.status, 200, "request {n}: {}", String::from_utf8_lossy(&got.body));
        let r = receipt_of(&got, &b.receipt_key);
        served += 2500;
        assert_eq!((r["seq"].as_u64(), r["charged"].as_str(), r["servedMsat"].as_str()), (Some(seq), Some("2500"), Some(served.to_string().as_str())));
        // the value follows the answer; the seller reveals, and both sides know the result
        let p = b.piece(seq, "/api", Kind::Request, 0, 2500);
        let j = b.draw(&[p]);
        assert_eq!((j["drawn"].as_u64(), j["refused"].clone()), (Some(n + 1), Value::Null));
        let won = b.outcomes.last().unwrap().win.is_some();
        wins += u64::from(won);
        // the seller lists exactly the wins this buyer worked out and has not paid
        let listed: Vec<u64> = j["wins"].as_array().unwrap().iter().map(|w| w["draw"].as_u64().unwrap()).collect();
        assert_eq!(listed, b.owed, "draw {}", n + 1);
        if won {
            // nothing is paid on the buyer's word: the session's totals move when the node shows the invoice settled
            assert_eq!(b.status()["session"]["paidMsat"], (paid * 4000).to_string());
            b.pay_all(&rig, &j);
            paid += 1;
            let st = b.status();
            assert_eq!((st["session"]["paidMsat"].as_str(), st["wins"].as_array().unwrap().len()), (Some((paid * 4000).to_string().as_str()), 0));
        }
    }
    // 40 draws at 5 in 8: 25 expected; and what the node was paid is the wins, each once
    assert!((12..=36).contains(&wins), "{wins}");
    assert_eq!(rig.node.count(InvoiceState::Settled) as u64, wins);
    assert_eq!(rig.node.invoices() as u64, wins, "an invoice per win and no other");
    let st = b.status();
    assert_eq!((st["session"]["servedMsat"].as_str(), st["session"]["wonMsat"].as_str(), st["session"]["drawn"].as_u64()),
               (Some("100000"), Some((wins * 4000).to_string().as_str()), Some(40)));
    assert_eq!(rig.hits(), 40);
    assert_eq!(rig.gw.stats().held_tickets, 0, "nothing is held for a lottery session");
}

#[test]
fn a_body_priced_per_byte_is_cut_into_pieces_that_are_each_a_draw() {
    let (rig, _d) = start(&lottery);
    let mut b = Drawer::open(&rig, 2);
    // 10 pieces and 100 bytes: 10 full pieces of 1,000 msat and a last one of 2 msat
    let size = 10 * PIECE as usize + 100;
    let target = format!("/files/{size}");
    let seq = b.seq;
    let sig = b.sign_at(seq, "GET", &target, b"");
    b.seq += 1;
    let seen = Arc::new(AtomicUsize::new(0));
    let get = stream_get(rig.addr.clone(), target.clone(), sig, seen.clone());
    let mut valued = 0u64;
    let mut most_ahead = 0u64;
    let deadline = Instant::now() + Duration::from_secs(20);
    while valued < 10 {
        if Instant::now() >= deadline {
            panic!("the body stopped at {} bytes, {valued} pieces valued: {}", seen.load(Ordering::SeqCst), b.status());
        }
        let have = seen.load(Ordering::SeqCst) as u64 / PIECE;
        most_ahead = most_ahead.max(have.saturating_sub(valued));
        if have == valued {
            std::thread::sleep(Duration::from_millis(2));
            continue;
        }
        // a value for every piece that has arrived whole, and the wins paid as they come
        let pieces: Vec<Piece> = (valued..have.min(10)).map(|k| b.piece(seq, &target, Kind::Bytes, k, 1000)).collect();
        valued += pieces.len() as u64;
        let j = b.draw(&pieces);
        assert_eq!(j["refused"], Value::Null, "{j}");
        b.pay_all(&rig, &j);
    }
    let got = get.join().unwrap();
    assert!(got.status == 200 && got.complete && got.body.len() == size);
    assert!(got.body.iter().enumerate().all(|(i, c)| *c == pattern(i)), "the bytes are the service's");
    assert!(most_ahead <= 4, "the seller sent {most_ahead} pieces beyond the last value: its window is 3 (and one piece in flight)");
    // the head's receipt: nothing charged before the body, and it says the body is streamed
    let head = unb64json(got.header("PAYMENT-RESPONSE").unwrap()).unwrap();
    assert_eq!((head["extra"]["stream"].clone(), head["extra"]["receipt"]["charged"].as_str()), (json!(true), Some("0")));
    check_draw_receipt(&head["extra"]["receipt"], &b.receipt_key);
    // the last piece is the body's 100 odd bytes, priced so that the pieces add up to the body's price
    let last = b.piece(seq, &target, Kind::Bytes, 10, 2);
    let j = b.draw(&[last]);
    assert_eq!(j["refused"], Value::Null, "{j}");
    b.pay_all(&rig, &j);
    let st = b.status();
    assert_eq!(st["session"]["servedMsat"], "10002", "16,000 msat a MiB over 655,460 bytes, rounded up once");
    assert_eq!((st["session"]["pending"].as_u64(), st["session"]["drawn"].as_u64()), (Some(0), Some(11)));
    let fin = &st["responses"][0];
    check_draw_receipt(fin, &b.receipt_key);
    assert_eq!((fin["seq"].as_u64(), fin["charged"].as_str(), fin["bytes"].as_u64(), fin["complete"].clone()), (Some(seq), Some("10002"), Some(size as u64), json!(true)));
    assert_eq!(fin["bodyHash"].as_str().unwrap(), xbt402::wire::body_hash(&got.body));
    assert_eq!(st["session"]["paidMsat"], st["session"]["wonMsat"]);
}

#[test]
fn a_buyer_that_sends_no_values_gets_the_window_and_a_buyer_that_never_pays_gets_the_grace() {
    let (rig, _d) = start(&lottery);
    // no values: three pages, and the fourth is refused with the code that says why
    let mut quiet = Drawer::open(&rig, 3);
    for _ in 0..3 {
        assert_eq!(quiet.get("/api").1.status, 200);
    }
    let (_, got) = quiet.get("/api");
    assert_eq!((got.status, got.error().as_str()), (402, "value_missing"));
    assert_eq!(receipt_of(&got, &quiet.receipt_key)["charged"], "0");
    assert_eq!(rig.hits(), 3);
    // a body: the window's three pieces arrive, and after the wait for a value it is cut short
    let mut quiet2 = Drawer::open(&rig, 4);
    let (_, body) = quiet2.get(&format!("/files/{}", 10 * PIECE));
    assert!(body.status == 200 && !body.complete, "cut where the buyer can see it");
    assert_eq!(body.body.len() as u64, 3 * PIECE);
    // values but no payment: served on for grace_pieces after the first win, then nothing
    let mut cheat = Drawer::open(&rig, 5);
    let mut after_win = 0;
    let mut refused = None;
    for _ in 0..60 {
        let (seq, got) = cheat.get("/api");
        if got.status != 200 {
            refused = Some(got);
            break;
        }
        if !cheat.owed.is_empty() {
            after_win += 1;
        }
        let p = cheat.piece(seq, "/api", Kind::Request, 0, 2500);
        cheat.draw(&[p]);
    }
    let refused = refused.expect("a buyer that pays no win is stopped");
    assert_eq!((refused.status, refused.error().as_str()), (402, "win_unpaid"));
    // by pieces (4 more after the first unpaid win) or by count (a third unpaid win), whichever came first
    assert!((1..=4).contains(&after_win), "{after_win} pages after the first unpaid win");
    let j = refused.json();
    assert!(!j["session"]["wins"].as_array().unwrap().is_empty(), "the refusal carries the unpaid wins and their invoices");
    assert!(j["accepts"].as_array().unwrap().iter().any(|a| a["scheme"] == "lottery"));
    // the free service: what was served less what was paid, which is nothing
    let st = cheat.status();
    let served: u64 = st["session"]["servedMsat"].as_str().unwrap().parse().unwrap();
    assert!(served <= 60 * 2500 && st["session"]["paidMsat"] == "0");
    // paying the wins (the node's word) opens the session again
    cheat.pay_all(&rig, &st);
    assert_eq!(cheat.get("/api").1.status, 200);
    // by time: one more win, unpaid, and the clock moves past grace_seconds
    let mut slow = Drawer::open(&rig, 6);
    loop {
        let (seq, got) = slow.get("/api");
        assert_eq!(got.status, 200);
        let p = slow.piece(seq, "/api", Kind::Request, 0, 2500);
        slow.draw(&[p]);
        if !slow.owed.is_empty() {
            break;
        }
    }
    assert_eq!(slow.get("/api").1.status, 200, "inside the grace");
    let p = slow.piece(slow.seq - 1, "/api", Kind::Request, 0, 2500);
    let j = slow.draw(&[p]);
    rig.advance(11);
    assert_eq!(slow.get("/api").1.error(), "win_unpaid");
    slow.pay_all(&rig, &j);
    assert_eq!(slow.get("/api").1.status, 200);
}

#[test]
fn a_hostile_buyer_changes_no_draw_and_learns_no_chain_value_early() {
    let (rig, _d) = start(&lottery);
    let mut b = Drawer::open(&rig, 7);
    let mut other = Drawer::open(&rig, 8);
    let (seq, got) = b.get("/api");
    assert_eq!(got.status, 200);
    let p = b.piece(seq, "/api", Kind::Request, 0, 2500);
    let body = |draw: u64, p: &Piece, amount: u64, value: &[u8; 32]| {
        json!({"values": [{"draw": draw, "seq": p.id.seq, "kind": p.id.kind.name(), "k": p.id.k, "amountMsat": amount.to_string(), "value": hex::encode(value)}]})
    };
    let (v1, v2) = (b.fresh_value(), b.fresh_value());
    // without the session's key, or with another session's: nothing, and nothing is told
    let raw = body(1, &p, 2500, &v1).to_string();
    assert_eq!(http(&rig.addr, "POST", "/x402/lottery/draw", &[], raw.as_bytes(), None).status, 401);
    let forged = b64json(&json!({"x402Version": 2, "accepted": {"scheme": "lottery", "network": NET, "extra": {"layer": "lightning"}},
        "payload": {"session": b.session, "seq": b.seq, "auth": lottery::request_auth(&other.key, &b.session, b.seq, &request_digest_v2("POST", &format!("{}/x402/lottery/draw", b.origin), raw.as_bytes()))}}));
    let got = http(&rig.addr, "POST", "/x402/lottery/draw", &[("PAYMENT-SIGNATURE", &forged)], raw.as_bytes(), None);
    assert_eq!((got.status, got.error().as_str()), (401, "bad_auth"));
    // a value for a draw that is not the next, for a piece that was not served, at a price that is not the piece's
    for (bad, code) in [
        (body(2, &p, 2500, &v1), "draw_out_of_order"),
        (body(1, &b.piece(seq + 9, "/api", Kind::Request, 0, 2500), 2500, &v1), "piece_unknown"),
        (body(1, &b.piece(seq, "/api", Kind::Bytes, 0, 2500), 2500, &v1), "piece_unknown"),
        (body(1, &p, 2499, &v1), "amount_mismatch"),
    ] {
        let j = b.call("draw", &bad).json();
        assert_eq!((j["refused"]["error"].as_str(), j["drawn"].as_u64(), j["reveal"].clone()), (Some(code), Some(0), Value::Null), "{bad}");
    }
    // the value is taken; the reveal comes with it and not before
    let first = b.call("draw", &body(1, &p, 2500, &v1)).json();
    assert_eq!((first["drawn"].as_u64(), first["refused"].clone()), (Some(1), Value::Null));
    let reveal = first["reveal"].as_str().unwrap().to_string();
    // having seen the reveal, the buyer sends another value for the same draw: refused, and the result stands
    let second = b.call("draw", &body(1, &p, 2500, &v2)).json();
    assert_eq!((second["refused"]["error"].as_str(), second["drawn"].as_u64(), second["reveal"].as_str()), (Some("value_conflict"), Some(1), Some(reveal.as_str())));
    // the same message again is answered as before
    let again = b.call("draw", &body(1, &p, 2500, &v1)).json();
    assert_eq!((again["refused"].clone(), again["reveal"].as_str(), again["wins"].clone()), (Value::Null, Some(reveal.as_str()), first["wins"].clone()));
    // a value used before, for the next draw
    let (seq2, _) = b.get("/api");
    let p2 = b.piece(seq2, "/api", Kind::Request, 0, 2500);
    assert_eq!(b.call("draw", &body(2, &p2, 2500, &v1)).json()["refused"]["error"], "value_reused");
    // a replayed request of the session is not served twice
    let sig = b.sign_at(seq2, "GET", "/api", b"");
    let replay = http(&rig.addr, "GET", "/api", &[("PAYMENT-SIGNATURE", &sig)], b"", None);
    assert_eq!((replay.status, replay.error().as_str()), (402, "bad_seq"));
    // values in the request's own header are not a thing: one path for a value
    let with_values = b64json(&json!({"x402Version": 2, "accepted": {"scheme": "lottery", "network": NET, "extra": {"layer": "lightning"}},
        "payload": {"session": b.session, "seq": b.seq, "auth": "0".repeat(64), "values": []}}));
    assert_eq!(http(&rig.addr, "GET", "/api", &[("PAYMENT-SIGNATURE", &with_values)], b"", None).status, 400);
    // a body that is not a draw request uses up no seq
    let before = b.seq;
    for bad in [json!({"values": "x"}), json!({"values": [{"draw": 1}]}), json!({"secrets": []}), json!({"values": vec![json!({}); 65]})] {
        assert_eq!(b.call("draw", &bad).status, 400, "{bad}");
    }
    assert_eq!(b.seq, before);
    // the other session saw none of this: its draws are its own
    assert_eq!(other.status()["session"]["drawn"], 0);
    assert_eq!(rig.hits(), 2);
}

#[test]
fn a_win_is_paid_only_by_its_own_invoice_in_full_and_an_invoice_that_lapsed_is_replaced() {
    let (rig, _d) = start(&lottery);
    let mut b = Drawer::open(&rig, 9);
    let j = loop {
        let (seq, got) = b.get("/api");
        assert_eq!(got.status, 200);
        let p = b.piece(seq, "/api", Kind::Request, 0, 2500);
        let j = b.draw(&[p]);
        if !b.owed.is_empty() {
            break j;
        }
    };
    let draw = b.owed[0];
    let h = b.invoice_hash(&j, draw);
    // a payment of less than the win does not pay it
    assert!(rig.node.pay_msat(&h, Some(3999)));
    assert_eq!(b.status()["session"]["paidMsat"], "0");
    // the win's invoice lapses unpaid on a fresh session: the next answer carries another, and the old one pays nothing
    let mut c = Drawer::open(&rig, 10);
    let j = loop {
        let (seq, got) = c.get("/api");
        assert_eq!(got.status, 200);
        let p = c.piece(seq, "/api", Kind::Request, 0, 2500);
        let j = c.draw(&[p]);
        if !c.owed.is_empty() {
            break j;
        }
    };
    let old = c.invoice_hash(&j, c.owed[0]);
    rig.node.expire_unpaid(&old);
    let st = c.status();
    let new = c.invoice_hash(&st, c.owed[0]);
    assert_ne!(old, new);
    assert!(!rig.node.pay(&old) && rig.node.pay(&new));
    let st = c.status();
    assert_eq!((st["session"]["paidMsat"].as_str(), st["wins"].as_array().unwrap().len()), (Some("4000"), 0));
    // the node away: a win stays unpaid and is asked about again, nothing is assumed
    rig.node.set_down(true);
    let _ = c.status();
    rig.node.set_down(false);
    assert_eq!(c.status()["session"]["paidMsat"], "4000");
}

#[test]
fn a_body_priced_per_second_is_a_draw_for_every_second_it_is_open() {
    let (rig, _d) = start(&lottery);
    let mut b = Drawer::open(&rig, 11);
    // the service sends 8 KiB every 100 ms: 20 of them are open for two seconds and a little
    let target = "/timed/163840";
    let (seq, got) = b.get(target);
    assert!(got.status == 200 && got.complete && got.body.len() == 163_840, "three seconds fit the window of 3");
    let st = b.status();
    let fin = &st["responses"][0];
    let seconds = fin["seconds"].as_u64().unwrap();
    assert!((2..=3).contains(&seconds), "{fin}");
    assert_eq!((fin["charged"].as_str(), st["session"]["servedMsat"].as_str()), (Some((seconds * 1000).to_string().as_str()), Some((seconds * 1000).to_string().as_str())));
    // a second is a piece when it starts: each has its draw, and a second that never started has none
    let pieces: Vec<Piece> = (0..seconds).map(|k| b.piece(seq, target, Kind::Second, k, 1000)).collect();
    let j = b.draw(&pieces);
    assert_eq!((j["refused"].clone(), j["drawn"].as_u64()), (Value::Null, Some(seconds)));
    let v = b.fresh_value();
    let j = b.call("draw", &json!({"values": [{"draw": seconds + 1, "seq": seq, "kind": "second", "k": seconds, "amountMsat": "1000", "value": hex::encode(v)}]})).json();
    assert_eq!(j["refused"]["error"], "piece_unknown");
    // with no values at all, a long answer stops when the window's seconds have started and none was drawn for
    let mut quiet = Drawer::open(&rig, 12);
    let (_, cut) = quiet.get("/timed/819200");
    assert!(cut.status == 200 && !cut.complete);
    assert_eq!(quiet.status()["responses"][0]["seconds"], 3);
}

#[test]
fn sessions_are_capped_a_wrong_size_is_refused_and_a_session_outlives_the_gateway() {
    let (rig, _d) = start(&lottery);
    for bad in [json!({}), json!({"version": "ticket/0"}), json!({"version": "lottery/0", "winMsat": 64000})] {
        assert_eq!(Drawer::open_raw(&rig, &bad).status, 400, "{bad}");
    }
    for (size, code) in [("1999", "win_size"), ("4001", "win_size")] {
        let got = Drawer::open_raw(&rig, &json!({"version": "lottery/0", "winMsat": size}));
        assert_eq!((got.status, got.error().as_str()), (402, code));
    }
    let small = Drawer::open_raw(&rig, &json!({"version": "lottery/0", "winMsat": "2600"})).json();
    assert_eq!(small["winMsat"], "2600");
    // a session whose win is not above the page's price cannot draw for it
    let mut tiny = Drawer::open_sized(&rig, 12, Some("2000"));
    let (_, refused) = tiny.get("/api");
    assert_eq!((refused.status, refused.error().as_str()), (402, "amount_not_below_win"));
    // eight sessions in all: two are open, six more fit, the ninth is told
    let mut keep = vec![];
    for n in 0..6 {
        keep.push(Drawer::open(&rig, 20 + n));
    }
    let got = Drawer::open_raw(&rig, &json!({"version": "lottery/0"}));
    assert_eq!((got.status, got.error().as_str()), (402, "too_many_sessions"));
    // a session that never drew is forgotten after a minute, and its place is free again
    rig.advance(61);
    rig.gw.tick();
    let mut b = Drawer::open(&rig, 30);
    assert_eq!(keep[0].get("/api").1.error(), "session_unknown");
    // closing a session forgets it at once
    assert_eq!(b.get("/api").1.status, 200);
    let closed = b.call("close", &json!({}));
    assert_eq!(closed.status, 200);
    assert_eq!(receipt_of(&closed, &b.receipt_key)["servedMsat"], "2500");
    assert_eq!(b.get("/api").1.error(), "session_unknown");
    // a restart of the gateway: the session goes on where it was, its piece still open
    let mut c = Drawer::open(&rig, 31);
    let (seq, got) = c.get("/api");
    assert_eq!(got.status, 200);
    let dir = _d;
    let (node, service, clock) = rig.stop();
    let rig = start_on(dir.path(), node, service, clock, &lottery);
    c.addr = rig.addr.clone();
    b.addr = rig.addr.clone();
    let st = c.status();
    assert_eq!((st["session"]["pending"].as_u64(), st["session"]["servedMsat"].as_str()), (Some(1), Some("2500")));
    let p = c.piece(seq, "/api", Kind::Request, 0, 2500);
    assert_eq!(c.draw(&[p])["refused"], Value::Null);
    // and a closed one stays closed: known to nobody, unsigned
    let (_, got) = b.get("/api");
    assert_eq!((got.status, got.error().as_str()), (402, "session_unknown"));
    assert!(got.header("PAYMENT-RESPONSE").is_none(), "a forgotten session has no totals to sign");
    assert_eq!(rig.gw.stats().held_tickets, 0);
}

#[test]
fn a_route_whose_dearest_piece_is_more_than_a_quarter_of_a_win_is_not_drawn_for_whatever_the_request_says() {
    // the shipped rule: no max_odds_den in the file
    let (rig, _d) = start(&|v| {
        lottery(v);
        v["lottery"].as_object_mut().unwrap().remove("max_odds_den");
    });
    // a page of 2,500 msat on a win of 4,000: tickets only, in the 402 and in the list of what is sold
    let j = http(&rig.addr, "GET", "/api", &[], b"", None).json();
    assert!(j["accepts"].as_array().unwrap().iter().all(|a| a["scheme"] == "ticket"), "{j}");
    // a body whose pieces cost 1,000 msat, a quarter of the win: offered
    let j = http(&rig.addr, "GET", "/files/10", &[], b"", None).json();
    assert_eq!(j["accepts"].as_array().unwrap().last().unwrap()["scheme"], "lottery");
    let s = http(&rig.addr, "GET", "/services", &[], b"", None).json();
    let by = |p: &str| s["routes"].as_array().unwrap().iter().find(|r| r["path"] == p).unwrap()["lottery"].clone();
    assert_eq!((by("/api"), by("/files/")), (json!(false), json!(true)));
    // a buyer that reads no 402 and names the lottery for the page: refused, signed, and the service is not asked
    let mut b = Drawer::open(&rig, 40);
    let (_, got) = b.get("/api");
    assert_eq!((got.status, got.error().as_str()), (402, "amount_not_below_win"));
    assert_eq!(receipt_of(&got, &b.receipt_key)["charged"], "0");
    assert_eq!(rig.hits(), 0);
    // the body is served to the same session
    let (_, got) = b.get(&format!("/files/{PIECE}"));
    assert!(got.status == 200 && got.complete);
    assert_eq!(rig.hits(), 1);
}

#[test]
fn a_buyer_that_voids_every_piece_gets_the_window_and_closing_does_not_give_it_another() {
    // a cap on voids far above the window, so that the window is what stops it; two sessions an address
    let (rig, _d) = start(&|v| {
        lottery(v);
        v["lottery"]["max_voids"] = json!(1000);
        v["lottery"]["sessions_per_address"] = json!(2);
    });
    let void_all = |b: &mut Drawer| -> (usize, Got) {
        let mut served = 0;
        loop {
            let (seq, got) = b.get("/api");
            if got.status != 200 {
                return (served, got);
            }
            served += 1;
            assert!(served <= 20, "a buyer that voids every piece is served without end");
            // "it never arrived": no value, and so no draw
            let j = b.call("draw", &json!({"void": [{"seq": seq, "kind": "request", "k": 0}]})).json();
            assert_eq!((j["session"]["voids"].as_u64(), j["session"]["pending"].as_u64(), j["drawn"].as_u64()), (Some(served as u64), Some(0), Some(0)), "{j}");
        }
    };
    let mut first = Drawer::open(&rig, 41);
    let (served, refused) = void_all(&mut first);
    assert_eq!((served, refused.status, refused.error().as_str()), (3, 402, "too_many_voids"), "the window is 3");
    assert_eq!(receipt_of(&refused, &first.receipt_key)["servedMsat"], "7500");
    // it closes and opens another: served the window again, and that was its address's second place
    assert_eq!(first.call("close", &json!({})).status, 200);
    assert_eq!(first.get("/api").1.error(), "session_unknown", "a closed session is known to nobody");
    let mut second = Drawer::open(&rig, 42);
    assert_eq!(void_all(&mut second).0, 3);
    assert_eq!(second.call("close", &json!({})).status, 200);
    let third = Drawer::open_raw(&rig, &json!({"version": "lottery/0"}));
    assert_eq!((third.status, third.error().as_str()), (402, "too_many_sessions"), "the closed sessions keep their places");
    assert_eq!(rig.hits(), 6, "two sessions, the window each, and nothing more");
    // as long as a session that never drew is kept, and no longer
    rig.advance(61);
    rig.gw.tick();
    let mut later = Drawer::open(&rig, 43);
    // a session that owes nothing gives its place back at once
    let (seq, got) = later.get("/api");
    assert_eq!(got.status, 200);
    let p = later.piece(seq, "/api", Kind::Request, 0, 2500);
    let j = later.draw(&[p]);
    later.pay_all(&rig, &j);
    let _ = later.status();
    assert_eq!(later.call("close", &json!({})).status, 200);
    let _a = Drawer::open(&rig, 44);
    let _b = Drawer::open(&rig, 45);
}

#[test]
fn the_cap_per_address_counts_the_address_a_named_proxy_reports_and_nobody_elses_word() {
    let open = |rig: &Rig, headers: &[(&str, &str)]| {
        let got = http(&rig.addr, "POST", "/x402/lottery/open", headers, json!({"version": "lottery/0"}).to_string().as_bytes(), None);
        (got.status, got.json()["error"].as_str().unwrap_or("").to_string())
    };
    let (ok, full) = ((200, String::new()), (402, "too_many_sessions".to_string()));
    // no proxy named: every request counts under its socket's address, whatever header it carries
    let (plain, _d1) = start(&|v| {
        lottery(v);
        v["lottery"]["sessions_per_address"] = json!(1);
    });
    assert_eq!(open(&plain, &[("X-Real-IP", "198.51.100.1")]), ok);
    assert_eq!(open(&plain, &[("X-Real-IP", "198.51.100.2")]), full, "a header nobody was told to believe");
    // the proxy named (the tests' sockets come from 127.0.0.1): one session for each address it reports
    let (rig, _d2) = start(&|v| {
        lottery(v);
        v["lottery"]["sessions_per_address"] = json!(1);
        v["caps"]["sessions_per_address"] = json!(1);
        v["http"] = json!({"forwarded_address": {"header": "X-Real-IP", "proxies": ["127.0.0.1"]}});
    });
    assert_eq!(open(&rig, &[("X-Real-IP", "198.51.100.1")]), ok);
    assert_eq!(open(&rig, &[("x-real-ip", "198.51.100.1")]), full);
    assert_eq!(open(&rig, &[("X-Real-IP", "198.51.100.2")]), ok);
    // of a list the last entry is the proxy's own; the ones before it are the buyer's to write
    assert_eq!(open(&rig, &[("X-Real-IP", "203.0.113.50, 198.51.100.2")]), full);
    assert_eq!(open(&rig, &[("X-Real-IP", "198.51.100.2, 203.0.113.50")]), ok);
    // no header, two of them, or no address in it: counted with the proxy itself, as one address
    assert_eq!(open(&rig, &[]), ok);
    assert_eq!(open(&rig, &[("X-Real-IP", "198.51.100.3"), ("X-Real-IP", "198.51.100.4")]), full);
    assert_eq!(open(&rig, &[("X-Real-IP", "unknown")]), full);
    // the same address is what a ticket session's place is counted under
    let lock = |headers: &[(&str, &str)], n: u8| {
        let body = json!({"version": "ticket/0", "hashes": [hex::encode(xbt402::ticket::ticket_hash(&[n; 32]))]});
        let got = http(&rig.addr, "POST", "/x402/ticket/lock", headers, body.to_string().as_bytes(), None);
        (got.status, got.json()["error"].as_str().unwrap_or("").to_string())
    };
    assert_eq!(lock(&[("X-Real-IP", "198.51.100.9")], 1), ok);
    assert_eq!(lock(&[("X-Real-IP", "198.51.100.9")], 2), full);
    assert_eq!(lock(&[("X-Real-IP", "198.51.100.10")], 3), ok);
    // and the operator's view is for this machine: a caller the proxy brought from elsewhere does not get it
    assert_eq!(http(&rig.addr, "GET", "/x402/ticket/health", &[("X-Real-IP", "198.51.100.1")], b"", None).status, 404);
    assert_eq!(http(&rig.addr, "GET", "/x402/ticket/health", &[("X-Real-IP", "127.0.0.1")], b"", None).status, 200);
    assert_eq!(http(&plain.addr, "GET", "/x402/ticket/health", &[("X-Real-IP", "198.51.100.1")], b"", None).status, 200);
}

#[test]
fn a_request_with_no_piece_is_not_a_draw_and_a_session_of_draws_is_told_nothing_for_it() {
    // "/status/" priced by the byte, so that the service's 304 comes from a route with no price per request
    let (rig, _d) = start(&|v| {
        lottery(v);
        for r in v["routes"].as_array_mut().unwrap() {
            if r["path"] == "/status/" {
                r["price"] = json!({"byte_msat": 16000, "per_bytes": 1048576});
            }
        }
    });
    let schemes = |method: &str, target: &str| -> Vec<String> {
        let got = http(&rig.addr, method, target, &[], b"", None);
        assert_eq!(got.status, 402);
        unb64json(got.header("PAYMENT-REQUIRED").unwrap()).unwrap()["accepts"].as_array().unwrap().iter().map(|a| a["scheme"].as_str().unwrap().to_string()).collect()
    };
    // the terms of a HEAD: a route priced by the byte only has no piece for it, so tickets; a route
    // with a price per request has one, the request's own
    assert_eq!(schemes("GET", "/files/1000"), ["ticket", "ticket", "lottery"]);
    assert_eq!(schemes("HEAD", "/files/1000"), ["ticket", "ticket"]);
    assert_eq!(schemes("HEAD", "/timed/8192"), ["ticket", "ticket"]);
    assert_eq!(schemes("HEAD", "/whole/10"), ["ticket", "ticket", "lottery"]);
    // a session of draws costs nothing to open. Its HEAD of a file is refused, signed, and the
    // service is not asked: no length, no ETag
    let mut b = Drawer::open(&rig, 50);
    for target in ["/files/1000", "/timed/8192"] {
        let (_, got) = b.send("HEAD", target, b"");
        assert_eq!(got.status, 402, "{target}");
        let j = unb64json(got.header("PAYMENT-REQUIRED").unwrap()).unwrap();
        assert_eq!(j["error"], "amount_not_below_win");
        assert!(j["accepts"].as_array().unwrap().iter().all(|a| a["scheme"] == "ticket"), "{j}");
        assert!(got.header("ETag").is_none() && got.header("Content-Length") != Some("1000"));
        assert_eq!(receipt_of(&got, &b.receipt_key)["charged"], "0");
    }
    assert_eq!(rig.hits(), 0);
    // where the request has a price it is a piece like any other: served, with the length, and owed a value
    let (seq, got) = b.send("HEAD", "/whole/10", b"");
    assert_eq!((got.status, got.header("Content-Length"), got.header("ETag")), (200, Some("10"), Some("\"e\"")));
    assert_eq!(receipt_of(&got, &b.receipt_key)["charged"], "2500");
    assert_eq!(b.status()["session"]["pending"], 1);
    let p = Piece { id: PieceId { seq, kind: Kind::Request, k: 0 }, req: b.digest("HEAD", "/whole/10", b""), amount_msat: 2500 };
    let j = b.draw(&[p]);
    assert_eq!(j["refused"], Value::Null, "{j}");
    b.pay_all(&rig, &j);
    // a GET the service answers without a body, on a route priced by the byte: no piece, nothing
    // owed, and the status alone
    let (_, got) = b.get("/status/304");
    assert_eq!((got.status, got.body.len()), (304, 0));
    assert!(got.header("Content-Type").is_none() && got.header("Content-Length").is_none(), "{:?}", got.headers);
    assert_eq!(receipt_of(&got, &b.receipt_key)["charged"], "0");
    assert_eq!(b.status()["session"]["pending"], 0);
}

/// The lottery's journal of a gateway's state directory, a record a line.
fn journal_of(dir: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(dir.join(xbt_gateway::gateway::LOTTERY_JOURNAL)).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

/// Whether the journal holds draw `draw` of `session` taken: as a record of its own, or inside the
/// session's counters after a rewrite.
fn holds_draw(journal: &[Value], session: &str, draw: u64) -> bool {
    journal.iter().any(|r| r["session"] == session && r["t"] == "take" && r["draw"].as_u64() == Some(draw))
        || journal.iter().any(|r| r["t"] == "session" && r["id"] == session && r["drawn"].as_u64() >= Some(draw))
}

/// A status call that adopts the seq the gateway expects, as a buyer does after the gateway lost a
/// few of its last counters.
fn status_adopting(b: &mut Drawer) -> Got {
    for _ in 0..2 {
        let got = b.call("status", &json!({}));
        if got.status == 402 && got.error() == "bad_seq" {
            b.seq = got.json()["nextSeq"].as_u64().unwrap();
            continue;
        }
        return got;
    }
    panic!("the gateway kept refusing the seq it asked for");
}

/// Stop a gateway without touching its node: the node's state is what a kill leaves.
fn halt(rig: Rig) -> (std::sync::Arc<xbt_gateway::standin::StandIn>, (xbt_svc::http::Running, std::sync::Arc<Service>), std::sync::Arc<std::sync::atomic::AtomicU64>) {
    rig.gw.stop();
    rig.running.stopper().stop();
    for t in rig.running.threads {
        let _ = t.join();
    }
    (rig.node, (rig.service_running, rig.service), rig.clock)
}

#[test]
fn a_session_and_its_unpaid_wins_outlive_a_restart_and_a_kill_at_any_write_of_the_journal() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let rig = start_on(&state, std::sync::Arc::new(xbt_gateway::standin::StandIn::new(100)), start_service(), std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1_000_000)), &lottery);
    let mut b = Drawer::open(&rig, 60);
    // pages, each drawn for. Every reveal the buyer is sent is for draws the journal holds already:
    // they were written, and synced, before the answer left
    let mut wins = vec![];
    while wins.len() < 2 {
        let (seq, got) = b.get("/api");
        assert_eq!(got.status, 200, "{}", String::from_utf8_lossy(&got.body));
        let p = b.piece(seq, "/api", Kind::Request, 0, 2500);
        let j = b.draw(&[p]);
        let drawn = j["drawn"].as_u64().unwrap();
        assert!(holds_draw(&journal_of(&state), &b.session, drawn), "draw {drawn} was revealed before the journal held it");
        if let Some(&w) = b.owed.last() {
            // the win's invoice is the journal's, by its hash, as soon as the buyer has it
            let h = b.invoice_hash(&j, w);
            assert!(journal_of(&state).iter().any(|r| r["t"] == "invoice" && r["hash"] == hex::encode(h)));
            wins.push((w, h));
            b.owed.clear();
        }
    }
    // the first win is paid; the second's invoice lapses, and the node makes its next one but the
    // answer is lost: that invoice is the journal's by its hash alone
    let ((_, paid), (second, lapsed)) = (wins[0], wins[1]);
    assert!(rig.node.pay(&paid));
    assert_eq!(b.status()["wins"].as_array().unwrap().len(), 1);
    rig.node.expire_unpaid(&lapsed);
    rig.node.lose_next_invoice_answer();
    let st = b.status();
    assert_eq!(st["wins"], json!([{"draw": second, "invoice": null}]), "an invoice whose answer was lost is not listed");
    let asked: Vec<String> = journal_of(&state).iter().filter(|r| r["t"] == "invoice" && r["draw"].as_u64() == Some(second)).map(|r| r["hash"].as_str().unwrap().to_string()).collect();
    let unknown = hex32(asked.last().unwrap()).unwrap();
    assert_eq!((asked.len(), rig.node.state_of(&unknown)), (2, Some(InvoiceState::Open)), "the node made it; the gateway does not know its text");
    // and one piece is served that has no value yet
    let (open_seq, got) = b.get("/api");
    assert_eq!(got.status, 200);
    let full = b.status()["session"].clone();
    let (node, mut service, clock) = halt(rig);
    // the journal as the kill would find it: before a restart rewrites it
    let whole: Vec<String> = std::fs::read_to_string(state.join(xbt_gateway::gateway::LOTTERY_JOURNAL)).unwrap().lines().map(str::to_string).collect();

    // a restart on the whole journal: the session, its open piece and its unpaid win, which gets an
    // invoice anew once the one the node made unseen is cancelled there
    let rig = start_on(&state, node.clone(), service, clock.clone(), &lottery);
    b.addr = rig.addr.clone();
    let st = status_adopting(&mut b).json();
    for k in ["drawn", "pending", "servedMsat", "wonMsat", "paidMsat", "voids"] {
        assert_eq!(st["session"][k], full[k], "{k}");
    }
    let fresh = Drawer::hash_in(&st, second);
    assert!(fresh != unknown && fresh != lapsed);
    assert_eq!((node.state_of(&unknown), node.state_of(&fresh)), (Some(InvoiceState::Canceled), Some(InvoiceState::Open)));
    // the open piece is drawn for where it was, and the win is paid on its new invoice
    let p = b.piece(open_seq, "/api", Kind::Request, 0, 2500);
    assert_eq!(b.draw(&[p])["refused"], Value::Null);
    assert!(node.pay(&fresh));
    let st = b.status();
    assert!(st["wins"].as_array().unwrap().iter().all(|w| w["draw"] != second), "{st}");
    let (node, s2, clock) = halt(rig);
    service = s2;

    // a kill at every write: the journal cut after each of its first `lines` records, a gateway
    // started on what is left. Each starts, takes back no draw it held, answers the last draw it
    // holds as it did, and lists no win the node shows paid
    let all: Vec<Value> = whole.iter().map(|l| serde_json::from_str(l).unwrap()).collect();
    let (mut restored, mut repeated, mut listed) = (0, 0, 0);
    for n in 0..=whole.len() {
        let cut = dir.path().join(format!("cut-{n}"));
        std::fs::create_dir_all(&cut).unwrap();
        let mut text: String = whole[..n].iter().map(|l| format!("{l}\n")).collect();
        // and a write the kill tore in half
        text.push_str(&whole[n.min(whole.len() - 1)][..10]);
        std::fs::write(cut.join(xbt_gateway::gateway::LOTTERY_JOURNAL), text).unwrap();
        let rig = start_on(&cut, node.clone(), service, clock.clone(), &lottery);
        let mut c = Drawer { addr: rig.addr.clone(), seq: 0, outcomes: vec![], owed: vec![], ..Drawer::open(&rig, 61) };
        c.session = b.session.clone();
        c.key = b.key;
        let opened = all[..n].iter().any(|r| r["t"] == "session" && r["id"] == b.session.as_str());
        let got = status_adopting(&mut c);
        if !opened {
            assert_eq!((got.status, got.error().as_str()), (402, "session_unknown"), "{n}");
        } else {
            assert_eq!(got.status, 200, "{n}: {}", String::from_utf8_lossy(&got.body));
            let st = got.json();
            let drawn = st["session"]["drawn"].as_u64().unwrap();
            let held = (1..=drawn).all(|d| holds_draw(&all[..n], &b.session, d));
            assert!(held, "{n}: drawn {drawn} with draws the cut journal does not hold");
            // the last draw it holds is answered as it was the first time
            if let Some(o) = b.outcomes.iter().find(|o| o.draw == drawn) {
                let p = &o.piece;
                let v = b.draws.open().count();
                assert_eq!(v, 0);
                let sent = all[..n].iter().find(|r| r["t"] == "take" && r["draw"].as_u64() == Some(drawn)).map(|r| r["value"].as_str().unwrap().to_string());
                if let Some(value) = sent {
                    let j = c.call("draw", &json!({"values": [{"draw": drawn, "seq": p.id.seq, "kind": p.id.kind.name(), "k": p.id.k, "amountMsat": p.amount_msat.to_string(), "value": value}]})).json();
                    assert_eq!((j["refused"].clone(), j["drawn"].as_u64()), (Value::Null, Some(drawn)), "{n}: {j}");
                    repeated += 1;
                }
            }
            // every win it lists has an invoice the node holds open, and the paid ones are not listed
            for w in st["wins"].as_array().unwrap() {
                let h = Drawer::hash_in(&st, w["draw"].as_u64().unwrap());
                assert_eq!(node.state_of(&h), Some(InvoiceState::Open), "{n}: {st}");
                assert!(h != paid && h != fresh, "{n}: a win the node shows paid is listed unpaid");
                listed += 1;
            }
            restored += 1;
        }
        let (n2, s2, c2) = halt(rig);
        drop((n2, c2));
        service = s2;
    }
    assert!(restored + 1 >= whole.len() && repeated * 4 >= restored * 3 && listed > 0, "{restored} restored, {repeated} draws answered again, {listed} wins listed, of {} cuts", whole.len() + 1);
}

#[test]
fn a_draw_that_cannot_be_written_down_is_not_revealed_and_ends_its_session() {
    let (rig, _d) = start(&lottery);
    let mut b = Drawer::open(&rig, 62);
    let (seq, got) = b.get("/api");
    assert_eq!(got.status, 200);
    rig.gw.break_lottery_journal();
    let p = b.piece(seq, "/api", Kind::Request, 0, 2500);
    let v = b.fresh_value();
    b.draws.issue(p, v, 64).unwrap();
    let values: Vec<Value> = b.draws.open().map(|(d, p, v)| json!({"draw": d, "seq": p.id.seq, "kind": p.id.kind.name(), "k": p.id.k, "amountMsat": p.amount_msat.to_string(), "value": hex::encode(v)})).collect();
    let got = b.call("draw", &json!({"values": values}));
    assert_eq!((got.status, got.error().as_str()), (500, "journal"));
    assert!(got.json()["reveal"].is_null() && got.header("PAYMENT-RESPONSE").is_none(), "no reveal, and no totals of a session that is over");
    let (_, got) = b.get("/api");
    assert_eq!(got.error(), "session_unknown");
}

#[test]
fn a_win_whose_payment_failed_has_its_next_invoice_by_the_time_the_grace_ends() {
    // a grace of 20 s, and no invoice_secs in the file: a win's invoice lives 20 s
    let (rig, _d) = start(&|v| {
        lottery(v);
        v["lottery"]["grace_seconds"] = json!(20);
    });
    let mut b = Drawer::open(&rig, 63);
    let j = loop {
        let (seq, got) = b.get("/api");
        assert_eq!(got.status, 200);
        let p = b.piece(seq, "/api", Kind::Request, 0, 2500);
        let j = b.draw(&[p]);
        if !b.owed.is_empty() {
            break j;
        }
    };
    let first = b.invoice_hash(&j, b.owed[0]);
    assert_eq!(rig.node.expiry_of(&first), Some(20), "the invoice lives as long as the grace, not longer");
    // the buyer's payment fails, and the buyer does not pay that invoice again. When the grace ends
    // the invoice has lapsed with it (the node cancels it), and the request the gateway refuses
    // carries the next one, which the buyer pays; then it is served
    rig.advance(21);
    rig.node.expire_unpaid(&first);
    let (_, got) = b.get("/api");
    assert_eq!((got.status, got.error().as_str()), (402, "win_unpaid"));
    let refused = unb64json(got.header("PAYMENT-REQUIRED").unwrap()).unwrap();
    let next = Drawer::hash_in(&refused["session"], b.owed[0]);
    assert!(next != first && rig.node.state_of(&next) == Some(InvoiceState::Open));
    assert!(rig.node.pay(&next));
    assert_eq!(b.get("/api").1.status, 200);
}
