//! Visits (a seller's own web page used inside the app, docs/SELLER-APPS.md) against a stand-in
//! signer that keeps a seller's session: each request costs the session's credit, and a call that
//! may spend a ticket's worth buys one when the credit is short. A visit spends at most its limit
//! however many requests run at once; a page's headers and body reach the signer, and the seller's
//! headers come back; a stopped visit and a request to upgrade are refused in the connector's own
//! words.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

const TICKET: i64 = 600;
const COST: i64 = 100;

#[derive(Default)]
struct Session {
    credit: i64,
    charged: i64,
    calls: Vec<Value>,
    /// The socket of an answer still being written went away ([`signer_at`]'s `/endless/`).
    reader_gone: bool,
}

/// The stand-in signer: one thread per connection, so a page's requests run at once.
fn signer(dir: &Path) -> (PathBuf, Arc<Mutex<Session>>) {
    signer_at(dir, TICKET)
}

/// The stand-in signer with tickets of `ticket` sat; a refusal names what one books, as the
/// signer's does. A request for `/dear/…` needs a limit of 2,500 sat; one for `/nohead/…` is
/// charged a ticket and its answer never starts (the stream is closed before a head).
fn signer_at(dir: &Path, ticket: i64) -> (PathBuf, Arc<Mutex<Session>>) {
    let sock = dir.join("signer.sock");
    let l = UnixListener::bind(&sock).unwrap();
    let stream_dir = dir.to_path_buf();
    let session = Arc::new(Mutex::new(Session::default()));
    let s2 = session.clone();
    std::thread::spawn(move || {
        for conn in l.incoming() {
            let mut conn = conn.unwrap();
            let (stream_dir, session) = (stream_dir.clone(), s2.clone());
            std::thread::spawn(move || {
                let mut line = String::new();
                BufReader::new(conn.try_clone().unwrap()).read_line(&mut line).unwrap();
                let req: Value = serde_json::from_str(&line).unwrap();
                let p = req["params"].clone();
                let max = p["max_sats"].as_i64().unwrap();
                let url = p["url"].as_str().unwrap_or("").to_string();
                // as the signer does: a seller whose terms (COST a request) are above the listing's price the buyer was shown
                // is paid nothing
                if p["price_ceiling"]["request_msat"].as_i64().is_some_and(|c| c < COST * 1000) {
                    session.lock().unwrap().calls.push(p.clone());
                    let _ = writeln!(conn, "{}", json!({"id": 1, "result": {"verdict": "deny", "rule": "price_ceiling",
                                                                            "reason": "the seller's terms are above the price the buyer was shown", "charged_sats": 0}}));
                    return;
                }
                if url.contains("/dear/") && max < 2_500 {
                    session.lock().unwrap().calls.push(p.clone());
                    let _ = writeln!(conn, "{}", json!({"id": 1, "result": {"verdict": "deny", "rule": "max_sats", "reason": "a dear answer",
                                                                            "charged_sats": 0, "ticket_booking_sats": ticket}}));
                    return;
                }
                if url.contains("/nohead/") {
                    // never more than the call may spend, as the signer
                    let ticket = ticket.min(max);
                    session.lock().unwrap().charged += ticket;
                    drop(UnixStream::connect(stream_dir.join(p["stream_to"].as_str().unwrap())));
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    let _ = writeln!(conn, "{}", json!({"id": 1, "result": {"verdict": "allow", "status": 502, "charged_sats": ticket, "complete": false}}));
                    return;
                }
                // the seller's routes, read unpaid as a visit opens (not counted among the page's calls): its web client is free
                if url.ends_with("/services") {
                    let doc = json!({"routes": [{"path": "/app/web/", "free": true, "methods": ["GET", "HEAD"]},
                                                {"path": "/", "free": false, "methods": ["GET", "POST"]}]}).to_string();
                    let mut out = UnixStream::connect(stream_dir.join(p["stream_to"].as_str().unwrap())).unwrap();
                    let _ = writeln!(out, "{}", json!({"status": 200, "content_length": doc.len(), "content_type": "application/json"}));
                    let _ = out.write_all(doc.as_bytes());
                    drop(out);
                    let _ = writeln!(conn, "{}", json!({"id": 1, "result": {"verdict": "allow", "rule": "free", "status": 200, "charged_sats": 0, "complete": true}}));
                    return;
                }
                // a path that was free and is sold now: asked for unpaid, the seller's 402 is refused with nothing to spend
                if url.contains("/app/web/gone/") && max == 0 {
                    session.lock().unwrap().calls.push(p.clone());
                    let _ = writeln!(conn, "{}", json!({"id": 1, "result": {"verdict": "deny", "rule": "max_sats", "reason": "the seller asks to be paid",
                                                                            "charged_sats": 0}}));
                    return;
                }
                // a seller that has not answered yet: the call holds a handler slot of the connector, waiting
                if url.contains("/hang/") {
                    std::thread::sleep(std::time::Duration::from_secs(120));
                    return;
                }
                // a free path asked for as it is (no terms of another route) is served free; the session's credit, or a
                // ticket where the call may spend one, pays any other
                let free = url.contains("/app/web/") && !url.contains("/app/web/gone/") && p["known_terms"] != true;
                let charged = if free {
                    session.lock().unwrap().calls.push(p.clone());
                    0
                } else {
                    let mut s = session.lock().unwrap();
                    s.calls.push(p.clone());
                    let mut charged = 0;
                    if s.credit < COST {
                        if max < ticket || p["credit_only"] == true {
                            drop(s);
                            let _ = writeln!(conn, "{}", json!({"id": 1, "result": {"verdict": "deny", "rule": "max_sats", "reason": "a ticket does not fit",
                                                                                    "charged_sats": 0, "ticket_booking_sats": ticket}}));
                            return;
                        }
                        s.credit += ticket;
                        s.charged += ticket;
                        charged = ticket;
                    }
                    s.credit -= COST;
                    charged
                };
                std::thread::sleep(std::time::Duration::from_millis(5));
                let mut out = UnixStream::connect(stream_dir.join(p["stream_to"].as_str().unwrap())).unwrap();
                // a film that goes on until its reader goes away, which is what stops the signer paying
                if url.contains("/endless/") {
                    let _ = writeln!(out, "{}", json!({"status": 200, "content_type": "video/mp4", "headers": [["Content-Type", "video/mp4"]]}));
                    let chunk = vec![7u8; 16 << 10];
                    while out.write_all(&chunk).is_ok() {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                    session.lock().unwrap().reader_gone = true;
                    let _ = writeln!(conn, "{}", json!({"id": 1, "result": {"verdict": "allow", "status": 200, "charged_sats": charged, "complete": false, "ended": "stopped by the buyer"}}));
                    return;
                }
                // a film's range that the wallet ends half-way (its limit, a seller gone quiet): `/cut/` with the part's length
                // stated, `/cutchunked/` with none. Half of it is written, and the call says it was not whole
                if url.contains("/cut/") || url.contains("/cutchunked/") {
                    let part: Vec<u8> = (0..256 * 1024u32).map(|i| (i % 251) as u8).collect();
                    let mut head = json!({"status": 206, "content_type": "video/mp4", "content_range": format!("bytes 0-{}/{}", part.len() - 1, 4 * part.len()),
                                          "headers": [["Content-Type", "video/mp4"], ["Accept-Ranges", "bytes"]]});
                    if url.contains("/cut/") {
                        head["content_length"] = part.len().into();
                    }
                    let _ = writeln!(out, "{head}");
                    let _ = out.write_all(&part[..part.len() / 2]);
                    drop(out);
                    let _ = writeln!(conn, "{}", json!({"id": 1, "result": {"verdict": "allow", "status": 206, "charged_sats": charged, "complete": false,
                                                                            "ended": "max_answer_s: the answer has been open for 50 s"}}));
                    return;
                }
                use base64::Engine as _;
                let body = p["body_b64"].as_str().map(|b| base64::engine::general_purpose::STANDARD.decode(b).unwrap()).unwrap_or_default();
                let echo = json!({"url": p["url"], "method": p["method"], "headers": p["headers"], "body": String::from_utf8_lossy(&body)}).to_string();
                let head = json!({"status": 200, "content_length": echo.len(), "content_type": "application/json",
                                  "headers": [["Content-Type", "application/json"], ["Set-Cookie", "jf=1; Path=/"], ["X-Seller", "yes"]]});
                let _ = writeln!(out, "{head}");
                let _ = out.write_all(echo.as_bytes());
                drop(out);
                let _ = writeln!(conn, "{}", json!({"id": 1, "result": {"verdict": "allow", "status": 200, "charged_sats": charged, "complete": true}}));
            });
        }
    });
    (sock, session)
}

fn start(sock: PathBuf, dir: &Path) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let cfg = lightning_stream::Config { signer: sock, stream_dir: dir.to_path_buf(), task: "app".into(), max_sats: 2_000 };
    let run = lightning_stream::serve(cfg, l).unwrap();
    let addr = run.addr.to_string();
    std::mem::forget(run);
    addr
}

/// One request: (status, head, body).
fn ask(addr: &str, method: &str, target: &str, extra: &str, body: &[u8]) -> (u16, String, Vec<u8>) {
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    write!(s, "{method} {target} HTTP/1.1\r\nHost: x\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
    s.write_all(body).unwrap();
    let mut all = vec![];
    s.read_to_end(&mut all).unwrap();
    let split = all.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&all[..split]).to_string();
    (head[9..12].parse().unwrap(), head, all[split + 4..].to_vec())
}

fn open(addr: &str, limit: i64) -> String {
    let body = json!({"base": "https://seller.example/app/", "limit_sats": limit}).to_string();
    let (status, _, b) = ask(addr, "POST", "/visits", "Content-Type: application/json\r\n", body.as_bytes());
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&b));
    serde_json::from_slice::<Value>(&b).unwrap()["visit"].as_str().unwrap().to_string()
}

/// A visit opened from a listing carries the listing's prices as the ceiling of every call it
/// makes: within them the seller is paid; a seller whose terms ask more is refused and paid nothing.
///
/// FAILS before: a visit passed no ceiling, so a seller could ask more than it listed, up to each
/// call's share.
#[test]
fn a_visit_pays_no_more_than_the_listing_it_was_chosen_from() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, session) = signer(dir.path());
    let addr = start(sock, dir.path());
    let open_at = |ceiling: Value| {
        let body = json!({"base": "https://seller.example/app/", "limit_sats": 5_000, "price_ceiling": ceiling}).to_string();
        let (status, _, b) = ask(&addr, "POST", "/visits", "Content-Type: application/json\r\n", body.as_bytes());
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&b));
        serde_json::from_slice::<Value>(&b).unwrap()["visit"].as_str().unwrap().to_string()
    };
    let honest = json!({"request_msat": COST * 1000, "gib_msat": 0, "second_msat": 0, "input_per_1k_msat": 0, "output_per_1k_msat": 0});
    let visit = open_at(honest.clone());
    let (st, head, _) = ask(&addr, "GET", &format!("/v/{visit}/page"), "", b"");
    assert_eq!(st, 200, "{head}");
    assert_eq!(session.lock().unwrap().calls.last().unwrap()["price_ceiling"], honest);
    // listed for less than it asks: refused, and nothing charged on this visit
    let visit = open_at(json!({"request_msat": COST * 1000 - 1, "gib_msat": 0, "second_msat": 0, "input_per_1k_msat": 0, "output_per_1k_msat": 0}));
    let (st, head, _) = ask(&addr, "GET", &format!("/v/{visit}/page"), "", b"");
    assert_ne!(st, 200, "{head}");
    let report: Value = serde_json::from_slice(&ask(&addr, "GET", &format!("/visits/{visit}"), "", b"").2).unwrap();
    assert_eq!(report["spent_sats"], 0, "{report}");
}

#[test]
fn a_visit_spends_at_most_its_limit_however_many_requests_run_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, session) = signer(dir.path());
    let addr = start(sock, dir.path());
    // two tickets fit in 1,500 sat, a third does not: twelve requests are paid, the rest refused
    let visit = open(&addr, 1_500);
    let results: Vec<(u16, String)> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..30).map(|i| { let (addr, visit) = (addr.clone(), visit.clone()); s.spawn(move || {
            let (st, head, _) = ask(&addr, "GET", &format!("/v/{visit}/asset/{i}.js"), "", b"");
            (st, head)
        }) }).collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let ok = results.iter().filter(|(s, _)| *s == 200).count();
    let refused: Vec<&(u16, String)> = results.iter().filter(|(s, _)| *s != 200).collect();
    assert_eq!(ok, 12, "{results:?}");
    assert!(refused.iter().all(|(s, h)| *s == 402 && h.to_ascii_lowercase().contains("x-ls-refusal: 1")), "{refused:?}");
    let charged = session.lock().unwrap().charged;
    assert_eq!(charged, 2 * TICKET);
    let (_, _, b) = ask(&addr, "GET", &format!("/visits/{visit}"), "", b"");
    let v: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!((v["spent_sats"].as_i64(), v["limit_sats"].as_i64()), (Some(charged), Some(1_500)), "{v}");
    assert!(v["ended"].as_str().unwrap().contains("limit"), "{v}");
    // each call held a share of the limit as its cap (all that was left, for one that ran alone), and the shares
    // running at once never added up to more than it
    let calls = session.lock().unwrap().calls.clone();
    assert!(calls.iter().all(|c| (1..=1_500).contains(&c["max_sats"].as_i64().unwrap())), "{calls:?}");
    // an eighth of the limit each: many ran on their own share, not one at a time
    assert!(calls.iter().filter(|c| c["max_sats"] == 187).count() >= 12, "{calls:?}");
    assert!(calls.iter().all(|c| c.get("credit_only").is_none()), "{calls:?}");
}

#[test]
fn a_pages_headers_and_body_reach_the_signer_and_the_sellers_headers_come_back() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, session) = signer(dir.path());
    let addr = start(sock, dir.path());
    let visit = open(&addr, 5_000);
    let (st, head, body) = ask(&addr, "POST", &format!("/v/{visit}/Users/AuthenticateByName?x=1"),
                               "Cookie: jf=1\r\nAuthorization: MediaBrowser Token=t\r\nX-Not-Passed: no\r\nContent-Type: application/json\r\n", b"{\"Username\":\"guest\"}");
    assert_eq!(st, 200, "{head}");
    let echo: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(echo["url"], "https://seller.example/app/Users/AuthenticateByName?x=1");
    assert_eq!((echo["method"].as_str(), echo["body"].as_str()), (Some("POST"), Some("{\"Username\":\"guest\"}")));
    let names: Vec<String> = echo["headers"].as_array().unwrap().iter().map(|h| h[0].as_str().unwrap().to_ascii_lowercase()).collect();
    assert!(names.contains(&"cookie".into()) && names.contains(&"authorization".into()) && !names.contains(&"x-not-passed".into()), "{names:?}");
    let h = head.to_ascii_lowercase();
    assert!(h.contains("set-cookie: jf=1") && h.contains("x-seller: yes") && !h.contains("x-ls-refusal"), "{head}");
    // a live connection is asked of the signer as one (`upgrade`), with the WebSocket's own headers and
    // a share of what is left of the limit; one the seller does not open is refused, and costs nothing
    let spent = |addr: &str| serde_json::from_slice::<Value>(&ask(addr, "GET", &format!("/visits/{visit}"), "", b"").2).unwrap()["spent_sats"].clone();
    let before = spent(&addr);
    let (st, head, _) = ask(&addr, "GET", &format!("/v/{visit}/socket"), "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: k1\r\n\
                                                                       Sec-WebSocket-Version: 13\r\n", b"");
    assert_eq!(st, 502, "{head}");
    let last = session.lock().unwrap().calls.last().cloned().unwrap();
    assert_eq!((last["upgrade"].as_bool(), last["max_sats"].as_i64().is_some_and(|m| (1..=1_000).contains(&m))), (Some(true), true), "{last}");
    assert!(last["headers"].as_array().unwrap().iter().any(|h| h[0].as_str().unwrap().eq_ignore_ascii_case("sec-websocket-key")), "{last}");
    assert_eq!(spent(&addr), before, "the share held for it is given back");
}

#[test]
fn a_stopped_or_unknown_visit_pays_nothing_more() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, session) = signer(dir.path());
    let addr = start(sock, dir.path());
    let visit = open(&addr, 5_000);
    assert_eq!(ask(&addr, "GET", &format!("/v/{visit}/"), "", b"").0, 200);
    let (st, _, b) = ask(&addr, "POST", &format!("/visits/{visit}/stop"), "", b"");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
    let calls = session.lock().unwrap().calls.len();
    let (st, head, b) = ask(&addr, "GET", &format!("/v/{visit}/more"), "", b"");
    assert_eq!(st, 402, "{head}");
    assert!(String::from_utf8_lossy(&b).contains("Stopped"));
    assert_eq!(ask(&addr, "GET", "/v/ffff/more", "", b"").0, 404);
    assert_eq!(session.lock().unwrap().calls.len(), calls, "nothing reached the signer");
    // a visit names a seller URL ending in /, and a limit
    for body in [json!({"base": "https://seller.example/app", "limit_sats": 10}), json!({"base": "ftp://x/", "limit_sats": 10}), json!({"base": "https://s/", "limit_sats": 0})] {
        assert_eq!(ask(&addr, "POST", "/visits", "", body.to_string().as_bytes()).0, 400, "{body}");
    }
}

/// A player's open range is asked for in parts of 4 MiB, each request holding a share of the
/// visit's limit as its cap: the shares of the requests running at once never add up to more than
/// the limit, and each part may be paid within its own share, before its head or as it arrives.
#[test]
fn a_range_goes_in_parts_each_within_a_share_of_the_limit() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, session) = signer(dir.path());
    let addr = start(sock, dir.path());
    let visit = open(&addr, 2_500);
    let results: Vec<u16> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..6).map(|i| { let (addr, visit) = (addr.clone(), visit.clone()); s.spawn(move || {
            ask(&addr, "GET", &format!("/v/{visit}/video/{i}.mp4"), &format!("Range: bytes={}-\r\n", i * 1000), b"").0
        }) }).collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert!(results.iter().all(|s| *s == 200), "{results:?}");
    let calls = session.lock().unwrap().calls.clone();
    for (i, c) in calls.iter().enumerate() {
        let r = c["range"].as_str().unwrap();
        let start: u64 = r.trim_start_matches("bytes=").split('-').next().unwrap().parse().unwrap();
        assert_eq!(r, format!("bytes={start}-{}", start + (4 << 20) - 1), "call {i}: {c}");
        // a share, or, for a request whose share was too small for a ticket, all that was left once it ran alone
        assert!((1..=2_500).contains(&c["max_sats"].as_i64().unwrap()), "call {i}: {c}");
    }
    let charged = session.lock().unwrap().charged;
    assert!(charged <= 2_500, "{charged}");
    let (_, _, b) = ask(&addr, "GET", &format!("/visits/{visit}"), "", b"");
    let v: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["spent_sats"].as_i64(), Some(charged), "only what was bought stays spent once every request ended: {v}");
}

/// A ticket dearer than a request's share is bought by a request asked again with room for one
/// beside its share; the requests after it hold a share of their own and run on the credit it bought.
#[test]
fn a_ticket_dearer_than_a_share_is_bought_by_a_request_asked_again_with_room_for_one() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, session) = signer_at(dir.path(), 1_002);
    let addr = start(sock, dir.path());
    // a ticket of 1,000 sat and its fee: more than a request's share of its own, well within the limit
    let visit = open(&addr, 30_000);
    let results: Vec<u16> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..40).map(|i| { let (addr, visit) = (addr.clone(), visit.clone()); s.spawn(move || {
            ask(&addr, "GET", &format!("/v/{visit}/asset/{i}.js"), "", b"").0
        }) }).collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert!(results.iter().all(|s| *s == 200), "{results:?}");
    let charged = session.lock().unwrap().charged;
    assert!((1_002..=30_000).contains(&charged), "{charged}");
    // the tickets were bought by requests asked again with room for one; a request on the credit holds its own share
    assert!(session.lock().unwrap().calls.iter().any(|c| c["max_sats"].as_i64().unwrap() >= 1_002));
    let (_, _, b) = ask(&addr, "GET", &format!("/v/{visit}/next.js"), "", b"");
    assert!(!b.is_empty());
    let last = session.lock().unwrap().calls.last().cloned().unwrap();
    assert!((1..=1_000 + 1_002).contains(&last["max_sats"].as_i64().unwrap()), "{last}");
    let (_, _, b) = ask(&addr, "GET", &format!("/visits/{visit}"), "", b"");
    let v: Value = serde_json::from_slice(&b).unwrap();
    assert!(v["ended"].is_null(), "{v}");
}

/// A call whose answer never starts (no head came) may still have been charged: its share stays
/// spent until the signer says what it charged, and the visit's limit holds.
///
/// FAILS before: the share went back as charged nothing, and the visit spent past its limit.
#[test]
fn a_call_that_ends_before_its_head_keeps_its_share_until_the_signer_says_what_it_charged() {
    let dir = tempfile::tempdir().unwrap();
    // tickets of 80 sat, within a request's share of a 1,000 sat visit (125)
    let (sock, session) = signer_at(dir.path(), 80);
    let addr = start(sock, dir.path());
    let visit = open(&addr, 1_000);
    let spent = |addr: &str| serde_json::from_slice::<Value>(&ask(addr, "GET", &format!("/visits/{visit}"), "", b"").2).unwrap()["spent_sats"].as_i64();
    let (st, _, _) = ask(&addr, "GET", &format!("/v/{visit}/nohead/a.js"), "", b"");
    assert_eq!(st, 502);
    // until the signer's answer comes after the refusal, all of the share stays spent; what it charged is counted then
    assert_eq!(spent(&addr), Some(125));
    let t = std::time::Instant::now();
    while spent(&addr) != Some(80) {
        assert!(t.elapsed() < std::time::Duration::from_secs(5), "{:?}", spent(&addr));
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // the visit's limit holds: requests are paid until what is left buys no ticket, then refused
    let mut refused = false;
    for i in 0..40 {
        let (st, _, _) = ask(&addr, "GET", &format!("/v/{visit}/b{i}.js"), "", b"");
        if st == 402 {
            refused = true;
            break;
        }
        assert_eq!(st, 200);
    }
    assert!(refused);
    let charged = session.lock().unwrap().charged;
    assert!(charged <= 1_000, "{charged}");
    assert_eq!(spent(&addr), Some(charged));
}

/// A request that needs more than a share goes alone once the requests running have ended: new
/// ones wait behind it, so it is not starved by a page that keeps asking.
///
/// FAILS before: it waited for a moment with nothing running, which a busy page never gives, and
/// was refused after two minutes.
#[test]
fn a_request_that_must_run_alone_gets_its_turn_on_a_busy_page() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, session) = signer(dir.path());
    let addr = start(sock, dir.path());
    let visit = open(&addr, 100_000);
    let stop = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|s| {
        // a page that keeps eight requests going
        for w in 0..8 {
            let (addr, visit, stop) = (addr.clone(), visit.clone(), &stop);
            s.spawn(move || {
                let mut i = 0;
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    let (st, _, _) = ask(&addr, "GET", &format!("/v/{visit}/busy/{w}-{i}.js"), "", b"");
                    assert_eq!(st, 200);
                    i += 1;
                }
            });
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
        let t = std::time::Instant::now();
        let (st, _, b) = ask(&addr, "GET", &format!("/v/{visit}/dear/film.js"), "", b"");
        let took = t.elapsed();
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
        assert!(took < std::time::Duration::from_secs(10), "{took:?}");
    });
    let calls = session.lock().unwrap().calls.clone();
    assert!(calls.iter().any(|c| c["url"].as_str().unwrap().contains("/dear/") && c["max_sats"].as_i64().unwrap() >= 2_500), "{calls:?}");
}

/// One read of a whole answer, as it came: the head (lower-cased) and every byte after it.
fn raw(addr: &str, target: &str, extra: &str) -> (String, Vec<u8>) {
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(std::time::Duration::from_secs(60))).unwrap();
    write!(s, "GET {target} HTTP/1.1\r\nHost: x\r\n{extra}Connection: close\r\n\r\n").unwrap();
    let mut all = vec![];
    let _ = s.read_to_end(&mut all);
    let split = all.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    (String::from_utf8_lossy(&all[..split]).to_ascii_lowercase(), all[split + 4..].to_vec())
}

/// A range of a film that the wallet ended half-way is never handed to the page as a whole one,
/// which a player takes for the end of the file and stops the film there: with the part's length
/// stated the body falls short of it; with none, the chunked body has no last chunk.
///
/// FAILS before for the chunked part: it ended with its last chunk, as if the range were whole.
#[test]
fn a_range_the_wallet_ended_half_way_reaches_the_page_cut_short_never_whole() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, _session) = signer(dir.path());
    let addr = start(sock, dir.path());
    let visit = open(&addr, 5_000);
    let (head, body) = raw(&addr, &format!("/v/{visit}/cut/film.mp4"), "Range: bytes=0-\r\n");
    assert!(head.starts_with("http/1.1 206") && head.contains("content-length: 262144"), "{head}");
    assert!(body.len() < 262_144, "a range cut half-way came whole: {} bytes", body.len());
    let (head, body) = raw(&addr, &format!("/v/{visit}/cutchunked/film.mp4"), "Range: bytes=0-\r\n");
    assert!(head.starts_with("http/1.1 206") && head.contains("transfer-encoding: chunked"), "{head}");
    assert!(!body.ends_with(b"0\r\n\r\n"), "a range cut half-way ended with its last chunk, as if whole");
}

/// Stopping a visit ends the answers open in it, even one its page is still reading: the signer's
/// socket closes, which is what stops it paying, so that "nothing more is paid" holds at once.
#[test]
fn stopping_a_visit_shuts_its_open_answers() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, session) = signer(dir.path());
    let addr = start(sock, dir.path());
    let visit = open(&addr, 5_000);
    let reading = { let (addr, visit) = (addr.clone(), visit.clone()); std::thread::spawn(move || raw(&addr, &format!("/v/{visit}/endless/film.mp4"), "")) };
    let waited = std::time::Instant::now();
    while session.lock().unwrap().calls.is_empty() {
        assert!(waited.elapsed() < std::time::Duration::from_secs(10), "the call never reached the signer");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert!(!session.lock().unwrap().reader_gone, "the answer ended before the stop");
    let at = std::time::Instant::now();
    let (st, _, _) = ask(&addr, "POST", &format!("/visits/{visit}/stop"), "", b"");
    assert_eq!(st, 200);
    while !session.lock().unwrap().reader_gone {
        assert!(at.elapsed() < std::time::Duration::from_secs(2), "the signer's socket was still open {:?} after the stop", at.elapsed());
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let (_, body) = reading.join().unwrap();
    assert!(!body.ends_with(b"0\r\n\r\n"), "an answer ended by a stop reached the page as whole");
}

/// A stop goes past the connector's handler slots: with every one of them held by requests stuck on a
/// seller, it still answers at once, and the visit is stopped.
#[test]
fn a_visit_stops_with_every_handler_slot_held() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, _session) = signer(dir.path());
    let addr = start(sock, dir.path());
    let visit = open(&addr, 100_000);
    for i in 0..20 {
        let (addr, visit) = (addr.clone(), visit.clone());
        std::thread::spawn(move || raw(&addr, &format!("/v/{visit}/hang/{i}"), ""));
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
    let at = std::time::Instant::now();
    let (st, _, b) = ask(&addr, "POST", &format!("/visits/{visit}/stop"), "", b"");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&b));
    assert!(at.elapsed() < std::time::Duration::from_secs(2), "the stop waited {:?} behind the stuck requests", at.elapsed());
    let v: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["ended"], "Stopped.", "{v}");
}

/// A path the seller serves free (its `/services` names the route free, as a media server's static
/// web client) is asked for as it is: with nothing to spend (`max_sats` 0), not on the terms of
/// another route (`known_terms`), and with no share of the visit held, however many at once. One
/// that is sold now goes the paid way.
///
/// FAILS before: a visit sent every path paid on the terms the signer kept for the seller, which a
/// free route refuses (`terms_changed`), so each free path took two round trips and made the
/// signer forget the seller's terms.
#[test]
fn a_path_on_a_free_route_is_asked_for_unpaid() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, session) = signer(dir.path());
    let addr = start(sock, dir.path());
    let visit = open(&addr, 1_000);
    let report = |addr: &str| serde_json::from_slice::<Value>(&ask(addr, "GET", &format!("/visits/{visit}"), "", b"").2).unwrap();
    // the seller's routes are read beside the page's first requests, which go the paid way until then
    let t = std::time::Instant::now();
    loop {
        let (st, head, _) = ask(&addr, "GET", &format!("/v/{visit}/web/index.html"), "", b"");
        assert_eq!(st, 200, "{head}");
        let last = session.lock().unwrap().calls.last().cloned().unwrap();
        if last["max_sats"] == 0 {
            assert_ne!(last["known_terms"], true, "{last}");
            break;
        }
        assert!(t.elapsed() < std::time::Duration::from_secs(5), "the free route was never learned: {last}");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let before = report(&addr)["spent_sats"].clone();
    let calls = session.lock().unwrap().calls.len();
    let results: Vec<u16> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..30).map(|i| { let (addr, visit) = (addr.clone(), visit.clone()); s.spawn(move || {
            ask(&addr, "GET", &format!("/v/{visit}/web/{i}.js"), "", b"").0
        }) }).collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert!(results.iter().all(|s| *s == 200), "{results:?}");
    let free: Vec<Value> = session.lock().unwrap().calls[calls..].to_vec();
    assert_eq!(free.len(), 30, "{free:?}");
    assert!(free.iter().all(|c| c["max_sats"] == 0 && c["known_terms"] != true), "{free:?}");
    let r = report(&addr);
    assert_eq!((r["spent_sats"].clone(), r["held_sats"].as_i64()), (before, Some(0)), "{r}");
    // a paid path pays as before
    let (st, head, _) = ask(&addr, "GET", &format!("/v/{visit}/Users/Me"), "", b"");
    assert_eq!(st, 200, "{head}");
    let last = session.lock().unwrap().calls.last().cloned().unwrap();
    assert!(last["max_sats"].as_i64().unwrap() >= 1 && last["known_terms"] == true, "{last}");
    // a path no longer free: refused with nothing to spend, then paid
    let (st, head, _) = ask(&addr, "GET", &format!("/v/{visit}/web/gone/a.js"), "", b"");
    assert_eq!(st, 200, "{head}");
    let gone: Vec<Value> = session.lock().unwrap().calls.iter().filter(|c| c["url"].as_str().unwrap().contains("/web/gone/")).cloned().collect();
    assert!(gone.len() >= 2 && gone[0]["max_sats"] == 0, "{gone:?}");
    assert!(gone[1..].iter().all(|c| c["known_terms"] == true && c["max_sats"].as_i64().unwrap() >= 1), "{gone:?}");
}

/// A stand-in signer whose session starts with `credit` sat and sells tickets of [`TICKET`] sat:
/// each answer under `/part/` costs [`COST`] and has [`PART`] bytes. As the signer does, an answer
/// whose credit runs out and whose call has no room left for a ticket is cut half-way (its length
/// stated, its call not whole); a call that names `top_up_sats` buys tickets before it goes until the
/// credit covers that, within its `max_sats`. Each reply says the balance left and the tickets bought.
fn signer_with_credit(dir: &Path, credit: i64) -> (PathBuf, Arc<Mutex<Session>>) {
    let sock = dir.join("signer.sock");
    let l = UnixListener::bind(&sock).unwrap();
    let stream_dir = dir.to_path_buf();
    let session = Arc::new(Mutex::new(Session { credit, ..Session::default() }));
    let s2 = session.clone();
    std::thread::spawn(move || {
        for conn in l.incoming() {
            let mut conn = conn.unwrap();
            let (stream_dir, session) = (stream_dir.clone(), s2.clone());
            std::thread::spawn(move || {
                let mut line = String::new();
                BufReader::new(conn.try_clone().unwrap()).read_line(&mut line).unwrap();
                let p: Value = serde_json::from_str::<Value>(&line).unwrap()["params"].clone();
                let url = p["url"].as_str().unwrap_or("").to_string();
                if !url.contains("/part/") {
                    let _ = writeln!(conn, "{}", json!({"id": 1, "result": {"verdict": "deny", "rule": "xbt402", "reason": "no such thing", "charged_sats": 0}}));
                    return;
                }
                let (max, top) = (p["max_sats"].as_i64().unwrap(), p["top_up_sats"].as_i64().unwrap_or(0));
                let mut s = session.lock().unwrap();
                s.calls.push(p.clone());
                let mut charged = 0;
                while s.credit < top && max - charged >= TICKET {
                    s.credit += TICKET;
                    charged += TICKET;
                }
                let whole = if s.credit >= COST {
                    true
                } else if max - charged >= TICKET {
                    s.credit += TICKET;
                    charged += TICKET;
                    true
                } else {
                    false
                };
                let used = if whole { COST } else { s.credit };
                s.credit -= used;
                s.charged += charged;
                let balance = s.credit;
                drop(s);
                let mut out = UnixStream::connect(stream_dir.join(p["stream_to"].as_str().unwrap())).unwrap();
                let _ = writeln!(out, "{}", json!({"status": 200, "content_length": PART, "content_type": "application/octet-stream"}));
                let body = vec![5u8; PART];
                let _ = out.write_all(if whole { &body } else { &body[..PART / 2] });
                drop(out);
                let mut r = json!({"verdict": "allow", "status": 200, "charged_sats": charged, "tickets_released": charged / TICKET, "complete": whole,
                                   "price_msat": (used * 1000).to_string(), "balance_msat": (balance * 1000).to_string()});
                if !whole {
                    r["ended"] = "stopped by the wallet: max_sats: the next ticket of this seller is over this call's limit".into();
                }
                let _ = writeln!(conn, "{}", json!({"id": 1, "result": r}));
            });
        }
    });
    (sock, session)
}

const PART: usize = 200_000;

/// A visit that starts on a little credit left from an earlier one keeps that credit ahead of its
/// requests: once a call says the credit is low, the next request tops it up with a ticket before it
/// goes, so that no answer is cut where the credit ends. Every answer comes whole, and the visit
/// spends within its limit.
///
/// FAILS before: each request ran with its share (125 sat of 1,000), too small for a 600 sat ticket,
/// and the answer that found the credit spent was cut half-way: the browser saw a body short of its
/// `Content-Length` (a bitrate test, a film's range).
#[test]
fn a_visit_tops_its_credit_up_before_an_answer_runs_out_of_it() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, session) = signer_with_credit(dir.path(), 150);
    let addr = start(sock, dir.path());
    let visit = open(&addr, 1_000);
    for i in 0..6 {
        let (status, head, body) = ask(&addr, "GET", &format!("/v/{visit}/part/{i}"), "", b"");
        assert_eq!((status, body.len()), (200, PART), "part {i}: {head}");
    }
    let s = session.lock().unwrap();
    assert!(s.charged > 0 && s.charged <= 1_000, "{}", s.charged);
    // the top-up went with the lane's request only
    assert!(s.calls.iter().filter(|c| c["top_up_sats"].as_i64().unwrap_or(0) > 0).count() >= 1);
    drop(s);
    let (_, _, b) = ask(&addr, "GET", &format!("/visits/{visit}"), "", b"");
    let r: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!((r["used_msat"].as_u64(), r["held_sats"].as_i64()), (Some(6 * COST as u64 * 1000), Some(0)), "{r}");
    assert!(r["spent_sats"].as_i64().unwrap() <= 1_000, "{r}");
}

/// A visit's limit is raised by the wallet on this box, as JSON: a request that names an `Origin` (a browser's, a page
/// that found the connector's port) or that is not JSON (a form) is refused, and the limit stays as it was.
///
/// FAILS before: any POST raised it.
#[test]
fn a_visits_limit_is_raised_only_by_the_wallet() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, _) = signer(dir.path());
    let addr = start(sock, dir.path());
    let visit = open(&addr, 1_000);
    let raise = |extra: &str, body: &[u8]| ask(&addr, "POST", &format!("/visits/{visit}/limit"), extra, body).0;
    let body = json!({"limit_sats": 5_000}).to_string();
    assert_eq!(raise("Content-Type: application/json\r\nOrigin: http://evil.example\r\n", body.as_bytes()), 403);
    assert_eq!(raise("Content-Type: application/x-www-form-urlencoded\r\n", b"limit_sats=5000"), 403);
    assert_eq!(raise("Content-Type: text/plain\r\n", body.as_bytes()), 403);
    let (_, _, b) = ask(&addr, "GET", &format!("/visits/{visit}"), "", b"");
    assert_eq!(serde_json::from_slice::<Value>(&b).unwrap()["limit_sats"], 1_000);
    assert_eq!(raise("Content-Type: application/json\r\n", body.as_bytes()), 200);
    let (_, _, b) = ask(&addr, "GET", &format!("/visits/{visit}"), "", b"");
    assert_eq!(serde_json::from_slice::<Value>(&b).unwrap()["limit_sats"], 5_000);
}
