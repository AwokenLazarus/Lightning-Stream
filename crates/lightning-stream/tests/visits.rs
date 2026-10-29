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
}

/// The stand-in signer: one thread per connection, so a page's requests run at once.
fn signer(dir: &Path) -> (PathBuf, Arc<Mutex<Session>>) {
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
                // the session's credit, or a ticket where the call may spend one
                let charged = {
                    let mut s = session.lock().unwrap();
                    s.calls.push(p.clone());
                    let mut charged = 0;
                    if s.credit < COST {
                        if max < TICKET || p["credit_only"] == true {
                            drop(s);
                            let _ = writeln!(conn, "{}", json!({"id": 1, "result": {"verdict": "deny", "rule": "max_sats", "reason": "a ticket does not fit", "charged_sats": 0}}));
                            return;
                        }
                        s.credit += TICKET;
                        s.charged += TICKET;
                        charged = TICKET;
                    }
                    s.credit -= COST;
                    charged
                };
                std::thread::sleep(std::time::Duration::from_millis(5));
                let mut out = UnixStream::connect(stream_dir.join(p["stream_to"].as_str().unwrap())).unwrap();
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
    // each call held a share of the limit as its cap, and the shares running at once never added up to more than it
    let calls = session.lock().unwrap().calls.clone();
    assert!(calls.iter().all(|c| (1..=1_000).contains(&c["max_sats"].as_i64().unwrap())), "{calls:?}");
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
        assert!((1..=1_000).contains(&c["max_sats"].as_i64().unwrap()), "call {i}: {c}");
    }
    let charged = session.lock().unwrap().charged;
    assert!(charged <= 2_500, "{charged}");
    let (_, _, b) = ask(&addr, "GET", &format!("/visits/{visit}"), "", b"");
    let v: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["spent_sats"].as_i64(), Some(charged), "only what was bought stays spent once every request ended: {v}");
}
