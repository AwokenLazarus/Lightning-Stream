//! The AI endpoint against a stand-in signer that plays two sellers: the models of both are listed
//! once; a request goes to the cheaper; one that the wallet refuses, or the first seller fails on,
//! lands at the other, with nothing booked for the first; one the first seller may still be serving
//! (paid for and sent, then silent) never lands at a second; an answer cut mid-way is not moved,
//! and says so; a stream of events reaches the client as the seller sent it; what each call cost is
//! booked against its key, and a key at its limit is refused before anything is paid.
//!
//! The stand-in does what the signer does on the ticket rail: it opens the caller's socket once a
//! request is paid for, says so (`paid`), says `paying` before paying again, sends nothing to a
//! caller that is gone, and says in its answer whether the request left (`request_sent`).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lightning_stream::credentials::{Kind, Store};
use serde_json::{json, Value};

/// How a stand-in seller answers a paid request.
#[derive(Clone, Copy, PartialEq)]
enum Plan {
    /// Streams `ANSWER` and is paid `price_msat`.
    Answer(u64),
    /// Part of an answer that is not a stream of events, then the wallet says it was cut.
    CutWhole(u64),
    /// The wallet refuses to pay it (nothing reaches the socket).
    Refused,
    /// Sends nothing for longer than the endpoint waits.
    Silent,
    /// Answers 500.
    Broken,
    /// Answers 400 (the request itself is wrong).
    BadRequest,
    /// Sends part of the answer, then stops; paid for what it sent.
    Cut(u64),
    /// Streams `ANSWER` and is paid `.0`, its payment taking `.1` ms over a slow route before the
    /// request leaves: the seller itself answers at once. A caller gone by then is sent nothing.
    SlowPay(u64, u64),
    /// Another call's ticket covers this one (it buys none: `charged_sats` 0), which waits `.1` ms
    /// for that payment; the request then leaves whatever became of the caller, as a rail that says
    /// nothing of `request_sent` may, and is served and paid `.0`.
    Covered(u64, u64),
    /// Paid for, then the seller's balance runs short: the wallet pays again for `.1` ms (saying
    /// `paying`, then `paid`), and the seller answers, paid `.0`.
    PayAgain(u64, u64),
    /// Paid for and sent; a proxy in front of the seller answers 524 with no receipt, and no head
    /// reaches the caller: the request may still be served behind it.
    ProxyTimeout,
    /// Answers whole, paid `.0`; the wallet's account comes `.1` ms after the socket closes (its
    /// wait for the seller's last receipt).
    LateReceipt(u64, u64),
    /// Answers whole; the wallet's account never comes (the call to the signer fails).
    Lost,
    /// Its service is full: it turns the request away before anything is paid or served.
    Busy,
}

/// The caller's socket is still there (as the signer checks before it sends).
fn there(s: &UnixStream) -> bool {
    s.set_nonblocking(true).unwrap();
    let open = matches!((&*s).read(&mut [0u8; 1]), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock);
    s.set_nonblocking(false).unwrap();
    open
}

const EMBEDDING: &str = "{\"object\":\"list\",\"data\":[{\"object\":\"embedding\",\"index\":0,\"embedding\":[0.1,0.2]}]}";

const ANSWER: &str = "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\" there\"}}]}\n\ndata: [DONE]\n\n";

struct Sellers {
    plans: HashMap<String, Plan>,
    /// The sellers the stand-in wallet paid a ticket, one entry a paid call.
    paid: Vec<String>,
    /// The sellers a request reached (served, or may be): one entry a request that left.
    served: Vec<String>,
    /// Each paid call: (url, body sent).
    calls: Vec<(String, Value)>,
    /// No seller's model list can be had (the wallet not ready, the links not open yet).
    models_down: bool,
}

fn signer(dir: &Path, sellers: Arc<Mutex<Sellers>>) -> PathBuf {
    let sock = dir.join("signer.sock");
    let l = UnixListener::bind(&sock).unwrap();
    let stream_dir = dir.to_path_buf();
    std::thread::spawn(move || {
        for conn in l.incoming() {
            let mut conn = conn.unwrap();
            let sellers = Arc::clone(&sellers);
            let stream_dir = stream_dir.clone();
            std::thread::spawn(move || {
                let mut line = String::new();
                BufReader::new(conn.try_clone().unwrap()).read_line(&mut line).unwrap();
                let req: Value = serde_json::from_str(&line).unwrap();
                let p = req["params"].clone();
                let url = p["url"].as_str().unwrap().to_string();
                let seller = url.split('/').nth(2).unwrap().to_string();
                let connect = || {
                    let s = UnixStream::connect(stream_dir.join(p["stream_to"].as_str().unwrap())).unwrap();
                    s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                    s
                };
                let head = |status: u16, t: &str| json!({"status": status, "content_type": t}).to_string();
                let down = sellers.lock().unwrap().models_down;
                let result = if url.ends_with("/v1/models") && down {
                    json!({"verdict": "deny", "rule": "xbt402", "reason": "the seller gave no answer: no link yet", "charged_sats": 0})
                } else if url.ends_with("/v1/models") && seller == "paid.example" {
                    // a gateway that serves nothing outside a paid session: its list is not free
                    json!({"verdict": "deny", "rule": "max_sats", "reason": "the seller asks to be paid and this call may spend nothing (max_sats 0)", "charged_sats": 0})
                } else if url.ends_with("/v1/models") {
                    let mut s = connect();
                    let models = match seller.as_str() {
                        "cheap.example" => json!({"data": [{"id": "llama"}, {"id": "qwen"}]}),
                        "third.example" => json!({"data": [{"id": "mistral"}]}),
                        _ => json!({"data": [{"id": "llama"}]}),
                    };
                    writeln!(s, "{}", head(200, "application/json")).unwrap();
                    s.write_all(models.to_string().as_bytes()).unwrap();
                    json!({"verdict": "allow", "rule": "free", "status": 200, "complete": true, "charged_sats": 0})
                } else {
                    let plan = { let mut g = sellers.lock().unwrap(); g.calls.push((url.clone(), serde_json::from_str(p["body"].as_str().unwrap()).unwrap())); g.plans[&seller] };
                    let serve = || sellers.lock().unwrap().served.push(seller.clone());
                    // as the signer does on the ticket rail: once the request is paid for, the socket opens, with a line
                    // that says so first where the caller asked for one; a caller gone by then (its socket closed, or never
                    // reached) is sent nothing, and the answer says the request did not leave
                    let opened = || {
                        let s = UnixStream::connect(stream_dir.join(p["stream_to"].as_str().unwrap())).ok()?;
                        s.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                        if p["stream_paid"] == true {
                            writeln!(&s, "{}", json!({"paid": true})).ok()?;
                        }
                        there(&s).then_some(s)
                    };
                    let gone = json!({"verdict": "deny", "rule": "ticket_caller_gone", "reason": "the caller stopped waiting before the request was sent",
                                      "status": null, "request_sent": false, "charged_sats": 900});
                    match plan {
                        Plan::Answer(msat) if url.ends_with("/v1/embeddings") => {
                            let mut s = connect();
                            serve();
                            writeln!(s, "{}", head(200, "application/json")).unwrap();
                            s.write_all(EMBEDDING.as_bytes()).unwrap();
                            json!({"verdict": "allow", "rail": "ticket", "status": 200, "complete": true, "price_msat": msat.to_string(), "charged_sats": 900,
                                   "request_sent": true})
                        }
                        Plan::Answer(msat) => {
                            let Some(mut s) = opened() else { return_gone(&conn, &gone); return };
                            serve();
                            writeln!(s, "{}", head(200, "text/event-stream")).unwrap();
                            for part in ANSWER.split_inclusive("\n\n") {
                                s.write_all(part.as_bytes()).unwrap();
                                std::thread::sleep(Duration::from_millis(5));
                            }
                            json!({"verdict": "allow", "rail": "ticket", "status": 200, "complete": true, "price_msat": msat.to_string(), "charged_sats": 900,
                                   "request_sent": true})
                        }
                        Plan::Refused => json!({"verdict": "deny", "rule": "allowlist", "reason": "destination not on allowlist", "charged_sats": 0}),
                        Plan::Busy => json!({"verdict": "deny", "rule": "seller_busy", "reason": "the seller's service is full (30 of 30 buyers): nothing was paid",
                                             "status": 503, "charged_sats": 0, "request_sent": false}),
                        Plan::Silent => {
                            // paid for and sent: the seller has it, and says nothing for longer than the endpoint waits
                            let _s = opened();
                            serve();
                            std::thread::sleep(Duration::from_millis(2500));
                            json!({"verdict": "deny", "rule": "ticket_seller", "reason": "the seller gave no answer to the paid request", "status": null,
                                   "request_sent": true, "charged_sats": 900})
                        }
                        Plan::Broken => {
                            let Some(mut s) = opened() else { return_gone(&conn, &gone); return };
                            serve();
                            writeln!(s, "{}", head(500, "application/json")).unwrap();
                            let _ = s.write_all(b"{\"error\":\"model crashed\"}");
                            json!({"verdict": "allow", "status": 500, "complete": true, "price_msat": "0", "request_sent": true})
                        }
                        Plan::BadRequest => {
                            let Some(mut s) = opened() else { return_gone(&conn, &gone); return };
                            serve();
                            writeln!(s, "{}", head(400, "application/json")).unwrap();
                            let _ = s.write_all(b"{\"error\":{\"message\":\"max_tokens too large\"}}");
                            json!({"verdict": "allow", "status": 400, "complete": true, "price_msat": "0", "request_sent": true})
                        }
                        Plan::SlowPay(msat, ms) => {
                            std::thread::sleep(Duration::from_millis(ms));
                            // paid: the caller may have stopped waiting meanwhile, and its socket be gone
                            let Some(mut s) = opened() else {
                                sellers.lock().unwrap().paid.push(seller.clone());
                                return_gone(&conn, &gone);
                                return;
                            };
                            serve();
                            let _ = writeln!(s, "{}", head(200, "text/event-stream"));
                            let _ = s.write_all(ANSWER.as_bytes());
                            json!({"verdict": "allow", "rail": "ticket", "status": 200, "complete": true, "price_msat": msat.to_string(), "charged_sats": 900,
                                   "request_sent": true})
                        }
                        Plan::Covered(msat, ms) => {
                            std::thread::sleep(Duration::from_millis(ms));
                            // the request leaves whatever became of the caller: the seller serves it and charges the balance
                            serve();
                            if let Ok(mut s) = UnixStream::connect(stream_dir.join(p["stream_to"].as_str().unwrap())) {
                                let _ = writeln!(s, "{}", json!({"paid": true}));
                                let _ = writeln!(s, "{}", head(200, "text/event-stream"));
                                let _ = s.write_all(ANSWER.as_bytes());
                            }
                            json!({"verdict": "allow", "rail": "ticket", "status": 200, "complete": false, "price_msat": msat.to_string(), "charged_sats": 0})
                        }
                        Plan::PayAgain(msat, ms) => {
                            let Some(mut s) = opened() else { return_gone(&conn, &gone); return };
                            // sent, refused unserved for a short balance, paid again, sent again
                            writeln!(s, "{}", json!({"paying": true})).unwrap();
                            std::thread::sleep(Duration::from_millis(ms));
                            writeln!(s, "{}", json!({"paid": true})).unwrap();
                            if !there(&s) {
                                return_gone(&conn, &gone);
                                return;
                            }
                            serve();
                            writeln!(s, "{}", head(200, "text/event-stream")).unwrap();
                            s.write_all(ANSWER.as_bytes()).unwrap();
                            json!({"verdict": "allow", "rail": "ticket", "status": 200, "complete": true, "price_msat": msat.to_string(), "charged_sats": 1800,
                                   "request_sent": true})
                        }
                        Plan::ProxyTimeout => {
                            let Some(s) = opened() else { return_gone(&conn, &gone); return };
                            serve();
                            drop(s);
                            json!({"verdict": "deny", "rule": "ticket_seller", "reason": "the seller answered HTTP 524 without a receipt", "status": 524,
                                   "request_sent": true, "charged_sats": 900})
                        }
                        Plan::LateReceipt(msat, ms) => {
                            let Some(mut s) = opened() else { return_gone(&conn, &gone); return };
                            serve();
                            writeln!(s, "{}", head(200, "text/event-stream")).unwrap();
                            s.write_all(ANSWER.as_bytes()).unwrap();
                            drop(s);
                            std::thread::sleep(Duration::from_millis(ms));
                            json!({"verdict": "allow", "rail": "ticket", "status": 200, "complete": true, "price_msat": msat.to_string(), "charged_sats": 900,
                                   "request_sent": true})
                        }
                        Plan::Lost => {
                            let Some(mut s) = opened() else { return_gone(&conn, &gone); return };
                            serve();
                            writeln!(s, "{}", head(200, "text/event-stream")).unwrap();
                            s.write_all(ANSWER.as_bytes()).unwrap();
                            drop(s);
                            // the call to the signer ends with no answer
                            return;
                        }
                        Plan::CutWhole(msat) => {
                            let Some(mut s) = opened() else { return_gone(&conn, &gone); return };
                            serve();
                            writeln!(s, "{}", head(200, "application/json")).unwrap();
                            s.write_all(b"{\"choices\":[{\"mess").unwrap();
                            json!({"verdict": "allow", "status": 200, "complete": false, "price_msat": msat.to_string(), "request_sent": true})
                        }
                        Plan::Cut(msat) => {
                            let Some(mut s) = opened() else { return_gone(&conn, &gone); return };
                            serve();
                            writeln!(s, "{}", head(200, "text/event-stream")).unwrap();
                            s.write_all(ANSWER.split_inclusive("\n\n").next().unwrap().as_bytes()).unwrap();
                            json!({"verdict": "allow", "status": 200, "complete": false, "price_msat": msat.to_string(), "request_sent": true})
                        }
                    }
                };
                if result["charged_sats"].as_i64().unwrap_or(0) > 0 {
                    sellers.lock().unwrap().paid.push(seller.clone());
                }
                let _ = writeln!(conn, "{}", json!({"id": 1, "result": result}));
            });
        }
    });
    sock
}

/// The stand-in's answer for a caller gone before its request was sent.
fn return_gone(mut conn: &UnixStream, gone: &Value) {
    let _ = writeln!(conn, "{}", json!({"id": 1, "result": gone}));
}

struct Rig {
    addr: String,
    key: String,
    key_id: String,
    creds: PathBuf,
    sellers: Arc<Mutex<Sellers>>,
    _dir: tempfile::TempDir,
}

fn rig(cheap: Plan, dear: Plan, limit_sats: u64) -> Rig {
    rig_with(cheap, dear, limit_sats, false)
}

/// The rig, its sellers' model lists unavailable when its endpoint starts if `models_down`.
fn rig_with(cheap: Plan, dear: Plan, limit_sats: u64, models_down: bool) -> Rig {
    rig_paying(cheap, dear, limit_sats, models_down, lightning_stream::inference_server::PAY_WAIT)
}

/// [`rig_with`], with `pay_wait` for a call's payment.
fn rig_paying(cheap: Plan, dear: Plan, limit_sats: u64, models_down: bool, pay_wait: Duration) -> Rig {
    rig_timed(cheap, dear, limit_sats, models_down, pay_wait, Duration::from_millis(1000))
}

/// [`rig_paying`], with `first_byte` for a seller's first byte.
fn rig_timed(cheap: Plan, dear: Plan, limit_sats: u64, models_down: bool, pay_wait: Duration, first_byte: Duration) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let sellers = Arc::new(Mutex::new(Sellers { plans: HashMap::from([("cheap.example".into(), cheap), ("dear.example".into(), dear)]), paid: vec![],
                                                served: vec![], calls: vec![], models_down }));
    let sock = signer(dir.path(), Arc::clone(&sellers));
    let creds = dir.path().join("credentials.json");
    let mut store = Store::open(&creds).unwrap();
    let (key_id, key) = store.make(Kind::AiKey, "test client", limit_sats, None, None);
    store.save().unwrap();
    let list = dir.path().join("ai-sellers.json");
    std::fs::write(&list, json!({"sellers": [
        {"name": "cheap", "route": "https://cheap.example/ai/", "prices": {"per_1k_output_msat": 5000}, "max_output": 1024},
        {"name": "dear", "route": "https://dear.example/ai/", "prices": {"per_1k_output_msat": 9000}, "max_output": 1024}]}).to_string()).unwrap();
    let cfg = lightning_stream::inference_server::Config {
        signer: sock, stream_dir: dir.path().to_path_buf(), task: "ai".into(), max_sats: 2000, credentials: creds.clone(), sellers: list,
        state: dir.path().join("ai-state.json"), first_byte, pay_wait,
        account_wait: Duration::from_millis(500), allowed_hosts: vec![],
    };
    let run = lightning_stream::inference_server::serve(cfg, TcpListener::bind("127.0.0.1:0").unwrap()).unwrap();
    let addr = run.addr.to_string();
    std::mem::forget(run);
    Rig { addr, key, key_id, creds, sellers, _dir: dir }
}

fn call(addr: &str, method: &str, path: &str, auth: Option<&str>, extra: &str, body: &str) -> (u16, String, String) {
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    let auth = auth.map(|k| format!("Authorization: Bearer {k}\r\n")).unwrap_or_default();
    write!(s, "{method} {path} HTTP/1.1\r\nHost: {addr}\r\n{auth}{extra}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    let mut all = vec![];
    s.read_to_end(&mut all).unwrap();
    let split = all.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&all[..split]).to_string();
    let status = head[9..12].parse().unwrap();
    let mut body = all[split + 4..].to_vec();
    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        let mut out = vec![];
        let mut rest = &body[..];
        loop {
            // a body cut short has no last chunk ([`chat_raw`] tells them apart)
            let Some(nl) = rest.windows(2).position(|w| w == b"\r\n") else { break };
            let n = usize::from_str_radix(std::str::from_utf8(&rest[..nl]).unwrap().trim(), 16).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&rest[nl + 2..nl + 2 + n]);
            rest = &rest[nl + 4 + n..];
        }
        body = out;
    }
    (status, head, String::from_utf8_lossy(&body).to_string())
}

fn chat(r: &Rig, model: &str) -> (u16, String, String) {
    call(&r.addr, "POST", "/v1/chat/completions", Some(&r.key), "", &json!({"model": model, "stream": true, "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}]}).to_string())
}

/// One chat, as it came: the bytes after the head, its chunks' framing included.
fn chat_raw(r: &Rig, model: &str) -> Vec<u8> {
    let mut s = std::net::TcpStream::connect(&r.addr).unwrap();
    let body = json!({"model": model, "stream": true, "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}]}).to_string();
    write!(s, "POST /v1/chat/completions HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", r.addr, r.key, body.len()).unwrap();
    let mut all = vec![];
    s.read_to_end(&mut all).unwrap();
    let split = all.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    all[split + 4..].to_vec()
}

fn spent(r: &Rig) -> u64 {
    Store::open(&r.creds).unwrap().entries.iter().find(|e| e.id == r.key_id).unwrap().spent_msat
}

fn sellers_called(r: &Rig) -> Vec<String> {
    r.sellers.lock().unwrap().calls.iter().map(|(u, _)| u.split('/').nth(2).unwrap().to_string()).collect()
}

#[test]
fn the_models_of_both_sellers_are_listed_and_a_key_is_needed() {
    let r = rig(Plan::Answer(1), Plan::Answer(1), 100);
    let (status, _, _) = call(&r.addr, "GET", "/v1/models", None, "", "");
    assert_eq!(status, 401);
    let (status, _, body) = call(&r.addr, "GET", "/v1/models", Some(&r.key), "", "");
    assert_eq!(status, 200, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    let ids: Vec<&str> = v["data"].as_array().unwrap().iter().map(|m| m["id"].as_str().unwrap()).collect();
    assert_eq!(ids.iter().filter(|i| **i == "llama").count(), 1);
    assert!(ids.contains(&"qwen") && ids.contains(&"cheap/llama") && ids.contains(&"dear/llama"));
}

#[test]
fn a_request_goes_to_the_cheaper_seller_streams_and_its_cost_is_booked_to_the_key() {
    let r = rig(Plan::Answer(1234), Plan::Answer(9999), 100);
    let (status, head, body) = chat(&r, "llama");
    assert_eq!(status, 200);
    assert!(head.to_ascii_lowercase().contains("content-type: text/event-stream"));
    assert_eq!(body, ANSWER, "the stream reaches the client as the seller sent it");
    assert_eq!(sellers_called(&r), ["cheap.example"]);
    // the seller is asked for its own model name
    assert_eq!(r.sellers.lock().unwrap().calls[0].1["model"], "llama");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(spent(&r), 1234, "the key is charged what the receipt says, exactly");
    // pinning the dearer one by name
    let (status, _, _) = chat(&r, "dear/llama");
    assert_eq!(status, 200);
    assert_eq!(sellers_called(&r), ["cheap.example", "dear.example"]);
}

fn served(r: &Rig) -> Vec<String> {
    r.sellers.lock().unwrap().served.clone()
}

#[test]
fn a_seller_that_is_refused_or_broken_hands_the_request_to_the_next() {
    for first in [Plan::Refused, Plan::Broken] {
        let r = rig(first, Plan::Answer(777), 100);
        let (status, _, body) = chat(&r, "llama");
        assert_eq!(status, 200, "{body}");
        assert_eq!(body, ANSWER);
        assert_eq!(sellers_called(&r), ["cheap.example", "dear.example"]);
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(spent(&r), 777, "only the seller that answered is booked");
    }
}

/// A seller paid for and sent the request, then silent past its time: it may still be serving the
/// request, and charge for it, so no other seller is tried. The client is told; one seller had the
/// request; with no receipt to say what it drew, the most the request may cost is booked.
///
/// FAILS before: the next seller was tried, and both could serve and charge one answer.
#[test]
fn a_seller_paid_for_and_silent_is_not_followed_by_another() {
    let r = rig(Plan::Silent, Plan::Answer(777), 100);
    let (status, _, body) = chat(&r, "llama");
    assert_eq!(status, 504, "{body}");
    assert_eq!(sellers_called(&r), ["cheap.example"], "no other seller is called");
    std::thread::sleep(Duration::from_millis(2700));
    assert_eq!(served(&r), ["cheap.example"], "one seller had the request");
    assert_eq!(spent(&r), 500, "no receipt: the most the request may cost (100 tokens out at 5 sat the 1,000) is booked");
}

/// A request that left, answered by a proxy in front of the seller with a 524 and no receipt: the
/// request may still be served behind the proxy, so no other seller is tried.
///
/// FAILS before: any 5xx in the wallet's account let the next seller be tried, so both could serve
/// and be paid for one answer.
#[test]
fn a_proxys_524_after_the_request_left_is_not_followed_by_another_seller() {
    let r = rig(Plan::ProxyTimeout, Plan::Answer(777), 100);
    let (status, _, body) = chat(&r, "llama");
    assert_eq!(status, 502, "{body}");
    assert_eq!(sellers_called(&r), ["cheap.example"], "no other seller is called");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(served(&r), ["cheap.example"]);
    assert_eq!(spent(&r), 500, "no receipt: the most the request may cost");
}

/// More quick calls at once than may wait on a payment (8) are a moment's queue, not a refusal: all
/// 12 are served, and each is booked.
///
/// FAILS before: the 9th call on was answered 503 at once, with nothing slow.
#[test]
fn more_quick_calls_at_once_than_may_wait_on_a_payment_are_all_served() {
    let r = rig_timed(Plan::Answer(10), Plan::Answer(10), 100, false, lightning_stream::inference_server::PAY_WAIT, Duration::from_secs(20));
    model_ids(&r);
    let (addr, key) = (r.addr.clone(), r.key.clone());
    let calls: Vec<_> = (0..12).map(|_| {
        let (addr, key) = (addr.clone(), key.clone());
        std::thread::spawn(move || call(&addr, "POST", "/v1/chat/completions", Some(&key), "", &json!({"model": "llama", "stream": true, "max_tokens": 100}).to_string()))
    }).collect();
    let got: Vec<_> = calls.into_iter().map(|c| c.join().unwrap()).collect();
    assert!(got.iter().all(|(status, _, body)| (*status, body.as_str()) == (200, ANSWER)), "{:?}", got.iter().map(|g| g.0).collect::<Vec<_>>());
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(served(&r).len(), 12);
    assert_eq!(spent(&r), 120, "each booked once");
}

/// When a slow route holds every place, a call waits only a moment for one, is told 503, and nothing
/// is sent or paid for it; the endpoint's health and list of models still answer.
#[test]
fn a_slow_route_holding_every_place_refuses_soon_and_the_endpoint_still_answers() {
    let r = rig(Plan::SlowPay(10, 3000), Plan::Answer(10), 100);
    model_ids(&r);
    let calls: Vec<_> = (0..8).map(|_| {
        let (addr, key) = (r.addr.clone(), r.key.clone());
        std::thread::spawn(move || call(&addr, "POST", "/v1/chat/completions", Some(&key), "", &json!({"model": "llama", "stream": true, "max_tokens": 100}).to_string()))
    }).collect();
    wait_until("all 8 at the wallet", || r.sellers.lock().unwrap().calls.len() == 8);
    let t = std::time::Instant::now();
    let (status, _, body) = chat(&r, "llama");
    assert_eq!(status, 503, "{body}");
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["error"]["code"], "busy");
    assert!(t.elapsed() < Duration::from_secs(2), "told soon, not after the payment: {:?}", t.elapsed());
    assert_eq!(call(&r.addr, "GET", "/health", None, "", "").0, 200);
    assert!(model_ids(&r).contains(&"llama".to_string()));
    assert_eq!(r.sellers.lock().unwrap().calls.len(), 8, "nothing sent for the call refused");
    for c in calls {
        assert_eq!(c.join().unwrap().0, 200);
    }
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(spent(&r), 80, "the 8 served are booked, the one refused is not");
}

fn wait_until(what: &str, done: impl Fn() -> bool) {
    let end = std::time::Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(std::time::Instant::now() < end, "waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A seller whose service is full turns the request away before anything is paid or served: the
/// next seller serves, and is the only one paid or booked.
///
/// FAILS before (the status alone read as a request that left): the call ended 502 with no other
/// seller tried.
#[test]
fn a_busy_seller_hands_the_request_to_the_next() {
    let r = rig(Plan::Busy, Plan::Answer(777), 100);
    let (status, _, body) = chat(&r, "llama");
    assert_eq!((status, body.as_str()), (200, ANSWER));
    assert_eq!(sellers_called(&r), ["cheap.example", "dear.example"]);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!((served(&r), r.sellers.lock().unwrap().paid.clone()), (vec!["dear.example".to_string()], vec!["dear.example".to_string()]));
    assert_eq!(spent(&r), 777);
}

/// The wallet's account of a whole answer comes after the endpoint's wait for it (the signer waits
/// up to 10 s for the seller's last receipt): what it cost is booked when it comes, the seller is
/// recorded as having answered, and no cut is said to the client.
///
/// FAILS before: the endpoint waited 10 s, booked nothing, recorded the seller as cut mid-answer and
/// sent the client a "stopped mid-answer" event after the answer's end.
#[test]
fn a_late_account_of_a_whole_answer_is_booked_with_no_cut_said() {
    let r = rig(Plan::LateReceipt(432, 1500), Plan::Answer(1), 100);
    let (status, _, body) = chat(&r, "llama");
    assert_eq!((status, body.as_str()), (200, ANSWER), "the answer as the seller sent it, no cut event");
    std::thread::sleep(Duration::from_millis(1800));
    assert_eq!(spent(&r), 432, "booked when the account came");
    let state: Value = serde_json::from_slice(&std::fs::read(r._dir.path().join("ai-state.json")).unwrap()).unwrap();
    assert_eq!((state["health"]["cheap"]["ok"].as_u64(), state["health"]["cheap"]["failed"].as_u64()), (Some(1), Some(0)), "{state}");
}

/// The wallet never says what a whole answer cost (the call to the signer failed): the most the
/// request may cost is booked to the key, never nothing.
///
/// FAILS before: nothing was booked.
#[test]
fn an_answer_whose_cost_the_wallet_never_says_books_the_most_it_may_cost() {
    let r = rig(Plan::Lost, Plan::Answer(1), 100);
    let (status, _, body) = chat(&r, "llama");
    assert_eq!((status, body.as_str()), (200, ANSWER));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(spent(&r), 500, "100 tokens out at 5 sat the 1,000: the bound");
}

/// A seller whose call takes 2.5 s to pay for (a first ticket over a slow route), with 1 s for its
/// first byte, is given that second from when it is paid for: it answers, and is the only seller
/// paid and booked.
///
/// FAILS before: the second ran from the start of the call, payment and all, so the request went
/// to the next seller as the first's payment went through: two sellers paid for one answer, and on
/// a slow route every AI call of a buyer failed over or failed.
#[test]
fn a_seller_paid_over_a_slow_route_is_given_its_time_from_the_payment() {
    let r = rig(Plan::SlowPay(777, 2500), Plan::Answer(999), 100);
    let (status, _, body) = chat(&r, "llama");
    assert_eq!((status, body.as_str()), (200, ANSWER));
    assert_eq!(sellers_called(&r), ["cheap.example"], "no other seller is called");
    std::thread::sleep(Duration::from_millis(200));
    // both sides: the wallet paid one seller, and the key is booked that seller's price only
    assert_eq!(r.sellers.lock().unwrap().paid, ["cheap.example"], "the wallet paid one seller");
    assert_eq!(spent(&r), 777, "the seller that answered, and only it, is booked");
}

/// A seller whose payment outlasts even the wait for it (here 1.5 s, against a payment of 2.5 s):
/// no other seller is tried while the wallet may still send the first the request. The wallet
/// finds the caller gone once paid, sends nothing, and says so: the next seller serves, and is the
/// only one that had the request or is booked. What the first was paid stays with it as credit.
///
/// FAILS before: the next seller was tried at once, and paid, as the first's payment went through.
#[test]
fn a_seller_whose_payment_outlasts_the_wait_is_followed_only_once_the_wallet_says_the_request_never_left() {
    let r = rig_paying(Plan::SlowPay(777, 2500), Plan::Answer(999), 100, false, Duration::from_millis(1500));
    let (status, _, body) = chat(&r, "llama");
    assert_eq!((status, body.as_str()), (200, ANSWER));
    assert_eq!(sellers_called(&r), ["cheap.example", "dear.example"]);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(served(&r), ["dear.example"], "one seller had the request: the first was sent nothing");
    assert_eq!(spent(&r), 999, "the seller that answered, and only it, is booked");
}

/// Another call's ticket covers this one, so the wallet buys none for it (`charged_sats` 0), and
/// the request leaves after the endpoint stopped waiting, from a rail that says nothing of
/// `request_sent`. A head means it reached the seller: no other is tried, and what the seller
/// charged is booked to the key though the client got no answer.
///
/// FAILS before: `charged_sats` 0 read as "nothing was paid", so the next seller was tried and both
/// served one answer; and nothing the first charged was booked to the key.
#[test]
fn a_call_another_paid_for_is_not_followed_by_another_seller_and_what_it_cost_is_booked() {
    let r = rig_paying(Plan::Covered(555, 2000), Plan::Answer(999), 100, false, Duration::from_millis(1500));
    let (status, _, body) = chat(&r, "llama");
    assert_eq!(status, 504, "{body}");
    assert_eq!(sellers_called(&r), ["cheap.example"], "no other seller is called");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(served(&r), ["cheap.example"]);
    assert_eq!(spent(&r), 555, "what the seller charged is booked to the key");
}

/// The wallet pays again after it said the request is paid for (the seller's balance ran short),
/// for longer than the seller's own time: the endpoint's clock waits for that payment, and the
/// seller answers. One seller served; it is booked.
///
/// FAILS before: the seller's second ran through the second payment, the next seller was tried,
/// and both were paid for one answer.
#[test]
fn a_second_payment_after_the_paid_line_is_not_the_sellers_time() {
    let r = rig(Plan::PayAgain(321, 1500), Plan::Answer(999), 100);
    let (status, _, body) = chat(&r, "llama");
    assert_eq!((status, body.as_str()), (200, ANSWER));
    assert_eq!(sellers_called(&r), ["cheap.example"]);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(served(&r), ["cheap.example"]);
    assert_eq!(spent(&r), 321);
}

#[test]
fn a_bad_request_is_not_moved_and_no_seller_left_is_an_error_in_openais_shape() {
    let r = rig(Plan::BadRequest, Plan::Answer(1), 100);
    let (status, _, body) = chat(&r, "llama");
    assert_eq!(status, 400);
    assert!(body.contains("max_tokens too large"));
    assert_eq!(sellers_called(&r), ["cheap.example"], "a request the seller refused would fare no better elsewhere");
    let r = rig(Plan::Broken, Plan::Refused, 100);
    let (status, _, body) = chat(&r, "llama");
    assert_eq!(status, 502);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["error"]["code"], "upstream_failed");
    let (status, _, body) = chat(&r, "gpt-9");
    assert_eq!(status, 404);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["error"]["code"], "model_not_found");
}

#[test]
fn an_answer_cut_mid_way_is_not_moved_says_so_and_is_paid_for_what_arrived() {
    let r = rig(Plan::Cut(300), Plan::Answer(1), 100);
    let (status, _, body) = chat(&r, "llama");
    assert_eq!(status, 200);
    assert!(body.starts_with(ANSWER.split_inclusive("\n\n").next().unwrap()));
    assert!(body.contains("\"code\":\"answer_cut\""), "{body}");
    assert_eq!(sellers_called(&r), ["cheap.example"], "never switched mid-answer");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(spent(&r), 300);
}

/// An answer cut mid-way never reaches the client as a whole one: a stream of events says so in an
/// event and has no last chunk, and an answer that is not a stream of events, with no event to say
/// it in, has no last chunk either. A whole answer ends with its last chunk.
#[test]
fn an_answer_cut_mid_way_has_no_last_chunk_stream_of_events_or_not() {
    let r = rig(Plan::Cut(300), Plan::Answer(1), 100);
    let raw = chat_raw(&r, "llama");
    assert!(String::from_utf8_lossy(&raw).contains("answer_cut"), "{}", String::from_utf8_lossy(&raw));
    assert!(!raw.ends_with(b"0\r\n\r\n"), "a cut stream of events ended as whole");
    let r = rig(Plan::CutWhole(300), Plan::Answer(1), 100);
    let raw = chat_raw(&r, "llama");
    assert!(!raw.ends_with(b"0\r\n\r\n"), "a cut answer that is not a stream of events ended as whole");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(spent(&r), 300, "and it is paid for what arrived");
    let r = rig(Plan::Answer(1), Plan::Answer(1), 100);
    assert!(chat_raw(&r, "llama").ends_with(b"0\r\n\r\n"), "a whole answer has its last chunk");
}

#[test]
fn a_key_at_its_limit_is_refused_before_anything_is_paid() {
    // the cheap seller's bound for 100 tokens out is 500 msat: a key of 0 sats cannot cover it
    let r = rig(Plan::Answer(1), Plan::Answer(1), 0);
    let (status, _, body) = chat(&r, "llama");
    assert_eq!(status, 402);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["error"]["code"], "limit_reached");
    assert!(sellers_called(&r).is_empty());
    // a revoked key is unknown
    let mut s = Store::open(&r.creds).unwrap();
    s.revoke(&r.key_id);
    s.save().unwrap();
    let (status, _, _) = chat(&r, "llama");
    assert_eq!(status, 401);
}

#[test]
fn a_web_page_cannot_use_the_endpoint() {
    let r = rig(Plan::Answer(1), Plan::Answer(1), 100);
    let (status, _, _) = call(&r.addr, "GET", "/v1/models", Some(&r.key), "Origin: https://evil.example\r\n", "");
    assert_eq!(status, 403);
    let (status, _, _) = call(&r.addr, "GET", "/v1/models", Some(&r.key), "Sec-Fetch-Site: cross-site\r\n", "");
    assert_eq!(status, 403);
}

#[test]
fn an_embedding_request_goes_to_the_sellers_embeddings_and_comes_back_whole() {
    let r = rig(Plan::Answer(42), Plan::Answer(1), 100);
    let (status, head, body) = call(&r.addr, "POST", "/v1/embeddings", Some(&r.key), "", &json!({"model": "llama", "input": "hello"}).to_string());
    assert_eq!(status, 200, "{body}");
    assert!(head.to_ascii_lowercase().contains("content-type: application/json"));
    assert_eq!(body, EMBEDDING);
    let calls = r.sellers.lock().unwrap().calls.clone();
    assert_eq!(calls[0].0, "https://cheap.example/ai/v1/embeddings");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(spent(&r), 42);
}

#[test]
fn the_first_request_of_a_fresh_endpoint_waits_for_the_catalogue_fetched_in_the_background() {
    // the rig's endpoint starts fetching the model lists when it starts; a request straight after finds the model
    let r = rig(Plan::Answer(5), Plan::Answer(9), 100);
    let (status, _, body) = chat(&r, "qwen");
    assert_eq!(status, 200, "{body}");
    assert_eq!(sellers_called(&r), ["cheap.example"]);
}

#[test]
fn a_seller_whose_list_is_not_free_is_listed_with_the_models_its_entry_names() {
    let r = rig(Plan::Answer(1), Plan::Answer(1), 100);
    r.sellers.lock().unwrap().plans.insert("paid.example".into(), Plan::Answer(3));
    let list = r._dir.path().join("ai-sellers.json");
    let mut v: Value = serde_json::from_slice(&std::fs::read(&list).unwrap()).unwrap();
    v["sellers"].as_array_mut().unwrap().push(json!({"name": "paid", "route": "https://paid.example/ai/", "prices": {"per_1k_output_msat": 1000},
                                                      "max_output": 1024, "models": ["tiny"]}));
    v["sellers"].as_array_mut().unwrap().push(json!({"name": "silent", "route": "https://paid.example/other/", "prices": {"per_1k_output_msat": 1}}));
    std::fs::write(&list, v.to_string()).unwrap();
    // the rig's endpoint read the sellers file when it started: one more endpoint on the changed file
    let cfg = lightning_stream::inference_server::Config {
        signer: r._dir.path().join("signer.sock"), stream_dir: r._dir.path().to_path_buf(), task: "ai".into(), max_sats: 2000,
        credentials: r.creds.clone(), sellers: list, state: r._dir.path().join("ai-state-2.json"), first_byte: Duration::from_millis(1000),
        pay_wait: lightning_stream::inference_server::PAY_WAIT, account_wait: Duration::from_millis(500), allowed_hosts: vec![],
    };
    let run = lightning_stream::inference_server::serve(cfg, TcpListener::bind("127.0.0.1:0").unwrap()).unwrap();
    let addr = run.addr.to_string();
    std::mem::forget(run);
    let (status, _, body) = call(&addr, "GET", "/v1/models", Some(&r.key), "", "");
    assert_eq!(status, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    let ids: Vec<&str> = v["data"].as_array().unwrap().iter().map(|m| m["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&"tiny") && ids.contains(&"paid/tiny"), "{ids:?}");
    assert!(!ids.iter().any(|i| i.starts_with("silent/")), "a seller with no free list and no models named is not listed");
    let (status, _, body) = call(&addr, "POST", "/v1/chat/completions", Some(&r.key), "", &json!({"model": "tiny", "stream": true, "max_tokens": 10}).to_string());
    assert_eq!(status, 200, "{body}");
    assert!(sellers_called(&r).contains(&"paid.example".to_string()));
}

#[test]
fn a_pin_or_a_block_applies_to_the_next_request_and_a_request_too_dear_for_the_key_says_so() {
    let r = rig(Plan::Answer(1), Plan::Answer(1), 1);
    assert_eq!(chat(&r, "llama").0, 200);
    let list = r._dir.path().join("ai-sellers.json");
    let mut v: Value = serde_json::from_slice(&std::fs::read(&list).unwrap()).unwrap();
    v["pinned"] = json!(["dear"]);
    std::thread::sleep(Duration::from_millis(20));
    std::fs::write(&list, v.to_string()).unwrap();
    assert_eq!(chat(&r, "llama").0, 200);
    assert_eq!(sellers_called(&r), ["cheap.example", "dear.example"], "the pin applies to the very next request");
    // 1 sat of limit: a request that may cost up to 9 sats (1,000 tokens at the dearer price) is refused, and says why
    let (status, _, body) = call(&r.addr, "POST", "/v1/chat/completions", Some(&r.key), "",
                                 &json!({"model": "llama", "stream": true, "max_tokens": 1000}).to_string());
    assert_eq!(status, 402);
    let m = serde_json::from_str::<Value>(&body).unwrap()["error"]["message"].as_str().unwrap().to_string();
    assert!(m.contains("may cost up to") && m.contains("fewer max_tokens"), "{m}");
}

fn model_ids(r: &Rig) -> Vec<String> {
    let (status, _, body) = call(&r.addr, "GET", "/v1/models", Some(&r.key), "", "");
    assert_eq!(status, 200, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    v["data"].as_array().unwrap().iter().map(|m| m["id"].as_str().unwrap().to_string()).collect()
}

#[test]
fn sellers_not_reachable_when_the_endpoint_starts_are_asked_again_within_seconds() {
    // the app and the wallet start together: the first fetch finds no seller, and the next request
    // after a short while asks again, instead of answering "no such model" for the whole TTL
    let r = rig_with(Plan::Answer(5), Plan::Answer(9), 100, true);
    assert!(model_ids(&r).is_empty());
    r.sellers.lock().unwrap().models_down = false;
    std::thread::sleep(lightning_stream::inference_server::CATALOGUE_RETRY + Duration::from_millis(300));
    let (status, _, body) = chat(&r, "qwen");
    assert_eq!(status, 200, "a request {:?} after the sellers are back is served: {body}", lightning_stream::inference_server::CATALOGUE_RETRY);
    assert_eq!(sellers_called(&r), ["cheap.example"]);
}

#[test]
fn a_seller_added_to_the_sellers_file_is_usable_on_the_next_request() {
    let r = rig(Plan::Answer(5), Plan::Answer(9), 100);
    assert!(model_ids(&r).contains(&"qwen".to_string()));
    r.sellers.lock().unwrap().plans.insert("third.example".into(), Plan::Answer(2));
    let list = r._dir.path().join("ai-sellers.json");
    let mut v: Value = serde_json::from_slice(&std::fs::read(&list).unwrap()).unwrap();
    v["sellers"].as_array_mut().unwrap().push(json!({"name": "third", "route": "https://third.example/ai/", "prices": {"per_1k_output_msat": 3000},
                                                      "max_output": 1024}));
    std::thread::sleep(Duration::from_millis(20));
    std::fs::write(&list, v.to_string()).unwrap();
    let (status, _, body) = chat(&r, "mistral");
    assert_eq!(status, 200, "the owner just allowed this seller: {body}");
    assert_eq!(sellers_called(&r), ["third.example"]);
}
