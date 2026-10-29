//! The AI endpoint against a stand-in signer that plays two sellers: the models of both are listed
//! once; a request goes to the cheaper; one that the first seller refuses, or that it sends nothing
//! for in time, lands at the other, with nothing booked for the first; an answer cut mid-way is not
//! moved, and says so; a stream of events reaches the client as the seller sent it; what each call
//! cost is booked against its key, and a key at its limit is refused before anything is paid.

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
}

const EMBEDDING: &str = "{\"object\":\"list\",\"data\":[{\"object\":\"embedding\",\"index\":0,\"embedding\":[0.1,0.2]}]}";

const ANSWER: &str = "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\" there\"}}]}\n\ndata: [DONE]\n\n";

struct Sellers {
    plans: HashMap<String, Plan>,
    /// Each paid call: (url, body sent).
    calls: Vec<(String, Value)>,
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
                let result = if url.ends_with("/v1/models") {
                    let mut s = connect();
                    let models = if seller == "cheap.example" { json!({"data": [{"id": "llama"}, {"id": "qwen"}]}) } else { json!({"data": [{"id": "llama"}]}) };
                    writeln!(s, "{}", head(200, "application/json")).unwrap();
                    s.write_all(models.to_string().as_bytes()).unwrap();
                    json!({"verdict": "allow", "rule": "free", "status": 200, "complete": true, "charged_sats": 0})
                } else {
                    let plan = { let mut g = sellers.lock().unwrap(); g.calls.push((url.clone(), serde_json::from_str(p["body"].as_str().unwrap()).unwrap())); g.plans[&seller] };
                    match plan {
                        Plan::Answer(msat) if url.ends_with("/v1/embeddings") => {
                            let mut s = connect();
                            writeln!(s, "{}", head(200, "application/json")).unwrap();
                            s.write_all(EMBEDDING.as_bytes()).unwrap();
                            json!({"verdict": "allow", "rail": "ticket", "status": 200, "complete": true, "price_msat": msat.to_string(), "charged_sats": 900})
                        }
                        Plan::Answer(msat) => {
                            let mut s = connect();
                            writeln!(s, "{}", head(200, "text/event-stream")).unwrap();
                            for part in ANSWER.split_inclusive("\n\n") {
                                s.write_all(part.as_bytes()).unwrap();
                                std::thread::sleep(Duration::from_millis(5));
                            }
                            json!({"verdict": "allow", "rail": "ticket", "status": 200, "complete": true, "price_msat": msat.to_string(), "charged_sats": 900})
                        }
                        Plan::Refused => json!({"verdict": "deny", "rule": "allowlist", "reason": "destination not on allowlist", "charged_sats": 0}),
                        Plan::Silent => {
                            let _s = connect();
                            std::thread::sleep(Duration::from_millis(2500));
                            json!({"verdict": "allow", "complete": false, "price_msat": "0"})
                        }
                        Plan::Broken => {
                            let mut s = connect();
                            writeln!(s, "{}", head(500, "application/json")).unwrap();
                            let _ = s.write_all(b"{\"error\":\"model crashed\"}");
                            json!({"verdict": "allow", "status": 500, "complete": true, "price_msat": "0"})
                        }
                        Plan::BadRequest => {
                            let mut s = connect();
                            writeln!(s, "{}", head(400, "application/json")).unwrap();
                            let _ = s.write_all(b"{\"error\":{\"message\":\"max_tokens too large\"}}");
                            json!({"verdict": "allow", "status": 400, "complete": true, "price_msat": "0"})
                        }
                        Plan::Cut(msat) => {
                            let mut s = connect();
                            writeln!(s, "{}", head(200, "text/event-stream")).unwrap();
                            s.write_all(ANSWER.split_inclusive("\n\n").next().unwrap().as_bytes()).unwrap();
                            json!({"verdict": "allow", "status": 200, "complete": false, "price_msat": msat.to_string()})
                        }
                    }
                };
                let _ = writeln!(conn, "{}", json!({"id": 1, "result": result}));
            });
        }
    });
    sock
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
    let dir = tempfile::tempdir().unwrap();
    let sellers = Arc::new(Mutex::new(Sellers { plans: HashMap::from([("cheap.example".into(), cheap), ("dear.example".into(), dear)]), calls: vec![] }));
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
        state: dir.path().join("ai-state.json"), first_byte: Duration::from_millis(1000), allowed_hosts: vec![],
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
            let nl = rest.windows(2).position(|w| w == b"\r\n").unwrap();
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

#[test]
fn a_seller_that_is_refused_broken_or_silent_hands_the_request_to_the_next() {
    for first in [Plan::Refused, Plan::Broken, Plan::Silent] {
        let r = rig(first, Plan::Answer(777), 100);
        let (status, _, body) = chat(&r, "llama");
        assert_eq!(status, 200, "{body}");
        assert_eq!(body, ANSWER);
        assert_eq!(sellers_called(&r), ["cheap.example", "dear.example"]);
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(spent(&r), 777, "only the seller that answered is booked");
    }
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
