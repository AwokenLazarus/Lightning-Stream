//! A route priced by the token, against a stand-in of an OpenAI-compatible service: streamed and
//! whole answers, with and without the counts at their end; exact charges; a request whose output
//! the balance cannot cover; and a stream cut where the balance runs out, its service's
//! connection closed.
mod common;

use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use serde_json::{json, Value};
use xbt_gateway::standin::StandIn;
use xbt_svc::http::{serve_with, Handler, Limits, Reply, Request, Response, Running, Streamed};

/// The stand-in model. A request's own fields choose what it does: `x_n` tokens of output (at
/// most its `max_tokens`), `x_prompt` tokens of input stated, `x_usage` false states no counts,
/// `x_said` states another output count than it streams, `x_pause_ms` between tokens.
#[derive(Default)]
struct Model {
    seen: Mutex<Vec<Value>>,
    /// Answers whose reader went away before the model finished writing.
    cut: Arc<AtomicUsize>,
    /// Tokens written, over all answers.
    written: Arc<AtomicU64>,
}

impl Handler for Model {
    fn body_limit(&self, _m: &str, _t: &str) -> usize {
        1 << 20
    }

    fn handle(&self, _req: Request) -> Response {
        Response::text(500, "text/plain", "unused")
    }

    fn reply(&self, req: Request) -> Reply {
        if req.method == "GET" {
            return Reply::Whole(Response::text(200, "application/json", json!({"data": [{"id": "m"}]}).to_string()));
        }
        let v: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        self.seen.lock().unwrap().push(v.clone());
        let max = v["max_tokens"].as_u64().unwrap_or(u64::MAX);
        let n = v["x_n"].as_u64().unwrap_or(10).min(max);
        let prompt = v["x_prompt"].as_u64().unwrap_or(5);
        let said = v["x_said"].as_u64().unwrap_or(n);
        let usage = v["x_usage"].as_bool().unwrap_or(true);
        let pause = Duration::from_millis(v["x_pause_ms"].as_u64().unwrap_or(0));
        if v["stream"] != true {
            let mut body = json!({"choices": [{"message": {"role": "assistant", "content": "abcd".repeat(n as usize)}}]});
            if usage {
                body["usage"] = json!({"prompt_tokens": prompt, "completion_tokens": said});
            }
            return Reply::Whole(Response::text(200, "application/json", body.to_string()));
        }
        let with_usage = usage && v["stream_options"]["include_usage"] == true;
        let (cut, written) = (self.cut.clone(), self.written.clone());
        Reply::Stream(Streamed {
            status: 200,
            headers: vec![("Content-Type".into(), "text/event-stream".into())],
            length: None,
            body: Box::new(move |out| {
                let mut send = |s: String| -> std::io::Result<()> {
                    if out.gone() {
                        cut.fetch_add(1, Ordering::SeqCst);
                        return Err(std::io::Error::other("gone"));
                    }
                    out.send(s.as_bytes()).inspect_err(|_| {
                        cut.fetch_add(1, Ordering::SeqCst);
                    })
                };
                send(format!("data: {}\n\n", json!({"choices": [{"delta": {"role": "assistant"}}]})))?;
                for _ in 0..n {
                    send(format!("data: {}\n\n", json!({"choices": [{"delta": {"content": "tok"}}]})))?;
                    written.fetch_add(1, Ordering::SeqCst);
                    if !pause.is_zero() {
                        std::thread::sleep(pause);
                    }
                }
                if with_usage {
                    send(format!("data: {}\n\n", json!({"choices": [], "usage": {"prompt_tokens": prompt, "completion_tokens": said}})))?;
                }
                send("data: [DONE]\n\n".into())
            }),
        })
    }
}

fn start_model() -> (Running, Arc<Model>) {
    let m = Arc::new(Model::default());
    let run = serve_with(m.clone(), TcpListener::bind("127.0.0.1:0").unwrap(), 16, Limits { per_address: 0, connections: 64, ..Limits::default() }).unwrap();
    (run, m)
}

/// A gateway whose `/v1/` route is the model, priced at `input`/`output` msat per 1,000 tokens,
/// its output capped at `cap` tokens.
fn rig(input: u64, output: u64, cap: u64) -> (Rig, tempfile::TempDir, Arc<Model>, Running) {
    let (model_run, model) = start_model();
    let up = format!("http://{}", model_run.addr);
    let dir = tempfile::tempdir().unwrap();
    let rig = start_on(dir.path(), Arc::new(StandIn::new(100)), start_service(), Arc::new(AtomicU64::new(1_000_000)), &|v| {
        let mut price = json!({"per_1k_output_msat": output});
        if input > 0 {
            price["per_1k_input_msat"] = input.into();
        }
        v["routes"].as_array_mut().unwrap().push(json!({"path": "/v1/", "methods": ["GET", "POST"], "upstream": up, "price": price,
                                                       "max_output_tokens": cap, "max_body": 65536}));
    });
    (rig, dir, model, model_run)
}

fn post(b: &mut Buyer, target: &str, body: &Value, secret: Option<&[u8; 32]>) -> Got {
    let body = body.to_string();
    let sig = b.sign("POST", target, body.as_bytes(), secret, None);
    let got = http(&b.addr, "POST", target, &[("PAYMENT-SIGNATURE", &sig), ("Content-Type", "application/json")], body.as_bytes(), None);
    b.used(&got);
    got
}

/// The tokens of output a streamed body carries, by its chunks with text.
fn streamed_tokens(body: &[u8]) -> usize {
    String::from_utf8_lossy(body).matches("\"content\":\"tok\"").count()
}

/// The last receipt the seller keeps for the session's answers.
fn last_final(b: &mut Buyer) -> Value {
    b.status()["responses"].as_array().unwrap().last().cloned().expect("a final receipt")
}

#[test]
fn a_streamed_answer_is_charged_its_tokens_exactly() {
    let (rig, _dir, model, _m) = rig(2000, 10_000, 500);
    let mut b = Buyer::new(&rig, 1);
    let s = b.lock(&rig, 1);
    let body = json!({"model": "m", "messages": [{"role": "user", "content": "hi"}], "stream": true, "x_n": 37, "x_prompt": 11});
    let got = post(&mut b, "/v1/chat/completions", &body, Some(&s[0]));
    assert_eq!(got.status, 200, "{}", String::from_utf8_lossy(&got.body));
    assert!(got.complete);
    assert_eq!(streamed_tokens(&got.body), 37);
    // the gateway bounded the output and asked for the counts
    let seen = model.seen.lock().unwrap()[0].clone();
    assert_eq!((seen["max_tokens"].as_u64(), seen["stream_options"]["include_usage"].as_bool()), (Some(500), Some(true)));
    // 11 tokens in at 2 sat a thousand (22 msat), 37 out at 10 sat a thousand (370 msat)
    assert_eq!(b.balance(), 1_000_000 - 22 - 370);
    let r = last_final(&mut b);
    assert_eq!((r["charged"].as_str(), r["complete"].as_bool()), (Some("392"), Some(true)));
    assert_eq!(r["tokens"], json!({"input": 11, "output": 37}));
}

#[test]
fn the_counts_settle_the_call_within_what_the_request_allows() {
    // the model says more output than it streamed: the counts win, up to max_tokens
    let (rig, _dir, _model, _m) = rig(0, 10_000, 500);
    let mut b = Buyer::new(&rig, 2);
    let s = b.lock(&rig, 1);
    let got = post(&mut b, "/v1/chat/completions", &json!({"stream": true, "x_n": 10, "x_said": 12, "max_tokens": 20}), Some(&s[0]));
    assert_eq!(got.status, 200);
    assert_eq!(b.balance(), 1_000_000 - 120);
    // and a count above the request's max_tokens is held to it
    let got = post(&mut b, "/v1/chat/completions", &json!({"stream": true, "x_n": 10, "x_said": 999, "max_tokens": 20}), None);
    assert_eq!(got.status, 200);
    assert_eq!(b.balance(), 1_000_000 - 120 - 200);
    // input is free on this route: nothing for the prompt, however long
    let got = post(&mut b, "/v1/chat/completions", &json!({"stream": true, "x_n": 1, "x_prompt": 400, "pad": "x".repeat(2000)}), None);
    assert_eq!(got.status, 200);
    assert_eq!(b.balance(), 1_000_000 - 120 - 200 - 10);
}

#[test]
fn a_service_that_states_no_counts_is_charged_its_chunks() {
    let (rig, _dir, _model, _m) = rig(4000, 10_000, 500);
    let mut b = Buyer::new(&rig, 3);
    let s = b.lock(&rig, 1);
    let body = json!({"stream": true, "x_n": 9, "x_usage": false});
    let len = body.to_string().len() as u64;
    let got = post(&mut b, "/v1/chat/completions", &body, Some(&s[0]));
    assert_eq!((got.status, streamed_tokens(&got.body)), (200, 9));
    // output: the 9 chunks; input: one token per four bytes of the request
    let input = (len.div_ceil(4) * 4000).div_ceil(1000);
    assert_eq!(b.balance(), 1_000_000 - input - 90);
}

#[test]
fn a_whole_answer_is_charged_from_its_counts() {
    let (rig, _dir, _model, _m) = rig(1000, 10_000, 500);
    let mut b = Buyer::new(&rig, 4);
    let s = b.lock(&rig, 1);
    // a prompt of 30 tokens is a body of more than 60 bytes: within what the body can hold
    let got = post(&mut b, "/v1/chat/completions", &json!({"x_n": 25, "x_prompt": 30, "messages": [{"role": "user", "content": "x".repeat(80)}]}), Some(&s[0]));
    assert_eq!(got.status, 200, "{}", String::from_utf8_lossy(&got.body));
    assert_eq!(got.json()["usage"]["completion_tokens"], 25);
    assert_eq!(b.balance(), 1_000_000 - 30 - 250);
    // without counts: a token per four characters of the text
    let got = post(&mut b, "/v1/chat/completions", &json!({"x_n": 25, "x_usage": false}), None);
    assert_eq!(got.status, 200);
    let body_len = json!({"x_n": 25, "x_usage": false}).to_string().len() as u64;
    let input = body_len.div_ceil(4);
    assert_eq!(b.balance(), 1_000_000 - 30 - 250 - input - 250);
}

#[test]
fn a_request_the_balance_cannot_bound_is_refused_before_the_model_is_asked() {
    // 10,000 msat a token: one ticket of 1,000,000 covers 100 tokens of output
    let (rig, _dir, model, _m) = rig(0, 10_000_000, 1000);
    let mut b = Buyer::new(&rig, 5);
    let s = b.lock(&rig, 1);
    let got = post(&mut b, "/v1/chat/completions", &json!({"stream": true, "x_n": 5, "max_tokens": 200}), Some(&s[0]));
    assert_eq!(got.status, 402, "{}", String::from_utf8_lossy(&got.body));
    assert_eq!(got.error(), "balance_short");
    assert!(model.seen.lock().unwrap().is_empty(), "the model was asked");
    // with max_tokens the balance covers, it is served
    let got = post(&mut b, "/v1/chat/completions", &json!({"stream": true, "x_n": 5, "max_tokens": 100}), None);
    assert_eq!(got.status, 200, "{}", String::from_utf8_lossy(&got.body));
    assert_eq!(b.balance(), 1_000_000 - 50_000);
    // a body that is not a request object is refused, and costs nothing
    let got = post(&mut b, "/v1/chat/completions", &json!([1, 2]), None);
    assert_eq!(got.status, 400);
    assert_eq!(b.balance(), 1_000_000 - 50_000);
    // a request with no body (the list of models) costs the route's price per request: nothing here
    let got = b.get("/v1/models", None);
    assert_eq!(got.status, 200);
    assert_eq!(b.balance(), 1_000_000 - 50_000);
}

#[test]
fn a_stream_stops_where_the_balance_does_and_the_model_is_hung_up_on() {
    // two answers at once on one ticket that covers 100 tokens: each is covered when it starts,
    // together they are not. What is sent never passes what is paid, and the one that runs out
    // is cut, its connection to the model closed
    let (rig, _dir, model, _m) = rig(0, 10_000_000, 100);
    let mut b = Buyer::new(&rig, 6);
    let s = b.lock(&rig, 1);
    let body = json!({"stream": true, "x_n": 100, "x_pause_ms": 15}).to_string();
    // the second asks for at most 50, which what is left when it starts still covers
    let body2 = json!({"stream": true, "x_n": 100, "x_pause_ms": 15, "max_tokens": 50}).to_string();
    let sig1 = b.sign("POST", "/v1/chat/completions", body.as_bytes(), Some(&s[0]), None);
    let sig2 = b.sign("POST", "/v1/chat/completions", body2.as_bytes(), None, None);
    let addr = b.addr.clone();
    let first = {
        let (addr, body, sig) = (addr.clone(), body.clone(), sig1);
        std::thread::spawn(move || http(&addr, "POST", "/v1/chat/completions", &[("PAYMENT-SIGNATURE", &sig)], body.as_bytes(), None))
    };
    std::thread::sleep(Duration::from_millis(150));
    let second = http(&addr, "POST", "/v1/chat/completions", &[("PAYMENT-SIGNATURE", &sig2)], body2.as_bytes(), None);
    let first = first.join().unwrap();
    assert_eq!((first.status, second.status), (200, 200));
    let (t1, t2) = (streamed_tokens(&first.body), streamed_tokens(&second.body));
    assert_eq!(t1 + t2, 100, "sent {t1} + {t2} tokens on a balance for 100");
    assert!(!first.complete || !second.complete, "one answer ran out");
    assert_eq!(b.balance(), 0);
    wait_for("the model to see the hang-up", || model.cut.load(Ordering::SeqCst) >= 1);
    // the model stopped writing short of the 150 tokens the two asked for
    std::thread::sleep(Duration::from_millis(300));
    assert!(model.written.load(Ordering::SeqCst) < 150);
}

#[test]
fn token_prices_are_in_the_terms_and_the_listing() {
    let (rig, _dir, _model, _m) = rig(0, 10_000, 512);
    let got = http(&rig.addr, "POST", "/v1/chat/completions", &[], b"{}", None);
    assert_eq!(got.status, 402);
    let pr: Value = xbt402::wire::unb64json(got.header("PAYMENT-REQUIRED").unwrap()).unwrap();
    let price = &pr["accepts"][0]["extra"]["price"];
    assert_eq!((price["outputPer1kMsat"].as_str(), price["inputPer1kMsat"].as_str(), price["maxOutputTokens"].as_str()),
               (Some("10000"), Some("0"), Some("512")));
}

#[test]
fn the_model_list_of_a_token_priced_route_is_free_to_read() {
    let (rig, _dir, _model, _m) = rig(0, 10_000, 512);
    let got = http(&rig.addr, "GET", "/v1/models", &[], b"", None);
    assert_eq!(got.status, 200, "a buyer reads the model list before paying");
    let v: Value = serde_json::from_slice(&got.body).unwrap();
    assert_eq!(v["data"][0]["id"], "m");
    assert_eq!(http(&rig.addr, "HEAD", "/v1/models", &[], b"", None).status, 200);
    // everything else on the route is still sold
    assert_eq!(http(&rig.addr, "GET", "/v1/other", &[], b"", None).status, 402);
    assert_eq!(http(&rig.addr, "POST", "/v1/models", &[], b"{}", None).status, 402);
}
