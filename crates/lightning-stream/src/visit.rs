//! Visits: a seller's own web page, used inside the app, paid for as it loads under a limit the
//! owner set for the visit (docs/SELLER-APPS.md).
//!
//! `POST /visits` `{"base": "<seller URL ending in />", "limit_sats": N}` → `{"visit": id}`.
//! `GET /visits/<id>`: what the visit has spent, its limit, and whether it has ended.
//! `POST /visits/<id>/stop`: end it; its next request is refused.
//! `<any method> /v/<id>/<path>`: one request of the page, sent to `base` + `path` and paid.
//!
//! **The limit, exactly.** A page asks for many things at once. One request of a visit at a time
//! holds the turn to buy: it may spend what is left of the limit. Every other one may use only the
//! credit the seller already holds for the session: it is sent `credit_only`, so the signer buys no
//! ticket for it, with what is left of the limit as the most its answer may charge (the seller is
//! told that figure and stops the answer there). One that needs a ticket before it starts waits for
//! the turn and is sent again. Tickets are bought only within the limit; answers running at once on
//! credit already bought each stop at what was left when they started.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt_svc::http::{BodyWriter, Reply, Request, Response, Streamed};

use crate::{listen_stream, one_range, random_hex, Connector, FIRST_BYTE, HEAD_LINE, LONGEST};

/// The most visits open at once; an idle one ends after [`IDLE`].
const MAX_VISITS: usize = 32;
const IDLE: Duration = Duration::from_secs(30 * 60);
/// The largest request body of a page passed on.
pub const MAX_BODY: usize = 1 << 20;
/// How long a request waits for the turn to buy.
const TURN_WAIT: Duration = Duration::from_secs(120);
/// The most of a visit's limit one WebSocket holds while it is open: counted as spent until it
/// ends, then only what it cost. A live connection does not hold the turn to buy, which the page's
/// other requests need.
const SOCKET_SHARE: i64 = 1_000;

/// The WebSocket's own request headers, passed to the seller beside [`PASSED`].
const SOCKET_HEADERS: [&str; 4] = ["sec-websocket-key", "sec-websocket-version", "sec-websocket-protocol", "sec-websocket-extensions"];

/// Request headers of a page that go to the seller. The seller's gateway passes on only those its
/// route names; the signer refuses the wallet's own and the hop-by-hop ones.
const PASSED: [&str; 13] = ["accept", "accept-language", "content-type", "if-modified-since", "if-none-match", "if-range", "authorization", "cookie",
                            "x-emby-authorization", "x-mediabrowser-token", "x-requested-with", "x-csrf-token", "x-api-key"];

#[derive(Default)]
struct State {
    spent: i64,
    ended: Option<String>,
    buying: bool,
    calls: u64,
    last: Option<Instant>,
}

pub struct Visit {
    base: String,
    limit: i64,
    state: Mutex<State>,
    turn: Condvar,
}

impl Visit {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn report(&self) -> Value {
        let s = self.lock();
        json!({"base": self.base, "limit_sats": self.limit, "spent_sats": s.spent, "ended": s.ended, "calls": s.calls})
    }

    /// Wait for the turn to buy. `Err`: the visit ended, or the wait was too long.
    /// What is left of the limit now, in sats.
    fn left(&self) -> i64 {
        let s = self.lock();
        self.limit - s.spent
    }

    fn take_turn(&self) -> Result<i64, String> {
        let mut s = self.lock();
        let until = Instant::now() + TURN_WAIT;
        loop {
            if let Some(e) = &s.ended {
                return Err(e.clone());
            }
            if !s.buying {
                let left = self.limit - s.spent;
                if left < 1 {
                    s.ended = Some("This visit's spending limit is reached.".into());
                    return Err(s.ended.clone().unwrap_or_default());
                }
                s.buying = true;
                return Ok(left);
            }
            let now = Instant::now();
            if now >= until {
                return Err("The page asked for too much at once: try again.".into());
            }
            s = self.turn.wait_timeout(s, until - now).unwrap_or_else(|p| p.into_inner()).0;
        }
    }

    /// Hold up to [`SOCKET_SHARE`] of what is left for a WebSocket. `Err`: the visit has ended, or
    /// nothing is left.
    fn reserve(&self) -> Result<i64, String> {
        let mut s = self.lock();
        if let Some(e) = &s.ended {
            return Err(e.clone());
        }
        let share = (self.limit - s.spent).min(SOCKET_SHARE);
        if share < 1 {
            s.ended = Some("This visit's spending limit is reached.".into());
            return Err(s.ended.clone().unwrap_or_default());
        }
        s.spent += share;
        Ok(share)
    }

    /// A WebSocket that held `share` has ended, having cost `charged`.
    fn release(&self, share: i64, charged: i64) {
        let mut s = self.lock();
        s.spent = s.spent - share + charged.clamp(0, share);
        drop(s);
        self.turn.notify_all();
    }

    fn settle(&self, charged: i64, had_turn: bool) {
        let mut s = self.lock();
        s.spent = s.spent.saturating_add(charged.max(0));
        if had_turn {
            s.buying = false;
        }
        drop(s);
        self.turn.notify_all();
    }
}

#[derive(Default)]
pub struct Visits {
    open: Mutex<HashMap<String, Arc<Visit>>>,
}

impl Visits {
    fn get(&self, id: &str) -> Option<Arc<Visit>> {
        self.open.lock().unwrap_or_else(|p| p.into_inner()).get(id).cloned()
    }

    fn open(&self, base: String, limit: i64) -> Result<String, String> {
        let mut m = self.open.lock().unwrap_or_else(|p| p.into_inner());
        m.retain(|_, v| {
            let s = v.lock();
            s.ended.is_none() && s.last.is_none_or(|t| t.elapsed() < IDLE)
        });
        if m.len() >= MAX_VISITS {
            return Err("too many visits open".into());
        }
        let id = random_hex();
        m.insert(id.clone(), Arc::new(Visit { base, limit, state: Mutex::new(State { last: Some(Instant::now()), ..State::default() }), turn: Condvar::new() }));
        Ok(id)
    }
}

/// The base of a visit: an absolute http(s) URL ending in `/`, of visible characters.
fn base_ok(b: &str) -> bool {
    (b.starts_with("https://") || b.starts_with("http://")) && b.ends_with('/') && b.len() <= 2000 && b.bytes().all(|c| c.is_ascii_graphic())
        && !b.contains(['?', '#', '\\'])
}

impl Connector {
    pub(crate) fn visits_reply(&self, req: &Request) -> Option<Reply> {
        let t = req.target.as_str();
        if t == "/visits" {
            if req.method != "POST" {
                return Some(Reply::Whole(json_response(405, &json!({"error": "POST a visit"}))));
            }
            let v: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let base = v.get("base").and_then(Value::as_str).unwrap_or("").to_string();
            let limit = v.get("limit_sats").and_then(Value::as_i64).unwrap_or(0);
            if !base_ok(&base) || !(1..=10_000_000).contains(&limit) {
                return Some(Reply::Whole(json_response(400, &json!({"error": "a visit is a seller URL ending in / and a limit of 1 sat or more"}))));
            }
            return Some(Reply::Whole(match self.visits.open(base, limit) {
                Ok(id) => json_response(200, &json!({"visit": id})),
                Err(e) => json_response(503, &json!({"error": e})),
            }));
        }
        if let Some(rest) = t.strip_prefix("/visits/") {
            let (id, stop) = match rest.strip_suffix("/stop") {
                Some(id) => (id, true),
                None => (rest, false),
            };
            let Some(v) = self.visits.get(id) else {
                return Some(Reply::Whole(json_response(404, &json!({"error": "no such visit"}))));
            };
            if stop {
                if req.method != "POST" {
                    return Some(Reply::Whole(json_response(405, &json!({"error": "POST to stop"}))));
                }
                v.lock().ended.get_or_insert_with(|| "Stopped.".into());
                v.turn.notify_all();
            }
            return Some(Reply::Whole(json_response(200, &v.report())));
        }
        let rest = t.strip_prefix("/v/")?;
        let (id, path) = rest.split_once('/').unwrap_or((rest, ""));
        let Some(visit) = self.visits.get(id) else {
            return Some(Reply::Whole(json_response(404, &json!({"error": "This visit has ended. Open the app again."}))));
        };
        Some(self.visit_call(visit, path, req))
    }

    /// One request of a page: credit first, then the turn to buy when the credit is not enough.
    fn visit_call(&self, visit: Arc<Visit>, path: &str, req: &Request) -> Reply {
        if req.header("Upgrade").is_some_and(|u| u.eq_ignore_ascii_case("websocket")) {
            return self.visit_socket(visit, path, req);
        }
        {
            let mut s = visit.lock();
            if let Some(e) = &s.ended {
                return Reply::Whole(json_response(402, &json!({"error": e, "rule": "visit"})));
            }
            s.calls += 1;
            s.last = Some(Instant::now());
        }
        let url = format!("{}{path}", visit.base);
        let headers: Vec<Value> = req.headers.iter().filter(|(k, _)| PASSED.contains(&k.to_ascii_lowercase().as_str()))
            .take(24).map(|(k, v)| json!([k, v])).collect();
        let range = req.header("Range").map(str::trim).filter(|r| one_range(r)).map(str::to_string);
        let method = req.method.to_ascii_uppercase();
        let body = if req.body.is_empty() { None } else {
            use base64::Engine as _;
            Some(base64::engine::general_purpose::STANDARD.encode(&req.body))
        };
        let call = |max_sats: i64, credit_only: bool| -> Result<Started, Value> {
            let mut params = json!({"url": url, "method": method, "max_sats": max_sats, "task": self.cfg.task, "headers": headers, "head_headers": true,
                                    "credit_only": credit_only});
            if let Some(b) = &body {
                params["body_b64"] = b.clone().into();
            }
            if let Some(r) = &range {
                params["range"] = r.clone().into();
            }
            if let Some(m) = params.as_object_mut() {
                xbt_wallet_mcp::wallet::with_transport(m);
            }
            self.start(params)
        };
        // the session's credit only: no ticket is bought, and the answer may charge at most what is left
        let left_now = visit.left();
        if left_now < 1 {
            visit.lock().ended.get_or_insert_with(|| "This visit's spending limit is reached.".into());
            return Reply::Whole(json_response(402, &json!({"error": "This visit's spending limit is reached.", "rule": "visit"})));
        }
        let (started, turn) = match call(left_now, true) {
            Ok(s) => (s, false),
            Err(v) if v.get("rule").and_then(Value::as_str) == Some("max_sats") => {
                let left = match visit.take_turn() {
                    Ok(l) => l,
                    Err(e) => return Reply::Whole(json_response(402, &json!({"error": e, "rule": "visit"}))),
                };
                match call(left, false) {
                    Ok(s) => (s, true),
                    Err(v) => {
                        let charged = v.get("charged_sats").and_then(Value::as_i64).unwrap_or(0);
                        visit.settle(charged, true);
                        if v.get("rule").and_then(Value::as_str) == Some("max_sats") {
                            visit.lock().ended.get_or_insert_with(|| "This visit's spending limit is reached.".into());
                            return Reply::Whole(json_response(402, &json!({"error": "This visit's spending limit is reached.", "rule": "visit"})));
                        }
                        return Reply::Whole(refusal(&v));
                    }
                }
            }
            Err(v) => {
                visit.settle(v.get("charged_sats").and_then(Value::as_i64).unwrap_or(0), false);
                return Reply::Whole(refusal(&v));
            }
        };
        let Started { head, first, src, done } = started;
        let status = head.get("status").and_then(Value::as_u64).and_then(|s| u16::try_from(s).ok()).unwrap_or(502);
        let mut out_headers: Vec<(String, String)> = vec![];
        for h in head.get("headers").and_then(Value::as_array).into_iter().flatten() {
            if let (Some(k), Some(v)) = (h.get(0).and_then(Value::as_str), h.get(1).and_then(Value::as_str)) {
                // what frames the body is this answer's own
                if !["content-length", "transfer-encoding", "connection", "keep-alive", "content-encoding"].contains(&k.to_ascii_lowercase().as_str()) {
                    out_headers.push((k.to_string(), v.to_string()));
                }
            }
        }
        if !out_headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
            if let Some(t) = head.get("content_type").and_then(Value::as_str) {
                out_headers.push(("Content-Type".into(), t.into()));
            }
        }
        let length = head.get("content_length").and_then(Value::as_u64);
        let mut settle = Settle { visit, turn, src: Some(src), done: Some(done) };
        Reply::Stream(Streamed {
            status,
            headers: out_headers,
            length,
            body: Box::new(move |out: &mut dyn BodyWriter| {
                out.send(&first)?;
                let mut buf = vec![0u8; 64 << 10];
                while let Some(src) = settle.src.as_mut() {
                    let n = src.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    out.send(&buf[..n])?;
                }
                Ok(())
            }),
        })
    }

    /// A page's WebSocket: paid for as its bytes pass, both ways, from a share of the visit's limit
    /// held while it is open ([`SOCKET_SHARE`]).
    fn visit_socket(&self, visit: Arc<Visit>, path: &str, req: &Request) -> Reply {
        if req.method != "GET" {
            return Reply::Whole(json_response(400, &json!({"error": "a WebSocket opens with a GET"})));
        }
        {
            let mut s = visit.lock();
            s.calls += 1;
            s.last = Some(Instant::now());
        }
        let share = match visit.reserve() {
            Ok(n) => n,
            Err(e) => return Reply::Whole(json_response(402, &json!({"error": e, "rule": "visit"}))),
        };
        let headers: Vec<Value> = req.headers.iter()
            .filter(|(k, _)| { let l = k.to_ascii_lowercase(); PASSED.contains(&l.as_str()) || SOCKET_HEADERS.contains(&l.as_str()) })
            .take(24).map(|(k, v)| json!([k, v])).collect();
        let mut params = json!({"url": format!("{}{path}", visit.base), "method": "GET", "max_sats": share, "task": self.cfg.task, "headers": headers,
                            "head_headers": true, "upgrade": true});
        if let Some(m) = params.as_object_mut() {
            xbt_wallet_mcp::wallet::with_transport(m);
        }
        let Started { head, first, src, done } = match self.start(params) {
            Ok(s) => s,
            Err(v) => {
                visit.release(share, v.get("charged_sats").and_then(Value::as_i64).unwrap_or(0));
                return Reply::Whole(refusal(&v));
            }
        };
        let status = head.get("status").and_then(Value::as_u64).unwrap_or(502);
        if status != 101 {
            drop(src);
            let charged = done.recv_timeout(Duration::from_secs(60)).ok().and_then(Result::ok).and_then(|v| v.get("charged_sats").and_then(Value::as_i64)).unwrap_or(0);
            visit.release(share, charged);
            return Reply::Whole(json_response(502, &json!({"error": format!("the seller did not open the WebSocket (HTTP {status})")})));
        }
        let headers: Vec<(String, String)> = head.get("headers").and_then(Value::as_array).into_iter().flatten()
            .filter_map(|h| Some((h.get(0)?.as_str()?.to_string(), h.get(1)?.as_str()?.to_string())))
            .filter(|(k, _)| k.to_ascii_lowercase().starts_with("sec-websocket-"))
            .chain(std::iter::once(("Upgrade".to_string(), "websocket".to_string())))
            .collect();
        Reply::Upgrade(xbt_svc::http::Upgraded {
            headers,
            run: Box::new(move |client, early| {
                join_socket(client, early, src, first);
                let charged = done.recv_timeout(Duration::from_secs(60)).ok().and_then(Result::ok).and_then(|v| v.get("charged_sats").and_then(Value::as_i64)).unwrap_or(0);
                visit.release(share, charged);
            }),
        })
    }

    /// Ask the signer to pay for one request and stream its answer: the head line and the first
    /// bytes, or `Err` with the signer's answer when it ended before any byte came (a refusal).
    fn start(&self, mut params: Value) -> Result<Started, Value> {
        let name = format!("ls-{}", random_hex());
        let path = self.cfg.stream_dir.join(&name);
        let listener = listen_stream(&path).map_err(|e| json!({"error": format!("stream socket: {e}")}))?;
        let _ = listener.set_nonblocking(true);
        params["stream_to"] = name.into();
        params["stream_head"] = true.into();
        let (tx, done) = mpsc::channel::<Result<Value, String>>();
        let signer = self.cfg.signer.clone();
        std::thread::spawn(move || {
            let _ = tx.send(xbt_wallet_mcp::wallet::signer_call(&signer, LONGEST, "xbt402_pay", &params));
        });
        let started = Instant::now();
        let src = loop {
            match listener.accept() {
                Ok((s, _)) => break s,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    let _ = std::fs::remove_file(&path);
                    return Err(json!({"error": format!("stream socket: {e}")}));
                }
            }
            if let Ok(d) = done.try_recv() {
                let _ = std::fs::remove_file(&path);
                return Err(d.unwrap_or_else(|e| json!({"error": e})));
            }
            if started.elapsed() > FIRST_BYTE {
                let _ = std::fs::remove_file(&path);
                return Err(json!({"error": "the seller sent nothing within 60 s"}));
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let _ = std::fs::remove_file(&path);
        let _ = src.set_nonblocking(false);
        let _ = src.set_read_timeout(Some(FIRST_BYTE));
        let mut r = BufReader::new(src);
        let mut line = String::new();
        let ok = (&mut r).take(HEAD_LINE * 16).read_line(&mut line).is_ok() && line.ends_with('\n');
        let head: Value = if ok { serde_json::from_str(&line).unwrap_or(Value::Null) } else { Value::Null };
        if head.get("status").is_none() {
            return Err(json!({"error": "the signer sent no head for the answer"}));
        }
        if let Some(why) = head.get("error").and_then(Value::as_str) {
            return Err(json!({"error": why}));
        }
        let first = r.buffer().to_vec();
        let src = r.into_inner();
        let _ = src.set_read_timeout(None);
        Ok(Started { head, first, src, done })
    }
}

struct Started {
    head: Value,
    first: Vec<u8>,
    src: UnixStream,
    done: mpsc::Receiver<Result<Value, String>>,
}

/// When an answer has been handed on (or its reader has gone): the stream is closed, so the signer
/// stops paying, then what the signer charged is counted against the visit, and the turn given up.
struct Settle {
    visit: Arc<Visit>,
    turn: bool,
    src: Option<UnixStream>,
    done: Option<mpsc::Receiver<Result<Value, String>>>,
}

impl Drop for Settle {
    fn drop(&mut self) {
        drop(self.src.take());
        let charged = self.done.take().and_then(|d| d.recv_timeout(Duration::from_secs(60)).ok()).and_then(Result::ok)
            .and_then(|v| v.get("charged_sats").and_then(Value::as_i64)).unwrap_or(0);
        self.visit.settle(charged, self.turn);
    }
}

/// A client's upgraded connection joined to the signer's stream socket, both ways, until either
/// side ends; what each sent before the join goes first.
fn join_socket(client: std::net::TcpStream, early: Vec<u8>, signer: UnixStream, first: Vec<u8>) {
    use std::io::Write as _;
    let (Ok(mut c2), Ok(mut s2)) = (client.try_clone(), signer.try_clone()) else { return };
    let (mut c1, mut s1) = (client, signer);
    std::thread::scope(|scope| {
        scope.spawn(move || {
            if s2.write_all(&early).is_ok() {
                let _ = io::copy(&mut c1, &mut s2);
            }
            let _ = s2.shutdown(std::net::Shutdown::Both);
            let _ = c1.shutdown(std::net::Shutdown::Both);
        });
        if c2.write_all(&first).is_ok() {
            let _ = io::copy(&mut s1, &mut c2);
        }
        let _ = c2.shutdown(std::net::Shutdown::Both);
        let _ = s1.shutdown(std::net::Shutdown::Both);
    });
}

/// The connector's own answer, marked so the app port tells it from the seller's.
fn json_response(status: u16, v: &Value) -> Response {
    let mut r = crate::json_response(status, v);
    r.headers.push(("X-LS-Refusal".into(), "1".into()));
    r
}

/// A call the signer refused, or could not make, before any byte came.
fn refusal(v: &Value) -> Response {
    let reason = v.get("reason").or(v.get("error")).and_then(Value::as_str).unwrap_or("the call ended with no answer");
    let rule = v.get("rule").and_then(Value::as_str).unwrap_or("");
    json_response(if rule.is_empty() { 502 } else { 402 }, &json!({"error": reason, "rule": rule}))
}
