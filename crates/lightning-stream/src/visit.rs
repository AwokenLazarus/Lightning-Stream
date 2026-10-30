//! Visits: a seller's own web page, used inside the app, paid for as it loads under a limit the
//! owner set for the visit (docs/SELLER-APPS.md).
//!
//! `POST /visits` `{"base": "<seller URL ending in />", "limit_sats": N}` → `{"visit": id}`.
//! `GET /visits/<id>`: what the visit has spent, its limit, and whether it has ended.
//! `POST /visits/<id>/stop`: end it; its next request is refused.
//! `<any method> /v/<id>/<path>`: one request of the page, sent to `base` + `path` and paid.
//!
//! **The limit, exactly.** A page asks for many things at once. Each request of a visit holds a share
//! of what is left of the limit while it runs (at most [`ANSWER_SHARE`], a WebSocket
//! [`SOCKET_SHARE`]), and is sent with its share as the most its answer may charge: the seller is
//! told that figure and stops the answer there, and the signer buys tickets for it within it,
//! before its head or as its body arrives. The shares held at once never add up to more than the
//! limit, so answers running side by side cannot together spend past it; when one ends, only what
//! it cost stays spent; where the signer has not said what it cost (an answer that never started),
//! all of the share stays spent until it does (for good, where it says nothing within
//! [`SETTLE_WAIT`]), and where the signer could not be reached at all, none of it. A request that finds no share free waits for one; one that needs more than a
//! share runs alone once the others have ended or stopped (an open WebSocket, or an answer whose cost
//! the signer has yet to say, holds no answer it must wait for), and no new share is handed out
//! while it waits. A range is asked for in
//! parts of at most [`RANGE_CHUNK`], as a player asks for its next part, so that no answer needs
//! more than its share.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::sync::atomic::{AtomicBool, Ordering};
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
/// How long a request waits for a share.
const TURN_WAIT: Duration = Duration::from_secs(120);
/// How long a request whose answer has stopped waits for the signer to say what it cost, past which
/// all of its share stays spent ([`Visit::settle`]): the longest the signer may wait for a seller's
/// next byte (its `tickets.read_timeout_s`, at most an hour) before it ends a call whose answer is
/// gone, and twice [`FIRST_BYTE`] for its last receipt and its reply. The share is counted apart
/// while it waits, so nothing else waits for it; only the visit's budget is held.
const SETTLE_WAIT: Duration = Duration::from_secs(3600 + 2 * FIRST_BYTE.as_secs());
/// The most of a visit's limit one WebSocket holds while it is open: counted as spent until it
/// ends, then only what it cost, with room for a ticket beside it as for [`ANSWER_SHARE`].
const SOCKET_SHARE: i64 = 1_000;
/// The most of a visit's limit one request holds while it runs for its answer, a part of a range
/// ([`RANGE_CHUNK`]) at the prices sellers ask; once a refusal has named what one of the seller's
/// tickets books, each share also has room for one to be bought.
const ANSWER_SHARE: i64 = 1_000;
/// The longest part of a range a request asks for: `bytes=N-` and longer ranges become
/// `bytes=N-(N+RANGE_CHUNK-1)`, and the page's player asks for the next part as it plays.
const RANGE_CHUNK: u64 = 4 << 20;

/// A `Range` with its length bounded to `chunk`: `bytes=N-` and `bytes=N-M` longer than `chunk`
/// become `bytes=N-(N+chunk-1)`. One that is not a single range from a start is kept as it is.
fn bounded_range(r: &str, chunk: u64) -> String {
    let parts = r.strip_prefix("bytes=").and_then(|s| s.split_once('-'))
        .and_then(|(a, b)| Some((a.parse::<u64>().ok()?, if b.is_empty() { None } else { Some(b.parse::<u64>().ok()?) })));
    match parts {
        Some((a, b)) if b.is_none_or(|b| b >= a && b - a >= chunk) => format!("bytes={a}-{}", a.saturating_add(chunk - 1)),
        _ => r.to_string(),
    }
}

/// The WebSocket's own request headers, passed to the seller beside [`PASSED`].
const SOCKET_HEADERS: [&str; 4] = ["sec-websocket-key", "sec-websocket-version", "sec-websocket-protocol", "sec-websocket-extensions"];

/// Request headers of a page that go to the seller. The seller's gateway passes on only those its
/// route names; the signer refuses the wallet's own and the hop-by-hop ones.
const PASSED: [&str; 13] = ["accept", "accept-language", "content-type", "if-modified-since", "if-none-match", "if-range", "authorization", "cookie",
                            "x-emby-authorization", "x-mediabrowser-token", "x-requested-with", "x-csrf-token", "x-api-key"];

#[derive(Default)]
struct State {
    /// What the visit has spent, the shares of the requests running now in it whole.
    spent: i64,
    /// The shares of the requests running now: part of `spent` until each ends.
    held: i64,
    /// The part of `held` that open WebSockets hold: they end when the page does, so a request
    /// waiting to run alone does not wait for them.
    sockets: i64,
    /// The part of `held` of requests that have stopped and wait for the signer's word on what they
    /// cost ([`Visit::settle`]): they hold no answer open, so a request waiting to run alone does not
    /// wait for them either, and what is left of the limit beside them is its.
    settling: i64,
    /// What one of the seller's tickets books, fee included, as a refusal named it: each share has
    /// room for one beside its own part, so that a request can buy the ticket it needs.
    ticket: i64,
    ended: Option<String>,
    calls: u64,
    last: Option<Instant>,
    /// Requests waiting to run alone ([`Visit::reserve_alone`]): no new share is handed out while
    /// one waits, so that the running ones can end and it gets its turn.
    alone: u32,
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

    /// Hold up to `most` of what is left of the limit for one request, and room for a ticket once
    /// the seller's price of one is known, waiting for a running one to
    /// give its share back where none is free. `Err`: the visit has ended, its limit is spent (with
    /// nothing running that could give some back), or the wait was too long.
    fn reserve(&self, most: i64) -> Result<i64, String> {
        self.reserve_as(most, false)
    }

    fn reserve_as(&self, most: i64, alone: bool) -> Result<i64, String> {
        let mut s = self.lock();
        let until = Instant::now() + TURN_WAIT;
        loop {
            if let Some(e) = &s.ended {
                return Err(e.clone());
            }
            // a request waiting to run alone goes first: no share is handed out past it
            if !alone && s.alone > 0 {
                let now = Instant::now();
                if now >= until {
                    return Err("The page asked for too much at once: try again.".into());
                }
                s = self.turn.wait_timeout(s, until - now).unwrap_or_else(|p| p.into_inner()).0;
                continue;
            }
            let share = (self.limit - s.spent).min(most.saturating_add(s.ticket));
            if share >= 1 {
                s.spent += share;
                s.held += share;
                return Ok(share);
            }
            if s.held == 0 {
                s.ended = Some("This visit's spending limit is reached.".into());
                return Err(s.ended.clone().unwrap_or_default());
            }
            let now = Instant::now();
            if now >= until {
                return Err("The page asked for too much at once: try again.".into());
            }
            s = self.turn.wait_timeout(s, until - now).unwrap_or_else(|p| p.into_inner()).0;
        }
    }

    /// Hold up to `most` of what is left once no other request holds a share: what a request whose
    /// share was too small for a ticket waits for, the most it can then have. `Err` as for
    /// [`Visit::reserve`].
    fn reserve_alone(&self, most: i64) -> Result<i64, String> {
        let mut s = self.lock();
        s.alone += 1;
        let until = Instant::now() + TURN_WAIT;
        let mut timed_out = false;
        while s.held > s.sockets + s.settling && s.ended.is_none() {
            let now = Instant::now();
            if now >= until {
                timed_out = true;
                break;
            }
            s = self.turn.wait_timeout(s, until - now).unwrap_or_else(|p| p.into_inner()).0;
        }
        drop(s);
        let got = if timed_out { Err("The page asked for too much at once: try again.".into()) } else { self.reserve_as(most, true) };
        self.lock().alone -= 1;
        self.turn.notify_all();
        got
    }

    /// A request that held `share` was refused because a ticket did not fit in it: where nothing
    /// else is running and no more than that share is left, nothing more can be bought in this
    /// visit, and it ends. `true`: ended.
    fn spent_out(&self, share: i64) -> bool {
        let mut s = self.lock();
        if s.held == 0 && self.limit - s.spent <= share {
            s.ended.get_or_insert_with(|| "This visit's spending limit is reached.".into());
            return true;
        }
        false
    }

    /// A request that held `share` was refused, its call's reply `v`: what it was charged stays
    /// spent, and what a ticket of the seller's books, where the reply names it, is kept.
    fn refused(self: &Arc<Self>, share: i64, f: Failed) {
        let Failed { v, done, unknown } = f;
        if let Some(t) = v.get("ticket_booking_sats").and_then(Value::as_i64) {
            let mut s = self.lock();
            s.ticket = s.ticket.max(t);
        }
        if let Some(c) = v.get("charged_sats").and_then(Value::as_i64) {
            return self.release(share, c);
        }
        match done {
            // the signer is still at the call, and may still book tickets for it: the share stays spent until it says
            // what it charged (nothing said: all of it)
            Some(done) => {
                let visit = self.clone();
                std::thread::spawn(move || visit.settle(share, Some(done), false));
            }
            // the signer's answer never came (the call to it failed or timed out): what it charged is not known, and
            // all of the share stays spent
            None if unknown => self.release(share, share),
            None => self.release(share, 0),
        }
    }

    /// A share held by a WebSocket from `open` until it ends ([`State::sockets`]).
    fn socket(&self, share: i64, open: bool) {
        let mut s = self.lock();
        s.sockets += if open { share } else { -share };
        drop(s);
        self.turn.notify_all();
    }

    /// A request that held `share` has stopped (a WebSocket's, `socket`: and closed): what the signer
    /// says it charged (`done`), within [`SETTLE_WAIT`], stays spent, all of the share where it says
    /// nothing. Its share is counted apart while it waits ([`State::settling`]).
    fn settle(&self, share: i64, done: Option<mpsc::Receiver<Result<Value, String>>>, socket: bool) {
        let mut s = self.lock();
        s.settling += share;
        if socket {
            s.sockets -= share;
        }
        drop(s);
        self.turn.notify_all();
        let charged = done.and_then(|d| d.recv_timeout(SETTLE_WAIT).ok()).and_then(Result::ok)
            .and_then(|v| v.get("charged_sats").and_then(Value::as_i64)).unwrap_or(share);
        self.lock().settling -= share;
        self.release(share, charged);
    }

    /// A request that held `share` has ended, having cost `charged`: only that stays spent.
    fn release(&self, share: i64, charged: i64) {
        let mut s = self.lock();
        s.spent = s.spent - share + charged.clamp(0, share);
        s.held -= share;
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

    /// One request of a page, paid for within a share of the visit's limit.
    fn visit_call(&self, visit: Arc<Visit>, path: &str, req: &Request) -> Reply {
        let t0 = Instant::now();
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
        // a range in parts, each paid for within one share
        let range = req.header("Range").map(str::trim).filter(|r| one_range(r)).map(|r| bounded_range(r, RANGE_CHUNK));
        let method = req.method.to_ascii_uppercase();
        let body = if req.body.is_empty() { None } else {
            use base64::Engine as _;
            Some(base64::engine::general_purpose::STANDARD.encode(&req.body))
        };
        let call = |max_sats: i64| -> Result<Started, Failed> {
            let mut params = json!({"url": url, "method": method, "max_sats": max_sats, "task": self.cfg.task, "headers": headers, "head_headers": true});
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
        // a share of what is left: the most this answer may charge, tickets bought for it included
        let share = match visit.reserve(ANSWER_SHARE) {
            Ok(n) => n,
            Err(e) => return Reply::Whole(json_response(402, &json!({"error": e, "rule": "visit"}))),
        };
        let max_sats = |f: &Failed| f.v.get("rule").and_then(Value::as_str) == Some("max_sats");
        let (started, share) = match call(share) {
            Ok(s) => (s, share),
            Err(f) if max_sats(&f) => {
                // a ticket did not fit in the share: the refusal named what one books, and the shares from here have room
                // for one. Asked again with such a share; where that is still too small, with all that is left once the
                // others have ended
                visit.refused(share, f);
                if visit.spent_out(share) {
                    return Reply::Whole(json_response(402, &json!({"error": "This visit's spending limit is reached.", "rule": "visit"})));
                }
                let again = match visit.reserve(ANSWER_SHARE) {
                    Ok(n) => n,
                    Err(e) => return Reply::Whole(json_response(402, &json!({"error": e, "rule": "visit"}))),
                };
                match call(again) {
                    Ok(s) => (s, again),
                    Err(f) if max_sats(&f) => {
                        visit.refused(again, f);
                        let share = match visit.reserve_alone(i64::MAX) {
                            Ok(n) => n,
                            Err(e) => return Reply::Whole(json_response(402, &json!({"error": e, "rule": "visit"}))),
                        };
                        match call(share) {
                            Ok(s) => (s, share),
                            Err(f) => {
                                let v = f.v.clone();
                                let out = max_sats(&f);
                                visit.refused(share, f);
                                if out && visit.spent_out(share) {
                                    return Reply::Whole(json_response(402, &json!({"error": "This visit's spending limit is reached.", "rule": "visit"})));
                                }
                                return Reply::Whole(refusal(&v));
                            }
                        }
                    }
                    Err(f) => {
                        let v = f.v.clone();
                        visit.refused(again, f);
                        return Reply::Whole(refusal(&v));
                    }
                }
            }
            Err(f) => {
                let v = f.v.clone();
                visit.refused(share, f);
                return Reply::Whole(refusal(&v));
            }
        };
        let Started { head, first, src, done } = started;
        let status = head.get("status").and_then(Value::as_u64).and_then(|s| u16::try_from(s).ok()).unwrap_or(502);
        if std::env::var_os("XBT_TRACE_WIRE").is_some() {
            let p: String = path.split('?').next().unwrap_or("/").chars().take(60).collect();
            eprintln!("visit: {} {p} {status} {} ms", req.method, t0.elapsed().as_millis());
        }
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
        let mut settle = Settle { visit, share, src: Some(src), done: Some(done) };
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
        let share = match visit.reserve(SOCKET_SHARE) {
            Ok(n) => n,
            Err(e) => return Reply::Whole(json_response(402, &json!({"error": e, "rule": "visit"}))),
        };
        visit.socket(share, true);
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
            Err(f) => {
                let v = f.v.clone();
                visit.socket(share, false);
                visit.refused(share, f);
                return Reply::Whole(refusal(&v));
            }
        };
        let status = head.get("status").and_then(Value::as_u64).unwrap_or(502);
        if status != 101 {
            drop(src);
            // nothing said of what it charged: all of the share stays spent
            visit.settle(share, Some(done), true);
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
                visit.settle(share, Some(done), true);
            }),
        })
    }

    /// Ask the signer to pay for one request and stream its answer: the head line and the first
    /// bytes, or `Err` with the signer's answer when it ended before any byte came (a refusal).
    fn start(&self, mut params: Value) -> Result<Started, Failed> {
        let name = format!("ls-{}", random_hex());
        let path = self.cfg.stream_dir.join(&name);
        let listener = listen_stream(&path).map_err(|e| Failed { v: json!({"error": format!("stream socket: {e}")}), done: None, unknown: false })?;
        let _ = listener.set_nonblocking(true);
        params["stream_to"] = name.into();
        params["stream_head"] = true.into();
        let (tx, done) = mpsc::channel::<Result<Value, String>>();
        let signer = self.cfg.signer.clone();
        // the signer could not be reached: nothing was sent, and nothing charged
        let unsent = Arc::new(AtomicBool::new(false));
        let u = unsent.clone();
        std::thread::spawn(move || {
            let r = xbt_wallet_mcp::wallet::signer_call_sent(&signer, LONGEST, "xbt402_pay", &params).map_err(|(sent, e)| {
                u.store(!sent, Ordering::SeqCst);
                e
            });
            let _ = tx.send(r);
        });
        let started = Instant::now();
        let src = loop {
            match listener.accept() {
                Ok((s, _)) => break s,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    let _ = std::fs::remove_file(&path);
                    return Err(Failed { v: json!({"error": format!("stream socket: {e}")}), done: Some(done), unknown: false });
                }
            }
            if let Ok(d) = done.try_recv() {
                let _ = std::fs::remove_file(&path);
                let unknown = d.is_err() && !unsent.load(Ordering::SeqCst);
                return Err(Failed { v: d.unwrap_or_else(|e| json!({"error": e})), done: None, unknown });
            }
            if started.elapsed() > FIRST_BYTE {
                let _ = std::fs::remove_file(&path);
                return Err(Failed { v: json!({"error": "the seller sent nothing within 60 s"}), done: Some(done), unknown: false });
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
            return Err(Failed { v: json!({"error": "the signer sent no head for the answer"}), done: Some(done), unknown: false });
        }
        if let Some(why) = head.get("error").and_then(Value::as_str) {
            return Err(Failed { v: json!({"error": why}), done: Some(done), unknown: false });
        }
        let first = r.buffer().to_vec();
        let src = r.into_inner();
        let _ = src.set_read_timeout(None);
        Ok(Started { head, first, src, done })
    }
}

/// A call that ended before any byte of its answer came: the signer's answer, or why there is none;
/// and the signer's final reply still to come, where the call may still be going.
struct Failed {
    v: Value,
    done: Option<mpsc::Receiver<Result<Value, String>>>,
    /// The signer's answer never came: the call to it failed or timed out, so what it charged is not
    /// known.
    unknown: bool,
}

struct Started {
    head: Value,
    first: Vec<u8>,
    src: UnixStream,
    done: mpsc::Receiver<Result<Value, String>>,
}

/// When an answer has been handed on (or its reader has gone): the stream is closed, so the signer
/// stops paying, then what the signer charged stays spent and the rest of the share goes back.
struct Settle {
    visit: Arc<Visit>,
    share: i64,
    src: Option<UnixStream>,
    done: Option<mpsc::Receiver<Result<Value, String>>>,
}

impl Drop for Settle {
    fn drop(&mut self) {
        drop(self.src.take());
        // the signer's count of what left the wallet for this answer; nothing known is the whole share, kept spent
        self.visit.settle(self.share, self.done.take(), false);
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
    // the page only sees a status; the owner's log says why (no URL, no header, nothing of the buyer's)
    eprintln!("lightning-stream: a page's request was refused: {}{reason}", if rule.is_empty() { String::new() } else { format!("{rule}: ") });
    // the seller's service is full: nothing was charged, and the page may try again
    if rule == "seller_busy" {
        let retry = v.pointer("/busy/retryAfter").and_then(Value::as_u64).unwrap_or(30).clamp(1, 3600);
        let mut r = json_response(503, &json!({"error": reason, "rule": rule}));
        r.headers.push(("Retry-After".into(), retry.to_string()));
        return r;
    }
    json_response(if rule.is_empty() { 502 } else { 402 }, &json!({"error": reason, "rule": rule}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn visit(limit: i64) -> Arc<Visit> {
        Arc::new(Visit { base: String::new(), limit, state: Mutex::new(State::default()), turn: Condvar::new() })
    }

    /// A page's WebSocket holds its share as long as the page is open: a request waiting to run
    /// alone does not wait for it, and the requests behind it are not held up for it.
    #[test]
    fn a_request_that_runs_alone_does_not_wait_for_an_open_websocket() {
        let v = visit(100_000);
        let ws = v.reserve(SOCKET_SHARE).unwrap();
        v.socket(ws, true);
        let page = v.reserve(ANSWER_SHARE).unwrap();
        let t = Instant::now();
        std::thread::scope(|s| {
            let alone = s.spawn(|| v.reserve_alone(i64::MAX));
            std::thread::sleep(Duration::from_millis(200));
            // the page's request ends; the socket stays open
            v.release(page, 10);
            let got = alone.join().unwrap().unwrap();
            assert_eq!(got, 100_000 - ws - 10);
        });
        assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
        // and once it has its share, the next requests get theirs as before
        assert!(v.lock().alone == 0);
    }

    /// An answer that has stopped and waits for the signer to say what it cost holds no answer open:
    /// a request waiting to run alone goes on beside it, with what is left of the limit past its
    /// share, and the share is settled when the signer says (all of it, where it says nothing).
    ///
    /// FAILS before: the request waiting to run alone waited for the signer's word, up to its
    /// [`TURN_WAIT`], and the page froze.
    #[test]
    fn a_request_that_runs_alone_does_not_wait_for_an_answer_being_settled() {
        let v = visit(100_000);
        let page = v.reserve(ANSWER_SHARE).unwrap();
        let (tx, done) = mpsc::channel::<Result<Value, String>>();
        std::thread::scope(|s| {
            let settling = s.spawn(|| v.settle(page, Some(done), false));
            std::thread::sleep(Duration::from_millis(100));
            let t = Instant::now();
            let got = v.reserve_alone(i64::MAX).unwrap();
            assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
            assert_eq!(got, 100_000 - page);
            v.release(got, 0);
            tx.send(Ok(json!({"charged_sats": 12}))).unwrap();
            settling.join().unwrap();
        });
        let s = v.lock();
        assert_eq!((s.spent, s.held, s.settling), (12, 0, 0));
    }

    /// A call whose signer answer never came (the call to the signer failed or timed out) may have
    /// been charged: all of its share stays spent.
    ///
    /// FAILS before: it was taken for a refusal that charged nothing, and the share went back.
    #[test]
    fn a_call_the_signer_never_answered_keeps_its_share_spent() {
        let v = visit(10_000);
        let share = v.reserve(ANSWER_SHARE).unwrap();
        v.refused(share, Failed { v: json!({"error": "the signer did not answer"}), done: None, unknown: true });
        let s = v.lock();
        assert_eq!((s.spent, s.held), (share, 0));
        drop(s);
        // and one the signer refused before anything was sent gives it back
        let other = v.reserve(ANSWER_SHARE).unwrap();
        v.refused(other, Failed { v: json!({"rule": "max_sats"}), done: None, unknown: false });
        assert_eq!(v.lock().spent, share);
    }

    /// A call that never reached the signer (its socket could not be reached) sent nothing and was
    /// charged nothing: its share goes back.
    ///
    /// FAILS before: any failed call to the signer kept all of its share spent.
    #[test]
    fn a_call_that_never_reached_the_signer_gives_its_share_back() {
        let dir = tempfile::tempdir().unwrap();
        let c = Connector::new(crate::Config { signer: dir.path().join("no-signer.sock"), stream_dir: dir.path().to_path_buf(), task: "t".into(), max_sats: 10 });
        let Err(f) = c.start(json!({"url": "https://example.invalid/"})) else { panic!("the call went") };
        assert!(!f.unknown, "{}", f.v);
        let v = visit(10_000);
        let share = v.reserve(ANSWER_SHARE).unwrap();
        v.refused(share, f);
        assert_eq!(v.lock().spent, 0);
    }
}
