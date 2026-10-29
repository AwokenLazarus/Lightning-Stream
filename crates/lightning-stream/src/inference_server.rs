//! The AI endpoint: an OpenAI-compatible address on the owner's network that sends each request to
//! one of the sellers the owner allowed, paid by the token through the wallet's signer.
//!
//! `GET /v1/models`: the models the allowed sellers offer ([`crate::inference::Catalogue`]).
//! `POST /v1/chat/completions`, `POST /v1/completions`, `POST /v1/embeddings`: sent to a seller.
//!
//! Every request carries `Authorization: Bearer sk-stream-…`, an AI key from the owner's credential
//! store ([`crate::credentials`]), each with its own limit. The router orders the sellers that offer
//! the model ([`crate::inference::Router::order`]); the request goes to the first, through the
//! signer's `xbt402_pay` with the body streamed to a socket of ours, and moves to the next only when
//! the first failed before any byte of its answer. What a call cost is the seller's receipt
//! (`price_msat` in the signer's answer), booked against the key when the answer has ended.
//!
//! The sellers come from a file the app writes (`sellers`): for each, its name, its AI route (the
//! seller's address of the route, ending in `/`), its prices and its cap on output. Their model
//! lists are asked of them through the signer with nothing to spend (a token-priced route answers
//! `/v1/models` free), and kept for [`CATALOGUE_TTL`].
//!
//! Not for web pages: the endpoint sends no CORS headers, so a page in a browser cannot read its
//! answers, and a request carrying a page's `Origin` or `Sec-Fetch-Site: cross-site` is refused.

use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt_svc::http::{BodyWriter, Handler, Reply, Request, Response, Streamed};

use crate::credentials::{self, Kind, Store};
use crate::inference::{error_body, refusal_answer, request_bounds, Catalogue, Health, Outcome, Prefs, Router};

/// How long the catalogue of models is kept before the sellers are asked again.
pub const CATALOGUE_TTL: Duration = Duration::from_secs(300);

/// The largest request body accepted.
pub const MAX_BODY: usize = 4 << 20;

/// The longest one answer is followed.
const LONGEST: Duration = Duration::from_secs(3600);

/// The longest head line the signer writes before the body.
const HEAD_LINE: u64 = 4096;

/// `max_tokens` when a request names none, for the bound of what it may cost.
const DEFAULT_MAX_TOKENS: u64 = 1024;

#[derive(Clone)]
pub struct Config {
    /// The signer's socket.
    pub signer: PathBuf,
    /// The directory the signer streams bodies into (`B2_STREAM_DIR`).
    pub stream_dir: PathBuf,
    /// The owner's task the calls are paid under.
    pub task: String,
    /// The most one call may spend, tickets included, in sat.
    pub max_sats: i64,
    /// The credential store (AI keys and local links).
    pub credentials: PathBuf,
    /// The sellers the app offers for AI and the owner's pins and blocks, written by the app (JSON:
    /// `{"sellers": [{"name", "route", "prices", "max_output"}], "pinned": [names], "blocked": [names]}`).
    pub sellers: PathBuf,
    /// The sellers' health record (JSON, written by this server; the app only reads it).
    pub state: PathBuf,
    /// How long a seller has for the first byte of its answer before the next is tried.
    pub first_byte: Duration,
    /// Host names a request may name (DNS rebinding): empty admits any.
    pub allowed_hosts: Vec<String>,
}

struct Inner {
    store: Store,
    router: Router,
    fetched: Option<Instant>,
    /// A fetch of the catalogue is running in the background.
    fetching: bool,
}

pub struct AiServer {
    cfg: Arc<Config>,
    inner: Arc<Mutex<Inner>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn json_response(status: u16, v: &Value) -> Response {
    Response::new(status, vec![("Content-Type".into(), "application/json".into()), ("Cache-Control".into(), "no-store".into())], v.to_string().into_bytes())
}

fn random_hex() -> String {
    let mut b = [0u8; 12];
    getrandom::getrandom(&mut b).expect("the system's random source");
    hex::encode(b)
}

fn listen_stream(path: &Path) -> io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    let l = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(l)
}

/// The router's state as kept in its file.
fn state_json(r: &Router) -> Value {
    let health: serde_json::Map<String, Value> = r.health.iter().map(|(k, h)| (k.clone(), json!({
        "ttft_ms": h.ttft_ms, "fails_in_a_row": h.fails_in_a_row, "cooled_at": h.cooled_at, "ok": h.ok, "failed": h.failed}))).collect();
    json!({"version": 1, "health": health})
}

fn state_from(v: &Value, r: &mut Router) {
    for (k, h) in v.get("health").and_then(Value::as_object).into_iter().flatten() {
        let n = |f: &str| h.get(f).and_then(Value::as_u64).unwrap_or(0);
        r.health.insert(k.clone(), Health {
            ttft_ms: h.get("ttft_ms").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_u64).collect(),
            fails_in_a_row: u32::try_from(n("fails_in_a_row")).unwrap_or(0),
            cooled_at: h.get("cooled_at").and_then(Value::as_u64),
            ok: n("ok"),
            failed: n("failed"),
        });
    }
}

fn write_atomic(path: &Path, v: &Value) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(serde_json::to_string_pretty(v)?.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// A call the signer has begun: the seller's head as the signer read it, the first bytes of the
/// body, the rest of it, and the signer's account of the call when it has ended.
struct Begun {
    status: u16,
    content_type: Option<String>,
    first: Vec<u8>,
    rest: BufReader<UnixStream>,
    done: mpsc::Receiver<Result<Value, String>>,
    ttft: Duration,
}

/// How a call failed before any byte of its answer.
struct Failed {
    /// Said to the client when no seller is left.
    status: u16,
    message: String,
    /// The seller refused the request itself (a 4xx other than payment): no other seller is tried,
    /// since the request would fare no better there.
    final_answer: Option<(u16, Vec<u8>, Option<String>)>,
}

/// Has the signer pay for one call and stream its body to a socket of ours; waits for the head
/// and the first byte of the body, at most `first_byte`.
fn begin(cfg: &Config, method: &str, url: &str, body: &[u8], max_sats: i64, first_byte: Duration) -> Result<Begun, Failed> {
    let fail = |status: u16, message: String| Failed { status, message, final_answer: None };
    let name = format!("ai-{}", random_hex());
    let path = cfg.stream_dir.join(&name);
    let listener = listen_stream(&path).map_err(|e| fail(500, format!("stream socket: {e}")))?;
    let _ = listener.set_nonblocking(true);
    let (tx, rx) = mpsc::channel::<Result<Value, String>>();
    let mut params = json!({"url": url, "method": method, "max_sats": max_sats, "task": cfg.task, "stream_to": name, "stream_head": true});
    if !body.is_empty() {
        params["body"] = Value::String(String::from_utf8_lossy(body).into_owned());
    }
    let signer = cfg.signer.clone();
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
                return Err(fail(500, format!("stream socket: {e}")));
            }
        }
        if let Ok(done) = rx.try_recv() {
            let _ = std::fs::remove_file(&path);
            let why = match done {
                Ok(v) => v.get("reason").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| "the wallet would not pay this seller".into()),
                Err(e) => e,
            };
            return Err(fail(502, why));
        }
        if started.elapsed() > first_byte {
            let _ = std::fs::remove_file(&path);
            return Err(fail(504, format!("the seller sent nothing within {} s", first_byte.as_secs())));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let _ = std::fs::remove_file(&path);
    let _ = src.set_nonblocking(false);
    let left = first_byte.saturating_sub(started.elapsed()).max(Duration::from_millis(100));
    let _ = src.set_read_timeout(Some(left));
    let mut src = BufReader::new(src);
    let mut line = String::new();
    let head: Value = match (&mut src).take(HEAD_LINE).read_line(&mut line) {
        Ok(_) if line.ends_with('\n') => serde_json::from_str(&line).unwrap_or(Value::Null),
        _ => Value::Null,
    };
    let Some(status) = head.get("status").and_then(Value::as_u64).and_then(|s| u16::try_from(s).ok()).filter(|s| (200..600).contains(s)) else {
        return Err(fail(502, "the wallet sent no head for the seller's answer".into()));
    };
    let content_type = head.get("content_type").and_then(Value::as_str).filter(|t| t.len() <= 128 && t.bytes().all(|b| b.is_ascii_graphic() || b == b' ')).map(str::to_string);
    let mut first = vec![0u8; 16 << 10];
    let n = loop {
        match src.read(&mut first) {
            Ok(n) => break n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(fail(504, format!("the seller sent no answer within {} s", first_byte.as_secs()))),
        }
    };
    first.truncate(n);
    let _ = src.get_ref().set_read_timeout(Some(Duration::from_secs(600)));
    // a seller's own failure: another may serve the request; a refusal of the request itself may not
    if status >= 500 || status == 402 || status == 429 || status == 408 {
        return Err(fail(502, format!("the seller answered {status}")));
    }
    if status >= 400 {
        let mut whole = first;
        let _ = src.take(1 << 20).read_to_end(&mut whole);
        return Err(Failed { status, message: String::new(), final_answer: Some((status, whole, content_type)) });
    }
    if n == 0 {
        return Err(fail(502, "the seller's answer was empty".into()));
    }
    Ok(Begun { status, content_type, first, rest: src, done: rx, ttft: started.elapsed() })
}

/// The sellers' model lists, asked of them through the signer with nothing to spend, and the
/// owner's pins and blocks, from the sellers file the app writes.
fn fetch_catalogue(cfg: &Config) -> (Catalogue, Prefs) {
    let sellers: Value = std::fs::read(&cfg.sellers).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
    let mut cat = Catalogue::default();
    for s in sellers.get("sellers").and_then(Value::as_array).into_iter().flatten() {
        let (Some(name), Some(route)) = (s.get("name").and_then(Value::as_str), s.get("route").and_then(Value::as_str)) else { continue };
        if !route.ends_with('/') {
            continue;
        }
        let max_output = s.get("max_output").and_then(Value::as_u64).unwrap_or(0);
        let prices = s.get("prices").cloned().unwrap_or(Value::Null);
        let Ok(mut b) = begin(cfg, "GET", &format!("{route}v1/models"), &[], 0, cfg.first_byte) else { continue };
        let mut body = std::mem::take(&mut b.first);
        let _ = (&mut b.rest).take(1 << 20).read_to_end(&mut body);
        if let Ok(models) = serde_json::from_slice::<Value>(&body) {
            cat.add_seller(name, route, &prices, max_output, &models);
        }
    }
    let strs = |k: &str| sellers.get(k).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect::<Vec<_>>();
    (cat, Prefs { pinned: strs("pinned"), blocked: strs("blocked") })
}

impl AiServer {
    pub fn new(cfg: Config) -> io::Result<Self> {
        let store = Store::open(&cfg.credentials)?;
        let mut router = Router::default();
        match std::fs::read(&cfg.state) {
            Ok(b) => state_from(&serde_json::from_slice(&b).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?, &mut router),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let me = Self { cfg: Arc::new(cfg), inner: Arc::new(Mutex::new(Inner { store, router, fetched: None, fetching: false })) };
        // the sellers' model lists are asked for at once, in the background: the first request does not wait for all of them
        me.fetch_in_background();
        Ok(me)
    }

    /// Starts a fetch of the catalogue in the background, unless one is running.
    fn fetch_in_background(&self) {
        {
            let mut g = lock(&self.inner);
            if g.fetching {
                return;
            }
            g.fetching = true;
        }
        let (cfg, inner) = (Arc::clone(&self.cfg), Arc::clone(&self.inner));
        std::thread::spawn(move || {
            let (cat, prefs) = fetch_catalogue(&cfg);
            let mut g = lock(&inner);
            g.router.catalogue = cat;
            g.router.prefs = prefs;
            g.fetched = Some(Instant::now());
            g.fetching = false;
        });
    }

    /// The catalogue for a request: a stale one is refreshed in the background and used meanwhile;
    /// before the first fetch has ended, the request waits for it (at most `first_byte`).
    fn refresh(&self) {
        let fetched = lock(&self.inner).fetched;
        match fetched {
            Some(t) if t.elapsed() <= CATALOGUE_TTL => {}
            Some(_) => self.fetch_in_background(),
            None => {
                self.fetch_in_background();
                let end = Instant::now() + self.cfg.first_byte.max(Duration::from_secs(2));
                while lock(&self.inner).fetched.is_none() && Instant::now() < end {
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }

    /// Re-reads the credential store (the app makes and revokes keys in it).
    fn reload_store(&self, inner: &mut Inner) {
        if let Ok(s) = Store::open(&self.cfg.credentials) {
            inner.store = s;
        }
    }

    fn save_state(&self, inner: &Inner) {
        let _ = write_atomic(&self.cfg.state, &state_json(&inner.router));
    }

    fn answer(&self, req: Request) -> Reply {
        let path = req.path().to_string();
        if req.method == "GET" && path == "/health" {
            return Reply::Whole(json_response(200, &json!({"ok": true})));
        }
        if let Some(why) = refused_origin(&req, &self.cfg.allowed_hosts) {
            return Reply::Whole(json_response(403, &error_body("refused", "invalid_request_error", why)));
        }
        let secret = req.header("Authorization").and_then(|h| h.strip_prefix("Bearer ")).map(str::trim).unwrap_or("").to_string();
        let today = credentials::day_of(credentials::now());
        let key_id = {
            let mut inner = lock(&self.inner);
            self.reload_store(&mut inner);
            match inner.store.check(Kind::AiKey, &secret) {
                Ok(e) => e.id.clone(),
                Err(r) => {
                    let (s, b) = refusal_answer(&r);
                    return Reply::Whole(json_response(s, &b));
                }
            }
        };
        match (req.method.as_str(), path.as_str()) {
            ("GET", "/v1/models") => {
                self.refresh();
                Reply::Whole(json_response(200, &lock(&self.inner).router.catalogue.models_json()))
            }
            ("POST", "/v1/chat/completions" | "/v1/completions" | "/v1/embeddings") => self.complete(&path, &req.body, &key_id, today),
            _ => Reply::Whole(json_response(404, &error_body("not_found", "invalid_request_error", "This endpoint serves /v1/models, /v1/chat/completions, /v1/completions and /v1/embeddings."))),
        }
    }

    fn complete(&self, path: &str, raw: &[u8], key_id: &str, today: u64) -> Reply {
        let mut body: Value = match serde_json::from_slice(raw) {
            Ok(v @ Value::Object(_)) => v,
            _ => return Reply::Whole(json_response(400, &error_body("invalid_json", "invalid_request_error", "The request body is not a JSON object."))),
        };
        let Some(model) = body.get("model").and_then(Value::as_str).map(str::to_string) else {
            return Reply::Whole(json_response(400, &error_body("model_missing", "invalid_request_error", "The request names no model.")));
        };
        self.refresh();
        let (input, max_tokens) = request_bounds(&body, raw.len(), DEFAULT_MAX_TOKENS);
        let now = credentials::now();
        let offers: Vec<_> = lock(&self.inner).router.order(&model, input, max_tokens, now).into_iter().cloned().collect();
        if offers.is_empty() {
            return Reply::Whole(json_response(404, &error_body("model_not_found", "invalid_request_error",
                &format!("No seller you allowed offers the model {model}, or every one is resting after failures."))));
        }
        let mut last: Option<Failed> = None;
        for offer in offers {
            let bound = offer.bound_msat(input, max_tokens);
            if let Err(r) = lock(&self.inner).store.may_spend(key_id, bound, today) {
                let (s, b) = refusal_answer(&r);
                return Reply::Whole(json_response(s, &b));
            }
            body["model"] = Value::String(offer.model.clone());
            let sent = body.to_string().into_bytes();
            let url = format!("{}{}", offer.route, path.trim_start_matches('/'));
            match begin(&self.cfg, "POST", &url, &sent, self.cfg.max_sats, self.cfg.first_byte) {
                Ok(b) => return self.relay(b, offer.seller.clone(), key_id.to_string(), today),
                Err(f) => {
                    let mut inner = lock(&self.inner);
                    if let Some((status, whole, ct)) = f.final_answer {
                        // the seller refused the request itself: said to the client as the seller said it
                        let headers = vec![("Content-Type".into(), ct.unwrap_or_else(|| "application/json".into())), ("Cache-Control".into(), "no-store".into())];
                        return Reply::Whole(Response::new(status, headers, whole));
                    }
                    inner.router.record(&offer.seller, Outcome::FailedBeforeAnswer, now);
                    self.save_state(&inner);
                    last = Some(f);
                    if !Router::may_fall_back(Outcome::FailedBeforeAnswer) {
                        break;
                    }
                }
            }
        }
        let f = last.unwrap_or(Failed { status: 502, message: "no seller answered".into(), final_answer: None });
        Reply::Whole(json_response(f.status, &error_body("upstream_failed", "api_error", &format!("No seller could answer: {}", f.message))))
    }

    /// Hands an answer on as it arrives, then books what it cost against the key and the seller's
    /// health. A seller that stops mid-answer is not left for another: the client gets what arrived
    /// (paid exactly) and, for a stream of events, an event saying the answer was cut.
    fn relay(&self, b: Begun, seller: String, key_id: String, today: u64) -> Reply {
        let inner = Arc::clone(&self.inner);
        let state = self.cfg.state.clone();
        let credentials = self.cfg.credentials.clone();
        let sse = b.content_type.as_deref().is_some_and(|t| t.starts_with("text/event-stream"));
        let headers = vec![
            ("Content-Type".to_string(), b.content_type.clone().unwrap_or_else(|| "application/json".into())),
            ("Cache-Control".into(), "no-store".into()),
        ];
        let Begun { status, first, mut rest, done, ttft, .. } = b;
        Reply::Stream(Streamed {
            status,
            headers,
            length: None,
            body: Box::new(move |out: &mut dyn BodyWriter| {
                let mut wrote = out.send(&first);
                let mut buf = vec![0u8; 32 << 10];
                while wrote.is_ok() {
                    match rest.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => wrote = out.send(&buf[..n]),
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
                // a client gone: dropping the socket tells the signer to stop paying
                drop(rest);
                let account = done.recv_timeout(Duration::from_secs(10)).ok().and_then(Result::ok).unwrap_or(Value::Null);
                let price_msat = account.get("price_msat").and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))).unwrap_or(0);
                let complete = account.get("complete").and_then(Value::as_bool).unwrap_or(false);
                let now = credentials::now();
                {
                    let mut g = lock(&inner);
                    if let Ok(s) = Store::open(&credentials) {
                        g.store = s;
                    }
                    g.store.add_spend(&key_id, price_msat, today);
                    g.store.pause_if_over(&key_id, today);
                    let _ = g.store.save();
                    let outcome = if complete { Outcome::Answered { ttft_ms: u64::try_from(ttft.as_millis()).unwrap_or(u64::MAX) } } else { Outcome::CutMidAnswer };
                    g.router.record(&seller, outcome, now);
                    let _ = write_atomic(&state, &state_json(&g.router));
                }
                if !complete && sse && wrote.is_ok() {
                    let ev = json!({"error": {"message": format!("The seller {seller} stopped mid-answer. What arrived was paid for; nothing more."), "type": "api_error", "code": "answer_cut"}});
                    let _ = out.send(format!("data: {ev}\n\n").as_bytes());
                }
                wrote.map(|_| ())
            }),
        })
    }
}

/// A request from a web page, or naming a host it may not: refused, with the reason.
pub fn refused_origin(req: &Request, allowed_hosts: &[String]) -> Option<&'static str> {
    if req.header("Origin").is_some() || req.header("Sec-Fetch-Site").is_some_and(|s| !s.eq_ignore_ascii_case("none") && !s.eq_ignore_ascii_case("same-origin")) {
        return Some("this endpoint is for programs on your network, not for web pages");
    }
    if !allowed_hosts.is_empty() {
        let host = req.header("Host").map(|h| h.rsplit_once(':').map_or(h, |(n, p)| if p.bytes().all(|b| b.is_ascii_digit()) { n } else { h })).unwrap_or("");
        if !allowed_hosts.iter().any(|a| a.eq_ignore_ascii_case(host)) {
            return Some("this endpoint does not answer to that host name");
        }
    }
    None
}

impl Handler for AiServer {
    fn body_limit(&self, method: &str, _t: &str) -> usize {
        if method == "POST" { MAX_BODY } else { 0 }
    }

    fn handle(&self, req: Request) -> Response {
        match self.answer(req) {
            Reply::Whole(r) => r,
            Reply::Stream(_) => json_response(500, &json!({"error": "a streamed answer where a whole one was asked for"})),
        }
    }

    fn reply(&self, req: Request) -> Reply {
        self.answer(req)
    }
}

/// Serve the AI endpoint on `listener`.
pub fn serve(cfg: Config, listener: std::net::TcpListener) -> io::Result<xbt_svc::http::Running> {
    xbt_svc::http::serve(Arc::new(AiServer::new(cfg)?), listener, 16)
}
