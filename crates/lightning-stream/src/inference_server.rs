//! The AI endpoint: an OpenAI-compatible address on the owner's network that sends each request to
//! one of the sellers the owner allowed, paid by the token through the wallet's signer.
//!
//! `GET /v1/models`: the models the allowed sellers offer ([`crate::inference::Catalogue`]).
//! `POST /v1/chat/completions`, `POST /v1/completions`, `POST /v1/embeddings`: sent to a seller.
//!
//! Every request carries `Authorization: Bearer sk-stream-…`, an AI key from the owner's credential
//! store ([`crate::credentials`]), each with its own limit. The router orders the sellers that offer
//! the model ([`crate::inference::Router::order`]); the request goes to the first, through the
//! signer's `xbt402_pay` with the body streamed to a socket of ours, and moves to the next only
//! while the request cannot have reached the first: the wallet refused it, or says it never left, or
//! the seller answered with a failure of its own. One answer is never paid to two sellers. What a
//! call cost is the seller's receipt (`price_msat` in the signer's answer), booked against the key
//! when the answer has ended, or when the wallet says, for a call the client got no answer from.
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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt_svc::http::{BodyWriter, Handler, Reply, Request, Response, Streamed};

use crate::credentials::{self, Kind, Store};
use crate::inference::{error_body, refusal_answer, request_bounds, Catalogue, Health, Outcome, Prefs, Router};

/// How long the catalogue of models is kept before the sellers are asked again.
pub const CATALOGUE_TTL: Duration = Duration::from_secs(300);

/// How soon the sellers are asked again after a fetch left one of them without models (its link
/// not open yet, the wallet still starting): doubled after each such fetch, up to [`CATALOGUE_TTL`].
pub const CATALOGUE_RETRY: Duration = Duration::from_secs(2);

/// The largest request body accepted.
pub const MAX_BODY: usize = 4 << 20;

/// The longest one answer is followed.
const LONGEST: Duration = Duration::from_secs(3600);

/// The longest head line the signer writes before the body.
const HEAD_LINE: u64 = 4096;

/// How long a paid call waits for the wallet to have paid for it, before the seller's own time
/// (`first_byte`) begins ([`Config::pay_wait`], this by default): longer than the wallet's own wait
/// for a ticket's payment (the node's `lightning.timeout_s`, 60 s by default, and 5 s more) after
/// the lock. A buyer on a slow route pays a first ticket in tens of seconds; that is not the seller
/// being slow.
pub const PAY_WAIT: Duration = Duration::from_secs(90);

/// How long an answer handed on waits, once it has ended, for the wallet's account of it
/// ([`Config::account_wait`], this by default): longer than the signer's own wait for the seller's
/// last receipt after the socket closes (10 s, and a second more).
pub const ACCOUNT_WAIT: Duration = Duration::from_secs(12);

/// The shortest `LS_AI_PAY_WAIT_S` taken: a wait shorter than a payment over an ordinary route
/// gives every paid call up before it is paid.
pub const PAY_WAIT_FLOOR: Duration = Duration::from_secs(30);

/// The most calls that wait on a payment at once ([`serve`] answers on 16 threads): one more is
/// answered 503 at once, so that a slow route never holds every thread and the endpoint's health
/// and list of models still answer.
pub const MAX_PAYING: usize = 8;

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
    /// How long a seller has for the first byte of its answer before the next is tried, from when
    /// its call is paid for.
    pub first_byte: Duration,
    /// How long a paid call waits for the wallet to pay for it ([`PAY_WAIT`]; `LS_AI_PAY_WAIT_S`).
    /// Past it, the next seller is tried only once the wallet has said the request never left.
    pub pay_wait: Duration,
    /// How long an answer handed on waits, once it has ended, for the wallet's account of it
    /// ([`ACCOUNT_WAIT`]); past it, what it cost is booked when the account comes.
    pub account_wait: Duration,
    /// Host names a request may name (DNS rebinding): empty admits any.
    pub allowed_hosts: Vec<String>,
}

struct Inner {
    store: Store,
    router: Router,
    fetched: Option<Instant>,
    /// How long the catalogue fetched last is kept: [`CATALOGUE_TTL`], or less while a seller is missing from it.
    keep: Duration,
    /// Fetches ended so far: a request that waits for one watches it change.
    fetches: u64,
    /// A fetch of the catalogue is running in the background.
    fetching: bool,
    /// When the sellers file was last read for the owner's pins and blocks.
    sellers_changed: Option<std::time::SystemTime>,
}

pub struct AiServer {
    cfg: Arc<Config>,
    inner: Arc<Mutex<Inner>>,
    /// Calls waiting on a payment now ([`MAX_PAYING`]).
    paying: AtomicUsize,
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
    credentials::write_file(path, serde_json::to_string_pretty(v)?.as_bytes(), false)
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

/// The wallet's account of a call given up on, or the way to it while the call goes on: what the
/// seller charged is booked to the key from it.
enum Account {
    Said(Value),
    Pending(mpsc::Receiver<Result<Value, String>>),
    Unknown,
}

impl Account {
    fn said(&self) -> Option<&Value> {
        match self {
            Account::Said(v) => Some(v),
            _ => None,
        }
    }
}

/// The seller's refusal of the request itself, said to the client as it said it: its status, its
/// body and its content type.
type SellersRefusal = (u16, Vec<u8>, Option<String>);

/// How a call failed before any byte of its answer.
struct Failed {
    /// Said to the client when no seller is left.
    status: u16,
    message: String,
    /// The seller refused the request itself (a 4xx other than payment): no other seller is tried,
    /// since the request would fare no better there.
    final_answer: Option<Box<SellersRefusal>>,
    /// The request may have reached this seller, and be served or charged by it: no other seller
    /// is tried, so that one answer is never paid to two.
    paid: bool,
    /// The wallet was still paying for the call when it was given up: the buyer's route was slow,
    /// not the seller.
    paying: bool,
    account: Account,
}

/// Where a paid call was when its socket said nothing more in time.
#[derive(Clone, Copy, PartialEq)]
enum Stage {
    /// The socket opened, no line yet.
    Opened,
    /// The wallet said the request is paid for and leaving.
    Paid,
    /// The wallet pays again after it said so (the seller's balance ran short).
    Paying,
}

/// What the seller's receipt charged the call, in msat, where the wallet's account says.
fn price_of(v: &Value) -> Option<u64> {
    v.get("price_msat").and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
}

/// What a call cost, in msat, by the wallet's account of it: the seller's receipt; where there is
/// none and the request may have left, what the wallet paid for the call (`charged_sats`, the most
/// the seller could have drawn on); nothing where the request never left.
fn cost_msat(v: &Value) -> u64 {
    if let Some(p) = price_of(v) {
        return p;
    }
    if v.get("request_sent").and_then(Value::as_bool) == Some(false) {
        return 0;
    }
    v.get("charged_sats").and_then(Value::as_u64).unwrap_or(0).saturating_mul(1000)
}

/// A seller's answer that is a failure of its own: another seller may serve the request.
fn sellers_failure(status: u16) -> bool {
    status >= 500 || matches!(status, 402 | 408 | 429)
}

/// Whether another seller may be tried after a call, by the wallet's account of it: only where the
/// request never left. The wallet says so on the ticket rail (`request_sent`); where it does not, a
/// status, a charge or a call it allowed means the request reached the seller. A status without a
/// receipt (a proxy's 524, say) is no failure of the seller's: the request may be served behind
/// it. A failure the seller signed is decided from its head line, before this. No account, or
/// anything else, may be an answer being served and paid for: never a second seller.
fn another_may_serve(account: Option<&Value>) -> bool {
    let Some(v) = account else { return false };
    if let Some(sent) = v.get("request_sent").and_then(Value::as_bool) {
        return !sent;
    }
    let sent = v.get("status").is_some_and(|s| !s.is_null())
        || v.get("charged_sats").and_then(Value::as_i64).unwrap_or(0) > 0
        || price_of(v).unwrap_or(0) > 0
        || v.get("verdict").and_then(Value::as_str) == Some("allow");
    !sent
}

/// The wallet's account of a call, waited for at most `wait`; past it, the way to it is kept.
fn hear(rx: mpsc::Receiver<Result<Value, String>>, wait: Duration) -> Account {
    match rx.recv_timeout(wait) {
        Ok(Ok(v)) => Account::Said(v),
        Err(mpsc::RecvTimeoutError::Timeout) => Account::Pending(rx),
        _ => Account::Unknown,
    }
}

/// A paid call whose socket said nothing more in time, by where the wallet was.
fn given_up(cfg: &Config, stage: Stage, rx: mpsc::Receiver<Result<Value, String>>, first_byte: Duration) -> Failed {
    if stage == Stage::Paid {
        // told the request is paid for and leaving: it may be served, and charged, whatever comes next
        return Failed { status: 504, message: format!("the seller sent nothing within {} s of being paid", first_byte.as_secs()), final_answer: None,
                        paid: true, paying: false, account: Account::Pending(rx) };
    }
    // paying (again), or no line at all: the wallet says whether the request left. Its socket is closed, so it sends
    // nothing more on this call
    let account = hear(rx, cfg.pay_wait);
    let paying = stage == Stage::Paying;
    let message = if paying { format!("the wallet's payment of the seller took more than {} s", cfg.pay_wait.as_secs()) }
                  else { format!("the seller sent nothing within {} s", first_byte.as_secs()) };
    Failed { status: 504, message, final_answer: None, paid: !another_may_serve(account.said()), paying, account }
}

/// Has the signer pay for one call and stream its body to a socket of ours; waits for the head
/// and the first byte of the body, at most `first_byte` from when the call is paid for (the
/// signer's `paid` line; a rail that sends no such line, from when the socket opens; a call that
/// pays nothing, from the start), and for a payment at most `pay_wait` (the clock stops on the
/// signer's `paying` line). A call is given up for another seller only while the request cannot
/// have reached this one ([`Failed::paid`]).
/// `ceiling`: the seller's listed prices, the most the wallet pays it (none for a free read).
fn begin(cfg: &Config, method: &str, url: &str, body: &[u8], max_sats: i64, first_byte: Duration, ceiling: Option<&Value>) -> Result<Begun, Failed> {
    let fail = |status: u16, message: String| Failed { status, message, final_answer: None, paid: false, paying: false, account: Account::Unknown };
    let name = format!("ai-{}", random_hex());
    let path = cfg.stream_dir.join(&name);
    let listener = listen_stream(&path).map_err(|e| fail(500, format!("stream socket: {e}")))?;
    let _ = listener.set_nonblocking(true);
    let (tx, rx) = mpsc::channel::<Result<Value, String>>();
    let mut params = json!({"url": url, "method": method, "max_sats": max_sats, "task": cfg.task, "stream_to": name, "stream_head": true});
    if !body.is_empty() {
        params["body"] = Value::String(String::from_utf8_lossy(body).into_owned());
    }
    if let Some(c) = ceiling {
        params["price_ceiling"] = c.clone();
    }
    // told when it is paid for: the seller's time is counted from there
    let paid_call = max_sats > 0;
    if paid_call {
        params["stream_paid"] = true.into();
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
                drop(listener);
                if !paid_call {
                    return Err(fail(500, format!("stream socket: {e}")));
                }
                // the wallet may be paying, or sending: another seller only once it says the request never left
                let account = hear(rx, cfg.pay_wait);
                return Err(Failed { status: 500, message: format!("stream socket: {e}"), final_answer: None, paid: !another_may_serve(account.said()),
                                    paying: false, account });
            }
        }
        if let Ok(done) = rx.try_recv() {
            let _ = std::fs::remove_file(&path);
            // over before its socket opened: refused, or ended at the seller; the wallet says which
            return Err(match done {
                Ok(v) => Failed {
                    status: 502,
                    message: v.get("reason").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| "the wallet would not pay this seller".into()),
                    final_answer: None,
                    paid: paid_call && !another_may_serve(Some(&v)),
                    paying: false,
                    account: Account::Said(v),
                },
                Err(e) => Failed { paid: paid_call, ..fail(502, e) },
            });
        }
        // a paid call: the socket opens once it is paid for, which a slow route makes long
        if started.elapsed() > if paid_call { cfg.pay_wait } else { first_byte } {
            let _ = std::fs::remove_file(&path);
            // a connection not taken is refused from here: the wallet sends nothing on it
            drop(listener);
            if !paid_call {
                return Err(fail(504, format!("the seller sent nothing within {} s", first_byte.as_secs())));
            }
            // the wallet is still at the payment: another seller is tried only once it has said the request never left
            let account = hear(rx, cfg.pay_wait);
            return Err(Failed { status: 504, message: format!("the wallet's payment of the seller took more than {} s", cfg.pay_wait.as_secs()),
                                final_answer: None, paid: !another_may_serve(account.said()), paying: true, account });
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let _ = std::fs::remove_file(&path);
    drop(listener);
    let _ = src.set_nonblocking(false);
    let mut src = BufReader::new(src);
    // the seller's time: from the wallet's `paid` line; for a rail that sends none, from when the socket opened (it
    // opens once the seller has answered); for a call that pays nothing, from its start. A `paying` line stops the
    // clock while the wallet pays again, up to the wait for a payment
    let mut since = if paid_call { Instant::now() } else { started };
    let mut until = since + first_byte;
    let mut stage = Stage::Opened;
    let head: Value = loop {
        let _ = src.get_ref().set_read_timeout(Some(until.saturating_duration_since(Instant::now()).max(Duration::from_millis(100))));
        let mut line = String::new();
        match (&mut src).take(HEAD_LINE).read_line(&mut line) {
            Ok(_) if line.ends_with('\n') => {
                let v: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
                if v.get("paid").and_then(Value::as_bool) == Some(true) {
                    since = Instant::now();
                    (until, stage) = (since + first_byte, Stage::Paid);
                    continue;
                }
                if v.get("paying").and_then(Value::as_bool) == Some(true) {
                    (until, stage) = (Instant::now() + cfg.pay_wait, Stage::Paying);
                    continue;
                }
                break v;
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                // given up: the socket closes, so the wallet sends nothing more on this call
                drop(src);
                if !paid_call {
                    return Err(fail(504, format!("the seller sent nothing within {} s", first_byte.as_secs())));
                }
                return Err(given_up(cfg, stage, rx, first_byte));
            }
            // the socket closed with no head: the wallet ended the call (a refusal, a seller fault), and says why
            _ => break Value::Null,
        }
    };
    let Some(status) = head.get("status").and_then(Value::as_u64).and_then(|s| u16::try_from(s).ok()).filter(|s| (200..600).contains(s)) else {
        drop(src);
        let account = hear(rx, if paid_call { cfg.pay_wait } else { Duration::from_secs(5) });
        let why = account.said().and_then(|v| v.get("reason")).and_then(Value::as_str).map(str::to_string);
        return Err(Failed { status: 502, message: why.unwrap_or_else(|| "the wallet sent no head for the seller's answer".into()), final_answer: None,
                            paid: paid_call && !another_may_serve(account.said()), paying: false, account });
    };
    // a signed head that is an answer (not a failure of the seller's): the request is the seller's, and no other is tried
    let answering = paid_call && !sellers_failure(status) && status < 400;
    let content_type = head.get("content_type").and_then(Value::as_str).filter(|t| t.len() <= 128 && t.bytes().all(|b| b.is_ascii_graphic() || b == b' ')).map(str::to_string);
    let _ = src.get_ref().set_read_timeout(Some(until.saturating_duration_since(Instant::now()).max(Duration::from_millis(100))));
    let mut first = vec![0u8; 16 << 10];
    let n = loop {
        match src.read(&mut first) {
            Ok(n) => break n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                drop(src);
                return Err(Failed { paid: answering, account: Account::Pending(rx), ..fail(504, format!("the seller sent no answer within {} s", first_byte.as_secs())) });
            }
        }
    };
    first.truncate(n);
    let _ = src.get_ref().set_read_timeout(Some(Duration::from_secs(600)));
    // a seller's own failure: another may serve the request; a refusal of the request itself may not. What either
    // cost is booked once the wallet says
    if sellers_failure(status) {
        drop(src);
        return Err(Failed { account: Account::Pending(rx), ..fail(502, format!("the seller answered {status}")) });
    }
    if status >= 400 {
        let mut whole = first;
        let _ = (&mut src).take(1 << 20).read_to_end(&mut whole);
        drop(src);
        return Err(Failed { final_answer: Some(Box::new((status, whole, content_type))), account: Account::Pending(rx), ..fail(status, String::new()) });
    }
    if n == 0 {
        drop(src);
        return Err(Failed { paid: answering, account: Account::Pending(rx), ..fail(502, "the seller's answer was empty".into()) });
    }
    // the seller's own speed, its payment apart
    Ok(Begun { status, content_type, first, rest: src, done: rx, ttft: since.elapsed() })
}

/// The sellers' model lists, asked of them through the signer with nothing to spend (or, for a
/// seller that will not answer that free, the `models` its entry in the sellers file names), and
/// the owner's pins and blocks, from the sellers file the app writes; and whether a seller of the
/// file was left without models.
fn fetch_catalogue(cfg: &Config) -> (Catalogue, Prefs, bool) {
    let sellers: Value = std::fs::read(&cfg.sellers).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
    let mut cat = Catalogue::default();
    let mut missing = false;
    for s in sellers.get("sellers").and_then(Value::as_array).into_iter().flatten() {
        let (Some(name), Some(route)) = (s.get("name").and_then(Value::as_str), s.get("route").and_then(Value::as_str)) else { continue };
        if !route.ends_with('/') {
            continue;
        }
        let max_output = s.get("max_output").and_then(Value::as_u64).unwrap_or(0);
        let prices = s.get("prices").cloned().unwrap_or(Value::Null);
        // the seller's own list, asked for with nothing to spend; a seller that asks to be paid even for
        // its list (a gateway that serves nothing outside a paid session) is listed with the models the
        // sellers file names for it, if any
        let asked = begin(cfg, "GET", &format!("{route}v1/models"), &[], 0, cfg.first_byte, None).ok().and_then(|mut b| {
            let mut body = std::mem::take(&mut b.first);
            let _ = (&mut b.rest).take(1 << 20).read_to_end(&mut body);
            serde_json::from_slice::<Value>(&body).ok().filter(|m| m.get("data").is_some_and(Value::is_array))
        });
        let named = s.get("models").and_then(Value::as_array).map(|ids| json!({"data": ids.iter().filter_map(Value::as_str).map(|id| json!({"id": id})).collect::<Vec<_>>()}));
        match asked.or(named) {
            Some(models) => cat.add_seller(name, route, &prices, max_output, &models),
            None => missing = true,
        }
    }
    let strs = |k: &str| sellers.get(k).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect::<Vec<_>>();
    (cat, Prefs { pinned: strs("pinned"), blocked: strs("blocked") }, missing)
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
        let me = Self { cfg: Arc::new(cfg), inner: Arc::new(Mutex::new(Inner { store, router, fetched: None, keep: CATALOGUE_TTL, fetches: 0, fetching: false, sellers_changed: None })),
                        paying: AtomicUsize::new(0) };
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
            let (cat, prefs, missing) = fetch_catalogue(&cfg);
            let mut g = lock(&inner);
            g.router.catalogue = cat;
            g.router.prefs = prefs;
            g.fetched = Some(Instant::now());
            g.fetches += 1;
            // a seller missing (not reachable yet, as when the app and the wallet start together): asked again
            // soon, then less often; all of them answered: kept the whole while
            g.keep = if !missing { CATALOGUE_TTL } else if g.keep >= CATALOGUE_TTL { CATALOGUE_RETRY } else { (g.keep * 2).min(CATALOGUE_TTL) };
            g.fetching = false;
        });
    }

    /// The catalogue for a request: a stale one is refreshed in the background and used meanwhile;
    /// before the first fetch has ended, while the catalogue is empty, or when the sellers file has
    /// just changed, the request waits for the fetch (at most `first_byte`). The owner's pins and blocks apply at once: they are read again
    /// whenever the sellers file has changed, and the sellers are asked again then too (a seller
    /// just allowed is usable on the next request).
    fn refresh(&self) {
        let changed = std::fs::metadata(&self.cfg.sellers).and_then(|m| m.modified()).ok();
        let mut renew = false;
        if changed.is_some() && changed != lock(&self.inner).sellers_changed {
            let sellers: Value = std::fs::read(&self.cfg.sellers).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
            let strs = |k: &str| sellers.get(k).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect::<Vec<_>>();
            let mut g = lock(&self.inner);
            g.router.prefs = Prefs { pinned: strs("pinned"), blocked: strs("blocked") };
            // the first read is the file the endpoint started with: only a later change asks the sellers again
            renew = g.sellers_changed.is_some();
            g.sellers_changed = changed;
        }
        let (fetched, keep, fetches, empty) = {
            let g = lock(&self.inner);
            (g.fetched, g.keep, g.fetches, g.router.catalogue.offers.is_empty())
        };
        match fetched {
            Some(t) if !renew && t.elapsed() <= keep => {}
            Some(_) if !empty && !renew => self.fetch_in_background(),
            _ => {
                self.fetch_in_background();
                let end = Instant::now() + self.cfg.first_byte.max(Duration::from_secs(2));
                while lock(&self.inner).fetches == fetches && Instant::now() < end {
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
        // a cap on the calls waiting on a payment at once (a fetch of the catalogue included): the endpoint's other
        // requests (its health, its list of models) keep threads to answer on while a slow route holds the rest
        let Some(_slot) = Slot::take(&self.paying, MAX_PAYING) else {
            return Reply::Whole(json_response(503, &error_body("busy", "api_error", "Too many requests are waiting for their payment to go through; try again shortly.")));
        };
        self.refresh();
        let (input, max_tokens) = request_bounds(&body, raw.len(), DEFAULT_MAX_TOKENS);
        let now = credentials::now();
        let offers: Vec<_> = lock(&self.inner).router.order(&model, input, max_tokens, now).into_iter().cloned().collect();
        if offers.is_empty() {
            return Reply::Whole(json_response(404, &error_body("model_not_found", "invalid_request_error",
                &format!("No seller you allowed offers the model {model}, or every one is resting after failures."))));
        }
        let mut last: Option<(u16, String)> = None;
        for offer in offers {
            let bound = offer.bound_msat(input, max_tokens);
            // one lock for both reads (a guard held in an `if let` scrutinee lives through its block)
            let (may, left) = {
                let g = lock(&self.inner);
                (g.store.may_spend(key_id, bound, today), g.store.entries.iter().find(|e| e.id == key_id).map_or(0, |e| e.left_msat(today)))
            };
            if let Err(r) = may {
                let (s, b) = match r {
                    // room left, but not for the most this request may cost
                    crate::credentials::Refusal::Paused { limit_sats } if left > 0 => (402, error_body("limit_reached", "insufficient_quota", &format!(
                        "This request may cost up to {} sats, more than the {} sats this key has left of its limit of {limit_sats} sats. \
                         Ask for fewer max_tokens, or raise the limit on the AI page of Lightning Stream.", bound.div_ceil(1000), left / 1000))),
                    r => refusal_answer(&r),
                };
                return Reply::Whole(json_response(s, &b));
            }
            body["model"] = Value::String(offer.model.clone());
            let sent = body.to_string().into_bytes();
            let url = format!("{}{}", offer.route, path.trim_start_matches('/'));
            // the seller's own listed prices are the most it is paid: a 402 asking more is refused
            match begin(&self.cfg, "POST", &url, &sent, self.cfg.max_sats, self.cfg.first_byte, Some(&offer.ceiling)) {
                Ok(b) => return self.relay(b, offer.seller.clone(), key_id.to_string(), today, bound),
                Err(Failed { status, message, final_answer, paid, paying, account }) => {
                    // whatever the call cost this seller is booked to the key, now or when the wallet says; where it
                    // never says and the request may have reached the seller, the most the request may cost
                    self.book_later(key_id, today, account, paid.then_some(bound));
                    if let Some((status, whole, ct)) = final_answer.map(|b| *b) {
                        // the seller refused the request itself: said to the client as the seller said it
                        let headers = vec![("Content-Type".into(), ct.unwrap_or_else(|| "application/json".into())), ("Cache-Control".into(), "no-store".into())];
                        return Reply::Whole(Response::new(status, headers, whole));
                    }
                    // a payment that outlasted its wait is the buyer's route, not the seller's failure
                    if !paying {
                        let mut inner = lock(&self.inner);
                        inner.router.record(&offer.seller, Outcome::FailedBeforeAnswer, now);
                        self.save_state(&inner);
                    }
                    last = Some((status, message));
                    if paid || !Router::may_fall_back(Outcome::FailedBeforeAnswer) {
                        break;
                    }
                }
            }
        }
        let (status, message) = last.unwrap_or((502, "no seller answered".into()));
        Reply::Whole(json_response(status, &error_body("upstream_failed", "api_error", &format!("No seller could answer: {message}"))))
    }

    /// Books what a call the client got no answer from cost the key, by the wallet's account of it:
    /// at once where it was said, and where the call goes on, once the wallet says (for as long as
    /// one answer is followed). An account never had: `unknown`, where given.
    fn book_later(&self, key_id: &str, today: u64, account: Account, unknown: Option<u64>) {
        let (credentials, inner, key_id) = (self.cfg.credentials.clone(), Arc::clone(&self.inner), key_id.to_string());
        let unknown = unknown.unwrap_or(0);
        match account {
            Account::Said(v) => book(&credentials, &inner, &key_id, today, cost_msat(&v)),
            Account::Pending(rx) => {
                std::thread::spawn(move || {
                    let cost = match rx.recv_timeout(LONGEST) {
                        Ok(Ok(v)) => cost_msat(&v),
                        _ => unknown,
                    };
                    book(&credentials, &inner, &key_id, today, cost);
                });
            }
            Account::Unknown => book(&credentials, &inner, &key_id, today, unknown),
        }
    }

    /// Hands an answer on as it arrives, then books what it cost against the key and the seller's
    /// health. A seller that stops mid-answer is not left for another: the client gets what arrived
    /// (paid exactly) and, for a stream of events, an event saying the answer was cut. The wallet's
    /// account is waited for [`Config::account_wait`] (it may wait that long for the seller's last
    /// receipt); past it, it is booked when it comes, and no cut is said that is not known.
    /// `bound`: the most the request may cost, booked where the wallet never says what it did.
    fn relay(&self, b: Begun, seller: String, key_id: String, today: u64, bound: u64) -> Reply {
        let account_wait = self.cfg.account_wait;
        let settle = Settle { inner: Arc::clone(&self.inner), state: self.cfg.state.clone(), credentials: self.cfg.credentials.clone(), key_id, today,
                              seller: seller.clone(), bound };
        let sse = b.content_type.as_deref().is_some_and(|t| t.starts_with("text/event-stream"));
        let headers = vec![
            ("Content-Type".to_string(), b.content_type.clone().unwrap_or_else(|| "application/json".into())),
            ("Cache-Control".into(), "no-store".into()),
        ];
        let Begun { status, first, mut rest, done, ttft, .. } = b;
        let ttft_ms = u64::try_from(ttft.as_millis()).unwrap_or(u64::MAX);
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
                let complete = match done.recv_timeout(account_wait) {
                    Ok(Ok(account)) => settle.account(&account, ttft_ms),
                    // the wallet still at the seller's last receipt: booked when it says, and no cut said meanwhile
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        std::thread::spawn(move || match done.recv_timeout(LONGEST) {
                            Ok(Ok(account)) => {
                                settle.account(&account, ttft_ms);
                            }
                            _ => settle.unknown(),
                        });
                        true
                    }
                    _ => {
                        settle.unknown();
                        true
                    }
                };
                if !complete && sse && wrote.is_ok() {
                    let ev = json!({"error": {"message": format!("The seller {seller} stopped mid-answer. What arrived was paid for; nothing more."), "type": "api_error", "code": "answer_cut"}});
                    let _ = out.send(format!("data: {ev}\n\n").as_bytes());
                }
                wrote.map(|_| ())
            }),
        })
    }
}

/// What an answer handed on to the client cost, and how its seller did: booked to the key and the
/// seller's health once the wallet says.
struct Settle {
    inner: Arc<Mutex<Inner>>,
    state: PathBuf,
    credentials: PathBuf,
    key_id: String,
    today: u64,
    seller: String,
    /// The most the request may cost: booked where the wallet never says what it did.
    bound: u64,
}

impl Settle {
    /// The wallet's account: what it cost is booked, and the seller's answer recorded whole or cut.
    /// Whether it was whole.
    fn account(&self, account: &Value, ttft_ms: u64) -> bool {
        let complete = account.get("complete").and_then(Value::as_bool).unwrap_or(false);
        book(&self.credentials, &self.inner, &self.key_id, self.today, cost_msat(account));
        let mut g = lock(&self.inner);
        g.router.record(&self.seller, if complete { Outcome::Answered { ttft_ms } } else { Outcome::CutMidAnswer }, credentials::now());
        let _ = write_atomic(&self.state, &state_json(&g.router));
        complete
    }

    /// No account from the wallet: the most the request may cost is booked, and nothing is said of
    /// the seller.
    fn unknown(&self) {
        book(&self.credentials, &self.inner, &self.key_id, self.today, self.bound);
    }
}

/// Books `price_msat` against the key, under the store's lock (so a change the app makes at the
/// same time is kept), and takes the store as booked.
fn book(credentials: &Path, inner: &Mutex<Inner>, key_id: &str, today: u64, price_msat: u64) {
    if price_msat == 0 {
        return;
    }
    let booked = Store::update(credentials, |s| {
        s.add_spend(key_id, price_msat, today);
        s.pause_if_over(key_id, today);
    });
    if booked.is_ok() {
        if let Ok(s) = Store::open(credentials) {
            lock(inner).store = s;
        }
    }
}

/// One of the places for a call waiting on a payment ([`MAX_PAYING`]), given back when dropped.
struct Slot<'a>(&'a AtomicUsize);

impl<'a> Slot<'a> {
    fn take(n: &'a AtomicUsize, most: usize) -> Option<Self> {
        n.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| (v < most).then_some(v + 1)).ok().map(|_| Slot(n))
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
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
            Reply::Stream(_) | Reply::Upgrade(_) => json_response(500, &json!({"error": "a streamed answer where a whole one was asked for"})),
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
