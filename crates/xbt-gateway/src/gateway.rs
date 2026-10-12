//! The gateway itself: the 402, the session endpoints, a paid request from its header to its
//! receipt, and the threads that follow the node (one per unreleased ticket, and a janitor).
//!
//! A paid request, in order; each step names the rule it keeps and who could break it:
//!
//! 1. **One reading of the target** ([`crate::upstream::decoded_path`]): a buyer who spells a priced
//!    path so that the service and the gateway read it differently gets 400, and a path with no
//!    route is 404 and never reaches the service.
//! 2. **Authenticated, in order** ([`Book::authenticate`]): the HMAC binds session, `seq`, secret,
//!    pledged ticket and the request digest; a replay, a request for another target, or anyone
//!    without the session key is refused before any state changes.
//! 3. **Locked, once, outside the margin** ([`Book::present`]), then **settled at once**
//!    ([`Node::settle`]) and credited only when the node said yes. The block height is the node's,
//!    no older than [`crate::config::Times::height_max_age`]; without it no secret is taken.
//! 4. **Paid first** ([`Book::charge`]): the request's price is taken before the service is
//!    asked, and given back when the service gives no answer or an error.
//! 5. **Only what the runner allowed reaches the service** ([`crate::upstream::forwarded`]), no
//!    redirect is followed, and nothing the service says is read for money: a body is charged by
//!    the bytes the gateway itself sent and the seconds it itself counted.
//! 6. **Receipt**: every answer to an authenticated request carries one, signed by the receipt key.
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use secp256k1::SecretKey;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use xbt402::ticket::{self, hex32, Terms, INVOICE_EXPIRY_S};
use xbt402::wire::{
    auth_eq, b64json, body_hash, request_digest_v2, settlement_response, unb64json, X402_VERSION,
};
use xbt402::xbt_primitives::ecdsa;
use xbt_svc::http::{
    AddrKey, BodyWriter, Handler, Limits, Reply, Request, Response, Running, Streamed,
};

use crate::book::{Book, Rec, Refusal};
use crate::config::{Config, Release, Route, SERVICES_PATH};
use crate::node::{Hash, Invoice, InvoiceState, Node, NodeError};
use crate::price::Meter;
use crate::store::{Store, COMPACT_AT};
use crate::upstream::{decoded_path, forwarded, returned, Answer, Upstream};
use crate::Error;

/// A body no larger than this, on a route priced per request only, is read whole so that its
/// receipt can carry its hash. Larger or metered bodies are streamed.
const WHOLE_BODY: u64 = 256 << 10;
/// The most of an error answer's body that is passed on (an error is not charged).
const ERROR_BODY: u64 = 64 << 10;
/// The body of a session endpoint's request.
const SESSION_BODY: usize = 16 << 10;
/// One read of the service's body, and so the most that is charged ahead of a write.
const CHUNK: usize = 16 << 10;
/// Final receipts of streamed responses kept per session, for `status`.
const FINALS_KEPT: usize = 8;

struct State {
    book: Book,
    store: Store,
    finals: HashMap<String, VecDeque<Value>>,
}

#[derive(Default)]
struct Height {
    polled: Option<(u32, Instant)>,
    /// The highest height at which the node accepted a ticket: the chain was at least there.
    floor: u32,
}

/// What a test or an operator reads off a running gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    /// Sessions in all, those that only keep a balance included.
    pub sessions: usize,
    /// Sessions with a ticket locked or a response open.
    pub active_sessions: usize,
    pub held_tickets: usize,
    pub settled: u64,
    /// The longest time from a secret's arrival to the node's yes, in microseconds.
    pub settle_max_us: u64,
    pub height: Option<u32>,
}

pub struct Gateway {
    cfg: Config,
    terms: Terms,
    node: Arc<dyn Node>,
    upstream: Upstream,
    key: SecretKey,
    state: Mutex<State>,
    /// Signalled whenever a session is credited: metered responses out of balance wait on it.
    credited: Condvar,
    height: Mutex<Height>,
    stop: AtomicBool,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
    settled: AtomicU64,
    settle_max_us: AtomicU64,
}

/// Wall-clock seconds.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn lnd_network(chain: &str) -> &str {
    match chain {
        "main" => "mainnet",
        "test" => "testnet",
        other => other,
    }
}

fn json_response(status: u16, body: &Value) -> Response {
    Response::new(
        status,
        vec![
            ("Content-Type".into(), "application/json".into()),
            ("Cache-Control".into(), "no-store".into()),
            ("X-Content-Type-Options".into(), "nosniff".into()),
        ],
        body.to_string().into_bytes(),
    )
}

fn error(status: u16, code: &str, detail: &str) -> Response {
    json_response(status, &json!({"error": code, "detail": detail}))
}

fn addr_name(peer: Option<SocketAddr>) -> String {
    match peer.map(|a| AddrKey::of(a.ip())) {
        Some(AddrKey::V4(a)) => format!("v4:{a}"),
        Some(AddrKey::V6Prefix(p)) => format!("v6:{p:016x}"),
        None => "none".into(),
    }
}

/// `payload` of PAYMENT-SIGNATURE, read strictly.
struct Pay {
    session: String,
    seq: u64,
    secret: Option<[u8; 32]>,
    ticket: Option<Hash>,
    secret_hex: String,
    ticket_hex: String,
    auth: String,
}

/// An authenticated request: its `seq` is used up, and its answer gets a receipt.
struct Authed {
    session: String,
    seq: u64,
    digest: String,
    ticket: Option<Hash>,
}

/// What a streamed body needs to meter itself and sign its last receipt.
struct Metered {
    session: String,
    seq: u64,
    digest: String,
    status: u16,
    route: Route,
    /// Charged before the head: the request's price.
    at_head: u64,
    /// Charged before the head and already in the meter: the first second.
    first_second: u64,
    started: Instant,
}

impl Gateway {
    /// Bring a gateway up on `cfg`: ask the node who and where it is, load the journal, read every
    /// unfinished ticket from the node again, and start the threads. `Err`: nothing was started.
    pub fn start(
        cfg: Config,
        node: Arc<dyn Node>,
        key: SecretKey,
        clock: Box<dyn Fn() -> u64 + Send + Sync>,
    ) -> Result<Arc<Self>, Error> {
        let info = node.info().map_err(|e| Error::Node(e.to_string()))?;
        let want = lnd_network(&cfg.chain);
        if !info.networks.iter().any(|n| n == want) {
            return Err(Error::Start(format!(
                "the node is on {:?}, and the config says chain {} ({want})",
                info.networks, cfg.chain
            )));
        }
        if !info.blake2b {
            return Err(Error::Start(
                "the node does not advertise feature 512: not an XBT Lightning build".into(),
            ));
        }
        let terms = Terms {
            network: cfg.network.clone(),
            pay_to: info.pubkey.clone(),
            ticket_msat: cfg.caps.ticket_msat,
            max_tickets: cfg.caps.max_tickets,
            ticket_blocks: cfg.ticket_blocks,
            receipt_key: hex::encode(ecdsa::pubkey(&key)),
            session: ticket::SESSION_PATH.into(),
        };
        let (mut store, recs) =
            Store::open(&cfg.state_dir).map_err(|e| Error::Journal(e.to_string()))?;
        let mut book = Book::restore(cfg.caps.clone(), &recs, clock())?;
        // what the node says of every ticket the journal left unfinished, before anything is served
        for hash in book.unfinished() {
            let rec = match node
                .lookup(&hash)
                .map_err(|e| Error::Node(format!("on a ticket of the journal: {e}")))?
            {
                Some(inv) => book.node_update(&hash, &inv),
                None => book.node_has_none(&hash),
            };
            drop(rec);
        }
        store
            .compact(&book.snapshot())
            .map_err(|e| Error::Journal(e.to_string()))?;
        let unfinished = book.unfinished();
        let upstream = Upstream::new(&cfg.upstream, cfg.times.upstream_wait);
        let gw = Arc::new(Self {
            terms,
            node,
            upstream,
            key,
            state: Mutex::new(State {
                book,
                store,
                finals: HashMap::new(),
            }),
            credited: Condvar::new(),
            height: Mutex::new(Height {
                polled: info.synced.then(|| (info.height, Instant::now())),
                floor: 0,
            }),
            stop: AtomicBool::new(false),
            clock,
            settled: AtomicU64::new(0),
            settle_max_us: AtomicU64::new(0),
            cfg,
        });
        for hash in unfinished {
            gw.watch(hash)
                .map_err(|e| Error::Start(format!("a watcher thread: {e}")))?;
        }
        let j = gw.clone();
        std::thread::Builder::new()
            .name("gateway-janitor".into())
            .spawn(move || {
                while !j.stop.load(Ordering::SeqCst) {
                    std::thread::sleep(j.cfg.times.tick);
                    j.tick();
                }
            })
            .map_err(|e| Error::Start(format!("the janitor thread: {e}")))?;
        Ok(gw)
    }

    /// Listen on `listener` with the config's limits.
    pub fn serve(self: &Arc<Self>, listener: TcpListener) -> io::Result<Running> {
        let limits = Limits {
            connections: self.cfg.http.connections,
            per_address: self.cfg.http.per_address,
            ..Limits::default()
        };
        xbt_svc::http::serve_with(
            Arc::new(Service(self.clone())),
            listener,
            self.cfg.http.threads,
            limits,
        )
    }

    /// Stop the threads (the listener has its own stop). Tickets stay as they are on the node.
    pub fn stop(&self) {
        let mut st = self.lock();
        let marks = st.book.take_marks();
        self.journal(&mut st, &marks);
        self.sync(&st.store.handle());
        self.stop.store(true, Ordering::SeqCst);
        st.store.close();
        drop(st);
        self.credited.notify_all();
    }

    pub fn terms(&self) -> &Terms {
        &self.terms
    }

    pub fn stats(&self) -> Stats {
        let st = self.lock();
        Stats {
            sessions: st.book.sessions(),
            active_sessions: st.book.active_sessions(),
            held_tickets: st.book.held(),
            settled: self.settled.load(Ordering::SeqCst),
            settle_max_us: self.settle_max_us.load(Ordering::SeqCst),
            height: self.known_height(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Write records into the journal's file (not yet onto the disk: see [`Gateway::sync`]). A
    /// journal that cannot be written is reported and the gateway goes on: what the node holds is
    /// the record of money, and a lock, the one step that needs the journal first, checks this.
    fn journal(&self, st: &mut State, recs: &[Rec]) -> bool {
        if self.stop.load(Ordering::SeqCst) {
            return false;
        }
        let done = st.store.append(recs);
        if let Err(e) = &done {
            eprintln!("xbt-gateway: the journal could not be written: {e}");
        }
        done.is_ok()
    }

    /// Write the counters of every session that changed into the journal's file: after this, a
    /// gateway that is killed comes back with them. (A power cut can still lose what the janitor
    /// had not synced yet: at most one tick.)
    fn flush(&self) {
        let mut st = self.lock();
        let marks = st.book.take_marks();
        self.journal(&mut st, &marks);
    }

    /// Have everything journalled so far on disk. Called without the state lock: a sync takes
    /// milliseconds, and no request waits for one it does not need.
    fn sync(&self, file: &std::fs::File) -> bool {
        let done = file.sync_data();
        if let Err(e) = &done {
            eprintln!("xbt-gateway: the journal could not be synced: {e}");
        }
        done.is_ok()
    }

    // --- the node's side ----------------------------------------------------------------------------

    /// The block height, if the node told it recently enough to vouch for a ticket's margin.
    fn known_height(&self) -> Option<u32> {
        let h = self.height.lock().unwrap_or_else(|p| p.into_inner());
        let (height, at) = h.polled?;
        (at.elapsed() <= self.cfg.times.height_max_age).then_some(height.max(h.floor))
    }

    /// The node's view of one ticket, into the book.
    fn apply(&self, hash: &Hash, inv: &Invoice) {
        if let Some(a) = inv.accept_height {
            let mut h = self.height.lock().unwrap_or_else(|p| p.into_inner());
            h.floor = h.floor.max(a);
        }
        let mut st = self.lock();
        if let Some(rec) = st.book.node_update(hash, inv) {
            let credit = matches!(rec, Rec::Released { .. });
            self.journal(&mut st, &[rec]);
            drop(st);
            if credit {
                self.credited.notify_all();
            }
        }
    }

    /// Follow one ticket on the node until it is finished or no longer in the book.
    fn watch(self: &Arc<Self>, hash: Hash) -> io::Result<()> {
        let gw = self.clone();
        std::thread::Builder::new()
            .name("ticket-watch".into())
            .stack_size(256 << 10)
            .spawn(move || {
                let mut wait = Duration::from_millis(100);
                loop {
                    if gw.stop.load(Ordering::SeqCst) || gw.lock().book.ticket(&hash).is_none() {
                        return;
                    }
                    let stream = gw.node.watch(&hash, &mut |inv| {
                        gw.apply(&hash, &inv);
                        wait = Duration::from_millis(100);
                        !gw.stop.load(Ordering::SeqCst) && gw.lock().book.ticket(&hash).is_some()
                    });
                    match stream {
                        Ok(()) => return,
                        Err(NodeError::Refused(m)) if m.contains("unable to locate invoice") => {
                            let mut st = gw.lock();
                            if let Some(rec) = st.book.node_has_none(&hash) {
                                gw.journal(&mut st, &[rec]);
                            }
                            return;
                        }
                        // the node is away or restarting: the ticket is as it was, and is read again
                        Err(_) => {
                            std::thread::sleep(wait);
                            wait = (wait * 2).min(Duration::from_secs(5));
                        }
                    }
                }
            })?;
        Ok(())
    }

    /// One round of the janitor: the height, what time and blocks ask to be cancelled, the journal.
    pub fn tick(&self) {
        if self.stop.load(Ordering::SeqCst) {
            return;
        }
        match self.node.info() {
            Ok(info) if info.synced => {
                self.height.lock().unwrap_or_else(|p| p.into_inner()).polled =
                    Some((info.height, Instant::now()));
            }
            // not synced, or no answer: the last height ages out by itself
            _ => {}
        }
        let height = self.known_height();
        let sweep = {
            let mut st = self.lock();
            let sweep = st.book.sweep(self.now(), height);
            for r in &sweep.recs {
                if let Rec::Drop { session } = r {
                    st.finals.remove(session);
                }
            }
            self.journal(&mut st, &sweep.recs);
            sweep
        };
        for hash in &sweep.cancel {
            self.cancel_on_node(hash);
        }
        let file = {
            let mut st = self.lock();
            let marks = st.book.take_marks();
            self.journal(&mut st, &marks);
            if st.store.lines() > COMPACT_AT {
                let snapshot = st.book.snapshot();
                if let Err(e) = st.store.compact(&snapshot) {
                    eprintln!("xbt-gateway: the journal could not be rewritten: {e}");
                }
            }
            st.store.handle()
        };
        self.sync(&file);
    }

    /// Cancel a ticket on the node and take it out of the book. True: it is cancelled.
    fn cancel_on_node(&self, hash: &Hash) -> bool {
        match self.node.cancel(hash) {
            Ok(()) => {
                self.apply(
                    hash,
                    &Invoice {
                        state: InvoiceState::Canceled,
                        paid_msat: 0,
                        expiry_height: None,
                        accept_height: None,
                    },
                );
                true
            }
            Err(NodeError::Refused(_)) => {
                // settled meanwhile, or gone: the node's own word decides
                match self.node.lookup(hash) {
                    Ok(Some(inv)) => self.apply(hash, &inv),
                    Ok(None) => {
                        let mut st = self.lock();
                        if let Some(rec) = st.book.node_has_none(hash) {
                            self.journal(&mut st, &[rec]);
                        }
                    }
                    Err(_) => {}
                }
                false
            }
            Err(NodeError::Unreachable(_)) => false,
        }
    }

    /// Steps 2 and 3 of a paid request for one secret: find its ticket, settle it at once, credit it.
    fn take_secret(&self, session: &str, secret: &[u8; 32]) -> Result<Hash, Refusal> {
        let arrived = Instant::now();
        let height = self.known_height();
        let presented = self.lock().book.present(session, secret, height);
        let hash = match presented {
            Ok(hash) => hash,
            Err(Refusal::TicketNotLocked) => {
                // the node's stream has not said this ticket is held. It may be behind: ask once,
                // for a ticket of this session only, and judge the secret again on the answer
                let hash = ticket::ticket_hash(secret);
                let ours = self
                    .lock()
                    .book
                    .ticket(&hash)
                    .is_some_and(|t| t.session == session);
                match if ours {
                    self.node.lookup(&hash)
                } else {
                    Ok(None)
                } {
                    Ok(Some(inv)) => self.apply(&hash, &inv),
                    _ => return Err(Refusal::TicketNotLocked),
                }
                self.lock().book.present(session, secret, height)?
            }
            Err(why) => return Err(why),
        };
        match self.node.settle(secret) {
            Ok(()) => {
                let mut st = self.lock();
                if let Some(rec) = st.book.settled(&hash, None) {
                    self.journal(&mut st, &[rec]);
                }
                drop(st);
                self.credited.notify_all();
                self.settled.fetch_add(1, Ordering::SeqCst);
                self.settle_max_us.fetch_max(
                    u64::try_from(arrived.elapsed().as_micros()).unwrap_or(u64::MAX),
                    Ordering::SeqCst,
                );
                Ok(hash)
            }
            Err(NodeError::Refused(_)) => {
                // not held after all (cancelled by the node since its last report): read it again
                self.lock().book.settle_unanswered(&hash);
                match self.node.lookup(&hash) {
                    Ok(Some(inv)) => self.apply(&hash, &inv),
                    Ok(None) => {
                        let mut st = self.lock();
                        if let Some(rec) = st.book.node_has_none(&hash) {
                            self.journal(&mut st, &[rec]);
                        }
                    }
                    Err(_) => {}
                }
                Err(Refusal::TicketNotLocked)
            }
            Err(NodeError::Unreachable(_)) => {
                // settled or not: the node's next report says, and credits it if it was
                self.lock().book.settle_unanswered(&hash);
                Err(Refusal::HeightUnknown)
            }
        }
    }

    // --- the wire ---------------------------------------------------------------------------------

    fn url(&self, target: &str) -> String {
        format!("{}{target}", self.cfg.public_url)
    }

    /// The x402 `PaymentRequired`, as header and as body.
    fn required(
        &self,
        target: &str,
        route: Option<&Route>,
        code: Option<&str>,
        session: Option<Value>,
    ) -> (Value, String) {
        let mut m = Map::new();
        m.insert("x402Version".into(), X402_VERSION.into());
        if let Some(c) = code {
            m.insert("error".into(), c.into());
        }
        m.insert("resource".into(), json!({"url": self.url(target)}));
        let accepts = route.map(|r| {
            self.terms
                .accepts(r.price.request_msat, r.release.name(), &r.price.terms())
        });
        m.insert(
            "accepts".into(),
            Value::Array(accepts.into_iter().collect()),
        );
        if let Some(s) = session {
            m.insert("session".into(), s);
        }
        let v = Value::Object(m);
        let header = b64json(&v);
        (v, header)
    }

    /// The 402 of an unpaid request: the terms.
    fn unpaid(&self, target: &str, route: &Route) -> Response {
        let (body, header) = self.required(target, Some(route), None, None);
        let mut r = json_response(402, &body);
        r.headers.push(("PAYMENT-REQUIRED".into(), header));
        r
    }

    fn session_view(&self, session: &str) -> Value {
        let st = self.lock();
        match st.book.session(session) {
            Some(s) => {
                json!({"id": session, "nextSeq": s.next_seq, "releasedMsat": s.released_msat.to_string(), "spentMsat": s.spent_msat.to_string(),
                              "balanceMsat": s.balance_msat().to_string(), "tickets": s.live()})
            }
            None => Value::Null,
        }
    }

    /// A signed receipt: the session's totals as they are now, and this request's own numbers.
    fn receipt(
        &self,
        session: &str,
        seq: u64,
        charged: u64,
        digest: &str,
        status: u16,
        body_hash: &str,
    ) -> Option<Value> {
        // a session that was forgotten meanwhile has no totals to sign: no receipt, never zeros
        let (released, spent) = {
            let st = self.lock();
            st.book
                .session(session)
                .map(|s| (s.released_msat, s.spent_msat))?
        };
        let mut r = json!({"scheme": ticket::SCHEME, "session": session, "seq": seq, "releasedMsat": released.to_string(), "spentMsat": spent.to_string(),
                           "charged": charged.to_string(), "req": digest, "status": status, "bodyHash": body_hash});
        r["sig"] = hex::encode(ecdsa::sign(&self.key, &ticket::receipt_message(&r))).into();
        Some(r)
    }

    /// Any answer to an authenticated request: with its receipt.
    fn answered(&self, a: &Authed, mut r: Response, charged: u64) -> Response {
        self.flush();
        let receipt = self.receipt(
            &a.session,
            a.seq,
            charged,
            &a.digest,
            r.status,
            &body_hash(&r.body),
        );
        if let Some(receipt) = receipt {
            let sr = settlement_response(&receipt, &self.cfg.network, "", r.status < 400);
            r.headers.push(("PAYMENT-RESPONSE".into(), b64json(&sr)));
        }
        r
    }

    /// An authenticated request that is not served: the code, the terms again, the session's numbers.
    fn refused(&self, a: &Authed, target: &str, route: Option<&Route>, why: Refusal) -> Response {
        let status = if why == Refusal::HeightUnknown {
            503
        } else {
            402
        };
        let (body, header) = self.required(
            target,
            route,
            Some(why.code()),
            Some(self.session_view(&a.session)),
        );
        let mut r = json_response(status, &body);
        r.headers.push(("PAYMENT-REQUIRED".into(), header));
        self.answered(a, r, 0)
    }

    /// PAYMENT-SIGNATURE, if the request has one. `Err`: it has one that cannot be read.
    fn pay_header(&self, req: &Request) -> Result<Option<Pay>, Response> {
        let mut found = req
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-SIGNATURE"));
        let Some((_, raw)) = found.next() else {
            return Ok(None);
        };
        if found.next().is_some() {
            return Err(error(400, "bad_payment", "more than one PAYMENT-SIGNATURE"));
        }
        let bad = |what: &str| error(400, "bad_payment", what);
        let v = unb64json(raw).map_err(|_| bad("PAYMENT-SIGNATURE is not base64 JSON"))?;
        if v.get("x402Version").and_then(Value::as_u64) != Some(X402_VERSION) {
            return Err(bad("x402Version is not 2"));
        }
        let accepted = v.get("accepted").ok_or_else(|| bad("no accepted entry"))?;
        if accepted.get("scheme").and_then(Value::as_str) != Some(ticket::SCHEME)
            || accepted.get("network").and_then(Value::as_str) != Some(self.cfg.network.as_str())
        {
            return Err(bad("accepted is not this seller's ticket entry"));
        }
        let p = v
            .get("payload")
            .and_then(Value::as_object)
            .ok_or_else(|| bad("no payload"))?;
        let text = |k: &str| match p.get(k) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.as_str())),
            Some(_) => Err(bad("a payload field of the wrong type")),
        };
        let session = text("session")?
            .filter(|s| s.len() == 32 && s.bytes().all(|c| c.is_ascii_hexdigit()))
            .ok_or_else(|| bad("no session"))?
            .to_string();
        let seq = p
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| bad("seq is a whole number"))?;
        let auth = text("auth")?
            .filter(|a| a.len() == 64)
            .ok_or_else(|| bad("no auth"))?
            .to_string();
        let secret_hex = text("secret")?.unwrap_or("").to_string();
        let ticket_hex = text("ticket")?.unwrap_or("").to_string();
        let hex_of = |s: &str, what: &str| {
            if s.is_empty() {
                Ok(None)
            } else {
                hex32(s).map(Some).ok_or_else(|| bad(what))
            }
        };
        Ok(Some(Pay {
            session,
            seq,
            secret: hex_of(&secret_hex, "secret is 64 lower-case hex characters")?,
            ticket: hex_of(&ticket_hex, "ticket is 64 lower-case hex characters")?,
            secret_hex,
            ticket_hex,
            auth,
        }))
    }

    /// Steps 2 and 3: authenticate the request, then take the secret it carries.
    fn authenticate(
        &self,
        req: &Request,
        pay: &Pay,
        route: Option<&Route>,
    ) -> Result<Authed, Response> {
        let digest = request_digest_v2(&req.method, &self.url(&req.target), &req.body);
        let checked = self.lock().book.authenticate(&pay.session, pay.seq, |key| {
            auth_eq(
                &ticket::request_auth(
                    key,
                    &pay.session,
                    pay.seq,
                    &pay.secret_hex,
                    &pay.ticket_hex,
                    &digest,
                ),
                &pay.auth,
            )
        });
        match checked {
            Ok(()) => {}
            // nothing about a session is told to someone who has not shown its key
            Err(Refusal::BadAuth) => {
                return Err(error(
                    401,
                    "bad_auth",
                    "the request is not authenticated for this session",
                ))
            }
            Err(Refusal::BadSeq(next)) => {
                return Err(json_response(
                    402,
                    &json!({"error": "bad_seq", "nextSeq": next}),
                ))
            }
            Err(why) => {
                let (body, header) = self.required(&req.target, route, Some(why.code()), None);
                let mut r = json_response(402, &body);
                r.headers.push(("PAYMENT-REQUIRED".into(), header));
                return Err(r);
            }
        }
        let a = Authed {
            session: pay.session.clone(),
            seq: pay.seq,
            digest,
            ticket: pay.ticket,
        };
        if let Some(secret) = &pay.secret {
            if let Err(why) = self.take_secret(&a.session, secret) {
                return Err(self.refused(&a, &req.target, route, why));
            }
        }
        Ok(a)
    }

    // --- the session endpoints ----------------------------------------------------------------------

    fn body_json(req: &Request) -> Result<Map<String, Value>, Response> {
        match serde_json::from_slice::<Value>(&req.body) {
            Ok(Value::Object(m)) => Ok(m),
            _ => Err(error(400, "bad_request", "the body is a JSON object")),
        }
    }

    fn hashes(v: Option<&Value>, most: usize) -> Result<Vec<Hash>, Response> {
        let bad = || {
            error(
                400,
                "bad_request",
                &format!(
                    "a list of 1 to {most} hashes or secrets, each 64 lower-case hex characters"
                ),
            )
        };
        let list = v
            .and_then(Value::as_array)
            .filter(|a| !a.is_empty() && a.len() <= most)
            .ok_or_else(bad)?;
        list.iter()
            .map(|h| h.as_str().and_then(hex32).ok_or_else(bad))
            .collect()
    }

    fn lock_tickets(self: &Arc<Self>, req: &Request) -> Response {
        let pay = match self.pay_header(req) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let body = match Self::body_json(req) {
            Ok(b) => b,
            Err(r) => return r,
        };
        if body.get("version").and_then(Value::as_str) != Some(ticket::VERSION) {
            return error(400, "bad_request", "version is ticket/0");
        }
        let hashes = match Self::hashes(body.get("hashes"), self.cfg.caps.max_tickets as usize) {
            Ok(h) => h,
            Err(r) => return r,
        };
        // a lock for a session that exists is a request of that session, authenticated as one
        let authed = match (&pay, body.get("session")) {
            (None, None) => None,
            (Some(p), named) if named.is_none_or(|s| s.as_str() == Some(p.session.as_str())) => match self.authenticate(req, p, None) {
                Ok(a) => Some(a),
                Err(r) => return r,
            },
            _ => return error(400, "bad_request", "a lock for an existing session carries its PAYMENT-SIGNATURE; a first lock names no session"),
        };
        let mut entropy = [0u8; 48];
        entropy.copy_from_slice(&xbt_svc::random_bytes(48));
        let granted = {
            let mut st = self.lock();
            let granted = st.book.lock(
                &addr_name(req.peer),
                authed.as_ref().map(|a| a.session.as_str()),
                &hashes,
                &entropy,
                self.now(),
            );
            granted.map(|g| {
                let written = self.journal(&mut st, &g.recs);
                (g, written, st.store.handle())
            })
        };
        // on disk before the node is asked: a ticket the node holds is never one the journal forgot
        let granted = match granted {
            Ok((g, written, file)) if written && self.sync(&file) => Ok(g),
            Ok((g, _, _)) => {
                let mut st = self.lock();
                for h in &g.issue {
                    st.book.issued(h, false);
                }
                st.book.forget_unused(&g.session);
                return error(500, "journal", "the gateway could not record the lock");
            }
            Err(why) => Err(why),
        };
        let g = match (granted, &authed) {
            (Ok(g), _) => g,
            (Err(why), Some(a)) => return self.refused(a, &req.target, None, why),
            (Err(why), None) => return json_response(402, &json!({"error": why.code()})),
        };
        let (mut tickets, mut refused, mut down) = (vec![], vec![], false);
        for h in &g.issue {
            let made = if down {
                Err(NodeError::Unreachable(String::new()))
            } else {
                self.node.add_hold(
                    h,
                    self.cfg.caps.ticket_msat,
                    self.cfg.ticket_blocks,
                    INVOICE_EXPIRY_S,
                )
            };
            let made = made.and_then(|inv| {
                self.watch(*h)
                    .map(|()| inv)
                    .map_err(|e| NodeError::Unreachable(e.to_string()))
            });
            match made {
                Ok(invoice) => tickets.push(json!({"hash": hex::encode(h), "invoice": invoice})),
                Err(e) => {
                    down |= matches!(e, NodeError::Unreachable(_));
                    let mut st = self.lock();
                    if let Some(rec) = st.book.issued(h, false) {
                        self.journal(&mut st, &[rec]);
                    }
                    refused.push(json!({"hash": hex::encode(h), "error": if down { "node_unavailable" } else { "hash_refused" }}));
                }
            }
        }
        let mut out = json!({"session": g.session, "tickets": tickets, "refused": refused});
        if let Some(key) = g.key {
            out["key"] = hex::encode(key).into();
        }
        if tickets_empty(&out) && g.key.is_some() {
            // a first lock that issued nothing leaves no session behind
            let mut st = self.lock();
            if let Some(rec) = st.book.forget_unused(&g.session) {
                self.journal(&mut st, &[rec]);
                out = json!({"tickets": [], "refused": out["refused"]});
            }
        }
        let status = if tickets_empty(&out) && down {
            503
        } else {
            200
        };
        match &authed {
            Some(a) => self.answered(a, json_response(status, &out), 0),
            None => json_response(status, &out),
        }
    }

    /// `release`, `cancel` and `status`: authenticated like any paid request.
    fn session_call(&self, req: &Request, what: &str) -> Response {
        let pay = match self.pay_header(req) {
            Ok(Some(p)) => p,
            Ok(None) => return error(401, "bad_auth", "this endpoint needs PAYMENT-SIGNATURE"),
            Err(r) => return r,
        };
        let body = match Self::body_json(req) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let most = self.cfg.caps.max_tickets as usize;
        // read the body before the request's seq is used up
        let list = match what {
            "release" => match Self::hashes(body.get("secrets"), most) {
                Ok(s) => Some(s),
                Err(r) => return r,
            },
            "cancel" if body.get("hashes").and_then(Value::as_str) == Some("all") => None,
            "cancel" => match Self::hashes(body.get("hashes"), most) {
                Ok(h) => Some(h),
                Err(r) => return r,
            },
            _ => None,
        };
        let a = match self.authenticate(req, &pay, None) {
            Ok(a) => a,
            Err(r) => return r,
        };
        let out = match what {
            "release" => {
                let (mut released, mut refused) = (vec![], vec![]);
                for secret in list.unwrap_or_default() {
                    match self.take_secret(&a.session, &secret) {
                        Ok(h) => released.push(Value::from(hex::encode(h))),
                        Err(why) => refused.push(json!({"hash": hex::encode(ticket::ticket_hash(&secret)), "error": why.code()})),
                    }
                }
                json!({"released": released, "refused": refused})
            }
            "cancel" => {
                let candidates = self.lock().book.cancellable(&a.session, list.as_deref());
                let cancelled: Vec<Value> = candidates
                    .iter()
                    .filter(|h| self.cancel_on_node(h))
                    .map(|h| hex::encode(h).into())
                    .collect();
                json!({"cancelled": cancelled})
            }
            _ => {
                let st = self.lock();
                let tickets: Vec<Value> = st
                    .book
                    .tickets_of(&a.session)
                    .iter()
                    .map(|(h, t)| json!({"hash": hex::encode(h), "state": format!("{:?}", t.state).to_uppercase(), "expiryHeight": t.expiry_height}))
                    .collect();
                let finals: Vec<Value> = st
                    .finals
                    .get(&a.session)
                    .map(|f| f.iter().cloned().collect())
                    .unwrap_or_default();
                drop(st);
                json!({"tickets": tickets, "height": self.known_height(), "responses": finals})
            }
        };
        let mut out = out;
        out["session"] = self.session_view(&a.session);
        self.answered(&a, json_response(200, &out), 0)
    }

    /// What this gateway sells, for anyone who asks. Not signed: see `docs/TICKETS.md`, section 8.
    fn services(&self) -> Response {
        let routes: Vec<Value> = self
            .cfg
            .routes
            .iter()
            .map(|r| json!({"path": r.path, "methods": r.methods, "free": r.free, "price": r.price.terms(), "release": r.release.name()}))
            .collect();
        json_response(
            200,
            &json!({"version": "services/0", "signed": false, "scheme": ticket::SCHEME, "network": self.terms.network, "payTo": self.terms.pay_to,
                    "receiptKey": self.terms.receipt_key, "session": self.terms.session, "ticketMsat": self.terms.ticket_msat.to_string(),
                    "maxTickets": self.terms.max_tickets, "ticketBlocks": self.terms.ticket_blocks, "routes": routes}),
        )
    }

    fn health(&self) -> Response {
        let s = self.stats();
        json_response(
            200,
            &json!({"height": s.height, "sessions": s.sessions, "activeSessions": s.active_sessions, "heldTickets": s.held_tickets,
                    "heldMsat": (s.held_tickets as u64).saturating_mul(self.cfg.caps.ticket_msat).to_string(), "settled": s.settled, "settleMaxUs": s.settle_max_us}),
        )
    }

    // --- a priced route -----------------------------------------------------------------------------

    fn passed_headers(answer: &Answer) -> Vec<(String, String)> {
        answer
            .headers
            .iter()
            .filter(|(k, _)| returned(k))
            .cloned()
            .collect()
    }

    /// Read at most `cap` bytes of a body. `Err`: the service stopped in the middle.
    fn read_body(body: &mut dyn Read, cap: u64) -> io::Result<Vec<u8>> {
        let mut out = vec![];
        body.take(cap).read_to_end(&mut out)?;
        Ok(out)
    }

    fn free(&self, req: &Request, route: &Route) -> Reply {
        let answer = match self.upstream.send(
            &req.method,
            &req.target,
            &forwarded(route, &req.headers),
            &req.body,
        ) {
            Ok(a) if a.status != 402 => a,
            _ => {
                return Reply::Whole(error(
                    502,
                    "upstream_unavailable",
                    "the service gave no answer",
                ))
            }
        };
        let headers = Self::passed_headers(&answer);
        let (status, length, mut src) = (answer.status, answer.length, answer.body);
        Reply::Stream(Streamed {
            status,
            headers,
            length,
            body: Box::new(move |out| {
                let mut buf = vec![0u8; CHUNK];
                loop {
                    match src.read(&mut buf)? {
                        0 => return Ok(()),
                        n => out.send(&buf[..n])?,
                    }
                }
            }),
        })
    }

    fn route(self: &Arc<Self>, req: Request) -> Reply {
        let path = match decoded_path(&req.target) {
            Ok(p) => p,
            Err(why) => return Reply::Whole(error(400, "bad_target", why)),
        };
        let Some(route) = self.cfg.route(&path) else {
            return Reply::Whole(error(
                404,
                "no_route",
                "nothing is sold or served at this path",
            ));
        };
        if !route.methods.iter().any(|m| m == &req.method) {
            return Reply::Whole(error(
                405,
                "method_not_allowed",
                "this route does not take that method",
            ));
        }
        if route.free {
            return self.free(&req, route);
        }
        let pay = match self.pay_header(&req) {
            Ok(Some(p)) => p,
            Ok(None) => return Reply::Whole(self.unpaid(&req.target, route)),
            Err(r) => return Reply::Whole(r),
        };
        let a = match self.authenticate(&req, &pay, Some(route)) {
            Ok(a) => a,
            Err(r) => return Reply::Whole(r),
        };
        let on_pledge = route.release == Release::AfterVerify;
        if let Some(hash) = &a.ticket {
            if !on_pledge {
                return Reply::Whole(self.answered(
                    &a,
                    error(
                        400,
                        "bad_payment",
                        "this route takes the secret with the request, not a pledged ticket",
                    ),
                    0,
                ));
            }
            let height = self.known_height();
            // the guard is gone before the refusal is written: `refused` reads the book again
            let pledged = self.lock().book.pledge(&a.session, hash, height);
            if let Err(why) = pledged {
                return Reply::Whole(self.refused(&a, &req.target, Some(route), why));
            }
        }
        // step 4: the request's price and the first second, before the service is asked; a body
        // priced per byte must be able to pay for its first byte
        let head_only = req.method == "HEAD";
        let first_second = if head_only {
            0
        } else {
            route.price.second_msat
        };
        let Some(reserve) = route.price.request_msat.checked_add(first_second) else {
            return Reply::Whole(self.refused(&a, &req.target, Some(route), Refusal::BalanceShort));
        };
        let first_byte = u64::from(!head_only && route.price.byte_msat > 0);
        let charged = {
            let mut st = self.lock();
            if st.book.chargeable(&a.session, on_pledge) < reserve.saturating_add(first_byte) {
                Err(Refusal::BalanceShort)
            } else {
                st.book.charge(&a.session, reserve, on_pledge, self.now())
            }
        };
        if let Err(why) = charged {
            return Reply::Whole(self.refused(&a, &req.target, Some(route), why));
        }
        let refund = |msat: u64| self.lock().book.refund(&a.session, msat);
        // step 5
        let mut answer = match self.upstream.send(
            &req.method,
            &req.target,
            &forwarded(route, &req.headers),
            &req.body,
        ) {
            // a service behind the gateway does not ask for payment through it
            Ok(ans) if ans.status != 402 => ans,
            _ => {
                refund(reserve);
                return Reply::Whole(self.answered(
                    &a,
                    error(
                        502,
                        "upstream_unavailable",
                        "the service gave no answer; nothing was charged",
                    ),
                    0,
                ));
            }
        };
        let headers = Self::passed_headers(&answer);
        if answer.status >= 400 {
            // an error is not a piece: passed on, capped, not charged
            refund(reserve);
            let passed = match Self::read_body(&mut answer.body, ERROR_BODY) {
                Ok(body) => Response::new(answer.status, headers, body),
                // an error whose body could not be read is not passed on as an empty one
                Err(_) => error(
                    502,
                    "upstream_unavailable",
                    "the service stopped in the middle of its answer; nothing was charged",
                ),
            };
            return Reply::Whole(self.answered(&a, passed, 0));
        }
        if head_only || matches!(answer.status, 100..=199 | 204 | 304) {
            // no body: the request's price, and no second of a body that does not exist. The
            // answer keeps the length the service stated (what a HEAD is asked for).
            refund(first_second);
            let charged = reserve.saturating_sub(first_second);
            let mut headers = headers;
            let receipt = self.receipt(
                &a.session,
                a.seq,
                charged,
                &a.digest,
                answer.status,
                &body_hash(b""),
            );
            if let Some(receipt) = receipt {
                let sr = settlement_response(&receipt, &self.cfg.network, "", true);
                headers.push(("PAYMENT-RESPONSE".into(), b64json(&sr)));
            }
            self.flush();
            return Reply::Stream(Streamed {
                status: answer.status,
                headers,
                length: answer.length,
                body: Box::new(|_| Ok(())),
            });
        }
        if !route.price.metered() && answer.length.is_some_and(|n| n <= WHOLE_BODY) {
            let want = answer.length.unwrap_or(0);
            return match Self::read_body(&mut answer.body, want) {
                Ok(body) if body.len() as u64 == want => Reply::Whole(self.answered(
                    &a,
                    Response::new(answer.status, headers, body),
                    reserve,
                )),
                _ => {
                    refund(reserve);
                    Reply::Whole(self.answered(
                        &a,
                        error(
                            502,
                            "upstream_unavailable",
                            "the service stopped in the middle of its answer; nothing was charged",
                        ),
                        0,
                    ))
                }
            };
        }
        // a body that is metered, long, or of unknown length: sent as it arrives
        self.lock().book.response(&a.session, true, self.now());
        // counted out again when the body ends, or is never started (the buyer hung up first)
        let open = OpenResponse {
            gw: self.clone(),
            session: a.session.clone(),
        };
        self.flush();
        let mut headers = headers;
        if let Some(head) = self.receipt(&a.session, a.seq, reserve, &a.digest, answer.status, "") {
            let mut sr = settlement_response(&head, &self.cfg.network, "", true);
            sr["extra"]["stream"] = true.into();
            headers.push(("PAYMENT-RESPONSE".into(), b64json(&sr)));
        }
        let m = Metered {
            session: a.session,
            seq: a.seq,
            digest: a.digest,
            status: answer.status,
            route: route.clone(),
            at_head: route.price.request_msat,
            first_second,
            started: Instant::now(),
        };
        let (gw, length, src) = (self.clone(), answer.length, answer.body);
        Reply::Stream(Streamed {
            status: answer.status,
            headers,
            length,
            body: Box::new(move |out| gw.pump(m, src, out, open)),
        })
    }

    /// Take what `want` further bytes of a body cost, waiting for a release when the balance is
    /// out. Returns how many bytes were paid for (fewer than `want` when the balance covers
    /// fewer) and what they cost; 0 bytes: the wait ran out, the buyer has stopped paying.
    fn pay_bytes(&self, m: &Metered, meter: &Meter, want: u64) -> (u64, u64) {
        let on_pledge = m.route.release == Release::AfterVerify;
        let deadline = Instant::now() + self.cfg.times.refill_wait;
        let mut st = self.lock();
        loop {
            let take = meter.affordable(want, st.book.chargeable(&m.session, on_pledge));
            if take > 0 {
                return match meter.bytes_due(take) {
                    Some(due)
                        if st
                            .book
                            .charge(&m.session, due, on_pledge, self.now())
                            .is_ok() =>
                    {
                        (take, due)
                    }
                    _ => (0, 0),
                };
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || self.stop.load(Ordering::SeqCst) {
                return (0, 0);
            }
            st = self
                .credited
                .wait_timeout(st, left)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
    }

    /// Take `due` for seconds that have started, waiting as [`Gateway::pay_bytes`] does.
    fn pay_seconds(&self, m: &Metered, due: u64) -> bool {
        let on_pledge = m.route.release == Release::AfterVerify;
        let deadline = Instant::now() + self.cfg.times.refill_wait;
        let mut st = self.lock();
        loop {
            if st
                .book
                .charge(&m.session, due, on_pledge, self.now())
                .is_ok()
            {
                return true;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || self.stop.load(Ordering::SeqCst) {
                return false;
            }
            st = self
                .credited
                .wait_timeout(st, left)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
    }

    /// A metered body: every chunk is paid for before it is sent, and what was not sent is given
    /// back. Ends when the service ends, the buyer stops reading, or the buyer stops paying.
    fn pump(
        &self,
        m: Metered,
        mut src: Box<dyn Read + Send>,
        out: &mut dyn BodyWriter,
        _open: OpenResponse,
    ) -> io::Result<()> {
        let mut meter = Meter::new(m.route.price);
        meter.seconds_charged(1, m.first_second);
        let mut hash = Sha256::new();
        let mut buf = vec![0u8; CHUNK];
        let stopped = |why: &str| Err(io::Error::other(why.to_string()));
        let result = 'body: loop {
            let elapsed = m.started.elapsed();
            if elapsed > self.cfg.times.max_response {
                break stopped("the response reached its longest life");
            }
            match meter.seconds_due(u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)) {
                Some((0, _)) => {}
                Some((secs, due)) if self.pay_seconds(&m, due) => meter.seconds_charged(secs, due),
                _ => break stopped("no balance for another second"),
            }
            let n = match src.read(&mut buf) {
                Ok(0) => break Ok(()),
                Ok(n) => n,
                Err(e) => break Err(e),
            };
            let mut off = 0;
            while off < n {
                let (take, due) = self.pay_bytes(&m, &meter, (n - off) as u64);
                if take == 0 {
                    break 'body stopped("no balance for another byte");
                }
                let take_n = take as usize;
                if let Err(e) = out.send(&buf[off..off + take_n]) {
                    self.lock().book.refund(&m.session, due);
                    break 'body Err(e);
                }
                hash.update(&buf[off..off + take_n]);
                meter.sent(take, due);
                off += take_n;
            }
        };
        let charged = m.at_head.saturating_add(meter.charged());
        let last = self.receipt(
            &m.session,
            m.seq,
            charged,
            &m.digest,
            m.status,
            &hex::encode(hash.finalize()),
        );
        let mut st = self.lock();
        if let Some(mut r) = last {
            // beside the signed fields: how the body ended
            r["bytes"] = meter.bytes().into();
            r["complete"] = result.is_ok().into();
            let finals = st.finals.entry(m.session.clone()).or_default();
            if finals.len() >= FINALS_KEPT {
                finals.pop_front();
            }
            finals.push_back(r);
        }
        let marks = st.book.take_marks();
        self.journal(&mut st, &marks);
        drop(st);
        result
    }
}

/// A metered response that is open: its session is not idle. Dropped when the body has ended, or
/// when it never ran.
struct OpenResponse {
    gw: Arc<Gateway>,
    session: String,
}

impl Drop for OpenResponse {
    fn drop(&mut self) {
        let now = self.gw.now();
        self.gw.lock().book.response(&self.session, false, now);
    }
}

fn tickets_empty(out: &Value) -> bool {
    out["tickets"].as_array().is_none_or(Vec::is_empty)
}

/// The gateway as the shared HTTP server sees it.
struct Service(Arc<Gateway>);

impl Service {
    fn session_path<'a>(&self, path: &'a str) -> Option<&'a str> {
        path.strip_prefix(ticket::SESSION_PATH)
            .and_then(|p| p.strip_prefix('/'))
    }
}

impl Handler for Service {
    fn body_limit(&self, _method: &str, target: &str) -> usize {
        let path = target.split('?').next().unwrap_or("");
        if self.session_path(path).is_some() {
            return SESSION_BODY;
        }
        decoded_path(target)
            .ok()
            .and_then(|p| self.0.cfg.route(&p).map(|r| r.max_body))
            .unwrap_or(0)
    }

    fn handle(&self, req: Request) -> Response {
        match self.reply(req) {
            Reply::Whole(r) => r,
            Reply::Stream(_) => error(
                500,
                "internal",
                "a streamed answer where a whole one was asked",
            ),
        }
    }

    fn reply(&self, req: Request) -> Reply {
        let gw = &self.0;
        let path = req.path().to_string();
        if let Some(call) = self.session_path(&path) {
            let loopback = req.peer.is_some_and(|p| p.ip().is_loopback());
            return Reply::Whole(match (req.method.as_str(), call) {
                ("POST", "lock") => gw.lock_tickets(&req),
                ("POST", "release" | "cancel" | "status") => gw.session_call(&req, call),
                // the operator's view, for the machine the gateway runs on only
                ("GET", "health") if loopback => gw.health(),
                _ => error(404, "no_route", "no such session endpoint"),
            });
        }
        if path == SERVICES_PATH && req.method == "GET" {
            return Reply::Whole(gw.services());
        }
        gw.route(req)
    }
}
