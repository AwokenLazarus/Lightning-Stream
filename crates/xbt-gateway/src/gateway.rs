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
//!
//! Two more rules, kept at a lock:
//!
//! - **Half the slots** ([`Book::lock`], [`Gateway::slot_room`]): held tickets, all sessions
//!   together, never pass the cap, and with a channels macaroon none is issued while an inbound
//!   channel of the node is half full of pending payments. A buyer that meets either is told
//!   `slots_short` and when to come back, before any invoice exists.
//! - **The caps before the node** ([`Book::lock_room`]): a lock that the caps on sessions, or the
//!   session's own cap on tickets, refuse is refused before the node is asked for its channel
//!   list. A lock for an existing session is authenticated before that; a first lock cannot be.
//! - **Prepaid is the node's word** ([`Gateway::take_prepaid`]): a ticket settled on arrival is
//!   an ordinary invoice whose preimage the gateway makes and forgets; it is credited once, when
//!   the node shows that invoice settled for the full amount, whoever asks.
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read};
use std::net::{IpAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use secp256k1::SecretKey;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use xbt402::ticket::{
    self, held_budget, hex32, Terms, INVOICE_EXPIRY_S, SETTLE_ON_ARRIVAL, SETTLE_ON_USE,
};
use xbt402::wire::{
    auth_eq, b64json, body_hash, request_digest_v2, settlement_response, unb64json, X402_VERSION,
};
use xbt402::xbt_primitives::ecdsa;
use xbt_svc::http::{
    AddrKey, BodyWriter, Handler, Limits, Reply, Request, Response, Running, Streamed,
};

use crate::book::{Book, Rec, Refusal};
use crate::config::{Config, Release, Route, LISTING_PATH, SERVICES_PATH};
use crate::node::{Hash, Invoice, InvoiceState, Node, NodeError};
pub use draws::JOURNAL as LOTTERY_JOURNAL;
use crate::price::Meter;
use crate::store::{Store, COMPACT_AT};
use crate::upstream::{decoded_path, forwarded, returned, Answer, Upstream};
use crate::Error;

mod draws;
mod offers;
pub use offers::JOURNAL as OFFERS_JOURNAL;

/// A body no larger than this, on a route priced per request only, is read whole so that its
/// receipt can carry its hash. Larger or metered bodies are streamed.
const WHOLE_BODY: u64 = 256 << 10;
/// The most of an error answer's body that is passed on (an error is not charged).
const ERROR_BODY: u64 = 64 << 10;
/// The body of a session endpoint's request.
const SESSION_BODY: usize = 16 << 10;
/// One read of the service's body, and so the most that is charged ahead of a write.
const CHUNK: usize = 16 << 10;
/// How often an answer waiting to be paid for looks whether its buyer is still there.
const GONE_CHECK: Duration = Duration::from_millis(250);
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
    /// Tickets settled on arrival that are issued and not yet credited: they hold no slot.
    pub prepaid_tickets: usize,
    /// The cap on held tickets as it is now (a gateway that reads its channels moves it).
    pub max_held: u32,
    pub settled: u64,
    /// The longest time from a secret's arrival to the node's yes, in microseconds.
    pub settle_max_us: u64,
    pub height: Option<u32>,
}

pub struct Gateway {
    cfg: Config,
    terms: Terms,
    node: Arc<dyn Node>,
    /// One client per service: the config's `upstream` and each route's own, by base URL.
    upstreams: HashMap<String, Upstream>,
    key: SecretKey,
    state: Mutex<State>,
    /// Signalled whenever a session is credited: metered responses out of balance wait on it.
    credited: Condvar,
    height: Mutex<Height>,
    stop: AtomicBool,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
    settled: AtomicU64,
    settle_max_us: AtomicU64,
    /// The lottery's sessions, where the runner offers it (`docs/TICKETS.md`, section 9).
    lottery: Option<draws::Lottery>,
    /// The node's BOLT 12 offer and what was paid to it, where the runner turned payment by offer
    /// on (`docs/TICKETS.md`, section 15).
    offers: Option<offers::Offers>,
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

/// Whether `host`, a request's `Host` header in lowercase, names `origin` (`https://name[:port]`):
/// the same name, and the same port with the scheme's default filled in.
fn same_host(origin: &str, host: &str) -> bool {
    let o = xbt402::wire::request_url(origin);
    let (name, port) = match host.rsplit_once(':') {
        Some((n, p)) if !p.contains(']') && p.bytes().all(|b| b.is_ascii_digit()) && !p.is_empty() => (n, p.trim_start_matches('0').to_string()),
        _ => (host, String::new()),
    };
    let port = if port.is_empty() { if o.scheme == "https" { "443".to_string() } else { "80".to_string() } } else { port };
    o.host == name && o.port == port
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

fn addr_name(client: Option<IpAddr>) -> String {
    match client.map(AddrKey::of) {
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
    /// The request is a HEAD: its answer has no body, whatever the route.
    head: bool,
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
    /// A request to a route priced by the token: what bounds its tokens.
    tokens: Option<TokenCall>,
    /// The most the buyer lets this answer charge, in msat ([`xbt402::ticket::MAX_MSAT_HEADER`]).
    cap_msat: Option<u64>,
}

impl Metered {
    /// What the buyer's cap leaves for this answer after `charged` msat of its own; no cap: all.
    fn room(&self, charged: u64) -> u64 {
        self.cap_msat.map_or(u64::MAX, |c| c.saturating_sub(self.at_head.saturating_add(charged)))
    }
}

/// What bounds the tokens of one request to a route priced by the token.
#[derive(Clone, Copy)]
struct TokenCall {
    /// The buyer's request body, in bytes, before the gateway bounded it.
    body_len: u64,
    /// The `max_tokens` the service was sent.
    max_output: u64,
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
            min_ticket_msat: cfg.min_ticket_msat,
            max_tickets: cfg.caps.max_tickets,
            ticket_blocks: cfg.ticket_blocks,
            receipt_key: hex::encode(ecdsa::pubkey(&key)),
            session: ticket::SESSION_PATH.into(),
        };
        let (mut store, recs) =
            Store::open(&cfg.state_dir).map_err(|e| Error::Journal(e.to_string()))?;
        let mut book = Book::restore(cfg.caps.clone(), &recs, clock())?;
        // a runner who gave a channels macaroon wants the cap read from the node: a macaroon that
        // does not work is a config that does not, and nothing starts on it
        if cfg.node.channels_macaroon.is_some() {
            let channels = node.channels().map_err(|e| {
                Error::Start(format!(
                    "node.channels_macaroon is set and the node's channels could not be read: {e}"
                ))
            })?;
            let (cap, _) = Self::sized(&cfg, &channels);
            book.set_max_held(cap);
        }
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
        // a ticket settled on arrival is not followed: the node's word is asked for when it is presented
        let unfinished: Vec<Hash> = book
            .unfinished()
            .into_iter()
            .filter(|h| book.ticket(h).is_some_and(|t| !t.prepaid))
            .collect();
        // the lottery's sessions, as its own journal beside the tickets' has them
        let lottery = match cfg.lottery.clone() {
            Some(l) => Some(draws::Lottery::open(l, &cfg.state_dir, clock())?),
            None => None,
        };
        let mut upstreams = HashMap::new();
        for base in cfg.upstream.iter().chain(cfg.routes.iter().filter_map(|r| r.upstream.as_ref())) {
            upstreams.entry(base.clone()).or_insert_with(|| Upstream::new(base, cfg.times.upstream_wait));
        }
        // the node's offer, made (or found again) before anything is served: terms that name it are
        // terms the node can be paid on
        let offers = Self::make_offer(&*node, &cfg, clock())?;
        let gw = Arc::new(Self {
            terms,
            node,
            upstreams,
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
            lottery,
            offers,
            cfg,
        });
        for hash in unfinished {
            gw.watch(hash)
                .map_err(|e| Error::Start(format!("a watcher thread: {e}")))?;
        }
        gw.lottery_restored();
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
        if let Some(l) = &self.lottery {
            l.close();
        }
        if let Some(o) = &self.offers {
            o.close();
        }
        self.credited.notify_all();
    }

    /// The signed listing, as the well-known URL serves it; `None` without a listing section.
    pub fn listing(&self) -> Option<Value> {
        self.listing_doc()
    }

    /// The receipt key's binding of `nostr_pubkey` to this seller (`docs/NOSTR.md`).
    pub fn bind_nostr(&self, nostr_pubkey: &[u8; 32]) -> String {
        xbt402::listing::bind(&self.key, nostr_pubkey, &self.cfg.public_url)
    }

    /// [`Self::stop`] has run.
    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    pub fn terms(&self) -> &Terms {
        &self.terms
    }

    /// For tests: the lottery's journal stops taking records, as a full disk would.
    #[doc(hidden)]
    pub fn break_lottery_journal(&self) {
        if let Some(l) = &self.lottery {
            l.close();
        }
    }

    pub fn stats(&self) -> Stats {
        let st = self.lock();
        Stats {
            sessions: st.book.sessions(),
            active_sessions: st.book.active_sessions(),
            held_tickets: st.book.held(),
            prepaid_tickets: st.book.prepaid_open(),
            max_held: st.book.caps().max_held,
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
        self.lottery_tick();
        self.offer_tick();
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

    /// Cancel a ticket on the node, and bring the book to what the node then shows of it. True:
    /// the node shows it cancelled.
    ///
    /// The answer to the cancel call is not taken for the invoice's state, yes or no. A yes says
    /// the call was accepted; whether the invoice is cancelled, or was settled a moment before
    /// (a settle whose answer was lost, a payment that arrived as the sweep ran), is what a
    /// lookup says. A ticket taken out of the book on a yes alone, when the node had in fact
    /// settled it, would be money the seller holds and the buyer was never credited. So: one
    /// lookup after every cancel that was answered, and the book follows the lookup. With no
    /// answer to the lookup the ticket stays as it was, and the next sweep asks again.
    fn cancel_on_node(&self, hash: &Hash) -> bool {
        if let Err(NodeError::Unreachable(_)) = self.node.cancel(hash) {
            return false;
        }
        match self.node.lookup(hash) {
            Ok(Some(inv)) => {
                self.apply(hash, &inv);
                inv.state == InvoiceState::Canceled
            }
            Ok(None) => {
                let mut st = self.lock();
                if let Some(rec) = st.book.node_has_none(hash) {
                    self.journal(&mut st, &[rec]);
                }
                false
            }
            Err(_) => false,
        }
    }

    /// The cap on held tickets and whether a channel is half full, from the node's channel list:
    /// half of the smallest channel's pending payments unless the runner set the cap, and no
    /// channels, no held tickets.
    fn sized(cfg: &Config, channels: &[crate::node::Channel]) -> (u32, bool) {
        let smallest = channels.iter().map(|c| c.slots).min().unwrap_or(0);
        let cap = if cfg.held_set {
            cfg.caps.max_held
        } else {
            held_budget(smallest).min(crate::config::MAX_HELD)
        };
        let half_full = channels
            .iter()
            .any(|c| c.pending_in >= held_budget(c.slots));
        (if channels.is_empty() { 0 } else { cap }, half_full)
    }

    /// Before a held ticket is issued, for a gateway that reads its node's channels: the cap is
    /// brought to what the channels carry now, and nothing is issued while one of them is half
    /// full of pending payments (the buyer's node chooses the channel a ticket arrives on, so the
    /// fullest one counts). A list that cannot be read moves nothing and widens nothing: the cap
    /// falls back to the config's own.
    fn slot_room(&self) -> Result<(), Refusal> {
        if self.cfg.node.channels_macaroon.is_none() {
            return Ok(());
        }
        match self.node.channels() {
            Ok(channels) => {
                let (cap, half_full) = Self::sized(&self.cfg, &channels);
                self.lock().book.set_max_held(cap);
                if half_full {
                    return Err(Refusal::SlotsShort(self.cfg.caps.slots_retry_secs));
                }
            }
            Err(e) => {
                eprintln!("xbt-gateway: the node's channels could not be read ({e}): the cap on held tickets is the config's until they can");
                self.lock().book.set_max_held(self.cfg.caps.max_held);
            }
        }
        Ok(())
    }

    /// A preimage presented for a ticket settled on arrival: the node says whether that invoice
    /// was paid, and a paid one is credited once. No settle call is made: there is nothing held.
    fn take_prepaid(&self, secret: &[u8; 32]) -> Result<Hash, Refusal> {
        let hash = ticket::ticket_hash(secret);
        match self.node.lookup(&hash) {
            Ok(Some(inv)) => {
                let face = self.lock().book.ticket_msat(&hash, inv.paid_msat).unwrap_or(self.cfg.caps.ticket_msat);
                let paid = inv.state == InvoiceState::Settled && inv.paid_msat >= face;
                self.apply(&hash, &inv);
                match inv.state {
                    _ if paid => Ok(hash),
                    InvoiceState::Open | InvoiceState::Accepted => Err(Refusal::TicketNotLocked),
                    InvoiceState::Settled | InvoiceState::Canceled => Err(Refusal::TicketUnknown),
                }
            }
            Ok(None) => {
                let mut st = self.lock();
                if let Some(rec) = st.book.node_has_none(&hash) {
                    self.journal(&mut st, &[rec]);
                }
                Err(Refusal::TicketUnknown)
            }
            Err(NodeError::Refused(_)) => Err(Refusal::TicketNotLocked),
            Err(NodeError::Unreachable(_)) => Err(Refusal::HeightUnknown),
        }
    }

    /// Steps 2 and 3 of a paid request for one secret: find its ticket, settle it at once, credit it.
    fn take_secret(&self, session: &str, secret: &[u8; 32]) -> Result<Hash, Refusal> {
        let kind = self.lock().book.presented_kind(session, secret);
        match kind {
            Ok(true) => return self.take_prepaid(secret),
            // no ticket of the book: a prepaid ticket paid by offer, where the terms name one
            Err(Refusal::TicketUnknown) if self.offers.is_some() => return self.take_offer_secret(session, secret),
            _ => {}
        }
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

    /// The address the caps per address count a request under: the socket's peer, or, where the
    /// runner named a reverse proxy and the header it sets (`http.forwarded_address`), the address
    /// that proxy says it took the request from. The header is read only on a connection from one
    /// of the named proxies; anyone else's is just a header, and that request counts under its own
    /// socket address. Of a list (`a, b, c`) the last entry is the one the proxy wrote. A header
    /// that is missing, sent twice or not an address counts the request under the proxy's own
    /// address, with everything else that came that way: the cap is then too tight, never open.
    fn client_ip(&self, req: &Request) -> Option<IpAddr> {
        let peer = req.peer.map(|p| p.ip().to_canonical())?;
        let Some(f) = self.cfg.forwarded.as_ref().filter(|f| f.proxies.contains(&peer)) else {
            return Some(peer);
        };
        let mut named = req.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(&f.header));
        let client = match (named.next(), named.next()) {
            (Some((_, v)), None) => v.rsplit(',').next().and_then(|a| a.trim().parse::<IpAddr>().ok()),
            _ => None,
        };
        Some(client.map_or(peer, |a| a.to_canonical()))
    }

    /// The origin a request came in on: an alias its `Host` names (`public_aliases`), else
    /// `public_url`. A payment binds the URL the buyer used, so each origin's terms name it.
    fn origin_of(&self, req: &Request) -> &str {
        let host = req.header("host").map(|h| h.trim().to_ascii_lowercase());
        host.and_then(|h| self.cfg.public_aliases.iter().find(|a| same_host(a, &h)))
            .map_or(self.cfg.public_url.as_str(), String::as_str)
    }

    /// The URL a request was sent to: its origin, then its target.
    fn req_url(&self, req: &Request) -> String {
        format!("{}{}", self.origin_of(req), req.target)
    }

    /// The x402 `PaymentRequired`, as header and as body.
    fn required(
        &self,
        resource: &str,
        route: Option<&Route>,
        head: bool,
        why: Option<Refusal>,
        session: Option<Value>,
    ) -> (Value, String) {
        let mut m = Map::new();
        m.insert("x402Version".into(), X402_VERSION.into());
        if let Some(w) = why {
            m.insert("error".into(), w.code().into());
            if let Refusal::SlotsShort(secs) = w {
                m.insert("retryAfter".into(), secs.into());
            }
        }
        m.insert("resource".into(), json!({"url": resource}));
        // one entry per way of settling the runner offers, the held one first: a buyer takes the
        // first it can use
        let ways = [
            (self.cfg.held, SETTLE_ON_USE),
            (self.cfg.prepaid, SETTLE_ON_ARRIVAL),
        ];
        let mut accepts: Vec<Value> = route
            .into_iter()
            .flat_map(|r| {
                ways.iter().filter(|(on, _)| *on).map(|(_, settle)| {
                    let mut e = self.terms.accepts(
                        r.price.request_msat,
                        r.release.name(),
                        settle,
                        &r.price.terms(),
                    );
                    // said up front, so that a buyer buys its prepaid ticket first instead of
                    // offering hashes the lock would refuse
                    if *settle == SETTLE_ON_USE && self.cfg.caps.held_after_paid {
                        e["extra"]["heldAfterPaid"] = true.into();
                    }
                    // a prepaid ticket can be paid by the node's offer as well as by its invoice
                    if let Some(o) = self.offer_text().filter(|_| *settle == SETTLE_ON_ARRIVAL) {
                        e["extra"][xbt402::offer::EXTRA_OFFER] = o.into();
                    }
                    e
                })
            })
            .collect();
        // and the lottery, last: a buyer that knows only tickets skips an entry it cannot read
        accepts.extend(route.and_then(|r| self.lottery_entry(r, head)));
        m.insert("accepts".into(), Value::Array(accepts));
        if let Some(s) = session {
            m.insert("session".into(), s);
        }
        let v = Value::Object(m);
        let header = b64json(&v);
        (v, header)
    }

    /// The 402 of an unpaid request: the terms.
    fn unpaid(&self, resource: &str, route: &Route, head: bool) -> Response {
        let (body, header) = self.required(resource, Some(route), head, None, None);
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
    fn refused(&self, a: &Authed, resource: &str, route: Option<&Route>, why: Refusal) -> Response {
        let status = if why == Refusal::HeightUnknown {
            503
        } else {
            402
        };
        let (body, header) = self.required(
            resource,
            route,
            a.head,
            Some(why),
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
            || !xbt402::ticket::on_network(accepted, &self.cfg.network)
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
        let digest = request_digest_v2(&req.method, &self.req_url(req), &req.body);
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
                let (body, header) = self.required(&self.req_url(req), route, req.method == "HEAD", Some(why), None);
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
            head: req.method == "HEAD",
        };
        if let Some(secret) = &pay.secret {
            if let Err(why) = self.take_secret(&a.session, secret) {
                return Err(self.refused(&a, &self.req_url(req), route, why));
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
        // `settle` in a lock says which kind of ticket is asked for; without it, a held one
        let prepaid = match body.get("settle").map(Value::as_str) {
            None => false,
            Some(Some(SETTLE_ON_USE)) => false,
            Some(Some(SETTLE_ON_ARRIVAL)) => true,
            Some(_) => return error(400, "bad_request", "settle is on-use or on-arrival"),
        };
        if (prepaid && !self.cfg.prepaid) || (!prepaid && !self.cfg.held) {
            return error(
                400,
                "bad_request",
                "this seller's terms do not offer tickets settled that way",
            );
        }
        // a buyer that pays its prepaid tickets by the node's offer asks for no invoice: a first
        // such lock makes the session and its key, a later one is answered with the offer
        match body.get("by") {
            None => {}
            Some(Value::String(b)) if b == "offer" && prepaid && self.offers.is_some() => {
                if body.contains_key("count") || body.contains_key("hashes") {
                    return error(400, "bad_request", "a lock to pay by offer names no count and no hashes");
                }
                return self.lock_by_offer(req, pay.as_ref(), body.get("session"));
            }
            Some(_) => return error(400, "bad_request", "by is \"offer\", in a lock for tickets settled on arrival of a seller whose terms name an offer"),
        }
        // the size: the gateway's own, or a smaller one the buyer asks for where the terms let it.
        // A gateway whose terms name no smallest size ignores the field, as the draft says
        let size = match (self.cfg.min_ticket_msat, body.get("ticketMsat")) {
            (None, _) | (_, None) => self.cfg.caps.ticket_msat,
            (Some(min), Some(v)) => {
                let asked = match v {
                    Value::String(s) => s.parse::<u64>().ok(),
                    v => v.as_u64(),
                };
                match asked.filter(|n| (min..=self.cfg.caps.ticket_msat).contains(n)) {
                    Some(n) => n,
                    None => {
                        return error(400, "bad_request", &format!("ticketMsat is from {min} to {}", self.cfg.caps.ticket_msat))
                    }
                }
            }
        };
        // for a ticket settled on arrival the buyer sends a count and the hashes are the seller's:
        // the preimage of each is made here, given to the node with the invoice, and not kept
        let most = self.cfg.caps.max_tickets as usize;
        let mut preimages: HashMap<Hash, [u8; 32]> = HashMap::new();
        let hashes = if prepaid {
            let count = body
                .get("count")
                .and_then(Value::as_u64)
                .filter(|n| (1..=most as u64).contains(n));
            let Some(count) = count else {
                return error(400, "bad_request", &format!("count is from 1 to {most}"));
            };
            if body.contains_key("hashes") {
                return error(
                    400,
                    "bad_request",
                    "a lock for tickets settled on arrival names a count, no hashes",
                );
            }
            (0..count)
                .map(|_| {
                    let mut p = [0u8; 32];
                    p.copy_from_slice(&xbt_svc::random_bytes(32));
                    let h = ticket::ticket_hash(&p);
                    preimages.insert(h, p);
                    h
                })
                .collect()
        } else {
            match Self::hashes(body.get("hashes"), most) {
                Ok(h) => h,
                Err(r) => return r,
            }
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
        let addr = addr_name(self.client_ip(req));
        // the caps on sessions before the node is asked for anything, its channel list included:
        // a first lock is authenticated by nobody, and one these caps refuse must cost one look
        // at the book and no call to the node (a gateway that reads its channels makes one, with
        // a timeout of seconds, for every lock that gets further than this)
        let fits = self.lock().book.lock_room(&addr, authed.as_ref().map(|a| a.session.as_str()), prepaid);
        // a held ticket takes a slot of the channel it arrives on: the node's channels next
        let room = fits.and_then(|_| if prepaid { Ok(()) } else { self.slot_room() });
        let granted = room.and_then(|()| {
            let mut st = self.lock();
            let granted = st.book.lock_sized(
                &addr,
                authed.as_ref().map(|a| a.session.as_str()),
                &hashes,
                prepaid,
                size,
                &entropy,
                self.now(),
            );
            granted.map(|g| {
                let written = self.journal(&mut st, &g.recs);
                (g, written, st.store.handle())
            })
        });
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
            (Err(why), Some(a)) => return self.refused(a, &self.req_url(req), None, why),
            (Err(Refusal::SlotsShort(secs)), None) => {
                return json_response(
                    402,
                    &json!({"error": Refusal::SlotsShort(secs).code(), "retryAfter": secs}),
                )
            }
            (Err(why), None) => return json_response(402, &json!({"error": why.code()})),
        };
        // a first lock is nobody's yet: its invoices lapse sooner, so that unpaid ones give their places back
        let expiry = if g.key.is_some() {
            u32::try_from(self.cfg.caps.first_lock_secs).unwrap_or(INVOICE_EXPIRY_S).min(INVOICE_EXPIRY_S)
        } else {
            INVOICE_EXPIRY_S
        };
        let (mut tickets, mut refused, mut down) = (vec![], vec![], false);
        for h in &g.issue {
            let made = match (down, preimages.get(h)) {
                (true, _) => Err(NodeError::Unreachable(String::new())),
                (false, Some(preimage)) => self.node.add_invoice(
                    preimage,
                    size,
                    self.cfg.ticket_blocks,
                    expiry,
                ),
                (false, None) => self
                    .node
                    .add_hold(
                        h,
                        size,
                        self.cfg.ticket_blocks,
                        expiry,
                    )
                    .and_then(|inv| {
                        self.watch(*h)
                            .map(|()| inv)
                            .map_err(|e| NodeError::Unreachable(e.to_string()))
                    }),
            };
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
                    .map(|(h, t)| json!({"hash": hex::encode(h), "state": format!("{:?}", t.state).to_uppercase(), "expiryHeight": t.expiry_height,
                                         "settle": if t.prepaid { SETTLE_ON_ARRIVAL } else { SETTLE_ON_USE }}))
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

    /// The signed catalog (`docs/LISTINGS.md`), when the runner wrote one. The receipt key signs it.
    fn listing_doc(&self) -> Option<Value> {
        let spec = self.cfg.listing.as_ref()?;
        let doc = xbt402::listing::document(spec, &self.cfg.public_url, &self.terms.receipt_key);
        Some(xbt402::listing::sign(&self.key, &doc))
    }

    /// What this gateway sells, for anyone who asks. Not signed: see `docs/TICKETS.md`, section 8.
    fn services(&self) -> Response {
        let routes: Vec<Value> = self
            .cfg
            .routes
            .iter()
            .map(|r| json!({"path": r.path, "methods": r.methods, "free": r.free, "price": r.price.terms(), "release": r.release.name(),
                            "lottery": self.lottery_entry(r, false).is_some()}))
            .collect();
        let settle: Vec<&str> = [
            (self.cfg.held, SETTLE_ON_USE),
            (self.cfg.prepaid, SETTLE_ON_ARRIVAL),
        ]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, s)| *s)
        .collect();
        json_response(
            200,
            &json!({"version": "services/0", "signed": false, "scheme": ticket::SCHEME, "network": self.terms.network, "payTo": self.terms.pay_to,
                    "receiptKey": self.terms.receipt_key, "session": self.terms.session, "ticketMsat": self.terms.ticket_msat.to_string(),
                    "minTicketMsat": self.terms.min_ticket_msat.map(|m| m.to_string()),
                    "maxTickets": self.terms.max_tickets, "ticketBlocks": self.terms.ticket_blocks, "settle": settle, "routes": routes,
                    "lottery": self.cfg.lottery.as_ref().map(|c| self.lottery_terms(c).accepts(0, "", &Value::Null)["extra"].clone())}),
        )
    }

    fn health(&self) -> Response {
        let s = self.stats();
        json_response(
            200,
            &json!({"height": s.height, "sessions": s.sessions, "activeSessions": s.active_sessions, "heldTickets": s.held_tickets,
                    "maxHeld": s.max_held, "prepaidTickets": s.prepaid_tickets,
                    "heldMsat": (s.held_tickets as u64).saturating_mul(self.cfg.caps.ticket_msat).to_string(), "settled": s.settled, "settleMaxUs": s.settle_max_us,
                    "lottery": self.lottery_health(), "offer": self.offer_text()}),
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

    /// Pass the request on to its route's service.
    pub(crate) fn send_upstream(&self, route: &Route, req: &Request) -> Result<Answer, crate::Error> {
        self.send_upstream_body(route, req, &req.body)
    }

    /// Pass the request on with another body (a request to a route priced by the token, bounded).
    fn send_upstream_body(&self, route: &Route, req: &Request, body: &[u8]) -> Result<Answer, crate::Error> {
        let base = route.upstream.as_ref().or(self.cfg.upstream.as_ref());
        // the config refuses a route with neither, and every base has its client
        let up = base.and_then(|b| self.upstreams.get(b)).ok_or_else(|| crate::Error::Upstream("no service for this route".into()))?;
        up.send(&req.method, &route.upstream_target(&req.target), &forwarded(route, &req.headers), body)
    }

    /// Read at most `cap` bytes of a body. `Err`: the service stopped in the middle.
    fn read_body(body: &mut dyn Read, cap: u64) -> io::Result<Vec<u8>> {
        let mut out = vec![];
        body.take(cap).read_to_end(&mut out)?;
        Ok(out)
    }

    fn free(&self, req: &Request, route: &Route) -> Reply {
        let answer = match self.send_upstream(route, req) {
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
        if Self::pays_by_lottery(&req) {
            return self.lottery_route(req, route);
        }
        let pay = match self.pay_header(&req) {
            Ok(Some(p)) => p,
            Ok(None) => return Reply::Whole(self.unpaid(&self.req_url(&req), route, req.method == "HEAD")),
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
                return Reply::Whole(self.refused(&a, &self.req_url(&req), Some(route), why));
            }
        }
        // a request with a body to a route priced by the token: its output bounded, its counts asked
        // for, and the most it can cost in the balance before the service is asked. A request with
        // no body (a list of models, a page) costs the route's price per request alone
        let tokens = route.price.tokens.active() && !req.body.is_empty();
        let prepared = if tokens {
            match xbt402::tokens::prepare(&req.body, route.price.tokens.max_output) {
                Ok(p) => Some(p),
                Err(why) => return Reply::Whole(self.answered(&a, error(400, "bad_request", why), 0)),
            }
        } else {
            None
        };
        let token_bound = match &prepared {
            None => Some(0),
            Some(p) => route.price.tokens.bound(req.body.len() as u64, p.max_output),
        };
        let Some(token_bound) = token_bound else {
            return Reply::Whole(self.refused(&a, &self.req_url(&req), Some(route), Refusal::BalanceShort));
        };
        // step 4: the request's price and the first second, before the service is asked; a body
        // priced per byte must be able to pay for its first byte
        let head_only = req.method == "HEAD";
        let first_second = if head_only {
            0
        } else {
            route.price.second_msat
        };
        let Some(reserve) = route.price.request_msat.checked_add(first_second) else {
            return Reply::Whole(self.refused(&a, &self.req_url(&req), Some(route), Refusal::BalanceShort));
        };
        // what the session must be able to pay to be served at all is the same with a body and
        // without: the request, the first second and the first byte. A HEAD is charged the
        // request's price alone, which on a route priced by the byte or the second is nothing;
        // were it also served to a session with nothing, a buyer that asked for tickets and paid
        // none would read the service's headers (a length, an ETag) for as long as its session
        // lives. So no answer of a priced route goes to a session that has no balance
        let first_byte = u64::from(route.price.byte_msat > 0);
        let needed = route
            .price
            .request_msat
            .saturating_add(route.price.second_msat)
            .saturating_add(first_byte)
            .saturating_add(token_bound);
        let charged = {
            let mut st = self.lock();
            if st.book.chargeable(&a.session, on_pledge) < needed {
                Err(Refusal::BalanceShort)
            } else {
                st.book.charge(&a.session, reserve, on_pledge, self.now())
            }
        };
        if let Err(why) = charged {
            return Reply::Whole(self.refused(&a, &self.req_url(&req), Some(route), why));
        }
        let refund = |msat: u64| self.lock().book.refund(&a.session, msat);
        // step 5
        let sent = match &prepared {
            Some(p) => self.send_upstream_body(route, &req, &p.body),
            None => self.send_upstream(route, &req),
        };
        let mut answer = match sent {
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
            tokens: prepared.as_ref().map(|p| TokenCall { body_len: req.body.len() as u64, max_output: p.max_output }),
            cap_msat: req.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(xbt402::ticket::MAX_MSAT_HEADER))
                .and_then(|(_, v)| v.trim().parse::<u64>().ok()),
        };
        let event_stream = answer.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v.to_ascii_lowercase().starts_with("text/event-stream"));
        // a body priced by the token has no length known before it is counted
        let length = if m.tokens.is_some() { None } else { answer.length };
        if m.tokens.is_some() {
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length"));
        }
        let (gw, src) = (self.clone(), answer.body);
        if m.tokens.is_some() {
            return Reply::Stream(Streamed {
                status: answer.status,
                headers,
                length,
                body: Box::new(move |out| gw.pump_tokens(m, src, out, open, event_stream)),
            });
        }
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
    fn pay_bytes(&self, m: &Metered, meter: &Meter, want: u64, gone: &mut dyn FnMut() -> bool) -> (u64, u64) {
        let on_pledge = m.route.release == Release::AfterVerify;
        let deadline = Instant::now() + self.cfg.times.refill_wait;
        let mut st = self.lock();
        let room = m.room(meter.charged());
        loop {
            let take = meter.affordable(want, st.book.chargeable(&m.session, on_pledge).min(room));
            // the buyer's own limit for this answer is reached: it ends now, with nothing more charged
            if take == 0 && meter.affordable(want, room) == 0 {
                return (0, 0);
            }
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
            // a buyer that has gone is not waited for: the answer ends now, not at the deadline
            drop(st);
            if gone() {
                return (0, 0);
            }
            st = self.lock();
            st = self
                .credited
                .wait_timeout(st, left.min(GONE_CHECK))
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
    }

    /// Take `due` msat (seconds that have started, tokens counted), waiting as [`Gateway::pay_bytes`] does.
    /// For an answer that has charged `charged` msat so far: refused when `due` would take it past
    /// the buyer's own limit for it.
    fn pay_msat_charged(&self, m: &Metered, due: u64, charged: u64, gone: &mut dyn FnMut() -> bool) -> bool {
        if due > m.room(charged) {
            return false;
        }
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
            drop(st);
            if gone() {
                return false;
            }
            st = self.lock();
            st = self
                .credited
                .wait_timeout(st, left.min(GONE_CHECK))
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
                Some((secs, due)) if self.pay_msat_charged(&m, due, meter.charged(), &mut || out.gone()) => meter.seconds_charged(secs, due),
                _ => break stopped("no balance for another second"),
            }
            let n = match src.read(&mut buf) {
                Ok(0) => break Ok(()),
                Ok(n) => n,
                Err(e) => break Err(e),
            };
            let mut off = 0;
            while off < n {
                let (take, due) = self.pay_bytes(&m, &meter, (n - off) as u64, &mut || out.gone());
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

impl Gateway {
    /// A body priced by the token: read event by event (a streamed answer) or whole, each part
    /// paid for before it is sent, and the call settled on the counts the service states at its
    /// end ([`xbt402::tokens`]). When the balance stops covering the next part, nothing more is
    /// sent and the service's connection is closed, so it stops writing.
    fn pump_tokens(
        &self,
        m: Metered,
        mut src: Box<dyn Read + Send>,
        out: &mut dyn BodyWriter,
        _open: OpenResponse,
        event_stream: bool,
    ) -> io::Result<()> {
        use xbt402::tokens::{settle, whole, Sse, Usage, MAX_WHOLE};
        let call = m.tokens.expect("a call priced by the token");
        let rule = m.route.price.tokens;
        let mut hash = Sha256::new();
        let (mut sent_bytes, mut counted, mut charged) = (0u64, 0u64, 0u64);
        let mut usage = Usage::default();
        let stopped = |why: &str| Err(io::Error::other(why.to_string()));
        // pay `due`, then send `bytes`; false: not paid, or the buyer is gone
        let mut part = |bytes: &[u8], due: u64, charged: &mut u64, sent: &mut u64, hash: &mut Sha256| -> io::Result<bool> {
            if due > 0 && !self.pay_msat_charged(&m, due, *charged, &mut || out.gone()) {
                return Ok(false);
            }
            *charged = charged.saturating_add(due);
            if let Err(e) = out.send(bytes) {
                self.lock().book.refund(&m.session, due);
                *charged = charged.saturating_sub(due);
                return Err(e);
            }
            hash.update(bytes);
            *sent = sent.saturating_add(bytes.len() as u64);
            Ok(true)
        };
        // what is due to bring the charge to the settled total (0 when it is there or above)
        let settle_due = |counted: u64, usage: Usage, charged: u64| -> (u64, u64) {
            let t = settle(call.body_len, call.max_output, counted, usage);
            let total = rule.cost(t).unwrap_or(u64::MAX);
            (total.saturating_sub(charged), charged.saturating_sub(total))
        };
        let mut buf = vec![0u8; CHUNK];
        let result: io::Result<()> = if event_stream {
            let mut sse = Sse::default();
            'body: loop {
                if m.started.elapsed() > self.cfg.times.max_response {
                    break stopped("the response reached its longest life");
                }
                let n = match src.read(&mut buf) {
                    Ok(0) => {
                        if let Some(ev) = sse.rest() {
                            match part(&ev.bytes, 0, &mut charged, &mut sent_bytes, &mut hash) {
                                Ok(true) => {}
                                Ok(false) => break 'body stopped("no balance for the rest"),
                                Err(e) => break 'body Err(e),
                            }
                        }
                        break Ok(());
                    }
                    Ok(n) => n,
                    Err(e) => break Err(e),
                };
                let events = match sse.feed(&buf[..n]) {
                    Ok(evs) => evs,
                    Err(why) => break stopped(why),
                };
                for ev in events {
                    // output as it goes, never past the request's bound; with the first event, the
                    // input as far as it can be told before the counts (a quarter of the body), so a
                    // buyer that stops reading early has paid for what the service read
                    let more = ev.tokens.min(call.max_output.saturating_sub(counted));
                    let mut due = rule.output_due(counted, more).unwrap_or(u64::MAX);
                    if sent_bytes == 0 && charged == 0 {
                        due = due.saturating_add(rule.input_cost(xbt402::tokens::input_guess(call.body_len)).unwrap_or(u64::MAX));
                    }
                    counted += more;
                    if let Some(u) = ev.usage {
                        // the counts: the call is settled before the event that states them is sent
                        usage = u;
                        let (up, down) = settle_due(counted, usage, charged.saturating_add(due));
                        due = due.saturating_add(up).saturating_sub(down);
                    }
                    match part(&ev.bytes, due, &mut charged, &mut sent_bytes, &mut hash) {
                        Ok(true) => {}
                        Ok(false) => break 'body stopped("no balance for the next tokens"),
                        Err(e) => break 'body Err(e),
                    }
                }
            }
        } else {
            // a whole answer: read, counted, paid for, then sent
            let mut body = vec![];
            match (&mut src).take(MAX_WHOLE as u64 + 1).read_to_end(&mut body) {
                Err(e) => Err(e),
                Ok(_) if body.len() > MAX_WHOLE => stopped("the answer is larger than the gateway reads whole"),
                Ok(_) => {
                    let (guess, u) = whole(&body);
                    usage = u;
                    counted = guess.min(call.max_output);
                    let (due, _) = settle_due(counted, usage, 0);
                    match part(&body, due, &mut charged, &mut sent_bytes, &mut hash) {
                        Ok(true) => Ok(()),
                        Ok(false) => stopped("no balance for the answer"),
                        Err(e) => Err(e),
                    }
                }
            }
        };
        // a stream that ended without its counts is settled on its chunks, and one that was charged
        // more than its counts settle at is given the difference back
        if result.is_ok() {
            let (up, down) = settle_due(counted, usage, charged);
            if up > 0 && self.pay_msat_charged(&m, up, charged, &mut || false) {
                charged = charged.saturating_add(up);
            }
            if down > 0 {
                self.lock().book.refund(&m.session, down);
                charged = charged.saturating_sub(down);
            }
        }
        // the service's connection is closed here, whatever was left of its answer
        drop(src);
        let total = m.at_head.saturating_add(charged);
        let last = self.receipt(&m.session, m.seq, total, &m.digest, m.status, &hex::encode(hash.finalize()));
        let mut st = self.lock();
        if let Some(mut r) = last {
            let t = settle(call.body_len, call.max_output, counted, usage);
            r["bytes"] = sent_bytes.into();
            r["complete"] = result.is_ok().into();
            r["tokens"] = json!({"input": t.input, "output": t.output});
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

    fn lottery_path<'a>(&self, path: &'a str) -> Option<&'a str> {
        path.strip_prefix(xbt402::lottery::SESSION_PATH)
            .and_then(|p| p.strip_prefix('/'))
    }
}

impl Handler for Service {
    fn body_limit(&self, _method: &str, target: &str) -> usize {
        let path = target.split('?').next().unwrap_or("");
        if self.session_path(path).is_some() || self.lottery_path(path).is_some() {
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
            // behind a named proxy on this machine every socket is loopback: the address it reports decides
            let loopback = gw.client_ip(&req).is_some_and(|a| a.is_loopback());
            return Reply::Whole(match (req.method.as_str(), call) {
                ("POST", "lock") => gw.lock_tickets(&req),
                ("POST", "release" | "cancel" | "status") => gw.session_call(&req, call),
                // the operator's view, for the machine the gateway runs on only
                ("GET", "health") if loopback => gw.health(),
                _ => error(404, "no_route", "no such session endpoint"),
            });
        }
        if let Some(call) = self.lottery_path(&path) {
            return Reply::Whole(match (req.method.as_str(), call) {
                ("POST", "open" | "draw" | "status" | "close") => gw.lottery_call(&req, call),
                _ => error(404, "no_route", "no such session endpoint"),
            });
        }
        if path == SERVICES_PATH && req.method == "GET" {
            return Reply::Whole(gw.services());
        }
        if path == LISTING_PATH && req.method == "GET" {
            return Reply::Whole(match gw.listing_doc() {
                Some(body) => json_response(200, &body),
                None => error(404, "no_route", "this seller publishes no listing"),
            });
        }
        gw.route(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xbt402::lottery::DrawError;
    use xbt402::ticket::PROTOCOL_CODES;

    /// Every code that follows `error(<status>, ` or `"error": ` in `src`, as written there.
    fn written_codes(src: &str) -> Vec<String> {
        let literal = |rest: &str| -> Option<String> {
            let rest = rest.trim_start().strip_prefix('"')?;
            let end = rest.find('"')?;
            let code = &rest[..end];
            (!code.is_empty() && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')).then(|| code.to_string())
        };
        let mut out = vec![];
        for (at, _) in src.match_indices("error(") {
            let rest = src[at + 6..].trim_start();
            let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 3 {
                if let Some(c) = rest[digits..].trim_start().strip_prefix(',').and_then(literal) {
                    out.push(c);
                }
            }
        }
        // `"error": "code"`, and `"error": if .. { "a" } else { "b" }`: every literal up to the end of the value
        for (at, _) in src.match_indices("\"error\":") {
            let rest = &src[at + 8..];
            // the value ends where the next key starts, or the object does
            let end = [", \"", ",\"", "})"].iter().filter_map(|e| rest.find(e)).min().unwrap_or(rest.len());
            let mut v = &rest[..end];
            while let Some(i) = v.find('"') {
                if let Some(c) = literal(&v[i..]) {
                    out.push(c);
                }
                v = &v[i + 1..];
                if let Some(j) = v.find('"') {
                    v = &v[j + 1..];
                } else {
                    break;
                }
            }
        }
        out
    }

    #[test]
    fn every_code_the_gateway_answers_with_is_one_the_wallet_names() {
        // a wallet repeats a seller's error only as one of the codes of `xbt402::ticket::PROTOCOL_CODES`;
        // a code that is not there it reports as nothing at all
        let mut codes: Vec<String> = vec![];
        // every refusal of the ticket book: the match has no wildcard, so a refusal added later is
        // a compile error here until it is listed
        let tickets = [Refusal::SessionUnknown, Refusal::BadAuth, Refusal::BadSeq(0), Refusal::TicketUnknown, Refusal::TicketNotLocked, Refusal::TicketUsed,
                       Refusal::TicketExpiring, Refusal::BalanceShort, Refusal::TooManyTickets, Refusal::TooManySessions, Refusal::SlotsShort(1),
                       Refusal::HeightUnknown, Refusal::PledgeOutstanding, Refusal::PrepaidFirst];
        for r in tickets {
            match r {
                Refusal::SessionUnknown | Refusal::BadAuth | Refusal::BadSeq(_) | Refusal::TicketUnknown | Refusal::TicketNotLocked | Refusal::TicketUsed
                | Refusal::TicketExpiring | Refusal::BalanceShort | Refusal::TooManyTickets | Refusal::TooManySessions | Refusal::SlotsShort(_)
                | Refusal::HeightUnknown | Refusal::PledgeOutstanding | Refusal::PrepaidFirst => codes.push(r.code().into()),
            }
        }
        // every refusal of the lottery's book, and every refusal of a value the seller's draw can give
        use crate::lottery::Refusal as Draws;
        let draws = [DrawError::AmountNotBelowWin, DrawError::ChainSpent, DrawError::PieceUnknown, DrawError::AmountMismatch, DrawError::DrawOutOfOrder,
                     DrawError::DrawUsed, DrawError::ValueConflict, DrawError::ValueReused];
        for r in [Draws::SessionUnknown, Draws::BadAuth, Draws::BadSeq(0), Draws::TooManySessions, Draws::WinSize, Draws::WinUnpaid, Draws::ValueMissing,
                  Draws::TooManyVoids].into_iter().chain(draws.into_iter().map(Draws::Draw)) {
            codes.push(r.code().into());
        }
        // and every code written out in the answers themselves
        // (of this file, the part before its tests)
        let own = include_str!("gateway.rs");
        let own = &own[..own.find("#[cfg(test)]").unwrap_or(own.len())];
        let written: Vec<String> = [own, include_str!("gateway/draws.rs")].iter().flat_map(|s| written_codes(s)).collect();
        for want in ["method_not_allowed", "internal", "bad_target", "no_route", "journal", "hash_refused", "node_unavailable", "upstream_unavailable"] {
            assert!(written.iter().any(|c| c == want), "the scan finds {want}: {written:?}");
        }
        codes.extend(written);
        for c in &codes {
            assert!(PROTOCOL_CODES.contains(&c.as_str()), "{c} is answered by the gateway and unknown to the wallet");
            assert_eq!(xbt402::ticket::protocol_code(Some(&json!(c))), c);
        }
    }
}
