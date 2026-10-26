//! The lottery over HTTP (`docs/TICKETS.md`, section 9): the session endpoints `open`, `draw`,
//! `status` and `close`, a request paid by draws, and a metered answer cut into pieces that are
//! each a draw. The rules of a session are [`crate::lottery`]'s; this file adds the node, the
//! service and the wire.
//!
//! A request of a lottery session, in order; each step names the rule it keeps:
//!
//! 1. **One reading of the target**, as for any route ([`Gateway::route`] did that already).
//! 2. **Authenticated, in order** ([`Book::authenticate`]): the HMAC binds the session, `seq` and
//!    the request digest, which covers a `draw`'s body and so every value in it.
//! 3. **Inside the window and the grace** ([`Book::blocked`]), on the node's own word about each
//!    unpaid win ([`Gateway::lottery_refresh`]): a buyer's claim that it paid moves nothing.
//! 4. **Only a route the terms offer by lottery** ([`crate::lottery::LotteryConfig::offers`]: its
//!    dearest piece is a small part of a win), and every piece below the session's own win
//!    (`amount_not_below_win` otherwise): a dearer piece is paid with tickets, whatever the
//!    request's header says.
//! 5. **Only what the runner allowed reaches the service**, and nothing the service says is read
//!    for money: a piece is the bytes the gateway itself sent and the seconds it itself counted.
//! 6. **A piece is a piece once it has left** ([`Book::serve`]): the buyer's value can only follow
//!    the work it pays for, so the gateway learns no result before it has served.
//! 7. **A reveal follows the value, and the disk** ([`Book::draw`], [`Gateway::lottery_call`]):
//!    the chain value of a draw leaves only in the answer to the request that brought its value,
//!    and only once the lottery's journal holds the draw on disk. A session outlives a restart
//!    with its chain, so this is what keeps a restart from taking a second value for a draw it
//!    has revealed for. A draw that cannot be written down ends its session, and nothing is
//!    revealed.
//! 8. **An invoice per win**, made by the node for the session's win size, with a preimage the
//!    gateway makes and forgets. Its hash is on disk before the node is asked for it, so a win
//!    paid across a restart is seen paid. A win is paid when the node shows that invoice settled
//!    in full.
//! 9. **Receipt**: every answer to an authenticated request carries one, signed by the receipt key.
use std::ops::{Deref, DerefMut};
use std::path::Path;

use xbt402::lottery::{self, DrawError, Kind, PieceId, RELEASE_AFTER_ANSWER, RELEASE_AFTER_VERIFY};

use super::*;
use crate::lottery::{Book as Draws, LotteryConfig, Rec as Logged, Refusal as Refused, Value32, MAX_BATCH};

/// The lottery's journal in the state directory, beside the tickets'.
pub const JOURNAL: &str = "lottery.jsonl";

/// The lottery's state beside the ticket book: its own lock, so that a draw never waits for a
/// ticket's settle.
pub(super) struct Lottery {
    state: Mutex<Journaled>,
    /// Signalled when a value is taken or a win is paid: answers that wait for either wake.
    pub(super) changed: Condvar,
}

/// The book and its journal under one lock: every change is appended in the order it was made.
pub(super) struct Journaled {
    book: Draws,
    store: Store<Logged>,
}

/// The book, locked. What it logged is appended to the journal when the guard goes, still under
/// the lock (an append is a write to the file's cache; what must be on disk is synced by the
/// caller, without the lock, from [`Guard::written`]).
pub(super) struct Guard<'a> {
    inner: Option<MutexGuard<'a, Journaled>>,
}

impl Deref for Guard<'_> {
    type Target = Draws;
    fn deref(&self) -> &Draws {
        &self.inner.as_ref().expect("a guard holds its lock until it goes").book
    }
}

impl DerefMut for Guard<'_> {
    fn deref_mut(&mut self) -> &mut Draws {
        &mut self.inner.as_mut().expect("a guard holds its lock until it goes").book
    }
}

impl Guard<'_> {
    /// Append what the book has logged; the journal's file, to sync, or None where it could not
    /// be written (the reason is on standard error).
    pub(super) fn written(&mut self) -> Option<Arc<std::fs::File>> {
        let j = self.inner.as_mut()?;
        let recs = j.book.take_log();
        // a gateway that is stopping writes nothing more, and says nothing of it
        if j.store.is_closed() {
            return None;
        }
        match j.store.append(&recs) {
            Ok(()) => Some(j.store.handle()),
            Err(e) => {
                eprintln!("xbt-gateway: the lottery's journal could not be written: {e}");
                None
            }
        }
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        drop(self.written());
    }
}

impl Lottery {
    /// The lottery of `cfg` with the sessions its journal in `dir` holds, at `now`. `Err`: the
    /// journal cannot be read whole, and nothing starts. Sessions whose records do not hold
    /// together are left out, and reported.
    pub(super) fn open(cfg: LotteryConfig, dir: &Path, now: u64) -> Result<Self, Error> {
        let (mut store, recs) = Store::open_beside(dir, JOURNAL).map_err(|e| Error::Journal(format!("{JOURNAL}: {e}")))?;
        let (book, problems) = Draws::restore(cfg, &recs, now);
        for p in problems {
            eprintln!("xbt-gateway: {p}; it is forgotten");
        }
        store.compact(&book.snapshot()).map_err(|e| Error::Journal(format!("{JOURNAL}: {e}")))?;
        Ok(Self { state: Mutex::new(Journaled { book, store }), changed: Condvar::new() })
    }

    pub(super) fn lock(&self) -> Guard<'_> {
        Guard { inner: Some(self.state.lock().unwrap_or_else(|p| p.into_inner())) }
    }

    /// Wait on [`Lottery::changed`] for at most `dur`, with what was logged written first.
    fn wait<'a>(&'a self, mut g: Guard<'a>, dur: Duration) -> Guard<'a> {
        drop(g.written());
        let Some(inner) = g.inner.take() else { return g };
        let (inner, _) = self.changed.wait_timeout(inner, dur).unwrap_or_else(|p| p.into_inner());
        Guard { inner: Some(inner) }
    }

    /// Nothing more is written: the gateway is stopping.
    pub(super) fn close(&self) {
        let mut g = self.lock();
        drop(g.written());
        if let Some(j) = g.inner.as_mut() {
            j.store.close();
        }
    }

    /// The journal's maintenance, from the janitor: rewritten when it has grown, and its file to sync.
    fn tend(&self) -> Arc<std::fs::File> {
        let mut g = self.lock();
        drop(g.written());
        let j = g.inner.as_mut().expect("a guard holds its lock until it goes");
        if j.store.lines() > COMPACT_AT {
            let snapshot = j.book.snapshot();
            if let Err(e) = j.store.compact(&snapshot) {
                eprintln!("xbt-gateway: the lottery's journal could not be rewritten: {e}");
            }
        }
        j.store.handle()
    }
}

/// `payload` of PAYMENT-SIGNATURE for a lottery session, read strictly.
struct DrawPay {
    session: String,
    seq: u64,
    auth: String,
}

/// What a streamed answer needs to cut itself into pieces and sign its last receipt.
struct Pieces {
    session: String,
    seq: u64,
    digest: String,
    req: [u8; 32],
    status: u16,
    route: Route,
    /// The body's length where the service stated it.
    length: Option<u64>,
    /// Served before the head: the request's own piece.
    at_head: u64,
    started: Instant,
}

/// An answer of a lottery session that is still being sent: its session is not idle.
struct OpenAnswer {
    gw: Arc<Gateway>,
    session: String,
}

impl Drop for OpenAnswer {
    fn drop(&mut self) {
        let now = self.gw.now();
        if let Some(l) = &self.gw.lottery {
            l.lock().response(&self.session, false, now);
        }
    }
}

fn decimal(v: Option<&Value>) -> Option<u64> {
    let s = v?.as_str()?;
    (!s.is_empty() && s.len() <= 20 && s.bytes().all(|c| c.is_ascii_digit()) && (s == "0" || !s.starts_with('0')))
        .then(|| s.parse().ok())
        .flatten()
}

fn piece_id(v: &Value) -> Option<PieceId> {
    Some(PieceId {
        seq: v.get("seq")?.as_u64()?,
        kind: Kind::parse(v.get("kind")?.as_str()?)?,
        k: v.get("k")?.as_u64()?,
    })
}

impl Gateway {
    /// Whether a request's PAYMENT-SIGNATURE names the lottery entry (and so belongs here).
    pub(super) fn pays_by_lottery(req: &Request) -> bool {
        req.header("PAYMENT-SIGNATURE")
            .and_then(|raw| unb64json(raw).ok())
            .is_some_and(|v| v.get("accepted").and_then(|a| a.get("scheme")).and_then(Value::as_str) == Some(lottery::SCHEME))
    }

    /// The lottery entry of a route's 402, where the runner offers the lottery and the route's
    /// dearest piece is a small enough part of a win.
    ///
    /// `head`: the terms are for a HEAD. A HEAD has no body, so its only piece is the request's
    /// own; on a route with no price per request it has none, and nothing to draw for. Such a
    /// request is not offered by lottery ([`Gateway::lottery_route`] refuses it): a lottery
    /// session costs nothing to open, and would read the service's headers for nothing.
    pub(super) fn lottery_entry(&self, route: &Route, head: bool) -> Option<Value> {
        let cfg = self.cfg.lottery.as_ref()?;
        if !cfg.offers(&route.price) || (head && route.price.request_msat == 0) {
            return None;
        }
        let release = match route.release {
            Release::AfterVerify => RELEASE_AFTER_VERIFY,
            Release::WithRequest => RELEASE_AFTER_ANSWER,
        };
        let mut e = self.lottery_terms(cfg).accepts(route.price.request_msat, release, &route.price.terms());
        // a win can be paid by the node's offer as well as by its invoice
        if let Some(o) = self.offer_text() {
            e["extra"][xbt402::offer::EXTRA_OFFER] = o.into();
        }
        Some(e)
    }

    pub(super) fn lottery_terms(&self, cfg: &crate::lottery::LotteryConfig) -> lottery::Terms {
        lottery::Terms {
            network: self.cfg.network.clone(),
            pay_to: self.terms.pay_to.clone(),
            win_msat: cfg.win_msat,
            min_win_msat: cfg.min_win_msat,
            win_blocks: cfg.win_blocks,
            window: cfg.window,
            grace_seconds: cfg.grace_seconds,
            grace_pieces: cfg.grace_pieces,
            max_unpaid_wins: cfg.max_unpaid_wins,
            chain_draws: cfg.chain_draws,
            piece_bytes: cfg.piece_bytes,
            receipt_key: self.terms.receipt_key.clone(),
            session: lottery::SESSION_PATH.into(),
        }
    }

    /// What an operator reads of the lottery: the sessions now, and the totals since the start.
    pub(super) fn lottery_health(&self) -> Value {
        match &self.lottery {
            None => Value::Null,
            Some(l) => {
                let b = l.lock();
                let t = b.totals();
                json!({"sessions": b.sessions(), "opened": t.opened, "servedMsat": t.served_msat.to_string(), "drawn": t.drawn, "wins": t.wins,
                       "paidWins": t.paid_wins, "wonMsat": t.won_msat.to_string(), "paidMsat": t.paid_msat.to_string()})
            }
        }
    }

    /// One round of the janitor for the lottery: quiet sessions are forgotten.
    /// One round of the janitor for the lottery: quiet sessions are forgotten, each after a last
    /// look at the node for wins it shows paid, and the journal is put on disk.
    pub(super) fn lottery_tick(&self) {
        if let Some(l) = &self.lottery {
            let now = self.now();
            // a win paid between requests is counted when the node shows it, not when the buyer
            // next asks for something: the operator's paidWins and a session's own count keep up
            let due = l.lock().due(now);
            let mut look = l.lock().awaiting_pay();
            look.extend(due.iter().cloned());
            look.sort();
            look.dedup();
            for id in &look {
                self.lottery_settle(l, id);
            }
            l.lock().sweep(now);
            let file = l.tend();
            self.sync(&file);
        }
    }

    /// Every session the journal brought back: a win its buyer paid while the gateway was down
    /// is seen paid now, whether or not that buyer comes back. The node is asked, nothing is made.
    pub(super) fn lottery_restored(&self) {
        if let Some(l) = &self.lottery {
            let ids: Vec<String> = l.lock().ids();
            for id in &ids {
                self.lottery_settle(l, id);
            }
        }
    }

    /// Ask the node about each unpaid win of `session` that has an invoice: one it shows settled
    /// in full is paid. Nothing is cancelled and nothing made.
    fn lottery_settle(&self, l: &Lottery, session: &str) {
        let (hashes, win_msat) = {
            let b = l.lock();
            match b.session(session) {
                Some(s) => (s.unpaid.iter().filter(|w| !w.issuing).filter_map(|w| w.invoice.as_ref().map(|i| i.hash)).collect::<Vec<Hash>>(), s.win_msat),
                None => return,
            }
        };
        for h in hashes {
            if let Ok(Some(inv)) = self.node.lookup(&h) {
                if inv.state == InvoiceState::Settled && inv.paid_msat >= win_msat && l.lock().win_paid(session, &h) {
                    l.changed.notify_all();
                }
            }
        }
    }

    fn draw_pay_header(&self, req: &Request) -> Result<Option<DrawPay>, Response> {
        let mut found = req.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-SIGNATURE"));
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
        if accepted.get("scheme").and_then(Value::as_str) != Some(lottery::SCHEME)
            || !xbt402::ticket::on_network(accepted, &self.cfg.network)
        {
            return Err(bad("accepted is not this seller's lottery entry"));
        }
        let p = v.get("payload").and_then(Value::as_object).ok_or_else(|| bad("no payload"))?;
        if p.keys().any(|k| !["session", "seq", "auth"].contains(&k.as_str())) {
            return Err(bad("a lottery payload is session, seq and auth: values travel in a draw request"));
        }
        let text = |k: &str| p.get(k).and_then(Value::as_str);
        let session = text("session")
            .filter(|s| s.len() == 32 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
            .ok_or_else(|| bad("no session"))?
            .to_string();
        let seq = p.get("seq").and_then(Value::as_u64).ok_or_else(|| bad("seq is a whole number"))?;
        let auth = text("auth").filter(|a| a.len() == 64).ok_or_else(|| bad("no auth"))?.to_string();
        Ok(Some(DrawPay { session, seq, auth }))
    }

    fn draw_authenticate(&self, l: &Lottery, req: &Request, pay: &DrawPay) -> Result<Authed, Response> {
        let digest = request_digest_v2(&req.method, &self.url(&req.target), &req.body);
        let now = self.now();
        let checked = l.lock().authenticate(&pay.session, pay.seq, now, |key| {
            auth_eq(&lottery::request_auth(key, &pay.session, pay.seq, &digest), &pay.auth)
        });
        match checked {
            Ok(()) => Ok(Authed { session: pay.session.clone(), seq: pay.seq, digest, ticket: None, head: req.method == "HEAD" }),
            // nothing about a session is told to someone who has not shown its key
            Err(Refused::BadAuth) => Err(error(401, "bad_auth", "the request is not authenticated for this session")),
            Err(Refused::BadSeq(next)) => Err(json_response(402, &json!({"error": "bad_seq", "nextSeq": next}))),
            Err(why) => Err(json_response(402, &json!({"error": why.code()}))),
        }
    }

    fn draw_view(&self, l: &Lottery, session: &str) -> Value {
        let b = l.lock();
        match b.session(session) {
            Some(s) => {
                let wins: Vec<Value> = s
                    .unpaid
                    .iter()
                    .map(|w| json!({"draw": w.draw, "invoice": w.invoice.as_ref().and_then(|i| i.text.as_deref())}))
                    .collect();
                json!({"id": session, "nextSeq": s.next_seq, "winMsat": s.win_msat.to_string(), "drawn": s.drawn(), "pending": s.pending(),
                       "servedMsat": s.served_msat.to_string(), "wonMsat": s.won_msat().to_string(), "paidMsat": s.paid_msat().to_string(),
                       "voids": s.voids, "wins": wins})
            }
            None => Value::Null,
        }
    }

    /// A signed receipt: the session's totals as they are now, and this request's own numbers.
    fn draw_receipt(&self, session: &str, seq: u64, charged: u64, digest: &str, status: u16, body_hash: &str) -> Option<Value> {
        let l = self.lottery.as_ref()?;
        // a session that was forgotten meanwhile has no totals to sign: no receipt, never zeros
        let (drawn, served, won, paid) = {
            let b = l.lock();
            b.session(session).map(|s| (s.drawn(), s.served_msat, s.won_msat(), s.paid_msat()))?
        };
        let mut r = json!({"scheme": lottery::SCHEME, "session": session, "seq": seq, "drawn": drawn, "servedMsat": served.to_string(),
                           "wonMsat": won.to_string(), "paidMsat": paid.to_string(), "charged": charged.to_string(), "req": digest,
                           "status": status, "bodyHash": body_hash});
        r["sig"] = hex::encode(ecdsa::sign(&self.key, &lottery::receipt_message(&r))).into();
        Some(r)
    }

    /// Any answer to an authenticated request of a lottery session: with its receipt.
    fn draw_answered(&self, a: &Authed, mut r: Response, charged: u64) -> Response {
        let receipt = self.draw_receipt(&a.session, a.seq, charged, &a.digest, r.status, &body_hash(&r.body));
        if let Some(receipt) = receipt {
            let sr = settlement_response(&receipt, &self.cfg.network, "", r.status < 400);
            r.headers.push(("PAYMENT-RESPONSE".into(), b64json(&sr)));
        }
        r
    }

    /// An authenticated request that is not served: the code, the terms again, the session's
    /// numbers and its unpaid wins with their invoices.
    fn draw_refused(&self, l: &Lottery, a: &Authed, target: &str, route: Option<&Route>, code: &str) -> Response {
        let (mut body, _) = self.required(target, route, a.head, None, Some(self.draw_view(l, &a.session)));
        body["error"] = code.into();
        let mut r = json_response(402, &body);
        r.headers.push(("PAYMENT-REQUIRED".into(), b64json(&body)));
        self.draw_answered(a, r, 0)
    }

    /// Bring a session's unpaid wins to what the node says: a win whose invoice the node shows
    /// settled in full is paid; a win with no invoice, or one whose invoice the node has cancelled
    /// (it lapsed unpaid), gets a new one. No lock is held while the node is asked.
    fn lottery_refresh(&self, l: &Lottery, session: &str) {
        // a win may have been paid by the node's offer: the node's list of its invoices says
        if self.offers.is_some() && l.lock().session(session).is_some_and(|s| !s.unpaid.is_empty()) {
            self.offer_sweep(true);
        }
        let (unpaid, win_msat, win_blocks, invoice_secs) = {
            let b = l.lock();
            match b.session(session) {
                Some(s) if !s.unpaid.is_empty() => (s.unpaid.clone(), s.win_msat, b.cfg().win_blocks, b.cfg().invoice_secs),
                _ => return,
            }
        };
        let mut paid = false;
        let settled = |inv: &Invoice| inv.state == InvoiceState::Settled && inv.paid_msat >= win_msat;
        for w in unpaid {
            let lapsed = match &w.invoice {
                None => true,
                // another request is asking the node for it at this moment
                Some(_) if w.issuing => false,
                Some(i) => match self.node.lookup(&i.hash) {
                    Ok(Some(inv)) if settled(&inv) => {
                        paid |= l.lock().win_paid(session, &i.hash);
                        false
                    }
                    // cancelled by the node when its time ran out: it can no longer be paid
                    Ok(Some(inv)) if inv.state == InvoiceState::Canceled => true,
                    Ok(None) => true,
                    // known here by its hash alone: the node was asked for it and the answer was lost, to
                    // a restart or to the node. The buyer may have been sent it, or not; it is cancelled
                    // on the node, and replaced once the node shows it cancelled, never before
                    Ok(Some(_)) if i.text.is_none() => {
                        drop(self.node.cancel(&i.hash));
                        match self.node.lookup(&i.hash) {
                            Ok(Some(inv)) if settled(&inv) => {
                                paid |= l.lock().win_paid(session, &i.hash);
                                false
                            }
                            Ok(Some(inv)) => inv.state == InvoiceState::Canceled,
                            Ok(None) => true,
                            Err(_) => false,
                        }
                    }
                    Ok(Some(_)) => false,
                    // no answer: the win is as it was, and is asked about again
                    Err(_) => false,
                },
            };
            if !lapsed {
                continue;
            }
            // one request at a time asks the node for a win's invoice: a second invoice for one win
            // could be paid and never be seen paid
            let mut preimage = [0u8; 32];
            preimage.copy_from_slice(&xbt_svc::random_bytes(32));
            let hash = Hash::from(Sha256::digest(preimage));
            let now = self.now();
            let claimed = {
                let mut b = l.lock();
                b.claim_invoice(session, w.draw, w.invoice.as_ref().map(|i| &i.hash), hash, now).then(|| b.written())
            };
            let Some(file) = claimed else { continue };
            // the invoice's hash on disk before the node is asked: an invoice the node makes is never
            // one the journal forgot, so a win paid across a restart is seen paid
            let made = match file {
                Some(f) if self.sync(&f) => self.node.add_invoice(&preimage, win_msat, win_blocks, invoice_secs).ok(),
                _ => None,
            };
            l.lock().win_invoiced(session, w.draw, &hash, made);
            l.changed.notify_all();
        }
        if paid {
            l.changed.notify_all();
        }
        // an invoice another request is asking the node for: this one's answer waits for it, so that
        // a win is not listed without the invoice that pays it
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut b = l.lock();
        while b.session(session).is_some_and(|s| s.unpaid.iter().any(|w| w.issuing)) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            b = l.wait(b, left);
        }
    }

    /// Wait until the session may be served another piece: for a value, as long as an answer
    /// waits for a refill; for a win's payment, until that win's grace has run out (a wallet that
    /// pays many sellers queues its wins, and an answer that waits holds nothing but a
    /// connection). False: it may not.
    fn lottery_wait_clear(&self, l: &Lottery, session: &str) -> bool {
        let started = Instant::now();
        // how long this answer stands still at the most, from when it first did
        let mut budget = Duration::ZERO;
        loop {
            self.lottery_refresh(l, session);
            let b = l.lock();
            let now = self.now();
            budget = budget.max(match b.blocked(session, now) {
                None => return true,
                Some(Refused::ValueMissing) => self.cfg.times.refill_wait,
                Some(Refused::WinUnpaid) => self.cfg.times.refill_wait.max(Duration::from_secs(b.grace_left(session, now))),
                Some(_) => return false,
            });
            let left = budget.saturating_sub(started.elapsed());
            if left.is_zero() || self.stop.load(Ordering::SeqCst) {
                return false;
            }
            // a payment shows on the node, not on the condvar: look again soon
            drop(l.wait(b, left.min(Duration::from_millis(50))));
        }
    }

    // --- the session endpoints ----------------------------------------------------------------------

    pub(super) fn lottery_call(&self, req: &Request, call: &str) -> Response {
        let Some(l) = &self.lottery else {
            return error(404, "no_route", "this seller offers no lottery");
        };
        if call == "open" {
            return self.lottery_open(l, req);
        }
        let pay = match self.draw_pay_header(req) {
            Ok(Some(p)) => p,
            Ok(None) => return error(401, "bad_auth", "this endpoint needs PAYMENT-SIGNATURE"),
            Err(r) => return r,
        };
        let body = match Self::body_json(req) {
            Ok(b) => b,
            Err(r) => return r,
        };
        // read the body before the request's seq is used up
        let batch = if call == "draw" {
            match Self::draw_body(&body) {
                Ok(b) => b,
                Err(r) => return r,
            }
        } else {
            (vec![], vec![])
        };
        let a = match self.draw_authenticate(l, req, &pay) {
            Ok(a) => a,
            Err(r) => return r,
        };
        let mut out = json!({});
        if call == "draw" {
            let now = self.now();
            let (drawn, file) = {
                let mut b = l.lock();
                let d = b.draw(&a.session, &batch.0, &batch.1, now);
                let file = b.written();
                (d, file)
            };
            l.changed.notify_all();
            match drawn {
                Ok(d) => {
                    // the draws this answer reveals for are on disk before it leaves: a session outlives a
                    // restart, and a restart that had lost a draw would take a second value for it from a
                    // buyer that holds its chain value. A draw that cannot be written down ends the session
                    if d.reveal.is_some() && !file.is_some_and(|f| self.sync(&f)) {
                        l.lock().forget(&a.session);
                        return error(500, "journal", "the gateway could not record the draw: nothing was revealed, and the session is over");
                    }
                    out["drawn"] = d.reveal.map_or(0, |(i, _)| i).into();
                    out["reveal"] = d.reveal.map_or(Value::Null, |(_, c)| hex::encode(c).into());
                    out["refused"] = d.refused.map_or(Value::Null, |(draw, e)| json!({"draw": draw, "error": e.code()}));
                }
                Err(why) => return json_response(402, &json!({"error": why.code()})),
            }
        }
        // the wins of this request get their invoices here, and a win paid meanwhile leaves the list
        self.lottery_refresh(l, &a.session);
        let view = self.draw_view(l, &a.session);
        out["wins"] = view["wins"].clone();
        if call == "status" {
            let finals: Vec<Value> = l.lock().session(&a.session).map(|s| s.finals.iter().cloned().collect()).unwrap_or_default();
            out["responses"] = finals.into();
        }
        out["session"] = view;
        let answer = self.draw_answered(&a, json_response(200, &out), 0);
        if call == "close" {
            let now = self.now();
            l.lock().close(&a.session, now);
        }
        answer
    }

    fn lottery_open(&self, l: &Lottery, req: &Request) -> Response {
        let body = match Self::body_json(req) {
            Ok(b) => b,
            Err(r) => return r,
        };
        if body.get("version").and_then(Value::as_str) != Some(lottery::VERSION) {
            return error(400, "bad_request", "version is lottery/0");
        }
        let asked = match body.get("winMsat") {
            None | Some(Value::Null) => None,
            Some(v) => match decimal(Some(v)) {
                Some(w) => Some(w),
                None => return error(400, "bad_request", "winMsat is a decimal string"),
            },
        };
        let addr = addr_name(self.client_ip(req));
        // the caps first: a request they refuse costs no chain
        let (win_msat, chain_draws) = {
            let b = l.lock();
            let size = b.room(&addr).and_then(|()| b.win_size(asked));
            match size {
                Ok(w) => (w, b.cfg().chain_draws),
                Err(why) => return json_response(402, &json!({"error": why.code()})),
            }
        };
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&xbt_svc::random_bytes(32));
        let Ok(chain) = lottery::Chain::new(seed, chain_draws) else {
            return error(500, "internal", "the chain could not be made");
        };
        let mut entropy = [0u8; 48];
        entropy.copy_from_slice(&xbt_svc::random_bytes(48));
        let opened = {
            let mut b = l.lock();
            b.open(&entropy, seed, chain, &addr, win_msat, self.now()).map(|id| {
                let anchor = b.anchor(&id).unwrap_or([0; 32]);
                (id, anchor)
            })
        };
        match opened {
            Ok((id, anchor)) => json_response(
                200,
                &json!({"session": id, "key": hex::encode(&entropy[16..]), "anchor": hex::encode(anchor), "winMsat": win_msat.to_string(),
                        "chainDraws": chain_draws}),
            ),
            Err(why) => json_response(402, &json!({"error": why.code()})),
        }
    }

    /// The values and the voids of a `draw` request's body, read strictly.
    fn draw_body(body: &Map<String, Value>) -> Result<(Vec<Value32>, Vec<PieceId>), Response> {
        let bad = |what: &str| error(400, "bad_request", what);
        if body.keys().any(|k| !["values", "void"].contains(&k.as_str())) {
            return Err(bad("a draw request is values and void"));
        }
        let list = |k: &str| match body.get(k) {
            None => Ok(&[][..]),
            Some(Value::Array(a)) if a.len() <= MAX_BATCH => Ok(a.as_slice()),
            Some(_) => Err(bad("values and void are lists of at most 64")),
        };
        let mut values = vec![];
        for v in list("values")? {
            let read = || {
                Some(Value32 {
                    draw: v.get("draw")?.as_u64()?,
                    piece: piece_id(v)?,
                    amount_msat: decimal(v.get("amountMsat"))?,
                    value: hex32(v.get("value")?.as_str()?)?,
                })
            };
            values.push(read().ok_or_else(|| bad("a value is draw, seq, kind, k, amountMsat and value (64 lower-case hex characters)"))?);
        }
        let mut voids = vec![];
        for v in list("void")? {
            voids.push(piece_id(v).ok_or_else(|| bad("a void is seq, kind and k"))?);
        }
        Ok((values, voids))
    }

    // --- a priced route, paid by draws --------------------------------------------------------------

    /// Mark one piece as served; what it cost.
    fn lottery_serve(&self, l: &Lottery, m: &Pieces, kind: Kind, k: u64, amount_msat: u64) -> Result<u64, Refused> {
        l.lock().serve(&m.session, Draws::piece(m.seq, m.req, kind, k, amount_msat))?;
        Ok(amount_msat)
    }

    pub(super) fn lottery_route(self: &Arc<Self>, req: Request, route: &Route) -> Reply {
        let head_only = req.method == "HEAD";
        let Some(l) = &self.lottery else {
            return Reply::Whole(self.unpaid(&req.target, route, head_only));
        };
        let pay = match self.draw_pay_header(&req) {
            Ok(Some(p)) => p,
            Ok(None) => return Reply::Whole(self.unpaid(&req.target, route, head_only)),
            Err(r) => return Reply::Whole(r),
        };
        let a = match self.draw_authenticate(l, &req, &pay) {
            Ok(a) => a,
            Err(r) => return Reply::Whole(r),
        };
        let Some(digest) = hex32(&a.digest) else {
            return Reply::Whole(error(500, "internal", "a request digest that is not 32 bytes"));
        };
        self.lottery_refresh(l, &a.session);
        let (blocked, win_msat, dearest, offered) = {
            let b = l.lock();
            (b.blocked(&a.session, self.now()), b.session(&a.session).map_or(0, |s| s.win_msat), b.cfg().dearest_piece(&route.price), b.cfg().offers(&route.price))
        };
        if let Some(why) = blocked {
            return Reply::Whole(self.draw_refused(l, &a, &req.target, Some(route), why.code()));
        }
        // the 402 offers the lottery only for a route whose dearest piece is a small part of a win, and
        // a buyer that names the lottery all the same is held to that: it is the buyer that reads no 402
        // whom the rule is for
        // and a HEAD of a route with no price per request has no piece at all: it is not a draw, and a
        // session that costs nothing to open is not told the service's headers for it. Its 402 lists
        // tickets only
        if !offered || dearest.is_none_or(|d| d >= win_msat) || (head_only && route.price.request_msat == 0) {
            return Reply::Whole(self.draw_refused(l, &a, &req.target, Some(route), DrawError::AmountNotBelowWin.code()));
        }
        let mut answer = match self.upstream.send(&req.method, &req.target, &forwarded(route, &req.headers), &req.body) {
            // a service behind the gateway does not ask for payment through it
            Ok(ans) if ans.status != 402 => ans,
            _ => {
                return Reply::Whole(self.draw_answered(&a, error(502, "upstream_unavailable", "the service gave no answer; no piece was served"), 0));
            }
        };
        let headers = Self::passed_headers(&answer);
        if answer.status >= 400 {
            // an error is not a piece: passed on, capped, and no draw is owed for it
            let passed = match Self::read_body(&mut answer.body, ERROR_BODY) {
                Ok(body) => Response::new(answer.status, headers, body),
                Err(_) => error(502, "upstream_unavailable", "the service stopped in the middle of its answer; no piece was served"),
            };
            return Reply::Whole(self.draw_answered(&a, passed, 0));
        }
        let m = Pieces {
            session: a.session.clone(),
            seq: a.seq,
            digest: a.digest.clone(),
            req: digest,
            status: answer.status,
            route: route.clone(),
            length: answer.length,
            at_head: route.price.request_msat,
            started: Instant::now(),
        };
        let no_body = head_only || matches!(answer.status, 100..=199 | 204 | 304);
        let small = if !no_body && !route.price.metered() && answer.length.is_some_and(|n| n <= WHOLE_BODY) {
            let want = answer.length.unwrap_or(0);
            match Self::read_body(&mut answer.body, want) {
                Ok(body) if body.len() as u64 == want => Some(body),
                _ => {
                    return Reply::Whole(self.draw_answered(
                        &a,
                        error(502, "upstream_unavailable", "the service stopped in the middle of its answer; no piece was served"),
                        0,
                    ));
                }
            }
        } else {
            None
        };
        // the request's own piece: it has left when the answer's head does. The window is asked
        // again as the piece is marked: requests of one session that arrived together each found room
        if let Err(why) = self.lottery_serve(l, &m, Kind::Request, 0, m.at_head) {
            let code = match why {
                Refused::Draw(DrawError::AmountNotBelowWin) => DrawError::AmountNotBelowWin.code(),
                Refused::Draw(_) => DrawError::ChainSpent.code(),
                other => other.code(),
            };
            return Reply::Whole(self.draw_refused(l, &a, &req.target, Some(route), code));
        }
        if no_body && m.at_head == 0 {
            // the service answered a GET without a body (not modified, no content) on a route with no
            // price per request: no piece was served, so nothing is owed, and nothing of the service's
            // is told but that status. A session of draws has no balance to have paid from
            let mut headers = vec![];
            if let Some(receipt) = self.draw_receipt(&a.session, a.seq, 0, &a.digest, answer.status, &body_hash(b"")) {
                headers.push(("PAYMENT-RESPONSE".into(), b64json(&settlement_response(&receipt, &self.cfg.network, "", true))));
            }
            return Reply::Stream(Streamed { status: answer.status, headers, length: None, body: Box::new(|_| Ok(())) });
        }
        if no_body {
            // the answer keeps the length the service stated (what a HEAD is asked for)
            let mut headers = headers;
            if let Some(receipt) = self.draw_receipt(&a.session, a.seq, m.at_head, &a.digest, answer.status, &body_hash(b"")) {
                headers.push(("PAYMENT-RESPONSE".into(), b64json(&settlement_response(&receipt, &self.cfg.network, "", true))));
            }
            return Reply::Stream(Streamed { status: answer.status, headers, length: answer.length, body: Box::new(|_| Ok(())) });
        }
        if let Some(body) = small {
            return Reply::Whole(self.draw_answered(&a, Response::new(answer.status, headers, body), m.at_head));
        }
        // a body that is metered, long, or of unknown length: sent as it arrives, piece by piece
        l.lock().response(&a.session, true, self.now());
        let open = OpenAnswer { gw: self.clone(), session: a.session.clone() };
        let mut headers = headers;
        if let Some(head) = self.draw_receipt(&a.session, a.seq, m.at_head, &a.digest, answer.status, "") {
            let mut sr = settlement_response(&head, &self.cfg.network, "", true);
            sr["extra"]["stream"] = true.into();
            headers.push(("PAYMENT-RESPONSE".into(), b64json(&sr)));
        }
        let (gw, length, src) = (self.clone(), answer.length, answer.body);
        Reply::Stream(Streamed { status: answer.status, headers, length, body: Box::new(move |out| gw.lottery_pump(m, src, out, open)) })
    }

    /// A metered body, cut into pieces: each piece is served only inside the window and the grace,
    /// and is a piece (a draw the buyer owes a value for) once all of it has been sent. Ends when
    /// the service ends, the buyer stops reading, or the buyer stops sending values or paying wins.
    fn lottery_pump(&self, m: Pieces, mut src: Box<dyn Read + Send>, out: &mut dyn BodyWriter, _open: OpenAnswer) -> io::Result<()> {
        let Some(l) = &self.lottery else { return Ok(()) };
        let price = m.route.price;
        let piece_bytes = l.lock().cfg().piece_bytes.max(1);
        let by_bytes = price.byte_msat > 0;
        let mut hash = Sha256::new();
        let mut buf = vec![0u8; CHUNK];
        let (mut sent, mut seconds, mut charged, mut last_piece_end) = (0u64, 0u64, m.at_head, 0u64);
        let stopped = |why: &str| Err(io::Error::other(why.to_string()));
        let bytes_piece = |k: u64, from: u64, to: u64| {
            let amount = crate::lottery::LotteryConfig::bytes_amount(&price, from, to).ok_or(Refused::Draw(DrawError::AmountNotBelowWin))?;
            self.lottery_serve(l, &m, Kind::Bytes, k, amount)
        };
        let result = 'body: loop {
            let elapsed = m.started.elapsed();
            if elapsed > self.cfg.times.max_response {
                break stopped("the response reached its longest life");
            }
            // a second is a piece when it starts
            while price.second_msat > 0 && seconds <= elapsed.as_secs() {
                if !self.lottery_wait_clear(l, &m.session) {
                    break 'body stopped("no value or no payment for another second");
                }
                match self.lottery_serve(l, &m, Kind::Second, seconds, price.second_msat) {
                    Ok(a) => charged = charged.saturating_add(a),
                    Err(_) => break 'body stopped("no draw left for another second"),
                }
                seconds += 1;
            }
            let n = match src.read(&mut buf) {
                Ok(0) => break Ok(()),
                Ok(n) => n,
                Err(e) => break Err(e),
            };
            let mut off = 0;
            while off < n {
                let in_piece = sent % piece_bytes;
                if by_bytes && in_piece == 0 && !self.lottery_wait_clear(l, &m.session) {
                    break 'body stopped("no value or no payment for another piece");
                }
                let take = if by_bytes { ((n - off) as u64).min(piece_bytes - in_piece) as usize } else { n - off };
                let end = sent + take as u64;
                // a piece is open for its value from just before its last bytes leave, so that a buyer
                // who has all of it never names a piece the seller does not know yet. The buyer gives a
                // value only for a piece it has whole, so this tells the seller no result early
                let ends_piece = by_bytes && (end.is_multiple_of(piece_bytes) || m.length == Some(end));
                if ends_piece {
                    let k = sent / piece_bytes;
                    match bytes_piece(k, k * piece_bytes, end) {
                        Ok(a) => charged = charged.saturating_add(a),
                        Err(_) => break 'body stopped("no draw left for another piece"),
                    }
                    last_piece_end = end;
                }
                if let Err(e) = out.send(&buf[off..off + take]) {
                    break 'body Err(e);
                }
                hash.update(&buf[off..off + take]);
                sent = end;
                off += take;
            }
        };
        // the last, short piece of a body whose length was not known ahead: only of a body that came
        // to its end, so that both sides count the same bytes
        if result.is_ok() && by_bytes && sent > last_piece_end {
            let k = sent / piece_bytes;
            if let Ok(a) = bytes_piece(k, k * piece_bytes, sent) {
                charged = charged.saturating_add(a);
            }
        }
        let last = self.draw_receipt(&m.session, m.seq, charged, &m.digest, m.status, &hex::encode(hash.finalize()));
        if let Some(mut r) = last {
            // beside the signed fields: how the body ended
            r["bytes"] = sent.into();
            r["seconds"] = seconds.into();
            r["complete"] = result.is_ok().into();
            l.lock().keep_final(&m.session, r);
        }
        result
    }
}
