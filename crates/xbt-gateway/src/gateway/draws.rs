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
//! 4. **Every piece costs less than the session's win** (`amount_not_below_win` otherwise): a
//!    dearer piece is paid with tickets.
//! 5. **Only what the runner allowed reaches the service**, and nothing the service says is read
//!    for money: a piece is the bytes the gateway itself sent and the seconds it itself counted.
//! 6. **A piece is a piece once it has left** ([`Book::serve`]): the buyer's value can only follow
//!    the work it pays for, so the gateway learns no result before it has served.
//! 7. **A reveal follows the value** ([`Book::draw`]): the chain value of a draw leaves only in the
//!    answer to the request that brought its value. A session and its chain live in this process
//!    only, so no restart can take a second value for a draw it has revealed for.
//! 8. **An invoice per win**, made by the node for the session's win size, with a preimage the
//!    gateway makes and forgets. A win is paid when the node shows that invoice settled in full.
//! 9. **Receipt**: every answer to an authenticated request carries one, signed by the receipt key.
use xbt402::lottery::{self, DrawError, Kind, PieceId, RELEASE_AFTER_ANSWER, RELEASE_AFTER_VERIFY};

use super::*;
use crate::lottery::{Book as Draws, Refusal as Refused, Value32, MAX_BATCH};

/// The lottery's state beside the ticket book: its own lock, so that a draw never waits for a
/// ticket's settle.
pub(super) struct Lottery {
    book: Mutex<Draws>,
    /// Signalled when a value is taken or a win is paid: answers that wait for either wake.
    changed: Condvar,
}

impl Lottery {
    pub(super) fn new(cfg: crate::lottery::LotteryConfig) -> Self {
        Self { book: Mutex::new(Draws::new(cfg)), changed: Condvar::new() }
    }

    fn lock(&self) -> MutexGuard<'_, Draws> {
        self.book.lock().unwrap_or_else(|p| p.into_inner())
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

    /// The lottery entry of a route's 402, where the runner offers the lottery and every piece of
    /// the route costs less than a win.
    pub(super) fn lottery_entry(&self, route: &Route) -> Option<Value> {
        let cfg = self.cfg.lottery.as_ref()?;
        if !cfg.offers(&route.price) {
            return None;
        }
        let release = match route.release {
            Release::AfterVerify => RELEASE_AFTER_VERIFY,
            Release::WithRequest => RELEASE_AFTER_ANSWER,
        };
        Some(self.lottery_terms(cfg).accepts(route.price.request_msat, release, &route.price.terms()))
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
    pub(super) fn lottery_tick(&self) {
        if let Some(l) = &self.lottery {
            let now = self.now();
            l.lock().sweep(now);
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
            || accepted.get("network").and_then(Value::as_str) != Some(self.cfg.network.as_str())
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
            Ok(()) => Ok(Authed { session: pay.session.clone(), seq: pay.seq, digest, ticket: None }),
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
                    .map(|w| json!({"draw": w.draw, "invoice": w.invoice.as_ref().map(|(_, inv, _)| inv.as_str())}))
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
        let (mut body, _) = self.required(target, route, None, Some(self.draw_view(l, &a.session)));
        body["error"] = code.into();
        let mut r = json_response(402, &body);
        r.headers.push(("PAYMENT-REQUIRED".into(), b64json(&body)));
        self.draw_answered(a, r, 0)
    }

    /// Bring a session's unpaid wins to what the node says: a win whose invoice the node shows
    /// settled in full is paid; a win with no invoice, or one whose invoice the node has cancelled
    /// (it lapsed unpaid), gets a new one. No lock is held while the node is asked.
    fn lottery_refresh(&self, l: &Lottery, session: &str) {
        let (unpaid, win_msat, win_blocks, invoice_secs) = {
            let b = l.lock();
            match b.session(session) {
                Some(s) if !s.unpaid.is_empty() => (s.unpaid.clone(), s.win_msat, b.cfg().win_blocks, b.cfg().invoice_secs),
                _ => return,
            }
        };
        let mut paid = false;
        for w in unpaid {
            let lapsed = match &w.invoice {
                None => true,
                Some((hash, _, _)) => match self.node.lookup(hash) {
                    Ok(Some(inv)) if inv.state == InvoiceState::Settled && inv.paid_msat >= win_msat => {
                        paid |= l.lock().win_paid(session, hash);
                        false
                    }
                    // cancelled by the node when its time ran out: it can no longer be paid
                    Ok(Some(inv)) => inv.state == InvoiceState::Canceled,
                    Ok(None) => true,
                    // no answer: the win is as it was, and is asked about again
                    Err(_) => false,
                },
            };
            // one request at a time asks the node for a win's invoice: a second invoice for one win
            // could be paid and never be seen paid
            if lapsed && l.lock().claim_invoice(session, w.draw, w.invoice.as_ref().map(|(h, _, _)| h)) {
                let mut preimage = [0u8; 32];
                preimage.copy_from_slice(&xbt_svc::random_bytes(32));
                let made = self.node.add_invoice(&preimage, win_msat, win_blocks, invoice_secs).ok().map(|invoice| (Hash::from(Sha256::digest(preimage)), invoice));
                l.lock().win_invoiced(session, w.draw, made, self.now());
                l.changed.notify_all();
            }
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
            b = l.changed.wait_timeout(b, left).unwrap_or_else(|p| p.into_inner()).0;
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
            drop(l.changed.wait_timeout(b, left.min(Duration::from_millis(50))).unwrap_or_else(|p| p.into_inner()));
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
            let drawn = l.lock().draw(&a.session, &batch.0, &batch.1, now);
            l.changed.notify_all();
            match drawn {
                Ok(d) => {
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
            l.lock().close(&a.session);
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
        let addr = addr_name(req.peer);
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
            b.open(&entropy, chain, &addr, win_msat, self.now()).map(|id| {
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
        let Some(l) = &self.lottery else {
            return Reply::Whole(self.unpaid(&req.target, route));
        };
        let pay = match self.draw_pay_header(&req) {
            Ok(Some(p)) => p,
            Ok(None) => return Reply::Whole(self.unpaid(&req.target, route)),
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
        let (blocked, win_msat, dearest) = {
            let b = l.lock();
            (b.blocked(&a.session, self.now()), b.session(&a.session).map_or(0, |s| s.win_msat), b.cfg().dearest_piece(&route.price))
        };
        if let Some(why) = blocked {
            return Reply::Whole(self.draw_refused(l, &a, &req.target, Some(route), why.code()));
        }
        if dearest.is_none_or(|d| d >= win_msat) {
            return Reply::Whole(self.draw_refused(l, &a, &req.target, Some(route), DrawError::AmountNotBelowWin.code()));
        }
        let head_only = req.method == "HEAD";
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
        // the request's own piece: it has left when the answer's head does
        if self.lottery_serve(l, &m, Kind::Request, 0, m.at_head).is_err() {
            return Reply::Whole(self.draw_refused(l, &a, &req.target, Some(route), DrawError::ChainSpent.code()));
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
