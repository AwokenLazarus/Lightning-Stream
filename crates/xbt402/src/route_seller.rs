//! The provider side of hub routing (B1 `RouteSeller` and the provider's routing endpoints,
//! AGP-021/023): route offers with a signed price quote, metered sessions in amsat, a fresh lock
//! point T per window in a payTo-signed invoice, ROUTE-AUTH / ROUTE-STATE on every routed call,
//! and `POST /x402/xbt-channel/lock`, which completes a hub's adaptor-locked ch2 state with the
//! window's t, saves it write-ahead and only then returns t.
//!
//! Serving rule (cmp constraint 6): a session is served while its unpaid charges are younger than
//! `window + lock_wait` (and under `credit_msat` if set). When the hub stops forwarding, the lock
//! never arrives and the provider stops within one window: its loss is at most one window of that
//! session's traffic, the client's at most one lock per provider.
//!
//! One deliberate difference from the reference: a channel keeps the answers to its last 256
//! completed locks (B1 keeps all of them). A hub retries only its one pending lock, and a replay of
//! an older lockId is refused as `bad_invoice` (it is not the session's open invoice).
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use serde_json::{json, Map, Value};
use xbt_primitives::ecdsa;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::sighash::SIGHASH_ALL_UNIFIED;

use crate::adaptor::{self, PreSig, Sc};
use crate::error::{fail, ChannelError, Result};
use crate::json::{dumps, py_int, py_str, py_u64};
use crate::ledger::{ChannelState, Ledger};
use crate::provider::{HttpResponse, Provider};
use crate::route::*;
use crate::wire::*;

/// Most completed-lock answers a channel keeps for idempotent retries.
pub const ROUTE_LOCKS_KEPT: usize = 256;

/// `charge(method, path, status, body) -> amsat` for a metered routed path.
pub type RouteChargeFn = Box<dyn Fn(&str, &str, u16, &[u8]) -> u128 + Send + Sync>;

/// A routed path on sale.
pub struct RouteOffer {
    pub path: String,
    /// Seconds per lock window.
    pub window: f64,
    /// Grace after a window for its lock to arrive.
    pub lock_wait: f64,
    /// A window's invoice is completed only until then.
    pub invoice_ttl: f64,
    /// `"any"` or `["<hub payTo>", ...]`.
    pub hubs: Value,
    pub amsat_per_call: u128,
    pub unit: String,
    /// Optional hard cap on unpaid credit, msat (0: time-based only).
    pub credit_msat: u128,
    pub charge: Option<RouteChargeFn>,
}

impl RouteOffer {
    pub fn new(path: &str, amsat_per_call: u128) -> Self {
        Self { path: path.into(), window: 1.0, lock_wait: 2.0, invoice_ttl: 15.0, hubs: "any".into(), amsat_per_call,
               unit: "call".into(), credit_msat: 0, charge: None }
    }
}

/// One client's metered session on a routed path.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteSession {
    pub session: String,
    pub client_pub: String,
    pub path: String,
    pub created: f64,
    pub seq: u64,
    pub accrued_amsat: u128,
    pub paid_sat: u64,
    pub calls: u64,
    /// Time of the oldest charge not covered by paid_sat (0: none).
    pub unpaid_since: f64,
    pub lock_id: String,
    /// The current window's secret (hex); never leaves until its lock completes.
    pub t: String,
    pub point: String,
    pub valid_until: f64,
    /// `{lockId, amount, secret}`: the client's receipt.
    pub last_lock: Value,
    pub locks: u64,
}

impl RouteSession {
    pub fn owed_amsat(&self) -> i128 {
        self.accrued_amsat as i128 - self.paid_sat as i128 * AMSAT_PER_SAT as i128
    }

    fn to_json(&self) -> Value {
        json!({"session": self.session, "client_pub": self.client_pub, "path": self.path, "created": self.created,
               "seq": self.seq, "accrued_amsat": int_value(self.accrued_amsat), "paid_sat": self.paid_sat, "calls": self.calls,
               "unpaid_since": self.unpaid_since, "lock_id": self.lock_id, "t": self.t, "point": self.point,
               "valid_until": self.valid_until, "last_lock": self.last_lock, "locks": self.locks})
    }

    fn from_json(v: &Value) -> Option<Self> {
        let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let f = |k: &str| v.get(k).and_then(Value::as_f64).unwrap_or(0.0);
        let n = |k: &str| py_u64(v.get(k)).unwrap_or(0);
        Some(Self { session: s("session"), client_pub: s("client_pub"), path: s("path"), created: f("created"), seq: n("seq"),
                    accrued_amsat: u128_of(v.get("accrued_amsat")).unwrap_or(0), paid_sat: n("paid_sat"), calls: n("calls"),
                    unpaid_since: f("unpaid_since"), lock_id: s("lock_id"), t: s("t"), point: s("point"),
                    valid_until: f("valid_until"), last_lock: v.get("last_lock").cloned().unwrap_or(json!({})), locks: n("locks") })
    }
}

fn token_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).expect("OS randomness");
    hex::encode(b)
}

/// A client's lock answer or ROUTE-STATE, and the held locks of a non-revealing provider.
#[derive(Default)]
pub struct SellerState {
    pub offers: HashMap<String, RouteOffer>,
    pub sessions: HashMap<String, RouteSession>,
    quotes: HashMap<String, PriceQuote>,
    quote_seq: i64,
    keys: HashMap<String, [u8; 32]>,
    /// Tests/demo: take locks, never reveal t (a withholding provider).
    pub no_reveal: bool,
    pub held: Vec<Value>,
}

/// The provider's routing book: offers, sessions (persisted next to the ledger) and the rest.
pub struct RouteSeller {
    pub state: Mutex<SellerState>,
    path: Option<PathBuf>,
    secret: SecretKey,
    pay_to: String,
    network: String,
    settle_multiple: u64,
}

impl RouteSeller {
    pub(crate) fn new(ledger: &Ledger, secret: SecretKey, network: &str, settle_multiple: u64) -> Self {
        let path = ledger.path().map(|p| {
            let s = p.to_string_lossy().to_string();
            PathBuf::from(format!("{}.routes.json", s.strip_suffix(".json").unwrap_or(&s)))
        });
        let mut st = SellerState { quote_seq: now_i(), ..Default::default() };
        if let Some(raw) = path.as_ref().and_then(|p| std::fs::read(p).ok()).and_then(|b| serde_json::from_slice::<Value>(&b).ok()) {
            for (k, v) in raw.get("sessions").and_then(Value::as_object).into_iter().flatten() {
                if let Some(s) = RouteSession::from_json(v) {
                    st.sessions.insert(k.clone(), s);
                }
            }
        }
        Self { state: Mutex::new(st), path, pay_to: hex::encode(ecdsa::pubkey(&secret)), secret, network: network.into(), settle_multiple }
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, SellerState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn save(&self, st: &SellerState) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let sessions: Map<String, Value> = st.sessions.iter().map(|(k, v)| (k.clone(), v.to_json())).collect();
        let tmp = path.with_extension("tmp");
        let io = |e: std::io::Error| ChannelError::new("ledger_error", e.to_string());
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp).map_err(io)?;
            f.write_all(dumps(&json!({"sessions": sessions})).as_bytes()).map_err(io)?;
            f.sync_all().map_err(io)?;
        }
        std::fs::rename(&tmp, path).map_err(io)
    }

    pub fn has_offer(&self, path: &str) -> bool {
        self.lock().offers.contains_key(path)
    }

    pub fn offer_paths(&self) -> Vec<String> {
        let mut v: Vec<String> = self.lock().offers.keys().cloned().collect();
        v.sort();
        v
    }

    fn price_quote(&self, st: &mut SellerState, path: &str) -> Result<PriceQuote> {
        let now = now_i();
        if let Some(q) = st.quotes.get(path) {
            if q.valid_until - now >= 60 {
                return Ok(q.clone());
            }
        }
        let o = st.offers.get(path).ok_or_else(|| ChannelError::code("unknown_route"))?;
        st.quote_seq += 1;
        let q = PriceQuote { pay_to: self.pay_to.clone(), network: self.network.clone(), path: path.into(), amsat_per_call: o.amsat_per_call,
                             unit: o.unit.clone(), seq: st.quote_seq, issued_at: now, valid_until: now + 3600, sig: String::new() }
            .sign(&self.secret);
        st.quotes.insert(path.into(), q.clone());
        Ok(q)
    }

    fn key(&self, st: &mut SellerState, sid: &str) -> Result<[u8; 32]> {
        if let Some(k) = st.keys.get(sid) {
            return Ok(*k);
        }
        let s = st.sessions.get(sid).ok_or_else(|| ChannelError::code("unknown_session"))?;
        let k = session_key(&self.secret, &hex::decode(&s.client_pub).unwrap_or_default())?;
        st.keys.insert(sid.to_string(), k);
        Ok(k)
    }

    /// A fresh (t, T) per window.
    fn new_window(s: &mut RouteSession, ttl: f64) {
        let t = adaptor::random_secret();
        s.t = hex::encode(t.secret_bytes());
        s.point = hex::encode(adaptor::enc(&adaptor::point_of(&t)));
        s.lock_id = token_hex(12);
        s.valid_until = now_f() + ttl;
    }

    fn invoice(&self, st: &SellerState, s: &RouteSession) -> Value {
        let hubs = st.offers.get(&s.path).map(|o| o.hubs.clone()).unwrap_or_else(|| "any".into());
        Invoice { pay_to: self.pay_to.clone(), network: self.network.clone(), session: s.session.clone(), lock_id: s.lock_id.clone(),
                  point: s.point.clone(), valid_until: round3(s.valid_until), hubs, sig: String::new() }
            .sign(&self.secret).to_json()
    }

    fn open_session(&self, st: &mut SellerState, path: &str, client_pub_hex: &str) -> Result<String> {
        let pubk = hex::decode(client_pub_hex.trim()).map_err(|_| ChannelError::new("bad_key", "not hex"))?;
        ecdsa::public_key(&pubk).map_err(|_| ChannelError::new("bad_key", "not a point"))?;
        let ttl = st.offers.get(path).map(|o| o.invoice_ttl).unwrap_or(15.0);
        let mut s = RouteSession { session: token_hex(16), client_pub: hex::encode(&pubk), path: path.into(), created: now_f(), seq: 0,
                                   accrued_amsat: 0, paid_sat: 0, calls: 0, unpaid_since: 0.0, lock_id: String::new(), t: String::new(),
                                   point: String::new(), valid_until: 0.0, last_lock: json!({}), locks: 0 };
        Self::new_window(&mut s, ttl);
        let sid = s.session.clone();
        st.sessions.insert(sid.clone(), s);
        self.save(st)?;
        Ok(sid)
    }

    /// `PaymentRequirements.extra.route` for a routed path: the offer, the signed price quote and,
    /// when the request named a client route key (ROUTE-CLIENT), a new session and its first
    /// invoice.
    pub fn route_extra(&self, path: &str, client_pub_hex: &str) -> Result<Value> {
        let mut st = self.lock();
        let q = self.price_quote(&mut st, path)?;
        let o = &st.offers[path];
        let mut out = json!({"window": o.window, "lockWait": o.lock_wait, "invoiceTtl": o.invoice_ttl, "hubs": o.hubs,
                             "creditMsat": o.credit_msat.to_string(), "quote": q.to_json(), "lockUrl": ROUTE_LOCK_PATH,
                             "settleMultiple": self.settle_multiple});
        if !client_pub_hex.is_empty() {
            let sid = self.open_session(&mut st, path, client_pub_hex)?;
            let inv = self.invoice(&st, &st.sessions[&sid]);
            out["session"] = sid.into();
            out["invoice"] = inv;
        }
        Ok(out)
    }

    fn serving(st: &SellerState, s: &RouteSession, now: f64) -> Option<&'static str> {
        let o = st.offers.get(&s.path)?;
        if s.owed_amsat() <= 0 {
            return None;
        }
        if s.unpaid_since > 0.0 && now - s.unpaid_since > o.window + o.lock_wait {
            return Some("route_credit");
        }
        if o.credit_msat > 0 && s.owed_amsat() > (o.credit_msat * AMSAT_PER_MSAT) as i128 {
            return Some("route_credit");
        }
        None
    }

    /// ROUTE-STATE: the signed running meter and the open invoice (and the last completed lock's t,
    /// so the client has its receipt even from a hub that withholds it).
    fn state_locked(&self, st: &mut SellerState, sid: &str, charge: u128) -> Result<Value> {
        let q = {
            let path = st.sessions.get(sid).map(|s| s.path.clone()).ok_or_else(|| ChannelError::code("unknown_session"))?;
            self.price_quote(st, &path)?
        };
        let ttl = st.sessions.get(sid).and_then(|s| st.offers.get(&s.path)).map(|o| o.invoice_ttl).unwrap_or(15.0);
        let s = st.sessions.get_mut(sid).ok_or_else(|| ChannelError::code("unknown_session"))?;
        if now_f() > s.valid_until - 1.0 {
            // an expired invoice: nobody can complete it now, issue a fresh T
            Self::new_window(s, ttl);
        }
        let s = st.sessions[sid].clone();
        let body = json!({"session": s.session, "seq": s.seq, "calls": s.calls, "chargeAmsat": charge.to_string(),
                          "accruedAmsat": s.accrued_amsat.to_string(), "paidSat": s.paid_sat, "quote": q.quote_id(),
                          "lastLock": s.last_lock, "invoice": self.invoice(st, &s)});
        Ok(state_sign(&self.secret, &body))
    }

    /// The session's current ROUTE-STATE (no charge).
    pub fn state(&self, sid: &str) -> Result<Value> {
        let mut st = self.lock();
        self.state_locked(&mut st, sid, 0)
    }

    /// Authenticate a routed call. `Ok((session, None))` to serve, `Ok((session, Some(error)))` or
    /// `Err(error)` (no session) to refuse.
    pub fn begin_call(&self, path: &str, hdr: &str, method: &str, req_path: &str, body: &[u8]) -> std::result::Result<(String, Option<&'static str>), &'static str> {
        let h = unb64json(hdr).map_err(|_| "bad_payload")?;
        let (Some(sid), Some(seq), Some(auth)) = (h.get("session"), py_int(h.get("seq")), h.get("auth")) else { return Err("bad_payload") };
        let (sid, auth) = (py_str(Some(sid)), py_str(Some(auth)));
        let mut st = self.lock();
        if st.sessions.get(&sid).is_none_or(|s| s.path != path) {
            return Err("unknown_session");
        }
        let key = self.key(&mut st, &sid).map_err(|_| "bad_auth")?;
        let s = st.sessions.get(&sid).ok_or("unknown_session")?;
        if seq <= s.seq as i128 {
            return Err("bad_auth");
        }
        let seq = u64::try_from(seq).map_err(|_| "bad_auth")?;
        if !auth_eq(&call_auth(&key, &sid, seq, &request_digest(method, req_path, body)), &auth) {
            return Err("bad_auth");
        }
        let s = st.sessions.get_mut(&sid).ok_or("unknown_session")?;
        s.seq = seq;
        let s = s.clone();
        let err = Self::serving(&st, &s, now_f());
        Ok((sid, err))
    }

    pub fn end_call(&self, sid: &str, charge_amsat: u128) -> Result<Value> {
        let mut st = self.lock();
        let s = st.sessions.get_mut(sid).ok_or_else(|| ChannelError::code("unknown_session"))?;
        if charge_amsat > 0 {
            if s.owed_amsat() <= 0 {
                s.unpaid_since = now_f();
            }
            s.accrued_amsat += charge_amsat;
        }
        s.calls += 1;
        self.state_locked(&mut st, sid, charge_amsat)
    }

    fn lock_answer(&self, st: &SellerState, chan: &str, routed: u64, lock_id: &str, rec: &Value) -> Value {
        let sid = py_str(rec.get("session"));
        let paid = st.sessions.get(&sid).map(|s| Value::from(s.paid_sat)).unwrap_or(Value::Null);
        json!({"lockId": lock_id, "secret": rec["secret"], "cum": py_str(rec.get("cum")), "chan": chan, "routedSat": routed,
               "session": state_sign(&self.secret, &json!({"session": sid, "lockId": lock_id, "amount": rec["amount"], "paidSat": paid}))})
    }
}

// --- the provider's routing endpoints --------------------------------------------------------------

fn err_json(status: u16, code: &str, detail: &str) -> HttpResponse {
    HttpResponse::new(status, vec![("Content-Type".into(), "application/json".into())], dumps(&json!({"error": code, "detail": detail})))
}

impl Provider {
    /// Sell `path` through hubs. Its 402 carries `extra.route` (the signed price quote and, for a
    /// client that names its route key in `ROUTE-CLIENT`, a session with a fresh lock point T per
    /// window). Calls carry ROUTE-AUTH and are metered in amsat; each window's accrued amount is
    /// paid by one adaptor-locked ch2 state from a hub.
    pub fn offer_route(&self, offer: RouteOffer) {
        let mut st = self.routes.lock();
        st.quotes.remove(&offer.path);
        st.offers.insert(offer.path.clone(), offer);
    }

    /// Tests/demo: stop revealing t (take locks and hold them), or resume.
    pub fn set_no_reveal(&self, on: bool) {
        self.routes.lock().no_reveal = on;
    }

    /// Close `chan` now with its best state (an operator's unilateral close; the watcher does the
    /// same at the close margin). Returns the close txid.
    pub fn close_now(&self, chan: &str) -> Result<String> {
        let cid = crate::channel::canonical_chan(chan)?;
        let mut l = self.ledger_lock();
        let mut st = l.channels.get(&cid).cloned().ok_or_else(|| ChannelError::code("unknown_channel"))?;
        let r = self.close_locked(&mut l, &mut st);
        l.channels.insert(cid, st);
        r
    }

    /// The routing book (sessions, held locks).
    pub fn routes(&self) -> &RouteSeller {
        &self.routes
    }

    /// Complete one adaptor-locked ch2 state (the ledger lock is held by the caller, and the hub's
    /// channel auth has passed). Checks the lock, completes it with the window's t, saves the plain
    /// state write-ahead, and only then credits the session and returns t.
    ///
    /// ch2's cumulative amount is `next_cum(routed, d, min_amount)`: the routed total with the
    /// channel's floor, which the hub pre-pays once per channel and later locks use up. A lock the
    /// floor covers needs no new state (and carries no adaptor). A lockId completed before is
    /// answered again with the same t.
    pub(crate) fn complete_lock(&self, l: &mut Ledger, st: &mut ChannelState, pl: &Value, route: &Value) -> Result<Value> {
        let bad = |m: &str| ChannelError::new("bad_payload", m.to_string());
        let sid = route.get("session").map(|v| py_str(Some(v))).ok_or_else(|| bad("'session'"))?;
        let lock_id = route.get("lockId").map(|v| py_str(Some(v))).ok_or_else(|| bad("'lockId'"))?;
        let amount = py_int(route.get("amount")).ok_or_else(|| bad("'amount'"))?;
        let point = pl.get("point").map(|v| py_str(Some(v)).to_lowercase()).ok_or_else(|| bad("'point'"))?;
        let auth = route.get("lockAuth").map(|v| py_str(Some(v))).ok_or_else(|| bad("'lockAuth'"))?;
        let hub = route.get("hub").map(|v| py_str(Some(v))).ok_or_else(|| bad("'hub'"))?;
        let cum = py_int(pl.get("cum")).ok_or_else(|| bad("'cum'"))?;
        let chan = st.params.channel_id();
        let mut locks = st.extra.get("route_locks").and_then(Value::as_object).cloned().unwrap_or_default();
        let routes = &self.routes;
        let mut rs = routes.lock();
        if let Some(done) = locks.get(&lock_id) {
            // idempotent: the same answer again
            if py_str(done.get("session")) != sid || py_int(done.get("amount")) != Some(amount) {
                return fail("bad_invoice", "lockId already completed with other terms");
            }
            let routed = py_u64(st.extra.get("routed_sat")).unwrap_or(0);
            return Ok(routes.lock_answer(&rs, &chan, routed, &lock_id, done));
        }
        let s = rs.sessions.get(&sid).cloned().ok_or_else(|| ChannelError::code("unknown_session"))?;
        let o = rs.offers.get(&s.path).ok_or_else(|| ChannelError::code("unknown_session"))?;
        let (hubs, ttl) = (o.hubs.clone(), o.invoice_ttl);
        if lock_id != s.lock_id || point != s.point {
            return fail("bad_invoice", "not this session's open invoice");
        }
        if now_f() > s.valid_until {
            return fail("bad_invoice", "invoice expired: a fresh point is in the next ROUTE-STATE");
        }
        if st.extra.get("hub").map(|v| py_str(Some(v))).unwrap_or_default() != hub {
            return fail("route_blocked", "this channel is not that hub's");
        }
        if !hubs_accept(&hubs, &hub) {
            return fail("route_blocked", "hub not accepted by this provider");
        }
        let key = routes.key(&mut rs, &sid)?;
        if !auth_eq(&lock_auth(&key, &sid, &lock_id, amount, &point, &hub), &auth) {
            return fail("bad_auth", "the client did not authorise this amount for this invoice");
        }
        if amount < 1 {
            return fail("bad_amount", "lock amount must be >= 1 sat");
        }
        let amount = u64::try_from(amount).map_err(|_| ChannelError::new("bad_amount", "lock amount out of range"))?;
        if rs.no_reveal {
            rs.held.push(json!({"lockId": lock_id, "cum": cum.to_string().parse::<u64>().ok(), "pre": pl.get("adaptor"), "chan": chan}));
            return Ok(json!({"held": lock_id}));
        }
        let routed = py_u64(st.extra.get("routed_sat")).unwrap_or(0);
        let need = next_cum(routed, amount, st.params.min_amount());
        let mut sig = Vec::new();
        if need <= st.best_cum {
            if cum != st.best_cum as i128 || pl.get("adaptor").is_some_and(|a| crate::json::truthy(Some(a))) {
                return fail("bad_amount", format!("the dust floor covers this lock: cum {}, no adaptor", st.best_cum));
            }
        } else {
            if cum != need as i128 {
                return fail("bad_amount", format!("lock pays {cum}, expected {need}"));
            }
            if need > st.params.max_amount() {
                return fail("channel_exhausted", "");
            }
            let pre = PreSig::from_json(pl.get("adaptor").unwrap_or(&Value::Null))?;
            let z = st.params.sighash(&st.params.state_tx(need)?)?;
            if !adaptor::preverify(&st.params.payer_pub, &z, &adaptor::dec_hex(&point)?, &pre) {
                return fail("bad_adaptor", "pre-signature does not verify under the invoice point");
            }
            let t = Sc::from_hex64(&s.t).and_then(|t| t.secret()).ok_or_else(|| ChannelError::new("bad_state", "window secret"))?;
            sig = adaptor::adapt(&pre, &t)?;
            sig.push(SIGHASH_ALL_UNIFIED);
            // an ordinary 0x21 state from here on
            self.payee(st)?.accept(need, &sig)?;
        }
        // write-ahead (M8): the plain state and the lock record are on disk before t leaves
        let rec = json!({"session": sid, "amount": amount, "cum": need.max(st.best_cum), "secret": s.t, "at": round3(now_f())});
        locks.insert(lock_id.clone(), rec.clone());
        while locks.len() > ROUTE_LOCKS_KEPT {
            let first = locks.keys().next().cloned().unwrap_or_default();
            locks.remove(&first);
        }
        if !sig.is_empty() {
            st.best_cum = need;
            st.best_sig = hex::encode(&sig);
        }
        st.extra.insert("route_locks".into(), Value::Object(locks));
        st.extra.insert("routed_sat".into(), (routed + amount).into());
        self.save_state(l, st)?;
        let sess = rs.sessions.get_mut(&sid).ok_or_else(|| ChannelError::code("unknown_session"))?;
        sess.paid_sat += amount;
        sess.locks += 1;
        sess.last_lock = json!({"lockId": lock_id, "amount": amount, "secret": s.t});
        sess.unpaid_since = if sess.owed_amsat() > 0 { now_f() } else { 0.0 };
        RouteSeller::new_window(sess, ttl);
        routes.save(&rs)?;
        Ok(routes.lock_answer(&rs, &chan, routed + amount, &lock_id, &rec))
    }

    /// POST /x402/xbt-channel/lock: a hub's adaptor-locked state on its ch2 to us, authenticated
    /// like a paid call (the hub's channel HMAC covers the JSON body with the route terms).
    pub(crate) fn route_lock(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8]) -> HttpResponse {
        let hdr = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-SIGNATURE")).map(|(_, v)| v.as_str()).unwrap_or("");
        let parsed = (|| -> Option<(Value, Value)> {
            let pl = unb64json(hdr).ok()?.get("payload")?.clone();
            let route = serde_json::from_slice::<Value>(body).ok()?.get("route")?.clone();
            (pl.is_object() && route.is_object()).then_some((pl, route))
        })();
        let Some((pl, route)) = parsed else { return err_json(400, "bad_payload", "") };
        let mut l = self.ledger_lock();
        let cid = pl.get("chan").and_then(Value::as_str).and_then(|c| crate::channel::canonical_chan(c).ok()).filter(|c| l.channels.contains_key(c));
        let Some(cid) = cid else { return err_json(400, "unknown_channel", "") };
        let mut st = l.channels[&cid].clone();
        if !self.authentic(&st, &pl, method, path, body) {
            return err_json(401, "bad_auth", "");
        }
        st.seq = py_u64(pl.get("seq")).unwrap_or(st.seq);
        l.channels.insert(cid.clone(), st.clone());
        let height = match self.height() {
            Ok(h) => h,
            Err(e) => return err_json(500, "node_error", &e.to_string()),
        };
        if !st.closed_txid.is_empty() || height as i64 >= st.params.expiry as i64 - self.cfg.close_margin as i64 {
            return err_json(400, "channel_closing", "");
        }
        if st.suspended {
            return err_json(400, "unconfirmed", "");
        }
        match self.complete_lock(&mut l, &mut st, &pl, &route) {
            Ok(out) => {
                l.channels.insert(cid, st);
                let status = if out.get("held").is_some() { 202 } else { 200 };
                HttpResponse::new(status, vec![("Content-Type".into(), "application/json".into())], dumps(&out))
            }
            Err(e) => {
                let _ = self.save_state(&mut l, &st);
                err_json(400, &e.code, &e.to_string())
            }
        }
    }

    /// A metered call on a routed path (ROUTE-AUTH, no PAYMENT-SIGNATURE).
    pub(crate) fn routed_call(&self, method: &str, path: &str, pk: &str, hdr: &str, body: &[u8], url: &str) -> HttpResponse {
        let refuse = |error: &str, sid: Option<&str>| {
            let mut doc = self.payment_required_doc(url, (self.price)(method, path), error, None);
            if let Ok(extra) = self.routes.route_extra(pk, "") {
                doc["accepts"][0]["extra"]["route"] = extra;
            }
            if let Some(sid) = sid {
                if let Ok(s) = self.routes.state(sid) {
                    doc["routeState"] = s;
                }
            }
            self.required_response(&doc)
        };
        let sid = match self.routes.begin_call(pk, hdr, method, path, body) {
            Err(e) => return refuse(e, None),
            Ok((sid, Some(e))) => return refuse(e, Some(&sid)),
            Ok((sid, None)) => sid,
        };
        let mut resp = (self.handler)(method, path, body);
        if resp.headers.iter().any(|(k, v)| k.contains(['\r', '\n', '\0']) || v.contains(['\r', '\n', '\0'])) {
            resp = HttpResponse::new(500, vec![], b"handler returned a header with CR/LF".to_vec());
        }
        let charge = {
            let rs = self.routes.lock();
            match rs.offers.get(pk) {
                Some(o) => match &o.charge {
                    Some(f) => f(method, path, resp.status, &resp.body),
                    None => o.amsat_per_call,
                },
                None => 0,
            }
        };
        let charge = if resp.status >= 500 { 0 } else { charge };
        match self.routes.end_call(&sid, charge) {
            Ok(state) => resp.headers.push(("ROUTE-STATE".into(), b64json(&state))),
            Err(e) => return err_json(500, &e.code, &e.to_string()),
        }
        resp
    }

    /// The 402 for a routed path without ROUTE-AUTH: `extra.route`, with a new session when the
    /// request carries ROUTE-CLIENT.
    pub(crate) fn route_offer_402(&self, method: &str, path: &str, pk: &str, client: &str, url: &str) -> HttpResponse {
        let mut doc = self.payment_required_doc(url, (self.price)(method, path), "payment_required", None);
        match self.routes.route_extra(pk, client) {
            Ok(extra) => doc["accepts"][0]["extra"]["route"] = extra,
            Err(_) => return HttpResponse::new(400, vec![], b"bad ROUTE-CLIENT key".to_vec()),
        }
        self.required_response(&doc)
    }
}

/// A lock answer's `secret` opens `point` (t·G == T)?
pub fn secret_opens(secret_hex: &str, point_hex: &str) -> Option<SecretKey> {
    let y = Sc::from_hex_mod_n(secret_hex)?.secret()?;
    let p = adaptor::dec_hex(point_hex).ok()?;
    (adaptor::point_of(&y) == p).then_some(y)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_json_round_trip() {
        let mut s = RouteSession { session: "s".into(), client_pub: "02".into(), path: "/p".into(), created: 1.5, seq: 3,
                                   accrued_amsat: 813_000_000_000_123_456_789 * 1000, paid_sat: 9, calls: 4, unpaid_since: 0.0,
                                   lock_id: "l".into(), t: "00".into(), point: "02".into(), valid_until: 7.25, last_lock: json!({}), locks: 1 };
        let v: Value = serde_json::from_str(&dumps(&s.to_json())).unwrap();
        assert_eq!(RouteSession::from_json(&v).unwrap(), s);
        s.paid_sat = 10_000_000_000;
        assert!(s.owed_amsat() < 0);
    }
}
