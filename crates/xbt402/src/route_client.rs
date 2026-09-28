//! `RoutePayer`: pay many xbt402 providers through one hub channel (a port of B1
//! `xbt402/route_client.py`, AGP-021).
//!
//! ```text
//! let payer = Arc::new(RoutePayer::new(hub_url, cfg, signer, transport, height));
//! payer.open()?;                                  // one ch1 to the hub, whatever the number of shards
//! let a = payer.shard("http://shard-a:port/forward", "POST")?;   // signed price quote + first invoice
//! payer.start(window / 2);                        // per-window locks, serial on ch1, off the data path
//! let r = payer.call(&a, "POST", chunk)?;         // data calls go straight to the provider
//! payer.stop(); payer.close()?;                   // cooperative close of ch1 (the hub closes it)
//! ```
//!
//! Data calls carry ROUTE-AUTH (an HMAC under a client ↔ provider ECDH key the hub never sees) and
//! come back with a provider-signed ROUTE-STATE: the running meter in amsat, what the provider has
//! been paid, the open invoice (a fresh lock point T per window) and the last lock's t. So the
//! client:
//! * never waits on routing per chunk: chunks run on the provider's credit window;
//! * pays each window's accrued amount as the ceil of the running total minus what is already paid
//!   (the carry) with one adaptor lock per provider, one after another on ch1;
//! * gets its receipt from the hub (t + r) or, if the hub withholds it, from the provider (t);
//! * gives a lock up when the hub refuses it, or when its invoice expires unanswered: the lock can
//!   then cost at most its own amount (one window of one provider), and a later state dominates it.
//!
//! Keys stay behind [`StateSigner`]: [`crate::signer::LocalSigner`] in process, or AGP-027's B2
//! signer, policy-checked, keys never in the client.
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use indexmap::IndexMap;
use serde_json::{json, Value};
use xbt_primitives::address::segwit_address;
use xbt_primitives::ecdsa;

use crate::adaptor::{self, Sc};
use crate::channel::{ChannelParams, FeePayer, DERIVATION};
use crate::client::{split_url, HeightFn, Transport};
use crate::error::{fail, ChannelError, Result};
use crate::json::{dumps, py_str, py_u64, truthy};
use crate::provider::HttpResponse;
use crate::route::*;
use crate::signer::StateSigner;
use crate::wire::*;

fn lk<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// RoutePayer settings (the reference's keywords).
#[derive(Debug, Clone)]
pub struct RoutePayerConfig {
    pub network: String,
    pub capacity: u64,
    pub expiry_blocks: u32,
    pub max_fee_ppm: u64,
    pub max_fee_base_msat: u64,
    pub max_lock_sat: u64,
    pub max_close_fee: u64,
    /// Seconds past an invoice's validUntil before its unanswered lock is given up.
    pub void_grace: f64,
}

impl RoutePayerConfig {
    pub fn new(network: &str) -> Self {
        Self { network: network.into(), capacity: 200_000, expiry_blocks: 8_000, max_fee_ppm: 10_000, max_fee_base_msat: 10_000,
               max_lock_sat: 50_000, max_close_fee: 2_000, void_grace: 1.0 }
    }
}

/// The mutable part of a shard session.
#[derive(Debug, Clone, Default)]
pub struct ShardState {
    pub seq: u64,
    pub invoice: Value,
    /// The provider's signed running total.
    pub accrued_amsat: u128,
    /// The sum of the per-call charges we were shown.
    pub seen_amsat: u128,
    /// What the provider says it has been paid (signed).
    pub paid_sat: u64,
    /// What our completed locks paid it.
    pub locked_sat: u64,
    pub calls: u64,
    pub last_lock: Value,
    /// Why the provider stopped serving us ("" while it serves).
    pub stopped: String,
    pub call_ms: Vec<f64>,
    pub lock_ms: Vec<f64>,
}

/// One metered session on a routed path.
#[derive(Debug)]
pub struct Shard {
    pub url: String,
    pub origin: String,
    pub path: String,
    pub pay_to: String,
    pub session: String,
    key: [u8; 32],
    pub quote: PriceQuote,
    pub window: f64,
    pub lock_wait: f64,
    pub state: Mutex<ShardState>,
}

impl Shard {
    /// The client ↔ provider session key (ECDH; the hub never has it).
    #[doc(hidden)]
    pub fn session_key(&self) -> [u8; 32] {
        self.key
    }

    /// `ceil(accrued) − max(paid, locked)`: what the next lock pays.
    pub fn due_sat(&self) -> i128 {
        let s = lk(&self.state);
        ceil_div(s.accrued_amsat, AMSAT_PER_SAT) as i128 - s.paid_sat.max(s.locked_sat) as i128
    }

    pub fn snapshot(&self) -> ShardState {
        lk(&self.state).clone()
    }
}

struct Pending {
    id: u64,
    shard: Arc<Shard>,
    lock_id: String,
    d: u64,
    f: u64,
    units: u128,
    cum: u64,
    floor: bool,
    t: String,
    t1: String,
    until: f64,
    t0: Instant,
    inflight: bool,
}

struct GivenUp {
    cum: u64,
    lock_id: String,
    after: (u64, u128, u64),
}

/// Counters (`stats` in the reference).
#[derive(Debug, Clone, Default)]
pub struct PayerStats {
    pub locks: u64,
    pub floor_locks: u64,
    pub voided: u64,
    pub via_provider: u64,
    pub refused: IndexMap<String, u64>,
}

struct Ch1 {
    params: ChannelParams,
    accepted: Value,
    seq: u64,
}

#[derive(Default)]
struct PState {
    ch: Option<Ch1>,
    quote: Option<FeeQuote>,
    hub_pay_to: String,
    routed: u64,
    fee_units: u128,
    fee_paid: u64,
    signed: u64,
    pending: Option<Pending>,
    given_up: Vec<GivenUp>,
    stats: PayerStats,
}

/// The routed-payment client.
pub struct RoutePayer {
    pub hub_url: String,
    pub cfg: RoutePayerConfig,
    signer: Arc<dyn StateSigner>,
    http: Box<dyn Transport>,
    height: HeightFn,
    st: Mutex<PState>,
    shards: Mutex<IndexMap<String, Arc<Shard>>>,
    stop: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
    ids: AtomicU64,
    pub events: Mutex<Vec<Value>>,
}

fn hdr_json(r: &HttpResponse, name: &str) -> Option<Value> {
    r.header(name).and_then(|h| unb64json(h).ok())
}

impl RoutePayer {
    pub fn new(hub_url: &str, cfg: RoutePayerConfig, signer: Arc<dyn StateSigner>, http: Box<dyn Transport>, height: HeightFn) -> Self {
        Self { hub_url: hub_url.trim_end_matches('/').to_string(), cfg, signer, http, height, st: Mutex::new(PState::default()),
               shards: Mutex::new(IndexMap::new()), stop: Arc::new(AtomicBool::new(false)), thread: Mutex::new(None),
               ids: AtomicU64::new(1), events: Mutex::new(vec![]) }
    }

    fn event(&self, e: Value) {
        lk(&self.events).push(e);
    }

    /// The ch1 channel id.
    pub fn chan(&self) -> Option<String> {
        lk(&self.st).ch.as_ref().map(|c| c.params.channel_id())
    }

    fn pick(&self, pr: &Value) -> Result<Value> {
        for acc in pr.get("accepts").and_then(Value::as_array).into_iter().flatten() {
            if acc.get("scheme").and_then(Value::as_str) == Some(SCHEME) && acc.get("network").and_then(Value::as_str) == Some(&self.cfg.network) {
                let ex = acc.get("extra").cloned().unwrap_or(Value::Null);
                if py_u64(ex.get("closeFeeSat")).is_none_or(|f| f > self.cfg.max_close_fee) {
                    return fail("bad_offer", "closeFeeSat above our cap");
                }
                if let Some(fp) = ex.get("closeFeePayer") {
                    FeePayer::parse(fp.as_str().unwrap_or("")).map_err(|_| ChannelError::new("bad_offer", "unknown closeFeePayer"))?;
                }
                if ex.get("derivation").and_then(Value::as_str) != Some(DERIVATION) {
                    return fail("bad_offer", "payee key derivation is not v2 (xbt402 v1.1)");
                }
                return Ok(acc.clone());
            }
        }
        fail("no_scheme", format!("no {SCHEME} offer on {}", self.cfg.network))
    }

    fn refresh_quote(&self, st: &mut PState, routing: &Value) -> Result<()> {
        let q = FeeQuote::from_json(routing.get("quote").unwrap_or(&Value::Null))?;
        if q.hub != st.hub_pay_to || q.network != self.cfg.network || !q.verify() || !q.live(now_f()) {
            return fail("route_fee", "hub fee quote not signed by the hub's payTo, or not live");
        }
        if q.fee_ppm > self.cfg.max_fee_ppm || q.fee_base_msat > self.cfg.max_fee_base_msat {
            return fail("route_fee", format!("hub fee {} msat + {} ppm above our caps", q.fee_base_msat, q.fee_ppm));
        }
        st.quote = Some(q);
        Ok(())
    }

    fn hub_offer(&self) -> Result<Value> {
        let r = self.http.request("GET", &format!("{}{HUB_ROUTE_PATH}", self.hub_url), b"", &[])?;
        if r.status != 402 {
            return fail("bad_offer", format!("hub answered {}, expected 402", r.status));
        }
        self.pick(&hdr_json(&r, "PAYMENT-REQUIRED").ok_or_else(|| ChannelError::new("bad_offer", "402 without PAYMENT-REQUIRED"))?)
    }

    fn post(&self, url: &str, v: &Value) -> Result<Value> {
        let r = self.http.request("POST", url, dumps(v).as_bytes(), &[("Content-Type".into(), "application/json".into())])?;
        let data: Value = serde_json::from_slice(&r.body).map_err(|_| ChannelError::new("provider_error", format!("HTTP {} non-JSON", r.status)))?;
        if r.status != 200 {
            let code = data.get("error").and_then(Value::as_str).filter(|c| safe_code(c)).unwrap_or("provider_error");
            return fail(code, py_str(data.get("detail")));
        }
        Ok(data)
    }

    /// Open ch1 to the hub from its 402 (x402 v2, xbt-channel, `extra.routing`). Returns
    /// `{chan, capacity, expiry}`.
    pub fn open(&self) -> Result<Value> {
        let acc = self.hub_offer()?;
        {
            let mut st = lk(&self.st);
            st.hub_pay_to = py_str(acc.get("payTo"));
            self.refresh_quote(&mut st, acc.get("extra").and_then(|e| e.get("routing")).unwrap_or(&Value::Null))?;
        }
        let ex = acc.get("extra").cloned().unwrap_or(Value::Null);
        let fee_payer = FeePayer::parse(ex.get("closeFeePayer").and_then(Value::as_str).unwrap_or("payer"))?;
        let cap = self.cfg.capacity.max(py_u64(ex.get("minCapacity")).unwrap_or(0));
        if cap > py_u64(ex.get("maxCapacity")).unwrap_or(cap) {
            return fail("budget", "channel capacity outside the hub's range");
        }
        let pubk = hex::decode(self.signer.new_key(&self.hub_url)?).map_err(|_| ChannelError::new("bad_key", "signer key"))?;
        let lo = py_u64(ex.get("minExpiryBlocks")).unwrap_or(0) + 6;
        let hi = py_u64(ex.get("maxExpiryBlocks")).unwrap_or(u64::MAX).saturating_sub(1);
        let expiry = (self.height)()? + (self.cfg.expiry_blocks as u64).max(lo).min(hi) as u32;
        let pay_to = hex::decode(py_str(acc.get("payTo"))).map_err(|_| ChannelError::new("bad_offer", "payTo"))?;
        let p = ChannelParams::derive(&pay_to, &pubk, expiry, py_u64(ex.get("closeFeeSat")).unwrap_or(0), None, &self.cfg.network, fee_payer)?;
        let hrp = if self.cfg.network == XBT_MAINNET { "bc" } else { "bcrt" };
        let (txid, vout) = self.signer.fund(&segwit_address(hrp, &p.spk())?, cap)?;
        let p = p.with_funding(&txid, vout, cap)?;
        self.signer.attach(&self.hub_url, &p)?;
        self.signer.sign_refund(&p.channel_id())?;
        let mut c = json!({"txid": txid, "vout": vout, "capacity": cap, "expiry": expiry, "payerPub": hex::encode(p.payer_pub),
                           "payerSpk": hex::encode(&p.payer_spk), "redeemScript": hex::encode(p.script())});
        if fee_payer != FeePayer::Payer {
            c["closeFeePayer"] = fee_payer.as_str().into();
        }
        let open_url = format!("{}{}", self.hub_url, ex.get("openUrl").and_then(Value::as_str).unwrap_or(OPEN_PATH));
        let r = self.post(&open_url, &json!({"x402Version": 2, "network": self.cfg.network, "channel": c}))?;
        if r.get("closeFeePayer").and_then(Value::as_str).unwrap_or("payer") != fee_payer.as_str() {
            return fail("bad_fee_payer", "the hub opened the channel with another closeFeePayer");
        }
        let out = json!({"chan": p.channel_id(), "capacity": p.capacity, "expiry": p.expiry});
        lk(&self.st).ch = Some(Ch1 { params: p, accepted: acc, seq: 0 });
        Ok(out)
    }

    /// Re-read the hub's 402 for a fresh fee quote.
    pub fn refresh_hub(&self) -> Result<()> {
        let acc = self.hub_offer()?;
        let mut st = lk(&self.st);
        if py_str(acc.get("payTo")) != st.hub_pay_to {
            return fail("bad_offer", "the hub's payTo changed");
        }
        self.refresh_quote(&mut st, acc.get("extra").and_then(|e| e.get("routing")).unwrap_or(&Value::Null))
    }

    /// Start a metered session on a routed path: verify the provider's signed price quote and first
    /// invoice (the hub never touches either).
    pub fn shard(&self, url: &str, method: &str) -> Result<Arc<Shard>> {
        let c = adaptor::random_secret();
        let r = self.http.request(method, url, b"", &[("ROUTE-CLIENT".into(), hex::encode(ecdsa::pubkey(&c)))])?;
        if r.status != 402 {
            return fail("bad_offer", format!("expected a 402 with extra.route, got {}", r.status));
        }
        let acc = self.pick(&hdr_json(&r, "PAYMENT-REQUIRED").ok_or_else(|| ChannelError::new("bad_offer", "no PAYMENT-REQUIRED"))?)?;
        let rt = acc.get("extra").and_then(|e| e.get("route")).cloned().unwrap_or(json!({}));
        let pay_to = py_str(acc.get("payTo"));
        let q = PriceQuote::from_json(rt.get("quote").unwrap_or(&Value::Null))?;
        let inv = Invoice::from_json(rt.get("invoice").unwrap_or(&Value::Null))?;
        if q.pay_to != pay_to || q.network != self.cfg.network || !q.verify() {
            return fail("bad_offer", "price quote not signed by the provider's payTo");
        }
        let session = py_str(rt.get("session"));
        if inv.pay_to != pay_to || inv.session != session || !inv.verify() {
            return fail("bad_invoice", "invoice not signed by the provider's payTo");
        }
        let hub = lk(&self.st).hub_pay_to.clone();
        if !inv.accepts_hub(&hub) {
            return fail("route_blocked", "the provider does not take locks from our hub");
        }
        let (origin, path) = split_url(url);
        let key = session_key(&c, &hex::decode(&pay_to).unwrap_or_default())?;
        let f = |k: &str| rt.get(k).and_then(Value::as_f64).unwrap_or(1.0);
        let sh = Arc::new(Shard { url: url.into(), origin, path, pay_to, session, key, quote: q, window: f("window"), lock_wait: f("lockWait"),
                                  state: Mutex::new(ShardState { invoice: inv.to_json(), last_lock: json!({}), ..Default::default() }) });
        lk(&self.shards).insert(url.to_string(), sh.clone());
        Ok(sh)
    }

    pub fn shards(&self) -> Vec<Arc<Shard>> {
        lk(&self.shards).values().cloned().collect()
    }

    // --- data path -------------------------------------------------------------------------------

    /// One metered call straight to the provider. A 402 with `error: route_credit` means the
    /// provider stopped serving us (its credit window ran out). Err only for a ROUTE-STATE that
    /// is not the provider's (`bad_receipt`) or a transport failure.
    pub fn call(&self, sh: &Arc<Shard>, method: &str, body: &[u8]) -> Result<HttpResponse> {
        let seq = {
            let mut s = lk(&sh.state);
            s.seq += 1;
            s.seq
        };
        let auth = call_auth(&sh.key, &sh.session, seq, &request_digest(method, &sh.path, body));
        let hdr = b64json(&json!({"session": sh.session, "seq": seq, "auth": auth}));
        let t0 = Instant::now();
        let r = self.http.request(method, &sh.url, body, &[("ROUTE-AUTH".into(), hdr)])?;
        lk(&sh.state).call_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
        let mut state = hdr_json(&r, "ROUTE-STATE");
        if state.is_none() && r.status == 402 {
            let doc: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
            state = doc.get("routeState").cloned();
            lk(&sh.state).stopped = doc.get("error").and_then(Value::as_str).unwrap_or("refused").to_string();
        }
        if let Some(state) = state {
            self.apply_state(sh, &state)?;
        }
        if r.status < 400 {
            lk(&sh.state).calls += 1;
        }
        Ok(r)
    }

    fn apply_state(&self, sh: &Arc<Shard>, state: &Value) -> Result<()> {
        if !state_verify(&sh.pay_to, state) || state.get("session").and_then(Value::as_str) != Some(sh.session.as_str()) {
            return fail("bad_receipt", "ROUTE-STATE not signed by the provider for this session");
        }
        let charge = u128_of(state.get("chargeAmsat")).unwrap_or(0);
        if sh.quote.amsat_per_call > 0 && charge > sh.quote.amsat_per_call {
            return fail("bad_receipt", "charged above the signed price quote");
        }
        {
            let mut s = lk(&sh.state);
            s.seen_amsat += charge;
            s.accrued_amsat = s.accrued_amsat.max(u128_of(state.get("accruedAmsat")).unwrap_or(0));
            s.paid_sat = s.paid_sat.max(py_u64(state.get("paidSat")).unwrap_or(0));
            let inv = state.get("invoice").cloned().unwrap_or(json!({}));
            if truthy(inv.get("lockId")) && inv.get("lockId") != s.invoice.get("lockId") {
                if let Ok(i) = Invoice::from_json(&inv) {
                    if i.verify() && i.pay_to == sh.pay_to && i.session == sh.session {
                        s.invoice = inv;
                    }
                }
            }
            if truthy(state.get("lastLock")) {
                s.last_lock = state["lastLock"].clone();
            }
        }
        self.check_pending(Some(sh));
        Ok(())
    }

    // --- locks (serial on ch1) -------------------------------------------------------------------

    fn commit(&self, st: &mut PState, p: &Pending, t_hex: &str, via: &str) {
        st.routed += p.d + p.f;
        st.fee_units = p.units;
        st.fee_paid += p.f;
        st.signed = st.signed.max(p.cum);
        {
            let mut s = lk(&p.shard.state);
            s.locked_sat += p.d;
            s.lock_ms.push(p.t0.elapsed().as_secs_f64() * 1000.0);
        }
        st.stats.locks += 1;
        if p.floor {
            st.stats.floor_locks += 1;
        }
        if via == "provider" {
            st.stats.via_provider += 1;
        }
        self.event(json!({"event": "lock", "provider": p.shard.origin, "lockId": p.lock_id, "amount": p.d, "fee": p.f, "cum1": p.cum,
                          "via": via, "t": &t_hex[..16.min(t_hex.len())]}));
    }

    fn chan_of(st: &PState) -> String {
        st.ch.as_ref().map(|c| c.params.channel_id()).unwrap_or_default()
    }

    fn check_pending(&self, from: Option<&Arc<Shard>>) {
        let mut st = lk(&self.st);
        let Some(p) = st.pending.as_ref() else { return };
        if from.is_some_and(|f| !Arc::ptr_eq(f, &p.shard)) {
            return;
        }
        let ll = lk(&p.shard.state).last_lock.clone();
        if ll.get("lockId").and_then(Value::as_str) == Some(p.lock_id.as_str()) {
            // the provider was paid for this lock: its t is our receipt even if the hub keeps t + r
            let Some(t) = Sc::from_hex_mod_n(&py_str(ll.get("secret"))).and_then(|s| s.secret()) else { return };
            if hex::encode(adaptor::enc(&adaptor::point_of(&t))) != p.t.to_lowercase() {
                return;
            }
            let chan = Self::chan_of(&st);
            if !p.floor && self.signer.resolve_lock(&chan, &hex::encode(t.secret_bytes())).is_err() {
                return;
            }
            let p = st.pending.take().expect("checked");
            self.commit(&mut st, &p, &hex::encode(t.secret_bytes()), "provider");
        } else if now_f() > p.until && !p.inflight {
            // never while our request is out: the hub may still complete it
            let p = st.pending.take().expect("checked");
            self.void(&mut st, &p, "invoice expired unanswered");
        }
    }

    fn void(&self, st: &mut PState, p: &Pending, why: &str) {
        if !p.floor {
            let _ = self.signer.void_lock(&Self::chan_of(st));
            let after = (st.routed + p.d + p.f, p.units, st.fee_paid + p.f);
            st.given_up.push(GivenUp { cum: p.cum, lock_id: p.lock_id.clone(), after });
            if st.given_up.len() > 16 {
                st.given_up.remove(0);
            }
        }
        st.stats.voided += 1;
        self.event(json!({"event": "void", "provider": p.shard.origin, "lockId": p.lock_id, "amount": p.d, "why": why}));
    }

    /// The hub completed a lock we had given up (it read t off the provider's ch2 close). Adopt its
    /// view only if its best state is one of those locks, with the counters it implied.
    fn resync(&self, st: &mut PState, doc: &Value) -> bool {
        let (Some(best), Some(r), Some(u), Some(pd)) = (py_u64(doc.get("bestCum")), py_u64(doc.get("routedSat")), u128_of(doc.get("feeUnits")),
                                                        py_u64(doc.get("feePaid"))) else { return false };
        let Some(i) = st.given_up.iter().position(|g| g.cum == best && g.after == (r, u, pd)) else { return false };
        if best <= st.signed {
            return false;
        }
        if self.signer.adopt_lock(&Self::chan_of(st), best).is_err() {
            return false;
        }
        (st.routed, st.fee_units, st.fee_paid, st.signed) = (r, u, pd, best);
        let g = st.given_up.remove(i);
        self.event(json!({"event": "resync", "lockId": g.lock_id, "cum1": best}));
        true
    }

    /// Pay `sh`'s accrued amount through the hub with one adaptor lock. `Ok(None)` if nothing is
    /// due or a lock is still pending on ch1; otherwise `{status: paid|refused|resynced|pending...}`.
    pub fn lock(&self, sh: &Arc<Shard>) -> Result<Option<Value>> {
        self.check_pending(None);
        let (id, pl, body, accepted, d, f, floor) = {
            let mut st = lk(&self.st);
            if st.pending.is_some() || st.ch.is_none() {
                return Ok(None);
            }
            let due = sh.due_sat();
            let inv = lk(&sh.state).invoice.clone();
            let vu = inv.get("validUntil").and_then(Value::as_f64).unwrap_or(0.0);
            let rts = st.quote.as_ref().map(|q| q.reveal_timeout_sec).unwrap_or(10) as f64;
            // the hub may wait revealTimeoutSec for the provider: lock only with that much invoice left
            if due < 1 || vu < now_f() + 1.0 + rts {
                return Ok(None);
            }
            if !st.quote.as_ref().is_some_and(|q| q.live(now_f() + 30.0)) {
                drop(st);
                self.refresh_hub()?;
                return Ok(None);
            }
            let q = st.quote.clone().expect("live");
            let d = (due as u64).min(self.cfg.max_lock_sat).min(q.max_lock_sat);
            let (f, units) = fee_due(&q, d, st.fee_units, st.fee_paid);
            let ch = st.ch.as_ref().expect("open");
            let (chan, min_amount) = (ch.params.channel_id(), ch.params.min_amount());
            let cum = next_cum(st.routed, d + f, min_amount);
            let floor = cum <= st.signed;
            let lock_id = py_str(inv.get("lockId"));
            let point = py_str(inv.get("point"));
            let mut route = json!({"provider": sh.origin, "payTo": sh.pay_to, "network": self.cfg.network, "amount": d, "point": point,
                                   "fee": f, "feeQuote": q.to_json(), "invoice": inv, "session": sh.session, "lockId": lock_id,
                                   "lockAuth": lock_auth(&sh.key, &sh.session, &lock_id, d as i128, &point, &st.hub_pay_to)});
            let id = self.ids.fetch_add(1, Ordering::Relaxed);
            let mut p = Pending { id, shard: sh.clone(), lock_id: lock_id.clone(), d, f, units, cum: cum.max(st.signed), floor, t: point.clone(),
                                  t1: String::new(), until: vu + self.cfg.void_grace, t0: Instant::now(), inflight: true };
            let mut pl;
            if floor {
                route["tweak"] = "00".repeat(32).into();
                pl = json!({"chan": chan, "seq": 0, "cum": st.signed.to_string()});
            } else {
                let sa = self.signer.sign_state_adaptor(&chan, cum, &point, &json!({"hub": self.hub_url, "provider": sh.origin, "lockId": lock_id,
                                                                                     "amount": d, "fee": f}))?;
                route["tweak"] = sa.tweak.into();
                p.t1 = sa.point.clone();
                pl = json!({"chan": chan, "seq": 0, "cum": cum.to_string(), "adaptor": sa.adaptor, "point": sa.point});
            }
            let body = dumps(&json!({"route": route}));
            let ch = st.ch.as_mut().expect("open");
            ch.seq += 1;
            pl["seq"] = ch.seq.into();
            let accepted = ch.accepted.clone();
            let auth = self.signer.request_auth(&chan, &pl["seq"], &pl["cum"], None, &request_digest("POST", HUB_ROUTE_PATH, body.as_bytes()));
            match auth {
                Ok(a) => pl["auth"] = a.into(),
                Err(e) => {
                    if !floor {
                        let _ = self.signer.void_lock(&chan);
                    }
                    return Err(e);
                }
            }
            st.pending = Some(p);
            (id, pl, body, accepted, d, f, floor)
        };
        let r = self.http.request("POST", &format!("{}{HUB_ROUTE_PATH}", self.hub_url), body.as_bytes(),
                                  &[("PAYMENT-SIGNATURE".into(), b64json(&json!({"x402Version": 2, "accepted": accepted, "payload": pl}))),
                                    ("Content-Type".into(), "application/json".into())]);
        let (status, doc) = match r {
            Ok(r) => (r.status, serde_json::from_slice::<Value>(&r.body).unwrap_or(Value::Null)),
            Err(_) => (0, Value::Null),
        };
        let mut st = lk(&self.st);
        match st.pending.as_mut() {
            Some(p) if p.id == id => p.inflight = false,
            _ => return Ok(Some(json!({"status": "resolved_elsewhere"}))),
        }
        let chan = Self::chan_of(&st);
        if status == 200 && truthy(doc.get("secret")) {
            let Some(y) = Sc::from_hex_mod_n(&py_str(doc.get("secret"))).and_then(|s| s.secret()) else {
                return Ok(Some(json!({"status": "pending", "why": "bad secret"})));
            };
            let yp = hex::encode(adaptor::enc(&adaptor::point_of(&y)));
            let p = st.pending.as_ref().expect("ours");
            let t = if floor {
                if yp != p.t.to_lowercase() {
                    return Ok(Some(json!({"status": "pending", "why": "bad secret"})));
                }
                hex::encode(y.secret_bytes())
            } else {
                // the answer must open OUR T1: a hub replaying its answer to an earlier attempt at this
                // invoice (whose lock we gave up) is refused here, and resynced on the next lock
                if doc.get("lockId").and_then(Value::as_str) != Some(p.lock_id.as_str()) || yp != p.t1 {
                    let p = st.pending.take().expect("ours");
                    self.void(&mut st, &p, "hub answer does not open this lock");
                    self.event(json!({"event": "stale_answer", "lockId": p.lock_id, "cum1": doc.get("cum")}));
                    return Ok(Some(json!({"status": "refused", "error": "stale_answer"})));
                }
                match self.signer.resolve_lock(&chan, &py_str(doc.get("secret"))) {
                    Ok(t) => t,
                    Err(e) => return Ok(Some(json!({"status": "pending", "why": e.to_string()}))),
                }
            };
            let p = st.pending.take().expect("ours");
            self.commit(&mut st, &p, &t, "hub");
            return Ok(Some(json!({"status": "paid", "amount": d, "fee": f, "lockId": p.lock_id})));
        }
        let code = doc.get("error").and_then(Value::as_str).map(str::to_string);
        if code.as_deref() == Some("bad_amount") && self.resync(&mut st, &doc) {
            if let Some(p) = st.pending.take() {
                self.void(&mut st, &p, "hub: resynced");
            }
            return Ok(Some(json!({"status": "resynced"})));
        }
        if [400, 401, 402, 502].contains(&status) {
            if let Some(code) = code {
                // the hub refused (or the provider did, through it): nothing was completed with t
                *st.stats.refused.entry(code.clone()).or_insert(0) += 1;
                if let Some(p) = st.pending.take() {
                    self.void(&mut st, &p, &format!("hub: {code}"));
                }
                return Ok(Some(json!({"status": "refused", "error": code})));
            }
        }
        Ok(Some(json!({"status": "pending", "http": status})))
    }

    // --- background locking ----------------------------------------------------------------------

    /// One pass: try a lock for every shard.
    pub fn tick(&self) {
        for sh in self.shards() {
            if self.stop.load(Ordering::Relaxed) {
                return;
            }
            if let Err(e) = self.lock(&sh) {
                self.event(json!({"event": "lock_error", "provider": sh.origin, "error": e.code}));
            }
        }
    }

    /// Run [`RoutePayer::tick`] every `interval` on a background thread.
    pub fn start(self: &Arc<Self>, interval: Duration) {
        self.stop.store(false, Ordering::Relaxed);
        let me = self.clone();
        let h = std::thread::Builder::new().name("route-payer".into()).spawn(move || {
            let mut next = Instant::now();
            while !me.stop.load(Ordering::Relaxed) {
                next += interval;
                me.tick();
                let now = Instant::now();
                if next > now {
                    std::thread::sleep(next - now);
                }
            }
        }).expect("spawn");
        *lk(&self.thread) = Some(h);
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = lk(&self.thread).take() {
            let _ = h.join();
        }
    }

    /// Cooperative close of ch1: the hub closes with the best state it holds (every completed lock
    /// is already a plain state there, so no final state is needed).
    pub fn close(&self) -> Result<Value> {
        let (chan, url) = {
            let st = lk(&self.st);
            let ch = st.ch.as_ref().ok_or_else(|| ChannelError::code("no_channel"))?;
            let cu = ch.accepted.get("extra").and_then(|e| e.get("closeUrl")).and_then(Value::as_str).unwrap_or(CLOSE_PATH).to_string();
            (ch.params.channel_id(), format!("{}{cu}", self.hub_url))
        };
        let sig = self.signer.sign_close(&chan)?;
        self.post(&url, &json!({"chan": chan, "sig": sig}))
    }

    /// Meters, locks and counters.
    pub fn summary(&self) -> Value {
        let st = lk(&self.st);
        let shards: serde_json::Map<String, Value> = lk(&self.shards).iter().map(|(u, s)| {
            let x = s.snapshot();
            (u.clone(), json!({"accrued_amsat": x.accrued_amsat.to_string(), "seen_amsat": x.seen_amsat.to_string(), "paid_sat": x.paid_sat,
                               "locked_sat": x.locked_sat, "calls": x.calls, "stopped": x.stopped, "pay_to": s.pay_to, "session": s.session}))
        }).collect();
        json!({"chan": st.ch.as_ref().map(|c| c.params.channel_id()), "routed_sat": st.routed, "fee_paid_sat": st.fee_paid,
               "fee_units": st.fee_units.to_string(), "signed": st.signed, "locks": st.stats.locks, "floor_locks": st.stats.floor_locks,
               "voided": st.stats.voided, "via_provider": st.stats.via_provider,
               "refused": st.stats.refused.iter().map(|(k, v)| (k.clone(), Value::from(*v))).collect::<serde_json::Map<String, Value>>(), "shards": shards})
    }

    pub fn stats(&self) -> PayerStats {
        lk(&self.st).stats.clone()
    }

    /// (routed, fee_paid, signed) on ch1.
    pub fn totals(&self) -> (u64, u64, u64) {
        let st = lk(&self.st);
        (st.routed, st.fee_paid, st.signed)
    }

    /// The hub's live fee quote as last seen.
    pub fn quote(&self) -> Option<FeeQuote> {
        lk(&self.st).quote.clone()
    }

    /// (routed, fee units, fee paid, signed) on ch1.
    pub fn counters(&self) -> (u64, u128, u64, u64) {
        let st = lk(&self.st);
        (st.routed, st.fee_units, st.fee_paid, st.signed)
    }

    pub fn hub_pay_to(&self) -> String {
        lk(&self.st).hub_pay_to.clone()
    }

    pub fn signer(&self) -> &Arc<dyn StateSigner> {
        &self.signer
    }

    /// ch1's accepted requirements and a fresh request seq (to build a request by hand: tests,
    /// tools).
    #[doc(hidden)]
    pub fn next_seq(&self) -> Option<(u64, Value)> {
        let mut st = lk(&self.st);
        let ch = st.ch.as_mut()?;
        ch.seq += 1;
        Some((ch.seq, ch.accepted.clone()))
    }

    /// Rewind ch1's request seq (tests: a stale seq).
    #[doc(hidden)]
    pub fn set_seq(&self, seq: u64) {
        if let Some(ch) = lk(&self.st).ch.as_mut() {
            ch.seq = seq;
        }
    }

    /// The pending lock, if any: `{lockId, d, f, cum, floor, until}`.
    pub fn pending(&self) -> Option<Value> {
        lk(&self.st).pending.as_ref().map(|p| json!({"lockId": p.lock_id, "d": p.d, "f": p.f, "cum": p.cum, "floor": p.floor, "until": p.until}))
    }

    /// Treat the pending lock's invoice as expired now and re-check it (tests).
    #[doc(hidden)]
    pub fn expire_pending(&self) {
        if let Some(p) = lk(&self.st).pending.as_mut() {
            p.until = now_f() - 1.0;
        }
        self.check_pending(None);
    }

    /// The cum of the last lock given up.
    pub fn last_given_up(&self) -> Option<u64> {
        lk(&self.st).given_up.last().map(|g| g.cum)
    }

    /// Adopt a hub view (`{bestCum, routedSat, feeUnits, feePaid}`) if it is a lock we gave up.
    #[doc(hidden)]
    pub fn try_resync(&self, doc: &Value) -> bool {
        let mut st = lk(&self.st);
        self.resync(&mut st, doc)
    }

    /// ch1's parameters.
    pub fn ch1_params(&self) -> Option<ChannelParams> {
        lk(&self.st).ch.as_ref().map(|c| c.params.clone())
    }
}
