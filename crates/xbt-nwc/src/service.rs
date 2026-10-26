//! The NWC wallet service: NIP-47 requests in, the signer's methods out, NIP-47 responses back.
//!
//! A request is answered only when every one of these holds: it is a kind 23194 event with a valid
//! id and signature; its `p` tag is the service key of one of our connections; its author is that
//! connection's app key; it is not past its `expiration` tag, not older than an hour, and not seen
//! before. Anything else is dropped without an answer (an unknown key learns nothing). Then:
//! NIP-44 v2 only (anything else is answered `UNSUPPORTED_ENCRYPTION`), the connection's expiry
//! (`UNAUTHORIZED`), its request rate (`RATE_LIMITED`), its allowed methods (`RESTRICTED`).
//!
//! `pay_invoice` reaches the signer's `ln_pay` with `max_sats` set to what is left of the
//! connection's budget for the last 24 hours, so the signer refuses anything that, with its fee
//! limit, would exceed it, and every other rule of the owner's policy (budgets, allowlist, the human
//! threshold, the Lightning rail's checks: feature bit 512, the chain, the channels) applies exactly
//! as it does to an agent's payment. The payment is booked against the connection before the
//! signer sees it, at that ceiling, and becomes what it cost when it settles.
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt_signer::bolt11::{self, FEATURE_BLAKE2B};
use xbt_signer::client::SignerClient;

use crate::event::{parse_pubkey, tag, Event, Keys, KIND_INFO, KIND_REQUEST, KIND_RESPONSE};
use crate::nip44;
use crate::relay::{Hub, Pool};
use crate::store::{Connection, PaymentRec, Store, METHODS};
use crate::ws::parse_url;

/// The subscription id this service uses on every relay.
const SUBSCRIPTION: &str = "nwc";
/// How far back a (re)subscription asks for requests: ones sent while the relay was reconnecting.
const SINCE_S: u64 = 300;
/// A request older than this is dropped (a replay, or one that waited too long on a relay).
const MAX_AGE_S: u64 = 3600;
const MAX_FUTURE_S: u64 = 600;
/// A pending payment the signer has no record of is taken as never sent after this long.
const UNSEEN_AFTER_S: u64 = 900;
/// How long `pay_invoice` follows a payment the signer answered as still in flight.
const PENDING_WAIT: Duration = Duration::from_secs(60);
/// Requests handled at once; more are dropped (and answered by nobody) until one finishes.
const MAX_WORKERS: usize = 32;
pub const MAX_RELAYS: usize = 8;
/// The most `list_transactions` puts in one answer, in bytes of JSON (a page: `offset` asks for more).
const MAX_LIST_BYTES: usize = 60_000;
pub const MAX_BUDGET_SATS: i64 = 100_000_000;

pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

pub struct Config {
    pub state_dir: PathBuf,
    /// The signer's socket.
    pub signer: PathBuf,
    pub signer_timeout: Duration,
    /// The relays a new connection uses when none are given.
    pub default_relays: Vec<String>,
    /// How long a payment above the owner's human threshold waits for the owner's approval in the
    /// wallet UI before it is answered; 0: at once (the grant stays, and the same invoice paid again
    /// after the approval goes through).
    pub approval_wait: Duration,
    /// Requests per connection per minute.
    pub rate_per_min: usize,
    pub clock: Option<Clock>,
}

impl Config {
    pub fn new(state_dir: PathBuf, signer: PathBuf) -> Self {
        Self { state_dir, signer, signer_timeout: Duration::from_secs(120), default_relays: vec![], approval_wait: Duration::ZERO,
               rate_per_min: 60, clock: None }
    }
}

/// A NIP-47 error: its code and its message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NwcErr {
    pub code: &'static str,
    pub message: String,
}

fn e(code: &'static str, m: impl Into<String>) -> NwcErr {
    NwcErr { code, message: m.into() }
}

pub struct Service {
    cfg: Config,
    store: Mutex<Store>,
    signer: SignerClient,
    pool: OnceLock<Arc<Pool>>,
    seen: Mutex<HashMap<String, u64>>,
    rate: Mutex<HashMap<String, VecDeque<u64>>>,
    pay: Mutex<()>,
    workers: AtomicUsize,
    me: Weak<Service>,
}

fn s(v: Option<&Value>) -> &str {
    v.and_then(Value::as_str).unwrap_or("")
}

fn int(v: Option<&Value>) -> Option<i64> {
    v.and_then(|x| x.as_i64().or_else(|| x.as_f64().map(|f| f as i64)))
}

/// Percent-encode a query value (everything but RFC 3986's unreserved characters).
pub fn urlenc(v: &str) -> String {
    v.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

impl Service {
    pub fn new(cfg: Config) -> Result<Arc<Self>, String> {
        let store = Store::open(&cfg.state_dir)?;
        let signer = SignerClient { sock_path: cfg.signer.clone(), timeout: cfg.signer_timeout };
        Ok(Arc::new_cyclic(|me| Self { cfg, store: Mutex::new(store), signer, pool: OnceLock::new(), seen: Mutex::new(HashMap::new()),
                                       rate: Mutex::new(HashMap::new()), pay: Mutex::new(()), workers: AtomicUsize::new(0), me: me.clone() }))
    }

    pub fn now(&self) -> u64 {
        self.cfg.clock.as_ref().map(|c| c()).unwrap_or_else(crate::now)
    }

    /// Connect to the relays of every connection.
    pub fn start(self: &Arc<Self>) {
        let hub: Weak<dyn Hub> = self.me.clone();
        let pool = self.pool.get_or_init(|| Pool::new(hub)).clone();
        pool.sync(&self.relays(), false);
    }

    pub fn stop(&self) {
        if let Some(p) = self.pool.get() {
            p.stop();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Every relay some connection uses, sorted.
    fn relays(&self) -> Vec<String> {
        let st = self.lock();
        let mut v: Vec<String> = st.connections.iter().flat_map(|c| c.relays.iter().cloned()).collect();
        v.sort();
        v.dedup();
        v
    }

    fn resync(&self) {
        if let Some(p) = self.pool.get() {
            p.sync(&self.relays(), true);
        }
    }

    /// Run `f` on the connection with this service key, and save the state after it.
    fn mutate<R>(&self, svc: &str, f: impl FnOnce(&mut Connection) -> R) -> Option<R> {
        let mut st = self.lock();
        let i = st.by_service(svc)?;
        let r = f(&mut st.connections[i]);
        if let Err(err) = st.save() {
            eprintln!("xbt-nwc: the state could not be saved: {err}");
        }
        Some(r)
    }

    fn read<R>(&self, svc: &str, f: impl FnOnce(&Connection) -> R) -> Option<R> {
        let st = self.lock();
        st.by_service(svc).map(|i| f(&st.connections[i]))
    }

    fn info_event(c: &Connection, now: u64) -> Option<Event> {
        let keys = Keys::from_hex(&c.service_secret)?;
        Some(Event::sign(&keys, now, KIND_INFO, vec![tag("encryption", "nip44_v2")], c.methods.join(" ")))
    }

    // --- requests -------------------------------------------------------------------------------

    /// Answer one event from a relay: `None` when it is not ours to answer.
    pub fn handle(&self, ev: &Event) -> Option<Event> {
        if ev.kind != KIND_REQUEST || !ev.verify() {
            return None;
        }
        let now = self.now();
        let svc = ev.tag("p")?.to_ascii_lowercase();
        let (keys, client, expired) = self.read(&svc, |c| (Keys::from_hex(&c.service_secret), c.client_pubkey.clone(), c.expired(now)))?;
        let keys = keys?;
        // an unknown key learns nothing, not even that this service exists
        if ev.pubkey != client {
            return None;
        }
        if ev.tag("expiration").and_then(|t| t.parse::<u64>().ok()).is_some_and(|t| t <= now) {
            return None;
        }
        if ev.created_at + MAX_AGE_S < now || ev.created_at > now + MAX_FUTURE_S {
            return None;
        }
        {
            let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
            seen.retain(|_, t| *t + 2 * MAX_AGE_S > now);
            if seen.insert(ev.id.clone(), now).is_some() {
                return None;
            }
        }
        let client_pk = parse_pubkey(&client)?;
        let ck = nip44::conversation_key(&keys.secret, &client_pk);
        let reply = |method: &str, r: Result<Value, NwcErr>| -> Option<Event> {
            let body = match r {
                Ok(v) => json!({"result_type": method, "error": null, "result": v}),
                Err(err) => json!({"result_type": method, "error": {"code": err.code, "message": err.message}, "result": null}),
            };
            let content = nip44::encrypt(&body.to_string(), &ck).ok()?;
            Some(Event::sign(&keys, now, KIND_RESPONSE, vec![tag("p", &client), tag("e", &ev.id)], content))
        };
        match ev.tag("encryption") {
            Some("nip44_v2") => {}
            // NIP-04 (the tag absent, or named) is not supported: it is deprecated, and unauthenticated
            other => return reply("", Err(e("UNSUPPORTED_ENCRYPTION", format!("only nip44_v2 is supported here, not {}", other.unwrap_or("nip04"))))),
        }
        let req: Value = match nip44::decrypt(&ev.content, &ck).ok().and_then(|t| serde_json::from_str(&t).ok()) {
            Some(v) => v,
            None => return reply("", Err(e("OTHER", "the request could not be decrypted or read"))),
        };
        let method = s(req.get("method")).to_string();
        let empty = json!({});
        let params = req.get("params").filter(|p| p.is_object()).unwrap_or(&empty);
        if expired {
            return reply(&method, Err(e("UNAUTHORIZED", "this connection has expired: make a new one in the wallet")));
        }
        if !self.rate_ok(&svc, now) {
            return reply(&method, Err(e("RATE_LIMITED", "too many requests: retry in a few seconds")));
        }
        self.mutate(&svc, |c| c.last_used = now);
        let r = self.dispatch(&svc, &method, params);
        reply(&method, r)
    }

    fn rate_ok(&self, svc: &str, now: u64) -> bool {
        let mut rate = self.rate.lock().unwrap_or_else(|p| p.into_inner());
        let q = rate.entry(svc.to_string()).or_default();
        while q.front().is_some_and(|t| *t + 60 <= now) {
            q.pop_front();
        }
        if q.len() >= self.cfg.rate_per_min {
            return false;
        }
        q.push_back(now);
        true
    }

    fn dispatch(&self, svc: &str, method: &str, p: &Value) -> Result<Value, NwcErr> {
        if !METHODS.contains(&method) {
            return Err(match method {
                "make_invoice" => e("NOT_IMPLEMENTED", "make_invoice is not offered: this wallet has no receive path yet (its Lightning \
                                                       access can pay, not create invoices)"),
                _ => e("NOT_IMPLEMENTED", format!("{method} is not offered by this wallet")),
            });
        }
        if !self.read(svc, |c| c.allows(method)).unwrap_or(false) {
            return Err(e("RESTRICTED", format!("this connection is not allowed {method}")));
        }
        match method {
            "pay_invoice" => self.pay_invoice(svc, p),
            "get_balance" => self.get_balance(svc),
            "get_info" => self.get_info(svc),
            "lookup_invoice" => self.lookup_invoice(svc, p),
            "list_transactions" => self.list_transactions(svc, p),
            _ => Err(e("NOT_IMPLEMENTED", method.to_string())),
        }
    }

    /// Bring a pending payment up to date from the signer's book.
    fn reconcile(&self, svc: &str, hash: &str) -> Option<PaymentRec> {
        let pending = self.read(svc, |c| c.find(hash).map(|r| r.state == "pending"))??;
        let looked = if pending { self.signer.call("ln_lookup", json!({"payment_hash": hash})).ok() } else { None };
        let now = self.now();
        self.mutate(svc, |c| {
            let mut add = 0i64;
            let out = {
                let rec = c.find_mut(hash)?;
                if rec.state == "pending" {
                    match &looked {
                        Some(v) if v["found"] == true => match s(v.get("state")) {
                            "settled" => {
                                rec.state = "settled".into();
                                rec.spent_sats = int(v.get("spent_sats")).unwrap_or(rec.booked_sats);
                                rec.fees_paid_msat = int(v.get("fee_msat")).unwrap_or(0).max(0) as u64;
                                rec.preimage = v.get("preimage").and_then(Value::as_str).map(str::to_string);
                                rec.settled_at = Some(int(v.get("settled_ts")).map(|t| t as u64).unwrap_or(now));
                                add = rec.spent_sats;
                            }
                            "failed" => {
                                rec.state = "failed".into();
                                rec.booked_sats = 0;
                            }
                            // still in flight: what the signer booked (never more than our ceiling)
                            _ => {
                                if let Some(b) = int(v.get("booked_sats")) {
                                    rec.booked_sats = b.min(rec.booked_sats);
                                }
                            }
                        },
                        Some(v) if v["found"] == false && rec.created_at + UNSEEN_AFTER_S < now => {
                            rec.state = "failed".into();
                            rec.booked_sats = 0;
                        }
                        _ => {}
                    }
                }
                rec.clone()
            };
            c.spent_total_sats = c.spent_total_sats.saturating_add(add);
            Some(out)
        })?
    }

    fn reconcile_all(&self, svc: &str) {
        let hashes = self.read(svc, |c| c.payments.iter().filter(|p| p.state == "pending").map(|p| p.payment_hash.clone()).collect::<Vec<_>>())
            .unwrap_or_default();
        for h in hashes {
            self.reconcile(svc, &h);
        }
    }

    fn set_state(&self, svc: &str, hash: &str, f: impl FnOnce(&mut PaymentRec) -> i64) {
        self.mutate(svc, |c| {
            let add = c.find_mut(hash).map(f).unwrap_or(0);
            c.spent_total_sats = c.spent_total_sats.saturating_add(add);
        });
    }

    fn fail(&self, svc: &str, hash: &str) {
        self.set_state(svc, hash, |r| {
            r.state = "failed".into();
            r.booked_sats = 0;
            0
        });
    }

    fn paid(rec: &PaymentRec) -> Value {
        json!({"preimage": rec.preimage.clone().unwrap_or_default(), "fees_paid": rec.fees_paid_msat})
    }

    fn pay_invoice(&self, svc: &str, p: &Value) -> Result<Value, NwcErr> {
        let invoice = s(p.get("invoice")).trim().to_string();
        if invoice.is_empty() {
            return Err(e("OTHER", "params.invoice is required"));
        }
        let lower = invoice.to_ascii_lowercase();
        if lower.starts_with("lno1") || lower.starts_with("lni1") || lower.starts_with("lnr1") {
            return Err(e("NOT_IMPLEMENTED", "pay_invoice takes a BOLT 11 invoice; BOLT 12 offers are not paid through this connection"));
        }
        let inv = bolt11::decode(&invoice).map_err(|err| e("OTHER", format!("not a valid BOLT 11 invoice: {err}")))?;
        if !inv.has_feature(FEATURE_BLAKE2B) {
            return Err(e("OTHER", "the invoice lacks feature bit 512 (option_blake2b): it is not an XBT Lightning invoice, and this \
                                   wallet pays XBT Lightning only"));
        }
        let Some(msat) = inv.amount_msat.filter(|m| *m > 0) else {
            return Err(e("NOT_IMPLEMENTED", "an invoice without an amount is not paid: the amount must be in the payee's signature"));
        };
        if let Some(a) = p.get("amount").filter(|a| !a.is_null()) {
            if a.as_u64() != Some(msat) {
                return Err(e("OTHER", "params.amount differs from the invoice's amount"));
            }
        }
        let amount_sats = msat.div_ceil(1000) as i64;
        let hash = inv.payment_hash_hex();
        let _g = self.pay.lock().unwrap_or_else(|p| p.into_inner());
        // asked before (an app that retries): the same answer, never a second payment
        if self.read(svc, |c| c.find(&hash).is_some()).unwrap_or(false) {
            let rec = self.reconcile(svc, &hash).ok_or_else(|| e("INTERNAL", "the connection is gone"))?;
            match rec.state.as_str() {
                "settled" => return Ok(Self::paid(&rec)),
                "pending" => return Err(e("OTHER", "this invoice's payment is still in flight: lookup_invoice shows its outcome")),
                _ => {}
            }
        }
        self.reconcile_all(svc);
        let now = self.now();
        let remaining = self.read(svc, |c| c.remaining(now)).ok_or_else(|| e("UNAUTHORIZED", "this connection is gone"))?;
        if amount_sats > remaining {
            return Err(e("QUOTA_EXCEEDED", format!("this connection has {remaining} sats left of its budget for the last 24 hours; the \
                                                    invoice is {amount_sats} sats")));
        }
        // booked against the connection before the signer sees it, at the most the signer may charge
        let rec = PaymentRec { payment_hash: hash.clone(), invoice: invoice.clone(), amount_msat: msat, booked_sats: remaining, spent_sats: 0,
                               fees_paid_msat: 0, state: "pending".into(), preimage: None, description: inv.description.clone(),
                               description_hash: inv.description_hash.map(hex::encode), created_at: now, expires_at: Some(inv.expires_at()),
                               settled_at: None };
        self.mutate(svc, |c| c.push(rec)).ok_or_else(|| e("UNAUTHORIZED", "this connection is gone"))?;
        let params = json!({"invoice": invoice, "max_sats": remaining});
        let mut r = self.signer.call("ln_pay", params.clone());
        if let Ok(v) = &r {
            if v["verdict"] == "needs_human" && !self.cfg.approval_wait.is_zero() {
                if let Some(again) = self.wait_for_approval(s(v.get("approval_token")), &params) {
                    r = Ok(again);
                }
            }
        }
        self.finish(svc, &hash, r)
    }

    /// Wait for the owner's approval of `token`; once approved, pay again under the grant.
    fn wait_for_approval(&self, token: &str, params: &Value) -> Option<Value> {
        if token.is_empty() {
            return None;
        }
        let until = Instant::now() + self.cfg.approval_wait;
        while Instant::now() < until {
            std::thread::sleep(Duration::from_millis(500));
            let st = self.signer.call("approval_status", json!({"token": token})).ok()?;
            match s(st.get("state")) {
                "approved" => return self.signer.call("ln_pay", params.clone()).ok(),
                "pending" => {}
                _ => return None,
            }
        }
        None
    }

    fn finish(&self, svc: &str, hash: &str, r: xbt_signer::Result<Value>) -> Result<Value, NwcErr> {
        let v = match r {
            Ok(v) => v,
            // the booking stays: the signer may have sent it; lookup_invoice reconciles it later
            Err(_) => return Err(e("INTERNAL", "the wallet's signer did not answer; the payment may still complete: lookup_invoice shows \
                                               its outcome")),
        };
        let reason = s(v.get("reason")).to_string();
        match s(v.get("verdict")) {
            "allow" if v["status"] == "SUCCEEDED" => {
                let spent = int(v.get("charged_sats")).unwrap_or(0);
                let fee = int(v.get("fee_msat")).unwrap_or(0).max(0) as u64;
                let pre = v.get("preimage").and_then(Value::as_str).map(str::to_string);
                let now = self.now();
                self.set_state(svc, hash, |rec| {
                    rec.state = "settled".into();
                    rec.spent_sats = spent;
                    rec.fees_paid_msat = fee;
                    rec.preimage = pre.clone();
                    rec.settled_at = Some(now);
                    spent
                });
                Ok(json!({"preimage": pre.unwrap_or_default(), "fees_paid": fee}))
            }
            "pending" => {
                if let Some(b) = int(v.get("charged_sats")) {
                    self.set_state(svc, hash, |rec| {
                        rec.booked_sats = b.min(rec.booked_sats);
                        0
                    });
                }
                let until = Instant::now() + PENDING_WAIT;
                while Instant::now() < until {
                    std::thread::sleep(Duration::from_secs(1));
                    match self.reconcile(svc, hash) {
                        Some(rec) if rec.state == "settled" => return Ok(Self::paid(&rec)),
                        Some(rec) if rec.state == "failed" => return Err(e("PAYMENT_FAILED", "the Lightning payment failed; nothing was spent")),
                        Some(_) => {}
                        None => break,
                    }
                }
                Err(e("OTHER", "the payment is still in flight: lookup_invoice shows its outcome"))
            }
            "needs_human" => {
                self.fail(svc, hash);
                Err(e("QUOTA_EXCEEDED", "this payment needs the wallet owner's approval: it is waiting on the wallet's Approvals page; pay \
                                         the same invoice again once it is approved"))
            }
            "deny" => {
                self.fail(svc, hash);
                let rule = s(v.get("rule"));
                let code = match rule {
                    "ln_payment_failed" => "PAYMENT_FAILED",
                    "daily_budget" | "weekly_budget" | "max_per_tx" | "per_counterparty" | "per_counterparty_cap" | "max_sats" | "ln_htlc_lock"
                    | "split_bypass" => "QUOTA_EXCEEDED",
                    "velocity" | "ln_rate_limit" | "ln_in_flight" => "RATE_LIMITED",
                    "allowlist" => "RESTRICTED",
                    "ln_disabled" | "ln_unavailable" | "ln_config" | "ln_halted" | "ln_backend" | "ln_chain" | "ln_macaroon" => "INTERNAL",
                    _ => "OTHER",
                };
                Err(e(code, if reason.is_empty() { format!("refused by the wallet's policy ({rule})") } else { format!("{rule}: {reason}") }))
            }
            _ => {
                self.fail(svc, hash);
                Err(e("OTHER", if reason.is_empty() { "the wallet did not pay".to_string() } else { reason }))
            }
        }
    }

    /// What this connection may spend now: what is left of its budget, and no more than the node's
    /// channels hold on our side, as the signer reports them.
    fn get_balance(&self, svc: &str) -> Result<Value, NwcErr> {
        self.reconcile_all(svc);
        let now = self.now();
        let remaining = self.read(svc, |c| c.remaining(now)).ok_or_else(|| e("UNAUTHORIZED", "this connection is gone"))?;
        let local = self.signer.call("ln_status", json!({})).ok().and_then(|st| int(st.get("exposure").and_then(|x| x.get("channel_local_sats"))));
        let sats = local.map(|l| l.min(remaining)).unwrap_or(remaining).max(0);
        Ok(json!({"balance": sats.saturating_mul(1000)}))
    }

    fn get_info(&self, svc: &str) -> Result<Value, NwcErr> {
        let methods = self.read(svc, |c| c.methods.clone()).ok_or_else(|| e("UNAUTHORIZED", "this connection is gone"))?;
        let health = self.signer.call("health", json!({})).map_err(|_| e("INTERNAL", "the wallet's signer did not answer"))?;
        let network = match s(health.get("chain")) {
            "main" => "mainnet",
            "test" | "testnet" => "testnet",
            "signet" => "signet",
            "regtest" => "regtest",
            other => other,
        }.to_string();
        let mut out = json!({"alias": "Lightning Stream", "network": network, "methods": methods, "notifications": []});
        if let Some(h) = self.signer.call("ln_status", json!({})).ok().and_then(|st| int(st.get("node").and_then(|n| n.get("block_height")))) {
            out["block_height"] = h.into();
        }
        Ok(out)
    }

    fn lookup_invoice(&self, svc: &str, p: &Value) -> Result<Value, NwcErr> {
        let mut hash = s(p.get("payment_hash")).trim().to_ascii_lowercase();
        if hash.is_empty() {
            let inv = s(p.get("invoice")).trim();
            if inv.is_empty() {
                return Err(e("OTHER", "params.payment_hash or params.invoice is required"));
            }
            hash = bolt11::decode(inv).map_err(|err| e("OTHER", format!("not a valid BOLT 11 invoice: {err}")))?.payment_hash_hex();
        }
        match self.reconcile(svc, &hash) {
            Some(rec) => Ok(rec.nip47()),
            None => Err(e("NOT_FOUND", "no payment of this connection has that payment hash (this wallet makes no invoices)")),
        }
    }

    fn list_transactions(&self, svc: &str, p: &Value) -> Result<Value, NwcErr> {
        if s(p.get("type")) == "incoming" {
            return Ok(json!({"transactions": []}));
        }
        self.reconcile_all(svc);
        let from = int(p.get("from")).unwrap_or(0).max(0) as u64;
        let until = int(p.get("until")).map(|u| u.max(0) as u64).unwrap_or(u64::MAX);
        let limit = int(p.get("limit")).filter(|l| *l > 0).unwrap_or(50).min(500) as usize;
        let offset = int(p.get("offset")).unwrap_or(0).max(0) as usize;
        let unpaid = p.get("unpaid").and_then(Value::as_bool).unwrap_or(false);
        let mut recs = self.read(svc, |c| c.payments.clone()).ok_or_else(|| e("UNAUTHORIZED", "this connection is gone"))?;
        recs.retain(|r| r.created_at >= from && r.created_at <= until && (unpaid || r.state == "settled"));
        recs.sort_by_key(|r| std::cmp::Reverse(r.created_at));
        let mut txs: Vec<Value> = recs.iter().skip(offset).take(limit).map(PaymentRec::nip47).collect();
        // a response stays within NIP-44's 2-byte length prefix: many apps do not read the extended one
        let mut size: usize = txs.iter().map(|t| t.to_string().len() + 1).sum();
        while size > MAX_LIST_BYTES {
            size -= txs.pop().map(|t| t.to_string().len() + 1).unwrap_or(size);
        }
        Ok(json!({"transactions": txs}))
    }

    // --- the admin socket's methods ------------------------------------------------------------------

    /// A new connection: `{name, budget_sats_per_day, expires_at (0: never) | expires_in_s, methods, relays}`.
    /// The answer carries the connection URI, with the app's secret: it exists only in this answer.
    pub fn create(&self, p: &Value) -> Result<Value, String> {
        let now = self.now();
        let name: String = s(p.get("name")).trim().chars().filter(|c| !c.is_control()).take(64).collect();
        let name = if name.is_empty() { "app".to_string() } else { name };
        let budget = int(p.get("budget_sats_per_day")).unwrap_or(0);
        if !(1..=MAX_BUDGET_SATS).contains(&budget) {
            return Err(format!("budget_sats_per_day: a whole number of sats from 1 to {MAX_BUDGET_SATS}"));
        }
        let expires_at = match (int(p.get("expires_at")), int(p.get("expires_in_s"))) {
            (Some(t), _) if t > 0 => t as u64,
            (_, Some(d)) if d > 0 => now + d as u64,
            _ => 0,
        };
        if expires_at != 0 && expires_at <= now {
            return Err("expires_at is in the past".into());
        }
        let methods: Vec<String> = match p.get("methods").and_then(Value::as_array) {
            Some(a) => a.iter().filter_map(Value::as_str).map(str::to_string).collect(),
            None => METHODS.iter().map(|m| m.to_string()).collect(),
        };
        if methods.is_empty() {
            return Err("allow at least one method".into());
        }
        if let Some(m) = methods.iter().find(|m| !METHODS.contains(&m.as_str())) {
            return Err(format!("{m} is not a method this service offers ({})", METHODS.join(", ")));
        }
        let mut methods: Vec<String> = METHODS.iter().filter(|m| methods.iter().any(|x| x == *m)).map(|m| m.to_string()).collect();
        methods.dedup();
        let relays: Vec<String> = match p.get("relays").and_then(Value::as_array) {
            Some(a) => a.iter().filter_map(Value::as_str).map(|r| r.trim().to_string()).filter(|r| !r.is_empty()).collect(),
            None => self.cfg.default_relays.clone(),
        };
        let mut seen = vec![];
        for r in &relays {
            parse_url(r).map_err(|err| format!("relay {r}: {err}"))?;
            if !seen.contains(r) {
                seen.push(r.clone());
            }
        }
        let relays = seen;
        if relays.is_empty() {
            return Err("give at least one relay (wss://...)".into());
        }
        if relays.len() > MAX_RELAYS {
            return Err(format!("at most {MAX_RELAYS} relays"));
        }
        let (service, client) = (Keys::generate(), Keys::generate());
        let id = hex::encode(xbt_svc::random_bytes(8));
        let c = Connection { id: id.clone(), name, created_at: now, expires_at, budget_sats_per_day: budget, methods, relays: relays.clone(),
                             service_secret: service.secret_hex(), service_pubkey: service.public_hex(), client_pubkey: client.public_hex(),
                             last_used: 0, spent_total_sats: 0, payments: vec![] };
        let public = c.public(now);
        {
            let mut st = self.lock();
            st.connections.push(c);
            if let Err(err) = st.save() {
                st.connections.retain(|x| x.id != id);
                return Err(err);
            }
        }
        self.resync();
        let q: Vec<String> = relays.iter().map(|r| format!("relay={}", urlenc(r))).collect();
        let uri = format!("nostr+walletconnect://{}?{}&secret={}", service.public_hex(), q.join("&"), client.secret_hex());
        Ok(json!({"connection": public, "uri": uri}))
    }

    pub fn list(&self) -> Value {
        let now = self.now();
        let st = self.lock();
        json!({"connections": st.connections.iter().map(|c| c.public(now)).collect::<Vec<_>>()})
    }

    /// Remove a connection now: its requests are dropped from this moment, and its relays are
    /// subscribed to again without its key.
    pub fn revoke(&self, id: &str) -> Result<Value, String> {
        let svc = {
            let mut st = self.lock();
            let i = st.by_id(id).ok_or("no connection with that id")?;
            let c = st.connections.remove(i);
            st.save()?;
            c.service_pubkey
        };
        self.rate.lock().unwrap_or_else(|p| p.into_inner()).remove(&svc);
        self.resync();
        Ok(json!({"revoked": true, "id": id}))
    }

    pub fn status(&self) -> Value {
        let relays = self.pool.get().map(|p| p.status()).unwrap_or_default();
        json!({"service": "xbt-nwc", "connections": self.lock().connections.len(), "default_relays": self.cfg.default_relays, "relays": relays,
               "methods": METHODS, "encryption": ["nip44_v2"], "approval_wait_s": self.cfg.approval_wait.as_secs()})
    }

    /// The relays a response from this service key goes to.
    fn relays_of(&self, svc: &str) -> Vec<String> {
        self.read(svc, |c| c.relays.clone()).unwrap_or_default()
    }
}

impl Hub for Service {
    fn on_connect(&self, relay: &str) -> Vec<String> {
        let now = self.now();
        let st = self.lock();
        let mine: Vec<&Connection> = st.connections.iter().filter(|c| c.relays.iter().any(|r| r == relay)).collect();
        let mut out = vec![];
        let keys: Vec<&str> = mine.iter().map(|c| c.service_pubkey.as_str()).collect();
        if keys.is_empty() {
            out.push(json!(["CLOSE", SUBSCRIPTION]).to_string());
            return out;
        }
        out.push(json!(["REQ", SUBSCRIPTION, {"kinds": [KIND_REQUEST], "#p": keys, "since": now.saturating_sub(SINCE_S)}]).to_string());
        for c in mine.iter().filter(|c| !c.expired(now)) {
            if let Some(ev) = Self::info_event(c, now) {
                out.push(json!(["EVENT", ev.to_value()]).to_string());
            }
        }
        out
    }

    fn on_event(&self, relay: &str, ev: Event) {
        if ev.kind != KIND_REQUEST {
            return;
        }
        // cheap drops first: not addressed to one of ours, or seen already
        let Some(svc) = ev.tag("p").map(str::to_ascii_lowercase) else { return };
        if self.read(&svc, |_| ()).is_none() || self.seen.lock().unwrap_or_else(|p| p.into_inner()).contains_key(&ev.id) {
            return;
        }
        if self.workers.fetch_add(1, Ordering::SeqCst) >= MAX_WORKERS {
            self.workers.fetch_sub(1, Ordering::SeqCst);
            return;
        }
        let pool = self.pool.get().cloned();
        let relay = relay.to_string();
        // the pool holds the service weakly; a worker holds it for as long as it runs
        match self.me.upgrade() {
            Some(arc) => {
                std::thread::spawn(move || {
                    let reply = arc.handle(&ev);
                    if let (Some(r), Some(pool)) = (reply, pool) {
                        let mut to = arc.relays_of(&svc);
                        if to.is_empty() {
                            to.push(relay);
                        }
                        pool.send(&to, &json!(["EVENT", r.to_value()]).to_string());
                    }
                    arc.workers.fetch_sub(1, Ordering::SeqCst);
                });
            }
            None => {
                self.workers.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }
}
