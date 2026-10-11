//! AGP-093 third closure audit, area OVERFLOW (the hub, and a provider's `/lock`): tests written by
//! the auditor, in process on the rig of `routing_checks.rs` ([`MemChain`] + [`MemNet`]).
//!
//! `overflow-checks = true` is on in every release build since d4c8328: a missed overflow is a
//! panic. These tests are built in the dev profile, which has overflow checks on as well, so what
//! panics here panics in the shipped `release` build. A request is sent the way the HTTP server
//! runs a handler: inside `catch_unwind` (`xbt_svc::http::connection`), so a panic is seen as one.
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::adaptor::{self, Sc};
use xbt402::channel::{channel_auth_key, FeePayer};
use xbt402::client::Transport;
use xbt402::error::Result;
use xbt402::funding::{ChainBackend, FundingPolicy, UtxoInfo};
use xbt402::hub::{HubConfig, RouteHub};
use xbt402::json::{dumps, py_int, truthy};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::route::*;
use xbt402::route_client::{RoutePayer, RoutePayerConfig, Shard};
use xbt402::route_seller::RouteOffer;
use xbt402::signer::LocalSigner;
use xbt402::wire::{b64json, request_auth, request_digest_v2};
use xbt402_interop::memnet::{ChainWallet, MemChain, MemNet, NetTransport};
use xbt_primitives::ecdsa;
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

const NET: &str = "bip122:11111111111111111111111111111111";
const HUB: &str = "http://hub.test";
const P0: &str = "http://p0.test";

fn pt33(h: &str) -> ecdsa::PubkeyBytes {
    hex::decode(h).unwrap().try_into().unwrap()
}

fn sk(n: u64) -> SecretKey {
    Sc::from_u64(n).secret().unwrap()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let base = PathBuf::from("/tmp/claude-1000/agp093-overflow");
        let p = base.join(format!("t-{}", hex::encode(&sha256(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes())[..8])));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The chain, with a switch: the next `boom` calls of `block_count` panic (a stand-in for any
/// panic, such as a missed overflow, in the code that asked).
struct Boom {
    chain: Arc<MemChain>,
    boom: AtomicU32,
    asked: AtomicU32,
}

impl ChainBackend for Boom {
    fn block_count(&self) -> Result<u32> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        if self.boom.load(Ordering::SeqCst) > 0 {
            self.boom.fetch_sub(1, Ordering::SeqCst);
            panic!("agp093: injected panic (a missed overflow)");
        }
        self.chain.block_count()
    }
    fn get_tx_out(&self, txid: &str, vout: u32, m: bool) -> Result<Option<UtxoInfo>> {
        self.chain.get_tx_out(txid, vout, m)
    }
    fn send_raw_transaction(&self, hex: &str) -> Result<String> {
        self.chain.send_raw_transaction(hex)
    }
    fn has_transaction(&self, txid: &str) -> Result<bool> {
        self.chain.has_transaction(txid)
    }
}

impl SpendScan for Boom {
    fn find_spend(&self, txid: &str, vout: u32, from: u32) -> Result<Option<Tx>> {
        self.chain.find_spend(txid, vout, from)
    }
    fn find_spend_at(&self, txid: &str, vout: u32, from: u32) -> Result<Option<(Tx, Option<u32>)>> {
        self.chain.find_spend_at(txid, vout, from)
    }
    fn scan_spk(&self, spk: &[u8]) -> Result<Vec<(String, u32, u64)>> {
        self.chain.scan_spk(spk)
    }
    fn fee_rate(&self, target: u32) -> Result<Option<f64>> {
        self.chain.fee_rate(target)
    }
    fn in_mempool(&self, txid: &str) -> Result<bool> {
        self.chain.in_mempool(txid)
    }
}

/// The net, with a switch: the next `boom` requests to a provider's `/lock` panic in the hub's
/// thread, after the hub wrote the lock on ch1 and ch2 and while it holds the provider's busy flag.
struct BoomNet {
    net: Arc<MemNet>,
    boom: Arc<AtomicU32>,
}

impl Transport for BoomNet {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        // (AGP-094: the lock itself, not the check the hub now sends before it pre-signs)
        if url.ends_with(ROUTE_LOCK_PATH) && !xbt402_interop::memnet::is_lock_check(ROUTE_LOCK_PATH, body) && self.boom.load(Ordering::SeqCst) > 0 {
            self.boom.fetch_sub(1, Ordering::SeqCst);
            panic!("agp093: injected panic while a lock is forwarded");
        }
        NetTransport(self.net.clone()).request(method, url, body, headers)
    }
}

fn provider(chain: &Arc<MemChain>, net: &Arc<MemNet>, dir: &TempDir, origin: &str) -> Arc<Provider> {
    let mut cfg = ProviderConfig::new(NET);
    cfg.close_margin = 36;
    cfg.policy = FundingPolicy { min_capacity: 20_000, min_expiry_blocks: 500, max_expiry_blocks: 8_640, close_margin: 36, ..FundingPolicy::default() };
    cfg.height_ttl = Duration::ZERO;
    cfg.settle_lock_multiple = 0;
    cfg.route_close_fee_payer = FeePayer::Payee;
    let ledger = Ledger::open(&dir.0.join("prov.jsonl")).unwrap();
    let p = Provider::new(chain.clone(), sk(0x5151), cfg, ledger, Box::new(|_, _| 1000),
                          Box::new(|_, _, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], b"{\"ok\":1}".to_vec()))).unwrap();
    p.offer_route(RouteOffer { window: 0.3, lock_wait: 0.6, invoice_ttl: 8.0, ..RouteOffer::new("/v1/chunk", 370 * 10u128.pow(18)) });
    let p = Arc::new(p);
    net.add(origin, p.clone());
    p
}

fn hub_cfg() -> HubConfig {
    HubConfig::from_json(&json!({"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500, "delta": 36,
                                 "reveal_timeout": 1.0, "ch2_capacity": 100000, "ch2_expiry_blocks": 1000, "settle_lock_multiple": 0, "refill_ahead_locks": 0, "close_margin": 36,
                                 "policy": {"min_capacity": 20000, "min_expiry_blocks": 500, "max_expiry_blocks": 8640}})).unwrap()
}

struct W {
    chain: Arc<MemChain>,
    net: Arc<MemNet>,
    boom: Arc<Boom>,
    net_boom: Arc<AtomicU32>,
    hub: Arc<RouteHub>,
    prov: Arc<Provider>,
    pay: Arc<RoutePayer>,
    sh: Arc<Shard>,
    _dir: TempDir,
}

fn world() -> W {
    let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
    let boom = Arc::new(Boom { chain: chain.clone(), boom: AtomicU32::new(0), asked: AtomicU32::new(0) });
    let net_boom = Arc::new(AtomicU32::new(0));
    let hub = Arc::new(RouteHub::new(boom.clone(), boom.clone(), Box::new(ChainWallet(chain.clone())), Box::new(BoomNet { net: net.clone(), boom: net_boom.clone() }),
                                     sk(0x4B4B), NET, Some(&dir.0.join("hub")), hub_cfg()).unwrap());
    net.add(HUB, hub.clone());
    let prov = provider(&chain, &net, &dir, P0);
    hub.connect(P0, None, None).unwrap();
    chain.confirm_all();
    hub.watch_tick();
    let mut cfg = RoutePayerConfig::new(NET);
    cfg.expiry_blocks = 8_000;
    let c = chain.clone();
    let pay = Arc::new(RoutePayer::new(HUB, cfg, Arc::new(LocalSigner::new()), Arc::new(ChainWallet(chain.clone())), Box::new(NetTransport(net.clone())),
                                       Box::new(move || Ok(c.height()))));
    pay.open().unwrap();
    let sh = pay.shard(&format!("{P0}/v1/chunk"), "POST").unwrap();
    let w = W { chain, net, boom, net_boom, hub, prov, pay, sh, _dir: dir };
    stream(&w, 10);
    w
}

fn stream(w: &W, n: usize) {
    calls(&w.pay, &w.sh, n);
}

fn calls(pay: &RoutePayer, sh: &Arc<Shard>, n: usize) {
    for _ in 0..n {
        let r = pay.call(sh, "POST", br#"{"tokens":1}"#).unwrap();
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    }
}

/// Another honest client: its own ch1 to the hub and its own session with the provider.
fn fresh_client(w: &W) -> (Arc<RoutePayer>, Arc<Shard>) {
    let mut cfg = RoutePayerConfig::new(NET);
    cfg.expiry_blocks = 8_000;
    let c = w.chain.clone();
    let pay = Arc::new(RoutePayer::new(HUB, cfg, Arc::new(LocalSigner::new()), Arc::new(ChainWallet(w.chain.clone())), Box::new(NetTransport(w.net.clone())),
                                       Box::new(move || Ok(c.height()))));
    pay.open().unwrap();
    w.chain.confirm_all();
    let sh = pay.shard(&format!("{P0}/v1/chunk"), "POST").unwrap();
    (pay, sh)
}

impl W {
    fn st1(&self) -> xbt402::ledger::ChannelState {
        self.hub.ch1_state(&self.pay.chan().unwrap()).unwrap()
    }

    fn oc(&self) -> xbt402::hub::OutChannel {
        self.hub.out_channels()[P0].clone()
    }
}

type Tamper<'a> = &'a dyn Fn(&mut Value, &mut Value);

/// The client's POST /x402/route built as `RoutePayer::lock` builds it, then edited; `seq` None is
/// the client's next one. `fee_cum`: pay this fee, with the state re-signed for it.
fn route_built(w: &W, tamper: Tamper<'_>, seq: Option<Value>, fee: Option<u64>) -> (String, String) {
    route_built_for(&w.pay, &w.sh, tamper, seq, fee)
}

fn route_built_for(pay: &RoutePayer, sh: &Arc<Shard>, tamper: Tamper<'_>, seq: Option<Value>, fee: Option<u64>) -> (String, String) {
    let inv = sh.snapshot().invoice;
    let d = sh.due_sat().max(1) as u64;
    let q = pay.quote().unwrap();
    let (routed, units, paid, _) = pay.counters();
    let f = fee.unwrap_or_else(|| fee_due(&q, d, units, paid).0);
    let cum = next_cum(routed, d + f, pay.ch1_params().unwrap().min_amount());
    let chan = pay.chan().unwrap();
    let point = inv["point"].as_str().unwrap().to_string();
    let lock_id = inv["lockId"].as_str().unwrap().to_string();
    let sa = pay.signer().sign_state_adaptor(&chan, cum, &pt33(&point), &json!({})).unwrap();
    let mut route = json!({"provider": sh.origin, "payTo": sh.pay_to, "network": NET, "amount": d, "point": point, "fee": f,
                           "feeQuote": q.to_json(), "invoice": inv, "session": sh.session, "lockId": lock_id,
                           "lockAuth": lock_auth(&sh.session_key(), &sh.session, &lock_id, d as i128, &point, &pay.hub_pay_to()),
                           "tweak": hex::encode(sa.tweak)});
    let mut pl = json!({"chan": chan, "seq": 0, "cum": cum.to_string(), "adaptor": sa.pre.to_json(), "point": hex::encode(sa.point)});
    tamper(&mut pl, &mut route);
    let (s, accepted) = pay.next_seq().unwrap();
    pl["seq"] = seq.unwrap_or_else(|| s.into());
    let body = dumps(&json!({"route": route}));
    pl["auth"] = pay.signer().request_auth(&chan, Some(&pl["seq"]), Some(&pl["cum"]), None, &request_digest_v2("POST", &format!("{HUB}{HUB_ROUTE_PATH}"), body.as_bytes())).unwrap().into();
    let hdr = b64json(&json!({"x402Version": 2, "accepted": accepted, "payload": pl}));
    pay.signer().void_lock(&chan).unwrap();
    (hdr, body)
}

/// The request as the HTTP server runs it: Err when the handler panicked.
fn hub_serve(w: &W, hdr: &str, body: &str) -> std::result::Result<(u16, Value), String> {
    let r = catch_unwind(AssertUnwindSafe(|| {
        w.hub.serve("POST", HUB_ROUTE_PATH, &[("PAYMENT-SIGNATURE".into(), hdr.to_string())], body.as_bytes(), &format!("{HUB}{HUB_ROUTE_PATH}"), None)
    }));
    match r {
        Ok(r) => Ok((r.status, xbt402::json::parse_slice(&r.body).unwrap_or(Value::Null))),
        Err(p) => Err(p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default()),
    }
}

/// A ch2 lock sent to the provider as the hub sends it, for `amount` (authorised by the client's
/// session key for exactly that amount, where it is an integer) at `cum`.
fn lock_serve(w: &W, amount: &Value, cum: &Value, with_adaptor: bool) -> std::result::Result<(u16, Value), String> {
    let oc = w.oc();
    let p2 = &oc.params;
    // the session's open invoice as the provider has it now (a completed lock opens a new window)
    let inv = w.prov.routes().state(&w.sh.session).unwrap()["invoice"].clone();
    let point = inv["point"].as_str().unwrap().to_string();
    let lock_id = inv["lockId"].as_str().unwrap().to_string();
    let secret = Sc::from_hex64(&oc.secret).unwrap().secret().unwrap();
    let auth = py_int(Some(amount)).map(|a| lock_auth(&w.sh.session_key(), &w.sh.session, &lock_id, a, &point, w.hub.pay_to())).unwrap_or_default();
    let route = json!({"session": w.sh.session, "lockId": lock_id, "amount": amount, "hub": w.hub.pay_to(), "lockAuth": auth});
    let seq = w.hub.with_out(|b| {
        let c = b.chans.get_mut(P0).unwrap();
        c.seq += 1;
        c.seq
    });
    let mut pl = json!({"chan": p2.channel_id(), "seq": seq, "cum": cum, "point": point});
    if with_adaptor {
        // a pre-signature that verifies for the state the provider will ask for, where there is one
        let routed = w.prov.channel_state(&p2.channel_id()).and_then(|s| py_int(s.extra.get("routed_sat"))).unwrap_or(0) as u64;
        let need = py_int(Some(amount)).and_then(|a| u64::try_from(a).ok()).map(|a| next_cum(routed, a, p2.min_amount()));
        let pre = need.and_then(|n| p2.state_tx(n).ok()).and_then(|tx| p2.sighash(&tx).ok())
            .and_then(|z| adaptor::presign(&secret, &z, &adaptor::dec_hex(&point).unwrap()).ok());
        pl["adaptor"] = pre.map(|p| p.to_json()).unwrap_or_else(|| json!({"R": "02", "R1": "02", "s1": "00", "c": "00", "z": "00"}));
    }
    let body = dumps(&json!({"route": route}));
    let key = channel_auth_key(&secret, &p2.payee_pub).unwrap();
    pl["auth"] = request_auth(&key, &p2.channel_id(), pl.get("seq"), pl.get("cum"), None, &request_digest_v2("POST", &format!("{P0}{ROUTE_LOCK_PATH}"), body.as_bytes())).into();
    let hdr = b64json(&json!({"x402Version": 2, "accepted": {}, "payload": pl}));
    let r = catch_unwind(AssertUnwindSafe(|| {
        w.prov.serve("POST", ROUTE_LOCK_PATH, &[("PAYMENT-SIGNATURE".into(), hdr)], body.as_bytes(), &format!("{P0}{ROUTE_LOCK_PATH}"), None)
    }));
    match r {
        Ok(r) => Ok((r.status, xbt402::json::parse_slice(&r.body).unwrap_or(Value::Null))),
        Err(p) => Err(p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default()),
    }
}

fn hostile() -> Vec<Value> {
    let mut v = vec![json!(0), json!(1), json!(545), json!(546), json!(20_000), json!(20_001), json!(u32::MAX), json!(u32::MAX as u64 + 1), json!(i64::MAX),
                     json!(i64::MAX as u64 + 1), json!(u64::MAX / 4), json!(u64::MAX / 4 + 1), json!(u64::MAX - 1), json!(u64::MAX), json!(-1), json!(i64::MIN),
                     json!(1.5), json!(1e300), json!(true), json!(null), json!([]), json!({}), json!(""), json!("+7"), json!(" 12 ")];
    for s in ["18446744073709551615", "18446744073709551616", "170141183460469231731687303715884105727", "999999999999999999999999999999",
              "-999999999999999999999999999999", "9223372036854775808", "-9223372036854775809", "4611686018427387903"] {
        v.push(json!(s));
    }
    v
}

type Answer = std::result::Result<(u16, Value), String>;

/// Counts what a group of hostile requests was answered, and keeps the panics.
#[derive(Default)]
struct Tally {
    hist: std::collections::BTreeMap<(String, u16, String), usize>,
    panics: Vec<String>,
    sent: usize,
}

impl Tally {
    fn note(&mut self, what: &str, r: Answer) {
        self.sent += 1;
        match r {
            Ok((st, doc)) => *self.hist.entry((what.split('=').next().unwrap_or("").to_string(), st, doc["error"].as_str().unwrap_or("").to_string())).or_default() += 1,
            Err(p) => self.panics.push(format!("{what}: {p}")),
        }
    }

    fn done(&self) {
        for ((k, st, code), n) in &self.hist {
            eprintln!("agp093_overflow: {k:26} {st} {code:20} x{n}");
        }
        assert!(self.panics.is_empty(), "{} of {} hostile requests made a handler panic; the first: {}", self.panics.len(), self.sent, self.panics[0]);
    }
}

/// A watcher tick, as the watcher thread runs it: Err when it panicked.
fn tick(w: &W) -> std::result::Result<(), String> {
    catch_unwind(AssertUnwindSafe(|| {
        w.hub.watch_tick();
        let _ = w.prov.close_due();
    })).map_err(|p| p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default())
}

/// Hostile numbers in an authenticated `/x402/route`: every one is a refusal or an answer, none a
/// panic, whatever the client puts in the amount, the fee, the state, the seq, the fee quote or
/// the invoice. Then the hub's and the provider's watcher ticks run, the same hub routes another
/// client's lock, and the largest fee a client can pay (its whole channel) is booked to the sat.
#[test]
fn hostile_numbers_on_the_hub_route_are_refusals_and_never_a_panic() {
    let w = world();
    let mut t = Tally::default();
    for n in hostile() {
        let cases: Vec<(&str, Box<dyn Fn(&mut Value, &mut Value)>)> = vec![
            ("route amount", Box::new(|_, rt| rt["amount"] = n.clone())),
            ("route fee", Box::new(|_, rt| rt["fee"] = n.clone())),
            ("route amount+fee", Box::new(|_, rt| { rt["amount"] = n.clone(); rt["fee"] = n.clone(); })),
            ("route cum", Box::new(|pl, _| pl["cum"] = n.clone())),
            ("route cum, no adaptor", Box::new(|pl, _| { pl["cum"] = n.clone(); pl.as_object_mut().unwrap().remove("adaptor"); pl.as_object_mut().unwrap().remove("point"); })),
            ("route fee+cum", Box::new(|pl, rt| { rt["fee"] = n.clone(); pl["cum"] = n.clone(); })),
            ("route quote.feePpm", Box::new(|_, rt| rt["feeQuote"]["feePpm"] = n.clone())),
            ("route quote.feeBaseMsat", Box::new(|_, rt| rt["feeQuote"]["feeBaseMsat"] = n.clone())),
            ("route quote.validUntil", Box::new(|_, rt| rt["feeQuote"]["validUntil"] = n.clone())),
            ("route invoice.validUntil", Box::new(|_, rt| rt["invoice"]["validUntil"] = n.clone())),
            ("route tweak", Box::new(|_, rt| rt["tweak"] = n.clone())),
        ];
        for (what, tamper) in &cases {
            let (hdr, body) = route_built(&w, &**tamper, None, None);
            t.note(&format!("{what}={n}"), hub_serve(&w, &hdr, &body));
        }
    }
    t.done();
    // both watchers run after it (none panics), and the hub and the provider still answer. (One of
    // these requests left the hub's ch2 blocked: that is its own finding, the next test.)
    for round in 0..3 {
        w.chain.mine(1);
        tick(&w).unwrap_or_else(|p| panic!("a watcher tick panicked after the hostile requests (round {round}): {p}"));
    }
    let (pay, sh) = fresh_client(&w);
    calls(&pay, &sh, 3);
    assert!(pay.lock(&sh).is_ok());
    eprintln!("agp093_overflow: {} hostile /x402/route requests, 0 panics", t.sent);
}

/// HOLE (failing today; found by the matrix above, outside the overflow question). One request
/// from any client stops the hub routing to a provider. The client sends a lock the provider will
/// refuse: its `lockAuth` is the client's own MAC under a key the hub does not hold, so the hub
/// cannot check it. The hub pre-signs ch2, the provider answers `bad_auth`, and the hub writes the
/// lock off and holds it (its pre-signature left: AGP-064). It then asks the provider to close
/// that ch2 (AGP-073), but nothing was ever signed on this ch2, so the provider answers `no_state`
/// on every tick, no next ch2 is funded ahead (`max_lock` is 0), and `ch2_refusal` refuses every
/// lock to that provider (`route_blocked`) until the hub's own refund at ch2's expiry
/// (`ch2_expiry_blocks`, 1,100 by default; 1,000 in this rig).
#[test]
fn one_client_request_does_not_stop_the_hub_routing_to_a_provider() {
    let w = world();
    let (bad, bad_sh) = fresh_client(&w);
    calls(&bad, &bad_sh, 3);
    let funded_before = w.hub.events.lock().unwrap().iter().filter(|e| e["event"] == "ch2_open").count();
    let (hdr, body) = route_built_for(&bad, &bad_sh, &|_, rt| rt["lockAuth"] = "00".repeat(32).into(), None, None);
    let r = hub_serve(&w, &hdr, &body).unwrap();
    assert_eq!((r.0, r.1["providerError"].as_str()), (502, Some("bad_auth")), "control: the provider refused the lock: {}", r.1);
    // 20 blocks of watcher ticks later an honest client's lock to that provider is still refused
    let mut last = Value::Null;
    for _ in 0..20 {
        w.chain.mine(1);
        w.chain.confirm_all();
        tick(&w).unwrap();
        stream(&w, 1);
        last = w.pay.lock(&w.sh).unwrap().unwrap_or(Value::Null);
        if last["status"] == "paid" {
            break;
        }
    }
    let ev = w.hub.events.lock().unwrap();
    let failed = ev.iter().filter(|e| e["event"] == "ch2_written_off_close_failed").count();
    let opened = ev.iter().filter(|e| e["event"] == "ch2_open").count() - funded_before;
    let oc = w.oc();
    assert_eq!(last["status"], "paid", "20 blocks after one client's refused lock the hub still routes nothing to this provider: {last};                ch2 {} with {} written-off lock, signed {}, {failed} closes asked and refused ({}), {opened} new ch2 opened; its refund is {} blocks away",
               oc.state, oc.stale.len(), oc.signed, ev.iter().rev().find(|e| e["event"] == "ch2_written_off_close_failed").map(|e| e["error"].to_string()).unwrap_or_default(),
               oc.params.expiry.saturating_sub(w.chain.height()));
}

/// The same request against a ch2 that has a signed state (measured, not a failing test): the hub
/// has the provider close it and funds a new one. What one refused lock costs is printed.
#[test]
fn measured_one_refused_lock_on_a_used_ch2_costs_a_close_and_a_new_funding() {
    let w = world();
    assert_eq!(w.pay.lock(&w.sh).unwrap().unwrap()["status"], "paid");
    let chan_before = w.oc().params.channel_id();
    let (bad, bad_sh) = fresh_client(&w);
    calls(&bad, &bad_sh, 3);
    let (hdr, body) = route_built_for(&bad, &bad_sh, &|_, rt| rt["lockAuth"] = "00".repeat(32).into(), None, None);
    let r = hub_serve(&w, &hdr, &body).unwrap();
    assert_eq!(r.0, 502, "{}", r.1);
    let mut blocks = 0;
    let mut paid = false;
    while blocks < 20 && !paid {
        w.chain.mine(1);
        w.chain.confirm_all();
        tick(&w).unwrap();
        blocks += 1;
        stream(&w, 1);
        paid = w.pay.lock(&w.sh).unwrap().is_some_and(|v| v["status"] == "paid");
    }
    let names: Vec<String> = w.hub.events.lock().unwrap().iter().map(|e| e["event"].as_str().unwrap_or("").to_string())
        .filter(|e| e.starts_with("ch2_") && e != "ch2_watch_error").collect();
    eprintln!("agp093_overflow: one refused lock on a used ch2: routing back after {blocks} block(s) (paid {paid}), ch2 {} -> {}, hub events {names:?}",
              &chan_before[..8], &w.oc().params.channel_id()[..8]);
    assert!(paid, "routing to the provider did not come back in 20 blocks");
    // AGP-094: this line asserted the cost the audit measured (`assert_ne`: the refused lock cost
    // the hub this ch2, a close and a new funding). The provider now refuses such a lock at the
    // hub's check, before anything is pre-signed: it costs the hub nothing, and the ch2 stays
    assert_eq!(w.oc().params.channel_id(), chan_before, "the refused lock cost the hub this ch2");
    assert_eq!(blocks, 1, "routing never stopped: the first lock after the refusal is paid");
}

/// The sums of the hub's ch1 counters at their bound: a client pays its whole channel as one
/// lock's fee (the largest `f` the hub admits), and it is booked to the sat. Then hostile seqs.
#[test]
fn the_largest_fee_a_client_can_pay_is_booked_to_the_sat() {
    let w = world();
    let p1 = w.pay.ch1_params().unwrap();
    let (routed1, _, _, _) = w.pay.counters();
    let d = w.sh.due_sat().max(1) as u64;
    let f = p1.max_amount() - routed1 - d;
    let (hdr, body) = route_built(&w, &|_, _| {}, None, Some(f));
    let r = hub_serve(&w, &hdr, &body).expect("the hub panicked on a lock that pays the whole channel as its fee");
    assert_eq!(r.0, 200, "{}", r.1);
    let st1 = w.st1();
    assert_eq!(st1.best_cum, p1.max_amount());
    assert_eq!(py_int(st1.extra.get("routed_sat")), Some(p1.max_amount() as i128));
    assert_eq!(py_int(st1.extra.get("fee_paid")), Some(f as i128));
    // more on a full channel: fees no channel holds, and fees no u64 holds, on the next invoice
    calls(&w.pay, &w.sh, 2);
    for f2 in [1u64, u64::MAX / 4, u64::MAX / 2, u64::MAX - d - 1] {
        let (hdr, body) = route_built(&w, &|pl, rt| { rt["fee"] = f2.into(); pl["cum"] = u64::MAX.to_string().into(); }, None, Some(0));
        let r = hub_serve(&w, &hdr, &body).unwrap_or_else(|p| panic!("the hub panicked on fee {f2} on a full channel: {p}"));
        assert!(r.0 == 400 || r.1["lockId"].is_string(), "{}", r.1);
        assert_eq!(w.st1().best_cum, p1.max_amount());
    }
    // the seq: whatever it is, a refusal or an answer (the largest spends every later seq of this ch1)
    for n in hostile() {
        let (hdr, body) = route_built(&w, &|_, _| {}, Some(n.clone()), None);
        if let Err(p) = hub_serve(&w, &hdr, &body) {
            panic!("the hub panicked on seq={n}: {p}");
        }
    }
    assert_eq!(w.st1().seq, u64::MAX);
    w.chain.mine(1);
    tick(&w).unwrap();
    // ch1 with its seq at u64::MAX and its capacity spent still closes at its margin
    w.chain.set_height(p1.expiry - 36);
    tick(&w).unwrap();
    assert!(!w.st1().closed_txid.is_empty(), "the hub did not close the full ch1 at its margin: {}", w.st1().close_error);
}

/// Hostile numbers in an authenticated `/lock` (what a hub, or anyone who opens a hub channel,
/// sends a provider; the amount is authorised by the client's session key, which the same party
/// can hold): refusals or answers, never a panic. Then the provider's watcher tick runs and it
/// serves another client's calls.
#[test]
fn hostile_numbers_on_the_provider_lock_are_refusals_and_never_a_panic() {
    let w = world();
    let mut t = Tally::default();
    let chan2 = w.oc().params.channel_id();
    let routed = |w: &W| w.prov.channel_state(&chan2).and_then(|s| py_int(s.extra.get("routed_sat"))).unwrap_or(0) as u64;
    for n in hostile() {
        let amt_u = py_int(Some(&n)).and_then(|a| u64::try_from(a).ok());
        for cum in [n.clone(), json!(u64::MAX.to_string())] {
            for adaptor in [false, true] {
                t.note(&format!("lock amount={n} cum={cum}"), lock_serve(&w, &n, &cum, adaptor));
            }
        }
        // last: the state the provider expects for that amount, as it stands now (a small amount
        // is then a lock the provider takes, twice)
        for adaptor in [false, true] {
            if let Some(a) = amt_u {
                let cum = json!(next_cum(routed(&w), a, w.oc().params.min_amount()).to_string());
                t.note(&format!("lock amount={n} at its cum"), lock_serve(&w, &n, &cum, adaptor));
            }
        }
        // an amount that makes `routed + amount` exactly u64::MAX
        let edge = json!((u64::MAX - routed(&w)).to_string());
        t.note(&format!("lock amount (edge)={edge}"), lock_serve(&w, &edge, &json!(u64::MAX.to_string()), true));
    }
    t.done();
    assert!(t.hist.iter().any(|((_, st, _), _)| *st == 200), "control: no lock was taken, so the matrix did not get past the checks before the sums");
    let st2 = w.prov.channel_state(&chan2).unwrap();
    assert!(st2.best_cum <= st2.params.max_amount() && routed(&w) <= st2.best_cum.max(st2.params.min_amount()), "the provider's ch2 counters left their bounds");
    w.chain.mine(1);
    w.prov.close_due().unwrap();
    let (pay, sh) = fresh_client(&w);
    calls(&pay, &sh, 3);
    eprintln!("agp093_overflow: {} hostile /lock requests, 0 panics", t.sent);
}

/// The mechanics, by experiment: the hub's handler panics while it forwards a lock (ch1's lock and
/// ch2's are written, the provider's busy flag is held). The flag is given back by the unwind, the
/// two write-ahead records stand, and the watcher's next tick finishes the lock: nothing is left
/// half-applied, and the next lock is paid.
#[test]
fn a_panic_while_the_hub_forwards_a_lock_is_finished_by_the_watcher() {
    let w = world();
    let (hdr, body) = route_built(&w, &|_, _| {}, None, None);
    let cum: u64 = xbt402::wire::unb64json(&hdr).unwrap()["payload"]["cum"].as_str().unwrap().parse().unwrap();
    w.net_boom.store(1, Ordering::SeqCst);
    let r = hub_serve(&w, &hdr, &body);
    assert!(r.is_err(), "control: the handler panicked: {r:?}");
    assert!(truthy(w.st1().extra.get("route_lock")), "the lock was written ahead on ch1");
    assert!(!w.oc().pending.is_empty(), "the lock was written ahead on ch2");
    // the busy flag is free again: the tick takes it, asks the provider again and settles both
    let acts = w.hub.watch_tick();
    assert!(acts.iter().any(|a| a["event"] == "lock_settled_late"), "{acts:?}");
    let st1 = w.st1();
    assert!(!truthy(st1.extra.get("route_lock")) && w.oc().pending.is_empty());
    assert_eq!(st1.best_cum, cum, "ch1 was not completed at the lock's state");
    assert!(w.oc().signed > 0);
    // the same request again (the client never got its answer): the saved answer, nothing moves
    let again = hub_serve(&w, &hdr, &body);
    assert!(matches!(&again, Ok((401, _))), "a spent seq authenticated again: {again:?}");
    // (the hand-built request above is not in the client's own records, so that client is left
    // aside.) Another client's lock goes over the same ch2 and is paid
    let (pay, sh) = fresh_client(&w);
    calls(&pay, &sh, 3);
    assert_eq!(pay.lock(&sh).unwrap().unwrap()["status"], "paid");
    w.chain.mine(1);
    tick(&w).unwrap();
}

/// HOLE (failing today). `RouteHub::watch` runs `watch_tick` on one thread, with nothing around
/// it: a panic in one tick ends the watcher for good, while the HTTP threads go on routing. No ch2
/// is then reconciled, refunded at its expiry or rolled over, no lock is written off, and ch1 is
/// not closed at its margin (`inbound.close_due()` is the tick's last step), so a client's refund
/// of a ch1 the hub was paid on becomes valid. With overflow checks on in release builds, a missed
/// overflow anywhere under `watch_tick` is such a panic. The panic here is injected by the chain
/// double (this audit found no counterparty-reachable panic under `watch_tick`).
#[test]
fn a_panic_in_one_tick_does_not_end_the_hub_watcher() {
    let w = world();
    let stop = w.hub.watch(Duration::from_millis(20));
    std::thread::sleep(Duration::from_millis(300));
    assert!(w.boom.asked.load(Ordering::SeqCst) > 2, "control: the watcher ticks");
    w.boom.boom.store(1, Ordering::SeqCst);
    let t0 = Instant::now();
    while w.boom.boom.load(Ordering::SeqCst) > 0 && t0.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(w.boom.boom.load(Ordering::SeqCst), 0, "control: the panic was taken");
    // the hub still routes: a lock is paid after the watcher's panic
    stream(&w, 3);
    assert_eq!(w.pay.lock(&w.sh).unwrap().unwrap()["status"], "paid", "control: the hub still routes");
    std::thread::sleep(Duration::from_millis(100));
    let n = w.boom.asked.load(Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(500));
    let ticks = w.boom.asked.load(Ordering::SeqCst) - n;
    stop.store(true, Ordering::SeqCst);
    assert!(ticks > 0, "the hub's watcher made no tick in 500 ms after one tick panicked: no ch2 is reconciled or refunded and no ch1 is closed at its \
                        margin any more, and the hub still routes (a lock was paid after the panic)");
}
