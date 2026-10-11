//! AGP-102 fourth closure audit, area HUB: tests written by the auditor on the rig of
//! `agp093_hub.rs` ([`MemChain`] + [`MemNet`], in process). Nothing here is a fix.
//!
//! Tests named after a rule fail today (each is a hole of the audit's list 1); `control_*` and
//! `measured_*` pass. What each failing test prints is the measurement the report quotes.
use std::cell::Cell;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use xbt402::adaptor;
use xbt402::adaptor::Sc;
use xbt402::channel::{channel_auth_key, FeePayer};
use xbt402::client::Transport;
use xbt402::funding::{ChainBackend, FundingPolicy, UtxoInfo};
use xbt402::http::HttpService;
use xbt402::hub::{HubConfig, OutChannel, RouteHub};
use xbt402::json::dumps;
use xbt402::ledger::{ChannelState, Ledger};
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::route::{fee_due, lock_auth, next_cum, SpendScan, HUB_ROUTE_PATH, ROUTE_LOCK_PATH};
use xbt402::route_client::{RoutePayer, RoutePayerConfig, Shard};
use xbt402::route_seller::RouteOffer;
use xbt402::signer::LocalSigner;
use xbt402::wire::{b64json, request_auth, request_digest_v2, CLOSE_PATH};
use xbt402_interop::memnet::{is_lock_check, ChainWallet, MemChain, MemNet, NetTransport};
use xbt_primitives::ecdsa;
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

const NET: &str = "bip122:11111111111111111111111111111111";
const HUB: &str = "http://hub.test";

thread_local! {
    /// The invoice TTL of the providers the next `W` is built with (seconds).
    static TTL: Cell<f64> = const { Cell::new(8.0) };
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let base = PathBuf::from("$HOME/xbt-rnd/xbt-rs-agp-102/run/tmp");
        let p = base.join(format!("agp102_hub_{}", hex::encode(&sha256(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes())[..8])));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The hub's node. `panic_on`: `gettxout` of that txid panics (a stand-in for any panic, such as a
/// missed overflow, in the code that reconciles ONE ch2), on every call while it is set.
struct Node {
    chain: Arc<MemChain>,
    panic_on: Mutex<Option<String>>,
}

impl ChainBackend for Node {
    fn block_count(&self) -> xbt402::Result<u32> {
        self.chain.block_count()
    }
    fn get_tx_out(&self, txid: &str, vout: u32, mempool: bool) -> xbt402::Result<Option<UtxoInfo>> {
        if self.panic_on.lock().unwrap().as_deref() == Some(txid) {
            panic!("agp102: injected panic while one ch2 is reconciled");
        }
        self.chain.get_tx_out(txid, vout, mempool)
    }
    fn send_raw_transaction(&self, hex: &str) -> xbt402::Result<String> {
        self.chain.send_raw_transaction(hex)
    }
    fn has_transaction(&self, txid: &str) -> xbt402::Result<bool> {
        self.chain.has_transaction(txid)
    }
    fn estimate_fee_rate(&self, target: u32) -> xbt402::Result<Option<f64>> {
        self.chain.estimate_fee_rate(target)
    }
    fn mempool_min_fee(&self) -> xbt402::Result<Option<f64>> {
        self.chain.mempool_min_fee()
    }
    fn submit_package(&self, hexes: &[String]) -> xbt402::Result<()> {
        self.chain.submit_package(hexes)
    }
}

/// The hub's spend scan, counting. `depth` false: it finds a spender and cannot say how deep it
/// is (a [`SpendScan`] that only has `find_spend`). `reads`: for every `find_spend_at` that found
/// a spender in a block, (from, the spender's height): the blocks `Rpc::find_spend_at` reads for
/// that answer are `height - from + 1` (`route.rs:483-494`: `getblock <hash> 2` for every height
/// from `from_height` up to the spender's block).
struct CountScan {
    chain: Arc<MemChain>,
    depth: bool,
    reads: Mutex<Vec<(u32, u32)>>,
}

impl CountScan {
    fn blocks_read(&self) -> u64 {
        self.reads.lock().unwrap().iter().map(|(from, h)| (h.saturating_sub(*from) + 1) as u64).sum()
    }
}

impl SpendScan for CountScan {
    fn find_spend(&self, txid: &str, vout: u32, from: u32) -> xbt402::Result<Option<Tx>> {
        self.chain.find_spend(txid, vout, from)
    }
    fn find_spend_at(&self, txid: &str, vout: u32, from: u32) -> xbt402::Result<Option<(Tx, Option<u32>)>> {
        let r = self.chain.find_spend_at(txid, vout, from)?;
        if let Some((_, Some(d))) = &r {
            if *d >= 1 {
                self.reads.lock().unwrap().push((from, self.chain.height() + 1 - d));
            }
        }
        Ok(r.map(|(tx, d)| (tx, if self.depth { d } else { None })))
    }
    fn scan_spk(&self, spk: &[u8]) -> xbt402::Result<Vec<(String, u32, u64)>> {
        self.chain.scan_spk(spk)
    }
    fn fee_rate(&self, target: u32) -> xbt402::Result<Option<f64>> {
        self.chain.fee_rate(target)
    }
    fn in_mempool(&self, txid: &str) -> xbt402::Result<bool> {
        self.chain.in_mempool(txid)
    }
}

/// The net as the hub reaches its providers. `stall`: a provider (by origin) that takes the
/// request and does not answer the hub's CHECK of a lock: the transport gives up after that long
/// (`xbt402-hub`'s transport gives up after 30 s). `stalled`: how many checks ended so.
struct HubNet {
    net: Arc<MemNet>,
    stall: Arc<Mutex<HashMap<String, Duration>>>,
    stalled: Arc<AtomicU32>,
}

impl Transport for HubNet {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> xbt402::Result<HttpResponse> {
        let (origin, path) = xbt402::client::split_url(url);
        if is_lock_check(&path, body) {
            let wait = self.stall.lock().unwrap().get(&origin).copied();
            if let Some(d) = wait {
                let _ = NetTransport(self.net.clone()).request(method, url, body, headers);
                std::thread::sleep(d);
                self.stalled.fetch_add(1, Ordering::SeqCst);
                return Err(xbt402::ChannelError::new("transport_error", "timed out reading the answer"));
            }
        }
        NetTransport(self.net.clone()).request(method, url, body, headers)
    }
}

/// A provider as the hub sees it over the net. `refuse`: it answers the hub's lock with a 400 AFTER
/// its inner provider completed it (it keeps the pre-signature and its t), and refuses the hub's
/// close requests (it closes when it likes).
struct Wrapped {
    inner: Arc<Provider>,
    refuse: Arc<AtomicBool>,
}

impl HttpService for Wrapped {
    fn body_limit(&self, path: &str) -> usize {
        HttpService::body_limit(&*self.inner, path)
    }

    fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str) -> HttpResponse {
        let no = || HttpResponse::new(400, vec![("Content-Type".into(), "application/json".into())], br#"{"error":"refused","detail":"no"}"#.to_vec());
        let refuse = self.refuse.load(Ordering::SeqCst);
        if refuse && path == CLOSE_PATH {
            return no();
        }
        let r = HttpService::serve(&*self.inner, method, path, headers, body, url);
        if refuse && path == ROUTE_LOCK_PATH && !is_lock_check(path, body) && r.status == 200 {
            return no();
        }
        r
    }
}

fn provider(chain: &Arc<MemChain>, net: &Arc<MemNet>, dir: &TempDir, origin: &str, settle_multiple: u64, sat_per_call: u128) -> (Arc<Provider>, Arc<AtomicBool>) {
    let mut cfg = ProviderConfig::new(NET);
    cfg.close_margin = 36;
    cfg.policy = FundingPolicy { min_capacity: 20_000, min_expiry_blocks: 500, max_expiry_blocks: 8_640, close_margin: 36, ..FundingPolicy::default() };
    cfg.settle_multiple = settle_multiple;
    cfg.height_ttl = Duration::ZERO;
    cfg.settle_lock_multiple = 0;
    cfg.route_close_fee_payer = FeePayer::Payee;
    let name = origin.replace("http://", "").replace('.', "_");
    let ledger = Ledger::open(&dir.0.join(format!("prov-{name}.jsonl"))).unwrap();
    let p = Provider::new(chain.clone(), adaptor::random_secret(), cfg, ledger, Box::new(|_, _| 1000),
                          Box::new(|_, _, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], b"{\"ok\":1}".to_vec()))).unwrap();
    p.offer_route(RouteOffer { window: 0.3, lock_wait: 0.6, invoice_ttl: TTL.with(Cell::get), ..RouteOffer::new("/v1/chunk", sat_per_call * 10u128.pow(21)) });
    let (p, refuse) = (Arc::new(p), Arc::new(AtomicBool::new(false)));
    net.add(origin, Arc::new(Wrapped { inner: p.clone(), refuse: refuse.clone() }));
    (p, refuse)
}

fn sk(n: u64) -> SecretKey {
    Sc::from_u64(n).secret().unwrap()
}

/// The rig's hub config, at the SHIPPED `spend_final_depth` (the rigs of the older files set 1).
fn hub_cfg() -> HubConfig {
    HubConfig::from_json(&json!({"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500, "delta": 36,
                                 "reveal_timeout": 0.3, "ch2_capacity": 100000, "ch2_expiry_blocks": 1000, "settle_lock_multiple": 0, "refill_ahead_locks": 0,
                                 "close_margin": 36, "policy": {"min_capacity": 20000, "min_expiry_blocks": 500, "max_expiry_blocks": 8640}})).unwrap()
}

struct W {
    chain: Arc<MemChain>,
    node: Arc<Node>,
    scan: Arc<CountScan>,
    net: Arc<MemNet>,
    stall: Arc<Mutex<HashMap<String, Duration>>>,
    stalled: Arc<AtomicU32>,
    hub: Arc<RouteHub>,
    provs: Vec<(String, Arc<Provider>)>,
    refuse: Vec<Arc<AtomicBool>>,
    pay: Arc<RoutePayer>,
    shards: Vec<Arc<Shard>>,
    _dir: TempDir,
}

impl W {
    fn new(n: usize) -> Self {
        Self::build(n, 20, 300, hub_cfg(), true)
    }

    fn build(n: usize, settle_multiple: u64, sat_per_call: u128, hcfg: HubConfig, depth: bool) -> Self {
        let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
        let scan = Arc::new(CountScan { chain: chain.clone(), depth, reads: Mutex::new(vec![]) });
        let node = Arc::new(Node { chain: chain.clone(), panic_on: Mutex::new(None) });
        let (stall, stalled) = (Arc::new(Mutex::new(HashMap::new())), Arc::new(AtomicU32::new(0)));
        let hub = Arc::new(RouteHub::new(node.clone(), scan.clone(), Box::new(ChainWallet(chain.clone())),
                                         Box::new(HubNet { net: net.clone(), stall: stall.clone(), stalled: stalled.clone() }), sk(0x4B4B), NET,
                                         Some(&dir.0.join("hub")), hcfg).unwrap());
        net.add(HUB, hub.clone());
        let (mut provs, mut refuse) = (vec![], vec![]);
        for i in 0..n {
            let origin = format!("http://p{i}.test");
            let (p, r) = provider(&chain, &net, &dir, &origin, settle_multiple, sat_per_call);
            provs.push((origin.clone(), p));
            refuse.push(r);
            hub.connect(&origin, None, None).unwrap();
        }
        chain.confirm_all();
        hub.watch_tick();
        let (pay, shards) = client(&chain, &net, &provs);
        Self { chain, node, scan, net, stall, stalled, hub, provs, refuse, pay, shards, _dir: dir }
    }

    fn st1(&self) -> ChannelState {
        self.hub.ch1_state(&self.pay.chan().unwrap()).unwrap()
    }

    fn stale1(&self) -> Vec<Value> {
        self.st1().extra.get("stale_locks").and_then(Value::as_array).cloned().unwrap_or_default()
    }

    fn lock(&self, i: usize) -> Option<Value> {
        stream(&self.pay, &self.shards[i], 10);
        self.pay.lock(&self.shards[i]).unwrap()
    }

    fn paid(&self, i: usize) {
        let r = self.lock(i);
        assert_eq!(r.as_ref().map(|r| r["status"].clone()), Some(json!("paid")), "{r:?}");
    }

    fn origin(&self, i: usize) -> &str {
        &self.provs[i].0
    }

    fn oc(&self, i: usize) -> OutChannel {
        self.hub.out_channels()[self.origin(i)].clone()
    }

    fn events(&self, name: &str) -> usize {
        self.hub.events.lock().unwrap().iter().filter(|e| e["event"] == name).count()
    }

    /// p`i` takes a lock and keeps it without revealing: written off on its ch2 and held on ch1.
    fn held_lock(&self, i: usize) -> Value {
        self.provs[i].1.set_no_reveal(true);
        let r = self.lock(i).unwrap();
        assert_eq!((r["status"].as_str(), r["error"].as_str()), (Some("refused"), Some("route_failed")), "{r}");
        self.provs[i].1.set_no_reveal(false);
        let held = self.stale1().pop().unwrap();
        assert!(held["hold"].is_object() && self.oc(i).stale.len() == 1, "control: written off on the ch2, held on ch1");
        held
    }

    /// p`i` completes a lock and answers the hub with a refusal: it keeps the pre-signature and t.
    /// Written off on its ch2 and held on ch1; the provider refuses the hub's close requests.
    fn kept_lock(&self, i: usize) -> Value {
        self.refuse[i].store(true, Ordering::SeqCst);
        let r = self.lock(i).unwrap();
        assert_eq!((r["status"].as_str(), r["error"].as_str()), (Some("refused"), Some("route_failed")), "{r}");
        let held = self.stale1().pop().unwrap();
        assert!(held["hold"].is_object() && self.oc(i).stale.len() == 1, "control: written off on the ch2, held on ch1");
        held
    }

    /// The hub's tick as its watcher thread runs it: a panic is caught (`WatchHealth::run`).
    fn tick(&self) -> std::result::Result<Vec<Value>, String> {
        catch_unwind(AssertUnwindSafe(|| self.hub.watch_tick())).map_err(|p| p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default())
    }
}

/// A client of the hub: its own ch1 and a session with every provider.
fn client(chain: &Arc<MemChain>, net: &Arc<MemNet>, provs: &[(String, Arc<Provider>)]) -> (Arc<RoutePayer>, Vec<Arc<Shard>>) {
    let mut cfg = RoutePayerConfig::new(NET);
    cfg.expiry_blocks = 8_000;
    let c = chain.clone();
    let pay = Arc::new(RoutePayer::new(HUB, cfg, Arc::new(LocalSigner::new()), Arc::new(ChainWallet(chain.clone())), Box::new(NetTransport(net.clone())),
                                       Box::new(move || Ok(c.height()))));
    pay.open().unwrap();
    chain.confirm_all();
    let shards = provs.iter().map(|(o, _)| pay.shard(&format!("{o}/v1/chunk"), "POST").unwrap()).collect();
    (pay, shards)
}

fn stream(pay: &RoutePayer, sh: &Arc<Shard>, n: usize) {
    for _ in 0..n {
        let r = pay.call(sh, "POST", br#"{"tokens":1}"#).unwrap();
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    }
}

fn has(acts: &[Value], name: &str) -> bool {
    acts.iter().any(|a| a["event"] == name)
}

fn pt33(h: &str) -> ecdsa::PubkeyBytes {
    hex::decode(h).unwrap().try_into().unwrap()
}

/// The client's POST /x402/route built as `RoutePayer::lock` builds it, then edited (the rig of
/// `agp093_overflow.rs`).
fn route_built_for(pay: &RoutePayer, sh: &Arc<Shard>, tamper: &dyn Fn(&mut Value, &mut Value)) -> (String, String) {
    let inv = sh.snapshot().invoice;
    let d = sh.due_sat().max(1) as u64;
    let q = pay.quote().unwrap();
    let (routed, units, paid, _) = pay.counters();
    let f = fee_due(&q, d, units, paid).0;
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
    pl["seq"] = s.into();
    let body = dumps(&json!({"route": route}));
    pl["auth"] = pay.signer().request_auth(&chan, Some(&pl["seq"]), Some(&pl["cum"]), None, &request_digest_v2("POST", &format!("{HUB}{HUB_ROUTE_PATH}"), body.as_bytes())).unwrap().into();
    let hdr = b64json(&json!({"x402Version": 2, "accepted": accepted, "payload": pl}));
    pay.signer().void_lock(&chan).unwrap();
    (hdr, body)
}

fn hub_serve(w: &W, hdr: &str, body: &str) -> (u16, Value) {
    let r = w.hub.serve("POST", HUB_ROUTE_PATH, &[("PAYMENT-SIGNATURE".into(), hdr.to_string())], body.as_bytes(), &format!("{HUB}{HUB_ROUTE_PATH}"), None);
    (r.status, xbt402::json::parse_slice(&r.body).unwrap_or(Value::Null))
}

/// A hub's CHECK of the open invoice of `sh`'s session, sent to p`i` over the hub's own ch2 as the
/// hub sends it (`hub.rs:1817-1839`), for the amount the client authorised.
fn check_serve(w: &W, i: usize, sh: &Arc<Shard>) -> (u16, Value) {
    let (oc, prov) = (w.oc(i), &w.provs[i].1);
    let p2 = &oc.params;
    let inv = prov.routes().state(&sh.session).unwrap()["invoice"].clone();
    let (point, lock_id) = (inv["point"].as_str().unwrap().to_string(), inv["lockId"].as_str().unwrap().to_string());
    let d = sh.due_sat().max(1) as u64;
    let secret = Sc::from_hex64(&oc.secret).unwrap().secret().unwrap();
    let route = json!({"session": sh.session, "lockId": lock_id, "amount": d, "hub": w.hub.pay_to(), "check": true,
                       "lockAuth": lock_auth(&sh.session_key(), &sh.session, &lock_id, d as i128, &point, w.hub.pay_to())});
    let seq = w.hub.with_out(|b| {
        let c = b.chans.get_mut(w.origin(i)).unwrap();
        c.seq += 1;
        c.seq
    });
    let need = next_cum(oc.routed, d, p2.min_amount());
    let mut pl = json!({"chan": p2.channel_id(), "seq": seq, "cum": need.to_string(), "point": point});
    let body = dumps(&json!({"route": route}));
    let url = format!("{}{ROUTE_LOCK_PATH}", w.origin(i));
    let key = channel_auth_key(&secret, &p2.payee_pub).unwrap();
    pl["auth"] = request_auth(&key, &p2.channel_id(), pl.get("seq"), pl.get("cum"), None, &request_digest_v2("POST", &url, body.as_bytes())).into();
    let hdr = b64json(&json!({"x402Version": 2, "accepted": {}, "payload": pl}));
    let r = prov.serve("POST", ROUTE_LOCK_PATH, &[("PAYMENT-SIGNATURE".into(), hdr)], body.as_bytes(), &url, None);
    (r.status, xbt402::json::parse_slice(&r.body).unwrap_or(Value::Null))
}

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64()
}

// --- Part B, `spend_final_depth`: what waiting for depth costs on every tick ---------------------------------
//
// A ch2 record keeps `scanned_to` at the tip of the day it was funded (`hub.rs:582`; nothing ever
// moves it). `reconcile` asks `find_spend_at(funding, scanned_to)` on every tick while the record
// is not final (`hub.rs:3588`). bitcoind's scan answers a spender in a block by reading every block
// from `scanned_to` to the spender's with `getblock <hash> 2` (`route.rs:483-494`). Before AGP-094 a
// spend was final in its first block, so this was one pass. Now the record waits `spend_final_depth`
// (6) blocks, and at the shipped `watch_interval` of 5 s that is about 600 ticks, each a full pass.

/// HOLE (Low, new in wave 5; Rust, B1 the same). The rule: a spend the watcher has found in a
/// block is not looked for again from the ch2's first block on every tick while it waits for depth.
#[test]
fn the_watcher_reads_the_chain_once_for_a_spend_that_waits_for_depth() {
    let w = W::new(1);
    w.paid(0);
    let funded_at = w.oc(0).scanned_to;
    w.chain.mine(200); // the ch2 is 200 blocks old when its provider closes it
    w.hub.watch_tick();
    let chan2 = w.oc(0).params.channel_id();
    w.provs[0].1.close_now(&chan2).unwrap();
    w.hub.watch_tick();
    w.chain.mine(1);
    let close_height = w.chain.height();
    let before = w.scan.blocks_read();
    let ticks = 20;
    for _ in 0..ticks {
        let acts = w.hub.watch_tick();
        assert!(!has(&acts, "ch2_closed"), "control: one block deep at depth 6, nothing is final: {acts:?}");
    }
    let (read, one_pass) = (w.scan.blocks_read() - before, (close_height - funded_at + 1) as u64);
    assert!(read <= 2 * one_pass,
            "{ticks} ticks while one close waited for depth read {read} blocks (`getblock <hash> 2` each, by `Rpc::find_spend_at`): {} per tick, from the \
             ch2's funding height {funded_at} to the close at {close_height}, every tick. At the shipped 5 s tick and 600 s blocks that is about 600 \
             ticks per close ({} block reads for this ch2; a ch2 refunded at its expiry is 1,100 blocks old)",
            read / ticks, 600 * one_pass);
}

/// The same for the usual case, a rollover: its parent is watched until the rollover is deep.
#[test]
fn the_watcher_reads_the_chain_once_for_a_rollover_that_waits_for_depth() {
    let w = W::build(1, 2, 40, hub_cfg(), true);
    w.chain.mine(200);
    w.hub.watch_tick();
    stream(&w.pay, &w.shards[0], 50);
    assert_eq!(w.pay.lock(&w.shards[0]).unwrap().unwrap()["status"], "paid");
    assert!(has(&w.hub.watch_tick(), "ch2_rollover"), "control: the ch2 is rolled over");
    w.chain.mine(1);
    let before = w.scan.blocks_read();
    let ticks = 20;
    for _ in 0..ticks {
        w.hub.watch_tick();
    }
    let read = w.scan.blocks_read() - before;
    assert!(read <= 2 * 202, "{ticks} ticks while one rollover waited for depth read {read} blocks: {} per tick for the rolled parent alone", read / ticks);
}

// --- Part C, found-not-fixed 1: `gone_at` and a spend that goes back to the mempool ---------------------------

/// The provider's close of a ch2 at the state before a written-off lock (no t) is mined, its block
/// is replaced, the close waits in the mempool for `wait` blocks and is mined again; the hub ticks
/// at every step. Then that block is replaced by one with the provider's other close, the one with
/// t. Returns (was the hold released while the close was ONE block deep, what ch1 closed at, the
/// lock's cum, what the hub's node showed of the funding while the close was back in the mempool).
fn close_mined_reorged_and_mined_again(depth: bool, wait: u32) -> (bool, u64, u64, bool) {
    let w = W::build(1, 20, 300, HubConfig { spend_final_depth: 3, ..hub_cfg() }, depth);
    w.paid(0);
    let (prov, chan2) = (&w.provs[0].1, w.oc(0).params.channel_id());
    let s0 = prov.channel_state(&chan2).unwrap();
    let held = w.kept_lock(0);
    let s1 = prov.channel_state(&chan2).unwrap();
    assert!(s1.best_cum > s0.best_cum, "control: the provider holds the lock's state and its t");
    prov.with_state(&chan2, |st| *st = s0.clone()).unwrap();
    let c0 = prov.close_now(&chan2).unwrap();
    w.hub.watch_tick();
    w.chain.mine(1);
    w.hub.watch_tick();
    assert_eq!(w.stale1().len(), 1, "control: one block deep, the hold stays");
    // the block is replaced; the close is back in the mempool and no block takes it for `wait` blocks
    w.chain.unconfirm(&c0);
    w.chain.set_block_min_feerate(1e9);
    let (ftxid, fvout) = (w.oc(0).params.funding_txid(), w.oc(0).params.funding_vout());
    let mut shown_unconfirmed = true;
    for _ in 0..wait {
        w.chain.mine(1);
        shown_unconfirmed &= w.node.get_tx_out(&ftxid, fvout, false).unwrap().is_some() && !w.chain.confirmed(&c0);
        w.hub.watch_tick();
        assert_eq!(w.stale1().len(), 1, "control: nothing is released while the close is in the mempool");
    }
    w.chain.set_block_min_feerate(0.0);
    w.chain.mine(1);
    assert!(w.chain.confirmed(&c0), "control: the close is mined again, one block deep");
    let mut acts = w.hub.watch_tick();
    acts.extend(w.hub.watch_tick());
    let released_at_one = has(&acts, "lock_released");
    let closed = w.pay.close();
    // that block is replaced too, by one with the close that carries t
    w.chain.unconfirm(&c0);
    w.chain.evict(&c0);
    prov.with_state(&chan2, |st| *st = s1.clone()).unwrap();
    let c1 = prov.close_now(&chan2).unwrap();
    assert_ne!(c0, c1);
    w.chain.mine(6);
    w.hub.watch_tick();
    w.hub.watch_tick();
    let _ = closed;
    (released_at_one, w.st1().best_cum, held["cum"].as_u64().unwrap(), shown_unconfirmed)
}

/// HOLE (Low; Rust, B1 the same from reading; scans without a depth only, which no shipped binary
/// uses). AGP-094 found-not-fixed 1, run. The stated limit says "a reorg between two ticks that
/// it does not see is not noticed". The watcher DOES see it: on every tick in between its own node
/// shows the funding back in the confirmed set (`spend_depth` answers 0, `hub.rs:3752-3754`), and
/// `gone_at` is kept all the same (`hub.rs:3526-3528` resets it only when the funding is unspent
/// counting the mempool). So the close counts as `spend_final_depth` deep in the first block that
/// mines it again, and the hold is released on one confirmation: item 2 of the third audit again.
#[test]
fn a_close_seen_back_in_the_mempool_is_counted_from_the_block_that_mines_it_again() {
    let (released_at_one, collected, lock_cum, shown) = close_mined_reorged_and_mined_again(false, 2);
    assert!(shown, "control: at every tick in between, the hub's node showed the funding unspent in the confirmed set");
    assert!(!released_at_one && collected >= lock_cum,
            "spend_final_depth 3, a scan without depth: the close was mined, reorged out, in the mempool for 2 blocks (the hub ticked on each and its \
             node showed the funding unspent), then mined again: one block deep the hold was released ({released_at_one}); that block was replaced by the \
             close with t and ch1 closed at {collected} sat, below the lock's {lock_cum}");
}

/// Control: with a scan that gives the depth (bitcoind, the shipped binaries) the same sequence
/// releases nothing at one confirmation, and the close with t is collected.
#[test]
fn control_with_a_scan_that_gives_the_depth_the_same_reorg_releases_nothing() {
    let (released_at_one, collected, lock_cum, _) = close_mined_reorged_and_mined_again(true, 2);
    assert!(!released_at_one && collected >= lock_cum, "released {released_at_one}, collected {collected} of {lock_cum}");
}

// --- Part B, hub admission "an invoice needs revealTimeoutSec left": the shipped defaults -----------------------

/// HOLE (Low; a default that defeats the rule; the hub's half is new in wave 5, the client's half
/// was there). `xbt402-hub` waits `reveal_timeout` 10 s by default (`hub.rs:339`) and now admits
/// an invoice only with that much left (`hub.rs:1492`); `xbt402-route-provider` issues invoices
/// that live 8 s by default (`xbt402-route-provider.rs:63`, `--ttl 8.0`). No invoice of the one
/// binary is ever admitted by the other at their defaults, and the shipped client never sends
/// one (`route_client.rs:1195`): the provider's credit runs out and it stops serving. The interop
/// script sets `reveal_timeout` 2 (`scripts/interop/route_interop.py:196`), and every in-process
/// rig sets 0.3 or 1, so no test runs the two defaults together.
#[test]
fn a_lock_is_routed_at_the_shipped_defaults_of_the_hub_and_the_route_provider() {
    TTL.with(|t| t.set(8.0)); // xbt402-route-provider --ttl default
    let w = W::build(1, 20, 300, HubConfig { reveal_timeout: HubConfig::default().reveal_timeout, ..hub_cfg() }, true);
    assert_eq!(HubConfig::default().reveal_timeout, 10.0);
    stream(&w.pay, &w.shards[0], 10);
    let r = w.pay.lock(&w.shards[0]).unwrap();
    // what the hub itself answers a client that does send it
    let (hdr, body) = route_built_for(&w.pay, &w.shards[0], &|_, _| {});
    let (st, doc) = hub_serve(&w, &hdr, &body);
    assert!(r.as_ref().is_some_and(|r| r["status"] == "paid"),
            "hub reveal_timeout 10 s, provider invoice TTL 8 s (both shipped defaults): the client's lock() answered {r:?} with {} sat due and a fresh invoice, \
             and the hub answers the same lock sent anyway {st} {}", w.shards[0].due_sat(), doc);
}

/// Control: with the library's default invoice TTL (`RouteOffer::new`, 15 s) and the hub's default
/// 10 s a fresh invoice is admitted (for the first 5 s of its 15; the client keeps 1 s more).
#[test]
fn control_a_fresh_invoice_of_15_s_is_routed_at_the_hubs_default_reveal_timeout() {
    assert_eq!(RouteOffer::new("/x", 1).invoice_ttl, 15.0);
    TTL.with(|t| t.set(15.0));
    let w = W::build(1, 20, 300, HubConfig { reveal_timeout: HubConfig::default().reveal_timeout, ..hub_cfg() }, true);
    w.paid(0);
}

// --- Part B, the check: who can send one, what it leaves, what it costs -----------------------------------------

/// Question (a), measured (not a failing test). A check with no lock after it: the provider keeps
/// `bound` on that session's window, in memory, until the window ends; a call of the client's does
/// not end the window early; the next window is unbound. The hub's ch2 keeps nothing but one seq.
#[test]
fn control_a_check_with_no_lock_after_it_binds_one_invoice_until_its_window_ends() {
    TTL.with(|t| t.set(1.2));
    let w = W::new(1);
    stream(&w.pay, &w.shards[0], 3);
    let prov = &w.provs[0].1;
    let sid = w.shards[0].session.clone();
    let (st0, oc0) = (prov.channel_state(&w.oc(0).params.channel_id()).unwrap(), w.oc(0));
    let lock_id = prov.routes().state(&sid).unwrap()["invoice"]["lockId"].clone();
    let (st, doc) = check_serve(&w, 0, &w.shards[0]);
    assert_eq!((st, doc["check"].clone()), (200, lock_id.clone()), "control: the check is answered yes: {doc}");
    let chan2 = w.oc(0).params.channel_id();
    assert_eq!(prov.routes().lock().sessions[&sid].bound, chan2, "the invoice is bound to the hub's ch2");
    let st1 = prov.channel_state(&chan2).unwrap();
    assert_eq!((st1.best_cum, st1.extra.get("routed_sat").cloned(), st1.seq), (st0.best_cum, st0.extra.get("routed_sat").cloned(), oc0.seq + 1),
               "the provider's channel moved by the request's seq and nothing else");
    // what a call of the client's runs (`state_locked`), inside the last second of the window: it
    // used to open a new window there
    let left = prov.routes().lock().sessions[&sid].valid_until - now();
    std::thread::sleep(Duration::from_secs_f64((left - 0.5).max(0.0)));
    assert_eq!(prov.routes().state(&sid).unwrap()["invoice"]["lockId"], lock_id, "the bound window lives to its validUntil");
    std::thread::sleep(Duration::from_secs_f64(0.7));
    let next = prov.routes().state(&sid).unwrap()["invoice"]["lockId"].clone();
    let s = prov.routes().lock().sessions[&sid].clone();
    assert!(s.bound.is_empty() && next != lock_id, "the next window is unbound: {:?}", s.bound);
    eprintln!("agp102_hub: a check with no lock after it: bound for {left:.2} s of a {:.1} s window, then gone; provider channel seq +1, nothing else", TTL.with(Cell::get));
}

/// Question (a), measured (not a failing test): what a client's lock that the provider refuses at
/// the check costs the client, the hub and the provider. The client pays nothing and can repeat it
/// at once; each one is a request to the provider, a seq on the ch2, and one more entry in the
/// hub's `events` list, which nothing in `xbt402-hub` ever empties (`hub.rs:1132-1134`; the third
/// audit's 088-F4). Honest locks are paid in between.
#[test]
fn measured_what_a_lock_refused_at_the_check_costs() {
    let w = W::new(1);
    w.paid(0);
    let (bad, bad_sh) = client(&w.chain, &w.net, &w.provs);
    stream(&bad, &bad_sh[0], 3);
    let (ev0, seq0, checks0) = (w.hub.events.lock().unwrap().len(), w.oc(0).seq, w.net.count(&format!("{ROUTE_LOCK_PATH}?check")));
    let ch1_before = w.hub.ch1_state(&bad.chan().unwrap()).unwrap();
    let n = 50;
    let t0 = Instant::now();
    for i in 0..n {
        let (hdr, body) = route_built_for(&bad, &bad_sh[0], &|_, rt| rt["lockAuth"] = "00".repeat(32).into());
        let (st, doc) = hub_serve(&w, &hdr, &body);
        assert_eq!((st, doc["providerError"].as_str()), (502, Some("bad_auth")), "{doc}");
        if i % 10 == 9 {
            // (the rig's stalled-check counter is not involved: these checks are answered)
            assert!(w.oc(0).stale.is_empty() && w.oc(0).blocked.is_empty(), "control: nothing written off or blocked");
        }
    }
    let per = t0.elapsed().as_secs_f64() * 1000.0 / n as f64;
    let (ev, seq, checks) = (w.hub.events.lock().unwrap().len() - ev0, w.oc(0).seq - seq0, w.net.count(&format!("{ROUTE_LOCK_PATH}?check")) - checks0);
    let ch1 = w.hub.ch1_state(&bad.chan().unwrap()).unwrap();
    assert_eq!((ch1.best_cum, ch1.extra.get("routed_sat").cloned()), (ch1_before.best_cum, ch1_before.extra.get("routed_sat").cloned()), "the client paid nothing");
    w.paid(0);
    eprintln!("agp102_hub: {n} locks refused at the check: client paid 0 sat; {checks} requests to the provider, ch2 seq +{seq}, hub events +{ev} (never emptied), \
               {per:.1} ms each in process; the honest client's next lock is paid");
    assert_eq!((checks, seq as usize, ev), (n, n, n), "one provider request, one ch2 seq and one hub event per refused lock");
}

/// Control: the answer to a check is lost (the transport gives up at once). Nothing is written off
/// or held, the ch2 is not blocked, and the client's next try is paid.
#[test]
fn control_a_check_whose_answer_is_lost_writes_nothing_off() {
    let w = W::new(1);
    w.stall.lock().unwrap().insert(w.origin(0).to_string(), Duration::ZERO);
    let r = w.lock(0).unwrap();
    assert_eq!((r["status"].as_str(), r["error"].as_str()), (Some("refused"), Some("route_failed")), "{r}");
    assert!(w.oc(0).stale.is_empty() && w.oc(0).blocked.is_empty() && w.oc(0).pending.is_empty() && w.stale1().is_empty());
    w.stall.lock().unwrap().clear();
    w.paid(0);
}

/// HOLE (Medium, availability; new in wave 5; Rust, B1 from reading). A provider that takes the
/// hub's check and does not answer is waited for until the hub's transport gives up (30 s in
/// `xbt402-hub`: `http.rs`, `UreqTransport::default`; `revealTimeoutSec` does not bound the check,
/// `hub.rs:1830`), and the answer is "no_answer: nothing written off, the ch2 not blocked"
/// (`hub.rs:1686-1691`). So it is waited for again on the next lock, and the next, for as long as
/// it hangs. A client's locks are serial on its ch1, so each of those waits is time in which that
/// client pays no other provider. Before AGP-094 the first unanswered lock blocked the ch2 and
/// every later one was refused at once (`route_blocked`).
///
/// The rule: a provider that did not answer is not waited for again on every lock.
#[test]
fn a_provider_that_does_not_answer_the_check_is_not_waited_for_on_every_lock() {
    let w = W::new(2);
    w.paid(0);
    w.paid(1);
    let stall = Duration::from_millis(700);
    w.stall.lock().unwrap().insert(w.origin(0).to_string(), stall);
    stream(&w.pay, &w.shards[0], 10);
    let rounds = 4;
    let t0 = Instant::now();
    let mut paid_other = 0;
    for _ in 0..rounds {
        // one round of the client's tick: p0 (hung), then p1
        let r = w.pay.lock(&w.shards[0]).unwrap();
        assert!(r.as_ref().is_none_or(|r| r["status"] == "refused"), "control: nothing is paid to the hung provider: {r:?}");
        if w.lock(1).is_some_and(|r| r["status"] == "paid") {
            paid_other += 1;
        }
    }
    let (took, waits) = (t0.elapsed(), w.stalled.load(Ordering::SeqCst));
    let oc = w.oc(0);
    assert!(waits <= 1,
            "{rounds} rounds of one client's tick took {:.1} s: the hub waited {waits} times {:.1} s for a provider that never answers a check (30 s each in \
             xbt402-hub), its ch2 is {} and blocked {:?} with {} written off, so the next lock waits again; the client paid its other provider {paid_other} \
             times in that time",
            took.as_secs_f64(), stall.as_secs_f64(), oc.state, oc.blocked, oc.stale.len());
}

/// The same hang, seen from the hub's other clients (measured against a bound). While one lock
/// waits for the hung provider's check it holds that provider's busy flag; every other lock for
/// that provider waits for the flag for up to 500 ms INSIDE the hub's ch1 ledger lock
/// (`hub.rs:1356` takes it, `hub.rs:1503` waits), which every request of every client to every
/// provider needs. Left from before (the wait under the lock is older than wave 5); wave 5 made it
/// last for as long as the provider hangs, where it used to end with the ch2 blocked.
#[test]
fn a_provider_that_does_not_answer_does_not_hold_up_a_lock_to_another_provider() {
    let w = Arc::new(W::new(2));
    w.paid(0);
    let (c2, sh2) = client(&w.chain, &w.net, &w.provs);
    let (c3, sh3) = client(&w.chain, &w.net, &w.provs);
    stream(&c2, &sh2[0], 10);
    stream(&c3, &sh3[1], 10);
    // control: a lock to p1 with nothing else going on
    let t = Instant::now();
    assert_eq!(c3.lock(&sh3[1]).unwrap().unwrap()["status"], "paid");
    let alone = t.elapsed();
    stream(&c3, &sh3[1], 10);
    w.stall.lock().unwrap().insert(w.origin(0).to_string(), Duration::from_millis(1500));
    let done = Arc::new(AtomicBool::new(false));
    let h1 = {
        let w = w.clone();
        std::thread::spawn(move || {
            stream(&w.pay, &w.shards[0], 10);
            let _ = w.pay.lock(&w.shards[0]);
        })
    };
    std::thread::sleep(Duration::from_millis(150)); // client 1's lock is waiting for p0's check
    let h2 = {
        let d = done.clone();
        std::thread::spawn(move || {
            let r = c2.lock(&sh2[0]);
            d.store(true, Ordering::SeqCst);
            r.ok().flatten()
        })
    };
    std::thread::sleep(Duration::from_millis(60)); // client 2's lock for p0 is waiting for the busy flag
    let t = Instant::now();
    let r3 = c3.lock(&sh3[1]).unwrap();
    let held_up = t.elapsed();
    let r2 = h2.join().unwrap();
    h1.join().unwrap();
    assert_eq!(r3.as_ref().map(|r| r["status"].clone()), Some(json!("paid")), "control: the lock to p1 is paid in the end: {r3:?}");
    assert!(held_up < Duration::from_millis(200),
            "a lock to p1 took {:.0} ms ({:.0} ms alone) while another client's lock for the hung p0 waited for its busy flag inside the hub's ch1 ledger \
             lock (that lock answered {:?}); each such request holds every route, view, open and close of the hub for up to 500 ms",
            held_up.as_secs_f64() * 1000.0, alone.as_secs_f64() * 1000.0, r2.map(|r| r["detail"].clone()));
}

// --- list 1 item 13: the catch is per tick, not per channel -------------------------------------------------------

/// HOLE (Low; the residue of item 13; Rust). The watcher's catch is around the whole tick
/// (`hub.rs:3999`), and `Provider::close_due`'s around all of ch1's channels (`provider.rs:1362`).
/// A ch2 whose reconcile panics on EVERY tick (the kind of panic the item is about: an unchecked
/// number in one record) ends each tick at that ch2: every ch2 after it in the book, the archive,
/// the orphan sweep and ch1's margin closes never run, exactly as when the watcher was dead.
/// `/healthz` does say 503. No panic reachable by a counterparty was found under the tick.
#[test]
fn a_ch2_whose_reconcile_panics_on_every_tick_does_not_stop_the_watcher_for_the_others() {
    let w = W::new(2);
    w.paid(0);
    w.paid(1);
    // p1 closes its ch2: the watcher should see the close and make the record `closing`
    w.provs[1].1.close_now(&w.oc(1).params.channel_id()).unwrap();
    *w.node.panic_on.lock().unwrap() = Some(w.oc(0).params.funding_txid());
    let mut panics = 0;
    for _ in 0..5 {
        w.chain.mine(1);
        if w.tick().is_err() {
            panics += 1;
        }
    }
    assert!(panics == 5, "control: every tick panicked at p0's ch2 ({panics} of 5)");
    assert_ne!(w.oc(1).state, "open",
               "5 ticks, each ended by a panic while p0's ch2 was reconciled: p1's ch2, closed by its provider 5 blocks ago, is still {:?} in the hub's book \
                (its close was never read), and ch1's margin closes ({} asked) never ran", w.oc(1).state, w.events("ch1_close"));
}

// --- question (b): what a close one to five blocks deep changes at the shipped depth ---------------------------

/// Control, at the shipped depth 6: a close that carries t is read one block deep (the secret
/// completes ch1 at once), the hold of a close without t stays for five more blocks and ch1 cannot
/// be closed below it meanwhile, and the hub's own refund of an unused ch2 is sent at its expiry
/// and not bumped once it is in a block.
#[test]
fn control_at_depth_one_to_five_secrets_are_read_holds_stay_and_the_refund_is_not_bumped() {
    assert_eq!(hub_cfg().spend_final_depth, 6);
    let w = W::new(3);
    w.paid(0);
    // p0 keeps a lock with its t and closes with it: read one block deep, long before depth 6
    let held0 = w.kept_lock(0);
    w.provs[0].1.close_now(&w.oc(0).params.channel_id()).unwrap();
    w.chain.mine(1);
    let acts = w.hub.watch_tick();
    assert!(acts.iter().any(|a| a["event"] == "secret_from_close" && a["ch1_completed"] == true), "one block deep the secret is read: {acts:?}");
    assert_eq!((w.st1().best_cum, w.oc(0).final_), (held0["cum"].as_u64().unwrap(), false), "ch1 collected the lock; the record waits for depth");
    // p1 does not reveal, and closes its ch2 at its best state: without t
    let held1 = w.held_lock(1);
    let chan1 = w.oc(1).params.channel_id();
    assert!(w.provs[1].1.channel_state(&chan1).unwrap().best_cum == 0, "control: the provider has no state on that ch2");
    let _ = chan1;
    // (a ch2 with nothing signed cannot be closed by its provider: the hold waits for the hub's refund)
    let oc1 = w.oc(1);
    w.chain.mine(oc1.params.expiry.saturating_sub(w.chain.height()));
    let acts = w.hub.watch_tick();
    assert!(has(&acts, "ch2_refund"), "the refunds go out at the expiry, hold or no hold: {acts:?}");
    let (r1, r2) = (w.oc(1).refund_txid.clone(), w.oc(2).refund_txid.clone());
    assert!(!r1.is_empty() && !r2.is_empty(), "both the ch2 with a held lock and the unused one are refunded");
    for deep in 1..=6u32 {
        w.chain.mine(1);
        let mut acts = w.hub.watch_tick();
        acts.extend(w.hub.watch_tick());
        assert!(!has(&acts, "ch2_refund_bump") && !has(&acts, "ch2_refund_rebroadcast"), "{deep} deep: {acts:?}");
        let released = w.stale1().iter().all(|s| s["lockId"] != held1["lockId"]);
        assert_eq!((released, w.oc(1).final_, w.oc(2).final_), (deep == 6, deep == 6, deep == 6), "{deep} block(s) deep: {acts:?}");
        assert_eq!((w.oc(1).refund_txid.clone(), w.oc(2).refund_txid.clone()), (r1.clone(), r2.clone()));
        if deep < 6 {
            assert_eq!(w.pay.close().unwrap_err().code, "lock_pending", "ch1 does not close below a hold that waits for depth");
        }
    }
}

/// Control: `gone_at` is on disk (a restart keeps the count), a ledger from before has none and is
/// counted from the first tick after the upgrade (later, never earlier), and a depth of 0 is refused.
#[test]
fn control_gone_at_is_persisted_and_a_record_from_before_counts_from_the_first_tick() {
    let w = W::build(1, 20, 300, HubConfig { spend_final_depth: 3, ..hub_cfg() }, false);
    w.paid(0);
    let chan2 = w.oc(0).params.channel_id();
    w.provs[0].1.close_now(&chan2).unwrap();
    w.hub.watch_tick();
    w.chain.mine(1);
    w.hub.watch_tick();
    let oc = w.oc(0);
    assert_eq!(oc.gone_at, w.chain.height(), "counted from the block at which the watcher saw it");
    let back = OutChannel::from_json(&oc.to_json()).unwrap();
    assert_eq!(back.gone_at, oc.gone_at, "written and read back");
    let mut old = oc.to_json();
    old.as_object_mut().unwrap().remove("gone_at");
    assert_eq!(OutChannel::from_json(&old).unwrap().gone_at, 0, "a record from before: not seen yet");
    assert_eq!(HubConfig::from_json(&json!({"spend_final_depth": 0})).unwrap_err().code, "bad_config");
    assert_eq!(HubConfig::from_json(&json!({})).unwrap().spend_final_depth, 6);
}

// --- list 1 item 12, fourth bullet ("a failed ch1 write during a completion"): the confirmed path ---------------

/// The provider keeps a lock with its t and closes its ch2 with it; the hub's first tick that sees
/// that close sees it `deep` blocks deep, and ch1's ledger does not take the completion's write on
/// that tick (`stop`) and takes the next write. Returns (the tick's events, what ch1 holds
/// written off after it, the ch2 record's final flag, ch1's best state, the lock's cum).
fn first_sight_of_a_close_with_t(deep: u32, stop: bool) -> (Vec<Value>, usize, bool, u64, u64) {
    let w = W::new(1);
    w.paid(0);
    let held = w.kept_lock(0);
    w.provs[0].1.close_now(&w.oc(0).params.channel_id()).unwrap();
    w.chain.mine(1); // (MemChain puts the mempool in the LAST block it mines)
    w.chain.mine(deep - 1);
    if stop {
        w.hub.set_stop("complete_ch1");
    }
    let acts = w.hub.watch_tick();
    w.hub.set_stop("");
    let mut all = acts.clone();
    all.extend(w.hub.watch_tick());
    (all, w.stale1().len(), w.oc(0).final_, w.st1().best_cum, held["cum"].as_u64().unwrap())
}

/// HOLE (Low; Rust, B1 from reading; the residue of item 12's fourth bullet). AGP-094 keeps the
/// lock on the ch2 record when ch1's ledger does not take the completion's write, "for the next
/// tick" (`hub.rs:3962-3967`). On a close that is already `spend_final_depth` deep there is no
/// next tick: the same pass goes on to `release_rolled` (`hub.rs:3713`), which finds that lock
/// still written off, releases it as unpaid on ch1 (that write is taken) and makes the record
/// final. The hub paid the lock on its ch2 and gave the client's hold back. It needs a ch1 write
/// that fails on the first tick that sees the close deep (a hub that was down while the close
/// confirmed) and succeeds a moment later; the loss is one lock (`max_lock_sat` at most).
#[test]
fn a_completion_ch1_did_not_take_is_not_released_as_unpaid_by_the_same_tick() {
    let (acts, left, final_, best, cum) = first_sight_of_a_close_with_t(6, true);
    assert!(acts.iter().any(|a| a["event"] == "secret_from_close" && a["ch1_completed"] == false), "control: the completion's write was not taken: {acts:?}");
    assert!(best >= cum,
            "the close with t was 6 deep when the hub first saw it and ch1 did not take the completion: the same tick released the lock as unpaid ({}), the \
             ch2 record is final ({final_}), ch1 holds {left} written-off lock(s) and its best state is {best} sat, below the lock's {cum} that the hub paid",
            has(&acts, "lock_released"));
}

/// Controls: the same close first seen one block deep (the next tick completes it), and first
/// seen six deep with a ledger that takes the write.
#[test]
fn control_a_completion_ch1_did_not_take_is_completed_by_the_next_tick_when_the_close_is_not_deep() {
    let (acts, left, _, best, cum) = first_sight_of_a_close_with_t(1, true);
    assert!(best >= cum && left == 0 && !has(&acts, "lock_released"), "{acts:?}");
    let (acts, left, final_, best, cum) = first_sight_of_a_close_with_t(6, false);
    assert!(best >= cum && left == 0 && final_ && !has(&acts, "lock_released"), "{acts:?}");
}
