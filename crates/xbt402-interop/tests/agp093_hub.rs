//! AGP-093, area HUB: tests of the third closure audit of the external review (fix wave 4, AGP-088).
//!
//! The harness is `agp088_hub.rs`'s, unchanged (lines below up to `has`).
//!
//! Tests named `hole_*` FAIL on `d4c8328`: each one shows a hole or a limit nobody wrote down. The
//! others pass and are the control of the hole beside them.
#![allow(dead_code, unused_imports)]
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use xbt402::adaptor;
use xbt402::adaptor::Sc;
use xbt402::channel::FeePayer;
use xbt402::funding::{ChainBackend, FundingPolicy, UtxoInfo};
use xbt402::http::HttpService;
use xbt402::hub::{HubConfig, OutChannel, RouteHub};
use xbt402::ledger::{ChannelState, Ledger};
use xbt402::provider::{HttpResponse, Provider, ProviderConfig, MAX_KEPT_INTENTS};
use xbt402::route::{fee_due, SpendScan, HUB_VIEW_PATH, ROUTE_LOCK_PATH, TERMS_PATH};
use xbt402::route_client::{RoutePayer, RoutePayerConfig, Shard};
use xbt402::route_seller::RouteOffer;
use xbt402::signer::{LocalSigner, RouteSigner, StateSigner};
use xbt402::wire::{b64json, request_digest_v2, CLOSE_PATH};
use xbt_primitives::tx::Tx;
use xbt402_interop::memnet::{ChainWallet, MemChain, MemNet, NetTransport};
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;

const NET: &str = "bip122:11111111111111111111111111111111";
const HUB: &str = "http://hub.test";

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("xbt-rs-agp093-hub-{}", hex::encode(&sha256(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes())[..8])));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A provider as the hub sees it over the net: its answer to `/lock` can be held at a gate, or
/// replaced by a 400 (the provider keeps the pre-signature); `deaf`: it refuses the hub's close
/// request (it will close when it likes).
struct Wrapped {
    inner: Arc<Provider>,
    gate: Mutex<(bool, bool, bool)>,
    cv: Condvar,
    refuse: AtomicBool,
    deaf: AtomicBool,
    /// Its /terms name this payTo, and it answers an open preflight with yes.
    pay_to: Mutex<Option<String>>,
    /// It answers the hub's close request 200 with this txid, at the hub's best state, and sends nothing.
    fake_close: Mutex<Option<(String, u64, u64)>>,
}

impl HttpService for Wrapped {
    fn body_limit(&self, path: &str) -> usize {
        HttpService::body_limit(&*self.inner, path)
    }

    fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str) -> HttpResponse {
        let json_ = |st: u16, v: Value| HttpResponse::new(st, vec![("Content-Type".into(), "application/json".into())], v.to_string().into_bytes());
        if path == CLOSE_PATH && self.deaf.load(Ordering::SeqCst) {
            return HttpResponse::new(400, vec![("Content-Type".into(), "application/json".into())], br#"{"error":"refused","detail":"later"}"#.to_vec());
        }
        if let (true, Some((txid, cum, fee))) = (path == CLOSE_PATH, self.fake_close.lock().unwrap().clone()) {
            return json_(200, json!({"txid": txid, "cum": cum.to_string(), "payeeFee": fee, "payeeNet": cum - fee, "status": "closed"}));
        }
        if let Some(pt) = self.pay_to.lock().unwrap().clone() {
            if path == TERMS_PATH {
                let mut doc: Value = serde_json::from_slice(&HttpService::serve(&*self.inner, method, path, headers, body, url).body).unwrap();
                doc["payTo"] = pt.into();
                return json_(200, doc);
            }
            if serde_json::from_slice::<Value>(body).is_ok_and(|b| b["preflight"] == true) {
                return json_(200, json!({"preflight": true, "closeFeePayer": "payee"}));
            }
        }
        let r = HttpService::serve(&*self.inner, method, path, headers, body, url);
        if path == ROUTE_LOCK_PATH {
            let mut g = self.gate.lock().unwrap();
            if g.0 {
                g.1 = true;
                self.cv.notify_all();
                let (mut g, _) = self.cv.wait_timeout_while(g, Duration::from_secs(10), |g| !g.2).unwrap();
                g.0 = false;
            }
        }
        if path == ROUTE_LOCK_PATH && self.refuse.load(Ordering::SeqCst) && r.status == 200 {
            return HttpResponse::new(400, vec![("Content-Type".into(), "application/json".into())], br#"{"error":"refused","detail":"no"}"#.to_vec());
        }
        r
    }
}

struct Node {
    chain: Arc<MemChain>,
    down: AtomicBool,
    /// `gettxout txid n false` as a real node answers it: the confirmed UTXO set only, so None for
    /// an output of an unconfirmed transaction (MemChain returns such an output with 0 confirmations).
    strict: AtomicBool,
}

impl ChainBackend for Node {
    fn block_count(&self) -> xbt402::Result<u32> {
        self.chain.block_count()
    }
    fn get_tx_out(&self, txid: &str, vout: u32, mempool: bool) -> xbt402::Result<Option<UtxoInfo>> {
        let r = self.chain.get_tx_out(txid, vout, mempool)?;
        Ok(r.filter(|u| mempool || u.confirmations > 0 || !self.strict.load(Ordering::SeqCst)))
    }
    fn send_raw_transaction(&self, hex: &str) -> xbt402::Result<String> {
        if self.down.load(Ordering::SeqCst) {
            return Err(xbt402::ChannelError::new("rpc_error", "timed out"));
        }
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
        if self.down.load(Ordering::SeqCst) {
            return Err(xbt402::ChannelError::new("rpc_error", "timed out"));
        }
        self.chain.submit_package(hexes)
    }
}

/// The chain's spend scan without the depth of what it finds (a [`SpendScan`] that only has
/// `find_spend`).
struct NoDepth(Arc<MemChain>);

impl SpendScan for NoDepth {
    fn find_spend(&self, txid: &str, vout: u32, from: u32) -> xbt402::Result<Option<Tx>> {
        self.0.find_spend(txid, vout, from)
    }
    fn scan_spk(&self, spk: &[u8]) -> xbt402::Result<Vec<(String, u32, u64)>> {
        self.0.scan_spk(spk)
    }
    fn in_mempool(&self, txid: &str) -> xbt402::Result<bool> {
        self.0.in_mempool(txid)
    }
}

fn provider(chain: &Arc<MemChain>, net: &Arc<MemNet>, dir: &TempDir, origin: &str, settle_multiple: u64, sat_per_call: u128) -> Arc<Wrapped> {
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
    p.offer_route(RouteOffer { window: 0.3, lock_wait: 0.6, invoice_ttl: 8.0, ..RouteOffer::new("/v1/chunk", sat_per_call * 10u128.pow(21)) });
    let w = Arc::new(Wrapped { inner: Arc::new(p), gate: Mutex::new((false, false, false)), cv: Condvar::new(), refuse: AtomicBool::new(false),
                               deaf: AtomicBool::new(false), pay_to: Mutex::new(None), fake_close: Mutex::new(None) });
    net.add(origin, w.clone());
    w
}

fn sk(n: u64) -> SecretKey {
    Sc::from_u64(n).secret().unwrap()
}

fn hub_cfg() -> HubConfig {
    HubConfig::from_json(&json!({"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500, "delta": 36,
                                 "reveal_timeout": 0.3, "ch2_capacity": 100000, "ch2_expiry_blocks": 1000, "settle_lock_multiple": 0, "refill_ahead_locks": 0,
                                 "close_margin": 36, "policy": {"min_capacity": 20000, "min_expiry_blocks": 500, "max_expiry_blocks": 8640}})).unwrap()
}

struct W {
    chain: Arc<MemChain>,
    node: Arc<Node>,
    net: Arc<MemNet>,
    hub: Arc<RouteHub>,
    provs: Vec<(String, Arc<Wrapped>)>,
    pay: Arc<RoutePayer>,
    signer: Arc<LocalSigner>,
    shards: Vec<Arc<Shard>>,
    _dir: TempDir,
}

impl W {
    fn new(n: usize) -> Self {
        Self::with_ch2_blocks(&vec![None; n])
    }

    fn with_ch2_blocks(blocks: &[Option<u32>]) -> Self {
        Self::build(blocks, 20, 300)
    }

    /// Providers that settle at `settle_multiple` x closeFee and charge `sat_per_call`.
    fn build(blocks: &[Option<u32>], settle_multiple: u64, sat_per_call: u128) -> Self {
        Self::build_with(blocks, settle_multiple, sat_per_call, hub_cfg(), |_| {})
    }

    /// The same, under hub config `cfg` and a client config `pc` may change.
    fn build_with(blocks: &[Option<u32>], settle_multiple: u64, sat_per_call: u128, hcfg: HubConfig, pc: impl FnOnce(&mut RoutePayerConfig)) -> Self {
        Self::build_full(blocks, settle_multiple, sat_per_call, hcfg, pc, true)
    }

    /// `depth` false: the hub's scan finds a spender and cannot say whether it is in a block.
    fn build_full(blocks: &[Option<u32>], settle_multiple: u64, sat_per_call: u128, hcfg: HubConfig, pc: impl FnOnce(&mut RoutePayerConfig), depth: bool) -> Self {
        let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
        let scan: Arc<dyn SpendScan> = if depth { chain.clone() } else { Arc::new(NoDepth(chain.clone())) };
        let node = Arc::new(Node { chain: chain.clone(), down: AtomicBool::new(false), strict: AtomicBool::new(false) });
        let hub = Arc::new(RouteHub::new(node.clone(), scan, Box::new(ChainWallet(chain.clone())), Box::new(NetTransport(net.clone())), sk(0x4B4B), NET,
                                         Some(&dir.0.join("hub")), hcfg).unwrap());
        net.add(HUB, hub.clone());
        let mut provs = vec![];
        for (i, b) in blocks.iter().enumerate() {
            let origin = format!("http://p{i}.test");
            provs.push((origin.clone(), provider(&chain, &net, &dir, &origin, settle_multiple, sat_per_call)));
            hub.connect(&origin, None, *b).unwrap();
        }
        chain.confirm_all();
        hub.watch_tick();
        let mut cfg = RoutePayerConfig::new(NET);
        cfg.expiry_blocks = 8_000;
        pc(&mut cfg);
        let c = chain.clone();
        let signer = Arc::new(LocalSigner::new());
        let pay = Arc::new(RoutePayer::new(HUB, cfg, signer.clone(), Arc::new(ChainWallet(chain.clone())), Box::new(NetTransport(net.clone())),
                                           Box::new(move || Ok(c.height()))));
        pay.open().unwrap();
        let shards = provs.iter().map(|(o, _)| pay.shard(&format!("{o}/v1/chunk"), "POST").unwrap()).collect();
        Self { chain, node, net, hub, provs, pay, signer, shards, _dir: dir }
    }

    fn st1(&self) -> ChannelState {
        self.hub.ch1_state(&self.pay.chan().unwrap()).unwrap()
    }

    fn st2(&self, i: usize) -> ChannelState {
        let p = &self.provs[i].1.inner;
        let all: Vec<ChannelState> = p.channel_ids().iter().filter_map(|c| p.channel_state(c)).collect();
        all.iter().find(|s| s.closed_txid.is_empty()).cloned().unwrap_or_else(|| all.last().unwrap().clone())
    }

    fn routed(&self) -> u64 {
        self.st1().extra.get("routed_sat").and_then(Value::as_u64).unwrap_or(0)
    }

    fn stale1(&self) -> Vec<Value> {
        self.st1().extra.get("stale_locks").and_then(Value::as_array).cloned().unwrap_or_default()
    }

    fn lock(&self, i: usize) -> Value {
        stream(&self.pay, &self.shards[i], 10);
        self.pay.lock(&self.shards[i]).unwrap().unwrap()
    }

    fn paid(&self, i: usize) {
        let r = self.lock(i);
        assert_eq!(r["status"], "paid", "{r}");
    }
}

fn stream(pay: &RoutePayer, sh: &Arc<Shard>, n: usize) {
    for _ in 0..n {
        let r = pay.call(sh, "POST", br#"{"tokens":1}"#).unwrap();
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    }
}

fn d_plus_f(lock: &Value) -> u64 {
    lock["d"].as_u64().unwrap() + lock["f"].as_u64().unwrap()
}

fn units(v: &Value) -> u128 {
    v.as_u64().map(u128::from).or_else(|| v.as_str().and_then(|s| s.parse().ok())).unwrap_or(0)
}

/// ch1's counters as the hub holds them: (routed, fee units, fee paid).
fn base1(w: &W) -> (u64, u128, u64) {
    let ex = w.st1().extra;
    let n = |k: &str| ex.get(k).cloned().unwrap_or(Value::Null);
    (n("routed_sat").as_u64().unwrap_or(0), units(&n("fee_units")), n("fee_paid").as_u64().unwrap_or(0))
}


impl W {
    fn origin(&self, i: usize) -> &str {
        &self.provs[i].0
    }

    fn oc(&self, i: usize) -> OutChannel {
        self.hub.out_channels()[self.origin(i)].clone()
    }

    fn events(&self, name: &str) -> Vec<Value> {
        self.hub.events.lock().unwrap().iter().filter(|e| e["event"] == name).cloned().collect()
    }

    /// p`i` (a colluding provider) names `lock_id` in its next invoice. The lockId of an invoice is
    /// the provider's to choose.
    fn invoice_lock_id(&self, i: usize, lock_id: &str) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
        let mut st = self.provs[i].1.inner.routes().lock();
        for s in st.sessions.values_mut() {
            s.lock_id = lock_id.to_string();
            s.valid_until = now + 8.0;
        }
    }

    /// p`i` takes a lock and keeps it without revealing: written off on its ch2 and held on ch1.
    fn held_lock(&self, i: usize) -> Value {
        self.provs[i].1.inner.set_no_reveal(true);
        let r = self.lock(i);
        assert_eq!((r["status"].as_str(), r["error"].as_str()), (Some("refused"), Some("route_failed")), "{r}");
        let held = self.stale1().pop().unwrap();
        assert!(held["hold"].is_object() && self.oc(i).stale.len() == 1, "control: written off on the ch2, held on ch1");
        held
    }

    /// Put the written-off lock `held` (of p`i`'s ch2) back where a hub that stopped mid-route
    /// leaves it: `route_lock` on ch1, nothing held, and pending on the ch2, which routes again.
    fn back_in_flight(&self, i: usize, held: &Value) {
        self.hub.inbound.with_state(&self.pay.chan().unwrap(), |st| {
            let mut rl = held.clone();
            let hold = rl["hold"].clone();
            rl.as_object_mut().unwrap().remove("hold");
            rl.as_object_mut().unwrap().remove("voided");
            for (k, a) in [("routed_sat", "routed"), ("fee_units", "units"), ("fee_paid", "paid")] {
                let cur = units(st.extra.get(k).unwrap_or(&Value::Null));
                st.extra.insert(k.into(), json!((cur - units(&hold[a])) as u64));
            }
            st.extra.insert("route_lock".into(), rl);
            st.extra.insert("stale_locks".into(), json!([]));
        }).unwrap();
        self.hub.with_out(|b| {
            let c = b.chans.get_mut(self.origin(i)).unwrap();
            let mut p = c.stale.remove(0);
            p.as_object_mut().unwrap().remove("voided");
            p.as_object_mut().unwrap().remove("why");
            c.pending = p.as_object().unwrap().clone();
            c.blocked = String::new();
        });
    }

    /// p`i` closes its ch2 on its own, at its best state.
    fn provider_closes(&self, i: usize) -> String {
        let st2 = self.st2(i);
        self.provs[i].1.inner.close_now(&st2.params.channel_id()).unwrap()
    }

    fn pending_anywhere(&self) -> usize {
        self.hub.out_channels().values().chain(self.hub.next_channels().values()).filter(|c| !c.pending.is_empty()).count()
            + self.hub.archived().iter().filter(|r| r["pending"].as_object().is_some_and(|p| !p.is_empty())).count()
    }
}

fn has(acts: &[Value], name: &str) -> bool {
    acts.iter().any(|a| a["event"] == name)
}

fn refused(r: &Value) {
    assert_eq!((r["status"].as_str(), r["error"].as_str()), (Some("refused"), Some("route_failed")), "{r}");
}

impl W {
    /// p`i` answers the hub's lock with a 400 after its inner provider completed it: it keeps the
    /// pre-signature and its t, and refuses the hub's close requests.
    fn keeps_locks(&self, i: usize) {
        self.provs[i].1.refuse.store(true, Ordering::SeqCst);
        self.provs[i].1.deaf.store(true, Ordering::SeqCst);
    }

    /// Lock toward p`i` until one is paid (a view adopted on the way counts as a try).
    fn pay_until_paid(&self, i: usize) -> Option<Value> {
        let mut last = None;
        for _ in 0..4 {
            stream(&self.pay, &self.shards[i], 10);
            last = self.pay.lock(&self.shards[i]).unwrap();
            if last.as_ref().is_some_and(|r| r["status"] == "paid") {
                break;
            }
        }
        last
    }
}

// --- Part B, `is_lock`: locks written before the `ch2` field existed ---------------------------------------
//
// A ch1 lock without `ch2` (a ledger written by f0554d0) is matched by its provider's ORIGIN. One
// origin can have two ch2s at once: the one a written-off lock blocks, and the one that replaced it
// (the next ch2 funded ahead, or the refill after the close request). f0554d0 admitted a second lock
// under a held lockId (no `lock_held` there), so a client and ONE provider could leave two held
// locks under one lockId on two ch2s of one origin. Loaded by d4c8328, both match either ch2.

/// Two written-off locks on one ch1 under one lockId, each over its own ch2 of the SAME provider.
/// `legacy`: as a hub from before AGP-088 wrote them (no `ch2` on the ch1 locks). Returns the
/// world, the first ch2 (archived, retired), the provider's state of it before the lock, the lockId.
fn two_held_locks_on_two_ch2s_of_one_provider(legacy: bool) -> (W, OutChannel, ChannelState, String) {
    let w = W::build_with(&[None], 20, 300, hub_cfg(), |c| c.held_probe_secs = 0.0);
    w.paid(0);
    let origin = w.origin(0).to_string();
    w.hub.connect_next(&origin, None, None).unwrap();
    w.chain.confirm_all();
    w.hub.watch_tick();
    assert_eq!(w.hub.next_channels()[&origin].state, "open", "control: the next ch2 is open");
    let a = w.oc(0);
    let before = w.provs[0].1.inner.channel_state(&a.params.channel_id()).unwrap();
    w.keeps_locks(0);
    refused(&w.lock(0));
    let lid = w.stale1()[0]["lockId"].as_str().unwrap().to_string();
    // the watcher gives the provider that refused its next ch2; the first one is archived with its lock
    let acts = w.hub.watch_tick();
    let b = w.oc(0);
    assert!(b.params.payer_pub != a.params.payer_pub && b.state == "open", "control: the next ch2 took over: {acts:?}");
    refused(&w.lock(0));
    assert_eq!(w.oc(0).stale.len(), 1, "control: the second lock is written off on the second ch2");
    // the second lock under the first one's lockId, as f0554d0 admitted it (cf. agp087_hub_a.rs)
    w.hub.inbound.with_state(&w.pay.chan().unwrap(), |st| {
        st.extra["stale_locks"][1]["lockId"] = lid.as_str().into();
        if legacy {
            for s in st.extra["stale_locks"].as_array_mut().unwrap() {
                s.as_object_mut().unwrap().remove("ch2");
            }
        }
    }).unwrap();
    w.hub.with_out(|bk| bk.chans[origin.as_str()].stale[0]["lockId"] = lid.as_str().into());
    let stale = w.stale1();
    assert!(stale.len() == 2 && stale.iter().all(|s| s["lockId"] == lid.as_str() && s["hold"].is_object() && s["provider"] == origin.as_str()),
            "control: one lockId, one provider, both held: {stale:?}");
    assert!(stale.iter().all(|s| s.get("ch2").is_none() == legacy));
    assert_eq!(w.pay.close().unwrap_err().code, "lock_pending", "control: ch1 cannot close below the two locks");
    (w, a, before, lid)
}

/// The provider closes its first ch2 at the state before the lock (no t), that close confirms; then
/// the client closes ch1 and the provider closes its second ch2 with the pre-signature it kept.
/// Returns (written-off locks left on ch1 after the first close, ch1's close, what ch1 collected,
/// the lock the second ch2 paid).
fn first_ch2_closes_without_t(w: &W, a: &OutChannel, before: &ChannelState) -> (usize, Result<Value, xbt402::ChannelError>, u64, u64) {
    let (prov, chan_a) = (&w.provs[0].1.inner, a.params.channel_id());
    prov.with_state(&chan_a, |st| *st = before.clone()).unwrap();
    let c0 = prov.close_now(&chan_a).unwrap();
    w.hub.watch_tick();
    w.chain.mine(1);
    assert!(w.chain.confirmed(&c0));
    let mut acts = w.hub.watch_tick();
    acts.extend(w.hub.watch_tick());
    assert!(acts.iter().any(|x| x["event"] == "lock_released" && x["held"] == true), "control: the first ch2's lock is released: {acts:?}");
    let left = w.stale1().len();
    let unresolved = w.oc(0).stale.len();
    assert_eq!(unresolved, 1, "control: the second ch2 still holds its written-off lock, its pre-signature is out");
    let lock_cum = w.oc(0).stale[0]["cum"].as_u64().unwrap();
    let lock_d = w.oc(0).stale[0]["d"].as_u64().unwrap();
    let closed = w.pay.close();
    let chan_b = w.oc(0).params.channel_id();
    prov.close_now(&chan_b).unwrap();
    w.hub.watch_tick();
    w.chain.mine(1);
    w.hub.watch_tick();
    assert_eq!(prov.channel_state(&chan_b).unwrap().best_cum, lock_cum, "control: the second ch2 closed at the lock's state");
    (left, closed, w.st1().best_cum, lock_d)
}

#[test]
fn with_the_ch2_field_the_lock_of_the_unresolved_ch2_stays_on_ch1() {
    // control: the same pair written by d4c8328 (each lock names its ch2)
    let (w, a, before, _) = two_held_locks_on_two_ch2s_of_one_provider(false);
    let (left, closed, _, _) = first_ch2_closes_without_t(&w, &a, &before);
    assert_eq!((left, closed.map_err(|e| e.code)), (1, Err("lock_pending".to_string())));
    assert!(w.stale1().is_empty(), "the second ch2's close showed t and completed its lock on ch1");
}

#[test]
fn hole_two_locks_from_a_ledger_before_agp088_to_one_provider_are_released_together() {
    let (w, a, before, lid) = two_held_locks_on_two_ch2s_of_one_provider(true);
    let held: Vec<u64> = w.stale1().iter().map(d_plus_f).collect();
    let (left, closed, collected, lock_d) = first_ch2_closes_without_t(&w, &a, &before);
    assert!(left == 1 && closed.is_err(),
            "the first ch2 closed without t and {} of the 2 locks under lockId {lid} left ch1 (holds of {held:?} sat given back); ch1 then closed ({}) \
             at {collected} sat, and the second ch2 paid its lock of {lock_d} sat with the pre-signature the provider kept: {lock_d} sat uncollected",
            2 - left, closed.as_ref().map(|c| c.to_string()).unwrap_or_else(|e| e.code.clone()));
}

// --- Part B, "spent in a block": one block deep ---------------------------------------------------------------

#[test]
fn hole_a_lock_released_on_a_close_one_block_deep_is_lost_when_that_block_is_reorged() {
    // The provider's close of its ch2 at the state before a written-off lock is one block deep: the
    // hub releases the hold, makes the ch2 record final and never looks at that funding again. The
    // block is replaced by one that carries the provider's other close, with the pre-signature and t.
    let w = W::new(1);
    w.paid(0);
    let (prov, chan2) = (&w.provs[0].1.inner, w.oc(0).params.channel_id());
    let s0 = prov.channel_state(&chan2).unwrap();
    w.keeps_locks(0);
    refused(&w.lock(0));
    let held = w.stale1()[0].clone();
    let s1 = prov.channel_state(&chan2).unwrap();
    assert!(s1.best_cum > s0.best_cum, "control: the provider holds the lock's state and its t");
    prov.with_state(&chan2, |st| *st = s0.clone()).unwrap();
    let c0 = prov.close_now(&chan2).unwrap();
    w.hub.watch_tick();
    assert_eq!((w.stale1().len(), w.oc(0).state.as_str()), (1, "closing"), "control: in the mempool nothing is released");
    w.chain.mine(1);
    let mut acts = w.hub.watch_tick();
    acts.extend(w.hub.watch_tick());
    let oc = w.oc(0);
    assert!(has(&acts, "lock_released") && oc.final_ && oc.state == "closed", "control: one block deep, released and final: {acts:?}");
    let closed = w.pay.close();
    // the reorg: c0's block is gone, the new block has the close with t
    w.chain.unconfirm(&c0);
    w.chain.evict(&c0);
    prov.with_state(&chan2, |st| *st = s1.clone()).unwrap();
    let c1 = prov.close_now(&chan2).unwrap();
    assert_ne!(c0, c1);
    w.chain.mine(6);
    let mut acts = w.hub.watch_tick();
    acts.extend(w.hub.watch_tick());
    assert_eq!(w.chain.spender(&oc.params.funding_txid(), oc.params.funding_vout()).as_deref(), Some(c1.as_str()), "control: the close with t is the one in the chain");
    let (collected, lock_cum, d) = (w.st1().best_cum, held["cum"].as_u64().unwrap(), held["d"].as_u64().unwrap());
    assert!(collected >= lock_cum,
            "the hub paid the lock of {d} sat on its ch2 (close {c1} at {} sat, six blocks deep) and ch1 closed ({}) at {collected} sat, below the lock's {lock_cum}: \
             after the reorg the hub did nothing ({acts:?}), its ch2 record is final at close {}",
            s1.best_cum, closed.as_ref().map(|c| c.to_string()).unwrap_or_else(|e| e.code.clone()), w.oc(0).close_txid);
}

// --- Part B, `max_held_locks`: who empties it ------------------------------------------------------------------

#[test]
fn hole_a_held_lock_completed_below_the_best_state_still_counts_against_max_held_locks() {
    // Default client config (max_held_locks 2). Two providers keep a lock each; both then close
    // their ch2 with t, the later lock first. The hub completes both and holds nothing. The client
    // learns of the first completion (it is the hub's best state, with its secret) and never of the
    // second (below the best state: no view shows it), so that lock stays "held" at the client for
    // the life of ch1. One more real hold and the client is at its cap with ONE lock held.
    let w = W::build_with(&[None, None, None, None], 20, 300, hub_cfg(), |c| c.held_probe_secs = 0.0);
    w.paid(3);
    for i in [0, 1] {
        w.keeps_locks(i);
        refused(&w.lock(i));
    }
    assert_eq!(w.stale1().len(), 2, "control: two locks held");
    w.provider_closes(1);
    assert!(w.hub.watch_tick().iter().any(|a| a["event"] == "secret_from_close" && a["ch1_completed"] == true));
    let r = w.pay_until_paid(3);
    assert_eq!(r.as_ref().map(|r| r["status"].clone()), Some(json!("paid")), "control: the completion is adopted and p3 is paid above one hold: {r:?}");
    w.provider_closes(0);
    assert!(w.hub.watch_tick().iter().any(|a| a["event"] == "secret_from_close" && a["ch1_completed"] == true));
    assert!(w.stale1().is_empty(), "control: the hub holds no lock on ch1");
    let r = w.pay_until_paid(3);
    assert_eq!(r.as_ref().map(|r| r["status"].clone()), Some(json!("paid")), "control: {r:?}");
    // one provider keeps a lock: the hub holds ONE lock, the client's cap is two
    w.keeps_locks(2);
    refused(&w.lock(2));
    assert_eq!(w.stale1().len(), 1, "control: one lock held");
    let (routes, views) = (w.net.count("/x402/route"), w.net.count(HUB_VIEW_PATH));
    let r = w.pay_until_paid(3);
    assert_eq!(r.as_ref().map(|r| r["status"].clone()), Some(json!("paid")),
               "the hub holds 1 lock and max_held_locks is {}: the client signed nothing for p3 ({} lock requests, {} view requests in 4 tries); \
                the lock p0 completed below the best state is still held at the client",
               RoutePayerConfig::new(NET).max_held_locks, w.net.count("/x402/route") - routes, w.net.count(HUB_VIEW_PATH) - views);
}

// --- Part B, `liquidity_cap_sat` counts archived ch2s: the check that still subtracts one ------------------------

#[test]
fn hole_a_ch2_replaced_because_its_pay_to_changed_is_funded_past_the_liquidity_cap() {
    // `committed` now counts a ch2 that moved to the archive until this node shows it spent. The
    // cap check in `fund_ch2` still takes the replaced ch2's capacity off ("freed") when the
    // provider's /terms name another payTo. The provider changes its payTo; connect() funds a second
    // ch2 while the first is open and unspent, and nobody asks for its close (it is not `retired`).
    let mut cfg = hub_cfg();
    cfg.liquidity_cap_sat = 100_000;
    let w = W::build_with(&[None], 20, 300, cfg, |_| {});
    w.paid(0);
    let old = w.oc(0);
    assert_eq!(w.hub.committed_sat(), 100_000, "control: at the cap");
    assert_eq!(w.hub.connect_next(w.origin(0), None, None).unwrap_err().code, "liquidity_cap", "control: the cap refuses a second ch2");
    *w.provs[0].1.pay_to.lock().unwrap() = Some(hex::encode(xbt_primitives::ecdsa::pubkey(&sk(0x7777))));
    let r = w.hub.connect(w.origin(0), None, None).map(|c| c.state).map_err(|e| e.code);
    for _ in 0..3 {
        w.hub.watch_tick();
    }
    let unspent = w.chain.get_tx_out(&old.params.funding_txid(), old.params.funding_vout(), true).unwrap().is_some();
    let rec = w.hub.archived().into_iter().find(|r| r["params"]["payer_pub"] == hex::encode(old.params.payer_pub));
    assert!(w.hub.committed_sat() <= 100_000,
            "connect answered {r:?}: {} sat committed under a cap of 100000; the first ch2 is unspent ({unspent}), archived as {:?}, retired {:?}, \
             and {} close requests went to the provider",
            w.hub.committed_sat(), rec.as_ref().map(|r| r["state"].clone()), rec.as_ref().map(|r| r["retired"].clone()), w.net.count(CLOSE_PATH));
}

// --- list 1 item 2, the step the second audit had from reading: the conflicting close is mined instead ---------

#[test]
fn a_mempool_close_of_an_unconfirmed_child_replaced_by_the_close_with_t_is_collected() {
    // A lock is written off on an unconfirmed rollover child. The provider sends a close of the
    // child at the state before the lock; with nothing in a block the hub releases nothing. That
    // close then leaves the mempool for the provider's other close, with the pre-signature it kept:
    // the hub reads t off it and completes the lock on ch1.
    let w = W::build_full(&[None], 2, 40, hub_cfg(), |_| {}, true);
    w.node.strict.store(true, Ordering::SeqCst);
    let lock = |calls: usize| {
        stream(&w.pay, &w.shards[0], calls);
        w.pay.lock(&w.shards[0]).unwrap().unwrap()
    };
    assert_eq!(lock(50)["status"], "paid");
    assert!(has(&w.hub.watch_tick(), "ch2_rollover"));
    let child = w.oc(0);
    assert!(child.state == "open" && child.zero_conf_pending(), "control: an unconfirmed child");
    assert_eq!(lock(5)["status"], "paid");
    let (prov, chan2) = (&w.provs[0].1.inner, child.params.channel_id());
    let s0 = prov.channel_state(&chan2).unwrap();
    w.keeps_locks(0);
    refused(&lock(40));
    let held = w.stale1()[0].clone();
    let s1 = prov.channel_state(&chan2).unwrap();
    assert!(s1.best_cum > s0.best_cum && w.oc(0).zero_conf_pending(), "control: the provider holds a state above the last paid one, on an unconfirmed child");
    prov.with_state(&chan2, |st| *st = s0.clone()).unwrap();
    let c0 = prov.close_now(&chan2).unwrap();
    for _ in 0..2 {
        let acts = w.hub.watch_tick();
        assert!(!has(&acts, "lock_released") && !has(&acts, "ch2_closed"), "{acts:?}");
    }
    assert_eq!((w.stale1().len(), w.pay.close().map_err(|e| e.code)), (1, Err("lock_pending".to_string())), "held while nothing is in a block");
    w.chain.evict(&c0);
    prov.with_state(&chan2, |st| *st = s1.clone()).unwrap();
    let c1 = prov.close_now(&chan2).unwrap();
    assert_ne!(c0, c1);
    let mut acts = w.hub.watch_tick();
    w.chain.mine(1);
    acts.extend(w.hub.watch_tick());
    assert!(acts.iter().any(|a| a["event"] == "secret_from_close" && a["ch1_completed"] == true), "{acts:?}");
    assert_eq!((w.st1().best_cum, w.stale1().len()), (held["cum"].as_u64().unwrap(), 0), "the hub collected the lock it paid");
}
