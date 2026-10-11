//! AGP-088 (fix wave 4, hub): tests of the fixes to the second closure audit's hub items, for the
//! parts the audit described from reading or that sit one step beside its own tests
//! (`agp087_hub_a.rs`, `agp087_hub_b.rs`).
//!
//! The harness is `agp087_hub_a.rs`'s, with two more switches on the provider as the hub sees it
//! (`pay_to`: its /terms name another payTo and its preflight says yes; `fake_close`: it answers
//! the hub's close request with a close it never sends).
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
        let p = std::env::temp_dir().join(format!("xbt-rs-agp088-hub-{}", hex::encode(&sha256(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes())[..8])));
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

// --- item 1: one unresolved lock per lockId on a ch1 --------------------------------------------------------

#[test]
fn a_lock_under_a_lock_id_ch1_holds_written_off_is_refused() {
    // The audit's steps for two written-off locks under one lockId: p0's lock is written off and
    // held, then p1 names the same lockId in its invoice. The hub now refuses that lock before it
    // pre-signs anything on p1's ch2, and tells the client what it holds.
    let w = W::new(2);
    w.paid(1);
    w.provs[0].1.refuse.store(true, Ordering::SeqCst);
    let r = w.lock(0);
    assert_eq!(r["error"], "route_failed", "{r}");
    let lid = w.stale1()[0]["lockId"].as_str().unwrap().to_string();
    let (base, sent) = (base1(&w), w.net.count(ROUTE_LOCK_PATH));
    w.invoice_lock_id(1, &lid);
    let r = w.lock(1);
    assert_eq!((r["status"].as_str(), r["error"].as_str()), (Some("refused"), Some("lock_held")), "{r}");
    assert_eq!(w.net.count(ROUTE_LOCK_PATH), sent, "nothing went to p1");
    let oc1 = w.oc(1);
    assert!(oc1.pending.is_empty() && oc1.stale.is_empty(), "nothing was pre-signed on p1's ch2");
    assert_eq!((w.stale1().len(), base1(&w)), (1, base), "ch1 holds the one lock, as before");
    let c = w.pay.counters();
    assert_eq!((c.0, c.1, c.2), base, "the client's counters are the hub's");
    // p1's next invoice has a lockId of its own: paid, above the held lock
    stream(&w.pay, &w.shards[1], 3);
    w.provs[1].1.inner.routes().lock().sessions.values_mut().for_each(|s| s.valid_until = 0.0);
    stream(&w.pay, &w.shards[1], 3);
    let r = w.pay.lock(&w.shards[1]).unwrap().unwrap();
    assert_eq!(r["status"], "paid", "{r}");
    assert!(w.st1().best_cum > w.stale1()[0]["cum"].as_u64().unwrap());
}

// --- item 2: "in a block" is never read off gettxout answering nothing ---------------------------------------

/// A lock written off on an unconfirmed rollover child whose provider then closes the child at
/// the state before the lock. `depth`: the hub's scan says how deep a spender is (bitcoind's does).
fn hold_on_an_unconfirmed_child(depth: bool) {
    let w = W::build_full(&[None], 2, 40, hub_cfg(), |_| {}, depth);
    w.node.strict.store(true, Ordering::SeqCst); // gettxout as a node answers it, whatever MemChain does
    let origin = w.origin(0).to_string();
    let lock = |calls: usize| {
        stream(&w.pay, &w.shards[0], calls);
        w.pay.lock(&w.shards[0]).unwrap().unwrap()
    };
    assert_eq!(lock(50)["status"], "paid");
    assert!(has(&w.hub.watch_tick(), "ch2_rollover"));
    let child = w.oc(0);
    assert!(child.state == "open" && child.zero_conf_pending(), "control: an unconfirmed child");
    assert_eq!(lock(5)["status"], "paid");
    w.provs[0].1.inner.set_no_reveal(true);
    assert_eq!(lock(5)["error"], "route_failed");
    let routed = w.routed();
    let close = w.provs[0].1.inner.close_now(&child.params.channel_id()).unwrap();
    for _ in 0..2 {
        let acts = w.hub.watch_tick();
        assert!(!has(&acts, "lock_released") && !has(&acts, "ch2_closed"), "depth {depth}: {acts:?}");
    }
    let oc = w.oc(0);
    assert_eq!((oc.state.as_str(), oc.final_, w.stale1().len(), w.routed()), ("closing", false, 1, routed), "depth {depth}: nothing is in a block");
    // the rollover and the close confirm: the close did not show t, so the lock was not paid
    w.chain.confirm_all();
    assert!(w.chain.confirmed(&close));
    let mut acts = w.hub.watch_tick();
    acts.extend(w.hub.watch_tick());
    assert!(acts.iter().any(|a| a["event"] == "lock_released" && a["held"] == true), "depth {depth}: {acts:?}");
    let oc = w.hub.archived().into_iter().chain(w.hub.out_channels().values().map(OutChannel::to_json))
        .find(|r| r["params"]["payer_pub"] == hex::encode(child.params.payer_pub)).unwrap();
    assert_eq!((oc["state"].as_str(), oc["final"].as_bool(), w.stale1().len()), (Some("closed"), Some(true), 0), "depth {depth}: {origin}");
    assert!(w.routed() < routed, "the hold left ch1's base");
}

#[test]
fn a_hold_on_an_unconfirmed_child_is_released_once_its_close_is_in_a_block() {
    hold_on_an_unconfirmed_child(true);
}

#[test]
fn the_same_with_a_scan_that_does_not_say_how_deep_a_spender_is() {
    // the hub then needs an output of the close in the node's confirmed set (the child's funding
    // was never seen confirmed and unspent)
    hold_on_an_unconfirmed_child(false);
}

// --- item 12: a rolled ch2 stays watched; a refill waits for the chain ---------------------------------------

#[test]
fn a_rolled_ch2_is_watched_until_its_rollover_is_in_a_block() {
    let w = W::build(&[None], 2, 40);
    let parent = w.oc(0);
    stream(&w.pay, &w.shards[0], 50);
    assert_eq!(w.pay.lock(&w.shards[0]).unwrap().unwrap()["status"], "paid");
    assert!(has(&w.hub.watch_tick(), "ch2_rollover"));
    let rec = |w: &W| w.hub.archived().into_iter().find(|r| r["params"]["payer_pub"] == hex::encode(parent.params.payer_pub)).unwrap();
    w.hub.watch_tick();
    let r = rec(&w);
    assert_eq!((r["state"].as_str(), r["final"].as_bool(), xbt402::hub::watched(&r)), (Some("rolled"), Some(false), true), "in the mempool: still watched");
    w.chain.confirm_all();
    w.hub.watch_tick();
    let r = rec(&w);
    assert_eq!((r["state"].as_str(), r["final"].as_bool(), xbt402::hub::watched(&r)), (Some("rolled"), Some(true), false), "in a block: done");
    assert_eq!(w.hub.committed_sat(), w.oc(0).params.capacity, "the coins are counted once, in the child");
}

#[test]
fn the_refill_follows_a_close_once_this_node_shows_it() {
    // the provider answers the hub's close with a close it has not sent. No refill is funded on
    // that answer; it is funded when the hub's own node shows the funding spent, within the cap
    let mut cfg = hub_cfg();
    cfg.liquidity_cap_sat = 100_000; // one ch2
    let w = W::build_with(&[None], 20, 300, cfg, |_| {});
    w.paid(0);
    let oc = w.oc(0);
    *w.provs[0].1.fake_close.lock().unwrap() = Some(("ab".repeat(32), oc.signed, oc.params.payee_fee()));
    let ev = w.hub.close_ch2(&oc, true).unwrap();
    assert!(ev["refillError"].as_str().is_some_and(|e| e.starts_with("deferred")), "the refill was funded on the provider's word: {ev}");
    for _ in 0..2 {
        w.hub.watch_tick();
    }
    let cur = w.oc(0);
    assert_eq!((cur.params.payer_pub, cur.state.as_str(), w.hub.committed_sat()), (oc.params.payer_pub, "closing", 100_000), "its coins still count");
    assert_eq!(w.hub.connect(w.origin(0), None, None).unwrap_err().code, "liquidity_cap", "and nobody funds past the cap meanwhile");
    // the provider closes after all: this node shows it, and the refill follows
    *w.provs[0].1.fake_close.lock().unwrap() = None;
    let close = w.provider_closes(0);
    let acts = w.hub.watch_tick();
    assert!(acts.iter().any(|a| a["event"] == "ch2_closing" && a["txid"] == close.as_str()), "{acts:?}");
    assert!(acts.iter().any(|a| a["event"] == "ch2_refill" && a.get("refillError").is_none()), "{acts:?}");
    let new = w.oc(0);
    assert!(new.params.payer_pub != oc.params.payer_pub && new.state == "funded", "{}", new.state);
    assert_eq!(w.hub.committed_sat(), 100_000, "the old ch2's coins are leaving, the new one's count");
    w.chain.confirm_all();
    w.hub.watch_tick();
    assert_eq!(w.events("ch2_refill").len(), 1, "once");
}

// --- item 13: what the routed client believes of its hub -----------------------------------------------------

#[test]
fn a_completion_the_hub_claims_is_adopted_only_with_the_secret_that_opens_the_lock() {
    // a lock the hub refused outright, then a view that says its best state is that lock: exactly
    // what a hub that completed it says, and what one that only wants the client's next lock quoted
    // a lock higher says too. Only the first can show t + r
    let w = W::new(1);
    w.paid(0);
    w.hub.with_out(|b| b.chans.get_mut(w.origin(0)).unwrap().blocked = "closed for the test".into());
    let c0 = w.pay.counters();
    let r = w.lock(0);
    assert_eq!((r["status"].as_str(), r["error"].as_str()), (Some("refused"), Some("route_blocked")), "{r}");
    let cum = w.pay.last_given_up().unwrap();
    let d = w.pay.events.lock().unwrap().iter().rev().find(|e| e["event"] == "void").unwrap()["amount"].as_u64().unwrap();
    let (f, total) = fee_due(&w.pay.quote().unwrap(), d, c0.1, c0.2);
    let claim = json!({"bestCum": cum, "routedSat": c0.0 + d + f, "feeUnits": total.to_string(), "feePaid": c0.2 + f, "held": [], "released": []});
    assert!(cum > c0.3, "control: the lock was signed above the last paid state");
    assert!(!w.pay.try_resync(&claim), "a completion was adopted on the hub's word");
    let mut wrong = claim.clone();
    wrong["secret"] = hex::encode(sk(0x1234).secret_bytes()).into();
    assert!(!w.pay.try_resync(&wrong), "a completion was adopted with a secret that does not open the lock");
    assert_eq!(w.pay.counters(), c0, "nothing moved");
}

#[test]
fn at_max_held_locks_nothing_more_is_signed_until_the_view_shows_a_hold_resolved() {
    let w = W::build_with(&[Some(600), None], 20, 300, hub_cfg(), |c| (c.max_held_locks, c.held_probe_secs) = (1, 0.0));
    w.paid(1);
    w.provs[0].1.refuse.store(true, Ordering::SeqCst);
    w.provs[0].1.deaf.store(true, Ordering::SeqCst);
    assert_eq!(w.lock(0)["error"], "route_failed");
    let (signed, held) = (w.pay.counters(), w.stale1()[0].clone());
    assert_eq!(signed.0, base1(&w).0, "control: the one hold is adopted");
    // p1 is owed, and nothing is pre-signed for it above the hold
    stream(&w.pay, &w.shards[1], 10);
    let routes = w.net.count("/x402/route");
    for _ in 0..3 {
        assert!(w.pay.lock(&w.shards[1]).unwrap().is_none());
    }
    assert_eq!((w.net.count("/x402/route"), w.pay.counters()), (routes, signed), "a lock was sent at the cap");
    assert!(w.net.count(HUB_VIEW_PATH) >= 3 && w.signer.void_lock(&w.pay.chan().unwrap()).is_ok_and(|v| !v), "it asked for the view, and holds no pre-signature");
    // p0's ch2 is refunded: the hold is released, the view says so, and p1 is paid
    w.chain.set_height(w.oc(0).params.expiry + 10);
    w.hub.watch_tick();
    w.chain.confirm_all();
    assert!(has(&w.hub.watch_tick(), "lock_released"));
    assert_eq!(w.pay.lock(&w.shards[1]).unwrap().unwrap()["status"], "resynced");
    assert_eq!(w.pay.counters().0, signed.0 - d_plus_f(&held));
    stream(&w.pay, &w.shards[1], 3);
    assert_eq!(w.pay.lock(&w.shards[1]).unwrap().unwrap()["status"], "paid");
    let c = w.pay.counters();
    assert_eq!((c.0, c.1, c.2), base1(&w));
}

#[test]
fn the_view_is_answered_to_ch1s_own_auth_and_spends_its_seq() {
    let w = W::new(1);
    w.paid(0);
    let chan = w.pay.chan().unwrap();
    let ask = |seq: u64, accepted: &Value, key_of: &str| {
        let url = format!("{HUB}{HUB_VIEW_PATH}");
        let auth = w.signer.request_auth(key_of, Some(&json!(seq)), Some(&json!("0")), None, &request_digest_v2("POST", &url, b"")).unwrap();
        let hdr = b64json(&json!({"x402Version": 2, "accepted": accepted, "payload": {"chan": chan, "seq": seq, "cum": "0", "auth": auth}}));
        let r = HttpService::serve(&*w.hub, "POST", HUB_VIEW_PATH, &[("PAYMENT-SIGNATURE".into(), hdr)], b"", &url);
        (r.status, serde_json::from_slice::<Value>(&r.body).unwrap_or(Value::Null))
    };
    let (seq, accepted) = w.pay.next_seq().unwrap();
    let (st, doc) = ask(seq, &accepted, &chan);
    let st1 = w.st1();
    assert_eq!((st, doc["bestCum"].as_u64(), doc["routedSat"].as_u64()), (200, Some(st1.best_cum), Some(w.routed())), "{doc}");
    assert_eq!(doc["secret"].as_str().map(str::len), Some(64), "the proof of the lock at its best state: {doc}");
    assert_eq!(ask(seq, &accepted, &chan).0, 401, "the same seq again");
    assert_eq!(w.st1().seq, seq, "and that seq is on disk");
    let r = HttpService::serve(&*w.hub, "POST", HUB_VIEW_PATH, &[], b"", &format!("{HUB}{HUB_VIEW_PATH}"));
    assert_eq!(r.status, 400);
}

// --- item 19: the smaller leftovers ----------------------------------------------------------------------------

#[test]
fn once_the_kept_intents_are_full_no_request_moves_the_state() {
    // The audit's closes one sat apart, then the two other ways a payer raises the state while the
    // hub's node refuses broadcasts: /x402/verify, and the watcher's own close after it
    let w = W::new(1);
    w.paid(0);
    let chan = w.pay.chan().unwrap();
    w.node.down.store(true, Ordering::SeqCst);
    let close = |cum: u64| {
        let sig = w.signer.sign_state(&chan, cum).unwrap();
        let body = json!({"chan": chan, "sig": hex::encode(w.signer.sign_close(&chan).unwrap()), "payload": {"chan": chan, "cum": cum.to_string(), "sig": hex::encode(sig)}});
        HttpService::serve(&*w.hub, "POST", CLOSE_PATH, &[], body.to_string().as_bytes(), &format!("{HUB}{CLOSE_PATH}"));
    };
    for _ in 0..12 {
        close(w.st1().best_cum + 1);
    }
    let st1 = w.st1();
    let kept = |st: &ChannelState| st.extra.get("close_intents").and_then(Value::as_array).map(Vec::len).unwrap_or(0);
    assert_eq!(kept(&st1), MAX_KEPT_INTENTS - 1, "one slot is left for the payee's own close");
    let (best, latest) = (st1.best_cum, st1.extra["close_intent"]["txid"].as_str().unwrap().to_string());
    let accepted = w.pay.next_seq().unwrap().1;
    let sig = hex::encode(w.signer.sign_state(&chan, best + 5).unwrap());
    let body = json!({"x402Version": 2, "paymentPayload": {"x402Version": 2, "accepted": accepted, "payload": {"chan": chan, "cum": (best + 5).to_string(), "sig": sig}},
                      "paymentRequirements": accepted});
    HttpService::serve(&*w.hub, "POST", "/x402/verify", &[], body.to_string().as_bytes(), &format!("{HUB}/x402/verify"));
    assert_eq!(w.st1().best_cum, best, "/x402/verify raised the state under a full set of unresolved closes");
    for _ in 0..3 {
        let _ = w.hub.inbound.close_due();
    }
    assert_eq!(kept(&w.st1()), MAX_KEPT_INTENTS - 1, "the watcher's close made another");
    // the node is back: the watcher's close is the one written ahead last
    w.node.down.store(false, Ordering::SeqCst);
    assert_eq!(w.hub.inbound.close_due().unwrap(), vec![latest.clone()]);
    assert_eq!((w.st1().closed_txid, w.st1().best_cum), (latest, best));
}

#[test]
fn a_stop_between_the_ch1_release_and_the_ch2_record_is_finished_by_the_next_tick() {
    // The release wrote the ch2 record first and ch1 second: a stop between them left ch1 holding a
    // lock that no ch2 record named any more, for good. Now ch1 goes first and the record is final
    // last, so the same stop leaves a ch2 the next tick finishes, and nothing is given back twice.
    let w = W::with_ch2_blocks(&[Some(600)]);
    w.paid(0);
    let base = base1(&w);
    w.provs[0].1.refuse.store(true, Ordering::SeqCst);
    w.provs[0].1.deaf.store(true, Ordering::SeqCst);
    assert_eq!(w.lock(0)["error"], "route_failed");
    assert!(base1(&w).0 > base.0);
    w.chain.set_height(w.oc(0).params.expiry + 10);
    assert!(has(&w.hub.watch_tick(), "ch2_refund"));
    w.chain.confirm_all();
    w.hub.set_stop("release");
    w.hub.watch_tick();
    let oc = w.oc(0);
    assert_eq!((w.stale1().len(), base1(&w), oc.stale.len(), oc.final_), (0, base, 1, false), "stopped after ch1, before the ch2 record");
    w.hub.set_stop("");
    w.hub.watch_tick();
    w.hub.watch_tick();
    let oc = w.oc(0);
    assert_eq!((oc.state.as_str(), oc.stale.len(), oc.final_), ("refunded", 0, true));
    assert_eq!((w.stale1().len(), base1(&w), w.events("lock_released").len()), (0, base, 1), "released once");
    assert!(w.pay.close().is_ok(), "nothing unresolved keeps ch1 open");
}

#[test]
fn a_lock_pending_on_a_ch2_that_is_closing_is_written_off_and_resolved() {
    // The hub stops with a lock in flight; when it is back the provider's close of that ch2, at the
    // state before the lock, is in the mempool. The watcher asks again for a pending lock only on an
    // open ch2, so nobody wrote this one off: ch1 kept its lock in flight (no route, no close) until
    // its margin, and the ch2 ended final with the lock still pending.
    let w = W::new(1);
    w.paid(0);
    let (base, held) = (base1(&w), w.held_lock(0));
    w.back_in_flight(0, &held);
    assert_eq!((base1(&w), w.oc(0).pending.is_empty()), (base, false), "control: in flight, nothing held");
    let close = w.provider_closes(0);
    let mut acts = w.hub.watch_tick();
    acts.extend(w.hub.watch_tick());
    assert!(has(&acts, "ch2_closing") && has(&acts, "lock_written_off"), "{acts:?}");
    let (oc, stale) = (w.oc(0), w.stale1());
    assert!(oc.pending.is_empty() && oc.stale.len() == 1 && stale.len() == 1 && stale[0]["hold"].is_object(), "written off on the ch2, held on ch1: {stale:?}");
    assert_eq!((base1(&w).0, w.st1().extra["route_lock"].is_null()), (base.0 + d_plus_f(&held), true));
    assert_eq!(w.pay.close().unwrap_err().code, "lock_pending", "its pre-signature may be out: ch1 does not close below it");
    // the close confirms without t: the lock was not paid
    w.chain.confirm_all();
    assert!(w.chain.confirmed(&close));
    let acts = w.hub.watch_tick();
    assert!(acts.iter().any(|a| a["event"] == "lock_released" && a["held"] == true), "{acts:?}");
    let oc = w.oc(0);
    assert_eq!((oc.state.as_str(), oc.final_, oc.pending.is_empty(), w.stale1().len(), base1(&w)), ("closed", true, true, 0, base));
    assert!(w.pay.close().is_ok(), "nothing unresolved keeps ch1 open");
}

#[test]
fn a_ch2_with_a_lock_pending_is_not_replaced_when_its_pay_to_changes() {
    // connect() (an embedder's refill, an operator) with the provider's /terms now naming another
    // payTo archived the origin's ch2 whatever it carried. With a lock pending on it the route that
    // sent the lock no longer found it, and the sweep took ch1's lock for an orphan and dropped it
    // while the ch2 pre-signature was out.
    let w = W::new(1);
    w.paid(0);
    let held = w.held_lock(0);
    w.back_in_flight(0, &held);
    let oc = w.oc(0);
    *w.provs[0].1.pay_to.lock().unwrap() = Some(hex::encode(xbt_primitives::ecdsa::pubkey(&sk(0x7777))));
    let r = w.hub.connect(w.origin(0), None, None);
    assert_eq!(r.map(|c| c.state).unwrap_err().code, "lock_pending");
    let cur = w.oc(0);
    assert!(cur.params.payer_pub == oc.params.payer_pub && !cur.pending.is_empty() && w.hub.archived().is_empty(), "the ch2 kept its place and its lock");
    w.hub.watch_tick();
    assert!(!w.st1().extra["route_lock"].is_null() || w.stale1().len() == 1, "ch1's lock was dropped as an orphan");
}

#[test]
fn a_next_ch2_does_not_take_over_from_under_a_pending_lock() {
    // the same through the switch: the live ch2 is closing (the provider's close is in the mempool)
    // with a lock pending, and the origin's next ch2 is open. It takes over only once that lock is
    // written off, so no archived ch2 ever carries a pending lock
    let w = W::new(1);
    w.paid(0);
    let base = base1(&w);
    w.hub.connect_next(w.origin(0), None, None).unwrap();
    w.chain.confirm_all();
    w.hub.watch_tick();
    assert_eq!(w.hub.next_channels()[w.origin(0)].state, "open");
    let held = w.held_lock(0);
    w.back_in_flight(0, &held);
    let old = w.oc(0);
    let close = w.provider_closes(0);
    w.hub.watch_tick();
    assert_eq!((w.oc(0).params.payer_pub, w.oc(0).state.as_str(), w.pending_anywhere()), (old.params.payer_pub, "closing", 1), "it kept its place");
    w.hub.watch_tick();
    assert!(w.oc(0).params.payer_pub != old.params.payer_pub && w.pending_anywhere() == 0, "written off, then replaced");
    assert_eq!((w.stale1().len(), base1(&w).0), (1, base.0 + d_plus_f(&held)), "held on ch1");
    w.chain.confirm_all();
    assert!(w.chain.confirmed(&close));
    assert!(has(&w.hub.watch_tick(), "lock_released"));
    assert_eq!((w.stale1().len(), base1(&w)), (0, base));
}
