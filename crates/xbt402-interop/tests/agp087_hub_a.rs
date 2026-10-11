//! AGP-087, area HUB-A (the hub's ch1 side): tests of the second closure audit of the external review.
//!
//! The harness is a copy of `hub_routing_safety.rs` with one field added to `Wrapped` (`deaf`: the
//! provider answers the hub's close request with a 400, as a provider that keeps a pre-signature
//! for later would).
//!
//! Tests named `hole_*` FAIL on main `f0554d0`: each one shows a hole. The others pass and are
//! evidence for a "fixed" verdict that had no test.
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::adaptor;
use xbt402::adaptor::Sc;
use xbt402::channel::FeePayer;
use xbt402::funding::{ChainBackend, FundingPolicy, UtxoInfo};
use xbt402::http::HttpService;
use xbt402::hub::{HubConfig, RouteHub};
use xbt402::ledger::{ChannelState, Ledger};
use xbt402::provider::{HttpResponse, Provider, ProviderConfig, MAX_KEPT_INTENTS};
use xbt402::route::{fee_due, FeeQuote, HUB_ROUTE_PATH, ROUTE_LOCK_PATH};
use xbt402::route_client::{RoutePayer, RoutePayerConfig, Shard};
use xbt402::route_seller::RouteOffer;
use xbt402::signer::{LocalSigner, StateSigner};
use xbt402::wire::{unb64json, CLOSE_PATH};
use xbt402_interop::memnet::{ChainWallet, MemChain, MemNet, NetTransport};
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;

const NET: &str = "bip122:11111111111111111111111111111111";
const HUB: &str = "http://hub.test";

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("xbt-rs-agp087-huba-{}", hex::encode(&sha256(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes())[..8])));
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
}

impl HttpService for Wrapped {
    fn body_limit(&self, path: &str) -> usize {
        HttpService::body_limit(&*self.inner, path)
    }

    fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str) -> HttpResponse {
        if path == CLOSE_PATH && self.deaf.load(Ordering::SeqCst) {
            return HttpResponse::new(400, vec![("Content-Type".into(), "application/json".into())], br#"{"error":"refused","detail":"later"}"#.to_vec());
        }
        let r = HttpService::serve(&*self.inner, method, path, headers, body, url);
        if path == ROUTE_LOCK_PATH && !xbt402_interop::memnet::is_lock_check(path, body) {
            let mut g = self.gate.lock().unwrap();
            if g.0 {
                g.1 = true;
                self.cv.notify_all();
                let (mut g, _) = self.cv.wait_timeout_while(g, Duration::from_secs(10), |g| !g.2).unwrap();
                g.0 = false;
            }
        }
        if path == ROUTE_LOCK_PATH && !xbt402_interop::memnet::is_lock_check(path, body) && self.refuse.load(Ordering::SeqCst) && r.status == 200 {
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
                               deaf: AtomicBool::new(false) });
    net.add(origin, w.clone());
    w
}

fn sk(n: u64) -> SecretKey {
    Sc::from_u64(n).secret().unwrap()
}

fn hub_cfg() -> HubConfig {
    HubConfig::from_json(&json!({"spend_final_depth": 1, "fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500, "delta": 36,
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
        let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
        let node = Arc::new(Node { chain: chain.clone(), down: AtomicBool::new(false), strict: AtomicBool::new(false) });
        let hub = Arc::new(RouteHub::new(node.clone(), chain.clone(), Box::new(ChainWallet(chain.clone())), Box::new(NetTransport(net.clone())), sk(0x4B4B), NET,
                                         Some(&dir.0.join("hub")), hub_cfg()).unwrap());
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

// --- H2: two written-off locks under one lockId ------------------------------------------------------------

/// Two written-off locks on one ch1 that carry the same lockId, each over its own ch2, both held in
/// ch1's base. p1 keeps its pre-signature and refuses the hub's close request.
///
/// AGP-088: the hub no longer lets the second lock in under that lockId (`lock_held`:
/// `agp088_hub.rs::a_lock_under_a_lock_id_ch1_holds_written_off_is_refused`), so the audit's way of
/// making the pair (p1 names p0's lockId in its invoice) now ends at that refusal. The pair is put
/// in the ledgers as a hub from before left it: p1's lock is written off under its own lockId and
/// then carries p0's, on ch1 and on p1's ch2. The controls and everything after are the audit's.
fn two_written_off_locks_under_one_lock_id(blocks: &[Option<u32>]) -> (W, String) {
    let w = W::with_ch2_blocks(blocks);
    w.paid(1); // ch1 has a state to close with
    w.provs[0].1.refuse.store(true, Ordering::SeqCst);
    let r = w.lock(0);
    assert_eq!((r["status"].as_str(), r["error"].as_str()), (Some("refused"), Some("route_failed")), "{r}");
    let lid = w.stale1()[0]["lockId"].as_str().unwrap().to_string();
    w.provs[1].1.refuse.store(true, Ordering::SeqCst);
    w.provs[1].1.deaf.store(true, Ordering::SeqCst);
    let r = w.lock(1);
    assert_eq!((r["status"].as_str(), r["error"].as_str()), (Some("refused"), Some("route_failed")), "{r}");
    // the second lock under the first one's lockId (its own T, its own ch2)
    w.hub.inbound.with_state(&w.pay.chan().unwrap(), |st| st.extra["stale_locks"][1]["lockId"] = lid.as_str().into()).unwrap();
    w.hub.with_out(|b| b.chans[w.provs[1].0.as_str()].stale[0]["lockId"] = lid.as_str().into());
    let stale = w.stale1();
    assert_eq!(stale.len(), 2, "control: both locks are written off and kept on ch1: {stale:?}");
    assert!(stale.iter().all(|s| s["lockId"] == lid.as_str() && s["hold"].is_object()), "control: one lockId, both held: {stale:?}");
    assert_ne!(stale[0]["T"], stale[1]["T"], "control: two different locks");
    assert_eq!(w.hub.out_channels()[&w.provs[1].0].stale.len(), 1, "control: p1's ch2 holds its written-off lock");
    assert_eq!(w.pay.close().unwrap_err().code, "lock_pending", "control: ch1 cannot close below the two locks");
    (w, lid)
}

/// What the hub's ch2s paid out against what ch1 collected, after the client closes ch1 and p1 then
/// closes its ch2 with the pre-signature it kept.
fn client_closes_then_p1_uses_its_pre_signature(w: &W) -> (Result<Value, xbt402::ChannelError>, u64, u64) {
    let closed = w.pay.close();
    let st2 = w.st2(1);
    w.provs[1].1.inner.close_now(&st2.params.channel_id()).unwrap();
    w.hub.watch_tick();
    w.chain.confirm_all();
    w.hub.watch_tick();
    let paid_out: u64 = (0..2).map(|i| {
        let p = &w.provs[i].1.inner;
        p.channel_ids().iter().filter_map(|c| p.channel_state(c)).filter(|s| !s.closed_txid.is_empty()).map(|s| s.best_cum).sum::<u64>()
    }).sum();
    (closed, w.st1().best_cum, paid_out)
}

#[test]
fn hole_h2_a_written_off_lock_is_dropped_when_another_with_its_lock_id_completes() {
    // The lockId comes from the provider's invoice, and the hub does not refuse one that a
    // written-off lock on the same ch1 already carries. `complete_ch1` then removes EVERY
    // written-off lock with that lockId when one of them completes: the second lock is gone from
    // ch1 while its pre-signature is still out on p1's ch2. Nothing keeps ch1 from closing below it
    // (H1's fix reads `stale_locks`), and p1's later close is paid by the hub for nothing.
    let w = {
        let (w, _) = two_written_off_locks_under_one_lock_id(&[None, None]);
        w
    };
    // p0 uses its pre-signature: its ch2 close shows t, the hub completes p0's lock on ch1
    let st2 = w.st2(0);
    w.provs[0].1.inner.close_now(&st2.params.channel_id()).unwrap();
    let acts = w.hub.watch_tick();
    assert!(acts.iter().any(|a| a["event"] == "secret_from_close"), "{acts:?}");
    assert_eq!(w.hub.out_channels()[&w.provs[1].0].stale.len(), 1, "p1's ch2 still holds its written-off lock, unresolved");
    let left = w.stale1().len();
    let (closed, collected, paid_out) = client_closes_then_p1_uses_its_pre_signature(&w);
    assert!(closed.is_err() && collected >= paid_out,
            "p1's written-off lock left ch1 with p0's ({left} written-off locks on ch1, 1 on p1's ch2); ch1 then closed ({}) at {collected} sat \
             and the hub paid {paid_out} sat on its ch2s: {} sat uncollected",
            closed.as_ref().map(|c| c.to_string()).unwrap_or_else(|e| e.code.clone()), paid_out.saturating_sub(collected));
}

#[test]
fn hole_h2_a_written_off_lock_is_dropped_when_another_with_its_lock_id_is_released() {
    // The same through the release: p0's ch2 is refunded, which proves p0's lock unpaid.
    // `release_unpaid` drops every written-off lock with that lockId and gives back one hold.
    let (w, _) = two_written_off_locks_under_one_lock_id(&[None, Some(3_000)]);
    let oc = w.hub.out_channels()[&w.provs[0].0].clone();
    w.chain.set_height(oc.params.expiry + 10);
    w.hub.watch_tick();
    w.chain.confirm_all();
    let acts = w.hub.watch_tick();
    assert!(acts.iter().any(|a| a["event"] == "lock_released" && a["held"] == true), "{acts:?}");
    assert_eq!(w.hub.out_channels()[&w.provs[1].0].stale.len(), 1, "p1's ch2 still holds its written-off lock, unresolved");
    let left = w.stale1().len();
    let (closed, collected, paid_out) = client_closes_then_p1_uses_its_pre_signature(&w);
    assert!(closed.is_err() && collected >= paid_out,
            "p1's written-off lock left ch1 with p0's ({left} written-off locks on ch1, 1 on p1's ch2); ch1 then closed ({}) at {collected} sat \
             and the hub paid {paid_out} sat on its ch2s: {} sat uncollected",
            closed.as_ref().map(|c| c.to_string()).unwrap_or_else(|e| e.code.clone()), paid_out.saturating_sub(collected));
}

// --- the routed client's resync: a completion and a release in one view (AGP-085 stated limit 5) ----------

/// Two locks are written off and held (the first to p`first`, then the other). One is then
/// completed off its ch2 close and the other released by its ch2's refund, before the client talks
/// to the hub again: the hub's next view carries a completion and a release at once.
/// p0's ch2 is the short one (refunded), p1's is closed with t, p2 takes the lock after the resync.
fn completion_and_release_in_one_view(first: usize) {
    let w = W::with_ch2_blocks(&[None, Some(3_000), Some(3_000)]);
    w.paid(2);
    let base = base1(&w);
    let signed0 = w.pay.counters().3;
    w.provs[0].1.deaf.store(true, Ordering::SeqCst);
    let mut adds = [0u64; 2];
    for i in [first, 1 - first] {
        w.net.set_drop(&w.provs[i].0, Some(Box::new(|_, p| p == ROUTE_LOCK_PATH)));
        let r = w.lock(i);
        assert_eq!((r["status"].as_str(), r["error"].as_str()), (Some("refused"), Some("route_failed")), "{r}");
        w.net.set_drop(&w.provs[i].0, None);
        adds[i] = d_plus_f(w.stale1().last().unwrap());
    }
    let stale = w.stale1();
    assert!(stale.len() == 2 && stale.iter().all(|s| s["hold"].is_object()));
    let cums: Vec<u64> = (0..2).map(|i| stale.iter().find(|s| s["provider"] == w.provs[i].0.as_str()).unwrap()["cum"].as_u64().unwrap()).collect();
    assert_eq!(w.pay.counters().0, base.0 + adds[0] + adds[1], "the client adopted both holds");
    assert_eq!(w.pay.counters().3, signed0, "and counts neither as signed");
    // p0's ch2 runs out and is refunded (its lock was not paid); p1 closes its ch2 with t
    let oc = w.hub.out_channels()[&w.provs[0].0].clone();
    w.chain.set_height(oc.params.expiry + 10);
    let mut acts = w.hub.watch_tick();
    w.chain.confirm_all();
    acts.extend(w.hub.watch_tick());
    acts.extend(w.hub.watch_tick());
    assert!(acts.iter().any(|a| a["event"] == "lock_released" && a["held"] == true), "{acts:?}");
    assert!(acts.iter().any(|a| a["event"] == "secret_from_close" && a["ch1_completed"] == true), "{acts:?}");
    assert!(w.stale1().is_empty());
    let st1 = w.st1();
    assert_eq!(st1.best_cum, cums[1], "ch1's best state is p1's completed lock");
    assert_eq!(base1(&w).0, base.0 + adds[1], "p1's lock stays in the base, p0's hold left it");
    // the client's next lock is refused for its amount; the view has the completion and the release
    stream(&w.pay, &w.shards[2], 10);
    let r = w.pay.lock(&w.shards[2]).unwrap().unwrap();
    assert_eq!(r["status"], "resynced", "first {first}: the client did not adopt a completion and a release in one view: {r}");
    let c = w.pay.counters();
    assert_eq!((c.0, c.1, c.2), base1(&w), "first {first}: the client's counters are the hub's");
    assert_eq!(c.3, st1.best_cum, "first {first}: the client counts the completed lock as signed, and nothing above it");
    // it never signs above what the hub can complete plus this lock
    let r = w.pay.lock(&w.shards[2]).unwrap().unwrap();
    assert_eq!(r["status"], "paid", "first {first}: {r}");
    let c = w.pay.counters();
    assert_eq!((c.0, c.1, c.2), base1(&w));
    let st1 = w.st1();
    assert_eq!(c.3, st1.best_cum);
    assert!(st1.best_cum >= c.0, "ch1's state covers what was routed");
    let paid_out: u64 = (0..3).map(|i| w.st2(i).best_cum).sum::<u64>() - w.st2(0).best_cum;
    assert!(st1.best_cum >= paid_out, "the hub collected {} for {paid_out} paid on p1's and p2's ch2s", st1.best_cum);
    // the client paid for p1's lock and p2's two, plus fees: never for p0's released lock twice
    assert!(st1.best_cum <= base.0.max(signed0) + adds[0] + adds[1] + 2 * adds[1], "{}", st1.best_cum);
    assert!(w.pay.close().is_ok(), "nothing unresolved keeps ch1 open");
}

#[test]
fn resync_adopts_a_completion_above_a_release_in_one_view() {
    // the released lock (p0's) was given up first: the completed one (p1's) sits above it, so the
    // client paid p0's hold ahead and gets it back as room under its signed state
    completion_and_release_in_one_view(0);
}

#[test]
fn resync_adopts_a_completion_below_a_release_in_one_view() {
    // the completed lock (p1's) was given up first: the released one (p0's) was signed above it and
    // can no longer complete (its ch2 is refunded)
    completion_and_release_in_one_view(1);
}

// --- the routed client and a hub that lies about holds -----------------------------------------------------

/// A hub that takes each lock, forwards nothing, and answers `route_failed` with a view that says
/// it holds the lock in ch1's base (as an honest hub does for a lock whose ch2 pre-signature is out).
struct LyingHub {
    inner: Arc<RouteHub>,
    lie: AtomicBool,
    /// (routed, units, paid, held lockIds, the cum of the last lock the client pre-signed)
    tally: Mutex<(u64, u128, u64, Vec<String>, u64)>,
}

impl HttpService for LyingHub {
    fn body_limit(&self, path: &str) -> usize {
        HttpService::body_limit(&*self.inner, path)
    }

    fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str) -> HttpResponse {
        let hdr = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-SIGNATURE")).map(|(_, v)| v.clone());
        if !(method == "POST" && path == HUB_ROUTE_PATH && self.lie.load(Ordering::SeqCst)) || hdr.is_none() {
            return HttpService::serve(&*self.inner, method, path, headers, body, url);
        }
        let pl = unb64json(&hdr.unwrap()).unwrap()["payload"].clone();
        let rt = serde_json::from_slice::<Value>(body).unwrap()["route"].clone();
        let (d, f) = (rt["amount"].as_u64().unwrap(), rt["fee"].as_u64().unwrap());
        let q = FeeQuote::from_json(&rt["feeQuote"]).unwrap();
        let best = self.inner.ch1_state(pl["chan"].as_str().unwrap()).unwrap().best_cum;
        let mut t = self.tally.lock().unwrap();
        let (_, total) = fee_due(&q, d, t.1, t.2);
        *t = (t.0 + d + f, total, t.2 + f, [t.3.clone(), vec![rt["lockId"].as_str().unwrap().to_string()]].concat(),
              pl["cum"].as_str().and_then(|c| c.parse().ok()).or(pl["cum"].as_u64()).unwrap());
        let view = json!({"error": "route_failed", "detail": "provider refused the lock: refused", "bestCum": best, "routedSat": t.0,
                          "feeUnits": t.1.to_string(), "feePaid": t.2, "held": t.3, "released": []});
        HttpResponse::new(502, vec![("Content-Type".into(), "application/json".into())], view.to_string().into_bytes())
    }
}

#[test]
fn hole_a_hub_that_lies_about_holds_raises_what_the_client_signs_without_bound() {
    // The client adopts a hold on the hub's word: it cannot see whether a ch2 pre-signature is out.
    // Each adopted hold raises the base of its next lock by d + f. A hub that claims a hold for every
    // lock it is sent (and forwards none) walks the client's next pre-signed state up by one lock per
    // try; the provider is owed d once. Forwarding the last one honestly then collects all of it.
    let w = W::new(1);
    w.paid(0);
    let (routed0, units0, paid0) = base1(&w);
    let signed0 = w.pay.counters().3;
    let liar = Arc::new(LyingHub { inner: w.hub.clone(), lie: AtomicBool::new(true), tally: Mutex::new((routed0, units0, paid0, vec![], 0)) });
    w.net.add(HUB, liar.clone());
    stream(&w.pay, &w.shards[0], 10);
    let due = w.shards[0].due_sat();
    let mut tries = 0;
    for _ in 0..6 {
        let Some(r) = w.pay.lock(&w.shards[0]).unwrap() else { break };
        assert_eq!((r["status"].as_str(), r["error"].as_str()), (Some("refused"), Some("route_failed")), "{r}");
        tries += 1;
    }
    let t = liar.tally.lock().unwrap().clone();
    let one = (t.0 - routed0) / tries.max(1);
    assert_eq!(w.net.count(ROUTE_LOCK_PATH), 1, "control: the hub forwarded nothing after the first, honest lock");
    assert_eq!(w.pay.counters().0, t.0, "control: the client adopted every hold the hub claimed");
    assert_eq!(w.pay.counters().3, signed0, "control: none of them is a state the client counts as signed");
    assert!(t.4 <= signed0 + 2 * one,
            "the provider is owed {due} sat; after {tries} locks the hub said it holds, the client pre-signed ch1 at {} under the provider's real T: \
             {} sat above its last paid state {signed0} ({} locks of {one} sat), which the hub collects by forwarding that one lock",
            t.4, t.4 - signed0, (t.4 - signed0) / one.max(1));
}

// --- close intents (AGP-085 item 7) ------------------------------------------------------------------------

#[test]
fn hole_unresolved_close_intents_are_not_bounded_for_closes_at_rising_amounts() {
    // AGP-085 bounds the kept intents by refusing the 9th ROLLOVER. A close is never refused, and a
    // close whose payload raises the state by one sat is another transaction: each one the node
    // errors on is kept, so the client grows the hub's ledger (and the watcher's work per tick) by
    // one signed transaction per sat while the hub's node refuses broadcasts.
    let w = W::new(1);
    w.paid(0);
    let chan = w.pay.chan().unwrap();
    w.node.down.store(true, Ordering::SeqCst);
    let mut codes = vec![];
    for i in 1..=12u64 {
        let cum = w.st1().best_cum + i.min(1);
        let sig = w.signer.sign_state(&chan, cum).unwrap();
        let body = json!({"chan": chan, "sig": hex::encode(w.signer.sign_close(&chan).unwrap()), "payload": {"chan": chan, "cum": cum.to_string(), "sig": hex::encode(sig)}});
        let r = HttpService::serve(&*w.hub, "POST", CLOSE_PATH, &[], body.to_string().as_bytes(), &format!("{HUB}{CLOSE_PATH}"));
        codes.push(serde_json::from_slice::<Value>(&r.body).unwrap()["error"].as_str().unwrap_or("").to_string());
    }
    let st1 = w.st1();
    let kept = st1.extra.get("close_intents").and_then(Value::as_array).map(Vec::len).unwrap_or(0);
    assert!(st1.closed_txid.is_empty(), "control: the node took nothing");
    assert!(codes.iter().all(|c| c == "close_failed"), "control: {codes:?}");
    assert!(kept <= MAX_KEPT_INTENTS, "{kept} unresolved spends are kept beside the latest after 12 closes one sat apart (bound: {MAX_KEPT_INTENTS})");
}

// --- paths that close or move ch1 under a held lock (evidence; these pass) ---------------------------------

#[test]
fn a_held_lock_is_not_escaped_through_settle_or_an_errored_close() {
    // H1/H2 neighbours of the close and the rollover, with a written-off lock held in ch1's base:
    // /x402/settle (calls close), a close whose payload pays one sat more (refused before the payload
    // is applied), and a close after the hub's node starts erroring (no intent is written).
    let w = W::new(2);
    w.paid(0);
    w.provs[0].1.refuse.store(true, Ordering::SeqCst);
    w.provs[0].1.deaf.store(true, Ordering::SeqCst);
    let r = w.lock(0);
    assert_eq!(r["error"], "route_failed", "{r}");
    let chan = w.pay.chan().unwrap();
    let (best, lcum) = (w.st1().best_cum, w.stale1()[0]["cum"].as_u64().unwrap());
    assert!(lcum > best + 2);
    let accepted = w.pay.next_seq().unwrap().1;
    let settle = |payload: Value| {
        let body = json!({"x402Version": 2, "paymentPayload": {"x402Version": 2, "accepted": accepted, "payload": payload}, "paymentRequirements": accepted});
        let r = HttpService::serve(&*w.hub, "POST", "/x402/settle", &[], body.to_string().as_bytes(), &format!("{HUB}/x402/settle"));
        serde_json::from_slice::<Value>(&r.body).unwrap_or(Value::Null)
    };
    let close_sig = hex::encode(w.signer.sign_close(&chan).unwrap());
    let r = settle(json!({"chan": chan, "sig": close_sig}));
    assert!(w.st1().closed_txid.is_empty(), "/x402/settle closed ch1 below a held lock: {r}");
    assert!(r["errorReason"].as_str().unwrap_or("").ends_with("lock_pending"), "{r}");
    // a close whose payload pays one sat more, still below the lock
    let sig = hex::encode(w.signer.sign_state(&chan, best + 1).unwrap());
    let r = settle(json!({"chan": chan, "sig": close_sig, "payload": {"chan": chan, "cum": (best + 1).to_string(), "sig": sig}}));
    assert!(w.st1().closed_txid.is_empty(), "{r}");
    assert!(r["errorReason"].as_str().unwrap_or("").ends_with("lock_pending") && w.st1().best_cum == best, "the refusal comes before the payload is applied: {r}");
    // with the node erroring: still refused, and no intent is written that would stop routing
    w.node.down.store(true, Ordering::SeqCst);
    assert_eq!(w.pay.close().unwrap_err().code, "lock_pending");
    w.node.down.store(false, Ordering::SeqCst);
    assert!(w.st1().extra.get("close_intent").is_none_or(|i| !xbt402::json::truthy(Some(i))), "a refused close left an intent");
    // the watcher at ch1's height today does not close it either, and the lock is still held
    assert!(w.hub.inbound.close_due().unwrap().is_empty());
    assert_eq!(w.stale1().len(), 1);
    // routing goes on above the hold (to p1), and the client pays for the held lock in that state
    let r = w.lock(1);
    assert_eq!(r["status"], "paid", "{r}");
    assert!(w.st1().best_cum > lcum, "the next lock sits above the held one");
    // now the held lock is covered by ch1's best state: the close goes through at a state that pays for it
    let closed = w.pay.close().unwrap();
    assert!(closed["cum"].as_str().and_then(|c| c.parse::<u64>().ok()).or(closed["cum"].as_u64()).unwrap() > lcum, "{closed}");
}

#[test]
fn a_restart_between_the_ch2_write_off_and_the_ch1_hold_keeps_the_lock_held() {
    // void() writes the ch2 lock off first, then holds the ch1 lock. A stop between the two leaves
    // ch1 with a `route_lock` that no ch2 has pending. The sweep before a close or a rollover (and
    // the watcher's) must hold it, not drop it: the pre-signature is out.
    let w = W::new(1);
    w.paid(0);
    w.provs[0].1.refuse.store(true, Ordering::SeqCst);
    w.provs[0].1.deaf.store(true, Ordering::SeqCst);
    let r = w.lock(0);
    assert_eq!(r["error"], "route_failed", "{r}");
    let chan = w.pay.chan().unwrap();
    // put ch1 back to where the stop would have left it: the lock in flight, nothing held
    let held = w.stale1()[0].clone();
    w.hub.inbound.with_state(&chan, |st| {
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
    let routed = w.routed();
    let refused = w.pay.close();
    assert!(w.st1().closed_txid.is_empty(), "ch1 closed below a lock whose ch2 pre-signature is out");
    assert_eq!(refused.unwrap_err().code, "lock_pending");
    assert!(w.hub.events.lock().unwrap().iter().any(|e| e["event"] == "orphan_lock_held"));
    let stale = w.stale1();
    assert!(stale.len() == 1 && stale[0]["hold"].is_object());
    assert_eq!(w.routed(), routed + d_plus_f(&stale[0]), "held by what the lock adds");
}

// --- a close of an unconfirmed rollover child (AGP-053) that is only in the mempool -------------------------

/// (the child's state, final, written-off locks left on ch1, the watcher's events) after the provider's
/// close of an unconfirmed child reached the mempool. `strict`: the node answers gettxout as a real one.
fn close_of_an_unconfirmed_child_in_the_mempool(strict: bool) -> (String, bool, usize, Vec<String>) {
    let w = W::build(&[None], 2, 40);
    w.node.strict.store(strict, Ordering::SeqCst);
    let origin = w.provs[0].0.clone();
    let lock = |calls: usize| {
        stream(&w.pay, &w.shards[0], calls);
        w.pay.lock(&w.shards[0]).unwrap().unwrap()
    };
    assert_eq!(lock(50)["status"], "paid");
    let acts = w.hub.watch_tick();
    assert!(acts.iter().any(|a| a["event"] == "ch2_rollover"), "{acts:?}");
    let child = w.hub.out_channels()[&origin].clone();
    assert!(child.state == "open" && child.zero_conf_pending(), "control: an unconfirmed child: {:?}", child.zero_conf);
    assert_eq!(lock(5)["status"], "paid"); // the child has a state to close with
    w.provs[0].1.inner.set_no_reveal(true); // the provider takes the next lock and keeps it
    let r = lock(5);
    assert_eq!((r["status"].as_str(), r["error"].as_str()), (Some("refused"), Some("route_failed")), "{r}");
    assert_eq!(w.stale1().len(), 1, "control: held on ch1");
    assert_eq!(w.hub.out_channels()[&origin].stale.len(), 1);
    // the provider closes the child at the state before the lock: into the mempool, nothing confirms
    let close = w.provs[0].1.inner.close_now(&child.params.channel_id()).unwrap();
    assert!(!w.chain.confirmed(&close) && !w.chain.confirmed(&child.params.funding_txid()), "control: neither the close nor the rollover is confirmed");
    let acts = w.hub.watch_tick();
    let oc = w.hub.out_channels()[&origin].clone();
    (oc.state.clone(), oc.final_, w.stale1().len(), acts.iter().map(|a| a["event"].as_str().unwrap_or("").to_string()).collect())
}

#[test]
fn hole_h2_a_hold_is_released_on_an_unconfirmed_close_of_an_unconfirmed_rollover_child() {
    // A ch2 that is a rollover's child takes locks before the rollover confirms. The watcher decides
    // "the close confirmed" by `gettxout(funding, include_mempool = false)` being None. For an output
    // of an UNCONFIRMED transaction that is always None on a real node, so a close of the child that
    // is only in the mempool counts as confirmed: the ch2 is `closed` and final (never read again)
    // and the written-off lock's hold leaves ch1. The provider still holds that lock's
    // pre-signature and can replace the mempool close with one that uses it: the hub pays on ch2,
    // and ch1 no longer holds the lock. (B1's FakeNode answers as a real node; MemChain does not,
    // hence `strict`.)
    let (state, fin, left, acts) = close_of_an_unconfirmed_child_in_the_mempool(false);
    assert_eq!((state.as_str(), fin, left), ("closing", false, 1), "control: with MemChain's gettxout the close is seen as unconfirmed: {acts:?}");
    let (state, fin, left, acts) = close_of_an_unconfirmed_child_in_the_mempool(true);
    assert!(left == 1 && !fin,
            "on a close that is only in the mempool the child is {state:?} (final {fin}) and ch1 holds {left} written-off locks: {acts:?}");
}
