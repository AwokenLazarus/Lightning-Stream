//! AGP-105 (fix wave 6, hub and routed client): the rules this wave states, on the rig of
//! `agp102_hub.rs` ([`MemChain`] + [`MemNet`], in process). The audit's own tests for the same
//! items are in `agp102_hub.rs` and `xbt402/tests/agp102_route_client.rs`; these pin what those do
//! not: how a provider that was set aside comes back, what many dark providers cost a tick, the
//! flag wait outside ch1's ledger lock, the session that could never be paid, the scan that
//! starts where the spend was found, and a wallet that cannot say what it sent.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::adaptor;
use xbt402::adaptor::Sc;
use xbt402::channel::FeePayer;
use xbt402::client::{Transport, Wallet};
use xbt402::funding::FundingPolicy;
use xbt402::hub::{HubConfig, OutChannel, RouteHub};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::route::SpendScan;
use xbt402::route_client::{FileRouteLedger, RoutePayer, RoutePayerConfig, Shard};
use xbt402::route_seller::RouteOffer;
use xbt402::signer::{LocalSigner, RouteSigner};
use xbt402::ChannelError;
use xbt402_interop::memnet::{is_lock_check, ChainWallet, MemChain, MemNet, NetTransport};
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

const NET: &str = "bip122:11111111111111111111111111111111";
const HUB: &str = "http://hub.test";
/// `hub.rs`'s `CHECK_UNANSWERED`: why a ch2 is blocked after an unanswered check.
const SET_ASIDE: &str = "the provider did not answer a lock check within revealTimeoutSec";

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let name = hex::encode(&sha256(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes())[..8]);
        let p = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("agp105_hub_{name}"));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The net as the hub reaches its providers. `dark`: a provider (by origin) that never answers a
/// check: the transport gives up after that long. `slow`: one that answers a check that much
/// later. `checks`: every check sent, the watcher's included.
#[derive(Default)]
struct Knobs {
    dark: Mutex<HashMap<String, Duration>>,
    slow: Mutex<HashMap<String, Duration>>,
    checks: AtomicU32,
}

struct HubNet(Arc<MemNet>, Arc<Knobs>);

impl Transport for HubNet {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> xbt402::Result<HttpResponse> {
        let (origin, path) = xbt402::client::split_url(url);
        if is_lock_check(&path, body) {
            self.1.checks.fetch_add(1, Ordering::SeqCst);
            let dark = self.1.dark.lock().unwrap().get(&origin).copied();
            if let Some(d) = dark {
                std::thread::sleep(d);
                return Err(ChannelError::new("transport_error", "timed out reading the answer"));
            }
            let slow = self.1.slow.lock().unwrap().get(&origin).copied();
            if let Some(d) = slow {
                std::thread::sleep(d);
            }
        }
        NetTransport(self.0.clone()).request(method, url, body, headers)
    }
}

/// A spend scan that, unlike [`MemChain`]'s, looks only from the height it is given, as bitcoind's
/// does. `lower`: the spender is reported that many blocks lower (a reorg mined it again in an
/// earlier block). `passes`: the `from` of every call.
struct FromScan {
    chain: Arc<MemChain>,
    lower: AtomicU32,
    passes: Mutex<Vec<u32>>,
}

impl SpendScan for FromScan {
    fn find_spend(&self, txid: &str, vout: u32, from: u32) -> xbt402::Result<Option<Tx>> {
        Ok(self.find_spend_at(txid, vout, from)?.map(|(tx, _)| tx))
    }
    fn find_spend_at(&self, txid: &str, vout: u32, from: u32) -> xbt402::Result<Option<(Tx, Option<u32>)>> {
        self.passes.lock().unwrap().push(from);
        let Some((tx, depth)) = self.chain.find_spend_at(txid, vout, from)? else { return Ok(None) };
        let depth = depth.unwrap_or(0);
        if depth == 0 {
            return Ok(Some((tx, Some(0))));
        }
        let tip = self.chain.height();
        let at = tip + 1 - depth - self.lower.load(Ordering::SeqCst);
        Ok((at >= from).then(|| (tx, Some(tip + 1 - at))))
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

fn provider(chain: &Arc<MemChain>, net: &Arc<MemNet>, dir: &TempDir, origin: &str, invoice_ttl: f64) -> Arc<Provider> {
    let mut cfg = ProviderConfig::new(NET);
    cfg.close_margin = 36;
    cfg.policy = FundingPolicy { min_capacity: 20_000, min_expiry_blocks: 500, max_expiry_blocks: 8_640, close_margin: 36, ..FundingPolicy::default() };
    cfg.settle_multiple = 20;
    cfg.height_ttl = Duration::ZERO;
    cfg.settle_lock_multiple = 0;
    cfg.route_close_fee_payer = FeePayer::Payee;
    let name = origin.replace("http://", "").replace('.', "_");
    let ledger = Ledger::open(&dir.0.join(format!("prov-{name}.jsonl"))).unwrap();
    let p = Provider::new(chain.clone(), adaptor::random_secret(), cfg, ledger, Box::new(|_, _| 1000),
                          Box::new(|_, _, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], b"{\"ok\":1}".to_vec()))).unwrap();
    p.offer_route(RouteOffer { window: 0.3, lock_wait: 0.6, invoice_ttl, ..RouteOffer::new("/v1/chunk", 300 * 10u128.pow(21)) });
    let p = Arc::new(p);
    net.add(origin, p.clone());
    p
}

fn sk(n: u64) -> SecretKey {
    Sc::from_u64(n).secret().unwrap()
}

fn hub_cfg(reveal_timeout: f64) -> HubConfig {
    HubConfig::from_json(&json!({"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500, "delta": 36,
                                 "reveal_timeout": reveal_timeout, "ch2_capacity": 100000, "ch2_expiry_blocks": 1000, "settle_lock_multiple": 0,
                                 "refill_ahead_locks": 0, "close_margin": 36,
                                 "policy": {"min_capacity": 20000, "min_expiry_blocks": 500, "max_expiry_blocks": 8640}})).unwrap()
}

struct W {
    chain: Arc<MemChain>,
    net: Arc<MemNet>,
    knobs: Arc<Knobs>,
    scan: Arc<FromScan>,
    hub: Arc<RouteHub>,
    provs: Vec<(String, Arc<Provider>)>,
    pay: Arc<RoutePayer>,
    shards: Vec<Arc<Shard>>,
    _dir: TempDir,
}

impl W {
    fn new(n: usize, reveal_timeout: f64) -> Self {
        Self::build(n, reveal_timeout, 8.0)
    }

    fn build(n: usize, reveal_timeout: f64, invoice_ttl: f64) -> Self {
        let (chain, net, dir, knobs) = (MemChain::new(1000), MemNet::new(), TempDir::new(), Arc::new(Knobs::default()));
        let scan = Arc::new(FromScan { chain: chain.clone(), lower: AtomicU32::new(0), passes: Mutex::new(vec![]) });
        let hub = Arc::new(RouteHub::new(chain.clone(), scan.clone(), Box::new(ChainWallet(chain.clone())), Box::new(HubNet(net.clone(), knobs.clone())),
                                         sk(0x4B4B), NET, Some(&dir.0.join("hub")), hub_cfg(reveal_timeout)).unwrap());
        net.add(HUB, hub.clone());
        let mut provs = vec![];
        for i in 0..n {
            let origin = format!("http://p{i}.test");
            provs.push((origin.clone(), provider(&chain, &net, &dir, &origin, invoice_ttl)));
            hub.connect(&origin, None, None).unwrap();
        }
        chain.confirm_all();
        hub.watch_tick();
        let (pay, shards) = client(&chain, &net, &provs);
        Self { chain, net, knobs, scan, hub, provs, pay, shards, _dir: dir }
    }

    fn lock(&self, i: usize) -> Option<Value> {
        stream(&self.pay, &self.shards[i], 10);
        self.pay.lock(&self.shards[i]).unwrap()
    }

    fn paid(&self, i: usize) {
        let r = self.lock(i);
        assert_eq!(r.as_ref().map(|r| r["status"].clone()), Some(json!("paid")), "{r:?}");
    }

    /// A lock for what is already due, with no call first (a provider left unpaid for longer than
    /// `window + lockWait` serves nothing until it is paid).
    fn pay_due(&self, i: usize) {
        let r = self.pay.lock(&self.shards[i]).unwrap();
        assert_eq!(r.as_ref().map(|r| r["status"].clone()), Some(json!("paid")), "{r:?}");
    }

    fn origin(&self, i: usize) -> &str {
        &self.provs[i].0
    }

    fn oc(&self, i: usize) -> OutChannel {
        self.hub.out_channels()[self.origin(i)].clone()
    }

    fn dark(&self, i: usize, d: Option<Duration>) {
        let mut m = self.knobs.dark.lock().unwrap();
        match d {
            Some(d) => m.insert(self.origin(i).to_string(), d),
            None => m.remove(self.origin(i)),
        };
    }

    fn checks(&self) -> u32 {
        self.knobs.checks.load(Ordering::SeqCst)
    }

    fn not_admitted(&self, code: &str) -> u64 {
        self.hub.stats.lock().unwrap().not_admitted.get(code).copied().unwrap_or(0)
    }
}

fn payer(chain: &Arc<MemChain>, net: &Arc<MemNet>, signer: Arc<dyn RouteSigner>, wallet: Arc<dyn Wallet>) -> RoutePayer {
    let mut cfg = RoutePayerConfig::new(NET);
    cfg.expiry_blocks = 8_000;
    let c = chain.clone();
    RoutePayer::new(HUB, cfg, signer, wallet, Box::new(NetTransport(net.clone())), Box::new(move || Ok(c.height())))
}

/// A client of the hub: its own ch1 and a session with every provider.
fn client(chain: &Arc<MemChain>, net: &Arc<MemNet>, provs: &[(String, Arc<Provider>)]) -> (Arc<RoutePayer>, Vec<Arc<Shard>>) {
    let pay = Arc::new(payer(chain, net, Arc::new(LocalSigner::new()), Arc::new(ChainWallet(chain.clone()))));
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

fn refused(r: &Option<Value>) -> Option<&str> {
    r.as_ref().filter(|r| r["status"] == "refused").and_then(|r| r["error"].as_str())
}

// --- item 2: a provider that does not answer the check ---------------------------------------------------------

/// The rule, whole: one unanswered check sets the provider aside with nothing written off or
/// held; the next lock for it is refused at once, with no request to it, and counted; the other
/// provider is paid meanwhile; a tick while it is still dark asks it once and leaves it aside; the
/// tick after it answers again lifts the block, and the next lock is paid.
#[test]
fn a_provider_set_aside_is_refused_at_once_and_comes_back_when_it_answers() {
    let w = W::new(2, 0.3);
    w.paid(0);
    w.paid(1);
    w.dark(0, Some(Duration::from_millis(400)));
    let r = w.lock(0);
    assert_eq!(refused(&r), Some("route_failed"), "{r:?}");
    let oc = w.oc(0);
    assert_eq!((oc.blocked.as_str(), oc.state.as_str(), oc.stale.len(), oc.pending.len()), (SET_ASIDE, "open", 0, 0), "set aside, nothing written off");
    let st1 = w.hub.ch1_state(&w.pay.chan().unwrap()).unwrap();
    assert!(st1.extra.get("stale_locks").and_then(Value::as_array).is_none_or(|s| s.is_empty()) && !xbt402::json::truthy(st1.extra.get("route_lock")),
            "nothing is held on ch1 and its lock is gone");
    assert_eq!(w.checks(), 3, "control: two paid locks and the unanswered one");

    // refused at once, without a request to the provider, and the hub says so
    let t = Instant::now();
    let r = w.pay.lock(&w.shards[0]).unwrap();
    assert_eq!(refused(&r), Some("route_blocked"), "{r:?}");
    assert!(r.unwrap()["detail"].as_str().unwrap_or("").contains(SET_ASIDE));
    assert!(t.elapsed() < Duration::from_millis(300) && w.checks() == 3, "{:?}, {} checks", t.elapsed(), w.checks());
    assert_eq!(w.not_admitted("route_blocked"), 1, "the refused lock is counted");
    w.paid(1);

    // still dark: the tick asks once, waits no longer than a check, and leaves it aside
    let t = Instant::now();
    let acts = w.hub.watch_tick();
    assert!(!has(&acts, "ch2_answers_again") && w.oc(0).blocked == SET_ASIDE && w.checks() == 5, "{acts:?}, {} checks", w.checks());
    assert!(t.elapsed() < Duration::from_millis(1500), "{:?}", t.elapsed());

    // it answers again: the next tick lifts the block and the next lock is paid
    w.dark(0, None);
    let acts = w.hub.watch_tick();
    assert!(has(&acts, "ch2_answers_again") && w.oc(0).blocked.is_empty(), "{acts:?}");
    assert!(!has(&w.hub.watch_tick(), "ch2_answers_again"), "once");
    w.pay_due(0);
    w.paid(0);
    assert_eq!(w.oc(0).stale.len(), 0);
}

/// The bound of the new block: providers that stay dark cost a tick one check's wait, however
/// many they are, and each is asked in its turn.
#[test]
fn providers_that_stay_dark_cost_a_tick_one_wait_and_are_asked_in_turn() {
    let w = W::new(3, 0.3);
    let wait = Duration::from_millis(350);
    for i in 0..3 {
        w.paid(i);
        w.dark(i, Some(wait));
        assert_eq!(refused(&w.lock(i)), Some("route_failed"));
        assert_eq!(w.oc(i).blocked, SET_ASIDE);
    }
    let before = w.checks();
    let t = Instant::now();
    w.hub.watch_tick();
    assert_eq!(w.checks() - before, 1, "one provider asked per tick");
    assert!(t.elapsed() < wait * 2, "three dark providers, one wait: {:?}", t.elapsed());
    for i in 0..3 {
        w.dark(i, None);
    }
    let mut back = 0;
    for _ in 0..3 {
        back += w.hub.watch_tick().iter().filter(|a| a["event"] == "ch2_answers_again").count();
    }
    assert_eq!(back, 3, "three ticks, each provider asked once");
    for i in 0..3 {
        w.pay_due(i);
    }
}

/// What does not set a provider aside: an answer that is a refusal, however late it comes on a
/// transport without the bound, and a check that fails at once (the audit's
/// `control_a_check_whose_answer_is_lost_writes_nothing_off` is the second).
#[test]
fn a_late_answer_is_an_answer() {
    let w = W::new(1, 0.3);
    w.paid(0);
    w.knobs.slow.lock().unwrap().insert(w.origin(0).to_string(), Duration::from_millis(450));
    // an honest slow provider on a transport that does not keep the bound: its yes is taken
    w.paid(0);
    assert!(w.oc(0).blocked.is_empty());
}

/// HUB 8, the other half of the audit's test: a lock that found the provider's flag taken waits
/// for it outside ch1's ledger lock and is then admitted, on ch1 as it is then. (The audit's test
/// shows that a third client is not held up meanwhile.)
#[test]
fn a_lock_that_waited_for_the_providers_flag_is_paid_when_it_is_free() {
    let w = Arc::new(W::new(1, 2.0));
    w.paid(0);
    let (c2, sh2) = client(&w.chain, &w.net, &w.provs);
    stream(&c2, &sh2[0], 10);
    stream(&w.pay, &w.shards[0], 10);
    w.knobs.slow.lock().unwrap().insert(w.origin(0).to_string(), Duration::from_millis(200));
    let first = {
        let w = w.clone();
        std::thread::spawn(move || w.pay.lock(&w.shards[0]).unwrap())
    };
    std::thread::sleep(Duration::from_millis(60)); // client 1's lock holds p0's flag while its check waits
    let t = Instant::now();
    let second = c2.lock(&sh2[0]).unwrap();
    let waited = t.elapsed();
    let first = first.join().unwrap();
    assert_eq!(first.as_ref().map(|r| r["status"].clone()), Some(json!("paid")), "{first:?}");
    assert_eq!(second.as_ref().map(|r| r["status"].clone()), Some(json!("paid")), "after {waited:?}: {second:?}");
    assert!(waited >= Duration::from_millis(100), "control: it did wait for the flag ({waited:?})");
    assert_eq!(w.not_admitted("lock_outstanding"), 0);
}

// --- item 10: a configuration that can route nothing -----------------------------------------------------------

/// A session no lock could ever pay is refused when it starts, with the two numbers; one second
/// more of invoice and it starts. The shipped defaults leave the client `window + lockWait` of
/// each invoice in which to send its lock.
#[test]
fn a_session_no_lock_could_pay_is_refused_when_it_starts() {
    let w = W::build(1, 10.0, 11.0); // the hub's shipped reveal_timeout, and the shortest invoice it can route
    provider(&w.chain, &w.net, &w._dir, "http://p9.test", 8.0); // `xbt402-route-provider --ttl` as it was shipped
    w.hub.connect("http://p9.test", None, None).unwrap();
    w.chain.confirm_all();
    w.hub.watch_tick();
    let e = w.pay.shard("http://p9.test/v1/chunk", "POST").map(|_| ()).unwrap_err();
    assert_eq!(e.code, "route_blocked");
    assert!(e.msg.contains("live 8 s") && e.msg.contains("= 11 s"), "{}", e.msg);

    let (offer, hub) = (RouteOffer::new("/v1/chunk", 1), HubConfig::default());
    assert_eq!((offer.invoice_ttl, hub.reveal_timeout), (15.0, 10.0), "the shipped defaults");
    assert!(xbt402::route::invoice_can_route(offer.invoice_ttl, hub.reveal_timeout) && !xbt402::route::invoice_can_route(8.0, hub.reveal_timeout));
    assert!(offer.invoice_ttl - (1.0 + hub.reveal_timeout) >= offer.window + offer.lock_wait, "a lock due after one window, and late by lockWait, can still be sent");
}

// --- item 11: the scan starts where the spend was found ---------------------------------------------------------

/// While a close waits for its depth the scan is asked from the block it was found in, and when
/// a reorg puts the close in a lower block the scan from that height finds nothing and the one
/// from the ch2's first block is run again: no answer depends on the remembered height.
#[test]
fn the_remembered_height_is_only_where_the_scan_starts() {
    let w = W::new(1, 0.3);
    w.paid(0);
    let funded_at = w.oc(0).scanned_to;
    w.chain.mine(50);
    w.hub.watch_tick();
    w.provs[0].1.close_now(&w.oc(0).params.channel_id()).unwrap();
    w.hub.watch_tick();
    w.chain.mine(1);
    let found_at = w.chain.height();
    w.hub.watch_tick();
    assert_eq!(w.oc(0).spend_at, found_at, "the close's height is on the record");
    w.scan.passes.lock().unwrap().clear();
    for _ in 0..5 {
        w.hub.watch_tick();
    }
    assert_eq!(*w.scan.passes.lock().unwrap(), vec![found_at; 5], "one scan per tick, from the close's block");

    // a reorg mines the close again three blocks lower
    w.scan.lower.store(3, Ordering::SeqCst);
    w.scan.passes.lock().unwrap().clear();
    w.hub.watch_tick();
    assert_eq!(*w.scan.passes.lock().unwrap(), vec![found_at, funded_at], "nothing from the remembered height: the whole scan again");
    assert_eq!((w.oc(0).spend_at, w.oc(0).state.as_str()), (found_at - 3, "closing"), "found, and remembered where it is now");
    w.chain.mine(2);
    assert!(has(&w.hub.watch_tick(), "ch2_closed"), "six deep counted from the lower block: final");
}

// --- item 6: a ch1 funding call that did not say whether it sent ------------------------------------------------

/// A wallet with `fund` only (it does not say it knows its sends): `after` true, it sends and then
/// errors; false, it refuses and sends nothing. The client cannot tell the two apart.
struct Deaf {
    chain: Arc<MemChain>,
    fail: AtomicBool,
    after: bool,
    sends: AtomicUsize,
}

impl Wallet for Deaf {
    fn fund(&self, address: &str, sats: u64) -> xbt402::Result<(String, u32)> {
        if self.fail.load(Ordering::SeqCst) && !self.after {
            return Err(ChannelError::new("wallet_error", "insufficient funds"));
        }
        let r = self.chain.fund(address, sats)?;
        self.sends.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(ChannelError::new("wallet_error", "timed out after the send"));
        }
        Ok(r)
    }
}

/// The rule for a wallet that cannot say: after a `fund` call without an outpoint nothing more is
/// sent, whether that call sent or not, until the owner has looked (`forget_unfunded`). The cost
/// is stated: a wallet that only refused is not asked again either.
#[test]
fn a_wallet_that_cannot_say_is_not_asked_twice_whatever_its_first_call_did() {
    for after in [true, false] {
        let w = W::new(1, 0.3);
        let wallet = Arc::new(Deaf { chain: w.chain.clone(), fail: AtomicBool::new(true), after, sends: AtomicUsize::new(0) });
        let pay = payer(&w.chain, &w.net, Arc::new(LocalSigner::new()), wallet.clone());
        assert_eq!(pay.open().unwrap_err().code, "wallet_error");
        wallet.fail.store(false, Ordering::SeqCst);
        for _ in 0..3 {
            let e = pay.open().unwrap_err();
            assert_eq!(e.code, "open_unresolved", "after {after}: {}", e.msg);
            assert!(e.msg.contains("forget_unfunded") && e.msg.contains("200000 sat to bcrt1"), "the message says what to look for: {}", e.msg);
        }
        assert_eq!(wallet.sends.load(Ordering::SeqCst), usize::from(after), "nothing more was sent (after {after})");
        // the owner looked and says there is no send: the record goes, and the next open funds
        assert!(pay.forget_unfunded().unwrap());
        pay.open().unwrap();
        assert_eq!(wallet.sends.load(Ordering::SeqCst), usize::from(after) + 1);
    }
}

/// That the wallet was asked is on the books before the call: a payer restarted from its ledger
/// after a call that never answered does not ask again.
#[test]
fn that_the_wallet_was_asked_survives_a_restart() {
    let w = W::new(1, 0.3);
    let wallet = Arc::new(Deaf { chain: w.chain.clone(), fail: AtomicBool::new(true), after: true, sends: AtomicUsize::new(0) });
    let signer: Arc<dyn RouteSigner> = Arc::new(LocalSigner::new());
    let path = w._dir.0.join("route.jsonl");
    let make = || payer(&w.chain, &w.net, signer.clone(), wallet.clone()).with_ledger(Box::new(FileRouteLedger::open(&path).unwrap())).unwrap();
    assert_eq!(make().open().unwrap_err().code, "wallet_error");
    wallet.fail.store(false, Ordering::SeqCst);
    assert_eq!(make().open().unwrap_err().code, "open_unresolved");
    assert_eq!(wallet.sends.load(Ordering::SeqCst), 1);
}
