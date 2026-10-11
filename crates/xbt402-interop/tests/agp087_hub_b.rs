//! AGP-087 (second closure audit, area HUB-B): the hub's ch2 side around a rollover's next channel
//! and a close-and-refill, one step to the side of AGP-085's tests. The harness (to `// --- AGP-087`)
//! is copied from `hub_money_safety.rs`; nothing in that file is changed.
//!
//! `hole_` tests FAIL on xbt-rs f0554d0; `ok_` tests pass and are evidence for a verdict.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::adaptor::Sc;
use xbt402::channel::FeePayer;
use xbt402::client::Wallet;
use xbt402::error::{ChannelError, Result};
use xbt402::funding::{ChainBackend, FundingPolicy, UtxoInfo};
use xbt402::http::HttpService;
use xbt402::hub::{HubConfig, OutChannel, RouteHub};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::route::{SpendScan, ROLLOVER_PATH, TERMS_PATH};
use xbt402::route_client::{RoutePayer, RoutePayerConfig, Shard};
use xbt402::route_seller::RouteOffer;
use xbt402::signer::LocalSigner;
use xbt402_interop::memnet::{ChainWallet, MemChain, MemNet, NetTransport};
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

const NET: &str = "bip122:11111111111111111111111111111111";
const HUB: &str = "http://hub.test";

fn sk(n: u64) -> SecretKey {
    Sc::from_u64(n).secret().unwrap()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("xbt-rs-agp087-hub-b-{}", hex::encode(&sha256(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes())[..8])));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn provider(chain: &Arc<MemChain>, net: &Arc<MemNet>, dir: &TempDir, origin: &str) -> Arc<Provider> {
    let mut cfg = ProviderConfig::new(NET);
    cfg.close_margin = 36;
    cfg.policy = FundingPolicy { min_capacity: 20_000, min_expiry_blocks: 500, max_expiry_blocks: 8_640, close_margin: 36, ..FundingPolicy::default() };
    cfg.height_ttl = Duration::ZERO;
    cfg.route_close_fee_payer = FeePayer::Payee;
    let name = origin.replace("http://", "").replace('.', "_");
    let ledger = Ledger::open(&dir.0.join(format!("prov-{name}.jsonl"))).unwrap();
    let p = Provider::new(chain.clone(), prov_secret(origin), cfg, ledger, Box::new(|_, _| 1000),
                          Box::new(|_, _, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], b"{\"ok\":1}".to_vec()))).unwrap();
    p.offer_route(RouteOffer { window: 0.3, lock_wait: 0.6, invoice_ttl: 8.0, ..RouteOffer::new("/v1/chunk", 370 * 10u128.pow(18)) });
    let p = Arc::new(p);
    net.add(origin, p.clone());
    p
}

/// A provider's payTo key, known to the tests (one signs for a hostile provider: AGP-085).
fn prov_secret(origin: &str) -> SecretKey {
    sk(0x5000 + origin.bytes().map(u64::from).sum::<u64>())
}

fn hub_cfg() -> HubConfig {
    HubConfig::from_json(&json!({"spend_final_depth": 1, "fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500, "delta": 36,
                                 "reveal_timeout": 1.0, "ch2_capacity": 100000, "ch2_expiry_blocks": 1000, "close_margin": 36,
                                 "policy": {"min_capacity": 20000, "min_expiry_blocks": 500, "max_expiry_blocks": 8640}})).unwrap()
}

type FundFn = Box<dyn Fn(&str, u64) -> Result<(String, u32)> + Send + Sync>;

/// A wallet hook: a closure over (address, sats).
struct FnWallet(FundFn);

impl Wallet for FnWallet {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        (self.0)(address, sats)
    }
}

/// The chain with `gettxout` failing for one txid (a node hiccup on one channel).
struct Flaky {
    chain: Arc<MemChain>,
    bad: Mutex<String>,
}

impl ChainBackend for Flaky {
    fn block_count(&self) -> Result<u32> {
        self.chain.block_count()
    }

    fn get_tx_out(&self, txid: &str, vout: u32, m: bool) -> Result<Option<UtxoInfo>> {
        if *self.bad.lock().unwrap() == txid {
            return Err(ChannelError::new("rpc_error", "node hiccup"));
        }
        self.chain.get_tx_out(txid, vout, m)
    }

    fn send_raw_transaction(&self, hex: &str) -> Result<String> {
        self.chain.send_raw_transaction(hex)
    }

    fn has_transaction(&self, txid: &str) -> Result<bool> {
        self.chain.has_transaction(txid)
    }
}

impl SpendScan for Flaky {
    fn find_spend(&self, txid: &str, vout: u32, from: u32) -> Result<Option<Tx>> {
        self.chain.find_spend(txid, vout, from)
    }

    fn scan_spk(&self, spk: &[u8]) -> Result<Vec<(String, u32, u64)>> {
        self.chain.scan_spk(spk)
    }

    fn fee_rate(&self, target: u32) -> Result<Option<f64>> {
        self.chain.fee_rate(target)
    }
}

type Edit = Box<dyn Fn(&str, &str, u16, &Value) -> Option<(u16, Vec<u8>)> + Send + Sync>;

/// A provider app whose answers `edit(method, path, status, doc)` may rewrite.
struct Wrap {
    app: Arc<Provider>,
    edit: Edit,
}

impl HttpService for Wrap {
    fn body_limit(&self, path: &str) -> usize {
        HttpService::body_limit(&*self.app, path)
    }

    fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str) -> HttpResponse {
        let r = HttpService::serve(&*self.app, method, path, headers, body, url);
        let doc: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        match (self.edit)(method, path, r.status, &doc) {
            Some((st, b)) => HttpResponse::new(st, vec![("Content-Type".into(), "application/json".into())], b),
            None => r,
        }
    }
}

fn wrap(net: &MemNet, origin: &str, app: &Arc<Provider>, edit: Edit) {
    net.add(origin, Arc::new(Wrap { app: app.clone(), edit }));
}

fn terms_edit(extra: Value) -> Edit {
    Box::new(move |_, p, _, doc| {
        if p != TERMS_PATH {
            return None;
        }
        let mut d = doc.clone();
        for (k, v) in extra.as_object().unwrap() {
            d["extra"][k] = v.clone();
        }
        Some((200, serde_json::to_vec(&d).unwrap()))
    })
}

fn stream(pay: &RoutePayer, sh: &Arc<Shard>, n: usize) {
    for _ in 0..n {
        let r = pay.call(sh, "POST", br#"{"tokens":1}"#).unwrap();
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    }
}

struct W {
    chain: Arc<MemChain>,
    net: Arc<MemNet>,
    hub: Arc<RouteHub>,
    provs: Vec<(String, Arc<Provider>)>,
    pay: Arc<RoutePayer>,
    shards: Vec<Arc<Shard>>,
    flaky: Arc<Flaky>,
    _dir: TempDir,
}

impl W {
    /// `n` providers with open ch2s, a client, 10 calls to p0, and (with `lock_first`) one routed
    /// lock so p0's ch2 carries a signed state.
    fn new(n: usize, lock_first: bool) -> Self {
        Self::with(n, lock_first, hub_cfg())
    }

    fn with(n: usize, lock_first: bool, cfg: HubConfig) -> Self {
        let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
        let flaky = Arc::new(Flaky { chain: chain.clone(), bad: Mutex::new(String::new()) });
        let h = Arc::new(RouteHub::new(flaky.clone(), flaky.clone(), Box::new(ChainWallet(chain.clone())), Box::new(NetTransport(net.clone())),
                                       sk(0x4B4B), NET, Some(&dir.0.join("hub")), cfg).unwrap());
        net.add(HUB, h.clone());
        let mut provs = vec![];
        for i in 0..n {
            let origin = format!("http://p{i}.test");
            provs.push((origin.clone(), provider(&chain, &net, &dir, &origin)));
            h.connect(&origin, None, None).unwrap();
        }
        chain.confirm_all();
        h.watch_tick();
        let c = chain.clone();
        let mut pc = RoutePayerConfig::new(NET);
        pc.expiry_blocks = 8_000;
        let pay = Arc::new(RoutePayer::new(HUB, pc, Arc::new(LocalSigner::new()), Arc::new(ChainWallet(chain.clone())),
                                           Box::new(NetTransport(net.clone())), Box::new(move || Ok(c.height()))));
        pay.open().unwrap();
        let shards: Vec<_> = provs.iter().map(|(o, _)| pay.shard(&format!("{o}/v1/chunk"), "POST").unwrap()).collect();
        stream(&pay, &shards[0], 10);
        let w = Self { chain, net, hub: h, provs, pay, shards, flaky, _dir: dir };
        if lock_first {
            assert_eq!(w.pay.lock(&w.shards[0]).unwrap().unwrap()["status"], "paid");
            assert!(w.oc(0).signed >= w.oc(0).params.min_amount());
        }
        w
    }

    fn origin(&self, i: usize) -> &str {
        &self.provs[i].0
    }

    fn oc(&self, i: usize) -> OutChannel {
        self.hub.out_channels()[self.origin(i)].clone()
    }

    fn events(&self, name: &str) -> Vec<Value> {
        self.hub.events.lock().unwrap().iter().filter(|e| e["event"] == name).cloned().collect()
    }

    /// The provider closes ch2 on its own (its best state), as at expiry − closeMargin.
    fn provider_closes(&self, i: usize) -> String {
        let p = &self.provs[i].1;
        let st = p.channel_ids().iter().filter_map(|c| p.channel_state(c)).find(|s| s.closed_txid.is_empty()).unwrap();
        p.close_now(&st.params.channel_id()).unwrap()
    }
}

fn has(acts: &[Value], f: impl Fn(&Value) -> bool) -> bool {
    acts.iter().any(f)
}
// --- 1b the rollover's next ch2 outlives a refusal (AGP-085) ----------------------------------------

/// A provider that takes a rollover request, keeps it (signed by the hub) and answers 400.
struct Keeps {
    app: Arc<Provider>,
    kept: Mutex<Vec<Vec<u8>>>,
}

impl HttpService for Keeps {
    fn body_limit(&self, path: &str) -> usize {
        HttpService::body_limit(&*self.app, path)
    }

    fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str) -> HttpResponse {
        if path != ROLLOVER_PATH {
            return HttpService::serve(&*self.app, method, path, headers, body, url);
        }
        self.kept.lock().unwrap().push(body.to_vec());
        HttpResponse::new(400, vec![("Content-Type".into(), "application/json".into())], br#"{"error":"bad_request","detail":"no"}"#.to_vec())
    }
}

impl W {
    /// p`i` keeps every rollover request and answers 400, until the returned handle is taken off.
    fn keeps(&self, i: usize) -> Arc<Keeps> {
        let k = Arc::new(Keeps { app: self.provs[i].1.clone(), kept: Mutex::new(vec![]) });
        self.net.add(self.origin(i), k.clone());
        k
    }

    fn honest(&self, i: usize) {
        self.net.add(self.origin(i), self.provs[i].1.clone());
    }

    /// p`i` answers 400 to a rollover it did broadcast.
    fn broadcasts_and_says_no(&self, i: usize) {
        wrap(&self.net, self.origin(i), &self.provs[i].1, Box::new(|_, p, st, _| {
            (p == ROLLOVER_PATH && st == 200).then(|| (400, br#"{"error":"bad_request","detail":"no"}"#.to_vec()))
        }));
    }

    fn next(&self, i: usize) -> Option<OutChannel> {
        let n = self.oc(i).next;
        (!n.is_empty()).then(|| OutChannel::from_json(&Value::Object(n)).unwrap())
    }

    /// The provider broadcasts the rollover of request `req` (which the hub signed) itself.
    fn provider_sends(&self, i: usize, parent: &OutChannel, req: &[u8]) -> String {
        let req: Value = serde_json::from_slice(req).unwrap();
        let p = &parent.params;
        let n = &req["next"];
        let expiry = n["expiry"].as_u64().unwrap() as u32;
        let pay_to = hex::decode(&parent.pay_to).unwrap();
        let nxt = xbt402::channel::ChannelParams::derive(&pay_to, &hex::decode(n["payerPub"].as_str().unwrap()).unwrap(), expiry, p.close_fee, None, NET,
                                                         p.close_fee_payer).unwrap();
        let amount = req["amount"].as_u64().unwrap();
        let mut tx = p.rollover_tx(amount, &nxt.spk(), p.rollover_next_capacity(amount)).unwrap();
        let digest = p.sighash(&tx).unwrap();
        let payee = xbt402::channel::channel_payee_secret(NET, &prov_secret(self.origin(i)), &p.payer_pub, p.expiry).unwrap();
        tx.inputs[0].witness = vec![hex::decode(req["sig"].as_str().unwrap()).unwrap(),
                                    xbt402::channel::sign_with_type(&payee, &digest, xbt_primitives::sighash::SIGHASH_ALL_UNIFIED), vec![0x01], p.script()];
        self.chain.send_raw_transaction(&tx.to_hex()).unwrap()
    }
}

/// The refund the hub holds for `oc` spends `oc`'s funding outpoint.
fn refund_spends_funding(oc: &OutChannel) -> bool {
    let tx = Tx::parse_hex(&oc.refund_hex).unwrap();
    (tx.inputs[0].prevout.txid_hex(), tx.inputs[0].prevout.vout) == (oc.params.funding_txid(), oc.params.funding_vout())
}


// --- AGP-087 ----------------------------------------------------------------------------------------

impl W {
    /// The rollover transaction of request `req` on `parent`, unsigned: what the hub signed for.
    fn rollover_of(&self, parent: &OutChannel, req: &[u8]) -> Tx {
        let req: Value = serde_json::from_slice(req).unwrap();
        let p = &parent.params;
        let n = &req["next"];
        let nxt = xbt402::channel::ChannelParams::derive(&hex::decode(&parent.pay_to).unwrap(), &hex::decode(n["payerPub"].as_str().unwrap()).unwrap(),
                                                         n["expiry"].as_u64().unwrap() as u32, p.close_fee, None, NET, p.close_fee_payer).unwrap();
        let amount = req["amount"].as_u64().unwrap();
        p.rollover_tx(amount, &nxt.spk(), p.rollover_next_capacity(amount)).unwrap()
    }

    /// Every unspent ch2 funding the hub's book knows, live, next or archived: (chan, sats).
    fn locked(&self) -> Vec<(String, u64)> {
        let recs: Vec<OutChannel> = self.hub.out_channels().values().cloned().chain(self.hub.next_channels().values().cloned())
            .chain(self.hub.archived().iter().filter_map(|r| OutChannel::from_json(r).ok())).collect();
        recs.iter().filter(|c| c.params.funding.is_some())
            .filter(|c| self.chain.get_tx_out(&c.params.funding_txid(), c.params.funding_vout(), true).unwrap().is_some())
            .map(|c| (c.params.channel_id(), c.params.capacity)).collect()
    }
}

/// A provider that answers a rollover 200 with the txid the hub expects and broadcasts nothing.
struct SaysRolled {
    app: Arc<Provider>,
    txid: Mutex<String>,
}

impl HttpService for SaysRolled {
    fn body_limit(&self, path: &str) -> usize {
        HttpService::body_limit(&*self.app, path)
    }

    fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str) -> HttpResponse {
        if path != ROLLOVER_PATH {
            return HttpService::serve(&*self.app, method, path, headers, body, url);
        }
        let req: Value = serde_json::from_slice(body).unwrap();
        let txid = self.txid.lock().unwrap().clone();
        let reply = json!({"chan": req["chan"], "txid": txid, "amount": req["amount"], "nextChan": format!("{txid}:1")});
        HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], serde_json::to_vec(&reply).unwrap())
    }
}

/// HOLE (from AGP-053/AGP-037, not closed by AGP-085). A 200 is the one rollover answer the hub
/// takes on the provider's word: the parent becomes `rolled` (never reconciled or refunded again)
/// and the child becomes the live ch2 at an outpoint that does not exist. A provider that says
/// "rolled" and broadcasts nothing leaves the parent's funding unspent for good: the hub never
/// sends the parent's refund, at its expiry or after. A refusal, a 5xx, a timeout or a wrong txid
/// all leave the parent live and refunded at expiry; only the honest-looking answer does not.
#[test]
fn hole_a_rollover_answered_200_and_never_broadcast_leaves_the_parent_refundable() {
    let mut cfg = hub_cfg();
    cfg.rollover_relay_grace = 0.0;
    let w = W::with(1, true, cfg);
    let oc = w.oc(0);
    w.chain.set_height(oc.params.expiry - 40);
    let k = w.keeps(0);
    assert!(w.hub.rollover(&oc).is_err());
    let txid = w.rollover_of(&oc, &k.kept.lock().unwrap()[0]).txid();
    w.net.add(w.origin(0), Arc::new(SaysRolled { app: w.provs[0].1.clone(), txid: Mutex::new(txid.clone()) }));
    let ev = w.hub.rollover(&w.oc(0)).unwrap();
    assert_eq!((ev["event"].as_str(), ev["txid"].as_str()), (Some("ch2_rollover"), Some(txid.as_str())), "{ev}");
    assert!(w.chain.spender(&oc.params.funding_txid(), oc.params.funding_vout()).is_none(), "nothing was broadcast");
    let child = w.oc(0);
    assert_eq!(child.params.funding_txid(), txid);
    w.hub.watch_tick();
    assert_eq!(w.events("ch2_rollover_vanished").len(), 1);
    // past the parent's expiry and its refund grace, then past the child's expiry too
    for h in [oc.params.expiry + 20, child.params.expiry + 20] {
        w.chain.set_height(h);
        w.hub.watch_tick();
        w.hub.watch_tick();
    }
    let parent = w.hub.archived().into_iter().find(|r| r["params"]["payer_pub"] == hex::encode(oc.params.payer_pub)).unwrap();
    assert!(w.chain.spender(&oc.params.funding_txid(), oc.params.funding_vout()).is_some(),
            "{} sat of the hub's coins are still in the parent ch2 {} blocks after its expiry: state {:?}, watched {}, refunds sent {}, locked {:?}",
            oc.params.capacity, w.chain.height() - oc.params.expiry, parent["state"], xbt402::hub::watched(&parent), w.events("ch2_refund").len(), w.locked());
}

/// A provider that keeps each rollover request with a 400 and answers a close with a txid of its
/// own invention at the amount the hub signed, broadcasting nothing.
struct NamesAClose {
    app: Arc<Provider>,
    hub: Mutex<Option<Arc<RouteHub>>>,
    origin: String,
    n: AtomicUsize,
}

impl HttpService for NamesAClose {
    fn body_limit(&self, path: &str) -> usize {
        HttpService::body_limit(&*self.app, path)
    }

    fn serve(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8], url: &str) -> HttpResponse {
        let json_ = |st: u16, v: Value| HttpResponse::new(st, vec![("Content-Type".into(), "application/json".into())], serde_json::to_vec(&v).unwrap());
        if path == ROLLOVER_PATH {
            return json_(400, json!({"error": "bad_request", "detail": "no"}));
        }
        if path.ends_with("/close") {
            let req: Value = serde_json::from_slice(body).unwrap();
            let hub = self.hub.lock().unwrap().clone().unwrap();
            let oc = hub.out_channels()[&self.origin].clone();
            assert_eq!(req["chan"], oc.params.channel_id());
            let n = self.n.fetch_add(1, Ordering::SeqCst);
            let (fee, cum) = (oc.params.payee_fee(), oc.signed);
            return json_(200, json!({"txid": hex::encode(sha256(format!("no such close {n}").as_bytes())), "cum": cum.to_string(), "payeeFee": fee,
                                     "payeeNet": cum - fee, "status": "closed"}));
        }
        HttpService::serve(&*self.app, method, path, headers, body, url)
    }
}

/// HOLE (the neighbour of AGP-085 decision 1). A refused rollover ends, one block later with the
/// default numbers, in close-and-refill. The refill is funded at once on the provider's word that
/// it closed (`check_close_reply` checks the shape of the txid and that cum is a signed state),
/// and a `closing` ch2 does not count against `liquidity_cap_sat`. A provider that names a close it
/// never sends has the hub fund one more ch2 per cycle while every earlier one stays locked until
/// its own expiry: the cap the operator set does not bound the hub's coins in ch2s.
#[test]
fn hole_a_close_the_provider_names_and_never_sends_stays_within_the_liquidity_cap() {
    let mut cfg = hub_cfg();
    cfg.ch2_expiry_blocks = 537; // = minExpiry 500 + minConf 1 + closeMargin 36: asked == floor, as with the default numbers
    cfg.liquidity_cap_sat = 200_000; // two ch2s
    let w = W::with(1, true, cfg);
    let bad = Arc::new(NamesAClose { app: w.provs[0].1.clone(), hub: Mutex::new(Some(w.hub.clone())), origin: w.origin(0).to_string(), n: AtomicUsize::new(0) });
    w.net.add(w.origin(0), bad.clone());
    let mut cycles = 0;
    for _ in 0..4 {
        let oc = w.oc(0);
        assert_eq!(oc.state, "open");
        assert!(w.hub.rollover(&oc).is_err(), "kept and refused");
        w.chain.mine(1);
        let ev = w.hub.rollover(&w.oc(0)).unwrap();
        assert_eq!(ev["event"], "ch2_close", "one block after the refusal the kept next ch2 is too old: {ev}");
        if ev.get("refillError").is_some() {
            break;
        }
        cycles += 1;
        w.chain.confirm_all();
        w.hub.watch_tick();
        assert_eq!(w.oc(0).state, "open", "the refill opened");
        stream(&w.pay, &w.shards[0], 10);
        assert_eq!(w.pay.lock(&w.shards[0]).unwrap().unwrap()["status"], "paid");
    }
    *bad.hub.lock().unwrap() = None;
    let locked = w.locked();
    let total: u64 = locked.iter().map(|l| l.1).sum();
    assert!(total <= w.hub.cfg.liquidity_cap_sat,
            "after {cycles} refused rollovers the hub has {total} sat in {} unspent ch2 fundings; liquidity_cap_sat is {} and committed_sat() says {}",
            locked.len(), w.hub.cfg.liquidity_cap_sat, w.hub.committed_sat());
}

/// Every non-200 or unusable answer to a rollover the provider DID broadcast: the watcher adopts
/// the next ch2 with its key and a refund that spends the rollover's output.
#[test]
fn ok_every_answer_to_a_rollover_the_provider_broadcast_is_adopted_with_its_refund() {
    let answers: [(&str, u16, &[u8]); 7] = [
        ("401", 401, br#"{"error":"unauthorized"}"#), ("403", 403, br#"{"error":"forbidden"}"#), ("500 not JSON", 500, b"oops"),
        ("503", 503, br#"{"error":"busy"}"#), ("200 not JSON", 200, b"<html>"), ("200 without txid", 200, br#"{"status":"rolled"}"#),
        ("200 naming another txid", 200, br#"{"txid":"abababababababababababababababababababababababababababababababab"}"#),
    ];
    for (name, st, body) in answers {
        let w = W::new(1, true);
        let oc = w.oc(0);
        w.chain.set_height(oc.params.expiry - 40);
        wrap(&w.net, w.origin(0), &w.provs[0].1, Box::new(move |_, p, s, _| (p == ROLLOVER_PATH && s == 200).then(|| (st, body.to_vec()))));
        assert!(w.hub.rollover(&oc).is_err(), "{name}");
        let spender = w.chain.spender(&oc.params.funding_txid(), oc.params.funding_vout()).expect("it did broadcast");
        assert!(w.next(0).is_some(), "{name}: the next ch2 is still written ahead");
        let acts = w.hub.watch_tick();
        assert!(has(&acts, |a| a["event"] == "ch2_rollover" && a["txid"] == spender.as_str()), "{name}: {acts:?}");
        let new = w.oc(0);
        assert!(new.params.funding_txid() == spender && !new.secret.is_empty() && refund_spends_funding(&new), "{name}");
    }
}

/// The hub's own refund of a ch2 whose rollover it was refused, racing that rollover: the refund is
/// out at expiry + grace, the provider's kept rollover confirms in its place, and the next ch2 is
/// adopted with its key and refund. Then nothing else happens to it: the hub refunds it at ITS expiry.
#[test]
fn ok_a_kept_rollover_that_beats_the_hubs_refund_is_adopted_and_refunded_at_its_own_expiry() {
    let w = W::new(1, true);
    let oc = w.oc(0);
    let k = w.keeps(0);
    assert!(w.hub.rollover(&oc).is_err());
    let req = k.kept.lock().unwrap()[0].clone();
    let kept = w.next(0).unwrap();
    w.chain.set_height(oc.params.expiry + w.hub.cfg.refund_grace_blocks);
    let acts = w.hub.watch_tick();
    assert!(has(&acts, |a| a["event"] == "ch2_refund"), "{acts:?}");
    let refund = w.chain.spender(&oc.params.funding_txid(), oc.params.funding_vout()).unwrap();
    assert!(w.next(0).is_some(), "an unconfirmed refund does not drop the next ch2");
    w.chain.evict(&refund);
    let txid = w.provider_sends(0, &oc, &req);
    w.chain.mine(1);
    let acts = w.hub.watch_tick();
    assert!(has(&acts, |a| a["event"] == "ch2_rollover" && a["txid"] == txid.as_str()), "{acts:?}");
    let child = w.oc(0);
    assert!(child.secret == kept.secret && child.params.funding_txid() == txid && refund_spends_funding(&child));
    // the hub's own refund of the child, at the child's expiry
    w.chain.set_height(child.params.expiry.max(w.chain.height()));
    for _ in 0..3 {
        w.hub.watch_tick();
    }
    let sp = w.chain.spender(&txid, 1).expect("the child is refunded at its expiry");
    let tx = w.chain.raw(&sp).unwrap();
    assert_eq!(tx.outputs.len(), 1, "a refund: {tx:?}");
}

/// The next ch2 adopted into the archive (its parent was closed and refilled meanwhile) is never
/// opened; the watcher refunds it at its expiry.
#[test]
fn ok_a_next_channel_adopted_in_the_archive_is_refunded_at_its_expiry() {
    let w = W::new(1, true);
    let oc = w.oc(0);
    let k = w.keeps(0);
    assert!(w.hub.rollover(&oc).is_err());
    let kept = w.next(0).unwrap();
    let req = k.kept.lock().unwrap()[0].clone();
    let bad = Arc::new(NamesAClose { app: w.provs[0].1.clone(), hub: Mutex::new(Some(w.hub.clone())), origin: w.origin(0).to_string(), n: AtomicUsize::new(0) });
    w.net.add(w.origin(0), bad.clone());
    w.chain.set_height(kept.params.expiry - 500);
    assert_eq!(w.hub.rollover(&w.oc(0)).unwrap()["event"], "ch2_close");
    *bad.hub.lock().unwrap() = None;
    w.honest(0);
    let txid = w.provider_sends(0, &oc, &req);
    w.chain.mine(1);
    assert!(has(&w.hub.watch_tick(), |a| a["event"] == "ch2_rollover" && a["txid"] == txid.as_str()));
    w.chain.set_height(kept.params.expiry);
    for _ in 0..3 {
        w.hub.watch_tick();
    }
    assert!(w.chain.spender(&txid, 1).is_some(), "the adopted next ch2 was refunded at its expiry; locked {:?}", w.locked());
}

/// Decision 1's arithmetic with the shipped defaults of both sides: the hub asks for exactly the
/// payer's floor, so a kept next ch2 is too old to ask under again one block after any refusal,
/// although the provider's own rollover rule (`expiry >= tip + minExpiryBlocks`) would take it for
/// another minConf + closeMarginBlocks = 145 blocks.
#[test]
fn ok_decision_1_the_default_numbers_leave_no_headroom_above_the_floor() {
    let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
    let h = RouteHub::new(chain.clone(), chain.clone(), Box::new(ChainWallet(chain.clone())), Box::new(NetTransport(net.clone())), sk(0x4B4B), NET,
                          Some(&dir.0.join("hub")), HubConfig::default()).unwrap();
    let pc = ProviderConfig::new(NET);
    let terms = json!({"payTo": "02".repeat(33), "extra": {"closeFeeSat": pc.close_fee, "minCapacity": pc.policy.min_capacity, "minConf": pc.policy.min_conf,
                       "minExpiryBlocks": pc.policy.min_expiry_blocks, "maxExpiryBlocks": pc.policy.max_expiry_blocks, "closeMarginBlocks": pc.close_margin,
                       "settleMultiple": pc.settle_multiple}});
    let (cap, blocks) = h.ch2_terms(&terms, None, None).unwrap();
    let floor = xbt402::funding::open_expiry_floor(pc.policy.min_expiry_blocks as u64, pc.policy.min_conf as u64, pc.close_margin as u64);
    // (AGP-104: the shipped `ch2_expiry_blocks` is that floor now, 1,153, where it was 1,100 and was
    // raised to it for every default seller. What is asked did not change, and neither did this)
    assert_eq!((cap, blocks as u64, floor, h.cfg.ch2_expiry_blocks), (100_000, 1_153, 1_153, 1_153));
    assert_eq!(floor - pc.policy.min_expiry_blocks as u64, 145);
}

/// `connect_next` and `promote` archive a parent as a close-and-refill does (AGP-085 left these
/// without a test): a ch2 with a kept next ch2 is replaced by its next one funded ahead, the
/// provider then broadcasts the rollover it kept, and the watcher adopts it in the archive with key
/// and refund.
#[test]
fn ok_a_rollover_kept_across_connect_next_and_promote_is_adopted() {
    let mut cfg = hub_cfg();
    cfg.settle_idle = 0.0; // the live ch2 counts as idle: its next one takes over as soon as it is open
    let w = W::with(1, true, cfg);
    let oc = w.oc(0);
    let k = w.keeps(0);
    assert!(w.hub.rollover(&oc).is_err());
    let kept = w.next(0).unwrap();
    let req = k.kept.lock().unwrap()[0].clone();
    let ahead = w.hub.connect_next(w.origin(0), None, None).unwrap();
    w.chain.confirm_all();
    for _ in 0..3 {
        w.hub.watch_tick();
    }
    assert_eq!(w.oc(0).params.payer_pub, ahead.params.payer_pub, "the next ch2 funded ahead took over: {:?}", w.events("ch2_switch"));
    let parent = w.hub.archived().into_iter().find(|r| r["params"]["payer_pub"] == hex::encode(oc.params.payer_pub)).unwrap();
    assert_eq!(parent["next"]["secret"].as_str(), Some(kept.secret.as_str()), "the kept next ch2 went to the archive with its parent");
    // retired, the parent was closed at the hub's request; that close leaves the mempool and the
    // provider sends the rollover it kept in its place
    let close = w.chain.spender(&oc.params.funding_txid(), oc.params.funding_vout()).expect("the retired parent was closed");
    assert_eq!(parent["state"], "closing");
    w.chain.evict(&close);
    let txid = w.provider_sends(0, &oc, &req);
    w.chain.mine(1);
    let mut acts = w.hub.watch_tick();
    acts.extend(w.hub.watch_tick());
    assert!(has(&acts, |a| a["event"] == "ch2_rollover" && a["txid"] == txid.as_str()), "{acts:?}");
    let arch: Vec<OutChannel> = w.hub.archived().iter().map(|r| OutChannel::from_json(r).unwrap()).collect();
    let child = arch.iter().find(|c| c.params.funding_txid() == txid).expect("the next ch2 is on the books");
    assert!(child.secret == kept.secret && refund_spends_funding(child) && xbt402::hub::watched(&child.to_json()));
}

/// K1, one step to the side: the next ch2 written ahead inside a ch2's record (and inside an
/// archived parent's) is sealed on disk like any ch2 key.
#[test]
fn ok_k1_a_next_channel_written_ahead_is_sealed_on_disk() {
    let w = W::new(1, true);
    let oc = w.oc(0);
    w.keeps(0);
    assert!(w.hub.rollover(&oc).is_err());
    let kept = w.next(0).unwrap();
    let raw = std::fs::read_to_string(w._dir.0.join("hub").join("ch2.json")).unwrap();
    assert!(raw.contains("secret_sealed") && !raw.contains(&kept.secret) && !raw.contains(&oc.secret), "a ch2 key is in ch2.json in plaintext");
    // archived with its parent (close-and-refill): still sealed
    w.honest(0);
    w.chain.set_height(kept.params.expiry - 500);
    assert_eq!(w.hub.rollover(&w.oc(0)).unwrap()["event"], "ch2_close");
    let raw = std::fs::read_to_string(w._dir.0.join("hub").join("ch2.json")).unwrap();
    let doc: Value = serde_json::from_str(&raw).unwrap();
    assert!(doc["archived"].as_array().unwrap().iter().any(|r| r["next"]["secret_sealed"].is_object()), "{}", doc["archived"]);
    assert!(!raw.contains(&kept.secret) && !raw.contains(&oc.secret) && !raw.contains(&w.oc(0).secret));
}
