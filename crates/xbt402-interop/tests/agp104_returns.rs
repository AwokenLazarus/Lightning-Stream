//! AGP-104: every coin the hub gets back reaches an address the operator controls, and the hub's
//! numbers add up. In process: [`MemChain`] + [`MemNet`], a hub wallet that counts what it holds.
//!
//! Rule R1: no coin of the hub's rests on a key only its state files know. A ch2 the hub funds
//! names a return address for its remainder; a closed ch1's payout and a ch2 remainder that an
//! older ledger left on a per-channel key are swept there.
//! Rule R2: one signed sweep per output. A sweep is written before it is sent, the same bytes are
//! sent again until the chain has them, and nothing is swept before the spend it depends on is
//! `spend_final_depth` deep.
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::adaptor::Sc;
use xbt402::channel::FeePayer;
use xbt402::client::{Wallet, WalletSend};
use xbt402::error::{ChannelError, Result};
use xbt402::funding::{ChainBackend, FundingPolicy, UtxoInfo};
use xbt402::hub::{HubConfig, OutChannel, RouteHub};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::route::{SpendScan, ROUTE_LOCK_PATH};
use xbt402::route_client::{RoutePayer, RoutePayerConfig, Shard};
use xbt402::route_seller::RouteOffer;
use xbt402::signer::LocalSigner;
use xbt402_interop::memnet::{ChainWallet, MemChain, MemNet, NetTransport};
use xbt_primitives::address::segwit_address;
use xbt_primitives::ecdsa;
use xbt_primitives::hash::sha256;
use xbt_primitives::script::p2wpkh_spk;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::{OutPoint, Tx, TxIn, TxOut};

const NET: &str = "bip122:11111111111111111111111111111111";
const HUB: &str = "http://hub.test";
/// What the test's wallet pays a miner for each funding it makes.
const FUND_FEE: u64 = 153;

fn sk(n: u64) -> SecretKey {
    Sc::from_u64(n).secret().unwrap()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("xbt-rs-agp104-{}", hex::encode(&sha256(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes())[..8])));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The operator's wallet: what was sent in (`cash`, less what it paid out) plus every unspent
/// output on the chain that pays one of the addresses it handed out.
struct OpWallet {
    chain: Arc<MemChain>,
    cash: Mutex<i64>,
    spks: Mutex<Vec<Vec<u8>>>,
    n: AtomicU64,
    /// Addresses fail while set (the wallet is locked, the node is away).
    down: Mutex<bool>,
}

impl OpWallet {
    fn new(chain: &Arc<MemChain>, deposit: u64) -> Arc<Self> {
        Arc::new(Self { chain: chain.clone(), cash: Mutex::new(deposit as i64), spks: Mutex::new(vec![]), n: AtomicU64::new(0), down: Mutex::new(false) })
    }

    fn address(&self) -> Result<String> {
        if *self.down.lock().unwrap() {
            return Err(ChannelError::new("rpc_error", "getnewaddress: wallet is not loaded"));
        }
        let spk = p2wpkh_spk(&ecdsa::pubkey(&sk(0x9000 + self.n.fetch_add(1, Ordering::Relaxed))));
        self.spks.lock().unwrap().push(spk.clone());
        Ok(segwit_address("bcrt", &spk).unwrap())
    }

    fn balance(&self) -> u64 {
        let on_chain: u64 = self.spks.lock().unwrap().iter().map(|s| self.chain.unspent_to(s)).sum();
        (*self.cash.lock().unwrap() + on_chain as i64) as u64
    }
}

struct WalletRef(Arc<OpWallet>);

impl Wallet for WalletRef {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        *self.0.cash.lock().unwrap() -= (sats + FUND_FEE) as i64;
        self.0.chain.fund(address, sats)
    }

    fn wallet_sends_to(&self, address: &str) -> Result<Vec<String>> {
        self.0.chain.wallet_sends_to(address)
    }

    fn wallet_send(&self, txid: &str, address: &str) -> Result<Option<WalletSend>> {
        self.0.chain.wallet_send(txid, address)
    }

    fn send_fee(&self, _txid: &str) -> Result<Option<u64>> {
        Ok(Some(FUND_FEE))
    }
}

/// The hub's node: the chain, refusing every broadcast while `refuse` is set.
struct Gate {
    chain: Arc<MemChain>,
    refuse: Mutex<bool>,
}

impl ChainBackend for Gate {
    fn block_count(&self) -> Result<u32> {
        self.chain.block_count()
    }

    fn get_tx_out(&self, txid: &str, vout: u32, m: bool) -> Result<Option<UtxoInfo>> {
        self.chain.get_tx_out(txid, vout, m)
    }

    fn send_raw_transaction(&self, hex: &str) -> Result<String> {
        if *self.refuse.lock().unwrap() {
            return Err(ChannelError::new("rpc_error", "the node is away"));
        }
        self.chain.send_raw_transaction(hex)
    }

    fn has_transaction(&self, txid: &str) -> Result<bool> {
        self.chain.has_transaction(txid)
    }
}

impl SpendScan for Gate {
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

fn provider(chain: &Arc<MemChain>, net: &Arc<MemNet>, dir: &TempDir, origin: &str) -> Arc<Provider> {
    let mut cfg = ProviderConfig::new(NET);
    cfg.close_margin = 36;
    cfg.policy = FundingPolicy { min_capacity: 20_000, min_expiry_blocks: 500, max_expiry_blocks: 8_640, close_margin: 36, ..FundingPolicy::default() };
    cfg.height_ttl = Duration::ZERO;
    cfg.route_close_fee_payer = FeePayer::Payee;
    let name = origin.replace("http://", "").replace('.', "_");
    let ledger = Ledger::open(&dir.0.join(format!("prov-{name}.jsonl"))).unwrap();
    let secret = sk(0x5000 + origin.bytes().map(u64::from).sum::<u64>());
    let p = Provider::new(chain.clone(), secret, cfg, ledger, Box::new(|_, _| 1000),
                          Box::new(|_, _, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], b"{\"ok\":1}".to_vec()))).unwrap();
    p.offer_route(RouteOffer { window: 0.3, lock_wait: 0.6, invoice_ttl: 8.0, ..RouteOffer::new("/v1/chunk", 500_000 * 10u128.pow(18)) });
    let p = Arc::new(p);
    net.add(origin, p.clone());
    p
}

/// The shipped depth (6) and refund grace; small channels and short expiries so a test reaches them.
fn hub_cfg(more: &Value) -> HubConfig {
    let mut c = json!({"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500, "delta": 36,
                       "reveal_timeout": 1.0, "ch2_capacity": 100000, "ch2_expiry_blocks": 1000, "close_margin": 36,
                       "policy": {"min_capacity": 20000, "min_expiry_blocks": 500, "max_expiry_blocks": 8640}});
    c.as_object_mut().unwrap().extend(more.as_object().cloned().unwrap_or_default());
    HubConfig::from_json(&c).unwrap()
}

struct W {
    chain: Arc<MemChain>,
    net: Arc<MemNet>,
    hub: Arc<RouteHub>,
    wallet: Arc<OpWallet>,
    provs: Vec<(String, Arc<Provider>)>,
    pay: Arc<RoutePayer>,
    shards: Vec<Arc<Shard>>,
    gate: Arc<Gate>,
    cfg: Value,
    dir: TempDir,
}

const DEPOSIT: u64 = 1_000_000;

impl W {
    /// A hub with `DEPOSIT` in its wallet, `n` sellers with open ch2s, one buyer with an open ch1.
    fn new(n: usize) -> Self {
        Self::with(n, json!({}), true)
    }

    /// `cfg`: hub config over the test's; `returns`: the hub has a return address (false: the
    /// library's default, and every hub before AGP-104 for what a close pays).
    fn with(n: usize, cfg: Value, returns: bool) -> Self {
        let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
        let wallet = OpWallet::new(&chain, DEPOSIT);
        let gate = Arc::new(Gate { chain: chain.clone(), refuse: Mutex::new(false) });
        let hub = Self::hub(&gate, &net, &dir, &wallet, &cfg, returns);
        net.add(HUB, hub.clone());
        let mut provs = vec![];
        for i in 0..n {
            let origin = format!("http://p{i}.test");
            provs.push((origin.clone(), provider(&chain, &net, &dir, &origin)));
            hub.connect(&origin, None, None).unwrap();
        }
        chain.confirm_all();
        hub.watch_tick();
        let c = chain.clone();
        let mut pc = RoutePayerConfig::new(NET);
        pc.expiry_blocks = 3_000;
        let pay = Arc::new(RoutePayer::new(HUB, pc, Arc::new(LocalSigner::new()), Arc::new(ChainWallet(chain.clone())),
                                           Box::new(NetTransport(net.clone())), Box::new(move || Ok(c.height()))));
        pay.open().unwrap();
        let shards: Vec<_> = provs.iter().map(|(o, _)| pay.shard(&format!("{o}/v1/chunk"), "POST").unwrap()).collect();
        Self { chain, net, hub, wallet, provs, pay, shards, gate, cfg, dir }
    }

    fn hub(gate: &Arc<Gate>, net: &Arc<MemNet>, dir: &TempDir, wallet: &Arc<OpWallet>, cfg: &Value, returns: bool) -> Arc<RouteHub> {
        let hub = Arc::new(RouteHub::new(gate.clone(), gate.clone(), Box::new(WalletRef(wallet.clone())), Box::new(NetTransport(net.clone())),
                                         sk(0x4B4B), NET, Some(&dir.0.join("hub")), hub_cfg(cfg)).unwrap());
        let w = wallet.clone();
        if returns {
            hub.set_return_to(Some(Box::new(move || w.address())));
        } else {
            // as `xbt402-hub` did before AGP-104: refunds to the wallet (AGP-037), nothing else
            hub.set_refund_to(Some(Box::new(move || w.address())));
        }
        hub
    }

    /// The hub stops and starts again on the same data dir, with a return address.
    fn restart(&mut self) {
        // the old hub goes first: it holds the ledger's lock
        let idle = Arc::new(RouteHub::new(self.gate.clone(), self.gate.clone(), Box::new(WalletRef(self.wallet.clone())), Box::new(NetTransport(self.net.clone())),
                                          sk(0x4B4C), NET, None, hub_cfg(&json!({}))).unwrap());
        self.net.add(HUB, idle.clone());
        self.hub = idle;
        self.hub = Self::hub(&self.gate, &self.net, &self.dir, &self.wallet, &self.cfg, true);
        self.net.add(HUB, self.hub.clone());
    }

    fn calls(&self, i: usize, calls: usize) {
        for _ in 0..calls {
            let r = self.pay.call(&self.shards[i], "POST", br#"{"tokens":1}"#).unwrap();
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        }
    }

    fn oc(&self, i: usize) -> OutChannel {
        self.hub.out_channels()[&self.provs[i].0].clone()
    }

    fn ch1(&self) -> String {
        self.pay.chan().unwrap()
    }

    /// The sweep ch1's ledger holds written ahead.
    fn ch1_sweep(&self) -> Option<Value> {
        self.hub.ch1_state(&self.ch1()).unwrap().extra.get("payee_sweep_intent").cloned()
    }

    fn mine_tick(&self) -> Vec<Value> {
        self.chain.mine(1);
        self.hub.watch_tick()
    }

    /// Pay seller `i` for `calls` requests and settle them with one routed lock.
    fn pay_seller(&self, i: usize, calls: usize) {
        self.calls(i, calls);
        assert_eq!(self.pay.lock(&self.shards[i]).unwrap().unwrap()["status"], "paid");
    }

    fn seller_closes(&self, i: usize) -> String {
        let p = &self.provs[i].1;
        let st = p.channel_ids().iter().filter_map(|c| p.channel_state(c)).find(|s| s.closed_txid.is_empty()).unwrap();
        p.close_now(&st.params.channel_id()).unwrap()
    }

    /// `n` blocks, the watcher looking after each.
    fn blocks(&self, n: u32) -> Vec<Value> {
        let mut acts = self.hub.watch_tick();
        for _ in 0..n {
            self.chain.mine(1);
            acts.extend(self.hub.watch_tick());
        }
        acts
    }

    fn records(&self) -> Vec<OutChannel> {
        let mut v: Vec<OutChannel> = self.hub.out_channels().into_values().chain(self.hub.next_channels().into_values()).collect();
        v.extend(self.hub.archived().iter().filter_map(|r| OutChannel::from_json(r).ok()));
        v
    }

    /// Sats on keys only the hub's state files know: each ch2's own payer key, each ch1's payee key.
    fn on_channel_keys(&self) -> (u64, u64) {
        let ch2: u64 = self.records().iter().map(|c| self.chain.unspent_to(&p2wpkh_spk(&c.params.payer_pub))).sum();
        let ch1: u64 = self.hub.inbound.channel_ids().iter().filter_map(|c| self.hub.ch1_state(c)).map(|s| self.chain.unspent_to(&s.params.payee_spk)).sum();
        (ch2, ch1)
    }

    fn events(&self, name: &str) -> Vec<Value> {
        self.hub.events.lock().unwrap().iter().filter(|e| e["event"] == name).cloned().collect()
    }

    fn status(&self) -> Value {
        self.hub.status(Some(self.wallet.balance()))
    }
}

fn n(v: &Value, k: &str) -> i64 {
    v[k].as_i64().unwrap_or_else(|| panic!("{k} in {v}"))
}

/// The four numbers add up to deposits plus fees earned less what the chain cost, to the sat, and
/// nothing in them is an estimate.
fn reconciles(w: &W, at: &str) -> Value {
    let s = w.status();
    let four = n(&s, "capitalSat") + n(&s, "inChannelsSat") + n(&s, "earnedSat") + n(&s, "stuckSat");
    assert_eq!(four, n(&s, "totalSat"), "{at}: {s}");
    assert_eq!(four, DEPOSIT as i64 + n(&s, "feesEarnedSat") - n(&s, "chainFeesSat") - n(&s, "dustSat"), "{at}: {s}");
    assert_eq!(n(&s, "depositsSat"), DEPOSIT as i64, "{at}: {s}");
    assert_eq!((s["estimated"].clone(), s["unsettled"].clone()), (json!(false), json!(false)), "{at}: {s}");
    s
}

// --- the full cycle ---------------------------------------------------------------------------------

#[test]
fn full_cycle_leaves_no_coin_on_a_channel_key_and_the_numbers_add_up() {
    // fund (two sellers), route, seller close, buyer close, refund
    let w = W::new(2);
    let s = reconciles(&w, "funded");
    assert_eq!((n(&s, "inChannelsSat"), n(&s, "chainFeesSat")), (200_000, 2 * FUND_FEE as i64));
    w.pay_seller(0, 10);
    let s = reconciles(&w, "routed");
    assert!(n(&s, "feesEarnedSat") > 0 && n(&s, "earnedSat") > 0, "{s}");
    w.seller_closes(0);
    w.blocks(7);
    reconciles(&w, "seller closed");
    assert!(w.pay.close().unwrap()["txid"].is_string());
    w.blocks(14);
    reconciles(&w, "buyer closed");
    // the seller never paid is refunded at its ch2's expiry
    let exp = w.hub.out_channels()[&w.provs[1].0].params.expiry;
    w.chain.set_height(exp);
    w.blocks(8);
    let s = reconciles(&w, "refunded");
    let (ch2, ch1) = w.on_channel_keys();
    assert_eq!((ch2, ch1), (0, 0), "sats left on per-channel keys (ch2 payer keys, ch1 payee keys)");
    // everything is back in the wallet: the deposit, plus the fees, less the chain's
    assert_eq!((n(&s, "inChannelsSat"), n(&s, "earnedSat"), n(&s, "stuckSat")), (0, 0, 0), "{s}");
    assert_eq!(w.wallet.balance() as i64, DEPOSIT as i64 + n(&s, "feesEarnedSat") - n(&s, "chainFeesSat"), "{s}");
    assert_eq!(w.events("ch1_swept").len(), 1, "{:?}", w.hub.events.lock().unwrap());
}

fn has(acts: &[Value], name: &str) -> bool {
    acts.iter().any(|a| a["event"] == name)
}

// --- R1: every funded ch2 names a return address -----------------------------------------------------

#[test]
fn a_ch2_names_a_return_address_when_it_is_funded_funded_ahead_and_rolled_over() {
    // (settle_lock_multiple 0: the ch2 rolls over at the seller's threshold)
    let w = W::with(1, json!({"settle_lock_multiple": 0}), true);
    let ours = |spk: &[u8]| w.wallet.spks.lock().unwrap().iter().any(|s| s == spk);
    let oc = w.oc(0);
    assert!(ours(&oc.params.payer_spk) && !xbt402::hub::own_key(&oc.params), "open: {}", hex::encode(&oc.params.payer_spk));
    // the seller holds the same script: its close pays it
    let p = &w.provs[0].1;
    assert_eq!(p.channel_state(&oc.params.channel_id()).unwrap().params.payer_spk, oc.params.payer_spk);
    let nxt = w.hub.connect_next(&w.provs[0].0, None, None).unwrap();
    assert!(ours(&nxt.params.payer_spk), "funded ahead");
    w.pay_seller(0, 30);
    let acts = w.hub.watch_tick();
    assert!(has(&acts, "ch2_rollover"), "{acts:?}");
    let child = w.oc(0);
    assert_eq!(child.rolled_from, oc.params.channel_id());
    assert_eq!(child.params.payer_spk, oc.params.payer_spk, "rollover: the next ch2 returns where its parent does");
    w.blocks(7);
    reconciles(&w, "rolled over");
}

#[test]
fn a_return_address_that_fails_funds_nothing() {
    let w = W::new(1);
    let (before, cash) = (w.records().len(), *w.wallet.cash.lock().unwrap());
    *w.wallet.down.lock().unwrap() = true;
    provider(&w.chain, &w.net, &w.dir, "http://late.test");
    let e = w.hub.connect("http://late.test", None, None).unwrap_err();
    assert_eq!(e.code, "return_address", "{e}");
    assert_eq!(w.hub.connect_next(&w.provs[0].0, None, None).unwrap_err().code, "return_address");
    assert_eq!((w.records().len(), *w.wallet.cash.lock().unwrap()), (before, cash), "no record, nothing paid");
    // the ch2s it has go on routing
    w.pay_seller(0, 10);
    *w.wallet.down.lock().unwrap() = false;
    assert_eq!(w.hub.connect("http://late.test", None, None).unwrap().state, "funded");
}

#[test]
fn a_bad_return_address_is_refused_before_anything_is_funded() {
    let w = W::new(0);
    provider(&w.chain, &w.net, &w.dir, "http://p0.test");
    // taproot: a seller takes it as a payerSpk, a sweep cannot pay it
    let p2tr = segwit_address("bcrt", &[&[0x51, 0x20][..], &[7u8; 32][..]].concat()).unwrap();
    for bad in ["", "not-an-address", p2tr.as_str()] {
        let b = bad.to_string();
        w.hub.set_return_to(Some(Box::new(move || Ok(b.clone()))));
        assert_eq!(w.hub.connect("http://p0.test", None, None).unwrap_err().code, "return_address", "{bad:?}");
    }
    assert!(w.records().is_empty());
}

// --- R1 + R2: the sweep of a closed ch1 --------------------------------------------------------------

/// A hub, one seller paid 5,000 sat through it, and the buyer's ch1 closed (in the mempool).
fn closed_ch1() -> (W, String) {
    let w = W::new(1);
    w.pay_seller(0, 10);
    let close = w.pay.close().unwrap()["txid"].as_str().unwrap().to_string();
    (w, close)
}

#[test]
fn nothing_is_swept_before_the_close_is_final() {
    let (w, close) = closed_ch1();
    for depth in 1..=3 {
        w.mine_tick();
        assert!(w.ch1_sweep().is_none(), "swept {depth} deep");
    }
    // the block with the close is replaced: its depth starts again
    w.chain.unconfirm(&close);
    for depth in 1..=5 {
        w.mine_tick();
        assert!(w.ch1_sweep().is_none(), "swept {depth} deep after the reorg");
    }
    let acts = w.mine_tick();
    assert!(has(&acts, "ch1_sweep"), "{acts:?}");
    let sw = w.ch1_sweep().unwrap();
    assert_eq!(w.chain.spender(&close, 0).as_deref(), sw["txid"].as_str(), "the close's payee output is spent by the sweep");
    // the sweep itself is final only at the same depth
    for _ in 0..5 {
        assert!(!has(&w.mine_tick(), "ch1_swept"));
    }
    assert!(has(&w.mine_tick(), "ch1_swept"));
    assert_eq!(w.on_channel_keys(), (0, 0));
    reconciles(&w, "swept");
    // and nothing looks at it again
    let calls = w.hub.events.lock().unwrap().len();
    w.blocks(3);
    assert_eq!(w.hub.events.lock().unwrap().len(), calls);
}

#[test]
fn a_failed_sweep_is_sent_again_with_the_same_bytes_and_never_signed_again() {
    let (w, close) = closed_ch1();
    w.blocks(5);
    *w.gate.refuse.lock().unwrap() = true;
    let acts = w.mine_tick();
    assert!(!has(&acts, "ch1_sweep") && w.events("sweep_error").len() == 1, "{acts:?}");
    let first = w.ch1_sweep().expect("written ahead of the send that failed");
    assert_eq!(w.chain.spender(&close, 0), None, "control: nothing reached the chain");
    // the hub stops and starts; fees rise; the wallet hands out another address: none of it
    // makes a second sweep of the same output
    let mut w = w;
    w.restart();
    w.chain.set_fee_rate(Some(9.0));
    let acts = w.mine_tick();
    assert!(has(&acts, "ch1_sweep_failed"), "still refused: {acts:?}");
    *w.gate.refuse.lock().unwrap() = false;
    let acts = w.mine_tick();
    assert!(has(&acts, "ch1_sweep_resent"), "{acts:?}");
    assert_eq!(w.ch1_sweep().unwrap(), first, "the sweep written ahead is unchanged");
    assert_eq!(w.chain.spender(&close, 0).as_deref(), first["txid"].as_str());
    // the operator's tool on the same channel gets the same sweep, whatever it asks for
    let other = w.hub.inbound.sweep_payee(&w.ch1(), &p2wpkh_spk(&ecdsa::pubkey(&sk(77))), 999).unwrap();
    assert_eq!(other["txid"], first["txid"]);
    w.blocks(6);
    assert_eq!((w.events("ch1_swept").len(), w.on_channel_keys()), (1, (0, 0)));
    reconciles(&w, "swept after a failure");
}

#[test]
fn a_sweep_that_leaves_the_mempool_goes_out_again() {
    let (w, close) = closed_ch1();
    w.blocks(6);
    let sw = w.ch1_sweep().unwrap();
    let txid = sw["txid"].as_str().unwrap();
    w.chain.evict(txid);
    assert_eq!(w.chain.spender(&close, 0), None);
    let acts = w.mine_tick();
    assert!(has(&acts, "ch1_sweep_resent"), "{acts:?}");
    assert_eq!(w.chain.spender(&close, 0).as_deref(), Some(txid));
    // in a block, then that block is replaced: it waits, and is final six deep, not before
    w.mine_tick();
    w.chain.unconfirm(txid);
    for _ in 0..5 {
        assert!(!has(&w.mine_tick(), "ch1_swept"));
    }
    assert!(has(&w.mine_tick(), "ch1_swept"));
}

#[test]
fn a_wallet_that_spends_the_swept_coin_at_once_does_not_leave_the_sweep_open() {
    let (w, _) = closed_ch1();
    w.blocks(6);
    let sw = w.ch1_sweep().unwrap();
    let (txid, value) = (sw["txid"].as_str().unwrap(), sw["swept"].as_u64().unwrap());
    w.mine_tick();
    // the wallet funds something with it: the sweep's output is gone from the UTXO set
    let dest = hex::decode(sw["dest_spk"].as_str().unwrap()).unwrap();
    let key = (0..64).map(|i| sk(0x9000 + i)).find(|k| p2wpkh_spk(&ecdsa::pubkey(k)) == dest).unwrap();
    let mut tx = Tx::new(2, vec![TxIn::new(OutPoint::from_display(txid, 0).unwrap(), 0xFFFF_FFFD)], vec![TxOut::new(value as i64 - 200, p2wpkh_spk(&ecdsa::pubkey(&sk(88))))], 0);
    xbt402::channel::sign_p2wpkh(&key, &mut tx, &[TxOut::new(value as i64, dest)], 0).unwrap();
    w.chain.send_raw_transaction(&tx.to_hex()).unwrap();
    let mut acts = vec![];
    for _ in 0..7 {
        acts.extend(w.mine_tick());
    }
    assert!(has(&acts, "ch1_swept"), "{acts:?}");
    assert!(!has(&acts, "ch1_sweep_resent") && !has(&acts, "ch1_sweep_failed"), "{acts:?}");
}

#[test]
fn a_payout_under_the_cost_of_a_sweep_is_left_and_counted() {
    // one call of 500 sat: ch1 closes at its dust floor
    let w = W::new(1);
    w.pay_seller(0, 1);
    w.pay.close().unwrap();
    let acts = w.blocks(7);
    assert!(has(&acts, "ch1_sweep_skipped") && !has(&acts, "ch1_sweep"), "546 < 110 + 546: never worth a sweep: {acts:?}");
    let s = reconciles(&w, "left");
    assert_eq!((n(&s, "dustSat"), n(&s, "earnedSat"), n(&s, "sweepsPending")), (546, 0, 0), "{s}");
    assert_eq!(w.on_channel_keys(), (0, 546), "it stays on the ch1's key, and the status says so");
}

#[test]
fn a_payout_the_fee_is_too_high_for_now_waits_for_a_lower_fee() {
    let w = W::new(1);
    w.pay_seller(0, 2);
    w.pay.close().unwrap();
    w.mine_tick(); // (the close confirms first, as in B1's test, whose node would bump an unconfirmed close at this rate)
    w.chain.set_fee_rate(Some(9.0));
    let acts = w.blocks(7);
    assert!(!has(&acts, "ch1_sweep") && !has(&acts, "ch1_sweep_skipped"), "about 1,000 sat does not bear 990: {acts:?}");
    let s = reconciles(&w, "waiting for a lower fee");
    assert_eq!(n(&s, "sweepsPending"), 1, "{s}");
    assert!(n(&s, "earnedSat") > 656 && n(&s, "earnedSat") < 1_536, "{s}");
    w.chain.set_fee_rate(None);
    assert!(has(&w.mine_tick(), "ch1_sweep"));
    w.blocks(6);
    assert_eq!(w.on_channel_keys(), (0, 0));
    reconciles(&w, "swept");
}

#[test]
fn a_payout_this_node_never_shows_is_given_up_and_one_that_is_there_but_shallow_is_waited_for() {
    // the close's output is not on this node (the payer's refund took the funding instead)
    let (w, close) = closed_ch1();
    w.chain.hide_outputs(&close);
    let exp = w.hub.ch1_state(&w.ch1()).unwrap().params.expiry;
    w.chain.set_height(exp + 143);
    assert!(!has(&w.mine_tick(), "ch1_sweep_skipped"), "not before 144 blocks past the expiry");
    assert!(has(&w.mine_tick(), "ch1_sweep_skipped"));
    assert_eq!(n(&w.status(), "sweepsPending"), 0);
    // a close that is on the chain but not six deep at that height is waited for, and swept
    let (w, _) = closed_ch1();
    let exp = w.hub.ch1_state(&w.ch1()).unwrap().params.expiry;
    w.chain.set_height(exp + 150);
    let acts = w.blocks(5);
    assert!(!has(&acts, "ch1_sweep_skipped") && !has(&acts, "ch1_sweep"), "{acts:?}");
    assert!(has(&w.blocks(1), "ch1_sweep"));
}

// --- a ledger from before AGP-104 ---------------------------------------------------------------------

#[test]
fn without_a_return_address_nothing_is_swept() {
    // the library's default, and what `xbt402-hub` did before AGP-104
    let w = W::with(1, json!({}), false);
    w.pay_seller(0, 10);
    w.seller_closes(0);
    w.pay.close().unwrap();
    w.blocks(20);
    let (ch2, ch1) = w.on_channel_keys();
    assert!(ch2 > 90_000 && ch1 > 5_000, "{ch2} {ch1}");
    assert!(w.events("ch1_sweep").is_empty() && w.events("ch2_sweep").is_empty());
    // the status counts them where they are: still the hub's, not in the wallet
    let s = reconciles(&w, "no return address");
    assert_eq!((n(&s, "inChannelsSat"), n(&s, "earnedSat"), s["returns"].clone()), (ch2 as i64, ch1 as i64, json!(false)), "{s}");
}

#[test]
fn a_ledger_from_before_is_swept_refunded_and_rolled_to_the_return_address() {
    // three sellers funded by a hub with no return address: one closes, one is never paid, one is paid on
    let mut w = W::with(3, json!({"settle_lock_multiple": 0}), false);
    assert!(w.records().iter().all(|c| xbt402::hub::own_key(&c.params)), "control: each ch2 names its own key");
    w.pay_seller(0, 10);
    w.seller_closes(0);
    w.pay.close().unwrap();
    w.blocks(20);
    let (ch2, ch1) = w.on_channel_keys();
    assert!(ch2 > 90_000 && ch1 > 5_000);
    // upgrade
    w.restart();
    let acts = w.mine_tick();
    assert!(has(&acts, "ch1_sweep") && has(&acts, "ch2_sweep"), "{acts:?}");
    reconciles(&w, "sweeps out");
    let acts = w.blocks(6);
    assert!(has(&acts, "ch1_swept") && has(&acts, "ch2_swept"), "{acts:?}");
    assert_eq!(w.on_channel_keys(), (0, 0));
    // the ch2 never paid is refunded to a return address, not to its own key
    let exp = w.oc(1).params.expiry;
    w.chain.set_height(exp);
    let acts = w.blocks(8);
    assert!(has(&acts, "ch2_refund_confirmed"), "{acts:?}");
    assert_eq!(w.on_channel_keys(), (0, 0));
    let s = reconciles(&w, "refunded");
    assert_eq!(n(&s, "sweepsPending"), 0, "{s}");
}

#[test]
fn a_ch2_on_its_own_key_rolls_over_into_one_that_names_a_return_address() {
    let mut w = W::with(1, json!({"settle_lock_multiple": 0}), false);
    w.restart();
    w.pay_seller(0, 30);
    let acts = w.hub.watch_tick();
    assert!(has(&acts, "ch2_rollover"), "{acts:?}");
    let child = w.oc(0);
    assert!(!xbt402::hub::own_key(&child.params) && w.wallet.spks.lock().unwrap().contains(&child.params.payer_spk));
}

#[test]
fn a_stop_between_the_write_and_the_send_leaves_one_sweep_that_the_next_start_sends() {
    let mut w = W::with(1, json!({}), false);
    w.pay_seller(0, 10);
    w.seller_closes(0);
    w.blocks(7);
    let key = p2wpkh_spk(&w.records()[0].params.payer_pub);
    let held = w.chain.unspent_to(&key);
    assert!(held > 90_000);
    w.restart();
    w.hub.set_stop("sweep");
    w.mine_tick();
    assert_eq!(w.chain.unspent_to(&key), held, "control: stopped before the send");
    let first = w.records()[0].sweep.clone();
    assert!(first.get("hex").is_some(), "written ahead: {first:?}");
    w.restart();
    let acts = w.mine_tick();
    assert!(has(&acts, "ch2_sweep_resent"), "{acts:?}");
    assert_eq!(w.records()[0].sweep.get("txid"), first.get("txid"));
    let acts = w.blocks(6);
    assert!(has(&acts, "ch2_swept"), "{acts:?}");
    assert_eq!(w.chain.unspent_to(&key), 0);
    reconciles(&w, "swept");
}

// --- status ------------------------------------------------------------------------------------------

#[test]
fn a_lock_without_an_answer_is_stuck_with_the_block_by_which_it_resolves() {
    let w = W::new(2);
    w.pay_seller(0, 10);
    w.net.set_drop(&w.provs[0].0, Some(Box::new(|_, p| p == ROUTE_LOCK_PATH)));
    w.calls(0, 10);
    let r = w.pay.lock(&w.shards[0]).unwrap().unwrap();
    assert_eq!((r["status"].as_str(), r["error"].as_str()), (Some("refused"), Some("route_failed")), "{r}");
    let s = reconciles(&w, "a lock written off");
    let oc = w.oc(0);
    assert_eq!(s["stuck"].as_array().unwrap().len(), 1, "{s}");
    let one = &s["stuck"][0];
    assert_eq!((one["seller"].as_str(), one["kind"].as_str(), one["amountSat"].as_u64()), (Some(w.provs[0].0.as_str()), Some("written off"), Some(5_000)), "{one}");
    assert_eq!(n(&s, "stuckSat"), 5_000, "what the seller may still take of the hub's side");
    // at the latest: its ch2's refund (expiry + grace), six blocks deep
    assert_eq!(one["resolvesBy"].as_u64(), Some(oc.params.expiry as u64 + 6 + 6), "{one}");
    assert!(one.get("ch1").is_none() && one.get("chan").is_none(), "a buyer's channel is not shown");
    // the seller closes with the lock: the hub reads the secret, and nothing is stuck
    w.net.set_drop(&w.provs[0].0, None);
    w.seller_closes(0);
    w.blocks(7);
    let s = reconciles(&w, "resolved");
    assert_eq!((n(&s, "stuckSat"), s["stuck"].as_array().unwrap().len()), (0, 0), "{s}");
}

#[test]
fn the_seller_list_and_the_capital_setting_are_in_the_status() {
    let w = W::with(2, json!({"capital_sat": 300_000}), true);
    let s = w.status();
    assert_eq!((s["capitalSetting"].as_u64(), s["liquidityCapSat"].as_u64(), s["committedSat"].as_u64()), (Some(300_000), Some(300_000), Some(200_000)));
    let sellers = s["sellers"].as_array().unwrap();
    assert_eq!(sellers.len(), 2);
    assert_eq!((sellers[0]["origin"].as_str(), sellers[0]["state"].as_str(), sellers[0]["capacitySat"].as_u64()), (Some("http://p0.test"), Some("open"), Some(100_000)));
    assert_eq!(s["payTo"].as_str(), Some(w.hub.pay_to()));
    // without the wallet the sums that need it are not guessed
    let s = w.hub.status(None);
    assert!(s["capitalSat"].is_null() && s["totalSat"].is_null() && s["depositsSat"].is_null(), "{s}");
    assert_eq!(n(&s, "inChannelsSat"), 200_000);
}

// --- capital ---------------------------------------------------------------------------------------------

#[test]
fn capital_admits_sellers_while_a_channel_and_one_spare_fit() {
    // 300,000 of capital, 100,000 a ch2: two sellers, and the third would take the spare
    let w = W::with(2, json!({"capital_sat": 300_000}), true);
    provider(&w.chain, &w.net, &w.dir, "http://p2.test");
    let e = w.hub.connect("http://p2.test", None, None).unwrap_err();
    assert_eq!(e.code, "liquidity_cap");
    assert!(e.to_string().contains("capital_sat 300000") && e.to_string().contains("kept for funding ahead"), "{e}");
    // the spare is what funding ahead uses, for one seller at a time
    assert_eq!(w.hub.connect_next(&w.provs[0].0, None, None).unwrap().state, "funded");
    assert_eq!(w.hub.connect_next(&w.provs[1].0, None, None).unwrap_err().code, "liquidity_cap");
    assert_eq!(w.hub.committed_sat(), 300_000);
}

#[test]
fn capital_is_one_setting() {
    let cfg = |v: Value| HubConfig::from_json(&v);
    assert_eq!(cfg(json!({"capital_sat": 500_000})).unwrap().liquidity_cap(), 500_000);
    assert_eq!(cfg(json!({"liquidity_cap_sat": 400_000})).unwrap().liquidity_cap(), 400_000, "as before");
    assert_eq!(cfg(json!({"capital_sat": 500_000, "liquidity_cap_sat": 500_000})).unwrap().liquidity_cap(), 500_000);
    assert_eq!(cfg(json!({"capital_sat": 500_000, "liquidity_cap_sat": 400_000})).unwrap_err().code, "bad_config");
    // one ch2 and its spare must fit (the shipped ch2 is 100,000)
    assert_eq!(cfg(json!({"capital_sat": 199_999})).unwrap_err().code, "bad_config");
    assert!(cfg(json!({"capital_sat": 200_000})).is_ok());
    // with funding ahead off there is no spare to keep
    let c = cfg(json!({"capital_sat": 100_000, "refill_ahead_locks": 0})).unwrap();
    assert_eq!((c.liquidity_cap(), c.spare_sat()), (100_000, 0));
}

#[test]
fn the_shipped_ch2_expiry_clears_a_default_sellers_floor() {
    // a seller's default terms: minExpiryBlocks 1,008, minConf 1, closeMarginBlocks 144
    let floor = xbt402::funding::open_expiry_floor(1_008, 1, 144);
    assert_eq!((floor, HubConfig::default().ch2_expiry_blocks as u64), (1_153, 1_153));
}
