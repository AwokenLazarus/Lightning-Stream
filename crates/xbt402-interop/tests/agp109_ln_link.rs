//! AGP-109: the hub beside a Lightning node. In process: [`MemChain`] + [`MemNet`], a real hub,
//! sellers and buyers, the link ([`LnLink`]) with a Lightning node that is a key and a counter.
//!
//! L1: a coin goes to the Lightning wallet only at an address the node gave, until the chain shows
//! it used. L2: only when the hub still holds its capital without it. L3: the link never stands
//! between the hub and the chain. I1: a payer treats a hub as node N's only on N's signed
//! statement for the hub key and network in front of it, not run out.
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::adaptor::Sc;
use xbt402::channel::FeePayer;
use xbt402::client::{Wallet, WalletSend};
use xbt402::error::{ChannelError, Result};
use xbt402::funding::FundingPolicy;
use xbt402::hub::{HubConfig, OutChannel, RouteHub};
use xbt402::hub_identity::{self, LIFE_SECS};
use xbt402::ledger::Ledger;
use xbt402::ln_wallet::{LinkConfig, LnLink, LnNode, Look};
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::route_client::{RoutePayer, RoutePayerConfig, Shard};
use xbt402::route_seller::RouteOffer;
use xbt402::signer::LocalSigner;
use xbt402_interop::memnet::{ChainWallet, MemChain, MemNet, NetTransport};
use xbt_primitives::address::segwit_address;
use xbt_primitives::ecdsa;
use xbt_primitives::hash::sha256;
use xbt_primitives::script::p2wpkh_spk;
use xbt_primitives::secp256k1::SecretKey;

const NET: &str = "bip122:11111111111111111111111111111111";
const HUB: &str = "http://hub.test";
/// What the test's wallet pays a miner for each funding it makes.
const FUND_FEE: u64 = 153;
const DEPOSIT: u64 = 1_000_000;

fn sk(n: u64) -> SecretKey {
    Sc::from_u64(n).secret().unwrap()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("xbt-rs-agp109-{}", hex::encode(&sha256(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes())[..8])));
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


/// The operator's Lightning node: its key signs, its on-chain wallet hands out addresses.
#[derive(Clone)]
struct Node {
    key: SecretKey,
    chain: Arc<MemChain>,
    spks: Arc<Mutex<Vec<Vec<u8>>>>,
    n: Arc<AtomicU64>,
    down: Arc<AtomicBool>,
    asked: Arc<AtomicU64>,
}

impl Node {
    fn new(chain: &Arc<MemChain>, key: u64) -> Self {
        Self { key: sk(key), chain: chain.clone(), spks: Arc::default(), n: Arc::new(AtomicU64::new(0)), down: Arc::default(), asked: Arc::default() }
    }

    fn id(&self) -> String {
        hex::encode(ecdsa::pubkey(&self.key))
    }

    /// What the node's on-chain wallet holds.
    fn balance(&self) -> u64 {
        self.spks.lock().unwrap().iter().map(|s| self.chain.unspent_to(s)).sum()
    }

    fn ask(&self) -> Result<()> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        if self.down.load(Ordering::SeqCst) {
            return Err(ChannelError::new("ln_link", "the Lightning node is not reachable: stopped"));
        }
        Ok(())
    }
}

impl LnNode for Node {
    fn new_address(&self) -> Result<String> {
        self.ask()?;
        let spk = p2wpkh_spk(&ecdsa::pubkey(&sk(0x7000 + self.n.fetch_add(1, Ordering::SeqCst))));
        self.spks.lock().unwrap().push(spk.clone());
        Ok(segwit_address("bcrt", &spk).unwrap())
    }

    fn sign_message(&self, msg: &[u8]) -> Result<String> {
        self.ask()?;
        Ok(hub_identity::ln_sign(msg, &self.key))
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// A buyer's wallet that counts what it funds.
struct Counting(ChainWallet, Arc<AtomicU64>);

impl Wallet for Counting {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        self.1.fetch_add(1, Ordering::SeqCst);
        self.0.fund(address, sats)
    }

    fn knows_its_sends(&self) -> bool {
        self.0.knows_its_sends()
    }

    fn wallet_sends_to(&self, address: &str) -> Result<Vec<String>> {
        self.0.wallet_sends_to(address)
    }

    fn wallet_send(&self, txid: &str, address: &str) -> Result<Option<WalletSend>> {
        self.0.wallet_send(txid, address)
    }
}

struct Buyer {
    pay: Arc<RoutePayer>,
    shards: Vec<Arc<Shard>>,
}

struct W {
    chain: Arc<MemChain>,
    net: Arc<MemNet>,
    hub: Arc<RouteHub>,
    wallet: Arc<OpWallet>,
    provs: Vec<(String, Arc<Provider>)>,
    node: Node,
    link: Option<Arc<LnLink>>,
    capital: u64,
    /// How many channels buyers funded.
    funded: Arc<AtomicU64>,
    dir: TempDir,
}

impl W {
    /// A hub with `DEPOSIT` in its wallet and `capital` as its capital (0: none set), `n` sellers
    /// with open ch2s, and (with `linked`) the link to a Lightning node, looked at once.
    fn new(n: usize, capital: u64, linked: bool) -> Self {
        let (chain, net, dir) = (MemChain::new(1000), MemNet::new(), TempDir::new());
        let wallet = OpWallet::new(&chain, DEPOSIT);
        let node = Node::new(&chain, 0x1001);
        let mut w = Self { hub: Self::hub(&chain, &net, &dir, &wallet, capital), chain, net, wallet, provs: vec![], node, link: None, capital, funded: Arc::default(), dir };
        w.net.add(HUB, w.hub.clone());
        for i in 0..n {
            let origin = format!("http://p{i}.test");
            w.provs.push((origin.clone(), provider(&w.chain, &w.net, &w.dir, &origin)));
            w.hub.connect(&origin, None, None).unwrap();
        }
        w.chain.confirm_all();
        w.hub.watch_tick();
        if linked {
            w.link_up();
        }
        w
    }

    fn hub(chain: &Arc<MemChain>, net: &Arc<MemNet>, dir: &TempDir, wallet: &Arc<OpWallet>, capital: u64) -> Arc<RouteHub> {
        let cfg = if capital > 0 { json!({"capital_sat": capital}) } else { json!({}) };
        let hub = Arc::new(RouteHub::new(chain.clone(), chain.clone(), Box::new(WalletRef(wallet.clone())), Box::new(NetTransport(net.clone())),
                                         sk(0x4B4B), NET, Some(&dir.0.join("hub")), hub_cfg(&cfg)).unwrap());
        let w = wallet.clone();
        hub.set_return_to(Some(Box::new(move || w.address())));
        hub
    }

    /// The link as `xbt402-hub` sets it up: opened on the hub's data, hooked in front of the
    /// hub's own return address, and looked at once.
    fn link_up(&mut self) {
        let cfg = LinkConfig { hrp: "bcrt".into(), network: NET.into(), pay_to: self.hub.pay_to().to_string(), cert: "cert".into() };
        let link = Arc::new(LnLink::open(Box::new(self.node.clone()), cfg, Some(&self.dir.0)).unwrap());
        let l = link.clone();
        self.hub.set_return_above(Some(Arc::new(move |sat| l.return_above(sat))));
        self.link = Some(link);
        self.look();
    }

    /// One round of the link's thread, as `xbt402-hub` runs it.
    fn look(&self) -> Vec<String> {
        let link = self.link.as_ref().unwrap();
        let paid = self.hub.returns_paid();
        let held = || {
            let s = self.hub.status(Some(self.wallet.balance()));
            if s["unsettled"] == true {
                return Err("a funding is being checked".to_string());
            }
            s["totalSat"].as_u64().ok_or_else(|| "not known".to_string())
        };
        let said = link.tick(&Look { now: unix_now(), capital: self.capital, held: &held,
                                     seen: &|spk| paid.clone().map(|p| p.iter().any(|r| r.seen && r.dest_spk == spk)) });
        self.hub.set_lightning(link.lightning_extra(unix_now()));
        said
    }

    /// The hub stops and starts again on the same data, and the link with it.
    fn restart(&mut self) {
        let idle = Arc::new(RouteHub::new(self.chain.clone(), self.chain.clone(), Box::new(WalletRef(self.wallet.clone())), Box::new(NetTransport(self.net.clone())),
                                          sk(0x4B4C), NET, None, hub_cfg(&json!({}))).unwrap());
        self.net.add(HUB, idle.clone());
        self.hub = idle;
        self.link = None;
        self.hub = Self::hub(&self.chain, &self.net, &self.dir, &self.wallet, self.capital);
        self.net.add(HUB, self.hub.clone());
        self.link_up();
    }

    /// A buyer with a ch1 open to the hub named `hub` (a URL, or `<node id>@host`).
    fn buyer_at(&self, hub: &str) -> Result<Buyer> {
        let c = self.chain.clone();
        let mut pc = RoutePayerConfig::new(NET);
        pc.expiry_blocks = 3_000;
        let pay = Arc::new(RoutePayer::new(hub, pc, Arc::new(LocalSigner::new()), Arc::new(Counting(ChainWallet(self.chain.clone()), self.funded.clone())),
                                           Box::new(NetTransport(self.net.clone())), Box::new(move || Ok(c.height()))));
        pay.open()?;
        let shards = self.provs.iter().map(|(o, _)| pay.shard(&format!("{o}/v1/chunk"), "POST").unwrap()).collect();
        Ok(Buyer { pay, shards })
    }

    fn buyer(&self) -> Buyer {
        self.buyer_at(HUB).unwrap()
    }

    /// `b` pays seller `i` for `calls` requests through the hub, with one routed lock.
    fn pay_seller(&self, b: &Buyer, i: usize, calls: usize) {
        for _ in 0..calls {
            let r = b.pay.call(&b.shards[i], "POST", br#"{"tokens":1}"#).unwrap();
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        }
        assert_eq!(b.pay.lock(&b.shards[i]).unwrap().unwrap()["status"], "paid");
    }

    /// `b` closes its ch1; blocks until the hub has swept what it was paid and the sweep is
    /// final, the link looking after each block. Returns the sweep as the hub's ledger has it.
    fn buyer_closes(&self, b: &Buyer) -> Value {
        let ch1 = b.pay.chan().unwrap();
        assert!(b.pay.close().unwrap()["txid"].is_string());
        self.blocks(14);
        self.hub.ch1_state(&ch1).unwrap().extra.get("payee_sweep_intent").cloned().expect("swept")
    }

    fn seller_closes(&self, i: usize) -> String {
        let p = &self.provs[i].1;
        let st = p.channel_ids().iter().filter_map(|c| p.channel_state(c)).find(|s| s.closed_txid.is_empty()).unwrap();
        p.close_now(&st.params.channel_id()).unwrap()
    }

    /// `n` blocks; after each the hub's watcher runs, then the link looks (when there is one).
    fn blocks(&self, n: u32) {
        for _ in 0..n {
            self.chain.mine(1);
            self.hub.watch_tick();
            if self.link.is_some() {
                self.look();
            }
        }
    }

    fn records(&self) -> Vec<OutChannel> {
        let mut v: Vec<OutChannel> = self.hub.out_channels().into_values().chain(self.hub.next_channels().into_values()).collect();
        v.extend(self.hub.archived().iter().filter_map(|r| OutChannel::from_json(r).ok()));
        v
    }

    /// Sats on keys only the hub's state files know.
    fn on_channel_keys(&self) -> u64 {
        let ch2: u64 = self.records().iter().map(|c| self.chain.unspent_to(&p2wpkh_spk(&c.params.payer_pub))).sum();
        let ch1: u64 = self.hub.inbound.channel_ids().iter().filter_map(|c| self.hub.ch1_state(c)).map(|s| self.chain.unspent_to(&s.params.payee_spk)).sum();
        ch2 + ch1
    }

    fn status(&self) -> Value {
        self.hub.status(Some(self.wallet.balance()))
    }

    fn link(&self) -> &LnLink {
        self.link.as_ref().unwrap()
    }

    fn is_ln(&self, spk_hex: &Value) -> bool {
        self.node.spks.lock().unwrap().iter().any(|s| hex::encode(s) == spk_hex.as_str().unwrap())
    }
}

fn n(v: &Value, k: &str) -> i64 {
    v[k].as_i64().unwrap_or_else(|| panic!("{k} in {v}"))
}

/// The four numbers add up, to the sat: what the hub holds is what was sent in, plus the fees it
/// earned, less what the chain cost, less what it returned to the Lightning wallet (`out`).
fn reconciles(w: &W, out: u64, at: &str) -> Value {
    let s = w.status();
    let four = n(&s, "capitalSat") + n(&s, "inChannelsSat") + n(&s, "earnedSat") + n(&s, "stuckSat");
    assert_eq!(four, n(&s, "totalSat"), "{at}: {s}");
    assert_eq!(four, DEPOSIT as i64 - out as i64 + n(&s, "feesEarnedSat") - n(&s, "chainFeesSat") - n(&s, "dustSat"), "{at}: {s}");
    assert_eq!(n(&s, "depositsSat"), DEPOSIT as i64 - out as i64, "{at}: taken out is what the Lightning wallet got: {s}");
    assert_eq!((s["estimated"].clone(), s["unsettled"].clone()), (json!(false), json!(false)), "{at}: {s}");
    s
}

// --- L1, L2: the full cycle -------------------------------------------------------------------------

#[test]
fn above_capital_a_return_reaches_the_lightning_wallet_and_every_sat_is_accounted_for() {
    // 1,000,000 sent in, capital 900,000: about 100,000 is above it
    let w = W::new(2, 900_000, true);
    let first = w.link().address().unwrap();
    reconciles(&w, 0, "funded");
    let b = w.buyer();
    w.pay_seller(&b, 0, 10);
    // the seller's close pays the hub's remainder to the hub's own wallet: a ch2 never names a
    // Lightning address (what it will pay is not known when it is funded)
    w.seller_closes(0);
    w.blocks(7);
    assert_eq!(w.node.balance(), 0);
    assert!(w.records().iter().all(|c| w.wallet.spks.lock().unwrap().contains(&c.params.payer_spk)), "every ch2 returns to the hub's wallet");
    reconciles(&w, 0, "seller closed");
    // the buyer's close: what the hub was paid is swept, whole, to the Lightning wallet
    let sweep = w.buyer_closes(&b);
    let swept = sweep["swept"].as_u64().unwrap();
    assert!(w.is_ln(&sweep["dest_spk"]), "{sweep}");
    assert_eq!(w.node.balance(), swept, "the Lightning wallet holds it");
    assert!(swept > 1_000, "{swept}");
    let s = reconciles(&w, swept, "buyer closed");
    assert!(n(&s, "totalSat") >= 900_000, "the hub kept its capital: {s}");
    // the chain showed that address used: the next one is in place
    let second = w.link().address().unwrap();
    assert_ne!(first, second);
    let paid = w.hub.returns_paid().unwrap();
    assert_eq!(paid.len(), 1);
    assert!(paid[0].seen && paid[0].sat == swept, "{paid:?}");
    assert_eq!(w.link().scripts().iter().filter(|s| **s == paid[0].dest_spk).count(), 1);
    // the seller never paid is refunded at its ch2's expiry, to the hub's wallet
    let exp = w.hub.out_channels()[&w.provs[1].0].params.expiry;
    w.chain.set_height(exp);
    w.blocks(8);
    let s = reconciles(&w, swept, "refunded");
    assert_eq!(w.on_channel_keys(), 0, "no coin on a per-channel key");
    assert_eq!((n(&s, "inChannelsSat"), n(&s, "earnedSat"), n(&s, "stuckSat")), (0, 0, 0), "{s}");
    assert_eq!(w.node.balance(), swept);
    assert_eq!(w.wallet.balance() + swept, (DEPOSIT as i64 + n(&s, "feesEarnedSat") - n(&s, "chainFeesSat")) as u64, "hub wallet + Lightning wallet: {s}");
}

#[test]
fn an_address_is_used_again_until_the_chain_shows_it_used() {
    let w = W::new(1, 900_000, true);
    let first = w.link().address().unwrap();
    let asked = w.node.asked.load(Ordering::SeqCst);
    let (a, b) = (w.buyer(), w.buyer());
    w.pay_seller(&a, 0, 5);
    w.pay_seller(&b, 0, 5);
    // both close in the same block: both sweeps are signed before either is in a block
    assert!(a.pay.close().unwrap()["txid"].is_string());
    assert!(b.pay.close().unwrap()["txid"].is_string());
    for _ in 0..5 {
        w.blocks(1);
        assert_eq!(w.link().address().unwrap(), first, "nothing paid to it yet");
    }
    assert_eq!(w.node.asked.load(Ordering::SeqCst), asked, "no new address was asked for");
    // the close is final at this tick: the watcher signs both sweeps, and the link looked before
    // either was mined
    w.chain.mine(1);
    w.hub.watch_tick();
    let paid = w.hub.returns_paid().unwrap();
    assert_eq!(paid.len(), 2, "{paid:?}");
    assert!(paid.iter().all(|r| !r.seen && w.is_ln(&json!(hex::encode(&r.dest_spk)))), "{paid:?}");
    assert_eq!(paid[0].dest_spk, paid[1].dest_spk, "the same address twice: neither was in a block");
    w.look();
    assert_eq!(w.link().address().unwrap(), first, "in the mempool is not used");
    w.blocks(1);
    assert_ne!(w.link().address().unwrap(), first, "one block: used, and the next is in place");
    assert_eq!(w.node.asked.load(Ordering::SeqCst), asked + 1);
    assert_eq!(w.node.balance(), paid.iter().map(|r| r.sat).sum::<u64>());
    reconciles(&w, w.node.balance(), "two sweeps to one address");
}

#[test]
fn at_or_below_capital_every_return_refills_the_hubs_wallet() {
    // capital is all that was sent in; capital is nearly all, and the return is larger than
    // what is above it; no capital is set
    for capital in [DEPOSIT, DEPOSIT - 5_000, 0] {
        let w = W::new(1, capital, true);
        let b = w.buyer();
        w.pay_seller(&b, 0, 10);
        let sweep = w.buyer_closes(&b);
        assert!(!w.is_ln(&sweep["dest_spk"]), "capital {capital}: {sweep}");
        assert_eq!(w.node.balance(), 0, "capital {capital}");
        assert!(w.wallet.spks.lock().unwrap().iter().any(|s| hex::encode(s) == sweep["dest_spk"].as_str().unwrap()));
        reconciles(&w, 0, "below capital");
        assert_eq!(w.link().report(unix_now(), None)["returnsHandedOut"], 0);
    }
}

#[test]
fn what_is_above_capital_is_not_handed_out_twice() {
    // about 10,000 above capital, two payouts of about 7,400 each closed together: one fits
    let w = W::new(1, DEPOSIT - 10_000, true);
    let (a, b) = (w.buyer(), w.buyer());
    w.pay_seller(&a, 0, 15);
    w.pay_seller(&b, 0, 15);
    assert!(a.pay.close().unwrap()["txid"].is_string());
    assert!(b.pay.close().unwrap()["txid"].is_string());
    w.blocks(14);
    let paid = w.hub.returns_paid().unwrap();
    let to_ln: Vec<_> = paid.iter().filter(|r| w.is_ln(&json!(hex::encode(&r.dest_spk)))).collect();
    assert_eq!((paid.len(), to_ln.len()), (2, 1), "{paid:?}");
    let s = reconciles(&w, to_ln[0].sat, "one of two");
    assert!(to_ln[0].sat > 5_000, "{to_ln:?}");
    assert!(n(&s, "totalSat") >= (DEPOSIT - 10_000) as i64, "the hub kept its capital: {s}");
}

#[test]
fn a_seller_channel_never_names_a_lightning_address() {
    // far above capital, the link up before any seller: funded, funded ahead and rolled over,
    // a ch2 returns to the hub's wallet (what it will pay is not known when it is named)
    let mut w = W::new(0, 300_000, true);
    assert!(w.link().report(unix_now(), None)["aboveCapitalSat"].as_u64().unwrap() >= 600_000);
    let origin = "http://p0.test".to_string();
    w.provs.push((origin.clone(), provider(&w.chain, &w.net, &w.dir, &origin)));
    w.hub.connect(&origin, None, None).unwrap();
    w.chain.confirm_all();
    w.hub.watch_tick();
    w.look();
    w.hub.connect_next(&origin, None, None).unwrap();
    let b = w.buyer();
    w.pay_seller(&b, 0, 30);
    w.blocks(3);
    let recs = w.records();
    assert!(recs.len() >= 2, "{}", recs.len());
    for c in &recs {
        assert!(w.wallet.spks.lock().unwrap().contains(&c.params.payer_spk), "{} {}", c.state, hex::encode(&c.params.payer_spk));
        assert!(!w.is_ln(&json!(hex::encode(&c.params.payer_spk))));
    }
    assert_eq!(w.link().report(unix_now(), None)["returnsHandedOut"], 0);
}

#[test]
fn a_hook_that_gives_what_is_no_address_never_holds_a_return_back() {
    // whatever stands behind the hook, a sweep goes out: to the hub's wallet when the hook's
    // answer is no witness v0 address of this network
    for wrong in ["not an address", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", ""] {
        let w = W::new(1, 0, false);
        let asked = Arc::new(AtomicU64::new(0));
        let a = asked.clone();
        w.hub.set_return_above(Some(Arc::new(move |_| {
            a.fetch_add(1, Ordering::SeqCst);
            Some(wrong.to_string())
        })));
        let b = w.buyer();
        w.pay_seller(&b, 0, 10);
        assert!(b.pay.close().unwrap()["txid"].is_string());
        w.blocks(14);
        let paid = w.hub.returns_paid().unwrap();
        assert_eq!((paid.len(), asked.load(Ordering::SeqCst)), (1, 1), "{wrong:?}: {paid:?}");
        assert!(paid[0].seen && w.wallet.spks.lock().unwrap().contains(&paid[0].dest_spk), "{wrong:?}");
        reconciles(&w, 0, "a hook with no address");
    }
}

// --- L3: the node away ------------------------------------------------------------------------------

#[test]
fn with_the_lightning_node_stopped_the_hub_routes_and_returns_and_returns_to_it_later() {
    let mut w = W::new(1, 900_000, true);
    let first = w.link().address().unwrap();
    w.node.down.store(true, Ordering::SeqCst);
    // routing, a buyer's close and its sweep all go on; the address on file is the node's
    let a = w.buyer();
    w.pay_seller(&a, 0, 10);
    let s1 = w.buyer_closes(&a);
    assert!(w.is_ln(&s1["dest_spk"]), "the address on file: {s1}");
    // it is used now and the node cannot give the next: the next return refills the hub's wallet
    assert_eq!(w.link().address(), None);
    assert!(w.link().report(unix_now(), None)["addressError"].as_str().unwrap().contains("not reachable"));
    let b = w.buyer();
    w.pay_seller(&b, 0, 10);
    let s2 = w.buyer_closes(&b);
    assert!(!w.is_ln(&s2["dest_spk"]), "{s2}");
    assert_eq!(w.node.balance(), s1["swept"].as_u64().unwrap());
    // a restart with the node still away: the hub starts, routes and still shows its statement
    w.restart();
    assert!(w.hub.routing_extra().unwrap()["lightning"].is_object());
    let c = w.buyer();
    w.pay_seller(&c, 0, 10);
    // the node is back: the next address is asked for (after the link's wait), and returns go to it
    w.node.down.store(false, Ordering::SeqCst);
    let link = w.link();
    let paid = w.hub.returns_paid().unwrap();
    let held = || Ok(w.status()["totalSat"].as_u64().unwrap());
    let seen = |spk: &[u8]| Ok(paid.iter().any(|r| r.seen && r.dest_spk == spk));
    link.tick(&Look { now: unix_now() + 60, capital: 900_000, held: &held, seen: &seen });
    let second = link.address().expect("the next address");
    assert_ne!(first, second);
    let s3 = w.buyer_closes(&c);
    assert!(w.is_ln(&s3["dest_spk"]), "{s3}");
    let out = s1["swept"].as_u64().unwrap() + s3["swept"].as_u64().unwrap();
    assert_eq!(w.node.balance(), out);
    reconciles(&w, out, "later");
}

// --- upgrade ----------------------------------------------------------------------------------------

#[test]
fn a_hub_that_ran_without_the_link_takes_it_up_and_its_old_returns_are_not_the_links() {
    let mut w = W::new(1, 900_000, false);
    let a = w.buyer();
    w.pay_seller(&a, 0, 10);
    assert!(a.pay.close().unwrap()["txid"].is_string());
    w.blocks(14);
    let before = w.hub.returns_paid().unwrap();
    assert_eq!(before.len(), 1);
    assert_eq!(w.node.balance(), 0);
    reconciles(&w, 0, "before the link");
    // the same data directory, now with the link
    w.restart();
    let first = w.link().address().unwrap();
    w.blocks(2);
    assert_eq!(w.link().address().unwrap(), first, "a sweep to the hub's own wallet does not use up the link's address");
    assert!(!w.link().scripts().contains(&before[0].dest_spk));
    let b = w.buyer();
    w.pay_seller(&b, 0, 10);
    let s = w.buyer_closes(&b);
    assert!(w.is_ln(&s["dest_spk"]));
    reconciles(&w, s["swept"].as_u64().unwrap(), "after");
}

// --- I1: the hub named by its Lightning node --------------------------------------------------------

fn named(node: &str) -> String {
    format!("{node}@hub.test")
}

#[test]
fn a_buyer_pays_a_hub_named_by_its_node_id() {
    let w = W::new(1, 0, true);
    let shown = w.hub.routing_extra().unwrap()["lightning"].clone();
    assert_eq!(shown["nodeId"], w.node.id().as_str());
    assert!(shown["statement"].as_str().unwrap().contains(&format!("payto={}", w.hub.pay_to())));
    let b = w.buyer_at(&named(&w.node.id())).unwrap();
    assert_eq!(b.pay.hub_node(), Some(w.node.id().as_str()));
    assert_eq!(b.pay.hub_url, HUB, "the signer and the ledger know the hub by where it is asked");
    w.pay_seller(&b, 0, 10);
    // and by its URL, as before, statement or none
    let by_url = w.buyer();
    w.pay_seller(&by_url, 0, 2);
    w.hub.set_lightning(None);
    w.pay_seller(&w.buyer(), 0, 2);
}

/// What a buyer does with a hub that shows `shown`: `Err(code, message)` when nothing was opened.
fn open_at(w: &W, hub: &str, shown: Option<Value>) -> std::result::Result<(), (String, String)> {
    w.hub.set_lightning(shown);
    let funded = w.funded.load(Ordering::SeqCst);
    match w.buyer_at(hub) {
        Ok(_) => Ok(()),
        Err(e) => {
            assert_eq!(w.funded.load(Ordering::SeqCst), funded, "nothing was funded: {e}");
            assert_eq!(w.hub.inbound.channel_ids().len(), 0, "nothing was opened: {e}");
            Err((e.code, e.msg))
        }
    }
}

#[test]
fn a_wrong_run_out_or_missing_statement_is_refused_before_anything_is_funded() {
    let w = W::new(1, 0, true);
    let node = w.node.id();
    let good = w.hub.routing_extra().unwrap()["lightning"].clone();
    let (text, sig) = (good["statement"].as_str().unwrap().to_string(), good["signature"].as_str().unwrap().to_string());
    let now = unix_now();
    let sign = |network: &str, payto: &str, until: u64, key: &SecretKey| {
        let t = hub_identity::sign_text(network, payto, until).unwrap();
        let s = hub_identity::ln_sign(t.as_bytes(), key);
        hub_identity::to_extra(&hex::encode(ecdsa::pubkey(key)), &t, &s)
    };
    let refused = |hub: &str, shown: Option<Value>, what: &str| {
        let (code, msg) = open_at(&w, hub, shown.clone()).expect_err(what);
        assert!(code == "hub_identity" && msg.contains(what), "{what}: {code}: {msg} ({shown:?})");
    };
    let other = sk(0x1002);
    let other_id = hex::encode(ecdsa::pubkey(&other));
    let other_hub = hex::encode(ecdsa::pubkey(&sk(0x4B4C)));
    // named by node id
    refused(&named(&node), None, "shows no statement");
    refused(&named(&other_id), Some(good.clone()), "named as the hub of node");
    refused(&named(&node), Some(sign(NET, w.hub.pay_to(), now + LIFE_SECS, &other)), "named as the hub of node");
    // a changed byte, in the text and in the signature
    refused(&named(&node), Some(hub_identity::to_extra(&node, &text.replace("until=1", "until=2"), &sig)), "not signed by node");
    let mut s2 = sig.clone().into_bytes();
    s2[40] = if s2[40] == b'y' { b'b' } else { b'y' };
    let s2 = String::from_utf8(s2).unwrap();
    let (_, msg) = open_at(&w, &named(&node), Some(hub_identity::to_extra(&node, &text, &s2))).expect_err("a changed signature");
    assert!(msg.contains("not signed by node") || msg.contains("recovers no key") || msg.contains("not a signature"), "{msg}");
    // run out, and signed for longer than a hub signs
    refused(&named(&node), Some(sign(NET, w.hub.pay_to(), now - 1, &w.node.key)), "ran out");
    refused(&named(&node), Some(sign(NET, w.hub.pay_to(), now + 400 * 86_400, &w.node.key)), "days ahead");
    // the node's statement for another hub key, and for another network
    refused(&named(&node), Some(sign(NET, &other_hub, now + LIFE_SECS, &w.node.key)), "another hub key");
    refused(&named(&node), Some(sign("bip122:22222222222222222222222222222222", w.hub.pay_to(), now + LIFE_SECS, &w.node.key)), "network");
    // by URL: a statement that is shown must hold all the same
    refused(HUB, Some(sign(NET, w.hub.pay_to(), now - 1, &w.node.key)), "ran out");
    refused(HUB, Some(sign(NET, &other_hub, now + LIFE_SECS, &w.node.key)), "another hub key");
    refused(HUB, Some(json!({"nodeId": node, "statement": text})), "signature is missing");
    // what is no hub address is refused as one, and asks nothing
    let (code, _) = open_at(&w, &format!("{node}@"), Some(good.clone())).expect_err("no host");
    assert_eq!(code, "hub_identity");
    // and with the node's own statement back, the same buyer opens
    assert!(open_at(&w, &named(&node), Some(good)).is_ok());
}

#[test]
fn a_statement_that_runs_out_stops_a_buyer_that_was_paying() {
    let w = W::new(1, 0, true);
    let b = w.buyer_at(&named(&w.node.id())).unwrap();
    w.pay_seller(&b, 0, 3);
    b.pay.refresh_hub().unwrap();
    // the hub's node has not signed for a month: the hub shows nothing more
    w.hub.set_lightning(None);
    let e = b.pay.refresh_hub().unwrap_err();
    assert!(e.code == "hub_identity" && e.msg.contains("shows no statement"), "{e}");
    // the buyer's coins are its own: it closes, or refunds at expiry, as with any hub
    assert!(b.pay.close().unwrap()["txid"].is_string());
}
