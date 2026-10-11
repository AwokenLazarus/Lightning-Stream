//! AGP-096, fix wave 5, the library client and its transport: the tests of the fixes to the third
//! closure audit's items 4 (the library's side), 6, 7, 14 and 18 that the audit's own file
//! (`agp093_client.rs`) does not hold. Each failed on branch `agp-093` before its fix, except the
//! `ok_` controls. The rig is the audit's.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use xbt402::client::{split_url, Client, ClientConfig, ClientLedger, FileClientLedger, MemoryClientLedger, Stage, Transport, Wallet, WalletSend, MAX_KEPT};
use xbt402::funding::{ChainBackend, FundingPolicy, UtxoInfo};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::signer::{LocalSigner, StateSigner};
use xbt402::wire::{b64json, unb64json, OPEN_PATH};
use xbt402::{ChannelError, Result};
use xbt_primitives::address::address_to_spk;
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

const NET: &str = "bip122:11111111111111111111111111111111";
const O: &str = "https://api.example";
const PRICE: u64 = 150;

#[derive(Default)]
struct MemChain {
    tip: Mutex<u32>,
    utxos: Mutex<HashMap<(String, u32), UtxoInfo>>,
    sent: Mutex<Vec<Tx>>,
}

impl ChainBackend for MemChain {
    fn block_count(&self) -> Result<u32> {
        Ok(*self.tip.lock().unwrap())
    }
    fn get_tx_out(&self, txid: &str, vout: u32, _m: bool) -> Result<Option<UtxoInfo>> {
        Ok(self.utxos.lock().unwrap().get(&(txid.to_string(), vout)).cloned())
    }
    fn send_raw_transaction(&self, hex: &str) -> Result<String> {
        let tx = Tx::parse_hex(hex)?;
        let mut u = self.utxos.lock().unwrap();
        for i in &tx.inputs {
            if u.remove(&(i.prevout.txid_hex(), i.prevout.vout)).is_none() {
                return Err(ChannelError::new("rpc_error", "missing inputs"));
            }
        }
        for (n, o) in tx.outputs.iter().enumerate() {
            u.insert((tx.txid(), n as u32), UtxoInfo { confirmations: 1, value: o.value as u64, script_pubkey: o.script_pubkey.clone(), coinbase: false });
        }
        self.sent.lock().unwrap().push(tx.clone());
        Ok(tx.txid())
    }
    fn has_transaction(&self, txid: &str) -> Result<bool> {
        Ok(self.sent.lock().unwrap().iter().any(|t| t.txid() == txid))
    }
}

#[derive(Default)]
struct TestWallet {
    chain: Arc<MemChain>,
    /// (txid, address, sats) of every send.
    sends: Mutex<Vec<(String, String, u64)>>,
    /// `fund` errors without sending.
    refuses: AtomicBool,
}

struct Shared(Arc<TestWallet>);

impl Wallet for Shared {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        if self.0.refuses.load(Ordering::SeqCst) {
            return Err(ChannelError::new("wallet_error", "insufficient funds"));
        }
        let mut sends = self.0.sends.lock().unwrap();
        let txid = hex::encode(sha256(format!("funding {}", sends.len() + 1).as_bytes()));
        let spk = address_to_spk(address, None).map_err(|e| ChannelError::new("bad_address", e.to_string()))?;
        self.0.chain.utxos.lock().unwrap().insert((txid.clone(), 0), UtxoInfo { confirmations: 6, value: sats, script_pubkey: spk, coinbase: false });
        sends.push((txid.clone(), address.to_string(), sats));
        Ok((txid, 0))
    }
    fn wallet_sends_to(&self, _address: &str) -> Result<Vec<String>> {
        Ok(vec![])
    }
    fn wallet_send(&self, _txid: &str, _address: &str) -> Result<Option<WalletSend>> {
        Ok(None)
    }
}

type Rewrite = Box<dyn Fn(&str, &Value, &[(String, String)], HttpResponse) -> Result<HttpResponse> + Send + Sync>;

/// The provider of the moment (a seller can restart with another key), with `f` free to change
/// or lose each answer on the way back.
struct Edit(Arc<Mutex<Arc<Provider>>>, Rewrite);

impl Transport for Edit {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        let (_, path) = split_url(url);
        let req: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        let p = self.0.lock().unwrap().clone();
        (self.1)(&path, &req, headers, p.serve(method, &path, headers, body, url, None))
    }
}

fn honest() -> Rewrite {
    Box::new(|_, _, _, r| Ok(r))
}

fn paid(path: &str, h: &[(String, String)]) -> bool {
    path.starts_with("/v1/") && h.iter().any(|(k, _)| k == "PAYMENT-SIGNATURE")
}

struct World {
    chain: Arc<MemChain>,
    wallet: Arc<TestWallet>,
    prov: Arc<Mutex<Arc<Provider>>>,
    dir: PathBuf,
}

fn provider(chain: &Arc<MemChain>, key: &[u8]) -> Arc<Provider> {
    provider_with(chain, key, None)
}

/// `short`: a seller whose offer asks for 144 + 1 + 36 blocks at least (the default asks for
/// 1,008 + 1 + 144, which is above the payer's own 1,008).
fn provider_with(chain: &Arc<MemChain>, key: &[u8], short: Option<()>) -> Arc<Provider> {
    let mut cfg = ProviderConfig::new(NET);
    if short.is_some() {
        cfg.close_margin = 36;
        cfg.policy = FundingPolicy { min_expiry_blocks: 144, close_margin: 36, ..FundingPolicy::default() };
    }
    let k = Mutex::new(0u64);
    let handler = move |m: &str, p: &str, _: &[u8]| {
        let mut k = k.lock().unwrap();
        *k += 1;
        HttpResponse::new(200, vec![], json!({"m": m, "answer": p, "n": *k}).to_string().into_bytes())
    };
    Arc::new(Provider::new(chain.clone(), SecretKey::from_slice(&sha256(key)).unwrap(), cfg, Ledger::in_memory(), Box::new(|_, _| PRICE), Box::new(handler)).unwrap())
}

fn world(name: &str) -> World {
    let dir = std::env::temp_dir().join(format!("xbt-rs-agp096-client-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let chain = Arc::new(MemChain::default());
    *chain.tip.lock().unwrap() = 1_000;
    let prov = Arc::new(Mutex::new(provider(&chain, b"provider payTo")));
    World { wallet: Arc::new(TestWallet { chain: chain.clone(), ..TestWallet::default() }), prov, chain, dir }
}

impl World {
    fn prov(&self) -> Arc<Provider> {
        self.prov.lock().unwrap().clone()
    }

    fn bare_client(&self, f: Rewrite) -> Client {
        let c = self.chain.clone();
        Client::new(ClientConfig::new(NET), Box::new(Edit(self.prov.clone(), f)), Box::new(Shared(self.wallet.clone())), Box::new(move || c.block_count()))
    }

    /// A client on the ledger file `name` (one at a time: the file is locked).
    fn client_on(&self, name: &str, f: Rewrite) -> Client {
        self.bare_client(f).with_ledger(Box::new(FileClientLedger::open(&self.dir.join(name)).unwrap())).unwrap()
    }

    fn funded(&self) -> usize {
        self.wallet.sends.lock().unwrap().len()
    }
}

fn get(c: &mut Client) -> std::result::Result<u16, String> {
    c.request("GET", &format!("{O}/v1/q"), b"").map(|r| r.status).map_err(|e| e.code)
}

fn paid_calls(c: &mut Client, n: usize) {
    for _ in 0..n {
        assert_eq!(get(c), Ok(200));
    }
}


/// A ledger a test can read and rewrite between two clients.
#[derive(Clone, Default)]
struct Shelf(Arc<MemoryClientLedger>);

impl ClientLedger for Shelf {
    fn load(&self) -> Result<Vec<(String, Value)>> {
        self.0.load()
    }
    fn save(&self, r: &[(String, Value)]) -> Result<()> {
        self.0.save(r)
    }
}

impl World {
    /// A client with a `LocalSigner` (returned too) or with local keys, on `shelf`.
    fn client_with(&self, signer: Option<Arc<LocalSigner>>, shelf: &Shelf, f: Rewrite) -> Client {
        let c = self.bare_client(f);
        let c = match signer {
            Some(s) => c.with_signer(s),
            None => c,
        };
        c.with_ledger(Box::new(shelf.clone())).unwrap()
    }

    fn tip(&self) -> u32 {
        *self.chain.tip.lock().unwrap()
    }

    fn mine(&self, n: u32) {
        *self.chain.tip.lock().unwrap() += n;
    }
}

fn get_at(c: &mut Client, origin: &str) -> std::result::Result<u16, String> {
    c.request("GET", &format!("{origin}/v1/q"), b"").map(|r| r.status).map_err(|e| e.code)
}

/// Rewrite the offer of every 402 with `f`.
fn offers(f: impl Fn(&mut Value) + Send + Sync + 'static) -> Rewrite {
    Box::new(move |_, _, _, mut r| {
        if r.status == 402 {
            let mut pr = unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap();
            f(&mut pr["accepts"][0]);
            r.headers.retain(|(k, _)| k != "PAYMENT-REQUIRED");
            r.headers.push(("PAYMENT-REQUIRED".into(), b64json(&pr)));
        }
        Ok(r)
    })
}

// --- item 6: a failed funding call at the shipped terms ------------------------------------------

/// The shipped provider asks for 1,008 + 1 + 144 blocks, the shipped payer for 1,008, so a channel
/// is derived with exactly the offer's floor. A `fund` call that failed is retried on the same
/// channel for as long as half of the offer's confirmation margin is left (72 blocks): the first
/// call with a funded wallet pays, with a signer and with a local key, and nothing is set aside.
#[test]
fn a_failed_funding_call_is_retried_on_the_same_channel_at_the_shipped_terms() {
    for (with_signer, later) in [(false, 1), (true, 1), (false, 72), (true, 72)] {
        let w = world(&format!("retry-{with_signer}-{later}"));
        let mut c = w.client_with(with_signer.then(|| Arc::new(LocalSigner::new())), &Shelf::default(), honest());
        w.wallet.refuses.store(true, Ordering::SeqCst);
        assert_eq!(get(&mut c), Err("wallet_error".into()));
        let derived = c.channels[O].payer.params.clone();
        assert_eq!(derived.expiry, 1_000 + 1_153);
        w.wallet.refuses.store(false, Ordering::SeqCst);
        w.mine(later);
        assert_eq!(get(&mut c), Ok(200), "signer {with_signer}, {later} blocks later");
        let p = &c.channels[O].payer.params;
        assert_eq!((w.funded(), c.channels[O].stage, p.expiry, p.payer_pub), (1, Stage::Open, derived.expiry, derived.payer_pub));
        assert!(c.unfunded.is_empty(), "nothing was set aside");
    }
}

/// Past that, the channel is derived again in the same call, for the same key, and funded: no
/// call fails for it, and the script that was set aside is kept with its terms.
#[test]
fn a_keyed_channel_too_old_to_fund_is_derived_again_and_funded_by_the_same_call() {
    for with_signer in [false, true] {
        let w = world(&format!("rederive-{with_signer}"));
        let signer = with_signer.then(|| Arc::new(LocalSigner::new()));
        let mut c = w.client_with(signer.clone(), &Shelf::default(), honest());
        w.wallet.refuses.store(true, Ordering::SeqCst);
        assert_eq!(get(&mut c), Err("wallet_error".into()));
        let old = c.channels[O].payer.params.clone();
        w.wallet.refuses.store(false, Ordering::SeqCst);
        w.mine(73);
        assert_eq!(get(&mut c), Ok(200), "signer {with_signer}");
        let p = c.channels[O].payer.params.clone();
        assert_eq!((w.funded(), p.expiry, p.payer_pub), (1, w.tip() + 1_153, old.payer_pub), "signer {with_signer}");
        assert_eq!(c.unfunded[O].iter().map(|u| &u.payer.params).collect::<Vec<_>>(), [&old]);
        // had the failed call sent after all, the script it paid still has its key
        let sent = old.clone().with_funding(&"ab".repeat(32), 0, old.capacity).unwrap();
        let refund = match (&signer, c.unfunded[O][0].payer.secret()) {
            (Some(s), _) => s.sign_refund(&s.attach(O, &sent).unwrap()).unwrap(),
            (None, Some(sk)) => sent.refund_tx(sk, None, None).unwrap().to_hex(),
            (None, None) => panic!("the kept record has no key"),
        };
        assert_eq!(Tx::parse_hex(&refund).unwrap().locktime, old.expiry);
    }
}

/// However long a wallet stays empty and however often the caller tries, the origin is never
/// refused for it: forty failed `fund` calls a hundred blocks apart, then a funded wallet, and
/// the first call pays. At most `MAX_KEPT` earlier scripts are kept, all for the channel's key.
#[test]
fn no_number_of_failed_fundings_ends_a_clients_business_with_a_seller() {
    for with_signer in [false, true] {
        let w = world(&format!("forty-{with_signer}"));
        let shelf = Shelf::default();
        let mut c = w.client_with(with_signer.then(|| Arc::new(LocalSigner::new())), &shelf, honest());
        w.wallet.refuses.store(true, Ordering::SeqCst);
        for _ in 0..40 {
            assert_eq!(get(&mut c), Err("wallet_error".into()), "signer {with_signer}");
            w.mine(100);
        }
        let key = c.channels[O].payer.params.payer_pub;
        assert_eq!(c.unfunded[O].len(), MAX_KEPT);
        assert!(c.unfunded[O].iter().all(|u| u.payer.params.payer_pub == key), "every script kept pays the channel's key");
        w.wallet.refuses.store(false, Ordering::SeqCst);
        assert_eq!(get(&mut c), Ok(200), "signer {with_signer}");
        assert_eq!((w.funded(), c.channels[O].payer.params.payer_pub, c.unfunded[O].len()), (1, key, MAX_KEPT));
        // and a new process reads the same book
        drop(c);
        let mut c = w.client_with(with_signer.then(|| Arc::new(LocalSigner::new())), &shelf, honest());
        assert_eq!((c.channels[O].stage, c.unfunded[O].len()), (Stage::Open, MAX_KEPT));
        if !with_signer {
            assert_eq!(get(&mut c), Ok(200));
        }
    }
}

/// The upgrade: a ledger written by AGP-090 with sixteen kept keys, each its own, and a stale
/// keyed channel (the state that refused the origin for good). The next call opens, and none of
/// the sixteen keys is dropped, now or after more failed fundings.
#[test]
fn a_ledger_with_sixteen_kept_keys_from_before_goes_on_and_drops_none() {
    let w = world("upgrade-kept");
    w.wallet.refuses.store(true, Ordering::SeqCst);
    // seventeen keyed channels, each derived by a client of its own: seventeen keys
    let mut recs = vec![];
    for _ in 0..17 {
        let mut c = w.bare_client(honest());
        assert_eq!(get(&mut c), Err("wallet_error".into()));
        recs.push(c.channels[O].to_json());
    }
    let keys: Vec<Value> = recs.iter().map(|r| r["params"]["payer_pub"].clone()).collect();
    let live = recs.pop().unwrap();
    let shelf = Shelf::default();
    shelf.save(&[(format!("chan {O}"), live), (format!("unfunded {O}"), Value::Array(recs))]).unwrap();
    let mut c = w.client_with(None, &shelf, honest());
    assert_eq!((c.unfunded[O].len(), c.channels[O].stage), (16, Stage::Keyed));
    w.mine(500);
    for _ in 0..5 {
        assert_eq!(get(&mut c), Err("wallet_error".into()));
        w.mine(500);
    }
    let kept: Vec<Value> = c.unfunded[O].iter().map(|u| u.to_json()["params"]["payer_pub"].clone()).collect();
    assert!(keys.iter().all(|k| kept.contains(k)), "a key of its own is never dropped");
    assert_eq!(kept.len(), 17, "the sixteen from before and the newest earlier script of the channel being opened");
    w.wallet.refuses.store(false, Ordering::SeqCst);
    assert_eq!(get(&mut c), Ok(200));
    assert_eq!(w.funded(), 1);
}

/// The budget holds on the day the coins leave. Six origins are keyed while the wallet is empty,
/// each inside the budget of 1,000,000 sat; when the wallet is funded five are opened and the
/// sixth is refused.
#[test]
fn channels_keyed_while_the_wallet_was_empty_are_not_all_funded_past_the_budget() {
    let w = world("budget");
    let mut c = w.bare_client(honest());
    let origins: Vec<String> = (1..=6).map(|i| format!("https://a{i}.example")).collect();
    w.wallet.refuses.store(true, Ordering::SeqCst);
    for o in &origins {
        assert_eq!(get_at(&mut c, o), Err("wallet_error".into()));
    }
    assert_eq!((c.channels.len(), c.opened_sats), (6, 0));
    w.wallet.refuses.store(false, Ordering::SeqCst);
    let out: Vec<_> = origins.iter().map(|o| get_at(&mut c, o)).collect();
    assert_eq!(out[5], Err("budget".into()), "{out:?}");
    assert_eq!((w.funded(), c.opened_sats), (5, 1_000_000), "{out:?}");
}

// --- item 18: the terms a keyed channel is funded on ---------------------------------------------

/// After the audit's test (the seller changed its payTo key; the call that finds out funds
/// nothing): the next call funds the channel derived from the new offer, once, and the seller
/// opens it. The script of the old terms is kept.
#[test]
fn a_keyed_channel_whose_seller_changed_its_key_is_opened_on_the_new_terms_by_the_next_call() {
    let w = world("new-terms");
    *w.prov.lock().unwrap() = provider_with(&w.chain, b"provider payTo", Some(()));
    w.wallet.refuses.store(true, Ordering::SeqCst);
    let mut c = w.client_on("c.jsonl", honest());
    assert_eq!(get(&mut c), Err("wallet_error".into()));
    let old = c.channels[O].payer.params.clone();
    w.wallet.refuses.store(false, Ordering::SeqCst);
    *w.prov.lock().unwrap() = provider_with(&w.chain, b"provider payTo after a key rotation", Some(()));
    w.mine(10);
    assert_eq!(get(&mut c), Err("open_unresolved".into()));
    let derived = c.channels[O].payer.params.clone();
    assert_eq!((w.funded(), c.channels[O].stage, derived.payer_pub), (0, Stage::Keyed, old.payer_pub));
    assert_ne!(derived.payee_pub, old.payee_pub, "derived again from the offer of the day");
    assert_eq!(get(&mut c), Ok(200));
    assert_eq!((w.funded(), c.channels[O].payer.params.payee_pub, c.unfunded[O].len()), (1, derived.payee_pub, 1));
    assert_eq!(c.unfunded[O][0].payer.params, old);
}

/// A price raised between the key and the funding. The channel used to be funded at the old
/// price and then refused every call ("price raised mid-channel"); it is derived again instead.
#[test]
fn a_keyed_channel_is_not_funded_at_a_price_the_seller_has_raised() {
    let w = world("raised");
    let price = Arc::new(AtomicUsize::new(150));
    let p2 = price.clone();
    let mut c = w.bare_client(offers(move |acc| acc["amount"] = p2.load(Ordering::SeqCst).to_string().into()));
    w.wallet.refuses.store(true, Ordering::SeqCst);
    assert_eq!(get(&mut c), Err("wallet_error".into()));
    w.wallet.refuses.store(false, Ordering::SeqCst);
    price.store(300, Ordering::SeqCst);
    assert_eq!(get(&mut c), Err("open_unresolved".into()));
    assert_eq!(w.funded(), 0);
    assert_eq!((get(&mut c), get(&mut c)), (Ok(200), Ok(200)));
    assert_eq!((w.funded(), c.channels[O].price), (1, 300));
}

/// What fills `unfunded`: only channels the wallet was asked to fund. A seller that changes its
/// offer on every call (here: a price one sat higher each time) makes the client derive its
/// channel again each time, and none of those is kept: the one record there is the channel whose
/// `fund` call failed, which may hold coins, and twenty changes of the offer do not push it out.
#[test]
fn a_seller_that_changes_its_offer_on_every_call_fills_nothing_and_pushes_nothing_out() {
    let w = world("flips");
    let price = Arc::new(AtomicUsize::new(150));
    let p2 = price.clone();
    let shelf = Shelf::default();
    let mut c = w.client_with(None, &shelf, offers(move |acc| acc["amount"] = p2.load(Ordering::SeqCst).to_string().into()));
    w.wallet.refuses.store(true, Ordering::SeqCst);
    assert_eq!(get(&mut c), Err("wallet_error".into()));
    let asked = c.channels[O].payer.params.clone();
    w.wallet.refuses.store(false, Ordering::SeqCst);
    for _ in 0..20 {
        price.fetch_add(1, Ordering::SeqCst);
        assert_eq!(get(&mut c), Err("open_unresolved".into()));
    }
    assert_eq!((w.funded(), c.unfunded[O].iter().map(|u| &u.payer.params).collect::<Vec<_>>()), (0, vec![&asked]));
    // the same after a restart: the ledger says which channel the wallet was asked for
    drop(c);
    let mut c = w.client_with(None, &shelf, honest());
    assert_eq!((c.unfunded[O].len(), c.unfunded[O][0].fund_tried, c.channels[O].fund_tried), (1, true, false));
    price.store(150, Ordering::SeqCst);
    assert_eq!((get(&mut c), w.funded()), (Ok(200), 1));
}

/// A seller whose offer is unchanged and whose preflight now says no (its policy changed, or its
/// node is behind): nothing is funded on the old yes. The channel is set aside, the call fails,
/// and once the seller says yes again the next call funds one channel.
#[test]
fn a_keyed_channel_is_not_funded_when_the_preflight_now_says_no() {
    let w = world("preflight-no");
    let refuse = Arc::new(AtomicBool::new(false));
    let r2 = refuse.clone();
    let mut c = w.bare_client(Box::new(move |path, req, _, r| {
        if path == OPEN_PATH && req.get("preflight") == Some(&Value::Bool(true)) && r2.load(Ordering::SeqCst) {
            return Ok(HttpResponse::new(400, vec![], json!({"error": "bad_expiry", "detail": "no"}).to_string().into_bytes()));
        }
        Ok(r)
    }));
    w.wallet.refuses.store(true, Ordering::SeqCst);
    assert_eq!(get(&mut c), Err("wallet_error".into()));
    let asked = c.channels[O].payer.params.clone();
    w.wallet.refuses.store(false, Ordering::SeqCst);
    refuse.store(true, Ordering::SeqCst);
    // the call that finds out sets the channel aside; the calls after it get the seller's own no
    let out: Vec<_> = (0..3).map(|_| get(&mut c).unwrap_err()).collect();
    assert_eq!(out, ["open_unresolved", "bad_expiry", "bad_expiry"]);
    assert_eq!((w.funded(), c.unfunded[O].iter().map(|u| &u.payer.params).collect::<Vec<_>>()), (0, vec![&asked]));
    refuse.store(false, Ordering::SeqCst);
    assert_eq!((get(&mut c), w.funded()), (Ok(200), 1));
    assert_eq!(c.channels[O].payer.params.payer_pub, asked.payer_pub);
}

/// The preflight is asked again before a keyed channel of an earlier call is funded, and an
/// answer that never comes is not a refusal: nothing is funded, nothing is set aside, and the
/// next call funds the same channel.
#[test]
fn a_preflight_that_gets_no_answer_leaves_the_keyed_channel_for_the_next_call() {
    let w = world("no-answer");
    let lost = Arc::new(AtomicBool::new(false));
    let l2 = lost.clone();
    let preflights = Arc::new(AtomicUsize::new(0));
    let n2 = preflights.clone();
    let mut c = w.bare_client(Box::new(move |path, req, _, r| {
        if path == OPEN_PATH && req.get("preflight") == Some(&Value::Bool(true)) {
            n2.fetch_add(1, Ordering::SeqCst);
            if l2.load(Ordering::SeqCst) {
                return Err(ChannelError::new("transport_error", "timed out"));
            }
        }
        Ok(r)
    }));
    w.wallet.refuses.store(true, Ordering::SeqCst);
    assert_eq!(get(&mut c), Err("wallet_error".into()));
    let derived = c.channels[O].payer.params.clone();
    w.wallet.refuses.store(false, Ordering::SeqCst);
    lost.store(true, Ordering::SeqCst);
    assert_eq!(get(&mut c), Err("transport_error".into()));
    assert_eq!((w.funded(), preflights.load(Ordering::SeqCst), c.channels[O].payer.params.clone()), (0, 2, derived.clone()));
    assert!(c.unfunded.is_empty());
    lost.store(false, Ordering::SeqCst);
    assert_eq!(get(&mut c), Ok(200));
    assert_eq!((w.funded(), preflights.load(Ordering::SeqCst)), (1, 3));
    assert_eq!(c.channels[O].payer.params.expiry, derived.expiry);
}

// --- item 18: one seller, one origin ---------------------------------------------------------------

/// One channel serves every spelling of its origin, and the book has one key for it.
#[test]
fn one_channel_serves_every_spelling_of_its_origin() {
    let w = world("one-origin");
    let mut c = w.client_on("c.jsonl", honest());
    for o in ["HTTPS://API.example:443", "https://api.example", "https://u:p@api.example", "https://API.EXAMPLE", "https://api.example:443"] {
        assert_eq!(get_at(&mut c, o), Ok(200), "{o}");
    }
    assert_eq!((w.funded(), c.channels.keys().cloned().collect::<Vec<_>>(), c.channels[O].receipts.len()), (1, vec![O.to_string()], 5));
    // another port, another scheme and another host are other sellers
    assert_eq!(split_url("https://api.example:8443/x").0, "https://api.example:8443");
    assert_eq!(split_url("http://api.example/x").0, "http://api.example");
    assert_eq!(split_url("https://api.example.evil.test/x").0, "https://api.example.evil.test");
    // close by any spelling
    let r = c.close("HTTPS://API.example:443").unwrap();
    assert_eq!(r["chan"], c.channels[O].payer.params.channel_id());
}

/// The upgrade: a ledger that holds a channel under another spelling of its origin. It is read
/// under the origin, the old key is removed from the ledger, and a call in any spelling pays on
/// that channel: nothing is funded again.
#[test]
fn a_ledger_that_names_an_origin_in_another_spelling_is_read_under_the_origin() {
    let w = world("upgrade-spelling");
    let shelf = Shelf::default();
    {
        let mut c = w.client_with(None, &shelf, honest());
        paid_calls(&mut c, 2);
    }
    // as a build from before wrote it for a caller that spelled the URL `https://API.example/...`
    let spelled = "https://API.example";
    let mut rec = shelf.load().unwrap().into_iter().find(|(k, _)| k == &format!("chan {O}")).unwrap().1;
    rec["origin"] = spelled.into();
    shelf.save(&[(format!("chan {O}"), Value::Null), (format!("chan {spelled}"), rec)]).unwrap();
    let mut c = w.client_with(None, &shelf, honest());
    assert_eq!(c.channels.keys().cloned().collect::<Vec<_>>(), [O.to_string()]);
    let keys: Vec<String> = shelf.load().unwrap().into_iter().map(|(k, _)| k).filter(|k| k.starts_with("chan ")).collect();
    assert_eq!(keys, [format!("chan {O}")], "moved in the ledger too");
    assert_eq!((get_at(&mut c, O), get_at(&mut c, spelled)), (Ok(200), Ok(200)));
    assert_eq!((w.funded(), c.channels[O].receipts.len()), (1, 4));
    assert!(c.close(spelled).is_ok());
}

/// The same upgrade when both spellings were funded before (the audit's hole 4): the channel
/// under the origin's own key is the one calls use, and the other stays on the books under its
/// spelling, where a close by that spelling finds it.
#[test]
fn a_ledger_with_two_spellings_of_one_origin_keeps_both_channels() {
    let w = world("upgrade-two");
    let (first, second) = (Shelf::default(), Shelf::default());
    for shelf in [&first, &second] {
        let mut c = w.client_with(None, shelf, honest());
        paid_calls(&mut c, 2);
    }
    assert_eq!(w.funded(), 2);
    let spelled = "https://API.example";
    let mut other = second.load().unwrap().into_iter().find(|(k, _)| k == &format!("chan {O}")).unwrap().1;
    other["origin"] = spelled.into();
    let other_chan = format!("{}:{}", other["params"]["funding_txid"].as_str().unwrap(), other["params"]["funding_vout"]);
    // with a list of its own, which stays with it
    first.save(&[(format!("chan {spelled}"), other.clone()), (format!("unfunded {spelled}"), json!([other]))]).unwrap();
    let mut c = w.client_with(None, &first, honest());
    let mut keys: Vec<String> = c.channels.keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, [spelled.to_string(), O.to_string()]);
    assert_eq!(c.unfunded.keys().cloned().collect::<Vec<_>>(), [spelled.to_string()]);
    let live = c.channels[O].payer.params.channel_id();
    assert_ne!(live, other_chan);
    assert_eq!((get_at(&mut c, spelled), get_at(&mut c, O)), (Ok(200), Ok(200)), "requests in any spelling pay on the origin's channel");
    assert_eq!((w.funded(), c.channels[O].receipts.len(), c.channels[spelled].receipts.len()), (2, 4, 2));
    assert_eq!(c.close(spelled).unwrap()["chan"], other_chan.as_str(), "the other channel is closed by its spelling");
    assert_eq!(c.close(O).unwrap()["chan"], live.as_str());
}

// --- item 4, the library's side: the lower bound of the expiry --------------------------------------

/// A seller whose offer has a window of one block and that answers the preflight yes (the audit's
/// item 4, through the library client): refused `bad_offer` before a key is made or anything is
/// funded. It used to be funded, 200,000 sat in a channel that expired one block later.
#[test]
fn an_offer_with_a_window_of_one_block_is_refused_before_anything_is_funded() {
    let w = world("window");
    let mut c = w.bare_client(Box::new(|path, req, _, mut r| {
        if r.status == 402 {
            let mut pr = unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap();
            let ex = &mut pr["accepts"][0]["extra"];
            (ex["minExpiryBlocks"], ex["maxExpiryBlocks"], ex["closeMarginBlocks"]) = (1.into(), 2.into(), 0.into());
            r.headers.retain(|(k, _)| k != "PAYMENT-REQUIRED");
            r.headers.push(("PAYMENT-REQUIRED".into(), b64json(&pr)));
        }
        if path == OPEN_PATH && req.get("preflight") == Some(&Value::Bool(true)) {
            return Ok(HttpResponse::new(200, vec![], json!({"preflight": true}).to_string().into_bytes()));
        }
        Ok(r)
    }));
    for _ in 0..3 {
        assert_eq!(get(&mut c), Err("bad_offer".into()));
    }
    assert_eq!((w.funded(), c.channels.len()), (0, 0));
}

/// The same bound at a rollover: no next channel is signed for a window the owner would not fund.
#[test]
fn a_rollover_is_not_signed_into_a_window_of_one_block() {
    let w = world("window-roll");
    let mut c = w.bare_client(honest());
    paid_calls(&mut c, 8);
    let ex = &mut c.channels.get_mut(O).unwrap().accepted["extra"];
    (ex["minExpiryBlocks"], ex["maxExpiryBlocks"], ex["closeMarginBlocks"]) = (1.into(), 2.into(), 0.into());
    let signed = c.channels[O].payer.signed;
    assert_eq!(c.rollover(O).unwrap_err().code, "bad_offer");
    assert!(c.next_rolled.is_empty() && c.channels[O].payer.signed == signed, "nothing was signed");
}

// --- item 18: the count of a request is saved before it leaves ---------------------------------------

/// What is in the ledger file at the moment a paid request is on the wire: the seq it carries.
#[test]
fn the_seq_of_a_paid_request_is_in_the_ledger_before_the_request_leaves() {
    let w = world("write-ahead");
    w.prov().offer_conditional("/v1/secret", 600, b"the deliverable", None);
    let file = w.dir.join("c.jsonl");
    let seen: Arc<Mutex<Vec<(u64, u64, u64)>>> = Arc::new(Mutex::new(vec![]));
    let s2 = seen.clone();
    let f2 = file.clone();
    let mut c = w.client_on("c.jsonl", Box::new(move |_, _, h, r| {
        if let Some((_, v)) = h.iter().find(|(k, _)| k == "PAYMENT-SIGNATURE") {
            let sent = unb64json(v).unwrap()["payload"]["seq"].as_u64().unwrap();
            let rec = std::fs::read_to_string(&f2).unwrap().lines().filter_map(|l| serde_json::from_str::<Value>(l).ok())
                .rfind(|l| l["k"] == format!("chan {O}")).unwrap();
            s2.lock().unwrap().push((sent, rec["v"]["seq"].as_u64().unwrap(), rec["v"]["unanswered_msat"].as_u64().unwrap()));
        }
        Ok(r)
    }));
    paid_calls(&mut c, 3);
    c.request_conditional("GET", &format!("{O}/v1/secret"), b"").unwrap();
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 4);
    for (sent, saved, unanswered) in seen {
        assert_eq!(sent, saved, "a request left with a seq the ledger did not hold yet");
        assert!(unanswered > 0, "and its quote was not counted");
    }
}

// --- item 14: arithmetic on a seller's numbers when the owner's cap is wide ---------------------------

/// The audit's sweep ran with the default `max_price` (1,000 sat), which refuses a large amount
/// before any arithmetic. A wallet that takes `max_price` from its caller (`xbt-wallet-mcp` sets
/// it to the tool call's `max_sats`) lets the seller's amount through to the sums. No amount, in
/// a plain or a prepaid offer or a conditional one, makes the client panic.
#[test]
fn no_amount_makes_a_client_with_a_wide_price_cap_panic() {
    let amounts = [json!(1), json!(u32::MAX), json!(i64::MAX), json!(u64::MAX / 1000), json!(u64::MAX / 1000 + 1), json!(u64::MAX - 1), json!(u64::MAX),
                   json!("18446744073709551615"), json!("18446744073709551616")];
    let mut panics = vec![];
    for amount in amounts {
        for (billing, cond, daily) in [("postpay", false, 0), ("prepay", false, 0), ("prepay", false, u64::MAX), ("postpay", true, u64::MAX), ("postpay", true, 1)] {
            let w = world("wide");
            w.prov().offer_conditional("/v1/secret", 600, b"the deliverable", None);
            let a2 = amount.clone();
            let mut c = w.bare_client(offers(move |acc| {
                acc["extra"]["billing"] = billing.into();
                if cond && acc["extra"].get("conditional").is_some() {
                    acc["extra"]["conditional"]["amount"] = a2.clone();
                } else {
                    acc["amount"] = a2.clone();
                }
            }));
            (c.cfg.max_price, c.cfg.daily_budget) = (u64::MAX, daily);
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                for _ in 0..3 {
                    let _ = c.request("GET", &format!("{O}/v1/q"), b"");
                    let _ = c.request_conditional("GET", &format!("{O}/v1/secret"), b"");
                }
                let _ = c.rollover(O);
                let _ = c.close(O);
            }));
            if r.is_err() {
                panics.push(format!("amount {amount}, {billing}, conditional {cond}, daily budget {daily}"));
            }
        }
    }
    assert!(panics.is_empty(), "{} sellers made the client panic:\n{}", panics.len(), panics.join("\n"));
}

/// A request counter at its end (a ledger's own number) is an error, not a panic.
#[test]
fn a_request_counter_at_its_end_is_refused_not_a_panic() {
    let w = world("seq-end");
    let mut c = w.bare_client(honest());
    paid_calls(&mut c, 2);
    c.channels.get_mut(O).unwrap().seq = u64::MAX;
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (get(&mut c), c.close(O).map_err(|e| e.code))));
    assert_eq!(r.ok(), Some((Err("exhausted".to_string()), Err("exhausted".to_string()))));
}

/// A conditional offer's `csvDelta` that does not fit 32 bits was cut to its low bits (2^32 + 10
/// read as 10) and a hash lock signed for it. It is refused before anything is signed.
#[test]
fn a_csv_delta_that_does_not_fit_is_refused_before_anything_is_signed() {
    let w = world("csv");
    w.prov().offer_conditional("/v1/secret", 600, b"the deliverable", None);
    let mut c = w.bare_client(offers(|acc| {
        if acc["extra"].get("conditional").is_some() {
            acc["extra"]["conditional"]["csvDelta"] = json!((1u64 << 32) + 10);
        }
    }));
    paid_calls(&mut c, 2);
    let seq = c.channels[O].seq;
    assert_eq!(c.request_conditional("GET", &format!("{O}/v1/secret"), b"").unwrap_err().code, "bad_offer");
    assert_eq!((c.channels[O].seq, c.channels[O].pending_cond.is_none()), (seq, true));
}

// --- item 18, written down: a refusal is unsigned ----------------------------------------------------

/// LIMIT (the audit's `hole_two_forged_refusals_do_not_end_the_channel`, which still fails). A 402
/// is not signed, so the payer cannot tell a refusal the provider sent from one that whoever sits
/// between put in place of an answer the provider served and charged. It gives the provider one
/// call of doubt in a channel's life; at the second, every call fails `bad_offer`. The numbers:
/// the payer then closes the channel, cooperatively, at what it signed, which is one call less
/// than the provider served; no coin is stuck, and the next call opens a new channel.
#[test]
fn limit_after_a_second_forged_refusal_the_channel_is_closed_at_what_the_payer_signed() {
    let w = world("forged-close");
    let forge = Arc::new(AtomicUsize::new(0));
    let f2 = forge.clone();
    let last_402: Mutex<Option<String>> = Mutex::new(None);
    let mut c = w.bare_client(Box::new(move |path, _, h, r| {
        if r.status == 402 {
            *last_402.lock().unwrap() = r.header("PAYMENT-REQUIRED").map(str::to_string);
        }
        if paid(path, h) && r.status == 200 && f2.load(Ordering::SeqCst) > 0 {
            f2.fetch_sub(1, Ordering::SeqCst);
            let mut pr = unb64json(&last_402.lock().unwrap().clone().unwrap()).unwrap();
            pr.as_object_mut().unwrap().remove("channel");
            return Ok(HttpResponse::new(402, vec![("PAYMENT-REQUIRED".into(), b64json(&pr))], vec![]));
        }
        Ok(r)
    }));
    paid_calls(&mut c, 4);
    let chan = c.channels[O].payer.params.channel_id();
    forge.store(1, Ordering::SeqCst);
    assert_eq!((get(&mut c), get(&mut c)), (Ok(402), Ok(200)));
    paid_calls(&mut c, 2);
    forge.store(1, Ordering::SeqCst);
    assert_eq!((get(&mut c), get(&mut c), get(&mut c)), (Ok(402), Err("bad_offer".into()), Err("bad_offer".into())));
    let served = w.prov().channel_state(&chan).unwrap().spent_msat / 1000;
    let (signed, answers) = (c.channels[O].payer.signed, c.channels[O].receipts.len() as u64);
    assert_eq!((served, signed, answers), (9 * PRICE, 8 * PRICE, 7), "served, signed, answers the payer holds a receipt for");
    let closed = c.close(O).expect("the channel can still be closed");
    assert_eq!(closed["chan"], chan.as_str());
    let paid_out = w.chain.sent.lock().unwrap().last().unwrap().outputs[0].value as u64;
    assert_eq!(paid_out, signed, "the provider is paid what the payer signed, one call less than it served");
}
