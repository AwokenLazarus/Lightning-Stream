//! AGP-093 third closure audit, CLIENT area (the channel library client and the transport): tests
//! written by the auditor against fix wave 4 (AGP-090). No fix is in this file.
//!
//! `hole_*` tests fail today and state the claim that should hold. `ok_*` tests are controls (the
//! honest path in the same rig) and `limit_*` tests pin a number a reader must be told; both pass.
//! The socket tests at the end need `--features http-client` and bind 127.0.0.1:27300-27399.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use xbt402::client::{split_url, Client, ClientConfig, FileClientLedger, MemoryClientLedger, Stage, Transport, Wallet, WalletSend};
use xbt402::funding::{ChainBackend, FundingPolicy, UtxoInfo};
use xbt402::hub::{HubConfig, RouteHub};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::route::SpendScan;
use xbt402::route_client::{RoutePayer, RoutePayerConfig};
use xbt402::signer::{LocalSigner, RouteSigner};
use xbt402::wire::{b64json, payment_payload, request_auth, request_digest_v2, unb64json, CLOSE_PATH, FACILITATOR_VERIFY, OPEN_PATH, ROLLOVER_PATH};
use xbt402::{ChannelError, Result};
use xbt_primitives::address::address_to_spk;
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

const NET: &str = "bip122:11111111111111111111111111111111";
const O: &str = "https://api.example";
const HUB: &str = "http://hub.test";
const PRICE: u64 = 150;

// --- the rig of agp090_client.rs ---------------------------------------------------------------

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

impl SpendScan for MemChain {
    fn find_spend(&self, _txid: &str, _vout: u32, _from: u32) -> Result<Option<Tx>> {
        Ok(None)
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
    let dir = std::env::temp_dir().join(format!("xbt-rs-agp093-client-{name}-{}", std::process::id()));
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

// --- Part B: the open stages -------------------------------------------------------------------

/// Control. A crash between the key (saved) and the funding: the new process reads the keyed
/// channel back, with a local key and with a signer, funds it once and opens it.
#[test]
fn ok_a_restart_before_the_funding_reads_the_keyed_channel_back() {
    for with_signer in [false, true] {
        let w = world(&format!("keyed-restart-{with_signer}"));
        let signer = Arc::new(LocalSigner::new());
        let make = |w: &World| {
            let c = w.bare_client(honest());
            let c = if with_signer { c.with_signer(signer.clone()) } else { c };
            c.with_ledger(Box::new(FileClientLedger::open(&w.dir.join("c.jsonl")).unwrap())).unwrap()
        };
        w.wallet.refuses.store(true, Ordering::SeqCst);
        let key = {
            let mut c = make(&w);
            assert_eq!(get(&mut c), Err("wallet_error".into()));
            assert_eq!(c.channels[O].stage, Stage::Keyed);
            c.channels[O].payer.params.payer_pub
        };
        w.wallet.refuses.store(false, Ordering::SeqCst);
        let mut c = make(&w);
        assert_eq!((c.channels[O].stage, c.channels[O].payer.params.payer_pub), (Stage::Keyed, key), "signer {with_signer}");
        assert_eq!(get(&mut c), Ok(200), "signer {with_signer}");
        assert_eq!((w.funded(), c.channels[O].stage, c.channels[O].payer.params.payer_pub), (1, Stage::Open, key), "signer {with_signer}");
    }
}

/// Control for the upgrade: a channel record written before AGP-090 (no `stage`, no
/// `unanswered_msat`, no `rolled_from`) is read as an open channel and pays on.
#[test]
fn ok_a_ledger_record_from_before_the_stages_is_an_open_channel() {
    let w = world("upgrade");
    let store = Arc::new(MemoryClientLedger::default());
    struct L(Arc<MemoryClientLedger>);
    impl xbt402::client::ClientLedger for L {
        fn load(&self) -> Result<Vec<(String, Value)>> {
            self.0.load()
        }
        fn save(&self, r: &[(String, Value)]) -> Result<()> {
            self.0.save(r)
        }
    }
    {
        let mut c = w.bare_client(honest()).with_ledger(Box::new(L(store.clone()))).unwrap();
        paid_calls(&mut c, 2);
    }
    // strip the three fields AGP-090 added, as an older build wrote the record
    use xbt402::client::ClientLedger;
    let mut recs = store.load().unwrap();
    for (k, v) in recs.iter_mut() {
        if k.starts_with("chan ") {
            let m = v.as_object_mut().unwrap();
            assert!(m.remove("stage").is_some() && m.remove("unanswered_msat").is_some() && m.remove("rolled_from").is_some());
        }
    }
    store.save(&recs).unwrap();
    let mut c = w.bare_client(honest()).with_ledger(Box::new(L(store.clone()))).unwrap();
    assert_eq!((c.channels[O].stage, c.channels[O].unanswered_msat), (Stage::Open, 0));
    paid_calls(&mut c, 2);
    assert_eq!(w.funded(), 1);
}

/// HOLE (Low, new in wave 4). The preflight (review C2) is asked when the channel is keyed. A
/// keyed channel whose `fund` call failed, or whose process stopped before the funding, is funded
/// by a later call on the terms saved then, with no new preflight, for as long as its expiry
/// allows: 827 blocks against a seller whose offer asks for 144 + 1 + 36 (none against the default
/// seller, whose floor is above the payer's own 1,008: see the two tests after the control). A
/// seller that has changed its payTo key meanwhile (a restart with a new key) refuses the funded
/// open: the capacity is locked until expiry by a seller whose preflight would have said no.
#[test]
fn hole_a_keyed_channel_is_not_funded_on_terms_the_seller_no_longer_offers() {
    let w = world("stale-terms");
    *w.prov.lock().unwrap() = provider_with(&w.chain, b"provider payTo", Some(()));
    w.wallet.refuses.store(true, Ordering::SeqCst);
    let mut c = w.client_on("c.jsonl", honest());
    assert_eq!(get(&mut c), Err("wallet_error".into()));
    assert_eq!((c.channels[O].stage, w.funded()), (Stage::Keyed, 0));
    // the wallet is topped up; the seller came back with another payTo key; 10 blocks went by
    w.wallet.refuses.store(false, Ordering::SeqCst);
    *w.prov.lock().unwrap() = provider_with(&w.chain, b"provider payTo after a key rotation", Some(()));
    *w.chain.tip.lock().unwrap() += 10;
    let r = get(&mut c);
    let ch = &c.channels[O];
    assert_eq!(w.funded(), 0, "the client funded {} sat to a channel with the seller's old payTo, with no preflight on the day it funded; \
                               the call answered {r:?}, the channel is {:?} and its coins are locked until block {} (tip {})",
               w.wallet.sends.lock().unwrap().first().map_or(0, |s| s.2), ch.stage, ch.payer.params.expiry, *w.chain.tip.lock().unwrap());
}

/// Control for the hole above: with the seller unchanged the same retry funds once and pays.
#[test]
fn ok_a_keyed_channel_is_funded_by_the_retry_when_the_seller_is_unchanged() {
    let w = world("stale-terms-control");
    *w.prov.lock().unwrap() = provider_with(&w.chain, b"provider payTo", Some(()));
    w.wallet.refuses.store(true, Ordering::SeqCst);
    let mut c = w.client_on("c.jsonl", honest());
    assert_eq!(get(&mut c), Err("wallet_error".into()));
    w.wallet.refuses.store(false, Ordering::SeqCst);
    *w.chain.tip.lock().unwrap() += 10;
    assert_eq!(get(&mut c), Ok(200));
    assert_eq!((w.funded(), c.channels[O].stage), (1, Stage::Open));
}

/// HOLE (Medium for availability, new in wave 4; nothing is lost). The shipped provider's offer
/// asks for 1,008 + 1 + 144 = 1,153 blocks at least, above the payer's own 1,008, so a keyed
/// channel is "too near its expiry to fund" (`client.rs:815`) as soon as the tip has moved by ONE
/// block. With a signer the stale record is never set aside (`shelve_keyed`, `client.rs:860`): one
/// failed `fund` call (an empty hot wallet, a policy refusal, a timeout) and one block later every
/// call to that seller fails `open_unresolved`, for good, until the embedder calls
/// `forget_unfunded`. No shipped binary calls it (`xbt-wallet-mcp` with `XBT_MCP_PAYER=local`,
/// `xbt-signer-payer`). Before wave 4 the next call simply tried again.
#[test]
fn hole_one_failed_funding_call_does_not_end_a_signer_backed_clients_business_with_a_seller() {
    let w = world("wedge-signer");
    let mut c = w.bare_client(honest()).with_signer(Arc::new(LocalSigner::new()));
    w.wallet.refuses.store(true, Ordering::SeqCst);
    assert_eq!(get(&mut c), Err("wallet_error".into()));
    // the wallet is topped up a block later
    w.wallet.refuses.store(false, Ordering::SeqCst);
    *w.chain.tip.lock().unwrap() += 1;
    let out: Vec<_> = (0..20).map(|_| {
        *w.chain.tip.lock().unwrap() += 1;
        get(&mut c)
    }).collect();
    assert!(out.contains(&Ok(200)), "one failed funding call, and 20 later calls with a funded wallet all fail: {:?} (funded {} channels)", &out[..3], w.funded());
}

/// The same with a local key: each failed `fund` call a block apart leaves one kept key, the call
/// after it fails `open_unresolved`, and at 16 kept keys the origin is refused for good.
#[test]
fn hole_failed_funding_calls_do_not_end_a_clients_business_with_a_seller() {
    let w = world("wedge-local");
    let mut c = w.client_on("c.jsonl", honest());
    w.wallet.refuses.store(true, Ordering::SeqCst);
    let mut failed = vec![];
    // an empty wallet, and a caller that tries again every block for a while
    for _ in 0..40 {
        failed.push(get(&mut c).unwrap_err());
        *w.chain.tip.lock().unwrap() += 1;
    }
    w.wallet.refuses.store(false, Ordering::SeqCst);
    let out: Vec<_> = (0..20).map(|_| {
        *w.chain.tip.lock().unwrap() += 1;
        get(&mut c)
    }).collect();
    assert!(out.contains(&Ok(200)), "after {} failed funding calls ({} keys kept), 20 calls with a funded wallet all fail: {:?}",
            failed.iter().filter(|e| *e == "wallet_error").count(), c.unfunded.get(O).map_or(0, Vec::len), &out[..3]);
}

/// LIMIT. A seller that answers the preflight yes and every funded open no: one channel is
/// funded, the client can sign no close for it, and the record stays `Funded` past the channel's
/// expiry. Nothing in the client clears it: until the embedder removes the record by hand the
/// origin can never be opened again, and the refund is the only way back to the coins.
#[test]
fn limit_a_refused_funded_channel_blocks_its_origin_until_the_embedder_removes_it() {
    let w = world("funded-for-ever");
    let mut c = w.client_on("c.jsonl", Box::new(|path, req, _, r| {
        if path == OPEN_PATH && req.get("preflight") != Some(&Value::Bool(true)) {
            return Ok(HttpResponse::new(400, vec![], json!({"error": "bad_funding", "detail": "no"}).to_string().into_bytes()));
        }
        Ok(r)
    }));
    for _ in 0..5 {
        assert_eq!(get(&mut c), Err("bad_funding".into()));
    }
    assert_eq!((w.funded(), c.opened_sats, c.channels[O].stage), (1, 200_000, Stage::Funded));
    assert_eq!(c.close(O).unwrap_err().code, "no_channel", "no cooperative way out before the expiry");
    let expiry = c.channels[O].payer.params.expiry;
    assert_eq!(expiry, 1_000 + 1_153, "the default seller asks for 1,008 + 1 + 144 blocks");
    // long after the expiry the record is still there and the origin still cannot be opened
    *w.chain.tip.lock().unwrap() = expiry + 5_000;
    assert_eq!(get(&mut c), Err("bad_funding".into()));
    assert_eq!((w.funded(), c.channels[O].stage), (1, Stage::Funded));
    let refund = Tx::parse_hex(&c.channels[O].refund_hex).unwrap();
    assert_eq!(refund.locktime, expiry, "the refund spends at the expiry, not before");
}

/// HOLE (Low, left from before; a way round the new rule "an origin with a channel on the books
/// is never funded again"). The book is keyed by the origin as the caller's URL spells it
/// (`split_url`), while the request binding itself reads `HTTPS://API.example:443` and
/// `https://u@api.example` as the origin `https://api.example` (`wire::request_url`). A seller
/// that refuses every funded open and gets its URLs called in several spellings (links in its own
/// answers, which an agent follows) is funded once per spelling, up to `budget_sats`.
#[test]
fn hole_a_refusing_seller_is_funded_once_however_its_origin_is_spelled() {
    let w = world("spellings");
    let mut c = w.bare_client(Box::new(|path, req, _, r| {
        if path == OPEN_PATH && req.get("preflight") != Some(&Value::Bool(true)) {
            return Ok(HttpResponse::new(400, vec![], json!({"error": "bad_funding", "detail": "no"}).to_string().into_bytes()));
        }
        Ok(r)
    }));
    let spellings = ["https://api.example", "https://API.example", "https://api.example:443", "https://u@api.example", "HTTPS://api.example"];
    for o in spellings {
        assert_eq!(xbt402::wire::request_url(&format!("{o}/v1/q")).host, "api.example");
        assert_eq!(c.request("GET", &format!("{o}/v1/q"), b"").unwrap_err().code, "bad_funding", "{o}");
    }
    assert_eq!(w.funded(), 1, "one seller, {} channels funded ({} sat): {:?}", w.funded(), c.opened_sats, c.channels.keys().collect::<Vec<_>>());
}

// --- Part B: the unanswered slack --------------------------------------------------------------

/// A seller (or whoever sits between) that serves nothing: `Serve` forwards to the provider,
/// `Error` answers every paid request with a 503 and no receipt and never shows it to the
/// provider, `Claim` answers the next paid request with an unsigned 402 naming `claim` msat.
struct Greedy {
    prov: Arc<Provider>,
    mode: Arc<AtomicUsize>,
    claim: Arc<Mutex<u64>>,
    last_402: Mutex<Option<Value>>,
}

impl Transport for Greedy {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        let (_, path) = split_url(url);
        let is_paid = paid(&path, headers);
        match self.mode.load(Ordering::SeqCst) {
            1 if is_paid => return Ok(HttpResponse::new(503, vec![], b"try later".to_vec())),
            2 if is_paid => {
                self.mode.store(1, Ordering::SeqCst);
                let mut pr = self.last_402.lock().unwrap().clone().unwrap();
                pr["channel"] = json!({"spentMsat": self.claim.lock().unwrap().to_string()});
                return Ok(HttpResponse::new(402, vec![("PAYMENT-REQUIRED".into(), b64json(&pr))], vec![]));
            }
            _ => {}
        }
        let r = self.prov.serve(method, &path, headers, body, url, None);
        if r.status == 402 {
            *self.last_402.lock().unwrap() = Some(unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap());
        }
        Ok(r)
    }
}

/// LIMIT (AGP-090 stated limit 2, with its number). The provider is believed for one quote for
/// EVERY paid request it answered without a receipt, not only for answers lost on the way: ten
/// requests answered `503` and never served, then one unsigned 402 naming ten more calls, and the
/// client signs for all ten. Before wave 4 the bound was one call over the channel's life. What
/// bounds it now is the caller (how often it retries), the channel's capacity and the daily budget.
/// The 402's channel view is unsigned, so anyone who can alter answers on the way can do the same
/// to an honest provider's payer (the provider is then overpaid at the close).
#[test]
fn limit_a_seller_that_answers_errors_is_believed_for_one_quote_per_request() {
    let w = world("believed");
    let (mode, claim) = (Arc::new(AtomicUsize::new(0)), Arc::new(Mutex::new(0u64)));
    let ch0 = w.chain.clone();
    let t = Greedy { prov: w.prov(), mode: mode.clone(), claim: claim.clone(), last_402: Mutex::new(None) };
    let mut c = Client::new(ClientConfig::new(NET), Box::new(t), Box::new(Shared(w.wallet.clone())), Box::new(move || ch0.block_count()));
    // an unpaid probe first, so the seller has a 402 of its own to copy
    paid_calls(&mut c, 1);
    let chan = c.channels[O].payer.params.channel_id();
    assert_eq!((c.channels[O].payer.signed, c.channels[O].spent_msat), (0, PRICE * 1000), "postpay: one call served, nothing signed yet");
    mode.store(1, Ordering::SeqCst);
    for _ in 0..10 {
        assert_eq!(get(&mut c), Ok(503), "an error answer carries no receipt and is handed to the caller");
    }
    assert_eq!(c.channels[O].unanswered_msat, 10 * PRICE * 1000);
    // it needs a 402 to copy: the client's next paid request gets the claim
    *claim.lock().unwrap() = 11 * PRICE * 1000;
    mode.store(2, Ordering::SeqCst);
    assert_eq!(get(&mut c), Ok(503));
    let ch = &c.channels[O];
    let served = w.prov().channel_state(&chan).unwrap().spent_msat;
    assert_eq!(served, PRICE * 1000, "the provider served one call");
    assert_eq!((ch.spent_msat, ch.payer.signed), (11 * PRICE * 1000, 11 * PRICE),
               "the payer adopted ten unserved calls on an unsigned 402 and signed {} sat for {} sat of service", ch.payer.signed, served / 1000);
    // one more than the requests it left unanswered is still refused (one is in flight again)
    *claim.lock().unwrap() = 14 * PRICE * 1000;
    mode.store(2, Ordering::SeqCst);
    assert_eq!(get(&mut c), Err("bad_offer".into()));
}

/// Control: the resync cannot move the payer's seq, and a receipt for another seq is refused
/// whatever its numbers; a 402 naming a LOWER total than the receipts changes nothing.
#[test]
fn ok_a_402_cannot_roll_the_state_back_or_move_the_seq() {
    let w = world("rollback");
    let (mode, claim) = (Arc::new(AtomicUsize::new(0)), Arc::new(Mutex::new(0u64)));
    let ch0 = w.chain.clone();
    let t = Greedy { prov: w.prov(), mode: mode.clone(), claim: claim.clone(), last_402: Mutex::new(None) };
    let mut c = Client::new(ClientConfig::new(NET), Box::new(t), Box::new(Shared(w.wallet.clone())), Box::new(move || ch0.block_count()));
    paid_calls(&mut c, 6);
    let (seq, spent, signed) = (c.channels[O].seq, c.channels[O].spent_msat, c.channels[O].payer.signed);
    *claim.lock().unwrap() = 0;
    mode.store(2, Ordering::SeqCst);
    assert_eq!(get(&mut c), Ok(503));
    let ch = &c.channels[O];
    assert_eq!(signed, 5 * PRICE, "postpay: the sixth call carried the state for five");
    assert_eq!((ch.spent_msat, ch.payer.signed), (spent, spent / 1000), "the receipted total stands; the next state pays it and no more");
    assert_eq!(ch.seq, seq + 2, "the seq is the payer's own count: two requests left");
}

/// The provider serves the request and the payer's process stops before it saves (`crash`).
struct Crashy(Arc<Provider>, Arc<AtomicBool>);

impl Transport for Crashy {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        let (_, path) = split_url(url);
        let r = self.0.serve(method, &path, headers, body, url, None);
        if paid(&path, headers) && self.1.load(Ordering::SeqCst) {
            assert_eq!(r.status, 200, "the provider served the call");
            panic!("the payer's process stops here: the request left, nothing is saved");
        }
        Ok(r)
    }
}

/// HOLE (Low, left from before: AGP-090 found-not-fixed 3, which says one such crash is covered).
/// The quote of a paid request is counted in memory when it leaves and saved only when the call
/// returns (`request_with` -> `saved`). A process that stops in between restarts one seq and one
/// quote behind; the channel's one call of slack covers that once. The second time in a channel's
/// life the 402 is refused `bad_offer` on every call: the wedge of the audit's item 9, reached by
/// two crashes where it took two lost answers.
#[test]
fn hole_two_crashes_after_a_request_left_do_not_end_the_channel() {
    let w = world("crash");
    let crash = Arc::new(AtomicBool::new(false));
    let make = |w: &World| {
        let c = w.chain.clone();
        Client::new(ClientConfig::new(NET), Box::new(Crashy(w.prov(), crash.clone())), Box::new(Shared(w.wallet.clone())), Box::new(move || c.block_count()))
            .with_ledger(Box::new(FileClientLedger::open(&w.dir.join("c.jsonl")).unwrap())).unwrap()
    };
    let mut c = make(&w);
    paid_calls(&mut c, 3);
    let mut after = vec![];
    for _ in 0..2 {
        crash.store(true, Ordering::SeqCst);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| get(&mut c)));
        assert!(r.is_err());
        crash.store(false, Ordering::SeqCst);
        drop(c);
        c = make(&w);
        after.push((0..4).map(|_| get(&mut c)).collect::<Vec<_>>());
    }
    // AGP-096 changed this line, and no other in this file: the audit pinned the first call after
    // a crash at 402 (its seq, then its amount, were one call behind, and the channel's slack
    // covered that once). The request's count is now saved before it leaves, so the call pays.
    assert_eq!(after[0], [Ok(200), Ok(200), Ok(200), Ok(200)], "a crash after a request left costs no later call");
    let chan = c.channels[O].payer.params.channel_id();
    assert!(after[1].contains(&Ok(200)), "after the second crash every call fails: {:?}; the provider has charged {} msat, the payer's book says {}",
            after[1], w.prov().channel_state(&chan).unwrap().spent_msat, c.channels[O].spent_msat);
}

/// HOLE (Low, the remainder of the audit's item 9 for someone between payer and provider). A 402
/// is unsigned, and the client takes one as the provider's word that the request was not charged
/// (`refused`, `client.rs:1115`). Whoever sits between lets the provider serve a paid request and
/// answers the payer with a bare 402 instead: the charge is real and the payer has taken its
/// quote off the books. The channel's one call of slack absorbs that once (the payer pays for an
/// answer it never saw); the second time every call is `bad_offer`, for good.
#[test]
fn hole_two_forged_refusals_do_not_end_the_channel() {
    let w = world("forged-402");
    let forge = Arc::new(AtomicUsize::new(0));
    let f2 = forge.clone();
    let last_402: Mutex<Option<String>> = Mutex::new(None);
    let mut c = w.bare_client(Box::new(move |path, _, h, r| {
        if r.status == 402 {
            *last_402.lock().unwrap() = r.header("PAYMENT-REQUIRED").map(str::to_string);
        }
        if paid(path, h) && r.status == 200 && f2.load(Ordering::SeqCst) > 0 {
            f2.fetch_sub(1, Ordering::SeqCst);
            // the provider served and charged; the payer is shown the offer and nothing else
            let mut pr = unb64json(&last_402.lock().unwrap().clone().unwrap()).unwrap();
            pr.as_object_mut().unwrap().remove("channel");
            return Ok(HttpResponse::new(402, vec![("PAYMENT-REQUIRED".into(), b64json(&pr))], vec![]));
        }
        Ok(r)
    }));
    paid_calls(&mut c, 4);
    let chan = c.channels[O].payer.params.channel_id();
    forge.store(1, Ordering::SeqCst);
    // one forged refusal: that call fails (its retry is one call short), the next adopts the hidden
    // charge on the channel's slack and pays for it
    assert_eq!((get(&mut c), get(&mut c)), (Ok(402), Ok(200)));
    paid_calls(&mut c, 2);
    forge.store(1, Ordering::SeqCst);
    let out: Vec<_> = (0..12).map(|_| get(&mut c)).collect();
    let charged = w.prov().channel_state(&chan).unwrap().spent_msat / (PRICE * 1000);
    let kept = c.channels[O].receipts.len();
    assert!(out[1..].contains(&Ok(200)), "after a second forged refusal no call succeeds: {out:?}; the provider charged {charged} calls, \
                                                      the payer kept {kept} answers");
}

// --- Part B: one next key per rollover ---------------------------------------------------------

/// The seller of the rollover tests: attempt 1 reaches the provider (which broadcasts it) and is
/// answered with an error; attempt 2's answer is lost; attempt 3 is answered `200` with whatever
/// the test put in `forged` (the transaction of attempt 2, which the seller never broadcasts).
fn rollover_seller(forged: Arc<Mutex<Option<Value>>>) -> Rewrite {
    let n = AtomicUsize::new(0);
    Box::new(move |path, _, _, r| {
        if path != ROLLOVER_PATH {
            return Ok(r);
        }
        match n.fetch_add(1, Ordering::SeqCst) {
            0 => {
                assert_eq!(r.status, 200, "the provider took the first rollover");
                Ok(HttpResponse::new(400, vec![], br#"{"error":"bad_request","detail":"no"}"#.to_vec()))
            }
            1 => Err(ChannelError::new("transport_error", "timed out")),
            _ => Ok(HttpResponse::new(200, vec![], forged.lock().unwrap().clone().unwrap().to_string().into_bytes())),
        }
    })
}

/// Three attempts to roll one channel over; the seller broadcasts the first and says yes to the
/// last. Returns (client, the txid on chain).
fn rolled_three_times(w: &World, with_signer: bool) -> (Client, String) {
    let forged = Arc::new(Mutex::new(None));
    let mut c = w.bare_client(rollover_seller(forged.clone()));
    if with_signer {
        c = c.with_signer(Arc::new(LocalSigner::new()));
    }
    paid_calls(&mut c, 8);
    assert_eq!(c.rollover(O).unwrap_err().code, "bad_request");
    let on_chain = w.chain.sent.lock().unwrap().last().unwrap().txid();
    *w.chain.tip.lock().unwrap() += 1;
    assert_eq!(c.rollover(O).unwrap_err().code, "transport_error");
    let second = &c.next_rolled[O][1].payer.params;
    assert_ne!(second.funding_txid(), on_chain, "a block later the rollover is another transaction");
    *forged.lock().unwrap() = Some(json!({"txid": second.funding_txid(), "nextChan": format!("{}:1", second.funding_txid()), "nextCapacity": second.capacity}));
    c.rollover(O).expect("the seller's yes names the transaction the client signed");
    (c, on_chain)
}

/// Control, a local key: the client made the next channel of the seller's "yes" the live one, and
/// the embedder, seeing the FIRST attempt's transaction on chain, adopts that one. Its refund is
/// held.
#[test]
fn ok_local_key_an_earlier_rollover_that_confirms_after_a_later_yes_is_adopted() {
    let w = world("roll-local");
    let (mut c, on_chain) = rolled_three_times(&w, false);
    c.adopt_rolled(O, &on_chain).unwrap();
    let refund = Tx::parse_hex(&c.channels[O].refund_hex).unwrap();
    assert_eq!((refund.inputs[0].prevout.txid_hex(), refund.inputs[0].prevout.vout), (on_chain, 1));
}

/// HOLE (Medium for an embedder that keeps keys in a `LocalSigner`; left from before, reached by
/// another step than the audit's item 6). Every attempt pays one next key (AGP-090), and the
/// signer binds that key to the next channel of the first rollover the seller says yes to
/// (`take_next` -> `attach`, which takes the issued key out of its slot). A seller that says yes
/// to a later attempt and broadcasts an earlier one leaves the next channel that is on chain with
/// no key the signer will sign a refund with: `adopt_rolled` fails `bad_key`.
#[test]
fn hole_signer_backed_an_earlier_rollover_that_confirms_after_a_later_yes_is_adopted() {
    let w = world("roll-signer");
    let (mut c, on_chain) = rolled_three_times(&w, true);
    let next = c.next_rolled[O].iter().find(|n| n.payer.params.funding_txid() == on_chain).expect("the record of the attempt on chain is kept").payer.params.clone();
    assert!(w.chain.utxos.lock().unwrap().contains_key(&(on_chain.clone(), 1)), "the next channel of the first attempt is funded on chain");
    let r = c.adopt_rolled(O, &on_chain);
    assert!(r.is_ok(), "{} sat sit in the next channel {}:1 and the signer-backed client cannot bind it or get its refund: {:?}",
            next.capacity, &on_chain[..16], r.unwrap_err());
}

// --- Part C, found-not-fixed 1 and its neighbours: the routed client's ch1 ----------------------

/// The hub as the routed client reaches it. `refuse`: funded opens are answered `bad_funding`
/// (the hub never hears of them). `lose`: the hub opens the channel and the answer is lost.
struct HubNet {
    hub: Arc<RouteHub>,
    refuse: Arc<AtomicBool>,
    lose: Arc<AtomicUsize>,
}

impl Transport for HubNet {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        let (_, path) = split_url(url);
        let req: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        let funded_open = path == OPEN_PATH && req.get("preflight") != Some(&Value::Bool(true));
        if funded_open && self.refuse.load(Ordering::SeqCst) {
            return Ok(HttpResponse::new(400, vec![], json!({"error": "bad_funding", "detail": "no"}).to_string().into_bytes()));
        }
        let r = self.hub.serve(method, &path, headers, body, url, None);
        if funded_open && self.lose.load(Ordering::SeqCst) > 0 {
            assert_eq!(r.status, 200, "the hub opened ch1: {}", String::from_utf8_lossy(&r.body));
            self.lose.fetch_sub(1, Ordering::SeqCst);
            return Err(ChannelError::new("transport_error", "timed out reading the answer"));
        }
        Ok(HttpResponse::new(r.status, r.headers.into_iter().map(|(k, v)| (k.to_ascii_uppercase(), v)).collect(), r.body))
    }
}

struct NoNet;

impl Transport for NoNet {
    fn request(&self, _: &str, url: &str, _: &[u8], _: &[(String, String)]) -> Result<HttpResponse> {
        Err(ChannelError::new("transport_error", format!("refused: {url}")))
    }
}

struct Routed {
    w: World,
    refuse: Arc<AtomicBool>,
    lose: Arc<AtomicUsize>,
    hub: Arc<RouteHub>,
}

fn routed(name: &str) -> Routed {
    let w = world(name);
    let hub_cfg = HubConfig::from_json(&json!({"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500,
                                               "delta": 36, "reveal_timeout": 1.0, "ch2_capacity": 100000, "ch2_expiry_blocks": 1000,
                                               "close_margin": 36, "policy": {"min_capacity": 20000, "min_expiry_blocks": 500, "max_expiry_blocks": 8640}})).unwrap();
    let hub = Arc::new(RouteHub::new(w.chain.clone(), w.chain.clone(), Box::new(Shared(Arc::new(TestWallet { chain: w.chain.clone(), ..TestWallet::default() }))),
                                     Box::new(NoNet), SecretKey::from_slice(&sha256(b"hub")).unwrap(), NET, Some(&w.dir.join("hub")), hub_cfg).unwrap());
    Routed { w, refuse: Arc::new(AtomicBool::new(false)), lose: Arc::new(AtomicUsize::new(0)), hub }
}

impl Routed {
    fn payer(&self) -> RoutePayer {
        let c = self.w.chain.clone();
        let signer: Arc<dyn RouteSigner> = Arc::new(LocalSigner::new());
        RoutePayer::new(HUB, RoutePayerConfig::new(NET), signer, Arc::new(Shared(self.w.wallet.clone())),
                        Box::new(HubNet { hub: self.hub.clone(), refuse: self.refuse.clone(), lose: self.lose.clone() }), Box::new(move || c.block_count()))
    }
}

/// Control: the routed client opens ch1 once at an honest hub, and a second `open` funds nothing.
#[test]
fn ok_the_routed_client_opens_ch1_once() {
    let r = routed("route-ok");
    let pay = r.payer();
    pay.open().unwrap();
    pay.open().unwrap();
    assert_eq!(r.w.funded(), 1);
}

/// HOLE (Medium, left from before: the routed variant of the audit's item 4, which named the
/// library client only). A hub that answers the preflight yes and the funded open no. The Rust
/// routed client records ch1 only when it has a ledger, and then only after `fund_channel` and
/// `attach` returned (`route_client.rs:575-585`); without a ledger a refused open leaves nothing
/// on the books, and every `open` funds another ch1. The routed client has no budget
/// (`budget_sats` is the library client's), so the hub's `minCapacity` is the amount, each time.
#[test]
fn hole_the_routed_client_funds_a_refusing_hub_once() {
    let r = routed("route-refuse");
    r.refuse.store(true, Ordering::SeqCst);
    let pay = r.payer();
    for _ in 0..4 {
        assert_eq!(pay.open().unwrap_err().code, "bad_funding");
    }
    let sent: u64 = r.w.wallet.sends.lock().unwrap().iter().map(|s| s.2).sum();
    assert_eq!(r.w.funded(), 1, "four calls to open funded {} ch1s, {sent} sat in all, at a hub that opened none", r.w.funded());
}

/// HOLE (Low, left from before; the "lost answer" side of the same open). With a ledger the
/// routed client posts the open again and funds nothing, but it does not take the hub's
/// `duplicate_channel` for the yes that was lost (the library client does, `client.rs:898`): after
/// one lost answer `open` fails on every call and after every restart, with ch1 funded and open
/// at the hub.
#[test]
fn hole_the_routed_client_finishes_an_open_whose_answer_was_lost() {
    let r = routed("route-lost");
    r.lose.store(1, Ordering::SeqCst);
    let pay = r.payer().with_ledger(Box::new(MemoryClientLedger::default())).unwrap();
    assert_eq!(pay.open().unwrap_err().code, "transport_error");
    let again = pay.open();
    assert_eq!(r.w.funded(), 1, "nothing is funded twice");
    assert!(again.is_ok(), "the hub has ch1 open and the client can never finish its open: {:?}", again.unwrap_err());
}

// --- Part C item 4: overflow checks are on in release; a counterparty's number must not panic ---

fn extreme_numbers() -> Vec<Value> {
    vec![json!(0), json!(1), json!(545), json!(546), json!(u32::MAX), json!(u32::MAX as u64 + 1), json!(i64::MAX), json!(i64::MAX as u64 + 1), json!(u64::MAX),
         json!(u64::MAX - 1), json!(-1), json!(i64::MIN), json!("18446744073709551615"), json!("18446744073709551616"),
         json!("340282366920938463463374607431768211455"), json!("999999999999999999999999999999"), json!("-999999999999999999999999999999"),
         json!(1e30), json!(1.5), json!(""), json!("x"), json!(null), json!(true), json!([]), json!({})]
}

/// No number a payer can put in a request makes the provider panic. The release profile keeps
/// overflow checks (a panic; an abort under `release-small`), and this test build has them too.
/// Every endpoint a payer reaches, every numeric field, the values above; the paid call is sent
/// with a valid request MAC so that it reaches the state checks.
#[test]
fn ok_no_number_from_a_payer_panics_the_provider() {
    let w = world("fuzz-provider");
    let mut c = w.bare_client(honest());
    paid_calls(&mut c, 3);
    let prov = w.prov();
    let ch = c.channels[O].clone();
    let chan = ch.payer.params.channel_id();
    let p = ch.payer.params.clone();
    let open = json!({"capacity": p.capacity, "expiry": p.expiry, "payerPub": hex::encode(p.payer_pub), "payerSpk": hex::encode(&p.payer_spk),
                      "redeemScript": hex::encode(p.script()), "txid": p.funding_txid(), "vout": 0});
    #[allow(clippy::type_complexity)]
    let mut reqs: Vec<(String, &str, Value, Vec<(String, String)>)> = vec![];
    let mut seq = 1_000u64;
    for x in extreme_numbers() {
        for k in ["capacity", "expiry", "vout", "txid"] {
            for preflight in [false, true] {
                let mut ch_req = open.clone();
                ch_req[k] = x.clone();
                let mut body = json!({"x402Version": 2, "network": NET, "channel": ch_req});
                if preflight {
                    body["preflight"] = true.into();
                    body["channel"].as_object_mut().unwrap().remove("txid");
                }
                reqs.push((OPEN_PATH.into(), "POST", body, vec![]));
            }
        }
        for (amount, expiry) in [(x.clone(), json!(2_100)), (json!(600), x.clone())] {
            reqs.push((ROLLOVER_PATH.into(), "POST", json!({"chan": chan, "amount": amount, "next": {"payerPub": hex::encode(p.payer_pub), "expiry": expiry,
                                                                                               "payerSpk": hex::encode(&p.payer_spk)}, "sig": "21"}), vec![]));
        }
        reqs.push((FACILITATOR_VERIFY.into(), "POST", json!({"x402Version": 2, "paymentPayload": {"x402Version": 2, "accepted": ch.accepted, "payload": {"chan": chan, "cum": x, "sig": "21"}},
                                                             "paymentRequirements": ch.accepted}), vec![]));
        reqs.push((CLOSE_PATH.into(), "POST", json!({"chan": chan, "sig": "00", "payload": {"chan": chan, "seq": x, "cum": x, "sig": ""}}), vec![]));
        // paid calls with a valid MAC: the seq and the cum are the payer's numbers
        for sig in ["", "21", "00"] {
            for (s, cum) in [(json!(seq), x.clone()), (x.clone(), json!("546")), (x.clone(), x.clone())] {
                seq += 1;
                let mut pl = json!({"chan": chan, "seq": s, "cum": cum});
                if !sig.is_empty() {
                    pl["sig"] = sig.into();
                }
                let url = format!("{O}/v1/q");
                pl["auth"] = request_auth(&ch.auth_key, &chan, pl.get("seq"), pl.get("cum"), Some(sig), &request_digest_v2("GET", &url, b"")).into();
                reqs.push(("/v1/q".into(), "GET", Value::Null, vec![("PAYMENT-SIGNATURE".into(), b64json(&payment_payload(&ch.accepted, &pl)))]));
            }
        }
    }
    let (mut panics, mut codes) = (vec![], std::collections::BTreeMap::<String, usize>::new());
    let n = reqs.len();
    for (path, method, body, headers) in reqs {
        let bytes = if body.is_null() { vec![] } else { body.to_string().into_bytes() };
        let url = format!("{O}{path}");
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prov.serve(method, &path, &headers, &bytes, &url, None)));
        match r {
            Ok(r) => {
                let doc = r.header("PAYMENT-REQUIRED").and_then(|h| unb64json(h).ok()).or_else(|| serde_json::from_slice::<Value>(&r.body).ok()).unwrap_or(Value::Null);
                *codes.entry(format!("{} {}", r.status, doc.get("error").and_then(Value::as_str).unwrap_or("-"))).or_default() += 1;
            }
            Err(_) => panics.push(format!("{method} {path} {body} {headers:?}")),
        }
    }
    assert!(panics.is_empty(), "{} of {n} requests made the provider panic:\n{}", panics.len(), panics.join("\n"));
    // the paid calls did get past the MAC: the state checks answered
    assert!(codes.keys().any(|k| k.contains("bad_sig") || k.contains("stale_amount") || k.contains("bad_amount")), "{codes:?}");
    // and the provider still serves (no lock was left held): another payer, since this one spent
    // its own seq up to u64::MAX with its own MAC key
    let mut c2 = w.bare_client(honest());
    paid_calls(&mut c2, 2);
    println!("{n} requests, answers: {codes:?}");
}

/// No number a seller can put in an offer, a 402's channel view, a rollover answer or a
/// conditional offer makes the client panic.
#[test]
fn ok_no_number_from_a_seller_panics_the_client() {
    let fields = ["amount", "minCapacity", "maxCapacity", "closeFeeSat", "minExpiryBlocks", "maxExpiryBlocks", "minConf", "closeMarginBlocks", "spentMsat",
                  "nextCapacity", "cond.amount", "cond.csvDelta"];
    let mut panics = vec![];
    let mut ran = 0;
    for field in fields {
        for x in extreme_numbers() {
            for open_first in [false, true] {
                let w = world("fuzz-client");
                w.prov().offer_conditional("/v1/secret", 600, b"the deliverable", None);
                let on = Arc::new(AtomicBool::new(!open_first));
                let (on2, x2) = (on.clone(), x.clone());
                let f: Rewrite = Box::new(move |path, _, _, mut r| {
                    if !on2.load(Ordering::SeqCst) {
                        return Ok(r);
                    }
                    if path == ROLLOVER_PATH && field == "nextCapacity" {
                        let mut v: Value = serde_json::from_slice(&r.body).unwrap_or(json!({}));
                        v["nextCapacity"] = x2.clone();
                        return Ok(HttpResponse::new(200, vec![], v.to_string().into_bytes()));
                    }
                    if r.status == 402 {
                        let mut pr = unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap();
                        match field {
                            "amount" => pr["accepts"][0]["amount"] = x2.clone(),
                            "spentMsat" => pr["channel"] = json!({"spentMsat": x2}),
                            "cond.amount" | "cond.csvDelta" => {
                                if pr["accepts"][0]["extra"].get("conditional").is_some() {
                                    pr["accepts"][0]["extra"]["conditional"][&field[5..]] = x2.clone();
                                }
                            }
                            "nextCapacity" => {}
                            k => pr["accepts"][0]["extra"][k] = x2.clone(),
                        }
                        r.headers.retain(|(k, _)| k != "PAYMENT-REQUIRED");
                        r.headers.push(("PAYMENT-REQUIRED".into(), b64json(&pr)));
                    }
                    Ok(r)
                });
                let mut c = w.bare_client(f);
                if open_first {
                    paid_calls(&mut c, 8);
                    on.store(true, Ordering::SeqCst);
                    if field == "spentMsat" {
                        // a 402 on an open channel: the provider refuses a seq it has seen
                        c.channels.get_mut(O).unwrap().seq = 1;
                    }
                }
                ran += 1;
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _ = c.request("GET", &format!("{O}/v1/q"), b"");
                    let _ = c.request_conditional("GET", &format!("{O}/v1/secret"), b"");
                    let _ = c.request("GET", &format!("{O}/v1/q"), b"");
                    let _ = c.rollover(O);
                    let _ = c.close(O);
                }));
                if r.is_err() {
                    panics.push(format!("{field} = {x} (channel open first: {open_first})"));
                }
            }
        }
    }
    assert!(panics.is_empty(), "{} of {ran} sellers made the client panic:\n{}", panics.len(), panics.join("\n"));
}

// --- Part A item 17 / Part C: the transport over real sockets ------------------------------------

#[cfg(feature = "http-client")]
mod sockets {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use xbt402::client::Transport;
    use xbt402::http::UreqTransport;

    /// Read one request head (and nothing after it) from `s`. False when the peer closed.
    fn read_head(s: &mut std::net::TcpStream) -> bool {
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match s.read(&mut b) {
                Ok(1) => head.push(b[0]),
                _ => return false,
            }
        }
        true
    }

    /// A server on 127.0.0.1:`port` that answers the k-th request of each connection with
    /// `answers[k]` and then keeps the connection open, or closes it when the answers run out.
    /// Returns how many connections it has accepted.
    fn server(port: u16, answers: Vec<Vec<u8>>) -> Arc<AtomicUsize> {
        let l = TcpListener::bind(("127.0.0.1", port)).unwrap();
        let conns = Arc::new(AtomicUsize::new(0));
        let c2 = conns.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                c2.fetch_add(1, Ordering::SeqCst);
                let answers = answers.clone();
                std::thread::spawn(move || {
                    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    for a in answers {
                        if !read_head(&mut s) {
                            return;
                        }
                        if s.write_all(&a).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        conns
    }

    fn get(t: &UreqTransport, port: u16) -> Result<String, String> {
        t.request("GET", &format!("http://127.0.0.1:{port}/c"), b"", &[]).map(|r| String::from_utf8_lossy(&r.body).to_string()).map_err(|e| format!("{}: {}", e.code, e.msg))
    }

    const WHOLE: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n";

    /// T3, every place a chunked body can be cut: each is an error, and the whole one is not.
    #[test]
    fn ok_t3_a_chunked_body_cut_anywhere_is_an_error() {
        let full = WHOLE.to_vec();
        let head = full.iter().position(|b| *b == b'5').unwrap();
        let mut port = 27_300u16;
        let mut wrong = vec![];
        // every cut from "inside the first chunk size" to "one byte short of the last chunk's size line"
        let last_chunk = full.len() - b"0\r\n\r\n".len();
        for cut in head..=last_chunk + 1 {
            server(port, vec![full[..cut].to_vec()]);
            let r = get(&UreqTransport::default(), port);
            // the body is complete exactly when the last-chunk line `0\r\n` has arrived
            if r.is_ok() {
                wrong.push(format!("cut at byte {cut} of {}: {r:?}", full.len()));
            }
            port += 1;
        }
        assert!(wrong.is_empty(), "a cut chunked body came back as Ok:\n{}", wrong.join("\n"));
        // complete: with the last chunk, with or without the final CRLF (a trailer section cut short loses no body byte)
        for cut in [full.len() - 2, full.len()] {
            server(port, vec![full[..cut].to_vec()]);
            assert_eq!(get(&UreqTransport::default(), port), Ok("helloworld".into()), "cut at {cut}");
            port += 1;
        }
        assert!(port <= 27_360);
    }

    /// The patch's side effects: a whole chunked answer still returns its connection to the pool
    /// (two requests, one connection), a Content-Length answer too, and after a cut chunked answer
    /// the next request does not reuse the broken connection.
    #[test]
    fn ok_the_patched_decoder_keeps_keep_alive_and_drops_a_cut_connection() {
        let t = UreqTransport::default();
        let conns = server(27_370, vec![WHOLE.to_vec(), WHOLE.to_vec(), WHOLE.to_vec()]);
        for _ in 0..3 {
            assert_eq!(get(&t, 27_370), Ok("helloworld".into()));
        }
        assert_eq!(conns.load(Ordering::SeqCst), 1, "three chunked answers on one pooled connection");
        let with_len = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhelloworld".to_vec();
        let conns = server(27_371, vec![with_len.clone(), with_len.clone()]);
        for _ in 0..2 {
            assert_eq!(get(&t, 27_371), Ok("helloworld".into()));
        }
        assert_eq!(conns.load(Ordering::SeqCst), 1, "two Content-Length answers on one pooled connection");
        // a Content-Length body cut short, then closed
        server(27_372, vec![b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello".to_vec()]);
        assert!(get(&t, 27_372).is_err());
        // a cut chunked answer is an error, and the same agent's next request gets a new connection
        let cut = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n5\r\nwor".to_vec();
        let conns = server(27_373, vec![cut]);
        assert!(get(&t, 27_373).is_err());
        assert!(get(&t, 27_373).is_err());
        assert_eq!(conns.load(Ordering::SeqCst), 2, "the cut connection was not pooled");
        // an empty chunked body is a whole body
        server(27_374, vec![b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec()]);
        assert_eq!(get(&t, 27_374), Ok(String::new()));
    }

    /// T3 one step to the side: an answer with BOTH framings. ureq reads it chunked; the transport
    /// then compares the bytes with the Content-Length header, so a chunked answer that also
    /// carries the wrong length is refused, never returned short.
    #[test]
    fn ok_t3_a_chunked_answer_that_also_carries_a_length_is_not_returned_short() {
        let both = b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec();
        server(27_380, vec![both]);
        let r = get(&UreqTransport::default(), 27_380);
        assert!(r.is_err(), "{r:?}");
    }
}
