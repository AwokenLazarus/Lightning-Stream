//! AGP-090 (fix wave 4, channel client and transport): the neighbours of the paths the second
//! closure audit named. `agp087_hub_b_client.rs` and `agp087_transport*.rs` hold the audit's own
//! tests; each test here is another way to the same state, and failed before the fix it names.
//!
//! The rules:
//! - open: a channel's key is in the ledger before its funding leaves, its refund before the
//!   provider is asked to open it, and an origin with a channel on the books is not funded again;
//! - rollover: every attempt to roll one channel over pays the same next key;
//! - receipts: a receipt is for the seq just sent, and the provider's spent total grows by at most
//!   one quote for each paid request it has not answered (a 402 is an answer: not charged), plus
//!   one call of slack over the channel's life.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use xbt402::client::{split_url, Client, ClientConfig, FileClientLedger, Stage, Transport, Wallet, WalletSend, MAX_KEPT};
use xbt402::funding::{ChainBackend, UtxoInfo};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::signer::LocalSigner;
use xbt402::wire::{b64json, unb64json, OPEN_PATH, ROLLOVER_PATH};
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

/// A wallet whose `fund` can fail before or after it sent, and that lists its sends or does not.
#[derive(Default)]
struct TestWallet {
    chain: Arc<MemChain>,
    /// (txid, address, sats) of every send.
    sends: Mutex<Vec<(String, String, u64)>>,
    /// `fund` errors without sending.
    refuses: AtomicBool,
    /// `fund` sends and then errors (a timeout after the broadcast).
    errors_after_send: AtomicBool,
    lists_sends: bool,
}

/// The wallet as the client holds it.
struct Shared(Arc<TestWallet>);

impl std::ops::Deref for Shared {
    type Target = TestWallet;
    fn deref(&self) -> &TestWallet {
        &self.0
    }
}

impl Wallet for Shared {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        if self.refuses.load(Ordering::SeqCst) {
            return Err(ChannelError::new("wallet_error", "insufficient funds"));
        }
        let mut sends = self.sends.lock().unwrap();
        let txid = hex::encode(sha256(format!("funding {}", sends.len() + 1).as_bytes()));
        let spk = address_to_spk(address, None).map_err(|e| ChannelError::new("bad_address", e.to_string()))?;
        self.chain.utxos.lock().unwrap().insert((txid.clone(), 0), UtxoInfo { confirmations: 1, value: sats, script_pubkey: spk, coinbase: false });
        sends.push((txid.clone(), address.to_string(), sats));
        if self.errors_after_send.load(Ordering::SeqCst) {
            return Err(ChannelError::new("wallet_error", "timed out"));
        }
        Ok((txid, 0))
    }
    fn wallet_sends_to(&self, address: &str) -> Result<Vec<String>> {
        Ok(if self.lists_sends { self.sends.lock().unwrap().iter().filter(|s| s.1 == address).map(|s| s.0.clone()).collect() } else { vec![] })
    }
    fn wallet_send(&self, txid: &str, address: &str) -> Result<Option<WalletSend>> {
        Ok(self.sends.lock().unwrap().iter().find(|s| self.lists_sends && s.0 == txid && s.1 == address)
            .map(|s| WalletSend { txid: s.0.clone(), vout: 0, sats: s.2, confirmations: 1, abandoned: false }))
    }
}

type Rewrite = Box<dyn Fn(&str, &Value, &[(String, String)], HttpResponse) -> Result<HttpResponse> + Send + Sync>;

/// The provider, with `f` free to change (or lose) each answer on the way back.
struct Edit(Arc<Provider>, Rewrite);

impl Transport for Edit {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        let (_, path) = split_url(url);
        let req: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        (self.1)(&path, &req, headers, self.0.serve(method, &path, headers, body, url, None))
    }
}

fn honest() -> Rewrite {
    Box::new(|_, _, _, r| Ok(r))
}

fn funded_open(path: &str, req: &Value) -> bool {
    path == OPEN_PATH && req.get("preflight") != Some(&Value::Bool(true))
}

/// The answers to funded opens are lost while `on` is set.
fn loses_funded_opens(on: Arc<AtomicBool>) -> Rewrite {
    Box::new(move |path, req, _, r| {
        if funded_open(path, req) && on.load(Ordering::SeqCst) {
            return Err(ChannelError::new("transport_error", "timed out"));
        }
        Ok(r)
    })
}

fn refuses_funded_opens() -> Rewrite {
    Box::new(|path, req, _, r| {
        if funded_open(path, req) {
            return Ok(HttpResponse::new(400, vec![], json!({"error": "bad_funding", "detail": "no"}).to_string().into_bytes()));
        }
        Ok(r)
    })
}

struct World {
    chain: Arc<MemChain>,
    wallet: Arc<TestWallet>,
    prov: Arc<Provider>,
    dir: PathBuf,
}

fn world(name: &str, lists_sends: bool) -> World {
    let dir = std::env::temp_dir().join(format!("xbt-rs-agp090-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let chain = Arc::new(MemChain::default());
    *chain.tip.lock().unwrap() = 1_000;
    let k = Mutex::new(0u64);
    let handler = move |m: &str, p: &str, _: &[u8]| {
        let mut k = k.lock().unwrap();
        *k += 1;
        HttpResponse::new(if p.starts_with("/v1/empty") { 204 } else { 200 }, vec![], json!({"m": m, "answer": p, "n": *k}).to_string().into_bytes())
    };
    let prov = Arc::new(Provider::new(chain.clone(), SecretKey::from_slice(&sha256(b"provider payTo")).unwrap(), ProviderConfig::new(NET), Ledger::in_memory(),
                                      Box::new(|_, _| PRICE), Box::new(handler)).unwrap());
    World { wallet: Arc::new(TestWallet { chain: chain.clone(), lists_sends, ..TestWallet::default() }), prov, chain, dir }
}

impl World {
    fn bare_client(&self, f: Rewrite) -> Client {
        let c = self.chain.clone();
        Client::new(ClientConfig::new(NET), Box::new(Edit(self.prov.clone(), f)), Box::new(Shared(self.wallet.clone())), Box::new(move || c.block_count()))
    }

    /// A client on the ledger file (one at a time: the file is locked).
    fn client(&self, f: Rewrite) -> Client {
        self.bare_client(f).with_ledger(Box::new(FileClientLedger::open(&self.dir.join("client.jsonl")).unwrap())).unwrap()
    }

    fn funded(&self) -> usize {
        self.wallet.sends.lock().unwrap().len()
    }

    fn on_disk(&self) -> String {
        std::fs::read_to_string(self.dir.join("client.jsonl")).unwrap_or_default()
    }
}

fn get(c: &mut Client) -> std::result::Result<u16, String> {
    c.request("GET", &format!("{O}/v1/q"), b"").map(|r| r.status).map_err(|e| e.code)
}

// --- open: the key before the funding, the refund before the open, one funding per origin -----------

/// The key is in the ledger before the wallet is asked to fund: a `fund` that sends and then errors
/// (a timeout after the broadcast) used to leave coins in a script whose key was never stored.
#[test]
fn a_fund_call_that_errors_after_it_sent_leaves_the_key_in_the_ledger() {
    let w = world("fund-errors", false);
    w.wallet.errors_after_send.store(true, Ordering::SeqCst);
    let mut c = w.client(honest());
    assert_eq!(get(&mut c), Err("wallet_error".into()));
    let ch = &c.channels[O];
    assert_eq!((ch.stage, ch.payer.params.funding.is_none()), (Stage::Keyed, true));
    let key = hex::encode(ch.payer.secret().unwrap().secret_bytes());
    assert!(w.on_disk().contains(&key), "the payer key of the script that was funded is in the ledger");
    // the script the coins went to is the one this key refunds
    let spk = address_to_spk(&w.wallet.sends.lock().unwrap()[0].1, None).unwrap();
    assert_eq!(spk, ch.payer.params.spk());
}

/// The retry asks the wallet for its own send to the channel's script before it sends again.
#[test]
fn a_funding_the_wallet_already_sent_is_adopted_not_sent_again() {
    let w = world("adopt", true);
    w.wallet.errors_after_send.store(true, Ordering::SeqCst);
    let mut c = w.client(honest());
    assert_eq!(get(&mut c), Err("wallet_error".into()));
    w.wallet.errors_after_send.store(false, Ordering::SeqCst);
    assert_eq!(get(&mut c), Ok(200));
    assert_eq!(w.funded(), 1, "the first send funds the channel");
    assert_eq!(c.channels[O].payer.params.funding_txid(), w.wallet.sends.lock().unwrap()[0].0);
    assert_eq!((c.channels[O].stage, c.opened_sats), (Stage::Open, 200_000));
}

/// A wallet that cannot list its sends: the retry funds the same script under the same key, so
/// whatever the first call did is refundable with the key on the books. Nothing is funded to a
/// key that was dropped.
#[test]
fn a_retry_after_a_failed_fund_call_pays_the_same_key() {
    let w = world("same-key", false);
    w.wallet.errors_after_send.store(true, Ordering::SeqCst);
    let mut c = w.client(honest());
    assert_eq!(get(&mut c), Err("wallet_error".into()));
    let key = c.channels[O].payer.params.payer_pub;
    w.wallet.errors_after_send.store(false, Ordering::SeqCst);
    assert_eq!(get(&mut c), Ok(200));
    let sends = w.wallet.sends.lock().unwrap().clone();
    assert_eq!((sends.len(), sends[0].1 == sends[1].1), (2, true), "both sends went to one script");
    assert_eq!(c.channels[O].payer.params.payer_pub, key);
}

/// A restart between the funding and the provider's answer reads the channel back with its refund,
/// asks the provider again and funds nothing.
#[test]
fn a_restart_after_the_funding_finishes_the_open_and_funds_nothing() {
    let w = world("restart", false);
    let lost = Arc::new(AtomicBool::new(true));
    let txid = {
        let mut c = w.client(loses_funded_opens(lost.clone()));
        assert_eq!(get(&mut c), Err("transport_error".into()));
        assert_eq!(c.channels[O].stage, Stage::Funded);
        c.channels[O].payer.params.funding_txid()
    };
    lost.store(false, Ordering::SeqCst);
    let mut c = w.client(honest());
    let ch = &c.channels[O];
    assert_eq!((ch.stage, ch.payer.params.funding_txid()), (Stage::Funded, txid.clone()));
    let refund = Tx::parse_hex(&ch.refund_hex).unwrap();
    assert_eq!(refund.inputs[0].prevout.txid_hex(), txid);
    // the provider opened it the first time: its duplicate_channel is the yes that was lost
    assert_eq!(get(&mut c), Ok(200));
    assert_eq!((w.funded(), w.prov.channel_ids().len(), c.channels[O].stage), (1, 1, Stage::Open));
}

/// The conditional call opens through the same function: refused after funding, the channel stays
/// on the books and the next conditional call funds nothing.
#[test]
fn a_conditional_call_whose_funded_open_is_refused_is_funded_once() {
    let w = world("conditional", false);
    w.prov.offer_conditional("/v1/secret", 600, b"the deliverable", None);
    let mut c = w.client(refuses_funded_opens());
    for _ in 0..4 {
        assert_eq!(c.request_conditional("GET", &format!("{O}/v1/secret"), b"").unwrap_err().code, "bad_funding");
    }
    assert_eq!((w.funded(), c.channels[O].stage), (1, Stage::Funded));
    assert!(w.on_disk().contains(&c.channels[O].payer.params.funding_txid()));
}

/// No state, close or rollover is signed for a channel the provider has not opened.
#[test]
fn nothing_is_signed_for_a_channel_that_is_not_open() {
    let w = world("not-open", false);
    let mut c = w.client(refuses_funded_opens());
    assert_eq!(get(&mut c), Err("bad_funding".into()));
    assert_eq!(c.close(O).unwrap_err().code, "no_channel");
    assert_eq!(c.rollover(O).unwrap_err().code, "no_channel");
    let ch = &c.channels[O];
    assert_eq!((ch.payer.signed, ch.seq, ch.last_sig.as_str()), (0, 0, ""));
}

/// A keyed channel whose funding call failed and that is now too near its expiry: its terms are
/// kept (the call may have sent), and the same call derives it again and funds that.
///
/// AGP-096 rewrote this test and the next (the third audit's item 6). AGP-090 failed this call
/// `open_unresolved`, opened the next with a new key, and refused the origin for good at sixteen
/// kept keys; with a signer it refused every call until the embedder called `forget_unfunded`.
#[test]
fn a_stale_unfunded_channel_keeps_its_terms_and_the_call_opens_anew() {
    let w = world("stale", false);
    w.wallet.refuses.store(true, Ordering::SeqCst);
    let mut c = w.client(honest());
    assert_eq!(get(&mut c), Err("wallet_error".into()));
    let old = c.channels[O].payer.params.clone();
    w.wallet.refuses.store(false, Ordering::SeqCst);
    *w.chain.tip.lock().unwrap() += 900; // 1,008 blocks asked; the offer's floor is 144 + 1 + 36
    assert_eq!(get(&mut c), Ok(200));
    assert_eq!((w.funded(), c.unfunded[O].len(), &c.unfunded[O][0].payer.params), (1, 1, &old));
    let now = &c.channels[O].payer.params;
    assert_eq!((now.payer_pub, now.expiry), (old.payer_pub, old.expiry + 900), "one key for the origin, a new expiry");
    assert!(w.on_disk().contains(&old.expiry.to_string()), "the old terms are still in the ledger");
    // the embedder drops the kept record once its wallet shows no send to it
    assert_eq!(c.forget_unfunded(O).unwrap(), 1);
    assert!(c.unfunded.is_empty() && c.channels[O].stage == Stage::Open);
}

/// The same with a signer, which answers the key it issued for the origin again: nothing waits
/// for the embedder, and the signer can still bind the script that was set aside.
#[test]
fn a_stale_unfunded_channel_with_a_signer_is_opened_anew_for_the_issued_key() {
    let w = world("stale-signer", false);
    w.wallet.refuses.store(true, Ordering::SeqCst);
    let signer = Arc::new(LocalSigner::new());
    let mut c = w.bare_client(honest()).with_signer(signer.clone());
    assert_eq!(get(&mut c), Err("wallet_error".into()));
    let old = c.channels[O].payer.params.clone();
    w.wallet.refuses.store(false, Ordering::SeqCst);
    *w.chain.tip.lock().unwrap() += 900;
    assert_eq!(get(&mut c), Ok(200));
    assert_eq!((w.funded(), c.channels[O].payer.params.payer_pub), (1, old.payer_pub), "the signer's issued key was not replaced");
    // had the failed call sent after all, the signer still signs that script's refund
    use xbt402::signer::StateSigner;
    let sent = old.clone().with_funding(&"ab".repeat(32), 0, 200_000).unwrap();
    let chan = signer.attach(O, &sent).unwrap();
    assert_eq!(Tx::parse_hex(&signer.sign_refund(&chan).unwrap()).unwrap().locktime, old.expiry);
}

/// A seller's `minCapacity` is its own number: the budget check does not wrap.
#[test]
fn a_min_capacity_that_overflows_the_budget_sum_is_refused_before_funding() {
    let w = world("mincap", false);
    let mut c = w.bare_client(Box::new(|_, _, _, mut r| {
        if r.status == 402 {
            let mut pr = unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap();
            pr["accepts"][0]["extra"]["minCapacity"] = json!(u64::MAX - 100_000);
            pr["accepts"][0]["extra"]["maxCapacity"] = json!(u64::MAX);
            r.headers.retain(|(k, _)| k != "PAYMENT-REQUIRED");
            r.headers.push(("PAYMENT-REQUIRED".into(), b64json(&pr)));
        }
        Ok(r)
    }));
    c.opened_sats = 200_000;
    assert_eq!(get(&mut c), Err("budget".into()));
    assert_eq!(w.funded(), 0);
}

// --- rollover: one next key per channel -----------------------------------------------------------

fn paid_calls(c: &mut Client, n: usize) {
    for _ in 0..n {
        assert_eq!(get(c), Ok(200));
    }
}

/// The provider broadcasts the first rollover and answers it with an error, as in the audit's test,
/// but the retry comes a block later, so it is another transaction: with a signer and with a local
/// key, every attempt pays the first attempt's key and whichever lands can be adopted.
#[test]
fn every_attempt_to_roll_a_channel_over_pays_the_first_attempts_key() {
    for with_signer in [false, true] {
        let w = world(&format!("roll-{with_signer}"), false);
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = n.clone();
        let f: Rewrite = Box::new(move |path, _, _, r| {
            if path == ROLLOVER_PATH && r.status == 200 && n2.fetch_add(1, Ordering::SeqCst) == 0 {
                return Ok(HttpResponse::new(400, vec![], br#"{"error":"bad_request","detail":"no"}"#.to_vec()));
            }
            Ok(r)
        });
        let mut c = w.bare_client(f);
        if with_signer {
            c = c.with_signer(Arc::new(LocalSigner::new()));
        }
        paid_calls(&mut c, 8);
        let parent = c.channels[O].payer.params.channel_id();
        assert_eq!(c.rollover(O).unwrap_err().code, "bad_request");
        let roll = w.chain.sent.lock().unwrap().last().unwrap().clone();
        for _ in 0..3 {
            *w.chain.tip.lock().unwrap() += 1;
            assert!(c.rollover(O).is_err(), "the channel is spent");
        }
        let next = &c.next_rolled[O];
        assert_eq!(next.len(), 4, "signer {with_signer}: four attempts, four transactions");
        assert!(next.iter().all(|x| x.payer.params.payer_pub == next[0].payer.params.payer_pub && x.rolled_from.as_deref() == Some(parent.as_str())),
                "signer {with_signer}: one key");
        c.adopt_rolled(O, &roll.txid()).unwrap();
        let refund = Tx::parse_hex(&c.channels[O].refund_hex).unwrap();
        assert_eq!((refund.inputs[0].prevout.txid_hex(), refund.inputs[0].prevout.vout), (roll.txid(), 1), "signer {with_signer}");
    }
}

/// A provider that answers every rollover with an error cannot make the client's book grow
/// without bound: past `MAX_KEPT` signed and unresolved rollovers the client signs no more.
#[test]
fn unresolved_rollovers_of_one_channel_are_bounded() {
    let w = world("roll-bound", false);
    let mut c = w.bare_client(Box::new(|path, _, _, r| {
        if path == ROLLOVER_PATH {
            return Err(ChannelError::new("transport_error", "timed out"));
        }
        Ok(r)
    }));
    paid_calls(&mut c, 8);
    let mut codes = vec![];
    for _ in 0..MAX_KEPT + 3 {
        *w.chain.tip.lock().unwrap() += 1;
        codes.push(c.rollover(O).unwrap_err().code);
    }
    assert_eq!(c.next_rolled[O].len(), MAX_KEPT, "{codes:?}");
    assert_eq!(codes.last().unwrap(), "rollover_unresolved", "{codes:?}");
}

// --- receipts: the seq just sent, and one quote per request sent ----------------------------------

/// Answers are lost on the way back (paid requests 3, 4 and 9). The payer goes on, and at the end
/// it has paid for exactly what the provider served: each call once.
#[test]
fn lost_answers_are_paid_for_once_and_the_channel_goes_on() {
    for billing in ["postpay", "prepay"] {
        let w = world(&format!("lost-{billing}"), false);
        let mut cfg = ProviderConfig::new(NET);
        cfg.billing = billing.into();
        let prov = Arc::new(Provider::new(w.chain.clone(), SecretKey::from_slice(&sha256(b"provider payTo")).unwrap(), cfg, Ledger::in_memory(),
                                          Box::new(|_, _| PRICE), Box::new(|_, _, _| HttpResponse::new(200, vec![], b"{}".to_vec()))).unwrap());
        let n = AtomicUsize::new(0);
        let f: Rewrite = Box::new(move |path, _, h, r| {
            let paid = path.starts_with("/v1/") && h.iter().any(|(k, _)| k == "PAYMENT-SIGNATURE") && r.status == 200;
            if paid && [3, 4, 9].contains(&(n.fetch_add(1, Ordering::SeqCst) + 1)) {
                return Err(ChannelError::new("transport_error", "timed out reading the answer"));
            }
            Ok(r)
        });
        let ch0 = w.chain.clone();
        let mut c = Client::new(ClientConfig::new(NET), Box::new(Edit(prov.clone(), f)), Box::new(Shared(w.wallet.clone())), Box::new(move || ch0.block_count()));
        let out: Vec<_> = (0..14).map(|_| get(&mut c)).collect();
        assert_eq!(out.iter().filter(|o| o.is_err()).count(), 3, "{billing}: only the lost answers fail: {out:?}");
        assert!(out[9..].iter().all(|o| *o == Ok(200)), "{billing}: {out:?}");
        let st = prov.channel_state(&c.channels[O].payer.params.channel_id()).unwrap();
        assert_eq!(st.spent_msat, 14 * PRICE * 1000, "{billing}: the provider served and charged 14 calls");
        assert_eq!((c.channels[O].spent_msat, c.channels[O].unanswered_msat), (st.spent_msat, 0), "{billing}: the payer's receipts say the same");
        c.close(O).unwrap();
        let st = prov.channel_state(&c.channels[O].payer.params.channel_id()).unwrap();
        assert_eq!(st.best_cum, 14 * PRICE, "{billing}: the close pays each served call once");
    }
}

/// The bound that replaced "one call": a receipt whose total grew by more than the requests the
/// payer sent is still refused, and so is a 402 that claims as much.
#[test]
fn a_provider_cannot_claim_more_calls_than_the_payer_sent() {
    let w = world("claim", false);
    let lose = Arc::new(AtomicBool::new(false));
    let l2 = lose.clone();
    let forge = Arc::new(AtomicBool::new(false));
    let f2 = forge.clone();
    let last_402: Mutex<Option<Value>> = Mutex::new(None);
    let mut c = w.bare_client(Box::new(move |path, _, h, r| {
        if r.status == 402 {
            *last_402.lock().unwrap() = Some(unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap());
        }
        let paid = path.starts_with("/v1/") && h.iter().any(|(k, _)| k == "PAYMENT-SIGNATURE");
        if paid && l2.load(Ordering::SeqCst) {
            return Err(ChannelError::new("transport_error", "timed out"));
        }
        if paid && f2.load(Ordering::SeqCst) {
            // an unsigned 402 that says ten calls were charged
            let mut pr = last_402.lock().unwrap().clone().unwrap();
            pr["channel"] = json!({"spentMsat": (20 * PRICE * 1000).to_string()});
            return Ok(HttpResponse::new(402, vec![("PAYMENT-REQUIRED".into(), b64json(&pr))], vec![]));
        }
        Ok(r)
    }));
    paid_calls(&mut c, 1);
    // two answers are lost (the first state, 546 sat, still covers them: no 402 comes); the payer then loses its count of them (a restart from an older book).
    // One uncounted call is the channel's slack; two are not
    lose.store(true, Ordering::SeqCst);
    assert!(get(&mut c).is_err() && get(&mut c).is_err());
    lose.store(false, Ordering::SeqCst);
    c.channels.get_mut(O).unwrap().unanswered_msat = 0;
    let signed = c.channels[O].payer.signed;
    assert_eq!(get(&mut c), Err("bad_receipt".into()), "three calls' growth for one request sent");
    // and a 402 naming charges for calls never sent
    forge.store(true, Ordering::SeqCst);
    assert_eq!(get(&mut c), Err("bad_offer".into()));
    assert_eq!(c.channels[O].payer.signed, signed, "nothing more was signed on either claim");
}

/// review M3 still holds under the new bound: a provider that serves nothing and answers every
/// paid request with a 402 naming one more charge gets the channel's one call of slack and no more.
/// A request it refused is not one it may have served.
#[test]
fn a_provider_that_refuses_every_call_cannot_claim_them() {
    let w = world("greedy", false);
    let on = Arc::new(AtomicBool::new(false));
    let on2 = on.clone();
    let last_402: Mutex<Option<Value>> = Mutex::new(None);
    let claimed = AtomicUsize::new(0);
    let mut c = w.bare_client(Box::new(move |path, _, h, r| {
        if r.status == 402 {
            *last_402.lock().unwrap() = Some(unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap());
        }
        if on2.load(Ordering::SeqCst) && path.starts_with("/v1/") && h.iter().any(|(k, _)| k == "PAYMENT-SIGNATURE") {
            let n = claimed.fetch_add(1, Ordering::SeqCst) as u64 + 1;
            let mut pr = last_402.lock().unwrap().clone().unwrap();
            pr["channel"] = json!({"spentMsat": ((1 + n) * PRICE * 1000).to_string()});
            return Ok(HttpResponse::new(402, vec![("PAYMENT-REQUIRED".into(), b64json(&pr))], vec![]));
        }
        Ok(r)
    }));
    paid_calls(&mut c, 1);
    on.store(true, Ordering::SeqCst);
    let out: Vec<_> = (0..10).map(|_| get(&mut c)).collect();
    assert_eq!(out.iter().filter(|o| **o == Err("bad_offer".into())).count(), 9, "{out:?}");
    let ch = &c.channels[O];
    assert!(ch.spent_msat <= 2 * PRICE * 1000 && ch.payer.signed <= 546 + 2 * PRICE, "one honest call and one call of slack: {} msat, {} sat signed",
            ch.spent_msat, ch.payer.signed);
}

/// The provider as its HTTP server frames it: no body goes out for a HEAD or a 204, whatever the
/// handler returned (and the receipt signed). Two paths model damage on the way.
struct Framed(Arc<Provider>);

impl Transport for Framed {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        let (_, path) = split_url(url);
        let mut r = self.0.serve(method, &path, headers, body, url, None);
        let paid = headers.iter().any(|(k, _)| k == "PAYMENT-SIGNATURE");
        if method == "HEAD" || r.status == 204 || (paid && path == "/v1/cut") {
            r.body.clear();
        }
        if paid && path == "/v1/head-with-body" {
            r.body = b"not what was signed".to_vec();
        }
        Ok(r)
    }
}

/// The receipt of a HEAD, and of a 204, is checked on what such an answer has: its status. A body
/// that does arrive is still checked, and a GET cut to nothing is not taken for a HEAD.
#[test]
fn a_paid_answer_without_a_body_is_checked_on_its_status() {
    let w = world("head", false);
    let ch0 = w.chain.clone();
    let mut c = Client::new(ClientConfig::new(NET), Box::new(Framed(w.prov.clone())), Box::new(Shared(w.wallet.clone())), Box::new(move || ch0.block_count()));
    paid_calls(&mut c, 1);
    assert_eq!(c.request("HEAD", &format!("{O}/v1/q"), b"").unwrap().status, 200);
    assert_eq!(c.request("GET", &format!("{O}/v1/empty"), b"").unwrap().status, 204);
    assert_eq!(c.request("GET", &format!("{O}/v1/cut"), b"").unwrap_err().code, "bad_receipt", "a GET cut to nothing is not a HEAD");
    assert_eq!(c.request("HEAD", &format!("{O}/v1/head-with-body"), b"").unwrap_err().code, "bad_receipt");
}
