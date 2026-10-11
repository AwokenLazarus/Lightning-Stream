//! AGP-102 fourth closure audit, area HUB (the routed client's staged open): tests written by the
//! auditor on the rig of `agp093_client.rs`. Nothing here is a fix.
//!
//! The test named after a rule fails today; `control_*` pass.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use xbt402::client::{split_url, MemoryClientLedger, Transport, Wallet, WalletSend};
use xbt402::funding::{ChainBackend, UtxoInfo};
use xbt402::hub::{HubConfig, RouteHub};
use xbt402::provider::HttpResponse;
use xbt402::route::SpendScan;
use xbt402::route_client::{RoutePayer, RoutePayerConfig};
use xbt402::signer::{LocalSigner, RouteSigner};
use xbt402::wire::OPEN_PATH;
use xbt402::{ChannelError, Result};
use xbt_primitives::address::address_to_spk;
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

const NET: &str = "bip122:11111111111111111111111111111111";
const HUB: &str = "http://hub.test";

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

/// A wallet whose `fund` sends and then errors `fail` times (the node took `sendtoaddress` and the
/// answer timed out). `lists`: it can say what it sent to an address (`listtransactions`, as
/// `Rpc` does); false is the `Wallet` trait's default, "none known" (`client.rs:54-64`), which
/// is also what the wallet wrappers of the shipped `xbt402-route-payer` answer
/// (`xbt402-route-payer.rs:37-61`: they implement `fund` and `fund_channel` only).
struct FlakyWallet {
    chain: Arc<MemChain>,
    sends: Mutex<Vec<(String, String, u64)>>,
    fail: AtomicUsize,
    lists: bool,
}

struct Shared(Arc<FlakyWallet>);

impl Wallet for Shared {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        let txid = {
            let mut sends = self.0.sends.lock().unwrap();
            let txid = hex::encode(sha256(format!("funding {}", sends.len() + 1).as_bytes()));
            let spk = address_to_spk(address, None).map_err(|e| ChannelError::new("bad_address", e.to_string()))?;
            self.0.chain.utxos.lock().unwrap().insert((txid.clone(), 0), UtxoInfo { confirmations: 6, value: sats, script_pubkey: spk, coinbase: false });
            sends.push((txid.clone(), address.to_string(), sats));
            txid
        };
        if self.0.fail.load(Ordering::SeqCst) > 0 {
            self.0.fail.fetch_sub(1, Ordering::SeqCst);
            return Err(ChannelError::new("wallet_error", "timed out after the send"));
        }
        Ok((txid, 0))
    }
    fn wallet_sends_to(&self, address: &str) -> Result<Vec<String>> {
        if !self.0.lists {
            return Ok(vec![]);
        }
        Ok(self.0.sends.lock().unwrap().iter().filter(|s| s.1 == address).map(|s| s.0.clone()).collect())
    }
    fn wallet_send(&self, txid: &str, address: &str) -> Result<Option<WalletSend>> {
        if !self.0.lists {
            return Ok(None);
        }
        Ok(self.0.sends.lock().unwrap().iter().find(|s| s.0 == txid && s.1 == address)
            .map(|s| WalletSend { txid: s.0.clone(), vout: 0, sats: s.2, confirmations: 6, abandoned: false }))
    }
}

struct NoNet;

impl Transport for NoNet {
    fn request(&self, _: &str, url: &str, _: &[u8], _: &[(String, String)]) -> Result<HttpResponse> {
        Err(ChannelError::new("transport_error", format!("refused: {url}")))
    }
}

/// The hub as the routed client reaches it. `opens`: the funded opens it was sent.
struct HubNet {
    hub: Arc<RouteHub>,
    opens: Arc<AtomicUsize>,
    fee_payer: Arc<AtomicBool>,
}

impl Transport for HubNet {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        let (_, path) = split_url(url);
        let req: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        let funded_open = path == OPEN_PATH && req.get("preflight") != Some(&Value::Bool(true));
        let r = self.hub.serve(method, &path, headers, body, url, None);
        if funded_open {
            self.opens.fetch_add(1, Ordering::SeqCst);
            if self.fee_payer.load(Ordering::SeqCst) && r.status == 200 {
                // a hub that opens the channel and says it did so under the other close-fee payer
                let mut doc: Value = serde_json::from_slice(&r.body).unwrap();
                doc["closeFeePayer"] = "payee".into();
                return Ok(HttpResponse::new(200, vec![], doc.to_string().into_bytes()));
            }
        }
        Ok(HttpResponse::new(r.status, r.headers.into_iter().map(|(k, v)| (k.to_ascii_uppercase(), v)).collect(), r.body))
    }
}

struct Routed {
    chain: Arc<MemChain>,
    wallet: Arc<FlakyWallet>,
    hub: Arc<RouteHub>,
    opens: Arc<AtomicUsize>,
    fee_payer: Arc<AtomicBool>,
    _dir: PathBuf,
}

fn routed(name: &str, lists: bool, fail: usize) -> Routed {
    let dir = std::env::temp_dir().join(format!("xbt-rs-agp102-route-client-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let chain = Arc::new(MemChain::default());
    *chain.tip.lock().unwrap() = 1_000;
    let hub_cfg = HubConfig::from_json(&json!({"fee_base_msat": 100, "fee_ppm": 2000, "max_lock_sat": 20000, "max_unguarded_lock_sat": 500,
                                               "delta": 36, "reveal_timeout": 1.0, "ch2_capacity": 100000, "ch2_expiry_blocks": 1000,
                                               "close_margin": 36, "policy": {"min_capacity": 20000, "min_expiry_blocks": 500, "max_expiry_blocks": 8640}})).unwrap();
    let hub_wallet = Arc::new(FlakyWallet { chain: chain.clone(), sends: Mutex::new(vec![]), fail: AtomicUsize::new(0), lists: true });
    let hub = Arc::new(RouteHub::new(chain.clone(), chain.clone(), Box::new(Shared(hub_wallet)), Box::new(NoNet), SecretKey::from_slice(&sha256(b"hub")).unwrap(), NET,
                                     Some(&dir.join("hub")), hub_cfg).unwrap());
    let wallet = Arc::new(FlakyWallet { chain: chain.clone(), sends: Mutex::new(vec![]), fail: AtomicUsize::new(fail), lists });
    Routed { chain, wallet, hub, opens: Arc::new(AtomicUsize::new(0)), fee_payer: Arc::new(AtomicBool::new(false)), _dir: dir }
}

impl Routed {
    fn payer(&self) -> RoutePayer {
        let c = self.chain.clone();
        let signer: Arc<dyn RouteSigner> = Arc::new(LocalSigner::new());
        RoutePayer::new(HUB, RoutePayerConfig::new(NET), signer, Arc::new(Shared(self.wallet.clone())),
                        Box::new(HubNet { hub: self.hub.clone(), opens: self.opens.clone(), fee_payer: self.fee_payer.clone() }), Box::new(move || c.block_count()))
    }

    fn funded(&self) -> (usize, u64) {
        let s = self.wallet.sends.lock().unwrap();
        (s.len(), s.iter().map(|x| x.2).sum())
    }

    fn scripts(&self) -> usize {
        let s = self.wallet.sends.lock().unwrap();
        let mut a: Vec<&String> = s.iter().map(|x| &x.1).collect();
        a.sort();
        a.dedup();
        a.len()
    }
}

/// HOLE (Medium by the audit's scale: coins left in a script until its expiry, with no refund
/// held and no outpoint on the books, by the owner's own wallet failing, not by a counterparty;
/// left from before, the half of list 1 item 5's "from reading" bullet that AGP-094 did not close).
/// A `fund_channel` that errors AFTER it sent. AGP-094 looks for the wallet's own send to ch1's
/// script before it funds again (`route_client.rs:645-648`), which works for a wallet that can
/// list its sends. The `Wallet` trait's default answers "none known" (`client.rs:54-64`), and
/// `fund_ch1` takes that for "nothing was sent": every `open` sends ch1's capacity again, to the
/// same script, with no bound. The shipped `xbt402-route-payer` wraps its wallet in a type that
/// has only `fund` (`xbt402-route-payer.rs:37-61`), so it is such a wallet. With and without a
/// ledger.
///
/// The rule AGP-094 states (`route_client.rs:536-540`): "no second funding sent while the first
/// is unresolved, whatever the hub or the wallet answered".
#[test]
fn a_ch1_funding_that_failed_after_it_was_sent_is_not_sent_again_by_a_wallet_that_cannot_list() {
    let mut seen = vec![];
    for with_ledger in [false, true] {
        let r = routed(if with_ledger { "nolist-l" } else { "nolist" }, false, 3);
        let pay = if with_ledger { r.payer().with_ledger(Box::new(MemoryClientLedger::default())).unwrap() } else { r.payer() };
        let errors: Vec<String> = (0..3).map(|_| pay.open().map(|_| "ok".to_string()).unwrap_or_else(|e| e.code)).collect();
        let (n, sats) = r.funded();
        seen.push(format!("ledger {with_ledger}: three calls to open ({errors:?}) sent ch1's funding {n} times, {sats} sat in all, to {} script(s); the books \
                           hold no outpoint ({:?}) and no refund was signed for any of them", r.scripts(), pay.chan()));
        seen.push(n.to_string());
    }
    assert!(seen[1] == "1" && seen[3] == "1", "{}\n{}", seen[0], seen[2]);
}

/// Control: the same wallet when it can list its sends (`Rpc` can): the first send is adopted.
#[test]
fn control_a_wallet_that_lists_its_sends_is_asked_once() {
    let r = routed("lists", true, 3);
    let pay = r.payer();
    assert_eq!(pay.open().unwrap_err().code, "wallet_error");
    pay.open().unwrap();
    pay.open().unwrap();
    assert_eq!((r.funded().0, r.opens.load(Ordering::SeqCst)), (1, 1), "one funding, one funded open");
}

/// Control (from reading, now run): `duplicate_channel` is taken as the yes that was lost, and it
/// is also taken after an answer the client itself refused. A hub that opened ch1 and said so under
/// the other close-fee payer is refused `bad_fee_payer` by the first `open`; the second `open` is
/// answered `duplicate_channel` and the client then counts ch1 as open (`route_client.rs:763-765`
/// returns before the check at `:767`). Nothing is lost by it (every state the client signs is then
/// refused by that hub), so it is a limit, not a hole: the first refusal is not final.
#[test]
fn control_duplicate_channel_is_the_yes_even_after_an_answer_the_client_refused() {
    let r = routed("dup", true, 0);
    let pay = r.payer();
    r.fee_payer.store(true, Ordering::SeqCst);
    assert_eq!(pay.open().unwrap_err().code, "bad_fee_payer");
    r.fee_payer.store(false, Ordering::SeqCst);
    let again = pay.open();
    assert!(again.is_ok(), "{again:?}");
    assert_eq!((r.funded().0, r.opens.load(Ordering::SeqCst)), (1, 2), "funded once; the second open was the hub's duplicate_channel");
}
