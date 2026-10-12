//! AGP-035: the surface xbt-compute (cmp) links, with default features off and only cmp-style
//! stand-ins for [`Transport`], [`Wallet`], [`ChainBackend`] and the
//! signer. Run it exactly as cmp builds the crate:
//!
//!     cargo test -p xbt402 --no-default-features --test cmp_surface
//!
//! * One process sells and buys (cmp's MoE dispatcher): a [`Provider`] on its own [`Ledger`] and a
//!   [`Client`] (keys in a [`StateSigner`], `with_signer`) on its own [`FileClientLedger`], side by
//!   side; the client restarts from its ledger and keeps paying on the same channel.
//! * A local-key client restarts from its ledger too; a signer-held record refuses to load without
//!   the signer.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde_json::json;
use xbt402::client::{split_url, Client, ClientConfig, ClientLedger, FileClientLedger, MemoryClientLedger, Transport, Wallet};
use xbt402::funding::{ChainBackend, UtxoInfo};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::signer::{LocalSigner, StateSigner};
use xbt402::{ChannelError, Result};
use xbt_primitives::address::address_to_spk;
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

const NET: &str = "bip122:11111111111111111111111111111111";

// --- cmp-style stand-ins ------------------------------------------------------------------------

/// cmp's chain backend (a node or an Electrum light client in cmp): a fake that confirms fundings
/// at once and tracks spends.
#[derive(Default)]
struct Chain {
    height: Mutex<u32>,
    utxos: Mutex<HashMap<(String, u32), UtxoInfo>>,
    spent: Mutex<HashMap<(String, u32), String>>,
    raw: Mutex<HashMap<String, String>>,
    n: Mutex<u64>,
}

impl Chain {
    fn new() -> Arc<Self> {
        let c = Self::default();
        *c.height.lock().unwrap() = 1_000;
        Arc::new(c)
    }
}

impl ChainBackend for Chain {
    fn block_count(&self) -> Result<u32> {
        Ok(*self.height.lock().unwrap())
    }
    fn get_tx_out(&self, txid: &str, vout: u32, _mempool: bool) -> Result<Option<UtxoInfo>> {
        let k = (txid.to_string(), vout);
        if self.spent.lock().unwrap().contains_key(&k) {
            return Ok(None);
        }
        Ok(self.utxos.lock().unwrap().get(&k).cloned())
    }
    fn send_raw_transaction(&self, hex: &str) -> Result<String> {
        let tx = Tx::parse_hex(hex)?;
        let txid = tx.txid();
        if self.raw.lock().unwrap().contains_key(&txid) {
            return Ok(txid);
        }
        let mut spent = self.spent.lock().unwrap();
        for i in &tx.inputs {
            if spent.get(&(i.prevout.txid_hex(), i.prevout.vout)).is_some_and(|s| *s != txid) {
                return Err(ChannelError::new("rpc_error", "txn-mempool-conflict"));
            }
        }
        for i in &tx.inputs {
            spent.insert((i.prevout.txid_hex(), i.prevout.vout), txid.clone());
        }
        for (n, o) in tx.outputs.iter().enumerate() {
            self.utxos.lock().unwrap().insert((txid.clone(), n as u32),
                                              UtxoInfo { confirmations: 0, value: o.value as u64, script_pubkey: o.script_pubkey.clone(), coinbase: false });
        }
        self.raw.lock().unwrap().insert(txid.clone(), hex.to_string());
        Ok(txid)
    }
    fn has_transaction(&self, txid: &str) -> Result<bool> {
        Ok(self.raw.lock().unwrap().contains_key(txid))
    }
}

/// cmp's wallet: funds a channel address, returns the outpoint.
struct CmpWallet(Arc<Chain>);

impl Wallet for CmpWallet {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        let mut n = self.0.n.lock().unwrap();
        *n += 1;
        let txid = hex::encode(sha256(format!("cmp funding {n}").as_bytes()));
        let spk = address_to_spk(address, None).map_err(|e| ChannelError::new("bad_address", e.to_string()))?;
        self.0.utxos.lock().unwrap().insert((txid.clone(), 0), UtxoInfo { confirmations: 6, value: sats, script_pubkey: spk, coinbase: false });
        Ok((txid, 0))
    }
}

type Service = Arc<dyn Fn(&str, &str, &[(String, String)], &[u8], &str) -> HttpResponse + Send + Sync>;

/// cmp's transport: origin -> an in-process service (cmp has its own HTTP stack).
#[derive(Default, Clone)]
struct Net(Arc<Mutex<HashMap<String, Service>>>);

impl Net {
    fn provider(&self, origin: &str, p: &Arc<Provider>) {
        let p = p.clone();
        self.0.lock().unwrap().insert(origin.into(), Arc::new(move |m, path, h, b, url| p.serve(m, path, h, b, url, None)));
    }
}

impl Transport for Net {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        let (origin, path) = split_url(url);
        let svc = self.0.lock().unwrap().get(&origin).cloned().ok_or_else(|| ChannelError::new("transport_error", format!("refused: {origin}")))?;
        let r = svc(method, &path, headers, body, url);
        Ok(HttpResponse::new(r.status, r.headers.into_iter().map(|(k, v)| (k.to_ascii_uppercase(), v)).collect(), r.body))
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("xbt-rs-cmp-{tag}-{}", hex::encode(&sha256(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes())[..6])));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn secret(label: &str) -> SecretKey {
    SecretKey::from_slice(&sha256(label.as_bytes())).unwrap()
}

fn provider(chain: &Arc<Chain>, label: &str, ledger: Ledger, price: u64) -> Arc<Provider> {
    Arc::new(Provider::new(chain.clone(), secret(label), ProviderConfig::new(NET), ledger, Box::new(move |_, _| price),
                           Box::new(|_, p, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())],
                                                                  json!({"path": p}).to_string().into_bytes()))).unwrap())
}

fn client(chain: &Arc<Chain>, net: &Net) -> Client {
    let c = chain.clone();
    Client::new(ClientConfig::new(NET), Box::new(net.clone()), Box::new(CmpWallet(chain.clone())), Box::new(move || c.block_count()))
}

// --- the tests ----------------------------------------------------------------------------------

#[test]
fn one_process_sells_and_buys_with_injected_ledgers_and_restarts() {
    let dir = TempDir::new("dispatcher");
    let (chain, net) = (Chain::new(), Net::default());
    // the dispatcher sells on its own Provider ledger ...
    let own = provider(&chain, "dispatcher payTo", Ledger::open(&dir.0.join("provider.jsonl")).unwrap(), 200);
    net.provider("http://dispatcher.test", &own);
    // ... and buys from two vendors, keys in its signer, channels in its own client ledger
    for (o, label) in [("http://vendor-a.test", "vendor a"), ("http://vendor-b.test", "vendor b")] {
        net.provider(o, &provider(&chain, label, Ledger::in_memory(), 150));
    }
    let signer: Arc<dyn StateSigner> = Arc::new(LocalSigner::new());
    let cl_path = dir.0.join("client.jsonl");
    let mut buyer = client(&chain, &net).with_signer(signer.clone()).with_ledger(Box::new(FileClientLedger::open(&cl_path).unwrap())).unwrap();
    // an outside customer pays the dispatcher
    let mut customer = client(&chain, &net);
    for i in 0..4 {
        assert_eq!(customer.request("POST", &format!("http://dispatcher.test/v1/moe?i={i}"), b"{}").unwrap().status, 200);
        for v in ["http://vendor-a.test", "http://vendor-b.test"] {
            let r = buyer.request("POST", &format!("{v}/v1/expert?i={i}"), b"{}").unwrap();
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        }
    }
    // the two books are separate: the provider ledger holds the customer's channel, the client
    // ledger the dispatcher's two vendor channels
    assert_eq!(own.channel_ids().len(), 1);
    assert_eq!(buyer.channels.len(), 2);
    let before: HashMap<String, (u64, u64, u64)> =
        buyer.channels.iter().map(|(o, c)| (o.clone(), (c.payer.signed, c.seq, c.spent_msat))).collect();
    let opened = buyer.opened_sats;
    drop(buyer);

    // restart: same signer, same ledger file; the channels come back and keep paying
    let mut buyer = client(&chain, &net).with_signer(signer.clone()).with_ledger(Box::new(FileClientLedger::open(&cl_path).unwrap())).unwrap();
    let after: HashMap<String, (u64, u64, u64)> =
        buyer.channels.iter().map(|(o, c)| (o.clone(), (c.payer.signed, c.seq, c.spent_msat))).collect();
    assert_eq!(after, before);
    assert_eq!(buyer.opened_sats, opened);
    assert!(buyer.channels.values().all(|c| c.payer.secret().is_none()), "keys stay in the signer");
    let chan_a = buyer.channels["http://vendor-a.test"].payer.params.channel_id();
    for i in 4..8 {
        assert_eq!(buyer.request("POST", &format!("http://vendor-a.test/v1/expert?i={i}"), b"{}").unwrap().status, 200);
    }
    let a = &buyer.channels["http://vendor-a.test"];
    assert_eq!(a.payer.params.channel_id(), chan_a, "no new channel after the restart");
    assert_eq!(a.spent_msat, 8 * 150_000);
    // the ledger file holds no payer secret
    let text = std::fs::read_to_string(&cl_path).unwrap();
    assert!(text.contains("\"key\":\"signer\""));
    #[cfg(unix)]
    assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&cl_path).unwrap().permissions()) & 0o777, 0o600);
    // a signer-held channel cannot be restored without the signer
    drop(buyer);
    let e = client(&chain, &net).with_ledger(Box::new(FileClientLedger::open(&cl_path).unwrap())).err().unwrap();
    assert_eq!(e.code, "no_signer");
}

#[test]
fn a_local_key_client_restarts_from_any_client_ledger() {
    let (chain, net) = (Chain::new(), Net::default());
    net.provider("http://vendor.test", &provider(&chain, "vendor", Ledger::in_memory(), 150));
    let store = Arc::new(MemoryClientLedger::default());
    struct Shared(Arc<MemoryClientLedger>);
    impl ClientLedger for Shared {
        fn load(&self) -> Result<Vec<(String, serde_json::Value)>> {
            self.0.load()
        }
        fn save(&self, r: &[(String, serde_json::Value)]) -> Result<()> {
            self.0.save(r)
        }
    }
    let mut c = client(&chain, &net).with_ledger(Box::new(Shared(store.clone()))).unwrap();
    for i in 0..3 {
        assert_eq!(c.request("GET", &format!("http://vendor.test/v1/q?i={i}"), b"").unwrap().status, 200);
    }
    let (chan, signed) = (c.channels["http://vendor.test"].payer.params.channel_id(), c.channels["http://vendor.test"].payer.signed);
    drop(c);
    let mut c = client(&chain, &net).with_ledger(Box::new(Shared(store.clone()))).unwrap();
    assert_eq!(c.channels["http://vendor.test"].payer.signed, signed);
    assert!(c.channels["http://vendor.test"].payer.secret().is_some());
    assert_eq!(c.request("GET", "http://vendor.test/v1/q?i=3", b"").unwrap().status, 200);
    assert_eq!(c.channels["http://vendor.test"].payer.params.channel_id(), chan);
    c.trim_receipts(1);
    assert_eq!(c.channels["http://vendor.test"].receipts.len(), 1);
    let r = c.close("http://vendor.test").unwrap();
    assert_eq!(r["cum"], "600");
    assert_eq!(store.load().unwrap().iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(), ["book", "chan http://vendor.test"]);
}
