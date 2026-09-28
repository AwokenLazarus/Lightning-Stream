//! An in-process routing world for tests (B1 `tests/security/routehelp.py`): a fake chain
//! ([`MemChain`]: the node calls, the watcher's spend scan and a wallet) and an in-process HTTP
//! network ([`MemNet`]: origin → service, with answers that can be dropped after serving). No
//! sockets, no node.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use xbt402::client::{Transport, Wallet};
use xbt402::error::{ChannelError, Result};
use xbt402::funding::{ChainBackend, UtxoInfo};
use xbt402::http::HttpService;
use xbt402::provider::HttpResponse;
use xbt402::route::SpendScan;
use xbt_primitives::address::address_to_spk;
use xbt_primitives::tx::Tx;

#[derive(Default)]
struct ChainState {
    height: u32,
    utxos: HashMap<(String, u32), UtxoInfo>,
    spent: HashMap<(String, u32), String>,
    raw: HashMap<String, String>,
}

/// A fake node: fundings appear with 6 confirmations, broadcasts spend their inputs (a conflicting
/// spend is refused) and create unconfirmed outputs; `confirm_all` confirms everything.
pub struct MemChain {
    st: Mutex<ChainState>,
}

impl MemChain {
    pub fn new(height: u32) -> Arc<Self> {
        Arc::new(Self { st: Mutex::new(ChainState { height, ..Default::default() }) })
    }

    fn st(&self) -> std::sync::MutexGuard<'_, ChainState> {
        self.st.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn height(&self) -> u32 {
        self.st().height
    }

    pub fn set_height(&self, h: u32) {
        self.st().height = h;
    }

    pub fn confirm_all(&self) {
        for u in self.st().utxos.values_mut() {
            u.confirmations = u.confirmations.max(1);
        }
    }

    pub fn raw(&self, txid: &str) -> Option<Tx> {
        self.st().raw.get(txid).and_then(|h| Tx::parse_hex(h).ok())
    }
}

fn rand_txid() -> String {
    let mut b = [0u8; 32];
    getrandom_fill(&mut b);
    hex::encode(b)
}

fn getrandom_fill(b: &mut [u8]) {
    // std-only randomness for test txids: hash a counter with the address of a stack value and time
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let h = xbt_primitives::hash::sha256(format!("{n}/{t}/{:p}", &n).as_bytes());
    b.copy_from_slice(&h[..b.len()]);
}

impl ChainBackend for MemChain {
    fn block_count(&self) -> Result<u32> {
        Ok(self.height())
    }

    fn get_tx_out(&self, txid: &str, vout: u32, _mempool: bool) -> Result<Option<UtxoInfo>> {
        let st = self.st();
        let k = (txid.to_string(), vout);
        if st.spent.contains_key(&k) {
            return Ok(None);
        }
        Ok(st.utxos.get(&k).cloned())
    }

    fn send_raw_transaction(&self, hex: &str) -> Result<String> {
        let tx = Tx::parse_hex(hex)?;
        let txid = tx.txid();
        let mut st = self.st();
        if st.raw.contains_key(&txid) {
            return Ok(txid);
        }
        for i in &tx.inputs {
            let k = (i.prevout.txid_hex(), i.prevout.vout);
            if st.spent.get(&k).is_some_and(|s| *s != txid) {
                return Err(ChannelError::new("rpc_error", "txn-mempool-conflict"));
            }
        }
        for i in &tx.inputs {
            st.spent.insert((i.prevout.txid_hex(), i.prevout.vout), txid.clone());
        }
        for (n, o) in tx.outputs.iter().enumerate() {
            st.utxos.insert((txid.clone(), n as u32), UtxoInfo { confirmations: 0, value: o.value as u64, script_pubkey: o.script_pubkey.clone(), coinbase: false });
        }
        st.raw.insert(txid.clone(), hex.to_string());
        Ok(txid)
    }

    fn has_transaction(&self, txid: &str) -> Result<bool> {
        Ok(self.st().raw.contains_key(txid))
    }
}

impl SpendScan for MemChain {
    fn find_spend(&self, txid: &str, vout: u32, _from: u32) -> Result<Option<Tx>> {
        let st = self.st();
        Ok(st.spent.get(&(txid.to_string(), vout)).and_then(|s| st.raw.get(s)).and_then(|h| Tx::parse_hex(h).ok()))
    }
}

impl Wallet for MemChain {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        let spk = address_to_spk(address, Some("bcrt")).map_err(|e| ChannelError::new("bad_address", e.to_string()))?;
        let txid = rand_txid();
        self.st().utxos.insert((txid.clone(), 0), UtxoInfo { confirmations: 6, value: sats, script_pubkey: spk, coinbase: false });
        Ok((txid, 0))
    }
}

/// A shared chain as a boxed wallet.
pub struct ChainWallet(pub Arc<MemChain>);

impl Wallet for ChainWallet {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        self.0.fund(address, sats)
    }
}

/// `drop(method, path) -> true` loses the answer after the service handled the request.
pub type DropFn = Box<dyn Fn(&str, &str) -> bool + Send + Sync>;

/// origin → service, in process.
#[derive(Default)]
pub struct MemNet {
    apps: Mutex<HashMap<String, Arc<dyn HttpService>>>,
    drops: Mutex<HashMap<String, DropFn>>,
    /// (method, origin, path) of every request.
    pub calls: Mutex<Vec<(String, String, String)>>,
}

impl MemNet {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn add(&self, origin: &str, app: Arc<dyn HttpService>) {
        self.apps.lock().unwrap().insert(origin.into(), app);
    }

    pub fn set_drop(&self, origin: &str, f: Option<DropFn>) {
        let mut d = self.drops.lock().unwrap();
        match f {
            Some(f) => d.insert(origin.into(), f),
            None => d.remove(origin),
        };
    }

    pub fn count(&self, path: &str) -> usize {
        self.calls.lock().unwrap().iter().filter(|c| c.2 == path).count()
    }
}

/// A [`Transport`] over a [`MemNet`].
pub struct NetTransport(pub Arc<MemNet>);

impl Transport for NetTransport {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        let (origin, path) = xbt402::client::split_url(url);
        let app = self.0.apps.lock().unwrap().get(&origin).cloned().ok_or_else(|| ChannelError::new("transport_error", format!("connection refused: {origin}")))?;
        self.0.calls.lock().unwrap().push((method.into(), origin.clone(), path.clone()));
        let r = app.serve(method, &path, headers, body, url);
        if self.0.drops.lock().unwrap().get(&origin).is_some_and(|d| d(method, &path)) {
            return Err(ChannelError::new("transport_error", "answer lost"));
        }
        let headers = r.headers.into_iter().map(|(k, v)| (k.to_ascii_uppercase(), v)).collect();
        Ok(HttpResponse::new(r.status, headers, r.body))
    }
}
