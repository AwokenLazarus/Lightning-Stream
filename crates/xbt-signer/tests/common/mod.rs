//! Test rig: a fake pruned node (B2 `tests/_agp017.py` `PrunedChain`: blocks, confirmations, no
//! txindex) as the signer's `Node`, and a signer root builder.
#![allow(dead_code)]
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{json, Value};
use xbt402::{ChannelError, Result};
use xbt_primitives::hash::sha256;
use xbt_primitives::tx::Tx;
use xbt_signer::node::Node;
use xbt_signer::signer::{Signer, SignerOptions};

pub const MAIN_961640: &str = "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb";

#[derive(Default)]
pub struct State {
    pub chain: String,
    pub height: u64,
    pub mempool: HashMap<String, Value>,
    pub blocks: HashMap<u64, Vec<Value>>,
    pub conf_height: HashMap<String, u64>,
    pub utxos: HashMap<(String, u32), (i64, String)>,
    pub spent_by: HashMap<(String, u32), String>,
    /// What an outpoint held before a transaction spent it (AGP-095: `gettxout` without the
    /// mempool still shows it while its spender is unconfirmed, and `evict` gives it back).
    pub spent: HashMap<(String, u32), (i64, String)>,
    pub sent: Vec<String>,
    pub calls: Vec<String>,
    pub reject: Option<String>,
    pub mined_by_signer: u64,
    pub down: bool,
    pub coinbase: std::collections::HashSet<String>,
    /// `getdeploymentinfo`; None: the node does not answer it.
    pub deployments: Option<Value>,
    /// How long `scantxoutset` takes (a scan of the UTXO set can take minutes on mainnet).
    pub scan_ms: u64,
}

pub struct FakeChain {
    pub st: Mutex<State>,
    pub allow_generate: AtomicBool,
}

fn rpc_err(m: &str) -> ChannelError {
    ChannelError::new("rpc_error", m.to_string())
}

/// The node's own JSON-RPC error (`xbt_signer::node::REFUSED`): it answered, and did not do it.
/// A rejected broadcast is one (AGP-085: only that lets a funding forget its pending record).
fn refused(m: &str) -> ChannelError {
    ChannelError::new(xbt_signer::node::REFUSED, m.to_string())
}

impl FakeChain {
    pub fn new(chain: &str, height: u64) -> Arc<Self> {
        Arc::new(Self { st: Mutex::new(State { chain: chain.into(), height, ..Default::default() }), allow_generate: AtomicBool::new(false) })
    }

    pub fn bhash(chain: &str, h: u64) -> String {
        if chain == "main" && h == 961_640 { MAIN_961640.into() } else { format!("{h:064x}") }
    }

    pub fn network(&self) -> String {
        let c = self.st.lock().unwrap().chain.clone();
        xbt_primitives::network::network_id(&Self::bhash(&c, if c == "main" { 961_640 } else { 101 }))
    }

    /// An outside coin (a faucet send) to `spk`.
    pub fn credit(&self, txid: &str, vout: u32, sats: i64, spk: &str, confirmed: bool) {
        let mut s = self.st.lock().unwrap();
        let mut outs: Vec<Value> = (0..vout).map(|n| json!({"n": n, "value": 0, "scriptPubKey": {"hex": ""}})).collect();
        outs.push(json!({"n": vout, "value": sats as f64 / 1e8, "scriptPubKey": {"hex": spk}}));
        let tx = json!({"txid": txid, "hex": "", "vin": [{"txid": "ee".repeat(32), "vout": 0}], "vout": outs});
        s.utxos.insert((txid.into(), vout), (sats, spk.into()));
        if confirmed {
            let h = s.height;
            s.blocks.entry(h).or_default().push(tx);
            s.conf_height.insert(txid.into(), h);
        } else {
            s.mempool.insert(txid.into(), tx);
        }
    }

    /// A coinbase paying `sats` to `spk`, in a block at the current height.
    pub fn credit_coinbase(&self, txid: &str, vout: u32, sats: i64, spk: &str) {
        let mut s = self.st.lock().unwrap();
        let mut outs: Vec<Value> = (0..vout).map(|n| json!({"n": n, "value": 0, "scriptPubKey": {"hex": ""}})).collect();
        outs.push(json!({"n": vout, "value": sats as f64 / 1e8, "scriptPubKey": {"hex": spk}}));
        let tx = json!({"txid": txid, "hex": "", "vin": [{"coinbase": "03c80000", "sequence": 4294967295u32}], "vout": outs});
        let h = s.height;
        s.utxos.insert((txid.into(), vout), (sats, spk.into()));
        s.blocks.entry(h).or_default().push(tx);
        s.conf_height.insert(txid.into(), h);
        s.coinbase.insert(txid.into());
    }

    pub fn mine(&self, n: u64) {
        let mut s = self.st.lock().unwrap();
        for _ in 0..n {
            s.height += 1;
            let h = s.height;
            let txs: Vec<Value> = s.mempool.drain().map(|(_, v)| v).collect();
            for t in &txs {
                let id = t["txid"].as_str().unwrap().to_string();
                s.conf_height.insert(id, h);
            }
            s.blocks.insert(h, txs);
        }
    }

    pub fn height(&self) -> u64 {
        self.st.lock().unwrap().height
    }

    /// A mempool transaction that is never mined leaves the mempool (expired, evicted, replaced by
    /// nothing): its inputs are unspent again and its outputs never existed (AGP-095).
    pub fn evict(&self, txid: &str) {
        let mut s = self.st.lock().unwrap();
        assert!(s.mempool.remove(txid).is_some(), "{txid} is not in the mempool");
        let ins: Vec<(String, u32)> = s.spent_by.iter().filter(|(_, sp)| sp.as_str() == txid).map(|(op, _)| op.clone()).collect();
        for op in ins {
            s.spent_by.remove(&op);
            if let Some(was) = s.spent.remove(&op) {
                s.utxos.insert(op, was);
            }
        }
        s.utxos.retain(|(t, _), _| t != txid);
    }

    pub fn mine_to(&self, h: u64) {
        let cur = self.height();
        if h > cur {
            self.mine(h - cur);
        }
    }

    pub fn mempool(&self) -> Vec<String> {
        self.st.lock().unwrap().mempool.keys().cloned().collect()
    }

    pub fn sent_txs(&self) -> Vec<Tx> {
        self.st.lock().unwrap().sent.iter().map(|h| Tx::parse_hex(h).unwrap()).collect()
    }

    pub fn tx(&self, txid: &str) -> Tx {
        self.sent_txs().into_iter().find(|t| t.txid() == txid).expect("tx sent")
    }

    pub fn unspent_to(&self, spk: &str) -> i64 {
        self.st.lock().unwrap().utxos.values().filter(|(_, s)| s == spk).map(|(v, _)| *v).sum()
    }

    fn send(&self, raw: &str) -> Result<String> {
        let mut s = self.st.lock().unwrap();
        if let Some(r) = s.reject.clone() {
            return Err(refused(&r));
        }
        let tx = Tx::parse_hex(raw).map_err(|_| refused("TX decode failed"))?;
        let txid = tx.txid();
        if s.mempool.contains_key(&txid) || s.conf_height.contains_key(&txid) {
            return Err(refused("txn-already-known"));
        }
        if tx.locktime > 0 && tx.locktime < 500_000_000 && tx.locktime as u64 > s.height {
            return Err(refused("non-final"));
        }
        for i in &tx.inputs {
            if !s.utxos.contains_key(&(i.prevout.txid_hex(), i.prevout.vout)) {
                return Err(refused("bad-txns-inputs-missingorspent"));
            }
        }
        for i in &tx.inputs {
            let op = (i.prevout.txid_hex(), i.prevout.vout);
            if let Some(was) = s.utxos.remove(&op) {
                s.spent.insert(op.clone(), was);
            }
            s.spent_by.insert(op, txid.clone());
        }
        for (n, o) in tx.outputs.iter().enumerate() {
            s.utxos.insert((txid.clone(), n as u32), (o.value, hex::encode(&o.script_pubkey)));
        }
        let vin: Vec<Value> = tx.inputs.iter().map(|i| json!({"txid": i.prevout.txid_hex(), "vout": i.prevout.vout,
            "txinwitness": i.witness.iter().map(hex::encode).collect::<Vec<_>>()})).collect();
        let vout: Vec<Value> = tx.outputs.iter().enumerate().map(|(n, o)| json!({"n": n, "value": o.value as f64 / 1e8,
            "scriptPubKey": {"hex": hex::encode(&o.script_pubkey)}})).collect();
        s.mempool.insert(txid.clone(), json!({"txid": txid, "hex": raw, "locktime": tx.locktime, "vin": vin, "vout": vout}));
        s.sent.push(raw.into());
        Ok(txid)
    }

    fn gettxout(&self, txid: &str, vout: u32, mem: bool) -> Value {
        let s = self.st.lock().unwrap();
        let op = (txid.to_string(), vout);
        // as a node answers: without the mempool, an output only a mempool transaction spends is still there
        let unspent = s.utxos.get(&op).cloned()
            .or_else(|| s.spent.get(&op).filter(|_| !mem && s.spent_by.get(&op).is_some_and(|sp| s.mempool.contains_key(sp))).cloned());
        let Some((v, spk)) = unspent else { return Value::Null };
        let confs = if s.mempool.contains_key(txid) {
            if !mem {
                return Value::Null;
            }
            0
        } else {
            s.height - s.conf_height.get(txid).copied().unwrap_or(s.height) + 1
        };
        json!({"bestblock": Self::bhash(&s.chain, s.height), "confirmations": confs, "value": v as f64 / 1e8,
               "scriptPubKey": {"hex": spk}, "coinbase": s.coinbase.contains(txid)})
    }
}

fn hash_height(h: &str) -> u64 {
    if h == MAIN_961640 { 961_640 } else { u64::from_str_radix(h, 16).unwrap_or(0) }
}

impl Node for FakeChain {
    fn call(&self, method: &str, p: Value) -> Result<Value> {
        let p = p.as_array().cloned().unwrap_or_default();
        {
            let mut s = self.st.lock().unwrap();
            s.calls.push(method.into());
            if s.down {
                return Err(rpc_err("connection refused"));
            }
        }
        let chain = self.st.lock().unwrap().chain.clone();
        Ok(match method {
            "getblockchaininfo" => {
                let s = self.st.lock().unwrap();
                json!({"chain": s.chain, "blocks": s.height, "initialblockdownload": false, "pruned": true})
            }
            "getblockcount" => json!(self.height()),
            "getblockhash" => {
                let h = p[0].as_u64().unwrap_or(0);
                if h > self.height() {
                    return Err(rpc_err("Block height out of range"));
                }
                json!(Self::bhash(&chain, h))
            }
            "getblockheader" => json!({"height": hash_height(p[0].as_str().unwrap_or(""))}),
            "getblock" => {
                let h = hash_height(p[0].as_str().unwrap_or(""));
                json!({"height": h, "tx": self.st.lock().unwrap().blocks.get(&h).cloned().unwrap_or_default()})
            }
            "sendrawtransaction" => json!(self.send(p[0].as_str().unwrap_or(""))?),
            "gettxout" => self.gettxout(p[0].as_str().unwrap_or(""), p[1].as_u64().unwrap_or(0) as u32, p.get(2).and_then(Value::as_bool).unwrap_or(true)),
            "getrawtransaction" => {
                let txid = p[0].as_str().unwrap_or("");
                let s = self.st.lock().unwrap();
                if let Some(t) = s.mempool.get(txid) {
                    return Ok(t.clone());
                }
                if let Some(bh) = p.get(2).and_then(Value::as_str) {
                    if let Some(t) = s.blocks.get(&hash_height(bh)).and_then(|b| b.iter().find(|t| t["txid"] == txid)) {
                        return Ok(t.clone());
                    }
                }
                return Err(rpc_err("No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries."));
            }
            "gettxspendingprevout" => {
                let s = self.st.lock().unwrap();
                let out: Vec<Value> = p[0].as_array().cloned().unwrap_or_default().into_iter().map(|o| {
                    let op = (o["txid"].as_str().unwrap_or("").to_string(), o["vout"].as_u64().unwrap_or(0) as u32);
                    let mut r = o.clone();
                    if let Some(sp) = s.spent_by.get(&op).filter(|sp| s.mempool.contains_key(*sp)) {
                        r["spendingtxid"] = sp.clone().into();
                    }
                    r
                }).collect();
                json!(out)
            }
            "scantxoutset" => {
                let wait = self.st.lock().unwrap().scan_ms;
                std::thread::sleep(std::time::Duration::from_millis(wait));
                let want: Vec<String> = p[1].as_array().cloned().unwrap_or_default().iter()
                    .filter_map(|d| d.as_str().and_then(|d| d.strip_prefix("raw(")).and_then(|d| d.strip_suffix(')')).map(str::to_string)).collect();
                let s = self.st.lock().unwrap();
                let u: Vec<Value> = s.utxos.iter().filter(|((t, _), (_, spk))| want.contains(spk) && !s.mempool.contains_key(t))
                    .map(|((t, v), (a, spk))| json!({"txid": t, "vout": v, "scriptPubKey": spk, "amount": *a as f64 / 1e8,
                                                     "coinbase": s.coinbase.contains(t), "height": s.conf_height.get(t)})).collect();
                json!({"success": true, "unspents": u})
            }
            "getnewaddress" => json!("bcrt1qmine"),
            "generatetoaddress" => {
                assert_eq!(chain, "regtest", "generatetoaddress off regtest");
                assert!(self.allow_generate.load(Ordering::SeqCst), "generate without the P3 guard");
                let n = p[0].as_u64().unwrap_or(1);
                self.st.lock().unwrap().mined_by_signer += n;
                self.mine(n);
                json!([])
            }
            "getbalances" => json!({"mine": {"trusted": 0, "untrusted_pending": 0, "immature": 0}}),
            "getdeploymentinfo" => {
                let d = self.st.lock().unwrap().deployments.clone();
                d.ok_or_else(|| rpc_err("Method not found"))?
            }
            "estimatesmartfee" => json!({"feerate": 0.00001}),
            // the node wallet's own send (the `pay` rail): a txid that names the call
            "sendtoaddress" => json!(hex::encode(sha256(Value::from(p.clone()).to_string().as_bytes()))),
            other => panic!("FakeChain: unexpected {other} {p:?}"),
        })
    }

    fn set_allow_generate(&self, allow: bool) {
        self.allow_generate.store(allow, Ordering::SeqCst);
    }

    fn wallet(&self) -> String {
        "agent".into()
    }
}

/// A seller's origin on the rig's allowlist.
pub const PROVIDER: &str = "http://127.0.0.1:33210";
/// An address on the rig's allowlist, for the on-chain `pay` rail.
pub const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/// The human's device key.
pub fn human() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

pub fn sign_human(msg: &[u8]) -> String {
    hex::encode(human().sign(msg).to_bytes())
}

/// The rig's policy (the numbers of the AGP-017 rehearsal, G1).
pub fn runbook_policy(extra: Value) -> Value {
    let mut p = json!({"allowlist": [PROVIDER, ADDR], "max_per_tx_sats": 1000, "daily_budget_sats": 6000, "weekly_budget_sats": 6000,
                       "per_counterparty_cap_sats": 9400, "velocity_max": 20, "velocity_window_s": 3600, "human_threshold_sats": 1000,
                       "hot_balance_cap_sats": 15000,
                       "human_pubkey": hex::encode(human().verifying_key().to_bytes()), "split_window_s": 0, "regtest_mine": false,
                       "anchor_interval_s": 5});
    if let (Value::Object(a), Value::Object(b)) = (&mut p, extra) {
        for (k, v) in b {
            a.insert(k, v);
        }
    }
    p
}

/// A signer root with `policy`; the wrapping key file outside it.
pub fn root_with(dir: &Path, policy: &Value) -> PathBuf {
    let root = dir.join("wallet");
    std::fs::create_dir_all(root.join(".run")).unwrap();
    std::fs::write(root.join("policy.json"), policy.to_string()).unwrap();
    root
}

/// Serializes the tests that set process environment variables.
pub static ENV: Mutex<()> = Mutex::new(());

/// The test that holds [`ENV`] (through [`env_lock`]), and since when.
static ENV_HELD: Mutex<Option<(String, std::time::Instant)>> = Mutex::new(None);

/// [`ENV`] held, as a guard that also says which test holds it. A watchdog ends the process
/// with that test's name when one has held it for longer than `XBT_TEST_HANG_SECS` (600 by
/// default): since every test of a binary waits for this lock, one that never returns would
/// otherwise keep the whole binary running, silently, until a CI job's own limit. Before it
/// ends the process it prints the stack of every thread ([`print_stacks`]), which names the
/// wait each one is stuck in.
pub fn env_lock() -> EnvGuard {
    static WATCH: std::sync::Once = std::sync::Once::new();
    WATCH.call_once(|| {
        let limit = std::env::var("XBT_TEST_HANG_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(600u64);
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            let hung = ENV_HELD.lock().unwrap_or_else(|p| p.into_inner()).as_ref().filter(|(_, since)| since.elapsed().as_secs() > limit).map(|(name, _)| name.clone());
            if let Some(name) = hung {
                // straight to the process's stderr: a thread spawned by a test inherits that test's capture of eprintln!
                use std::io::Write;
                let _ = writeln!(std::io::stderr(), "test {name} has run for more than {limit} s: the stacks of its process follow, and the process is ended so that the hang has a name");
                print_stacks();
                let _ = writeln!(std::io::stderr(), "test {name} has run for more than {limit} s: the process is ended so that the hang has a name");
                std::process::exit(101);
            }
        });
    });
    let g = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let name = std::thread::current().name().unwrap_or("?").to_string();
    *ENV_HELD.lock().unwrap_or_else(|p| p.into_inner()) = Some((name, std::time::Instant::now()));
    EnvGuard(Some(g))
}

/// Every thread's stack of this process, to its own stdout and stderr (not a test's capture),
/// by gdb (`thread apply all bt`), for a test that hangs. gdb attaches to the process that started it only where the system lets a
/// process be traced by its own child (`kernel.yama.ptrace_scope` 0, as CI sets it) or gdb runs
/// as root; elsewhere, or with no gdb on the PATH, one line says so. gdb gets 120 s, and is
/// then killed.
pub fn print_stacks() {
    use std::io::Write;
    let pid = std::process::id().to_string();
    let child = std::process::Command::new("gdb")
        .args(["-p", pid.as_str(), "-batch", "-nx", "-q", "-ex", "set pagination off", "-ex", "set print thread-events off", "-ex", "thread apply all bt"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "no thread stacks: gdb did not start ({e}); install gdb to have them");
            return;
        }
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    let _ = writeln!(std::io::stderr(), "gdb ended with {status}: where it could not attach, set kernel.yama.ptrace_scope to 0 or run the tests as root");
                }
                return;
            }
            Ok(None) if std::time::Instant::now() < deadline => std::thread::sleep(std::time::Duration::from_millis(200)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = writeln!(std::io::stderr(), "gdb took more than 120 s and was killed");
                return;
            }
        }
    }
}

pub struct EnvGuard(Option<std::sync::MutexGuard<'static, ()>>);

impl Drop for EnvGuard {
    fn drop(&mut self) {
        *ENV_HELD.lock().unwrap_or_else(|p| p.into_inner()) = None;
        self.0.take();
    }
}

pub fn env_for(dir: &Path) {
    std::env::set_var("B2_HOT_KEYFILE", dir.join("keys").join("hot.key"));
    std::env::remove_var("B2_HOT_PASSPHRASE");
    std::env::remove_var("B2_ANCHOR_SOCK");
    std::env::remove_var("B2_CHAIN");
    std::env::remove_var("B2_HOT_ALLOW_PLAINTEXT");
    std::env::remove_var("B2_CHAIN_BACKEND");
    std::env::set_var("B2_WATCH_INTERVAL", "0");
}

pub fn signer(root: &Path, chain: &Arc<FakeChain>, anchor: Option<xbt_signer::anchor::AnchorClient>) -> xbt402::Result<Arc<Signer>> {
    Signer::new(root, SignerOptions { node: Some(chain.clone()), anchor, ..Default::default() })
}

pub fn call(s: &Signer, m: &str, p: Value) -> Value {
    s.handle(m, &p).unwrap_or_else(|e| panic!("{m}: {}: {}", e.code, e.msg))
}

/// One signer on a fake pruned node.
pub struct Rig {
    pub dir: tempfile::TempDir,
    pub root: PathBuf,
    pub chain: Arc<FakeChain>,
    pub s: Arc<Signer>,
    pub witness: Option<xbt_signer::anchor::Witness>,
}

impl Rig {
    /// Hold `ENV` for the whole test (the signer reads its environment).
    pub fn new(policy_extra: Value, with_witness: bool) -> Self {
        Self::build(policy_extra, with_witness, "regtest")
    }

    pub fn build(policy_extra: Value, with_witness: bool, chain_name: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        env_for(dir.path());
        let chain = FakeChain::new(chain_name, if chain_name == "main" { 962_000 } else { 6_720 });
        let witness = with_witness.then(|| xbt_signer::anchor::serve_witness(&dir.path().join("anchor"), &dir.path().join("anchor/w.sock"), 0o600).unwrap());
        let root = root_with(dir.path(), &runbook_policy(policy_extra));
        let ac = witness.as_ref().map(|w| xbt_signer::anchor::AnchorClient::new(&w.sock_path));
        let s = Signer::new(&root, SignerOptions { node: Some(chain.clone()), anchor: ac,
                                                   ..Default::default() }).unwrap();
        Self { dir, root, chain, s, witness }
    }

    /// A fresh signer process on the same root (a restart).
    pub fn restart(&mut self) -> xbt402::Result<()> {
        let ac = self.witness.as_ref().map(|w| xbt_signer::anchor::AnchorClient::new(&w.sock_path));
        self.s = Signer::new(&self.root, SignerOptions { node: Some(self.chain.clone()), anchor: ac,
                                                         ..Default::default() })?;
        Ok(())
    }

    pub fn call(&self, m: &str, p: Value) -> Value {
        call(&self.s, m, p)
    }

    /// The hot-key rotation the human signs (AGP-063 W3: `rotate_hot_key` is never unsigned).
    pub fn rotate_hot_key(&self) -> Value {
        let old = self.call("hot_address", json!({}))["hot_address"].as_str().unwrap().to_string();
        let exp = xbt_signer::pyjson::now_f64() as i64 + 300;
        self.call("rotate_hot_key", json!({"expiry": exp, "signature": sign_human(&xbt_signer::approval::rotate_message(&old, exp))}))
    }

    pub fn hot_spk(&self) -> String {
        self.call("hot_address", json!({}))["hot_spk"].as_str().unwrap().to_string()
    }

    pub fn hot_sats(&self) -> i64 {
        self.call("hot_address", json!({}))["hot_sats"].as_i64().unwrap()
    }

    /// A confirmed coin to the hot key, noticed.
    pub fn fund_hot(&self, tag: u8, sats: i64) -> String {
        let txid = hex::encode([tag; 32]);
        self.chain.credit(&txid, 0, sats, &self.hot_spk(), true);
        self.call("notice_hot_txid", json!({"txid": txid}));
        txid
    }

    pub fn sigs(&self) -> Vec<Value> {
        self.call("signatures", json!({"limit": 1000}))["signatures"].as_array().unwrap().clone()
    }
}
