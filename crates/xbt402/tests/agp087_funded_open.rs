//! AGP-087 (second closure audit): the library client around a FUNDED open that the
//! seller answers with an error, and its rollover neighbours.
//!
//! review C2 was closed with a preflight. The preflight is the seller's word; this file asks what the
//! client holds after the seller says yes to the preflight and no (or nothing readable) to the
//! funded open. Each `hole_` test FAILS on xbt-rs f0554d0; each `ok_` test passes and is evidence.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use xbt402::client::{split_url, Client, ClientConfig, FileClientLedger, Transport, Wallet};
use xbt402::funding::{ChainBackend, UtxoInfo};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::wire::{OPEN_PATH, ROLLOVER_PATH};
use xbt402::{ChannelError, Result};
use xbt_primitives::address::address_to_spk;
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

const NET: &str = "bip122:11111111111111111111111111111111";
const O: &str = "https://api.example";

#[derive(Default)]
struct MemChain {
    tip: Mutex<u32>,
    utxos: Mutex<HashMap<(String, u32), UtxoInfo>>,
    sent: Mutex<Vec<Tx>>,
}

impl MemChain {
    fn new() -> Arc<Self> {
        let c = Self::default();
        *c.tip.lock().unwrap() = 1_000;
        Arc::new(c)
    }
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

/// Counts what it funds and remembers each funded outpoint.
struct CountingWallet(Arc<MemChain>, Arc<AtomicUsize>, Arc<Mutex<Vec<(String, u64)>>>);

impl Wallet for CountingWallet {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        let n = self.1.fetch_add(1, Ordering::SeqCst) + 1;
        let txid = hex::encode(sha256(format!("funding {n}").as_bytes()));
        let spk = address_to_spk(address, None).map_err(|e| ChannelError::new("bad_address", e.to_string()))?;
        self.0.utxos.lock().unwrap().insert((txid.clone(), 0), UtxoInfo { confirmations: 1, value: sats, script_pubkey: spk, coinbase: false });
        self.2.lock().unwrap().push((txid.clone(), sats));
        Ok((txid, 0))
    }
}

type Rewrite = Box<dyn Fn(&str, &Value, HttpResponse) -> Result<HttpResponse> + Send + Sync>;

/// The provider, with `f` free to change (or lose) each answer on the way back.
struct Edit(Arc<Provider>, Rewrite);

impl Transport for Edit {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        let (_, path) = split_url(url);
        let req: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        (self.1)(&path, &req, self.0.serve(method, &path, headers, body, url, None))
    }
}

fn secret(label: &str) -> SecretKey {
    SecretKey::from_slice(&sha256(label.as_bytes())).unwrap()
}

fn provider(chain: &Arc<MemChain>) -> Arc<Provider> {
    Arc::new(Provider::new(chain.clone(), secret("provider payTo"), ProviderConfig::new(NET), Ledger::in_memory(), Box::new(|_, _| 150),
                           Box::new(|_, p, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())],
                                                                  json!({"answer": p}).to_string().into_bytes()))).unwrap())
}

struct World {
    chain: Arc<MemChain>,
    funded: Arc<AtomicUsize>,
    outs: Arc<Mutex<Vec<(String, u64)>>>,
    prov: Arc<Provider>,
    dir: PathBuf,
}

fn world(name: &str) -> World {
    let dir = std::env::temp_dir().join(format!("xbt-rs-agp087-hub-b-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let chain = MemChain::new();
    World { prov: provider(&chain), chain, funded: Arc::default(), outs: Arc::default(), dir }
}

impl World {
    fn client(&self, f: Rewrite) -> Client {
        let c = self.chain.clone();
        Client::new(ClientConfig::new(NET), Box::new(Edit(self.prov.clone(), f)),
                    Box::new(CountingWallet(self.chain.clone(), self.funded.clone(), self.outs.clone())), Box::new(move || c.block_count()))
            .with_ledger(Box::new(FileClientLedger::open(&self.dir.join("client.jsonl")).unwrap())).unwrap()
    }

    /// Everything a restart of the client would read.
    fn on_disk(&self) -> String {
        std::fs::read_to_string(self.dir.join("client.jsonl")).unwrap_or_default()
    }
}

fn funded_open(path: &str, req: &Value) -> bool {
    path == OPEN_PATH && req.get("preflight") != Some(&Value::Bool(true))
}

/// The seller answers the preflight yes and the funded open 400.
fn says_yes_then_no() -> Rewrite {
    Box::new(|path, req, r| {
        if funded_open(path, req) {
            return Ok(HttpResponse::new(400, vec![], json!({"error": "bad_funding", "detail": "no"}).to_string().into_bytes()));
        }
        Ok(r)
    })
}

// --- C2, one step to the side: the funded open is answered with an error ------------------------------

/// The seller says yes to the preflight and 400 to the funded open. The buyer has paid 200,000 sat
/// into a 2-of-2 whose refund needs the payer key. With no `on_refund` hook (the default, and what
/// every binary in the workspace uses) that key exists only in `open`'s local `ClientChannel`,
/// which is dropped at the error: nothing in memory or in the ledger can ever sign the refund.
#[test]
fn hole_c2_a_funded_open_answered_with_an_error_keeps_the_channel_key() {
    let w = world("refused");
    let mut c = w.client(says_yes_then_no());
    let e = c.request("GET", &format!("{O}/v1/q"), b"").unwrap_err();
    assert_eq!(e.code, "bad_funding", "{e}");
    assert_eq!(w.funded.load(Ordering::SeqCst), 1, "the funded open is what was refused");
    let (txid, sats) = w.outs.lock().unwrap()[0].clone();
    assert!(w.chain.get_tx_out(&txid, 0, true).unwrap().is_some(), "{sats} sat sit in the channel script");
    let held = c.channels.values().chain(c.pending_rolled.values()).chain(c.next_rolled.values().flatten())
        .any(|ch| ch.payer.params.funding_txid() == txid);
    assert!(held || w.on_disk().contains(&txid),
            "the client funded {sats} sat at {txid}:0 and holds no key and no refund for it (memory: {} channels; ledger: {:?})",
            c.channels.len(), w.on_disk());
}

/// The same when the seller DID open the channel and only its answer was lost: the provider holds
/// an open channel, the buyer has forgotten it.
#[test]
fn hole_c2_a_funded_open_whose_answer_was_lost_keeps_the_channel_key() {
    let w = world("lost");
    let mut c = w.client(Box::new(|path, req, r| {
        if funded_open(path, req) {
            return Err(ChannelError::new("transport", "timed out"));
        }
        Ok(r)
    }));
    assert!(c.request("GET", &format!("{O}/v1/q"), b"").is_err());
    assert_eq!((w.funded.load(Ordering::SeqCst), w.prov.channel_ids().len()), (1, 1), "the provider opened it");
    let (txid, sats) = w.outs.lock().unwrap()[0].clone();
    let held = c.channels.values().any(|ch| ch.payer.params.funding_txid() == txid);
    assert!(held || w.on_disk().contains(&txid), "the client funded {sats} sat at {txid}:0, the provider opened it, and the client forgot it");
}

/// What the seller's answers can make the client do: every later request funds another channel,
/// because the origin has no channel on the books, until `budget_sats` is used up.
#[test]
fn hole_c2_a_seller_refusing_every_funded_open_is_funded_once() {
    let w = world("drain");
    let mut c = w.client(says_yes_then_no());
    for _ in 0..8 {
        let _ = c.request("GET", &format!("{O}/v1/q"), b"");
    }
    let n = w.funded.load(Ordering::SeqCst);
    let total: u64 = w.outs.lock().unwrap().iter().map(|o| o.1).sum();
    assert_eq!(n, 1, "the seller's yes-then-no made the client fund {n} channels, {total} sat, none of them on its books");
}

/// With the hook set, the refund is handed out before the funded open leaves: the original C2 limit
/// (locked until expiry), not a loss. Evidence for the limit's wording.
#[test]
fn ok_c2_with_a_refund_hook_the_refused_open_is_refundable_at_expiry() {
    let w = world("hook");
    let mut c = w.client(says_yes_then_no());
    let refunds: Arc<Mutex<Vec<(String, u32)>>> = Arc::default();
    let r2 = refunds.clone();
    c.on_refund = Some(Box::new(move |hx, exp| r2.lock().unwrap().push((hx.to_string(), exp))));
    assert!(c.request("GET", &format!("{O}/v1/q"), b"").is_err());
    let (txid, _) = w.outs.lock().unwrap()[0].clone();
    let (hx, _) = refunds.lock().unwrap()[0].clone();
    let tx = Tx::parse_hex(&hx).unwrap();
    assert_eq!((tx.inputs[0].prevout.txid_hex(), tx.inputs[0].prevout.vout), (txid, 0));
}

// --- C3: the rollover after an error answer, then close, then refund --------------------------------

fn paid_calls(c: &mut Client, n: usize) {
    for _ in 0..n {
        assert_eq!(c.request("GET", &format!("{O}/v1/q"), b"").unwrap().status, 200);
    }
}

/// Every answer a provider can give to a rollover it DID broadcast: the next channel is on the
/// client's books and in its ledger, with a refund that spends the rollover's second output, and
/// `adopt_rolled` makes it the live one.
#[test]
fn ok_c3_every_rollover_answer_leaves_the_next_channel_and_its_refund() {
    type Ans = fn(HttpResponse) -> Result<HttpResponse>;
    let answers: [(&str, Ans); 6] = [
        ("400", |_| Ok(HttpResponse::new(400, vec![], br#"{"error":"bad_request","detail":"no"}"#.to_vec()))),
        ("403", |_| Ok(HttpResponse::new(403, vec![], br#"{"error":"forbidden"}"#.to_vec()))),
        ("500", |_| Ok(HttpResponse::new(500, vec![], b"oops".to_vec()))),
        ("timeout", |_| Err(ChannelError::new("transport", "timed out"))),
        ("garbage 200", |_| Ok(HttpResponse::new(200, vec![], b"<html>".to_vec()))),
        ("200 without txid", |_| Ok(HttpResponse::new(200, vec![], br#"{"status":"rolled"}"#.to_vec()))),
    ];
    for (i, (name, ans)) in answers.into_iter().enumerate() {
        let w = world(&format!("roll{i}"));
        let mut c = w.client(Box::new(move |path, _, r| if path == ROLLOVER_PATH && r.status == 200 { ans(r) } else { Ok(r) }));
        paid_calls(&mut c, 8);
        let old = c.channels[O].payer.params.clone();
        assert!(c.rollover(O).is_err(), "{name}");
        let roll = w.chain.sent.lock().unwrap().last().unwrap().clone();
        assert_eq!(roll.inputs[0].prevout.txid_hex(), old.funding_txid(), "{name}: the provider broadcast the rollover");
        let next = &c.next_rolled[O];
        assert_eq!(next.len(), 1, "{name}");
        let refund = Tx::parse_hex(&next[0].refund_hex).unwrap();
        assert_eq!((refund.inputs[0].prevout.txid_hex(), refund.inputs[0].prevout.vout), (roll.txid(), 1), "{name}");
        assert!(w.on_disk().contains(&roll.txid()), "{name}: the next channel is in the ledger");
        c.adopt_rolled(O, &roll.txid()).unwrap();
        assert_eq!(c.channels[O].payer.params.funding_txid(), roll.txid(), "{name}");
        assert_eq!(c.pending_rolled[O].payer.params.funding_txid(), old.funding_txid(), "{name}");
    }
}

/// A rollover the provider refused and did NOT broadcast, then a close: the close goes through
/// (AGP-085 item 3), and the next channel record of the dead rollover stays on the books.
#[test]
fn ok_c3_a_close_after_a_refused_rollover_goes_through() {
    let w = world("rollclose");
    let chain = w.chain.clone();
    let mut c = w.client(Box::new(|_, _, r| Ok(r)));
    paid_calls(&mut c, 8);
    // the node refuses the rollover's broadcast: the provider answers close_failed
    let funding = c.channels[O].payer.params.funding_txid();
    let saved = chain.utxos.lock().unwrap().remove(&(funding.clone(), 0)).unwrap();
    assert!(c.rollover(O).is_err());
    chain.utxos.lock().unwrap().insert((funding, 0), saved);
    let r = c.close(O);
    assert!(r.is_ok(), "{r:?}");
}

/// A restart between the rollover's write-ahead and its answer reads the next channel back.
#[test]
fn ok_c3_the_next_channel_survives_a_restart() {
    let w = world("restart");
    let txid = {
        let mut c = w.client(Box::new(|path, _, r| if path == ROLLOVER_PATH { Err(ChannelError::new("transport", "timed out")) } else { Ok(r) }));
        paid_calls(&mut c, 8);
        assert!(c.rollover(O).is_err());
        c.next_rolled[O][0].payer.params.funding_txid()
    };
    let mut c = w.client(Box::new(|_, _, r| Ok(r)));
    assert_eq!(c.next_rolled[O][0].payer.params.funding_txid(), txid);
    c.adopt_rolled(O, &txid).unwrap();
    assert!(!c.channels[O].refund_hex.is_empty());
}

// --- C5: the ledger lock is keyed on the path string ---------------------------------------------------

/// The stated limit, measured: the lock is `<path>.lock` for the path as given. The same path
/// spelled another way (`a/../x`, a symlinked DIRECTORY) reaches the same lock file and is refused.
/// A symlink or a hard link to the ledger FILE has its own sidecar and is accepted; the Rust
/// ledger's compaction then renames a new file over the link, so the two openers hold two files.
#[cfg(unix)]
#[test]
fn ok_c5_limit_a_second_path_to_the_ledger_file_is_locked_only_when_it_shares_the_sidecar() {
    let w = world("c5");
    std::fs::create_dir_all(w.dir.join("sub")).unwrap();
    let path = w.dir.join("ledger.jsonl");
    let first = Ledger::open(&path).unwrap();
    // another spelling, and a symlinked directory: the same sidecar, refused
    assert_eq!(Ledger::open(&w.dir.join("sub").join("..").join("ledger.jsonl")).unwrap_err().code, "ledger_locked");
    std::os::unix::fs::symlink(&w.dir, w.dir.join("dirlink")).unwrap();
    assert_eq!(Ledger::open(&w.dir.join("dirlink").join("ledger.jsonl")).unwrap_err().code, "ledger_locked");
    // a symlink and a hard link to the file: their own sidecars, accepted
    std::os::unix::fs::symlink(&path, w.dir.join("sym.jsonl")).unwrap();
    std::fs::hard_link(&path, w.dir.join("hard.jsonl")).unwrap();
    let via_sym = Ledger::open(&w.dir.join("sym.jsonl"));
    let via_hard = Ledger::open(&w.dir.join("hard.jsonl"));
    assert!(via_sym.is_ok() && via_hard.is_ok(), "the limit changed: {:?} {:?}", via_sym.err(), via_hard.err());
    // the Rust compaction replaced the symlink by a regular file: two ledgers from here on
    assert!(!std::fs::symlink_metadata(w.dir.join("sym.jsonl")).unwrap().file_type().is_symlink());
    drop(first);
}

// --- C2: how long a refused (or ignored) funded open locks the capacity -------------------------------

/// The expiry a client funds is `max(want, minExpiryBlocks + minConf + closeMarginBlocks)` capped
/// at `maxExpiryBlocks - 1`, and all four numbers are the seller's. The client has no ceiling of
/// its own (the hub has one for its ch2s: `ch2_max_expiry_blocks`). A seller whose offer says
/// minExpiryBlocks 2,000,000 gets a funded channel that the buyer can refund in about 38 years,
/// and "locked until expiry" (the stated C2 limit) means that long.
#[test]
fn hole_c2_the_client_bounds_the_expiry_a_sellers_offer_asks_for() {
    let w = world("expiry");
    let mut cfg = ProviderConfig::new(NET);
    cfg.policy.min_expiry_blocks = 2_000_000;
    cfg.policy.max_expiry_blocks = 3_000_000;
    let prov = Arc::new(Provider::new(w.chain.clone(), secret("slow seller"), cfg, Ledger::in_memory(), Box::new(|_, _| 150),
                                      Box::new(|_, _, _| HttpResponse::new(200, vec![], b"{}".to_vec()))).unwrap());
    let c0 = w.chain.clone();
    let cc = ClientConfig::new(NET);
    let want = cc.expiry_blocks;
    let mut c = Client::new(cc, Box::new(Edit(prov, Box::new(|_, _, r| Ok(r)))),
                            Box::new(CountingWallet(w.chain.clone(), w.funded.clone(), w.outs.clone())), Box::new(move || c0.block_count()));
    let r = c.request("GET", &format!("{O}/v1/q"), b"");
    let funded = w.funded.load(Ordering::SeqCst);
    let blocks = c.channels.get(O).map(|ch| ch.payer.params.expiry - 1_000).unwrap_or(0);
    assert!(funded == 0 || blocks <= 10 * want,
            "the client wanted {want} blocks and funded {} sat locked for {blocks} blocks (about {} years) on the seller's word: {:?}",
            w.outs.lock().unwrap()[0].1, blocks / 52_560, r.map(|r| r.status));
}

// --- C3 with a signer: a second rollover attempt replaces the first one's key --------------------------

/// A signer keeps ONE issued key per origin (`pending:<origin>/next`; `new_key` replaces it:
/// `LocalSigner::new_key`, and xbt-signer `channels.rs` `issue_key`: "an issued key never used is
/// replaced"). The client asks for a new key at every rollover attempt. So: attempt 1 is answered
/// with an error (the provider broadcast it, or keeps it), the embedder tries again, attempt 2's
/// `new_key` wipes the key attempt 1's next channel is paid to, and `adopt_rolled` for attempt 1's
/// transaction is refused `bad_key`: the next channel's coins have no key and no refund. The hub
/// got "one next key per ch2" for this in AGP-085; the signer-backed client did not.
#[test]
fn hole_c3_a_signer_backed_rollover_tried_again_keeps_the_first_attempts_key() {
    use xbt402::signer::LocalSigner;
    let w = world("signer-retry");
    let c0 = w.chain.clone();
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    // the provider broadcasts the first rollover and answers 400; later ones get its real answer
    let t = Edit(w.prov.clone(), Box::new(move |path, _, r| {
        if path == ROLLOVER_PATH && r.status == 200 && n2.fetch_add(1, Ordering::SeqCst) == 0 {
            return Ok(HttpResponse::new(400, vec![], br#"{"error":"bad_request","detail":"no"}"#.to_vec()));
        }
        Ok(r)
    }));
    let mut c = Client::new(ClientConfig::new(NET), Box::new(t), Box::new(CountingWallet(w.chain.clone(), w.funded.clone(), w.outs.clone())),
                            Box::new(move || c0.block_count())).with_signer(Arc::new(LocalSigner::new()));
    paid_calls(&mut c, 8);
    let old = c.channels[O].payer.params.clone();
    assert_eq!(c.rollover(O).unwrap_err().code, "bad_request");
    let roll = w.chain.sent.lock().unwrap().last().unwrap().clone();
    assert_eq!(roll.inputs[0].prevout.txid_hex(), old.funding_txid(), "the provider broadcast attempt 1");
    let leftover = roll.outputs[1].value;
    // the embedder was told the rollover failed and tries again
    assert!(c.rollover(O).is_err());
    assert_eq!(n.load(Ordering::SeqCst), 1, "attempt 2 was not broadcast (the channel is spent)");
    // ... then sees attempt 1's transaction on chain and adopts it
    let r = c.adopt_rolled(O, &roll.txid());
    assert!(r.is_ok() && !c.channels[O].refund_hex.is_empty(),
            "{leftover} sat sit in the next channel of rollover {} and the signer no longer holds its key: {:?}", roll.txid(), r.err());
}
