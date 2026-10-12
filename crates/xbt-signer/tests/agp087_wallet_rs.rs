//! AGP-087 (second closure audit, Rust wallet). Each test states what the wallet must do and
//! fails on main `f0554d0` for the reason in its doc comment. Nothing here changes the wallet.
//!
//! 1. `xbt402_new_key` wipes the key of a next channel a rollover signature already pays.
//! 2. Two `approve` calls of one token that wait on the spend lock both pay.
//! 3. A stream manifest whose `n * price` overflows is bought past `max_sats` and the budgets.
//! 4. A seller's `minExpiryBlocks` sets how long the channel's coins are locked, with no owner bound.
//! 5. A kept funding that can never confirm blocks its destination past expiry (AGP-085 limit 2).
mod common;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use common::*;
use serde_json::{json, Value};
use xbt402::channel::ChannelParams;
use xbt402::client::Transport;
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::wire::{b64json, unb64json, OPEN_PATH, ROLLOVER_PATH};
use xbt_primitives::ecdsa;
use xbt_primitives::hash::sha256;
use xbt_signer::node::Node;
use xbt_signer::session::{leaf, manifest_message};
use xbt_signer::signer::{Signer, SignerOptions};

type Hook = Box<dyn Fn(&str, &str, &[u8], &[(String, String)]) -> Option<xbt402::Result<HttpResponse>> + Send + Sync>;

struct Hooked {
    web: Arc<Web>,
    hook: Hook,
}

impl Transport for Hooked {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> xbt402::Result<HttpResponse> {
        match (self.hook)(method, url, body, headers) {
            Some(r) => r,
            None => self.web.request(method, url, body, headers),
        }
    }
}

fn hooked(rig: &mut Rig, hook: Hook) {
    let t = Arc::new(Hooked { web: rig.web.clone(), hook });
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(rig.chain.clone()), transport: Some(t), ..Default::default() }).unwrap();
}

fn has_sig(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-SIGNATURE"))
}

fn seller_pay_to() -> Vec<u8> {
    ecdsa::pubkey(&secret("provider payTo")).to_vec()
}

fn ledger(rig: &Rig) -> i64 {
    rig.s.engine.store.payments().unwrap().iter().map(|e| e.amount_sats).sum()
}

fn provider_with(rig: &Rig, doc: Value, min_capacity: u64, price: u64) {
    let mut cfg = ProviderConfig::new(&rig.chain.network());
    cfg.policy.min_capacity = min_capacity;
    cfg.policy.max_capacity = 10_000;
    cfg.policy.min_expiry_blocks = 1_008;
    cfg.policy.min_conf = 1;
    let body = doc.to_string().into_bytes();
    let p = Provider::new(Arc::new(ProviderChain(rig.chain.clone())), secret("provider payTo"), cfg, Ledger::in_memory(), Box::new(move |_, _| price),
                          Box::new(move |_, _, _| HttpResponse::new(200, vec![("Content-Type".into(), "application/json".into())], body.clone()))).unwrap();
    rig.web.sites.lock().unwrap().insert(PROVIDER.into(), Arc::new(p));
}

// --- 1. xbt402_new_key and a rollover already signed ---------------------------------------------------

/// `xbt402_sign_rollover` signs a transaction that pays the rest of the channel into the next
/// channel, whose payer key is the one issued for `<origin>/next`. The reply to the rollover is
/// lost or an error, and the client asks for a key again (xbt402's `Client::rollover` calls
/// `new_key("<origin>/next")` on every attempt, client.rs:950). The provider then broadcasts the
/// first rollover. The signer must still hold the key of the channel its own signature funded:
/// both spending paths of that channel need it (the close and the refund).
///
/// Fails on f0554d0: `ChannelBook::issue_key` wipes the earlier key (channels.rs:584), the attach is
/// refused `bad_key`, and no refund can be signed. The next channel's coins cannot be spent again.
#[test]
fn a_second_new_key_does_not_forget_the_key_a_signed_rollover_pays() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let rig = Rig::new(json!({"max_per_tx_sats": 5000, "human_threshold_sats": 5000}), false);
    provider_with(&rig, json!({"ok": true}), 5_000, 600);
    rig.fund_hot(1, 12_000);
    assert_eq!(rig.call("xbt402_pay", json!({"url": URL, "max_sats": 1_000}))["verdict"], "pending");
    rig.chain.mine(1);
    let chan = rig.call("xbt402_pay", json!({"url": URL, "max_sats": 1_000}))["chan"].as_str().unwrap().to_string();
    let rec = rig.s.book.get(PROVIDER).unwrap();
    let cur = rec.params().unwrap();
    let next_origin = format!("{}/next", rec.origin);
    let k1 = hex::decode(rig.call("xbt402_new_key", json!({"origin": next_origin}))["pub"].as_str().unwrap()).unwrap();
    let next = ChannelParams::derive(&seller_pay_to(), &k1, (rig.chain.height() + 1_014) as u32, cur.close_fee, Some(hex::decode(rig.hot_spk()).unwrap()),
                                     &rig.chain.network(), cur.close_fee_payer).unwrap();
    let amount = rec.used_sats as u64;
    let next_cap = cur.rollover_next_capacity(amount);
    let sig = rig.call("xbt402_sign_rollover", json!({"chan": chan, "amount": amount, "next_spk": hex::encode(next.spk()), "next_capacity": next_cap,
                                                      "next": next.to_json()}));
    assert!(sig["sig"].is_string(), "{sig}");
    // the answer to the rollover never came; the client asks again
    let k2 = rig.call("xbt402_new_key", json!({"origin": next_origin}));
    assert!(k2["pub"].is_string(), "{k2}");
    // the provider broadcasts the rollover it was sent
    let body = json!({"chan": chan, "amount": amount, "sig": sig["sig"],
                      "next": {"payerPub": hex::encode(next.payer_pub), "expiry": next.expiry, "payerSpk": hex::encode(&next.payer_spk)}});
    let resp = rig.web.request("POST", &format!("{PROVIDER}{ROLLOVER_PATH}"), body.to_string().as_bytes(), &[("Content-Type".into(), "application/json".into())]).unwrap();
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    let reply: Value = serde_json::from_slice(&resp.body).unwrap();
    let real = next.with_funding(reply["txid"].as_str().unwrap(), 1, next_cap).unwrap();
    assert_eq!(rig.chain.unspent_to(&hex::encode(real.spk())), next_cap as i64, "the rollover is on chain and funds the next channel");
    let a = rig.call("xbt402_attach", json!({"origin": next_origin, "params": real.to_json()}));
    let refund = rig.call("xbt402_sign_refund", json!({"chan": real.channel_id()}));
    assert!(a["chan"] == real.channel_id() && refund["hex"].is_string(),
            "{next_cap} sat sit in a channel this signer's rollover signature funded, and the signer has wiped its payer key: attach {a}, refund {refund}");
}

// --- 2. one approval, two concurrent approve calls --------------------------------------------------------

const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/// The rig's node with a wallet: `sendtoaddress` with the memo `gate` waits until the gate opens
/// (the caller holds the signer's spend lock meanwhile); every send is noted as `(amount, memo)`.
struct GateNode {
    chain: Arc<FakeChain>,
    open: Mutex<bool>,
    cv: Condvar,
    waiting: AtomicBool,
    n: AtomicUsize,
    sends: Mutex<Vec<(String, String)>>,
}

impl Node for GateNode {
    fn call(&self, method: &str, p: Value) -> xbt402::Result<Value> {
        if method == "sendtoaddress" {
            let (amount, memo) = (p[1].as_str().unwrap_or("").to_string(), p[2].as_str().unwrap_or("").to_string());
            if memo == "gate" {
                self.waiting.store(true, Ordering::SeqCst);
                let mut g = self.open.lock().unwrap();
                while !*g {
                    g = self.cv.wait(g).unwrap();
                }
            }
            self.sends.lock().unwrap().push((amount, memo));
            return Ok(json!(format!("{:064x}", self.n.fetch_add(1, Ordering::SeqCst) + 1)));
        }
        self.chain.call(method, p)
    }
    fn set_allow_generate(&self, allow: bool) {
        self.chain.set_allow_generate(allow);
    }
    fn wallet(&self) -> String {
        self.chain.wallet()
    }
}

/// The human signs one approval for one 1,000 sat payment. The UI's request is sent twice (a
/// double click, or a retry after a timeout) while another payment holds the signer's spend lock,
/// which `xbt402_pay` can do for `open_wait_s`. One approval pays once.
///
/// Fails on f0554d0: `approve_signed` reads the token and its `used` flag before it takes the
/// spend lock (signer.rs:1567-1597), so both calls pass the check, and the second writes the hold
/// again and pays again: two payments of 1,000 sat, 2,100 sat booked.
#[test]
fn one_approval_pays_once_when_two_approve_calls_wait_on_the_spend_lock() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({"allowlist": [ADDR]}), false);
    let node = Arc::new(GateNode { chain: rig.chain.clone(), open: Mutex::new(false), cv: Condvar::new(), waiting: AtomicBool::new(false),
                                   n: AtomicUsize::new(0), sends: Mutex::new(vec![]) });
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(node.clone()), transport: Some(rig.web.clone()), ..Default::default() }).unwrap();
    let r = rig.call("pay", json!({"to": ADDR, "amount_sats": 1000, "memo": "big"}));
    assert_eq!(r["verdict"], "needs_human", "{r}");
    let (tok, exp) = (r["approval_token"].as_str().unwrap().to_string(), r["approval_expires"].as_i64().unwrap());
    let ok = json!({"token": tok, "dest": ADDR, "amount_sats": 1000, "expiry": exp,
                    "signature": sign_human(&xbt_signer::approval::canonical_message(&tok, ADDR, 1000, exp))});
    // another payment holds the spend lock
    let s = rig.s.clone();
    let holder = std::thread::spawn(move || s.handle("pay", &json!({"to": ADDR, "amount_sats": 100, "memo": "gate"})).map_err(|e| e.msg));
    while !node.waiting.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(10));
    }
    let approves: Vec<_> = (0..2).map(|_| {
        let (s, ok) = (rig.s.clone(), ok.clone());
        std::thread::spawn(move || s.handle("approve", &ok).map_err(|e| e.msg))
    }).collect();
    std::thread::sleep(Duration::from_millis(600)); // both are past the token check, waiting for the lock
    *node.open.lock().unwrap() = true;
    node.cv.notify_all();
    holder.join().unwrap().unwrap();
    let answers: Vec<_> = approves.into_iter().map(|t| t.join().unwrap()).collect();
    let big = node.sends.lock().unwrap().iter().filter(|(_, memo)| memo == "big").count();
    assert_eq!((big, ledger(&rig)), (1, 1_100), "one approval, {big} payments of 1,000 sat; answers: {answers:?}");
}

// --- 3. a stream whose n * price overflows ------------------------------------------------------------------

fn node_hash(a: &[u8], b: &[u8]) -> [u8; 32] {
    sha256(&[b"node".as_slice(), a, b].concat())
}

/// A Merkle tree over 16 chunks, as `session::verify_proof` reads it: `(root, proofs)`.
fn tree(chunks: &[Vec<u8>]) -> ([u8; 32], Vec<Vec<String>>) {
    let mut level: Vec<[u8; 32]> = chunks.iter().enumerate().map(|(i, c)| leaf(i as u32, c)).collect();
    let mut proofs = vec![vec![]; chunks.len()];
    let mut idx: Vec<usize> = (0..chunks.len()).collect();
    while level.len() > 1 {
        for (p, i) in proofs.iter_mut().zip(idx.iter_mut()) {
            p.push(hex::encode(level[*i ^ 1]));
            *i /= 2;
        }
        level = level.chunks(2).map(|c| node_hash(&c[0], &c[1])).collect();
    }
    (level[0], proofs)
}

/// The owner allows 2,000 sat for this call, 6,000 sat a day. The seller's signed manifest says
/// `n` = 2^54 chunks at 1,024 sat: 2^64 sat, which is 0 in a 64-bit product. The stream must be
/// refused (it costs more than `max_sats` leaves) with nothing more signed.
///
/// Fails on f0554d0. In a debug build `n * price` (session.rs:691) panics on overflow inside the
/// signer. In a release build (no overflow checks: Cargo.toml `[profile.release]`) the product
/// wraps to 0, the check passes, and the wallet signs and books one chunk after another until the
/// channel's cap stops it: 8,792 sat signed on a 2,000 sat call, past the daily budget of 6,000.
#[test]
fn a_stream_whose_cost_overflows_is_refused_not_bought_to_the_channel_cap() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({"max_per_tx_sats": 5000, "human_threshold_sats": 5000}), false);
    rig.fund_hot(1, 12_000);
    let chunks: Vec<Vec<u8>> = (0..16u8).map(|i| vec![i; 8]).collect();
    let (root, proofs) = tree(&chunks);
    let (n, price): (i64, i64) = (1 << 54, 1_024);
    let mut m = json!({"id": "s1", "n": n, "size": 128, "root": hex::encode(root), "lock": "00".repeat(32), "finalCt": "00".repeat(32),
                       "price": price, "payTo": hex::encode(seller_pay_to()), "lastProof": []});
    m["sig"] = hex::encode(ecdsa::sign(&secret("provider payTo"), &manifest_message(&m))).into();
    provider_with(&rig, json!({"stream": "xbt402-merkle-v1", "manifest": m, "chunkUrl": "/chunk/{i}"}), 10_000, 600);
    hooked(&mut rig, Box::new(move |_, url, _, _| {
        let i: usize = url.rsplit_once("/chunk/")?.1.parse().ok()?;
        let c = json!({"i": i, "data": hex::encode(chunks.get(i)?), "proof": proofs[i]});
        Some(Ok(HttpResponse::new(200, vec![], c.to_string().into_bytes())))
    }));
    let call = || rig.s.handle("xbt402_pay", &json!({"url": URL, "method": "GET", "body": "", "max_sats": 2_000}));
    assert_eq!(call().unwrap()["verdict"], "pending");
    rig.chain.mine(1);
    let s = rig.s.clone();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || s.handle("xbt402_pay", &json!({"url": URL, "method": "GET", "body": "", "max_sats": 2_000}))));
    let used = rig.s.book.get(PROVIDER).map(|r| r.used_sats).unwrap_or(0);
    let outcome = match &r {
        Ok(Ok(v)) => format!("answered {}", v["stream"]),
        Ok(Err(e)) => format!("error {}", e.msg),
        Err(_) => "the signer panicked (arithmetic overflow at session.rs:691)".to_string(),
    };
    assert!(r.is_ok() && used <= 2_000 && ledger(&rig) <= 2_000,
            "max_sats 2,000, daily budget 6,000: the channel has {used} sat signed and the ledger holds {}; {outcome}", ledger(&rig));
}

// --- 4. the seller's expiry window ------------------------------------------------------------------------------

/// The owner's policy says `channel_expiry_blocks` 1,008. For a channel an external client funds,
/// the signer holds the expiry to `max(channel_expiry_blocks, 4032)` blocks (signer.rs:170, 1101-1107).
/// The signer's own `xbt402_pay` must hold a seller's offer to the same bound: a seller that asks
/// for `minExpiryBlocks` 500,000 and answers the preflight "yes" gets the wallet's per-channel cap
/// locked for about nine and a half years if it then never opens or closes the channel.
///
/// Fails on f0554d0: `open_from_offer` takes `minExpiryBlocks`, `minConf` and `closeMarginBlocks`
/// from the offer with no upper bound (session.rs:256-272), and funds.
#[test]
fn a_sellers_min_expiry_does_not_lock_the_channel_past_the_owners_bound() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    let web = rig.web.clone();
    hooked(&mut rig, Box::new(move |method, url, body, headers| {
        if url == URL && !has_sig(headers) {
            let r = web.request(method, url, body, headers).unwrap();
            let mut pr = unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap();
            pr["accepts"][0]["extra"]["minExpiryBlocks"] = 500_000.into();
            pr["accepts"][0]["extra"]["maxExpiryBlocks"] = 1_000_000.into();
            return Some(Ok(HttpResponse::new(402, vec![("PAYMENT-REQUIRED".into(), b64json(&pr))], b"".to_vec())));
        }
        if url.ends_with(OPEN_PATH) && String::from_utf8_lossy(body).contains("\"preflight\"") {
            return Some(Ok(HttpResponse::new(200, vec![], json!({"preflight": true}).to_string().into_bytes())));
        }
        None
    }));
    let before = rig.hot_sats();
    let r = rig.pay();
    let locked = rig.s.book.get(PROVIDER).map(|c| (c.funding_sats, c.expiry - rig.chain.height() as i64));
    assert!(locked.is_none_or(|(_, blocks)| blocks <= 4_032),
            "the wallet funded {:?} (sat, blocks to expiry) on the seller's word; hot balance {before} -> {}; answer: {}",
            locked, rig.hot_sats(), r["verdict"]);
}

// --- 5. a kept funding that can never confirm ----------------------------------------------------------------------

/// The funding broadcast times out and so does the lookup after it (the record is kept, AGP-085).
/// The transaction never reached the node, and from then on the node refuses it (its inputs were
/// spent elsewhere after a `hot_reconcile`).
///
/// AGP-089 fixed this double, not what the test asserts: it refused the funding as
/// `bad-txns-inputs-missingorspent` while still answering `gettxout` for those inputs as unspent,
/// which no node does. It now does what its own description says: once the funding is lost, a
/// transaction in a block has spent the funding's inputs (`conflict`).
struct LostNode {
    chain: Arc<FakeChain>,
    /// 0: nothing sent yet; 1: the send timed out, the lookup is next; 2: afterwards.
    step: AtomicUsize,
}

impl LostNode {
    /// Another transaction spends every input of `raw`, in the block at the tip.
    fn conflict(&self, raw: &str) {
        let tx = xbt_primitives::tx::Tx::parse_hex(raw).unwrap();
        let mut s = self.chain.st.lock().unwrap();
        let (h, other) = (s.height, "ee".repeat(32));
        let vin: Vec<Value> = tx.inputs.iter().map(|i| json!({"txid": i.prevout.txid_hex(), "vout": i.prevout.vout})).collect();
        for i in &tx.inputs {
            let op = (i.prevout.txid_hex(), i.prevout.vout);
            s.utxos.remove(&op);
            s.spent_by.insert(op, other.clone());
        }
        s.conf_height.insert(other.clone(), h);
        s.blocks.entry(h).or_default().push(json!({"txid": other, "vin": vin, "vout": []}));
    }
}

impl Node for LostNode {
    fn call(&self, method: &str, p: Value) -> xbt402::Result<Value> {
        let timeout = || Err(xbt402::ChannelError::new("rpc_error", "timed out reading response"));
        match (method, self.step.load(Ordering::SeqCst)) {
            ("sendrawtransaction", 0) => {
                self.step.store(1, Ordering::SeqCst);
                self.conflict(p[0].as_str().unwrap_or(""));
                timeout()
            }
            ("gettxout", 1) => {
                self.step.store(2, Ordering::SeqCst);
                timeout()
            }
            ("sendrawtransaction", _) => Err(xbt402::ChannelError::new("rpc_refused", r#"{"code":-25,"message":"bad-txns-inputs-missingorspent"}"#)),
            _ => self.chain.call(method, p),
        }
    }
    fn set_allow_generate(&self, allow: bool) {
        self.chain.set_allow_generate(allow);
    }
    fn wallet(&self) -> String {
        self.chain.wallet()
    }
}

/// AGP-085 stated limit 2: "A kept funding that can never confirm blocks its destination until
/// the refund answers at expiry." At expiry the destination must be free again.
///
/// Fails on f0554d0: the refund answers `funding_unknown` and changes nothing (signer.rs:688), so
/// the record stays pending and every later payment to that origin is `pending`, with no end and
/// no socket method that removes it.
#[test]
fn a_kept_funding_that_never_confirms_frees_its_destination_at_expiry() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({}), false);
    rig.fund_hot(1, 12_000);
    let node = Arc::new(LostNode { chain: rig.chain.clone(), step: AtomicUsize::new(0) });
    rig.s = Signer::new(&rig.root, SignerOptions { node: Some(node), transport: Some(rig.web.clone()), ..Default::default() }).unwrap();
    let r = rig.pay();
    assert_eq!(r["verdict"], "deny", "{r}");
    let rec = rig.s.book.get(PROVIDER).expect("the funding of unknown fate is kept");
    assert_eq!(rec.state, "pending");
    rig.chain.mine_to(rec.expiry as u64 + 1);
    let acts = rig.s.watch_tick();
    let state = rig.s.book.get(PROVIDER).map(|r| r.state);
    let again = rig.pay();
    assert!(state.as_deref() != Some("pending"),
            "past expiry the record is still {state:?} and the next payment answers {} / {}; watcher: {acts:?}", again["verdict"], again["rule"]);
}

// --- 6. attach of a rollover's next channel takes the key before the steps that can refuse -----------------------

/// A seller holds a signed rollover (it answered the request with an error), answers the close
/// that follows with 200 and broadcasts nothing, then broadcasts the rollover. The wallet's record
/// is "closed, not proven" at that moment. The attach of the next channel is refused
/// `close_unproven` until the watcher has seen the spend; after that it must succeed.
///
/// Fails on f0554d0: `attach` calls `take_issued` (signer.rs:1414) before `add_funded`, which
/// refuses an unproven close (channels.rs:704). The key is already out of the keys file and is
/// dropped with the refusal, so the retry is `bad_key` and no refund can be signed.
#[test]
fn an_attach_refused_for_an_unproven_close_keeps_the_next_channels_key() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({"max_per_tx_sats": 5000, "human_threshold_sats": 5000, "hot_balance_cap_sats": 100_000}), false);
    provider_with(&rig, json!({"ok": true}), 5_000, 600);
    rig.fund_hot(1, 12_000);
    assert_eq!(rig.call("xbt402_pay", json!({"url": URL, "max_sats": 1_000}))["verdict"], "pending");
    rig.chain.mine(1);
    let chan = rig.call("xbt402_pay", json!({"url": URL, "max_sats": 1_000}))["chan"].as_str().unwrap().to_string();
    let rec = rig.s.book.get(PROVIDER).unwrap();
    let cur = rec.params().unwrap();
    let next_origin = format!("{}/next", rec.origin);
    let k1 = hex::decode(rig.call("xbt402_new_key", json!({"origin": next_origin}))["pub"].as_str().unwrap()).unwrap();
    let next = ChannelParams::derive(&seller_pay_to(), &k1, (rig.chain.height() + 1_014) as u32, cur.close_fee, Some(hex::decode(rig.hot_spk()).unwrap()),
                                     &rig.chain.network(), cur.close_fee_payer).unwrap();
    let amount = rec.used_sats as u64;
    let next_cap = cur.rollover_next_capacity(amount);
    let sig = rig.call("xbt402_sign_rollover", json!({"chan": chan, "amount": amount, "next_spk": hex::encode(next.spk()), "next_capacity": next_cap,
                                                      "next": next.to_json()}));
    assert!(sig["sig"].is_string(), "{sig}");
    hooked(&mut rig, Box::new(|_, url, _, _| {
        url.ends_with(xbt402::wire::CLOSE_PATH).then(|| Ok(HttpResponse::new(200, vec![], json!({"txid": "cd".repeat(32), "cum": "600", "unpaidMsat": "0"}).to_string().into_bytes())))
    }));
    let c = rig.call("close_channel", json!({"counterparty": PROVIDER}));
    assert_eq!((c["verdict"].as_str(), c["close_proven"].as_bool()), (Some("allow"), Some(false)), "{c}");
    let body = json!({"chan": chan, "amount": amount, "sig": sig["sig"],
                      "next": {"payerPub": hex::encode(next.payer_pub), "expiry": next.expiry, "payerSpk": hex::encode(&next.payer_spk)}});
    let resp = rig.web.request("POST", &format!("{PROVIDER}{ROLLOVER_PATH}"), body.to_string().as_bytes(), &[("Content-Type".into(), "application/json".into())]).unwrap();
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    let reply: Value = serde_json::from_slice(&resp.body).unwrap();
    let real = next.with_funding(reply["txid"].as_str().unwrap(), 1, next_cap).unwrap();
    let first = rig.call("xbt402_attach", json!({"origin": next_origin, "params": real.to_json()}));
    rig.s.watch_tick(); // the watcher sees the funding spent: the close is proven
    let second = rig.call("xbt402_attach", json!({"origin": next_origin, "params": real.to_json()}));
    assert_eq!(second["chan"], real.channel_id(),
               "{next_cap} sat are in the next channel; the first attach answered {} and dropped its key, the retry answers {second}", first["rule"]);
}
