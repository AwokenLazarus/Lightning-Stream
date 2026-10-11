//! AGP-102 fourth closure audit, CLIENT area (the channel library client and its transport): tests
//! written by the auditor against fix wave 5 (AGP-096, AGP-101). No fix is in this file.
//!
//! `hole_*` tests fail today and state the rule that should hold. `control_*` tests are the honest
//! path in the same rig and `limit_*` tests pin a number a reader must be told; both pass.
//! The socket tests need `--features http-client,http-server` and bind 127.0.0.1:27750-27759.
//!
//!   CARGO_TARGET_DIR=$PWD/target cargo test --offline -p xbt402 --test agp102_client \
//!       --features http-client,http-server -- --nocapture

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use xbt402::client::{split_url, Client, ClientConfig, FileClientLedger, Stage, Transport, Wallet, WalletSend};
use xbt402::funding::{ChainBackend, UtxoInfo};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::wire::{b64json, unb64json};
use xbt402::{ChannelError, Result};
use xbt_primitives::address::address_to_spk;
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

const NET: &str = "bip122:11111111111111111111111111111111";
const O: &str = "https://api.example";
const PRICE: u64 = 150;

// --- the rig of agp096_client.rs -----------------------------------------------------------------

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

/// A wallet that cannot list its sends (the trait's default), whose `fund` can refuse, or send and
/// then error (a timeout after the broadcast).
#[derive(Default)]
struct TestWallet {
    chain: Arc<MemChain>,
    /// (txid, address, sats) of every send.
    sends: Mutex<Vec<(String, String, u64)>>,
    refuses: AtomicBool,
    errors_after_send: AtomicBool,
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
        if self.0.errors_after_send.load(Ordering::SeqCst) {
            return Err(ChannelError::new("wallet_error", "timed out after the broadcast"));
        }
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

fn paid(path: &str, h: &[(String, String)]) -> bool {
    path.starts_with("/v1/") && h.iter().any(|(k, _)| k == "PAYMENT-SIGNATURE")
}

struct World {
    chain: Arc<MemChain>,
    wallet: Arc<TestWallet>,
    prov: Arc<Provider>,
    dir: PathBuf,
}

fn provider(chain: &Arc<MemChain>, key: &[u8]) -> Arc<Provider> {
    let cfg = ProviderConfig::new(NET);
    let k = Mutex::new(0u64);
    let handler = move |m: &str, p: &str, _: &[u8]| {
        let mut k = k.lock().unwrap();
        *k += 1;
        HttpResponse::new(200, vec![], json!({"m": m, "answer": p, "n": *k}).to_string().into_bytes())
    };
    Arc::new(Provider::new(chain.clone(), SecretKey::from_slice(&sha256(key)).unwrap(), cfg, Ledger::in_memory(), Box::new(|_, _| PRICE), Box::new(handler)).unwrap())
}

fn world(name: &str) -> World {
    let dir = std::env::temp_dir().join(format!("xbt-rs-agp102-client-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let chain = Arc::new(MemChain::default());
    *chain.tip.lock().unwrap() = 1_000;
    let prov = provider(&chain, b"provider payTo");
    World { wallet: Arc::new(TestWallet { chain: chain.clone(), ..TestWallet::default() }), prov, chain, dir }
}

impl World {
    fn bare_client(&self, f: Rewrite) -> Client {
        let c = self.chain.clone();
        Client::new(ClientConfig::new(NET), Box::new(Edit(self.prov.clone(), f)), Box::new(Shared(self.wallet.clone())), Box::new(move || c.block_count()))
    }

    fn funded(&self) -> usize {
        self.wallet.sends.lock().unwrap().len()
    }

    fn mine(&self, n: u32) {
        *self.chain.tip.lock().unwrap() += n;
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

// --- Part A item 18, Part C: the forged refusal, and what "closes it and opens another" means ------

/// The seller of `limit_two_forged_refusals_end_the_channel`: the provider serves and charges, and
/// the payer is shown a bare 402, `forge` times.
fn forger(forge: Arc<AtomicUsize>) -> Rewrite {
    let last_402: Mutex<Option<String>> = Mutex::new(None);
    Box::new(move |path, _, h, r| {
        if r.status == 402 {
            *last_402.lock().unwrap() = r.header("PAYMENT-REQUIRED").map(str::to_string);
        }
        if paid(path, h) && r.status == 200 && forge.load(Ordering::SeqCst) > 0 {
            forge.fetch_sub(1, Ordering::SeqCst);
            let mut pr = unb64json(&last_402.lock().unwrap().clone().unwrap()).unwrap();
            pr.as_object_mut().unwrap().remove("channel");
            return Ok(HttpResponse::new(402, vec![("PAYMENT-REQUIRED".into(), b64json(&pr))], vec![]));
        }
        Ok(r)
    })
}

/// HOLE (Low, a public sentence that is not true of the library; left from before, the sentence is
/// new in wave 5). AGP-101's sentence for the summary says that at the second forged refusal the
/// payer "closes the channel at what it signed and opens another". The library does neither by
/// itself: every call is `bad_offer` until the embedder calls `close`, and `close` leaves the
/// closed channel on the book as `Stage::Open`, so after it every call is still refused: nothing
/// "opens another" until the embedder also removes the record (`xbt-wallet-mcp`'s close tool does;
/// `Client::close` does not, and no document says the embedder must).
#[test]
fn hole_after_the_close_that_follows_two_forged_refusals_the_next_call_opens_a_new_channel() {
    let w = world("forged-close-next");
    let forge = Arc::new(AtomicUsize::new(0));
    let mut c = w.bare_client(forger(forge.clone()));
    paid_calls(&mut c, 4);
    let chan = c.channels[O].payer.params.channel_id();
    forge.store(1, Ordering::SeqCst);
    assert_eq!((get(&mut c), get(&mut c)), (Ok(402), Ok(200)));
    paid_calls(&mut c, 2);
    forge.store(1, Ordering::SeqCst);
    assert_eq!((get(&mut c), get(&mut c)), (Ok(402), Err("bad_offer".into())));
    // control: the payer did not close anything by itself
    assert_eq!(w.prov.channel_state(&chan).map(|s| s.closed_txid), Some(String::new()), "control: the channel is still open at the provider; the client closed nothing");
    c.close(O).expect("the embedder's close");
    let after: Vec<_> = (0..3).map(|_| get(&mut c)).collect();
    let now = c.channels.get(O).map(|ch| (ch.payer.params.channel_id(), ch.stage));
    assert!(after.contains(&Ok(200)), "after the close every call is still refused: {after:?}; the book still holds {now:?} (the closed channel was {chan}), \
                                       and {} channel(s) were funded", w.funded());
}

/// CONTROL for the hole above: with the closed record removed by the embedder (what
/// `xbt-wallet-mcp`'s close tool does) the next call funds and opens a new channel.
#[test]
fn control_after_the_close_and_the_embedder_removing_the_record_the_next_call_opens_a_new_channel() {
    let w = world("forged-close-removed");
    let forge = Arc::new(AtomicUsize::new(0));
    let mut c = w.bare_client(forger(forge.clone()));
    paid_calls(&mut c, 4);
    forge.store(1, Ordering::SeqCst);
    assert_eq!((get(&mut c), get(&mut c)), (Ok(402), Ok(200)));
    paid_calls(&mut c, 2);
    forge.store(1, Ordering::SeqCst);
    assert_eq!((get(&mut c), get(&mut c)), (Ok(402), Err("bad_offer".into())));
    c.close(O).unwrap();
    c.channels.remove(O);
    assert_eq!((get(&mut c), w.funded()), (Ok(200), 2));
}

/// The provider serves the request and the payer's process stops before the answer is handled.
struct Faulty {
    prov: Arc<Provider>,
    crash: Arc<AtomicBool>,
    forge: Rewrite,
}

impl Transport for Faulty {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        let (_, path) = split_url(url);
        let r = self.prov.serve(method, &path, headers, body, url, None);
        if paid(&path, headers) && self.crash.load(Ordering::SeqCst) {
            assert_eq!(r.status, 200, "the provider served the call");
            panic!("the payer's process stops here: the request left, its answer is never handled");
        }
        (self.forge)(&path, &Value::Null, headers, r)
    }
}

/// CONTROL (question d). The request-saved-before-it-leaves rule against the slack: a crash after
/// a request left costs none of the channel's one call of slack, in any order with one forged
/// refusal: refusal then two crashes, and two crashes then a refusal. Only a second forged refusal
/// ends the channel (the limit).
#[test]
fn control_crashes_cost_no_slack_before_or_after_one_forged_refusal() {
    for refusal_first in [true, false] {
        let w = world(&format!("crash-forge-{refusal_first}"));
        let (crash, forge) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicUsize::new(0)));
        let make = |w: &World| {
            let ch = w.chain.clone();
            let t = Faulty { prov: w.prov.clone(), crash: crash.clone(), forge: forger(forge.clone()) };
            Client::new(ClientConfig::new(NET), Box::new(t), Box::new(Shared(w.wallet.clone())), Box::new(move || ch.block_count()))
                .with_ledger(Box::new(FileClientLedger::open(&w.dir.join("c.jsonl")).unwrap())).unwrap()
        };
        let mut c = make(&w);
        paid_calls(&mut c, 3);
        let refuse = |c: &mut Client| {
            forge.store(1, Ordering::SeqCst);
            assert_eq!((get(c), get(c)), (Ok(402), Ok(200)), "one forged refusal: that call fails, the next adopts the hidden charge on the slack");
        };
        if refusal_first {
            refuse(&mut c);
        }
        for n in 0..2 {
            crash.store(true, Ordering::SeqCst);
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| get(&mut c))).is_err());
            crash.store(false, Ordering::SeqCst);
            drop(c);
            c = make(&w);
            let out: Vec<_> = (0..3).map(|_| get(&mut c)).collect();
            assert_eq!(out, vec![Ok(200); 3], "refusal first {refusal_first}, crash {n}");
        }
        if !refusal_first {
            refuse(&mut c);
        }
        paid_calls(&mut c, 2);
        let chan = c.channels[O].payer.params.channel_id();
        let (ch, served) = (&c.channels[O], w.prov.channel_state(&chan).unwrap().spent_msat);
        assert_eq!((ch.slack_msat, ch.spent_msat), (PRICE * 1000, served), "one call of slack used, by the refusal alone; books agree");
    }
}

// --- Part B: `unfunded`, `fund_tried`, the budget at funding, with a wallet that cannot list -----

/// LIMIT (AGP-096 stated limit 4 and AGP-101 found-not-fixed 1, measured in Rust; the result
/// names it for B1 only and words it as "may fund two scripts"). With a wallet whose `fund` errors
/// after it sent and that cannot list its sends (the `Wallet` trait's default), every retry inside
/// the 72-block window pays the SAME script again, and the budget counts none of it: the client
/// adds a channel to `opened_sats` only when a `fund` call answers. Six such calls send 1,200,000
/// sat under a budget of 1,000,000 and the book says 0. The seller cannot cause it; the owner's own
/// wallet does. Neither shipped wallet is such a wallet (`Rpc` lists its sends, `xbt-signer`
/// refuses a second funding).
#[test]
fn limit_a_wallet_that_errors_after_it_sent_and_cannot_list_pays_one_script_on_every_retry_past_the_budget() {
    let w = world("bare-wallet");
    let mut c = w.bare_client(honest());
    assert_eq!(c.cfg.budget_sats, 1_000_000);
    w.wallet.errors_after_send.store(true, Ordering::SeqCst);
    for _ in 0..6 {
        assert_eq!(get(&mut c), Err("wallet_error".into()));
        w.mine(10);
    }
    let sends = w.wallet.sends.lock().unwrap().clone();
    let scripts: std::collections::HashSet<_> = sends.iter().map(|s| s.1.clone()).collect();
    let total: u64 = sends.iter().map(|s| s.2).sum();
    assert_eq!((sends.len(), scripts.len(), total, c.opened_sats), (6, 1, 1_200_000, 0), "six sends to one script, none of them in the budget's count");
    assert_eq!((c.channels[O].stage, c.channels[O].refund_hex.is_empty()), (Stage::Keyed, true), "and no refund is held for any of them");
    // the seventh call answers: the client now holds the refund of that one output only
    w.wallet.errors_after_send.store(false, Ordering::SeqCst);
    assert_eq!(get(&mut c), Ok(200));
    assert_eq!((w.funded(), c.opened_sats), (7, 200_000));
    let refund = Tx::parse_hex(&c.channels[O].refund_hex).unwrap();
    assert_eq!((refund.inputs.len(), refund.inputs[0].prevout.txid_hex()), (1, w.wallet.sends.lock().unwrap()[6].0.clone()));
}

/// LIMIT (question e: a seller plus an ordinary wallet failure). The same wallet, and a seller that
/// changes its offer between the failed `fund` and the retry: the first script is set aside (its
/// terms are kept in `unfunded`, its key is the next channel's) and the call after funds a second
/// script. Two scripts hold 400,000 sat, the client holds a refund for one, `on_refund` was never
/// called for the other, and the budget counts one.
#[test]
fn limit_a_seller_that_changes_its_offer_after_a_fund_that_failed_after_it_sent_gets_two_scripts_funded() {
    let w = world("two-scripts");
    let fee = Arc::new(AtomicUsize::new(0));
    let f2 = fee.clone();
    let mut c = w.bare_client(offers(move |acc| {
        if f2.load(Ordering::SeqCst) > 0 {
            acc["amount"] = json!((PRICE + 1).to_string());
        }
    }));
    let refunds = Arc::new(AtomicUsize::new(0));
    let r2 = refunds.clone();
    c.on_refund = Some(Box::new(move |_, _| { r2.fetch_add(1, Ordering::SeqCst); }));
    w.wallet.errors_after_send.store(true, Ordering::SeqCst);
    assert_eq!(get(&mut c), Err("wallet_error".into()));
    w.wallet.errors_after_send.store(false, Ordering::SeqCst);
    w.mine(100); // past the retry floor: the channel is derived again with a new expiry
    fee.store(1, Ordering::SeqCst);
    let out: Vec<_> = (0..2).map(|_| get(&mut c)).collect();
    let sends = w.wallet.sends.lock().unwrap().clone();
    assert_eq!(sends.len(), 2, "{out:?}");
    assert_ne!(sends[0].1, sends[1].1, "two different scripts");
    let kept = &c.unfunded[O];
    assert_eq!((kept.len(), kept[0].payer.params.payer_pub == c.channels[O].payer.params.payer_pub), (1, true), "the first script's terms are kept and it pays the same key");
    assert_eq!((c.opened_sats, refunds.load(Ordering::SeqCst)), (200_000, 1), "400,000 sat left the wallet; the budget counts 200,000 and one refund was handed out");
}

// --- Part A item 18 (origin), question c: what `canonical_origin` unifies -------------------------

/// What the book's key unifies and what it does not, from `wire::canonical_origin` alone (the real
/// transport's reading of the same strings is in `sockets` below).
#[test]
fn limit_what_the_canonical_origin_unifies() {
    let one = |u: &str| split_url(u).0;
    // unified: scheme and host case, the default port, leading zeros of a port, an empty port, userinfo
    for u in ["https://api.example/x", "HTTPS://API.Example/x", "https://api.example:443/x", "https://api.example:0443/x", "https://api.example:/x",
              "https://u:p@api.example/x", "https://api.example?x"] {
        assert_eq!(one(u), "https://api.example", "{u}");
    }
    // not unified (each is its own key, so its own channel): a trailing dot, percent-encoding, the
    // number forms of an IPv4 address, the forms of an IPv6 address, an IDN and its punycode
    let apart = [("https://api.example./x", "https://api.example."), ("https://%61pi.example/x", "https://%61pi.example"),
                 ("http://127.1/x", "http://127.1"), ("http://2130706433/x", "http://2130706433"), ("http://0x7f.0.0.1/x", "http://0x7f.0.0.1"),
                 ("http://[0:0:0:0:0:0:0:1]/x", "http://[0:0:0:0:0:0:0:1]"), ("http://[::1]/x", "http://[::1]")];
    for (u, key) in apart {
        assert_eq!(one(u), key, "{u}");
    }
    // a different port, scheme or host is never the same key
    assert_ne!(one("https://api.example:8443/x"), one("https://api.example/x"));
    assert_ne!(one("http://api.example/x"), one("https://api.example/x"));
}

#[cfg(all(feature = "http-client", feature = "http-server"))]
mod sockets {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    use xbt402::http::{serve_http, UreqTransport};
    use xbt402::wire::OPEN_PATH;

    use super::*;

    /// A real provider on 127.0.0.1:`port` and a payer that reaches it with the shipped transport.
    fn http_world(name: &str, port: u16) -> World {
        let w = world(name);
        serve_http(w.prov.clone(), &format!("127.0.0.1:{port}"), 4).unwrap();
        w
    }

    fn ureq_client(w: &World, t: Box<dyn Transport>) -> Client {
        let c = w.chain.clone();
        Client::new(ClientConfig::new(NET), t, Box::new(Shared(w.wallet.clone())), Box::new(move || c.block_count()))
    }

    /// Another host: it records the head of every request it is sent and answers 503.
    fn other_host(port: u16) -> Arc<Mutex<Vec<String>>> {
        let l = TcpListener::bind(("127.0.0.1", port)).unwrap();
        let heads = Arc::new(Mutex::new(vec![]));
        let h2 = heads.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let (mut head, mut b) = (Vec::new(), [0u8; 1]);
                while !head.ends_with(b"\r\n\r\n") {
                    match s.read(&mut b) {
                        Ok(1) => head.push(b[0]),
                        _ => break,
                    }
                }
                h2.lock().unwrap().push(String::from_utf8_lossy(&head).to_string());
                let _ = s.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
        });
        heads
    }

    fn header_of(head: &str, name: &str) -> Option<String> {
        head.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string()))
    }

    /// HOLE (Medium, new in wave 5). The book's key, the request binding and every caller of
    /// `split_url` read the host of `http://A\@B/x` as B (`wire::request_url` ends the authority
    /// at `/` or `?` and keeps what follows the last `@`). The shipped transport (ureq, through the
    /// `url` crate) reads it as the WHATWG rule does: a backslash ends the authority of an http(s)
    /// URL, so the request goes to A with the path `/@B/x`. Before AGP-096 the book was keyed by
    /// the URL's own spelling, so such a URL had a book entry (and, in `xbt-wallet-mcp`, an
    /// allowlist verdict) of its own. Now it is B's: a paid request for B's open channel, with
    /// B's PAYMENT-SIGNATURE, is sent to A, and `xbt-wallet-mcp`'s allowlist check
    /// (`wallet.rs:308-316`, on `split_url`'s origin) passes for an allowlisted B while the unpaid
    /// probe and the paid request go to A.
    ///
    /// What A can do with it is run below: it replays the header to B once and is served B's paid
    /// answer at the payer's cost. A is also "whoever sits between a payer and a provider" of the
    /// forged-refusal limit, without being on the network path.
    #[test]
    fn hole_a_paid_request_is_sent_only_to_the_host_its_origin_names() {
        let (a, b) = (27_750u16, 27_751u16);
        let w = http_world("backslash", b);
        let good = format!("http://127.0.0.1:{b}");
        let mut c = ureq_client(&w, Box::new(UreqTransport::default()));
        for _ in 0..2 {
            assert_eq!(c.request("GET", &format!("{good}/v1/q"), b"").map(|r| r.status).map_err(|e| e.code), Ok(200));
        }
        let chan = c.channels[&good].payer.params.channel_id();
        let heads = other_host(a);
        // control: userinfo, as the request binding has always read it, reaches the seller
        assert_eq!(c.request("GET", &format!("http://u@127.0.0.1:{b}/v1/q"), b"").map(|r| r.status).map_err(|e| e.code), Ok(200));
        assert_eq!((heads.lock().unwrap().len(), c.channels.len()), (0, 1), "control");

        let url = format!("http://127.0.0.1:{a}\\@127.0.0.1:{b}/v1/q");
        assert_eq!(split_url(&url), (good.clone(), "/v1/q".to_string()), "the book, the binding and an allowlist on split_url read host B");
        let before = w.prov.channel_state(&chan).unwrap().spent_msat;
        let out = c.request("GET", &url, b"").map(|r| r.status).map_err(|e| format!("{}: {}", e.code, e.msg));
        let seen = heads.lock().unwrap().clone();
        let leaked = seen.iter().find_map(|h| header_of(h, "PAYMENT-SIGNATURE"));
        // what host A can do with what it was sent: replay it to B and be served, at the payer's cost
        let mut replay = None;
        if let Some(sig) = &leaked {
            let r = UreqTransport::default().request("GET", &format!("{good}/v1/q"), b"", &[("PAYMENT-SIGNATURE".into(), sig.clone())]).unwrap();
            replay = Some((r.status, r.header("PAYMENT-RESPONSE").is_some(), w.prov.channel_state(&chan).unwrap().spent_msat - before));
        }
        assert!(seen.is_empty(), "the client answered {out:?}; host A (port {a}) was sent {} request(s), first line {:?}, with B's PAYMENT-SIGNATURE: {}; \
                                  replayed to B by A: (status, receipt, msat charged to the payer) = {replay:?}; the payer's book: unanswered {} msat",
                seen.len(), seen[0].lines().next().unwrap_or(""), leaked.is_some(), c.channels[&good].unanswered_msat);
    }

    /// The seller of the audit's `hole_a_refusing_seller_is_funded_once_however_its_origin_is_spelled`,
    /// on the shipped transport: yes to the preflight, no to every funded open.
    struct Refusing(UreqTransport);

    impl Transport for Refusing {
        fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
            let req: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
            if split_url(url).1 == OPEN_PATH && req.get("preflight") != Some(&Value::Bool(true)) {
                return Ok(HttpResponse::new(400, vec![], json!({"error": "bad_funding", "detail": "no"}).to_string().into_bytes()));
            }
            self.0.request(method, url, body, headers)
        }
    }

    /// HOLE (Low, left from before; AGP-096 fixed it for the five spellings the audit named). "One
    /// seller is one origin, however a caller spells it" holds for case, the default port and
    /// userinfo. The shipped transport reaches the same server through other spellings of its
    /// host that the book keys apart: the number forms of an IPv4 address, percent-encoding, and
    /// (for a name) a trailing dot. A seller that refuses every funded open and gets its URLs
    /// called in those spellings (links in its own answers, which an agent follows) is still funded
    /// once per spelling, up to `budget_sats`. A payer behind a signer with an allowlist is not
    /// affected: each spelling needs its own allowlist entry.
    #[test]
    fn hole_a_refusing_seller_is_funded_once_however_its_host_is_spelled() {
        let port = 27_752u16;
        let w = http_world("host-spellings", port);
        let mut c = ureq_client(&w, Box::new(Refusing(UreqTransport::default())));
        let spellings = [format!("http://127.0.0.1:{port}"), format!("http://127.1:{port}"), format!("http://2130706433:{port}"), format!("http://0x7f.0.0.1:{port}"),
                         format!("http://%31%32%37.0.0.1:{port}")];
        let mut reached = vec![];
        for o in &spellings {
            let r = c.request("GET", &format!("{o}/v1/q"), b"").map(|r| r.status).map_err(|e| e.code);
            // `bad_funding` is the seller's own refusal of a funded open: the spelling reached it
            if r == Err("bad_funding".into()) {
                reached.push(o.clone());
            }
        }
        assert!(reached.len() >= 2, "control: at least two spellings reach the one server: {reached:?}");
        assert_eq!(w.funded(), 1, "one seller (one listener on port {port}), {} channels funded, {} sat locked until expiry, under the keys {:?}",
                   w.funded(), c.opened_sats, c.channels.keys().collect::<Vec<_>>());
    }
}
