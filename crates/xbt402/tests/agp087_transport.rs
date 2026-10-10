//! AGP-087 second closure audit, transport area (T2-T4): tests written by the auditor. A failing
//! test here is a finding, not a regression.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use xbt402::client::{split_url, Client, ClientConfig, Transport, Wallet};
use xbt402::funding::{ChainBackend, UtxoInfo};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::wire::*;
use xbt402::{ChannelError, Result};
use xbt_primitives::address::address_to_spk;
use xbt_primitives::hash::sha256;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

const NET: &str = "bip122:11111111111111111111111111111111";
#[derive(Default)]
struct MemChain {
    tip: Mutex<u32>,
    utxos: Mutex<HashMap<(String, u32), UtxoInfo>>,
    sent: Mutex<Vec<Tx>>,
    n: Mutex<u64>,
    /// AGP-084: the node answers a broadcast with an error and does not have the tx.
    down: Mutex<bool>,
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
        if *self.down.lock().unwrap() {
            return Err(ChannelError::new("rpc_error", "timed out"));
        }
        let tx = Tx::parse_hex(hex)?;
        let mut u = self.utxos.lock().unwrap();
        for i in &tx.inputs {
            if u.remove(&(i.prevout.txid_hex(), i.prevout.vout)).is_none() && !tx.inputs.is_empty() && i.prevout.vout < 1000 {
                // spending an output we do not know: the node would refuse
                if !self.sent.lock().unwrap().iter().any(|t| t.txid() == tx.txid()) {
                    return Err(ChannelError::new("rpc_error", "missing inputs"));
                }
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

struct MemWallet(Arc<MemChain>);

impl Wallet for MemWallet {
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        let mut n = self.0.n.lock().unwrap();
        *n += 1;
        let txid = hex::encode(sha256(format!("funding {n}").as_bytes()));
        let spk = address_to_spk(address, None).map_err(|e| ChannelError::new("bad_address", e.to_string()))?;
        self.0.utxos.lock().unwrap().insert((txid.clone(), 0), UtxoInfo { confirmations: 1, value: sats, script_pubkey: spk, coinbase: false });
        Ok((txid, 0))
    }
}


fn secret(label: &str) -> SecretKey {
    SecretKey::from_slice(&sha256(label.as_bytes())).unwrap()
}

const O: &str = "https://api.example";

/// What the transport does to the answer of the n-th request (1-based) it carries to `path`.
#[derive(Clone, Copy, PartialEq)]
enum Do {
    /// The provider serves it; the answer never reaches the payer (a timeout on the way back).
    Lose,
    /// The provider never sees it; the payer gets the answer (and receipt) of the request before.
    Replay,
    /// The provider serves it; the payer gets this status, no body and no PAYMENT-RESPONSE.
    Bare(u16),
}

/// Someone between payer and provider. `log` gets one line per request the provider served.
struct Net {
    prov: Arc<Provider>,
    plan: Mutex<HashMap<u64, Do>>,
    n: Mutex<u64>,
    last: Mutex<Option<HttpResponse>>,
    served: Arc<Mutex<u64>>,
}

impl Transport for Net {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        let (_, path) = split_url(url);
        let paid = headers.iter().any(|(k, _)| k == "PAYMENT-SIGNATURE");
        let what = if paid && path.starts_with("/v1/") {
            let mut n = self.n.lock().unwrap();
            *n += 1;
            self.plan.lock().unwrap().get(&n).copied()
        } else {
            None
        };
        if what == Some(Do::Replay) {
            return Ok(self.last.lock().unwrap().clone().expect("an earlier answer"));
        }
        let r = self.prov.serve(method, &path, headers, body, url, None);
        if paid && r.status == 200 {
            *self.served.lock().unwrap() += 1;
            *self.last.lock().unwrap() = Some(r.clone());
        }
        match what {
            Some(Do::Lose) => Err(ChannelError::new("transport_error", "timed out reading the answer")),
            Some(Do::Bare(s)) => Ok(HttpResponse::new(s, vec![], vec![])),
            _ => Ok(r),
        }
    }
}

struct World {
    prov: Arc<Provider>,
    c: Client,
    served: Arc<Mutex<u64>>,
}

/// A provider whose every answer differs (a counter), 150 sat a call, and a payer behind `plan`.
fn world(billing: &str, plan: &[(u64, Do)]) -> World {
    let chain = MemChain::new();
    let mut cfg = ProviderConfig::new(NET);
    cfg.billing = billing.into();
    let k = Mutex::new(0u64);
    let handler = move |_: &str, p: &str, _: &[u8]| {
        let mut k = k.lock().unwrap();
        *k += 1;
        HttpResponse::new(200, vec![], json!({"answer": p, "n": *k}).to_string().into_bytes())
    };
    let prov = Arc::new(Provider::new(chain.clone(), secret("provider payTo"), cfg, Ledger::in_memory(), Box::new(|_, _| 150), Box::new(handler)).unwrap());
    let served = Arc::new(Mutex::new(0));
    let net = Net { prov: prov.clone(), plan: Mutex::new(plan.iter().copied().collect()), n: Mutex::new(0), last: Mutex::new(None), served: served.clone() };
    let ch = chain.clone();
    let c = Client::new(ClientConfig::new(NET), Box::new(net), Box::new(MemWallet(chain.clone())), Box::new(move || ch.block_count()));
    World { prov, c, served }
}

fn n_of(r: &HttpResponse) -> u64 {
    serde_json::from_slice::<Value>(&r.body).unwrap()["n"].as_u64().unwrap()
}

/// T4 (receipt covers the answer), one step to the side: the receipt names the request, the status
/// and the body, and the payer checks all three, but not that the receipt is for the seq it just
/// sent. Someone between payer and provider answers an identical request with the answer before
/// and its genuine receipt: the payer takes a stale answer as the paid one.
#[test]
fn t4_an_earlier_answer_replayed_with_its_receipt_is_refused() {
    // paid request 1 opens the channel's use; request 2 is the honest call; request 3 gets request 2's answer again
    let mut w = world("postpay", &[(3, Do::Replay)]);
    let url = format!("{O}/v1/price");
    let a = w.c.request("GET", &url, b"").unwrap();
    let b = w.c.request("GET", &url, b"").unwrap();
    assert_ne!(n_of(&a), n_of(&b), "every honest answer differs");
    let served = *w.served.lock().unwrap();
    let r = w.c.request("GET", &url, b"");
    assert_eq!(*w.served.lock().unwrap(), served, "the provider never saw the third request");
    match r {
        Err(e) => assert_eq!(e.code, "bad_receipt", "{e}"),
        Ok(r) => panic!("the payer took answer n={} again as the answer to a new paid request (seq {} sent, receipt seq {})",
                        n_of(&r), w.c.channels[O].seq, w.c.channels[O].receipts.last().unwrap()["seq"]),
    }
}

/// AGP-081 "Noticed, not changed", first bullet. One answer is lost on the way back while the
/// channel's first state (the 546 sat minimum) still covers the next calls, so the provider sends
/// no 402 to resynchronise on. Every call after it is served, charged and thrown away.
#[test]
fn t4_one_lost_answer_does_not_cost_the_answers_after_it() {
    let mut w = world("postpay", &[(2, Do::Lose)]);
    let url = format!("{O}/v1/q");
    w.c.request("GET", &url, b"").unwrap();
    assert_eq!(w.c.request("GET", &url, b"").unwrap_err().code, "transport_error");
    let mut out = vec![];
    for _ in 0..8 {
        out.push(match w.c.request("GET", &url, b"") {
            Ok(r) => r.status.to_string(),
            Err(e) => e.code,
        });
    }
    let chan = w.c.channels[O].payer.params.channel_id();
    let st = w.prov.channel_state(&chan).unwrap();
    let discarded = out.iter().filter(|o| *o != "200").count();
    assert_eq!(discarded, 0, "after ONE lost answer: outcomes {out:?}; provider served {} paid calls and holds spent {} msat under a signed state of {} sat; \
                               the payer has receipts for {} msat", *w.served.lock().unwrap(), st.spent_msat, st.best_cum, w.c.channels[O].spent_msat);
}

/// The same once the minimum state is used up: the 402 path absorbs one lost answer over the
/// channel's life (`slack_msat`), and no second one.
#[test]
fn t4_two_lost_answers_do_not_end_the_channel() {
    for billing in ["postpay", "prepay"] {
        let mut w = world(billing, &[(8, Do::Lose), (12, Do::Lose)]);
        let url = format!("{O}/v1/q");
        let mut out = vec![];
        for _ in 0..20 {
            out.push(match w.c.request("GET", &url, b"") {
                Ok(r) => r.status.to_string(),
                Err(e) => e.code,
            });
        }
        let after = &out[12..];
        assert!(after.iter().all(|o| o == "200"), "{billing}: after two lost answers the channel no longer serves: {out:?}");
    }
}

/// T4c's rule is "an answer below 400 to a paid request needs its receipt": 204, 3xx included.
#[test]
fn t4_a_paid_answer_below_400_without_a_receipt_is_refused_whatever_its_status() {
    for status in [204u16, 301, 302, 304, 307, 399] {
        let mut w = world("postpay", &[(2, Do::Bare(status))]);
        let url = format!("{O}/v1/q");
        w.c.request("GET", &url, b"").unwrap();
        let e = w.c.request("GET", &url, b"").expect_err("taken with no receipt");
        assert_eq!(e.code, "bad_receipt", "{status}: {e}");
    }
    // 400 and above comes back as it is
    let mut w = world("postpay", &[(2, Do::Bare(404))]);
    w.c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    assert_eq!(w.c.request("GET", &format!("{O}/v1/q"), b"").unwrap().status, 404);
}

/// `Local`, with the 402's `extra.derivation` rewritten (a server from before AGP-068, or someone
/// between who wants the old binding back).
struct Old(Arc<Provider>, &'static str, Arc<Mutex<u64>>);

impl Transport for Old {
    fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
        let (_, path) = split_url(url);
        let mut r = self.0.serve(method, &path, headers, body, url, None);
        if r.status == 402 {
            let mut pr = unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap();
            pr["accepts"][0]["extra"]["derivation"] = self.1.into();
            r.headers.retain(|(k, _)| k != "PAYMENT-REQUIRED");
            r.headers.push(("PAYMENT-REQUIRED".into(), b64json(&pr)));
        }
        if path.starts_with("/x402/xbt-channel/open") {
            *self.2.lock().unwrap() += 1;
        }
        Ok(r)
    }
}

/// T2, downgrade (the first audit: "No Rust test for refusing a v2 offer"): an offer that names the
/// old binding is refused before anything is funded, opened or signed.
#[test]
fn t2_an_offer_for_an_older_binding_is_refused_before_funding() {
    for old in ["v2", "v1", "", "V3", "v3 "] {
        let chain = MemChain::new();
        let prov = Arc::new(Provider::new(chain.clone(), secret("provider payTo"), ProviderConfig::new(NET), Ledger::in_memory(), Box::new(|_, _| 150),
                                          Box::new(|_, _, _| HttpResponse::new(200, vec![], b"x".to_vec()))).unwrap());
        let opens = Arc::new(Mutex::new(0));
        let mut c = Client::new(ClientConfig::new(NET), Box::new(Old(prov, old, opens.clone())), Box::new(MemWallet(chain.clone())), Box::new(|| Ok(1_000)));
        let e = c.request("GET", &format!("{O}/v1/q"), b"").expect_err(old);
        assert_eq!(e.code, "bad_offer", "{old:?}: {e}");
        assert_eq!((*chain.n.lock().unwrap(), *opens.lock().unwrap(), c.channels.len()), (0, 0, 0), "{old:?}: funded or opened");
    }
}

/// AGP-078 stated limit 5, as it is: without a RouteWal (the default) a routed session's seq is
/// written only when a lock completes, so after a provider restart a ROUTE-AUTH header it already
/// served authenticates again and is served and metered again. This test passes while the limit
/// stands; it is here so the limit is measured, not to hold it in place.
#[test]
fn t4_limit_a_routed_call_header_is_served_again_after_a_restart_without_a_route_wal() {
    use xbt402::route::{call_auth, session_key};
    use xbt402::route_seller::RouteOffer;
    use xbt_primitives::ecdsa;
    const PATH: &str = "/v1/chunk";
    let dir = std::env::temp_dir().join(format!("xbt402-agp087-routed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let chain = MemChain::new();
    let served = Arc::new(Mutex::new(0u64));
    let make = |chain: &Arc<MemChain>, served: &Arc<Mutex<u64>>| {
        let s = served.clone();
        let p = Provider::new(chain.clone(), secret("provider payTo"), ProviderConfig::new(NET), Ledger::open(&dir.join("prov.jsonl")).unwrap(),
                              Box::new(|_, _| 1000),
                              Box::new(move |_, _, _| {
                                  *s.lock().unwrap() += 1;
                                  HttpResponse::new(200, vec![], b"{\"ok\":1}".to_vec())
                              })).unwrap();
        p.offer_route(RouteOffer { window: 30.0, lock_wait: 30.0, ..RouteOffer::new(PATH, 1_000_000) });
        p
    };
    let p = make(&chain, &served);
    assert!(p.cfg.route_wal.is_none(), "the default has no RouteWal");
    let c = secret("routed client");
    let r = p.serve("POST", PATH, &[("ROUTE-CLIENT".into(), hex::encode(ecdsa::pubkey(&c)))], b"", "", None);
    assert_eq!(r.status, 402);
    let pr = unb64json(r.header("PAYMENT-REQUIRED").unwrap()).unwrap();
    let session = pr["accepts"][0]["extra"]["route"]["session"].as_str().unwrap().to_string();
    let key = session_key(&c, &hex::decode(p.pay_to()).unwrap()).unwrap();
    let hdr = |seq: u64| {
        let auth = call_auth(&key, &session, seq, &request_digest_v2("POST", PATH, b"x"));
        vec![("ROUTE-AUTH".to_string(), b64json(&json!({"session": session, "seq": seq, "auth": auth})))]
    };
    for seq in 1..=3 {
        assert_eq!(p.serve("POST", PATH, &hdr(seq), b"x", "", None).status, 200);
    }
    assert_eq!(p.serve("POST", PATH, &hdr(3), b"x", "", None).status, 402, "control: a used seq is refused by the running provider");
    assert_eq!(*served.lock().unwrap(), 3);
    drop(p);
    let p = make(&chain, &served);
    let again: Vec<u16> = (1..=3).map(|seq| p.serve("POST", PATH, &hdr(seq), b"x", "", None).status).collect();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(again, [200, 200, 200], "without a RouteWal the three served headers are served again after a restart (stated limit); \
                                        if this now fails the limit is gone and the audit row should say so");
    assert_eq!(*served.lock().unwrap(), 6);
}

/// T2, injectivity of the v2 digest over a bare target (what a server binds when it is given no
/// origin: an embedder calling `Provider::serve` with an empty `url`, as the in-process transports
/// do). `request_url` splits at the first "://" wherever it is, so a "://" inside the query makes
/// the path a "scheme" (lowercased) and the rest a host (lowercased, userinfo dropped).
#[test]
fn t2_two_bare_targets_do_not_share_a_digest() {
    let pairs = [("/A?next=http://h/x", "/a?next=http://h/x"),
                 ("/a?next=http://H/x", "/a?next=http://h/x"),
                 ("/a?next=http://user@h/x", "/a?next=http://h/x"),
                 ("/a?next=http://h:080/x", "/a?next=http://h:80/x")];
    let mut same = vec![];
    for (a, b) in pairs {
        if request_digest_v2("GET", a, b"") == request_digest_v2("GET", b, b"") {
            same.push((a, b));
        }
    }
    // and served: a payment for one is taken on the other
    let chain = MemChain::new();
    let seen = Arc::new(Mutex::new(vec![]));
    let s2 = seen.clone();
    let prov = Arc::new(Provider::new(chain.clone(), secret("provider payTo"), ProviderConfig::new(NET), Ledger::in_memory(), Box::new(|_, _| 150),
                                      Box::new(move |_, p, _| {
                                          s2.lock().unwrap().push(p.to_string());
                                          HttpResponse::new(200, vec![], b"x".to_vec())
                                      })).unwrap());
    struct Local(Arc<Provider>);
    impl Transport for Local {
        fn request(&self, method: &str, url: &str, body: &[u8], headers: &[(String, String)]) -> Result<HttpResponse> {
            Ok(self.0.serve(method, &split_url(url).1, headers, body, url, None))
        }
    }
    let mut c = Client::new(ClientConfig::new(NET), Box::new(Local(prov.clone())), Box::new(MemWallet(chain.clone())), Box::new(|| Ok(1_000)));
    c.request("GET", &format!("{O}/v1/q"), b"").unwrap();
    let ch = c.channels.get_mut(O).unwrap();
    let sig = hex::encode(ch.payer.sign_state(546).unwrap());
    let chan = ch.payer.params.channel_id();
    // the payer binds the bare target /a?next=http://h/x; on the way it becomes /A?next=HTTP://h/x
    let mut pl = json!({"chan": chan, "seq": 50, "cum": "546", "sig": sig});
    pl["auth"] = request_auth(&ch.auth_key, &chan, pl.get("seq"), pl.get("cum"), Some(&sig), &request_digest_v2("GET", "/a?next=http://h/x", b"")).into();
    let h = vec![("PAYMENT-SIGNATURE".to_string(), b64json(&payment_payload(&ch.accepted, &pl)))];
    let r = prov.serve("GET", "/A?next=HTTP://h/x", &h, b"", "", None);
    assert!(!seen.lock().unwrap().iter().any(|p| p.starts_with("/A")), "a payment bound to /a?next=http://h/x was served on {:?} (HTTP {})",
            seen.lock().unwrap().last(), r.status);
    assert!(same.is_empty(), "different request targets with one digest: {same:?}");
}
