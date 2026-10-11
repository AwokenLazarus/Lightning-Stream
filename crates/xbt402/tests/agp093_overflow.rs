//! AGP-093 third closure audit, area OVERFLOW (the provider over real sockets): tests written by
//! the auditor. Run with `--features http-client,http-server`.
//!
//! `overflow-checks = true` is on in every release build since d4c8328, so a missed overflow is a
//! panic. Tests are built in the dev profile, which has overflow checks on too: what panics here
//! panics in the shipped `release` build. The first test sends hostile numbers to every endpoint
//! of a real `Provider` behind the real HTTP server and looks for a handler that panicked (the
//! server answers `500 handler panicked` for one). The second shows what a panic under the ledger
//! lock leaves behind (the lock is poisoned and every later `lock()` takes it anyway). The third
//! is the watcher loop the provider binaries run: one panic in a tick ends it for good.
#![cfg(all(feature = "http-client", feature = "http-server"))]
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use xbt402::channel::{ChannelParams, FeePayer};
use xbt402::client::{Client, ClientChannel, ClientConfig, Wallet};
use xbt402::funding::{ChainBackend, UtxoInfo};
use xbt402::http::{serve_listener, UreqTransport};
use xbt402::ledger::Ledger;
use xbt402::provider::{HttpResponse, Provider, ProviderConfig};
use xbt402::route::{call_auth, session_key};
use xbt402::route_seller::RouteOffer;
use xbt402::wire::*;
use xbt402::{ChannelError, Result};
use xbt_primitives::address::address_to_spk;
use xbt_primitives::ecdsa;
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
    /// The next `boom` calls of `block_count` panic: a stand-in for any panic (a missed overflow)
    /// at a point where the caller holds what it holds when it asks for the height.
    boom: AtomicU32,
    asked: AtomicU32,
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
        self.asked.fetch_add(1, Ordering::SeqCst);
        if self.boom.load(Ordering::SeqCst) > 0 {
            self.boom.fetch_sub(1, Ordering::SeqCst);
            panic!("agp093: injected panic (a missed overflow)");
        }
        Ok(*self.tip.lock().unwrap())
    }
    fn get_tx_out(&self, txid: &str, vout: u32, _m: bool) -> Result<Option<UtxoInfo>> {
        Ok(self.utxos.lock().unwrap().get(&(txid.to_string(), vout)).cloned())
    }
    fn send_raw_transaction(&self, hex: &str) -> Result<String> {
        let tx = Tx::parse_hex(hex)?;
        let mut u = self.utxos.lock().unwrap();
        for i in &tx.inputs {
            u.remove(&(i.prevout.txid_hex(), i.prevout.vout));
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
        let txid = hex::encode(sha256(format!("agp093 funding {n}").as_bytes()));
        let spk = address_to_spk(address, None).map_err(|e| ChannelError::new("bad_address", e.to_string()))?;
        self.0.utxos.lock().unwrap().insert((txid.clone(), 0), UtxoInfo { confirmations: 1, value: sats, script_pubkey: spk, coinbase: false });
        Ok((txid, 0))
    }
}

fn prov_secret() -> SecretKey {
    SecretKey::from_slice(&sha256(b"agp093 provider payTo")).unwrap()
}

fn start(port: u16) -> (Arc<MemChain>, Arc<Provider>, String) {
    let chain = MemChain::new();
    let mut cfg = ProviderConfig::new(NET);
    cfg.height_ttl = Duration::ZERO; // every request asks the chain for the height
    let prov = Arc::new(Provider::new(chain.clone(), prov_secret(), cfg, Ledger::in_memory(), Box::new(|_, _| 150),
                                      Box::new(|_, p, _| HttpResponse::new(200, vec![], json!({"answer": p}).to_string().into_bytes()))).unwrap());
    prov.offer_route(RouteOffer::new("/r/x", 370 * 10u128.pow(18)));
    let l = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let addr = l.local_addr().unwrap().to_string();
    serve_listener(prov.clone(), l, 4).unwrap();
    (chain, prov, addr)
}

fn payer(chain: &Arc<MemChain>) -> Client {
    let c = chain.clone();
    Client::new(ClientConfig::new(NET), Box::new(UreqTransport::default()), Box::new(MemWallet(chain.clone())), Box::new(move || Ok(*c.tip.lock().unwrap())))
}

fn raw(addr: &str, req: &[u8]) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).to_string()
}

fn post(addr: &str, path: &str, headers: &[(&str, String)], body: &str) -> String {
    let hs: String = headers.iter().map(|(k, v)| format!("{k}: {v}\r\n")).collect();
    raw(addr, format!("POST {path} HTTP/1.1\r\nHost: {addr}\r\n{hs}Content-Length: {}\r\n\r\n{body}", body.len()).as_bytes())
}

fn get(addr: &str, path: &str, headers: &[(&str, String)]) -> String {
    let hs: String = headers.iter().map(|(k, v)| format!("{k}: {v}\r\n")).collect();
    raw(addr, format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{hs}\r\n").as_bytes())
}

fn status(r: &str) -> u16 {
    r.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// Numbers a counterparty can put where a number is read: as JSON numbers and as the decimal
/// strings `py_int` also takes.
fn hostile() -> Vec<Value> {
    let mut v = vec![json!(0), json!(1), json!(545), json!(546), json!(u32::MAX), json!(u32::MAX as u64 + 1), json!(i64::MAX), json!(i64::MAX as u64 + 1),
                     json!(u64::MAX - 1), json!(u64::MAX), json!(-1), json!(i64::MIN), json!(1.5), json!(1e300), json!(true), json!(null), json!([]), json!({}),
                     json!(""), json!("-0"), json!("+7"), json!(" 12 ")];
    for s in ["18446744073709551615", "18446744073709551616", "170141183460469231731687303715884105727", "999999999999999999999999999999",
              "-999999999999999999999999999999", "9223372036854775808", "-9223372036854775809", "18446744073709551069", "4611686018427387903"] {
        v.push(json!(s));
    }
    v
}

/// A PAYMENT-SIGNATURE that authenticates (the channel HMAC is the payer's own), with the given
/// `seq`, `cum` and `sig`, and any more payload fields.
fn header(ch: &ClientChannel, seq: &Value, cum: &Value, sig: Option<&str>, more: &Value, method: &str, url: &str, body: &[u8]) -> String {
    let chan = ch.payer.params.channel_id();
    let mut pl = json!({"chan": chan, "seq": seq, "cum": cum});
    if let Some(s) = sig {
        pl["sig"] = s.into();
    }
    for (k, v) in more.as_object().into_iter().flatten() {
        pl[k] = v.clone();
    }
    // as the provider computes it: `sig` only when it is truthy
    let s = sig.filter(|s| !s.is_empty());
    pl["auth"] = request_auth(&ch.auth_key, &chan, pl.get("seq"), pl.get("cum"), s, &request_digest_v2(method, url, body)).into();
    b64json(&payment_payload(&ch.accepted, &pl))
}

/// Hostile numbers on every provider endpoint: each is a refusal (or an answer), never a panic,
/// and the provider then serves an honest payer and its watcher tick runs.
#[test]
fn hostile_numbers_on_every_provider_endpoint_are_refusals_and_never_a_panic() {
    let (chain, prov, addr) = start(27601);
    let o = format!("http://{addr}");
    let mut c = payer(&chain);
    assert_eq!(c.request("GET", &format!("{o}/v1/q"), b"").unwrap().status, 200);
    let mut ch = c.channels[&o].clone();
    let chan = ch.payer.params.channel_id();
    let p = ch.payer.params.clone();
    let good_sig = hex::encode(ch.payer.sign_state(1_000).unwrap());
    let mut answers: Vec<(String, String)> = vec![];
    let mut sent = 0usize;
    let mut note = |what: String, r: String| {
        answers.push((what, r));
    };
    let url = format!("{o}/v1/q");

    // --- a paid call: cum, sig -----------------------------------------------------------------
    let mut seq = 10u64;
    for cum in hostile() {
        for sig in [None, Some(""), Some("21"), Some("00"), Some("3006020101020101"), Some(good_sig.as_str()), Some("zz")] {
            for more in [json!({}), json!({"hashlock": "00"}), json!({"hashlock": true, "sig": sig.unwrap_or("21")})] {
                seq += 1;
                let h = header(&ch, &json!(seq), &cum, sig, &more, "GET", &url, b"");
                note(format!("call cum={cum} sig={sig:?} more={more}"), get(&addr, "/v1/q", &[("PAYMENT-SIGNATURE", h)]));
                sent += 1;
            }
        }
    }
    // --- a hash-locked sale (the conditional state is built on the best state) ----------------------
    let (h, _, _) = prov.offer_conditional("/c/x", 700, b"deliverable", None);
    let curl = format!("{o}/c/x");
    for cum in hostile() {
        for sig in [Some("21"), Some("00"), Some(good_sig.as_str()), None] {
            seq += 1;
            let hd = header(&ch, &json!(seq), &cum, sig, &json!({"hashlock": hex::encode(h)}), "GET", &curl, b"");
            note(format!("cond cum={cum} sig={sig:?}"), get(&addr, "/c/x", &[("PAYMENT-SIGNATURE", hd)]));
            sent += 1;
        }
    }
    // --- the facilitator endpoints ---------------------------------------------------------------
    let acc = json!({"scheme": ch.accepted["scheme"], "network": NET, "payTo": prov.pay_to()});
    for cum in hostile() {
        for sig in ["21", good_sig.as_str(), "", "00"] {
            let body = json!({"x402Version": 2, "paymentRequirements": acc, "paymentPayload": {"x402Version": 2, "accepted": acc,
                              "payload": {"chan": chan, "cum": cum, "sig": sig}}}).to_string();
            note(format!("verify cum={cum}"), post(&addr, FACILITATOR_VERIFY, &[], &body));
            sent += 1;
        }
    }
    // --- open (funded and preflight): capacity, vout, expiry ---------------------------------------
    let pay_to = hex::decode(prov.pay_to()).unwrap();
    for n in hostile() {
        for (field, preflight) in [("capacity", true), ("capacity", false), ("vout", false), ("expiry", true), ("expiry", false)] {
            let mut chn = json!({"txid": p.funding_txid(), "vout": 0, "capacity": p.capacity, "expiry": p.expiry, "payerPub": hex::encode(p.payer_pub),
                                 "payerSpk": hex::encode(&p.payer_spk), "redeemScript": hex::encode(p.script())});
            chn[field] = n.clone();
            if field == "expiry" {
                // the script this provider derives for that expiry, so the request gets past it
                if let Some(e) = n.as_u64().and_then(|e| u32::try_from(e).ok()) {
                    if let Ok(q) = ChannelParams::derive(&pay_to, &p.payer_pub, e, p.close_fee, Some(p.payer_spk.clone()), NET, FeePayer::Payer) {
                        chn["redeemScript"] = hex::encode(q.script()).into();
                    }
                }
            }
            let mut body = json!({"x402Version": 2, "network": NET, "channel": chn});
            if preflight {
                body["preflight"] = true.into();
                body["channel"].as_object_mut().unwrap().remove("txid");
            }
            note(format!("open {field}={n} preflight={preflight}"), post(&addr, OPEN_PATH, &[], &body.to_string()));
            sent += 1;
            // the same as a hub's ch2 (the hub binding is checked after the numbers are read)
            body["hub"] = json!({"payTo": hex::encode(p.payer_pub), "sig": "3006020101020101"});
            note(format!("open(hub) {field}={n}"), post(&addr, OPEN_PATH, &[], &body.to_string()));
            sent += 1;
        }
    }
    // --- rollover: amount, the next expiry ---------------------------------------------------------
    for n in hostile() {
        for (amount, expiry) in [(n.clone(), json!(p.expiry)), (json!(1_000), n.clone()), (n.clone(), n.clone())] {
            for sig in ["21", "", "3006020101020101" /* no hash type */, "300602010102010121"] {
                let body = json!({"chan": chan, "amount": amount, "sig": sig, "next": {"payerPub": hex::encode(p.payer_pub), "expiry": expiry}}).to_string();
                note(format!("rollover amount={amount} expiry={expiry}"), post(&addr, ROLLOVER_PATH, &[], &body));
                sent += 1;
            }
        }
    }
    // --- close with a final state: cum (a refused payload closes nothing) -------------------------
    let close_sig = hex::encode(ch.payer.sign_close().unwrap());
    for cum in hostile().into_iter().filter(|c| c.as_u64() != Some(1_000) && !matches!(c, Value::Null | Value::Bool(_))) {
        for sig in [json!("21"), json!("00"), json!(""), Value::Null] {
            let body = json!({"chan": chan, "sig": close_sig, "payload": {"cum": cum, "sig": sig, "x": 1}}).to_string();
            let r = post(&addr, CLOSE_PATH, &[], &body);
            note(format!("close cum={cum} sig={sig}"), r);
            sent += 1;
        }
    }
    // --- a hub's lock on a channel that is not a hub's: amount, cum --------------------------------
    for n in hostile() {
        seq += 1;
        let body = json!({"route": {"session": "s", "lockId": "l", "amount": n, "lockAuth": "00", "hub": "00"}}).to_string();
        let h = header(&ch, &json!(seq), &n, None, &json!({"point": "02"}), "POST", &format!("{o}{LOCK_PATH}"), body.as_bytes());
        note(format!("lock amount=cum={n}"), post(&addr, LOCK_PATH, &[("PAYMENT-SIGNATURE", h)], &body));
        sent += 1;
    }
    // --- a routed call (ROUTE-AUTH): seq -----------------------------------------------------------
    let ck = SecretKey::from_slice(&sha256(b"agp093 route client")).unwrap();
    let r = get(&addr, "/r/x", &[("ROUTE-CLIENT", hex::encode(ecdsa::pubkey(&ck)))]);
    let doc: Value = serde_json::from_str(r.split("\r\n\r\n").nth(1).unwrap_or("")).unwrap_or(Value::Null);
    let sid = doc["accepts"][0]["extra"]["route"]["session"].as_str().expect("a route session").to_string();
    let key = session_key(&ck, &pay_to).unwrap();
    let rurl = format!("{o}/r/x");
    let mut last_ok = 0u64;
    for n in hostile() {
        // authenticated where the seq is a u64 (the MAC is over its decimal), a bare claim otherwise
        let auth = n.as_u64().or_else(|| n.as_str().and_then(|s| s.trim().parse().ok())).map(|s| call_auth(&key, &sid, s, &request_digest_v2("GET", &rurl, b"")));
        let h = b64json(&json!({"session": sid, "seq": n, "auth": auth.unwrap_or_default()}));
        let r = get(&addr, "/r/x", &[("ROUTE-AUTH", h)]);
        if status(&r) == 200 {
            last_ok = n.as_u64().or_else(|| n.as_str().and_then(|s| s.trim().parse().ok())).unwrap_or(0);
        }
        note(format!("route call seq={n}"), r);
        sent += 1;
    }
    assert!(last_ok > 0, "control: no routed call was served, so its metering was not reached");
    // --- the seq of a paid call, last: the largest one is spent for good on this channel ------------
    for s in hostile() {
        let h = header(&ch, &s, &json!(1_000), Some(&good_sig), &json!({}), "GET", &url, b"");
        note(format!("call seq={s}"), get(&addr, "/v1/q", &[("PAYMENT-SIGNATURE", h)]));
        sent += 1;
    }

    let panicked: Vec<&(String, String)> = answers.iter().filter(|(_, r)| r.contains("handler panicked") || status(r) == 0).collect();
    assert!(panicked.is_empty(), "{} of {sent} hostile requests made a handler panic (or got no answer); the first: {:?}", panicked.len(),
            panicked.first().map(|(w, r)| (w, r.lines().next().unwrap_or(""))));
    let served = answers.iter().filter(|(w, r)| w.starts_with("call ") && status(r) == 200).count();
    assert!(served > 0, "control: none of the authenticated calls was served, so the matrix did not get past the auth");
    // the channel the largest seq was spent on is unusable for calls from then on (its payer's own
    // doing: only the payer holds the HMAC key), and still closes
    assert_eq!(prov.channel_state(&chan).unwrap().seq, u64::MAX);
    assert!(prov.close_channel(&chan).is_ok(), "the channel whose seq is u64::MAX no longer closes");
    // the provider still serves an honest payer, and its watcher tick runs
    let mut c2 = payer(&chain);
    assert_eq!(c2.request("GET", &format!("{o}/v1/q"), b"").unwrap().status, 200);
    assert_eq!(c2.request("GET", &format!("{o}/v1/q"), b"").unwrap().status, 200);
    prov.close_due().unwrap();
    // what each group was answered (kind, status, error code): shows how deep the matrix got
    let mut hist: std::collections::BTreeMap<(String, u16, String), usize> = Default::default();
    for (w, r) in &answers {
        let body = r.split("\r\n\r\n").nth(1).unwrap_or("");
        let code = serde_json::from_str::<Value>(body).ok().and_then(|d| d.get("error").or(d.get("invalidReason")).and_then(Value::as_str).map(str::to_string)).unwrap_or_default();
        *hist.entry((w.split([' ', '=']).next().unwrap_or("").to_string(), status(r), code)).or_default() += 1;
    }
    for ((k, st, code), n) in &hist {
        eprintln!("agp093_overflow: {k:10} {st} {code:28} x{n}");
    }
    eprintln!("agp093_overflow: {sent} hostile requests, 0 panics, {served} authenticated calls served");
}

/// The mechanics, by experiment: a panic in a request handler while it holds the ledger lock.
/// The server answers 500 for that request; the lock is poisoned and every later `lock()` takes
/// it anyway (`into_inner`); the ledger holds no half-applied state (the request worked on a copy);
/// the next honest call is served.
#[test]
fn a_panic_under_the_ledger_lock_costs_one_request_and_leaves_the_ledger_as_it_was() {
    let (chain, prov, addr) = start(27602);
    let o = format!("http://{addr}");
    let mut c = payer(&chain);
    assert_eq!(c.request("GET", &format!("{o}/v1/q"), b"").unwrap().status, 200);
    let ch = c.channels[&o].clone();
    let chan = ch.payer.params.channel_id();
    let before = prov.channel_state(&chan).unwrap();
    // the paid call asks for the height under the ledger lock (provider.rs:1694)
    let mut pc = ch.clone();
    let sig = hex::encode(pc.payer.sign_state(2_000).unwrap());
    let h = header(&ch, &json!(50), &json!(2_000), Some(&sig), &json!({}), "GET", &format!("{o}/v1/q"), b"");
    chain.boom.store(1, Ordering::SeqCst);
    let r = get(&addr, "/v1/q", &[("PAYMENT-SIGNATURE", h.clone())]);
    assert_eq!(status(&r), 500, "{r}");
    assert!(r.contains("handler panicked"), "{r}");
    let after = prov.channel_state(&chan).unwrap();
    assert_eq!((after.seq, after.best_cum, after.spent_msat), (before.seq, before.best_cum, before.spent_msat),
               "a request that panicked left part of itself in the ledger");
    // the same header again: it was never served, so it is served now, once
    let r = get(&addr, "/v1/q", &[("PAYMENT-SIGNATURE", h.clone())]);
    assert_eq!(status(&r), 200, "{r}");
    assert_eq!(status(&get(&addr, "/v1/q", &[("PAYMENT-SIGNATURE", h)])), 402, "the header was served twice");
    // eight more in a row (more than the 4 handler slots): no slot is lost to a panic
    for i in 0..8u64 {
        chain.boom.store(1, Ordering::SeqCst);
        let h = header(&ch, &json!(60 + i), &json!(2_000), Some(&sig), &json!({}), "GET", &format!("{o}/v1/q"), b"");
        assert_eq!(status(&get(&addr, "/v1/q", &[("PAYMENT-SIGNATURE", h)])), 500);
    }
    let mut c2 = payer(&chain);
    assert_eq!(c2.request("GET", &format!("{o}/v1/q"), b"").unwrap().status, 200);
    prov.close_due().unwrap();
}

/// HOLE (failing today). The provider binaries (`xbt402-rust-provider`, `xbt-work-provider`) run
/// the watcher as `thread::spawn(move || loop { sleep; prov.close_due() })`. A panic in one tick
/// unwinds that thread and nothing starts it again: the HTTP server goes on taking payments while
/// no channel is closed at its margin any more, and the payer's refund becomes valid at expiry.
/// With overflow checks on in release builds, a missed overflow anywhere under `close_due` is such
/// a panic. The loop below is the binaries' loop, word for word; the panic is injected by the
/// chain double (no counterparty-reachable panic under `close_due` was found by this audit).
#[test]
fn a_panic_in_one_watcher_tick_does_not_end_the_provider_watcher() {
    let (chain, prov, addr) = start(27603);
    let o = format!("http://{addr}");
    let mut c = payer(&chain);
    assert_eq!(c.request("GET", &format!("{o}/v1/q"), b"").unwrap().status, 200);
    let w = prov.clone();
    // crates/xbt402-interop/src/bin/xbt402-rust-provider.rs:54 (with a shorter sleep)
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(20));
        if let Err(e) = w.close_due() {
            eprintln!("watcher: {e}");
        }
    });
    std::thread::sleep(Duration::from_millis(200));
    assert!(chain.asked.load(Ordering::SeqCst) > 2, "control: the watcher ticks");
    chain.boom.store(1, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(chain.boom.load(Ordering::SeqCst), 0, "control: the panic was taken");
    let n = chain.asked.load(Ordering::SeqCst);
    // the service still answers and takes payments
    assert_eq!(c.request("GET", &format!("{o}/v1/q"), b"").unwrap().status, 200);
    let paid = chain.asked.load(Ordering::SeqCst) - n;
    std::thread::sleep(Duration::from_millis(400));
    let ticks = chain.asked.load(Ordering::SeqCst) - n - paid;
    assert!(ticks > 0, "the watcher made no tick in 400 ms after one tick panicked: nothing closes this provider's channels at their margin any more, \
                        and the HTTP server still serves (a paid call was answered 200 after the panic)");
}
