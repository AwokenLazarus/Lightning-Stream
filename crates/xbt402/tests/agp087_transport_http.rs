//! AGP-087 second closure audit, transport area (T2, T3, T4 over real sockets): tests written by
//! the auditor. Run with `--features http-client,http-server`. A failing test is a finding.
#![cfg(all(feature = "http-client", feature = "http-server"))]
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use xbt402::client::{Client, ClientConfig, Transport, Wallet};
use xbt402::funding::{ChainBackend, UtxoInfo};
use xbt402::http::{serve_listener, UreqTransport};
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


/// A real provider on a real listener, and what its handler was asked for.
type Started = (Arc<MemChain>, Arc<Provider>, String, Arc<Mutex<Vec<String>>>);

fn start() -> Started {
    let chain = MemChain::new();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    let handler = move |m: &str, p: &str, _: &[u8]| {
        s2.lock().unwrap().push(format!("{m} {p}"));
        HttpResponse::new(200, vec![], json!({"answer": p}).to_string().into_bytes())
    };
    let prov = Arc::new(Provider::new(chain.clone(), SecretKey::from_slice(&sha256(b"provider payTo")).unwrap(), ProviderConfig::new(NET),
                                      Ledger::in_memory(), Box::new(|_, _| 150), Box::new(handler)).unwrap());
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    serve_listener(prov.clone(), l, 4).unwrap();
    (chain, prov, addr, seen)
}

fn payer(chain: &Arc<MemChain>) -> Client {
    let c = chain.clone();
    Client::new(ClientConfig::new(NET), Box::new(UreqTransport::default()), Box::new(MemWallet(chain.clone())), Box::new(move || c.block_count()))
}

fn raw(addr: &str, req: &str) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).to_string()
}

/// A PAYMENT-SIGNATURE the payer would send for `method url` at `seq` (the least state).
fn header_for(ch: &mut xbt402::client::ClientChannel, seq: u64, method: &str, url: &str) -> String {
    let chan = ch.payer.params.channel_id();
    let sig = hex::encode(ch.payer.sign_state(546).unwrap());
    let mut pl = json!({"chan": chan, "seq": seq, "cum": "546", "sig": sig});
    pl["auth"] = request_auth(&ch.auth_key, &chan, pl.get("seq"), pl.get("cum"), Some(&sig), &request_digest_v2(method, url, b"")).into();
    b64json(&payment_payload(&ch.accepted, &pl))
}

/// T2, the sides of the `#` fix: what the server binds is what it routes on, however the request
/// line and `Host` are written. Each line is a payment signed for one URL and sent as another
/// request; none may reach the handler.
#[test]
fn t2_a_payment_reaches_the_handler_only_on_the_target_it_was_signed_for() {
    let (chain, _prov, addr, seen) = start();
    let mut c = payer(&chain);
    let o = format!("http://{addr}");
    assert_eq!(c.request("GET", &format!("{o}/v1/q"), b"").unwrap().status, 200);
    let mut ch = c.channels[&o].clone();
    let mut seq = 100;
    let mut send = |signed: &str, line: &str, hosts: &[&str]| {
        seq += 1;
        let h = header_for(&mut ch, seq, "GET", signed);
        let hosts: String = hosts.iter().map(|h| format!("Host: {h}\r\n")).collect();
        let before = seen.lock().unwrap().len();
        let r = raw(&addr, &format!("{line}\r\n{hosts}PAYMENT-SIGNATURE: {h}\r\n\r\n"));
        let served = seen.lock().unwrap()[before..].to_vec();
        (r.split("\r\n").next().unwrap_or("").to_string(), served)
    };
    let cases: Vec<(String, String, Vec<String>)> = vec![
        // signed for /a/b; Host carries the first segment, the server is asked for /b
        (format!("{o}/a/b"), "GET /b HTTP/1.1".into(), vec![format!("{addr}/a")]),
        // signed for /a?x=1; sent with the query moved into Host
        (format!("{o}/a?x=1"), "GET /a HTTP/1.1".into(), vec![format!("{addr}?x=1")]),
        // absolute-form request target for another path than the one signed
        (format!("{o}/v1/q"), format!("GET {o}/v1/other HTTP/1.1"), vec![addr.clone()]),
        // two Host headers: the signed one second
        ("http://other.example/v1/q".to_string(), "GET /v1/q HTTP/1.1".into(), vec![addr.clone(), "other.example".into()]),
        // percent-encoding, a doubled slash, a dot segment, a path parameter, a trailing dot on the host: other requests
        (format!("{o}/v1/q"), "GET /v1/%71 HTTP/1.1".into(), vec![addr.clone()]),
        (format!("{o}/v1/q"), "GET //v1/q HTTP/1.1".into(), vec![addr.clone()]),
        (format!("{o}/v1/q"), "GET /v1/x/../q HTTP/1.1".into(), vec![addr.clone()]),
        (format!("{o}/v1/q"), "GET /v1/q;p=1 HTTP/1.1".into(), vec![addr.clone()]),
        (format!("{o}/v1/q"), "GET /v1/q?%23 HTTP/1.1".into(), vec![addr.clone()]),
        (format!("{o}/v1/q"), "get /v1/q HTTP/1.1".into(), vec![addr.clone()]),
        (format!("{o}/v1/q"), "GET /v1/q HTTP/1.1".into(), vec![format!("{}.:{}", "127.0.0.1", addr.rsplit(':').next().unwrap())]),
        (format!("{o}/v1/q"), "GET /v1/q HTTP/1.1".into(), vec![addr.clone()]),
    ];
    let n = cases.len();
    for (i, (signed, line, hosts)) in cases.into_iter().enumerate() {
        let hs: Vec<&str> = hosts.iter().map(String::as_str).collect();
        let (status, served) = send(&signed, &line, &hs);
        if i == n - 1 {
            // the control: the request as signed is served
            assert!(status.starts_with("HTTP/1.1 200"), "control: {status}");
            assert_eq!(served, ["GET /v1/q"]);
        } else {
            assert!(served.is_empty(), "signed for {signed}, sent as {line:?} with Host {hosts:?}: the handler served {served:?} ({status})");
            assert!(status.starts_with("HTTP/1.1 402") || status.starts_with("HTTP/1.1 400"), "{line:?}: {status}");
        }
    }
}

/// T4 (the receipt covers status and body) on a HEAD: the server sends no body for HEAD, the
/// receipt's bodyHash is of the handler's body.
#[test]
fn t4_a_paid_head_request_gets_a_receipt_the_payer_can_check() {
    let (chain, prov, addr, _seen) = start();
    let mut c = payer(&chain);
    let o = format!("http://{addr}");
    assert_eq!(c.request("GET", &format!("{o}/v1/q"), b"").unwrap().status, 200);
    let chan = c.channels[&o].payer.params.channel_id();
    let before = prov.channel_state(&chan).unwrap().spent_msat;
    let r = c.request("HEAD", &format!("{o}/v1/q"), b"");
    let after = prov.channel_state(&chan).unwrap().spent_msat;
    assert!(r.is_ok(), "the provider charged {} msat for the HEAD and the payer threw the answer away: {}", after - before, r.unwrap_err());
}

/// A raw server answering every connection with `bytes`, then closing.
fn raw_server(bytes: Vec<u8>) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let bytes = bytes.clone();
            std::thread::spawn(move || {
                let mut req = [0u8; 4096];
                let _ = s.read(&mut req);
                let _ = s.write_all(&bytes);
            });
        }
    });
    addr
}

/// T3 one step to the side: a chunked answer cut before its last chunk is an error too.
#[test]
fn t3_a_chunked_body_cut_short_is_an_error() {
    let addr = raw_server(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n5\r\nwor".to_vec());
    let r = UreqTransport::default().request("GET", &format!("http://{addr}/c"), b"", &[]);
    assert!(r.is_err(), "a cut chunked body came back as Ok: {:?}", r.map(|r| String::from_utf8_lossy(&r.body).to_string()));
    // cut on a chunk boundary, with no terminating chunk
    let addr = raw_server(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n".to_vec());
    let r = UreqTransport::default().request("GET", &format!("http://{addr}/c"), b"", &[]);
    assert!(r.is_err(), "a chunked body with no last chunk came back as Ok: {:?}", r.map(|r| String::from_utf8_lossy(&r.body).to_string()));
}

/// T3: an answer with neither Content-Length nor chunking ends when the connection does, so the
/// transport cannot tell a cut one from a whole one. Recorded as it is: on a paid call the
/// receipt's bodyHash is what catches it (`the_receipt_covers_the_response`).
#[test]
fn t3_a_close_delimited_body_cut_short_is_not_seen_by_the_transport() {
    let addr = raw_server(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhalf of the ans".to_vec());
    let r = UreqTransport::default().request("GET", &format!("http://{addr}/c"), b"", &[]).unwrap();
    assert_eq!(r.body, b"half of the ans");
}

fn _unused(_: HashMap<u8, u8>, _: Value, _: ChannelError) {}
