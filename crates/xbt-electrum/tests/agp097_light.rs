//! AGP-097, fix wave 5, the light client: the rules the fixes keep, at the neighbours of the paths
//! the third audit named (its own tests are in `agp093_light.rs`).
//!
//! Ports: the proxies made here listen on 27560-27579 (the `sim` servers pick their own).
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::json;
use xbt_electrum::sim::{FakeElectrum, SimChain, CHECKPOINT};
use xbt_electrum::{Config, ElectrumBackend};

static NEXT_PORT: AtomicU16 = AtomicU16::new(27560);

fn spk(b: u8) -> Vec<u8> {
    [vec![0x00, 0x14], vec![b; 20]].concat()
}

fn sim(height: u32) -> Arc<Mutex<SimChain>> {
    Arc::new(Mutex::new(SimChain::new(height, 0)))
}

fn backend(chain: &Arc<Mutex<SimChain>>, urls: &[String], timeout: Duration) -> ElectrumBackend {
    let mut c = Config::new(&urls.iter().map(String::as_str).collect::<Vec<_>>(), "regtest");
    c.checkpoint = Some((CHECKPOINT, hex::encode(chain.lock().unwrap().hash_at(CHECKPOINT))));
    c.timeout = timeout;
    c.sync_interval = Duration::ZERO;
    ElectrumBackend::new(c).unwrap()
}

fn flags_on(b: &ElectrumBackend, s: &Arc<FakeElectrum>) -> Vec<String> {
    b.flags().into_iter().filter(|f| f.server == s.url()).map(|f| f.reason).collect()
}

/// A TCP proxy in front of one server. A request line containing `needle` is held for `hold_ms`;
/// with `in_order` every later line waits behind it (a slow server), without it the others pass at
/// once (a server slow to answer one method: a real server works its requests in parallel, the
/// `sim` works one connection's in order).
struct Proxy {
    addr: SocketAddr,
    hold_ms: Arc<AtomicU64>,
}

impl Proxy {
    fn start(upstream: SocketAddr, needle: &'static str, hold_ms: u64, in_order: bool) -> Self {
        let l = TcpListener::bind(("127.0.0.1", NEXT_PORT.fetch_add(1, Ordering::SeqCst))).unwrap();
        let addr = l.local_addr().unwrap();
        let hold = Arc::new(AtomicU64::new(hold_ms));
        let h = hold.clone();
        std::thread::spawn(move || {
            for c in l.incoming() {
                let Ok(client) = c else { break };
                let Ok(up) = TcpStream::connect(upstream) else { continue };
                let (mut up_r, mut client_w) = (up.try_clone().unwrap(), client.try_clone().unwrap());
                std::thread::spawn(move || {
                    let mut buf = [0u8; 1 << 16];
                    while let Ok(n) = up_r.read(&mut buf) {
                        if n == 0 || client_w.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    let _ = client_w.shutdown(std::net::Shutdown::Both);
                });
                let h = h.clone();
                std::thread::spawn(move || {
                    let up = Arc::new(Mutex::new(up));
                    let send = |up: &Arc<Mutex<TcpStream>>, line: &str| {
                        let mut u = up.lock().unwrap();
                        u.write_all(line.as_bytes()).and_then(|_| u.write_all(b"\n")).is_ok()
                    };
                    for line in BufReader::new(client).lines() {
                        let Ok(line) = line else { break };
                        let ms = h.load(Ordering::SeqCst);
                        if line.contains(needle) && ms > 0 {
                            if in_order {
                                std::thread::sleep(Duration::from_millis(ms));
                            } else {
                                let up = up.clone();
                                std::thread::spawn(move || {
                                    std::thread::sleep(Duration::from_millis(ms));
                                    let mut u = up.lock().unwrap();
                                    let _ = u.write_all(line.as_bytes()).and_then(|_| u.write_all(b"\n"));
                                });
                                continue;
                            }
                        }
                        if !send(&up, &line) {
                            break;
                        }
                    }
                    let _ = up.lock().unwrap().shutdown(std::net::Shutdown::Both);
                });
            }
        });
        Self { addr, hold_ms: hold }
    }

    fn url(&self) -> String {
        format!("tcp://{}", self.addr)
    }
}

const COINS: usize = 20;

fn coins(chain: &Arc<Mutex<SimChain>>, a: &[u8]) {
    for _ in 0..COINS {
        chain.lock().unwrap().credit(0, 5_000, a, true);
    }
}

fn asked(s: &Arc<FakeElectrum>, method: &str) -> usize {
    s.calls.lock().unwrap().iter().filter(|m| *m == method).count()
}

/// The rule: what a scan asks a server for does not grow with the number of coins beyond what each
/// coin needs once. The script's history is asked for once a scan, not once a coin.
#[test]
fn a_scan_asks_for_the_scripts_history_once() {
    let chain = sim(200);
    let a = spk(0x71);
    coins(&chain, &a);
    let (s1, s2) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    let b = backend(&chain, &[s1.url(), s2.url()], Duration::from_secs(3));
    for scan in 1..=2 {
        assert_eq!(b.unspent_marked(&a).map(|(c, every)| (c.len(), every)).ok(), Some((COINS, true)));
        for s in [&s1, &s2] {
            assert_eq!(asked(s, "blockchain.scripthash.get_history"), scan, "get_history requests after scan {scan}");
        }
    }
    // a spent coin is still left out: the one history serves every coin's search
    let spent = b.unspent(&a).unwrap()[0].clone();
    chain.lock().unwrap().spend(&[(&spent.txid, spent.vout)], vec![xbt_primitives::tx::TxOut::new(4_000, spk(0x72))], true);
    let left = b.unspent(&a).unwrap();
    assert!(left.len() == COINS - 1 && !left.iter().any(|u| u.txid == spent.txid));
}

/// The coins' proofs, cold: a server that takes a quarter of the timeout for each proof request,
/// lies about nothing, and is the first to claim every coin. One request a coin was 20 round trips
/// to it, five seconds against a deadline of four; one batch a server is one.
#[test]
fn a_cold_scan_of_many_coins_succeeds_beside_a_server_slow_to_prove() {
    let chain = sim(200);
    let a = spk(0x73);
    coins(&chain, &a);
    let (slowish, honest) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    let proxy = Proxy::start(slowish.addr, "blockchain.transaction.get_merkle", 250, true);
    let b = backend(&chain, &[proxy.url(), honest.url()], Duration::from_secs(1));
    b.block_count().unwrap();
    let t0 = Instant::now();
    let got = b.unspent_marked(&a).map(|(c, every)| (c.len(), every));
    println!("AGP-097 measure: cold scan of {COINS} coins, the first server 250 ms per proof request, timeout 1 s: {:?} after {:?}",
             got.as_ref().map_err(|e| e.msg.clone()), t0.elapsed());
    assert_eq!(got.ok(), Some((COINS, true)));
    assert!(b.flags().is_empty(), "{:?}", b.flags());
}

/// The rule: a server is hung up on only for a request that went a whole timeout unanswered. A
/// request the call's deadline cuts short ends the call's wait and nothing else: the server keeps
/// its connection, is not flagged, and answers the next call on it.
#[test]
fn a_request_the_calls_deadline_cuts_short_does_not_hang_up_or_flag() {
    let chain = sim(200);
    let a = spk(0x74);
    let txid = chain.lock().unwrap().credit(0, 70_000, &a, true);
    let (s1, s2) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    let proxy = Proxy::start(s1.addr, "blockchain.scripthash.get_history", 0, false);
    let mut c = Config::new(&[proxy.url().as_str(), s2.url().as_str()], "regtest");
    c.checkpoint = Some((CHECKPOINT, hex::encode(chain.lock().unwrap().hash_at(CHECKPOINT))));
    (c.timeout, c.sync_interval, c.call_deadline) = (Duration::from_secs(3), Duration::ZERO, Some(Duration::from_millis(400)));
    let b = ElectrumBackend::new(c).unwrap();
    assert_eq!(b.tx_out(&txid, 0, true).unwrap().map(|o| o.confirmations), Some(1));
    let before = (s1.connections(), s2.connections());
    // the history now takes longer than the whole call may: the call ends unknown, not "not there"
    proxy.hold_ms.store(900, Ordering::SeqCst);
    let fresh = chain.lock().unwrap().credit(0, 60_000, &a, true);
    let got = b.tx_out(&fresh, 0, true);
    assert!(got.is_err(), "{:?}", got.map(|o| o.map(|o| o.confirmations)));
    assert_eq!((s1.connections(), s2.connections()), before, "a server was hung up on");
    assert!(b.flags().is_empty(), "{:?}", b.flags());
    // its late answers arrive on the connection it kept, and the next call is answered there
    proxy.hold_ms.store(0, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(1_000));
    assert_eq!(b.tx_out(&fresh, 0, true).unwrap().map(|o| o.confirmations), Some(1));
    assert_eq!((s1.connections(), s2.connections()), before);
    assert!(b.flags().is_empty(), "{:?}", b.flags());
}

/// The other side of the same rule: a request that goes a whole timeout unanswered still hangs up
/// and flags, deadline or not.
#[test]
fn a_request_that_goes_a_whole_timeout_unanswered_still_hangs_up() {
    let chain = sim(200);
    let a = spk(0x75);
    let txid = chain.lock().unwrap().credit(0, 70_000, &a, true);
    let (s1, s2) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    let proxy = Proxy::start(s1.addr, "blockchain.scripthash.get_history", 0, false);
    let b = backend(&chain, &[proxy.url(), s2.url()], Duration::from_millis(300));
    assert_eq!(b.tx_out(&txid, 0, true).unwrap().map(|o| o.confirmations), Some(1));
    let before = s1.connections();
    proxy.hold_ms.store(5_000, Ordering::SeqCst);
    let fresh = chain.lock().unwrap().credit(0, 60_000, &a, true);
    // the honest server's proof still answers (a proven coin needs no word from the silent one)
    assert_eq!(b.tx_out(&fresh, 0, true).unwrap().map(|o| o.confirmations), Some(1));
    assert!(b.flags().iter().any(|f| f.server == proxy.url() && f.reason.contains("timed out")), "{:?}", b.flags());
    proxy.hold_ms.store(0, Ordering::SeqCst);
    assert_eq!(b.tx_out(&fresh, 0, true).unwrap().map(|o| o.confirmations), Some(1));
    assert!(s1.connections() > before, "it was connected to again");
}

/// The rule: a claim is a lie only against a tip the server reported after it made the claim. The
/// side that must still hold: with nothing in the way of our forced sync, a claim above the tip
/// the server then reports is flagged, and the honest server's proof decides.
#[test]
fn a_claim_above_the_tip_a_server_reports_in_our_own_sync_is_still_a_lie() {
    let chain = sim(200);
    let a = spk(0x76);
    let txid = chain.lock().unwrap().credit(0, 70_000, &a, true);
    let (liar, honest) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    liar.knobs().claim_height.insert(txid.clone(), 5_000);
    let b = backend(&chain, &[liar.url(), honest.url()], Duration::from_secs(3));
    assert_eq!(b.tx_out(&txid, 0, true).unwrap().map(|o| o.confirmations), Some(1));
    assert!(flags_on(&b, &liar).iter().any(|f| f.contains("above the tip it reports")), "{:?}", b.flags());
    // and alone it is an answer: every claim was judged and none holds
    let only = backend(&chain, &[liar.url()], Duration::from_secs(3));
    assert!(matches!(only.tx_out(&txid, 0, true), Ok(None)));
}

/// `scantxoutset` over coins whose values sum past u64 is refused in words, and the typed call,
/// which adds nothing up, still lists them.
#[test]
fn scantxoutset_refuses_a_total_past_u64() {
    let chain = sim(200);
    let a = spk(0x77);
    for _ in 0..3 {
        chain.lock().unwrap().credit(0, i64::MAX as u64, &a, true);
    }
    let s = FakeElectrum::start(chain.clone(), false);
    let b = backend(&chain, &[s.url()], Duration::from_secs(3));
    let e = b.call("scantxoutset", &json!(["start", [format!("raw({})", hex::encode(&a))]])).unwrap_err();
    assert!(e.msg.contains("sum past"), "{e:?}");
    // two of them fit
    let c = sim(200);
    for _ in 0..2 {
        c.lock().unwrap().credit(0, i64::MAX as u64, &a, true);
    }
    let s = FakeElectrum::start(c.clone(), false);
    let b = backend(&c, &[s.url()], Duration::from_secs(3));
    assert_eq!(b.call("scantxoutset", &json!(["start", [format!("raw({})", hex::encode(&a))]])).unwrap()["unspents"].as_array().map(Vec::len), Some(2));
}

/// The rule: a request is written by one deadline, however slowly the server reads. A server that
/// answers `server.version` and then reads 256 kB every 50 ms is sent a broadcast far larger than
/// the socket buffers. Every write moves some of it, so a timeout per write never fires, and the
/// write took as long as the server chose to read for (measured before the change: 3.3 s at a
/// 500 ms timeout, 0.8 s after), with the connection's lock held throughout.
#[test]
fn a_server_that_reads_a_little_at_a_time_does_not_hold_a_broadcast() {
    use xbt_primitives::tx::{OutPoint, Tx, TxIn, TxOut};
    let chain = sim(200);
    let l = TcpListener::bind(("127.0.0.1", NEXT_PORT.fetch_add(1, Ordering::SeqCst))).unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { break };
            std::thread::spawn(move || {
                let mut first = String::new();
                let mut r = BufReader::new(c.try_clone().unwrap());
                if r.read_line(&mut first).is_err() {
                    return;
                }
                let id = serde_json::from_str::<serde_json::Value>(&first).ok().and_then(|v| v["id"].as_u64()).unwrap_or(0);
                let _ = c.write_all(format!("{}\n", json!({"jsonrpc": "2.0", "id": id, "result": ["trickle", "1.6"]})).as_bytes());
                let mut buf = vec![0u8; 256 << 10];
                while matches!(r.get_mut().read(&mut buf), Ok(n) if n > 0) {
                    std::thread::sleep(Duration::from_millis(50));
                }
            });
        }
    });
    let mut c = Config::new(&[format!("tcp://{addr}").as_str()], "regtest");
    c.checkpoint = Some((CHECKPOINT, hex::encode(chain.lock().unwrap().hash_at(CHECKPOINT))));
    c.timeout = Duration::from_millis(500);
    let b = ElectrumBackend::new(c).unwrap();
    // about 10 MB raw, 20 MB as a request line: far above the loopback buffers of both ends
    let big = Tx::new(2, (0..250_000u32).map(|n| TxIn::new(OutPoint::new([0x33; 32], n), 0)).collect(), vec![TxOut::new(1_000, spk(0x78))], 0);
    let hex = big.to_hex();
    // what parsing the transaction costs before anything is written (a debug build is slow at it)
    let t0 = Instant::now();
    Tx::parse_hex(&hex).unwrap().txid();
    let parse = t0.elapsed();
    let t0 = Instant::now();
    let got = b.broadcast(&hex);
    let took = t0.elapsed().saturating_sub(parse);
    println!("AGP-097 measure: broadcast of a {} byte transaction to a server that reads 256 kB every 50 ms, timeout 500 ms: {:?} after {took:?} (and {parse:?} to parse it)",
             hex.len() / 2, got.as_ref().map_err(|e| e.msg.clone()));
    assert!(got.is_err() && took < Duration::from_millis(1_500), "the write was held {took:?} at a 500 ms timeout");
}
