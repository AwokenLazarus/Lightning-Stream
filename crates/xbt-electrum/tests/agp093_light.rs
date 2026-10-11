//! AGP-093 (third closure audit, area LIGHT): what wave 4's two rules of `backend.rs` leave open.
//!
//! Each test is named as the claim that should hold. Those named `hole_*` FAIL on `d4c8328`; those
//! named `control_*` pass and show the honest path in the same rig.
//!
//! * The call deadline is over the whole scan, and the scan asks every server for the script's
//!   history once per coin: one server that answers each request well inside the timeout makes a
//!   scan of a script with many coins fail (and the honest server is flagged and hung up on by the
//!   requests made after the deadline).
//! * A claim above the tip a server last reported is read as a lie (an answer) when our forced sync
//!   was skipped because another sync was in flight: "not there" is then answered as known.
//! * `call("scantxoutset")` sums the coins' values with an unchecked `+=`.
//!
//! Ports: the proxies made here listen on 27540-27559 (the `sim` servers pick their own, as in
//! every other test of this crate).
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::json;
use xbt_electrum::sim::{FakeElectrum, SimChain, CHECKPOINT};
use xbt_electrum::{Config, ElectrumBackend};

static NEXT_PORT: AtomicU16 = AtomicU16::new(27540);

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

/// Twenty confirmed coins on one script, an honest server, and a second honest server behind a
/// proxy that holds each `get_history` for `hold_ms`.
fn many_coins(hold_ms: u64) -> (Arc<Mutex<SimChain>>, Vec<u8>, Arc<FakeElectrum>, Arc<FakeElectrum>, Proxy) {
    let chain = sim(200);
    let a = spk(0x61);
    for _ in 0..COINS {
        chain.lock().unwrap().credit(0, 5_000, &a, true);
    }
    let (honest, slowish) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    let proxy = Proxy::start(slowish.addr, "blockchain.scripthash.get_history", hold_ms, true);
    (chain, a, honest, slowish, proxy)
}

/// The call deadline is four timeouts for the whole scan (1 s timeout: 4 s). The scan asks for the
/// script's history once per coin, so a server that takes a quarter of the timeout per answer, and
/// lies about nothing, uses the deadline up after 15 coins. Before wave 4 the scan was slow; now it
/// fails, on every call, for as long as that server is configured.
#[test]
fn hole_a_scan_of_many_coins_succeeds_when_every_server_answers_inside_a_quarter_of_the_timeout() {
    let (chain, a, honest, _slowish, proxy) = many_coins(250);
    let b = backend(&chain, &[honest.url(), proxy.url()], Duration::from_secs(1));
    b.block_count().unwrap();
    let t0 = Instant::now();
    let got = b.unspent_marked(&a).map(|(coins, complete)| (coins.len(), complete));
    println!("AGP-093 measure: scan of {COINS} coins, one server 250 ms per get_history, timeout 1 s: {:?} after {:?}; flags on the honest server: {:?}",
             got.as_ref().map_err(|e| e.msg.clone()), t0.elapsed(), flags_on(&b, &honest));
    assert_eq!(got.ok(), Some((COINS, true)));
}

/// The same scan, from the honest server's side: it answered every request at once. The requests
/// the scan still makes after its deadline has passed are sent with no time left, time out at once,
/// and each such timeout hangs up on the server and flags it.
#[test]
fn hole_an_honest_server_is_not_flagged_or_hung_up_on_when_another_server_used_the_deadline_up() {
    let (chain, a, honest, _slowish, proxy) = many_coins(0);
    let b = backend(&chain, &[honest.url(), proxy.url()], Duration::from_secs(1));
    // a first scan with nobody slow: every coin's proof is now held, as in a wallet that has run a while
    assert_eq!(b.unspent_marked(&a).map(|(c, every)| (c.len(), every)).ok(), Some((COINS, true)));
    proxy.hold_ms.store(250, Ordering::SeqCst);
    let before = honest.connections();
    let got = b.unspent_marked(&a).map(|(c, every)| (c.len(), every));
    let flags = flags_on(&b, &honest);
    println!("AGP-093 measure: second scan: {:?}; flags on the honest server: {flags:?}; connections it accepted: {} -> {}",
             got.map_err(|e| e.msg), before, honest.connections());
    assert!(flags.is_empty(), "the honest server was flagged: {flags:?}");
}

#[test]
fn control_the_same_scan_succeeds_with_no_slow_server() {
    let (chain, a, honest, _slowish, proxy) = many_coins(0);
    let b = backend(&chain, &[honest.url(), proxy.url()], Duration::from_secs(1));
    assert_eq!(b.unspent_marked(&a).map(|(c, every)| (c.len(), every)).ok(), Some((COINS, true)));
    assert!(flags_on(&b, &honest).is_empty());
}

/// No server lies here. One is slow to answer `headers.subscribe`, so a sync round is in flight
/// when a block arrives. A call in that window cannot sync (the gate is held: `sync` answers from
/// the chain as it is), so it holds no header for the new block. Both servers' true claim at that
/// height is then judged against the tip each last reported, called a lie, and the lookup answers
/// "no such output" as if every server had been heard: the rule "unknown is not absent" is broken
/// with nobody lying, and two honest servers are flagged.
#[test]
fn hole_a_claim_above_the_tip_a_server_last_reported_is_not_a_lie_while_our_sync_is_skipped() {
    let chain = sim(200);
    let a = spk(0x62);
    let (s1, s2) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    let slow = Proxy::start(s1.addr, "blockchain.headers.subscribe", 0, false);
    let b = Arc::new(backend(&chain, &[slow.url(), s2.url()], Duration::from_secs(3)));
    b.block_count().unwrap();
    slow.hold_ms.store(2_000, Ordering::SeqCst);
    let holder = {
        let b = b.clone();
        std::thread::spawn(move || b.sync(true))
    };
    std::thread::sleep(Duration::from_millis(400)); // the other server's part of the round is done
    let txid = chain.lock().unwrap().credit(0, 70_000, &a, true); // a block arrives
    let out = b.tx_out(&txid, 0, true);
    let seen = b.transaction(&txid).map(|t| t.is_some());
    let flags = flags_on(&b, &s2);
    let _ = holder.join();
    println!("AGP-093 measure: tx_out of an output confirmed while a sync was in flight: {:?}; transaction: {:?}; flags on the honest server: {flags:?}",
             out.as_ref().map(|o| o.as_ref().map(|o| o.confirmations)).map_err(|e| e.msg.clone()), seen.as_ref().map_err(|e| e.msg.clone()));
    assert!(!matches!(out, Ok(None)), "a confirmed, unspent output both servers list was answered as not there");
    assert!(!matches!(seen, Ok(false)), "has_transaction: a transaction both servers list in a block was answered as not there");
    assert!(!flags.iter().any(|f| f.contains("above the tip it reports")), "an honest server was flagged as lying: {flags:?}");
}

#[test]
fn control_the_same_output_is_found_when_no_sync_is_in_flight() {
    let chain = sim(200);
    let a = spk(0x63);
    let (s1, s2) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    let slow = Proxy::start(s1.addr, "blockchain.headers.subscribe", 0, false);
    let b = backend(&chain, &[slow.url(), s2.url()], Duration::from_secs(3));
    b.block_count().unwrap();
    let txid = chain.lock().unwrap().credit(0, 70_000, &a, true);
    assert_eq!(b.tx_out(&txid, 0, true).unwrap().map(|o| o.confirmations), Some(1));
    assert!(flags_on(&b, &s2).is_empty());
}

/// Overflow checks are on in every build (AGP-089). `call("scantxoutset")` adds the coins' values
/// with `total += u.value` (backend.rs:1737), u64 over values a block can hold (any i64). Three
/// proven coins of i64::MAX each make the call panic instead of answering or refusing. The values
/// are the servers' only if a block with them is mined: on mainnet that is a miner's attack (the
/// light client checks headers and Merkle proofs, not amounts).
#[test]
fn hole_scantxoutset_answers_or_refuses_coins_whose_values_sum_past_u64() {
    let chain = sim(200);
    let a = spk(0x64);
    for _ in 0..3 {
        chain.lock().unwrap().credit(0, i64::MAX as u64, &a, true);
    }
    let s = FakeElectrum::start(chain.clone(), false);
    let b = backend(&chain, &[s.url()], Duration::from_secs(3));
    assert_eq!(b.unspent(&a).unwrap().len(), 3, "control: the typed call lists them");
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        b.call("scantxoutset", &json!(["start", [format!("raw({})", hex::encode(&a))]])).map(|v| v["unspents"].as_array().map(Vec::len))
    }));
    println!("AGP-093 measure: scantxoutset over three coins of i64::MAX sats: {}", if r.is_err() { "panicked".to_string() } else { format!("{r:?}") });
    assert!(r.is_ok(), "scantxoutset panicked (attempt to add with overflow)");
    // the backend still answers after it: no lock was held, and its locks recover from poison
    assert!(b.block_count().is_ok());
}

/// Measure (passes): what one slow server can hold. It lies about nothing and answers every
/// request 400 ms after it was sent, in order, at a 500 ms timeout (call deadline and sync deadline
/// 2 s each). AGP-092's limit 6 gives the worst case of one call as a header sync, the call
/// deadline and one forced sync.
#[test]
fn measure_one_slow_server_holds_a_lookup() {
    let chain = sim(200);
    let a = spk(0x65);
    let txid = chain.lock().unwrap().credit(0, 70_000, &a, true);
    let (honest, slowish) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    let proxy = Proxy::start(slowish.addr, "\"method\"", 400, true);
    let b = backend(&chain, &[proxy.url(), honest.url()], Duration::from_millis(500));
    let t = Instant::now();
    let cold = b.tx_out(&txid, 0, true).map(|o| o.map(|o| o.confirmations));
    let cold_t = t.elapsed();
    let t = Instant::now();
    let warm = b.tx_out(&txid, 0, true).map(|o| o.map(|o| o.confirmations));
    let warm_t = t.elapsed();
    let t2 = chain.lock().unwrap().credit(0, 70_000, &a, true);
    let t = Instant::now();
    let fresh = b.tx_out(&t2, 0, true).map(|o| o.map(|o| o.confirmations));
    let fresh_t = t.elapsed();
    println!("AGP-093 measure: one server 400 ms per request, timeout 500 ms: first gettxout {cold_t:?} ({:?}), second {warm_t:?} ({:?}), \
              gettxout of a new block's output {fresh_t:?} ({:?})",
             cold.map_err(|e| e.msg), warm.map_err(|e| e.msg), fresh.map_err(|e| e.msg));
    assert!(cold_t < Duration::from_secs(12) && fresh_t < Duration::from_secs(12));
}

/// Measure (passes): "a server that refuses its tip is hung up on" (wave 4, for electrs' protocol
/// 1.4 negotiation). There is no back-off: a server that keeps refusing `headers.subscribe` is
/// connected to again on every sync round, one TCP (and TLS) connection, `server.version` and the
/// subscriptions each time, and each round adds a flag to a list that holds 50.
#[test]
fn measure_a_server_that_refuses_its_tip_costs_one_connection_per_sync_round() {
    let chain = sim(200);
    let (refuser, honest) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    let b = backend(&chain, &[refuser.url(), honest.url()], Duration::from_secs(3));
    b.block_count().unwrap();
    refuser.knobs().fail.insert("blockchain.headers.subscribe".into(), "unsupported".into());
    let before = refuser.connections();
    for _ in 0..20 {
        b.block_count().unwrap();
    }
    let n = refuser.connections() - before;
    let own = b.flags().iter().filter(|f| f.server == refuser.url()).count();
    println!("AGP-093 measure: 20 sync rounds against a server that refuses its tip: {n} new connections; {own} of the {} flags held are its",
             b.flags().len());
    assert!(n <= 20);
}

/// "Not there" is read from a server's words (`NOT_THERE`), and two of the six are generic:
/// "not found" and "missing". JSON-RPC's own error for a method a server does not serve is
/// "Method not found" (-32601; the code is not looked at). A server that cannot be asked for
/// transactions at all has said nothing about this one, yet with one server hiding it the lookup
/// answers "no such output" as if every server had been heard.
#[test]
fn hole_method_not_found_is_not_no_such_transaction() {
    let chain = sim(200);
    let a = spk(0x66);
    let txid = chain.lock().unwrap().credit(0, 70_000, &a, true);
    let (liar, honest) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    liar.knobs().hide.insert(txid.clone());
    honest.knobs().fail.insert("blockchain.transaction.get".into(), "Method not found".into());
    let b = backend(&chain, &[liar.url(), honest.url()], Duration::from_secs(3));
    let out = b.tx_out(&txid, 0, true);
    println!("AGP-093 measure: one server hides the funding, the other answers transaction.get \"Method not found\": {:?}",
             out.as_ref().map(|o| o.as_ref().map(|o| o.confirmations)).map_err(|e| e.msg.clone()));
    assert!(out.is_err(), "answered as not there");
}

#[test]
fn control_a_busy_error_beside_a_hiding_server_is_unknown() {
    let chain = sim(200);
    let a = spk(0x67);
    let txid = chain.lock().unwrap().credit(0, 70_000, &a, true);
    let (liar, honest) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    liar.knobs().hide.insert(txid.clone());
    honest.knobs().fail.insert("blockchain.transaction.get".into(), "server busy".into());
    let b = backend(&chain, &[liar.url(), honest.url()], Duration::from_secs(3));
    assert!(b.tx_out(&txid, 0, true).is_err());
}
