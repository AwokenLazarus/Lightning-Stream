//! AGP-102 (fourth closure audit, area LIGHT): what fix wave 5 leaves open in the light client.
//!
//! Each test is named as the rule that should hold. The two that are not `control_` or `measure_`
//! FAIL on `2e745f2`; the controls pass in the same rig.
//!
//!   * A lookup of a confirmed output that an honest server proves fails for as long as one other
//!     configured server, listed before it, claims the transaction one block above the tip and is
//!     slow in the header sync that claim forces: the forced sync runs inside the call's deadline
//!     and has a deadline of its own that is as long (four timeouts each at the defaults).
//!   * A request line above rustls' 64 kB send buffer is never written over TLS: a transaction
//!     above about 32 kB cannot be broadcast to an `ssl://` server, honest or not.
//!
//! Ports: the proxies made here listen on 27850-27869 (the `sim` servers pick their own).
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use xbt_electrum::sim::{FakeElectrum, SimChain, CHECKPOINT, TEST_CA};
use xbt_electrum::{Config, ElectrumBackend};
use xbt_primitives::tx::{OutPoint, Tx, TxIn, TxOut};

static NEXT_PORT: AtomicU16 = AtomicU16::new(27850);

fn spk(b: u8) -> Vec<u8> {
    [vec![0x00, 0x14], vec![b; 20]].concat()
}

fn sim(height: u32) -> Arc<Mutex<SimChain>> {
    Arc::new(Mutex::new(SimChain::new(height, 0)))
}

fn config(chain: &Arc<Mutex<SimChain>>, urls: &[String], timeout: Duration) -> Config {
    let mut c = Config::new(&urls.iter().map(String::as_str).collect::<Vec<_>>(), "regtest");
    c.checkpoint = Some((CHECKPOINT, hex::encode(chain.lock().unwrap().hash_at(CHECKPOINT))));
    c.timeout = timeout;
    c.sync_interval = Duration::ZERO;
    c
}

fn flags_on(b: &ElectrumBackend, url: &str) -> Vec<String> {
    b.flags().into_iter().filter(|f| f.server == url).map(|f| f.reason).collect()
}

/// The TCP proxy of `agp097_light.rs`: a request line containing `needle` is held for `hold_ms`,
/// every other line passes at once (a server slow to answer one method).
struct Proxy {
    addr: SocketAddr,
    #[allow(dead_code)]
    hold_ms: Arc<AtomicU64>,
}

impl Proxy {
    fn start(upstream: SocketAddr, needle: &'static str, hold_ms: u64) -> Self {
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
                    for line in BufReader::new(client).lines() {
                        let Ok(line) = line else { break };
                        let ms = h.load(Ordering::SeqCst);
                        if line.contains(needle) && ms > 0 {
                            let up = up.clone();
                            std::thread::spawn(move || {
                                std::thread::sleep(Duration::from_millis(ms));
                                let mut u = up.lock().unwrap();
                                let _ = u.write_all(line.as_bytes()).and_then(|_| u.write_all(b"\n"));
                            });
                            continue;
                        }
                        let mut u = up.lock().unwrap();
                        if u.write_all(line.as_bytes()).and_then(|_| u.write_all(b"\n")).is_err() {
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

const TIMEOUT: Duration = Duration::from_millis(400);

/// One hostile server beside one honest one. The hostile one:
///   * shows a tip on another branch (150 regtest blocks from just above the checkpoint: less work
///     than ours, so it is never adopted), which makes every header sync walk back from its tip
///     one `blockchain.block.header` request at a time;
///   * answers each of those requests 0.7 timeouts late (never a whole timeout: it is not hung
///     up on), so its part of every sync round ends at the sync deadline;
///   * claims the transaction asked about one block above the real tip.
/// It lies about nothing else and supplies whatever it lists.
/// Returns (chain, the honest server, the hostile one, its proxy, the confirmed coin's txid).
fn rig() -> (Arc<Mutex<SimChain>>, Arc<FakeElectrum>, Arc<FakeElectrum>, Proxy, String) {
    let chain = sim(300);
    let txid = chain.lock().unwrap().credit(0, 70_000, &spk(0x61), true);
    chain.lock().unwrap().mine(2);
    let (honest, liar) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    {
        let c = chain.lock().unwrap();
        let mut k = liar.knobs();
        k.headers = Some(c.alt_chain(CHECKPOINT + 1, 150, 0x7A));
        k.claim_height.insert(txid.clone(), c.tip_height() as i64 + 1);
    }
    let slow = Proxy::start(liar.addr, "blockchain.block.header", TIMEOUT.as_millis() as u64 * 7 / 10);
    (chain, honest, liar, slow, txid)
}

/// The rule (the README's, since AGP-092): one server can make a call slow or make a "not there"
/// answer fail; what the client proves keeps working. Here the output is confirmed three blocks
/// deep, the honest server lists it at its real height and has the proof, and the lookup still
/// fails on every call, for as long as the hostile server is configured before the honest one.
///
/// Cause: the hostile claim is looked at first (claims are in the configured order), it names a
/// block we do not hold, so the call forces a header sync (`backend.rs:1292-1296`). That sync has
/// its own deadline (`sync_deadline`, four timeouts) and runs inside the call's (`call_deadline`,
/// four timeouts): when it ends the call is over, and the honest server's claim is then "not
/// judged" (`backend.rs:1321-1324`).
#[test]
fn a_confirmed_output_an_honest_server_proves_is_answered_beside_a_server_that_holds_the_forced_sync() {
    let (chain, honest, liar, slow, txid) = rig();
    let b = ElectrumBackend::new(config(&chain, &[slow.url(), honest.url()], TIMEOUT)).unwrap();
    let mut fails = 0;
    for n in 1..=3 {
        let t0 = Instant::now();
        let got = b.tx_out(&txid, 0, true);
        println!("AGP-102 measure: lookup {n} of a coin 3 blocks deep, hostile server first, timeout {TIMEOUT:?}: {:?} after {:?}",
                 got.as_ref().map(|o| o.as_ref().map(|o| o.confirmations)).map_err(|e| e.msg.clone()), t0.elapsed());
        fails += got.is_err() as u32;
    }
    println!("AGP-102 measure: flags on the hostile server: {:#?}", flags_on(&b, &slow.url()));
    println!("AGP-102 measure: flags on the honest server: {:?}", flags_on(&b, &honest.url()));
    let _ = liar;
    assert_eq!(fails, 0, "{fails} of 3 lookups of a confirmed, provable output failed beside one hostile server");
}

/// The same two servers in the other order: the honest claim is proven first and the hostile one
/// is never looked at.
#[test]
fn control_the_same_output_is_found_when_the_honest_server_is_listed_first() {
    let (chain, honest, _liar, slow, txid) = rig();
    let b = ElectrumBackend::new(config(&chain, &[honest.url(), slow.url()], TIMEOUT)).unwrap();
    for _ in 0..2 {
        let t0 = Instant::now();
        let got = b.tx_out(&txid, 0, true).unwrap().unwrap();
        println!("AGP-102 measure: the same lookup, honest server first: {} confirmations after {:?}", got.confirmations, t0.elapsed());
        assert_eq!(got.confirmations, 3);
    }
}

fn tls_backend(chain: &Arc<Mutex<SimChain>>, s: &Arc<FakeElectrum>) -> ElectrumBackend {
    let dir = std::env::temp_dir().join(format!("agp102-light-ca-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ca = dir.join("ca.pem");
    std::fs::write(&ca, TEST_CA).unwrap();
    let mut c = config(chain, &[s.url()], Duration::from_secs(3));
    c.extra_ca = vec![ca];
    ElectrumBackend::new(c).unwrap()
}

/// A transaction of `bytes` raw bytes, more or less (one output with a long data script).
fn tx_of(bytes: usize) -> Tx {
    let mut script = vec![0x6A];
    script.resize(bytes, 0x00);
    Tx::new(2, vec![TxIn::new(OutPoint::new([0x44; 32], 0), 0)], vec![TxOut::new(0, script), TxOut::new(1_000, spk(0x62))], 0)
}

/// The rule: a transaction the backend accepts for broadcast (it parses, and a standard
/// transaction can be 100 kB) reaches an honest server whatever the transport. Over TLS the whole
/// request line is handed to rustls first (`conn.rs:183`, `write_all` on `Writer`), and rustls
/// buffers at most 64 kB of unsent records: `write` then takes nothing, `write_all` fails with
/// "failed to write whole buffer", the connection is closed and the server is never asked.
#[test]
fn a_transaction_of_100_kb_is_broadcast_to_an_honest_tls_server() {
    let chain = sim(150);
    let s = FakeElectrum::start(chain.clone(), true);
    let b = tls_backend(&chain, &s);
    assert_eq!(b.block_count().unwrap(), 150);
    for bytes in [20_000usize, 40_000, 100_000] {
        let tx = tx_of(bytes);
        let got = b.broadcast(&tx.to_hex());
        println!("AGP-102 measure: broadcast of a {bytes} byte transaction over TLS to an honest server: {:?}",
                 got.as_ref().map(|t| &t[..16]).map_err(|e| e.msg.clone()));
        assert_eq!(got.ok(), Some(tx.txid()), "a {bytes} byte transaction was not broadcast over TLS");
    }
}

/// The same transactions over plain TCP are accepted.
#[test]
fn control_the_same_transactions_are_broadcast_over_tcp() {
    let chain = sim(150);
    let s = FakeElectrum::start(chain.clone(), false);
    let b = ElectrumBackend::new(config(&chain, &[s.url()], Duration::from_secs(3))).unwrap();
    for bytes in [20_000usize, 40_000, 100_000] {
        let tx = tx_of(bytes);
        assert_eq!(b.broadcast(&tx.to_hex()).ok(), Some(tx.txid()));
    }
}

/// The rule (the module documentation of `backend.rs`, "unknown is not absent"): a coin a server
/// lists is left out of a scan only on an answer, and "busy" is no answer (`says_not_there`:
/// "any other error is no answer: busy, rate-limited"). `fetch_tx` keeps that. `supply_from`
/// (`backend.rs:1100-1103`) takes any error for a requested transaction as "does not supply it":
/// one server hides the coin, the honest one lists it and is busy when asked for its transaction,
/// and the scan answers "no coins", marked complete. Left from AGP-092; not a wave 5 change.
#[test]
fn a_coin_whose_only_lister_is_busy_for_its_transaction_fails_the_scan() {
    let chain = sim(200);
    let a = spk(0x63);
    let txid = chain.lock().unwrap().credit(0, 9_000, &a, true);
    let (honest, liar) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    liar.knobs().hide.insert(txid.clone());
    honest.knobs().fail.insert("blockchain.transaction.get".into(), "server busy, try again later".into());
    let b = ElectrumBackend::new(config(&chain, &[honest.url(), liar.url()], Duration::from_secs(2))).unwrap();
    let got = b.unspent_marked(&a);
    println!("AGP-102 measure: a scan beside a hiding server while the honest one is busy for the coin's transaction: {:?}",
             got.as_ref().map(|(c, every)| (c.len(), *every)).map_err(|e| e.msg.clone()));
    assert!(got.is_err(), "the scan answered {:?} for a script that holds a confirmed coin", got.map(|(c, every)| (c.len(), every)));
}

/// With the honest server answering, the same scan finds the coin (the liar hides it in vain).
#[test]
fn control_the_same_scan_finds_the_coin_when_the_honest_server_supplies_it() {
    let chain = sim(200);
    let a = spk(0x64);
    let txid = chain.lock().unwrap().credit(0, 9_000, &a, true);
    let (honest, liar) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    liar.knobs().hide.insert(txid.clone());
    let b = ElectrumBackend::new(config(&chain, &[honest.url(), liar.url()], Duration::from_secs(2))).unwrap();
    assert_eq!(b.unspent_marked(&a).map(|(c, every)| (c.len(), every)).ok(), Some((1, true)));
}
