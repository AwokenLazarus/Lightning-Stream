//! AGP-087 second closure audit, area LIGHT: sides of review E1 the AGP-081 fix did not cover.
//! The tests named `hole_*` FAIL on `f0554d0` (each states the behaviour a closed E1 would show);
//! the tests named `measure_*` pass and print a number.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use xbt402::funding::ChainBackend;
use xbt_electrum::sim::{coinbase, FakeElectrum, SimChain, CHECKPOINT};
use xbt_electrum::{scripthash, tls_config, Config, Connection, ElectrumBackend};

fn spk(b: u8) -> Vec<u8> {
    [vec![0x00, 0x14], vec![b; 20]].concat()
}

fn sim(height: u32) -> Arc<Mutex<SimChain>> {
    Arc::new(Mutex::new(SimChain::new(height, 0)))
}

fn cfg(chain: &Arc<Mutex<SimChain>>, urls: &[String], timeout: Duration) -> Config {
    let mut c = Config::new(&urls.iter().map(String::as_str).collect::<Vec<_>>(), "regtest");
    c.checkpoint = Some((CHECKPOINT, hex::encode(chain.lock().unwrap().hash_at(CHECKPOINT))));
    c.timeout = timeout;
    c.sync_interval = Duration::ZERO;
    c
}

/// A TCP proxy in front of a server: every request line that contains `needle` is held `delay_ms`
/// before it is passed on (a server that is slow on one method only).
struct SlowProxy {
    addr: SocketAddr,
    delay_ms: Arc<AtomicU64>,
}

impl SlowProxy {
    fn start(upstream: SocketAddr, needle: &'static str, delay_ms: u64) -> Self {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let delay = Arc::new(AtomicU64::new(delay_ms));
        let d = delay.clone();
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
                let d = d.clone();
                std::thread::spawn(move || {
                    let mut up = up;
                    for line in BufReader::new(client).lines() {
                        let Ok(line) = line else { break };
                        if line.contains(needle) {
                            std::thread::sleep(Duration::from_millis(d.load(Ordering::SeqCst)));
                        }
                        if up.write_all(line.as_bytes()).and_then(|_| up.write_all(b"\n")).is_err() {
                            break;
                        }
                    }
                    let _ = up.shutdown(std::net::Shutdown::Both);
                });
            }
        });
        Self { addr, delay_ms: delay }
    }

    fn url(&self) -> String {
        format!("tcp://{}", self.addr)
    }
}

fn gets(s: &Arc<FakeElectrum>) -> usize {
    s.calls.lock().unwrap().iter().filter(|m| *m == "blockchain.transaction.get").count()
}

/// E1, history path. One hostile server beside an honest one lists history entries for the funding
/// script that no server can supply, and answers each `blockchain.transaction.get` inside the
/// request timeout. Every `gettxout` of the funding then costs entries x delay; nothing bounds the
/// call (the header sync has a deadline of 4 x timeout, this path has none).
/// On mainnet defaults: 10,000 entries x just under 15 s = about 41 hours per call.
#[test]
fn hole_one_slow_server_holds_gettxout_for_entries_times_delay() {
    let chain = sim(200);
    let fund = spk(0x41);
    let f = chain.lock().unwrap().credit(0, 70_000, &fund, true);
    let (liar, honest) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    let n = 40u32;
    liar.knobs().extra_history.insert(scripthash(&fund), (0..n).map(|k| (coinbase(3_000_000 + k, 9).txid(), 150)).collect());
    let slow = SlowProxy::start(liar.addr, "blockchain.transaction.get", 250);
    let timeout = Duration::from_secs(1);
    let b = ElectrumBackend::new(cfg(&chain, &[slow.url(), honest.url()], timeout)).unwrap();
    assert_eq!(b.block_count().unwrap(), 201);
    let t = Instant::now();
    let out = b.tx_out(&f, 0, false).unwrap();
    let took = t.elapsed();
    println!("AGP-087 measure: gettxout with {n} unfetchable entries, 250 ms per transaction.get, timeout 1 s: {took:?}; flags: {:?}",
             b.flags().iter().map(|f| f.reason.clone()).collect::<Vec<_>>());
    assert!(out.is_some(), "the honest server's proof still answers");
    assert!(took < timeout * 4, "one slow server among honest ones held gettxout for {took:?} (4 x timeout = {:?})", timeout * 4);
}

/// The same entries with no delay: the server that invented them is never flagged (the check in
/// `flag_invented` only judges transactions it could fetch), so nothing tells the operator.
#[test]
fn hole_an_invented_history_no_server_can_supply_is_not_flagged() {
    let chain = sim(200);
    let fund = spk(0x42);
    let f = chain.lock().unwrap().credit(0, 70_000, &fund, true);
    let (liar, honest) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    liar.knobs().extra_history.insert(scripthash(&fund), (0..50u32).map(|k| (coinbase(4_000_000 + k, 9).txid(), 150)).collect());
    let b = ElectrumBackend::new(cfg(&chain, &[liar.url(), honest.url()], Duration::from_secs(3))).unwrap();
    assert!(b.tx_out(&f, 0, false).unwrap().is_some());
    assert!(b.flags().iter().any(|fl| fl.server == liar.url()), "50 invented entries, no flag: {:?}", b.flags());
}

/// The crate docs say an invented entry is "fetched once". It is fetched again on every call, from
/// every server: a transaction no server supplies is not remembered.
#[test]
fn hole_invented_entries_are_fetched_again_on_every_call() {
    let chain = sim(200);
    let fund = spk(0x43);
    let f = chain.lock().unwrap().credit(0, 70_000, &fund, true);
    let (liar, honest) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    liar.knobs().extra_history.insert(scripthash(&fund), (0..50u32).map(|k| (coinbase(5_000_000 + k, 9).txid(), 150)).collect());
    let b = ElectrumBackend::new(cfg(&chain, &[liar.url(), honest.url()], Duration::from_secs(3))).unwrap();
    assert!(b.tx_out(&f, 0, false).unwrap().is_some());
    let first = gets(&liar) + gets(&honest);
    assert!(b.tx_out(&f, 0, false).unwrap().is_some());
    let second = gets(&liar) + gets(&honest) - first;
    println!("AGP-087 measure: transaction.get requests, first gettxout {first}, second gettxout {second}");
    assert!(second < 20, "the second gettxout asked for the 50 invented transactions again: {second} requests");
}

/// AGP-081 made "no server answered get_history / listunspent" an error. The same case one step
/// to the side is still an answer: when every server fails `blockchain.transaction.get` (here: a
/// timeout), `tx_out` says "no such output" and `has_transaction` says "no such transaction".
/// A caller reads that as spent or never funded.
#[test]
fn hole_no_answer_to_transaction_get_reads_as_no_such_transaction() {
    let chain = sim(200);
    let fund = spk(0x44);
    let f = chain.lock().unwrap().credit(0, 70_000, &fund, true);
    let honest = FakeElectrum::start(chain.clone(), false);
    let slow = SlowProxy::start(honest.addr, "blockchain.transaction.get", 0);
    let b = ElectrumBackend::new(cfg(&chain, &[slow.url()], Duration::from_millis(400))).unwrap();
    assert_eq!(b.block_count().unwrap(), 201);
    slow.delay_ms.store(1_500, Ordering::SeqCst); // past the timeout: no answer at all
    let out = b.tx_out(&f, 0, true);
    let has = ChainBackend::has_transaction(&b, &f);
    println!("AGP-087 measure: tx_out = {out:?}; has_transaction = {has:?}");
    assert!(out.is_err(), "no server answered transaction.get, and tx_out answered {out:?}");
    assert!(has.is_err(), "no server answered transaction.get, and has_transaction answered {has:?}");
}

/// TLS (the mainnet transport): the handshake has a read timeout per read, not a deadline. A server
/// that sends one byte of a handshake record inside each timeout holds `connect()`, and with it
/// `live()`, which every backend call goes through and which waits for every reconnect.
/// A full record is 16,384 bytes: at one byte per (15 s less a little) that is about 68 hours.
#[test]
fn hole_a_trickled_tls_handshake_holds_connect_past_its_timeout() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let Ok((mut s, _)) = l.accept() else { return };
        let mut hello = [0u8; 4096];
        let _ = s.read(&mut hello);
        // a handshake record header announcing 16,384 bytes, then its body one byte at a time
        let _ = s.write_all(&[0x16, 0x03, 0x03, 0x40, 0x00]);
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(100));
            if s.write_all(&[0]).is_err() {
                return;
            }
        }
    });
    let timeout = Duration::from_millis(300);
    let c = Connection::new(&format!("ssl://localhost:{port}"), timeout, Some(tls_config(&[]).unwrap()), None).unwrap();
    let t = Instant::now();
    let r = c.connect();
    let took = t.elapsed();
    println!("AGP-087 measure: TLS connect against a 1 byte / 100 ms handshake, timeout 300 ms: {took:?} ({})",
             r.as_ref().err().map(|e| e.to_string()).unwrap_or_default());
    assert!(r.is_err());
    assert!(took < timeout * 4, "the handshake was held for {took:?} with a 300 ms timeout (the server stopped at 4 s)");
}

/// A configured server that accepts connections and never answers (or a black-holed address) is
/// reconnected to, and waited on for a full timeout, by every `live()` call: several per `gettxout`.
/// Passing: it prints what one dead server costs each call.
#[test]
fn measure_a_silent_server_taxes_every_call() {
    let chain = sim(200);
    let fund = spk(0x45);
    let f = chain.lock().unwrap().credit(0, 70_000, &fund, true);
    let honest = FakeElectrum::start(chain.clone(), false);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = format!("tcp://{}", l.local_addr().unwrap());
    let held = Arc::new(Mutex::new(Vec::new()));
    let h2 = held.clone();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            h2.lock().unwrap().push(c); // accepted, never answered
        }
    });
    let timeout = Duration::from_millis(500);
    let b = ElectrumBackend::new(cfg(&chain, &[dead, honest.url()], timeout)).unwrap();
    let t = Instant::now();
    assert_eq!(b.block_count().unwrap(), 201);
    let first = t.elapsed();
    let t = Instant::now();
    assert!(b.tx_out(&f, 0, false).unwrap().is_some());
    let cold = t.elapsed();
    let t = Instant::now();
    assert!(b.tx_out(&f, 0, false).unwrap().is_some());
    let warm = t.elapsed();
    println!("AGP-087 measure: one silent server, timeout 500 ms: block_count {first:?}, first gettxout {cold:?}, second gettxout {warm:?}, connections it accepted {}",
             held.lock().unwrap().len());
}

/// One more step along the history path: a server may list the same transaction many times, each
/// with a height above our tip. `confirmed()` forces a whole sync round (every server asked for its
/// tip again) for each such claim before it reaches the honest server's claim. A round can last
/// `sync_deadline`; with 10,000 claims that is 10,000 rounds inside one `gettxout`.
#[test]
fn hole_each_claimed_height_above_the_tip_forces_a_sync_round() {
    let chain = sim(200);
    let fund = spk(0x46);
    let f = chain.lock().unwrap().credit(0, 70_000, &fund, true);
    let (liar, honest) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    let n = 200u32;
    {
        let mut k = liar.knobs();
        k.claim_height.insert(f.clone(), 999_999);
        k.extra_history.insert(scripthash(&fund), (0..n).map(|x| (f.clone(), 1_000_000 + x as i64)).collect());
    }
    let b = ElectrumBackend::new(cfg(&chain, &[liar.url(), honest.url()], Duration::from_secs(3))).unwrap();
    assert_eq!(b.block_count().unwrap(), 201);
    let tips = |s: &Arc<FakeElectrum>| s.calls.lock().unwrap().iter().filter(|m| *m == "blockchain.headers.subscribe").count();
    let before = tips(&honest);
    let t = Instant::now();
    assert!(b.tx_out(&f, 0, false).unwrap().is_some());
    let rounds = tips(&honest) - before;
    println!("AGP-087 measure: {n} claims above the tip for one txid: {rounds} sync rounds in one gettxout, {:?}; flags {}", t.elapsed(), b.flags().len());
    assert!(rounds <= 5, "{rounds} sync rounds forced by one server's {n} history entries");
}
