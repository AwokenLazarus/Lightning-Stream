//! AGP-106 (fix wave 6, light client): the neighbours of the fourth audit's holes, each named as
//! the rule that holds. The audit's own tests are `agp102_light.rs`; these are the places next to
//! them that could break the same rules.
//!
//!   * The header sync a call forces is not paid for out of the call's time, and it moves the
//!     call's deadline once: a lookup beside a server that holds every sync is bounded by the sync
//!     before the call, the one forced sync and the call's own deadline.
//!   * A number no integer holds (`1e999`) is not a number to this reader: the line is not JSON,
//!     its server is dropped, and the honest server's proof answers.
//!   * A request line above rustls' 64 kB buffer is written by one deadline, also to a TLS server
//!     that stops reading.
//!   * In a scan only "no such transaction", in the server's words, withdraws a coin its server
//!     listed; busy is no answer (the audit's test), and the words still are one (the control here).
//!
//! Ports: the proxy made here listens on 27840-27849 (the `sim` servers pick their own).
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt_electrum::sim::{test_server_tls, FakeElectrum, SimChain, CHECKPOINT, TEST_CA};
use xbt_electrum::{tls_config, Config, Connection, ElectrumBackend};

static NEXT_PORT: AtomicU16 = AtomicU16::new(27840);

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

/// A TCP proxy that holds every request line containing `needle` for `hold` (the proxy of
/// `agp102_light.rs`).
fn slow_proxy(upstream: SocketAddr, needle: &'static str, hold: Duration) -> String {
    let l = TcpListener::bind(("127.0.0.1", NEXT_PORT.fetch_add(1, Ordering::SeqCst))).unwrap();
    let addr = l.local_addr().unwrap();
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
            std::thread::spawn(move || {
                let up = Arc::new(Mutex::new(up));
                for line in BufReader::new(client).lines() {
                    let Ok(line) = line else { break };
                    let (up, held) = (up.clone(), line.contains(needle));
                    let send = move || {
                        let mut u = up.lock().unwrap();
                        u.write_all(line.as_bytes()).and_then(|_| u.write_all(b"\n")).is_ok()
                    };
                    if held {
                        std::thread::spawn(move || {
                            std::thread::sleep(hold);
                            send()
                        });
                    } else if !send() {
                        break;
                    }
                }
            });
        }
    });
    format!("tcp://{addr}")
}

const TIMEOUT: Duration = Duration::from_millis(400);

/// The rule: the sync a call forces moves the call's deadline once, by what the sync took. So one
/// lookup beside a server that holds every sync to its deadline takes at most the sync before the
/// call, the forced one and the call's own deadline (four timeouts each at the defaults), and the
/// honest server is not flagged for any of it. The hostile server is flagged for each sync it held
/// and for the claim that started one.
#[test]
fn a_lookup_beside_a_server_that_holds_every_sync_is_bounded_and_flags_only_that_server() {
    let chain = sim(300);
    let txid = chain.lock().unwrap().credit(0, 70_000, &spk(0x71), true);
    chain.lock().unwrap().mine(2);
    let (honest, liar) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    {
        let c = chain.lock().unwrap();
        let mut k = liar.knobs();
        k.headers = Some(c.alt_chain(CHECKPOINT + 1, 150, 0x7A));
        k.claim_height.insert(txid.clone(), c.tip_height() as i64 + 1);
    }
    let slow = slow_proxy(liar.addr, "blockchain.block.header", TIMEOUT * 7 / 10);
    let b = ElectrumBackend::new(config(&chain, &[slow.clone(), honest.url()], TIMEOUT)).unwrap();
    let sync = TIMEOUT * 4;
    let t0 = Instant::now();
    let got = b.tx_out(&txid, 0, true).unwrap().unwrap();
    let took = t0.elapsed();
    println!("AGP-106 measure: a lookup beside a server that holds the sync before the call and the one it forces: {} confirmations after {took:?}", got.confirmations);
    assert_eq!(got.confirmations, 3);
    assert!(took >= sync * 2 - TIMEOUT, "both syncs were held: {took:?}");
    assert!(took < sync * 3, "one sync before the call, one forced, and the call's deadline: {took:?}");
    let on_liar = flags_on(&b, &slow);
    assert!(on_liar.iter().filter(|f| f.starts_with("headers:")).count() >= 2, "{on_liar:#?}");
    assert!(on_liar.iter().any(|f| f.contains("above the tip it reports")), "{on_liar:#?}");
    assert_eq!(flags_on(&b, &honest.url()), Vec::<String>::new());
}

/// The rule (B2's since AGP-106, and this reader's by its JSON parser): a number no integer or
/// float holds is not taken for one. `1e999` is outside what `serde_json` reads, so the line is
/// not JSON-RPC: its server is dropped, nothing of the line is used, and the honest server's
/// proof answers the lookup.
#[test]
fn a_height_no_integer_holds_drops_the_server_that_sent_it_and_the_honest_one_answers() {
    let chain = sim(200);
    let txid = chain.lock().unwrap().credit(0, 70_000, &spk(0x72), true);
    let (honest, odd) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    for line in [format!(r#"{{"jsonrpc":"2.0","id":0,"result":[{{"tx_hash":"{txid}","height":1e999}}]}}"#),
                 r#"{"jsonrpc":"2.0","method":"blockchain.headers.subscribe","params":[{"height":1e999,"hex":""}]}"#.to_string(),
                 r#"{"jsonrpc":"2.0","id":0,"result":{"pos":123456789012345678901234567890,"merkle":[],"block_height":-1e999}}"#.to_string()] {
        assert!(serde_json::from_str::<Value>(&line).is_err(), "{line}");
        odd.knobs().line_before = Some(("blockchain.scripthash.get_history".into(), Arc::new(line.into_bytes())));
        let b = ElectrumBackend::new(config(&chain, &[odd.url(), honest.url()], Duration::from_secs(2))).unwrap();
        let got = b.tx_out(&txid, 0, true);
        println!("AGP-106 measure: one server sends a line with a number no integer holds: {:?}",
                 got.as_ref().map(|o| o.as_ref().map(|o| o.confirmations)).map_err(|e| e.msg.clone()));
        assert_eq!(got.unwrap().map(|o| o.confirmations), Some(1));
        assert_eq!(flags_on(&b, &honest.url()), Vec::<String>::new());
    }
}

/// A TLS server that answers `server.version` and then stops reading.
fn deaf_tls_server() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for sock in l.incoming() {
            let Ok(sock) = sock else { break };
            let conn = rustls::ServerConnection::new(test_server_tls()).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, sock);
            let mut line = String::new();
            if BufReader::new(&mut tls).read_line(&mut line).is_err() {
                continue;
            }
            let Ok(req) = serde_json::from_str::<Value>(&line) else { continue };
            let _ = tls.write_all(format!("{}\n", json!({"id": req["id"], "result": ["deaf", "1.4"]})).as_bytes());
            held.push(tls); // open, and never read again
        }
    });
    format!("ssl://localhost:{port}")
}

/// The rule (AGP-097, `Link::send`): a request is written by one deadline, however slowly the
/// server reads. Since AGP-106 a line above rustls' buffer goes out in pieces over TLS; each piece
/// is sent under what is left of the same deadline. 16 MB is more than the loopback's buffers
/// take, so the write must end at the deadline and not when the server reads.
#[test]
fn a_line_above_the_tls_buffer_is_given_up_at_one_deadline_when_the_server_stops_reading() {
    let dir = std::env::temp_dir().join(format!("agp106-light-ca-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ca = dir.join("ca.pem");
    std::fs::write(&ca, TEST_CA).unwrap();
    let c = Connection::new(&deaf_tls_server(), Duration::from_millis(500), Some(tls_config(&[ca.as_path()]).unwrap()), None).unwrap();
    c.connect().unwrap();
    let t0 = Instant::now();
    let got = c.request("blockchain.transaction.broadcast", json!(["00".repeat(8 << 20)]));
    let took = t0.elapsed();
    println!("AGP-106 measure: a 16 MB request line to a TLS server that stops reading, timeout 0.5 s: {:?} after {took:?}",
             got.as_ref().map(|_| "answered").map_err(|e| e.msg.clone()));
    assert!(got.is_err());
    assert!(took < Duration::from_millis(1500), "the write was held for {took:?} past a deadline of 0.5 s");
    assert!(!c.connected(), "a line half written: the server is hung up on");
}

/// The control of the audit's `a_coin_whose_only_lister_is_busy_for_its_transaction_fails_the_scan`:
/// "no such transaction", in the server's own words, is still an answer. The server that listed
/// the coin withdraws it, it is flagged for listing what it does not supply, and the scan answers.
#[test]
fn control_a_lister_that_says_no_such_transaction_has_answered_and_the_scan_goes_on() {
    let chain = sim(200);
    let a = spk(0x73);
    let txid = chain.lock().unwrap().credit(0, 9_000, &a, true);
    let (lister, hider) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    hider.knobs().hide.insert(txid.clone());
    lister.knobs().fail.insert("blockchain.transaction.get".into(), "No such mempool or blockchain transaction".into());
    let b = ElectrumBackend::new(config(&chain, &[lister.url(), hider.url()], Duration::from_secs(2))).unwrap();
    let got = b.unspent_marked(&a);
    assert_eq!(got.map(|(c, every)| (c.len(), every)).map_err(|e| e.msg), Ok((0, true)));
    assert!(flags_on(&b, &lister.url()).iter().any(|f| f.contains("lists a transaction it does not supply")));
}
