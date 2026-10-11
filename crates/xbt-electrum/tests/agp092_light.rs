//! AGP-092 (fix wave 4, light client): the two rules of `backend.rs`, from the sides the AGP-087
//! tests do not take.
//!
//! * Unknown is not absent: "not there" is answered only when every server asked answered.
//! * A call has a deadline, and a server is asked only for what it listed itself.
//!
//! Every test here fails on `5521674` (the fix's base) except the two named `evidence_*`.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use xbt402::funding::ChainBackend;
use xbt_electrum::sim::{FakeElectrum, SimChain, CHECKPOINT};
use xbt_electrum::{scripthash, Config, ElectrumBackend, Kind};
use xbt_primitives::tx::{OutPoint, Tx, TxIn, TxOut};

const BUSY: &str = "server busy";

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

fn backend(chain: &Arc<Mutex<SimChain>>, urls: &[String]) -> ElectrumBackend {
    ElectrumBackend::new(cfg(chain, urls, Duration::from_secs(3))).unwrap()
}

fn flagged(b: &ElectrumBackend, s: &Arc<FakeElectrum>, what: &str) -> bool {
    b.flags().iter().any(|f| f.server == s.url() && f.reason.contains(what))
}

fn gets(s: &Arc<FakeElectrum>) -> usize {
    s.calls.lock().unwrap().iter().filter(|m| *m == "blockchain.transaction.get").count()
}

/// A TCP proxy that holds every request line containing `needle` for `delay_ms` (as `agp087_light.rs`).
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

/// The B2 refund hole's cause, in Rust: one server hides the funding, the honest one serves the
/// transaction and fails the script's history. The funding used to read as "no such output".
#[test]
fn a_hiding_server_and_a_busy_honest_one_are_unknown_not_absent() {
    let chain = sim(200);
    let fund = spk(0x51);
    let f = chain.lock().unwrap().credit(0, 70_000, &fund, true);
    let (liar, honest) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    liar.knobs().hide.insert(f.clone());
    honest.knobs().fail.insert("blockchain.scripthash.get_history".into(), BUSY.into());
    let b = backend(&chain, &[liar.url(), honest.url()]);
    for include_mempool in [true, false] {
        let out = b.tx_out(&f, 0, include_mempool);
        assert_eq!(out.as_ref().err().map(|e| e.kind), Some(Kind::Unreachable), "tx_out answered {out:?}");
    }
    assert!(b.transaction(&f).is_err() && ChainBackend::has_transaction(&b, &f).is_err());
    assert!(ChainBackend::get_tx_out(&b, &f, 0, true).is_err(), "the trait a wallet calls says so too");
    assert!(b.call("gettxout", &serde_json::json!([f, 0, true])).is_err() && b.call("getrawtransaction", &serde_json::json!([f, true])).is_err());
    // the honest server answers again: the funding is there, proven
    honest.knobs().fail.clear();
    assert_eq!(b.tx_out(&f, 0, true).unwrap().unwrap().confirmations, 1);
    assert!(ChainBackend::has_transaction(&b, &f).unwrap());
}

/// One step on: the honest server lists the funding in a block and then fails the proof request,
/// while a liar calls it unconfirmed. "Unconfirmed" used to win, and without the mempool that is None.
#[test]
fn an_unanswered_proof_is_unknown_not_unconfirmed() {
    let chain = sim(200);
    let fund = spk(0x52);
    let f = chain.lock().unwrap().credit(0, 70_000, &fund, true);
    let (liar, honest) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    liar.knobs().claim_height.insert(f.clone(), 0);
    liar.knobs().fail.insert("blockchain.transaction.get_merkle".into(), BUSY.into());
    honest.knobs().fail.insert("blockchain.transaction.get_merkle".into(), BUSY.into());
    let b = backend(&chain, &[liar.url(), honest.url()]);
    let out = b.tx_out(&f, 0, false);
    assert!(out.is_err(), "confirmed funding, proof unanswered, and gettxout without the mempool answered {out:?}");
    // with the mempool the liar's claim is an answer a caller cannot be hurt by: 0 confirmations
    assert_eq!(b.tx_out(&f, 0, true).unwrap().unwrap().confirmations, 0);
    assert!(b.unspent(&fund).is_err(), "nor is the coin left out of the unspent list");
    honest.knobs().fail.clear();
    assert_eq!(b.tx_out(&f, 0, false).unwrap().unwrap().confirmations, 1);
    assert_eq!(b.unspent(&fund).unwrap().len(), 1);
}

/// A JSON-RPC error that is not "no such transaction" is no answer.
#[test]
fn a_busy_error_is_not_no_such_transaction() {
    let chain = sim(200);
    let f = chain.lock().unwrap().credit(0, 70_000, &spk(0x53), true);
    let s = FakeElectrum::start(chain.clone(), false);
    s.knobs().fail.insert("blockchain.transaction.get".into(), BUSY.into());
    let b = backend(&chain, &[s.url()]);
    assert!(b.tx_out(&f, 0, true).is_err() && ChainBackend::has_transaction(&b, &f).is_err() && b.spending_tx(&f, 0).is_err());
    // a server's own "no such transaction" still is one
    s.knobs().fail.clear();
    let never = "ab".repeat(32);
    assert_eq!(b.tx_out(&never, 0, true).unwrap(), None);
    assert!(!ChainBackend::has_transaction(&b, &never).unwrap());
}

/// `scantxoutset`: a coin whose transaction the listing server does not get to supply used to be
/// left out, a shorter list a caller cannot tell from "no coins".
#[test]
fn a_coin_whose_transaction_went_unanswered_fails_the_scan() {
    let chain = sim(200);
    let a = spk(0x54);
    chain.lock().unwrap().credit(0, 70_000, &a, true);
    let s = FakeElectrum::start(chain.clone(), false);
    let slow = SlowProxy::start(s.addr, "blockchain.transaction.get", 0);
    let b = ElectrumBackend::new(cfg(&chain, &[slow.url()], Duration::from_millis(400))).unwrap();
    assert_eq!(b.block_count().unwrap(), 201);
    slow.delay_ms.store(1_500, Ordering::SeqCst);
    let got = b.unspent(&a);
    assert!(got.is_err(), "the scan answered {got:?}");
    slow.delay_ms.store(0, Ordering::SeqCst);
    assert_eq!(b.unspent(&a).unwrap().len(), 1);
}

/// The stall with entries the server can supply: real transactions that have nothing to do with the
/// script, each answered slowly. The first one fetched shows the list is invented and ends it.
#[test]
fn a_list_of_real_unrelated_transactions_ends_at_the_first() {
    let chain = sim(200);
    let fund = spk(0x55);
    let f = chain.lock().unwrap().credit(0, 70_000, &fund, true);
    let unrelated: Vec<String> = (0..40u8).map(|k| chain.lock().unwrap().credit(0, 1_000 + k as u64, &spk(0x80 + k), true)).collect();
    let (liar, honest) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    liar.knobs().extra_history.insert(scripthash(&fund), unrelated.iter().map(|t| (t.clone(), 150)).collect());
    let slow = SlowProxy::start(liar.addr, "blockchain.transaction.get", 250);
    let timeout = Duration::from_secs(1);
    let b = ElectrumBackend::new(cfg(&chain, &[slow.url(), honest.url()], timeout)).unwrap();
    assert_eq!(b.block_count().unwrap(), 241);
    let before = gets(&liar);
    let t = Instant::now();
    assert!(b.tx_out(&f, 0, false).unwrap().is_some());
    assert!(t.elapsed() < timeout * 2, "{:?}", t.elapsed());
    assert!(gets(&liar) - before <= 3, "asked the liar for {} transactions", gets(&liar) - before);
    assert!(b.flags().iter().any(|fl| fl.server == slow.url() && fl.reason.contains("neither pays nor spends")), "{:?}", b.flags());
}

/// The stall nothing can cut short: entries that pay the script (an invented payment cannot be told
/// from an unconfirmed one), each batch answered inside the timeout. The call's deadline ends it,
/// the server is flagged, and the honest server's proof still answers.
#[test]
fn a_slow_list_of_payments_ends_at_the_call_deadline() {
    let chain = sim(200);
    let fund = spk(0x56);
    let f = chain.lock().unwrap().credit(0, 70_000, &fund, true);
    let (liar, honest) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    {
        let mut k = liar.knobs();
        let mut list = Vec::new();
        for n in 0..200u32 {
            let tx = Tx::new(2, vec![TxIn::new(OutPoint::new([0x77; 32], n), 0)], vec![TxOut::new(1_000, fund.clone())], 0);
            list.push((tx.txid(), 0));
            k.invented.insert(tx.txid(), tx);
        }
        k.extra_history.insert(scripthash(&fund), list);
    }
    let slow = SlowProxy::start(liar.addr, "blockchain.transaction.get", 600);
    let mut c = cfg(&chain, &[slow.url(), honest.url()], Duration::from_secs(1));
    c.call_deadline = Some(Duration::from_millis(1_500));
    let b = ElectrumBackend::new(c).unwrap();
    assert_eq!(b.block_count().unwrap(), 201);
    let t = Instant::now();
    assert_eq!(b.tx_out(&f, 0, false).unwrap().unwrap().confirmations, 1);
    let took = t.elapsed();
    assert!(took < Duration::from_millis(2_500), "held {took:?} with a call deadline of 1.5 s");
    assert!(b.flags().iter().any(|fl| fl.server == slow.url() && fl.reason.contains("transaction.get")), "{:?}", b.flags());
}

/// One claim per server and transaction: a second block height for it is flagged and not used.
#[test]
fn a_transaction_listed_twice_is_one_claim() {
    let chain = sim(200);
    let fund = spk(0x57);
    let f = chain.lock().unwrap().credit(0, 70_000, &fund, true);
    let liar = FakeElectrum::start(chain.clone(), false);
    liar.knobs().extra_history.insert(scripthash(&fund), (0..30).map(|x| (f.clone(), 150 + x)).collect());
    let b = backend(&chain, &[liar.url()]);
    let merkle = |s: &Arc<FakeElectrum>| s.calls.lock().unwrap().iter().filter(|m| *m == "blockchain.transaction.get_merkle").count();
    assert_eq!(b.tx_out(&f, 0, false).unwrap().unwrap().confirmations, 1);
    assert!(merkle(&liar) <= 2, "{} proof requests for one transaction", merkle(&liar));
    assert!(flagged(&b, &liar, "at two heights"), "{:?}", b.flags());
}

/// Found by the regtest interop run: electrs lists a transaction twice while a block arrives (once
/// from its mempool, once from the block). That is not a lie: no flag, and the block height is the
/// claim, whichever entry comes first.
#[test]
fn evidence_a_mempool_and_a_block_entry_for_one_transaction_are_one_honest_claim() {
    let chain = sim(200);
    let fund = spk(0x5b);
    let f = chain.lock().unwrap().credit(0, 70_000, &fund, true);
    for first in [true, false] {
        let s = FakeElectrum::start(chain.clone(), false);
        if first {
            s.knobs().claim_height.insert(f.clone(), 0);
            s.knobs().extra_history.insert(scripthash(&fund), vec![(f.clone(), 201), (f.clone(), 201)]);
        } else {
            s.knobs().extra_history.insert(scripthash(&fund), vec![(f.clone(), 0), (f.clone(), 201)]);
        }
        let b = backend(&chain, &[s.url()]);
        assert_eq!(b.tx_out(&f, 0, false).unwrap().unwrap().confirmations, 1);
        assert!(b.flags().is_empty(), "{:?}", b.flags());
    }
}

/// Evidence (passes before and after): a spend that only an unanswered proof would confirm does not
/// block the refund. The search for a spend is the one place that does not wait for every server.
#[test]
fn evidence_an_unproven_spend_does_not_hold_the_refund_back() {
    let chain = sim(200);
    let fund = [vec![0x00, 0x20], vec![0x58; 32]].concat();
    let f = chain.lock().unwrap().credit(0, 100_000, &fund, true);
    let fake = Tx::new(2, vec![TxIn::new(OutPoint::from_display(&f, 0).unwrap(), 0)], vec![TxOut::new(99_000, spk(0x59))], 0);
    let (liar, honest) = (FakeElectrum::start(chain.clone(), false), FakeElectrum::start(chain.clone(), false));
    {
        let mut k = liar.knobs();
        k.invented.insert(fake.txid(), fake.clone());
        k.extra_history.insert(scripthash(&fund), vec![(fake.txid(), 201)]);
    }
    let slow = SlowProxy::start(liar.addr, "blockchain.transaction.get_merkle", 1_500);
    let b = ElectrumBackend::new(cfg(&chain, &[slow.url(), honest.url()], Duration::from_millis(400))).unwrap();
    assert!(b.tx_out(&f, 0, true).unwrap().is_some(), "an invented spend with no proof must not read as spent, nor as an error");
}

/// Evidence: with every configured server hiding a transaction, the backend cannot know better.
/// This is the stated limit; a caller that books a loss on it must ask for proof of the spend
/// (`ElectrumBackend::spending_tx` with a confirmed status), as B2's refund now does.
#[test]
fn evidence_every_server_hiding_reads_as_absent() {
    let chain = sim(200);
    let fund = spk(0x5a);
    let f = chain.lock().unwrap().credit(0, 70_000, &fund, true);
    let s = FakeElectrum::start(chain.clone(), false);
    s.knobs().hide.insert(f.clone());
    let b = backend(&chain, &[s.url()]);
    assert_eq!(b.tx_out(&f, 0, true).unwrap(), None);
    assert_eq!(b.spending_tx(&f, 0).unwrap(), None, "and no spend is claimed for it");
}

/// Found by the regtest interop run: electrs negotiates protocol 1.4 until it has indexed a v2
/// header, and refuses headers on that connection from then on. A client that connected early kept
/// the connection and never synced. A refused tip now ends the connection; the next round connects
/// and negotiates again.
#[test]
fn a_server_that_refuses_its_tip_is_reconnected_to() {
    let chain = sim(200);
    let s = FakeElectrum::start(chain.clone(), false);
    s.knobs().fail.insert("blockchain.headers.subscribe".into(), "refusing block headers to a client at protocol 1.4".into());
    let b = backend(&chain, &[s.url()]);
    assert!(b.block_count().is_err());
    let versions = |s: &Arc<FakeElectrum>| s.calls.lock().unwrap().iter().filter(|m| *m == "server.version").count();
    assert_eq!(versions(&s), 1);
    s.knobs().fail.clear();
    assert_eq!(b.block_count().unwrap(), 200);
    assert_eq!(versions(&s), 2, "it negotiated again on a new connection");
}
