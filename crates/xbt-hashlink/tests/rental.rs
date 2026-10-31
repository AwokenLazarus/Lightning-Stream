//! A whole rental in one process: the stand-in pool as the hashtaker's gateway, the hashmaker and the
//! hashtaker over a real link on loopback, and stand-in miners. Work is what a share's hash proves, on
//! each side by its own count, and a renter pays ahead. The pass lines: both sides' proven counts agree,
//! and every payment was due by [`order`]'s rule; a stopped payment stops the hash with no share forwarded
//! past what's paid; a stopped hash stops the payments. Each runs with the lab's rail over the link,
//! and with slices paid the wallet's way: one paid request per slice through a stand-in for the wallet's
//! signer and the hashmaker's gateway, which passes each request to the hashmaker's slice endpoint.

use secp256k1::PublicKey;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use xbt_hashlink::listing::{self, Hashrate};
use xbt_hashlink::meter::share_work;
use xbt_hashlink::msg::Terms;
use xbt_hashlink::rail::{LabHashtaker, LabSeller, SignerPayer};
use xbt_hashlink::{hashtaker, hashmaker, noise, order, standin, trust};

/// About 4096 hashes a share: the chain's own format, at a difficulty a CPU reaches.
const DIFF: f64 = 1.0 / (1u64 << 20) as f64;
const SHARES_PER_SLICE: u128 = 8;
/// The tests pick free ports by binding and letting go: one test at a time, so no two pick the same.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

/// `N` distinct free ports: all bound at once before any is let go, so none is picked twice. They
/// come from below the kernel's ephemeral range (on Linux 32768 and up by default): a port the
/// kernel hands out itself can be taken, between being let go and bound again, as the source port
/// of any outgoing connection on the machine.
fn ports<const N: usize>() -> [String; N] {
    loop {
        let mut b = [0u8; 2];
        getrandom::getrandom(&mut b).unwrap();
        let base = 20_000 + u16::from_le_bytes(b) % 12_000;
        let ls: Vec<TcpListener> =
            (0..N as u16).filter_map(|i| TcpListener::bind(("127.0.0.1", base + i * 7)).ok()).collect();
        if ls.len() == N {
            return std::array::from_fn(|i| ls[i].local_addr().unwrap().to_string());
        }
    }
}

fn wait_for(addr: &str) {
    for _ in 0..200 {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("{addr} never came up");
}

fn terms() -> Terms {
    Terms { slice_work: SHARES_PER_SLICE * share_work(DIFF), price_msat: 5_000, grace_ms: 1500, start_slices: 0 }
}

fn tempdir() -> PathBuf {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).unwrap();
    let d = std::env::temp_dir().join(format!("hashlink-{}", hex::encode(b)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The wallet's signer and the hashmaker's gateway in one: `xbt402_pay` POSTs the body to the
/// hashmaker's slice endpoint and answers as the signer does (status 200, verdict allow), and
/// counts what it was asked; `ticket_stop` is recorded.
fn fake_wallet(dir: &std::path::Path, slices: String, calls: Arc<Mutex<Vec<Value>>>) -> PathBuf {
    let sock = dir.join("signer.sock");
    let l = UnixListener::bind(&sock).unwrap();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(c) = c else { continue };
            let mut line = String::new();
            BufReader::new(c.try_clone().unwrap()).read_line(&mut line).unwrap();
            let req: Value = serde_json::from_str(&line).unwrap();
            let p = &req["params"];
            calls.lock().unwrap().push(req.clone());
            let result = match req["method"].as_str() {
                // as the signer does: a slice whose price is above the ceiling the buyer was shown is paid nothing
                Some("xbt402_pay") if p["price_ceiling"]["request_msat"].as_u64().is_some_and(|c| c < terms().price_msat) => {
                    json!({"verdict": "deny", "rule": "price_ceiling", "charged_sats": 0})
                }
                Some("xbt402_pay") => {
                    let url = p["url"].as_str().unwrap();
                    let path = &url[url.find("/hashrate").unwrap()..];
                    let body = p["body"].as_str().unwrap();
                    let mut s = TcpStream::connect(&slices).unwrap();
                    write!(s, "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
                    let mut out = String::new();
                    s.read_to_string(&mut out).unwrap();
                    let status: u64 = out.split_whitespace().nth(1).unwrap().parse().unwrap();
                    json!({"verdict": "allow", "rail": "ticket", "status": status, "session": "s1", "charged_sats": if status == 200 { 5 } else { 0 }})
                }
                _ => json!({"ok": true}),
            };
            let mut w = c;
            writeln!(w, "{}", json!({"id": 1, "result": result})).unwrap();
        }
    });
    sock
}

struct Run {
    hashmaker: Value,
    hashtaker: Value,
    pool: Value,
    miners_done_ms: u64,
    miners: Vec<standin::MinerResult>,
    wallet_calls: Vec<Value>,
}

fn rental(stop_paying_after: Option<u64>, miner_secs: u64, wallet: bool) -> Run {
    rental_cut(stop_paying_after, miner_secs, wallet, None)
}

/// A TCP relay between the hashtaker and the hashmaker that can cut every connection through it:
/// the link drops as it does when a network goes away for a moment.
fn cuttable(listen: String, to: String) -> Arc<Mutex<Vec<TcpStream>>> {
    let open: Arc<Mutex<Vec<TcpStream>>> = Arc::default();
    let l = TcpListener::bind(&listen).unwrap();
    let o = open.clone();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(a) = c else { continue };
            let Ok(b) = TcpStream::connect(&to) else { continue };
            {
                let mut g = o.lock().unwrap();
                g.push(a.try_clone().unwrap());
                g.push(b.try_clone().unwrap());
            }
            for (mut x, mut y) in [(a.try_clone().unwrap(), b.try_clone().unwrap()), (b, a)] {
                thread::spawn(move || {
                    let _ = std::io::copy(&mut x, &mut y);
                    let _ = y.shutdown(std::net::Shutdown::Both);
                });
            }
        }
    });
    open
}

fn cut(open: &Arc<Mutex<Vec<TcpStream>>>) {
    for s in open.lock().unwrap().drain(..) {
        let _ = s.shutdown(std::net::Shutdown::Both);
    }
}

fn rental_cut(stop_paying_after: Option<u64>, miner_secs: u64, wallet: bool, cut_after: Option<Duration>) -> Run {
    let _serial = serial();
    let [pool_a, link_a, miners_a, slices_a, relay_a] = ports::<5>();
    let dir = tempdir();
    let pool_report = dir.join("pool.json");
    {
        let (a, r) = (pool_a.clone(), pool_report.clone());
        thread::spawn(move || {
            standin::pool(standin::PoolConfig { listen: a, diff: DIFF, job_every: Duration::from_millis(700), report: Some(r) })
        });
    }
    wait_for(&pool_a);
    let hk = noise::fresh_key();
    let hpub = PublicKey::from_secret_key(secp256k1::SECP256K1, &hk);
    let h = {
        let cfg = hashmaker::Config {
            miners: miners_a.clone(),
            link: link_a.clone(),
            key: hk,
            terms: terms(),
            report: None,
            slices: wallet.then(|| slices_a.clone()),
            fallback: None,
            rentable: None,
            min_slice_time: hashmaker::MIN_SLICE_TIME,
        };
        thread::spawn(move || hashmaker::run(cfg, Box::<LabSeller>::default()).unwrap())
    };
    wait_for(&link_a);
    let to_hashmaker = match cut_after {
        Some(after) => {
            let open = cuttable(relay_a.clone(), link_a.clone());
            thread::spawn(move || {
                thread::sleep(after);
                cut(&open);
            });
            relay_a.clone()
        }
        None => link_a.clone(),
    };
    let calls: Arc<Mutex<Vec<Value>>> = Arc::default();
    let payer = wallet.then(|| {
        SignerPayer::new(fake_wallet(&dir, slices_a.clone(), calls.clone()), "https://hashmaker.example/hashrate".into(), "hashrate".into(), terms().price_msat, None,
                         Some(600), std::time::Duration::from_secs(5))
    });
    let b = {
        let cfg = hashtaker::Config {
            hashmaker: to_hashmaker,
            hashmaker_key: hpub,
            key: noise::fresh_key(),
            upstream: pool_a.clone(),
            user: "hashtaker.rented".into(),
            terms: terms(),
            rental: "rental-1".into(),
            listing: "lab".into(),
            stop_paying_after,
            // with no fallback, a miner that comes back waits up to ten seconds for its name to be
            // taken (hashmaker::LOCK_WAIT): a shorter limit would end a rental that was about to go on
            idle: Duration::from_secs(if cut_after.is_some() { 15 } else { 3 }),
            duration: Some(Duration::from_secs(120)),
            report: None,
            payer: payer.map(|p| Box::new(p) as Box<dyn xbt_hashlink::rail::Payer>),
            miners: 0,
            budget_msat: None,
            cut: None,
            live: None,
            gateway_api: None,
            allow_unblinded: true,
        };
        thread::spawn(move || hashtaker::run(cfg, Box::<LabHashtaker>::default()).unwrap())
    };
    thread::sleep(Duration::from_millis(300));
    let miners: Vec<_> = (0..2)
        .map(|i| {
            let a = miners_a.clone();
            thread::spawn(move || {
                standin::miner(standin::MinerConfig {
                    pool: a,
                    user: format!("hashmaker.m{i}"),
                    max_rate: 8.0,
                    bad_every: 7,
                    duration: Some(Duration::from_secs(miner_secs)),
                    // miners whose rental waits for its hashtaker are let go in the lab (no fallback) and connect again
                    reconnect: cut_after.is_some(),
                    extranonce_subscribe: false,
                    bind: None,
                })
            })
        })
        .collect();
    let miners: Vec<standin::MinerResult> = miners.into_iter().map(|m| m.join().unwrap().unwrap()).collect();
    let miners_done_ms = xbt_hashlink::now_ms();
    let hashtaker = b.join().unwrap();
    let hashmaker = h.join().unwrap();
    // the stand-in pool rewrites its report every 500 ms: wait past one rewrite, then for the file,
    // which on a loaded machine may not be there yet
    thread::sleep(Duration::from_millis(700));
    let pool = (0..200)
        .find_map(|_| {
            let got = std::fs::read(&pool_report).ok().and_then(|b| serde_json::from_slice(&b).ok());
            if got.is_none() {
                thread::sleep(Duration::from_millis(50));
            }
            got
        })
        .expect("the stand-in pool wrote its report within 10 s");
    let wallet_calls = calls.lock().unwrap().clone();
    Run { hashmaker, hashtaker, pool, miners_done_ms, miners, wallet_calls }
}

fn w(v: &Value) -> u128 {
    v.as_str().unwrap().parse().unwrap()
}

/// Is another slice due by the renter's rule, at this count, with shares of this size?
fn due(terms: &Terms, proven: u128, largest_share: u128, paid: u64) -> bool {
    order::Standing { proven, largest_share, paid, start_slices: terms.start_slices, slice_work: terms.slice_work, price_msat: terms.price_msat, msat_a_second: 0.0, buy_secs: 0.0 }.pay_next()
}

/// Every payment was due by the hashtaker's rule when it was made: each receipt says its proven count
/// then. (A share is worth `sw` throughout; a channel's largest share is at most that.)
fn each_payment_was_due(b: &Value, terms: &Terms, sw: u128) {
    for r in b["receipts"].as_array().unwrap() {
        let slice = r["slice"].as_u64().unwrap();
        assert!(due(terms, w(&r["work"]), sw, slice - 1), "slice {slice} paid when it wasn't due: {r}");
    }
}

fn paid_then_stopped(wallet: bool) {
    let r = rental(None, 10, wallet);
    let (s, sw) = (terms().slice_work, share_work(DIFF));
    let paid = r.hashmaker["paid"].as_u64().unwrap();
    assert!(paid >= 3, "only {paid} slices: {}", r.hashmaker);
    // every slice paid once, each when the rule said; the two sides' proven counts are the same, each its own
    assert_eq!(r.hashtaker["released"].as_u64().unwrap(), paid);
    assert_eq!(r.hashmaker["receipts"].as_array().unwrap().len() as u64, paid);
    each_payment_was_due(&r.hashtaker, &terms(), sw);
    assert_eq!(r.hashmaker["meter"]["work"], r.hashtaker["meter"]["work"], "{} / {}", r.hashmaker, r.hashtaker);
    assert_eq!(r.hashmaker["meter"]["proven"], r.hashtaker["meter"]["proven"]);
    let work = w(&r.hashmaker["meter"]["work"]);
    assert!(work <= order::paid_work(paid, 0, s), "proven work stayed within what was paid: {}", r.hashmaker);
    assert_eq!(r.hashmaker["stopped"]["unpaidWork"], "0", "{}", r.hashmaker);
    assert!(!due(&terms(), work, 0, paid), "nothing due was left unpaid: {}", r.hashtaker);
    // the gateway saw only the hashtaker's name, and the work both meters counted
    let users = r.pool["users"].as_object().unwrap();
    assert_eq!(users.keys().collect::<Vec<_>>(), vec!["hashtaker.rented"]);
    assert_eq!(w(&r.pool["work"]), work, "{}", r.pool);
    // a share that doesn't prove goes no further than the hashmaker, which answers the miner itself: the
    // gateway has nothing to reject, and the hashtaker nothing to refuse
    assert_eq!(r.pool["rejected"], 0, "{}", r.pool);
    assert_eq!(r.hashtaker["meter"]["rejected"], 0, "{}", r.hashtaker);
    assert_eq!(r.hashtaker["meter"]["refused"], 0, "{}", r.hashtaker);
    let (submitted, told): (u64, u64) = (r.miners.iter().map(|m| m.submitted).sum(), r.miners.iter().map(|m| m.rejected).sum());
    let (proven, refused) = (r.hashmaker["meter"]["proven"].as_u64().unwrap(), r.hashmaker["meter"]["refused"].as_u64().unwrap());
    assert!(told > 0, "the bad shares come back to the miners as rejected: {:?}", r.miners);
    // all but the answer to a miner's very last share, which it may not stay for
    assert!(refused >= told && refused <= told + r.miners.len() as u64, "refused {refused}, miners told {told}");
    assert_eq!(proven + refused, submitted, "every share was proven or refused: {}", r.hashmaker);
    // a stopped hash stops the payments: nothing paid after the miners stopped
    let pays = r.hashtaker["pays"].as_array().unwrap();
    let last_pay = pays.last().unwrap()["atMs"].as_u64().unwrap();
    assert!(last_pay <= r.miners_done_ms + 1500);
    assert_eq!(r.hashtaker["closed"], "no proven work");
    // both sides name the rental and the receipts behind its payments the same way, so a hashtaker's
    // delivery record and the hashmaker's summary of the same rental match
    let taker = PublicKey::from_slice(&hex::decode(r.hashmaker["buyer"].as_str().unwrap()).unwrap()).unwrap();
    let maker = PublicKey::from_secret_key(secp256k1::SECP256K1, &noise::fresh_key());
    let record = trust::attestation_of(&r.hashtaker, "rental-1", 0, &taker, &maker, 0, false, 3600).unwrap();
    let served = trust::served_of(&r.hashmaker, &maker, 3600).unwrap();
    assert_eq!(
        (&record.commit, &record.receipts_hash, record.paid_slices),
        (&served.commit, &served.receipts_hash, served.paid_slices),
        "{} / {}", r.hashtaker, r.hashmaker
    );
    if wallet {
        // one paid request per slice, in order, each with its receipt; then the session stopped
        let pays: Vec<_> = r.wallet_calls.iter().filter(|c| c["method"] == "xbt402_pay").collect();
        assert_eq!(pays.len() as u64, paid);
        for (i, c) in pays.iter().enumerate() {
            assert!(c["params"]["url"].as_str().unwrap().ends_with(&format!("/rental-1/{}", i + 1)));
            assert_eq!(c["params"]["task"], "hashrate");
            // the offer's price, with nothing by the byte: an honest hashmaker is paid within it
            assert_eq!(c["params"]["price_ceiling"], xbt_hashlink::rail::slice_ceiling(terms().price_msat), "{c}");
            let receipt: Value = serde_json::from_str(c["params"]["body"].as_str().unwrap()).unwrap();
            assert_eq!(receipt["slice"], i as u64 + 1);
        }
        assert!(r.hashtaker["pays"].as_array().unwrap().iter().all(|p| p["ok"] == true));
        assert_eq!(r.wallet_calls.last().unwrap()["method"], "ticket_stop");
    } else {
        assert_eq!(r.hashtaker["events"].as_array().unwrap().iter().filter(|e| e["ev"] == "cancelled").count(), 2);
    }
}

fn unpaid_stops(wallet: bool) {
    let r = rental(Some(2), 20, wallet);
    let (s, sw) = (terms().slice_work, share_work(DIFF));
    let stop = &r.hashmaker["stopped"];
    assert_eq!(stop["reason"], "unpaid", "{}", r.hashmaker);
    assert_eq!(r.hashmaker["paid"].as_u64().unwrap(), 2);
    // no share went past what's paid, and it stopped only once the next one wouldn't fit
    let work = w(&stop["work"]);
    assert!(work <= order::paid_work(2, 0, s), "{work} against a slice of {s}");
    assert!(!order::fits(work, sw, 2, 0, s), "{work} had room for another share, slice {s}");
    assert_eq!(stop["unpaidWork"], "0", "{}", r.hashmaker);
    // the hashtaker counted all of it, and the gateway stops there too
    assert_eq!(w(&r.hashtaker["meter"]["work"]), work, "{}", r.hashtaker);
    assert_eq!(w(&r.pool["work"]), work, "{}", r.pool);
    assert!(r.hashtaker["closed"].as_str().unwrap().starts_with("hashmaker closed"));
}

#[test]
fn a_paid_rental_then_the_hash_stops() {
    paid_then_stopped(false);
}

#[test]
fn a_stopped_payment_stops_the_hash_within_one_slice() {
    unpaid_stops(false);
}

#[test]
fn paid_by_the_wallet_then_the_hash_stops() {
    paid_then_stopped(true);
}

#[test]
fn unpaid_by_the_wallet_stops_the_hash() {
    unpaid_stops(true);
}

/// A renter that never pays: no miner moves, nothing is hashed for it, and it's told why.
#[test]
fn a_renter_that_never_pays_gets_no_work() {
    let r = rental(Some(0), 4, false);
    assert_eq!(r.hashmaker["stopped"]["reason"], "no first payment", "{}", r.hashmaker);
    assert_eq!(r.hashmaker["ready"], false, "{}", r.hashmaker);
    assert_eq!(r.hashmaker["paid"], 0);
    assert_eq!(r.hashmaker["miners"], json!([]), "no miner was taken: {}", r.hashmaker);
    assert_eq!(w(&r.hashmaker["meter"]["work"]), 0);
    assert_eq!(r.pool["accepted"], 0, "{}", r.pool);
    assert!(r.hashtaker["events"].as_array().unwrap().iter().all(|e| e["ev"] != "open"), "no session opened to the renter's gateway: {}", r.hashtaker);
    assert!(r.miners.iter().all(|m| m.submitted == 0), "{:?}", r.miners);
    assert!(r.hashtaker["closed"].as_str().unwrap().contains("no first payment"), "{}", r.hashtaker);
}

/// The hashmaker's endpoint, before any work: a first slice is taken at once (a renter pays ahead, and
/// nothing waits for a count), once. Anything but the renter's receipt for the next slice is refused
/// (409), so a gateway in front of it charges nothing.
#[test]
fn a_slice_out_of_turn_or_without_the_renters_receipt_is_refused() {
    let _serial = serial();
    let [link_a, miners_a, slices_a] = ports::<3>();
    let hk = noise::fresh_key();
    let hpub = PublicKey::from_secret_key(secp256k1::SECP256K1, &hk);
    let cfg = hashmaker::Config {
        miners: miners_a,
        link: link_a.clone(),
        key: hk,
        terms: terms(),
        report: None,
        slices: Some(slices_a.clone()),
        fallback: None,
        rentable: None,
        min_slice_time: hashmaker::MIN_SLICE_TIME,
    };
    let h = hashmaker::Hashmaker::start(cfg, Box::new(|| Box::<LabSeller>::default())).unwrap();
    wait_for(&link_a);
    let bk = noise::fresh_key();
    let mut l = xbt_hashlink::link::dial(&link_a, bk, hpub).unwrap();
    l.tx.send(&xbt_hashlink::msg::Msg::Hello { rental: "r9".into(), listing: "l".into(), terms: terms(), miners: 0, proof: Some(xbt_hashlink::msg::PROOF.into()) }).unwrap();
    assert!(matches!(l.rx.recv().unwrap(), Some(xbt_hashlink::msg::Msg::Welcome { .. })));
    let signed = |slice: u64, key: &secp256k1::SecretKey| xbt_hashlink::meter::Receipt { rental: "r9".into(), slice, work: 0, accepted: 0, rejected: 0, at_ms: 1 }.sign(key).to_string();
    let post = |path: &str, body: &str| {
        let mut s = TcpStream::connect(&slices_a).unwrap();
        write!(s, "POST {path} HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    };
    let refused = |what: &str, out: String| assert!(out.starts_with("HTTP/1.1 409"), "{what}: {out}");
    refused("out of turn", post("/hashrate/r9/2", &signed(2, &bk)));
    refused("another slice's receipt", post("/hashrate/r9/1", &signed(2, &bk)));
    refused("another's signature", post("/hashrate/r9/1", &signed(1, &noise::fresh_key())));
    refused("another rental", post("/hashrate/other/1", &signed(1, &bk)));
    refused("not a receipt", post("/hashrate/r9/1", "not json"));
    assert_eq!(h.status()["rentals"][0]["paid"], 0, "none of those was credited: {}", h.status());
    let t0 = Instant::now();
    let first = post("/hashrate/r9/1", &signed(1, &bk));
    assert!(first.starts_with("HTTP/1.1 200"), "the first slice, before any work: {first}");
    assert!(t0.elapsed() < Duration::from_secs(2), "no wait for a count: {} ms", t0.elapsed().as_millis());
    assert_eq!(h.status()["rentals"][0]["paid"], 1);
    assert_eq!(h.status()["rentals"][0]["ready"], true);
    refused("the same slice again", post("/hashrate/r9/1", &signed(1, &bk)));
    assert_eq!(h.status()["rentals"][0]["paid"], 1, "paid once: {}", h.status());
    h.shutdown();
}

#[test]
fn the_hashtaker_finds_the_hashmaker_on_nostr() {
    let relay = xbt_nostr::standin::StandinRelay::start().unwrap();
    let link = noise::fresh_key();
    let h = Hashrate {
        name: "lab hashmaker".into(),
        algorithm: "blake2b".into(),
        hashrate_hs: 4_000_000_000_000,
        link_addr: "127.0.0.1:1".into(),
        link_key: PublicKey::from_secret_key(secp256k1::SECP256K1, &link),
        iroh: None,
        pay_url: "https://hashmaker.example/hashrate".into(),
        pay_node: "02".to_string() + &"aa".repeat(32),
        terms: terms(),
        proof: Some(xbt_hashlink::msg::PROOF.into()),
        capacity: listing::Capacity { miners: 2, free_miners: 2, free_hs: 1_000_000 },
    };
    let nostr = xbt_nostr::event::Keys::generate();
    let ev = h.event(&link, &nostr, xbt_nostr::now()).unwrap();
    let said = listing::publish(std::slice::from_ref(&relay.url), &ev);
    assert_eq!(said[0]["ok"], true, "{said:?}");
    // a forgery: another Nostr key re-signing the hashmaker's tags
    let forged = xbt_nostr::event::Event::sign(&xbt_nostr::event::Keys::generate(), xbt_nostr::now(), listing::KIND, ev.tags.clone(), String::new());
    listing::publish(std::slice::from_ref(&relay.url), &forged);
    let (found, refused) = listing::find(std::slice::from_ref(&relay.url), xbt_nostr::now());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, h);
    assert_eq!(refused, 1);
}

/// A link that drops for a moment does not end the rental: the hashtaker dials again within the
/// grace time, the hashmaker takes it back and sends again what it may have lost, and the rental carries
/// on to its end. Every slice is still paid once, and the two sides' proven counts agree.
#[test]
fn a_rental_survives_a_moment_without_its_link() {
    let r = rental_cut(None, 22, false, Some(Duration::from_secs(4)));
    let evs = |v: &Value| v["events"].as_array().cloned().unwrap_or_default();
    let maker = evs(&r.hashmaker);
    let taker = evs(&r.hashtaker);
    assert!(maker.iter().any(|e| e["ev"] == "link lost, waiting for the hashtaker"), "{}", r.hashmaker);
    assert!(maker.iter().any(|e| e["ev"] == "hashtaker back, rental resumed"), "{}", r.hashmaker);
    assert!(taker.iter().any(|e| e["ev"] == "rental resumed"), "{}", r.hashtaker);
    // it carried on, not just came back: the miners worked for it again and those slices were paid
    let back = maker.iter().find(|e| e["ev"] == "hashtaker back, rental resumed").unwrap()["atMs"].as_u64().unwrap();
    let after = maker.iter().filter(|e| e["ev"] == "pay" && e["ok"] == true && e["atMs"].as_u64().unwrap() > back).count();
    let first = maker.iter().find(|e| e["ev"] == "pay" && e["ok"] == true && e["atMs"].as_u64().unwrap() > back).map(|e| e["atMs"].as_u64().unwrap() - back);
    eprintln!("{after} slices paid after the resume, the first {first:?} ms after it");
    assert!(after >= 3, "only {after} slices paid after the resume: {}", r.hashmaker);
    let paid = r.hashmaker["paid"].as_u64().unwrap();
    assert!(paid >= 3, "only {paid} slices: {}", r.hashmaker);
    assert_eq!(r.hashtaker["released"].as_u64().unwrap(), paid, "each slice paid once");
    each_payment_was_due(&r.hashtaker, &terms(), share_work(DIFF));
    eprintln!("{} shares counted from being sent again", r.hashtaker["resentCounted"]);
    assert_eq!(r.hashmaker["meter"]["work"], r.hashtaker["meter"]["work"], "{} / {}", r.hashmaker, r.hashtaker);
    assert_eq!(r.hashmaker["meter"]["proven"], r.hashtaker["meter"]["proven"]);
    assert!(!r.hashmaker["stopped"]["reason"].as_str().unwrap_or("").starts_with("link lost"), "{}", r.hashmaker);
    assert_eq!(r.hashtaker["closed"], "no proven work", "it ended when the miners stopped, not when the link dropped");
}

/// A relay between the hashtaker and the hashmaker: it can lose what either side sends with the
/// connection left open, close what it carries, and refuse new connections.
struct Road {
    addr: String,
    open: Arc<Mutex<Vec<TcpStream>>>,
    lose: Arc<AtomicBool>,
    lose_down: Arc<AtomicBool>,
    keep: Arc<AtomicBool>,
    refuse: Arc<AtomicBool>,
}

impl Road {
    fn start(addr: String, to: String) -> Road {
        let r = Road { addr: addr.clone(), open: Arc::default(), lose: Arc::default(), lose_down: Arc::default(), keep: Arc::default(), refuse: Arc::default() };
        let l = TcpListener::bind(&addr).unwrap();
        let (o, lose, lose_down, keep, refuse) = (r.open.clone(), r.lose.clone(), r.lose_down.clone(), r.keep.clone(), r.refuse.clone());
        thread::spawn(move || {
            for c in l.incoming() {
                let Ok(mut a) = c else { continue };
                if refuse.load(Ordering::SeqCst) {
                    continue;
                }
                let Ok(mut b) = TcpStream::connect(&to) else { continue };
                o.lock().unwrap().extend([a.try_clone().unwrap(), b.try_clone().unwrap()]);
                let (mut a2, mut b2) = (a.try_clone().unwrap(), b.try_clone().unwrap());
                let (ld, k) = (lose_down.clone(), keep.clone());
                thread::spawn(move || {
                    let mut buf = [0u8; 16 << 10];
                    while let Ok(n) = b2.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        if !ld.load(Ordering::SeqCst) {
                            let _ = a2.write_all(&buf[..n]);
                        }
                    }
                    if !k.load(Ordering::SeqCst) {
                        let _ = a2.shutdown(std::net::Shutdown::Both);
                    }
                });
                let (lo, k) = (lose.clone(), keep.clone());
                thread::spawn(move || {
                    let mut buf = [0u8; 16 << 10];
                    while let Ok(n) = a.read(&mut buf) {
                        if n == 0 || (!lo.load(Ordering::SeqCst) && b.write_all(&buf[..n]).is_err()) {
                            break;
                        }
                    }
                    if !k.load(Ordering::SeqCst) {
                        let _ = b.shutdown(std::net::Shutdown::Both);
                    }
                });
            }
        });
        r
    }

    fn cut(&self) {
        for s in self.open.lock().unwrap().drain(..) {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        self.lose.store(false, Ordering::SeqCst);
    }

    /// Silent both ways: nothing arrives, and no side hears that anything ended.
    fn stall(&self) {
        self.keep.store(true, Ordering::SeqCst);
        self.lose.store(true, Ordering::SeqCst);
        self.lose_down.store(true, Ordering::SeqCst);
    }
}

/// A rental paid the wallet's way through a [`Road`], with its miner on the fallback first.
struct WalletRental {
    h: hashmaker::Hashmaker,
    road: Road,
    live: Arc<Mutex<Value>>,
    end: Arc<AtomicBool>,
    calls: Arc<Mutex<Vec<Value>>>,
    b: thread::JoinHandle<Value>,
    _miner: thread::JoinHandle<Result<standin::MinerResult, String>>,
}

impl WalletRental {
    fn start(terms: Terms, rate: f64, idle: Duration) -> WalletRental {
        let [pool_a, fallback_a, link_a, miners_a, slices_a, relay_a] = ports::<6>();
        let dir = tempdir();
        for a in [pool_a.clone(), fallback_a.clone()] {
            // jobs stay good for four of these: long enough for a share whose newer jobs were lost with the link
            thread::spawn(move || standin::pool(standin::PoolConfig { listen: a, diff: DIFF, job_every: Duration::from_secs(5), report: None }));
        }
        wait_for(&pool_a);
        wait_for(&fallback_a);
        let hk = noise::fresh_key();
        let h = hashmaker::Hashmaker::start(
            hashmaker::Config {
                miners: miners_a.clone(),
                link: link_a.clone(),
                key: hk,
                terms: terms.clone(),
                report: None,
                slices: Some(slices_a.clone()),
                fallback: Some(fallback_a.clone()),
                rentable: None,
                min_slice_time: hashmaker::MIN_SLICE_TIME,
            },
            Box::new(|| Box::<LabSeller>::default()),
        )
        .unwrap();
        wait_for(&link_a);
        let road = Road::start(relay_a, link_a);
        let miner = {
            let a = miners_a.clone();
            thread::spawn(move || {
                standin::miner(standin::MinerConfig {
                    pool: a,
                    user: "hashmaker.m0".into(),
                    max_rate: rate,
                    bad_every: 0,
                    duration: Some(Duration::from_secs(150)),
                    reconnect: true,
                    extranonce_subscribe: false,
                    bind: None,
                })
            })
        };
        // the miner on the fallback first, as a hashmaker's are
        let t0 = Instant::now();
        while !h.status()["miners"].as_array().is_some_and(|m| m.len() == 1 && m[0]["work"] != "0") {
            assert!(t0.elapsed() < Duration::from_secs(20), "the miner never hashed at the fallback");
            thread::sleep(Duration::from_millis(100));
        }
        let calls: Arc<Mutex<Vec<Value>>> = Arc::default();
        let live: Arc<Mutex<Value>> = Arc::default();
        let end: Arc<AtomicBool> = Arc::default();
        let payer = SignerPayer::new(fake_wallet(&dir, slices_a, calls.clone()), "https://hashmaker.example/hashrate".into(), "hashrate".into(), terms.price_msat, None,
                                     Some(600), Duration::from_secs(5));
        let cfg = hashtaker::Config {
            hashmaker: road.addr.clone(),
            hashmaker_key: PublicKey::from_secret_key(secp256k1::SECP256K1, &hk),
            key: noise::fresh_key(),
            upstream: pool_a,
            user: "hashtaker.rented".into(),
            terms: terms.clone(),
            rental: "rental-1".into(),
            listing: "lab".into(),
            stop_paying_after: None,
            idle,
            duration: Some(Duration::from_secs(120)),
            report: None,
            payer: Some(Box::new(payer)),
            miners: 0,
            budget_msat: None,
            cut: Some(end.clone()),
            live: Some(live.clone()),
            gateway_api: None,
            allow_unblinded: true,
        };
        let b = thread::spawn(move || hashtaker::run(cfg, Box::<LabHashtaker>::default()).unwrap());
        WalletRental { h, road, live, end, calls, b, _miner: miner }
    }

    fn maker(&self) -> Value {
        self.h.status()["rentals"][0].clone()
    }

    fn accepted(v: &Value) -> u64 {
        v["meter"]["accepted"].as_u64().unwrap_or(0)
    }

    fn proven(v: &Value) -> u64 {
        v["meter"]["proven"].as_u64().unwrap_or(0)
    }

    /// Wait until the hashmaker has a verdict for at least `n` shares.
    fn wait_counted(&self, n: u64) {
        let t0 = Instant::now();
        while Self::accepted(&self.maker()) < n {
            assert!(t0.elapsed() < Duration::from_secs(40), "{n} shares not counted: {}", self.h.status());
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// Wait until the hashmaker has proven more than `n` shares, or the rental has ended, or it's taken too long.
    fn wait_proven_past(&self, n: u64, within: Duration) {
        let t0 = Instant::now();
        while Self::proven(&self.maker()) <= n && self.h.finished().is_empty() && t0.elapsed() < within {
            thread::sleep(Duration::from_millis(100));
        }
    }

    /// What the hashtaker sends is lost, until it has a verdict the hashmaker never hears of.
    fn lose_a_verdict(&self) {
        self.road.lose.store(true, Ordering::SeqCst);
        let t0 = Instant::now();
        while Self::accepted(&self.live.lock().unwrap()) <= Self::accepted(&self.maker()) {
            assert!(t0.elapsed() < Duration::from_secs(20), "the hashtaker never got ahead: {} vs {}", self.live.lock().unwrap(), self.h.status());
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// The reports once both sides ended, and what the wallet was charged for slices that were paid.
    fn ended(self) -> (Value, Value, u64, Vec<Value>) {
        let b = self.b.join().unwrap();
        let t0 = Instant::now();
        let r = loop {
            if let Some(r) = self.h.finished().into_iter().find(|r| r["rental"] == "rental-1") {
                break r;
            }
            assert!(t0.elapsed() < hashmaker::QUIET_LIMIT + Duration::from_secs(15), "the rental never ended: {}", self.h.status());
            thread::sleep(Duration::from_millis(100));
        };
        self.h.shutdown();
        let charged = b["pays"].as_array().unwrap().iter().filter(|p| p["ok"] == true).map(|p| p["wallet"]["charged_sats"].as_u64().unwrap()).sum();
        let calls = self.calls.lock().unwrap().clone();
        (b, r, charged, calls)
    }
}

/// What a rental paid through the wallet must show once it's over, whatever became of its link: the
/// wallet was charged what the hashmaker earned, every slice once, and the two proven counts agree.
fn check_wallet_books(terms: &Terms, b: &Value, r: &Value, charged: u64) {
    let paid = r["paid"].as_u64().unwrap();
    assert!(paid >= 1, "hashtaker {b}\nhashmaker {r}");
    assert_eq!(b["payFailed"], false, "no slice refused\nhashtaker {b}\nhashmaker {r}");
    assert_eq!(b["paidSlices"].as_u64().unwrap(), paid, "hashtaker {b}\nhashmaker {r}");
    assert_eq!(charged * 1000, paid * terms.price_msat, "what the wallet was charged is what the hashmaker earned: {r}");
    assert_eq!(b["spentMsat"], r["earnedMsat"], "hashtaker {b}\nhashmaker {r}");
    assert_eq!(r["meter"]["work"], b["meter"]["work"], "both sides count the same work\nhashtaker {b}\nhashmaker {r}");
    assert_eq!(r["meter"]["proven"], b["meter"]["proven"], "hashtaker {b}\nhashmaker {r}");
    each_payment_was_due(b, terms, share_work(DIFF));
    assert!(!r["stopped"]["reason"].as_str().unwrap_or("").contains("unpaid"), "{r}");
}

/// Slices paid the wallet's way, by a miner whose shares come seconds apart (a real miner's do): a
/// verdict lost with the link leaves the hashmaker with one fewer verdict for good, and that changes
/// nothing, since a verdict sets no work. The rental carries on, and no count or charge differs.
#[test]
fn a_verdict_lost_with_the_link_changes_no_count_and_no_slice_paid_through_the_wallet() {
    let _serial = serial();
    let terms = Terms { slice_work: 3 * share_work(DIFF), ..terms() };
    let w = WalletRental::start(terms.clone(), 0.25, Duration::from_secs(25));
    // one share with its verdict on both sides, the next one's verdict heard by the hashtaker alone; then the link drops
    w.wait_counted(1);
    w.lose_a_verdict();
    let (ta, mk) = (WalletRental::accepted(&w.live.lock().unwrap()), WalletRental::accepted(&w.maker()));
    eprintln!("the hashtaker ahead when the link drops: {ta} verdicts against {mk}");
    let at_cut = WalletRental::proven(&w.maker());
    w.road.cut();
    // the miner comes back from the fallback and proves more on the new link; then the rental is ended
    w.wait_proven_past(at_cut, Duration::from_secs(50));
    assert!(WalletRental::proven(&w.maker()) > at_cut, "the rental went on after the drop: {}", w.h.status());
    w.end.store(true, Ordering::SeqCst);
    let (b, r, charged, _) = w.ended();
    check_wallet_books(&terms, &b, &r, charged);
    assert!(WalletRental::accepted(&b) > WalletRental::accepted(&r), "that verdict stayed lost, and the counts still agree\nhashtaker {b}\nhashmaker {r}");
}

/// A link that's lost one way, or lost and not back for a while. `half_dead`: the link stays up losing
/// what the hashtaker sends for that long. `down`: then nothing connects for that long. The wallet's
/// payments don't go by the link, so they go on: each slice paid once on both sides, whichever.
fn an_outage_paid_through_the_wallet(half_dead: Duration, down: Duration) {
    let _serial = serial();
    let terms = Terms { slice_work: 2 * share_work(DIFF), grace_ms: 15_000, ..terms() };
    let w = WalletRental::start(terms.clone(), 0.25, Duration::from_secs(40));
    w.wait_counted(1);
    w.lose_a_verdict();
    thread::sleep(half_dead);
    w.road.refuse.store(!down.is_zero(), Ordering::SeqCst);
    let at_cut = WalletRental::proven(&w.maker());
    w.road.cut();
    thread::sleep(down);
    w.road.refuse.store(false, Ordering::SeqCst);
    w.wait_proven_past(at_cut, Duration::from_secs(45));
    assert!(WalletRental::proven(&w.maker()) > at_cut, "the rental went on after the outage: {}", w.h.status());
    w.end.store(true, Ordering::SeqCst);
    let (b, r, charged, _) = w.ended();
    let paid = r["paid"].as_u64().unwrap();
    let ms: Vec<Value> = b["pays"].as_array().unwrap().iter().map(|p| p["ms"].clone()).collect();
    eprintln!("half dead {half_dead:?}, down {down:?}: payment waits {ms:?} ms, paid {paid}, charged {charged} sat, payFailed {}, resent counted {}", b["payFailed"], b["resentCounted"]);
    check_wallet_books(&terms, &b, &r, charged);
}

#[test]
fn slices_paid_through_the_wallet_when_the_link_drops_at_once() {
    an_outage_paid_through_the_wallet(Duration::ZERO, Duration::ZERO);
}

#[test]
fn slices_paid_through_the_wallet_over_a_two_second_outage() {
    an_outage_paid_through_the_wallet(Duration::ZERO, Duration::from_secs(2));
}

#[test]
fn slices_paid_through_the_wallet_over_a_half_dead_link() {
    an_outage_paid_through_the_wallet(Duration::from_secs(4), Duration::ZERO);
}

#[test]
fn slices_paid_through_the_wallet_over_a_six_second_outage() {
    an_outage_paid_through_the_wallet(Duration::ZERO, Duration::from_secs(6));
}

/// Slices paid the wallet's way, and the link goes silent with no close and no end of stream. The
/// hashtaker sees no more proven work, so it pays no more; the hashmaker's miner hashes on, so a share comes
/// that doesn't fit, and it stops when that goes unpaid. What the wallet was charged is what the hashmaker earned,
/// and the wallet's session is stopped, which gives its unused tickets back.
#[test]
fn a_silent_link_ends_a_rental_paid_through_the_wallet_with_the_session_stopped() {
    let _serial = serial();
    let terms = Terms { slice_work: 4 * share_work(DIFF), ..terms() };
    let w = WalletRental::start(terms.clone(), 8.0, Duration::from_secs(6));
    let t0 = Instant::now();
    while w.maker()["paid"].as_u64().unwrap_or(0) < 2 {
        assert!(t0.elapsed() < Duration::from_secs(30), "{}", w.h.status());
        thread::sleep(Duration::from_millis(5));
    }
    w.road.stall();
    let stalled = Instant::now();
    let (b, r, charged, calls) = w.ended();
    let took = stalled.elapsed();
    eprintln!("both sides ended {} ms after the link went silent; hashtaker: {}, hashmaker: {}", took.as_millis(), b["closed"], r["stopped"]["reason"]);
    assert_eq!(b["closed"], "no proven work", "{b}");
    assert_eq!(r["stopped"]["reason"], "unpaid", "{r}");
    assert_eq!(r["stopped"]["unpaidWork"], "0", "{r}");
    assert!(took < hashmaker::QUIET_LIMIT + Duration::from_secs(10), "{} s", took.as_secs());
    let paid = r["paid"].as_u64().unwrap();
    assert_eq!(b["paidSlices"].as_u64().unwrap(), paid, "hashtaker {b}\nhashmaker {r}");
    assert_eq!(charged * 1000, paid * terms.price_msat, "what the wallet was charged is what the hashmaker earned: {r}");
    assert_eq!(b["spentMsat"], r["earnedMsat"], "hashtaker {b}\nhashmaker {r}");
    assert!(calls.iter().any(|c| c["method"] == "ticket_stop"), "the wallet's session was stopped: {calls:?}");
}

/// Measured for docs/P2P-HASH.md, not a pass line. A verdict is lost and the link stays down for ten
/// seconds, on a grace long enough to come back.
///
/// `cargo test -p xbt-hashlink --test rental measure_ -- --ignored --nocapture`
#[test]
#[ignore]
fn measure_a_long_outage_paid_through_the_wallet() {
    let _serial = serial();
    let terms = Terms { slice_work: 2 * share_work(DIFF), grace_ms: 30_000, ..terms() };
    let w = WalletRental::start(terms.clone(), 0.25, Duration::from_secs(40));
    w.wait_counted(1);
    w.lose_a_verdict();
    w.road.refuse.store(true, Ordering::SeqCst);
    w.road.cut();
    thread::sleep(Duration::from_secs(10));
    w.road.refuse.store(false, Ordering::SeqCst);
    let t0 = Instant::now();
    while w.h.finished().is_empty() && t0.elapsed() < Duration::from_secs(60) {
        thread::sleep(Duration::from_millis(100));
    }
    w.end.store(true, Ordering::SeqCst);
    let (b, r, charged, _) = w.ended();
    let pays: Vec<(Value, Value)> = b["pays"].as_array().unwrap().iter().map(|p| (p["slice"].clone(), p["ok"].clone())).collect();
    eprintln!(
        "MEASURED wallet charged {charged} sat; pays {pays:?}; payFailed {}; hashtaker closed {}; hashmaker paid {}, stopped {}; slices at the hashtaker's meter {}; resent counted {}; proven {} / {}",
        b["payFailed"], b["closed"], r["paid"], r["stopped"], b["slicesDone"].as_array().unwrap().len(), b["resentCounted"], r["meter"]["proven"], b["meter"]["proven"]
    );
}

/// Measured for docs/P2P-HASH.md, not a pass line. Paid the wallet's way, what the hashtaker sends is
/// lost for good while what the hashmaker sends still arrives: the shares go on reaching the hashtaker,
/// its payments go on by the wallet, and no new job reaches the miner. Whichever side ends it, and why.
#[test]
#[ignore]
fn measure_a_one_way_outage_paid_through_the_wallet() {
    let _serial = serial();
    let terms = Terms { slice_work: 4 * share_work(DIFF), ..terms() };
    let w = WalletRental::start(terms.clone(), 8.0, Duration::from_secs(30));
    let t0 = Instant::now();
    while w.maker()["paid"].as_u64().unwrap_or(0) < 2 {
        assert!(t0.elapsed() < Duration::from_secs(30), "{}", w.h.status());
        thread::sleep(Duration::from_millis(5));
    }
    w.road.lose.store(true, Ordering::SeqCst);
    let t0 = Instant::now();
    let (b, r, charged, _) = w.ended();
    let s = terms.slice_work as f64;
    let work: f64 = b["meter"]["work"].as_str().unwrap().parse().unwrap();
    eprintln!(
        "MEASURED ended {} s after the outage began; hashtaker closed {}; hashmaker paid {}, stopped {}; wallet charged {charged} sat, payFailed {}; the hashtaker's meter {:.1} slices of work, so {:.1} unpaid",
        t0.elapsed().as_secs(), b["closed"], r["paid"], r["stopped"]["reason"], b["payFailed"], work / s, work / s - r["paid"].as_f64().unwrap()
    );
}

/// A seller's own ticket, as the hashmaker's shop sells them: far more than one slice. Here it also
/// sells any size down to a slice.
const TICKET_MSAT: u64 = 900_000;

/// What [`ticket_wallet`] holds: the session's credit with the shop, the tickets bought and what
/// they came to, the first of them, and what the paid slices were charged.
#[derive(Default, Debug)]
struct Book {
    credit_msat: u64,
    tickets: u64,
    bought_msat: u64,
    first_msat: u64,
    charged_msat: u64,
}

/// [`fake_wallet`] with the signer's money rules: a slice is paid from the session's credit, and a
/// ticket of the call's `max_charge_sats` (else `max_sats`), inside what the shop sells, is bought
/// only where the call's `max_sats` takes it whole; the slice is charged only within its charge cap.
/// Credit stays with the shop between rentals, as a session's balance does.
fn ticket_wallet(dir: &std::path::Path, slices: String, book: Arc<Mutex<Book>>) -> PathBuf {
    let sock = dir.join("signer.sock");
    let l = UnixListener::bind(&sock).unwrap();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(c) = c else { continue };
            let mut line = String::new();
            BufReader::new(c.try_clone().unwrap()).read_line(&mut line).unwrap();
            let req: Value = serde_json::from_str(&line).unwrap();
            let p = &req["params"];
            let price = terms().price_msat;
            let max_msat = p["max_sats"].as_u64().unwrap_or(0) * 1000;
            let charge_msat = p["max_charge_sats"].as_u64().map_or(max_msat, |c| c * 1000);
            let result = match req["method"].as_str() {
                Some("xbt402_pay") if price > charge_msat => json!({"verdict": "deny", "rule": "max_sats", "charged_sats": 0}),
                Some("xbt402_pay") => {
                    let mut b = book.lock().unwrap();
                    if b.credit_msat < price {
                        // a whole ticket and its fee limit (10 sat and 0.5%) must fit the call's max_sats
                        let ticket = charge_msat.clamp(price, TICKET_MSAT);
                        if ticket + 10_000 + ticket.div_ceil(200).div_ceil(1000) * 1000 > max_msat {
                            let r = json!({"verdict": "deny", "rule": "max_sats", "charged_sats": 0});
                            drop(b);
                            let mut w = c;
                            writeln!(w, "{}", json!({"id": 1, "result": r})).unwrap();
                            continue;
                        }
                        b.credit_msat += ticket;
                        b.tickets += 1;
                        b.bought_msat += ticket;
                        if b.first_msat == 0 {
                            b.first_msat = ticket;
                        }
                    }
                    drop(b);
                    let url = p["url"].as_str().unwrap();
                    let path = &url[url.find("/hashrate").unwrap()..];
                    let body = p["body"].as_str().unwrap();
                    let mut s = TcpStream::connect(&slices).unwrap();
                    write!(s, "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
                    let mut out = String::new();
                    s.read_to_string(&mut out).unwrap();
                    let status: u64 = out.split_whitespace().nth(1).unwrap().parse().unwrap();
                    if status == 200 {
                        let mut b = book.lock().unwrap();
                        b.credit_msat -= price;
                        b.charged_msat += price;
                    }
                    json!({"verdict": "allow", "rail": "ticket", "status": status, "session": "s1", "charged_sats": if status == 200 { price / 1000 } else { 0 }})
                }
                _ => json!({"ok": true}),
            };
            let mut w = c;
            writeln!(w, "{}", json!({"id": 1, "result": result})).unwrap();
        }
    });
    sock
}

/// One hashmaker selling on the lab's rail, its miners running for a minute, and a wallet with no
/// credit at its shop ([`ticket_wallet`]); `rent` runs one rental on it to the end, its payer
/// made as the hashtaker's service makes it for a rental of that budget ([`SignerPayer::new`]).
struct TicketShop {
    h: hashmaker::Hashmaker,
    hpub: PublicKey,
    link: String,
    pool: String,
    sock: PathBuf,
    book: Arc<Mutex<Book>>,
    miners: Vec<thread::JoinHandle<Result<standin::MinerResult, String>>>,
}

impl TicketShop {
    fn start() -> Self {
        let [pool, link, miners_at, slices] = ports::<4>();
        let dir = tempdir();
        thread::spawn({
            let a = pool.clone();
            move || standin::pool(standin::PoolConfig { listen: a, diff: DIFF, job_every: Duration::from_millis(700), report: None })
        });
        wait_for(&pool);
        let hk = noise::fresh_key();
        let hpub = PublicKey::from_secret_key(secp256k1::SECP256K1, &hk);
        let cfg = hashmaker::Config { miners: miners_at.clone(), link: link.clone(), key: hk, terms: terms(), report: None,
                                      slices: Some(slices.clone()), fallback: None, rentable: None, min_slice_time: hashmaker::MIN_SLICE_TIME };
        let h = hashmaker::Hashmaker::start(cfg, Box::new(|| Box::<LabSeller>::default())).unwrap();
        wait_for(&link);
        let book: Arc<Mutex<Book>> = Arc::default();
        let sock = ticket_wallet(&dir, slices, book.clone());
        let miners = (0..2)
            .map(|i| {
                let a = miners_at.clone();
                thread::spawn(move || {
                    standin::miner(standin::MinerConfig { pool: a, user: format!("hashmaker.m{i}"), max_rate: 8.0, bad_every: 7,
                                                          duration: Some(Duration::from_secs(60)), reconnect: true, extranonce_subscribe: false, bind: None })
                })
            })
            .collect();
        TicketShop { h, hpub, link, pool, sock, book, miners }
    }

    fn rent(&self, id: &str, budget_sats: u64) -> Value {
        let payer = SignerPayer::new(self.sock.clone(), "https://hashmaker.example/hashrate".into(), "hashrate".into(), terms().price_msat, Some(budget_sats), None,
                                     Duration::from_secs(5));
        let cfg = hashtaker::Config { hashmaker: self.link.clone(), hashmaker_key: self.hpub, key: noise::fresh_key(), upstream: self.pool.clone(),
                                      user: "hashtaker.rented".into(), terms: terms(), rental: id.into(), listing: "lab".into(), stop_paying_after: None,
                                      idle: Duration::from_secs(3), duration: Some(Duration::from_secs(40)), report: None, payer: Some(Box::new(payer)), miners: 0,
                                      budget_msat: Some(budget_sats * 1000), cut: None, live: None, gateway_api: None, allow_unblinded: true };
        hashtaker::run(cfg, Box::<LabHashtaker>::default()).unwrap()
    }

    /// The hashmaker's own reports of the `n` rentals it served, once all are in; the shop stops.
    fn finish(self, n: usize) -> (Vec<Value>, Arc<Mutex<Book>>) {
        let mut reports = vec![];
        for _ in 0..200 {
            reports = self.h.finished();
            if reports.len() >= n {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        self.h.shutdown();
        for m in self.miners {
            let _ = m.join();
        }
        (reports, self.book)
    }
}

/// A trial slice from a buyer with no credit at the shop, then a rental of at least ten slices:
/// the trial's ticket is its budget, one slice, not the shop's own, and every slice of both is
/// charged its price, by the hashmaker's count and the wallet's.
#[test]
fn a_trial_slice_from_no_credit_is_paid_and_a_rental_after_it_pays_every_slice() {
    let _serial = serial();
    let shop = TicketShop::start();
    let price_sats = terms().price_msat / 1000;
    // the trial: one slice's budget, from no credit
    let trial = shop.rent("trial-1", price_sats);
    let paid_trial = trial["released"].as_u64().unwrap();
    let b = format!("{:?}", shop.book.lock().unwrap());
    assert_eq!(paid_trial, 1, "the trial slice was paid: {trial} {b}");
    assert!(trial["pays"].as_array().unwrap().iter().all(|p| p["ok"] == true), "{trial}");
    {
        let b = shop.book.lock().unwrap();
        assert_eq!((b.tickets, b.bought_msat, b.charged_msat, b.credit_msat), (1, terms().price_msat, terms().price_msat, 0),
                   "one slice's ticket bought and charged, nothing left at the shop: {b:?}");
    }
    // a rental of twelve slices after it
    let rental = shop.rent("rental-2", 12 * price_sats);
    let paid_rental = rental["released"].as_u64().unwrap();
    assert!(paid_rental >= 10, "{paid_rental} slices: {rental}");
    assert!(rental["pays"].as_array().unwrap().iter().all(|p| p["ok"] == true), "{rental}");
    let (reports, book) = shop.finish(2);
    let maker_paid: u64 = reports.iter().map(|r| r["paid"].as_u64().unwrap_or(0)).sum();
    let b = book.lock().unwrap();
    // charged = slices × price, by the wallet's book and the hashmaker's count of paid slices
    let slices = paid_trial + paid_rental;
    assert_eq!(b.charged_msat, slices * terms().price_msat, "{b:?}");
    let brief: Vec<_> = reports.iter().map(|r| (r["rental"].clone(), r["paid"].clone(), r["slicesDone"].as_array().map(Vec::len), r["stopped"].clone())).collect();
    assert_eq!((reports.len(), maker_paid), (2, slices), "{brief:?}");
    assert_eq!(b.bought_msat, b.charged_msat + b.credit_msat, "what left the wallet is what was charged and what the shop holds: {b:?}");
    assert!(b.bought_msat <= (1 + 12) * terms().price_msat, "no ticket past the budgets, however far a whole one would have gone: {b:?}");
}

/// A rental of twelve slices, 60 sat in all, from a buyer with no credit at the shop and no trial
/// before it: its first ticket is the first step inside its budget, far under the shop's own 900 sat,
/// and every slice is paid, each charged its price, until the budget is spent, with nothing left at
/// the shop. What leaves for tickets never passes the budget.
#[test]
fn a_small_rental_from_no_credit_buys_one_ticket_and_pays_every_slice() {
    let _serial = serial();
    let shop = TicketShop::start();
    let price_msat = terms().price_msat;
    let budget_sats = 12 * price_msat / 1000;
    let rental = shop.rent("small-1", budget_sats);
    let paid = rental["released"].as_u64().unwrap();
    let b = format!("{:?}", shop.book.lock().unwrap());
    assert!(rental["pays"].as_array().unwrap().iter().all(|p| p["ok"] == true), "every slice's payment went through: {rental} {b}");
    assert_eq!(paid, 12, "the rental ran to its budget, twelve slices: {rental} {b}");
    let (reports, book) = shop.finish(1);
    let b = book.lock().unwrap();
    let maker_paid = reports.first().and_then(|r| r["paid"].as_u64());
    // what the wallet was charged = what the hashmaker counted paid = 12 × price = the budget
    assert_eq!((b.charged_msat, maker_paid), (budget_sats * 1000, Some(12)), "{b:?} {reports:?}");
    assert_eq!(b.first_msat, budget_sats * 1000, "the first step, inside what the budget has: {b:?}");
    assert_eq!((b.bought_msat, b.credit_msat), (budget_sats * 1000, 0), "tickets came to the budget, and none past it: {b:?}");
}
