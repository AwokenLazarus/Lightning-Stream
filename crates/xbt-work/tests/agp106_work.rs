//! AGP-106, fix wave 6, pay-with-work: the neighbours of the fourth closure audit's holes
//! (`agp102_work.rs` has the holes' own tests). Each test names the rule it holds the code to.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use xbt402::client::Transport;
use xbt402::provider::HttpResponse;
use xbt402::scheme::ProviderScheme;
use xbt_work::auth::{auth_tag, request_digest};
use xbt_work::book::ReceiptBook;
use xbt_work::payer::{PayerConfig, WorkPayer};
use xbt_work::provider::{WorkConfig, WorkProvider, WorkScheme};
use xbt_work::receipt::{PrimeKey, Signed, WorkReceipt};

const NET: &str = "bip122:00000000000000000000000000000001";
const PROV: &str = "bcrt1q76vavszzsq657n375vk6updhxm0tfay7k28cc3";
const MAIN_BITS: u32 = 0x1a00_f0b5;
const MAIN_V: u64 = 312_500_000;
const PRICE: u64 = 150;

fn key() -> PrimeKey { PrimeKey::from_seed(70, &[9u8; 32]) }
fn config(k: &PrimeKey) -> WorkConfig {
    WorkConfig::new(NET, PROV, 70, &k.pubkey_hex(), "http://prime.test/receipt").shipped(MAIN_BITS, MAIN_V, PRICE)
}
fn receipt(inv: &str, seq: u64, cum: u64, first: u32, last: u32) -> WorkReceipt {
    WorkReceipt { seq, cum_work: cum, shares: seq, first_height: first, last_height: last, difficulty: 1, ..WorkReceipt::zero(70, PROV, inv) }
}
fn payment(inv_doc: &Value, k: &PrimeKey, r: &WorkReceipt, n: u64, path: &str) -> Value {
    let key = hex::decode(inv_doc["authKey"].as_str().unwrap()).unwrap();
    let s = k.sign(r).unwrap();
    let auth = auth_tag(&key, &r.invoice, n, r.seq, r.cum_work, &request_digest("GET", path, b"")).unwrap();
    json!({"x402Version": 2, "accepted": {"scheme": "xbt-work", "network": NET, "payTo": PROV},
           "payload": {"receipt": r.to_doc(), "sig": hex::encode(s.sig), "n": n, "auth": auth}})
}
fn call(wp: &Arc<WorkProvider>, pay: &Value, path: &str) -> std::result::Result<(), String> {
    WorkScheme(wp.clone()).authorize(pay, "GET", path, b"", PRICE, &format!("http://api.test{path}")).map(|_| ())
        .map_err(|v| v["error"].as_str().unwrap_or("").to_string())
}
fn state_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("xbt-work-agp106-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A relay in memory: the blob it holds for each lookup, whoever signed what is in it.
#[derive(Default)]
struct Relay {
    blobs: Mutex<HashMap<String, Vec<u8>>>,
}

impl Relay {
    fn put(&self, s: &Signed) {
        let blob = xbt_work::relay::seal(xbt402::json::dumps(&s.to_doc()).as_bytes(), PROV, &s.receipt.invoice, None).unwrap();
        self.blobs.lock().unwrap().insert(xbt_work::relay::lookup(PROV, &s.receipt.invoice), blob);
    }
}

impl Transport for Relay {
    fn request(&self, _: &str, url: &str, _: &[u8], _: &[(String, String)]) -> xbt402::error::Result<HttpResponse> {
        let id = url.rsplit('/').next().unwrap_or("");
        Ok(match self.blobs.lock().unwrap().get(id) {
            Some(b) => HttpResponse::new(200, vec![], b.clone()),
            None => HttpResponse::new(404, vec![], b"not found".to_vec()),
        })
    }
}

/// (inode, ctime) of a file: it changes with every replacement.
#[cfg(unix)]
fn stamp(p: &std::path::Path) -> (u64, i64, i64) {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(p).unwrap();
    (m.ino(), m.ctime(), m.ctime_nsec())
}

/// The rule of item 8: **the state is written when it changed, and only then.** Its neighbours
/// on the pull path, one invoice each: a blob nobody signed, a blob another key signed, an older
/// receipt the book holds already, the receipt of a distrusted Prime. None changes anything, so
/// none writes; and the first sight of an older receipt, which the book does keep, writes once.
#[cfg(unix)]
#[test]
fn a_receipt_that_changes_nothing_writes_no_state_whoever_put_it_on_the_relay() {
    let dir = state_dir("nowrite");
    let k = key();
    let stranger = PrimeKey::from_seed(70, &[8u8; 32]);
    let path = dir.join("work.json");
    let cfg = WorkConfig { state_path: Some(path.clone()), relay_url: Some("http://relay.test".into()), ..config(&k) };
    let wp = Arc::new(WorkProvider::new(cfg.clone()).unwrap());
    let relay = Relay::default();
    let inv = wp.issue_invoice().unwrap()["invoice"].as_str().unwrap().to_string();
    assert_eq!(wp.accept(&k.sign(&receipt(&inv, 5, 50, 101, 102)).unwrap()).unwrap(), 50);
    // a stranger's receipt for an invoice with a record, with more work on it
    relay.put(&stranger.sign(&receipt(&inv, 6, 9_000, 101, 103)).unwrap());
    let before = stamp(&path);
    for _ in 0..3 {
        assert_eq!(wp.refresh(&relay).into_iter().map(|(_, r)| r.unwrap_err().code).collect::<Vec<_>>(), vec!["bad_sig"]);
    }
    assert_eq!(stamp(&path), before, "a receipt the Prime did not sign replaced the state file");
    // an older receipt of the Prime's: kept the first time it is seen (the book holds it for
    // fraud proofs), then nothing
    relay.put(&k.sign(&receipt(&inv, 4, 40, 101, 102)).unwrap());
    assert_eq!(wp.refresh(&relay).pop().unwrap().1.unwrap(), 0);
    let kept = stamp(&path);
    assert_ne!(kept, before, "a receipt the book now holds is on disk");
    for _ in 0..3 {
        assert_eq!(wp.refresh(&relay).pop().unwrap().1.unwrap(), 0);
    }
    assert_eq!(stamp(&path), kept, "the same older receipt again replaced the state file");
    // what the first sight wrote is what a restart reads
    drop(wp);
    let wp = Arc::new(WorkProvider::new(cfg).unwrap());
    assert_eq!((wp.balance(&inv), wp.refresh(&relay).pop().unwrap().1.unwrap()), (Some((50, 0)), 0));
    assert_eq!(stamp(&path), kept, "after a restart the receipt is still held: nothing to write");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other half of the rule: what did change is on disk when `accept` returns. An equivocation
/// the pull sees distrusts the Prime (`agp102_work`), and a restart still knows it.
#[test]
fn a_distrust_the_pull_set_is_kept_across_a_restart_and_writes_nothing_after_it() {
    let dir = state_dir("distrust");
    let k = key();
    let path = dir.join("work.json");
    let cfg = WorkConfig { state_path: Some(path.clone()), relay_url: Some("http://relay.test".into()), ..config(&k) };
    let wp = Arc::new(WorkProvider::new(cfg.clone()).unwrap());
    let relay = Relay::default();
    let doc = wp.issue_invoice().unwrap();
    let inv = doc["invoice"].as_str().unwrap().to_string();
    relay.put(&k.sign(&receipt(&inv, 1, 100, 101, 102)).unwrap());
    assert_eq!(wp.refresh(&relay).pop().unwrap().1.unwrap(), 100);
    relay.put(&k.sign(&receipt(&inv, 1, 200, 101, 102)).unwrap());
    assert_eq!(wp.refresh(&relay).pop().unwrap().1.unwrap_err().code, "equivocation");
    let written = std::fs::read(&path).unwrap();
    // every later round: refused with the distrust, nothing recorded, nothing written
    for _ in 0..3 {
        assert_eq!(wp.refresh(&relay).pop().unwrap().1.unwrap_err().code, "equivocation");
    }
    assert_eq!(std::fs::read(&path).unwrap(), written);
    drop(wp);
    let wp = Arc::new(WorkProvider::new(cfg).unwrap());
    let r = wp.report();
    assert_eq!((r["distrust"]["code"].clone(), r["equivocations"].as_array().unwrap().len()), (json!("equivocation"), 1));
    assert_eq!(call(&wp, &payment(&doc, &k, &receipt(&inv, 2, 300, 101, 103), 1, "/v1/a"), "/v1/a"), Err("equivocation".into()));
    // the credit granted before the equivocation stays what it was: distrust refuses, it does not erase
    assert_eq!((wp.balance(&inv), wp.exposure().0), (Some((100, 0)), 100));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A Prime distrusted for a failed audit and not for an equivocation: the same rule. Its receipt
/// for an invoice that has a record already credits nothing through the pull.
#[test]
fn a_distrusted_primes_receipt_credits_nothing_on_an_invoice_that_has_a_record() {
    let k = key();
    let wp = Arc::new(WorkProvider::new(WorkConfig { relay_url: Some("http://relay.test".into()), ..config(&k) }).unwrap());
    let relay = Relay::default();
    let (a, b) = (wp.issue_invoice().unwrap(), wp.issue_invoice().unwrap());
    let (ia, ib) = (a["invoice"].as_str().unwrap().to_string(), b["invoice"].as_str().unwrap().to_string());
    assert_eq!(wp.accept(&k.sign(&receipt(&ia, 1, 100, 101, 102)).unwrap()).unwrap(), 100);
    assert_eq!(wp.accept(&k.sign(&receipt(&ib, 1, 100, 101, 102)).unwrap()).unwrap(), 100);
    assert_eq!(wp.accept(&k.sign(&receipt(&ib, 1, 101, 101, 102)).unwrap()).unwrap_err().code, "equivocation");
    let later = k.sign(&receipt(&ia, 2, 500, 101, 103)).unwrap();
    assert_eq!(wp.accept(&later).unwrap_err().code, "equivocation", "refused with the distrust, as a call is");
    relay.put(&later);
    wp.refresh(&relay);
    assert_eq!((wp.balance(&ia), wp.exposure().0), (Some((100, 0)), 200));
    assert_eq!(wp.book().best(&ia).map(|s| s.receipt.seq), Some(1), "the book did not take it");
}

/// The rule of WORK 6 where it is kept, in the book: **one pair of receipts is one proof.** Each
/// of the three kinds of equivocation, offered five times.
#[test]
fn the_book_records_an_equivocation_once_however_often_it_is_offered() {
    const I: &str = "vfer2e5e75t4tv7in42lakx6i4";
    let k = key();
    let mut b = ReceiptBook::new(PROV, k.pubkey(), 70);
    b.accept(&k.sign(&receipt(I, 3, 30, 101, 102)).unwrap(), I).unwrap();
    b.accept(&k.sign(&receipt(I, 7, 70, 101, 104)).unwrap(), I).unwrap();
    // one seq, two states; a later seq with less work; an earlier seq with more
    let twins = [receipt(I, 7, 71, 101, 104), receipt(I, 9, 60, 101, 105), receipt(I, 5, 80, 101, 103)];
    for (n, t) in twins.iter().enumerate() {
        let s = k.sign(t).unwrap();
        for _ in 0..5 {
            assert_eq!(b.accept(&s, I).unwrap_err().code, "equivocation");
        }
        assert_eq!(b.fraud.len(), n + 1, "{t:?}");
        assert!(b.fraud.iter().all(|f| f.check(&k.pubkey())));
    }
}

/// What "nothing changed" rests on in `WorkProvider::accept`: a receipt the book holds already,
/// answered with no new credit, leaves the book as it was. Every receipt of a small space offered
/// in a fixed pseudo-random order, twice over, under caps that hold work back.
#[test]
fn a_receipt_the_book_holds_and_credits_nothing_for_leaves_the_book_unchanged() {
    const I: [&str; 2] = ["vfer2e5e75t4tv7in42lakx6i4", "vfer2e5e75t4tv7in42lakx6i5"];
    let k = key();
    let mut b = ReceiptBook::new(PROV, k.pubkey(), 70);
    b.caps.total = Some(120);
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let mut next = |n: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % n
    };
    let (mut unchanged, mut offered) = (0, 0);
    for _ in 0..1_200 {
        let inv = I[next(2) as usize];
        let seq = next(6);
        // mostly consistent (work follows seq), sometimes not: equivocations of every kind
        let cum = if next(8) == 0 { next(100) } else { seq * 20 };
        let s = k.sign(&receipt(inv, seq, cum, 101, 101 + seq as u32)).unwrap();
        let (held, before) = (b.holds(&s), b.to_json());
        let r = b.accept(&s, inv);
        offered += 1;
        if held && matches!(r, Ok(0)) {
            unchanged += 1;
            assert_eq!(b.to_json(), before, "{s:?}");
        }
        // room for held work now and then
        if next(50) == 0 {
            b.pay(200, 40);
        }
    }
    assert!(unchanged > 150, "{unchanged} of {offered}");
}

/// WORK 8, the neighbour: two saved sessions whose keys are spellings of one origin. Neither is
/// dropped: the payer refuses to start and names both, and the file is left as it was.
#[test]
fn two_saved_sessions_under_spellings_of_one_origin_are_refused_and_neither_is_dropped() {
    let dir = state_dir("payer2");
    let k = key();
    let path = dir.join("payer.json");
    let session = |inv: &str, cum: u64| json!({"accepted": {"scheme": "xbt-work", "network": NET, "amount": "10", "payTo": PROV, "extra": {"primePubkey": k.pubkey_hex()}},
                                             "invoice": {"invoice": inv, "identity": PROV, "authKey": "11".repeat(32)},
                                             "n": 4, "best": k.sign(&receipt(inv, 5, cum, 101, 102)).unwrap().to_doc(), "spent": 40, "unanswered": []});
    let raw = serde_json::to_vec(&json!({"http://API.example:80": session("vfer2e5e75t4tv7in42lakx6i4", 500),
                                         "http://api.example": session("vfer2e5e75t4tv7in42lakx6i5", 900),
                                         "https://other.example": session("vfer2e5e75t4tv7in42lakx6i6", 100)})).unwrap();
    std::fs::write(&path, &raw).unwrap();
    let e = WorkPayer::new(PayerConfig { network: NET.into(), state_path: Some(path.clone()), ..Default::default() }).err().expect("refused");
    assert_eq!(e.code, "bad_state");
    assert!(e.msg.contains("http://API.example:80") && e.msg.contains("http://api.example"), "{e}");
    assert_eq!(std::fs::read(&path).unwrap(), raw);
    // control: without the second spelling the file loads, and the other seller's session with it
    let one = serde_json::to_vec(&json!({"http://API.example:80": session("vfer2e5e75t4tv7in42lakx6i4", 500),
                                         "https://other.example": session("vfer2e5e75t4tv7in42lakx6i6", 100)})).unwrap();
    std::fs::write(&path, one).unwrap();
    let p = WorkPayer::new(PayerConfig { network: NET.into(), state_path: Some(path), ..Default::default() }).unwrap();
    assert_eq!(p.session("http://api.example").map(|s| s.credited()), Some(500));
    assert_eq!(p.session("https://other.example").map(|s| s.credited()), Some(100));
    let _ = std::fs::remove_dir_all(&dir);
}
