//! A paying call waits for the signer's answer as long as the signer works on it; any other call
//! gives up after `B2_SIGNER_TIMEOUT`; and a paying call whose answer is lost after it was sent says
//! that it may have paid, never that nothing happened. Against a signer that answers late, or not at all.
#![cfg(unix)]
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Map, Value};
use xbt_wallet_mcp::wallet::Wallet;

#[derive(Clone, Copy)]
enum Answer {
    /// the answer, after this long
    After(Duration),
    /// the request is read, then the connection is closed with no answer
    Never,
}

/// A signer that answers every call as `answer` says.
fn signer(dir: &Path, answer: Answer) -> PathBuf {
    let sock = dir.join("signer.sock");
    let l = UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            std::thread::spawn(move || {
                let mut line = String::new();
                BufReader::new(c.try_clone().unwrap()).read_line(&mut line).unwrap();
                let req: Value = serde_json::from_str(&line).unwrap();
                match answer {
                    Answer::After(d) => {
                        std::thread::sleep(d);
                        let result = json!({"verdict": "allow", "rail": "lottery", "method": req["method"], "charged_sats": 65});
                        let _ = c.write_all(format!("{}\n", json!({"id": 1, "result": result})).as_bytes());
                    }
                    Answer::Never => drop(c),
                }
            });
        }
    });
    sock
}

/// A wallet that gives up on an answer after one second.
fn wallet(sock: PathBuf) -> Wallet {
    let mut w = Wallet::new(sock);
    w.timeout = Duration::from_secs(1);
    w
}

fn pay_args() -> Map<String, Value> {
    let mut a = Map::new();
    a.insert("url".into(), "http://127.0.0.1:9/film.bin".into());
    a.insert("max_sats".into(), 200.into());
    a
}

fn ln_args() -> Map<String, Value> {
    let mut a = Map::new();
    a.insert("invoice".into(), "lnbcrt1...".into());
    a.insert("max_sats".into(), 1000.into());
    a
}

#[test]
fn a_paying_call_waits_for_an_answer_that_comes_after_the_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let w = wallet(signer(dir.path(), Answer::After(Duration::from_secs(3))));
    for (tool, args) in [("xbt402_pay", pay_args()), ("ln_pay", ln_args())] {
        let v: Value = serde_json::from_str(&w.call_tool(tool, args).unwrap()).unwrap();
        assert_eq!((v["verdict"].as_str(), v["method"].as_str()), (Some("allow"), Some(tool)), "{tool}: {v}");
    }
}

#[test]
fn any_other_call_still_gives_up_after_the_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let w = wallet(signer(dir.path(), Answer::After(Duration::from_secs(3))));
    let t0 = std::time::Instant::now();
    let e = w.call_tool("ticket_status", Map::new()).unwrap_err();
    assert!(t0.elapsed() < Duration::from_millis(2500), "gave up after {:?}", t0.elapsed());
    assert!(e.starts_with("signer socket "), "{e}");
}

#[test]
fn a_paying_call_whose_answer_is_lost_says_it_may_have_paid() {
    let dir = tempfile::tempdir().unwrap();
    let w = wallet(signer(dir.path(), Answer::Never));
    for (tool, args) in [("xbt402_pay", pay_args()), ("ln_pay", ln_args())] {
        let v: Value = serde_json::from_str(&w.call_tool(tool, args).unwrap()).unwrap();
        assert_eq!((v["verdict"].as_str(), v["rule"].as_str(), v["request_sent"].as_bool()),
                   (Some("unknown"), Some("signer_no_answer"), Some(true)), "{tool}: {v}");
        assert!(v["reason"].as_str().is_some_and(|r| r.contains("may have paid")), "{tool}: {v}");
    }
}

#[test]
fn a_paying_call_that_never_reached_the_signer_is_an_error_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let w = wallet(dir.path().join("no-signer.sock"));
    let e = w.call_tool("xbt402_pay", pay_args()).unwrap_err();
    assert!(e.starts_with("signer socket "), "{e}");
}
