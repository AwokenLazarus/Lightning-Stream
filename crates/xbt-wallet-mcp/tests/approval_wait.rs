//! `XBT_MCP_APPROVAL_WAIT_S`: a payment over the owner's threshold waits in the MCP for the human
//! (who approves or denies in the wallet's web UI), against a signer that follows a script.
#![cfg(unix)]
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Map, Value};
use xbt_wallet_mcp::wallet::Wallet;

/// A signer whose `ln_pay` needs the human until the token is approved, and whose
/// `approval_status` gives `states` one after the other (the last one from then on).
fn scripted_signer(dir: &Path, states: &'static [&'static str]) -> (PathBuf, Arc<Mutex<Vec<String>>>) {
    let sock = dir.join("signer.sock");
    let l = UnixListener::bind(&sock).unwrap();
    let seen = Arc::new(Mutex::new(vec![]));
    let s2 = seen.clone();
    std::thread::spawn(move || {
        let mut asked = 0;
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let mut line = String::new();
            BufReader::new(c.try_clone().unwrap()).read_line(&mut line).unwrap();
            let req: Value = serde_json::from_str(&line).unwrap();
            let method = req["method"].as_str().unwrap().to_string();
            s2.lock().unwrap().push(method.clone());
            // what the human's last answer was, as the signer knows it
            let state = if asked == 0 { "pending" } else { states[(asked - 1).min(states.len() - 1)] };
            let result = match method.as_str() {
                "approval_status" => {
                    asked += 1;
                    json!({"state": states[(asked - 1).min(states.len() - 1)]})
                }
                "ln_pay" if state == "approved" => json!({"verdict": "allow", "rail": "ln", "approved": true, "charged_sats": 1000}),
                _ => json!({"verdict": "needs_human", "rule": "human_threshold", "approval_token": "tok1", "approval_expires": 1}),
            };
            let _ = c.write_all(format!("{}\n", json!({"id": 1, "result": result})).as_bytes());
        }
    });
    (sock, seen)
}

fn args() -> Map<String, Value> {
    let mut a = Map::new();
    a.insert("invoice".into(), "lnbcrt1...".into());
    a.insert("max_sats".into(), 1000.into());
    a
}

fn call(w: &Wallet) -> Value {
    serde_json::from_str(&w.call_tool("ln_pay", args()).unwrap()).unwrap()
}

#[test]
fn without_a_wait_the_answer_is_needs_human_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, seen) = scripted_signer(dir.path(), &["pending"]);
    let v = call(&Wallet::new(sock));
    assert_eq!(v["verdict"], "needs_human");
    assert!(v.get("approval_state").is_none(), "{v}");
    assert_eq!(*seen.lock().unwrap(), ["ln_pay"], "the signer was asked once, and not for the approval's state");
}

#[test]
fn a_call_that_waits_is_paid_once_the_human_approves() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, seen) = scripted_signer(dir.path(), &["pending", "pending", "approved"]);
    let mut w = Wallet::new(sock);
    w.approval_wait = Duration::from_secs(30);
    let v = call(&w);
    assert_eq!((v["verdict"].as_str(), v["approved"].as_bool(), v["waited_for_human"].as_bool()), (Some("allow"), Some(true), Some(true)), "{v}");
    let seen = seen.lock().unwrap();
    assert_eq!(seen.iter().filter(|m| *m == "ln_pay").count(), 2, "asked, then asked again under the approval: {seen:?}");
    assert_eq!(seen.iter().filter(|m| *m == "approval_status").count(), 3, "{seen:?}");
}

#[test]
fn a_deny_ends_the_wait_with_the_first_answer_and_the_state() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, seen) = scripted_signer(dir.path(), &["pending", "denied"]);
    let mut w = Wallet::new(sock);
    w.approval_wait = Duration::from_secs(30);
    let v = call(&w);
    assert_eq!((v["verdict"].as_str(), v["approval_state"].as_str()), (Some("needs_human"), Some("denied")), "{v}");
    assert_eq!(seen.lock().unwrap().iter().filter(|m| *m == "ln_pay").count(), 1, "a denied payment is not asked for again");
}
