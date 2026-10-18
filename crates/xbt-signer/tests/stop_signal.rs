//! The shipped binaries stop on SIGTERM, as a container stop sends it: the request in flight is
//! answered, no new one is taken, the socket is removed, the process exits 0 well inside Docker's
//! 10 s grace period, and what it wrote is whole and read back by the next start. Before this a
//! signer that was PID 1 ignored SIGTERM (no handler), and anywhere else it died of it at once.
#![cfg(unix)]
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

const SIGNER: &str = env!("CARGO_BIN_EXE_xbt-signer");
const WITNESS: &str = env!("CARGO_BIN_EXE_xbt-anchor-witness");

/// A node whose every answer takes `delay`: a request to the signer that asks it is in flight that long.
fn slow_node(delay: Duration) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && s.read(&mut b).map(|n| n == 1).unwrap_or(false) {
                    head.push(b[0]);
                }
                let text = String::from_utf8_lossy(&head).to_ascii_lowercase();
                let n: usize = text.lines().find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0))).unwrap_or(0);
                let mut body = vec![0u8; n];
                let _ = s.read_exact(&mut body);
                std::thread::sleep(delay);
                let answer = r#"{"result":{"mine":{"trusted":0.5,"untrusted_pending":0,"immature":0}},"error":null,"id":1}"#;
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}", answer.len()).as_bytes());
            });
        }
    });
    port
}

fn signer(root: &Path, node_port: u16) -> Child {
    Command::new(SIGNER)
        .env_clear()
        .env("B2_ROOT", root)
        .env("B2_SIGNER_SOCK", root.join("signer.sock"))
        .env("XBT_MODE", "dev")
        .env("B2_CHAIN", "regtest")
        .env("B2_RPCHOST", "127.0.0.1")
        .env("B2_RPCPORT", node_port.to_string())
        .env("B2_RPCCOOKIE", root.join("node.cookie"))
        .env("B2_HOT_ALLOW_PLAINTEXT", "1")
        .env("B2_WATCH_INTERVAL", "0.2")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// One request on its own connection: the answer, or the error the socket gave.
fn call(sock: &Path, method: &str, params: Value) -> Result<Value, String> {
    let mut s = std::os::unix::net::UnixStream::connect(sock).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    s.write_all(format!("{}\n", json!({"id": 1, "method": method, "params": params})).as_bytes()).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(&line).map_err(|e| format!("{e}: {line:?}"))?;
    match v.get("result") {
        Some(r) => Ok(r.clone()),
        None => Err(v["error"]["message"].as_str().unwrap_or("").to_string()),
    }
}

fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let t0 = Instant::now();
    while !f() {
        assert!(t0.elapsed() < Duration::from_secs(20), "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn term(child: &Child) {
    assert!(Command::new("kill").args(["-TERM", &child.id().to_string()]).status().unwrap().success());
}

/// How the child ended, and how long after `since`; panics past `most`.
fn exit_within(child: &mut Child, since: Instant, most: Duration) -> (std::process::ExitStatus, Duration) {
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            return (st, since.elapsed());
        }
        if since.elapsed() > most {
            let _ = child.kill();
            panic!("still running {most:?} after SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn stderr_of(child: &mut Child) -> String {
    let mut s = String::new();
    child.stderr.take().unwrap().read_to_string(&mut s).unwrap();
    s
}

/// Every line of an append-only log is one whole JSON value.
fn whole_lines(p: &PathBuf) -> Vec<Value> {
    let text = std::fs::read_to_string(p).unwrap();
    assert!(text.ends_with('\n'), "{} ends inside a row", p.display());
    text.lines().map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{}: {e}: {l:?}", p.display()))).collect()
}

#[test]
fn the_signer_answers_what_is_in_flight_and_exits_0_on_sigterm() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("root");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("policy.json"), r#"{"allowlist": [], "anchor_required": false}"#).unwrap();
    std::fs::write(root.join("node.cookie"), "u:p").unwrap();
    let sock = root.join("signer.sock");
    let node = slow_node(Duration::from_millis(800));
    let mut child = signer(&root, node);
    wait_for("the signer's socket", || call(&sock, "health", json!({})).is_ok());
    // something on disk before the stop: a refusal is booked in the audit log
    let denied = call(&sock, "pay", json!({"to": "bcrt1qxyz", "amount_sats": 1000})).unwrap();
    assert_eq!(denied["verdict"], "deny");
    // a request that waits on the node is in flight when SIGTERM arrives
    let s2 = sock.clone();
    let in_flight = std::thread::spawn(move || call(&s2, "balance", json!({})));
    std::thread::sleep(Duration::from_millis(250));
    let t0 = Instant::now();
    term(&child);
    // while it drains: no new request is taken
    std::thread::sleep(Duration::from_millis(100));
    let late = call(&sock, "health", json!({}));
    assert!(late.is_err(), "a request after SIGTERM was answered: {late:?}");
    let (st, took) = exit_within(&mut child, t0, Duration::from_secs(8));
    let said = stderr_of(&mut child);
    assert!(st.success(), "exit {st:?}: {said}");
    assert!(took < Duration::from_secs(5), "took {took:?}: {said}");
    assert!(said.contains("SIGTERM received") && said.contains("xbt-signer: stopped"), "{said}");
    let answered = in_flight.join().unwrap();
    assert!(answered.is_ok(), "the request in flight was cut: {answered:?}");
    assert!(!sock.exists(), "the socket is removed");
    // what it wrote is whole, and the next start reads it
    let audit = whole_lines(&root.join(".run").join("audit.jsonl"));
    assert!(audit.iter().any(|r| r["verdict"] == "deny" && r["dest"] == "bcrt1qxyz"), "{audit:?}");
    let mut again = signer(&root, node);
    wait_for("the signer's socket again", || call(&sock, "health", json!({})).is_ok());
    let history = call(&sock, "history", json!({})).unwrap();
    assert!(history["events"].as_array().unwrap().iter().any(|e| e["dest"] == "bcrt1qxyz"), "{history}");
    let t0 = Instant::now();
    term(&again);
    let (st, _) = exit_within(&mut again, t0, Duration::from_secs(8));
    assert!(st.success(), "{st:?}");
}

#[test]
fn the_witness_exits_0_on_sigterm_with_its_store_whole() {
    let d = tempfile::tempdir().unwrap();
    let (store, sock) = (d.path().join("store"), d.path().join("anchor.sock"));
    let start = || Command::new(WITNESS).arg("serve").arg("--store").arg(&store).arg("--sock").arg(&sock).env_clear()
        .stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let mut child = start();
    wait_for("the witness's socket", || call(&sock, "latest", json!({})).is_ok());
    let latest = call(&sock, "latest", json!({})).unwrap();
    let t0 = Instant::now();
    term(&child);
    let (st, took) = exit_within(&mut child, t0, Duration::from_secs(8));
    let said = stderr_of(&mut child);
    assert!(st.success() && took < Duration::from_secs(2), "exit {st:?} after {took:?}: {said}");
    assert!(!sock.exists(), "the socket is removed");
    let mut again = start();
    wait_for("the witness's socket again", || call(&sock, "latest", json!({})).is_ok());
    assert_eq!(call(&sock, "latest", json!({})).unwrap(), latest);
    term(&again);
    let (st, _) = exit_within(&mut again, Instant::now(), Duration::from_secs(8));
    assert!(st.success());
}
