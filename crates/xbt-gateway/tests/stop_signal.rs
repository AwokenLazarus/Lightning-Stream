//! The shipped binary stops on SIGTERM, as a container stop (through `xbt-supervise`) sends it: no
//! new connection, the request in flight answered, the book's counters journalled, the journal
//! fsynced and closed, exit 0 well inside Docker's 10 s grace period; and the next start reads the
//! journal back whole. Before this the gateway died of SIGTERM at once, with what the janitor had
//! not yet written (up to one tick of counters), or, as PID 1, ignored it until the kill.
#![cfg(unix)]
mod common;

use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::macaroon::lnd_macaroon_for_tests as macaroon;
use xbt_svc::http::{serve, Body, Handler, Reply, Request, Response, Streamed};

const BIN: &str = env!("CARGO_BIN_EXE_xbt-gateway");

/// The few lnd REST calls a gateway makes while it opens a session, over plain http on loopback:
/// every invoice is open, and stays so.
struct Lnd;

impl Handler for Lnd {
    fn body_limit(&self, _m: &str, _t: &str) -> usize {
        1 << 16
    }

    fn handle(&self, _req: Request) -> Response {
        Response::text(500, "text/plain", "unused")
    }

    fn reply(&self, req: Request) -> Reply {
        let json = |v: Value| Reply::Whole(Response::text(200, "application/json", v.to_string()));
        let open = json!({"state": "OPEN", "htlcs": []});
        match req.path() {
            "/v1/getinfo" => json(json!({"identity_pubkey": format!("02{}", "11".repeat(32)), "block_height": 200, "synced_to_chain": true,
                                         "chains": [{"chain": "bitcoin", "network": "regtest"}], "features": {"512": {"name": "blake2b"}}})),
            "/v2/invoices/hodl" => json(json!({"payment_request": "lnbcrt10u1stopsignaltest"})),
            "/v2/invoices/lookup" => json(open),
            "/v2/invoices/cancel" => json(json!({})),
            p if p.starts_with("/v2/invoices/subscribe/") => {
                // the state now, then nothing: the stream stays open as the node's does
                let body: Body = Box::new(move |out| {
                    out.send(format!("{}\n", json!({"result": open})).as_bytes())?;
                    std::thread::sleep(Duration::from_secs(30));
                    Ok(())
                });
                Reply::Stream(Streamed { status: 200, headers: vec![("Content-Type".into(), "application/json".into())], length: None, body })
            }
            _ => Reply::Whole(Response::text(404, "text/plain", "not found")),
        }
    }
}

/// The seller's service: `/free/slow` answers after a second.
struct Slow;

impl Handler for Slow {
    fn body_limit(&self, _m: &str, _t: &str) -> usize {
        0
    }

    fn handle(&self, req: Request) -> Response {
        if req.path() == "/free/slow" {
            std::thread::sleep(Duration::from_secs(1));
            return Response::text(200, "text/plain", "done");
        }
        Response::text(404, "text/plain", "no such thing")
    }
}

fn config(dir: &Path, node: &str, upstream: &str) -> std::path::PathBuf {
    std::fs::write(dir.join("invoices.macaroon"), macaroon(&[("invoices", &["read", "write"])], &[])).unwrap();
    std::fs::write(dir.join("info.macaroon"), macaroon(&[("info", &["read"])], &[])).unwrap();
    let v = json!({"listen": "127.0.0.1:0", "public_url": "http://127.0.0.1:8402", "upstream": upstream, "state_dir": dir.join("state"),
        "chain": "regtest", "network": common::NET,
        "node": {"rest": node, "macaroon": dir.join("invoices.macaroon"), "info_macaroon": dir.join("info.macaroon")},
        "caps": {"sessions_per_address": 0, "held_after_paid": false, "unpaid_per_address": 0},
        "routes": [{"path": "/hang", "price": {"request_msat": 2500}}, {"path": "/free/", "free": true}]});
    let path = dir.join("gateway.json");
    std::fs::write(&path, v.to_string()).unwrap();
    path
}

/// Start the binary; its child, and the address it says it listens on.
fn start(cfg: &Path) -> (Child, String, std::thread::JoinHandle<String>) {
    let mut child = Command::new(BIN).arg(cfg).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let mut err = BufReader::new(child.stderr.take().unwrap());
    let t0 = Instant::now();
    let mut said = String::new();
    let addr = loop {
        let mut line = String::new();
        assert!(err.read_line(&mut line).unwrap() > 0 && t0.elapsed() < Duration::from_secs(20), "no listener: {said}");
        said.push_str(&line);
        if let Some(rest) = line.split("listening on ").nth(1) {
            break rest.split(';').next().unwrap().trim().to_string();
        }
    };
    // the rest of what it says, for the asserts after it stops
    let rest = std::thread::spawn(move || {
        let mut s = said;
        let _ = err.read_to_string(&mut s);
        s
    });
    (child, addr, rest)
}

fn term(child: &Child) {
    assert!(Command::new("kill").args(["-TERM", &child.id().to_string()]).status().unwrap().success());
}

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

#[test]
fn the_gateway_journals_and_exits_0_on_sigterm_and_starts_again_on_its_journal() {
    let d = tempfile::tempdir().unwrap();
    let lnd = serve(Arc::new(Lnd), std::net::TcpListener::bind("127.0.0.1:0").unwrap(), 8).unwrap();
    let svc = serve(Arc::new(Slow), std::net::TcpListener::bind("127.0.0.1:0").unwrap(), 4).unwrap();
    let cfg = config(d.path(), &format!("http://{}", lnd.addr), &format!("http://{}", svc.addr));
    let (mut child, addr, said) = start(&cfg);
    // a session with two tickets: the journal has it, synced, before the invoices are handed out
    let hashes: Vec<String> = (1u8..=2).map(|i| hex::encode(xbt402::ticket::ticket_hash(&[i; 32]))).collect();
    let body = json!({"version": "ticket/0", "hashes": hashes}).to_string();
    let got = common::http(&addr, "POST", "/x402/ticket/lock", &[], body.as_bytes(), None);
    assert_eq!(got.status, 200, "{}", got.error());
    let session = got.json()["session"].as_str().unwrap().to_string();
    // a request in flight when the stop arrives: the service takes a second over it
    let a2 = addr.clone();
    let slow = std::thread::spawn(move || common::http(&a2, "GET", "/free/slow", &[], b"", None));
    std::thread::sleep(Duration::from_millis(300));
    let t0 = Instant::now();
    term(&child);
    // while it drains, the listener takes nothing new
    std::thread::sleep(Duration::from_millis(100));
    assert!(std::net::TcpStream::connect(&addr).is_err(), "a connection after SIGTERM was taken");
    let (st, took) = exit_within(&mut child, t0, Duration::from_secs(9));
    let said = said.join().unwrap();
    assert!(st.success(), "exit {st:?}: {said}");
    assert!(took < Duration::from_secs(3), "took {took:?}: {said}");
    assert!(said.contains("SIGTERM received") && said.contains("xbt-gateway: stopped"), "{said}");
    let slow = slow.join().unwrap();
    assert_eq!((slow.status, slow.body.as_slice()), (200, &b"done"[..]), "the request in flight was answered in full");
    // the journal is whole: every line one record, the last one ended
    let journal = d.path().join("state").join("journal.jsonl");
    let text = std::fs::read_to_string(&journal).unwrap();
    assert!(text.ends_with('\n') && text.contains(&session), "{text}");
    for l in text.lines() {
        serde_json::from_str::<Value>(l).unwrap_or_else(|e| panic!("{e}: {l:?}"));
    }
    // and the next start reads it: the session is still there, with its two tickets
    let (mut again, addr, said) = start(&cfg);
    let health = common::http(&addr, "GET", "/x402/ticket/health", &[], b"", None).json();
    assert_eq!((health["sessions"].as_u64(), health["heldTickets"].as_u64()), (Some(1), Some(2)), "{health}");
    let t0 = Instant::now();
    term(&again);
    let (st, took) = exit_within(&mut again, t0, Duration::from_secs(9));
    let said = said.join().unwrap();
    assert!(st.success() && took < Duration::from_secs(2), "exit {st:?} after {took:?}: {said}");
    assert!(said.contains("xbt-gateway: stopped"), "{said}");
}

#[test]
fn a_gateway_waiting_for_its_node_stops_at_once() {
    let d = tempfile::tempdir().unwrap();
    // a node that is not there: the gateway waits for it, and a stop ends the wait
    let cfg = config(d.path(), "http://127.0.0.1:1", "http://127.0.0.1:1");
    let mut child = Command::new(BIN).arg(&cfg).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let mut err = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    while !line.contains("waiting for the node") {
        line.clear();
        assert!(err.read_line(&mut line).unwrap() > 0, "it never said it waits");
    }
    let t0 = Instant::now();
    term(&child);
    let (st, took) = exit_within(&mut child, t0, Duration::from_secs(9));
    assert!(st.success() && took < Duration::from_secs(1), "exit {st:?} after {took:?}");
}
