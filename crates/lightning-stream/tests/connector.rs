//! The connector against a stand-in signer: a body the signer streams reaches the client whole; a
//! call the signer refuses is said to the client plainly; a client that hangs up closes the socket
//! the signer writes to, which is what makes the real signer stop paying.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{json, Value};

/// A signer that answers one `xbt402_pay` per connection: `body` streamed to the call's socket, or
/// no body and `refusal` as its answer. Reports whether the write of the whole body failed.
fn signer(dir: &Path, body: Vec<u8>, refusal: Option<Value>) -> (PathBuf, mpsc::Receiver<bool>) {
    let sock = dir.join("signer.sock");
    let l = UnixListener::bind(&sock).unwrap();
    let stream_dir = dir.to_path_buf();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for conn in l.incoming() {
            let mut conn = conn.unwrap();
            let mut line = String::new();
            BufReader::new(conn.try_clone().unwrap()).read_line(&mut line).unwrap();
            let req: Value = serde_json::from_str(&line).unwrap();
            if req["method"] == "ln_status" {
                writeln!(conn, "{}", json!({"id": 1, "result": {"ready": true}})).unwrap();
                continue;
            }
            let result = match &refusal {
                Some(r) => r.clone(),
                None => {
                    let name = req["params"]["stream_to"].as_str().unwrap().to_string();
                    let mut out = UnixStream::connect(stream_dir.join(name)).unwrap();
                    let failed = body.chunks(16 << 10).any(|c| {
                        std::thread::sleep(Duration::from_millis(2));
                        out.write_all(c).is_err()
                    });
                    let _ = tx.send(failed);
                    json!({"verdict": "allow", "complete": !failed})
                }
            };
            writeln!(conn, "{}", json!({"id": 1, "result": result})).unwrap();
        }
    });
    (sock, rx)
}

fn start(sock: PathBuf, dir: &Path) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let cfg = lightning_stream::Config { signer: sock, stream_dir: dir.to_path_buf(), task: "film".into(), max_sats: 2_000 };
    let run = lightning_stream::serve(cfg, l).unwrap();
    let addr = run.addr.to_string();
    std::mem::forget(run);
    addr
}

fn get(addr: &str, target: &str) -> (u16, String, Vec<u8>) {
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    write!(s, "GET {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    let mut all = vec![];
    s.read_to_end(&mut all).unwrap();
    let split = all.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&all[..split]).to_string();
    let status = head[9..12].parse().unwrap();
    let mut body = all[split + 4..].to_vec();
    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        let mut out = vec![];
        let mut rest = &body[..];
        loop {
            let nl = rest.windows(2).position(|w| w == b"\r\n").unwrap();
            let n = usize::from_str_radix(std::str::from_utf8(&rest[..nl]).unwrap().trim(), 16).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&rest[nl + 2..nl + 2 + n]);
            rest = &rest[nl + 4 + n..];
        }
        body = out;
    }
    (status, head, body)
}

#[test]
fn a_body_the_signer_streams_reaches_the_client_whole_and_typed() {
    let dir = tempfile::tempdir().unwrap();
    let mut film = b"\0\0\0\x20ftypisom".to_vec();
    film.extend((0..300_000u32).map(|i| (i % 251) as u8));
    let (sock, _) = signer(dir.path(), film.clone(), None);
    let addr = start(sock, dir.path());
    let (status, head, body) = get(&addr, "/s/https://seller.example/Videos/1/stream?static=true");
    assert_eq!(status, 200, "{head}");
    assert!(head.to_ascii_lowercase().contains("content-type: video/mp4"), "{head}");
    assert_eq!(body, film);
    assert_eq!(get(&addr, "/health").0, 200);
}

#[test]
fn a_call_the_signer_refuses_is_said_plainly_and_streams_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, _) = signer(dir.path(), vec![], Some(json!({"verdict": "deny", "rule": "ticket_task_budget", "reason": "the task's budget is used up"})));
    let addr = start(sock, dir.path());
    let (status, _, body) = get(&addr, "/s/https://seller.example/x");
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!((status, v["rule"].as_str()), (402, Some("ticket_task_budget")), "{v}");
    assert_eq!(get(&addr, "/s/ftp://x").0, 400);
    assert_eq!(get(&addr, "/other").0, 404);
}

#[test]
fn a_client_that_hangs_up_closes_the_signers_socket() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, wrote) = signer(dir.path(), vec![7u8; 40 << 20], None);
    let addr = start(sock, dir.path());
    let mut s = std::net::TcpStream::connect(&addr).unwrap();
    write!(s, "GET /s/https://seller.example/big HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    let mut buf = vec![0u8; 256 << 10];
    s.read_exact(&mut buf).unwrap();
    drop(s);
    assert!(wrote.recv_timeout(Duration::from_secs(20)).unwrap(), "the signer's writes failed once the client had gone");
}
