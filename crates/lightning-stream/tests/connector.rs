//! The connector against a stand-in signer: a body the signer streams reaches the client whole; a
//! call the signer refuses is said to the client plainly; a client that hangs up closes the socket
//! the signer writes to, which is what makes the real signer stop paying; a client's `Range` goes
//! to the signer, and the seller's 206 comes back with its range, from the head line the signer
//! writes before the body.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{json, Value};

/// A signer that answers one `xbt402_pay` per connection: `body` streamed to the call's socket
/// (the part a `range` names, as a 206, or all of it), after the head line where the call asked
/// for one (`head` in place of the one it would write, where given); or no body and `refusal` as
/// its answer. Reports each call's parameters, and whether the write of its body failed.
fn signer(dir: &Path, body: Vec<u8>, refusal: Option<Value>, head: Option<Value>) -> (PathBuf, mpsc::Receiver<(Value, bool)>) {
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
            let params = req["params"].clone();
            let result = match &refusal {
                Some(r) => r.clone(),
                None => {
                    let name = params["stream_to"].as_str().unwrap().to_string();
                    let mut out = UnixStream::connect(stream_dir.join(name)).unwrap();
                    let n = body.len();
                    let span = params["range"].as_str().and_then(|r| r.strip_prefix("bytes=")).and_then(|r| r.split_once('-'))
                        .map(|(a, b)| (a.parse::<usize>().unwrap(), if b.is_empty() { n - 1 } else { b.parse::<usize>().unwrap().min(n - 1) }));
                    let (status, part, mut line) = match span {
                        Some((a, b)) => (206, &body[a..=b], json!({"status": 206, "content_length": b - a + 1, "content_range": format!("bytes {a}-{b}/{n}"),
                                                                   "accept_ranges": "bytes", "content_type": "video/mp4"})),
                        None => (200, &body[..], json!({"status": 200, "content_length": n})),
                    };
                    if let Some(h) = &head {
                        line = h.clone();
                    }
                    if params["stream_head"] == true {
                        let _ = writeln!(out, "{line}");
                    }
                    let failed = line.get("error").is_none() && part.chunks(16 << 10).any(|c| {
                        std::thread::sleep(Duration::from_millis(2));
                        out.write_all(c).is_err()
                    });
                    let _ = tx.send((params.clone(), failed));
                    json!({"verdict": "allow", "status": status, "complete": !failed})
                }
            };
            let _ = writeln!(conn, "{}", json!({"id": 1, "result": result}));
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

fn get_with(addr: &str, target: &str, extra: &str) -> (u16, String, Vec<u8>) {
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    write!(s, "GET {target} HTTP/1.1\r\nHost: x\r\n{extra}Connection: close\r\n\r\n").unwrap();
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

fn get(addr: &str, target: &str) -> (u16, String, Vec<u8>) {
    get_with(addr, target, "")
}

fn film() -> Vec<u8> {
    let mut film = b"\0\0\0\x20ftypisom".to_vec();
    film.extend((0..300_000u32).map(|i| (i % 251) as u8));
    film
}

#[test]
fn a_body_the_signer_streams_reaches_the_client_whole_and_typed() {
    let dir = tempfile::tempdir().unwrap();
    let film = film();
    let (sock, calls) = signer(dir.path(), film.clone(), None, None);
    let addr = start(sock, dir.path());
    let (status, head, body) = get(&addr, "/s/https://seller.example/Videos/1/stream?static=true");
    assert_eq!(status, 200, "{head}");
    let lower = head.to_ascii_lowercase();
    assert!(lower.contains("content-type: video/mp4") && lower.contains("accept-ranges: bytes"), "{head}");
    assert!(lower.contains(&format!("content-length: {}", film.len())), "framed by the length the head stated: {head}");
    assert_eq!(body, film);
    let (params, _) = calls.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!((params["stream_head"].as_bool(), params.get("range")), (Some(true), None), "{params}");
    assert_eq!(get(&addr, "/health").0, 200);
}

#[test]
fn a_range_goes_to_the_signer_and_the_sellers_206_comes_back_with_its_range() {
    let dir = tempfile::tempdir().unwrap();
    let film = film();
    let n = film.len();
    let (sock, calls) = signer(dir.path(), film.clone(), None, None);
    let addr = start(sock, dir.path());
    let (status, head, body) = get_with(&addr, "/s/https://seller.example/Videos/1/stream?static=true", "Range: bytes=1000-\r\n");
    assert_eq!(status, 206, "{head}");
    let lower = head.to_ascii_lowercase();
    assert!(lower.contains(&format!("content-range: bytes 1000-{}/{n}", n - 1)), "{head}");
    assert!(lower.contains(&format!("content-length: {}", n - 1000)) && lower.contains("accept-ranges: bytes") && lower.contains("content-type: video/mp4"), "{head}");
    assert_eq!(body, film[1000..]);
    assert_eq!(calls.recv_timeout(Duration::from_secs(5)).unwrap().0["range"], "bytes=1000-");
    // a closed range
    let (status, head, body) = get_with(&addr, "/s/https://seller.example/v", "Range: bytes=10-19\r\n");
    assert_eq!((status, body.as_slice()), (206, &film[10..20]), "{head}");
    assert_eq!(calls.recv_timeout(Duration::from_secs(5)).unwrap().0["range"], "bytes=10-19");
    // a Range that is not one plain byte range is not passed on: the whole body, as HTTP allows
    for bad in ["bytes=0-1,5-9", "bytes=-500", "bytes=9-2", "lines=1-"] {
        let (status, _, body) = get_with(&addr, "/s/https://seller.example/v", &format!("Range: {bad}\r\n"));
        assert_eq!((status, body.len()), (200, n), "{bad}");
        assert!(calls.recv_timeout(Duration::from_secs(5)).unwrap().0.get("range").is_none(), "{bad}");
    }
    assert!(lightning_stream::one_range("bytes=0-") && !lightning_stream::one_range("bytes=1-0"));
}

#[test]
fn a_head_the_signer_will_not_read_past_is_a_502() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, _) = signer(dir.path(), film(), None, Some(json!({"status": 206, "error": "the seller's 206 is for bytes 0-9, not the range asked for (bytes=5-)"})));
    let addr = start(sock, dir.path());
    let (status, _, body) = get_with(&addr, "/s/https://seller.example/v", "Range: bytes=5-\r\n");
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status, 502, "{v}");
    assert!(v["error"].as_str().unwrap().contains("not the range asked for"), "{v}");
}

#[test]
fn a_call_the_signer_refuses_is_said_plainly_and_streams_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, _) = signer(dir.path(), vec![], Some(json!({"verdict": "deny", "rule": "ticket_task_budget", "reason": "the task's budget is used up"})), None);
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
    let (sock, wrote) = signer(dir.path(), vec![7u8; 40 << 20], None, None);
    let addr = start(sock, dir.path());
    let mut s = std::net::TcpStream::connect(&addr).unwrap();
    write!(s, "GET /s/https://seller.example/big HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    let mut buf = vec![0u8; 256 << 10];
    s.read_exact(&mut buf).unwrap();
    drop(s);
    assert!(wrote.recv_timeout(Duration::from_secs(20)).unwrap().1, "the signer's writes failed once the client had gone");
}
