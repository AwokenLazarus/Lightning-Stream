//! A streamed answer over real sockets: a known length is `Content-Length` and never exceeded, an
//! unknown one is chunked, a body that fails is cut short where the client can see it, `HEAD` runs
//! no body, a streaming handler leaves its handler slot before the body, and a client that takes
//! nothing ends the stream at the write deadline.
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use xbt_svc::http::{serve_with, Handler, Limits, Reply, Request, Response, Running, Streamed};

struct T {
    sent: Arc<AtomicUsize>,
}

impl Handler for T {
    fn body_limit(&self, _method: &str, _target: &str) -> usize {
        0
    }

    fn handle(&self, _req: Request) -> Response {
        Response::text(200, "text/plain", "whole")
    }

    fn reply(&self, req: Request) -> Reply {
        let sent = self.sent.clone();
        let (length, fail, parts): (Option<u64>, bool, Vec<&'static [u8]>) = match req.path() {
            "/known" => (Some(6), false, vec![b"abc", b"def"]),
            "/chunked" => (None, false, vec![b"abc", b"", b"def"]),
            "/cut" => (None, true, vec![b"abc"]),
            "/short" => (Some(6), true, vec![b"abc"]),
            "/long" => (Some(4), false, vec![b"abc", b"def"]),
            "/slow" => (None, false, vec![]),
            "/flood" => (None, false, vec![&[0u8; 65536]; 4096]),
            _ => return Reply::Whole(self.handle(req)),
        };
        let slow = req.path() == "/slow";
        Reply::Stream(Streamed {
            status: 200,
            headers: vec![("X-A".into(), "1".into()), ("Content-Length".into(), "999".into())],
            length,
            body: Box::new(move |out| {
                if slow {
                    std::thread::sleep(Duration::from_millis(600));
                    out.send(b"late")?;
                }
                for p in parts {
                    out.send(p)?;
                    sent.fetch_add(p.len(), Ordering::SeqCst);
                }
                if fail {
                    return Err(io::Error::other("the source failed"));
                }
                Ok(())
            }),
        })
    }
}

fn start(threads: usize, stall: Duration) -> (Running, String, Arc<AtomicUsize>) {
    let sent = Arc::new(AtomicUsize::new(0));
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let limits = Limits { stream_write: stall, ..Limits::default() };
    let run = serve_with(Arc::new(T { sent: sent.clone() }), l, threads, limits).unwrap();
    let addr = run.addr.to_string();
    (run, addr, sent)
}

fn ask(addr: &str, method: &str, path: &str) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(s, "{method} {path} HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn a_known_length_is_content_length_and_an_unknown_one_is_chunked() {
    let (run, addr, _) = start(2, Duration::from_secs(5));
    let r = ask(&addr, "GET", "/known");
    assert!(r.starts_with("HTTP/1.1 200 OK\r\n") && r.contains("\r\nContent-Length: 6\r\n") && r.ends_with("\r\n\r\nabcdef"), "{r}");
    assert!(!r.contains("999") && !r.to_lowercase().contains("transfer-encoding") && r.contains("X-A: 1"), "{r}");
    let r = ask(&addr, "GET", "/chunked");
    assert!(r.contains("\r\nTransfer-Encoding: chunked\r\n") && r.ends_with("\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n"), "{r}");
    assert!(!r.to_lowercase().contains("content-length"), "{r}");
    run.stopper().stop();
}

#[test]
fn a_body_that_fails_is_cut_short_where_the_client_can_tell() {
    let (run, addr, _) = start(2, Duration::from_secs(5));
    let r = ask(&addr, "GET", "/cut");
    assert!(r.ends_with("\r\n\r\n3\r\nabc\r\n"), "no last chunk: {r}");
    let r = ask(&addr, "GET", "/short");
    assert!(r.contains("Content-Length: 6") && r.ends_with("\r\n\r\nabc"), "{r}");
    // a body longer than it announced stops at the announced length's last whole write
    let r = ask(&addr, "GET", "/long");
    assert!(r.contains("Content-Length: 4") && r.ends_with("\r\n\r\nabc"), "{r}");
    run.stopper().stop();
}

#[test]
fn head_runs_no_body() {
    let (run, addr, sent) = start(2, Duration::from_secs(5));
    let r = ask(&addr, "HEAD", "/known");
    assert!(r.contains("Content-Length: 6") && r.ends_with("\r\n\r\n"), "{r}");
    assert_eq!(sent.load(Ordering::SeqCst), 0);
    run.stopper().stop();
}

#[test]
fn a_streaming_answer_does_not_hold_the_handler_slot() {
    // one handler slot: while /slow's body sleeps, another request is answered
    let (run, addr, _) = start(1, Duration::from_secs(5));
    let a = addr.clone();
    let slow = std::thread::spawn(move || ask(&a, "GET", "/slow"));
    std::thread::sleep(Duration::from_millis(150));
    let t = Instant::now();
    assert!(ask(&addr, "GET", "/whole").ends_with("whole"));
    assert!(t.elapsed() < Duration::from_millis(400), "{:?}", t.elapsed());
    assert!(slow.join().unwrap().ends_with("4\r\nlate\r\n0\r\n\r\n"));
    run.stopper().stop();
}

#[test]
fn a_client_that_takes_nothing_ends_the_stream_at_the_write_deadline() {
    let (run, addr, sent) = start(2, Duration::from_millis(300));
    let mut s = TcpStream::connect(&addr).unwrap();
    write!(s, "GET /flood HTTP/1.1\r\nHost: t\r\n\r\n").unwrap();
    // never read: the socket buffers fill, a write waits 300 ms, the body ends
    let t = Instant::now();
    let mut last = 0;
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let now = sent.load(Ordering::SeqCst);
        if now == last {
            break;
        }
        last = now;
        assert!(t.elapsed() < Duration::from_secs(20), "the stream never stopped");
    }
    assert!(last < 4096 * 65536, "the whole body went to a client that read nothing");
    drop(s);
    run.stopper().stop();
}
