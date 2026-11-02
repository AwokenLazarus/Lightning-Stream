//! WebSockets through the gateway (docs/SELLER-APPS.md): a route that carries them joins the
//! buyer and the service into one two-way stream, and charges every byte of it, either way, as a
//! body's byte is charged; when the balance runs out and no refill comes, the stream ends.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use common::*;

/// Open a WebSocket on `target` with these extra headers; the gateway's answer head, and the
/// connection, ready for the stream.
fn open(addr: &str, target: &str, extra: &[(&str, &str)]) -> (String, TcpStream) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut head = format!("GET {target} HTTP/1.1\r\nHost: gateway.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: k1\r\nSec-WebSocket-Version: 13\r\n");
    for (k, v) in extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).unwrap();
    let mut got = vec![];
    let mut b = [0u8; 1];
    while !got.ends_with(b"\r\n\r\n") {
        assert_eq!(s.read(&mut b).unwrap(), 1, "the head ended early: {:?}", String::from_utf8_lossy(&got));
        got.push(b[0]);
    }
    (String::from_utf8(got).unwrap(), s)
}

/// Send `out` and read back as many bytes, or what comes before the connection ends.
fn echo(s: &mut TcpStream, out: &[u8]) -> Vec<u8> {
    s.write_all(out).unwrap();
    let mut back = vec![0u8; out.len()];
    let mut n = 0;
    while n < out.len() {
        match s.read(&mut back[n..]) {
            Ok(0) | Err(_) => break,
            Ok(k) => n += k,
        }
    }
    back.truncate(n);
    back
}

#[test]
fn a_free_websocket_is_joined_to_the_service_both_ways() {
    let (rig, _d) = start(&|_| {});
    let (head, mut s) = open(&rig.addr, "/wsfree/chat", &[]);
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert!(head.contains("Sec-WebSocket-Accept: accept-k1"), "the service's answer to the opening goes to the buyer: {head}");
    let msg: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
    assert_eq!(echo(&mut s, &msg), msg);
}

/// A paid WebSocket: the request's price at the opening, then every byte either way at the
/// route's price, from the session's balance; a receipt at the opening and a last one at the end.
#[test]
fn a_paid_websocket_charges_every_byte_either_way() {
    let (rig, _d) = start(&|_| {});
    let mut b = Buyer::new(&rig, 1);
    let secrets = b.lock(&rig, 2);
    let sig = b.sign("GET", "/ws/chat", b"", Some(&secrets[0]), None);
    let (head, mut s) = open(&rig.addr, "/ws/chat", &[("PAYMENT-SIGNATURE", &sig)]);
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert!(head.to_ascii_lowercase().contains("payment-response:"), "the opening carries its receipt: {head}");
    let msg = vec![7u8; 10 * 1024];
    assert_eq!(echo(&mut s, &msg).len(), msg.len());
    drop(s);
    // 2,500 msat to open, and 20 KiB at 1,000 msat a KiB: 10 KiB each way
    let want = 2_500 + 20 * 1_000;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let st = b.status();
        if st["session"]["spentMsat"].as_str() == Some(&want.to_string()) {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "spent {} msat, not {want}: {st}", st["session"]["spentMsat"]);
        std::thread::sleep(Duration::from_millis(50));
    }
    // and the operator's health counts it in what the shop charged (the seller's "Earned")
    let h = http(&rig.addr, "GET", "/x402/ticket/health", &[], b"", None).json();
    assert_eq!(h["chargedMsat"].as_str(), Some(want.to_string().as_str()), "{h}");
}

/// When the balance stops covering the next byte and no ticket comes within the refill wait, the
/// stream ends there: no byte goes unpaid.
#[test]
fn a_websocket_ends_where_the_balance_does() {
    let (rig, _d) = start(&|_| {});
    let mut b = Buyer::new(&rig, 1);
    let secrets = b.lock(&rig, 1);
    let sig = b.sign("GET", "/wsdear/chat", b"", Some(&secrets[0]), None);
    let (head, mut s) = open(&rig.addr, "/wsdear/chat", &[("PAYMENT-SIGNATURE", &sig)]);
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    // one ticket of 1,000 sat pays for 1 KiB at 1,000 sat a KiB: half a KiB out, half back
    let back = echo(&mut s, &vec![1u8; 4096]);
    assert!(back.len() <= 1024, "{} bytes came back, more than one ticket pays for", back.len());
    let mut rest = vec![];
    let _ = s.read_to_end(&mut rest);
    assert!(back.len() + rest.len() <= 1024);
}

/// A paid WebSocket whose buyer names the most it may charge (`X-Xbt402-Max-Msat`, a call's
/// `max_charge_sats`) is charged no more, as a body is: a large frame is cut at the cap, both
/// connections close there, and the seller's own count (the session's spend) stays within it,
/// however much the balance holds. FAILS before the socket path read the cap: an honest seller
/// went on relaying and charged the whole frame, and the buyer's wallet called it over its cap.
#[test]
fn a_paid_websocket_is_charged_no_more_than_the_buyers_limit_for_it() {
    let (rig, _d) = start(&|_| {});
    let mut b = Buyer::new(&rig, 1);
    let secrets = b.lock(&rig, 2);
    let sig = b.sign("GET", "/ws/chat", b"", Some(&secrets[0]), None);
    // 10 sat: 2,500 msat to open leaves 7,500 msat, 7.5 KiB at 1,000 msat a KiB, either way
    let (head, mut s) = open(&rig.addr, "/ws/chat", &[("PAYMENT-SIGNATURE", &sig), (xbt402::ticket::MAX_MSAT_HEADER, "10000")]);
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    // one frame of 64 KiB, far past the cap, sent whole
    let msg = vec![9u8; 64 * 1024];
    let back = echo(&mut s, &msg);
    let mut rest = vec![];
    let _ = s.read_to_end(&mut rest);
    let carried = back.len() + rest.len();
    assert!(carried < 7_680, "{carried} bytes came back: the socket went past the cap");
    drop(s);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let spent = loop {
        let st = b.status();
        let spent: u64 = st["session"]["spentMsat"].as_str().unwrap().parse().unwrap();
        // settled once the socket's last receipt is in: what it charged no longer grows
        std::thread::sleep(Duration::from_millis(200));
        let again: u64 = b.status()["session"]["spentMsat"].as_str().unwrap().parse().unwrap();
        if spent == again && spent > 2_500 {
            break spent;
        }
        assert!(std::time::Instant::now() < deadline, "the socket's charge never settled: {st}");
    };
    assert!(spent <= 10_000, "charged {spent} msat for a socket whose buyer allowed 10,000");
    // it used what it was allowed: up to the cap, not cut short of it by more than a chunk's worth
    assert!(spent >= 2_500 + 4_000, "charged only {spent} msat");
    let h = http(&rig.addr, "GET", "/x402/ticket/health", &[], b"", None).json();
    let earned: u64 = h["chargedMsat"].as_str().unwrap().parse().unwrap();
    assert_eq!(earned, spent, "the shop's count is the session's: {h}");
}
