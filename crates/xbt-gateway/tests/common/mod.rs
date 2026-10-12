//! A gateway in process, over real sockets: the stand-in node, a small service behind the gateway
//! that records what reached it, and a buyer that speaks the wire draft.
#![allow(dead_code)]
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use xbt402::ticket;
use xbt402::wire::{b64json, request_digest_v2, unb64json};
use xbt402::xbt_primitives::ecdsa;
use xbt_gateway::config::Config;
use xbt_gateway::gateway::Gateway;
use xbt_gateway::node::{Hash, InvoiceState};
use xbt_gateway::standin::StandIn;
use xbt_svc::http::{serve_with, Handler, Limits, Reply, Request, Response, Running, Streamed};

pub const NET: &str = "lightning:00000000000000000000000000000001";

// --- the service behind the gateway -----------------------------------------------------------------

#[derive(Default)]
pub struct Service {
    pub hits: AtomicUsize,
    pub seen: Mutex<Vec<Request>>,
}

/// Byte `i` of every generated body.
pub fn pattern(i: usize) -> u8 {
    (i % 251) as u8
}

impl Handler for Service {
    fn body_limit(&self, _m: &str, _t: &str) -> usize {
        1 << 20
    }

    fn handle(&self, _req: Request) -> Response {
        Response::text(500, "text/plain", "unused")
    }

    fn reply(&self, req: Request) -> Reply {
        // only what came through the gateway counts: on a shared host other programs may ask a
        // freshly opened port for `/`, and they are not the gateway
        if req.header("Via") != Some(xbt_gateway::upstream::VIA) {
            return Reply::Whole(Response::text(404, "text/plain", "not the gateway"));
        }
        self.hits.fetch_add(1, Ordering::SeqCst);
        self.seen.lock().unwrap().push(req.clone());
        let path = req.path().to_string();
        let sized = |p: &str| path.strip_prefix(p).and_then(|n| n.parse::<usize>().ok());
        let body = |n: usize, pause: Duration| -> xbt_svc::http::Body {
            Box::new(move |out| {
                let mut sent = 0;
                while sent < n {
                    let k = (n - sent).min(8192);
                    let chunk: Vec<u8> = (sent..sent + k).map(pattern).collect();
                    out.send(&chunk)?;
                    sent += k;
                    if !pause.is_zero() {
                        std::thread::sleep(pause);
                    }
                }
                Ok(())
            })
        };
        if let Some(n) = sized("/files/")
            .or_else(|| sized("/files/free/"))
            .or_else(|| sized("/verify/"))
            .or_else(|| sized("/whole/"))
        {
            return Reply::Stream(Streamed {
                status: 200,
                headers: vec![
                    ("Content-Type".into(), "application/octet-stream".into()),
                    ("ETag".into(), "\"e\"".into()),
                ],
                length: Some(n as u64),
                body: body(n, Duration::ZERO),
            });
        }
        if let Some(n) = sized("/chunked/") {
            return Reply::Stream(Streamed {
                status: 200,
                headers: vec![],
                length: None,
                body: body(n, Duration::ZERO),
            });
        }
        if let Some(n) = sized("/timed/") {
            // n bytes, 8 KiB every 100 ms
            return Reply::Stream(Streamed {
                status: 200,
                headers: vec![],
                length: None,
                body: body(n, Duration::from_millis(100)),
            });
        }
        if let Some(code) = sized("/status/") {
            return Reply::Whole(Response::text(
                code as u16,
                "text/plain",
                "x".repeat(100_000),
            ));
        }
        Reply::Whole(match path.as_str() {
            "/api" => Response::text(200, "application/json", json!({"method": req.method, "target": req.target, "body": String::from_utf8_lossy(&req.body)}).to_string()),
            "/hang" => {
                std::thread::sleep(Duration::from_secs(4));
                Response::text(200, "text/plain", "late")
            }
            "/cut" => return Reply::Stream(Streamed { status: 200, headers: vec![], length: Some(1000), body: Box::new(|out| out.send(&[1u8; 400])) }),
            "/money" => Response::new(
                200,
                vec![("PAYMENT-RESPONSE".into(), "forged".into()), ("Payment-Required".into(), "forged".into()), ("Ticket-Units".into(), "999999".into()), ("X-Kept".into(), "yes".into())],
                b"ok".to_vec(),
            ),
            "/pay" => Response::text(402, "text/plain", "pay me instead"),
            "/moved" => Response::new(302, vec![("Location".into(), "/api".into())], vec![]),
            _ => Response::text(404, "text/plain", "no such thing"),
        })
    }
}

pub fn start_service() -> (Running, Arc<Service>) {
    let s = Arc::new(Service::default());
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let run = serve_with(
        s.clone(),
        l,
        16,
        Limits {
            per_address: 0,
            connections: 256,
            ..Limits::default()
        },
    )
    .unwrap();
    (run, s)
}

// --- the gateway --------------------------------------------------------------------------------------

pub struct Rig {
    pub gw: Arc<Gateway>,
    pub running: Running,
    pub node: Arc<StandIn>,
    pub service: Arc<Service>,
    pub service_running: Running,
    pub clock: Arc<AtomicU64>,
    pub addr: String,
    pub origin: String,
    pub cfg: Value,
}

pub fn routes() -> Value {
    json!([
        {"path": "/files/", "price": {"byte_msat": 1000, "per_bytes": 1048576}},
        {"path": "/chunked/", "price": {"byte_msat": 1000, "per_bytes": 1048576}},
        {"path": "/files/free/", "free": true},
        {"path": "/whole/", "price": {"request_msat": 2500}},
        {"path": "/api", "methods": ["GET", "POST"], "price": {"request_msat": 2500}, "max_body": 4096, "forward_headers": ["X-Trace"]},
        {"path": "/status/", "price": {"request_msat": 2500}},
        {"path": "/hang", "price": {"request_msat": 2500}},
        {"path": "/cut", "price": {"request_msat": 2500}},
        {"path": "/money", "price": {"request_msat": 2500}},
        {"path": "/pay", "price": {"request_msat": 2500}},
        {"path": "/moved", "price": {"request_msat": 2500}},
        {"path": "/timed/", "price": {"second_msat": 100000}},
        {"path": "/verify/", "price": {"request_msat": 400000}, "release": "after-verify"}
    ])
}

/// A config for tests: `edit` changes it before it is read.
pub fn config(state: &Path, upstream: &str, edit: &dyn Fn(&mut Value)) -> Value {
    let mut v = json!({"listen": "127.0.0.1:0", "public_url": "http://gateway.test:8402", "upstream": upstream, "state_dir": state,
        "chain": "regtest", "network": NET,
        "node": {"rest": "http://127.0.0.1:1", "macaroon": "unused", "info_macaroon": "unused"},
        "caps": {"sessions_per_address": 0},
        "times": {"refill_wait_ms": 300, "upstream_wait_secs": 2, "tick_ms": 50},
        "routes": routes()});
    edit(&mut v);
    v
}

pub fn receipt_secret() -> secp256k1::SecretKey {
    secp256k1::SecretKey::from_slice(&[9u8; 32]).unwrap()
}

/// Start a gateway on `state` with an existing node and service (a restart keeps both).
pub fn start_on(
    state: &Path,
    node: Arc<StandIn>,
    service: (Running, Arc<Service>),
    clock: Arc<AtomicU64>,
    edit: &dyn Fn(&mut Value),
) -> Rig {
    let cfg = config(state, &format!("http://{}", service.0.addr), edit);
    let parsed = Config::from_json(&cfg).unwrap();
    let c = clock.clone();
    let gw = Gateway::start(
        parsed,
        node.clone(),
        receipt_secret(),
        Box::new(move || c.load(Ordering::SeqCst)),
    )
    .unwrap();
    let running = gw.serve(TcpListener::bind("127.0.0.1:0").unwrap()).unwrap();
    let addr = running.addr.to_string();
    Rig {
        gw,
        running,
        node,
        service: service.1,
        service_running: service.0,
        clock,
        addr,
        origin: "http://gateway.test:8402".into(),
        cfg,
    }
}

pub fn start(edit: &dyn Fn(&mut Value)) -> (Rig, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let rig = start_on(
        dir.path(),
        Arc::new(StandIn::new(100)),
        start_service(),
        Arc::new(AtomicU64::new(1_000_000)),
        edit,
    );
    (rig, dir)
}

impl Rig {
    /// Stop the gateway (not the node, not the service): what a restart leaves behind.
    pub fn stop(self) -> (Arc<StandIn>, (Running, Arc<Service>), Arc<AtomicU64>) {
        self.gw.stop();
        self.running.stopper().stop();
        for t in self.running.threads {
            let _ = t.join();
        }
        // a watcher waits on the node's stream: breaking the streams lets it see the flag
        self.node.set_down(true);
        std::thread::sleep(Duration::from_millis(150));
        self.node.set_down(false);
        (self.node, (self.service_running, self.service), self.clock)
    }

    pub fn hits(&self) -> usize {
        self.service.hits.load(Ordering::SeqCst)
    }

    pub fn advance(&self, secs: u64) {
        self.clock.fetch_add(secs, Ordering::SeqCst);
    }

    /// A new tip on the node, seen by the gateway.
    pub fn height(&self, h: u32) {
        self.node.set_height(h);
        self.gw.tick();
    }
}

// --- HTTP as a buyer sends it -----------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Got {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The body arrived whole (its Content-Length, or its last chunk).
    pub complete: bool,
}

impl Got {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|_| panic!("not JSON: {:?}", String::from_utf8_lossy(&self.body)))
    }

    pub fn error(&self) -> String {
        self.json()["error"].as_str().unwrap_or("").to_string()
    }

    /// The signed receipt of PAYMENT-RESPONSE, its signature checked against `key`.
    pub fn receipt(&self, key: &str) -> Value {
        let sr = unb64json(
            self.header("PAYMENT-RESPONSE")
                .expect("no PAYMENT-RESPONSE"),
        )
        .unwrap();
        let r = sr["extra"]["receipt"].clone();
        check_receipt(&r, key);
        r
    }
}

pub fn check_receipt(r: &Value, key: &str) {
    let sig = hex::decode(r["sig"].as_str().unwrap()).unwrap();
    assert!(
        ecdsa::verify(
            &hex::decode(key).unwrap(),
            &ticket::receipt_message(r),
            &sig
        ),
        "bad receipt signature: {r}"
    );
}

/// One request on its own connection. `stop_after`: read this many body bytes, then hang up.
pub fn http(
    addr: &str,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    stop_after: Option<usize>,
) -> Got {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut head = format!("{method} {target} HTTP/1.1\r\nHost: gateway.test:8402\r\n");
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() || method == "POST" {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut raw = Vec::new();
    let mut buf = [0u8; 16384];
    let split = loop {
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        match s.read(&mut buf) {
            Ok(0) | Err(_) => panic!("no response head: {:?}", String::from_utf8_lossy(&raw)),
            Ok(n) => raw.extend_from_slice(&buf[..n]),
        }
    };
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let mut rest = raw[split + 4..].to_vec();
    let length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok());
    let chunked = headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"));
    let limit = stop_after.unwrap_or(usize::MAX);
    loop {
        if rest.len() >= limit || length.is_some_and(|n| rest.len() >= n) {
            break;
        }
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => rest.extend_from_slice(&buf[..n]),
        }
    }
    drop(s);
    let (body, complete) = if chunked {
        dechunk(&rest)
    } else {
        let whole = length.is_none_or(|n| rest.len() >= n);
        (rest, whole)
    };
    Got {
        status,
        headers,
        body,
        complete: complete && method != "HEAD" || method == "HEAD",
    }
}

/// The bytes of a chunked body, and whether its last chunk arrived.
fn dechunk(raw: &[u8]) -> (Vec<u8>, bool) {
    let (mut out, mut i) = (vec![], 0);
    loop {
        let Some(nl) = raw[i..].windows(2).position(|w| w == b"\r\n") else {
            return (out, false);
        };
        let Ok(n) = usize::from_str_radix(std::str::from_utf8(&raw[i..i + nl]).unwrap_or("x"), 16)
        else {
            return (out, false);
        };
        i += nl + 2;
        if n == 0 {
            return (out, true);
        }
        let end = (i + n).min(raw.len());
        out.extend_from_slice(&raw[i..end]);
        if end < i + n {
            return (out, false);
        }
        i = end + 2;
    }
}

// --- a buyer ------------------------------------------------------------------------------------------

pub struct Buyer {
    pub addr: String,
    pub origin: String,
    pub session: String,
    pub key: [u8; 32],
    pub seq: u64,
    pub receipt_key: String,
    pub next_secret: u64,
    pub tag: u8,
}

pub fn secret_of(tag: u8, n: u64) -> [u8; 32] {
    let mut s = [tag; 32];
    s[..8].copy_from_slice(&n.to_be_bytes());
    s
}

impl Buyer {
    pub fn new(rig: &Rig, tag: u8) -> Self {
        Self {
            addr: rig.addr.clone(),
            origin: rig.origin.clone(),
            session: String::new(),
            key: [0; 32],
            seq: 0,
            receipt_key: rig.gw.terms().receipt_key.clone(),
            next_secret: 0,
            tag,
        }
    }

    pub fn fresh_secrets(&mut self, n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|_| {
                self.next_secret += 1;
                secret_of(self.tag, self.next_secret)
            })
            .collect()
    }

    /// PAYMENT-SIGNATURE for a request, using up one `seq`.
    pub fn sign(
        &mut self,
        method: &str,
        target: &str,
        body: &[u8],
        secret: Option<&[u8; 32]>,
        pledge: Option<&Hash>,
    ) -> String {
        let h = self.sign_at(self.seq, method, target, body, secret, pledge);
        self.seq += 1;
        h
    }

    pub fn sign_at(
        &self,
        seq: u64,
        method: &str,
        target: &str,
        body: &[u8],
        secret: Option<&[u8; 32]>,
        pledge: Option<&Hash>,
    ) -> String {
        let digest = request_digest_v2(method, &format!("{}{target}", self.origin), body);
        let (s, t) = (
            secret.map(hex::encode).unwrap_or_default(),
            pledge.map(hex::encode).unwrap_or_default(),
        );
        let auth = ticket::request_auth(&self.key, &self.session, seq, &s, &t, &digest);
        let mut payload = json!({"session": self.session, "seq": seq, "auth": auth});
        if secret.is_some() {
            payload["secret"] = s.into();
        }
        if pledge.is_some() {
            payload["ticket"] = t.into();
        }
        b64json(
            &json!({"x402Version": 2, "accepted": {"scheme": "ticket", "network": NET}, "payload": payload}),
        )
    }

    /// Ask for tickets for `secrets`; the invoices' hashes that were issued.
    pub fn lock_raw(&mut self, secrets: &[[u8; 32]]) -> Got {
        let hashes: Vec<String> = secrets
            .iter()
            .map(|s| hex::encode(ticket::ticket_hash(s)))
            .collect();
        let (body, headers) = if self.session.is_empty() {
            (
                json!({"version": "ticket/0", "hashes": hashes}).to_string(),
                vec![],
            )
        } else {
            let body = json!({"version": "ticket/0", "session": self.session, "hashes": hashes})
                .to_string();
            let sig = self.sign("POST", "/x402/ticket/lock", body.as_bytes(), None, None);
            (body, vec![("PAYMENT-SIGNATURE".to_string(), sig)])
        };
        let hs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let got = http(
            &self.addr,
            "POST",
            "/x402/ticket/lock",
            &hs,
            body.as_bytes(),
            None,
        );
        if !hs.is_empty() {
            self.used(&got);
        }
        if got.status == 200 && self.session.is_empty() && got.json()["session"].is_string() {
            let j = got.json();
            self.session = j["session"].as_str().unwrap().to_string();
            self.key = ticket::hex32(j["key"].as_str().unwrap()).unwrap();
        }
        got
    }

    /// Lock `n` tickets and pay them on the node; their secrets, once the gateway has seen them held.
    pub fn lock(&mut self, rig: &Rig, n: usize) -> Vec<[u8; 32]> {
        let secrets = self.fresh_secrets(n);
        let got = self.lock_raw(&secrets);
        assert_eq!(got.status, 200, "{}", String::from_utf8_lossy(&got.body));
        assert_eq!(
            got.json()["tickets"].as_array().unwrap().len(),
            n,
            "{}",
            got.json()
        );
        for s in &secrets {
            assert!(rig.node.pay(&ticket::ticket_hash(s)));
        }
        self.wait_state(&secrets, "ACCEPTED");
        secrets
    }

    /// Wait until the gateway shows every one of `secrets` in `state`.
    pub fn wait_state(&mut self, secrets: &[[u8; 32]], state: &str) {
        let want: Vec<String> = secrets
            .iter()
            .map(|s| hex::encode(ticket::ticket_hash(s)))
            .collect();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let st = self.status();
            let tickets = st["tickets"].as_array().unwrap().clone();
            if want.iter().all(|h| {
                tickets
                    .iter()
                    .any(|t| t["hash"] == h.as_str() && t["state"] == state)
            }) {
                return;
            }
            assert!(Instant::now() < deadline, "tickets never {state}: {st}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn call(&mut self, what: &str, body: &Value) -> Got {
        let target = format!("/x402/ticket/{what}");
        let body = body.to_string();
        let sig = self.sign("POST", &target, body.as_bytes(), None, None);
        let got = http(
            &self.addr,
            "POST",
            &target,
            &[("PAYMENT-SIGNATURE", &sig)],
            body.as_bytes(),
            None,
        );
        self.used(&got);
        got
    }

    /// A `seq` is used up by a request that was authenticated, and only then does its answer
    /// carry a receipt: an answer without one leaves the `seq` for the next request.
    pub fn used(&mut self, got: &Got) {
        if got.header("PAYMENT-RESPONSE").is_none() {
            self.seq -= 1;
        }
    }

    pub fn status(&mut self) -> Value {
        let got = self.call("status", &json!({}));
        assert_eq!(got.status, 200, "{}", String::from_utf8_lossy(&got.body));
        got.receipt(&self.receipt_key);
        got.json()
    }

    pub fn release(&mut self, secrets: &[[u8; 32]]) -> Got {
        self.call(
            "release",
            &json!({"secrets": secrets.iter().map(hex::encode).collect::<Vec<_>>()}),
        )
    }

    pub fn get(&mut self, target: &str, secret: Option<&[u8; 32]>) -> Got {
        let sig = self.sign("GET", target, b"", secret, None);
        let got = http(
            &self.addr,
            "GET",
            target,
            &[("PAYMENT-SIGNATURE", &sig)],
            b"",
            None,
        );
        self.used(&got);
        got
    }

    pub fn balance(&mut self) -> u64 {
        self.status()["session"]["balanceMsat"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap()
    }
}

pub fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub fn count(node: &StandIn, state: InvoiceState) -> usize {
    node.count(state)
}
