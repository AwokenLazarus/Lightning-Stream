//! The paid relay's credit API (`docs/PAID-RELAYS.md`): a small HTTP service that only the
//! operator's own gateway reaches. The relay is sold like any Stream service: a priced route on
//! the operator's gateway (paid with Stream tickets, inside the paying shop's spending rules) whose
//! upstream is this API, so the relay itself never touches Lightning.
//!
//! | Request | |
//! | --- | --- |
//! | `POST /credit` `{"key": "<link key, 64 hex>"}` with `x-relay-credit-token` | one credit for that key (the gateway calls it once per paid request); answers the account |
//! | `GET /balance?key=&ts=&sig=` | the account of `key`, for the app that holds it: `sig` is the key's ed25519 signature of [`balance_message`] |
//! | `GET /balance?key=&ts=&sig=&home=1` | the same, and this relay is the key's home for the next [`crate::paid::HOME_TTL_S`]: `sig` signs [`home_message`] |
//! | `GET /terms` | the price and the rest of the terms |
//!
//! Crediting a key is a gift to it, so a credit needs no proof that the payer holds the key; only
//! the gateway may credit (the token), since only it was paid. A gift declares nothing: a key is
//! charged only after its holder has said this relay is its home, with its own signature, so nobody
//! pays a relay it didn't choose. A balance tells how much an app receives, so only the key's
//! holder may read it.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use crate::paid::{key_from_hex, Paid};

/// The header the operator's gateway sends the token in (its route's `upstream_headers`).
pub const TOKEN_HEADER: &str = "x-relay-credit-token";
/// Signed balance queries: what the key signs.
pub const BALANCE_DOMAIN: &str = "xbt-stream-relay/balance/v1";
/// Signed home declarations: what the key signs.
pub const HOME_DOMAIN: &str = "xbt-stream-relay/home/v1";
/// How far a balance query's time may be from the relay's.
pub const BALANCE_SKEW_S: u64 = 300;
const MAX_HEAD: usize = 8 * 1024;
const MAX_BODY: usize = 4 * 1024;
const IO_WAIT: Duration = Duration::from_secs(10);

/// What a shop's link key signs to read its balance at `ts` (Unix seconds).
pub fn balance_message(key_hex: &str, ts: u64) -> String {
    format!("{BALANCE_DOMAIN}|{}|{ts}", key_hex.to_ascii_lowercase())
}

/// What a link key signs to declare this relay its home at `ts`, and read its balance.
pub fn home_message(key_hex: &str, ts: u64) -> String {
    format!("{HOME_DOMAIN}|{}|{ts}", key_hex.to_ascii_lowercase())
}

/// Check a balance query: the key's signature of [`balance_message`] (or of [`home_message`] when
/// `home`), within [`BALANCE_SKEW_S`].
pub fn check_balance_query(key_hex: &str, ts: u64, sig_hex: &str, now: u64) -> Result<[u8; 32], String> {
    check_signed(key_hex, ts, sig_hex, now, false)
}

fn check_signed(key_hex: &str, ts: u64, sig_hex: &str, now: u64, home: bool) -> Result<[u8; 32], String> {
    let key = key_from_hex(key_hex).ok_or("key is 64 hex characters")?;
    if ts.abs_diff(now) > BALANCE_SKEW_S {
        return Err("ts is too far from the relay's clock".into());
    }
    let sig: [u8; 64] = hex::decode(sig_hex.trim()).ok().and_then(|b| b.try_into().ok()).ok_or("sig is 128 hex characters")?;
    let pk = iroh_base::PublicKey::from_bytes(&key).map_err(|_| "key is not a link key")?;
    let msg = if home { home_message(key_hex, ts) } else { balance_message(key_hex, ts) };
    pk.verify(msg.as_bytes(), &iroh_base::Signature::from_bytes(&sig)).map_err(|_| "the signature does not hold")?;
    Ok(key)
}

/// A parsed request: method, path, query, lower-case headers, body.
struct Req {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Req {
    fn header(&self, k: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }
    fn q(&self, k: &str) -> Option<&str> {
        self.query.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }
}

fn read_req(c: &TcpStream) -> Result<Req, String> {
    let mut r = BufReader::new(c.take((MAX_HEAD + MAX_BODY) as u64));
    let mut first = String::new();
    r.read_line(&mut first).map_err(|e| e.to_string())?;
    let mut it = first.split_whitespace();
    let (method, target) = (it.next().ok_or("empty request")?.to_string(), it.next().ok_or("no target")?.to_string());
    let mut headers = Vec::new();
    let mut seen = first.len();
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            return Err("closed in the head".into());
        }
        seen += line.len();
        if seen > MAX_HEAD {
            return Err("head too large".into());
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let len: usize = headers.iter().find(|(k, _)| k == "content-length").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
    if len > MAX_BODY {
        return Err("body too large".into());
    }
    let mut body = vec![0; len];
    r.read_exact(&mut body).map_err(|e| e.to_string())?;
    let (path, qs) = target.split_once('?').unwrap_or((&target, ""));
    let query = qs.split('&').filter_map(|p| p.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect();
    Ok(Req { method, path: path.to_string(), query, headers, body })
}

/// Constant-time comparison of the token.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Answer one request.
fn handle(meter: &Paid, req: &Req, now: u64) -> (u16, Value) {
    let s = meter.settings();
    if !s.enabled {
        return (503, json!({"error": "not_paid", "message": "This relay is free: nothing to pay."}));
    }
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/terms") => (200, s.terms()),
        ("POST", "/credit") => {
            if s.credit_token.len() < crate::paid::MIN_TOKEN || !req.header(TOKEN_HEADER).is_some_and(|t| same(t, &s.credit_token)) {
                return (403, json!({"error": "bad_token"}));
            }
            let key = serde_json::from_slice::<Value>(&req.body).ok().and_then(|v| v.get("key").and_then(Value::as_str).and_then(key_from_hex));
            match key {
                Some(k) => (200, meter.credit(&k)),
                None => (400, json!({"error": "bad_key", "message": "The body is {\"key\": \"<the link key, 64 hex>\"}."})),
            }
        }
        ("GET", "/balance") => {
            let (key, ts, sig) = (req.q("key").unwrap_or(""), req.q("ts").and_then(|t| t.parse().ok()).unwrap_or(0), req.q("sig").unwrap_or(""));
            let home = req.q("home") == Some("1");
            match check_signed(key, ts, sig, now, home) {
                Ok(k) => {
                    if home {
                        meter.declare_home(&k);
                    }
                    (200, meter.account(&k).unwrap_or_else(|| json!({"key": hex::encode(k), "balance_bytes": 0, "home": false, "carrying": false})))
                }
                Err(e) => (403, json!({"error": "bad_query", "message": e})),
            }
        }
        _ => (404, json!({"error": "not_found"})),
    }
}

fn serve_one(meter: &Paid, mut c: TcpStream) {
    let _ = c.set_read_timeout(Some(IO_WAIT));
    let _ = c.set_write_timeout(Some(IO_WAIT));
    let (code, body) = match read_req(&c) {
        Ok(req) => handle(meter, &req, crate::status::now()),
        Err(e) => (400, json!({"error": "bad_request", "message": e})),
    };
    let body = body.to_string();
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Service Unavailable",
    };
    let _ = write!(c, "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
}

/// Serve the credit API on `listen` until the process ends: a thread per request. The address
/// the listener got is returned.
pub fn spawn(meter: Arc<Paid>, listen: SocketAddr) -> std::io::Result<SocketAddr> {
    let l = TcpListener::bind(listen)?;
    let addr = l.local_addr()?;
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            let m = meter.clone();
            std::thread::spawn(move || serve_one(&m, c));
        }
    });
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paid::PaidSettings;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn paid() -> Paid {
        Paid::new(PaidSettings { enabled: true, msat_per_gb: 2_000, credit_token: TOKEN.into(), ..PaidSettings::default() })
    }

    fn req(method: &str, path: &str, query: &[(&str, &str)], headers: &[(&str, &str)], body: &str) -> Req {
        Req { method: method.into(), path: path.into(), query: query.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(),
              headers: headers.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(), body: body.as_bytes().to_vec() }
    }

    fn signed(secret: [u8; 32], ts: u64) -> (String, String) {
        let sk = iroh_base::SecretKey::from_bytes(&secret);
        let key = hex::encode(sk.public().as_bytes());
        let sig = hex::encode(sk.sign(balance_message(&key, ts).as_bytes()).to_bytes());
        (key, sig)
    }

    fn signed_home(secret: [u8; 32], ts: u64) -> (String, String) {
        let sk = iroh_base::SecretKey::from_bytes(&secret);
        let key = hex::encode(sk.public().as_bytes());
        let sig = hex::encode(sk.sign(home_message(&key, ts).as_bytes()).to_bytes());
        (key, sig)
    }

    #[test]
    fn only_the_keys_holder_declares_a_home() {
        let m = paid();
        let now = crate::status::now();
        let ts = now.to_string();
        let (key, home_sig) = signed_home([9; 32], now);
        let (_, read_sig) = signed([9; 32], now);
        let q = |sig: &str, home: &str| req("GET", "/balance", &[("key", &key), ("ts", &ts), ("sig", sig), ("home", home)], &[], "");
        // a read's signature does not declare a home, nor the other way round
        assert_eq!(handle(&m, &q(&read_sig, "1"), now).0, 403);
        assert_eq!(handle(&m, &q(&home_sig, "0"), now).0, 403);
        let (code, v) = handle(&m, &q(&read_sig, "0"), now);
        assert_eq!((code, &v["home"]), (200, &json!(false)));
        let (code, v) = handle(&m, &q(&home_sig, "1"), now);
        assert_eq!((code, &v["home"]), (200, &json!(true)), "{v}");
    }

    #[test]
    fn credit_needs_the_token_and_a_key() {
        let m = paid();
        let key = hex::encode([7u8; 32]);
        let body = format!("{{\"key\": \"{key}\"}}");
        assert_eq!(handle(&m, &req("POST", "/credit", &[], &[], &body), 0).0, 403);
        assert_eq!(handle(&m, &req("POST", "/credit", &[], &[(TOKEN_HEADER, "x")], &body), 0).0, 403);
        assert_eq!(handle(&m, &req("POST", "/credit", &[], &[(TOKEN_HEADER, TOKEN)], "{}"), 0).0, 400);
        let (code, v) = handle(&m, &req("POST", "/credit", &[], &[(TOKEN_HEADER, TOKEN)], &body), 0);
        assert_eq!((code, v["balance_bytes"].as_i64(), v["credited_msat"].as_u64()), (200, Some(10_000_000_000), Some(20_000)));
        assert_eq!(v["home"], false, "a credit declares no home");
    }

    #[test]
    fn a_balance_is_read_only_by_the_keys_holder() {
        let m = paid();
        let now = 1_700_000_000;
        let (key, sig) = signed([9; 32], now);
        let ts = now.to_string();
        let (code, v) = handle(&m, &req("GET", "/balance", &[("key", &key), ("ts", &ts), ("sig", &sig)], &[], ""), now);
        assert_eq!((code, v["balance_bytes"].as_i64()), (200, Some(0)));
        // another key's signature, an old one, or none: refused
        let (_, other) = signed([8; 32], now);
        assert_eq!(handle(&m, &req("GET", "/balance", &[("key", &key), ("ts", &ts), ("sig", &other)], &[], ""), now).0, 403);
        assert_eq!(handle(&m, &req("GET", "/balance", &[("key", &key), ("ts", &ts), ("sig", &sig)], &[], ""), now + 301).0, 403);
        assert_eq!(handle(&m, &req("GET", "/balance", &[("key", &key)], &[], ""), now).0, 403);
    }

    #[test]
    fn terms_and_a_free_relay() {
        let m = paid();
        let (code, v) = handle(&m, &req("GET", "/terms", &[], &[], ""), 0);
        assert_eq!((code, v["msat_per_gb"].as_u64(), v.get("credit_token")), (200, Some(2_000), None));
        assert_eq!((v["credit_bytes"].as_u64(), v["credit_msat"].as_u64()), (Some(10_000_000_000), Some(20_000)));
        m.set_settings(PaidSettings::default());
        assert_eq!(handle(&m, &req("GET", "/terms", &[], &[], ""), 0).0, 503);
    }

    #[test]
    fn serves_over_http() {
        let m = Arc::new(paid());
        let addr = spawn(m, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut c = TcpStream::connect(addr).unwrap();
        write!(c, "GET /terms HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut out = String::new();
        c.read_to_string(&mut out).unwrap();
        assert!(out.starts_with("HTTP/1.1 200") && out.contains("\"msat_per_gb\":2000"), "{out}");
    }
}
