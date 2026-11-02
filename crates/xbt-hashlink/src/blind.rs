//! The renter's check that its own gateway hides which shares win.
//!
//! A hashmaker sees every share's raw hash. If a job's block hash is that raw hash, it can tell a winner and
//! drop it. So a job must commit to an `xor_key`, whose mask blinds the block hash from the share's own bits
//! down: `clear_bits` must equal those bits exactly. One job without it is enough to lose a block.
//!
//! Stratum can't show any of that: the commitment is inside `h2`, in `coinb1`. So the gateway opens each job on
//! its local API (`GET /xbt/job`), without the key, and this recomputes `h2` from what it says and holds it to
//! the bytes the miner is about to be given.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::Duration;

const HTTP_WAIT: Duration = Duration::from_secs(2);
/// A job's coinbases may still be being written when its notify is read.
const NOT_READY_TRIES: u32 = 5;
const NOT_READY_WAIT: Duration = Duration::from_millis(200);
const KEYS_KEPT: usize = 4096;
const PROBE_WAIT: Duration = Duration::from_secs(10);
/// The modes whose key this app can check: the renter's own gateway holds it, fresh for each template.
pub const KNOWN_MODES: [&str; 2] = ["solo", "pool-key"];
/// How a job in any other mode is refused (and told apart from a gateway that doesn't answer).
const UNSUPPORTED: &str = "not supported yet";

pub(crate) fn tagged(tag: &str, msg: &[u8]) -> [u8; 32] {
    let t: [u8; 32] = Sha256::digest(tag.as_bytes()).into();
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h.update(msg);
    h.finalize().into()
}

/// The power of two a gateway rounds a share's difficulty to, as it does: difficulty 1 is sent as
/// 65535/65536 of itself, so a plain floor of the log would be one low.
pub fn pot_of(d: f64) -> u32 {
    let pdiff = (d * 65536.0 / 65535.0).round();
    if pdiff < 1.0 {
        0
    } else {
        pdiff.log2().floor() as u32
    }
}

/// The checks on one rental's gateway.
pub struct Check {
    api: String,
    /// Key hash → the previous block it was used on: a key is for one template, never reused on the next.
    keys: Mutex<HashMap<[u8; 32], [u8; 32]>>,
}

fn hex32(v: &Value, what: &str) -> Result<[u8; 32], String> {
    let s = v.get(what).and_then(Value::as_str).ok_or_else(|| format!("the gateway's answer has no {what}"))?;
    hex::decode(s).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| format!("the gateway's {what} is not 32 bytes"))
}

fn num(v: &Value, what: &str) -> Result<u64, String> {
    v.get(what).and_then(Value::as_u64).ok_or_else(|| format!("the gateway's answer has no {what}"))
}

/// `h2` from the fields a gateway says it committed to, as the node computes it.
pub(crate) fn h2_of(a: &Value, prev: &[u8; 32], clear_bits: u8) -> Result<[u8; 32], String> {
    let mut p = Vec::with_capacity(119);
    p.extend_from_slice(&(num(a, "version")? as u32).to_le_bytes());
    p.extend_from_slice(prev);
    p.extend_from_slice(&(num(a, "height")? as u32).to_le_bytes());
    p.extend_from_slice(&hex32(a, "merkle_root")?);
    p.extend_from_slice(&(num(a, "time_on_wire")? as u32).to_le_bytes());
    p.push(0);
    p.extend_from_slice(&(num(a, "nbits")? as u32).to_le_bytes());
    p.extend_from_slice(&(num(a, "txcount")? as u32).to_le_bytes());
    p.push(num(a, "flags")? as u8);
    p.push(clear_bits);
    p.extend_from_slice(&hex32(a, "xor_key_hash")?);
    let h1 = tagged("Bitcoin block header 1", &p);
    let mut q = Vec::with_capacity(96);
    q.extend_from_slice(&h1);
    q.extend_from_slice(&[0u8; 32]);
    q.extend_from_slice(&hex32(a, "rhs")?);
    Ok(tagged("Merge-mining hook", &q))
}

impl Check {
    pub fn new(api: String) -> Check {
        Check { api, keys: Mutex::new(HashMap::new()) }
    }

    /// Is this job blinded, at the difficulty it'll be mined at? The gateway's word for whose key it is, or
    /// why it can't be shown to be blinded. Nothing is decided by that word or by which pool it is: only by
    /// what's committed, so a pool that adds a key passes with no change here.
    pub fn job(&self, notify: &Value, d: f64) -> Result<String, String> {
        self.job_seen(notify, d).map(|j| j.mode)
    }

    /// As [`Check::job`], with the key hash and previous block the job commits to: what a renter records to show no
    /// key outlives the block it was revealed in.
    pub fn job_seen(&self, notify: &Value, d: f64) -> Result<JobSeen, String> {
        let p = notify.get("params").and_then(Value::as_array).ok_or("a notify with no params")?;
        let id = p.first().and_then(Value::as_str).ok_or("a notify with no job id")?;
        let coinb1 = p.get(2).and_then(Value::as_str).and_then(|s| hex::decode(s).ok()).ok_or("a notify with no coinb1")?;
        let hidden = p.get(1).and_then(Value::as_str).and_then(|s| hex::decode(s).ok()).ok_or("a notify with no prevhash")?;
        let pot = pot_of(d);
        let a = self.ask(id, pot)?;
        verify(&a, &coinb1, &hidden, pot)?;
        let mode = a.get("mode").and_then(Value::as_str).unwrap_or("").to_string();
        // Mike's rule: what can't be checked is refused. Only a key the renter's own gateway holds can be checked to
        // change with every template: "solo" and "pool-key". A key the pool holds ("abw") may outlast a block it
        // found, and nothing here can see whether it does; any other word is a mode this app doesn't know
        if !KNOWN_MODES.contains(&mode.as_str()) {
            return Err(if mode == "abw" {
                format!("{UNSUPPORTED}: its pool holds the key (ABW), and this app can't check that the pool changes it after a block")
            } else {
                format!("{UNSUPPORTED}: the gateway names a mode this app doesn't know ({mode:?})")
            });
        }
        // one key for one template: a key seen on another previous block could be one a found block has shown
        let (key, prev) = (hex32(&a, "xor_key_hash")?, hex32(&a, "prevblock")?);
        let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        if keys.get(&key).is_some_and(|was| *was != prev) {
            return Err("the gateway used one key on two templates".into());
        }
        if keys.len() >= KEYS_KEPT {
            keys.clear();
        }
        keys.insert(key, prev);
        drop(keys);
        Ok(JobSeen { mode, key_hash: hex::encode(hex32(&a, "xor_key_hash")?), prevblock: hex::encode(hex32(&a, "prevblock")?) })
    }

    fn ask(&self, id: &str, pot: u32) -> Result<Value, String> {
        let esc: String = id.bytes().map(|b| if b.is_ascii_alphanumeric() { (b as char).to_string() } else { format!("%{b:02X}") }).collect();
        for _ in 0..NOT_READY_TRIES {
            let (code, body) = self.get(&format!("/xbt/job?id={esc}&pot={pot}"))?;
            match code {
                200 => return serde_json::from_slice(&body).map_err(|_| "the gateway's answer is not JSON".to_string()),
                404 => std::thread::sleep(NOT_READY_WAIT),
                c => return Err(format!("the gateway's API said {c}")),
            }
        }
        Err("the gateway doesn't know this job".into())
    }

    fn get(&self, path: &str) -> Result<(u16, Vec<u8>), String> {
        let addr = self.api.to_socket_addrs().ok().and_then(|mut a| a.next()).ok_or_else(|| format!("no such address: {}", self.api))?;
        let mut s = TcpStream::connect_timeout(&addr, HTTP_WAIT).map_err(|e| format!("the gateway's API at {}: {e}", self.api))?;
        let _ = s.set_read_timeout(Some(HTTP_WAIT));
        let _ = s.set_write_timeout(Some(HTTP_WAIT));
        let ask = format!("GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", self.api);
        s.write_all(ask.as_bytes()).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        s.read_to_end(&mut out).map_err(|e| format!("the gateway's API: {e}"))?;
        let at = out.windows(4).position(|w| w == b"\r\n\r\n").ok_or("the gateway's API sent no HTTP answer")?;
        let code = std::str::from_utf8(&out[..at]).ok().and_then(|h| h.split_whitespace().nth(1)).and_then(|c| c.parse().ok()).ok_or("the gateway's API sent no status")?;
        Ok((code, out[at + 4..].to_vec()))
    }
}

/// A job shown blinded: whose key, which key, on which previous block.
#[derive(Clone, Debug, PartialEq)]
pub struct JobSeen {
    pub mode: String,
    pub key_hash: String,
    pub prevblock: String,
}

/// What an upstream's jobs show, in plain words for the renter's page.
#[derive(Clone, Debug, PartialEq)]
pub enum Shown {
    /// A job was opened and its commitment checks out. The gateway's word for whose key it is.
    Blinded(String),
    /// A job was opened and it isn't blinded, or doesn't match what was opened.
    NotBlinded(String),
    /// No job could be opened: no way to tell.
    Unverifiable(String),
}

impl Shown {
    pub fn to_json(&self) -> Value {
        let (state, why) = match self {
            Shown::Blinded(mode) => ("blinded", mode.as_str()),
            Shown::NotBlinded(why) => ("not blinded", why.as_str()),
            Shown::Unverifiable(why) => ("can't be checked", why.as_str()),
        };
        json!({"state": state, "why": why, "words": self.words()})
    }

    pub fn words(&self) -> String {
        match self {
            Shown::Blinded(mode) => {
                let whose = match mode.as_str() {
                    "solo" => "Your gateway holds the key, on a block of your own.",
                    "pool-key" => "Your gateway holds the key, and your pool takes it when a block is found.",
                    _ => "",
                };
                format!("Blinded: a hashmaker can't tell which shares win, so it can't drop those. {whose}").trim_end().to_string()
            }
            Shown::NotBlinded(why) => format!("Not blinded: {why}. A hashmaker could see which shares win and drop those, so rentals to this upstream are refused."),
            Shown::Unverifiable(why) => format!("This can't be checked: {why}. Without a look inside its jobs nobody can say a hashmaker can't drop the shares that win, so rentals to this upstream are refused."),
        }
    }

    /// A rental can go on.
    pub fn may_rent(&self) -> bool {
        matches!(self, Shown::Blinded(_))
    }
}

/// Open a session to an upstream as a miner would, and put its first job to the check. For the renter's page,
/// before and between rentals, with no rental to look through.
pub fn probe(upstream: &str, api: Option<&str>, user: &str) -> Shown {
    let Some(api) = api else {
        return Shown::Unverifiable("this upstream has no local gateway to open its jobs: it's a pool reached directly, or a gateway without the check".into());
    };
    let Some(addr) = upstream.to_socket_addrs().ok().and_then(|mut a| a.next()) else {
        return Shown::Unverifiable(format!("no such address: {upstream}"));
    };
    let Ok(mut s) = TcpStream::connect_timeout(&addr, PROBE_WAIT) else {
        return Shown::Unverifiable(format!("{upstream} doesn't answer"));
    };
    let _ = s.set_read_timeout(Some(PROBE_WAIT));
    let _ = s.set_write_timeout(Some(PROBE_WAIT));
    let hello = format!("{}\n{}\n", json!({"id": 1, "method": "mining.subscribe", "params": ["hashlink-check/0"]}), json!({"id": 2, "method": "mining.authorize", "params": [user, "x"]}));
    if s.write_all(hello.as_bytes()).is_err() {
        return Shown::Unverifiable(format!("{upstream} doesn't answer"));
    }
    let Ok(read) = s.try_clone() else { return Shown::Unverifiable("no connection".into()) };
    let mut lines = BufReader::new(read);
    let (mut d, mut line, t0) = (1.0, String::new(), std::time::Instant::now());
    while t0.elapsed() < PROBE_WAIT {
        line.clear();
        match lines.read_line(&mut line) {
            Ok(n) if n > 0 => {}
            _ => break,
        }
        let Some(v) = crate::sv1::parse(&line) else { continue };
        if let Some(x) = crate::sv1::set_difficulty(&v) {
            d = x;
        } else if crate::sv1::method(&v) == Some("mining.notify") {
            let _ = s.shutdown(std::net::Shutdown::Both);
            return match Check::new(api.to_string()).job(&v, d) {
                Ok(mode) => Shown::Blinded(mode),
                // no answer about the job is no answer; an answer that fails is one
                Err(why) if why.contains("API") || why.contains("doesn't know") || why.contains("no such address") || why.contains(UNSUPPORTED) => {
                    Shown::Unverifiable(why)
                }
                Err(why) => Shown::NotBlinded(why),
            };
        }
    }
    let _ = s.shutdown(std::net::Shutdown::Both);
    Shown::Unverifiable(format!("{upstream} gave no job to look at"))
}

/// Hold a gateway's answer to the job the miner is about to get.
fn verify(a: &Value, coinb1: &[u8], hidden_prev: &[u8], pot: u32) -> Result<(), String> {
    if a.get("null_key").and_then(Value::as_bool) != Some(false) {
        return Err("this job isn't blinded: its key is null".into());
    }
    if hex32(a, "xor_key_hash")? == tagged("Bitcoin block hash PoW XOR key", &[0u8; 16]) {
        return Err("this job isn't blinded: its key is null".into());
    }
    let clear = num(a, "clear_bits")?;
    if clear != 32 + pot as u64 {
        return Err(format!("this job's clear_bits is {clear}, and its shares have {} bits", 32 + pot));
    }
    let prev = hex32(a, "prevblock")?;
    let mut want = tagged("Bitcoin prevblock header, hashed", &prev);
    want[..6].fill(0);
    if hidden_prev != want {
        return Err("this job's previous block isn't the one the gateway opened".into());
    }
    let h2 = h2_of(a, &prev, clear as u8)?;
    if coinb1.get(3..35) != Some(&h2[..]) {
        return Err("this job's coinbase doesn't commit to what the gateway opened".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::net::TcpListener;

    /// A real job from a real gateway on regtest (lab-results/gateway-blind/A): its `coinb1` commits to this.
    fn real() -> Value {
        json!({"id":"N6ae641b506c0dbff","pot":0,"mode":"solo","null_key":false,"version":2684354560u64,
            "prevblock":"00000000f096dbc530ef1b760da9314dc71759bc8bea7ae064f73bc5473357c5","prevblock_order":"display","height":127,
            "merkle_root":"c1787705bb3cf86e97e59c6577096c7ff1065946341df1361f08cb01e8af49d8","time_on_wire":1793474997u64,"nbits":545259519u64,"txcount":1,"flags":0,"clear_bits":32,
            "xor_key_hash":"91d985b6f94929d5be6d0d51657d6a827d2546b5c4bd5f1a0d7500f48a18b7c1",
            "rhs":"0000000000000000000000000000000000000000000000000000000000000000",
            "h2":"1c90a6aa663261d4a6281ba5f2a1d46d77751dfadcb34d4ef06e0eaaee894cde"})
    }

    fn parts(a: &Value) -> (Vec<u8>, Vec<u8>) {
        let prev = hex32(a, "prevblock").unwrap();
        let mut hidden = tagged("Bitcoin prevblock header, hashed", &prev);
        hidden[..6].fill(0);
        let mut c = vec![0u8; 3];
        c.extend_from_slice(&hex::decode(a["h2"].as_str().unwrap()).unwrap());
        c.extend_from_slice(&[0u8; 4]);
        (c, hidden.to_vec())
    }

    #[test]
    fn a_real_jobs_h2_comes_out_of_what_the_gateway_said() {
        let a = real();
        let (c, hidden) = parts(&a);
        assert_eq!(verify(&a, &c, &hidden, 0), Ok(()));
    }

    #[test]
    fn every_way_of_not_being_blinded_is_refused() {
        let (c, hidden) = parts(&real());
        // each field of what's committed, changed: what the gateway says is no longer what the job commits to
        for (k, v) in [
            ("clear_bits", json!(33)),
            ("xor_key_hash", json!("00".repeat(32))),
            ("merkle_root", json!("00".repeat(32))),
            ("height", json!(128)),
            ("time_on_wire", json!(1)),
            ("nbits", json!(1)),
            ("version", json!(1)),
            ("txcount", json!(2)),
            ("flags", json!(1)),
            ("rhs", json!("11".repeat(32))),
            ("prevblock", json!("11".repeat(32))),
            ("null_key", json!(true)),
        ] {
            let mut a = real();
            a[k] = v;
            assert!(verify(&a, &c, &hidden, 0).is_err(), "{k}");
        }
        // the null key's own hash, said plainly or not
        let mut a = real();
        a["xor_key_hash"] = json!(hex::encode(tagged("Bitcoin block hash PoW XOR key", &[0u8; 16])));
        assert!(verify(&a, &c, &hidden, 0).unwrap_err().contains("null"));
        // clear_bits right for another difficulty than the shares'
        assert!(verify(&real(), &c, &hidden, 1).unwrap_err().contains("clear_bits"));
        // a job with another coinbase, or too short to hold one
        let mut other = c.clone();
        other[3] ^= 1;
        assert!(verify(&real(), &other, &hidden, 0).is_err());
        assert!(verify(&real(), &c[..20], &hidden, 0).is_err());
        let mut h = hidden.clone();
        h[31] ^= 1;
        assert!(verify(&real(), &c, &h, 0).is_err());
    }

    #[test]
    fn pot_follows_how_the_gateway_rounds_difficulty() {
        assert_eq!(pot_of(0.9999847412109375), 0);
        assert_eq!(pot_of(1.0), 0);
        assert_eq!(pot_of(1.999_969_482_421_875), 1);
        assert_eq!(pot_of(4095.9375), 12);
        assert_eq!(pot_of(16384.0), 14);
    }

    /// An API on a port: answers each request from `answer` by the request's first line.
    fn api(answer: impl Fn(&str) -> (u16, String) + Send + 'static) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let mut c = c;
                let (mut got, mut b) = (Vec::new(), [0u8; 2048]);
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut b) {
                        Ok(n) if n > 0 => got.extend_from_slice(&b[..n]),
                        _ => break,
                    }
                }
                let line = String::from_utf8_lossy(&got).lines().next().unwrap_or("").to_string();
                let (code, body) = answer(&line);
                let _ = write!(c, "HTTP/1.1 {code} X\r\nContent-Length: {}\r\n\r\n{body}", body.len());
            }
        });
        addr
    }

    fn notify(a: &Value) -> Value {
        let (c, hidden) = parts(a);
        json!({"id": null, "method": "mining.notify", "params": [a["id"], hex::encode(hidden), hex::encode(c), "", [], "", "", "", true]})
    }

    #[test]
    fn a_job_is_asked_for_by_id_and_pot_and_an_unknown_one_is_refused() {
        let a = real();
        let body = a.to_string();
        let good = api(move |line| {
            assert!(line.contains("/xbt/job?id=N6ae641b506c0dbff&pot=0"), "{line}");
            (200, body.clone())
        });
        assert_eq!(Check::new(good).job(&notify(&a), 1.0), Ok("solo".to_string()));
        let unknown = api(|_| (404, "{\"error\":\"unknown job\"}".into()));
        assert!(Check::new(unknown).job(&notify(&a), 1.0).unwrap_err().contains("doesn't know"));
        let denied = api(|_| (403, "{}".into()));
        assert!(Check::new(denied).job(&notify(&a), 1.0).unwrap_err().contains("403"));
        // nothing there at all
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let gone = l.local_addr().unwrap().to_string();
        drop(l);
        assert!(Check::new(gone).job(&notify(&a), 1.0).is_err());
    }

    #[test]
    fn one_key_on_two_templates_is_refused() {
        // h2 isn't reached: the second job's answer, for this test, has a different previous block
        let a = real();
        let body = a.to_string();
        let check = Check::new(api(move |_| (200, body.clone())));
        check.job(&notify(&a), 1.0).unwrap();
        check.keys.lock().unwrap().insert(hex32(&a, "xor_key_hash").unwrap(), [9u8; 32]);
        assert!(check.job(&notify(&a), 1.0).unwrap_err().contains("two templates"));
    }

    /// Mike's rule: what can't be checked is refused. A pool-held key (ABW) can outlast a block the pool found and
    /// nothing here sees whether it does; a mode never seen can't be judged at all. Both are refused even with a
    /// commitment that checks out, and the page says why without calling them unmasked.
    #[test]
    fn a_pool_held_key_and_a_mode_never_seen_are_refused_as_unverifiable() {
        for mode in ["abw", "some-pool-next-year", ""] {
            let mut a = real();
            a["mode"] = json!(mode);
            let body = a.to_string();
            let check = Check::new(api(move |_| (200, body.clone())));
            let why = check.job(&notify(&a), 1.0).unwrap_err();
            assert!(why.contains(UNSUPPORTED), "{mode}: {why}");
            if mode == "abw" {
                assert!(why.contains("ABW"), "{why}");
            }
            let up = stratum(notify(&a));
            let body = a.to_string();
            let shown = probe(&up, Some(&api(move |_| (200, body.clone()))), "u");
            assert!(matches!(shown, Shown::Unverifiable(_)) && !shown.may_rent(), "{mode}: {shown:?}");
        }
    }

    /// Every mode that isn't refused keeps one key to one template: a key seen on another previous block is refused,
    /// in pool-key as in solo.
    #[test]
    fn one_key_on_two_templates_is_refused_in_every_mode_that_rents() {
        for mode in KNOWN_MODES {
            let mut a = real();
            a["mode"] = json!(mode);
            let body = a.to_string();
            let check = Check::new(api(move |_| (200, body.clone())));
            assert_eq!(check.job(&notify(&a), 1.0), Ok(mode.to_string()));
            check.keys.lock().unwrap().insert(hex32(&a, "xor_key_hash").unwrap(), [9u8; 32]);
            assert!(check.job(&notify(&a), 1.0).unwrap_err().contains("two templates"), "{mode}");
        }
    }

    #[test]
    fn a_pool_with_no_key_is_refused_whatever_its_word() {
        // a pool with no key at all is still refused, whatever word it uses
        let mut a = real();
        a["mode"] = json!("pool-null");
        a["null_key"] = json!(true);
        let body = a.to_string();
        assert!(Check::new(api(move |_| (200, body.clone()))).job(&notify(&a), 1.0).is_err());
    }

    /// An upstream speaking Stratum, giving one job.
    fn stratum(job: Value) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let mut w = c.try_clone().unwrap();
                let _ = writeln!(w, "{}", json!({"id": null, "method": "mining.set_difficulty", "params": [1.0]}));
                let _ = writeln!(w, "{job}");
                // read what the caller sends until it goes: closing with its lines unread would reset the connection,
                // and could take the job with it
                let job = job.clone();
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut BufReader::new(c), &mut std::io::sink());
                    drop(job);
                });
            }
        });
        addr
    }

    #[test]
    fn the_renters_page_is_told_plainly_what_each_upstream_shows() {
        let a = real();
        let up = stratum(notify(&a));
        // a pool reached directly, with no gateway of the renter's: only h2 in sight, so unverifiable
        let direct = probe(&up, None, "u");
        assert!(matches!(direct, Shown::Unverifiable(_)) && !direct.may_rent(), "{direct:?}");
        assert!(direct.words().contains("refused"), "{}", direct.words());
        // a gateway that opens it
        let body = a.to_string();
        let shown = probe(&up, Some(&api(move |_| (200, body.clone()))), "u");
        assert_eq!(shown, Shown::Blinded("solo".into()));
        assert!(shown.may_rent() && shown.words().starts_with("Blinded"), "{}", shown.words());
        // a pool with no key
        let mut n = real();
        n["mode"] = json!("pool-null");
        n["null_key"] = json!(true);
        let body = n.to_string();
        let shown = probe(&up, Some(&api(move |_| (200, body.clone()))), "u");
        assert!(matches!(&shown, Shown::NotBlinded(w) if w.contains("null")), "{shown:?}");
        assert_eq!(shown.to_json()["state"], "not blinded");
        // a gateway without the check says 404 to what it doesn't know
        let shown = probe(&up, Some(&api(|_| (404, "{}".into()))), "u");
        assert!(matches!(shown, Shown::Unverifiable(_)), "{shown:?}");
    }
}
