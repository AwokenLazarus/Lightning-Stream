//! A stand-in pool and a stand-in miner for the lab.
//!
//! They speak ordinary Stratum V1 (subscribe, authorize, set_difficulty, notify, submit), but
//! the share hash is a toy, not the chain's proof of work: BLAKE2b-256 of
//! `job|extranonce1|extranonce2|ntime|nonce`, and difficulty 1 is a hash under 2^240 (65536
//! tries on average), so a CPU finds shares at any difficulty the lab picks. The pool checks
//! every share (known job, authorized user, no repeat, the hash under the target) and keeps its
//! own count of accepted work, a third witness beside the hasher's and the buyer's meters.

use crate::meter::share_work;
use crate::{now_ms, sv1};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub fn toy_hash(job: &str, en1: &str, en2: &str, ntime: &str, nonce: &str) -> [u8; 32] {
    let mut h = Blake2b::<U32>::new();
    h.update(format!("{job}|{en1}|{en2}|{ntime}|{nonce}").as_bytes());
    h.finalize().into()
}

/// Does the toy hash meet difficulty `d`? (hash < 2^240 / d, read from its top 128 bits)
pub fn meets(hash: &[u8; 32], d: f64) -> bool {
    let top = u128::from_be_bytes(hash[..16].try_into().unwrap()) as f64;
    top * d < 2f64.powi(112)
}

#[derive(Default)]
struct PoolSt {
    accepted: u64,
    rejected: u64,
    work: u128,
    users: HashMap<String, u64>,
    reasons: HashMap<String, u64>,
    last_accept_ms: u64,
    sessions: u64,
}

pub struct PoolConfig {
    pub listen: String,
    pub diff: f64,
    pub job_every: Duration,
    pub report: Option<PathBuf>,
}

fn report(st: &PoolSt) -> Value {
    json!({"role": "pool", "accepted": st.accepted, "rejected": st.rejected, "work": st.work.to_string(),
        "users": st.users, "reasons": st.reasons, "lastAcceptMs": st.last_accept_ms, "sessions": st.sessions})
}

fn write_report(path: &Option<PathBuf>, v: &Value) {
    if let Some(p) = path {
        let tmp = p.with_extension("tmp");
        if std::fs::write(&tmp, serde_json::to_vec_pretty(v).unwrap_or_default()).is_ok() {
            let _ = std::fs::rename(&tmp, p);
        }
    }
}

/// Run the stand-in pool until the process ends.
pub fn pool(cfg: PoolConfig) -> Result<(), String> {
    let l = TcpListener::bind(&cfg.listen).map_err(|e| format!("pool listen {}: {e}", cfg.listen))?;
    eprintln!("pool: {} at difficulty {}", cfg.listen, cfg.diff);
    let st = Arc::new(Mutex::new(PoolSt::default()));
    {
        let st = st.clone();
        let path = cfg.report.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(500));
            write_report(&path, &report(&st.lock().unwrap()));
        });
    }
    let mut n = 0u32;
    for c in l.incoming() {
        let Ok(c) = c else { continue };
        n += 1;
        let (st, diff, every) = (st.clone(), cfg.diff, cfg.job_every);
        std::thread::spawn(move || pool_session(c, n, st, diff, every));
    }
    Ok(())
}

fn pool_session(c: TcpStream, n: u32, st: Arc<Mutex<PoolSt>>, diff: f64, every: Duration) {
    st.lock().unwrap().sessions += 1;
    let en1 = format!("{n:08x}");
    let Ok(w) = c.try_clone() else { return };
    let w = Arc::new(Mutex::new(w));
    let jobs: Arc<Mutex<VecDeque<String>>> = Arc::default();
    let send = |w: &Arc<Mutex<TcpStream>>, v: Value| w.lock().unwrap().write_all(format!("{v}\n").as_bytes()).is_ok();
    let mut user: Option<String> = None;
    let mut seen = HashSet::new();
    let mut started = false;
    let mut r = BufReader::new(c);
    let mut line = String::new();
    loop {
        line.clear();
        match r.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let Some(v) = sv1::parse(&line) else { continue };
        let id = v.get("id").cloned().unwrap_or(Value::Null);
        match sv1::method(&v) {
            Some("mining.subscribe") => {
                send(&w, json!({"id": id, "result": [[["mining.set_difficulty", en1], ["mining.notify", en1]], en1, 4], "error": null}));
            }
            Some("mining.extranonce.subscribe") => {
                send(&w, json!({"id": id, "result": true, "error": null}));
            }
            Some("mining.authorize") => {
                user = sv1::authorize_user(&v);
                send(&w, json!({"id": id, "result": true, "error": null}));
                if !started {
                    started = true;
                    let (w, jobs, en1) = (w.clone(), jobs.clone(), en1.clone());
                    send(&w, json!({"id": null, "method": "mining.set_difficulty", "params": [diff]}));
                    std::thread::spawn(move || {
                        let mut k = 0u64;
                        loop {
                            k += 1;
                            let job = format!("{en1}-{k}");
                            {
                                let mut j = jobs.lock().unwrap();
                                j.push_back(job.clone());
                                if j.len() > 4 {
                                    j.pop_front();
                                }
                            }
                            let p = json!({"id": null, "method": "mining.notify",
                                "params": [job, format!("{:064x}", k), "", "", [], "00000002", "1d00ffff", format!("{:08x}", now_ms() / 1000), true]});
                            if !send(&w, p) {
                                return;
                            }
                            std::thread::sleep(every);
                        }
                    });
                }
            }
            Some("mining.submit") => {
                let p = sv1::params(&v).cloned().unwrap_or_default();
                let s = |i: usize| p.get(i).and_then(Value::as_str).unwrap_or("").to_string();
                let (u, job, en2, ntime, nonce) = (s(0), s(1), s(2), s(3), s(4));
                let why = if user.as_deref() != Some(&u) {
                    Some("unauthorized user")
                } else if !jobs.lock().unwrap().contains(&job) {
                    Some("stale job")
                } else if !seen.insert(format!("{job}|{en2}|{ntime}|{nonce}")) {
                    Some("duplicate")
                } else if !meets(&toy_hash(&job, &en1, &en2, &ntime, &nonce), diff) {
                    Some("low difficulty")
                } else {
                    None
                };
                let mut g = st.lock().unwrap();
                match why {
                    None => {
                        g.accepted += 1;
                        g.work += share_work(diff);
                        *g.users.entry(u).or_default() += 1;
                        g.last_accept_ms = now_ms();
                        drop(g);
                        send(&w, json!({"id": id, "result": true, "error": null}));
                    }
                    Some(why) => {
                        g.rejected += 1;
                        *g.reasons.entry(why.to_string()).or_default() += 1;
                        drop(g);
                        send(&w, json!({"id": id, "result": false, "error": [23, why, null]}));
                    }
                }
            }
            _ => {
                send(&w, json!({"id": id, "result": null, "error": [20, "unknown method", null]}));
            }
        }
    }
}

pub struct MinerConfig {
    pub pool: String,
    pub user: String,
    /// At most this many shares a second.
    pub max_rate: f64,
    /// Every `bad_every`-th share is sent with a wrong nonce (0: never).
    pub bad_every: u64,
    pub duration: Option<Duration>,
    /// Connect again when the connection ends or the pool asks (`client.reconnect`), as a real
    /// miner does; without it the miner stops when its connection ends.
    pub reconnect: bool,
    /// Ask for `mining.set_extranonce` (`mining.extranonce.subscribe`), as some firmware does.
    pub extranonce_subscribe: bool,
}

/// What a stand-in miner did.
#[derive(Clone, Debug, Default)]
pub struct MinerResult {
    pub submitted: u64,
    pub accepted: u64,
    pub rejected: u64,
    /// Connections made (1 when it never reconnected).
    pub sessions: u64,
    /// `mining.set_extranonce` messages taken.
    pub extranonce_changes: u64,
    /// The longest time between two accepted shares, after the first, and when it ended (ms
    /// after the miner started).
    pub max_gap_ms: u64,
    pub max_gap_end_ms: u64,
}

#[derive(Default)]
struct MinerSt {
    en1: String,
    diff: f64,
    job: Option<(String, String)>,
    accepted: u64,
    rejected: u64,
    extranonce_changes: u64,
    last_accept: Option<Instant>,
    max_gap: Duration,
    max_gap_end: Option<Instant>,
    gone: bool,
    /// The connection now in use: a reader of an older one changes nothing.
    gen: u64,
}

/// Run the stand-in miner until its time is up (or, without `reconnect`, its connection ends).
pub fn miner(cfg: MinerConfig) -> Result<MinerResult, String> {
    let t0 = Instant::now();
    let st = Arc::new(Mutex::new(MinerSt { diff: 1.0, ..Default::default() }));
    let mut res = MinerResult::default();
    let mut id = 10u64;
    let mut en2 = 0u32;
    let mut last = Instant::now() - Duration::from_secs(10);
    let over = |t0: Instant| cfg.duration.is_some_and(|d| t0.elapsed() > d);
    'session: loop {
        if over(t0) {
            break;
        }
        let c = match TcpStream::connect(&cfg.pool) {
            Ok(c) => c,
            Err(e) if res.sessions == 0 => return Err(format!("miner connect {}: {e}", cfg.pool)),
            Err(_) if cfg.reconnect => {
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
            Err(_) => break,
        };
        res.sessions += 1;
        let gen = res.sessions;
        {
            let mut g = st.lock().unwrap();
            g.gen = gen;
            g.gone = false;
            g.job = None;
            g.en1.clear();
        }
        let mut w = c.try_clone().map_err(|e| e.to_string())?;
        let say = |w: &mut TcpStream, v: Value| w.write_all(format!("{v}\n").as_bytes()).map_err(|e| e.to_string());
        let _ = say(&mut w, json!({"id": 1, "method": "mining.subscribe", "params": ["standin-miner/0"]}));
        if cfg.extranonce_subscribe {
            let _ = say(&mut w, json!({"id": 3, "method": "mining.extranonce.subscribe", "params": []}));
        }
        let _ = say(&mut w, json!({"id": 2, "method": "mining.authorize", "params": [cfg.user, "x"]}));
        {
            let st = st.clone();
            std::thread::spawn(move || {
                let mut r = BufReader::new(c);
                let mut line = String::new();
                loop {
                    line.clear();
                    if !matches!(r.read_line(&mut line), Ok(n) if n > 0) {
                        let mut g = st.lock().unwrap();
                        if g.gen == gen {
                            g.gone = true;
                        }
                        return;
                    }
                    let Some(v) = sv1::parse(&line) else { continue };
                    let mut g = st.lock().unwrap();
                    if g.gen != gen {
                        return;
                    }
                    if let Some(d) = sv1::set_difficulty(&v) {
                        g.diff = d;
                    } else if let Some(job) = sv1::notify_job(&v) {
                        let ntime = sv1::params(&v).and_then(|p| p.get(7)).and_then(Value::as_str).unwrap_or("").to_string();
                        g.job = Some((job, ntime));
                    } else if sv1::method(&v) == Some("mining.set_extranonce") {
                        if let Some(e) = sv1::params(&v).and_then(|p| p.first()).and_then(Value::as_str) {
                            g.en1 = e.to_string();
                            g.extranonce_changes += 1;
                        }
                    } else if sv1::method(&v) == Some("client.reconnect") {
                        // as a miner does: let this connection go, then connect again
                        g.gone = true;
                        return;
                    } else if v.get("id") == Some(&json!(1)) {
                        g.en1 = v["result"][1].as_str().unwrap_or("").to_string();
                    } else if v.get("id").and_then(Value::as_u64).is_some_and(|i| i >= 10) {
                        if sv1::accepted(&v) {
                            g.accepted += 1;
                            let now = Instant::now();
                            if let Some(prev) = g.last_accept {
                                if now - prev > g.max_gap {
                                    g.max_gap = now - prev;
                                    g.max_gap_end = Some(now);
                                }
                            }
                            g.last_accept = Some(now);
                        } else {
                            g.rejected += 1;
                        }
                    }
                }
            });
        }
        loop {
            if over(t0) {
                let _ = w.shutdown(std::net::Shutdown::Both);
                break 'session;
            }
            let (en1, diff, job, gone) = {
                let g = st.lock().unwrap();
                (g.en1.clone(), g.diff, g.job.clone(), g.gone)
            };
            if gone {
                let _ = w.shutdown(std::net::Shutdown::Both);
                if cfg.reconnect {
                    continue 'session;
                }
                break 'session;
            }
            let Some((job, ntime)) = job.filter(|_| !en1.is_empty()) else {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            };
            en2 = en2.wrapping_add(1);
            let e2 = format!("{en2:08x}");
            let mut found = None;
            for nonce in 0u32..2_000_000 {
                let n = format!("{nonce:08x}");
                if meets(&toy_hash(&job, &en1, &e2, &ntime, &n), diff) {
                    found = Some(n);
                    break;
                }
            }
            let Some(mut nonce) = found else { continue };
            let gap = Duration::from_secs_f64(1.0 / cfg.max_rate.max(0.001));
            if let Some(wait) = gap.checked_sub(last.elapsed()) {
                std::thread::sleep(wait);
            }
            last = Instant::now();
            id += 1;
            if cfg.bad_every > 0 && (id - 10).is_multiple_of(cfg.bad_every) {
                nonce = "ffffffff".into();
            }
            if say(&mut w, json!({"id": id, "method": "mining.submit", "params": [cfg.user, job, e2, ntime, nonce]})).is_err() {
                st.lock().unwrap().gone = true;
            }
        }
    }
    // the last verdicts in flight
    std::thread::sleep(Duration::from_millis(200));
    let g = st.lock().unwrap();
    res.submitted = id - 10;
    res.accepted = g.accepted;
    res.rejected = g.rejected;
    res.extranonce_changes = g.extranonce_changes;
    res.max_gap_ms = g.max_gap.as_millis() as u64;
    res.max_gap_end_ms = g.max_gap_end.map(|t| (t - t0).as_millis() as u64).unwrap_or(0);
    Ok(res)
}
