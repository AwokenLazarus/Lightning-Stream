//! The relay pool: one thread per relay URL, each holding a WebSocket to its relay, reconnecting with
//! a growing pause (1 s to 60 s) when it drops. On every (re)connect the thread asks the [`Hub`] what
//! to send (the subscription and the info events); events from the relay go to the hub.
use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::event::{Event, MAX_EVENT_BYTES};
use crate::ws::{Msg, WebSocket};

/// What the pool tells its owner, and asks it.
pub trait Hub: Send + Sync + 'static {
    /// The messages to send on a fresh connection to `relay` (a `REQ`, info events).
    fn on_connect(&self, relay: &str) -> Vec<String>;
    /// An event a relay sent for one of our subscriptions.
    fn on_event(&self, relay: &str, ev: Event);
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(100);
const KEEPALIVE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Default)]
pub struct RelayStatus {
    pub connected: bool,
    pub since: u64,
    pub last_error: Option<String>,
    pub notices: Vec<String>,
}

enum Out {
    Text(String),
    Stop,
}

struct Relay {
    tx: Sender<Out>,
    status: Arc<Mutex<RelayStatus>>,
}

pub struct Pool {
    hub: Weak<dyn Hub>,
    relays: Mutex<HashMap<String, Relay>>,
}

fn now() -> u64 {
    crate::now()
}

impl Pool {
    pub fn new(hub: Weak<dyn Hub>) -> Arc<Self> {
        Arc::new(Self { hub, relays: Mutex::new(HashMap::new()) })
    }

    /// Have a thread for exactly these relays: new ones start, ones not listed stop. A relay already
    /// running is sent `refresh` (the messages its hub would send on connect) when `refresh` is set.
    pub fn sync(&self, urls: &[String], refresh: bool) {
        let mut rs = self.relays.lock().unwrap_or_else(|p| p.into_inner());
        rs.retain(|u, r| {
            let keep = urls.contains(u);
            if !keep {
                let _ = r.tx.send(Out::Stop);
            }
            keep
        });
        for u in urls {
            if let Some(r) = rs.get(u) {
                if refresh {
                    if let Some(h) = self.hub.upgrade() {
                        for m in h.on_connect(u) {
                            let _ = r.tx.send(Out::Text(m));
                        }
                    }
                }
                continue;
            }
            let (tx, rx) = mpsc::channel();
            let status = Arc::new(Mutex::new(RelayStatus::default()));
            let (hub, url, st) = (self.hub.clone(), u.clone(), status.clone());
            let _ = std::thread::Builder::new().name("nostr-relay".into()).spawn(move || run(url, hub, rx, st));
            rs.insert(u.clone(), Relay { tx, status });
        }
    }

    /// Send `text` to each of `urls` the pool has (a relay that is down gets it on reconnect only if the
    /// hub's `on_connect` says so: a response sent while a relay is down is lost on that relay).
    pub fn send(&self, urls: &[String], text: &str) {
        let rs = self.relays.lock().unwrap_or_else(|p| p.into_inner());
        for u in urls {
            if let Some(r) = rs.get(u) {
                let _ = r.tx.send(Out::Text(text.to_string()));
            }
        }
    }

    pub fn status(&self) -> Vec<Value> {
        let rs = self.relays.lock().unwrap_or_else(|p| p.into_inner());
        let mut v: Vec<Value> = rs.iter().map(|(u, r)| {
            let s = r.status.lock().unwrap_or_else(|p| p.into_inner()).clone();
            json!({"url": u, "connected": s.connected, "since": s.since, "last_error": s.last_error, "notices": s.notices})
        }).collect();
        v.sort_by(|a, b| a["url"].as_str().cmp(&b["url"].as_str()));
        v
    }

    /// Stop every relay thread.
    pub fn stop(&self) {
        self.sync(&[], false);
    }
}

fn set(st: &Mutex<RelayStatus>, f: impl FnOnce(&mut RelayStatus)) {
    f(&mut st.lock().unwrap_or_else(|p| p.into_inner()));
}

/// Wait up to `d` for a stop; true if one came. Other messages queued meanwhile are dropped: they are
/// for a connection that is down, and the hub resends what matters on connect.
fn pause(rx: &Receiver<Out>, d: Duration) -> bool {
    let until = Instant::now() + d;
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        match rx.recv_timeout(left) {
            Ok(Out::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => return true,
            Ok(Out::Text(_)) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => return false,
        }
    }
}

fn run(url: String, hub: Weak<dyn Hub>, rx: Receiver<Out>, st: Arc<Mutex<RelayStatus>>) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let Some(h) = hub.upgrade() else { return };
        let mut ws = match WebSocket::connect(&url, CONNECT_TIMEOUT) {
            Ok(ws) => ws,
            Err(e) => {
                drop(h);
                set(&st, |s| {
                    s.connected = false;
                    s.last_error = Some(e.to_string());
                });
                if pause(&rx, backoff) {
                    return;
                }
                backoff = (backoff * 2).min(Duration::from_secs(60));
                continue;
            }
        };
        let _ = ws.set_read_timeout(POLL);
        set(&st, |s| {
            s.connected = true;
            s.since = now();
            s.last_error = None;
        });
        // anything queued while it was down is stale: on_connect has what is current
        while rx.try_recv().is_ok_and(|m| !matches!(m, Out::Stop)) {}
        let mut err = None;
        for m in h.on_connect(&url) {
            if let Err(e) = ws.send_text(&m) {
                err = Some(e.to_string());
                break;
            }
        }
        drop(h);
        let mut last_ping = Instant::now();
        loop {
            if err.is_some() {
                break;
            }
            match ws.read() {
                Ok(Some(Msg::Text(t))) => {
                    backoff = Duration::from_secs(1);
                    on_text(&url, &hub, &st, &t);
                }
                Ok(Some(Msg::Close)) => {
                    err = Some("the relay closed the connection".into());
                    continue;
                }
                Ok(Some(_)) | Ok(None) => {}
                Err(e) => {
                    err = Some(e.to_string());
                    continue;
                }
            }
            loop {
                match rx.try_recv() {
                    Ok(Out::Text(m)) => {
                        if let Err(e) = ws.send_text(&m) {
                            err = Some(e.to_string());
                            break;
                        }
                    }
                    Ok(Out::Stop) | Err(mpsc::TryRecvError::Disconnected) => {
                        ws.close();
                        set(&st, |s| s.connected = false);
                        return;
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                }
            }
            if last_ping.elapsed() > KEEPALIVE {
                last_ping = Instant::now();
                if let Err(e) = ws.send_ping(b"xbt") {
                    err = Some(e.to_string());
                }
            }
        }
        ws.shutdown();
        set(&st, |s| {
            s.connected = false;
            s.last_error = err.clone();
        });
        if pause(&rx, backoff) {
            return;
        }
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

fn on_text(url: &str, hub: &Weak<dyn Hub>, st: &Mutex<RelayStatus>, t: &str) {
    if t.len() > MAX_EVENT_BYTES {
        return;
    }
    let Ok(Value::Array(a)) = serde_json::from_str::<Value>(t) else { return };
    match a.first().and_then(Value::as_str) {
        Some("EVENT") => {
            if let (Some(ev), Some(h)) = (a.get(2).and_then(Event::from_value), hub.upgrade()) {
                h.on_event(url, ev);
            }
        }
        // a refusal of what we published, a notice, a closed subscription: kept for the status page
        Some("OK") if a.get(2) == Some(&Value::Bool(false)) => note(st, format!("refused {}: {}", short(a.get(1)), short(a.get(3)))),
        Some("NOTICE") => note(st, format!("notice: {}", short(a.get(1)))),
        Some("CLOSED") => note(st, format!("subscription closed: {}", short(a.get(2)))),
        Some("AUTH") => note(st, "the relay asks for NIP-42 authentication, which this service does not do".into()),
        _ => {}
    }
}

fn short(v: Option<&Value>) -> String {
    v.and_then(Value::as_str).unwrap_or("").chars().filter(|c| !c.is_control()).take(200).collect()
}

fn note(st: &Mutex<RelayStatus>, m: String) {
    set(st, |s| {
        s.notices.push(m);
        if s.notices.len() > 5 {
            s.notices.remove(0);
        }
    });
}
