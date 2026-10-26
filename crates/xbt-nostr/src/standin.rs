//! A stand-in Nostr relay on loopback, in process: for the tests and for trying the service on one
//! machine. It is not a relay to run for anyone: it keeps everything in memory, checks each event's
//! id and signature, keeps the newest replaceable event (kinds 10000-19999) per author and kind,
//! the newest addressable one (30000-39999) per author, kind and `d`, forwards ephemeral ones
//! (20000-29999) to the subscriptions open at the time, and matches filters on `ids`, `authors`,
//! `kinds`, single-letter tags (`#p`, `#t`, ...), `since` and `until`, newest first up to `limit`.
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use crate::event::Event;
use crate::ws::{Msg, WebSocket};

struct Sub {
    client: usize,
    id: String,
    filters: Vec<Value>,
}

#[derive(Default)]
struct State {
    stored: Vec<Event>,
    subs: Vec<Sub>,
    clients: Vec<(usize, Sender<String>)>,
    next: usize,
}

pub struct StandinRelay {
    pub url: String,
    st: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    /// Every event accepted, in order (what the tests look at).
    pub log: Arc<Mutex<Vec<Event>>>,
}

fn matches(f: &Value, ev: &Event) -> bool {
    let list = |k: &str| f.get(k).and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect::<Vec<_>>());
    if list("ids").is_some_and(|l| !l.contains(&ev.id)) || list("authors").is_some_and(|l| !l.contains(&ev.pubkey)) {
        return false;
    }
    if f.get("kinds").and_then(Value::as_array).is_some_and(|k| !k.iter().any(|x| x.as_u64() == Some(ev.kind))) {
        return false;
    }
    let tag_filters = f.as_object().into_iter().flatten().filter_map(|(k, _)| k.strip_prefix('#').filter(|t| t.len() == 1).map(|t| (t.to_string(), k.clone())));
    for (t, key) in tag_filters {
        if let Some(l) = list(&key) {
            if !ev.tags.iter().any(|tg| tg.first() == Some(&t) && tg.get(1).is_some_and(|v| l.contains(v))) {
                return false;
            }
        }
    }
    if f.get("since").and_then(Value::as_u64).is_some_and(|s| ev.created_at < s) || f.get("until").and_then(Value::as_u64).is_some_and(|u| ev.created_at > u) {
        return false;
    }
    true
}

impl StandinRelay {
    pub fn start() -> std::io::Result<Self> {
        Self::start_on("127.0.0.1:0")
    }

    /// The same relay on a chosen address: for a rehearsal between machines of one LAN.
    pub fn start_on(addr: &str) -> std::io::Result<Self> {
        let l = TcpListener::bind(addr)?;
        let url = format!("ws://{}", l.local_addr()?);
        let st = Arc::new(Mutex::new(State::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let log = Arc::new(Mutex::new(vec![]));
        let (st2, stop2, log2) = (st.clone(), stop.clone(), log.clone());
        l.set_nonblocking(true)?;
        std::thread::spawn(move || {
            while !stop2.load(Ordering::SeqCst) {
                match l.accept() {
                    Ok((tcp, _)) => {
                        let _ = tcp.set_nonblocking(false);
                        let (st, stop, log) = (st2.clone(), stop2.clone(), log2.clone());
                        std::thread::spawn(move || {
                            if let Ok(ws) = WebSocket::accept(tcp) {
                                serve(ws, st, stop, log);
                            }
                        });
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(20)),
                }
            }
        });
        Ok(Self { url, st, stop, log })
    }

    /// Events accepted so far of this kind.
    pub fn events(&self, kind: u64) -> Vec<Event> {
        self.log.lock().unwrap().iter().filter(|e| e.kind == kind).cloned().collect()
    }

    /// Open subscriptions (all clients).
    pub fn subscriptions(&self) -> Vec<Value> {
        self.st.lock().unwrap().subs.iter().map(|s| json!({"id": s.id, "filters": s.filters})).collect()
    }

    /// Drop every client connection (a relay restart, for the reconnect test).
    pub fn drop_clients(&self) {
        let mut st = self.st.lock().unwrap();
        st.clients.clear();
        st.subs.clear();
    }
}

impl Drop for StandinRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn serve(mut ws: WebSocket, st: Arc<Mutex<State>>, stop: Arc<AtomicBool>, log: Arc<Mutex<Vec<Event>>>) {
    let (tx, rx) = mpsc::channel::<String>();
    let me = {
        let mut s = st.lock().unwrap();
        s.next += 1;
        let id = s.next;
        s.clients.push((id, tx));
        id
    };
    let _ = ws.set_read_timeout(Duration::from_millis(50));
    while !stop.load(Ordering::SeqCst) {
        if !st.lock().unwrap().clients.iter().any(|(c, _)| *c == me) {
            break; // dropped
        }
        while let Ok(m) = rx.try_recv() {
            if ws.send_text(&m).is_err() {
                return;
            }
        }
        let text = match ws.read() {
            Ok(Some(Msg::Text(t))) => t,
            Ok(Some(Msg::Close)) | Err(_) => break,
            Ok(_) => continue,
        };
        let Ok(Value::Array(a)) = serde_json::from_str::<Value>(&text) else { continue };
        match a.first().and_then(Value::as_str) {
            Some("EVENT") => {
                let Some(ev) = a.get(1).and_then(Event::from_value) else { continue };
                let ok = ev.verify();
                let _ = ws.send_text(&json!(["OK", ev.id, ok, if ok { "" } else { "invalid: bad id or signature" }]).to_string());
                if !ok {
                    continue;
                }
                log.lock().unwrap().push(ev.clone());
                let mut s = st.lock().unwrap();
                if (10_000..20_000).contains(&ev.kind) {
                    s.stored.retain(|x| !(x.kind == ev.kind && x.pubkey == ev.pubkey));
                    s.stored.push(ev.clone());
                } else if (30_000..40_000).contains(&ev.kind) {
                    // addressable: the newest per author, kind and `d`; on a tie the lowest id (NIP-01)
                    let d = ev.tag("d").unwrap_or("").to_string();
                    let newer = !s.stored.iter().any(|x| x.kind == ev.kind && x.pubkey == ev.pubkey && x.tag("d").unwrap_or("") == d && (x.created_at, &ev.id) > (ev.created_at, &x.id));
                    if newer {
                        s.stored.retain(|x| !(x.kind == ev.kind && x.pubkey == ev.pubkey && x.tag("d").unwrap_or("") == d));
                        s.stored.push(ev.clone());
                    }
                } else if !(20_000..30_000).contains(&ev.kind) {
                    s.stored.push(ev.clone());
                }
                let msgs: Vec<(usize, String)> = s.subs.iter().filter(|sub| sub.filters.iter().any(|f| matches(f, &ev)))
                    .map(|sub| (sub.client, json!(["EVENT", sub.id, ev.to_value()]).to_string())).collect();
                for (c, m) in msgs {
                    if let Some((_, tx)) = s.clients.iter().find(|(id, _)| *id == c) {
                        let _ = tx.send(m);
                    }
                }
            }
            Some("REQ") => {
                let Some(id) = a.get(1).and_then(Value::as_str).map(str::to_string) else { continue };
                let filters: Vec<Value> = a[2..].to_vec();
                let mut s = st.lock().unwrap();
                s.subs.retain(|x| !(x.client == me && x.id == id));
                let limit = filters.iter().filter_map(|f| f.get("limit").and_then(Value::as_u64)).max().map_or(usize::MAX, |l| l as usize);
                let mut old: Vec<&Event> = s.stored.iter().filter(|ev| filters.iter().any(|f| matches(f, ev))).collect();
                old.sort_by_key(|e| std::cmp::Reverse(e.created_at));
                let old: Vec<String> = old.into_iter().take(limit).map(|ev| json!(["EVENT", id, ev.to_value()]).to_string()).collect();
                s.subs.push(Sub { client: me, id: id.clone(), filters });
                drop(s);
                for m in old {
                    let _ = ws.send_text(&m);
                }
                let _ = ws.send_text(&json!(["EOSE", id]).to_string());
            }
            Some("CLOSE") => {
                let id = a.get(1).and_then(Value::as_str).unwrap_or("").to_string();
                st.lock().unwrap().subs.retain(|x| !(x.client == me && x.id == id));
            }
            _ => {}
        }
    }
    let mut s = st.lock().unwrap();
    s.subs.retain(|x| x.client != me);
    s.clients.retain(|(c, _)| *c != me);
    drop(s);
    ws.shutdown();
}
