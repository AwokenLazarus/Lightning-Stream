//! One event out, or one query, then hang up: for a seller publishing its listing now and then and
//! a buyer's app reading listings when its owner opens the page. Each relay is asked on a thread of
//! its own, so a slow or dead relay costs its timeout once, not once per relay.
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::event::{Event, MAX_EVENT_BYTES};
use crate::ws::{Msg, WebSocket};

/// What one relay said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub relay: String,
    /// `Ok` when the relay accepted (publish) or ended its stored events (query); the reason
    /// otherwise.
    pub result: Result<(), String>,
}

/// At most this many events are kept from one relay for one query.
pub const MAX_EVENTS_PER_RELAY: usize = 500;

fn each<T: Send + 'static>(relays: &[String], f: impl Fn(String) -> T + Send + Sync + Clone + 'static) -> Vec<T> {
    let handles: Vec<_> = relays.iter().cloned().map(|r| {
        let f = f.clone();
        std::thread::spawn(move || f(r))
    }).collect();
    handles.into_iter().filter_map(|h| h.join().ok()).collect()
}

fn left(until: Instant) -> Option<Duration> {
    let d = until.saturating_duration_since(Instant::now());
    (!d.is_zero()).then_some(d.min(Duration::from_millis(200)))
}

/// Send `ev` to each relay and wait for its `OK`, up to `timeout` for each.
pub fn publish(relays: &[String], ev: &Event, timeout: Duration) -> Vec<Outcome> {
    let text = json!(["EVENT", ev.to_value()]).to_string();
    let id = ev.id.clone();
    each(relays, move |relay| {
        let result = publish_one(&relay, &text, &id, timeout);
        Outcome { relay, result }
    })
}

fn publish_one(relay: &str, text: &str, id: &str, timeout: Duration) -> Result<(), String> {
    let until = Instant::now() + timeout;
    let mut ws = WebSocket::connect(relay, timeout).map_err(|e| e.to_string())?;
    ws.send_text(text).map_err(|e| e.to_string())?;
    let out = loop {
        let Some(d) = left(until) else { break Err("no answer from the relay in time".to_string()) };
        let _ = ws.set_read_timeout(d);
        match ws.read() {
            Ok(Some(Msg::Text(t))) => {
                let Ok(Value::Array(a)) = serde_json::from_str::<Value>(&t) else { continue };
                if a.first().and_then(Value::as_str) == Some("OK") && a.get(1).and_then(Value::as_str) == Some(id) {
                    break match a.get(2) {
                        Some(Value::Bool(true)) => Ok(()),
                        _ => Err(format!("refused: {}", clean(a.get(3)))),
                    };
                }
            }
            Ok(Some(Msg::Close)) => break Err("the relay closed the connection".into()),
            Ok(_) => {}
            Err(e) => break Err(e.to_string()),
        }
    };
    ws.close();
    ws.shutdown();
    out
}

/// Run `filter` on each relay until it ends its stored events (`EOSE`) or `timeout` passes, and
/// return every event that came, with what each relay said. Events are not checked here: the
/// caller verifies each one ([`Event::verify`]) before it believes anything in it.
pub fn query(relays: &[String], filter: &Value, timeout: Duration) -> (Vec<Event>, Vec<Outcome>) {
    let filter = filter.clone();
    let got = each(relays, move |relay| {
        let mut events = Vec::new();
        let result = query_one(&relay, &filter, timeout, &mut events);
        (events, Outcome { relay, result })
    });
    let mut events = Vec::new();
    let mut outcomes = Vec::new();
    for (e, o) in got {
        events.extend(e);
        outcomes.push(o);
    }
    (events, outcomes)
}

fn query_one(relay: &str, filter: &Value, timeout: Duration, out: &mut Vec<Event>) -> Result<(), String> {
    let until = Instant::now() + timeout;
    let mut ws = WebSocket::connect(relay, timeout).map_err(|e| e.to_string())?;
    let sub = {
        let mut b = [0u8; 8];
        getrandom::getrandom(&mut b).map_err(|e| e.to_string())?;
        hex::encode(b)
    };
    ws.send_text(&json!(["REQ", sub, filter]).to_string()).map_err(|e| e.to_string())?;
    let res = loop {
        let Some(d) = left(until) else { break Err("the relay did not finish in time".to_string()) };
        let _ = ws.set_read_timeout(d);
        match ws.read() {
            Ok(Some(Msg::Text(t))) => {
                if t.len() > MAX_EVENT_BYTES {
                    continue;
                }
                let Ok(Value::Array(a)) = serde_json::from_str::<Value>(&t) else { continue };
                if a.get(1).and_then(Value::as_str) != Some(sub.as_str()) {
                    continue;
                }
                match a.first().and_then(Value::as_str) {
                    Some("EVENT") if out.len() < MAX_EVENTS_PER_RELAY => {
                        if let Some(ev) = a.get(2).and_then(Event::from_value) {
                            out.push(ev);
                        }
                    }
                    Some("EOSE") => break Ok(()),
                    Some("CLOSED") => break Err(format!("the relay closed the query: {}", clean(a.get(2)))),
                    _ => {}
                }
            }
            Ok(Some(Msg::Close)) => break Err("the relay closed the connection".into()),
            Ok(_) => {}
            Err(e) => break Err(e.to_string()),
        }
    };
    let _ = ws.send_text(&json!(["CLOSE", sub]).to_string());
    ws.close();
    ws.shutdown();
    res
}

fn clean(v: Option<&Value>) -> String {
    v.and_then(Value::as_str).unwrap_or("").chars().filter(|c| !c.is_control()).take(200).collect()
}
