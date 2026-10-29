//! A route's capacity (`capacity` in the config, docs/CAPACITY.md): how many buyers and long answers
//! the service carries at once, and how fast together. A buyer turned away is turned away before
//! paying anything (the 402 of a new visit, or a paid request before it is charged), with a 503 that
//! says which limit is reached; a buyer already served is never cut off to make room.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use serde_json::{json, Value};

use crate::config::{Capacity, Route, BUYER_IDLE_S};

/// A body longer than this, or of unknown length that is media or an event stream, is a long
/// answer: it holds the service for a while, so it counts against `max_streams`.
pub const STREAM_BYTES: u64 = 8 << 20;

/// How long a buyer turned away is asked to wait before trying again, in seconds.
pub const RETRY_AFTER_S: u64 = 30;

/// The window the rate of a route's answers is measured over.
const RATE_WINDOW_S: u64 = 10;

/// A limit reached: which, how much of it is in use, and what it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Busy {
    pub scope: Scope,
    pub in_use: u32,
    pub limit: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Buyers,
    Streams,
    BuyerStreams,
    Bandwidth,
}

impl Scope {
    pub fn name(self) -> &'static str {
        match self {
            Scope::Buyers => "buyers",
            Scope::Streams => "streams",
            Scope::BuyerStreams => "buyer_streams",
            Scope::Bandwidth => "bandwidth",
        }
    }
}

impl Busy {
    /// What the buyer's app shows, in plain words.
    pub fn words(&self) -> String {
        match self.scope {
            Scope::Buyers => format!("This shop is busy ({} of {} buyers served at once). Try again in a moment.", self.in_use, self.limit),
            Scope::Streams => format!("This shop is busy ({} of {} streams in use). Try again in a moment.", self.in_use, self.limit),
            Scope::BuyerStreams => format!("You already have {} of the {} streams this shop allows one buyer at once.", self.in_use, self.limit),
            Scope::Bandwidth => format!("This shop is busy (carrying {} of its {} Mbit/s). Try again in a moment.", self.in_use, self.limit),
        }
    }

    /// The body of the 503: the code `busy`, the words, and the counts for a program to read.
    pub fn body(&self) -> Value {
        json!({"error": "busy", "detail": self.words(),
               "busy": {"scope": self.scope.name(), "inUse": self.in_use, "limit": self.limit, "retryAfter": RETRY_AFTER_S}})
    }
}

#[derive(Default)]
struct RouteLoad {
    /// Buyer (session) → the unix time of its last request of the route.
    buyers: HashMap<String, u64>,
    /// Buyer (session, or "" for a free route's answers) → its long answers open.
    streams: HashMap<String, u32>,
    /// Bytes sent in each of the last [`RATE_WINDOW_S`] seconds, by the second they were sent in.
    bytes: Vec<(u64, u64)>,
}

impl RouteLoad {
    fn open(&self) -> u32 {
        self.streams.values().sum()
    }

    fn prune(&mut self, now: u64) {
        let streams = &self.streams;
        self.buyers.retain(|s, last| now.saturating_sub(*last) <= BUYER_IDLE_S || streams.get(s).is_some_and(|n| *n > 0));
        self.bytes.retain(|(sec, _)| now.saturating_sub(*sec) < RATE_WINDOW_S);
    }

    /// The route's rate over the window, in whole megabits a second.
    fn mbit(&self) -> u32 {
        let total: u64 = self.bytes.iter().map(|(_, b)| b).sum();
        (total.saturating_mul(8) / RATE_WINDOW_S / 1_000_000).min(u64::from(u32::MAX)) as u32
    }
}

/// Every route's load. Kept in memory: a restarted gateway starts with no buyer counted, and its
/// buyers come back through the 402 as new ones would.
#[derive(Default)]
pub struct Load {
    routes: Mutex<HashMap<String, RouteLoad>>,
    started: Option<Instant>,
}

impl Load {
    pub fn new() -> Arc<Self> {
        Arc::new(Load { routes: Mutex::default(), started: Some(Instant::now()) })
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, RouteLoad>> {
        self.routes.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Seconds on a monotonic clock, for the rate window (a wall clock that steps would bend it).
    fn mono(&self) -> u64 {
        self.started.map_or(0, |s| s.elapsed().as_secs())
    }

    /// A request of `route` by `session` (none: a new visit, asking the price). A buyer already
    /// counted is let in and its time renewed; a new one is let in, and counted when it has a
    /// session, unless the route serves `max_buyers` already.
    pub fn buyer(&self, route: &Route, session: Option<&str>, now: u64) -> Result<(), Busy> {
        let cap = route.capacity;
        if !cap.is_set() {
            return Ok(());
        }
        let mut all = self.lock();
        let load = all.entry(route.path.clone()).or_default();
        load.prune(now);
        if let Some(s) = session {
            if let Some(last) = load.buyers.get_mut(s) {
                *last = now;
                return Ok(());
            }
        }
        if let Some(max) = cap.max_buyers {
            let in_use = load.buyers.len() as u32;
            if in_use >= max {
                return Err(Busy { scope: Scope::Buyers, in_use, limit: max });
            }
        }
        if let Some(s) = session {
            load.buyers.insert(s.to_string(), now);
        }
        Ok(())
    }

    /// A long answer of `route` for `session` ("" for a free route) about to start: a slot, held
    /// until the slot is dropped, unless a stream limit or the route's rate says no.
    pub fn stream(self: &Arc<Self>, route: &Route, session: &str) -> Result<Slot, Busy> {
        let cap: Capacity = route.capacity;
        if cap.max_streams.is_none() && cap.max_streams_per_buyer.is_none() && cap.max_mbit.is_none() {
            return Ok(Slot { load: None, route: String::new(), session: String::new() });
        }
        let mono = self.mono();
        let mut all = self.lock();
        let load = all.entry(route.path.clone()).or_default();
        load.bytes.retain(|(sec, _)| mono.saturating_sub(*sec) < RATE_WINDOW_S);
        if let Some(max) = cap.max_streams_per_buyer {
            let in_use = load.streams.get(session).copied().unwrap_or(0);
            if !session.is_empty() && in_use >= max {
                return Err(Busy { scope: Scope::BuyerStreams, in_use, limit: max });
            }
        }
        if let Some(max) = cap.max_streams {
            let in_use = load.open();
            if in_use >= max {
                return Err(Busy { scope: Scope::Streams, in_use, limit: max });
            }
        }
        if let Some(max) = cap.max_mbit {
            let in_use = load.mbit();
            if in_use >= max {
                return Err(Busy { scope: Scope::Bandwidth, in_use, limit: max });
            }
        }
        *load.streams.entry(session.to_string()).or_insert(0) += 1;
        Ok(Slot { load: Some(self.clone()), route: route.path.clone(), session: session.to_string() })
    }

    /// `n` bytes of an answer of `route` sent: counted toward its rate.
    pub fn sent(&self, route: &str, n: u64) {
        if n == 0 {
            return;
        }
        let mono = self.mono();
        let mut all = self.lock();
        let Some(load) = all.get_mut(route) else { return };
        match load.bytes.last_mut() {
            Some((sec, b)) if *sec == mono => *b += n,
            _ => load.bytes.push((mono, n)),
        }
    }

    /// What `route` carries now, for the listing and the seller's page.
    pub fn view(&self, route: &Route, now: u64) -> Value {
        let cap = route.capacity;
        let mono = self.mono();
        let mut all = self.lock();
        let load = all.entry(route.path.clone()).or_default();
        load.prune(now);
        load.bytes.retain(|(sec, _)| mono.saturating_sub(*sec) < RATE_WINDOW_S);
        let (buyers, streams, mbit) = (load.buyers.len() as u32, load.open(), load.mbit());
        let full = |n: u32, max: Option<u32>| max.is_some_and(|m| n >= m);
        json!({"buyers": buyers, "maxBuyers": cap.max_buyers, "streams": streams, "maxStreams": cap.max_streams,
               "maxStreamsPerBuyer": cap.max_streams_per_buyer, "mbit": mbit, "maxMbit": cap.max_mbit,
               "busy": full(buyers, cap.max_buyers) || full(streams, cap.max_streams) || full(mbit, cap.max_mbit)})
    }

    fn release(&self, route: &str, session: &str) {
        let mut all = self.lock();
        if let Some(load) = all.get_mut(route) {
            if let Some(n) = load.streams.get_mut(session) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    load.streams.remove(session);
                }
            }
        }
    }
}

/// A long answer's place in its route's `max_streams`: given back when dropped, however the
/// answer ends (finished, the buyer gone, the service stopped).
pub struct Slot {
    load: Option<Arc<Load>>,
    route: String,
    session: String,
}

impl Slot {
    /// `n` bytes of this answer sent.
    pub fn sent(&self, n: u64) {
        if let Some(load) = &self.load {
            load.sent(&self.route, n);
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Some(load) = self.load.take() {
            load.release(&self.route, &self.session);
        }
    }
}

/// Whether an answer, by its headers, is a long one: an event stream, audio or video, or a body
/// longer than [`STREAM_BYTES`] or of no stated length that is not a page's ordinary part.
pub fn is_long(headers: &[(String, String)], length: Option<u64>) -> bool {
    let kind = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-type")).map(|(_, v)| v.to_ascii_lowercase()).unwrap_or_default();
    if kind.starts_with("text/event-stream") || kind.starts_with("video/") || kind.starts_with("audio/") {
        return true;
    }
    match length {
        Some(n) => n > STREAM_BYTES,
        None => !(kind.starts_with("text/") || kind.contains("json") || kind.contains("javascript") || kind.starts_with("image/")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(cap: Capacity) -> Route {
        let mut r = crate::config::parse_route_for_tests("/v/");
        r.capacity = cap;
        r
    }

    #[test]
    fn a_route_full_of_buyers_turns_a_new_one_away_and_keeps_the_ones_it_has() {
        let load = Load::new();
        let r = route(Capacity { max_buyers: Some(2), ..Default::default() });
        assert!(load.buyer(&r, Some("a"), 100).is_ok());
        assert!(load.buyer(&r, Some("b"), 100).is_ok());
        // a new visit asking the price, and a new session, are turned away
        assert_eq!(load.buyer(&r, None, 101), Err(Busy { scope: Scope::Buyers, in_use: 2, limit: 2 }));
        assert_eq!(load.buyer(&r, Some("c"), 101).unwrap_err().scope, Scope::Buyers);
        // the buyers served go on
        assert!(load.buyer(&r, Some("a"), 102).is_ok());
        // a buyer idle past the window frees its place
        assert!(load.buyer(&r, Some("b"), 102).is_ok());
        assert!(load.buyer(&r, Some("c"), 102 + BUYER_IDLE_S + 1).is_ok());
    }

    #[test]
    fn a_buyer_with_a_stream_open_stays_counted_however_long_it_is_quiet() {
        let load = Load::new();
        let r = route(Capacity { max_buyers: Some(1), max_streams: Some(5), ..Default::default() });
        load.buyer(&r, Some("a"), 0).unwrap();
        let slot = load.stream(&r, "a").unwrap();
        assert_eq!(load.buyer(&r, Some("b"), BUYER_IDLE_S * 3).unwrap_err().scope, Scope::Buyers);
        drop(slot);
        assert!(load.buyer(&r, Some("b"), BUYER_IDLE_S * 3).is_ok());
    }

    #[test]
    fn streams_are_counted_over_all_buyers_and_for_each_and_given_back_when_they_end() {
        let load = Load::new();
        let r = route(Capacity { max_streams: Some(3), max_streams_per_buyer: Some(2), ..Default::default() });
        let a1 = load.stream(&r, "a").unwrap();
        let _a2 = load.stream(&r, "a").unwrap();
        assert_eq!(load.stream(&r, "a").err(), Some(Busy { scope: Scope::BuyerStreams, in_use: 2, limit: 2 }));
        let _b1 = load.stream(&r, "b").unwrap();
        assert_eq!(load.stream(&r, "c").err(), Some(Busy { scope: Scope::Streams, in_use: 3, limit: 3 }));
        drop(a1);
        let _c1 = load.stream(&r, "c").unwrap();
        assert_eq!(load.view(&r, 0)["streams"], 3);
    }

    #[test]
    fn a_route_over_its_rate_starts_no_new_long_answer() {
        let load = Load::new();
        let r = route(Capacity { max_mbit: Some(8), ..Default::default() });
        let slot = load.stream(&r, "a").unwrap();
        // 100 MB in the window is 80 Mbit/s over 10 s, over 8
        slot.sent(100_000_000);
        assert_eq!(load.stream(&r, "b").err().map(|b| b.scope), Some(Scope::Bandwidth));
        assert_eq!(load.view(&r, 0)["busy"], true);
    }

    #[test]
    fn a_route_with_no_capacity_counts_nothing_and_refuses_nothing() {
        let load = Load::new();
        let r = route(Capacity::default());
        for i in 0..100 {
            assert!(load.buyer(&r, Some(&format!("s{i}")), 0).is_ok());
            std::mem::forget(load.stream(&r, "x").unwrap());
        }
        assert_eq!(load.view(&r, 0)["busy"], false);
    }

    #[test]
    fn long_answers_are_media_event_streams_and_big_or_open_bodies() {
        let h = |t: &str| vec![("Content-Type".to_string(), t.to_string())];
        assert!(is_long(&h("video/mp4"), Some(1000)));
        assert!(is_long(&h("text/event-stream"), None));
        assert!(is_long(&h("application/octet-stream"), Some(STREAM_BYTES + 1)));
        assert!(is_long(&h("application/octet-stream"), None));
        assert!(!is_long(&h("application/javascript"), Some(500_000)));
        assert!(!is_long(&h("text/html"), None));
        assert!(!is_long(&h("image/png"), None));
        assert!(!is_long(&h("application/json"), Some(STREAM_BYTES)));
    }
}
