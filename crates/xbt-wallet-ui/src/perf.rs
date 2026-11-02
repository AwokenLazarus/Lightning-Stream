//! Page speed plumbing: what one request spent and where, and the snapshots that keep slow work off
//! the request path.
//!
//! * [`Request`]: set by the server around each request. It numbers the request (the signer link's
//!   per-request memo, [`crate::link`]), says whether it is a GET (only a GET reads from a cache), and
//!   adds up the time spent waiting on the signer and on other services. The server sends that as a
//!   `Server-Timing` header and logs a request slower than `XBT_UI_SLOW_MS` (default 1000 ms).
//! * [`Swr`]: a snapshot served at once, made again in the background once it is older than its
//!   freshness ("stale while revalidate"). Only the first request, when there is no snapshot yet,
//!   waits for it, and only for a bounded time.
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// What one request spent waiting, by kind.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Spent {
    pub signer_calls: u32,
    /// Signer reads answered from the cache, without a call.
    pub signer_cached: u32,
    pub signer: Duration,
    /// Calls to other services: the connector, the gateway, the hashrate services, sellers, Nostr relays.
    pub upstream_calls: u32,
    pub upstream: Duration,
}

#[derive(Debug, Clone)]
struct Current {
    id: u64,
    get: bool,
    spent: Arc<Mutex<Spent>>,
}

thread_local! {
    static CURRENT: RefCell<Option<Current>> = const { RefCell::new(None) };
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// The request this thread is serving, while it is alive.
pub struct Request {
    started: Instant,
    spent: Arc<Mutex<Spent>>,
}

impl Request {
    /// Begin a request on this thread: `get` for a GET or HEAD (a request that changes nothing).
    pub fn begin(get: bool) -> Self {
        let spent = Arc::new(Mutex::new(Spent::default()));
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        CURRENT.with(|c| *c.borrow_mut() = Some(Current { id, get, spent: spent.clone() }));
        Self { started: Instant::now(), spent }
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    pub fn spent(&self) -> Spent {
        self.spent.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// The `Server-Timing` header's value: the whole request, the signer and the other services.
    pub fn server_timing(&self) -> String {
        let s = self.spent();
        let ms = |d: Duration| d.as_secs_f64() * 1000.0;
        format!("app;dur={:.1}, signer;dur={:.1};desc=\"{} calls, {} cached\", upstream;dur={:.1};desc=\"{} calls\"",
                ms(self.elapsed()), ms(s.signer), s.signer_calls, s.signer_cached, ms(s.upstream), s.upstream_calls)
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        CURRENT.with(|c| *c.borrow_mut() = None);
    }
}

/// The request this thread serves: its number, and whether it is a GET. `None` off a request
/// (a background refresh, the files server) or in a thread a request spawned without [`carry`].
pub fn current() -> Option<(u64, bool)> {
    CURRENT.with(|c| c.borrow().as_ref().map(|c| (c.id, c.get)))
}

/// Count a signer call (`cached`: answered without one) that took `d`.
pub fn signer(d: Duration, cached: bool) {
    with_spent(|s| {
        if cached {
            s.signer_cached += 1;
        } else {
            s.signer_calls += 1;
            s.signer += d;
        }
    });
}

/// Count a call to another service that took `d`.
pub fn upstream(d: Duration) {
    with_spent(|s| {
        s.upstream_calls += 1;
        s.upstream += d;
    });
}

/// Time `f` as a call to another service.
pub fn timed<T>(f: impl FnOnce() -> T) -> T {
    let t = Instant::now();
    let r = f();
    upstream(t.elapsed());
    r
}

/// Counts the call to another service it is made for when it goes out of scope.
pub struct Upstream(Instant);

impl Upstream {
    pub fn start() -> Self {
        Self(Instant::now())
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        upstream(self.0.elapsed());
    }
}

fn with_spent(f: impl FnOnce(&mut Spent)) {
    CURRENT.with(|c| {
        if let Some(c) = c.borrow().as_ref() {
            f(&mut c.spent.lock().unwrap_or_else(|p| p.into_inner()));
        }
    });
}

/// The current request, to run part of it on another thread: `carry()` on the request's thread,
/// then `.enter()` on the other one. Its time and its cache reads count as the request's.
#[derive(Clone)]
pub struct Carried(Option<Current>);

pub fn carry() -> Carried {
    Carried(CURRENT.with(|c| c.borrow().clone()))
}

impl Carried {
    pub fn enter<T>(self, f: impl FnOnce() -> T) -> T {
        let before = CURRENT.with(|c| std::mem::replace(&mut *c.borrow_mut(), self.0));
        let r = f();
        CURRENT.with(|c| *c.borrow_mut() = before);
        r
    }
}

/// Run `a` and `b` at once, as parts of the current request; both answers.
pub fn both<A: Send, B: Send>(a: impl FnOnce() -> A + Send, b: impl FnOnce() -> B + Send) -> (A, B) {
    let (ca, cb) = (carry(), carry());
    std::thread::scope(|s| {
        let hb = s.spawn(move || cb.enter(b));
        let ra = ca.enter(a);
        (ra, hb.join().unwrap_or_else(|p| std::panic::resume_unwind(p)))
    })
}

/// The slowest a request may be before the server logs it (`XBT_UI_SLOW_MS`, default 1000 ms).
pub fn slow_limit() -> Duration {
    static MS: std::sync::LazyLock<u64> = std::sync::LazyLock::new(|| {
        std::env::var("XBT_UI_SLOW_MS").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(1000)
    });
    Duration::from_millis(*MS)
}

// --- stale while revalidate ---------------------------------------------------------------------

struct SwrState<T> {
    value: Option<(Instant, T)>,
    busy: bool,
    /// Bumped by [`Swr::forget`]: a snapshot begun before it is not kept.
    generation: u64,
    /// How many times the snapshot was made (tests read it).
    made: u64,
}

/// A snapshot that is served at once and made again in the background when it is older than
/// `fresh`. Clones share it.
pub struct Swr<T> {
    inner: Arc<(Mutex<SwrState<T>>, Condvar)>,
}

impl<T> Clone for Swr<T> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl<T> Default for Swr<T> {
    fn default() -> Self {
        Self { inner: Arc::new((Mutex::new(SwrState { value: None, busy: false, generation: 0, made: 0 }), Condvar::new())) }
    }
}

impl<T: Clone + Send + 'static> Swr<T> {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SwrState<T>> {
        self.inner.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The last snapshot and when it was made, without making one.
    pub fn peek(&self) -> Option<(Instant, T)> {
        self.lock().value.clone()
    }

    /// How many snapshots were made.
    pub fn made(&self) -> u64 {
        self.lock().made
    }

    /// The snapshot at once. One older than `fresh` is made again in the background; with none yet,
    /// one is started and waited for, at most `wait` (`None`: not ready by then).
    pub fn get(&self, fresh: Duration, wait: Duration, make: impl FnOnce() -> T + Send + 'static) -> Option<T> {
        let mut g = self.lock();
        let stale = g.value.as_ref().is_none_or(|(at, _)| at.elapsed() >= fresh);
        if stale && !g.busy {
            g.busy = true;
            let (me, generation) = (self.clone(), g.generation);
            std::thread::spawn(move || me.store(make(), generation));
        }
        if let Some((_, v)) = &g.value {
            return Some(v.clone());
        }
        let deadline = Instant::now() + wait;
        while g.value.is_none() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            g = self.inner.1.wait_timeout(g, left).unwrap_or_else(|p| p.into_inner()).0;
        }
        g.value.as_ref().map(|(_, v)| v.clone())
    }

    /// Make the snapshot now, on this thread (the owner asked to look again), and keep it.
    pub fn refresh(&self, make: impl FnOnce() -> T) -> T {
        let v = make();
        let mut g = self.lock();
        g.value = Some((Instant::now(), v.clone()));
        g.made += 1;
        self.inner.1.notify_all();
        v
    }

    /// Forget the snapshot's age: the next [`Self::get`] makes it again (in the background, still
    /// serving this one).
    pub fn expire(&self) {
        if let Some((at, _)) = self.lock().value.as_mut() {
            *at = Instant::now().checked_sub(Duration::from_secs(86_400 * 365)).unwrap_or(*at);
        }
    }

    /// Drop the snapshot: the next [`Self::get`] waits for a new one (after an action that changed it).
    pub fn forget(&self) {
        let mut g = self.lock();
        g.value = None;
        g.generation += 1;
    }

    fn store(&self, v: T, generation: u64) {
        let mut g = self.lock();
        g.busy = false;
        g.made += 1;
        if g.generation == generation {
            g.value = Some((Instant::now(), v));
        }
        self.inner.1.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn a_stale_snapshot_is_served_at_once_and_made_again_in_the_background() {
        let s: Swr<usize> = Swr::new();
        let n = Arc::new(AtomicUsize::new(0));
        let slow = |n: Arc<AtomicUsize>| move || {
            std::thread::sleep(Duration::from_millis(300));
            n.fetch_add(1, Ordering::SeqCst) + 1
        };
        // the first: nothing to serve, so it waits for the first snapshot
        assert_eq!(s.get(Duration::from_secs(60), Duration::from_secs(5), slow(n.clone())), Some(1));
        // fresh: served, nothing asked
        let t = Instant::now();
        assert_eq!(s.get(Duration::from_secs(60), Duration::from_secs(5), slow(n.clone())), Some(1));
        assert!(t.elapsed() < Duration::from_millis(100));
        assert_eq!(n.load(Ordering::SeqCst), 1);
        // stale: the old one at once, a new one made behind it
        s.expire();
        let t = Instant::now();
        assert_eq!(s.get(Duration::from_secs(60), Duration::from_secs(5), slow(n.clone())), Some(1));
        assert!(t.elapsed() < Duration::from_millis(100), "a stale snapshot does not wait: {:?}", t.elapsed());
        // asked again while it is being made: still the old one, and no second maker
        assert_eq!(s.get(Duration::ZERO, Duration::from_secs(5), slow(n.clone())), Some(1));
        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(n.load(Ordering::SeqCst), 2, "one refresh in the background");
        assert_eq!(s.get(Duration::from_secs(60), Duration::from_secs(5), slow(n.clone())), Some(2));
    }

    #[test]
    fn the_first_wait_is_bounded() {
        let s: Swr<u8> = Swr::new();
        let t = Instant::now();
        assert_eq!(s.get(Duration::from_secs(60), Duration::from_millis(100), || { std::thread::sleep(Duration::from_millis(500)); 7 }), None);
        assert!(t.elapsed() < Duration::from_millis(400));
        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(s.get(Duration::from_secs(60), Duration::ZERO, || 8), Some(7), "the one started is kept");
        assert_eq!(s.made(), 1);
    }

    #[test]
    fn a_request_adds_up_what_it_waited_for_even_on_other_threads() {
        let r = Request::begin(true);
        signer(Duration::from_millis(5), false);
        signer(Duration::ZERO, true);
        let (a, b) = both(|| { upstream(Duration::from_millis(7)); 1 }, || { upstream(Duration::from_millis(9)); 2 });
        assert_eq!((a, b), (1, 2));
        assert!(current().is_some(), "the request is still this thread's after `both`");
        let s = r.spent();
        assert_eq!((s.signer_calls, s.signer_cached, s.upstream_calls), (1, 1, 2));
        assert_eq!(s.upstream, Duration::from_millis(16));
        assert!(r.server_timing().contains("signer;dur=5.0;desc=\"1 calls, 1 cached\""), "{}", r.server_timing());
        drop(r);
        assert!(current().is_none());
    }
}
