//! Stopping on SIGTERM and SIGINT. A service that runs as PID 1 in its container has no default
//! action for either signal (the kernel drops a signal that PID 1 has no handler for), so without
//! this a `docker stop` waits out its grace period and kills it.
//!
//! [`listen`] blocks both signals in the calling thread, and so in every thread started after it,
//! and starts one thread that takes them with `sigwait(3)`: the signal arrives as a value in
//! ordinary code, with no handler and nothing that must be async-signal-safe. A service calls it
//! before it starts any thread of its own: a thread started earlier keeps both signals unblocked,
//! and one delivered to it is dropped (PID 1) or ends the process without a word (anyone else).
//! A child started with `std::process::Command` gets an empty mask back (std resets it).
//!
//! What a service does when told: it takes no new work, gives the work in flight [`DRAIN`] to
//! finish, flushes what it owns and exits 0. Work still running after that is abandoned as a kill
//! would abandon it, which every service here already survives: each one writes a record durably
//! before it answers for it, so a stop needs nothing more than that.
//!
//! `unsafe`: std has no signal API, so the four calls (`sigemptyset`, `sigaddset`,
//! `pthread_sigmask`, `sigwait`) go through `libc`, already a dependency. Each is a plain call on
//! a `sigset_t` this module owns; no handler runs, no memory is shared with one.
use std::io;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// How long a stopping service waits for its work in flight: well inside Docker's default grace
/// period of 10 s, and inside `xbt-supervise`'s 15 s.
pub const DRAIN: Duration = Duration::from_secs(5);

/// The stop signal, once one has arrived.
#[derive(Clone, Debug, Default)]
pub struct Signals(Arc<(Mutex<Option<i32>>, Condvar)>);

impl Signals {
    /// A `Signals` no signal reaches: for tests, and for a caller that stops some other way.
    pub fn none() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<i32>> {
        self.0 .0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The signal that arrived, if one has.
    pub fn received(&self) -> Option<i32> {
        *self.lock()
    }

    /// Wait for a signal.
    pub fn wait(&self) -> i32 {
        let mut got = self.lock();
        loop {
            if let Some(s) = *got {
                return s;
            }
            got = self.0 .1.wait(got).unwrap_or_else(|p| p.into_inner());
        }
    }

    /// Wait at most `d` for a signal: a sleep that a stop cuts short.
    pub fn wait_timeout(&self, d: Duration) -> Option<i32> {
        let end = Instant::now() + d;
        let mut got = self.lock();
        loop {
            if got.is_some() {
                return *got;
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            got = self.0 .1.wait_timeout(got, left).unwrap_or_else(|p| p.into_inner()).0;
        }
    }

    /// Record `sig` as received (what the signal thread does; tests call it too).
    pub fn raise(&self, sig: i32) {
        let mut got = self.lock();
        if got.is_none() {
            *got = Some(sig);
        }
        drop(got);
        self.0 .1.notify_all();
    }
}

/// `SIGTERM`, `SIGINT`, or the number.
pub fn name(sig: i32) -> String {
    #[cfg(unix)]
    {
        if sig == libc::SIGTERM {
            return "SIGTERM".into();
        }
        if sig == libc::SIGINT {
            return "SIGINT".into();
        }
    }
    format!("signal {sig}")
}

#[cfg(unix)]
fn stop_set() -> libc::sigset_t {
    // SAFETY: sigset_t is plain data; sigemptyset initialises it before sigaddset adds to it, and
    // both only write the set they are given
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        set
    }
}

/// Take SIGTERM and SIGINT from here on (module docs). Call it before the process starts a thread.
#[cfg(unix)]
pub fn listen() -> io::Result<Signals> {
    let set = stop_set();
    // SAFETY: blocks the two signals in this thread's mask; `set` is initialised, the old mask is not asked for
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    let s = Signals::default();
    let t = s.clone();
    std::thread::Builder::new().name("signals".into()).spawn(move || loop {
        let mut sig: libc::c_int = 0;
        // SAFETY: sigwait reads `set` and writes `sig`, both alive for the whole call
        let rc = unsafe { libc::sigwait(&set, &mut sig) };
        if rc != 0 {
            // EINVAL only, which these two signals cannot give: stop waiting rather than spin
            eprintln!("sigwait: {}", io::Error::from_raw_os_error(rc));
            return;
        }
        t.raise(sig);
    })?;
    Ok(s)
}

/// Elsewhere there is no SIGTERM: a `Signals` that never fires.
#[cfg(not(unix))]
pub fn listen() -> io::Result<Signals> {
    Ok(Signals::none())
}

/// Work in flight, for a service whose requests are not HTTP connections (the signer's and the
/// witness's sockets, where one connection carries many requests): [`Drain::enter`] for each
/// request, [`Drain::finish`] at a stop.
#[derive(Debug, Default)]
pub struct Drain {
    /// (requests running, stopping)
    state: Mutex<(usize, bool)>,
    idle: Condvar,
}

/// One request in flight: it counts until dropped.
pub struct Busy<'a>(&'a Drain);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        let mut s = self.0.state.lock().unwrap_or_else(|p| p.into_inner());
        s.0 -= 1;
        drop(s);
        self.0.idle.notify_all();
    }
}

impl Drain {
    /// Count one request in, unless the service is stopping (`None`: refuse it).
    pub fn enter(&self) -> Option<Busy<'_>> {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if s.1 {
            return None;
        }
        s.0 += 1;
        Some(Busy(self))
    }

    pub fn stopping(&self) -> bool {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).1
    }

    /// Take no more requests, and wait at most `bound` for the ones running. True: none is left.
    pub fn finish(&self, bound: Duration) -> bool {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        s.1 = true;
        let end = Instant::now() + bound;
        while s.0 > 0 {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            s = self.idle.wait_timeout(s, left).unwrap_or_else(|p| p.into_inner()).0;
        }
        true
    }
}

/// What a stopping service says, in one place: the signal, then whether its work in flight ended.
pub fn say_stopping(service: &str, sig: i32) {
    eprintln!("{service}: {} received: stopping (work in flight gets {} s)", name(sig), DRAIN.as_secs());
}

pub fn say_stopped(service: &str, drained: bool) {
    if drained {
        eprintln!("{service}: stopped");
    } else {
        eprintln!("{service}: stopped; work still in flight after {} s was abandoned", DRAIN.as_secs());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_drain_waits_for_its_requests_and_refuses_new_ones() {
        let d = Drain::default();
        std::thread::scope(|sc| {
            let busy = d.enter().unwrap();
            sc.spawn(move || {
                std::thread::sleep(Duration::from_millis(150));
                drop(busy);
            });
            let t0 = Instant::now();
            assert!(d.finish(Duration::from_secs(5)));
            assert!(t0.elapsed() >= Duration::from_millis(100), "it waited for the one in flight");
            assert!(d.enter().is_none() && d.stopping());
        });
        // one that never ends is abandoned at the bound
        let e = Drain::default();
        let _held = e.enter().unwrap();
        let t0 = Instant::now();
        assert!(!e.finish(Duration::from_millis(100)));
        assert!(t0.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn a_raised_signal_ends_a_wait() {
        let s = Signals::none();
        assert_eq!(s.wait_timeout(Duration::from_millis(20)), None);
        let s2 = s.clone();
        let t = std::thread::spawn(move || s2.wait());
        s.raise(15);
        s.raise(2);
        assert_eq!(t.join().unwrap(), 15, "the first signal is the one kept");
        assert_eq!(s.received(), Some(15));
    }
}
