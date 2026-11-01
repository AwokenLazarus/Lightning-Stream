//! `xbt-supervise`: run one program, start it only once the files it needs exist, and start it again
//! when one of them changes. For the images, which have no shell: a setup page writes a config or a
//! macaroon, and the service picks it up without anyone restarting the container.
//!
//!   xbt-supervise [--wait FILE]... [--watch FILE]... [--peer HOST:PORT] [--every SECS] -- PROGRAM [ARGS...]
//!   xbt-supervise probe URL [--waiting-for FILE]
//!                                  exit 0 when GET URL (plain http) answers 200: a HEALTHCHECK.
//!                                  With --waiting-for, also 0 while FILE is not there: the program
//!                                  is not started yet by design (a seller with no shop yet), not broken
//!
//! `--wait`: PROGRAM is not started until FILE is a regular file, and is stopped again if it goes
//! away. `--watch`: a FILE whose content changes (appears, goes away, is rewritten) restarts PROGRAM.
//! Waited files are watched too. Files are compared by content every `--every` seconds (default 2).
//! PROGRAM is stopped with SIGTERM, then SIGKILL after 15 s. SIGTERM or SIGINT to this process stops
//! PROGRAM the same way, at once (not at the next look at the files), and exits 0. When PROGRAM
//! exits on its own, this exits with its code, so the platform's restart policy applies.
//!
//! `--peer`: a TCP address of the container whose network namespace this one shares (Docker's
//! `network_mode: service:X`), looked at every `--every` seconds whether or not PROGRAM has started. When
//! that container restarts it gets a new namespace, and this one is left in the old one, where nothing
//! answers. So once the peer has answered, [`PEER_FAILS`] refused looks in a row stop PROGRAM (SIGKILL after
//! [`PEER_GONE_GRACE`], not 15 s: nothing it serves can reach it any more) and exit
//! [`PEER_GONE`]; a peer that never answers within [`PEER_GRACE`] does the same. The restart policy then
//! starts this container again, in the peer's namespace as it is now.
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, ExitCode};
use std::time::{Duration, Instant};

use xbt_svc::shutdown::Signals;

struct Args {
    wait: Vec<PathBuf>,
    watch: Vec<PathBuf>,
    peer: Option<SocketAddr>,
    every: Duration,
    program: Vec<String>,
}

/// Refused looks in a row at a peer that has answered before: its namespace is gone.
const PEER_FAILS: u32 = 3;
/// How long a peer may take to answer for the first time.
const PEER_GRACE: Duration = Duration::from_secs(90);
/// How long one look at the peer may take.
const PEER_LOOK: Duration = Duration::from_secs(1);
/// The exit code when the peer is gone (not PROGRAM's: the restart policy acts on any failure).
const PEER_GONE: u8 = 3;
/// How long PROGRAM has after SIGTERM before SIGKILL.
const STOP_GRACE: Duration = Duration::from_secs(15);
/// The same once the peer is gone: the namespace is dead (nothing PROGRAM serves or talks to is
/// reachable from it), so there is nothing a graceful stop could still save, and every second it takes is
/// a second the peer goes without it.
const PEER_GONE_GRACE: Duration = Duration::from_secs(2);

/// The peer whose network namespace this container shares, as last looked at.
struct Peer {
    addr: SocketAddr,
    since: Instant,
    seen: bool,
    fails: u32,
}

impl Peer {
    fn new(addr: SocketAddr, now: Instant) -> Peer {
        Peer { addr, since: now, seen: false, fails: 0 }
    }

    /// One look's result: why the namespace is gone, or `None` while it may still be there.
    fn note(&mut self, answered: bool, now: Instant) -> Option<String> {
        if answered {
            self.seen = true;
            self.fails = 0;
            return None;
        }
        self.fails += 1;
        if self.seen && self.fails >= PEER_FAILS {
            Some(format!("{} stopped answering ({} looks in a row): its network namespace is gone", self.addr, self.fails))
        } else if !self.seen && now.duration_since(self.since) >= PEER_GRACE {
            Some(format!("{} has not answered in {} s: this is not its network namespace", self.addr, PEER_GRACE.as_secs()))
        } else {
            None
        }
    }

    fn look(&mut self) -> Option<String> {
        let answered = TcpStream::connect_timeout(&self.addr, PEER_LOOK).is_ok();
        self.note(answered, Instant::now())
    }
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut a = Args { wait: vec![], watch: vec![], peer: None, every: Duration::from_secs(2), program: vec![] };
    let mut i = 0;
    while i < args.len() {
        let value = || args.get(i + 1).cloned().ok_or_else(|| format!("{} needs a value", args[i]));
        match args[i].as_str() {
            "--wait" => a.wait.push(PathBuf::from(value()?)),
            "--watch" => a.watch.push(PathBuf::from(value()?)),
            "--peer" => a.peer = Some(value()?.parse().map_err(|_| "--peer is an IP address and a port (127.0.0.1:23343)")?),
            "--every" => {
                let s: f64 = value()?.parse().map_err(|_| "--every is a number of seconds")?;
                if !(0.05..=3600.0).contains(&s) {
                    return Err("--every is from 0.05 to 3600 seconds".into());
                }
                a.every = Duration::from_secs_f64(s);
            }
            "--" => {
                a.program = args[i + 1..].to_vec();
                break;
            }
            o => return Err(format!("unknown argument {o}")),
        }
        i += 2;
    }
    if a.program.is_empty() {
        return Err("no program: xbt-supervise [--wait FILE]... [--watch FILE]... [--peer HOST:PORT] -- PROGRAM [ARGS...]".into());
    }
    Ok(a)
}

/// What every file holds now (`None`: not a regular file).
fn snapshot(files: &[PathBuf]) -> Vec<Option<Vec<u8>>> {
    files
        .iter()
        .map(|f| match std::fs::metadata(f) {
            Ok(m) if m.is_file() => std::fs::read(f).ok(),
            _ => None,
        })
        .collect()
}

fn say(msg: impl std::fmt::Display) {
    eprintln!("xbt-supervise: {msg}");
}

/// SIGTERM, then SIGKILL after `grace`.
fn stop(child: &mut Child, grace: Duration) {
    if let Ok(pid) = libc::pid_t::try_from(child.id()) {
        // SAFETY: kill(2) on our own child's pid; no memory is shared
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
    let t0 = Instant::now();
    while t0.elapsed() < grace {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn supervise(a: Args, signals: Signals) -> ExitCode {
    let stopped = || signals.received().is_some();
    let all: Vec<PathBuf> = a.wait.iter().chain(a.watch.iter()).cloned().collect();
    let mut peer = a.peer.map(|p| Peer::new(p, Instant::now()));
    let mut peer_gone = || peer.as_mut().and_then(Peer::look);
    loop {
        // wait for every --wait file
        let mut told = false;
        loop {
            if stopped() {
                return ExitCode::SUCCESS;
            }
            let missing: Vec<String> = a.wait.iter().filter(|f| !f.is_file()).map(|f| f.display().to_string()).collect();
            if missing.is_empty() {
                break;
            }
            if let Some(why) = peer_gone() {
                say(why);
                return ExitCode::from(PEER_GONE);
            }
            if !told {
                say(format!("waiting for {} before starting {}", missing.join(", "), a.program[0]));
                told = true;
            }
            signals.wait_timeout(a.every);
        }
        let seen = snapshot(&all);
        // the child gets SIGTERM and SIGINT back: listen() blocked them here, and a child inherits the
        // mask, so a program with no handler of its own (the Stream Gateway) would outlive every stop
        let mut child = match xbt_svc::shutdown::unblocked(Command::new(&a.program[0]).args(&a.program[1..])).spawn() {
            Ok(c) => c,
            Err(e) => {
                say(format!("{}: {e}", a.program[0]));
                return ExitCode::from(127);
            }
        };
        loop {
            // a stop signal cuts the wait short; so does the child's own exit, at the next look
            signals.wait_timeout(a.every);
            if stopped() {
                stop(&mut child, STOP_GRACE);
                return ExitCode::SUCCESS;
            }
            match child.try_wait() {
                Ok(Some(st)) => {
                    let code = st.code().unwrap_or(1);
                    say(format!("{} exited ({st})", a.program[0]));
                    return ExitCode::from(u8::try_from(code).unwrap_or(1));
                }
                Ok(None) => {}
                Err(e) => {
                    say(format!("{}: {e}", a.program[0]));
                    return ExitCode::from(1);
                }
            }
            if let Some(why) = peer_gone() {
                say(format!("{why}: stopping {}", a.program[0]));
                stop(&mut child, PEER_GONE_GRACE);
                return ExitCode::from(PEER_GONE);
            }
            let now = snapshot(&all);
            if now != seen {
                let changed: Vec<String> =
                    all.iter().zip(now.iter().zip(&seen)).filter(|(_, (n, s))| n != s).map(|(f, _)| f.display().to_string()).collect();
                say(format!("{} changed: restarting {}", changed.join(", "), a.program[0]));
                stop(&mut child, STOP_GRACE);
                break;
            }
        }
    }
}

fn probe(url: &str, waiting_for: Option<&str>) -> ExitCode {
    if let Some(f) = waiting_for {
        if !std::path::Path::new(f).is_file() {
            return ExitCode::SUCCESS;
        }
    }
    let Some(rest) = url.strip_prefix("http://") else {
        say("probe: only http:// URLs");
        return ExitCode::from(2);
    };
    let (host, path) = rest.find('/').map(|i| (&rest[..i], &rest[i..])).unwrap_or((rest, "/"));
    match xbt_svc::probe::get(host, path, Duration::from_secs(5)) {
        Ok((200, _)) => ExitCode::SUCCESS,
        Ok((code, body)) => {
            say(format!("probe {url}: {code} {}", body.trim()));
            ExitCode::from(1)
        }
        Err(e) => {
            say(format!("probe {url}: {e}"));
            ExitCode::from(1)
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("-h" | "--help") => {
            println!("usage: xbt-supervise [--wait FILE]... [--watch FILE]... [--peer HOST:PORT] [--every SECS] -- PROGRAM [ARGS...] | probe URL [--waiting-for FILE]");
            ExitCode::SUCCESS
        }
        Some("probe") => match (args.get(1), args.get(2).map(String::as_str), args.get(3)) {
            (Some(u), None, _) => probe(u, None),
            (Some(u), Some("--waiting-for"), Some(f)) if args.len() == 4 => probe(u, Some(f)),
            _ => {
                say("usage: xbt-supervise probe URL [--waiting-for FILE]");
                ExitCode::from(2)
            }
        },
        _ => match parse(&args) {
            // the signals before any thread or child exists (xbt_svc::shutdown)
            Ok(a) => match xbt_svc::shutdown::listen() {
                Ok(signals) => supervise(a, signals),
                Err(e) => {
                    say(format!("signals: {e}"));
                    ExitCode::from(1)
                }
            },
            Err(e) => {
                say(e);
                ExitCode::from(2)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parses_files_and_program() {
        let a = parse(&s(&["--wait", "/a", "--watch", "/b", "--every", "0.5", "--", "/bin/x", "--flag", "y"])).unwrap();
        assert_eq!(a.wait, vec![PathBuf::from("/a")]);
        assert_eq!(a.watch, vec![PathBuf::from("/b")]);
        assert_eq!(a.every, Duration::from_millis(500));
        assert_eq!(a.program, s(&["/bin/x", "--flag", "y"]));
        assert!(parse(&s(&["--wait", "/a"])).is_err());
        assert!(parse(&s(&["--every", "0", "--", "x"])).is_err());
        assert!(parse(&s(&["--nope", "1", "--", "x"])).is_err());
        assert_eq!(a.peer, None);
        let p = parse(&s(&["--peer", "127.0.0.1:23343", "--", "/bin/x"])).unwrap();
        assert_eq!(p.peer, Some("127.0.0.1:23343".parse().unwrap()));
        assert!(parse(&s(&["--peer", "renter:23343", "--", "x"])).is_err(), "an address, not a name: a name needs a resolver");
    }

    #[test]
    fn a_peer_that_answered_and_stops_is_gone_after_three_refusals() {
        let t0 = Instant::now();
        let mut p = Peer::new("127.0.0.1:9".parse().unwrap(), t0);
        assert_eq!(p.note(true, t0), None);
        assert_eq!(p.note(false, t0), None);
        assert_eq!(p.note(false, t0), None);
        // one answer between refusals starts the count again
        assert_eq!(p.note(true, t0), None);
        assert_eq!(p.note(false, t0), None);
        assert_eq!(p.note(false, t0), None);
        assert!(p.note(false, t0).is_some_and(|w| w.contains("stopped answering")));
    }

    #[test]
    fn a_peer_that_never_answers_is_given_its_grace() {
        let t0 = Instant::now();
        let mut p = Peer::new("127.0.0.1:9".parse().unwrap(), t0);
        for _ in 0..20 {
            assert_eq!(p.note(false, t0 + Duration::from_secs(10)), None, "a slow start is not a gone namespace");
        }
        assert!(p.note(false, t0 + PEER_GRACE).is_some_and(|w| w.contains("has not answered")));
    }

    /// A supervised program with no SIGTERM handler of its own (sh running sleep, as the Stream Gateway
    /// has none) stops at the stop, not at the SIGKILL 15 s later: with SIGTERM and SIGINT blocked in
    /// this thread as listen() blocks them in the real supervisor.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_program_with_no_handler_stops_at_sigterm_not_at_the_kill() {
        std::thread::spawn(|| {
            // SAFETY: blocks SIGTERM and SIGINT in this thread only, as listen() does
            unsafe {
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGTERM);
                libc::sigaddset(&mut set, libc::SIGINT);
                assert_eq!(libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()), 0);
            }
            let signals = Signals::none();
            let s2 = signals.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(800));
                s2.raise(libc::SIGTERM);
            });
            let a = parse(&s(&["--every", "0.1", "--", "/bin/sh", "-c", "sleep 60"])).unwrap();
            let t0 = Instant::now();
            let _ = supervise(a, signals);
            assert!(t0.elapsed() < Duration::from_secs(5), "stopped after {:?}: the program never saw SIGTERM", t0.elapsed());
        })
        .join()
        .unwrap();
    }

    #[test]
    fn a_real_peer_is_looked_at() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let mut p = Peer::new(addr, Instant::now());
        assert_eq!(p.look(), None);
        assert!(p.seen);
        drop(l);
        assert_eq!(p.look(), None);
        assert_eq!(p.look(), None);
        assert!(p.look().is_some(), "three refusals once its listener is gone");
    }

    /// The whole program: a peer that goes away stops PROGRAM and exits PEER_GONE, waiting for its files or not.
    #[test]
    fn supervise_exits_when_the_peer_goes_away() {
        let t = tempfile::tempdir().unwrap();
        let marker = t.path().join("started");
        for waiting in [false, true] {
            let _ = std::fs::remove_file(&marker);
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap();
            let script = format!("touch {}; exec sleep 60", marker.display());
            let mut args = vec!["--peer".to_string(), addr.to_string(), "--every".into(), "0.1".into()];
            if waiting {
                args.extend(["--wait".into(), t.path().join("never").display().to_string()]);
            }
            args.extend(["--".into(), "/bin/sh".into(), "-c".into(), script]);
            let a = parse(&args).unwrap();
            let signals = xbt_svc::shutdown::listen().unwrap();
            let h = std::thread::spawn(move || supervise(a, signals));
            // the peer answers for a while, then its listener is gone
            let t0 = Instant::now();
            while t0.elapsed() < Duration::from_millis(600) {
                accept_now(&l);
            }
            drop(l);
            let code = h.join().unwrap();
            assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(PEER_GONE)), "waiting={waiting}");
            assert_eq!(marker.exists(), !waiting, "the program ran only when nothing was waited for");
        }
    }

    /// A program that outlives SIGTERM is killed soon after the peer is gone, not after the usual 15 s.
    #[test]
    fn a_program_that_ignores_sigterm_is_killed_soon_once_the_peer_is_gone() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let args = s(&["--peer", &addr.to_string(), "--every", "0.1", "--", "/bin/sh", "-c", "trap '' TERM; while :; do sleep 0.1; done"]);
        let a = parse(&args).unwrap();
        let signals = xbt_svc::shutdown::listen().unwrap();
        let h = std::thread::spawn(move || supervise(a, signals));
        std::thread::sleep(Duration::from_millis(500));
        drop(l);
        let t0 = Instant::now();
        let code = h.join().unwrap();
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(PEER_GONE)));
        assert!(t0.elapsed() < PEER_GONE_GRACE + Duration::from_secs(3), "took {:?}", t0.elapsed());
    }

    /// A listener's accept that gives up at once (std has no accept with a deadline).
    fn accept_now(l: &std::net::TcpListener) {
        l.set_nonblocking(true).unwrap();
        if l.accept().is_err() {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn snapshot_sees_content() {
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("c");
        let files = vec![f.clone()];
        assert_eq!(snapshot(&files), vec![None]);
        std::fs::write(&f, b"one").unwrap();
        let a = snapshot(&files);
        std::fs::write(&f, b"two").unwrap();
        assert_ne!(a, snapshot(&files));
        std::fs::create_dir(t.path().join("d")).unwrap();
        assert_eq!(snapshot(&[t.path().join("d")]), vec![None]);
    }
}
