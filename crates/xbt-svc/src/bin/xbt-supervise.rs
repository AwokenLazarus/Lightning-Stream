//! `xbt-supervise`: run one program, start it only once the files it needs exist, and start it again
//! when one of them changes. For the images, which have no shell: a setup page writes a config or a
//! macaroon, and the service picks it up without anyone restarting the container.
//!
//!   xbt-supervise [--wait FILE]... [--watch FILE]... [--every SECS] -- PROGRAM [ARGS...]
//!   xbt-supervise probe URL        exit 0 when GET URL (plain http) answers 200: a HEALTHCHECK
//!
//! `--wait`: PROGRAM is not started until FILE is a regular file, and is stopped again if it goes
//! away. `--watch`: a FILE whose content changes (appears, goes away, is rewritten) restarts PROGRAM.
//! Waited files are watched too. Files are compared by content every `--every` seconds (default 2).
//! PROGRAM is stopped with SIGTERM, then SIGKILL after 15 s. SIGTERM or SIGINT to this process stops
//! PROGRAM the same way and exits 0. When PROGRAM exits on its own, this exits with its code, so the
//! platform's restart policy applies.
use std::path::PathBuf;
use std::process::{Child, Command, ExitCode};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

static SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_signal(sig: libc::c_int) {
    SIGNAL.store(sig, Ordering::SeqCst);
}

struct Args {
    wait: Vec<PathBuf>,
    watch: Vec<PathBuf>,
    every: Duration,
    program: Vec<String>,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut a = Args { wait: vec![], watch: vec![], every: Duration::from_secs(2), program: vec![] };
    let mut i = 0;
    while i < args.len() {
        let value = || args.get(i + 1).cloned().ok_or_else(|| format!("{} needs a value", args[i]));
        match args[i].as_str() {
            "--wait" => a.wait.push(PathBuf::from(value()?)),
            "--watch" => a.watch.push(PathBuf::from(value()?)),
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
        return Err("no program: xbt-supervise [--wait FILE]... [--watch FILE]... -- PROGRAM [ARGS...]".into());
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

fn stopped() -> bool {
    SIGNAL.load(Ordering::SeqCst) != 0
}

/// SIGTERM, then SIGKILL after 15 s.
fn stop(child: &mut Child) {
    if let Ok(pid) = libc::pid_t::try_from(child.id()) {
        // SAFETY: kill(2) on our own child's pid; no memory is shared
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(15) {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn supervise(a: Args) -> ExitCode {
    // SAFETY: the handler only stores into an atomic, which is async-signal-safe
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
    }
    let all: Vec<PathBuf> = a.wait.iter().chain(a.watch.iter()).cloned().collect();
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
            if !told {
                say(format!("waiting for {} before starting {}", missing.join(", "), a.program[0]));
                told = true;
            }
            std::thread::sleep(a.every);
        }
        let seen = snapshot(&all);
        let mut child = match Command::new(&a.program[0]).args(&a.program[1..]).spawn() {
            Ok(c) => c,
            Err(e) => {
                say(format!("{}: {e}", a.program[0]));
                return ExitCode::from(127);
            }
        };
        loop {
            std::thread::sleep(a.every);
            if stopped() {
                stop(&mut child);
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
            let now = snapshot(&all);
            if now != seen {
                let changed: Vec<String> =
                    all.iter().zip(now.iter().zip(&seen)).filter(|(_, (n, s))| n != s).map(|(f, _)| f.display().to_string()).collect();
                say(format!("{} changed: restarting {}", changed.join(", "), a.program[0]));
                stop(&mut child);
                break;
            }
        }
    }
}

fn probe(url: &str) -> ExitCode {
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
            println!("usage: xbt-supervise [--wait FILE]... [--watch FILE]... [--every SECS] -- PROGRAM [ARGS...] | probe URL");
            ExitCode::SUCCESS
        }
        Some("probe") => match args.get(1) {
            Some(u) => probe(u),
            None => {
                say("usage: xbt-supervise probe URL");
                ExitCode::from(2)
            }
        },
        _ => match parse(&args) {
            Ok(a) => supervise(a),
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
