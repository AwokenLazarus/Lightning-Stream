//! The shipped binary stops on SIGTERM, as a container stop sends it: exit 0 at once, not after
//! Docker's grace period (as PID 1 it used to ignore SIGTERM, having no handler).
#![cfg(unix)]
use std::process::{Command, Stdio};

fn term_and_wait(child: &mut std::process::Child) -> (std::process::ExitStatus, std::time::Duration) {
    assert!(std::process::Command::new("kill").args(["-TERM", &child.id().to_string()]).status().unwrap().success());
    let t0 = std::time::Instant::now();
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            return (st, t0.elapsed());
        }
        if t0.elapsed() > std::time::Duration::from_secs(9) {
            let _ = child.kill();
            panic!("still running 9 s after SIGTERM");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// GET `path` on `addr` until it answers 200.
fn wait_200(addr: &str, path: &str) {
    let t0 = std::time::Instant::now();
    loop {
        if let Ok((200, _)) = xbt_svc::probe::get(addr, path, std::time::Duration::from_secs(2)) {
            return;
        }
        assert!(t0.elapsed() < std::time::Duration::from_secs(20), "{addr}{path} never answered 200");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// The address a child says it listens on: the first `marker` in what it writes, up to a space.
fn said_addr(r: impl std::io::Read, marker: &str) -> String {
    use std::io::BufRead;
    for line in std::io::BufReader::new(r).lines() {
        let line = line.unwrap();
        if let Some(rest) = line.split(marker).nth(1) {
            return rest.split([' ', '/', ',']).next().unwrap().to_string();
        }
    }
    panic!("it never said {marker}");
}

#[test]
fn the_ui_exits_0_on_sigterm() {
    let d = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_xbt-wallet-ui")).env_clear().env("XBT_UI_BIND", "127.0.0.1:0")
        .env("XBT_UI_DATA_DIR", d.path()).env("XBT_UI_SIGNER_SOCK", d.path().join("none.sock"))
        .stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let mut err = child.stderr.take().unwrap();
    let addr = said_addr(&mut err, "listening on http://");
    wait_200(&addr, "/healthz");
    let (st, took) = term_and_wait(&mut child);
    let mut said = String::new();
    std::io::Read::read_to_string(&mut err, &mut said).unwrap();
    assert!(st.success() && took < std::time::Duration::from_secs(2), "exit {st:?} after {took:?}: {said}");
    assert!(said.contains("SIGTERM received") && said.contains("xbt-wallet-ui: stopped"), "{said}");
}
