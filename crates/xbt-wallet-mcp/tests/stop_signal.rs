//! The shipped binary stops on SIGTERM over HTTP, as a container stop sends it: exit 0 at once,
//! not after Docker's grace period (as PID 1 it used to ignore SIGTERM, having no handler).
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

#[test]
fn the_mcp_over_http_exits_0_on_sigterm() {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = Command::new(env!("CARGO_BIN_EXE_xbt-wallet-mcp")).env_clear().env("B2_SIGNER_SOCK", "/nonexistent/signer.sock")
        .env("XBT_MCP_HTTP_TOKEN", "t0ken").args(["--http", &addr]).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    wait_200(&addr, "/healthz");
    let (st, took) = term_and_wait(&mut child);
    let mut said = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut said).unwrap();
    assert!(st.success() && took < std::time::Duration::from_secs(2), "exit {st:?} after {took:?}: {said}");
    assert!(said.contains("SIGTERM received") && said.contains("xbt-wallet-mcp: stopped"), "{said}");
}
