//! The binary over HTTP on a port the OS picks: tests run side by side (several suites on one machine,
//! as CI runs them), so no test names a port, and none takes for its own whatever answers on one.
#![allow(dead_code)]
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// What the binary's listener says it is on, once it is bound (`streamable HTTP on http://<host>:<port>`).
const ON: &str = "streamable HTTP on http://";

/// Starts `cmd` (given `--http 127.0.0.1:0` or `XBT_MCP_HTTP=...:0`) with its stderr read here, and waits for the
/// port its listener was given. The stderr goes on being read into the second value, to the binary's end.
pub fn spawn_on_own_port(mut cmd: Command) -> (Child, u16, Arc<Mutex<String>>) {
    let mut child = cmd.stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let said = Arc::new(Mutex::new(String::new()));
    let (tx, rx) = std::sync::mpsc::channel();
    let err = child.stderr.take().unwrap();
    let s2 = said.clone();
    std::thread::spawn(move || {
        for line in BufReader::new(err).lines().map_while(Result::ok) {
            if let Some(port) = line.split_once(ON).and_then(|(_, at)| at.split(['/', ' ']).next()).and_then(|hp| hp.rsplit_once(':')).and_then(|(_, p)| p.parse::<u16>().ok()) {
                let _ = tx.send(port);
            }
            let mut s = s2.lock().unwrap();
            s.push_str(&line);
            s.push('\n');
        }
    });
    let t0 = Instant::now();
    loop {
        if let Ok(port) = rx.recv_timeout(Duration::from_millis(50)) {
            assert_ne!(port, 0, "the listener said port 0: {}", said.lock().unwrap());
            return (child, port, said);
        }
        if let Some(st) = child.try_wait().unwrap() {
            panic!("the MCP ended ({st}) before it listened: {}", said.lock().unwrap());
        }
        assert!(t0.elapsed() < Duration::from_secs(20), "the MCP did not listen within 20 s: {}", said.lock().unwrap());
    }
}
