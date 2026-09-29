//! The binary over both transports, in front of a recording mock signer (B2's socket protocol):
//! the tool surface, the forbidden tools, key material, signer errors, and streamable HTTP's
//! sessions, status codes, origin check and bearer token.
#![cfg(unix)]
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use xbt_wallet_mcp::mcp::{FORBIDDEN, TOOL_NAMES};

const BIN: &str = env!("CARGO_BIN_EXE_xbt-wallet-mcp");
const WIF: &str = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";

/// A signer that records every request and answers with key-bearing probe results.
fn mock_signer(dir: &Path) -> (PathBuf, Arc<Mutex<Vec<Value>>>) {
    let sock = dir.join("signer.sock");
    let l = UnixListener::bind(&sock).unwrap();
    let seen = Arc::new(Mutex::new(vec![]));
    let s2 = seen.clone();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let mut line = String::new();
            BufReader::new(c.try_clone().unwrap()).read_line(&mut line).unwrap();
            let req: Value = serde_json::from_str(&line).unwrap();
            s2.lock().unwrap().push(req.clone());
            let resp = if req["params"]["to"] == "err" {
                json!({"id": 1, "error": {"message": "boom"}})
            } else {
                json!({"id": 1, "result": {"method": req["method"], "params": req["params"], "hot_privkey": "aa", "note": WIF,
                                           "untrusted_provider_response": {"body": WIF}}})
            };
            let _ = c.write_all(format!("{resp}\n").as_bytes());
        }
    });
    (sock, seen)
}

fn init_msg(id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "initialize",
           "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}})
}

struct Stdio_ {
    child: Child,
    out: BufReader<std::process::ChildStdout>,
}

impl Stdio_ {
    fn start(sock: &Path) -> Self {
        let mut child = Command::new(BIN).env_clear().env("B2_SIGNER_SOCK", sock).stdin(Stdio::piped()).stdout(Stdio::piped())
            .stderr(Stdio::null()).spawn().unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        Self { child, out }
    }

    fn send(&mut self, m: &Value) {
        writeln!(self.child.stdin.as_mut().unwrap(), "{m}").unwrap();
    }

    fn ask(&mut self, m: Value) -> Value {
        self.send(&m);
        let mut line = String::new();
        self.out.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    fn call(&mut self, id: u64, name: &str, args: Value) -> Value {
        self.ask(json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": args}}))["result"].clone()
    }
}

#[test]
fn stdio_surface_safety_and_errors() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, seen) = mock_signer(dir.path());
    let mut s = Stdio_::start(&sock);
    let init = s.ask(init_msg(1));
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(init["result"]["serverInfo"]["name"], "xbt-agent-wallet");
    s.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    let tools = s.ask(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let names: Vec<&str> = tools["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, TOOL_NAMES);
    for f in FORBIDDEN {
        assert!(!names.contains(&f));
        let r = s.call(3, f, json!({}));
        assert_eq!(r, json!({"content": [{"type": "text", "text": format!("Unknown tool: {f}")}], "isError": true}));
    }
    // a call: forwarded with its defaults, key-named fields dropped, key-shaped strings redacted,
    // the provider's untrusted body kept verbatim
    let r = s.call(4, "xbt402_pay", json!({"url": "http://x/y", "max_sats": "7"}));
    assert_eq!(r["isError"], false);
    let text = r["content"][0]["text"].as_str().unwrap();
    assert_eq!(r["structuredContent"]["result"], text);
    let v: Value = serde_json::from_str(text).unwrap();
    assert!(v.get("hot_privkey").is_none());
    assert_eq!(v["note"], "[redacted]");
    assert_eq!(v["untrusted_provider_response"]["body"], WIF);
    assert_eq!(v["params"], json!({"url": "http://x/y", "method": "GET", "body": "", "max_sats": 7}));
    assert_eq!(seen.lock().unwrap().last().unwrap()["method"], "xbt402_pay");
    // a signer error reaches the model only as B2's generic line
    let r = s.call(5, "pay", json!({"to": "err", "amount_xbt": 1}));
    assert_eq!(r["content"][0]["text"], "Error executing tool pay");
    assert_eq!(r["isError"], true);
    // a validation error never reaches the signer
    let n = seen.lock().unwrap().len();
    let r = s.call(6, "history", json!({"limit": 5.5}));
    assert!(r["content"][0]["text"].as_str().unwrap().starts_with("Error executing tool history: 1 validation error for historyArguments"));
    assert_eq!(seen.lock().unwrap().len(), n);
    drop(s.child.stdin.take());
    let _ = s.child.wait();
}

struct Http {
    child: Child,
    base: String,
}

impl Drop for Http {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn http(sock: &Path, port: u16, token: Option<&str>) -> Http {
    let mut cmd = Command::new(BIN);
    cmd.env_clear().env("B2_SIGNER_SOCK", sock).args(["--http", &format!("127.0.0.1:{port}")]).stdout(Stdio::null()).stderr(Stdio::null());
    if let Some(t) = token {
        cmd.env("XBT_MCP_HTTP_TOKEN", t);
    }
    let child = cmd.spawn().unwrap();
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Http { child, base: format!("http://127.0.0.1:{port}/mcp") }
}

/// (status, Mcp-Session-Id, body)
fn req(method: &str, url: &str, body: Option<&Value>, headers: &[(&str, &str)]) -> (u16, Option<String>, String) {
    let mut r = ureq::request(method, url).set("Accept", "application/json, text/event-stream");
    for (k, v) in headers {
        r = r.set(k, v);
    }
    let resp = match body {
        Some(b) => r.set("Content-Type", "application/json").send_string(&b.to_string()),
        None => r.call(),
    };
    let resp = match resp {
        Ok(x) => x,
        Err(ureq::Error::Status(_, x)) => x,
        Err(e) => panic!("{e}"),
    };
    let (st, sid) = (resp.status(), resp.header("Mcp-Session-Id").map(str::to_string));
    let mut s = String::new();
    resp.into_reader().read_to_string(&mut s).unwrap();
    (st, sid, s)
}

// ports: AGP-030's range 33500-33599
#[test]
fn streamable_http_sessions_and_guards() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, _) = mock_signer(dir.path());
    let h = http(&sock, 33591, None);
    let (st, sid, body) = req("POST", &h.base, Some(&init_msg(1)), &[]);
    assert_eq!(st, 200);
    let sid = sid.expect("session id");
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["result"]["serverInfo"]["name"], "xbt-agent-wallet");
    let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    assert_eq!(req("POST", &h.base, Some(&list), &[]).0, 400); // no session
    assert_eq!(req("POST", &h.base, Some(&list), &[("Mcp-Session-Id", "nope")]).0, 404);
    let (st, _, body) = req("POST", &h.base, Some(&list), &[("Mcp-Session-Id", &sid), ("MCP-Protocol-Version", "2025-06-18")]);
    assert_eq!(st, 200);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["result"]["tools"].as_array().unwrap().len(), 10);
    let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    assert_eq!(req("POST", &h.base, Some(&note), &[("Mcp-Session-Id", &sid)]).0, 202);
    let call = json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "balance", "arguments": {}}});
    let (st, _, body) = req("POST", &h.base, Some(&call), &[("Mcp-Session-Id", &sid)]);
    assert_eq!(st, 200);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["result"]["isError"], false);
    assert_eq!(req("POST", &h.base, Some(&list), &[("Mcp-Session-Id", &sid), ("MCP-Protocol-Version", "1999-01-01")]).0, 400);
    assert_eq!(req("POST", &h.base, Some(&list), &[("Mcp-Session-Id", &sid), ("Origin", "https://evil.example")]).0, 403);
    assert_eq!(req("POST", &h.base, Some(&list), &[("Mcp-Session-Id", &sid), ("Origin", "http://localhost:3000")]).0, 200);
    assert_eq!(req("GET", &h.base, None, &[("Mcp-Session-Id", &sid)]).0, 405);
    assert_eq!(req("POST", &h.base.replace("/mcp", "/other"), Some(&list), &[]).0, 404);
    assert_eq!(req("DELETE", &h.base, None, &[("Mcp-Session-Id", &sid)]).0, 200);
    assert_eq!(req("POST", &h.base, Some(&list), &[("Mcp-Session-Id", &sid)]).0, 404);

    let t = http(&sock, 33592, Some("s3cret"));
    assert_eq!(req("POST", &t.base, Some(&init_msg(1)), &[]).0, 401);
    assert_eq!(req("POST", &t.base, Some(&init_msg(1)), &[("Authorization", "Bearer wrong!")]).0, 401);
    assert_eq!(req("POST", &t.base, Some(&init_msg(1)), &[("Authorization", "Bearer s3cret")]).0, 200);
}

#[test]
fn http_refuses_non_loopback_without_token() {
    let out = Command::new(BIN).env_clear().args(["--http", "0.0.0.0:33593"]).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a loopback address"));
    let out = Command::new(BIN).env_clear().args(["--http", "0.0.0.0:33593", "--http-allow-remote"]).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("needs XBT_MCP_HTTP_TOKEN"));
}

/// A tool call sent before initialize is refused even when initialize follows at once (the call runs
/// on its own thread; it must see the session as it was when the call arrived).
#[test]
fn stdio_call_before_initialize_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, seen) = mock_signer(dir.path());
    for _ in 0..20 {
        let mut s = Stdio_::start(&sock);
        s.send(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "balance", "arguments": {}}}));
        s.send(&init_msg(2));
        let mut got = std::collections::HashMap::new();
        for _ in 0..2 {
            let mut line = String::new();
            s.out.read_line(&mut line).unwrap();
            let v: Value = serde_json::from_str(&line).unwrap();
            got.insert(v["id"].as_u64().unwrap(), v);
        }
        assert_eq!(got[&1]["error"]["code"], -32602, "{}", got[&1]);
        drop(s.child.stdin.take());
        let _ = s.child.wait();
    }
    assert!(seen.lock().unwrap().is_empty());
}

/// AGP-038 container mode: XBT_DATA_DIR, a non-loopback listener with a generated token, a base path,
/// /healthz and /readyz following the signer's readiness file. Port 33740 (AGP-038's 33700-33799).
#[test]
fn data_dir_mode_health_token_and_base_path() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (sock, _) = mock_signer(dir.path());
    let data = dir.path().join("data");
    let child = Command::new(BIN).env_clear().env("XBT_DATA_DIR", &data).env("B2_SIGNER_SOCK", &sock).env("XBT_BASE_PATH", "/w/")
        .env("XBT_MCP_HTTP", "0.0.0.0:33740").stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let h = Http { child, base: "http://127.0.0.1:33740".into() };
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", 33740)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let tok_path = data.join("mcp/secrets/mcp-http-token");
    let token = std::fs::read_to_string(&tok_path).unwrap();
    assert_eq!(token.len(), 64);
    assert_eq!(std::fs::metadata(&tok_path).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(data.join("mcp/secrets")).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(req("GET", &format!("{}/healthz", h.base), None, &[]).0, 200);
    assert_eq!(req("GET", &format!("{}/w/healthz", h.base), None, &[]).0, 200);
    // the signer answers, but its readiness file is missing: not ready
    let (st, _, body) = req("GET", &format!("{}/w/readyz", h.base), None, &[]);
    assert_eq!(st, 503, "{body}");
    let ready = data.join("run/signer/ready.json");
    std::fs::create_dir_all(ready.parent().unwrap()).unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();
    std::fs::write(&ready, json!({"ok": false, "ts": now}).to_string()).unwrap();
    assert_eq!(req("GET", &format!("{}/readyz", h.base), None, &[]).0, 503);
    std::fs::write(&ready, json!({"ok": true, "ts": now}).to_string()).unwrap();
    let (st, _, body) = req("GET", &format!("{}/readyz", h.base), None, &[]);
    assert_eq!(st, 200, "{body}");
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["signer"]["reachable"], true);
    std::fs::write(&ready, json!({"ok": true, "ts": now - 3600.0}).to_string()).unwrap();
    assert_eq!(req("GET", &format!("{}/readyz", h.base), None, &[]).0, 503); // stale
    // MCP itself: the token, under the base path and without it (a proxy that strips it)
    let auth = format!("Bearer {token}");
    assert_eq!(req("POST", &format!("{}/w/mcp", h.base), Some(&init_msg(1)), &[]).0, 401);
    assert_eq!(req("POST", &format!("{}/w/mcp", h.base), Some(&init_msg(1)), &[("Authorization", &auth)]).0, 200);
    assert_eq!(req("POST", &format!("{}/mcp", h.base), Some(&init_msg(1)), &[("Authorization", &auth)]).0, 200);
    // AGP-042: owner rotation without a restart (the UI's Agents page)
    assert_eq!(req("POST", &format!("{}/rotate-token", h.base), None, &[("Authorization", &auth)]).0, 403);
    let (st, _, body) = req("POST", &format!("{}/rotate-token", h.base), None, &[("Authorization", &auth), ("X-XBT-Rotate", "owner")]);
    assert_eq!(st, 200, "{body}");
    let new = serde_json::from_str::<Value>(&body).unwrap()["token"].as_str().unwrap().to_string();
    assert_eq!(new.len(), 64);
    assert_ne!(new, token.trim());
    assert_eq!(std::fs::read_to_string(&tok_path).unwrap().trim(), new);
    assert_eq!(req("POST", &format!("{}/mcp", h.base), Some(&init_msg(1)), &[("Authorization", &auth)]).0, 401);
    assert_eq!(req("POST", &format!("{}/mcp", h.base), Some(&init_msg(1)), &[("Authorization", &format!("Bearer {new}"))]).0, 200);
    // production mode (a data dir) refuses the token as a plain env value
    let out = Command::new(BIN).env_clear().env("XBT_DATA_DIR", &data).env("XBT_MCP_HTTP_TOKEN", "x")
        .env("XBT_MCP_HTTP", "127.0.0.1:33741").env("B2_SIGNER_SOCK", &sock).output().unwrap();
    assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("refused in production mode"));
}
