//! AGP-039: the web UI over real HTTP against a regtest signer (the signer suite's rig: the Rust
//! signer on a fake pruned regtest node, served on its socket).
//!
//! Auth (first run, login, throttle, sessions, logout), CSRF, the security headers, proxy base paths,
//! and every action: approve (a payment, and the grant of a Lightning payment), deny, the policy
//! editor (the signer's errors, a signed change applied live, JSON mode), human-key enrolment and
//! rotation, sweep, rotation, backup, anchor, and the pages, among them the read-only list of what
//! an earlier version's on-chain channels left.
#[path = "../../xbt-signer/tests/common/mod.rs"]
mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use serde_json::{json, Value};
use xbt_signer::approval::{backup_message, canonical_message, deny_message, human_key_message, policy_message, rotate_message, sweep_message};
use xbt_wallet_ui::app::App;
use xbt_wallet_ui::config::Config;

/// A signer on its socket plus the UI in front of it.
struct Box_ {
    rig: Rig,
    _sock: xbt_signer::server::Running,
    _app: Arc<App>,
    _srv: xbt_wallet_ui::server::Running,
    base: String,
    data: tempfile::TempDir,
}

fn start(policy_extra: Value, witness: bool, tweak: impl FnOnce(&mut Config)) -> Box_ {
    start_on(Rig::new(policy_extra, witness), tweak)
}

/// The UI in front of this rig's signer.
fn start_on(rig: Rig, tweak: impl FnOnce(&mut Config)) -> Box_ {
    let sock_path = rig.dir.path().join("signer.sock");
    let sock = xbt_signer::server::spawn(rig.s.clone(), &sock_path, false).unwrap();
    let data = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_test(sock_path, data.path().join("ui"), "127.0.0.1:0");
    tweak(&mut cfg);
    let app = App::new(cfg).unwrap();
    let srv = xbt_wallet_ui::server::spawn(app.clone()).unwrap();
    let base = format!("http://{}", srv.addr);
    Box_ { rig, _sock: sock, _app: app, _srv: srv, base, data }
}

struct R {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
}

impl R {
    fn location(&self) -> &str {
        self.headers.get("location").map(String::as_str).unwrap_or("")
    }
}

/// A browser: one cookie, no redirects followed.
struct B {
    base: String,
    cookie: String,
    agent: ureq::Agent,
}

fn field(html: &str, name: &str) -> String {
    let pat = format!("name=\"{name}\" value=\"");
    let i = html.find(&pat).unwrap_or_else(|| panic!("no field {name} in page"));
    let rest = &html[i + pat.len()..];
    unescape(&rest[..rest.find('"').unwrap()])
}

fn unescape(s: &str) -> String {
    s.replace("&quot;", "\"").replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
}

fn enc(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

impl B {
    fn new(base: &str) -> Self {
        Self { base: base.into(), cookie: String::new(), agent: ureq::AgentBuilder::new().redirects(0).build() }
    }

    fn send(&mut self, method: &str, path: &str, body: Option<&str>, extra: &[(&str, &str)]) -> R {
        let mut rq = self.agent.request(method, &format!("{}{path}", self.base));
        if !self.cookie.is_empty() {
            rq = rq.set("Cookie", &self.cookie);
        }
        for (k, v) in extra {
            rq = rq.set(k, v);
        }
        let resp = match body {
            Some(b) => rq.set("Content-Type", "application/x-www-form-urlencoded").send_string(b),
            None => rq.call(),
        };
        let resp = match resp {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => panic!("{method} {path}: {e}"),
        };
        let mut headers = HashMap::new();
        for n in resp.headers_names() {
            headers.insert(n.to_ascii_lowercase(), resp.all(&n).join("\n"));
        }
        if let Some(c) = headers.get("set-cookie") {
            let v = c.split(';').next().unwrap().to_string();
            self.cookie = if v.ends_with('=') { String::new() } else { v };
        }
        R { status: resp.status(), headers, body: resp.into_string().unwrap_or_default() }
    }

    fn get(&mut self, path: &str) -> R {
        self.send("GET", path, None, &[])
    }

    fn post(&mut self, path: &str, form: &[(&str, &str)]) -> R {
        let body = form.iter().map(|(k, v)| format!("{}={}", enc(k), enc(v))).collect::<Vec<_>>().join("&");
        self.send("POST", path, Some(&body), &[])
    }

    /// POST with the CSRF token of `page`.
    fn act(&mut self, page: &str, path: &str, form: &[(&str, &str)]) -> R {
        let csrf = field(&self.get(page).body, "csrf");
        let mut f = vec![("csrf", csrf.as_str())];
        f.extend_from_slice(form);
        self.post(path, &f)
    }

    /// The flash on the page a POST redirected to.
    fn flash_after(&mut self, r: &R) -> String {
        assert_eq!(r.status, 303, "{}", r.body);
        let to = r.location().trim_start_matches('.').to_string();
        let page = self.get(&to).body;
        let i = page.find("class=\"flash").map(|i| &page[i..]).unwrap_or("");
        let text = &i[i.find('>').map(|x| x + 1).unwrap_or(0)..];
        unescape(&text[..text.find("</div>").unwrap_or(0)])
    }
}

const PW: &str = "a long box password";

fn logged_in(b: &Box_) -> B {
    let mut br = B::new(&b.base);
    let code = std::fs::read_to_string(b.data.path().join("ui/setup-code")).unwrap();
    let r = br.post("/setup-password", &[("code", code.trim()), ("password", PW), ("password2", PW)]);
    assert_eq!(r.status, 303, "{}", r.body);
    br
}

fn sig(m: &[u8]) -> String {
    sign_human(m)
}

// --- auth, sessions, CSRF, headers -------------------------------------------------------------------

#[test]
fn first_run_needs_the_setup_code_then_the_password_and_logins_are_throttled() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |_| {});
    let mut br = B::new(&bx.base);
    assert_eq!(br.get("/healthz").status, 200);
    assert_eq!(br.get("/readyz").body, "{\"ok\":true,\"signer\":\"reachable\"}");
    let r = br.get("/");
    assert!(r.body.contains("Setup code"), "first run asks for the setup code");
    let r = br.get("/approvals");
    assert_eq!((r.status, r.location()), (303, "./setup-password"));
    let r = br.post("/setup-password", &[("code", "000000000000"), ("password", PW), ("password2", PW)]);
    assert!(r.body.contains("wrong setup code"));
    let code = std::fs::read_to_string(bx.data.path().join("ui/setup-code")).unwrap();
    let r = br.post("/setup-password", &[("code", code.trim()), ("password", "short"), ("password2", "short")]);
    assert!(r.body.contains("at least 10 characters"));
    let r = br.post("/setup-password", &[("code", code.trim()), ("password", PW), ("password2", PW)]);
    assert_eq!((r.status, r.location()), (303, "./setup"));
    let c = r.headers["set-cookie"].clone();
    assert!(c.contains("HttpOnly") && c.contains("SameSite=Strict") && c.contains("Path=/"), "{c}");
    assert!(!bx.data.path().join("ui/setup-code").exists(), "the setup code is spent");
    let h = std::fs::read_to_string(bx.data.path().join("ui/password.scrypt")).unwrap();
    assert!(h.starts_with("scrypt$15$8$1$") && !h.contains(PW));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(bx.data.path().join("ui/password.scrypt")).unwrap().permissions().mode() & 0o777, 0o600);
    }
    assert_eq!(br.get("/setup").status, 200);
    // log out: the session is gone
    let r = br.act("/", "/logout", &[]);
    assert_eq!(r.location(), "./login");
    br.cookie.clear();
    assert_eq!(br.get("/").location(), "./login");
    assert_eq!(br.get("/api/pending").status, 401);
    // wrong passwords, then the throttle refuses even the right one
    for _ in 0..5 {
        assert_eq!(br.post("/login", &[("password", "nope nope nope")]).status, 401);
    }
    let r = br.post("/login", &[("password", PW)]);
    assert!(r.body.contains("too many failed logins"), "{}", r.body);
    // a stolen old cookie does not work
    let mut other = B::new(&bx.base);
    other.cookie = "xbtui=00".into();
    assert_eq!(other.get("/").location(), "./login");
}

#[test]
fn a_platform_password_sessions_expire_and_csrf_is_required() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |c| c.password = Some("platform password".into()));
    assert!(!bx.data.path().join("ui/setup-code").exists(), "no setup code with a platform password");
    let mut br = B::new(&bx.base);
    assert_eq!(br.get("/").location(), "./login");
    assert_eq!(br.post("/login", &[("password", "platform password")]).location(), "./");
    let page = br.get("/approvals");
    assert_eq!(page.status, 200);
    // security headers on every response
    for (k, want) in [("content-security-policy", "default-src 'none'; script-src 'self'"), ("x-frame-options", "DENY"),
                      ("x-content-type-options", "nosniff"), ("referrer-policy", "no-referrer"), ("cache-control", "no-store")] {
        assert!(page.headers.get(k).is_some_and(|v| v.contains(want)), "{k}: {:?}", page.headers.get(k));
    }
    // no absolute URLs and nothing from elsewhere
    for p in ["/", "/approvals", "/policy", "/channels", "/signatures", "/keys", "/setup"] {
        let html = br.get(p).body;
        for bad in ["href=\"/", "src=\"/", "action=\"/", "http://", "https://"] {
            if bad.starts_with("http") {
                assert!(!html.contains(&format!("href=\"{bad}")) && !html.contains(&format!("src=\"{bad}")) && !html.contains(&format!("action=\"{bad}")),
                        "{p} has an absolute {bad} link");
            } else {
                assert!(!html.contains(bad), "{p} has a root-relative URL {bad}");
            }
        }
    }
    // CSRF: none, wrong, another session's, cross-site
    let r = br.post("/deny", &[("token", "x")]);
    assert_eq!(r.status, 403);
    let r = br.post("/deny", &[("csrf", "00"), ("token", "x")]);
    assert_eq!(r.status, 403);
    let mut other = B::new(&bx.base);
    other.post("/login", &[("password", "platform password")]);
    let foreign = field(&other.get("/").body, "csrf");
    assert_eq!(br.post("/deny", &[("csrf", &foreign), ("token", "x")]).status, 403);
    let mine = field(&br.get("/").body, "csrf");
    let body = format!("csrf={mine}&token=x");
    assert_eq!(br.send("POST", "/deny", Some(&body), &[("Sec-Fetch-Site", "cross-site")]).status, 403);
    assert_eq!(br.send("POST", "/deny", Some(&body), &[("Sec-Fetch-Site", "same-origin")]).status, 303);
    // the static assets
    let js = br.get("/ui.js");
    assert_eq!(js.status, 200);
    assert!(js.headers["content-type"].starts_with("text/javascript"));
}

#[test]
fn sessions_expire_when_idle() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |c| {
        c.password = Some("platform password".into());
        c.session_idle = Duration::from_millis(1500);
    });
    let mut br = B::new(&bx.base);
    assert_eq!(br.post("/login", &[("password", "platform password")]).location(), "./");
    assert_eq!(br.get("/keys").status, 200);
    std::thread::sleep(Duration::from_millis(1700));
    assert_eq!(br.get("/keys").location(), "./login");
}

#[test]
fn behind_a_proxy_prefix_and_the_peer_allowlist() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |c| {
        c.base_path = "/apps/wallet/".into();
        c.setup_open = true;
    });
    let mut br = B::new(&bx.base);
    assert_eq!(br.get("/apps/wallet").location(), "./wallet/");
    let r = br.post("/apps/wallet/setup-password", &[("password", PW), ("password2", PW)]);
    assert_eq!(r.status, 303, "the open setup needs no code: {}", r.body);
    assert!(r.headers["set-cookie"].contains("Path=/apps/wallet/"));
    assert_eq!(br.get("/apps/wallet/approvals").status, 200);
    assert_eq!(br.get("/approvals").status, 200, "a proxy that strips the prefix works too");
    // X-Forwarded-Proto https: a Secure cookie
    let mut b2 = B::new(&bx.base);
    let r = b2.send("POST", "/apps/wallet/login", Some(&format!("password={}", enc(PW))), &[("X-Forwarded-Proto", "https")]);
    assert!(r.headers["set-cookie"].contains("; Secure"));
    drop(bx);
    let bx = start(json!({}), false, |c| c.allow_ips = vec!["10.9.".into()]);
    assert_eq!(B::new(&bx.base).get("/").status, 403, "only the configured peers");
}

/// AGP-063 W4: a public name pointed at the box (DNS rebinding) is refused, and so is a POST from a
/// foreign origin; the box's own names, `null` and `XBT_UI_ALLOWED_HOSTS` are not.
#[test]
fn w4_a_rebound_host_and_a_foreign_origin_are_refused() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |c| c.setup_open = true);
    let mut br = B::new(&bx.base);
    assert_eq!(br.send("GET", "/login", None, &[("Host", "rebind.example:8480")]).status, 421);
    for h in ["umbrel.local", "abcdefghijklmnop.onion:80", "xbt-wallet-ui:8480", "[::1]:8480", "10.21.0.4"] {
        assert_ne!(br.send("GET", "/login", None, &[("Host", h)]).status, 421, "{h}");
    }
    let form = format!("password={}&password2={}", enc(PW), enc(PW));
    assert_eq!(br.send("POST", "/setup-password", Some(&form), &[("Origin", "https://evil.example")]).status, 403);
    assert_eq!(br.send("POST", "/setup-password", Some(&form), &[("Origin", "null")]).status, 303, "the UI's own no-referrer pages send null");
    let allowed = vec!["wallet.example.com".to_string()];
    assert!(xbt_wallet_ui::app::host_allowed("wallet.example.com:443", &allowed) && !xbt_wallet_ui::app::host_allowed("evil.example", &allowed));
    assert!(xbt_wallet_ui::app::origin_allowed("https://wallet.example.com", &allowed) && !xbt_wallet_ui::app::origin_allowed("https://x.wallet.example.com", &allowed));
}

// --- actions against the signer -----------------------------------------------------------------------

#[test]
fn approve_a_payment_in_the_ui_with_a_signature_from_another_device_and_deny_drops_one() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |_| {});
    let mut br = logged_in(&bx);
    let r = bx.rig.call("pay", json!({"to": ADDR, "amount_sats": 1000, "memo": "invoice 7"}));
    assert_eq!(r["verdict"], "needs_human");
    assert_eq!(br.get("/api/pending").body, "{\"pending\":1}");
    let page = br.get("/approvals").body;
    assert!(page.contains(ADDR) && page.contains("1,000 sats"), "the queue shows the payee and amount");
    let token = field(&page, "token");
    let (dest, amount, exp) = (field(&page, "dest"), field(&page, "amount_sats"), field(&page, "expiry"));
    assert_eq!((dest.as_str(), amount.as_str()), (ADDR, "1000"));
    // the message shown for another device is exactly the signer's
    let m = canonical_message(&token, &dest, 1000, exp.parse().unwrap());
    assert!(page.contains(&hex::encode(&m)));
    // a bad signature is refused by the signer
    let r = br.act("/approvals", "/approve", &[("token", &token), ("dest", &dest), ("amount_sats", "1000"), ("expiry", &exp), ("signature", &sig(b"x"))]);
    assert!(br.flash_after(&r).contains("approval_sig"));
    // the signature pasted from another device
    let r = br.act("/approvals", "/approve", &[("token", &token), ("dest", &dest), ("amount_sats", "1000"), ("expiry", &exp),
                                               ("signature", ""), ("signature_ext", &sig(&m))]);
    let f = br.flash_after(&r);
    assert!(f.starts_with("Approved and paid: 1000 sats to"), "{f}");
    assert!(!br.get("/approvals").body.contains(&format!("value=\"{token}\"")), "nothing left to sign for it");
    assert_eq!(bx.rig.s.engine.store.payments().unwrap().iter().map(|e| e.amount_sats).sum::<i64>(), 1000, "paid once");
    // deny another
    let r2 = bx.rig.call("pay", json!({"to": ADDR, "amount_sats": 1000, "memo": "invoice 8"}));
    let t2 = r2["approval_token"].as_str().unwrap();
    let r = br.act("/approvals", "/deny", &[("token", t2), ("reason", "too much")]);
    assert!(br.flash_after(&r).contains("human_sig"), "AGP-063 W3: a deny is signed like an approval");
    let dexp = (xbt_wallet_ui::now() + 300).to_string();
    let r = br.act("/approvals", "/deny", &[("token", t2), ("reason", "too much"), ("expiry", &dexp),
                                            ("signature", &sig(&deny_message(t2, dexp.parse().unwrap())))]);
    assert_eq!(br.flash_after(&r), "Denied.");
    assert_eq!(bx.rig.call("approval_status", json!({"token": t2}))["state"], "denied");
    let hist = bx.rig.call("history", json!({"limit": 100}))["events"].to_string();
    assert!(hist.contains("too much"));
}

/// A Lightning payment over the threshold is granted, not paid, when the human approves: the page
/// says so, and says that it is paid when the agent asks again.
#[test]
fn approving_a_lightning_payment_grants_it_and_the_page_says_when_it_is_paid() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |_| {});
    let mut br = logged_in(&bx);
    let r = bx.rig.call("pay", json!({"to": ADDR, "amount_sats": 1000, "memo": "m"}));
    let token = r["approval_token"].as_str().unwrap().to_string();
    // as `ln_pay` leaves a request that waits for the human
    bx.rig.s.engine.store.update_approval(&token, &json!({"kind": "ln", "payment_hash": "ab".repeat(32)})).unwrap();
    let page = br.get("/approvals").body;
    assert!(page.contains("Lightning payment (paid when the agent asks again"), "{page}");
    let exp = field(&page, "expiry");
    let m = canonical_message(&token, ADDR, 1000, exp.parse().unwrap());
    let r = br.act("/approvals", "/approve", &[("token", &token), ("dest", ADDR), ("amount_sats", "1000"), ("expiry", &exp), ("signature", &sig(&m))]);
    let f = br.flash_after(&r);
    assert!(f.starts_with("Approved. The agent's Lightning payment to"), "{f}");
    assert!(br.get("/approvals").body.contains("Approved: paid when the agent"));
    assert!(bx.rig.s.engine.store.payments().unwrap().is_empty(), "nothing is paid by the approval itself");
}

#[test]
fn approve_a_pay_token_pays_at_once() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |_| {});
    let mut br = logged_in(&bx);
    let r = bx.rig.call("pay", json!({"to": ADDR, "amount_sats": 1000, "memo": "invoice 7"}));
    let page = br.get("/approvals").body;
    assert!(page.contains("invoice 7") && page.contains("paid as soon as you approve"));
    let m = canonical_message(r["approval_token"].as_str().unwrap(), ADDR, 1000, r["approval_expires"].as_i64().unwrap());
    let r = br.act("/approvals", "/approve", &[("token", r["approval_token"].as_str().unwrap()), ("dest", ADDR), ("amount_sats", "1000"),
                                               ("expiry", &r["approval_expires"].to_string()), ("signature", &sig(&m))]);
    let f = br.flash_after(&r);
    assert!(f.starts_with("Approved and paid: 1000 sats to") && f.contains("onchain"), "{f}");
}

#[test]
fn a_halted_lightning_rail_shows_as_a_resume_request_that_pays_nothing() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |_| {});
    let mut br = logged_in(&bx);
    let exp = xbt_wallet_ui::now() + 300;
    bx.rig.s.engine.store.put_approval("resume-1", json!({"kind": "ln_resume", "halt_id": "h1", "dest": "ln:resume", "amount_sats": 3002,
        "memo": "Lightning payments are halted: a late rebook broke the policy", "expires": exp, "ts": 1, "used": false})).unwrap();
    let page = br.get("/approvals").body;
    assert!(page.contains("resume Lightning payments") && page.contains("Nothing is paid when you approve"), "{page}");
    assert!(!page.contains("paid as soon as you approve"));
    let m = canonical_message("resume-1", "ln:resume", 3002, exp);
    let r = br.act("/approvals", "/approve", &[("token", "resume-1"), ("dest", "ln:resume"), ("amount_sats", "3002"), ("expiry", &exp.to_string()),
                                               ("signature", &sig(&m))]);
    assert_eq!(br.flash_after(&r), "Resumed: the agent may pay over Lightning again, within the policy.");
    assert!(!br.get("/approvals").body.contains("resume-1"));
}

#[test]
fn the_policy_editor_shows_the_signer_s_errors_and_applies_a_signed_change_live() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |_| {});
    let mut br = logged_in(&bx);
    let page = br.get("/policy").body;
    assert!(page.contains("name=\"f_human_threshold_sats\" value=\"1000\""));
    // an invalid value: the page lists exactly what the signer's validator says
    let csrf = field(&page, "csrf");
    let mut form: Vec<(String, String)> = vec![("csrf".into(), csrf.clone()), ("mode".into(), "form".into())];
    for k in ["max_per_tx_sats", "daily_budget_sats", "weekly_budget_sats", "per_counterparty_cap_sats", "human_threshold_sats", "approval_ttl_s",
              "split_window_s", "velocity_max", "velocity_window_s", "hot_balance_cap_sats", "anchor_interval_s", "treasury_csv"] {
        let v = field(&page, &format!("f_{k}"));
        form.push((format!("f_{k}"), v));
    }
    form.push(("f_allowlist".into(), PROVIDER.into()));
    let post = |br: &mut B, f: &[(String, String)]| br.post("/policy", &f.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect::<Vec<_>>());
    let mut bad = form.clone();
    bad.iter_mut().find(|(k, _)| k == "f_max_per_tx_sats").unwrap().1 = "lots".into();
    let r = post(&mut br, &bad);
    let mut raw = bx.rig.call("policy_get", json!({}))["policy"].clone();
    raw["max_per_tx_sats"] = "lots".into();
    let want = bx.rig.call("policy_validate", json!({"policy": raw}))["errors"][0].as_str().unwrap().to_string();
    assert_eq!(want, "policy.json max_per_tx_sats: not an integer");
    assert!(r.body.contains(&want), "the UI shows the signer's own error");
    let mut bad = form.clone();
    bad.iter_mut().find(|(k, _)| k == "f_approval_ttl_s").unwrap().1 = "0".into();
    assert!(post(&mut br, &bad).body.contains("policy.json approval_ttl_s: must be &gt; 0 (got 0)"));
    // a valid change: preview (diff + the exact text), sign what is shown, apply
    let mut good = form.clone();
    good.iter_mut().find(|(k, _)| k == "f_human_threshold_sats").unwrap().1 = "5000".into();
    let prev = post(&mut br, &good).body;
    assert!(prev.contains("<code>human_threshold_sats</code>") && prev.contains("Sign and apply"), "{prev}");
    let text = field(&prev, "text");
    let (sha, exp) = (field(&prev, "prev_sha256"), field(&prev, "expiry"));
    let shown = &prev[prev.find("<pre class=\"signed-text\">").unwrap() + 25..];
    assert_eq!(unescape(&shown[..shown.find("</pre>").unwrap()]), text, "what is shown is what is signed");
    let m = policy_message(&sha, exp.parse().unwrap(), &text);
    assert!(prev.contains(&hex::encode(&m)));
    let r = br.post("/policy-apply", &[("csrf", &csrf), ("text", &text), ("prev_sha256", &sha), ("expiry", &exp), ("signature", &sig(b"wrong"))]);
    assert!(br.flash_after(&r).contains("human_sig"));
    let r = br.post("/policy-apply", &[("csrf", &csrf), ("text", &text), ("prev_sha256", &sha), ("expiry", &exp), ("signature", &sig(&m))]);
    assert_eq!(br.flash_after(&r), "Policy applied; it is in force now.");
    assert_eq!(bx.rig.s.config().human_threshold_sats, 5000);
    // JSON mode, with a restart-only key
    let cur = bx.rig.call("policy_get", json!({}));
    let mut p = cur["policy"].clone();
    p["anchor_interval_s"] = 30.into();
    let prev = br.post("/policy", &[("csrf", &csrf), ("mode", "json"), ("json", &p.to_string())]).body;
    assert!(prev.contains("after restart"));
    let (text, sha, exp) = (field(&prev, "text"), field(&prev, "prev_sha256"), field(&prev, "expiry"));
    let r = br.post("/policy-apply", &[("csrf", &csrf), ("text", &text), ("prev_sha256", &sha), ("expiry", &exp),
                                        ("signature", &sig(&policy_message(&sha, exp.parse().unwrap(), &text)))]);
    assert!(br.flash_after(&r).contains("take effect when the signer restarts: anchor_interval_s"));
    assert!(br.get("/policy").body.contains("waiting for a signer restart: anchor_interval_s"));
    assert!(br.post("/policy", &[("csrf", &csrf), ("mode", "json"), ("json", "{nope")]).body.contains("policy.json: key must be a string"));
    // the template
    assert!(br.get("/policy?template=starter").body.contains("name=\"f_max_per_tx_sats\" value=\"100000\""));
}

#[test]
fn enrol_and_replace_the_human_key_then_sweep_rotate_backup_and_anchor() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({"human_pubkey": ""}), true, |_| {});
    bx.rig.fund_hot(1, 20_000);
    let mut br = logged_in(&bx);
    let setup = br.get("/setup").body;
    assert!(setup.contains("id=\"keygen\"") && setup.contains("./human-key-enroll"));
    assert!(br.get("/").body.contains("No approval key is enrolled"));
    let pubhex = hex::encode(human().verifying_key().to_bytes());
    let r = br.act("/setup", "/human-key-enroll", &[("pubkey", &pubhex), ("code", "0000-0000-0000")]);
    assert!(br.flash_after(&r).contains("enrolment code"), "AGP-063 W4: the code from the signer's log, not trust on first use");
    let code = std::fs::read_to_string(bx.rig.root.join(".run/enroll-code")).unwrap();
    let r = br.act("/setup", "/human-key-enroll", &[("pubkey", &pubhex), ("code", code.trim())]);
    assert_eq!(br.flash_after(&r), "Approval key enrolled.");
    let r = br.act("/setup", "/human-key-enroll", &[("pubkey", &pubhex)]);
    assert!(br.flash_after(&r).contains("already enrolled"));
    let keys = br.get("/keys").body;
    assert!(keys.contains(&format!("data-enrolled=\"{pubhex}\"")));
    // sweep 5,000 sats to an outside address
    let hot = field(&keys, "hot_address");
    let exp = field(&keys, "expiry").parse::<i64>().unwrap();
    let to = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let r = br.act("/keys", "/sweep", &[("to", to), ("amount_sats", "5000"), ("expiry", &exp.to_string()), ("signature", &sig(&sweep_message(&hot, to, 5000, exp)))]);
    let f = br.flash_after(&r);
    assert!(f.starts_with("Swept 5000 sats to"), "{f}");
    // rotate
    let r = br.act("/keys", "/rotate", &[("expiry", &exp.to_string()), ("signature", &sig(&rotate_message(&hot, exp)))]);
    let f = br.flash_after(&r);
    assert!(f.starts_with("Hot key rotated"), "{f}");
    // backup: a JSON download
    let keys = br.get("/keys").body;
    let hot = field(&keys, "hot_address");
    let csrf = field(&keys, "csrf");
    let r = br.post("/backup", &[("csrf", &csrf), ("expiry", &exp.to_string()), ("backup_pass", "correct horse battery"), ("backup_pass2", "different"),
                                 ("signature", &sig(&backup_message(&hot, exp)))]);
    assert!(br.flash_after(&r).contains("differ"));
    let r = br.post("/backup", &[("csrf", &csrf), ("expiry", &exp.to_string()), ("backup_pass", "correct horse battery"), ("backup_pass2", "correct horse battery"),
                                 ("signature", &sig(&backup_message(&hot, exp)))]);
    assert_eq!(r.status, 200);
    assert!(r.headers["content-disposition"].starts_with("attachment; filename=\"xbt-wallet-backup-"));
    let doc: Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(doc["format"], "xbt-agentwallet-backup-v1");
    assert!(br.get("/setup").body.contains("A backup was exported."));
    // replace the human key: signed by the old one
    let new = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
    let new_hex = hex::encode(new.verifying_key().to_bytes());
    let r = br.act("/keys", "/human-key-rotate", &[("old_pub", &pubhex), ("pubkey", &new_hex), ("expiry", &exp.to_string()),
                                                   ("signature", &sig(&human_key_message(&pubhex, &new_hex, exp)))]);
    assert!(br.flash_after(&r).starts_with("The new approval key is enrolled"));
    assert_eq!(hex::encode(bx.rig.s.human_key()), new_hex);
    // the signature log and the anchor
    let r = br.act("/signatures", "/anchor-now", &[]);
    assert_eq!(br.flash_after(&r), "Anchored.");
    let s = br.get("/signatures").body;
    assert!(s.contains("chain intact, matches the anchor"), "{s}");
    assert!(s.contains("human:sweep_signature") && s.contains("human:rotate_signature"));
}

/// A wallet upgraded with an on-chain channel still open: the page lists it with the close reports
/// the earlier version kept and says what to do, and offers no action. The wallet has no such rail.
#[test]
fn channels_of_an_earlier_version_are_listed_read_only_with_what_to_do() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let mut rig = Rig::new(json!({}), false);
    let run = rig.root.join(".run");
    let book = r#"{"channels": {"http://127.0.0.1:33210": {"state": "open", "dest": "http://127.0.0.1:33210", "origin": "http://127.0.0.1:33210", "chan": "c1", "cap_sats": 9400, "used_sats": 546, "expiry": 7728},
                                 "http://b": {"state": "closed", "dest": "http://b", "chan": "c0", "cap_sats": 9400, "used_sats": 546, "expiry": 7000, "closed_txid": "ab"}}, "archived": []}"#;
    std::fs::write(run.join("channels.json"), book).unwrap();
    std::fs::write(run.join("close_reports.json"), r#"{"c0": {"report": {"status": "ok", "cum": 546, "unpaid_msat": 0}}}"#).unwrap();
    rig.restart().unwrap();
    let bx = start_on(rig, |_| {});
    let mut br = logged_in(&bx);
    let page = br.get("/channels").body;
    assert!(page.contains("c1") && page.contains(">open<") && page.contains(">closed<"), "{page}");
    assert!(page.contains("cannot close or refund") && page.contains(xbt_signer::legacy::LAST_WITH_CHANNEL), "the owner is told what to do: {page}");
    assert!(page.contains("Close report") && page.contains("provider cum 546"), "{page}");
    assert!(!page.contains("channel-close") && !page.contains("channel-refund") && !page.contains("<button>Close"), "no action is offered");
    for gone in ["/channel-close", "/channel-refund"] {
        let r = br.act("/channels", gone, &[("counterparty", PROVIDER)]);
        assert_eq!(r.status, 404, "{gone}");
    }
    let ov = br.get("/").body;
    assert!(ov.contains("Channels of an earlier version") && ov.contains("Open</dt><dd>1") && ov.contains("Closed</dt><dd>1"), "{ov}");
    assert_eq!(std::fs::read_to_string(bx.rig.root.join(".run/channels.json")).unwrap(), book, "the book is left as it was");
    // a wallet that never had a channel shows no such card
    drop(bx);
    let fresh = start(json!({}), false, |_| {});
    let mut br = logged_in(&fresh);
    assert!(!br.get("/").body.contains("Channels of an earlier version"));
    assert!(br.get("/channels").body.contains("No channels."));
}

/// A stand-in HTTP service on a port the OS picks: `answer(path)` is the status and body.
fn mock_http(answer: fn(&str) -> (u16, &'static str)) -> std::net::SocketAddr {
    struct Mock(fn(&str) -> (u16, &'static str));
    impl xbt_svc::http::Handler for Mock {
        fn body_limit(&self, _: &str, _: &str) -> usize {
            0
        }
        fn handle(&self, req: xbt_svc::http::Request) -> xbt_svc::http::Response {
            let (code, body) = (self.0)(req.path());
            xbt_svc::http::Response::text(code, "application/json", body)
        }
    }
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    xbt_svc::http::serve(Arc::new(Mock(answer)), l, 2).unwrap().addr
}

#[test]
fn the_agents_page_shows_the_mcp_endpoint_and_token_only_after_login() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let tdir = tempfile::tempdir().unwrap();
    let tok = tdir.path().join("mcp-http-token");
    let bx = start(json!({}), false, |c| {
        c.mcp_urls = vec!["http://umbrel.local:33510/mcp".into()];
        c.mcp_token_file = tok.clone();
    });
    let mut anon = B::new(&bx.base);
    let r = anon.get("/agents");
    assert_eq!(r.status, 303, "login first");
    let mut br = logged_in(&bx);
    let page = br.get("/agents").body;
    assert!(page.contains("http://umbrel.local:33510/mcp") && page.contains("No token here yet"), "{page}");
    // as xbt-init leaves it on a box: 0640, the MCP reads it by group
    xbt_svc::replace_secret_file(&tok, format!("{}\n", "ab".repeat(32)).as_bytes(), 0o640).unwrap();
    let page = br.get("/agents").body;
    assert!(page.contains(&"ab".repeat(32)) && page.contains("Bearer ") && page.contains("<details>"), "{page}");
    assert!(page.contains("aria-current=\"page\">Agents") && page.contains("Rotate the token"), "{page}");
    // AGP-042: the real MCP HTTP transport, reading the same file (the UI never calls it to rotate)
    let wallet = std::sync::Arc::new(xbt_wallet_mcp::wallet::Wallet::new(tdir.path().join("no-signer.sock")));
    let mut cfg = xbt_wallet_mcp::transport::HttpConfig::new("127.0.0.1:34202");
    cfg.token_file = Some(tok.clone());
    let server = std::sync::Arc::new(xbt_wallet_mcp::mcp::Server::new(wallet));
    std::thread::spawn(move || xbt_wallet_mcp::transport::serve_http(server, cfg));
    let mcp_init = |t: &str| {
        for _ in 0..100 {
            let r = ureq::post("http://127.0.0.1:34202/mcp").set("Accept", "application/json, text/event-stream")
                .set("Authorization", &format!("Bearer {t}"))
                .send_string(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26",
                                     "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}}).to_string());
            match r {
                Ok(x) => return x.status(),
                Err(ureq::Error::Status(c, _)) => return c,
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
        panic!("mcp not listening")
    };
    assert_eq!(mcp_init(&"ab".repeat(32)), 200);
    // no confirmation box: nothing changes
    let r = br.act("/agents", "/rotate-token", &[]);
    assert!(br.flash_after(&r).contains("tick the box"));
    assert_eq!(std::fs::read_to_string(&tok).unwrap().trim(), "ab".repeat(32));
    let r = br.act("/agents", "/rotate-token", &[("confirm", "1")]);
    let flash = br.flash_after(&r);
    assert!(flash.contains("Agent token rotated"), "{flash}");
    // the old token is refused on the next request; the new one (shown only on this page) works
    assert_eq!(mcp_init(&"ab".repeat(32)), 401);
    let page = br.get("/agents").body;
    let new = regex_token(&page);
    assert!(new.len() == 64 && new != "ab".repeat(32));
    assert_eq!(std::fs::read_to_string(&tok).unwrap().trim(), new);
    assert_eq!(mcp_init(&new), 200);
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&tok).unwrap().permissions().mode() & 0o777, 0o640, "the mode is kept: group, never others");
    }
    let left: Vec<_> = std::fs::read_dir(tdir.path()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
    assert!(left.iter().all(|n| !n.contains(".tmp")), "{left:?}");
}

fn regex_token(page: &str) -> String {
    let i = page.find("<code id=\"mcp-token\">").expect("token on page");
    let rest = &page[i + "<code id=\"mcp-token\">".len()..];
    rest[..rest.find("</code>").unwrap()].to_string()
}

#[test]
fn xbt_compute_status_tile_and_link_when_configured() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let cmp_addr = mock_http(|_| (200, "{\"ok\":true,\"role\":\"node-host\",\"node_sync_pct\":99.7}"));
    let bx = start(json!({}), false, |c| {
        c.cmp_status_url = Some(format!("http://{cmp_addr}/readyz"));
        c.cmp_url = Some("http://umbrel.local:3900/".into());
    });
    let mut br = logged_in(&bx);
    let page = br.get("/").body;
    assert!(page.contains("id=\"cmp-status\"") && page.contains(">up</span>") && page.contains("node_sync_pct") && page.contains("99.7"), "{page}");
    assert!(page.contains("href=\"http://umbrel.local:3900/\" target=\"_blank\" rel=\"noopener noreferrer\""));
    drop(bx);
    let bx = start(json!({}), false, |c| c.cmp_status_url = Some("http://127.0.0.1:1/readyz".into()));
    let mut br = logged_in(&bx);
    assert!(br.get("/").body.contains("unreachable"), "a down cmp shows as unreachable, the page still renders");
}

// --- the setup pages: the Lightning rail and the seller gateway ------------------------------------

fn mac(ops: &[(&str, &[&str])]) -> String {
    hex::encode(xbt402::macaroon::lnd_macaroon_for_tests(ops, &[]))
}

#[cfg(unix)]
#[test]
fn the_lightning_page_stores_only_the_rail_s_macaroon_and_never_shows_it() {
    use std::os::unix::fs::PermissionsExt;
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let ln = tempfile::tempdir().unwrap();
    let dir = ln.path().to_path_buf();
    let b = start(json!({}), false, |c| {
        c.ln.dir = dir.clone();
        c.ln.rest = Some("https://10.21.21.66:8180".into());
    });
    let mut br = logged_in(&b);
    let page = br.get("/lightning").body;
    assert!(page.contains("https://10.21.21.66:8180") && page.contains("info:read offchain:read offchain:write onchain:read"), "{page}");
    // an admin-like macaroon is refused, and nothing is written
    let admin = mac(&[("info", &["read"]), ("offchain", &["read", "write"]), ("onchain", &["read", "write"]), ("macaroon", &["generate"])]);
    let r = br.act("/lightning", "/lightning", &[("action", "save"), ("macaroon", &admin)]);
    let f = br.flash_after(&r);
    assert!(f.contains("onchain:write") || f.contains("grants"), "{f}");
    assert!(!dir.join("rail.macaroon").exists());
    // one that lacks a permission is refused too
    let short = mac(&[("info", &["read"]), ("offchain", &["read"])]);
    let r = br.act("/lightning", "/lightning", &[("action", "save"), ("macaroon", &short)]);
    assert!(br.flash_after(&r).contains("lacks"));
    // the rail's four: stored 0640, never shown back
    let good = mac(&[("info", &["read"]), ("offchain", &["read", "write"]), ("onchain", &["read"])]);
    let r = br.act("/lightning", "/lightning", &[("action", "save"), ("macaroon", &good)]);
    assert!(br.flash_after(&r).contains("saved"), "save");
    let stored = std::fs::read(dir.join("rail.macaroon")).unwrap();
    assert_eq!(hex::encode(&stored), good);
    assert_eq!(std::fs::metadata(dir.join("rail.macaroon")).unwrap().permissions().mode() & 0o777, 0o640);
    let page = br.get("/lightning").body;
    assert!(page.contains("stored") && !page.contains(&good));
    // regtest: no acknowledgement asked, none written
    assert!(!dir.join("mainnet-ack").exists() && !page.contains("name=\"mainnet_ack\""));
    let r = br.act("/lightning", "/lightning", &[("action", "remove")]);
    assert!(br.flash_after(&r).contains("removed"));
    assert!(!dir.join("rail.macaroon").exists());
}

#[test]
fn the_starter_policy_turns_the_rail_and_tickets_on_and_is_low_on_mainnet() {
    let t = xbt_wallet_ui::app::starter_policy("regtest");
    assert_eq!((t["ln"]["enabled"].clone(), t["tickets"]["enabled"].clone()), (json!(true), json!(true)));
    assert!(t["ln"].get("split_height").is_none());
    let m = xbt_wallet_ui::app::starter_policy("main");
    assert_eq!(m["ln"]["split_height"], json!(xbt_wallet_ui::app::MAINNET_SPLIT_HEIGHT));
    assert!(m["max_per_tx_sats"].as_i64().unwrap() <= 2000 && m["daily_budget_sats"].as_i64().unwrap() <= 10000);
    assert!(m["tickets"]["tasks"]["default"]["budget_sats"].as_i64().unwrap() <= 10000);
    // the signer takes both
    for p in [t, m] {
        assert!(xbt_signer::policy::validate_policy(&p).0.is_empty(), "{p}");
    }
}

/// The gateway app's UI: no signer, one page.
fn gateway_ui(dir: &std::path::Path) -> (tempfile::TempDir, Arc<App>, xbt_wallet_ui::server::Running, String) {
    let data = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_test(data.path().join("no-signer.sock"), data.path().join("ui"), "127.0.0.1:0");
    cfg.role = xbt_wallet_ui::config::Role::Gateway;
    cfg.gw.dir = dir.to_path_buf();
    cfg.gw.node_rest = Some("https://10.21.21.66:8180".into());
    cfg.gw.node_tls_cert = Some("/data/lightning/tls.cert".into());
    let app = App::new(cfg).unwrap();
    let srv = xbt_wallet_ui::server::spawn(app.clone()).unwrap();
    let base = format!("http://{}", srv.addr);
    (data, app, srv, base)
}

#[cfg(unix)]
#[test]
fn the_gateway_page_writes_a_config_the_gateway_takes_and_mainnet_is_asked_for() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let gw = tempfile::tempdir().unwrap();
    let dir = gw.path();
    let (data, _app, _srv, base) = gateway_ui(dir);
    let mut br = B::new(&base);
    let code = std::fs::read_to_string(data.path().join("ui/setup-code")).unwrap();
    assert_eq!(br.post("/setup-password", &[("code", code.trim()), ("password", PW), ("password2", PW)]).status, 303);
    assert_eq!(br.get("/readyz").status, 200, "no signer, and ready");
    let page = br.get("/").body;
    assert!(page.contains("Lightning Stream Gateway") && page.contains("invoices:read invoices:write") && !page.contains("Approvals"), "{page}");
    // the count it shows is said to be the node's word, not income
    assert!(page.contains("by its own word") && page.contains("not yet income"), "{page}");
    assert_eq!(br.get("/policy").status, 404);
    let inv = mac(&[("invoices", &["read", "write"])]);
    let info = mac(&[("info", &["read"])]);
    let net = "lightning:0123456789abcdef0123456789abcdef";
    let form = |public: &str, inv: &str, chain: &str, ack: &str| -> Vec<(String, String)> {
        [("upstream", "http://10.21.21.50:8080"), ("price_msat", "2500"), ("unit", "request"), ("public_url", public), ("proxies", ""),
         ("chain", chain), ("network", if chain == "main" { "" } else { net }), ("mainnet_ack", ack), ("max_sessions", "30"),
         ("sessions_per_address", "2"), ("max_held_tickets", "15"), ("invoices_macaroon", inv), ("info_macaroon", info.as_str())]
            .iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    };
    let send = |br: &mut B, f: Vec<(String, String)>| {
        let f: Vec<(&str, &str)> = f.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        br.act("/", "/gateway", &f)
    };
    // the gateway's own parser refuses plain http to a non-loopback origin; nothing is written
    let r = send(&mut br, form("http://seller.example", &inv, "regtest", ""));
    assert_eq!(r.status, 200);
    assert!(unescape(&r.body).contains("not https"), "{}", r.body);
    assert!(!dir.join("config.json").exists());
    // a macaroon wider than invoices is refused
    let wide = mac(&[("invoices", &["read", "write"]), ("offchain", &["write"])]);
    let r = send(&mut br, form("https://seller.example", &wide, "regtest", ""));
    assert!(unescape(&r.body).contains("offchain:write"), "{}", r.body);
    // a good one: https behind a proxy listens on every address, and with no proxy named the per-address cap is off
    let r = send(&mut br, form("https://seller.example", &inv, "regtest", ""));
    assert!(br.flash_after(&r).contains("Saved"));
    let c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    assert_eq!((c["listen"].as_str(), c["caps"]["sessions_per_address"].as_u64()), (Some("0.0.0.0:8402"), Some(0)));
    assert_eq!(c["node"]["macaroon"], json!(dir.join("invoices.macaroon").display().to_string()));
    assert_eq!(c["routes"], json!([{"path": "/", "price": {"request_msat": 2500}}]));
    xbt_gateway::config::Config::from_json(&c).unwrap();
    assert_eq!(hex::encode(std::fs::read(dir.join("invoices.macaroon")).unwrap()), inv);
    // a buyer on this machine (a test): loopback, and the macaroons kept when left empty
    let r = send(&mut br, form("http://127.0.0.1:8402", "", "regtest", ""));
    assert!(br.flash_after(&r).contains("Saved"));
    let c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    assert_eq!(c["listen"], json!("127.0.0.1:8402"));
    // mainnet: refused without the acknowledgement word for word; with it, the warning shows and the caps go low
    let r = send(&mut br, form("https://seller.example", "", "main", "yes"));
    assert!(unescape(&r.body).contains(xbt_gateway::config::MAINNET_ACK) && unescape(&r.body).contains("regtest only"), "{}", r.body);
    let r = send(&mut br, form("https://seller.example", "", "main", xbt_gateway::config::MAINNET_ACK));
    assert!(br.flash_after(&r).contains("mainnet"));
    let c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    assert_eq!((c["chain"].as_str(), c["mainnet_ack"].as_str()), (Some("main"), Some(xbt_gateway::config::MAINNET_ACK)));
    assert_eq!((c["caps"]["max_sessions"].as_u64(), c["caps"]["max_held_tickets"].as_u64()), (Some(4), Some(4)));
    assert!(c.get("network").is_none());
    xbt_gateway::config::Config::from_json(&c).unwrap();
}

const FILM: &str = "https://media.lazarus-xbt.xyz/Videos/057627270372dfed4d8ea15fa9ab5f01/stream?static=true";
const NOTES: &str = "https://files.example/notes?a=1&b=2";

#[test]
fn browse_player_and_connections_follow_the_services_file_and_stop_through_the_signer() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("services.json");
    std::fs::write(&path, format!(r#"[
        {{"name": "Zebra files", "kind": "files", "seller": "https://files.example", "price_text": "5 sat a file",
         "items": [{{"title": "<b>notes</b>", "year": 2020, "url": "{NOTES}", "credit": "CC0"}}]}},
        {{"name": "Alpha films", "kind": "video", "seller": "https://media.lazarus-xbt.xyz", "price_text": "20 sat a MiB",
         "items": [{{"title": "Big Buck Bunny", "year": 2008, "url": "{FILM}", "credit": "(c) Blender Foundation, CC BY 3.0"}}]}}
    ]"#)).unwrap();
    let bx = start(json!({}), false, |c| c.services_file = Some(path.clone()));
    let mut br = logged_in(&bx);
    let mut anon = B::new(&bx.base);
    assert_eq!(anon.get("/browse").location(), "./login");
    assert_eq!(anon.get("/connections").location(), "./login");

    let page = br.get("/browse");
    assert_eq!(page.status, 200);
    assert!(page.body.contains("aria-current=\"page\">Browse"));
    assert!(page.body.contains("href=\"./play\"") && page.body.contains("href=\"./connections\""));
    assert!(page.body.find("Alpha films").unwrap() < page.body.find("Zebra files").unwrap(), "name sort");
    assert!(page.body.contains("&lt;b&gt;notes&lt;/b&gt;") && !page.body.contains("<b>notes</b>"));
    assert!(page.body.contains(&format!("href=\"./play?item={}\"", enc(FILM))));
    assert!(page.headers.get("content-security-policy").is_some_and(|v| v.contains("media-src 'self'")));

    let by_price = br.get("/browse?sort=price").body;
    assert!(by_price.find("Zebra files").unwrap() < by_price.find("Alpha films").unwrap(), "price sort");
    assert!(by_price.contains("selected>Price") || by_price.contains("value=\"price\" selected"));
    let files = br.get("/browse?kind=files").body;
    assert!(files.contains("Zebra files") && !files.contains("Big Buck Bunny"));
    assert!(files.contains("notes?a=1&amp;b=2"));
    let videos = br.get("/browse?kind=video").body;
    assert!(videos.contains("Big Buck Bunny") && !videos.contains("Zebra files"));
    assert!(br.get("/browse?kind=nope").body.contains("No services of this kind"));

    let play = br.get(&format!("/play?item={}", enc(FILM)));
    assert!(play.body.contains("aria-current=\"page\">Player"));
    assert!(play.body.contains(&format!("src=\"./s/{FILM}\"")));
    assert!(play.body.contains("<video controls autoplay"));
    assert!(play.body.contains("CC BY 3.0") && play.body.contains("Stop and cut the connection"));
    assert!(play.body.contains("20 sat a MiB"));
    assert!(br.get("/play").body.contains("Choose a video"));
    assert!(br.get("/play?item=https://media.lazarus-xbt.xyz/missing").body.contains("not in the services file"));
    let notes = br.get(&format!("/play?item={}", enc(NOTES))).body;
    assert!(!notes.contains("<video") && notes.contains("files item"));

    let r = br.post("/play", &[("item", FILM)]);
    assert_eq!(r.status, 403, "a stop without the CSRF token is refused");
    let r = br.act(&format!("/play?item={}", enc(FILM)), "/play", &[("item", FILM)]);
    assert!(br.flash_after(&r).contains("No open session"), "nothing is open with that seller");

    let conn = br.get("/connections");
    assert!(conn.body.contains("aria-current=\"page\">Connections"));
    assert!(conn.body.contains("http-equiv=\"refresh\" content=\"4\""));
    assert!(conn.body.contains("Nothing is open") && conn.body.contains("Cut all"));
    let r = br.act("/connections", "/connections", &[("all", "1")]);
    assert!(br.flash_after(&r).contains("Nothing is open"));
    let r = br.act("/connections", "/connections", &[("session", "not-a-session")]);
    assert!(br.flash_after(&r).contains("No open session"));

    std::fs::remove_file(&path).unwrap();
    let gone = br.get("/browse").body;
    assert!(gone.contains("services file") && gone.contains("XBT_UI_SERVICES") && gone.contains("examples/services.example.json"));
}

/// A TLS node on loopback with the gateway's test certificate (public test data), answering nothing.
fn tls_node() -> (u16, Vec<u8>) {
    use std::sync::Arc;
    let der = |name: &str| {
        use base64::Engine;
        let pem = std::fs::read_to_string(format!("{}/../xbt-gateway/tests/data/node-tls/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        base64::engine::general_purpose::STANDARD.decode(body).unwrap()
    };
    let cert = der("seller.pem");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = Arc::new(rustls::ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_no_client_auth()
        .with_single_cert(vec![rustls::pki_types::CertificateDer::from(cert.clone())],
                          rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(der("seller.key")))).unwrap());
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for sock in l.incoming().flatten() {
            let cfg = cfg.clone();
            std::thread::spawn(move || {
                use std::io::Read;
                let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(cfg).unwrap(), sock);
                let _ = tls.read(&mut [0u8; 1]);
            });
        }
    });
    (port, cert)
}

/// A platform that cannot mount the node's certificate alone (`XBT_UI_LN_TLS_PIN=1`): the Lightning
/// page shows the certificate the node presents and its fingerprint, and pins it when the owner
/// confirms; a fingerprint that is not the node's pins nothing; without the setting there is no
/// card, and the platform's own certificate is used as before.
#[test]
fn the_owner_pins_the_node_certificate_on_a_platform_that_cannot_mount_it() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (port, cert) = tls_node();
    let pinned_dir = tempfile::tempdir().unwrap();
    let pinned = pinned_dir.path().join("tls.cert");
    let p2 = pinned.clone();
    let b = start(json!({}), false, move |c| {
        c.ln.rest = Some(format!("https://127.0.0.1:{port}"));
        c.ln.tls_cert = Some(p2);
        c.ln.pin = true;
    });
    let mut br = logged_in(&b);
    let page = br.get("/lightning").body;
    assert!(page.contains("Pin the node&#39;s certificate") || page.contains("Pin the node's certificate"), "{page}");
    let fp = field(&page, "fingerprint");
    assert_eq!(fp.split(':').count(), 32, "{fp}");
    // a fingerprint that is not the one the node shows: nothing pinned
    let r = br.act("/lightning", "/lightning", &[("action", "pin_cert"), ("fingerprint", "00:11")]);
    assert!(br.flash_after(&r).contains("another certificate"));
    assert!(!pinned.exists());
    // the owner confirms the one shown
    let r = br.act("/lightning", "/lightning", &[("action", "pin_cert"), ("fingerprint", &fp)]);
    assert!(br.flash_after(&r).starts_with("Certificate pinned"));
    let pem = std::fs::read_to_string(&pinned).unwrap();
    assert_eq!(xbt_gateway::node::pem_cert_der(&pem).unwrap(), cert);
    // without the platform's setting: no card, and pinning is refused
    let b2 = start(json!({}), false, |c| c.ln.rest = Some("https://127.0.0.1:1".into()));
    let mut br2 = logged_in(&b2);
    assert!(!br2.get("/lightning").body.contains("name=\"fingerprint\""));
    let r = br2.act("/lightning", "/lightning", &[("action", "pin_cert"), ("fingerprint", &fp)]);
    assert!(br2.flash_after(&r).contains("gives the node's certificate itself"));
}

/// The player's video comes from the page's own origin: the UI relays `/s/<seller URL>` to the
/// connector (which listens on loopback only), for a logged-in owner only, so a player on another
/// device of the network can play it.
#[test]
fn the_ui_relays_the_players_video_from_the_connector_to_a_logged_in_owner() {
    use std::io::{Read, Write};
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let film: Vec<u8> = b"\0\0\0\x20ftypisom".iter().copied().chain((0..200_000u32).map(|i| (i % 251) as u8)).collect();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let connector = format!("http://{}", l.local_addr().unwrap());
    let body = film.clone();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let mut head = [0u8; 4096];
            let n = s.read(&mut head).unwrap_or(0);
            let asked = String::from_utf8_lossy(&head[..n]).to_string();
            if asked.starts_with("GET /s/https://media.lazarus-xbt.xyz/v?static=true ") {
                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: video/mp4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = s.write_all(&body);
            } else {
                let _ = write!(s, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
        }
    });
    let b = start(json!({}), false, move |c| c.connector = connector);
    let mut anon = B::new(&b.base);
    assert_eq!(anon.get("/s/https://media.lazarus-xbt.xyz/v?static=true").status, 401, "not logged in");
    let br = logged_in(&b);
    let resp = br.agent.get(&format!("{}/s/https://media.lazarus-xbt.xyz/v?static=true", b.base)).set("Cookie", &br.cookie).call().unwrap();
    assert_eq!(resp.header("Content-Type"), Some("video/mp4"));
    let mut got = vec![];
    resp.into_reader().read_to_end(&mut got).unwrap();
    assert_eq!(got, film);
}

/// Connected apps: a connection made on the NWC service's admin socket, its URI shown once (in the
/// answer to the form, never stored here), listed with its budget, and revoked.
#[test]
fn connected_apps_make_show_once_list_and_revoke() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    // without the NWC service the page says how to set it up
    let plain = start(json!({}), false, |_| {});
    let mut br = logged_in(&plain);
    let page = br.get("/apps").body;
    assert!(page.contains("aria-current=\"page\">Connected apps"), "{page}");
    assert!(page.contains("XBT_UI_NWC_SOCK"));

    let nwc_dir = tempfile::tempdir().unwrap();
    let mut cfg = xbt_nwc::service::Config::new(nwc_dir.path().join("state"), nwc_dir.path().join("no-signer.sock"));
    cfg.default_relays = vec!["wss://relay.example.com".into()];
    let svc = xbt_nwc::service::Service::new(cfg).unwrap();
    let sock = nwc_dir.path().join("admin.sock");
    let _admin = xbt_nwc::admin::spawn(svc.clone(), &sock, 0o600).unwrap();
    let b = start(json!({}), false, |c| c.nwc_sock = Some(sock.clone()));
    let mut br = logged_in(&b);
    let mut anon = B::new(&b.base);
    assert_eq!(anon.get("/apps").location(), "./login");
    let page = br.get("/apps").body;
    assert!(page.contains("No app is connected"));
    assert!(page.contains("wss://relay.example.com"), "the service's default relays are offered");
    assert_eq!(br.post("/apps-create", &[("name", "x"), ("budget_sats_per_day", "10")]).status, 403, "no CSRF token");

    let form = [("name", "Phone <wallet>"), ("budget_sats_per_day", "2500"), ("expires_in_s", "604800"), ("m_pay_invoice", "1"),
                ("m_get_info", "1"), ("relays", "wss://relay.example.com\nwss://relay.example.org")];
    let made = br.act("/apps", "/apps-create", &form);
    assert_eq!(made.status, 200, "{}", made.body);
    assert_eq!(made.headers.get("cache-control").map(String::as_str), Some("no-store"));
    assert_eq!(made.body.matches("nostr+walletconnect://").count(), 1);
    assert!(made.body.contains("data-copy=\"nwc-uri\""));
    assert!(made.body.contains("only time"));
    let at = made.body.find("nostr+walletconnect://").unwrap();
    let uri = unescape(made.body[at..].split('"').next().unwrap());
    let parsed = xbt_nwc::client::Uri::parse(&uri).unwrap();
    assert_eq!(parsed.relays, vec!["wss://relay.example.com", "wss://relay.example.org"]);
    // never again: not on the page, not in the UI's data dir
    let page = br.get("/apps").body;
    assert!(!page.contains("nostr+walletconnect://") && !page.contains(&parsed.secret.secret_hex()));
    assert!(page.contains("Phone &lt;wallet&gt;") && !page.contains("Phone <wallet>"));
    assert!(page.contains("pay_invoice get_info") && page.contains("2,500 sats"));
    for f in walk(b.data.path()) {
        let t = std::fs::read(&f).unwrap_or_default();
        assert!(!String::from_utf8_lossy(&t).contains(&parsed.secret.secret_hex()), "{}", f.display());
    }
    let listed = svc.list();
    assert_eq!(listed["connections"][0]["methods"], json!(["pay_invoice", "get_info"]));
    assert_eq!(listed["connections"][0]["budget_sats_per_day"], 2500);

    let r = br.act("/apps", "/apps-create", &[("name", "bad"), ("budget_sats_per_day", "0"), ("expires_in_s", "0"), ("m_get_info", "1")]);
    assert!(br.flash_after(&r).contains("Not made"));

    let id = field(&br.get("/apps").body, "id");
    let r = br.act("/apps", "/apps-revoke", &[("id", &id)]);
    assert!(br.flash_after(&r).contains("Revoked"));
    assert!(br.get("/apps").body.contains("No app is connected"));
    assert_eq!(svc.list()["connections"], json!([]));
}

fn walk(d: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = vec![];
    for e in std::fs::read_dir(d).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}
