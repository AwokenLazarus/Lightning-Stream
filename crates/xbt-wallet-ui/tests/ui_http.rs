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
    // paying on already: the page edits the rules in force (with paying off it opens on the starter rules)
    let bx = start(json!({"ln": {"enabled": true}}), false, |_| {});
    let mut br = logged_in(&bx);
    let page = br.get("/policy").body;
    assert!(page.contains("name=\"f_human_threshold_sats\" value=\"1000\""));
    assert!(!page.contains("Paying is not turned on yet") && page.contains("Start from the safe starter rules"), "{page}");
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
    assert!(prev.contains("Ask me first for a payment of at least: 5,000 sats (was 1,000 sats)"), "{prev}");
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
    assert!(br.flash_after(&r).contains("waits for the app to restart (How often the records are sealed)"), "{}", br.flash_after(&r));
    assert!(br.get("/policy").body.contains("waiting for the app to restart: How often the records are sealed"));
    assert!(br.post("/policy", &[("csrf", &csrf), ("mode", "json"), ("json", "{nope")]).body.contains("policy.json: key must be a string"));
    // the template
    assert!(br.get("/policy?template=starter").body.contains("name=\"f_max_per_tx_sats\" value=\"100000\""));
}

#[test]
fn with_paying_off_the_rules_page_opens_on_the_starter_rules_and_signing_them_turns_paying_on() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |_| {});
    let mut br = logged_in(&bx);
    let page = br.get("/policy").body;
    assert!(page.contains("Paying is not turned on yet, so the safe starter rules are filled in below"), "{page}");
    assert!(page.contains("name=\"f_max_per_tx_sats\" value=\"100000\""), "the starter value, not the rule in force");
    // the node's limit: shown in words, empty off mainnet (not required there)
    assert!(page.contains("The most your Lightning node may hold that this app trusts it with (sats)"), "{page}");
    assert!(page.contains("name=\"f_ln_exposure_cap_sats\" value=\"\""), "{page}");
    // what is posted: the starter's Lightning and ticket sections come along, and a cap typed in lands in ln
    let mut f = policy_form_fields(&page);
    f.push(("f_ln_exposure_cap_sats".into(), "120000".into()));
    let prev = br.post("/policy", &f.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect::<Vec<_>>()).body;
    let signed: Value = serde_json::from_str(&field(&prev, "text")).unwrap();
    assert_eq!((signed["ln"]["enabled"].clone(), signed["ln"]["exposure_cap_sats"].clone(), signed["tickets"]["enabled"].clone()),
               (json!(true), json!(120000), json!(true)), "{signed}");
    // emptied: taken out of ln, the rest of ln kept
    f.iter_mut().find(|(k, _)| k == "f_ln_exposure_cap_sats").unwrap().1 = "".into();
    let prev = br.post("/policy", &f.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect::<Vec<_>>()).body;
    let signed: Value = serde_json::from_str(&field(&prev, "text")).unwrap();
    assert!(signed["ln"].get("exposure_cap_sats").is_none() && signed["ln"]["enabled"] == json!(true), "{signed}");
}

#[test]
fn the_mainnet_starter_rules_set_the_node_s_exposure_cap_from_what_it_holds() {
    use xbt_wallet_ui::app::{starter_exposure_cap, starter_policy, starter_policy_for, STARTER_EXPOSURE_CAP_SATS};
    assert_eq!(STARTER_EXPOSURE_CAP_SATS, 100_000);
    // twice what the channels hold, rounded up to 10,000, never below the least cap
    for (held, cap) in [(0, 100_000), (29_692, 100_000), (50_000, 100_000), (50_001, 110_000), (70_000, 140_000), (-5, 100_000), (i64::MAX, i64::MAX / 10_000 * 10_000)] {
        assert_eq!(starter_exposure_cap(held), cap, "held {held}");
    }
    let m = starter_policy("main");
    // exactly the Lightning section the signer's mainnet readiness test signs (xbt-signer tests/ln_rail.rs)
    assert_eq!(m["ln"], json!({"enabled": true, "split_height": xbt_wallet_ui::app::MAINNET_SPLIT_HEIGHT, "exposure_cap_sats": 100_000}));
    assert_eq!(starter_policy_for("main", Some(70_000))["ln"]["exposure_cap_sats"], json!(140_000));
    // off mainnet the signer needs no cap: none is set
    assert!(starter_policy_for("regtest", Some(70_000))["ln"].get("exposure_cap_sats").is_none());
    assert!(xbt_signer::policy::validate_policy(&m).0.is_empty(), "{m}");
}

/// On mainnet the app pays nothing until the owner confirms paying with real money: setup lists that
/// step straight after the rules, the rules page says so with a link to it, and neither calls the
/// wallet ready. Once the confirmation is on file, both are gone.
#[test]
fn on_mainnet_setup_and_the_rules_page_ask_for_the_real_money_confirmation() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let ack = tempfile::tempdir().unwrap();
    let ack_file = ack.path().join("mainnet-ack");
    std::env::set_var(xbt_signer::ticket::MAINNET_ACK_ENV, &ack_file);
    let policy = json!({"ln": {"enabled": true, "exposure_cap_sats": 100_000}, "tickets": {"enabled": true, "tasks": {"default": {"budget_sats": 10_000}}}});
    let b = start_on(Rig::build(policy, false, "main"), |_| {});
    let mut br = logged_in(&b);
    assert_eq!(b.rig.call("ln_status", json!({}))["real_money_ack_needed"], true);
    let setup = unescape(&br.get("/setup").body);
    let (rules, ack_step) = (setup.find("Your spending rules").unwrap(), setup.find("Pay with real money").expect("the step is listed"));
    assert!(rules < ack_step && ack_step < setup.find("Your Lightning node").unwrap(), "straight after the rules");
    assert!(setup.contains("./lightning#ack") && !setup.contains("Connected and ready to pay"), "{setup}");
    let page = unescape(&br.get("/policy").body);
    assert!(page.contains("pays nothing until you confirm") && page.contains("./lightning#ack"), "{page}");
    // a refused buy says what to do, in words
    let off = xbt_signer::ticket::TicketPolicy::for_chain(&serde_json::Map::new(), "main", false);
    assert!(off.mainnet_off.is_none(), "tickets off by policy: no confirmation asked");
    // confirmed: the step and the warning are gone
    std::fs::write(&ack_file, format!("{}\n", xbt402::ticket::MAINNET_ACK)).unwrap();
    assert_eq!(b.rig.call("ln_status", json!({}))["real_money_ack_needed"], false);
    assert!(!unescape(&br.get("/setup").body).contains("Pay with real money"));
    assert!(!unescape(&br.get("/policy").body).contains("pays nothing until you confirm"));
    std::env::remove_var(xbt_signer::ticket::MAINNET_ACK_ENV);
}

/// Every field of the policy form on `page`, as a browser would post it.
fn policy_form_fields(page: &str) -> Vec<(String, String)> {
    let mut form: Vec<(String, String)> = vec![("csrf".into(), field(page, "csrf")), ("mode".into(), "form".into())];
    for k in ["max_per_tx_sats", "daily_budget_sats", "weekly_budget_sats", "per_counterparty_cap_sats", "human_threshold_sats", "approval_ttl_s",
              "split_window_s", "velocity_max", "velocity_window_s", "hot_balance_cap_sats", "anchor_interval_s", "treasury_csv"] {
        form.push((format!("f_{k}"), field(page, &format!("f_{k}"))));
    }
    form.push(("f_allowlist".into(), PROVIDER.into()));
    form.push(("f_unseen".into(), field(page, "f_unseen")));
    form
}

fn sign_policy_form(br: &mut B, form: &[(String, String)]) -> String {
    let csrf = form[0].1.clone();
    let prev = br.post("/policy", &form.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect::<Vec<_>>()).body;
    assert!(prev.contains("Sign and apply"), "{prev}");
    let (text, sha, exp) = (field(&prev, "text"), field(&prev, "prev_sha256"), field(&prev, "expiry"));
    let r = br.post("/policy-apply", &[("csrf", &csrf), ("text", &text), ("prev_sha256", &sha), ("expiry", &exp),
                                        ("signature", &sig(&policy_message(&sha, exp.parse().unwrap(), &text)))]);
    br.flash_after(&r)
}

#[test]
fn signing_the_starter_rules_turns_paying_over_lightning_and_tickets_on() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |_| {});
    let mut br = logged_in(&bx);
    assert!(bx.rig.call("policy_get", json!({}))["policy"].get("ln").is_none(), "a fresh box has no Lightning section");
    let page = br.get("/policy?template=starter").body;
    let flash = sign_policy_form(&mut br, &policy_form_fields(&page));
    assert!(flash.starts_with("Policy applied"), "{flash}");
    let p = bx.rig.call("policy_get", json!({}))["policy"].clone();
    assert_eq!(p["ln"]["enabled"], true, "{p}");
    assert_eq!(p["tickets"]["enabled"], true, "{p}");
    assert!(p["tickets"]["tasks"]["default"]["budget_sats"].as_i64().unwrap() > 0, "{p}");
}

#[test]
fn editing_one_rule_keeps_every_section_the_form_does_not_show() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({"ln": {"enabled": true, "max_fee_ppm": 4000}, "tickets": {"enabled": true, "tasks": {"films": {"budget_sats": 700}}}}), false, |_| {});
    let mut br = logged_in(&bx);
    let page = br.get("/policy").body;
    let mut form = policy_form_fields(&page);
    form.iter_mut().find(|(k, _)| k == "f_human_threshold_sats").unwrap().1 = "4000".into();
    let flash = sign_policy_form(&mut br, &form);
    assert!(flash.starts_with("Policy applied"), "{flash}");
    let p = bx.rig.call("policy_get", json!({}))["policy"].clone();
    assert_eq!(p["human_threshold_sats"], 4000);
    assert_eq!(p["ln"]["max_fee_ppm"], 4000, "{p}");
    assert_eq!(p["tickets"]["tasks"]["films"]["budget_sats"], 700, "{p}");
    // a form posted without the carried sections (an old page) still removes nothing
    let page = br.get("/policy").body;
    let mut form = policy_form_fields(&page);
    form.retain(|(k, _)| k != "f_unseen");
    form.iter_mut().find(|(k, _)| k == "f_human_threshold_sats").unwrap().1 = "3000".into();
    sign_policy_form(&mut br, &form);
    let p = bx.rig.call("policy_get", json!({}))["policy"].clone();
    assert_eq!(p["ln"]["max_fee_ppm"], 4000, "{p}");
    assert_eq!(p["tickets"]["tasks"]["films"]["budget_sats"], 700, "{p}");
}

#[test]
fn enrol_and_replace_the_human_key_then_sweep_rotate_backup_and_anchor() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({"human_pubkey": ""}), true, |_| {});
    bx.rig.fund_hot(1, 20_000);
    let mut br = logged_in(&bx);
    let setup = br.get("/setup").body;
    assert!(setup.contains("id=\"keygen\"") && setup.contains("./human-key-enroll"));
    assert!(br.get("/wallet").body.contains("No approval key yet"));
    assert!(br.get("/").body.contains("Finish setting up"), "home says what is left to do");
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
    let ov = br.get("/wallet").body;
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
    assert!(page.contains("http://umbrel.local:33510/mcp") && page.contains("No token in"), "{page}");
    // as xbt-init leaves it on a box: 0640, the MCP reads it by group
    xbt_svc::replace_secret_file(&tok, format!("{}\n", "ab".repeat(32)).as_bytes(), 0o640).unwrap();
    let page = br.get("/agents").body;
    assert!(page.contains(&"ab".repeat(32)) && page.contains("Bearer ") && page.contains("<details>"), "{page}");
    assert!(page.contains("aria-current=\"page\">AI agents") && page.contains("Rotate the token"), "{page}");
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
    let page = br.get("/wallet").body;
    assert!(page.contains("id=\"cmp-status\"") && page.contains(">up</span>") && page.contains("node_sync_pct") && page.contains("99.7"), "{page}");
    assert!(page.contains("href=\"http://umbrel.local:3900/\" target=\"_blank\" rel=\"noopener noreferrer\""));
    drop(bx);
    let bx = start(json!({}), false, |c| c.cmp_status_url = Some("http://127.0.0.1:1/readyz".into()));
    let mut br = logged_in(&bx);
    assert!(br.get("/wallet").body.contains("unreachable"), "a down cmp shows as unreachable, the page still renders");
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
    // renting miners pays under its own task: there from the start, low on mainnet, and only to listed sellers
    assert!(m["tickets"]["tasks"]["hashrate"]["budget_sats"].as_i64().unwrap() <= 5000 && t["tickets"]["tasks"]["hashrate"]["budget_sats"].as_i64().unwrap() > 0);
    assert!(m["tickets"]["tasks"]["hashrate"].get("admit").is_none());
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
    assert!(page.contains(">Lightning Stream<") && page.contains("<h1>Sell</h1>") && page.contains("invoices:read invoices:write") && !page.contains("Approvals"), "{page}");
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
    assert!(unescape(&r.body).contains(xbt_gateway::config::MAINNET_ACK) && unescape(&r.body).contains("small amounts only"), "{}", r.body);
    let r = send(&mut br, form("https://seller.example", "", "main", xbt_gateway::config::MAINNET_ACK));
    assert!(br.flash_after(&r).contains("mainnet"));
    let c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    assert_eq!((c["chain"].as_str(), c["mainnet_ack"].as_str()), (Some("main"), Some(xbt_gateway::config::MAINNET_ACK)));
    assert_eq!((c["caps"]["max_sessions"].as_u64(), c["caps"]["max_held_tickets"].as_u64()), (Some(4), Some(4)));
    assert!(c.get("network").is_none());
    xbt_gateway::config::Config::from_json(&c).unwrap();
}

const FILM: &str = "https://stream.lazarus-xbt.xyz/Videos/057627270372dfed4d8ea15fa9ab5f01/stream?static=true";
const NOTES: &str = "https://files.example/notes?a=1&b=2";

#[test]
fn browse_player_and_connections_follow_the_services_file_and_stop_through_the_signer() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("services.json");
    std::fs::write(&path, format!(r#"[
        {{"name": "Zebra files", "kind": "files", "seller": "https://files.example", "price_text": "5 sat a file",
         "items": [{{"title": "<b>notes</b>", "year": 2020, "url": "{NOTES}", "credit": "CC0"}}]}},
        {{"name": "Alpha films", "kind": "video", "seller": "https://stream.lazarus-xbt.xyz", "price_text": "20 sat a MiB",
         "items": [{{"title": "Big Buck Bunny", "year": 2008, "url": "{FILM}", "credit": "(c) Blender Foundation, CC BY 3.0"}}]}}
    ]"#)).unwrap();
    let bx = start(json!({}), false, |c| c.services_file = Some(path.clone()));
    let mut br = logged_in(&bx);
    let mut anon = B::new(&bx.base);
    assert_eq!(anon.get("/browse").location(), "./login");
    assert_eq!(anon.get("/connections").location(), "./login");

    let page = br.get("/browse");
    assert_eq!(page.status, 200);
    assert!(page.body.contains("aria-current=\"page\">Browse") && page.body.contains("aria-current=\"page\">Services"));
    assert!(page.body.contains("href=\"./services\"") && page.body.contains("href=\"./connections\""));
    assert!(page.body.find("Alpha films").unwrap() < page.body.find("Zebra files").unwrap(), "name sort");
    assert!(page.body.contains(">Media <") && page.body.contains(">Data &amp; APIs <"), "the categories, media one of them");
    assert!(!page.body.contains("Big Buck Bunny"), "Browse lists services, not what a media service has inside");
    assert!(page.headers.get("content-security-policy").is_some_and(|v| v.contains("media-src 'self'")));
    // a media service's own page lists what it plays
    let media = br.get(&format!("/service?seller={}&name={}", enc("https://stream.lazarus-xbt.xyz"), enc("Alpha films"))).body;
    assert!(media.contains("Big Buck Bunny") && media.contains(&format!("href=\"./play?item={}\"", enc(FILM))), "{media}");
    // any other service's page: its address for apps and agents, no player
    let files = br.get(&format!("/service?seller={}&name={}", enc("https://files.example"), enc("Zebra files"))).body;
    assert!(files.contains("&lt;b&gt;notes&lt;/b&gt;") && !files.contains("<b>notes</b>"));
    assert!(files.contains("notes?a=1&amp;b=2") && files.contains("Connect an AI agent") && !files.contains("./play?"), "{files}");
    assert!(br.get("/service?seller=https://x.example&name=x").body.contains("not in your list"));

    let by_price = br.get("/browse?sort=price").body;
    assert!(by_price.find("Zebra files").unwrap() < by_price.find("Alpha films").unwrap(), "price sort");
    assert!(by_price.contains("aria-current=\"true\">price"));
    let data = br.get("/browse?cat=data").body;
    assert!(data.contains("Zebra files") && !data.contains("Alpha films"));
    let old_link = br.get("/browse?kind=video").body;
    assert!(old_link.contains("Alpha films") && !old_link.contains("Zebra files"), "a kind names its category");
    assert!(br.get("/browse?cat=ai").body.contains("No services in this category yet"));

    let play = br.send("GET", &format!("/play?item={}", enc(FILM)), None, &[("Sec-Fetch-Site", "same-origin")]);
    assert!(play.body.contains("aria-current=\"page\">Services"));
    let token = xbt_wallet_ui::app::stream_token(&field(&play.body, "csrf"));
    assert!(play.body.contains(&format!("src=\"./s/~{token}/{FILM}\"")), "the video carries the session's stream token");
    assert!(play.body.contains("<video controls autoplay"));
    // opened by a browser that does not say from where: it waits for Play
    assert!(!br.get(&format!("/play?item={}", enc(FILM))).body.contains("autoplay"));
    assert!(play.body.contains("CC BY 3.0") && play.body.contains("Stop and cut the connection"));
    assert!(play.body.contains("20 sat a MiB") && play.body.contains("<h1>Big Buck Bunny</h1>"));
    assert!(br.get("/play").body.contains("Choose something to play"));
    assert!(br.get("/play?item=https://stream.lazarus-xbt.xyz/missing").body.contains("not in your list of services"));
    let notes = br.get(&format!("/play?item={}", enc(NOTES))).body;
    assert!(!notes.contains("<video") && notes.contains("not something to play"));

    let r = br.post("/play", &[("item", FILM)]);
    assert_eq!(r.status, 403, "a stop without the CSRF token is refused");
    let r = br.act(&format!("/play?item={}", enc(FILM)), "/play", &[("item", FILM)]);
    assert!(br.flash_after(&r).contains("No open connection"), "nothing is open with that seller");

    let conn = br.get("/connections");
    assert!(conn.body.contains("aria-current=\"page\">Live connections"));
    assert!(conn.body.contains("http-equiv=\"refresh\" content=\"4\""));
    assert!(conn.body.contains("Nothing is open"));
    let r = br.act("/connections", "/connections", &[("all", "1")]);
    assert!(br.flash_after(&r).contains("Nothing is open"));
    let r = br.act("/connections", "/connections", &[("session", "not-a-session")]);
    assert!(br.flash_after(&r).contains("not open any more"));

    std::fs::remove_file(&path).unwrap();
    let gone = br.get("/browse").body;
    assert!(gone.contains("services file") && gone.contains("Add a seller") && gone.contains("href=\"./services\""));
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
            if asked.starts_with("GET /s/https://stream.lazarus-xbt.xyz/v?static=true ") {
                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: video/mp4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = s.write_all(&body);
            } else {
                let _ = write!(s, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
        }
    });
    let b = start(json!({}), false, move |c| c.connector = connector);
    let mut anon = B::new(&b.base);
    assert_eq!(anon.get("/s/https://stream.lazarus-xbt.xyz/v?static=true").status, 401, "not logged in");
    let br = logged_in(&b);
    let mut br = br;
    let token = xbt_wallet_ui::app::stream_token(&field(&br.get("/browse").body, "csrf"));
    let resp = br.agent.get(&format!("{}/s/~{token}/https://stream.lazarus-xbt.xyz/v?static=true", b.base)).set("Cookie", &br.cookie).call().unwrap();
    assert_eq!(resp.header("Content-Type"), Some("video/mp4"));
    let mut got = vec![];
    resp.into_reader().read_to_end(&mut got).unwrap();
    assert_eq!(got, film);
}

/// A page on another port of this host (another app of the box) is of the same site: the browser
/// sends the wallet's cookie with what it asks, `SameSite=Strict` notwithstanding. It must not be
/// able to have the wallet stream, and pay for, what it names, nor act with the owner's session:
/// not in a browser that says where a request comes from (`Sec-Fetch-Site`), and not in an older
/// one that does not.
#[test]
fn a_page_on_another_port_of_the_box_cannot_make_the_wallet_pay_or_act() {
    use std::io::{Read, Write};
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    // a connector that serves whatever it is asked for, and notes what that was
    let asked: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let connector = format!("http://{}", l.local_addr().unwrap());
    let seen = asked.clone();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let mut head = [0u8; 4096];
            let n = s.read(&mut head).unwrap_or(0);
            let line = String::from_utf8_lossy(&head[..n]).lines().next().unwrap_or("").to_string();
            seen.lock().unwrap().push(line);
            let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: video/mp4\r\nContent-Length: 4\r\nConnection: close\r\n\r\nfilm");
        }
    });
    let b = start(json!({}), false, move |c| c.connector = connector);
    let mut br = logged_in(&b);
    let evil = "/s/https://evil.example/evil-film";
    // a <video> on another port, in a browser that says so
    let video = [("Sec-Fetch-Site", "same-site"), ("Sec-Fetch-Mode", "no-cors"), ("Sec-Fetch-Dest", "video")];
    assert_eq!(br.send("GET", evil, None, &video).status, 403, "a stream asked by another page");
    // the same in an older browser, which sends the cookie and says nothing else
    let r = br.send("GET", evil, None, &[]);
    assert!(r.status == 403 || r.status == 404, "a stream named by a page that cannot know this session's stream token: {}", r.status);
    assert!(asked.lock().unwrap().is_empty(), "nothing reached the connector: {:?}", asked.lock().unwrap());
    // an action with the right token even, from another page: by Sec-Fetch-Site, and by Origin in an older browser
    let csrf = field(&br.get("/browse").body, "csrf");
    let form = format!("csrf={}", enc(&csrf));
    assert_eq!(br.send("POST", "/logout", Some(&form), &[("Sec-Fetch-Site", "same-site")]).status, 403);
    assert_eq!(br.send("POST", "/logout", Some(&form), &[("Origin", "http://127.0.0.1:9")]).status, 403, "an older browser's Origin");
    assert_eq!(br.send("POST", "/logout", Some(&form), &[("Referer", "http://127.0.0.1:9/x")]).status, 403, "and its Referer, with no Origin");
    // a page another page opens is the home page, never the page it named
    let nav = [("Sec-Fetch-Site", "same-site"), ("Sec-Fetch-Mode", "navigate"), ("Sec-Fetch-Dest", "document")];
    let r = br.send("GET", "/play?item=https://evil.example/evil-film", None, &nav);
    assert_eq!((r.status, r.location()), (303, "/"));
    let r = br.send("GET", "/play?item=x", None, &[("Referer", "http://127.0.0.1:9/x")]);
    assert_eq!((r.status, r.location()), (303, "/"), "an older browser opened from another page");
    assert_eq!(br.send("GET", "/", None, &nav).status, 200, "the box's dashboard opens the app");
    // the wallet's own pages, as before
    assert_eq!(br.send("GET", "/browse", None, &[("Sec-Fetch-Site", "same-origin")]).status, 200);
    let own = b.base.clone();
    assert_eq!(br.send("GET", "/browse", None, &[("Referer", &format!("{own}/"))]).status, 200);
    assert_eq!(br.send("POST", "/logout", Some(&form), &[("Sec-Fetch-Site", "same-origin"), ("Origin", &own)]).status, 303);
}

/// Each request a connector got: its path and its `Range`.
type Seen = Arc<std::sync::Mutex<Vec<(String, Option<String>)>>>;

/// A connector on loopback that answers `/s/<FILM>` with the film, or the part a `Range` names as a
/// 206, and records each request's path and `Range`.
fn range_connector(film: Vec<u8>) -> (String, Seen) {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let connector = format!("http://{}", l.local_addr().unwrap());
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let mut head = [0u8; 8192];
            let n = s.read(&mut head).unwrap_or(0);
            let asked = String::from_utf8_lossy(&head[..n]).to_string();
            let path = asked.split(' ').nth(1).unwrap_or("").to_string();
            let range = asked.lines().find_map(|l| l.strip_prefix("Range: ").or_else(|| l.strip_prefix("range: "))).map(str::to_string);
            log.lock().unwrap().push((path.clone(), range.clone()));
            if path != format!("/s/{FILM}") {
                let _ = write!(s, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                continue;
            }
            let from = range.as_deref().and_then(|r| r.strip_prefix("bytes=")).and_then(|r| r.strip_suffix('-')).and_then(|a| a.parse::<usize>().ok());
            match from {
                Some(a) => {
                    let _ = write!(s, "HTTP/1.1 206 Partial Content\r\nContent-Type: video/mp4\r\nAccept-Ranges: bytes\r\nContent-Range: bytes {a}-{}/{}\r\n\
                                       Content-Length: {}\r\nConnection: close\r\n\r\n", film.len() - 1, film.len(), film.len() - a);
                    let _ = s.write_all(&film[a..]);
                }
                None => {
                    let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: video/mp4\r\nAccept-Ranges: bytes\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", film.len());
                    let _ = s.write_all(&film);
                }
            }
        }
    });
    (connector, seen)
}

/// Seeking through the relay, and the links for VLC and mpv: the player's `Range` reaches the
/// connector and its 206 comes back with its range; a link is made by a logged-in POST with the
/// CSRF token, plays its one item without a cookie, names no other, and stops when it is revoked
/// or expires.
#[test]
fn the_relay_passes_range_and_a_players_link_plays_its_one_item_until_it_expires() {
    use std::io::Read;
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let film: Vec<u8> = b"\0\0\0\x20ftypisom".iter().copied().chain((0..200_000u32).map(|i| (i % 251) as u8)).collect();
    let (connector, seen) = range_connector(film.clone());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("services.json");
    std::fs::write(&path, format!(r#"[
        {{"name": "Films", "kind": "video", "seller": "https://stream.lazarus-xbt.xyz", "price_text": "20 sat a MiB",
         "items": [{{"title": "Big Buck Bunny", "year": 2008, "url": "{FILM}", "credit": "CC BY 3.0"}}]}},
        {{"name": "Files", "kind": "files", "seller": "https://files.example", "price_text": "5 sat a file",
         "items": [{{"title": "notes", "year": 2020, "url": "{NOTES}", "credit": "CC0"}}]}}
    ]"#)).unwrap();
    let ttl = Duration::from_secs(3);
    let services = path.clone();
    let b = start(json!({}), false, move |c| {
        c.connector = connector;
        c.services_file = Some(services);
        c.relay_ttl = ttl;
    });
    let mut br = logged_in(&b);
    let mut anon = B::new(&b.base);
    let get_range = |url: &str, cookie: Option<&str>, range: Option<&str>| {
        let mut rq = ureq::AgentBuilder::new().redirects(0).build().get(url);
        if let Some(c) = cookie {
            rq = rq.set("Cookie", c);
        }
        if let Some(r) = range {
            rq = rq.set("Range", r);
        }
        let resp = match rq.call() {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => panic!("{url}: {e}"),
        };
        let headers: HashMap<String, String> = resp.headers_names().iter().map(|n| (n.to_ascii_lowercase(), resp.header(n).unwrap_or("").to_string())).collect();
        let status = resp.status();
        let mut body = vec![];
        resp.into_reader().read_to_end(&mut body).unwrap();
        (status, headers, body)
    };

    // the page's player seeks: the Range goes to the connector, the 206 comes back with its headers
    let st = xbt_wallet_ui::app::stream_token(&field(&br.get("/browse").body, "csrf"));
    let (status, h, body) = get_range(&format!("{}/s/~{st}/{FILM}", b.base), Some(&br.cookie), Some("bytes=1000-"));
    assert_eq!(status, 206);
    assert_eq!((h.get("content-range").map(String::as_str), h.get("accept-ranges").map(String::as_str), h.get("content-type").map(String::as_str)),
               (Some(format!("bytes 1000-{}/{}", film.len() - 1, film.len()).as_str()), Some("bytes"), Some("video/mp4")));
    assert_eq!(h.get("content-length").map(String::as_str), Some((film.len() - 1000).to_string().as_str()));
    assert_eq!(body, film[1000..]);
    assert_eq!(seen.lock().unwrap().last().unwrap(), &(format!("/s/{FILM}"), Some("bytes=1000-".to_string())));
    let (status, _, body) = get_range(&format!("{}/s/~{st}/{FILM}", b.base), Some(&br.cookie), None);
    assert_eq!((status, body.len()), (200, film.len()));
    assert_eq!(seen.lock().unwrap().last().unwrap().1, None, "no Range where the player sent none");

    // a link is made only by a logged-in POST with the CSRF token, for a video of the services file
    let play = format!("/play?item={}", enc(FILM));
    assert!(br.get(&play).body.contains("Play in VLC, mpv or another player") && br.get(&play).body.contains("Make a link"));
    assert_eq!(anon.post("/play-link", &[("action", "create"), ("item", FILM)]).location(), "./login");
    assert_eq!(br.post("/play-link", &[("action", "create"), ("item", FILM)]).status, 403, "no CSRF token");
    let r = br.act(&play, "/play-link", &[("action", "create"), ("item", NOTES)]);
    assert!(br.flash_after(&r).contains("not a video"));
    let r = br.act(&play, "/play-link", &[("action", "create"), ("item", FILM)]);
    assert!(br.flash_after(&r).contains("Link made"));
    let page = br.get(&play).body;
    let at = page.find("/r/").expect("the page shows the link");
    let token = page[at + 3..at + 3 + 64].to_string();
    assert!(token.bytes().all(|c| c.is_ascii_hexdigit()));
    assert!(page.contains(&format!("value=\"{}/r/{token}\"", b.base)), "the exact address to paste");
    assert!(page.contains("Revoke"));

    // the link plays its item with no cookie, seeking included
    let link = format!("{}/r/{token}", b.base);
    let (status, h, body) = get_range(&link, None, Some("bytes=5000-"));
    assert_eq!((status, h.get("content-range").cloned()), (206, Some(format!("bytes 5000-{}/{}", film.len() - 1, film.len()))));
    assert_eq!(body, film[5000..]);
    assert_eq!(seen.lock().unwrap().last().unwrap().0, format!("/s/{FILM}"));
    // and only that item: the request names no other, another token is nothing, and nothing else of the UI opens with it
    let n = seen.lock().unwrap().len();
    let (status, _, body) = get_range(&format!("{link}?item={}", enc(NOTES)), None, None);
    assert_eq!((status, body.len()), (200, film.len()));
    assert_eq!(seen.lock().unwrap()[n].0, format!("/s/{FILM}"), "the token's item, whatever the request says");
    let other = format!("{}{}", &token[..63], if token.ends_with('0') { "1" } else { "0" });
    for refused in [format!("{}/r/{other}", b.base), format!("{link}/x"), format!("{}/r/", b.base), format!("{}/s/{NOTES}", b.base), format!("{}/s/{FILM}", b.base)] {
        let (status, _, _) = get_range(&refused, None, None);
        assert!(status == 404 || status == 401, "{refused}: {status}");
    }
    assert_eq!(seen.lock().unwrap().len(), n + 1, "nothing refused reached the connector");
    assert_eq!(anon.get("/play").location(), "./login", "the link is no login");

    // revoked: it plays nothing
    let r = br.act(&play, "/play-link", &[("action", "revoke"), ("item", FILM), ("token", &token)]);
    assert!(br.flash_after(&r).contains("revoked"));
    assert_eq!(get_range(&link, None, None).0, 404);
    // a new one expires on its own
    let r = br.act(&play, "/play-link", &[("action", "create"), ("item", FILM)]);
    assert!(br.flash_after(&r).contains("Link made"));
    let page = br.get(&play).body;
    let at = page.find("/r/").unwrap();
    let fresh = format!("{}/r/{}", b.base, &page[at + 3..at + 3 + 64]);
    assert_eq!(get_range(&fresh, None, None).0, 200);
    std::thread::sleep(ttl + Duration::from_millis(300));
    assert_eq!(get_range(&fresh, None, None).0, 404, "expired");
    assert!(!br.get(&play).body.contains("/r/"), "an expired link is not shown");
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
    assert!(page.contains("aria-current=\"page\">Apps") && page.contains("not set up on this box"), "{page}");
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

/// The one Lightning Stream app (`XBT_UI_SELL=1`): Sell sets up the gateway beside the wallet in
/// plain words, one service at a time, and writes a config the gateway takes.
#[cfg(unix)]
#[test]
fn the_sell_page_sets_up_several_services_and_says_what_each_one_needs() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let gw = tempfile::tempdir().unwrap();
    let dir = gw.path().to_path_buf();
    let media = mock_http(|_| (200, "ok"));
    let bx = start(json!({}), false, |c| {
        c.sell = true;
        c.gw.dir = dir.clone();
        c.gw.node_rest = Some("https://10.21.21.66:8180".into());
        c.gw.node_tls_cert = Some("/data/lightning/tls.cert".into());
        c.hash.slices = Some("http://127.0.0.1:9".into());
        c.hash.settings = dir.join("hashrate-settings.json");
        c.nostr_relays = vec!["wss://relay.one.example".into(), "wss://relay.two.example".into()];
    });
    let mut br = logged_in(&bx);
    let page = br.get("/sell").body;
    assert!(page.contains(">Lightning Stream<") && page.contains("href=\"./sell\"") && page.contains("href=\"./browse\""), "{page}");
    assert!(page.contains("Not selling yet") && page.contains("Connect your Lightning node"), "{page}");
    // plain words on the main screen; the gateway's own terms only inside the collapsed parts
    let main_part = page[page.find("<main").unwrap()..].split("<details").next().unwrap().replace("<em>Macaroons</em>", "");
    // the words a person reads: the text between the tags
    let main_part: String = main_part.split('<').map(|s| s.split_once('>').map(|(_, t)| t).unwrap_or(s)).collect::<String>().to_ascii_lowercase();
    for jargon in ["macaroon", "msat", "upstream", "htlc", "receipt key", "cltv"] {
        assert!(!main_part.contains(jargon), "{jargon} on the main screen");
    }
    let inv = mac(&[("invoices", &["read", "write"])]);
    let info = mac(&[("info", &["read"])]);
    let wide = mac(&[("invoices", &["read", "write"]), ("offchain", &["write"])]);
    let r = br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &wide), ("info_macaroon", &info)]);
    assert!(br.flash_after(&r).contains("does not fit"));
    let r = br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &inv), ("info_macaroon", &info)]);
    let f = br.flash_after(&r);
    assert!(f.contains("connected") && f.contains("Say where buyers find you"), "{f}");
    assert!(!br.get("/sell").body.contains("1. Connect your Lightning node"), "step 1 is done");
    let r = br.act("/sell", "/sell", &[("action", "shop"), ("name", "Mike's box"), ("public_url", "http://seller.example")]);
    assert_eq!(r.status, 200);
    assert!(unescape(&r.body).contains("https:// address"), "said in a sentence, on the page kept as typed");
    let r = br.act("/sell", "/sell", &[("action", "shop"), ("name", "Mike's box"), ("public_url", "https://seller.example/")]);
    assert!(br.flash_after(&r).contains("network id"), "a test chain asks for its network under Advanced");
    let r = br.act("/sell", "/sell", &[("action", "advanced"), ("max_sessions", "30"), ("sessions_per_address", "2"), ("max_held_tickets", "15"),
                                       ("proxies", ""), ("network", "bip122:0123456789abcdef0123456789abcdef")]);
    let f = br.flash_after(&r);
    assert!(f.contains("Advanced settings saved"), "{f}");

    // a price that is not a number is said so, and nothing changes
    let addr = format!("http://{media}");
    let r = br.act("/sell", "/sell", &[("action", "service"), ("kind", "media"), ("address", &addr), ("price", "twenty"), ("unit", "mib")]);
    assert_eq!(r.status, 200);
    assert!(unescape(&r.body).contains("The price is a number of sats"));
    let r = br.act("/sell", "/sell", &[("action", "service"), ("kind", "media"), ("address", "jellyfin:8096"), ("price", "20"), ("unit", "mib")]);
    assert!(unescape(&r.body).contains("not an address this box can reach"));
    // the media server: the first service gets the root
    let r = br.act("/sell", "/sell", &[("action", "service"), ("kind", "media"), ("address", &addr), ("price", "20"), ("unit", "mib"), ("strip", "1"),
                                       ("titles", "Sintel | /Videos/s/stream")]);
    assert!(br.flash_after(&r).contains("restarts"));
    // an AI model nobody answers for: its own path, requests passed on without it, and POST
    let r = br.act("/sell", "/sell", &[("action", "service"), ("kind", "ai"), ("address", "http://127.0.0.1:9"), ("price", "0.5"), ("unit", "request"),
                                       ("name", "My model"), ("strip", "1")]);
    assert!(br.flash_after(&r).contains("restarts"));
    let c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    let cfg = xbt_gateway::config::Config::from_json(&c).unwrap();
    assert_eq!(cfg.public_url, "https://seller.example");
    assert!(cfg.public_aliases.is_empty(), "a first address has none");
    assert_eq!(c["tickets"]["ticket_msat"], 900_000, "a ticket with its fee limit stays under the starter rules' 1,000 sat");
    assert_eq!(cfg.upstream, None);
    assert_eq!(cfg.routes.iter().map(|r| (r.path.as_str(), r.upstream.clone().unwrap(), r.strip_prefix)).collect::<Vec<_>>(),
               [("/", addr.clone(), false), ("/my-model/", "http://127.0.0.1:9".to_string(), true)]);
    assert_eq!((cfg.routes[0].price.byte_msat, cfg.routes[0].price.per_bytes, cfg.routes[1].price.request_msat), (20_000, 1_048_576, 500));
    assert!(cfg.routes[1].methods.contains(&"POST".to_string()));
    let l = cfg.listing.unwrap();
    assert_eq!((l.name.as_str(), l.services.len(), l.services[0].kind.as_str(), l.services[1].kind.as_str()), ("Mike's box", 2, "video", "ai"));
    // a new shop is published on Nostr, on the app's relays, with nothing written by hand
    let n = cfg.nostr.as_ref().expect("a nostr section");
    assert!(n.publish);
    assert_eq!(n.relays, ["wss://relay.one.example", "wss://relay.two.example"]);
    assert_eq!(l.services[0].items[0].url, "https://seller.example/Videos/s/stream");

    let page = br.get("/sell").body;
    assert!(page.contains("Selling, with a problem") && page.contains("Can&#39;t reach your AI model"), "{page}");
    assert!(page.contains("20 sat a MiB") && page.contains("0.5 sat a request"));
    // pause: the route is gone and the listing with it; the shop says so
    let shop: Value = serde_json::from_str(&std::fs::read_to_string(bx.data.path().join("ui/sell.json")).unwrap()).unwrap();
    let ai = shop["offers"][1]["id"].as_str().unwrap().to_string();
    let r = br.act("/sell", "/sell", &[("action", "pause"), ("id", &ai)]);
    assert!(br.flash_after(&r).contains("Paused"));
    let c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    assert_eq!(c["routes"].as_array().unwrap().len(), 1);
    let page = br.get("/sell").body;
    assert!(page.contains(">Paused<") && page.contains(">Resume<") && page.contains(">Selling<"), "{page}");
    // an edit keeps the path and the pause; remove drops it
    let r = br.act("/sell", "/sell", &[("action", "service"), ("id", &ai), ("kind", "ai"), ("address", "http://127.0.0.1:9"), ("price", "2"),
                                       ("unit", "request"), ("name", "My model")]);
    assert!(br.flash_after(&r).contains("Changes saved"));
    let shop: Value = serde_json::from_str(&std::fs::read_to_string(bx.data.path().join("ui/sell.json")).unwrap()).unwrap();
    assert_eq!((shop["offers"][1]["paths"][0].as_str(), shop["offers"][1]["paused"].as_bool(), shop["offers"][1]["price_msat"].as_u64()),
               (Some("/my-model/"), Some(true), Some(2000)));
    let r = br.act("/sell", "/sell", &[("action", "remove"), ("id", &ai)]);
    assert!(br.flash_after(&r).contains("Removed"));
    assert!(!br.get("/sell").body.contains("My model"));

    // renting out miners lists hashrate beside the other services, priced by the piece of work
    let listing = || {
        let c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
        xbt_gateway::config::Config::from_json(&c).unwrap().listing.unwrap()
    };
    assert!(listing().services.iter().all(|s| s.kind != "hashrate"), "not while renting is off");
    let r = br.act("/sell-hashrate", "/sell-hashrate", &[("action", "save"), ("fallback", "192.168.1.20:23334"), ("price", "40"),
                                                          ("name", "Basement miners"), ("enabled", "1")]);
    assert!(br.flash_after(&r).starts_with("Saved. Renting is on."));
    let l = listing();
    let h = l.services.iter().find(|s| s.kind == "hashrate").expect("a hashrate service");
    assert_eq!((h.name.as_str(), h.path.as_str(), h.prices["request_msat"].as_str()), ("Basement miners", "/hashrate/", Some("40000")));
    assert_eq!(l.services.len(), 2);
    let r = br.act("/sell-hashrate", "/sell-hashrate", &[("action", "save"), ("fallback", "192.168.1.20:23334"), ("price", "40")]);
    assert!(br.flash_after(&r).contains("Renting is off"));
    assert!(listing().services.iter().all(|s| s.kind != "hashrate"));
    // an update that lists more: the config is written again at start, without a Save
    let mut st: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("hashrate-settings.json")).unwrap()).unwrap();
    st["enabled"] = json!(true);
    std::fs::write(dir.join("hashrate-settings.json"), st.to_string()).unwrap();
    assert!(listing().services.iter().all(|s| s.kind != "hashrate"));
    assert_eq!(bx._app.refresh_shop_config(), Some("written"));
    assert!(listing().services.iter().any(|s| s.kind == "hashrate"));
    assert_eq!(bx._app.refresh_shop_config(), Some("unchanged"), "and only once");
    // a relay named by hand is kept after the app's, and publishing written off stays off
    let mut c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    c["nostr"] = json!({"relays": ["wss://relay.own.example", "wss://relay.two.example"], "publish": false});
    std::fs::write(dir.join("config.json"), c.to_string()).unwrap();
    let r = br.act("/sell", "/sell", &[("action", "shop"), ("name", "Mike's box"), ("public_url", "https://seller.example/")]);
    assert_eq!(r.status, 303);
    let c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    let n = xbt_gateway::config::Config::from_json(&c).unwrap().nostr.unwrap();
    // a shop that moves answers at its old address too, and moving back drops it from the others. Its
    // items move with it, also one saved as a whole address (as a shop of before 0.1.16 did)
    let mut shop: Value = serde_json::from_str(&std::fs::read_to_string(bx.data.path().join("ui/sell.json")).unwrap()).unwrap();
    shop["offers"][0]["titles"] = json!([{"title": "Sintel", "url": "https://seller.example/Videos/s/stream"}]);
    std::fs::write(bx.data.path().join("ui/sell.json"), shop.to_string()).unwrap();
    let r = br.act("/sell", "/sell", &[("action", "shop"), ("name", "Mike's box"), ("public_url", "https://new.example")]);
    assert_eq!(r.status, 303);
    let cfg = |dir: &std::path::Path| xbt_gateway::config::Config::from_json(&serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap()).unwrap();
    let moved = cfg(&dir);
    let films = moved.listing.as_ref().unwrap().services.iter().find(|s| s.kind == "video").unwrap().items.clone();
    assert!(!films.is_empty() && films.iter().all(|i| i.url.starts_with("https://new.example/")), "the items follow the shop: {films:?}");
    let st: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("hashrate-settings.json")).unwrap()).unwrap();
    assert_eq!(st["payUrl"], "https://new.example/hashrate", "hashrate is paid at the new address");
    assert_eq!((moved.public_url.as_str(), moved.public_aliases.as_slice()), ("https://new.example", &["https://seller.example".to_string()][..]));
    let r = br.act("/sell", "/sell", &[("action", "shop"), ("name", "Mike's box"), ("public_url", "https://seller.example")]);
    assert_eq!(r.status, 303);
    let back = cfg(&dir);
    assert_eq!((back.public_url.as_str(), back.public_aliases.as_slice()), ("https://seller.example", &["https://new.example".to_string()][..]));
    assert!(!n.publish);
    assert_eq!(n.relays, ["wss://relay.one.example", "wss://relay.two.example", "wss://relay.own.example"]);
}

#[test]
fn without_sell_the_wallet_has_no_sell_page() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |_| {});
    let mut br = logged_in(&bx);
    assert_eq!(br.get("/sell").status, 404);
    let page = br.get("/").body;
    assert!(page.contains(">Lightning Stream<") && !page.contains("href=\"./sell\"") && page.contains("href=\"./browse\""));
    assert!(page.contains("Use a service") && !page.contains("Sell a service"), "{page}");
}

/// Services: a seller added by its address shows on Browse with each service its signed listing
/// names, and goes when removed. A listing that does not verify adds nothing.
#[test]
fn a_seller_added_by_address_shows_its_services_on_browse() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |_| {});
    let mut br = logged_in(&bx);
    assert!(br.get("/services").body.contains("No sellers yet"));
    let sk = xbt_primitives::ecdsa::secret_key(&xbt_primitives::hash::sha256(b"ui-services-test")).unwrap();
    let pk = hex::encode(xbt_primitives::ecdsa::pubkey(&sk));
    let origin = "https://seller.example";
    let draft = xbt402::listing::parse_draft(&json!({"name": "Mike's box", "updated": "2026-10-26", "credits": "the makers", "services": [
        {"name": "Films", "kind": "video", "path": "/", "prices": {"byte_msat": 20000, "per_bytes": 1048576},
         "items": [{"title": "Sintel", "url": "https://seller.example/Videos/s", "year": 2010}]},
        {"name": "Model", "kind": "ai", "path": "/ai/", "prices": {"request_msat": 500}, "items": []}]})).unwrap();
    let doc = serde_json::to_string(&xbt402::listing::sign(&sk, &xbt402::listing::document(&draft, origin, &pk))).unwrap();
    let terms = serde_json::to_string(&json!({"accepts": [{"extra": {"receiptKey": pk}}]})).unwrap();
    let get = |key: &str| {
        let (doc, terms) = (doc.clone(), terms.replace(&pk, key));
        move |u: &str| Ok(if u.ends_with(xbt402::listing::PATH) {
            xbt402::listing::Page { status: 200, headers: vec![], body: doc.clone() }
        } else {
            xbt402::listing::Page { status: 402, headers: vec![], body: terms.clone() }
        })
    };
    let other = "02".to_string() + &"11".repeat(32);
    assert!(bx._app.add_seller(origin, get(&other)).unwrap_err().contains("could not be used"));
    assert!(bx._app.add_seller("not a url", get(&pk)).is_err());
    assert!(br.get("/services").body.contains("No sellers yet"), "nothing was added");
    let m = bx._app.add_seller(origin, get(&pk)).unwrap();
    assert!(m.contains("Added Mike's box: 2 services"), "{m}");
    let page = br.get("/services").body;
    assert!(page.contains("Mike&#39;s box: Films") && page.contains("20 sat a MiB") && page.contains("0.5 sat a request"), "{page}");
    let browse = br.get("/browse").body;
    assert!(browse.contains("Mike&#39;s box: Films") && browse.contains("Mike&#39;s box: Model") && browse.contains("cat-ai"), "{browse}");
    // the model's page gives the address apps and agents use it at; the films' page lists what it plays
    let model = br.get(&format!("/service?seller={}&name={}", enc(origin), enc("Mike's box: Model"))).body;
    assert!(model.contains("value=\"https://seller.example/ai/\"") && model.contains("0.5 sat a request") && !model.contains("<video"), "{model}");
    let films = br.get(&format!("/service?seller={}&name={}", enc(origin), enc("Mike's box: Films"))).body;
    assert!(films.contains("Sintel") && films.contains("./play?item="), "{films}");
    // again: replaced, not doubled
    assert!(bx._app.add_seller(&format!("{origin}/"), get(&pk)).unwrap().starts_with("Updated"));
    let all = xbt_wallet_ui::services::load(&bx.data.path().join("ui/services.json")).unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!((all[0].items[0].year.as_str(), all[0].items[0].credit.as_str()), ("2010", "the makers"));
    let r = br.act("/services", "/services", &[("action", "remove"), ("url", origin)]);
    assert!(br.flash_after(&r).contains("Seller removed"));
    assert!(!br.get("/browse").body.contains("Sintel"));
}

/// A seller on loopback: its signed listing at the well-known path, and a 402 naming a receipt
/// key on anything else.
struct Seller {
    listing: String,
    terms: String,
}

impl xbt_svc::http::Handler for Seller {
    fn body_limit(&self, _: &str, _: &str) -> usize {
        0
    }
    fn handle(&self, req: xbt_svc::http::Request) -> xbt_svc::http::Response {
        if req.path() == xbt402::listing::PATH {
            xbt_svc::http::Response::text(200, "application/json", self.listing.clone())
        } else {
            xbt_svc::http::Response::text(402, "application/json", self.terms.clone())
        }
    }
}

type Sk = xbt_primitives::secp256k1::SecretKey;

fn receipt_key(seed: &[u8]) -> (Sk, String) {
    let sk = xbt_primitives::ecdsa::secret_key(&xbt_primitives::hash::sha256(seed)).unwrap();
    (sk, hex::encode(xbt_primitives::ecdsa::pubkey(&sk)))
}

/// A seller whose listing `name` is signed by `sk`, and whose terms name `terms_key`: its origin
/// and its signed listing.
fn seller_on(sk: &Sk, pk: &str, name: &str, terms_key: &str) -> (String, Value) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", l.local_addr().unwrap());
    let d = xbt402::listing::parse_draft(&json!({
        "name": name, "kind": "video", "prices": {"byte_msat": 20000, "per_bytes": 1048576},
        "items": [{"title": "Sintel", "url": format!("{origin}/v/sintel"), "year": 2010, "credit": "(c) Blender Foundation, CC BY 3.0"}],
        "licence": "CC BY 3.0", "credits": "Blender Foundation", "updated": "2026-10-26",
    }))
    .unwrap();
    let doc = xbt402::listing::sign(sk, &xbt402::listing::document(&d, &origin, pk));
    let terms = json!({"accepts": [{"extra": {"receiptKey": terms_key}}]});
    let h = Seller { listing: doc.to_string(), terms: terms.to_string() };
    std::mem::forget(xbt_svc::http::serve(Arc::new(h), l, 2).unwrap());
    (origin, doc)
}

#[test]
fn browse_nostr_lists_checked_listings_unvetted_and_the_seller_confirms_its_own() {
    use xbt_nostr::{event::Event, event::Keys, market, oneshot, standin::StandinRelay};
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let relay = StandinRelay::start().unwrap();
    let relays = vec![relay.url.clone()];
    let publish = |keys: &Keys, sk: &Sk, doc: &Value, seller: &str| {
        let bind = xbt402::listing::bind(sk, &keys.public.serialize(), seller);
        let ev = market::listing_event(keys, doc, &bind, xbt_nostr::now()).unwrap();
        assert_eq!(oneshot::publish(&relays, &ev, Duration::from_secs(5))[0].result, Ok(()));
        ev
    };
    // a genuine seller, whose own terms name the key that signed its listing
    let (sk, pk) = receipt_key(b"films seller");
    let (origin, doc) = seller_on(&sk, &pk, "Open films", &pk);
    publish(&Keys::generate(), &sk, &doc, &origin);
    // a listing well signed by a key the seller's own address does not name
    let (isk, ipk) = receipt_key(b"impostor");
    let (other, idoc) = seller_on(&isk, &ipk, "Impostor films", &receipt_key(b"real owner").1);
    let impostor = publish(&Keys::generate(), &isk, &idoc, &other);
    // a forged event: the listing changed after it was signed, under a third Nostr key
    let mut forged = idoc.clone();
    forged["name"] = json!("Forged films");
    let tags = impostor.tags.iter().map(|t| if t[0] == market::LISTING_TAG { vec![t[0].clone(), forged.to_string()] } else { t.clone() }).collect();
    oneshot::publish(&relays, &Event::sign(&Keys::generate(), impostor.created_at, impostor.kind, tags, impostor.content.clone()), Duration::from_secs(5));

    let bx = start(json!({}), false, |c| c.nostr_relays = relays.clone());
    let mut br = logged_in(&bx);
    assert_eq!(B::new(&bx.base).get("/nostr").location(), "./login");
    assert!(br.get("/browse").body.contains("href=\"./nostr\""));
    let page = br.get("/nostr");
    assert_eq!(page.status, 200);
    assert!(page.body.contains("Unvetted") && page.body.contains(">unvetted<"));
    assert!(page.body.contains("Open films") && page.body.contains("Impostor films") && !page.body.contains("Forged films"));
    assert!(page.body.contains("failed a signature check"));
    assert!(page.body.contains("20 sat a MiB"));
    assert!(!br.get("/browse").body.contains("Open films"), "Browse lists the services file only");
    // a film found on Nostr plays as one of the services file does
    let film = format!("{origin}/v/sintel");
    assert!(page.body.contains(&format!("href=\"./play?item={}\"", enc(&film))));
    assert!(br.get(&format!("/play?item={}", enc(&film))).body.contains(&format!("/{film}\"")));

    let event_of = |name: &str| {
        let rest = &page.body[page.body.find(name).unwrap()..];
        let v = rest.find("name=\"event\" value=\"").unwrap() + "name=\"event\" value=\"".len();
        rest[v..v + 64].to_string()
    };
    let r = br.act("/nostr", "/nostr-check", &[("event", &event_of("Open films"))]);
    assert!(br.flash_after(&r).contains("signs with the same key"));
    let r = br.act("/nostr", "/nostr-check", &[("event", &event_of("Impostor films"))]);
    assert!(br.flash_after(&r).contains("the seller's terms name"));
    let r = br.act("/nostr", "/nostr-check", &[("event", "00")]);
    assert!(br.flash_after(&r).contains("no longer"));
}

#[test]
fn without_relays_the_nostr_page_asks_none_and_relays_are_checked() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |_| {});
    let mut br = logged_in(&bx);
    assert!(!br.get("/browse").body.contains("href=\"./nostr\""));
    assert!(br.get("/nostr").body.contains("No Nostr relays are set"));
    assert_eq!(xbt_wallet_ui::config::nostr_relays(Some("wss://a.example, wss://b.example")).unwrap().len(), 2);
    assert!(xbt_wallet_ui::config::nostr_relays(Some("ws://relay.example")).is_err());
    assert!(xbt_wallet_ui::config::nostr_relays(None).unwrap().is_empty());
}

/// The words a person reads on a page's main screen: the text of `<main>`, without what sits
/// in a collapsed `<details>` (technical detail is kept there on purpose) and without the tags.
fn main_words(page: &str) -> String {
    let main = &page[page.find("<main").unwrap_or(0)..page.find("</main>").unwrap_or(page.len())];
    let (mut out, mut depth, mut rest) = (String::new(), 0usize, main);
    while !rest.is_empty() {
        let open = rest.find("<details");
        let close = rest.find("</details>");
        match (open, close) {
            (Some(o), c) if c.is_none_or(|c| o < c) => {
                if depth == 0 {
                    out.push_str(&rest[..o]);
                }
                depth += 1;
                rest = &rest[o + 8..];
            }
            (_, Some(c)) => {
                if depth == 0 {
                    out.push_str(&rest[..c]);
                }
                depth = depth.saturating_sub(1);
                rest = &rest[c + 10..];
            }
            _ => {
                if depth == 0 {
                    out.push_str(rest);
                }
                break;
            }
        }
    }
    out.split('<').map(|s| s.split_once('>').map(|(_, t)| t).unwrap_or(s)).collect::<String>().to_ascii_lowercase()
}

/// Someone with no technical knowledge uses the app: no page's main screen speaks the plumbing's
/// language. The exact terms stay inside the collapsed "Advanced" and "Details" parts.
#[cfg(unix)]
#[test]
fn main_screens_speak_plain_words() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    assert!(main_words("<main><p>a macaroon</p><details><summary>x</summary><details>msat</details>cltv</details>ok</main>").contains("macaroon")
            && !main_words("<main><details><details>msat</details>cltv</details></main>").contains("cltv"), "the check sees the main screen, not the details");
    const JARGON: [&str; 11] = ["macaroon", "msat", "millisat", "preimage", "upstream", "htlc", "cltv", "receipt key", "mcp", "nwc", "xbt_ui_"];
    let check = |what: &str, page: &str| {
        let words = main_words(page);
        assert!(words.split_whitespace().count() > 8, "{what}: the page has words to read: {words}");
        for j in JARGON {
            assert!(!words.contains(j), "{what}: \"{j}\" on the main screen: {words}");
        }
    };
    let gw = tempfile::tempdir().unwrap();
    let services = gw.path().join("services.json");
    std::fs::write(&services, json!([
        {"name": "Open films", "kind": "video", "seller": "https://media.example", "price_text": "20 sat a MiB",
         "items": [{"title": "Sintel", "year": 2010, "url": "https://media.example/v/1", "credit": "CC BY 3.0"}]},
        {"name": "Local model", "kind": "ai", "seller": "https://ai.example", "address": "https://ai.example/ai/", "price_text": "10 sat a request", "items": []}
    ]).to_string()).unwrap();
    let dir = gw.path().join("gateway");
    std::fs::create_dir_all(&dir).unwrap();
    let bx = start(json!({}), false, |c| {
        c.sell = true;
        c.gw.dir = dir.clone();
        c.gw.node_rest = Some("https://10.21.21.66:8180".into());
        c.services_file = Some(services.clone());
        c.mcp_urls = vec!["http://umbrel.local:33510/mcp".into()];
    });
    let mut anon = B::new(&bx.base);
    check("first run", &anon.get("/").body);
    let mut br = logged_in(&bx);
    for path in ["/", "/browse", "/browse?cat=ai", "/services", "/connections", "/sell", "/wallet", "/approvals", "/apps", "/agents", "/setup",
                 "/lightning", "/policy", "/keys", "/signatures", "/channels", "/nostr",
                 "/service?seller=https%3A%2F%2Fai.example&name=Local%20model", "/service?seller=https%3A%2F%2Fmedia.example&name=Open%20films",
                 "/play?item=https%3A%2F%2Fmedia.example%2Fv%2F1"] {
        let r = br.get(path);
        assert_eq!(r.status, 200, "{path}");
        check(path, &r.body);
    }
    // the separate seller's page
    let gdir = tempfile::tempdir().unwrap();
    let (data, _app, _srv, base) = gateway_ui(gdir.path());
    let mut g = B::new(&base);
    let code = std::fs::read_to_string(data.path().join("ui/setup-code")).unwrap();
    assert_eq!(g.post("/setup-password", &[("code", code.trim()), ("password", PW), ("password2", PW)]).status, 303);
    check("seller's page", &g.get("/").body);
}

/// Requests a stand-in control page saw: (method, path, the Authorization header, the body).
type ControlSeen = Arc<std::sync::Mutex<Vec<(String, String, String, String)>>>;

/// A stand-in for the hasher's and the renter's control pages: fixed answers, every request kept.
fn control_standin(answer: fn(&str, &str) -> Value) -> (String, ControlSeen) {
    use std::io::{BufRead, BufReader, Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let seen: ControlSeen = Arc::default();
    let s2 = seen.clone();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let mut r = BufReader::new(c.try_clone().unwrap());
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            let mut it = line.split_whitespace();
            let (m, p) = (it.next().unwrap_or("").to_string(), it.next().unwrap_or("").to_string());
            let (mut len, mut auth) = (0usize, String::new());
            loop {
                let mut h = String::new();
                r.read_line(&mut h).unwrap();
                let h = h.trim_end().to_string();
                if h.is_empty() {
                    break;
                }
                let (k, v) = h.split_once(':').unwrap();
                match k.to_ascii_lowercase().as_str() {
                    "content-length" => len = v.trim().parse().unwrap(),
                    "authorization" => auth = v.trim().to_string(),
                    _ => {}
                }
            }
            let mut body = vec![0u8; len];
            r.read_exact(&mut body).unwrap();
            let out = answer(&m, &p).to_string();
            s2.lock().unwrap().push((m, p, auth, String::from_utf8_lossy(&body).to_string()));
            let _ = write!(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}", out.len());
        }
    });
    (base, seen)
}

#[test]
fn hashrate_is_rented_out_and_rented_in_plain_words() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (hasher, hseen) = control_standin(|m, p| match (m, p) {
        ("GET", "/status") => json!({
            "open": true, "settings": {"enabled": true, "fallback": "192.168.1.20:23334", "priceSat": 40, "sliceWork": "140737488355328", "graceMs": 45000,
                                       "rentable": null, "name": "Basement miners"},
            "minersAddress": "umbrel.local:23334", "listing": {"ok": true, "freeMiners": 1, "miners": 2},
            "miners": [{"name": "s11", "connected": true, "hashrateHs": 4.1e12, "rentedTo": "r1", "earnedMsat": 120000},
                       {"name": "s12", "connected": true, "hashrateHs": 4.0e12, "rentedTo": null, "earnedMsat": 0}],
            "rentals": [{"rental": "r1", "buyer": "02aa", "miners": ["s11"], "paid": 3, "earnedMsat": 120000}]}),
        ("POST", "/stop/r1") => json!({"ok": true, "stopped": "r1"}),
        _ => json!({"error": "no"}),
    });
    let (renter, rseen) = control_standin(|m, p| match (m, p) {
        ("GET", "/status") => json!({
            "datum": {"addr": "datum-gateway:23334", "reachable": true, "found": ["datum-gateway:23334"]},
            "rentals": [{"rental": "r9", "hasher": "Basement miners", "miners": 1, "budgetSats": 4000, "minutes": 60, "ended": false,
                         "live": {"closed": null, "paidSlices": 5, "spentMsat": 200000, "miners": 1, "lastRate": {"hs": 4.1e12}}}]}),
        ("GET", "/offers") => json!({"offers": [{"name": "Basement miners", "linkKey": "02bb", "priceMsat": 40000, "sliceWork": "140737488355328",
                                                  "miners": 2, "freeMiners": 1, "freeHs": "4000000000000"},
                                                 {"name": "Garage miners", "linkKey": "02dd", "priceMsat": 40000, "sliceWork": "140737488355328",
                                                  "miners": 1, "freeMiners": 1, "freeHs": "4000000000000",
                                                  "payUrl": "https://miners.example/hashrate", "payNode": format!("03{}", "c".repeat(64))}]}),
        ("POST", "/rent") => json!({"ok": true, "rental": "r10"}),
        ("POST", "/cut") => json!({"ok": true}),
        ("POST", "/datum") => json!({"ok": true, "datum": "datum-gateway:23334", "reachable": true}),
        _ => json!({"error": "no"}),
    });
    let dir = tempfile::tempdir().unwrap();
    let (htok, rtok) = (dir.path().join("hasher-token"), dir.path().join("renter-token"));
    std::fs::write(&htok, "h".repeat(64)).unwrap();
    std::fs::write(&rtok, "r".repeat(64)).unwrap();
    let settings = dir.path().join("hashrate/settings.json");
    let gw = dir.path().join("gateway");
    std::fs::create_dir_all(&gw).unwrap();
    let bx = start(json!({}), false, |c| {
        c.sell = true;
        c.gw.dir = gw.clone();
        c.gw.node_rest = Some("https://10.21.21.66:8180".into());
        c.hash.hasher = Some(hasher.clone());
        c.hash.hasher_token = Some(htok.clone());
        c.hash.renter = Some(renter.clone());
        c.hash.renter_token = Some(rtok.clone());
        c.hash.slices = Some("http://127.0.0.1:9".into());
        c.hash.settings = settings.clone();
    });
    let mut br = logged_in(&bx);
    const JARGON: [&str; 11] = ["macaroon", "msat", "millisat", "preimage", "upstream", "htlc", "cltv", "receipt key", "mcp", "nwc", "xbt_ui_"];
    let plain = |what: &str, page: &str| {
        let words = main_words(page);
        for j in JARGON {
            assert!(!words.contains(j), "{what}: \"{j}\" on the main screen: {words}");
        }
    };

    // Sell → Hashrate: where to point the miners, each miner, the rental going on
    let p = br.get("/sell-hashrate");
    assert_eq!(p.status, 200);
    for s in ["Renting out: 1 of 2 miners rented", "stratum+tcp://umbrel.local:23334", "Your pool", "Rented out", "4.10 TH/s", "120 sats", "Stop this rental", "Listed"] {
        assert!(p.body.contains(s), "{s} missing from Sell hashrate");
    }
    assert!(p.body.contains("href=\"./sell-hashrate\" aria-current"), "Hashrate is a tab of Sell");
    assert!(br.get("/browse").body.contains("href=\"./hashrate\""), "and of Services");
    plain("/sell-hashrate", &p.body);
    let r = br.act("/sell-hashrate", "/sell-hashrate", &[("action", "stop"), ("rental", "r1")]);
    assert!(br.flash_after(&r).starts_with("Stopped."));
    assert!(hseen.lock().unwrap().iter().any(|(m, p, a, _)| m == "POST" && p == "/stop/r1" && *a == format!("Bearer {}", "h".repeat(64))),
            "the stop went to the hasher's control page with its token");
    // turning renting on writes the hasher's settings
    let r = br.act("/sell-hashrate", "/sell-hashrate", &[("action", "save"), ("fallback", "192.168.1.20:23334"), ("price", "40"), ("rentable", "1"),
                                                          ("name", "Basement miners"), ("enabled", "1")]);
    assert!(br.flash_after(&r).starts_with("Saved. Renting is on."));
    let s: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!((s["enabled"].clone(), s["fallback"].clone(), s["priceSat"].clone(), s["rentable"].clone()),
               (json!(true), json!("192.168.1.20:23334"), json!(40), json!(1)));
    let r = br.act("/sell-hashrate", "/sell-hashrate", &[("action", "save"), ("fallback", "no port"), ("price", "40")]);
    assert!(br.flash_after(&r).contains("with its port"));

    // Services → Hashrate: the offers, the rental going on, renting and cutting
    let p = br.get("/hashrate");
    assert_eq!(p.status, 200);
    for s in ["Ready to rent", "Basement miners", "1 of 2 machines free", "Rent", "Hashrate from Basement miners", "200 sats", "Cut", "Lazarus Pool"] {
        assert!(p.body.contains(s), "{s} missing from Hashrate");
    }
    plain("/hashrate", &p.body);
    // a hashmaker the spending rules do not list yet: allowed first (the rules page, with its node), Rent waits
    let garage = &p.body[p.body.find("Garage miners").unwrap()..];
    let garage = &garage[..garage.find("</section>").unwrap()];
    assert!(garage.contains("Allow this hashmaker to be paid") && garage.contains("./policy?allow=") && garage.contains(&format!("node=03{}", "c".repeat(64))),
            "{garage}");
    assert!(garage.contains("<button disabled>Rent</button>"), "{garage}");
    let r = br.act("/hashrate", "/hashrate", &[("action", "rent"), ("key", "02bb"), ("miners", "1"), ("budget", "4000"), ("minutes", "60")]);
    assert!(br.flash_after(&r).starts_with("Renting."));
    let rent = rseen.lock().unwrap().iter().find(|(m, p, _, _)| m == "POST" && p == "/rent").cloned().unwrap();
    let body: Value = serde_json::from_str(&rent.3).unwrap();
    assert_eq!((body["linkKey"].clone(), body["miners"].clone(), body["budgetSats"].clone()), (json!("02bb"), json!(1), json!(4000)));
    assert_eq!(rent.2, format!("Bearer {}", "r".repeat(64)));
    // Live connections shows the rental, with its Cut button
    let p = br.get("/connections");
    assert!(p.body.contains("Rented hashrate") && p.body.contains("data-spent=\"200\""), "{}", p.body);
    plain("/connections", &p.body);
    let r = br.act("/connections", "/hashrate", &[("action", "cut"), ("rental", "r9"), ("back", "connections")]);
    assert_eq!(r.location(), "./connections");
    assert!(rseen.lock().unwrap().iter().any(|(m, p, _, b)| m == "POST" && p == "/cut" && b.contains("r9")));
}

/// Without an address renters outside can reach, the offer stays off public listings and the page
/// says why in plain words; the address is set, and cleared, on the page.
#[test]
fn hashrate_without_a_public_address_is_not_listed_and_says_why() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (hasher, _hseen) = control_standin(|m, p| match (m, p) {
        ("GET", "/status") => json!({
            "open": true, "settings": {"enabled": true, "fallback": "192.168.1.20:23334", "priceSat": 40, "sliceWork": "140737488355328", "graceMs": 45000,
                                       "rentable": 1, "name": "Basement miners", "linkPublic": null},
            "minersAddress": "umbrel.local:23340", "linkLan": "umbrel.local:23341",
            "listing": {"ok": false, "missing": "link-public",
                        "why": "Add the address hashtakers use to reach your miners (it needs a port forward or a tunnel). Until then your offer is not published; hashtakers on your own network can still use this box's address."},
            "miners": [{"name": "s11", "connected": true, "hashrateHs": 4.1e12, "rentedTo": null, "earnedMsat": 0}], "rentals": []}),
        _ => json!({"error": "no"}),
    });
    let dir = tempfile::tempdir().unwrap();
    let htok = dir.path().join("hasher-token");
    std::fs::write(&htok, "h".repeat(64)).unwrap();
    let settings = dir.path().join("hashrate/settings.json");
    let gw = dir.path().join("gateway");
    std::fs::create_dir_all(&gw).unwrap();
    let bx = start(json!({}), false, |c| {
        c.sell = true;
        c.gw.dir = gw.clone();
        c.gw.node_rest = Some("https://10.21.21.66:8180".into());
        c.hash.hasher = Some(hasher.clone());
        c.hash.hasher_token = Some(htok.clone());
        c.hash.settings = settings.clone();
    });
    let mut br = logged_in(&bx);
    let p = br.get("/sell-hashrate");
    for s in ["Not listed", "Add the address hashtakers use to reach your miners", "Address hashtakers use to reach your miners (needs a port forward or tunnel)",
              "umbrel.local:23341"] {
        assert!(p.body.contains(s), "{s} missing from Sell hashrate: {}", p.body);
    }
    fn save(link: &str) -> [(&str, &str); 7] {
        [("action", "save"), ("fallback", "192.168.1.20:23334"), ("price", "40"), ("rentable", "1"), ("name", "Basement miners"),
                             ("enabled", "1"), ("link_public", link)]
    }
    let r = br.act("/sell-hashrate", "/sell-hashrate", &save("not an address"));
    assert!(br.flash_after(&r).contains("with its port"), "a bad address is refused");
    let r = br.act("/sell-hashrate", "/sell-hashrate", &save("miners.example.com:23341"));
    assert!(br.flash_after(&r).starts_with("Saved."));
    let read = || serde_json::from_str::<Value>(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(read()["linkPublic"], json!("miners.example.com:23341"));
    let r = br.act("/sell-hashrate", "/sell-hashrate", &save(""));
    assert!(br.flash_after(&r).starts_with("Saved."));
    assert_eq!(read()["linkPublic"], json!(""), "an empty address clears it: no listing on public relays");
}

// --- no setup on a box: the node connects itself, the box's login, the code, the player, your shop --

/// The keys the app makes itself through the box's node: the Lightning page says it is connected by
/// itself, keeps the owner's own key under Advanced, and a disconnect is not undone at the next start.
#[cfg(unix)]
#[test]
fn a_node_the_box_connected_by_itself_needs_no_key_and_a_disconnect_stays() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let ln = tempfile::tempdir().unwrap();
    let dir = ln.path().to_path_buf();
    let s = xbt_wallet_ui::node_keys::Settings { rest: "https://10.21.21.66:8180".into(), tls_cert: None, admin: dir.join("none"), grant: None,
                                                 rail_dir: Some(dir.clone()), gw_dir: None };
    let rail = mac(&[("info", &["read"]), ("offchain", &["read", "write"]), ("onchain", &["read"])]);
    let made = xbt_wallet_ui::node_keys::make_keys(&s, &mut |_, _| Ok(hex::decode(&rail).unwrap())).unwrap();
    assert_eq!(made.made, vec!["rail.macaroon"]);
    let b = start(json!({}), false, |c| {
        c.ln.dir = dir.clone();
        c.ln.rest = Some("https://10.21.21.66:8180".into());
    });
    let mut br = logged_in(&b);
    let page = br.get("/lightning").body;
    assert!(page.contains("connected by itself") && page.contains("made by the app") && page.contains("root key id "), "{page}");
    assert!(page.contains("Advanced: use a key of your own instead") && !page.contains(&rail), "{page}");
    assert!(page.contains("Before you uninstall") && page.contains("deletemacaroonid"), "{page}");
    // Home and Setup tell the same state as this page: connected, not yet ready (no rules signed)
    if !page.contains("Connected to your Lightning node") {
        let home = br.get("/").body;
        assert!(home.contains("connected but cannot pay yet") && !home.contains("Not connected"), "{home}");
        let setup = br.get("/setup").body;
        assert!(setup.contains("Connected, not ready yet.") && !setup.contains("ln.enabled") && !setup.contains("Lightning rail"), "{setup}");
    }
    let r = br.act("/lightning", "/lightning", &[("action", "remove")]);
    assert!(br.flash_after(&r).contains("removed"));
    // the next start makes nothing: the node is not even asked
    assert!(xbt_wallet_ui::node_keys::run(&s).unwrap().made.is_empty());
    assert!(!dir.join("rail.macaroon").exists());
    assert!(br.get("/lightning").body.contains("Not connected"));
}

/// The box's own login proxy (here: the loopback peer, named `localhost`) is the owner, already logged
/// in by the box: no app password. A box whose proxy is another peer still asks for it.
#[test]
fn the_boxs_login_proxy_needs_no_app_password_and_other_peers_still_do() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let b = start(json!({}), false, |c| c.platform_login = Some("localhost".into()));
    let mut br = B::new(&b.base);
    let r = br.get("/wallet?x=1");
    assert_eq!((r.status, r.location()), (303, "./wallet?x=1"), "{}", r.body);
    assert!(!br.cookie.is_empty(), "a session is made at once");
    let page = br.get("/wallet");
    assert_eq!(page.status, 200, "{}", page.body);
    assert_eq!(br.get("/login").location(), "./");
    let other = start(json!({}), false, |c| c.platform_login = Some("no-such-host.invalid".into()));
    let mut br = B::new(&other.base);
    let r = br.get("/wallet");
    assert_ne!(r.status, 200);
    assert!(br.cookie.is_empty(), "no session for a peer that is not the proxy");
}

/// The box hands the setup page the signer's one-time code: the owner types nothing from a log.
#[test]
fn the_enrolment_code_the_box_gives_is_filled_in() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let code = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(code.path(), "ABCD-EFGH-IJKL\n").unwrap();
    let path = code.path().to_path_buf();
    let b = start_on(Rig::new(json!({"human_pubkey": ""}), false), |c| c.enroll_code_file = Some(path.clone()));
    let mut br = logged_in(&b);
    let page = br.get("/setup").body;
    assert!(page.contains("<input type=\"hidden\" name=\"code\" value=\"ABCD-EFGH-IJKL\">"), "{page}");
    assert!(!page.contains("Enrolment code<input") && page.contains("Use this key for approvals"), "{page}");
    assert!(page.contains("Download the approval key backup (this is not your passphrase)") && page.contains("I saved the downloaded file somewhere safe"), "{page}");
    // what saving needs is said before Save is pressed: the download and the tick, or the last 8 characters
    assert!(page.contains("keep its backup in one of two ways") && page.contains("type the backup's last 8 characters"), "{page}");
    // without the box's copy the code is asked as before
    let b = start_on(Rig::new(json!({"human_pubkey": ""}), false), |_| {});
    let mut br = logged_in(&b);
    assert!(br.get("/setup").body.contains("Enrolment code<input"));
}

const FILM2: &str = "https://stream.lazarus-xbt.xyz/Videos/0f0967c6719ebc0951976655686df3bc/stream?static=true";

/// The player never sits black: a wallet that cannot pay says so before anything is tried, with the
/// next step, and a play that failed says why in plain words.
#[test]
fn the_player_says_why_it_cannot_play_and_what_to_do() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("services.json");
    std::fs::write(&path, format!(r#"[{{"name": "Films", "kind": "video", "seller": "https://stream.lazarus-xbt.xyz", "price_text": "20 sat a MiB",
        "items": [{{"title": "Elephants Dream", "year": 2006, "url": "{FILM2}", "credit": "CC BY 2.5"}}]}}]"#)).unwrap();
    // no approval key: nothing can pay yet
    let b = start_on(Rig::new(json!({"human_pubkey": ""}), false), |c| c.services_file = Some(path.clone()));
    let mut br = logged_in(&b);
    let play = br.get(&format!("/play?item={}", enc(FILM2))).body;
    assert!(play.contains("Your wallet isn&#39;t set up yet") || play.contains("Your wallet isn't set up yet"), "{play}");
    assert!(play.contains("href=\"./setup\"") && play.contains("Finish setup") && !play.contains("<video"), "{play}");
    // with a key: the player, with a place for a message, and the reason of a failed play on ask
    let b = start(json!({}), false, |c| c.services_file = Some(path.clone()));
    let mut br = logged_in(&b);
    let play = br.get(&format!("/play?item={}", enc(FILM2))).body;
    assert!(play.contains("<video") && play.contains("data-player") && play.contains("class=\"player-msg\""), "{play}");
    // this rig's node is not ready: said above the player, with where to look
    assert!(play.contains("may not be able to pay yet") && (play.contains("Check your node") || play.contains("Open the starter rules")), "{play}");
    assert_eq!(serde_json::from_str::<Value>(&br.get(&format!("/api/play-error?item={}", enc(FILM2))).body).unwrap()["failed"], false);
    for (status, body, words, href) in [
        (402, r#"{"error": "the seller is not on the allowlist", "rule": "allowlist"}"#, "not allowed yet", "./services"),
        (402, r#"{"error": "the daily budget is spent", "rule": "daily_budget"}"#, "spending limit", "./policy"),
        (402, r#"{"error": "no route: insufficient outbound balance", "rule": "ln"}"#, "Not enough balance", "./wallet"),
        (504, r#"{"error": "the seller sent nothing within 60 s"}"#, "didn't answer", "./services"),
        (402, r#"{"error": "no human key is enrolled", "rule": "human_key"}"#, "isn't set up", "./setup"),
    ] {
        b._app.note_play_error(FILM2, status, body.as_bytes());
        let v: Value = serde_json::from_str(&br.get(&format!("/api/play-error?item={}", enc(FILM2))).body).unwrap();
        assert_eq!(v["failed"], true);
        assert!(v["words"].as_str().unwrap().contains(words), "{v}");
        assert_eq!(v["href"], href, "{v}");
    }
    // the reason is the owner's: not without a login
    assert_eq!(B::new(&b.base).get(&format!("/api/play-error?item={}", enc(FILM2))).status, 401);
}

/// A box cannot buy from its own shop: its services are marked as the owner's, and their items play
/// as a free preview straight from the service on the box, for the logged-in owner only.
#[test]
fn your_own_shop_is_marked_and_previews_free_for_you_only() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    fn film(path: &str) -> (u16, &'static str) {
        if path.starts_with("/Videos/abc/") { (200, "FILM BYTES") } else { (404, "{}") }
    }
    let service = mock_http(film);
    let gw = tempfile::tempdir().unwrap();
    std::fs::write(gw.path().join("config.json"), json!({"public_url": "https://media.example", "upstream": format!("http://{service}"),
        "routes": [{"path": "/Videos/abc/"}]}).to_string()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("services.json");
    let item = "https://media.example/Videos/abc/stream?static=true";
    std::fs::write(&path, format!(r#"[{{"name": "My films", "kind": "video", "seller": "https://media.example", "price_text": "20 sat a MiB",
        "items": [{{"title": "Sintel", "year": 2010, "url": "{item}", "credit": "CC BY 3.0"}}]}},
        {{"name": "Their films", "kind": "video", "seller": "https://other.example", "price_text": "20 sat a MiB",
        "items": [{{"title": "Other", "year": 2010, "url": "https://other.example/Videos/abc/stream", "credit": "CC0"}}]}}]"#)).unwrap();
    let gwdir = gw.path().to_path_buf();
    let b = start(json!({}), false, |c| {
        c.services_file = Some(path.clone());
        c.sell = true;
        c.gw.dir = gwdir.clone();
    });
    let mut br = logged_in(&b);
    let browse = br.get("/browse").body;
    assert_eq!(browse.matches("Your shop</span>").count(), 1, "{browse}");
    let page = br.get(&format!("/service?seller={}&name={}", enc("https://media.example"), enc("My films"))).body;
    assert!(page.contains("This is your shop") && page.contains("Preview (free)"), "{page}");
    let theirs = br.get(&format!("/service?seller={}&name={}", enc("https://other.example"), enc("Their films"))).body;
    assert!(!theirs.contains("This is your shop") && !theirs.contains("Preview (free)"));
    let play = br.get(&format!("/play?item={}", enc(item))).body;
    assert!(play.contains(&format!("src=\"./preview?item={}\"", enc(item))) && play.contains("Nothing is paid"), "{play}");
    assert!(!play.contains("./s/"), "never through the gateway or the wallet");
    let r = br.get(&format!("/preview?item={}", enc(item)));
    assert_eq!((r.status, r.body.as_str()), (200, "FILM BYTES"));
    // not without the owner's login, and never another seller's item
    assert_eq!(B::new(&b.base).get(&format!("/preview?item={}", enc(item))).status, 401);
    assert_eq!(br.get(&format!("/preview?item={}", enc("https://other.example/Videos/abc/stream"))).status, 404);
}

/// "Allow this seller to be paid": the seller's node read from its own terms, then the spending rules
/// filled in with its address tied to that node, for one signature.
#[test]
fn allowing_a_seller_fills_in_the_spending_rules_for_one_signature() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let node = format!("02{}", "ab".repeat(32));
    let terms = json!({"accepts": [{"scheme": "ticket", "payTo": node}]}).to_string();
    let got = xbt_wallet_ui::app::services_page::seller_node(&["https://seller.example/x".into(), "https://seller.example".into()], |u| {
        Ok(if u.ends_with("/x") { xbt402::listing::Page { status: 402, headers: vec![], body: terms.clone() } }
           else { xbt402::listing::Page { status: 404, headers: vec![], body: String::new() } })
    }).unwrap();
    assert_eq!(got, node);
    assert!(xbt_wallet_ui::app::services_page::seller_node(&["https://seller.example".into()], |_| {
        Ok(xbt402::listing::Page { status: 200, headers: vec![], body: String::new() })
    }).is_err());
    // a shop that moved: its services at its new address, its items still at its old one (an alias of
    // the same gateway). The node is read from a priced place on the new address, never the front page
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("services.json");
    std::fs::write(&path, r#"[{"name": "Films", "kind": "video", "seller": "https://new.example", "address": "https://new.example/Videos/",
        "price_text": "20 sat a MiB", "items": [{"title": "Sintel", "url": "https://old.example/Videos/s/stream?static=true"}]},
        {"name": "Model", "kind": "ai", "seller": "https://new.example", "address": "https://new.example/ai/", "price_text": "1 sat", "items": []}]"#).unwrap();
    let moved = start_on(Rig::new(json!({}), false), |c| c.services_file = Some(path.clone()));
    let mut asked = vec![];
    let link = moved._app.allow_link("https://new.example", |u| {
        asked.push(u.to_string());
        // the shop answers 402 only on its priced paths, and only on its new address here
        Ok(if u.starts_with("https://new.example/") && u.len() > "https://new.example/".len() {
            xbt402::listing::Page { status: 402, headers: vec![], body: terms.clone() }
        } else { xbt402::listing::Page { status: 404, headers: vec![], body: String::new() } })
    }).unwrap();
    assert_eq!(link, format!("./policy?allow={}&node={node}", enc("https://new.example")));
    assert_eq!(asked, ["https://new.example/Videos/"], "the service's own address first");
    // with only the item to go by, it is asked at the seller's address, not the old one
    std::fs::write(&path, r#"[{"name": "Films", "kind": "video", "seller": "https://new.example", "price_text": "20 sat a MiB",
        "items": [{"title": "Sintel", "url": "https://old.example/Videos/s/stream?static=true"}]}]"#).unwrap();
    let mut asked = vec![];
    moved._app.allow_link("https://new.example", |u| {
        asked.push(u.to_string());
        Ok(if u.contains("/Videos/") { xbt402::listing::Page { status: 402, headers: vec![], body: terms.clone() } }
           else { xbt402::listing::Page { status: 404, headers: vec![], body: String::new() } })
    }).unwrap();
    assert_eq!(asked, ["https://new.example/Videos/s/stream?static=true"]);
    let b = start(json!({}), false, |_| {});
    let mut br = logged_in(&b);
    let page = br.get(&format!("/policy?allow={}&node={node}", enc("https://seller.example"))).body;
    assert!(page.contains("Allow https://seller.example to be paid") && page.contains("in any 7 days"), "{page}");
    assert!(page.contains("https://seller.example") && page.contains(&node), "{page}");
    // a bad node is ignored: nothing filled in
    let page = br.get(&format!("/policy?allow={}&node=zz", enc("https://seller.example"))).body;
    assert!(!page.contains("Allow https://seller.example to be paid"));
}

/// The Sell page offers the services it finds on the box, in one click.
#[test]
fn the_sell_page_offers_the_services_found_on_the_box() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    fn ok(_: &str) -> (u16, &'static str) { (200, "{}") }
    let jelly = mock_http(ok);
    let gw = tempfile::tempdir().unwrap();
    let gwdir = gw.path().to_path_buf();
    let b = start(json!({}), false, |c| {
        c.sell = true;
        c.gw.dir = gwdir.clone();
        c.local_services = vec![("Jellyfin".into(), format!("http://{jelly}")), ("Gone".into(), "http://127.0.0.1:1".into())];
    });
    let mut br = logged_in(&b);
    let page = br.get("/sell").body;
    assert!(page.contains("Found on this box") && page.contains(&format!("data-value=\"http://{jelly}\"")), "{page}");
    assert!(!page.contains("http://127.0.0.1:1\""), "a service that does not answer is not offered");
    assert!(page.contains("I don&#39;t have an https address yet") || page.contains("I don't have an https address yet"), "{page}");
}

#[test]
fn on_mainnet_the_rules_page_suggests_the_node_s_limit_and_never_prefills_the_signer_s_test_chain_defaults() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    // paying on, no exposure cap, and the money limits left out: the signer's own defaults would be huge
    let mut rig = Rig::build(json!({"ln": {"enabled": true}}), false, "main");
    let path = rig.root.join("policy.json");
    let mut p: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    for k in ["max_per_tx_sats", "daily_budget_sats", "hot_balance_cap_sats"] {
        p.as_object_mut().unwrap().remove(k);
    }
    std::fs::write(&path, serde_json::to_string(&p).unwrap()).unwrap();
    rig.restart().unwrap();
    let eff = rig.call("policy_get", json!({}))["effective"].clone();
    assert!(eff["max_per_tx_sats"].as_i64().unwrap() > 2000, "the signer's default is above the starter's: {eff}");
    let bx = start_on(rig, |_| {});
    let mut br = logged_in(&bx);
    let page = br.get("/policy").body;
    assert!(!page.contains("Paying is not turned on yet"), "paying is on: the rules in force are edited");
    assert!(page.contains("Your Lightning node needs a limit before the app can pay through it: <span class=\"money\">100,000 sats"), "{page}");
    assert!(page.contains("name=\"f_ln_exposure_cap_sats\" value=\"100000\""), "{page}");
    assert!(page.contains("the safe starter values are filled in below instead of the signer&#39;s built-in ones")
            || page.contains("the safe starter values are filled in below instead of the signer's built-in ones"), "{page}");
    let starter = xbt_wallet_ui::app::starter_policy("main");
    for k in ["max_per_tx_sats", "daily_budget_sats", "hot_balance_cap_sats"] {
        assert!(page.contains(&format!("name=\"f_{k}\" value=\"{}\"", starter[k])), "{k}: {page}");
    }
    // a limit the rules do set is shown as it is
    assert!(page.contains("name=\"f_weekly_budget_sats\" value=\"6000\""), "{page}");
    // signing the form as shown: the cap lands in ln, paying stays on
    let mut f = policy_form_fields(&page);
    f.push(("f_ln_exposure_cap_sats".into(), field(&page, "f_ln_exposure_cap_sats")));
    let prev = br.post("/policy", &f.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect::<Vec<_>>()).body;
    let signed: Value = serde_json::from_str(&field(&prev, "text")).unwrap();
    assert_eq!((signed["ln"]["enabled"].clone(), signed["ln"]["exposure_cap_sats"].clone(), signed["max_per_tx_sats"].clone()),
               (json!(true), json!(100000), starter["max_per_tx_sats"].clone()), "{signed}");
}

/// A seller that charged a call past its limit is said at the top of the wallet page, with the
/// numbers, and its line in the records reads as words.
#[test]
fn a_seller_that_charged_past_a_calls_limit_is_said_on_the_wallet_page() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let b = start(json!({}), false, |_| {});
    b.rig.s.engine.audit.append(json!({"type": "ticket_over_cap", "ts": 1_793_000_000, "origin": "https://lab-shop.example", "dest": "ln:02ab",
                                        "charged_msat": "68244", "max_msat": "50000", "receipt": {"charged": "68244"}}));
    let mut br = logged_in(&b);
    let page = unescape(&br.get("/wallet").body);
    assert!(page.contains("https://lab-shop.example charged 68.244 sats for one answer, more than the 50 sats the call allowed"), "{page}");
    assert!(page.contains("A seller charged past the limit"), "{page}");
}
