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

/// The rules the signer's market test runs on (`crates/xbt-signer/tests/ticket_pay.rs`, `mainnet_starter`).
#[test]
fn the_starter_rules_on_mainnet_are_those_the_signer_is_tested_at_market_with() {
    let p = xbt_wallet_ui::app::starter_policy("main");
    assert_eq!(p["tickets"]["tasks"]["hashrate"], json!({"budget_sats": 200_000, "rental": {"max_ticket_sats": 10_000, "max_sends_per_hour": 600}}));
    for (k, v) in [("max_per_tx_sats", 2_000), ("daily_budget_sats", 10_000), ("weekly_budget_sats", 30_000), ("per_counterparty_cap_sats", 10_000),
                   ("per_counterparty_daily_sats", 5_000), ("velocity_max", 60), ("velocity_window_s", 3600), ("human_threshold_sats", 1_000), ("split_window_s", 600)] {
        assert_eq!(p[k], json!(v), "{k}");
    }
    assert_eq!(p["tickets"]["tasks"]["default"]["budget_sats"], 10_000);
    // off mainnet the task is as it was
    assert_eq!(xbt_wallet_ui::app::starter_policy("regtest")["tickets"]["tasks"]["hashrate"], json!({"budget_sats": 100_000}));
}

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
    form.push(("f_sellers".into(), field(&page, "f_sellers")));
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
    assert!(page.contains("Most your Lightning node may hold (sats)"), "{page}");
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
    // 0.2.3: a node of ordinary size (287,070 sats in 0.2.1's hands-on run) is not refused at the first payment
    assert_eq!(STARTER_EXPOSURE_CAP_SATS, 1_000_000);
    // twice what the channels hold, rounded up to 10,000, never below the least cap
    for (held, cap) in [(0, 1_000_000), (287_070, 1_000_000), (500_000, 1_000_000), (500_001, 1_010_000), (700_000, 1_400_000), (-5, 1_000_000),
                        (i64::MAX, i64::MAX / 10_000 * 10_000)] {
        assert_eq!(starter_exposure_cap(held), cap, "held {held}");
    }
    let m = starter_policy("main");
    // the Lightning section the signer's mainnet readiness test signs (xbt-signer tests/ln_rail.rs), with the starter's least cap
    assert_eq!(m["ln"], json!({"enabled": true, "split_height": xbt_wallet_ui::app::MAINNET_SPLIT_HEIGHT, "exposure_cap_sats": 1_000_000}));
    assert_eq!(starter_policy_for("main", Some(700_000))["ln"]["exposure_cap_sats"], json!(1_400_000));
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
    form.push(("f_sellers".into(), field(page, "f_sellers")));
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
    let home = br.get("/").body;
    assert!(home.contains("Get started") && home.contains("Make your approval key") && home.contains("aria-current=\"step\""),
            "home says what is left to do, the next step first: {home}");
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
    // the key is not in the page as it opens: only on "Show the access key", a POST with the CSRF token
    assert!(!page.contains(&"ab".repeat(32)) && !page.contains("Bearer ") && page.contains("action=\"./agents-key\""), "{page}");
    assert!(page.contains("aria-current=\"page\">AI agents") && page.contains("Rotate the token"), "{page}");
    assert!(!br.post("/agents-key", &[]).body.contains(&"ab".repeat(32)), "not without the CSRF token");
    let page = br.act("/agents", "/agents-key", &[]).body;
    assert!(page.contains(&"ab".repeat(32)) && page.contains("Bearer "), "{page}");
    // AGP-042: the real MCP HTTP transport, reading the same file (the UI never calls it to rotate)
    let wallet = std::sync::Arc::new(xbt_wallet_mcp::wallet::Wallet::new(tdir.path().join("no-signer.sock")));
    // a port of its own (0: the system picks a free one), bound before the server starts, so a request
    // is taken as soon as it is sent: nothing to wait for, however loaded the machine
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mcp_addr = listener.local_addr().unwrap();
    let mut cfg = xbt_wallet_mcp::transport::HttpConfig::new(mcp_addr.to_string());
    cfg.token_file = Some(tok.clone());
    let server = std::sync::Arc::new(xbt_wallet_mcp::mcp::Server::new(wallet));
    let _mcp = xbt_wallet_mcp::transport::serve_listener(server, cfg, listener).unwrap();
    let mcp_init = |t: &str| {
        let r = ureq::post(&format!("http://{mcp_addr}/mcp")).set("Accept", "application/json, text/event-stream")
            .set("Authorization", &format!("Bearer {t}"))
            .send_string(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26",
                                 "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}}).to_string());
        match r {
            Ok(x) => x.status(),
            Err(ureq::Error::Status(c, _)) => c,
            Err(e) => panic!("mcp at {mcp_addr}: {e}"),
        }
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
    let page = br.act("/agents", "/agents-key", &[]).body;
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
    // renting miners pays under its own task: there from the start, and only to listed sellers. On mainnet it's a rental
    // task (Mike's decision for 0.2.0): a budget of 200,000 sat, tickets of at most 10,000 sat, 600 sends an hour
    assert_eq!(m["tickets"]["tasks"]["hashrate"], json!({"budget_sats": 200_000, "rental": {"max_ticket_sats": 10_000, "max_sends_per_hour": 600}}));
    assert!(t["tickets"]["tasks"]["hashrate"]["budget_sats"].as_i64().unwrap() > 0);
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
         ("chain", chain), ("network", if chain == "main" { "" } else { net }), ("mainnet_ack", ack), ("max_sessions", "100"),
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
    // and so is the cap on connections from one address: every buyer comes over the proxy's
    assert_eq!(c["http"]["per_address"], 0, "{c}");
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
    assert_eq!((c["caps"]["max_sessions"].as_u64(), c["caps"]["max_held_tickets"].as_u64()), (Some(25), Some(4)));
    assert!(c.get("network").is_none());
    xbt_gateway::config::Config::from_json(&c).unwrap();
}

const FILM: &str = "https://stream.lazarus-xbt.xyz/Videos/057627270372dfed4d8ea15fa9ab5f01/stream?static=true";
const NOTES: &str = "https://files.example/notes?a=1&b=2";

#[test]
fn browse_and_connections_follow_the_services_file_and_stop_through_the_signer() {
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
    assert!(page.body.contains(">Web apps <") && page.body.contains(">Files <") && page.body.contains(">Data &amp; APIs <"), "the categories");
    assert!(!page.body.contains(">Media <"), "no media category of its own");
    assert!(!page.body.contains("Big Buck Bunny"), "Browse lists services, not what a media service has inside");
    assert!(page.headers.get("content-security-policy").is_some_and(|v| v.contains("media-src 'self'")));
    // an older film listing (no web app) is files: each to download or open in the buyer's own player, no player here
    let media = br.get(&format!("/service?seller={}&name={}", enc("https://stream.lazarus-xbt.xyz"), enc("Alpha films"))).body;
    let token = xbt_wallet_ui::app::stream_token(&field(&media, "csrf"));
    // the Download names the service it is bought from: `./s/~<token>.<service id>/<file>`
    assert!(media.contains("Big Buck Bunny") && media.contains(&format!("href=\"./s/~{token}.")) && media.contains(&format!("/{FILM}\" download>Download</a>")), "{media}");
    assert!(media.contains("Open in your player") && media.contains("20 sat a MiB"), "{media}");
    assert!(!media.contains("./play?") && !media.contains("<video"), "the app has no player: {media}");
    assert_eq!(br.get(&format!("/play?item={}", enc(FILM))).status, 404, "no player page");
    // a link for the buyer's own player: made by a logged-in POST, shown with a copy button, revoked
    let back = format!("/service?seller={}&name={}", enc("https://stream.lazarus-xbt.xyz"), enc("Alpha films"));
    let r = br.act(&back, "/file-link", &[("action", "create"), ("item", FILM)]);
    assert!(br.flash_after(&r).contains("Link made"));
    let page = br.get(&back).body;
    let link = page.split("value=\"").find(|v| v.contains("/r/")).map(|v| v.split('"').next().unwrap().to_string()).expect("a link");
    assert!(link.contains("/r/") && page.contains("data-copy=\"link-0-0\""), "{page}");
    let tok = link.rsplit("/r/").next().unwrap().to_string();
    let r = br.act(&back, "/file-link", &[("action", "revoke"), ("item", FILM), ("token", &tok)]);
    assert!(br.flash_after(&r).contains("Link revoked"));
    let r = br.act(&back, "/file-link", &[("action", "create"), ("item", "https://elsewhere.example/x")]);
    assert!(br.flash_after(&r).contains("not in your list"));
    // a files service: its files to download, the item's text escaped
    let files = br.get(&format!("/service?seller={}&name={}", enc("https://files.example"), enc("Zebra files"))).body;
    assert!(files.contains("&lt;b&gt;notes&lt;/b&gt;") && !files.contains("<b>notes</b>"));
    assert!(files.contains("notes?a=1&amp;b=2") && files.contains(">Download</a>") && !files.contains("./play?"), "{files}");
    assert!(br.get("/service?seller=https://x.example&name=x").body.contains("not in your list"));

    let by_price = br.get("/browse?sort=price").body;
    assert!(by_price.find("Zebra files").unwrap() < by_price.find("Alpha films").unwrap(), "price sort");
    assert!(by_price.contains("aria-current=\"true\">price"));
    let data = br.get("/browse?cat=files").body;
    assert!(data.contains("Zebra files") && data.contains("Alpha films"), "files, and an older film listing");
    let old_link = br.get("/browse?kind=video").body;
    assert!(old_link.contains("Alpha films") && old_link.contains("aria-current=\"page\">Files"), "an older films link is files");
    let old_cat = br.get("/browse?cat=media").body;
    assert!(old_cat.contains("aria-current=\"page\">Web apps"), "the older media category is web apps");
    assert!(br.get("/browse?cat=ai").body.contains("No services in this category yet"));

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

/// A download comes from the page's own origin: the UI relays `/s/<file URL>` to the connector
/// (which listens on loopback only), for a logged-in owner only, so a browser on another device of the
/// network can download it.
#[test]
fn the_ui_relays_a_download_from_the_connector_to_a_logged_in_owner() {
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
    assert!(r.status == 403 || r.status == 404, "the app streams no video of its own: {}", r.status);
    assert!(asked.lock().unwrap().is_empty(), "nothing reached the connector: {:?}", asked.lock().unwrap());
    // an action with the right token even, from another page: by Sec-Fetch-Site, and by Origin in an older browser
    let csrf = field(&br.get("/browse").body, "csrf");
    let form = format!("csrf={}", enc(&csrf));
    assert_eq!(br.send("POST", "/logout", Some(&form), &[("Sec-Fetch-Site", "same-site")]).status, 403);
    assert_eq!(br.send("POST", "/logout", Some(&form), &[("Origin", "http://127.0.0.1:9")]).status, 403, "an older browser's Origin");
    assert_eq!(br.send("POST", "/logout", Some(&form), &[("Referer", "http://127.0.0.1:9/x")]).status, 403, "and its Referer, with no Origin");
    // a page another page opens is the home page, never the page it named
    let nav = [("Sec-Fetch-Site", "same-site"), ("Sec-Fetch-Mode", "navigate"), ("Sec-Fetch-Dest", "document")];
    let r = br.send("GET", "/app?u=https://evil.example/evil-app", None, &nav);
    assert_eq!((r.status, r.location()), (303, "/"));
    let r = br.send("GET", "/browse?cat=apps", None, &[("Referer", "http://127.0.0.1:9/x")]);
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
            // `bytes=N-` or `bytes=N-M`, the end held to the film's last byte
            let from = range.as_deref().and_then(|r| r.strip_prefix("bytes=")).and_then(|r| r.split_once('-')).and_then(|(a, e)| {
                let a = a.parse::<usize>().ok()?;
                let e = if e.is_empty() { film.len() - 1 } else { e.parse::<usize>().ok()?.min(film.len() - 1) };
                Some((a, e))
            });
            match from {
                Some((a, e)) => {
                    let _ = write!(s, "HTTP/1.1 206 Partial Content\r\nContent-Type: video/mp4\r\nAccept-Ranges: bytes\r\nContent-Range: bytes {a}-{e}/{}\r\n\
                                       Content-Length: {}\r\nConnection: close\r\n\r\n", film.len(), e + 1 - a);
                    let _ = s.write_all(&film[a..=e]);
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

/// A player that reads a little of a long film and goes away is charged at most one part beyond
/// what it read: the relay asks for an open range one READ_CHUNK at a time, and asks for no more once
/// the player has gone. The connector is what the wallet pays through, so
/// what it was asked for bounds what the seller can meter.
#[test]
fn a_reader_that_goes_away_early_is_asked_for_at_most_one_part() {
    use std::io::{Read, Write};
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let film: Vec<u8> = b"\0\0\0\x20ftypisom".iter().copied().chain((0..(10u32 << 20)).map(|i| (i % 251) as u8)).collect();
    let (connector, seen) = range_connector(film.clone());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("services.json");
    std::fs::write(&path, format!(r#"[{{"name": "Films", "kind": "video", "seller": "https://stream.lazarus-xbt.xyz", "price_text": "20 sat a MiB",
         "items": [{{"title": "Big Buck Bunny", "year": 2008, "url": "{FILM}", "credit": "CC BY 3.0"}}]}}]"#)).unwrap();
    let services = path.clone();
    let b = start(json!({}), false, move |c| {
        c.connector = connector;
        c.services_file = Some(services);
    });
    let mut br = logged_in(&b);
    let st = xbt_wallet_ui::app::stream_token(&field(&br.get("/browse").body, "csrf"));
    // a player's first request for a film: an open range from the start
    let addr = b.base.trim_start_matches("http://").split('/').next().unwrap().to_string();
    let mut sock = std::net::TcpStream::connect(&addr).unwrap();
    let prefix = b.base.splitn(4, '/').nth(3).map(|p| format!("/{p}")).unwrap_or_default();
    write!(sock, "GET {prefix}/s/~{st}/{FILM} HTTP/1.1\r\nHost: {addr}\r\nCookie: {}\r\nRange: bytes=0-\r\n\r\n", br.cookie).unwrap();
    let mut got = vec![0u8; 256 << 10];
    let mut have = 0;
    while have < got.len() {
        let n = sock.read(&mut got[have..]).unwrap();
        if n == 0 { break; }
        have += n;
    }
    drop(sock); // the player is closed
    std::thread::sleep(Duration::from_millis(500));
    let asked = seen.lock().unwrap().clone();
    assert_eq!(asked.len(), 1, "one request reached the connector: {asked:?}");
    assert_eq!(asked[0].1.as_deref(), Some("bytes=0-4194303"), "an open range is asked for one part (4 MiB) at a time");
    let head = String::from_utf8_lossy(&got[..have.min(1024)]).to_string();
    assert!(head.starts_with("HTTP/1.1 206") && head.contains(&format!("bytes 0-4194303/{}", film.len())), "{head}");
}

/// Seeking through the relay, and the links for the buyer's own player (VLC, mpv, a TV app): the
/// reader's `Range` reaches the connector and its 206 comes back with its range; a link is made by a
/// logged-in POST with the CSRF token, plays its one file without a cookie, names no other, and
/// stops when it is revoked or expires.
#[test]
fn the_relay_passes_range_and_a_players_link_plays_its_one_file_until_it_expires() {
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

    // a download that resumes: the Range goes to the connector, the 206 comes back with its headers
    let st = xbt_wallet_ui::app::stream_token(&field(&br.get("/browse").body, "csrf"));
    let (status, h, body) = get_range(&format!("{}/s/~{st}/{FILM}", b.base), Some(&br.cookie), Some("bytes=1000-"));
    assert_eq!(status, 206);
    assert_eq!((h.get("content-range").map(String::as_str), h.get("accept-ranges").map(String::as_str), h.get("content-type").map(String::as_str)),
               (Some(format!("bytes 1000-{}/{}", film.len() - 1, film.len()).as_str()), Some("bytes"), Some("video/mp4")));
    assert_eq!(h.get("content-length").map(String::as_str), Some((film.len() - 1000).to_string().as_str()));
    assert_eq!(body, film[1000..]);
    // an open range is asked for as one part of at most READ_CHUNK; this film is shorter than that
    assert_eq!(seen.lock().unwrap().last().unwrap(), &(format!("/s/{FILM}"), Some("bytes=1000-4195303".to_string())));
    let (status, _, body) = get_range(&format!("{}/s/~{st}/{FILM}", b.base), Some(&br.cookie), None);
    assert_eq!((status, body.len()), (200, film.len()));
    assert_eq!(seen.lock().unwrap().last().unwrap().1, None, "no Range where the download sent none");

    // a link is made only by a logged-in POST with the CSRF token, for a file of the services file
    let play = format!("/service?seller={}&name={}", enc("https://stream.lazarus-xbt.xyz"), enc("Films"));
    assert!(br.get(&play).body.contains("Open in your player"));
    assert_eq!(anon.post("/file-link", &[("action", "create"), ("item", FILM)]).location(), "./login");
    assert_eq!(br.post("/file-link", &[("action", "create"), ("item", FILM)]).status, 403, "no CSRF token");
    let r = br.act(&play, "/file-link", &[("action", "create"), ("item", "https://stream.lazarus-xbt.xyz/not-listed")]);
    assert!(br.flash_after(&r).contains("not in your list"));
    let r = br.act(&play, "/file-link", &[("action", "create"), ("item", FILM)]);
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
    assert_eq!(anon.get("/browse").location(), "./login", "the link is no login");

    // revoked: it plays nothing
    let r = br.act(&play, "/file-link", &[("action", "revoke"), ("item", FILM), ("token", &token)]);
    assert!(br.flash_after(&r).contains("revoked"));
    assert_eq!(get_range(&link, None, None).0, 404);
    // a new one expires on its own
    let r = br.act(&play, "/file-link", &[("action", "create"), ("item", FILM)]);
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

/// A service's own web page (docs/SELLER-APPS.md): the AI model's page at its own path, a media
/// server's at the root, each route given the methods and headers a page uses, its compressed pages,
/// and the seller's guest login; the listing names each page beside its service. A guest login of
/// the wallet's own headers is refused.
/// A service's `capacity` set on the Sell page reaches each of its routes: a free one counts no
/// buyers, an empty box sets no limit, and a number that is not one is refused in words.
#[cfg(unix)]
#[test]
fn how_many_buyers_at_once_on_the_sell_page_becomes_each_routes_capacity() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let gw = tempfile::tempdir().unwrap();
    let dir = gw.path().to_path_buf();
    let media = mock_http(|_| (200, "ok"));
    let bx = start(json!({}), false, |c| {
        c.sell = true;
        c.gw.dir = dir.clone();
        c.gw.node_rest = Some("https://10.21.21.66:8180".into());
        c.gw.node_tls_cert = Some("/data/lightning/tls.cert".into());
    });
    let mut br = logged_in(&bx);
    let inv = mac(&[("invoices", &["read", "write"])]);
    let info = mac(&[("info", &["read"])]);
    br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &inv), ("info_macaroon", &info)]);
    br.act("/sell", "/sell", &[("action", "advanced"), ("max_sessions", "30"), ("sessions_per_address", "2"), ("max_held_tickets", "15"),
                               ("proxies", ""), ("network", "bip122:0123456789abcdef0123456789abcdef")]);
    br.act("/sell", "/sell", &[("action", "shop"), ("name", "Box"), ("public_url", "https://seller.example")]);
    assert!(br.get("/sell").body.contains("How many buyers at once"));
    let addr = format!("http://{media}");
    // a number that is not one: refused, in words
    let r = br.act("/sell", "/sell", &[("action", "service"), ("kind", "media"), ("address", &addr), ("price", "20"), ("unit", "mib"),
                                       ("paths", "/Videos/1/"), ("cap_buyers", "many")]);
    assert_eq!(r.status, 200, "the form comes back with what is wrong");
    assert!(r.body.contains("Most buyers at once is a whole number"), "{}", r.body);
    // films with 5 buyers and 3 streams at once, the page at the root with them
    let r = br.act("/sell", "/sell", &[("action", "service"), ("kind", "media"), ("address", &addr), ("price", "20"), ("unit", "mib"),
                                       ("paths", "/Videos/1/"), ("app", "1"), ("cap_buyers", "5"), ("cap_streams", "3"), ("cap_streams_buyer", "")]);
    assert!(br.flash_after(&r).contains("restarts"), "{}", br.flash_after(&r));
    // a free service with a stream limit only
    let r = br.act("/sell", "/sell", &[("action", "service"), ("kind", "web"), ("address", "http://127.0.0.1:9"), ("price", "0"), ("unit", "request"),
                                       ("name", "Free"), ("paths", "/free/"), ("cap_buyers", "4"), ("cap_streams", "2")]);
    assert!(br.flash_after(&r).contains("restarts"), "{}", br.flash_after(&r));
    let c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    let cfg = xbt_gateway::config::Config::from_json(&c).unwrap();
    // behind a proxy that does not say who each buyer is, all buyers come from one address: no cap per address
    assert_eq!((cfg.http.per_address, cfg.caps.sessions_per_address), (0, 0), "{c}");
    let route = |p: &str| cfg.routes.iter().find(|r| r.path == p).unwrap_or_else(|| panic!("no route {p}"));
    let want = xbt_gateway::config::Capacity { max_buyers: Some(5), max_streams: Some(3), max_streams_per_buyer: None, max_mbit: None };
    assert_eq!(route("/Videos/1/").capacity, want);
    assert_eq!(route("/").capacity, want, "the page counts with its service");
    assert_eq!(route("/").service, route("/Videos/1/").service, "and is one service with it");
    assert_ne!(route("/free/").service, route("/").service);
    // the free one counts no buyers: a gateway would refuse that
    assert_eq!(route("/free/").capacity, xbt_gateway::config::Capacity { max_streams: Some(2), ..Default::default() });
    // and the page shows the limits again when the service is edited
    let page = br.get("/sell").body;
    assert!(page.contains("name=\"cap_streams\""));
    // the limits of the whole shop, which a seller meets before any of these, are said beside them
    assert!(page.contains("Your whole shop serves up to 30 buyers at once and 512 open connections"), "{page}");
}

#[cfg(unix)]
#[test]
fn a_service_sold_with_its_own_web_page_gets_a_route_and_a_listing_for_it() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let gw = tempfile::tempdir().unwrap();
    let dir = gw.path().to_path_buf();
    let media = mock_http(|_| (200, "ok"));
    let bx = start(json!({}), false, |c| {
        c.sell = true;
        c.gw.dir = dir.clone();
        c.gw.node_rest = Some("https://10.21.21.66:8180".into());
        c.gw.node_tls_cert = Some("/data/lightning/tls.cert".into());
    });
    let mut br = logged_in(&bx);
    let inv = mac(&[("invoices", &["read", "write"])]);
    let info = mac(&[("info", &["read"])]);
    br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &inv), ("info_macaroon", &info)]);
    br.act("/sell", "/sell", &[("action", "advanced"), ("max_sessions", "30"), ("sessions_per_address", "2"), ("max_held_tickets", "15"),
                               ("proxies", ""), ("network", "bip122:0123456789abcdef0123456789abcdef")]);
    br.act("/sell", "/sell", &[("action", "shop"), ("name", "Box"), ("public_url", "https://seller.example")]);
    assert!(br.get("/sell").body.contains("Buyers can open its own web page inside their app"));
    let addr = format!("http://{media}");
    // films sold under one path, the media server's own page at the root, with a guest login
    let r = br.act("/sell", "/sell", &[("action", "service"), ("kind", "media"), ("address", &addr), ("price", "20"), ("unit", "mib"),
                                       ("paths", "/Videos/1/"), ("app", "1"), ("app_entry", "/web/"), ("app_login", "X-Emby-Token: guest-1")]);
    assert!(br.flash_after(&r).contains("restarts"), "{}", br.flash_after(&r));
    // the model, its page at its own path
    let r = br.act("/sell", "/sell", &[("action", "service"), ("kind", "ai"), ("address", "http://127.0.0.1:9"), ("price", "10"), ("unit", "tokens"),
                                       ("name", "Model"), ("strip", "1"), ("app", "1")]);
    assert!(br.flash_after(&r).contains("restarts"), "{}", br.flash_after(&r));
    let c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    let cfg = xbt_gateway::config::Config::from_json(&c).unwrap();
    let route = |p: &str| cfg.routes.iter().find(|r| r.path == p).unwrap_or_else(|| panic!("no route {p}"));
    let (films, root, model) = (route("/Videos/1/"), route("/"), route("/model/"));
    assert!(!films.accept_gzip && films.upstream_headers.is_empty(), "the films' own route is as it was");
    assert!(root.accept_gzip && root.methods.contains(&"DELETE".to_string()) && root.forward_headers.contains(&"cookie".to_string()));
    assert_eq!(root.upstream_headers, [("x-emby-token".to_string(), "guest-1".to_string())]);
    assert_eq!((root.price.byte_msat, root.upstream.as_deref()), (20_000, Some(addr.as_str())));
    assert!(model.accept_gzip && model.strip_prefix && model.methods.contains(&"POST".to_string()) && model.upstream_headers.is_empty());
    let l = cfg.listing.unwrap();
    let apps: Vec<(&str, &str, &str)> = l.services.iter().filter(|s| s.kind == "app").map(|s| (s.name.as_str(), s.path.as_str(), s.items[0].url.as_str())).collect();
    assert_eq!(apps, [("Media server", "/", "https://seller.example/web/"), ("Model", "/model/", "https://seller.example/model/")]);
    // the buyer's side reads each page with its service
    let svc = xbt_wallet_ui::services::from_listing(&xbt402::listing::Listing { name: l.name.clone(), kind: l.kind.clone(), seller: "https://seller.example".into(),
        receipt_key: String::new(), prices: l.prices.clone(), items: l.items.clone(), licence: l.licence.clone(), credits: l.credits.clone(), updated: l.updated.clone(),
        services: l.services.clone() });
    let m = svc.iter().find(|s| s.name.ends_with("Model")).unwrap();
    assert_eq!((m.app.as_str(), m.app_base.as_str()), ("https://seller.example/model/", "https://seller.example/model/"));
    // the page turned off: its routes are as any other, and the listing names no page
    let shop: Value = serde_json::from_str(&std::fs::read_to_string(bx.data.path().join("ui/sell.json")).unwrap()).unwrap();
    let id = shop["offers"][1]["id"].as_str().unwrap().to_string();
    br.act("/sell", "/sell", &[("action", "service"), ("id", &id), ("kind", "ai"), ("address", "http://127.0.0.1:9"), ("price", "10"), ("unit", "tokens"),
                               ("name", "Model"), ("strip", "1")]);
    let c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    let cfg = xbt_gateway::config::Config::from_json(&c).unwrap();
    assert!(!cfg.routes.iter().find(|r| r.path == "/model/").unwrap().accept_gzip);
    assert_eq!(cfg.listing.unwrap().services.iter().filter(|s| s.kind == "app").count(), 1);
    // a guest login may not be the shop's own headers, and a page's base is not another service's path
    let r = br.act("/sell", "/sell", &[("action", "service"), ("kind", "ai"), ("address", "http://127.0.0.1:9"), ("price", "10"), ("unit", "tokens"),
                                       ("name", "Other"), ("app", "1"), ("app_login", "Cookie: x=1")]);
    assert!(unescape(&r.body).contains("cannot be the login header"), "{}", r.body);
    let r = br.act("/sell", "/sell", &[("action", "service"), ("kind", "ai"), ("address", "http://127.0.0.1:9"), ("price", "10"), ("unit", "tokens"),
                                       ("name", "Other"), ("app", "1"), ("app_base", "/Videos/1/")]);
    assert!(unescape(&r.body).contains("already uses /Videos/1/, so Other cannot have it"), "{}", r.body);
}

/// Buyers' own accounts set up on the Sell page (docs/BUYER-ACCOUNTS.md): the seller pastes the
/// Jellyfin API key, the shop checks it against the service and lists its libraries, keeps the key
/// in a file beside the gateway's config that the page never shows again, and the route names the
/// file and the libraries ticked (all of them where none is). A wrong key, no key and a free
/// service are refused in plain words; turning accounts off removes the key.
#[cfg(unix)]
#[test]
fn the_sell_page_sets_up_buyers_own_accounts_with_the_sellers_jellyfin_key() {
    const KEY: &str = "5e11e7a9c0ffee5e11e7a9c0ffee5e11";
    struct Jellyfin;
    impl xbt_svc::http::Handler for Jellyfin {
        fn body_limit(&self, _: &str, _: &str) -> usize {
            0
        }
        fn handle(&self, req: xbt_svc::http::Request) -> xbt_svc::http::Response {
            if req.header("x-emby-token") != Some(KEY) {
                return xbt_svc::http::Response::text(401, "text/plain", "no");
            }
            match req.path() {
                "/Library/VirtualFolders" => xbt_svc::http::Response::text(200, "application/json",
                    r#"[{"Name": "Films", "ItemId": "aaaa1111"}, {"Name": "Shows", "ItemId": "bbbb2222"}]"#),
                _ => xbt_svc::http::Response::text(404, "text/plain", "no"),
            }
        }
    }
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let gw = tempfile::tempdir().unwrap();
    let dir = gw.path().to_path_buf();
    let jf = xbt_svc::http::serve(Arc::new(Jellyfin), std::net::TcpListener::bind("127.0.0.1:0").unwrap(), 2).unwrap().addr;
    let bx = start(json!({}), false, |c| {
        c.sell = true;
        c.gw.dir = dir.clone();
        c.gw.node_rest = Some("https://10.21.21.66:8180".into());
    });
    let mut br = logged_in(&bx);
    let inv = mac(&[("invoices", &["read", "write"])]);
    let info = mac(&[("info", &["read"])]);
    br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &inv), ("info_macaroon", &info)]);
    br.act("/sell", "/sell", &[("action", "advanced"), ("max_sessions", "30"), ("sessions_per_address", "2"), ("max_held_tickets", "15"),
                               ("proxies", ""), ("network", "bip122:0123456789abcdef0123456789abcdef")]);
    br.act("/sell", "/sell", &[("action", "shop"), ("name", "Box"), ("public_url", "https://seller.example")]);
    assert!(br.get("/sell").body.contains("Each buyer gets their own Jellyfin account"));
    let addr = format!("http://{jf}");
    fn service<'a>(addr: &'a str, extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
        let mut f = vec![("action", "service"), ("kind", "media"), ("address", addr), ("price", "20"), ("unit", "mib"), ("app", "1"),
                         ("app_entry", "/web/"), ("app_accounts", "1")];
        f.extend_from_slice(extra);
        f
    }
    let routes = || {
        let c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
        (xbt_gateway::config::Config::from_json(&c).unwrap(), c)
    };
    // no key, a key that is not one, and a key Jellyfin refuses: nothing is saved
    let r = br.act("/sell", "/sell", &service(&addr, &[]));
    assert!(unescape(&r.body).contains("Paste your Jellyfin API key"), "{}", r.body);
    let r = br.act("/sell", "/sell", &service(&addr, &[("app_key", "not a key")]));
    assert!(unescape(&r.body).contains("That is not a Jellyfin API key"), "{}", r.body);
    let r = br.act("/sell", "/sell", &service(&addr, &[("app_key", "ffffffffffffffffffffffffffffffff")]));
    assert!(unescape(&r.body).contains("Jellyfin did not accept that API key"), "{}", r.body);
    let r = br.act("/sell", "/sell", &[("action", "service"), ("kind", "media"), ("address", &addr), ("price", "0"), ("unit", "mib"), ("app", "1"),
                                       ("app_accounts", "1"), ("app_key", KEY)]);
    assert!(unescape(&r.body).contains("only on a priced service"), "{}", r.body);
    assert!(!dir.join("config.json").exists() || routes().0.routes.iter().all(|r| r.accounts.is_none()));
    // the right key, no library ticked: every library, the key in a file of its own the route names
    let r = br.act("/sell", "/sell", &service(&addr, &[("app_key", KEY)]));
    assert!(br.flash_after(&r).contains("restarts"), "{}", br.flash_after(&r));
    let (cfg, raw) = routes();
    let root = cfg.routes.iter().find(|r| r.path == "/").expect("the page's route");
    let shop: Value = serde_json::from_str(&std::fs::read_to_string(bx.data.path().join("ui/sell.json")).unwrap()).unwrap();
    let id = shop["offers"][0]["id"].as_str().unwrap().to_string();
    let key_file = dir.join(format!("app-key-{id}.key"));
    assert_eq!(root.accounts, Some(xbt_gateway::config::Accounts::Jellyfin { admin_key_file: key_file.clone(), libraries: vec!["aaaa1111".into(), "bbbb2222".into()] }));
    assert_eq!(std::fs::read_to_string(&key_file).unwrap().trim(), KEY);
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&key_file).unwrap().permissions().mode() & 0o077, 0o040, "the owner and the gateway's group only");
    }
    assert!(!raw.to_string().contains(KEY) && !shop.to_string().contains(KEY), "the key is in its file only");
    // the page shows the libraries to tick, and never the key
    let page = br.get(&format!("/sell?edit={id}")).body;
    assert!(page.contains("Films") && page.contains("name=\"app_lib_bbbb2222\"") && page.contains("leave empty to keep it") && !page.contains(KEY), "{page}");
    // one library ticked, the key kept: that library only
    let r = br.act("/sell", "/sell", &service(&addr, &[("id", &id), ("app_lib_bbbb2222", "1")]));
    assert!(br.flash_after(&r).contains("restarts"), "{}", br.flash_after(&r));
    let root = routes().0.routes.into_iter().find(|r| r.path == "/").unwrap();
    assert_eq!(root.accounts, Some(xbt_gateway::config::Accounts::Jellyfin { admin_key_file: key_file.clone(), libraries: vec!["bbbb2222".into()] }));
    // accounts off: the route has none, and the key is gone
    let r = br.act("/sell", "/sell", &[("action", "service"), ("id", &id), ("kind", "media"), ("address", &addr), ("price", "20"), ("unit", "mib"), ("app", "1"), ("app_entry", "/web/")]);
    assert!(br.flash_after(&r).contains("restarts"), "{}", br.flash_after(&r));
    assert!(routes().0.routes.iter().all(|r| r.accounts.is_none()));
    assert!(!key_file.exists());
}

/// A page on another port of this host (a seller's own app, another app of the box) is of the same
/// site: the browser sends the wallet's cookies with what it asks. Only the opening of the home page
/// is answered; a stream, an action or another page is not.
#[cfg(unix)]
#[test]
fn a_request_from_another_page_of_the_same_site_is_refused_and_home_still_opens() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |_| {});
    let mut br = logged_in(&bx);
    let site = [("Sec-Fetch-Site", "same-site"), ("Sec-Fetch-Mode", "no-cors"), ("Sec-Fetch-Dest", "video")];
    let r = br.send("GET", "/s/https://seller.example/film", None, &site);
    assert_eq!(r.status, 403, "a stream asked by another page");
    let r = br.send("GET", "/browse", None, &[("Sec-Fetch-Site", "same-site"), ("Sec-Fetch-Mode", "cors"), ("Sec-Fetch-Dest", "empty")]);
    assert_eq!(r.status, 403);
    let nav = [("Sec-Fetch-Site", "same-site"), ("Sec-Fetch-Mode", "navigate"), ("Sec-Fetch-Dest", "document")];
    let r = br.send("GET", "/sell", None, &nav);
    assert_eq!((r.status, r.location()), (303, "/"), "a page another page opens is the home page");
    assert_eq!(br.send("GET", "/", None, &nav).status, 200, "the box's dashboard opens the app");
    let csrf = field(&br.get("/browse").body, "csrf");
    let r = br.send("POST", "/logout", Some(&format!("csrf={}", enc(&csrf))), &[("Sec-Fetch-Site", "same-site")]);
    assert_eq!(r.status, 403, "an action asked by another page, with the right token even");
    // the page itself, as before
    assert_eq!(br.send("GET", "/browse", None, &[("Sec-Fetch-Site", "same-origin")]).status, 200);
    assert_eq!(br.send("POST", "/logout", Some(&format!("csrf={}", enc(&csrf))), &[("Sec-Fetch-Site", "same-origin")]).status, 303);
}

/// A box whose node keys are pasted (StartOS: Lightning Fork grants the wallet's key only) gives the
/// gateway its link signing key on Sell too, or its node never vouches for the shop's direct link and
/// no buyer can allow it. The key is optional, checked to sign messages and nothing else, and either
/// way lnd writes that (the URI permission, or the `message:write` entity Lightning Fork bakes).
#[cfg(unix)]
#[test]
fn a_pasted_link_signing_key_lets_the_node_vouch_for_the_direct_link() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let gw = tempfile::tempdir().unwrap();
    let dir = gw.path().to_path_buf();
    let bx = start(json!({}), false, |c| {
        c.sell = true;
        c.gw.dir = dir.clone();
        c.gw.node_rest = Some("https://10.21.21.66:8180".into());
        c.gw.node_tls_cert = Some("/data/lightning/tls.cert".into());
    });
    let mut br = logged_in(&bx);
    let page = br.get("/sell").body;
    assert!(page.contains("name=\"sign_macaroon\""), "step 1 asks for the link signing key: {page}");
    let inv = mac(&[("invoices", &["read", "write"])]);
    let info = mac(&[("info", &["read"])]);
    let sign_uri = mac(&[("uri", &["/lnrpc.Lightning/SignMessage"])]);
    let sign_entity = mac(&[("message", &["write"])]);
    let sign = dir.join("sign.macaroon");

    // a key that can do more than sign is refused, by the permission it should not have, and nothing is written
    let wide = mac(&[("message", &["write"]), ("invoices", &["write"])]);
    let r = br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &inv), ("info_macaroon", &info), ("sign_macaroon", &wide)]);
    let said = br.flash_after(&r);
    assert!(said.contains("does not fit") && said.contains("invoices:write"), "{said}");
    assert!(!sign.exists() && !dir.join("invoices.macaroon").exists(), "nothing written when one key is refused");
    // an invoices key in the signing field is refused
    let r = br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &inv), ("info_macaroon", &info), ("sign_macaroon", &inv)]);
    let said = br.flash_after(&r);
    assert!(said.contains("does not fit") && said.contains("invoices:read"), "{said}");
    assert!(!sign.exists());
    // so is SignMessage's URI with another URI beside it, named; and a key whose permissions can't be read
    let uris = mac(&[("uri", &["/lnrpc.Lightning/SignMessage", "/lnrpc.Lightning/SendCoins"])]);
    let r = br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &inv), ("info_macaroon", &info), ("sign_macaroon", &uris)]);
    let said = br.flash_after(&r);
    assert!(said.contains("does not fit") && said.contains("uri:/lnrpc.Lightning/SendCoins") && !said.contains("SignMessage,"), "{said}");
    let nothing = hex::encode(xbt402::macaroon::lnd_macaroon_for_tests(&[], &[]));
    let r = br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &inv), ("info_macaroon", &info), ("sign_macaroon", &nothing)]);
    let said = br.flash_after(&r);
    assert!(said.contains("grants no permission"), "{said}");
    // not lnd's identifier (its version byte): what it allows can't be read from it
    let mut other = xbt402::macaroon::lnd_macaroon_for_tests(&[("message", &["write"])], &[]);
    assert_eq!(other[8], 3, "the identifier's version byte");
    other[8] = 4;
    let r = br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &inv), ("info_macaroon", &info), ("sign_macaroon", &hex::encode(&other))]);
    let said = br.flash_after(&r);
    assert!(said.contains("cannot be read"), "{said}");
    assert!(!sign.exists());

    // without it the shop connects (it can sell at a web address), and the page says what is missing
    let r = br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &inv), ("info_macaroon", &info), ("sign_macaroon", "")]);
    assert!(br.flash_after(&r).contains("connected"));
    assert!(!sign.exists());
    let page = br.get("/sell").body;
    assert!(page.contains("name=\"sign_macaroon\""), "the replace form takes it later: {page}");

    // Lightning Fork's kind (message:write) is taken on its own, the other keys kept; the shop is not
    // restarted for it (the gateway reads it at its next look at the link) and the page does not say it is
    let r = br.act("/sell", "/sell", &[("action", "connect"), ("sign_macaroon", &sign_entity)]);
    let said = br.flash_after(&r);
    assert!(said.contains("connected") && !said.contains("restarts with it"), "{said}");
    assert_eq!(hex::encode(std::fs::read(&sign).unwrap()), sign_entity);
    assert_eq!(hex::encode(std::fs::read(dir.join("invoices.macaroon")).unwrap()), inv);
    // and the URI kind, as Umbrel and Linux bake it, replaces it
    let r = br.act("/sell", "/sell", &[("action", "connect"), ("sign_macaroon", &sign_uri)]);
    assert!(br.flash_after(&r).contains("connected"));
    assert_eq!(hex::encode(std::fs::read(&sign).unwrap()), sign_uri);
    // a key with both (each signs messages only) is taken; so is one narrowed further by caveats
    let both = mac(&[("message", &["write"]), ("uri", &["/lnrpc.Lightning/SignMessage"])]);
    let r = br.act("/sell", "/sell", &[("action", "connect"), ("sign_macaroon", &both)]);
    assert!(br.flash_after(&r).contains("connected"));
    assert_eq!(hex::encode(std::fs::read(&sign).unwrap()), both);
    let caveated = xbt402::macaroon::lnd_macaroon_for_tests(&[("message", &["write"])], &["time-before 2099-01-01T00:00:00Z", "ipaddr 10.21.21.66"]);
    // pasted as base64, wrapped over lines as a dashboard shows it
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&caveated);
    let wrapped: String = b64.as_bytes().chunks(40).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("\n");
    let r = br.act("/sell", "/sell", &[("action", "connect"), ("sign_macaroon", &format!("  {wrapped}\n"))]);
    assert!(br.flash_after(&r).contains("connected"));
    assert_eq!(std::fs::read(&sign).unwrap(), caveated);
    // written as the gateway's other keys are: readable by its group, by no one else
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&sign).unwrap().permissions().mode() & 0o777, 0o640);
}

/// A link signing key pasted alone on a running, complete shop does not touch the gateway's config:
/// the gateway restarts on any change to it (cutting buyers' sessions), and it reads the sign key
/// itself. A config written on an earlier day differs from today's only by the listing's date,
/// which is no change, so it is left byte for byte. The same holds for any save that changes nothing.
#[cfg(unix)]
#[test]
fn a_sign_key_pasted_on_a_running_shop_leaves_its_config_as_it_is_from_any_day() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let gw = tempfile::tempdir().unwrap();
    let dir = gw.path().to_path_buf();
    let media = mock_http(|_| (200, "ok"));
    let bx = start(json!({}), false, |c| {
        c.sell = true;
        c.gw.dir = dir.clone();
        c.gw.node_rest = Some("https://10.21.21.66:8180".into());
        c.nostr_relays = vec!["wss://relay.one.example".into()];
    });
    let mut br = logged_in(&bx);
    br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &mac(&[("invoices", &["read", "write"])])),
                               ("info_macaroon", &mac(&[("info", &["read"])]))]);
    br.act("/sell", "/sell", &[("action", "advanced"), ("max_sessions", "30"), ("sessions_per_address", "2"), ("max_held_tickets", "15"),
                               ("proxies", ""), ("network", "bip122:0123456789abcdef0123456789abcdef")]);
    br.act("/sell", "/sell", &[("action", "shop"), ("name", "Home films"), ("reach", "direct")]);
    let r = br.act("/sell", "/sell", &[("action", "service"), ("kind", "web"), ("address", &format!("http://{media}")), ("price", "1"), ("unit", "request")]);
    assert!(br.flash_after(&r).contains("restarts with it"), "a complete shop: its config is written");
    let path = dir.join("config.json");
    // the config as the gateway runs it, written yesterday (or any earlier day)
    let mut c: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert!(c["listing"]["updated"].is_string() && c["link"].is_object(), "{c}");
    c["listing"]["updated"] = json!("2000-01-01");
    let yesterday = serde_json::to_string_pretty(&c).unwrap() + "\n";
    std::fs::write(&path, &yesterday).unwrap();

    let sign = mac(&[("message", &["write"])]);
    let r = br.act("/sell", "/sell", &[("action", "connect"), ("sign_macaroon", &sign)]);
    let said = br.flash_after(&r);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), yesterday, "config.json untouched, so the gateway is not restarted");
    assert_eq!(hex::encode(std::fs::read(dir.join("sign.macaroon")).unwrap()), sign);
    assert!(said.contains("signing key is in") && said.contains("within a minute") && said.contains("keeps running")
            && !said.contains("restarts"), "{said}");
    // the payment requests key pasted again as it is: nothing changed, the shop keeps running
    let inv = mac(&[("invoices", &["read", "write"])]);
    let r = br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &inv)]);
    let said = br.flash_after(&r);
    assert!(said.contains("keeps running") && !said.contains("restarts"), "{said}");
    // a new one: the config is the same, but the gateway's supervisor watches that key and restarts it
    let new_inv = hex::encode(xbt402::macaroon::lnd_macaroon_for_tests(&[("invoices", &["read", "write"])], &["time-before 2099-01-01T00:00:00Z"]));
    let r = br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &new_inv)]);
    let said = br.flash_after(&r);
    assert!(said.contains("restarts with it") && !said.contains("keeps running"), "{said}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), yesterday, "the config itself is still as it was");
    assert_eq!(hex::encode(std::fs::read(dir.join("invoices.macaroon")).unwrap()), new_inv);
    // so with the network time key, given with the sign key
    let new_info = hex::encode(xbt402::macaroon::lnd_macaroon_for_tests(&[("info", &["read"])], &["time-before 2099-01-01T00:00:00Z"]));
    let r = br.act("/sell", "/sell", &[("action", "connect"), ("info_macaroon", &new_info), ("sign_macaroon", &sign)]);
    let said = br.flash_after(&r);
    assert!(said.contains("restarts with it"), "{said}");
    // a save that changes nothing leaves it too, and says the shop keeps running
    let r = br.act("/sell", "/sell", &[("action", "shop"), ("name", "Home films"), ("reach", "direct")]);
    let said = br.flash_after(&r);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), yesterday);
    assert!(said.contains("keeps running") && !said.contains("restarts"), "{said}");
    // a real change is written, with today's date
    let r = br.act("/sell", "/sell", &[("action", "shop"), ("name", "Home films and more"), ("reach", "direct")]);
    assert!(br.flash_after(&r).contains("restarts with it"));
    let c: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(c["listing"]["name"], "Home films and more");
    assert_ne!(c["listing"]["updated"], "2000-01-01");
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
    assert!(f.contains("connected") && f.contains("Say how buyers reach you"), "{f}");
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
    // the media server: the first service gets the root, and is shared as its own web app (films listed for the
    // old built-in player are not kept)
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
    let kinds: Vec<&str> = l.services.iter().map(|s| s.kind.as_str()).collect();
    assert_eq!((l.name.as_str(), kinds), ("Mike's box", vec!["video", "app", "ai"]), "the media server with its web app, then the model");
    assert!(l.services[0].items.is_empty(), "no films listed for a player");
    assert_eq!(l.services[1].items[0].url, "https://seller.example/", "the web app opens at the shop's root");
    // a new shop is published on Nostr, on the app's relays, with nothing written by hand
    let n = cfg.nostr.as_ref().expect("a nostr section");
    assert!(n.publish);
    assert_eq!(n.relays, ["wss://relay.one.example", "wss://relay.two.example"]);


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
    assert_eq!(l.services.len(), 3, "the media server, its web app, and the hashrate");
    // the shop sells a ticket of the first step, and the route larger prepaid ones; the shop's own size, which the
    // held budget is figured on, stays
    let conf = || -> Value { serde_json::from_str::<Value>(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap() };
    let tickets = || conf()["tickets"].clone();
    assert_eq!((tickets()["min_ticket_msat"].clone(), tickets()["ticket_msat"].clone()), (json!(546_000), json!(900_000)), "{}", tickets());
    let top = |c: &Value| c["routes"].as_array().unwrap().iter().find(|r| r["path"] == "/hashrate/").unwrap()["top_ticket_msat"].clone();
    assert_eq!(top(&conf()), json!(100_000_000), "{}", conf());
    let r = br.act("/sell-hashrate", "/sell-hashrate", &[("action", "save"), ("fallback", "192.168.1.20:23334"), ("price", "40")]);
    assert!(br.flash_after(&r).contains("Renting is off"));
    assert!(listing().services.iter().all(|s| s.kind != "hashrate"));
    // an update that lists more: the config is written again at start, without a Save
    let mut st: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("hashrate-settings.json")).unwrap()).unwrap();
    st["enabled"] = json!(true);
    std::fs::write(dir.join("hashrate-settings.json"), st.to_string()).unwrap();
    assert!(listing().services.iter().all(|s| s.kind != "hashrate"));
    // and the ticket follows it, from what a hand wrote above the first step: an update needs no Save to be rentable
    let mut c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    c["tickets"]["min_ticket_msat"] = json!(800_000);
    std::fs::write(dir.join("config.json"), c.to_string()).unwrap();
    assert_eq!(bx._app.refresh_shop_config(), Some("written"));
    assert!(listing().services.iter().any(|s| s.kind == "hashrate"));
    assert_eq!(tickets()["min_ticket_msat"], json!(546_000), "{}", tickets());
    assert_eq!(top(&conf()), json!(100_000_000), "the route's top ticket, written at start too: {}", conf());
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
    // and at start, with no save: a shop that moved before this version still has its items at the old
    // address in its saved settings; the config written at start lists them at the new one
    let mut shop: Value = serde_json::from_str(&std::fs::read_to_string(bx.data.path().join("ui/sell.json")).unwrap()).unwrap();
    shop["offers"][0]["titles"] = json!([{"title": "Sintel", "url": "https://seller.example/Videos/s/stream"}]);
    std::fs::write(bx.data.path().join("ui/sell.json"), shop.to_string()).unwrap();
    let mut c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    c["listing"]["services"][0]["items"] = json!([{"title": "Sintel", "url": "https://seller.example/Videos/s/stream"}]);
    std::fs::write(dir.join("config.json"), c.to_string()).unwrap();
    assert_eq!(bx._app.refresh_shop_config(), Some("written"));
    let at_start = cfg(&dir).listing.unwrap().services.into_iter().find(|s| s.kind == "video").unwrap().items;
    assert!(at_start.iter().all(|i| i.url.starts_with("https://new.example/")), "at start too: {at_start:?}");
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
    // the model's page gives the address apps and agents use it at; the films (an older listing) are files
    let model = br.get(&format!("/service?seller={}&name={}", enc(origin), enc("Mike's box: Model"))).body;
    assert!(model.contains("value=\"https://seller.example/ai/\"") && model.contains("0.5 sat a request") && !model.contains("<video"), "{model}");
    let films = br.get(&format!("/service?seller={}&name={}", enc(origin), enc("Mike's box: Films"))).body;
    assert!(films.contains("Sintel") && films.contains(">Download</a>") && !films.contains("./play?item="), "{films}");
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
    // a film found on Nostr is listed, with nothing to play: the app has no player
    let film = format!("{origin}/v/sintel");
    assert!(page.body.contains(&film) && !page.body.contains("./play?item="));

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
                 "/service?seller=https%3A%2F%2Fai.example&name=Local%20model", "/service?seller=https%3A%2F%2Fmedia.example&name=Open%20films"] {
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
            "blinding": {"state": "blinded", "why": "solo", "words": "Blinded: a hashmaker can't tell which shares win, so it can't drop those."},
            "rentals": [{"rental": "r9", "hasher": "Basement miners", "miners": 1, "budgetSats": 4000, "minutes": 60, "ended": false,
                         "live": {"closed": null, "paidSlices": 5, "spentMsat": 200000, "miners": 1, "lastRate": {"hs": 4.1e12},
                                  "walletMovedSats": 1002, "leftWithSellerMsat": 800000}}]}),
        ("GET", "/offers") => json!({"offers": [{"name": "Basement miners", "linkKey": "02bb", "priceMsat": 40000, "sliceWork": "140737488355328",
                                                  "miners": 2, "freeMiners": 1, "freeHs": "4000000000000",
                                                  "trialMayBuyTicketUpToSats": 2000, "mayBuyTicketUpToSats": 2000},
                                                 {"name": "Garage miners", "linkKey": "02dd", "priceMsat": 40000, "sliceWork": "140737488355328",
                                                  "miners": 1, "freeMiners": 1, "freeHs": "4000000000000",
                                                  "payUrl": "https://miners.example/hashrate", "payNode": format!("03{}", "c".repeat(64))}]}),
        ("POST", "/rent") => json!({"ok": true, "rental": "r10", "budgetSats": 40, "mayBuyTicketUpToSats": 2000}),
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
    assert!(p.body.contains("name=\"enabled\" value=\"1\" checked> Rent out my miners"), "an owner renting keeps the box ticked: {}", p.body);
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
    // a trial (40 sats) and a small rental may buy the shop's whole ticket: what may leave the wallet is said
    let basement = &p.body[p.body.find("Hashrate</span><h3>Basement miners</h3>").unwrap()..];
    let basement = &basement[..basement.find("</section>").unwrap()];
    assert_eq!(basement.matches("your wallet may buy a ticket of up to 2,000 sats from this shop; unused credit stays with this seller for about 20 hours, \
                                 for a later rental there").count(), 2,
               "the trial's text and the rental's: {basement}");
    // the rental's card says what left the wallet (a ticket bought whole) and what stays with the seller, not only the slices
    let card = &p.body[p.body.find("Hashrate from Basement miners").unwrap()..];
    let card = &card[..card.find("</section>").unwrap()];
    assert!(card.contains("Left your wallet: <span class=\"money\">1,002 sats</span>, a ticket bought whole from this shop; 800 sats of it stays \
                           with this seller as credit for about 20 hours"), "{card}");
    assert!(basement.contains("about 40 sats") && basement.contains("charged at most that"), "{basement}");
    let r = br.act("/hashrate", "/hashrate", &[("action", "rent"), ("key", "02bb"), ("miners", "1"), ("budget", "4000"), ("minutes", "60")]);
    assert!(br.flash_after(&r).starts_with("Renting."));
    let rent = rseen.lock().unwrap().iter().find(|(m, p, _, _)| m == "POST" && p == "/rent").cloned().unwrap();
    let body: Value = serde_json::from_str(&rent.3).unwrap();
    assert_eq!((body["linkKey"].clone(), body["miners"].clone(), body["budgetSats"].clone()), (json!("02bb"), json!(1), json!(4000)));
    assert_eq!(rent.2, format!("Bearer {}", "r".repeat(64)));
    // the form sent twice (a double click, the browser sending it again) carries one request mark, which the
    // renter's service starts one rental for: each Rent form has its own
    let page = br.get("/hashrate").body;
    let form = &page[page.find("Hashrate</span><h3>Basement miners</h3>").unwrap()..];
    let once = field(&form[form.find("value=\"rent\"").unwrap()..], "once");
    assert!(once.len() >= 32, "{once}");
    assert_ne!(once, field(&form[form.find("value=\"trial\"").unwrap()..], "once"), "the trial's form has a mark of its own");
    let csrf = field(&page, "csrf");
    for _ in 0..2 {
        let r = br.post("/hashrate", &[("csrf", csrf.as_str()), ("action", "rent"), ("key", "02bb"), ("miners", "1"), ("budget", "4000"), ("minutes", "60"),
                                       ("once", once.as_str())]);
        assert!(br.flash_after(&r).starts_with("Renting."));
    }
    let marks: Vec<Value> = rseen.lock().unwrap().iter().filter(|(m, p, _, _)| m == "POST" && p == "/rent")
        .map(|x| serde_json::from_str::<Value>(&x.3).unwrap()["once"].clone()).collect();
    assert_eq!(marks[marks.len() - 2..], [json!(once), json!(once)], "both sends carried the form's mark: {marks:?}");
    assert_ne!(field(&br.get("/hashrate").body, "once"), once, "a page shown again has new marks");
    let r = br.act("/hashrate", "/hashrate", &[("action", "trial"), ("key", "02bb")]);
    let said = br.flash_after(&r);
    assert!(said.starts_with("Trying one slice, at most 40 sats. Your wallet may buy a ticket of up to 2,000 sats from this shop for it; unused credit stays \
                              with this seller for about 20 hours, for a later rental there."),
            "{said}");
    // Live connections shows the rental, with its Cut button
    let p = br.get("/connections");
    assert!(p.body.contains("Rented hashrate") && p.body.contains("data-spent=\"200\""), "{}", p.body);
    plain("/connections", &p.body);
    let r = br.act("/connections", "/hashrate", &[("action", "cut"), ("rental", "r9"), ("back", "connections")]);
    assert_eq!(r.location(), "./connections");
    assert!(rseen.lock().unwrap().iter().any(|(m, p, _, b)| m == "POST" && p == "/cut" && b.contains("r9")));
}

/// Without an address renters outside can reach, the offer stays off public listings and the page
/// An owner who has never saved the form finds "Rent out my miners" not ticked, with what a renter's word
/// means beside it, and one who has saved keeps their choice, either way.
#[test]
fn renting_out_starts_unticked_says_what_a_renter_can_do_and_keeps_a_saved_choice() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (hasher, _hseen) = control_standin(|m, p| match (m, p) {
        // as a hashmaker with a settings file not yet written says: not enabled, no fallback
        ("GET", "/status") => json!({"open": false, "settings": {"enabled": false, "priceSat": 40, "sliceWork": "140737488355328", "graceMs": 45000},
                                      "minersAddress": "umbrel.local:23340", "miners": [], "rentals": []}),
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
    const OFF: &str = "name=\"enabled\" value=\"1\"> Rent out my miners";
    const ON: &str = "name=\"enabled\" value=\"1\" checked> Rent out my miners";
    const WARNING: &str = "A renter gets no work it hasn&#39;t paid for. If it stops paying, your miners go back to your own pool within seconds. A renter whose payment is slow to arrive can send them back to it for up to 10 seconds while it does. Your node checks every share&#39;s hash itself, so a renter&#39;s word doesn&#39;t set what the work is worth.";
    assert!(!settings.exists(), "nothing saved yet");
    let p = br.get("/sell-hashrate");
    assert!(p.body.contains(OFF) && !p.body.contains(ON), "first view: not ticked: {}", p.body);
    let warning = |body: &str| body.contains(WARNING) || body.contains(&WARNING.replace("&#39;", "'"));
    assert!(warning(&p.body), "the warning, before anything is saved: {}", p.body);
    assert!(p.body.find("Rent out my miners").unwrap() < p.body.find("A renter gets no work").unwrap(), "next to the choice");
    assert!(p.body.find("A renter gets no work").unwrap() < p.body.find("<button>Save</button>").unwrap(), "before the save: {}", p.body);
    // saved on, it stays on
    let save = |on: bool| {
        let mut f = vec![("action", "save"), ("fallback", "192.168.1.20:23334"), ("price", "40")];
        if on {
            f.push(("enabled", "1"));
        }
        f
    };
    let r = br.act("/sell-hashrate", "/sell-hashrate", &save(true));
    assert!(br.flash_after(&r).starts_with("Saved. Renting is on."));
    let p = br.get("/sell-hashrate");
    assert!(p.body.contains(ON), "saved on: {}", p.body);
    assert!(warning(&p.body), "the warning stays: {}", p.body);
    // saved off, it stays off
    let r = br.act("/sell-hashrate", "/sell-hashrate", &save(false));
    assert!(br.flash_after(&r).contains("Renting is off"));
    let p = br.get("/sell-hashrate");
    assert!(p.body.contains(OFF) && !p.body.contains(ON), "saved off: {}", p.body);
}

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

/// A hashmaker whose direct link is up needs no port forward: the page says so in plain words, the
/// forwarded address moves under Advanced as optional, and the offer is listed without one.
#[test]
fn hashrate_over_the_direct_link_needs_no_address() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (hasher, _hseen) = control_standin(|m, p| match (m, p) {
        ("GET", "/status") => json!({
            "open": true, "settings": {"enabled": true, "fallback": "192.168.1.20:23334", "priceSat": 40, "sliceWork": "140737488355328", "graceMs": 45000,
                                       "rentable": 1, "name": "Basement miners", "linkPublic": null},
            "minersAddress": "umbrel.local:23340", "linkLan": "umbrel.local:23341",
            "iroh": {"id": "ab".repeat(32), "relays": ["https://relay.example/"]},
            "listing": {"ok": true, "freeMiners": 1, "miners": 1},
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
    for s in ["No setup", "no port forward, address or certificate is needed", "Listed", "Also reachable at a forwarded address"] {
        assert!(p.body.contains(s), "{s} missing from Sell hashrate: {}", p.body);
    }
    assert!(!p.body.contains("(needs a port forward or tunnel)"), "the port forward is no longer asked for: {}", p.body);
    // the forwarded address sits under Advanced, after the main choices
    let adv = p.body.find("<summary>Advanced</summary>").unwrap();
    assert!(p.body.find("Also reachable at a forwarded address").unwrap() > adv, "the forwarded address is under Advanced");
    // saving without one is fine
    let r = br.act("/sell-hashrate", "/sell-hashrate", &[("action", "save"), ("fallback", "192.168.1.20:23334"), ("price", "40"), ("enabled", "1")]);
    assert!(br.flash_after(&r).starts_with("Saved."));
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
    let s = xbt_wallet_ui::node_keys::Settings { rest: "https://10.21.21.66:8180".into(), tls_cert: None, admin: dir.join("none"), grant: None, bake_to: None, take_from: None,
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

/// Umbrel, the app installed before the owner made the wallet in Lightning Fork: the Lightning page says
/// to make the wallet there, and that the app then connects by itself (node-keys-bake).
#[cfg(unix)]
#[test]
fn before_the_nodes_wallet_exists_the_page_says_to_make_it_in_lightning_fork() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let ln = tempfile::tempdir().unwrap();
    let dir = ln.path().to_path_buf();
    let b = start(json!({}), false, |c| {
        c.ln.dir = dir.clone();
        c.ln.rest = Some("https://10.21.21.66:8180".into());
        c.ln.auto = true;
    });
    let mut br = logged_in(&b);
    let page = br.get("/lightning").body;
    assert!(page.contains("Not connected") && page.contains("Create your Lightning wallet in Lightning Fork first")
            && page.contains("picks it up automatically"), "{page}");
}

/// Umbrel (node-keys-bake): after the owner disconnects the key the app made, the page promises no
/// automatic reconnect (the baker makes nothing turned off), and "Reconnect automatically" lets the
/// next start make it again.
#[cfg(unix)]
#[test]
fn a_disconnect_on_a_box_that_makes_the_key_is_not_undone_unless_asked() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let ln = tempfile::tempdir().unwrap();
    let dir = ln.path().to_path_buf();
    let s = xbt_wallet_ui::node_keys::Settings { rest: "https://10.21.21.66:8180".into(), tls_cert: None, admin: dir.join("none"), grant: None, bake_to: None, take_from: None,
                                                 rail_dir: Some(dir.clone()), gw_dir: None };
    let rail = mac(&[("info", &["read"]), ("offchain", &["read", "write"]), ("onchain", &["read"])]);
    xbt_wallet_ui::node_keys::make_keys(&s, &mut |_, _| Ok(hex::decode(&rail).unwrap())).unwrap();
    let b = start(json!({}), false, |c| {
        c.ln.dir = dir.clone();
        c.ln.rest = Some("https://10.21.21.66:8180".into());
        c.ln.auto = true;
    });
    let mut br = logged_in(&b);
    let r = br.act("/lightning", "/lightning", &[("action", "remove")]);
    assert!(br.flash_after(&r).contains("removed"));
    let page = br.get("/lightning").body;
    assert!(page.contains("Not connected") && page.contains("You disconnected the key the app made")
            && page.contains("Reconnect automatically"), "{page}");
    assert!(!page.contains("picks it up automatically"), "promises a reconnect that never comes: {page}");
    // the baker makes nothing turned off
    assert!(xbt_wallet_ui::node_keys::run(&s).unwrap().made.is_empty());
    let r = br.act("/lightning", "/lightning", &[("action", "auto_on")]);
    let said = br.flash_after(&r);
    assert!(said.contains("makes its key again") && said.contains("restart"), "{said}");
    assert!(!xbt_wallet_ui::node_keys::turned_off(&dir));
    let page = br.get("/lightning").body;
    assert!(page.contains("makes its key again when it restarts") && !page.contains("Reconnect automatically"), "{page}");
    // and the next start makes it
    assert_eq!(xbt_wallet_ui::node_keys::make_keys(&s, &mut |_, _| Ok(hex::decode(&rail).unwrap())).unwrap().made, vec!["rail.macaroon"]);
}

/// Umbrel: the owner's own key removed on a box that makes its key: the page says the app makes one
/// when it restarts (the baker ran at the start and is gone), not "within a minute".
#[cfg(unix)]
#[test]
fn removing_the_owners_own_key_on_a_box_that_makes_one_says_to_restart() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let ln = tempfile::tempdir().unwrap();
    let dir = ln.path().to_path_buf();
    let rail = mac(&[("info", &["read"]), ("offchain", &["read", "write"]), ("onchain", &["read"])]);
    std::fs::write(dir.join("rail.macaroon"), hex::decode(&rail).unwrap()).unwrap();
    let b = start(json!({}), false, |c| {
        c.ln.dir = dir.clone();
        c.ln.rest = Some("https://10.21.21.66:8180".into());
        c.ln.auto = true;
    });
    let mut br = logged_in(&b);
    let r = br.act("/lightning", "/lightning", &[("action", "remove")]);
    let said = br.flash_after(&r);
    assert!(said.contains("removed") && said.contains("makes its own key when it restarts"), "{said}");
    let page = br.get("/lightning").body;
    assert!(page.contains("makes its key again when it restarts") && !page.contains("within a minute"), "{page}");
    assert!(!xbt_wallet_ui::node_keys::turned_off(&dir), "not turned off: the next start makes the app's key");
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


/// A box cannot buy from its own shop: its services are marked as the owner's, and its files are
/// listed with nothing to buy. There is no player to preview films in.
#[test]
fn your_own_shop_is_marked_and_has_no_player() {
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
    assert!(page.contains("This is your shop") && page.contains("Sintel") && !page.contains(">Download</a>") && !page.contains("./play?"), "{page}");
    let theirs = br.get(&format!("/service?seller={}&name={}", enc("https://other.example"), enc("Their films"))).body;
    assert!(!theirs.contains("This is your shop"));
    // the old preview of an item is gone with the player, and never streams the film
    let r = br.get(&format!("/preview?item={}", enc(item)));
    assert!(r.status == 404 && r.body != "FILM BYTES", "{}", r.status);
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
    // by its name where the list of sellers has one, else its short address
    assert!(page.contains("Allow seller.example to be paid") && page.contains("in any 7 days"), "{page}");
    assert!(page.contains("https://seller.example") && page.contains(&node), "{page}");
    // a bad node is ignored: nothing filled in
    let page = br.get(&format!("/policy?allow={}&node=zz", enc("https://seller.example"))).body;
    assert!(!page.contains("Allow seller.example to be paid"));
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
    // reached directly through the app by default; an https address of one's own is under Advanced
    assert!(page.contains("Directly, through the app") && page.contains("value=\"direct\" checked"), "{page}");
    assert!(page.contains("Advanced: use my own https address instead"), "{page}");
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
    assert!(page.contains("Your Lightning node needs a limit before the app can pay through it: <span class=\"money\">1,000,000 sats"), "{page}");
    assert!(page.contains("name=\"f_ln_exposure_cap_sats\" value=\"1000000\""), "{page}");
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
               (json!(true), json!(1000000), starter["max_per_tx_sats"].clone()), "{signed}");
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

#[test]
fn the_stream_relays_page_lists_announced_relays_and_keeps_the_owner_s_choices() {
    use xbt_nostr::{event::Keys, oneshot, relays, standin::StandinRelay};
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let relay = StandinRelay::start().unwrap();
    let nostr = vec![relay.url.clone()];
    // two announced relays: neither answers a probe here (port 9 on this machine), so neither is used
    for (host, region) in [("relay-a.example", "eu-central"), ("relay-b.example", "us-west")] {
        let offer = relays::Offer { relay: format!("https://{host}"), region: region.into(), capacity_mbit: Some(200), udp: false,
                                    contact: String::new(), note: String::new(), ttl_s: 86_400 };
        let ev = relays::announcement_event(&Keys::generate(), &offer, xbt_nostr::now()).unwrap();
        assert_eq!(oneshot::publish(&nostr, &ev, Duration::from_secs(5))[0].result, Ok(()));
    }
    let bx = start(json!({}), false, |c| {
        c.nostr_relays = nostr.clone();
        c.stream_relay = "https://127.0.0.1:9/".into();
    });
    let mut br = logged_in(&bx);
    assert_eq!(B::new(&bx.base).get("/relays").location(), "./login");
    let page = br.get("/relays");
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("https://relay-a.example/") && page.body.contains("us-west"));
    assert!(page.body.contains("not answering"));
    assert!(page.body.contains("2 relays announced on 1 of 1 Nostr relays"));
    assert!(page.body.contains("Run a relay for the Stream network") && page.body.contains("RUN-A-RELAY.md"));

    // prefer one, block another; the choices are kept in relays.json, with what they select
    let r = br.act("/relays", "/relays-prefs", &[("action", "pin"), ("relay", "https://Relay-A.example")]);
    assert!(br.flash_after(&r).contains("Saved"));
    let r = br.act("/relays", "/relays-prefs", &[("action", "block"), ("relay", "https://127.0.0.1:9")]);
    assert!(br.flash_after(&r).contains("Saved"));
    let file: Value = serde_json::from_str(&std::fs::read_to_string(bx.data.path().join("ui/relays.json")).unwrap()).unwrap();
    assert_eq!(file["pinned"], json!(["https://relay-a.example/"]));
    assert_eq!(file["blocked"], json!(["https://127.0.0.1:9/"]));
    // nothing answers and the default is blocked: nothing is selected (the link then uses the public relays)
    assert_eq!(file["selected"], json!([]));
    // a bad address is refused in words; only own needs an own relay first
    let r = br.act("/relays", "/relays-prefs", &[("action", "pin"), ("relay", "http://plain.example")]);
    assert!(br.flash_after(&r).contains("https://"));
    let r = br.act("/relays", "/relays-prefs", &[("action", "only-own-on")]);
    assert!(br.flash_after(&r).contains("own relay first"));
    let r = br.act("/relays", "/relays-prefs", &[("action", "own-add"), ("relay", "https://mine.example")]);
    assert!(br.flash_after(&r).contains("Saved"));
    let r = br.act("/relays", "/relays-prefs", &[("action", "only-own-on")]);
    assert!(br.flash_after(&r).contains("Saved"));
    let file: Value = serde_json::from_str(&std::fs::read_to_string(bx.data.path().join("ui/relays.json")).unwrap()).unwrap();
    assert_eq!((file["only_own"].clone(), file["selected"].clone()), (json!(true), json!(["https://mine.example/"])));

    // announcing the owner's relay publishes a signed announcement and lists it as theirs
    let r = br.act("/relays", "/relays-publish", &[("relay", "https://mine.example"), ("region", "home"), ("capacity_mbit", "100"), ("udp", "1")]);
    assert!(br.flash_after(&r).contains("Announced on 1 of 1"));
    let (events, _) = oneshot::query(&nostr, &relays::filter(10), Duration::from_secs(5));
    let (found, refused) = relays::collect(&events, xbt_nostr::now());
    assert_eq!(refused, 0);
    let mine = found.iter().find(|a| a.relay == "https://mine.example/").unwrap();
    assert_eq!((mine.region.as_str(), mine.capacity_mbit, mine.udp), ("home", Some(100), true));
    let r = br.act("/relays", "/relays-publish", &[("relay", "https://mine.example"), ("region", "home"), ("capacity_mbit", "lots")]);
    assert!(br.flash_after(&r).contains("whole number"));
}

/// A shop without a web address (`docs/DIRECT-LINKS.md`): added by its shop key from the app's Nostr
/// relays, shown by that key, and allowed to be paid through the node its link's signature names.
#[test]
fn a_shop_without_a_web_address_is_added_by_its_key_and_allowed_through_the_node_that_vouches_for_its_link() {
    use xbt_nostr::{event::Keys, market, oneshot, standin::StandinRelay};
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let relay = StandinRelay::start().unwrap();
    let relays = vec![relay.url.clone()];
    let keys = Keys::generate();
    let shop = xbt402::shop::origin_for(&keys.public.serialize());
    let npub = xbt402::shop::npub(&keys.public.serialize());
    let (sk, pk) = receipt_key(b"home films");
    let d = xbt402::listing::parse_draft(&json!({
        "name": "Home films", "kind": "video", "prices": {"byte_msat": 1000, "per_bytes": 1048576},
        "items": [{"title": "Sintel", "url": format!("{shop}/v/sintel"), "year": 2010, "credit": "(c) Blender Foundation, CC BY 3.0"}],
        "licence": "CC BY 3.0", "credits": "Blender Foundation", "updated": "2026-10-29",
    })).unwrap();
    let doc = xbt402::listing::sign(&sk, &xbt402::listing::document(&d, &shop, &pk));
    // the seller's node vouches for the shop's link
    let node = Sk::from_slice(&[9u8; 32]).unwrap();
    let node_hex = hex::encode(xbt_primitives::ecdsa::pubkey(&node));
    let expires = xbt_nostr::now() + 30 * 86_400;
    let ep = "ab".repeat(32);
    let link = xbt402::transport::Link { kind: "iroh".into(), endpoint_id: ep.clone(), relays: vec!["https://relay.example".into()], direct: vec![], expires,
                                         node_sig: xbt402::claim::sign(xbt402::claim::claim_text(&ep, &shop, expires).as_bytes(), &node) };
    let t = xbt402::transport::sign(&sk, &xbt402::transport::document(&shop, &pk, &[link], "2026-10-29"));
    let bind = xbt402::listing::bind(&sk, &keys.public.serialize(), &shop);
    let ev = market::listing_event_with(&keys, &doc, &bind, Some(&t), xbt_nostr::now()).unwrap();
    assert_eq!(oneshot::publish(&relays, &ev, Duration::from_secs(5))[0].result, Ok(()));

    let bx = start(json!({}), false, |c| c.nostr_relays = relays.clone());
    let mut br = logged_in(&bx);
    assert!(br.get("/services").body.contains("npub1"), "the form asks for a shop key too");
    let r = br.act("/services", "/services", &[("action", "add"), ("url", &format!("  {npub}  "))]);
    let f = br.flash_after(&r);
    assert!(f.contains("Added Home films: 1 service on Browse now"), "{f}");
    let page = br.get("/services").body;
    assert!(page.contains(&npub) && page.contains("Direct link"), "shown by its key: {page}");
    assert!(!page.contains(&format!(">{shop}<")), "the made-up name is not shown as an address");
    let kept = xbt_wallet_ui::shops::load(&bx.data.path().join("ui/shops.json")).unwrap();
    assert_eq!(kept[&shop].transport, Some(t));
    // allowed: the node is the one whose signature vouches for the link
    let r = br.act("/services", "/services", &[("action", "allow"), ("url", &shop)]);
    assert_eq!(r.status, 303, "{}", r.body);
    assert!(r.location().contains(&format!("node={node_hex}")) && r.location().contains("shop.invalid"), "{}", r.location());
    let rules = br.get(r.location().trim_start_matches('.')).body;
    assert!(rules.contains(&format!("Allow {npub} to be paid")), "the rules page names the shop by its key");
    // and in the list of who may be paid, by its listing's name, with its key under it (#37 items 7, 11)
    assert!(rules.contains("<strong>Home films</strong><br><code class=\"key small\">") && rules.contains(&format!("title=\"{node_hex}\"")), "{rules}");
    // Found on Nostr knows it is on the list (#37 items 6, 15). FAILS before: "Add this shop" still, no mark
    let found = br.get("/nostr").body;
    assert!(found.contains(">On your list<") && found.contains(">Check for updates<") && !found.contains(">Add this shop<"), "{found}");
    assert!(found.contains("A shop reached by its key: its address is that key"), "the intro fits shops reached by their key: {found}");

    // a wrong key, and an unknown one
    // the last character changed to a different one: bech32's checksum catches any one changed character
    let last = if npub.ends_with('q') { 'p' } else { 'q' };
    let r = br.act("/services", "/services", &[("action", "add"), ("url", &format!("{}{last}", &npub[..npub.len() - 1]))]);
    assert!(br.flash_after(&r).contains("not a valid one"));
    let other = xbt402::shop::npub(&Keys::generate().public.serialize());
    let r = br.act("/services", "/services", &[("action", "add"), ("url", &other)]);
    assert!(br.flash_after(&r).contains("could not be found"));
}

/// An AI seller added after the AI address already has one reaches it at once: the sellers file the
/// endpoint reads follows each add, update and removal on the Services page, with no visit to the AI
/// page and no "read the prices again" press.
#[test]
fn ai_sellers_added_or_removed_later_reach_the_ai_address_at_once() {
    use xbt_nostr::{event::Keys, market, oneshot, standin::StandinRelay};
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let relay = StandinRelay::start().unwrap();
    let relays = vec![relay.url.clone()];
    // a shop reached by its key, selling one model at `out` msat per 1,000 tokens written
    let publish = |name: &str, out: u64| {
        let keys = Keys::generate();
        let shop = xbt402::shop::origin_for(&keys.public.serialize());
        let (sk, pk) = receipt_key(name.as_bytes());
        let d = xbt402::listing::parse_draft(&json!({
            "name": name, "services": [{"name": "Model", "kind": "ai", "path": "/ai/", "prices": {"per_1k_output_msat": out}, "items": []}],
            "updated": "2026-10-31",
        })).unwrap();
        let doc = xbt402::listing::sign(&sk, &xbt402::listing::document(&d, &shop, &pk));
        let bind = xbt402::listing::bind(&sk, &keys.public.serialize(), &shop);
        let ev = market::listing_event_with(&keys, &doc, &bind, None, xbt_nostr::now()).unwrap();
        assert_eq!(oneshot::publish(&relays, &ev, Duration::from_secs(5))[0].result, Ok(()));
        (xbt402::shop::npub(&keys.public.serialize()), shop)
    };
    let (npub_a, _) = publish("First shop", 10_000);
    let (npub_b, shop_b) = publish("Second shop", 7_000);
    let dir = tempfile::tempdir().unwrap();
    let ai = dir.path().join("ai");
    let bx = start(json!({}), false, |c| {
        c.nostr_relays = relays.clone();
        c.ai = xbt_wallet_ui::config::AiSetup { endpoint: Some("http://box.local:33540/v1".into()), sellers: ai.join("sellers.json"),
                                                credentials: ai.join("credentials.json"), state: ai.join("state.json") };
    });
    let mut br = logged_in(&bx);
    let sellers = || -> Vec<(String, Value)> {
        let v: Value = serde_json::from_slice(&std::fs::read(ai.join("sellers.json")).unwrap_or_default()).unwrap_or(json!({}));
        let mut s: Vec<(String, Value)> = v["sellers"].as_array().into_iter().flatten()
            .map(|e| (e["name"].as_str().unwrap_or("").to_string(), e["prices"]["per_1k_output_msat"].clone())).collect();
        s.sort_by(|a, b| a.0.cmp(&b.0));
        s
    };
    let added = |br: &mut B, npub: &str| {
        let r = br.act("/services", "/services", &[("action", "add"), ("url", npub)]);
        let f = br.flash_after(&r);
        assert!(f.contains("1 service on Browse now"), "{f}");
    };
    // the first seller, and the AI page seen once (the file is made)
    added(&mut br, &npub_a);
    assert!(br.get("/ai").body.contains("First shop"));
    assert_eq!(sellers().len(), 1, "{:?}", sellers());
    // a second seller added later: in the file at once, at its own price
    added(&mut br, &npub_b);
    let s = sellers();
    assert_eq!(s.len(), 2, "the second seller reaches the AI address without a visit or a press: {s:?}");
    assert!(s.iter().any(|(n, p)| n.starts_with("Second shop") && p.as_str() == Some("7000")), "{s:?}");
    // removed: gone from the file at once
    let r = br.act("/services", "/services", &[("action", "remove"), ("url", &shop_b)]);
    assert!(br.flash_after(&r).contains("Seller removed"));
    let s = sellers();
    assert!(s.len() == 1 && s[0].0.starts_with("First shop"), "{s:?}");
}

/// Two shops that call themselves the same, each selling a model: the AI page and the sellers file
/// the AI address reads tell them apart by their keys, and preferring or blocking one leaves the
/// other as it was.
#[test]
fn two_ai_shops_with_one_name_are_told_apart_and_pinned_or_blocked_one_at_a_time() {
    use xbt_nostr::{event::Keys, market, oneshot, standin::StandinRelay};
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let relay = StandinRelay::start().unwrap();
    let relays = vec![relay.url.clone()];
    let publish = |name: &str, out: u64| {
        let keys = Keys::generate();
        let shop = xbt402::shop::origin_for(&keys.public.serialize());
        let (sk, pk) = receipt_key(format!("{name}{out}").as_bytes());
        let d = xbt402::listing::parse_draft(&json!({
            "name": name, "services": [{"name": "Model", "kind": "ai", "path": "/ai/", "prices": {"per_1k_output_msat": out}, "items": []}],
            "updated": "2026-10-31",
        })).unwrap();
        let doc = xbt402::listing::sign(&sk, &xbt402::listing::document(&d, &shop, &pk));
        let bind = xbt402::listing::bind(&sk, &keys.public.serialize(), &shop);
        let ev = market::listing_event_with(&keys, &doc, &bind, None, xbt_nostr::now()).unwrap();
        assert_eq!(oneshot::publish(&relays, &ev, Duration::from_secs(5))[0].result, Ok(()));
        xbt402::shop::npub(&keys.public.serialize())
    };
    let (a, b) = (publish("Money round shop", 10_000), publish("Money round shop", 7_000));
    let dir = tempfile::tempdir().unwrap();
    let ai = dir.path().join("ai");
    let bx = start(json!({}), false, |c| {
        c.nostr_relays = relays.clone();
        c.ai = xbt_wallet_ui::config::AiSetup { endpoint: Some("http://box.local:33540/v1".into()), sellers: ai.join("sellers.json"),
                                                credentials: ai.join("credentials.json"), state: ai.join("state.json") };
    });
    let mut br = logged_in(&bx);
    for npub in [&a, &b] {
        let r = br.act("/services", "/services", &[("action", "add"), ("url", npub)]);
        assert!(br.flash_after(&r).contains("on Browse now"));
    }
    let r = br.act("/ai", "/ai", &[("do", "refresh")]);
    assert_eq!(r.status, 303, "{}", r.body);
    let file = || -> Value { serde_json::from_slice(&std::fs::read(ai.join("sellers.json")).unwrap()).unwrap() };
    let named: Vec<(String, String)> = file()["sellers"].as_array().unwrap().iter()
        .map(|e| (e["name"].as_str().unwrap().to_string(), e["prices"]["per_1k_output_msat"].as_str().unwrap_or("").to_string())).collect();
    assert_eq!(named.len(), 2, "{named:?}");
    let name_of = |npub: &str, price: &str| -> String {
        let n = named.iter().find(|(_, p)| p == price).unwrap().0.clone();
        assert!(n.contains("Money round shop") && n.contains(&npub[..14]), "named by its key: {n}");
        n
    };
    let (na, nb) = (name_of(&a, "10000"), name_of(&b, "7000"));
    assert_ne!(na, nb, "each its own name");
    let page = unescape(&br.get("/ai").body);
    assert!(page.contains(&na) && page.contains(&nb), "{page}");
    // preferring one prefers that one only; blocking the other blocks it only
    br.act("/ai", "/ai", &[("do", "pin"), ("seller", &na)]);
    br.act("/ai", "/ai", &[("do", "block"), ("seller", &nb)]);
    let f = file();
    assert_eq!((f["pinned"].clone(), f["blocked"].clone()), (json!([na]), json!([nb])));
    // and a name that is not shared stays as it was (a pin made before keeps working)
    let c = publish("Other shop", 5_000);
    let r = br.act("/services", "/services", &[("action", "add"), ("url", &c)]);
    assert!(br.flash_after(&r).contains("on Browse now"));
    br.act("/ai", "/ai", &[("do", "refresh")]);
    assert!(file()["sellers"].as_array().unwrap().iter().any(|e| e["name"] == json!("Other shop")), "{}", file());
}

/// A seller who picks "Directly, through the app": no web address is written, the gateway gets a
/// link section (the app's relays, the private switch) and the listing goes to Nostr anyway.
/// Needs the gateway to read the `link` section (the direct-links transport work).
#[cfg(unix)]
#[test]
fn a_shop_reached_directly_writes_a_link_and_no_web_address() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let gw = tempfile::tempdir().unwrap();
    let dir = gw.path().to_path_buf();
    let media = mock_http(|_| (200, "ok"));
    let bx = start(json!({}), false, |c| {
        c.sell = true;
        c.gw.dir = dir.clone();
        c.gw.node_rest = Some("https://10.21.21.66:8180".into());
        c.nostr_relays = vec!["wss://relay.one.example".into()];
    });
    let mut br = logged_in(&bx);
    let inv = mac(&[("invoices", &["read", "write"])]);
    let info = mac(&[("info", &["read"])]);
    br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &inv), ("info_macaroon", &info)]);
    br.act("/sell", "/sell", &[("action", "advanced"), ("max_sessions", "30"), ("sessions_per_address", "2"), ("max_held_tickets", "15"),
                               ("proxies", ""), ("network", "bip122:0123456789abcdef0123456789abcdef")]);
    let addr = format!("http://{media}");
    // a web service without a page of its own (a direct shop listing its media server's web app:
    // `a_direct_shop_lists_its_media_servers_web_app`)
    br.act("/sell", "/sell", &[("action", "service"), ("kind", "web"), ("address", &addr), ("price", "1"), ("unit", "request")]);
    let r = br.act("/sell", "/sell", &[("action", "shop"), ("name", "Home films"), ("reach", "direct"), ("private", "1"), ("public_url", "https://ignored.example")]);
    let f = br.flash_after(&r);
    assert!(f.contains("restarts"), "{f}");
    let c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    assert!(c.get("public_url").is_none(), "{c}");
    assert_eq!(c["link"], json!({"relays": ["https://iroh.lazarus-xbt.xyz"], "private": true}));
    assert_eq!(c["nostr"]["publish"], true, "a direct shop is found on Nostr");
    assert!(c["listen"].as_str().unwrap().starts_with("127.0.0.1:"), "with the app beside it (no health address), only on loopback");
    // the page keeps the choice; the https address went with "web"
    let page = br.get("/sell").body;
    assert!(page.contains("value=\"direct\" checked") && page.contains("name=\"private\" value=\"1\" checked"), "{page}");
    assert!(page.contains("Your shop key"));
    // back to a web address: the link goes (the gateway neither serves it nor has it vouched for), the address comes back
    let r = br.act("/sell", "/sell", &[("action", "shop"), ("name", "Home films"), ("reach", "web"), ("public_url", "https://films.example")]);
    assert!(br.flash_after(&r).contains("restarts"));
    let c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    assert_eq!(c["public_url"], "https://films.example");
    assert!(c["link"].is_null(), "{c}");
}

/// The order the Sell page leads a seller through: the shop saved first, with nothing to sell, then
/// its first service. With nothing to list, publishing is left out (off), not written off, so the
/// first service puts the shop on Nostr; a shop reached directly is found nowhere else.
#[cfg(unix)]
#[test]
fn a_shop_saved_before_its_first_service_is_published_once_it_has_one() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let gw = tempfile::tempdir().unwrap();
    let dir = gw.path().to_path_buf();
    let media = mock_http(|_| (200, "ok"));
    let bx = start(json!({}), false, |c| {
        c.sell = true;
        c.gw.dir = dir.clone();
        c.gw.node_rest = Some("https://10.21.21.66:8180".into());
        c.nostr_relays = vec!["wss://relay.one.example".into()];
    });
    let mut br = logged_in(&bx);
    let inv = mac(&[("invoices", &["read", "write"])]);
    let info = mac(&[("info", &["read"])]);
    br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &inv), ("info_macaroon", &info)]);
    br.act("/sell", "/sell", &[("action", "advanced"), ("max_sessions", "30"), ("sessions_per_address", "2"), ("max_held_tickets", "15"),
                               ("proxies", ""), ("network", "bip122:0123456789abcdef0123456789abcdef")]);
    let config = || -> Value { serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap() };
    br.act("/sell", "/sell", &[("action", "shop"), ("name", "Home films"), ("reach", "direct")]);
    let c = config();
    assert!(c.get("listing").is_none(), "{c}");
    assert!(c.get("nostr").is_none_or(|n| n.get("publish").is_none()), "nothing to list: publishing left out, not written off: {c}");
    let r = br.act("/sell", "/sell", &[("action", "service"), ("kind", "web"), ("address", &format!("http://{media}")), ("price", "1"), ("unit", "request")]);
    assert!(br.flash_after(&r).contains("Added"));
    assert_eq!(config()["nostr"]["publish"], true, "the first service puts the shop on Nostr");
    // paused, nothing is listed and publishing goes off; resumed, it comes back
    let shop: Value = serde_json::from_str(&std::fs::read_to_string(bx.data.path().join("ui/sell.json")).unwrap()).unwrap();
    let id = shop["offers"][0]["id"].as_str().unwrap().to_string();
    br.act("/sell", "/sell", &[("action", "pause"), ("id", &id)]);
    assert!(config()["nostr"].get("publish").is_none());
    br.act("/sell", "/sell", &[("action", "resume"), ("id", &id)]);
    assert_eq!(config()["nostr"]["publish"], true);
}

/// A shop reached by its key that sells only its VPN exit is still listed and published: buyers'
/// wallets reach a key-named shop only through the transport document its listing carries.
#[cfg(unix)]
#[test]
fn a_direct_shop_that_sells_only_its_vpn_exit_is_listed_and_published() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let gw = tempfile::tempdir().unwrap();
    let dir = gw.path().to_path_buf();
    let vpn = tempfile::tempdir().unwrap();
    let vdir = vpn.path().to_path_buf();
    let bx = start(json!({}), false, |c| {
        c.sell = true;
        c.gw.dir = dir.clone();
        c.gw.node_rest = Some("https://10.21.21.66:8180".into());
        c.nostr_relays = vec!["wss://relay.one.example".into()];
        c.vpn = xbt_wallet_ui::config::VpnSetup { status_dir: vdir.clone(), dir: vdir.clone(), endpoint: Some("192.168.1.20:51820".into()),
                                                   tunnel_upstream: Some("http://127.0.0.1:51880".into()) };
    });
    let mut br = logged_in(&bx);
    let inv = mac(&[("invoices", &["read", "write"])]);
    let info = mac(&[("info", &["read"])]);
    br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &inv), ("info_macaroon", &info)]);
    br.act("/sell", "/sell", &[("action", "advanced"), ("max_sessions", "30"), ("sessions_per_address", "2"), ("max_held_tickets", "15"),
                               ("proxies", ""), ("network", "bip122:0123456789abcdef0123456789abcdef")]);
    br.act("/sell", "/sell", &[("action", "shop"), ("name", "Pi exit"), ("reach", "direct")]);
    let config = || -> Value { serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap() };
    assert!(config().get("listing").is_none(), "nothing to sell yet");
    let r = br.act("/sell-vpn", "/sell-vpn", &[("offer", "on"), ("understood", "on"), ("sat_per_gb", "1000"), ("country", "US"), ("kind", "private"),
                                                ("max_connections", "512"), ("blocked_ports", "25")]);
    // (no gateway runs here to name the shop's key, so the page says the exit waits to be announced)
    assert!(br.flash_after(&r).starts_with("Saved"));
    let c = config();
    let parsed = xbt_gateway::config::Config::from_json(&c).unwrap();
    let l = parsed.listing.expect("the exit alone is listed");
    assert!(l.services.iter().any(|s| s.name == "VPN exit" && s.path == "/vpn/"), "{c}");
    assert_eq!(c["nostr"]["publish"], true, "and the shop goes on Nostr, with its transport: {c}");
    assert!(c["routes"].as_array().unwrap().iter().any(|r| r["path"] == "/vpn/" && r["service"] == "vpn-exit"));
}

/// Files: a folder on this box, shared with no media server. The Sell page writes a route to the
/// folder the app serves, with the files key and GET/HEAD only, priced per GB; the listing names each
/// file with its size; the folder answers only with the key, and serves a range. A buyer's app reads
/// the price per GB.
#[test]
fn a_shared_folder_is_sold_per_gb_with_each_file_listed_and_served_only_to_the_gateway() {
    use std::io::Read;
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let gw = tempfile::tempdir().unwrap();
    let dir = gw.path().to_path_buf();
    let shared = tempfile::tempdir().unwrap();
    std::fs::write(shared.path().join("Sintel.mp4"), vec![7u8; 2_500_000]).unwrap();
    std::fs::create_dir(shared.path().join("Books")).unwrap();
    std::fs::write(shared.path().join("Books/A book.epub"), b"epub").unwrap();
    std::fs::write(shared.path().join(".hidden"), b"no").unwrap();
    let sdir = shared.path().to_path_buf();
    let bx = start(json!({}), false, |c| {
        c.sell = true;
        c.gw.dir = dir.clone();
        c.gw.node_rest = Some("https://10.21.21.66:8180".into());
        c.gw.node_tls_cert = Some("/data/lightning/tls.cert".into());
        c.files.dir = sdir.clone();
    });
    let mut br = logged_in(&bx);
    let inv = mac(&[("invoices", &["read", "write"])]);
    let info = mac(&[("info", &["read"])]);
    br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &inv), ("info_macaroon", &info)]);
    br.act("/sell", "/sell", &[("action", "advanced"), ("max_sessions", "30"), ("sessions_per_address", "2"), ("max_held_tickets", "15"),
                               ("proxies", ""), ("network", "bip122:0123456789abcdef0123456789abcdef")]);
    br.act("/sell", "/sell", &[("action", "shop"), ("name", "Box"), ("public_url", "https://seller.example")]);
    let page = br.get("/sell").body;
    assert!(page.contains("value=\"files\"") && page.contains("Files shares a folder") && page.contains("Jellyfin or Plex"), "{page}");
    // no address to type: the app serves the folder
    let r = br.act("/sell", "/sell", &[("action", "service"), ("kind", "files"), ("address", ""), ("price", "1000"), ("unit", "gb"), ("name", "My files")]);
    assert!(br.flash_after(&r).contains("restarts"), "{}", br.flash_after(&r));
    let c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    let cfg = xbt_gateway::config::Config::from_json(&c).unwrap();
    let route = &cfg.routes[0];
    let files_addr = bx._srv.files_addr.expect("the folder is served");
    assert_eq!(route.upstream.as_deref(), Some(format!("http://{files_addr}").as_str()));
    assert_eq!((route.price.byte_msat, route.price.per_bytes), (1_000_000, 1_000_000_000));
    assert_eq!(route.methods, ["GET", "HEAD"]);
    let (hk, key) = route.upstream_headers[0].clone();
    assert_eq!(hk, xbt_wallet_ui::files::KEY_HEADER);
    let l = cfg.listing.unwrap();
    assert_eq!(l.services[0].kind, "files");
    let items: Vec<(&str, &str, Option<&str>)> = l.services[0].items.iter().map(|i| (i.title.as_str(), i.url.as_str(), i.credit.as_deref())).collect();
    // under a path of its own, even alone, so that a media server added later can have the root
    assert_eq!(route.path, "/my-files/");
    assert_eq!(items, [("Books/A book.epub", "https://seller.example/my-files/Books/A%20book.epub", Some("4 bytes")),
                       ("Sintel.mp4", "https://seller.example/my-files/Sintel.mp4", Some("2.5 MB"))], "each file with its size, no hidden ones");
    let page = br.get("/sell").body;
    assert!(page.contains("2 files in the folder") && page.contains("Update the file list"), "{page}");
    // a new file shows once the list is updated
    std::fs::write(shared.path().join("New.txt"), b"hi").unwrap();
    let r = br.act("/sell", "/sell", &[("action", "files_refresh")]);
    assert!(br.flash_after(&r).contains("file list is updated"));
    let c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    assert_eq!(xbt_gateway::config::Config::from_json(&c).unwrap().listing.unwrap().services[0].items.len(), 3);
    // the folder: nothing without the key, a range with it
    let get = |path: &str, key: Option<&str>, range: Option<&str>| {
        let mut rq = ureq::get(&format!("http://{files_addr}{path}"));
        if let Some(k) = key { rq = rq.set(xbt_wallet_ui::files::KEY_HEADER, k); }
        if let Some(r) = range { rq = rq.set("Range", r); }
        match rq.call() { Ok(r) => r, Err(ureq::Error::Status(_, r)) => r, Err(e) => panic!("{e}") }
    };
    assert_eq!(get("/Sintel.mp4", None, None).status(), 403);
    assert_eq!(get("/Sintel.mp4", Some("wrong"), None).status(), 403);
    assert_eq!(get("/.hidden", Some(&key), None).status(), 404);
    assert_eq!(get("/../etc/passwd", Some(&key), None).status(), 404);
    let r = get("/Sintel.mp4", Some(&key), Some("bytes=100-199"));
    assert_eq!((r.status(), r.header("Content-Range").map(str::to_string), r.header("Content-Type").map(str::to_string)),
               (206, Some("bytes 100-199/2500000".into()), Some("video/mp4".into())));
    let mut body = vec![];
    r.into_reader().read_to_end(&mut body).unwrap();
    assert_eq!(body.len(), 100);
    assert_eq!(get("/", None, None).status(), 204, "the Sell page's reachability check");
    // a buyer reads the price per GB
    assert_eq!(xbt_wallet_ui::services::price_words(&json!({"byte_msat": "1000000", "per_bytes": "1000000000"})), "1000 sat a GB");
}

/// Services added in any order each get a path of their own: a folder, a model and a web app added
/// before the media server leave `/` to it (its web app sees the shop's root), and every route reaches
/// its own service. A service that holds `/` by hand is named when a media server would need it.
#[test]
fn services_added_in_any_order_each_get_their_own_path() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let gw = tempfile::tempdir().unwrap();
    let dir = gw.path().to_path_buf();
    let shared = tempfile::tempdir().unwrap();
    std::fs::write(shared.path().join("film.mkv"), b"frames").unwrap();
    let sdir = shared.path().to_path_buf();
    let media = mock_http(|_| (200, "jellyfin"));
    let web = mock_http(|_| (200, "web"));
    let bx = start(json!({}), false, |c| {
        c.sell = true;
        c.gw.dir = dir.clone();
        c.gw.node_rest = Some("https://10.21.21.66:8180".into());
        c.gw.node_tls_cert = Some("/data/lightning/tls.cert".into());
        c.files.dir = sdir.clone();
    });
    let mut br = logged_in(&bx);
    let inv = mac(&[("invoices", &["read", "write"])]);
    let info = mac(&[("info", &["read"])]);
    br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &inv), ("info_macaroon", &info)]);
    br.act("/sell", "/sell", &[("action", "advanced"), ("max_sessions", "30"), ("sessions_per_address", "2"), ("max_held_tickets", "15"),
                               ("proxies", ""), ("network", "bip122:0123456789abcdef0123456789abcdef")]);
    br.act("/sell", "/sell", &[("action", "shop"), ("name", "Box"), ("public_url", "https://seller.example")]);
    let added = |br: &mut B, form: &[(&str, &str)]| {
        let r = br.act("/sell", "/sell", form);
        let f = br.flash_after(&r);
        assert!(f.contains("restarts"), "{form:?}: {f}");
    };
    // the folder first, then a web app with its own page, then the media server
    added(&mut br, &[("action", "service"), ("kind", "files"), ("address", ""), ("price", "1000"), ("unit", "gb"), ("name", "My files")]);
    let web_addr = format!("http://{web}");
    added(&mut br, &[("action", "service"), ("kind", "web"), ("address", &web_addr), ("price", "1"), ("unit", "request"), ("name", "Notes"), ("app", "1")]);
    let media_addr = format!("http://{media}");
    added(&mut br, &[("action", "service"), ("kind", "media"), ("address", &media_addr), ("price", "1"), ("unit", "mib"), ("app_entry", "/web/")]);
    let c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    let cfg = xbt_gateway::config::Config::from_json(&c).unwrap();
    let mut routes: Vec<(String, String)> = cfg.routes.iter().map(|r| (r.path.clone(), r.upstream.clone().unwrap_or_default())).collect();
    routes.sort();
    let files_up = format!("http://{}", bx._srv.files_addr.expect("the folder is served"));
    assert_eq!(routes, [("/".to_string(), media_addr.clone()), ("/my-files/".to_string(), files_up), ("/notes/".to_string(), web_addr.clone())],
               "each service under a path of its own, the media server at the root");
    let page = br.get("/sell").body;
    assert!(!page.contains("already uses"), "{page}");
    // a second media server: the root is taken, and the page names who has it
    let r = br.act("/sell", "/sell", &[("action", "service"), ("kind", "media"), ("address", &media_addr), ("price", "1"), ("unit", "mib"), ("name", "Plex")]);
    let f = unescape(&r.body);
    assert!(f.contains("Media server already uses /, so Plex cannot have it"), "{f}");
}

/// The folder's address is taken by another program (a clash on 8486): the Sell page says so on the
/// Files service, with the setting that moves it, and does not call it selling because that other
/// program answers.
#[test]
fn a_shared_folder_whose_port_is_taken_says_so_plainly() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let gw = tempfile::tempdir().unwrap();
    let dir = gw.path().to_path_buf();
    let shared = tempfile::tempdir().unwrap();
    std::fs::write(shared.path().join("film.mkv"), b"frames").unwrap();
    let sdir = shared.path().to_path_buf();
    // another program on the folder's port, answering anything
    let other = mock_http(|_| (200, "someone else"));
    let taken = other.to_string();
    let bx = start(json!({}), false, |c| {
        c.sell = true;
        c.gw.dir = dir.clone();
        c.gw.node_rest = Some("https://10.21.21.66:8180".into());
        c.gw.node_tls_cert = Some("/data/lightning/tls.cert".into());
        c.files.dir = sdir.clone();
        c.files.bind = taken.clone();
    });
    assert!(bx._srv.files_addr.is_none(), "the folder cannot be served where another program listens");
    let mut br = logged_in(&bx);
    let inv = mac(&[("invoices", &["read", "write"])]);
    let info = mac(&[("info", &["read"])]);
    br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &inv), ("info_macaroon", &info)]);
    br.act("/sell", "/sell", &[("action", "advanced"), ("max_sessions", "30"), ("sessions_per_address", "2"), ("max_held_tickets", "15"),
                               ("proxies", ""), ("network", "bip122:0123456789abcdef0123456789abcdef")]);
    br.act("/sell", "/sell", &[("action", "shop"), ("name", "Box"), ("public_url", "https://seller.example")]);
    br.act("/sell", "/sell", &[("action", "service"), ("kind", "files"), ("address", ""), ("price", "1000"), ("unit", "gb"), ("name", "My files")]);
    let page = br.get("/sell").body;
    assert!(page.contains("Your shared folder isn&#39;t served") || page.contains("Your shared folder isn't served"), "{page}");
    assert!(page.contains(&format!("serve it at {taken}")) && page.contains("LS_FILES_PORT"), "{page}");
    assert!(page.contains("Selling, with a problem"), "not plain selling while the folder is not served: {page}");
}

/// A direct shop (no web address, reached by its key) selling its media server as a web app, a
/// shared folder, a model and its miners: the Sell page lists each where it opens from the shop's
/// own root, and the gateway lists those at the shop's name once it has named itself by its key.
#[test]
fn a_direct_shop_lists_its_media_servers_web_app() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let gw = tempfile::tempdir().unwrap();
    let dir = gw.path().to_path_buf();
    let shared = tempfile::tempdir().unwrap();
    std::fs::write(shared.path().join("film.mkv"), b"frames").unwrap();
    let sdir = shared.path().to_path_buf();
    let media = mock_http(|_| (200, "ok"));
    let bx = start(json!({}), false, |c| {
        c.sell = true;
        c.gw.dir = dir.clone();
        c.gw.node_rest = Some("https://10.21.21.66:8180".into());
        c.gw.node_tls_cert = Some("/data/lightning/tls.cert".into());
        c.nostr_relays = vec!["wss://relay.one.example".into()];
        c.files.dir = sdir.clone();
        c.hash.slices = Some("http://127.0.0.1:9".into());
        c.hash.settings = dir.join("hashrate-settings.json");
    });
    let mut br = logged_in(&bx);
    let inv = mac(&[("invoices", &["read", "write"])]);
    let info = mac(&[("info", &["read"])]);
    br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &inv), ("info_macaroon", &info)]);
    br.act("/sell", "/sell", &[("action", "advanced"), ("max_sessions", "30"), ("sessions_per_address", "2"), ("max_held_tickets", "15"),
                               ("proxies", ""), ("network", "bip122:0123456789abcdef0123456789abcdef")]);
    let addr = format!("http://{media}");
    br.act("/sell", "/sell", &[("action", "service"), ("kind", "media"), ("address", &addr), ("price", "1"), ("unit", "mib"), ("app_entry", "/web/")]);
    br.act("/sell", "/sell", &[("action", "service"), ("kind", "files"), ("address", ""), ("price", "1000"), ("unit", "gb"), ("name", "My files")]);
    br.act("/sell", "/sell", &[("action", "service"), ("kind", "ai"), ("address", "http://127.0.0.1:9"), ("price", "10"), ("unit", "tokens"),
                               ("name", "Model")]);
    br.act("/sell-hashrate", "/sell-hashrate", &[("action", "save"), ("fallback", "192.168.1.20:23334"), ("price", "40"), ("enabled", "1")]);
    let r = br.act("/sell", "/sell", &[("action", "shop"), ("name", "Home films"), ("reach", "direct"), ("private", "1")]);
    let f = br.flash_after(&r);
    assert!(f.contains("restarts"), "{f}");
    // the gateway takes it, and lists every address at the shop's name once it is known
    let c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
    let mut cfg = xbt_gateway::config::Config::from_json(&c).unwrap();
    let origin = xbt402::shop::origin_for(&[9; 32]);
    cfg.name_shop(origin.clone());
    let l = cfg.listing.unwrap();
    let kinds: Vec<&str> = l.services.iter().map(|s| s.kind.as_str()).collect();
    for k in ["app", "files", "hashrate"] {
        assert!(kinds.contains(&k), "{k} in {kinds:?}");
    }
    assert!(kinds.iter().any(|k| *k == "ai" || *k == "api"), "the model in {kinds:?}");
    let urls: Vec<&str> = l.services.iter().flat_map(|s| s.items.iter().map(|i| i.url.as_str())).collect();
    assert!(urls.iter().any(|u| *u == format!("{origin}/web/")), "the media server opens at the shop: {urls:?}");
    assert!(urls.iter().any(|u| u.starts_with(&origin) && u.ends_with("/film.mkv")), "the shared file: {urls:?}");
    assert!(urls.iter().all(|u| u.starts_with(&origin)), "nothing left unnamed: {urls:?}");
}

#[test]
fn the_built_in_relay_is_switched_on_with_a_domain_and_shows_its_status() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let dirs = tempfile::tempdir().unwrap();
    let (cfg_dir, status) = (dirs.path().join("relay"), dirs.path().join("status.json"));
    std::fs::create_dir_all(&cfg_dir).unwrap();
    let (cd, sp) = (cfg_dir.clone(), status.clone());
    let bx = start(json!({}), false, move |c| {
        c.stream_relay = "https://127.0.0.1:9/".into();
        c.relay_dir = Some(cd);
        c.relay_status = Some(sp);
        c.relay_start_hint = Some("run: docker compose --profile relay up -d".into());
    });
    let mut br = logged_in(&bx);
    let page = br.get("/relays").body;
    assert!(page.contains("Run a relay for the Stream network") && page.contains("Switch the relay on"));
    // a home-network name and a missing e-mail are refused before anything is written
    let r = br.act("/relays", "/relay-run", &[("action", "on"), ("domain", "box.local"), ("contact", "ops@example.com")]);
    assert!(br.flash_after(&r).contains("public domain name"));
    let r = br.act("/relays", "/relay-run", &[("action", "on"), ("domain", "relay.example.com"), ("contact", "nope")]);
    assert!(br.flash_after(&r).contains("e-mail"));
    assert!(!cfg_dir.join("relay.json").exists());
    // switched on: the settings the relay service reads
    let r = br.act("/relays", "/relay-run", &[("action", "on"), ("domain", "Relay.Example.com"), ("contact", "ops@example.com"), ("udp", "1")]);
    assert!(br.flash_after(&r).contains("checks the domain"));
    let v: Value = serde_json::from_str(&std::fs::read_to_string(cfg_dir.join("relay.json")).unwrap()).unwrap();
    assert_eq!((v["enabled"].clone(), v["domain"].clone(), v["udp"].clone(), v["port_forwarded"].clone()),
               (json!(true), json!("relay.example.com"), json!(true), json!(false)));
    // no status yet: the service isn't running, and the page says how to start it
    assert!(br.get("/relays").body.contains("docker compose --profile relay up -d"));
    // a fresh status from the service: its checks, then traffic once running
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    std::fs::write(&status, json!({"state": "not_ready", "message": "Not ready: nothing was asked of Let's Encrypt.", "written": now,
        "preflight": {"ready": false, "checks": [{"id": "dns", "level": "fail", "words": "relay.example.com doesn't resolve yet."}]}}).to_string()).unwrap();
    let page = unescape(&br.get("/relays").body);
    assert!(page.contains("doesn't resolve yet"), "{page}");
    assert!(page.contains("needs attention"));
    std::fs::write(&status, json!({"state": "running", "message": "Running.", "written": now, "bytes_sent": 2_500_000_000u64,
        "bytes_recv": 1_000_000_000u64, "clients": 3}).to_string()).unwrap();
    let page = br.get("/relays").body;
    assert!(page.contains("2.50 GB out") && page.contains("3 apps connected now") && page.contains("UDP 7842"));
    // the announce form is filled with the relay's address
    assert!(page.contains("value=\"https://relay.example.com\""));
    // try again bumps the attempt; off switches it off
    let r = br.act("/relays", "/relay-run", &[("action", "retry")]);
    br.flash_after(&r);
    let v: Value = serde_json::from_str(&std::fs::read_to_string(cfg_dir.join("relay.json")).unwrap()).unwrap();
    assert_eq!(v["attempt"], json!(1));
    let r = br.act("/relays", "/relay-run", &[("action", "off")]);
    assert!(br.flash_after(&r).contains("switching off"));
    let v: Value = serde_json::from_str(&std::fs::read_to_string(cfg_dir.join("relay.json")).unwrap()).unwrap();
    assert_eq!(v["enabled"], json!(false));
}

#[test]
fn a_platform_without_the_relay_says_why_and_refuses_the_switch() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({}), false, |c| {
        c.stream_relay = "https://127.0.0.1:9/".into();
        c.relay_unavailable = Some("Umbrel apps can't take this box's port 443.".into());
    });
    let mut br = logged_in(&bx);
    let page = unescape(&br.get("/relays").body);
    assert!(page.contains("can't take this box"));
    assert!(!page.contains("Switch the relay on"));
    let r = br.act("/relays", "/relay-run", &[("action", "on"), ("domain", "relay.example.com"), ("contact", "ops@example.com")]);
    assert!(br.flash_after(&r).contains("no built-in relay"));
}

#[test]
fn the_ai_page_makes_a_key_shown_once_and_keeps_its_hash_and_writes_pins_for_the_endpoint() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let services = dir.path().join("services.json");
    std::fs::write(&services, r#"[{"name": "Lab model", "kind": "ai", "seller": "https://ai.invalid", "price_text": "10 sat per 1,000 tokens",
        "items": [], "address": "https://ai.invalid/ai"}]"#).unwrap();
    let ai = dir.path().join("ai");
    let bx = start(json!({}), false, |c| {
        c.services_file = Some(services.clone());
        c.ai = xbt_wallet_ui::config::AiSetup { endpoint: Some("http://box.local:33540/v1".into()), sellers: ai.join("sellers.json"),
                                                credentials: ai.join("credentials.json"), state: ai.join("state.json") };
    });
    let mut br = logged_in(&bx);
    let page = br.get("/ai");
    assert_eq!(page.status, 200);
    assert!(page.body.contains("http://box.local:33540/v1") && page.body.contains("Lab model") && page.body.contains("not allowed"), "{}", page.body);
    // the first visit wrote the sellers file (the seller's listing could not be read, so it is not offered yet)
    let sellers: Value = serde_json::from_slice(&std::fs::read(ai.join("sellers.json")).unwrap()).unwrap();
    assert_eq!(sellers["sellers"], json!([]));
    // a key: shown once, kept as its hash
    let made = br.act("/ai", "/ai", &[("do", "make"), ("name", "Open WebUI"), ("limit_sats", "500")]);
    assert_eq!(made.status, 200, "{}", made.body);
    assert_eq!(made.headers.get("cache-control").map(String::as_str), Some("no-store"));
    let at = made.body.find("sk-stream-").expect("the key is shown");
    let key: String = made.body[at..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
    assert_eq!(key.len(), "sk-stream-".len() + 22);
    let store = std::fs::read_to_string(ai.join("credentials.json")).unwrap();
    assert!(!store.contains(&key) && store.contains("Open WebUI"));
    assert!(!br.get("/ai").body.contains(&key), "never shown again");
    // the store's own check finds it, as the endpoint's does
    let s = lightning_stream::credentials::Store::open(&ai.join("credentials.json")).unwrap();
    let id = s.check(lightning_stream::credentials::Kind::AiKey, &key).unwrap().id.clone();
    // a pin and a block, for the endpoint
    br.act("/ai", "/ai", &[("do", "pin"), ("seller", "Lab model")]);
    let sellers: Value = serde_json::from_slice(&std::fs::read(ai.join("sellers.json")).unwrap()).unwrap();
    assert_eq!(sellers["pinned"], json!(["Lab model"]));
    br.act("/ai", "/ai", &[("do", "block"), ("seller", "Lab model")]);
    let sellers: Value = serde_json::from_slice(&std::fs::read(ai.join("sellers.json")).unwrap()).unwrap();
    assert_eq!((sellers["pinned"].clone(), sellers["blocked"].clone()), (json!([]), json!(["Lab model"])), "a blocked seller is not preferred");
    // a new limit, then revoke
    let r = br.act("/ai", "/ai", &[("do", "limit"), ("id", &id), ("limit_sats", "900")]);
    assert!(br.flash_after(&r).contains("900"));
    let r = br.act("/ai", "/ai", &[("do", "revoke"), ("id", &id)]);
    assert!(br.flash_after(&r).contains("Revoked"));
    let s = lightning_stream::credentials::Store::open(&ai.join("credentials.json")).unwrap();
    assert!(s.check(lightning_stream::credentials::Kind::AiKey, &key).is_err());
    // without an endpoint the page says so, and still lists the sellers
    let bx2 = start(json!({}), false, |c| c.services_file = Some(services.clone()));
    let mut br2 = logged_in(&bx2);
    assert!(br2.get("/ai").body.contains("does not serve an AI address yet"));
}

/// A Files item listed at `1.0 KB`, bought through the relay: the connector is told the most this
/// file can cost (its listed size at the listed price, with 2% slack); a seller that says it sends
/// more than the listing shows is refused before any of the body is read; one that sends more
/// without saying so is cut at the listed size.
#[test]
fn a_file_is_paid_no_further_than_its_listed_size() {
    use std::io::{Read, Write};
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    const OK: &str = "https://files.example/f/ok.bin";
    const BIG: &str = "https://files.example/f/big.bin";
    const QUIET: &str = "https://files.example/f/quiet.bin";
    const TICKET: &str = "https://files.example/f/ticket.bin";
    const CAPPED: &str = "https://files.example/f/capped.bin";
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let connector = format!("http://{}", l.local_addr().unwrap());
    let max_sats: Seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = max_sats.clone();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let mut head = [0u8; 8192];
            let n = s.read(&mut head).unwrap_or(0);
            let asked = String::from_utf8_lossy(&head[..n]).to_string();
            let path = asked.split(' ').nth(1).unwrap_or("").to_string();
            let cap = asked.lines().find_map(|l| l.strip_prefix("X-Max-Sats: ").or_else(|| l.strip_prefix("x-max-sats: "))).map(str::to_string);
            log.lock().unwrap().push((path.clone(), cap.clone()));
            let body = vec![7u8; 5_000];
            if path == format!("/s/{OK}") {
                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n");
                let _ = s.write_all(&body[..1000]);
            } else if path == format!("/s/{BIG}") {
                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 5000\r\nConnection: close\r\n\r\n");
                let _ = s.write_all(&body);
            } else if path == format!("/s/{TICKET}") && cap.as_deref() != Some("700") {
                // a shop whose smallest ticket books 700 sat: the wallet refuses a smaller limit, paying nothing
                let no = r#"{"error": "the smallest prepaid ticket this seller sells is 690 sat (up to 10 sat more in routing fees), over this call's limit of 559 sat: nothing was paid; call again with max_sats of at least 700", "rule": "max_sats"}"#;
                let _ = write!(s, "HTTP/1.1 402 Payment Required\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{no}", no.len());
            } else if path == format!("/s/{TICKET}") {
                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n");
                let _ = s.write_all(&body[..1000]);
            } else if path == format!("/s/{CAPPED}") {
                let no = r#"{"error": "over the <per-payment> cap of your rules", "rule": "max_payment_sats"}"#;
                let _ = write!(s, "HTTP/1.1 402 Payment Required\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{no}", no.len());
            } else if path == format!("/s/{QUIET}") {
                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n");
                let _ = s.write_all(&body);
            } else {
                let _ = write!(s, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("services.json");
    std::fs::write(&path, format!(r#"[
        {{"name": "Files", "kind": "files", "seller": "https://files.example", "price_text": "1 sat a KB",
         "prices": {{"request_msat": 1000, "byte_msat": 1, "per_bytes": 1}},
         "items": [{{"title": "ok", "year": 2020, "url": "{OK}", "credit": "1.0 KB"}},
                   {{"title": "big", "year": 2020, "url": "{BIG}", "credit": "1.0 KB"}},
                   {{"title": "quiet", "year": 2020, "url": "{QUIET}", "credit": "1.0 KB"}},
                   {{"title": "ticket", "year": 2020, "url": "{TICKET}", "credit": "1.0 KB"}},
                   {{"title": "capped", "year": 2020, "url": "{CAPPED}", "credit": "1.0 KB"}}]}}
    ]"#)).unwrap();
    let services = path.clone();
    let b = start(json!({}), false, move |c| {
        c.connector = connector;
        c.services_file = Some(services);
    });
    let mut br = logged_in(&b);
    let st = xbt_wallet_ui::app::stream_token(&field(&br.get("/browse").body, "csrf"));
    let id = xbt_wallet_ui::services::load(&path).unwrap()[0].id();
    let get = |item: &str| {
        let resp = match ureq::AgentBuilder::new().redirects(0).build().get(&format!("{}/s/~{st}.{id}/{item}", b.base)).set("Cookie", &br.cookie).call() {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => panic!("{item}: {e}"),
        };
        let status = resp.status();
        let mut body = vec![];
        let clean = resp.into_reader().read_to_end(&mut body).is_ok();
        (status, body, clean)
    };
    // 1.0 KB stands for at most 1,050 bytes: 1,000 msat a request + 1,050 msat, +2%, is 3 sats, +1. Under the
    // smallest ticket a seller sells with its fees (546 + 13 sat): the call may buy that one ticket, and the rest stays as credit
    let (status, body, clean) = get(OK);
    assert_eq!((status, body.len(), clean), (200, 1000, true));
    assert_eq!(max_sats.lock().unwrap().last().unwrap().1.as_deref(), Some("559"), "the call's cap is one smallest ticket, over the listed size's price");
    // a shop whose smallest ticket is larger: the wallet's refusal names the limit, and the call is made once more with it
    let (status, body, _) = get(TICKET);
    assert_eq!((status, body.len()), (200, 1000), "{}", String::from_utf8_lossy(&body));
    let caps: Vec<_> = max_sats.lock().unwrap().iter().filter(|(p, _)| p.ends_with("ticket.bin")).map(|(_, c)| c.clone().unwrap_or_default()).collect();
    assert_eq!(caps, ["559", "700"]);
    // any other refusal is a page in words, not the connector's JSON
    let (status, body, _) = get(CAPPED);
    let page = String::from_utf8_lossy(&body);
    assert_eq!(status, 402);
    assert!(page.starts_with("<!doctype html>") && page.contains("over the &lt;per-payment&gt; cap") && !page.contains("\"rule\""), "{page}");
    let (status, body, _) = get(BIG);
    assert_eq!(status, 502, "a seller saying it sends 5,000 bytes of a 1.0 KB file is refused");
    assert!(String::from_utf8_lossy(&body).contains("more than the size its listing shows"));
    let (status, body, clean) = get(QUIET);
    assert_eq!(status, 200);
    assert_eq!((body.len(), clean), (1050, false), "one that sends more without saying so is cut at the listed size, and its reader sees a cut");
}

/// A player's seek through the wallet's relay: the seller's copy's validators come back, and the player's
/// `If-Range` goes on with its range. A connector that says the copy changed (412) is answered as it said.
#[test]
fn the_relay_passes_if_range_and_the_copys_validators() {
    use std::io::{Read, Write};
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let film: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let connector = format!("http://{}", l.local_addr().unwrap());
    let seen = Arc::new(std::sync::Mutex::new(Vec::<Option<String>>::new()));
    let log = seen.clone();
    let body = film.clone();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let mut head = [0u8; 8192];
            let n = s.read(&mut head).unwrap_or(0);
            let asked = String::from_utf8_lossy(&head[..n]).to_string();
            let if_range = asked.lines().find_map(|l| l.strip_prefix("If-Range: ").or_else(|| l.strip_prefix("if-range: "))).map(str::to_string);
            log.lock().unwrap().push(if_range.clone());
            if if_range.as_deref().is_some_and(|v| v != "\"v1\"") {
                let msg = r#"{"error":"ticket_range_ignored: the copy changed"}"#;
                let _ = write!(s, "HTTP/1.1 412 Precondition Failed\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{msg}", msg.len());
                continue;
            }
            let _ = write!(s, "HTTP/1.1 206 Partial Content\r\nContent-Type: video/mp4\r\nAccept-Ranges: bytes\r\nETag: \"v1\"\r\nContent-Range: bytes 1000-{}/{}\r\n\
                               Content-Length: {}\r\nConnection: close\r\n\r\n", body.len() - 1, body.len(), body.len() - 1000);
            let _ = s.write_all(&body[1000..]);
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("services.json");
    std::fs::write(&path, format!(r#"[{{"name": "Films", "kind": "video", "seller": "https://stream.lazarus-xbt.xyz", "price_text": "20 sat a MiB",
         "items": [{{"title": "Big Buck Bunny", "year": 2008, "url": "{FILM}", "credit": "CC BY 3.0"}}]}}]"#)).unwrap();
    let services = path.clone();
    let b = start(json!({}), false, move |c| {
        c.connector = connector;
        c.services_file = Some(services);
    });
    let mut br = logged_in(&b);
    let st = xbt_wallet_ui::app::stream_token(&field(&br.get("/browse").body, "csrf"));
    let url = format!("{}/s/~{st}/{FILM}", b.base);
    let call = |if_range: &str| {
        let rq = ureq::AgentBuilder::new().redirects(0).build().get(&url).set("Cookie", &br.cookie).set("Range", "bytes=1000-").set("If-Range", if_range);
        match rq.call() {
            Ok(r) => (r.status(), r.header("ETag").map(str::to_string)),
            Err(ureq::Error::Status(c, r)) => (c, r.header("ETag").map(str::to_string)),
            Err(e) => panic!("{e}"),
        }
    };
    assert_eq!(call("\"v1\""), (206, Some("\"v1\"".to_string())));
    assert_eq!(call("\"v0\"").0, 412);
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen, vec![Some("\"v1\"".to_string()), Some("\"v0\"".to_string())]);
}

/// The hashmaker's price follows the chain: by default what a piece of work is worth when mined, read through the
/// signer from the XBT node, written for the hasher and into the shop's route alike. A new price waits for the
/// rentals going on to end, no live price is no new rental, and a typed price is kept.
#[cfg(unix)]
#[test]
fn the_hashmakers_price_follows_the_difficulty_and_waits_for_the_rentals_going_on() {
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::SeqCst};
    use xbt_wallet_ui::app::hashrate::Repriced;
    static RENTALS: AtomicUsize = AtomicUsize::new(0);
    static PAUSED: AtomicBool = AtomicBool::new(false);
    // the hasher's terms: what its settings file says, as it reads it, or (`LAGS`) the price it hasn't moved from yet
    static SETTINGS_AT: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);
    static LAGS: AtomicBool = AtomicBool::new(false);
    static STALE_MSAT: AtomicU64 = AtomicU64::new(0);
    fn hasher_terms() -> Value {
        if LAGS.load(SeqCst) {
            return json!({"priceMsat": STALE_MSAT.load(SeqCst)});
        }
        let at = SETTINGS_AT.lock().unwrap().clone();
        let s: Value = at.and_then(|p| std::fs::read_to_string(p).ok()).and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
        json!({"priceMsat": s["priceSat"].as_u64().unwrap_or(0) * 1000})
    }
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (hasher, _hseen) = control_standin(|m, p| match (m, p) {
        ("GET", "/status") => json!({
            "open": true, "settings": {}, "minersAddress": "umbrel.local:23340", "linkLan": "umbrel.local:23341", "terms": hasher_terms(),
            "miners": [{"name": "s11", "connected": true, "hashrateHs": 4.1e12, "rentedTo": null, "earnedMsat": 0}],
            "rentals": (0..RENTALS.load(SeqCst)).map(|i| json!({"rental": format!("r{i}"), "buyer": "02aa", "miners": ["s11"], "paid": 1, "earnedMsat": 404000}))
                .collect::<Vec<_>>(),
            "paused": if PAUSED.load(SeqCst) { json!("a new price waits for the rentals going on to end") } else { Value::Null }}),
        _ => json!({"error": "no"}),
    });
    let gw = tempfile::tempdir().unwrap();
    let dir = gw.path().to_path_buf();
    let htok = dir.join("hasher-token");
    std::fs::write(&htok, "h".repeat(64)).unwrap();
    let settings = dir.join("hashrate-settings.json");
    *SETTINGS_AT.lock().unwrap() = Some(settings.clone());
    let bx = start(json!({}), false, |c| {
        c.sell = true;
        c.gw.dir = dir.clone();
        c.gw.node_rest = Some("https://10.21.21.66:8180".into());
        c.gw.node_tls_cert = Some("/data/lightning/tls.cert".into());
        c.hash.hasher = Some(hasher.clone());
        c.hash.hasher_token = Some(htok.clone());
        c.hash.slices = Some("http://127.0.0.1:9".into());
        c.hash.settings = settings.clone();
    });
    let mut br = logged_in(&bx);
    // a shop that sells: its node, its address, its chain
    let (inv, info) = (mac(&[("invoices", &["read", "write"])]), mac(&[("info", &["read"])]));
    br.act("/sell", "/sell", &[("action", "connect"), ("invoices_macaroon", &inv), ("info_macaroon", &info)]);
    br.act("/sell", "/sell", &[("action", "shop"), ("name", "Mike's box"), ("public_url", "https://seller.example/")]);
    let r = br.act("/sell", "/sell", &[("action", "advanced"), ("max_sessions", "30"), ("sessions_per_address", "2"), ("max_held_tickets", "15"),
                                       ("proxies", ""), ("network", "bip122:0123456789abcdef0123456789abcdef")]);
    assert!(br.flash_after(&r).contains("Advanced settings saved"));
    let read = || serde_json::from_str::<Value>(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    let route = || {
        let c: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("config.json")).unwrap()).unwrap();
        c["routes"].as_array().unwrap().iter().find(|r| r["path"] == "/hashrate/").map(|r| r["price"]["request_msat"].clone())
    };
    let terms = |s: &Value| (s["priceSat"].as_u64(), s["sliceWork"].as_str().map(str::to_string), s["startSlices"].as_u64());

    // the first view, nothing saved: the market price, for a piece sized to the miner here (4.1 TH/s: 2^45)
    let p = br.get("/sell-hashrate");
    assert!(p.body.contains("name=\"price_mode\" value=\"market\" checked"), "following the market is the default");
    assert!(p.body.contains("It costs <strong>404 sats</strong>") && p.body.contains("worth about 404 sats"), "{}", p.body);
    assert!(p.body.contains("start fee of <strong>404 sats</strong> (1 piece of work"), "{}", p.body);
    assert!(!p.body.contains("Below mining value"));
    assert!(p.body.contains("name=\"price\" value=\"\""), "no price typed, and the old 40 sat default is gone");

    // saved at the market: the hasher's terms and the shop's route say the same price
    let r = br.act("/sell-hashrate", "/sell-hashrate", &[("action", "save"), ("fallback", "192.168.1.20:23334"), ("price_mode", "market"),
                                                          ("price_pct", "100"), ("price", ""), ("enabled", "1")]);
    assert!(br.flash_after(&r).starts_with("Saved. Renting is on."));
    let s = read();
    assert_eq!(terms(&s), (Some(404), Some((1u128 << 45).to_string()), Some(1)), "{s}");
    assert_eq!((s["priceMode"].as_str(), s["holdNew"].as_bool(), s["priceSeenMs"].is_u64()), (Some("market"), Some(false), true), "{s}");
    assert_eq!(route(), Some(json!(404_000)));
    assert_eq!(bx._app.hash_reprice(false), Repriced::Same);

    // the difficulty rises: within ten minutes of the last new price, the price in force stays (each restarts the shop)
    bx.rig.chain.st.lock().unwrap().difficulty = Some(7.0e9);
    assert_eq!(bx._app.hash_reprice(false), Repriced::Same);
    assert_eq!((terms(&read()).0, read().get("pending"), route()), (Some(404), None, Some(json!(404_000))));
    let aged = |s: &std::path::Path| {
        let mut v: Value = serde_json::from_str(&std::fs::read_to_string(s).unwrap()).unwrap();
        v["appliedMs"] = json!(v["appliedMs"].as_u64().unwrap() - 600_000);
        std::fs::write(s, v.to_string()).unwrap();
    };
    aged(&settings);
    // past that, while a rental goes on: the new price waits, no new rental starts, the route keeps its price
    RENTALS.store(1, SeqCst);
    assert_eq!(bx._app.hash_reprice(false), Repriced::Held(1));
    let s = read();
    assert_eq!(terms(&s).0, Some(404), "the rental going on pays what it was made with");
    assert_eq!((s["holdNew"].as_bool(), s["pending"]["priceSat"].as_u64()), (Some(true), Some(366)), "{s}");
    assert_eq!(route(), Some(json!(404_000)));
    // still going on: still waiting, whatever the hasher says
    PAUSED.store(true, SeqCst);
    assert_eq!(bx._app.hash_reprice(false), Repriced::Held(1));
    // it ends: the new price is in force, in the terms and the route alike
    RENTALS.store(0, SeqCst);
    assert_eq!(bx._app.hash_reprice(false), Repriced::Applied);
    let s = read();
    assert_eq!(terms(&s).0, Some(366));
    assert!(s.get("pending").is_none(), "{s}");
    assert_eq!(s["holdNew"], false, "nothing held with no rental going on: {s}");
    assert_eq!(route(), Some(json!(366_000)));
    PAUSED.store(false, SeqCst);
    assert_eq!(bx._app.hash_reprice(false), Repriced::Same);

    // the node stops answering: no live price, and nothing is made up; the price in force is not confirmed again
    let seen_at = read()["priceSeenMs"].clone();
    bx.rig.chain.st.lock().unwrap().down = true;
    match bx._app.hash_reprice(false) {
        Repriced::NoPrice(why) => assert!(why.contains("does not answer"), "{why}"),
        o => panic!("{o:?}"),
    }
    assert_eq!((terms(&read()).0, read()["priceSeenMs"].clone()), (Some(366), seen_at));
    let p = br.get("/sell-hashrate");
    assert!(p.body.contains("No live price") && p.body.contains("no new rental starts until it can"), "{}", p.body);
    // a pruned node, whose getblockstats fails: the block reward is the chain's schedule at the tip (regtest's
    // halves every 150 blocks: 3.125 at 700), and the price is the one a full node gives
    let height = {
        let mut c = bx.rig.chain.st.lock().unwrap();
        c.down = false;
        c.subsidy = Some(None);
        std::mem::replace(&mut c.height, 700)
    };
    assert_eq!(bx._app.hash_reprice(false), Repriced::Same);
    assert_eq!((terms(&read()).0, route()), (Some(366), Some(json!(366_000))));
    let p = br.get("/sell-hashrate");
    assert!(!p.body.contains("No live price") && p.body.contains("366 sats"), "{}", p.body);
    // a node that can't say the block reward is no price either: no getblockstats, and a height whose schedule gives none
    bx.rig.chain.st.lock().unwrap().height = height;
    assert!(matches!(bx._app.hash_reprice(false), Repriced::NoPrice(w) if w.contains("block reward")));
    bx.rig.chain.st.lock().unwrap().subsidy = None;

    // a fixed price is kept, without the node, and is warned below mining value
    let r = br.act("/sell-hashrate", "/sell-hashrate", &[("action", "save"), ("fallback", "192.168.1.20:23334"), ("price_mode", "fixed"),
                                                          ("price_pct", "100"), ("price", "100"), ("enabled", "1")]);
    assert!(br.flash_after(&r).starts_with("Saved. Renting is on."));
    let s = read();
    assert_eq!((terms(&s).0, s["priceMode"].as_str(), s.get("priceSeenMs")), (Some(100), Some("fixed"), None), "{s}");
    assert_eq!(route(), Some(json!(100_000)));
    let p = br.get("/sell-hashrate");
    assert!(p.body.contains("Below mining value") && p.body.contains("about 366 sats a piece"), "{}", p.body);
    bx.rig.chain.st.lock().unwrap().down = true;
    assert_eq!(bx._app.hash_reprice(false), Repriced::Same);
    assert_eq!(terms(&read()).0, Some(100));
    bx.rig.chain.st.lock().unwrap().down = false;
    // at or above it: no warning
    br.act("/sell-hashrate", "/sell-hashrate", &[("action", "save"), ("fallback", "192.168.1.20:23334"), ("price_mode", "fixed"), ("price", "400"), ("enabled", "1")]);
    assert!(!br.get("/sell-hashrate").body.contains("Below mining value"));
    assert_eq!(route(), Some(json!(400_000)));

    // a renter's hello racing a new price: the hasher hasn't read the new terms yet when the price is saved, and takes a
    // renter at the old ones. The shop keeps charging the old price till the hasher shows the new terms with no rental
    // going on, so that renter pays the price it was taken at, and no renter is taken at the new terms meanwhile
    // (the hasher takes none till its shop charges its terms)
    STALE_MSAT.store(400_000, SeqCst);
    LAGS.store(true, SeqCst);
    br.act("/sell-hashrate", "/sell-hashrate", &[("action", "save"), ("fallback", "192.168.1.20:23334"), ("price_mode", "fixed"), ("price", "300"), ("enabled", "1")]);
    let s = read();
    assert_eq!((terms(&s).0, s["routePriceSat"].as_u64(), route()), (Some(300), Some(400), Some(json!(400_000))), "{s}");
    RENTALS.store(1, SeqCst);
    LAGS.store(false, SeqCst);
    assert_eq!(bx._app.hash_reprice(false), Repriced::Same);
    assert_eq!(route(), Some(json!(400_000)), "the renter taken at the old terms is still paying them");
    RENTALS.store(0, SeqCst);
    assert_eq!(bx._app.hash_reprice(false), Repriced::Same);
    assert_eq!((read()["routePriceSat"].as_u64(), route()), (Some(300), Some(json!(300_000))), "its rental ended: the shop charges the new price");
}

/// A renter whose DATUM Gateway doesn't mask its jobs (a stock gateway: nothing to open them, so they can't be checked) is
/// told plainly before any click, every Rent is off, and a rent sent anyway is refused with nothing paid. One whose
/// gateway does mask can rent.
#[test]
fn renting_waits_for_a_gateway_that_masks_its_jobs() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    fn offers() -> Value {
        json!({"offers": [{"name": "Big miners", "linkKey": "02bb", "priceMsat": 40_000, "sliceWork": (1u128 << 47).to_string(), "proves": true,
                           "miners": 1, "freeMiners": 1, "freeHs": "4000000000000", "payUrl": format!("{PROVIDER}/hashrate"),
                           "payNode": format!("03{}", "c".repeat(64))}]})
    }
    // the hashmaker is on the spending rules, with its node, so the gateway is the only thing Rent waits for
    let rules = json!({"counterparties": {PROVIDER: {"ln_node": format!("03{}", "c".repeat(64))}}});
    for masked in [false, true] {
        let (renter, rseen) = if masked {
            control_standin(|m, p| match (m, p) {
                ("GET", "/status") => json!({"datum": {"addr": "datum-gateway:23334", "reachable": true, "found": []}, "rentals": [],
                                             "blinding": {"state": "blinded", "why": "solo", "words": "Blinded: a hashmaker can't tell which shares win."}}),
                ("GET", "/offers") => offers(),
                ("POST", "/rent") => json!({"ok": true, "rental": "r1"}),
                _ => json!({"error": "no"}),
            })
        } else {
            control_standin(|m, p| match (m, p) {
                ("GET", "/status") => json!({"datum": {"addr": "datum-gateway:23334", "reachable": true, "found": []}, "rentals": [],
                                             "blinding": {"state": "can't be checked", "why": "the gateway's API: connection refused", "words": "This can't be checked."}}),
                ("GET", "/offers") => offers(),
                ("POST", "/rent") => json!({"ok": true, "rental": "r1"}),
                _ => json!({"error": "no"}),
            })
        };
        let dir = tempfile::tempdir().unwrap();
        let rtok = dir.path().join("renter-token");
        std::fs::write(&rtok, "r".repeat(64)).unwrap();
        let bx = start(rules.clone(), false, |c| {
            c.hash.renter = Some(renter.clone());
            c.hash.renter_token = Some(rtok.clone());
        });
        let mut br = logged_in(&bx);
        let p = br.get("/hashrate");
        let card = &p.body[p.body.find("<h3>Big miners</h3>").unwrap()..];
        let card = &card[..card.find("</section>").unwrap()];
        if masked {
            assert!(p.body.contains("Ready to rent") && !p.body.contains("masking its jobs"), "{}", p.body);
            assert!(card.contains("<button>Rent</button>"), "{card}");
        } else {
            assert!(p.body.contains("Your gateway isn&#39;t masking its jobs") || p.body.contains("Your gateway isn't masking its jobs"), "{}", p.body);
            assert!(p.body.contains("the gateway that comes with this app is running") && p.body.contains("nothing is paid") && !p.body.contains("coming soon"), "{}", p.body);
            assert!(card.contains("<button disabled>Rent</button>"), "{card}");
            assert!(!p.body.contains("can't be checked") && !p.body.contains("refused"), "no scary words: {}", p.body);
            let r = br.act("/hashrate", "/hashrate", &[("action", "rent"), ("key", "02bb"), ("budget", "1000"), ("minutes", "60"), ("miners", "1")]);
            assert!(br.flash_after(&r).contains("Nothing was paid"));
            assert!(!rseen.lock().unwrap().iter().any(|(m, p, _, _)| m == "POST" && p == "/rent"), "no rent reached the renter's service");
        }
    }
}

/// The renter's offer card says the start fee, in sats and seconds, and a trial and a budget include it.
#[test]
fn an_offer_shows_its_start_fee() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (renter, _rseen) = control_standin(|m, p| match (m, p) {
        ("GET", "/status") => json!({"datum": {"addr": "datum-gateway:23334", "reachable": true, "found": []}, "rentals": [],
                                     "blinding": {"state": "blinded", "why": "solo", "words": "Blinded."}}),
        ("GET", "/offers") => json!({"offers": [
            {"name": "Big miners", "linkKey": "02bb", "priceMsat": 3_235_000, "sliceWork": (1u128 << 48).to_string(), "startSlices": 2, "proves": true,
             "miners": 1, "freeMiners": 1, "freeHs": "41000000000000", "payUrl": "https://miners.example/hashrate", "payNode": "02aa"},
            {"name": "Old miners", "linkKey": "02cc", "priceMsat": 40_000, "sliceWork": (1u128 << 47).to_string(), "proves": false,
             "miners": 1, "freeMiners": 1, "freeHs": "4000000000000"}]}),
        _ => json!({"error": "no"}),
    });
    let dir = tempfile::tempdir().unwrap();
    let rtok = dir.path().join("renter-token");
    std::fs::write(&rtok, "r".repeat(64)).unwrap();
    let bx = start(json!({}), false, |c| {
        c.hash.renter = Some(renter.clone());
        c.hash.renter_token = Some(rtok.clone());
    });
    let mut br = logged_in(&bx);
    let p = br.get("/hashrate");
    let card = |name: &str| {
        let c = &p.body[p.body.find(&format!("<h3>{name}</h3>")).unwrap()..];
        c[..c.find("</section>").unwrap()].to_string()
    };
    let big = card("Big miners");
    assert!(big.contains("Start fee: <strong>6,470 sats</strong>, about 14 seconds of a machine") && big.contains("paid first"), "{big}");
    assert!(big.contains("one piece of work and its start fee, about 9,705 sats"), "the trial pays the fee too: {big}");
    assert!(big.contains("About an hour of one machine, with its start fee"), "{big}");
    let old = card("Old miners");
    assert!(old.contains("Needs updating") && old.contains("<button disabled>Rent</button>"), "{old}");
    assert!(!old.contains("Start fee"), "{old}");
}

/// The renter's status with the bundled Stream Gateway in use: `state` as the renter reads it.
fn bundled_status(running: bool, node: Option<bool>, masking: bool, moved: Option<&str>) -> Value {
    let blinding = match (node, masking) {
        (Some(true), true) => json!({"state": "blinded", "why": "solo", "words": "Blinded."}),
        (Some(true), false) => json!({"state": "not blinded", "why": "this job isn't blinded: its key is null", "words": "Not blinded."}),
        _ => json!({"state": "can't be checked", "why": "127.0.0.1:23339 gave no job to look at", "words": "This can't be checked."}),
    };
    json!({"datum": {"addr": "127.0.0.1:23339", "reachable": running, "found": ["127.0.0.1:23339"], "movedFrom": moved},
           "bundled": {"addr": "127.0.0.1:23339", "inUse": true, "running": running, "node": node, "masking": masking},
           "blinding": blinding, "rentals": []})
}

fn offers_one() -> Value {
    json!({"offers": [{"name": "Big miners", "linkKey": "02bb", "priceMsat": 40_000, "sliceWork": (1u128 << 47).to_string(), "proves": true,
                       "miners": 1, "freeMiners": 1, "freeHs": "4000000000000", "payUrl": "https://miners.example/hashrate", "payNode": MINERS_NODE}]})
}

const MINERS_NODE: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/// Spending rules that let the app pay the stand-in hashmaker (its origin listed, with its node).
fn miners_allowed() -> Value {
    json!({"allowlist": [PROVIDER, ADDR, "https://miners.example"], "counterparties": {"https://miners.example": {"ln_node": MINERS_NODE}}})
}

/// "Your gateway": the bundled Stream Gateway's settings are written to its config for each mode, an address is checked
/// first (nothing written when it doesn't), no secret goes in, and renting waits for the gateway to be set up.
#[test]
fn the_stream_gateways_settings_are_written_for_each_mode_with_the_address_checked() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (renter, _seen) = control_standin(|m, p| match (m, p) {
        ("GET", "/status") => bundled_status(false, None, false, None),
        ("GET", "/offers") => offers_one(),
        _ => json!({"error": "no"}),
    });
    let dir = tempfile::tempdir().unwrap();
    let rtok = dir.path().join("renter-token");
    std::fs::write(&rtok, "r".repeat(64)).unwrap();
    let gwdir = dir.path().join("run/datum");
    std::fs::create_dir_all(&gwdir).unwrap();
    let bx = start(miners_allowed(), false, |c| {
        c.hash.renter = Some(renter.clone());
        c.hash.renter_token = Some(rtok.clone());
        c.hash.stream_gw.rpcurl = Some("http://xbt-knots_bitcoind_1:18443".into());
        c.hash.stream_gw.dir = gwdir.clone();
    });
    let mut br = logged_in(&bx);
    let p = br.get("/hashrate");
    assert!(p.body.contains("Set up your gateway") && p.body.contains("Stream Gateway (DATUM-compatible)"), "{}", p.body);
    assert!(!p.body.contains("DATUM Gateway"), "never the product name: {}", p.body);
    assert!(p.body.contains("name=\"mode\" value=\"solo\" checked"), "solo is the default");
    assert!(p.body.contains("could hide a block it finds from the pool, the same as any DATUM miner can today"));
    let card = &p.body[p.body.find("<h3>Big miners</h3>").unwrap()..];
    assert!(card[..card.find("</section>").unwrap()].contains("<button disabled>Rent</button>"));
    let conf = gwdir.join("config.json");
    // a mainnet address on this regtest node, and a typo: refused, nothing written
    for bad in ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt081", ""] {
        let r = br.act("/hashrate", "/hashrate", &[("action", "gateway"), ("mode", "solo"), ("payout", bad)]);
        assert!(br.flash_after(&r).len() > 5);
        assert!(!conf.exists(), "{bad}");
    }
    const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let r = br.act("/hashrate", "/hashrate", &[("action", "gateway"), ("mode", "solo"), ("payout", ADDR)]);
    assert!(br.flash_after(&r).starts_with("Saved."));
    let c: Value = serde_json::from_str(&std::fs::read_to_string(&conf).unwrap()).unwrap();
    assert_eq!(c["datum"], json!({"pool_host": "", "pooled_mining_only": false}));
    assert_eq!(c["mining"]["pool_address"], ADDR);
    assert_eq!(c["bitcoind"]["rpcurl"], "http://xbt-knots_bitcoind_1:18443");
    assert_eq!(c["bitcoind"]["rpccookiefile"], "/data/run/datum/rpc.cookie");
    assert_eq!((c["api"]["listen_addr"].as_str(), c["api"]["listen_port"].as_u64(), c["api"]["admin_password"].as_str(), c["api"]["xbt_job_allow"].as_str()),
               (Some("127.0.0.1"), Some(7152), Some(""), Some("")));
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::metadata(&conf).unwrap().mode() & 0o777, 0o640);
    }
    // Lazarus Pool: the pool's server and key, the same address and id
    let r = br.act("/hashrate", "/hashrate", &[("action", "gateway"), ("mode", "pool-key"), ("payout", ADDR)]);
    assert!(br.flash_after(&r).contains("Lazarus Pool"));
    let c2: Value = serde_json::from_str(&std::fs::read_to_string(&conf).unwrap()).unwrap();
    assert_eq!((c2["datum"]["pool_host"].as_str(), c2["datum"]["pool_port"].as_u64(), c2["datum"]["pooled_mining_only"].as_bool()),
               (Some("datum.lazarus-xbt.xyz"), Some(28915), Some(true)));
    assert_eq!(c2["datum"]["pool_pubkey"].as_str().map(str::len), Some(128));
    assert_eq!(c2["mining"]["coinbase_unique_id"], c["mining"]["coinbase_unique_id"]);
    assert_eq!(c2["xbt"]["mode"], "pool-key");
    // the page shows what was saved, and no longer asks to set it up
    let p = br.get("/hashrate");
    assert!(p.body.contains("name=\"mode\" value=\"pool-key\" checked") && p.body.contains(ADDR), "{}", p.body);
    assert!(!p.body.contains("Set up your gateway") && p.body.contains("Your gateway isn't running"), "{}", p.body);
    // no secret of the box's in it: not the renter's token, not the UI's password
    let text = std::fs::read_to_string(&conf).unwrap();
    assert!(!text.contains(&"r".repeat(64)) && !text.contains("rpcpassword") && !text.contains("rpcuser"));
}

/// The bundled gateway's state on the rent page: running, connected to the node, masking, each said plainly, and
/// Rent opens only once all three are so.
#[test]
fn the_rent_page_shows_the_bundled_gateways_state() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    type Answer = fn(&str, &str) -> Value;
    let cases: [(Answer, &str, bool, usize); 4] = [
        (|m, p| match (m, p) { ("GET", "/status") => bundled_status(false, None, false, None), ("GET", "/offers") => offers_one(), _ => json!({}) },
         "Your gateway isn't running", false, 0),
        (|m, p| match (m, p) { ("GET", "/status") => bundled_status(true, Some(false), false, None), ("GET", "/offers") => offers_one(), _ => json!({}) },
         "Your gateway is waiting for your node", false, 1),
        (|m, p| match (m, p) { ("GET", "/status") => bundled_status(true, Some(true), false, None), ("GET", "/offers") => offers_one(), _ => json!({}) },
         "Lazarus Pool doesn&#39;t take gateway keys yet", false, 2),
        (|m, p| match (m, p) { ("GET", "/status") => bundled_status(true, Some(true), true, None), ("GET", "/offers") => offers_one(), _ => json!({}) },
         "Ready to rent", true, 3),
    ];
    for (answer, head, can, good) in cases {
        let (renter, _seen) = control_standin(answer);
        let dir = tempfile::tempdir().unwrap();
        let rtok = dir.path().join("renter-token");
        std::fs::write(&rtok, "r".repeat(64)).unwrap();
        let gwdir = dir.path().join("run/datum");
        std::fs::create_dir_all(&gwdir).unwrap();
        let bx = start(miners_allowed(), false, |c| {
            c.hash.renter = Some(renter.clone());
            c.hash.renter_token = Some(rtok.clone());
            c.hash.stream_gw.rpcurl = Some("http://node:18443".into());
            c.hash.stream_gw.dir = gwdir.clone();
        });
        let st = xbt_wallet_ui::config::StreamGwSetup { rpcurl: Some("http://node:18443".into()), dir: gwdir.clone(), ..Default::default() };
        let s = xbt_wallet_ui::stream_gateway::Settings::new(xbt_wallet_ui::stream_gateway::Mode::Solo, "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080");
        xbt_wallet_ui::stream_gateway::write(&st, &s, "regtest").unwrap();
        let mut br = logged_in(&bx);
        let p = br.get("/hashrate");
        assert!(p.body.contains(head), "{head}: {}", p.body);
        let rows = &p.body[p.body.find("<ul class=\"plain\">").unwrap()..];
        let rows = &rows[..rows.find("</ul>").unwrap()];
        assert!(rows.contains("Running") && rows.contains("Connected to your node") && rows.contains("Masking its jobs"), "{rows}");
        assert_eq!(rows.matches("pill good").count(), good, "{head}: {rows}");
        let card = &p.body[p.body.find("<h3>Big miners</h3>").unwrap()..];
        let card = &card[..card.find("</section>").unwrap()];
        assert_eq!(card.contains("<button>Rent</button>"), can, "{head}: {card}");
    }
}

/// An install moved to the bundled gateway at the upgrade is told so, with a one-click way back that the renter keeps;
/// one on another gateway gets the one-click switch to the bundled one.
#[test]
fn a_moved_install_is_told_and_can_switch_either_way() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (renter, seen) = control_standin(|m, p| match (m, p) {
        ("GET", "/status") => bundled_status(true, Some(true), true, Some("datum_web_1:23334")),
        ("GET", "/offers") => offers_one(),
        ("POST", "/datum") => json!({"ok": true, "datum": "datum_web_1:23334", "reachable": true, "bundled": false}),
        _ => json!({}),
    });
    let dir = tempfile::tempdir().unwrap();
    let rtok = dir.path().join("renter-token");
    std::fs::write(&rtok, "r".repeat(64)).unwrap();
    let bx = start(miners_allowed(), false, |c| {
        c.hash.renter = Some(renter.clone());
        c.hash.renter_token = Some(rtok.clone());
        c.hash.stream_gw.rpcurl = Some("http://node:18443".into());
        c.hash.stream_gw.dir = dir.path().to_path_buf();
    });
    let mut br = logged_in(&bx);
    let p = br.get("/hashrate");
    assert!(p.body.contains("Rented work now goes to the Stream Gateway (DATUM-compatible) that comes with this app") && p.body.contains("datum_web_1:23334"),
            "{}", p.body);
    assert!(p.body.contains("Use datum_web_1:23334 again"));
    let r = br.act("/hashrate", "/hashrate", &[("action", "use-previous"), ("addr", "datum_web_1:23334")]);
    assert!(br.flash_after(&r).starts_with("Saved."));
    assert!(seen.lock().unwrap().iter().any(|(m, p, _, b)| m == "POST" && p == "/datum" && b.contains("datum_web_1:23334")));

    // on another gateway: the switch back to the bundled one
    let (renter2, seen2) = control_standin(|m, p| match (m, p) {
        ("GET", "/status") => json!({"datum": {"addr": "datum_web_1:23334", "reachable": true, "found": []},
                                     "bundled": {"addr": "127.0.0.1:23339", "inUse": false, "running": true, "state": "not in use"},
                                     "blinding": {"state": "can't be checked", "why": "the gateway's API: connection refused", "words": "x"}, "rentals": []}),
        ("GET", "/offers") => offers_one(),
        ("POST", "/datum") => json!({"ok": true, "datum": "127.0.0.1:23339", "reachable": true, "bundled": true}),
        _ => json!({}),
    });
    let bx2 = start(miners_allowed(), false, |c| {
        c.hash.renter = Some(renter2.clone());
        c.hash.renter_token = Some(rtok.clone());
        c.hash.stream_gw.rpcurl = Some("http://node:18443".into());
        c.hash.stream_gw.dir = dir.path().to_path_buf();
    });
    let mut br2 = logged_in(&bx2);
    let p = br2.get("/hashrate");
    assert!(p.body.contains("Use the Stream Gateway (DATUM-compatible)") && p.body.contains("isn't masking its jobs"), "{}", p.body);
    let r = br2.act("/hashrate", "/hashrate", &[("action", "use-bundled")]);
    assert!(br2.flash_after(&r).contains("comes with this app"));
    assert!(seen2.lock().unwrap().iter().any(|(m, p, _, b)| m == "POST" && p == "/datum" && b.contains("127.0.0.1:23339")));
}

/// A build of the app without the bundled gateway (armv7): the rent page says the gateway isn't masking, Rent is off, and
/// there are no gateway settings to fill in.
#[test]
fn without_the_bundled_gateway_renting_says_it_isnt_masking() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (renter, _seen) = control_standin(|m, p| match (m, p) {
        ("GET", "/status") => bundled_status(false, None, false, None),
        ("GET", "/offers") => offers_one(),
        _ => json!({}),
    });
    let dir = tempfile::tempdir().unwrap();
    let rtok = dir.path().join("renter-token");
    std::fs::write(&rtok, "r".repeat(64)).unwrap();
    let bx = start(miners_allowed(), false, |c| {
        c.hash.renter = Some(renter.clone());
        c.hash.renter_token = Some(rtok.clone());
    });
    let mut br = logged_in(&bx);
    let p = br.get("/hashrate");
    assert!(p.body.contains("Your gateway isn't masking its jobs") && p.body.contains("doesn&#39;t include the Stream Gateway"), "{}", p.body);
    assert!(!p.body.contains("name=\"payout\""), "no settings for a gateway that isn't here");
    let card = &p.body[p.body.find("<h3>Big miners</h3>").unwrap()..];
    assert!(card[..card.find("</section>").unwrap()].contains("<button disabled>Rent</button>"));
}

/// StartOS (W7): the bundled gateway up, with no Stratum yet while it waits for the node. The rent page says it waits for
/// the node, never the generic "can't be checked: ... doesn't answer", and a rent sent anyway comes back in the gateway's words.
#[test]
fn a_bundled_gateway_waiting_for_its_node_reads_as_that_not_as_an_address_that_doesnt_answer() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (renter, _seen) = control_standin(|m, p| match (m, p) {
        // as an older renter (or a stale look) words it: the generic words; the bundled state is the truth
        ("GET", "/status") => json!({"datum": {"addr": "127.0.0.1:23339", "reachable": false, "found": []},
            "bundled": {"addr": "127.0.0.1:23339", "inUse": true, "running": true, "node": false, "masking": false, "state": "waiting for the node"},
            "blinding": {"state": "can't be checked", "why": "127.0.0.1:23339 doesn't answer",
                         "words": "This can't be checked: 127.0.0.1:23339 doesn't answer. Without a look inside its jobs nobody can say a hashmaker can't drop the shares that win, so rentals to this upstream are refused."},
            "rentals": []}),
        ("GET", "/offers") => offers_one(),
        _ => json!({}),
    });
    let dir = tempfile::tempdir().unwrap();
    let rtok = dir.path().join("renter-token");
    std::fs::write(&rtok, "r".repeat(64)).unwrap();
    let gwdir = dir.path().join("run/datum");
    std::fs::create_dir_all(&gwdir).unwrap();
    let bx = start(miners_allowed(), false, |c| {
        c.hash.renter = Some(renter.clone());
        c.hash.renter_token = Some(rtok.clone());
        c.hash.stream_gw.rpcurl = Some("http://node:18443".into());
        c.hash.stream_gw.dir = gwdir.clone();
    });
    let st = xbt_wallet_ui::config::StreamGwSetup { rpcurl: Some("http://node:18443".into()), dir: gwdir.clone(), ..Default::default() };
    xbt_wallet_ui::stream_gateway::write(&st, &xbt_wallet_ui::stream_gateway::Settings::new(xbt_wallet_ui::stream_gateway::Mode::Solo,
                                         "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"), "regtest").unwrap();
    let mut br = logged_in(&bx);
    let p = br.get("/hashrate");
    assert!(p.body.contains("Your gateway is waiting for your node") && p.body.contains("has no work from your XBT node yet"), "{}", p.body);
    for generic in ["doesn&#39;t answer", "doesn't answer", "can&#39;t be checked", "can't be checked", "Can&#39;t reach", "Can't reach", "isn&#39;t running", "isn't running"] {
        assert!(!p.body.contains(generic), "{generic}: {}", p.body);
    }
    let rows = &p.body[p.body.find("<ul class=\"plain\">").unwrap()..];
    let rows = &rows[..rows.find("</ul>").unwrap()];
    assert_eq!(rows.matches("pill good").count(), 1, "running, and not yet connected to the node: {rows}");
    let card = &p.body[p.body.find("<h3>Big miners</h3>").unwrap()..];
    assert!(card[..card.find("</section>").unwrap()].contains("<button disabled>Rent</button>"));
}

/// Linux lane: another gateway's API can be given on the page (checked, and sent to the renter with the choice), and a
/// gateway chosen here that the installer's changed settings overrode is said, with the way back.
#[test]
fn another_gateways_api_is_set_on_the_page_and_an_installer_override_is_said() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let (renter, seen) = control_standin(|m, p| match (m, p) {
        ("GET", "/status") => json!({"datum": {"addr": "10.0.0.6:23334", "api": "10.0.0.6:7160", "reachable": true, "found": [],
                                               "installerWon": "127.0.0.1:23339"},
                                     "bundled": {"addr": "127.0.0.1:23339", "inUse": false, "running": false, "state": "not running"},
                                     "blinding": {"state": "blinded", "why": "solo", "words": "Blinded."}, "rentals": []}),
        ("GET", "/offers") => offers_one(),
        ("POST", "/datum") => json!({"ok": true, "datum": "10.0.0.6:23334", "reachable": true, "bundled": false}),
        _ => json!({}),
    });
    let dir = tempfile::tempdir().unwrap();
    let rtok = dir.path().join("renter-token");
    std::fs::write(&rtok, "r".repeat(64)).unwrap();
    let bx = start(miners_allowed(), false, |c| {
        c.hash.renter = Some(renter.clone());
        c.hash.renter_token = Some(rtok.clone());
        c.hash.stream_gw.rpcurl = Some("http://node:18443".into());
        c.hash.stream_gw.dir = dir.path().to_path_buf();
    });
    let mut br = logged_in(&bx);
    let p = br.get("/hashrate");
    // the override, said, with the page's choice offered back
    assert!(p.body.contains("The app's install settings changed since you chose <code>127.0.0.1:23339</code> on this page")
            && p.body.contains("<code>10.0.0.6:23334</code> now, as they say") && p.body.contains("Use 127.0.0.1:23339 again"), "{}", p.body);
    // the API field, filled with the API in use (not the one the address implies)
    assert!(p.body.contains("name=\"api\" value=\"10.0.0.6:7160\""), "{}", p.body);
    // a bad API address is refused on the page: nothing reaches the renter
    for bad in ["nocolon", "10.0.0.6:port", "10.0.0.6:0", "10.0.0.6:70000", ":7152"] {
        let r = br.act("/hashrate", "/hashrate", &[("action", "datum"), ("addr", "10.0.0.6:23334"), ("api", bad)]);
        assert!(br.flash_after(&r).contains("the API address is host:port"), "{bad}");
    }
    assert!(!seen.lock().unwrap().iter().any(|(m, p, _, _)| m == "POST" && p == "/datum"));
    // a good one goes with the choice
    let r = br.act("/hashrate", "/hashrate", &[("action", "datum"), ("addr", "10.0.0.6:23334"), ("api", "10.0.0.7:7160")]);
    assert!(br.flash_after(&r).starts_with("Saved."));
    let sent = seen.lock().unwrap().iter().find(|(m, p, _, _)| m == "POST" && p == "/datum").cloned().unwrap();
    assert_eq!(serde_json::from_str::<Value>(&sent.3).unwrap(), json!({"addr": "10.0.0.6:23334", "api": "10.0.0.7:7160"}));
    // empty: none sent, the renter uses the host's 7152
    let r = br.act("/hashrate", "/hashrate", &[("action", "datum"), ("addr", "10.0.0.6:23334"), ("api", "")]);
    br.flash_after(&r);
    let last = seen.lock().unwrap().iter().rfind(|(m, p, _, _)| m == "POST" && p == "/datum").cloned().unwrap();
    assert_eq!(serde_json::from_str::<Value>(&last.3).unwrap(), json!({"addr": "10.0.0.6:23334"}));
    // "use it again": the page's earlier choice, sent back
    let r = br.act("/hashrate", "/hashrate", &[("action", "use-previous"), ("addr", "127.0.0.1:23339")]);
    br.flash_after(&r);
    assert!(seen.lock().unwrap().iter().any(|(m, p, _, b)| m == "POST" && p == "/datum" && b.contains("127.0.0.1:23339")));
}

// --- who may be paid: sellers by name, never a node lost (0.2.2, #37) ---------------------------------

/// A shop reached by its key, as Mike's Genesis was: its listing's services in the services file
/// (named `shop: service`, as several are), and its link vouched for by `node` in the shops file.
/// Returns the shop's origin, its npub and the node's id.
fn genesis_shop(bx: &Box_) -> (String, String, String) {
    let shop_pk = [0x4e; 32];
    let shop = xbt402::shop::origin_for(&shop_pk);
    let npub = xbt402::shop::npub(&shop_pk);
    let (sk, pk) = receipt_key(b"genesis");
    let node = Sk::from_slice(&[9u8; 32]).unwrap();
    let node_hex = hex::encode(xbt_primitives::ecdsa::pubkey(&node));
    let expires = xbt_nostr::now() + 30 * 86_400;
    let ep = "ab".repeat(32);
    let link = xbt402::transport::Link { kind: "iroh".into(), endpoint_id: ep.clone(), relays: vec!["https://relay.example".into()], direct: vec![], expires,
                                         node_sig: xbt402::claim::sign(xbt402::claim::claim_text(&ep, &shop, expires).as_bytes(), &node) };
    let t = xbt402::transport::sign(&sk, &xbt402::transport::document(&shop, &pk, &[link], "2026-11-01"));
    let mut shops = std::collections::BTreeMap::new();
    shops.insert(shop.clone(), xbt_wallet_ui::shops::Shop { receipt_key: pk, transport: Some(t) });
    let cfg = &bx._app.cfg;
    std::fs::create_dir_all(cfg.shops_path().parent().unwrap()).unwrap();
    xbt_wallet_ui::shops::save(&cfg.shops_path(), &shops).unwrap();
    std::fs::write(cfg.services_path(), json!([
        {"name": "Lightning Stream Genesis: Blender open films (Jellyfin)", "kind": "video", "seller": shop, "price_text": "20 sat a MiB", "items": []},
        {"name": "Lightning Stream Genesis: Notes", "kind": "api", "seller": shop, "price_text": "1 sat a request", "items": []},
    ]).to_string()).unwrap();
    assert_eq!(xbt_wallet_ui::shops::node(&shops[&shop], &shop, xbt_nostr::now()).as_deref(), Some(node_hex.as_str()));
    (shop, npub, node_hex)
}

const OTHER: &str = "https://other.example";

/// Spending rules → "Who may be paid" is a list of sellers, by name, with their key and node, and a
/// Remove box. Editing the rules takes whole sellers out and can never cut a seller's node off: 0.2.1
/// had a free-text box where Genesis's line wrapped, and an edit saved it with no node, so every
/// payment to it was refused. A seller on the list with no node is a warning, before signing.
///
/// FAILS without the list: the page has the two text boxes, no `f_sellers`, no names and no warning.
#[test]
fn editing_the_rules_never_drops_a_seller_s_node_and_a_seller_without_one_is_warned_before_signing() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let other_node = hex::encode(xbt_primitives::ecdsa::pubkey(&Sk::from_slice(&[7u8; 32]).unwrap()));
    let bx = start(json!({"ln": {"enabled": true}}), false, |_| {});
    let (shop, npub, node_hex) = genesis_shop(&bx);
    // the rules: the rig's own (PROVIDER, with no node, and a coin address), Genesis and another seller, each with its node
    let mut p = bx.rig.call("policy_get", json!({}))["policy"].clone();
    p["allowlist"] = json!([PROVIDER, ADDR, shop, OTHER]);
    p["counterparties"] = json!({shop.clone(): {"ln_node": node_hex}, OTHER: {"ln_node": other_node}});
    let mut br = logged_in(&bx);
    let csrf = field(&br.get("/policy").body, "csrf");
    let prev = br.post("/policy", &[("csrf", &csrf), ("mode", "json"), ("json", &p.to_string())]).body;
    assert!(prev.contains("Sign and apply"), "{prev}");
    let (text, sha, exp) = (field(&prev, "text"), field(&prev, "prev_sha256"), field(&prev, "expiry"));
    let r = br.post("/policy-apply", &[("csrf", &csrf), ("text", &text), ("prev_sha256", &sha), ("expiry", &exp),
                                        ("signature", &sig(&policy_message(&sha, exp.parse().unwrap(), &text)))]);
    assert!(br.flash_after(&r).starts_with("Policy applied"));

    let page = br.get("/policy").body;
    // a list, not free text
    assert!(!page.contains("name=\"f_allowlist\"") && !page.contains("name=\"f_counterparties\""), "{page}");
    assert!(page.contains("<table class=\"sellers\">"), "{page}");
    // the shop by its listing's name and its key; its node shortened, in full on hover
    let rules = &page[page.find("id=\"sellers\"").unwrap()..];
    let rules = &rules[..rules.find("</fieldset>").unwrap()];
    assert!(rules.contains("<strong>Lightning Stream Genesis</strong>") && rules.contains(&npub), "{rules}");
    assert!(rules.contains(&format!("title=\"{node_hex}\"")) && rules.contains(&format!("{}…{}", &node_hex[..8], &node_hex[58..])), "{rules}");
    assert!(!rules.contains(&format!(">{shop}<")) && rules.contains(&format!("<code class=\"key small\">{npub}</code>")), "no made-up address shown: {rules}");
    // the rig's PROVIDER is on the list with no node: said, with what follows
    let warn = "this seller will be refused: it has no Lightning node on file";
    assert!(page.contains(warn) && page.contains("seller-warning"), "{page}");

    // an edit: another rule changed and the other seller removed; Genesis keeps its node
    let mut form = policy_form_fields(&page);
    form.iter_mut().find(|(k, _)| k == "f_human_threshold_sats").unwrap().1 = "4000".into();
    let other_row = rules[..rules.find(&format!("value=\"{OTHER}\"")).unwrap()].rfind("name=\"f_drop_").unwrap();
    let name = rules[other_row + 6..].split('"').next().unwrap().to_string();
    form.push((name, OTHER.into()));
    // the review warns about PROVIDER too, before anything is signed
    let review = br.post("/policy", &form.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect::<Vec<_>>()).body;
    assert!(review.contains(warn) && review.contains("Sign and apply"), "{review}");
    let flash = sign_policy_form(&mut br, &form);
    assert!(flash.starts_with("Policy applied"), "{flash}");
    let p = bx.rig.call("policy_get", json!({}))["policy"].clone();
    assert_eq!(p["human_threshold_sats"], 4000);
    assert_eq!(p["counterparties"][&shop]["ln_node"], json!(node_hex), "the node is kept: {p}");
    assert_eq!(p["allowlist"], json!([PROVIDER, ADDR, shop]), "{p}");
    assert!(p["counterparties"].get(OTHER).is_none(), "{p}");

    // a page from before (free text, the node cut off, no list): the sellers stay as they are
    let page = br.get("/policy").body;
    let mut old: Vec<(String, String)> = policy_form_fields(&page).into_iter().filter(|(k, _)| k != "f_sellers").collect();
    old.push(("f_allowlist".into(), shop.clone()));
    old.push(("f_counterparties".into(), shop.clone()));
    old.iter_mut().find(|(k, _)| k == "f_human_threshold_sats").unwrap().1 = "3000".into();
    assert!(sign_policy_form(&mut br, &old).starts_with("Policy applied"));
    let p = bx.rig.call("policy_get", json!({}))["policy"].clone();
    assert_eq!(p["human_threshold_sats"], 3000);
    assert_eq!(p["counterparties"][&shop]["ln_node"], json!(node_hex), "an old page cannot drop the node: {p}");
    assert_eq!(p["allowlist"], json!([PROVIDER, ADDR, shop]), "{p}");

    // the expert's file: a node other than the one the shop vouches for is a warning, with the fix
    let mut wrong = p.clone();
    wrong["counterparties"][&shop]["ln_node"] = json!(other_node);
    let review = br.post("/policy", &[("csrf", &csrf), ("mode", "json"), ("json", &wrong.to_string())]).body;
    assert!(review.contains("this seller will be refused: its Lightning node on file is not the one the shop vouches for now"), "{review}");
    assert!(review.contains(&format!("Lightning Stream Genesis ({npub}) › ln_node")), "the change names the shop: {review}");
    let mut none = p.clone();
    none["counterparties"] = json!({});
    let review = br.post("/policy", &[("csrf", &csrf), ("mode", "json"), ("json", &none.to_string())]).body;
    assert!(review.contains("<strong>Lightning Stream Genesis</strong>: this seller will be refused: it has no Lightning node on file"), "{review}");
}

/// Sellers names a shop by its listing's name, not after its first service; removing a seller there
/// says it is still allowed to be paid and opens the rules with it ticked for removal; the version
/// is in the footer and Settings.
///
/// FAILS before: the heading was "Lightning Stream Genesis: Blender open films (Jellyfin)", the removal
/// said nothing of the rules, and no version was shown.
#[test]
fn sellers_are_named_by_their_shop_and_a_removed_seller_still_in_the_rules_is_offered_for_removal() {
    let _e = ENV.lock().unwrap_or_else(|p| p.into_inner());
    let bx = start(json!({"ln": {"enabled": true}}), false, |_| {});
    let (shop, npub, node_hex) = genesis_shop(&bx);
    let mut br = logged_in(&bx);
    let csrf = field(&br.get("/policy").body, "csrf");
    let mut p = bx.rig.call("policy_get", json!({}))["policy"].clone();
    p["allowlist"] = json!([ADDR, shop]);
    p["counterparties"] = json!({shop.clone(): {"ln_node": node_hex}});
    let prev = br.post("/policy", &[("csrf", &csrf), ("mode", "json"), ("json", &p.to_string())]).body;
    let (text, sha, exp) = (field(&prev, "text"), field(&prev, "prev_sha256"), field(&prev, "expiry"));
    let r = br.post("/policy-apply", &[("csrf", &csrf), ("text", &text), ("prev_sha256", &sha), ("expiry", &exp),
                                        ("signature", &sig(&policy_message(&sha, exp.parse().unwrap(), &text)))]);
    assert!(br.flash_after(&r).starts_with("Policy applied"));

    let sellers = br.get("/services").body;
    assert!(sellers.contains("<h3>Lightning Stream Genesis</h3>"), "{sellers}");
    assert!(!sellers.contains("Still allowed to be paid"), "it is on the list");
    // the version: the release's, not the crate's 0.1.0
    let v = xbt_wallet_ui::release_version();
    assert_ne!(v, "0.1.0");
    assert!(sellers.contains(&format!("Lightning Stream {v}</span></footer>")), "{sellers}");
    assert!(br.get("/setup").body.contains(&format!("Lightning Stream version {v}")));

    let r = br.act("/services", "/services", &[("action", "remove"), ("url", &shop)]);
    let f = br.flash_after(&r);
    assert!(f.contains("Seller removed") && f.contains("still allowed to be paid in your spending rules"), "{f}");
    let sellers = br.get("/services").body;
    let link = format!("./policy?drop={}", xbt_wallet_ui::services::urlenc(&shop));
    assert!(sellers.contains("Still allowed to be paid") && sellers.contains(&link) && sellers.contains(&npub), "{sellers}");
    // the rules, with it ticked for removal; signed, it is gone from both lists
    let page = br.get(link.trim_start_matches('.')).body;
    assert!(page.contains("is still allowed to be paid. It is ticked for removal"), "{page}");
    let row = &page[page.find(&format!("value=\"{shop}\" checked")).expect("ticked")..];
    assert!(row.starts_with(&format!("value=\"{shop}\" checked")));
    let i = page[..page.find(&format!("value=\"{shop}\" checked")).unwrap()].rfind("name=\"f_drop_").unwrap();
    let name = page[i + 6..].split('"').next().unwrap().to_string();
    let mut form = policy_form_fields(&page);
    form.push((name, shop.clone()));
    assert!(sign_policy_form(&mut br, &form).starts_with("Policy applied"));
    let p = bx.rig.call("policy_get", json!({}))["policy"].clone();
    assert_eq!(p["allowlist"], json!([ADDR]), "{p}");
    assert_eq!(p["counterparties"], json!({}), "{p}");
    assert!(!br.get("/services").body.contains("Still allowed to be paid"));
}
