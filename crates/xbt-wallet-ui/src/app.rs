//! The routes and pages.
//!
//! Reads go straight to the signer socket. Every change is a POST with the session's CSRF token.
//! The ones that raise what the wallet may spend or move keys (approve, policy, human key, sweep,
//! rotation, backup) also carry the human's ed25519 signature, made in the browser by `ui.js` (or
//! pasted from another device); the signer verifies it, so this process cannot forge them.
use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::auth::Auth;
use crate::config::{Config, Role};
use crate::html::{esc, escv, int, json_block, kv, page, sats, short, txt, utc, Nav, Section, GATEWAY_BRAND, GATEWAY_SECTIONS, STREAM_BRAND, STREAM_SECTIONS,
                  STREAM_SECTIONS_HASH, WALLET_BRAND, WALLET_SECTIONS, WALLET_SECTIONS_HASH};
use crate::link::SignerLink;
use crate::relay::RelayLinks;
use crate::server::{strip_base, Req, Resp};
use crate::{msg, now};

#[path = "stream_pages.rs"]
mod stream_pages;
#[path = "nwc_pages.rs"]
mod nwc_pages;
#[path = "sell.rs"]
pub(crate) mod sell;
#[path = "services_page.rs"]
pub mod services_page;
#[path = "nostr_pages.rs"]
mod nostr_pages;
#[path = "hashrate.rs"]
pub(crate) mod hashrate;

pub const COOKIE: &str = "xbtui";
/// How long a signed form stays valid.
pub const SIGN_WINDOW_S: i64 = 600;

pub struct App {
    pub cfg: Config,
    pub auth: Auth,
    pub signer: SignerLink,
    /// The links external players play one item through ([`crate::relay`]).
    pub relays: RelayLinks,
    /// Sellers found on Nostr, when the owner set relays ([`crate::nostr`]).
    pub nostr: crate::nostr::NostrCache,
    /// The platform's login proxy, when it does the login ([`crate::auth::PlatformLogin`]).
    pub platform: Option<crate::auth::PlatformLogin>,
    /// Why the last play of an item failed, by item URL, for the player page to say (a few minutes).
    pub play_errors: std::sync::Mutex<HashMap<String, (std::time::Instant, u16, Value)>>,
}

/// What a human who signs on another device needs.
enum Ext {
    /// The exact bytes.
    Bytes(Vec<u8>),
    /// The fields are typed on this page: the message's lines, described.
    Lines(String),
    /// Only this browser can do it (the new key is made here).
    Browser,
}

impl Ext {
    fn html(&self) -> String {
        let paste = "<textarea name=\"signature_ext\" rows=\"2\" placeholder=\"128 hex characters\"></textarea>";
        match self {
            Ext::Bytes(m) => format!("<details><summary>Sign on another device</summary><p>Sign these bytes (hex) with your ed25519 approval key, \
                                      e.g. <code>xbt-wallet-ui sign --key KEYFILE --message-hex HEX</code>, and paste the signature:</p>\
                                      <pre class=\"hex\">{}</pre>{paste}</details>", hex::encode(m)),
            Ext::Lines(l) => format!("<details><summary>Sign on another device</summary><p>The message is these lines joined by a newline \
                                      (<code>xbt-wallet-ui sign --key KEYFILE --message-hex HEX</code> signs its hex):</p><pre>{}</pre>{paste}</details>", esc(l)),
            Ext::Browser => String::new(),
        }
    }
}

/// One request's session.
pub(crate) struct Ctx {
    pub(crate) sid: String,
    pub(crate) csrf: String,
    pub(crate) flash: Option<(bool, String)>,
}

const INT_KEYS: [(&str, &str, &str); 12] = [
    ("max_per_tx_sats", "Largest single payment (sats)", "budgets"),
    ("daily_budget_sats", "Spending limit for any 24 hours (sats)", "budgets"),
    ("weekly_budget_sats", "Spending limit for any 7 days (sats)", "budgets"),
    ("per_counterparty_cap_sats", "Most to any one seller in 7 days (sats)", "budgets"),
    ("human_threshold_sats", "Ask me first for a payment of at least (sats)", "human"),
    ("approval_ttl_s", "A request for your approval expires after (seconds)", "human"),
    ("split_window_s", "Smaller payments to one seller within this many seconds count as one (so a large payment can't be split to avoid asking you)", "human"),
    ("velocity_max", "At most this many payments…", "velocity"),
    ("velocity_window_s", "…in this many seconds", "velocity"),
    ("hot_balance_cap_sats", "Most this box may hold for agents (sats; 0 means no limit)", "hot"),
    ("anchor_interval_s", "Seal the records every (seconds; after a restart)", "anchor"),
    ("treasury_csv", "Treasury delay (blocks; not used by this signer)", "anchor"),
];

/// The height the XBT chain split from the SHA-256 chain at: a Lightning channel funded only from
/// coins older than this exists on both chains, and the rail refuses it.
pub const MAINNET_SPLIT_HEIGHT: i64 = 961_640;

/// A conservative first policy (the setup wizard's template; `xbt-wallet-mcp/policy.example.json`'s limits),
/// with the Lightning rail and stream tickets on (one task, `default`, with a budget: tickets are paid only
/// under a task). On mainnet (`chain` "main") the caps are low: the software has run on regtest only.
pub fn starter_policy(chain: &str) -> Value {
    let mut p = json!({"allowlist": [], "counterparties": {}, "max_per_tx_sats": 100000, "daily_budget_sats": 200000, "weekly_budget_sats": 500000,
           "per_counterparty_cap_sats": 100000, "velocity_max": 60, "velocity_window_s": 3600, "human_threshold_sats": 50000,
           "split_window_s": 600, "approval_ttl_s": 900, "hot_balance_cap_sats": 1500000, "anchor_interval_s": 300,
           "ln": {"enabled": true}, "tickets": {"enabled": true, "tasks": {"default": {"budget_sats": 100000}}}});
    if chain == "main" {
        for (k, v) in [("max_per_tx_sats", 2000), ("daily_budget_sats", 10000), ("weekly_budget_sats", 30000), ("per_counterparty_cap_sats", 10000),
                       ("human_threshold_sats", 1000), ("hot_balance_cap_sats", 50000)] {
            p[k] = json!(v);
        }
        p["ln"]["split_height"] = json!(MAINNET_SPLIT_HEIGHT);
        p["tickets"]["tasks"]["default"]["budget_sats"] = json!(10000);
    }
    p
}

/// A static asset. The pages ask for it as `?v=<content hash>`: that URL never changes meaning, so
/// it is cached for a year; any other request for it, for a day.
fn asset(req: &Req, ctype: &str, body: &'static str) -> Resp {
    let current = req.query.get("v").is_some_and(|v| *v == crate::html::asset_version(body));
    Resp::text(200, ctype, body).header("Cache-Control", if current { "public, max-age=31536000, immutable" } else { "public, max-age=86400" })
}

fn state_of(c: &Value) -> &'static str {
    if c.get("refund_txid").is_some_and(|v| !v.is_null()) {
        "refunded"
    } else {
        match c.get("state").and_then(Value::as_str) {
            Some("open") => "open",
            Some("pending") => "pending",
            Some("closed") => "closed",
            _ => "other",
        }
    }
}

/// The signer did it: no deny, no `ok: false`, no error.
fn ok_of(r: &Value) -> bool {
    r.is_object() && !matches!(r.get("verdict").and_then(Value::as_str), Some("deny") | Some("needs_human"))
        && r.get("ok") != Some(&Value::Bool(false)) && r.get("error").is_none_or(Value::is_null)
}

fn reason_of(r: &Value) -> String {
    for k in ["reason", "error"] {
        if let Some(s) = r.get(k).and_then(Value::as_str) {
            return format!("{}{s}", r.get("rule").and_then(Value::as_str).map(|x| format!("{x}: ")).unwrap_or_default());
        }
    }
    r.to_string()
}

impl App {
    pub fn new(cfg: Config) -> Result<Arc<Self>, String> {
        let auth = Auth::open(&cfg.data_dir, cfg.password.as_deref(), cfg.setup_open, cfg.session_idle, cfg.session_max)?;
        let signer = SignerLink::new(cfg.signer_sock.clone(), std::time::Duration::from_secs(90));
        let relays = RelayLinks::new(cfg.relay_ttl);
        let nostr = crate::nostr::NostrCache::new(cfg.nostr_relays.clone());
        let platform = cfg.platform_login.as_deref().map(crate::auth::PlatformLogin::new);
        Ok(Arc::new(Self { cfg, auth, signer, relays, nostr, platform, play_errors: std::sync::Mutex::new(HashMap::new()) }))
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        self.signer.call(method, params)
    }

    pub(crate) fn cookie(&self, req: &Req, sid: &str, max_age: i64) -> String {
        let secure = self.cfg.secure_cookie.unwrap_or_else(|| req.header("x-forwarded-proto").eq_ignore_ascii_case("https"));
        format!("{COOKIE}={sid}; Path={}; HttpOnly; SameSite=Strict; Max-Age={max_age}{}", self.cfg.base_path, if secure { "; Secure" } else { "" })
    }

    /// Whether the request came through the platform's login proxy (the owner, logged in by the box).
    pub(crate) fn platform_owner(&self, req: &Req) -> bool {
        self.platform.as_ref().is_some_and(|p| p.is_proxy(&req.peer))
    }

    fn peer_allowed(&self, peer: &str) -> bool {
        self.cfg.allow_ips.is_empty() || self.cfg.allow_ips.iter().any(|p| peer == p || (p.ends_with('.') || p.ends_with(':')) && peer.starts_with(p.as_str()))
    }

    /// For `GET /s/<seller URL>` (the player's video), the same checks as a page of the wallet; for
    /// `GET /r/<token>` (an external player's link), the same checks less the login, and a live
    /// token for an item still in the services file. `Some(Ok(url))`: relay the seller URL `url`
    /// (for `/s/`, `None`: the caller takes it from the request target); `Some(Err)`: the answer
    /// that refuses it; `None` for anything else.
    pub fn relay_gate(&self, req: &Req) -> Option<Result<Option<String>, Resp>> {
        let path = strip_base(&req.path, &self.cfg.base_path)?;
        let link = path.strip_prefix("/r/");
        if req.method != "GET" || !(path.starts_with("/s/") || link.is_some()) || self.cfg.role == Role::Gateway {
            return None;
        }
        if !self.peer_allowed(&req.peer) {
            return Some(Err(Resp::text(403, "text/plain", "forbidden")));
        }
        if !host_allowed(req.header("host"), &self.cfg.allowed_hosts) {
            return Some(Err(Resp::text(421, "text/plain", "unknown Host: add it to XBT_UI_ALLOWED_HOSTS")));
        }
        if !self.auth.has_password() && !self.platform_owner(req) {
            return Some(Err(Resp::text(401, "text/plain", "login required")));
        }
        if let Some(token) = link {
            // the link alone: no cookie, and only the one item it was made for
            let in_file = |item: &str| self.services().is_ok_and(|all| crate::services::find_item(&all, item).is_some());
            return Some(match self.relays.item_of(token) {
                Some(item) if in_file(&item) => Ok(Some(item)),
                _ => Err(Resp::text(404, "text/plain", "no such link: it expired, was revoked, or its item is gone")),
            });
        }
        let sid = req.cookie(COOKIE).unwrap_or_default();
        if self.auth.with_session(&sid, |_| ()).is_none() {
            return Some(Err(Resp::text(401, "text/plain", "login required")));
        }
        Some(Ok(None))
    }

    /// For `GET /preview?item=<URL>`: the owner's free preview of an item of their own shop, past
    /// the same checks as every page (login included: there is no link for it). `Some(Ok(url))`:
    /// stream `url`, the service on this box; `None` for any other request.
    pub fn preview_gate(&self, req: &Req) -> Option<Result<String, Resp>> {
        let path = strip_base(&req.path, &self.cfg.base_path)?;
        if req.method != "GET" || path != "/preview" || self.cfg.role == Role::Gateway {
            return None;
        }
        if !self.peer_allowed(&req.peer) {
            return Some(Err(Resp::text(403, "text/plain", "forbidden")));
        }
        if !host_allowed(req.header("host"), &self.cfg.allowed_hosts) {
            return Some(Err(Resp::text(421, "text/plain", "unknown Host: add it to XBT_UI_ALLOWED_HOSTS")));
        }
        let sid = req.cookie(COOKIE).unwrap_or_default();
        if self.auth.with_session(&sid, |_| ()).is_none() {
            return Some(Err(Resp::text(401, "text/plain", "login required")));
        }
        let item = req.query.get("item").map(String::as_str).unwrap_or("");
        Some(self.preview_upstream(item).map_err(|e| Resp::json(404, &json!({"error": e}))))
    }

    /// What stops any payment before a play is tried, in plain words with the next step: no
    /// approval key enrolled, so no spending rules can be signed and nothing can be paid.
    pub fn play_blocker(&self) -> Option<(String, String, String)> {
        let ks = self.call("keystore_status", json!({})).ok()?;
        txt(ks.get("human_pubkey")).is_empty()
            .then(|| ("Your wallet isn't set up yet, so it can't pay for this.".into(), "Finish setup".into(), "./setup".into()))
    }

    /// A Lightning node that is not ready to pay: said above the player (the play is still tried;
    /// if it fails, the player says why).
    pub fn play_warning(&self) -> Option<String> {
        let ln = self.call("ln_status", json!({})).ok()?;
        (ln["ready"] != true).then(|| {
            let why = txt(ln.get("reason").or(ln.get("config_error")));
            if why.is_empty() { "Your wallet may not be able to pay yet: your Lightning node isn't ready.".into() }
            else { format!("Your wallet may not be able to pay yet. {}", crate::setup::plain_reason(&why)) }
        })
    }

    /// Keep why a play of `item` failed, for [`Self::play_error`].
    pub fn note_play_error(&self, item: &str, status: u16, body: &[u8]) {
        let v: Value = serde_json::from_slice(body).unwrap_or_else(|_| json!({"error": String::from_utf8_lossy(&body[..body.len().min(300)]).to_string()}));
        let mut g = self.play_errors.lock().unwrap_or_else(|p| p.into_inner());
        g.retain(|_, (t, _, _)| t.elapsed() < std::time::Duration::from_secs(600));
        if g.len() < 256 {
            g.insert(item.to_string(), (std::time::Instant::now(), status, v));
        }
    }

    /// Why the last play of `item` failed, in plain words, with the next step: (headline, link text, link).
    pub fn play_error(&self, item: &str) -> Option<(String, String, String)> {
        let g = self.play_errors.lock().unwrap_or_else(|p| p.into_inner());
        let (t, status, v) = g.get(item)?;
        (t.elapsed() < std::time::Duration::from_secs(600)).then(|| play_error_words(*status, v))
    }

    pub fn handle(&self, mut req: Req) -> Resp {
        if !self.peer_allowed(&req.peer) {
            return Resp::text(403, "text/plain", "forbidden");
        }
        if !host_allowed(req.header("host"), &self.cfg.allowed_hosts) {
            return Resp::text(421, "text/plain", "unknown Host: add it to XBT_UI_ALLOWED_HOSTS");
        }
        let Some(path) = strip_base(&req.path, &self.cfg.base_path) else { return Resp::text(404, "text/plain", "not found") };
        if path.is_empty() {
            let last = self.cfg.base_path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
            return Resp::redirect(&format!("./{last}/"));
        }
        req.path = path;
        let get = req.method == "GET" || req.method == "HEAD";
        let post = req.method == "POST";
        if !get && !post {
            return Resp::text(405, "text/plain", "method not allowed");
        }
        match (get, req.path.as_str()) {
            (true, "/ui.js") => return asset(&req, "text/javascript; charset=utf-8", crate::UI_JS),
            (true, "/river.js") => return asset(&req, "text/javascript; charset=utf-8", crate::river_js()),
            (true, "/ui.css") => return asset(&req, "text/css; charset=utf-8", crate::UI_CSS),
            (true, "/healthz") => return Resp::json(200, &json!({"ok": true})),
            (true, "/readyz") if self.cfg.role == Role::Gateway => return Resp::json(200, &json!({"ok": true, "role": "gateway"})),
            (true, "/readyz") => {
                let up = self.call("health", json!({})).is_ok();
                return Resp::json(if up { 200 } else { 503 }, &json!({"ok": up, "signer": if up { "reachable" } else { "unreachable" }}));
            }
            _ => {}
        }
        // a POST from another site is refused before anything else (the CSRF token is the second check)
        if post && req.header("sec-fetch-site").eq_ignore_ascii_case("cross-site") {
            return Resp::text(403, "text/plain", "cross-site request refused");
        }
        let origin = req.header("origin");
        if post && !origin.is_empty() && !origin_allowed(origin, &self.cfg.allowed_hosts) {
            return Resp::text(403, "text/plain", "cross-origin request refused");
        }
        // the box's own login proxy: its user is the owner, logged in by the platform. A session is
        // made at once and the same page asked again with its cookie; no app password is needed
        if self.platform_owner(&req) {
            let sid = req.cookie(COOKIE).unwrap_or_default();
            if self.auth.with_session(&sid, |_| ()).is_none() {
                let sid = self.auth.new_session();
                let page = match req.path.as_str() {
                    "/login" | "/setup-password" => "./".to_string(),
                    p => format!(".{p}{}", query_string(&req.query)),
                };
                return Resp::redirect(&page).header("Set-Cookie", &self.cookie(&req, &sid, self.cfg.session_max.as_secs() as i64));
            }
            if matches!(req.path.as_str(), "/login" | "/setup-password") {
                return Resp::redirect("./");
            }
        } else if !self.auth.has_password() {
            return self.setup_password(&req);
        }
        match req.path.as_str() {
            "/login" => return self.login(&req),
            "/setup-password" => return Resp::redirect("./login"),
            _ => {}
        }
        let sid = req.cookie(COOKIE).unwrap_or_default();
        let Some((csrf, flash)) = self.auth.with_session(&sid, |s| (s.csrf.clone(), s.flash.take())) else {
            if req.path.starts_with("/api/") {
                return Resp::json(401, &json!({"error": "login required"}));
            }
            return Resp::redirect("./login");
        };
        let ctx = Ctx { sid, csrf, flash };
        if post {
            let form = req.form();
            if !self.auth.check_csrf(&ctx.sid, form.get("csrf").map(String::as_str).unwrap_or("")) {
                return Resp::text(403, "text/plain", "missing or wrong CSRF token: reload the page");
            }
            if self.cfg.role == Role::Gateway {
                return self.gateway_post(&req, &ctx, &form);
            }
            return self.post(&req, &ctx, &form);
        }
        if self.cfg.role == Role::Gateway {
            return match req.path.as_str() {
                "/" => self.gateway_page(&ctx, None),
                _ => Resp::html(404, self.render("Not found", &ctx, "<p>No such page. <a href=\"./\">Back to Sell</a></p>")),
            };
        }
        match req.path.as_str() {
            "/" => self.home(&ctx),
            "/wallet" => self.overview(&ctx),
            "/browse" => self.browse(&ctx, &req.query),
            "/service" => self.service_page(&ctx, &req.query),
            "/services" => self.services_page(&ctx),
            "/sell" if self.cfg.sell => self.sell_page(&ctx, &req.query),
            "/sell-hashrate" if self.cfg.sell => self.sell_hashrate_page(&ctx),
            "/hashrate" => self.hashrate_page(&ctx),
            "/nostr" => self.nostr_page(&ctx, &req.query),
            "/play" => self.play(&ctx, &req),
            "/connections" => self.connections(&ctx),
            "/apps" => self.apps_page(&ctx),
            "/approvals" => self.approvals(&ctx),
            "/policy" => self.policy_page(&ctx, req.query.get("template").map(|t| t == "starter").unwrap_or(false),
                                          req.query.get("allow").zip(req.query.get("node")).map(|(a, n)| (a.as_str(), n.as_str()))),
            "/channels" => self.channels(&ctx),
            "/signatures" => self.signatures(&ctx),
            "/keys" => self.keys(&ctx),
            "/agents" => self.agents(&ctx),
            "/setup" => self.setup(&ctx),
            "/lightning" => self.lightning_page(&ctx),
            "/api/pending" => Resp::json(200, &json!({"pending": self.pending_count()})),
            "/api/play-error" => {
                let item = req.query.get("item").map(String::as_str).unwrap_or("");
                match self.play_error(item) {
                    Some((words, link, href)) => Resp::json(200, &json!({"failed": true, "words": words, "link": link, "href": href})),
                    None => Resp::json(200, &json!({"failed": false})),
                }
            }
            _ => Resp::html(404, self.render("Not found", &ctx, "<p>No such page. <a href=\"./\">Home</a></p>")),
        }
    }

    pub(crate) fn flash(&self, ctx: &Ctx, ok: bool, m: impl Into<String>) {
        let m = m.into();
        self.auth.with_session(&ctx.sid, |s| s.flash = Some((ok, m)));
    }

    fn pending_count(&self) -> usize {
        self.call("approvals", json!({})).ok().and_then(|v| v.get("approvals").and_then(Value::as_array).cloned())
            .map(|a| a.iter().filter(|x| x["state"] == "pending").count()).unwrap_or(0)
    }

    pub(crate) fn nav<'a>(&self, active: &'a str, csrf: &'a str, logged_in: bool) -> Nav<'a> {
        let hash = self.cfg.hash.hasher.is_some() || self.cfg.hash.renter.is_some();
        let (sections, brand): (&'static [&'static Section], &'static str) = match self.cfg.role {
            Role::Wallet if self.cfg.sell && hash => (&STREAM_SECTIONS_HASH, STREAM_BRAND),
            Role::Wallet if self.cfg.sell => (&STREAM_SECTIONS, STREAM_BRAND),
            Role::Wallet if hash => (&WALLET_SECTIONS_HASH, WALLET_BRAND),
            Role::Wallet => (&WALLET_SECTIONS, WALLET_BRAND),
            Role::Gateway => (&GATEWAY_SECTIONS, GATEWAY_BRAND),
        };
        let pending = if logged_in && self.cfg.role == Role::Wallet { self.pending_count() } else { 0 };
        Nav { active, csrf, pending, logged_in, sections, brand }
    }

    pub(crate) fn render(&self, title: &str, ctx: &Ctx, body: &str) -> String {
        page(title, &self.nav(title, &ctx.csrf, true), ctx.flash.clone(), body)
    }

    pub(crate) fn page(&self, title: &str, ctx: &Ctx, body: String) -> Resp {
        Resp::html(200, self.render(title, ctx, &body))
    }

    pub(crate) fn csrf_input(ctx: &Ctx) -> String {
        format!("<input type=\"hidden\" name=\"csrf\" value=\"{}\">", esc(&ctx.csrf))
    }

    pub(crate) fn error_box(e: &str) -> String {
        format!("<div class=\"flash bad\">{}</div>", esc(e))
    }

    /// A form the human signs: `kind` picks the message in ui.js (built there from these fields).
    #[allow(clippy::too_many_arguments)]
    fn signed_form(&self, ctx: &Ctx, action: &str, kind: &str, human: &str, hidden: &[(&str, String)], visible: &str, button: &str,
                   message: Ext) -> String {
        let mut h = String::new();
        for (k, v) in hidden {
            h.push_str(&format!("<input type=\"hidden\" name=\"{}\" value=\"{}\">", esc(k), esc(v)));
        }
        format!("<form method=\"post\" action=\"{action}\" data-sign=\"{kind}\" data-human=\"{}\" class=\"signed\">{}{h}{visible}\
                 <input type=\"hidden\" name=\"signature\" value=\"\">\
                 <div class=\"row\"><input class=\"pin\" type=\"password\" autocomplete=\"off\" inputmode=\"text\" placeholder=\"Key passphrase\" aria-label=\"Key passphrase\">\
                 <button type=\"submit\">{}</button></div><p class=\"sign-msg\" aria-live=\"polite\"></p>\
                 {}</form>",
                esc(human), Self::csrf_input(ctx), esc(button), message.html())
    }

    fn human_pub(&self) -> String {
        self.call("keystore_status", json!({})).ok().and_then(|v| v.get("human_pubkey").and_then(Value::as_str).map(str::to_string)).unwrap_or_default()
    }

    // --- login and first run ------------------------------------------------------------------------

    fn bare(&self, title: &str, flash: Option<(bool, String)>, body: &str) -> String {
        page(title, &self.nav("", "", false), flash, body)
    }

    fn setup_password(&self, req: &Req) -> Resp {
        let code_field = if self.auth.needs_setup_code() {
            "<label>Setup code<input name=\"code\" autocomplete=\"off\" required></label>\
             <p class=\"hint\">A one-time code that proves this app is yours. It is in the app's log, on the line that says \
             <em>setup code</em>. On Umbrel: right-click the Lightning Stream icon and choose <em>Troubleshoot</em>. \
             On StartOS: open Lightning Stream and choose <em>Logs</em>.</p>\
             <details><summary>Running it another way?</summary><p>The code is also in the file <code>setup-code</code> in the app's data folder.</p></details>"
        } else {
            ""
        };
        let form = |flash: Option<(bool, String)>| {
            Resp::html(200, self.bare("Welcome", flash, &format!(
                "{}<p class=\"lead\">Lightning Stream lets you pay for services, and sell your own, in small amounts over Lightning. \
                 First, choose a password for this app.</p>\
                 <form method=\"post\" action=\"./setup-password\" class=\"card\">{code_field}\
                 <label>New password<input type=\"password\" name=\"password\" autocomplete=\"new-password\" required minlength=\"{n}\"></label>\
                 <p class=\"hint\">At least {n} characters. You need it each time you open the app.</p>\
                 <label>The same password again<input type=\"password\" name=\"password2\" autocomplete=\"new-password\" required></label>\
                 <button>Set password and continue</button></form>", progress(1), n = crate::auth::MIN_PASSWORD)))
        };
        if req.method != "POST" || req.path != "/setup-password" {
            if req.path != "/setup-password" && req.path != "/" {
                return Resp::redirect("./setup-password");
            }
            return form(None);
        }
        let f = req.form();
        let pw = f.get("password").cloned().unwrap_or_default();
        if Some(&pw) != f.get("password2") {
            return form(Some((false, "The two passwords differ. Type the same one twice.".into())));
        }
        match self.auth.set_initial(f.get("code").map(String::as_str).unwrap_or(""), &pw) {
            Err(e) => form(Some((false, e))),
            Ok(()) => {
                let sid = self.auth.new_session();
                self.auth.with_session(&sid, |s| s.flash = Some((true, "Password set. Next: your approval key and your spending rules.".into())));
                Resp::redirect("./setup").header("Set-Cookie", &self.cookie(req, &sid, self.cfg.session_max.as_secs() as i64))
            }
        }
    }

    fn login(&self, req: &Req) -> Resp {
        let form = |flash: Option<(bool, String)>, status: u16| {
            Resp::html(status, self.bare("Log in", flash, "<form method=\"post\" action=\"./login\" class=\"card\">\
                <label>Password<input type=\"password\" name=\"password\" autocomplete=\"current-password\" autofocus required></label>\
                <button>Log in</button></form>"))
        };
        if req.method != "POST" {
            return form(None, 200);
        }
        match self.auth.login(req.form().get("password").map(String::as_str).unwrap_or("")) {
            Err(e) => form(Some((false, e)), 401),
            Ok(sid) => Resp::redirect("./").header("Set-Cookie", &self.cookie(req, &sid, self.cfg.session_max.as_secs() as i64)),
        }
    }

    // --- POST actions -------------------------------------------------------------------------------

    fn post(&self, req: &Req, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let g = |k: &str| f.get(k).map(|v| v.trim().to_string()).unwrap_or_default();
        let sig = || { let s = g("signature"); if s.is_empty() { g("signature_ext") } else { s } };
        let i = |k: &str| g(k).parse::<i64>().unwrap_or(0);
        let back = |to: &str, r: Result<Value, String>, ok_text: &dyn Fn(&Value) -> String| -> Resp {
            match r {
                Ok(v) if ok_of(&v) => self.flash(ctx, true, ok_text(&v)),
                Ok(v) => self.flash(ctx, false, reason_of(&v)),
                Err(e) => self.flash(ctx, false, e),
            }
            Resp::redirect(to)
        };
        match req.path.as_str() {
            "/play" => self.play_stop(ctx, f),
            "/services" => self.services_post(ctx, f),
            "/sell" if self.cfg.sell => self.sell_post(ctx, f),
            "/sell-hashrate" if self.cfg.sell => self.sell_hashrate_post(ctx, f),
            "/hashrate" => self.hashrate_post(ctx, f),
            "/play-link" => self.play_link(ctx, f),
            "/nostr-check" => self.nostr_check(ctx, f),
            "/connections" => self.connections_stop(ctx, f),
            "/apps-create" => self.apps_create(ctx, f),
            "/apps-revoke" => self.apps_revoke(ctx, f),
            "/logout" => {
                self.auth.logout(&ctx.sid);
                Resp::redirect("./login").header("Set-Cookie", &self.cookie(req, "", 0))
            }
            "/approve" => back("./approvals", self.call("approve", json!({"token": g("token"), "dest": g("dest"), "amount_sats": i("amount_sats"),
                                                                          "expiry": i("expiry"), "signature": sig()})), &|v| {
                if v["granted"] == true {
                    format!("Approved. The agent's Lightning payment to {} will be paid (at most {} sats) when it arrives; approvals expire at {}.",
                            txt(v.get("dest")), int(v.get("amount_sats")), utc(int(v.get("expires"))))
                } else if v["resumed"] == true {
                    "Resumed: the agent may pay over Lightning again, within the policy.".into()
                } else {
                    format!("Approved and paid: {} sats to {} ({}{}).", int(v.get("amount_sats")), txt(v.get("dest")), txt(v.get("rail")),
                            v.get("txid").or(v.get("chan")).map(|t| format!(" {}", txt(Some(t)))).unwrap_or_default())
                }
            }),
            "/deny" => back("./approvals", self.call("deny_approval", json!({"token": g("token"), "reason": g("reason"), "expiry": i("expiry"), "signature": sig()})),
                            &|_| "Denied.".into()),
            "/policy" => self.policy_preview(ctx, f),
            // browsers submit line breaks as CRLF; the signed text is LF only (JSON escapes a CR inside a string)
            "/policy-apply" => back("./policy", self.call("policy_set", json!({"text": f.get("text").map(|t| t.replace("\r\n", "\n")).unwrap_or_default(),
                                                                              "prev_sha256": g("prev_sha256"), "expiry": i("expiry"), "signature": sig()})), &|v| {
                let pr = v.get("pending_restart").and_then(Value::as_array).map(|a| a.iter().map(|x| txt(Some(x))).collect::<Vec<_>>().join(", ")).unwrap_or_default();
                if pr.is_empty() { "Policy applied; it is in force now.".into() } else { format!("Policy applied. These take effect when the signer restarts: {pr}.") }
            }),
            "/human-key-enroll" => back("./setup", self.call("human_key_enroll", json!({"pubkey": g("pubkey"), "code": g("code")})), &|_| "Approval key enrolled.".into()),
            "/human-key-rotate" => back("./keys", self.call("human_key_rotate", json!({"pubkey": g("pubkey"), "expiry": i("expiry"), "signature": sig()})),
                                        &|_| "The new approval key is enrolled; the old one no longer approves anything.".into()),
            "/sweep" => back("./keys", self.call("sweep_hot", json!({"to": g("to"), "amount_sats": i("amount_sats"), "expiry": i("expiry"), "signature": sig()})),
                             &|v| format!("Swept {} sats to {} (txid {}).", int(v.get("swept_sats")), txt(v.get("to")), txt(v.get("txid")))),
            "/rotate" => back("./keys", self.call("rotate_hot_key_signed", json!({"expiry": i("expiry"), "signature": sig()})),
                              &|v| format!("Hot key rotated: new address {}.", txt(v.get("new_address")))),
            "/rotate-token" => {
                if g("confirm") != "1" {
                    self.flash(ctx, false, "tick the box to rotate the agent token");
                    return Resp::redirect("./agents");
                }
                match self.rotate_mcp_token() {
                    Ok(_) => self.flash(ctx, true, "Agent token rotated. Give your agents the new token from this page."),
                    Err(e) => self.flash(ctx, false, e),
                }
                Resp::redirect("./agents")
            }
            "/lightning" => self.lightning_post(ctx, f),
            "/anchor-now" => back("./signatures", self.call("anchor_now", json!({"reason": "operator:ui"})), &|_| "Anchored.".into()),
            "/backup" => {
                if f.get("backup_pass") != f.get("backup_pass2") {
                    self.flash(ctx, false, "the backup passphrases differ");
                    return Resp::redirect("./keys");
                }
                match self.call("backup_export", json!({"expiry": i("expiry"), "signature": sig(), "backup_pass": f.get("backup_pass").cloned().unwrap_or_default()})) {
                    Ok(v) if ok_of(&v) => Resp::text(200, "application/json", txt(v.get("backup_json")))
                        .header("Content-Disposition", &format!("attachment; filename=\"xbt-wallet-backup-{}.json\"", now())),
                    Ok(v) => { self.flash(ctx, false, reason_of(&v)); Resp::redirect("./keys") }
                    Err(e) => { self.flash(ctx, false, e); Resp::redirect("./keys") }
                }
            }
            _ => Resp::text(404, "text/plain", "not found"),
        }
    }

    // --- overview -----------------------------------------------------------------------------------

    /// Home: what the owner can do here, and whether the wallet is ready, in a few lines.
    fn home(&self, ctx: &Ctx) -> Resp {
        let mut b = String::new();
        let human = !self.human_pub().is_empty();
        let ln = self.call("ln_status", json!({})).unwrap_or(json!({}));
        let ready = ln["ready"] == true;
        if !human || !ready {
            b.push_str(&progress(2));
            b.push_str(&format!("<section class=\"card primary\"><h2>Finish setting up</h2><p>{}</p>\
                <p><a class=\"button-link primary\" href=\"./setup\">Continue setup</a></p></section>",
                if !human { "Make your approval key and connect your Lightning node. It takes a few minutes, once." }
                else { "Connect your Lightning node, so the app can pay for services." }));
        }
        let services = self.file_services().unwrap_or_default();
        let sellers = {
            let mut o: Vec<String> = services.iter().filter_map(|s| crate::services::http_origin(&s.seller)).collect();
            o.sort();
            o.dedup();
            o.len()
        };
        let mut cats: Vec<String> = services.iter().map(|s| esc(s.kind.category_words())).collect();
        cats.sort();
        cats.dedup();
        b.push_str("<section class=\"grid home\">");
        b.push_str(&format!("<div class=\"card choice-card\"><h2>Use a service</h2><p>{}</p><p><a class=\"button-link{}\" href=\"./browse\">Browse services</a></p></div>",
            if services.is_empty() { "Pay for what you use, a little at a time: media, AI models, data and more. Add a seller to begin.".to_string() }
            else { format!("{} service{} from {} seller{}: {}.", services.len(), if services.len() == 1 { "" } else { "s" }, sellers,
                           if sellers == 1 { "" } else { "s" }, cats.join(", ")) },
            if human && ready { " primary" } else { "" }));
        if self.cfg.sell {
            let (class, headline, next) = self.sell_summary();
            b.push_str(&format!("<div class=\"card choice-card\"><h2>Sell a service</h2><p><span class=\"pill {class}\">{}</span></p><p>{}</p>\
                <p><a class=\"button-link\" href=\"./sell\">Open Sell</a></p></div>", esc(&headline), esc(&next)));
        }
        b.push_str("</section>");
        let line = if ready {
            let n = int(ln.get("usable_channels"));
            format!("<span class=\"pill good\">Ready to pay</span> Your Lightning node is connected, with {n} channel{} to pay through.", if n == 1 { "" } else { "s" })
        } else if ln["configured"] == true {
            "<span class=\"pill warn\">Not ready</span> Your Lightning node is connected but cannot pay yet. <a href=\"./lightning\">See why</a>".into()
        } else {
            "<span class=\"pill warn\">Not connected</span> Connect your Lightning node to pay for services. <a href=\"./lightning\">Connect it</a>".into()
        };
        b.push_str(&format!("<p class=\"status-line\">{line} · <a href=\"./wallet\">Wallet</a></p>"));
        self.page("Home", ctx, b)
    }

    fn overview(&self, ctx: &Ctx) -> Resp {
        let health = match self.call("health", json!({})) {
            Ok(h) => h,
            Err(e) => return self.page("Wallet", ctx, Self::error_box(&e)),
        };
        let mut b = String::new();
        let bal = self.call("balance", json!({})).unwrap_or(json!({}));
        let hot = bal.get("hot").cloned().unwrap_or(json!({}));
        let approvals = self.call("approvals", json!({})).unwrap_or(json!({}));
        if approvals["human_key"] == false {
            b.push_str("<div class=\"flash warn\">No approval key yet: <a href=\"./setup\">finish the setup</a>.</div>");
        }
        if hot["hot_over_cap"] == true {
            b.push_str("<div class=\"flash warn\">This box holds more than you allowed: <a href=\"./keys\">move the extra to your own wallet</a>.</div>");
        }
        b.push_str("<section class=\"grid\"><div class=\"card\"><h2>Money</h2>");
        b.push_str(&kv(&[("On your node", money(int(bal.get("trusted_sats")))), ("On its way to your node", money(int(bal.get("untrusted_pending_sats")))),
                         ("On this box, for agents", money(int(hot.get("hot_sats")))),
                         ("Most this box may hold", if int(hot.get("hot_cap_sats")) > 0 { money(int(hot.get("hot_cap_sats"))) } else { "no limit".into() }),
                         ("Status", if hot["hot_over_cap"] == true { "<span class=\"pill bad\">Over the limit</span>".into() } else { "<span class=\"pill good\">Within the limit</span>".into() }),
                         ("Keys locked with encryption", if hot["hot_encrypted"] == true { "yes".into() } else { "<span class=\"pill bad\">no</span>".into() })]));
        b.push_str("</div>");
        // on-chain channels are no rail of this wallet; a wallet upgraded with some is shown what they hold
        let chans = bal.get("channels").and_then(Value::as_array).cloned().unwrap_or_default();
        if !chans.is_empty() {
            let mut counts: HashMap<&str, usize> = HashMap::new();
            for c in &chans {
                *counts.entry(state_of(c)).or_default() += 1;
            }
            b.push_str("<div class=\"card\"><h2>Channels of an earlier version</h2>");
            b.push_str(&kv(&[("Open", counts.get("open").copied().unwrap_or(0).to_string()), ("Pending", counts.get("pending").copied().unwrap_or(0).to_string()),
                             ("Closed", counts.get("closed").copied().unwrap_or(0).to_string()), ("Refunded", counts.get("refunded").copied().unwrap_or(0).to_string())]));
            b.push_str("<p><a href=\"./channels\">Old channels →</a></p></div>");
        }
        if let Some(t) = self.cmp_tile() {
            b.push_str(&t);
        }
        b.push_str("</section>");
        if let Ok(h) = self.call("history", json!({"limit": 15})) {
            b.push_str("<h2>Recent activity</h2><div class=\"scroll\"><table><thead><tr><th>When</th><th>What</th><th>To</th><th>Amount</th><th>Detail</th></tr></thead><tbody>");
            let events = h["events"].as_array().cloned().unwrap_or_default();
            if events.is_empty() {
                b.push_str("<tr><td colspan=\"5\" class=\"small\">Nothing yet.</td></tr>");
            }
            for e in events.iter().rev() {
                let what = match e["type"].as_str() {
                    Some("decision") => match e["verdict"].as_str() { Some("allow") => "Allowed".into(), Some("deny") => "Refused".into(),
                                                                       Some("needs_human") => "Asked for your approval".into(), v => format!("Decision: {}", v.unwrap_or("")) },
                    Some(t) => { let t = t.replace('_', " "); let mut c = t.chars(); c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default() }
                    None => String::new(),
                };
                let amt = e.get("amount_sats").map(|a| money(int(Some(a)))).unwrap_or_default();
                b.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{amt}</td><td class=\"small\">{}</td></tr>", utc(int(e.get("ts"))), esc(&what),
                                    esc(&short(&txt(e.get("dest")), 40)), esc(&short(&txt(e.get("reason").or(e.get("txid"))), 80))));
            }
            b.push_str("</tbody></table></div>");
        }
        b.push_str("<details class=\"card\"><summary>Technical details</summary>");
        b.push_str(&kv(&[("Chain", escv(health.get("chain"))), ("Signer", escv(health.get("implementation"))),
                         ("Node wallet", escv(health.get("wallet"))), ("Test mining", escv(health.get("mining")))]));
        b.push_str("</details>");
        self.page("Wallet", ctx, b)
    }

    // --- approvals ----------------------------------------------------------------------------------

    fn approvals(&self, ctx: &Ctx) -> Resp {
        let q = match self.call("approvals", json!({})) {
            Ok(q) => q,
            Err(e) => return self.page("Approvals", ctx, Self::error_box(&e)),
        };
        let human = self.human_pub();
        let mut b = String::from("<p class=\"lead\">Payments at or above the amount you set wait here for you. Approving signs \
            <em>exactly</em> what is shown, with the approval key in this browser.</p>");
        let rows = q["approvals"].as_array().cloned().unwrap_or_default();
        if rows.is_empty() {
            b.push_str("<p class=\"empty\">Nothing waits for you.</p>");
        }
        for a in rows {
            let token = txt(a.get("token"));
            let dest = txt(a.get("dest"));
            let amount = int(a.get("amount_sats"));
            let exp = int(a.get("expires"));
            let kind = txt(a.get("kind"));
            let state = txt(a.get("state"));
            b.push_str(&format!("<article class=\"card approval {}\"><h2>{}</h2>", esc(&state), sats(amount)));
            let mut rows = vec![("To", format!("<code>{}</code>", esc(&dest)))];
            if kind == "ln" {
                rows.push(("Kind", "Lightning payment (paid when the agent asks again for this invoice, at most this amount)".into()));
            } else if kind == "xbt402" {
                rows.push(("Kind", "a call over the on-chain channel, which this wallet no longer has: approving it drops it".into()));
            } else if kind == "ln_resume" {
                rows.push(("Kind", "resume Lightning payments: they are halted because a payment the node recorded late (this amount) \
                                    broke the policy when it was booked. Nothing is paid when you approve; the agent may pay over \
                                    Lightning again, within the policy.".into()));
            } else {
                rows.push(("Kind", "payment (paid as soon as you approve)".into()));
            }
            rows.push(("Agent's memo", escv(a.get("memo"))));
            rows.push(("Requested", utc(int(a.get("ts")))));
            rows.push(("Expires", format!("{} · <span data-expires=\"{exp}\"></span>", utc(exp))));
            b.push_str(&kv(&rows));
            b.push_str(&format!("<details><summary>Details</summary>{}</details>", kv(&[("Request id", format!("<code>{}</code>", esc(&token)))])));
            match state.as_str() {
                "pending" => {
                    let hidden = [("token", token.clone()), ("dest", dest.clone()), ("amount_sats", amount.to_string()), ("expiry", exp.to_string())];
                    b.push_str(&self.signed_form(ctx, "./approve", "approve", &human, &hidden, "", "Approve", Ext::Bytes(msg::approve(&token, &dest, amount, exp))));
                    let sexp = now() + SIGN_WINDOW_S;
                    b.push_str(&self.signed_form(ctx, "./deny", "deny", &human, &[("token", token.clone()), ("expiry", sexp.to_string())],
                        "<input name=\"reason\" placeholder=\"Reason (optional)\" maxlength=\"200\">", "Deny", Ext::Bytes(msg::deny(&token, sexp))));
                }
                "approved" => {
                    let sexp = now() + SIGN_WINDOW_S;
                    b.push_str("<p class=\"tag ok\">Approved: paid when the agent's call arrives.</p>");
                    b.push_str(&self.signed_form(ctx, "./deny", "deny", &human, &[("token", token.clone()), ("expiry", sexp.to_string()), ("reason", "revoked".into())],
                        "", "Revoke", Ext::Bytes(msg::deny(&token, sexp))));
                }
                _ => b.push_str(&format!("<p class=\"tag\">Expired.</p><form method=\"post\" action=\"./deny\">{}<input type=\"hidden\" name=\"token\" value=\"{}\">\
                    <input type=\"hidden\" name=\"reason\" value=\"expired\"><button>Dismiss</button></form>", Self::csrf_input(ctx), esc(&token))),
            }
            b.push_str("</article>");
        }
        self.page("Approvals", ctx, b)
    }

    // --- policy -------------------------------------------------------------------------------------

    /// `eff`: the signer's values in force (defaults included), shown where policy.json leaves a key out.
    fn policy_form(&self, ctx: &Ctx, p: &Value, eff: &Value, errors: &[String], warnings: &[String]) -> String {
        let mut b = String::new();
        if !errors.is_empty() {
            b.push_str("<div class=\"flash bad\"><p>The signer refuses this policy:</p><ul>");
            for e in errors {
                b.push_str(&format!("<li>{}</li>", esc(e)));
            }
            b.push_str("</ul></div>");
        }
        if !warnings.is_empty() {
            b.push_str("<div class=\"flash warn\"><ul>");
            for w in warnings {
                b.push_str(&format!("<li>{}</li>", esc(w)));
            }
            b.push_str("</ul></div>");
        }
        b.push_str(&format!("<form method=\"post\" action=\"./policy\" class=\"policy\">{}<input type=\"hidden\" name=\"mode\" value=\"form\">", Self::csrf_input(ctx)));
        let groups = [("budgets", "Spending limits"), ("human", "Ask me first"), ("velocity", "How fast"), ("hot", "Money on this box"), ("anchor", "Records")];
        for (g, title) in groups {
            if g == "velocity" {
                b.push_str("<details><summary>More rules</summary>");
            }
            b.push_str(&format!("<fieldset><legend>{title}</legend>"));
            for (k, label, grp) in INT_KEYS {
                if grp == g {
                    b.push_str(&format!("<label>{}<input name=\"f_{k}\" value=\"{}\" inputmode=\"numeric\"></label>", esc(label), escv(p.get(k).or(eff.get(k)))));
                }
            }
            if g == "anchor" {
                b.push_str(&format!("<label class=\"check\"><input type=\"checkbox\" name=\"f_anchor_required\" value=\"1\"{}> Refuse to start without the separate record keeper (after a restart)</label>",
                                    if p.get("anchor_required").or(eff.get("anchor_required")) == Some(&Value::Bool(true)) { " checked" } else { "" }));
            }
            b.push_str("</fieldset>");
            if g == "anchor" {
                b.push_str("</details>");
            }
        }
        let allow = p.get("allowlist").and_then(Value::as_array).map(|a| a.iter().map(|x| txt(Some(x))).collect::<Vec<_>>().join("\n")).unwrap_or_default();
        let cps = p.get("counterparties").and_then(Value::as_object).map(|m| m.iter().map(|(k, v)| format!("{k} {}", txt(v.get("ln_node")))).collect::<Vec<_>>().join("\n")).unwrap_or_default();
        b.push_str(&format!("<fieldset><legend>Who may be paid</legend>\
            <label>Sellers agents may pay, one per line: a web address such as <code>https://api.example.net</code>, or a coin address\
            <textarea name=\"f_allowlist\" rows=\"4\">{}</textarea></label>\
            <label>Sellers paid through their Lightning node, one per line: the web address, a space, then the node's id\
            <textarea name=\"f_counterparties\" rows=\"3\">{}</textarea></label></fieldset>\
            <input type=\"hidden\" name=\"f_unseen\" value=\"{}\">\
            <div class=\"row\"><button>Review the change</button> <a class=\"button-link\" href=\"./policy?template=starter\">Start from the safe starter rules</a></div></form>",
            esc(&allow), esc(&cps), esc(&Self::unseen_sections(p).to_string())));
        b.push_str(&format!("<details><summary>Edit the rules as a file (policy.json)</summary><form method=\"post\" action=\"./policy\">{}\
            <input type=\"hidden\" name=\"mode\" value=\"json\"><textarea name=\"json\" rows=\"20\" class=\"mono\">{}</textarea>\
            <button>Review the change</button></form></details>", Self::csrf_input(ctx), esc(&serde_json::to_string_pretty(p).unwrap_or_default())));
        b
    }

    fn policy_page(&self, ctx: &Ctx, template: bool, allow: Option<(&str, &str)>) -> Resp {
        let cur = match self.call("policy_get", json!({})) {
            Ok(v) => v,
            Err(e) => return self.page("Spending rules", ctx, Self::error_box(&e)),
        };
        let mut b = String::from("<p class=\"lead\">The rules the wallet applies to every payment an app or an agent asks for. A change takes \
            effect once you sign it with your approval key. Apps and agents cannot change them.</p>");
        let pr = cur["pending_restart"].as_array().cloned().unwrap_or_default();
        if !pr.is_empty() {
            b.push_str(&format!("<div class=\"flash warn\">Signed but waiting for a signer restart: {}.</div>",
                                esc(&pr.iter().map(|x| txt(Some(x))).collect::<Vec<_>>().join(", "))));
        }
        let mut p = cur["policy"].clone();
        if template {
            let keep = p.clone();
            let chain = self.call("health", json!({})).ok().and_then(|h| h.get("chain").and_then(Value::as_str).map(str::to_string)).unwrap_or_default();
            p = starter_policy(&chain);
            for k in ["allowlist", "counterparties", "human_pubkey"] {
                if let Some(v) = keep.get(k) {
                    p[k] = v.clone();
                }
            }
            b.push_str("<div class=\"flash ok\">The safe starter rules are filled in below (your list of sellers is kept), with paying over \
                        Lightning turned on and low limits. Review them, then sign.</div>");
        }
        // a seller to allow, from the Sellers page: its address on the list, tied to its node
        if let Some((origin, node)) = allow {
            let origin = crate::services::http_origin(origin).unwrap_or_default();
            let node = node.trim().to_ascii_lowercase();
            if !origin.is_empty() && node.len() == 66 && node.bytes().all(|c| c.is_ascii_hexdigit()) {
                let mut list: Vec<Value> = p["allowlist"].as_array().cloned().unwrap_or_default();
                if !list.iter().any(|x| x.as_str().and_then(crate::services::http_origin).as_deref() == Some(origin.as_str())) {
                    list.push(Value::from(origin.clone()));
                }
                p["allowlist"] = Value::from(list);
                if !p["counterparties"].is_object() {
                    p["counterparties"] = json!({});
                }
                p["counterparties"][origin.as_str()] = json!({"ln_node": node});
                let cap = p.get("per_counterparty_cap_sats").or(cur["effective"].get("per_counterparty_cap_sats")).and_then(Value::as_i64).unwrap_or(0);
                b.push_str(&format!("<div class=\"flash ok\"><p><strong>Allow {} to be paid.</strong> Sign below with your approval key. \
                    The app may then pay this seller up to {} in any 7 days, within your other limits.</p></div>", esc(&origin), money(cap)));
            }
        }
        let errs: Vec<String> = cur["errors"].as_array().map(|a| a.iter().map(|x| txt(Some(x))).collect()).unwrap_or_default();
        let warns: Vec<String> = cur["warnings"].as_array().map(|a| a.iter().map(|x| txt(Some(x))).collect()).unwrap_or_default();
        b.push_str(&self.policy_form(ctx, &p, &cur["effective"], &errs, &warns));
        b.push_str(&format!("<p class=\"small\">policy.json SHA-256 <code>{}</code></p>", escv(cur.get("sha256"))));
        self.page("Spending rules", ctx, b)
    }

    /// The sections of `p` the form has no field for (the Lightning and ticket settings, and any key
    /// this page does not know): the form carries them as they are, so that signing the form signs
    /// them too. The approval key is never among them: it is the signer's own, and kept from the
    /// current policy.
    fn unseen_sections(p: &Value) -> Value {
        let mut m = p.as_object().cloned().unwrap_or_default();
        for (k, _, _) in INT_KEYS {
            m.remove(k);
        }
        for k in ["anchor_required", "allowlist", "counterparties", "human_pubkey"] {
            m.remove(k);
        }
        Value::Object(m)
    }

    /// The form's fields on top of the current policy. Unknown keys are kept, and the sections the
    /// form carried unseen (the starter rules' Lightning and ticket settings) are put back: a form
    /// signs every section it was shown with, never fewer.
    fn proposed_from_form(cur: &Value, f: &HashMap<String, String>) -> Value {
        let mut p = cur.as_object().cloned().unwrap_or_default();
        if let Some(Value::Object(unseen)) = f.get("f_unseen").and_then(|s| serde_json::from_str::<Value>(s).ok()) {
            for (k, v) in unseen {
                if k != "human_pubkey" {
                    p.insert(k, v);
                }
            }
        }
        let num = |s: &str| -> Value { s.trim().parse::<i64>().map(Value::from).unwrap_or_else(|_| Value::from(s.trim())) };
        for (k, _, _) in INT_KEYS {
            if let Some(v) = f.get(&format!("f_{k}")) {
                p.insert(k.into(), num(v));
            }
        }
        p.insert("anchor_required".into(), Value::Bool(f.contains_key("f_anchor_required")));
        let lines = |k: &str| -> Vec<String> { f.get(k).map(|v| v.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()).unwrap_or_default() };
        p.insert("allowlist".into(), Value::from(lines("f_allowlist")));
        let old_cp = cur.get("counterparties").and_then(Value::as_object).cloned().unwrap_or_default();
        let mut cps = Map::new();
        for l in lines("f_counterparties") {
            let mut it = l.split_whitespace();
            let (Some(origin), node) = (it.next(), it.next().unwrap_or("")) else { continue };
            let mut e = old_cp.get(origin).and_then(Value::as_object).cloned().unwrap_or_default();
            // the payTo key of an on-chain channel: that rail was removed and the signer ignores the key
            e.remove("pay_to");
            if node.is_empty() {
                e.remove("ln_node");
            } else {
                e.insert("ln_node".into(), node.into());
            }
            cps.insert(origin.into(), Value::Object(e));
        }
        p.insert("counterparties".into(), Value::Object(cps));
        // the section of the retired hub routing and the settings of the removed on-chain channel: the
        // signer ignores them, so the form leaves them out
        for k in ["routing", "channel_expiry_blocks", "refund_enabled", "refund_margin_blocks", "open_wait_s", "open_retry_s", "close_fee_max_sats", "channel_rail"] {
            p.remove(k);
        }
        Value::Object(p)
    }

    fn policy_preview(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let cur = match self.call("policy_get", json!({})) {
            Ok(v) => v,
            Err(e) => return self.page("Spending rules", ctx, Self::error_box(&e)),
        };
        let proposed = if f.get("mode").map(String::as_str) == Some("json") {
            match serde_json::from_str::<Value>(f.get("json").map(String::as_str).unwrap_or("")) {
                Ok(v) => v,
                Err(e) => {
                    let body = self.policy_form(ctx, &cur["policy"], &cur["effective"], &[format!("policy.json: {e}")], &[]);
                    return self.page("Spending rules", ctx, body);
                }
            }
        } else {
            Self::proposed_from_form(&cur["policy"], f)
        };
        let prep = match self.call("policy_prepare", json!({"policy": proposed})) {
            Ok(v) => v,
            Err(e) => return self.page("Spending rules", ctx, Self::error_box(&e)),
        };
        let strs = |k: &str| -> Vec<String> { prep[k].as_array().map(|a| a.iter().map(|x| txt(Some(x))).collect()).unwrap_or_default() };
        if prep["ok"] != true {
            let body = self.policy_form(ctx, &proposed, &cur["effective"], &strs("errors"), &strs("warnings"));
            return self.page("Spending rules", ctx, body);
        }
        let mut b = String::from("<p>Check the change, then sign it with your approval key. The signer writes exactly the text below.</p>");
        let diff = prep["diff"].as_array().cloned().unwrap_or_default();
        if diff.is_empty() {
            b.push_str("<p class=\"empty\">No change.</p>");
        } else {
            b.push_str("<div class=\"scroll\"><table><thead><tr><th>Setting</th><th>Now</th><th>New</th><th></th></tr></thead><tbody>");
            for d in &diff {
                b.push_str(&format!("<tr><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>", escv(d.get("key")),
                                    esc(&short(&d.get("old").map(|v| v.to_string()).unwrap_or_else(|| "(none)".into()), 200)),
                                    esc(&short(&d.get("new").map(|v| v.to_string()).unwrap_or_else(|| "(none)".into()), 200)),
                                    if d["restart"] == true { "<span class=\"tag warn\">after restart</span>" } else { "" }));
            }
            b.push_str("</tbody></table></div>");
        }
        let w = strs("warnings");
        if !w.is_empty() {
            b.push_str("<div class=\"flash warn\"><ul>");
            for x in w {
                b.push_str(&format!("<li>{}</li>", esc(&x)));
            }
            b.push_str("</ul></div>");
        }
        if prep["human_key"] != true {
            b.push_str("<div class=\"flash bad\">No approval key is enrolled: <a href=\"./setup\">set one up</a> before you can sign a policy.</div>");
        }
        let text = txt(prep.get("text"));
        let prev = txt(prep.get("prev_sha256"));
        let exp = int(prep.get("expiry"));
        let visible = format!("<details open><summary>The policy you sign</summary><pre class=\"signed-text\">{}</pre></details>", esc(&text));
        b.push_str(&self.signed_form(ctx, "./policy-apply", "policy", &self.human_pub(),
                                     &[("text", text.clone()), ("prev_sha256", prev.clone()), ("expiry", exp.to_string())], &visible,
                                     "Sign and apply", Ext::Bytes(msg::policy(&prev, exp, &text))));
        b.push_str("<p><a href=\"./policy\">Cancel</a></p>");
        self.page("Spending rules", ctx, b)
    }

    // --- channels -----------------------------------------------------------------------------------

    /// What an earlier version's on-chain channels left: read-only. This wallet opens, pays, closes
    /// and refunds none.
    fn channels(&self, ctx: &Ctx) -> Resp {
        let ch = match self.call("channels", json!({})) {
            Ok(v) => v,
            Err(e) => return self.page("Old channels", ctx, Self::error_box(&e)),
        };
        let reps = self.call("channel_reports", json!({})).unwrap_or(json!({}));
        let height = int(ch.get("height"));
        let mut b = format!("<p>This wallet pays over Lightning and no longer has an on-chain channel: it opens, pays, closes and refunds none. \
                             This page lists what an earlier version of the wallet left. Tip height {height}.</p>");
        if let Some(todo) = ch.pointer("/legacy_channels/what_to_do").and_then(Value::as_str) {
            b.push_str(&format!("<div class=\"flash warn\">{}</div>", esc(todo)));
        }
        let list = ch["channels"].as_array().cloned().unwrap_or_default();
        if list.is_empty() {
            b.push_str("<p class=\"empty\">No channels.</p>");
        }
        for c in list.iter().rev() {
            let st = state_of(c);
            let chan = txt(c.get("chan"));
            let dest = txt(c.get("dest"));
            b.push_str(&format!("<article class=\"card chan\"><h2><span class=\"tag {}\">{st}</span> {}</h2>", if st == "open" || st == "pending" { "warn" } else { "" },
                                esc(&txt(c.get("origin")).chars().next().map(|_| txt(c.get("origin"))).unwrap_or(dest.clone()))));
            let mut rows = vec![("Channel", format!("<code>{}</code>", esc(&chan))), ("Capacity", sats(int(c.get("cap_sats")))),
                                ("Paid (signed state)", sats(int(c.get("used_sats")))), ("Expiry", format!("block {}", int(c.get("expiry"))))];
            for (k, label) in [("funding_txid", "Funding"), ("closed_txid", "Close")] {
                if let Some(t) = c.get(k).and_then(Value::as_str) {
                    rows.push((label, format!("<code>{}</code>", esc(t))));
                }
            }
            if let Some(r) = reps.pointer(&format!("/reports/{}", chan.replace('~', "~0").replace('/', "~1"))) {
                let rep = &r["report"];
                let mut t = format!("<span class=\"tag {}\">{}</span> provider cum {}, unpaid {} msat", if rep["status"] == "ok" { "ok" } else { "bad" },
                                    escv(rep.get("status")), escv(rep.get("cum")), escv(rep.get("unpaid_msat")));
                if rep.get("payee_fee").is_some() {
                    t.push_str(&format!(", payeeFee {} (the provider's own close fee), payeeNet {}", escv(rep.get("payee_fee")), escv(rep.get("payee_net"))));
                }
                rows.push(("Close report", t));
            }
            b.push_str(&kv(&rows));
            b.push_str("</article>");
        }
        self.page("Old channels", ctx, b)
    }

    // --- signatures ---------------------------------------------------------------------------------

    fn signatures(&self, ctx: &Ctx) -> Resp {
        let s = match self.call("signatures", json!({"limit": 200})) {
            Ok(v) => v,
            Err(e) => return self.page("Records", ctx, Self::error_box(&e)),
        };
        let a = &s["anchor"];
        let mut b = String::from("<p class=\"lead\">A tamper-evident record of every payment and change the wallet signed. A separate \
            record keeper seals it from time to time, so a record changed afterwards fails the check below.</p>");
        let chain_ok = s["chain_ok"] == true;
        b.push_str(&kv(&[
            ("Log check", if chain_ok { "<span class=\"tag ok\">chain intact, matches the anchor</span>".into() }
                          else { format!("<span class=\"tag bad\">FAILED</span> {}", esc(&s["chain"].to_string())) }),
            ("Anchor witness", if a["enabled"] == true { "enabled".into() } else { "<span class=\"tag warn\">not configured</span>".into() }),
            ("Anchored lines", escv(a.get("anchored_n"))), ("Log lines", escv(a.get("log_lines"))),
            ("Not yet anchored", escv(a.get("unanchored_lines"))), ("Last anchor", utc(int(a.get("anchored_at")))),
            ("Anchored head", format!("<code>{}</code>", esc(&short(&txt(a.get("anchored_head")), 20)))),
        ]));
        if let Some(e) = s.get("chain").and_then(|c| c.get("anchor_error")).or(s.get("anchor_error")) {
            b.push_str(&Self::error_box(&txt(Some(e))));
        }
        b.push_str(&format!("<form method=\"post\" action=\"./anchor-now\">{}<button class=\"secondary\">Seal the record now</button></form>", Self::csrf_input(ctx)));
        b.push_str("<div class=\"scroll\"><table><thead><tr><th>When</th><th>Kind</th><th>Authorised by</th><th>Method</th><th>Destination</th><th>Signature hash</th></tr></thead><tbody>");
        for e in s["signatures"].as_array().cloned().unwrap_or_default().iter().rev() {
            b.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>", utc(int(e.get("ts"))),
                                escv(e.get("kind")), escv(e.get("rule")), escv(e.get("method")), esc(&short(&txt(e.get("dest")), 40)),
                                esc(&short(&txt(e.get("sig_sha256")), 16))));
        }
        b.push_str("</tbody></table></div>");
        self.page("Records", ctx, b)
    }

    // --- keys ---------------------------------------------------------------------------------------

    fn keygen_block(&self, ctx: &Ctx, enroll: bool) -> String {
        // the box hands the setup page the signer's one-time code (`XBT_UI_ENROLL_CODE_FILE`): nothing to read in a log
        let given = self.cfg.enroll_code_file.as_ref().and_then(|p| std::fs::read_to_string(p).ok()).map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty() && c.len() <= 64 && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        let enroll_form = if enroll {
            let code_field = match &given {
                Some(c) => format!("<input type=\"hidden\" name=\"code\" value=\"{}\">", esc(c)),
                None => "<label>Enrolment code<input name=\"code\" class=\"mono\" autocomplete=\"off\" required placeholder=\"XXXX-XXXX-XXXX\"></label>\
                     <p class=\"hint\">The signer prints a one-time code in its log while no key is enrolled (Umbrel: the app's log; StartOS: Logs; \
                     a server: the signer's stderr or <code>.run/enroll-code</code>).</p>".to_string(),
            };
            format!("<form method=\"post\" action=\"./human-key-enroll\" id=\"enroll-form\" hidden>{}<input type=\"hidden\" name=\"pubkey\" value=\"\">\
                     {code_field}<button>{}</button></form>", Self::csrf_input(ctx),
                    if given.is_some() { "Use this key for approvals" } else { "Enrol this public key with the signer" })
        } else {
            String::new()
        };
        format!("<div id=\"keygen\" class=\"card\"><h3>An approval key in this browser</h3>\
            <p>The key is made here and never sent to the box; only its public half is. It is kept in this browser's storage, \
            encrypted under a passphrase. Write the backup down: it is the only copy.</p>\
            <p><button type=\"button\" id=\"keygen-new\">Make a new key</button></p>\
            <details><summary>…or restore a key from its backup</summary><input id=\"keygen-import-hex\" class=\"mono\" placeholder=\"64 hex characters\" autocomplete=\"off\">\
            <button type=\"button\" id=\"keygen-import\">Use this key</button></details>\
            <div id=\"keygen-step2\" hidden><p>Your key's backup. It is the only copy: keep it somewhere safe, off this computer \
            (a USB stick in a drawer, or written on paper).</p><pre id=\"keygen-backup\" class=\"hex\"></pre>\
            <p><button type=\"button\" id=\"keygen-download\" class=\"secondary\">Download the backup file</button></p>\
            <label class=\"check\"><input type=\"checkbox\" id=\"keygen-saved\"> I saved the backup somewhere safe</label>\
            <details><summary>…or confirm by typing its last 8 characters</summary><label>Last 8 characters<input id=\"keygen-confirm\" autocomplete=\"off\"></label></details>\
            <label>Passphrase for this browser (at least 12 characters, not only digits or a repeated pattern)\
            <input id=\"keygen-pin\" type=\"password\" autocomplete=\"new-password\" minlength=\"12\"></label>\
            <p id=\"keygen-strength\" class=\"hint\" aria-live=\"polite\">At least 12 characters, not only digits, not a repeated pattern.</p>\
            <label>Passphrase again<input id=\"keygen-pin2\" type=\"password\" autocomplete=\"new-password\" minlength=\"12\"></label>\
            <button type=\"button\" id=\"keygen-save\">Save the key in this browser</button></div>\
            <p id=\"keygen-msg\" class=\"msg\" aria-live=\"polite\"></p>{enroll_form}\
            <p><button type=\"button\" id=\"keygen-forget\" class=\"link\">Remove the key from this browser</button></p></div>")
    }

    fn keys(&self, ctx: &Ctx) -> Resp {
        let ks = match self.call("keystore_status", json!({})) {
            Ok(v) => v,
            Err(e) => return self.page("Keys and backup", ctx, Self::error_box(&e)),
        };
        let human = txt(ks.get("human_pubkey"));
        let hot = &ks["hot"];
        let hot_addr = txt(hot.get("hot_address"));
        let exp = now() + SIGN_WINDOW_S;
        let mut b = format!("<section class=\"card\" id=\"human-key-state\" data-enrolled=\"{}\"><h2>Your approval key</h2>", esc(&human));
        b.push_str(&kv(&[("Enrolled public key", if human.is_empty() { "<span class=\"tag bad\">none</span>".into() } else { format!("<code>{}</code>", esc(&human)) })]));
        b.push_str("<p id=\"browser-key\" class=\"msg\"></p>");
        if human.is_empty() {
            b.push_str(&self.keygen_block(ctx, true));
        } else {
            b.push_str("<details><summary>Put the enrolled key in this browser (from its backup)</summary>");
            b.push_str(&self.keygen_block(ctx, false));
            b.push_str("</details><details><summary>Replace the approval key</summary><p>A new key is made in this browser, and the \
                current one signs the handover. The new key is kept under the same passphrase; write its backup down from the key page afterwards.</p>");
            b.push_str(&self.signed_form(ctx, "./human-key-rotate", "human-key", &human, &[("old_pub", human.clone()), ("pubkey", String::new()),
                                         ("expiry", exp.to_string())], "", "Make a new key and hand over", Ext::Browser));
            b.push_str("</details>");
        }
        b.push_str("</section>");
        b.push_str("<section class=\"card\"><h2>Money on this box, for agents</h2>");
        b.push_str(&kv(&[("Address", format!("<code>{}</code>", esc(&hot_addr))), ("Balance", sats(int(hot.get("hot_sats")))),
                         ("Cap", if int(hot.get("hot_cap_sats")) > 0 { sats(int(hot.get("hot_cap_sats"))) } else { "none".into() }),
                         ("Retired keys", escv(hot.get("hot_retired_keys")))]));
        b.push_str("<h3>Sweep to your own wallet</h3>");
        b.push_str(&self.signed_form(ctx, "./sweep", "sweep", &human, &[("hot_address", hot_addr.clone()), ("expiry", exp.to_string())],
            "<label>To address<input name=\"to\" class=\"mono\" autocomplete=\"off\" required></label>\
             <label>Amount (sats)<input name=\"amount_sats\" inputmode=\"numeric\" required></label>",
            "Sign and sweep",
            Ext::Lines(format!("xbt-agentwallet-hot-sweep-v1\n{hot_addr}\n<to address>\n<amount in sats>\n{exp}"))));
        b.push_str("<h3>Replace this key</h3><p>A new key for the money on this box; the coins on the old one move to it.</p>");
        b.push_str(&self.signed_form(ctx, "./rotate", "rotate", &human, &[("hot_address", hot_addr.clone()), ("expiry", exp.to_string())], "",
                                     "Sign and rotate", Ext::Bytes(msg::rotate(&hot_addr, exp))));
        b.push_str("</section>");
        b.push_str("<section class=\"card\"><h2>Encryption and backup</h2>");
        b.push_str(&kv(&[("Keys encrypted at rest", if ks["encrypted"] == true { "yes".into() } else { "<span class=\"tag bad\">no (test mode)</span>".into() }),
                         ("Wrapping key", match ks["kdf"].as_str() { Some("keyfile") => "a key file".into(), Some("scrypt") => "a passphrase".into(), _ => "none".into() }),
                         ("Key file", escv(ks.get("keyfile"))),
                         ("Key file mode", match ks["keyfile_mode"].as_str() { Some("600") | Some("400") => format!("{} <span class=\"tag ok\">private</span>", escv(ks.get("keyfile_mode"))),
                                                                             Some(m) => format!("{} <span class=\"tag bad\">readable by others</span>", esc(m)), None => "-".into() })]));
        b.push_str("<p>The backup holds the policy, the sealed keys, the channel book and the logs, plus the wrapping key sealed under the \
                    passphrase you choose here. Without that passphrase it opens nothing.</p>");
        b.push_str(&self.signed_form(ctx, "./backup", "backup", &human, &[("hot_address", hot_addr.clone()), ("expiry", exp.to_string())],
            "<label>Backup passphrase (at least 12 characters)<input name=\"backup_pass\" type=\"password\" autocomplete=\"new-password\" required></label>\
             <label>Again<input name=\"backup_pass2\" type=\"password\" autocomplete=\"new-password\" required></label>",
            "Sign and download the backup", Ext::Bytes(msg::backup(&hot_addr, exp))));
        b.push_str("</section>");
        self.page("Keys and backup", ctx, b)
    }

    // --- setup ------------------------------------------------------------------------------

    /// How an agent connects: the MCP endpoint and its bearer token (AGP-040). A box has no terminal, so
    /// this page is where the owner gets them. The token lets an agent pay allowlisted services within the
    /// policy and below the human threshold; it cannot approve, change the policy or move keys.
    fn agents(&self, ctx: &Ctx) -> Resp {
        let mut b = String::from("<p class=\"lead\">Let an AI agent pay for services on its own, within your spending rules. It cannot approve \
            payments, change your rules or move your money. (For other apps, such as a phone wallet, see <a href=\"./apps\">Apps</a>.)</p>\
            <section class=\"card\"><h2>Connect an agent</h2>");
        let urls = &self.cfg.mcp_urls;
        let token = std::fs::read_to_string(&self.cfg.mcp_token_file).ok().map(|t| t.trim().to_string()).filter(|t| !t.is_empty());
        match &token {
            None => b.push_str("<p class=\"empty\">Agents can't connect yet: the app has not made their access key. It does this when it starts; \
                                restart the app if this stays.</p>"),
            Some(_) => b.push_str("<p>Give your agent the address and the access key below. Treat the key like a card with a spending limit: \
                                   anyone who holds it can pay what your rules allow.</p>"),
        }
        if let Some(u) = urls.first() {
            b.push_str(&format!("<label>Agent address<input readonly class=\"mono\" value=\"{}\"></label>", esc(u)));
        }
        let mut details = String::new();
        if urls.is_empty() {
            details.push_str("<p>No address is set for this page (<code>XBT_UI_MCP_URL</code>). The agent server (MCP) listens on port 33510 at <code>/mcp</code>.</p>");
        } else if urls.len() > 1 {
            details.push_str("<p>Other addresses:</p><ul>");
            for u in &urls[1..] {
                details.push_str(&format!("<li><code>{}</code></li>", esc(u)));
            }
            details.push_str("</ul>");
        }
        match token {
            None => details.push_str(&format!("<p>No token in <code>{}</code>. The box's installer copies it from the agent server on start.</p>",
                                              esc(&self.cfg.mcp_token_file.display().to_string()))),
            Some(t) => {
                let url = urls.first().cloned().unwrap_or_else(|| "http://<this box>:33510/mcp".into());
                let snippet = json!({"mcpServers": {"xbt-wallet": {"type": "http", "url": url, "headers": {"Authorization": format!("Bearer {t}")}}}});
                b.push_str(&format!("<details><summary>Show the access key</summary><p><code id=\"mcp-token\">{}</code></p>\
                                     <p>A configuration to paste into an agent that speaks MCP:</p>{}</details>", esc(&t), json_block(&snippet)));
                b.push_str(&format!("<form method=\"post\" action=\"./rotate-token\" class=\"stack\">{}<h3>Replace the access key</h3><p>If the key \
                    leaked, replace it here. Every agent loses access until you give it the new one.</p>\
                    <label class=\"check\"><input type=\"checkbox\" name=\"confirm\" value=\"1\" required> I will give my agents the new key</label>\
                    <button type=\"submit\" class=\"secondary\">Rotate the token</button></form>", Self::csrf_input(ctx)));
            }
        }
        b.push_str(&format!("<details><summary>Technical details</summary>{details}</details>"));
        b.push_str("</section>");
        self.page("AI agents", ctx, b)
    }

    /// Replace the MCP bearer token (AGP-042). The UI owns the token file and the MCP only reads it, on
    /// every request, so the old token stops working at once. The MCP is never asked: rotation must not be
    /// reachable with the token it replaces, and the new token goes nowhere but this file and this page.
    fn rotate_mcp_token(&self) -> Result<(), String> {
        let p = &self.cfg.mcp_token_file;
        let md = std::fs::symlink_metadata(p).map_err(|e| format!("read token: {e}"))?;
        if !md.file_type().is_file() {
            return Err("the token file is not a regular file".into());
        }
        // keep the mode xbt-init gave it (0640 on a box: the MCP reads it by group), never a bit for others
        let mode = mode_bits(&md) & 0o640;
        let new = hex::encode(crate::random_bytes::<32>());
        xbt_svc::replace_secret_file(p, format!("{new}\n").as_bytes(), mode | 0o600).map_err(|e| format!("{}: {e}", p.display()))
    }

    /// xbt-compute's node: a link to its status page and, when a status URL is set, a
    /// compact tile from its JSON (CONTRACT §U: `/healthz`, `/readyz`, JSON status with node sync %).
    /// The JSON has no fixed schema yet, so the tile shows the common fields and folds the rest.
    fn cmp_tile(&self) -> Option<String> {
        if self.cfg.cmp_url.is_none() && self.cfg.cmp_status_url.is_none() {
            return None;
        }
        let mut b = String::from("<div class=\"card\" id=\"cmp-status\"><h2>XBT Compute</h2>");
        if let Some(u) = &self.cfg.cmp_status_url {
            match http_get(u) {
                Ok((st, body)) => {
                    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                    let up = st == 200 && v.get("ok") != Some(&Value::Bool(false)) && v.get("ready") != Some(&Value::Bool(false));
                    let rows = vec![("Status", format!("<span class=\"tag {}\">{}</span> HTTP {st}", if up { "ok" } else { "bad" }, if up { "up" } else { "not ready" }))];
                    let mut extra: Vec<(String, String)> = vec![];
                    if let Some(m) = v.as_object() {
                        for (k, x) in m {
                            let kl = k.to_ascii_lowercase();
                            if (kl.contains("sync") || ["role", "version", "chain", "height", "ready", "ok", "mode"].contains(&kl.as_str())) && !x.is_object() && !x.is_array() {
                                extra.push((k.clone(), esc(&short(&txt(Some(x)), 80))));
                            }
                        }
                    }
                    let mut html = kv(&rows);
                    if !extra.is_empty() {
                        html.push_str(&kv(&extra.iter().map(|(k, v)| (k.as_str(), v.clone())).collect::<Vec<_>>()));
                    }
                    b.push_str(&html);
                    if !v.is_null() {
                        b.push_str(&format!("<details><summary>Status JSON</summary>{}</details>", json_block(&v)));
                    }
                }
                Err(e) => b.push_str(&format!("<p><span class=\"tag bad\">unreachable</span> {}</p>", esc(&e))),
            }
        }
        if let Some(l) = &self.cfg.cmp_url {
            b.push_str(&format!("<p><a href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\">Node status →</a></p>", esc(l)));
        }
        b.push_str("</div>");
        Some(b)
    }

    fn setup(&self, ctx: &Ctx) -> Resp {
        let ks = match self.call("keystore_status", json!({})) {
            Ok(v) => v,
            Err(e) => return self.page("Setup", ctx, Self::error_box(&e)),
        };
        let pol = self.call("policy_get", json!({})).unwrap_or(json!({}));
        let hist = self.call("history", json!({"limit": 5000})).unwrap_or(json!({}));
        let events = hist["events"].as_array().cloned().unwrap_or_default();
        let seen = |t: &str| events.iter().any(|e| e["type"] == t);
        let human = txt(ks.get("human_pubkey"));
        let allow_n = pol["policy"]["allowlist"].as_array().map(|a| a.len()).unwrap_or(0);
        let step = |done: bool, title: &str, body: String| {
            format!("<li class=\"step {}\"><h2>{}</h2>{body}</li>", if done { "done" } else { "todo" }, esc(title))
        };
        let ln = self.call("ln_status", json!({})).unwrap_or(json!({}));
        let enc = ks["encrypted"] == true;
        let done = [true, !human.is_empty(), seen("policy_change"), ln["ready"] == true, enc && seen("backup_export")];
        let n = done.iter().filter(|d| **d).count();
        let mut b = progress(if n == done.len() { 3 } else { 2 });
        b.push_str(&format!("<p class=\"lead\">{n} of {} done. The app is safe to leave running after each step: nothing is paid until your rules allow it.</p><ol class=\"steps\">",
                            done.len()));
        b.push_str(&step(true, "Password", if self.platform.is_some() {
            "<p>Not needed: you opened the app from your box's dashboard, which already asked who you are.</p>".into()
        } else {
            "<p>Set. You are logged out after 15 minutes without use.</p>".into()
        }));
        let key_body = if human.is_empty() {
            format!("<p>Your approval key is how you say yes to a large payment or a change of rules. It is made and kept in this browser, \
                     under a passphrase only you know.</p><section id=\"human-key-state\" data-enrolled=\"\"><p id=\"browser-key\" class=\"msg\"></p>{}</section>",
                    self.keygen_block(ctx, true))
        } else {
            format!("<section id=\"human-key-state\" data-enrolled=\"{}\"><p>Made and enrolled.</p><p id=\"browser-key\" class=\"msg\"></p>\
                     <details><summary>Its public half</summary><p><code>{}</code></p></details>\
                     <p><a href=\"./keys\">Keys and backup →</a></p></section>", esc(&human), esc(&human))
        };
        b.push_str(&step(done[1], "Your approval key", key_body));
        b.push_str(&step(done[2], "Your spending rules",
            format!("<p>How much may be spent, and when the app asks you first. The safe starter rules are a good start: {} seller{} allowed now.</p>\
                     <p><a href=\"./policy?template=starter\">Open the starter rules →</a></p>", allow_n, if allow_n == 1 { "" } else { "s" })));
        b.push_str(&step(done[3], "Your Lightning node",
            format!("<p>{}</p><p><a href=\"./lightning\">Your node →</a></p>",
                    if done[3] { "Connected and ready to pay.".to_string() }
                    else { format!("Not ready yet: {}", esc(&txt(ln.get("reason").or(ln.get("config_error"))))) })));
        b.push_str(&step(done[4], "A backup",
            format!("<p>The app's keys are {} on this box. {}</p><p><a href=\"./keys\">Download an encrypted backup →</a></p>",
                    if enc { "locked with encryption" } else { "<strong>not</strong> locked with encryption" },
                    if seen("backup_export") { "A backup was exported." } else { "No backup yet." })));
        b.push_str("</ol>");
        self.page("Setup", ctx, b)
    }
}

/// A failed play in plain words and the next step: (what happened, link text, link). From the
/// connector's answer: the wallet's refusal (`402`, with its `rule` and reason) or an error.
pub fn play_error_words(status: u16, v: &Value) -> (String, String, String) {
    let rule = v["rule"].as_str().unwrap_or("").to_ascii_lowercase();
    let why = v["error"].as_str().unwrap_or("").to_ascii_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| rule.contains(w) || why.contains(w));
    let (h, l, href) = if why.starts_with("the connector") {
        ("The app's player part isn't answering. Restart the app from your box's dashboard.", "See live connections", "./connections")
    } else if has(&["human_key", "enrol", "no policy", "policy is not"]) {
        ("Your wallet isn't set up yet.", "Finish setup", "./setup")
    } else if has(&["allowlist", "not named", "unlisted", "listed", "not allowed"]) {
        ("Payment refused by your spending rules: this seller is not allowed yet.", "Allow this seller", "./services")
    } else if has(&["budget", "cap", "velocity", "max_sats", "limit", "threshold"]) {
        ("Payment refused: your spending limit is reached.", "See your spending rules", "./policy")
    } else if has(&["balance", "liquidity", "insufficient", "no route", "no_route", "unable to find a path", "outbound"]) {
        ("Not enough balance to pay: your node has no way to send this much.", "See your wallet", "./wallet")
    } else if has(&["ln_unavailable", "ln_disabled", "ln_config", "ln_halted", "no_rail", "mainnet", "macaroon", "not ready"]) {
        ("Your wallet can't pay yet: your Lightning node isn't ready.", "Check your node", "./lightning")
    } else if status == 504 || has(&["sent nothing", "did not answer", "could not reach", "timed out", "unreachable", "connection refused"]) {
        ("The seller didn't answer. Try again in a moment.", "See your sellers", "./services")
    } else if status == 401 {
        ("You were logged out. Log in and press play again.", "Log in", "./login")
    } else {
        return (format!("This didn't play: {}.", v["error"].as_str().unwrap_or("the payment did not go through").trim_end_matches('.')),
                "See live connections".into(), "./connections".into());
    };
    (h.into(), l.into(), href.into())
}

/// `?k=v&...` for a redirect back to the same page (empty when there is no query).
fn query_string(q: &HashMap<String, String>) -> String {
    if q.is_empty() {
        return String::new();
    }
    let mut kv: Vec<_> = q.iter().collect();
    kv.sort();
    format!("?{}", kv.iter().map(|(k, v)| format!("{}={}", crate::services::urlenc(k), crate::services::urlenc(v))).collect::<Vec<_>>().join("&"))
}

/// An amount as the pages show money: sats, in the money colour.
pub(crate) fn money(n: i64) -> String {
    format!("<span class=\"money\">{}</span>", sats(n))
}

/// The first run's three steps, with `now` (1 to 3) the one the owner is on.
pub(crate) fn progress(now: usize) -> String {
    let mut b = String::from("<ol class=\"progress\" aria-label=\"Getting started\">");
    for (i, name) in ["Password", "Your approval key and rules", "Ready"].iter().enumerate() {
        let n = i + 1;
        let class = if n < now { "done" } else if n == now { "now" } else { "" };
        b.push_str(&format!("<li class=\"{class}\"{}><span>{n}</span> {name}</li>", if n == now { " aria-current=\"step\"" } else { "" }));
    }
    b.push_str("</ol>");
    b
}

#[cfg(unix)]
fn mode_bits(md: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    md.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn mode_bits(_: &std::fs::Metadata) -> u32 {
    0o600
}

/// A plain-HTTP GET with a short timeout (the status page is on the box's own network).
pub fn http_get(url: &str) -> Result<(u16, String), String> {
    use std::io::{Read, Write};
    let rest = url.strip_prefix("http://").ok_or("only http:// URLs are probed")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let addr = std::net::ToSocketAddrs::to_socket_addrs(&if hostport.contains(':') { hostport.to_string() } else { format!("{hostport}:80") })
        .map_err(|e| e.to_string())?.next().ok_or("no address")?;
    let t = std::time::Duration::from_secs(3);
    let mut s = std::net::TcpStream::connect_timeout(&addr, t).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(t)).ok();
    s.write_all(format!("GET {path} HTTP/1.0\r\nHost: {hostport}\r\nConnection: close\r\n\r\n").as_bytes()).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    s.take(64 * 1024).read_to_end(&mut buf).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    Ok((status, body))
}

/// AGP-063 W4: a Host this UI answers to. An absent one (no browser sends none), an IP literal, a
/// single-label name (`localhost`, a container name behind the box's proxy), `*.local`,
/// `*.localhost`, `*.onion`, or one of `XBT_UI_ALLOWED_HOSTS`. Any other name points a public DNS
/// name at this box's address: a rebinding page that would read the UI.
pub fn host_allowed(host: &str, allowed: &[String]) -> bool {
    let h = host.trim().to_ascii_lowercase();
    if h.is_empty() || allowed.iter().any(|a| a == "*") {
        return true;
    }
    let name = match h.strip_prefix('[') {
        Some(r) => return r.split(']').next().is_some_and(|ip| ip.parse::<std::net::Ipv6Addr>().is_ok()),
        None => h.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map(|(n, _)| n).unwrap_or(&h),
    };
    let name = name.trim_end_matches('.');
    name.parse::<std::net::IpAddr>().is_ok() || !name.contains('.') || [".local", ".localhost", ".onion"].iter().any(|t| name.ends_with(t))
        || allowed.iter().any(|a| a == name)
}

/// A POST's `Origin`: its host must be one [`host_allowed`] accepts. `null` counts as absent: this
/// UI's own pages send it (`Referrer-Policy: no-referrer`), and any page can, so the Host check
/// is what refuses a rebinding; the CSRF token and SameSite cookie refuse the rest.
pub fn origin_allowed(origin: &str, allowed: &[String]) -> bool {
    let o = origin.trim();
    if o == "null" {
        return true;
    }
    let rest = o.strip_prefix("http://").or_else(|| o.strip_prefix("https://"));
    rest.is_some_and(|r| !r.is_empty() && !r.contains('/') && host_allowed(r, allowed))
}
