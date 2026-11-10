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
use crate::html::{esc, escv, int, json_block, kv, page, sats, short, txt, utc, Nav, Section, GATEWAY_BRAND, GATEWAY_SECTIONS, SIMPLE_SECTIONS, STREAM_BRAND, STREAM_SECTIONS,
                  STREAM_SECTIONS_HASH, WALLET_BRAND, WALLET_SECTIONS, WALLET_SECTIONS_HASH};
use crate::link::SignerLink;
use crate::server::{strip_base, Req, Resp};
use crate::{msg, now};

#[path = "stream_pages.rs"]
pub(crate) mod stream_pages;
#[path = "nwc_pages.rs"]
mod nwc_pages;
#[path = "sell.rs"]
pub(crate) mod sell;
#[path = "services_page.rs"]
pub mod services_page;
#[path = "nostr_pages.rs"]
mod nostr_pages;
#[path = "relay_pages.rs"]
mod relay_pages;
#[path = "hashrate.rs"]
pub mod hashrate;
#[path = "inference_page.rs"]
pub(crate) mod inference_page;
#[path = "vpn_page.rs"]
pub(crate) mod vpn_page;

pub const COOKIE: &str = "xbtui";
/// How long a signed form stays valid.
pub const SIGN_WINDOW_S: i64 = 600;

pub struct App {
    pub cfg: Config,
    pub auth: Auth,
    pub signer: SignerLink,
    /// The links buyers' own players open one file through ([`crate::relay`]).
    pub relays: crate::relay::RelayLinks,
    /// Where the shared folder of a Files service is served, once it is ([`crate::files`]).
    pub files_addr: std::sync::Mutex<Option<std::net::SocketAddr>>,
    /// Why the shared folder is not served (its address taken by another program, say), for the Sell page.
    pub files_error: std::sync::Mutex<Option<String>>,
    /// Sellers found on Nostr, when the owner set relays ([`crate::nostr`]).
    pub nostr: crate::nostr::NostrCache,
    /// VPN exits on the owner's relays, for the VPN page's Found on Nostr.
    pub vpn_exits: crate::nostr::ExitCache,
    /// Stream relays: the owner's choices, those announced on Nostr, and their probes ([`crate::relaynet`]).
    pub relay_net: crate::relaynet::RelayNet,
    /// The platform's login proxy, when it does the login ([`crate::auth::PlatformLogin`]).
    pub platform: Option<crate::auth::PlatformLogin>,
    /// Sellers' own pages on the app ports ([`crate::seller_app`]).
    pub apps: crate::seller_app::AppOrigins,
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

pub(crate) const INT_KEYS: [(&str, &str, &str); 13] = [
    ("max_per_tx_sats", "Largest single payment (sats)", "budgets"),
    ("daily_budget_sats", "Spending limit for any 24 hours (sats)", "budgets"),
    ("weekly_budget_sats", "Spending limit for any 7 days (sats)", "more"),
    ("per_counterparty_cap_sats", "Most to any one seller in 7 days (sats)", "more"),
    ("per_counterparty_daily_sats", "Most to any one seller in 24 hours (sats)", "more"),
    ("human_threshold_sats", "Ask me first for a payment of at least (sats)", "human"),
    ("approval_ttl_s", "A request for your approval expires after (seconds)", "human"),
    ("split_window_s", "Smaller payments to one seller within this many seconds count as one (so a large payment can't be split to avoid asking you)", "human"),
    ("velocity_max", "At most this many payments…", "velocity"),
    ("velocity_window_s", "…in this many seconds", "velocity"),
    ("hot_balance_cap_sats", "Most this box may hold for agents (sats; 0 means no limit)", "hot"),
    ("anchor_interval_s", "How often the records are sealed (seconds; after a restart)", "anchor"),
    ("treasury_csv", "Treasury delay (blocks; not used by this signer)", "anchor"),
];

/// The stream tickets' own limit (`tickets.tasks.default.budget_sats`), a field beside the other spending limits.
/// 0.2.6 showed it only in the rules file, by its raw name, and its refusal sent the owner there.
pub(crate) const TICKETS_BUDGET_LABEL: &str = "Most for paid services (stream tickets) in 24 hours (sats)";

/// The stream tickets' budget the rules `p` set, where they have a tickets section.
fn tickets_budget(p: &Value) -> Option<&Value> {
    p.get("tickets")?.get("tasks")?.get("default")?.get("budget_sats")
}

/// The height the XBT chain split from the SHA-256 chain at: a Lightning channel funded only from
/// coins older than this exists on both chains, and the rail refuses it.
pub const MAINNET_SPLIT_HEIGHT: i64 = 961_640;

/// The stream token of a login session whose CSRF token is `csrf`: a download's URL carries
/// it (`./s/~<token>/<seller URL>`), and the relay plays nothing without it. Derived, so the URL
/// (which may be logged) never carries the CSRF token itself.
pub fn stream_token(csrf: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(&Sha256::digest(format!("xbt-wallet-ui/stream|{csrf}").as_bytes())[..16])
}

/// What the starter rules let rented hashrate cost on mainnet in any 24 hours: about 70 minutes of a
/// 4 TH/s miner at market. The owner's limit: a rental's own budget is inside it.
pub const STARTER_RENTAL_BUDGET_SATS: i64 = 200_000;

/// What the starter rules let one seller be paid on mainnet in any 24 hours (`per_counterparty_daily_sats`):
/// a film on the demo shop (about 5,000 sat at 20 sat a MiB) several times over. 0.2.5's 5,000 stopped a film
/// near its end.
pub const STARTER_PER_SELLER_DAILY_SATS: i64 = 20_000;

/// What the starter rules let the wallet spend on mainnet in any 24 hours (`daily_budget_sats`), and the
/// day's budget of stream tickets: above [`STARTER_PER_SELLER_DAILY_SATS`], so a day at one shop leaves room
/// for another.
pub const STARTER_DAILY_SATS: i64 = 25_000;

/// The least `ln.exposure_cap_sats` the starter rules set on mainnet: 1,000,000 sats, so a node of
/// ordinary size is not refused at the first payment (0.2.1's 100,000 refused a node holding
/// 287,070). What the app may spend stays under the spending limits; this only bounds the node.
pub const STARTER_EXPOSURE_CAP_SATS: i64 = 1_000_000;

/// The exposure cap the starter rules suggest for a node that holds `held` sats in its channels:
/// twice that, rounded up to 10,000 sats, and never below [`STARTER_EXPOSURE_CAP_SATS`]. The signer
/// refuses every payment on mainnet without a cap, and while the node holds more than it.
pub fn starter_exposure_cap(held: i64) -> i64 {
    let twice = held.max(0).saturating_mul(2);
    let rounded = twice.saturating_add(9_999) / 10_000 * 10_000;
    rounded.max(STARTER_EXPOSURE_CAP_SATS)
}

/// The money limits the plain form never pre-fills above their mainnet starter value from the
/// signer's built-in defaults (which are for test chains). For these, a larger number trusts more.
const MAINNET_CAPPED_KEYS: [&str; 8] = ["max_per_tx_sats", "daily_budget_sats", "weekly_budget_sats", "per_counterparty_cap_sats", "per_counterparty_daily_sats",
                                         "human_threshold_sats", "hot_balance_cap_sats", "velocity_max"];

/// Whether paying over Lightning is turned on in `p`.
/// `p` with the seller at `origin` on the list of who may be paid, tied to its Lightning node `node`: the seller's
/// origin, or nothing (and `p` untouched) where either is not what it should be.
fn allow_seller(p: &mut Value, origin: &str, node: &str) -> Option<String> {
    let origin = crate::services::http_origin(origin)?;
    let node = node.trim().to_ascii_lowercase();
    if !p.is_object() || node.len() != 66 || !node.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut list: Vec<Value> = p["allowlist"].as_array().cloned().unwrap_or_default();
    if !list.iter().any(|x| x.as_str().and_then(crate::services::http_origin).as_deref() == Some(origin.as_str())) {
        list.push(Value::from(origin.clone()));
    }
    p["allowlist"] = Value::from(list);
    if !p["counterparties"].is_object() {
        p["counterparties"] = json!({});
    }
    p["counterparties"][origin.as_str()] = json!({"ln_node": node});
    Some(origin)
}

/// The node a mainnet box suggests for the first connection: Lightning Stream Genesis, the demo shop's node, with the two
/// addresses it announces.
pub const GENESIS_NODE: &str = "035d867908cdcdbccda8763bf81a99574dc042e2a6d00e44e9845836b7123d0b7d";
pub const GENESIS_HOST: &str = "103.219.170.129:9735";
pub const GENESIS_ONION: &str = "ywcqvtf3jcntadpjky46z7hwz3jx5jz43qa6m4qtqtczp5ab5wljxaad.onion:9735";

/// The least a first deposit should be: under it a channel may not open, or leaves too little to spend.
const MIN_DEPOSIT_SATS: i64 = 250_000;

/// Where a rules change made from one of the simple view's pages goes back to: that page, and no other address.
fn back_page(back: Option<&str>) -> Option<&'static str> {
    match back {
        Some("./limits") => Some("./limits"),
        Some("./browse") => Some("./browse"),
        _ => None,
    }
}

/// The amounts a limit's slider stops at, in sats.
const LIMIT_STEPS: [i64; 10] = [1_000, 2_000, 5_000, 10_000, 20_000, 50_000, 100_000, 200_000, 500_000, 1_000_000];

/// The limits of the Limits page: the rule each changes, its name there, and what it means.
const LIMITS: [(&str, &str, &str); 3] = [
    ("daily_budget_sats", "In a day", "The most the app may spend in any 24 hours, on everything together."),
    ("weekly_budget_sats", "In a week", "The most the app may spend in any 7 days."),
    ("per_counterparty_daily_sats", "One shop, in a day", "The most any one shop may be paid in any 24 hours."),
];

/// A slider's stops: [`LIMIT_STEPS`], and the limit as it is now where that is none of them.
fn limit_steps(now: i64) -> Vec<i64> {
    let mut v = LIMIT_STEPS.to_vec();
    if now > 0 && !v.contains(&now) {
        v.push(now);
        v.sort_unstable();
    }
    v
}

fn paying_on(p: &Value) -> bool {
    p.get("ln").and_then(|l| l.get("enabled")) == Some(&Value::Bool(true))
}

/// A conservative first policy (the setup wizard's template; `xbt-wallet-mcp/policy.example.json`'s limits),
/// with the Lightning rail and stream tickets on (tickets are paid only under a task with a budget: `default`
/// for buying, `hashrate` for the pieces of work of rented miners). On mainnet (`chain` "main") the caps are
/// low (the software has been tested on mainnet with small amounts only), and the node's exposure cap is
/// set (see [`starter_policy_for`] to size it from what the node holds).
pub fn starter_policy(chain: &str) -> Value {
    starter_policy_for(chain, None)
}

/// [`starter_policy`], with the exposure cap on mainnet sized from `held`, the sats the node holds
/// in its channels now ([`starter_exposure_cap`]); `None`: the least cap.
pub fn starter_policy_for(chain: &str, held: Option<i64>) -> Value {
    let mut p = json!({"allowlist": [], "counterparties": {}, "max_per_tx_sats": 100000, "daily_budget_sats": 200000, "weekly_budget_sats": 500000,
           "per_counterparty_cap_sats": 100000, "per_counterparty_daily_sats": 20000, "velocity_max": 60, "velocity_window_s": 3600, "human_threshold_sats": 50000,
           "split_window_s": 600, "approval_ttl_s": 900, "hot_balance_cap_sats": 1500000, "anchor_interval_s": 300,
           "ln": {"enabled": true}, "tickets": {"enabled": true, "tasks": {"default": {"budget_sats": 100000}, "hashrate": {"budget_sats": 100000}}}});
    if chain == "main" {
        // sized so that a first film at one shop (about 5,000 sat at 20 sat a MiB) and some AI fit in a day with that shop, and
        // two or three shops in a day: the most to one seller in a day is under the day's total, and a week's under the week's
        for (k, v) in [("max_per_tx_sats", 2000), ("daily_budget_sats", STARTER_DAILY_SATS), ("weekly_budget_sats", 60_000), ("per_counterparty_cap_sats", 50_000),
                       ("per_counterparty_daily_sats", STARTER_PER_SELLER_DAILY_SATS), ("human_threshold_sats", 1000), ("hot_balance_cap_sats", 50000)] {
            p[k] = json!(v);
        }
        p["ln"]["split_height"] = json!(MAINNET_SPLIT_HEIGHT);
        p["ln"]["exposure_cap_sats"] = json!(starter_exposure_cap(held.unwrap_or(0)));
        // the day's tickets: as much as the day's spending limit
        p["tickets"]["tasks"]["default"]["budget_sats"] = json!(STARTER_DAILY_SATS);
        // market price for a 4 TH/s miner is about 165,000 sat an hour, which no limit above would let through: the
        // task pays by its own (`tickets.tasks.*.rental`), and the rest of the wallet stands
        p["tickets"]["tasks"]["hashrate"] = json!({"budget_sats": STARTER_RENTAL_BUDGET_SATS, "rental": {"max_ticket_sats": 10_000, "max_sends_per_hour": 600}});
    }
    p
}

/// The ticket task a rented miner's pieces of work are paid under (the renter names it on every payment).
pub const HASHRATE_TASK: &str = "hashrate";

/// What the signed rules say of renting hashrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RentRules {
    /// Stream tickets are on and the rules have a `hashrate` task.
    Allowed,
    /// Stream tickets are on, but no `hashrate` task: the wallet refuses every rental's payment
    /// (0.2.11 on rules signed before the task: `no_rail`, "names no task \"hashrate\"").
    NoTask,
    /// Stream tickets are off, and rentals are paid with them.
    TicketsOff,
}

/// What the rules `p` (policy.json as signed) say of renting hashrate. Tickets are on as the signer reads
/// `tickets.enabled` (any value that is not false, 0, empty or missing), and a task is there when it is an object.
pub fn rent_rules(p: &Value) -> RentRules {
    let t = &p["tickets"];
    let on = match t.get("enabled") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_none_or(|f| f != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    };
    if !on {
        RentRules::TicketsOff
    } else if t["tasks"][HASHRATE_TASK].is_object() {
        RentRules::Allowed
    } else {
        RentRules::NoTask
    }
}

/// The `hashrate` task as the starter rules for `chain` set it ([`starter_policy_for`]).
pub fn starter_hashrate_task(chain: &str) -> Value {
    starter_policy(chain)["tickets"]["tasks"][HASHRATE_TASK].clone()
}

/// The rules `p` with only the `hashrate` task added, at the starter values for `chain`: every other
/// key is as it was. None where tickets are off or the task is there already.
pub fn with_hashrate_task(p: &Value, chain: &str) -> Option<Value> {
    if rent_rules(p) != RentRules::NoTask {
        return None;
    }
    let mut q = p.clone();
    let t = q.get_mut("tickets")?.as_object_mut()?;
    let tasks = t.entry("tasks").or_insert_with(|| json!({}));
    // tasks that are not an object are no tasks at all to the signer
    if !tasks.is_object() {
        *tasks = json!({});
    }
    tasks.as_object_mut()?.insert(HASHRATE_TASK.into(), starter_hashrate_task(chain));
    Some(q)
}

/// The `hashrate` task `task`, read-only, in words: its budget and window, and a rental's own caps.
pub(crate) fn hashrate_task_rows(task: &Value) -> String {
    let n = |v: &Value| v.as_i64();
    let mut rows: Vec<(&str, String)> = vec![];
    let window = n(&task["window_s"]).unwrap_or(86_400);
    let span = if window == 86_400 { "any 24 hours".to_string() } else if window % 3600 == 0 { format!("any {} hours", window / 3600) } else { format!("any {window} seconds") };
    rows.push(("Most for rented hashrate", match n(&task["budget_sats"]) {
        Some(b) => format!("{} in {span}", money(b)),
        None => "no budget set: nothing is paid".into(),
    }));
    if let Some(r) = task["rental"].as_object() {
        if let Some(t) = r.get("max_ticket_sats").and_then(Value::as_i64) {
            rows.push(("Largest ticket for a rental", money(t)));
        }
        if let Some(s) = r.get("max_sends_per_hour").and_then(Value::as_i64) {
            rows.push(("Most payments an hour for a rental", crate::html::group3(s.unsigned_abs())));
        }
    }
    kv(&rows)
}

/// The rows of Recent activity on the Wallet page, and with Show more.
const RECENT_ROWS: usize = 15;
const RECENT_MORE: usize = 200;

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
        let signer = SignerLink::new(cfg.signer_sock.clone(), std::time::Duration::from_secs(90)).keeping(cfg.read_cache);
        let nostr = crate::nostr::NostrCache::new(cfg.nostr_relays.clone());
        let vpn_exits = crate::nostr::ExitCache::new(cfg.nostr_relays.clone());
        let relay_net = crate::relaynet::RelayNet::with_default(cfg.nostr_relays.clone(), &cfg.data_dir, &cfg.stream_relay);
        let platform = cfg.platform_login.as_deref().map(crate::auth::PlatformLogin::new);
        let relays = crate::relay::RelayLinks::new(cfg.relay_ttl);
        // a tunnel secret an older build wrote owner-only is given to the VPN service's group, so an
        // exit offered before this upgrade isn't left refusing every buyer
        match vpn_page::migrate_tunnel_secret(&cfg.vpn.dir) {
            Ok(true) => eprintln!("xbt-wallet-ui: the VPN exit's tunnel secret is now readable by the VPN service"),
            Ok(false) => {}
            Err(e) => eprintln!("xbt-wallet-ui: the VPN exit's tunnel secret was left as it was: {e}"),
        }
        let app = Arc::new(Self { cfg, auth, signer, relays, files_addr: std::sync::Mutex::new(None),
                         files_error: std::sync::Mutex::new(None), nostr, vpn_exits, relay_net, platform,
                         apps: Default::default() });
        if app.cfg.prefetch {
            app.prefetch();
        }
        // the agents' catalog, for a box whose services file predates it (or was edited by hand)
        app.write_catalog();
        Ok(app)
    }

    /// The slow sources asked once in the background ([`Config::prefetch`]): the first visit to their
    /// pages then serves an answer at once, and the pages ask again behind it as they always did.
    pub fn prefetch(self: &Arc<Self>) {
        let me = self.clone();
        std::thread::spawn(move || {
            if me.nostr.enabled() {
                let _ = me.nostr.get(false);
                let _ = me.vpn_exits.get(false);
                let _ = me.relay_net.get(false);
            }
            me.hashrate_prefetch();
        });
    }

    pub(crate) fn call(&self, method: &str, params: Value) -> Result<Value, String> {
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

    /// For `GET /s/<file URL>` (a download from the page), the same checks as a page of the wallet;
    /// for `GET /r/<token>` (a link for the buyer's own player), the same checks less the login, and
    /// a live token for a file still in the services file. `Some(Ok(url))`: relay the seller URL `url`
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
        let Some(csrf) = self.auth.with_session(&sid, |s| s.csrf.clone()) else {
            return Some(Err(Resp::text(401, "text/plain", "login required")));
        };
        // the session's stream token: only a page of the wallet's own knows it (another page of the box sends
        // the cookie with what it asks for, but cannot read the token), so only the wallet's own page pays
        let token = path.strip_prefix("/s/~").and_then(|t| t.split_once('/')).map(|(t, _)| t).unwrap_or("");
        // `<token>.<service id>`: the service is only which price applies, never what the token proves
        let token = token.split_once('.').map_or(token, |(t, _)| t);
        if !crate::ct_eq(token.as_bytes(), stream_token(&csrf).as_bytes()) {
            return Some(Err(Resp::text(403, "text/plain", "refused: a stream this page did not ask for")));
        }
        Some(Ok(None))
    }

    /// The listing's prices of the service the buyer chose for the relayed `item`, as the call's
    /// `price_ceiling`: from a player's link, the service it was made for; from a Download
    /// (`/s/~<token>.<service id>/`), the service it names. `None`: that service lists no price.
    pub fn relay_ceiling(&self, req: &Req, item: &str) -> Option<Value> {
        let path = strip_base(&req.path, &self.cfg.base_path)?;
        let service = match path.strip_prefix("/r/") {
            Some(token) => self.relays.service_of(token)?,
            None => path.strip_prefix("/s/~").and_then(|t| t.split_once('/')).and_then(|(t, _)| t.split_once('.')).map(|(_, s)| s.to_string())?,
        };
        let all = self.services().ok()?;
        crate::services::find_item_of(&all, &service, item).and_then(|(s, _)| s.price_ceiling())
    }

    /// What one relayed part of a listed file may cost, from its listing: the most bytes its listed
    /// size can stand for ([`crate::files::size_most`]) and, for a part of `range_len` bytes, the
    /// call's limit ([`file_call_sats`]: the listed prices with 2% slack, at least one ticket).
    /// `None`: no listed size or price to hold the seller to.
    pub fn relay_limit(&self, req: &Req, item: &str, range_len: Option<u64>) -> Option<(u64, i64)> {
        let path = strip_base(&req.path, &self.cfg.base_path)?;
        let service = match path.strip_prefix("/r/") {
            Some(token) => self.relays.service_of(token)?,
            None => path.strip_prefix("/s/~").and_then(|t| t.split_once('/')).and_then(|(t, _)| t.split_once('.')).map(|(_, s)| s.to_string())?,
        };
        let all = self.services().ok()?;
        let (svc, it) = crate::services::find_item_of(&all, &service, item)?;
        let size = crate::files::size_most(&it.credit)?;
        let c = svc.price_ceiling()?;
        Some((size, file_call_sats(&c, range_len.map_or(size, |r| r.min(size)))))
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
            (true, "/vt.js") => return asset(&req, "text/javascript; charset=utf-8", crate::VT_JS),
            (true, "/mark.svg") => return asset(&req, "image/svg+xml", crate::MARK_SVG),
            (true, p) if p.starts_with("/fonts/") => {
                if let Some(b) = crate::font(&p["/fonts/".len()..]) {
                    return Resp::text(200, "font/woff2", b.to_vec()).header("Cache-Control", "public, max-age=31536000, immutable");
                }
            }
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
                    p => format!("{}{}{}", to_root(p), &p[1..], query_string(&req.query)),
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
            return Resp::redirect(&format!("{}login", to_root(&req.path)));
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
            "/wallet" => self.overview(&ctx, &req.query),
            "/browse" => self.browse(&ctx, &req.query),
            "/service" => self.service_page(&ctx, &req),
            "/services" => self.services_page(&ctx),
            "/sell" if self.cfg.sell => self.sell_page(&ctx, &req.query),
            "/sell-hashrate" if self.cfg.sell => self.sell_hashrate_page(&ctx),
            "/hashrate" => self.hashrate_page(&ctx),
            "/hashrate/gateway" => Resp::redirect("./gateway/"),
            p if p.starts_with("/hashrate/gateway/") => self.gateway_status_page(&ctx, &p["/hashrate/gateway/".len()..]),
            "/ai" => self.ai_page(&ctx, inference_page::page_host(&req)),
            "/vpn" => self.vpn_page(&ctx, &req.query),
            "/sell-vpn" if self.cfg.sell => self.sell_vpn_page(&ctx),
            "/nostr" => self.nostr_page(&ctx, &req.query),
            "/relays" => self.relays_page(&ctx, &req.query),
            "/app" => self.app_page(&ctx, &req.query),
            "/api/visit" => self.api_visit(&req.query),
            "/api/hashrate-rentals" => self.api_hashrate_rentals(&ctx),
            "/connections" => self.connections(&ctx),
            "/activity" => self.activity_page(&ctx, &req.query),
            "/limits" => self.limits_page(&ctx),
            "/add-money" => self.add_money_page(&ctx, &req.query),
            "/apps" => self.apps_page(&ctx),
            "/approvals" => self.approvals(&ctx),
            "/policy" => match req.query.get("fix").map(String::as_str) {
                Some("cap") => self.policy_fix_cap(&ctx),
                // the simple view: allowing a shop is one sheet, the change to approve, not the whole form of rules
                _ if self.simple() && req.query.contains_key("allow") && req.query.contains_key("node") => {
                    let cur = self.call("policy_get", json!({})).unwrap_or(Value::Null);
                    let mut p = cur["policy"].clone();
                    match (paying_on(&p), allow_seller(&mut p, &req.query["allow"], &req.query["node"])) {
                        (true, Some(_)) => self.policy_preview(&ctx, &HashMap::from([("mode".to_string(), "json".to_string()), ("json".to_string(), p.to_string()),
                                                                                    ("back".to_string(), "./browse".to_string())])),
                        _ => self.policy_page(&ctx, false, Some((req.query["allow"].as_str(), req.query["node"].as_str())), &[], None),
                    }
                }
                _ => self.policy_page(&ctx, req.query.get("template").map(|t| t == "starter").unwrap_or(false),
                                      req.query.get("allow").zip(req.query.get("node")).map(|(a, n)| (a.as_str(), n.as_str())),
                                      &req.query.get("drop").and_then(|d| crate::services::http_origin(d)).into_iter().collect::<Vec<_>>(),
                                      req.query.get("task").map(String::as_str)),
            },
            "/channels" => self.channels(&ctx),
            "/signatures" => self.signatures(&ctx),
            "/keys" => self.keys(&ctx),
            "/agents" => self.agents(&ctx, false),
            "/setup" => self.setup(&ctx),
            "/lightning" => self.lightning_page(&ctx),
            "/your-gateway" => self.your_gateway_page(&ctx),
            "/api/pending" => Resp::json(200, &json!({"pending": self.pending_count()})),
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
        // the owner's choice of view: the simple one has four entries, whatever the box can also do
        let advanced = (logged_in && self.cfg.role == Role::Wallet).then(|| self.prefs().advanced);
        let sections = if advanced == Some(false) { &SIMPLE_SECTIONS } else { sections };
        Nav { active, csrf, pending, logged_in, sections, brand, advanced }
    }

    /// The owner's choices for this box's pages ([`crate::prefs`]).
    pub(crate) fn prefs(&self) -> crate::prefs::Prefs {
        crate::prefs::load(&self.cfg.data_dir.join(crate::prefs::FILE))
    }

    fn save_prefs(&self, p: &crate::prefs::Prefs) -> Result<(), String> {
        crate::prefs::save(&self.cfg.data_dir.join(crate::prefs::FILE), p)
    }

    /// The simple view is on: four entries in the menu, the pages said for someone who buys.
    pub(crate) fn simple(&self) -> bool {
        self.cfg.role == Role::Wallet && !self.prefs().advanced
    }

    /// `POST /advanced`: the simple view (`on=0`) or every page (`on=1`). Nothing but the menu changes: every page keeps its address.
    fn advanced_post(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let mut p = self.prefs();
        p.advanced = f.get("on").is_some_and(|v| v == "1");
        match self.save_prefs(&p) {
            Ok(()) => self.flash(ctx, true, if p.advanced { "Every page is in the menu now. Simple view puts the short menu back." }
                                            else { "Simple view is on. The other pages are behind Advanced." }),
            Err(e) => self.flash(ctx, false, e),
        }
        Resp::redirect(if p.advanced { "./" } else { "./wallet" })
    }

    /// `GET /add-money`: the box's deposit address, the deposit once it has arrived (`?check=1` asks the node), and the
    /// approval that moves it on to the owner's Lightning node. Coins that pass through this address can always be
    /// proven to be XBT's alone, so a channel opened from them can be paid through, wherever they came from.
    fn add_money_page(&self, ctx: &Ctx, query: &HashMap<String, String>) -> Resp {
        let check = query.get("check").is_some_and(|c| c == "1");
        let st = match self.call("deposit_status", json!({"scan": check})) {
            Ok(v) if ok_of(&v) => v,
            Ok(v) => return self.page("Add money", ctx, Self::error_box(&reason_of(&v))),
            Err(e) => return self.page("Add money", ctx, Self::error_box(&e)),
        };
        let addr = txt(st.get("address"));
        let mut b = format!("<p class=\"lead\">Send XBT from any wallet or exchange to the address below. The app then moves it to your \
            Lightning node, where it becomes the balance you pay shops with.</p>\
            <section class=\"card\"><h2>1. Send to this address</h2><p><code class=\"mono deposit-address\">{}</code></p>\
            <p class=\"small\">Send at least {} sats: a little goes to network fees and to a small reserve your node keeps, the rest is yours to \
            spend. The address belongs to this box. Why not straight to your node? Coins that pass through this address can be proven to be \
            XBT's alone, which the app requires before it pays through a channel.</p></section>",
            esc(&addr), crate::html::group3(MIN_DEPOSIT_SATS as u64));
        b.push_str("<section class=\"card\"><h2>2. Wait for it to arrive</h2>");
        let found = int(st.get("confirmed_sats"));
        if !check {
            b.push_str("<p>After you have sent it, give it about 10 minutes, then check.</p>");
        } else if let Some(e) = st.get("scan_error").and_then(Value::as_str) {
            b.push_str(&format!("<div class=\"flash warn\">The app could not ask your XBT node just now ({}). Try again in a minute.</div>", esc(e)));
        } else if found == 0 {
            b.push_str("<p><span class=\"pill warn\">Not arrived yet</span> Nothing confirmed at the address so far. A deposit shows here after its first confirmation.</p>");
        } else {
            b.push_str(&format!("<p><span class=\"pill good\">Arrived</span> <strong class=\"money\">{} sats</strong> are at the address.{}</p>",
                crate::html::group3(found as u64),
                if found < MIN_DEPOSIT_SATS { format!(" That is under {} sats: enough to move on, but a channel that small may not open.", crate::html::group3(MIN_DEPOSIT_SATS as u64)) }
                else { String::new() }));
        }
        b.push_str("<p><a class=\"button-link\" href=\"./add-money?check=1\">Check for my deposit</a> <span class=\"small\">On a small box the check can take a minute or two.</span></p></section>");
        // with the open key the box does the rest: the node's own address, then the channel
        let funding = self.call("funding_status", json!({})).unwrap_or(Value::Null);
        let auto = funding["open_key"] == true;
        if check && found > 0 && auto {
            let human = self.human_pub();
            let exp = now() + SIGN_WINDOW_S;
            b.push_str(&format!("<section class=\"card\"><h2>3. Move it to your Lightning node</h2><p>{} sats will arrive there ({} sats network fee).</p>",
                                crate::html::group3((found - int(st.get("fee_sats"))).max(0) as u64), crate::html::group3(int(st.get("fee_sats")).max(0) as u64)));
            match self.call("funding_address", json!({})) {
                _ if human.is_empty() => b.push_str("<p>Set up approvals first: <a href=\"./setup\">finish the setup</a>.</p>"),
                Ok(a) if ok_of(&a) => {
                    let to = txt(a.get("address"));
                    b.push_str(&self.signed_form(ctx, "./deposit-forward", "deposit", &human,
                        &[("deposit_address", addr.clone()), ("to", to.clone()), ("expiry", exp.to_string())],
                        &format!("<p class=\"small\">To your node's own address <code class=\"mono\">{}</code>, which the app asked it for.</p>", esc(&to)),
                        "Approve and move it", Ext::Bytes(msg::deposit_forward(&addr, &to, exp))));
                }
                Ok(a) => b.push_str(&Self::error_box(&reason_of(&a))),
                Err(e) => b.push_str(&Self::error_box(&e)),
            }
            b.push_str("</section>");
        }
        if auto {
            b.push_str(&self.open_connection_html(ctx, &funding));
        }
        if check && found > 0 && !auto {
            let human = self.human_pub();
            let exp = now() + SIGN_WINDOW_S;
            b.push_str(&format!("<section class=\"card\"><h2>3. Move it to your Lightning node</h2><p>{} sats will arrive there ({} sats network fee).</p>",
                                crate::html::group3((found - int(st.get("fee_sats"))).max(0) as u64), crate::html::group3(int(st.get("fee_sats")).max(0) as u64)));
            if human.is_empty() {
                b.push_str("<p>Set up approvals first: <a href=\"./setup\">finish the setup</a>.</p>");
            } else {
                b.push_str(&self.signed_form(ctx, "./deposit-forward", "deposit", &human, &[("deposit_address", addr.clone()), ("expiry", exp.to_string())],
                    "<label>An address of your Lightning node<input name=\"to\" class=\"mono\" autocomplete=\"off\" required></label>\
                     <p class=\"small\">In your Lightning node's app (Lightning Fork), make a new on-chain receive address and paste it here. \
                     Once the coins are there, open a channel with them in that app. A later version does both steps for you.</p>",
                    "Approve and move it", Ext::Lines(format!("xbt-agentwallet-deposit-forward-v1\n{addr}\n(the address you type)\n{exp}"))));
            }
            b.push_str("</section>");
        }
        self.page("Add money", ctx, b)
    }

    /// The last step of Add money, where the box opens the channel itself: each deposit moved to the node, and for
    /// one that has a confirmation and no channel yet, the approval that opens the connection.
    fn open_connection_html(&self, ctx: &Ctx, funding: &Value) -> String {
        let forwards = funding["forwards"].as_array().cloned().unwrap_or_default();
        if forwards.is_empty() {
            return String::new();
        }
        let mut b = String::from("<section class=\"card\" id=\"open-connection\"><h2>4. Open your connection</h2>");
        let human = self.human_pub();
        // the box's own choice, else on mainnet the demo shop's node (it has both addresses: the other is said below)
        let genesis = self.cfg.funding_peer.is_none() && self.signer_chain() == "main";
        let (peer, host) = self.cfg.funding_peer.clone()
            .or_else(|| genesis.then(|| (GENESIS_NODE.to_string(), GENESIS_HOST.to_string()))).unwrap_or_default();
        let other = if genesis { format!(" If it cannot be reached at that address, use its other one: <code class=\"mono\">{GENESIS_ONION}</code>.") } else { String::new() };
        for f in &forwards {
            let (txid, amount) = (txt(f.get("txid")), crate::html::group3(int(f.get("sats")).max(0) as u64));
            if f.get("channel").is_some() {
                b.push_str(&format!("<p><span class=\"pill good\">Opening</span> {amount} sats: your connection is opening. It is ready to pay through \
                    after about an hour (6 confirmations). Then your <a href=\"./wallet\">Wallet</a> shows what you can spend.</p>"));
            } else if f["confirmations"].as_i64().is_some_and(|c| c >= 1) && !human.is_empty() {
                let exp = now() + SIGN_WINDOW_S;
                b.push_str(&format!("<p><span class=\"pill good\">Arrived at your node</span> {amount} sats. One approval opens your connection with them: \
                    almost all becomes your balance; the opening fee and a small reserve your node keeps are not spendable.</p>"));
                b.push_str(&self.signed_form(ctx, "./channel-open", "channel", &human, &[("forward_txid", txid.clone()), ("expiry", exp.to_string())],
                    &format!("<details{}><summary>Who you connect to{}</summary>\
                        <label>Node key<input name=\"peer\" value=\"{}\" class=\"mono\" autocomplete=\"off\" required pattern=\"0[23][0-9a-fA-F]{{64}}\"></label>\
                        <label>Its address<input name=\"host\" value=\"{}\" class=\"mono\" autocomplete=\"off\" required placeholder=\"host:9735\"></label>\
                        <p class=\"small\">Your payments to shops travel through this node. It never holds your money: the connection is yours, \
                        and you can close it from your Lightning node's app at any time.{other}</p></details>",
                        if peer.is_empty() { " open" } else { "" },
                        if genesis { ": Lightning Stream Genesis, change it if you like" } else if peer.is_empty() { "" } else { ": the suggested node, change it if you like" },
                        esc(&peer), esc(&host)),
                    "Approve and open", Ext::Lines(format!("xbt-agentwallet-channel-open-v1\n(the node key)\n(its address)\n{txid}\n{exp}"))));
            } else if f["confirmations"].is_null() {
                b.push_str(&format!("<p><span class=\"pill warn\">Not found</span> {amount} sats moved to your node, but the coin is not there to open a \
                    connection with: it may have been spent from your node's own app.</p>"));
            } else {
                b.push_str(&format!("<p><span class=\"pill warn\">On its way</span> {amount} sats are on their way to your node. After one confirmation \
                    (about 10 minutes) the last step shows here. <a href=\"./add-money\">Look again</a></p>"));
            }
        }
        b.push_str("</section>");
        b
    }

    /// `GET /limits`: the three limits most owners ever change, as sliders. Each slider moves over [`LIMIT_STEPS`] and
    /// the limit as it is now, so opening the page and pressing the button changes nothing.
    fn limits_page(&self, ctx: &Ctx) -> Resp {
        let cur = match self.call("policy_get", json!({})) {
            Ok(v) => v,
            Err(e) => return self.page("Limits", ctx, Self::error_box(&e)),
        };
        if !paying_on(&cur["policy"]) {
            return self.page("Limits", ctx, "<section class=\"card\"><p>Paying is not turned on yet, so there are no limits to change. \
                The safe starter rules turn it on, with low limits.</p><p><a class=\"button-link primary\" href=\"./policy\">Turn paying on</a></p></section>".into());
        }
        let mut b = String::from("<p class=\"lead\">How much the app may spend without asking you. It never spends past these, whatever a shop or an \
            agent asks for. A change takes effect once you approve it.</p><form method=\"post\" action=\"./limits\" class=\"card limits\">");
        b.push_str(&Self::csrf_input(ctx));
        for (key, title, words) in LIMITS {
            let now = int(cur["policy"].get(key).or(cur["effective"].get(key)));
            let steps = limit_steps(now);
            let at = steps.iter().position(|s| *s == now).unwrap_or(0);
            b.push_str(&format!("<label class=\"limit\"><span class=\"limit-title\">{title}</span>\
                <input type=\"range\" name=\"{key}\" min=\"0\" max=\"{}\" step=\"1\" value=\"{at}\" data-steps=\"{}\">\
                <output>{} sats</output></label><input type=\"hidden\" name=\"cur_{key}\" value=\"{now}\">\
                <p class=\"small\">{words} Now: {} sats. The slider goes from {} to {} sats.</p>",
                steps.len() - 1, steps.iter().map(i64::to_string).collect::<Vec<_>>().join(","), crate::html::group3(now.max(0) as u64),
                crate::html::group3(now.max(0) as u64), crate::html::group3(steps[0] as u64), crate::html::group3(steps[steps.len() - 1] as u64)));
        }
        b.push_str("<button>Review the change</button></form>\
            <p class=\"small\">A week's limit is never under a day's, and one shop's never over the day's: the app evens them out when you review. \
            Every other rule (who may be paid, when the app asks you first) is in <a href=\"./policy\">all spending rules</a>.</p>");
        self.page("Limits", ctx, b)
    }

    /// `POST /limits`: the signed rules with the sliders' limits, shown as a change to review and approve: the same
    /// review, signature and signer checks as a change made on the Spending rules page.
    fn limits_post(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let cur = match self.call("policy_get", json!({})) {
            Ok(v) => v,
            Err(e) => return self.page("Limits", ctx, Self::error_box(&e)),
        };
        let mut p = cur["policy"].clone();
        if !p.is_object() || !paying_on(&p) {
            return Resp::redirect("./limits");
        }
        for (key, _, _) in LIMITS {
            // the slider's steps were built from the limit the page showed: the same list here, whatever changed since
            let shown = f.get(&format!("cur_{key}")).and_then(|v| v.trim().parse::<i64>().ok()).filter(|v| *v > 0)
                .unwrap_or_else(|| int(cur["policy"].get(key).or(cur["effective"].get(key))));
            let steps = limit_steps(shown);
            let Some(at) = f.get(key).and_then(|v| v.trim().parse::<usize>().ok()).filter(|i| *i < steps.len()) else { continue };
            p[key] = Value::from(steps[at]);
        }
        let n = |p: &Value, k: &str| p.get(k).and_then(Value::as_i64);
        if let (Some(day), Some(week)) = (n(&p, "daily_budget_sats"), n(&p, "weekly_budget_sats")) {
            p["weekly_budget_sats"] = Value::from(week.max(day));
        }
        if let (Some(day), Some(shop)) = (n(&p, "daily_budget_sats"), n(&p, "per_counterparty_daily_sats")) {
            p["per_counterparty_daily_sats"] = Value::from(shop.min(day));
        }
        let as_json = HashMap::from([("mode".to_string(), "json".to_string()), ("json".to_string(), p.to_string()), ("back".to_string(), "./limits".to_string())]);
        self.policy_preview(ctx, &as_json)
    }

    /// `POST /favorite`: keep a shop as a favorite, or stop. Back to the page it was pressed on.
    fn favorite_post(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let back = f.get("back").map(String::as_str).filter(|b| b.starts_with("./service?") && !b.contains(['\r', '\n'])).unwrap_or("./browse").to_string();
        let Some(origin) = f.get("seller").and_then(|s| crate::services::http_origin(s)) else {
            self.flash(ctx, false, "That is not a shop's address.");
            return Resp::redirect(&back);
        };
        let on = f.get("on").is_some_and(|v| v == "1");
        let mut p = self.prefs();
        if !p.set_favorite(&origin, on) {
            self.flash(ctx, false, format!("You have {} favorites, the most the app keeps. Remove one first.", crate::prefs::MAX_FAVORITES));
            return Resp::redirect(&back);
        }
        match self.save_prefs(&p) {
            Ok(()) => self.flash(ctx, true, if on { "Added to your favorites." } else { "Removed from your favorites." }),
            Err(e) => self.flash(ctx, false, e),
        }
        Resp::redirect(&back)
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
        // simple mode: where the box's PIN key is the approval key, the PIN signs (`./api/pin-sign`), not a browser key;
        // a handover to the PIN key itself is signed by the browser key it replaces
        let by_pin = kind != "pin-handover" && self.pin_approves();
        let (pin_attr, pin_mode, pin_label) = if by_pin { (" data-pin=\"1\"", "numeric", "PIN") } else { ("", "text", "Approval key passphrase") };
        format!("<form method=\"post\" action=\"{action}\" data-sign=\"{kind}\" data-human=\"{}\"{pin_attr} class=\"signed\">{}{h}{visible}\
                 <input type=\"hidden\" name=\"signature\" value=\"\">\
                 <div class=\"row\"><input class=\"pin\" type=\"password\" autocomplete=\"one-time-code\" data-lpignore=\"true\" data-1p-ignore data-bwignore inputmode=\"{pin_mode}\" placeholder=\"{pin_label}\" aria-label=\"{pin_label}\">\
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
        // where the code is: the platform's own words (XBT_UI_SETUP_CODE_HINT), or the general ones
        let code_field = if self.auth.needs_setup_code() {
            format!("<label>Setup code<input name=\"code\" autocomplete=\"off\" required></label>\
             <p class=\"hint\">A one-time code that proves this app is yours. {}</p>",
                    match &self.cfg.setup_code_hint {
                        Some(h) => esc(h),
                        None => "It is in the app's log, on the line that says <em>setup code</em>, and in the file \
                                 <code>setup-code</code> in the app's data folder.".into(),
                    })
        } else {
            String::new()
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
                return Resp::redirect(&format!("{}setup-password", to_root(&req.path)));
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
            "/app" => self.app_open(ctx, f),
            "/advanced" => self.advanced_post(ctx, f),
            "/favorite" => self.favorite_post(ctx, f),
            "/limits" => self.limits_post(ctx, f),
            "/channel-open" => back("./add-money", self.call("channel_open", json!({"peer": g("peer").to_ascii_lowercase(), "host": g("host"),
                                        "forward_txid": g("forward_txid"), "expiry": i("expiry"), "signature": sig()})),
                                    &|_| "Your connection is opening. It is ready to pay through after about an hour (6 confirmations); nothing more to do.".into()),
            "/deposit-forward" => back("./add-money", self.call("deposit_forward", json!({"to": g("to"), "expiry": i("expiry"), "signature": sig()})),
                                       &|v| format!("{} sats are on their way to your Lightning node. They are there after one confirmation, about 10 minutes.",
                                                    crate::html::group3(int(v.get("sats")).max(0) as u64))),
            "/app-stop" => self.app_stop(ctx, f),
            "/app-limit" => self.app_limit(f),
            "/identity" => self.identity(ctx, f),
            "/services" => self.services_post(ctx, f),
            "/sell" if self.cfg.sell => self.sell_post(ctx, f),
            "/sell-hashrate" if self.cfg.sell => self.sell_hashrate_post(ctx, f),
            "/hashrate" => self.hashrate_post(ctx, f),
            "/ai" => self.ai_post(ctx, f, inference_page::page_host(req)),
            "/file-link" => self.file_link(ctx, f),
            "/vpn" => self.vpn_post(ctx, f),
            "/sell-vpn" if self.cfg.sell => self.sell_vpn_post(ctx, f),
            "/nostr-check" => self.nostr_check(ctx, f),
            "/relays-prefs" => self.relays_prefs(ctx, f),
            "/relays-publish" => self.relays_publish(ctx, f),
            "/relay-run" => self.relay_run(ctx, f),
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
            "/seller-unblock" => back("./policy", self.call("seller_unblock", json!({"block": g("block"), "expiry": i("expiry"), "signature": sig()})),
                                      &|_| "Unblocked. The app may buy from this shop again.".into()),
            // browsers submit line breaks as CRLF; the signed text is LF only (JSON escapes a CR inside a string)
            "/policy-apply" => self.policy_apply(ctx, f),
            "/api/pin-sign" => self.api_pin_sign(f),
            "/pin-set" => self.pin_set_post(ctx, f),
            "/pin-change" => {
                if g("new_pin") != g("new_pin2") {
                    self.flash(ctx, false, "The two new PINs differ: type the same digits twice.");
                    return Resp::redirect("./keys#pin");
                }
                back("./keys#pin", self.call("pin_change", json!({"pin": g("pin"), "new_pin": g("new_pin"), "gate": self.pin_gate()})),
                     &|_| "PIN changed.".into())
            }
            "/human-key-enroll" => back("./setup", self.call("human_key_enroll", json!({"pubkey": g("pubkey"), "code": g("code")})), &|_| "Approval key enrolled.".into()),
            "/human-key-rotate" => back("./keys", self.call("human_key_rotate", json!({"pubkey": g("pubkey"), "expiry": i("expiry"), "signature": sig()})),
                                        &|_| "The new approval key is enrolled; the old one no longer approves anything.".into()),
            "/sweep" => back("./keys", self.call("sweep_hot", json!({"to": g("to"), "amount_sats": i("amount_sats"), "expiry": i("expiry"), "signature": sig()})),
                             &|v| format!("Swept {} sats to {} (txid {}).", int(v.get("swept_sats")), txt(v.get("to")), txt(v.get("txid")))),
            "/rotate" => back("./keys", self.call("rotate_hot_key_signed", json!({"expiry": i("expiry"), "signature": sig()})),
                              &|v| format!("Hot key rotated: new address {}.", txt(v.get("new_address")))),
            // the access key is in a page only when the owner asks for it, by a POST with the CSRF token:
            // never in the source of the page as it opens (0.2.1 hands-on run)
            "/agents-key" => self.agents(ctx, true),
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
        let (ready, connected, _) = self.node_state();
        let ack = connected && self.ack_needed();
        b.push_str(&self.get_started(ctx, human, connected, ack));
        let services = self.file_services().unwrap_or_default();
        let sellers = {
            let mut o: Vec<String> = services.iter().filter_map(|s| crate::services::http_origin(&s.seller)).collect();
            o.sort();
            o.dedup();
            o.len()
        };
        let mut cats: Vec<String> = services.iter().map(|s| esc(s.category_words())).collect();
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
            let can = crate::pay_feedback::spendable_sats(&ln).map(|c| format!(" It can send about {} now.", money(c))).unwrap_or_default();
            format!("<span class=\"pill good\">Ready to pay</span> Your Lightning node is connected, with {n} channel{} to pay through.{can}", if n == 1 { "" } else { "s" })
        } else if ack {
            "<span class=\"pill warn\">One last step</span> Confirm that the app may pay with real money. <a href=\"./lightning#ack\">Start paying</a>".into()
        } else if connected {
            "<span class=\"pill warn\">Not ready</span> Your Lightning node is connected but cannot pay yet. <a href=\"./lightning\">See why</a>".into()
        } else {
            "<span class=\"pill warn\">Not connected</span> Connect your Lightning node to pay for services. <a href=\"./lightning\">Connect it</a>".into()
        };
        b.push_str(&format!("<p class=\"status-line\">{line} · <a href=\"./wallet\">Wallet</a></p>"));
        self.page("Home", ctx, b)
    }

    /// Home's "First steps" list, until every step is done: the approval key, the node, the starter
    /// rules (with, on mainnet, the yes to paying with real money ticked as they are signed), a shop allowed (the demo shop in one press where the box
    /// suggests one) and a first purchase. Each step says what it is; the next one to do has its button.
    fn get_started(&self, ctx: &Ctx, human: bool, connected: bool, ack: bool) -> String {
        let pol = self.call("policy_get", json!({})).map(|v| v["policy"].clone()).unwrap_or(Value::Null);
        let paying = paying_on(&pol);
        // allowed as the signer decides: also a shop allowed only through its node's `ln:` line
        let at = xbt_nostr::now();
        let shops: Vec<(String, Option<String>)> = crate::shops::load(&self.cfg.shops_path()).unwrap_or_default().iter()
            .map(|(o, s)| (o.clone(), crate::shops::node(s, o, at))).collect();
        let allowed = any_seller_allowed(&pol, &shops);
        // the history is read only once a shop is allowed: nothing can have been bought before
        let bought = allowed && self.call("history", json!({"limit": 500})).ok().and_then(|h| h["events"].as_array().cloned()).unwrap_or_default().iter()
            .any(|e| matches!(e["type"].as_str(), Some("ticket_settled" | "ln_settled" | "ticket_open" | "ticket_paid_first")));
        let demo = self.first_suggestion();
        // mainnet: the signer asks for the confirmation, or the confirmation is on file; before the rules
        // are signed the signer asks nothing yet, so the chain is read then (once, until they are)
        let main = ack || self.cfg.ln.dir.join(crate::setup::MAINNET_ACK_FILE).is_file() || (!paying && connected && self.signer_chain() == "main");
        // (done, title, what it is, where to go, its button)
        let mut steps: Vec<(bool, &str, &str, String, &str)> = vec![
            (human, "Make your approval key", "It is how you say yes to a rule change or a large payment. It stays in this browser.",
             "./setup".into(), "Make the key")];
        if !connected {
            steps.push((false, "Connect your Lightning node", "The app pays through your own node.", "./lightning".into(), "Connect it"));
        }
        // on mainnet the yes to real money is a box on the same page as the rules' Sign: one step, done with both
        if !main {
            steps.push((paying, "Sign the starter rules", "Low limits on what the app may spend. You can change them any time.",
                        "./policy?template=starter".into(), "Open the starter rules"));
        } else if paying && ack {
            // signed without the box ticked: the confirmation alone is left, on Your node
            steps.push((false, "Sign the starter rules", "Your rules are signed. Confirm that the app may pay with real money within them.",
                        "./lightning#ack".into(), "Start paying"));
        } else {
            steps.push((paying && connected && !ack, "Sign the starter rules",
                        "Low limits on what the app may spend, and your yes to paying with real money within them. You can change them any time.",
                        "./policy?template=starter".into(), "Open the starter rules"));
        }
        steps.push((allowed, if demo.is_some() { "Try the demo shop" } else { "Allow a shop" },
                    if demo.is_some() { "Add Lightning Stream Genesis and allow it to be paid, with one signature." }
                    else { "Add a shop on Sellers and allow it to be paid." }, "./services".into(), "Add a shop"));
        steps.push((bought, "Buy something", "Open a shop's app or download a file. Stop it any time on Live connections.", "./browse".into(), "Browse"));
        let done = steps.iter().filter(|s| s.0).count();
        if done == steps.len() {
            return String::new();
        }
        let next = steps.iter().position(|s| !s.0).unwrap_or(0);
        let mut b = format!("<section class=\"card primary\" id=\"get-started\"><h2>First steps</h2><p class=\"small\">{done} of {} done</p><ol class=\"checklist\">",
                            steps.len());
        for (i, (ok, title, what, href, button)) in steps.iter().enumerate() {
            let action = if i != next {
                String::new()
            } else if *title == "Try the demo shop" {
                format!("<form method=\"post\" action=\"./services\">{}<input type=\"hidden\" name=\"action\" value=\"try\">\
                         <input type=\"hidden\" name=\"url\" value=\"{}\"><button>Try the demo shop</button></form>",
                        Self::csrf_input(ctx), esc(demo.as_deref().unwrap_or_default()))
            } else {
                format!("<p><a class=\"button-link primary\" href=\"{href}\">{}</a></p>", esc(button))
            };
            b.push_str(&format!("<li class=\"{}\"{}><strong>{}</strong> <span class=\"small\">{}</span>{action}</li>",
                                if *ok { "done" } else if i == next { "now" } else { "" }, if i == next { " aria-current=\"step\"" } else { "" },
                                esc(title), esc(what)));
        }
        b.push_str("</ol></section>");
        b
    }

    fn overview(&self, ctx: &Ctx, query: &HashMap<String, String>) -> Resp {
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
        // the signer runs without the XBT node, and the amounts on it wait for it
        if self.call("node_status", json!({})).is_ok_and(|n| n["reachable"] == false) {
            b.push_str("<div class=\"flash warn\">The app cannot reach your XBT node yet, so the amounts on it below may be out of date. \
                        Paying over Lightning does not need it. Check that the node is running and that the app has its address and \
                        password (on Linux: LS_NODE_RPC_* in .env).</div>");
        }
        // Lightning first: what pays for services. The XBT node's on-chain coins are another wallet, said apart
        // (0.2.1 showed "On your node 0 sats" while the channels held 286,000)
        let ln = self.call("ln_status", json!({})).unwrap_or(json!({}));
        let ready = ln["ready"] == true && ln["real_money_ack_needed"] != true;
        b.push_str("<section class=\"grid\"><div class=\"card\"><h2>Lightning</h2>");
        b.push_str(&kv(&[("Can send now", crate::pay_feedback::spendable_sats(&ln).map(|c| format!("about {}", money(c))).unwrap_or_else(|| "not known".into())),
                         ("Status", if ready { "<span class=\"pill good\">Ready to pay</span>".into() } else { "<span class=\"pill warn\">Not ready</span> <a href=\"./lightning\">See why</a>".into() })]));
        // the simple view: what can be spent, favorite shops, and where to go; the coins on chain and the rest are behind Advanced
        if self.simple() {
            b.push_str("<p class=\"small\">This is what you can spend in shops right now, within your <a href=\"./limits\">limits</a>.</p></div></section>");
            b.push_str(&self.favorites_html(&self.services().unwrap_or_default()));
            b.push_str("<p class=\"status-line\"><a class=\"button-link primary\" href=\"./browse\">Browse shops</a> · <a href=\"./add-money\">Add money</a> · \
                        <a href=\"./activity\">What you paid: Activity</a></p>");
            return self.page("Wallet", ctx, b);
        }
        b.push_str("<p class=\"small\">Credit left with shops is on <a href=\"./services\">Sellers</a> and on each shop's service page \
                    (on <a href=\"./connections\">Live connections</a> while a connection is open). \
                    What the app may spend is in your <a href=\"./policy\">spending rules</a>.</p></div>");
        b.push_str("<div class=\"card\"><h2>XBT on chain</h2>");
        b.push_str(&kv(&[("On your XBT node", money(int(bal.get("trusted_sats")))), ("On its way to your XBT node", money(int(bal.get("untrusted_pending_sats")))),
                         ("On this box, for agents", money(int(hot.get("hot_sats")))),
                         ("Most this box may hold for agents", if int(hot.get("hot_cap_sats")) > 0 { money(int(hot.get("hot_cap_sats"))) } else { "no limit".into() }),
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
        b.push_str(&self.activity_html(query, "./wallet"));
        b.push_str("<details class=\"card\"><summary>Technical details</summary>");
        b.push_str(&kv(&[("Chain", escv(health.get("chain"))), ("Signer", escv(health.get("implementation"))),
                         ("Node wallet", escv(health.get("wallet"))), ("Test mining", escv(health.get("mining")))]));
        b.push_str("</details>");
        self.page("Wallet", ctx, b)
    }

    /// `GET /activity`: what was paid, reserved and refused, newest first. The Wallet page's list, on a page of its own.
    fn activity_page(&self, ctx: &Ctx, query: &HashMap<String, String>) -> Resp {
        let b = format!("<p class=\"lead\">Every payment the app made or refused, newest first.</p>{}", self.activity_html(query, "./activity"));
        self.page("Activity", ctx, b)
    }

    /// The latest payments as a table, for the page at `here` (its "Show more" comes back to it).
    fn activity_html(&self, query: &HashMap<String, String>, here: &str) -> String {
        let mut b = String::new();
        // the latest 15 events, or with "Show more" (`?more=1`) the latest 200
        let more = query.get("more").is_some_and(|m| m == "1");
        let recent = self.call("history", json!({"limit": if more { RECENT_MORE } else { RECENT_ROWS }}));
        // a seller by its name where the list of sellers has it, never by a made-up `…shop.invalid` address
        let known = self.services().unwrap_or_default();
        // a payment to `ln:<node>` by the name of the seller paid through that node: on file in the rules, or vouched for by its shop
        // (read only where a row names a node: the page's reads stay few)
        let named_nodes = recent.as_ref().ok().and_then(|h| h["events"].as_array())
            .is_some_and(|a| a.iter().any(|e| e["dest"].as_str().is_some_and(|d| d.starts_with("ln:"))));
        let nodes: Vec<(String, String)> = if !named_nodes { Vec::new() } else { self.seller_nodes() };
        let who = |d: &str| {
            if let Some(o) = d.strip_prefix("ln:").and_then(|n| nodes.iter().find(|(x, _)| x.eq_ignore_ascii_case(n.trim()))).map(|(_, o)| o) {
                return crate::services::seller_name(&known, o);
            }
            match crate::services::http_origin(d) {
                Some(o) if xbt402::shop::is_shop(&o) || crate::services::shop_name(&known, &o).is_some() => crate::services::seller_name(&known, &o),
                _ => short(d, 40),
            }
        };
        // a seller that charged more than a call allowed: said at the top, with the numbers
        if let Some(e) = recent.as_ref().ok().and_then(|h| h["events"].as_array().cloned()).unwrap_or_default().iter().rev().find(|e| e["type"] == "ticket_over_cap") {
            let msat = |k: &str| e.get(k).and_then(|v| v.as_str().and_then(|s| s.parse::<u64>().ok()).or(v.as_u64())).unwrap_or(0);
            b.push_str(&format!("<div class=\"flash bad\">{} charged {} sats for one answer, more than the {} sats the call allowed. \
                                 The app stopped paying that seller in that session; the seller's signed receipt is kept in the wallet's records.</div>",
                                esc(&who(&txt(e.get("origin")))), sats_of_msat(msat("charged_msat")), msat("max_msat") / 1000));
        }
        if let Ok(h) = recent {
            if here == "./wallet" {
                b.push_str("<h2>Recent activity</h2>");
            }
            b.push_str("<div class=\"scroll\"><table><thead><tr><th>When</th><th>What</th><th>To</th><th>Amount</th><th>Detail</th></tr></thead><tbody>");
            // the bookkeeping of a reservation (its booking made what was paid) is not a row of its own
            let all: Vec<Value> = h["events"].as_array().cloned().unwrap_or_default();
            // and one row a payment: its allowed and reserved steps fold into its outcome
            let folds = activity_folds(&all);
            let events: Vec<(usize, &Value)> = all.iter().enumerate().filter(|(i, e)| !folds.contains_key(i) && activity_row(e, &all)).collect();
            // what each settled payment cost, from its settled record: one read for the page
            let hashes: Vec<&str> = events.iter().map(|&(_, e)| e).filter(|e| matches!(e["type"].as_str(), Some("ticket_settled" | "ln_settled" | "ticket_prepaid")))
                .filter_map(|e| e["payment_hash"].as_str()).collect();
            let settled = if hashes.is_empty() { Value::Null } else {
                self.call("settled_amounts", json!({"hashes": hashes})).map(|v| v["settled"].clone()).unwrap_or(Value::Null)
            };
            if events.is_empty() {
                b.push_str("<tr><td colspan=\"5\" class=\"small\">Nothing yet.</td></tr>");
            }
            for &(i, e) in events.iter().rev() {
                let txid = txt(e.get("txid"));
                // a booking before a payment settles (a ticket, a Lightning payment, a coin send not yet answered) is a reservation
                let reserved = e["type"] == "commit" && ["ln:", "ticket:", "onchain:unconfirmed:"].iter().any(|p| txid.starts_with(p));
                let what = match e["type"].as_str() {
                    Some("commit") if reserved => "Reserved".into(),
                    Some("commit") => "Sent on chain".into(),
                    Some("ticket_settled" | "ln_settled" | "ticket_prepaid") => "Paid".into(),
                    Some("ticket_prepay") => "Reserved".into(),
                    Some("ticket_left_with_seller") => "Credit left with the shop".into(),
                    Some("ticket_seller_forgot") => "The shop had forgotten an earlier connection".into(),
                    Some("decision") => match e["verdict"].as_str() { Some("allow") => "Allowed".into(), Some("deny") => "Refused".into(),
                                                                       Some("needs_human") => "Asked for your approval".into(), v => format!("Decision: {}", v.unwrap_or("")) },
                    Some("ticket_over_cap") => "A seller charged past the limit".into(),
                    Some("ticket_seller_fault") => "A seller broke the rules: stopped".into(),
                    Some(t) => { let t = t.replace('_', " "); let mut c = t.chars(); c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default() }
                    None => String::new(),
                };
                // a ticket's row has its amount too (0.2.1 showed none). A settled payment: what was paid, as its settled record says,
                // with its two parts; what was booked before it settled: reserved
                let rec = e["payment_hash"].as_str().and_then(|h| settled.get(h));
                let left = e["type"] == "ticket_left_with_seller";
                let amt = match rec {
                    _ if left => match txt(e.get("left_msat")).parse::<u64>() {
                        Ok(m) => format!("<span class=\"money\">{} sats</span> <span class=\"small\">credit left</span>", crate::html::msat_num(m)),
                        Err(_) => "<span class=\"small\">not said by the shop</span>".into(),
                    },
                    Some(r) if what == "Paid" => crate::html::paid_html(int(r.get("paid_sats")),
                        Some((txt(r.get("value_msat")).parse().unwrap_or(0), txt(r.get("fee_msat")).parse().unwrap_or(0)))),
                    _ if what == "Paid" => e.get("spent_sats").map(|a| crate::html::paid_html(int(Some(a)), None)).unwrap_or_default(),
                    // a reservation is the most the payment may cost, routing fees included: said so, beside the exact Paid row
                    _ if reserved => e.get("amount_sats").map(|a| format!("{} <span class=\"small\">reserved, the most it may cost</span>", money(int(Some(a))))).unwrap_or_default(),
                    _ if e["type"] == "ticket_prepay" => e.get("booked_sats").map(|a| format!("{} <span class=\"small\">reserved, the most it may cost</span>", money(int(Some(a))))).unwrap_or_default(),
                    _ => match ["amount_sats", "spent_sats"].iter().find_map(|k| e.get(*k)) {
                        Some(a) => money(int(Some(a))),
                        None => e.get("booked_sats").map(|a| format!("{} <span class=\"small\">reserved</span>", money(int(Some(a))))).unwrap_or_default(),
                    },
                };
                // a refusal in the refusal pages' plain words, the signer's own under Details
                let (what, detail) = match refusal_words(e) {
                    Some((title, words)) => (title, format!("{} <details><summary>Details</summary>{}</details>", esc(&words), esc(&short(&txt(e.get("reason")), 300)))),
                    None => (what, activity_detail(e, reserved) + &activity_steps(&all, &folds, i)),
                };
                b.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{amt}</td><td class=\"small\">{detail}</td></tr>", utc(int(e.get("ts"))), esc(&what),
                                    esc(&who(&txt(e.get("dest").or(e.get("origin")))))));
            }
            b.push_str("</tbody></table></div>");
            // there may be more than the page shows
            if !more && h["events"].as_array().is_some_and(|a| a.len() >= RECENT_ROWS) {
                b.push_str(&format!("<p class=\"small\"><a href=\"{here}?more=1\">Show more</a> (the latest {RECENT_MORE})</p>"));
            }
        }
        b
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
    /// `drop`: sellers shown ticked for removal (from Sellers, after the owner removed one there).
    fn policy_form(&self, ctx: &Ctx, p: &Value, eff: &Value, errors: &[String], warnings: &[String], drop: &[String]) -> String {
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
        b.push_str(&seller_warnings_box(&self.seller_checks(p)));
        let main = self.signer_chain() == "main";
        let starter = starter_policy("main");
        // on mainnet, a limit the rules leave out is shown at its starter value, not at the signer's
        // built-in one (made for test chains): signing the form as shown never trusts more than that
        let mut lowered: Vec<&str> = vec![];
        let shown = |k: &str, label: &'static str, lowered: &mut Vec<&str>| -> Option<Value> {
            if let Some(v) = p.get(k) {
                return Some(v.clone());
            }
            let e = eff.get(k).cloned();
            if !(main && MAINNET_CAPPED_KEYS.contains(&k)) {
                return e;
            }
            let sv = starter.get(k).and_then(Value::as_i64);
            let above = match (e.as_ref().and_then(Value::as_i64), sv) {
                // the box's balance cap: 0 is no limit at all
                (Some(0), Some(_)) if k == "hot_balance_cap_sats" => true,
                (Some(ev), Some(sv)) => ev > sv,
                (None, Some(_)) => true,
                _ => false,
            };
            if above {
                lowered.push(label);
                starter.get(k).cloned()
            } else {
                e
            }
        };
        let mut fields = String::new();
        fields.push_str(&format!("<form method=\"post\" action=\"./policy\" class=\"policy\">{}<input type=\"hidden\" name=\"mode\" value=\"form\">", Self::csrf_input(ctx)));
        let mut cap_suggested: Option<i64> = None;
        // the limits a first-time owner reads up front; the rest under More rules
        let groups = [("budgets", "Spending limits"), ("human", "Ask me first"), ("more", "More spending limits"), ("velocity", "How fast"),
                      ("hot", "Money on this box"), ("anchor", "Records")];
        for (g, title) in groups {
            if g == "more" {
                fields.push_str("<details><summary>More rules</summary>");
            }
            fields.push_str(&format!("<fieldset><legend>{title}</legend>"));
            for (k, label, grp) in INT_KEYS {
                if grp == g {
                    let v = shown(k, label, &mut lowered);
                    fields.push_str(&format!("<label>{}<input name=\"f_{k}\" value=\"{}\" inputmode=\"numeric\"></label>", esc(label), escv(v.as_ref())));
                }
            }
            if g == "budgets" && p.get("ln").is_some() {
                let set = p.get("ln").and_then(|l| l.get("exposure_cap_sats")).filter(|v| !v.is_null()).cloned();
                let held = self.ln_held();
                let value = match set {
                    Some(v) => txt(Some(&v)),
                    None if main && paying_on(p) => {
                        let c = starter_exposure_cap(held);
                        cap_suggested = Some(c);
                        c.to_string()
                    }
                    None => String::new(),
                };
                fields.push_str(&format!("<label>Most your Lightning node may hold (sats)\
                    <input name=\"f_ln_exposure_cap_sats\" value=\"{}\" inputmode=\"numeric\"></label>\
                    <p class=\"hint\">Your node's channels hold {} now. Keep this above that: while the node holds more, the app pays nothing. \
                    It does not change what the app may spend{}.</p>",
                    esc(&value), money(held), if main { ". On mainnet it is required" } else { "" }));
            }
            // the stream tickets' budget: its own limit, beside the others (the hashrate task's stays in the rules file)
            if g == "budgets" && p.get("tickets").is_some_and(Value::is_object) {
                let value = tickets_budget(p).map(|v| txt(Some(v))).unwrap_or_default();
                fields.push_str(&format!("<label>{}<input name=\"f_tickets_budget_sats\" value=\"{}\" inputmode=\"numeric\"></label>\
                    <p class=\"hint\">What the app may pay shops for web apps, files and AI, a little at a time, in any 24 hours. \
                    It counts within the spending limit above.</p>", esc(TICKETS_BUDGET_LABEL), esc(&value)));
                // renting hashrate: its own task, shown read-only (changed in Advanced, or added from Buy → Hashrate)
                match rent_rules(p) {
                    RentRules::Allowed => fields.push_str(&format!("<div id=\"renting-hashrate\"><p><strong>Renting hashrate</strong></p>{}\
                        <p class=\"hint\">What rented miners' work may cost, apart from the limits above. To change it, edit the rules as a file under \
                        Advanced below.</p></div>", hashrate_task_rows(&p["tickets"]["tasks"][HASHRATE_TASK]))),
                    RentRules::NoTask => fields.push_str("<div id=\"renting-hashrate\"><p><strong>Renting hashrate</strong></p>\
                        <p class=\"hint\">Not allowed: your rules have no budget for renting hashrate, so the wallet pays no rental. \
                        <a href=\"./policy?task=hashrate\">Allow renting hashrate in your spending rules</a></p></div>"),
                    RentRules::TicketsOff => {}
                }
            }
            if g == "anchor" {
                fields.push_str(&format!("<label class=\"check\"><input type=\"checkbox\" name=\"f_anchor_required\" value=\"1\"{}> Refuse to start without the separate record keeper (after a restart)</label>",
                                    if p.get("anchor_required").or(eff.get("anchor_required")) == Some(&Value::Bool(true)) { " checked" } else { "" }));
            }
            fields.push_str("</fieldset>");
            if g == "anchor" {
                fields.push_str("</details>");
            }
        }
        if let Some(c) = cap_suggested {
            b.push_str(&format!("<div class=\"flash warn\"><p>Your Lightning node needs a limit before the app can pay through it: \
                {} is filled in below (\"Most your Lightning node may hold\"). Review it, then sign.</p></div>", money(c)));
        }
        if !lowered.is_empty() {
            b.push_str(&format!("<div class=\"flash warn\"><p>Your rules leave these out, so the safe starter values are filled in below \
                instead of the signer's built-in ones, which are for test chains: {}. Signing the form sets them.</p></div>",
                esc(&lowered.join("; "))));
        }
        b.push_str(&fields);
        b.push_str(&self.sellers_fieldset(p, drop));
        b.push_str(&format!("<input type=\"hidden\" name=\"f_unseen\" value=\"{}\">\
            <div class=\"row\"><button>Review the change</button> <a class=\"button-link\" href=\"./policy?template=starter\">Start from the safe starter rules</a></div></form>",
            esc(&Self::unseen_sections(p).to_string())));
        b.push_str(&format!("<details><summary>Advanced: edit the rules as a file (each seller's address and node as the rules hold them)</summary><form method=\"post\" action=\"./policy\">{}\
            <input type=\"hidden\" name=\"mode\" value=\"json\"><textarea name=\"json\" rows=\"20\" class=\"mono\">{}</textarea>\
            <button>Review the change</button></form></details>", Self::csrf_input(ctx), esc(&serde_json::to_string_pretty(p).unwrap_or_default())));
        b
    }

    /// Each seller the rules `p` name, with its name and what would make the signer refuse it: an
    /// address on the list that may be paid with no Lightning node on file, or a shop reached by its
    /// key whose node on file is not the one the shop vouches for now ([`crate::shops::node`]).
    fn seller_checks(&self, p: &Value) -> Vec<SellerCheck> {
        // names from the list of sellers and from Found on Nostr
        let all = self.services().unwrap_or_default();
        let shops = crate::shops::load(&self.cfg.shops_path()).unwrap_or_default();
        let now = xbt_nostr::now();
        let rows = rule_sellers(p);
        // each seller's node: on file in the rules, else the one its shop vouches for
        let vouched: Vec<Option<String>> = rows.iter().map(|r| r.origin.as_ref().and_then(|o| shops.get(o).and_then(|s| crate::shops::node(s, o, now)))).collect();
        let node_name = |n: &str| rows.iter().zip(&vouched).find_map(|(r, v)| {
            let o = r.origin.as_ref()?;
            [r.node.as_deref(), v.as_deref()].into_iter().flatten().any(|x| x.eq_ignore_ascii_case(n)).then(|| crate::services::seller_name(&all, o))
        }).or_else(|| {
            // a seller allowed only by its node's line: the shop on file that vouches for that node
            shops.iter().find(|(o, sh)| crate::shops::node(sh, o, now).is_some_and(|x| x.eq_ignore_ascii_case(n)))
                .map(|(o, _)| crate::services::seller_name(&all, o))
        });
        rows.iter().zip(&vouched).map(|(r, vouched)| {
            let name = match (&r.origin, ln_line_node(&r.key)) {
                (Some(o), _) => crate::services::seller_name(&all, o),
                // an `ln:` line is a seller's Lightning node, never a coin address
                (None, Some(n)) => match node_name(n) {
                    Some(who) => format!("Lightning node of {who}"),
                    None => format!("Lightning node {}", short_node(n)),
                },
                (None, None) => "A coin address".into(),
            };
            let through_node = r.origin.as_ref().is_some_and(|o| rules_allow(p, o, vouched.as_deref())) && r.node.is_none();
            let problem = match (&r.origin, &r.node, vouched) {
                (Some(_), None, _) if r.listed && !through_node => Some("this seller will be refused: it has no Lightning node on file"),
                (Some(_), Some(n), Some(v)) if r.listed && !n.eq_ignore_ascii_case(v) =>
                    Some("this seller will be refused: its Lightning node on file is not the one the shop vouches for now"),
                _ => None,
            };
            SellerCheck { rule: r.clone(), name, vouched: vouched.clone(), problem, through_node }
        }).collect()
    }

    /// "Who may be paid": one row per seller the rules name, by name, with its shop key or web
    /// address and its node, and a Remove box. The list itself goes with the form unchanged
    /// (`f_sellers`): only whole sellers are taken out, so a node is never cut off by an edit.
    fn sellers_fieldset(&self, p: &Value, drop: &[String]) -> String {
        let checks = self.seller_checks(p);
        let shown = json!({"allowlist": p.get("allowlist").cloned().unwrap_or(json!([])), "counterparties": p.get("counterparties").cloned().unwrap_or(json!({}))});
        let mut b = format!("<fieldset id=\"sellers\"><legend>Who may be paid</legend><input type=\"hidden\" name=\"f_sellers\" value=\"{}\">", esc(&shown.to_string()));
        if checks.is_empty() {
            b.push_str("<p class=\"empty\">No seller may be paid yet.</p>");
        } else {
            b.push_str("<div class=\"scroll\"><table class=\"sellers\"><thead><tr><th>Seller</th><th>Lightning node</th><th></th></tr></thead><tbody>");
            for (i, c) in checks.iter().enumerate() {
                let r = &c.rule;
                // a node's line by its node, short (the full key in its tooltip): never the raw `ln:` line
                let addr = match (&r.origin, ln_line_node(&r.key)) {
                    (Some(o), _) => xbt402::shop::display(o),
                    (None, Some(n)) => format!("node {}", short_node(n)),
                    (None, None) => r.key.clone(),
                };
                let node = match (&r.node, &r.origin, ln_line_node(&r.key)) {
                    (Some(n), _, _) => format!("<code title=\"{}\">{}</code>", esc(n), esc(&short_node(n))),
                    (None, Some(_), _) if c.through_node => "<span class=\"tag ok\">allowed through its node line</span>".into(),
                    (None, Some(_), _) => "<span class=\"tag warn\">none on file</span>".into(),
                    (None, None, Some(n)) => format!("<code title=\"{}\">{}</code>", esc(n), esc(&short_node(n))),
                    (None, None, None) => "<span class=\"small\">not needed</span>".into(),
                };
                let mut notes = String::new();
                if !r.listed {
                    notes.push_str("<br><span class=\"small\">Not on the list that may be paid: only its node is kept.</span>");
                }
                if let Some(why) = c.problem {
                    notes.push_str(&format!("<br><span class=\"tag bad\">{}</span>", esc(&capital(why))));
                    match (&c.vouched, &r.origin) {
                        (Some(v), Some(o)) => notes.push_str(&format!(" <a href=\"./policy?allow={}&amp;node={}\">Use the node the shop vouches for</a>",
                                                                         crate::services::urlenc(o), esc(v))),
                        _ => notes.push_str(" <a href=\"./services\">Allow it again on Sellers</a>"),
                    }
                }
                let ticked = r.origin.as_ref().is_some_and(|o| drop.contains(o));
                b.push_str(&format!("<tr><td><strong>{}</strong><br><code class=\"key small\">{}</code>{notes}</td><td>{node}</td>\
                    <td><label class=\"check\"><input type=\"checkbox\" name=\"f_drop_{i}\" value=\"{}\"{}> Remove</label></td></tr>",
                    esc(&c.name), esc(&addr), esc(&r.key), if ticked { " checked" } else { "" }));
            }
            b.push_str("</tbody></table></div>");
        }
        b.push_str("<p class=\"hint\">To add a seller, open <a href=\"./services\">Sellers</a> and press \"Allow this seller to be paid\". \
            To change an address or a node by hand, use Advanced below.</p></fieldset>");
        b
    }

    /// The sats the Lightning node holds in its channels now, as the signer counts them against the
    /// exposure cap (0 when the node can't be read).
    /// What the node holds in its channels, as the signer reads it; `None` where it could not.
    fn ln_held_read(&self) -> Option<i64> {
        self.call("ln_status", json!({})).ok().and_then(|s| s["exposure"]["total_sats"].as_i64())
    }

    fn ln_held(&self) -> i64 {
        self.ln_held_read().unwrap_or(0)
    }

    /// The rules page with only the node's exposure cap raised to what the starter rules suggest for
    /// what the node holds now: the one-click fix where the node holds more than the signed cap.
    fn policy_fix_cap(&self, ctx: &Ctx) -> Resp {
        let cur = match self.call("policy_get", json!({})) {
            Ok(v) => v,
            Err(e) => return self.page("Spending rules", ctx, Self::error_box(&e)),
        };
        let mut p = cur["policy"].clone();
        let Some(held) = self.ln_held_read() else {
            return self.page("Spending rules", ctx, Self::error_box("The app can't read your Lightning node right now, so it can't suggest a limit. Try again in a minute."));
        };
        let cap = starter_exposure_cap(held);
        if !p["ln"].is_object() {
            p["ln"] = json!({});
        }
        p["ln"]["exposure_cap_sats"] = json!(cap);
        let mut b = format!("<div class=\"flash ok\">Your Lightning node holds {} now. The limit on what it may hold is set to {} below (twice that, \
            rounded up); nothing else changes. Review it, then sign.</div>", money(held), money(cap));
        let errs: Vec<String> = cur["errors"].as_array().map(|a| a.iter().map(|x| txt(Some(x))).collect()).unwrap_or_default();
        let warns: Vec<String> = cur["warnings"].as_array().map(|a| a.iter().map(|x| txt(Some(x))).collect()).unwrap_or_default();
        b.push_str(&self.policy_form(ctx, &p, &cur["effective"], &errs, &warns, &[]));
        self.page("Spending rules", ctx, b)
    }

    /// Shops the wallet caught charging more than they delivered: blocked until the owner lifts it
    /// with the approval key. Each shows the three it is blocked by and the evidence.
    fn blocked_sellers(&self, ctx: &Ctx) -> String {
        let list = self.call("seller_blocks", json!({})).ok().and_then(|v| v["blocked"].as_array().cloned()).unwrap_or_default();
        if list.is_empty() {
            return String::new();
        }
        let human = self.human_pub();
        let mut b = String::from("<section id=\"blocked\"><h2>Shops blocked for overcharging</h2><p>The app caught these shops charging more than \
            they delivered. It stopped paying them at once and buys nothing more from them, and pays them no lottery win, until you unblock \
            them with your approval key. A shop is blocked by its Lightning node, its receipt key and its address: changing one of them \
            does not lift the block.</p>");
        for e in &list {
            let id = txt(e.get("id"));
            let receipt = e["evidence"]["receipt"].clone();
            let rows = [("Address", esc(&txt(e.get("origin")))), ("Lightning node", format!("<code>{}</code>", esc(&txt(e.get("payee"))))),
                        ("Receipt key", format!("<code>{}</code>", esc(&txt(e.get("receipt_key"))))), ("What it did", esc(&txt(e.get("reason")))),
                        ("When", utc(int(e.get("ts"))))];
            b.push_str("<div class=\"card\">");
            b.push_str(&kv(&rows));
            if !receipt.is_null() {
                b.push_str(&format!("<details><summary>The receipt it signed (evidence)</summary><pre>{}</pre></details>",
                                    esc(&serde_json::to_string_pretty(&receipt).unwrap_or_default())));
            }
            let sexp = now() + SIGN_WINDOW_S;
            b.push_str(&self.signed_form(ctx, "./seller-unblock", "unblock", &human, &[("block", id.clone()), ("expiry", sexp.to_string())], "",
                                         "Unblock", Ext::Bytes(msg::unblock(&id, sexp))));
            b.push_str("</div>");
        }
        b.push_str("</section>");
        b
    }

    fn policy_page(&self, ctx: &Ctx, template: bool, allow: Option<(&str, &str)>, drop: &[String], task: Option<&str>) -> Resp {
        let cur = match self.call("policy_get", json!({})) {
            Ok(v) => v,
            Err(e) => return self.page("Spending rules", ctx, Self::error_box(&e)),
        };
        // `?task=hashrate`, from Buy → Hashrate: the signed rules with only the hashrate task added, to sign
        let task_note = match (task, rent_rules(&cur["policy"])) {
            (Some(HASHRATE_TASK), RentRules::NoTask) => return self.hashrate_task_page(ctx, &cur["policy"]),
            (Some(HASHRATE_TASK), RentRules::Allowed) => "<div class=\"flash ok\"><p>Renting hashrate is already allowed in your spending rules: \
                see Renting hashrate below.</p></div>",
            (Some(HASHRATE_TASK), RentRules::TicketsOff) => "<div class=\"flash warn\"><p>Stream tickets are off in your spending rules, and rented \
                hashrate is paid with them. The safe starter rules turn them on, with renting hashrate; or turn <code>tickets.enabled</code> on under \
                Advanced and sign.</p></div>",
            _ => "",
        };
        let mut b = String::from("<p class=\"lead\">The rules the wallet applies to every payment an app or an agent asks for. A change takes \
            effect once you sign it with your approval key. Apps and agents cannot change them.</p>");
        b.push_str(task_note);
        b.push_str(&self.blocked_sellers(ctx));
        let pr = cur["pending_restart"].as_array().cloned().unwrap_or_default();
        if !pr.is_empty() {
            let hint = self.cfg.restart_hint.clone();
            let mut hint_cap = hint.clone();
            if let Some(c) = hint_cap.get_mut(0..1) { c.make_ascii_uppercase(); }
            b.push_str(&format!("<div class=\"flash warn\">Signed, and waiting for the app to restart: {}. {}.</div>",
                                esc(&pr.iter().map(|x| setting_name(&txt(Some(x)))).collect::<Vec<_>>().join(", ")), esc(&hint_cap)));
        }
        if paying_on(&cur["policy"]) && self.ack_needed() {
            b.push_str("<div class=\"flash warn\">Your rules are signed, but the app pays nothing until you confirm that it may pay with real money. \
                <a href=\"./lightning#ack\">Start paying</a></div>");
        }
        let mut p = cur["policy"].clone();
        // paying not on yet: the page opens on the starter rules, which turn it on
        let auto = !template && allow.is_none() && !paying_on(&p);
        if template || auto {
            let keep = p.clone();
            let chain = self.signer_chain();
            let held = self.ln_held_read();
            p = starter_policy_for(&chain, held);
            for k in ["allowlist", "counterparties", "human_pubkey"] {
                if let Some(v) = keep.get(k) {
                    p[k] = v.clone();
                }
            }
            if held.is_none() && chain == "main" {
                b.push_str(&format!("<div class=\"flash warn\">The app could not read your Lightning node yet, so the least limit on what it may \
                    hold ({}) is filled in below. If your node holds more, the app will say so after you sign, with a button that raises it.</div>",
                    money(STARTER_EXPOSURE_CAP_SATS)));
            }
            b.push_str(if auto {
                "<div class=\"flash ok\">Paying is not turned on yet, so the safe starter rules are filled in below (your list of sellers is \
                 kept): they turn paying over Lightning on, with low limits. Review them, then sign.</div>"
            } else {
                "<div class=\"flash ok\">The safe starter rules are filled in below (your list of sellers is kept), with paying over \
                 Lightning turned on and low limits. Review them, then sign.</div>"
            });
        } else {
            b.push_str("<section class=\"card\"><p>Not sure what to set? The safe starter rules turn paying on with low limits, and keep your \
                        list of sellers.</p><p><a class=\"button-link\" href=\"./policy?template=starter\">Start from the safe starter rules</a></p></section>");
        }
        // a seller to allow, from the Sellers page: its address on the list, tied to its node
        if let Some((origin, node)) = allow {
            if let Some(origin) = allow_seller(&mut p, origin, node) {
                let cap = p.get("per_counterparty_cap_sats").or(cur["effective"].get("per_counterparty_cap_sats")).and_then(Value::as_i64).unwrap_or(0);
                b.push_str(&format!("<div class=\"flash ok\"><p><strong>Allow {} to be paid.</strong> Sign below with your approval key. \
                    The app may then pay this seller up to {} in any 7 days, within your other limits.</p></div>", esc(&self.seller_name(&origin)), money(cap)));
            }
        }
        if !drop.is_empty() {
            let all = self.file_services().unwrap_or_default();
            let names: Vec<String> = drop.iter().map(|o| crate::services::seller_name(&all, o)).collect();
            b.push_str(&format!("<div class=\"flash warn\"><p>{} is still allowed to be paid. It is ticked for removal under \"Who may be paid\" below: \
                review the change, then sign it. To keep it allowed, leave this page.</p></div>", esc(&names.join(", "))));
        }
        let errs: Vec<String> = cur["errors"].as_array().map(|a| a.iter().map(|x| txt(Some(x))).collect()).unwrap_or_default();
        let warns: Vec<String> = cur["warnings"].as_array().map(|a| a.iter().map(|x| txt(Some(x))).collect()).unwrap_or_default();
        b.push_str(&self.policy_form(ctx, &p, &cur["effective"], &errs, &warns, drop));
        b.push_str(&format!("<details><summary>Advanced: the rules file's fingerprint</summary><p class=\"small\">policy.json SHA-256 <code>{}</code></p></details>",
                            escv(cur.get("sha256"))));
        self.page("Spending rules", ctx, b)
    }

    /// The signed rules `p` with only the hashrate task added at the starter values for this chain, for the owner
    /// to review and sign: the exact rules go as the rules file (the form's JSON mode), so no other field changes,
    /// not even one the plain form would fill with its starter value. Nothing is signed here.
    fn hashrate_task_page(&self, ctx: &Ctx, p: &Value) -> Resp {
        let chain = self.signer_chain();
        let Some(q) = with_hashrate_task(p, &chain) else { return Resp::redirect("./policy") };
        let mut b = String::from("<p class=\"lead\">The rules the wallet applies to every payment an app or an agent asks for. A change takes \
            effect once you sign it with your approval key. Apps and agents cannot change them.</p>");
        b.push_str("<section class=\"card\" id=\"add-hashrate-task\"><h2>Allow renting hashrate</h2>\
            <p>Your spending rules have stream tickets on, but nothing for renting hashrate, so your wallet refuses to pay for rented \
            miners' work. This adds only that, at the starter values. Everything else in your rules stays exactly as you signed it.</p>");
        b.push_str(&hashrate_task_rows(&q["tickets"]["tasks"][HASHRATE_TASK]));
        // one task not named "default" takes the payments that name none; with a second, those are refused
        let others: Vec<String> = p["tickets"]["tasks"].as_object().map(|m| m.keys().cloned().collect()).unwrap_or_default();
        if let [only] = others.as_slice() {
            if only != "default" {
                b.push_str(&format!("<p class=\"hint warn\">Your rules have one other ticket task, <code>{}</code>, which now takes every payment that \
                    names no task. With two tasks, such a payment is refused unless one of them is named <code>default</code>.</p>", esc(only)));
            }
        }
        b.push_str(&format!("<form method=\"post\" action=\"./policy\">{}<input type=\"hidden\" name=\"mode\" value=\"json\">\
            <input type=\"hidden\" name=\"json\" value=\"{}\"><div class=\"row\"><button>Review the change</button> \
            <a href=\"./hashrate\">Cancel</a></div></form><p class=\"small\">You sign the change with your approval key on the next page. \
            To change other rules, open <a href=\"./policy\">all your spending rules</a>.</p></section>",
            Self::csrf_input(ctx), esc(&serde_json::to_string_pretty(&q).unwrap_or_default())));
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
        // the node's exposure cap, the one Lightning setting the form shows: empty takes it out
        if let Some(v) = f.get("f_ln_exposure_cap_sats") {
            let mut ln = p.get("ln").and_then(Value::as_object).cloned().unwrap_or_default();
            if v.trim().is_empty() {
                ln.remove("exposure_cap_sats");
            } else {
                ln.insert("exposure_cap_sats".into(), num(v));
            }
            if !ln.is_empty() {
                p.insert("ln".into(), Value::Object(ln));
            }
        }
        // the stream tickets' budget: set where the rules have a tickets section; empty leaves it as it is (a task needs one)
        if let Some(v) = f.get("f_tickets_budget_sats").map(|v| v.trim().replace(',', "")).filter(|v| !v.is_empty()) {
            if let Some(t) = p.get_mut("tickets").and_then(Value::as_object_mut) {
                let tasks = t.entry("tasks").or_insert_with(|| json!({}));
                if let Some(tasks) = tasks.as_object_mut() {
                    let d = tasks.entry("default").or_insert_with(|| json!({}));
                    if let Some(d) = d.as_object_mut() {
                        d.insert("budget_sats".into(), num(&v));
                    }
                }
            }
        }
        p.insert("anchor_required".into(), Value::Bool(f.contains_key("f_anchor_required")));
        // the sellers: the list the page showed (`f_sellers`), less those ticked for removal. Nothing on
        // the page is typed, so a seller's node is never lost to an edit (0.2.1: a node wrapped in a
        // text box and cut off left its seller refused). A form without the list (an older page) keeps
        // the sellers as they are; an expert changes them in Advanced.
        if let Some(Value::Object(shown)) = f.get("f_sellers").and_then(|s| serde_json::from_str::<Value>(s).ok()) {
            let drops: Vec<&String> = f.iter().filter(|(k, _)| k.starts_with("f_drop_")).map(|(_, v)| v).collect();
            let dropped = |key: &str| drops.iter().any(|d| d.as_str() == key || crate::services::http_origin(d).is_some_and(|o| crate::services::http_origin(key) == Some(o)));
            let allow: Vec<Value> = shown.get("allowlist").and_then(Value::as_array).cloned().unwrap_or_default().into_iter()
                .filter(|x| !dropped(&txt(Some(x)))).collect();
            let mut cps = Map::new();
            for (k, v) in shown.get("counterparties").and_then(Value::as_object).cloned().unwrap_or_default() {
                if dropped(&k) {
                    continue;
                }
                let mut e = v.as_object().cloned().unwrap_or_default();
                // the payTo key of an on-chain channel: that rail was removed and the signer ignores the key
                e.remove("pay_to");
                cps.insert(k, Value::Object(e));
            }
            p.insert("allowlist".into(), Value::from(allow));
            p.insert("counterparties".into(), Value::Object(cps));
        }
        // the section of the retired hub routing and the settings of the removed on-chain channel: the
        // signer ignores them, so the form leaves them out
        for k in ["routing", "channel_expiry_blocks", "refund_enabled", "refund_margin_blocks", "open_wait_s", "open_retry_s", "close_fee_max_sats", "channel_rail"] {
            p.remove(k);
        }
        Value::Object(p)
    }

    /// The signed rules, applied; with the real-money box ticked (`ack=1`), the confirmation is written
    /// next, by the same code as Your node's Start paying. Unticked, or refused, the page that asks for it
    /// is next.
    fn policy_apply(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let g = |k: &str| f.get(k).map(|v| v.trim().to_string()).unwrap_or_default();
        let sig = { let s = g("signature"); if s.is_empty() { g("signature_ext") } else { s } };
        // browsers submit line breaks as CRLF; the signed text is LF only (JSON escapes a CR inside a string)
        let r = self.call("policy_set", json!({"text": f.get("text").map(|t| t.replace("\r\n", "\n")).unwrap_or_default(),
                                                "prev_sha256": g("prev_sha256"), "expiry": g("expiry").parse::<i64>().unwrap_or(0), "signature": sig}));
        let v = match r {
            Ok(v) if ok_of(&v) => v,
            Ok(v) => { self.flash(ctx, false, reason_of(&v)); return Resp::redirect("./policy"); }
            Err(e) => { self.flash(ctx, false, e); return Resp::redirect("./policy"); }
        };
        let pr = v.get("pending_restart").and_then(Value::as_array).map(|a| a.iter().map(|x| setting_name(&txt(Some(x)))).collect::<Vec<_>>().join(", ")).unwrap_or_default();
        // ticked: the same confirmation Your node writes
        let confirmed = if f.get("ack").map(String::as_str) == Some("1") { Some(self.confirm_real_money(f)) } else { None };
        if let Some(Err(e)) = &confirmed {
            self.flash(ctx, false, format!("Policy applied, but paying with real money is not confirmed yet: {e}"));
            return Resp::redirect("./lightning#ack");
        }
        let real = matches!(confirmed, Some(Ok(true)));
        let ack_needed = !real && self.ack_needed();
        let m = if !pr.is_empty() {
            format!("Policy applied{}. One part waits for the app to restart ({pr}): {}.", if real { ", and the app may now pay with real money within it" } else { "" },
                    self.cfg.restart_hint)
        } else if real {
            "Policy applied, and the app may now pay with real money within it. It is in force now.".into()
        } else if ack_needed {
            "Policy applied. One last step before the app pays: confirm below that it may pay with real money.".into()
        } else {
            "Policy applied; it is in force now.".into()
        };
        self.flash(ctx, true, m);
        Resp::redirect(if ack_needed { "./lightning#ack" } else { back_page(f.get("back").map(String::as_str)).unwrap_or("./policy") })
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
                    let body = self.policy_form(ctx, &cur["policy"], &cur["effective"], &[format!("policy.json: {e}")], &[], &[]);
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
            let body = self.policy_form(ctx, &proposed, &cur["effective"], &strs("errors"), &strs("warnings"), &[]);
            return self.page("Spending rules", ctx, body);
        }
        let mut b = String::from("<p>Check the change, then sign it with your approval key.</p>");
        // a seller the signed rules would leave refused: said before anything is signed
        let checks = self.seller_checks(&proposed);
        b.push_str(&seller_warnings_box(&checks));
        // the sellers by name in the list of changes, not by their made-up `…shop.invalid` addresses
        let named = |d: &str| checks.iter().filter_map(|c| c.rule.origin.as_ref().map(|o| (o, c))).filter(|(o, _)| xbt402::shop::is_shop(o))
            .fold(d.to_string(), |d, (o, c)| d.replace(o.as_str(), &format!("{} ({})", c.name, xbt402::shop::display(o))));
        let diff = prep["diff"].as_array().cloned().unwrap_or_default();
        if diff.is_empty() {
            b.push_str("<p class=\"empty\">No change.</p>");
        } else {
            b.push_str("<ul class=\"changes\">");
            for d in &diff {
                let k = txt(d.get("key"));
                let (head, details) = change_words(&k, d.get("old").filter(|v| !v.is_null()), d.get("new").filter(|v| !v.is_null()));
                let sub = if details.is_empty() { String::new() } else {
                    format!("<ul>{}</ul>", details.iter().map(|x| format!("<li>{}</li>", esc(&named(x)))).collect::<String>())
                };
                b.push_str(&format!("<li>{}{}{sub}</li>", esc(&head),
                                    if d["restart"] == true { " <span class=\"tag warn\">after the app restarts</span>" } else { "" }));
            }
            b.push_str("</ul><details><summary>Advanced: each setting as the signer names it</summary><div class=\"scroll\"><table><thead><tr><th>Setting</th><th>Now</th><th>New</th><th></th></tr></thead><tbody>");
            for d in &diff {
                b.push_str(&format!("<tr><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>", escv(d.get("key")),
                                    esc(&d.get("old").map(|v| v.to_string()).unwrap_or_else(|| "(none)".into())),
                                    esc(&d.get("new").map(|v| v.to_string()).unwrap_or_else(|| "(none)".into())),
                                    if d["restart"] == true { "<span class=\"tag warn\">after restart</span>" } else { "" }));
            }
            b.push_str("</tbody></table></div></details>");
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
        let mut visible = format!("<details><summary>Advanced: the exact text you sign</summary><pre class=\"signed-text\">{}</pre></details>", esc(&text));
        // mainnet, paying not yet confirmed: the yes to real money is one box beside Sign, not a page of its own
        if paying_on(&proposed) && self.real_money_to_confirm() {
            visible.push_str(&format!("<div class=\"flash warn\" id=\"real-money\"><p><strong>This is real money.</strong> Keep your rules low while you try the app.</p>\
                <details><summary>Read before you start</summary>{}</details>\
                <label class=\"check\"><input type=\"checkbox\" name=\"ack\" value=\"1\"> I understand the app pays with real money, within these rules</label></div>",
                crate::setup::notice_html(&crate::setup::WALLET_MAINNET_NOTICE)));
        }
        // the simple view's pages (Limits, a shop to allow) come back to themselves, not to the whole form of rules
        let back = back_page(f.get("back").map(String::as_str));
        let mut hidden = vec![("text", text.clone()), ("prev_sha256", prev.clone()), ("expiry", exp.to_string())];
        if let Some(to) = back {
            hidden.push(("back", to.to_string()));
        }
        b.push_str(&self.signed_form(ctx, "./policy-apply", "policy", &self.human_pub(), &hidden, &visible,
                                     "Sign and apply", Ext::Bytes(msg::policy(&prev, exp, &text))));
        b.push_str(&format!("<p><a href=\"{}\">Cancel</a></p>", back.unwrap_or("./policy")));
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

    /// Each seller's Lightning node (lowercase) and its origin: on file in the spending rules, or vouched
    /// for by its shop. For naming an `ln:<node>` destination by its seller.
    fn seller_nodes(&self) -> Vec<(String, String)> {
        let pol = self.call("policy_get", json!({})).map(|v| v["policy"].clone()).unwrap_or(Value::Null);
        let shops = crate::shops::load(&self.cfg.shops_path()).unwrap_or_default();
        let mut v: Vec<(String, String)> = rule_sellers(&pol).into_iter().filter_map(|r| Some((r.node?.to_ascii_lowercase(), r.origin?))).collect();
        v.extend(shops.iter().filter_map(|(o, sh)| crate::shops::node(sh, o, xbt_nostr::now()).map(|n| (n.to_ascii_lowercase(), o.clone()))));
        v
    }

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
            ("Not yet anchored", escv(a.get("unanchored_lines"))), ("Last sealed", match (int(a.get("anchored_at")), int(a.get("anchored_n"))) {
                // lines sealed with no time on file: said, not a bare "-" beside a count (0.2.1), in plain words (0.2.6 said
                // "its time was not recorded")
                (0, n) if n > 0 => "<span class=\"small\">time not known</span>".into(),
                (0, _) => "none yet".into(),
                (t, _) => utc(t),
            }),
            ("Anchored head", format!("<code>{}</code>", esc(&short(&txt(a.get("anchored_head")), 20)))),
        ]));
        if let Some(e) = s.get("chain").and_then(|c| c.get("anchor_error")).or(s.get("anchor_error")) {
            b.push_str(&Self::error_box(&txt(Some(e))));
        }
        b.push_str(&format!("<form method=\"post\" action=\"./anchor-now\">{}<button class=\"secondary\">Seal the record now</button></form>", Self::csrf_input(ctx)));
        b.push_str("<div class=\"scroll\"><table><thead><tr><th>When</th><th>Kind</th><th>Authorized by</th><th>Method</th><th>Destination</th><th>Signature hash</th></tr></thead><tbody>");
        let rows = s["signatures"].as_array().cloned().unwrap_or_default();
        // the seller, by name, for a destination that is its Lightning node or its address (read only where a row needs it)
        let nodes = if rows.iter().any(|e| txt(e.get("dest")).starts_with("ln:")) { self.seller_nodes() } else { Vec::new() };
        let known = if rows.iter().any(|e| !txt(e.get("dest")).is_empty()) { self.services().unwrap_or_default() } else { Vec::new() };
        for e in rows.iter().rev() {
            let (rule, method) = (txt(e.get("rule")), txt(e.get("method")));
            let kind = txt(e.get("kind"));
            b.push_str(&format!("<tr><td>{}</td><td><span title=\"{}\">{}</span></td><td><span title=\"{}\">{}</span></td><td><span title=\"{}\">{}</span></td><td>{}</td><td><code>{}</code></td></tr>",
                                utc(int(e.get("ts"))), esc(&kind), esc(&kind_words(&kind)),
                                esc(&rule), esc(&rule_words(&rule)), esc(&method), esc(&method_words(&method)),
                                esc(&dest_words(&txt(e.get("dest")), &nodes, &known)), esc(&short(&txt(e.get("sig_sha256")), 16))));
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
                None => "<label>Enrollment code<input name=\"code\" class=\"mono\" autocomplete=\"off\" required placeholder=\"XXXX-XXXX-XXXX\"></label>\
                     <p class=\"hint\">The signer prints a one-time code in its log while no key is enrolled (Umbrel: the app's log; StartOS: Logs; \
                     a server: the signer's stderr or <code>.run/enroll-code</code>).</p>".to_string(),
            };
            format!("<form method=\"post\" action=\"./human-key-enroll\" id=\"enroll-form\" hidden>{}<input type=\"hidden\" name=\"pubkey\" value=\"\">\
                     {code_field}<button>{}</button></form>", Self::csrf_input(ctx),
                    if given.is_some() { "Use this key for approvals" } else { "Enroll this public key with the signer" })
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
            <p class=\"hint\">Before the key is saved, keep its backup in one of two ways: download the backup file and tick the box, \
            or type the backup's last 8 characters.</p>\
            <p><button type=\"button\" id=\"keygen-download\" class=\"secondary\">Download the approval key backup (this is not your passphrase)</button></p>\
            <label class=\"check\"><input type=\"checkbox\" id=\"keygen-saved\" disabled> I saved the downloaded file somewhere safe \
            <small>(download it first)</small></label>\
            <label>…or type the backup's last 8 characters<input id=\"keygen-confirm\" autocomplete=\"off\"></label>\
            <label>Passphrase for this browser (at least 12 characters, not only digits or a repeated pattern)\
            <input id=\"keygen-pin\" type=\"password\" autocomplete=\"new-password\" minlength=\"12\"></label>\
            <p class=\"hint\">This passphrase unlocks the key in this browser each time you approve something. It is not the app's login \
            password, and it is not in the backup file: write it down too.</p>\
            <p id=\"keygen-strength\" class=\"hint\" aria-live=\"polite\">At least 12 characters, not only digits, not a repeated pattern.</p>\
            <label>Passphrase again<input id=\"keygen-pin2\" type=\"password\" autocomplete=\"new-password\" minlength=\"12\"></label>\
            <button type=\"button\" id=\"keygen-save\">Save the key in this browser</button></div>\
            <p id=\"keygen-msg\" class=\"msg\" aria-live=\"polite\"></p>{enroll_form}\
            <p><button type=\"button\" id=\"keygen-forget\" class=\"link\">Remove the key from this browser</button></p></div>")
    }

    /// The signer's gate for PIN calls ([`xbt_signer::pin`]): written beside the enrolment code's copy, readable by
    /// the UI's group only, so the model-facing process cannot try PINs. Empty: none (a development signer).
    fn pin_gate(&self) -> String {
        self.cfg.enroll_code_file.as_ref().and_then(|p| p.parent()).map(|d| d.join("pin-gate"))
            .and_then(|p| std::fs::read_to_string(p).ok()).map(|t| t.trim().to_string()).unwrap_or_default()
    }

    fn pin_status(&self) -> Value {
        self.call("pin_status", json!({})).unwrap_or(Value::Null)
    }

    /// The box's PIN key is the enrolled approval key: signed forms ask for the PIN.
    pub(crate) fn pin_approves(&self) -> bool {
        self.pin_status()["enrolled"] == true
    }

    /// `./api/pin-sign`: the PIN signs one approval message (the page rebuilt it from the fields shown).
    fn api_pin_sign(&self, f: &HashMap<String, String>) -> Resp {
        let g = |k: &str| f.get(k).map(|v| v.trim().to_string()).unwrap_or_default();
        match self.call("approve_with_pin", json!({"pin": g("pin"), "message": g("message"), "gate": self.pin_gate()})) {
            Ok(v) if v["ok"] == true => Resp::json(200, &json!({"signature": v["signature"]})),
            Ok(v) => Resp::json(200, &json!({"error": reason_of(&v), "rule": v["rule"]})),
            Err(e) => Resp::json(200, &json!({"error": e})),
        }
    }

    /// `./pin-set`: the box's PIN key becomes the approval key: with the enrolment code on a box with none yet, or
    /// handed over by the browser key (the form's signature).
    fn pin_set_post(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let g = |k: &str| f.get(k).map(|v| v.trim().to_string()).unwrap_or_default();
        let to = Resp::redirect("./keys#pin");
        if g("new_pin") != g("new_pin2") {
            self.flash(ctx, false, "The two PINs differ: type the same digits twice.");
            return to;
        }
        let gate = self.pin_gate();
        let prep = match self.call("pin_prepare", json!({"gate": gate})) {
            Ok(v) if v["ok"] == true => v,
            Ok(v) => { self.flash(ctx, false, reason_of(&v)); return to; }
            Err(e) => { self.flash(ctx, false, e); return to; }
        };
        let mut p = json!({"pin": g("new_pin"), "gate": gate});
        if prep["needs"] == "code" {
            let file = self.cfg.enroll_code_file.as_ref().and_then(|p| std::fs::read_to_string(p).ok()).map(|c| c.trim().to_string());
            p["code"] = json!(file.filter(|c| !c.is_empty()).unwrap_or_else(|| g("code")));
        } else {
            p["expiry"] = json!(g("expiry").parse::<i64>().unwrap_or(0));
            p["signature"] = json!(g("signature"));
        }
        match self.call("pin_set", p) {
            Ok(v) if v["ok"] == true => self.flash(ctx, true, "PIN set. From now on your PIN approves what spends money; no browser key is needed."),
            Ok(v) => self.flash(ctx, false, reason_of(&v)),
            Err(e) => self.flash(ctx, false, e),
        }
        to
    }

    /// The Keys page's PIN section: set a PIN (with the enrolment code, or handed over by the browser key), or change it.
    fn pin_section(&self, ctx: &Ctx, human: &str) -> String {
        let st = self.pin_status();
        let pins = "<label>PIN (4 to 8 digits)<input name=\"new_pin\" type=\"password\" inputmode=\"numeric\" pattern=\"[0-9]{4,8}\" autocomplete=\"new-password\" required></label>\
                    <label>PIN again<input name=\"new_pin2\" type=\"password\" inputmode=\"numeric\" pattern=\"[0-9]{4,8}\" autocomplete=\"new-password\" required></label>";
        let mut b = String::from("<section class=\"card\" id=\"pin\"><h2>Approve with a PIN</h2>");
        if st["enrolled"] == true {
            b.push_str("<p>Your PIN approves everything that spends money. The key it unlocks is kept on this box, sealed.</p>");
            b.push_str(&format!("<form method=\"post\" action=\"./pin-change\">{}<label>Current PIN<input name=\"pin\" type=\"password\" inputmode=\"numeric\" autocomplete=\"current-password\" required></label>\
                {}<button>Change the PIN</button></form><p class=\"hint\">Forgot it? Reset it from the box's own page (the app's Reset PIN action), then set a new one.</p>",
                Self::csrf_input(ctx), pins.replace("PIN (4", "New PIN (4").replace("PIN again", "New PIN again")));
        } else if st["reset_needed"] == true {
            b.push_str("<p class=\"flash bad\">Too many wrong PINs: reset the PIN from the box's own page.</p>");
        } else if human.is_empty() {
            b.push_str(&format!("<p>Instead of a key in this browser, choose a PIN: the box keeps the approval key, sealed, and uses it only \
                when the right PIN is typed. Five wrong PINs in a row lock approvals for a while.</p>\
                <form method=\"post\" action=\"./pin-set\">{}{pins}<button>Use a PIN for approvals</button></form>", Self::csrf_input(ctx)));
        } else {
            match self.call("pin_prepare", json!({"gate": self.pin_gate()})) {
                Ok(v) if v["ok"] == true => {
                    b.push_str("<p>Switch from the key in this browser to a PIN. Your current key signs the handover once; after that \
                        the PIN approves and the browser key no longer does.</p>");
                    let exp = now() + SIGN_WINDOW_S;
                    b.push_str(&self.signed_form(ctx, "./pin-set", "pin-handover", human, &[("old_pub", human.to_string()), ("pubkey", txt(v.get("pubkey"))),
                                                 ("expiry", exp.to_string())], pins, "Switch to a PIN", Ext::Browser));
                }
                Ok(v) => b.push_str(&format!("<p class=\"hint\">{}</p>", esc(&reason_of(&v)))),
                Err(e) => b.push_str(&format!("<p class=\"hint\">{}</p>", esc(&e))),
            }
        }
        b.push_str("</section>");
        b
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
        let mut b = self.pin_section(ctx, &human);
        b.push_str(&format!("<section class=\"card\" id=\"human-key-state\" data-enrolled=\"{}\"><h2>Your approval key</h2>", esc(&human)));
        b.push_str(&kv(&[("Enrolled public key", if human.is_empty() { "<span class=\"tag bad\">none</span>".into() } else { format!("<code>{}</code>", esc(&human)) })]));
        b.push_str("<p id=\"browser-key\" class=\"msg\"></p>");
        if human.is_empty() {
            b.push_str(&self.keygen_block(ctx, true));
        } else {
            b.push_str("<details id=\"restore\"><summary>Put the enrolled key in this browser, or forgot your passphrase? (from its backup)</summary>");
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
    fn agents(&self, ctx: &Ctx, reveal: bool) -> Resp {
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
                b.push_str(&if reveal {
                    format!("<section class=\"card\" id=\"access-key\"><h3>The access key</h3><p><code id=\"mcp-token\">{}</code></p>\
                             <p>A configuration to paste into an agent that speaks MCP:</p>{}<p><a href=\"./agents\">Hide it</a></p></section>",
                            esc(&t), json_block(&snippet))
                } else {
                    format!("<form method=\"post\" action=\"./agents-key\">{}<button class=\"secondary\">Show the access key</button></form>",
                            Self::csrf_input(ctx))
                });
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
        // a seller counts once: its address and its `ln:` node line are one seller (0.2.1 said "2 sellers" for one)
        let allow_n = rule_sellers(&pol["policy"]).iter().filter(|r| r.listed && r.origin.is_some()).count();
        let step = |done: bool, title: &str, body: String| {
            format!("<li class=\"step {}\"><h2>{}</h2>{body}</li>", if done { "done" } else { "todo" }, esc(title))
        };
        let ln = self.call("ln_status", json!({})).unwrap_or(json!({}));
        let enc = ks["encrypted"] == true;
        let ack_needed = ln["real_money_ack_needed"] == true;
        // on mainnet the rules step takes the yes to real money too (a box beside its Sign): done with both
        // the password is not counted: it is set before any page shows (0.2.14 counted it, and a new install
        // started at 1 here). Home's First steps is another list (it adds a shop and a first purchase and leaves
        // out the backup), so each names its own: First steps with "0 of 5 done" there, "Setup: 0 of 4 done" here
        let done = [!human.is_empty(), seen("policy_change") && !ack_needed, ln["ready"] == true && !ack_needed, enc && seen("backup_export")];
        let n = done.iter().filter(|d| **d).count();
        let total = done.len();
        let mut b = format!("<p class=\"lead\">Setup: {n} of {total} done. The app is safe to leave running after each step: nothing is paid until your rules allow it.</p>\
                             <p class=\"small\"><span class=\"pill good\">Password</span> {}</p><ol class=\"steps\">",
                            if self.platform.is_some() { "Not needed: you opened the app from your box's dashboard, which already asked who you are." }
                            else { "Set. You are logged out after 15 minutes without use." });
        let key_body = if human.is_empty() {
            format!("<p>Your approval key is how you say yes to a large payment or a change of rules. It is made and kept in this browser, \
                     under a passphrase only you know.</p><section id=\"human-key-state\" data-enrolled=\"\"><p id=\"browser-key\" class=\"msg\"></p>{}</section>",
                    self.keygen_block(ctx, true))
        } else {
            format!("<section id=\"human-key-state\" data-enrolled=\"{}\"><p>Made and enrolled.</p><p id=\"browser-key\" class=\"msg\"></p>\
                     <details><summary>Its public half</summary><p><code>{}</code></p></details>\
                     <p><a href=\"./keys\">Keys and backup →</a></p></section>", esc(&human), esc(&human))
        };
        b.push_str(&step(done[0], "Your approval key", key_body));
        b.push_str(&step(done[1], "Your spending rules",
            format!("<p>How much may be spent, and when the app asks you first. The safe starter rules are a good start: {} seller{} allowed now.</p>{}",
                    allow_n, if allow_n == 1 { "" } else { "s" },
                    // mainnet: the yes to real money is a box beside the rules' Sign; signed without it, Your node takes it alone
                    if ack_needed && seen("policy_change") {
                        "<p>This box's Lightning node holds real money. Your rules are signed, but until you confirm that the app may pay \
                         with it, the app pays nothing.</p><p><a href=\"./lightning#ack\">Start paying →</a></p>"
                    } else if ack_needed {
                        "<p>This box's Lightning node holds real money: when you sign, tick the box that says the app pays with real money \
                         within these rules.</p><p><a href=\"./policy?template=starter\">Open the starter rules →</a></p>"
                    } else {
                        "<p><a href=\"./policy?template=starter\">Open the starter rules →</a></p>"
                    })));
        b.push_str(&step(done[2], "Your Lightning node",
            format!("<p>{}</p><p><a href=\"./lightning\">Your node →</a></p>",
                    if done[2] { "Connected and ready to pay.".to_string() }
                    else if ack_needed && ln["ready"] == true { "Connected. Confirm paying with real money with your rules (above) and it is ready.".to_string() }
                    else {
                        let (_, connected, why) = self.node_state();
                        esc(&format!("{} {why}", if connected { "Connected, not ready yet." } else { "Not connected yet." }))
                    })));
        b.push_str(&step(done[3], "A backup",
            format!("<p>The app's keys are {} on this box. {}</p><p><a href=\"./keys\">Download an encrypted backup →</a></p>",
                    if enc { "locked with encryption" } else { "<strong>not</strong> locked with encryption" },
                    if seen("backup_export") { "A backup was exported." } else { "No backup yet." })));
        b.push_str("</ol>");
        b.push_str(&format!("<p class=\"small\" id=\"version\">Lightning Stream version {}</p>", esc(crate::release_version())));
        self.page("Setup", ctx, b)
    }
}


/// One seller the rules name: its address as the rules hold it (`key`), that address as a web origin
/// (none for a coin address), whether it is on the list that may be paid, and the node it is tied to.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RuleSeller {
    pub key: String,
    pub origin: Option<String>,
    pub listed: bool,
    pub node: Option<String>,
}

/// A seller of the rules, as the rules page shows it.
pub(crate) struct SellerCheck {
    rule: RuleSeller,
    name: String,
    /// The node a shop reached by its key vouches for now.
    vouched: Option<String>,
    /// Why the signer will refuse it, in words.
    problem: Option<&'static str>,
    /// No node on file for its address, and paid all the same: its node's `ln:` line covers it.
    through_node: bool,
}

/// The sellers the rules `p` name: those on the list that may be paid, in its order, then those
/// tied to a node only. An address and its node match by web origin.
pub(crate) fn rule_sellers(p: &Value) -> Vec<RuleSeller> {
    let cps = p.get("counterparties").and_then(Value::as_object);
    let same = |a: &str, ao: &Option<String>, b: &str| a == b || (ao.is_some() && crate::services::http_origin(b) == *ao);
    let node_of = |key: &str, origin: &Option<String>| -> Option<String> {
        cps?.iter().find(|(k, _)| same(key, origin, k)).and_then(|(_, v)| v.get("ln_node")).and_then(Value::as_str)
            .map(str::trim).filter(|n| !n.is_empty()).map(str::to_string)
    };
    let mut out: Vec<RuleSeller> = vec![];
    for x in p.get("allowlist").and_then(Value::as_array).into_iter().flatten() {
        let key = txt(Some(x));
        let origin = crate::services::http_origin(&key);
        if key.is_empty() || out.iter().any(|r| same(&key, &origin, &r.key)) {
            continue;
        }
        let node = node_of(&key, &origin);
        out.push(RuleSeller { key, origin, listed: true, node });
    }
    for k in cps.into_iter().flat_map(|m| m.keys()) {
        let origin = crate::services::http_origin(k);
        if out.iter().any(|r| same(k, &origin, &r.key)) {
            continue;
        }
        let node = node_of(k, &origin);
        out.push(RuleSeller { key: k.clone(), origin, listed: false, node });
    }
    out
}

/// Whether the rules `p` let the signer pay the seller at `origin`, as its `ticket_listed` decides: the
/// seller's address on the list with its node on file, or `ln:<node>` on the list for its node on file
/// or for `known_node` (the node its shop entry vouches for). 0.2.2 called a seller allowed only through
/// its address and node, and said Genesis, allowed by its `ln:` line, could not be paid.
pub(crate) fn rules_allow(p: &Value, origin: &str, known_node: Option<&str>) -> bool {
    let o = crate::services::http_origin(origin);
    let rows = rule_sellers(p);
    let me = rows.iter().find(|r| r.origin.is_some() && r.origin == o);
    if me.is_some_and(|r| r.listed && r.node.is_some()) {
        return true;
    }
    let list: Vec<String> = p.get("allowlist").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str)
        .map(|x| x.trim().to_ascii_lowercase()).collect();
    let nodes = [me.and_then(|r| r.node.as_deref()), known_node];
    let covered = nodes.into_iter().flatten().any(|n| list.contains(&format!("ln:{}", n.trim().to_ascii_lowercase())));
    covered
}

/// Whether the rules `p` let the signer pay any seller: one of the rules' own, or a shop added in the
/// app (`shops`: its origin and the node its entry vouches for), as [`rules_allow`] decides. Home's
/// Get started counted only a seller listed by its address with its node on file, so a shop allowed
/// through its node's `ln:` line never counted.
pub(crate) fn any_seller_allowed(p: &Value, shops: &[(String, Option<String>)]) -> bool {
    rule_sellers(p).into_iter().filter_map(|r| r.origin).map(|o| (o, None)).chain(shops.iter().cloned())
        .any(|(o, node)| rules_allow(p, &o, node.as_deref()))
}

/// The node of an `ln:<node>` line of the rules, if `key` is one.
pub(crate) fn ln_line_node(key: &str) -> Option<&str> {
    key.strip_prefix("ln:").map(str::trim).filter(|n| n.len() == 66 && n.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A refused payment of the history as the refusal pages say it ([`crate::pay_feedback::explain`], and the
/// node's own limits as Your node says them): (what, the words). `None` for anything that is not a refusal.
/// 0.2.2 showed the signer's own words ("Ln refused … the LN node holds 287070 sats … above ln.…").
pub(crate) fn refusal_words(e: &Value) -> Option<(String, String)> {
    let t = e["type"].as_str().unwrap_or("");
    let refused = t.ends_with("_refused") || t.ends_with("_denied") || t.ends_with("_refused_by_policy") || (t == "decision" && e["verdict"] == "deny");
    let reason = txt(e.get("reason"));
    if !refused || reason.is_empty() {
        return None;
    }
    let rule = txt(e.get("rule"));
    let x = crate::pay_feedback::explain(&json!({"reason": reason, "rule": rule}).to_string(), None, false);
    if x.kind != crate::pay_feedback::Kind::Other {
        return Some((x.title, format!("{} {}", x.words, x.fix).trim().to_string()));
    }
    let plain = crate::setup::plain_reason(&reason);
    Some(("Not paid".into(), if plain.starts_with("Your node said:") { format!("The wallet did not pay. {reason}") } else { format!("Not paid. {plain}") }))
}

/// Whether the wallet's event `e` is a row of Recent activity, among `all` the page read. Left out: a reservation's
/// bookkeeping (its booking made what was paid), the signer's start (no shop to name), a prepaid ticket's booking and
/// payment where the reservation and the exact Paid row of the same payment say them (0.2.6 showed both, rounded and exact).
pub(crate) fn activity_row(e: &Value, all: &[Value]) -> bool {
    let hash = e["payment_hash"].as_str().unwrap_or("");
    match e["type"].as_str() {
        Some("ln_amend" | "ticket_start") => false,
        Some("ticket_prepay") if !hash.is_empty() => !all.iter().any(|x| x["type"] == "commit" && x["txid"].as_str() == Some(&format!("ticket:{hash}"))),
        Some("ticket_prepaid") if !hash.is_empty() => {
            !all.iter().any(|x| matches!(x["type"].as_str(), Some("ticket_settled" | "ln_settled")) && x["payment_hash"].as_str() == Some(hash))
        }
        _ => true,
    }
}

/// One row a payment (0.2.11 showed three: "Allowed", "Reserved", "Paid"). Among `all` (oldest first), the steps before a
/// payment's outcome fold into a later row of the same payment: its reservation (a `commit` of `ln:`/`ticket:<hash>`, a
/// `ticket_prepay`) into its Paid or failed row, by the payment's hash; the allowed decision, which names no hash, into the
/// first reservation after it to the same seller of the same amount, within minutes (the signer books the very payment it
/// allowed, in the same call). A step with no outcome yet stays a row: the reservation, in progress. A refusal, an approval
/// asked for, or a decision with no reservation after it stays a row of its own. By event index: the row each step folds into.
pub(crate) fn activity_folds(all: &[Value]) -> HashMap<usize, usize> {
    let hash_of = |e: &Value| -> Option<String> {
        match e["type"].as_str() {
            Some("commit") => { let t = txt(e.get("txid")); t.strip_prefix("ln:").or(t.strip_prefix("ticket:")).filter(|h| !h.is_empty()).map(str::to_string) }
            Some("ticket_prepay") => e["payment_hash"].as_str().filter(|h| !h.is_empty()).map(str::to_string),
            _ => None,
        }
    };
    let booked = |e: &Value| int(e.get("amount_sats").or(e.get("booked_sats")));
    let mut into: HashMap<usize, usize> = HashMap::new();
    // a reservation into its payment's outcome: the latest one the page shows (a later settle tells more than a failure)
    for (i, e) in all.iter().enumerate() {
        let Some(h) = hash_of(e).filter(|_| activity_row(e, all)) else { continue };
        let outcome = all.iter().enumerate().skip(i + 1).rev().find(|(_, x)| {
            matches!(x["type"].as_str(), Some("ticket_settled" | "ln_settled" | "ticket_prepaid" | "ln_failed" | "ticket_failed"))
                && x["payment_hash"].as_str() == Some(&h) && activity_row(x, all)
        });
        if let Some((j, _)) = outcome {
            into.insert(i, j);
        }
    }
    // an allowed decision into the reservation it allowed: one decision a reservation
    let mut claimed: Vec<usize> = Vec::new();
    for (i, e) in all.iter().enumerate() {
        if e["type"] != "decision" || e["verdict"] != "allow" {
            continue;
        }
        let r = all.iter().enumerate().skip(i + 1).find(|(j, x)| {
            hash_of(x).is_some() && activity_row(x, all) && !claimed.contains(j) && x["dest"] == e["dest"] && booked(x) == int(e.get("amount_sats"))
                && (int(x.get("ts")) - int(e.get("ts"))).abs() <= 300
        });
        if let Some((j, _)) = r {
            claimed.push(j);
            into.insert(i, into.get(&j).copied().unwrap_or(j));
        }
    }
    into
}

/// What a row's folded steps said ([`activity_folds`]), small and behind a click: "Allowed and reserved first".
pub(crate) fn activity_steps(all: &[Value], folds: &HashMap<usize, usize>, row: usize) -> String {
    let mut steps: Vec<usize> = folds.iter().filter(|&(_, &to)| to == row).map(|(&from, _)| from).collect();
    if steps.is_empty() {
        return String::new();
    }
    steps.sort_unstable();
    let allowed = steps.iter().any(|&i| all[i]["type"] == "decision");
    let reserved = steps.iter().any(|&i| all[i]["type"] != "decision");
    let said: Vec<String> = steps.iter().map(|&i| {
        let e = &all[i];
        if e["type"] == "decision" {
            let d = activity_detail(e, false);
            if d.is_empty() { "Allowed".into() } else { format!("Allowed: {d}") }
        } else {
            format!("{} reserved, the most it may cost", money(int(e.get("amount_sats").or(e.get("booked_sats")))))
        }
    }).collect();
    let title = match (allowed, reserved) { (true, true) => "Allowed and reserved first", (true, false) => "Allowed first", _ => "Reserved first" };
    format!(" <details><summary>{title}</summary>{}</details>", said.join(" · "))
}

/// A row's Detail in plain words: the signer's word where it is one a person reads, nothing where it is an id
/// (0.2.6 showed `ticket:<hash>` and "all policy rules passed").
pub(crate) fn activity_detail(e: &Value, reserved: bool) -> String {
    if reserved {
        return String::new();
    }
    let said = txt(e.get("reason").or(e.get("txid")));
    match e["type"].as_str() {
        Some("decision") if e["verdict"] == "allow" && (e["rule"] == "ok" || said == "all policy rules passed") => "Within your spending rules".into(),
        Some("ticket_seller_forgot") => "A new one was opened".into(),
        _ if said.starts_with("ticket:") || said.starts_with("ln:") => String::new(),
        _ => esc(&short(&said, 80)),
    }
}

/// The credit left with each shop once its connections closed, by origin, in msat: from the wallet's
/// history (oldest first), the newest `ticket_left_with_seller` of each shop's node, until a later
/// session with that node opens (it is then that session's, drawn first) or the credit is given up.
/// About: the shop's own count may differ by what was in flight.
pub(crate) fn credit_left(events: &[Value]) -> HashMap<String, u64> {
    let msat = |v: Option<&Value>| v.and_then(|x| x.as_u64().or_else(|| x.as_str().and_then(|s| s.parse().ok())));
    // by the seller's node: (origin, session, msat)
    let mut by_dest: HashMap<String, (String, String, u64)> = HashMap::new();
    for e in events {
        let dest = txt(e.get("dest"));
        match e["type"].as_str() {
            Some("ticket_left_with_seller") => match (crate::services::http_origin(&txt(e.get("origin"))), msat(e.get("left_msat"))) {
                (Some(o), Some(m)) if m > 0 => { by_dest.insert(dest, (o, txt(e.get("session")), m)); }
                _ => { by_dest.remove(&dest); }
            },
            Some("ticket_open" | "ticket_session_again") => { by_dest.remove(&dest); }
            Some("ticket_credit_given_up") => {
                let sid = txt(e.get("session"));
                by_dest.retain(|_, v| v.1 != sid);
            }
            _ => {}
        }
    }
    let mut out = HashMap::new();
    for (o, _, m) in by_dest.into_values() {
        *out.entry(o).or_insert(0) += m;
    }
    out
}

/// "You have about 476 sat of credit with …": the line Sellers and a service's page show.
pub(crate) fn credit_line(name: &str, msat: u64) -> String {
    format!("<p class=\"credit\"><span class=\"pill good\">Credit</span> You have about {} sat of credit with {}; it's used first next time.</p>",
            crate::html::group3(msat.saturating_add(500) / 1000), esc(name))
}

/// The warning over the rules: each seller the signer will refuse, by name, and why.
fn seller_warnings_box(checks: &[SellerCheck]) -> String {
    let bad: Vec<String> = checks.iter().filter_map(|c| c.problem.map(|why| format!("<li><strong>{}</strong>: {}.</li>", esc(&c.name), esc(why)))).collect();
    if bad.is_empty() {
        return String::new();
    }
    format!("<div class=\"flash bad seller-warning\"><p>Check who may be paid:</p><ul>{}</ul><p>Remove it below, then allow it again from \
             <a href=\"./services\">Sellers</a>, or use the fix shown next to it.</p></div>", bad.concat())
}

/// A node id, short: `02abcdef…12345678`.
/// What authorized a signature, as the Records page says it (`policy:ok` is your spending rules).
/// The signer's own word stays in the cell's tooltip.
pub(crate) fn rule_words(rule: &str) -> String {
    match rule {
        "policy:ok" | "policy" => "Your spending rules".into(),
        "watcher:auto_refund" => "Automatic refund".into(),
        "unattributed" | "" => "Not recorded".into(),
        "ticket_refused" => "A ticket your rules refused".into(),
        r if r.starts_with("approval") || r.starts_with("human:") => "Your approval key".into(),
        r if r.starts_with("method:") => "The signer's own rule for this kind of request".into(),
        r if r.starts_with("watcher:") => "The payment watcher".into(),
        r => capital(&r.replace([':', '_'], " ")),
    }
}

/// A signed record's kind, in words (the signer's own word in the cell's tooltip): 0.2.6 showed `ticket_settled`.
pub(crate) fn kind_words(kind: &str) -> String {
    match kind {
        "ticket_settled" => "Ticket paid".into(),
        "ticket_prepay" => "Ticket paid ahead".into(),
        "ticket_release" => "Ticket released, not paid".into(),
        "ln_payment" => "Lightning payment".into(),
        "lottery_win_pay" => "Winning draw paid".into(),
        "human_sweep" => "Coins sent, with your approval".into(),
        "rotation_sweep" => "Coins moved to a new key".into(),
        "retired_sweep" => "Coins moved from a retired key".into(),
        "" => "—".into(),
        k => capital(&k.replace('_', " ")),
    }
}

/// The signer's method, in words (`xbt402_pay` is paying a service).
pub(crate) fn method_words(method: &str) -> String {
    match method {
        "xbt402_pay" => "Paid a service".into(),
        "" => "—".into(),
        m if m.starts_with("ticket_") => "Stream ticket".into(),
        m if m.starts_with("ln_") => "Lightning payment".into(),
        m if m.starts_with("policy_") => "Spending rules".into(),
        m => capital(&m.replace('_', " ")),
    }
}

/// A destination as a person reads it: `ln:<node>` as "Lightning node of <seller>" (`nodes`, from
/// [`App::seller_nodes`]), a shop's address by its name, never its `…shop.invalid` address.
pub(crate) fn dest_words(d: &str, nodes: &[(String, String)], known: &[crate::services::Service]) -> String {
    if let Some(n) = d.strip_prefix("ln:").map(str::trim) {
        return match nodes.iter().find(|(x, _)| x.eq_ignore_ascii_case(n)) {
            Some((_, o)) => format!("Lightning node of {}", crate::services::seller_name(known, o)),
            None => format!("Lightning node {}", short_node(n)),
        };
    }
    match crate::services::http_origin(d) {
        Some(o) if xbt402::shop::is_shop(&o) || crate::services::shop_name(known, &o).is_some() => crate::services::seller_name(known, &o),
        _ => short(d, 40),
    }
}

fn short_node(n: &str) -> String {
    if n.len() <= 20 || !n.is_ascii() { n.to_string() } else { format!("{}…{}", &n[..8], &n[n.len() - 8..]) }
}

/// `s` with its first letter in capitals.
fn capital(s: &str) -> String {
    let mut c = s.chars();
    c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
}

/// The relative way from `path` to the app's root, as a link on its page: `./` for a page at the top (`/hashrate`), one
/// `../` for each level below it (`/hashrate/gateway/threads`: `../../`), so a redirect lands at the top under any base path.
fn to_root(path: &str) -> String {
    match path.matches('/').count().saturating_sub(1) {
        0 => "./".to_string(),
        n => "../".repeat(n),
    }
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
/// A rule's name as the owner reads it (the form's label without its unit), or the setting's own
/// name where the form has no field for it.
fn setting_name(k: &str) -> String {
    match INT_KEYS.iter().find(|(key, _, _)| *key == k) {
        Some((_, label, _)) => label.split(" (").next().unwrap_or(label).trim_end_matches('…').to_string(),
        None => match k {
            "ln" => "Paying over Lightning".into(),
            "tickets" => "Pay-as-you-go tickets".into(),
            "allowlist" => "Sellers that may be paid".into(),
            "counterparties" => "Sellers paid through their Lightning node".into(),
            "anchor_required" => "Refuse to start without the record keeper".into(),
            "regtest_mine" => "Mining blocks on a test chain".into(),
            "anchor_interval_s" => "How often the record keeper is asked".into(),
            "human_pubkey" => "Your approval key".into(),
            other => format!("The setting {other}"),
        },
    }
}

/// The most nested changes listed under one rule; the rest are in Advanced.
const MAX_DETAILS: usize = 40;

/// One change of the rules in a sentence, with its unit: what the owner reviews before signing.
/// A rule that holds settings of its own (Lightning, tickets, the sellers) comes with each of its
/// changes, key by key, so that no change is signed unseen.
fn change_words(k: &str, old: Option<&Value>, new: Option<&Value>) -> (String, Vec<String>) {
    let name = setting_name(k);
    let unit = INT_KEYS.iter().find(|(key, _, _)| *key == k).map(|(_, label, _)| {
        if label.contains("(sats") { "sats" } else if label.contains("seconds") { "seconds" } else if label.contains("(blocks") { "blocks" } else { "" }
    });
    let count = |v: Option<&Value>| v.and_then(|v| v.as_array().map(Vec::len).or(v.as_object().map(|m| m.len()))).unwrap_or(0);
    let on = |v: Option<&Value>| v.and_then(|v| v.get("enabled")) == Some(&Value::Bool(true));
    let word = |b: bool| if b { "on" } else { "off" };
    let mut details = vec![];
    let head = match (k, unit) {
        (_, Some(u)) => {
            let f = |v: Option<&Value>| match v.and_then(Value::as_i64) {
                Some(n) if u == "sats" => plain_sats(n),
                Some(n) => format!("{n} {u}").trim_end().to_string(),
                None => v.map(|v| v.to_string()).unwrap_or_else(|| "not set".into()),
            };
            return (match old {
                Some(_) => format!("{name}: {} (was {})", f(new), f(old)),
                None => format!("{name}: {}", f(new)),
            }, vec![]);
        }
        ("anchor_required", _) => return (format!("{name}: {}", if new == Some(&Value::Bool(true)) { "yes" } else { "no" }), vec![]),
        ("ln" | "tickets", _) => {
            leaf_changes("", old, new, &mut details);
            details.retain(|d| !d.starts_with("enabled:"));
            // the stream tickets' budget by its field's label
            if k == "tickets" {
                let label = TICKETS_BUDGET_LABEL.split(" (sats)").next().unwrap_or(TICKETS_BUDGET_LABEL);
                for d in &mut details {
                    if let Some(rest) = d.strip_prefix("tasks › default › budget_sats:") {
                        *d = format!("{label}:{rest}");
                    }
                    for (raw, words) in [("tasks › hashrate › budget_sats:", "Renting hashrate, most in its window:"),
                                         ("tasks › hashrate › rental › max_ticket_sats:", "Renting hashrate, largest ticket for a rental:"),
                                         ("tasks › hashrate › rental › max_sends_per_hour:", "Renting hashrate, most payments an hour for a rental:")] {
                        if let Some(rest) = d.strip_prefix(raw) {
                            *d = format!("{words}{rest}");
                        }
                    }
                }
            }
            match old {
                Some(_) if on(old) == on(new) => format!("{name}: {}", word(on(new))),
                Some(_) => format!("{name}: {} (was {})", word(on(new)), word(on(old))),
                None => format!("{name}: {}", word(on(new))),
            }
        }
        ("allowlist" | "counterparties", _) => {
            leaf_changes("", old, new, &mut details);
            format!("{name}: {} (was {})", count(new), count(old))
        }
        _ => {
            leaf_changes("", old, new, &mut details);
            format!("{name} changes")
        }
    };
    if details.len() > MAX_DETAILS {
        let more = details.len() - MAX_DETAILS;
        details.truncate(MAX_DETAILS);
        details.push(format!("and {more} more: see Advanced"));
    }
    (head, details)
}

/// Every change between two values, key by key: `section › key: new (was old)`. A list of plain values is
/// told as what it adds and removes.
fn leaf_changes(path: &str, old: Option<&Value>, new: Option<&Value>, out: &mut Vec<String>) {
    if old == new {
        return;
    }
    let at = |k: &str| if path.is_empty() { k.to_string() } else { format!("{path} › {k}") };
    match (old, new) {
        (Some(Value::Object(_)) | None, Some(Value::Object(_))) | (Some(Value::Object(_)), None) => {
            let (a, b) = (old.and_then(Value::as_object), new.and_then(Value::as_object));
            let mut keys: Vec<&String> = a.into_iter().flat_map(|m| m.keys()).chain(b.into_iter().flat_map(|m| m.keys())).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                leaf_changes(&at(k), a.and_then(|m| m.get(k)), b.and_then(|m| m.get(k)), out);
            }
        }
        (Some(Value::Array(a)), Some(Value::Array(b))) if a.iter().chain(b).all(|v| !v.is_object() && !v.is_array()) => {
            let label = if path.is_empty() { String::new() } else { format!("{path}: ") };
            out.extend(b.iter().filter(|v| !a.contains(v)).map(|v| format!("{label}adds {}", plain_value(path, Some(v)))));
            out.extend(a.iter().filter(|v| !b.contains(v)).map(|v| format!("{label}removes {}", plain_value(path, Some(v)))));
        }
        (Some(_), None) => out.push(format!("{path}: removed (was {})", plain_value(path, old))),
        (None, _) => out.push(format!("{path}: {}", plain_value(path, new))),
        _ => out.push(format!("{path}: {} (was {})", plain_value(path, new), plain_value(path, old))),
    }
}

/// A setting's value in full, as the owner reads it: sats grouped, switches on or off.
fn plain_value(path: &str, v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "not set".into(),
        Some(Value::Number(n)) if path.ends_with("_sats") && n.as_i64().is_some() => plain_sats(n.as_i64().unwrap_or(0)),
        Some(Value::Bool(b)) if path.ends_with("enabled") => (if *b { "on" } else { "off" }).into(),
        Some(Value::Bool(b)) => (if *b { "yes" } else { "no" }).into(),
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
    }
}

/// Sats in plain text, grouped: "5,000 sats".
fn plain_sats(n: i64) -> String {
    format!("{}{} sats", if n < 0 { "-" } else { "" }, crate::html::group3(n.unsigned_abs()))
}

/// Millisats as sats, with the fraction where there is one: 68244 is "68.244".
fn sats_of_msat(m: u64) -> String {
    if m.is_multiple_of(1000) { (m / 1000).to_string() } else { format!("{}.{:03}", m / 1000, m % 1000).trim_end_matches('0').to_string() }
}

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
    http_get_with(url, &[])
}

/// [`http_get`] with extra request headers (the gateway's health token).
pub fn http_get_with(url: &str, headers: &[(&str, &str)]) -> Result<(u16, String), String> {
    let _timed = crate::perf::Upstream::start();
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
    let extra: String = headers.iter().map(|(k, v)| format!("{k}: {v}\r\n")).collect();
    s.write_all(format!("GET {path} HTTP/1.0\r\nHost: {hostport}\r\n{extra}Connection: close\r\n\r\n").as_bytes()).map_err(|e| e.to_string())?;
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

/// The smallest prepaid ticket a seller may sell, in sats: the protocol's dust floor
/// ([`xbt402::ticket::MIN_HELD_TICKET_MSAT`], 546 sat). A listing does not name its shop's own
/// smallest ticket, so this is the least a first call to a seller the buyer has no credit with needs.
pub const MIN_TICKET_SATS: i64 = (xbt402::ticket::MIN_HELD_TICKET_MSAT / 1000) as i64;

/// What the signer books for that ticket at its default routing-fee limit (10 sat + 5,000 ppm),
/// 559 sat: the least `max_sats` a call to a seller with no credit buys a ticket with. Less pays
/// nothing ("call again with max_sats of at least 559").
pub const MIN_CALL_SATS: i64 = {
    let t = xbt402::ticket::MIN_HELD_TICKET_MSAT / 1000;
    (t + 10 + (t * 5_000).div_ceil(1_000_000)) as i64
};

/// The `max_sats` of one relayed call for `bytes` of a listed file at the listing's `ceiling`
/// ([`crate::services::Service::price_ceiling`]): its price with 2% slack, and never under
/// [`MIN_CALL_SATS`]. A file that costs less than a ticket still buys one whole ticket on a first
/// call, and what the file does not use stays as credit with the seller. The owner's spending rules
/// still bound every payment; this is only the call's own limit.
pub fn file_call_sats(ceiling: &Value, bytes: u64) -> i64 {
    let n = |k: &str| ceiling.get(k).and_then(Value::as_u64).unwrap_or(0) as u128;
    let msat = n("request_msat") + (n("gib_msat") * u128::from(bytes)).div_ceil(1 << 30);
    let sats = (msat * 102 / 100).div_ceil(1000) + 1;
    i64::try_from(sats).unwrap_or(i64::MAX).max(MIN_CALL_SATS)
}

#[cfg(test)]
mod back_tests {
    /// A change comes back to Limits or Shops, and to no address a form could be made to carry.
    #[test]
    fn a_rules_change_goes_back_to_one_of_the_apps_own_pages_only() {
        assert_eq!(super::back_page(Some("./limits")), Some("./limits"));
        assert_eq!(super::back_page(Some("./browse")), Some("./browse"));
        for other in ["https://elsewhere.example", "//elsewhere.example", "./limits?x=1", "", "./keys"] {
            assert_eq!(super::back_page(Some(other)), None, "{other}");
        }
        assert_eq!(super::back_page(None), None);
    }
}

#[cfg(test)]
mod file_call_tests {
    use super::*;

    /// Big Buck Bunny at Lightning Stream Genesis: 276 MB at 1,000 sat/GB is about 284 sat with the
    /// slack, under the smallest ticket's 559: the call's limit is a whole ticket, not the file's price.
    #[test]
    fn a_small_file_call_can_buy_the_smallest_ticket() {
        assert_eq!((MIN_TICKET_SATS, MIN_CALL_SATS), (546, 559));
        let genesis = xbt402::listing::price_ceiling(&json!({"byte_msat": 1_000_000, "per_bytes": 1_000_000_000u64}));
        let bunny = crate::files::size_most("276 MB").unwrap();
        // its price alone, with the slack: the 284 sat limit the signer refused
        let n = |k: &str| genesis[k].as_u64().unwrap() as u128;
        let price = ((n("request_msat") + (n("gib_msat") * u128::from(bunny)).div_ceil(1 << 30)) * 102 / 100).div_ceil(1000) + 1;
        assert_eq!(price, 284);
        assert_eq!(file_call_sats(&genesis, bunny), 559, "a 276 MB file buys one 546-sat ticket");
        assert_eq!(file_call_sats(&genesis, 4 << 20), 559, "and so does a player's 4 MiB part");
        // a file that costs more than a ticket keeps its own price
        assert_eq!(file_call_sats(&genesis, 2_000_000_000), 2_042);
    }
}

#[cfg(test)]
mod change_tests {
    use super::*;

    /// Records and the Wallet say who authorized a signature, what it was and where it went in words:
    /// not `policy:ok`, `xbt402_pay` or `ln:035d…`.
    #[test]
    fn a_record_is_said_in_words() {
        assert_eq!(rule_words("policy:ok"), "Your spending rules");
        assert_eq!(rule_words("human:approval_signature"), "Your approval key");
        assert_eq!(method_words("xbt402_pay"), "Paid a service");
        let node = format!("02{}", "ab".repeat(32));
        let nodes = vec![(node.clone(), "https://films.example".to_string())];
        let shop = crate::services::Service { name: "Demo Films".into(), kind: crate::services::Kind::Api, seller: "https://films.example".into(),
            price_text: String::new(), prices: Value::Null, items: vec![], address: String::new(), app: String::new(), app_base: String::new() };
        assert_eq!(dest_words(&format!("ln:{node}"), &nodes, std::slice::from_ref(&shop)), "Lightning node of Demo Films");
        assert!(dest_words(&format!("ln:03{}", "cd".repeat(32)), &nodes, &[shop]).starts_with("Lightning node 03cdcdcd…"));
    }

    /// The rules form takes whole sellers out, and nothing else: a node is never cut off by an edit
    /// (0.2.1: a node wrapped in a free-text box and was saved without it), and a form with no list of
    /// sellers (an older page) keeps them as they are.
    ///
    /// Rules signed before the hashrate task (VM 118): only that task is added, at the starter values for the chain,
    /// and every other field is as signed, compared field by field.
    #[test]
    fn the_hashrate_task_is_added_alone_at_the_starter_values() {
        let signed = json!({"allowlist": ["https://a.example"], "counterparties": {"https://a.example": {"ln_node": "02".repeat(33)}},
                            "max_per_tx_sats": 1234, "daily_budget_sats": 5678, "human_pubkey": "ab".repeat(32), "anchor_required": true,
                            "ln": {"enabled": true, "exposure_cap_sats": 3_000_000, "split_height": MAINNET_SPLIT_HEIGHT},
                            "tickets": {"enabled": true, "mainnet_ack": "yes", "max_ticket_sats": 5000, "tasks": {"default": {"budget_sats": 7777, "window_s": 3600}}},
                            "some_future_key": [1, 2]});
        assert_eq!(rent_rules(&signed), RentRules::NoTask);
        for chain in ["main", "regtest"] {
            let q = with_hashrate_task(&signed, chain).unwrap();
            assert_eq!(rent_rules(&q), RentRules::Allowed);
            assert_eq!(q["tickets"]["tasks"][HASHRATE_TASK], starter_policy(chain)["tickets"]["tasks"]["hashrate"], "{chain}");
            let (a, b) = (signed.as_object().unwrap(), q.as_object().unwrap());
            assert_eq!(a.keys().collect::<Vec<_>>(), b.keys().collect::<Vec<_>>());
            for (k, v) in a {
                if k == "tickets" {
                    let (ta, tb) = (v.as_object().unwrap(), b[k].as_object().unwrap());
                    assert_eq!(ta.keys().collect::<Vec<_>>(), tb.keys().collect::<Vec<_>>());
                    for (tk, tv) in ta {
                        if tk == "tasks" {
                            let mut want = tv.as_object().unwrap().clone();
                            want.insert(HASHRATE_TASK.into(), starter_hashrate_task(chain));
                            assert_eq!(tb[tk], Value::Object(want), "{chain}");
                        } else {
                            assert_eq!(&tb[tk], tv, "{chain} tickets.{tk}");
                        }
                    }
                } else {
                    assert_eq!(&b[k], v, "{chain} {k}");
                }
            }
        }
        assert_eq!(starter_hashrate_task("main"), json!({"budget_sats": STARTER_RENTAL_BUDGET_SATS, "rental": {"max_ticket_sats": 10_000, "max_sends_per_hour": 600}}));
        assert_eq!(starter_hashrate_task("regtest"), json!({"budget_sats": 100000}));
        // already there, or tickets off: nothing to add
        assert_eq!(with_hashrate_task(&starter_policy("main"), "main"), None);
        assert_eq!(rent_rules(&json!({"tickets": {"enabled": false, "tasks": {}}})), RentRules::TicketsOff);
        assert_eq!(rent_rules(&json!({})), RentRules::TicketsOff);
        assert_eq!(with_hashrate_task(&json!({"tickets": {"enabled": false}}), "main"), None);
        // a tickets section with no tasks gets one
        let q = with_hashrate_task(&json!({"tickets": {"enabled": true}}), "regtest").unwrap();
        assert_eq!(q, json!({"tickets": {"enabled": true, "tasks": {"hashrate": {"budget_sats": 100000}}}}));
    }

    /// FAILS before: the parse read free text, and a line with no node dropped `ln_node`.
    #[test]
    fn the_rules_form_takes_whole_sellers_out_and_never_a_node() {
        let shop = xbt402::shop::origin_for(&[4u8; 32]);
        let node = format!("02{}", "a".repeat(64));
        let cur = json!({"allowlist": ["https://a.example", "bc1qcoin", shop], "human_threshold_sats": 1,
                         "counterparties": {shop.clone(): {"ln_node": node, "pay_to": "x"}, "https://a.example": {"ln_node": "03bb"}, "https://b.example": {"ln_node": "03cc"}}});
        let sellers = json!({"allowlist": cur["allowlist"], "counterparties": cur["counterparties"]}).to_string();
        let form = |extra: &[(&str, &str)]| -> HashMap<String, String> {
            let mut f: HashMap<String, String> = extra.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            f.insert("f_human_threshold_sats".into(), "5".into());
            f
        };
        // untouched: every seller and node as it was (the old on-chain payTo key left out)
        let p = App::proposed_from_form(&cur, &form(&[("f_sellers", &sellers)]));
        assert_eq!(p["counterparties"][&shop], json!({"ln_node": node}));
        assert_eq!(p["allowlist"], cur["allowlist"]);
        // one removed: gone from both lists, the others whole
        let p = App::proposed_from_form(&cur, &form(&[("f_sellers", &sellers), ("f_drop_0", "https://a.example/")]));
        assert_eq!(p["allowlist"], json!(["bc1qcoin", shop]));
        assert!(p["counterparties"].get("https://a.example").is_none() && p["counterparties"][&shop]["ln_node"] == json!(node), "{p}");
        // an older page's free text, with the node cut off, and no list: nothing changes
        let p = App::proposed_from_form(&cur, &form(&[("f_allowlist", &shop), ("f_counterparties", &shop)]));
        assert_eq!((p["allowlist"].clone(), p["counterparties"].clone()), (cur["allowlist"].clone(), cur["counterparties"].clone()));
        assert_eq!(p["human_threshold_sats"], 5);
        // the rows: on the list in order (a coin address too), then a node alone
        let rows = rule_sellers(&cur);
        assert_eq!(rows.iter().map(|r| (r.key.as_str(), r.listed, r.node.as_deref())).collect::<Vec<_>>(),
                   vec![("https://a.example", true, Some("03bb")), ("bc1qcoin", true, None), (shop.as_str(), true, Some(node.as_str())),
                        ("https://b.example", false, Some("03cc"))]);
    }

    #[test]
    fn a_nested_change_is_shown_key_by_key_and_never_hidden_behind_a_count() {
        // a seller's node swapped for another: the same number of sellers
        let (head, d) = change_words("counterparties", Some(&json!({"stream": {"ln_node": "03aa"}})), Some(&json!({"stream": {"ln_node": "02bb"}})));
        assert_eq!((head.as_str(), d), ("Sellers paid through their Lightning node: 1 (was 1)", vec!["stream › ln_node: 02bb (was 03aa)".to_string()]));
        // one seller swapped for another on the allowlist
        let (_, d) = change_words("allowlist", Some(&json!(["a", "b", "c"])), Some(&json!(["a", "b", "evil"])));
        assert_eq!(d, vec!["adds evil".to_string(), "removes c".to_string()]);
        // Lightning turned on with its exposure cap in the same change
        let (head, d) = change_words("ln", Some(&json!({"enabled": false})), Some(&json!({"enabled": true, "exposure_cap_sats": 100_000})));
        assert_eq!((head.as_str(), d), ("Paying over Lightning: on (was off)", vec!["exposure_cap_sats: 100,000 sats".to_string()]));
        // a ticket cap, deep in its section
        let (_, d) = change_words("tickets", Some(&json!({"enabled": true, "seller_max_locked_sats": 2_000, "tasks": {"film": {"budget_sats": 10_000}}})),
                                  Some(&json!({"enabled": true, "seller_max_locked_sats": 9_000, "tasks": {"film": {"budget_sats": 50_000}}})));
        assert_eq!(d, vec!["seller_max_locked_sats: 9,000 sats (was 2,000 sats)".to_string(), "tasks › film › budget_sats: 50,000 sats (was 10,000 sats)".to_string()]);
        // values are never cut, and a long list points at Advanced
        let long = "x".repeat(400);
        let (_, d) = change_words("counterparties", None, Some(&json!({"s": {"note": long}})));
        assert!(d[0].ends_with(&long), "{d:?}");
        let many: serde_json::Map<String, Value> = (0..50).map(|i| (format!("k{i:02}"), json!(i))).collect();
        let (_, d) = change_words("ln", None, Some(&Value::Object(many)));
        assert_eq!((d.len(), d.last().map(String::as_str)), (MAX_DETAILS + 1, Some("and 10 more: see Advanced")));
    }
}

#[cfg(test)]
mod handson_0202_tests {
    use super::*;

    /// Mike's rules (0.2.2 hands-on): Genesis by its key address with no node on file, and its node's
    /// `ln:` line. The signer pays it (`ticket_listed`: the `ln:` line); the UI said it couldn't be paid.
    #[test]
    fn a_seller_allowed_through_its_node_line_is_allowed_as_the_signer_decides() {
        let node = &format!("035d867908cd{}0b7d", "0".repeat(50));
        assert_eq!(node.len(), 66);
        let shop = xbt402::shop::origin_for(&[0x5a; 32]);
        let p = json!({"allowlist": [shop, format!("ln:{node}")], "counterparties": {}});
        assert!(rules_allow(&p, &shop, Some(node)), "its node, from its shop entry, is on the list");
        assert!(!rules_allow(&p, &shop, None), "no node known: nothing says it is paid");
        assert!(!rules_allow(&p, &shop, Some(&"02".repeat(33))), "another node");
        // the address listed with its node on file, no `ln:` line
        let web = json!({"allowlist": ["https://a.example"], "counterparties": {"https://a.example": {"ln_node": node}}});
        assert!(rules_allow(&web, "https://a.example/", None));
        // its node line alone (the address not listed), the node on file
        let line = json!({"allowlist": [format!("ln:{node}")], "counterparties": {"https://a.example": {"ln_node": node}}});
        assert!(rules_allow(&line, "https://a.example", None));
        // listed, no node anywhere: refused, as the signer refuses it
        assert!(!rules_allow(&json!({"allowlist": ["https://a.example"]}), "https://a.example", None));
        assert_eq!(ln_line_node(&format!("ln:{node}")), Some(node.as_str()));
        assert_eq!(ln_line_node("bc1qcoin"), None);
    }

    /// The wallet's MCP server (`list_services`) marks a seller allowed as Browse does: the same answer for each case.
    #[test]
    fn the_agents_catalog_marks_a_seller_allowed_as_browse_does() {
        let node = format!("035d867908cd{}0b7d", "0".repeat(50));
        let shop = xbt402::shop::origin_for(&[0x5a; 32]);
        let other = "02".repeat(33);
        let rules = [json!({"allowlist": [shop.clone(), format!("ln:{node}")], "counterparties": {}}),
                     json!({"allowlist": ["https://a.example"], "counterparties": {"https://a.example": {"ln_node": node}}}),
                     json!({"allowlist": [format!("ln:{node}")], "counterparties": {"https://a.example": {"ln_node": node}}}),
                     json!({"allowlist": ["https://a.example"]}), json!({}), json!({"allowlist": ["https://A.example:443/"], "counterparties": {"https://a.example": {"ln_node": node}}})];
        for p in &rules {
            for origin in [shop.as_str(), "https://a.example", "https://a.example/", "https://b.example"] {
                for known in [None, Some(node.as_str()), Some(other.as_str())] {
                    assert_eq!(xbt_wallet_mcp::catalog::allowed(p, origin, known), rules_allow(p, origin, known), "{p} {origin} {known:?}");
                }
            }
        }
    }

    /// Home's First steps counts a shop allowed as the signer allows it: also one allowed only
    /// through its node's `ln:` line, its node known from its shop entry or on file.
    ///
    /// FAILS before: only a seller listed by its address with its node on file counted, so Home kept
    /// saying "Allow a shop" for a shop the wallet pays.
    #[test]
    fn get_started_counts_a_shop_allowed_through_its_node() {
        let node = format!("03{}", "ab".repeat(32));
        let shop = xbt402::shop::origin_for(&[0x5a; 32]);
        let line = json!({"allowlist": [format!("ln:{node}")], "counterparties": {}});
        assert!(any_seller_allowed(&line, &[(shop.clone(), Some(node.clone()))]), "its node line, its node from its shop entry");
        assert!(!any_seller_allowed(&line, &[(shop.clone(), None)]), "no node known for it");
        assert!(!any_seller_allowed(&line, &[(shop.clone(), Some("02".repeat(33)))]), "another node");
        assert!(!any_seller_allowed(&line, &[]));
        // its node on file, the address not listed
        let on_file = json!({"allowlist": [format!("ln:{node}")], "counterparties": {"https://a.example": {"ln_node": node}}});
        assert!(any_seller_allowed(&on_file, &[]));
        // the address listed with its node on file, as before
        let web = json!({"allowlist": ["https://a.example"], "counterparties": {"https://a.example": {"ln_node": node}}});
        assert!(any_seller_allowed(&web, &[]));
        // listed with no node anywhere: refused, as the signer refuses it
        assert!(!any_seller_allowed(&json!({"allowlist": ["https://a.example"]}), &[]));
    }

    /// The credit left with a shop: its newest `ticket_left_with_seller`, until a session with its node
    /// opens again or the credit is given up.
    #[test]
    fn the_credit_left_with_a_shop_is_read_from_the_history() {
        let left = |sid: &str, dest: &str, origin: &str, m: Option<&str>| json!({"type": "ticket_left_with_seller", "session": sid, "dest": dest, "origin": origin, "left_msat": m});
        let ev = vec![left("s1", "ln:aa", "http://a.shop.invalid", Some("475900")), left("s2", "ln:bb", "https://b.example", Some("1000")),
                      json!({"type": "ticket_open", "session": "s3", "dest": "ln:bb"}), left("s4", "ln:cc", "https://c.example", None)];
        let c = credit_left(&ev);
        assert_eq!(c.get("http://a.shop.invalid"), Some(&475_900));
        assert!(!c.contains_key("https://b.example"), "a later session with its node took it");
        assert!(!c.contains_key("https://c.example"), "not said by the shop: nothing claimed");
        let mut given = ev.clone();
        given.push(json!({"type": "ticket_credit_given_up", "session": "s1"}));
        assert!(credit_left(&given).is_empty());
        let line = credit_line("Lightning Stream Genesis", 475_900);
        assert!(line.contains("about 476 sat of credit with Lightning Stream Genesis; it's used first next time"), "{line}");
    }

    /// A refused payment in the Wallet's history is said as the refusal pages say it, not in the signer's
    /// words (0.2.2: "Ln refused … the LN node holds 287070 sats … above ln.…").
    #[test]
    fn a_refused_payment_in_the_history_is_in_plain_words() {
        let e = json!({"type": "ln_refused", "reason": "the LN node holds 287070 sats in its channels, above ln.exposure_cap_sats 100000", "dest": "ln:aa"});
        let (what, words) = refusal_words(&e).unwrap();
        assert!(!words.contains("ln.exposure_cap_sats") && !what.is_empty(), "{what}: {words}");
        let e = json!({"type": "decision", "verdict": "deny", "rule": "allowlist", "reason": "not on allowlist"});
        assert_eq!(refusal_words(&e).unwrap().0, "This shop isn't allowed yet");
        assert!(refusal_words(&json!({"type": "ticket_settled", "reason": "x"})).is_none());
        // a prepaid ticket refused by the owner's rules: their words, not the signer's (`budget_sats`)
        let e = json!({"type": "ticket_prepay_refused_by_policy", "rule": "ticket_task_budget", "dest": "ln:aa",
                       "reason": "with this ticket's 915 sats, 10618 would be above the task's budget_sats (10000)"});
        let (what, words) = refusal_words(&e).unwrap();
        assert!(what == "Today's limit for paid services would be passed" && words.contains("Most for paid services"), "{what}: {words}");
    }

    /// Recent activity names what happened in plain words: no `ticket:<hash>`, no "all policy rules passed", no signer
    /// start with no shop, and a prepaid ticket once as reserved (the most it may cost) and once as paid, exactly.
    ///
    /// FAILS before (0.2.6): "Ticket prepay 915 sats" beside "Reserved 915 sats ticket:8e2b…", "Ticket prepaid 903 sats"
    /// beside "Paid 902.009 sats", "Ticket start" with no shop, "Ticket seller forgot".
    #[test]
    fn recent_activity_is_in_plain_words_and_says_each_payment_once() {
        let h = "8e2b82a0";
        let all = vec![
            json!({"type": "ticket_start", "retired": 0}),
            json!({"type": "commit", "txid": format!("ticket:{h}"), "amount_sats": 915, "dest": "ln:aa"}),
            json!({"type": "ticket_prepay", "payment_hash": h, "booked_sats": 915, "dest": "ln:aa"}),
            json!({"type": "ln_settled", "payment_hash": h, "dest": "ln:aa"}),
            json!({"type": "ticket_prepaid", "payment_hash": h, "spent_sats": 903, "dest": "ln:aa"}),
            json!({"type": "ticket_prepaid", "payment_hash": "other", "spent_sats": 10, "dest": "ln:aa"}),
            json!({"type": "ticket_prepay", "payment_hash": "lone", "booked_sats": 20, "dest": "ln:aa"}),
            json!({"type": "ln_amend"}),
        ];
        let kept: Vec<&str> = all.iter().filter(|e| activity_row(e, &all)).map(|e| e["type"].as_str().unwrap()).collect();
        assert_eq!(kept, vec!["commit", "ln_settled", "ticket_prepaid", "ticket_prepay"], "a payment once, its unpaired records kept");
        assert_eq!(activity_detail(&all[1], true), "", "no ticket:<hash>");
        assert_eq!(activity_detail(&json!({"type": "decision", "verdict": "allow", "rule": "ok", "reason": "all policy rules passed"}), false),
                   "Within your spending rules");
        assert_eq!(activity_detail(&json!({"type": "commit", "txid": "ln:abc"}), false), "");
        assert_eq!(activity_detail(&json!({"type": "ticket_seller_forgot", "origin": "https://a.example"}), false), "A new one was opened");
        assert_eq!(activity_detail(&json!({"type": "commit", "txid": "d00d"}), false), "d00d", "a coin send's txid stays");
    }

    /// One row a payment: its allowed decision and its reservation fold into its Paid (or failed) row; a payment with no
    /// outcome yet is one row, reserved; a refusal and an allowed decision nothing was booked for stay rows of their own.
    ///
    /// FAILS before (0.2.11): each payment of a hashrate rental was three rows, "Allowed 559 sats", "Reserved 559 sats" and "Paid".
    #[test]
    fn a_payment_is_one_row_its_allowed_and_reserved_steps_folded_in() {
        let all = vec![
            json!({"type": "decision", "verdict": "allow", "rule": "ok", "reason": "all policy rules passed", "dest": "ln:aa", "amount_sats": 559, "ts": 100}),
            json!({"type": "commit", "txid": "ln:h1", "amount_sats": 559, "dest": "ln:aa", "ts": 101}),
            json!({"type": "decision", "verdict": "allow", "rule": "ok", "reason": "all policy rules passed", "dest": "ln:aa", "amount_sats": 559, "ts": 102}),
            json!({"type": "ln_amend", "txid": "ln:h1", "ts": 103}),
            json!({"type": "ln_settled", "payment_hash": "h1", "dest": "ln:aa", "spent_sats": 550, "ts": 104}),
            json!({"type": "commit", "txid": "ln:h2", "amount_sats": 559, "dest": "ln:aa", "ts": 105}),
            json!({"type": "decision", "verdict": "deny", "rule": "max_per_tx", "reason": "x", "dest": "ln:aa", "amount_sats": 9999, "ts": 106}),
            json!({"type": "decision", "verdict": "allow", "rule": "ok", "dest": "ln:bb", "amount_sats": 7, "ts": 107}),
            json!({"type": "decision", "verdict": "allow", "rule": "ok", "dest": "ln:aa", "amount_sats": 20, "ts": 108}),
            json!({"type": "commit", "txid": "ticket:h3", "amount_sats": 20, "dest": "ln:aa", "ts": 109}),
            json!({"type": "ticket_failed", "payment_hash": "h3", "dest": "ln:aa", "released_sats": 20, "ts": 110}),
            json!({"type": "decision", "verdict": "allow", "rule": "ok", "dest": "ln:cc", "amount_sats": 5, "ts": 111}),
            json!({"type": "commit", "txid": "ln:h4", "amount_sats": 5, "dest": "ln:cc", "ts": 9999}),
        ];
        let folds = activity_folds(&all);
        let rows: Vec<usize> = (0..all.len()).filter(|i| !folds.contains_key(i) && activity_row(&all[*i], &all)).collect();
        // h1 paid, h2 in progress (its decision the second one), the refusal, a decision nothing was booked for, h3 failed,
        // and a booking hours after a decision of the same amount: not taken for its step
        assert_eq!(rows, vec![4, 5, 6, 7, 10, 11, 12], "{folds:?}");
        assert_eq!((folds[&0], folds[&1], folds[&2], folds[&8], folds[&9]), (4, 4, 5, 10, 10));
        let paid = activity_steps(&all, &folds, 4);
        assert!(paid.contains("<summary>Allowed and reserved first</summary>Allowed: Within your spending rules · ") && paid.contains("559")
                && paid.contains("reserved, the most it may cost"), "{paid}");
        assert!(activity_steps(&all, &folds, 5).contains("<summary>Allowed first</summary>"));
        assert_eq!(activity_steps(&all, &folds, 6), "");
    }

    /// Records' Kind column in plain words; the signer's own word is its tooltip.
    ///
    /// FAILS before (0.2.6): the column showed `ticket_settled` and `ticket_prepay`.
    #[test]
    fn a_records_kind_is_in_plain_words() {
        assert_eq!(kind_words("ticket_settled"), "Ticket paid");
        assert_eq!(kind_words("ticket_prepay"), "Ticket paid ahead");
        assert_eq!(kind_words("ln_payment"), "Lightning payment");
        assert_eq!(kind_words("something_new"), "Something new");
        for k in ["ticket_settled", "ticket_prepay", "ticket_release", "ln_payment", "lottery_win_pay", "human_sweep"] {
            assert!(!kind_words(k).contains('_'), "{k}");
        }
    }
}
