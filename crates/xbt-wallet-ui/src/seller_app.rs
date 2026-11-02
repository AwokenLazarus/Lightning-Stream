//! A seller's own web page, used inside the app (docs/SELLER-APPS.md).
//!
//! The owner opens it from Browse: `GET /app` asks for the visit's limit, `POST /app` opens a
//! visit at the connector and shows the page in a frame, `POST /app-stop` ends it, and
//! `GET /api/visit` says what it has spent. The page itself is served on an app port
//! ([`AppOrigin`], `XBT_UI_APP_PORTS`), another origin than this one. A port serves nothing
//! without its visit's cookie, which it gives for a one-time code in the frame's address.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::app::{App, Ctx, MIN_CALL_SATS, MIN_TICKET_SATS};
use crate::html::esc;
use crate::server::Resp;

/// A one-time code is good for this long.
const CODE_TTL: Duration = Duration::from_secs(60);
/// The visit's limit the page suggests, in sats.
pub const SUGGESTED_LIMIT: i64 = 1_000;
// the form's own suggestion opens a visit that can buy a ticket
const _: () = assert!(SUGGESTED_LIMIT >= MIN_CALL_SATS);
/// The largest limit a visit may have, in sats.
const MAX_VISIT_SATS: i64 = 10_000_000;
/// The most the page suggests for a video app: what it asks for ten minutes of film at 1 MiB/s (about
/// 1080p) by its listed price, at least [`SUGGESTED_LIMIT`] and at most this. The bar offers more as the
/// visit nears its limit ([`App::app_limit`]); nothing is raised without the owner's click.
const SUGGESTED_VIDEO_MAX: i64 = 20_000;

/// The limit the page suggests for `svc`: [`SUGGESTED_LIMIT`], or for a video app priced by the byte,
/// ten minutes of 1080p at its listed price (whole thousands, at most [`SUGGESTED_VIDEO_MAX`]).
pub(crate) fn suggested_limit(svc: &crate::services::Service) -> i64 {
    if svc.kind != crate::services::Kind::Video {
        return SUGGESTED_LIMIT;
    }
    let gib_msat = svc.price_ceiling().and_then(|c| c.get("gib_msat").and_then(Value::as_u64)).unwrap_or(0);
    // 600 MiB, in sats
    let ten_minutes = i64::try_from((u128::from(gib_msat) * 600 / 1024).div_ceil(1000)).unwrap_or(i64::MAX);
    (ten_minutes.saturating_add(999) / 1000).saturating_mul(1000).clamp(SUGGESTED_LIMIT, SUGGESTED_VIDEO_MAX)
}

/// The visit's limit from what the owner entered. A limit under the smallest ticket a shop sells
/// with its routing fees ([`MIN_CALL_SATS`]) would open a visit whose first request is refused
/// with nothing spent, so it is refused here, in words, with the form set to that least limit
/// (`Err((words, Some(limit)))`) for the owner to confirm.
pub(crate) fn visit_limit(entered: Option<&str>) -> Result<i64, (String, Option<i64>)> {
    let n: i64 = entered.and_then(|v| v.trim().replace(',', "").parse().ok()).unwrap_or(0);
    if !(1..=MAX_VISIT_SATS).contains(&n) {
        return Err((format!("Set a limit of {MIN_CALL_SATS} sat or more."), None));
    }
    if n < MIN_CALL_SATS {
        return Err((format!("A shop's smallest ticket is {MIN_TICKET_SATS} sat, so with routing fees a visit needs at least {MIN_CALL_SATS} sat: \
                             the limit is now set to {MIN_CALL_SATS} sat. Press Open the app to go on. What you don't use stays as credit with the shop."),
                    Some(MIN_CALL_SATS)));
    }
    Ok(n)
}

/// The largest request body a page sends.
const MAX_BODY: usize = 1 << 20;

/// What a port's cookie lets its holder do: use one visit.
#[derive(Clone)]
struct Grant {
    visit: String,
    port: u16,
    /// The seller's URL the page sees as `/`, ending in `/`.
    base: String,
    /// Where it opens, as a path on the port.
    entry: String,
    /// The seller's mark in this port's cookie names: one seller's cookies never go to another.
    tag: String,
    /// The owner's free preview of a page of their own shop: the service on the box it is asked
    /// from directly, as the gateway would ask it. Nothing is paid; no connector visit.
    direct: Option<String>,
}

#[derive(Default)]
struct State {
    /// By port: the seller (origin) that has it, and when it was last given out.
    ports: HashMap<u16, (String, Instant)>,
    /// One-time codes: code → (made, grant, the port's storage is someone else's).
    codes: HashMap<String, (Instant, Grant, bool)>,
    /// Cookies: secret → grant.
    grants: HashMap<String, Grant>,
    /// The owner's free previews, by visit id: nothing to ask the connector about.
    previews: std::collections::HashSet<String>,
    /// The wallet's latest refusal of a request of each visit, and when: shown above the frame, in
    /// words, by the visit's page ([`App::api_visit`]).
    refusals: HashMap<String, (Instant, String)>,
}

/// A refusal is shown above a visit's frame for this long after it came.
const REFUSAL_SHOWN: Duration = Duration::from_secs(60);

#[derive(Default)]
pub struct AppOrigins {
    state: Mutex<State>,
    /// The app ports that are being served: those of `XBT_UI_APP_PORTS` this UI could bind.
    live: Mutex<Vec<u16>>,
}

impl AppOrigins {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// The cookie that carries a port's visit.
fn visit_cookie(port: u16) -> String {
    format!("__ls_visit_{port}")
}

/// The prefix of the seller's own cookies on a port.
fn cookie_prefix(port: u16, tag: &str) -> String {
    format!("lsa{port}_{tag}_")
}

fn seller_tag(origin: &str) -> String {
    hex::encode(&Sha256::digest(origin.as_bytes())[..4])
}

/// A JSON request to the connector, which is on this box's loopback.
fn connector_json(method: &str, url: &str, body: Option<&Value>) -> Result<(u16, Value), String> {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(10)).redirects(0).build();
    let req = agent.request(method, url);
    let sent = match body {
        Some(b) => req.set("Content-Type", "application/json").send_string(&b.to_string()),
        None => req.call(),
    };
    let r = match sent {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => return Err(format!("the connector: {e}")),
    };
    let status = r.status();
    Ok((status, serde_json::from_str(&r.into_string().unwrap_or_default()).unwrap_or(Value::Null)))
}

fn secret() -> String {
    hex::encode(crate::random_bytes::<24>())
}

impl App {
    fn app_ports(&self) -> Vec<u16> {
        self.apps.live.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// A port for the app at `app` (its base URL): the one it had, else a free one, else the one
    /// given out longest ago. One app to a port, so two apps of one seller open at once are two
    /// origins, with two sets of cookies and storage. `true`: the port's storage was another app's.
    fn port_for(&self, seller: &str) -> Option<(u16, bool)> {
        let ports = self.app_ports();
        let ports = ports.as_slice();
        let mut s = self.apps.lock();
        let pick = ports.iter().copied().find(|p| s.ports.get(p).is_some_and(|(o, _)| o == seller))
            .or_else(|| ports.iter().copied().find(|p| !s.ports.contains_key(p)))
            .or_else(|| ports.iter().copied().min_by_key(|p| s.ports.get(p).map(|(_, t)| *t)))?;
        let other = s.ports.get(&pick).is_some_and(|(o, _)| o != seller);
        if other {
            // the last seller's visits on this port end with its storage
            s.grants.retain(|_, g| g.port != pick);
        }
        s.ports.insert(pick, (seller.to_string(), Instant::now()));
        Some((pick, other))
    }

    /// `GET /app?u=<where it opens>&b=<its base>`: open a seller's own page, with a limit.
    pub(crate) fn app_page(&self, ctx: &Ctx, q: &HashMap<String, String>) -> Resp {
        let (entry, base) = (q.get("u").cloned().unwrap_or_default(), q.get("b").cloned().unwrap_or_default());
        let svc = self.file_services().ok().and_then(|all| all.into_iter().find(|s| !s.app.is_empty() && s.app == entry && s.app_base == base));
        let Some(svc) = svc else {
            return self.page("Open the app", ctx, "<p class=\"empty\">That app is not one of your sellers' any more. <a href=\"./browse\">Browse</a></p>".into());
        };
        if self.app_ports().is_empty() {
            return self.page("Open the app", ctx, "<p class=\"empty\">This box does not open sellers' apps.</p>".into());
        }
        if self.is_own_shop(&svc.seller) {
            let b = format!("<section class=\"card primary\"><h2>Preview your own app</h2>\
                <p>This is your shop: buyers open <strong>{}</strong> here and pay {} for what it loads. You can try it for free: it comes \
                straight from your service on this box, and nothing is paid.</p>\
                <form method=\"post\" action=\"./app\">{}<input type=\"hidden\" name=\"u\" value=\"{}\"><input type=\"hidden\" name=\"b\" value=\"{}\">\
                <input type=\"hidden\" name=\"preview\" value=\"1\"><div class=\"row\"><button>Preview the app (free)</button><a href=\"./browse\">Cancel</a></div></form></section>",
                esc(&svc.name), esc(&svc.price_text), App::csrf_input(ctx), esc(&entry), esc(&base));
            return self.page("Open the app", ctx, b);
        }
        // the node can't send a first ticket: said before anything is paid
        let warn = crate::pay_feedback::cant_send_card(self.spendable_sats(), MIN_CALL_SATS, "this shop");
        // a limit the owner entered under the smallest ticket comes back raised to it (see [`visit_limit`])
        let suggested = q.get("limit").and_then(|v| v.parse::<i64>().ok()).filter(|n| (MIN_CALL_SATS..=MAX_VISIT_SATS).contains(n)).unwrap_or_else(|| suggested_limit(&svc));
        // the shop by its listed name ("Lightning Stream Genesis"), never its key or made-up address
        let shop = self.seller_name(&svc.seller);
        let b = format!("{warn}<section class=\"card primary\"><h2>Open {}'s app</h2>\
            <p>You use <strong>{}</strong> inside this page. What it loads is paid at {}, and stops at the limit you set here.</p>\
            <p class=\"small\">Shop address: {}</p>\
            <form method=\"post\" action=\"./app\">{}<input type=\"hidden\" name=\"u\" value=\"{}\"><input type=\"hidden\" name=\"b\" value=\"{}\">\
            {}<div class=\"row\"><button>Open the app</button><a href=\"./browse\">Cancel</a></div></form></section>\
            <p class=\"small\">The app runs apart from your wallet: it cannot see your keys, your rules or this page.</p>{}",
            esc(&shop), esc(&svc.name), esc(&svc.price_text), esc(&crate::app::stream_pages::host(&svc.seller)), App::csrf_input(ctx), esc(&entry), esc(&base), limit_field(suggested),
            self.identity_card(ctx, &svc.seller, &base, &entry));
        self.page("Open the app", ctx, b)
    }

    /// The note, and the choice, for a shop that keeps an account for each buyer of the app at
    /// `base` (docs/BUYER-ACCOUNTS.md); nothing for a shop that does not.
    fn identity_card(&self, ctx: &Ctx, seller: &str, base: &str, entry: &str) -> String {
        if !shop_keeps_accounts(seller) {
            return String::new();
        }
        let origin = crate::services::http_origin(seller).unwrap_or_default();
        let known = self.call("identity_get", json!({"origin": origin})).unwrap_or(Value::Null);
        // the wallet cannot read its choices: it stays anonymous everywhere, and there is nothing to choose until that is mended
        if known.get("damaged") == Some(&json!(true)) {
            return "<section class=\"card\"><h3>Your history at this shop</h3><p>The wallet cannot read its record of which shops may recognise you, so it stays anonymous \
                    at every shop for now. A shop with no shared guest refuses you until that file (identity.json) is mended or removed.</p></section>".to_string();
        }
        let anonymous = known.get("here") == Some(&json!(true));
        let (state, button, to) = if anonymous {
            ("You stay anonymous at this shop: it does not keep your history, and you use its shared guest where it has one.", "Let this shop recognise me", "0")
        } else {
            ("This shop keeps your watch history. It sees a private handle, not who you are, and it is the same each time you come back.", "Stay anonymous here", "1")
        };
        format!("<section class=\"card\"><h3>Your history at this shop</h3><p>{}</p>\
            <form method=\"post\" action=\"./identity\" class=\"inline\">{}<input type=\"hidden\" name=\"origin\" value=\"{}\">\
            <input type=\"hidden\" name=\"anonymous\" value=\"{to}\"><input type=\"hidden\" name=\"u\" value=\"{}\"><input type=\"hidden\" name=\"b\" value=\"{}\">\
            <button class=\"secondary\">{button}</button></form>\
            <p class=\"hint\">The handle is made for this shop alone: another shop cannot tell it is you. A restore from your backup keeps it.</p></section>",
            state, App::csrf_input(ctx), esc(&origin), esc(entry), esc(base))
    }

    /// `POST /identity`: stay anonymous at a shop, or let it recognise this wallet.
    pub(crate) fn identity(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let g = |k: &str| f.get(k).cloned().unwrap_or_default();
        match self.call("identity_set", json!({"origin": g("origin"), "anonymous": g("anonymous") == "1"})) {
            Ok(v) if v.get("ok") == Some(&json!(true)) => {
                let said = if g("anonymous") == "1" { format!("You stay anonymous at that shop.{}", stopped_note(&v)) } else { "That shop recognises you now.".to_string() };
                self.flash(ctx, true, said)
            }
            Ok(v) => self.flash(ctx, false, format!("Not changed: {}", v.get("reason").and_then(Value::as_str).unwrap_or("the wallet refused"))),
            Err(e) => self.flash(ctx, false, format!("Not changed: {e}")),
        }
        Resp::redirect(&format!("./app?u={}&b={}", crate::services::urlenc(&g("u")), crate::services::urlenc(&g("b"))))
    }

    /// `POST /app`: the visit opened, and the page in its frame.
    pub(crate) fn app_open(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let (entry, base) = (f.get("u").cloned().unwrap_or_default(), f.get("b").cloned().unwrap_or_default());
        let Some(svc) = self.file_services().ok().and_then(|all| all.into_iter().find(|s| !s.app.is_empty() && s.app == entry && s.app_base == base)) else {
            self.flash(ctx, false, "That app is not one of your sellers' any more.");
            return Resp::redirect("./browse");
        };
        let preview = f.get("preview").is_some_and(|v| v == "1") && self.is_own_shop(&svc.seller);
        let direct = if preview {
            match self.preview_upstream(&base) {
                Ok(u) => Some(format!("{}/", u.trim_end_matches('/'))),
                Err(e) => {
                    self.flash(ctx, false, format!("The preview could not be opened: {e}"));
                    return Resp::redirect("./browse");
                }
            }
        } else {
            None
        };
        let limit = if preview { 0 } else {
            match visit_limit(f.get("limit").map(String::as_str)) {
                Ok(n) => n,
                Err((words, raised)) => {
                    self.flash(ctx, false, words);
                    let again = raised.map(|n| format!("&limit={n}")).unwrap_or_default();
                    return Resp::redirect(&format!("./app?u={}&b={}{again}", crate::services::urlenc(&entry), crate::services::urlenc(&base)));
                }
            }
        };
        // one port, one cookie prefix, for each app: a seller's two apps never share a page's state
        let Some((port, other)) = self.port_for(&base) else {
            self.flash(ctx, false, "This box does not open sellers' apps.");
            return Resp::redirect("./browse");
        };
        let opened = if preview { Ok((200, json!({"visit": secret()}))) } else {
            // the seller's listed prices: the most each of the visit's calls pays
            let mut body = json!({"base": base, "limit_sats": limit});
            if let Some(c) = svc.price_ceiling() {
                body["price_ceiling"] = c;
            }
            connector_json("POST", &format!("{}/visits", self.cfg.connector.trim_end_matches('/')), Some(&body))
        };
        let visit = match opened {
            Ok((200, v)) => v.get("visit").and_then(Value::as_str).unwrap_or("").to_string(),
            Ok((_, v)) => {
                self.flash(ctx, false, format!("The app could not be opened: {}", v.get("error").and_then(Value::as_str).unwrap_or("the connector refused")));
                return Resp::redirect("./browse");
            }
            Err(e) => {
                self.flash(ctx, false, format!("The app could not be opened: {e}"));
                return Resp::redirect("./browse");
            }
        };
        let path = entry.strip_prefix(&base).unwrap_or("");
        let grant = Grant { visit: visit.clone(), port, base: base.clone(), entry: format!("/{path}"), tag: seller_tag(&base), direct };
        let code = secret();
        {
            let mut s = self.apps.lock();
            if preview {
                s.previews.insert(visit.clone());
            }
            s.codes.retain(|_, (t, _, _)| t.elapsed() < CODE_TTL);
            s.codes.insert(code.clone(), (Instant::now(), grant, other));
        }
        // the shop by its name in the visit's words (its key only in small detail text)
        let host = self.seller_name(&svc.seller);
        let b = format!("<section class=\"card app-visit\" data-visit=\"{}\" data-port=\"{port}\" data-code=\"{}\">\
            <div class=\"offer-head\"><h2>Your visit</h2><span class=\"pill good\" data-visit-state>Open</span></div>\
            <div class=\"card primary refusal\" data-visit-refusal hidden></div>\
            <p>{} &middot; {} \
            <form method=\"post\" action=\"./app-stop\" class=\"inline\">{}<input type=\"hidden\" name=\"visit\" value=\"{}\"><button class=\"danger\">Stop</button></form></p>\
            <iframe class=\"seller-app\" title=\"{}\" sandbox=\"allow-scripts allow-same-origin allow-forms allow-downloads allow-modals allow-pointer-lock\" \
            allow=\"fullscreen; autoplay; encrypted-media; picture-in-picture\" referrerpolicy=\"no-referrer\"></iframe>\
            <p class=\"hint\" data-visit-note>{}'s own page. It cannot see your wallet. Close this page or press Stop to end the visit.</p></section>",
            esc(&visit), esc(&code),
            if preview { "Your own shop, free: nothing is paid".to_string() } else {
                format!("<span data-visit-spent>0</span> sat used of <strong><span data-visit-limit>{}</span> sat</strong> on this visit<span data-visit-paid></span> \
                         <button type=\"button\" class=\"secondary\" data-visit-add=\"{}\" hidden>Add {} sat</button>",
                        crate::html::group3(limit.unsigned_abs()), limit, crate::html::group3(limit.unsigned_abs()))
            },
            esc(&svc.price_text), App::csrf_input(ctx), esc(&visit), esc(&svc.name), esc(&host));
        let frames: String = self.app_ports().iter().map(|p| format!(" http://*:{p} https://*:{p}")).collect();
        let csp = format!("{}; media-src 'self'; frame-src{frames}", crate::server::CSP);
        // the shop's own name, as Browse shows it; the seller's address or key is in the line below
        self.page(&svc.name, ctx, b).header("Content-Security-Policy", &csp)
    }

    /// `POST /app-stop`.
    pub(crate) fn app_stop(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let visit = f.get("visit").cloned().unwrap_or_default();
        let mut used = String::new();
        let mut ended = String::new();
        if visit.bytes().all(|b| b.is_ascii_hexdigit()) && !visit.is_empty() {
            let base = self.apps.lock().grants.values().find(|g| g.visit == visit).map(|g| g.base.clone());
            if !self.apps.lock().previews.remove(&visit) {
                let said = connector_json("POST", &format!("{}/visits/{visit}/stop", self.cfg.connector.trim_end_matches('/')), Some(&json!({})));
                if let Ok((200, v)) = said {
                    used = visit_numbers(&v).get("said").and_then(Value::as_str).map(|s| format!(" {s}")).unwrap_or_default();
                }
            }
            let origin = base.as_deref().and_then(crate::services::http_origin);
            let others: Vec<String> = {
                let mut s = self.apps.lock();
                s.grants.retain(|_, g| g.visit != visit);
                s.refusals.remove(&visit);
                let mut v: Vec<String> = s.grants.values().filter(|g| g.direct.is_none() && crate::services::http_origin(&g.base) == origin)
                    .map(|g| g.visit.clone()).collect();
                v.sort();
                v.dedup();
                v
            };
            // another visit to the shop counts only while the connector holds it open: a grant outlives a visit that ended
            // without a Stop (its page closed, its limit reached, its idle time out), and such a grant kept the connection open
            let gone: Vec<String> = others.into_iter().filter(|id| !self.visit_open(id)).collect();
            let still_used = {
                let mut s = self.apps.lock();
                s.grants.retain(|_, g| !gone.contains(&g.visit));
                s.grants.values().any(|g| g.direct.is_none() && crate::services::http_origin(&g.base) == origin)
            };
            // one Stop ends it all: the connection the visit paid through closes too, unless another open visit to that shop still uses it
            if let Some(o) = origin.filter(|_| !still_used) {
                if self.stop_seller_sessions(&o) > 0 {
                    ended = format!(" Its connection with {} is closed.", self.seller_name(&o));
                }
            }
        }
        self.flash(ctx, true, format!("Stopped. The app is closed and nothing more is paid for it.{ended}{used}"));
        Resp::redirect("./browse")
    }

    /// Whether the connector holds visit `id` open (not ended, not gone): one at its limit counts, since it waits for its
    /// owner to raise it and goes on with the connection it has. A connector that cannot be asked is taken to hold it, so
    /// that a Stop never closes a connection another visit may use.
    fn visit_open(&self, id: &str) -> bool {
        match connector_json("GET", &format!("{}/visits/{id}", self.cfg.connector.trim_end_matches('/')), None) {
            Ok((200, v)) => holds_open(&v),
            Ok((404, _)) => false,
            _ => true,
        }
    }

    /// `POST /app-limit` (`visit`, `add`): the owner raises an open visit's limit by `add` sat (the bar's
    /// "Add" button, as the visit nears its limit); a visit that ended at its limit goes on. JSON, for
    /// the bar: the visit's numbers, or why not.
    pub(crate) fn app_limit(&self, f: &HashMap<String, String>) -> Resp {
        let visit = f.get("visit").cloned().unwrap_or_default();
        let add = f.get("add").and_then(|v| v.trim().replace(',', "").parse::<i64>().ok()).unwrap_or(0);
        if visit.is_empty() || !visit.bytes().all(|b| b.is_ascii_hexdigit()) || !(1..=MAX_VISIT_SATS).contains(&add) {
            return Resp::json(400, &json!({"error": "no visit, or no amount to add"}));
        }
        let base = self.cfg.connector.trim_end_matches('/').to_string();
        let now = match connector_json("GET", &format!("{base}/visits/{visit}"), None) {
            Ok((200, v)) => v.get("limit_sats").and_then(Value::as_i64).unwrap_or(0),
            _ => return Resp::json(404, &json!({"error": "This visit has ended. Open the app again."})),
        };
        let to = now.saturating_add(add).min(MAX_VISIT_SATS);
        match connector_json("POST", &format!("{base}/visits/{visit}/limit"), Some(&json!({"limit_sats": to}))) {
            Ok((200, v)) => Resp::json(200, &visit_numbers(&v)),
            Ok((_, v)) => Resp::json(409, &json!({"error": v.get("error").and_then(Value::as_str).unwrap_or("The limit was not raised.")})),
            Err(e) => Resp::json(502, &json!({"error": e})),
        }
    }

    /// `GET /api/visit?v=<id>`: what the visit has spent.
    pub(crate) fn api_visit(&self, q: &HashMap<String, String>) -> Resp {
        let visit = q.get("v").cloned().unwrap_or_default();
        if visit.is_empty() || !visit.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Resp::json(400, &json!({"error": "no visit"}));
        }
        if self.apps.lock().previews.contains(&visit) {
            return Resp::json(200, &json!({"spent_sats": 0, "ended": null}));
        }
        let refused = {
            let mut s = self.apps.lock();
            s.refusals.retain(|_, (t, _)| t.elapsed() < 10 * REFUSAL_SHOWN);
            s.refusals.get(&visit).filter(|(t, _)| t.elapsed() < REFUSAL_SHOWN).map(|(_, b)| b.clone())
        };
        // the shop's name, for a refusal by the buyer's own rules that names it
        let shop = self.apps.lock().grants.values().find(|g| g.visit == visit).and_then(|g| crate::services::http_origin(&g.base)).map(|o| self.seller_name(&o));
        // the refusal in words, with what the node can send where it found no route
        let refusal = refused.map(|body| {
            let no_route = crate::pay_feedback::explain(&body, None, false).kind == crate::pay_feedback::Kind::NoRoute;
            crate::pay_feedback::as_json(&crate::pay_feedback::explain_at(&body, if no_route { self.spendable_sats() } else { None }, false, shop.as_deref()))
        });
        match connector_json("GET", &format!("{}/visits/{visit}", self.cfg.connector.trim_end_matches('/')), None) {
            Ok((200, v)) => {
                let mut out = visit_numbers(&v);
                // the visit ended by the buyer's own spending rules (a top-up refused, say): said as such a refusal is, with
                // the shop, the limit and the field to raise, where the frame has shown nothing newer
                let by_rules = v.get("policy_refused").filter(|p| p.is_object())
                    .map(|p| crate::pay_feedback::as_json(&crate::pay_feedback::explain_at(&json!({"error": p["reason"], "rule": p["rule"], "limit_sats": p["limit_sats"]}).to_string(),
                                                                                           None, false, shop.as_deref())));
                out["refusal"] = refusal.or(by_rules).unwrap_or(Value::Null);
                // a visit that runs on earlier credit pays nothing new: the bar says what is left of that credit
                if out["prepaid_sats"].as_i64() == Some(0) && out["used_sats"].as_i64().unwrap_or(0) > 0 {
                    let origin = self.apps.lock().grants.values().find(|g| g.visit == visit).and_then(|g| crate::services::http_origin(&g.base));
                    if let Some(m) = origin.and_then(|o| self.live_credit_msat(&o)) {
                        out["credit_left_sats"] = json!(m / 1000);
                    }
                }
                Resp::json(200, &out)
            }
            _ => Resp::json(200, &json!({"ended": "This visit has ended."})),
        }
    }

    /// The credit the open connection with the shop at `origin` holds now (msat), by the wallet's count.
    fn live_credit_msat(&self, origin: &str) -> Option<u64> {
        let st = self.call("ticket_status", json!({})).ok()?;
        st["paying"].as_array()?.iter().filter(|p| p["origin"].as_str().and_then(crate::services::http_origin).as_deref() == Some(origin))
            .filter_map(|p| p["balance_msat"].as_str().and_then(|s| s.parse::<u64>().ok())).max()
    }

    /// What the node can send now, about ([`crate::pay_feedback::spendable_sats`]); `None` where the
    /// signer does not say.
    pub(crate) fn spendable_sats(&self) -> Option<i64> {
        self.call("ln_status", json!({})).ok().and_then(|v| crate::pay_feedback::spendable_sats(&v))
    }
}

/// Whether the connector's report of a visit says it is open: not ended, or ended at its limit, where it waits for its owner
/// to raise it (with the connection it has, and its page as it was).
pub(crate) fn holds_open(report: &Value) -> bool {
    report.get("ended").is_none_or(Value::is_null) || report.get("limit_reached") == Some(&Value::Bool(true))
}

/// The visit's numbers for its page, from the connector's report: what its answers used (`used_sats`,
/// and `spent_sats`, the same), what was paid for tickets in it (`prepaid_sats`) and what of that is
/// left as credit with the shop (`credit_sats`), its limit, and `said`, the line in words. A
/// connector that does not count what was used gives its `spent_sats` as before.
pub(crate) fn visit_numbers(v: &Value) -> Value {
    let Some(used_msat) = v.get("used_msat").and_then(Value::as_u64) else {
        return json!({"spent_sats": v["spent_sats"], "limit_sats": v["limit_sats"], "ended": v["ended"], "limit_reached": v["limit_reached"]});
    };
    let used = i64::try_from(used_msat.div_ceil(1000)).unwrap_or(i64::MAX);
    let paid = v.get("paid_sats").and_then(Value::as_i64).unwrap_or(0).max(0);
    let credit = i64::try_from((paid.unsigned_abs() * 1000).saturating_sub(used_msat) / 1000).unwrap_or(0);
    // the three figures every page names (crate::html::paid_html): used, paid (what left the node, as the
    // signer charged it), credit left
    let mut said = format!("This visit used {used} sat");
    if paid > 0 {
        said.push_str(&format!(". Paid: {paid} sat; credit left with the shop: {credit} sat."));
    } else if used > 0 {
        said.push_str(" from your credit with the shop; nothing new was paid.");
    } else {
        said.push('.');
    }
    json!({"used_sats": used, "spent_sats": used, "prepaid_sats": paid, "credit_sats": credit, "limit_sats": v["limit_sats"], "ended": v["ended"],
           "limit_reached": v.get("limit_reached").and_then(Value::as_bool).unwrap_or(false), "said": said})
}

/// The visit limit's field, with the least a visit needs up front, set to `suggested`.
fn limit_field(suggested: i64) -> String {
    format!("<label>Spend at most on this visit: at least {MIN_CALL_SATS} sat\
             <input name=\"limit\" value=\"{suggested}\" required inputmode=\"numeric\" pattern=\"[0-9,]+\"></label>\
             <p class=\"hint\">The shop is paid ahead in steps of {MIN_TICKET_SATS} sat or more, plus routing fees. \
             What you don't use stays with the shop as credit for next time.</p>")
}

/// One app port: a seller's own page, for the visit whose cookie the browser holds.
pub struct AppOrigin {
    pub app: Arc<App>,
    pub port: u16,
}

/// Request headers of the page that go on to the connector (which passes on fewer still).
const PASSED: [&str; 12] = ["accept", "accept-language", "content-type", "if-modified-since", "if-none-match", "if-range", "range", "authorization",
                            "x-emby-authorization", "x-mediabrowser-token", "x-requested-with", "x-csrf-token"];

fn text(status: u16, s: &str) -> xbt_svc::http::Reply {
    frame_reply(status, crate::pay_feedback::frame_page("", s, "", ""))
}

/// The wallet's refusal of a request of the visit, as the frame shows it: in words, with the fix,
/// its own words under Details; the links to the fix are above the frame.
fn refused_in_frame(status: u16, body: &str) -> xbt_svc::http::Reply {
    let e = crate::pay_feedback::explain(body, None, false);
    let fix = format!("{} The links are above this frame.", e.fix);
    frame_reply(status, crate::pay_feedback::frame_page(&e.title, &e.words, &fix, &e.raw))
}

fn frame_reply(status: u16, html: String) -> xbt_svc::http::Reply {
    xbt_svc::http::Reply::Whole(xbt_svc::http::Response::new(status, vec![("Content-Type".into(), "text/html; charset=utf-8".into()),
        ("Cache-Control".into(), "no-store".into()), ("Content-Security-Policy".into(), "default-src 'none'; style-src 'unsafe-inline'".into())], html.into_bytes()))
}

impl AppOrigin {
    fn grant_of(&self, rq: &xbt_svc::http::Request) -> Option<Grant> {
        let name = visit_cookie(self.port);
        let cookies = rq.header("cookie").unwrap_or("");
        let secret = cookies.split(';').filter_map(|c| c.trim().split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v.to_string())?;
        self.app.apps.lock().grants.get(&secret).filter(|g| g.port == self.port).cloned()
    }

    /// `/__ls/enter?c=<code>`: the code traded for this port's cookie, then the page's entry.
    fn enter(&self, query: &str) -> xbt_svc::http::Reply {
        let code = query.split('&').find_map(|kv| kv.strip_prefix("c=")).unwrap_or("").to_string();
        let taken = {
            let mut s = self.app.apps.lock();
            // a code is for its own port: another port neither takes it nor spends it
            let mine = s.codes.get(&code).is_some_and(|(_, g, _)| g.port == self.port);
            match if mine { s.codes.remove(&code) } else { None } {
                Some((t, g, other)) if t.elapsed() < CODE_TTL => {
                    let secret = secret();
                    s.grants.retain(|_, x| x.visit != g.visit);
                    s.grants.insert(secret.clone(), g.clone());
                    Some((secret, g, other))
                }
                _ => None,
            }
        };
        let Some((secret, g, other)) = taken else {
            return text(403, "This link has been used or is too old. Open the app again from Lightning Stream.");
        };
        let mut headers = vec![("Location".to_string(), g.entry.clone()), ("Cache-Control".into(), "no-store".into()),
            ("Set-Cookie".into(), format!("{}={secret}; Path=/; HttpOnly; SameSite=Strict", visit_cookie(self.port))), ("Referrer-Policy".into(), "no-referrer".into())];
        if other {
            // the port was another seller's: its storage is not this one's to read
            headers.push(("Clear-Site-Data".into(), "\"storage\"".into()));
        }
        xbt_svc::http::Reply::Whole(xbt_svc::http::Response::new(302, headers, vec![]))
    }
}

/// The page's cookies that are its own (this port's and this seller's), with their names as the
/// seller set them. Every other cookie of the host (the wallet's, another port's) stays here.
fn own_cookies(header: &str, prefix: &str) -> String {
    header.split(';').map(str::trim).filter_map(|c| c.strip_prefix(prefix)).filter(|c| c.contains('=')).collect::<Vec<_>>().join("; ")
}

/// A seller's `Set-Cookie` for this port: its name under the port's prefix, no `Domain` (the
/// cookie is the host's), and no `Secure` or `SameSite=None` (the port is plain http).
fn own_set_cookie(v: &str, prefix: &str) -> Option<String> {
    let mut parts = v.split(';').map(str::trim);
    let first = parts.next()?;
    let (name, val) = first.split_once('=')?;
    let name = name.trim();
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?={}".contains(&b)) {
        return None;
    }
    let mut out = format!("{prefix}{name}={}", val.trim());
    for a in parts {
        let l = a.to_ascii_lowercase();
        if l.starts_with("domain") || l == "secure" || l == "samesite=none" || l == "partitioned" {
            continue;
        }
        out.push_str("; ");
        out.push_str(a);
    }
    Some(out)
}

impl xbt_svc::http::Handler for AppOrigin {
    fn body_limit(&self, _m: &str, _t: &str) -> usize {
        MAX_BODY
    }

    fn handle(&self, rq: xbt_svc::http::Request) -> xbt_svc::http::Response {
        match self.reply(rq) {
            xbt_svc::http::Reply::Whole(r) => r,
            xbt_svc::http::Reply::Stream(_) | xbt_svc::http::Reply::Upgrade(_) => xbt_svc::http::Response::text(500, "text/plain", "streamed"),
        }
    }

    fn reply(&self, rq: xbt_svc::http::Request) -> xbt_svc::http::Reply {
        if !crate::app::host_allowed(rq.header("host").unwrap_or(""), &self.app.cfg.allowed_hosts) {
            return text(421, "Unknown host.");
        }
        let (path, query) = rq.target.split_once('?').unwrap_or((&rq.target, ""));
        if path == "/__ls/enter" {
            return self.enter(query);
        }
        let Some(g) = self.grant_of(&rq) else {
            return text(403, "Open this app from Lightning Stream: Browse, then Open the app.");
        };
        let prefix = cookie_prefix(self.port, &g.tag);
        if rq.header("upgrade").is_some_and(|u| u.eq_ignore_ascii_case("websocket")) {
            return self.socket(&rq, &g, &prefix);
        }
        let target = rq.target.trim_start_matches('/');
        // the owner's free preview: the service on the box itself; a visit: through the connector, paid
        let url = match &g.direct {
            Some(d) => format!("{d}{target}"),
            None => format!("{}/v/{}/{target}", self.app.cfg.connector.trim_end_matches('/'), g.visit),
        };
        let agent = ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(5)).redirects(0).build();
        let mut req = agent.request(&rq.method.to_ascii_uppercase(), &url);
        for (k, v) in &rq.headers {
            if PASSED.contains(&k.to_ascii_lowercase().as_str()) {
                req = req.set(k, v);
            }
        }
        let cookies = own_cookies(rq.header("cookie").unwrap_or(""), &prefix);
        if !cookies.is_empty() {
            req = req.set("Cookie", &cookies);
        }
        let sent = if rq.body.is_empty() { req.call() } else { req.send_bytes(&rq.body) };
        let resp = match sent {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return text(502, &format!("The app could not be reached: {e}")),
        };
        let status = resp.status();
        // the connector's own refusal (the visit ended, the limit reached): in words, for the frame
        if resp.header("x-ls-refusal").is_some() {
            let body = resp.into_string().unwrap_or_default();
            let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            let words = v.get("error").and_then(Value::as_str).unwrap_or("The visit has ended.");
            // the seller's service is full: nothing was charged, and this page can simply be loaded again
            if v.get("rule").and_then(Value::as_str) == Some("seller_busy") {
                return text(503, &format!("{words} Nothing was charged. Reload this page to try again."));
            }
            // shown above the frame too, with the links to the fix ([`App::api_visit`])
            self.app.apps.lock().refusals.insert(g.visit.clone(), (Instant::now(), body.clone()));
            return refused_in_frame(status, &body);
        }
        let mut headers = vec![];
        for name in resp.headers_names() {
            let l = name.to_ascii_lowercase();
            if ["content-length", "transfer-encoding", "connection", "keep-alive", "content-encoding"].contains(&l.as_str()) {
                continue;
            }
            for v in resp.all(&name) {
                match l.as_str() {
                    "set-cookie" => {
                        if let Some(c) = own_set_cookie(v, &prefix) {
                            headers.push(("Set-Cookie".to_string(), c));
                        }
                    }
                    // a redirect to the seller's own address stays on this port
                    "location" => headers.push(("Location".into(), match v.strip_prefix(&g.base).or_else(|| g.direct.as_deref().and_then(|d| v.strip_prefix(d))) {
                        Some(rest) => format!("/{rest}"),
                        None => v.to_string(),
                    })),
                    _ => headers.push((name.clone(), v.to_string())),
                }
            }
        }
        if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("referrer-policy")) {
            headers.push(("Referrer-Policy".into(), "no-referrer".into()));
        }
        // a page's own absolute links to the seller (its base) stay on this port: rewritten in text answers as they stream
        let mut rewrite = (rewritable(resp.header("content-type").unwrap_or("")) && resp.header("content-range").is_none())
            .then(|| Rewriter::new(&[g.base.as_str()].into_iter().chain(g.direct.as_deref()).collect::<Vec<_>>()));
        let length = resp.header("content-length").and_then(|n| n.parse::<u64>().ok()).filter(|_| rewrite.is_none());
        let mut src = resp.into_reader();
        xbt_svc::http::Reply::Stream(xbt_svc::http::Streamed {
            status,
            headers,
            length,
            body: Box::new(move |out: &mut dyn xbt_svc::http::BodyWriter| {
                let mut buf = vec![0u8; 64 << 10];
                loop {
                    let n = std::io::Read::read(&mut src, &mut buf)?;
                    if n == 0 {
                        if let Some(r) = rewrite.as_mut() {
                            out.send(&r.finish())?;
                        }
                        return Ok(());
                    }
                    match rewrite.as_mut() {
                        Some(r) => out.send(&r.feed(&buf[..n]))?,
                        None => out.send(&buf[..n])?,
                    }
                }
            }),
        })
    }
}

impl AppOrigin {
    /// A page's WebSocket: asked of the connector as part of the visit (or of the service itself,
    /// for the owner's preview), and joined to the browser's connection when it opens.
    fn socket(&self, rq: &xbt_svc::http::Request, g: &Grant, prefix: &str) -> xbt_svc::http::Reply {
        use std::io::{Read as _, Write as _};
        let target = rq.target.trim_start_matches('/');
        let url = match &g.direct {
            Some(d) => format!("{d}{target}"),
            None => format!("{}/v/{}/{target}", self.app.cfg.connector.trim_end_matches('/'), g.visit),
        };
        let Some(rest) = url.strip_prefix("http://") else { return text(502, "The app's live connection could not be reached.") };
        let (host, path) = rest.split_once('/').map_or((rest, "".to_string()), |(h, p)| (h, format!("/{p}")));
        let Ok(mut up) = std::net::TcpStream::connect(host) else { return text(502, "The app's live connection could not be reached.") };
        let _ = up.set_read_timeout(Some(Duration::from_secs(60)));
        let mut head = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n");
        for (k, v) in &rq.headers {
            let l = k.to_ascii_lowercase();
            if (PASSED.contains(&l.as_str()) || l.starts_with("sec-websocket-")) && !k.bytes().chain(v.bytes()).any(|c| matches!(c, b'\r' | b'\n' | 0)) {
                head.push_str(&format!("{k}: {v}\r\n"));
            }
        }
        let cookies = own_cookies(rq.header("cookie").unwrap_or(""), prefix);
        if !cookies.is_empty() {
            head.push_str(&format!("Cookie: {cookies}\r\n"));
        }
        head.push_str("\r\n");
        if up.write_all(head.as_bytes()).is_err() {
            return text(502, "The app's live connection could not be reached.");
        }
        let mut buf = vec![];
        let mut tmp = [0u8; 2048];
        let end = loop {
            match up.read(&mut tmp) {
                Ok(0) | Err(_) => return text(502, "The app's live connection ended before it opened."),
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i;
            }
            if buf.len() > 32 << 10 {
                return text(502, "The app's live connection answered with too long a head.");
            }
        };
        let early = buf.split_off(end + 4);
        let head = String::from_utf8_lossy(&buf[..end]).to_string();
        let mut lines = head.split("\r\n");
        let status = lines.next().and_then(|l| l.split(' ').nth(1)).and_then(|c| c.parse::<u16>().ok()).unwrap_or(502);
        let headers: Vec<(String, String)> = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
        if status != 101 {
            // the visit's words, when the connector refused (the limit reached, the visit stopped)
            let words = if status == 503 {
                "This shop is busy, so the app's live connection did not open. Nothing was charged. Reload this page to try again."
            } else if headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("x-ls-refusal")) {
                "The visit's limit is reached, or it was stopped."
            } else {
                "The app's live connection did not open."
            };
            return text(match status { 402 | 503 => status, _ => 502 }, words);
        }
        let _ = up.set_read_timeout(None);
        let passed: Vec<(String, String)> = headers.into_iter().filter(|(k, _)| k.to_ascii_lowercase().starts_with("sec-websocket-"))
            .chain(std::iter::once(("Upgrade".to_string(), "websocket".to_string()))).collect();
        xbt_svc::http::Reply::Upgrade(xbt_svc::http::Upgraded {
            headers: passed,
            run: Box::new(move |browser, from_browser| {
                let (Ok(mut b2), Ok(mut u2)) = (browser.try_clone(), up.try_clone()) else { return };
                let (mut b1, mut u1) = (browser, up);
                std::thread::scope(|scope| {
                    scope.spawn(move || {
                        if u2.write_all(&from_browser).is_ok() {
                            let _ = std::io::copy(&mut b1, &mut u2);
                        }
                        let _ = u2.shutdown(std::net::Shutdown::Both);
                        let _ = b1.shutdown(std::net::Shutdown::Both);
                    });
                    if b2.write_all(&early).is_ok() {
                        let _ = std::io::copy(&mut u1, &mut b2);
                    }
                    let _ = b2.shutdown(std::net::Shutdown::Both);
                    let _ = u1.shutdown(std::net::Shutdown::Both);
                });
            }),
        })
    }
}

/// Whether the shop's route for the app at `base` gives each buyer an account: its `/services`
/// says so. Asked when the page is shown; a shop that does not answer is taken to keep none.
fn shop_keeps_accounts(seller: &str) -> bool {
    let Some(origin) = crate::services::http_origin(seller) else { return false };
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(4)).redirects(0).build();
    let Ok(r) = agent.get(&format!("{}/services", origin.trim_end_matches('/'))).call() else { return false };
    let v: Value = serde_json::from_str(&r.into_string().unwrap_or_default()).unwrap_or(Value::Null);
    routes_keep_accounts(&v)
}

/// Whether any route of a shop's list of what it sells keeps buyers' accounts. Any, not the one the app's
/// base falls under: an app's pages reach the shop's other routes too (a Jellyfin listed at `/films/` asks
/// `/` for its accounts), so the owner is offered the choice wherever an account can be made.
fn routes_keep_accounts(services: &Value) -> bool {
    services.get("routes").and_then(Value::as_array).into_iter().flatten().any(|r| r.get("accounts") == Some(&json!(true)))
}

/// What turning anonymous stopped, for the owner: the sessions, and the credit they left with the shop.
fn stopped_note(v: &Value) -> String {
    let stopped = v.get("stopped").and_then(Value::as_array).cloned().unwrap_or_default();
    if stopped.is_empty() {
        return String::new();
    }
    let left: u64 = stopped.iter().filter_map(|s| s.get("left_with_seller_msat").and_then(Value::as_str)?.parse::<u64>().ok()).sum();
    match left / 1000 {
        0 => " Your open session there was stopped.".to_string(),
        sats => format!(" Your open session there was stopped; {sats} sat of credit stays with that shop."),
    }
}

/// A text answer a page's own links are in: HTML, scripts, styles, JSON, SVG and manifests. Video,
/// images and other bytes pass untouched.
fn rewritable(content_type: &str) -> bool {
    let t = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    t.starts_with("text/") || ["application/javascript", "application/json", "application/manifest+json", "application/xml", "image/svg+xml"].contains(&t.as_str())
        || t.ends_with("+json") || t.ends_with("+xml")
}

/// Rewrites a seller's absolute address to `/` in a body as it streams: the app port serves the
/// seller's base at its own `/`, so a page's absolute link to the seller stays in the visit. The
/// base as written, without its scheme (`//host/...`) and with its slashes escaped as JSON writes
/// them. Bytes that may begin an address are held back until the next chunk shows whether they do.
struct Rewriter {
    from: Vec<Vec<u8>>,
    longest: usize,
    held: Vec<u8>,
}

impl Rewriter {
    fn new(bases: &[&str]) -> Self {
        let mut from: Vec<Vec<u8>> = vec![];
        for b in bases.iter().filter(|b| b.ends_with('/') && b.contains("://")) {
            let bare = &b[b.find("://").map_or(0, |i| i + 1)..];
            for f in [b.to_string(), bare.to_string(), b.replace('/', "\\/")] {
                if !from.iter().any(|x| x == f.as_bytes()) {
                    from.push(f.into_bytes());
                }
            }
        }
        // the longest first: `https://host/` before `//host/`
        from.sort_by_key(|f| std::cmp::Reverse(f.len()));
        let longest = from.iter().map(Vec::len).max().unwrap_or(0);
        Self { from, longest, held: vec![] }
    }

    fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        let mut data = std::mem::take(&mut self.held);
        data.extend_from_slice(chunk);
        let mut out = Vec::with_capacity(data.len());
        let mut i = 0;
        while i < data.len() {
            let rest = &data[i..];
            if let Some(f) = self.from.iter().find(|f| rest.starts_with(f)) {
                // the escaped form keeps its escaping
                out.extend_from_slice(if f.ends_with(b"\\/") { b"\\/" } else { b"/" });
                i += f.len();
            } else if rest.len() < self.longest && self.from.iter().any(|f| f.starts_with(rest)) {
                self.held = rest.to_vec();
                break;
            } else {
                out.push(data[i]);
                i += 1;
            }
        }
        out
    }

    fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.held)
    }
}

/// Serve the app ports, on the UI's own address. A port this UI cannot bind is left out, and said
/// in the log: the rest of the app works without it. `Err` only where `strict` and one is left out.
pub fn spawn(app: &Arc<App>, strict: bool) -> Result<Vec<(u16, xbt_svc::http::Running)>, String> {
    let host = app.cfg.bind.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_else(|| "127.0.0.1".into());
    let mut out = vec![];
    for &port in &app.cfg.app_ports {
        let addr = format!("{host}:{port}");
        let run = std::net::TcpListener::bind(&addr).map_err(|e| format!("bind {addr}: {e}"))
            .and_then(|l| xbt_svc::http::serve(Arc::new(AppOrigin { app: app.clone(), port }), l, 8).map_err(|e| format!("serve {addr}: {e}")));
        match run {
            Ok(r) => out.push((port, r)),
            Err(e) if strict => return Err(e),
            Err(e) => eprintln!("xbt-wallet-ui: a seller's app port is left out: {e}"),
        }
    }
    *app.apps.live.lock().unwrap_or_else(|p| p.into_inner()) = out.iter().map(|(p, _)| *p).collect();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A visit that reached its limit waits for its owner to raise it: it is open, so stopping another visit to the same shop
    /// leaves the connection it will go on with. One stopped, or ended any other way, is not.
    ///
    /// FAILS before: any visit that had ended counted as gone, the one at its limit too: stopping another visit to the shop
    /// dropped its grant and closed its connection, and its Add then led to a page that answered 403.
    #[test]
    fn a_visit_at_its_limit_still_holds_the_shops_connection() {
        assert!(holds_open(&json!({"ended": null, "limit_reached": false})));
        assert!(holds_open(&json!({"ended": "This visit's spending limit is reached.", "limit_reached": true})));
        assert!(!holds_open(&json!({"ended": "Stopped.", "limit_reached": false})));
        assert!(!holds_open(&json!({"ended": "This visit's spending limit is reached."})), "a connector that does not say it may go on");
    }

    /// A video app priced by the byte is offered a limit for about ten minutes of 1080p at its price,
    /// not the 1,000 sat a film at 20 sat a MiB spends in under a minute; other apps keep 1,000.
    ///
    /// FAILS before: every app was offered 1,000 sat.
    #[test]
    fn a_video_app_is_offered_a_limit_for_minutes_of_film() {
        let svc = |kind: &str, prices: Value| crate::services::parse(&json!([{"name": "x", "kind": kind, "seller": "http://s.example", "price_text": "a price",
                                                                              "items": [], "app": "http://s.example/web/", "app_base": "http://s.example/",
                                                                              "prices": prices}]).to_string()).unwrap().remove(0);
        // 20 sat a MiB: 600 MiB is 12,000 sat
        assert_eq!(suggested_limit(&svc("video", json!({"byte_msat": 20_000, "per_bytes": 1_048_576}))), 12_000);
        // dear: at most 20,000; cheap: at least 1,000
        assert_eq!(suggested_limit(&svc("video", json!({"byte_msat": 100_000, "per_bytes": 1_048_576}))), SUGGESTED_VIDEO_MAX);
        assert_eq!(suggested_limit(&svc("video", json!({"byte_msat": 100, "per_bytes": 1_048_576}))), SUGGESTED_LIMIT);
        assert_eq!(suggested_limit(&svc("video", json!({"request_msat": 1000}))), SUGGESTED_LIMIT);
        assert_eq!(suggested_limit(&svc("api", json!({"byte_msat": 20_000, "per_bytes": 1_048_576}))), SUGGESTED_LIMIT);
    }

    /// A visit limit of 500 sat is under the smallest ticket with its fees: refused in words, with
    /// the form set to 559, and not opened to fail at its first request with nothing spent.
    #[test]
    fn a_visit_limit_under_the_smallest_ticket_is_raised_with_words() {
        let (words, raised) = visit_limit(Some("500")).unwrap_err();
        assert_eq!(raised, Some(559));
        assert!(words.contains("smallest ticket is 546 sat") && words.contains("set to 559 sat") && words.contains("stays as credit with the shop"), "{words}");
        assert_eq!(visit_limit(Some("559")), Ok(559));
        assert_eq!(visit_limit(Some("1,000")), Ok(1_000));
        assert_eq!(visit_limit(Some("0")).unwrap_err().1, None);
        assert_eq!(visit_limit(None).unwrap_err().1, None);
    }

    /// The limit field says the least a visit needs up front, and starts at 1,000 sat.
    ///
    /// FAILS before: the least was said only under the field, after the owner typed 500.
    #[test]
    fn the_visit_limit_field_says_the_least_up_front_and_starts_at_1000() {
        let f = limit_field(SUGGESTED_LIMIT);
        assert!(f.starts_with("<label>Spend at most on this visit: at least 559 sat<input"), "{f}");
        assert!(f.contains("value=\"1000\""));
    }

    /// The visit's counter: what was used, apart from what was prepaid and is left as credit, during
    /// and after the visit; not the shares held while requests run.
    ///
    /// FAILS before: `spent_sats` was the connector's budget count: 559 of 559 while the film played,
    /// 0 after Stop, though 65 sat were used.
    #[test]
    fn the_visit_counter_shows_what_was_used_and_what_was_prepaid() {
        // playing: the whole limit is held, 30 sat used so far, from credit bought on an earlier visit
        let playing = visit_numbers(&json!({"limit_sats": 559, "spent_sats": 559, "held_sats": 559, "used_msat": 29_400, "paid_sats": 0, "ended": null}));
        assert_eq!((playing["spent_sats"].as_i64(), playing["used_sats"].as_i64(), playing["prepaid_sats"].as_i64()), (Some(30), Some(30), Some(0)));
        // stopped: nothing held, 65 sat used
        let stopped = visit_numbers(&json!({"limit_sats": 559, "spent_sats": 0, "held_sats": 0, "used_msat": 64_870, "paid_sats": 0, "ended": "Stopped."}));
        assert_eq!(stopped["used_sats"].as_i64(), Some(65));
        assert_eq!(stopped["said"], "This visit used 65 sat from your credit with the shop; nothing new was paid.");
        // a ticket bought in the visit: prepaid, and the rest left as credit
        let bought = visit_numbers(&json!({"limit_sats": 1000, "spent_sats": 559, "held_sats": 0, "used_msat": 64_870, "paid_sats": 559, "ended": null}));
        assert_eq!((bought["used_sats"].as_i64(), bought["prepaid_sats"].as_i64(), bought["credit_sats"].as_i64()), (Some(65), Some(559), Some(494)));
        assert_eq!(bought["said"], "This visit used 65 sat. Paid: 559 sat; credit left with the shop: 494 sat.");
        // an older connector: as before
        assert_eq!(visit_numbers(&json!({"limit_sats": 559, "spent_sats": 12}))["spent_sats"].as_i64(), Some(12));
    }

    /// The owner is offered "Stay anonymous here" for a shop where any route keeps accounts, not only
    /// the one its app is listed under: a Jellyfin listed at `/films/` asks `/` for its accounts.
    #[test]
    fn a_shop_keeps_accounts_where_any_of_its_routes_does() {
        let jellyfin = json!({"routes": [{"path": "/files/"}, {"path": "/films/"}, {"path": "/", "accounts": true}]});
        assert!(routes_keep_accounts(&jellyfin));
        assert!(!routes_keep_accounts(&json!({"routes": [{"path": "/files/"}, {"path": "/", "accounts": false}]})));
        assert!(!routes_keep_accounts(&json!({})));
    }

    /// Turning anonymous says what it stopped and what credit stays with the shop.
    #[test]
    fn turning_anonymous_says_what_it_stopped_and_left() {
        assert_eq!(stopped_note(&json!({"stopped": []})), "");
        assert_eq!(stopped_note(&json!({"stopped": [{"left_with_seller_msat": "0"}]})), " Your open session there was stopped.");
        assert_eq!(stopped_note(&json!({"stopped": [{"left_with_seller_msat": "997500"}]})), " Your open session there was stopped; 997 sat of credit stays with that shop.");
    }

    #[test]
    fn the_seller_gets_only_its_own_cookies_and_the_wallets_stay_here() {
        let p = cookie_prefix(8486, "ab12cd34");
        let h = format!("xbt_ui_session=SECRET; {p}jf=1; lsa8487_ffff0000_x=2; __ls_visit_8486=V; {p}theme=dark");
        assert_eq!(own_cookies(&h, &p), "jf=1; theme=dark");
        assert_eq!(own_cookies("xbt_ui_session=SECRET", &p), "");
    }

    /// A page's absolute links to the seller's base stay on the app port, however the body is cut
    /// into chunks; links elsewhere, and the base's look-alikes, are left as they are.
    #[test]
    fn a_pages_absolute_links_to_the_seller_stay_in_the_visit() {
        let page = r#"<a href="https://shop.example/jf/web/x">x</a> <img src="//shop.example/jf/i.png"> {"u":"https:\/\/shop.example\/jf\/api"}
            <a href="https://shop.example/other/">out</a> <a href="https://shop.example.evil/jf/">no</a> https://shop.example/jf"#;
        let want = r#"<a href="/web/x">x</a> <img src="/i.png"> {"u":"\/api"}
            <a href="https://shop.example/other/">out</a> <a href="https://shop.example.evil/jf/">no</a> https://shop.example/jf"#;
        for cut in [1, 2, 3, 7, 13, 64, 4096] {
            let mut r = Rewriter::new(&["https://shop.example/jf/"]);
            let mut got = vec![];
            for c in page.as_bytes().chunks(cut) {
                got.extend(r.feed(c));
            }
            got.extend(r.finish());
            assert_eq!(String::from_utf8(got).unwrap(), want, "chunks of {cut}");
        }
        // a shop reached by a direct link has no web address of its own: its base works the same
        let link = "http://mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dzpiyq.shop.invalid/jf/";
        let mut r = Rewriter::new(&[link]);
        let mut got = r.feed(format!("<a href=\"{link}web/\">x</a> {{\"u\":\"{}api\"}}", link.replace('/', "\\/")).as_bytes());
        got.extend(r.finish());
        assert_eq!(String::from_utf8(got).unwrap(), "<a href=\"/web/\">x</a> {\"u\":\"\\/api\"}");
        assert_ne!(seller_tag(link), seller_tag("http://other.shop.invalid/jf/"), "two linked shops, two cookie prefixes");
        assert!(rewritable("text/html; charset=utf-8") && rewritable("application/javascript") && rewritable("application/vnd.api+json"));
        assert!(!rewritable("video/mp4") && !rewritable("image/png") && !rewritable("application/octet-stream"));
    }

    #[test]
    fn a_sellers_cookie_is_kept_under_the_ports_prefix_and_made_plain_http() {
        let p = "lsa8486_ab12cd34_";
        assert_eq!(own_set_cookie("sid=abc; Path=/; Domain=seller.example; Secure; HttpOnly; SameSite=None", p).unwrap(),
                   "lsa8486_ab12cd34_sid=abc; Path=/; HttpOnly");
        assert!(own_set_cookie("bad name=1", p).is_none());
    }
}
