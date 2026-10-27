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

use crate::app::{App, Ctx};
use crate::html::esc;
use crate::server::Resp;

/// A one-time code is good for this long.
const CODE_TTL: Duration = Duration::from_secs(60);
/// The visit's limit the page suggests, in sats.
pub const SUGGESTED_LIMIT: i64 = 1_000;
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
}

#[derive(Default)]
struct State {
    /// By port: the seller (origin) that has it, and when it was last given out.
    ports: HashMap<u16, (String, Instant)>,
    /// One-time codes: code → (made, grant, the port's storage is someone else's).
    codes: HashMap<String, (Instant, Grant, bool)>,
    /// Cookies: secret → grant.
    grants: HashMap<String, Grant>,
}

#[derive(Default)]
pub struct AppOrigins {
    state: Mutex<State>,
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

/// `scheme://host[:port]/` of a URL, lower case.
fn origin_of(url: &str) -> String {
    crate::services::http_origin(url).unwrap_or_default()
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
    fn app_ports(&self) -> &[u16] {
        &self.cfg.app_ports
    }

    /// A port for `seller`: the one it had, else a free one, else the one given out longest ago.
    /// `true`: the port's storage was another seller's.
    fn port_for(&self, seller: &str) -> Option<(u16, bool)> {
        let ports = self.app_ports();
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
        let host = crate::app::stream_pages::host(&svc.seller);
        let b = format!("<section class=\"card primary\"><h2>Open {}'s app</h2>\
            <p>You use <strong>{}</strong> as it is on {}'s own network, inside this page. What it loads is paid at {}, \
            and stops at the limit you set here.</p>\
            <form method=\"post\" action=\"./app\">{}<input type=\"hidden\" name=\"u\" value=\"{}\"><input type=\"hidden\" name=\"b\" value=\"{}\">\
            <label>Spend at most, on this visit, in sats<input name=\"limit\" value=\"{SUGGESTED_LIMIT}\" required inputmode=\"numeric\" pattern=\"[0-9]+\"></label>\
            <p class=\"hint\">A seller sells in tickets, often 546 sats or more, so a visit needs at least that. Your spending rules apply as well.</p>\
            <div class=\"row\"><button>Open the app</button><a href=\"./browse\">Cancel</a></div></form></section>\
            <p class=\"small\">The app runs apart from your wallet: it cannot see your keys, your rules or this page.</p>",
            esc(&host), esc(&svc.name), esc(&host), esc(&svc.price_text), App::csrf_input(ctx), esc(&entry), esc(&base));
        self.page("Open the app", ctx, b)
    }

    /// `POST /app`: the visit opened, and the page in its frame.
    pub(crate) fn app_open(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let (entry, base) = (f.get("u").cloned().unwrap_or_default(), f.get("b").cloned().unwrap_or_default());
        let Some(svc) = self.file_services().ok().and_then(|all| all.into_iter().find(|s| !s.app.is_empty() && s.app == entry && s.app_base == base)) else {
            self.flash(ctx, false, "That app is not one of your sellers' any more.");
            return Resp::redirect("./browse");
        };
        let limit: i64 = f.get("limit").and_then(|v| v.trim().replace(',', "").parse().ok()).unwrap_or(0);
        if !(1..=10_000_000).contains(&limit) {
            self.flash(ctx, false, "Set a limit of 1 sat or more.");
            return Resp::redirect(&format!("./app?u={}&b={}", crate::services::urlenc(&entry), crate::services::urlenc(&base)));
        }
        let seller = origin_of(&base);
        let Some((port, other)) = self.port_for(&seller) else {
            self.flash(ctx, false, "This box does not open sellers' apps.");
            return Resp::redirect("./browse");
        };
        let opened = connector_json("POST", &format!("{}/visits", self.cfg.connector.trim_end_matches('/')), Some(&json!({"base": base, "limit_sats": limit})));
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
        let grant = Grant { visit: visit.clone(), port, base: base.clone(), entry: format!("/{path}"), tag: seller_tag(&seller) };
        let code = secret();
        {
            let mut s = self.apps.lock();
            s.codes.retain(|_, (t, _, _)| t.elapsed() < CODE_TTL);
            s.codes.insert(code.clone(), (Instant::now(), grant, other));
        }
        let host = crate::app::stream_pages::host(&svc.seller);
        let b = format!("<section class=\"card app-visit\" data-visit=\"{}\" data-port=\"{port}\" data-code=\"{}\">\
            <div class=\"offer-head\"><h2>{}</h2><span class=\"pill good\" data-visit-state>Open</span></div>\
            <p><span data-visit-spent>0</span> of <strong>{} sat</strong> spent on this visit &middot; {} \
            <form method=\"post\" action=\"./app-stop\" class=\"inline\">{}<input type=\"hidden\" name=\"visit\" value=\"{}\"><button class=\"danger\">Stop</button></form></p>\
            <iframe class=\"seller-app\" title=\"{}\" sandbox=\"allow-scripts allow-same-origin allow-forms allow-downloads allow-modals allow-pointer-lock\" \
            allow=\"fullscreen; autoplay; encrypted-media; picture-in-picture\" referrerpolicy=\"no-referrer\"></iframe>\
            <p class=\"hint\" data-visit-note>{}'s own page. It cannot see your wallet. Close this page or press Stop to end the visit.</p></section>",
            esc(&visit), esc(&code), esc(&svc.name), limit, esc(&svc.price_text), App::csrf_input(ctx), esc(&visit), esc(&svc.name), esc(&host));
        let frames: String = self.app_ports().iter().map(|p| format!(" http://*:{p} https://*:{p}")).collect();
        let csp = format!("{}; media-src 'self'; frame-src{frames}", crate::server::CSP);
        self.page(&format!("{}'s app", host), ctx, b).header("Content-Security-Policy", &csp)
    }

    /// `POST /app-stop`.
    pub(crate) fn app_stop(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let visit = f.get("visit").cloned().unwrap_or_default();
        if visit.bytes().all(|b| b.is_ascii_hexdigit()) && !visit.is_empty() {
            let _ = connector_json("POST", &format!("{}/visits/{visit}/stop", self.cfg.connector.trim_end_matches('/')), Some(&json!({})));
            self.apps.lock().grants.retain(|_, g| g.visit != visit);
        }
        self.flash(ctx, true, "Stopped. The app is closed and nothing more is paid for it.");
        Resp::redirect("./browse")
    }

    /// `GET /api/visit?v=<id>`: what the visit has spent.
    pub(crate) fn api_visit(&self, q: &HashMap<String, String>) -> Resp {
        let visit = q.get("v").cloned().unwrap_or_default();
        if visit.is_empty() || !visit.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Resp::json(400, &json!({"error": "no visit"}));
        }
        match connector_json("GET", &format!("{}/visits/{visit}", self.cfg.connector.trim_end_matches('/')), None) {
            Ok((200, v)) => {
                Resp::json(200, &json!({"spent_sats": v["spent_sats"], "limit_sats": v["limit_sats"], "ended": v["ended"]}))
            }
            _ => Resp::json(200, &json!({"ended": "This visit has ended."})),
        }
    }
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
    let html = format!("<!doctype html><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>Lightning Stream</title>\
        <body style=\"font:16px system-ui,sans-serif;margin:2rem;color:#222\"><p>{}</p></body>", esc(s));
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
            xbt_svc::http::Reply::Stream(_) => xbt_svc::http::Response::text(500, "text/plain", "streamed"),
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
        if rq.header("upgrade").is_some() {
            return text(501, "This app asked for a live connection (WebSocket), which Lightning Stream cannot carry yet.");
        }
        let prefix = cookie_prefix(self.port, &g.tag);
        let target = rq.target.trim_start_matches('/');
        let url = format!("{}/v/{}/{target}", self.app.cfg.connector.trim_end_matches('/'), g.visit);
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
            let v: Value = serde_json::from_str(&resp.into_string().unwrap_or_default()).unwrap_or(Value::Null);
            let words = v.get("error").and_then(Value::as_str).unwrap_or("The visit has ended.");
            return text(status, &format!("{words} Back in Lightning Stream, you can open the app again with a new limit."));
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
                    "location" => headers.push(("Location".into(), match v.strip_prefix(&g.base) {
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
        let length = resp.header("content-length").and_then(|n| n.parse::<u64>().ok());
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
                        return Ok(());
                    }
                    out.send(&buf[..n])?;
                }
            }),
        })
    }
}

/// Serve every app port, on the UI's own address.
pub fn spawn(app: &Arc<App>) -> Result<Vec<(u16, xbt_svc::http::Running)>, String> {
    let host = app.cfg.bind.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_else(|| "127.0.0.1".into());
    let mut out = vec![];
    for &port in &app.cfg.app_ports {
        let addr = format!("{host}:{port}");
        let l = std::net::TcpListener::bind(&addr).map_err(|e| format!("bind {addr}: {e}"))?;
        let run = xbt_svc::http::serve(Arc::new(AppOrigin { app: app.clone(), port }), l, 8).map_err(|e| format!("serve {addr}: {e}"))?;
        out.push((port, run));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seller_gets_only_its_own_cookies_and_the_wallets_stay_here() {
        let p = cookie_prefix(8486, "ab12cd34");
        let h = format!("xbt_ui_session=SECRET; {p}jf=1; lsa8487_ffff0000_x=2; __ls_visit_8486=V; {p}theme=dark");
        assert_eq!(own_cookies(&h, &p), "jf=1; theme=dark");
        assert_eq!(own_cookies("xbt_ui_session=SECRET", &p), "");
    }

    #[test]
    fn a_sellers_cookie_is_kept_under_the_ports_prefix_and_made_plain_http() {
        let p = "lsa8486_ab12cd34_";
        assert_eq!(own_set_cookie("sid=abc; Path=/; Domain=seller.example; Secure; HttpOnly; SameSite=None", p).unwrap(),
                   "lsa8486_ab12cd34_sid=abc; Path=/; HttpOnly");
        assert!(own_set_cookie("bad name=1", p).is_none());
    }
}
