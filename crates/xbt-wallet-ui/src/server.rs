//! The HTTP server: [`xbt_svc::http`] (header caps, read deadlines, a connection limit) with a few
//! handlers at once, requests reduced to [`Req`], answers as [`Resp`] with the security headers on every
//! response the app makes.
use std::collections::HashMap;
use std::sync::Arc;

use crate::app::App;

pub const MAX_BODY: usize = 256 * 1024;

pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; \
                       form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

#[derive(Debug, Default, Clone)]
pub struct Req {
    pub method: String,
    /// The path below the base path, starting with `/` (`/`, `/approvals`, ...).
    pub path: String,
    pub query: HashMap<String, String>,
    /// Lower-case names.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub peer: String,
}

impl Req {
    pub fn header(&self, k: &str) -> &str {
        self.headers.get(k).map(String::as_str).unwrap_or("")
    }

    pub fn cookie(&self, name: &str) -> Option<String> {
        self.header("cookie").split(';').filter_map(|c| c.trim().split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v.to_string())
    }

    pub fn form(&self) -> HashMap<String, String> {
        parse_qs(&String::from_utf8_lossy(&self.body))
    }
}

#[derive(Debug, Clone)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn html(status: u16, body: String) -> Self {
        Self { status, headers: vec![("Content-Type".into(), "text/html; charset=utf-8".into())], body: body.into_bytes() }
    }

    pub fn text(status: u16, ctype: &str, body: impl Into<Vec<u8>>) -> Self {
        Self { status, headers: vec![("Content-Type".into(), ctype.into())], body: body.into() }
    }

    pub fn json(status: u16, v: &serde_json::Value) -> Self {
        Self::text(status, "application/json", v.to_string())
    }

    /// 303 to a relative location (`./approvals`).
    pub fn redirect(to: &str) -> Self {
        Self { status: 303, headers: vec![("Location".into(), to.into())], body: vec![] }
    }

    pub fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }
}

fn hexval(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

pub fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                match (hexval(b[i + 1]), hexval(b[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push(h * 16 + l);
                        i += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_qs(s: &str) -> HashMap<String, String> {
    s.split('&').filter(|p| !p.is_empty()).map(|p| {
        let (k, v) = p.split_once('=').unwrap_or((p, ""));
        (url_decode(k), url_decode(v))
    }).collect()
}

/// Strip the base path; `None` when the path is outside it.
pub fn strip_base(path: &str, base: &str) -> Option<String> {
    if base == "/" {
        return Some(path.to_string());
    }
    let b = base.trim_end_matches('/');
    if path == b {
        return Some(String::new()); // the bare prefix: redirected to "prefix/"
    }
    path.strip_prefix(b).filter(|r| r.starts_with('/')).map(str::to_string).or_else(|| Some(path.to_string()))
}

/// The security headers of every answer.
pub fn security_headers(r: &mut Resp) {
    // a page that frames a seller's own app sets its own policy, the same one with its frame-src
    if !r.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("Content-Security-Policy")) {
        r.headers.push(("Content-Security-Policy".into(), format!("{CSP}; media-src 'self'")));
    }
    for (k, v) in [("X-Frame-Options", "DENY"), ("X-Content-Type-Options", "nosniff"),
                   ("Referrer-Policy", "no-referrer"), ("Cross-Origin-Opener-Policy", "same-origin"),
                   ("Cross-Origin-Resource-Policy", "same-origin"), ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=()")] {
        r.headers.push((k.into(), v.into()));
    }
    if !r.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("Cache-Control")) {
        r.headers.push(("Cache-Control".into(), "no-store".into()));
    }
}

struct Ui(Arc<App>);

/// The authority (`host[:port]`) of an `http(s)://` origin or URL; `None` for anything else,
/// `"null"` included.
fn authority(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let a = rest.split(['/', '?', '#']).next().unwrap_or("");
    (!a.is_empty()).then_some(a)
}

/// A request another page asked for: another origin of the same site (another app of the box, on
/// another port of this host) or another site. The browser sends the wallet's cookie with the
/// first, `SameSite=Strict` notwithstanding, so such a request could have the wallet stream, and
/// pay for, what that page names, or act with the owner's session. Only the opening of the home
/// page is answered; a page it names opens the home page instead, and anything else is refused.
///
/// Where the browser says (`Sec-Fetch-Site`), that is the answer. An older browser that does not is
/// judged by `Origin`, then `Referer`, against `Host` (or `X-Forwarded-Host` behind a proxy): an
/// action whose page is elsewhere is refused, and a page opened from elsewhere is the home page. A
/// request that says nothing at all passes here: an action still needs the session's CSRF token,
/// which no other page can read.
fn foreign_refused(method: &str, target: &str, base: &str, headers: &[(String, String)]) -> Option<Resp> {
    let h = |k: &str| headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.trim()).unwrap_or("");
    let read_only = matches!(method, "GET" | "HEAD");
    let path = target.split('?').next().unwrap_or("");
    let home = strip_base(path, base).is_some_and(|p| p.is_empty() || p == "/");
    let home_url = format!("{}/", base.trim_end_matches('/'));
    let (foreign, navigate) = match h("sec-fetch-site").to_ascii_lowercase().as_str() {
        "same-origin" | "none" => return None,
        "" => {
            let own: Vec<&str> = [h("x-forwarded-host"), h("host")].into_iter().filter(|a| !a.is_empty()).collect();
            let elsewhere = |v: &str| !v.is_empty() && authority(v).is_none_or(|a| !own.iter().any(|o| o.eq_ignore_ascii_case(a)));
            // `null` is what the UI's own pages send under `Referrer-Policy: no-referrer`: no word, like none
            let origin = Some(h("origin")).filter(|o| !o.is_empty() && !o.eq_ignore_ascii_case("null"));
            let foreign = match origin { Some(o) => elsewhere(o), None => elsewhere(h("referer")) };
            // an older browser does not say how it asks: a read is taken for the opening of a page
            (foreign, read_only)
        }
        _ => (true, h("sec-fetch-mode").eq_ignore_ascii_case("navigate") && read_only),
    };
    if !foreign || (navigate && home) {
        return None;
    }
    if navigate {
        return Some(Resp::redirect(&home_url));
    }
    Some(Resp::text(403, "text/plain", "refused: a request from another page (another app of this box, or another site)"))
}

impl xbt_svc::http::Handler for Ui {
    fn body_limit(&self, _method: &str, _target: &str) -> usize {
        MAX_BODY
    }

    fn handle(&self, rq: xbt_svc::http::Request) -> xbt_svc::http::Response {
        if let Some(mut r) = foreign_refused(&rq.method.to_uppercase(), &rq.target, &self.0.cfg.base_path, &rq.headers) {
            security_headers(&mut r);
            return xbt_svc::http::Response::new(r.status, r.headers, r.body);
        }
        let peer = rq.peer.map(|a| a.ip().to_string()).unwrap_or_default();
        let (raw_path, q) = rq.target.split_once('?').unwrap_or((&rq.target, ""));
        let headers = rq.headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.clone())).collect();
        let req = Req { method: rq.method.to_uppercase(), path: raw_path.to_string(), query: parse_qs(q), headers, body: rq.body, peer };
        let mut resp = self.0.handle(req);
        security_headers(&mut resp);
        xbt_svc::http::Response::new(resp.status, resp.headers, resp.body)
    }

    /// Every request, past the check for one another page asked for ([`foreign_refused`]), then
    /// [`Self::handle`]. A seller's media server is a web app ([`crate::seller_app`]); this UI
    /// streams no video of its own.
    fn reply(&self, rq: xbt_svc::http::Request) -> xbt_svc::http::Reply {
        if let Some(mut r) = foreign_refused(&rq.method.to_uppercase(), &rq.target, &self.0.cfg.base_path, &rq.headers) {
            security_headers(&mut r);
            return xbt_svc::http::Reply::Whole(xbt_svc::http::Response::new(r.status, r.headers, r.body));
        }
        xbt_svc::http::Reply::Whole(self.handle(rq))
    }
}

/// A running server; stops when dropped.
pub struct Running {
    pub addr: std::net::SocketAddr,
    stop: xbt_svc::http::Stop,
    /// The app ports and their servers ([`crate::seller_app`]).
    pub app_ports: Vec<(u16, std::net::SocketAddr)>,
    apps: Vec<xbt_svc::http::Stop>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.stop();
        for s in &self.apps {
            s.stop();
        }
    }
}

impl Running {
    /// Stop taking connections and wait at most `bound` for the open ones (a stop signal). The UI's
    /// files are written whole (a temp file, fsynced, renamed), so nothing waits to be flushed.
    /// True: every request in flight ended.
    pub fn finish(&self, bound: std::time::Duration) -> bool {
        self.stop.drain(bound)
    }
}

pub fn spawn(app: Arc<App>) -> Result<Running, String> {
    let listener = std::net::TcpListener::bind(&app.cfg.bind).map_err(|e| format!("bind {}: {e}", app.cfg.bind))?;
    let threads = app.cfg.threads;
    // strict for a test (`XBT_UI_APP_PORTS_STRICT`), which tries a port taken in between again on another
    let apps = crate::seller_app::spawn(&app, std::env::var_os("XBT_UI_APP_PORTS_STRICT").is_some())?;
    let run = xbt_svc::http::serve(Arc::new(Ui(app)), listener, threads).map_err(|e| format!("serve: {e}"))?;
    let app_ports = apps.iter().map(|(p, r)| (*p, r.addr)).collect();
    let apps = apps.iter().map(|(_, r)| r.stopper()).collect();
    Ok(Running { addr: run.addr, stop: run.stopper(), app_ports, apps })
}
