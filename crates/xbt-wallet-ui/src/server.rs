//! The HTTP server: [`xbt_svc::http`] (header caps, read deadlines, a connection limit) with a few
//! handlers at once, requests reduced to [`Req`], answers as [`Resp`] with the security headers on every
//! response the app makes.
use std::collections::HashMap;
use std::sync::Arc;

use crate::app::App;

pub const MAX_BODY: usize = 256 * 1024;

pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; \
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

/// The security headers of every answer. Video plays from this page's own origin: the UI relays
/// the connector (`/s/…`).
pub fn security_headers(r: &mut Resp) {
    let csp = format!("{CSP}; media-src 'self'");
    for (k, v) in [("Content-Security-Policy", csp.as_str()), ("X-Frame-Options", "DENY"), ("X-Content-Type-Options", "nosniff"),
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
/// and a stream the session's stream token ([`App::stream_token`]), which no other page can read.
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

    /// A paid video: `GET /s/<seller URL>` for the page's player, past the same checks as every
    /// page, or `GET /r/<token>` for an external player's link ([`crate::relay`]), relayed from the
    /// connector as it streams, with the player's `Range`. Everything else is [`Self::handle`].
    fn reply(&self, rq: xbt_svc::http::Request) -> xbt_svc::http::Reply {
        if let Some(mut r) = foreign_refused(&rq.method.to_uppercase(), &rq.target, &self.0.cfg.base_path, &rq.headers) {
            security_headers(&mut r);
            return xbt_svc::http::Reply::Whole(xbt_svc::http::Response::new(r.status, r.headers, r.body));
        }
        let peer = rq.peer.map(|a| a.ip().to_string()).unwrap_or_default();
        let (raw_path, q) = rq.target.split_once('?').unwrap_or((&rq.target, ""));
        let headers = rq.headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.clone())).collect();
        let req = Req { method: rq.method.to_uppercase(), path: raw_path.to_string(), query: parse_qs(q), headers, body: vec![], peer };
        // the owner's free preview of an item of their own shop, straight from the service on the box
        if let Some(gate) = self.0.preview_gate(&req) {
            return match gate {
                Err(mut resp) => {
                    security_headers(&mut resp);
                    xbt_svc::http::Reply::Whole(xbt_svc::http::Response::new(resp.status, resp.headers, resp.body))
                }
                Ok(url) => relay(&url, req.headers.get("range").map(String::as_str), &|_, _| {}),
            };
        }
        match self.0.relay_gate(&req) {
            None => xbt_svc::http::Reply::Whole(self.handle(rq)),
            Some(Err(mut resp)) => {
                security_headers(&mut resp);
                xbt_svc::http::Reply::Whole(xbt_svc::http::Response::new(resp.status, resp.headers, resp.body))
            }
            Some(Ok(item)) => {
                // for /s/~<stream token>/, the seller URL is everything after the token, its own query included
                let item = item.unwrap_or_else(|| {
                    let after = rq.target.split_once("/s/").map(|(_, u)| u).unwrap_or_default();
                    after.strip_prefix('~').and_then(|t| t.split_once('/')).map(|(_, u)| u.to_string()).unwrap_or_default()
                });
                let url = format!("{}/s/{item}", self.0.cfg.connector.trim_end_matches('/'));
                let app = self.0.clone();
                relay(&url, req.headers.get("range").map(String::as_str), &move |code, body| app.note_play_error(&item, code, body))
            }
        }
    }
}

/// The headers of a relayed answer that are passed on from the connector.
const RELAYED: [&str; 3] = ["Content-Type", "Content-Range", "Accept-Ranges"];

/// Stream the answer at `url` (the connector's for a seller URL, or the owner's own service for a
/// preview) to the player, with the player's `Range` (the connector takes one plain byte range and
/// ignores any other). An answer that is not a success is handed whole to `failed` first, so the
/// player page can say why.
fn relay(url: &str, range: Option<&str>, failed: &dyn Fn(u16, &[u8])) -> xbt_svc::http::Reply {
    let agent = ureq::AgentBuilder::new().timeout_connect(std::time::Duration::from_secs(5)).redirects(0).build();
    let mut rq = agent.get(url);
    if let Some(r) = range.map(str::trim).filter(|r| r.len() <= 128 && r.bytes().all(|b| b.is_ascii_graphic() || b == b' ')) {
        rq = rq.set("Range", r);
    }
    let passed = |r: &ureq::Response| -> Vec<(String, String)> {
        RELAYED.iter().filter_map(|k| r.header(k).map(|v| (k.to_string(), v.to_string()))).collect()
    };
    let resp = match rq.call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code, r)) => {
            let headers = passed(&r).into_iter().filter(|(k, _)| k != "Content-Type").collect::<Vec<_>>();
            let body = r.into_string().unwrap_or_default().into_bytes();
            failed(code, &body);
            let mut whole = Resp::text(code, "application/json", body);
            whole.headers.extend(headers);
            security_headers(&mut whole);
            return xbt_svc::http::Reply::Whole(xbt_svc::http::Response::new(whole.status, whole.headers, whole.body));
        }
        Err(e) => {
            let v = serde_json::json!({"error": format!("the connector: {e}")});
            failed(502, v.to_string().as_bytes());
            let mut whole = Resp::json(502, &v);
            security_headers(&mut whole);
            return xbt_svc::http::Reply::Whole(xbt_svc::http::Response::new(whole.status, whole.headers, whole.body));
        }
    };
    let status = resp.status();
    let mut headers = passed(&resp);
    if !headers.iter().any(|(k, _)| k == "Content-Type") {
        headers.push(("Content-Type".into(), "application/octet-stream".into()));
    }
    headers.extend([("Cache-Control".to_string(), "no-store".to_string()), ("X-Content-Type-Options".into(), "nosniff".into()),
                    ("Cross-Origin-Resource-Policy".into(), "same-origin".into())]);
    let length = resp.header("Content-Length").and_then(|n| n.parse::<u64>().ok());
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
                // a player that has gone: the connection to the connector closes, and the wallet stops paying
                out.send(&buf[..n])?;
            }
        }),
    })
}

/// A running server; stops when dropped.
pub struct Running {
    pub addr: std::net::SocketAddr,
    stop: xbt_svc::http::Stop,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.stop();
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
    let run = xbt_svc::http::serve(Arc::new(Ui(app)), listener, threads).map_err(|e| format!("serve: {e}"))?;
    Ok(Running { addr: run.addr, stop: run.stopper() })
}
