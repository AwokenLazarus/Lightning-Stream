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
/// and a download the session's stream token ([`App::stream_token`]), which no other page can read.
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
        let get = req.method == "GET" || req.method == "HEAD";
        // an action changes what the pages show: they ask the signer afresh, during it and after it
        if !get {
            self.0.signer.forget();
        }
        let timing = crate::perf::Request::begin(get);
        let mut resp = self.0.handle(req);
        if !get {
            self.0.signer.forget();
        }
        security_headers(&mut resp);
        resp.headers.push(("Server-Timing".into(), timing.server_timing()));
        if timing.elapsed() >= crate::perf::slow_limit() {
            eprintln!("xbt-wallet-ui: slow request: {} {} took {:.0} ms ({})", rq.method.to_uppercase(), log_path(raw_path),
                      timing.elapsed().as_secs_f64() * 1000.0, timing.server_timing());
        }
        xbt_svc::http::Response::new(resp.status, resp.headers, resp.body)
    }

    /// A paid file: `GET /s/~<stream token>/<file URL>` for a download from the page, past the same
    /// checks as every page, or `GET /r/<token>` for the buyer's own player ([`crate::relay`]),
    /// relayed from the connector as it streams, with the reader's `Range`. Everything else is
    /// [`Self::handle`]. A seller's media server is a web app ([`crate::seller_app`]): this UI has no
    /// player of its own.
    ///
    /// A player's `HEAD /r/<token>` (some ask that first) passes the same gate as its `GET` (token,
    /// expiry, revocation, the file still listed) and is answered here, with no body ([`link_head`]):
    /// the connector is not called, so nothing is paid, and the link's use is not counted.
    fn reply(&self, rq: xbt_svc::http::Request) -> xbt_svc::http::Reply {
        if let Some(mut r) = foreign_refused(&rq.method.to_uppercase(), &rq.target, &self.0.cfg.base_path, &rq.headers) {
            security_headers(&mut r);
            return xbt_svc::http::Reply::Whole(xbt_svc::http::Response::new(r.status, r.headers, r.body));
        }
        let peer = rq.peer.map(|a| a.ip().to_string()).unwrap_or_default();
        let (raw_path, q) = rq.target.split_once('?').unwrap_or((&rq.target, ""));
        let headers = rq.headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.clone())).collect();
        let method = rq.method.to_uppercase();
        let head = method == "HEAD" && strip_base(raw_path, &self.0.cfg.base_path).is_some_and(|p| p.starts_with("/r/"));
        // a link's HEAD is gated as its GET
        let req = Req { method: if head { "GET".into() } else { method }, path: raw_path.to_string(), query: parse_qs(q), headers, body: vec![], peer };
        match self.0.relay_gate(&req) {
            None => xbt_svc::http::Reply::Whole(self.handle(rq)),
            Some(Err(mut resp)) => {
                security_headers(&mut resp);
                xbt_svc::http::Reply::Whole(xbt_svc::http::Response::new(resp.status, resp.headers, resp.body))
            }
            Some(Ok(Some(item))) if head => {
                let token = strip_base(raw_path, &self.0.cfg.base_path).and_then(|p| p.strip_prefix("/r/").map(str::to_string)).unwrap_or_default();
                link_head(&self.0, &item, &token)
            }
            Some(Ok(item)) => {
                // for /s/~<stream token>/, the seller URL is everything after the token, its own query included
                let item = item.unwrap_or_else(|| {
                    let after = rq.target.split_once("/s/").map(|(_, u)| u).unwrap_or_default();
                    after.strip_prefix('~').and_then(|t| t.split_once('/')).map(|(_, u)| u.to_string()).unwrap_or_default()
                });
                let url = format!("{}/s/{item}", self.0.cfg.connector.trim_end_matches('/'));
                // a range is asked for in parts of at most READ_CHUNK, whatever the reader asked
                let range = bounded_range(req.headers.get("range").map(String::as_str), READ_CHUNK);
                // the file's service's listed prices: the most each part is paid at
                let ceiling = self.0.relay_ceiling(&req, &item);
                // and its listed size: the most bytes, and so sats, one part may cost
                let limit = self.0.relay_limit(&req, &item, range.as_deref().and_then(range_len));
                // a refusal is a page of the app's, in words; one of no route says what the node can send
                let base = self.0.cfg.base_path.clone();
                let app = self.0.clone();
                let page = move |body: &str| {
                    let no_route = crate::pay_feedback::explain(body, None, true).kind == crate::pay_feedback::Kind::NoRoute;
                    refused_html(body, &base, if no_route { app.spendable_sats() } else { None })
                };
                // a player's link counts what it carries, for its row on the Files page
                let used = strip_base(&req.path, &self.0.cfg.base_path).and_then(|p| p.strip_prefix("/r/").and_then(|t| self.0.relays.usage(t)));
                let reply = relay(&url, range.as_deref(), req.headers.get("if-range").map(String::as_str), ceiling.as_ref(), limit, &page);
                match (used, reply) {
                    (Some(used), xbt_svc::http::Reply::Stream(mut s)) => {
                        // the file's whole size, for the link's HEAD (a player may ask it for the size)
                        if let Some(n) = whole_size(s.status, s.length, &s.headers) {
                            used.learn_size(n);
                        }
                        let body = s.body;
                        s.body = Box::new(move |out: &mut dyn xbt_svc::http::BodyWriter| {
                            let _open = used.start();
                            body(&mut Counted { out, used: &used })
                        });
                        xbt_svc::http::Reply::Stream(s)
                    }
                    (_, r) => r,
                }
            }
        }
    }
}

/// The answer to a player's `HEAD` of the live link `token` for `item`: what its `GET` answers when the
/// file is sent whole (`200`, the type its URL names, ranges taken, its length where it is known), and
/// no body. The length is the listing's, where the link's service lists the file in exact bytes, or else
/// the one the shop's answer to an earlier request through the link gave ([`whole_size`]); not known, no
/// `Content-Length`. The connector is not asked: any request of it is a paid call. A `Range` is ignored,
/// as HTTP has it for `HEAD`.
fn link_head(app: &App, item: &str, token: &str) -> xbt_svc::http::Reply {
    let service = app.relays.service_of(token).unwrap_or_default();
    let listed = app.services().ok().and_then(|all| {
        let found = if service.is_empty() { None } else { crate::services::find_item_of(&all, &service, item) };
        found.or_else(|| crate::services::find_item(&all, item)).and_then(|(_, it)| exact_bytes(&it.credit))
    });
    let size = listed.or_else(|| app.relays.usage(token).and_then(|u| u.size()));
    let headers = vec![("Content-Type".to_string(), media_type_of(item).to_string()), ("Accept-Ranges".into(), "bytes".into()),
                       ("Cache-Control".into(), "no-store".into()), ("X-Content-Type-Options".into(), "nosniff".into()),
                       ("Cross-Origin-Resource-Policy".into(), "same-origin".into())];
    xbt_svc::http::Reply::Stream(xbt_svc::http::Streamed { status: 200, headers, length: size, body: Box::new(|_| Ok(())) })
}

/// A file's whole size from a relayed answer: a `200`'s length, or the total of a `206`'s
/// `Content-Range` (`bytes 0-99/1234`; `*` is not known).
fn whole_size(status: u16, length: Option<u64>, headers: &[(String, String)]) -> Option<u64> {
    match status {
        200 => length,
        206 => headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("Content-Range"))
            .and_then(|(_, v)| v.trim().strip_prefix("bytes ")?.rsplit_once('/')?.1.trim().parse().ok()),
        _ => None,
    }
}

/// A listing's size when it is exact (`N bytes`); a rounded one (`1.2 GB`) is no `Content-Length`.
fn exact_bytes(words: &str) -> Option<u64> {
    words.trim().strip_suffix(" bytes").and_then(|n| n.trim().parse().ok())
}

/// A file's media type from its URL's extension, for a `HEAD` the seller is not asked about.
fn media_type_of(url: &str) -> &'static str {
    let path = url.split(['?', '#']).next().unwrap_or("").to_ascii_lowercase();
    let ext = path.rsplit_once('/').map_or(path.as_str(), |(_, f)| f).rsplit_once('.').map_or("", |(_, e)| e);
    match ext {
        "mp4" | "m4v" => "video/mp4",
        "mkv" => "video/x-matroska",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "ts" => "video/mp2t",
        "m3u8" => "application/vnd.apple.mpegurl",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "flac" => "audio/flac",
        "ogg" | "oga" => "audio/ogg",
        "opus" => "audio/opus",
        "wav" => "audio/wav",
        _ => "application/octet-stream",
    }
}

/// The player links' own listener (`XBT_UI_LINKS_BIND`): `GET /r/<token>` (and its `HEAD`), through the UI's own
/// relay ([`Ui::reply`]: the same checks, limits, counting and revocation), and nothing else: no page,
/// no action, no download, no API. It is for a platform whose login sits in front of the UI's port
/// (umbrelOS's app login), which a player on another device cannot pass.
struct Links(Arc<App>);

impl Links {
    /// Whether this listener answers the request: a `GET` or `HEAD` of `/r/<something>` (the token is checked by the relay).
    fn serves(&self, rq: &xbt_svc::http::Request) -> bool {
        let path = rq.target.split('?').next().unwrap_or("");
        (rq.method.eq_ignore_ascii_case("GET") || rq.method.eq_ignore_ascii_case("HEAD")) && self.0.cfg.role != crate::config::Role::Gateway
            && strip_base(path, &self.0.cfg.base_path).is_some_and(|p| p.strip_prefix("/r/").is_some_and(|t| !t.is_empty()))
    }

    fn not_found() -> xbt_svc::http::Response {
        let mut r = Resp::text(404, "text/plain", "not found: this port serves only links for your player");
        security_headers(&mut r);
        xbt_svc::http::Response::new(r.status, r.headers, r.body)
    }
}

impl xbt_svc::http::Handler for Links {
    fn body_limit(&self, _method: &str, _target: &str) -> usize {
        0
    }

    fn handle(&self, _rq: xbt_svc::http::Request) -> xbt_svc::http::Response {
        Self::not_found()
    }

    fn reply(&self, rq: xbt_svc::http::Request) -> xbt_svc::http::Reply {
        if !self.serves(&rq) {
            return xbt_svc::http::Reply::Whole(Self::not_found());
        }
        xbt_svc::http::Handler::reply(&Ui(self.0.clone()), rq)
    }
}

/// A path as the slow-request log line shows it: a link's token (`/r/`, `/s/~`) is never logged.
pub fn log_path(path: &str) -> String {
    let cut = ["/r/", "/s/"].iter().filter_map(|m| path.find(m).map(|i| i + m.len())).min();
    let p = match cut {
        Some(i) => format!("{}…", &path[..i]),
        None => path.to_string(),
    };
    p.chars().take(80).collect()
}

/// The most one ranged request of a reader buys at once: 4 MiB.
///
/// A player (VLC, mpv, a TV app) reads ahead of the picture, and a paused one may go on filling its
/// buffer, and every byte of it is paid for. So the relay never asks the connector for more than
/// this in one ranged answer: a `Range` that is open (`bytes=N-`) or longer is cut to this length,
/// and the seller answers `206` with that part. The player asks for the next part when it needs it,
/// as it does for any server that answers in parts. However it stops, what it is charged beyond
/// what it received is at most one such part. A download asks for no range: the whole file, paid as
/// it arrives, and stopped when the download is.
pub const READ_CHUNK: u64 = 4 << 20;

/// A reader's `Range` with its length bounded to `chunk`: `bytes=N-` and `bytes=N-M` longer than
/// `chunk` become `bytes=N-(N+chunk-1)`. A suffix range (`bytes=-N`), several ranges, a header that is
/// not one plain byte range, or none at all are passed on as they are (the connector asks for the
/// whole body then, as HTTP lets it).
pub fn bounded_range(range: Option<&str>, chunk: u64) -> Option<String> {
    let r = range?.trim();
    let Some(spec) = r.strip_prefix("bytes=") else { return Some(r.to_string()) };
    let Some((a, b)) = spec.split_once('-') else { return Some(r.to_string()) };
    let (Ok(start), b) = (a.trim().parse::<u64>(), b.trim()) else { return Some(r.to_string()) };
    if chunk == 0 || spec.contains(',') {
        return Some(r.to_string());
    }
    let last = start.saturating_add(chunk - 1);
    let end = if b.is_empty() { last } else {
        match b.parse::<u64>() {
            Ok(e) if e >= start => e.min(last),
            _ => return Some(r.to_string()),
        }
    };
    Some(format!("bytes={start}-{end}"))
}

/// The bytes a plain `bytes=N-M` range asks for; `None` for any other.
pub fn range_len(r: &str) -> Option<u64> {
    let (a, b) = r.trim().strip_prefix("bytes=")?.split_once('-')?;
    let (a, b) = (a.trim().parse::<u64>().ok()?, b.trim().parse::<u64>().ok()?);
    (b >= a).then(|| b - a + 1)
}

/// Whether a seller's answer says it sends more than the listed size can stand for: the total in
/// a `206`'s `Content-Range`, or the `Content-Length` of any other `2xx`, above `size` (the rule the
/// wallet and the seller judge by too).
pub fn more_than_listed(status: u16, content_length: Option<&str>, content_range: Option<&str>, size: u64) -> bool {
    let num = |s: &str| s.trim().parse::<u64>().ok();
    match status {
        206 => content_range.and_then(|r| r.rsplit_once('/')).and_then(|(_, t)| num(t)).is_some_and(|t| t > size),
        200..=299 => content_length.and_then(num).is_some_and(|n| n > size),
        _ => false,
    }
}

/// The answer to a reader whose file the seller says is larger than its listing shows.
fn larger_than_listed() -> xbt_svc::http::Reply {
    let v = serde_json::json!({"error": "the seller sends more than the size its listing shows; nothing more is paid for this file"});
    let mut whole = Resp::json(502, &v);
    security_headers(&mut whole);
    xbt_svc::http::Reply::Whole(xbt_svc::http::Response::new(whole.status, whole.headers, whole.body))
}

/// The headers of a relayed answer that are passed on from the connector.
const RELAYED: [&str; 5] = ["Content-Type", "Content-Range", "Accept-Ranges", "ETag", "Last-Modified"];

/// Stream the connector's answer for a seller URL to the reader, with the reader's `Range` (the
/// connector takes one plain byte range and ignores any other).
fn relay(url: &str, range: Option<&str>, if_range: Option<&str>, ceiling: Option<&serde_json::Value>, mut limit: Option<(u64, i64)>,
         page: &dyn Fn(&str) -> String) -> xbt_svc::http::Reply {
    let mut retried = false;
    loop {
        match relay_once(url, range, if_range, ceiling, limit) {
            Relayed::Reply(r) => return r,
            // the seller's smallest ticket is above the call's limit, and nothing was paid: asked once
            // more with the limit the wallet named, where it is a modest one
            Relayed::Refused(body) => match (limit, (!retried).then(|| ticket_retry_sats(&body, limit.map(|(_, s)| s))).flatten()) {
                (Some((size, _)), Some(n)) => {
                    retried = true;
                    limit = Some((size, n));
                }
                _ => return refused_page(page(&body)),
            },
        }
    }
}

/// The most a download's first call is asked again with when the wallet's refusal names the
/// seller's smallest ticket: a few tickets of the protocol's smallest. A shop whose ticket is
/// larger is not paid from a Download without the owner's word; its refusal is shown.
pub const RETRY_MOST_SATS: i64 = 2_000;

/// The `max_sats` to call again with, from the connector's 402 `body`: where the wallet refused a
/// call whose limit (`sent`) is below the seller's smallest ticket and paid nothing, the limit it
/// names, when that is more than was sent and at most [`RETRY_MOST_SATS`].
pub fn ticket_retry_sats(body: &str, sent: Option<i64>) -> Option<i64> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let words = v.get("error").and_then(serde_json::Value::as_str)?;
    if v.get("rule").and_then(serde_json::Value::as_str) != Some("max_sats") || !words.contains("nothing was paid") {
        return None;
    }
    let (_, after) = words.split_once("max_sats of at least ")?;
    let n: i64 = after.chars().take_while(char::is_ascii_digit).collect::<String>().parse().ok()?;
    (n > sent.unwrap_or(0) && n <= RETRY_MOST_SATS).then_some(n)
}

/// A refusal of the wallet's, as a page a person reads rather than the connector's JSON: the app's
/// look, the refusal in plain words with its fix, the wallet's words under Details, and a way back.
/// `base`: the app's base path; `spendable`: what the node can send, said with a refusal of no route.
pub fn refused_html(body: &str, base: &str, spendable: Option<i64>) -> String {
    let base = if base.ends_with('/') { base.to_string() } else { format!("{base}/") };
    crate::pay_feedback::page(&crate::pay_feedback::explain(body, spendable, true), &base, "This file was not paid for")
}

fn refused_page(html: String) -> xbt_svc::http::Reply {
    let mut whole = Resp::html(402, html);
    security_headers(&mut whole);
    xbt_svc::http::Reply::Whole(xbt_svc::http::Response::new(whole.status, whole.headers, whole.body))
}

/// One call to the connector: its answer for the reader, or the body of the wallet's 402 refusal.
enum Relayed {
    Reply(xbt_svc::http::Reply),
    Refused(String),
}

fn relay_once(url: &str, range: Option<&str>, if_range: Option<&str>, ceiling: Option<&serde_json::Value>, limit: Option<(u64, i64)>) -> Relayed {
    let agent = ureq::AgentBuilder::new().timeout_connect(std::time::Duration::from_secs(5)).redirects(0).build();
    let mut rq = agent.get(url);
    if let Some(c) = ceiling {
        rq = rq.set("X-Price-Ceiling", &c.to_string());
    }
    // the connector pays no more than this part of the listed file can cost (it takes the lower of
    // this and its own limit)
    if let Some((size, sats)) = limit {
        rq = rq.set("X-Max-Sats", &sats.to_string());
        // and the most bytes the listed file has: a seller that says it sends more is refused before
        // any of its body is sent, so a file that grew after it was listed costs nothing
        rq = rq.set("X-Max-Size", &size.to_string());
    }
    if let Some(r) = range.map(str::trim).filter(|r| r.len() <= 128 && r.bytes().all(|b| b.is_ascii_graphic() || b == b' ')) {
        rq = rq.set("Range", r);
        // the reader's copy, as its validator names it: a changed file is not spliced onto what it has
        if let Some(v) = if_range.map(str::trim).filter(|v| !v.is_empty() && v.len() <= 256 && v.bytes().all(|b| (0x20..0x7f).contains(&b))) {
            rq = rq.set("If-Range", v);
        }
    }
    let passed = |r: &ureq::Response| -> Vec<(String, String)> {
        RELAYED.iter().filter_map(|k| r.header(k).map(|v| (k.to_string(), v.to_string()))).collect()
    };
    let resp = match rq.call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code, r)) => {
            let headers = passed(&r).into_iter().filter(|(k, _)| k != "Content-Type").collect::<Vec<_>>();
            let body = r.into_string().unwrap_or_default().into_bytes();
            // the seller (412) or the wallet (502, the seller not reading the size it was told) refused
            // a file larger than its listing before any of it was read
            let said = String::from_utf8_lossy(&body);
            if limit.is_some() && matches!(code, 412 | 502) && (said.contains("larger_than_shown") || said.contains("the buyer was shown")) {
                return Relayed::Reply(larger_than_listed());
            }
            // the wallet's refusal (nothing paid): asked again, or shown in words
            if code == 402 {
                return Relayed::Refused(said.into_owned());
            }
            let mut whole = Resp::text(code, "application/json", body);
            whole.headers.extend(headers);
            security_headers(&mut whole);
            return Relayed::Reply(xbt_svc::http::Reply::Whole(xbt_svc::http::Response::new(whole.status, whole.headers, whole.body)));
        }
        Err(e) => {
            let v = serde_json::json!({"error": format!("the connector: {e}")});
            let mut whole = Resp::json(502, &v);
            security_headers(&mut whole);
            return Relayed::Reply(xbt_svc::http::Reply::Whole(xbt_svc::http::Response::new(whole.status, whole.headers, whole.body)));
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
    // a seller that says it sends more than its listing: refused before any of the body is read, so
    // the wallet pays for none of it (at most the part's head), and the buyer is told why
    if let Some((size, _)) = limit {
        if more_than_listed(status, resp.header("Content-Length"), resp.header("Content-Range"), size) {
            return Relayed::Reply(larger_than_listed());
        }
    }
    // and one that sends more than that without saying so is cut there
    let left = limit.map_or(u64::MAX, |(size, _)| size);
    let mut src = resp.into_reader();
    Relayed::Reply(xbt_svc::http::Reply::Stream(xbt_svc::http::Streamed {
        status,
        headers,
        length,
        body: Box::new(move |out: &mut dyn xbt_svc::http::BodyWriter| send_within(&mut src, left, out)),
    }))
}

/// A player's body as it is sent, counted for its link ([`crate::relay::LinkUse`]).
struct Counted<'a> {
    out: &'a mut dyn xbt_svc::http::BodyWriter,
    used: &'a crate::relay::LinkUse,
}

impl xbt_svc::http::BodyWriter for Counted<'_> {
    fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.out.send(bytes)?;
        self.used.sent(bytes.len() as u64);
        Ok(())
    }

    fn gone(&mut self) -> bool {
        self.out.gone()
    }
}

/// A relayed body, at most `left` bytes of it. One that has more than that ends in an error, so that
/// its reader sees a cut and not a whole file of the listed size.
fn send_within(src: &mut dyn std::io::Read, mut left: u64, out: &mut dyn xbt_svc::http::BodyWriter) -> std::io::Result<()> {
    let mut buf = vec![0u8; 64 << 10];
    loop {
        if left == 0 {
            return match src.read(&mut buf[..1])? {
                0 => Ok(()),
                _ => Err(std::io::Error::other("the seller sends more than the size its listing shows")),
            };
        }
        let want = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        let n = src.read(&mut buf[..want])?;
        if n == 0 {
            return Ok(());
        }
        left -= n as u64;
        // a reader that has gone: the connection to the connector closes, and the wallet stops paying
        out.send(&buf[..n])?;
    }
}

/// A running server; stops when dropped.
pub struct Running {
    pub addr: std::net::SocketAddr,
    stop: xbt_svc::http::Stop,
    /// The app ports and their servers ([`crate::seller_app`]).
    pub app_ports: Vec<(u16, std::net::SocketAddr)>,
    apps: Vec<xbt_svc::http::Stop>,
    /// Where the shared folder is served ([`crate::files`]), when the box sells.
    pub files_addr: Option<std::net::SocketAddr>,
    /// Where the player links' own listener answers (`XBT_UI_LINKS_BIND`), when it is set.
    pub links_addr: Option<std::net::SocketAddr>,
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
    let run = xbt_svc::http::serve(Arc::new(Ui(app.clone())), listener, threads).map_err(|e| format!("serve: {e}"))?;
    let app_ports = apps.iter().map(|(p, r)| (*p, r.addr)).collect();
    let mut apps: Vec<xbt_svc::http::Stop> = apps.iter().map(|(_, r)| r.stopper()).collect();
    // the shared folder of a Files service: served to the gateway only, with the files key
    let files_addr = match files_server(&app) {
        Ok(Some(f)) => {
            apps.push(f.stopper());
            Some(f.addr)
        }
        Ok(None) => None,
        Err(e) => {
            eprintln!("xbt-wallet-ui: the shared folder is not served: {e}");
            *app.files_error.lock().unwrap_or_else(|p| p.into_inner()) = Some(e);
            None
        }
    };
    // the player links' own port, where the platform's login is in front of this one
    let links_addr = match links_server(&app) {
        Ok(Some(l)) => {
            apps.push(l.stopper());
            app.relays.set_served_at(l.addr);
            Some(l.addr)
        }
        Ok(None) => None,
        Err(e) => {
            eprintln!("xbt-wallet-ui: player links are not served on their own port (the page gives this one's address): {e}");
            None
        }
    };
    Ok(Running { addr: run.addr, stop: run.stopper(), app_ports, apps, files_addr, links_addr })
}

fn links_server(app: &Arc<App>) -> Result<Option<xbt_svc::http::Running>, String> {
    let Some(bind) = app.cfg.links_bind.as_deref().filter(|_| app.cfg.role != crate::config::Role::Gateway) else { return Ok(None) };
    let l = std::net::TcpListener::bind(bind).map_err(|e| format!("bind {bind}: {e}"))?;
    xbt_svc::http::serve(Arc::new(Links(app.clone())), l, app.cfg.threads).map(Some).map_err(|e| format!("serve: {e}"))
}

fn files_server(app: &Arc<App>) -> Result<Option<xbt_svc::http::Running>, String> {
    if !app.cfg.sell || app.cfg.role == crate::config::Role::Gateway {
        return Ok(None);
    }
    let key = crate::files::key(&app.cfg.data_dir.join("secrets"))?;
    let l = std::net::TcpListener::bind(&app.cfg.files.bind).map_err(|e| format!("bind {}: {e}", app.cfg.files.bind))?;
    *app.files_addr.lock().unwrap_or_else(|p| p.into_inner()) = l.local_addr().ok();
    let server = crate::files::Server { setup: app.cfg.files.clone(), key };
    xbt_svc::http::serve(Arc::new(server), l, 4).map(Some).map_err(|e| format!("serve: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A link's HEAD gives the file's size the shop's answer said: a whole file's length, or a part's total.
    #[test]
    fn a_relayed_answer_says_the_files_whole_size() {
        let cr = |v: &str| vec![("Content-Range".to_string(), v.to_string())];
        assert_eq!(whole_size(200, Some(1234), &[]), Some(1234));
        assert_eq!(whole_size(206, Some(100), &cr("bytes 0-99/1234")), Some(1234));
        assert_eq!(whole_size(206, Some(100), &cr("bytes 0-99/*")), None, "not known");
        assert_eq!(whole_size(206, Some(100), &[]), None);
        assert_eq!(whole_size(200, None, &[]), None, "chunked: not known");
        assert_eq!(whole_size(416, Some(0), &cr("bytes */1234")), None);
        assert_eq!(exact_bytes("1234 bytes"), Some(1234));
        assert_eq!(exact_bytes("1.4 GB"), None, "a rounded size is no Content-Length");
    }

    #[test]
    fn a_seller_saying_it_sends_more_than_listed_is_refused() {
        let size = 1_000;
        assert!(!more_than_listed(200, Some("1000"), None, size));
        assert!(more_than_listed(200, Some("1001"), None, size), "a whole file bigger than listed");
        assert!(!more_than_listed(206, Some("100"), Some("bytes 0-99/1000"), size));
        assert!(more_than_listed(206, Some("100"), Some("bytes 0-99/5000"), size), "a part of a file bigger than listed");
        // one rule with the wallet and the seller: a 206 by its total, any other 2xx by its length
        assert!(!more_than_listed(200, None, Some("bytes 0-99/5000"), size), "a 200 is judged by its length");
        assert!(more_than_listed(203, Some("1001"), None, size));
        assert!(!more_than_listed(404, Some("5000"), None, size), "not a 2xx: not the file");
        assert!(!more_than_listed(200, None, None, size), "no length said: cut at the listed size as it streams");
        assert_eq!((range_len("bytes=0-99"), range_len("bytes=10-9"), range_len("bytes=5-")), (Some(100), None, None));
    }

    /// A body that goes past the listed size is sent up to it and ends in an error, never as a whole
    /// file of that size; one of the size, or less, ends cleanly.
    #[test]
    fn a_body_past_the_listed_size_is_a_cut_not_a_clean_end() {
        struct Out(Vec<u8>);
        impl xbt_svc::http::BodyWriter for Out {
            fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
                self.0.extend_from_slice(bytes);
                Ok(())
            }
        }
        let send = |len: usize, size: u64| {
            let mut out = Out(vec![]);
            let r = send_within(&mut std::io::Cursor::new(vec![7u8; len]), size, &mut out);
            (r.is_ok(), out.0.len())
        };
        assert_eq!(send(1_001, 1_000), (false, 1_000), "past the size");
        assert_eq!(send(200_000, 100_000), (false, 100_000), "past it, over several reads");
        assert_eq!(send(1_000, 1_000), (true, 1_000), "the size");
        assert_eq!(send(999, 1_000), (true, 999), "less");
    }

    /// The wallet's refusal of a call under the seller's smallest ticket names the limit that would do:
    /// asked once more with it, when nothing was paid and it is a modest one; every other refusal is
    /// a page in words, never the connector's JSON.
    #[test]
    fn a_refusal_under_the_smallest_ticket_is_asked_again_once_and_others_are_words() {
        let genesis = r#"{"error": "the smallest prepaid ticket this seller sells is 546 sat (up to 13 sat more in routing fees), over this call's limit of 284 sat: nothing was paid; call again with max_sats of at least 559", "rule": "max_sats"}"#;
        assert_eq!(ticket_retry_sats(genesis, Some(284)), Some(559));
        assert_eq!(ticket_retry_sats(genesis, Some(559)), None, "not again with the same limit");
        let big = genesis.replace("at least 559", "at least 50013");
        assert_eq!(ticket_retry_sats(&big, Some(284)), None, "a large ticket is not bought from a Download");
        let some_paid = r#"{"error": "the next ticket of this seller is 546 sat, and only 10 sat of this call's limit of 559 sat is left: no more was paid", "rule": "max_sats"}"#;
        assert_eq!(ticket_retry_sats(some_paid, Some(559)), None);
        assert_eq!(ticket_retry_sats(r#"{"error": "over the daily budget", "rule": "budget"}"#, Some(559)), None);
        let page = refused_html(r#"{"error": "over the <per-payment> cap", "rule": "max_payment_sats"}"#, "/", None);
        assert!(page.starts_with("<!doctype html>") && page.contains("This file was not paid for") && page.contains("over the &lt;per-payment&gt; cap"), "{page}");
        assert!(page.contains("href=\"/ui.css") && page.contains("Back to Browse"), "the app's look and a way back: {page}");
        assert!(refused_html(&big, "/", None).contains("at most 2,000 sat for its first ticket"));
        assert!(refused_html("not json", "/", None).contains("The wallet did not pay for this file."));
        // the common rules in plain words, with the fix
        let not_named = r#"{"error": "the owner has not named the seller 03ab and task \"stream\" pays only named sellers", "rule": "ticket_admission"}"#;
        let page = refused_html(not_named, "/ls", None);
        assert!(page.contains("Your spending rules don&#39;t allow this shop yet") && page.contains("Allow this seller to be paid") && page.contains("href=\"/ls/services\""), "{page}");
        let no_route = r#"{"error": "the wallet's node has found no route to the seller for 8.0 s: nothing was sent", "rule": "ln_no_route"}"#;
        let page = refused_html(no_route, "/", Some(0));
        assert!(page.contains("can&#39;t send to this shop right now: your channels hold about 0 sat you can spend") && page.contains("download/#channel"), "{page}");
    }

    #[test]
    fn a_readers_range_is_cut_to_one_part() {
        let c = 4 << 20;
        assert_eq!(bounded_range(Some("bytes=0-"), c).as_deref(), Some("bytes=0-4194303"));
        assert_eq!(bounded_range(Some("bytes=1000-"), c).as_deref(), Some("bytes=1000-4195303"));
        assert_eq!(bounded_range(Some("bytes=0-99"), c).as_deref(), Some("bytes=0-99"), "a short range is kept");
        assert_eq!(bounded_range(Some("bytes=10-99999999"), c).as_deref(), Some("bytes=10-4194313"));
        assert_eq!(bounded_range(Some("bytes=-500"), c).as_deref(), Some("bytes=-500"), "a suffix range is passed on");
        assert_eq!(bounded_range(Some("bytes=0-1,5-9"), c).as_deref(), Some("bytes=0-1,5-9"));
        assert_eq!(bounded_range(Some("bytes=9-3"), c).as_deref(), Some("bytes=9-3"), "not a valid range: left to the connector");
        assert_eq!(bounded_range(None, c), None);
    }
}
