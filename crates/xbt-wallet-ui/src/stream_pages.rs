//! Browse, a service's own page and the live connections page.
//!
//! Browse reads the services file and lists services by category (web apps, AI, hashrate, data and
//! APIs). A seller's media server (Jellyfin, Plex) is a web app: its page opens the seller's own app
//! inside Lightning Stream ([`crate::seller_app`]), paid as it loads. Any other service's page gives
//! the address apps and agents use it at. Stopping is a POST: this process asks the signer to
//! `ticket_stop` the open session. Connections lists every session `ticket_status` still has open
//! and reloads itself every 4 seconds (a meta refresh: the page's script policy does not allow an
//! inline script).
use std::collections::HashMap;

use serde_json::{json, Value};

use super::{ok_of, reason_of, App, Ctx};
use crate::html::{self, esc, int, sats};
use crate::server::Resp;
use crate::services::{self, Kind, Service, Sort};

const REFRESH: &str = "<meta http-equiv=\"refresh\" content=\"4\">";

impl App {
    pub(crate) fn browse(&self, ctx: &Ctx, q: &HashMap<String, String>) -> Resp {
        let cat = q.get("cat").or(q.get("kind")).map(String::as_str).unwrap_or("");
        let sort = Sort::parse(q.get("sort").map(String::as_str).unwrap_or(""));
        let body = match self.file_services() {
            Ok(all) => browse_html(&all, cat, sort, &self.suggested(ctx, &all), &|seller| self.is_own_shop(seller)),
            Err(e) => format!("{}{}", Self::error_box(&e), empty_how(&self.suggested(ctx, &[]))),
        };
        let more = if self.nostr.enabled() {
            "<p class=\"small\">More sellers, not checked by anyone: <a href=\"./nostr\">found on Nostr</a>.</p>"
        } else {
            ""
        };
        self.html_page("Browse", "Browse", ctx, &format!("{body}{more}"), "")
    }

    /// One-click forms for the suggested sellers not added yet.
    pub(crate) fn suggested(&self, ctx: &Ctx, have: &[Service]) -> String {
        let mut b = String::new();
        for url in self.cfg.suggested_sellers.iter().filter(|u| !have.iter().any(|s| services::same_origin(&s.seller, u))) {
            b.push_str(&format!("<form method=\"post\" action=\"./services\" class=\"row suggested\">{}<input type=\"hidden\" name=\"action\" value=\"add\">\
                <input type=\"hidden\" name=\"url\" value=\"{}\"><span>Suggested: <strong>{}</strong></span><button class=\"secondary\">Add this seller</button></form>",
                App::csrf_input(ctx), esc(url), esc(url.trim_start_matches("https://"))));
        }
        b
    }

    /// `GET /service?seller=…&name=…`: one service, as its category needs.
    pub(crate) fn service_page(&self, ctx: &Ctx, q: &HashMap<String, String>) -> Resp {
        let seller = q.get("seller").map(String::as_str).unwrap_or("");
        let name = q.get("name").map(String::as_str).unwrap_or("");
        let found = self.services().ok().and_then(|all| all.into_iter().find(|s| services::same_origin(&s.seller, seller) && s.name == name));
        match found {
            Some(svc) => {
                let body = service_html(&svc, self.is_own_shop(&svc.seller));
                self.html_page("Service", &svc.name, ctx, &body, "")
            }
            None => self.html_page("Service", "Service", ctx, &format!("{}<p><a href=\"./browse\">Back to Browse</a></p>",
                                                                     Self::error_box("That service is not in your list. A seller may have removed it.")), ""),
        }
    }

    pub(crate) fn connections(&self, ctx: &Ctx) -> Resp {
        let names = self.services().unwrap_or_default();
        // rented hashrate is one more kind of connection: a pulse for each piece of work paid
        let (cards, spent) = self.hash_live_cards(ctx);
        let mut body = match self.call("ticket_status", json!({})) {
            Ok(st) => connections_html(ctx, &st, &|id| self.call("ticket_status", json!({"session": id})), &names, crate::now(), !cards.is_empty()),
            Err(e) => Self::error_box(&e),
        };
        if !cards.is_empty() {
            body.push_str(&format!("<h2>Rented hashrate</h2><div class=\"stack\" data-spent=\"{spent}\">{cards}</div>"));
        }
        self.html_page("Live connections", "Live connections", ctx, &body, REFRESH)
    }

    pub(crate) fn connections_stop(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let st = match self.call("ticket_status", json!({})) {
            Ok(v) => v,
            Err(e) => {
                self.flash(ctx, false, e);
                return Resp::redirect("./connections");
            }
        };
        let ids = if f.get("all").is_some_and(|v| v == "1") {
            open_ids(&st, None)
        } else {
            let id = f.get("session").map(|s| s.trim().to_string()).unwrap_or_default();
            if open_ids(&st, None).iter().any(|s| s == &id) {
                vec![id]
            } else {
                self.flash(ctx, false, "That connection is not open any more.");
                return Resp::redirect("./connections");
            }
        };
        self.flash_stops(ctx, &ids, "");
        Resp::redirect("./connections")
    }

    /// What a service page and a seller's app may open: the services file, and the sellers the
    /// Nostr page last found (unvetted, shown on that page only).
    pub(crate) fn services(&self) -> Result<Vec<Service>, String> {
        let mut all = self.file_services()?;
        all.extend(self.nostr.services());
        Ok(all)
    }

    /// The services file, as Browse lists it.
    pub(crate) fn file_services(&self) -> Result<Vec<Service>, String> {
        match &self.cfg.services_file {
            Some(p) => services::load(p),
            // the default file exists once the Services page added a seller
            None => {
                let p = self.cfg.services_path();
                if p.exists() { services::load(&p) } else { Ok(Vec::new()) }
            }
        }
    }

    /// `nav`: the page as the menu knows it; `title`: its heading.
    pub(crate) fn html_page(&self, nav: &str, title: &str, ctx: &Ctx, body: &str, head: &str) -> Resp {
        Resp::html(200, html::page_head(title, &self.nav(nav, &ctx.csrf, true), ctx.flash.clone(), body, head))
    }

    fn flash_stops(&self, ctx: &Ctx, ids: &[String], seller: &str) {
        if ids.is_empty() {
            let who = if seller.is_empty() { "Nothing is open.".into() } else { format!("No open connection with {seller}.") };
            self.flash(ctx, false, who);
            return;
        }
        let mut stopped = 0usize;
        let mut errs: Vec<String> = Vec::new();
        for id in ids {
            match self.call("ticket_stop", json!({"session": id})) {
                Ok(v) if ok_of(&v) => stopped += 1,
                Ok(v) => errs.push(reason_of(&v)),
                Err(e) => errs.push(e),
            }
        }
        if errs.is_empty() {
            self.flash(ctx, true, format!("Stopped {stopped} connection{}. Nothing more is paid on {}.", if stopped == 1 { "" } else { "s" },
                                          if stopped == 1 { "it" } else { "them" }));
        } else if stopped == 0 {
            self.flash(ctx, false, errs.join(" "));
        } else {
            self.flash(ctx, false, format!("Stopped {stopped}; {} could not be stopped: {}", errs.len(), errs.join(" ")));
        }
    }
}

fn empty_how(suggested: &str) -> String {
    format!("<section class=\"card empty-card\"><p class=\"empty\">No services yet.</p>\
     <p>Add a seller to see what they offer: web apps such as a media server, AI models to ask, hashrate, data and other services, each paid a little at a time.</p>\
     <p><a class=\"button-link primary\" href=\"./services\">Add a seller</a></p>{suggested}</section>")
}

fn browse_html(all: &[Service], cat: &str, sort: Sort, suggested: &str, own: &dyn Fn(&str) -> bool) -> String {
    let cat = cat.trim().to_ascii_lowercase();
    // a kind or an older category (`video`, `media`) names its category
    let cat = match cat.as_str() {
        "video" | "media" => "apps".to_string(),
        "files" | "api" => "data".to_string(),
        c if services::CATEGORIES.iter().any(|(id, _)| *id == c) => cat,
        _ => String::new(),
    };
    let sort_q = if sort == Sort::Price { "&amp;sort=price" } else { "" };
    let mut b = String::from("<nav class=\"chips\" aria-label=\"Categories\">");
    let count = |id: &str| all.iter().filter(|s| id.is_empty() || s.category() == id).count();
    for (id, words) in std::iter::once(("", "All")).chain(services::CATEGORIES.iter().copied()) {
        let cur = if id == cat { " aria-current=\"page\"" } else { "" };
        b.push_str(&format!("<a href=\"./browse?cat={id}{sort_q}\"{cur}>{} <span class=\"count\">{}</span></a>", esc(words), count(id)));
    }
    b.push_str("</nav>");
    if all.is_empty() {
        b.push_str(&empty_how(suggested));
        return b;
    }
    let shown = services::arrange(all.to_vec(), Some(&cat), sort);
    b.push_str(&format!("<p class=\"small sort\">Sort by: {} · {}</p>",
        if sort == Sort::Name { "<strong aria-current=\"true\">name</strong>".to_string() } else { format!("<a href=\"./browse?cat={cat}\">name</a>") },
        if sort == Sort::Price { "<strong aria-current=\"true\">price</strong>".to_string() } else { format!("<a href=\"./browse?cat={cat}&amp;sort=price\">price</a>") }));
    if shown.is_empty() {
        b.push_str("<p class=\"empty\">No services in this category yet. <a href=\"./browse\">Show all</a></p>");
        return b;
    }
    b.push_str("<div class=\"grid services\">");
    for s in &shown {
        let what = match s.kind {
            Kind::Video if s.app.is_empty() => "An older media listing: nothing to open yet".into(),
            _ if s.category() == "apps" => "A web app: open it inside Lightning Stream".into(),
            Kind::Video => "A web app: open it inside Lightning Stream".into(),
            Kind::Ai => "Ask it from your apps and agents".into(),
            Kind::Api => "Use it from your apps and agents".into(),
            Kind::Files if !s.items.is_empty() => format!("{} file{}", s.items.len(), if s.items.len() == 1 { "" } else { "s" }),
            Kind::Files => "Files".into(),
            Kind::Hashrate => "Rent miners by the piece of work".into(),
        };
        let mine = own(&s.seller);
        let what = if s.app.is_empty() || s.category() == "apps" { what } else { format!("{what} · has its own app") };
        b.push_str(&format!("<a class=\"card service-card\" href=\"{}\"><span class=\"pill cat-{}\">{}</span>{}<h2>{}</h2>\
                             <p class=\"price\">{}</p><p class=\"small\">{} · {}</p></a>",
                            service_href(s), s.category(), esc(s.category_words()),
                            if mine { " <span class=\"pill good\">Your shop</span>" } else { "" },
                            esc(&s.name), esc(&s.price_text), esc(&what), esc(&host(&s.seller))));
    }
    b.push_str("</div>");
    b
}

pub(crate) fn host(url: &str) -> String {
    services::http_origin(url).unwrap_or_else(|| url.to_string()).trim_start_matches("https://").trim_start_matches("http://").to_string()
}

fn service_href(s: &Service) -> String {
    // miners are rented on the Rent hashrate page, which finds the seller's offer itself
    if s.kind == Kind::Hashrate {
        return "./hashrate".into();
    }
    format!("./service?seller={}&amp;name={}", services::urlenc(&s.seller), services::urlenc(&s.name))
}

/// A service's own page: its price and seller, then what its category needs. `own`: the seller is
/// this box's own shop, which this box cannot buy from: its app opens as a free preview instead.
fn service_html(s: &Service, own: bool) -> String {
    let mut b = format!("<p class=\"small\"><a href=\"./browse?cat={}\">← {}</a></p>\
        <section class=\"card\"><div class=\"offer-head\"><span class=\"pill cat-{}\">{}</span><span class=\"price\">{}</span></div>\
        <p class=\"small\">Sold by {}</p></section>",
        s.category(), esc(s.category_words()), s.category(), esc(s.category_words()), esc(&s.price_text), esc(&host(&s.seller)));
    if own {
        b.push_str(if s.app.is_empty() {
            "<section class=\"status ok\"><p class=\"status-head\">This is your shop</p><p>Buyers pay for this. Your box can't buy from \
            its own shop.</p></section>"
        } else {
            "<section class=\"status ok\"><p class=\"status-head\">This is your shop</p><p>Buyers pay for this. You can preview it \
            here for free: it opens straight from your service on this box, and nothing is paid.</p></section>"
        });
    }
    if !s.app.is_empty() {
        let seller = host(&s.seller);
        b.push_str(&if own {
            format!("<section class=\"card\"><h2>Its own app</h2><p>Buyers can open this service's own web page inside their app, \
                and pay your price for what it loads. You can try it here for free.</p>\
                <div class=\"row\"><a class=\"button-link\" href=\"./app?u={}&amp;b={}\">Preview the app (free)</a></div></section>",
                services::urlenc(&s.app), services::urlenc(&s.app_base))
        } else {
            format!("<section class=\"card primary\"><h2>Its own app</h2><p>Use {}'s own page for this service, inside Lightning Stream. \
                What it loads is paid at the price above, up to a limit you set.</p>\
                <div class=\"row\"><a class=\"button-link primary\" href=\"./app?u={}&amp;b={}\">Open {}'s app</a></div></section>",
                esc(&seller), services::urlenc(&s.app), services::urlenc(&s.app_base), esc(&seller))
        });
    }
    match s.kind {
        // a media server is the seller's own web app, opened above; an older listing names films for a
        // player this app no longer has
        Kind::Video => {
            if s.app.is_empty() {
                b.push_str("<section class=\"status warn\"><p class=\"status-head\">This shop uses an older media listing</p>\
                    <p>Ask the seller to share their media server as a web app. Lightning Stream opens a seller's own app (Jellyfin, \
                    Plex) and pays for what it loads; it has no player of its own.</p></section>");
            }
        }
        Kind::Hashrate => b.push_str("<section class=\"card primary\"><h2>Rent miners</h2>\
            <p>This seller rents out its miners: they hash for your own pool, and you pay for each piece of work as it is done.</p>\
            <div class=\"row\"><a class=\"button-link primary\" href=\"./hashrate\">Rent hashrate</a></div></section>"),
        _ => {
            b.push_str(&format!("<section class=\"card primary\"><h2>Use it</h2>\
                <p>Apps and AI agents connected to this wallet can use this service. Each request is paid as it is made, a little at a time, \
                within your spending rules.</p>\
                <label>Its address, for your apps and agents<input id=\"service-address\" readonly class=\"mono\" value=\"{}\"></label>\
                <div class=\"row\"><button type=\"button\" class=\"secondary\" data-copy=\"service-address\">Copy the address</button>\
                <a class=\"button-link primary\" href=\"./agents\">Connect an AI agent</a><a class=\"button-link\" href=\"./apps\">Connect an app</a></div>\
                <p class=\"hint\">Your spending rules decide how much may be spent and when the app asks you first.</p></section>",
                esc(s.address())));
            if !s.items.is_empty() {
                b.push_str("<h2>What it offers</h2><ul class=\"offers\">");
                for item in &s.items {
                    b.push_str(&format!("<li><strong>{}</strong> <span class=\"small\">{}</span><br><code class=\"small\">{}</code></li>",
                                        esc(&item.title), esc(&item.credit), esc(&item.url)));
                }
                b.push_str("</ul>");
            }
        }
    }
    b
}

/// Session ids `ticket_status` lists as open. With `origins`, only those sellers.
fn open_ids(st: &Value, origins: Option<&[String]>) -> Vec<String> {
    st.get("sessions").and_then(Value::as_array).into_iter().flatten().filter_map(|s| {
        if s.get("state").and_then(Value::as_str) != Some("open") {
            return None;
        }
        let origin = s.get("origin").and_then(Value::as_str).unwrap_or("");
        if origins.is_some_and(|os| !os.iter().any(|o| services::same_origin(origin, o))) {
            return None;
        }
        s.get("session").and_then(Value::as_str).filter(|id| !id.is_empty()).map(str::to_string)
    }).collect()
}

#[derive(Default)]
struct Counts {
    locked: u64,
    released: u64,
    prepaid: u64,
    settled: u64,
    never_sent: u64,
    cancelled_at_stop: u64,
    payment_failed: u64,
    booked_sats: i64,
}

/// Counts for one session, from `session_tickets` and the session's `stopped_ts`.
/// A failed ticket is `never_sent` when nothing was sent, `cancelled_at_stop` when it failed after
/// the session was stopped and it was not prepaid, and `payment_failed` otherwise: the same three
/// ways `ticket_status` reports `failed_by`.
fn counts_of(tickets: &Value, stopped_ts: f64) -> Counts {
    let mut c = Counts::default();
    for t in tickets.as_array().into_iter().flatten() {
        if t.get("prepaid") == Some(&Value::Bool(true)) {
            c.prepaid += 1;
        }
        match t.get("state").and_then(Value::as_str) {
            Some("sending" | "locked") => c.locked += 1,
            Some("released") => {
                c.released += 1;
                c.booked_sats = c.booked_sats.saturating_add(int(t.get("booked_sats")));
            }
            Some("retired") => c.booked_sats = c.booked_sats.saturating_add(int(t.get("booked_sats"))),
            // a settled ticket was paid: a prepaid one settles as soon as it arrives, a held one when the
            // seller collects it, and either way it is money that left the node
            Some("settled") => {
                c.settled += 1;
                c.booked_sats = c.booked_sats.saturating_add(int(t.get("booked_sats")));
            }
            Some("failed") => match failed_as(t, stopped_ts) {
                "never_sent" => c.never_sent += 1,
                "cancelled_at_stop" => c.cancelled_at_stop += 1,
                _ => c.payment_failed += 1,
            },
            _ => {}
        }
    }
    c
}

fn failed_as(t: &Value, stopped_ts: f64) -> &'static str {
    if num(t.get("sent_ts")) <= 0.0 {
        "never_sent"
    } else if t.get("prepaid") != Some(&Value::Bool(true)) && stopped_ts > 0.0 && num(t.get("done_ts")) >= stopped_ts {
        "cancelled_at_stop"
    } else {
        "payment_failed"
    }
}

fn num(v: Option<&Value>) -> f64 {
    match v {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) => s.parse().unwrap_or(0.0),
        _ => 0.0,
    }
}

fn msat_of(v: &Value) -> Option<u64> {
    match v {
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

/// What a session has cost so far, in sats, and the part of a sat the seller still holds (msat).
fn spent_of(paying: &Value, sid: &str, booked_sats: i64) -> (i64, u64) {
    let row = paying.as_array().and_then(|a| a.iter().find(|p| p.get("session").and_then(Value::as_str) == Some(sid)));
    if let Some(paid) = row.and_then(|p| p.get("paid_sats")).map(|v| int(Some(v))) {
        return (paid.max(booked_sats), 0);
    }
    let rem = row.and_then(|p| p.get("balance_msat")).and_then(msat_of).map(|m| m % 1000).unwrap_or(0);
    (booked_sats, rem)
}

fn balance_cell(paying: &Value, sid: &str, booked_sats: i64) -> String {
    let row = paying.as_array().and_then(|a| a.iter().find(|p| p.get("session").and_then(Value::as_str) == Some(sid)));
    if let Some(msat) = row.and_then(|p| p.get("balance_msat")).and_then(msat_of) {
        let whole = i64::try_from(msat / 1000).unwrap_or(i64::MAX);
        let rem = msat % 1000;
        if rem == 0 {
            return sats(whole);
        }
        return format!("{} <span class=\"small\">+ {rem} msat</span>", sats(whole));
    }
    if let Some(paid) = row.and_then(|p| p.get("paid_sats")).map(|v| int(Some(v))) {
        return format!("{} <span class=\"small\">paid</span>", sats(paid));
    }
    if booked_sats > 0 {
        return format!("{} <span class=\"small\">booked</span>", sats(booked_sats));
    }
    "—".into()
}

/// `more`: other connections (rented hashrate) follow, so an empty list here is not "nothing open".
fn connections_html(ctx: &Ctx, st: &Value, detail: &dyn Fn(&str) -> Result<Value, String>, names: &[Service], now: i64, more: bool) -> String {
    let csrf = App::csrf_input(ctx);
    let mut b = String::from("<p class=\"lead\">Every service you are paying for right now. Stop one and its payments end at once. \
                              A ticket held but not yet taken comes back to you; credit left from a prepaid ticket stays with that \
                              seller and is spent first next time. This page updates every few seconds.</p>");
    if let Some(e) = st.get("error").and_then(Value::as_str) {
        b.push_str(&App::error_box(e));
    }
    let Some(sessions) = st.get("sessions").and_then(Value::as_array).filter(|a| !a.is_empty()) else {
        if !more {
            b.push_str("<p class=\"empty\">Nothing is open. Use a service from <a href=\"./browse\">Browse</a> and it shows up here.</p>");
        }
        return b;
    };
    let paying = st.get("paying").cloned().unwrap_or(json!([]));
    let mut total = 0i64;
    let mut cards = String::new();
    let mut open = 0usize;
    for s in sessions {
        let id = s.get("session").and_then(Value::as_str).unwrap_or("");
        let origin = s.get("origin").and_then(Value::as_str).unwrap_or("");
        let state = s.get("state").and_then(Value::as_str).unwrap_or("");
        let (counts, err) = match detail(id) {
            Ok(d) => (counts_of(d.get("session_tickets").unwrap_or(&json!([])), num(s.get("stopped_ts"))), None),
            Err(e) => (Counts::default(), Some(e)),
        };
        let (spent, _) = spent_of(&paying, id, counts.booked_sats);
        total = total.saturating_add(spent);
        open += usize::from(state == "open");
        let svc = names.iter().filter(|n| services::same_origin(&n.seller, origin)).map(|n| n.name.as_str()).collect::<Vec<_>>();
        let name = if svc.is_empty() { host(origin) } else { svc.join(", ") };
        let opened = num(s.get("opened_ts"));
        let minutes = if opened > 0.0 { ((now as f64 - opened) / 60.0).max(0.0) } else { 0.0 };
        cards.push_str(&session_card(ctx, id, &name, origin, state, &counts, &paying, spent, minutes, err.as_deref()));
    }
    if open > 1 {
        b.push_str(&format!("<form method=\"post\" action=\"./connections\" class=\"row\">{csrf}\
                             <input type=\"hidden\" name=\"all\" value=\"1\"><button class=\"danger\" type=\"submit\">Stop all ({open})</button></form>"));
    }
    b.push_str(&format!("<div class=\"stack\" data-spent=\"{total}\">{cards}</div>"));
    b
}

#[allow(clippy::too_many_arguments)]
fn session_card(ctx: &Ctx, id: &str, name: &str, origin: &str, state: &str, c: &Counts, paying: &Value, spent: i64, minutes: f64, err: Option<&str>) -> String {
    let open = state == "open";
    let stop = if open && !id.is_empty() {
        format!("<form method=\"post\" action=\"./connections\">{}<input type=\"hidden\" name=\"session\" value=\"{}\">\
                 <button class=\"danger\" type=\"submit\">Stop</button></form>", App::csrf_input(ctx), esc(id))
    } else {
        String::new()
    };
    let row = paying.as_array().and_then(|a| a.iter().find(|p| p.get("session").and_then(Value::as_str) == Some(id)));
    let streaming = row.and_then(|p| p.get("answer_open")).and_then(Value::as_bool).unwrap_or(false);
    let pill = match state {
        "open" if streaming => "<span class=\"pill good\">Streaming</span>",
        "open" => "<span class=\"pill\">Open, idle</span>",
        "stopping" | "stopped" => "<span class=\"pill warn\">Stopping</span>",
        _ => "<span class=\"pill\">Closed</span>",
    };
    // the rate is of what the seller used, where its receipts say: a prepaid ticket is paid all at once
    let used_msat = row.and_then(|p| p.get("spent_msat")).and_then(msat_of);
    let per_min = used_msat.map_or(spent as f64, |m| m as f64 / 1000.0) / minutes.max(1.0);
    let rate = if open && minutes >= 1.0 && per_min > 0.0 {
        format!(" · about <span class=\"money\">{}</span> a minute", msat_text((per_min * 1000.0).round() as u64))
    } else {
        String::new()
    };
    let how_long = if minutes >= 1.0 { format!(" · open {} min", minutes.round() as i64) } else { String::new() };
    let failed = format!("never sent {}<br>cancelled at stop {}<br>payment failed {}", c.never_sent, c.cancelled_at_stop, c.payment_failed);
    let err = err.map(|e| format!("<p class=\"hint bad\">{}</p>", esc(e))).unwrap_or_default();
    let used = usage_line(row);
    format!("<section class=\"card live\"><div class=\"offer-head\"><h2>{}</h2>{pill}</div>\
             <p>Paid so far: <span class=\"money\">{}</span>{rate}{how_long}</p>{used}{err}<div class=\"row\">{stop}</div>\
             <details><summary>Details</summary><p class=\"small\">{} · connection <code>{}</code></p><div class=\"scroll\"><table><thead><tr><th>Locked</th>\
             <th>Released</th><th>Prepaid</th><th>Settled</th><th>Failed by</th><th>Balance</th></tr></thead><tbody><tr><td>{}</td><td>{}</td><td>{}</td>\
             <td>{}</td><td class=\"small\">{failed}</td><td>{}</td></tr></tbody></table></div></details></section>",
            esc(name), sats_short(spent), esc(origin), esc(id), c.locked, c.released, c.prepaid, c.settled, balance_cell(paying, id, c.booked_sats))
}

/// What the seller has drawn from what was paid, and the credit it still holds, from the seller's
/// signed receipts as far as the wallet has them (one arrives with each answer).
fn usage_line(row: Option<&Value>) -> String {
    let Some(row) = row else { return String::new() };
    let msat = |k: &str| row.get(k).and_then(msat_of);
    let (Some(spent), Some(left)) = (msat("spent_msat"), msat("balance_msat")) else { return String::new() };
    if spent == 0 && left == 0 {
        return String::new();
    }
    format!("<p class=\"small\">Used: <span class=\"money\">{}</span> · credit left with this seller: <span class=\"money\">{}</span></p>",
            msat_text(spent), msat_text(left))
}

/// Sats with up to three decimals: `40 sats`, `0.12 sats`.
fn msat_text(msat: u64) -> String {
    if msat.is_multiple_of(1000) {
        return sats_short(i64::try_from(msat / 1000).unwrap_or(i64::MAX));
    }
    let s = format!("{}.{:03}", msat / 1000, msat % 1000);
    format!("{} sats", s.trim_end_matches('0'))
}

/// `1,234 sats`, without the XBT figure.
fn sats_short(n: i64) -> String {
    let full = sats(n);
    full.split(" <span").next().unwrap_or(&full).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticket(state: &str, sent: f64, done: f64, prepaid: bool, booked: i64) -> Value {
        json!({"state": state, "sent_ts": sent, "done_ts": done, "prepaid": prepaid, "booked_sats": booked})
    }

    #[test]
    fn a_session_s_tickets_count_the_way_ticket_status_does() {
        let tickets = json!([
            ticket("locked", 1.0, 0.0, false, 0),
            ticket("sending", 1.0, 0.0, false, 0),
            ticket("released", 1.0, 0.0, false, 40),
            ticket("released", 1.0, 0.0, true, 10),
            ticket("settled", 1.0, 2.0, false, 40),
            ticket("failed", 0.0, 3.0, false, 0),
            ticket("failed", 1.0, 9.0, false, 0),
            ticket("failed", 1.0, 4.0, true, 0),
        ]);
        let c = counts_of(&tickets, 8.0);
        assert_eq!((c.locked, c.released, c.prepaid, c.settled, c.booked_sats), (2, 2, 2, 1, 90));
        assert_eq!((c.never_sent, c.cancelled_at_stop, c.payment_failed), (1, 1, 1));
    }

    #[test]
    fn a_prepaid_ticket_that_settled_still_counts_as_paid_and_the_usage_shows() {
        // a prepaid ticket settles as soon as it arrives; the page once read it as nothing paid
        let c = counts_of(&json!([ticket("settled", 1.0, 2.0, true, 901)]), 0.0);
        assert_eq!((c.settled, c.booked_sats), (1, 901));
        let row = json!({"session": "s1", "spent_msat": "120", "balance_msat": "879880", "answer_open": true});
        let html = usage_line(Some(&row));
        assert!(html.contains("Used: <span class=\"money\">0.12 sats</span>") && html.contains("879.88 sats"), "{html}");
        assert!(usage_line(Some(&json!({"spent_msat": "0", "balance_msat": "0"}))).is_empty());
        assert_eq!(msat_text(40_000), sats_short(40));
    }

    #[test]
    fn hashrate_shows_in_its_own_category_and_leads_to_rent_hashrate() {
        let section = xbt402::listing::Section { name: "My miners".into(), kind: "hashrate".into(), path: "/hashrate/".into(),
            prices: json!({"request_msat": "40000"}), items: vec![], licence: String::new(), credits: String::new() };
        let l = xbt402::listing::Listing { name: "Box".into(), kind: "hashrate".into(), seller: "https://box.example".into(), receipt_key: String::new(),
            prices: section.prices.clone(), items: vec![], licence: String::new(), credits: String::new(), updated: String::new(), services: vec![section] };
        let all = services::from_listing(&l);
        assert_eq!((all[0].kind, all[0].price_text.as_str()), (Kind::Hashrate, "40 sat a piece of work"));
        let html = browse_html(&all, "hashrate", Sort::Name, "", &|_| false);
        assert!(html.contains("cat-hashrate") && html.contains("Rent miners by the piece of work") && html.contains("href=\"./hashrate\""), "{html}");
        assert!(service_html(&all[0], false).contains("href=\"./hashrate\""));
    }
}
