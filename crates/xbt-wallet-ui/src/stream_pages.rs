//! Browse, a service's own page, the player and the live connections page.
//!
//! Browse reads the services file and lists services by category (media, AI, data and APIs), each
//! with its own page: a media service's page lists what it has to play, and any other service's
//! page gives the address apps and agents use it at. The player points a `<video>` at the connector
//! (`XBT_UI_CONNECTOR` + `/s/` + the item URL), relayed by this process; for VLC, mpv and other
//! players it makes links of their own for one item ([`crate::relay`], `POST /play-link`), shown
//! with the exact address to paste. Stopping is a POST: this process asks the signer
//! to `ticket_stop` the open session whose origin is that seller. Connections lists every session
//! `ticket_status` still has open and reloads itself every 4 seconds (a meta refresh: the page's
//! script policy does not allow an inline script).
use std::collections::HashMap;

use serde_json::{json, Value};

use super::{ok_of, reason_of, App, Ctx};
use crate::html::{self, esc, int, sats};
use crate::server::{Req, Resp};
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

    pub(crate) fn play(&self, ctx: &Ctx, req: &Req) -> Resp {
        let item_url = req.query.get("item").map(String::as_str).unwrap_or("");
        let mut title = "Player".to_string();
        let body = match self.services() {
            Ok(all) => match services::find_item(&all, item_url) {
                Some((service, item)) => {
                    title = item.title.clone();
                    if self.is_own_shop(&service.seller) {
                        own_player_html(service, item)
                    } else if let Some((words, link, href)) = self.play_blocker() {
                        format!("<p class=\"small\"><a href=\"{}\">← {}</a></p><section class=\"status bad\"><p class=\"status-head\">{}</p>\
                                 <p><a class=\"button-link primary\" href=\"{}\">{}</a></p></section>",
                                service_href(service), esc(&service.name), esc(&words), esc(&href), esc(&link))
                    } else {
                        let links = self.relays.of_item(&item.url);
                        let warn = self.play_warning().map(|w| {
                            let (href, link) = if w.contains("spending rules") { ("./policy?template=starter", "Open the starter rules") } else { ("./lightning", "Check your node") };
                            format!("<div class=\"flash warn\">{} <a href=\"{href}\">{link}</a></div>", esc(&w))
                        })
                            .unwrap_or_default();
                        format!("{warn}{}{}", player_html(ctx, &self.cfg.connector, service, item),
                                if service.kind == Kind::Video { links_html(ctx, &self.link_base(req), &item.url, &links) } else { String::new() })
                    }
                }
                None if item_url.is_empty() => "<p>Choose something to play from a media service on <a href=\"./browse?cat=media\">Browse</a>.</p>".into(),
                None => format!("{}<p><a href=\"./browse\">Back to Browse</a></p>", Self::error_box("That item is not in your list of services.")),
            },
            Err(e) => format!("{}{}", Self::error_box(&e), empty_how("")),
        };
        self.html_page("Player", &title, ctx, &body, "")
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

    pub(crate) fn play_stop(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let item_url = f.get("item").map(|s| s.trim().to_string()).unwrap_or_default();
        let back = format!("./play?item={}", services::urlenc(&item_url));
        let origins = match self.services() {
            Ok(all) => match services::find_item(&all, &item_url) {
                Some((service, item)) => services::pay_origins(service, item),
                None => {
                    self.flash(ctx, false, "That item is not in your list of services.");
                    return Resp::redirect("./browse");
                }
            },
            Err(e) => {
                self.flash(ctx, false, e);
                return Resp::redirect("./browse");
            }
        };
        let st = match self.call("ticket_status", json!({})) {
            Ok(v) => v,
            Err(e) => {
                self.flash(ctx, false, e);
                return Resp::redirect(&back);
            }
        };
        let ids = open_ids(&st, Some(&origins));
        self.flash_stops(ctx, &ids, &origins.join(", "));
        Resp::redirect(&back)
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

    /// `POST /play-link`: make a link for an external player for one video item of the services
    /// file (`action=create`), or revoke one (`action=revoke`, `token`). The CSRF token was checked
    /// with every POST.
    pub(crate) fn play_link(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let item_url = f.get("item").map(|s| s.trim().to_string()).unwrap_or_default();
        let back = format!("./play?item={}", services::urlenc(&item_url));
        match f.get("action").map(String::as_str) {
            Some("create") => {
                let video = self.services().ok().is_some_and(|all| services::find_item(&all, &item_url).is_some_and(|(s, _)| s.kind == Kind::Video));
                if !video {
                    self.flash(ctx, false, "That item is not a video in your list of services.");
                    return Resp::redirect("./browse");
                }
                self.relays.create(&item_url);
                self.flash(ctx, true, format!("Link made. It plays this film only, and stops working in {}.", lasts(self.cfg.relay_ttl)));
            }
            Some("revoke") => {
                let token = f.get("token").map(|s| s.trim().to_string()).unwrap_or_default();
                if self.relays.revoke(&token) {
                    self.flash(ctx, true, "Link revoked: it plays nothing now.");
                } else {
                    self.flash(ctx, false, "No such link: it had expired or was revoked already.");
                }
            }
            _ => self.flash(ctx, false, "Unknown action."),
        }
        Resp::redirect(&back)
    }

    /// The address of this UI as the browser reached it, for a link another device opens:
    /// `http(s)://<Host><base path>`. The Host was checked against the allowed names already.
    fn link_base(&self, req: &Req) -> String {
        let https = self.cfg.secure_cookie.unwrap_or_else(|| req.header("x-forwarded-proto").eq_ignore_ascii_case("https"));
        let host = req.header("host").trim();
        let base = if self.cfg.base_path.ends_with('/') { self.cfg.base_path.clone() } else { format!("{}/", self.cfg.base_path) };
        format!("{}://{host}{base}", if https { "https" } else { "http" })
    }

    /// What the player and the links for external players may open: the services file, and the
    /// sellers the Nostr page last found (unvetted, shown on that page only).
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
     <p>Add a seller to see what they offer: media to watch, AI models to ask, data and other services, each paid a little at a time.</p>\
     <p><a class=\"button-link primary\" href=\"./services\">Add a seller</a></p>{suggested}</section>")
}

fn browse_html(all: &[Service], cat: &str, sort: Sort, suggested: &str, own: &dyn Fn(&str) -> bool) -> String {
    let cat = cat.trim().to_ascii_lowercase();
    // a kind (`video`, from an older link) names its category
    let cat = match cat.as_str() {
        "video" => "media".to_string(),
        "files" | "api" => "data".to_string(),
        c if services::CATEGORIES.iter().any(|(id, _)| *id == c) => cat,
        _ => String::new(),
    };
    let sort_q = if sort == Sort::Price { "&amp;sort=price" } else { "" };
    let mut b = String::from("<nav class=\"chips\" aria-label=\"Categories\">");
    let count = |id: &str| all.iter().filter(|s| id.is_empty() || s.kind.category() == id).count();
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
            Kind::Video if !s.items.is_empty() => format!("{} to play", s.items.len()),
            Kind::Video => "Media".into(),
            Kind::Ai => "Ask it from your apps and agents".into(),
            Kind::Api => "Use it from your apps and agents".into(),
            Kind::Files if !s.items.is_empty() => format!("{} file{}", s.items.len(), if s.items.len() == 1 { "" } else { "s" }),
            Kind::Files => "Files".into(),
        };
        let mine = own(&s.seller);
        b.push_str(&format!("<a class=\"card service-card\" href=\"{}\"><span class=\"pill cat-{}\">{}</span>{}<h2>{}</h2>\
                             <p class=\"price\">{}</p><p class=\"small\">{} · {}</p></a>",
                            service_href(s), s.kind.category(), esc(s.kind.category_words()),
                            if mine { " <span class=\"pill good\">Your shop</span>" } else { "" },
                            esc(&s.name), esc(&s.price_text), esc(&what), esc(&host(&s.seller))));
    }
    b.push_str("</div>");
    b
}

fn host(url: &str) -> String {
    services::http_origin(url).unwrap_or_else(|| url.to_string()).trim_start_matches("https://").trim_start_matches("http://").to_string()
}

fn service_href(s: &Service) -> String {
    format!("./service?seller={}&amp;name={}", services::urlenc(&s.seller), services::urlenc(&s.name))
}

/// A service's own page: its price and seller, then what its category needs. `own`: the seller is
/// this box's own shop, which this box cannot buy from: its items play as a free preview instead.
fn service_html(s: &Service, own: bool) -> String {
    let mut b = format!("<p class=\"small\"><a href=\"./browse?cat={}\">← {}</a></p>\
        <section class=\"card\"><div class=\"offer-head\"><span class=\"pill cat-{}\">{}</span><span class=\"price\">{}</span></div>\
        <p class=\"small\">Sold by {}</p></section>",
        s.kind.category(), esc(s.kind.category_words()), s.kind.category(), esc(s.kind.category_words()), esc(&s.price_text), esc(&host(&s.seller)));
    if own {
        b.push_str("<section class=\"status ok\"><p class=\"status-head\">This is your shop</p><p>Buyers pay for this. You can preview it \
            here for free: it plays straight from your service on this box, and nothing is paid.</p></section>");
    }
    let play = if own { "Preview (free)" } else { "Play" };
    match s.kind {
        Kind::Video => {
            if s.items.is_empty() {
                b.push_str("<p class=\"empty\">This seller lists nothing to play yet.</p>");
            } else {
                b.push_str("<div class=\"grid\">");
                for item in &s.items {
                    b.push_str(&format!("<article class=\"card item\"><h3>{} <span class=\"small\">{}</span></h3><p class=\"small\">{}</p>\
                                         <p><a class=\"button-link\" href=\"./play?item={}\">{play}</a></p></article>",
                                        esc(&item.title), esc(&item.year), esc(&item.credit), services::urlenc(&item.url)));
                }
                b.push_str("</div>");
            }
        }
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

fn player_html(ctx: &Ctx, connector: &str, service: &Service, item: &services::Item) -> String {
    if service.kind != Kind::Video {
        return format!("<p>{} is not something to play. Its service's page says how to use it: <a href=\"{}\">{}</a>.</p>",
                       esc(&item.title), service_href(service), esc(&service.name));
    }
    let src = match services::player_src(connector, &item.url) {
        Ok(s) => s,
        Err(e) => return format!("{}<p><a href=\"./browse\">Back to Browse</a></p>", App::error_box(&e)),
    };
    format!("<p class=\"small\"><a href=\"{}\">← {}</a> · {} · <span class=\"price\">{}</span></p>\
             <div class=\"player\" data-player data-item=\"{}\"><video controls autoplay src=\"{}\"></video>\
             <p class=\"player-msg\" role=\"status\" aria-live=\"polite\" hidden></p></div>\
             <p class=\"small\">{}</p>\
             <form method=\"post\" action=\"./play\" data-stop-player>\
             {}<input type=\"hidden\" name=\"item\" value=\"{}\">\
             <button class=\"danger\" type=\"submit\">Stop and cut the connection</button></form>\
             <p class=\"hint\">You pay as it plays. Stopping ends the payments at once; <a href=\"./connections\">Live connections</a> shows what is open.</p>",
            service_href(service), esc(&service.name), esc(&item.year), esc(&service.price_text), esc(&item.url), esc(&src), esc(&item.credit),
            App::csrf_input(ctx), esc(&item.url))
}

/// The owner's own shop: a free preview, straight from the service on this box (`/preview`), never
/// through the gateway and never paid. Only the owner, logged in, gets this page.
fn own_player_html(service: &Service, item: &services::Item) -> String {
    format!("<p class=\"small\"><a href=\"{}\">← {}</a> · {}</p>\
             <section class=\"status ok\"><p class=\"status-head\">Preview of your shop (free)</p><p>This plays straight from your service on \
             this box. Nothing is paid: a box cannot buy from its own shop. Buyers pay {}.</p></section>\
             <div class=\"player\" data-player data-item=\"{}\" data-preview><video controls autoplay src=\"./preview?item={}\"></video>\
             <p class=\"player-msg\" role=\"status\" aria-live=\"polite\" hidden></p></div>\
             <p class=\"small\">{}</p>",
            service_href(service), esc(&service.name), esc(&item.year), esc(&service.price_text), esc(&item.url), services::urlenc(&item.url), esc(&item.credit))
}

/// `6 hours`, `90 minutes`, `45 seconds`.
fn lasts(d: std::time::Duration) -> String {
    let s = d.as_secs();
    let (n, unit) = if s >= 7200 { (s / 3600, "hour") } else if s >= 120 { (s / 60, "minute") } else { (s, "second") };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

/// The Player page's section for VLC, mpv and other players: the item's live links, each with the
/// exact address to paste and a button that revokes it, and a button that makes one.
fn links_html(ctx: &Ctx, base: &str, item_url: &str, links: &[crate::relay::Shown]) -> String {
    let csrf = App::csrf_input(ctx);
    let mut b = format!("<details class=\"card\"{}><summary>", if links.is_empty() { "" } else { " open" });
    b.push_str("Play in VLC, mpv or another player</summary>\
        <p class=\"small\">A link plays this item through this app on any device that can reach it, without logging in: paste it into \
        VLC (Media, Open Network Stream) or run <code>mpv '&lt;link&gt;'</code>. Seeking works, and each part is paid as it plays, \
        within your spending rules. Anyone who has the link can play this item, and nothing else, until it expires or you revoke it.</p>");
    for l in links {
        let url = format!("{base}r/{}", l.token);
        b.push_str(&format!("<div class=\"row\"><input readonly class=\"relay-link\" aria-label=\"Link for an external player\" value=\"{}\">\
                             <span class=\"small\">{} left</span>\
                             <form method=\"post\" action=\"./play-link\" class=\"inline\">{csrf}<input type=\"hidden\" name=\"action\" value=\"revoke\">\
                             <input type=\"hidden\" name=\"item\" value=\"{}\"><input type=\"hidden\" name=\"token\" value=\"{}\">\
                             <button class=\"danger\" type=\"submit\">Revoke</button></form></div>",
                            esc(&url), lasts(l.left), esc(item_url), esc(&l.token)));
    }
    b.push_str(&format!("<form method=\"post\" action=\"./play-link\">{csrf}<input type=\"hidden\" name=\"action\" value=\"create\">\
                         <input type=\"hidden\" name=\"item\" value=\"{}\"><button type=\"submit\" class=\"secondary\">{}</button></form></details>",
                        esc(item_url), if links.is_empty() { "Make a link" } else { "Make another link" }));
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
            Some("settled") => c.settled += 1,
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
    let mut b = String::from("<p class=\"lead\">Every service you are paying for right now. Stop one and its payments end at once; \
                              what you paid ahead and did not use comes back to you. This page updates every few seconds.</p>");
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
    let pill = match state {
        "open" => "<span class=\"pill good\">Open</span>",
        "stopping" | "stopped" => "<span class=\"pill warn\">Stopping</span>",
        _ => "<span class=\"pill\">Closed</span>",
    };
    let rate = if open && minutes >= 1.0 && spent > 0 {
        format!(" · about <span class=\"money\">{}</span> a minute", sats_short((spent as f64 / minutes).round() as i64))
    } else {
        String::new()
    };
    let how_long = if minutes >= 1.0 { format!(" · open {} min", minutes.round() as i64) } else { String::new() };
    let failed = format!("never sent {}<br>cancelled at stop {}<br>payment failed {}", c.never_sent, c.cancelled_at_stop, c.payment_failed);
    let err = err.map(|e| format!("<p class=\"hint bad\">{}</p>", esc(e))).unwrap_or_default();
    format!("<section class=\"card live\"><div class=\"offer-head\"><h2>{}</h2>{pill}</div>\
             <p>Spent so far: <span class=\"money\">{}</span>{rate}{how_long}</p>{err}<div class=\"row\">{stop}</div>\
             <details><summary>Details</summary><p class=\"small\">{} · connection <code>{}</code></p><div class=\"scroll\"><table><thead><tr><th>Locked</th>\
             <th>Released</th><th>Prepaid</th><th>Settled</th><th>Failed by</th><th>Balance</th></tr></thead><tbody><tr><td>{}</td><td>{}</td><td>{}</td>\
             <td>{}</td><td class=\"small\">{failed}</td><td>{}</td></tr></tbody></table></div></details></section>",
            esc(name), sats_short(spent), esc(origin), esc(id), c.locked, c.released, c.prepaid, c.settled, balance_cell(paying, id, c.booked_sats))
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
        assert_eq!((c.locked, c.released, c.prepaid, c.settled, c.booked_sats), (2, 2, 2, 1, 50));
        assert_eq!((c.never_sent, c.cancelled_at_stop, c.payment_failed), (1, 1, 1));
    }

    #[test]
    fn the_player_src_is_the_connector_plus_the_item_and_the_credit_is_escaped() {
        let svc = Service { name: "Films".into(), kind: Kind::Video, seller: "https://media.lazarus-xbt.xyz".into(),
                            price_text: "20 sat a MiB".into(),
                            items: vec![services::Item { title: "<b>".into(), year: "2008".into(),
                                url: "https://media.lazarus-xbt.xyz/v?static=true&x=1".into(), credit: "CC <BY>".into() }],
                            address: String::new() };
        let ctx = Ctx { sid: "s".into(), csrf: "tok&1".into(), flash: None };
        let html = player_html(&ctx, "http://127.0.0.1:8480/", &svc, &svc.items[0]);
        assert!(html.contains("src=\"./s/https://media.lazarus-xbt.xyz/v?static=true&amp;x=1\""));
        assert!(html.contains("Stop and cut the connection"));
        assert!(html.contains("value=\"tok&amp;1\""));
        // the item's title is the page's heading (escaped by the layout); the credit is in the body
        assert!(html.contains("CC &lt;BY&gt;") && !html.contains("<BY>"));
    }
}
