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
use crate::server::{Req, Resp};
use crate::services::{self, Kind, Service, Sort};

const REFRESH: &str = "<meta http-equiv=\"refresh\" content=\"4\">";

impl App {
    pub(crate) fn browse(&self, ctx: &Ctx, q: &HashMap<String, String>) -> Resp {
        let cat = q.get("cat").or(q.get("kind")).map(String::as_str).unwrap_or("");
        let sort = Sort::parse(q.get("sort").map(String::as_str).unwrap_or(""));
        let body = match self.file_services() {
            Ok(all) => {
                // a shop reached by its key that looks offline (its listing stale, no node vouching for it) is folded away
                let shops = crate::shops::load(&self.cfg.shops_path()).unwrap_or_default();
                let now = xbt_nostr::now();
                let days = |seller: &str| if self.is_own_shop(seller) { None } else {
                    services::http_origin(seller).and_then(|o| shops.get(&o).and_then(|s| crate::shops::offline_days(s, &o, now)))
                };
                let (live, gone) = split_offline(&all, &days);
                // sellers to pay, and a node that can't send a first ticket to any: said before anything is opened
                let warn = if live.iter().any(|s| !self.is_own_shop(&s.seller)) {
                    crate::pay_feedback::cant_send_card(self.spendable_sats(), crate::app::MIN_CALL_SATS, "your sellers")
                } else {
                    String::new()
                };
                // a hashrate seller's live offer, where the Hashrate page's last look found it: nothing is asked for Browse
                let offers = self.kept_hash_offers();
                let live_offer = |seller: &str| crate::app::hashrate::live_offer_words(&offers, seller);
                let favorites = if cat.is_empty() { self.favorites_html(&live) } else { String::new() };
                let shown = browse_html(&live, cat, sort, &self.suggested(ctx, &all), &|seller| self.is_own_shop(seller), &live_offer);
                format!("{warn}{favorites}{shown}{}", offline_html(&gone, &days))
            }
            Err(e) => format!("{}{}", Self::error_box(&e), empty_how(&self.suggested(ctx, &[]))),
        };
        // the sellers on the owner's list (adding a shop, allowing it to be paid, the credit with each): once a tab of Buy
        let more = format!("<p class=\"small\">Your <a href=\"./services\">sellers</a>: add a shop, allow it to be paid, see the credit left with each.{}</p>",
                           if self.nostr.enabled() { " More sellers, not checked by anyone: <a href=\"./nostr\">found on Nostr</a>." } else { "" });
        self.html_page("Browse", "Browse", ctx, &format!("{body}{more}"), "")
    }

    /// The owner's favorite shops' services, as cards: on the Wallet page of the simple view and at the top of Browse.
    /// Nothing where there are none.
    pub(crate) fn favorites_html(&self, all: &[Service]) -> String {
        let prefs = self.prefs();
        let favs: Vec<&Service> = all.iter().filter(|s| services::http_origin(&s.seller).is_some_and(|o| prefs.is_favorite(&o))).collect();
        if favs.is_empty() {
            return String::new();
        }
        let mut b = String::from("<h2>Favorites</h2><div class=\"grid services favorites\">");
        for s in favs {
            b.push_str(&format!("<a class=\"card service-card\" href=\"{}\"><span class=\"pill cat-{}\">{}{}</span><h2>{}</h2><p class=\"price\">{}</p><p class=\"small\">{}</p></a>",
                                service_href(s), s.category(), services::icon(s.category()), esc(s.category_words()), esc(&s.name),
                                esc(if s.kind == Kind::Hashrate { services::HASHRATE_PRICE_WORDS } else { &s.price_text }), esc(&seller_words(all, &s.seller))));
        }
        b.push_str("</div>");
        b
    }

    /// The button on a service's page that keeps its shop as a favorite, or stops.
    fn favorite_form(&self, ctx: &Ctx, svc: &Service) -> String {
        let Some(origin) = services::http_origin(&svc.seller) else { return String::new() };
        let is = self.prefs().is_favorite(&origin);
        format!("<form method=\"post\" action=\"./favorite\" class=\"favorite\">{}<input type=\"hidden\" name=\"seller\" value=\"{}\">\
                 <input type=\"hidden\" name=\"on\" value=\"{}\"><input type=\"hidden\" name=\"back\" value=\"{}\">\
                 <button class=\"secondary\">{}</button></form>",
                App::csrf_input(ctx), esc(&origin), if is { "0" } else { "1" }, service_href(svc),
                if is { "★ In your favorites: remove" } else { "☆ Add this shop to your favorites" })
    }

    /// One-click forms for the suggested sellers not added yet.
    /// The first suggested seller not added yet, if any: the demo shop on a box as installed.
    pub(crate) fn first_suggestion(&self) -> Option<String> {
        let have = self.file_services().unwrap_or_default();
        self.cfg.suggested_sellers.iter().find(|u| {
            let origin = xbt402::shop::parse(u).unwrap_or_else(|| u.to_string());
            !have.iter().any(|s| services::same_origin(&s.seller, &origin))
        }).cloned()
    }

    pub(crate) fn suggested(&self, ctx: &Ctx, have: &[Service]) -> String {
        let mut b = String::new();
        // a suggestion is a web address or a shop key: matched against the sellers added by the address it names
        for url in self.cfg.suggested_sellers.iter().filter(|u| {
            let origin = xbt402::shop::parse(u).unwrap_or_else(|| u.to_string());
            !have.iter().any(|s| services::same_origin(&s.seller, &origin))
        }) {
            let shown = if url == DEMO_SHOP {
                "Lightning Stream Genesis, the demo shop".to_string()
            } else if url.starts_with("npub1") && url.len() > 16 {
                format!("shop key {}…{}", &url[..10], &url[url.len() - 6..])
            } else {
                url.trim_start_matches("https://").to_string()
            };
            // one press adds the shop and opens the rules with it allowed: one signature, no second visit to Sellers
            b.push_str(&format!("<form method=\"post\" action=\"./services\" class=\"row suggested\">{}<input type=\"hidden\" name=\"action\" value=\"try\">\
                <input type=\"hidden\" name=\"url\" value=\"{}\"><span>Suggested: <strong>{}</strong></span><button class=\"secondary\">Add and allow</button></form>",
                App::csrf_input(ctx), esc(url), esc(&shown)));
        }
        b
    }

    /// `GET /service?seller=…&name=…`: one service, as its category needs.
    pub(crate) fn service_page(&self, ctx: &Ctx, req: &Req) -> Resp {
        let q = &req.query;
        let seller = q.get("seller").map(String::as_str).unwrap_or("");
        let name = q.get("name").map(String::as_str).unwrap_or("");
        let found = self.services().ok().and_then(|all| all.into_iter().find(|s| services::same_origin(&s.seller, seller) && s.name == name));
        match found {
            Some(svc) => {
                let own = self.is_own_shop(&svc.seller);
                let mut body = String::new();
                // a shop that looks offline: said first, in place of advice that can't help
                let offline = if own { None } else { self.offline_days(&svc.seller) };
                if let Some(days) = offline {
                    body.push_str(&format!("<section class=\"flash warn\" id=\"offline\"><p><strong>This shop looks offline.</strong> {}</p></section>",
                                           esc(&crate::shops::offline_words(days))));
                }
                // a shop the rules don't allow yet: said before the owner tries it and is refused, with the one button that fixes it
                if !own && offline.is_none() && svc.kind != Kind::Hashrate && !self.seller_allowed(&svc.seller) {
                    let origin = services::http_origin(&svc.seller).unwrap_or_else(|| svc.seller.clone());
                    body.push_str(&format!("<section class=\"flash warn\" id=\"not-allowed\"><p><strong>Allow {} first.</strong> Your spending rules don't \
                        allow this shop yet, so the app would refuse to pay it. Allowing it takes one signature.</p>\
                        <form method=\"post\" action=\"./services\">{}<input type=\"hidden\" name=\"action\" value=\"allow\">\
                        <input type=\"hidden\" name=\"url\" value=\"{}\"><button>Allow this seller to be paid</button></form></section>",
                        esc(&self.seller_name(&origin)), App::csrf_input(ctx), esc(&origin)));
                }
                if !own {
                    if let Some(m) = services::http_origin(&svc.seller).and_then(|o| self.credits().get(&o).copied()) {
                        body.push_str(&crate::app::credit_line(&self.seller_name(&svc.seller), m));
                    }
                }
                body.push_str(&service_html(&svc, own, &seller_words(&self.services().unwrap_or_default(), &svc.seller)));
                if !own {
                    body.push_str(&self.favorite_form(ctx, &svc));
                }
                if svc.has_files() {
                    // the node can't send a first ticket: said before a download is started
                    if !own {
                        body.push_str(&crate::pay_feedback::cant_send_card(self.spendable_sats(), crate::app::MIN_CALL_SATS, "this shop"));
                    }
                    body.push_str(&files_html(ctx, &svc, own, &self.link_base(req), &|item| self.relays.of_item(item)));
                }
                self.html_page("Service", &svc.name, ctx, &body, "")
            }
            None => self.html_page("Service", "Service", ctx, &format!("{}<p><a href=\"./browse\">Back to Browse</a></p>",
                                                                     Self::error_box("That service is not in your list. A seller may have removed it.")), ""),
        }
    }

    pub(crate) fn connections(&self, ctx: &Ctx) -> Resp {
        let names = self.services().unwrap_or_default();
        // rented hashrate is one more kind of connection: a pulse for each piece of work paid
        let (cards, spent, renting) = self.hash_live_cards(ctx);
        let conns = match self.call("ticket_status", json!({})) {
            Ok(st) => connections_html(ctx, &st, &|id| self.call("ticket_status", json!({"session": id})), &names, crate::now(), !cards.is_empty(), &renting),
            Err(e) => Self::error_box(&e),
        };
        // a rental going on first: the shop's connection that pays it is the means, said as that below it
        let body = if cards.is_empty() {
            conns
        } else {
            format!("<h2>Rented hashrate</h2><div class=\"stack\" data-spent=\"{spent}\">{cards}</div><h2>Connections</h2>{conns}")
        };
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

    /// `POST /file-link`: a link for the buyer's own player for one file of the services file
    /// (`action=create`), or revoke one (`action=revoke`, `token`). The CSRF token was checked with
    /// every POST. Back to the file's service page.
    pub(crate) fn file_link(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let item_url = f.get("item").map(|s| s.trim().to_string()).unwrap_or_default();
        let all = self.services().unwrap_or_default();
        // the service the buyer chose, where several list the file; else the first that does
        let chosen = f.get("service").map(|s| s.trim().to_string()).unwrap_or_default();
        let found = services::find_item_of(&all, &chosen, &item_url).or_else(|| services::find_item(&all, &item_url));
        let Some((svc, _)) = found.filter(|(s, _)| s.has_files()) else {
            self.flash(ctx, false, "That file is not in your list of services.");
            return Resp::redirect("./browse?cat=files");
        };
        let back = format!("./service?seller={}&name={}", services::urlenc(&svc.seller), services::urlenc(&svc.name));
        match f.get("action").map(String::as_str) {
            Some("create") => {
                self.relays.create_for(&item_url, &svc.id());
                self.flash(ctx, true, format!("Link made: copy it into your player. It plays this file only, and stops working in {}.", lasts(self.cfg.relay_ttl)));
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
    /// `http(s)://<Host><base path>`. The Host was checked against the allowed names already. Where the
    /// links have a port of their own (`XBT_UI_LINKS_BIND`), that port's address instead.
    fn link_base(&self, req: &Req) -> String {
        // the links' own port (a platform's login is in front of this page's): its address, by IP where this page was
        if let Some(base) = self.relays.served_at().and_then(|a| crate::relay::links_base(self.cfg.links_url.as_deref(), a.port(), req.header("host"))) {
            return base;
        }
        let https = self.cfg.secure_cookie.unwrap_or_else(|| req.header("x-forwarded-proto").eq_ignore_ascii_case("https"));
        let host = req.header("host").trim();
        let base = if self.cfg.base_path.ends_with('/') { self.cfg.base_path.clone() } else { format!("{}/", self.cfg.base_path) };
        format!("{}://{host}{base}", if https { "https" } else { "http" })
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

    /// Stop every open connection with the seller at `origin`: how many were stopped.
    pub(crate) fn stop_seller_sessions(&self, origin: &str) -> usize {
        let Ok(st) = self.call("ticket_status", json!({})) else { return 0 };
        open_ids(&st, Some(&[origin.to_string()])).iter()
            .filter(|id| self.call("ticket_stop", json!({"session": id})).is_ok_and(|v| ok_of(&v))).count()
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

/// The demo shop every package suggests (Lightning Stream Genesis), named on the pages that offer it.
pub(crate) const DEMO_SHOP: &str = "npub1kqdrfmfg6mg52sy3ehu4vv7m3fjpa0830rhjdmvqrf09u3t3724q8cwr6a";

fn empty_how(suggested: &str) -> String {
    format!("<section class=\"card empty-card\"><p class=\"empty\">No services yet.</p>\
     <p>Add a seller to see what they offer: web apps such as a media server, AI models to ask, hashrate, data and other services, each paid a little at a time.</p>\
     <p><a class=\"button-link primary\" href=\"./services\">Add a seller</a></p>{suggested}</section>")
}

/// The services of shops that look offline (`days`: how old the listing of one that does is,
/// [`crate::shops::offline_days`]) apart from the others: (the others, those).
fn split_offline(all: &[Service], days: &dyn Fn(&str) -> Option<u64>) -> (Vec<Service>, Vec<Service>) {
    all.iter().cloned().partition(|s| days(&s.seller).is_none())
}

/// Browse's fold for the shops that look offline: each by name, with how old its listing is and its services.
fn offline_html(gone: &[Service], days: &dyn Fn(&str) -> Option<u64>) -> String {
    let mut sellers: Vec<&str> = vec![];
    for s in gone {
        if !sellers.contains(&s.seller.as_str()) {
            sellers.push(&s.seller);
        }
    }
    if sellers.is_empty() {
        return String::new();
    }
    let mut b = format!("<details class=\"card offline-shops\"><summary>Offline shops ({})</summary>\
        <p class=\"small\">These shops' listings are more than two days old and no Lightning node vouches for them any more, so they \
        can't be paid. A shop that comes back is listed above again once you press Check for updates on <a href=\"./services\">Sellers</a>.</p><ul>",
        sellers.len());
    for seller in sellers {
        let words = days(seller).map(crate::shops::offline_words).unwrap_or_default();
        let links: Vec<String> = gone.iter().filter(|s| s.seller == seller)
            .map(|s| format!("<a href=\"{}\">{}</a>", service_href(s), esc(&s.name))).collect();
        b.push_str(&format!("<li><strong>{}</strong>: {} <span class=\"small\">{}</span></li>", esc(&seller_words(gone, seller)), esc(&words), links.join(" · ")));
    }
    b.push_str("</ul></details>");
    b
}

/// `live`: what a hashrate seller's live offer asks ([`crate::app::hashrate::live_offer_words`]), where it is known.
fn browse_html(all: &[Service], cat: &str, sort: Sort, suggested: &str, own: &dyn Fn(&str) -> bool, live: &dyn Fn(&str) -> Option<String>) -> String {
    let cat = cat.trim().to_ascii_lowercase();
    // a kind or an older category names its category: films (`video`) are files, a media server (`media`) a web app
    let cat = match cat.as_str() {
        "video" => "files".to_string(),
        "media" => "apps".to_string(),
        "api" => "data".to_string(),
        c if services::CATEGORIES.iter().any(|(id, _)| *id == c) => cat,
        _ => String::new(),
    };
    let sort_q = if sort == Sort::Price { "&amp;sort=price" } else { "" };
    let mut b = String::from("<nav class=\"chips\" aria-label=\"Categories\">");
    let count = |id: &str| all.iter().filter(|s| id.is_empty() || s.category() == id).count();
    // every kind of service, one row: AI and VPN lead to their own pages (once tabs of Buy beside Browse, so AI was there
    // twice), the others filter the list. Hashrate is offered on its page, from the listings shops publish, not from the
    // list of sellers: with none on that list its chip leads there, with no count (0.2.1 said "Hashrate 0" beside an offer)
    for (id, words) in [("", "All"), ("ai", "AI"), ("hashrate", "Hashrate"), ("vpn", "VPN"), ("files", "Files"), ("data", "Data & APIs"), ("apps", "Web apps")] {
        if matches!(id, "ai" | "vpn") || (id == "hashrate" && count(id) == 0) {
            b.push_str(&format!("<a href=\"./{id}\">{}{}</a>", services::icon(id), esc(words)));
            continue;
        }
        let cur = if id == cat { " aria-current=\"page\"" } else { "" };
        b.push_str(&format!("<a href=\"./browse?cat={id}{sort_q}\"{cur}>{}{} <span class=\"count\">{}</span></a>", services::icon(id), esc(words), count(id)));
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
        // miners for rent are listed on the Hashrate page, from the offers shops publish, not on the list of sellers
        b.push_str(if cat == "hashrate" {
            "<p class=\"empty\">Miners for rent are listed on the <a href=\"./hashrate\">Hashrate</a> page. <a href=\"./browse\">Show all</a></p>"
        } else {
            "<p class=\"empty\">No services in this category yet. <a href=\"./browse\">Show all</a></p>"
        });
        return b;
    }
    b.push_str("<div class=\"grid services\">");
    for s in &shown {
        let n = s.items.len();
        let what = match s.kind {
            _ if s.category() == "apps" => "A web app: open it inside Lightning Stream".into(),
            _ if s.has_files() => format!("{n} file{}: download, or open in your player", if n == 1 { "" } else { "s" }),
            Kind::Video | Kind::Files => "No files listed yet".into(),
            Kind::Ai => "Ask it from your apps and agents".into(),
            Kind::Api => "Use it from your apps and agents".into(),
            Kind::Hashrate => "Rent miners by the piece of work".into(),
        };
        let mine = own(&s.seller);
        let what = if s.app.is_empty() || s.category() == "apps" { what } else { format!("{what} · has its own app") };
        // a hashrate seller costs what its live offer asks, never the price its listing (or an older services file) names
        let price = if s.kind == Kind::Hashrate { live(&s.seller).unwrap_or_else(|| services::HASHRATE_PRICE_WORDS.into()) } else { s.price_text.clone() };
        b.push_str(&format!("<a class=\"card service-card\" href=\"{}\"><span class=\"pill cat-{}\">{}{}</span>{}<h2>{}</h2>\
                             <p class=\"price\">{}</p><p class=\"small\">{} · {}</p></a>",
                            service_href(s), s.category(), services::icon(s.category()), esc(s.category_words()),
                            if mine { " <span class=\"pill good\">Your shop</span>" } else { "" },
                            esc(&s.name), esc(&price), esc(&what), esc(&seller_words(all, &s.seller))));
    }
    b.push_str("</div>");
    b
}

/// A seller as the pages show it: its web address's host, or for a shop reached by its key, that key
/// shortened (its made-up `<key>.shop.invalid` name means nothing to a person, and is too long for a line).
/// A seller as a line under a service names it: a shop known by its key by its listing's name
/// ("Lightning Stream Genesis"), a seller with a web address by its host.
pub(crate) fn seller_words(all: &[Service], seller: &str) -> String {
    match services::http_origin(seller) {
        Some(o) if xbt402::shop::is_shop(&o) => services::seller_name(all, &o),
        _ => host(seller),
    }
}

pub(crate) fn host(url: &str) -> String {
    if let Some(pk) = xbt402::shop::key_of(url) {
        let npub = xbt402::shop::npub(&pk);
        return format!("{}…{}", &npub[..13], &npub[npub.len() - 4..]);
    }
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
fn service_html(s: &Service, own: bool, seller: &str) -> String {
    let mut b = format!("<p class=\"small\"><a href=\"./browse?cat={}\">← {}</a></p>\
        <section class=\"card\"><div class=\"offer-head\"><span class=\"pill cat-{}\">{}{}</span><span class=\"price\">{}</span></div>\
        <p class=\"small\">Sold by {}</p></section>",
        s.category(), esc(s.category_words()), s.category(), services::icon(s.category()), esc(s.category_words()),
        esc(if s.kind == Kind::Hashrate { services::HASHRATE_PRICE_WORDS } else { &s.price_text }), esc(seller));
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
        b.push_str(&if own {
            format!("<section class=\"card\"><h2>Its own app</h2><p>Buyers can open this service's own web page inside their app, \
                and pay your price for what it loads. You can try it here for free.</p>\
                <div class=\"row\"><a class=\"button-link\" href=\"./app?u={}&amp;b={}\">Preview the app (free)</a></div></section>",
                services::urlenc(&s.app), services::urlenc(&s.app_base))
        } else {
            format!("<section class=\"card primary\"><h2>Its own app</h2><p>Use {}'s own page for this service, inside Lightning Stream. \
                What it loads is paid at the price above, up to a limit you set.</p>\
                <div class=\"row\"><a class=\"button-link primary\" href=\"./app?u={}&amp;b={}\">Open {}'s app</a></div></section>",
                esc(seller), services::urlenc(&s.app), services::urlenc(&s.app_base), esc(seller))
        });
    }
    match s.kind {
        // a media server is the seller's own web app, opened above; an older listing names films for a
        // player this app no longer has
        Kind::Video | Kind::Files if s.has_files() || !s.app.is_empty() => {}
        Kind::Files => b.push_str("<p class=\"empty\">This seller lists no files yet.</p>"),
        Kind::Video => b.push_str("<section class=\"status warn\"><p class=\"status-head\">This shop uses an older media listing</p>\
            <p>It names nothing to download or open. Ask the seller to share their media server as a web app: Lightning Stream opens \
            a seller's own app (Jellyfin, Plex) and pays for what it loads.</p></section>"),
        // an AI seller is used through this box's own AI address (any OpenAI-style program, with a key of its own), which
        // picks the cheapest allowed seller; the seller's own address (for a shop reached by its key, a made-up one only
        // this wallet's agents can reach) stays in the details
        Kind::Ai => b.push_str(&format!("<section class=\"card primary\"><h2>Use it</h2>\
            <p>Use this seller's models from any program that works with OpenAI's API (Open WebUI, coding agents, your own scripts): \
            give the program this box's AI address and a key of its own, both on the AI page. Each request is paid by the word as it arrives, \
            within your spending rules.</p>\
            <div class=\"row\"><a class=\"button-link primary\" href=\"./ai\">Get the AI address and a key</a>\
            <a class=\"button-link\" href=\"./agents\">Connect an AI agent</a></div>\
            <details><summary>Technical details</summary><p class=\"small\">The seller's own address, for agents connected to this wallet: \
            <code>{}</code></p></details></section>", esc(s.address()))),
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

/// A size as a Files listing words it (`850 KB`, `1.4 GB`, `850 bytes`): bytes.
fn size_of(words: &str) -> Option<f64> {
    let (n, unit) = words.trim().split_once(' ')?;
    let n: f64 = n.parse().ok()?;
    let mult = match unit {
        "bytes" => 1.0,
        "KB" => 1e3,
        "MB" => 1e6,
        "GB" => 1e9,
        "TB" => 1e12,
        _ => return None,
    };
    Some(n * mult)
}

/// The sats a byte costs, from a price as Browse words it (`1000 sat a GB`, `20 sat a MiB`).
fn sat_a_byte(price: &str) -> Option<f64> {
    let (n, rest) = price.trim().split_once(" sat a ")?;
    let n: f64 = n.replace(',', "").parse().ok()?;
    match rest {
        "GB" => Some(n / 1e9),
        "MiB" => Some(n / 1_048_576.0),
        _ => None,
    }
}

/// About what a file costs: `about 1,400 sat`, `under 1 sat`.
fn about_sats(bytes: f64, per_byte: f64) -> String {
    let sats = bytes * per_byte;
    if sats < 1.0 {
        return "under 1 sat".into();
    }
    let n = sats.round() as u64;
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    format!("about {out} sat")
}

/// What a player's link has carried, beside it on the Files page: running while the player reads, a
/// short total once it stops. The sats are the file's listed price for those bytes (the UI relays the
/// bytes; what each call paid stays with the connector), so "about".
fn link_use(bytes: u64, in_use: bool, playing: bool, per_byte: Option<f64>) -> String {
    if bytes == 0 && !in_use {
        return String::new();
    }
    let sats = per_byte.map(|p| format!(", {}", about_sats(bytes as f64, p))).unwrap_or_default();
    if in_use {
        // "Playing" only while bytes move; a player that holds the link paused is "Open"
        let pill = if playing { "<span class=\"pill good\">Playing</span>" } else { "<span class=\"pill\">Open</span>" };
        format!("<span class=\"small link-use\">{pill} {} so far{sats}</span>", bytes_words(bytes))
    } else {
        format!("<span class=\"small link-use\">Carried {}{sats}</span>", bytes_words(bytes))
    }
}

/// `12.3 MB`, `1.40 GB`, `800 bytes`, as file sizes are listed (powers of 1,000).
fn bytes_words(n: u64) -> String {
    let f = n as f64;
    match n {
        0..1_000 => format!("{n} bytes"),
        1_000..1_000_000 => format!("{:.0} KB", f / 1e3),
        1_000_000..1_000_000_000 => format!("{:.1} MB", f / 1e6),
        _ => format!("{:.2} GB", f / 1e9),
    }
}

/// `6 hours`, `90 minutes`, `45 seconds`.
/// How long a link lasts, or has left, rounded to the nearest hour or minute: a link made for 6 hours says
/// "6 hours left" just after, as its flash said (0.2.6 cut it down to "5 hours left" a second later).
fn lasts(d: std::time::Duration) -> String {
    let s = d.as_secs();
    let (n, unit) = if s >= 7200 { ((s + 1800) / 3600, "hour") } else if s >= 120 { ((s + 30) / 60, "minute") } else { (s, "second") };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

/// A Files service's list: each file's name, size and price, a Download (paid as it arrives, from
/// this page's own address: [`crate::server`]), and Open in your player: a link VLC, mpv or a TV app
/// opens on any device that reaches this app ([`crate::relay`]). `own`: this box's own shop, which it
/// cannot buy from.
fn files_html(ctx: &Ctx, s: &Service, own: bool, base: &str, links: &dyn Fn(&str) -> Vec<crate::relay::Shown>) -> String {
    let per_byte = sat_a_byte(&s.price_text);
    let token = crate::app::stream_token(&ctx.csrf);
    let csrf = App::csrf_input(ctx);
    let mut b = String::from("<section class=\"card\"><h2>Files</h2>");
    b.push_str(if own {
        "<p class=\"hint\">Your box can't buy from its own shop: buyers see this list, and the files are in your shared folder.</p>"
    } else {
        "<p class=\"hint\">Download a file, or open it in your own player (VLC, mpv, a TV app). Either way you pay as it arrives, \
          within your spending rules, and stop paying when it stops.</p>"
    });
    b.push_str("<table class=\"files\"><thead><tr><th>Name</th><th>Size</th><th>Price</th><th></th></tr></thead><tbody>");
    for (i, item) in s.items.iter().enumerate() {
        let bytes = size_of(&item.credit);
        let size = if bytes.is_some() { esc(&item.credit) } else { String::new() };
        let note = if bytes.is_none() && !item.credit.is_empty() { format!("<br><span class=\"small\">{}</span>", esc(&item.credit)) } else { String::new() };
        let price = match (bytes, per_byte) {
            (Some(n), Some(p)) => about_sats(n, p),
            _ => esc(&s.price_text),
        };
        // a service not chosen from a listing has no price the app can hold the seller to: said, not hidden
        let price = if s.prices.is_object() { price } else { format!("{price}<br><span class=\"small\">no listed price</span>") };
        let actions = if own {
            String::new()
        } else {
            let dl = match services::download_src(&token, &s.id(), &item.url) {
                Ok(src) => format!("<a class=\"button-link\" href=\"{}\" download>Download</a>", esc(&src)),
                Err(_) => String::new(),
            };
            let shown = links(&item.url);
            let mut l = String::new();
            for (j, x) in shown.iter().enumerate() {
                let id = format!("link-{i}-{j}");
                let carried = link_use(x.bytes, x.in_use, x.playing, per_byte);
                l.push_str(&format!("<div class=\"row\"><input id=\"{id}\" readonly class=\"mono relay-link\" aria-label=\"Link for your player\" value=\"{}\">\
                    <button type=\"button\" class=\"secondary\" data-copy=\"{id}\">Copy</button><span class=\"small\">{} left</span>{carried}\
                    <form method=\"post\" action=\"./file-link\" class=\"inline\">{csrf}<input type=\"hidden\" name=\"action\" value=\"revoke\">\
                    <input type=\"hidden\" name=\"item\" value=\"{}\"><input type=\"hidden\" name=\"token\" value=\"{}\">\
                    <button class=\"link\" type=\"submit\">Revoke</button></form></div>",
                    esc(&format!("{base}r/{}", x.token)), lasts(x.left), esc(&item.url), esc(&x.token)));
            }
            format!("<div class=\"row\">{dl}<form method=\"post\" action=\"./file-link\" class=\"inline\">{csrf}\
                <input type=\"hidden\" name=\"action\" value=\"create\"><input type=\"hidden\" name=\"item\" value=\"{}\">\
                <input type=\"hidden\" name=\"service\" value=\"{}\">\
                <button class=\"secondary\" type=\"submit\">Open in your player</button></form></div>{l}", esc(&item.url), esc(&s.id()))
        };
        b.push_str(&format!("<tr><td><strong>{}</strong>{note}</td><td>{size}</td><td>{price}</td><td>{actions}</td></tr>", esc(&item.title)));
    }
    b.push_str("</tbody></table>");
    if !own {
        b.push_str("<p class=\"hint\">Open in your player makes a link: paste it into VLC (Media, Open Network Stream), run \
            <code>mpv '&lt;link&gt;'</code>, or add it in a TV app. It plays this one file, seeking included, from any device that reaches this app, \
            until it expires or you revoke it.</p>");
    }
    b.push_str("</section>");
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
    /// What left the node for the session's settled tickets, as the signer booked it (whole sats), and
    /// its two parts: what the seller's node got and the routing fee ([`crate::html::paid_html`]).
    paid_sats: i64,
    paid_value_msat: u64,
    paid_fee_msat: u64,
    /// Booked for tickets whose secret left and that have not settled yet: reserved, not paid.
    reserved_sats: i64,
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
                c.reserved_sats = c.reserved_sats.saturating_add(int(t.get("booked_sats")));
            }
            Some("retired") => {
                c.booked_sats = c.booked_sats.saturating_add(int(t.get("booked_sats")));
                c.reserved_sats = c.reserved_sats.saturating_add(int(t.get("booked_sats")));
            }
            // a settled ticket was paid: a prepaid one settles as soon as it arrives, a held one when the
            // seller collects it, and either way it is money that left the node
            Some("settled") => {
                c.settled += 1;
                c.booked_sats = c.booked_sats.saturating_add(int(t.get("booked_sats")));
                c.paid_sats = c.paid_sats.saturating_add(int(t.get("booked_sats")));
                c.paid_value_msat = c.paid_value_msat.saturating_add(t.get("msat").and_then(msat_of).unwrap_or(0));
                c.paid_fee_msat = c.paid_fee_msat.saturating_add(t.get("fee_msat").and_then(msat_of).unwrap_or(0));
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

/// What a session has paid so far ([`crate::html::paid_html`]): its settled tickets as the signer
/// booked them, with their two parts; or, where the wallet's count of the session says more was paid
/// (a payment of a call that was not a ticket), that count, whole sats only.
fn paid_of(paying: &Value, sid: &str, c: &Counts) -> (i64, Option<(u64, u64)>) {
    let row = paying.as_array().and_then(|a| a.iter().find(|p| p.get("session").and_then(Value::as_str) == Some(sid)));
    let counted = row.and_then(|p| p.get("paid_sats")).map(|v| int(Some(v))).unwrap_or(0);
    if counted > c.paid_sats {
        return (counted, None);
    }
    (c.paid_sats, (c.settled > 0 && c.paid_value_msat > 0).then_some((c.paid_value_msat, c.paid_fee_msat)))
}

fn balance_cell(paying: &Value, sid: &str, booked_sats: i64) -> String {
    let row = paying.as_array().and_then(|a| a.iter().find(|p| p.get("session").and_then(Value::as_str) == Some(sid)));
    if let Some(msat) = row.and_then(|p| p.get("balance_msat")).and_then(msat_of) {
        let whole = i64::try_from(msat / 1000).unwrap_or(i64::MAX);
        if msat % 1000 == 0 {
            return sats(whole);
        }
        // one figure, as the rest of the page writes it: 558.479 sats, not "558 sats + 479 msat"
        return msat_text(msat);
    }
    if let Some(paid) = row.and_then(|p| p.get("paid_sats")).map(|v| int(Some(v))) {
        return format!("{} <span class=\"small\">paid</span>", sats(paid));
    }
    if booked_sats > 0 {
        return format!("{} <span class=\"small\">reserved</span>", sats(booked_sats));
    }
    "—".into()
}

/// `more`: other connections (rented hashrate) follow, so an empty list here is not "nothing open".
/// `renting`: the rentals going on, by the address they are paid at and their name, whose shop connection pays them.
#[allow(clippy::too_many_arguments)]
fn connections_html(ctx: &Ctx, st: &Value, detail: &dyn Fn(&str) -> Result<Value, String>, names: &[Service], now: i64, more: bool,
                    renting: &[(String, String)]) -> String {
    let csrf = App::csrf_input(ctx);
    let mut b = String::from("<p class=\"lead\">Every service you are paying for right now. Stop one and its payments end at once. \
                              Money paid ahead and not used stays with that shop as credit, and is spent first next time. \
                              This page updates every few seconds.</p>");
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
        let paid = paid_of(&paying, id, &counts);
        total = total.saturating_add(paid.0);
        open += usize::from(state == "open");
        // the shop by its listing's name, never its made-up `…shop.invalid` address
        let name = services::seller_name(names, origin);
        // its key (npub) or web address under Details
        let origin = &xbt402::shop::display(origin);
        let opened = num(s.get("opened_ts"));
        let minutes = if opened > 0.0 { ((now as f64 - opened) / 60.0).max(0.0) } else { 0.0 };
        let pays_rental = renting.iter().find(|(pay, _)| services::same_origin(pay, s.get("origin").and_then(Value::as_str).unwrap_or(""))).map(|(_, h)| h.as_str());
        cards.push_str(&session_card(ctx, id, &name, origin, state, &counts, &paying, paid, minutes, err.as_deref(), pays_rental));
    }
    if open > 1 {
        b.push_str(&format!("<form method=\"post\" action=\"./connections\" class=\"row\">{csrf}\
                             <input type=\"hidden\" name=\"all\" value=\"1\"><button class=\"danger\" type=\"submit\">Stop all ({open})</button></form>"));
    }
    b.push_str(&format!("<div class=\"stack\" data-spent=\"{total}\">{cards}</div>"));
    b
}

#[allow(clippy::too_many_arguments)]
/// `rental`: the rental going on that this connection pays, by name: it is not idle between its payments.
fn session_card(ctx: &Ctx, id: &str, name: &str, origin: &str, state: &str, c: &Counts, paying: &Value, paid: (i64, Option<(u64, u64)>), minutes: f64,
                err: Option<&str>, rental: Option<&str>) -> String {
    let spent = paid.0;
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
        "open" if rental.is_some() => "<span class=\"pill good\">Paying a rental</span>",
        "open" => "<span class=\"pill\">Open, idle</span>",
        "stopping" | "stopped" => "<span class=\"pill warn\">Stopping</span>",
        _ => "<span class=\"pill\">Closed</span>",
    };
    // the rate is of what the seller used, where its receipts say: a prepaid ticket is paid all at once.
    // Only while bytes flow: an answer held open with nothing moving (a web app's event stream) showed the
    // connection's old average as if it were spending now
    let used_msat = row.and_then(|p| p.get("spent_msat")).and_then(msat_of);
    let per_min = used_msat.map_or(spent as f64, |m| m as f64 / 1000.0) / minutes.max(1.0);
    let flowing = used_msat.is_some_and(|m| use_moving(id, m, std::time::Instant::now()));
    let rate = if open && streaming && flowing && minutes >= 1.0 && per_min > 0.0 {
        format!(" · about <span class=\"money\">{}</span> a minute", msat_text((per_min * 1000.0).round() as u64))
    } else {
        String::new()
    };
    // nothing paid on this connection, yet something used: it ran on credit paid on an earlier one
    let paid_words = if paid.0 == 0 && used_msat.is_some_and(|m| m > 0) {
        "Paid from earlier credit: nothing new paid on this connection".to_string()
    } else {
        format!("Paid so far: {}", crate::html::paid_html(paid.0, paid.1))
    };
    let how_long = if minutes >= 1.0 { format!(" · open {} min", minutes.round() as i64) } else { String::new() };
    let failed = format!("{} never sent · {} canceled at Stop · {} failed", c.never_sent, c.cancelled_at_stop, c.payment_failed);
    let err = err.map(|e| format!("<p class=\"hint bad\">{}</p>", esc(e))).unwrap_or_default();
    let used = usage_line(row);
    let used = match rental.filter(|_| open) {
        Some(h) => format!("<p class=\"hint\">This connection pays the rental Hashrate from {}, under Rented hashrate above.</p>{used}", esc(h)),
        None => used,
    };
    // booked for tickets whose secret left and that have not settled: reserved, not paid yet
    let reserved = if c.reserved_sats > 0 { format!(" · <span class=\"small\">{} reserved</span>", sats_short(c.reserved_sats)) } else { String::new() };
    format!("<section class=\"card live\"><div class=\"offer-head\"><h2>{}</h2>{pill}</div>\
             <p>{paid_words}{reserved}{rate}{how_long}</p>{used}{err}<div class=\"row\">{stop}</div>\
             <details><summary>Details</summary><p class=\"small\">{} · connection <code>{}</code></p>{}</details></section>",
            esc(name), esc(origin), esc(id),
            crate::html::kv(&[("Payments held", c.locked.to_string()), ("Given back", c.released.to_string()), ("Paid ahead (tickets)", c.prepaid.to_string()),
                              ("Settled", c.settled.to_string()), ("Not paid", failed), ("Credit left", balance_cell(paying, id, c.booked_sats))]))
}

/// How long after the seller's count last grew a connection still counts as moving bytes.
const MOVING_FOR: std::time::Duration = std::time::Duration::from_secs(20);

/// Whether the seller's count of what connection `id` used (`used_msat`) grew within [`MOVING_FOR`] of
/// `now`, by what the page saw on its last looks (it refreshes every few seconds). A connection seen for
/// the first time is not moving yet: its rate shows from the next look on, if it is.
fn use_moving(id: &str, used_msat: u64, now: std::time::Instant) -> bool {
    type Seen = std::sync::Mutex<HashMap<String, (u64, std::time::Instant)>>;
    static SEEN: std::sync::LazyLock<Seen> = std::sync::LazyLock::new(Default::default);
    let mut seen = SEEN.lock().unwrap_or_else(|p| p.into_inner());
    if seen.len() > 512 {
        seen.retain(|_, (_, at)| now.saturating_duration_since(*at) < MOVING_FOR);
    }
    match seen.get_mut(id) {
        Some((last, at)) => {
            if used_msat > *last {
                *last = used_msat;
                *at = now;
            }
            now.saturating_duration_since(*at) < MOVING_FOR
        }
        None => {
            // first seen: dated long enough ago that it reads as idle until the count grows
            seen.insert(id.to_string(), (used_msat, now.checked_sub(MOVING_FOR).unwrap_or(now)));
            false
        }
    }
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
    format!("<p class=\"small\">Used: <span class=\"money\">{}</span> · credit left: <span class=\"money\">{}</span></p>",
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

    /// A visit's Stop closes the open connections with its shop, and only those.
    #[test]
    fn the_open_connections_of_one_shop_are_the_ones_a_visits_stop_ends() {
        let st = json!({"sessions": [{"session": "a", "origin": "http://127.0.0.1:9001", "state": "open"},
                                     {"session": "b", "origin": "http://127.0.0.1:9001", "state": "closed"},
                                     {"session": "c", "origin": "https://other.example", "state": "open"}]});
        assert_eq!(open_ids(&st, Some(&["http://127.0.0.1:9001/".to_string()])), vec!["a".to_string()]);
        assert_eq!(open_ids(&st, None).len(), 2);
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

    /// The shop connection that pays a rental going on says so, not "Open, idle" between the rental's payments.
    #[test]
    fn a_connection_paying_a_rental_says_so() {
        let ctx = crate::app::Ctx { sid: String::new(), csrf: "c".into(), flash: None };
        let shop = xbt402::shop::origin_for(&[7u8; 32]);
        let st = json!({"sessions": [{"session": "s1", "origin": shop, "state": "open"}, {"session": "s2", "origin": "https://films.example", "state": "open"}], "paying": []});
        let html = connections_html(&ctx, &st, &|_| Ok(json!({})), &[], 0, true, &[(format!("{shop}/hashrate"), "Laz Hash".into())]);
        let cards: Vec<&str> = html.split("<section class=\"card live\">").skip(1).collect();
        assert_eq!(cards.len(), 2, "{html}");
        assert!(cards[0].contains("Paying a rental") && cards[0].contains("This connection pays the rental Hashrate from Laz Hash") && !cards[0].contains("Open, idle"), "{html}");
        assert!(cards[1].contains("Open, idle") && !cards[1].contains("rental"), "another shop's stays as it is: {html}");
    }

    /// A connection that runs on credit paid on an earlier one says so, not "Paid so far: 0" beside what it
    /// used; and its rate shows only while the seller's count grows, not as an old average while it is idle.
    #[test]
    fn a_connection_on_earlier_credit_and_its_rate_only_while_bytes_flow() {
        let ctx = crate::app::Ctx { sid: String::new(), csrf: "c".into(), flash: None };
        let paying = |spent: &str| json!([{"session": "on-credit", "spent_msat": spent, "balance_msat": "500000", "answer_open": true}]);
        let card = |spent: &str| session_card(&ctx, "on-credit", "Demo Films", "https://films.example", "open", &Counts::default(), &paying(spent), (0, None), 10.0, None, None);
        let first = card("499000");
        assert!(first.contains("Paid from earlier credit") && !first.contains("Paid so far"), "{first}");
        assert!(!first.contains("a minute"), "first look: not known to be moving: {first}");
        assert!(card("520000").contains("a minute"), "the count grew: bytes are flowing");
        let t = std::time::Instant::now();
        assert!(!use_moving("idle", 5, t) && use_moving("idle", 9, t) && use_moving("idle", 9, t + std::time::Duration::from_secs(5)));
        assert!(!use_moving("idle", 9, t + MOVING_FOR + std::time::Duration::from_secs(1)), "idle since: no rate");
        // nothing used yet: the paid line as before
        let fresh = session_card(&ctx, "fresh", "Demo Films", "https://films.example", "open", &Counts::default(), &json!([]), (0, None), 0.0, None, None);
        assert!(fresh.contains("Paid so far"), "{fresh}");
    }

    /// A player's link shows what it carried: running while it plays, a total after.
    #[test]
    fn a_player_link_shows_its_bytes_and_sats() {
        let per = sat_a_byte("1000 sat a GB");
        assert_eq!(link_use(0, false, false, per), "");
        let playing = link_use(250_000_000, true, true, per);
        assert!(playing.contains("Playing") && playing.contains("250.0 MB so far") && playing.contains("about 250 sat"), "{playing}");
        let paused = link_use(250_000_000, true, false, per);
        assert!(paused.contains(">Open<") && !paused.contains("Playing"), "{paused}");
        let after = link_use(1_400_000_000, false, false, per);
        assert!(after.contains("Carried 1.40 GB, about 1,400 sat") && !after.contains("Playing"), "{after}");
        assert_eq!(bytes_words(800), "800 bytes");
    }

    /// A new player link's flash and its row say the same time left.
    ///
    /// FAILS before (0.2.6): "stops working in 6 hours", then "5 hours left" a second later.
    #[test]
    fn a_new_links_time_left_matches_its_flash() {
        use std::time::Duration;
        assert_eq!(lasts(Duration::from_secs(6 * 3600)), "6 hours");
        assert_eq!(lasts(Duration::from_secs(6 * 3600 - 2)), "6 hours");
        assert_eq!(lasts(Duration::from_secs(5 * 3600 + 1700)), "5 hours");
        assert_eq!(lasts(Duration::from_secs(10 * 60 - 1)), "10 minutes");
        assert_eq!(lasts(Duration::from_secs(45)), "45 seconds");
    }

    /// 0.2.14: on Browse, a shop reached by its key that looks offline (its kept listing stale and no Lightning node
    /// vouching for it, the orphan test shop of 2026-10-30) is folded under "Offline shops (N)", one line a shop with
    /// its services; the others are listed as before.
    ///
    /// FAILS without `split_offline`: the dead shop's services are listed with the live ones.
    #[test]
    fn a_shop_that_looks_offline_is_folded_away_on_browse() {
        let shop = |seller: &str, name: &str, kinds: &[&str]| {
            let sections = kinds.iter().map(|k| xbt402::listing::Section { name: format!("{name} {k}"), kind: k.to_string(), path: format!("/{k}/"),
                prices: json!({"request_msat": "1000"}), items: vec![], licence: String::new(), credits: String::new() }).collect::<Vec<_>>();
            services::from_listing(&xbt402::listing::Listing { name: name.into(), kind: kinds[0].into(), seller: seller.into(), receipt_key: String::new(),
                prices: json!({"request_msat": "1000"}), items: vec![], licence: String::new(), credits: String::new(), updated: String::new(), services: sections })
        };
        let dead = xbt402::shop::origin_for(&[7u8; 32]);
        let mut all = shop(&dead, "StartOS packaging test", &["api", "video"]);
        all.extend(shop("https://live.example", "Live films", &["video"]));
        let days = |seller: &str| (seller == dead).then_some(6);
        let (live, gone) = split_offline(&all, &days);
        assert_eq!((live.len(), gone.len()), (1, 2));
        let html = browse_html(&live, "", Sort::Name, "", &|_| false, &|_| None);
        assert!(html.contains("Live films") && !html.contains("StartOS packaging test"), "{html}");
        let fold = offline_html(&gone, &days);
        assert!(fold.starts_with("<details class=\"card offline-shops\"><summary>Offline shops (1)</summary>"), "{fold}");
        assert!(fold.contains("This listing is 6 days old and no Lightning node vouches for it any more: the shop looks offline."), "{fold}");
        assert_eq!(fold.matches("<li>").count(), 1, "one line a shop: {fold}");
        assert_eq!(fold.matches("./service?seller=").count(), 2, "with each of its services: {fold}");
        assert_eq!(offline_html(&[], &days), "", "nothing offline: no fold");
    }

    /// Each category's count is what its list shows, the box's own shop included; Hashrate with nothing listed leads to
    /// the Hashrate page, where miners for rent are.
    #[test]
    fn a_categorys_count_matches_its_list() {
        let section = xbt402::listing::Section { name: "Laz Hash".into(), kind: "hashrate".into(), path: "/hashrate/".into(),
            prices: json!({"request_msat": "40000"}), items: vec![], licence: String::new(), credits: String::new() };
        let l = xbt402::listing::Listing { name: "Box".into(), kind: "hashrate".into(), seller: "https://box.example".into(), receipt_key: String::new(),
            prices: section.prices.clone(), items: vec![], licence: String::new(), credits: String::new(), updated: String::new(), services: vec![section] };
        let all = services::from_listing(&l);
        for own in [false, true] {
            let html = browse_html(&all, "hashrate", Sort::Name, "", &|_| own, &|_| None);
            assert!(html.contains("Hashrate <span class=\"count\">1</span>"), "{html}");
            assert_eq!(html.matches("class=\"card service-card\"").count(), 1, "{html}");
        }
        let html = browse_html(&all, "data", Sort::Name, "", &|_| false, &|_| None);
        assert!(html.contains("No services in this category yet"), "{html}");
        let none: Vec<Service> = vec![Service { kind: Kind::Ai, ..all[0].clone() }];
        let html = browse_html(&none, "hashrate", Sort::Name, "", &|_| false, &|_| None);
        assert!(html.contains("Miners for rent are listed on the <a href=\"./hashrate\">Hashrate</a> page") && !html.contains("No services in this category"), "{html}");
    }

    /// Every kind has its icon before its name, on its chip and on its cards' pill, hidden from screen readers; All has none.
    #[test]
    fn each_kind_has_its_icon_on_its_chip_and_its_cards() {
        let section = xbt402::listing::Section { name: "My miners".into(), kind: "hashrate".into(), path: "/hashrate/".into(),
            prices: json!({"request_msat": "40000"}), items: vec![], licence: String::new(), credits: String::new() };
        let l = xbt402::listing::Listing { name: "Box".into(), kind: "hashrate".into(), seller: "https://box.example".into(), receipt_key: String::new(),
            prices: section.prices.clone(), items: vec![], licence: String::new(), credits: String::new(), updated: String::new(), services: vec![section] };
        let all = services::from_listing(&l);
        let html = browse_html(&all, "", Sort::Name, "", &|_| false, &|_| None);
        for (icon, words) in [("🤖", "AI"), ("⛏️", "Hashrate"), ("🔒", "VPN"), ("📁", "Files"), ("📊", "Data &amp; APIs"), ("🌐", "Web apps")] {
            assert!(html.contains(&format!("<span class=\"icon\" aria-hidden=\"true\">{icon}</span>{words}")), "{words}: {html}");
        }
        assert!(html.contains("aria-current=\"page\">All <span class=\"count\">"), "{html}");
        assert!(html.contains("<span class=\"pill cat-hashrate\"><span class=\"icon\" aria-hidden=\"true\">⛏️</span>Hashrate</span>"), "{html}");
    }

    #[test]
    fn hashrate_shows_in_its_own_category_and_leads_to_rent_hashrate() {
        let section = xbt402::listing::Section { name: "My miners".into(), kind: "hashrate".into(), path: "/hashrate/".into(),
            prices: json!({"request_msat": "40000"}), items: vec![], licence: String::new(), credits: String::new() };
        let l = xbt402::listing::Listing { name: "Box".into(), kind: "hashrate".into(), seller: "https://box.example".into(), receipt_key: String::new(),
            prices: section.prices.clone(), items: vec![], licence: String::new(), credits: String::new(), updated: String::new(), services: vec![section] };
        let all = services::from_listing(&l);
        assert_eq!((all[0].kind, all[0].price_text.as_str()), (Kind::Hashrate, services::HASHRATE_PRICE_WORDS));
        let html = browse_html(&all, "hashrate", Sort::Name, "", &|_| false, &|_| None);
        assert!(html.contains("cat-hashrate") && html.contains("Rent miners by the piece of work") && html.contains("href=\"./hashrate\""), "{html}");
        assert!(html.contains("Live price on the Hashrate page") && !html.contains("40 sat"), "{html}");
        let page = service_html(&all[0], false, "x");
        assert!(page.contains("href=\"./hashrate\"") && !page.contains("40 sat"), "{page}");
    }

    /// A hashrate seller on Browse shows what its live offer asks, as the Hashrate page says it; with no offer
    /// of that seller known, no price at all. A services file saved by 0.2.11 keeps the listing's price: not shown.
    ///
    /// FAILS before: Browse said "40 sat a piece of work", from the listing, beside a live offer asking 404 sats.
    #[test]
    fn a_hashrate_card_shows_the_live_offer_not_the_listing_price() {
        let old = Service { name: "Lazarus Stream: Laz Hash".into(), kind: Kind::Hashrate, seller: "https://stream.example".into(),
            price_text: "40 sat a piece of work".into(), prices: json!({"request_msat": "40000"}), items: vec![], address: String::new(),
            app: String::new(), app_base: String::new() };
        let all = vec![old];
        let offers = json!({"offers": [
            {"payUrl": "https://other.example/hashrate/", "priceMsat": 1000, "sliceWork": 35_184_372_088_832u64},
            {"payUrl": "https://stream.example/hashrate/", "priceMsat": 404_000, "sliceWork": 35_184_372_088_832u64}]});
        let live = |seller: &str| crate::app::hashrate::live_offer_words(&offers, seller);
        let html = browse_html(&all, "hashrate", Sort::Name, "", &|_| false, &live);
        assert!(html.contains("About 41,337 sats an hour for 1 TH/s (404 sats a piece of work)") && !html.contains("40 sat a piece"), "{html}");
        // no offer of that seller seen: no price
        let html = browse_html(&all, "hashrate", Sort::Name, "", &|_| false, &|_| None);
        assert!(html.contains("Live price on the Hashrate page") && !html.contains("40 sat"), "{html}");
        assert_eq!(crate::app::hashrate::live_offer_words(&serde_json::Value::Null, "https://stream.example"), None);
    }

    /// Two services list the same file at different prices: the Download and the player's link carry
    /// the service the buyer chose, and the relay takes that one's prices; a service with no listed
    /// price says so.
    ///
    /// FAILS before: the file was found as the first service that lists it, whatever the buyer chose.
    #[test]
    fn a_file_is_paid_at_the_price_of_the_service_the_buyer_chose() {
        let url = "https://box.example/files/a.mkv";
        let item = services::Item { title: "A".into(), year: String::new(), url: url.into(), credit: "1 GiB".into() };
        let svc = |name: &str, byte_msat: u64| Service { name: name.into(), kind: Kind::Files, seller: "https://box.example".into(),
            price_text: "1 sat a MiB".into(), prices: json!({"byte_msat": byte_msat, "per_bytes": 1_048_576}), items: vec![item.clone()],
            address: String::new(), app: String::new(), app_base: String::new() };
        let (cheap, dear) = (svc("Cheap", 1_000), svc("Dear", 9_000));
        let all = vec![cheap.clone(), dear.clone()];
        assert_ne!(cheap.id(), dear.id());
        let (chosen, _) = services::find_item_of(&all, &dear.id(), url).unwrap();
        assert_eq!(chosen.price_ceiling(), dear.price_ceiling(), "the chosen one, not the first that lists the file");
        assert!(services::download_src("tok", &dear.id(), url).unwrap().starts_with(&format!("./s/~tok.{}/", dear.id())));
        let links = crate::relay::RelayLinks::new(std::time::Duration::from_secs(60));
        let t = links.create_for(url, &dear.id());
        assert_eq!(links.service_of(&t).as_deref(), Some(dear.id().as_str()));
        // with no listed price, the page says so
        let ctx = crate::app::Ctx { sid: String::new(), csrf: "c".into(), flash: None };
        let mut plain = cheap.clone();
        plain.prices = serde_json::Value::Null;
        assert!(files_html(&ctx, &plain, false, "http://x/", &|_| vec![]).contains("no listed price"));
        assert!(!files_html(&ctx, &cheap, false, "http://x/", &|_| vec![]).contains("no listed price"));
    }

    /// A service chosen from a listing keeps the listing's prices, through the services file, as
    /// the ceiling the app pays it at; one not from a listing has none.
    #[test]
    fn a_service_keeps_its_listings_prices_as_its_price_ceiling() {
        let section = xbt402::listing::Section { name: "Films".into(), kind: "files".into(), path: "/files/".into(),
            prices: json!({"request_msat": "0", "byte_msat": 1000, "per_bytes": 1_048_576}), items: vec![], licence: String::new(), credits: String::new() };
        let l = xbt402::listing::Listing { name: "Box".into(), kind: "files".into(), seller: "https://box.example".into(), receipt_key: String::new(),
            prices: section.prices.clone(), items: vec![], licence: String::new(), credits: String::new(), updated: String::new(), services: vec![section] };
        let all = services::from_listing(&l);
        let want = xbt402::listing::price_ceiling(&l.prices);
        assert_eq!(all[0].price_ceiling(), Some(want.clone()));
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("services.json");
        services::save(&p, &all).unwrap();
        let back = services::load(&p).unwrap();
        assert_eq!(back[0].price_ceiling(), Some(want), "kept through the file");
        let mut plain = back[0].clone();
        plain.prices = serde_json::Value::Null;
        assert_eq!(plain.price_ceiling(), None);
    }
}
