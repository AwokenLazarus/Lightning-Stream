//! Browse, the player and the live connections page.
//!
//! Browse reads the services file. The player points a `<video>` at the connector
//! (`XBT_UI_CONNECTOR` + `/s/` + the item URL). Stopping is a POST: this process asks the signer
//! to `ticket_stop` the open session whose origin is that seller. Connections lists every session
//! `ticket_status` still has open and reloads itself every 4 seconds (a meta refresh: the page's
//! script policy does not allow an inline script).
use std::collections::HashMap;

use serde_json::{json, Value};

use super::{ok_of, reason_of, App, Ctx};
use crate::html::{self, esc, int, sats};
use crate::server::Resp;
use crate::services::{self, Kind, Service, Sort};

const REFRESH: &str = "<meta http-equiv=\"refresh\" content=\"4\">";

impl App {
    pub(crate) fn browse(&self, ctx: &Ctx, q: &HashMap<String, String>) -> Resp {
        let kind = q.get("kind").map(String::as_str).unwrap_or("");
        let sort = Sort::parse(q.get("sort").map(String::as_str).unwrap_or(""));
        let body = match self.services() {
            Ok(all) => browse_html(&all, kind, sort),
            Err(e) => format!("{}{}", Self::error_box(&e), empty_how()),
        };
        self.html_page("Browse", ctx, &body, "")
    }

    pub(crate) fn play(&self, ctx: &Ctx, q: &HashMap<String, String>) -> Resp {
        let item_url = q.get("item").map(String::as_str).unwrap_or("");
        let body = match self.services() {
            Ok(all) => match services::find_item(&all, item_url) {
                Some((service, item)) => player_html(ctx, &self.cfg.connector, service, item),
                None if item_url.is_empty() => "<p>Choose a video on <a href=\"./browse\">Browse</a>. The player opens it through the connector, \
                                                 which pays the seller as it streams.</p>".into(),
                None => format!("{}<p><a href=\"./browse\">Back to Browse</a></p>", Self::error_box("That item is not in the services file.")),
            },
            Err(e) => format!("{}{}", Self::error_box(&e), empty_how()),
        };
        self.html_page("Player", ctx, &body, "")
    }

    pub(crate) fn connections(&self, ctx: &Ctx) -> Resp {
        let body = match self.call("ticket_status", json!({})) {
            Ok(st) => connections_html(ctx, &st, &|id| self.call("ticket_status", json!({"session": id}))),
            Err(e) => Self::error_box(&e),
        };
        self.html_page("Connections", ctx, &body, REFRESH)
    }

    pub(crate) fn play_stop(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let item_url = f.get("item").map(|s| s.trim().to_string()).unwrap_or_default();
        let back = format!("./play?item={}", services::urlenc(&item_url));
        let origins = match self.services() {
            Ok(all) => match services::find_item(&all, &item_url) {
                Some((service, item)) => services::pay_origins(service, item),
                None => {
                    self.flash(ctx, false, "That item is not in the services file.");
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
                self.flash(ctx, false, "No open session with that id.");
                return Resp::redirect("./connections");
            }
        };
        self.flash_stops(ctx, &ids, "");
        Resp::redirect("./connections")
    }

    fn services(&self) -> Result<Vec<Service>, String> {
        match &self.cfg.services_file {
            Some(p) => services::load(p),
            None => Ok(Vec::new()),
        }
    }

    fn html_page(&self, title: &str, ctx: &Ctx, body: &str, head: &str) -> Resp {
        Resp::html(200, html::page_head(title, &self.nav(title, &ctx.csrf, true), ctx.flash.clone(), body, head))
    }

    fn flash_stops(&self, ctx: &Ctx, ids: &[String], seller: &str) {
        if ids.is_empty() {
            let who = if seller.is_empty() { "Nothing is open.".into() } else { format!("No open session with {seller}.") };
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
            self.flash(ctx, true, format!("Cut {stopped} connection{}.", if stopped == 1 { "" } else { "s" }));
        } else if stopped == 0 {
            self.flash(ctx, false, errs.join(" "));
        } else {
            self.flash(ctx, false, format!("Cut {stopped}; {} could not be cut: {}", errs.len(), errs.join(" ")));
        }
    }
}

fn empty_how() -> String {
    "<div class=\"card\"><p class=\"empty\">No services yet.</p>\
     <p>Point <code>XBT_UI_SERVICES</code> at a JSON file: a list of services, each with a name, a kind \
     (<code>video</code>, <code>files</code> or <code>api</code>), the seller's URL, a price in words, and items \
     (title, year, url, credit). The wallet UI crate ships <code>examples/services.example.json</code> \
     with three Creative Commons films.</p></div>".into()
}

fn selected(on: bool) -> &'static str {
    if on { " selected" } else { "" }
}

fn browse_html(all: &[Service], kind: &str, sort: Sort) -> String {
    let shown = services::arrange(all.to_vec(), Some(kind), sort);
    let mut b = format!("<form method=\"get\" action=\"./browse\" class=\"row\">\
        <label>Kind<select name=\"kind\">\
        <option value=\"\"{all_on}>All</option>\
        <option value=\"video\"{v}>Video</option>\
        <option value=\"files\"{f}>Files</option>\
        <option value=\"api\"{a}>API</option></select></label>\
        <label>Sort<select name=\"sort\">\
        <option value=\"name\"{by_name}>Name</option>\
        <option value=\"price\"{by_price}>Price</option></select></label>\
        <button type=\"submit\">Apply</button></form>",
        all_on = selected(kind.is_empty() || kind.eq_ignore_ascii_case("all")),
        v = selected(kind.eq_ignore_ascii_case("video")),
        f = selected(kind.eq_ignore_ascii_case("files")),
        a = selected(kind.eq_ignore_ascii_case("api")),
        by_name = selected(sort == Sort::Name),
        by_price = selected(sort == Sort::Price));
    if all.is_empty() {
        b.push_str(&empty_how());
        return b;
    }
    if shown.is_empty() {
        b.push_str("<p class=\"empty\">No services of this kind. Choose another kind, or add one to the services file.</p>");
        return b;
    }
    for s in &shown {
        b.push_str(&format!("<section class=\"card\"><h2>{} <span class=\"tag\">{}</span></h2><p>{}</p><p class=\"small\">{}</p>",
                            esc(&s.name), s.kind.as_str(), esc(&s.price_text), esc(&s.seller)));
        if s.items.is_empty() {
            b.push_str("<p class=\"empty\">No items in this service.</p>");
        } else {
            b.push_str("<div class=\"grid\">");
            for item in &s.items {
                let open = if s.kind == Kind::Video {
                    format!("<p><a href=\"./play?item={}\">Play</a></p>", services::urlenc(&item.url))
                } else {
                    format!("<p class=\"small\"><code>{}</code></p>", esc(&item.url))
                };
                b.push_str(&format!("<article class=\"card\"><h3>{} <span class=\"small\">{}</span></h3><p class=\"small\">{}</p>{open}</article>",
                                    esc(&item.title), esc(&item.year), esc(&item.credit)));
            }
            b.push_str("</div>");
        }
        b.push_str("</section>");
    }
    b
}

fn player_html(ctx: &Ctx, connector: &str, service: &Service, item: &services::Item) -> String {
    if service.kind != Kind::Video {
        return format!("<p>{} is a {} item. This player plays video. Files and APIs are listed on \
                        <a href=\"./browse\">Browse</a>.</p><p>{}</p>", esc(&item.title), service.kind.as_str(), esc(&item.credit));
    }
    let src = match services::player_src(connector, &item.url) {
        Ok(s) => s,
        Err(e) => return format!("{}<p><a href=\"./browse\">Back to Browse</a></p>", App::error_box(&e)),
    };
    format!("<h2>{} <span class=\"small\">{}</span></h2>\
             <p class=\"hint\">{} · {}</p>\
             <video controls autoplay src=\"{}\"></video>\
             <p>{}</p>\
             <p class=\"small\">{}</p>\
             <form method=\"post\" action=\"./play\" data-stop-player>\
             {}<input type=\"hidden\" name=\"item\" value=\"{}\">\
             <button class=\"danger\" type=\"submit\">Stop and cut the connection</button></form>\
             <p class=\"small\"><a href=\"./browse\">Back to Browse</a> · <a href=\"./connections\">Connections</a></p>",
            esc(&item.title), esc(&item.year), esc(&service.price_text), esc(&service.name), esc(&src), esc(&item.credit),
            esc(&service.seller), App::csrf_input(ctx), esc(&item.url))
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

fn connections_html(ctx: &Ctx, st: &Value, detail: &dyn Fn(&str) -> Result<Value, String>) -> String {
    let csrf = App::csrf_input(ctx);
    let mut b = format!("<p class=\"hint\">Open sessions, reloaded every 4 seconds. Cutting one asks the signer to stop it: \
                         unused held tickets are cancelled.</p>\
                         <form method=\"post\" action=\"./connections\">{csrf}\
                         <input type=\"hidden\" name=\"all\" value=\"1\"><button class=\"danger\" type=\"submit\">Cut all</button></form>");
    if let Some(e) = st.get("error").and_then(Value::as_str) {
        b.push_str(&App::error_box(e));
    }
    let Some(sessions) = st.get("sessions").and_then(Value::as_array).filter(|a| !a.is_empty()) else {
        b.push_str("<p class=\"empty\">Nothing is open. Play a film from <a href=\"./browse\">Browse</a> and it shows up here.</p>");
        return b;
    };
    b.push_str("<div class=\"scroll\"><table><thead><tr><th>Seller</th><th>Locked</th><th>Released</th><th>Prepaid</th>\
                <th>Settled</th><th>Failed by</th><th>Balance</th><th></th></tr></thead><tbody>");
    let paying = st.get("paying").cloned().unwrap_or(json!([]));
    for s in sessions {
        let id = s.get("session").and_then(Value::as_str).unwrap_or("");
        let origin = s.get("origin").and_then(Value::as_str).unwrap_or("");
        let state = s.get("state").and_then(Value::as_str).unwrap_or("");
        let (counts, err) = match detail(id) {
            Ok(d) => (counts_of(d.get("session_tickets").unwrap_or(&json!([])), num(s.get("stopped_ts"))), None),
            Err(e) => (Counts::default(), Some(e)),
        };
        b.push_str(&session_row(ctx, id, origin, state, &counts, &paying, err.as_deref()));
    }
    b.push_str("</tbody></table></div>");
    b
}

fn session_row(ctx: &Ctx, id: &str, origin: &str, state: &str, c: &Counts, paying: &Value, err: Option<&str>) -> String {
    let cut = if state == "open" && !id.is_empty() {
        format!("<form method=\"post\" action=\"./connections\" class=\"inline\">{}<input type=\"hidden\" name=\"session\" value=\"{}\">\
                 <button class=\"danger\" type=\"submit\">Cut</button></form>", App::csrf_input(ctx), esc(id))
    } else {
        String::new()
    };
    let failed = format!("never sent {}<br>cancelled at stop {}<br>payment failed {}", c.never_sent, c.cancelled_at_stop, c.payment_failed);
    let err = err.map(|e| format!("<div class=\"small\">{}</div>", esc(e))).unwrap_or_default();
    format!("<tr><td>{} <span class=\"tag\">{}</span><br><code class=\"small\">{}</code>{err}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
             <td class=\"small\">{failed}</td><td>{}</td><td>{cut}</td></tr>",
            esc(origin), esc(state), esc(id), c.locked, c.released, c.prepaid, c.settled, balance_cell(paying, id, c.booked_sats))
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
                                url: "https://media.lazarus-xbt.xyz/v?static=true&x=1".into(), credit: "CC <BY>".into() }] };
        let ctx = Ctx { sid: "s".into(), csrf: "tok&1".into(), flash: None };
        let html = player_html(&ctx, "http://127.0.0.1:8480/", &svc, &svc.items[0]);
        assert!(html.contains("src=\"http://127.0.0.1:8480/s/https://media.lazarus-xbt.xyz/v?static=true&amp;x=1\""));
        assert!(html.contains("Stop and cut the connection"));
        assert!(html.contains("value=\"tok&amp;1\""));
        assert!(html.contains("&lt;b&gt;") && html.contains("CC &lt;BY&gt;"));
        assert!(!html.contains("<b>"));
    }
}
