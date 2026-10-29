//! The AI page: the address programs on the owner's network use for AI (the connector's
//! OpenAI-compatible endpoint), the keys those programs use, and the sellers requests go to.
//!
//! It writes the sellers file the endpoint reads (`XBT_UI_AI_SELLERS`): the AI services on the
//! Sellers page, each with its route and prices from the seller's signed listing, and the owner's
//! pinned and blocked sellers. It makes, limits and revokes AI keys in the credential store it
//! shares with local links (`XBT_UI_CREDENTIALS`). It only reads the endpoint's record of the
//! sellers' health (`XBT_UI_AI_STATE`).
//!
//! A new key is shown once, in the answer to the form that made it (`Cache-Control: no-store`),
//! and kept only as its hash: never in the session, a flash or a log.

use std::collections::HashMap;
use std::path::Path;

use lightning_stream::credentials::{self, Entry, Kind, Store};
use serde_json::{json, Value};

use super::{App, Ctx};
use crate::html::{esc, sats};
use crate::server::Resp;
use crate::services::{self, Service};

/// The sellers file as the endpoint reads it: each AI service's name, route and prices, and the
/// owner's pins and blocks.
fn read_sellers(path: &Path) -> Value {
    std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_else(|| json!({"sellers": [], "pinned": [], "blocked": []}))
}

fn write_json(path: &Path, v: &Value) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let body = serde_json::to_vec_pretty(v).map_err(|e| e.to_string())?;
    credentials::write_file(path, &body, false).map_err(|e| format!("{}: {e}", path.display()))
}

fn names(v: &Value, k: &str) -> Vec<String> {
    v.get(k).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect()
}

/// The route an AI service is reached at, ending in `/`.
fn route_of(s: &Service) -> String {
    let a = s.address();
    if a.ends_with('/') { a.to_string() } else { format!("{a}/") }
}

/// The sellers' entries for the endpoint: each AI service, with the prices of its section in the
/// seller's signed listing (the listing names the route's path). A seller whose listing cannot be
/// read now keeps the prices it had.
pub fn sellers_entries(ai: &[Service], old: &Value, mut get: impl FnMut(&str) -> Result<xbt402::listing::Page, String>) -> (Vec<Value>, Vec<String>) {
    let mut out = vec![];
    let mut problems = vec![];
    for s in ai {
        let route = route_of(s);
        let prices = match xbt402::listing::fetch(&s.seller, &mut get) {
            Ok(l) => {
                let path = route.strip_prefix(&services::http_origin(&s.seller).unwrap_or_default()).unwrap_or("/").to_string();
                l.services.iter().find(|x| x.kind == "ai" && (x.path == path || format!("{}/", x.path.trim_end_matches('/')) == path)).map(|x| x.prices.clone())
            }
            Err(e) => {
                problems.push(format!("{}: {e}", s.name));
                None
            }
        };
        let prices = prices.or_else(|| old.get("sellers").and_then(Value::as_array).into_iter().flatten()
            .find(|o| o["route"].as_str() == Some(route.as_str())).map(|o| o["prices"].clone()));
        let Some(prices) = prices else { continue };
        out.push(json!({"name": s.name, "route": route, "prices": prices, "max_output": 0}));
    }
    (out, problems)
}

fn health_html(state: &Value, name: &str) -> String {
    let h = &state["health"][name];
    let ok = h["ok"].as_u64().unwrap_or(0);
    let failed = h["failed"].as_u64().unwrap_or(0);
    if ok + failed == 0 {
        return "<span class=\"small\">not used yet</span>".into();
    }
    let mut ttft: Vec<u64> = h["ttft_ms"].as_array().into_iter().flatten().filter_map(Value::as_u64).collect();
    ttft.sort_unstable();
    let speed = ttft.get(ttft.len() / 2).map(|m| format!(", first words in about {:.1} s", *m as f64 / 1000.0)).unwrap_or_default();
    let tag = if h["fails_in_a_row"].as_u64().unwrap_or(0) >= 3 { "<span class=\"tag warn\">resting</span> " } else if failed == 0 { "<span class=\"tag ok\">answering</span> " } else { "" };
    format!("{tag}<span class=\"small\">{ok} answered, {failed} failed{speed}</span>")
}

fn key_row(ctx: &Ctx, e: &Entry, today: u64) -> String {
    let state = if e.paused || e.left_msat(today) == 0 { "<span class=\"tag warn\">at its limit</span>" } else { "<span class=\"tag ok\">active</span>" };
    let day = e.per_day_sats.map(|d| format!("<div class=\"small\">at most {} a day</div>", sats(d as i64))).unwrap_or_default();
    format!(
        "<tr><td>{} {state}<div class=\"small\">made {}</div></td><td>{} <span class=\"small\">of {}</span>{day}</td>\
         <td><details><summary>Change the limit</summary><form method=\"post\" action=\"./ai\" class=\"stack\">{}\
         <input type=\"hidden\" name=\"do\" value=\"limit\"><input type=\"hidden\" name=\"id\" value=\"{}\">\
         <label>Limit (sats in all)<input name=\"limit_sats\" type=\"number\" min=\"0\" step=\"1\" value=\"{}\"></label>\
         <label>At most a day (sats, optional)<input name=\"per_day_sats\" type=\"number\" min=\"0\" step=\"1\" value=\"{}\"></label>\
         <button type=\"submit\">Save the limit</button></form></details>\
         <form method=\"post\" action=\"./ai\" class=\"inline\">{}<input type=\"hidden\" name=\"do\" value=\"revoke\"><input type=\"hidden\" name=\"id\" value=\"{}\">\
         <button class=\"danger\" type=\"submit\">Revoke</button></form></td></tr>",
        esc(&e.name), crate::html::utc(e.created as i64), sats((e.spent_msat / 1000) as i64), sats(e.limit_sats as i64),
        App::csrf_input(ctx), esc(&e.id), e.limit_sats, e.per_day_sats.map(|d| d.to_string()).unwrap_or_default(), App::csrf_input(ctx), esc(&e.id))
}

impl App {
    fn ai_services(&self) -> Vec<Service> {
        self.file_services().unwrap_or_default().into_iter().filter(|s| s.kind == services::Kind::Ai).collect()
    }

    /// Writes the sellers file from the AI services and their listings, keeping the owner's pins
    /// and blocks. Returns what could not be read, in words.
    fn ai_write_sellers(&self) -> Result<Vec<String>, String> {
        let old = read_sellers(&self.cfg.ai.sellers);
        let (sellers, problems) = sellers_entries(&self.ai_services(), &old, crate::app::services_page::get_page);
        write_json(&self.cfg.ai.sellers, &json!({"sellers": sellers, "pinned": names(&old, "pinned"), "blocked": names(&old, "blocked")}))?;
        Ok(problems)
    }

    pub(crate) fn ai_page(&self, ctx: &Ctx) -> Resp {
        // the first visit writes the sellers file, so the endpoint has sellers without a click
        if !self.cfg.ai.sellers.exists() && !self.ai_services().is_empty() {
            let _ = self.ai_write_sellers();
        }
        let body = self.ai_html(ctx, None);
        self.page("AI", ctx, body)
    }

    fn ai_html(&self, ctx: &Ctx, made: Option<(&str, &str)>) -> String {
        let mut b = String::from("<p class=\"lead\">Use AI models from the sellers you allowed, in any program on your network that works with \
            OpenAI's API: Open WebUI, coding agents, your own scripts. Each request goes to the cheapest seller that answers, and is paid by the \
            word as it arrives, within your spending rules.</p>");
        // the address
        match &self.cfg.ai.endpoint {
            None => b.push_str("<section class=\"card\"><h2>Your AI address</h2><p class=\"empty\">This box does not serve an AI address yet.</p>\
                <details><summary>Technical details</summary><p>The connector serves it when <code>LS_AI_LISTEN</code> is set, and this page shows it \
                when <code>XBT_UI_AI_ENDPOINT</code> names it.</p></details></section>"),
            Some(ep) => b.push_str(&format!(
                "<section class=\"card\"><h2>Your AI address</h2>\
                 <label>Address<input id=\"ai-endpoint\" class=\"mono\" readonly value=\"{}\"></label>\
                 <div class=\"row\"><button type=\"button\" data-copy=\"ai-endpoint\">Copy</button></div>\
                 <p class=\"hint\">In the program's settings, put this address where it asks for the OpenAI \"base URL\" or \"API base\", and a key \
                 from below where it asks for an \"API key\". Then pick a model from the list it shows.</p></section>", esc(ep))),
        }
        if let Some((name, key)) = made {
            b.push_str(&format!(
                "<section class=\"card\"><h2>Key made: {}</h2>\
                 <p class=\"hint warn\">This is the only time the key is shown. Copy it into the program now; nobody can show it again, and anyone \
                 who has it can spend up to its limit. If it is lost, revoke it and make a new one.</p>\
                 <label>Key<input id=\"ai-key\" class=\"mono\" readonly value=\"{}\"></label>\
                 <div class=\"row\"><button type=\"button\" data-copy=\"ai-key\">Copy</button></div></section>", esc(name), esc(key)));
        }
        b.push_str(&self.ai_keys_html(ctx));
        b.push_str(&self.ai_sellers_html(ctx));
        b
    }

    fn ai_keys_html(&self, ctx: &Ctx) -> String {
        let today = credentials::day_of(credentials::now());
        let store = match Store::open(&self.cfg.ai.credentials) {
            Ok(s) => s,
            Err(e) => return Self::error_box(&format!("The store of keys cannot be read: {e}")),
        };
        let keys: Vec<&Entry> = store.entries.iter().filter(|e| e.kind == Kind::AiKey && !e.revoked).collect();
        let rows: String = keys.iter().map(|e| key_row(ctx, e, today)).collect();
        let list = if keys.is_empty() {
            "<p class=\"empty\">No key yet. Make one for each program, so each has its own limit and can be revoked on its own.</p>".to_string()
        } else {
            format!("<div class=\"scroll\"><table><thead><tr><th>Program</th><th>Spent</th><th></th></tr></thead>\
                     <tbody>{rows}</tbody></table></div><p class=\"small\">A key at its limit pays nothing more until you raise the limit. \
                     Revoking takes effect at once.</p>")
        };
        format!("<section class=\"card\"><h2>Keys</h2>{list}\
                 <form method=\"post\" action=\"./ai\" class=\"stack\">{}<input type=\"hidden\" name=\"do\" value=\"make\">\
                 <label>Program (for you)<input name=\"name\" maxlength=\"64\" placeholder=\"Open WebUI\" required></label>\
                 <label>Limit (sats in all)<input name=\"limit_sats\" type=\"number\" min=\"1\" step=\"1\" value=\"2000\" required></label>\
                 <details><summary>Advanced</summary><label>At most a day (sats, optional)<input name=\"per_day_sats\" type=\"number\" min=\"1\" step=\"1\"></label></details>\
                 <button type=\"submit\">Make a key</button></form></section>", App::csrf_input(ctx))
    }

    fn ai_sellers_html(&self, ctx: &Ctx) -> String {
        let ai = self.ai_services();
        if ai.is_empty() {
            return "<section class=\"card\"><h2>Sellers</h2><p class=\"empty\">No seller of AI is on your list yet.</p>\
                    <p>Add one on <a href=\"./services\">Sellers</a>, or find one in <a href=\"./browse?kind=ai\">Browse</a>.</p></section>".into();
        }
        let sellers = read_sellers(&self.cfg.ai.sellers);
        let state: Value = std::fs::read(&self.cfg.ai.state).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
        let (pinned, blocked) = (names(&sellers, "pinned"), names(&sellers, "blocked"));
        let mut rows = String::new();
        for s in &ai {
            let allowed = self.seller_allowed(&s.seller);
            let listed = sellers["sellers"].as_array().into_iter().flatten().any(|o| o["name"].as_str() == Some(s.name.as_str()));
            let (is_pinned, is_blocked) = (pinned.contains(&s.name), blocked.contains(&s.name));
            let status = if !allowed {
                "<span class=\"tag warn\">not allowed</span> <a class=\"small\" href=\"./services\">Allow on Sellers</a>".to_string()
            } else if is_blocked {
                "<span class=\"tag bad\">blocked</span>".to_string()
            } else if !listed {
                "<span class=\"tag warn\">prices not read</span>".to_string()
            } else {
                health_html(&state, &s.name)
            };
            let button = |what: &str, words: &str, class: &str| format!(
                "<form method=\"post\" action=\"./ai\" class=\"inline\">{}<input type=\"hidden\" name=\"do\" value=\"{what}\">\
                 <input type=\"hidden\" name=\"seller\" value=\"{}\"><button{class} type=\"submit\">{words}</button></form>",
                App::csrf_input(ctx), esc(&s.name));
            let pin = if is_pinned { button("unpin", "Unpin", "") } else { button("pin", "Prefer", "") };
            let block = if is_blocked { button("unblock", "Unblock", "") } else { button("block", "Block", " class=\"danger\"") };
            rows.push_str(&format!("<tr><td>{}{}</td><td>{}</td><td>{status}</td><td>{pin} {block}</td></tr>",
                                   esc(&s.name), if is_pinned { " <span class=\"tag ok\">preferred</span>" } else { "" }, esc(&s.price_text)));
        }
        format!("<section class=\"card\"><h2>Sellers</h2><div class=\"scroll\"><table><thead><tr><th>Seller</th><th>Price</th><th>State</th><th></th></tr>\
                 </thead><tbody>{rows}</tbody></table></div>\
                 <p class=\"small\">Preferred sellers are tried first. A blocked seller is never asked. A seller that fails three times in a row rests \
                 for five minutes.</p>\
                 <form method=\"post\" action=\"./ai\" class=\"inline\">{}<input type=\"hidden\" name=\"do\" value=\"refresh\">\
                 <button type=\"submit\">Read the sellers' prices again</button></form></section>", App::csrf_input(ctx))
    }

    pub(crate) fn ai_post(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let g = |k: &str| f.get(k).map(|v| v.trim().to_string()).unwrap_or_default();
        let today = credentials::day_of(credentials::now());
        let n = |k: &str| g(k).parse::<u64>().ok();
        // every change under the store's lock (the endpoint books spend in it at the same time)
        let store = |f: &dyn Fn(&mut Store) -> Result<String, String>| -> Result<String, String> {
            if let Some(dir) = self.cfg.ai.credentials.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            Store::update(&self.cfg.ai.credentials, f).map_err(|e| format!("The store of keys cannot be changed: {e}"))?
        };
        let prefs = |name: &str, list: &str, add: bool| -> Result<String, String> {
            let mut v = read_sellers(&self.cfg.ai.sellers);
            let mut l = names(&v, list);
            l.retain(|x| x != name);
            if add {
                l.push(name.to_string());
            }
            v[list] = json!(l);
            write_json(&self.cfg.ai.sellers, &v)?;
            Ok(String::new())
        };
        let r: Result<String, String> = match g("do").as_str() {
            "make" => {
                let name: String = g("name").chars().take(64).collect();
                let Some(limit) = n("limit_sats").filter(|l| *l > 0) else {
                    self.flash(ctx, false, "Give the key a limit of at least 1 sat.");
                    return Resp::redirect("./ai");
                };
                if name.is_empty() {
                    self.flash(ctx, false, "Name the program the key is for.");
                    return Resp::redirect("./ai");
                }
                let made = std::cell::RefCell::new(String::new());
                match store(&|s| { *made.borrow_mut() = s.make(Kind::AiKey, &name, limit, n("per_day_sats").filter(|d| *d > 0), None).1; Ok(String::new()) }) {
                    Ok(_) => {
                        let key = made.into_inner();
                        let body = self.ai_html(ctx, Some((&name, &key)));
                        return self.page("AI", ctx, body).header("Cache-Control", "no-store");
                    }
                    Err(e) => Err(e),
                }
            }
            "revoke" => store(&|s| { s.revoke(&g("id")); Ok("Revoked: that key pays nothing from now on.".into()) }),
            "limit" => {
                let limit = n("limit_sats").unwrap_or(0);
                store(&|s| { s.set_limits(&g("id"), limit, n("per_day_sats").filter(|d| *d > 0), today); Ok(format!("The key's limit is {} now.", sats(limit as i64))) })
            }
            "pin" => prefs(&g("seller"), "pinned", true).map(|_| format!("{} is preferred: it is tried first.", g("seller"))),
            "unpin" => prefs(&g("seller"), "pinned", false).map(|_| format!("{} is no longer preferred.", g("seller"))),
            "block" => prefs(&g("seller"), "blocked", true).and_then(|_| prefs(&g("seller"), "pinned", false))
                .map(|_| format!("{} is blocked: no request goes to it.", g("seller"))),
            "unblock" => prefs(&g("seller"), "blocked", false).map(|_| format!("{} may be asked again.", g("seller"))),
            "refresh" => self.ai_write_sellers().map(|p| if p.is_empty() { "The sellers' prices are read again; the AI address uses them within five minutes.".into() }
                                                          else { format!("Read again, except: {}.", p.join("; ")) }),
            _ => Err("Unknown action.".into()),
        };
        match r {
            Ok(m) if m.is_empty() => {}
            Ok(m) => self.flash(ctx, true, m),
            Err(e) => self.flash(ctx, false, e),
        }
        Resp::redirect("./ai")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::Item;

    fn ai(name: &str, seller: &str, address: &str) -> Service {
        Service { name: name.into(), kind: services::Kind::Ai, seller: seller.into(), price_text: "10 sat per 1,000 tokens".into(), items: Vec::<Item>::new(),
                  address: address.into() }
    }

    #[test]
    fn a_route_ends_in_a_slash() {
        assert_eq!(route_of(&ai("a", "https://s.example", "https://s.example/ai")), "https://s.example/ai/");
        assert_eq!(route_of(&ai("a", "https://s.example", "")), "https://s.example/");
    }

    #[test]
    fn a_seller_whose_listing_cannot_be_read_keeps_its_old_prices_and_one_never_read_is_left_out() {
        let old = json!({"sellers": [{"name": "Old", "route": "https://old.example/ai/", "prices": {"per_1k_output_msat": 7000}}]});
        let services = [ai("Old", "https://old.example", "https://old.example/ai"), ai("New", "https://new.example", "https://new.example/ai")];
        let (out, problems) = sellers_entries(&services, &old, |_| Err("offline".into()));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["prices"]["per_1k_output_msat"], 7000);
        assert_eq!(problems.len(), 2);
    }
}
