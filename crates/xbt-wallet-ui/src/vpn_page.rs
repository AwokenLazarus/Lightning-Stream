//! The VPN pages: a buyer's devices that go out through other people's exits, and an owner's own
//! exit, if they offer one.
//!
//! The pages write settings files the VPN service reads, in `XBT_UI_VPN_DIR`:
//! - `devices.json`: each device's name, WireGuard public key, tunnel address, limit and policy.
//!   A device's private key is made here, shown once in its config and QR code (in the answer to
//!   the form, `Cache-Control: no-store`), and never kept. Its `exits`: the exits the owner added
//!   from Found on Nostr (*Add this exit*), each its signed announcement, which the service checks
//!   as it checks the ones its relays give, and every device prefers.
//! - `exit.json`: this box's exit, if offered: its kind, what it blocks, its protections, its price.
//!
//! And they read what the service writes, in `XBT_UI_VPN_STATUS_DIR` (the same dir unless set): `endpoint.json` (the WireGuard key devices pair with),
//! `status.json` (each device's exit, use, and why its traffic is blocked, if it is) and
//! `exit-status.json` (bytes the exit carried; counts only).
//!
//! Buyers pay as they use it, by the GB: the words never say "ahead" or "balance".

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;

use base64::Engine;
use serde_json::{json, Value};

use super::{App, Ctx};
use crate::html::esc;
use crate::server::Resp;

fn read(path: &Path) -> Value {
    std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null)
}

/// Writes a settings file the VPN service reads: whole, with the folder's group (the service's) and
/// mode 0640.
fn write(path: &Path, v: &Value) -> Result<(), String> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else {
        return Err(format!("{} is not a file path", path.display()));
    };
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    crate::setup::write_shared(dir, name, &serde_json::to_vec_pretty(v).map_err(|e| e.to_string())?)
}

fn b64(k: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(k)
}

fn key32(s: &str) -> Option<[u8; 32]> {
    base64::engine::general_purpose::STANDARD.decode(s.trim()).ok()?.try_into().ok()
}

/// The first free tunnel address, 10.66.0.2 to 10.66.0.250 (10.66.0.1 is the box).
fn next_ip(devices: &[Value]) -> Option<Ipv4Addr> {
    let used: Vec<&str> = devices.iter().filter_map(|d| d["tunnel_ip"].as_str()).collect();
    (2..=250u8).map(|n| Ipv4Addr::new(10, 66, 0, n)).find(|ip| !used.contains(&ip.to_string().as_str()))
}

/// An exit's price by the GB, in sats (`msat` as the announcement says it).
fn price_words(msat: Option<u64>) -> String {
    match msat {
        None => String::new(),
        Some(0) => "free".into(),
        Some(m) => format!("{} sat/GB", crate::html::group3(m.div_ceil(1000))),
    }
}

/// A device's policy in plain words.
pub fn policy_words(p: &Value) -> String {
    let mut w = vec![match p["kind"].as_str() {
        Some("filtered") => "Filtered exits only".to_string(),
        Some("any") => "Any exit".to_string(),
        _ => "Private exits".to_string(),
    }];
    if let Some(c) = p["country"].as_str().filter(|c| !c.is_empty()) {
        w.push(format!("in {}", c.to_ascii_uppercase()));
    }
    if p["two_hop"].as_bool() == Some(true) {
        w.push("two hops".into());
    }
    if let Some(n) = p["max_sat_per_gb"].as_u64() {
        w.push(format!("up to {n} sats a GB"));
    }
    if let Some(n) = p["min_mbit"].as_u64() {
        w.push(format!("at least {n} Mbit/s"));
    }
    if p["no_logs"].as_bool() == Some(true) {
        w.push("no logs".into());
    }
    w.push(match p["mode"].as_str() {
        Some("sticky") => "one exit at a time".to_string(),
        Some("spread") => "spread over exits".to_string(),
        _ => "the best exit".to_string(),
    });
    w.join(" · ")
}

/// A policy from the form's fields. Unknown or empty fields leave that requirement out.
fn policy_from(g: &dyn Fn(&str) -> String) -> Value {
    let num = |k: &str| g(k).parse::<u64>().ok().filter(|n| *n > 0);
    let country: String = g("country").chars().filter(char::is_ascii_alphabetic).take(2).collect::<String>().to_ascii_uppercase();
    json!({
        "kind": match g("kind").as_str() { "filtered" => "filtered", "any" => "any", _ => "private" },
        "country": (country.len() == 2).then_some(country),
        "two_hop": g("two_hop") == "on",
        "max_sat_per_gb": num("max_sat_per_gb"),
        "min_mbit": num("min_mbit"),
        "no_logs": g("no_logs") == "on",
        "mode": match g("mode").as_str() { "sticky" => "sticky", "spread" => "spread", _ => "best" },
    })
}

fn policy_fields(p: &Value) -> String {
    let sel = |k: &str, v: &str| if p[k].as_str() == Some(v) { " selected" } else { "" };
    let chk = |k: &str| if p[k].as_bool() == Some(true) { " checked" } else { "" };
    let num = |k: &str| p[k].as_u64().map(|n| n.to_string()).unwrap_or_default();
    format!(
        "<label>Kind of exit<select name=\"kind\"><option value=\"private\"{}>Private: the exit cannot see which sites (recommended)</option>\
         <option value=\"filtered\"{}>Filtered: the exit blocks some sites, and sees site names</option><option value=\"any\"{}>Either</option></select></label>\
         <label>Country (two letters, optional)<input name=\"country\" maxlength=\"2\" placeholder=\"DE\" value=\"{}\"></label>\
         <label class=\"check\"><input type=\"checkbox\" name=\"two_hop\"{}> Two hops: the exit never learns this device's address (slower)</label>\
         <details><summary>Advanced</summary>\
         <label>Most it may cost (sats a GB, optional)<input name=\"max_sat_per_gb\" type=\"number\" min=\"1\" step=\"1\" value=\"{}\"></label>\
         <label>Slowest exit it may use (Mbit/s, optional)<input name=\"min_mbit\" type=\"number\" min=\"1\" step=\"1\" value=\"{}\"></label>\
         <label class=\"check\"><input type=\"checkbox\" name=\"no_logs\"{}> Only exits that say they keep no logs</label>\
         <label>Which exit<select name=\"mode\"><option value=\"best\"{}>The best one, switching new connections when a better one appears</option>\
         <option value=\"sticky\"{}>One exit until it fails (for sites that dislike a changing address)</option>\
         <option value=\"spread\"{}>Spread over several exits, each site on one</option></select></label></details>",
        sel("kind", "private"), sel("kind", "filtered"), sel("kind", "any"), esc(p["country"].as_str().unwrap_or("")), chk("two_hop"),
        num("max_sat_per_gb"), num("min_mbit"), chk("no_logs"), sel("mode", "best"), sel("mode", "sticky"), sel("mode", "spread"),
    )
}

impl App {
    fn vpn_devices(&self) -> Vec<Value> {
        read(&self.cfg.vpn.dir.join("devices.json"))["devices"].as_array().cloned().unwrap_or_default()
    }

    /// The WireGuard key devices pair with, as the VPN service wrote it.
    fn vpn_endpoint_key(&self) -> Option<[u8; 32]> {
        read(&self.cfg.vpn.status_dir.join("endpoint.json"))["public_key"].as_str().and_then(key32)
    }

    pub(crate) fn vpn_page(&self, ctx: &Ctx, q: &HashMap<String, String>) -> Resp {
        let body = self.vpn_html(ctx, None, q.get("refresh").is_some_and(|v| v == "1"));
        self.page("VPN", ctx, body)
    }

    /// The exits the owner added (`exits` of `devices.json`): their exit keys.
    fn vpn_added(&self) -> Vec<String> {
        read(&self.cfg.vpn.dir.join("devices.json"))["exits"].as_array().map(|a| a.iter()
            .filter_map(|e| xbt_nostr::event::Event::from_value(e).and_then(|e| e.tag("exit").map(str::to_string))).collect()).unwrap_or_default()
    }

    /// Found on Nostr: the exits the owner's relays carry, each checked, with *Add this exit* for one the
    /// owner wants: the service then reads it with the ones it finds, and every device prefers it.
    fn vpn_found_on_nostr(&self, ctx: &Ctx, in_use: &[&Value], refresh: bool) -> String {
        if !self.vpn_exits.enabled() {
            return String::new();
        }
        let own = read(&self.cfg.vpn.status_dir.join("exit-status.json"))["exit"].as_str().map(str::to_string);
        let added = self.vpn_added();
        let look = "<p class=\"small\"><a href=\"./vpn?refresh=1#found-exits\">Look again</a></p>";
        let Some(snap) = self.vpn_exits.get(refresh) else {
            return format!("<section class=\"card\" id=\"found-exits\"><h2>Found on Nostr</h2><p class=\"empty\">The relays are still being asked: \
                reload this page in a few seconds.</p>{look}</section>");
        };
        let mut known = self.file_services().unwrap_or_default();
        known.extend(self.nostr.services());
        let rows: String = snap.exits.iter().map(|f| {
            let e = &f.exit.exit;
            // the shop it is paid through, by its name where a listing names it (the services file, or Found on Nostr)
            let shop = f.exit.tunnel.as_deref().and_then(crate::services::http_origin).map(|o| crate::services::seller_name(&known, &o)).unwrap_or_default();
            let action = if own.as_deref() == Some(e.id.as_str()) {
                "<span class=\"tag\">this box's exit</span>".to_string()
            } else if added.contains(&e.id) {
                format!("<span class=\"tag ok\">added</span> <form method=\"post\" action=\"./vpn\" class=\"inline\">{}<input type=\"hidden\" name=\"do\" value=\"remove_exit\">\
                         <input type=\"hidden\" name=\"exit\" value=\"{}\"><button class=\"link\" type=\"submit\">Remove</button></form>", App::csrf_input(ctx), esc(&e.id))
            } else if e.price_msat_per_gb > 0 && f.exit.tunnel.is_none() {
                "<span class=\"small\">names no place to pay it: not usable</span>".to_string()
            } else {
                format!("<form method=\"post\" action=\"./vpn\" class=\"inline\">{}<input type=\"hidden\" name=\"do\" value=\"add_exit\">\
                         <input type=\"hidden\" name=\"exit\" value=\"{}\"><button class=\"secondary\" type=\"submit\">Add this exit</button></form>", App::csrf_input(ctx), esc(&e.id))
            };
            let seen = if in_use.iter().any(|x| x["exit"].as_str() == Some(e.id.as_str())) { " <span class=\"tag ok\">found by the VPN service</span>" } else { "" };
            format!("<tr><td><code>{}…</code>{seen}<div class=\"small\">{}{}</div></td><td>{}</td><td>{}</td><td>{}</td><td>{action}</td></tr>",
                    esc(&e.id.chars().take(12).collect::<String>()), if e.filtered { "filtered" } else { "private" },
                    if shop.is_empty() { String::new() } else { format!(" · paid through {}", esc(&shop)) },
                    esc(&e.region), price_words(Some(e.price_msat_per_gb)), if e.logs { "says it keeps logs" } else { "says no logs" })
        }).collect();
        let table = if snap.exits.is_empty() {
            "<p class=\"empty\">None of your Nostr relays carries an exit right now.</p>".to_string()
        } else {
            format!("<div class=\"scroll\"><table><thead><tr><th>Exit</th><th>Says</th><th>Price</th><th>Logs</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>")
        };
        format!("<section class=\"card\" id=\"found-exits\"><h2>Found on Nostr</h2><p class=\"small\">Exits your Nostr relays carry, each signed by its own key. \
            The VPN service looks for them by itself; <strong>Add this exit</strong> hands it one by hand, and your devices then use it first \
            whenever it meets their rules. Their rules still decide: country, price and the rest.</p>{table}{look}</section>")
    }

    fn vpn_html(&self, ctx: &Ctx, made: Option<(&str, &str)>, refresh: bool) -> String {
        let mut b = String::from("<p class=\"lead\">Send a phone's, a laptop's or your whole home's traffic out through someone else's connection, \
            in the country you choose. Paid as you use it, by the GB, within your spending rules. If no exit meets a device's rules, its \
            traffic stops: it never goes out your own connection by mistake.</p>");
        let ready = self.cfg.vpn.endpoint.is_some() && self.vpn_endpoint_key().is_some();
        if !ready {
            b.push_str("<section class=\"card\"><h2>Not running yet</h2><p class=\"empty\">The VPN isn't running on this box yet, so devices \
                can't be added.</p><details><summary>Technical details</summary><p>The VPN service writes its WireGuard key to \
                <code>endpoint.json</code> in <code>XBT_UI_VPN_STATUS_DIR</code> (or <code>XBT_UI_VPN_DIR</code>), and this page needs <code>XBT_UI_VPN_ENDPOINT</code>: the address \
                devices reach this box on.</p></details></section>");
        }
        if let Some((name, config)) = made {
            let qr = xbt_vpn::wg::qr_svg(config).unwrap_or_default();
            b.push_str(&format!(
                "<section class=\"card\"><h2>Added: {}</h2>\
                 <p class=\"hint warn\">This is the only time this device's settings are shown: they hold its private key. Scan the code with the \
                 WireGuard app, or copy the text into it, now. If they're lost, remove the device and add it again.</p>\
                 <div class=\"qr\">{qr}</div>\
                 <label>Settings<textarea id=\"vpn-config\" class=\"mono\" rows=\"10\" readonly>{}</textarea></label>\
                 <div class=\"row\"><button type=\"button\" data-copy=\"vpn-config\">Copy</button></div></section>",
                esc(name), esc(config)));
        }
        let status = read(&self.cfg.vpn.status_dir.join("status.json"));
        let devices = self.vpn_devices();
        let live: Vec<&Value> = devices.iter().filter(|d| d["revoked"].as_bool() != Some(true)).collect();
        let rows: String = live.iter().map(|d| {
            let id = d["id"].as_str().unwrap_or("");
            let (st, why) = device_line(&status, id);
            let state = match (why, st["exit"].as_str()) {
                (Some(why), _) => format!("<span class=\"tag bad\">blocked</span> <span class=\"small\">{}</span>", esc(why)),
                (None, Some(exit)) => format!("<span class=\"tag ok\">out through {}</span>", esc(exit)),
                _ => "<span class=\"tag\">no traffic yet</span>".to_string(),
            };
            let used = st["used_msat"].as_u64().unwrap_or(0) / 1000;
            let limit = d["limit_sats"].as_u64().map(|l| format!(" of {l}")).unwrap_or_default();
            format!("<tr><td>{}<div class=\"small\">{}</div></td><td>{}</td><td>{used}{limit} sats</td><td>\
                     <form method=\"post\" action=\"./vpn\" class=\"inline\">{}<input type=\"hidden\" name=\"do\" value=\"remove\">\
                     <input type=\"hidden\" name=\"id\" value=\"{}\"><button class=\"danger\" type=\"submit\">Remove</button></form></td></tr>",
                    esc(d["name"].as_str().unwrap_or("")), esc(&policy_words(&d["policy"])), state, App::csrf_input(ctx), esc(id))
        }).collect();
        let list = if live.is_empty() {
            "<p class=\"empty\">No device yet.</p>".to_string()
        } else {
            format!("<div class=\"scroll\"><table><thead><tr><th>Device and its rules</th><th>Now</th><th>Used</th><th></th></tr></thead>\
                     <tbody>{rows}</tbody></table></div><p class=\"small\">Removing a device stops its traffic at once.</p>")
        };
        b.push_str(&format!("<section class=\"card\"><h2>Devices</h2>{list}</section>"));
        // each exit's country, checked against where its traffic really comes out
        // every exit the service found (0.2.3: also the ones whose country is not checked yet), with its check
        let exits: Vec<&Value> = status["exits"].as_array().map(|a| a.iter().collect()).unwrap_or_default();
        if !exits.is_empty() {
            let rows: String = exits.iter().map(|e| {
                let id = e["exit"].as_str().unwrap_or("");
                let tag = if e["verified"] == true { "<span class=\"tag ok\">checked</span>" }
                          else if e["checked_at"].as_u64().unwrap_or(0) == 0 && e.get("checked_at").is_some() { "<span class=\"tag\">not checked</span>" }
                          else { "<span class=\"tag\">not used for its country</span>" };
                let added = if e["added"] == true { " <span class=\"tag ok\">added</span>" } else { "" };
                format!("<tr><td><code>{}…</code>{added}</td><td>{}</td><td>{}</td><td>{tag} <span class=\"small\">{}</span></td></tr>",
                        esc(&id.chars().take(12).collect::<String>()), esc(e["region"].as_str().unwrap_or("")), price_words(e["price_msat_gb"].as_u64()),
                        esc(e["region_check"].as_str().unwrap_or("")))
            }).collect();
            b.push_str(&format!("<section class=\"card\" id=\"exits\"><h2>Exits found</h2><p class=\"small\">The exits this box's VPN service can use. \
                An exit's country is checked, not taken on its word: \
                its traffic's address is read through it from several independent sites and looked up in a country table that comes with the app. \
                The check is best-effort: an exit could route those sites differently from your traffic.</p>\
                <div class=\"scroll\"><table><thead><tr><th>Exit</th><th>Says</th><th>Price</th><th>Check</th></tr></thead><tbody>{rows}</tbody></table></div>\
                <p class=\"small\"><a href=\"https://db-ip.com\" rel=\"noopener\">IP geolocation by DB-IP</a> (CC BY 4.0).</p></section>"));
        }
        if exits.is_empty() {
            // where exits come from, said where there are none (0.2.1 listed nothing and said nothing)
            b.push_str("<section class=\"card\" id=\"no-exits\"><h2>Exits</h2><p class=\"empty\">No exit found yet.</p>\
                <p class=\"small\">Exits are boxes that sell their internet connection. Their owners publish them on Nostr, and this box's VPN \
                service looks for them there by itself and checks each one's country. If none shows up after a few minutes, the relays it \
                reads may carry none yet; an exit listed under Found on Nostr can be added by hand.</p></section>");
        }
        b.push_str(&self.vpn_found_on_nostr(ctx, &exits, refresh));
        if ready {
            b.push_str(&format!(
                "<section class=\"card\"><h2>Add a device</h2><form method=\"post\" action=\"./vpn\" class=\"stack\">{}\
                 <input type=\"hidden\" name=\"do\" value=\"add\">\
                 <label>Name (for you)<input name=\"name\" maxlength=\"64\" placeholder=\"Phone\" required></label>\
                 <label>Limit (sats in all, optional)<input name=\"limit_sats\" type=\"number\" min=\"1\" step=\"1\"></label>\
                 {}<button type=\"submit\">Add the device</button></form>\
                 <p class=\"small\">You'll get settings and a QR code for the WireGuard app. A router can use the same settings.</p></section>",
                App::csrf_input(ctx), policy_fields(&json!({}))));
        }
        b
    }

    pub(crate) fn vpn_post(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let g = |k: &str| f.get(k).map(|v| v.trim().to_string()).unwrap_or_default();
        let path = self.cfg.vpn.dir.join("devices.json");
        let mut devices = self.vpn_devices();
        // the file whole: what is not changed here (the exits added by hand, the devices) stays
        let doc = |devices: &[Value], exits: Option<Vec<Value>>| -> Value {
            let mut d = read(&path);
            if !d.is_object() {
                d = json!({});
            }
            d["devices"] = json!(devices);
            if let Some(x) = exits {
                d["exits"] = json!(x);
            }
            d
        };
        let r: Result<String, String> = match g("do").as_str() {
            "add" => {
                let name: String = g("name").chars().take(64).collect();
                let (Some(endpoint), Some(endpoint_key)) = (self.cfg.vpn.endpoint.clone(), self.vpn_endpoint_key()) else {
                    self.flash(ctx, false, "The VPN isn't running on this box yet.");
                    return Resp::redirect("./vpn");
                };
                if name.is_empty() {
                    self.flash(ctx, false, "Name the device.");
                    return Resp::redirect("./vpn");
                }
                let Some(ip) = next_ip(&devices) else {
                    self.flash(ctx, false, "This box has as many devices as it takes. Remove one first.");
                    return Resp::redirect("./vpn");
                };
                let (private, public) = xbt_vpn::wg::keypair();
                let policy = policy_from(&g);
                devices.push(json!({
                    "id": hex::encode(&public[..8]), "name": name, "public_key": b64(&public), "tunnel_ip": ip.to_string(),
                    "limit_sats": g("limit_sats").parse::<u64>().ok().filter(|n| *n > 0), "policy": policy,
                    "added": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
                }));
                match write(&path, &doc(&devices, None)) {
                    Ok(()) => {
                        let config = xbt_vpn::wg::device_config(private, ip, endpoint_key, &endpoint, "10.66.0.1");
                        let body = self.vpn_html(ctx, Some((&name, &config)), false);
                        return self.page("VPN", ctx, body).header("Cache-Control", "no-store");
                    }
                    Err(e) => Err(format!("The devices file cannot be written: {e}")),
                }
            }
            "remove" => {
                let id = g("id");
                for d in devices.iter_mut().filter(|d| d["id"].as_str() == Some(id.as_str())) {
                    d["revoked"] = json!(true);
                }
                write(&path, &doc(&devices, None)).map(|_| "Removed: that device's traffic stops now.".into())
                    .map_err(|e| format!("The devices file cannot be written: {e}"))
            }
            // an exit from Found on Nostr: its signed announcement as the relays gave it (never the form's
            // word), kept for the service, which checks it again
            "add_exit" => {
                let id = g("exit");
                let mut exits: Vec<Value> = read(&path)["exits"].as_array().cloned().unwrap_or_default();
                exits.retain(|e| xbt_nostr::event::Event::from_value(e).and_then(|e| e.tag("exit").map(str::to_string)).as_deref() != Some(id.as_str()));
                match self.vpn_exits.find(&id) {
                    None => Err("That exit is no longer on your Nostr relays. Look again.".into()),
                    Some(_) if exits.len() >= xbt_vpn::service::MAX_ADDED_EXITS => Err(format!("At most {} exits can be added. Remove one first.", xbt_vpn::service::MAX_ADDED_EXITS)),
                    Some(f) => {
                        exits.push(f.event.to_value());
                        write(&path, &doc(&devices, Some(exits))).map(|_| format!("Added the exit in {}. The VPN service starts again with it in a few seconds; \
                            your devices use it first whenever it meets their rules.", f.exit.exit.region))
                            .map_err(|e| format!("The devices file cannot be written: {e}"))
                    }
                }
            }
            "remove_exit" => {
                let id = g("exit");
                let mut exits: Vec<Value> = read(&path)["exits"].as_array().cloned().unwrap_or_default();
                exits.retain(|e| xbt_nostr::event::Event::from_value(e).and_then(|e| e.tag("exit").map(str::to_string)).as_deref() != Some(id.as_str()));
                write(&path, &doc(&devices, Some(exits))).map(|_| "Removed the exit from your list. The VPN service may still find it on Nostr by itself.".into())
                    .map_err(|e| format!("The devices file cannot be written: {e}"))
            }
            _ => Err("Unknown action.".into()),
        };
        match r {
            Ok(m) => self.flash(ctx, true, m),
            Err(e) => self.flash(ctx, false, e),
        }
        Resp::redirect("./vpn")
    }

    /// What the shop's gateway says it charged its buyers in all (`chargedMsat` of its health), if it answers.
    fn shop_charged_msat(&self) -> Option<u64> {
        let Some(Ok((200, body))) = self.cfg.gw.health() else { return None };
        charged_in(&body)
    }

    pub(crate) fn sell_vpn_page(&self, ctx: &Ctx) -> Resp {
        let e = read(&self.cfg.vpn.dir.join("exit.json"));
        let st = read(&self.cfg.vpn.status_dir.join("exit-status.json"));
        let on = e["offer"].as_bool() == Some(true);
        let chk = |b: bool| if b { " checked" } else { "" };
        let filtered = e["kind"].as_str() == Some("filtered");
        let cats: Vec<&str> = e["categories"].as_array().into_iter().flatten().filter_map(|c| c.as_str()).collect();
        let cat_boxes: String = xbt_vpn::lists::CATEGORIES.iter().map(|c| format!(
            "<label class=\"check\"><input type=\"checkbox\" name=\"cat_{}\"{}> {}</label>", c.id, chk(cats.contains(&c.id)), esc(c.name))).collect();
        let sources: String = xbt_vpn::lists::CATEGORIES.iter().map(|c| format!("<li>{}: {}, {}</li>", esc(c.name), esc(c.source), esc(c.licence))).collect();
        let own = e["own_blocklist"].as_array().into_iter().flatten().filter_map(|d| d.as_str()).collect::<Vec<_>>().join("\n");
        let carried = if on {
            let gb = (st["up_bytes"].as_u64().unwrap_or(0) + st["down_bytes"].as_u64().unwrap_or(0)) as f64 / 1e9;
            let mut unlisted = st["not_announced_because"].as_str().map(|w| format!("<p class=\"hint warn\">Your exit isn't listed yet: {}.</p>", esc(w))).unwrap_or_default();
            if let Some(w) = st["paid_tunnels_closed_because"].as_str() {
                unlisted.push_str(&format!("<p class=\"hint warn\">Buyers can't use your exit yet: {}.</p>", esc(w)));
            }
            // what the shop's gateway charged its buyers (it meters the tunnels; the exit only counts bytes)
            let earned = st["earned_msat"].as_u64().or_else(|| self.shop_charged_msat()).unwrap_or(0);
            format!("<p>Carried for buyers so far: {gb:.2} GB. Your shop has earned {} sats.</p>{unlisted}", earned / 1000)
        } else {
            String::new()
        };
        let body = format!(
            "<p class=\"lead\">Let people use your internet connection as their exit, and get paid as they use it, by the GB. You need no \
             port forward: buyers reach this box through Stream's encrypted links.</p>\
             <section class=\"card\"><h2>Before you offer an exit</h2><p class=\"hint warn\">Strangers' traffic will leave the internet from \
             your connection. Your internet provider will see it as yours, and complaints about it (copyright or abuse) will come to you. \
             Your provider's terms may not allow sharing your connection. Running the exit on a rented server instead of at home keeps your \
             home address out of it.</p>{carried}</section>\
             <section class=\"card\"><h2>Your exit</h2><form method=\"post\" action=\"./sell-vpn\" class=\"stack\">{}\
             <label class=\"check\"><input type=\"checkbox\" name=\"offer\"{}> Offer my connection as an exit</label>\
             <label class=\"check\"><input type=\"checkbox\" name=\"understood\"{}> I've read the warning above</label>\
             <label>Price (sats a GB)<input name=\"sat_per_gb\" type=\"number\" min=\"1\" step=\"1\" value=\"{}\" required></label>\
             <label>The country your connection is in (two letters, like DE)<input name=\"country\" maxlength=\"2\" value=\"{}\" \
             placeholder=\"DE\"></label><p class=\"small\">Buyers choose exits by country, so your exit is listed only once this is set.</p>\
             <label>Kind<select name=\"kind\"><option value=\"private\"{}>Private: you can't see which sites buyers visit (most buyers want this)</option>\
             <option value=\"filtered\"{}>Filtered: block the sites below; your exit sees site names</option></select></label>\
             <fieldset><legend>Block, if filtered</legend>{cat_boxes}\
             <label>Your own list (one site a line)<textarea name=\"own_blocklist\" rows=\"4\" placeholder=\"example.com\">{}</textarea></label>\
             <details><summary>Where the lists come from</summary><ul>{sources}</ul><p class=\"small\">Lists update once a day. A site can still \
             get through by some routes (an address, some encrypted lookups); buyers see what your exit blocks before they choose it.</p></details></fieldset>\
             <details><summary>Advanced: protections</summary>\
             <label>Each buyer's speed (Mbit/s, optional)<input name=\"buyer_mbit\" type=\"number\" min=\"1\" step=\"1\" value=\"{}\"></label>\
             <label>Each buyer's connections at once<input name=\"max_connections\" type=\"number\" min=\"1\" step=\"1\" value=\"{}\"></label>\
             <label>Ports never carried (email's 25 by default)<input name=\"blocked_ports\" value=\"{}\"></label>\
             <p class=\"small\">Your exit never keeps a record of where buyers go, and never lets anyone reach your own network.</p></details>\
             <button type=\"submit\">Save</button></form></section>",
            App::csrf_input(ctx), chk(on), chk(on), e["sat_per_gb"].as_u64().unwrap_or(20), esc(e["country"].as_str().unwrap_or("")), if filtered { "" } else { " selected" },
            if filtered { " selected" } else { "" }, esc(&own), e["buyer_mbit"].as_u64().map(|n| n.to_string()).unwrap_or_default(),
            e["max_connections"].as_u64().unwrap_or(512),
            esc(&e["blocked_ports"].as_array().map(|p| p.iter().filter_map(|x| x.as_u64()).map(|x| x.to_string()).collect::<Vec<_>>().join(", ")).unwrap_or_else(|| "25".into())),
        );
        self.page("VPN exit", ctx, body)
    }

    pub(crate) fn sell_vpn_post(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let g = |k: &str| f.get(k).map(|v| v.trim().to_string()).unwrap_or_default();
        let offer = g("offer") == "on";
        if offer && g("understood") != "on" {
            self.flash(ctx, false, "Tick that you've read the warning before offering an exit.");
            return Resp::redirect("./sell-vpn");
        }
        let cats: Vec<&str> = xbt_vpn::lists::CATEGORIES.iter().filter(|c| g(&format!("cat_{}", c.id)) == "on").map(|c| c.id).collect();
        let own: Vec<String> = g("own_blocklist").lines().map(str::trim).filter(|l| l.contains('.') && !l.contains(char::is_whitespace)).take(5000).map(str::to_ascii_lowercase).collect();
        let ports: Vec<u16> = g("blocked_ports").split(|c: char| c == ',' || c.is_whitespace()).filter_map(|p| p.parse().ok()).collect();
        let filtered = g("kind") == "filtered";
        let v = json!({
            "offer": offer,
            "kind": if filtered { "filtered" } else { "private" },
            "categories": if filtered { cats } else { Vec::new() },
            "own_blocklist": if filtered { own } else { Vec::new() },
            "sat_per_gb": g("sat_per_gb").parse::<u64>().ok().filter(|n| *n > 0).unwrap_or(20),
            "country": Some(g("country").to_ascii_uppercase()).filter(|c| c.len() == 2 && c.chars().all(|ch| ch.is_ascii_alphabetic())),
            "buyer_mbit": g("buyer_mbit").parse::<u64>().ok().filter(|n| *n > 0),
            "max_connections": g("max_connections").parse::<u64>().ok().filter(|n| *n > 0).unwrap_or(512),
            "blocked_ports": ports,
        });
        let mut v = v;
        // buyers pay for the exit as one of the shop's services: where their wallets open its tunnels
        let tunnel = self.vpn_tunnel_url();
        v["tunnel_url"] = json!(tunnel);
        let r = write(&self.cfg.vpn.dir.join("exit.json"), &v).map_err(|e| format!("The exit's settings cannot be written: {e}")).and_then(|()| {
            if self.cfg.vpn.tunnel_upstream.is_none() {
                return Ok(if offer { "Saved. Selling the exit is off in this install, so buyers can't pay for it yet.".to_string() } else { "Saved: your exit isn't offered.".into() });
            }
            // the shop sells the exit: its route follows these settings
            let words = self.commit(&self.shop(), "").map_err(|e| format!("Saved, but your shop could not be updated: {e}"))?;
            Ok(match (offer, tunnel.is_some()) {
                (false, _) => "Saved: your exit isn't offered.".to_string(),
                (true, true) => format!("Saved: your exit is offered, paid as buyers use it. {}", words.trim()),
                (true, false) => "Saved. Your exit is announced once your shop is reachable: set it up on the Sell page.".to_string(),
            })
        });
        match r {
            Ok(m) => self.flash(ctx, true, m),
            Err(e) => self.flash(ctx, false, e),
        }
        Resp::redirect("./sell-vpn")
    }

    /// Where buyers' wallets open paid tunnels to this box's exit: [`VPN_PATH`] on its shop (its https
    /// address, or its shop key's address for a shop reached by its key). `None` until the shop has one.
    fn vpn_tunnel_url(&self) -> Option<String> {
        let shop = self.shop();
        if shop.public_url.starts_with("https://") {
            return Some(format!("{}{VPN_PATH}tunnel", shop.public_url.trim_end_matches('/')));
        }
        let npub = self.link_status()?.get("npub")?.as_str()?.to_string();
        Some(format!("{}{VPN_PATH}tunnel", xbt402::shop::origin_for(&xbt402::shop::from_npub(&npub)?)))
    }

    /// The shop's route that sells this box's exit, while one is offered: each tunnel a WebSocket the
    /// gateway joins to the VPN service, paid per byte both ways at the exit's price a GB.
    /// Only the shop's gateway reaches the exit's tunnel endpoint: each tunnel it joins carries the
    /// secret the two share, written here beside the exit's settings.
    pub(crate) fn vpn_route(&self) -> Option<Value> {
        let upstream = self.cfg.vpn.tunnel_upstream.clone()?;
        let s = xbt_vpn::service::exit_from(&read(&self.cfg.vpn.dir.join("exit.json")))?;
        let secret = tunnel_secret(&self.cfg.vpn.dir)?;
        Some(json!({"path": VPN_PATH, "upstream": upstream, "methods": ["GET"], "websocket": true, "service": "vpn-exit",
                    "upstream_headers": {xbt_vpn::paid::TUNNEL_HEADER: secret},
                    "price": {"byte_msat": s.sat_per_gb.saturating_mul(1000), "per_bytes": 1u64 << 30}}))
    }
}

/// The path a shop sells its VPN exit under.
pub const VPN_PATH: &str = "/vpn/";

/// The secret the shop's gateway and the exit's tunnel endpoint share, made once. Written as the
/// other files the VPN service reads ([`crate::setup::write_shared`]): whole or not at all, with the
/// folder's group (the VPN service's) and mode 0640, so the service can read it and nobody else.
/// A file that holds no whole secret (cut short, or garbled) is replaced.
fn tunnel_secret(dir: &std::path::Path) -> Option<String> {
    let _ = migrate_tunnel_secret(dir);
    if let Some(s) = xbt_vpn::paid::tunnel_secret_in(dir) {
        return Some(s);
    }
    let secret = xbt_vpn::paid::new_tunnel_secret();
    std::fs::create_dir_all(dir).ok()?;
    crate::setup::write_shared(dir, xbt_vpn::paid::TUNNEL_SECRET_FILE, secret.as_bytes()).ok()?;
    Some(secret)
}

/// A whole tunnel secret written as an older build wrote it (owner-only, the app's own group) is
/// written again, the same secret, as [`tunnel_secret`] writes one: the folder's group (the VPN
/// service's) and 0640, whole. Without it an exit offered before the upgrade stays closed: the
/// service can't read the file and lets nobody in. `Ok(true)`: it was rewritten.
pub(crate) fn migrate_tunnel_secret(dir: &std::path::Path) -> Result<bool, String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let path = dir.join(xbt_vpn::paid::TUNNEL_SECRET_FILE);
    let Ok(md) = std::fs::metadata(&path) else { return Ok(false) };
    let Some(secret) = xbt_vpn::paid::tunnel_secret_in(dir) else { return Ok(false) };
    let folder = std::fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if md.permissions().mode() & 0o777 == 0o640 && md.gid() == folder.gid() {
        return Ok(false);
    }
    crate::setup::write_shared(dir, xbt_vpn::paid::TUNNEL_SECRET_FILE, secret.as_bytes())?;
    Ok(true)
}

/// A device's line in the VPN service's `status.json`, and why its traffic is stopped, if it is. The service
/// writes `devices` as a list of lines, each with its `id`, the reason as `blocked`
/// ([`xbt_vpn::service::device_status`]); a map by id with `why_blocked` is read too.
fn device_line<'a>(status: &'a Value, id: &str) -> (&'a Value, Option<&'a str>) {
    let st = status["devices"].as_array().and_then(|a| a.iter().find(|x| x["id"].as_str() == Some(id))).unwrap_or(&status["devices"][id]);
    (st, st["blocked"].as_str().or(st["why_blocked"].as_str()))
}

/// `chargedMsat` of a gateway's health answer.
fn charged_in(health: &str) -> Option<u64> {
    serde_json::from_str::<Value>(health).ok()?.get("chargedMsat")?.as_str()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_the_shop_earned_is_read_from_its_gateway() {
        assert_eq!(charged_in(r#"{"height": 900000, "chargedMsat": "294967"}"#), Some(294_967));
        assert_eq!(charged_in(r#"{"height": 900000}"#), None, "a gateway of before");
        assert_eq!(charged_in("not json"), None);
    }

    #[test]
    fn why_a_device_is_blocked_is_read_from_the_vpn_services_own_status() {
        let d = xbt_vpn::service::devices_from(&json!({"devices": [{"id": "aa57dcdaefeb9a90", "name": "phone",
            "public_key": "Tvq8X4Gcj3JZLBsSi/BPkP7HdQxGYdqI61SoZLAJUhc=", "tunnel_ip": "10.66.0.2"}]})).remove(0);
        let status = json!({"devices": [xbt_vpn::service::device_status(&d, 0, 0, Some("No exit is verified to be in US.".into()))]});
        assert_eq!(device_line(&status, "aa57dcdaefeb9a90").1, Some("No exit is verified to be in US."));
        assert_eq!(device_line(&status, "someone-else").1, None);
        let old = json!({"devices": {"b2": {"why_blocked": "No exit is verified to be in JP."}}});
        assert_eq!(device_line(&old, "b2").1, Some("No exit is verified to be in JP."));
    }

    #[test]
    fn a_policy_reads_in_plain_words() {
        let p = policy_from(&|k| match k {
            "kind" => "private".into(),
            "country" => "de".into(),
            "two_hop" => "on".into(),
            "max_sat_per_gb" => "50".into(),
            _ => String::new(),
        });
        assert_eq!(policy_words(&p), "Private exits · in DE · two hops · up to 50 sats a GB · the best exit");
        assert_eq!(policy_words(&json!({})), "Private exits · the best exit");
    }

    #[test]
    fn tunnel_addresses_are_never_reused() {
        let d = vec![json!({"tunnel_ip": "10.66.0.2"}), json!({"tunnel_ip": "10.66.0.3"})];
        assert_eq!(next_ip(&d), Some(Ipv4Addr::new(10, 66, 0, 4)));
        let full: Vec<Value> = (2..=250).map(|n| json!({"tunnel_ip": format!("10.66.0.{n}")})).collect();
        assert_eq!(next_ip(&full), None);
    }

    #[test]
    fn the_tunnel_secret_is_made_once_and_kept_from_others() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let first = tunnel_secret(d.path()).unwrap();
        assert_eq!(first.len(), 64);
        assert_eq!(tunnel_secret(d.path()).as_deref(), Some(first.as_str()), "the same secret every time the route is written");
        let md = std::fs::metadata(d.path().join(xbt_vpn::paid::TUNNEL_SECRET_FILE)).unwrap();
        assert_eq!(md.permissions().mode() & 0o777, 0o640, "its owner and the folder's group (the VPN service's) read it, nobody else");
    }

    /// A secret an older build wrote owner-only (0600) is written again, the same secret, 0640
    /// with the folder's group, so an exit offered before the upgrade opens to its gateway again.
    #[test]
    fn a_secret_written_by_an_older_build_is_given_to_the_vpn_service() {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join(xbt_vpn::paid::TUNNEL_SECRET_FILE);
        let old = xbt_vpn::paid::new_tunnel_secret();
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).unwrap();
        std::io::Write::write_all(&mut f, old.as_bytes()).unwrap();
        drop(f);
        assert_eq!(migrate_tunnel_secret(d.path()), Ok(true));
        let md = std::fs::metadata(&path).unwrap();
        assert_eq!(md.permissions().mode() & 0o777, 0o640);
        assert_eq!(md.gid(), std::fs::metadata(d.path()).unwrap().gid());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), old, "the same secret: the gateway's route still matches");
        assert_eq!(migrate_tunnel_secret(d.path()), Ok(false), "once is enough");
        assert_eq!(tunnel_secret(d.path()).as_deref(), Some(old.as_str()));
    }

    /// The VPN service reads the secret by the folder's group: the file takes that group, so the
    /// service (another user) can read it. One that holds no whole secret is replaced, whole.
    #[test]
    fn the_tunnel_secret_takes_the_folders_group_and_a_bad_one_is_replaced() {
        use std::os::unix::fs::MetadataExt;
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join(xbt_vpn::paid::TUNNEL_SECRET_FILE);
        std::fs::write(&path, "0123abcd").unwrap();
        let s = tunnel_secret(d.path()).unwrap();
        assert!(xbt_vpn::paid::is_tunnel_secret(&s), "{s}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), s, "the short file was replaced");
        assert_eq!(std::fs::metadata(&path).unwrap().gid(), std::fs::metadata(d.path()).unwrap().gid(), "the folder's group");
        let leftovers: Vec<_> = std::fs::read_dir(d.path()).unwrap().filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().starts_with('.')).collect();
        assert!(leftovers.is_empty(), "no half-written file left behind");
    }
}
