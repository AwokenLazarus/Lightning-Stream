//! Hashrate, as one more kind of service.
//!
//! Sell → Hashrate (`XBT_UI_HASHER`): the owner rents out this box's miners. Miners point at the
//! app once; any miner nobody rents hashes for the owner's own pool or DATUM Gateway. The page
//! writes the hasher service's settings file, shows each miner and each rental, and stops a
//! rental. Renters pay each piece of work through this box's shop, which sells it under
//! `/hashrate/` (the route [`App::hash_route`] adds).
//!
//! Services → Hashrate (`XBT_UI_HASHRENT`): the owner rents other people's miners into their own
//! DATUM Gateway (the pool is chosen there, not here), with a budget, and can cut a rental at any
//! time. Rentals also show on Live connections.
//!
//! Both talk to their service's control page on the box's own network, with its token.
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{json, Value};

use super::{App, Ctx};
use crate::html::{esc, short};
use crate::server::Resp;

const WAIT: Duration = Duration::from_secs(6);
/// Suggested price of a piece of work, and its size: about half a minute of a 4 TH/s miner.
pub const SUGGESTED_PRICE_SAT: u64 = 40;
pub const SLICE_WORK: u128 = 1 << 47;
/// The miner speed estimates are given for.
const EXAMPLE_HS: f64 = 4e12;

/// One call to a service's control page.
fn call(base: &str, token: &Option<PathBuf>, method: &str, path: &str, body: Option<&Value>) -> Result<Value, String> {
    let agent = ureq::AgentBuilder::new().timeout_connect(WAIT).timeout_read(WAIT).timeout_write(WAIT).redirects(0).build();
    let mut req = agent.request(method, &format!("{}{path}", base.trim_end_matches('/')));
    if let Some(t) = token {
        let t = std::fs::read_to_string(t).map_err(|_| "The hashrate service has not started yet.".to_string())?;
        req = req.set("Authorization", &format!("Bearer {}", t.trim()));
    }
    let r = match body {
        Some(b) => req.set("Content-Type", "application/json").send_string(&b.to_string()),
        None => req.call(),
    };
    let r = match r {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(_) => return Err("The hashrate service does not answer. It may still be starting: try again in a minute.".into()),
    };
    r.into_string().ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()).ok_or_else(|| "The hashrate service gave an answer this page cannot read.".into())
}

/// A speed in words: `4.10 TH/s`, `850 GH/s`.
pub fn speed(hs: f64) -> String {
    let units = [(1e15, "PH/s"), (1e12, "TH/s"), (1e9, "GH/s"), (1e6, "MH/s")];
    for (d, u) in units {
        if hs >= d {
            return format!("{:.2} {u}", hs / d);
        }
    }
    if hs > 0.0 {
        format!("{hs:.0} H/s")
    } else {
        "—".into()
    }
}

fn num(v: &Value) -> f64 {
    match v {
        Value::Number(n) => n.as_f64().unwrap_or(0.0),
        Value::String(s) => s.parse().unwrap_or(0.0),
        _ => 0.0,
    }
}

/// What a piece of work of `slice_work` hashes at `price_sat` costs an hour at `hs`.
pub fn per_hour(price_sat: f64, slice_work: f64, hs: f64) -> f64 {
    if slice_work <= 0.0 {
        return 0.0;
    }
    price_sat * hs * 3600.0 / slice_work
}

fn sats_n(n: f64) -> String {
    let n = n.round() as i64;
    let s = n.to_string();
    let mut o = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            o.push(',');
        }
        o.push(c);
    }
    format!("{o} {}", if n == 1 { "sat" } else { "sats" })
}

/// A closed rental's reason, in words.
fn ended_words(why: &str) -> String {
    let w = why.trim_start_matches("hasher closed: ").trim_start_matches("buyer closed: ");
    match w {
        "cut by the buyer" => "You cut it.".into(),
        "budget used up" => "Its budget is used up.".into(),
        "rental time over" => "Its time is up.".into(),
        "no accepted work" => "The miners stopped sending work.".into(),
        "unpaid" => "A piece of work was not paid in time.".into(),
        "stopped by the hasher" => "The seller stopped it.".into(),
        "no miners free now" => "The seller has no miners free.".into(),
        w if w.starts_with("link lost") => "The connection to the seller was lost.".into(),
        w if w.starts_with("could not start") => format!("It could not start: {}", w.trim_start_matches("could not start: ")),
        w => format!("Ended: {w}."),
    }
}

/// The settings file, with its dir's group (the hasher service reads it by group).
fn write_settings(path: &std::path::Path, v: &Value) -> Result<(), String> {
    let dir = path.parent().ok_or("no folder for the settings")?;
    let name = path.file_name().and_then(|n| n.to_str()).ok_or("no file name for the settings")?;
    if !dir.is_dir() {
        std::fs::create_dir_all(dir).map_err(|e| format!("The settings could not be saved: {e}"))?;
    }
    crate::setup::write_shared(dir, name, (serde_json::to_string_pretty(v).unwrap_or_default() + "\n").as_bytes())
        .map_err(|e| format!("The settings could not be saved: {e}"))
}

impl App {
    pub(crate) fn hash_settings(&self) -> Value {
        std::fs::read_to_string(&self.cfg.hash.settings).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(json!({}))
    }

    /// The shop's route for paid pieces of work, when renting out is on: `None` otherwise.
    pub(crate) fn hash_route(&self) -> Option<Value> {
        let slices = self.cfg.hash.slices.as_ref()?;
        let s = self.hash_settings();
        if s["enabled"] != true {
            return None;
        }
        let price = s["priceSat"].as_u64().unwrap_or(SUGGESTED_PRICE_SAT) * 1000;
        Some(json!({"path": "/hashrate/", "upstream": slices, "methods": ["POST"], "max_body": 65536, "price": {"request_msat": price}}))
    }

    // --- Sell → Hashrate ------------------------------------------------------------------------

    pub(crate) fn sell_hashrate_page(&self, ctx: &Ctx) -> Resp {
        let Some(base) = self.cfg.hash.hasher.clone() else {
            return self.html_page("Sell hashrate", "Sell hashrate", ctx,
                "<p class=\"empty\">This box does not rent out miners. The Lightning Stream app on Umbrel does.</p>", "");
        };
        let st = call(&base, &self.cfg.hash.hasher_token, "GET", "/status", None);
        let saved = self.hash_settings();
        let csrf = App::csrf_input(ctx);
        let mut b = String::new();
        let settings = st.as_ref().ok().map(|s| s["settings"].clone()).unwrap_or(json!({}));
        let pick = |k: &str| saved.get(k).filter(|v| !v.is_null()).cloned().or_else(|| settings.get(k).filter(|v| !v.is_null()).cloned());
        let on = pick("enabled") == Some(Value::Bool(true));
        let fallback = pick("fallback").and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
        let miners: Vec<Value> = st.as_ref().ok().and_then(|s| s["miners"].as_array().cloned()).unwrap_or_default();
        let rentals: Vec<Value> = st.as_ref().ok().and_then(|s| s["rentals"].as_array().cloned()).unwrap_or_default();
        let live = miners.iter().filter(|m| m["connected"] == true).count();
        let rented = miners.iter().filter(|m| !m["rentedTo"].is_null()).count();
        let (class, head, next) = match &st {
            Err(e) => ("bad", "Can't reach the hashrate service".to_string(), e.clone()),
            Ok(_) if !on || fallback.is_empty() => ("warn", "Not renting out".to_string(),
                "Say where your miners hash when nobody rents them, then turn renting on below.".to_string()),
            Ok(_) if live == 0 => ("warn", "Renting is on, no miners yet".to_string(), "Point your miners at the address below.".to_string()),
            Ok(_) => ("good", format!("Renting out: {rented} of {live} miner{} rented", if live == 1 { "" } else { "s" }),
                      if rented == 0 { "The others hash for your own pool until someone rents them.".into() } else { String::new() }),
        };
        b.push_str(&format!("<section class=\"status {class}\" aria-live=\"polite\"><p class=\"status-head\">{}</p>{}</section>",
                            esc(&head), if next.is_empty() { String::new() } else { format!("<p>{}</p>", esc(&next)) }));

        // where the miners point, once
        let addr = st.as_ref().ok().and_then(|s| s["minersAddress"].as_str().map(str::to_string)).unwrap_or_default();
        if !addr.is_empty() {
            b.push_str(&format!("<section class=\"card\"><h2>Point your miners at this box</h2>\
                <p>In each miner's settings, set its first pool to this address. Keep its worker name and password as they are.</p>\
                <label>Pool address for your miners<input id=\"miners-address\" readonly class=\"mono\" value=\"stratum+tcp://{}\"></label>\
                <div class=\"row\"><button type=\"button\" class=\"secondary\" data-copy=\"miners-address\">Copy the address</button></div>\
                <p class=\"hint\">If a miner cannot find this name, use this box's IP address with the same port. Keep your own pool as the miner's second pool.</p></section>",
                esc(&addr)));
        }

        // the miners
        if !miners.is_empty() {
            b.push_str("<h2>Your miners</h2><div class=\"scroll\"><table><thead><tr><th>Miner</th><th>Speed</th><th>Now</th><th>Earned</th></tr></thead><tbody>");
            for m in &miners {
                let now = if m["connected"] != true {
                    "<span class=\"pill\">Offline</span>".to_string()
                } else if m["rentedTo"].is_null() {
                    "<span class=\"pill good\">Your pool</span>".to_string()
                } else {
                    "<span class=\"pill cat-media\">Rented out</span>".to_string()
                };
                b.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{now}</td><td class=\"money\">{}</td></tr>",
                                    esc(m["name"].as_str().unwrap_or("")), speed(num(&m["hashrateHs"])), sats_n(num(&m["earnedMsat"]) / 1000.0)));
            }
            b.push_str("</tbody></table></div>");
        }

        // the rentals going on
        if !rentals.is_empty() {
            b.push_str("<h2>Rented now</h2>");
            for r in &rentals {
                let id = r["rental"].as_str().unwrap_or("");
                let names: Vec<&str> = r["miners"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
                b.push_str(&format!("<section class=\"card live\"><div class=\"offer-head\"><h3>{} miner{}: {}</h3><span class=\"pill good\">Hashing</span></div>\
                    <p>Earned so far: <span class=\"money\">{}</span> · {} piece{} of work paid</p>\
                    <form method=\"post\" action=\"./sell-hashrate\">{csrf}<input type=\"hidden\" name=\"action\" value=\"stop\"><input type=\"hidden\" name=\"rental\" value=\"{}\">\
                    <button class=\"danger\">Stop this rental</button></form>\
                    <details><summary>Details</summary><p class=\"small\">Renter <code>{}</code> · rental <code>{}</code></p></details></section>",
                    names.len(), if names.len() == 1 { "" } else { "s" }, esc(&names.join(", ")),
                    sats_n(num(&r["earnedMsat"]) / 1000.0), r["paid"].as_u64().unwrap_or(0), if r["paid"].as_u64() == Some(1) { "" } else { "s" },
                    esc(id), esc(&short(r["buyer"].as_str().unwrap_or(""), 20)), esc(id)));
            }
        }

        // the main action: turn renting on, or change it
        let price = pick("priceSat").and_then(|v| v.as_u64()).unwrap_or(SUGGESTED_PRICE_SAT);
        let slice: f64 = pick("sliceWork").map(|v| num(&v)).filter(|w| *w > 0.0).unwrap_or(SLICE_WORK as f64);
        let rentable = pick("rentable").and_then(|v| v.as_u64()).map(|n| n.to_string()).unwrap_or_default();
        let name = pick("name").and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
        let link_public = pick("linkPublic").and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
        let link_lan = st.as_ref().ok().and_then(|s| s["linkLan"].as_str().map(str::to_string)).filter(|a| !a.is_empty()).unwrap_or_else(|| "this box's address, port 23341".into());
        let grace_s = pick("graceMs").and_then(|v| v.as_u64()).unwrap_or(45_000) / 1000;
        b.push_str(&format!("<section class=\"card primary\"><h2>{}</h2><form method=\"post\" action=\"./sell-hashrate\">{csrf}\
            <input type=\"hidden\" name=\"action\" value=\"save\">\
            <label>Your own pool, where your miners hash when nobody rents them<input name=\"fallback\" value=\"{}\" required class=\"mono\" \
            pattern=\"[A-Za-z0-9.\\-\\[\\]:]+:[0-9]+\" title=\"An address with its port, like 192.168.1.20:23334\" placeholder=\"192.168.1.20:23334\"></label>\
            <p class=\"hint\">Your DATUM Gateway or your pool, as your miners use it today. Every miner nobody rents keeps hashing there.</p>\
            <label>Price for each piece of work, in sats<input name=\"price\" value=\"{price}\" required inputmode=\"numeric\" pattern=\"[0-9]+\" title=\"A whole number of sats\"></label>\
            <p class=\"hint\">At this price a {} miner earns about <strong>{}</strong> an hour while it is rented.</p>\
            <label>Miners to rent out at most <small>(empty: all of them)</small><input name=\"rentable\" value=\"{}\" inputmode=\"numeric\" pattern=\"[0-9]*\"></label>\
            <label>Name, as renters see it<input name=\"name\" value=\"{}\" maxlength=\"80\" placeholder=\"My miners\"></label>\
            <label>Address renters use to reach your miners (needs a port forward or tunnel)<input name=\"link_public\" value=\"{}\" class=\"mono\" \
            pattern=\"[A-Za-z0-9.\\-\\[\\]:]+:[0-9]+\" title=\"An address with its port, like my-box.example.com:23341\" placeholder=\"my-box.example.com:23341\"></label>\
            <p class=\"hint\">Renters' apps connect to this box's port 23341. Leave it empty and your offer stays off public listings; renters on your own network can still use {}.</p>\
            <details><summary>How do I get this address?</summary><ol>\
            <li>On your router, forward <strong>TCP port 23341</strong> to this box ({}). Forward only 23341: your miners' port stays on your own network.</li>\
            <li>Write your router's public address with the port, like <code>203.0.113.7:23341</code>, or a name that points at it (dynamic DNS), \
            like <code>my-box.example.com:23341</code>.</li>\
            <li>Save. Your offer goes on public listings within a minute.</li></ol>\
            <p class=\"hint\">This is a plain TCP port, so https tunnels for websites cannot carry it. The link is encrypted end to end, so it needs no \
            certificate. If you cannot forward ports, a tunnel app that forwards a TCP port to this box works too.</p></details>\
            <label class=\"check\"><input type=\"checkbox\" name=\"enabled\" value=\"1\"{}> Rent out my miners</label>\
            <details><summary>Advanced</summary>\
            <label>Work in each piece (hashes)<input name=\"slice_work\" value=\"{:.0}\" inputmode=\"numeric\" pattern=\"[0-9]+\" class=\"mono\"></label>\
            <label>How long to wait for each payment, in seconds<input name=\"grace_s\" value=\"{grace_s}\" inputmode=\"numeric\" pattern=\"[0-9]+\"></label>\
            </details><div class=\"row\"><button>{}</button></div></form></section>",
            if on { "Change renting" } else { "Rent out your miners" }, esc(&fallback), speed(EXAMPLE_HS), sats_n(per_hour(price as f64, slice, EXAMPLE_HS)),
            esc(&rentable), esc(&name), esc(&link_public), esc(&link_lan), esc(&link_lan), if on || saved.get("enabled").is_none() { " checked" } else { "" }, slice,
            if on { "Save" } else { "Save and start renting" }));
        if let Ok(s) = &st {
            match s["listing"].get("ok") {
                Some(Value::Bool(true)) => b.push_str(&format!(
                    "<section class=\"card\"><p><span class=\"pill good\">Listed</span> Your offer is on public listings: {} of {} miners free.</p></section>",
                    s["listing"]["freeMiners"], s["listing"]["miners"])),
                Some(Value::Bool(false)) => b.push_str(&format!(
                    "<section class=\"card\"><p><span class=\"pill warn\">Not listed</span> {}</p></section>",
                    esc(s["listing"]["why"].as_str().unwrap_or("Your offer is not published yet.")))),
                _ => b.push_str("<section class=\"card\"><p><span class=\"pill warn\">Not listed yet</span> Your offer goes on public listings once a miner is connected and the address renters use is set.</p></section>"),
            }
        }
        self.html_page("Sell hashrate", "Sell hashrate", ctx, &b, "")
    }

    pub(crate) fn sell_hashrate_post(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let g = |k: &str| f.get(k).map(|s| s.trim().to_string()).unwrap_or_default();
        let r: Result<String, String> = match g("action").as_str() {
            "stop" => match &self.cfg.hash.hasher {
                None => Err("This box does not rent out miners.".into()),
                Some(base) => call(base, &self.cfg.hash.hasher_token, "POST", &format!("/stop/{}", crate::services::urlenc(&g("rental"))), None)
                    .and_then(|v| if v["ok"] == true { Ok("Stopped. Those miners hash for your own pool again.".into()) } else { Err("That rental had ended already.".into()) }),
            },
            "save" => (|| {
                let fallback = g("fallback");
                if !fallback.contains(':') || fallback.contains(['/', ' ']) {
                    return Err("Write your own pool's address with its port, like 192.168.1.20:23334.".into());
                }
                let price: u64 = g("price").parse().map_err(|_| "The price is a whole number of sats.".to_string())?;
                if price == 0 {
                    return Err("Set a price above 0 sats.".into());
                }
                let rentable: Option<u64> = if g("rentable").is_empty() { None } else { Some(g("rentable").parse().map_err(|_| "Miners to rent out is a whole number, or empty.".to_string())?) };
                let slice: u128 = if g("slice_work").is_empty() { SLICE_WORK } else { g("slice_work").parse().map_err(|_| "The work in each piece is a whole number.".to_string())? };
                if slice < 1 << 32 {
                    return Err("Each piece of work is at least 4,294,967,296 hashes.".into());
                }
                let grace: u64 = if g("grace_s").is_empty() { 45 } else { g("grace_s").parse().map_err(|_| "The wait is a whole number of seconds.".to_string())? };
                let mut v = self.hash_settings();
                let shop = self.shop();
                v["enabled"] = json!(g("enabled") == "1");
                v["fallback"] = json!(fallback);
                v["priceSat"] = json!(price);
                v["rentable"] = json!(rentable);
                v["sliceWork"] = json!(slice.to_string());
                v["graceMs"] = json!(grace.clamp(5, 600) * 1000);
                v["name"] = json!(if g("name").is_empty() { "Hashrate".to_string() } else { g("name").chars().take(80).collect() });
                let link = g("link_public");
                if !link.is_empty() && (!link.contains(':') || link.contains(['/', ' '])) {
                    return Err("Write the address renters use with its port, like my-box.example.com:23341.".into());
                }
                // empty clears it: no listing on public relays until it is set
                v["linkPublic"] = json!(link);
                if !shop.public_url.is_empty() {
                    v["payUrl"] = json!(format!("{}/hashrate", shop.public_url.trim_end_matches('/')));
                }
                write_settings(&self.cfg.hash.settings, &v)?;
                // the shop sells each piece of work: its route follows these settings
                let words = self.commit(&shop, "")?;
                Ok(if v["enabled"] == true {
                    format!("Saved. Renting is on. {}", words.trim())
                } else {
                    "Saved. Renting is off: every miner hashes for your own pool.".into()
                })
            })(),
            _ => Err("Unknown action.".into()),
        };
        match r {
            Ok(m) => self.flash(ctx, true, m),
            Err(e) => self.flash(ctx, false, e),
        }
        Resp::redirect("./sell-hashrate")
    }

    // --- Services → Hashrate ---------------------------------------------------------------------

    /// Rentals going on (for Live connections): cards with a Cut button, and what they spent.
    pub(crate) fn hash_live_cards(&self, ctx: &Ctx) -> (String, i64) {
        let Some(base) = &self.cfg.hash.renter else { return (String::new(), 0) };
        let Ok(st) = call(base, &self.cfg.hash.renter_token, "GET", "/status", None) else { return (String::new(), 0) };
        let mut spent = 0i64;
        let mut cards = String::new();
        for r in st["rentals"].as_array().into_iter().flatten().filter(|r| r["ended"] != true) {
            spent += (num(&r["live"]["spentMsat"]) / 1000.0) as i64;
            cards.push_str(&rental_card(ctx, r, "./connections-hashrate"));
        }
        (cards, spent)
    }

    pub(crate) fn hashrate_page(&self, ctx: &Ctx) -> Resp {
        let Some(base) = self.cfg.hash.renter.clone() else {
            return self.html_page("Hashrate", "Hashrate", ctx,
                "<p class=\"empty\">This box does not rent miners. The Lightning Stream app on Umbrel does.</p>", "");
        };
        let token = self.cfg.hash.renter_token.clone();
        let st = call(&base, &token, "GET", "/status", None);
        let csrf = App::csrf_input(ctx);
        let mut b = String::from("<p class=\"lead\">Rent miners from other people, by the piece of work they do, into your own DATUM Gateway. \
            You pay only for work your gateway accepts, a little at a time, and you can cut a rental at any moment.</p>");
        let st = match st {
            Ok(s) => s,
            Err(e) => {
                b.push_str(&App::error_box(&e));
                return self.html_page("Hashrate", "Hashrate", ctx, &b, "");
            }
        };
        // the buyer's own DATUM Gateway: where rented work goes
        let datum = st["datum"]["addr"].as_str().unwrap_or("");
        let ready = st["datum"]["reachable"] == true;
        let found: Vec<String> = st["datum"]["found"].as_array().map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default();
        let (class, head, next) = if datum.is_empty() {
            ("warn", "No DATUM Gateway yet", "Rented work goes to your own DATUM Gateway, which builds the blocks and is paid through your pool. Set its address below.")
        } else if !ready {
            ("bad", "Can't reach your DATUM Gateway", "Check that it is running, and that its address below is right.")
        } else {
            ("good", "Ready to rent", "")
        };
        b.push_str(&format!("<section class=\"status {class}\" aria-live=\"polite\"><p class=\"status-head\">{head}</p>{}</section>",
                            if next.is_empty() { String::new() } else { format!("<p>{next}</p>") }));

        // the rentals going on and the last ones
        let rentals: Vec<Value> = st["rentals"].as_array().cloned().unwrap_or_default();
        if !rentals.is_empty() {
            b.push_str("<h2>Your rentals</h2><div class=\"stack\">");
            for r in rentals.iter().take(10) {
                b.push_str(&rental_card(ctx, r, "./hashrate"));
            }
            b.push_str("</div>");
        }

        // the offers: the main action
        b.push_str("<h2>Miners for rent</h2>");
        match call(&base, &token, "GET", "/offers", None) {
            Err(e) => b.push_str(&App::error_box(&e)),
            Ok(o) => {
                let offers: Vec<Value> = o["offers"].as_array().cloned().unwrap_or_default();
                if offers.is_empty() {
                    b.push_str("<p class=\"empty\">No miners for rent found right now. Sellers publish their offers on Nostr; look again in a while.</p>");
                }
                b.push_str("<div class=\"grid services\">");
                for x in &offers {
                    let price = num(&x["priceMsat"]) / 1000.0;
                    let slice = num(&x["sliceWork"]);
                    let free = x["freeMiners"].as_u64().unwrap_or(0);
                    let total = x["miners"].as_u64().unwrap_or(0);
                    let free_hs = num(&x["freeHs"]);
                    let per_miner = if free > 0 && free_hs > 0.0 { free_hs / free as f64 } else { EXAMPLE_HS };
                    let budget = per_hour(price, slice, per_miner).ceil().max(price) as u64;
                    let can = ready && (free > 0 || total == 0);
                    b.push_str(&format!("<section class=\"card offer\"><span class=\"pill cat-media\">Hashrate</span><h3>{}</h3>\
                        <p class=\"price\">{} a piece of work</p><p class=\"small\">About <strong>{}</strong> an hour for each {} of speed · {}</p>\
                        <form method=\"post\" action=\"./hashrate\">{csrf}<input type=\"hidden\" name=\"action\" value=\"rent\"><input type=\"hidden\" name=\"key\" value=\"{}\">\
                        <div class=\"price-row\"><label>Machines<input name=\"miners\" value=\"1\" inputmode=\"numeric\" pattern=\"[0-9]+\" required></label>\
                        <label>For how long, in minutes<input name=\"minutes\" value=\"60\" inputmode=\"numeric\" pattern=\"[0-9]+\" required></label></div>\
                        <label>The most it may cost, in sats<input name=\"budget\" value=\"{budget}\" inputmode=\"numeric\" pattern=\"[0-9]+\" required></label>\
                        <p class=\"hint\">About an hour of one machine. The rental ends when this much is spent.</p>\
                        <button{}>Rent</button></form></section>",
                        esc(x["name"].as_str().unwrap_or("Miners")), sats_n(price), sats_n(per_hour(price, slice, 1e12)), "1 TH/s",
                        if total > 0 { format!("{free} of {total} machines free, {}", speed(free_hs)) } else { "free machines not given".into() },
                        esc(x["linkKey"].as_str().unwrap_or("")), if can { "" } else { " disabled" }));
                }
                b.push_str("</div>");
            }
        }

        // the DATUM Gateway's address
        b.push_str(&format!("<section class=\"card\"><h2>Your DATUM Gateway</h2><form method=\"post\" action=\"./hashrate\">{csrf}\
            <input type=\"hidden\" name=\"action\" value=\"datum\">\
            <label>Its address, with the port your miners use<input name=\"addr\" value=\"{}\" class=\"mono\" required placeholder=\"datum-gateway:23334\" \
            pattern=\"[A-Za-z0-9.\\-\\[\\]:_]+:[0-9]+\" title=\"An address with its port, like 192.168.1.20:23334\"></label>{}\
            <p class=\"hint\">The pool your rented work is paid through is chosen in your DATUM Gateway, not here.</p>\
            <button class=\"secondary\">Save</button></form>\
            <p class=\"small\">No DATUM Gateway yet? <a href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\">How to set one up</a> (it suggests Lazarus Pool).</p></section>",
            esc(datum), if found.is_empty() || found.iter().any(|f| f == datum) { String::new() } else { format!("<p class=\"hint\">Found on this box: <code>{}</code></p>", esc(&found.join(", "))) },
            esc(&self.cfg.hash.datum_guide)));
        self.html_page("Hashrate", "Hashrate", ctx, &b, "")
    }

    pub(crate) fn hashrate_post(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let back = if f.get("back").is_some_and(|b| b == "connections") { "./connections" } else { "./hashrate" };
        let Some(base) = self.cfg.hash.renter.clone() else {
            self.flash(ctx, false, "This box does not rent miners.");
            return Resp::redirect(back);
        };
        let token = self.cfg.hash.renter_token.clone();
        let g = |k: &str| f.get(k).map(|s| s.trim().to_string()).unwrap_or_default();
        let n = |k: &str| g(k).parse::<u64>().unwrap_or(0);
        let r: Result<String, String> = match g("action").as_str() {
            "rent" => {
                if n("budget") == 0 {
                    Err("Set the most this rental may cost.".into())
                } else {
                    call(&base, &token, "POST", "/rent", Some(&json!({"linkKey": g("key"), "miners": n("miners").max(1), "budgetSats": n("budget"), "minutes": n("minutes").max(1)})))
                        .and_then(|v| match v["rental"].as_str() {
                            Some(_) => Ok("Renting. The miners start on your DATUM Gateway in a few seconds; you pay as their work is accepted.".into()),
                            None => Err(v["error"].as_str().map(|e| format!("Not rented: {e}.")).unwrap_or_else(|| "Not rented.".into())),
                        })
                }
            }
            "cut" => call(&base, &token, "POST", "/cut", Some(&json!({"rental": g("rental")})))
                .and_then(|v| if v["ok"] == true { Ok("Cut. The miners stop working for you and payments stop.".into()) } else { Err("That rental had ended already.".into()) }),
            "datum" => call(&base, &token, "POST", "/datum", Some(&json!({"addr": g("addr")}))).and_then(|v| {
                if v["ok"] != true {
                    Err(v["error"].as_str().map(|e| format!("Not saved: {e}.")).unwrap_or_else(|| "Not saved.".into()))
                } else if v["reachable"] == true {
                    Ok("Saved. Your DATUM Gateway answers.".into())
                } else {
                    Ok("Saved, but nothing answers at that address yet. Check that your DATUM Gateway is running.".into())
                }
            }),
            _ => Err("Unknown action.".into()),
        };
        match r {
            Ok(m) => self.flash(ctx, true, m),
            Err(e) => self.flash(ctx, false, e),
        }
        Resp::redirect(back)
    }
}

/// One rental, as the renter sees it.
fn rental_card(ctx: &Ctx, r: &Value, _action: &str) -> String {
    let live = &r["live"];
    let ended = r["ended"] == true || !live["closed"].is_null();
    let id = r["rental"].as_str().unwrap_or("");
    let hs = num(&live["lastRate"]["hs"]);
    let paid = live["paidSlices"].as_u64().unwrap_or(0);
    let spent = num(&live["spentMsat"]) / 1000.0;
    let pill = if ended { "<span class=\"pill\">Ended</span>".to_string() } else { "<span class=\"pill good\">Hashing</span>".to_string() };
    let why = live["closed"].as_str().map(|w| format!("<p class=\"hint\">{}</p>", esc(&ended_words(w)))).unwrap_or_default();
    let cut = if ended {
        String::new()
    } else {
        format!("<form method=\"post\" action=\"./hashrate\">{}<input type=\"hidden\" name=\"action\" value=\"cut\"><input type=\"hidden\" name=\"rental\" value=\"{}\">\
                 <input type=\"hidden\" name=\"back\" value=\"{}\"><button class=\"danger\">Cut</button></form>",
                App::csrf_input(ctx), esc(id), if _action.contains("connections") { "connections" } else { "hashrate" })
    };
    format!("<section class=\"card live\"><div class=\"offer-head\"><h3>Hashrate from {}</h3>{pill}</div>\
             <p>Spent so far: <span class=\"money\">{}</span> of {} · {} piece{} of work paid · {} on {} machine{}</p>{why}<div class=\"row\">{cut}</div></section>",
            esc(r["hasher"].as_str().unwrap_or("a seller")), sats_n(spent), sats_n(num(&r["budgetSats"])), paid, if paid == 1 { "" } else { "s" },
            speed(hs), live["miners"].as_u64().unwrap_or(0), if live["miners"].as_u64() == Some(1) { "" } else { "s" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn speeds_and_prices_read_plainly() {
        assert_eq!(speed(4.1e12), "4.10 TH/s");
        assert_eq!(speed(8.5e11), "850.00 GH/s");
        assert_eq!(speed(0.0), "—");
        // 40 sats a piece of 2^47 hashes, at 4 TH/s: about 4,093 sats an hour
        let h = per_hour(40.0, SLICE_WORK as f64, 4e12);
        assert!((h - 4093.0).abs() < 1.0, "{h}");
        assert_eq!(sats_n(4093.4), "4,093 sats");
        assert_eq!(sats_n(1.0), "1 sat");
        assert_eq!(ended_words("hasher closed: unpaid"), "A piece of work was not paid in time.");
        assert_eq!(ended_words("cut by the buyer"), "You cut it.");
    }
}
