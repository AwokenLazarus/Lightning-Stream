//! Settings, Stream relays: the relays a direct link falls back to ([`crate::relaynet`]), the
//! owner's choices among them, and, for an owner who runs one, a guide and a button to announce it.
use std::collections::HashMap;

use super::{App, Ctx};
use crate::html::esc;
use crate::server::Resp;
use xbt_nostr::relays::{self, Offer};

/// Where the setup guide lives.
pub const GUIDE: &str = "https://github.com/AwokenLazarus/Lightning-Stream/blob/main/docs/RUN-A-RELAY.md";

impl App {
    pub(crate) fn relays_page(&self, ctx: &Ctx, q: &HashMap<String, String>) -> Resp {
        let net = &self.relay_net;
        let snap = net.get(q.get("refresh").is_some_and(|v| v == "1"));
        let prefs = net.prefs();
        let selected = net.selected(&prefs);
        let for_video = net.selected_for(&prefs, xbt_nostr::relays::Purpose::Throughput);
        let mut b = String::from("<p>When your app and a seller's can't connect directly (some routers and VPNs don't allow it), a <strong>relay</strong> \
            passes the traffic between them. It can't read anything: the connection is encrypted from one app to the other. \
            It does see both addresses and how much passes.</p>");
        let in_use = if selected.is_empty() {
            "<p>None of the relays you allow is answering, so the app falls back to iroh's public relays.</p>".to_string()
        } else {
            format!("<p class=\"small\">Tried in this order: the first is your home relay.</p><ol>{}</ol>",
                    selected.iter().map(|u| format!("<li><code>{}</code></li>", esc(u))).collect::<String>())
        };
        let in_use = if for_video != selected && !for_video.is_empty() {
            format!("{in_use}<p class=\"small\">For video, files and VPN exits, where what a relay can carry matters more than how quickly \
                     it answers: {}</p>", for_video.iter().map(|u| format!("<code>{}</code>", esc(u))).collect::<Vec<_>>().join(", "))
        } else { in_use };
        b.push_str(&format!("<section class=\"card\"><h2>In use now</h2>{in_use}\
            <p class=\"small\"><a href=\"./relays?refresh=1\">Check the relays again</a></p></section>"));
        // known relays
        let mut known: Vec<String> = vec![net.default_relay().to_string()];
        for u in prefs.own.iter().chain(&prefs.pinned).chain(&prefs.blocked).cloned().chain(snap.announced.iter().map(|a| a.relay.clone())) {
            if !known.contains(&u) {
                known.push(u);
            }
        }
        b.push_str("<section class=\"card\"><h2>Relays this app knows</h2><ul class=\"offers\">");
        for u in &known {
            let ann = snap.announced.iter().find(|a| &a.relay == u);
            let region = ann.map(|a| a.region.as_str()).unwrap_or(if u == net.default_relay() { "default" } else { "" });
            let probe = snap.probes.get(u).copied().unwrap_or_default();
            let health = match (probe.rtt_ms, prefs.blocked.contains(u)) {
                (_, true) => "<span class=\"pill\">blocked</span>".to_string(),
                (Some(ms), _) if probe.healthy() => format!("{ms} ms"),
                _ => format!("<span class=\"pill warn\" title=\"{}\">not answering</span>", esc(snap.errors.get(u).map(String::as_str).unwrap_or(""))),
            };
            let tags = [(prefs.pinned.contains(u), "pinned"), (prefs.own.contains(u), "yours")].iter().filter(|(on, _)| *on)
                .map(|(_, t)| format!(" <span class=\"pill\">{t}</span>")).collect::<String>();
            let (pin_a, pin_l) = if prefs.pinned.contains(u) { ("unpin", "Unpin") } else { ("pin", "Prefer") };
            let (block_a, block_l) = if prefs.blocked.contains(u) { ("unblock", "Allow") } else { ("block", "Block") };
            let buttons = format!("<form method=\"post\" action=\"./relays-prefs\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
                <input type=\"hidden\" name=\"relay\" value=\"{}\">\
                <button type=\"submit\" name=\"action\" value=\"{pin_a}\" class=\"secondary\">{pin_l}</button> \
                <button type=\"submit\" name=\"action\" value=\"{block_a}\" class=\"secondary\">{block_l}</button></form>", esc(&ctx.csrf), esc(u));
            let place = if region.is_empty() { String::new() } else { format!("{} · ", esc(region)) };
            b.push_str(&format!("<li><p><code>{}</code>{tags}</p><p class=\"small\">{place}{health}</p>{buttons}</li>", esc(u)));
        }
        b.push_str("</ul>");
        if !net.nostr_enabled() {
            b.push_str("<p class=\"small\">No Nostr relays are set, so relays others announce are not listed.</p>\
                        <details><summary>Technical details</summary><p class=\"small\">Set <code>XBT_UI_NOSTR_RELAYS</code> to read relay announcements.</p></details>");
        } else {
            let up = snap.nostr.iter().filter(|o| o.result.is_ok()).count();
            b.push_str(&format!("<p class=\"small\">{} relays announced on {up} of {} Nostr relays", snap.announced.len(), snap.nostr.len()));
            if snap.refused > 0 {
                b.push_str(&format!("; {} announcements failed a check and are not shown", snap.refused));
            }
            b.push_str(".</p>");
        }
        b.push_str(&format!("<details><summary>Use only your own relays</summary><form method=\"post\" action=\"./relays-prefs\" class=\"stack\">\
            <input type=\"hidden\" name=\"csrf\" value=\"{0}\"><label>Your relay's address <input name=\"relay\" placeholder=\"https://relay.example.com\"></label>\
            <input type=\"hidden\" name=\"action\" value=\"own-add\"><button type=\"submit\" class=\"secondary\">Add as yours</button></form>\
            <form method=\"post\" action=\"./relays-prefs\"><input type=\"hidden\" name=\"csrf\" value=\"{0}\">\
            <input type=\"hidden\" name=\"action\" value=\"{1}\"><button type=\"submit\" class=\"secondary\">{2}</button></form>\
            <p class=\"small\">With only your own relays, the app never uses ours or anyone else's, even when yours don't answer.</p></details></section>",
            esc(&ctx.csrf), if prefs.only_own { "only-own-off" } else { "only-own-on" },
            if prefs.only_own { "Use any relay again" } else { "Use only my own relays" }));
        // run one
        b.push_str(&format!("<section class=\"card\"><h2>Run a Stream relay</h2>\
            <p>A relay adds capacity for everyone whose router blocks direct connections. It needs a server with a public address, \
            usually a small rented server (VPS): port 443 open, and a domain name. Running one is free for now; paying relays for what \
            they carry is planned.</p><p><a href=\"{GUIDE}\">The setup guide</a> walks through it step by step.</p>\
            <details><summary>Announce your relay</summary><form method=\"post\" action=\"./relays-publish\" class=\"stack\">\
            <input type=\"hidden\" name=\"csrf\" value=\"{}\">\
            <label>Your relay's address <input name=\"relay\" required placeholder=\"https://relay.example.com\"></label>\
            <label>Where it runs <input name=\"region\" required maxlength=\"{}\" placeholder=\"eu-central\"></label>\
            <label>What it can carry, in Mbit/s (optional) <input name=\"capacity_mbit\" inputmode=\"numeric\"></label>\
            <label><input type=\"checkbox\" name=\"udp\" value=\"1\"> It also answers on UDP (helps direct connections)</label>\
            <label>How to reach you (optional) <input name=\"contact\" maxlength=\"{}\"></label>\
            <button type=\"submit\">Announce</button></form>\
            <p class=\"small\">The announcement is signed with a key this app keeps for it, and lasts 30 days; announce again to keep it listed. \
            Apps check every relay themselves before using it.</p></details></section>",
            esc(&ctx.csrf), relays::MAX_REGION, relays::MAX_CONTACT));
        self.html_page("Settings", "Stream relays", ctx, &b, "")
    }

    /// `POST /relays-prefs`: prefer, block, add as yours, only own.
    pub(crate) fn relays_prefs(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let net = &self.relay_net;
        let mut p = net.prefs();
        let action = f.get("action").map(String::as_str).unwrap_or("");
        let relay = f.get("relay").map(|s| s.trim()).unwrap_or("");
        let url = if matches!(action, "only-own-on" | "only-own-off") { String::new() } else {
            match relays::canonical_relay(relay) {
                Ok(u) => u,
                Err(e) => {
                    self.flash(ctx, false, e);
                    return Resp::redirect("./relays");
                }
            }
        };
        let add = |v: &mut Vec<String>, u: &str| if !v.iter().any(|x| x == u) { v.push(u.to_string()) };
        match action {
            "pin" => { add(&mut p.pinned, &url); p.blocked.retain(|x| x != &url) }
            "unpin" => p.pinned.retain(|x| x != &url),
            "block" => { add(&mut p.blocked, &url); p.pinned.retain(|x| x != &url) }
            "unblock" => p.blocked.retain(|x| x != &url),
            "own-add" => { add(&mut p.own, &url); p.blocked.retain(|x| x != &url) }
            "only-own-on" if p.own.is_empty() => {
                self.flash(ctx, false, "Add your own relay first.");
                return Resp::redirect("./relays");
            }
            "only-own-on" => p.only_own = true,
            "only-own-off" => p.only_own = false,
            _ => {
                self.flash(ctx, false, "Unknown choice.");
                return Resp::redirect("./relays");
            }
        }
        match net.save(&p) {
            Ok(()) => self.flash(ctx, true, "Saved. Connections opened from now on use it."),
            Err(e) => self.flash(ctx, false, e),
        }
        Resp::redirect("./relays")
    }

    /// `POST /relays-publish`: announce the owner's relay on their Nostr relays.
    pub(crate) fn relays_publish(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let g = |k: &str| f.get(k).map(|s| s.trim().to_string()).unwrap_or_default();
        let capacity = match g("capacity_mbit") {
            s if s.is_empty() => None,
            s => match s.parse::<u32>() {
                Ok(n) => Some(n),
                Err(_) => {
                    self.flash(ctx, false, "What it can carry is a whole number of Mbit/s.");
                    return Resp::redirect("./relays");
                }
            },
        };
        let offer = Offer { relay: g("relay"), region: g("region"), capacity_mbit: capacity, udp: g("udp") == "1", contact: g("contact"),
                            note: String::new(), ttl_s: relays::MAX_TTL_S };
        match self.relay_net.publish(&offer) {
            Ok((ok, all)) if ok > 0 => self.flash(ctx, true, format!("Announced on {ok} of {} Nostr relays. It is listed as yours here.", all.len())),
            Ok((_, all)) => self.flash(ctx, false, format!("No Nostr relay accepted the announcement: {}",
                all.iter().filter_map(|o| o.result.as_ref().err().map(|e| format!("{}: {e}", o.relay))).collect::<Vec<_>>().join("; "))),
            Err(e) => self.flash(ctx, false, e),
        }
        Resp::redirect("./relays")
    }
}
