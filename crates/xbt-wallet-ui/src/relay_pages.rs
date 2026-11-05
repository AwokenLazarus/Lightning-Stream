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
        let own = self.builtin_relay_html(ctx);
        let prefill = self.builtin_relay_settings().filter(|r| r.enabled && !r.domain.is_empty()).map(|r| format!("https://{}", r.domain)).unwrap_or_default();
        b.push_str(&format!("<section class=\"card\"><h2>Run a relay for the Stream network</h2>\
            <p>A relay adds capacity for everyone whose router blocks direct connections. It needs a public address and port 443, \
            so it suits a small rented server (VPS) better than a box at home. Running one is free for now; paying relays for what \
            they carry is planned.</p>{own}<p><a href=\"{GUIDE}\">The setup guide</a> covers both ways: switching it on here, or \
            running the relay on its own.</p>\
            <details><summary>Announce a relay</summary><form method=\"post\" action=\"./relays-publish\" class=\"stack\">\
            <input type=\"hidden\" name=\"csrf\" value=\"{}\">\
            <label>Your relay's address <input name=\"relay\" required placeholder=\"https://relay.example.com\" value=\"{}\"></label>\
            <label>Where it runs <input name=\"region\" required maxlength=\"{}\" placeholder=\"eu-central\"></label>\
            <label>What it can carry, in Mbit/s (optional) <input name=\"capacity_mbit\" inputmode=\"numeric\"></label>\
            <label><input type=\"checkbox\" name=\"udp\" value=\"1\"> It also answers on UDP (helps direct connections)</label>\
            <label>How to reach you (optional) <input name=\"contact\" maxlength=\"{}\"></label>\
            <button type=\"submit\">Announce</button></form>\
            <p class=\"small\">The announcement is signed with a key this app keeps for it, and lasts a week; this app announces it again each day while it runs. \
            Apps check every relay themselves before using it.</p></details></section>",
            esc(&ctx.csrf), esc(&prefill), relays::MAX_REGION, relays::MAX_CONTACT));
        self.html_page("Stream relays", "Stream relays", ctx, &b, "")
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
                            note: String::new(), ttl_s: crate::relaynet::ANNOUNCE_TTL_S };
        match self.relay_net.publish(&offer) {
            Ok((ok, all)) if ok > 0 => self.flash(ctx, true, format!("Announced on {ok} of {} Nostr relays. It is listed as yours here.", all.len())),
            Ok((_, all)) => self.flash(ctx, false, format!("No Nostr relay accepted the announcement: {}",
                all.iter().filter_map(|o| o.result.as_ref().err().map(|e| format!("{}: {e}", o.relay))).collect::<Vec<_>>().join("; "))),
            Err(e) => self.flash(ctx, false, e),
        }
        Resp::redirect("./relays")
    }
}

/// What the built-in relay service reads (`relay.json`): the same fields as
/// `xbt_stream_relay::config::Settings`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BuiltinRelay {
    pub enabled: bool,
    pub domain: String,
    pub contact: String,
    pub udp: bool,
    pub port_forwarded: bool,
    pub attempt: u64,
}

fn gb(bytes: u64) -> String {
    format!("{:.2} GB", bytes as f64 / 1e9)
}

impl App {
    fn builtin_relay_settings(&self) -> Option<BuiltinRelay> {
        let dir = self.cfg.relay_dir.as_ref()?;
        let v: serde_json::Value = std::fs::read_to_string(dir.join("relay.json")).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        let st = |k: &str| v.get(k).and_then(serde_json::Value::as_str).unwrap_or("").to_string();
        let b = |k: &str| v.get(k).and_then(serde_json::Value::as_bool).unwrap_or(false);
        Some(BuiltinRelay { enabled: b("enabled"), domain: st("domain"), contact: st("contact"), udp: b("udp"), port_forwarded: b("port_forwarded"),
                            attempt: v.get("attempt").and_then(serde_json::Value::as_u64).unwrap_or(0) })
    }

    fn builtin_relay_status(&self) -> serde_json::Value {
        self.cfg.relay_status.as_ref().and_then(|p| std::fs::read_to_string(p).ok()).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }

    fn builtin_relay_html(&self, ctx: &Ctx) -> String {
        if let Some(why) = &self.cfg.relay_unavailable {
            return format!("<p class=\"flash warn\">This box can't run one: {}</p>", esc(why));
        }
        let Some(r) = self.builtin_relay_settings() else {
            return "<p class=\"small\">This package doesn't include the built-in relay. The Linux package does.</p>".into();
        };
        let st = self.builtin_relay_status();
        // the service rewrites its status every few seconds; an old one means it isn't running
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let fresh = st.get("written").and_then(serde_json::Value::as_u64).is_some_and(|t| now.saturating_sub(t) < 60);
        let (state, words) = if r.enabled && !fresh {
            ("stopped", match &self.cfg.relay_start_hint {
                Some(h) => format!("The relay service isn't running. To start it, {h}."),
                None => "The relay service isn't running.".to_string(),
            })
        } else {
            (st.get("state").and_then(serde_json::Value::as_str).unwrap_or(if r.enabled { "starting" } else { "off" }),
             st.get("message").and_then(serde_json::Value::as_str).unwrap_or("").to_string())
        };
        let words = words.as_str();
        let pill = match state {
            "running" => "<span class=\"pill\">running</span>",
            "off" => "<span class=\"pill\">off</span>",
            "checking" | "certifying" | "starting" => "<span class=\"pill warn\">starting</span>",
            _ => "<span class=\"pill warn\">needs attention</span>",
        };
        let mut b = format!("<h3>On this box {pill}</h3><p>{}</p>", esc(words));
        if let Some(checks) = st.pointer("/preflight/checks").and_then(serde_json::Value::as_array).filter(|_| fresh) {
            b.push_str("<ul class=\"offers\">");
            for c in checks {
                let mark = match c.get("level").and_then(serde_json::Value::as_str) { Some("pass") => "✓", Some("warn") => "!", _ => "✗" };
                b.push_str(&format!("<li>{mark} {}</li>", esc(c.get("words").and_then(serde_json::Value::as_str).unwrap_or(""))));
            }
            b.push_str("</ul>");
        }
        if state == "running" && fresh {
            let n = |k: &str| st.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0);
            b.push_str(&format!("<p class=\"small\">Carried {} out and {} in since it started · {} apps connected now{}</p>",
                                gb(n("bytes_sent")), gb(n("bytes_recv")), n("clients"),
                                if r.udp { " · answering on UDP 7842" } else { "" }));
        }
        let csrf = esc(&ctx.csrf);
        if r.enabled {
            b.push_str(&format!("<form method=\"post\" action=\"./relay-run\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                <button type=\"submit\" name=\"action\" value=\"off\" class=\"secondary\">Switch the relay off</button> \
                <button type=\"submit\" name=\"action\" value=\"retry\" class=\"secondary\">Try again</button></form>"));
        } else {
            b.push_str(&format!("<details><summary>Switch on a relay on this box</summary>\
                <form method=\"post\" action=\"./relay-run\" class=\"stack\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                <input type=\"hidden\" name=\"action\" value=\"on\">\
                <label>The relay's domain name <input name=\"domain\" required placeholder=\"relay.example.com\" value=\"{}\"></label>\
                <p class=\"small\">Point it at this box first: an A record to this box's public address (with Cloudflare, DNS only).</p>\
                <label>Your e-mail, for Let's Encrypt <input name=\"contact\" type=\"email\" required value=\"{}\"></label>\
                <label><input type=\"checkbox\" name=\"udp\" value=\"1\"{}> Also answer on UDP 7842 (helps direct connections; open it in the firewall too)</label>\
                <label><input type=\"checkbox\" name=\"port_forwarded\" value=\"1\"{}> TCP 443 is forwarded to this box (only behind a home router)</label>\
                <button type=\"submit\">Switch the relay on</button></form>\
                <p class=\"small\">Before asking Let's Encrypt for a certificate, the relay checks that the domain points here and that \
                port 443 is free and reachable. Let's Encrypt refuses a name for an hour after 5 failed tries, so it only asks when the checks pass.</p></details>",
                esc(&r.domain), esc(&r.contact), if r.udp { " checked" } else { "" }, if r.port_forwarded { " checked" } else { "" }));
        }
        b
    }

    /// `POST /relay-run`: switch the built-in relay on or off, or try again.
    pub(crate) fn relay_run(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let Some(dir) = self.cfg.relay_dir.clone().filter(|_| self.cfg.relay_unavailable.is_none()) else {
            self.flash(ctx, false, "This box has no built-in relay.");
            return Resp::redirect("./relays");
        };
        let mut r = self.builtin_relay_settings().unwrap_or_default();
        let g = |k: &str| f.get(k).map(|s| s.trim().to_string()).unwrap_or_default();
        match f.get("action").map(String::as_str) {
            Some("on") => {
                r = BuiltinRelay { enabled: true, domain: g("domain").to_ascii_lowercase(), contact: g("contact"), udp: g("udp") == "1",
                                   port_forwarded: g("port_forwarded") == "1", attempt: r.attempt };
                if let Err(e) = check_domain(&r.domain).and_then(|_| check_contact(&r.contact)) {
                    self.flash(ctx, false, e);
                    return Resp::redirect("./relays");
                }
            }
            Some("off") => r.enabled = false,
            Some("retry") => r.attempt += 1,
            _ => {
                self.flash(ctx, false, "Unknown choice.");
                return Resp::redirect("./relays");
            }
        }
        let v = serde_json::json!({"enabled": r.enabled, "domain": r.domain, "contact": r.contact, "udp": r.udp,
                                   "port_forwarded": r.port_forwarded, "attempt": r.attempt});
        let tmp = dir.join("relay.json.tmp");
        match std::fs::write(&tmp, format!("{v:#}\n")).and_then(|_| std::fs::rename(&tmp, dir.join("relay.json"))) {
            Ok(()) => self.flash(ctx, true, if r.enabled { "Saved. The relay checks the domain and port 443 now; this page shows how it goes." }
                                            else { "The relay is switching off." }),
            Err(e) => self.flash(ctx, false, format!("{}: {e}", dir.display())),
        }
        Resp::redirect("./relays")
    }
}

/// The same checks as the relay service's, so the owner hears at once.
pub fn check_domain(d: &str) -> Result<(), String> {
    if d.is_empty() || d.parse::<std::net::IpAddr>().is_ok() || !d.contains('.') || d.len() > 253
        || d.split('.').any(|l| l.is_empty() || l.len() > 63 || l.starts_with('-') || l.ends_with('-') || !l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')) {
        return Err("Enter the relay's full domain name, such as relay.example.com.".into());
    }
    if [".local", ".lan", ".internal", ".home.arpa"].iter().any(|t| d.ends_with(t)) {
        return Err("That name only works on your home network: a relay needs a public domain name.".into());
    }
    Ok(())
}

pub fn check_contact(c: &str) -> Result<(), String> {
    let ok = c.len() <= 128 && c.split_once('@').is_some_and(|(u, h)| !u.is_empty() && h.contains('.') && !h.starts_with('.')) && !c.chars().any(char::is_whitespace);
    if ok { Ok(()) } else { Err("Enter an e-mail address Let's Encrypt can write to about the certificate.".into()) }
}
