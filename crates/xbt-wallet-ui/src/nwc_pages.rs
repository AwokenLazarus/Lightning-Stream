//! Connected apps: Nostr Wallet Connect connections, made, listed and revoked on the NWC wallet
//! service's admin socket (`XBT_UI_NWC_SOCK`, the `xbt-nwc` service).
//!
//! A new connection's URI holds the app's secret. The service does not keep that secret, and this
//! process does not either: the URI is in the one answer to the form that made it, sent with
//! `Cache-Control: no-store`, and nowhere else (not in the session, not in a flash, not in a log).
use std::collections::HashMap;

use serde_json::{json, Value};

use super::{App, Ctx};
use crate::html::{esc, int, sats, txt, utc};
use crate::link::SignerLink;
use crate::server::Resp;

/// The methods a connection may be allowed, with what each lets the app do.
const METHODS: [(&str, &str); 5] = [
    ("pay_invoice", "Pay XBT Lightning invoices, within the budget and your policy"),
    ("get_balance", "See what it may still spend"),
    ("get_info", "See the network and the methods it has"),
    ("lookup_invoice", "Look up its own payments"),
    ("list_transactions", "List its own payments"),
];

const EXPIRIES: [(i64, &str); 5] = [(86_400, "1 day"), (7 * 86_400, "7 days"), (30 * 86_400, "30 days"), (90 * 86_400, "90 days"), (0, "Never")];

impl App {
    fn nwc(&self) -> Option<SignerLink> {
        self.cfg.nwc_sock.clone().map(|s| SignerLink::new(s, std::time::Duration::from_secs(30)))
    }

    pub(crate) fn apps_page(&self, ctx: &Ctx) -> Resp {
        let body = self.apps_html(ctx, None);
        self.page("Apps", ctx, body)
    }

    fn apps_html(&self, ctx: &Ctx, made: Option<(&Value, &str)>) -> String {
        let mut b = String::from("<p class=\"lead\">Let another app, such as a phone wallet or a browser extension, pay through this wallet, \
            each with its own budget and expiry. (For AI agents, see <a href=\"./agents\">AI agents</a>.)</p>");
        if let Some((c, uri)) = made {
            b.push_str(&format!(
                "<section class=\"card\"><h2>Connection made: {}</h2>\
                 <p class=\"hint warn\">This is the only time the connection string is shown. Copy it into the app now (paste it, or \
                 scan it there); nobody can show it again, and anyone who has it can spend up to this connection's budget. If it is lost, \
                 revoke the connection and make a new one.</p>\
                 <label>Connection string<input id=\"nwc-uri\" class=\"mono\" readonly value=\"{}\"></label>\
                 <div class=\"row\"><button type=\"button\" data-copy=\"nwc-uri\">Copy</button></div></section>",
                esc(&txt(c.get("name"))), esc(uri)));
        }
        let Some(link) = self.nwc() else {
            b.push_str("<section class=\"card\"><p class=\"empty\">Connecting other apps is not set up on this box.</p>\
                        <p>When it is, other apps can pay through this wallet, each with its own budget, expiry and allowed actions.</p>\
                        <details><summary>Technical details</summary><p>Run the Nostr Wallet Connect service (<code>xbt-nwc</code>) beside the signer \
                        and point <code>XBT_UI_NWC_SOCK</code> at its admin socket.</p></details></section>");
            return b;
        };
        let status = link.call("nwc_status", json!({}));
        let list = link.call("nwc_list", json!({}));
        let (status, list) = match (status, list) {
            (Ok(s), Ok(l)) => (s, l),
            (Err(e), _) | (_, Err(e)) => {
                b.push_str(&Self::error_box(&format!("The service that connects apps does not answer: {e}")));
                return b;
            }
        };
        b.push_str(&new_form(ctx, &status));
        b.push_str(&list_html(ctx, &list));
        b.push_str(&relays_html(&status));
        b
    }

    pub(crate) fn apps_create(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let g = |k: &str| f.get(k).map(|v| v.trim().to_string()).unwrap_or_default();
        let Some(link) = self.nwc() else {
            self.flash(ctx, false, "Nostr Wallet Connect is not set up on this box.");
            return Resp::redirect("./apps");
        };
        let budget = g("budget_sats_per_day").parse::<i64>().unwrap_or(0);
        let expires_in_s = g("expires_in_s").parse::<i64>().unwrap_or(-1);
        if !EXPIRIES.iter().any(|(s, _)| *s == expires_in_s) {
            self.flash(ctx, false, "Choose when the connection expires.");
            return Resp::redirect("./apps");
        }
        let methods: Vec<&str> = METHODS.iter().filter(|(m, _)| f.get(&format!("m_{m}")).is_some_and(|v| v == "1")).map(|(m, _)| *m).collect();
        let relays: Vec<String> = g("relays").split(|c: char| c == '\n' || c == ',' || c.is_whitespace())
            .map(str::trim).filter(|r| !r.is_empty()).map(str::to_string).collect();
        let p = json!({"name": g("name"), "budget_sats_per_day": budget, "expires_in_s": expires_in_s, "methods": methods, "relays": relays});
        match link.call("nwc_create", p) {
            Ok(r) => match r.get("uri").and_then(Value::as_str) {
                Some(uri) => {
                    let body = self.apps_html(ctx, Some((&r["connection"], uri)));
                    self.page("Apps", ctx, body)
                }
                None => {
                    self.flash(ctx, false, "The NWC wallet service made no connection string.");
                    Resp::redirect("./apps")
                }
            },
            Err(e) => {
                self.flash(ctx, false, format!("Not made: {e}"));
                Resp::redirect("./apps")
            }
        }
    }

    pub(crate) fn apps_revoke(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let id = f.get("id").map(|s| s.trim().to_string()).unwrap_or_default();
        match self.nwc().map(|l| l.call("nwc_revoke", json!({"id": id}))) {
            None => self.flash(ctx, false, "Nostr Wallet Connect is not set up on this box."),
            Some(Ok(_)) => self.flash(ctx, true, "Revoked. That app can no longer use this wallet; its requests go unanswered from now on."),
            Some(Err(e)) => self.flash(ctx, false, format!("Not revoked: {e}")),
        }
        Resp::redirect("./apps")
    }
}

fn new_form(ctx: &Ctx, status: &Value) -> String {
    let relays: Vec<String> = status.get("default_relays").and_then(Value::as_array).into_iter().flatten().map(|r| txt(Some(r))).collect();
    let mut methods = String::new();
    for (m, what) in METHODS {
        methods.push_str(&format!("<label class=\"check\" title=\"{m}\"><input type=\"checkbox\" name=\"m_{m}\" value=\"1\" checked> {}</label>",
                                  esc(what)));
    }
    let mut expiry = String::new();
    for (s, name) in EXPIRIES {
        expiry.push_str(&format!("<option value=\"{s}\"{}>{name}</option>", if s == 30 * 86_400 { " selected" } else { "" }));
    }
    format!("<section class=\"card primary\"><h2>Connect an app</h2>\
             <p>The app gets a connection string to paste or scan (Nostr Wallet Connect). Every payment it makes keeps to your spending rules \
             and to the connection's own budget. It never holds a key of this wallet, and this wallet holds nobody else's money. \
             Receiving payments this way is not offered yet.</p>\
             <form method=\"post\" action=\"./apps-create\" class=\"stack\">{}\
             <label>Name (for you)<input name=\"name\" maxlength=\"64\" placeholder=\"Phone wallet\" required></label>\
             <label>Budget (sats per 24 hours)<input name=\"budget_sats_per_day\" type=\"number\" min=\"1\" step=\"1\" value=\"1000\" required></label>\
             <label>Expires after<select name=\"expires_in_s\">{expiry}</select></label>\
             <fieldset><legend>The app may</legend>{methods}</fieldset>\
             <details><summary>Advanced</summary><label>Relays the app's messages go through (one per line, <code>wss://</code>)\
             <textarea name=\"relays\" rows=\"3\">{}</textarea></label></details>\
             <button type=\"submit\">Make the connection</button></form></section>",
            App::csrf_input(ctx), esc(&relays.join("\n")))
}

fn list_html(ctx: &Ctx, list: &Value) -> String {
    let cs = list.get("connections").and_then(Value::as_array).cloned().unwrap_or_default();
    if cs.is_empty() {
        return "<section class=\"card\"><h2>Connected apps</h2><p class=\"empty\">No app is connected.</p></section>".into();
    }
    let mut rows = String::new();
    for c in &cs {
        let expires = int(c.get("expires_at"));
        let expiry = if c["expired"] == true {
            "<span class=\"tag bad\">expired</span>".to_string()
        } else if expires == 0 {
            "never".to_string()
        } else {
            utc(expires)
        };
        let methods: Vec<String> = c.get("methods").and_then(Value::as_array).into_iter().flatten().map(|m| esc(&txt(Some(m)))).collect();
        let relays: Vec<String> = c.get("relays").and_then(Value::as_array).into_iter().flatten().map(|m| esc(&txt(Some(m)))).collect();
        let last = int(c.get("last_used"));
        let pending = int(c.get("pending_payments"));
        rows.push_str(&format!(
            "<tr><td>{}<div class=\"small\">since {}</div></td><td>{}</td><td>{}<div class=\"small\">of {} a day{}</div></td><td>{}</td>\
             <td class=\"small\">{}</td><td class=\"small\">{}</td><td>{}</td>\
             <td><form method=\"post\" action=\"./apps-revoke\" class=\"inline\">{}<input type=\"hidden\" name=\"id\" value=\"{}\">\
             <button class=\"danger\" type=\"submit\">Revoke</button></form></td></tr>",
            esc(&txt(c.get("name"))), utc(int(c.get("created_at"))), expiry, sats(int(c.get("spent_24h_sats"))), sats(int(c.get("budget_sats_per_day"))),
            if pending > 0 { format!(", {pending} in flight") } else { String::new() }, sats(int(c.get("spent_total_sats"))), methods.join(" "),
            relays.join("<br>"), if last > 0 { utc(last) } else { "never".into() }, App::csrf_input(ctx), esc(&txt(c.get("id")))));
    }
    format!("<section class=\"card\"><h2>Connected apps</h2><div class=\"scroll\"><table><thead><tr><th>App</th><th>Expires</th>\
             <th>Spent (24 h)</th><th>Spent in all</th><th>May</th><th>Relays</th><th>Last used</th><th></th></tr></thead><tbody>{rows}</tbody>\
             </table></div><p class=\"small\">Revoking takes effect at once: the service stops answering that app.</p></section>")
}

fn relays_html(status: &Value) -> String {
    let rs = status.get("relays").and_then(Value::as_array).cloned().unwrap_or_default();
    if rs.is_empty() {
        return String::new();
    }
    let mut items = String::new();
    for r in &rs {
        let state = if r["connected"] == true { "<span class=\"tag ok\">connected</span>" } else { "<span class=\"tag warn\">not connected</span>" };
        let err = r.get("last_error").filter(|e| !e.is_null()).map(|e| format!(" <span class=\"small\">{}</span>", esc(&txt(Some(e))))).unwrap_or_default();
        items.push_str(&format!("<li><code>{}</code> {state}{err}</li>", esc(&txt(r.get("url")))));
    }
    format!("<details class=\"card\"><summary>Relays</summary><ul>{items}</ul></details>")
}
