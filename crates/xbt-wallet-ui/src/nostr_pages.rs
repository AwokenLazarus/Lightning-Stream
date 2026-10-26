//! Browse, Nostr: sellers whose signed listings the owner's relays hold (`XBT_UI_NOSTR_RELAYS`),
//! shown apart from the services file and marked unvetted, with a Check button that asks the
//! seller itself whether the listing is its own ([`crate::nostr`]).
use std::collections::HashMap;

use super::{App, Ctx};
use crate::html::esc;
use crate::nostr::{self, Snapshot};
use crate::server::Resp;
use crate::services::{self, Kind};

impl App {
    pub(crate) fn nostr_page(&self, ctx: &Ctx, q: &HashMap<String, String>) -> Resp {
        if !self.nostr.enabled() {
            let body = "<div class=\"card\"><p class=\"empty\">No Nostr relays are set.</p>\
                        <p>Set <code>XBT_UI_NOSTR_RELAYS</code> to the relays to read sellers' listings from \
                        (<code>wss://</code> addresses, comma-separated). They are asked only when this page opens.</p></div>";
            return self.page("Browse", ctx, body.to_string());
        }
        let snap = self.nostr.get(q.get("refresh").is_some_and(|v| v == "1"));
        self.page("Browse", ctx, nostr_html(ctx, &snap))
    }

    /// `POST /nostr-check`: ask the seller whether the listing found on Nostr is its own.
    pub(crate) fn nostr_check(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let id = f.get("event").map(|s| s.trim().to_string()).unwrap_or_default();
        let snap = self.nostr.get(false);
        match snap.listings.iter().find(|n| n.event_id == id) {
            None => self.flash(ctx, false, "That listing is no longer on the relays. Reload the page."),
            Some(n) => match nostr::check(n) {
                Ok(_) => self.flash(ctx, true, format!("{} answers with the same receipt key: this listing is the seller's own.", n.listing.seller)),
                Err(e) => self.flash(ctx, false, format!("{}: {e}", n.listing.seller)),
            },
        }
        Resp::redirect("./nostr")
    }
}

fn nostr_html(ctx: &Ctx, snap: &Snapshot) -> String {
    let mut b = String::from("<p><a href=\"./browse\">Your services</a> · <strong>Nostr</strong> · <a href=\"./nostr?refresh=1\">Ask the relays again</a></p>\
        <div class=\"flash bad\">Unvetted. These sellers published their listings on Nostr. Each listing is signed by the key the seller \
        signs receipts with, but nobody has checked who the seller is. Check one before you pay it: the app then asks the seller's own \
        address whether it uses that key. Payments still keep to your policy and budgets.</div>");
    let up = snap.relays.iter().filter(|r| r.result.is_ok()).count();
    b.push_str(&format!("<p class=\"small\">{up} of {} relays answered", snap.relays.len()));
    if snap.refused > 0 {
        b.push_str(&format!("; {} listings failed a signature check and are not shown", snap.refused));
    }
    b.push_str(".</p>");
    for r in snap.relays.iter().filter(|r| r.result.is_err()) {
        b.push_str(&format!("<p class=\"small\">{}: {}</p>", esc(&r.relay), esc(r.result.as_ref().err().map(String::as_str).unwrap_or(""))));
    }
    if snap.listings.is_empty() {
        b.push_str("<p class=\"empty\">No Lightning Stream listings on these relays.</p>");
        return b;
    }
    for n in &snap.listings {
        let s = nostr::to_service(n);
        b.push_str(&format!("<section class=\"card\"><h2>{} <span class=\"tag\">{}</span> <span class=\"tag\">unvetted</span></h2><p>{}</p>\
                             <p class=\"small\">{}</p><p class=\"small\">Nostr key <code>{}</code>, receipt key <code>{}</code></p>\
                             <form method=\"post\" action=\"./nostr-check\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
                             <input type=\"hidden\" name=\"event\" value=\"{}\"><button type=\"submit\">Check with the seller</button></form>",
                            esc(&s.name), s.kind.as_str(), esc(&s.price_text), esc(&s.seller), esc(&n.author), esc(&n.listing.receipt_key),
                            esc(&ctx.csrf), esc(&n.event_id)));
        if !s.items.is_empty() {
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
