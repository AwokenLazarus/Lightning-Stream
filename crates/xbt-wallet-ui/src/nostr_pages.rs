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
                        <p>Sellers can publish their lists on Nostr. To look there, the app needs the addresses of some Nostr relays.</p>\
                        <details><summary>Technical details</summary><p>Set <code>XBT_UI_NOSTR_RELAYS</code> to the relays to read sellers' listings from \
                        (<code>wss://</code> addresses, comma-separated). They are asked only when this page opens.</p></details></div>";
            return self.html_page("Browse", "Found on Nostr", ctx, body, "");
        }
        let snap = self.nostr.get(q.get("refresh").is_some_and(|v| v == "1"));
        self.html_page("Browse", "Found on Nostr", ctx, &nostr_html(ctx, &snap), "")
    }

    /// `POST /nostr-check`: ask the seller whether the listing found on Nostr is its own.
    pub(crate) fn nostr_check(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let id = f.get("event").map(|s| s.trim().to_string()).unwrap_or_default();
        let snap = self.nostr.get(false);
        match snap.listings.iter().find(|n| n.event_id == id) {
            None => self.flash(ctx, false, "That listing is no longer on the relays. Reload the page."),
            Some(n) => match nostr::check(n) {
                Ok(_) => self.flash(ctx, true, format!("{} confirms this listing is its own: it signs with the same key.", n.listing.seller)),
                Err(e) => self.flash(ctx, false, format!("{}: {e}", n.listing.seller)),
            },
        }
        Resp::redirect("./nostr")
    }
}

fn nostr_html(ctx: &Ctx, snap: &Snapshot) -> String {
    let mut b = String::from("<p class=\"small\"><a href=\"./browse\">← Your services</a> · <a href=\"./nostr?refresh=1\">Look again</a></p>\
        <div class=\"flash warn\"><strong>Unvetted.</strong> These sellers published their lists on Nostr. Each list is signed by the seller's \
        own key, but nobody has checked who the seller is. Check one before you pay it: the app then asks the seller's own address whether \
        the list is theirs. Payments still keep to your spending rules.</div>");
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
        b.push_str(&format!("<section class=\"card\"><div class=\"offer-head\"><h2>{}</h2><span class=\"pill warn\">unvetted</span></div>\
                             <p class=\"small\">{}</p><details><summary>Keys</summary><p class=\"small\">Nostr key <code>{}</code>, receipt key <code>{}</code></p></details>\
                             <form method=\"post\" action=\"./nostr-check\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
                             <input type=\"hidden\" name=\"event\" value=\"{}\"><button type=\"submit\" class=\"secondary\">Check with the seller</button></form>",
                            esc(&n.listing.name), esc(&n.listing.seller), esc(&n.author), esc(&n.listing.receipt_key),
                            esc(&ctx.csrf), esc(&n.event_id)));
        for s in nostr::to_services(n) {
            b.push_str(&format!("<h3>{} <span class=\"pill cat-{}\">{}</span></h3><p class=\"price\">{}</p>", esc(&s.name), s.kind.category(),
                                esc(s.kind.category_words()), esc(&s.price_text)));
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
        }
        b.push_str("</section>");
    }
    b
}
