//! Browse, Nostr: sellers whose signed listings the owner's relays hold (`XBT_UI_NOSTR_RELAYS`),
//! shown apart from the services file and marked unvetted, with a Check button that asks the
//! seller itself whether the listing is its own ([`crate::nostr`]).
use std::collections::HashMap;

use super::{App, Ctx};
use crate::html::esc;
use crate::nostr::{self, Snapshot};
use crate::server::Resp;
use crate::services::{self, Service};

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
        let have = self.file_services().unwrap_or_default();
        // this box's own shop, by its web address or its shop key: marked, never offered to add (a box can't buy from itself)
        let own_key = if self.cfg.sell {
            self.link_status().and_then(|v| v.get("npub").and_then(serde_json::Value::as_str).and_then(xbt402::shop::parse))
        } else {
            None
        };
        let own = |seller: &str| self.is_own_shop(seller) || own_key.as_deref().is_some_and(|k| services::same_origin(k, seller));
        self.html_page("Browse", "Found on Nostr", ctx, &nostr_html(ctx, &snap, &have, &own), "")
    }

    /// `POST /nostr-check`: ask the seller whether the listing found on Nostr is its own.
    pub(crate) fn nostr_check(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let id = f.get("event").map(|s| s.trim().to_string()).unwrap_or_default();
        let snap = self.nostr.get(false);
        match snap.listings.iter().find(|n| n.event_id == id) {
            None => self.flash(ctx, false, "That listing is no longer on the relays. Reload the page."),
            // a shop reached by its key has no web address to ask: the key that signed the list is its address
            Some(n) if key_shop(n) => self.flash(ctx, true, format!("{} is reached by its key, and this list is signed by that key: it is the shop's own. Press Add this shop.", n.listing.name)),
            Some(n) => match nostr::check(n) {
                Ok(_) => self.flash(ctx, true, format!("{} confirms this listing is its own: it signs with the same key.", n.listing.seller)),
                Err(e) => self.flash(ctx, false, format!("{}: {e}", n.listing.seller)),
            },
        }
        Resp::redirect("./nostr")
    }
}

/// `have`: the sellers on the owner's list, marked "On your list".
fn nostr_html(ctx: &Ctx, snap: &Snapshot, have: &[Service], own: &dyn Fn(&str) -> bool) -> String {
    let mut b = String::from("<p class=\"small\"><a href=\"./browse\">← Your services</a> · <a href=\"./nostr?refresh=1\">Look again</a></p>\
        <div class=\"flash warn\"><strong>Unvetted.</strong> These sellers published their lists on Nostr, each signed by the \
        seller's own key, but nobody has checked who runs them. A shop reached by its key: its address is that key, so the list is its own. \
        A seller with a web address: press Check with the seller, and the app asks that address whether the list is theirs. \
        Payments still keep to your spending rules.</div>");
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
        if own(&n.listing.seller) {
            b.push_str(&format!("<section class=\"card\"><div class=\"offer-head\"><h2>{}</h2><span class=\"pill good\">Your shop</span></div>\
                                 <p class=\"small\">This is the listing your box publishes. See it on <a href=\"./sell\">Sell</a>.</p></section>",
                                esc(&n.listing.name)));
            continue;
        }
        let added = have.iter().any(|s| services::same_origin(&s.seller, &n.listing.seller));
        let mine = if added { "<span class=\"pill good\">On your list</span>" } else { "" };
        let (add_label, add_class) = if added { ("Check for updates", " class=\"secondary\"") } else { ("Add this shop", "") };
        if key_shop(n) {
            // a shop without a web address: its address is its key, and the listing is signed by that key, so
            // there is no other address to ask. It is added as a shop key on Sellers ([`App::add_seller`])
            b.push_str(&format!("<section class=\"card\"><div class=\"offer-head\"><h2>{}</h2><span class=\"pill\">reached by its key</span>{mine}</div>\
                                 <p class=\"small\">Shop key <code class=\"key\">{}</code>. This list is signed by that key, so it is the shop's own; \
                                 who runs the shop is not checked by anyone.</p>\
                                 <form method=\"post\" action=\"./services\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
                                 <input type=\"hidden\" name=\"action\" value=\"add\"><input type=\"hidden\" name=\"url\" value=\"{}\">\
                                 <button type=\"submit\"{add_class}>{add_label}</button></form>",
                                esc(&n.listing.name), esc(&xbt402::shop::display(&n.listing.seller)), esc(&ctx.csrf), esc(&n.listing.seller)));
        } else {
            let pill = if added { mine } else { "<span class=\"pill warn\">unvetted</span>" };
            b.push_str(&format!("<section class=\"card\"><div class=\"offer-head\"><h2>{}</h2>{pill}</div>\
                                 <p class=\"small\">{}</p><details><summary>Keys</summary><p class=\"small\">Nostr key <code>{}</code>, receipt key <code>{}</code></p></details>\
                                 <form method=\"post\" action=\"./nostr-check\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
                                 <input type=\"hidden\" name=\"event\" value=\"{}\"><button type=\"submit\" class=\"secondary\">Check with the seller</button></form>",
                                esc(&n.listing.name), esc(&n.listing.seller), esc(&n.author), esc(&n.listing.receipt_key),
                                esc(&ctx.csrf), esc(&n.event_id)));
        }
        for s in nostr::to_services(n) {
            b.push_str(&format!("<h3>{} <span class=\"pill cat-{}\">{}</span></h3><p class=\"price\">{}</p>", esc(&s.name), s.category(),
                                esc(s.category_words()), esc(&s.price_text)));
            if !s.items.is_empty() {
                b.push_str("<div class=\"grid\">");
                for item in &s.items {
                    let open = format!("<p class=\"small\"><code>{}</code></p>", esc(&item.url));
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

/// Whether `n` is the listing of a shop without a web address whose address is the key that signed it.
fn key_shop(n: &xbt_nostr::market::NostrListing) -> bool {
    xbt402::shop::key_of(&n.listing.seller).is_some_and(|k| hex::encode(k) == n.author.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::key_shop;
    use serde_json::json;

    fn listing(seller: &str, author: &str) -> xbt_nostr::market::NostrListing {
        xbt_nostr::market::NostrListing {
            listing: xbt402::listing::Listing { name: "Shop".into(), kind: "shop".into(), seller: seller.into(), receipt_key: String::new(), prices: json!({}),
                                                items: vec![], licence: String::new(), credits: String::new(), updated: String::new(), services: vec![] },
            author: author.into(), event_id: "e".into(), created_at: 0, transport: None,
        }
    }

    /// A shop reached by its key is offered to add: its address is the key that signed its list. Its list can't be
    /// checked with the seller over the web, so Found on Nostr must not offer only that check (it failed on a name
    /// lookup of the shop's made-up address, the 0.2.0 Genesis report).
    ///
    /// FAILS without `key_shop`: the card offers "Check with the seller" alone.
    #[test]
    fn a_shop_reached_by_its_key_is_offered_to_add_when_its_key_signed_the_list() {
        let pk = [7u8; 32];
        let origin = xbt402::shop::origin_for(&pk);
        assert!(key_shop(&listing(&origin, &hex::encode(pk))), "the key in the address signed it");
        assert!(key_shop(&listing(&origin, &hex::encode(pk).to_uppercase())));
        assert!(!key_shop(&listing(&origin, &hex::encode([8u8; 32]))), "another key signed a list naming this address");
        assert!(!key_shop(&listing("https://seller.example", &hex::encode(pk))), "a shop with a web address is checked with the seller");
    }
}
