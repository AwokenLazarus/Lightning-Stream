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
        let own_key = self.own_shop_key_origin();
        let own = |seller: &str| self.is_own_shop(seller) || own_key.as_deref().is_some_and(|k| services::same_origin(k, seller));
        self.html_page("Browse", "Found on Nostr", ctx, &nostr_html(ctx, &snap, &have, &own, xbt_nostr::now()), "")
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

/// `have`: the sellers on the owner's list, marked "On your list". `now` dates the listings: a shop that looks
/// offline ([`xbt_nostr::market::NostrListing::offline`]: its listing is stale and no Lightning node vouches for it
/// now) is folded away under "Offline shops", never this box's own.
fn nostr_html(ctx: &Ctx, snap: &Snapshot, have: &[Service], own: &dyn Fn(&str) -> bool, now: u64) -> String {
    let mut b = String::from("<p class=\"small\"><a href=\"./browse\">← Browse</a> · <a href=\"./nostr?refresh=1\">Look again</a></p>\
        <div class=\"flash warn\"><strong>Unvetted.</strong> These sellers published their lists on Nostr, each signed by the \
        seller's own key, but nobody has checked who runs them. A shop reached by its key: its address is that key, so the list is its own. \
        A seller with a web address: press Check with the seller, and the app asks that address whether the list is theirs. \
        Who runs a shop is not checked by anyone. Payments still keep to your spending rules.</div>");
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
    let (gone, live): (Vec<_>, Vec<_>) = snap.listings.iter().partition(|n| !own(&n.listing.seller) && n.offline(now));
    if live.is_empty() {
        b.push_str("<p class=\"empty\">No shop on these relays is online now.</p>");
    }
    for n in live {
        b.push_str(&listing_card(ctx, n, have, own, None));
    }
    if !gone.is_empty() {
        b.push_str(&format!("<details class=\"offline-shops\"><summary>Offline shops ({})</summary>\
            <p class=\"small\">These listings are more than two days old and no Lightning node vouches for them any more: their shops look \
            offline. A shop that comes back is listed above again once it publishes a new listing.</p>", gone.len()));
        for n in gone {
            b.push_str(&listing_card(ctx, n, have, own, Some(n.age_days(now))));
        }
        b.push_str("</details>");
    }
    b
}

/// One listing's card. `offline`: the shop looks offline, its listing this many days old.
fn listing_card(ctx: &Ctx, n: &xbt_nostr::market::NostrListing, have: &[Service], own: &dyn Fn(&str) -> bool, offline: Option<u64>) -> String {
    let mut b = String::new();
    if own(&n.listing.seller) {
        return format!("<section class=\"card\"><div class=\"offer-head\"><h2>{}</h2><span class=\"pill good\">Your shop</span></div>\
                        <p class=\"small\">This is the listing your box publishes. See it on <a href=\"./sell\">Sell</a>.</p></section>",
                       esc(&n.listing.name));
    }
    let added = have.iter().any(|s| services::same_origin(&s.seller, &n.listing.seller));
    let mine = if added { "<span class=\"pill good\">On your list</span>" } else { "" };
    // a shop that looks offline is said to be: it can't be allowed to be paid until it publishes again
    let gone = offline.map(|d| format!("<p class=\"small\">{}</p>", esc(&crate::shops::offline_words(d)))).unwrap_or_default();
    let mine = if offline.is_some() { "<span class=\"pill\">offline</span>" } else { mine };
    let (add_label, add_class) = if added { ("Check for updates", " class=\"secondary\"") } else { ("Add this shop", "") };
    if key_shop(n) {
        // a shop without a web address: its address is its key, and the listing is signed by that key, so
        // there is no other address to ask. It is added as a shop key on Sellers ([`App::add_seller`])
        b.push_str(&format!("<section class=\"card\"><div class=\"offer-head\"><h2>{}</h2><span class=\"pill\">reached by its key</span>{mine}</div>\
                             <p class=\"small\">Shop key <code class=\"key\">{}</code></p>{gone}\
                             <form method=\"post\" action=\"./services\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
                             <input type=\"hidden\" name=\"action\" value=\"add\"><input type=\"hidden\" name=\"url\" value=\"{}\">\
                             <button type=\"submit\"{add_class}>{add_label}</button></form>",
                            esc(&n.listing.name), esc(&xbt402::shop::display(&n.listing.seller)), esc(&ctx.csrf), esc(&n.listing.seller)));
    } else {
        let pill = if added || offline.is_some() { mine } else { "<span class=\"pill warn\">unvetted</span>" };
        b.push_str(&format!("<section class=\"card\"><div class=\"offer-head\"><h2>{}</h2>{pill}</div>\
                             <p class=\"small\">{}</p>{gone}<details><summary>Keys</summary><p class=\"small\">Nostr key <code>{}</code>, receipt key <code>{}</code></p></details>\
                             <form method=\"post\" action=\"./nostr-check\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">\
                             <input type=\"hidden\" name=\"event\" value=\"{}\"><button type=\"submit\" class=\"secondary\">Check with the seller</button></form>",
                            esc(&n.listing.name), esc(&xbt402::shop::display(&n.listing.seller)), esc(&n.author), esc(&n.listing.receipt_key),
                            esc(&ctx.csrf), esc(&n.event_id)));
    }
    for s in nostr::to_services(n) {
        b.push_str(&format!("<h3>{} <span class=\"pill cat-{}\">{}</span></h3><p class=\"price\">{}</p>", esc(&s.name), s.category(),
                            esc(s.category_words()), esc(&s.price_text)));
        if !s.items.is_empty() {
            b.push_str("<div class=\"grid\">");
            for item in &s.items {
                // the file's path at the shop, not its made-up `…shop.invalid` address
                let path = services::http_origin(&item.url).filter(|o| xbt402::shop::is_shop(o))
                    .and_then(|o| item.url.strip_prefix(&o).map(str::to_string)).unwrap_or_else(|| item.url.clone());
                // shown decoded ("My film.mkv", not "My%20film.mkv"); the link itself is not changed
                let open = format!("<p class=\"small\"><code>{}</code></p>", esc(&crate::services::path_words(&path)));
                b.push_str(&format!("<article class=\"card\"><h3>{} <span class=\"small\">{}</span></h3><p class=\"small\">{}</p>{open}</article>",
                                    esc(&item.title), esc(&item.year), esc(&item.credit)));
            }
            b.push_str("</div>");
        }
    }
    b.push_str("</section>");
    b
}

/// Whether `n` is the listing of a shop without a web address whose address is the key that signed it.
fn key_shop(n: &xbt_nostr::market::NostrListing) -> bool {
    xbt402::shop::key_of(&n.listing.seller).is_some_and(|k| hex::encode(k) == n.author.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::{key_shop, nostr_html};
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

    /// 0.2.14: a listing that is stale and that no Lightning node vouches for (a shop whose box was reinstalled with its
    /// key inside, so its listing can never be withdrawn) is folded under "Offline shops (N)" and said to look offline;
    /// a new one, or this box's own, is shown as before.
    ///
    /// FAILS without the fold: the dead shop is listed beside the live ones.
    #[test]
    fn a_shop_that_looks_offline_is_folded_away() {
        let now = 1_790_000_000;
        let dead_pk = [7u8; 32];
        let dead_origin = xbt402::shop::origin_for(&dead_pk);
        let mut dead = listing(&dead_origin, &hex::encode(dead_pk));
        dead.listing.name = "StartOS packaging test".into();
        dead.created_at = now - 6 * 86_400;
        let mut live = listing("https://live.example", &hex::encode([8u8; 32]));
        live.listing.name = "Live films".into();
        live.created_at = now - 3600;
        let mut own = listing("https://own.example", &hex::encode([9u8; 32]));
        own.listing.name = "My shop".into();
        own.created_at = now - 9 * 86_400;
        let snap = crate::nostr::Snapshot { at: std::time::Instant::now(), listings: vec![dead, live, own], refused: 0, relays: vec![] };
        let ctx = crate::app::Ctx { sid: String::new(), csrf: "c".into(), flash: None };
        let html = nostr_html(&ctx, &snap, &[], &|s: &str| s == "https://own.example", now);
        let fold = html.find("<details class=\"offline-shops\"><summary>Offline shops (1)</summary>").expect(&html);
        let (above, below) = html.split_at(fold);
        assert!(above.contains("Live films") && above.contains("My shop") && !above.contains("StartOS packaging test"), "{above}");
        assert!(below.contains("StartOS packaging test") && below.contains("This listing is 6 days old and no Lightning node vouches for it any more: the shop looks offline."), "{below}");
        // nothing offline: no fold
        let snap = crate::nostr::Snapshot { listings: snap.listings[1..].to_vec(), ..snap };
        assert!(!nostr_html(&ctx, &snap, &[], &|s: &str| s == "https://own.example", now).contains("Offline shops"));
    }
}
