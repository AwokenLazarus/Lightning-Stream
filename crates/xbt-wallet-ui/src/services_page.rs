//! Services: the sellers whose services Browse lists. The owner pastes a seller's address; this
//! process fetches the seller's signed listing, checks it against the receipt key in the seller's
//! own 402 terms ([`xbt402::listing::fetch`]), and saves each service it lists in the services
//! file. Nothing a seller says is trusted beyond its own listing: no directory, no relay.
use std::collections::HashMap;
use std::io::Read;
use std::time::Duration;

use super::{App, Ctx};
use crate::html::esc;
use crate::server::Resp;
use crate::services::{self, Service};

/// How long one request to a seller may take.
const FETCH_WAIT: Duration = Duration::from_secs(10);
/// The most of an answer read: the listing's own limit, and a byte more to see it was passed.
const MAX_ANSWER: u64 = (256 << 10) + 1;

/// One GET, as [`xbt402::listing::fetch`] asks for it. No redirect is followed.
pub fn get_page(url: &str) -> Result<xbt402::listing::Page, String> {
    let agent = ureq::AgentBuilder::new().timeout_connect(FETCH_WAIT).timeout_read(FETCH_WAIT).timeout_write(FETCH_WAIT).redirects(0).build();
    let resp = match agent.get(url).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => return Err(format!("could not reach {url}: {e}")),
    };
    let status = resp.status();
    let headers = resp.headers_names().into_iter().filter_map(|n| resp.header(&n).map(|v| (n.clone(), v.to_string()))).collect();
    let mut body = String::new();
    resp.into_reader().take(MAX_ANSWER).read_to_string(&mut body).map_err(|e| format!("{url}: {e}"))?;
    Ok(xbt402::listing::Page { status, headers, body })
}

/// The seller's Lightning node, from its own 402 terms (`accepts[].payTo`), asked at `urls` in turn
/// (its priced items, then its address): the node the policy ties the seller's address to.
pub fn seller_node(urls: &[String], mut get: impl FnMut(&str) -> Result<xbt402::listing::Page, String>) -> Result<String, String> {
    use base64::Engine;
    let mut why = String::from("the seller asked for no payment at its address");
    for u in urls.iter().take(6) {
        let page = match get(u) {
            Ok(p) => p,
            Err(e) => {
                why = e;
                continue;
            }
        };
        if page.status != 402 {
            continue;
        }
        let header = page.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("PAYMENT-REQUIRED")).map(|(_, v)| v.clone());
        let terms: Option<serde_json::Value> = header
            .and_then(|h| base64::engine::general_purpose::STANDARD.decode(h.trim()).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .or_else(|| serde_json::from_str(&page.body).ok());
        let node = terms.as_ref().and_then(|t| t["accepts"].as_array().cloned()).unwrap_or_default().iter()
            .filter_map(|a| a["payTo"].as_str().map(str::to_string))
            .find(|n| n.len() == 66 && n.bytes().all(|c| c.is_ascii_hexdigit()));
        match node {
            Some(n) => return Ok(n.to_ascii_lowercase()),
            None => why = "the seller's terms name no Lightning node".into(),
        }
    }
    Err(why)
}

/// The sellers in the services file, by origin, in the file's order.
fn by_seller(all: &[Service]) -> Vec<(String, Vec<&Service>)> {
    let mut out: Vec<(String, Vec<&Service>)> = vec![];
    for s in all {
        let origin = services::http_origin(&s.seller).unwrap_or_else(|| s.seller.clone());
        match out.iter_mut().find(|(o, _)| *o == origin) {
            Some((_, v)) => v.push(s),
            None => out.push((origin, vec![s])),
        }
    }
    out
}

impl App {
    pub(crate) fn services_page(&self, ctx: &Ctx) -> Resp {
        let mut b = String::from("<p class=\"lead\">Add a seller to see what they offer on <a href=\"./browse\">Browse</a>. \
            Paste what the seller gave you: a web address, or a shop key that starts with npub. The app checks that the list really comes from that seller.</p>");
        let all = self.file_services();
        b.push_str(&format!("<form method=\"post\" action=\"./services\" class=\"card primary add\">{}<input type=\"hidden\" name=\"action\" value=\"add\">\
            <label>Seller's address or shop key<input name=\"url\" type=\"text\" inputmode=\"url\" required placeholder=\"https://seller.example or npub1…\" \
            pattern=\"(https?://|npub1|nostr:).+\" title=\"Paste the seller's web address (https://…) or shop key (npub1…)\" autocomplete=\"off\" spellcheck=\"false\"></label>\
            <button>Add seller</button></form>{}", App::csrf_input(ctx), self.suggested(ctx, all.as_deref().unwrap_or(&[]))));
        match all {
            Err(e) => b.push_str(&App::error_box(&format!("The list of sellers could not be read: {e}"))),
            Ok(all) if all.is_empty() => b.push_str("<p class=\"empty\">No sellers yet. Add one above.</p>"),
            Ok(all) => {
                b.push_str("<h2>Your sellers</h2>");
                let credits = self.credits();
                for (origin, list) in by_seller(&all) {
                    let shown = if xbt402::shop::is_shop(&origin) {
                        format!("Shop key <code class=\"key\">{}</code> <span class=\"pill\">Direct link</span>", esc(&xbt402::shop::display(&origin)))
                    } else {
                        esc(&origin)
                    };
                    // a shop known by its key can be linked to on this page, by that key
                    let anchor = if xbt402::shop::is_shop(&origin) { format!(" id=\"key-{}\"", esc(&xbt402::shop::display(&origin))) } else { String::new() };
                    b.push_str(&format!("<section class=\"card seller\"{anchor}><h3>{}</h3><p class=\"small\">{shown}</p><ul class=\"offers\">",
                                        esc(&services::seller_name(&all, &origin))));
                    for s in &list {
                        let n = s.items.len();
                        b.push_str(&format!("<li><span class=\"pill cat-{}\">{}{}</span> <strong>{}</strong> <span class=\"price\">{}</span>{}</li>",
                                            s.category(), services::icon(s.category()), esc(s.category_words()), esc(&s.name), esc(&s.price_text),
                                            if n > 0 { format!(" <span class=\"small\">{n} to choose from</span>") } else { String::new() }));
                    }
                    b.push_str("</ul>");
                    // what is left with the shop from earlier connections, drawn first next time
                    if let Some(m) = credits.get(&origin) {
                        b.push_str(&crate::app::credit_line(&services::seller_name(&all, &origin), *m));
                    }
                    let allowed = self.seller_allowed(&origin);
                    b.push_str(&if allowed {
                        "<p><span class=\"pill good\">Allowed to be paid</span> within your spending rules.</p>".to_string()
                    } else if self.in_rules(&origin) && self.vouched_node(&origin).is_some() {
                        // on the list with no node on file (or another): the fix in place, reviewed and signed on the rules page
                        format!("<p><span class=\"pill warn\">No Lightning node on file</span> Your rules list this shop, but not the node it is paid \
                                 through, so the app would refuse to pay it.</p>\
                                 <form method=\"post\" action=\"./services\">{}<input type=\"hidden\" name=\"action\" value=\"allow\">\
                                 <input type=\"hidden\" name=\"url\" value=\"{}\"><button>Use the node the shop vouches for</button></form>",
                                App::csrf_input(ctx), esc(&origin))
                    } else {
                        format!("<p><span class=\"pill warn\">Not allowed to be paid yet</span> Your spending rules list the sellers the app may pay.</p>\
                                 <form method=\"post\" action=\"./services\">{}<input type=\"hidden\" name=\"action\" value=\"allow\">\
                                 <input type=\"hidden\" name=\"url\" value=\"{}\"><button>Allow this seller to be paid</button></form>",
                                App::csrf_input(ctx), esc(&origin))
                    });
                    b.push_str("<div class=\"row\">");
                    for (action, label, class) in [("refresh", "Check for updates", " class=\"secondary\""), ("remove", "Remove", " class=\"danger\"")] {
                        b.push_str(&format!("<form method=\"post\" action=\"./services\">{}<input type=\"hidden\" name=\"action\" value=\"{action}\">\
                                             <input type=\"hidden\" name=\"url\" value=\"{}\"><button{class}>{label}</button></form>",
                                            App::csrf_input(ctx), esc(&origin)));
                    }
                    b.push_str("</div></section>");
                }
            }
        }
        b.push_str(&self.still_allowed(&self.file_services().unwrap_or_default()));
        self.page("Sellers", ctx, b)
    }

    pub(crate) fn services_post(&self, ctx: &Ctx, f: &HashMap<String, String>) -> Resp {
        let typed = f.get("url").map(|s| s.trim().trim_end_matches('/').to_string()).unwrap_or_default();
        let Some(url) = xbt402::shop::parse(&typed) else {
            self.flash(ctx, false, "That shop key is not a valid one. Check it: a shop key starts with npub1, and one wrong letter makes it invalid.");
            return Resp::redirect("./services");
        };
        let result = match f.get("action").map(String::as_str) {
            Some("add") | Some("refresh") => self.add_seller(&url, get_page),
            Some("remove") => self.remove_seller(&url).map(|m| if self.in_rules(&url) {
                format!("{m} It is still allowed to be paid in your spending rules: review it below.")
            } else {
                m
            }),
            // "Try the demo shop": add the seller, then straight to the rules with it allowed, ready to sign once
            Some("try") => match self.add_seller(&url, get_page) {
                Ok(_) if self.seller_allowed(&url) => Ok(format!("{} is on Browse and allowed to be paid.", self.seller_name(&url))),
                Ok(_) => match self.allow_link(&url, get_page) {
                    Ok(link) => return Resp::redirect(&link),
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            },
            Some("allow") => match self.allow_link(&url, get_page) {
                Ok(link) => return Resp::redirect(&link),
                Err(e) => Err(e),
            },
            _ => Err("Unknown action.".into()),
        };
        match result {
            Ok(m) => self.flash(ctx, true, m),
            Err(e) => self.flash(ctx, false, e),
        }
        Resp::redirect("./services")
    }

    /// Fetch and check `url`'s listing, and put its services in place of the seller's old ones.
    pub fn add_seller(&self, url: &str, get: impl FnMut(&str) -> Result<xbt402::listing::Page, String>) -> Result<String, String> {
        if let Some(pk) = xbt402::shop::key_of(url) {
            let found = self.nostr.find_shop(&pk).map_err(|e| format!("That shop could not be found: {e}"))?;
            return self.add_shop(found);
        }
        if services::http_origin(url).is_none() {
            return Err("That is not a web address. Paste the seller's address, starting with https://".into());
        }
        let listing = xbt402::listing::fetch(url, get).map_err(|e| format!("That seller's list could not be used: {e}."))?;
        let new = services::from_listing(&listing);
        let mut all = self.file_services().unwrap_or_default();
        let had = all.iter().any(|s| services::same_origin(&s.seller, &listing.seller));
        all.retain(|s| !services::same_origin(&s.seller, &listing.seller));
        let n = new.len();
        all.extend(new);
        services::save(&self.cfg.services_path(), &all)?;
        self.write_catalog();
        self.ai_sellers_follow(&listing.seller);
        let allowed = self.seller_allowed(&listing.seller);
        Ok(format!("{} {}: {n} service{} on Browse now.{}", if had { "Updated" } else { "Added" }, listing.name, if n == 1 { "" } else { "s" },
                   if allowed { "" } else { " To let the app pay this seller, press \"Allow this seller to be paid\" below." }))
    }

    /// Put a shop without a web address in the list, from its checked Nostr listing, and keep how to
    /// reach it. Its listing came from the key in its name ([`crate::nostr::shop_listing`]), so it is
    /// the shop's own.
    pub fn add_shop(&self, found: xbt_nostr::market::NostrListing) -> Result<String, String> {
        let listing = found.listing;
        let new = services::from_listing(&listing);
        let mut all = self.file_services().unwrap_or_default();
        let had = all.iter().any(|s| services::same_origin(&s.seller, &listing.seller));
        all.retain(|s| !services::same_origin(&s.seller, &listing.seller));
        let n = new.len();
        all.extend(new);
        let mut shops = crate::shops::load(&self.cfg.shops_path())?;
        shops.insert(listing.seller.clone(), crate::shops::Shop { receipt_key: listing.receipt_key.clone(), transport: found.transport });
        crate::shops::save(&self.cfg.shops_path(), &shops)?;
        services::save(&self.cfg.services_path(), &all)?;
        self.write_catalog();
        self.ai_sellers_follow(&listing.seller);
        let allowed = self.seller_allowed(&listing.seller);
        Ok(format!("{} {}: {n} service{} on Browse now.{}", if had { "Updated" } else { "Added" }, listing.name, if n == 1 { "" } else { "s" },
                   if allowed { "" } else { " To let the app pay this seller, press \"Allow this seller to be paid\" below." }))
    }

    /// The seller's name for any page: the shop's listing name, else its short address
    /// ([`services::seller_name`]). For the pages that name a seller by its origin alone (a visit, an
    /// activity line).
    pub fn seller_name(&self, origin: &str) -> String {
        // the sellers on the owner's list, then the ones Found on Nostr last saw (0.2.2 showed a key for a shop known only there)
        services::seller_name(&self.services().unwrap_or_default(), origin)
    }

    /// Whether the spending rules name the seller at `origin` at all: on the list that may be paid,
    /// or tied to a Lightning node.
    pub(crate) fn in_rules(&self, origin: &str) -> bool {
        let Ok(p) = self.signer.call("policy_get", serde_json::json!({})) else { return false };
        rules_naming(&p["policy"], &[]).iter().any(|o| services::same_origin(o, origin))
    }

    /// The sellers the spending rules still allow to be paid that are not on the list of sellers
    /// (removed there, say): each with a link that opens the rules with it ticked for removal.
    fn still_allowed(&self, have: &[Service]) -> String {
        let Ok(p) = self.signer.call("policy_get", serde_json::json!({})) else { return String::new() };
        let gone = rules_naming(&p["policy"], have);
        if gone.is_empty() {
            return String::new();
        }
        let mut b = String::from("<section class=\"card\" id=\"still-allowed\"><h2>Still allowed to be paid</h2>\
            <p>Your spending rules still allow these sellers to be paid, though they are not on your list. Review them to remove them there too.</p><ul>");
        for o in &gone {
            b.push_str(&format!("<li><strong>{}</strong> <span class=\"small\"><code class=\"key\">{}</code></span> \
                                 <a href=\"./policy?drop={}\">Review in your spending rules</a></li>",
                                esc(&services::seller_name(have, o)), esc(&xbt402::shop::display(o)), services::urlenc(o)));
        }
        b.push_str("</ul></section>");
        b
    }

    /// Write the agents' catalog ([`services::catalog`]) from the services file as it is now. Unchecked: an agent
    /// then sees the catalog of the last write, and the owner's log says why.
    pub fn write_catalog(&self) {
        let all = self.file_services().unwrap_or_default();
        let shops = crate::shops::load(&self.cfg.shops_path()).unwrap_or_default();
        let v = services::catalog(&all, &shops, self.cfg.ai.endpoint.as_deref(), xbt_nostr::now());
        if let Err(e) = services::save_catalog(&self.cfg.catalog_path(), &v) {
            eprintln!("xbt-wallet-ui: the agents' catalog was not written: {e}");
        }
    }

    /// Whether the spending rules let the app pay the seller at `origin`: its address on the list,
    /// tied to a Lightning node.
    pub(crate) fn seller_allowed(&self, origin: &str) -> bool {
        let Ok(p) = self.signer.call("policy_get", serde_json::json!({})) else { return false };
        crate::app::rules_allow(&p["policy"], origin, self.vouched_node(origin).as_deref())
    }

    /// The credit left with each shop ([`crate::app::credit_left`]), from the wallet's history.
    pub(crate) fn credits(&self) -> HashMap<String, u64> {
        let events = self.signer.call("history", serde_json::json!({"limit": 1000})).ok()
            .and_then(|h| h["events"].as_array().cloned()).unwrap_or_default();
        crate::app::credit_left(&events)
    }

    /// The Lightning node the shop at `origin` (one reached by its key) vouches for now, from its entry.
    pub(crate) fn vouched_node(&self, origin: &str) -> Option<String> {
        let o = services::http_origin(origin)?;
        let shops = crate::shops::load(&self.cfg.shops_path()).ok()?;
        shops.get(&o).and_then(|s| crate::shops::node(s, &o, xbt_nostr::now()))
    }

    /// The spending rules page with this seller added, ready to sign: the seller's node is read from
    /// its own 402 terms, at its priced items first.
    pub fn allow_link(&self, url: &str, get: impl FnMut(&str) -> Result<xbt402::listing::Page, String>) -> Result<String, String> {
        let origin = services::http_origin(url).ok_or("That is not a web address.")?;
        if xbt402::shop::is_shop(&origin) {
            let shops = crate::shops::load(&self.cfg.shops_path())?;
            let shop = shops.get(&origin).ok_or("Add this shop again: the app has not kept how to reach it.")?;
            let node = crate::shops::node(shop, &origin, xbt_nostr::now())
                .ok_or("This seller could not be allowed: its listing names no direct link that its Lightning node vouches for now. Press Check for updates, or ask the seller.")?;
            return Ok(format!("./policy?allow={}&node={}", services::urlenc(&origin), node));
        }
        // the seller's priced places: each service's address, then a priced item of each, on the seller's own
        // address (a seller that moved may still list items at its old one, which answers the same). The bare
        // address last: a shop need not price its front page
        let mut urls: Vec<String> = vec![];
        for s in self.file_services().unwrap_or_default().iter().filter(|s| services::same_origin(&s.seller, &origin)) {
            let here = std::iter::once(s.address().to_string()).chain(s.items.iter().take(1).map(|i| i.url.clone()));
            for u in here.filter_map(|u| services::rebase(&u, &origin)) {
                if !urls.contains(&u) && u.trim_end_matches('/') != origin.trim_end_matches('/') {
                    urls.push(u);
                }
            }
        }
        urls.push(origin.clone());
        let node = seller_node(&urls, get).map_err(|e| format!("This seller could not be allowed: {e}."))?;
        Ok(format!("./policy?allow={}&node={}", services::urlenc(&origin), node))
    }

    fn remove_seller(&self, url: &str) -> Result<String, String> {
        let mut all = self.file_services()?;
        let before = all.len();
        all.retain(|s| !services::same_origin(&s.seller, url));
        if all.len() == before {
            return Err("That seller is not in the list.".into());
        }
        services::save(&self.cfg.services_path(), &all)?;
        self.write_catalog();
        self.ai_sellers_follow(url);
        Ok("Seller removed. Their services are no longer on Browse.".into())
    }
}

/// The web addresses (and shop keys) the rules `p` name, on the list that may be paid or tied to a
/// node, that no service in `have` is sold by. With `have` empty: every one.
fn rules_naming(p: &serde_json::Value, have: &[Service]) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    let listed = p["allowlist"].as_array().into_iter().flatten().filter_map(|x| x.as_str());
    let tied = p["counterparties"].as_object().into_iter().flat_map(|m| m.keys().map(String::as_str));
    for o in listed.chain(tied).filter_map(services::http_origin) {
        if !out.contains(&o) && !have.iter().any(|s| services::same_origin(&s.seller, &o)) {
            out.push(o);
        }
    }
    out
}
