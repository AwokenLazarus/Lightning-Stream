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
                for (origin, list) in by_seller(&all) {
                    let shown = if xbt402::shop::is_shop(&origin) {
                        format!("Shop key <code class=\"key\">{}</code> <span class=\"pill\">Direct link</span>", esc(&xbt402::shop::display(&origin)))
                    } else {
                        esc(&origin)
                    };
                    // a shop known by its key can be linked to on this page, by that key
                    let anchor = if xbt402::shop::is_shop(&origin) { format!(" id=\"key-{}\"", esc(&xbt402::shop::display(&origin))) } else { String::new() };
                    b.push_str(&format!("<section class=\"card seller\"{anchor}><h3>{}</h3><p class=\"small\">{shown}</p><ul class=\"offers\">",
                                        esc(&list[0].name)));
                    for s in &list {
                        let n = s.items.len();
                        b.push_str(&format!("<li><span class=\"pill cat-{}\">{}</span> <strong>{}</strong> <span class=\"price\">{}</span>{}</li>",
                                            s.category(), esc(s.category_words()), esc(&s.name), esc(&s.price_text),
                                            if n > 0 { format!(" <span class=\"small\">{n} to choose from</span>") } else { String::new() }));
                    }
                    b.push_str("</ul>");
                    let allowed = self.seller_allowed(&origin);
                    b.push_str(&if allowed {
                        "<p><span class=\"pill good\">Allowed to be paid</span> within your spending rules.</p>".to_string()
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
            Some("remove") => self.remove_seller(&url),
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
        self.ai_sellers_follow(&listing.seller);
        let allowed = self.seller_allowed(&listing.seller);
        Ok(format!("{} {}: {n} service{} on Browse now.{}", if had { "Updated" } else { "Added" }, listing.name, if n == 1 { "" } else { "s" },
                   if allowed { "" } else { " To let the app pay this seller, press \"Allow this seller to be paid\" below." }))
    }

    /// Whether the spending rules let the app pay the seller at `origin`: its address on the list,
    /// tied to a Lightning node.
    pub(crate) fn seller_allowed(&self, origin: &str) -> bool {
        let Ok(p) = self.signer.call("policy_get", serde_json::json!({})) else { return false };
        let pol = &p["policy"];
        let o = services::http_origin(origin).unwrap_or_default();
        let listed = pol["allowlist"].as_array().is_some_and(|a| a.iter().filter_map(|x| x.as_str()).any(|x| services::http_origin(x).as_deref() == Some(o.as_str())));
        listed && pol["counterparties"].as_object().is_some_and(|m| m.iter().any(|(k, v)|
            services::http_origin(k).as_deref() == Some(o.as_str()) && v["ln_node"].as_str().is_some_and(|n| !n.is_empty())))
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
        self.ai_sellers_follow(url);
        Ok("Seller removed. Their services are no longer on Browse.".into())
    }
}
