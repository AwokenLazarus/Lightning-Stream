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
            Paste the address the seller gave you. The app checks that the list really comes from that seller.</p>");
        let all = self.file_services();
        b.push_str(&format!("<form method=\"post\" action=\"./services\" class=\"card primary add\">{}<input type=\"hidden\" name=\"action\" value=\"add\">\
            <label>Seller's address<input name=\"url\" type=\"url\" inputmode=\"url\" required placeholder=\"https://seller.example\" \
            pattern=\"https?://.+\" title=\"Paste the seller's web address, starting with https://\" autocomplete=\"off\"></label>\
            <button>Add seller</button></form>{}", App::csrf_input(ctx), self.suggested(ctx, all.as_deref().unwrap_or(&[]))));
        match all {
            Err(e) => b.push_str(&App::error_box(&format!("The list of sellers could not be read: {e}"))),
            Ok(all) if all.is_empty() => b.push_str("<p class=\"empty\">No sellers yet. Add one above.</p>"),
            Ok(all) => {
                b.push_str("<h2>Your sellers</h2>");
                for (origin, list) in by_seller(&all) {
                    b.push_str(&format!("<section class=\"card seller\"><h3>{}</h3><p class=\"small\">{}</p><ul class=\"offers\">",
                                        esc(&list[0].name), esc(&origin)));
                    for s in &list {
                        let n = s.items.len();
                        b.push_str(&format!("<li><span class=\"pill cat-{}\">{}</span> <strong>{}</strong> <span class=\"price\">{}</span>{}</li>",
                                            s.kind.category(), esc(s.kind.category_words()), esc(&s.name), esc(&s.price_text),
                                            if n > 0 { format!(" <span class=\"small\">{n} to choose from</span>") } else { String::new() }));
                    }
                    b.push_str("</ul><div class=\"row\">");
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
        let url = f.get("url").map(|s| s.trim().trim_end_matches('/').to_string()).unwrap_or_default();
        let result = match f.get("action").map(String::as_str) {
            Some("add") | Some("refresh") => self.add_seller(&url, get_page),
            Some("remove") => self.remove_seller(&url),
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
        Ok(format!("{} {}: {n} service{} on Browse now.", if had { "Updated" } else { "Added" }, listing.name, if n == 1 { "" } else { "s" }))
    }

    fn remove_seller(&self, url: &str) -> Result<String, String> {
        let mut all = self.file_services()?;
        let before = all.len();
        all.retain(|s| !services::same_origin(&s.seller, url));
        if all.len() == before {
            return Err("That seller is not in the list.".into());
        }
        services::save(&self.cfg.services_path(), &all)?;
        Ok("Seller removed. Their services are no longer on Browse.".into())
    }
}
