//! Sellers found on Nostr (`XBT_UI_NOSTR_RELAYS`, `docs/NOSTR.md`): the listings the owner's relays
//! hold, each checked by [`xbt_nostr::market`] (the event, the listing and the binding all verify),
//! kept for a while, and turned into services the player can open.
//!
//! The relays are asked only when the owner opens the Nostr page, never in the background, and
//! never with no relays set (the default). A seller found here is unvetted: its listing is signed
//! by a receipt key, but only the seller's own 402 terms say that key is the seller's. The page's
//! Check button asks the seller that ([`check`]).
use std::sync::Mutex;
use std::time::{Duration, Instant};

use xbt402::listing::{self, Page};
use xbt_nostr::market::{self, NostrListing};
use xbt_nostr::oneshot::{self, Outcome};

use crate::services::Service;

/// A query older than this is asked again when the page opens.
pub const FRESH: Duration = Duration::from_secs(120);
/// Each relay gets this long to send what it has.
pub const QUERY_WAIT: Duration = Duration::from_secs(8);
/// How many listings each relay is asked for.
pub const QUERY_LIMIT: usize = 200;

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub at: Instant,
    pub listings: Vec<NostrListing>,
    /// Events that failed a check.
    pub refused: usize,
    pub relays: Vec<Outcome>,
}

pub struct NostrCache {
    relays: Vec<String>,
    snap: Mutex<Option<Snapshot>>,
}

impl NostrCache {
    pub fn new(relays: Vec<String>) -> Self {
        Self { relays, snap: Mutex::new(None) }
    }

    pub fn enabled(&self) -> bool {
        !self.relays.is_empty()
    }

    /// The listings, asking the relays when there is nothing fresh (or `refresh`).
    pub fn get(&self, refresh: bool) -> Snapshot {
        if let Some(s) = self.snap.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            if !refresh && s.at.elapsed() < FRESH {
                return s.clone();
            }
        }
        let (events, relays) = oneshot::query(&self.relays, &market::filter(QUERY_LIMIT), QUERY_WAIT);
        let (listings, refused) = market::collect(&events, xbt_nostr::now());
        let s = Snapshot { at: Instant::now(), listings, refused, relays };
        *self.snap.lock().unwrap_or_else(|p| p.into_inner()) = Some(s.clone());
        s
    }

    /// The services found the last time the page asked, without asking again: what the player and
    /// the links for external players may open.
    pub fn services(&self) -> Vec<Service> {
        self.snap.lock().unwrap_or_else(|p| p.into_inner()).as_ref().map(|s| s.listings.iter().flat_map(to_services).collect()).unwrap_or_default()
    }
}

/// A checked listing as services of Browse: one for a `listing/0`, one per service for a
/// `listing/1`, as the Services page makes them.
pub fn to_services(n: &NostrListing) -> Vec<Service> {
    crate::services::from_listing(&n.listing)
}

const MAX_BODY: u64 = 256 * 1024;

/// One GET for [`listing::fetch`]: the status, headers and body, a 402 included.
fn get(url: &str) -> Result<Page, String> {
    let agent = ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(5)).timeout(Duration::from_secs(15)).redirects(0).build();
    let resp = match agent.get(url).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => return Err(format!("{url}: {e}")),
    };
    let status = resp.status();
    let headers = resp.headers_names().into_iter().filter_map(|h| resp.header(&h).map(|v| (h.clone(), v.to_string()))).collect();
    let mut body = String::new();
    std::io::Read::read_to_string(&mut std::io::Read::take(resp.into_reader(), MAX_BODY + 1), &mut body).map_err(|e| format!("{url}: {e}"))?;
    Ok(Page { status, headers, body })
}

/// Ask the seller itself: its listing, checked against the receipt key its 402 terms name, must
/// carry the receipt key the Nostr listing carries. `Ok` with the seller's own listing.
pub fn check(n: &NostrListing) -> Result<listing::Listing, String> {
    check_with(n, get)
}

pub fn check_with(n: &NostrListing, get: impl FnMut(&str) -> Result<Page, String>) -> Result<listing::Listing, String> {
    // the terms come with a 402, so ask for something priced: an item of the seller's own origin
    let priced = n.listing.services.iter().flat_map(|s| s.items.iter()).map(|i| i.url.as_str()).find(|u| crate::services::same_origin(u, &n.listing.seller)).unwrap_or(&n.listing.seller);
    let own = listing::fetch(priced, get)?;
    if own.receipt_key != n.listing.receipt_key {
        return Err("the seller's own terms name another receipt key: this Nostr listing is not the seller's".into());
    }
    Ok(own)
}
