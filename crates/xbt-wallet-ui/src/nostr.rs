//! Sellers found on Nostr (`XBT_UI_NOSTR_RELAYS`, `docs/NOSTR.md`): the listings the owner's relays
//! hold, each checked by [`xbt_nostr::market`] (the event, the listing and the binding all verify),
//! kept for a while, and turned into services a service page can open.
//!
//! The relays are asked only when the owner opens the Nostr page, and never with no relays set (the
//! default). The page shows the last answer at once: when it is older than [`FRESH`] the relays are
//! asked again behind it, and the next visit shows that. Only the first visit waits for them, at most
//! [`FIRST_WAIT`]; *Look again* waits for them in full. A seller found here is unvetted: its listing is signed
//! by a receipt key, but only the seller's own 402 terms say that key is the seller's. The page's
//! Check button asks the seller that ([`check`]).
use std::sync::Arc;
use std::time::{Duration, Instant};

use xbt402::listing::{self, Page};
use xbt_nostr::market::{self, NostrListing};
use xbt_nostr::oneshot::{self, Outcome};

use crate::services::Service;

/// A query older than this is asked again (in the background) when the page opens.
pub const FRESH: Duration = Duration::from_secs(120);
/// The first visit waits this long at most for the relays; after that the page says they are still
/// being asked.
pub const FIRST_WAIT: Duration = Duration::from_millis(1500);
/// What a relay not done yet at the first visit is said to be doing.
pub const STILL_ASKING: &str = "still being asked: reload this page in a few seconds";
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

/// How the relays are asked: the query of [`NostrCache::get`] (a test gives its own).
pub type Query = Arc<dyn Fn(&[String]) -> (Vec<xbt_nostr::event::Event>, Vec<Outcome>) + Send + Sync>;

pub struct NostrCache {
    relays: Vec<String>,
    snap: crate::perf::Swr<Snapshot>,
    query: Query,
}

impl NostrCache {
    pub fn new(relays: Vec<String>) -> Self {
        Self::with_query(relays, Arc::new(|r: &[String]| oneshot::query(r, &market::filter(QUERY_LIMIT), QUERY_WAIT)))
    }

    pub fn with_query(relays: Vec<String>, query: Query) -> Self {
        Self { relays, snap: crate::perf::Swr::new(), query }
    }

    /// How many times the relays were asked for the listings.
    pub fn queries(&self) -> u64 {
        self.snap.made()
    }

    pub fn enabled(&self) -> bool {
        !self.relays.is_empty()
    }

    /// The listings: the last answer at once, the relays asked again behind it when it is older
    /// than [`FRESH`]. `refresh` (the owner asked to look again) waits for the relays.
    pub fn get(&self, refresh: bool) -> Snapshot {
        let (relays, query) = (self.relays.clone(), self.query.clone());
        let make = move || {
            let (events, outcomes) = crate::perf::timed(|| query(&relays));
            let (listings, refused) = market::collect(&events, xbt_nostr::now());
            let listings = newest_per_shop(listings);
            Snapshot { at: Instant::now(), listings, refused, relays: outcomes }
        };
        if refresh {
            return self.snap.refresh(make);
        }
        self.snap.get(FRESH, FIRST_WAIT, make).unwrap_or_else(|| Snapshot {
            at: Instant::now(), listings: vec![], refused: 0,
            relays: self.relays.iter().map(|r| Outcome { relay: r.clone(), result: Err(STILL_ASKING.into()) }).collect(),
        })
    }

    /// The services found the last time the page asked, without asking again: what a service page
    /// may open.
    pub fn services(&self) -> Vec<Service> {
        self.snap.peek().map(|(_, s)| s.listings.iter().flat_map(to_services).collect()).unwrap_or_default()
    }

    /// The shop with Nostr key `pk` (a shop without a web address, `docs/DIRECT-LINKS.md`): its
    /// newest listing on the owner's relays. The relays are asked for that key's listings only.
    pub fn find_shop(&self, pk: &[u8; 32]) -> Result<NostrListing, String> {
        if !self.enabled() {
            return Err("The app has no Nostr relays to look the shop up on. Set them in the app's settings, or paste the seller's web address.".into());
        }
        let filter = serde_json::json!({"kinds": [market::KIND_CLASSIFIED], "authors": [hex::encode(pk)], "#t": [market::TOPIC], "limit": 20});
        let (events, _) = oneshot::query(&self.relays, &filter, QUERY_WAIT);
        shop_listing(&events, pk, xbt_nostr::now()).ok_or_else(|| "None of the app's Nostr relays has a listing from that shop. Check the key, or ask the seller which relays it publishes to.".into())
    }
}

/// VPN exits found on Nostr: each a checked announcement ([`xbt_vpn::announce::read_event`]) and the
/// signed event itself, which the VPN page's *Add this exit* writes for the VPN service to read again.
#[derive(Debug, Clone)]
pub struct FoundExit {
    pub exit: xbt_vpn::announce::Announced,
    pub event: xbt_nostr::event::Event,
}

#[derive(Debug, Clone)]
pub struct ExitSnapshot {
    pub at: Instant,
    pub exits: Vec<FoundExit>,
    pub refused: usize,
    pub relays: Vec<Outcome>,
}

/// The newest good announcement of each exit among `events`, and how many were refused.
pub fn found_exits(events: &[xbt_nostr::event::Event], now: u64) -> (Vec<FoundExit>, usize) {
    let mut best: std::collections::HashMap<String, FoundExit> = std::collections::HashMap::new();
    let mut seen = std::collections::HashSet::new();
    let mut refused = 0;
    for ev in events.iter().filter(|e| seen.insert(e.id.clone())) {
        match xbt_vpn::announce::read_event(ev, now) {
            Ok(a) if best.get(&a.exit.id).is_none_or(|o| a.created_at > o.exit.created_at) => {
                best.insert(a.exit.id.clone(), FoundExit { exit: a, event: ev.clone() });
            }
            Ok(_) => {}
            Err(_) => refused += 1,
        }
    }
    let mut out: Vec<FoundExit> = best.into_values().collect();
    out.sort_by(|a, b| (a.exit.exit.region.as_str(), a.exit.exit.price_msat_per_gb, a.exit.exit.id.as_str())
        .cmp(&(b.exit.exit.region.as_str(), b.exit.exit.price_msat_per_gb, b.exit.exit.id.as_str())));
    (out, refused)
}

/// The VPN exits on the owner's relays, asked as Found on Nostr asks for listings: the last answer at
/// once, asked again behind it when older than [`FRESH`].
pub struct ExitCache {
    relays: Vec<String>,
    snap: crate::perf::Swr<ExitSnapshot>,
}

impl ExitCache {
    pub fn new(relays: Vec<String>) -> Self {
        Self { relays, snap: crate::perf::Swr::new() }
    }

    pub fn enabled(&self) -> bool {
        !self.relays.is_empty()
    }

    /// `None`: the relays are still being asked (the first visit waits [`FIRST_WAIT`] at most).
    pub fn get(&self, refresh: bool) -> Option<ExitSnapshot> {
        let relays = self.relays.clone();
        let make = move || {
            let (events, outcomes) = crate::perf::timed(|| oneshot::query(&relays, &xbt_vpn::announce::filter(QUERY_LIMIT), QUERY_WAIT));
            let (exits, refused) = found_exits(&events, xbt_nostr::now());
            ExitSnapshot { at: Instant::now(), exits, refused, relays: outcomes }
        };
        if refresh {
            return Some(self.snap.refresh(make));
        }
        self.snap.get(FRESH, FIRST_WAIT, make)
    }

    /// The exit `id` as last found, without asking again.
    pub fn find(&self, id: &str) -> Option<FoundExit> {
        self.snap.peek().and_then(|(_, s)| s.exits.into_iter().find(|e| e.exit.exit.id == id))
    }
}

/// The newest good listing among `events` that the shop with Nostr key `pk` published for itself.
pub fn shop_listing(events: &[xbt_nostr::event::Event], pk: &[u8; 32], now: u64) -> Option<NostrListing> {
    let origin = xbt402::shop::origin_for(pk);
    let author = hex::encode(pk);
    events.iter().filter_map(|e| market::read_event(e, now).ok())
        .filter(|n| n.author == author && n.listing.seller == origin)
        .max_by_key(|n| n.created_at)
}

/// A checked listing as services of Browse: one for a `listing/0`, one per service for a
/// `listing/1`, as the Services page makes them.
pub fn to_services(n: &NostrListing) -> Vec<Service> {
    crate::services::from_listing(&n.listing)
}

/// Of one author's listings under one receipt key, only the newest: a shop that changed its address
/// (or went from a web address to its key, #40) left its old listing behind on relays that keep it
/// after its withdrawal, and Found on Nostr listed the shop twice.
pub fn newest_per_shop(listings: Vec<NostrListing>) -> Vec<NostrListing> {
    let mut newest: std::collections::HashMap<(String, String), u64> = Default::default();
    for n in &listings {
        let t = newest.entry((n.listing.receipt_key.clone(), n.author.clone())).or_insert(n.created_at);
        *t = (*t).max(n.created_at);
    }
    listings.into_iter().filter(|n| newest.get(&(n.listing.receipt_key.clone(), n.author.clone())).is_none_or(|t| n.created_at >= *t)).collect()
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

#[cfg(test)]
mod swr_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// #40: a shop that went Private is listed once, at its key, not also at its old web address.
    #[test]
    fn a_shop_that_moved_is_listed_once() {
        let l = |seller: &str, author: &str, at: u64| NostrListing {
            listing: xbt402::listing::Listing { name: "Demo".into(), kind: "video".into(), seller: seller.into(), receipt_key: "rk".into(),
                prices: serde_json::Value::Null, items: vec![], licence: String::new(), credits: String::new(), updated: String::new(), services: vec![] },
            author: author.into(), event_id: format!("{seller}{at}"), created_at: at, transport: None,
        };
        let got = newest_per_shop(vec![l("https://stream.example", "a1", 100), l("http://key.shop.invalid", "a1", 200), l("https://other.example", "a2", 50)]);
        let sellers: Vec<&str> = got.iter().map(|n| n.listing.seller.as_str()).collect();
        assert_eq!(sellers, ["http://key.shop.invalid", "https://other.example"]);
    }

    /// Found on Nostr never waits for the relays once it has an answer (0.2.2: the page took up to
    /// the relays' 8 s each time its last answer was over two minutes old).
    #[test]
    fn the_page_serves_the_last_answer_and_asks_the_relays_behind_it() {
        let asked = Arc::new(AtomicUsize::new(0));
        let a = asked.clone();
        let c = NostrCache::with_query(vec!["wss://relay.example".into()], Arc::new(move |r: &[String]| {
            a.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(400));
            (vec![], r.iter().map(|r| Outcome { relay: r.clone(), result: Ok(()) }).collect())
        }));
        // the first visit waits for them (within FIRST_WAIT)
        let s = c.get(false);
        assert!(s.relays.iter().all(|o| o.result.is_ok()), "{:?}", s.relays);
        // fresh: no asking
        let t = Instant::now();
        c.get(false);
        assert!(t.elapsed() < Duration::from_millis(100));
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        // stale: served at once, asked again behind it
        c.snap.expire();
        let t = Instant::now();
        let s = c.get(false);
        assert!(t.elapsed() < Duration::from_millis(100), "a stale answer is served at once: {:?}", t.elapsed());
        assert!(s.relays.iter().all(|o| o.result.is_ok()));
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(asked.load(Ordering::SeqCst), 2, "asked again in the background");
        // Look again waits for the relays
        let t = Instant::now();
        c.get(true);
        assert!(t.elapsed() >= Duration::from_millis(400));
        assert_eq!(c.queries(), 3);
    }

    #[test]
    fn a_slow_first_visit_says_the_relays_are_still_being_asked() {
        let c = NostrCache::with_query(vec!["wss://slow.example".into()], Arc::new(|_: &[String]| {
            std::thread::sleep(FIRST_WAIT + Duration::from_millis(800));
            (vec![], vec![])
        }));
        let t = Instant::now();
        let s = c.get(false);
        assert!(t.elapsed() < FIRST_WAIT + Duration::from_millis(400));
        assert_eq!(s.relays, vec![Outcome { relay: "wss://slow.example".into(), result: Err(STILL_ASKING.into()) }]);
    }
}
