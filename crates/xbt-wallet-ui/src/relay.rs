//! Links for the buyer's own player (VLC, mpv, a TV app): `GET <UI>/r/<token>`, relayed to the
//! connector like a download's `/s/<file URL>`, without the login cookie a player does not have.
//!
//! * A link is made by a POST from the logged-in page of a Files service (CSRF-checked like every
//!   POST), for one file of the services file, and is bound to that file's URL here: the token names
//!   the file, the request cannot name another, and a file taken out of the services file stops.
//! * The token is 32 random bytes (64 hex characters), compared in constant time.
//! * It expires a fixed time after it was made (`XBT_UI_RELAY_LINK_S`, 6 hours by default), can be
//!   revoked on that page, and lives in memory only: a restart of the UI revokes every link.
//! * At most [`MAX_LINKS`] are live; a new one past that replaces the oldest.
//!
//! * Where the platform's own login sits in front of the UI's port (umbrelOS's app login), the links
//!   are served on a port of their own (`XBT_UI_LINKS_BIND`), which answers `GET /r/<token>` (and
//!   its `HEAD`, with no call to the connector) and nothing else, through the same checks ([`crate::server::spawn`]); the page gives that address.
//!
//! What a link can spend is what the connector spends for that one file: each request through it
//! is one paid call under the connector's task and per-call cap, within the owner's budgets. It
//! cannot reach any page of the UI, any other file, or the signer.
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::{ct_eq, random_bytes};

pub const MAX_LINKS: usize = 32;

struct Link {
    token: String,
    item: String,
    /// The service it was made for ([`crate::services::Service::id`]).
    service: String,
    expires: Instant,
    used: Arc<LinkUse>,
}

/// What a link carried, as the UI relayed it: the bytes sent to the player, and how many of its
/// requests are open now. Counted here, at the relay: the sats are figured from the file's listed
/// price, not from the seller's receipts (the connector does not tell the UI what each call paid).
#[derive(Default)]
pub struct LinkUse {
    bytes: AtomicU64,
    open: AtomicUsize,
    /// When bytes last went to the player, in ms since [`epoch`].
    last_ms: AtomicU64,
}

/// How recently bytes must have moved for a link to read as playing.
pub const PLAYING_WITHIN: Duration = Duration::from_secs(10);

/// A fixed instant of this process, to date a link's last bytes by.
fn epoch() -> Instant {
    static AT: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);
    *AT
}

impl LinkUse {
    /// `n` more bytes went to the player.
    pub fn sent(&self, n: u64) {
        self.bytes.fetch_add(n, Ordering::Relaxed);
        self.last_ms.store(u64::try_from(epoch().elapsed().as_millis()).unwrap_or(u64::MAX).max(1), Ordering::Relaxed);
    }

    /// A request is open and bytes moved within [`PLAYING_WITHIN`].
    fn playing(&self) -> bool {
        let last = self.last_ms.load(Ordering::Relaxed);
        let now = u64::try_from(epoch().elapsed().as_millis()).unwrap_or(u64::MAX);
        self.open.load(Ordering::Relaxed) > 0 && last > 0 && now.saturating_sub(last) < PLAYING_WITHIN.as_millis() as u64
    }

    /// A request through the link starts; it ends when the guard drops.
    pub fn start(self: &Arc<Self>) -> OpenGuard {
        self.open.fetch_add(1, Ordering::Relaxed);
        OpenGuard(self.clone())
    }
}

/// One request of a link in progress ([`LinkUse::start`]).
pub struct OpenGuard(Arc<LinkUse>);

impl Drop for OpenGuard {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct RelayLinks {
    links: Mutex<Vec<Link>>,
    ttl: Duration,
    /// Where the links' own listener answers (`XBT_UI_LINKS_BIND`), once it does.
    served_at: Mutex<Option<std::net::SocketAddr>>,
}

/// The address a player's link starts with (ending in `/`, the token's `r/<token>` follows) when the
/// links have a listener of their own on `port`: `url` (`XBT_UI_LINKS_URL`), by the box's IP where the
/// page was opened by its IPv4 address (as the AI page gives its address), since another device may not
/// resolve the box's name; without `url`, the page's own host on that port. `None`: no host to name.
pub fn links_base(url: Option<&str>, port: u16, page_host: &str) -> Option<String> {
    let page_host = page_host.trim();
    let page_name = if page_host.starts_with('[') {
        page_host.split_inclusive(']').next().unwrap_or("")
    } else {
        page_host.rsplit_once(':').map_or(page_host, |(h, _)| h)
    };
    let page_ip = page_name.parse::<std::net::Ipv4Addr>().ok().filter(|a| !a.is_loopback() && !a.is_unspecified());
    let Some(url) = url else {
        return (!page_name.is_empty()).then(|| format!("http://{page_name}:{port}/"));
    };
    let url = url.trim_end_matches('/');
    let (scheme, rest) = url.split_once("://")?;
    let cut = rest.find('/').unwrap_or(rest.len());
    let (authority, path) = rest.split_at(cut);
    let (host, port_part) = match authority.rsplit_once(':') {
        Some((h, p)) if !authority.starts_with('[') => (h, format!(":{p}")),
        _ => (authority, String::new()),
    };
    Some(match page_ip {
        Some(ip) if !host.starts_with('[') && host.parse::<std::net::IpAddr>().is_err() => format!("{scheme}://{ip}{port_part}{path}/"),
        _ => format!("{url}/"),
    })
}

/// A live link, as a Files service's page lists it.
pub struct Shown {
    pub token: String,
    pub left: Duration,
    /// The bytes it has carried so far.
    pub bytes: u64,
    /// A request through it is open now (the player holds it).
    pub in_use: bool,
    /// And bytes moved through it within [`PLAYING_WITHIN`] (the player is reading).
    pub playing: bool,
}

impl RelayLinks {
    pub fn new(ttl: Duration) -> Self {
        Self { links: Mutex::new(Vec::new()), ttl, served_at: Mutex::new(None) }
    }

    /// The links' own listener answers at `addr`.
    pub fn set_served_at(&self, addr: std::net::SocketAddr) {
        *self.served_at.lock().unwrap_or_else(|p| p.into_inner()) = Some(addr);
    }

    /// Where the links' own listener answers; `None`: the links are on the UI's own address.
    pub fn served_at(&self) -> Option<std::net::SocketAddr> {
        *self.served_at.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn live(&self) -> std::sync::MutexGuard<'_, Vec<Link>> {
        let mut l = self.links.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        l.retain(|x| x.expires > now);
        l
    }

    /// A new link for `item` (a URL of the services file): its token.
    pub fn create(&self, item: &str) -> String {
        self.create_for(item, "")
    }

    /// A new link for `item` of the service `service` the buyer chose: its token.
    pub fn create_for(&self, item: &str, service: &str) -> String {
        let token = hex::encode(random_bytes::<32>());
        let mut l = self.live();
        if l.len() >= MAX_LINKS {
            l.remove(0);
        }
        l.push(Link { token: token.clone(), item: item.to_string(), service: service.to_string(), expires: Instant::now() + self.ttl, used: Arc::default() });
        token
    }

    /// The item a live token is for.
    pub fn item_of(&self, token: &str) -> Option<String> {
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let l = self.live();
        // every live link is compared, so that the time taken says nothing of which one matched
        l.iter().fold(None, |found, x| if ct_eq(x.token.as_bytes(), token.as_bytes()) { Some(x.item.clone()) } else { found })
    }

    /// The service a live token was made for (empty: none named).
    pub fn service_of(&self, token: &str) -> Option<String> {
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let l = self.live();
        l.iter().fold(None, |found, x| if ct_eq(x.token.as_bytes(), token.as_bytes()) { Some(x.service.clone()) } else { found })
    }

    /// The counter of what a live token carries.
    pub fn usage(&self, token: &str) -> Option<Arc<LinkUse>> {
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let l = self.live();
        l.iter().fold(None, |found, x| if ct_eq(x.token.as_bytes(), token.as_bytes()) { Some(x.used.clone()) } else { found })
    }

    /// Revoke a link. True: it was live.
    pub fn revoke(&self, token: &str) -> bool {
        let mut l = self.live();
        let before = l.len();
        l.retain(|x| !ct_eq(x.token.as_bytes(), token.as_bytes()));
        l.len() != before
    }

    /// The live links of `item`, newest first.
    pub fn of_item(&self, item: &str) -> Vec<Shown> {
        let now = Instant::now();
        self.live().iter().rev().filter(|x| x.item == item).map(|x| Shown {
            token: x.token.clone(), left: x.expires - now,
            bytes: x.used.bytes.load(Ordering::Relaxed), in_use: x.used.open.load(Ordering::Relaxed) > 0, playing: x.used.playing(),
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A link on its own port: the configured address, by the IP the page was opened at where it was,
    /// else the page's host on that port.
    #[test]
    fn a_links_address_is_by_ip_where_the_page_was_opened_by_ip() {
        let url = Some("http://umbrel.local:33541");
        assert_eq!(links_base(url, 33541, "192.168.1.20:8482").as_deref(), Some("http://192.168.1.20:33541/"));
        assert_eq!(links_base(url, 33541, "192.168.1.20").as_deref(), Some("http://192.168.1.20:33541/"));
        assert_eq!(links_base(url, 33541, "umbrel.local:8482").as_deref(), Some("http://umbrel.local:33541/"));
        // a loopback page (an ssh tunnel) says nothing of where other devices find the box
        assert_eq!(links_base(url, 33541, "127.0.0.1:8482").as_deref(), Some("http://umbrel.local:33541/"));
        assert_eq!(links_base(url, 33541, "[fe80::1]:8482").as_deref(), Some("http://umbrel.local:33541/"));
        // an address that is already an IP is kept
        assert_eq!(links_base(Some("http://10.0.0.5:33541/"), 33541, "192.168.1.20:8482").as_deref(), Some("http://10.0.0.5:33541/"));
        // no address configured: the page's host on the links' port
        assert_eq!(links_base(None, 33541, "umbrel.local:8482").as_deref(), Some("http://umbrel.local:33541/"));
        assert_eq!(links_base(None, 40001, "[::1]:8482").as_deref(), Some("http://[::1]:40001/"));
        assert_eq!(links_base(None, 33541, ""), None);
    }

    /// A link counts what it carries while a request is open, and keeps the total after.
    #[test]
    fn a_link_counts_its_bytes_while_in_use_and_keeps_the_total() {
        let links = RelayLinks::new(Duration::from_secs(60));
        let t = links.create("https://box.example/files/a.mkv");
        let u = links.usage(&t).unwrap();
        let g = u.start();
        u.sent(1000);
        u.sent(500);
        let s = &links.of_item("https://box.example/files/a.mkv")[0];
        assert_eq!((s.bytes, s.in_use, s.playing), (1500, true, true));
        drop(g);
        let s = &links.of_item("https://box.example/files/a.mkv")[0];
        assert_eq!((s.bytes, s.in_use, s.playing), (1500, false, false));
        assert!(links.usage(&"0".repeat(64)).is_none());
    }

    #[test]
    fn a_link_names_its_item_until_it_expires_or_is_revoked() {
        let r = RelayLinks::new(Duration::from_millis(200));
        let a = r.create("https://stream.lazarus-xbt.xyz/a");
        let b = r.create("https://stream.lazarus-xbt.xyz/b");
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert_eq!(r.item_of(&a).as_deref(), Some("https://stream.lazarus-xbt.xyz/a"));
        assert_eq!(r.item_of(&b).as_deref(), Some("https://stream.lazarus-xbt.xyz/b"));
        assert_eq!(r.item_of(&a.to_uppercase().replace(|c: char| c.is_ascii_digit(), "0")), None);
        assert_eq!(r.item_of(""), None);
        assert_eq!(r.of_item("https://stream.lazarus-xbt.xyz/a").len(), 1);
        assert!(r.revoke(&a) && !r.revoke(&a));
        assert_eq!(r.item_of(&a), None);
        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(r.item_of(&b), None, "expired");
        let many: Vec<String> = (0..MAX_LINKS + 1).map(|i| r.create(&format!("https://x.example/{i}"))).collect();
        assert_eq!(r.item_of(&many[0]), None, "the oldest made room");
        assert!(r.item_of(&many[MAX_LINKS]).is_some());
    }
}
