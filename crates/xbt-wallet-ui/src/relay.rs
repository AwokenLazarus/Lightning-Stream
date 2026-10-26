//! Links for an external player (VLC, mpv, a TV app): `GET <UI>/r/<token>`, relayed to the
//! connector like the in-page player's `/s/<seller URL>`, without the login cookie a player does
//! not have.
//!
//! * A link is made by a POST from the logged-in Player page (CSRF-checked like every POST), for
//!   one item of the services file, and is bound to that item's URL here: the token names the item,
//!   the request cannot name another, and an item taken out of the services file stops playing.
//! * The token is 32 random bytes (64 hex characters), compared in constant time.
//! * It expires a fixed time after it was made (`XBT_UI_RELAY_LINK_S`, 6 hours by default), can be
//!   revoked on the Player page, and lives in memory only: a restart of the UI revokes every link.
//! * At most [`MAX_LINKS`] are live; a new one past that replaces the oldest.
//!
//! What a link can spend is what the connector spends for that one item: each request through it
//! is one paid call under the connector's task and per-call cap, within the owner's budgets. It
//! cannot reach any page of the UI, any other item, or the signer.
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::{ct_eq, random_bytes};

pub const MAX_LINKS: usize = 32;

struct Link {
    token: String,
    item: String,
    expires: Instant,
}

pub struct RelayLinks {
    links: Mutex<Vec<Link>>,
    ttl: Duration,
}

/// A live link, as the Player page lists it.
pub struct Shown {
    pub token: String,
    pub left: Duration,
}

impl RelayLinks {
    pub fn new(ttl: Duration) -> Self {
        Self { links: Mutex::new(Vec::new()), ttl }
    }

    fn live(&self) -> std::sync::MutexGuard<'_, Vec<Link>> {
        let mut l = self.links.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        l.retain(|x| x.expires > now);
        l
    }

    /// A new link for `item` (a URL of the services file): its token.
    pub fn create(&self, item: &str) -> String {
        let token = hex::encode(random_bytes::<32>());
        let mut l = self.live();
        if l.len() >= MAX_LINKS {
            l.remove(0);
        }
        l.push(Link { token: token.clone(), item: item.to_string(), expires: Instant::now() + self.ttl });
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
        self.live().iter().rev().filter(|x| x.item == item).map(|x| Shown { token: x.token.clone(), left: x.expires - now }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_names_its_item_until_it_expires_or_is_revoked() {
        let r = RelayLinks::new(Duration::from_millis(200));
        let a = r.create("https://media.lazarus-xbt.xyz/a");
        let b = r.create("https://media.lazarus-xbt.xyz/b");
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert_eq!(r.item_of(&a).as_deref(), Some("https://media.lazarus-xbt.xyz/a"));
        assert_eq!(r.item_of(&b).as_deref(), Some("https://media.lazarus-xbt.xyz/b"));
        assert_eq!(r.item_of(&a.to_uppercase().replace(|c: char| c.is_ascii_digit(), "0")), None);
        assert_eq!(r.item_of(""), None);
        assert_eq!(r.of_item("https://media.lazarus-xbt.xyz/a").len(), 1);
        assert!(r.revoke(&a) && !r.revoke(&a));
        assert_eq!(r.item_of(&a), None);
        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(r.item_of(&b), None, "expired");
        let many: Vec<String> = (0..MAX_LINKS + 1).map(|i| r.create(&format!("https://x.example/{i}"))).collect();
        assert_eq!(r.item_of(&many[0]), None, "the oldest made room");
        assert!(r.item_of(&many[MAX_LINKS]).is_some());
    }
}
