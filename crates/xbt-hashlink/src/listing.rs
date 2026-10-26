//! A hasher's `hashrate` listing on Nostr: what it rents, at what price, where its link answers
//! and where its slices are paid. Nostr is the directory only: the work goes over the link, the
//! money over Lightning.
//!
//! The event is a NIP-99 classified listing (kind 30402), so any client that shows classifieds
//! shows it. A reader of ours takes nothing from its human-readable tags: everything it uses is
//! in the `xbt-hashrate` tag, a JSON object, and is believed only when
//! * the event's own signature holds (its author is a Nostr key of the hasher's),
//! * the `xbt-hashrate-bind` tag is the link key's ECDSA signature binding that Nostr key, and
//! * the `d` tag is the link key.
//!
//! So whoever can publish a listing that names a link key holds that key, and the Noise handshake
//! with that key is what the buyer then checks. What a listing does not prove: that its Lightning
//! node is the hasher's (the gateway's own 402 names the node the tickets pay, and the buyer's
//! wallet ties the seller's origin to a node it trusts), or that the hashrate is real (the meter
//! pays only for accepted work).

use crate::msg::Terms;
use secp256k1::ecdsa::Signature;
use secp256k1::{Message, PublicKey, SecretKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;
use xbt_nostr::event::{tag, Event, Keys};

/// NIP-99.
pub const KIND: u64 = 30402;
/// The `t` tag readers ask relays for.
pub const TOPIC: &str = "lightning-stream-hashrate";
pub const DOC_TAG: &str = "xbt-hashrate";
pub const BIND_TAG: &str = "xbt-hashrate-bind";
pub const VERSION: &str = "hashrate/0";
const BIND: &str = "xbt-hashlink/nostr-bind/0";
/// An event dated further ahead than this is refused.
const MAX_AHEAD_S: u64 = 600;

#[derive(Clone, Debug, PartialEq)]
pub struct Hashrate {
    pub name: String,
    /// The proof of work hashed (`blake2b`).
    pub algorithm: String,
    /// Hashrate on offer, hashes a second.
    pub hashrate_hs: u64,
    /// Where the hasher's link answers, and its static key.
    pub link_addr: String,
    pub link_key: PublicKey,
    /// Where finished slices are paid (the hasher's gateway route), and the node its tickets pay.
    pub pay_url: String,
    pub pay_node: String,
    pub terms: Terms,
}

fn bind_message(nostr: &[u8; 32]) -> Message {
    let mut h = Sha256::new();
    h.update(BIND.as_bytes());
    h.update(b"|");
    h.update(nostr);
    Message::from_digest(h.finalize().into())
}

impl Hashrate {
    pub fn to_json(&self) -> Value {
        json!({
            "version": VERSION, "name": self.name, "algorithm": self.algorithm, "hashrateHs": self.hashrate_hs.to_string(),
            "link": {"addr": self.link_addr, "key": hex::encode(self.link_key.serialize())},
            "pay": {"url": self.pay_url, "node": self.pay_node},
            "terms": self.terms.to_json(),
        })
    }

    pub fn from_json(v: &Value) -> Result<Hashrate, String> {
        let s = |p: &str| v.pointer(p).and_then(Value::as_str).map(str::to_string).ok_or(format!("{p} missing"));
        if s("/version")? != VERSION {
            return Err("not a hashrate/0 listing".into());
        }
        let key = hex::decode(s("/link/key")?).ok().and_then(|b| PublicKey::from_slice(&b).ok()).ok_or("bad link key")?;
        Ok(Hashrate {
            name: s("/name")?,
            algorithm: s("/algorithm")?,
            hashrate_hs: s("/hashrateHs")?.parse().map_err(|_| "bad hashrate")?,
            link_addr: s("/link/addr")?,
            link_key: key,
            pay_url: s("/pay/url")?,
            pay_node: s("/pay/node")?,
            terms: Terms::from_json(v.get("terms").ok_or("terms missing")?).ok_or("bad terms")?,
        })
    }

    /// The listing event, by the Nostr key `nostr`, bound to the link key `link`.
    pub fn event(&self, link: &SecretKey, nostr: &Keys, created_at: u64) -> Result<Event, String> {
        if PublicKey::from_secret_key(secp256k1::SECP256K1, link) != self.link_key {
            return Err("the link key is not the listing's".into());
        }
        let bind = secp256k1::SECP256K1.sign_ecdsa(&bind_message(&nostr.public.serialize()), link);
        let price_sat = format!("{}", self.terms.price_msat as f64 / 1000.0);
        let tags = vec![
            tag("d", &hex::encode(self.link_key.serialize())),
            tag("title", &self.name),
            tag("summary", &format!("{} hashrate, {} sat a slice, paid as accepted work arrives", self.algorithm, price_sat)),
            tag("published_at", &created_at.to_string()),
            tag("t", TOPIC),
            tag("t", "hashrate"),
            tag("t", &self.algorithm),
            vec!["price".into(), price_sat, "SAT".into(), "slice".into()],
            tag(DOC_TAG, &self.to_json().to_string()),
            tag(BIND_TAG, &hex::encode(bind.serialize_compact())),
        ];
        let content = format!(
            "**{}**: {} hashrate for rent, about {:.2} TH/s, pointed at your own DATUM Gateway. Paid per slice of accepted work over Lightning Stream.\n",
            self.name,
            self.algorithm,
            self.hashrate_hs as f64 / 1e12
        );
        Ok(Event::sign(nostr, created_at, KIND, tags, content))
    }

    /// Check an event as [`Self::event`] wrote it.
    pub fn read_event(ev: &Event, now: u64) -> Result<Hashrate, String> {
        if ev.kind != KIND || !ev.verify() {
            return Err("not a signed classified listing".into());
        }
        if ev.created_at > now + MAX_AHEAD_S {
            return Err("dated in the future".into());
        }
        if !ev.tags.iter().any(|t| t.len() >= 2 && t[0] == "t" && t[1] == TOPIC) {
            return Err("not a hashrate listing".into());
        }
        let doc: Value = serde_json::from_str(ev.tag(DOC_TAG).ok_or("no listing in the event")?).map_err(|_| "listing not JSON")?;
        let h = Hashrate::from_json(&doc)?;
        if ev.tag("d") != Some(hex::encode(h.link_key.serialize()).as_str()) {
            return Err("the d tag is not the link key".into());
        }
        let author: [u8; 32] = hex::decode(&ev.pubkey).ok().and_then(|b| b.try_into().ok()).ok_or("bad author")?;
        let sig = hex::decode(ev.tag(BIND_TAG).ok_or("no binding")?).ok().and_then(|b| Signature::from_compact(&b).ok()).ok_or("bad binding")?;
        secp256k1::SECP256K1
            .verify_ecdsa(&bind_message(&author), &sig, &h.link_key)
            .map_err(|_| "the link key did not bind this Nostr key")?;
        Ok(h)
    }
}

pub fn filter(limit: usize) -> Value {
    json!({"kinds": [KIND], "#t": [TOPIC], "limit": limit})
}

/// Publish a listing to each relay: what each said.
pub fn publish(relays: &[String], ev: &Event) -> Vec<Value> {
    xbt_nostr::oneshot::publish(relays, ev, Duration::from_secs(10))
        .into_iter()
        .map(|o| json!({"relay": o.relay, "ok": o.result.is_ok(), "why": o.result.err()}))
        .collect()
}

/// Every good listing on the relays, newest per link key; and how many events were refused.
pub fn find(relays: &[String], now: u64) -> (Vec<(Hashrate, Event)>, usize) {
    let (events, _) = xbt_nostr::oneshot::query(relays, &filter(100), Duration::from_secs(10));
    let mut best: Vec<(Hashrate, Event)> = Vec::new();
    let mut refused = 0;
    for ev in events {
        match Hashrate::read_event(&ev, now) {
            Ok(h) => match best.iter_mut().find(|(b, _)| b.link_key == h.link_key) {
                Some(slot) if slot.1.created_at < ev.created_at => *slot = (h, ev),
                Some(_) => {}
                None => best.push((h, ev)),
            },
            Err(_) => refused += 1,
        }
    }
    (best, refused)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listing(link: &SecretKey) -> Hashrate {
        Hashrate {
            name: "test hasher".into(),
            algorithm: "blake2b".into(),
            hashrate_hs: 4_100_000_000_000,
            link_addr: "192.0.2.1:9".into(),
            link_key: PublicKey::from_secret_key(secp256k1::SECP256K1, link),
            pay_url: "https://192.0.2.1:8443/hashrate".into(),
            pay_node: "02".to_string() + &"11".repeat(32),
            terms: Terms { slice_work: 1 << 50, price_msat: 40_000, grace_ms: 30_000 },
        }
    }

    #[test]
    fn written_and_read_back() {
        let link = SecretKey::from_slice(&[5; 32]).unwrap();
        let nostr = Keys::generate();
        let h = listing(&link);
        let ev = h.event(&link, &nostr, 1000).unwrap();
        assert_eq!(Hashrate::read_event(&ev, 1000).unwrap(), h);
        // a different Nostr key, re-signing the same tags, is not bound
        let other = Keys::generate();
        let forged = Event::sign(&other, 1000, KIND, ev.tags.clone(), ev.content.clone());
        assert!(Hashrate::read_event(&forged, 1000).is_err());
        // a changed price breaks the event's signature
        let mut changed = ev.clone();
        changed.tags[8][1] = changed.tags[8][1].replace("40000", "1");
        assert!(Hashrate::read_event(&changed, 1000).is_err());
        // another link key in the document is not what the binding is for
        let link2 = SecretKey::from_slice(&[6; 32]).unwrap();
        let ev2 = Hashrate { link_key: PublicKey::from_secret_key(secp256k1::SECP256K1, &link2), ..h.clone() };
        let tags: Vec<Vec<String>> = ev.tags.iter().map(|t| if t[0] == DOC_TAG { tag(DOC_TAG, &ev2.to_json().to_string()) } else { t.clone() }).collect();
        assert!(Hashrate::read_event(&Event::sign(&nostr, 1000, KIND, tags, String::new()), 1000).is_err());
        assert!(Hashrate::read_event(&ev, 0).is_err(), "dated ahead");
        assert!(h.event(&link2, &nostr, 1).is_err());
    }
}
