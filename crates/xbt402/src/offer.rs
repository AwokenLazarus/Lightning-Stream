//! Paying a seller by BOLT 12 offer (`docs/TICKETS.md`, section 15): the payer note that binds a
//! payment made by offer to the session it pays for. No state and no IO: the seller gateway and
//! the wallet compute it alike.
//!
//! A seller's 402 entry for prepaid tickets, and its lottery entry, may carry `extra.offer`: one
//! BOLT 12 offer of the seller's own node, with no amount. A buyer that understands it fetches an
//! invoice from that offer for the exact amount (a ticket's `ticketMsat`, or the session's win
//! size) and puts this note in the invoice request's `payer_note`. The seller's node repeats the
//! note in the invoice it signs, and the seller credits a paid invoice to the session the note
//! names only when the note's MAC is good under that session's key, the purpose and amount are
//! the ones paid, and the note has not been used before.
//!
//! ```text
//! note = "xbt402-note/0" SP scheme SP session SP purpose SP amountMsat SP nonce SP mac
//! mac  = HMAC-SHA256(key, "xbt402/offer-note/0|" scheme "|" session "|" purpose "|" amountMsat "|" nonce)
//! ```
//!
//! `scheme` is `ticket` or `lottery`, the scheme whose session `key` is (the key the seller sent
//! at `lock` or at `open`); `purpose` is `ticket` for a prepaid ticket and `win:<draw>` for the
//! win of draw `<draw>` of a lottery session; `nonce` is 16 random bytes, hex, fresh for every
//! invoice requested; `mac` is hex. Every field is lower-case ASCII, so the note has one spelling.
//!
//! Why a MAC and not the session id alone: anyone who learns a session id (it travels in every
//! request header) could otherwise name it on a payment of theirs, and a seller would have no way
//! to tell whose payment it is. With the MAC only the two parties who hold the session key can
//! write a note the seller takes, and the amount and purpose in it cannot be changed after the
//! fact. Why a nonce: one session pays many prepaid tickets of one size, and each note must be
//! told apart, so that a note seen once credits nothing a second time.
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// The first word of every note.
pub const NOTE_VERSION: &str = "xbt402-note/0";
/// What the MAC is taken over, before the fields.
pub const NOTE_LABEL: &str = "xbt402/offer-note/0";
/// The `extra` field of a 402 entry that carries the seller's offer.
pub const EXTRA_OFFER: &str = "offer";
/// A note is never longer than this (the longest it can be is about 200 characters).
pub const MAX_NOTE: usize = 256;

/// What a payment by offer pays for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// A prepaid ticket of a ticket session (`settle: "on-arrival"`).
    Ticket,
    /// The win of this draw of a lottery session.
    Win(u64),
}

impl Purpose {
    /// The scheme whose session this purpose belongs to.
    pub fn scheme(self) -> &'static str {
        match self {
            Self::Ticket => crate::ticket::SCHEME,
            Self::Win(_) => crate::lottery::SCHEME,
        }
    }

    pub fn word(self) -> String {
        match self {
            Self::Ticket => "ticket".into(),
            Self::Win(d) => format!("win:{d}"),
        }
    }

    fn parse(scheme: &str, s: &str) -> Option<Self> {
        let p = match s.strip_prefix("win:") {
            Some(d) if decimal(d) => Self::Win(d.parse().ok()?),
            Some(_) => return None,
            None if s == "ticket" => Self::Ticket,
            None => return None,
        };
        (p.scheme() == scheme).then_some(p)
    }
}

/// A note, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub session: String,
    pub purpose: Purpose,
    pub amount_msat: u64,
    pub nonce: [u8; 16],
    mac: String,
}

impl Note {
    /// The note's MAC is good under `key`, the key of the session it names.
    pub fn verify(&self, key: &[u8; 32]) -> bool {
        crate::wire::auth_eq(&mac(key, &self.session, self.purpose, self.amount_msat, &self.nonce), &self.mac)
    }

    /// What tells this note apart from every other: no two payments may carry it.
    pub fn id(&self) -> String {
        format!("{} {} {}", self.session, self.purpose.word(), hex::encode(self.nonce))
    }
}

fn decimal(s: &str) -> bool {
    !s.is_empty() && s.len() <= 20 && s.bytes().all(|c| c.is_ascii_digit()) && (s == "0" || !s.starts_with('0'))
}

fn mac(key: &[u8; 32], session: &str, purpose: Purpose, amount_msat: u64, nonce: &[u8; 16]) -> String {
    let msg = [NOTE_LABEL, purpose.scheme(), session, &purpose.word(), &amount_msat.to_string(), &hex::encode(nonce)].join("|");
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(msg.as_bytes());
    hex::encode(m.finalize().into_bytes())
}

/// The note a buyer puts in its invoice request: for `purpose` in `session` (whose key is `key`),
/// for exactly `amount_msat`, with a fresh `nonce`.
pub fn note(key: &[u8; 32], session: &str, purpose: Purpose, amount_msat: u64, nonce: &[u8; 16]) -> String {
    [NOTE_VERSION, purpose.scheme(), session, &purpose.word(), &amount_msat.to_string(), &hex::encode(nonce),
     &mac(key, session, purpose, amount_msat, nonce)]
        .join(" ")
}

/// Read a note strictly: any other spelling is no note. Its MAC is [`Note::verify`]'s to check.
pub fn parse(s: &str) -> Option<Note> {
    if s.len() > MAX_NOTE {
        return None;
    }
    let f: Vec<&str> = s.split(' ').collect();
    let [version, scheme, session, purpose, amount, nonce, mac] = f.as_slice() else { return None };
    let hex_lower = |x: &str, n: usize| x.len() == n && x.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
    if *version != NOTE_VERSION || !hex_lower(session, 32) || !hex_lower(nonce, 32) || !hex_lower(mac, 64) || !decimal(amount) {
        return None;
    }
    let mut n = [0u8; 16];
    n.copy_from_slice(&hex::decode(nonce).ok()?);
    Some(Note { session: session.to_string(), purpose: Purpose::parse(scheme, purpose)?, amount_msat: amount.parse().ok()?, nonce: n, mac: mac.to_string() })
}

/// The offer an `accepts` entry carries (`extra.offer`), if it carries one that looks like an
/// offer (`lno1...`). Whether it can be paid is the wallet's to check.
pub fn entry_offer(entry: &serde_json::Value) -> Option<&str> {
    let o = entry.get("extra")?.get(EXTRA_OFFER)?.as_str()?.trim();
    (o.len() > 4 && o.len() <= 4096 && o.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("lno1"))).then_some(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];
    const SID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn a_note_reads_back_and_verifies_only_under_its_own_key_and_fields() {
        let n = note(&KEY, SID, Purpose::Ticket, 1_000_000, &[1u8; 16]);
        assert!(n.starts_with("xbt402-note/0 ticket 0123456789abcdef0123456789abcdef ticket 1000000 01010101"), "{n}");
        assert!(n.len() <= MAX_NOTE);
        let r = parse(&n).unwrap();
        assert_eq!((r.session.as_str(), r.purpose, r.amount_msat, r.nonce), (SID, Purpose::Ticket, 1_000_000, [1u8; 16]));
        assert!(r.verify(&KEY));
        assert!(!r.verify(&[8u8; 32]));
        // any field changed: the MAC no longer holds
        for (from, to) in [(" 1000000 ", " 1000001 "), (" ticket 1", " ticket 2")] {
            if let Some(changed) = parse(&n.replacen(from, to, 1)) {
                assert!(!changed.verify(&KEY), "{from} -> {to}");
            }
        }
        let w = parse(&note(&KEY, SID, Purpose::Win(42), 64_000, &[2u8; 16])).unwrap();
        assert_eq!((w.purpose, w.purpose.scheme()), (Purpose::Win(42), "lottery"));
        assert!(w.verify(&KEY));
        assert_ne!(w.id(), r.id());
    }

    #[test]
    fn a_note_has_one_spelling() {
        let n = note(&KEY, SID, Purpose::Win(3), 64_000, &[2u8; 16]);
        let bad = [
            n.replace("xbt402-note/0", "xbt402-note/1"),
            n.replace(' ', "  "),
            n.to_uppercase(),
            n.replace(" lottery ", " ticket "),
            n.replace("win:3", "win:03"),
            n.replace("win:3", "win:"),
            n.replace(" 64000 ", " 064000 "),
            format!("{n} "),
            "x".repeat(300),
            String::new(),
        ];
        for b in bad {
            assert!(parse(&b).is_none_or(|r| !r.verify(&KEY)), "{b}");
        }
        // a prepaid ticket's purpose under the lottery's scheme, or the other way round, is no note
        assert!(parse(&n.replace(" lottery ", " ticket ")).is_none());
    }

    #[test]
    fn an_entry_offer_is_read_where_it_looks_like_one() {
        let e = |o: serde_json::Value| serde_json::json!({"extra": {"offer": o}});
        assert_eq!(entry_offer(&e("lno1qcp4256ypq".into())), Some("lno1qcp4256ypq"));
        for bad in [e("lnbc1xyz".into()), e(5.into()), e("lno1".into()), serde_json::json!({"extra": {}})] {
            assert_eq!(entry_offer(&bad), None, "{bad}");
        }
    }
}
