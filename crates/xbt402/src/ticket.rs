//! The stream-ticket wire, draft v0 (`docs/TICKETS.md`): the names, the request authentication and
//! the signed receipt that a seller and a buyer must compute alike. No state and no IO: the seller
//! gateway (`xbt-gateway`) and a wallet both build on this.
//!
//! ```text
//! auth    = HMAC-SHA256(key, "ticket/auth|" session "|" seq "|" secret "|" ticket "|" request_digest_v2)
//! receipt = tagged_hash("xbt402/ticket-receipt/v0", f(scheme) ‖ f(session) ‖ … ‖ f(bodyHash)),  f(x) = LE64(len(x)) ‖ x
//! ```
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::json::py_str;
use crate::wire::{put_field, tagged};

pub const SCHEME: &str = "ticket";
pub const VERSION: &str = "ticket/0";
pub const ASSET: &str = "XBT:msat";
/// Every ticket invoice carries this feature bit, required: it is what makes an invoice XBT's.
pub const FEATURE_BLAKE2B: u64 = 512;
/// Where the session endpoints live on the seller's origin unless its terms say otherwise.
pub const SESSION_PATH: &str = "/x402/ticket";
pub const RECEIPT_TAG: &str = "xbt402/ticket-receipt/v0";
/// A ticket is used only while more than this many blocks are left before its HTLC expires: the
/// seller's node cancels a held invoice 18 blocks before expiry, and 6 more are for a settle that
/// has to go on chain.
pub const SETTLE_MARGIN_BLOCKS: u32 = 24;
/// The node takes no hold invoice with a final CLTV delta of this or less.
pub const MIN_TICKET_BLOCKS: u32 = 24;
/// How long an unpaid ticket invoice may wait to be paid, in seconds.
pub const INVOICE_EXPIRY_S: u32 = 60;
/// `settle` in the terms: a ticket is a held payment, settled when its secret is used.
pub const SETTLE_ON_USE: &str = "on-use";
/// `settle` in the terms: a ticket is an ordinary payment, settled when it arrives (a prepaid
/// balance). It holds no HTLC slot and needs no hold invoice.
pub const SETTLE_ON_ARRIVAL: &str = "on-arrival";
/// The smallest ticket that may be held: the larger of the two dust limits a channel of this
/// network has (354 sat on a Lightning Fork node, 546 sat on a Core Lightning node). A held
/// payment below a channel's dust limit has no output in that channel's transaction, and its
/// value goes to the miners if the channel is force-closed while it is held.
pub const MIN_HELD_TICKET_MSAT: u64 = 546_000;
/// The pending payments a channel carries each way where its node does not say: Core Lightning's
/// default, and the smallest default of the implementations on this network. The protocol's
/// ceiling is [`MAX_CHANNEL_SLOTS`].
pub const DEFAULT_CHANNEL_SLOTS: u32 = 30;
pub const MAX_CHANNEL_SLOTS: u32 = 483;

/// The held tickets a channel of `slots` pending payments may carry: half, so that the other half
/// stays for ordinary payments, for settles on their way and for everyone else on that channel.
pub fn held_budget(slots: u32) -> u32 {
    slots.min(MAX_CHANNEL_SLOTS) / 2
}

/// `lightning:` and the 32 hex characters of the chain's `bip122` id: a Lightning network is not
/// the chain, and XBT shares its genesis block with the SHA-256 chain.
pub fn network_id(bip122: &str) -> Option<String> {
    let id = bip122.strip_prefix("bip122:")?;
    (id.len() == 32 && id.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))).then(|| format!("lightning:{id}"))
}

/// The message `payload.auth` MACs. A field that is absent is empty.
pub fn auth_message(session: &str, seq: u64, secret: &str, ticket: &str, req: &str) -> String {
    ["ticket/auth", session, &seq.to_string(), secret, ticket, req].join("|")
}

/// `payload.auth`, hex: binds one request to the session, a fresh `seq`, the secret it releases and
/// the ticket it pledges.
pub fn request_auth(key: &[u8; 32], session: &str, seq: u64, secret: &str, ticket: &str, req: &str) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(auth_message(session, seq, secret, ticket, req).as_bytes());
    hex::encode(m.finalize().into_bytes())
}

/// The fields a ticket receipt signs, in order.
pub const RECEIPT_FIELDS: [&str; 9] = ["scheme", "session", "seq", "releasedMsat", "spentMsat", "charged", "req", "status", "bodyHash"];

/// What `receiptKey` signs: each of [`RECEIPT_FIELDS`] formatted as Python's `str()` formats it
/// (a JSON number and its decimal string sign alike), length-prefixed, under [`RECEIPT_TAG`].
pub fn receipt_message(r: &Value) -> [u8; 32] {
    let mut h = tagged(RECEIPT_TAG);
    for k in RECEIPT_FIELDS {
        put_field(&mut h, py_str(r.get(k)).as_bytes());
    }
    h.finalize().into()
}

/// The hash a secret names: the ticket's payment hash.
pub fn ticket_hash(secret: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(secret).into()
}

/// 32 bytes from 64 lower-case hex characters, and nothing else (an upper-case spelling would be a
/// second name for one ticket).
pub fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

/// What a seller's terms say about tickets: the `extra` of its `accepts` entry.
#[derive(Debug, Clone, PartialEq)]
pub struct Terms {
    /// `lightning:<32 hex>`.
    pub network: String,
    /// The seller's Lightning node id, 33 bytes hex: the payee of every ticket invoice.
    pub pay_to: String,
    pub ticket_msat: u64,
    pub max_tickets: u32,
    pub ticket_blocks: u32,
    /// The key that signs receipts, 33 bytes hex.
    pub receipt_key: String,
    /// Path of the session endpoints.
    pub session: String,
}

impl Terms {
    /// The `accepts` entry for a request priced at `amount_msat`, released `release`
    /// (`with-request` or `after-verify`), settled `settle` ([`SETTLE_ON_USE`] or
    /// [`SETTLE_ON_ARRIVAL`]), with the route's price rule as the seller states it. A seller that
    /// offers both ways lists two entries, the held one first.
    pub fn accepts(&self, amount_msat: u64, release: &str, settle: &str, price: &Value) -> Value {
        let mut extra = Map::new();
        extra.insert("version".into(), VERSION.into());
        extra.insert("features".into(), Value::Array(vec![FEATURE_BLAKE2B.into()]));
        extra.insert("ticketMsat".into(), self.ticket_msat.to_string().into());
        extra.insert("maxTickets".into(), self.max_tickets.into());
        extra.insert("ticketBlocks".into(), self.ticket_blocks.into());
        extra.insert("release".into(), release.into());
        extra.insert("settle".into(), settle.into());
        extra.insert("receiptKey".into(), self.receipt_key.clone().into());
        extra.insert("session".into(), self.session.clone().into());
        extra.insert("price".into(), price.clone());
        let mut m = Map::new();
        m.insert("scheme".into(), SCHEME.into());
        m.insert("network".into(), self.network.clone().into());
        m.insert("asset".into(), ASSET.into());
        m.insert("amount".into(), amount_msat.to_string().into());
        m.insert("payTo".into(), self.pay_to.clone().into());
        m.insert("extra".into(), Value::Object(extra));
        Value::Object(m)
    }
}

/// The error codes of the ticket scheme and of the lottery beside it ([`crate::lottery`]): what a
/// gateway answers a payer with.
pub const PROTOCOL_CODES: [&str; 32] = [
    "amount_mismatch", "amount_not_below_win", "bad_auth", "bad_payment", "bad_request", "bad_seq", "bad_target", "balance_short", "chain_spent",
    "draw_out_of_order", "draw_used", "hash_refused", "journal", "no_route", "node_unavailable", "piece_unknown", "pledge_outstanding",
    "session_unknown", "slots_short", "ticket_expiring", "ticket_not_locked", "ticket_unknown", "ticket_used", "too_many_sessions",
    "too_many_tickets", "too_many_voids", "upstream_unavailable", "value_conflict", "value_missing", "value_reused", "win_size", "win_unpaid",
];

/// The seller's error code as one of the scheme's own ([`PROTOCOL_CODES`]), or `""`. The string
/// returned is this crate's, never the seller's bytes: a payer names a seller's code only through
/// this, so a seller picks from the list and writes nothing.
pub fn protocol_code(code: Option<&Value>) -> &'static str {
    let code = code.and_then(Value::as_str).unwrap_or("");
    PROTOCOL_CODES.iter().copied().find(|c| *c == code).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_network_id_is_the_chain_id_under_another_prefix() {
        assert_eq!(network_id(xbt_primitives::network::XBT_MAINNET).as_deref(), Some("lightning:0000000000000050c1e5f69672f45929"));
        for bad in ["", "bip122:", "bip122:00", "lightning:0000000000000050c1e5f69672f45929", "bip122:0000000000000050C1E5F69672F45929", "bip122:0000000000000050c1e5f69672f459299"] {
            assert_eq!(network_id(bad), None, "{bad}");
        }
    }

    #[test]
    fn auth_binds_every_field_and_an_absent_one_is_empty() {
        let key = [7u8; 32];
        assert_eq!(auth_message("s", 3, "", "", "d"), "ticket/auth|s|3|||d");
        let base = request_auth(&key, "s", 3, "aa", "bb", "d");
        assert_eq!(base.len(), 64);
        for other in [
            request_auth(&[8u8; 32], "s", 3, "aa", "bb", "d"),
            request_auth(&key, "t", 3, "aa", "bb", "d"),
            request_auth(&key, "s", 4, "aa", "bb", "d"),
            request_auth(&key, "s", 3, "ab", "bb", "d"),
            request_auth(&key, "s", 3, "aa", "bc", "d"),
            request_auth(&key, "s", 3, "aa", "bb", "e"),
            // a secret is not a ticket: the two fields do not run together
            request_auth(&key, "s", 3, "", "aabb", "d"),
        ] {
            assert_ne!(base, other);
        }
    }

    #[test]
    fn a_receipt_signs_its_nine_fields_and_a_number_as_its_decimal_string() {
        let r = json!({"scheme": "ticket", "session": "ab", "seq": 2, "releasedMsat": "1000000", "spentMsat": "2500", "charged": "2500",
                       "req": "00", "status": 200, "bodyHash": "ff", "sig": "ignored"});
        let m = receipt_message(&r);
        let mut same = r.clone();
        same["seq"] = "2".into();
        same["status"] = "200".into();
        same["sig"] = "other".into();
        assert_eq!(m, receipt_message(&same));
        for k in RECEIPT_FIELDS {
            let mut other = r.clone();
            other[k] = "x".into();
            assert_ne!(m, receipt_message(&other), "{k}");
        }
        // the tag is part of the message: the same fields under another tag are another message
        let mut h = crate::wire::tagged("xbt402/receipt/v2");
        for k in RECEIPT_FIELDS {
            crate::wire::put_field(&mut h, py_str(r.get(k)).as_bytes());
        }
        let other: [u8; 32] = sha2::Digest::finalize(h).into();
        assert_ne!(m, other);
    }

    #[test]
    fn a_hash_is_64_lower_case_hex_characters() {
        let h = hex::encode(ticket_hash(&[1u8; 32]));
        assert_eq!(hex32(&h), Some(ticket_hash(&[1u8; 32])));
        for bad in [h.to_uppercase(), h[..62].to_string(), format!("{h}00"), format!("0x{}", &h[2..]), format!("{} ", &h[1..]), "g".repeat(64)] {
            assert_eq!(hex32(&bad), None, "{bad}");
        }
    }

    #[test]
    fn the_accepts_entry_is_the_one_the_draft_shows() {
        let t = Terms { network: "lightning:0000000000000050c1e5f69672f45929".into(), pay_to: "02".repeat(33), ticket_msat: 1_000_000, max_tickets: 2, ticket_blocks: 40,
                        receipt_key: "03".repeat(33), session: SESSION_PATH.into() };
        let a = t.accepts(2500, "with-request", SETTLE_ON_USE, &json!({"requestMsat": "2500"}));
        assert_eq!(a["scheme"], "ticket");
        assert_eq!(a["amount"], "2500");
        assert_eq!(a["extra"]["ticketMsat"], "1000000");
        assert_eq!(a["extra"]["features"], json!([512]));
        assert_eq!(a["extra"]["settle"], "on-use");
        assert_eq!(a["extra"]["session"], "/x402/ticket");
        assert_eq!(a["extra"]["maxTickets"], 2);
        let b = t.accepts(2500, "with-request", SETTLE_ON_ARRIVAL, &json!({"requestMsat": "2500"}));
        assert_eq!(b["extra"]["settle"], "on-arrival");
    }

    #[test]
    fn held_tickets_take_half_of_a_channels_slots() {
        assert_eq!((held_budget(DEFAULT_CHANNEL_SLOTS), held_budget(MAX_CHANNEL_SLOTS), held_budget(1), held_budget(0)), (15, 241, 0, 0));
        assert_eq!(held_budget(u32::MAX), 241, "no channel has more than the protocol's ceiling");
        assert_eq!(MIN_HELD_TICKET_MSAT, 546_000);
    }
}
