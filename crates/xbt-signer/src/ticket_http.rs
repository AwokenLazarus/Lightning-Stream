//! Stream tickets, the buyer's reading of a seller's HTTP messages (`docs/TICKETS.md` sections 1,
//! 3 and 4): the entry of a 402, a price, a receipt, and the wallet's own account of a session.
//! No IO: [`crate::ticket_pay`] is the part that sends and receives.
//!
//! The rules kept here, one sentence each:
//!
//! * **A price is the terms' rule applied to what the wallet itself counted** ([`Price`]): bytes it
//!   received and seconds it measured, never a number in an answer.
//! * **A receipt is believed only for the request it was asked for** ([`Receipt::read`]): signed by
//!   the key of the terms the wallet fetched, for this session, this `seq`, this request digest
//!   and this status.
//! * **A seller's totals can only confirm the wallet's own** ([`Account::absorb`]): what the seller
//!   says was released never exceeds what the wallet released and never falls; what it says was
//!   spent never exceeds what was released, and rises by no more than the price of what the wallet
//!   asked for. Anything else is a fault, and a session with a fault releases nothing more. (A
//!   `spentMsat` that falls is taken: a seller gives back what it charged ahead and did not send,
//!   and a fall is in the buyer's favour.)
//! * **Which rail pays is one function** ([`offers`]): a ticket entry, then a single Lightning
//!   payment, then the frozen channel entry.
//!
//! Every number from outside is parsed as a `u64` of decimal digits and combined with checked
//! arithmetic; a price that does not fit is no price.
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::pyjson::str_or_empty;
use crate::ticket::{outside_u64, Refusal, Terms};

fn refuse<T>(rule: &'static str, msg: impl Into<String>) -> Result<T, Refusal> {
    Err((rule, msg.into()))
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

// --- the price ---------------------------------------------------------------------------------------

/// The price rule of one route, as the seller's terms state it (`extra.price`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Price {
    /// Once per request that is answered with a status below 400.
    pub request_msat: u64,
    /// For every `per_bytes` bytes of the answer's body, rounded up over the whole body.
    pub byte_msat: u64,
    /// At least 1.
    pub per_bytes: u64,
    /// For every started second the answer is open.
    pub second_msat: u64,
}

impl Price {
    /// From an `accepts` entry: `extra.price`, or `amount` alone when the entry has no rule. The
    /// entry's `amount` and the rule's `requestMsat` must agree: they are one number said twice.
    pub fn parse(acc: &Value) -> Result<Self, Refusal> {
        let amount = outside_u64(acc.get("amount")).ok_or(("ticket_terms", "amount is not a whole number of msat".to_string()))?;
        let Some(p) = acc.get("extra").and_then(|x| x.get("price")).filter(|p| !p.is_null()) else {
            return Ok(Self { request_msat: amount, byte_msat: 0, per_bytes: 1, second_msat: 0 });
        };
        if !p.is_object() {
            return refuse("ticket_terms", "price is not an object");
        }
        let num = |k: &str, dflt: u64| match p.get(k).filter(|v| !v.is_null()) {
            None => Ok(dflt),
            Some(v) => outside_u64(Some(v)).ok_or(("ticket_terms", format!("price.{k} is not a whole number"))),
        };
        let price = Self { request_msat: num("requestMsat", 0)?, byte_msat: num("byteMsat", 0)?, per_bytes: num("perBytes", 1)?, second_msat: num("secondMsat", 0)? };
        if price.per_bytes == 0 {
            return refuse("ticket_terms", "price.perBytes is 0");
        }
        if price.request_msat != amount {
            return refuse("ticket_terms", format!("amount {amount} and price.requestMsat {} differ", price.request_msat));
        }
        Ok(price)
    }

    /// Whether the body is paid for as it arrives.
    pub fn metered(&self) -> bool {
        self.byte_msat > 0 || self.second_msat > 0
    }

    /// The price of the first `bytes` bytes of a body: `ceil(bytes * byte_msat / per_bytes)`.
    pub fn for_bytes(&self, bytes: u64) -> Option<u64> {
        let total = u128::from(bytes).checked_mul(u128::from(self.byte_msat))?;
        u64::try_from(total.div_ceil(u128::from(self.per_bytes.max(1)))).ok()
    }

    pub fn for_seconds(&self, seconds: u64) -> Option<u64> {
        seconds.checked_mul(self.second_msat)
    }

    /// The most bytes of a body whose byte price stays within `msat`.
    pub fn bytes_for(&self, msat: u64) -> u64 {
        if self.byte_msat == 0 {
            return u64::MAX;
        }
        u64::try_from(u128::from(msat) * u128::from(self.per_bytes.max(1)) / u128::from(self.byte_msat)).unwrap_or(u64::MAX)
    }

    /// What a request costs once `bytes` of its body have arrived and `seconds` of it have started.
    pub fn cost(&self, bytes: u64, seconds: u64) -> Option<u64> {
        self.request_msat.checked_add(self.for_bytes(bytes)?)?.checked_add(self.for_seconds(seconds)?)
    }

    /// What the seller wants in the balance before it asks the service: the request's price, the
    /// first second, and one msat for the first byte of a body priced by its size.
    pub fn reserve(&self) -> Option<u64> {
        self.request_msat.checked_add(self.second_msat)?.checked_add(u64::from(self.byte_msat > 0))
    }
}

// --- the terms ---------------------------------------------------------------------------------------

/// A ticket entry of a seller's 402, read whole: what the book needs ([`Terms`]) and what the HTTP
/// binding needs.
#[derive(Debug, Clone, PartialEq)]
pub struct PayTerms {
    pub terms: Terms,
    /// The key that signs the seller's receipts, 33 bytes.
    pub receipt_key: Vec<u8>,
    /// Path of the session endpoints on the seller's origin.
    pub session_path: String,
    pub price: Price,
    /// `with-request` (the only release this wallet makes) or `after-verify`.
    pub release: String,
    /// The entry as the seller sent it: what `accepted` in PAYMENT-SIGNATURE repeats.
    pub accepted: Value,
}

impl PayTerms {
    pub fn parse(acc: &Value, lightning: &str) -> Result<Self, Refusal> {
        let terms = Terms::parse(acc, lightning)?;
        let x = acc.get("extra").cloned().unwrap_or(Value::Null);
        let key = str_or_empty(x.get("receiptKey"));
        let receipt_key = hex::decode(&key).ok().filter(|b| is_hex(&key, 66) && xbt_primitives::secp256k1::PublicKey::from_slice(b).is_ok())
            .ok_or(("ticket_terms", "receiptKey is not a compressed public key (66 lower-case hex)".to_string()))?;
        let session_path = match x.get("session").filter(|v| !v.is_null()) {
            None => xbt402::ticket::SESSION_PATH.to_string(),
            Some(v) => v.as_str().map(str::to_string).ok_or(("ticket_terms", "session is not a path".to_string()))?,
        };
        Ok(Self { terms, receipt_key, session_path, price: Price::parse(acc)?, release: str_or_empty(x.get("release")), accepted: acc.clone() })
    }

    /// Whether `other` (the terms of a later 402 from the same origin) is the same seller on the
    /// same session terms: the node that is paid, the key that signs, the ticket, the endpoints.
    /// The price is a route's and may differ from request to request.
    pub fn same_seller(&self, other: &PayTerms) -> bool {
        self.terms == other.terms && self.receipt_key == other.receipt_key && self.session_path == other.session_path
    }
}

/// What a 402 offers, in the order the wallet takes them (`docs/TICKETS.md` section 12).
#[derive(Debug, Clone, PartialEq)]
pub enum Offer {
    /// `scheme: "ticket"` on this Lightning network.
    Ticket(Value),
    /// `scheme: "exact"` on this Lightning network, with a BOLT 11 invoice: one payment, then the
    /// request again with the preimage.
    Lightning(Value),
    /// The on-chain channel entry (`batch-settlement`) on this chain: the frozen rail.
    Channel(Value),
}

impl Offer {
    pub fn rail(&self) -> &'static str {
        match self {
            Offer::Ticket(_) => "ticket",
            Offer::Lightning(_) => "ln",
            Offer::Channel(_) => "xbt402",
        }
    }
}

/// The entries of a `PAYMENT-REQUIRED` this wallet could pay, in its order of choice: a ticket
/// entry, a single Lightning payment, the channel entry. `lightning` and `chain` are this wallet's
/// network ids (`lightning:<32 hex>`, `bip122:...`); an entry on any other network is not listed.
pub fn offers(pr: &Value, lightning: &str, chain: &str) -> Vec<Offer> {
    let entries: Vec<&Value> = pr.get("accepts").and_then(Value::as_array).into_iter().flatten().collect();
    let on = |a: &&&Value, scheme: &str, net: &str| a.get("scheme").and_then(Value::as_str) == Some(scheme) && a.get("network").and_then(Value::as_str) == Some(net);
    let mut out = vec![];
    out.extend(entries.iter().find(|a| on(a, xbt402::ticket::SCHEME, lightning)).map(|a| Offer::Ticket((*a).clone())));
    out.extend(entries.iter().find(|a| on(a, LN_SCHEME, lightning)).map(|a| Offer::Lightning((*a).clone())));
    out.extend(entries.iter().find(|a| xbt402::wire::scheme_accepted(a.get("scheme").and_then(Value::as_str)) && a.get("network").and_then(Value::as_str) == Some(chain))
        .map(|a| Offer::Channel((*a).clone())));
    out
}

/// The scheme name of a single Lightning payment in a 402 (x402's `exact`).
pub const LN_SCHEME: &str = "exact";

// --- a receipt ---------------------------------------------------------------------------------------

/// A seller's signed receipt, after its signature and its session were checked.
#[derive(Debug, Clone, PartialEq)]
pub struct Receipt {
    pub seq: u64,
    pub released_msat: u64,
    pub spent_msat: u64,
    pub charged: u64,
    pub status: u64,
    pub req: String,
    /// Empty on the head of an answer that is sent as it arrives.
    pub body_hash: String,
    pub raw: Value,
}

impl Receipt {
    /// A receipt object: signed by `key` under the ticket receipt tag, for `session`.
    pub fn verify(r: &Value, key: &[u8], session: &str) -> Result<Self, String> {
        if !r.is_object() {
            return Err("no receipt".into());
        }
        let sig = hex::decode(str_or_empty(r.get("sig"))).map_err(|_| "the receipt's signature is not hex".to_string())?;
        if !xbt_primitives::ecdsa::verify(key, &xbt402::ticket::receipt_message(r), &sig) {
            return Err("the receipt is not signed by the receipt key of the seller's terms".into());
        }
        if str_or_empty(r.get("scheme")) != xbt402::ticket::SCHEME || str_or_empty(r.get("session")) != session {
            return Err("the receipt is for another session".into());
        }
        let num = |k: &str| outside_u64(r.get(k)).ok_or(format!("the receipt's {k} is not a whole number"));
        Ok(Self { seq: num("seq")?, released_msat: num("releasedMsat")?, spent_msat: num("spentMsat")?, charged: num("charged")?, status: num("status")?,
                  req: str_or_empty(r.get("req")), body_hash: str_or_empty(r.get("bodyHash")), raw: r.clone() })
    }

    /// The receipt of the answer to one request: `header` is its `PAYMENT-RESPONSE`. It must be
    /// for this `seq`, this request (`digest`) and the status the answer came with; a receipt for
    /// anything else is an answer to another request, replayed or made up.
    pub fn read(header: Option<&str>, key: &[u8], session: &str, seq: u64, digest: &str, status: u16) -> Result<Self, String> {
        let sr = xbt402::wire::unb64json(header.ok_or("the answer has no PAYMENT-RESPONSE")?).map_err(|_| "PAYMENT-RESPONSE is not base64 JSON".to_string())?;
        let r = Self::verify(sr.get("extra").and_then(|e| e.get("receipt")).unwrap_or(&Value::Null), key, session)?;
        r.for_request(seq, digest, status)?;
        Ok(r)
    }

    pub fn for_request(&self, seq: u64, digest: &str, status: u16) -> Result<(), String> {
        if self.seq != seq || self.req != digest {
            return Err("the receipt is for another request".into());
        }
        if self.status != u64::from(status) {
            return Err(format!("the receipt is for status {}, the answer came with {status}", self.status));
        }
        Ok(())
    }
}

/// SHA-256 of a body, hex: what a receipt's `bodyHash` is compared with.
pub fn body_hash(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

// --- the wallet's account of a session ---------------------------------------------------------------

/// How much a receipt may say was spent since the last one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Due {
    /// At most this much: the price, by the terms, of what the wallet asked for and received.
    AtMost(u64),
    /// Anything the balance covers: an answer priced as it goes is open, or was cut short by the
    /// wallet, and what the seller had already sent cannot be counted from here.
    Balance,
}

/// One session's money as the wallet counts it. `sent` is its own; `acked` and `spent` are the
/// seller's signed totals, taken only where [`Account::absorb`] found them inside the wallet's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Account {
    /// The tickets whose secret has left the wallet for this seller, in msat.
    pub sent_msat: u64,
    /// The seller's signed `releasedMsat`.
    pub acked_msat: u64,
    /// The seller's signed `spentMsat`.
    pub spent_msat: u64,
}

impl Account {
    /// What the seller still holds for this session by its own signed word.
    pub fn balance(&self) -> u64 {
        self.acked_msat.saturating_sub(self.spent_msat)
    }

    /// A secret of `ticket_msat` has left the wallet.
    pub fn released(&mut self, ticket_msat: u64) {
        self.sent_msat = self.sent_msat.saturating_add(ticket_msat);
    }

    /// Take a receipt's totals. `charged_max`: the most the receipt may say this request was
    /// charged. `due`: the most `spentMsat` may have risen. `outstanding`: a secret has left whose
    /// taking the seller has not yet confirmed (then `releasedMsat` may be one ticket short).
    /// `Err`: the seller's word contradicts the wallet's own count; nothing is taken from it.
    pub fn absorb(&mut self, r: &Receipt, charged_max: u64, due: Due, outstanding: bool) -> Result<(), String> {
        if r.released_msat > self.sent_msat {
            return Err(format!("the seller says {} msat were released, the wallet released {}", r.released_msat, self.sent_msat));
        }
        if r.released_msat < self.acked_msat {
            return Err(format!("the seller's releasedMsat fell from {} to {}", self.acked_msat, r.released_msat));
        }
        if !outstanding && r.released_msat != self.sent_msat {
            return Err(format!("the wallet released {} msat and the seller credits {}", self.sent_msat, r.released_msat));
        }
        if r.spent_msat > r.released_msat {
            return Err(format!("the seller says {} msat were spent of {} released", r.spent_msat, r.released_msat));
        }
        if r.charged > charged_max {
            return Err(format!("the seller charged {} msat for a request whose price by its terms is at most {charged_max}", r.charged));
        }
        if let Due::AtMost(most) = due {
            let rose = r.spent_msat.saturating_sub(self.spent_msat);
            if rose > most {
                return Err(format!("the seller's spentMsat rose by {rose} msat, and what was asked for costs at most {most} by its terms"));
            }
        }
        self.acked_msat = r.released_msat;
        self.spent_msat = r.spent_msat;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use xbt_primitives::ecdsa;

    fn key() -> (xbt_primitives::secp256k1::SecretKey, Vec<u8>) {
        let sk = ecdsa::secret_key(&[9u8; 32]).unwrap();
        (sk, ecdsa::pubkey(&sk).to_vec())
    }

    fn node_id() -> String {
        hex::encode(ecdsa::pubkey(&ecdsa::secret_key(&[0x33; 32]).unwrap()))
    }

    const NET: &str = "lightning:00000000000000000000000000000001";

    fn accepts(price: Value) -> Value {
        json!({"scheme": "ticket", "network": NET, "asset": "XBT:msat", "amount": "2500", "payTo": node_id(),
               "extra": {"version": "ticket/0", "features": [512], "ticketMsat": "1000000", "maxTickets": 8, "ticketBlocks": 40,
                         "release": "with-request", "settle": "on-use", "receiptKey": hex::encode(key().1), "session": "/x402/ticket", "price": price}})
    }

    #[test]
    fn a_price_is_read_strictly_and_never_wraps() {
        let p = Price::parse(&accepts(json!({"requestMsat": "2500", "byteMsat": "200000", "perBytes": "1048576", "secondMsat": "0"}))).unwrap();
        assert_eq!(p, Price { request_msat: 2500, byte_msat: 200_000, per_bytes: 1 << 20, second_msat: 0 });
        assert!(p.metered());
        assert_eq!((p.for_bytes(0), p.for_bytes(1), p.for_bytes(1 << 20), p.for_bytes((1 << 20) + 1)), (Some(0), Some(1), Some(200_000), Some(200_001)));
        assert_eq!(p.bytes_for(1_000_000), 5 << 20, "a ticket of 1,000 sat pays for 5 MiB");
        assert_eq!(p.cost(1 << 20, 3), Some(202_500));
        assert_eq!(p.reserve(), Some(2501));
        let dear = Price { request_msat: 0, byte_msat: u64::MAX, per_bytes: 1, second_msat: 0 };
        assert_eq!((dear.for_bytes(1), dear.for_bytes(2), dear.cost(2, 0)), (Some(u64::MAX), None, None), "a price that does not fit is no price");
        let per_s = Price { request_msat: 0, byte_msat: 0, per_bytes: 1, second_msat: u64::MAX };
        assert_eq!((per_s.for_seconds(1), per_s.for_seconds(2), per_s.cost(0, 2), per_s.bytes_for(5)), (Some(u64::MAX), None, None, u64::MAX));
        // no rule: the amount alone
        let mut a = accepts(Value::Null);
        assert_eq!(Price::parse(&a).unwrap(), Price { request_msat: 2500, byte_msat: 0, per_bytes: 1, second_msat: 0 });
        a["amount"] = json!(-1);
        assert!(Price::parse(&a).is_err());
        for bad in [json!({"requestMsat": "2501"}), json!({"requestMsat": "2500", "perBytes": 0}), json!({"requestMsat": "2500", "byteMsat": "1e3"}),
                    json!({"requestMsat": "2500", "secondMsat": -5}), json!([1]), json!("free")] {
            assert_eq!(Price::parse(&accepts(bad.clone())).map_err(|e| e.0), Err("ticket_terms"), "{bad}");
        }
    }

    #[test]
    fn terms_name_the_key_and_the_endpoints_and_a_later_402_is_compared_with_them() {
        let t = PayTerms::parse(&accepts(json!({"requestMsat": "2500"})), NET).unwrap();
        assert_eq!((t.receipt_key.len(), t.session_path.as_str(), t.release.as_str()), (33, "/x402/ticket", "with-request"));
        let with = |path: &[&str], v: Value| {
            let mut a = accepts(json!({"requestMsat": "2500"}));
            let mut at = &mut a;
            for p in &path[..path.len() - 1] {
                at = &mut at[*p];
            }
            at[path[path.len() - 1]] = v;
            PayTerms::parse(&a, NET)
        };
        assert_eq!(with(&["extra", "receiptKey"], json!("02")).map_err(|e| e.0), Err("ticket_terms"));
        assert_eq!(with(&["extra", "receiptKey"], json!(format!("02{}", "ff".repeat(32)))).map_err(|e| e.0), Err("ticket_terms"), "not a point on the curve");
        assert_eq!(with(&["extra", "receiptKey"], json!(hex::encode(key().1).to_uppercase())).map_err(|e| e.0), Err("ticket_terms"));
        assert_eq!(with(&["extra", "session"], json!(7)).map_err(|e| e.0), Err("ticket_terms"));
        assert_eq!(with(&["network"], json!("lightning:00000000000000000000000000000002")).map_err(|e| e.0), Err("ticket_network"));
        // another route's price is the same seller; another node, key, ticket or path is not
        let mut other_price = accepts(json!({"requestMsat": "9"}));
        other_price["amount"] = json!("9");
        assert!(t.same_seller(&PayTerms::parse(&other_price, NET).unwrap()));
        let other_node = hex::encode(ecdsa::pubkey(&ecdsa::secret_key(&[0x34; 32]).unwrap()));
        for (path, v) in [(vec!["payTo"], json!(other_node)), (vec!["extra", "receiptKey"], json!(node_id())), (vec!["extra", "ticketMsat"], json!("2000000")),
                          (vec!["extra", "ticketBlocks"], json!(41)), (vec!["extra", "maxTickets"], json!(9)), (vec!["extra", "session"], json!("/other"))] {
            assert!(!t.same_seller(&with(&path, v).unwrap()), "{path:?}");
        }
    }

    #[test]
    fn the_rails_of_a_402_are_listed_in_the_wallets_order_and_only_on_its_own_networks() {
        let chain = "bip122:00000000000000000000000000000001";
        let ticket = accepts(json!({"requestMsat": "2500"}));
        let channel = json!({"scheme": "batch-settlement", "network": chain, "amount": 3});
        let ln = json!({"scheme": "exact", "network": NET, "amount": "3000", "extra": {"invoice": "lnbcrt1..."}});
        let pr = json!({"accepts": [channel, ln, ticket, {"scheme": "ticket", "network": "lightning:other"}, {"scheme": "exact", "network": "lnbtc:x"}, 7]});
        let got = offers(&pr, NET, chain);
        assert_eq!(got.iter().map(Offer::rail).collect::<Vec<_>>(), ["ticket", "ln", "xbt402"]);
        assert_eq!(offers(&json!({"accepts": [channel]}), NET, chain).iter().map(Offer::rail).collect::<Vec<_>>(), ["xbt402"]);
        assert!(offers(&json!({"accepts": [{"scheme": "ticket", "network": chain}]}), NET, chain).is_empty(), "a ticket entry names a Lightning network");
        assert!(offers(&json!({}), NET, chain).is_empty());
        assert!(offers(&json!({"accepts": "all"}), NET, chain).is_empty());
    }

    fn receipt(seq: u64, released: u64, spent: u64, charged: u64, status: u16, body: &str) -> Value {
        let mut r = json!({"scheme": "ticket", "session": "s1", "seq": seq, "releasedMsat": released.to_string(), "spentMsat": spent.to_string(),
                           "charged": charged.to_string(), "req": "d1", "status": status, "bodyHash": body});
        r["sig"] = hex::encode(ecdsa::sign(&key().0, &xbt402::ticket::receipt_message(&r))).into();
        r
    }

    fn header(r: &Value) -> String {
        xbt402::wire::b64json(&xbt402::wire::settlement_response(r, NET, "", true))
    }

    #[test]
    fn a_receipt_is_believed_only_for_the_request_it_was_asked_for() {
        let pk = key().1;
        let r = receipt(4, 1_000_000, 2500, 2500, 200, "ab");
        let got = Receipt::read(Some(&header(&r)), &pk, "s1", 4, "d1", 200).unwrap();
        assert_eq!((got.released_msat, got.spent_msat, got.charged, got.body_hash.as_str()), (1_000_000, 2500, 2500, "ab"));
        // a replayed answer: the receipt of another request, another seq, another status or another session
        assert!(Receipt::read(Some(&header(&r)), &pk, "s1", 5, "d1", 200).is_err());
        assert!(Receipt::read(Some(&header(&r)), &pk, "s1", 4, "d2", 200).is_err());
        assert!(Receipt::read(Some(&header(&r)), &pk, "s1", 4, "d1", 402).is_err());
        assert!(Receipt::read(Some(&header(&r)), &pk, "s2", 4, "d1", 200).is_err());
        // a forged one: no receipt, one signed by another key, one changed after signing
        assert!(Receipt::read(None, &pk, "s1", 4, "d1", 200).is_err());
        assert!(Receipt::read(Some("not base64"), &pk, "s1", 4, "d1", 200).is_err());
        assert!(Receipt::read(Some(&header(&r)), &hex::decode(node_id()).unwrap(), "s1", 4, "d1", 200).is_err());
        for (k, v) in [("spentMsat", json!("0")), ("releasedMsat", json!("9000000")), ("charged", json!("0")), ("status", json!(201)), ("seq", json!(5))] {
            let mut bent = r.clone();
            bent[k] = v;
            assert!(Receipt::read(Some(&header(&bent)), &pk, "s1", 4, "d1", 200).is_err(), "{k}");
        }
        // a number that is not one, signed all the same
        let mut odd = json!({"scheme": "ticket", "session": "s1", "seq": 4, "releasedMsat": "-1", "spentMsat": "0", "charged": "0", "req": "d1", "status": 200, "bodyHash": ""});
        odd["sig"] = hex::encode(ecdsa::sign(&key().0, &xbt402::ticket::receipt_message(&odd))).into();
        assert!(Receipt::read(Some(&header(&odd)), &pk, "s1", 4, "d1", 200).is_err());
    }

    #[test]
    fn a_sellers_totals_can_only_confirm_the_wallets_own() {
        let pk = key().1;
        let rd = |released, spent, charged| Receipt::verify(&receipt(1, released, spent, charged, 200, ""), &pk, "s1").unwrap();
        let mut a = Account::default();
        a.released(1_000_000);
        // the seller has not taken the secret yet: one ticket short is allowed only while it is outstanding
        assert!(a.absorb(&rd(0, 0, 0), 0, Due::AtMost(0), false).is_err());
        a.absorb(&rd(0, 0, 0), 0, Due::AtMost(0), true).unwrap();
        a.absorb(&rd(1_000_000, 2500, 2500), 2500, Due::AtMost(2500), false).unwrap();
        assert_eq!((a.acked_msat, a.spent_msat, a.balance()), (1_000_000, 2500, 997_500));
        let before = a;
        for (r, charged_max, due, why) in [
            (rd(2_000_000, 2500, 0), 0, Due::AtMost(0), "more released than the wallet released"),
            (rd(0, 0, 0), 0, Due::AtMost(0), "released fell"),
            (rd(1_000_000, 5000, 2500), 2500, Due::AtMost(2499), "spent rose by more than the price"),
            (rd(1_000_000, 5000, 2501), 2500, Due::AtMost(2500), "charged more than the price"),
            (rd(1_000_000, 1_000_001, 0), 0, Due::Balance, "spent more than released"),
        ] {
            assert!(a.absorb(&r, charged_max, due, false).is_err(), "{why}");
            assert_eq!(a, before, "{why}: nothing is taken from a receipt that is refused");
        }
        // what the seller gives back is taken
        a.absorb(&rd(1_000_000, 2000, 0), 0, Due::AtMost(0), false).unwrap();
        assert_eq!(a.balance(), 998_000);
        a.absorb(&rd(1_000_000, 2500, 500), 500, Due::AtMost(500), false).unwrap();
        // an answer priced as it goes, cut short by the wallet: anything up to the balance
        a.absorb(&rd(1_000_000, 1_000_000, 997_500), 997_500, Due::Balance, false).unwrap();
        assert_eq!(a.balance(), 0);
    }
}
