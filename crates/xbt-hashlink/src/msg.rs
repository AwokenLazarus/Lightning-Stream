//! The link's messages: one JSON object per Noise message, typed by `"t"`.
//!
//! | `t` | From | Meaning |
//! |---|---|---|
//! | `hello` | hashtaker | version, proof, rental id, listing id, terms, how many miners (0: as many as are free) |
//! | `resume` | hashtaker | on a new link after the old one dropped: carry on with this rental |
//! | `welcome` | hashmaker | the terms are accepted; their hash; the proof, repeated |
//! | `resend` | hashmaker | after a `resume`: a recent share the hashtaker may never have read, for its count alone |
//! | `due` | hashmaker | a share is waiting for payment: what this side has proven, and has been paid |
//! | `paying` | hashtaker | a payment is on its way: wait for it up to 30 s, with the miners on the hashmaker's own pool |
//! | `open` | hashmaker | a miner connected: channel id and its worker name |
//! | `up` | hashmaker | a Stratum V1 line from that miner (subscribe, authorize, submit: only shares its hash proves) |
//! | `down` | hashtaker | a Stratum V1 line from the hashtaker's gateway (notify, set_difficulty: the jobs; the results of submits: the gateway's verdicts) |
//! | `shut` | either | a channel ended |
//! | `lock` | hashtaker | the ticket for a slice is locked: its payment hash |
//! | `pay` | hashtaker | a slice is paid for, ahead of its work: the ticket's preimage and the signed work receipt |
//! | `rate` | hashmaker | hashrate report |
//! | `ping` / `pong` | either | keepalive |
//! | `close` | either | the rental ends, with a reason; the hashtaker's also says how many slices it counted |
//!
//! Work is a decimal string (it can pass 2^53).

use serde_json::{json, Value};

/// The terms of a rental, as the listing states them and the hashtaker repeats them in `hello`.
#[derive(Clone, Debug, PartialEq)]
pub struct Terms {
    /// Work per slice, in hashes (share difficulty × 2^32 summed over accepted shares).
    pub slice_work: u128,
    /// The price of one slice.
    pub price_msat: u64,
    /// How long the hashmaker waits for a first payment, and for a hashtaker to come back.
    pub grace_ms: u64,
    /// The start fee, in slices: paid first, with no work for them. It pays for moving the miners.
    pub start_slices: u64,
}

impl Terms {
    pub fn to_json(&self) -> Value {
        json!({"sliceWork": self.slice_work.to_string(), "priceMsat": self.price_msat, "graceMs": self.grace_ms, "startSlices": self.start_slices})
    }

    pub fn from_json(v: &Value) -> Option<Terms> {
        Some(Terms {
            slice_work: v.get("sliceWork")?.as_str()?.parse().ok().filter(|w| *w > 0)?,
            price_msat: v.get("priceMsat")?.as_u64()?,
            grace_ms: v.get("graceMs")?.as_u64()?,
            start_slices: v.get("startSlices").and_then(Value::as_u64).unwrap_or(0),
        })
    }

    /// SHA-256 of the canonical JSON (both sides compute it the same way).
    pub fn hash(&self) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(self.to_json().to_string().as_bytes()).into()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Msg {
    /// `proof`: how shares are proven. A peer that doesn't say counts on verdicts, and is refused.
    Hello { rental: String, listing: String, terms: Terms, miners: u32, proof: Option<String> },
    /// The hashtaker, on a new link after the old one dropped: carry on with this rental.
    Resume { rental: String },
    Welcome { rental: String, terms_hash: String, proof: Option<String> },
    /// A share forwarded just before a drop, sent again. It's checked and counted like any other, once;
    /// it isn't sent to the gateway, whose session ended with the old link.
    Resend { chan: u32, line: String },
    /// A proven share doesn't fit in what's paid, and waits on a short clock.
    Due { work: u128, paid: u64 },
    /// A payment is on its way, after a `due`.
    Paying,
    /// After a resume. From the hashmaker, once the shares it sent again are all sent: its count when it sent them.
    /// From the hashtaker, once those are all settled: its count at the drop and the ones it counted from them. The
    /// hashmaker's count comes down to the hashtaker's, by no more than what could have been on its way.
    Resynced { work: u128, proven: u64 },
    Open { chan: u32, worker: String },
    Up { chan: u32, line: String },
    Down { chan: u32, line: String },
    Shut { chan: u32 },
    Lock { slice: u64, hash: String },
    Pay { slice: u64, preimage: String, receipt: Value },
    Rate { hs: f64, miners: u32 },
    Ping { n: u64 },
    Pong { n: u64 },
    Close { reason: String, slices: Option<u64> },
}

pub const VERSION: &str = "hashlink/0";
/// How shares are proven: BLAKE2b over the 80 bytes an ASIC hashes (see [`crate::proof`]).
pub const PROOF: &str = "blake2b-80/1";

impl Msg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let v = match self {
            Msg::Hello { rental, listing, terms, miners, proof } => {
                json!({"t": "hello", "v": VERSION, "proof": proof, "rental": rental, "listing": listing, "terms": terms.to_json(), "miners": miners})
            }
            Msg::Resume { rental } => json!({"t": "resume", "v": VERSION, "rental": rental}),
            Msg::Welcome { rental, terms_hash, proof } => json!({"t": "welcome", "rental": rental, "termsHash": terms_hash, "proof": proof}),
            Msg::Resend { chan, line } => json!({"t": "resend", "chan": chan, "line": line}),
            Msg::Due { work, paid } => json!({"t": "due", "work": work.to_string(), "paid": paid}),
            Msg::Paying => json!({"t": "paying"}),
            Msg::Resynced { work, proven } => json!({"t": "resynced", "work": work.to_string(), "proven": proven}),
            Msg::Open { chan, worker } => json!({"t": "open", "chan": chan, "worker": worker}),
            Msg::Up { chan, line } => json!({"t": "up", "chan": chan, "line": line}),
            Msg::Down { chan, line } => json!({"t": "down", "chan": chan, "line": line}),
            Msg::Shut { chan } => json!({"t": "shut", "chan": chan}),
            Msg::Lock { slice, hash } => json!({"t": "lock", "slice": slice, "hash": hash}),
            Msg::Pay { slice, preimage, receipt } => {
                json!({"t": "pay", "slice": slice, "preimage": preimage, "receipt": receipt})
            }
            Msg::Rate { hs, miners } => json!({"t": "rate", "hs": hs, "miners": miners}),
            Msg::Ping { n } => json!({"t": "ping", "n": n}),
            Msg::Pong { n } => json!({"t": "pong", "n": n}),
            Msg::Close { reason, slices: None } => json!({"t": "close", "reason": reason}),
            Msg::Close { reason, slices: Some(n) } => json!({"t": "close", "reason": reason, "slices": n}),
        };
        v.to_string().into_bytes()
    }

    pub fn from_bytes(b: &[u8]) -> Option<Msg> {
        let v: Value = serde_json::from_slice(b).ok()?;
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        let u = |k: &str| v.get(k).and_then(Value::as_u64);
        let chan = || u("chan").and_then(|c| u32::try_from(c).ok());
        Some(match v.get("t")?.as_str()? {
            "hello" if s("v")? == VERSION => Msg::Hello {
                rental: s("rental")?,
                listing: s("listing")?,
                terms: Terms::from_json(v.get("terms")?)?,
                miners: u("miners").and_then(|m| u32::try_from(m).ok()).unwrap_or(0),
                proof: s("proof"),
            },
            "resume" if s("v")? == VERSION => Msg::Resume { rental: s("rental")? },
            "welcome" => Msg::Welcome { rental: s("rental")?, terms_hash: s("termsHash")?, proof: s("proof") },
            "resend" => Msg::Resend { chan: chan()?, line: s("line")? },
            "due" => Msg::Due { work: s("work")?.parse().ok()?, paid: u("paid")? },
            "paying" => Msg::Paying,
            "resynced" => Msg::Resynced { work: s("work")?.parse().ok()?, proven: u("proven")? },
            "open" => Msg::Open { chan: chan()?, worker: s("worker")? },
            "up" => Msg::Up { chan: chan()?, line: s("line")? },
            "down" => Msg::Down { chan: chan()?, line: s("line")? },
            "shut" => Msg::Shut { chan: chan()? },
            "lock" => Msg::Lock { slice: u("slice")?, hash: s("hash")? },
            "pay" => Msg::Pay { slice: u("slice")?, preimage: s("preimage")?, receipt: v.get("receipt")?.clone() },
            "rate" => Msg::Rate { hs: v.get("hs")?.as_f64()?, miners: u32::try_from(u("miners")?).ok()? },
            "ping" => Msg::Ping { n: u("n")? },
            "pong" => Msg::Pong { n: u("n")? },
            "close" => Msg::Close { reason: s("reason")?, slices: u("slices") },
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let t = Terms { slice_work: 1 << 60, price_msat: 2000, grace_ms: 3000, start_slices: 2 };
        for m in [
            Msg::Hello { rental: "r".into(), listing: "l".into(), terms: t.clone(), miners: 3, proof: Some(PROOF.into()) },
            Msg::Resume { rental: "r".into() },
            Msg::Welcome { rental: "r".into(), terms_hash: "00".into(), proof: Some(PROOF.into()) },
            Msg::Resend { chan: 3, line: "{\"id\":1}".into() },
            Msg::Due { work: 1 << 70, paid: 4 },
            Msg::Paying,
            Msg::Resynced { work: 1 << 70, proven: 9 },
            Msg::Up { chan: 3, line: "{\"id\":1}".into() },
            Msg::Pay { slice: 2, preimage: "00".into(), receipt: json!({"a": 1}) },
            Msg::Rate { hs: 1.5e12, miners: 2 },
            Msg::Close { reason: "unpaid".into(), slices: None },
            Msg::Close { reason: "no proven work".into(), slices: Some(7) },
        ] {
            assert_eq!(Msg::from_bytes(&m.to_bytes()), Some(m));
        }
        assert_eq!(Msg::from_bytes(br#"{"t":"hello","v":"hashlink/9","rental":"r","listing":"l","terms":{}}"#), None);
        assert_eq!(Msg::from_bytes(br#"{"t":"nope"}"#), None);
        // an earlier version's hello and welcome say no proof: they parse, and are refused by what they lack
        let old = br#"{"t":"hello","v":"hashlink/0","rental":"r","listing":"l","terms":{"sliceWork":"1","priceMsat":1,"graceMs":1}}"#;
        assert!(matches!(Msg::from_bytes(old), Some(Msg::Hello { proof: None, .. })));
        assert!(matches!(Msg::from_bytes(br#"{"t":"welcome","rental":"r","termsHash":"00"}"#), Some(Msg::Welcome { proof: None, .. })));
    }
}
