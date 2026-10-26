//! The link's messages: one JSON object per Noise message, typed by `"t"`.
//!
//! | `t` | From | Meaning |
//! |---|---|---|
//! | `hello` | buyer | version, rental id, listing id, terms, how many miners (0: as many as are free) |
//! | `welcome` | hasher | the terms are accepted; their hash |
//! | `open` | hasher | a miner connected: channel id and its worker name |
//! | `up` | hasher | a Stratum V1 line from that miner (subscribe, authorize, submit: the shares) |
//! | `down` | buyer | a Stratum V1 line from the buyer's gateway (notify, set_difficulty: the jobs; the results of submits: the gateway's verdicts) |
//! | `shut` | either | a channel ended |
//! | `lock` | buyer | the ticket for a slice is locked: its payment hash |
//! | `pay` | buyer | a slice is done: the ticket's preimage and the signed work receipt |
//! | `rate` | hasher | hashrate report |
//! | `ping` / `pong` | either | keepalive |
//! | `close` | either | the rental ends, with a reason; the buyer's also says how many slices it counted |
//!
//! Work is a decimal string (it can pass 2^53).

use serde_json::{json, Value};

/// The terms of a rental, as the listing states them and the buyer repeats them in `hello`.
#[derive(Clone, Debug, PartialEq)]
pub struct Terms {
    /// Work per slice, in hashes (share difficulty × 2^32 summed over accepted shares).
    pub slice_work: u128,
    /// The price of one slice.
    pub price_msat: u64,
    /// How long the hasher waits for a slice's payment once the slice is done.
    pub grace_ms: u64,
}

impl Terms {
    pub fn to_json(&self) -> Value {
        json!({"sliceWork": self.slice_work.to_string(), "priceMsat": self.price_msat, "graceMs": self.grace_ms})
    }

    pub fn from_json(v: &Value) -> Option<Terms> {
        Some(Terms {
            slice_work: v.get("sliceWork")?.as_str()?.parse().ok().filter(|w| *w > 0)?,
            price_msat: v.get("priceMsat")?.as_u64()?,
            grace_ms: v.get("graceMs")?.as_u64()?,
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
    Hello { rental: String, listing: String, terms: Terms, miners: u32 },
    Welcome { rental: String, terms_hash: String },
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

impl Msg {
    pub fn to_bytes(&self) -> Vec<u8> {
        let v = match self {
            Msg::Hello { rental, listing, terms, miners } => {
                json!({"t": "hello", "v": VERSION, "rental": rental, "listing": listing, "terms": terms.to_json(), "miners": miners})
            }
            Msg::Welcome { rental, terms_hash } => json!({"t": "welcome", "rental": rental, "termsHash": terms_hash}),
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
            },
            "welcome" => Msg::Welcome { rental: s("rental")?, terms_hash: s("termsHash")? },
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
        let t = Terms { slice_work: 1 << 60, price_msat: 2000, grace_ms: 3000 };
        for m in [
            Msg::Hello { rental: "r".into(), listing: "l".into(), terms: t.clone(), miners: 3 },
            Msg::Up { chan: 3, line: "{\"id\":1}".into() },
            Msg::Pay { slice: 2, preimage: "00".into(), receipt: json!({"a": 1}) },
            Msg::Rate { hs: 1.5e12, miners: 2 },
            Msg::Close { reason: "unpaid".into(), slices: None },
            Msg::Close { reason: "no accepted work".into(), slices: Some(7) },
        ] {
            assert_eq!(Msg::from_bytes(&m.to_bytes()), Some(m));
        }
        assert_eq!(Msg::from_bytes(br#"{"t":"hello","v":"hashlink/9","rental":"r","listing":"l","terms":{}}"#), None);
        assert_eq!(Msg::from_bytes(br#"{"t":"nope"}"#), None);
    }
}
