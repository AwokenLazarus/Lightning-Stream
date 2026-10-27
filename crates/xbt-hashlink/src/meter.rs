//! The work meter, slices, and the hashtaker's signed work receipts.
//!
//! Work is counted only for shares the hashtaker's gateway accepts, weighted by difficulty: a share
//! at difficulty `d` is `d × 2^32` hashes. A share's difficulty is the one in force when its job
//! was sent (the last `mining.set_difficulty` before that job's `mining.notify` on the same
//! channel), so the hashmaker and the hashtaker, reading the same lines in the same order, count the
//! same work at every step.

use secp256k1::ecdsa::Signature;
use secp256k1::{Message, PublicKey, SecretKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};

use crate::sv1;

/// Jobs remembered per channel (older jobs' shares are counted as unknown).
const JOBS_KEPT: usize = 64;
/// Submits awaiting a verdict, per channel.
const PENDING_KEPT: usize = 1024;

/// The work of one share at difficulty `d`.
pub fn share_work(d: f64) -> u128 {
    if d.is_finite() && d > 0.0 {
        (d * 4_294_967_296.0).round() as u128
    } else {
        0
    }
}

#[derive(Default)]
struct Chan {
    diff: f64,
    jobs: VecDeque<(String, f64)>,
    pending: HashMap<String, u128>,
}

/// What a line did to the count.
#[derive(Debug, PartialEq)]
pub enum Event {
    Accepted(u128),
    Rejected,
}

#[derive(Default)]
pub struct Meter {
    chans: HashMap<u32, Chan>,
    pub work: u128,
    pub accepted: u64,
    pub rejected: u64,
    /// Submits for a job the meter never saw (counted as no work).
    pub unknown_job: u64,
}

impl Meter {
    /// A line towards the gateway (from the miner).
    pub fn up(&mut self, chan: u32, v: &Value) {
        let Some(job) = sv1::submit_job(v) else { return };
        let Some(id) = sv1::id_key(v) else { return };
        let c = self.chans.entry(chan).or_default();
        match c.jobs.iter().rev().find(|(j, _)| *j == job) {
            Some((_, d)) => {
                if c.pending.len() >= PENDING_KEPT {
                    c.pending.clear();
                }
                c.pending.insert(id, share_work(*d));
            }
            None => self.unknown_job += 1,
        }
    }

    /// A line towards the miner (from the gateway).
    pub fn down(&mut self, chan: u32, v: &Value) -> Option<Event> {
        let c = self.chans.entry(chan).or_default();
        if let Some(d) = sv1::set_difficulty(v) {
            c.diff = d;
            return None;
        }
        if let Some(job) = sv1::notify_job(v) {
            if c.jobs.len() == JOBS_KEPT {
                c.jobs.pop_front();
            }
            c.jobs.push_back((job, c.diff));
            return None;
        }
        if !sv1::is_response(v) {
            return None;
        }
        let w = c.pending.remove(&sv1::id_key(v)?)?;
        if sv1::accepted(v) {
            self.work += w;
            self.accepted += 1;
            Some(Event::Accepted(w))
        } else {
            self.rejected += 1;
            Some(Event::Rejected)
        }
    }

    pub fn close(&mut self, chan: u32) {
        self.chans.remove(&chan);
    }

    pub fn to_json(&self) -> Value {
        json!({"work": self.work.to_string(), "accepted": self.accepted, "rejected": self.rejected, "unknownJob": self.unknown_job})
    }
}

/// The hashtaker's receipt for a finished slice: the cumulative work the hashtaker's gateway accepted.
#[derive(Clone, Debug, PartialEq)]
pub struct Receipt {
    pub rental: String,
    pub slice: u64,
    pub work: u128,
    pub accepted: u64,
    pub rejected: u64,
    pub at_ms: u64,
}

const RECEIPT_TAG: &str = "xbt-hashlink/receipt/0";

impl Receipt {
    fn line(&self) -> String {
        format!("{RECEIPT_TAG}|{}|{}|{}|{}|{}|{}", self.rental, self.slice, self.work, self.accepted, self.rejected, self.at_ms)
    }

    fn digest(&self) -> Message {
        Message::from_digest(Sha256::digest(self.line().as_bytes()).into())
    }

    pub fn sign(&self, key: &SecretKey) -> Value {
        let sig = secp256k1::SECP256K1.sign_ecdsa(&self.digest(), key);
        json!({
            "rental": self.rental, "slice": self.slice, "work": self.work.to_string(),
            "accepted": self.accepted, "rejected": self.rejected, "atMs": self.at_ms,
            "sig": hex::encode(sig.serialize_compact()),
        })
    }

    /// Parse a signed receipt and check its signature by `signer`.
    pub fn verify(v: &Value, signer: &PublicKey) -> Option<Receipt> {
        let r = Receipt {
            rental: v.get("rental")?.as_str()?.to_string(),
            slice: v.get("slice")?.as_u64()?,
            work: v.get("work")?.as_str()?.parse().ok()?,
            accepted: v.get("accepted")?.as_u64()?,
            rejected: v.get("rejected")?.as_u64()?,
            at_ms: v.get("atMs")?.as_u64()?,
        };
        let sig = Signature::from_compact(&hex::decode(v.get("sig")?.as_str()?).ok()?).ok()?;
        secp256k1::SECP256K1.verify_ecdsa(&r.digest(), &sig, signer).ok()?;
        Some(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Value {
        sv1::parse(s).unwrap()
    }

    #[test]
    fn counts_by_the_jobs_difficulty() {
        let mut m = Meter::default();
        m.down(1, &p(r#"{"id":null,"method":"mining.set_difficulty","params":[2]}"#));
        m.down(1, &p(r#"{"id":null,"method":"mining.notify","params":["a"]}"#));
        m.down(1, &p(r#"{"id":null,"method":"mining.set_difficulty","params":[8]}"#));
        // a share for job a, sent at difficulty 2, counts 2 even after the change
        m.up(1, &p(r#"{"id":5,"method":"mining.submit","params":["u","a","","",""]}"#));
        m.down(1, &p(r#"{"id":null,"method":"mining.notify","params":["b"]}"#));
        m.up(1, &p(r#"{"id":6,"method":"mining.submit","params":["u","b","","",""]}"#));
        m.up(1, &p(r#"{"id":7,"method":"mining.submit","params":["u","b","","",""]}"#));
        m.up(1, &p(r#"{"id":8,"method":"mining.submit","params":["u","zz","","",""]}"#));
        assert_eq!(m.down(1, &p(r#"{"id":6,"result":true,"error":null}"#)), Some(Event::Accepted(share_work(8.0))));
        assert_eq!(m.down(1, &p(r#"{"id":5,"result":true,"error":null}"#)), Some(Event::Accepted(share_work(2.0))));
        assert_eq!(m.down(1, &p(r#"{"id":7,"result":false,"error":[23,"low",null]}"#)), Some(Event::Rejected));
        // an answer nobody asked for, or a repeat, counts nothing
        assert_eq!(m.down(1, &p(r#"{"id":6,"result":true,"error":null}"#)), None);
        assert_eq!(m.work, share_work(10.0));
        assert_eq!((m.accepted, m.rejected, m.unknown_job), (2, 1, 1));
    }

    #[test]
    fn receipts_sign_and_verify() {
        let k = SecretKey::from_slice(&[7; 32]).unwrap();
        let pk = PublicKey::from_secret_key(secp256k1::SECP256K1, &k);
        let r = Receipt { rental: "r1".into(), slice: 3, work: 1 << 70, accepted: 9, rejected: 1, at_ms: 5 };
        let v = r.sign(&k);
        assert_eq!(Receipt::verify(&v, &pk), Some(r));
        let mut bad = v.clone();
        bad["work"] = json!("1");
        assert_eq!(Receipt::verify(&bad, &pk), None);
        let other = PublicKey::from_secret_key(secp256k1::SECP256K1, &SecretKey::from_slice(&[8; 32]).unwrap());
        assert_eq!(Receipt::verify(&v, &other), None);
    }
}
