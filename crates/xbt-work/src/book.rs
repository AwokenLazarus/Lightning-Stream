//! The provider's receipt book (spec §9.1 steps 6-8, §10.2): verifies receipts under the pinned
//! Prime key, credits only the increase over the best receipt it holds per invoice, keeps
//! conflicting receipts as an equivocation fraud proof, and remembers the height interval of every
//! credited increase for the coinbase audit. A port of receipts.py `Provider.accept`, rule for rule.
use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;
use indexmap::IndexMap;
use serde_json::Value;
use xbt402::json::obj;

use crate::error::{fail, Result, WorkError};
use crate::receipt::{sig64, Signed, WorkReceipt};

/// Two receipts the Prime key signed that cannot both be true (§9.1 step 7, §10.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Equivocation {
    pub a: Signed,
    pub b: Signed,
    pub why: String,
}

impl Equivocation {
    pub fn to_json(&self) -> Value {
        obj([("why", self.why.clone().into()), ("a", self.a.line_doc()), ("b", self.b.line_doc())])
    }

    /// Anyone holding the Prime key can check it: both lines verify, name one (identity, invoice),
    /// and have one seq with different states or a cumulative state that fell as seq rose.
    pub fn check(&self, pubkey: &VerifyingKey) -> bool {
        let (a, b) = (&self.a.receipt, &self.b.receipt);
        if !self.a.verify(pubkey) || !self.b.verify(pubkey) || (a.prime_id, &a.identity, &a.invoice) != (b.prime_id, &b.identity, &b.invoice) {
            return false;
        }
        (a.seq == b.seq && a != b)
            || (a.seq < b.seq && (b.cum_work < a.cum_work || b.shares < a.shares || b.last_height < a.last_height))
            || (b.seq < a.seq && (a.cum_work < b.cum_work || a.shares < b.shares || a.last_height < b.last_height))
    }
}

/// A credited increase: `work` units whose shares all lie in heights `[lo, hi]` (§5.3 rule 2).
pub type Interval = (u32, u32, u64);

/// The receipts a provider holds for one identity under one Prime key.
#[derive(Debug, Clone)]
pub struct ReceiptBook {
    pub identity: String,
    pub prime_pubkey: VerifyingKey,
    pub prime_id: u32,
    /// invoice -> the highest-seq receipt held (insertion order is kept: fraud proofs list them so).
    pub last: IndexMap<String, Signed>,
    by_seq: HashMap<(String, u64), Signed>,
    /// invoice -> cum_work already turned into credit.
    pub credited: HashMap<String, u64>,
    pub intervals: Vec<Interval>,
    pub fraud: Vec<Equivocation>,
}

impl ReceiptBook {
    pub fn new(identity: &str, prime_pubkey: VerifyingKey, prime_id: u32) -> Self {
        Self { identity: identity.into(), prime_pubkey, prime_id, last: IndexMap::new(), by_seq: HashMap::new(),
               credited: HashMap::new(), intervals: vec![], fraud: vec![] }
    }

    /// Verify a receipt presented for `invoice`; return the newly credited work (0 for a replay).
    pub fn accept(&mut self, s: &Signed, invoice: &str) -> Result<u64> {
        let r = &s.receipt;
        if r.identity != self.identity {
            return fail("wrong_identity", "receipt pays another identity");
        }
        if r.prime_id != self.prime_id {
            return fail("wrong_prime", "");
        }
        if r.invoice != invoice {
            return fail("wrong_invoice", "receipt is for another invoice");
        }
        if !s.verify(&self.prime_pubkey) {
            return fail("bad_sig", "not signed by the pinned Prime key");
        }
        let key = (invoice.to_string(), r.seq);
        if let Some(twin) = self.by_seq.get(&key) {
            if twin.receipt != *r {
                self.fraud.push(Equivocation { a: twin.clone(), b: s.clone(), why: "equivocation: two receipts, one seq".into() });
                return fail("equivocation", "two receipts with one seq");
            }
        }
        self.by_seq.insert(key, s.clone());
        let prev = self.last.get(invoice).cloned();
        if let Some(prev) = &prev {
            let p = &prev.receipt;
            if r.seq > p.seq && (r.cum_work < p.cum_work || r.shares < p.shares || r.last_height < p.last_height) {
                self.fraud.push(Equivocation { a: prev.clone(), b: s.clone(), why: "cumulative state went backwards".into() });
                return fail("equivocation", "cumulative state went backwards");
            }
            if r.seq < p.seq && (r.cum_work > p.cum_work || r.shares > p.shares) {
                self.fraud.push(Equivocation { a: s.clone(), b: prev.clone(), why: "cumulative state went backwards".into() });
                return fail("equivocation", "cumulative state went backwards");
            }
            if r.seq <= p.seq {
                return Ok(0);
            }
        }
        if r.seq == 0 {
            return Ok(0);
        }
        self.last.insert(invoice.to_string(), s.clone());
        let before = self.credited.get(invoice).copied().unwrap_or(0);
        let lo = match &prev {
            Some(p) if p.receipt.seq != 0 => p.receipt.last_height,
            _ => r.first_height,
        };
        let delta = r.cum_work.saturating_sub(before);
        if delta > 0 {
            self.intervals.push((lo, r.last_height, delta));
        }
        self.credited.insert(invoice.to_string(), r.cum_work);
        Ok(delta)
    }

    /// The receipts a §10.4 fraud proof for the block at `height` carries: per invoice, the latest
    /// receipt held and, when its span does not lie inside `(window_start, height)`, the held
    /// receipt of that invoice with the most work whose span does (the one that brackets the
    /// window), placed before it. A third party can only count whole in-span receipts.
    pub fn proof_receipts(&self, window_start: u32, height: u32) -> Vec<&Signed> {
        let inside = |s: &Signed| s.receipt.first_height > window_start && s.receipt.last_height < height;
        let mut out = vec![];
        for (inv, last) in &self.last {
            if !inside(last) {
                let best = self.by_seq.iter().filter(|((i, _), s)| i == inv && inside(s)).map(|(_, s)| s)
                    .max_by_key(|s| (s.receipt.cum_work, s.receipt.seq));
                out.extend(best);
            }
            out.push(last);
        }
        out
    }

    /// The best receipt held for `invoice`.
    pub fn best(&self, invoice: &str) -> Option<&Signed> {
        self.last.get(invoice)
    }

    /// Everything a restart needs (the receipts are signed, so reloading re-verifies them).
    pub fn to_json(&self) -> Value {
        let last: Vec<Value> = self.last.values().map(Signed::to_doc).collect();
        let iv: Vec<Value> = self.intervals.iter().map(|(lo, hi, w)| Value::from(vec![Value::from(*lo), Value::from(*hi), Value::from(*w)])).collect();
        let cr: serde_json::Map<String, Value> = self.last.keys().map(|k| (k.clone(), self.credited.get(k).copied().unwrap_or(0).into())).collect();
        obj([("last", last.into()), ("credited", Value::Object(cr)), ("intervals", iv.into()),
             ("fraud", self.fraud.iter().map(Equivocation::to_json).collect::<Vec<_>>().into())])
    }

    /// Restore [`ReceiptBook::to_json`]. Every held receipt must still verify.
    pub fn load(&mut self, v: &Value) -> Result<()> {
        let bad = |w: &str| WorkError::new("bad_state", w.to_string());
        for d in v.get("last").and_then(Value::as_array).into_iter().flatten() {
            let s = Signed::from_doc(d).map_err(|e| bad(&e.0))?;
            if !s.verify(&self.prime_pubkey) || s.receipt.identity != self.identity {
                return Err(bad("held receipt does not verify"));
            }
            self.by_seq.insert((s.receipt.invoice.clone(), s.receipt.seq), s.clone());
            self.last.insert(s.receipt.invoice.clone(), s);
        }
        for (k, c) in v.get("credited").and_then(Value::as_object).into_iter().flatten() {
            self.credited.insert(k.clone(), c.as_u64().ok_or_else(|| bad("credited"))?);
        }
        for i in v.get("intervals").and_then(Value::as_array).into_iter().flatten() {
            let f = |j: usize| i.get(j).and_then(Value::as_u64).ok_or_else(|| bad("interval"));
            self.intervals.push((f(0)? as u32, f(1)? as u32, f(2)?));
        }
        for e in v.get("fraud").and_then(Value::as_array).into_iter().flatten() {
            let line = |k: &str| -> Result<Signed> {
                let d = e.get(k).ok_or_else(|| bad("fraud"))?;
                let r = WorkReceipt::parse_line(d.get("message").and_then(Value::as_str).unwrap_or("")).map_err(|e| bad(&e.0))?;
                Ok(Signed { receipt: r, sig: sig64(d.get("sig")).map_err(|e| bad(&e.0))? })
            };
            self.fraud.push(Equivocation { a: line("a")?, b: line("b")?, why: e.get("why").and_then(Value::as_str).unwrap_or("").into() });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::PrimeKey;

    const P: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const I: &str = "vfer2e5e75t4tv7in42lakx6i4";

    fn r(seq: u64, cum: u64, first: u32, last: u32) -> WorkReceipt {
        WorkReceipt { seq, cum_work: cum, shares: seq, first_height: first, last_height: last, difficulty: 4, ..WorkReceipt::zero(70, P, I) }
    }

    #[test]
    fn deltas_replays_equivocation_and_reload() {
        let k = PrimeKey::from_seed(70, &[1u8; 32]);
        let mut b = ReceiptBook::new(P, k.pubkey(), 70);
        assert_eq!(b.accept(&k.sign(&r(3, 12, 101, 102)).unwrap(), I).unwrap(), 12);
        assert_eq!(b.accept(&k.sign(&r(7, 28, 101, 104)).unwrap(), I).unwrap(), 16);
        assert_eq!(b.accept(&k.sign(&r(3, 12, 101, 102)).unwrap(), I).unwrap(), 0);
        assert_eq!(b.intervals, vec![(101, 102, 12), (102, 104, 16)]);
        let e = b.accept(&k.sign(&r(7, 56, 101, 104)).unwrap(), I).unwrap_err();
        assert_eq!(e.code, "equivocation");
        assert!(b.fraud[0].check(&k.pubkey()));
        let e = b.accept(&k.sign(&r(9, 20, 101, 105)).unwrap(), I).unwrap_err();
        assert_eq!(e.code, "equivocation");
        assert!(b.fraud[1].check(&k.pubkey()));
        let other = PrimeKey::from_seed(70, &[2u8; 32]);
        assert_eq!(b.accept(&other.sign(&r(8, 40, 101, 105)).unwrap(), I).unwrap_err().code, "bad_sig");
        let mut c = ReceiptBook::new(P, k.pubkey(), 70);
        c.load(&b.to_json()).unwrap();
        assert_eq!((c.intervals.clone(), c.credited.clone(), c.fraud.len()), (b.intervals.clone(), b.credited.clone(), 2));
        assert_eq!(c.accept(&k.sign(&r(8, 30, 101, 105)).unwrap(), I).unwrap(), 2);
    }
}
