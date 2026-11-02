//! Sellers this wallet caught over-charging (a charge or a spend past what it could account for,
//! docs/TICKETS.md), blocked until the owner unblocks them with a signed message: no new ticket
//! session is opened, no ticket released and no draw paid to a blocked seller. A block is kept by
//! the seller's Lightning node, its receipt key and its origin, and a seller matching any of the
//! three is blocked: a new node or a new address alone does not shake it off. Each block keeps its
//! evidence (the receipt that over-charged, the session's count as it stood). The file is in the
//! signer's run folder; the audit log has the same entry (`ticket_seller_fault`).

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{json, Map, Value};

use crate::keystore::write_private;

/// The file, in the signer's run folder.
pub const FILE: &str = "blocked_sellers.json";

/// Who a block is on.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Seller<'a> {
    /// The Lightning node it is paid through (hex).
    pub payee: &'a str,
    /// The key that signs its receipts (hex).
    pub receipt_key: &'a str,
    pub origin: &'a str,
}

impl Seller<'_> {
    /// The block's id: the three, in one line.
    pub fn id(&self) -> String {
        format!("{}|{}|{}", self.payee.to_ascii_lowercase(), self.receipt_key.to_ascii_lowercase(), self.origin.to_ascii_lowercase())
    }
}

/// The blocks, by id. One lock for reading and writing the file: the signer serves calls side by side.
pub struct SellerBlocks {
    path: PathBuf,
    lock: Mutex<()>,
}

impl SellerBlocks {
    pub fn open(run: &Path) -> Self {
        Self { path: run.join(FILE), lock: Mutex::new(()) }
    }

    fn read(&self) -> Map<String, Value> {
        std::fs::read_to_string(&self.path).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|v| v.as_object().cloned()).unwrap_or_default()
    }

    /// The block on this seller, if any of its node, its receipt key or its origin is blocked.
    pub fn get(&self, s: &Seller<'_>) -> Option<Value> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let hit = |b: &Value, k: &str, v: &str| !v.is_empty() && b[k].as_str().is_some_and(|x| x.eq_ignore_ascii_case(v));
        self.read().into_iter().find(|(_, b)| hit(b, "payee", s.payee) || hit(b, "receipt_key", s.receipt_key) || hit(b, "origin", s.origin))
            .map(|(id, mut b)| {
                b["id"] = json!(id);
                b
            })
    }

    /// Block the seller, with why and the evidence (kept as it was where it is blocked already:
    /// the first fault is the evidence).
    pub fn block(&self, s: &Seller<'_>, why: &str, session: &str, ts: f64, evidence: Value) {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut m = self.read();
        m.entry(s.id()).or_insert_with(|| json!({"payee": s.payee.to_ascii_lowercase(), "receipt_key": s.receipt_key.to_ascii_lowercase(),
                                                 "origin": s.origin, "reason": why, "session": session, "ts": ts, "evidence": evidence}));
        let _ = write_private(&self.path, &Value::Object(m).to_string());
    }

    /// Lift the block `id`: whether there was one.
    pub fn unblock(&self, id: &str) -> bool {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut m = self.read();
        let was = m.remove(id).is_some();
        if was {
            let _ = write_private(&self.path, &Value::Object(m).to_string());
        }
        was
    }

    /// Every block, for the owner's page: `[{id, payee, receipt_key, origin, reason, session, ts, evidence}]`.
    pub fn list(&self) -> Vec<Value> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        self.read().into_iter().map(|(k, mut v)| {
            v["id"] = json!(k);
            v
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_matches_the_node_the_receipt_key_or_the_origin_and_lasts_until_lifted() {
        let d = tempfile::tempdir().unwrap();
        let b = SellerBlocks::open(d.path());
        let s = Seller { payee: "02AB", receipt_key: "03cd", origin: "https://shop" };
        assert!(b.get(&s).is_none());
        b.block(&s, "charged past the bound", "s1", 1.0, json!({"receipt": {"charged": "5000"}}));
        b.block(&s, "a later fault", "s2", 2.0, json!({}));
        // a new signer reads the same file; any one of the three is enough
        let b2 = SellerBlocks::open(d.path());
        for other in [Seller { payee: "02ab", ..Default::default() }, Seller { receipt_key: "03CD", ..Default::default() },
                      Seller { origin: "https://shop", ..Default::default() }] {
            assert_eq!(b2.get(&other).unwrap()["reason"], "charged past the bound", "{other:?}");
        }
        assert!(b2.get(&Seller { payee: "02ff", receipt_key: "03ff", origin: "https://other" }).is_none());
        let id = b2.list()[0]["id"].as_str().unwrap().to_string();
        assert_eq!(b2.list()[0]["evidence"]["receipt"]["charged"], "5000");
        assert!(b2.unblock(&id));
        assert!(b2.get(&s).is_none() && !b2.unblock(&id));
    }
}
