//! Sellers this wallet caught charging more than it could account for (a seller fault, docs/TICKETS.md),
//! blocked until the owner unblocks them: no new ticket session is opened with a blocked seller's
//! node. The evidence (the receipts and the wallet's count as they stood) is in the audit log, under
//! `ticket_seller_fault`; this file holds only what the block needs, in the signer's run folder.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{json, Map, Value};

use crate::keystore::write_private;

/// The file, in the signer's run folder.
pub const FILE: &str = "blocked_sellers.json";

/// The blocks, by the seller's Lightning node id (hex). One lock for reading and writing the file:
/// the signer serves calls side by side.
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

    /// The block on `node`, if it is blocked: when, at which address, and why.
    pub fn get(&self, node: &str) -> Option<Value> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        self.read().get(&node.to_ascii_lowercase()).cloned()
    }

    /// Block `node` (kept as it was where it is blocked already: the first fault is the evidence).
    pub fn block(&self, node: &str, origin: &str, why: &str, session: &str, ts: f64) {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut m = self.read();
        m.entry(node.to_ascii_lowercase()).or_insert_with(|| json!({"origin": origin, "reason": why, "session": session, "ts": ts}));
        let _ = write_private(&self.path, &Value::Object(m).to_string());
    }

    /// Unblock `node`: whether it was blocked.
    pub fn unblock(&self, node: &str) -> bool {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut m = self.read();
        let was = m.remove(&node.trim().to_ascii_lowercase()).is_some();
        if was {
            let _ = write_private(&self.path, &Value::Object(m).to_string());
        }
        was
    }

    /// Every block, for the owner's page: `[{node, origin, reason, session, ts}]`.
    pub fn list(&self) -> Vec<Value> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        self.read().into_iter().map(|(k, mut v)| {
            v["node"] = json!(k);
            v
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_lasts_until_the_owner_lifts_it_and_keeps_the_first_reason() {
        let d = tempfile::tempdir().unwrap();
        let b = SellerBlocks::open(d.path());
        assert!(b.get("02AB").is_none());
        b.block("02AB", "https://shop", "charged past the bound", "s1", 1.0);
        b.block("02ab", "https://shop", "a later fault", "s2", 2.0);
        // a new signer reads the same file
        let b2 = SellerBlocks::open(d.path());
        assert_eq!(b2.get("02ab").unwrap()["reason"], "charged past the bound");
        assert_eq!(b2.list().len(), 1);
        assert!(b2.unblock("02AB"));
        assert!(b2.get("02ab").is_none() && !b2.unblock("02ab"));
    }
}
