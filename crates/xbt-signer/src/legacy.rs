//! On-chain channel records left by an earlier version of this wallet.
//!
//! Until 2026-10 the wallet paid sellers over an on-chain one-way channel and kept a book of them
//! (`.run/channels.json`, the payer keys sealed in `.run/channel_keys.json`). That rail was removed.
//! This version never writes either file, never signs for a channel, and cannot close or refund
//! one: it only reads the book once at start, to tell the owner what it holds.
//!
//! A channel that is still `pending` or `open` has coins in it that are the owner's: the seller's
//! close pays the unspent part to the hot key, and after the channel's expiry a refund signed with
//! the sealed key takes all of it back. Both need the version that had the channel
//! ([`LAST_WITH_CHANNEL`]). The files are left exactly as they were for it.
use std::path::Path;

use serde_json::{json, Value};

/// The last revision of this repository whose wallet could close and refund a channel.
pub const LAST_WITH_CHANNEL: &str = "2a31170";

/// The fields of a record a reader may see (never a key: the book holds none, they are sealed apart).
const SHOWN: [&str; 9] = ["state", "dest", "origin", "chan", "cap_sats", "used_sats", "expiry", "funding_txid", "closed_txid"];

/// What `channels.json` held when this signer started.
#[derive(Debug, Default)]
pub struct LegacyChannels {
    rows: Vec<Value>,
    /// Why the file could not be read, if it is there and could not: said, never taken for "no channels".
    unread: Option<String>,
}

impl LegacyChannels {
    /// Read the book at `path`. A missing file is a wallet that never had a channel.
    pub fn read(path: &Path) -> Self {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Self::default(),
            Err(e) => return Self { rows: vec![], unread: Some(format!("{}: {:?}", path.display(), e.kind())) },
        };
        let Some(m) = serde_json::from_str::<Value>(&text).ok().and_then(|v| v.get("channels").and_then(Value::as_object).cloned()) else {
            return Self { rows: vec![], unread: Some(format!("{}: not a channel book", path.display())) };
        };
        let rows = m.iter().map(|(dest, rec)| {
            let mut row = serde_json::Map::new();
            for k in SHOWN {
                row.insert(k.into(), rec.get(k).cloned().unwrap_or(Value::Null));
            }
            if row["dest"].is_null() {
                row.insert("dest".into(), dest.clone().into());
            }
            row.insert("legacy".into(), true.into());
            Value::Object(row)
        }).collect();
        Self { rows, unread: None }
    }

    /// The records, for `channels` and `balance`.
    pub fn public(&self) -> Vec<Value> {
        self.rows.clone()
    }

    /// Records with coins still in them: neither closed nor refunded.
    pub fn unsettled(&self) -> usize {
        self.rows.iter().filter(|r| !matches!(r["state"].as_str(), Some("closed" | "refunded"))).count()
    }

    /// What the owner is told, or None when there is nothing to tell.
    pub fn notice(&self) -> Option<Value> {
        if let Some(why) = &self.unread {
            return Some(json!({"unsettled": Value::Null, "unread": why,
                               "what_to_do": format!("this wallet's old channel book could not be read; this version cannot close or refund an on-chain channel: run revision {LAST_WITH_CHANNEL} on this data directory to see and settle what it holds")}));
        }
        let n = self.unsettled();
        (n > 0).then(|| json!({"unsettled": n,
                               "what_to_do": format!("this wallet holds {n} on-chain channel(s) from an earlier version that are not closed or refunded; this version cannot close or refund them and leaves their records and sealed keys untouched: run revision {LAST_WITH_CHANNEL} on this data directory to close or refund them")}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wallet_that_never_had_a_channel_says_nothing() {
        let d = std::env::temp_dir().join(format!("xbt-legacy-none-{}", std::process::id()));
        let l = LegacyChannels::read(&d.join("channels.json"));
        assert!(l.public().is_empty() && l.notice().is_none());
    }

    #[test]
    fn an_open_channel_is_listed_without_secrets_and_the_owner_is_told_what_to_do() {
        let d = std::env::temp_dir().join(format!("xbt-legacy-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("channels.json");
        std::fs::write(&p, r#"{"channels": {"http://a": {"state": "open", "chan": "c1", "cap_sats": 9, "used_sats": 4, "expiry": 700, "payer_secret": "x"},
                                            "http://b": {"state": "closed", "dest": "http://b", "chan": "c2"},
                                            "http://c": {"state": "refunded", "chan": "c3"}}, "archived": []}"#).unwrap();
        let before = std::fs::read(&p).unwrap();
        let l = LegacyChannels::read(&p);
        assert_eq!(l.public().len(), 3);
        assert_eq!((l.public()[0]["dest"].as_str(), l.public()[0]["legacy"].as_bool()), (Some("http://a"), Some(true)));
        assert!(!serde_json::to_string(&l.public()).unwrap().contains("payer_secret"));
        assert_eq!(l.unsettled(), 1);
        let n = l.notice().unwrap();
        assert!(n["unsettled"] == 1 && n["what_to_do"].as_str().unwrap().contains(LAST_WITH_CHANNEL));
        assert_eq!(std::fs::read(&p).unwrap(), before, "the book is never written");
        // a book that is there and cannot be read is said, not taken for an empty one
        std::fs::write(&p, "{nope").unwrap();
        let bad = LegacyChannels::read(&p);
        assert!(bad.notice().unwrap()["unread"].is_string());
        let _ = std::fs::remove_dir_all(&d);
    }
}
