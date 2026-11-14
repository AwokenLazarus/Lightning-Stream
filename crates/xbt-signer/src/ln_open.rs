//! Opening the first channel: the Lightning node's second key, for the funding step only.
//!
//! The key the wallet pays with ([`crate::macaroon::NEEDED_OPS`]) cannot move coins on chain, and stays
//! that narrow. Opening a channel needs more (a new address, a peer to connect to, coins to spend), so
//! it has a key of its own, [`OPEN_OPS`], read from `B2_LN_OPEN_MACAROON` and used for exactly three
//! calls: a new address of the node (where the deposit is forwarded to, [`crate::deposit`]), a
//! connection to the peer the owner chose, and one channel to that peer, funded from the forwarded
//! deposit alone. An LND macaroon cannot be limited to one peer or one coin, so the signer is what
//! limits it: an address is only asked for, never given; a channel opens only on the owner's signature
//! over the peer and the coin, and only from a coin this signer forwarded itself.
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::ln::LndRest;
use crate::{err, Result};

/// What the open key holds: the calls above, and reading what they did.
pub const OPEN_OPS: [&str; 6] = ["address:write", "offchain:read", "offchain:write", "onchain:read", "onchain:write", "peers:write"];
pub const ENV_MACAROON: &str = "B2_LN_OPEN_MACAROON";
/// The most forwarded deposits and node addresses remembered.
const KEPT: usize = 200;

/// The node, as the funding step uses it.
pub trait OpenBackend: Send + Sync {
    /// A new on-chain address of the node (`GET /v1/newaddress`, native segwit).
    fn new_address(&self) -> Result<String>;
    /// Connect to `pubkey@host` (`POST /v1/peers`). Already connected is no error.
    fn connect(&self, pubkey: &str, host: &str) -> Result<()>;
    /// One private channel to `pubkey`, funded with everything in `txid:vout` and nothing else
    /// (`POST /v1/channels`, `fund_max` over that one outpoint): the funding transaction's id.
    fn open(&self, pubkey: &str, txid: &str, vout: u32) -> Result<String>;
    /// `GET /v1/channels/pending`: the channels still opening.
    fn pending(&self) -> Result<Vec<Value>>;
}

/// Why a macaroon is not an open key, if it is not: a permission missing, or (as `strict`, on mainnet)
/// one beyond [`OPEN_OPS`].
pub fn not_an_open_key(ops: &[String], readable: bool, strict: bool) -> Option<String> {
    let need = OPEN_OPS.join(" ");
    if !readable {
        return Some(format!("the open key's permissions cannot be read: bake one with only {need}"));
    }
    let missing: Vec<&str> = ["address:write", "offchain:write", "onchain:write", "peers:write"].into_iter().filter(|o| !ops.iter().any(|x| x == o)).collect();
    if !missing.is_empty() {
        return Some(format!("the open key lacks {}: bake one with {need}", missing.join(", ")));
    }
    let excess: Vec<&str> = ops.iter().map(String::as_str).filter(|o| !OPEN_OPS.contains(o)).collect();
    (strict && !excess.is_empty()).then(|| format!("the open key grants {}: bake one with only {need}", excess.join(", ")))
}

/// LND over REST with the open key. `strict`: refuse a key with more than [`OPEN_OPS`] (mainnet).
pub struct LndOpen {
    rest: LndRest,
}

impl LndOpen {
    pub fn new(base: &str, macaroon: &Path, tls_cert: Option<&Path>, strict: bool) -> Result<Self> {
        let bytes = std::fs::read(macaroon).map_err(|e| err("ln_config", format!("open key {}: {e}", macaroon.display())))?;
        let m = crate::macaroon::parse(&bytes).map_err(|e| err("ln_config", format!("open key: {e}")))?;
        if let Some(why) = not_an_open_key(&m.ops, m.readable(), strict) {
            return Err(err("ln_config", why));
        }
        Ok(Self { rest: LndRest::new(base, macaroon, tls_cert)? })
    }

    /// From `B2_LN_REST`, [`ENV_MACAROON`], `B2_LN_TLS_CERT`; `None` where there is no open key.
    pub fn from_env(strict: bool) -> Result<Option<Self>> {
        let (Ok(base), Ok(mac)) = (std::env::var("B2_LN_REST"), std::env::var(ENV_MACAROON)) else { return Ok(None) };
        if base.trim().is_empty() || mac.trim().is_empty() || !Path::new(&mac).is_file() {
            return Ok(None);
        }
        let cert = std::env::var("B2_LN_TLS_CERT").ok().map(PathBuf::from);
        Self::new(&base, Path::new(&mac), cert.as_deref(), strict).map(Some)
    }
}

/// A node public key: 33 bytes in hex, compressed.
pub fn valid_pubkey(pk: &str) -> bool {
    pk.len() == 66 && pk.bytes().all(|c| c.is_ascii_hexdigit()) && (pk.starts_with("02") || pk.starts_with("03"))
}

/// A peer's address as LND dials it: `host:port`, no spaces, path or user part. An onion address is one.
pub fn valid_host(host: &str) -> bool {
    let Some((h, port)) = host.rsplit_once(':') else { return false };
    !h.is_empty() && host.len() <= 300 && port.parse::<u16>().is_ok_and(|p| p > 0)
        && h.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'[' | b']' | b':'))
}

impl OpenBackend for LndOpen {
    fn new_address(&self) -> Result<String> {
        let v = self.rest.get("/v1/newaddress?type=WITNESS_PUBKEY_HASH")?;
        v.get("address").and_then(Value::as_str).filter(|a| !a.is_empty()).map(str::to_string).ok_or_else(|| err("ln_backend", "the node gave no address"))
    }

    fn connect(&self, pubkey: &str, host: &str) -> Result<()> {
        match self.rest.post("/v1/peers", &json!({"addr": {"pubkey": pubkey, "host": host}, "perm": false, "timeout": "20"}), 30) {
            Ok(_) => Ok(()),
            // the node's own words are carried apart from ours (`seller`): "already connected to peer: …" is no failure
            Err(e) if e.seller.as_deref().is_some_and(|m| m.contains("already connected")) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn open(&self, pubkey: &str, txid: &str, vout: u32) -> Result<String> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let pk = hex::decode(pubkey).map_err(|_| err("ln_open", "the peer's key is not hex"))?;
        let v = self.rest.post("/v1/channels", &json!({"node_pubkey": b64.encode(pk), "private": true, "fund_max": true, "target_conf": 6,
                                                       "outpoints": [{"txid_str": txid, "output_index": vout}]}), 60)?;
        if let Some(s) = v.get("funding_txid_str").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            return Ok(s.to_string());
        }
        // the id as bytes: in the order of the transaction's hash, the reverse of how it is written
        let mut raw = v.get("funding_txid_bytes").and_then(Value::as_str).and_then(|s| b64.decode(s).ok()).filter(|b| b.len() == 32)
            .ok_or_else(|| err("ln_backend", "the node opened no channel it named"))?;
        raw.reverse();
        Ok(hex::encode(raw))
    }

    fn pending(&self) -> Result<Vec<Value>> {
        Ok(self.rest.get("/v1/channels/pending")?.get("pending_open_channels").and_then(Value::as_array).cloned().unwrap_or_default())
    }
}

/// What the funding step did, kept beside the signer's other records: the node's addresses it was given,
/// the deposits it forwarded to them, and the channels opened from those. No secret.
pub struct FundingLog {
    path: PathBuf,
    lock: Mutex<()>,
}

pub const LOG_FILE: &str = "funding.json";

impl FundingLog {
    pub fn open(path: &Path) -> Self {
        Self { path: path.into(), lock: Mutex::new(()) }
    }

    fn read(&self) -> Value {
        std::fs::read(&self.path).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()).filter(Value::is_object)
            .unwrap_or_else(|| json!({"addresses": [], "forwards": []}))
    }

    fn write(&self, v: &Value) -> Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, format!("{v:#}\n")).and_then(|_| std::fs::rename(&tmp, &self.path)).map_err(|e| err("io", format!("funding record: {e}")))
    }

    fn push(&self, list: &str, entry: Value) -> Result<()> {
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut v = self.read();
        let mut a = v[list].as_array().cloned().unwrap_or_default();
        a.push(entry);
        if a.len() > KEPT {
            a.drain(..a.len() - KEPT);
        }
        v[list] = Value::from(a);
        self.write(&v)
    }

    pub fn add_address(&self, address: &str) -> Result<()> {
        self.push("addresses", Value::from(address))
    }

    /// Is `address` one the node gave this signer?
    pub fn is_node_address(&self, address: &str) -> bool {
        self.read()["addresses"].as_array().is_some_and(|a| a.iter().any(|x| x.as_str() == Some(address)))
    }

    /// The newest address the node gave that no forwarded deposit has paid yet: asked for once, shown until used.
    pub fn unused_address(&self) -> Option<String> {
        let v = self.read();
        let last = v["addresses"].as_array()?.last()?.as_str()?.to_string();
        let used = v["forwards"].as_array().is_some_and(|f| f.iter().any(|x| x["to"].as_str() == Some(last.as_str())));
        (!used).then_some(last)
    }

    pub fn add_forward(&self, txid: &str, to: &str, sats: i64, ts: i64) -> Result<()> {
        self.push("forwards", json!({"txid": txid, "to": to, "sats": sats, "ts": ts}))
    }

    pub fn forwards(&self) -> Vec<Value> {
        self.read()["forwards"].as_array().cloned().unwrap_or_default()
    }

    /// The forwarded deposit `txid`, if this signer made it.
    pub fn forward(&self, txid: &str) -> Option<Value> {
        self.forwards().into_iter().find(|f| f["txid"].as_str() == Some(txid))
    }

    /// Note the channel opened from the forwarded deposit `txid`.
    pub fn set_channel(&self, txid: &str, peer: &str, funding_txid: &str) -> Result<()> {
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut v = self.read();
        if let Some(f) = v["forwards"].as_array_mut().and_then(|a| a.iter_mut().find(|f| f["txid"].as_str() == Some(txid))) {
            f["channel"] = json!({"peer": peer, "funding_txid": funding_txid});
        }
        self.write(&v)
    }
}

/// The addresses a peer is tried at, in order: `host` as one address, or up to [`MAX_HOSTS`] separated by commas (a
/// node's public address, then its onion one). `None` when any of them is not an address.
pub fn hosts(host: &str) -> Option<Vec<&str>> {
    let v: Vec<&str> = host.split(',').map(str::trim).collect();
    (!v.is_empty() && v.len() <= MAX_HOSTS && v.iter().all(|h| valid_host(h))).then_some(v)
}
pub const MAX_HOSTS: usize = 3;

#[cfg(test)]
mod tests {
    use super::*;

    /// The Add money page is looked at many times before a deposit is moved: the node is asked for one
    /// address, and for a new one only after a deposit has gone to it.
    ///
    /// FAILS when every look asks the node: its wallet fills with addresses nothing was sent to.
    #[test]
    fn the_nodes_address_is_kept_until_a_deposit_has_gone_to_it() {
        let dir = tempfile::tempdir().unwrap();
        let log = FundingLog::open(&dir.path().join(LOG_FILE));
        assert_eq!(log.unused_address(), None, "none asked for yet");
        log.add_address("addr1").unwrap();
        assert_eq!(log.unused_address().as_deref(), Some("addr1"));
        log.add_forward("aa", "addr1", 249_400, 1).unwrap();
        assert_eq!(log.unused_address(), None, "a deposit went there");
        log.add_address("addr2").unwrap();
        assert_eq!(log.unused_address().as_deref(), Some("addr2"));
    }

    #[test]
    fn an_open_key_has_what_opening_needs_and_on_mainnet_nothing_more() {
        let ops = |o: &[&str]| o.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(not_an_open_key(&ops(&OPEN_OPS), true, true), None);
        assert_eq!(not_an_open_key(&ops(&["address:write", "offchain:write", "onchain:write", "peers:write"]), true, true), None, "reading is optional");
        assert!(not_an_open_key(&ops(&crate::macaroon::NEEDED_OPS), true, false).unwrap().contains("lacks address:write, onchain:write, peers:write"));
        let more = ops(&["address:write", "offchain:write", "onchain:write", "peers:write", "macaroon:generate"]);
        assert!(not_an_open_key(&more, true, true).unwrap().contains("grants macaroon:generate"));
        assert_eq!(not_an_open_key(&more, true, false), None, "off mainnet a wider key is taken (a lab's admin key)");
        assert!(not_an_open_key(&ops(&OPEN_OPS), false, false).unwrap().contains("cannot be read"));
    }

    #[test]
    fn a_peer_is_a_key_and_a_host_with_a_port() {
        assert!(valid_pubkey(&format!("02{}", "ab".repeat(32))) && !valid_pubkey(&format!("04{}", "ab".repeat(32))) && !valid_pubkey("02ab"));
        for ok in ["203.0.113.7:9735", "node.example:9735", "abcdefghijklmnop234567abcdefghijklmnop234567abcdefghijkl.onion:9735", "[2001:db8::1]:9735"] {
            assert!(valid_host(ok), "{ok}");
        }
        for bad in ["node.example", "node.example:0", "node.example:99999", "user@node.example:9735", "node.example:9735/x", "a b:9735", ":9735"] {
            assert!(!valid_host(bad), "{bad}");
        }
    }

    #[test]
    fn a_peer_may_have_a_few_addresses_tried_in_order() {
        assert_eq!(hosts("203.0.113.7:9735"), Some(vec!["203.0.113.7:9735"]));
        assert_eq!(hosts("203.0.113.7:9735, abc.onion:9735"), Some(vec!["203.0.113.7:9735", "abc.onion:9735"]));
        assert_eq!(hosts("203.0.113.7:9735,nope"), None);
        assert_eq!(hosts(""), None);
        assert_eq!(hosts("a:1,b:1,c:1,d:1"), None, "no more than a few");
    }

    #[test]
    fn the_funding_record_keeps_addresses_forwards_and_their_channel() {
        let dir = tempfile::tempdir().unwrap();
        let log = FundingLog::open(&dir.path().join(LOG_FILE));
        assert!(!log.is_node_address("bcrt1qa") && log.forward("aa").is_none());
        log.add_address("bcrt1qa").unwrap();
        log.add_forward("aa", "bcrt1qa", 249_400, 100).unwrap();
        assert!(log.is_node_address("bcrt1qa") && !log.is_node_address("bcrt1qb"));
        log.set_channel("aa", &format!("02{}", "ab".repeat(32)), "ff").unwrap();
        let f = FundingLog::open(&dir.path().join(LOG_FILE)).forward("aa").unwrap();
        assert_eq!((f["sats"].as_i64(), f["channel"]["funding_txid"].as_str()), (Some(249_400), Some("ff")), "{f}");
    }
}
