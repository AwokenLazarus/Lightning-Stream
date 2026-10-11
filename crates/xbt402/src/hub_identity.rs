//! A hub named by a Lightning node (AGP-109): the statement the node signs, the check a payer
//! runs on it, and the hub's address `<node id>@host:port`.
//!
//! The statement is four lines of text, no line break after the last:
//!
//! ```text
//! xbt-stream-hub v1
//! network=<network id>
//! payto=<the hub's 33-byte payTo key, hex>
//! until=<unix time>
//! ```
//!
//! The node signs it as any Lightning signed message (`SignMessage`): the digest is the double
//! SHA-256 of `Lightning Signed Message:` followed by the text, the signature is 65 bytes in
//! zbase32 (a header byte carrying the recovery id, then r and s). A payer recovers the key and
//! compares it with the node id; it needs no Lightning node and no network to do so.
//!
//! Rule I1: **a payer treats a hub as the hub of node N only on a statement that N's key signed,
//! that names the payTo key and the network of the offer in front of it, and that has not run
//! out and runs at most [`MAX_AHEAD_SECS`] ahead.** Every way to break it is refused by
//! [`verify`]:
//!
//! | Case | Refused as |
//! |---|---|
//! | a byte of the text or of the signature changed | the key recovered is not the node's, or none |
//! | a statement for another hub key (a copy from another hub of the same node) | `payto` |
//! | a statement for another network | `network` |
//! | `until` passed | expired |
//! | `until` further ahead than a hub signs (a holder of the hub's macaroon signing one for years) | too far ahead |
//! | a text that is not exactly the four lines (more lines, other order, spaces, a line break at the end) | not a statement |
//! | a node id that is not a compressed public key | node id |
//!
//! What it does not cover: the node key says which hub key is its hub; the hub key signs the fee
//! quotes and is the key the payer's channel pays. Nothing here says the node is honest, or that
//! its channels back the hub: no Lightning payment is part of a Stream payment.
//!
//! No IO: the text and the time are arguments.
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, PublicKey, SECP256K1};
use serde_json::{json, Value};
use xbt_primitives::hash::sha256;

use crate::error::{ChannelError, Result};

/// The statement's first line.
pub const HEADER: &str = "xbt-stream-hub v1";
/// What every Lightning node puts before a message it signs.
pub const LN_PREFIX: &[u8] = b"Lightning Signed Message:";
/// A hub asks for a statement that runs this long.
pub const LIFE_SECS: u64 = 30 * 86_400;
/// A hub asks again once its statement is this old.
pub const RESIGN_AFTER_SECS: u64 = 7 * 86_400;
/// The furthest ahead a payer takes an `until`: a hub's 30 days and a day for two clocks.
pub const MAX_AHEAD_SECS: u64 = 31 * 86_400;
/// A statement is this long at most (a network id is short; the cap keeps a 402 small).
pub const MAX_TEXT: usize = 512;

const ZBASE32: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

fn bad(msg: impl Into<String>) -> ChannelError {
    ChannelError::new("hub_identity", msg)
}

/// What a statement says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub network: String,
    /// The hub's payTo key: 33 bytes, lowercase hex.
    pub payto: String,
    pub until: u64,
}

/// A compressed public key in lowercase hex (a node id, a payTo key), or why not.
pub fn key_hex(s: &str) -> Option<String> {
    let ok = s.len() == 66 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
    let b = ok.then(|| hex::decode(s).ok()).flatten()?;
    PublicKey::from_slice(&b).ok().map(|_| s.to_string())
}

impl Statement {
    /// The text a node signs. A network id with a line break or an `=`-free form is the
    /// caller's to refuse: [`Statement::parse`] of this text must give `self` back, and
    /// [`sign_text`] checks that it does.
    pub fn text(&self) -> String {
        format!("{HEADER}\nnetwork={}\npayto={}\nuntil={}", self.network, self.payto, self.until)
    }

    /// Exactly the four lines, in order, each `key=value` with nothing around it. `until` is
    /// decimal digits with no sign and no leading zero.
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > MAX_TEXT {
            return Err(bad("the statement is too long"));
        }
        let lines: Vec<&str> = text.split('\n').collect();
        let [header, network, payto, until] = lines.as_slice() else { return Err(bad("not a hub statement: four lines expected")) };
        if *header != HEADER {
            return Err(bad(format!("not a hub statement: the first line is not {HEADER:?}")));
        }
        let field = |line: &str, key: &str| line.strip_prefix(key).and_then(|r| r.strip_prefix('=')).map(str::to_string)
            .ok_or_else(|| bad(format!("not a hub statement: no {key}= line where one is expected")));
        let network = field(network, "network")?;
        if network.is_empty() || network.bytes().any(|c| !c.is_ascii_graphic()) {
            return Err(bad("the statement's network is not a network id"));
        }
        let payto = key_hex(&field(payto, "payto")?).ok_or_else(|| bad("the statement's payto is not a public key in lowercase hex"))?;
        let until = field(until, "until")?;
        if until.is_empty() || until.len() > 12 || !until.bytes().all(|c| c.is_ascii_digit()) || (until.len() > 1 && until.starts_with('0')) {
            return Err(bad("the statement's until is not a unix time"));
        }
        let until = until.parse::<u64>().map_err(|_| bad("the statement's until is not a unix time"))?;
        Ok(Self { network, payto, until })
    }
}

/// The statement text for a hub key on a network, running to `until`: the text handed to the
/// node. Refuses what [`Statement::parse`] would not read back.
pub fn sign_text(network: &str, payto: &str, until: u64) -> Result<String> {
    let st = Statement { network: network.to_string(), payto: payto.to_string(), until };
    let text = st.text();
    if Statement::parse(&text)? != st {
        return Err(bad("the statement does not read back as written"));
    }
    Ok(text)
}

/// zbase32 to bytes: every character in the alphabet, and no bits left over.
fn zbase32_decode(s: &str) -> Option<Vec<u8>> {
    if !(s.len() * 5).is_multiple_of(8) {
        return None;
    }
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::with_capacity(s.len() * 5 / 8));
    for c in s.bytes() {
        let v = ZBASE32.iter().position(|a| *a == c)? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Bytes to zbase32 (the vector emitter and the tests sign with a key of their own).
pub fn zbase32_encode(b: &[u8]) -> String {
    let (mut acc, mut bits, mut out) = (0u32, 0u32, String::with_capacity(b.len() * 8 / 5 + 1));
    for byte in b {
        acc = (acc << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ZBASE32[((acc >> bits) & 31) as usize] as char);
            acc &= (1 << bits) - 1;
        }
    }
    if bits > 0 {
        out.push(ZBASE32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// What a Lightning node signs for `msg`.
pub fn ln_digest(msg: &[u8]) -> [u8; 32] {
    let mut m = LN_PREFIX.to_vec();
    m.extend_from_slice(msg);
    sha256(&sha256(&m))
}

/// The key that signed `msg` as a Lightning signed message, in hex: `signature` is the node's
/// zbase32 answer (65 bytes: 31 to 34 for the recovery id of a compressed key, then r and s).
pub fn recover_node_id(msg: &[u8], signature: &str) -> Result<String> {
    let sig = zbase32_decode(signature).filter(|s| s.len() == 65).ok_or_else(|| bad("the signature is not 65 bytes of zbase32"))?;
    let rid = sig[0].checked_sub(31).filter(|r| *r < 4).ok_or_else(|| bad("the signature's first byte is not a compressed-key recovery id"))?;
    let rid = RecoveryId::from_i32(i32::from(rid)).map_err(|_| bad("the signature's recovery id"))?;
    let rsig = RecoverableSignature::from_compact(&sig[1..], rid).map_err(|_| bad("the signature is not a signature"))?;
    let key = SECP256K1.recover_ecdsa(&Message::from_digest(ln_digest(msg)), &rsig).map_err(|_| bad("the signature recovers no key"))?;
    Ok(hex::encode(key.serialize()))
}

/// Sign `msg` as a Lightning node would (tests and the vector emitter; a hub never holds a node
/// key).
pub fn ln_sign(msg: &[u8], key: &secp256k1::SecretKey) -> String {
    let (rid, sig) = SECP256K1.sign_ecdsa_recoverable(&Message::from_digest(ln_digest(msg)), key).serialize_compact();
    let mut b = vec![31 + rid.to_i32() as u8];
    b.extend_from_slice(&sig);
    zbase32_encode(&b)
}

/// Rule I1. `node_id`: the node the payer was told (the hub's address) or the one the hub claims.
/// `network` and `payto`: those of the offer the statement came with. `now`: unix seconds.
pub fn verify(text: &str, signature: &str, node_id: &str, network: &str, payto: &str, now: u64) -> Result<Statement> {
    let node = key_hex(node_id).ok_or_else(|| bad("the node id is not a public key in lowercase hex"))?;
    let st = Statement::parse(text)?;
    if recover_node_id(text.as_bytes(), signature)? != node {
        return Err(bad(format!("the statement is not signed by node {node}")));
    }
    if st.network != network {
        return Err(bad(format!("the statement is for network {}, and the hub's offer is on {network}", st.network)));
    }
    if st.payto != payto {
        return Err(bad("the statement names another hub key than the one this hub is paid on"));
    }
    if st.until <= now {
        return Err(bad(format!("the statement ran out at {} (now {now}): the hub's Lightning node has not signed a new one", st.until)));
    }
    if st.until > now.saturating_add(MAX_AHEAD_SECS) {
        return Err(bad(format!("the statement runs to {}, more than {} days ahead: a hub signs for {} days", st.until, MAX_AHEAD_SECS / 86_400, LIFE_SECS / 86_400)));
    }
    Ok(st)
}

/// `extra.routing.lightning` of a hub's 402.
pub fn to_extra(node_id: &str, text: &str, signature: &str) -> Value {
    json!({"nodeId": node_id, "statement": text, "signature": signature})
}

/// [`verify`] on `extra.routing.lightning`. `want_node`: the node id the payer was given, if the
/// hub was named by one. Returns the node id the statement is good for.
///
/// * `lightning` absent or null: `Ok(None)` for a hub named by URL; an error for one named by a
///   node id (anyone could answer at that address).
/// * present: it must verify, whoever named the hub (a hub that shows a wrong or run-out
///   statement is not paid by URL either), and for the node the payer was given.
pub fn check_extra(lightning: Option<&Value>, want_node: Option<&str>, network: &str, payto: &str, now: u64) -> Result<Option<String>> {
    let Some(l) = lightning.filter(|l| !l.is_null()) else {
        return match want_node {
            Some(n) => Err(bad(format!("the hub shows no statement signed by node {n}"))),
            None => Ok(None),
        };
    };
    let s = |k: &str| l.get(k).and_then(Value::as_str).ok_or_else(|| bad(format!("extra.routing.lightning.{k} is missing")));
    let (node, text, sig) = (s("nodeId")?, s("statement")?, s("signature")?);
    if let Some(w) = want_node.filter(|w| *w != node) {
        return Err(bad(format!("the hub shows a statement of node {node}, and was named as the hub of node {w}")));
    }
    verify(text, sig, node, network, payto, now)?;
    Ok(Some(node.to_string()))
}

/// A hub's address: `<node id>@host:port`, the shape of a Lightning node's. After the `@` a full
/// `http://` or `https://` URL is taken as it is (a hub behind a proxy, or under a path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubAddress {
    pub node_id: String,
    pub url: String,
}

impl HubAddress {
    /// `None`: `s` does not start with a node id and an `@` (it is a URL, and is left alone).
    /// `Some(Err)`: it does, and what follows is no host.
    pub fn parse(s: &str) -> Option<Result<Self>> {
        let (node, rest) = s.trim().split_once('@')?;
        let node_id = key_hex(&node.to_ascii_lowercase())?;
        let rest = rest.trim_end_matches('/');
        let url = if rest.starts_with("http://") || rest.starts_with("https://") { rest.to_string() } else { format!("http://{rest}") };
        let host = url.split("://").nth(1).unwrap_or("");
        if host.is_empty() || host.starts_with(':') || host.bytes().any(|c| c.is_ascii_whitespace() || c == b'@') {
            return Some(Err(bad("a hub address is <node id>@host:port")));
        }
        Some(Ok(Self { node_id, url }))
    }

    /// `<node id>@host:port` for a hub served at `url` (`http://host:port`), or the URL form.
    pub fn display(node_id: &str, url: &str) -> String {
        let url = url.trim_end_matches('/');
        match url.strip_prefix("http://").filter(|r| !r.contains('/')) {
            Some(hostport) => format!("{node_id}@{hostport}"),
            None => format!("{node_id}@{url}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET: &str = "bip122:000000000019d6689c085ae165831e93";

    fn key(b: u8) -> (secp256k1::SecretKey, String) {
        let k = secp256k1::SecretKey::from_slice(&[b; 32]).unwrap();
        (k, hex::encode(PublicKey::from_secret_key(SECP256K1, &k).serialize()))
    }

    fn signed(until: u64) -> (String, String, String, String) {
        let ((node, node_id), (_, payto)) = (key(7), key(9));
        let text = sign_text(NET, &payto, until).unwrap();
        (ln_sign(text.as_bytes(), &node), text, node_id, payto)
    }

    #[test]
    fn a_statement_reads_back_and_nothing_else_does() {
        let (_, payto) = key(9);
        let text = sign_text(NET, &payto, 1_800_000_000).unwrap();
        assert_eq!(text, format!("xbt-stream-hub v1\nnetwork={NET}\npayto={payto}\nuntil=1800000000"));
        assert_eq!(Statement::parse(&text).unwrap(), Statement { network: NET.into(), payto: payto.clone(), until: 1_800_000_000 });
        for wrong in [format!("{text}\n"), format!(" {text}"), text.replace("v1", "v2"), text.replace("until=", "until= "), text.replace("until=1", "until=01"),
                      text.replace("until=1800000000", "until=-1"), text.replace("until=1800000000", "until="), text.replace("\npayto", "\r\npayto"),
                      text.replace(&payto, &payto.to_uppercase()), text.replace(&payto, &payto[..64]), format!("{text}\nuntil=9999999999"),
                      text.replace("network=", "network= "), text.replacen("network", "payto", 1), "x".repeat(MAX_TEXT + 1), String::new()] {
            assert!(Statement::parse(&wrong).is_err(), "{wrong:?}");
        }
        // a network id that would add a line is not written
        assert!(sign_text("a\nuntil=1", &payto, 5).is_err());
        assert!(sign_text(NET, "02zz", 5).is_err());
    }

    #[test]
    fn zbase32_round_trips_and_refuses_what_is_not() {
        for n in [0usize, 1, 5, 64, 65] {
            let b: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            let s = zbase32_encode(&b);
            if n % 5 == 0 {
                assert_eq!(zbase32_decode(&s).unwrap(), b, "{n}");
            }
        }
        assert_eq!(zbase32_encode(&[0xff; 65]).len(), 104);
        assert!(zbase32_decode("l").is_none(), "bits left over");
        assert!(zbase32_decode("yyyyyyyl").is_none(), "a letter outside the alphabet");
        assert!(zbase32_decode("YYYYYYYY").is_none(), "upper case");
    }

    #[test]
    fn rule_i1_every_way_to_break_it_is_refused() {
        let now = 1_700_000_000;
        let (sig, text, node, payto) = signed(now + LIFE_SECS);
        assert_eq!(verify(&text, &sig, &node, NET, &payto, now).unwrap().until, now + LIFE_SECS);
        assert_eq!(recover_node_id(text.as_bytes(), &sig).unwrap(), node);
        let refused = |r: Result<Statement>, what: &str| {
            let e = r.unwrap_err();
            assert!(e.code == "hub_identity" && e.msg.contains(what), "{e} / {what}");
        };
        // every single character of the signature, changed to its neighbour in the alphabet
        for i in 0..sig.len() {
            let mut b = sig.clone().into_bytes();
            let at = ZBASE32.iter().position(|a| *a == b[i]).unwrap();
            b[i] = ZBASE32[(at + 1) % 32];
            assert!(verify(&text, &String::from_utf8(b).unwrap(), &node, NET, &payto, now).is_err(), "signature char {i}");
        }
        // every byte of the text, changed (one that still parses is signed by nobody)
        for i in 0..text.len() {
            let mut b = text.clone().into_bytes();
            b[i] = if b[i] == b'1' { b'2' } else { b'1' };
            if let Ok(t) = String::from_utf8(b) {
                assert!(verify(&t, &sig, &node, NET, &payto, now).is_err(), "text byte {i}");
            }
        }
        refused(verify(&text, &sig, &key(8).1, NET, &payto, now), "not signed by node");
        refused(verify(&text, &sig, &node, "bip122:other", &payto, now), "network");
        refused(verify(&text, &sig, &node, NET, &key(10).1, now), "another hub key");
        refused(verify(&text, &sig, &node, NET, &payto, now + LIFE_SECS), "ran out");
        refused(verify(&text, &sig, &node, NET, &payto, now + LIFE_SECS + 1), "ran out");
        assert!(verify(&text, &sig, &node, NET, &payto, now + LIFE_SECS - 1).is_ok(), "its last second");
        refused(verify(&text, &sig, &node.to_uppercase(), NET, &payto, now), "node id");
        refused(verify(&text, &sig[..103], &node, NET, &payto, now), "65 bytes");
        // signed for years by whoever holds the hub's macaroon: the bound a payer keeps
        let (sig, text, node, payto) = signed(now + MAX_AHEAD_SECS + 1);
        refused(verify(&text, &sig, &node, NET, &payto, now), "days ahead");
        let (sig, text, node, payto) = signed(now + MAX_AHEAD_SECS);
        assert!(verify(&text, &sig, &node, NET, &payto, now).is_ok());
        // a header byte outside 31..=34 (an uncompressed-key or a Bitcoin-message header)
        let mut raw = zbase32_decode(&sig).unwrap();
        raw[0] = 27;
        refused(verify(&text, &zbase32_encode(&raw), &node, NET, &payto, now), "recovery id");
    }

    #[test]
    fn the_402s_extra_named_by_url_or_by_node() {
        let now = 1_700_000_000;
        let (sig, text, node, payto) = signed(now + LIFE_SECS);
        let ex = to_extra(&node, &text, &sig);
        assert_eq!(check_extra(Some(&ex), Some(&node), NET, &payto, now).unwrap().as_deref(), Some(node.as_str()));
        assert_eq!(check_extra(Some(&ex), None, NET, &payto, now).unwrap().as_deref(), Some(node.as_str()));
        // no statement: by URL as before, never by node id
        assert_eq!(check_extra(None, None, NET, &payto, now).unwrap(), None);
        assert_eq!(check_extra(Some(&Value::Null), None, NET, &payto, now).unwrap(), None);
        assert!(check_extra(None, Some(&node), NET, &payto, now).unwrap_err().msg.contains("no statement"));
        // another node's statement at the address of the node we were given
        assert!(check_extra(Some(&ex), Some(&key(8).1), NET, &payto, now).unwrap_err().msg.contains("named as the hub of node"));
        // a wrong or run-out statement is refused by URL too
        assert!(check_extra(Some(&ex), None, NET, &payto, now + LIFE_SECS).is_err());
        let mut cut = ex.clone();
        cut.as_object_mut().unwrap().remove("signature");
        assert!(check_extra(Some(&cut), None, NET, &payto, now).unwrap_err().msg.contains("signature is missing"));
        assert!(check_extra(Some(&json!("x")), None, NET, &payto, now).is_err());
        // the hub claims a node id the signature is not of
        let lie = to_extra(&key(8).1, &text, &sig);
        assert!(check_extra(Some(&lie), None, NET, &payto, now).is_err());
    }

    #[test]
    fn a_hub_address_is_a_node_id_and_a_host() {
        let (_, node) = key(7);
        let a = HubAddress::parse(&format!("{node}@hub.example:9480")).unwrap().unwrap();
        assert_eq!((a.node_id.as_str(), a.url.as_str()), (node.as_str(), "http://hub.example:9480"));
        assert_eq!(HubAddress::display(&node, "http://hub.example:9480/"), format!("{node}@hub.example:9480"));
        let a = HubAddress::parse(&format!("{}@https://hub.example/base/", node.to_uppercase())).unwrap().unwrap();
        assert_eq!((a.node_id.as_str(), a.url.as_str()), (node.as_str(), "https://hub.example/base"));
        assert_eq!(HubAddress::display(&node, "https://hub.example/base"), format!("{node}@https://hub.example/base"));
        assert_eq!(HubAddress::parse(&HubAddress::display(&node, "https://hub.example/base")).unwrap().unwrap(), a);
        // a URL stays a URL, userinfo and all
        assert!(HubAddress::parse("http://hub.example:9480").is_none());
        assert!(HubAddress::parse("http://user@hub.example:9480").is_none());
        assert!(HubAddress::parse(&format!("{}@hub.example:9480", &node[..65])).is_none());
        for rest in ["", ":9480", "a b:1", "x@y:1"] {
            assert!(HubAddress::parse(&format!("{node}@{rest}")).unwrap().is_err(), "{rest:?}");
        }
    }
}
