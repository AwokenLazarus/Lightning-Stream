//! A Lightning node's macaroon, read: its permissions and caveats from the macaroon itself (the v2
//! binary format and LND's identifier). Shared by the agent wallet's Lightning rail (`xbt-signer`,
//! AGP-049) and the hub's Lightning link (AGP-109), each with its own list of what it needs.
//! Nothing here verifies the macaroon's HMAC: that is the node's job, and no reader holds the
//! root key.
//!
//! Rule M1 (the hub's, AGP-109): **on mainnet the hub uses a macaroon only if every permission
//! in it is one of the two calls the link makes, `NewAddress` and `SignMessage`.** An allowlist,
//! so a permission this code has never heard of is refused with the rest:
//!
//! | Macaroon | Mainnet |
//! |---|---|
//! | `uri:/lnrpc.Lightning/NewAddress` and `uri:/lnrpc.Lightning/SignMessage` (per call) | used |
//! | `address:write` and `message:write` (per entity: at Lightning Fork 0.21.3-beta-blake2b.17 each covers that one call and no other) | used |
//! | one of the two alone | used: with the signature alone the hub is named and returns nothing; with the address alone neither (no address of a node that has not signed is paid) |
//! | `admin.macaroon`, `readonly.macaroon`, the wallet rail's, or any one permission more | refused |
//! | an identifier that is not LND's, or that does not parse to its end | refused |
//! | not a macaroon | refused on every network |
//!
//! Off mainnet a wider macaroon is used and named in the log, as the rail does; with
//! `XBT_HUB_LN_STRICT=1` the mainnet rule applies on every network.
use serde_json::{json, Value};

/// The two calls of the hub's Lightning link, as per-call permissions.
pub const HUB_CALLS: [&str; 2] = ["uri:/lnrpc.Lightning/NewAddress", "uri:/lnrpc.Lightning/SignMessage"];
/// The same two calls as entity permissions (what `lncli bakemacaroon address:write message:write`
/// gives). Read from Lightning Fork's permission table: `address:write` is required by `NewAddress`
/// only and `message:write` by `SignMessage` only.
pub const HUB_PAIRS: [&str; 2] = ["address:write", "message:write"];

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Macaroon {
    pub location: String,
    pub identifier: Vec<u8>,
    /// First-party caveat conditions (`ipaddr 1.2.3.4`, `time-before 2026-…`, `lnd-custom …`).
    pub caveats: Vec<String>,
    /// `entity:action`, from LND's identifier (empty if the identifier is not LND's).
    pub ops: Vec<String>,
    /// The identifier was read to its last byte. False: `ops` may be short of what the node reads
    /// (a field this reader stops at), so nothing may be concluded from what is missing.
    pub exact: bool,
}

fn uvarint(b: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let c = *b.get(*pos)?;
        *pos += 1;
        v |= ((c & 0x7f) as u64) << shift;
        if c & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// One v2 field: `(type, data)`, or `None` at the end-of-section marker (a zero byte).
fn field<'a>(b: &'a [u8], pos: &mut usize) -> Result<Option<(u64, &'a [u8])>, String> {
    let t = uvarint(b, pos).ok_or("truncated field type")?;
    if t == 0 {
        return Ok(None);
    }
    let n = usize::try_from(uvarint(b, pos).ok_or("truncated field length")?).map_err(|_| "field past the end")?;
    let end = pos.checked_add(n).filter(|e| *e <= b.len()).ok_or("field past the end")?;
    let d = &b[*pos..end];
    *pos = end;
    Ok(Some((t, d)))
}

/// A protobuf length-delimited walk: `(field number, bytes)` for every wire-type-2 field; other wire
/// types are skipped. The flag: the walk ended exactly at the last byte (false: it stopped at a
/// field it does not read, or the bytes ran out inside one).
fn proto_fields(b: &[u8]) -> (Vec<(u64, &[u8])>, bool) {
    let mut out = vec![];
    let mut pos = 0;
    while pos < b.len() {
        let Some(key) = uvarint(b, &mut pos) else { return (out, false) };
        match key & 7 {
            0 => {
                if uvarint(b, &mut pos).is_none() {
                    return (out, false);
                }
            }
            1 => pos = pos.saturating_add(8),
            5 => pos = pos.saturating_add(4),
            2 => {
                let Some(n) = uvarint(b, &mut pos) else { return (out, false) };
                let Some(end) = usize::try_from(n).ok().and_then(|n| pos.checked_add(n)).filter(|e| *e <= b.len()) else { return (out, false) };
                out.push((key >> 3, &b[pos..end]));
                pos = end;
            }
            _ => return (out, false),
        }
    }
    (out, pos == b.len())
}

/// LND's identifier: a version byte (3), then `MacaroonId { nonce = 1; storageId = 2; repeated Op ops = 3 }`
/// with `Op { entity = 1; repeated actions = 2 }`.
fn lnd_ops(id: &[u8]) -> (Vec<String>, bool) {
    if id.first() != Some(&3) {
        return (vec![], false);
    }
    let mut ops = vec![];
    let (fields, mut exact) = proto_fields(&id[1..]);
    for (f, op) in fields {
        if f != 3 {
            continue;
        }
        let (parts, whole) = proto_fields(op);
        exact &= whole;
        let entity = parts.iter().find(|(n, _)| *n == 1).map(|(_, e)| String::from_utf8_lossy(e).to_string()).unwrap_or_default();
        for (_, a) in parts.iter().filter(|(n, _)| *n == 2) {
            ops.push(format!("{entity}:{}", String::from_utf8_lossy(a)));
        }
    }
    ops.sort();
    ops.dedup();
    (ops, exact)
}

/// Parse a v2 binary macaroon (what LND writes to `*.macaroon`).
pub fn parse(b: &[u8]) -> Result<Macaroon, String> {
    if b.first() != Some(&2) {
        return Err("not a v2 binary macaroon".into());
    }
    let mut pos = 1;
    let mut m = Macaroon::default();
    while let Some((t, d)) = field(b, &mut pos)? {
        match t {
            1 => m.location = String::from_utf8_lossy(d).into(),
            2 => m.identifier = d.to_vec(),
            _ => {}
        }
    }
    loop {
        if b.get(pos) == Some(&0) {
            pos += 1;
            break;
        }
        if pos >= b.len() {
            return Err("truncated caveats".into());
        }
        let (mut id, mut third_party) = (Vec::new(), false);
        while let Some((t, d)) = field(b, &mut pos)? {
            match t {
                2 => id = d.to_vec(),
                4 => third_party = true,
                _ => {}
            }
        }
        m.caveats.push(if third_party { format!("third-party {}", hex::encode(&id)) } else { String::from_utf8_lossy(&id).into() });
    }
    match field(b, &mut pos)? {
        Some((6, _)) => {}
        _ => return Err("no signature".into()),
    }
    (m.ops, m.exact) = lnd_ops(&m.identifier);
    Ok(m)
}

impl Macaroon {
    /// The caveat's argument for a condition name (`ipaddr`, `iprange`, `time-before`).
    pub fn caveat(&self, cond: &str) -> Option<String> {
        self.caveats.iter().find_map(|c| c.strip_prefix(cond).and_then(|r| r.strip_prefix(' ')).map(str::to_string))
    }

    /// The permissions that are not in `allowed`.
    pub fn outside(&self, allowed: &[&str]) -> Vec<String> {
        self.ops.iter().filter(|o| !allowed.contains(&o.as_str())).cloned().collect()
    }

    /// Whether what this macaroon allows can be read from it: LND's identifier, read to its end,
    /// with at least one permission.
    pub fn readable(&self) -> bool {
        self.exact && !self.ops.is_empty()
    }

    /// Rule M1: why this macaroon is more than the hub's link needs, if it is.
    pub fn beyond_hub(&self) -> Option<String> {
        const BAKE: &str = "bake one with only uri:/lnrpc.Lightning/NewAddress and uri:/lnrpc.Lightning/SignMessage \
                            (lncli bakemacaroon uri:/lnrpc.Lightning/NewAddress uri:/lnrpc.Lightning/SignMessage)";
        if !self.readable() {
            return Some(format!("the Lightning macaroon's permissions cannot be read: {BAKE}"));
        }
        let allowed: Vec<&str> = HUB_CALLS.iter().chain(HUB_PAIRS.iter()).copied().collect();
        let excess = self.outside(&allowed);
        (!excess.is_empty()).then(|| format!("the Lightning macaroon grants {}: {BAKE}", excess.join(", ")))
    }

    /// For the hub's status: the permissions and caveats, and whether they are the two calls only.
    pub fn hub_report(&self) -> Value {
        json!({"ops": self.ops, "onlyTheTwoCalls": self.beyond_hub().is_none(), "caveats": self.caveats, "timeBefore": self.caveat("time-before")})
    }
}

/// Test support: a macaroon as LND bakes it (v2; identifier version 3 + MacaroonId; first-party
/// caveats), with a made-up signature. No node takes it.
pub fn lnd_macaroon_for_tests(ops: &[(&str, &[&str])], caveats: &[&str]) -> Vec<u8> {
    fn len(out: &mut Vec<u8>, mut n: usize) {
        while n >= 0x80 {
            out.push((n & 0x7f) as u8 | 0x80);
            n >>= 7;
        }
        out.push(n as u8);
    }
    fn put(out: &mut Vec<u8>, t: u8, d: &[u8]) {
        out.push(t);
        len(out, d.len());
        out.extend_from_slice(d);
    }
    fn proto(field: u8, d: &[u8]) -> Vec<u8> {
        let mut v = vec![(field << 3) | 2];
        len(&mut v, d.len());
        v.extend_from_slice(d);
        v
    }
    let mut id = vec![3u8];
    id.extend(proto(1, &[7; 16]));
    id.extend(proto(2, b"0"));
    for (e, acts) in ops {
        let mut op = proto(1, e.as_bytes());
        for a in *acts {
            op.extend(proto(2, a.as_bytes()));
        }
        id.extend(proto(3, &op));
    }
    let mut m = vec![2u8];
    put(&mut m, 1, b"lnd");
    put(&mut m, 2, &id);
    m.push(0);
    for c in caveats {
        put(&mut m, 2, c.as_bytes());
        m.push(0);
    }
    m.push(0);
    put(&mut m, 6, &[9; 32]);
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnd_macaroon_for_tests as mac;

    const NEW: (&str, &[&str]) = ("uri", &["/lnrpc.Lightning/NewAddress"]);
    const SIGN: (&str, &[&str]) = ("uri", &["/lnrpc.Lightning/SignMessage"]);

    #[test]
    fn rule_m1_the_two_calls_and_nothing_more() {
        let ok = |ops: &[(&str, &[&str])]| parse(&mac(ops, &[])).unwrap().beyond_hub();
        assert_eq!(ok(&[NEW, SIGN]), None);
        assert_eq!(ok(&[("uri", &["/lnrpc.Lightning/NewAddress", "/lnrpc.Lightning/SignMessage"])]), None);
        assert_eq!(ok(&[("address", &["write"]), ("message", &["write"])]), None);
        assert_eq!(ok(&[NEW]), None, "one call alone is no wider");
        assert_eq!(parse(&mac(&[NEW, SIGN], &["time-before 2030-01-01T00:00:00Z"])).unwrap().beyond_hub(), None, "a caveat only narrows");
        // one permission more, of every kind: refused, and named
        let more: [(&str, &[&str]); 12] = [("uri", &["/lnrpc.Lightning/SendCoins"]), ("uri", &["/lnrpc.Lightning/NewAddress2"]), ("onchain", &["write"]),
                                           ("onchain", &["read"]), ("address", &["read"]), ("message", &["read"]), ("info", &["read"]), ("offchain", &["write"]),
                                           ("macaroon", &["generate"]), ("signer", &["generate"]), ("uri", &["/walletrpc.WalletKit/SendOutputs"]), ("address", &["*"])];
        for extra in more {
            let why = ok(&[NEW, SIGN, extra]).unwrap_or_else(|| panic!("{extra:?} was taken"));
            assert!(why.contains(&format!("{}:{}", extra.0, extra.1[0])) && why.contains("bake one with only"), "{why}");
        }
        // the node's own files
        let admin: &[(&str, &[&str])] = &[("address", &["read", "write"]), ("info", &["read", "write"]), ("invoices", &["read", "write"]), ("macaroon", &["generate", "read", "write"]),
                                          ("message", &["read", "write"]), ("offchain", &["read", "write"]), ("onchain", &["read", "write"]), ("peers", &["read", "write"]),
                                          ("signer", &["generate", "read"])];
        assert!(ok(admin).unwrap().contains("onchain:write"));
        assert!(ok(&[("info", &["read"]), ("offchain", &["read", "write"]), ("onchain", &["read"])]).unwrap().contains("info:read"), "the wallet rail's macaroon");
        // nothing readable is nothing allowed
        assert!(ok(&[]).unwrap().contains("cannot be read"));
        let mut other_id = mac(&[NEW, SIGN], &[]);
        let at = other_id.iter().position(|b| *b == 3).unwrap();
        other_id[at] = 4; // the identifier's version byte
        assert!(parse(&other_id).unwrap().beyond_hub().unwrap().contains("cannot be read"));
    }

    #[test]
    fn an_identifier_that_does_not_read_to_its_end_allows_nothing() {
        // a field of a wire type this reader stops at (a group), then one more permission: a
        // reader that skips the group sees `onchain:write`, so what this one saw is not the list
        let mut id = vec![3u8];
        let op = |e: &str, a: &str| {
            let mut o = vec![0x0a, e.len() as u8];
            o.extend_from_slice(e.as_bytes());
            o.extend([0x12, a.len() as u8]);
            o.extend_from_slice(a.as_bytes());
            let mut f = vec![0x1a, o.len() as u8];
            f.extend(o);
            f
        };
        id.extend(op("uri", "/lnrpc.Lightning/NewAddress"));
        id.extend([0x23, 0x24]); // field 4: start group, end group
        id.extend(op("onchain", "write"));
        let mut m = vec![2u8, 2, id.len() as u8];
        m.extend(&id);
        m.extend([0, 0, 6, 32]);
        m.extend([9u8; 32]);
        let p = parse(&m).unwrap();
        assert_eq!(p.ops, vec!["uri:/lnrpc.Lightning/NewAddress"]);
        assert!(!p.exact && !p.readable());
        assert!(p.beyond_hub().unwrap().contains("cannot be read"));
        // cut inside a permission
        let mut cut = vec![3u8];
        cut.extend(op("uri", "/lnrpc.Lightning/NewAddress"));
        cut.extend([0x1a, 40, 0x0a]);
        let mut m = vec![2u8, 2, cut.len() as u8];
        m.extend(&cut);
        m.extend([0, 0, 6, 32]);
        m.extend([9u8; 32]);
        assert!(!parse(&m).unwrap().exact);
        assert!(parse(&mac(&[NEW, SIGN], &[])).unwrap().exact);
    }

    #[test]
    fn refuses_garbage() {
        assert!(parse(b"").is_err());
        assert!(parse(&[1, 2, 3]).is_err());
        let mut b = mac(&[("info", &["read"])], &[]);
        b.truncate(b.len() - 10);
        assert!(parse(&b).is_err());
        // a length that does not fit
        assert!(parse(&[2, 2, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]).is_err());
    }
}
