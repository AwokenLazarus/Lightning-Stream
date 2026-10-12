//! A Lightning node's macaroon, read: its permissions and caveats from the macaroon itself (the v2
//! binary format and LND's identifier). The agent wallet's Lightning rail (`xbt-signer`, AGP-049)
//! holds the list of what it needs and the rule built on it.
//! Nothing here verifies the macaroon's HMAC: that is the node's job, and no reader holds the
//! root key.
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
