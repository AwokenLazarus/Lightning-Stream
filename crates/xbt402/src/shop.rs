//! A shop that has no web address (`docs/DIRECT-LINKS.md`).
//!
//! A seller who sells over a direct link needs no domain, no certificate and no port forward. Its
//! identity is its gateway's Nostr key, and everywhere the rest of the code wants a seller's origin
//! it gets one made from that key: `http://<key in base32>.shop.invalid`. `.invalid` never resolves
//! (RFC 6761), so nothing can reach that name except through the link that the seller's signed
//! listing names. Because the key is in the name, a listing for the shop proves itself: the Nostr
//! event that carries it is signed by the key in its `seller`.
//!
//! People see and share the key as an `npub` (NIP-19). The policy, the books, receipts and credit
//! keep using the origin, so they need nothing new.

/// The domain under which shops without a web address are named.
pub const SUFFIX: &str = ".shop.invalid";

/// RFC 4648 base32, lower case, no padding: 32 bytes are 52 letters, one DNS label.
const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
/// The bech32 alphabet (BIP-173).
const BECH32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn base32(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn unbase32(s: &str) -> Option<Vec<u8>> {
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for c in s.bytes() {
        let v = B32.iter().position(|&x| x == c)? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // the bits left over are padding and must be zero, so each key has one name
    (acc & ((1 << bits) - 1) == 0).then_some(out)
}

/// The host name of the shop whose Nostr key is `pk`.
pub fn host_for(pk: &[u8; 32]) -> String {
    format!("{}{SUFFIX}", base32(pk))
}

/// The origin the rest of the code knows the shop by.
pub fn origin_for(pk: &[u8; 32]) -> String {
    format!("http://{}", host_for(pk))
}

/// The Nostr key named by a shop host or origin; `None` for any other name.
pub fn key_of(host_or_origin: &str) -> Option<[u8; 32]> {
    let h = host_or_origin.strip_prefix("http://").unwrap_or(host_or_origin);
    let h = h.split(['/', '?', '#']).next().unwrap_or(h).to_ascii_lowercase();
    let label = h.strip_suffix(SUFFIX)?;
    if label.len() != 52 {
        return None;
    }
    unbase32(label)?.try_into().ok()
}

/// Whether `origin` is a shop without a web address.
pub fn is_shop(origin: &str) -> bool {
    key_of(origin).is_some()
}

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk = 1u32;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|b| b & 31));
    v
}

fn to_5bit(data: &[u8]) -> Vec<u8> {
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 31) as u8);
    }
    out
}

fn from_5bit(data: &[u8]) -> Option<Vec<u8>> {
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for &v in data {
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    (bits < 5 && acc & ((1 << bits) - 1) == 0).then_some(out)
}

/// `pk` as an `npub`, the way Nostr apps show a key.
pub fn npub(pk: &[u8; 32]) -> String {
    let data = to_5bit(pk);
    let mut values = hrp_expand("npub");
    values.extend(&data);
    values.extend([0u8; 6]);
    let pm = polymod(&values) ^ 1;
    let mut s = String::from("npub1");
    for v in data.iter().copied().chain((0..6).map(|i| ((pm >> (5 * (5 - i))) & 31) as u8)) {
        s.push(BECH32[v as usize] as char);
    }
    s
}

/// The key in an `npub`, if its checksum holds.
pub fn from_npub(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() > 90 || (s != s.to_ascii_lowercase() && s != s.to_ascii_uppercase()) {
        return None;
    }
    let s = s.to_ascii_lowercase();
    let rest = s.strip_prefix("npub1")?;
    let values: Vec<u8> = rest.bytes().map(|c| BECH32.iter().position(|&x| x == c).map(|p| p as u8)).collect::<Option<_>>()?;
    if values.len() < 6 {
        return None;
    }
    let mut all = hrp_expand("npub");
    all.extend(&values);
    if polymod(&all) != 1 {
        return None;
    }
    from_5bit(&values[..values.len() - 6])?.try_into().ok()
}

/// The seller a person typed: an `npub`, `nostr:<npub or 64 hex>`, a shop origin, or a web address.
/// A key comes back as its shop origin; anything else comes back trimmed, for the caller to check
/// as a web address. `None` when it looks like a key and is not a valid one.
pub fn parse(input: &str) -> Option<String> {
    let t = input.trim();
    let bare = t.strip_prefix("nostr:").unwrap_or(t);
    let lower = bare.to_ascii_lowercase();
    if lower.starts_with("npub1") {
        return from_npub(bare).map(|pk| origin_for(&pk));
    }
    if t.starts_with("nostr:") || (bare.len() == 64 && bare.bytes().all(|c| c.is_ascii_hexdigit())) {
        let pk: [u8; 32] = hex::decode(bare).ok()?.try_into().ok()?;
        return Some(origin_for(&pk));
    }
    if let Some(pk) = key_of(t) {
        return Some(origin_for(&pk));
    }
    Some(t.to_string())
}

/// How a person should see a seller: the `npub` of a shop without a web address, else the origin.
pub fn display(origin: &str) -> String {
    key_of(origin).map(|pk| npub(&pk)).unwrap_or_else(|| origin.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // NIP-19's own example key and npub
    const HEX: &str = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";
    const NPUB: &str = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg";

    fn pk() -> [u8; 32] {
        hex::decode(HEX).unwrap().try_into().unwrap()
    }

    #[test]
    fn an_npub_is_the_one_nip19_gives_and_reads_back() {
        assert_eq!(npub(&pk()), NPUB);
        assert_eq!(from_npub(NPUB), Some(pk()));
        assert_eq!(from_npub(&NPUB.to_uppercase()), Some(pk()));
    }

    #[test]
    fn an_npub_with_a_wrong_letter_or_mixed_case_is_refused() {
        let mut bad = NPUB.to_string();
        bad.replace_range(20..21, if &bad[20..21] == "q" { "p" } else { "q" });
        assert_eq!(from_npub(&bad), None);
        let mixed = format!("N{}", &NPUB[1..]);
        assert_eq!(from_npub(&mixed), None);
    }

    #[test]
    fn a_shop_name_is_one_dns_label_and_names_its_key() {
        let host = host_for(&pk());
        let label = host.strip_suffix(SUFFIX).unwrap();
        assert_eq!(label.len(), 52);
        assert!(label.bytes().all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c)));
        assert_eq!(key_of(&host), Some(pk()));
        assert_eq!(key_of(&origin_for(&pk())), Some(pk()));
        assert_eq!(key_of(&format!("{}/ai/x?y", origin_for(&pk()))), Some(pk()));
        assert_eq!(key_of(&host.to_uppercase()), Some(pk()));
    }

    #[test]
    fn other_names_are_not_shops() {
        assert_eq!(key_of("https://stream.lazarus-xbt.xyz"), None);
        assert_eq!(key_of("http://abc.shop.invalid"), None);
        // a label whose padding bits are set would name the same key twice: refused
        let host = host_for(&pk());
        let mut label: Vec<u8> = host.strip_suffix(SUFFIX).unwrap().bytes().collect();
        let last = label.len() - 1;
        label[last] = if label[last] == b'a' { b'b' } else { b'7' };
        assert_eq!(key_of(&format!("{}{SUFFIX}", String::from_utf8(label).unwrap())), None);
        assert!(!is_shop("https://example.com"));
    }

    #[test]
    fn what_a_person_types_comes_back_as_the_shops_origin() {
        let o = origin_for(&pk());
        for typed in [NPUB, &format!("nostr:{NPUB}"), &format!("  {NPUB}  "), HEX, &format!("nostr:{HEX}"), &o, &host_for(&pk())] {
            assert_eq!(parse(typed).as_deref(), Some(o.as_str()), "{typed}");
        }
        assert_eq!(parse(" https://stream.lazarus-xbt.xyz ").as_deref(), Some("https://stream.lazarus-xbt.xyz"));
        assert_eq!(parse("npub1notakey"), None);
        assert_eq!(parse("nostr:zz"), None);
        assert_eq!(display(&o), NPUB);
        assert_eq!(display("https://a.example"), "https://a.example");
    }
}
