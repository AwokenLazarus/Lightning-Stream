//! The seller's Lightning node vouches for its link key.
//!
//! A link key is an iroh endpoint key: anyone can make one. What makes it the seller's is a statement
//! the seller's own Lightning node signs with lnd's `SignMessage`, naming the key, the seller and an
//! expiry. The buyer checks it offline, before it sends a byte: it recovers the signer from the
//! signature and compares it with the node the seller's listing names, the node the buyer pays.
//!
//! lnd's message signature: the double SHA-256 of `"Lightning Signed Message:"` followed by the
//! message, signed as a 65-byte compact recoverable ECDSA signature (a header byte, then r and s),
//! written in z-base32.

use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, PublicKey, SECP256K1};
use sha2::{Digest, Sha256};

const PREFIX: &[u8] = b"Lightning Signed Message:";
const ZBASE32: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// The text the seller's node signs. `seller` is the seller's listing identity (its public origin or
/// its listing key); `expires` is a Unix time after which the claim is refused.
pub fn claim_text(endpoint_id_hex: &str, seller: &str, expires: u64) -> String {
    format!("lightning-stream link v1\nendpoint {endpoint_id_hex}\nseller {seller}\nexpires {expires}")
}

/// Why a claim was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// The signature is not z-base32, or not 65 bytes, or its header byte is not a recoverable one.
    Malformed,
    /// No key recovers from it.
    NoSigner,
    /// It was signed by another node than the listing names.
    OtherNode,
    /// It has expired.
    Expired,
}

/// Checks that `node_pubkey_hex` (33-byte compressed, hex) signed the claim for this key, this seller
/// and this expiry, and that the expiry is still ahead of `now`.
pub fn verify(endpoint_id_hex: &str, seller: &str, expires: u64, signature_zbase32: &str, node_pubkey_hex: &str, now: u64)
              -> Result<(), Refused> {
    if now >= expires {
        return Err(Refused::Expired);
    }
    let signer = recover(claim_text(endpoint_id_hex, seller, expires).as_bytes(), signature_zbase32)?;
    if hex::encode(signer.serialize()) != node_pubkey_hex.to_ascii_lowercase() {
        return Err(Refused::OtherNode);
    }
    Ok(())
}

/// The node that made an lnd message signature over `msg`.
pub fn recover(msg: &[u8], signature_zbase32: &str) -> Result<PublicKey, Refused> {
    let sig = zbase32_decode(signature_zbase32).ok_or(Refused::Malformed)?;
    if sig.len() != 65 || !(27..=34).contains(&sig[0]) {
        return Err(Refused::Malformed);
    }
    let id = RecoveryId::from_i32(i32::from((sig[0] - 27) & 3)).map_err(|_| Refused::Malformed)?;
    let rsig = RecoverableSignature::from_compact(&sig[1..], id).map_err(|_| Refused::Malformed)?;
    SECP256K1.recover_ecdsa(&Message::from_digest(digest(msg)), &rsig).map_err(|_| Refused::NoSigner)
}

fn digest(msg: &[u8]) -> [u8; 32] {
    let once = Sha256::new().chain_update(PREFIX).chain_update(msg).finalize();
    Sha256::digest(once).into()
}

/// Signs as lnd's `SignMessage` does. Used by tests and by a seller that holds its node key itself.
pub fn sign(msg: &[u8], key: &secp256k1::SecretKey) -> String {
    let (id, rs) = SECP256K1.sign_ecdsa_recoverable(&Message::from_digest(digest(msg)), key).serialize_compact();
    let mut out = Vec::with_capacity(65);
    out.push(27 + 4 + id.to_i32() as u8); // compressed key
    out.extend_from_slice(&rs);
    zbase32_encode(&out)
}

fn zbase32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ZBASE32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ZBASE32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn zbase32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = ZBASE32.iter().position(|&a| a == c)? as u32;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> secp256k1::SecretKey {
        secp256k1::SecretKey::from_slice(&[b; 32]).unwrap()
    }

    #[test]
    fn a_claim_signed_by_the_listed_node_passes_until_it_expires() {
        let node = key(7);
        let node_hex = hex::encode(node.public_key(SECP256K1).serialize());
        let ep = "ab".repeat(32);
        let sig = sign(claim_text(&ep, "https://shop.example", 2_000).as_bytes(), &node);
        assert_eq!(verify(&ep, "https://shop.example", 2_000, &sig, &node_hex, 1_000), Ok(()));
        assert_eq!(verify(&ep, "https://shop.example", 2_000, &sig, &node_hex, 2_000), Err(Refused::Expired));
    }

    #[test]
    fn a_claim_for_another_key_seller_or_node_is_refused() {
        let node = key(7);
        let node_hex = hex::encode(node.public_key(SECP256K1).serialize());
        let other_hex = hex::encode(key(8).public_key(SECP256K1).serialize());
        let ep = "ab".repeat(32);
        let sig = sign(claim_text(&ep, "https://shop.example", 2_000).as_bytes(), &node);
        assert_eq!(verify(&"cd".repeat(32), "https://shop.example", 2_000, &sig, &node_hex, 1), Err(Refused::OtherNode));
        assert_eq!(verify(&ep, "https://other.example", 2_000, &sig, &node_hex, 1), Err(Refused::OtherNode));
        assert_eq!(verify(&ep, "https://shop.example", 2_000, &sig, &other_hex, 1), Err(Refused::OtherNode));
        assert_eq!(verify(&ep, "https://shop.example", 2_000, "not-zbase32!", &node_hex, 1), Err(Refused::Malformed));
    }

    #[test]
    fn z_base32_round_trips() {
        for n in [0usize, 1, 5, 32, 65] {
            let data: Vec<u8> = (0..n as u8).map(|i| i.wrapping_mul(37)).collect();
            assert_eq!(zbase32_decode(&zbase32_encode(&data)).unwrap()[..n], data[..]);
        }
    }
}
