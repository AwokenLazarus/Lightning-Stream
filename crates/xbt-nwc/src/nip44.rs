//! NIP-44 version 2: the encryption of NWC requests and responses.
//!
//! ECDH on secp256k1 (the shared point's x coordinate, unhashed), HKDF-SHA256 extract with the salt
//! `nip44-v2` (the conversation key), HKDF expand with the message's 32-byte nonce into a ChaCha20
//! key and nonce and an HMAC-SHA256 key, the spec's power-of-two padding, and
//! `base64(0x02 || nonce || ciphertext || mac)`. The MAC is checked (in constant time) before
//! anything is decrypted. `tests/nip44_vectors.rs` runs the spec's published test vectors.
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, SecretKey, XOnlyPublicKey};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const VERSION: u8 = 2;
/// The largest plaintext this service encrypts or accepts. NIP-47 messages are small; the spec allows
/// up to 4 GiB and asks implementations to set their own limit, checked before base64 decoding.
pub const MAX_PLAINTEXT: usize = 256 * 1024;
const MIN_PAYLOAD_B64: usize = 132;
const MIN_PAYLOAD: usize = 99;
const EXTENDED: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The payload's version (or a leading `#`) is not one this code knows.
    UnknownVersion,
    InvalidPayload(&'static str),
    InvalidMac,
    InvalidPadding,
    InvalidKey,
    InvalidLength,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnknownVersion => write!(f, "unknown encryption version"),
            Error::InvalidPayload(w) => write!(f, "invalid payload: {w}"),
            Error::InvalidMac => write!(f, "invalid MAC"),
            Error::InvalidPadding => write!(f, "invalid padding"),
            Error::InvalidKey => write!(f, "invalid key"),
            Error::InvalidLength => write!(f, "invalid plaintext length"),
        }
    }
}

impl std::error::Error for Error {}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// HKDF-SHA256 expand (RFC 5869) to `out.len()` bytes (at most 255 blocks).
fn hkdf_expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) {
    let mut t: Vec<u8> = Vec::new();
    for (i, chunk) in out.chunks_mut(32).enumerate() {
        let block = hmac(prk, &[&t, info, &[(i + 1) as u8]]);
        chunk.copy_from_slice(&block[..chunk.len()]);
        t = block.to_vec();
    }
}

/// The conversation key of `sk` and the x-only public key `pk` (the same both ways round).
pub fn conversation_key(sk: &SecretKey, pk: &XOnlyPublicKey) -> [u8; 32] {
    let full = PublicKey::from_x_only_public_key(*pk, secp256k1::Parity::Even);
    let point = secp256k1::ecdh::shared_secret_point(&full, sk);
    // HKDF-extract: HMAC(salt, IKM)
    hmac(b"nip44-v2", &[&point[..32]])
}

/// As [`conversation_key`], from hex keys (a 32-byte secret key, a 32-byte x-only public key).
pub fn conversation_key_hex(sk_hex: &str, pk_hex: &str) -> Result<[u8; 32], Error> {
    let sk = hex::decode(sk_hex).ok().and_then(|b| SecretKey::from_slice(&b).ok()).ok_or(Error::InvalidKey)?;
    let pk = hex::decode(pk_hex).ok().and_then(|b| XOnlyPublicKey::from_slice(&b).ok()).ok_or(Error::InvalidKey)?;
    Ok(conversation_key(&sk, &pk))
}

/// The per-message keys: `(chacha_key, chacha_nonce, hmac_key)`.
pub fn message_keys(conversation_key: &[u8; 32], nonce: &[u8; 32]) -> ([u8; 32], [u8; 12], [u8; 32]) {
    let mut okm = [0u8; 76];
    hkdf_expand(conversation_key, nonce, &mut okm);
    let (mut k, mut n, mut h) = ([0u8; 32], [0u8; 12], [0u8; 32]);
    k.copy_from_slice(&okm[..32]);
    n.copy_from_slice(&okm[32..44]);
    h.copy_from_slice(&okm[44..]);
    (k, n, h)
}

/// The padded length of a plaintext of `len` bytes (64-bit arithmetic, as the spec asks).
pub fn padded_len(len: usize) -> usize {
    if len <= 32 {
        return 32;
    }
    let next_power = 1usize << (usize::BITS - (len - 1).leading_zeros());
    let chunk = if next_power <= 256 { 32 } else { next_power / 8 };
    chunk * ((len - 1) / chunk + 1)
}

fn pad(plain: &[u8]) -> Result<Vec<u8>, Error> {
    if plain.is_empty() || plain.len() > MAX_PLAINTEXT || plain.len() > u32::MAX as usize {
        return Err(Error::InvalidLength);
    }
    let mut out = Vec::with_capacity(6 + padded_len(plain.len()));
    if plain.len() >= EXTENDED {
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&(plain.len() as u32).to_be_bytes());
    } else {
        out.extend_from_slice(&(plain.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(plain);
    out.resize(out.len() + padded_len(plain.len()) - plain.len(), 0);
    Ok(out)
}

fn unpad(padded: &[u8]) -> Result<Vec<u8>, Error> {
    if padded.len() < 2 {
        return Err(Error::InvalidPadding);
    }
    let first = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    let (len, prefix) = if first == 0 {
        if padded.len() < 6 {
            return Err(Error::InvalidPadding);
        }
        let l = u32::from_be_bytes([padded[2], padded[3], padded[4], padded[5]]) as usize;
        if l < EXTENDED {
            return Err(Error::InvalidPadding);
        }
        (l, 6)
    } else {
        (first, 2)
    };
    if len == 0 || padded.len() != prefix + padded_len(len) {
        return Err(Error::InvalidPadding);
    }
    Ok(padded[prefix..prefix + len].to_vec())
}

/// Encrypt with a given nonce (the tests' vectors); [`encrypt`] draws a fresh one.
pub fn encrypt_with_nonce(plaintext: &str, conversation_key: &[u8; 32], nonce: &[u8; 32]) -> Result<String, Error> {
    let (key, cnonce, hkey) = message_keys(conversation_key, nonce);
    let mut buf = pad(plaintext.as_bytes())?;
    ChaCha20::new(&key.into(), &cnonce.into()).apply_keystream(&mut buf);
    let mac = hmac(&hkey, &[nonce, &buf]);
    let mut raw = Vec::with_capacity(1 + 32 + buf.len() + 32);
    raw.push(VERSION);
    raw.extend_from_slice(nonce);
    raw.extend_from_slice(&buf);
    raw.extend_from_slice(&mac);
    Ok(B64.encode(raw))
}

/// Encrypt `plaintext` under `conversation_key` with a nonce from the OS's random source.
pub fn encrypt(plaintext: &str, conversation_key: &[u8; 32]) -> Result<String, Error> {
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).expect("OS randomness");
    encrypt_with_nonce(plaintext, conversation_key, &nonce)
}

/// Decrypt a payload; the MAC is checked before decryption.
pub fn decrypt(payload: &str, conversation_key: &[u8; 32]) -> Result<String, Error> {
    if payload.is_empty() || payload.starts_with('#') {
        return Err(Error::UnknownVersion);
    }
    if payload.len() < MIN_PAYLOAD_B64 {
        return Err(Error::InvalidPayload("too short"));
    }
    // the base64 of the largest payload this service accepts, checked before it is decoded
    if payload.len() > (MAX_PLAINTEXT + 6 + 65).div_ceil(3) * 4 + 4 {
        return Err(Error::InvalidPayload("too long"));
    }
    let data = B64.decode(payload).map_err(|_| Error::InvalidPayload("not base64"))?;
    if data.len() < MIN_PAYLOAD {
        return Err(Error::InvalidPayload("too short"));
    }
    if data[0] != VERSION {
        return Err(Error::UnknownVersion);
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&data[1..33]);
    let (ct, mac) = data[33..].split_at(data.len() - 33 - 32);
    let (key, cnonce, hkey) = message_keys(conversation_key, &nonce);
    let want = hmac(&hkey, &[&nonce, ct]);
    if !ct_eq(&want, mac) {
        return Err(Error::InvalidMac);
    }
    let mut buf = ct.to_vec();
    ChaCha20::new(&key.into(), &cnonce.into()).apply_keystream(&mut buf);
    let plain = unpad(&buf)?;
    String::from_utf8(plain).map_err(|_| Error::InvalidPayload("not UTF-8"))
}

/// Constant-time equality for byte strings of public length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tamper() {
        let ck = [7u8; 32];
        let p = encrypt("hello world", &ck).unwrap();
        assert_eq!(decrypt(&p, &ck).unwrap(), "hello world");
        let mut raw = B64.decode(&p).unwrap();
        raw[40] ^= 1;
        assert_eq!(decrypt(&B64.encode(raw), &ck), Err(Error::InvalidMac));
        assert_eq!(decrypt(&p, &[8u8; 32]), Err(Error::InvalidMac));
        assert_eq!(encrypt("", &ck), Err(Error::InvalidLength));
    }

    #[test]
    fn padding_lengths() {
        for (n, want) in [(1, 32), (32, 32), (33, 64), (257, 320), (65_535, 65_536), (65_536, 65_536), (65_537, 81_920)] {
            assert_eq!(padded_len(n), want, "{n}");
        }
    }
}
