//! BOLT 8: `Noise_XK_secp256k1_ChaChaPoly_SHA256`, the handshake and the framed transport that
//! Lightning peers use, here between the hashmaker's app and the hashtaker's app.
//!
//! The hashtaker (initiator) knows the hashmaker's static key from its listing; the hashmaker learns the
//! hashtaker's static key in act three. Both are secp256k1 keys. The prologue is a parameter: the
//! link uses [`PROLOGUE`], so a hashlink handshake never completes against a Lightning peer (or
//! the other way round); BOLT 8's own test vectors use `b"lightning"`.
//!
//! Messages are at most 65535 bytes: a 2-byte big-endian length, encrypted (18 bytes on the
//! wire), then the body, encrypted. Each direction's key rotates after 1000 encryptions.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use secp256k1::ecdh::SharedSecret;
use secp256k1::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};

/// The prologue of a hashlink handshake.
pub const PROLOGUE: &[u8] = b"xbt-hashlink/0";
const PROTOCOL: &[u8] = b"Noise_XK_secp256k1_ChaChaPoly_SHA256";
/// The largest message body.
pub const MAX_MSG: usize = 65535;
const ROTATE_AT: u64 = 1000;
pub const ACT_ONE: usize = 50;
pub const ACT_TWO: usize = 50;
pub const ACT_THREE: usize = 66;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// A bad version byte, key or MAC in the handshake, or a MAC failure in transport.
    Crypto(&'static str),
    TooLong(usize),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "link i/o: {e}"),
            Error::Crypto(w) => write!(f, "link crypto: {w}"),
            Error::TooLong(n) => write!(f, "link message of {n} bytes is over {MAX_MSG}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// HKDF with two outputs, as BOLT 8 uses it.
fn hkdf(salt: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let prk = hmac(salt, &[ikm]);
    let a = hmac(&prk, &[&[1u8]]);
    let b = hmac(&prk, &[&a, &[2u8]]);
    (a, b)
}

fn nonce(n: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[4..].copy_from_slice(&n.to_le_bytes());
    out
}

fn seal(k: &[u8; 32], n: u64, ad: &[u8], pt: &[u8]) -> Vec<u8> {
    ChaCha20Poly1305::new(k.into())
        .encrypt(&nonce(n).into(), Payload { msg: pt, aad: ad })
        .expect("encryption does not fail")
}

fn open(k: &[u8; 32], n: u64, ad: &[u8], ct: &[u8]) -> Result<Vec<u8>, Error> {
    ChaCha20Poly1305::new(k.into())
        .decrypt(&nonce(n).into(), Payload { msg: ct, aad: ad })
        .map_err(|_| Error::Crypto("bad MAC"))
}

/// BOLT 8's ECDH: SHA-256 of the compressed shared point.
fn ecdh(pk: &PublicKey, sk: &SecretKey) -> [u8; 32] {
    SharedSecret::new(pk, sk).secret_bytes()
}

fn parse_pub(b: &[u8]) -> Result<PublicKey, Error> {
    PublicKey::from_slice(b).map_err(|_| Error::Crypto("bad public key"))
}

/// One side of a handshake in progress.
pub struct Handshake {
    h: [u8; 32],
    ck: [u8; 32],
    temp_k2: [u8; 32],
    s: SecretKey,
    e: SecretKey,
    re: Option<PublicKey>,
    rs: Option<PublicKey>,
}

impl Handshake {
    fn new(prologue: &[u8], s: SecretKey, e: SecretKey, responder_static: &PublicKey) -> Self {
        let h0 = sha256(&[PROTOCOL]);
        let h = sha256(&[&sha256(&[&h0, prologue]), &responder_static.serialize()]);
        Handshake { h, ck: h0, temp_k2: [0; 32], s, e, re: None, rs: None }
    }

    /// The initiator, who knows the responder's static key `rs`.
    pub fn initiator(prologue: &[u8], s: SecretKey, e: SecretKey, rs: PublicKey) -> Self {
        let mut hs = Self::new(prologue, s, e, &rs);
        hs.rs = Some(rs);
        hs
    }

    /// The responder, with its own static key.
    pub fn responder(prologue: &[u8], s: SecretKey, e: SecretKey) -> Self {
        let own = PublicKey::from_secret_key(secp256k1::SECP256K1, &s);
        Self::new(prologue, s, e, &own)
    }

    fn mix(&mut self, data: &[u8]) {
        self.h = sha256(&[&self.h, data]);
    }

    pub fn act_one(&mut self) -> [u8; ACT_ONE] {
        let epub = PublicKey::from_secret_key(secp256k1::SECP256K1, &self.e).serialize();
        self.mix(&epub);
        let (ck, k) = hkdf(&self.ck, &ecdh(self.rs.as_ref().expect("initiator"), &self.e));
        self.ck = ck;
        let c = seal(&k, 0, &self.h, &[]);
        self.mix(&c);
        let mut out = [0u8; ACT_ONE];
        out[1..34].copy_from_slice(&epub);
        out[34..].copy_from_slice(&c);
        out
    }

    pub fn read_act_one(&mut self, m: &[u8; ACT_ONE]) -> Result<(), Error> {
        if m[0] != 0 {
            return Err(Error::Crypto("unknown handshake version"));
        }
        let re = parse_pub(&m[1..34])?;
        self.mix(&m[1..34]);
        let (ck, k) = hkdf(&self.ck, &ecdh(&re, &self.s));
        self.ck = ck;
        open(&k, 0, &self.h, &m[34..])?;
        self.mix(&m[34..]);
        self.re = Some(re);
        Ok(())
    }

    pub fn act_two(&mut self) -> [u8; ACT_TWO] {
        let epub = PublicKey::from_secret_key(secp256k1::SECP256K1, &self.e).serialize();
        self.mix(&epub);
        let (ck, k) = hkdf(&self.ck, &ecdh(self.re.as_ref().expect("after act one"), &self.e));
        self.ck = ck;
        self.temp_k2 = k;
        let c = seal(&k, 0, &self.h, &[]);
        self.mix(&c);
        let mut out = [0u8; ACT_TWO];
        out[1..34].copy_from_slice(&epub);
        out[34..].copy_from_slice(&c);
        out
    }

    pub fn read_act_two(&mut self, m: &[u8; ACT_TWO]) -> Result<(), Error> {
        if m[0] != 0 {
            return Err(Error::Crypto("unknown handshake version"));
        }
        let re = parse_pub(&m[1..34])?;
        self.mix(&m[1..34]);
        let (ck, k) = hkdf(&self.ck, &ecdh(&re, &self.e));
        self.ck = ck;
        self.temp_k2 = k;
        open(&k, 0, &self.h, &m[34..])?;
        self.mix(&m[34..]);
        self.re = Some(re);
        Ok(())
    }

    /// Act three, and the initiator's transport.
    pub fn act_three(mut self) -> ([u8; ACT_THREE], Transport) {
        let spub = PublicKey::from_secret_key(secp256k1::SECP256K1, &self.s).serialize();
        let c = seal(&self.temp_k2, 1, &self.h, &spub);
        self.mix(&c);
        let (ck, k3) = hkdf(&self.ck, &ecdh(self.re.as_ref().expect("after act two"), &self.s));
        let t = seal(&k3, 0, &self.h, &[]);
        let (sk, rk) = hkdf(&ck, &[]);
        let mut out = [0u8; ACT_THREE];
        out[1..50].copy_from_slice(&c);
        out[50..].copy_from_slice(&t);
        let remote = self.rs.expect("initiator");
        (out, Transport::new(ck, sk, rk, remote))
    }

    /// Act three, and the responder's transport, which names the initiator's static key.
    pub fn read_act_three(mut self, m: &[u8; ACT_THREE]) -> Result<Transport, Error> {
        if m[0] != 0 {
            return Err(Error::Crypto("unknown handshake version"));
        }
        let rs = parse_pub(&open(&self.temp_k2, 1, &self.h, &m[1..50])?)?;
        self.mix(&m[1..50]);
        let (ck, k3) = hkdf(&self.ck, &ecdh(&rs, &self.e));
        open(&k3, 0, &self.h, &m[50..])?;
        let (rk, sk) = hkdf(&ck, &[]);
        Ok(Transport::new(ck, sk, rk, rs))
    }
}

/// One direction's cipher state.
pub struct Cipher {
    ck: [u8; 32],
    k: [u8; 32],
    n: u64,
}

impl Cipher {
    fn next(&mut self) -> u64 {
        let n = self.n;
        self.n += 1;
        n
    }

    fn rotate(&mut self) {
        if self.n == ROTATE_AT {
            let (ck, k) = hkdf(&self.ck, &self.k);
            self.ck = ck;
            self.k = k;
            self.n = 0;
        }
    }

    /// The key in use now (for the test vectors).
    pub fn key(&self) -> [u8; 32] {
        self.k
    }

    /// One framed message: the encrypted length, then the encrypted body.
    pub fn encrypt(&mut self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        if msg.len() > MAX_MSG {
            return Err(Error::TooLong(msg.len()));
        }
        let n = self.next();
        let mut out = seal(&self.k, n, &[], &(msg.len() as u16).to_be_bytes());
        let n = self.next();
        out.extend(seal(&self.k, n, &[], msg));
        self.rotate();
        Ok(out)
    }

    pub fn decrypt_len(&mut self, c: &[u8; 18]) -> Result<usize, Error> {
        let n = self.next();
        let l = open(&self.k, n, &[], c)?;
        Ok(u16::from_be_bytes([l[0], l[1]]) as usize)
    }

    pub fn decrypt_body(&mut self, c: &[u8]) -> Result<Vec<u8>, Error> {
        let n = self.next();
        let m = open(&self.k, n, &[], c)?;
        self.rotate();
        Ok(m)
    }
}

/// The transport after a handshake: the two directions and the peer's static key.
pub struct Transport {
    pub send: Cipher,
    pub recv: Cipher,
    pub remote: PublicKey,
    /// The chaining key at the end of the handshake (for the test vectors).
    pub ck: [u8; 32],
}

impl Transport {
    fn new(ck: [u8; 32], sk: [u8; 32], rk: [u8; 32], remote: PublicKey) -> Self {
        Transport {
            send: Cipher { ck, k: sk, n: 0 },
            recv: Cipher { ck, k: rk, n: 0 },
            remote,
            ck,
        }
    }
}

/// Run the initiator's handshake over a stream.
pub fn connect<S: Read + Write>(io: &mut S, prologue: &[u8], s: SecretKey, rs: PublicKey) -> Result<Transport, Error> {
    let mut hs = Handshake::initiator(prologue, s, fresh_key(), rs);
    io.write_all(&hs.act_one())?;
    let mut two = [0u8; ACT_TWO];
    io.read_exact(&mut two)?;
    hs.read_act_two(&two)?;
    let (three, t) = hs.act_three();
    io.write_all(&three)?;
    io.flush()?;
    Ok(t)
}

/// Run the responder's handshake over a stream.
pub fn accept<S: Read + Write>(io: &mut S, prologue: &[u8], s: SecretKey) -> Result<Transport, Error> {
    let mut hs = Handshake::responder(prologue, s, fresh_key());
    let mut one = [0u8; ACT_ONE];
    io.read_exact(&mut one)?;
    hs.read_act_one(&one)?;
    io.write_all(&hs.act_two())?;
    io.flush()?;
    let mut three = [0u8; ACT_THREE];
    io.read_exact(&mut three)?;
    hs.read_act_three(&three)
}

/// Read one message.
pub fn read_msg<R: Read>(io: &mut R, c: &mut Cipher) -> Result<Vec<u8>, Error> {
    let mut l = [0u8; 18];
    io.read_exact(&mut l)?;
    let n = c.decrypt_len(&l)?;
    let mut body = vec![0u8; n + 16];
    io.read_exact(&mut body)?;
    c.decrypt_body(&body)
}

/// A fresh random secret key.
pub fn fresh_key() -> SecretKey {
    loop {
        let mut b = [0u8; 32];
        getrandom::getrandom(&mut b).expect("system randomness");
        if let Ok(k) = SecretKey::from_slice(&b) {
            return k;
        }
    }
}
