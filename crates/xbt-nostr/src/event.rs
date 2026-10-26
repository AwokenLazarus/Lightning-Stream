//! Nostr events (NIP-01): the id is SHA-256 of `[0, pubkey, created_at, kind, tags, content]`
//! serialised as compact JSON, signed with a BIP-340 Schnorr signature over secp256k1.
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Message, SecretKey, XOnlyPublicKey, SECP256K1};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// NIP-47 kinds.
pub const KIND_INFO: u64 = 13194;
pub const KIND_REQUEST: u64 = 23194;
pub const KIND_RESPONSE: u64 = 23195;

/// The largest event this service accepts from a relay (its content is a NIP-44 payload of at most
/// [`crate::nip44::MAX_PLAINTEXT`] bytes).
pub const MAX_EVENT_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

/// A secp256k1 key pair, as Nostr uses it (the x-only public key, hex).
#[derive(Clone)]
pub struct Keys {
    pub secret: SecretKey,
    pub keypair: Keypair,
    pub public: XOnlyPublicKey,
}

impl std::fmt::Debug for Keys {
    // never the secret
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Keys({})", self.public_hex())
    }
}

impl Keys {
    pub fn new(secret: SecretKey) -> Self {
        let keypair = Keypair::from_secret_key(SECP256K1, &secret);
        let (public, _) = keypair.x_only_public_key();
        Self { secret, keypair, public }
    }

    /// A fresh key from the OS's random source.
    pub fn generate() -> Self {
        loop {
            let mut b = [0u8; 32];
            getrandom::getrandom(&mut b).expect("OS randomness");
            if let Ok(sk) = SecretKey::from_slice(&b) {
                return Self::new(sk);
            }
        }
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        let b = hex::decode(s.trim()).ok()?;
        SecretKey::from_slice(&b).ok().map(Self::new)
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public.serialize())
    }

    /// The secret key, hex. Only for the state file and the connection URI shown once.
    pub fn secret_hex(&self) -> String {
        hex::encode(self.secret.secret_bytes())
    }
}

pub fn parse_pubkey(s: &str) -> Option<XOnlyPublicKey> {
    let b = hex::decode(s).ok()?;
    XOnlyPublicKey::from_slice(&b).ok()
}

fn id_of(pubkey: &str, created_at: u64, kind: u64, tags: &[Vec<String>], content: &str) -> [u8; 32] {
    let ser = serde_json::to_string(&json!([0, pubkey, created_at, kind, tags, content])).expect("JSON");
    Sha256::digest(ser.as_bytes()).into()
}

impl Event {
    /// A new event signed by `keys`.
    pub fn sign(keys: &Keys, created_at: u64, kind: u64, tags: Vec<Vec<String>>, content: String) -> Self {
        let pubkey = keys.public_hex();
        let id = id_of(&pubkey, created_at, kind, &tags, &content);
        let mut aux = [0u8; 32];
        getrandom::getrandom(&mut aux).expect("OS randomness");
        let sig = SECP256K1.sign_schnorr_with_aux_rand(&Message::from_digest(id), &keys.keypair, &aux);
        Self { id: hex::encode(id), pubkey, created_at, kind, tags, content, sig: hex::encode(sig.serialize()) }
    }

    /// The id matches the fields and the signature is the pubkey's.
    pub fn verify(&self) -> bool {
        let Some(pk) = parse_pubkey(&self.pubkey) else { return false };
        if self.pubkey != self.pubkey.to_ascii_lowercase() {
            return false;
        }
        let id = id_of(&self.pubkey, self.created_at, self.kind, &self.tags, &self.content);
        if hex::encode(id) != self.id {
            return false;
        }
        let Some(sig) = hex::decode(&self.sig).ok().and_then(|b| Signature::from_slice(&b).ok()) else { return false };
        SECP256K1.verify_schnorr(&sig, &Message::from_digest(id), &pk).is_ok()
    }

    /// The first value of the first tag named `name`.
    pub fn tag(&self, name: &str) -> Option<&str> {
        self.tags.iter().find(|t| t.first().map(String::as_str) == Some(name)).and_then(|t| t.get(1)).map(String::as_str)
    }

    pub fn to_value(&self) -> Value {
        json!({"id": self.id, "pubkey": self.pubkey, "created_at": self.created_at, "kind": self.kind, "tags": self.tags,
               "content": self.content, "sig": self.sig})
    }

    /// An event as a relay sends it; `None` for anything malformed (the signature is checked by [`Self::verify`]).
    pub fn from_value(v: &Value) -> Option<Self> {
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        let tags = v.get("tags")?.as_array()?.iter().map(|t| {
            t.as_array().and_then(|a| a.iter().map(|x| x.as_str().map(str::to_string)).collect::<Option<Vec<_>>>())
        }).collect::<Option<Vec<_>>>()?;
        Some(Self { id: s("id")?, pubkey: s("pubkey")?, created_at: v.get("created_at")?.as_u64()?, kind: v.get("kind")?.as_u64()?, tags,
                    content: s("content")?, sig: s("sig")? })
    }
}

pub fn tag(name: &str, value: &str) -> Vec<String> {
    vec![name.to_string(), value.to_string()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_tamper() {
        let k = Keys::generate();
        let e = Event::sign(&k, 1_700_000_000, KIND_REQUEST, vec![tag("p", &"ab".repeat(32))], "x\n\"y\"\u{1}é".into());
        assert!(e.verify());
        let back = Event::from_value(&e.to_value()).unwrap();
        assert_eq!(back, e);
        let mut bad = e.clone();
        bad.content.push('!');
        assert!(!bad.verify());
        let mut bad = e.clone();
        bad.pubkey = Keys::generate().public_hex();
        assert!(!bad.verify());
        assert_eq!(e.tag("p"), Some("ab".repeat(32).as_str()));
    }

    /// NIP-01's serialisation: the escapes JSON requires, nothing else (non-ASCII stays UTF-8).
    #[test]
    fn id_serialisation() {
        let ser = serde_json::to_string(&json!([0, "pk", 1, 1, [["a", "b"]], "line\nquote\"tab\tbs\\é/"])).unwrap();
        assert_eq!(ser, "[0,\"pk\",1,1,[[\"a\",\"b\"]],\"line\\nquote\\\"tab\\tbs\\\\é/\"]");
    }
}
