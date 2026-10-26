//! NIP-44 v2 against the spec's published test vectors: `vectors/nip44.vectors.json` is the file
//! NIP-44 names by its SHA-256 (checked here first), from the reference repository
//! (github.com/paulmillr/nip44), and the extended-length-prefix table printed in NIP-44 itself.
use secp256k1::{SecretKey, SECP256K1};
use serde_json::Value;
use sha2::{Digest, Sha256};
use xbt_nostr::nip44;

const VECTORS: &str = include_str!("vectors/nip44.vectors.json");
const VECTORS_SHA256: &str = "269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040";

fn v2() -> Value {
    assert_eq!(hex::encode(Sha256::digest(VECTORS.as_bytes())), VECTORS_SHA256, "the vectors file is the one NIP-44 names");
    serde_json::from_str::<Value>(VECTORS).unwrap()["v2"].clone()
}

fn h32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
}

fn xonly_hex(sec: &str) -> String {
    let sk = SecretKey::from_slice(&hex::decode(sec).unwrap()).unwrap();
    hex::encode(sk.x_only_public_key(SECP256K1).0.serialize())
}

#[test]
fn valid_conversation_keys() {
    let v = v2();
    let cases = v["valid"]["get_conversation_key"].as_array().unwrap();
    assert!(cases.len() > 30);
    for c in cases {
        let ck = nip44::conversation_key_hex(c["sec1"].as_str().unwrap(), c["pub2"].as_str().unwrap()).unwrap();
        assert_eq!(hex::encode(ck), c["conversation_key"].as_str().unwrap(), "{c}");
    }
}

#[test]
fn valid_message_keys() {
    let v = v2();
    let m = &v["valid"]["get_message_keys"];
    let ck = h32(&m["conversation_key"]);
    for k in m["keys"].as_array().unwrap() {
        let (key, nonce, hk) = nip44::message_keys(&ck, &h32(&k["nonce"]));
        assert_eq!(hex::encode(key), k["chacha_key"].as_str().unwrap());
        assert_eq!(hex::encode(nonce), k["chacha_nonce"].as_str().unwrap());
        assert_eq!(hex::encode(hk), k["hmac_key"].as_str().unwrap());
    }
}

#[test]
fn valid_padded_lengths() {
    for c in v2()["valid"]["calc_padded_len"].as_array().unwrap() {
        assert_eq!(nip44::padded_len(c[0].as_u64().unwrap() as usize) as u64, c[1].as_u64().unwrap(), "{c}");
    }
}

#[test]
fn valid_encrypt_decrypt() {
    for c in v2()["valid"]["encrypt_decrypt"].as_array().unwrap() {
        let (s1, s2) = (c["sec1"].as_str().unwrap(), c["sec2"].as_str().unwrap());
        let ck = nip44::conversation_key_hex(s1, &xonly_hex(s2)).unwrap();
        assert_eq!(hex::encode(ck), c["conversation_key"].as_str().unwrap());
        assert_eq!(nip44::conversation_key_hex(s2, &xonly_hex(s1)).unwrap(), ck, "the same both ways round");
        let p = nip44::encrypt_with_nonce(c["plaintext"].as_str().unwrap(), &ck, &h32(&c["nonce"])).unwrap();
        assert_eq!(p, c["payload"].as_str().unwrap());
        assert_eq!(nip44::decrypt(&p, &ck).unwrap(), c["plaintext"].as_str().unwrap());
    }
}

#[test]
fn valid_long_messages() {
    for c in v2()["valid"]["encrypt_decrypt_long_msg"].as_array().unwrap() {
        let plain = c["pattern"].as_str().unwrap().repeat(c["repeat"].as_u64().unwrap() as usize);
        assert_eq!(hex::encode(Sha256::digest(plain.as_bytes())), c["plaintext_sha256"].as_str().unwrap());
        let ck = h32(&c["conversation_key"]);
        let p = nip44::encrypt_with_nonce(&plain, &ck, &h32(&c["nonce"])).unwrap();
        assert_eq!(hex::encode(Sha256::digest(p.as_bytes())), c["payload_sha256"].as_str().unwrap());
        assert_eq!(nip44::decrypt(&p, &ck).unwrap(), plain);
    }
}

/// NIP-44's table of the u16 / extended prefix boundary.
#[test]
fn extended_prefix_boundary() {
    let ck = h32(&Value::from("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d"));
    let nonce = h32(&Value::from("0000000000000000000000000000000000000000000000000000000000000001"));
    for (len, padded, plain_sha, payload_sha) in [
        (65_535, 65_536, "6e1bebca6a8229364a162a72ef064826c4cd7457bf54f190ef782bd9deff3e42", "6d8c2810d1e870fbaa1f0a0937126cca837a15f9260e27060c331d70a3c0bc84"),
        (65_536, 65_536, "bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a", "b7b4edb36ba92e267d322d56d9aebc22e7fa96ff52e3c12adc07f07a43cbc616"),
        (65_537, 81_920, "008ffc88d3c96a9f307524eb361e47c5222a887fc45fa0c1fb8d429c5c23b430", "eeb7c7c5373894ea2c1547cfd3ccb15d5a0b2d619da852e5c79df792dcc9e435"),
    ] {
        let plain = "a".repeat(len);
        assert_eq!(nip44::padded_len(len), padded);
        assert_eq!(hex::encode(Sha256::digest(plain.as_bytes())), plain_sha);
        let p = nip44::encrypt_with_nonce(&plain, &ck, &nonce).unwrap();
        assert_eq!(hex::encode(Sha256::digest(p.as_bytes())), payload_sha, "{len}");
        assert_eq!(nip44::decrypt(&p, &ck).unwrap(), plain);
    }
}

#[test]
fn invalid_message_lengths() {
    // The vectors file lists 65536 and 100000 as invalid: it predates NIP-44's extended length prefix,
    // which makes them valid (see `extended_prefix_boundary`). 0 is invalid either way, and 10,000,000
    // is above this service's limit (nip44::MAX_PLAINTEXT), which the spec asks implementations to set.
    let ck = [1u8; 32];
    for n in v2()["invalid"]["encrypt_msg_lengths"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as usize) {
        let r = nip44::encrypt_with_nonce(&"a".repeat(n), &ck, &[2u8; 32]);
        if n == 0 || n > nip44::MAX_PLAINTEXT {
            assert_eq!(r, Err(nip44::Error::InvalidLength), "{n}");
        } else {
            assert!(r.is_ok(), "{n}: valid under the extended prefix");
        }
    }
}

#[test]
fn invalid_conversation_keys() {
    for c in v2()["invalid"]["get_conversation_key"].as_array().unwrap() {
        assert!(nip44::conversation_key_hex(c["sec1"].as_str().unwrap(), c["pub2"].as_str().unwrap()).is_err(), "{c}");
    }
}

#[test]
fn invalid_payloads() {
    let cases = v2()["invalid"]["decrypt"].as_array().unwrap().clone();
    assert_eq!(cases.len(), 12);
    for c in cases {
        let r = nip44::decrypt(c["payload"].as_str().unwrap(), &h32(&c["conversation_key"]));
        assert!(r.is_err(), "{}: decrypted to {r:?}", c["note"]);
        let note = c["note"].as_str().unwrap();
        match r.unwrap_err() {
            nip44::Error::InvalidMac => assert_eq!(note, "invalid MAC"),
            nip44::Error::InvalidPadding => assert_eq!(note, "invalid padding"),
            // an empty payload is "unknown version" in the spec's pseudocode, "length 0" in the file's note
            nip44::Error::UnknownVersion => assert!(note.starts_with("unknown encryption version") || c["payload"] == "", "{note}"),
            nip44::Error::InvalidPayload(_) => assert!(note.starts_with("invalid payload length") || note == "invalid base64", "{note}"),
            e => panic!("{note}: {e}"),
        }
    }
}
