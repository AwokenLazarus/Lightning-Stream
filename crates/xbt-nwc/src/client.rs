//! The app's side of NIP-47, as far as the tests (and a quick manual check) need it: read a
//! connection URI, make a signed and encrypted request, read the response.
use serde_json::{json, Value};

use crate::event::{parse_pubkey, tag, Event, Keys, KIND_REQUEST};
use crate::nip44;

#[derive(Debug, Clone)]
pub struct Uri {
    pub service_pubkey: String,
    pub relays: Vec<String>,
    pub secret: Keys,
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl Uri {
    /// `nostr+walletconnect://<service pubkey>?relay=...&secret=...`
    pub fn parse(uri: &str) -> Result<Self, String> {
        let rest = uri.strip_prefix("nostr+walletconnect://").ok_or("not a nostr+walletconnect:// URI")?;
        let (pk, q) = rest.split_once('?').ok_or("no query")?;
        parse_pubkey(pk).ok_or("bad service pubkey")?;
        let (mut relays, mut secret) = (vec![], None);
        for kv in q.split('&') {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            match k {
                "relay" => relays.push(pct_decode(v)),
                "secret" => secret = Keys::from_hex(v),
                _ => {}
            }
        }
        Ok(Self { service_pubkey: pk.to_ascii_lowercase(), relays, secret: secret.ok_or("bad or missing secret")? })
    }

    fn ck(&self) -> [u8; 32] {
        nip44::conversation_key(&self.secret.secret, &parse_pubkey(&self.service_pubkey).expect("checked in parse"))
    }

    /// A request event for `method` with `params`, created at `now`.
    pub fn request(&self, method: &str, params: Value, now: u64) -> Event {
        let content = nip44::encrypt(&json!({"method": method, "params": params}).to_string(), &self.ck()).expect("a small request");
        Event::sign(&self.secret, now, KIND_REQUEST, vec![tag("p", &self.service_pubkey), tag("encryption", "nip44_v2")], content)
    }

    /// A response's decrypted body, checked to be from the service, to us, and for `request_id`.
    pub fn read_response(&self, ev: &Event, request_id: &str) -> Result<Value, String> {
        if !ev.verify() || ev.pubkey != self.service_pubkey {
            return Err("not signed by the wallet service".into());
        }
        if ev.tag("p") != Some(self.secret.public_hex().as_str()) || ev.tag("e") != Some(request_id) {
            return Err("not a response to that request".into());
        }
        let t = nip44::decrypt(&ev.content, &self.ck()).map_err(|e| e.to_string())?;
        serde_json::from_str(&t).map_err(|e| e.to_string())
    }
}
