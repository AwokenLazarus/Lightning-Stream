//! Simple mode's approvals: an approval key kept by the signer and used only with the owner's PIN.
//!
//! The human's approval key used to live in one browser only, under a long passphrase, with a backup
//! file. For people who should not have to manage a key, the signer can hold one instead: an ed25519
//! key made here, sealed with the signer's wrapping key ([`KeyStore`]) like the hot key, and enrolled
//! as the human key (the policy's `human_pubkey`) the usual way: with the one-time enrolment code when
//! no human key is enrolled yet, or with one signature by the current key (the human-key handover
//! message) when one is. Every operation still checks the same signed messages: `approve_with_pin`
//! signs one of those messages, and the caller then sends the signature to the operation's own method.
//!
//! What protects it:
//! * the PIN is kept only as a scrypt hash (N = 2^15, r = 8, p = 1, a 16-byte salt), compared in
//!   constant time;
//! * wrong PINs are counted in a file under `.run`, so a restart does not reset them: 5 wrong in a row
//!   lock approvals for 10 minutes, 10 for an hour, 15 for a day, and 20 until the PIN is reset. A right
//!   PIN clears the count. At most 20 of the 10,000 four-digit PINs can be tried before a reset;
//! * the socket is shared with the model-facing process, so the PIN alone is not enough: a PIN call also
//!   carries the *gate*, a random token the signer writes beside the enrolment code's copy for the UI
//!   (`B2_ENROLL_CODE_COPY`'s directory, readable by the signer's and the UI's group only). A process
//!   that cannot read that file cannot try PINs at all;
//! * only messages under the approval domains are signed ([`approvable`]); nothing else.
//!
//! A forgotten PIN is reset on the box itself ([`reset_offline`], `xbt-signer pin-reset`): it removes the
//! box key and the human key from the policy, so the signer issues a new enrolment code at its next start
//! and the owner sets a new PIN with it.
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{json, Value};

use crate::approval::{BACKUP_DOMAIN, DENY_DOMAIN, DOMAIN, HUMAN_KEY_DOMAIN, POLICY_DOMAIN, RECOVER_DOMAIN, ROTATE_DOMAIN, SWEEP_DOMAIN,
                      UNBLOCK_DOMAIN, human_key_message, x2b};
use crate::keystore::{random_bytes, write_private, KeyStore};
use crate::pyjson::{dumps_indent, py_int, str_or_empty, ts_value};
use crate::signer::{deny, Signer};
use crate::{err, Result};

/// The box key and the PIN's hash, under `.run`.
pub const PIN_FILE: &str = "pin-approver.json";
/// A box key made for a handover that has not been signed yet.
pub const PIN_PENDING_FILE: &str = "pin-approver-pending.json";
/// The wrong PINs in a row and the lock they set.
pub const PIN_TRIES_FILE: &str = "pin-tries.json";
/// The gate's file name, beside the enrolment code's copy for the UI.
pub const PIN_GATE_FILE: &str = "pin-gate";
const SEAL_AAD: &str = "xbt-signer/pin-approver/v1";
const SCRYPT_LOG_N: u8 = 15;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

/// Every domain a human-approved message starts with: only these are signed with the box key.
pub const APPROVABLE: [&[u8]; 9] = [DOMAIN, RECOVER_DOMAIN, SWEEP_DOMAIN, POLICY_DOMAIN, HUMAN_KEY_DOMAIN, ROTATE_DOMAIN, BACKUP_DOMAIN,
                                    DENY_DOMAIN, UNBLOCK_DOMAIN];

/// `msg` is one of the human-approved messages: an approval domain, then a newline.
pub fn approvable(msg: &[u8]) -> bool {
    APPROVABLE.iter().any(|d| msg.len() > d.len() && msg.starts_with(d) && msg[d.len()] == b'\n')
}

/// 4 to 8 digits.
pub fn valid_pin(pin: &str) -> bool {
    (4..=8).contains(&pin.len()) && pin.bytes().all(|b| b.is_ascii_digit())
}

/// How long approvals stay locked after `failures` wrong PINs in a row; `None`: not locked.
/// `Some(i64::MAX)`: until the PIN is reset.
pub fn lock_secs(failures: u32) -> Option<i64> {
    match failures {
        0..=4 => None,
        5..=9 => Some(600),
        10..=14 => Some(3600),
        15..=19 => Some(86_400),
        _ => Some(i64::MAX),
    }
}

fn hash_pin(pin: &str, salt: &[u8], log_n: u8) -> Result<[u8; 32]> {
    let params = scrypt::Params::new(log_n, SCRYPT_R, SCRYPT_P, 32).map_err(|e| err("pin", e.to_string()))?;
    let mut out = [0u8; 32];
    scrypt::scrypt(pin.as_bytes(), salt, &params, &mut out).map_err(|e| err("pin", e.to_string()))?;
    Ok(out)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The gate's path: beside the enrolment code's copy for the UI. None: no copy configured (a test or a
/// development signer), and PIN calls need no gate.
pub fn gate_path() -> Option<PathBuf> {
    let copy = std::env::var(crate::admin::ENROLL_CODE_COPY_ENV).ok().filter(|p| !p.trim().is_empty())?;
    Some(Path::new(&copy).parent().unwrap_or(Path::new(".")).join(PIN_GATE_FILE))
}

/// The box key's seed, sealed (or, where plaintext keys are allowed, as hex).
fn seal_seed(ks: Option<&KeyStore>, seed: &[u8; 32]) -> Result<Value> {
    match ks {
        Some(k) => k.seal(seed, SEAL_AAD, None),
        None if KeyStore::plaintext_allowed() => Ok(json!({"plaintext_hex": hex::encode(seed)})),
        None => Err(err("keystore", "the box approval key must be encrypted at rest: the signer has no wrapping key")),
    }
}

fn open_seed(ks: Option<&KeyStore>, blob: &Value) -> Result<SigningKey> {
    let bytes: Vec<u8> = match (ks, blob.get("plaintext_hex").and_then(Value::as_str)) {
        (_, Some(h)) if KeyStore::plaintext_allowed() => hex::decode(h).map_err(|_| err("pin", "the box key file is damaged"))?,
        (Some(k), _) => k.open(blob, SEAL_AAD)?.to_vec(),
        _ => return Err(err("keystore", "the box approval key is sealed and this signer has no wrapping key")),
    };
    let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| err("pin", "the box key file is damaged"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn read_json(path: &Path) -> Result<Option<Value>> {
    match std::fs::read_to_string(path) {
        Ok(t) => serde_json::from_str(&t).map(Some).map_err(|_| err("pin", format!("{}: unreadable", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(err("io", format!("{}: {e}", path.display()))),
    }
}

fn write_json(path: &Path, v: &Value) -> Result<()> {
    write_private(path, &dumps_indent(v, 2, true))
}

/// The wrong PINs in a row and until when approvals are locked (a missing file: none).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Tries {
    pub failures: u32,
    pub locked_until: i64,
}

impl Tries {
    fn load(path: &Path) -> Result<Self> {
        // an unreadable file locks: it is never taken for a clean count
        Ok(match read_json(path) {
            Ok(Some(v)) => Tries { failures: py_int(v.get("failures")).unwrap_or(0).clamp(0, u32::MAX as i64) as u32,
                                   locked_until: py_int(v.get("locked_until")).unwrap_or(0) },
            Ok(None) => Tries::default(),
            Err(_) => Tries { failures: 20, locked_until: i64::MAX },
        })
    }

    fn save(&self, path: &Path) -> Result<()> {
        write_json(path, &json!({"failures": self.failures, "locked_until": self.locked_until}))
    }

    /// One more wrong PIN at `now`.
    pub fn failed(self, now: i64) -> Self {
        let failures = self.failures.saturating_add(1);
        let locked_until = match lock_secs(failures) {
            // a lock starts only on the try that reaches its step (5, 10, 15, 20)
            Some(s) if failures.is_multiple_of(5) => now.saturating_add(s),
            _ => self.locked_until,
        };
        Tries { failures, locked_until }
    }

    pub fn locked(&self, now: i64) -> bool {
        self.locked_until > now
    }
}

impl Signer {
    fn pin_paths(&self) -> (PathBuf, PathBuf, PathBuf) {
        (self.run.join(PIN_FILE), self.run.join(PIN_PENDING_FILE), self.run.join(PIN_TRIES_FILE))
    }

    fn pin_now(&self) -> i64 {
        self.engine.now() as i64
    }

    /// At start: a fresh gate for this run, where the UI reads it. Nothing when no copy is configured.
    pub(crate) fn issue_pin_gate(&self) {
        if let Some(path) = gate_path() {
            let token = hex::encode(random_bytes::<32>());
            if let Err(e) = crate::admin::write_group_copy(&path, &format!("{token}\n")) {
                eprintln!("xbt-signer: the PIN gate for the UI was not written ({e}): approvals with a PIN are off");
                return;
            }
            *self.pin_gate.lock().unwrap_or_else(|p| p.into_inner()) = token;
        }
    }

    /// `None` when the call may try a PIN; else the deny.
    fn pin_gate_ok(&self, p: &Value) -> Option<Value> {
        gate_path()?;
        let want = self.pin_gate.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let given = str_or_empty(p.get("gate"));
        if want.is_empty() || !ct_eq(given.trim().as_bytes(), want.as_bytes()) {
            return Some(deny("pin_gate", "PIN approvals are answered only for the app's own web page"));
        }
        None
    }

    fn pin_doc(&self) -> Result<Option<Value>> {
        read_json(&self.pin_paths().0)
    }

    fn box_pub_hex(doc: &Value) -> String {
        str_or_empty(doc.get("pubkey"))
    }

    pub(crate) fn pin_dispatch(&self, method: &str, p: &Value) -> Option<Result<Value>> {
        Some(match method {
            "pin_status" => self.pin_status(),
            "pin_prepare" => self.pin_prepare(p),
            "pin_set" => self.pin_set(p),
            "pin_change" => self.pin_change(p),
            "approve_with_pin" => self.approve_with_pin(p),
            _ => return None,
        })
    }

    fn pin_status(&self) -> Result<Value> {
        let doc = self.pin_doc()?;
        let tries = Tries::load(&self.pin_paths().2)?;
        let human = hex::encode(self.human_key());
        let pubkey = doc.as_ref().map(Self::box_pub_hex).unwrap_or_default();
        let now = self.pin_now();
        Ok(json!({"ok": true, "set": doc.is_some(), "pubkey": pubkey, "enrolled": !pubkey.is_empty() && pubkey == human,
                  "human_key": !human.is_empty(), "failures": tries.failures,
                  "locked_until": if tries.locked(now) { json!(tries.locked_until) } else { Value::Null },
                  "reset_needed": tries.locked_until == i64::MAX}))
    }

    /// The box key a handover will enrol, made once and kept aside until [`Self::pin_set`]: its public key
    /// is what the current key signs over (the human-key handover message).
    fn pin_prepare(&self, p: &Value) -> Result<Value> {
        if let Some(d) = self.pin_gate_ok(p) {
            return Ok(d);
        }
        let _g = self.lock();
        if self.pin_doc()?.is_some() {
            return Ok(deny("pin", "a PIN is already set: change it with the current PIN"));
        }
        let pending = self.pin_paths().1;
        let pubkey = match read_json(&pending)? {
            Some(d) => Self::box_pub_hex(&d),
            None => {
                let seed = random_bytes::<32>();
                let pk = hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
                write_json(&pending, &json!({"pubkey": pk, "seed": seal_seed(self.keystore.as_deref(), &seed)?}))?;
                pk
            }
        };
        let human = hex::encode(self.human_key());
        Ok(json!({"ok": true, "pubkey": pubkey, "old_pub": human, "needs": if human.is_empty() { "code" } else { "signature" }}))
    }

    /// Set the PIN and enrol the box key: with the enrolment `code` when no human key is enrolled, else with
    /// `expiry` and `signature`, the current key's handover to the box key.
    fn pin_set(&self, p: &Value) -> Result<Value> {
        if let Some(d) = self.pin_gate_ok(p) {
            return Ok(d);
        }
        let pin = str_or_empty(p.get("pin"));
        if !valid_pin(&pin) {
            return Ok(deny("pin", "the PIN must be 4 to 8 digits"));
        }
        let _g = self.lock();
        if self.pin_doc()?.is_some() {
            return Ok(deny("pin", "a PIN is already set: change it with the current PIN"));
        }
        let (file, pending, tries) = self.pin_paths();
        let Some(pend) = read_json(&pending)? else { return Ok(deny("pin", "no box key is prepared: call pin_prepare first")) };
        let new = Self::box_pub_hex(&pend);
        let old = hex::encode(self.human_key());
        if old.is_empty() {
            if let Some(d) = self.take_enroll_code(&str_or_empty(p.get("code")))? {
                return Ok(d);
            }
        } else {
            let expiry = py_int(p.get("expiry")).unwrap_or(0);
            if let Some(d) = self.check_sig(&human_key_message(&old, &new, expiry), p, expiry) {
                return Ok(d);
            }
        }
        let salt = random_bytes::<16>();
        let hash = hash_pin(&pin, &salt, SCRYPT_LOG_N)?;
        write_json(&file, &json!({"v": 1, "pubkey": new, "seed": pend["seed"].clone(),
                                  "pin": {"kdf": "scrypt", "log_n": SCRYPT_LOG_N, "r": SCRYPT_R, "p": SCRYPT_P,
                                          "salt": hex::encode(salt), "hash": hex::encode(hash)}}))?;
        let _ = std::fs::remove_file(&pending);
        Tries::default().save(&tries)?;
        let sha = self.set_human_pubkey_in_policy(&new)?;
        self.engine.audit.append(json!({"type": "pin_set", "human_pubkey": new, "old": old, "ts": ts_value(self.engine.now())}));
        Ok(json!({"ok": true, "human_pubkey": new, "policy_sha256": sha}))
    }

    /// The PIN checked against the lock and the hash; a wrong one is counted. `Ok(Ok(key))` with the right
    /// PIN; `Ok(Err(deny))` otherwise.
    fn pin_check(&self, pin: &str) -> Result<std::result::Result<SigningKey, Value>> {
        let (file, _, tries_path) = self.pin_paths();
        let Some(doc) = read_json(&file)? else { return Ok(Err(deny("pin", "no PIN is set"))) };
        let now = self.pin_now();
        let tries = Tries::load(&tries_path)?;
        if tries.locked(now) {
            return Ok(Err(if tries.locked_until == i64::MAX {
                deny("pin_locked", "too many wrong PINs: reset the PIN from the box's own page")
            } else {
                deny("pin_locked", format!("too many wrong PINs: try again in {} minutes", (tries.locked_until - now + 59) / 60))
            }));
        }
        let ph = &doc["pin"];
        let salt = x2b(&str_or_empty(ph.get("salt"))).unwrap_or_default();
        let want = x2b(&str_or_empty(ph.get("hash"))).unwrap_or_default();
        let log_n = py_int(ph.get("log_n")).unwrap_or(SCRYPT_LOG_N as i64).clamp(10, 20) as u8;
        let right = valid_pin(pin) && !salt.is_empty() && ct_eq(&hash_pin(pin, &salt, log_n)?, &want);
        if !right {
            let t = tries.failed(now);
            t.save(&tries_path)?;
            self.engine.audit.append(json!({"type": "pin_wrong", "failures": t.failures, "ts": ts_value(self.engine.now())}));
            let left = 5 - (t.failures % 5);
            return Ok(Err(if t.locked(now) {
                deny("pin_locked", if t.locked_until == i64::MAX { "too many wrong PINs: reset the PIN from the box's own page".to_string() }
                                   else { format!("too many wrong PINs: approvals are locked for {} minutes", (t.locked_until - now + 59) / 60) })
            } else {
                deny("pin_wrong", format!("wrong PIN ({left} {} before approvals lock)", if left == 1 { "try" } else { "tries" }))
            }));
        }
        if tries.failures > 0 {
            Tries::default().save(&tries_path)?;
        }
        Ok(Ok(open_seed(self.keystore.as_deref(), &doc["seed"])?))
    }

    /// Sign `message` (hex) with the box key, given the right PIN: only an approval-domain message, and only
    /// while the box key is the enrolled human key.
    fn approve_with_pin(&self, p: &Value) -> Result<Value> {
        if let Some(d) = self.pin_gate_ok(p) {
            return Ok(d);
        }
        let Some(msg) = x2b(&str_or_empty(p.get("message"))) else { return Ok(deny("pin", "message must be hex")) };
        if !approvable(&msg) {
            return Ok(deny("pin", "only an approval message is signed with the PIN"));
        }
        let _g = self.lock();
        let doc = self.pin_doc()?;
        let enrolled = doc.as_ref().is_some_and(|d| Self::box_pub_hex(d) == hex::encode(self.human_key()));
        if !enrolled {
            return Ok(deny("pin", "the PIN's key is not the enrolled approval key"));
        }
        let key = match self.pin_check(&str_or_empty(p.get("pin")))? {
            Ok(k) => k,
            Err(d) => return Ok(d),
        };
        let sig = key.sign(&msg).to_bytes();
        Ok(json!({"ok": true, "signature": hex::encode(sig)}))
    }

    /// A new PIN for the same box key, given the current one (a wrong one counts as a wrong try).
    fn pin_change(&self, p: &Value) -> Result<Value> {
        if let Some(d) = self.pin_gate_ok(p) {
            return Ok(d);
        }
        let new_pin = str_or_empty(p.get("new_pin"));
        if !valid_pin(&new_pin) {
            return Ok(deny("pin", "the new PIN must be 4 to 8 digits"));
        }
        let _g = self.lock();
        if let Err(d) = self.pin_check(&str_or_empty(p.get("pin")))? {
            return Ok(d);
        }
        let file = self.pin_paths().0;
        let Some(mut doc) = read_json(&file)? else { return Ok(deny("pin", "no PIN is set")) };
        let salt = random_bytes::<16>();
        doc["pin"] = json!({"kdf": "scrypt", "log_n": SCRYPT_LOG_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": hex::encode(salt),
                            "hash": hex::encode(hash_pin(&new_pin, &salt, SCRYPT_LOG_N)?)});
        write_json(&file, &doc)?;
        self.engine.audit.append(json!({"type": "pin_changed", "ts": ts_value(self.engine.now())}));
        Ok(json!({"ok": true}))
    }
}

/// `xbt-signer pin-reset`, on the box with the signer stopped: remove the box key, the PIN and its tries,
/// and the human key from the policy (it was the box key), so the next start issues an enrolment code and a
/// new PIN can be set with it. A browser key enrolled instead of a PIN is left as it is. Returns what it did.
pub fn reset_offline(root: &Path, run: &Path) -> Result<String> {
    let file = run.join(PIN_FILE);
    let doc = read_json(&file)?;
    let policy_path = root.join("policy.json");
    let mut raw: Value = serde_json::from_str(&std::fs::read_to_string(&policy_path).map_err(|e| err("io", format!("policy.json: {e}")))?)
        .map_err(|e| err("policy", format!("policy.json: {e}")))?;
    let human = str_or_empty(raw.get("human_pubkey")).trim().to_lowercase();
    let boxed = doc.as_ref().map(Signer::box_pub_hex).unwrap_or_default();
    let mut did = vec![];
    if !boxed.is_empty() && human == boxed {
        raw["human_pubkey"] = "".into();
        let text = crate::admin::canonical_policy(&raw);
        if policy_path.exists() {
            let _ = std::fs::copy(&policy_path, policy_path.with_extension("json.prev"));
        }
        write_private(&policy_path, &text)?;
        did.push("the PIN's key is no longer the approval key");
    } else if !human.is_empty() {
        did.push("a key other than the PIN's is enrolled: it is kept");
    }
    for f in [PIN_FILE, PIN_PENDING_FILE, PIN_TRIES_FILE] {
        match std::fs::remove_file(run.join(f)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(err("io", format!("{f}: {e}"))),
        }
    }
    did.push("the PIN and its wrong tries are removed");
    Ok(format!("{}. Start the app again: it shows a new enrolment code, and the setup page sets a new PIN with it.", did.join("; ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_approval_messages_are_signed() {
        assert!(approvable(&crate::approval::policy_message("ab", 9, "{}")));
        assert!(approvable(&crate::approval::canonical_message("t", "d", 5, 9)));
        assert!(!approvable(b"xbt-agentwallet-policy-v1"), "a bare domain is no message");
        assert!(!approvable(b"xbt-agentwallet-policy-v1x\n"), "a longer domain is another domain");
        assert!(!approvable(b"anything else\n"));
    }

    #[test]
    fn pins_are_digits() {
        assert!(valid_pin("0042") && valid_pin("12345678"));
        assert!(!valid_pin("123") && !valid_pin("123456789") && !valid_pin("12a4") && !valid_pin(""));
    }

    #[test]
    fn wrong_pins_lock_in_steps_and_twenty_need_a_reset() {
        let mut t = Tries::default();
        for _ in 0..4 {
            t = t.failed(1000);
        }
        assert!(!t.locked(1000));
        t = t.failed(1000);
        assert_eq!(t.locked_until, 1600, "the 5th wrong PIN locks 10 minutes");
        assert!(t.locked(1599) && !t.locked(1600));
        for _ in 0..5 {
            t = t.failed(2000);
        }
        assert_eq!((t.failures, t.locked_until), (10, 2000 + 3600));
        for _ in 0..5 {
            t = t.failed(9000);
        }
        assert_eq!(t.locked_until, 9000 + 86_400);
        for _ in 0..5 {
            t = t.failed(200_000);
        }
        assert_eq!(t.locked_until, i64::MAX, "20 wrong in a row: locked until a reset");
    }

    #[test]
    fn the_seed_is_sealed_under_the_wrapping_key() {
        let ks = KeyStore::with_key([9u8; 32]);
        let seed = [5u8; 32];
        let blob = seal_seed(Some(&ks), &seed).unwrap();
        assert!(!blob.to_string().contains(&hex::encode(seed)));
        assert_eq!(open_seed(Some(&ks), &blob).unwrap().to_bytes(), seed);
        assert!(open_seed(Some(&KeyStore::with_key([8u8; 32])), &blob).is_err(), "another wrapping key opens nothing");
    }

    #[test]
    fn the_hash_is_salted_and_slow_enough() {
        let a = hash_pin("1234", b"salt-one-16bytes", 10).unwrap();
        let b = hash_pin("1234", b"salt-two-16bytes", 10).unwrap();
        assert_ne!(a, b);
        assert_eq!(a, hash_pin("1234", b"salt-one-16bytes", 10).unwrap());
    }
}
