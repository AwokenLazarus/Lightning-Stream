//! Payer keys outside the client: the [`StateSigner`] seam (AGP-027).
//!
//! A port of B1's `ChannelSigner` interface (`xbt402/signer.py`), which B2's agent wallet serves
//! over its signer socket. With a signer, [`Client`](crate::client::Client) never sees a
//! per-channel payer secret: it asks for a fresh key, attaches the funded channel's params,
//! and asks the signer for every state, close, refund and request authentication. The signer
//! can apply its own policy on every call (B2 does: budgets, allowlist, the human threshold).
//!
//! [`LocalSigner`] is the in-process implementation (keys in memory, no policy), for tests and
//! for callers that do not run a separate signer process. `xbt-signer` provides the B2 signer
//! (a Unix-socket process with sealed keys and the policy engine) and a socket client that
//! implements this trait.
//!
//! Routed payments (AGP-026) add [`RouteSigner`], an extension of the same seam with B1's adaptor
//! lock methods (`sign_state_adaptor`, `resolve_lock`, `void_lock`, `adopt_lock`, `recover_lock`),
//! which B2's signer socket serves as `xbt402_*`. [`crate::route_client::RoutePayer`] runs over it,
//! and funds its channel through a [`crate::client::Wallet`] (funding is the wallet's job, not the
//! signer's). Lock rules are B1's: one pending lock per channel; the lock `(cum, pre, r, T, T1)` is
//! recorded before the pre-signature leaves; `resolve_lock` takes t + r (from the hub) or t (the
//! provider's receipt); a given-up lock can be adopted later only by its own cum.
use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::Value;
use xbt_primitives::ecdsa::{self, PubkeyBytes};
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::sighash::{SIGHASH_ALL_UNIFIED, SIGHASH_SINGLE_ACP_UNIFIED};
use xbt_primitives::tx::Tx;

use crate::adaptor::{self, PreSig, Sc};

use crate::channel::{channel_auth_key, sign_with_type, ChannelParams};
use crate::conditional::ConditionalParams;
use crate::error::{fail, ChannelError, Result};
use crate::wire::{close_message, request_auth};

/// Everything a payer needs signed, keyed by channel id (`txid:vout`). Signatures are
/// `DER || hash_type` as the wire carries them; `sign_close` is plain DER.
pub trait StateSigner: Send + Sync {
    /// A payer key for a channel to `origin` (33-byte compressed pubkey).
    ///
    /// The rule for issued keys (AGP-089 in `xbt-signer`, AGP-096 here): **a key a signer issued
    /// is never replaced or dropped.** Asking again answers the key already issued for `origin`
    /// while no channel is bound to it: the caller may be retrying an open whose funding failed,
    /// or a rollover whose answer was lost, and coins may already pay the first answer.
    fn new_key(&self, origin: &str) -> Result<PubkeyBytes>;
    /// Bind the key issued for `origin` to the funded channel. Returns the channel id.
    ///
    /// One key can be bound to more than one channel: every attempt to roll a channel over pays
    /// the same next key, and whichever attempt confirms is the one bound, also after another was
    /// bound on the provider's word (review C3). Binding the same channel again is not an error.
    fn attach(&self, origin: &str, params: &ChannelParams) -> Result<String>;
    /// Where the payer's change goes at close (`None`: P2WPKH of the channel key). B2 returns
    /// its hot key, so close change and refunds come back to the wallet.
    fn payer_spk(&self) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    /// The 0x21 state for cumulative `amount` (never lower than one already signed).
    fn sign_state(&self, chan: &str, amount: u64) -> Result<Vec<u8>>;
    /// The 0xA3 fee-input state.
    fn sign_state_a3(&self, chan: &str, amount: u64) -> Result<Vec<u8>>;
    /// The payer's 0x21 signature for a rollover tx.
    fn sign_rollover(&self, chan: &str, amount: u64, next_spk: &[u8], next_capacity: u64) -> Result<Vec<u8>>;
    /// [`StateSigner::sign_rollover`] with the next channel's unfunded params, so a signer can check
    /// the target is a channel of its own (AGP-063 W3). The default signs by script alone.
    fn sign_rollover_next(&self, chan: &str, amount: u64, next: &ChannelParams, next_capacity: u64) -> Result<Vec<u8>> {
        self.sign_rollover(chan, amount, &next.spk(), next_capacity)
    }
    /// The payer's close authorisation over `tagged_hash("xbt402/close", chan)` (DER).
    fn sign_close(&self, chan: &str) -> Result<Vec<u8>>;
    /// The signed CLTV refund tx (hex).
    fn sign_refund(&self, chan: &str) -> Result<String>;
    /// `payload.auth` for one paid request; the ECDH channel key never leaves the signer.
    fn request_auth(&self, chan: &str, seq: Option<&Value>, cum: Option<&Value>, sig: Option<&str>, req: &str) -> Result<String>;
    /// The 0x21 hash-locked state paying `uncond` plus the conditional amount.
    fn sign_conditional(&self, chan: &str, uncond: u64, cond: &ConditionalParams) -> Result<Vec<u8>>;
}

/// What [`RouteSigner::sign_state_adaptor`] returns (B1's dict, typed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptorLock {
    /// The pre-signature of state(cum) under T1.
    pub pre: PreSig,
    /// T1 = T + r·G (compressed).
    pub point: PubkeyBytes,
    /// r, the payer's fresh tweak (the hub learns it with the lock).
    pub tweak: [u8; 32],
    pub cum: u64,
}

/// A pending (or given-up) adaptor lock: `{cum, pre, r, T, T1, route}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingLock {
    pub cum: u64,
    pub pre: PreSig,
    pub r: [u8; 32],
    /// T, the provider's invoice point.
    pub t: PubkeyBytes,
    /// T1 = T + r·G.
    pub t1: PubkeyBytes,
    pub route: Value,
}

/// The routed-payment extension of [`StateSigner`]: adaptor-locked states through a hub (AGP-026).
/// Secrets and points are typed; `route` is the lock's context (`hub`, `provider`, `lockId`,
/// `amount`, `fee`) that a policy-checking signer (B2, `xbt-signer`) enforces its routing policy on.
pub trait RouteSigner: StateSigner {
    /// Pre-sign state(cum) under T1 = T + r·G (`point` = T; r is fresh here). Raises the signed
    /// amount only when resolved or adopted.
    fn sign_state_adaptor(&self, chan: &str, cum: u64, point: &PubkeyBytes, route: &Value) -> Result<AdaptorLock>;
    /// The lock was paid: `secret` is t + r (the hub) or t (the provider). Returns t.
    fn resolve_lock(&self, chan: &str, secret: &[u8; 32]) -> Result<[u8; 32]>;
    /// Give the pending lock up (the hub refused it, or its invoice expired). `true` if one was pending.
    fn void_lock(&self, chan: &str) -> Result<bool>;
    /// A lock this signer gave up was completed after all (the hub read t off a close).
    fn adopt_lock(&self, chan: &str, cum: u64) -> Result<()>;
    /// t from the hub's ch1 close, which carries the completed pre-signature (t + r).
    fn recover_lock(&self, chan: &str, close_tx: &Tx) -> Result<[u8; 32]>;
}

struct LocalChannel {
    secret: SecretKey,
    params: ChannelParams,
    signed: u64,
    lock: Option<PendingLock>,
    given_up: Vec<PendingLock>,
}

/// In-memory [`StateSigner`] (B1 `ChannelSigner` without a policy hook).
///
/// It keeps every key it issued, by public key, for as long as it lives (AGP-096): `attach` used
/// to take the key out of its origin's slot and `new_key` to overwrite it, so the next channel of
/// a rollover that confirmed after another attempt had been bound, and the script of an open that
/// was derived again, had no key here. One key (32 bytes) is kept per channel opened or rolled
/// over, as one [`LocalChannel`] already is.
#[derive(Default)]
pub struct LocalSigner {
    /// origin -> the key issued for it that no channel is bound to yet.
    pending: Mutex<HashMap<String, PubkeyBytes>>,
    /// Every key issued: pubkey -> (the origin it was issued for, the secret).
    issued: Mutex<HashMap<PubkeyBytes, (String, SecretKey)>>,
    chans: Mutex<HashMap<String, LocalChannel>>,
}

/// A uniformly random valid secret key from the OS.
pub fn random_secret() -> SecretKey {
    loop {
        let mut b = [0u8; 32];
        getrandom::getrandom(&mut b).expect("OS randomness");
        if let Ok(sk) = SecretKey::from_slice(&b) {
            return sk;
        }
    }
}

impl LocalSigner {
    pub fn new() -> Self {
        Self::default()
    }

    fn with<T>(&self, chan: &str, f: impl FnOnce(&mut LocalChannel) -> Result<T>) -> Result<T> {
        let mut g = self.chans.lock().map_err(|_| ChannelError::code("poisoned"))?;
        let c = g.get_mut(chan).ok_or_else(|| ChannelError::new("unknown_channel", chan.to_string()))?;
        f(c)
    }

    /// The highest amount signed on `chan` (0 if unknown).
    pub fn signed(&self, chan: &str) -> u64 {
        self.with(chan, |c| Ok(c.signed)).unwrap_or(0)
    }

    /// The pending lock on `chan`, if any.
    pub fn pending_lock(&self, chan: &str) -> Option<PendingLock> {
        self.with(chan, |c| Ok(c.lock.clone())).ok().flatten()
    }
}

impl StateSigner for LocalSigner {
    fn new_key(&self, origin: &str) -> Result<PubkeyBytes> {
        let mut pending = self.pending.lock().map_err(poisoned)?;
        if let Some(pk) = pending.get(origin) {
            return Ok(*pk);
        }
        let sk = random_secret();
        let pk = ecdsa::pubkey(&sk);
        self.issued.lock().map_err(poisoned)?.insert(pk, (origin.to_string(), sk));
        pending.insert(origin.to_string(), pk);
        Ok(pk)
    }

    fn attach(&self, origin: &str, params: &ChannelParams) -> Result<String> {
        let mut pending = self.pending.lock().map_err(poisoned)?;
        let sk = match self.issued.lock().map_err(poisoned)?.get(&params.payer_pub) {
            Some((o, sk)) if o == origin => *sk,
            Some(_) => return fail("bad_key", "attached params pay a key issued for another origin"),
            None if pending.contains_key(origin) => return fail("bad_key", "attached params do not match the issued key"),
            None => return fail("bad_key", "call new_key before attach"),
        };
        let chan = params.channel_id();
        // a channel bound before keeps what was signed on it
        self.chans.lock().map_err(poisoned)?.entry(chan.clone())
            .or_insert_with(|| LocalChannel { secret: sk, params: params.clone(), signed: 0, lock: None, given_up: vec![] });
        if pending.get(origin) == Some(&params.payer_pub) {
            pending.remove(origin); // used: the next open or rollover of this origin gets a key of its own
        }
        Ok(chan)
    }

    fn sign_state(&self, chan: &str, amount: u64) -> Result<Vec<u8>> {
        self.with(chan, |c| {
            if amount < c.signed {
                return fail("stale_amount", "never sign a lower cumulative amount");
            }
            let tx = c.params.state_tx(amount)?;
            let sig = sign_with_type(&c.secret, &c.params.sighash(&tx)?, SIGHASH_ALL_UNIFIED);
            c.signed = amount;
            Ok(sig)
        })
    }

    fn sign_state_a3(&self, chan: &str, amount: u64) -> Result<Vec<u8>> {
        self.with(chan, |c| {
            if amount < c.signed {
                return fail("stale_amount", "never sign a lower cumulative amount");
            }
            let tx = c.params.state_tx_a3(amount)?;
            let sig = sign_with_type(&c.secret, &c.params.sighash_a3(&tx)?, SIGHASH_SINGLE_ACP_UNIFIED);
            c.signed = amount;
            Ok(sig)
        })
    }

    fn sign_rollover(&self, chan: &str, amount: u64, next_spk: &[u8], next_capacity: u64) -> Result<Vec<u8>> {
        self.with(chan, |c| {
            if amount < c.signed {
                return fail("stale_amount", "never sign a lower cumulative amount");
            }
            let tx = c.params.rollover_tx(amount, next_spk, next_capacity)?;
            let sig = sign_with_type(&c.secret, &c.params.sighash(&tx)?, SIGHASH_ALL_UNIFIED);
            c.signed = amount;
            Ok(sig)
        })
    }

    fn sign_close(&self, chan: &str) -> Result<Vec<u8>> {
        self.with(chan, |c| Ok(ecdsa::sign(&c.secret, &close_message(chan))))
    }

    fn sign_refund(&self, chan: &str) -> Result<String> {
        self.with(chan, |c| Ok(c.params.refund_tx(&c.secret, None, None)?.to_hex()))
    }

    fn request_auth(&self, chan: &str, seq: Option<&Value>, cum: Option<&Value>, sig: Option<&str>, req: &str) -> Result<String> {
        self.with(chan, |c| {
            let key = channel_auth_key(&c.secret, &c.params.payee_pub)?;
            Ok(request_auth(&key, chan, seq, cum, sig, req))
        })
    }

    fn sign_conditional(&self, chan: &str, uncond: u64, cond: &ConditionalParams) -> Result<Vec<u8>> {
        self.with(chan, |c| {
            let tx = cond.state_tx(uncond)?;
            Ok(sign_with_type(&c.secret, &cond.sighash(&tx)?, SIGHASH_ALL_UNIFIED))
        })
    }
}

fn poisoned<T>(_: std::sync::PoisonError<T>) -> ChannelError {
    ChannelError::code("poisoned")
}

fn dec_point(p: &PubkeyBytes) -> Result<xbt_primitives::secp256k1::PublicKey> {
    adaptor::dec(p)
}

impl RouteSigner for LocalSigner {
    fn sign_state_adaptor(&self, chan: &str, cum: u64, point: &PubkeyBytes, route: &Value) -> Result<AdaptorLock> {
        self.with(chan, |c| {
            if c.lock.is_some() {
                return fail("lock_outstanding", "one adaptor lock per channel at a time");
            }
            if cum <= c.signed {
                return fail("stale_amount", "a lock must raise the signed amount");
            }
            let t = dec_point(point)?;
            let r = random_secret();
            let t1 = adaptor::add(Some(&t), Some(&adaptor::point_of(&r))).ok_or_else(|| ChannelError::new("bad_point", "T + r·G at infinity"))?;
            let pre = adaptor::presign(&c.secret, &c.params.sighash(&c.params.state_tx(cum)?)?, &t1)?;
            let lk = PendingLock { cum, pre: pre.clone(), r: r.secret_bytes(), t: *point, t1: adaptor::enc(&t1), route: route.clone() };
            // recorded before the pre-signature leaves
            c.lock = Some(lk.clone());
            Ok(AdaptorLock { pre, point: lk.t1, tweak: lk.r, cum })
        })
    }

    fn resolve_lock(&self, chan: &str, secret: &[u8; 32]) -> Result<[u8; 32]> {
        self.with(chan, |c| {
            let lk = c.lock.clone().ok_or_else(|| ChannelError::new("no_state", "no pending lock"))?;
            let y = Sc::reduce(secret).secret().ok_or_else(|| ChannelError::new("bad_secret", "not a secret"))?;
            let yp = adaptor::enc(&adaptor::point_of(&y));
            let t = if yp == lk.t1 {
                Sc::from_secret(&y).sub(&Sc::reduce(&lk.r))
            } else if yp == lk.t {
                Sc::from_secret(&y)
            } else {
                return fail("bad_secret", "secret opens neither T1 nor T");
            };
            c.signed = c.signed.max(lk.cum);
            c.lock = None;
            Ok(t.0)
        })
    }

    fn void_lock(&self, chan: &str) -> Result<bool> {
        self.with(chan, |c| match c.lock.take() {
            Some(lk) => {
                c.given_up.push(lk);
                if c.given_up.len() > 16 {
                    c.given_up.remove(0);
                }
                Ok(true)
            }
            None => Ok(false),
        })
    }

    fn adopt_lock(&self, chan: &str, cum: u64) -> Result<()> {
        self.with(chan, |c| {
            let i = c.given_up.iter().position(|l| l.cum == cum).ok_or_else(|| ChannelError::new("bad_amount", "not a lock this signer pre-signed"))?;
            if c.lock.is_some() {
                return fail("lock_outstanding", "resolve or void the pending lock first");
            }
            c.given_up.remove(i);
            c.signed = c.signed.max(cum);
            Ok(())
        })
    }

    fn recover_lock(&self, chan: &str, close_tx: &Tx) -> Result<[u8; 32]> {
        let lk = self.pending_lock(chan).ok_or_else(|| ChannelError::new("no_state", "no pending lock"))?;
        let t1 = dec_point(&lk.t1)?;
        let wit = close_tx.inputs.first().map(|i| i.witness.clone()).unwrap_or_default();
        let y = adaptor::secret_from_witness(&lk.pre, &wit, &t1).ok_or_else(|| ChannelError::new("bad_secret", "this close does not carry the lock"))?;
        self.resolve_lock(chan, &y.secret_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::FeePayer;

    fn params(payer: &PubkeyBytes, expiry: u32, txid: &str) -> ChannelParams {
        let pay_to = ecdsa::pubkey(&SecretKey::from_slice(&[7u8; 32]).unwrap());
        let p = ChannelParams::derive(&pay_to, payer, expiry, 600, None, "bip122:11111111111111111111111111111111", FeePayer::Payer).unwrap();
        p.with_funding(txid, 0, 50_000).unwrap()
    }

    /// The rule for issued keys (AGP-096): asked again, the signer answers the key it issued; one
    /// key binds every channel that pays it; a bound key is not issued again; and a key is bound
    /// only under the origin it was issued for.
    #[test]
    fn an_issued_key_is_never_replaced_and_binds_every_channel_that_pays_it() {
        let s = LocalSigner::new();
        let k = s.new_key("https://a.example/next").unwrap();
        assert_eq!(s.new_key("https://a.example/next").unwrap(), k, "asking again answers the key already issued");
        let (one, two) = (params(&k, 2_000, &"11".repeat(32)), params(&k, 2_001, &"22".repeat(32)));
        let c2 = s.attach("https://a.example/next", &two).unwrap();
        s.sign_state(&c2, 700).unwrap();
        // the attempt that confirmed is another one: bound too, with its own refund
        let c1 = s.attach("https://a.example/next", &one).unwrap();
        assert_ne!(c1, c2);
        let refund = Tx::parse_hex(&s.sign_refund(&c1).unwrap()).unwrap();
        assert_eq!((refund.inputs[0].prevout.txid_hex(), refund.locktime), ("11".repeat(32), 2_000));
        // binding a channel again keeps what was signed on it
        assert_eq!(s.attach("https://a.example/next", &two).unwrap(), c2);
        assert_eq!(s.signed(&c2), 700);
        assert_eq!(s.sign_state(&c2, 600).unwrap_err().code, "stale_amount");
        // the key is used: the next rollover gets its own, and the first still signs
        let k2 = s.new_key("https://a.example/next").unwrap();
        assert_ne!(k2, k);
        assert!(s.sign_refund(&c1).is_ok());
        // only under its own origin, and only a key this signer issued
        assert_eq!(s.attach("https://b.example", &params(&k, 2_002, &"33".repeat(32))).unwrap_err().code, "bad_key");
        let other = ecdsa::pubkey(&SecretKey::from_slice(&[9u8; 32]).unwrap());
        assert_eq!(s.attach("https://a.example/next", &params(&other, 2_000, &"44".repeat(32))).unwrap_err().code, "bad_key");
        assert_eq!(s.attach("https://c.example", &params(&other, 2_000, &"55".repeat(32))).unwrap_err().msg, "call new_key before attach");
    }
}
