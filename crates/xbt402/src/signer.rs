//! The payer's signing seam for routed payments: [`StateSigner`], and [`LocalSigner`], an
//! in-process implementation (keys in this process: tests, regtest, the interop tools).
//!
//! The methods are B1 `ChannelSigner`'s, which B2's signer socket serves as `xbt402_new_key`,
//! `xbt402_attach`, `xbt402_sign_state`, `xbt402_sign_close`, `xbt402_sign_refund`,
//! `xbt402_request_auth`, `xbt402_sign_state_adaptor`, `xbt402_resolve_lock`, `xbt402_void_lock`,
//! `xbt402_adopt_lock`, `xbt402_recover_lock` and `xbt402_fund`. AGP-027 implements this trait over
//! that socket (the B2 signer and policy engine in Rust), so [`crate::route_client::RoutePayer`]
//! runs with its keys outside the client process without any change here.
//!
//! Adaptor locks follow B1's rules: one pending lock per channel; the lock `(cum, pre, r, T, T1)`
//! is recorded before the pre-signature leaves; `resolve_lock` takes t + r (from the hub) or t
//! (the provider's receipt); a given-up lock can be adopted later only by its own cum.
use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::{json, Value};
use xbt_primitives::ecdsa;
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::tx::Tx;

use crate::adaptor::{self, PreSig, Sc};
use crate::channel::{channel_auth_key, sign_with_type, ChannelParams};
use crate::client::Wallet;
use crate::error::{fail, ChannelError, Result};
use crate::wire::{close_message, request_auth};
use xbt_primitives::sighash::SIGHASH_ALL_UNIFIED;

/// What [`StateSigner::sign_state_adaptor`] returns (the reference's dict).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptorLock {
    /// The pre-signature, wire form.
    pub adaptor: Value,
    /// T1 = T + r·G, compressed hex.
    pub point: String,
    /// r, 64 hex.
    pub tweak: String,
    pub cum: u64,
}

/// Channel-key operations for a payer. Every method takes `&self`: implementations are shared
/// between a payer's data path and its lock thread.
pub trait StateSigner: Send + Sync {
    /// A fresh payer key for a channel to `origin` (compressed hex).
    fn new_key(&self, origin: &str) -> Result<String>;
    /// Bind the key issued for `origin` to the funded channel. Returns the channel id.
    fn attach(&self, origin: &str, params: &ChannelParams) -> Result<String>;
    /// DER‖0x21 hex of the state paying `amount`. Never lower than before.
    fn sign_state(&self, chan: &str, amount: u64) -> Result<String>;
    /// The payer's close request signature (hex DER).
    fn sign_close(&self, chan: &str) -> Result<String>;
    /// The payer's refund tx (hex), valid at expiry.
    fn sign_refund(&self, chan: &str) -> Result<String>;
    /// `payload.auth` for one request (the channel's ECDH key never leaves the signer).
    fn request_auth(&self, chan: &str, seq: &Value, cum: &Value, sig: Option<&str>, req: &str) -> Result<String>;
    /// Pre-sign state(cum) under T1 = T + r·G for a routed lock (`point` = T; r is fresh here).
    fn sign_state_adaptor(&self, chan: &str, cum: u64, point: &str, route: &Value) -> Result<AdaptorLock>;
    /// The lock was paid: `secret` is t + r (the hub) or t (the provider). Returns t (hex).
    fn resolve_lock(&self, chan: &str, secret: &str) -> Result<String>;
    /// Give the pending lock up (the hub refused it, or its invoice expired).
    fn void_lock(&self, chan: &str) -> Result<Value>;
    /// A lock this signer gave up was completed after all (the hub read t off a close).
    fn adopt_lock(&self, chan: &str, cum: u64) -> Result<()>;
    /// t from the hub's ch1 close, which carries the completed pre-signature (t + r).
    fn recover_lock(&self, chan: &str, close_tx: &Tx) -> Result<String>;
    /// Fund `address` with `sats`: the funding outpoint.
    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)>;
    /// The pending lock on `chan`, if any (`{cum, pre, r, T, T1, route}`).
    fn pending_lock(&self, chan: &str) -> Option<Value> {
        let _ = chan;
        None
    }
}

#[derive(Clone)]
struct Lock {
    cum: u64,
    pre: PreSig,
    r: Sc,
    t: String,
    t1: String,
    route: Value,
}

#[derive(Default)]
struct Inner {
    pending_keys: HashMap<String, SecretKey>,
    secrets: HashMap<String, SecretKey>,
    params: HashMap<String, ChannelParams>,
    signed: HashMap<String, u64>,
    locks: HashMap<String, Lock>,
    given_up: HashMap<String, Vec<Lock>>,
}

/// Keys in this process (B1 `ChannelSigner`). `policy(chan, amount)` may deny a signature.
pub struct LocalSigner {
    inner: Mutex<Inner>,
    wallet: Option<Box<dyn Wallet>>,
    #[allow(clippy::type_complexity)]
    policy: Option<Box<dyn Fn(&str, u64) -> Result<()> + Send + Sync>>,
}

impl LocalSigner {
    pub fn new(wallet: Option<Box<dyn Wallet>>) -> Self {
        Self { inner: Mutex::new(Inner::default()), wallet, policy: None }
    }

    /// Refuse signatures `policy(chan, amount)` denies.
    pub fn with_policy(mut self, policy: Box<dyn Fn(&str, u64) -> Result<()> + Send + Sync>) -> Self {
        self.policy = Some(policy);
        self
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn check(&self, chan: &str, amount: u64) -> Result<()> {
        match &self.policy {
            Some(p) => p(chan, amount),
            None => Ok(()),
        }
    }

    /// The highest amount signed on `chan`.
    pub fn signed(&self, chan: &str) -> u64 {
        self.inner().signed.get(chan).copied().unwrap_or(0)
    }
}

fn secret_of(i: &Inner, chan: &str) -> Result<(SecretKey, ChannelParams)> {
    match (i.secrets.get(chan), i.params.get(chan)) {
        (Some(s), Some(p)) => Ok((*s, p.clone())),
        _ => fail("unknown_channel", chan.to_string()),
    }
}

fn lock_json(l: &Lock) -> Value {
    json!({"cum": l.cum, "pre": l.pre.to_json(), "r": l.r.hex(), "T": l.t, "T1": l.t1, "route": l.route})
}

impl StateSigner for LocalSigner {
    fn new_key(&self, origin: &str) -> Result<String> {
        let sk = adaptor::random_secret();
        self.inner().pending_keys.insert(origin.to_string(), sk);
        Ok(hex::encode(ecdsa::pubkey(&sk)))
    }

    fn attach(&self, origin: &str, params: &ChannelParams) -> Result<String> {
        let mut i = self.inner();
        let sk = i.pending_keys.remove(origin).ok_or_else(|| ChannelError::new("bad_key", "call new_key before attach"))?;
        if ecdsa::pubkey(&sk) != params.payer_pub {
            return fail("bad_key", "attached params do not match issued key");
        }
        let chan = params.channel_id();
        i.secrets.insert(chan.clone(), sk);
        i.params.insert(chan.clone(), params.clone());
        i.signed.insert(chan.clone(), 0);
        Ok(chan)
    }

    fn sign_state(&self, chan: &str, amount: u64) -> Result<String> {
        self.check(chan, amount)?;
        let mut i = self.inner();
        let (sk, p) = secret_of(&i, chan)?;
        if amount < i.signed.get(chan).copied().unwrap_or(0) {
            return fail("stale_amount", "never sign a lower cumulative amount");
        }
        let tx = p.state_tx(amount)?;
        let sig = sign_with_type(&sk, &p.sighash(&tx)?, SIGHASH_ALL_UNIFIED);
        i.signed.insert(chan.to_string(), amount);
        Ok(hex::encode(sig))
    }

    fn sign_close(&self, chan: &str) -> Result<String> {
        let (sk, _) = secret_of(&self.inner(), chan)?;
        Ok(hex::encode(ecdsa::sign(&sk, &close_message(chan))))
    }

    fn sign_refund(&self, chan: &str) -> Result<String> {
        let (sk, p) = secret_of(&self.inner(), chan)?;
        Ok(p.refund_tx(&sk, None, None)?.to_hex())
    }

    fn request_auth(&self, chan: &str, seq: &Value, cum: &Value, sig: Option<&str>, req: &str) -> Result<String> {
        let (sk, p) = secret_of(&self.inner(), chan)?;
        let key = channel_auth_key(&sk, &p.payee_pub)?;
        Ok(request_auth(&key, chan, Some(seq), Some(cum), sig, req))
    }

    fn sign_state_adaptor(&self, chan: &str, cum: u64, point: &str, route: &Value) -> Result<AdaptorLock> {
        self.check(chan, cum)?;
        let mut i = self.inner();
        let (sk, p) = secret_of(&i, chan)?;
        if i.locks.contains_key(chan) {
            return fail("lock_outstanding", "one adaptor lock per channel at a time");
        }
        if cum <= i.signed.get(chan).copied().unwrap_or(0) {
            return fail("stale_amount", "a lock must raise the signed amount");
        }
        let t = adaptor::dec_hex(point)?;
        let r = adaptor::random_secret();
        let t1 = adaptor::add(Some(&t), Some(&adaptor::point_of(&r))).ok_or_else(|| ChannelError::new("bad_point", "T + r·G at infinity"))?;
        let pre = adaptor::presign(&sk, &p.sighash(&p.state_tx(cum)?)?, &t1)?;
        let lk = Lock { cum, pre: pre.clone(), r: Sc::from_secret(&r), t: point.to_lowercase(), t1: hex::encode(adaptor::enc(&t1)), route: route.clone() };
        // recorded before the pre-signature leaves
        i.locks.insert(chan.to_string(), lk.clone());
        Ok(AdaptorLock { adaptor: pre.to_json(), point: lk.t1, tweak: lk.r.hex(), cum })
    }

    fn resolve_lock(&self, chan: &str, secret: &str) -> Result<String> {
        let mut i = self.inner();
        let lk = i.locks.get(chan).cloned().ok_or_else(|| ChannelError::new("no_state", "no pending lock"))?;
        let y = Sc::from_hex_mod_n(secret).and_then(|s| s.secret()).ok_or_else(|| ChannelError::new("bad_secret", "not a secret"))?;
        let yp = hex::encode(adaptor::enc(&adaptor::point_of(&y)));
        let t = if yp == lk.t1 {
            Sc::from_secret(&y).sub(&lk.r)
        } else if yp == lk.t {
            Sc::from_secret(&y)
        } else {
            return fail("bad_secret", "secret opens neither T1 nor T");
        };
        let s = i.signed.entry(chan.to_string()).or_insert(0);
        *s = (*s).max(lk.cum);
        i.locks.remove(chan);
        Ok(t.hex())
    }

    fn void_lock(&self, chan: &str) -> Result<Value> {
        let mut i = self.inner();
        match i.locks.remove(chan) {
            Some(lk) => {
                let v = lock_json(&lk);
                i.given_up.entry(chan.to_string()).or_default().push(lk);
                Ok(v)
            }
            None => Ok(json!({})),
        }
    }

    fn adopt_lock(&self, chan: &str, cum: u64) -> Result<()> {
        let mut i = self.inner();
        if !i.given_up.get(chan).is_some_and(|g| g.iter().any(|l| l.cum == cum)) {
            return fail("bad_amount", "not a lock this signer pre-signed");
        }
        let s = i.signed.entry(chan.to_string()).or_insert(0);
        *s = (*s).max(cum);
        Ok(())
    }

    fn recover_lock(&self, chan: &str, close_tx: &Tx) -> Result<String> {
        let lk = self.inner().locks.get(chan).cloned().ok_or_else(|| ChannelError::new("no_state", "no pending lock"))?;
        let t1 = adaptor::dec_hex(&lk.t1)?;
        let wit = close_tx.inputs.first().map(|i| i.witness.clone()).unwrap_or_default();
        let y = adaptor::secret_from_witness(&lk.pre, &wit, &t1).ok_or_else(|| ChannelError::new("bad_secret", "this close does not carry the lock"))?;
        self.resolve_lock(chan, &hex::encode(y.secret_bytes()))
    }

    fn fund(&self, address: &str, sats: u64) -> Result<(String, u32)> {
        match &self.wallet {
            Some(w) => w.fund(address, sats),
            None => fail("no_wallet", "signer has no fund() hook"),
        }
    }

    fn pending_lock(&self, chan: &str) -> Option<Value> {
        self.inner().locks.get(chan).map(lock_json)
    }
}
