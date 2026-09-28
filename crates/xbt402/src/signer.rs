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
use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::Value;
use xbt_primitives::ecdsa::{self, PubkeyBytes};
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::sighash::{SIGHASH_ALL_UNIFIED, SIGHASH_SINGLE_ACP_UNIFIED};

use crate::channel::{channel_auth_key, sign_with_type, ChannelParams};
use crate::conditional::ConditionalParams;
use crate::error::{fail, ChannelError, Result};
use crate::wire::{close_message, request_auth};

/// Everything a payer needs signed, keyed by channel id (`txid:vout`). Signatures are
/// `DER || hash_type` as the wire carries them; `sign_close` is plain DER.
pub trait StateSigner: Send + Sync {
    /// A fresh payer key for a channel to `origin` (33-byte compressed pubkey).
    fn new_key(&self, origin: &str) -> Result<PubkeyBytes>;
    /// Bind the key issued for `origin` to the funded channel. Returns the channel id.
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
    /// The payer's close authorisation over `tagged_hash("xbt402/close", chan)` (DER).
    fn sign_close(&self, chan: &str) -> Result<Vec<u8>>;
    /// The signed CLTV refund tx (hex).
    fn sign_refund(&self, chan: &str) -> Result<String>;
    /// `payload.auth` for one paid request; the ECDH channel key never leaves the signer.
    fn request_auth(&self, chan: &str, seq: Option<&Value>, cum: Option<&Value>, sig: Option<&str>, req: &str) -> Result<String>;
    /// The 0x21 hash-locked state paying `uncond` plus the conditional amount.
    fn sign_conditional(&self, chan: &str, uncond: u64, cond: &ConditionalParams) -> Result<Vec<u8>>;
}

struct LocalChannel {
    secret: SecretKey,
    params: ChannelParams,
    signed: u64,
}

/// In-memory [`StateSigner`] (B1 `ChannelSigner` without a policy hook).
#[derive(Default)]
pub struct LocalSigner {
    pending: Mutex<HashMap<String, SecretKey>>,
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
}

impl StateSigner for LocalSigner {
    fn new_key(&self, origin: &str) -> Result<PubkeyBytes> {
        let sk = random_secret();
        let pk = ecdsa::pubkey(&sk);
        self.pending.lock().map_err(|_| ChannelError::code("poisoned"))?.insert(origin.to_string(), sk);
        Ok(pk)
    }

    fn attach(&self, origin: &str, params: &ChannelParams) -> Result<String> {
        let sk = self.pending.lock().map_err(|_| ChannelError::code("poisoned"))?.remove(origin)
            .ok_or_else(|| ChannelError::new("bad_key", "call new_key before attach"))?;
        if ecdsa::pubkey(&sk) != params.payer_pub {
            return fail("bad_key", "attached params do not match the issued key");
        }
        let chan = params.channel_id();
        self.chans.lock().map_err(|_| ChannelError::code("poisoned"))?
            .insert(chan.clone(), LocalChannel { secret: sk, params: params.clone(), signed: 0 });
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
