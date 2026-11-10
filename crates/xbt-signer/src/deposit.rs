//! The first deposit's hop: a key of the box's own with a pay-to-public-key-hash address, and the
//! transaction that forwards what arrives there to the Lightning node.
//!
//! **Why a hop.** The signer pays only through a channel whose funding transaction it can prove is
//! valid on XBT alone ([`crate::ln_funding`]): the funding, or a transaction it descends from, must be
//! pinned by something its txid commits to. Coins a new owner sends from an exchange or another wallet
//! often have no such ancestor in reach, and a channel opened from them would hold money the app
//! refuses to pay with. A spend of a pay-to-public-key-hash coin carries its 0x21 signature in the
//! scriptSig, which the txid commits to, so the forwarding transaction made here is such a pin by
//! construction, one step behind the channel's funding, whatever the deposit came from.
//!
//! This module is the hop's arithmetic only: the address, and the signed forwarding transaction. It
//! reads no node and keeps no file; the caller finds the coins, chooses the destination (an address
//! of the owner's own Lightning node) and broadcasts.
use xbt_primitives::address::p2pkh_address;
use xbt_primitives::ecdsa::{self, PubkeyBytes};
use xbt_primitives::network::Chain;
use xbt_primitives::script::{p2pkh_spk, push_into};
use xbt_primitives::secp256k1::SecretKey;
use xbt_primitives::sighash::{unified_sighash, ScriptType, SIGHASH_ALL_UNIFIED};
use xbt_primitives::tx::{OutPoint, Tx, TxIn, TxOut};

use crate::hot::{DUST, SEQUENCE};
use crate::{err, Result};

/// The forwarding transaction's fee: this much, and [`FEE_PER_INPUT`] for each coin it spends (a
/// pay-to-public-key-hash input is about 148 bytes, the rest of the transaction about 45).
pub const FEE_BASE: i64 = 300;
pub const FEE_PER_INPUT: i64 = 300;
/// The most coins one forwarding transaction spends: a deposit is one coin, seldom a few.
pub const MAX_INPUTS: usize = 20;

/// The fee of a forwarding transaction that spends `inputs` coins.
pub fn forward_fee(inputs: usize) -> i64 {
    FEE_BASE + FEE_PER_INPUT * inputs as i64
}

/// The box's deposit key: where the first deposit is sent.
pub struct DepositKey {
    secret: SecretKey,
    pub pubkey: PubkeyBytes,
    pub spk: Vec<u8>,
    pub address: String,
}

impl Drop for DepositKey {
    fn drop(&mut self) {
        self.secret.non_secure_erase();
    }
}

impl DepositKey {
    pub fn new(secret: SecretKey, chain: Chain) -> Result<Self> {
        let pubkey = ecdsa::pubkey(&secret);
        let spk = p2pkh_spk(&pubkey);
        let address = p2pkh_address(chain, &spk)?;
        Ok(Self { secret, pubkey, spk, address })
    }
}

/// A coin at the deposit address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositCoin {
    pub txid: String,
    pub vout: u32,
    pub value: i64,
}

/// The transaction that sends every coin of `coins` (all at `key`'s address) to `dest_spk`, less
/// `fee`: one output, no change, each input signed 0x21 in its scriptSig.
pub fn forward(key: &DepositKey, coins: &[DepositCoin], dest_spk: &[u8], fee: i64) -> Result<Tx> {
    if coins.is_empty() || coins.len() > MAX_INPUTS {
        return Err(err("deposit", format!("a forwarding transaction spends 1 to {MAX_INPUTS} coins, not {}", coins.len())));
    }
    if dest_spk.is_empty() || dest_spk == key.spk.as_slice() {
        return Err(err("deposit", "the deposit is forwarded to the Lightning node's address, not back to the deposit address"));
    }
    if coins.iter().any(|c| c.value <= 0) || fee < 0 {
        return Err(err("deposit", "a coin's value and the fee are amounts"));
    }
    let total = coins.iter().try_fold(0i64, |a, c| a.checked_add(c.value)).ok_or_else(|| err("deposit", "the coins' total is out of range"))?;
    let out = total - fee;
    if out < DUST {
        return Err(err("deposit", format!("{total} sats less the {fee} sats fee leaves too little to send")));
    }
    let inputs = coins.iter().map(|c| OutPoint::from_display(&c.txid, c.vout).map(|op| TxIn::new(op, SEQUENCE)))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut tx = Tx::new(2, inputs, vec![TxOut::new(out, dest_spk.to_vec())], 0);
    let prevouts: Vec<TxOut> = coins.iter().map(|c| TxOut::new(c.value, key.spk.clone())).collect();
    // the unified message commits to every input's amount and script, never to a scriptSig: each input is signed
    // over the transaction as it is, then its scriptSig is put in
    let mut script_sigs = Vec::with_capacity(coins.len());
    for i in 0..coins.len() {
        // script type 0: the script code is the coin's own script (it holds no signature to remove)
        let digest = unified_sighash(&tx, &prevouts, i, ScriptType::Bare, &key.spk, SIGHASH_ALL_UNIFIED, None)?;
        let mut sig = ecdsa::sign(&key.secret, &digest);
        sig.push(SIGHASH_ALL_UNIFIED);
        let mut script_sig = Vec::with_capacity(sig.len() + key.pubkey.len() + 2);
        push_into(&mut script_sig, &sig)?;
        push_into(&mut script_sig, &key.pubkey)?;
        script_sigs.push(script_sig);
    }
    for (inp, script_sig) in tx.inputs.iter_mut().zip(script_sigs) {
        inp.script_sig = script_sig;
    }
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ln_funding::{checked_sighashes, pushes, SIGHASH_UNIFIED_ALL};
    use xbt_primitives::script::p2wpkh_spk;

    fn key() -> DepositKey {
        DepositKey::new(ecdsa::secret_key(&[7u8; 32]).unwrap(), Chain::Regtest).unwrap()
    }

    fn coin(n: u8, value: i64) -> DepositCoin {
        DepositCoin { txid: hex::encode([n; 32]), vout: n as u32, value }
    }

    /// The forwarding transaction is what the funding proof looks for: every input a pay-to-public-key-hash
    /// spend with one 0x21 signature in its scriptSig and no witness, each signature good for XBT's message.
    #[test]
    fn a_forwarded_deposit_is_pinned_by_its_script_sigs() {
        let k = key();
        assert!(k.address.starts_with('m') || k.address.starts_with('n'), "a regtest legacy address: {}", k.address);
        let dest = p2wpkh_spk(&ecdsa::pubkey(&ecdsa::secret_key(&[9u8; 32]).unwrap()));
        let coins = [coin(1, 250_000), coin(2, 40_000)];
        let fee = forward_fee(coins.len());
        let tx = forward(&k, &coins, &dest, fee).unwrap();
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!((tx.outputs[0].value, tx.outputs[0].script_pubkey.as_slice()), (290_000 - fee, dest.as_slice()));
        let prevouts: Vec<TxOut> = coins.iter().map(|c| TxOut::new(c.value, k.spk.clone())).collect();
        for (i, inp) in tx.inputs.iter().enumerate() {
            assert!(inp.witness.is_empty(), "the signature is in the scriptSig, which the txid commits to");
            assert_eq!(checked_sighashes(inp, &k.spk).unwrap(), [SIGHASH_UNIFIED_ALL]);
            let items = pushes(&inp.script_sig).unwrap();
            assert_eq!(items.len(), 2);
            assert_eq!(items[1], k.pubkey.to_vec());
            let (der, hash_type) = items[0].split_at(items[0].len() - 1);
            assert_eq!(hash_type, [SIGHASH_ALL_UNIFIED]);
            // signed over the transaction whatever the scriptSigs hold: the message does not commit to them
            let digest = unified_sighash(&tx, &prevouts, i, ScriptType::Bare, &k.spk, SIGHASH_ALL_UNIFIED, None).unwrap();
            assert!(ecdsa::verify(&k.pubkey, &digest, der), "input {i}");
        }
        // the txid commits to the signatures: another signature, another txid
        let mut other = tx.clone();
        other.inputs[0].script_sig[5] ^= 1;
        assert_ne!(other.txid(), tx.txid());
    }

    #[test]
    fn what_cannot_be_forwarded_is_refused() {
        let k = key();
        let dest = p2wpkh_spk(&[2u8; 33]);
        assert!(forward(&k, &[], &dest, 600).is_err(), "no coin");
        assert!(forward(&k, &[coin(1, 1_000)], &dest, 600).is_err(), "what is left is dust");
        assert!(forward(&k, &[coin(1, 250_000)], &k.spk, 600).is_err(), "back to the deposit address");
        assert!(forward(&k, &[coin(1, 250_000)], &dest, -1).is_err());
        assert!(forward(&k, &[coin(1, 0)], &dest, 600).is_err());
        let many: Vec<DepositCoin> = (0..=MAX_INPUTS as u8).map(|n| coin(n, 10_000)).collect();
        assert!(forward(&k, &many, &dest, forward_fee(many.len())).is_err(), "more coins than one transaction takes");
        assert!(forward(&k, &[coin(1, 250_000)], &dest, forward_fee(1)).is_ok());
    }
}
