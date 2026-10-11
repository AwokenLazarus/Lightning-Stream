//! Payee-side funding checks before a channel is credited, against any [`ChainBackend`].
use serde_json::Value;
use xbt_primitives::amount::Amount;

use crate::channel::ChannelParams;
use crate::error::{fail, ChannelError, Result};
use crate::json::py_u64;

/// An unspent output as `gettxout` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoInfo {
    pub confirmations: u32,
    /// Sats.
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    pub coinbase: bool,
}

/// The node calls the provider and the payer SDK need. The `rpc` feature implements it over
/// bitcoind JSON-RPC; a light client or a test stub can implement it too.
pub trait ChainBackend: Send + Sync {
    fn block_count(&self) -> Result<u32>;
    /// `gettxout txid vout include_mempool`: None when unknown or spent.
    fn get_tx_out(&self, txid: &str, vout: u32, include_mempool: bool) -> Result<Option<UtxoInfo>>;
    /// Broadcast; returns the txid.
    fn send_raw_transaction(&self, hex: &str) -> Result<String>;
    /// Does the node know this transaction (mempool, or txindex)?
    fn has_transaction(&self, txid: &str) -> Result<bool>;

    /// `estimatesmartfee target` in sat/vB; None without an estimate (AGP-067: the close bump).
    fn estimate_fee_rate(&self, _target: u32) -> Result<Option<f64>> {
        Ok(None)
    }

    /// The least feerate this node's mempool takes now, in sat/vB (`getmempoolinfo`: the larger
    /// of `mempoolminfee` and `minrelaytxfee`); None when unknown.
    fn mempool_min_fee(&self) -> Result<Option<f64>> {
        Ok(None)
    }

    /// Submit a parent and the child that pays for it as one package (`submitpackage`), so a
    /// parent below the mempool's floor gets in on the child's fee. Default: each in order, a
    /// refusal of the parent left to show as the child's missing input.
    fn submit_package(&self, hexes: &[String]) -> Result<()> {
        for (i, h) in hexes.iter().enumerate() {
            match self.send_raw_transaction(h) {
                Err(e) if i + 1 == hexes.len() => return Err(e),
                _ => {}
            }
        }
        Ok(())
    }
}

/// What a payee accepts as funding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingPolicy {
    pub min_capacity: u64,
    pub max_capacity: u64,
    /// ~1 day left at open.
    pub min_expiry_blocks: u32,
    /// ~60 days: bounds how long the payee's key is hot.
    pub max_expiry_blocks: u32,
    /// The payee closes this many blocks before expiry.
    pub close_margin: u32,
    pub min_conf: u32,
    /// Accept unconfirmed funding up to this capacity (0 = never).
    pub zero_conf_max: u64,
    /// Above this a funding reorg is worth more to an attacker...
    pub large_capacity: u64,
    /// ...so wait for more confirmations.
    pub large_min_conf: u32,
}

impl Default for FundingPolicy {
    fn default() -> Self {
        Self {
            min_capacity: 20_000,
            max_capacity: 10_000_000,
            min_expiry_blocks: 144,
            max_expiry_blocks: 8_640,
            close_margin: 36,
            min_conf: 1,
            zero_conf_max: 0,
            large_capacity: 1_000_000,
            large_min_conf: 3,
        }
    }
}

impl FundingPolicy {
    pub fn conf_for(&self, capacity: u64) -> u32 {
        if capacity > self.large_capacity { self.min_conf.max(self.large_min_conf) } else { self.min_conf }
    }
}

/// Err unless the funding output is acceptable; its confirmations otherwise. Coinbase fundings
/// are refused outright (#419 maturity would outlast the channel).
pub fn check_funding(chain: &dyn ChainBackend, p: &ChannelParams, pol: &FundingPolicy) -> Result<u32> {
    let out = chain
        .get_tx_out(&p.funding_txid(), p.funding_vout(), true)
        .map_err(|e| ChannelError::new("unknown_funding", e.to_string()))?
        .ok_or_else(|| ChannelError::new("unknown_funding", "no such unspent output (unknown, or already spent)"))?;
    if out.coinbase {
        return fail("coinbase_funding", "coinbase outputs cannot fund a channel (maturity)");
    }
    if out.script_pubkey != p.spk() {
        return fail("bad_funding", "output is not this channel's script");
    }
    if out.value != p.capacity {
        return fail("bad_funding", "capacity mismatch");
    }
    if !(pol.min_capacity..=pol.max_capacity).contains(&p.capacity) {
        return fail("bad_capacity", format!("capacity outside [{}, {}]", pol.min_capacity, pol.max_capacity));
    }
    let left = p.expiry as i64 - chain.block_count()? as i64;
    if left < pol.min_expiry_blocks as i64 || left > pol.max_expiry_blocks as i64 {
        return fail("bad_expiry", format!("{left} blocks to expiry, need [{}, {}]", pol.min_expiry_blocks, pol.max_expiry_blocks));
    }
    let need = pol.conf_for(p.capacity);
    if out.confirmations < need && p.capacity > pol.zero_conf_max {
        return fail("unconfirmed", format!("{} confirmations, need {need}", out.confirmations));
    }
    let _ = Amount::from_sat(p.capacity).map_err(|_| ChannelError::new("bad_capacity", "above MAX_MONEY"))?;
    Ok(out.confirmations)
}

/// The fewest blocks to expiry a payer asks for when it opens on an offer: `minExpiryBlocks +
/// minConf + closeMarginBlocks`, all three from that offer (AGP-076).
///
/// [`check_funding`] compares the blocks left with `min_expiry_blocks` at the provider's tip when
/// the funded open reaches it, not at the payer's tip when the payer chose the expiry. In between
/// the funding has to get `minConf` confirmations, and it may wait for the first one. So the
/// payer adds `minConf`, plus the time the provider itself allows a transaction to confirm on this
/// chain: `closeMarginBlocks`, how long before expiry it broadcasts its close. A funding that takes
/// longer than that would be refused `bad_expiry` on every retry, with the coins locked until the
/// refund. No provider check reads the margin; it is only the payer's allowance.
pub fn open_expiry_floor(min_expiry: u64, min_conf: u64, close_margin: u64) -> u64 {
    min_expiry.saturating_add(min_conf).saturating_add(close_margin)
}

/// Blocks to expiry for a new channel: what the payer wants, at least [`open_expiry_floor`], at
/// most `maxExpiryBlocks - 1`. An offer whose window is narrower than the floor gets the top of
/// its window: the open preflight answers that before anything is funded.
pub fn open_expiry_blocks(want: u64, min_expiry: u64, max_expiry: u64, min_conf: u64, close_margin: u64) -> u64 {
    want.max(open_expiry_floor(min_expiry, min_conf, close_margin)).min(max_expiry.saturating_sub(1))
}

/// An offer's `minExpiryBlocks`, `maxExpiryBlocks`, `minConf` and `closeMarginBlocks`.
fn offer_terms(extra: &Value) -> Result<(u64, u64, u64, u64)> {
    let need = |k: &str| py_u64(extra.get(k)).ok_or_else(|| ChannelError::new("bad_offer", format!("extra.{k} missing")));
    let min_conf = if extra.get("minConf").is_some() { need("minConf")? } else { 1 };
    Ok((need("minExpiryBlocks")?, need("maxExpiryBlocks")?, min_conf, need("closeMarginBlocks")?))
}

/// [`open_expiry_floor`] for an offer's `extra`.
pub fn offer_expiry_floor(extra: &Value) -> Result<u64> {
    let (min_expiry, _, min_conf, close_margin) = offer_terms(extra)?;
    Ok(open_expiry_floor(min_expiry, min_conf, close_margin))
}

/// The fewest blocks to expiry at which a payer still sends the funding of a channel it derived
/// earlier (a retry after a `fund` call that failed, or after a restart): `minExpiryBlocks +
/// minConf`, plus the larger half of `closeMarginBlocks`.
///
/// The rule (AGP-096, audit item 6): a retry may use up to half of the time the offer allows a
/// funding to confirm, and the other half stays for the funding itself. The test used to be the
/// whole of [`open_expiry_floor`], which is the very number a payer opens at when its own wish is
/// below it (1,153 against 1,008 with the shipped provider), so a channel was too old to fund one
/// block after it was derived. Below this number the channel is derived again, never funded late:
/// a funding the provider meets with fewer than `minExpiryBlocks` left is refused `bad_expiry` on
/// every retry, with the coins locked until the refund (AGP-076).
pub fn offer_retry_floor(extra: &Value) -> Result<u64> {
    let (min_expiry, _, min_conf, close_margin) = offer_terms(extra)?;
    Ok(open_expiry_floor(min_expiry, min_conf, close_margin - close_margin / 2))
}

/// The most blocks to expiry a payer funds on an offer unless its owner sets another bound: four
/// weeks, the bound the signer socket's `open_channel` has had since AGP-063.
pub const OWNER_MAX_EXPIRY_BLOCKS: u64 = 4_032;

/// The same for a channel to a routing hub: twice as long, as the signer socket allows a hub
/// channel (a route's locks need the room).
pub const OWNER_MAX_HUB_EXPIRY_BLOCKS: u64 = 2 * OWNER_MAX_EXPIRY_BLOCKS;

/// The fewest blocks to expiry a payer funds on an offer, unless its owner asks for fewer: a day.
/// The signer's `open_from_offer` holds the same number (AGP-095).
pub const OWNER_MIN_EXPIRY_BLOCKS: u64 = 144;

/// [`open_expiry_blocks`] for an offer's `extra`, held to the owner's bounds. `minConf` absent is
/// 1, as everywhere on this wire; the three others have no default, so an offer without one is
/// refused `bad_offer`.
///
/// The rule (AGP-090, review C2; the lower side AGP-096, audit item 4): how long a payer's coins
/// are locked, and how long the channel they pay for lasts, are the owner's numbers, never only
/// the seller's. Every term of [`open_expiry_floor`] comes from the offer, and so did the only cap
/// (`maxExpiryBlocks`). From above: an offer with `minExpiryBlocks` 2,000,000 got a channel that
/// refunds in 38 years, so the payer asks for at most `owner_max` blocks, and an offer whose floor
/// is above that is refused. From below: an offer with `maxExpiryBlocks` 2 got a channel that
/// expires in one block, which no provider opens and which costs a funding fee and a refund fee,
/// so the payer funds nothing that lasts less than the offer's own floor (below it the provider's
/// own check refuses the open) or less than [`OWNER_MIN_EXPIRY_BLOCKS`] (or the owner's `want`, if
/// that is smaller). Both are refused `bad_offer` here, before a key is made or anything is
/// funded, and neither is clamped. Every payer that opens on an offer (the library client's open
/// and rollover, the routed client's ch1) comes through this function.
pub fn offer_expiry_blocks(extra: &Value, want: u64, owner_max: u64) -> Result<u64> {
    let (min_expiry, max_expiry, min_conf, close_margin) = offer_terms(extra)?;
    let blocks = open_expiry_blocks(want.min(owner_max), min_expiry, max_expiry, min_conf, close_margin);
    if blocks > owner_max {
        return fail("bad_offer", format!("the offer needs {blocks} blocks to expiry and this payer locks its coins for at most {owner_max}"));
    }
    let least = open_expiry_floor(min_expiry, min_conf, close_margin).max(want.min(OWNER_MIN_EXPIRY_BLOCKS));
    if blocks < least {
        return fail("bad_offer", format!("the offer's window lets the channel last {blocks} blocks and this payer funds one only for {least} or more"));
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn floor_is_min_expiry_plus_min_conf_plus_close_margin() {
        // three margins, three answers: a slack that mirrors one provider's default fails two of them
        assert_eq!(open_expiry_blocks(1_008, 1_008, 8_640, 1, 144), 1_153);
        assert_eq!(open_expiry_blocks(1_008, 1_008, 8_640, 1, 36), 1_045);
        assert_eq!(open_expiry_blocks(1_008, 1_008, 8_640, 3, 5), 1_016);
        assert_eq!(open_expiry_blocks(1_008, 1_008, 8_640, 0, 0), 1_008);
    }

    #[test]
    fn want_above_the_floor_is_kept_and_the_offer_max_bounds_both() {
        assert_eq!(open_expiry_blocks(2_016, 1_008, 8_640, 1, 144), 2_016);
        assert_eq!(open_expiry_blocks(9_000, 1_008, 8_640, 1, 144), 8_639);
        assert_eq!(open_expiry_blocks(100, 1_008, 1_100, 1, 144), 1_099);
        assert_eq!(open_expiry_blocks(100, u64::MAX, u64::MAX, u64::MAX, u64::MAX), u64::MAX - 1);
        assert_eq!(open_expiry_blocks(100, 10, 0, 1, 5), 0);
    }

    #[test]
    fn offer_fields_have_no_default_but_min_conf() {
        let ex = json!({"minExpiryBlocks": 1_008, "maxExpiryBlocks": 8_640, "closeMarginBlocks": 144, "minConf": 3});
        assert_eq!(offer_expiry_blocks(&ex, 1_008, OWNER_MAX_EXPIRY_BLOCKS).unwrap(), 1_155);
        let mut no_conf = ex.clone();
        no_conf.as_object_mut().unwrap().remove("minConf");
        assert_eq!(offer_expiry_blocks(&no_conf, 1_008, OWNER_MAX_EXPIRY_BLOCKS).unwrap(), 1_153);
        for k in ["minExpiryBlocks", "maxExpiryBlocks", "closeMarginBlocks"] {
            let mut e = ex.clone();
            e.as_object_mut().unwrap().remove(k);
            let err = offer_expiry_blocks(&e, 1_008, OWNER_MAX_EXPIRY_BLOCKS).unwrap_err();
            assert_eq!(err.code, "bad_offer", "{k}");
            e[k] = json!(-1);
            assert_eq!(offer_expiry_blocks(&e, 1_008, OWNER_MAX_EXPIRY_BLOCKS).unwrap_err().code, "bad_offer", "{k} negative");
        }
        let mut e = ex.clone();
        e["minConf"] = json!("x");
        assert_eq!(offer_expiry_blocks(&e, 1_008, OWNER_MAX_EXPIRY_BLOCKS).unwrap_err().code, "bad_offer");
    }

    #[test]
    fn the_owners_bound_holds_whatever_the_offer_says() {
        let ex = |min: u64, max: u64| json!({"minExpiryBlocks": min, "maxExpiryBlocks": max, "closeMarginBlocks": 144});
        // inside the bound: as before
        assert_eq!(offer_expiry_blocks(&ex(1_008, 8_640), 1_008, 4_032).unwrap(), 1_153);
        assert_eq!(offer_expiry_blocks(&ex(3_887, 8_640), 1_008, 4_032).unwrap(), 4_032);
        // a floor one block above it, and the audit's 38 years: refused, not clamped (a clamped
        // channel would be funded and then refused bad_expiry by the provider)
        for min in [3_888, 2_000_000, u64::MAX] {
            assert_eq!(offer_expiry_blocks(&ex(min, u64::MAX), 1_008, 4_032).unwrap_err().code, "bad_offer", "{min}");
        }
        // the owner's own wish is held to the bound too
        assert_eq!(offer_expiry_blocks(&ex(144, 100_000), 50_000, 4_032).unwrap(), 4_032);
        // and a bound the owner raised is the owner's
        assert_eq!(offer_expiry_blocks(&ex(2_000_000, 3_000_000), 1_008, 2_100_000).unwrap(), 2_000_145);
    }

    #[test]
    fn the_owners_floor_holds_whatever_the_offer_says() {
        let ex = |min: u64, max: u64, margin: u64| json!({"minExpiryBlocks": min, "maxExpiryBlocks": max, "closeMarginBlocks": margin});
        // the audit's seller: a window of one block, no floor of its own
        for max in [0, 1, 2, 144] {
            assert_eq!(offer_expiry_blocks(&ex(1, max, 0), 1_008, 4_032).unwrap_err().code, "bad_offer", "maxExpiryBlocks {max}");
        }
        assert_eq!(offer_expiry_blocks(&ex(1, 145, 0), 1_008, 4_032).unwrap(), 144);
        // a window below the offer's own floor: the provider's check would refuse the open
        assert_eq!(offer_expiry_blocks(&ex(1_008, 1_100, 144), 1_008, 4_032).unwrap_err().code, "bad_offer");
        assert_eq!(offer_expiry_blocks(&ex(1_008, 1_154, 144), 1_008, 4_032).unwrap(), 1_153);
        // an owner who asks for less than a day gets it, down to the offer's floor
        assert_eq!(offer_expiry_blocks(&ex(1, 30, 0), 20, 4_032).unwrap(), 20);
        assert_eq!(offer_expiry_blocks(&ex(1, 30, 0), 0, 4_032).unwrap(), 2);
        assert_eq!(offer_expiry_blocks(&ex(1, 15, 0), 20, 4_032).unwrap_err().code, "bad_offer");
        for x in [0, 1, u64::MAX - 1, u64::MAX] {
            let _ = offer_expiry_blocks(&ex(x, x, x), x, x);
            let _ = offer_retry_floor(&ex(x, x, x));
        }
    }

    #[test]
    fn a_retry_keeps_the_larger_half_of_the_margin_for_the_funding() {
        let ex = |margin: u64| json!({"minExpiryBlocks": 1_008, "maxExpiryBlocks": 8_640, "closeMarginBlocks": margin});
        assert_eq!((offer_expiry_floor(&ex(144)).unwrap(), offer_retry_floor(&ex(144)).unwrap()), (1_153, 1_081));
        assert_eq!(offer_retry_floor(&ex(36)).unwrap(), 1_027);
        assert_eq!(offer_retry_floor(&ex(5)).unwrap(), 1_012);
        assert_eq!(offer_retry_floor(&ex(1)).unwrap(), 1_010);
        assert_eq!(offer_retry_floor(&ex(0)).unwrap(), 1_009);
    }
}
