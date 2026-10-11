//! Helpers for the interop binaries (feature `tools`): the node's view of the chain (network id,
//! the epoch's nBits, pool coinbases) and the Prime's window statements, fed to the audit.
use serde_json::{json, Value};
use xbt402::rpc::Rpc;
use xbt_primitives::network::network_id;

use crate::audit::PrimeTerms;
use crate::chain::{ChainBlock, Maturity};
use crate::error::{Result, WorkError};

/// `--name value` from argv.
pub fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

pub fn flag(name: &str) -> bool {
    std::env::args().any(|x| x == name)
}

/// `--flag value`, else the env variable.
pub fn opt(flag: &str, var: &str) -> Option<String> {
    arg(flag).or_else(|| std::env::var(var).ok().filter(|v| !v.trim().is_empty()))
}

fn opt_num<T: std::str::FromStr>(flag: &str, var: &str) -> Result<Option<T>> {
    opt(flag, var).map(|v| v.trim().parse().map_err(|_| WorkError::new("bad_config", format!("{flag} / {var}: not a number: {v}")))).transpose()
}

/// The Prime's pool terms (AGP-065) from `--prime-window`, `--prime-window-min-work`,
/// `--window-tolerance-bps`, `--prime-fee-bps`, `--prime-min-payout` or their `XBT_WORK_*` env
/// variables; primed's defaults for any not given.
pub fn prime_terms() -> Result<PrimeTerms> {
    let d = PrimeTerms::default();
    Ok(PrimeTerms { window: opt_num("--prime-window", "XBT_WORK_PRIME_WINDOW")?.unwrap_or(d.window),
                    window_min_work: opt_num("--prime-window-min-work", "XBT_WORK_PRIME_WINDOW_MIN_WORK")?.unwrap_or(d.window_min_work),
                    window_tolerance_bps: opt_num("--window-tolerance-bps", "XBT_WORK_WINDOW_TOLERANCE_BPS")?.unwrap_or(d.window_tolerance_bps),
                    fee_bps: opt_num("--prime-fee-bps", "XBT_WORK_PRIME_FEE_BPS")?.unwrap_or(d.fee_bps),
                    max_min_payout: opt_num("--prime-min-payout", "XBT_WORK_PRIME_MIN_PAYOUT")?.unwrap_or(d.max_min_payout) })
}

pub fn rpc(port: &str, cookie: &str) -> Result<Rpc> {
    Ok(Rpc::from_cookie(&format!("http://127.0.0.1:{port}"), std::path::Path::new(cookie))?)
}

/// The CAIP-2 network of the node's chain (the first BLAKE2b block, 101 on regtest).
pub fn network(rpc: &Rpc) -> Result<String> {
    let h = rpc.call("getblockhash", json!([101]))?;
    Ok(network_id(h.as_str().ok_or_else(|| WorkError::new("node", "getblockhash"))?))
}

/// The tip's compact target (the epoch's `bits`).
pub fn tip_bits(rpc: &Rpc) -> Result<u32> {
    let best = rpc.call("getbestblockhash", json!([]))?;
    let hdr = rpc.call("getblockheader", json!([best]))?;
    u32::from_str_radix(hdr["bits"].as_str().unwrap_or(""), 16).map_err(|_| WorkError::new("node", "bits"))
}

pub fn block_count(rpc: &Rpc) -> Result<u32> {
    rpc.call("getblockcount", json!([]))?.as_u64().and_then(|n| u32::try_from(n).ok()).ok_or_else(|| WorkError::new("node", "getblockcount"))
}

pub fn block_hash(rpc: &Rpc, height: u32) -> Result<String> {
    rpc.call("getblockhash", json!([height]))?.as_str().map(str::to_string).ok_or_else(|| WorkError::new("node", "getblockhash"))
}

/// A block's coinbase: (block hash, total value V in sats, [(address, sats)]).
pub type Coinbase = (String, u64, Vec<(String, u64)>);

pub fn coinbase(rpc: &Rpc, height: u32) -> Result<Coinbase> {
    let hash = block_hash(rpc, height)?;
    let blk = rpc.call("getblock", json!([hash, 2]))?;
    let (total, outs) = coinbase_outputs(&blk)?;
    Ok((hash, total, outs))
}

fn coinbase_outputs(blk: &Value) -> Result<(u64, Vec<(String, u64)>)> {
    let vout = blk["tx"][0]["vout"].as_array().ok_or_else(|| WorkError::new("node", "getblock: no coinbase outputs"))?;
    let mut total = 0u64;
    let mut outs = vec![];
    for o in vout {
        let btc = o["value"].as_f64().ok_or_else(|| WorkError::new("node", "getblock: output value"))?;
        // The rule (AGP-106): a number of the node's that does not fit, or a sum of them that
        // does not, is the node's error and not a value. No block pays past u64 sats; a value
        // the cast would clamp, or a saturated total, would be audited as if it were one.
        let sats = (btc * 1e8).round();
        if !(0.0..u64::MAX as f64).contains(&sats) {
            return Err(WorkError::new("node", "getblock: an output value that is no amount"));
        }
        let sats = sats as u64;
        total = total.checked_add(sats).ok_or_else(|| WorkError::new("node", "getblock: coinbase outputs sum past u64"))?;
        // an output with no address (OP_RETURN, the witness commitment) pays no identity
        outs.push((o["scriptPubKey"]["address"].as_str().unwrap_or("").to_string(), sats));
    }
    Ok((total, outs))
}

fn bits_of(v: &Value) -> Result<u32> {
    u32::from_str_radix(v["bits"].as_str().unwrap_or(""), 16).map_err(|_| WorkError::new("node", "bits"))
}

/// The block at `height` as the provider's node has it, with what its coinbase pays `identity`.
pub fn chain_block(rpc: &Rpc, height: u32, identity: &str) -> Result<ChainBlock> {
    let hash = block_hash(rpc, height)?;
    let blk = rpc.call("getblock", json!([hash, 2]))?;
    let (value_sats, outs) = coinbase_outputs(&blk)?;
    let bits = bits_of(&blk)?;
    let prev_bits = match blk["previousblockhash"].as_str() {
        Some(p) => bits_of(&rpc.call("getblockheader", json!([p]))?)?,
        None => bits,
    };
    Ok(ChainBlock { height, hash, value_sats, paid_sats: paid_to(&outs, identity), bits, prev_bits })
}

/// The node's coinbase maturity (Knots `getdeploymentinfo`).
pub fn maturity(rpc: &Rpc) -> Result<Maturity> {
    Ok(Maturity::from_deployments(&rpc.call("getdeploymentinfo", json!([]))?)?)
}

/// What a coinbase pays `identity` (bech32 compared lower-case). It never panics: outputs that
/// sum past u64 give `u64::MAX` (AGP-106; before, `sum` panicked and the audit walk with it).
/// Outputs read from a node never get that far: [`coinbase`] and [`chain_block`] refuse a
/// coinbase whose whole value does not fit, which this is a part of.
pub fn paid_to(outs: &[(String, u64)], identity: &str) -> u64 {
    outs.iter().filter(|(a, _)| a.eq_ignore_ascii_case(identity)).fold(0u64, |a, (_, s)| a.saturating_add(*s))
}

/// What the price follows at the tip, read from the node in one go: (`bits`, the block value in
/// sats). The rule (AGP-106): **a price is worked out only from what the node answered.** If the
/// height, the tip's `bits` or the subsidy cannot be read this is an error and the caller keeps
/// the epoch in force; before, a height that could not be read was taken for 0 and calls were
/// priced at the first block's subsidy, and a subsidy that could not be read for an older one.
pub fn epoch(rpc: &Rpc) -> Result<(u32, u64)> {
    let height = block_count(rpc)?;
    let stats = rpc.call("getblockstats", json!([height, ["subsidy"]]))?;
    let subsidy = stats["subsidy"].as_u64().ok_or_else(|| WorkError::new("node", "getblockstats: subsidy"))?;
    Ok((tip_bits(rpc)?, subsidy))
}

/// The Prime's statement for a pool block: [`crate::provider::window_statement`].
pub use crate::provider::window_statement as window;

#[cfg(test)]
mod tests {
    use super::*;

    /// A coinbase whose outputs sum past u64 is the node's error: no total, no payment, no panic.
    #[test]
    fn a_coinbase_whose_outputs_sum_past_u64_is_a_node_error() {
        let blk = |vals: &[f64]| json!({"tx": [{"vout": vals.iter().map(|v| json!({"value": v, "scriptPubKey": {"address": "bcrt1qid"}})).collect::<Vec<_>>()}]});
        let (total, outs) = coinbase_outputs(&blk(&[3.125, 0.0])).unwrap();
        assert_eq!((total, paid_to(&outs, "BCRT1QID")), (312_500_000, 312_500_000), "control");
        // a value no u64 of sats holds, a negative one, and two that fit but not together
        for vals in [&[1e30][..], &[-1.0], &[f64::NAN], &[92_233_720_368.0; 3]] {
            let e = coinbase_outputs(&blk(vals)).unwrap_err();
            assert_eq!(e.code, "node", "{vals:?}: {e}");
        }
        assert_eq!(paid_to(&[("a".into(), u64::MAX), ("A".into(), 1)], "a"), u64::MAX, "no panic on its own either");
    }
}
