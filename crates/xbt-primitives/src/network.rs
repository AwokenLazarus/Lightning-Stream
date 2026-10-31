//! Chains, their bech32 prefixes, and the CAIP-2 network id xbt402 uses.
//!
//! CAIP-2 `bip122` names a chain by the first 32 hex characters of its genesis block hash. XBT's id
//! is keyed to block 961640 instead, the first BLAKE2b block. XBT shares genesis and everything up
//! to 961631 with Bitcoin, and 961632..=961639 (still SHA-256d) with the BIP-110 chain that stayed
//! on SHA-256d, so a genesis-keyed id would be Bitcoin's own (`bip122:000000000019d6689c085ae165831e93`)
//! and a payment requirement could not say which chain it means. 961640 is the first block only XBT
//! has; it is also the light client's default trust anchor.
use crate::error::{Error, Result};

/// The first BLAKE2b block on XBT mainnet: the anchor of the mainnet network id.
pub const MAINNET_ANCHOR_HEIGHT: u32 = 961_640;
/// Its hash (display hex).
pub const MAINNET_ANCHOR_HASH: &str = "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb";
/// On regtest the rigs switch to BLAKE2b at block 101 (`-testactivationheight=blake2b@101`); the
/// network id is that block's hash.
pub const REGTEST_ANCHOR_HEIGHT: u32 = 101;
/// `network_id(block 961640)`, the xbt402 mainnet network string.
pub const XBT_MAINNET: &str = "bip122:0000000000000050c1e5f69672f45929";

/// A chain as `getblockchaininfo.chain` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Chain {
    Main,
    Test,
    Testnet4,
    Signet,
    Regtest,
}

impl Chain {
    pub fn from_name(name: &str) -> Result<Self> {
        Ok(match name {
            "main" => Chain::Main,
            "test" => Chain::Test,
            "testnet4" => Chain::Testnet4,
            "signet" => Chain::Signet,
            "regtest" => Chain::Regtest,
            _ => return Err(Error::BadAddress(format!("unknown chain {name:?}"))),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Chain::Main => "main",
            Chain::Test => "test",
            Chain::Testnet4 => "testnet4",
            Chain::Signet => "signet",
            Chain::Regtest => "regtest",
        }
    }

    /// The bech32 human-readable part.
    pub fn hrp(self) -> &'static str {
        match self {
            Chain::Main => "bc",
            Chain::Test | Chain::Testnet4 | Chain::Signet => "tb",
            Chain::Regtest => "bcrt",
        }
    }

    /// The block whose hash names the network (mainnet 961640, regtest 101). None elsewhere.
    pub fn anchor_height(self) -> Option<u32> {
        match self {
            Chain::Main => Some(MAINNET_ANCHOR_HEIGHT),
            Chain::Regtest => Some(REGTEST_ANCHOR_HEIGHT),
            _ => None,
        }
    }

    /// Blocks between halvings of the block subsidy: Knots' `consensus.nSubsidyHalvingInterval`
    /// (`src/kernel/chainparams.cpp`), 150 on regtest and 210,000 on every other chain. XBT kept it.
    pub fn halving_interval(self) -> u64 {
        match self {
            Chain::Regtest => 150,
            _ => 210_000,
        }
    }

    /// The block subsidy at `height`, in sats: Knots' `GetBlockSubsidy` (`src/validation.cpp`), 50 coins
    /// halved once every [`Chain::halving_interval`] blocks, and none from the 64th halving on. What a node
    /// that can no longer read a block (a pruned one) would say `getblockstats` gave, from the height alone.
    pub fn block_subsidy(self, height: u64) -> u64 {
        match height / self.halving_interval() {
            h if h >= 64 => 0,
            h => 5_000_000_000 >> h,
        }
    }
}

/// CAIP-2 `bip122:<first 32 hex characters of the anchor block hash>`.
pub fn network_id(anchor_block_hash_hex: &str) -> String {
    let h: String = anchor_block_hash_hex.chars().take(32).collect();
    format!("bip122:{h}")
}

/// The network id for `chain` from its anchor block hash; on mainnet it must be [`XBT_MAINNET`].
pub fn network_for(chain: Chain, anchor_block_hash_hex: &str) -> Result<String> {
    let id = network_id(anchor_block_hash_hex);
    if chain == Chain::Main && id != XBT_MAINNET {
        return Err(Error::Header(format!("block {MAINNET_ANCHOR_HEIGHT} gives {id}, not {XBT_MAINNET}")));
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_id() {
        assert_eq!(network_id(MAINNET_ANCHOR_HASH), XBT_MAINNET);
        assert!(network_for(Chain::Main, &"11".repeat(32)).is_err());
        assert_eq!(Chain::Regtest.hrp(), "bcrt");
        assert_eq!(Chain::from_name("main").unwrap().hrp(), "bc");
    }

    #[test]
    fn subsidy_halves_as_knots_says() {
        let m = Chain::Main;
        assert_eq!((m.block_subsidy(0), m.block_subsidy(209_999), m.block_subsidy(210_000)), (5_000_000_000, 5_000_000_000, 2_500_000_000));
        assert_eq!((m.block_subsidy(839_999), m.block_subsidy(840_000)), (625_000_000, 312_500_000));
        // XBT's first BLAKE2b block, and the tip when the hashmaker's price was set: 3.125 XBT
        assert_eq!((m.block_subsidy(MAINNET_ANCHOR_HEIGHT as u64), m.block_subsidy(1_049_999), m.block_subsidy(1_050_000)),
                   (312_500_000, 312_500_000, 156_250_000));
        assert_eq!((m.block_subsidy(32 * 210_000), m.block_subsidy(33 * 210_000), m.block_subsidy(64 * 210_000), m.block_subsidy(u64::MAX)),
                   (1, 0, 0, 0));
        for c in [Chain::Test, Chain::Testnet4, Chain::Signet] {
            assert_eq!(c.block_subsidy(840_000), 312_500_000);
        }
        let r = Chain::Regtest;
        assert_eq!((r.block_subsidy(149), r.block_subsidy(150), r.block_subsidy(1_000), r.block_subsidy(6_720)), (5_000_000_000, 2_500_000_000, 78_125_000, 0));
    }
}
