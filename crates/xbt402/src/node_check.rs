//! Is the node this service was pointed at on XBT? (AGP-104)
//!
//! XBT shares its genesis block and every block below 961,640 with the SHA-256 chain, and a
//! platform may offer a node of either chain for the same slot. A hub that started against the
//! other chain's node would advertise that chain's network id and fund channels there. So before
//! it serves anything it checks one block:
//!
//! * mainnet: block 961,640 is the first one only XBT has, and its hash is pinned
//!   ([`MAINNET_ANCHOR_HASH`]);
//! * any other chain (regtest, a test network) has no pinned block, so the check is on the block's
//!   form: its header is a BLAKE2b header (164 bytes) that commits its own height and hashes, by
//!   this crate's own BLAKE2b code, to the hash the node gives. A SHA-256 chain's node gives an
//!   80-byte header. On regtest the block is 101 (where the regtest rigs switch to BLAKE2b, and
//!   the block the network id is read from); elsewhere it is the tip.
use xbt_primitives::header::parse_header;
use xbt_primitives::network::{MAINNET_ANCHOR_HASH, MAINNET_ANCHOR_HEIGHT, REGTEST_ANCHOR_HEIGHT};

/// The height to check on `chain` (`getblockchaininfo`'s name); None: the node's tip.
pub fn check_height(chain: &str) -> Option<u32> {
    match chain {
        "main" => Some(MAINNET_ANCHOR_HEIGHT),
        "regtest" => Some(REGTEST_ANCHOR_HEIGHT),
        _ => None,
    }
}

/// `Ok` when the block at `height`, with the hash and the raw header the node gave
/// (`getblockhash`, `getblockheader <hash> false`), is an XBT block. `Err`: why not, for the
/// operator.
pub fn check_chain(chain: &str, height: u32, hash_hex: &str, header_hex: &str) -> Result<(), String> {
    let hash = hash_hex.trim().to_ascii_lowercase();
    if chain == "main" {
        if height != MAINNET_ANCHOR_HEIGHT {
            return Err(format!("mainnet is checked at block {MAINNET_ANCHOR_HEIGHT}, not {height}"));
        }
        if hash != MAINNET_ANCHOR_HASH {
            return Err(format!("block {height} of this node is {hash}, and XBT's is {MAINNET_ANCHOR_HASH}: the node is on another chain \
                                (the SHA-256 chain shares every block below {MAINNET_ANCHOR_HEIGHT})"));
        }
        return Ok(());
    }
    let raw = hex::decode(header_hex.trim()).map_err(|_| format!("block {height}: the node's header is not hex"))?;
    if raw.len() == 80 {
        return Err(format!("block {height} of this node has an 80-byte SHA-256 header: the node is not on XBT, or its chain has not reached BLAKE2b at block {height}"));
    }
    let h = parse_header(&raw).map_err(|e| format!("block {height}: not a BLAKE2b header ({e})"))?;
    if h.height != height {
        return Err(format!("block {height}: its header commits height {}", h.height));
    }
    if h.hash_hex() != hash {
        return Err(format!("block {height}: the node calls it {hash}, and its header hashes to {} under BLAKE2b: the node is not on XBT", h.hash_hex()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mainnet headers 961,630 to 961,649 as a node gave them: ten of the shared chain, then XBT's.
    fn headers() -> Vec<String> {
        let v: serde_json::Value = serde_json::from_str(include_str!("../../../vectors/mainnet_headers_961630.json")).unwrap();
        assert_eq!(v["start"], 961_630);
        v["headers"].as_array().unwrap().iter().map(|h| h.as_str().unwrap().to_string()).collect()
    }

    #[test]
    fn mainnet_is_the_pinned_block_and_nothing_else() {
        assert_eq!((check_height("main"), check_height("regtest"), check_height("testnet4")), (Some(961_640), Some(101), None));
        assert!(check_chain("main", 961_640, MAINNET_ANCHOR_HASH, "").is_ok());
        assert!(check_chain("main", 961_640, &MAINNET_ANCHOR_HASH.to_uppercase(), "").is_ok());
        // the SHA-256 chain's block at that height (any other hash)
        let e = check_chain("main", 961_640, &"00".repeat(32), "").unwrap_err();
        assert!(e.contains("another chain"), "{e}");
        assert!(check_chain("main", 961_639, MAINNET_ANCHOR_HASH, "").is_err());
    }

    #[test]
    fn elsewhere_the_block_must_be_a_blake2b_block_that_hashes_to_what_the_node_says() {
        let hs = headers();
        // XBT's first block, checked by its form as a regtest or test network block would be
        let first = &hs[10];
        assert_eq!(first.len(), 164 * 2);
        assert!(check_chain("regtest", 961_640, MAINNET_ANCHOR_HASH, first).is_ok());
        // a SHA-256 header (the shared chain's last block): refused, whatever hash comes with it
        assert_eq!(hs[9].len(), 80 * 2);
        let e = check_chain("regtest", 961_639, MAINNET_ANCHOR_HASH, &hs[9]).unwrap_err();
        assert!(e.contains("SHA-256"), "{e}");
        // a BLAKE2b header the node gives another hash for, or at another height
        assert!(check_chain("regtest", 961_640, &"11".repeat(32), first).unwrap_err().contains("not on XBT"));
        assert!(check_chain("regtest", 961_641, MAINNET_ANCHOR_HASH, first).unwrap_err().contains("commits height"));
        // one changed byte no longer hashes to it
        let mut bad = first.clone();
        bad.replace_range(80..82, if &first[80..82] == "00" { "01" } else { "00" });
        assert!(check_chain("regtest", 961_640, MAINNET_ANCHOR_HASH, &bad).is_err());
        assert!(check_chain("regtest", 101, "", "zz").is_err());
        assert!(check_chain("regtest", 101, "", "").is_err());
    }
}
