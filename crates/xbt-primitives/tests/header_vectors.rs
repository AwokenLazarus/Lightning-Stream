//! The BLAKE2b header code against the vectors copied from Bitcoin Knots and recorded from a Knots
//! regtest node (see THIRD_PARTY_NOTICES.md): `vectors/block_header_v2.json` (five headers, every
//! stage of the hash) and `vectors/blake2b_regtest.json` (24 headers across the v1/v2 boundary,
//! the captured blocks' merkle roots, and a header chain built from the first v2 header).
use serde_json::Value;
use xbt_primitives::header::{self, HeaderChain};
use xbt_primitives::tx::Tx;

fn vectors(name: &str) -> Value {
    let path = format!("{}/../../vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn u(v: &Value) -> u64 {
    v.as_u64().unwrap()
}

#[test]
fn every_stage_of_the_five_v2_headers() {
    let v = vectors("block_header_v2.json");
    let headers = v["headers"].as_array().unwrap();
    assert_eq!(headers.len(), 5);
    for hv in headers {
        let name = hv["name"].as_str().unwrap();
        let f = &hv["fields"];
        // the fields, serialized as the wire carries them
        let mut b = Vec::with_capacity(164);
        b.extend(((u(&f["nVersion"]) as u32) | header::V2_FLAG).to_le_bytes());
        let rev = |k: &str| {
            let mut x = h(&f[k]);
            x.reverse();
            x
        };
        b.extend(rev("hashPrevBlock"));
        b.extend(rev("hashMerkleRoot"));
        // the wire carries nTime - offset when the time-offset flag is set
        let flags = u(&f["m_flags"]) as u8;
        let (t, off) = (u(&f["nTime"]) as u32, u(&f["m_time_offset"]) as u32);
        b.extend((if flags & header::FLAG_USE_TIME_OFFSET != 0 { t.wrapping_sub(off) } else { t }).to_le_bytes());
        for k in ["nBits", "nNonce", "m_nonce2", "m_nonce3"] {
            b.extend((u(&f[k]) as u32).to_le_bytes());
        }
        // extranonce, xor key and the reserved slot are uint128/uint256: given in display order
        b.extend(rev("m_extranonce"));
        b.extend(off.to_le_bytes());
        b.extend((u(&f["m_txcount"]) as u16).to_le_bytes());
        b.push(flags);
        b.push(u(&f["m_xor_key_mask_clear_bits"]) as u8);
        b.extend(rev("m_xor_key"));
        b.extend((u(&f["m_height"]) as u32).to_le_bytes());
        b.extend(rev("m_mm_rhs"));
        assert_eq!(hex::encode(&b), hv["serialized"].as_str().unwrap(), "{name}: serialization");
        let s = header::v2_stages(&h(&hv["serialized"])).unwrap();
        for (k, got) in [("xor_key_hash", s.xor_key_hash.to_vec()), ("h1", s.h1.to_vec()), ("h2", s.h2.to_vec()), ("blake2b_1", s.blake2b_1.to_vec()),
                         ("blake2b_2", s.blake2b_2.to_vec()), ("mask", s.mask.to_vec()), ("block_hash", s.block_hash.to_vec()), ("asic_input", s.asic_input.clone())] {
            assert_eq!(hex::encode(&got), hv[k].as_str().unwrap(), "{name}: {k}");
        }
        assert_eq!(u(&hv["asic_profile"]), u64::from(flags & 3), "{name}: asic_profile");
        let hd = header::parse_header(&b).unwrap();
        assert_eq!((hd.time, hd.height), (t, u(&f["m_height"]) as u32), "{name}: parsed time and height");
    }
}

#[test]
fn the_knots_regtest_capture_hashes_links_and_chains() {
    let v = vectors("blake2b_regtest.json");
    let hdrs = v["headers"].as_array().unwrap();
    assert_eq!(hdrs.len(), 24);
    let (mut v1_raw, mut v2_raw): (Vec<Vec<u8>>, Vec<Vec<u8>>) = (vec![], vec![]);
    let mut first_v2: Option<(u32, String)> = None;
    for hv in hdrs {
        let raw = h(&hv["header"]);
        let (height, want) = (u(&hv["height"]) as u32, hv["hash"].as_str().unwrap());
        if header::header_size(&raw).unwrap() == header::V2_SIZE {
            let p = header::parse_header(&raw).unwrap();
            first_v2.get_or_insert((height, want.to_string()));
            assert_eq!((p.hash_hex().as_str(), p.height), (want, height), "height {height}");
            assert!(header::check_pow(&p, &header::ChainRules::regtest()).is_ok(), "height {height}: proof of work");
            v2_raw.push(raw);
        } else {
            assert_eq!(hex::encode(header::v1_hash(&raw).unwrap()), want, "height {height}");
            if first_v2.is_none() {
                v1_raw.push(raw);
            }
        }
    }
    for (height, b) in v["blocks"].as_object().unwrap() {
        let (hdr, txs) = header::parse_block(&h(&b["raw"])).unwrap();
        let ids: Vec<[u8; 32]> = txs.iter().map(Tx::txid_bytes).collect();
        let hash = if hdr.len() == header::V2_SIZE { header::parse_header(&hdr).unwrap().hash_hex() } else { hex::encode(header::v1_hash(&hdr).unwrap()) };
        assert_eq!(&header::merkle_root(&ids)[..], &hdr[36..68], "block {height}: merkle root");
        assert_eq!((txs.len() as u64, hash.as_str()), (u(&b["ntx"]), b["hash"].as_str().unwrap()), "block {height}");
    }
    // the chain: a checkpoint at the first v2 header, above the v1 headers the median needs, then
    // the rest connected under regtest rules
    let (cp_h, cp_hash) = first_v2.unwrap();
    let mut c = HeaderChain::new("regtest", (cp_h, &cp_hash), None, || u64::MAX / 2).unwrap();
    let n = c.prior_needed() as usize;
    assert!(v1_raw.len() >= n, "too few v1 headers below the first v2");
    c.set_checkpoint(&v2_raw[0], &v1_raw[v1_raw.len() - n..]).unwrap();
    let r = c.connect(cp_h, &v2_raw[1..]).unwrap();
    assert!(r.adopted && r.tip == cp_h + v2_raw.len() as u32 - 1, "chain tip {} not adopted", r.tip);
    // a broken link is refused
    let mut bad = v2_raw[2].clone();
    bad[4] ^= 1;
    assert!(c.connect(cp_h + 1, &[bad]).is_err(), "a header that does not link was accepted");
}
