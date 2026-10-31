//! The share check against the chain's own data: every real mainnet header in
//! `vectors/mainnet_headers_961630.json`, put in the Stratum form a miner was given, hashes to its
//! block id; the vectors copied from Bitcoin Knots and the pool's pinned header give their recorded
//! hashes; and shares a real gateway took from a real miner (`vectors/hashlink_real_shares.json`),
//! with nothing but their Stratum lines, give the block hashes that gateway logged.

use serde_json::{json, Value};
use xbt_hashlink::proof::{job_from_notify, proven_at, session_from_subscribe, share_hash, Job, Session};
use xbt_primitives::header;

fn vectors(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{}/../../vectors/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap()
}

/// A real header as the job and share lines a C gateway makes of it, its extranonce's four zero
/// bytes in `coinb1`: `000000 | h2 | 00000000`, 4 bytes of en1, 8 of en2.
fn stratum_form(raw: &[u8]) -> (Value, Value, Value) {
    let s = header::v2_stages(raw).unwrap();
    assert_eq!(raw[88..92], [0u8; 4], "a C gateway's extranonce starts with four zero bytes");
    let coinb1 = [&[0u8; 3][..], &s.h2, &[0u8; 4]].concat();
    let notify = json!({"id": null, "method": "mining.notify", "params": ["j", hex::encode(&s.asic_input[..32]), hex::encode(coinb1), "", [], "", "", "", true]});
    let subscribe = json!({"id": 1, "result": [[], hex::encode(&raw[92..96]), 8], "error": null});
    let ntime = [&raw[104..108], &raw[84..88]].concat();
    let submit = json!({"id": 9, "method": "mining.submit", "params": ["u", "j", hex::encode(&raw[96..104]), hex::encode(ntime), hex::encode(&raw[76..84])]});
    (notify, subscribe, submit)
}

#[test]
fn every_real_mainnet_header_hashes_to_its_block_id_from_the_stratum_form() {
    let v = vectors("mainnet_headers_961630.json");
    let start = v["start"].as_u64().unwrap();
    let mut checked = 0;
    let mut by_height = std::collections::BTreeMap::new();
    for (i, h) in v["headers"].as_array().unwrap().iter().enumerate() {
        let raw = hex::decode(h.as_str().unwrap()).unwrap();
        if raw.len() != header::V2_SIZE {
            continue;
        }
        let (notify, subscribe, submit) = stratum_form(&raw);
        let hash = share_hash(&job_from_notify(&notify).unwrap(), &session_from_subscribe(&subscribe).unwrap(), &submit).unwrap();
        let parsed = header::parse_header(&raw).unwrap();
        assert_eq!(hash, parsed.hash, "height {}", start + i as u64);
        // and it did meet that block's target: a hash at a difficulty far past any share's
        assert!(proven_at(&hash, 1e6), "height {}: {}", start + i as u64, hex::encode(hash));
        by_height.insert(start + i as u64, hex::encode(hash));
        checked += 1;
    }
    assert_eq!(checked, 61, "every BLAKE2b header in the file");
    // the chain's own anchor: the first BLAKE2b block, a hash this tree pins from Knots
    assert_eq!(by_height[&(header::MAINNET_CHECKPOINT.0 as u64)], header::MAINNET_CHECKPOINT.1);
}

/// One byte moved in any part of a share or its job, and the hash is another: nothing here is ignored.
#[test]
fn a_share_changed_anywhere_does_not_hash_to_its_block_id() {
    let v = vectors("mainnet_headers_961630.json");
    let raw = hex::decode(v["headers"].as_array().unwrap().last().unwrap().as_str().unwrap()).unwrap();
    let (notify, subscribe, submit) = stratum_form(&raw);
    let good = header::parse_header(&raw).unwrap().hash;
    let hash = |n: &Value, s: &Value, m: &Value| share_hash(&job_from_notify(n).unwrap(), &session_from_subscribe(s).unwrap(), m).unwrap();
    assert_eq!(hash(&notify, &subscribe, &submit), good);
    let flip = |v: &Value, path: &[&str], i: usize| {
        let mut v = v.clone();
        let mut at = &mut v;
        for p in path {
            at = &mut at[*p];
        }
        let s = at[i].as_str().unwrap().to_string();
        let last = s.len() - 1;
        let c = if &s[last..] == "0" { "1" } else { "0" };
        at[i] = Value::String(format!("{}{c}", &s[..last]));
        v
    };
    for i in [2, 3, 4] {
        assert_ne!(hash(&notify, &subscribe, &flip(&submit, &["params"], i)), good, "submit param {i}");
    }
    for i in [1, 2] {
        assert_ne!(hash(&flip(&notify, &["params"], i), &subscribe, &submit), good, "notify param {i}");
    }
    assert_ne!(hash(&notify, &flip(&subscribe, &["result"], 1), &submit), good, "extranonce1");
}

/// The vectors copied from Bitcoin Knots, profile 0: both extranonces in the 35-byte `coinb1` layout
/// (`000000 | h2`, 8 bytes of en1, 8 of en2), which is also ratum-gateway's. The hash before the mask.
#[test]
fn the_knots_vectors_give_their_recorded_hash_before_the_mask() {
    let v = vectors("block_header_v2.json");
    let mut checked = 0;
    for h in v["headers"].as_array().unwrap() {
        if h["fields"]["m_flags"].as_u64().unwrap() & 3 != 0 {
            continue;
        }
        let raw = hex::decode(h["serialized"].as_str().unwrap()).unwrap();
        let s = header::v2_stages(&raw).unwrap();
        let job = Job { prev: s.asic_input[..32].try_into().unwrap(), coinb1: [&[0u8; 3][..], &s.h2].concat(), coinb2: vec![] };
        let session = Session { en1: raw[88..96].to_vec(), en2_size: 8 };
        let ntime = [&raw[104..108], &raw[84..88]].concat();
        let submit = json!({"params": ["u", "j", hex::encode(&raw[96..104]), hex::encode(ntime), hex::encode(&raw[76..84])]});
        let hash = share_hash(&job, &session, &submit).unwrap();
        assert_eq!(hex::encode(hash), h["blake2b_2"].as_str().unwrap(), "{}", h["name"]);
        checked += 1;
    }
    assert_eq!(checked, 2);
}

/// The hash the pool pins so a refactor can't move a byte (`lazarus/protocol/src/pow.rs`
/// `pow_hash_is_stable`): another implementation's answer, with its `coinb1` as that test states it.
#[test]
fn the_pools_pinned_header_gives_the_pools_hash() {
    let coinb1 = hex::decode("000000f9ca68495589351ece0db5f2b73aca85626d01b0a93624f163115c2df5e57fbc00000000").unwrap();
    let mut prev = xbt_primitives::hash::tagged_hash("Bitcoin prevblock header, hashed", &[0x5a; 32]);
    prev[..6].fill(0);
    let job = Job { prev, coinb1: coinb1[..35].to_vec(), coinb2: vec![] };
    let session = Session { en1: vec![1, 2, 3, 4, 5, 6, 7, 8], en2_size: 8 };
    let nonce = [0x1234_5678u32.to_le_bytes(), 0x9abc_def0u32.to_le_bytes()].concat();
    let ntime = [0u32.to_le_bytes(), 0x0f0f_0f0fu32.to_le_bytes()].concat();
    let submit = json!({"params": ["u", "j", hex::encode([9u8, 10, 11, 12, 13, 14, 15, 16]), hex::encode(ntime), hex::encode(nonce)]});
    assert_eq!(hex::encode(share_hash(&job, &session, &submit).unwrap()), "6ee726ff19dc275c4024d488db4cc560338fe9723ea5fa5e5d46a0e54f00602f");
}

/// A real gateway's lines and a real miner's shares, through a rental: the hash is the one the gateway
/// logged as a block, or for pool shares one it accepted, and each proves the difficulty it was at.
#[test]
fn shares_a_real_gateway_took_prove_from_their_lines_alone() {
    let v = vectors("hashlink_real_shares.json");
    let mut checked = 0;
    for run in v["runs"].as_array().unwrap() {
        let session = session_from_subscribe(&run["subscribe_answer"]).unwrap();
        for s in run["shares"].as_array().unwrap() {
            let job = job_from_notify(&s["notify"]).unwrap();
            let hash = share_hash(&job, &session, &s["submit"]).unwrap();
            assert_eq!(hex::encode(hash), s["hash"].as_str().unwrap(), "{}", run["name"]);
            assert!(proven_at(&hash, s["difficulty"].as_f64().unwrap()), "{} {}", run["name"], s["hash"]);
            checked += 1;
        }
    }
    assert!(checked >= 3, "{checked}");
}

#[test]
fn a_share_or_job_this_check_cant_follow_is_an_error_not_a_guess() {
    let v = vectors("hashlink_real_shares.json");
    let run = &v["runs"][0];
    let s = &run["shares"][0];
    let session = session_from_subscribe(&run["subscribe_answer"]).unwrap();
    let job = job_from_notify(&s["notify"]).unwrap();
    // a wrong difficulty is no proof
    let hash = share_hash(&job, &session, &s["submit"]).unwrap();
    assert!(!proven_at(&hash, 1e30) && !proven_at(&hash, 0.0) && !proven_at(&hash, f64::NAN));
    // extranonce2 of another size
    let mut m = s["submit"].clone();
    m["params"][2] = json!("0011");
    assert!(share_hash(&job, &session, &m).is_err());
    // nonce and ntime of no size a gateway reads
    for i in [3, 4] {
        let mut m = s["submit"].clone();
        m["params"][i] = json!("001122");
        assert!(share_hash(&job, &session, &m).is_err(), "param {i}");
    }
    // a leaf that is not 52 bytes
    let long = Job { coinb2: vec![0], ..job.clone() };
    assert!(share_hash(&long, &session, &s["submit"]).is_err());
    // merkle branches, a prevhash not hidden, not hex
    for (i, bad) in [(4, json!(["00"])), (1, json!("ff".repeat(32))), (2, json!("zz"))] {
        let mut n = s["notify"].clone();
        n["params"][i] = bad;
        assert!(job_from_notify(&n).is_err(), "notify param {i}");
    }
}

/// A gateway reads 8 hex digits as a number stored little-endian, 16 byte for byte: firmware sends either.
#[test]
fn nonce_and_ntime_read_as_a_gateway_reads_them() {
    let v = vectors("hashlink_real_shares.json");
    let run = &v["runs"][0];
    let s = &run["shares"][0];
    let session = session_from_subscribe(&run["subscribe_answer"]).unwrap();
    let job = job_from_notify(&s["notify"]).unwrap();
    let with = |nonce: &str, ntime: &str| {
        let mut m = s["submit"].clone();
        m["params"][4] = json!(nonce);
        m["params"][3] = json!(ntime);
        share_hash(&job, &session, &m).unwrap()
    };
    assert_eq!(with("aabbccdd", "11223344"), with("ddccbbaa00000000", "4433221100000000"));
    assert_ne!(with("aabbccdd", "11223344"), with("aabbccdd00000000", "1122334400000000"));
}

/// What checking one share costs, on this machine, with real lines: the submit parsed, its hash rebuilt, the
/// difficulty compared. Run with `--release --ignored --nocapture`.
#[test]
#[ignore]
fn measure_the_cost_of_checking_one_share() {
    use std::time::Instant;
    use xbt_hashlink::proof;
    let v = vectors("hashlink_real_shares.json");
    let run = &v["runs"][0];
    let session = proof::session_from_subscribe(&run["subscribe_answer"]).unwrap();
    let share = &run["shares"][0];
    let job = proof::job_from_notify(&share["notify"]).unwrap();
    let line = share["submit"].to_string();
    let d = share["difficulty"].as_f64().unwrap();
    let n = 200_000u32;
    let mut best = [f64::MAX; 3];
    for _ in 0..7 {
        let t = Instant::now();
        for _ in 0..n {
            std::hint::black_box(serde_json::from_str::<Value>(std::hint::black_box(&line)).unwrap());
        }
        let parse = t.elapsed().as_nanos() as f64 / n as f64;
        let submit: Value = serde_json::from_str(&line).unwrap();
        let t = Instant::now();
        for _ in 0..n {
            let h = proof::share_hash(&job, &session, std::hint::black_box(&submit)).unwrap();
            std::hint::black_box(proof::proven_at(&h, d));
        }
        let hash = t.elapsed().as_nanos() as f64 / n as f64;
        let t = Instant::now();
        for _ in 0..n {
            let s: Value = serde_json::from_str(std::hint::black_box(&line)).unwrap();
            let h = proof::share_hash(&job, &session, &s).unwrap();
            std::hint::black_box(proof::proven_at(&h, d));
        }
        let whole = t.elapsed().as_nanos() as f64 / n as f64;
        for (b, x) in best.iter_mut().zip([parse, hash, whole]) {
            *b = b.min(x);
        }
    }
    let cpu = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let model = cpu.lines().find(|l| l.starts_with("model name") || l.starts_with("Model")).unwrap_or("").to_string();
    eprintln!("measure: share check on {model}: parse {:.0} ns, hash {:.0} ns, whole {:.0} ns, best of 7 x {n}; one core checks {:.0} shares a second",
              best[0], best[1], best[2], 1e9 / best[2]);
}

/// What a hashmaker can tell about a share from what it sees, when blocks are rarer than shares: a block target
/// `EXTRA` bits harder than the share target, as on a real chain. The hashmaker sees each share's raw hash and its
/// job, never the key. Real shares of real jobs, hashed as an ASIC does, under a fresh key for each template, with
/// `clear_bits` at the share's own bits; win or not is decided as the node decides it, on the masked hash.
///
/// Two classifiers, from the hashmaker's seat. The rule it would use on an unblinded job: a raw hash under the
/// block target is a win. And one that learns: it takes the value of the raw hash's bits just past `clear_bits`
/// that won most often on half the templates, labels and all, and calls that a win on the other half. Both should be
/// at chance. With the key, the same shares are classified exactly. With a null key the first rule finds every win,
/// which shows the test can see a classifier that works.
#[test]
fn a_hashmaker_cant_tell_a_winning_share_from_its_raw_hash_when_the_job_is_blinded() {
    use xbt_hashlink::{proof, standin};
    use xbt_primitives::hash::tagged_hash;
    const EXTRA: u32 = 4;
    // the key changes with the template, and every share of one template wins or not against the same mask: the
    // shares of a template aren't independent draws, the templates are. So many templates, a few shares each, and the
    // bound below widened by the design effect for clusters of that size (at most their size)
    const TEMPLATES: u64 = 1280;
    const SHARES_EACH: u64 = 8;
    // difficulty 2^-24: a share is a hash with its top 8 bits zero, so clear_bits is 8
    let d = 1.0 / (1u64 << 24) as f64;
    let clear_bits: u32 = 8;
    let block_bits = clear_bits + EXTRA;
    let top = |h: &[u8; 32], bits: u32| u32::from_be_bytes(h[..4].try_into().unwrap()) >> (32 - bits);
    let mask_of = |key: &[u8; 16]| {
        let mut m = tagged_hash("Bitcoin block hash PoW XOR mask", key);
        m[0] = 0; // the top 8 bits, clear_bits, are left as they are
        m
    };
    let en1 = "00000001";
    // (template, raw hash, mask)
    let mut shares: Vec<(u64, [u8; 32], [u8; 32])> = Vec::new();
    let mut seed = 0u64;
    for t in 0..TEMPLATES {
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&tagged_hash("test key", &t.to_le_bytes())[..8]);
        key[8..].copy_from_slice(&(t + 1).to_le_bytes());
        let mask = mask_of(&key);
        let notify = standin::notify_line(&format!("t{t}"), 1000 + t, 1_700_000_000, true);
        let job = proof::job_from_notify(&notify).unwrap();
        let session = proof::Session { en1: hex::decode(en1).unwrap(), en2_size: 8 };
        for _ in 0..SHARES_EACH {
            seed += 1;
            let (e2, nonce) = standin::find_share(&notify, en1, 8, d, seed).unwrap();
            let submit = json!({"id": 1, "method": "mining.submit", "params": ["u", format!("t{t}"), e2, "6553f100", nonce]});
            let raw = proof::share_hash(&job, &session, &submit).unwrap();
            assert!(proof::proven_at(&raw, d));
            assert_eq!(top(&raw, clear_bits), 0, "every share's top clear_bits are zero, win or not");
            shares.push((t, raw, mask));
        }
    }
    let masked = |raw: &[u8; 32], mask: &[u8; 32]| -> [u8; 32] { std::array::from_fn(|i| raw[i] ^ mask[i]) };
    let win = |raw: &[u8; 32], mask: &[u8; 32]| top(&masked(raw, mask), block_bits) == 0;
    let wins: Vec<bool> = shares.iter().map(|(_, r, m)| win(r, m)).collect();
    let n = shares.len() as f64;
    let base = wins.iter().filter(|w| **w).count() as f64 / n;
    // a 99.9% two-sided band around the rate 2^-EXTRA, for a count of k out of m
    let chance = 1.0 / (1u32 << EXTRA) as f64;
    let band = |m: f64| 3.29 * (chance * (1.0 - chance) / m).sqrt();
    // the rule for an unblinded job, on the raw hash
    let rule = |raw: &[u8; 32]| top(raw, block_bits) == 0;
    let picked: Vec<bool> = shares.iter().map(|(_, r, _)| rule(r)).collect();
    let picked_n = picked.iter().filter(|p| **p).count() as f64;
    let picked_wins = picked.iter().zip(&wins).filter(|(p, w)| **p && **w).count() as f64;
    let picked_rate = picked_wins / picked_n.max(1.0);
    let found = picked_wins / wins.iter().filter(|w| **w).count().max(1) as f64;
    // the learner: on templates 0..20, the value of the 4 bits past clear_bits that won most; tried on 20..40
    let bits = |raw: &[u8; 32]| top(raw, block_bits) & ((1 << EXTRA) - 1);
    let mut tally = [0u32; 16];
    for ((t, r, _), w) in shares.iter().zip(&wins) {
        if *t < TEMPLATES / 2 && *w {
            tally[bits(r) as usize] += 1;
        }
    }
    let best = (0..16).max_by_key(|v| tally[*v]).unwrap() as u32;
    let test: Vec<(&[u8; 32], bool)> = shares.iter().zip(&wins).filter(|((t, _, _), _)| *t >= TEMPLATES / 2).map(|((_, r, _), w)| (r, *w)).collect();
    let chosen: Vec<bool> = test.iter().filter(|(r, _)| bits(r) == best).map(|(_, w)| *w).collect();
    let learned_rate = chosen.iter().filter(|w| **w).count() as f64 / chosen.len().max(1) as f64;
    // balanced accuracy: the mean of the rates of wins called wins and of the rest called the rest. "Never a win" scores
    // 0.5 on it, however rare wins are. A 99% bound for a classifier that knows nothing, from both rates' spread
    let balanced = |pred: &[bool], truth: &[bool]| -> (f64, f64) {
        let (mut tp, mut tn, mut p, mut q) = (0f64, 0f64, 0f64, 0f64);
        for (x, y) in pred.iter().zip(truth) {
            if *y {
                p += 1.0;
                tp += *x as u8 as f64;
            } else {
                q += 1.0;
                tn += !*x as u8 as f64;
            }
        }
        let (tpr, tnr) = (tp / p.max(1.0), tn / q.max(1.0));
        let bound = 2.576 * 0.5 * (tpr * (1.0 - tpr) / p.max(1.0) + tnr * (1.0 - tnr) / q.max(1.0)).sqrt().max(0.5 / p.max(1.0));
        ((tpr + tnr) / 2.0, bound)
    };
    let cluster = (SHARES_EACH as f64).sqrt();
    let (raw_ba, raw_bound) = balanced(&picked, &wins);
    let raw_bound = raw_bound * cluster;
    let test_truth: Vec<bool> = test.iter().map(|(_, w)| *w).collect();
    let test_pred: Vec<bool> = test.iter().map(|(r, _)| bits(r) == best).collect();
    let (learned_ba, learned_bound) = balanced(&test_pred, &test_truth);
    let learned_bound = learned_bound * cluster;
    // with the key: the node's own rule
    let key_pred: Vec<bool> = shares.iter().map(|(_, r, m)| win(r, m)).collect();
    let (key_ba, _) = balanced(&key_pred, &wins);
    // with a null key, the same shares: the raw-hash rule against wins as they'd be unblinded
    let null_truth: Vec<bool> = shares.iter().map(|(_, r, _)| win(r, &[0u8; 32])).collect();
    let (null_ba, null_bound) = balanced(&picked, &null_truth);
    let null_wins = null_truth.iter().filter(|w| **w).count();
    eprintln!(
        "measure: {} shares, {} templates, {} wins, block {EXTRA} bits past the share (chance {chance:.4}, win rate {base:.4}). \
         Balanced accuracy, 99% bound for knowing nothing (widened x{cluster:.2} for {SHARES_EACH} shares a key): hashmaker's raw-hash rule {raw_ba:.4} +-{raw_bound:.4} \
         (picked {picked_n}, won {picked_wins}, found {found:.4} of the wins); learner across templates (value {best:#x}) {learned_ba:.4} +-{learned_bound:.4} \
         on {} shares; with the key {key_ba:.4}; under a null key the raw-hash rule {null_ba:.4} +-{null_bound:.4} ({null_wins} wins).",
        n, TEMPLATES, wins.iter().filter(|w| **w).count(), test.len()
    );
    let _ = (learned_rate, picked_rate);
    assert!(n >= 10_000.0);
    assert!((base - chance).abs() < band(n), "the win rate itself: {base}");
    assert!((raw_ba - 0.5).abs() < raw_bound, "from the hashmaker's view, at chance: {raw_ba} +-{raw_bound}");
    assert!((learned_ba - 0.5).abs() < learned_bound, "a learner across templates, at chance: {learned_ba} +-{learned_bound}");
    assert_eq!(key_ba, 1.0, "with the key, exact");
    assert!(null_ba > 0.5 + 10.0 * null_bound && null_wins > 0, "under a null key the raw hash tells the wins: {null_ba}");
}
