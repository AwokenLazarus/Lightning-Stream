//! The proof a share carries: what an ASIC on this chain hashed, rebuilt from the Stratum V1 lines
//! alone, with nobody's word for the result.
//!
//! ```text
//! root = BLAKE2b-256(0x00 | coinb1 | en1 | en2 | coinb2)        52 bytes in all
//! work = prev(32) | nonce(8) | ntime(8) | root(32)              80 bytes
//! hash = BLAKE2b-256(work), read big-endian
//! ```
//!
//! This is `CBlockHeader::GetHash` for message profile 0, the only one Stratum V1 carries, before any
//! `xor_key` mask: a gateway checks a share with no mask too. The header's other fields are inside
//! `h2` in `coinb1`, which only the job's author can open, so this proves the hashing was done on
//! that job, not that the job is a good one. Both sides' meters use it: see [`crate::meter`].

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use serde_json::Value;

/// What a miner was given to hash, from `mining.notify`.
#[derive(Clone, Debug, PartialEq)]
pub struct Job {
    pub prev: [u8; 32],
    pub coinb1: Vec<u8>,
    pub coinb2: Vec<u8>,
}

/// The extranonce a channel was given, from the answer to its `mining.subscribe`.
#[derive(Clone, Debug, PartialEq)]
pub struct Session {
    pub en1: Vec<u8>,
    pub en2_size: usize,
}

fn blake2b256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2b::<U32>::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn hex_str(v: Option<&Value>, what: &str) -> Result<Vec<u8>, String> {
    let s = v.and_then(Value::as_str).ok_or_else(|| format!("{what} is not a string"))?;
    hex::decode(s).map_err(|_| format!("{what} is not hex"))
}

/// A job, from a `mining.notify` line; an error for one this check can't follow.
pub fn job_from_notify(v: &Value) -> Result<Job, String> {
    let p = v.get("params").and_then(Value::as_array).ok_or("a notify with no params")?;
    let prev: [u8; 32] = hex_str(p.get(1), "prevhash")?.try_into().map_err(|_| "prevhash is not 32 bytes")?;
    // the hidden form a miner hashes as it is: a block's own hash would need the node's tagged hash first
    if prev[..6] != [0u8; 6] {
        return Err("prevhash is not in its hidden form".into());
    }
    if !p.get(4).and_then(Value::as_array).is_some_and(Vec::is_empty) {
        return Err("a job with merkle branches".into());
    }
    Ok(Job { prev, coinb1: hex_str(p.get(2), "coinb1")?, coinb2: hex_str(p.get(3), "coinb2")? })
}

/// A channel's extranonce, from the answer to its `mining.subscribe`.
pub fn session_from_subscribe(v: &Value) -> Result<Session, String> {
    let r = v.get("result").and_then(Value::as_array).ok_or("a subscribe answer with no result")?;
    let en2_size = r.get(2).and_then(Value::as_u64).ok_or("a subscribe answer with no extranonce2 size")?;
    Ok(Session { en1: hex_str(r.get(1), "extranonce1")?, en2_size: en2_size as usize })
}

/// A share's 8-byte nonce or ntime, as a gateway reads it: 16 hex digits byte for byte, or 8 digits
/// as a number stored little-endian with the rest zero.
fn eight(v: Option<&Value>, what: &str) -> Result<[u8; 8], String> {
    let b = hex_str(v, what)?;
    match b.len() {
        8 => Ok(b.try_into().expect("8 bytes")),
        4 => {
            let mut out = [0u8; 8];
            for (o, c) in out.iter_mut().zip(b.iter().rev()) {
                *o = *c;
            }
            Ok(out)
        }
        n => Err(format!("{what} is {n} bytes")),
    }
}

/// The first four bytes of an ntime field as a little-endian number: a header-v2 hasher's time offset, which the node
/// adds to the job's wire time (the gateway's `datum_blake2b_share_ntime`). 8 hex digits are read as a number.
pub fn ntime_offset(v: Option<&Value>) -> Result<u32, String> {
    let b = eight(v, "ntime")?;
    Ok(u32::from_le_bytes(b[..4].try_into().expect("4 bytes")))
}

/// The hash of a share, from its `mining.submit` line, on the job and session it names.
pub fn share_hash(job: &Job, session: &Session, submit: &Value) -> Result<[u8; 32], String> {
    let p = submit.get("params").and_then(Value::as_array).ok_or("a submit with no params")?;
    let en2 = hex_str(p.get(2), "extranonce2")?;
    if en2.len() != session.en2_size {
        return Err(format!("extranonce2 is {} bytes, the session said {}", en2.len(), session.en2_size));
    }
    if 1 + job.coinb1.len() + session.en1.len() + en2.len() + job.coinb2.len() != 52 {
        return Err("the coinbase leaf is not 52 bytes".into());
    }
    let root = leaf_root(job, &session.en1, &en2);
    let (nonce, ntime) = (eight(p.get(4), "nonce")?, eight(p.get(3), "ntime")?);
    Ok(work_hash(&job.prev, &nonce, &ntime, &root))
}

/// The root an extranonce gives on a job.
pub fn leaf_root(job: &Job, en1: &[u8], en2: &[u8]) -> [u8; 32] {
    blake2b256(&[&[0], &job.coinb1, en1, en2, &job.coinb2])
}

/// What an ASIC hashes, and the hash.
pub fn work_hash(prev: &[u8; 32], nonce: &[u8; 8], ntime: &[u8; 8], root: &[u8; 32]) -> [u8; 32] {
    blake2b256(&[prev, nonce, ntime, root])
}

/// Does `hash` prove difficulty `d`? (`hash <= 2^224 / d`, read from its top 128 bits: difficulty 1 is
/// a hash whose top 32 bits are zero, one share in 2^32 hashes.)
pub fn proven_at(hash: &[u8; 32], d: f64) -> bool {
    if !d.is_finite() || d <= 0.0 {
        return false;
    }
    let top = u128::from_be_bytes(hash[..16].try_into().expect("16 bytes"));
    (top as f64) * d < 2f64.powi(96)
}

/// Where `hash` falls under difficulty `d`'s target, from 0 to 1. A miner whose target is `d` finds this
/// uniform; one searching for a harder target finds it bunched low.
pub fn target_fraction(hash: &[u8; 32], d: f64) -> f64 {
    let top = u128::from_be_bytes(hash[..16].try_into().expect("16 bytes"));
    ((top as f64) * d / 2f64.powi(96)).clamp(0.0, 1.0)
}
