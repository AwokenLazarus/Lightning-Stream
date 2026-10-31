//! Trust before renting: a paid test slice's result, and a signed delivery history on Nostr.
//!
//! **A test slice** is an ordinary rental with a budget of one slice: the hashtaker's own gateway
//! checks every share, the slice is paid like any other, and [`trial_result`] reads the rental's
//! report into what the hashtaker wants to know before renting more: the speed delivered against
//! the speed advertised, the stale and rejected shares, and the share round trip.
//!
//! **A delivery record** ([`Attestation`]) is published by a hashtaker after a rental, if it chooses
//! to. It is a Nostr event (kind 30078, NIP-78 application data) signed by the hashtaker's link
//! key used as a Nostr key, so the hashmaker, who saw that key on the link, can tell it is the
//! hashtaker it served. It names the hashmaker's link key, a commitment to the rental (a hash, not
//! the rental's name), the work the hashtaker's gateway accepted, what was paid, and a hash of the
//! signed work receipts behind the payments. It names no pool, payout, user name or address, and
//! its time is rounded down to the hour.
//!
//! **A hashmaker's summary** ([`Summary`]) is its own signed list of the rentals it served, by the
//! same commitment, with what it was paid and the same receipts hash. It is signed by the Nostr key
//! its listing is bound to. A record that matches an entry in the summary is confirmed by both sides.
//!
//! **Neither proves anything to a third party**: Lightning payments are private, and keys are free, so one
//! person can write records under many keys and confirm them as the hashmaker. [`aggregate`] makes no score
//! of them: it counts records and the keys that signed them, drops a hashmaker's records about itself, counts
//! each key for at most a few rentals, and shows one line per key. The only evidence this app checks is the
//! hashtaker's own rentals, a test slice first. Payment never depends on any of it ([`crate::order`]).

use secp256k1::{PublicKey, SecretKey, XOnlyPublicKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use xbt_nostr::event::{tag, Event, Keys};

/// NIP-78 application data.
pub const KIND: u64 = 30078;
pub const ATTEST_TOPIC: &str = "lightning-stream-hash-attest";
pub const SUMMARY_TOPIC: &str = "lightning-stream-hash-summary";
/// The longest content a record may have (the relay refuses more).
pub const ATTEST_MAX: usize = 2048;
/// The longest content a summary may have, and how many rentals it lists at most.
pub const SUMMARY_MAX: usize = 16384;
pub const SUMMARY_RENTALS: usize = 40;
/// Rentals counted per hashtaker key for one hashmaker (its most recent).
pub const PER_KEY: usize = 3;
/// Hashes in one TH-hour.
const TH_HOUR: f64 = 1e12 * 3600.0;

/// The commitment both sides compute for a rental: it names the rental without saying its name.
pub fn commit(rental: &str, hashtaker: &PublicKey, hashmaker: &PublicKey) -> String {
    let line = format!("xbt-hashlink/rental/0|{rental}|{}|{}", hex::encode(hashtaker.serialize()), hex::encode(hashmaker.serialize()));
    hex::encode(Sha256::digest(line.as_bytes()))
}

/// The hash of the first `paid` signed work receipts, in slice order: what the payments were for.
/// Both sides hold the same signed receipts (the hashtaker sends each with its payment), so both
/// compute the same hash.
pub fn receipts_hash(receipts: &[Value], paid: u64) -> String {
    let mut by_slice: Vec<(u64, &str)> = receipts.iter().filter_map(|r| Some((r.get("slice")?.as_u64()?, r.get("sig")?.as_str()?))).collect();
    by_slice.sort();
    by_slice.dedup_by_key(|(s, _)| *s);
    let mut h = Sha256::new();
    h.update(b"xbt-hashlink/receipts/0");
    for (_, sig) in by_slice.into_iter().take(paid as usize) {
        h.update(b"|");
        h.update(sig.as_bytes());
    }
    hex::encode(h.finalize())
}

fn xonly(pk: &PublicKey) -> XOnlyPublicKey {
    pk.x_only_public_key().0
}

fn parse_key(s: &str) -> Option<PublicKey> {
    PublicKey::from_slice(&hex::decode(s).ok()?).ok()
}

fn hour(unix: u64) -> u64 {
    unix - unix % 3600
}

/// A hashtaker's record of one rental (see the module documentation).
#[derive(Clone, Debug, PartialEq)]
pub struct Attestation {
    pub hashmaker: PublicKey,
    pub hashtaker: PublicKey,
    pub commit: String,
    pub paid_slices: u64,
    pub paid_msat: u64,
    pub slice_work: u128,
    /// Work the hashtaker's gateway accepted, in hashes.
    pub work: u128,
    pub duration_s: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub stale: u64,
    pub advertised_hs: u64,
    pub delivered_hs: u64,
    pub latency_ms_p50: Option<u32>,
    pub receipts_hash: String,
    pub trial: bool,
    /// When it ended, Unix seconds rounded down to the hour.
    pub ended_at: u64,
}

impl Attestation {
    pub fn to_json(&self) -> Value {
        json!({
            "v": 1, "hashmaker": hex::encode(self.hashmaker.serialize()), "hashtaker": hex::encode(self.hashtaker.serialize()),
            "commit": self.commit, "paidSlices": self.paid_slices, "paidMsat": self.paid_msat, "sliceWork": self.slice_work.to_string(),
            "work": self.work.to_string(), "durationS": self.duration_s, "accepted": self.accepted, "rejected": self.rejected,
            "stale": self.stale, "advertisedHs": self.advertised_hs.to_string(), "deliveredHs": self.delivered_hs.to_string(),
            "latencyMsP50": self.latency_ms_p50, "receiptsHash": self.receipts_hash, "trial": self.trial, "endedAt": hour(self.ended_at),
        })
    }

    pub fn from_json(v: &Value) -> Option<Attestation> {
        let n = |k: &str| v.get(k)?.as_u64();
        let big = |k: &str| v.get(k)?.as_str()?.parse::<u128>().ok();
        if n("v")? != 1 {
            return None;
        }
        let a = Attestation {
            hashmaker: parse_key(v.get("hashmaker")?.as_str()?)?,
            hashtaker: parse_key(v.get("hashtaker")?.as_str()?)?,
            commit: v.get("commit")?.as_str().filter(|c| c.len() == 64 && c.bytes().all(|b| b.is_ascii_hexdigit()))?.to_string(),
            paid_slices: n("paidSlices")?,
            paid_msat: n("paidMsat")?,
            slice_work: big("sliceWork").filter(|w| *w > 0)?,
            work: big("work")?,
            duration_s: n("durationS")?,
            accepted: n("accepted")?,
            rejected: n("rejected")?,
            stale: n("stale")?,
            advertised_hs: big("advertisedHs")? as u64,
            delivered_hs: big("deliveredHs")? as u64,
            latency_ms_p50: v.get("latencyMsP50").and_then(Value::as_u64).map(|l| l.min(u32::MAX as u64) as u32),
            receipts_hash: v.get("receiptsHash")?.as_str()?.to_string(),
            trial: v.get("trial").and_then(Value::as_bool).unwrap_or(false),
            ended_at: n("endedAt")?,
        };
        Some(a)
    }

    /// The record as a Nostr event, signed by the hashtaker's link key `key` used as a Nostr key.
    pub fn event(&self, key: &SecretKey, created_at: u64) -> Result<Event, String> {
        if PublicKey::from_secret_key(secp256k1::SECP256K1, key) != self.hashtaker {
            return Err("the key is not the record's hashtaker".into());
        }
        let content = self.to_json().to_string();
        if content.len() > ATTEST_MAX {
            return Err("the record is too long".into());
        }
        let tags = vec![
            tag("d", &format!("{ATTEST_TOPIC}:{}", self.commit)),
            tag("t", ATTEST_TOPIC),
            tag("p", &hex::encode(xonly(&self.hashmaker).serialize())),
        ];
        Ok(Event::sign(&Keys::new(*key), created_at, KIND, tags, content))
    }

    /// Read and check an event as [`Self::event`] wrote it: its signature, its tags, and that its
    /// author is the hashtaker it names.
    pub fn read_event(ev: &Event) -> Result<Attestation, String> {
        if ev.kind != KIND || !ev.verify() {
            return Err("not a signed application-data event".into());
        }
        if ev.content.len() > ATTEST_MAX {
            return Err("too long".into());
        }
        if ev.tag("t") != Some(ATTEST_TOPIC) {
            return Err("not a delivery record".into());
        }
        let a = Attestation::from_json(&serde_json::from_str(&ev.content).map_err(|_| "not JSON")?).ok_or("not a delivery record")?;
        if ev.tag("d") != Some(format!("{ATTEST_TOPIC}:{}", a.commit).as_str()) {
            return Err("the d tag is not the record's rental".into());
        }
        if ev.tag("p") != Some(hex::encode(xonly(&a.hashmaker).serialize()).as_str()) {
            return Err("the p tag is not the record's hashmaker".into());
        }
        if ev.pubkey != hex::encode(xonly(&a.hashtaker).serialize()) {
            return Err("not signed by the hashtaker it names".into());
        }
        Ok(a)
    }
}

/// One rental in a hashmaker's summary.
#[derive(Clone, Debug, PartialEq)]
pub struct Served {
    pub commit: String,
    pub hashtaker: PublicKey,
    pub paid_slices: u64,
    pub paid_msat: u64,
    pub work: u128,
    pub receipts_hash: String,
    pub ended_at: u64,
}

/// A hashmaker's signed list of the rentals it served (see the module documentation).
#[derive(Clone, Debug, PartialEq)]
pub struct Summary {
    pub hashmaker: PublicKey,
    pub rentals: Vec<Served>,
}

impl Summary {
    pub fn to_json(&self) -> Value {
        let rentals: Vec<Value> = self
            .rentals
            .iter()
            .map(|r| {
                json!({"commit": r.commit, "hashtaker": hex::encode(r.hashtaker.serialize()), "paidSlices": r.paid_slices,
                       "paidMsat": r.paid_msat, "work": r.work.to_string(), "receiptsHash": r.receipts_hash, "endedAt": hour(r.ended_at)})
            })
            .collect();
        json!({"v": 1, "hashmaker": hex::encode(self.hashmaker.serialize()), "rentals": rentals})
    }

    pub fn from_json(v: &Value) -> Option<Summary> {
        if v.get("v")?.as_u64()? != 1 {
            return None;
        }
        let rentals = v
            .get("rentals")?
            .as_array()?
            .iter()
            .filter_map(|r| {
                Some(Served {
                    commit: r.get("commit")?.as_str()?.to_string(),
                    hashtaker: parse_key(r.get("hashtaker")?.as_str()?)?,
                    paid_slices: r.get("paidSlices")?.as_u64()?,
                    paid_msat: r.get("paidMsat")?.as_u64()?,
                    work: r.get("work")?.as_str()?.parse().ok()?,
                    receipts_hash: r.get("receiptsHash")?.as_str()?.to_string(),
                    ended_at: r.get("endedAt")?.as_u64()?,
                })
            })
            .collect();
        Some(Summary { hashmaker: parse_key(v.get("hashmaker")?.as_str()?)?, rentals })
    }

    /// The summary as a Nostr event by `nostr`, the key the hashmaker's listing is bound to. The
    /// newest [`SUMMARY_RENTALS`] rentals are kept.
    pub fn event(&self, nostr: &Keys, created_at: u64) -> Result<Event, String> {
        let mut s = self.clone();
        s.rentals.sort_by_key(|r| std::cmp::Reverse(r.ended_at));
        s.rentals.truncate(SUMMARY_RENTALS);
        let content = s.to_json().to_string();
        if content.len() > SUMMARY_MAX {
            return Err("the summary is too long".into());
        }
        let tags = vec![
            tag("d", &format!("{SUMMARY_TOPIC}:{}", hex::encode(self.hashmaker.serialize()))),
            tag("t", SUMMARY_TOPIC),
            tag("p", &hex::encode(xonly(&self.hashmaker).serialize())),
        ];
        Ok(Event::sign(nostr, created_at, KIND, tags, content))
    }

    /// Read and check a summary event; `listing_author` is the Nostr key the hashmaker's listing is
    /// bound to (a summary by any other key is not the hashmaker's).
    pub fn read_event(ev: &Event, listing_author: &str) -> Result<Summary, String> {
        if ev.kind != KIND || !ev.verify() {
            return Err("not a signed application-data event".into());
        }
        if ev.tag("t") != Some(SUMMARY_TOPIC) || ev.content.len() > SUMMARY_MAX {
            return Err("not a hashmaker summary".into());
        }
        if ev.pubkey != listing_author {
            return Err("not signed by the key the listing is bound to".into());
        }
        let s = Summary::from_json(&serde_json::from_str(&ev.content).map_err(|_| "not JSON")?).ok_or("not a hashmaker summary")?;
        if ev.tag("d") != Some(format!("{SUMMARY_TOPIC}:{}", hex::encode(s.hashmaker.serialize())).as_str()) {
            return Err("the d tag is not the summary's hashmaker".into());
        }
        Ok(s)
    }
}

/// The records asked for about each hashmaker.
pub const RECORDS_PER_HASHMAKER: usize = 200;

/// What to ask relays for, for the hashmakers on show (each with the Nostr key its listing is bound to): one
/// filter of records for each hashmaker, by its `p` tag, and one of summaries by those listings' keys. A relay
/// answers each filter with its own newest events, so records about other hashmakers (anyone can publish
/// those, as many as they like) can't push one hashmaker's records out of the answer, and only a listing's
/// own key can write the summary asked for.
pub fn filters(hashmakers: &[(PublicKey, String)]) -> Vec<Value> {
    let mut out: Vec<Value> = hashmakers
        .iter()
        .map(|(h, _)| json!({"kinds": [KIND], "#t": [ATTEST_TOPIC], "#p": [hex::encode(xonly(h).serialize())], "limit": RECORDS_PER_HASHMAKER}))
        .collect();
    let authors: BTreeSet<&String> = hashmakers.iter().map(|(_, a)| a).filter(|a| !a.is_empty()).collect();
    if !authors.is_empty() {
        out.push(json!({"kinds": [KIND], "#t": [SUMMARY_TOPIC], "authors": authors, "limit": authors.len() * 4}));
    }
    out
}

/// One hashmaker's delivery records as the app shows them, from the records and the hashmaker's summary.
/// Nothing in a record is checked by this app: anyone can sign one, under as many keys as they like, and a
/// hashmaker can confirm its own. So no score is made of them. They are counted, with the keys that signed
/// them, each key for at most [`PER_KEY`] of its newest; the newest few are shown one for each key, so one
/// key's many records fill no more than one line.
pub fn aggregate(hashmaker: &PublicKey, listing_author: &str, advertised_hs: u64, events: &[Event]) -> Value {
    // the newest summary by the listing's key
    let summary = events
        .iter()
        .filter(|e| e.tag("t") == Some(SUMMARY_TOPIC))
        .filter_map(|e| Summary::read_event(e, listing_author).ok().filter(|s| s.hashmaker == *hashmaker).map(|s| (e.created_at, s)))
        .max_by_key(|(t, _)| *t)
        .map(|(_, s)| s);
    let records: Vec<Attestation> = events.iter().filter(|e| e.tag("t") == Some(ATTEST_TOPIC)).filter_map(|e| Attestation::read_event(e).ok()).collect();
    let self_x = xonly(hashmaker);
    let mut mine: Vec<&Attestation> = records
        .iter()
        // a record is one per rental (the newest per commitment), and a hashmaker's records about
        // itself (its own link key, or its listing's Nostr key) do not count
        .filter(|a| a.hashmaker == *hashmaker && xonly(&a.hashtaker) != self_x && hex::encode(xonly(&a.hashtaker).serialize()) != listing_author)
        .collect();
    mine.sort_by_key(|a| std::cmp::Reverse(a.ended_at));
    let mut seen_commit = BTreeSet::new();
    mine.retain(|a| seen_commit.insert(a.commit.clone()));
    let mut per_key: BTreeMap<[u8; 33], usize> = BTreeMap::new();
    let (mut verified_work, mut all_work) = (0f64, 0f64);
    let (mut counted, mut confirmed, mut disputed) = (0u64, 0u64, 0u64);
    let mut recent = Vec::new();
    for a in &mine {
        let n = per_key.entry(a.hashtaker.serialize()).or_default();
        *n += 1;
        if *n > PER_KEY {
            continue;
        }
        counted += 1;
        let matched = summary.as_ref().and_then(|s| s.rentals.iter().find(|r| r.commit == a.commit && r.hashtaker == a.hashtaker));
        let ok = matched.is_some_and(|r| r.paid_slices == a.paid_slices && r.receipts_hash == a.receipts_hash);
        if matched.is_some() && !ok {
            disputed += 1;
        }
        if ok {
            confirmed += 1;
        }
        let ratio = if a.advertised_hs > 0 { (a.delivered_hs as f64 / a.advertised_hs as f64).clamp(0.0, 2.0) } else { 0.0 };
        if recent.len() < 5 && *n == 1 {
            recent.push(json!({
                "endedAt": a.ended_at, "deliveredHs": a.delivered_hs.to_string(), "ratio": ratio, "trial": a.trial,
                "paidSats": a.paid_msat / 1000, "staleShare": stale_share(a),
            }));
        }
        let work = matched.filter(|_| ok).map(|r| r.work.min(a.work)).unwrap_or(a.work) as f64;
        all_work += work;
        if ok {
            verified_work += work;
        }
    }
    json!({
        "records": mine.len(), "keys": per_key.len(), "counted": counted, "confirmed": confirmed, "disputed": disputed,
        "verifiedThHours": verified_work / TH_HOUR, "claimedThHours": all_work / TH_HOUR,
        "advertisedHs": advertised_hs.to_string(), "recent": recent,
        "hashmakerSays": summary.map(|s| json!({
            "rentals": s.rentals.len(), "paidSats": s.rentals.iter().map(|r| r.paid_msat).sum::<u64>() / 1000,
            "thHours": s.rentals.iter().map(|r| r.work as f64).sum::<f64>() / TH_HOUR,
        })),
    })
}

fn stale_share(a: &Attestation) -> f64 {
    let all = a.accepted + a.rejected;
    if all == 0 {
        0.0
    } else {
        a.stale as f64 / all as f64
    }
}

/// What a finished (or running) rental showed, from the hashtaker's report and when it started:
/// the speed delivered against the speed advertised, stale and rejected shares, and the share round
/// trip. The delivered speed is the accepted work over the time from the start to the last finished
/// slice (or to now while nothing has finished), so it includes the first seconds of connecting.
pub fn trial_result(report: &Value, started_ms: u64, now_ms: u64, advertised_hs: u64) -> Value {
    let work: f64 = report.pointer("/meter/work").and_then(Value::as_str).and_then(|w| w.parse().ok()).unwrap_or(0.0);
    let end = report
        .get("slicesDone")
        .and_then(Value::as_array)
        .and_then(|s| s.last())
        .and_then(|s| s.get("atMs"))
        .and_then(Value::as_u64)
        .unwrap_or(now_ms);
    let secs = (end.saturating_sub(started_ms)) as f64 / 1000.0;
    let delivered = if secs > 0.0 { work / secs } else { 0.0 };
    let n = |p: &str| report.pointer(p).and_then(Value::as_u64).unwrap_or(0);
    let (acc, rej, stale) = (n("/meter/accepted"), n("/meter/rejected"), n("/meter/stale"));
    let all = (acc + rej).max(1) as f64;
    json!({
        "deliveredHs": delivered.round() as u64, "advertisedHs": advertised_hs,
        "ratio": if advertised_hs > 0 { Value::from(delivered / advertised_hs as f64) } else { Value::Null },
        "accepted": acc, "rejected": rej, "stale": stale,
        "staleShare": stale as f64 / all, "rejectedShare": rej as f64 / all,
        "latencyMsP50": report.pointer("/latencyMs/p50"), "latencyMsP95": report.pointer("/latencyMs/p95"),
        "seconds": secs, "paidSlices": n("/paidSlices"), "spentMsat": n("/spentMsat"),
    })
}

/// The record a hashtaker may publish for a rental it ran: from its report, the rental's name and
/// start, both link keys and the advertised speed.
#[allow(clippy::too_many_arguments)]
pub fn attestation_of(report: &Value, rental: &str, started_ms: u64, hashtaker: &PublicKey, hashmaker: &PublicKey, advertised_hs: u64, trial: bool, ended_unix: u64) -> Option<Attestation> {
    let paid = report.get("paidSlices")?.as_u64()?;
    let receipts: Vec<Value> = report.get("receipts").and_then(Value::as_array).cloned().unwrap_or_default();
    let r = trial_result(report, started_ms, crate::now_ms(), advertised_hs);
    let slice_work: u128 = report.pointer("/terms/sliceWork")?.as_str()?.parse().ok()?;
    Some(Attestation {
        hashmaker: *hashmaker,
        hashtaker: *hashtaker,
        commit: commit(rental, hashtaker, hashmaker),
        paid_slices: paid,
        paid_msat: report.get("spentMsat").and_then(Value::as_u64).unwrap_or(0),
        slice_work,
        work: report.pointer("/meter/work")?.as_str()?.parse().ok()?,
        duration_s: r["seconds"].as_f64().unwrap_or(0.0) as u64,
        accepted: r["accepted"].as_u64().unwrap_or(0),
        rejected: r["rejected"].as_u64().unwrap_or(0),
        stale: r["stale"].as_u64().unwrap_or(0),
        advertised_hs,
        delivered_hs: r["deliveredHs"].as_u64().unwrap_or(0),
        latency_ms_p50: r["latencyMsP50"].as_u64().map(|l| l as u32),
        receipts_hash: receipts_hash(&receipts, paid),
        trial,
        ended_at: ended_unix,
    })
}

/// The hashmaker's entry for a rental that ended, from its finished-rental report.
pub fn served_of(finished: &Value, hashmaker: &PublicKey, ended_unix: u64) -> Option<Served> {
    let hashtaker = parse_key(finished.get("buyer")?.as_str()?)?;
    let rental = finished.get("rental")?.as_str()?;
    let paid = finished.get("paid")?.as_u64()?;
    if paid == 0 {
        return None;
    }
    let receipts: Vec<Value> = finished.get("receipts").and_then(Value::as_array).cloned().unwrap_or_default();
    Some(Served {
        commit: commit(rental, &hashtaker, hashmaker),
        hashtaker,
        paid_slices: paid,
        paid_msat: finished.get("earnedMsat").and_then(Value::as_u64).unwrap_or(0),
        work: finished.pointer("/meter/work")?.as_str()?.parse().ok()?,
        receipts_hash: receipts_hash(&receipts, paid),
        ended_at: ended_unix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sk(b: u8) -> SecretKey {
        SecretKey::from_slice(&[b; 32]).unwrap()
    }
    fn pk(b: u8) -> PublicKey {
        PublicKey::from_secret_key(secp256k1::SECP256K1, &sk(b))
    }
    fn receipts(n: u64) -> Vec<Value> {
        (1..=n).rev().map(|s| json!({"slice": s, "sig": format!("sig{s}")})).collect()
    }
    fn record(taker: u8, maker: u8, rental: &str, paid: u64, delivered: u64, ended: u64) -> Attestation {
        Attestation {
            hashmaker: pk(maker),
            hashtaker: pk(taker),
            commit: commit(rental, &pk(taker), &pk(maker)),
            paid_slices: paid,
            paid_msat: paid * 12_000,
            slice_work: 1 << 47,
            work: (paid as u128) << 47,
            duration_s: 600,
            accepted: 100,
            rejected: 2,
            stale: 1,
            advertised_hs: 4_000_000_000_000,
            delivered_hs: delivered,
            latency_ms_p50: Some(110),
            receipts_hash: receipts_hash(&receipts(paid), paid),
            trial: false,
            ended_at: ended,
        }
    }

    #[test]
    fn both_sides_compute_the_same_commitment_and_receipts_hash() {
        assert_eq!(commit("r1", &pk(1), &pk(2)), commit("r1", &pk(1), &pk(2)));
        assert_ne!(commit("r1", &pk(1), &pk(2)), commit("r2", &pk(1), &pk(2)));
        assert_ne!(commit("r1", &pk(1), &pk(2)), commit("r1", &pk(2), &pk(1)));
        // order of arrival and a repeated receipt do not change it; a slice not paid is not in it
        let mut a = receipts(3);
        a.push(json!({"slice": 2, "sig": "sig2"}));
        assert_eq!(receipts_hash(&a, 3), receipts_hash(&receipts(3), 3));
        assert_ne!(receipts_hash(&receipts(3), 2), receipts_hash(&receipts(3), 3));
        assert_eq!(receipts_hash(&receipts(4), 3), receipts_hash(&receipts(3), 3));
    }

    #[test]
    fn a_record_is_signed_by_its_hashtaker_and_tampering_shows() {
        let a = record(1, 2, "r1", 5, 3_900_000_000_000, 7_205);
        let ev = a.event(&sk(1), 9_000).unwrap();
        let back = Attestation::read_event(&ev).unwrap();
        assert_eq!(back.ended_at, 7_200, "rounded down to the hour");
        assert_eq!(back.commit, a.commit);
        assert!(a.event(&sk(3), 9_000).is_err(), "only the hashtaker it names signs it");
        // another key re-signing the same record: not its hashtaker
        let forged = Event::sign(&Keys::new(sk(3)), 9_000, KIND, ev.tags.clone(), ev.content.clone());
        assert!(Attestation::read_event(&forged).is_err());
        // a changed number breaks the signature
        let mut changed = ev.clone();
        changed.content = changed.content.replace("\"paidSlices\":5", "\"paidSlices\":50");
        assert!(Attestation::read_event(&changed).is_err());
        // a record about another hashmaker than its p tag says
        let tags: Vec<Vec<String>> = ev.tags.iter().map(|t| if t[0] == "p" { tag("p", &hex::encode(xonly(&pk(9)).serialize())) } else { t.clone() }).collect();
        assert!(Attestation::read_event(&Event::sign(&Keys::new(sk(1)), 9_000, KIND, tags, ev.content.clone())).is_err());
        // no address, pool or user name is in it
        for word in ["addr", "pool", "user", "payout", "rental\""] {
            assert!(!ev.content.contains(word), "{word}");
        }
    }

    #[test]
    fn a_summary_counts_only_from_the_listings_key() {
        let maker = Keys::new(sk(20));
        let s = Summary { hashmaker: pk(2), rentals: vec![Served { commit: "c".into(), hashtaker: pk(1), paid_slices: 1, paid_msat: 12_000, work: 1 << 47, receipts_hash: "h".into(), ended_at: 3_700 }] };
        let ev = s.event(&maker, 9_000).unwrap();
        assert_eq!(Summary::read_event(&ev, &maker.public_hex()).unwrap().rentals[0].ended_at, 3_600);
        assert!(Summary::read_event(&ev, &Keys::new(sk(21)).public_hex()).is_err());
        // the newest rentals are kept when there are many
        let many = Summary { hashmaker: pk(2), rentals: (0..100).map(|i| Served { ended_at: i * 3600, ..s.rentals[0].clone() }).collect() };
        let back = Summary::read_event(&many.event(&maker, 1).unwrap(), &maker.public_hex()).unwrap();
        assert_eq!(back.rentals.len(), SUMMARY_RENTALS);
        assert_eq!(back.rentals[0].ended_at, 99 * 3600);
    }

    #[test]
    fn the_history_counts_records_and_keys_and_refuses_gaming() {
        let maker_nostr = Keys::new(sk(20));
        let maker = pk(2);
        let good = record(1, 2, "r1", 4, 4_000_000_000_000, 10_000);
        let unconfirmed = record(3, 2, "r2", 4, 2_000_000_000_000, 9_000);
        // the hashmaker's own key writing records about itself
        let selfish = record(2, 2, "r3", 100, 8_000_000_000_000, 8_000);
        // key 1 also rented from another hashmaker: it has history
        let elsewhere = record(1, 7, "r4", 1, 1_000_000_000_000, 7_000);
        let summary = Summary {
            hashmaker: maker,
            rentals: vec![Served { commit: good.commit.clone(), hashtaker: pk(1), paid_slices: 4, paid_msat: 48_000, work: good.work, receipts_hash: good.receipts_hash.clone(), ended_at: 10_000 }],
        };
        let mut events = vec![
            good.event(&sk(1), 1).unwrap(),
            unconfirmed.event(&sk(3), 1).unwrap(),
            selfish.event(&sk(2), 1).unwrap(),
            elsewhere.event(&sk(1), 1).unwrap(),
            summary.event(&maker_nostr, 1).unwrap(),
        ];
        let h = aggregate(&maker, &maker_nostr.public_hex(), 4_000_000_000_000, &events);
        assert_eq!(h["records"], 2, "its own record about itself is dropped");
        assert_eq!(h["confirmed"], 1);
        assert_eq!(h["disputed"], 0);
        assert_eq!(h["keys"], 2);
        let verified = h["verifiedThHours"].as_f64().unwrap();
        assert!((verified - ((4u128 << 47) as f64 / TH_HOUR)).abs() < 1e-9, "{verified}");
        // no score made of them: each record says its own
        assert!(h.get("deliveredVsAdvertised").is_none(), "{h}");
        let ratios: Vec<f64> = h["recent"].as_array().unwrap().iter().map(|r| r["ratio"].as_f64().unwrap()).collect();
        assert_eq!(ratios, [1.0, 0.5]);
        assert_eq!(h["hashmakerSays"]["rentals"], 1);

        // a summary that disagrees on what was paid: disputed, not confirmed
        let mut wrong = summary.clone();
        wrong.rentals[0].paid_slices = 9;
        events.push(wrong.event(&maker_nostr, 2).unwrap());
        let h = aggregate(&maker, &maker_nostr.public_hex(), 4_000_000_000_000, &events);
        assert_eq!((h["confirmed"].as_u64(), h["disputed"].as_u64()), (Some(0), Some(1)));

        // one key's many rentals count for at most PER_KEY
        let flood: Vec<Event> = (0..10).map(|i| record(5, 2, &format!("f{i}"), 1, 4_000_000_000_000, 1000 + i).event(&sk(5), 1).unwrap()).collect();
        let h = aggregate(&maker, &maker_nostr.public_hex(), 4_000_000_000_000, &flood);
        assert_eq!((h["records"].as_u64(), h["counted"].as_u64(), h["keys"].as_u64()), (Some(10), Some(PER_KEY as u64), Some(1)));
        // and fill one line of the newest, however many it writes
        let mut mixed = flood.clone();
        mixed.push(good.event(&sk(1), 1).unwrap());
        let h = aggregate(&maker, &maker_nostr.public_hex(), 4_000_000_000_000, &mixed);
        assert_eq!(h["recent"].as_array().unwrap().len(), 2, "{h}");
        // a summary by another key than the listing's is not the hashmaker's
        let h = aggregate(&maker, &Keys::new(sk(21)).public_hex(), 4_000_000_000_000, &events[..5]);
        assert_eq!(h["confirmed"], 0);
        assert!(h["hashmakerSays"].is_null());
    }

    #[test]
    fn a_test_slice_reads_as_speed_stales_and_round_trip() {
        let report = json!({
            "meter": {"work": ((1u128 << 47) * 2).to_string(), "accepted": 98, "rejected": 2, "stale": 1},
            "latencyMs": {"p50": 110, "p95": 300},
            "slicesDone": [{"work": "1", "atMs": 30_000}, {"work": "2", "atMs": 70_000}],
            "paidSlices": 1, "spentMsat": 12_000, "terms": {"sliceWork": (1u128 << 47).to_string()},
            "receipts": [{"slice": 1, "sig": "s1"}],
        });
        let r = trial_result(&report, 0, 99_000, 4_000_000_000_000);
        // 2 × 2^47 hashes in 70 s: about 4.02 TH/s
        let d = r["deliveredHs"].as_u64().unwrap();
        assert!((4_000_000_000_000..4_100_000_000_000).contains(&d), "{d}");
        assert!((r["ratio"].as_f64().unwrap() - 1.005).abs() < 0.01);
        assert_eq!(r["staleShare"].as_f64().unwrap(), 0.01);
        assert_eq!(r["latencyMsP50"], 110);
        let a = attestation_of(&report, "r9", 0, &pk(1), &pk(2), 4_000_000_000_000, true, 7_300).unwrap();
        assert_eq!((a.paid_slices, a.trial, a.paid_msat), (1, true, 12_000));
        assert_eq!(a.receipts_hash, receipts_hash(&[json!({"slice": 1, "sig": "s1"})], 1));
        // the hashmaker's side of the same rental gives the same commitment and receipts hash
        let fin = json!({"rental": "r9", "buyer": hex::encode(pk(1).serialize()), "paid": 1, "earnedMsat": 12_000,
                         "meter": {"work": (1u128 << 47).to_string()}, "receipts": [{"slice": 1, "sig": "s1"}]});
        let s = served_of(&fin, &pk(2), 7_300).unwrap();
        assert_eq!((s.commit, s.receipts_hash), (a.commit, a.receipts_hash));
    }
}
