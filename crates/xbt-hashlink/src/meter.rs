//! The work meter, slices, and the hashtaker's signed work receipts.
//!
//! Work is what a share's hash proves, and nobody's word: a share at difficulty `d` is `d × 2^32`
//! hashes, once its hash, rebuilt from the Stratum V1 lines alone, meets `d` ([`crate::proof`]). The
//! hashmaker and the hashtaker each run this same meter on the same lines and keep their own count.
//! The gateway's verdicts set no work. The hashtaker reads them for what they say about the shares
//! reaching it in time.
//!
//! Job window: a share's job is in the channel's last 64 notifies and at most one `clean_jobs` generation
//! old, which allows for shares in flight across a job change with no clocks.
//!
//! Credit: a share counts at its job's difficulty. On the channel's newest job it counts at the larger of
//! that and the difficulty now, of those the hash meets, since firmware may apply a new difficulty at once
//! or at the next job.

use crate::proof::{self, Job, Session};
use crate::sv1;
use secp256k1::ecdsa::Signature;
use secp256k1::{Message, PublicKey, SecretKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Jobs remembered per channel (older jobs' shares are not counted).
const JOBS_KEPT: usize = 64;
/// Submits awaiting a verdict, per channel.
const PENDING_KEPT: usize = 1024;
/// Share round trips kept for the latency figures (submit to verdict, as this side sees them).
const LATENCY_KEPT: usize = 512;
/// Hashes remembered against repeats, in each of two generations. Long enough that a share repeated from
/// past the job window is refused by that window anyway.
const SEEN_KEPT: usize = 1 << 21;
/// Shares in one window of the hash test and of the job-age check.
const WINDOW: u32 = 32;
/// Below this mean of hash/target over [`WINDOW`] shares, the window is low: 3.5 sigma under the 1/2 of
/// a miner whose target is the difficulty it was given.
const HASH_TEST_LOW: f64 = 0.5 - 3.5 * 0.051_031_036_307_982_9;
/// The youngest a window of shares may be, at the least. See [`Meter::commit`].
const AGE_FLOOR: Duration = Duration::from_secs(10);
/// Verdicts in one window, and the fewest accepted in it.
const VERDICT_WINDOW: u32 = 64;
const VERDICTS_ACCEPTED_LEAST: u32 = 48;
/// So many rejections in a row is a bad enough verdict without waiting for a window.
const VERDICTS_REJECTED_IN_A_ROW: u32 = 8;
/// A share of a job past `clean_jobs` may be on its way for this long.
const SUPERSEDED_IN_FLIGHT: Duration = Duration::from_secs(2);
/// The late shares of a superseded job a channel stands: one could be firmware finishing up, a second is
/// a miner left on the old job, whose work is useless and credited.
const SUPERSEDED_SHARES: u32 = 2;
/// How far a share's time may roll forward from its job's: a gateway takes up to two hours past its template's time.
pub const NTIME_ROLL_MOST: u32 = 7200;

/// The work of one share at difficulty `d`.
pub fn share_work(d: f64) -> u128 {
    if d.is_finite() && d > 0.0 {
        (d * 4_294_967_296.0).round() as u128
    } else {
        0
    }
}

/// Why a share isn't counted.
#[derive(Clone, Debug, PartialEq)]
pub enum Refused {
    /// Not in the channel's last 64 jobs.
    UnknownJob,
    /// More than one `clean_jobs` generation old.
    TooOld,
    /// The hash doesn't meet the difficulty.
    Low,
    /// This hash was counted already.
    Repeat,
    /// Its time rolls back from its job's, or further forward than a gateway takes.
    Time,
    /// A line this check can't read.
    Bad(String),
}

impl Refused {
    /// The rejection the miner gets for it, in place of a verdict: a share not forwarded has no other answer.
    pub fn rejection(&self, id: &Value) -> Value {
        let (code, words) = match self {
            Refused::UnknownJob => (21, "job not found"),
            Refused::TooOld => (21, "stale job"),
            Refused::Low => (23, "low difficulty share"),
            Refused::Time => (20, "ntime out of range"),
            Refused::Repeat => (22, "duplicate share"),
            Refused::Bad(_) => (20, "share can't be checked"),
        };
        json!({"id": id, "result": false, "error": [code, words, null]})
    }
}

/// What a share proved.
#[derive(Clone, Debug, PartialEq)]
pub struct Proven {
    pub work: u128,
    /// This share ended a second window in a row low on the hash test: the miner's target looks harder
    /// than the difficulty it was given.
    pub harder: bool,
    /// This share ended a second window in a row too old on the job-age check.
    pub old: bool,
    /// The second share to come late on a job `clean_jobs` has superseded.
    pub old_job: bool,
    /// The share's raw hash.
    pub hash: [u8; 32],
}

/// A share read and ready to hash, with no lock held for it. See [`Meter::claim`].
pub struct Claim {
    chan: u32,
    id: Option<String>,
    job: Arc<Job>,
    session: Arc<Session>,
    submit: Value,
    d_job: f64,
    /// The difficulty now, for a share of the channel's newest job.
    d_now: Option<f64>,
    job_at: Instant,
    /// The newest of how long the channel's jobs have lasted.
    job_life: Duration,
    /// Its job was superseded, longer ago than a share could be on its way.
    superseded: bool,
}

impl Claim {
    pub fn chan(&self) -> u32 {
        self.chan
    }

    pub fn hash(&self) -> Result<[u8; 32], String> {
        proof::share_hash(&self.job, &self.session, &self.submit)
    }
}

/// Two low windows in a row: each alone has odds of about 1 in 5,000, and a long rental has many.
#[derive(Default)]
struct Windows {
    n: u32,
    sum: f64,
    last_low: bool,
}

impl Windows {
    /// Add one share's figure; at a window's end, whether it and the one before were both low.
    fn add(&mut self, x: f64, low: impl Fn(f64) -> bool) -> bool {
        self.n += 1;
        self.sum += x;
        if self.n < WINDOW {
            return false;
        }
        let this = low(self.sum / WINDOW as f64);
        let both = this && self.last_low;
        self.last_low = this;
        self.n = 0;
        self.sum = 0.0;
        both
    }
}

struct JobRec {
    id: String,
    job: Arc<Job>,
    d: f64,
    gen: u64,
    at: Instant,
    /// The time offset its notify gave, which a miner's own may roll forward from.
    ntime: Option<u32>,
}

struct Chan {
    /// A channel starts at Stratum's own default.
    diff: f64,
    /// The gateway has said a difficulty, so a share's size is known.
    told: bool,
    gen: u64,
    jobs: VecDeque<JobRec>,
    /// When the last `clean_jobs` came, and the late shares of older jobs since.
    clean_at: Option<Instant>,
    late_shares: u32,
    sub_id: Option<String>,
    session: Option<Arc<Session>>,
    /// Submit id → (its work, when it went up, in ms).
    pending: HashMap<String, (u128, u64)>,
    hash_test: Windows,
}

impl Default for Chan {
    fn default() -> Chan {
        Chan { diff: 1.0, told: false, gen: 0, jobs: VecDeque::new(), clean_at: None, late_shares: 0, sub_id: None, session: None, pending: HashMap::new(), hash_test: Windows::default() }
    }
}

/// What a line did to the count.
#[derive(Debug, PartialEq)]
pub enum Event {
    Accepted(u128),
    Rejected,
}

/// A rejection the gateway called stale: the share was for a job it had already moved past
/// (Stratum V1 error 21, "job not found", or any error whose words say stale).
fn stale(v: &Value) -> bool {
    match v.get("error") {
        Some(Value::Array(e)) => {
            e.first().and_then(Value::as_i64) == Some(21)
                || e.get(1).and_then(Value::as_str).is_some_and(|m| m.to_ascii_lowercase().contains("stale"))
        }
        Some(Value::String(m)) => m.to_ascii_lowercase().contains("stale"),
        _ => false,
    }
}

#[derive(Default)]
pub struct Meter {
    chans: HashMap<u32, Chan>,
    /// Proven work.
    pub work: u128,
    /// Shares proven and counted.
    pub proven: u64,
    /// Shares refused, for whatever reason.
    pub refused: u64,
    /// Refused because their job isn't one this channel has (also in `refused`).
    pub unknown_job: u64,
    /// Refused repeats (also in `refused`).
    pub repeats: u64,
    /// The gateway's verdicts on the shares sent to it.
    pub accepted: u64,
    pub rejected: u64,
    /// Rejections the gateway called stale (also counted in `rejected`).
    pub stale: u64,
    seen: HashSet<[u8; 16]>,
    seen_before: HashSet<[u8; 16]>,
    age_test: Windows,
    window_accepted: u32,
    window_verdicts: u32,
    rejected_in_a_row: u32,
    /// A window of verdicts had too few accepted.
    pub verdicts_low: bool,
    /// The last share round trips, submit to verdict, in ms.
    latency: VecDeque<u32>,
}

impl Meter {
    /// A line towards the gateway that isn't a share: the channel's own subscribe is remembered, so
    /// that its answer can be read for the extranonce.
    pub fn note_up(&mut self, chan: u32, v: &Value) {
        if sv1::method(v) == Some("mining.subscribe") {
            self.chans.entry(chan).or_default().sub_id = sv1::id_key(v);
        }
    }

    /// Read a share under whatever lock guards this meter, so it can be hashed outside it. A share that
    /// fails here isn't counted or forwarded.
    pub fn claim(&mut self, chan: u32, v: &Value) -> Result<Claim, Refused> {
        let r = self.claim_inner(chan, v);
        if let Err(e) = &r {
            self.note_refused(e);
        }
        r
    }

    fn claim_inner(&self, chan: u32, v: &Value) -> Result<Claim, Refused> {
        let c = self.chans.get(&chan).ok_or(Refused::UnknownJob)?;
        let id = sv1::submit_job(v).ok_or_else(|| Refused::Bad("not a share".into()))?;
        let at = c.jobs.iter().rposition(|j| j.id == id).ok_or(Refused::UnknownJob)?;
        let j = &c.jobs[at];
        if j.gen + 1 < c.gen {
            return Err(Refused::TooOld);
        }
        // the time the node would read: the job's, rolled forward at most as far as a gateway takes (its template
        // time and two hours). A share whose block would be refused for its time is no work to sell
        if let Some(jt) = j.ntime {
            let t = proof::ntime_offset(sv1::params(v).and_then(|p| p.get(3))).map_err(Refused::Bad)?;
            if t.wrapping_sub(jt) > NTIME_ROLL_MOST {
                return Err(Refused::Time);
            }
        }
        let session = c.session.clone().ok_or_else(|| Refused::Bad("a share before the subscribe's answer".into()))?;
        let newest = at + 1 == c.jobs.len();
        let first = c.jobs.front().map(|f| f.at).unwrap_or(j.at);
        let last = c.jobs.back().map(|l| l.at).unwrap_or(j.at);
        // how long a job lasts here: the mean between notifies, or the newest job's age if that's longer
        let mean = if c.jobs.len() > 1 { (last - first) / (c.jobs.len() as u32 - 1) } else { Duration::ZERO };
        Ok(Claim {
            chan,
            id: sv1::id_key(v),
            job: j.job.clone(),
            session,
            submit: v.clone(),
            d_job: j.d,
            d_now: newest.then_some(c.diff),
            job_at: j.at,
            job_life: mean.max(last.elapsed()),
            superseded: j.gen < c.gen && c.clean_at.is_some_and(|t| t.elapsed() > SUPERSEDED_IN_FLIGHT),
        })
    }

    /// A share refused before it reached the meter (its id, or a job not yet checked at its difficulty): counted
    /// as any refusal is.
    pub fn refuse(&mut self, e: &Refused) {
        self.note_refused(e);
    }

    fn note_refused(&mut self, e: &Refused) {
        self.refused += 1;
        match e {
            Refused::UnknownJob => self.unknown_job += 1,
            Refused::Repeat => self.repeats += 1,
            _ => {}
        }
    }

    /// Count a claimed share by its hash. Two figures go with it:
    /// * hash/target over its window. If a miner's target is the difficulty it was given, this is uniform.
    /// * its job's age over its window. Honest shares are spread over a job's life, so a window whose
    ///   youngest share is older than a quarter of that life (at least 10 s) has odds of about 1e-4; shares
    ///   held back, or mined on an old job on purpose, look like this.
    pub fn commit(&mut self, c: &Claim, hash: Result<[u8; 32], String>) -> Result<Proven, Refused> {
        self.commit_at(c, hash, Instant::now())
    }

    /// [`Meter::commit`] for a share that arrived at `at`: a share sent again after a drop is aged at the drop, when
    /// it was on its way, not when it came again.
    pub fn commit_at(&mut self, c: &Claim, hash: Result<[u8; 32], String>, at: Instant) -> Result<Proven, Refused> {
        let r = self.commit_inner(c, hash, at);
        if let Err(e) = &r {
            self.note_refused(e);
        }
        r
    }

    /// The work a hash proves on its claim, if it's one to count. Nothing is counted by this: a share that doesn't
    /// fit in what's paid is proven and waits.
    pub fn worth(&mut self, c: &Claim, hash: &Result<[u8; 32], String>) -> Result<u128, Refused> {
        let r = self.earned(c, hash).map(|(_, d)| share_work(d));
        if let Err(e) = &r {
            self.note_refused(e);
        }
        r
    }

    /// The difficulty a hash earns on its claim.
    fn earned(&self, c: &Claim, hash: &Result<[u8; 32], String>) -> Result<([u8; 32], f64), Refused> {
        let h = *hash.as_ref().map_err(|e| Refused::Bad(e.clone()))?;
        let d = match c.d_now {
            Some(now) if now > c.d_job && proof::proven_at(&h, now) => now,
            _ if proof::proven_at(&h, c.d_job) => c.d_job,
            Some(now) if proof::proven_at(&h, now) => now,
            _ => return Err(Refused::Low),
        };
        let key: [u8; 16] = h[..16].try_into().unwrap();
        if self.seen.contains(&key) || self.seen_before.contains(&key) {
            return Err(Refused::Repeat);
        }
        Ok((h, d))
    }

    /// Take a hash once.
    fn credit(&mut self, c: &Claim, hash: Result<[u8; 32], String>) -> Result<([u8; 32], f64), Refused> {
        let (h, d) = self.earned(c, &hash)?;
        let key: [u8; 16] = h[..16].try_into().unwrap();
        if self.seen.len() >= SEEN_KEPT {
            self.seen_before = std::mem::take(&mut self.seen);
        }
        self.seen.insert(key);
        self.work += share_work(d);
        self.proven += 1;
        Ok((h, d))
    }

    fn commit_inner(&mut self, c: &Claim, hash: Result<[u8; 32], String>, at: Instant) -> Result<Proven, Refused> {
        let (h, d) = self.credit(c, hash)?;
        let work = share_work(d);
        let (limit, age) = (AGE_FLOOR.max(c.job_life / 4), at.saturating_duration_since(c.job_at));
        let old = self.age_test.add(if age > limit { 1.0 } else { 0.0 }, |all| all >= 1.0);
        let (mut harder, mut old_job) = (false, false);
        if let Some(ch) = self.chans.get_mut(&c.chan) {
            harder = ch.hash_test.add(proof::target_fraction(&h, d), |mean| mean < HASH_TEST_LOW);
            if c.superseded {
                ch.late_shares += 1;
                old_job = ch.late_shares >= SUPERSEDED_SHARES;
            }
            if let Some(id) = &c.id {
                if ch.pending.len() >= PENDING_KEPT {
                    ch.pending.clear();
                }
                ch.pending.insert(id.clone(), (work, crate::now_ms()));
            }
        }
        Ok(Proven { work, harder, old, old_job, hash: h })
    }

    /// Was this share, sent again after a drop, counted already? Its claim, to commit, if not. A share the
    /// hashtaker counted before the drop is passed over without a word; one that fails its checks is `Err`.
    pub fn resent_claim(&mut self, chan: u32, v: &Value) -> Result<Option<(Claim, Result<[u8; 32], String>)>, Refused> {
        let c = self.claim(chan, v)?;
        let h = c.hash();
        match self.earned(&c, &h) {
            Err(Refused::Repeat) => Ok(None),
            _ => Ok(Some((c, h))),
        }
    }

    /// A share read, hashed and counted at once.
    pub fn check(&mut self, chan: u32, v: &Value) -> Result<Proven, Refused> {
        let c = self.claim(chan, v)?;
        let h = c.hash();
        self.commit(&c, h)
    }

    /// A line towards the miner (from the gateway). An error is a line that can't be followed: its jobs
    /// could not be checked, so the rental can't go on.
    pub fn down(&mut self, chan: u32, v: &Value) -> Result<Option<Event>, String> {
        let c = self.chans.entry(chan).or_default();
        if let Some(d) = sv1::set_difficulty(v) {
            if !(d.is_finite() && d > 0.0) {
                return Err(format!("a difficulty of {d}"));
            }
            c.diff = d;
            c.told = true;
            return Ok(None);
        }
        if sv1::method(v) == Some("mining.set_difficulty") {
            return Err("a difficulty that isn't a number".into());
        }
        if sv1::method(v) == Some("mining.notify") {
            let id = sv1::notify_job(v).ok_or("a notify with no job id")?;
            let job = proof::job_from_notify(v)?;
            if let Some(s) = &c.session {
                let leaf = 1 + job.coinb1.len() + s.en1.len() + s.en2_size + job.coinb2.len();
                if leaf != 52 {
                    return Err(format!("a job whose leaf comes to {leaf} bytes, not 52"));
                }
            }
            if sv1::params(v).and_then(|p| p.get(8)).and_then(Value::as_bool) == Some(true) {
                c.gen += 1;
                c.clean_at = Some(Instant::now());
                c.late_shares = 0;
            }
            if c.jobs.len() == JOBS_KEPT {
                c.jobs.pop_front();
            }
            let ntime = proof::ntime_offset(sv1::params(v).and_then(|p| p.get(7))).ok();
            c.jobs.push_back(JobRec { id, job: Arc::new(job), d: c.diff, gen: c.gen, at: Instant::now(), ntime });
            return Ok(None);
        }
        if !sv1::is_response(v) {
            return Ok(None);
        }
        let Some(key) = sv1::id_key(v) else { return Ok(None) };
        if c.sub_id.as_deref() == Some(key.as_str()) {
            c.sub_id = None;
            c.session = Some(Arc::new(proof::session_from_subscribe(v)?));
            return Ok(None);
        }
        let Some((w, sent)) = c.pending.remove(&key) else { return Ok(None) };
        if self.latency.len() == LATENCY_KEPT {
            self.latency.pop_front();
        }
        self.latency.push_back(crate::now_ms().saturating_sub(sent).min(u32::MAX as u64) as u32);
        self.window_verdicts += 1;
        let ev = if sv1::accepted(v) {
            self.accepted += 1;
            self.window_accepted += 1;
            self.rejected_in_a_row = 0;
            Event::Accepted(w)
        } else {
            self.rejected += 1;
            self.rejected_in_a_row += 1;
            self.verdicts_low |= self.rejected_in_a_row >= VERDICTS_REJECTED_IN_A_ROW;
            if stale(v) {
                self.stale += 1;
            }
            Event::Rejected
        };
        if self.window_verdicts == VERDICT_WINDOW {
            self.verdicts_low |= self.window_accepted < VERDICTS_ACCEPTED_LEAST;
            self.window_verdicts = 0;
            self.window_accepted = 0;
        }
        Ok(Some(ev))
    }

    pub fn close(&mut self, chan: u32) {
        self.chans.remove(&chan);
    }

    /// The channels this meter knows now, for keeping their job tables across a dropped link.
    pub fn channels(&self) -> Vec<u32> {
        self.chans.keys().copied().collect()
    }

    /// This channel's difficulty now.
    pub fn diff_now(&self, chan: u32) -> f64 {
        self.chans.get(&chan).map(|c| c.diff).unwrap_or(1.0)
    }

    /// The work of a share at the difficulty this channel's gateway has said; none till it says.
    pub fn share_now(&self, chan: u32) -> u128 {
        self.chans.get(&chan).filter(|c| c.told).map(|c| share_work(c.diff)).unwrap_or(0)
    }

    /// The largest share any channel in `live` could send now.
    pub fn largest_share(&self, live: impl Iterator<Item = u32>) -> u128 {
        live.map(|c| self.share_now(c)).max().unwrap_or(0)
    }

    /// The `q` quantile (0..=1) of the recent share round trips, in ms; `None` before any verdict.
    pub fn latency_ms(&self, q: f64) -> Option<u32> {
        if self.latency.is_empty() {
            return None;
        }
        let mut l: Vec<u32> = self.latency.iter().copied().collect();
        l.sort_unstable();
        let i = ((l.len() - 1) as f64 * q.clamp(0.0, 1.0)).round() as usize;
        Some(l[i])
    }

    pub fn to_json(&self) -> Value {
        json!({"work": self.work.to_string(), "proven": self.proven, "refused": self.refused, "unknownJob": self.unknown_job, "repeats": self.repeats,
               "accepted": self.accepted, "rejected": self.rejected, "stale": self.stale})
    }

    /// The share round trip as this side sees it (each side measures its own, so it is kept apart
    /// from the counts).
    pub fn latency_json(&self) -> Value {
        json!({"p50": self.latency_ms(0.5), "p95": self.latency_ms(0.95)})
    }
}

/// What a fallback's verdicts say a miner did while it isn't rented. That session is the hashmaker's own
/// pool, whose jobs needn't be of this chain: its verdicts are only read for the miner's hashrate.
#[derive(Default)]
pub struct Verdicts {
    chans: HashMap<u32, VerdictChan>,
}

#[derive(Default)]
struct VerdictChan {
    diff: f64,
    jobs: VecDeque<(String, f64)>,
    pending: HashMap<String, u128>,
}

impl Verdicts {
    pub fn up(&mut self, chan: u32, v: &Value) {
        let (Some(job), Some(id)) = (sv1::submit_job(v), sv1::id_key(v)) else { return };
        let c = self.chans.entry(chan).or_default();
        if let Some((_, d)) = c.jobs.iter().rev().find(|(j, _)| *j == job) {
            if c.pending.len() >= PENDING_KEPT {
                c.pending.clear();
            }
            c.pending.insert(id, share_work(*d));
        }
    }

    /// The work of a share this line accepted.
    pub fn down(&mut self, chan: u32, v: &Value) -> Option<u128> {
        let c = self.chans.entry(chan).or_default();
        if let Some(d) = sv1::set_difficulty(v) {
            c.diff = d;
            return None;
        }
        if let Some(job) = sv1::notify_job(v) {
            if c.jobs.len() == JOBS_KEPT {
                c.jobs.pop_front();
            }
            c.jobs.push_back((job, c.diff));
            return None;
        }
        if !sv1::is_response(v) {
            return None;
        }
        let w = c.pending.remove(&sv1::id_key(v)?)?;
        sv1::accepted(v).then_some(w)
    }
}

/// The hashtaker's signed receipt for a slice it paid: its own proven count when it paid. It says how
/// the two counts stood; nothing is decided by it.
#[derive(Clone, Debug, PartialEq)]
pub struct Receipt {
    pub rental: String,
    pub slice: u64,
    pub work: u128,
    pub accepted: u64,
    pub rejected: u64,
    pub at_ms: u64,
}

const RECEIPT_TAG: &str = "xbt-hashlink/receipt/0";

impl Receipt {
    fn line(&self) -> String {
        format!("{RECEIPT_TAG}|{}|{}|{}|{}|{}|{}", self.rental, self.slice, self.work, self.accepted, self.rejected, self.at_ms)
    }

    fn digest(&self) -> Message {
        Message::from_digest(Sha256::digest(self.line().as_bytes()).into())
    }

    pub fn sign(&self, key: &SecretKey) -> Value {
        let sig = secp256k1::SECP256K1.sign_ecdsa(&self.digest(), key);
        json!({
            "rental": self.rental, "slice": self.slice, "work": self.work.to_string(),
            "accepted": self.accepted, "rejected": self.rejected, "atMs": self.at_ms,
            "sig": hex::encode(sig.serialize_compact()),
        })
    }

    /// Parse a signed receipt and check its signature by `signer`.
    pub fn verify(v: &Value, signer: &PublicKey) -> Option<Receipt> {
        let r = Receipt {
            rental: v.get("rental")?.as_str()?.to_string(),
            slice: v.get("slice")?.as_u64()?,
            work: v.get("work")?.as_str()?.parse().ok()?,
            accepted: v.get("accepted")?.as_u64()?,
            rejected: v.get("rejected")?.as_u64()?,
            at_ms: v.get("atMs")?.as_u64()?,
        };
        let sig = Signature::from_compact(&hex::decode(v.get("sig")?.as_str()?).ok()?).ok()?;
        secp256k1::SECP256K1.verify_ecdsa(&r.digest(), &sig, signer).ok()?;
        Some(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::standin;

    fn p(s: &str) -> Value {
        sv1::parse(s).unwrap()
    }

    const D: f64 = 1.0 / (1u64 << 22) as f64;

    /// A channel with a session and the line that gives it a job. `k` names the job.
    fn job(k: u64, clean: bool) -> Value {
        standin::notify_line(&format!("j{k}"), k, 1_700_000_000, clean)
    }

    fn open(m: &mut Meter, chan: u32) {
        m.note_up(chan, &p(r#"{"id":1,"method":"mining.subscribe","params":[]}"#));
        m.down(chan, &p(r#"{"id":1,"result":[[],"00000001",8],"error":null}"#)).unwrap();
    }

    fn share(k: u64, d: f64, en2: u64, id: u64) -> Value {
        let (e2, n) = standin::find_share(&job(k, false), "00000001", 8, d, en2).unwrap();
        json!({"id": id, "method": "mining.submit", "params": ["u", format!("j{k}"), e2, format!("{:08x}", 1_700_000_000u32), n]})
    }

    #[test]
    fn a_share_counts_when_its_hash_proves_it_and_only_then() {
        let mut m = Meter::default();
        open(&mut m, 1);
        m.down(1, &json!({"id": null, "method": "mining.set_difficulty", "params": [D]})).unwrap();
        m.down(1, &job(1, false)).unwrap();
        let s = share(1, D, 1, 5);
        assert_eq!(m.check(1, &s).unwrap().work, share_work(D));
        assert_eq!(m.check(1, &s).err(), Some(Refused::Repeat), "a repeat is not counted");
        let mut bad = s.clone();
        bad["params"][4] = json!("ffffffff");
        assert!(matches!(m.check(1, &bad), Err(Refused::Low) | Ok(_)));
        assert_eq!(m.work, if m.proven == 1 { share_work(D) } else { 2 * share_work(D) });
        let mut unknown = s.clone();
        unknown["params"][1] = json!("zz");
        assert_eq!(m.check(1, &unknown).err(), Some(Refused::UnknownJob));
        // a verdict adds nothing, and a verdict nobody asked for means nothing
        let before = m.work;
        assert_eq!(m.down(1, &p(r#"{"id":5,"result":true,"error":null}"#)).unwrap(), Some(Event::Accepted(share_work(D))));
        assert_eq!(m.down(1, &p(r#"{"id":5,"result":true,"error":null}"#)).unwrap(), None);
        assert_eq!(m.work, before);
        assert_eq!(m.accepted, 1);
    }

    /// A share's time may roll forward from its job's as far as a gateway takes (two hours), and never back.
    #[test]
    fn a_share_whose_time_leaves_its_jobs_range_is_refused() {
        let mut m = Meter::default();
        open(&mut m, 1);
        m.down(1, &json!({"id": null, "method": "mining.set_difficulty", "params": [D]})).unwrap();
        m.down(1, &job(1, false)).unwrap();
        let s = share(1, D, 1, 5);
        let at = |t: u32| {
            let mut v = s.clone();
            v["params"][3] = json!(format!("{t:08x}"));
            v
        };
        assert_eq!(m.claim(1, &at(1_700_000_000 - 1)).err(), Some(Refused::Time), "rolled back");
        assert_eq!(m.claim(1, &at(1_700_000_000 + NTIME_ROLL_MOST + 1)).err(), Some(Refused::Time), "past two hours");
        assert!(m.claim(1, &at(1_700_000_000 + NTIME_ROLL_MOST)).is_ok());
        assert!(m.claim(1, &at(1_700_000_000)).is_ok());
        // the 16-digit form: its first four bytes are the time, little-endian
        let mut long = s.clone();
        long["params"][3] = json!(format!("{}{}", hex::encode((1_700_000_000u32 - 5).to_le_bytes()), "00000000"));
        assert_eq!(m.claim(1, &long).err(), Some(Refused::Time));
        assert_eq!(m.refused, 3);
    }

    #[test]
    fn no_share_is_counted_from_more_than_one_clean_generation_back() {
        let mut m = Meter::default();
        open(&mut m, 1);
        m.down(1, &json!({"id": null, "method": "mining.set_difficulty", "params": [D]})).unwrap();
        m.down(1, &job(1, true)).unwrap();
        let s = share(1, D, 1, 5);
        m.down(1, &job(2, true)).unwrap();
        // one generation back: in flight across the change
        let c = m.claim(1, &s);
        assert!(c.is_ok());
        m.down(1, &job(3, true)).unwrap();
        assert_eq!(m.check(1, &s).err(), Some(Refused::TooOld));
    }

    #[test]
    fn a_share_of_an_older_job_keeps_that_jobs_difficulty() {
        let mut m = Meter::default();
        open(&mut m, 1);
        m.down(1, &json!({"id": null, "method": "mining.set_difficulty", "params": [D]})).unwrap();
        m.down(1, &job(1, false)).unwrap();
        m.down(1, &json!({"id": null, "method": "mining.set_difficulty", "params": [D * 4.0]})).unwrap();
        // the newest job, still of the old difficulty: a hash that meets the new one counts at it
        let s = share(1, D * 4.0, 1, 5);
        assert_eq!(m.check(1, &s).unwrap().work, share_work(D * 4.0));
        // a later job: the share of the old one counts at the old difficulty, whatever it meets
        m.down(1, &job(2, false)).unwrap();
        let s = share(1, D * 4.0, 2, 6);
        assert_eq!(m.check(1, &s).unwrap().work, share_work(D));
    }

    #[test]
    fn a_job_or_difficulty_it_cannot_follow_is_an_error() {
        let mut m = Meter::default();
        open(&mut m, 1);
        let mut j = job(1, false);
        j["params"][1] = json!("ff".repeat(32));
        assert!(m.down(1, &j).is_err(), "prev not in its hidden form");
        let mut j = job(1, false);
        j["params"][2] = json!("00");
        assert!(m.down(1, &j).is_err(), "leaf not 52 bytes");
        let mut j = job(1, false);
        j["params"][4] = json!(["00"]);
        assert!(m.down(1, &j).is_err(), "branches");
        assert!(m.down(1, &json!({"id": null, "method": "mining.set_difficulty", "params": [0.0]})).is_err());
    }

    #[test]
    fn a_miner_given_a_target_harder_than_its_difficulty_fails_the_hash_test_and_an_honest_one_does_not() {
        // both hashes are real: the honest miner searches at D, the other at 3D and is credited D
        for (search, fires) in [(D, false), (D * 3.0, true)] {
            let mut m = Meter::default();
            open(&mut m, 1);
            m.down(1, &json!({"id": null, "method": "mining.set_difficulty", "params": [D]})).unwrap();
            m.down(1, &job(1, false)).unwrap();
            m.down(1, &job(2, false)).unwrap();
            let mut seen = false;
            for i in 0..(2 * WINDOW as u64) {
                seen |= m.check(1, &share(1, search, i + 1, i + 10)).unwrap().harder;
            }
            assert_eq!(seen, fires, "search at {search}");
        }
    }

    #[test]
    fn a_window_of_verdicts_with_too_few_accepted_is_marked() {
        let mut m = Meter::default();
        open(&mut m, 1);
        m.down(1, &json!({"id": null, "method": "mining.set_difficulty", "params": [D]})).unwrap();
        m.down(1, &job(1, false)).unwrap();
        for i in 0..VERDICT_WINDOW as u64 {
            let s = share(1, D, i + 1, i + 10);
            m.check(1, &s).unwrap();
            let ok = i >= 17; // 17 refused is 47 accepted
            m.down(1, &json!({"id": i + 10, "result": ok, "error": if ok { Value::Null } else { json!([21, "stale", null]) }})).unwrap();
        }
        assert!(m.verdicts_low);
        assert_eq!((m.accepted, m.rejected, m.stale), (47, 17, 17));
    }

    #[test]
    fn verdicts_count_for_shares_it_sent_and_round_trips_are_measured() {
        let mut m = Meter::default();
        open(&mut m, 1);
        m.down(1, &json!({"id": null, "method": "mining.set_difficulty", "params": [D]})).unwrap();
        m.down(1, &job(1, false)).unwrap();
        assert_eq!(m.latency_ms(0.5), None);
        for i in 1..=2u64 {
            m.check(1, &share(1, D, i, i + 10)).unwrap();
        }
        m.down(1, &p(r#"{"id":11,"result":true,"error":null}"#)).unwrap();
        m.down(1, &p(r#"{"id":12,"result":false,"error":[23,"Low difficulty share",null]}"#)).unwrap();
        assert_eq!((m.accepted, m.rejected, m.stale), (1, 1, 0));
        assert!(m.latency_ms(0.5).is_some_and(|l| l < 1000));
        assert!(m.latency_json()["p95"].is_u64());
    }

    #[test]
    fn receipts_sign_and_verify() {
        let k = SecretKey::from_slice(&[7; 32]).unwrap();
        let pk = PublicKey::from_secret_key(secp256k1::SECP256K1, &k);
        let r = Receipt { rental: "r1".into(), slice: 3, work: 1 << 70, accepted: 9, rejected: 1, at_ms: 5 };
        let v = r.sign(&k);
        assert_eq!(Receipt::verify(&v, &pk), Some(r));
        let mut bad = v.clone();
        bad["work"] = json!("1");
        assert_eq!(Receipt::verify(&bad, &pk), None);
        let other = PublicKey::from_secret_key(secp256k1::SECP256K1, &SecretKey::from_slice(&[8; 32]).unwrap());
        assert_eq!(Receipt::verify(&v, &other), None);
    }
}
