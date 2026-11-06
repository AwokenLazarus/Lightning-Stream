//! The hashtaker's side: dial the hashmaker, open one Stratum V1 session to the hashtaker's own gateway for
//! each of the hashmaker's miners, and carry the lines both ways (the gateway credits the hashtaker: its
//! user name replaces the miner's). Every share's hash is checked here too ([`crate::meter`]), and only one
//! it proves goes on to the gateway. This side pays by its own count, as [`crate::order`] says, each payment
//! with a signed receipt saying what that count was.
//!
//! The hashmaker chooses which shares reach here, so this side also watches for shares held back: it ends
//! the rental if its gateway accepts too few of them, or if they keep arriving too old.
//!
//! A channel's meter is let go only after its upstream session has ended and its last verdict was sent on:
//! the hashtaker then says `shut`. A dropped link is another matter: the channels' job tables stay until the
//! next drop, so that shares the hashmaker sends again can still be checked.

use crate::blind;
use crate::link::{self, Sender};
use crate::meter::{self, Meter, Receipt};
use crate::msg::{Msg, Terms, PROOF};
use crate::order;
use crate::rail::{self, sha256, HashtakerRail, Payer};
use crate::{now_ms, sv1};
use secp256k1::{PublicKey, SecretKey};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

pub struct Config {
    /// The hashmaker's link address and static key (from its listing).
    pub hashmaker: String,
    pub hashmaker_key: PublicKey,
    pub key: SecretKey,
    /// The hashtaker's own gateway (Stratum V1), and the user name it credits.
    pub upstream: String,
    pub user: String,
    pub terms: Terms,
    pub rental: String,
    pub listing: String,
    /// Lab: stop paying after this many slices (to show the hashmaker stopping).
    pub stop_paying_after: Option<u64>,
    /// End the rental when no work has been proven for this long.
    pub idle: Duration,
    /// End the rental after this long.
    pub duration: Option<Duration>,
    pub report: Option<PathBuf>,
    /// Slices paid by the wallet through the hashmaker's gateway; without it, over the link (the
    /// lab's stand-in rail).
    pub payer: Option<Box<dyn Payer>>,
    /// How many of the hashmaker's miners to rent (0: as many as are free).
    pub miners: u32,
    /// The most the rental may cost: it ends once that much is paid.
    pub budget_msat: Option<u64>,
    /// Set to end the rental now (the app's Cut button).
    pub cut: Option<Arc<AtomicBool>>,
    /// Budget and time added while it goes on (the app's Add to this rental), on top of `budget_msat` and `duration`.
    pub added: Option<Arc<Added>>,
    /// The report, kept current (twice a second) for the app's pages.
    pub live: Option<Arc<Mutex<Value>>>,
    /// The local API of the hashtaker's gateway, where each job is opened and checked for its blinding.
    pub gateway_api: Option<String>,
    /// Rent onto jobs that aren't blinded, where a hashmaker could drop the shares that win (a lab's own
    /// pool). Off, a rental refuses any job it can't show is blinded.
    pub allow_unblinded: bool,
}

/// Budget and time the hashtaker added to a rental going on: the rental reads them twice a second, and the wallet's
/// payer before each payment ([`crate::rail::SignerPayer::added`]). They only grow.
#[derive(Debug, Default)]
pub struct Added {
    pub msat: AtomicU64,
    pub secs: AtomicU64,
}

impl Added {
    pub fn msat(&self) -> u64 {
        self.msat.load(Ordering::Relaxed)
    }

    pub fn secs(&self) -> u64 {
        self.secs.load(Ordering::Relaxed)
    }
}

/// Tickets kept locked ahead of the work.
const AHEAD: u64 = 2;
/// Ticket buys whose time is kept, for the trigger.
const BUYS_KEPT: usize = 16;
/// Job keys kept for the report.
const KEYS_REPORTED: usize = 1024;
/// Refused shares a rental stands before it asks how they compare with the proven ones.
const REFUSED_LEEWAY: u64 = 8;
/// Lines' ids kept for their answers: this side gives each line its own id towards the gateway.
const IDS_KEPT: usize = 4096;
/// Times the link may drop and be made again in an hour. Past that the rental ends: each drop lets the hashmaker
/// send shares again, which this side can only count up to what could have been on their way.
pub const COMEBACKS_AN_HOUR: usize = 8;
/// How long a share may have been on its way when the link dropped, past the link's own silence before it.
const IN_FLIGHT: Duration = Duration::from_secs(2);
/// How far into a wait for a payment on its way, by this side's clock, it says `paying` if the payment is still on its way.
const PAYING_AFTER: Duration = Duration::from_millis(500);
/// A payment the measured buys say lands by this far into the wait needs no `paying`.
const LANDS_BY: Duration = Duration::from_millis(1200);
/// How long after the hashmaker's resends this side waits for their verdicts before it says its count.
const RESYNC_SETTLE: Duration = Duration::from_millis(1500);
/// A payment the measured buys say arrives this much before the hashmaker's short clock runs out needs no `paying`.
const IN_TIME_MARGIN: f64 = 0.5;
/// Shares sent again that are taken past what the miners' rate says could have been on their way.
const RESEND_SLACK: u64 = 4;
/// How long the dropped link's gateway sessions stay open after the hashmaker is back, for shares sent again.
const RESEND_WINDOW: Duration = Duration::from_secs(10);
/// The miners' rate before a drop is taken over this long.
const RATE_WINDOW: Duration = Duration::from_secs(30);
/// Miner requests carried to the gateway. Anything else (`mining.suggest_difficulty`, `mining.suggest_target`, ...)
/// could change what a share is worth, or the jobs: it's answered here and goes no further.
const CARRIED: [&str; 5] = ["mining.subscribe", "mining.authorize", "mining.submit", "mining.extranonce.subscribe", "mining.configure"];

/// What guards the rental against a hashmaker's tricks with ids, drops and difficulties.
#[derive(Default)]
struct Guard {
    /// This side's id for each line sent to the gateway → the channel and the hashmaker's own id for it.
    up_ids: BTreeMap<u64, (u32, Value)>,
    /// The hashmaker's ids of shares waiting for their verdict, by channel: one can't be used twice.
    waiting: HashSet<(u32, String)>,
    next_id: u64,
    /// The gateway sessions of the link that last dropped, open a while for the shares sent again.
    retired_up: HashMap<u32, TcpStream>,
    retire_until: Option<Instant>,
    /// When the link that dropped was last heard from: shares sent again are aged as of then.
    dropped_at: Option<Instant>,
    /// Shares sent again this side still takes, after the last drop.
    resend_left: u64,
    resends_refused: u64,
    comebacks: VecDeque<Instant>,
    last_heard: Option<Instant>,
    /// When each recent share was proven, for the miners' rate.
    proven_at: VecDeque<Instant>,
    /// The share bits each channel's last job was checked at, and channels whose difficulty changed since: their
    /// shares wait for a job checked at the new one.
    checked_pot: HashMap<u32, u32>,
    await_job: HashSet<u32>,
    /// After a drop: this side's count at the drop, what it has counted since from shares sent again, when the
    /// hashmaker said its resends were all sent, and whether this side has said its count.
    resync_base: Option<(u128, u64)>,
    resync_resent: (u128, u64),
    resync_marker: Option<Instant>,
    resync_said: bool,
    /// Shares sent again past what could have been on their way, waiting for their gateway's verdict, by this side's id.
    resend_pending: HashMap<u64, (meter::Claim, meter::Hashed, Instant)>,
    /// When the payment in flight was queued.
    in_flight_since: Option<Instant>,
    /// Since when the hashmaker has said a share waits for payment, while what's been paid (not what's on its way)
    /// leaves the next share unpaid; and whether `paying` has been said for it.
    due_open_since: Option<Instant>,
    paying_said: bool,
    /// The credit the seller holds and what's left of the budget, as the wallet last said (with the wallet's payer).
    credit_msat: u64,
    budget_left: Option<u64>,
}

impl Guard {
    /// This side's own id for a line, keeping the hashmaker's to answer with.
    fn own_id(&mut self, chan: u32, theirs: Value) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.up_ids.insert(id, (chan, theirs));
        while self.up_ids.len() > IDS_KEPT {
            if let Some((_, (c, t))) = self.up_ids.pop_first() {
                self.waiting.remove(&(c, t.to_string()));
            }
        }
        id
    }

    /// The hashmaker's id for an answer to one of this side's, if it was one.
    fn theirs(&mut self, chan: u32, v: &Value) -> Option<Value> {
        let id = v.get("id")?.as_u64()?;
        if self.up_ids.get(&id).is_some_and(|(c, _)| *c == chan) {
            let (c, t) = self.up_ids.remove(&id)?;
            self.waiting.remove(&(c, t.to_string()));
            return Some(t);
        }
        None
    }

    /// Shares that could have been on their way when the link dropped: the miners' rate over the half minute before
    /// it went quiet, over that silence and [`IN_FLIGHT`], and a few more.
    fn could_be_in_flight(&self, now: Instant) -> u64 {
        let heard = self.last_heard.unwrap_or(now);
        let from = heard.checked_sub(RATE_WINDOW);
        let n = self.proven_at.iter().filter(|t| from.is_none_or(|f| **t >= f) && **t <= heard).count() as f64;
        let over = self.proven_at.front().map_or(RATE_WINDOW, |f| heard.saturating_duration_since(*f).clamp(Duration::from_secs(5), RATE_WINDOW));
        let rate = n / over.as_secs_f64();
        (rate * (now.saturating_duration_since(heard) + IN_FLIGHT).as_secs_f64()).ceil() as u64 + RESEND_SLACK
    }
}

struct St {
    terms: Terms,
    rental: String,
    key: SecretKey,
    meter: Meter,
    locked: BTreeSet<u64>,
    released: u64,
    done: Vec<(u128, u64)>,
    receipts: Vec<Value>,
    upstreams: HashMap<u32, TcpStream>,
    rail: Box<dyn HashtakerRail>,
    stop_paying_after: Option<u64>,
    last_work: Instant,
    rate: Option<Value>,
    pays: Vec<Value>,
    events: Vec<Value>,
    closed: Option<String>,
    /// Slices for the wallet to pay, in order (with the wallet's payer; none over the link).
    /// Each with whether it was started ahead of the step to buy a ticket ([`order::Standing::buy_ahead`]).
    queue: Option<mpsc::Sender<(u64, Value, bool)>>,
    /// The wallet refused or failed a slice: no later slice is asked for.
    pay_failed: bool,
    budget_msat: Option<u64>,
    /// The wallet refused a slice because a budget of the renter's own is spent (the rental's, or its task's in the
    /// owner's rules): no later slice is asked for, and the rental ends as its paid work runs out, said as that reason.
    spent: Option<&'static str>,

    /// The hashes of the tickets locked over the link, sent again after the link comes back.
    lock_hashes: BTreeMap<u64, String>,
    /// The last payments sent over the link, sent again after it comes back (the hashmaker takes
    /// each slice once, so one that did arrive is not paid twice).
    sent_pays: Vec<(u64, String, Value)>,
    /// Channels of the link that last dropped: their job tables wait for shares sent again.
    retired: BTreeSet<u32>,
    /// Shares counted from the hashmaker's sending them again after a drop.
    resent_counted: u64,
    /// Jobs its gateway showed to be blinded.
    jobs_shown_blinded: u64,
    /// The gateway's word for whose key its last job has.
    blinding: Option<String>,
    /// Each job key hash seen, with the previous block its job was on.
    keys_seen: Vec<(String, String)>,
    first_proven: Option<Instant>,
    /// When the gateway first accepted a share (and the time to report it): the rental's time runs from here,
    /// so the seconds spent connecting and moving the miners are not taken from it.
    first_accepted: Option<(Instant, u64)>,
    /// The hashmaker said a share waits for payment, how many times, and its last count when it did.
    dues: u64,
    last_due: Option<(u128, u64)>,
    /// Payments queued for the wallet and not yet answered, and how long the last ones that bought a ticket took.
    in_flight: u64,
    buys: VecDeque<f64>,
    guard: Guard,
}

impl St {
    /// The hashmaker waits for a payment: say `paying` if one is on its way and won't arrive, by the measured buys or
    /// by how long the clock has run, before the hashmaker's 2 s clock is out. Once for each wait; the wait is over
    /// when what's been paid lets the next share go.
    fn say_paying_if_late(&mut self, tx: &Sender) {
        let Some(since) = self.guard.due_open_since else { return };
        let mut paid = self.standing();
        paid.paid = self.released.saturating_sub(self.in_flight);
        if !paid.needed() {
            self.guard.due_open_since = None;
            self.guard.paying_said = false;
            return;
        }
        if self.in_flight == 0 || self.guard.paying_said {
            return;
        }
        let measured = self.standing().buy_secs;
        let clock = order::WAIT_FOR_PAYMENT.as_secs_f64() - IN_TIME_MARGIN;
        let on_its_way = self.guard.in_flight_since.map_or(0.0, |t| t.elapsed().as_secs_f64());
        // the hashmaker's clock starts again with each payment that lands, so a wait is timed from the later of the
        // due and the payment now on its way
        let since = self.guard.in_flight_since.map_or(since, |f| f.max(since));
        // the hashmaker's clock starts when a payment is credited, a little before this side hears so, and the ticker
        // comes round every half second: said half a second into the wait, it's in well before the clock's two. But a
        // payment the measured buys say lands by 1.2 s into the wait needs no wait said, which would use one of the
        // hour's few: a wallet on a slow box at about a second a payment, often caught short, would run out of them.
        // One past its measured time is late, and said at once
        let elapsed = since.elapsed().as_secs_f64();
        let left = measured - on_its_way;
        let lands_in_time = measured > 0.0 && left >= 0.0 && elapsed + left <= LANDS_BY.as_secs_f64();
        if measured <= 0.0 || measured.max(on_its_way) > clock || (since.elapsed() >= PAYING_AFTER && !lands_in_time) {
            let _ = tx.send(&Msg::Paying);
            self.guard.paying_said = true;
        }
    }

    /// The ticker's housekeeping, twice a second: `paying` said for a payment that won't arrive in time, and the
    /// dropped link's gateway sessions closed once their window for shares sent again is over.
    fn tick(&mut self, tx: &Sender) {
        self.say_paying_if_late(tx);
        self.say_resynced(tx);
        if self.guard.retire_until.is_some_and(|t| Instant::now() > t) {
            self.guard.retire_until = None;
            self.guard.resend_pending.clear();
            for (_, u) in self.guard.retired_up.drain() {
                let _ = u.shutdown(std::net::Shutdown::Both);
            }
        }
    }

    /// A share sent again, counted: part of what this side says its count is after the resume.
    fn count_resent(&mut self, work: u128) {
        self.resent_counted += 1;
        if self.guard.resync_base.is_some() && !self.guard.resync_said {
            self.guard.resync_resent.0 += work;
            self.guard.resync_resent.1 += 1;
        }
    }

    /// Once the hashmaker's resends are all here and settled (each counted, or refused, or past waiting for its
    /// verdict), say this side's count: at the drop, and what it counted from them.
    fn say_resynced(&mut self, tx: &Sender) {
        let (Some((w, p)), Some(at)) = (self.guard.resync_base, self.guard.resync_marker) else { return };
        if self.guard.resync_said || !(self.guard.resend_pending.is_empty() || at.elapsed() > RESYNC_SETTLE) {
            return;
        }
        self.guard.resync_said = true;
        let (rw, rp) = self.guard.resync_resent;
        let _ = tx.send(&Msg::Resynced { work: w + rw, proven: p + rp });
    }

    fn lock_ahead(&mut self, tx: &Sender) {
        if self.queue.is_some() {
            return;
        }
        let want = self.released + AHEAD;
        let next = self.locked.last().copied().unwrap_or(self.released).max(self.released) + 1;
        for slice in next..=want {
            match self.rail.lock(slice, self.terms.price_msat) {
                Ok(h) => {
                    self.locked.insert(slice);
                    self.lock_hashes.insert(slice, hex::encode(h));
                    let _ = tx.send(&Msg::Lock { slice, hash: hex::encode(h) });
                }
                Err(e) => {
                    self.events.push(json!({"ev": "lock failed", "slice": slice, "why": e, "atMs": now_ms()}));
                    return;
                }
            }
        }
    }

    /// End the rental from this side.
    fn end(&mut self, why: &str, tx: &Sender) {
        self.closed = Some(why.to_string());
        let _ = tx.send(&Msg::Close { reason: why.into(), slices: Some(self.done.len() as u64) });
        tx.shutdown();
    }

    /// The largest share a live channel could send now.
    fn largest_share(&self) -> u128 {
        self.meter.largest_share(self.upstreams.keys().copied())
    }

    /// What this rental stands at for [`crate::order`], by this side's own count.
    fn standing(&self) -> order::Standing {
        // the output, in money, since the first proof
        let msat_a_second = self.first_proven.map_or(0.0, |t| {
            let seconds = t.elapsed().as_secs_f64();
            if seconds < 1.0 {
                0.0
            } else {
                self.meter.work as f64 / self.terms.slice_work as f64 * self.terms.price_msat as f64 / seconds
            }
        });
        order::Standing {
            proven: self.meter.work,
            largest_share: self.largest_share(),
            paid: self.released,
            start_slices: self.terms.start_slices,
            slice_work: self.terms.slice_work,
            price_msat: self.terms.price_msat,
            msat_a_second,
            buy_secs: order::buy_estimate(self.buys.iter().copied()),
        }
    }

    /// The rental's budget can't pay its next slice: by its price, or as the wallet said when it refused one for a
    /// budget, moving nothing (a ticket the budget left can't buy: 0.2.14 on mainnet, 495 sats left of 20,202 and a
    /// smallest ticket of 546; or the task's budget in the owner's rules). Only the wallet knows the seller's smallest
    /// ticket and the task's budget: a ticket is never under a slice, so the budget alone can't say. Why, if so.
    fn budget_spent(&self) -> Option<&'static str> {
        if self.spent.is_some() {
            return self.spent;
        }
        // by the slices the wallet said it paid: one that failed, or whose answer was lost, is not counted as paid
        let by_price = self.budget_msat.is_some_and(|b| (self.paid_slices() + 1).saturating_mul(self.terms.price_msat) > b);
        by_price.then_some(order::BUDGET_USED_UP)
    }

    /// End the rental from this side once its budget is spent and the work it paid for is used (the next share
    /// wouldn't fit): before the hashmaker holds a share it would wait for payment of, and ends the rental unpaid.
    /// Whether it ended it.
    ///
    /// Never after a payment that failed (the wallet's error, money that may have moved): that rental ends on the
    /// failure's path ("could not be paid", unpaid), not as a budget used up, which reads as the renter's own choice.
    /// Nor while a payment is on its way: its answer decides.
    fn end_if_spent(&mut self, tx: &Sender) -> bool {
        if self.closed.is_some() || self.pay_failed || self.in_flight > 0 {
            return false;
        }
        let Some(why) = self.budget_spent() else { return false };
        // the work the slices confirmed paid cover, not those released (one released may have failed or been lost)
        if order::fits(self.meter.work, self.largest_share().max(1), self.paid_slices(), self.terms.start_slices, self.terms.slice_work) {
            return false;
        }
        self.events.push(json!({"ev": "budget spent", "why": why, "released": self.released, "atMs": now_ms()}));
        self.end(why, tx);
        true
    }

    /// The rental's budget as the hashtaker raised it. A budget the wallet said was spent is asked about again: the
    /// next slice is asked for once, and the wallet decides. A refusal for the task's budget in the owner's rules is
    /// said again then (the rules decide, not the rental's budget), and nothing more is asked until the next top-up.
    fn top_up(&mut self, budget_msat: Option<u64>, tx: &Sender) {
        let rose = match (self.budget_msat, budget_msat) {
            (Some(was), Some(now)) => now > was,
            (Some(_), None) => true,
            _ => false,
        };
        self.budget_msat = budget_msat;
        if rose && self.spent.take().is_some() {
            self.events.push(json!({"ev": "budget raised: asking the wallet again", "budgetMsat": budget_msat, "atMs": now_ms()}));
        }
        self.settle_up(tx);
    }

    /// Note slices' worth of proven work reached, and pay whatever [`order::pay_next`] says is due.
    fn settle_up(&mut self, tx: &Sender) {
        // nothing more once this side has ended it, whatever is still on its way
        if self.closed.is_some() {
            return;
        }
        let s = self.terms.slice_work;
        while self.meter.work >= (self.done.len() as u128 + 1) * s {
            let w = self.meter.work;
            self.done.push((w, now_ms()));
        }
        loop {
            let s = self.standing();
            // a ticket bought ahead, so the slice after it is paid from credit and not on a buy (#64)
            let ahead = self.queue.is_some() && s.buy_ahead(self.guard.credit_msat) && !s.pay_next();
            if self.queue.is_some() {
                // the wallet pays one slice at a time, so each knows the credit at the seller and the budget left: a
                // ticket is sized to keep what's gone and unworked within the step, and never past the budget
                if self.in_flight > 0 || !s.pay_next_with(self.guard.credit_msat) {
                    return;
                }
            } else if !s.pay_next() {
                return;
            }
            let slice = self.released + 1;
            if self.stop_paying_after.is_some_and(|n| slice > n) {
                return;
            }
            if self.budget_msat.is_some_and(|b| slice * self.terms.price_msat > b) {
                return;
            }
            // the wallet said a budget is spent: none is asked for again. The rental ends as what's paid runs out
            // ([`St::end_if_spent`])
            if self.spent.is_some() {
                return;
            }
            let receipt = Receipt {
                rental: self.rental.clone(),
                slice,
                work: self.meter.work,
                accepted: self.meter.accepted,
                rejected: self.meter.rejected,
                at_ms: now_ms(),
            }
            .sign(&self.key);
            if let Some(q) = &self.queue {
                if self.pay_failed || q.send((slice, receipt.clone(), ahead)).is_err() {
                    return;
                }
                self.in_flight += 1;
                self.guard.in_flight_since = Some(Instant::now());
                self.receipts.push(receipt);
                self.released = slice;
                continue;
            }
            let Ok(pre) = self.rail.release(slice) else { return };
            self.locked.remove(&slice);
            self.lock_hashes.remove(&slice);
            self.sent_pays.push((slice, hex::encode(pre), receipt.clone()));
            if self.sent_pays.len() > AHEAD as usize + 2 {
                self.sent_pays.remove(0);
            }
            let _ = tx.send(&Msg::Pay { slice, preimage: hex::encode(pre), receipt: receipt.clone() });
            self.receipts.push(receipt);
            self.pays.push(json!({"slice": slice, "atMs": now_ms()}));
            self.released = slice;
            self.lock_ahead(tx);
        }
    }

    /// Slices paid: by the wallet (its answers), or released over the link.
    fn paid_slices(&self) -> u64 {
        if self.queue.is_some() || !self.pays.is_empty() && self.pays.iter().any(|p| p.get("ok").is_some()) {
            self.pays.iter().filter(|p| p["ok"] == true).count() as u64
        } else {
            self.released
        }
    }

    fn report(&self) -> Value {
        json!({
            "role": "buyer", "rental": self.rental, "terms": self.terms.to_json(), "meter": self.meter.to_json(),
            "latencyMs": self.meter.latency_json(),
            "slicesDone": self.done.iter().map(|(w, t)| json!({"work": w.to_string(), "atMs": t})).collect::<Vec<_>>(),
            "released": self.released, "locked": self.locked, "pays": self.pays, "receipts": self.receipts,
            "lastRate": self.rate, "closed": self.closed, "payFailed": self.pay_failed, "events": self.events,
            "resentCounted": self.resent_counted, "resendsRefused": self.guard.resends_refused, "comebacks": self.guard.comebacks.len(), "jobsShownBlinded": self.jobs_shown_blinded, "blinding": self.blinding,
            "keysSeen": self.keys_seen.iter().map(|(k, p)| json!({"keyHash": k, "prevblock": p})).collect::<Vec<_>>(),
            "firstAcceptedMs": self.first_accepted.map(|(_, ms)| ms),
            "dues": self.dues, "lastDue": self.last_due.map(|(w, p)| json!({"work": w.to_string(), "paid": p})),
            "paidSlices": self.paid_slices(), "spentMsat": self.paid_slices() * self.terms.price_msat,
            // how long a ticket buy takes (p95 of the last few), and how far ahead of need the next one starts (#64)
            "buySecs": self.standing().buy_secs, "buyLeadSecs": self.standing().buy_lead_secs(),
            "miners": self.upstreams.len(), "budgetMsat": self.budget_msat,
            // what left the wallet for the rental (tickets bought whole, with their fees), and what its stop
            // said stays with the seller as credit: a ticket bought for a small rental is more than it uses
            "walletMovedSats": self.pays.iter().filter_map(|p| p["wallet"]["charged_sats"].as_u64()).sum::<u64>(),
            "leftWithSellerMsat": self.events.iter().rev().find(|e| e["ev"] == "wallet session stopped")
                .and_then(|e| e["result"]["http"]["left_with_seller_msat"].as_str()).and_then(|s| s.parse::<u64>().ok()),
        })
    }
}

fn write_report(path: &Option<PathBuf>, v: &Value) {
    if let Some(p) = path {
        let tmp = p.with_extension("tmp");
        if std::fs::write(&tmp, serde_json::to_vec_pretty(v).unwrap_or_default()).is_ok() {
            let _ = std::fs::rename(&tmp, p);
        }
    }
}

/// Run one rental to its end and return the report. `rail` makes, releases and cancels the
/// tickets; whatever is still locked at the end is cancelled.
pub fn run(cfg: Config, rail: Box<dyn HashtakerRail>) -> Result<Value, String> {
    if cfg.gateway_api.is_none() && !cfg.allow_unblinded {
        return Err("nothing to check this gateway's blinding with: a hashmaker could drop the shares that win".into());
    }
    // the gateway's own first job is checked before the hashmaker is dialled, so nothing is paid, not the start fee
    // nor the first ticket, onto jobs that aren't blinded
    if !cfg.allow_unblinded {
        match blind::probe(&cfg.upstream, cfg.gateway_api.as_deref(), &cfg.user) {
            blind::Shown::Blinded(_) => {}
            other => return Err(format!("{} Nothing was paid.", other.words())),
        }
    }
    let link::Link { tx, mut rx, .. } = link::dial(&cfg.hashmaker, cfg.key, cfg.hashmaker_key).map_err(|e| e.to_string())?;
    tx.send(&Msg::Hello { rental: cfg.rental.clone(), listing: cfg.listing.clone(), terms: cfg.terms.clone(), miners: cfg.miners, proof: Some(PROOF.into()) })
        .map_err(|e| e.to_string())?;
    match rx.recv_within(link::HANDSHAKE_TIMEOUT).map_err(|e| e.to_string())? {
        Some(Msg::Welcome { terms_hash, proof, .. }) if terms_hash == hex::encode(cfg.terms.hash()) => {
            if proof.as_deref() != Some(PROOF) {
                tx.shutdown();
                return Err(format!("this hashmaker doesn't prove shares ({PROOF}): it needs updating"));
            }
        }
        // an older hashmaker's terms hash differently and it says no proof: name the cause, not the hash
        Some(Msg::Welcome { proof: None, .. }) => {
            tx.shutdown();
            return Err(format!("this hashmaker needs updating (it doesn't prove shares, {PROOF})"));
        }
        Some(Msg::Close { reason, .. }) => return Err(format!("hashmaker refused: {reason}")),
        _ => return Err("no welcome".into()),
    }
    eprintln!("hashtaker: rental {} with hashmaker {}", cfg.rental, cfg.hashmaker);
    let st = Arc::new(Mutex::new(St {
        terms: cfg.terms.clone(),
        rental: cfg.rental.clone(),
        key: cfg.key,
        meter: Meter::default(),
        locked: BTreeSet::new(),
        released: 0,
        done: Vec::new(),
        receipts: Vec::new(),
        upstreams: HashMap::new(),
        rail,
        stop_paying_after: cfg.stop_paying_after,
        last_work: Instant::now(),
        rate: None,
        pays: Vec::new(),
        events: Vec::new(),
        closed: None,
        queue: None,
        pay_failed: false,
        budget_msat: cfg.budget_msat,
        spent: None,
        lock_hashes: BTreeMap::new(),
        sent_pays: Vec::new(),
        retired: BTreeSet::new(),
        resent_counted: 0,
        jobs_shown_blinded: 0,
        blinding: None,
        keys_seen: Vec::new(),
        first_proven: None,
        first_accepted: None,
        dues: 0,
        last_due: None,
        in_flight: 0,
        buys: VecDeque::new(),
        guard: Guard::default(),
    }));
    lock(&st).lock_ahead(&tx);
    let blind_check = if cfg.allow_unblinded { None } else { cfg.gateway_api.clone().map(|a| Arc::new(blind::Check::new(a))) };

    // the wallet's payer, one slice at a time, off the relay's path
    let stopped_session: Arc<Mutex<Option<Value>>> = Arc::default();
    let redial = Redial { hashmaker: cfg.hashmaker.clone(), key: cfg.key, hashmaker_key: cfg.hashmaker_key, rental: cfg.rental.clone(), terms: cfg.terms.clone() };
    let payer_thread = cfg.payer.map(|mut p| {
        let (qtx, qrx) = mpsc::channel::<(u64, Value, bool)>();
        lock(&st).queue = Some(qtx);
        let (st, rental, out, ptx) = (st.clone(), cfg.rental.clone(), stopped_session.clone(), tx.clone());
        {
            let (credit, left) = p.held();
            let mut g = lock(&st);
            (g.guard.credit_msat, g.guard.budget_left) = (credit, left);
        }
        std::thread::spawn(move || {
            for (slice, receipt, ahead) in qrx {
                if lock(&st).pay_failed {
                    continue;
                }
                let t0 = Instant::now();
                // the ticket this payment may buy, if the credit at the seller doesn't cover it: what keeps the money gone
                // and not yet worked within the step the rental has earned, by this side's own count now, the start fee
                // still to pay with it
                let ticket = {
                    let mut s = lock(&st).standing();
                    s.paid = slice;
                    s.ticket_msat_with(p.held().0)
                };
                p.caps_for(ticket);
                let r = p.pay(&rental, slice, &receipt);
                let mut g = lock(&st);
                (g.guard.credit_msat, g.guard.budget_left) = p.held();
                let ms = t0.elapsed().as_millis() as u64;
                g.in_flight = g.in_flight.saturating_sub(1);
                if r.as_ref().is_ok_and(|v| v["charged_sats"].as_u64().is_some_and(|c| c > 0)) {
                    if g.buys.len() == BUYS_KEPT {
                        g.buys.pop_front();
                    }
                    g.buys.push_back(ms as f64 / 1000.0);
                }
                match r {
                    // its answer lost after it was sent: it may have paid. Not paid again; the hashmaker, which knows
                    // whether it arrived, ends the rental if it didn't
                    Ok(v) if v["verdict"] == "unknown" => g.pays.push(json!({"slice": slice, "atMs": now_ms(), "ms": ms, "ok": null, "unknown": true, "wallet": v})),
                    Ok(v) => g.pays.push(json!({"slice": slice, "atMs": now_ms(), "ms": ms, "ok": true, "ticketMsat": ticket, "ahead": ahead, "wallet": v})),
                    // a budget of the renter's own is spent (the wallet refused it, nothing moved): not a failed payment.
                    // The slice is taken back, no other is asked for, and the rental ends as what's paid runs out, the
                    // hashmaker told why. A first slice so refused is a rental that could not start
                    Err(why) if g.paid_slices() > 0 && g.released == slice && rail::budget_spent(&why).is_some() => {
                        g.spent = rail::budget_spent(&why);
                        g.released = slice - 1;
                        g.receipts.pop();
                        g.events.push(json!({"ev": "refused: budget spent", "slice": slice, "atMs": now_ms(), "ms": ms, "why": why}));
                    }
                    Err(why) => {
                        g.pay_failed = true;
                        g.pays.push(json!({"slice": slice, "atMs": now_ms(), "ms": ms, "ok": false, "why": why}));
                    }
                }
                // the next slice, if one is due now, now that this one is answered; or the end, if the budget is spent
                g.settle_up(&ptx);
                g.end_if_spent(&ptx);
            }
            *out.lock().unwrap_or_else(|p| p.into_inner()) = p.stop();
        })
    });
    lock(&st).settle_up(&tx);

    // ticker: idle, duration, report
    {
        let st = st.clone();
        let tx = tx.clone();
        let report = cfg.report.clone();
        let (idle, cut, live, budget, added) = (cfg.idle, cfg.cut.clone(), cfg.live.clone(), cfg.budget_msat, cfg.added.clone());
        let mut duration = cfg.duration;
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(500));
            let mut g = lock(&st);
            if let Some(l) = &live {
                *l.lock().unwrap_or_else(|p| p.into_inner()) = g.report();
            }
            if g.closed.is_some() {
                return;
            }
            // budget and time the hashtaker added: a slice held back by the budget is paid now, if it is due
            if let Some(a) = &added {
                duration = cfg.duration.map(|d| d + Duration::from_secs(a.secs()));
                let more = budget.map(|b| b.saturating_add(a.msat()));
                if more != g.budget_msat {
                    g.top_up(more, &tx);
                }
            }
            g.tick(&tx);
            let why = if cut.as_ref().is_some_and(|c| c.load(Ordering::Relaxed)) {
                Some("cut by the hashtaker")
            } else if g.end_if_spent(&tx) {
                // the next slice can't be paid: ended as the last paid one runs out, before the hashmaker does it
                return;
            } else if g.standing().too_slow() {
                Some("the route to this hashmaker is too slow for its miners' rate")
            } else if g.pay_failed && g.paid_slices() == 0 {
                Some("the first slice could not be paid")
            } else if g.last_work.elapsed() > idle {
                Some("no proven work")
            } else if time_over(g.first_accepted.map(|(t, _)| t), duration) {
                Some("rental time over")
            } else {
                None
            };
            if let Some(why) = why {
                g.end(why, &tx);
                return;
            }
            write_report(&report, &g.report());
        });
    }

    loop {
        let m = match rx.recv() {
            Ok(Some(m)) => m,
            Ok(None) => continue,
            Err(e) => {
                if lock(&st).closed.is_none() {
                    // a link that dropped is made again within the grace time, and the rental carries on
                    if let Some(back) = come_back(&redial, &tx, &st, &e.to_string()) {
                        rx = back;
                        continue;
                    }
                }
                let mut g = lock(&st);
                if g.closed.is_none() {
                    g.closed = Some(format!("link lost: {e}"));
                }
                break;
            }
        };
        // this side ended it: whatever else was on its way is not read
        {
            let mut g = lock(&st);
            if g.closed.is_some() {
                break;
            }
            g.guard.last_heard = Some(Instant::now());
        }
        match m {
            Msg::Open { chan, worker } => {
                let up = TcpStream::connect(&cfg.upstream);
                let mut g = lock(&st);
                g.events.push(json!({"ev": "open", "chan": chan, "worker": worker, "ok": up.is_ok(), "atMs": now_ms()}));
                match up.and_then(|u| u.try_clone().map(|w| (u, w))) {
                    Ok((u, w)) => {
                        g.upstreams.insert(chan, w);
                        let (st, tx, check) = (st.clone(), tx.clone(), blind_check.clone());
                        std::thread::spawn(move || upstream(chan, u, st, tx, check));
                    }
                    Err(_) => {
                        g.meter.close(chan);
                        let _ = tx.send(&Msg::Shut { chan });
                    }
                }
            }
            Msg::Up { chan, line } => {
                let Some(mut v) = sv1::parse(&line) else { continue };
                let is_share = sv1::submit_job(&v).is_some();
                let theirs = v.get("id").cloned().unwrap_or(Value::Null);
                {
                    let mut g = lock(&st);
                    // a line that could change what a share is worth, or the jobs, goes no further than here
                    if sv1::method(&v).is_some_and(|m| !CARRIED.contains(&m)) {
                        if !theirs.is_null() {
                            let _ = tx.send(&Msg::Down { chan, line: json!({"id": theirs, "result": null, "error": [20, "not carried to the gateway", null]}).to_string() });
                        }
                        continue;
                    }
                    if sv1::method(&v) == Some("mining.configure") {
                        drop_minimum_difficulty(&mut v);
                    }
                    // every share has an id of its own, so its verdict is read: none, or one still waiting, is refused
                    let refusal = if is_share && (theirs.is_null() || g.guard.waiting.contains(&(chan, theirs.to_string()))) {
                        Some(meter::Refused::Bad("a share needs an id of its own".into()))
                    } else if is_share && g.guard.await_job.contains(&chan) {
                        Some(meter::Refused::Bad("its difficulty changed and no job has been checked at it yet".into()))
                    } else {
                        None
                    };
                    if let Some(why) = refusal {
                        g.meter.refuse(&why);
                        let _ = tx.send(&Msg::Down { chan, line: why.rejection(&theirs).to_string() });
                        if g.meter.refused > REFUSED_LEEWAY + g.meter.proven / 8 {
                            g.end("shares that don't prove", &tx);
                        }
                        continue;
                    }
                    if !theirs.is_null() {
                        if is_share {
                            g.guard.waiting.insert((chan, theirs.to_string()));
                        }
                        let own = g.guard.own_id(chan, theirs.clone());
                        v["id"] = json!(own);
                    }
                }
                if is_share {
                    // read under the lock, hashed outside it
                    let claim = lock(&st).meter.claim(chan, &v);
                    let proved = claim.and_then(|c| {
                        let h = c.hash();
                        lock(&st).meter.commit(&c, h)
                    });
                    let mut g = lock(&st);
                    match proved {
                        Ok(p) if p.old => {
                            g.end("shares arrive too old", &tx);
                            continue;
                        }
                        Ok(p) if p.old_job => {
                            g.end("shares on an old job", &tx);
                            continue;
                        }
                        Ok(_) => {
                            g.last_work = Instant::now();
                            g.first_proven.get_or_insert_with(Instant::now);
                            g.guard.proven_at.push_back(Instant::now());
                            while g.guard.proven_at.front().is_some_and(|t| t.elapsed() > RATE_WINDOW * 2) {
                                g.guard.proven_at.pop_front();
                            }
                        }
                        Err(why) => {
                            if let Some(own) = v.get("id").and_then(Value::as_u64) {
                                g.guard.up_ids.remove(&own);
                            }
                            g.guard.waiting.remove(&(chan, theirs.to_string()));
                            let answer = why.rejection(&theirs);
                            let _ = tx.send(&Msg::Down { chan, line: answer.to_string() });
                            // the odd one is a job change in flight; many are shares nobody hashed
                            if g.meter.refused > REFUSED_LEEWAY + g.meter.proven / 8 {
                                g.end("shares that don't prove", &tx);
                            }
                            continue;
                        }
                    }
                } else {
                    lock(&st).meter.note_up(chan, &v);
                }
                let mut g = lock(&st);
                let out = sv1::with_user(&v, &cfg.user).unwrap_or_else(|| v.to_string());
                if let Some(u) = g.upstreams.get_mut(&chan) {
                    if u.write_all(format!("{out}\n").as_bytes()).is_err() {
                        g.upstreams.remove(&chan);
                        let _ = tx.send(&Msg::Shut { chan });
                    }
                }
                if is_share {
                    g.settle_up(&tx);
                    g.end_if_spent(&tx);
                }
            }
            Msg::Due { work, paid } => {
                // a nudge: what's due is by this side's own count
                let mut g = lock(&st);
                g.dues += 1;
                g.last_due = Some((work, paid));
                g.settle_up(&tx);
                // a share waits for a slice the budget can't pay: ended now, not on the hashmaker's clock
                if g.end_if_spent(&tx) {
                    continue;
                }
                // a payment on its way that won't arrive within the hashmaker's short clock: it waits for it, its
                // miners on its own pool meanwhile. One the measured buys say arrives in time needs no move; should it
                // not, the ticker says paying before the clock runs out
                // a share held after a wait already said for: a new wait of its own
                if g.guard.paying_said {
                    g.guard.paying_said = false;
                    g.guard.due_open_since = None;
                }
                g.guard.due_open_since.get_or_insert_with(Instant::now);
                g.say_paying_if_late(&tx);
            }
            Msg::Resend { chan, line } => {
                // a share the hashmaker sent before the drop: one this side counted already is passed over. A new one
                // goes on to its gateway session of before the drop, for its verdict, aged as of the drop, and only as
                // many as could have been on their way
                let Some(mut v) = sv1::parse(&line) else { continue };
                let mut g = lock(&st);
                let theirs = v.get("id").cloned().unwrap_or(Value::Null);
                if !g.retired.contains(&chan) || !g.guard.retired_up.contains_key(&chan) || theirs.is_null() || sv1::submit_job(&v).is_none() {
                    g.guard.resends_refused += 1;
                    continue;
                }
                let own = g.guard.next_id;
                v["id"] = json!(own);
                let (c, h) = match g.meter.resent_claim(chan, &v) {
                    Ok(Some(ch)) => ch,
                    Ok(None) => continue,
                    Err(_) => {
                        g.guard.resends_refused += 1;
                        continue;
                    }
                };
                let out = sv1::with_user(&v, &cfg.user).unwrap_or_else(|| v.to_string());
                let sent = g.guard.retired_up.get_mut(&chan).is_some_and(|u| u.write_all(format!("{out}\n").as_bytes()).is_ok());
                if !sent {
                    g.guard.retired_up.remove(&chan);
                    g.guard.resends_refused += 1;
                    continue;
                }
                g.guard.own_id(chan, theirs);
                let at = g.guard.dropped_at.unwrap_or_else(Instant::now);
                // past what could have been on its way, a share sent again counts only once its gateway takes it: that
                // verdict is the proof it reached the gateway, and it's still aged as of the drop
                if g.guard.resend_left == 0 {
                    g.guard.resend_pending.insert(own, (c, h, at));
                    continue;
                }
                g.guard.resend_left -= 1;
                match g.meter.commit_at(&c, h, at) {
                    Ok(p) if p.old => g.end("shares arrive too old", &tx),
                    Ok(p) if p.old_job => g.end("shares on an old job", &tx),
                    Ok(p) => {
                        g.count_resent(p.work);
                        g.last_work = Instant::now();
                        g.settle_up(&tx);
                    }
                    Err(_) => g.guard.resends_refused += 1,
                }
            }
            Msg::Resynced { .. } => {
                // the hashmaker's resends are all sent: this side says its count once they're settled
                let mut g = lock(&st);
                g.guard.resync_marker = Some(Instant::now());
                g.say_resynced(&tx);
            }
            Msg::Shut { chan } => {
                // the miner is gone: close its upstream session; the channel is let go (and the
                // hashmaker told) when that session's last verdict has been read
                let mut g = lock(&st);
                if let Some(u) = g.upstreams.remove(&chan) {
                    let _ = u.shutdown(std::net::Shutdown::Both);
                }
            }
            Msg::Rate { hs, miners } => lock(&st).rate = Some(json!({"hs": hs, "miners": miners, "atMs": now_ms()})),
            Msg::Ping { n } => {
                let _ = tx.send(&Msg::Pong { n });
            }
            Msg::Close { reason, .. } => {
                // the hashmaker answers our own close with one of its own: the first reason stands
                lock(&st).closed.get_or_insert_with(|| format!("hashmaker closed: {reason}"));
                break;
            }
            _ => {}
        }
    }
    // the wallet's payer: the slices asked for are paid, or found failed, before the session ends
    let payer = lock(&st).queue.take();
    drop(payer);
    if let Some(h) = payer_thread {
        let _ = h.join();
    }
    let mut g = lock(&st);
    if let Some(stop) = stopped_session.lock().unwrap_or_else(|p| p.into_inner()).take() {
        g.events.push(json!({"ev": "wallet session stopped", "result": stop, "atMs": now_ms()}));
    }
    for slice in std::mem::take(&mut g.locked) {
        g.rail.cancel(slice);
        g.events.push(json!({"ev": "cancelled", "slice": slice, "atMs": now_ms()}));
    }
    let mut ups: Vec<TcpStream> = g.upstreams.drain().map(|(_, u)| u).collect();
    ups.extend(g.guard.retired_up.drain().map(|(_, u)| u));
    for u in ups {
        let _ = u.shutdown(std::net::Shutdown::Both);
    }
    tx.shutdown();
    let r = g.report();
    write_report(&cfg.report, &r);
    if let Some(l) = &cfg.live {
        *l.lock().unwrap_or_else(|p| p.into_inner()) = r.clone();
    }
    Ok(r)
}

/// What dialling the hashmaker again needs.
struct Redial {
    hashmaker: String,
    key: SecretKey,
    hashmaker_key: PublicKey,
    rental: String,
    terms: Terms,
}

/// The link dropped: the old upstream sessions end (the hashmaker has let their channels go and opens new
/// ones), and the hashmaker is dialled again, with growing pauses, until most of its grace time is gone. On its
/// welcome, every clone of `tx` sends on the new link, and the locks and the last payments are sent again. A dial
/// or a welcome that does not come is given up at the deadline, whatever the road does. `None`: not back in
/// time, or the hashmaker refused.
fn come_back(cfg: &Redial, tx: &Sender, st: &Arc<Mutex<St>>, why: &str) -> Option<link::Receiver> {
    let deadline = Instant::now() + Duration::from_millis(cfg.terms.grace_ms) * 4 / 5;
    {
        let mut g = lock(st);
        g.events.push(json!({"ev": "link lost, dialling again", "why": why, "atMs": now_ms()}));
        // each drop lets the hashmaker send shares again: a link that keeps dropping ends the rental
        let now = Instant::now();
        while g.guard.comebacks.front().is_some_and(|t| now.duration_since(*t) > Duration::from_secs(3600)) {
            g.guard.comebacks.pop_front();
        }
        if g.guard.comebacks.len() >= COMEBACKS_AN_HOUR {
            g.closed.get_or_insert_with(|| "the link to this hashmaker drops too often".to_string());
            return None;
        }
        g.guard.comebacks.push_back(now);
        for chan in std::mem::take(&mut g.retired) {
            g.meter.close(chan);
        }
        for (_, u) in g.guard.retired_up.drain() {
            let _ = u.shutdown(std::net::Shutdown::Both);
        }
        g.retired = g.meter.channels().into_iter().collect();
        // the gateway sessions stay open a while, for the shares on their way when the link dropped
        let up: Vec<(u32, TcpStream)> = g.upstreams.drain().collect();
        g.guard.retired_up.extend(up);
        g.guard.retire_until = None;
        g.guard.dropped_at = Some(g.guard.last_heard.unwrap_or(now));
        g.guard.resend_left = g.guard.could_be_in_flight(now);
        g.guard.resync_base = Some((g.meter.work, g.meter.proven));
        g.guard.resync_resent = (0, 0);
        g.guard.resync_marker = None;
        g.guard.resync_said = false;
    }
    let mut pause = Duration::from_millis(250);
    while Instant::now() + pause < deadline {
        std::thread::sleep(pause);
        pause = (pause * 2).min(Duration::from_secs(1));
        if lock(st).closed.is_some() {
            return None;
        }
        let left = || deadline.saturating_duration_since(Instant::now()).min(link::HANDSHAKE_TIMEOUT);
        let Ok(link::Link { tx: new_tx, rx: mut new_rx, .. }) = link::dial_within(&cfg.hashmaker, cfg.key, cfg.hashmaker_key, left()) else { continue };
        if new_tx.send(&Msg::Resume { rental: cfg.rental.clone() }).is_err() {
            continue;
        }
        match new_rx.recv_within(left()) {
            Ok(Some(Msg::Welcome { terms_hash, proof, .. })) if terms_hash == hex::encode(cfg.terms.hash()) && proof.as_deref() == Some(PROOF) => {
                tx.adopt(new_tx);
                let mut g = lock(st);
                let allowed = g.guard.resend_left;
                g.events.push(json!({"ev": "rental resumed", "resendsAllowed": allowed, "atMs": now_ms()}));
                g.guard.retire_until = Some(Instant::now() + RESEND_WINDOW);
                let released = g.released;
                for (slice, hash) in g.lock_hashes.clone() {
                    if slice > released {
                        let _ = tx.send(&Msg::Lock { slice, hash });
                    }
                }
                for (slice, preimage, receipt) in g.sent_pays.clone() {
                    // its lock may have been lost with the link too; a slice already paid ignores both
                    if let Ok(p) = hex::decode(&preimage) {
                        let _ = tx.send(&Msg::Lock { slice, hash: hex::encode(sha256(&p)) });
                    }
                    let _ = tx.send(&Msg::Pay { slice, preimage, receipt });
                }
                g.settle_up(tx);
                return Some(new_rx);
            }
            Ok(Some(Msg::Close { reason, .. })) => {
                lock(st).events.push(json!({"ev": "resume refused", "why": reason, "atMs": now_ms()}));
                return None;
            }
            _ => continue,
        }
    }
    None
}

/// `mining.configure` without its `minimum-difficulty` extension, which would let the hashmaker set what a share is
/// worth at the renter's gateway.
fn drop_minimum_difficulty(v: &mut Value) {
    let Some(p) = v.get_mut("params").and_then(Value::as_array_mut) else { return };
    if let Some(exts) = p.first_mut().and_then(Value::as_array_mut) {
        exts.retain(|e| e.as_str() != Some("minimum-difficulty"));
    }
    if let Some(opts) = p.get_mut(1).and_then(Value::as_object_mut) {
        opts.retain(|k, _| !k.starts_with("minimum-difficulty"));
    }
}

/// Is a rental's time up? It runs from the first share its gateway accepted: none yet, none of it used.
fn time_over(first_accepted: Option<Instant>, duration: Option<Duration>) -> bool {
    matches!((first_accepted, duration), (Some(t), Some(d)) if t.elapsed() > d)
}

fn lock(st: &Mutex<St>) -> std::sync::MutexGuard<'_, St> {
    st.lock().unwrap_or_else(|p| p.into_inner())
}

fn upstream(chan: u32, u: TcpStream, st: Arc<Mutex<St>>, tx: Sender, check: Option<Arc<blind::Check>>) {
    let mut r = BufReader::new(u);
    let mut line = String::new();
    loop {
        line.clear();
        match r.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let Some(mut v) = sv1::parse(&line) else { continue };
        // a job the gateway can't show to be blinded goes no further: one is enough to lose a block. The gateway
        // is asked with no lock held, and this channel's lines stay in order
        let shown = match (&check, sv1::method(&v) == Some("mining.notify")) {
            (Some(c), true) => {
                let d = st.lock().unwrap_or_else(|p| p.into_inner()).meter.diff_now(chan);
                Some((c.job_seen(&v, d), blind::pot_of(d)))
            }
            _ => None,
        };
        let mut g = st.lock().unwrap_or_else(|p| p.into_inner());
        if g.closed.is_some() {
            break;
        }
        match shown {
            Some((Ok(seen), pot)) => {
                g.jobs_shown_blinded += 1;
                g.guard.checked_pot.insert(chan, pot);
                g.guard.await_job.remove(&chan);
                g.blinding = Some(seen.mode.clone());
                // each key and the block it was used after, once: what shows a key never outlives its block
                let rec = (seen.key_hash, seen.prevblock);
                if g.keys_seen.len() < KEYS_REPORTED && !g.keys_seen.contains(&rec) {
                    g.keys_seen.push(rec);
                }
            }
            Some((Err(why), _)) => {
                g.events.push(json!({"ev": "a job not shown to be blinded", "why": why, "atMs": now_ms()}));
                g.end("the gateway's jobs aren't blinded", &tx);
                break;
            }
            None => {}
        }
        // the gateway's jobs are for hashing and for checking, or the rental can't go on
        if sv1::method(&v) == Some("mining.set_extranonce") {
            g.end("the gateway changed the extranonce", &tx);
            break;
        }
        // a share sent again that waited for its verdict: counted once the gateway takes it, before the meter reads that
        // verdict, so the verdict is counted with it
        if let Some((c, h, at)) = v.get("id").and_then(Value::as_u64).and_then(|own| g.guard.resend_pending.remove(&own)) {
            if !sv1::accepted(&v) {
                g.guard.resends_refused += 1;
            } else {
                match g.meter.commit_at(&c, h, at) {
                    Ok(p) if p.old => {
                        g.end("shares arrive too old", &tx);
                        break;
                    }
                    Ok(p) if p.old_job => {
                        g.end("shares on an old job", &tx);
                        break;
                    }
                    Ok(p) => {
                        g.count_resent(p.work);
                        g.last_work = Instant::now();
                        if g.first_accepted.is_none() {
                            g.first_accepted = Some((Instant::now(), now_ms()));
                        }
                    }
                    Err(_) => g.guard.resends_refused += 1,
                }
            }
            g.say_resynced(&tx);
        }
        match g.meter.down(chan, &v) {
            Err(why) => {
                g.events.push(json!({"ev": "a line that can't be checked", "why": why, "atMs": now_ms()}));
                g.end("a job this app can't check", &tx);
                break;
            }
            Ok(Some(crate::meter::Event::Accepted(_))) if g.first_accepted.is_none() => g.first_accepted = Some((Instant::now(), now_ms())),
            Ok(_) => {}
        }
        // a new difficulty: the jobs were checked for shares of the old one's bits. Its shares wait for a job
        // checked at the new one, which a gateway sends with it
        if let (Some(_), Some(d)) = (&check, sv1::set_difficulty(&v)) {
            if g.guard.checked_pot.get(&chan) != Some(&blind::pot_of(d)) {
                g.guard.await_job.insert(chan);
            }
        }
        // an answer to a line of the hashmaker's goes back with its own id
        let mut out = line.trim_end().to_string();
        if sv1::is_response(&v) {
            if let Some(theirs) = g.guard.theirs(chan, &v) {
                v["id"] = theirs;
                out = v.to_string();
            }
        }
        // a channel of a dropped link: its verdicts are counted, and nothing goes to the hashmaker, who let it go
        if !g.retired.contains(&chan) {
            let _ = tx.send(&Msg::Down { chan, line: out });
        }
        if g.meter.verdicts_low {
            g.end("the gateway accepted too few shares", &tx);
            break;
        }
        // a new difficulty changes what's due
        g.settle_up(&tx);
    }
    // this channel's last verdict has been read and sent: it's let go here, unless a dropped link took it, when
    // its job table waits for shares sent again
    let mut g = st.lock().unwrap_or_else(|p| p.into_inner());
    if !g.retired.contains(&chan) {
        g.upstreams.remove(&chan);
        g.meter.close(chan);
        let _ = tx.send(&Msg::Shut { chan });
    }
}

#[cfg(test)]
mod come_back_tests {
    use super::*;

    #[test]
    fn a_rentals_time_runs_from_its_first_accepted_share() {
        let d = Some(Duration::from_secs(5));
        assert!(!time_over(None, d), "no share accepted yet: none of its time used, however long it took to start");
        assert!(!time_over(Some(Instant::now()), d));
        assert!(!time_over(Instant::now().checked_sub(Duration::from_secs(4)), d));
        assert!(time_over(Instant::now().checked_sub(Duration::from_secs(6)), d));
        assert!(!time_over(Instant::now().checked_sub(Duration::from_secs(6)), None), "no time limit");
    }
    use crate::rail::LabHashtaker;
    use std::net::TcpListener;

    fn terms() -> Terms {
        Terms { slice_work: 1 << 32, price_msat: 5_000, grace_ms: 5_000, start_slices: 0 }
    }

    fn state() -> Arc<Mutex<St>> {
        Arc::new(Mutex::new(St {
            terms: terms(),
            rental: "r".into(),
            key: crate::noise::fresh_key(),
            meter: Meter::default(),
            locked: BTreeSet::new(),
            released: 0,
            done: Vec::new(),
            receipts: Vec::new(),
            upstreams: HashMap::new(),
            rail: Box::<LabHashtaker>::default(),
            stop_paying_after: None,
            last_work: Instant::now(),
            rate: None,
            pays: Vec::new(),
            events: Vec::new(),
            closed: None,
            queue: None,
            pay_failed: false,
            budget_msat: None,
            spent: None,
            lock_hashes: BTreeMap::new(),
            sent_pays: Vec::new(),
            retired: BTreeSet::new(),
            resent_counted: 0,
            jobs_shown_blinded: 0,
            blinding: None,
            keys_seen: Vec::new(),
            first_proven: None,
            first_accepted: None,
            dues: 0,
            last_due: None,
            in_flight: 0,
            buys: VecDeque::new(),
            guard: Guard::default(),
        }))
    }

    /// FAILS before (0.2.14 on mainnet): the wallet refused slice 387 for a budget, moving nothing, and the renter
    /// marked the payment failed, asked for nothing more and left the hashmaker to end the rental unpaid. Now, the
    /// refused slice taken back (`spent`), none is asked for again, the work paid for runs out, and the renter ends the
    /// rental itself as its budget spent, with no failed payment.
    #[test]
    fn a_budget_the_wallet_says_is_spent_asks_for_no_more_and_ends_the_rental_as_its_work_runs_out() {
        let (key, hk) = (crate::noise::fresh_key(), crate::noise::fresh_key());
        let (tx, _peer) = a_link(key, hk);
        let st = state();
        let (qtx, qrx) = mpsc::channel::<(u64, Value, bool)>();
        let mut g = lock(&st);
        g.terms.price_msat = 51_000;
        g.queue = Some(qtx);
        g.budget_msat = Some(20_202_000);
        g.released = 386;
        // the wallet's answers: 386 slices paid
        g.pays = vec![json!({"slice": 386, "ok": true}); 386];
        g.spent = rail::budget_spent("What is left of this rental's budget (495 sats) is less than this hashmaker's smallest ticket (546 sats).");
        assert_eq!(g.spent, Some(order::BUDGET_USED_UP));
        assert!((g.released + 1) * g.terms.price_msat <= g.budget_msat.unwrap(), "its price alone fits the budget");
        // the work of slice 386 under way: the next share still fits
        g.meter.work = 385 * g.terms.slice_work;
        g.settle_up(&tx);
        assert!(qrx.try_recv().is_err() && g.released == 386, "no slice asked for again");
        assert!(!g.end_if_spent(&tx) && g.closed.is_none(), "not while the work paid for goes on");
        // that work used: the next share wouldn't fit, and the renter ends it
        g.meter.work = 386 * g.terms.slice_work;
        g.settle_up(&tx);
        assert!(qrx.try_recv().is_err());
        assert!(g.end_if_spent(&tx));
        assert_eq!(g.closed.as_deref(), Some(order::BUDGET_USED_UP));
        assert!(!g.pay_failed && g.pays.iter().all(|p| p["ok"] == true));
        assert!(g.events.iter().any(|e| e["ev"] == "budget spent"), "{:?}", g.events);
    }

    /// FAILS before: a top-up after the wallet said the budget was spent was ignored (`spent` was never cleared), and
    /// the rental ended "budget used up" anyway. Now the raised budget asks the wallet again: the next slice is asked
    /// for once and paid once; a task budget refused again asks nothing more until the next top-up.
    #[test]
    fn a_top_up_after_the_wallet_said_the_budget_was_spent_asks_again_once() {
        let (key, hk) = (crate::noise::fresh_key(), crate::noise::fresh_key());
        let (tx, _peer) = a_link(key, hk);
        let st = state();
        let (qtx, qrx) = mpsc::channel::<(u64, Value, bool)>();
        let mut g = lock(&st);
        g.terms.price_msat = 51_000;
        g.queue = Some(qtx);
        g.budget_msat = Some(20_202_000);
        g.released = 386;
        g.pays = vec![json!({"slice": 386, "ok": true}); 386];
        g.spent = Some(order::BUDGET_USED_UP);
        g.meter.work = 386 * g.terms.slice_work;
        g.settle_up(&tx);
        assert!(qrx.try_recv().is_err(), "spent: nothing asked");
        // the hashtaker adds 1,000 sats
        g.top_up(Some(21_202_000), &tx);
        assert!(g.spent.is_none());
        let (slice, _, _) = qrx.try_recv().expect("slice 387 asked for again");
        assert_eq!(slice, 387);
        assert!(qrx.try_recv().is_err(), "once");
        // paid: the rental goes on, not ended as spent
        g.in_flight = 0;
        g.pays.push(json!({"slice": 387, "ok": true}));
        assert!(!g.end_if_spent(&tx) && g.closed.is_none());
        // the task's budget in the rules refuses the next: said again, nothing more asked, not even on a later share
        g.spent = Some(order::TASK_BUDGET_USED_UP);
        g.meter.work = 387 * g.terms.slice_work;
        g.settle_up(&tx);
        assert!(qrx.try_recv().is_err(), "no loop on a task budget");
        // a lower or equal budget asks nothing
        g.top_up(Some(21_202_000), &tx);
        assert!(qrx.try_recv().is_err() && g.spent.is_some());
    }

    /// FAILS before: a slice that really failed (the signer's error: money may have moved) on the budget's last
    /// coverable slice was counted as paid by `released`, and the rental closed as "budget used up", the renter's own
    /// choice. Now it keeps the failure's path: the rental is not ended as spent, and payFailed stays true.
    #[test]
    fn a_real_failure_on_the_budgets_last_slice_is_a_failure_not_a_budget_spent() {
        let (key, hk) = (crate::noise::fresh_key(), crate::noise::fresh_key());
        let (tx, _peer) = a_link(key, hk);
        let st = state();
        let (qtx, _qrx) = mpsc::channel::<(u64, Value, bool)>();
        let mut g = lock(&st);
        g.terms.price_msat = 5_000;
        g.queue = Some(qtx);
        // the budget pays 4 slices; the 4th was released and failed
        g.budget_msat = Some(20_000);
        g.released = 4;
        g.pays = vec![json!({"slice": 1, "ok": true}), json!({"slice": 2, "ok": true}), json!({"slice": 3, "ok": true}),
                      json!({"slice": 4, "ok": false, "why": "signer error"})];
        g.pay_failed = true;
        g.meter.work = 4 * g.terms.slice_work;
        assert!(!g.end_if_spent(&tx), "a failure is not a budget spent");
        assert!(g.closed.is_none() && g.pay_failed);
        assert!(g.report()["payFailed"] == true);
        // and without the flag, the by-price test counts the confirmed slices only: 3 paid, the 4th still in the budget
        g.pay_failed = false;
        assert_eq!(g.budget_spent(), None);
        // an answer lost (ok null) is not counted as paid either
        g.pays[3] = json!({"slice": 4, "ok": null, "unknown": true});
        assert_eq!(g.budget_spent(), None);
    }

    /// A link made and left: the sender `come_back` is given.
    fn a_link(key: SecretKey, hk: SecretKey) -> (Sender, std::thread::JoinHandle<link::Link>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let peer = std::thread::spawn(move || link::answer(l.accept().unwrap().0, hk).unwrap());
        let hpub = PublicKey::from_secret_key(secp256k1::SECP256K1, &hk);
        (link::dial(&addr, key, hpub).unwrap().tx, peer)
    }

    /// Something that answers the dial and drips bytes, each within a read's timeout: the whole of a dial
    /// and of the wait for a welcome is held to the time to come back, not each read of it.
    #[test]
    fn a_road_that_drips_bytes_does_not_hold_a_return_past_its_time() {
        use std::io::Write as _;
        let (key, hk) = (crate::noise::fresh_key(), crate::noise::fresh_key());
        let (tx, _peer) = a_link(key, hk);
        let st = state();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            for _ in 0..1000 {
                if s.write_all(&[0u8]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(400));
            }
        });
        // four fifths of this is a deadline of 1 s
        let cfg = Redial { hashmaker: addr, key, hashmaker_key: PublicKey::from_secret_key(secp256k1::SECP256K1, &hk), rental: "r".into(), terms: Terms { grace_ms: 1_250, ..terms() } };
        let t0 = Instant::now();
        assert!(come_back(&cfg, &tx, &st, "test").is_none());
        assert!(t0.elapsed() < Duration::from_secs(3), "{} ms against a deadline of 1 s", t0.elapsed().as_millis());
    }

    /// A share waits for payment and the payment on its way is late, past what the quick buys before it said: with no
    /// second due to remind it, the ticker says `paying` before the hashmaker's 2 s clock runs out.
    #[test]
    fn the_ticker_says_paying_for_a_payment_late_past_the_measured_buys() {
        let (key, hk) = (crate::noise::fresh_key(), crate::noise::fresh_key());
        let (tx, peer) = a_link(key, hk);
        let st = state();
        {
            let mut g = lock(&st);
            // slice 1 on its way for 1.3 s, the buys before it quick, the share waiting 1.2 s
            g.released = 1;
            g.in_flight = 1;
            g.guard.in_flight_since = Some(Instant::now() - Duration::from_millis(1300));
            g.buys = VecDeque::from([0.2, 0.2]);
            g.guard.due_open_since = Some(Instant::now() - Duration::from_millis(1200));
            g.tick(&tx);
        }
        let mut lk = peer.join().unwrap();
        let mut said = false;
        while let Ok(Some(m)) = lk.rx.recv_within(Duration::from_millis(500)) {
            said |= matches!(m, Msg::Paying);
        }
        assert!(said, "paying said by the ticker");
        assert!(lock(&st).guard.paying_said);
    }

    /// A payment that landed restarts the hashmaker's clock for a share still short: the next one, queued as it
    /// landed, is timed from then, not from the first due (review 22d, finding 2), so no wait is said for it early.
    #[test]
    fn a_wait_is_timed_from_the_payment_on_its_way_not_the_first_due() {
        let (key, hk) = (crate::noise::fresh_key(), crate::noise::fresh_key());
        let (tx, peer) = a_link(key, hk);
        let st = state();
        {
            let mut g = lock(&st);
            // the share has waited 1.2 s since its due; a payment landed 0.2 s ago and the next was queued then
            g.released = 1;
            g.in_flight = 1;
            g.guard.in_flight_since = Some(Instant::now() - Duration::from_millis(200));
            g.buys = VecDeque::from([0.2, 0.2]);
            g.guard.due_open_since = Some(Instant::now() - Duration::from_millis(1200));
            g.tick(&tx);
            assert!(!g.guard.paying_said, "not said 0.2 s into this payment");
        }
        drop(tx);
        let mut lk = peer.join().unwrap();
        while let Ok(Some(m)) = lk.rx.recv_within(Duration::from_millis(300)) {
            assert!(!matches!(m, Msg::Paying), "said early");
        }
    }

    /// A wallet at about 0.9 s a payment, on its way 0.6 s of it: the measured buys say it lands by 1.2 s into the wait,
    /// so no wait is said, and none of the hour's few is used.
    #[test]
    fn a_payment_the_measured_buys_say_lands_in_time_says_no_paying() {
        let (key, hk) = (crate::noise::fresh_key(), crate::noise::fresh_key());
        let (tx, _peer) = a_link(key, hk);
        let st = state();
        let mut g = lock(&st);
        g.released = 1;
        g.in_flight = 1;
        g.guard.in_flight_since = Some(Instant::now() - Duration::from_millis(600));
        g.buys = VecDeque::from([0.9, 0.9, 0.9]);
        g.guard.due_open_since = Some(Instant::now() - Duration::from_millis(600));
        g.tick(&tx);
        assert!(!g.guard.paying_said, "lands in 0.3 s more: no wait said");
        // the same payment past its measured time: late, said
        g.guard.in_flight_since = Some(Instant::now() - Duration::from_millis(1000));
        g.guard.due_open_since = Some(Instant::now() - Duration::from_millis(1000));
        g.tick(&tx);
        assert!(g.guard.paying_said, "past its measured time: said");
    }

    /// The hashmaker's clock for a held share starts at the credit of the payment before, a little before this side
    /// hears the wallet's answer; with the link's latency and the ticker's half second on top, `paying` for a payment
    /// late past its measured buys (0.2 s, on its way 0.6 s) is said half a second into this side's wait, in good time
    /// before the hashmaker's two.
    #[test]
    fn paying_is_said_half_a_second_into_a_wait() {
        let (key, hk) = (crate::noise::fresh_key(), crate::noise::fresh_key());
        let (tx, peer) = a_link(key, hk);
        let st = state();
        {
            let mut g = lock(&st);
            g.released = 1;
            g.in_flight = 1;
            g.guard.in_flight_since = Some(Instant::now() - Duration::from_millis(600));
            g.buys = VecDeque::from([0.2, 0.2]);
            g.guard.due_open_since = Some(Instant::now() - Duration::from_millis(600));
            g.tick(&tx);
            assert!(g.guard.paying_said, "said 0.6 s into the wait");
        }
        let mut lk = peer.join().unwrap();
        let mut said = false;
        while let Ok(Some(m)) = lk.rx.recv_within(Duration::from_millis(300)) {
            said |= matches!(m, Msg::Paying);
        }
        assert!(said);
    }

    /// A gateway's API that answers each job id with what it was given: enough for [`blind::Check`].
    fn api_standin(answers: Arc<Mutex<HashMap<String, Value>>>) -> String {
        use std::io::{Read as _, Write as _};
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for c in l.incoming() {
                let Ok(mut c) = c else { continue };
                let mut buf = [0u8; 2048];
                let n = c.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let id = req.split("id=").nth(1).and_then(|r| r.split('&').next()).unwrap_or("").to_string();
                let body = answers.lock().unwrap().get(&id).cloned();
                let (code, body) = match body {
                    Some(b) => ("200 OK", b.to_string()),
                    None => ("404 Not Found", json!({"error": "unknown job"}).to_string()),
                };
                let _ = write!(c, "HTTP/1.1 {code}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            }
        });
        addr
    }

    /// A masked job and the gateway's answer for it, its `clear_bits` for shares of `pot`.
    fn masked_job(id: &str, pot: u32) -> (Value, Value) {
        let prev = [7u8; 32];
        let answer = json!({"id": id, "pot": pot, "mode": "solo", "null_key": false, "version": 2684354560u64, "prevblock": hex::encode(prev),
                            "height": 127, "merkle_root": "11".repeat(32), "time_on_wire": 1793474997u64, "nbits": 545259519u64, "txcount": 1,
                            "flags": 0, "clear_bits": 32 + pot, "xor_key_hash": "22".repeat(32), "rhs": "00".repeat(32)});
        let h2 = blind::h2_of(&answer, &prev, (32 + pot) as u8).unwrap();
        let mut hidden = blind::tagged("Bitcoin prevblock header, hashed", &prev);
        hidden[..6].fill(0);
        let mut coinb1 = vec![0u8; 3];
        coinb1.extend_from_slice(&h2);
        coinb1.extend_from_slice(&[0u8; 4]);
        let notify = json!({"id": null, "method": "mining.notify",
                            "params": [id, hex::encode(hidden), hex::encode(coinb1), "", [], "a0000000", "1d00ffff", "6625406b", false]});
        (notify, answer)
    }

    /// A new difficulty whose share bits aren't those the channel's last job was checked at: its shares wait (refused)
    /// until a job checked at the new difficulty comes, as a gateway sends with it.
    #[test]
    fn a_new_difficulty_holds_shares_till_a_job_is_checked_at_it() {
        use std::io::Write as _;
        let (key, hk) = (crate::noise::fresh_key(), crate::noise::fresh_key());
        let (tx, _peer) = a_link(key, hk);
        let st = state();
        let answers: Arc<Mutex<HashMap<String, Value>>> = Arc::default();
        let check = Arc::new(blind::Check::new(api_standin(answers.clone())));
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let u = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (mut gw, _) = l.accept().unwrap();
        lock(&st).meter.note_up(7, &json!({"id": 1, "method": "mining.subscribe", "params": []}));
        {
            let (st, tx) = (st.clone(), tx.clone());
            std::thread::spawn(move || upstream(7, u, st, tx, Some(check)));
        }
        let wait = |what: &str, ok: &dyn Fn(&St) -> bool| {
            let t0 = Instant::now();
            while !ok(&lock(&st)) {
                assert!(t0.elapsed() < Duration::from_secs(5), "{what}: {:?}", lock(&st).events);
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        let (job_a, answer_a) = masked_job("A", 0);
        let (job_b, answer_b) = masked_job("B", 1);
        answers.lock().unwrap().insert("A".into(), answer_a);
        answers.lock().unwrap().insert("B".into(), answer_b);
        for v in [json!({"id": 1, "result": [[], "00000001", 8], "error": null}), json!({"id": null, "method": "mining.set_difficulty", "params": [1.0]}), job_a] {
            writeln!(gw, "{v}").unwrap();
        }
        wait("job A checked at pot 0", &|g| g.guard.checked_pot.get(&7) == Some(&0) && !g.guard.await_job.contains(&7));
        // difficulty 2: one bit more, and job A's clear_bits are for difficulty 1
        writeln!(gw, "{}", json!({"id": null, "method": "mining.set_difficulty", "params": [2.0]})).unwrap();
        wait("shares held", &|g| g.guard.await_job.contains(&7));
        // the same difficulty again changes nothing more; a job checked at it lets shares go
        writeln!(gw, "{}", job_b).unwrap();
        wait("job B checked at pot 1", &|g| g.guard.checked_pot.get(&7) == Some(&1) && !g.guard.await_job.contains(&7));
        assert!(lock(&st).closed.is_none(), "{:?}", lock(&st).events);
        // back to difficulty 2's bits: nothing held
        writeln!(gw, "{}", json!({"id": null, "method": "mining.set_difficulty", "params": [2.5]})).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert!(!lock(&st).guard.await_job.contains(&7), "same share bits: nothing to wait for");
    }

    /// The job tables stay across a drop and go at the next one, and a share sent again is counted once.
    #[test]
    fn a_share_sent_again_after_a_drop_is_checked_and_counted_once() {
        let (key, hk) = (crate::noise::fresh_key(), crate::noise::fresh_key());
        let (tx, _peer) = a_link(key, hk);
        let st = state();
        let d = 1.0 / (1u64 << 20) as f64;
        let notify = crate::standin::notify_line("a", 1, 1_700_000_000, false);
        let (e2, nonce) = crate::standin::find_share(&notify, "00000001", 8, d, 1).unwrap();
        let share = json!({"id": 5, "method": "mining.submit", "params": ["u", "a", e2, format!("{:08x}", 1_700_000_000u32), nonce]});
        {
            let mut g = lock(&st);
            g.meter.note_up(7, &json!({"id": 1, "method": "mining.subscribe", "params": []}));
            g.meter.down(7, &json!({"id": 1, "result": [[], "00000001", 8], "error": null})).unwrap();
            g.meter.down(7, &json!({"id": null, "method": "mining.set_difficulty", "params": [d]})).unwrap();
            g.meter.down(7, &notify).unwrap();
        }
        let cfg = Redial { hashmaker: "127.0.0.1:1".into(), key, hashmaker_key: PublicKey::from_secret_key(secp256k1::SECP256K1, &hk), rental: "r".into(), terms: Terms { grace_ms: 1, ..terms() } };
        assert!(come_back(&cfg, &tx, &st, "test").is_none());
        let mut g = lock(&st);
        let (c, h) = g.meter.resent_claim(7, &share).unwrap().expect("not counted before");
        assert_eq!(g.meter.commit_at(&c, h, Instant::now()).unwrap().work, crate::meter::share_work(d));
        assert!(g.meter.resent_claim(7, &share).unwrap().is_none(), "once");
        assert_eq!((g.meter.proven, g.meter.refused), (1, 0));
        drop(g);
        // a later drop lets that channel go
        assert!(come_back(&cfg, &tx, &st, "test").is_none());
        assert!(come_back(&cfg, &tx, &st, "test").is_none());
        let mut bad = share.clone();
        bad["id"] = json!(6);
        assert!(lock(&st).meter.resent_claim(7, &bad).is_err(), "its channel is gone");
        assert!(lock(&st).meter.channels().is_empty());
    }

    /// A slice due as a link comes back is paid on the new link.
    #[test]
    fn a_slice_due_on_return_is_paid_on_the_new_link() {
        let (key, hk) = (crate::noise::fresh_key(), crate::noise::fresh_key());
        let (tx, _peer) = a_link(key, hk);
        let st = state();
        {
            let mut g = lock(&st);
            g.key = key;
            g.lock_ahead(&tx);
            g.meter.work = terms().slice_work;
            g.released = 0;
        }
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let t = terms();
        let maker = std::thread::spawn(move || {
            let mut lk = link::answer(l.accept().unwrap().0, hk).unwrap();
            let Ok(Some(Msg::Resume { .. })) = lk.rx.recv() else { panic!("no resume") };
            lk.tx.send(&Msg::Welcome { rental: "r".into(), terms_hash: hex::encode(t.hash()), proof: Some(PROOF.into()) }).unwrap();
            let mut paid = None;
            while let Ok(Some(m)) = lk.rx.recv_within(Duration::from_secs(5)) {
                if let Msg::Pay { slice, .. } = m {
                    paid = Some(slice);
                    break;
                }
            }
            paid
        });
        let cfg = Redial { hashmaker: addr, key, hashmaker_key: PublicKey::from_secret_key(secp256k1::SECP256K1, &hk), rental: "r".into(), terms: terms() };
        assert!(come_back(&cfg, &tx, &st, "test").is_some());
        assert_eq!(maker.join().unwrap(), Some(1), "slice 1 is paid on the new link");
        assert!(lock(&st).released >= 1);
    }
}
