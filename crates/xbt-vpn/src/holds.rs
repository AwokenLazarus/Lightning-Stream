//! What a buyer holds against priced exits, so that nobody can make it pay again and again for
//! nothing: [`Holds`] (exits not to open paid tunnels to for a while) and [`CheckGate`] (the
//! region checks it pays for, under one daily budget).
//!
//! Exit ids cost nothing to make, so both count by **operator** (the exit's Nostr key) as well as
//! by exit: an operator whose exits keep dying as they open, or ask more than they announced, or
//! fail their region checks, is held off as a whole.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// A day, for the daily caps.
pub const DAY: Duration = Duration::from_secs(24 * 3600);
/// The first hold of an exit whose paid tunnel died young; each one after doubles, up to [`YOUNG_MAX`].
pub const YOUNG_FIRST: Duration = Duration::from_secs(30);
pub const YOUNG_MAX: Duration = Duration::from_secs(3600);
/// How long an exit whose terms are above what it announced is not used (bait and switch), unless
/// it announces a higher price first.
pub const MISPRICED_HOLD: Duration = DAY;
/// Exits of one operator that died young in a day before the operator is held off as a whole.
pub const OPERATOR_YOUNG: u32 = 3;
/// The most paid tunnels opened to one exit for one device in a day: each opening pays its head.
/// Only openings that succeeded count: a wallet that refused, or an exit that didn't answer, costs
/// nothing and uses none.
pub const OPENS_PER_DAY: u32 = 48;

#[derive(Debug, Clone)]
struct Hold {
    until: Instant,
    /// The last young hold, doubled by the next; zero once the exit served well.
    last: Duration,
    /// Held for asking more than it announced: the price it announced then (msat a GB).
    mispriced_at: Option<u64>,
    /// For an operator's hold: the exit that caused it.
    cause: Option<String>,
}

/// Exits (and operators) not to open paid tunnels to until a time, and how many openings each
/// exit had today.
#[derive(Debug, Default)]
pub struct Holds {
    exits: HashMap<String, Hold>,
    operators: HashMap<String, Hold>,
    /// An operator's exits that died young today: (since, how many).
    young_by_operator: HashMap<String, (Instant, u32)>,
    /// Paid tunnels opened today, by device and exit: (since, how many).
    opens: HashMap<String, (Instant, u32)>,
}

fn today(slot: &mut (Instant, u32), now: Instant) -> &mut u32 {
    if now.saturating_duration_since(slot.0) >= DAY {
        *slot = (now, 0);
    }
    &mut slot.1
}

impl Holds {
    /// Whether `id` (or its operator `operator`) is held off at `now`.
    pub fn held(&self, id: &str, operator: &str, now: Instant) -> bool {
        let on = |h: Option<&Hold>| h.is_some_and(|h| now < h.until);
        on(self.exits.get(id)) || (!operator.is_empty() && on(self.operators.get(operator)))
    }

    /// `id`'s paid tunnel died young: held off for twice its last such hold (the first 30 s, at
    /// most an hour). An operator with [`OPERATOR_YOUNG`] of them today is held off as a whole.
    /// Returns the hold.
    pub fn young(&mut self, id: &str, operator: &str, now: Instant) -> Duration {
        let h = self.exits.entry(id.to_string()).or_insert(Hold { until: now, last: Duration::ZERO, mispriced_at: None, cause: None });
        let d = if h.last.is_zero() { YOUNG_FIRST } else { (h.last * 2).min(YOUNG_MAX) };
        h.last = d;
        h.until = h.until.max(now + d);
        if !operator.is_empty() {
            let n = today(self.young_by_operator.entry(operator.to_string()).or_insert((now, 0)), now);
            *n += 1;
            if *n >= OPERATOR_YOUNG {
                let o = self.operators.entry(operator.to_string()).or_insert(Hold { until: now, last: Duration::ZERO, mispriced_at: None, cause: None });
                o.until = o.until.max(now + d);
            }
        }
        d
    }

    /// `id`'s paid tunnel served (lived past the young limit, or carried enough): its next young
    /// hold starts again from the first.
    pub fn served(&mut self, id: &str) {
        if let Some(h) = self.exits.get_mut(id) {
            h.last = Duration::ZERO;
        }
    }

    /// `id` asked more than the `announced` price: held off, with its operator, for
    /// [`MISPRICED_HOLD`], unless it announces a higher price first ([`Self::announced`]).
    pub fn mispriced(&mut self, id: &str, operator: &str, announced: u64, now: Instant) {
        let until = now + MISPRICED_HOLD;
        let h = self.exits.entry(id.to_string()).or_insert(Hold { until: now, last: Duration::ZERO, mispriced_at: None, cause: None });
        h.until = h.until.max(until);
        h.mispriced_at = Some(announced);
        if !operator.is_empty() {
            self.operators.insert(operator.to_string(), Hold { until, last: Duration::ZERO, mispriced_at: Some(announced), cause: Some(id.to_string()) });
        }
    }

    /// `id` announced `price` (msat a GB). An exit held for asking more than it announced, which
    /// now announces more than it did then, was an honest one raising its price: its hold (and
    /// its operator's, if it caused that) ends. Announcing the same or less does not end it.
    pub fn announced(&mut self, id: &str, operator: &str, price: u64) {
        let raised = |h: &Hold| h.mispriced_at.is_some_and(|p| price > p);
        if self.exits.get(id).is_some_and(raised) {
            self.exits.remove(id);
            if self.operators.get(operator).is_some_and(|o| o.cause.as_deref() == Some(id) && raised(o)) {
                self.operators.remove(operator);
            }
        }
    }

    /// Whether another paid tunnel may be opened for `key` (a device and an exit) today
    /// ([`OPENS_PER_DAY`]). Asking counts nothing: [`Self::opened`] counts one that opened.
    pub fn may_open(&mut self, key: &str, now: Instant) -> bool {
        self.opens.get_mut(key).is_none_or(|slot| *today(slot, now) < OPENS_PER_DAY)
    }

    /// A paid tunnel opened for `key`: its opening was paid, so it counts toward the day's cap.
    pub fn opened(&mut self, key: &str, now: Instant) {
        *today(self.opens.entry(key.to_string()).or_insert((now, 0)), now) += 1;
    }
}

/// The most one region check of a priced exit may move out of the wallet (sats): the check tunnel's
/// `max_sats`. It is charged far less (`REGION_CHECK_MAX_SATS`), but a buyer with no credit at the
/// exit's shop must buy one of its tickets first, and what the check leaves of it stays there as
/// credit. A shop whose ticket is bigger than this can't be checked.
pub const REGION_CHECK_TICKET_SATS: u64 = 2_000;
/// The most region checks may move out of the wallet in a day, across all exits (sats): two checks
/// that each bought a whole [`REGION_CHECK_TICKET_SATS`] ticket. A check starts only if the day's
/// spend plus that most still fits, and counts what actually left for it: with tickets of T sats,
/// 1 + ⌊2,000 / T⌋ checks a day.
pub const CHECK_SATS_PER_DAY: u64 = 2 * REGION_CHECK_TICKET_SATS;
/// How often one priced exit's region is checked (paid for) at most.
pub const CHECK_EVERY: Duration = DAY;
/// Region checks of one operator's exits that may fail in a day before its exits are checked no more.
pub const CHECK_FAILS_PER_OPERATOR: u32 = 2;

/// The paid region checks of priced exits, under one budget: [`CHECK_SATS_PER_DAY`] in all, one
/// check of an exit a day, none more for an operator whose checks failed [`CHECK_FAILS_PER_OPERATOR`]
/// times today, and the exits seen longest first (a crowd of new ones can't push them out).
///
/// Kept in wall-clock time and, with [`CheckGate::load`], in a file (written and synced at each
/// change), so the service starting again (as it does at every change of its settings) does not
/// start the day's budget again. A check is paid for in two steps: [`CheckGate::reserve`] counts its
/// most and is on disk before its tunnel opens; [`CheckGate::settle`] then counts what actually left.
/// A reservation found unsettled at load (the service stopped between the two) stays counted in full.
#[derive(Debug, Default)]
pub struct CheckGate {
    file: Option<PathBuf>,
    /// The day's start and what left the wallet for checks since (unix seconds, sats).
    spent: Option<(u64, u64)>,
    last: HashMap<String, u64>,
    fails: HashMap<String, (u64, u32)>,
    /// The check paid for and not yet settled: the exit, its operator, and the day it was counted in.
    reserved: Option<(String, String, u64)>,
    first_seen: HashMap<String, SystemTime>,
}

/// Unix seconds; a clock before 1970 is 0.
fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// What [`CheckGate`] keeps in its file. Any other shape (or a file that can't be read) is a bad
/// file: the day's budget counts as spent.
#[derive(Serialize, Deserialize)]
struct GateFile {
    /// The day's start and what has left the wallet for checks since (unix seconds, sats).
    spent: (u64, u64),
    /// Each exit's last check (unix seconds).
    #[serde(default)]
    last: HashMap<String, u64>,
    /// Each operator's failed checks: the day's start and how many (unix seconds, count).
    #[serde(default)]
    fails: HashMap<String, (u64, u32)>,
    /// The check paid for and not yet settled: the exit, its operator, and the day it was counted in.
    #[serde(default)]
    reserved: Option<(String, String, u64)>,
}

/// `slot`'s count, started again if its day is over (wall-clock seconds; a clock set back counts as
/// no time passed).
fn today_at(slot: &mut (u64, u32), now: u64) -> &mut u32 {
    if now.saturating_sub(slot.0) >= DAY.as_secs() {
        *slot = (now, 0);
    }
    &mut slot.1
}

impl CheckGate {
    /// The gate kept in `file` (made if missing): what it holds is read back. A check reserved and
    /// never settled (the service stopped during it) is counted in full, and that exit not checked
    /// again that day.
    /// The gate kept in `file` (made if missing): what it holds is read back. A check reserved and
    /// never settled (the service stopped during it) is counted in full, and that exit not checked
    /// again that day. A file that is there but can't be read, or isn't a gate's (any other shape,
    /// empty included), does not start the budget again: the day's budget counts as spent from now
    /// (no paid check until a day has passed), and the bad file is kept beside it (`.bad`) for a look.
    pub fn load(file: &Path) -> CheckGate {
        let mut g = CheckGate { file: Some(file.to_path_buf()), ..CheckGate::default() };
        let kept: GateFile = match std::fs::read(file).map(|b| serde_json::from_slice::<GateFile>(&b)) {
            Ok(Ok(kept)) => kept,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return g,
            Err(e) => return g.spend_the_day(&e.to_string()),
            Ok(Err(e)) => return g.spend_the_day(&e.to_string()),
        };
        g.spent = Some(kept.spent);
        g.last = kept.last;
        g.fails = kept.fails;
        if let Some((id, _, day)) = kept.reserved {
            // its most stays in the day's spend; the exit counts as checked when it was (kept), or
            // from the day's start
            g.last.entry(id).or_insert(day);
            let _ = g.save();
        }
        g
    }

    /// The gate's file could not be read (`why`): the day's budget counts as spent from now.
    fn spend_the_day(mut self, why: &str) -> CheckGate {
        if let Some(file) = &self.file {
            eprintln!("region checks: {} could not be read ({why}): no paid region check for a day", file.display());
            let _ = std::fs::copy(file, file.with_extension("bad"));
        }
        self.spent = Some((unix(SystemTime::now()), CHECK_SATS_PER_DAY));
        let _ = self.save();
        self
    }

    /// Writes the gate to its file: whole (a file of its own, synced, then renamed over it), and
    /// readable by this user only.
    fn save(&self) -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        use std::sync::atomic::{AtomicU64, Ordering};
        static WRITES: AtomicU64 = AtomicU64::new(0);
        let Some(file) = &self.file else { return Ok(()) };
        let kept = GateFile {
            spent: self.spent.unwrap_or((unix(SystemTime::now()), 0)),
            last: self.last.clone(),
            fails: self.fails.clone(),
            reserved: self.reserved.clone(),
        };
        let body = serde_json::to_vec(&kept).map_err(std::io::Error::other)?;
        // a name no other write shares
        let tmp = file.with_extension(format!("{}-{}.tmp", std::process::id(), WRITES.fetch_add(1, Ordering::Relaxed)));
        let written = (|| {
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
            f.write_all(&body)?;
            f.sync_all()?;
            std::fs::rename(&tmp, file)
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        written?;
        if let Some(dir) = file.parent() {
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    }

    /// When `id` was first seen (now, if it is new): checks go to the longest seen first.
    pub fn seen(&mut self, id: &str, now: SystemTime) -> SystemTime {
        *self.first_seen.entry(id.to_string()).or_insert(now)
    }

    /// What has left the wallet for region checks today, a check under way counted at its most (sats).
    pub fn spent_today(&self) -> u64 {
        self.spent.map_or(0, |s| s.1)
    }

    /// Whether `id`, run by `operator`, may be checked now: the most a check may move out of the
    /// wallet ([`REGION_CHECK_TICKET_SATS`]) must still fit in the day's budget.
    pub fn may(&mut self, id: &str, operator: &str, now: SystemTime) -> bool {
        let now = unix(now);
        let spent = self.spent.get_or_insert((now, 0));
        if now.saturating_sub(spent.0) >= DAY.as_secs() && self.reserved.is_none() {
            *spent = (now, 0);
        }
        if self.reserved.is_some() || spent.1.saturating_add(REGION_CHECK_TICKET_SATS) > CHECK_SATS_PER_DAY {
            return false;
        }
        if self.last.get(id).is_some_and(|t| now.saturating_sub(*t) < CHECK_EVERY.as_secs()) {
            return false;
        }
        !self.fails.get_mut(operator).is_some_and(|f| *today_at(f, now) >= CHECK_FAILS_PER_OPERATOR)
    }

    /// `id` is about to be checked: its most ([`REGION_CHECK_TICKET_SATS`]) is counted now, and on
    /// disk before this returns. `Err`: it could not be kept, and the check must not be paid for.
    pub fn reserve(&mut self, id: &str, operator: &str, now: SystemTime) -> std::io::Result<()> {
        let now = unix(now);
        let spent = self.spent.get_or_insert((now, 0));
        spent.1 = spent.1.saturating_add(REGION_CHECK_TICKET_SATS);
        self.reserved = Some((id.to_string(), operator.to_string(), spent.0));
        self.last.insert(id.to_string(), now);
        if let Err(e) = self.save() {
            // not kept: as if never reserved
            self.reserved = None;
            if let Some(s) = &mut self.spent {
                s.1 = s.1.saturating_sub(REGION_CHECK_TICKET_SATS);
            }
            self.last.remove(id);
            return Err(e);
        }
        Ok(())
    }

    /// The check reserved last is done, and `left` sats left the wallet for it (the tickets the
    /// wallet bought or released for the check, by its answer; its most where that is not known);
    /// `ok`: its region held.
    pub fn settle(&mut self, left: u64, ok: bool, now: SystemTime) {
        let now = unix(now);
        let Some((_, operator, day)) = self.reserved.take() else { return };
        if let Some(s) = self.spent.as_mut().filter(|s| s.0 == day) {
            s.1 = s.1.saturating_sub(REGION_CHECK_TICKET_SATS).saturating_add(left);
        }
        if !ok && !operator.is_empty() {
            *today_at(self.fails.entry(operator).or_insert((now, 0)), now) += 1;
        }
        let _ = self.save();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_exit_that_keeps_dying_young_is_held_longer_and_one_that_served_starts_again() {
        let (mut h, now) = (Holds::default(), Instant::now());
        assert_eq!(h.young("a", "", now), YOUNG_FIRST);
        assert_eq!(h.young("a", "", now), YOUNG_FIRST * 2);
        assert!(h.held("a", "", now + YOUNG_FIRST));
        // it served: the next young hold is the first again
        h.served("a");
        assert_eq!(h.young("a", "", now + Duration::from_secs(600)), YOUNG_FIRST);
    }

    #[test]
    fn new_exit_ids_dont_dodge_a_hold_their_operator_earned() {
        let (mut h, now) = (Holds::default(), Instant::now());
        for i in 0..OPERATOR_YOUNG {
            h.young(&format!("exit{i}"), "op", now);
        }
        assert!(h.held("fresh-exit", "op", now), "a new exit of the same operator is held too");
        assert!(!h.held("fresh-exit", "other", now));
        // bait and switch: the operator is held with the exit
        h.mispriced("b1", "op2", 1000, now);
        assert!(h.held("b2", "op2", now + Duration::from_secs(3600)));
    }

    #[test]
    fn an_exit_that_raises_its_price_is_used_again_and_one_that_lowers_it_is_not() {
        let (mut h, now) = (Holds::default(), Instant::now());
        h.mispriced("x", "op", 1000, now);
        h.announced("x", "op", 1000);
        assert!(h.held("x", "op", now), "the same price: still held");
        h.announced("x", "op", 500);
        assert!(h.held("x", "op", now), "a lower price is the bait again: still held");
        h.announced("x", "op", 5000);
        assert!(!h.held("x", "op", now), "an honest exit raised its price: used again");
    }

    #[test]
    fn an_exit_is_opened_at_most_so_often_a_day() {
        let (mut h, now) = (Holds::default(), Instant::now());
        for _ in 0..OPENS_PER_DAY {
            assert!(h.may_open("phone#x", now));
            h.opened("phone#x", now);
        }
        assert!(!h.may_open("phone#x", now));
        assert!(h.may_open("laptop#x", now), "another device's openings are its own");
        assert!(h.may_open("phone#x", now + DAY), "a new day");
    }

    /// Openings that failed (the wallet refused, restarting, out of budget; the exit didn't answer)
    /// paid nothing, so they don't use up the day: a while of wallet trouble doesn't lock an
    /// honest exit out until tomorrow.
    #[test]
    fn openings_that_failed_dont_use_up_the_day() {
        let (mut h, now) = (Holds::default(), Instant::now());
        for i in 0..(OPENS_PER_DAY * 4) {
            assert!(h.may_open("phone#x", now + Duration::from_secs(u64::from(i) * 15)), "attempt {i}");
        }
    }

    #[test]
    fn region_checks_share_one_daily_budget_and_failing_operators_get_no_more() {
        let check = |g: &mut CheckGate, id: &str, op: &str, left: u64, ok: bool, now: SystemTime| {
            g.reserve(id, op, now).unwrap();
            g.settle(left, ok, now);
        };
        // a crowd of exits under fresh keys, each check buying a whole ticket of its shop: the day's
        // checks move no more than the budget out of the wallet, whatever their tickets cost
        for ticket in [REGION_CHECK_TICKET_SATS, 1_000, 546, 21] {
            let (mut g, now) = (CheckGate::default(), SystemTime::now());
            let (mut checked, mut left) = (0, 0);
            for i in 0..100 {
                let id = format!("sybil{i}");
                if g.may(&id, &format!("op{i}"), now) {
                    check(&mut g, &id, &format!("op{i}"), ticket, true, now);
                    checked += 1;
                    left += ticket;
                }
            }
            assert!(left <= CHECK_SATS_PER_DAY, "ticket {ticket}: {left} sats left in a day");
            assert_eq!(g.spent_today(), left, "ticket {ticket}: what left is what is counted");
            // every check that still fits its most is allowed: 1 + (budget - most) / ticket
            assert_eq!(checked, 1 + (CHECK_SATS_PER_DAY - REGION_CHECK_TICKET_SATS) / ticket, "ticket {ticket}");
            assert!(!g.may("sybil-late", "op-late", now + Duration::from_secs(3600)), "ticket {ticket}: the rest of the day");
            assert!(g.may("sybil-late", "op-late", now + DAY), "ticket {ticket}: a new day");
        }
        let (mut g, now) = (CheckGate::default(), SystemTime::now());
        check(&mut g, "a", "op", 20, false, now);
        check(&mut g, "b", "op", 20, false, now);
        assert!(!g.may("c", "op", now), "an operator whose checks failed twice today gets no more");
        assert!(g.may("c", "op", now + DAY), "a new day");
        check(&mut g, "z", "other", 20, true, now);
        assert!(!g.may("z", "other", now + Duration::from_secs(3600)), "one check of an exit a day");
        // the longest seen first
        let mut g = CheckGate::default();
        let older = g.seen("old", now);
        assert!(g.seen("new", now + Duration::from_secs(10)) > older);
        assert_eq!(g.seen("old", now + Duration::from_secs(20)), older);
    }

    fn gate_file(tag: &str) -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join(format!("{tag}.json"));
        (d, f)
    }

    /// The service starts again at every change of its settings: the day's region-check budget,
    /// each exit's last check and each operator's failures survive it, in wall-clock time.
    #[test]
    fn starting_again_mid_day_does_not_start_the_region_check_budget_again() {
        let (_d, f) = gate_file("gate");
        let now = SystemTime::now();
        let mut g = CheckGate::load(&f);
        for id in ["a", "b"] {
            assert!(g.may(id, "op", now));
            g.reserve(id, "op", now).unwrap();
            g.settle(100, false, now);
        }
        let later = now + Duration::from_secs(3600);
        let g2 = CheckGate::load(&f);
        let mut g = g2;
        assert_eq!(g.spent_today(), 200, "the day's spend survived");
        assert!(!g.may("c", "op", later), "op's two failures today survived");
        assert!(!g.may("a", "other-op", later), "a's check today survived");
        assert!(g.may("c", "fresh-op", later));
        g.reserve("c", "fresh-op", later).unwrap();
        g.settle(1_900, true, later);
        // ten restarts later
        for _ in 0..10 {
            g = CheckGate::load(&f);
        }
        assert_eq!(g.spent_today(), 2_100);
        assert!(!g.may("d", "fresh-op2", later), "2,100 + 2,000 is past the 4,000 a day, restarts or not");
        assert!(g.may("d", "fresh-op2", now + DAY), "a new day: the budget again");
    }

    /// The service stopped after a check's tunnel was paid for and before what left was counted:
    /// the check counts its most, in full.
    #[test]
    fn a_check_cut_off_between_paying_and_counting_counts_its_most() {
        let (_d, f) = gate_file("gate");
        let now = SystemTime::now();
        let mut g = CheckGate::load(&f);
        assert!(g.may("a", "op", now));
        g.reserve("a", "op", now).unwrap();
        // the service stops here: no settle
        drop(g);
        let mut g = CheckGate::load(&f);
        assert_eq!(g.spent_today(), REGION_CHECK_TICKET_SATS);
        assert!(!g.may("a", "op", now + Duration::from_secs(60)), "nor is that exit paid to check again today");
        assert!(g.may("b", "op2", now + Duration::from_secs(60)));
        g.reserve("b", "op2", now).unwrap();
        g.settle(700, true, now);
        assert_eq!(CheckGate::load(&f).spent_today(), REGION_CHECK_TICKET_SATS + 700, "settled, it counts what left");
    }

    /// A gate file that is there but can't be read (corrupt, or not a file) does not start the day's
    /// budget again: no paid check until a day has passed.
    #[test]
    fn a_gate_file_that_cannot_be_read_spends_the_day_not_resets_it() {
        let (_d, f) = gate_file("gate");
        let now = SystemTime::now();
        let mut g = CheckGate::load(&f);
        g.reserve("a", "op", now).unwrap();
        g.settle(1_000, true, now);
        std::fs::write(&f, b"{\"spent\": [1, 10").unwrap();
        let mut g = CheckGate::load(&f);
        assert_eq!(g.spent_today(), CHECK_SATS_PER_DAY, "a corrupt file counts the day as spent");
        assert!(!g.may("b", "op2", now + Duration::from_secs(60)));
        assert!(g.may("b", "op2", now + DAY + Duration::from_secs(60)), "a new day");
        assert!(f.with_extension("bad").exists(), "the bad file is kept for a look");
        // files of any other shape: read as bad, never a panic, never an empty gate
        for bad in [&b""[..], b"{}", b"{\"spent\":[]}", b"{\"spent\":[1]}", b"{\"spent\":null}", b"{\"spent\":\"x\"}",
                    b"{\"spent\":[1,2],\"fails\":{\"op\":[1]}}", b"[1,2]"] {
            let (_d, f) = gate_file("shape");
            std::fs::write(&f, bad).unwrap();
            let mut g = CheckGate::load(&f);
            let shown = String::from_utf8_lossy(bad);
            assert_eq!(g.spent_today(), CHECK_SATS_PER_DAY, "{shown}");
            assert!(!g.may("b", "op2", now + Duration::from_secs(60)), "{shown}");
        }
        // not a file at all
        let (d, _) = gate_file("gate");
        let dir = d.path().join("gate.json");
        std::fs::create_dir(&dir).unwrap();
        let mut g = CheckGate::load(&dir);
        assert!(!g.may("b", "op2", now + Duration::from_secs(60)));
        assert!(g.reserve("b", "op2", now).is_err(), "and it can't be paid for either");
    }

    /// A check cut off between paying and counting keeps the time its exit was checked: that exit is
    /// not paid to check again until a day after it, not a day after the budget's day began.
    #[test]
    fn a_check_cut_off_keeps_when_its_exit_was_checked() {
        let (_d, f) = gate_file("gate");
        let day_start = SystemTime::now();
        let mut g = CheckGate::load(&f);
        assert!(g.may("x", "op0", day_start));
        g.reserve("x", "op0", day_start).unwrap();
        g.settle(10, true, day_start);
        let later = day_start + Duration::from_secs(5 * 3600);
        assert!(g.may("a", "op", later));
        g.reserve("a", "op", later).unwrap();
        drop(g);
        let mut g = CheckGate::load(&f);
        // a new budget day, but less than a day since "a" was checked
        let next = day_start + DAY + Duration::from_secs(3600);
        assert!(!g.may("a", "op", next), "a was checked 20 h ago");
        assert!(g.may("a", "op", later + DAY), "a day after its check");
    }

    /// The gate's file is this user's alone, and every write is whole: no file of a write is left
    /// beside it.
    #[test]
    fn the_gate_file_is_private_and_written_whole() {
        use std::os::unix::fs::PermissionsExt;
        let (d, f) = gate_file("gate");
        let now = SystemTime::now();
        let mut g = CheckGate::load(&f);
        for id in ["a", "b"] {
            g.reserve(id, "op", now).unwrap();
            g.settle(100, true, now);
        }
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
        let names: Vec<_> = std::fs::read_dir(d.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, vec![f.file_name().unwrap().to_owned()], "only the gate itself");
    }

    /// A reservation that can't be written is not paid for: the gate says so, and counts nothing.
    #[test]
    fn a_check_that_cannot_be_kept_on_disk_is_refused() {
        let (d, _) = gate_file("gate");
        let mut g = CheckGate::load(&d.path().join("missing-dir").join("gate.json"));
        assert!(g.reserve("a", "op", SystemTime::now()).is_err());
        assert_eq!(g.spent_today(), 0);
        assert!(g.may("a", "op", SystemTime::now()));
    }
}
