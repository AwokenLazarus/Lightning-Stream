//! What a buyer holds against priced exits, so that nobody can make it pay again and again for
//! nothing: [`Holds`] (exits not to open paid tunnels to for a while) and [`CheckGate`] (the
//! region checks it pays for, under one daily budget).
//!
//! Exit ids cost nothing to make, so both count by **operator** (the exit's Nostr key) as well as
//! by exit: an operator whose exits keep dying as they open, or ask more than they announced, or
//! fail their region checks, is held off as a whole.

use std::collections::HashMap;
use std::time::{Duration, Instant};

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
/// spend plus that most still fits, and counts what actually left for it.
pub const CHECK_SATS_PER_DAY: u64 = 2 * REGION_CHECK_TICKET_SATS;
/// How often one priced exit's region is checked (paid for) at most.
pub const CHECK_EVERY: Duration = DAY;
/// Region checks of one operator's exits that may fail in a day before its exits are checked no more.
pub const CHECK_FAILS_PER_OPERATOR: u32 = 2;

/// The paid region checks of priced exits, under one budget: [`CHECK_SATS_PER_DAY`] in all, one
/// check of an exit a day, none more for an operator whose checks failed [`CHECK_FAILS_PER_OPERATOR`]
/// times today, and the exits seen longest first (a crowd of new ones can't push them out).
#[derive(Debug, Default)]
pub struct CheckGate {
    spent: Option<(Instant, u64)>,
    last: HashMap<String, Instant>,
    fails: HashMap<String, (Instant, u32)>,
    first_seen: HashMap<String, Instant>,
}

impl CheckGate {
    /// When `id` was first seen (now, if it is new): checks go to the longest seen first.
    pub fn seen(&mut self, id: &str, now: Instant) -> Instant {
        *self.first_seen.entry(id.to_string()).or_insert(now)
    }

    /// Whether `id`, run by `operator`, may be checked now: the most a check may move out of the
    /// wallet ([`REGION_CHECK_TICKET_SATS`]) must still fit in the day's budget.
    pub fn may(&mut self, id: &str, operator: &str, now: Instant) -> bool {
        let spent = self.spent.get_or_insert((now, 0));
        if now.saturating_duration_since(spent.0) >= DAY {
            *spent = (now, 0);
        }
        if spent.1.saturating_add(REGION_CHECK_TICKET_SATS) > CHECK_SATS_PER_DAY {
            return false;
        }
        if self.last.get(id).is_some_and(|t| now.saturating_duration_since(*t) < CHECK_EVERY) {
            return false;
        }
        !self.fails.get_mut(operator).is_some_and(|f| *today(f, now) >= CHECK_FAILS_PER_OPERATOR)
    }

    /// `id` was checked, and `left` sats left the wallet for it (the tickets the wallet bought or
    /// released for the check, by its answer; the check's most where that is not known); `ok`: its
    /// region held.
    pub fn record(&mut self, id: &str, operator: &str, left: u64, ok: bool, now: Instant) {
        let spent = self.spent.get_or_insert((now, 0));
        spent.1 = spent.1.saturating_add(left);
        self.last.insert(id.to_string(), now);
        if !ok && !operator.is_empty() {
            *today(self.fails.entry(operator.to_string()).or_insert((now, 0)), now) += 1;
        }
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
        // a crowd of exits under fresh keys, each check buying a whole ticket of its shop: the day's
        // checks move no more than the budget out of the wallet, whatever their tickets cost
        for ticket in [REGION_CHECK_TICKET_SATS, 1_000, 546, 21] {
            let (mut g, now) = (CheckGate::default(), Instant::now());
            let (mut checked, mut left) = (0, 0);
            for i in 0..100 {
                let id = format!("sybil{i}");
                if g.may(&id, &format!("op{i}"), now) {
                    g.record(&id, &format!("op{i}"), ticket, true, now);
                    checked += 1;
                    left += ticket;
                }
            }
            assert!(left <= CHECK_SATS_PER_DAY, "ticket {ticket}: {left} sats left in a day");
            // every check that still fits its most is allowed: the budget is not spent on guesses
            assert_eq!(checked, 1 + (CHECK_SATS_PER_DAY - REGION_CHECK_TICKET_SATS) / ticket, "ticket {ticket}");
            assert!(!g.may("sybil-late", "op-late", now + Duration::from_secs(3600)), "ticket {ticket}: the rest of the day");
            assert!(g.may("sybil-late", "op-late", now + DAY), "ticket {ticket}: a new day");
        }
        let (mut g, now) = (CheckGate::default(), Instant::now());
        g.record("a", "op", 20, false, now);
        g.record("b", "op", 20, false, now);
        assert!(!g.may("c", "op", now), "an operator whose checks failed twice today gets no more");
        assert!(g.may("c", "op", now + DAY), "a new day");
        g.record("z", "other", 20, true, now);
        assert!(!g.may("z", "other", now + Duration::from_secs(3600)), "one check of an exit a day");
        // the longest seen first
        let mut g = CheckGate::default();
        let older = g.seen("old", now);
        assert!(g.seen("new", now + Duration::from_secs(10)) > older);
        assert_eq!(g.seen("old", now + Duration::from_secs(20)), older);
    }
}
