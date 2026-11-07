//! Who pays when: a rental's steps. Everything about the order of paying and working is here, and the two sides
//! only ask these questions.
//!
//! * **A price and a start fee.** A rental's terms price a slice, and name a start fee in whole slices, which
//!   pay for moving the miners. Miners don't move until the fee and one slice have arrived.
//! * **No share past what's paid.** The hashmaker holds a share that doesn't fit in what's paid, asks for
//!   payment, and if none comes within its short clock the rental stops and the miners go home. So it never
//!   forwards unpaid work, and a renter that stops paying gets nothing more.
//! * **Steps are earned.** What's paid and unused never goes past the largest of 546 sat, one share, or what has
//!   been delivered, up to 30 s of the miner's output. Steps ignore reputation, so fake history pays nothing.
//!   So a hashmaker that takes a payment and vanishes keeps at most that.
//! * **A slow wallet buys ahead.** A payment that buys a ticket can take many seconds (11 to 15 s over several
//!   Lightning hops, issue #64). The renter times its buys, and starts the next one while what's paid still lasts
//!   that long and a margin ([`Standing::buy_lead_secs`], at most [`BUY_AHEAD_MOST_SECS`]), so the slice after it is
//!   paid from the credit it bought. That can pass the step by at most one slice and a ticket on top of the lead's
//!   worth of output ([`Standing::most_unworked_msat`]).

/// The smallest ticket a seller sells, and the first step: the dust limit that held tickets have too.
pub const FIRST_STEP_MSAT: u64 = 546_000;
/// How much of a miner's output a step can reach.
pub const STEP_SECONDS: f64 = 30.0;
/// How long a share that doesn't fit waits for payment before the rental stops.
pub const WAIT_FOR_PAYMENT: std::time::Duration = std::time::Duration::from_secs(2);
/// How long it waits instead when the renter has said a payment is on its way (`paying`): a Lightning payment over
/// several hops, a ticket bought on it, takes 11 to 15 s (issue #64), and this leaves room for twice that. Its miners
/// hash for the hashmaker's own pool meanwhile, and no share goes to the renter unpaid, so the wait costs it the move
/// and, with no pool of its own to go to, the miners' time: at most [`PAYING_WAITS_AN_HOUR`] of these an hour (3 min),
/// and [`RAMP_WAITS_MOST`] while the step ramps up. Until 0.2.13 it was 10 s, under one such payment.
pub const WAIT_FOR_PAYING: std::time::Duration = std::time::Duration::from_secs(30);
/// Such waits a rental may have in an hour.
pub const PAYING_WAITS_AN_HOUR: usize = 6;
/// While the renter's step ramps up to its cap ([`STEP_SECONDS`] of output), which is the miners' first that many
/// seconds of work for the rental, a wallet slower than the step lasts can't keep a large miner fed, and each early
/// ticket buy may be waited for. Those waits aren't counted against [`PAYING_WAITS_AN_HOUR`]; there may be this many.
/// Each is still held to [`WAIT_FOR_PAYING`].
pub const RAMP_WAITS_MOST: usize = 12;
/// Ticket buys measured faster than this land inside the hashmaker's short clock ([`WAIT_FOR_PAYMENT`]): none is
/// started ahead of need for them.
pub const BUY_AHEAD_FROM_SECS: f64 = 1.0;
/// The least margin a ticket buy is started with, past its measured time ([`Standing::buy_lead_secs`]).
pub const BUY_MARGIN_SECS: f64 = 3.0;
/// The most output, in seconds, a ticket buy is started ahead of: the step's own cap ([`STEP_SECONDS`]). A buy slower
/// than this less the margin is late, said with `paying`, and waited for ([`WAIT_FOR_PAYING`]).
pub const BUY_AHEAD_MOST_SECS: f64 = STEP_SECONDS;
/// A share may be worth this many slices at most. Past it a renter would pay many slices ahead of one share.
pub const LARGEST_SHARE_SLICES: u128 = 4;

/// The work what's been paid covers, the start fee taken out.
pub fn paid_work(paid: u64, start_slices: u64, slice_work: u128) -> u128 {
    paid.saturating_sub(start_slices) as u128 * slice_work
}

/// The hashmaker's rule: has the rental paid enough for its miners to be handed over?
pub fn ready_to_serve(paid: u64, start_slices: u64) -> bool {
    paid > start_slices
}

/// The hashmaker's rule: can this share be forwarded? If not, it waits for payment.
pub fn fits(proven: u128, share: u128, paid: u64, start_slices: u64, slice_work: u128) -> bool {
    proven + share <= paid_work(paid, start_slices, slice_work)
}

/// Is a difficulty asking for a share worth too many slices?
pub fn share_too_big(share: u128, slice_work: u128) -> bool {
    share > LARGEST_SHARE_SLICES * slice_work
}

/// The most that may be paid and unused now: the largest of the first step, one share or what's been delivered,
/// up to [`STEP_SECONDS`] of the output. `msat_a_second` is the output as this side has measured it, at the
/// rental's price: none yet gives the floor.
pub fn step_msat(delivered_msat: u64, share_msat: u64, msat_a_second: f64) -> u64 {
    let floor = FIRST_STEP_MSAT.max(share_msat);
    let cap = floor.max((msat_a_second.max(0.0) * STEP_SECONDS) as u64);
    delivered_msat.max(floor).min(cap)
}

/// What a rental stands at, as the renter sees it.
#[derive(Clone, Copy, Debug)]
pub struct Standing {
    pub proven: u128,
    /// The largest share a channel could send now; 0 till a gateway has said.
    pub largest_share: u128,
    pub paid: u64,
    pub start_slices: u64,
    pub slice_work: u128,
    pub price_msat: u64,
    pub msat_a_second: f64,
    /// How long buying a ticket takes, as measured (p95 of the last few); 0 till one is measured.
    pub buy_secs: f64,
}

/// p95 of measured ticket buys, in seconds: the renter's estimate of how long the next one takes. 0 for none.
pub fn buy_estimate(buys: impl IntoIterator<Item = f64>) -> f64 {
    let mut b: Vec<f64> = buys.into_iter().filter(|s| s.is_finite() && *s >= 0.0).collect();
    b.sort_by(f64::total_cmp);
    b.get(((b.len() as f64 * 0.95).ceil() as usize).saturating_sub(1)).copied().unwrap_or(0.0)
}

impl Standing {
    fn msat_of(&self, work: u128) -> u64 {
        (work.saturating_mul(self.price_msat as u128) / self.slice_work).min(u64::MAX as u128) as u64
    }

    /// The most that may be paid and unused now.
    pub fn step_msat(&self) -> u64 {
        let share = self.largest_share.min(LARGEST_SHARE_SLICES * self.slice_work);
        step_msat(self.msat_of(self.proven), self.msat_of(share), self.msat_a_second)
    }

    /// The renter's rule: pay another slice now? Always for the first (with its start fee), and always when the next
    /// share wouldn't fit. Past that, as far ahead as the step allows: a payment that buys a new ticket takes seconds
    /// (measured 4 s on the regtest's first), longer than the hashmaker waits for a share that doesn't fit, so the
    /// renter keeps what the step allows paid ahead and buys the next ticket while that lasts.
    pub fn pay_next(&self) -> bool {
        if !ready_to_serve(self.paid, self.start_slices) {
            return true;
        }
        let share = self.largest_share.min(LARGEST_SHARE_SLICES * self.slice_work);
        let covered = paid_work(self.paid, self.start_slices, self.slice_work);
        if self.proven + share > covered {
            return true;
        }
        let after = covered + self.slice_work;
        if self.msat_of(after.saturating_sub(self.proven)) > self.step_msat() {
            return false;
        }
        // keep the whole step paid ahead: the next ticket is bought while that lasts, which starts it well before what's
        // paid runs short of two buys' time, and a link that stalls for a few seconds finds the work still paid for. A
        // trigger at two buys' time alone was measured to end a rental on a 3 s one-way stall (regtest, 7569c9ba)
        true
    }

    /// A payment that has to be made now: the start fee and the first slice, or one the next share needs.
    pub fn needed(&self) -> bool {
        let share = self.largest_share.min(LARGEST_SHARE_SLICES * self.slice_work);
        !ready_to_serve(self.paid, self.start_slices) || self.proven + share > paid_work(self.paid, self.start_slices, self.slice_work)
    }

    /// [`Standing::pay_next`], with `credit_msat` the renter's credit at the seller. Paid from credit, a slice changes
    /// nothing gone and unworked. One that has to buy a ticket adds the ticket: only paid ahead of need when the
    /// smallest ticket keeps all that within [`Standing::most_unworked_msat`].
    pub fn pay_next_with(&self, credit_msat: u64) -> bool {
        if self.buy_ahead(credit_msat) {
            return true;
        }
        if !self.pay_next() {
            return false;
        }
        let covered = paid_work(self.paid, self.start_slices, self.slice_work);
        if self.needed() || credit_msat >= self.price_msat {
            return true;
        }
        let ahead = self.msat_of(covered.saturating_sub(self.proven));
        // a ticket bought ahead of need: within the most that may ever be gone and unworked, so it's bought while
        // what's paid still runs, not when the next share waits for it
        ahead + credit_msat + self.smallest_ticket_msat() <= self.most_unworked_msat()
    }

    /// How long before what's paid runs out the next ticket buy starts, in seconds of output: the measured buy
    /// ([`Standing::buy_secs`]) and a margin of half of it, at least [`BUY_MARGIN_SECS`], up to
    /// [`BUY_AHEAD_MOST_SECS`]. 0 (none started ahead) for buys under [`BUY_AHEAD_FROM_SECS`], or none measured.
    pub fn buy_lead_secs(&self) -> f64 {
        if !self.buy_secs.is_finite() || self.buy_secs < BUY_AHEAD_FROM_SECS {
            return 0.0;
        }
        (self.buy_secs + (self.buy_secs / 2.0).max(BUY_MARGIN_SECS)).min(BUY_AHEAD_MOST_SECS)
    }

    /// [`Standing::buy_lead_secs`] of output at the measured rate, in msat: 0 till a rate is measured.
    pub fn buy_lead_msat(&self) -> u64 {
        let lead = self.buy_lead_secs();
        if lead <= 0.0 || !self.msat_a_second.is_finite() || self.msat_a_second <= 0.0 {
            return 0;
        }
        (self.msat_a_second * lead) as u64
    }

    /// Start the next ticket buy now, ahead of the step? Only once the miners are served, when the credit at the seller
    /// doesn't cover the next slice (so its payment buys a ticket), and what's paid ahead lasts less than
    /// [`Standing::buy_lead_secs`] at the measured rate. A buy started then lands while what's paid still runs, and the
    /// slice after it is paid from the credit it bought (issue #64: buys of 11 to 15 s against a step that lasted 8.5 s).
    /// What it adds to what's gone and unworked stays within [`Standing::most_unworked_msat`].
    pub fn buy_ahead(&self, credit_msat: u64) -> bool {
        if !ready_to_serve(self.paid, self.start_slices) || credit_msat >= self.price_msat {
            return false;
        }
        let lead = self.buy_lead_msat();
        let ahead = self.msat_of(paid_work(self.paid, self.start_slices, self.slice_work).saturating_sub(self.proven));
        lead > 0 && ahead < lead && ahead + credit_msat + self.smallest_ticket_msat() <= self.most_unworked_msat()
    }

    /// The smallest ticket a payment can buy: the seller's smallest (546 sat), and never under the slice's price.
    pub fn smallest_ticket_msat(&self) -> u64 {
        FIRST_STEP_MSAT.max(self.price_msat)
    }

    /// The ticket to buy for slice `self.paid` (counted in `paid`), when the credit at the seller doesn't cover it:
    /// what keeps the money gone and not yet worked, slices paid ahead and credit left at the seller, within the step
    /// and the start fee still to pay, and never under the smallest ticket.
    pub fn ticket_msat_with(&self, credit_msat: u64) -> u64 {
        let ahead = self.msat_of(paid_work(self.paid, self.start_slices, self.slice_work).saturating_sub(self.proven));
        let fee_left = self.start_slices.saturating_sub(self.paid).saturating_mul(self.price_msat);
        let room = (self.step_msat() + fee_left + self.price_msat).saturating_sub(ahead + credit_msat);
        room.max(self.smallest_ticket_msat())
    }

    /// The most that is ever gone and not yet worked (slices paid ahead and credit at the seller), the start fee aside:
    /// the step; or, when a share must be paid for and a ticket bought for it, one share, one slice and the smallest
    /// ticket; or, when a ticket is bought ahead ([`Standing::buy_ahead`]), the lead's output, one slice and the smallest
    /// ticket; whichever is most. The lead is at most [`BUY_AHEAD_MOST_SECS`] of output, the step's own cap.
    pub fn most_unworked_msat(&self) -> u64 {
        let share = self.largest_share.min(LARGEST_SHARE_SLICES * self.slice_work);
        let room = self.price_msat.saturating_add(self.smallest_ticket_msat());
        self.step_msat().max(self.msat_of(share).saturating_add(room)).max(self.buy_lead_msat().saturating_add(room))
    }

    /// How long what's paid and not yet worked lasts at the measured output.
    pub fn secs_left(&self) -> f64 {
        let covered = paid_work(self.paid, self.start_slices, self.slice_work);
        if self.msat_a_second <= 0.0 {
            return f64::INFINITY;
        }
        self.msat_of(covered.saturating_sub(self.proven)) as f64 / self.msat_a_second
    }

    /// The route is too slow for this miner's rate: how far ahead a buy starts (the step, or the lead it buys ahead
    /// with), and the hashmaker's wait for a payment on its way, last less than a ticket takes to buy. Said in words,
    /// before a share waits past them.
    pub fn too_slow(&self) -> bool {
        self.msat_a_second > 0.0
            && self.buy_secs > 0.0
            && (self.step_msat() as f64 / self.msat_a_second).max(self.buy_lead_secs()) + WAIT_FOR_PAYING.as_secs_f64() < self.buy_secs
    }

}

/// Why a renter ends its rental when its own budget is spent: the rental's, or the one the owner's spending rules give
/// its task in the wallet (`ticket_task_budget`). Both are the renter's own choice, said to the hashmaker in `close`.
pub const BUDGET_USED_UP: &str = "budget used up";
pub const TASK_BUDGET_USED_UP: &str = "the task's budget in the wallet's rules is used up";

/// Was this ended rental a failed first step? Money went and little work came back, and the renter didn't end it
/// itself. A renter's app stops going back to a seller after [`FAILED_FIRST_STEPS`] of these in a row.
pub fn failed_first_step(report: &serde_json::Value) -> bool {
    let closed = report["closed"].as_str().unwrap_or("");
    let own_choice = ["cut by the hashtaker", "rental time over", BUDGET_USED_UP, TASK_BUDGET_USED_UP].contains(&closed);
    let paid = report["paidSlices"].as_u64().unwrap_or(0);
    let start = report["terms"]["startSlices"].as_u64().unwrap_or(0);
    let slice: u128 = report["terms"]["sliceWork"].as_str().and_then(|w| w.parse().ok()).unwrap_or(1);
    let proven: u128 = report["meter"]["work"].as_str().and_then(|w| w.parse().ok()).unwrap_or(0);
    !own_choice && paid > 0 && proven * 2 < paid_work(paid, start, slice).max(1)
}

/// How many failed first steps in a row a renter's app stands from one seller.
pub const FAILED_FIRST_STEPS: u32 = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_task_budget_spent_is_the_renters_own_end_not_a_failed_first_step() {
        assert!(!failed_first_step(&serde_json::json!({"closed": TASK_BUDGET_USED_UP, "paidSlices": 3, "meter": {"work": "0"}, "terms": {"sliceWork": "100"}})));
        assert!(!failed_first_step(&serde_json::json!({"closed": BUDGET_USED_UP, "paidSlices": 3, "meter": {"work": "0"}, "terms": {"sliceWork": "100"}})));
    }

    #[test]
    fn a_failed_first_step_is_money_gone_for_little_work_not_a_renters_own_stop() {
        let r = |closed: &str, paid: u64, work: u128| serde_json::json!({"closed": closed, "paidSlices": paid, "meter": {"work": work.to_string()}, "terms": {"sliceWork": "100", "startSlices": 2}});
        assert!(failed_first_step(&r("no proven work", 3, 0)));
        assert!(failed_first_step(&r("link lost: gone", 3, 49)));
        assert!(!failed_first_step(&r("link lost: gone", 3, 50)), "half of it came");
        assert!(!failed_first_step(&r("no proven work", 0, 0)), "no money went");
        assert!(!failed_first_step(&r("cut by the hashtaker", 3, 0)), "its own stop");
        // only the start fee paid, and nothing back: money went
        assert!(failed_first_step(&r("no proven work", 2, 0)));
    }

    fn at(proven: u128, largest_share: u128, paid: u64) -> Standing {
        Standing { proven, largest_share, paid, start_slices: 2, slice_work: 1000, price_msat: 400_000, msat_a_second: 0.0, buy_secs: 0.0 }
    }

    #[test]
    fn a_step_is_earned_from_the_floor_up_to_the_cap() {
        assert_eq!(step_msat(0, 0, 0.0), 546_000);
        assert_eq!(step_msat(0, 800_000, 0.0), 800_000, "one share");
        // delivered raises it, the output caps it
        assert_eq!(step_msat(2_000_000, 0, 100_000.0), 2_000_000);
        assert_eq!(step_msat(9_000_000, 0, 100_000.0), 3_000_000);
        // nothing measured yet: the floor, however much is claimed delivered
        assert_eq!(step_msat(9_000_000, 0, 0.0), 546_000);
    }

    #[test]
    fn nothing_moves_till_the_fee_and_a_slice_are_paid() {
        assert!(!ready_to_serve(2, 2));
        assert!(ready_to_serve(3, 2));
        for paid in 0..3 {
            assert!(at(0, 0, paid).pay_next(), "{paid}");
        }
        assert!(!at(0, 0, 3).pay_next(), "share unknown");
        assert_eq!(paid_work(3, 2, 1000), 1000);
        assert_eq!(paid_work(1, 2, 1000), 0);
    }

    #[test]
    fn a_share_fits_only_inside_what_is_paid() {
        assert!(fits(0, 1000, 3, 2, 1000));
        assert!(!fits(1, 1000, 3, 2, 1000));
        assert!(!fits(0, 1000, 2, 2, 1000));
    }

    #[test]
    fn the_renter_pays_when_the_next_share_would_not_fit_and_ahead_only_as_the_step_allows() {
        // 1 slice of credit, share = a slice, 400 sat: a second slice ahead would be 800 sat unused, over 546
        assert!(!at(0, 1000, 3).pay_next());
        // that slice delivered: the next share wouldn't fit
        assert!(at(1000, 1000, 3).pay_next());
        // delivered raises the step: with 2,000 delivered, and the output to match, one share ahead is allowed
        let mut s = at(5000, 1000, 8);
        assert!(!s.pay_next(), "not without measured output");
        s.msat_a_second = 100_000.0;
        assert!(s.pay_next());
    }

    /// Cheap slices: the renter keeps the whole first step paid ahead, so the next ticket is bought while it lasts,
    /// and no further.
    #[test]
    fn the_renter_keeps_the_step_paid_ahead_and_no_more() {
        let s = |paid| Standing { proven: 0, largest_share: 100, paid, start_slices: 0, slice_work: 1000, price_msat: 100_000, msat_a_second: 0.0, buy_secs: 0.0 };
        assert!(s(1).pay_next() && s(4).pay_next(), "up to 500 sat unused, under the 546 sat step");
        assert!(!s(5).pay_next(), "600 sat unused would pass the step");
    }

    #[test]
    fn however_large_a_gateway_says_a_share_is_nothing_more_is_due_than_the_limit() {
        // 4 slices at the most; 400 sat a slice
        let s = at(0, u128::MAX / 8, 7);
        assert_eq!(s.step_msat(), 1_600_000);
        assert!(!s.pay_next(), "5 slices covered, the share at its limit fits, and 6 unused is over the step");
        assert!(at(0, u128::MAX / 8, 5).pay_next(), "3 covered: the share at its limit doesn't fit");
    }

    #[test]
    fn the_first_ticket_holds_the_fee_and_the_first_step() {
        // the first payment (slice 1, a fee slice): it, the other fee slice and the first step
        assert_eq!(at(0, 0, 1).ticket_msat_with(0), 546_000 + 800_000);
        // a slice above the first step: the fee slice and the step, then the smallest ticket, a slice
        let s = Standing { price_msat: 1_000_000, start_slices: 1, ..at(0, 0, 1) };
        assert_eq!(s.ticket_msat_with(0), 1_546_000);
        assert_eq!(Standing { paid: 2, ..s }.ticket_msat_with(546_000), 1_000_000);
        // past the fee: the step, less what's paid ahead (a slice) and the credit, with this slice
        assert_eq!(at(0, 0, 3).ticket_msat_with(0), 546_000);
        assert_eq!(at(0, 0, 3).ticket_msat_with(100_000), 546_000, "never under the smallest ticket");
    }

    /// A rental on a timeline: a share every second, each payment that buys a ticket taking `buy` seconds to arrive
    /// (one in every `per_ticket` payments). A share that doesn't fit waits 2 s, or 10 s while a payment is on its way
    /// (`paying`). What the most paid ahead came to, whether a share waited past that, whether the route was said to be
    /// too slow, and how many 10 s waits there were.
    fn timeline(price_msat: u64, buy: f64, per_ticket: u64, seconds: u64) -> (u64, bool, bool, usize) {
        let slice = 1000u128;
        let share = 100u128;
        let mut s = Standing { proven: 0, largest_share: share, paid: 0, start_slices: 0, slice_work: slice, price_msat, msat_a_second: 0.0, buy_secs: 0.0 };
        let mut arrives: Vec<f64> = Vec::new();
        let (mut most_ahead, mut stalled, mut said_slow, mut waits) = (0u64, false, false, 0usize);
        for t in 0..seconds {
            let now = t as f64;
            while s.pay_next() {
                s.paid += 1;
                let slow = s.paid % per_ticket == 1;
                arrives.push(now + if slow { buy } else { 0.01 });
                if slow {
                    s.buy_secs = buy;
                }
            }
            said_slow |= s.too_slow();
            let issued = paid_work(s.paid, 0, slice);
            most_ahead = most_ahead.max(s.msat_of(issued - s.proven));
            assert!(s.msat_of(issued - s.proven) <= s.step_msat().max(s.msat_of(slice)), "never past the step: t {now}");
            let arrived = |at: f64| arrives.iter().filter(|a| **a <= at).count() as u64;
            if s.proven + share > paid_work(arrived(now), 0, slice) {
                let on_its_way = arrived(f64::INFINITY) > arrived(now);
                let wait = if on_its_way { WAIT_FOR_PAYING } else { WAIT_FOR_PAYMENT }.as_secs_f64();
                if s.proven + share > paid_work(arrived(now + wait), 0, slice) {
                    stalled = true;
                    break;
                }
                waits += usize::from(on_its_way && s.proven + share > paid_work(arrived(now + WAIT_FOR_PAYMENT.as_secs_f64()), 0, slice));
            }
            s.proven += share;
            s.msat_a_second = if t >= 2 { s.msat_of(s.proven) as f64 / (now + 1.0) } else { 0.0 };
        }
        (most_ahead, stalled, said_slow, waits)
    }

    /// Payments that take 8 s to buy a ticket. A small miner's step outlasts two buys, so nothing waits; a large one's
    /// first steps don't, and it waits on `paying` a few times, within the hour's limit, then its step outlasts them.
    #[test]
    fn slow_ticket_buys_keep_a_rental_running_small_or_large() {
        // 10 sat a slice of 10 shares, a share a second: the 546 sat step lasts 546 s
        let (most, stalled, slow, waits) = timeline(10_000, 8.0, 54, 3600);
        assert!(!stalled && !slow && waits == 0, "small: most ahead {most}, waits {waits}");
        assert!(most <= 546_000);
        // 1,000 sat a slice: 100 sat a second; the 546 sat step lasts 5.46 s at first, against a buy of 8 s
        let (most, stalled, slow, waits) = timeline(1_000_000, 8.0, 1, 3600);
        assert!(!stalled && !slow, "large: most ahead {most}, waits {waits}");
        assert!(waits <= PAYING_WAITS_AN_HOUR, "large: {waits} waits in the hour");
    }

    /// What's gone and not yet worked (slices paid ahead and the credit at the seller) never passes
    /// [`Standing::most_unworked_msat`] and the start fee still to pay, at the moment each ticket is bought, over prices,
    /// share sizes, miner rates and start fees; and the renter's own count never leaves a share waiting.
    #[test]
    fn what_is_gone_and_unworked_stays_within_the_stated_bound() {
        let mut worst = 0.0f64;
        for price in [20_000u64, 100_000, 400_000, 546_000, 1_000_000, 3_000_000] {
            for share in [1u128, 10, 100, 400, 1000, 3000, 4000] {
                for per_sec in [0.2f64, 1.0, 5.0, 40.0] {
                    for start in [0u64, 1, 3] {
                        let slice = 1000u128;
                        let mut s = Standing { proven: 0, largest_share: share, paid: 0, start_slices: start, slice_work: slice, price_msat: price, msat_a_second: 0.0, buy_secs: 0.0 };
                        let mut credit = 0u64;
                        let mut owed = 0.0f64;
                        for tick in 0..3000u64 {
                            let now = tick as f64 / 10.0;
                            while s.pay_next_with(credit) {
                                s.paid += 1;
                                if credit < price {
                                    credit += s.ticket_msat_with(credit);
                                    let fee_left = start.saturating_sub(s.paid) * price;
                                    let ahead = s.msat_of(paid_work(s.paid, start, slice).saturating_sub(s.proven));
                                    let gone = ahead + credit - price;
                                    let bound = s.most_unworked_msat() + fee_left;
                                    assert!(gone <= bound, "price {price} share {share} rate {per_sec} start {start} t {now}: {gone} over {bound}");
                                    worst = worst.max(gone as f64 / s.step_msat() as f64);
                                }
                                credit -= price;
                            }
                            owed += per_sec / 10.0;
                            while owed >= 1.0 && fits(s.proven, share, s.paid, start, slice) {
                                owed -= 1.0;
                                s.proven += share;
                            }
                            assert!(owed < 2.0 + per_sec, "a share waited: price {price} share {share} rate {per_sec} start {start} t {now}");
                            if now >= 1.0 {
                                s.msat_a_second = s.msat_of(s.proven) as f64 / now;
                            }
                        }
                    }
                }
            }
        }
        eprintln!("MEASURED the most gone and unworked, over the step: {worst:.2}");
    }

    /// A buy slower than the lead it is started with (at most 30 s) and the hashmaker's 30 s wait together: said in words.
    #[test]
    fn a_route_too_slow_for_the_miner_is_said_in_words() {
        // 1,000 sat a slice, 100 sat a second, 200 sat delivered: the 546 sat step lasts 5.46 s, and a buy is started up
        // to 30 s ahead. (On the timeline the first slow buy stalls the rental before any rate is measured, so the rule is
        // checked on these numbers.)
        let s = Standing { proven: 200, largest_share: 100, paid: 1, start_slices: 0, slice_work: 1000, price_msat: 1_000_000,
                           msat_a_second: 100_000.0, buy_secs: 70.0 };
        assert!(s.too_slow(), "a 70 s buy against a 30 s lead and a 30 s wait");
        assert!(!Standing { buy_secs: 55.0, ..s }.too_slow(), "a 55 s buy: the lead and the wait cover it");
        assert!(!Standing { buy_secs: 20.0, ..s }.too_slow(), "a 20 s buy: before 0.2.13 (no lead, a 10 s wait) this was too slow");
        assert!(!Standing { msat_a_second: 0.0, ..s }.too_slow(), "no rate measured yet: nothing said");
    }

    /// The renter's estimate of a buy: the p95 of those measured, 0 for none.
    #[test]
    fn a_buy_is_estimated_by_the_p95_of_those_measured() {
        assert_eq!(buy_estimate([]), 0.0);
        assert_eq!(buy_estimate([3.7]), 3.7);
        assert_eq!(buy_estimate([3.7, 15.4, 12.2, 11.4, 11.7, 12.4]), 15.4);
        let many: Vec<f64> = (1..=20).map(f64::from).collect();
        assert_eq!(buy_estimate(many), 19.0);
        assert_eq!(buy_estimate([f64::NAN, 2.0]), 2.0, "a measure that isn't one is left out");
    }

    /// Issue #64's rental: 404 sat a slice, 546 sat tickets, a miner whose 30 s of output is 480 sat (16 sat a second),
    /// so the step stays at 546 sat, and buys of 11 to 15 s. Before, the next slice was paid only with less than 142 sat
    /// (8.9 s) ahead, under one buy. Now a buy starts with the measured buy and half of it ahead (18.6 s for 12.4 s).
    #[test]
    fn issue_64_a_slow_buy_starts_while_what_is_paid_still_lasts_it() {
        // a slice is 1,000 work; 16 sat a second is 39.6 work a second
        let at = |proven: u128, paid: u64, buy_secs: f64| Standing { proven, largest_share: 10, paid, start_slices: 0, slice_work: 1000,
                                                                     price_msat: 404_000, msat_a_second: 16_000.0, buy_secs };
        // 2 slices paid, 1,282 work proven: 718 work (290 sat, 18.1 s) ahead
        let s = at(1282, 2, 12.4);
        assert_eq!(s.step_msat(), 546_000);
        assert!((s.buy_lead_secs() - 18.6).abs() < 1e-9 && s.buy_lead_msat() == 297_600, "{} {}", s.buy_lead_secs(), s.buy_lead_msat());
        assert!(!s.pay_next(), "the step alone waits for 142 sat ahead");
        assert!(s.buy_ahead(142_000) && s.pay_next_with(142_000), "18.1 s ahead, under 18.6 s: the buy starts");
        assert!(!s.buy_ahead(404_000), "the credit pays the slice: no buy, and the step decides");
        assert!(!at(1250, 2, 12.4).buy_ahead(142_000), "18.9 s ahead: not yet");
        // with no buy measured, or only quick ones, nothing changes
        assert!(!at(1282, 2, 0.0).pay_next_with(142_000) && !at(1282, 2, 0.5).pay_next_with(142_000));
        // the most gone and unworked: the lead's output, a slice and a ticket (1,247.6 sat), over the step's 950
        assert_eq!(s.most_unworked_msat(), 297_600 + 404_000 + 546_000);
        // the lead is held to the step's own cap, 30 s of output, however slow the buys
        let slow = at(1282, 2, 50.0);
        assert_eq!((slow.buy_lead_secs(), slow.buy_lead_msat()), (30.0, 480_000));
    }

    /// A rental paid by the wallet on a timeline of 0.1 s: one payment at a time; one from credit takes `credit_secs`,
    /// one that buys a ticket `buys(n)` for the n-th buy; the renter measures its buys (`measured`: else it is never told,
    /// as before 0.2.13, when it could never buy ahead); the hashmaker forwards a share only when what has arrived
    /// covers it, holding it otherwise. Within `budget_msat` (tickets sized within what is left of it, as `caps_at`
    /// does). What it came to.
    struct Wallet {
        /// The longest a share was held for a payment, in seconds, and when.
        longest_hold: (f64, f64),
        /// Holds past the hashmaker's short clock (each a `paying` wait).
        waits: usize,
        paid: u64,
        bought: u64,
        bought_ahead: u64,
        /// What left the wallet: tickets.
        moved_msat: u64,
        /// The most gone and unworked over its bound, at any buy (never above 1).
        worst_over_bound: f64,
        /// Seconds it ran.
        ran: f64,
    }

    fn wallet_timeline(price_msat: u64, msat_a_second: f64, buys: &dyn Fn(u64) -> f64, credit_secs: f64, measured: bool, budget_msat: u64, hours: f64) -> Wallet {
        let slice = 1000u128;
        let share = 10u128;
        let work_a_second = msat_a_second * slice as f64 / price_msat as f64;
        let mut s = Standing { proven: 0, largest_share: share, paid: 0, start_slices: 0, slice_work: slice, price_msat, msat_a_second: 0.0, buy_secs: 0.0 };
        let (mut credit, mut arrived) = (0u64, 0u64);
        // the payment on its way: when it lands, the credit then, and how long it took if it bought a ticket
        let mut in_flight: Option<(f64, u64, Option<f64>)> = None;
        let mut measures: Vec<f64> = Vec::new();
        let mut owed = 0.0f64;
        let mut held_since: Option<f64> = None;
        let mut w = Wallet { longest_hold: (0.0, 0.0), waits: 0, paid: 0, bought: 0, bought_ahead: 0, moved_msat: 0, worst_over_bound: 0.0, ran: 0.0 };
        let ticks = (hours * 36_000.0) as u64;
        for tick in 0..ticks {
            let now = tick as f64 / 10.0;
            w.ran = now;
            if let Some((at, c, took)) = in_flight {
                if now >= at {
                    in_flight = None;
                    arrived += 1;
                    credit = c;
                    if let Some(t) = took {
                        measures.push(t);
                        if measures.len() > 16 {
                            measures.remove(0);
                        }
                    }
                }
            }
            s.buy_secs = if measured { buy_estimate(measures.iter().copied()) } else { 0.0 };
            // as the renter: no slice past the budget; a ticket inside what is left of it, never under a slice (`caps_at`)
            let left = budget_msat.saturating_sub(w.moved_msat);
            let affordable = (s.paid + 1) * price_msat <= budget_msat;
            if in_flight.is_none() && affordable && s.pay_next_with(credit) {
                let ahead_buy = s.buy_ahead(credit) && !s.pay_next();
                s.paid += 1;
                if credit >= price_msat {
                    in_flight = Some((now + credit_secs, credit - price_msat, None));
                } else {
                    let ticket = s.ticket_msat_with(credit).min(left).max(price_msat);
                    let after = credit + ticket - price_msat;
                    // what's gone and unworked once it lands, against the bound
                    let ahead = s.msat_of(paid_work(s.paid, 0, slice).saturating_sub(s.proven));
                    w.worst_over_bound = w.worst_over_bound.max((ahead + after) as f64 / s.most_unworked_msat() as f64);
                    let took = buys(w.bought);
                    w.bought += 1;
                    w.bought_ahead += u64::from(ahead_buy);
                    w.moved_msat += ticket;
                    in_flight = Some((now + took, after, Some(took)));
                }
                w.paid += 1;
            }
            // the miners move once the first slice has arrived
            if arrived > 0 {
                owed += work_a_second / 10.0 / share as f64;
            }
            while owed >= 1.0 {
                if !fits(s.proven, share, arrived, 0, slice) {
                    let since = *held_since.get_or_insert(now);
                    if now - since > w.longest_hold.0 {
                        w.longest_hold = (now - since, now);
                    }
                    break;
                }
                if held_since.take().is_some_and(|t| now - t > WAIT_FOR_PAYMENT.as_secs_f64()) {
                    w.waits += 1;
                }
                owed -= 1.0;
                s.proven += share;
            }
            if now >= 1.0 {
                s.msat_a_second = s.msat_of(s.proven) as f64 / now;
            }
            // the rental ends where the budget does: no share fits and none can be paid
            if !affordable && in_flight.is_none() && !fits(s.proven, share, arrived, 0, slice) {
                break;
            }
        }
        w
    }

    /// Issue #64 on the timeline: 404 sat slices, 16 sat a second, the first buy 3.7 s and every other 12.4 s (one in
    /// five 15.4 s), a payment from credit 1 s. Before 0.2.13 (no buy measured ahead) a share waited past the old 10 s
    /// for a buy, which ended the rental unpaid; now each buy starts ahead and no share waits past the short clock but
    /// once, on the second buy, the first measured (3.7 s) being short of it. Over 24 hours: every slice paid once, in
    /// turn, one payment at a time; what's gone and unworked within its bound at every buy; the budget never passed.
    #[test]
    fn issue_64_slow_buys_run_a_day_long_rental_to_its_end() {
        let buys = |n: u64| if n == 0 { 3.7 } else if n.is_multiple_of(5) { 15.4 } else { 12.4 };
        let before = wallet_timeline(404_000, 16_000.0, &buys, 1.0, false, u64::MAX, 1.0);
        eprintln!("MEASURED before: longest hold {:.1} s at {:.0} s, {} waits, {} buys of {} payments", before.longest_hold.0, before.longest_hold.1,
                  before.waits, before.bought, before.paid);
        assert!(before.longest_hold.0 > 10.0, "before: a share waited {:.1} s for a buy", before.longest_hold.0);
        let budget = 1_400_000_000; // 1.4M sat, about the day's output (16 sat a second is 1.38M sat a day)
        let after = wallet_timeline(404_000, 16_000.0, &buys, 1.0, true, budget, 24.0);
        eprintln!("MEASURED after: longest hold {:.1} s at {:.0} s, {} waits, {} buys ({} ahead) of {} payments, {:.0} s, moved {} msat, \
                   worst {:.3} of the bound", after.longest_hold.0, after.longest_hold.1, after.waits, after.bought, after.bought_ahead, after.paid,
                  after.ran, after.moved_msat, after.worst_over_bound);
        assert!(after.ran >= 24.0 * 3600.0 - 1.0 || after.paid * 404_000 + 404_000 > budget, "ran {:.0} s", after.ran);
        assert!(after.longest_hold.0 < WAIT_FOR_PAYING.as_secs_f64() && after.waits <= 1, "after: held {:.1} s, {} waits", after.longest_hold.0, after.waits);
        assert!(after.longest_hold.1 < 120.0 || after.longest_hold.0 <= WAIT_FOR_PAYMENT.as_secs_f64(), "only the second buy may wait: {:?}", after.longest_hold);
        assert!(after.bought_ahead > after.bought / 2, "{} of {} buys started ahead", after.bought_ahead, after.bought);
        assert!(after.worst_over_bound <= 1.0, "{}", after.worst_over_bound);
        // slices charged within the budget; tickets past it by less than a slice at the most, left with the seller as credit
        // (a ticket is never under a slice: a known limit since 0.2.0, which buying ahead doesn't change)
        assert!(after.paid * 404_000 <= budget && after.moved_msat < budget + 404_000, "the budget: {} moved of {budget}", after.moved_msat);
    }

    /// Ticket buys started ahead keep what's gone and unworked within its bound and the budget, over prices, rates and
    /// buy times, and never leave a share waiting past the hashmaker's wait for a payment on its way.
    #[test]
    fn buys_started_ahead_stay_within_the_bound_and_the_budget() {
        for price in [20_000u64, 100_000, 404_000, 1_000_000, 3_000_000] {
            for rate in [1_000.0f64, 16_000.0, 100_000.0, 1_000_000.0] {
                for buy in [0.3f64, 2.0, 8.0, 12.4, 20.0] {
                    let budget = 300_000_000u64;
                    let w = wallet_timeline(price, rate, &|_| buy, 0.5, true, budget, 0.5);
                    assert!(w.worst_over_bound <= 1.0, "price {price} rate {rate} buy {buy}: {}", w.worst_over_bound);
                    assert!(w.paid * price <= budget && w.moved_msat < budget + price, "price {price} rate {rate} buy {buy}: moved {}", w.moved_msat);
                    assert!(w.longest_hold.0 < WAIT_FOR_PAYING.as_secs_f64(), "price {price} rate {rate} buy {buy}: held {:?}", w.longest_hold);
                }
            }
        }
    }
}
