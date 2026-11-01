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

/// The smallest ticket a seller sells, and the first step: the dust limit that held tickets have too.
pub const FIRST_STEP_MSAT: u64 = 546_000;
/// How much of a miner's output a step can reach.
pub const STEP_SECONDS: f64 = 30.0;
/// How long a share that doesn't fit waits for payment before the rental stops.
pub const WAIT_FOR_PAYMENT: std::time::Duration = std::time::Duration::from_secs(2);
/// How long it waits instead when the renter has said a payment is on its way (`paying`). Its miners hash for the
/// hashmaker's own pool meanwhile, so the wait costs it nothing but the move.
pub const WAIT_FOR_PAYING: std::time::Duration = std::time::Duration::from_secs(10);
/// Such waits a rental may have in an hour.
pub const PAYING_WAITS_AN_HOUR: usize = 6;
/// While the renter's step ramps up to its cap ([`STEP_SECONDS`] of output), which is the miners' first that many
/// seconds of work for the rental, a wallet slower than the step lasts can't keep a large miner fed, and each early
/// ticket buy may be waited for. Those waits aren't counted against [`PAYING_WAITS_AN_HOUR`]; there may be this many.
/// Each is still held to [`WAIT_FOR_PAYING`].
pub const RAMP_WAITS_MOST: usize = 12;
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
    /// smallest ticket keeps all that within the step.
    pub fn pay_next_with(&self, credit_msat: u64) -> bool {
        if !self.pay_next() {
            return false;
        }
        let covered = paid_work(self.paid, self.start_slices, self.slice_work);
        if self.needed() || credit_msat >= self.price_msat {
            return true;
        }
        let ahead = self.msat_of(covered.saturating_sub(self.proven));
        ahead + credit_msat + self.smallest_ticket_msat() <= self.step_msat()
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
    /// the step, or, when a share must be paid for and a ticket bought for it, one share, one slice and the smallest
    /// ticket, whichever is more.
    pub fn most_unworked_msat(&self) -> u64 {
        let share = self.largest_share.min(LARGEST_SHARE_SLICES * self.slice_work);
        self.step_msat().max(self.msat_of(share) + self.price_msat + self.smallest_ticket_msat())
    }

    /// How long what's paid and not yet worked lasts at the measured output.
    pub fn secs_left(&self) -> f64 {
        let covered = paid_work(self.paid, self.start_slices, self.slice_work);
        if self.msat_a_second <= 0.0 {
            return f64::INFINITY;
        }
        self.msat_of(covered.saturating_sub(self.proven)) as f64 / self.msat_a_second
    }

    /// The route is too slow for this miner's rate: the most the renter may have paid ahead, and the hashmaker's wait for
    /// a payment on its way, last less than a ticket takes to buy. Said in words, before a share waits past them.
    pub fn too_slow(&self) -> bool {
        self.msat_a_second > 0.0
            && self.buy_secs > 0.0
            && (self.step_msat() as f64 / self.msat_a_second) + WAIT_FOR_PAYING.as_secs_f64() < self.buy_secs
    }

}

/// Was this ended rental a failed first step? Money went and little work came back, and the renter didn't end it
/// itself. A renter's app stops going back to a seller after [`FAILED_FIRST_STEPS`] of these in a row.
pub fn failed_first_step(report: &serde_json::Value) -> bool {
    let closed = report["closed"].as_str().unwrap_or("");
    let own_choice = ["cut by the hashtaker", "rental time over", "budget used up"].contains(&closed);
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

    /// A buy slower than the step and the 10 s wait together: said in words.
    #[test]
    fn a_route_too_slow_for_the_miner_is_said_in_words() {
        // 1,000 sat a slice, 100 sat a second, 200 sat delivered: the 546 sat step lasts 5.46 s. (On the timeline the first
        // 20 s buy stalls the rental before any rate is measured, so the rule is checked on these numbers.)
        let s = Standing { proven: 200, largest_share: 100, paid: 1, start_slices: 0, slice_work: 1000, price_msat: 1_000_000,
                           msat_a_second: 100_000.0, buy_secs: 20.0 };
        assert!(s.too_slow(), "a 20 s buy against a 5.46 s step and a 10 s wait");
        assert!(!Standing { buy_secs: 15.0, ..s }.too_slow(), "a 15 s buy: the step and the wait cover it");
        assert!(!Standing { msat_a_second: 0.0, ..s }.too_slow(), "no rate measured yet: nothing said");
    }
}
