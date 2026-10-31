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
        self.msat_of(after.saturating_sub(self.proven)) <= self.step_msat()
    }

    /// The largest ticket worth buying for the payment that's due. With the start fee on the first, whose share
    /// isn't known yet.
    pub fn ticket_msat(&self) -> u64 {
        let step = self.step_msat();
        if self.paid == 0 {
            return step.max(self.price_msat).saturating_add(self.start_slices.saturating_mul(self.price_msat));
        }
        step.max(self.price_msat)
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
        Standing { proven, largest_share, paid, start_slices: 2, slice_work: 1000, price_msat: 400_000, msat_a_second: 0.0 }
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
        let s = |paid| Standing { proven: 0, largest_share: 100, paid, start_slices: 0, slice_work: 1000, price_msat: 100_000, msat_a_second: 0.0 };
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
        assert_eq!(at(0, 0, 0).ticket_msat(), 546_000 + 800_000);
        // a slice above the first step: that, then
        let s = Standing { price_msat: 1_000_000, start_slices: 1, ..at(0, 0, 0) };
        assert_eq!(s.ticket_msat(), 2_000_000);
        assert_eq!(at(0, 0, 3).ticket_msat(), 546_000);
    }
}
