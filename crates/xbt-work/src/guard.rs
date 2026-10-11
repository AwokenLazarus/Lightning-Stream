//! One round of a background loop, kept apart from the next (AGP-097).
//!
//! The rule: **a panic in one round of a loop the provider depends on ends that round, not the
//! loop.** `xbt-work-provider` runs three: the channel watcher (`close_due`), the relay pull, which
//! also follows the epoch, and the audit walk. Every release build has overflow checks on, so a
//! missed overflow anywhere under one of them is a panic; before, the thread ended and the service
//! went on answering with no watcher, no pull or no audit. The state these loops share is behind
//! locks that are taken again after a panic (`WorkProvider`, the ledger), and each round reads what
//! it needs from them afresh.
//!
//! A build with `panic = "abort"` (the `release-small` profile) has nothing to catch: there the
//! process ends and its supervisor starts it again.
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Run one round. Err: it panicked, with the panic's message.
pub fn round(f: impl FnOnce()) -> Result<(), String> {
    catch_unwind(AssertUnwindSafe(f)).map_err(|p| {
        p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_else(|| "a panic with no message".into())
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_round_that_panics_does_not_end_the_rounds_after_it() {
        let quiet = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let mut done = 0u32;
        let mut failed = vec![];
        for n in 0..5u32 {
            // the third round overflows, as a missed check would under overflow-checks
            let r = super::round(|| {
                let top = if n == 2 { u32::MAX } else { n };
                done += top.checked_add(1).map(|_| 1).unwrap_or_else(|| panic!("round {n} overflowed"));
            });
            failed.extend(r.err());
        }
        std::panic::set_hook(quiet);
        assert_eq!((done, failed), (4, vec!["round 2 overflowed".to_string()]));
    }
}
