//! What a piece costs. A route's price is the sum of three rules a runner can set without changing
//! the service behind the gateway: an amount per request, an amount per `per_bytes` bytes of the
//! response, and an amount per started second the response is open. All in millisatoshi, all
//! checked: a price that does not fit is no price, and the request is not served.
//!
//! What these rules cannot price is anything only the service can count, such as the tokens a model
//! produced: the gateway sees bytes and time. [`UNITS_HEADER`] is the name kept for a count the
//! service may one day state; this version reads no price from it and never passes it on.
use serde_json::{json, Value};

/// Reserved: a response header in which an upstream may state how many units it produced. Not read
/// for money in this version, and removed from every response.
pub const UNITS_HEADER: &str = "Ticket-Units";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Price {
    /// Charged once, when the upstream answers with a status below 400.
    pub request_msat: u64,
    /// Charged for every `per_bytes` bytes of the response body, rounded up over the whole body.
    pub byte_msat: u64,
    /// At least 1.
    pub per_bytes: u64,
    /// Charged for every started second between the response's head and its last byte.
    pub second_msat: u64,
}

impl Price {
    pub fn is_free(&self) -> bool {
        self.request_msat == 0 && self.byte_msat == 0 && self.second_msat == 0
    }

    /// Whether the body is metered as it goes (per byte or per second).
    pub fn metered(&self) -> bool {
        self.byte_msat > 0 || self.second_msat > 0
    }

    /// The price of the first `bytes` bytes of a body: `ceil(bytes * byte_msat / per_bytes)`.
    pub fn for_bytes(&self, bytes: u64) -> Option<u64> {
        if self.byte_msat == 0 {
            return Some(0);
        }
        let per = u128::from(self.per_bytes.max(1));
        let total = u128::from(bytes).checked_mul(u128::from(self.byte_msat))?;
        u64::try_from(total.div_ceil(per)).ok()
    }

    /// The price of `seconds` started seconds.
    pub fn for_seconds(&self, seconds: u64) -> Option<u64> {
        seconds.checked_mul(self.second_msat)
    }

    /// The most bytes a body may reach while its byte price stays within `msat`.
    pub fn bytes_for(&self, msat: u64) -> u64 {
        if self.byte_msat == 0 {
            return u64::MAX;
        }
        let n = u128::from(msat) * u128::from(self.per_bytes.max(1)) / u128::from(self.byte_msat);
        u64::try_from(n).unwrap_or(u64::MAX)
    }

    /// The rule as the terms state it.
    pub fn terms(&self) -> Value {
        json!({"requestMsat": self.request_msat.to_string(), "byteMsat": self.byte_msat.to_string(), "perBytes": self.per_bytes.to_string(),
               "secondMsat": self.second_msat.to_string()})
    }
}

/// One response body's meter: what has been sent and what has been charged for it. `charged` only
/// rises, and is always the price of exactly `bytes` bytes and `seconds` started seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meter {
    price: Price,
    bytes: u64,
    seconds: u64,
    charged: u64,
}

impl Meter {
    pub fn new(price: Price) -> Self {
        Self {
            price,
            bytes: 0,
            seconds: 0,
            charged: 0,
        }
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// What the body has cost so far (the request price is not in it).
    pub fn charged(&self) -> u64 {
        self.charged
    }

    /// What `more` further bytes would add to the charge. `None`: it does not fit.
    pub fn bytes_due(&self, more: u64) -> Option<u64> {
        let after = self.price.for_bytes(self.bytes.checked_add(more)?)?;
        after.checked_sub(self.price.for_bytes(self.bytes)?)
    }

    /// How many of `want` further bytes `budget` msat pays for.
    pub fn affordable(&self, want: u64, budget: u64) -> u64 {
        let paid = self.price.for_bytes(self.bytes).unwrap_or(u64::MAX);
        let reach = self.price.bytes_for(paid.saturating_add(budget));
        want.min(reach.saturating_sub(self.bytes))
    }

    /// Count `more` bytes as sent and `due` as charged for them (`due` is [`Meter::bytes_due`]).
    pub fn sent(&mut self, more: u64, due: u64) {
        self.bytes = self.bytes.saturating_add(more);
        self.charged = self.charged.saturating_add(due);
    }

    /// What is due for the seconds started up to `elapsed_ms` after the head and not yet charged.
    /// `None`: it does not fit. The first second starts at the head.
    pub fn seconds_due(&self, elapsed_ms: u64) -> Option<(u64, u64)> {
        let started = elapsed_ms / 1000 + 1;
        let new = started.saturating_sub(self.seconds);
        Some((new, self.price.for_seconds(new)?))
    }

    pub fn seconds_charged(&mut self, seconds: u64, due: u64) {
        self.seconds = self.seconds.saturating_add(seconds);
        self.charged = self.charged.saturating_add(due);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KIB: Price = Price {
        request_msat: 0,
        byte_msat: 1000,
        per_bytes: 1 << 20,
        second_msat: 0,
    };

    #[test]
    fn bytes_are_priced_rounded_up_over_the_whole_body() {
        assert_eq!(KIB.for_bytes(0), Some(0));
        assert_eq!(KIB.for_bytes(1), Some(1));
        assert_eq!(KIB.for_bytes(1 << 20), Some(1000));
        assert_eq!(KIB.for_bytes((1 << 20) + 1), Some(1001));
        assert_eq!(KIB.for_bytes(100 << 20), Some(100_000));
        // however a body is cut into chunks, the charges add up to the price of the whole
        for chunk in [1u64, 7, 1000, 16384, 65536, 1 << 20] {
            let mut m = Meter::new(KIB);
            let total = 3_000_000u64;
            let mut left = total;
            while left > 0 {
                let n = chunk.min(left);
                let due = m.bytes_due(n).unwrap();
                m.sent(n, due);
                left -= n;
            }
            assert_eq!(m.charged(), KIB.for_bytes(total).unwrap(), "chunk {chunk}");
            assert_eq!(m.bytes(), total);
        }
    }

    #[test]
    fn a_price_that_does_not_fit_is_no_price() {
        let huge = Price {
            request_msat: 0,
            byte_msat: u64::MAX,
            per_bytes: 1,
            second_msat: u64::MAX,
        };
        assert_eq!(huge.for_bytes(2), None);
        assert_eq!(huge.for_seconds(2), None);
        assert_eq!(Meter::new(huge).bytes_due(2), None);
        assert_eq!(Meter::new(huge).seconds_due(5000), None);
        let mut m = Meter::new(KIB);
        m.sent(u64::MAX - 1, 0);
        assert_eq!(m.bytes_due(2), None, "the byte count itself overflows");
    }

    #[test]
    fn affordable_is_the_most_bytes_the_budget_pays_for() {
        let m = Meter::new(KIB);
        assert_eq!(m.affordable(10, 0), 0);
        // 1 msat pays for up to 1048 bytes: ceil(1048 * 1000 / 2^20) = 1, and 1049 costs 2
        assert_eq!(m.affordable(1 << 20, 1), 1048);
        assert_eq!(KIB.for_bytes(1048), Some(1));
        assert_eq!(KIB.for_bytes(1049), Some(2));
        assert_eq!(m.affordable(500, 1), 500);
        // whatever the budget and the chunk, what is affordable never costs more than the budget
        for budget in [0u64, 1, 2, 3, 15, 16, 999, 1000] {
            let mut m = Meter::new(KIB);
            let mut left = budget;
            for want in [1u64, 100, 16384, 1 << 20, 5 << 20] {
                let n = m.affordable(want, left);
                let due = m.bytes_due(n).unwrap();
                assert!(due <= left, "budget {budget} want {want}: {due} > {left}");
                m.sent(n, due);
                left -= due;
            }
            assert!(m.charged() <= budget);
            // and one byte more would have cost more than what is left
            assert!(m.bytes_due(1).unwrap() > left || left > 0 && m.affordable(1, left) == 1);
        }
        let free = Meter::new(Price {
            per_bytes: 1,
            ..Price::default()
        });
        assert_eq!(free.affordable(77, 0), 77);
    }

    #[test]
    fn seconds_are_charged_as_they_start() {
        let p = Price {
            request_msat: 0,
            byte_msat: 0,
            per_bytes: 1,
            second_msat: 50,
        };
        let mut m = Meter::new(p);
        assert_eq!(
            m.seconds_due(0),
            Some((1, 50)),
            "the first second starts at the head"
        );
        m.seconds_charged(1, 50);
        assert_eq!(m.seconds_due(999), Some((0, 0)));
        assert_eq!(m.seconds_due(1000), Some((1, 50)));
        assert_eq!(m.seconds_due(3500), Some((3, 150)));
        m.seconds_charged(3, 150);
        assert_eq!(m.charged(), 200);
        assert_eq!(m.seconds_due(3999), Some((0, 0)));
    }
}
