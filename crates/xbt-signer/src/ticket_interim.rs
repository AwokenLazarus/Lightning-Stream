//! A seller's **interim receipts** for an answer that is still open (a WebSocket, a VPN tunnel),
//! checked as the answer runs (docs/VPN-EXITS.md, "Interim receipts").
//!
//! A long-lived answer is otherwise checked only by its last receipt, at its end. The seller lists
//! its latest signed count of each open answer in `status` (`interim`), and the wallet compares it
//! with its own count every [`INTERIM_POLL`] while the answer runs. A count the wallet cannot
//! believe is a seller fault, which stops the session like any other:
//!
//! 1. **Order:** each one is a later part than the last, and its charge and byte counts never fall.
//! 2. **The call's limit:** it never charges past what the call allowed (`max_sats`).
//! 3. **The bytes:** the bytes it says it passed each way are no more than the wallet counted, with
//!    room for what is still on the way ([`slack`]); and its charge is no more than those bytes cost.
//! 4. **Liveness:** once a seller has sent one, bytes that keep flowing without a newer one for
//!    [`INTERIM_STALE`] are a fault too, once the seller has had its say: [`STALE_ANSWERS`]
//!    `status` answers in a row with no newer count, or `status` failing for [`STALE_FAILING`]
//!    times as long (a slow or lossy link is not taken for a seller that stopped counting, and a
//!    seller that answers only errors is still caught). A seller that never sends any (one from
//!    before interim receipts) is held to the rules every answer has: its spend never passes what
//!    was released.

use std::time::{Duration, Instant};

use crate::ticket_http::{Price, Receipt};

/// How often the wallet asks for the seller's count of an open answer (`B2_INTERIM_POLL_MS` sets it).
pub const INTERIM_POLL: Duration = Duration::from_secs(10);
/// Bytes flowing with no newer interim receipt for this long, after a first one: a fault
/// (`B2_INTERIM_STALE_MS` sets it). Three of the seller's periods.
pub const INTERIM_STALE: Duration = Duration::from_secs(30);

fn env_ms(name: &str, default: Duration) -> Duration {
    std::env::var(name).ok().and_then(|v| v.parse::<u64>().ok()).map(Duration::from_millis).unwrap_or(default)
}

/// [`INTERIM_POLL`], or what `B2_INTERIM_POLL_MS` says.
pub fn poll_every() -> Duration {
    env_ms("B2_INTERIM_POLL_MS", INTERIM_POLL)
}

/// [`INTERIM_STALE`], or what `B2_INTERIM_STALE_MS` says.
pub fn stale_after() -> Duration {
    env_ms("B2_INTERIM_STALE_MS", INTERIM_STALE)
}
/// How many bytes must have flowed meanwhile for [`INTERIM_STALE`] to count: the seller signs one
/// for every MiB's price, so more than that with none is not a quiet link.
pub const INTERIM_STALE_BYTES: u64 = 2 << 20;

/// What the wallet holds of an answer's interim receipts.
#[derive(Debug, Clone, PartialEq)]
pub struct Seen {
    pub part: u64,
    pub charged: u64,
    pub up: u64,
    pub down: u64,
    /// When the wallet first saw this part, and its own byte count then.
    pub at: Instant,
    pub own_at: u64,
}

/// What a seller's interim charge may run ahead of the bytes it counted: a seller pays for a chunk
/// before it writes it and counts it after, so one chunk (16 KiB) each way may be paid and not yet
/// counted when the other way signs.
pub const CHUNK_SLACK: u64 = 2 * 16 * 1024;

/// What the seller may count past the wallet in one direction: bytes on their way (in the seller's
/// and the link's buffers) when the receipt was signed and the wallet read its own count: 2% of
/// the wallet's count and 4 MiB.
pub fn slack(own: u64) -> u64 {
    own / 50 + (4 << 20)
}

/// One interim receipt (already checked for signature and session) against the wallet's own count
/// of the answer: `own_up` bytes it sent, `own_down` it received. `head` is what the answer's head
/// charged (the request's price); `max_msat` the call's limit. `Ok(true)`: a newer part, now held
/// in `last`; `Ok(false)`: not newer (already seen, or another answer's); `Err`: the fault.
#[allow(clippy::too_many_arguments)]
pub fn check(
    r: &Receipt,
    seq: u64,
    digest: &str,
    status: u16,
    own_up: u64,
    own_down: u64,
    price: &Price,
    max_msat: u64,
    last: &mut Option<Seen>,
) -> Result<bool, String> {
    if r.for_request(seq, digest, status).is_err() {
        return Ok(false);
    }
    let Some((part, up, down)) = xbt402::ticket::parse_interim(&r.body_hash) else { return Ok(false) };
    if let Some(l) = last.as_ref() {
        if part == l.part && r.charged == l.charged && up == l.up && down == l.down {
            return Ok(false);
        }
        if part <= l.part || r.charged < l.charged || up < l.up || down < l.down {
            return Err(format!(
                "the seller's count of an open answer went back (part {part} after {}, {} msat after {})",
                l.part, r.charged, l.charged
            ));
        }
    }
    if r.spent_msat > r.released_msat {
        return Err(format!("the seller's interim receipt spends {} msat of {} released", r.spent_msat, r.released_msat));
    }
    if r.charged > max_msat {
        return Err(format!("the seller charged {} msat so far for an open answer, more than the {max_msat} msat the call allowed", r.charged));
    }
    if up > own_up.saturating_add(slack(own_up)) || down > own_down.saturating_add(slack(own_down)) {
        return Err(format!(
            "the seller says it passed {up} bytes out and {down} back on an open answer; the wallet counted {own_up} and {own_down}"
        ));
    }
    let worth = price.cost(up.saturating_add(down).saturating_add(CHUNK_SLACK), 0).unwrap_or(u64::MAX);
    if r.charged > worth {
        return Err(format!("the seller charged {} msat for an open answer whose bytes, by its own count, cost {worth}", r.charged));
    }
    *last = Some(Seen { part, charged: r.charged, up, down, at: Instant::now(), own_at: own_up.saturating_add(own_down) });
    Ok(true)
}

/// Whether a seller that has sent interim receipts has stopped while bytes still flow: `own` is
/// the wallet's byte count now, `after` how long the wallet waits for a newer one ([`stale_after`]).
/// `status` answers in a row with no newer count, past [`INTERIM_STALE`], before a seller is stale.
pub const STALE_ANSWERS: u32 = 2;
/// How many times [`INTERIM_STALE`] a failing `status` may last before its seller is stale.
pub const STALE_FAILING: u32 = 3;

/// How the seller's `status` answered since its last newer count: answers with none newer, and
/// since when it has failed (no answer, or none the wallet can take).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Polls {
    pub answered: u32,
    pub failing_since: Option<Instant>,
}

impl Polls {
    /// A `status` answer with no newer count.
    pub fn answered(&mut self) {
        self.answered = self.answered.saturating_add(1);
        self.failing_since = None;
    }
    /// A `status` the wallet could not have or take.
    pub fn failed(&mut self, now: Instant) {
        self.failing_since.get_or_insert(now);
    }
    /// A newer count: the seller is counting.
    pub fn counted(&mut self) {
        *self = Polls::default();
    }
}

pub fn stale(last: &Option<Seen>, polls: &Polls, own: u64, now: Instant, after: Duration) -> Option<String> {
    let l = last.as_ref()?;
    let flowed = own.saturating_sub(l.own_at);
    // the seller has had its say: answers with nothing newer, or a status failing for a long while
    let heard = polls.answered >= STALE_ANSWERS || polls.failing_since.is_some_and(|t| now.saturating_duration_since(t) >= after * STALE_FAILING);
    (heard && now.saturating_duration_since(l.at) >= after && flowed >= INTERIM_STALE_BYTES).then(|| {
        format!(
            "the seller sent no count of an open answer for {} s while {flowed} more bytes passed",
            now.saturating_duration_since(l.at).as_secs()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn price() -> Price {
        // 1 msat a KiB, and 100 msat for the request
        Price { tokens: Default::default(), request_msat: 100, byte_msat: 1, per_bytes: 1024, second_msat: 0 }
    }

    fn receipt(part: u64, up: u64, down: u64, charged: u64) -> Receipt {
        Receipt {
            seq: 7,
            released_msat: 10_000_000,
            spent_msat: 1_000,
            charged,
            status: 101,
            req: "d".into(),
            body_hash: xbt402::ticket::interim_body_hash(part, up, down),
            raw: json!({}),
        }
    }

    fn cost(bytes: u64) -> u64 {
        price().cost(bytes, 0).unwrap()
    }

    #[test]
    fn an_honest_sellers_counts_are_taken_part_by_part() {
        let mut last = None;
        let r1 = receipt(1, 1 << 20, 4 << 20, cost(5 << 20));
        assert_eq!(check(&r1, 7, "d", 101, 1 << 20, 4 << 20, &price(), u64::MAX, &mut last), Ok(true));
        // the same part again, as the next poll finds it: not newer, no fault
        assert_eq!(check(&r1, 7, "d", 101, 2 << 20, 9 << 20, &price(), u64::MAX, &mut last), Ok(false));
        // a later part, counted a little ahead of the wallet (bytes still on their way)
        let r3 = receipt(3, 2 << 20, 10 << 20, cost(12 << 20));
        assert_eq!(check(&r3, 7, "d", 101, 2 << 20, 9 << 20, &price(), u64::MAX, &mut last), Ok(true));
        assert_eq!(last.as_ref().map(|l| l.part), Some(3));
        // another answer's, or a final receipt: not this one's
        assert_eq!(check(&receipt(9, 0, 0, 0), 8, "d", 101, 0, 0, &price(), u64::MAX, &mut last), Ok(false));
        let mut fin = receipt(4, 0, 0, 0);
        fin.body_hash = "ab".repeat(32);
        assert_eq!(check(&fin, 7, "d", 101, 0, 0, &price(), u64::MAX, &mut last), Ok(false));
    }

    #[test]
    fn a_seller_that_counts_more_bytes_than_passed_is_a_fault() {
        let mut last = None;
        // 50 MiB back claimed; the wallet received 10
        let r = receipt(1, 0, 50 << 20, cost(50 << 20));
        assert!(check(&r, 7, "d", 101, 0, 10 << 20, &price(), u64::MAX, &mut last).unwrap_err().contains("wallet counted"));
        assert!(last.is_none());
    }

    #[test]
    fn a_seller_that_charges_more_than_its_own_bytes_cost_is_a_fault() {
        let mut last = None;
        let r = receipt(1, 0, 1 << 20, cost(1 << 20) * 3);
        assert!(check(&r, 7, "d", 101, 0, 1 << 20, &price(), u64::MAX, &mut last).unwrap_err().contains("cost"));
    }

    #[test]
    fn a_chunk_paid_for_and_not_yet_counted_each_way_is_no_fault_and_more_is() {
        // the seller paid for a chunk each way that it had not counted when it signed
        let mut last = None;
        let r = receipt(1, 0, 1 << 20, cost((1 << 20) + CHUNK_SLACK));
        assert_eq!(check(&r, 7, "d", 101, 0, 1 << 20, &price(), u64::MAX, &mut last), Ok(true));
        let mut last = None;
        let r = receipt(1, 0, 1 << 20, cost((1 << 20) + CHUNK_SLACK) + 2);
        assert!(check(&r, 7, "d", 101, 0, 1 << 20, &price(), u64::MAX, &mut last).unwrap_err().contains("cost"));
    }

    #[test]
    fn a_charge_past_the_calls_limit_or_a_count_that_goes_back_is_a_fault() {
        let mut last = None;
        let r = receipt(1, 0, 1 << 20, cost(1 << 20));
        assert!(check(&r, 7, "d", 101, 0, 1 << 20, &price(), cost(1 << 19), &mut last).unwrap_err().contains("allowed"));
        assert_eq!(check(&r, 7, "d", 101, 0, 1 << 20, &price(), u64::MAX, &mut last), Ok(true));
        let back = receipt(2, 0, 1 << 19, cost(1 << 19));
        assert!(check(&back, 7, "d", 101, 0, 2 << 20, &price(), u64::MAX, &mut last).unwrap_err().contains("went back"));
        let old_part = receipt(1, 0, 2 << 20, cost(2 << 20));
        assert!(check(&old_part, 7, "d", 101, 0, 2 << 20, &price(), u64::MAX, &mut last).is_err());
    }

    #[test]
    fn a_seller_that_stops_counting_while_bytes_flow_is_found() {
        let now = Instant::now();
        // the seller answered status twice with nothing newer
        let answered = Polls { answered: STALE_ANSWERS, failing_since: None };
        assert_eq!(stale(&None, &answered, 1 << 30, now, INTERIM_STALE), None, "a seller that never sent one is held to the usual rules");
        let seen = Some(Seen { part: 1, charged: 0, up: 0, down: 0, at: now, own_at: 1 << 20 });
        assert_eq!(stale(&seen, &answered, 100 << 20, now + Duration::from_secs(5), INTERIM_STALE), None, "not long enough");
        assert_eq!(stale(&seen, &answered, (1 << 20) + 1000, now + Duration::from_secs(60), INTERIM_STALE), None, "a quiet link");
        assert!(stale(&seen, &answered, 100 << 20, now + Duration::from_secs(31), INTERIM_STALE).is_some());
        // a status that failed for a short while is a slow link, not a seller that stopped counting
        let failing = Polls { answered: 0, failing_since: Some(now + Duration::from_secs(20)) };
        assert_eq!(stale(&seen, &failing, 100 << 20, now + Duration::from_secs(31), INTERIM_STALE), None, "an honest seller behind a slow status");
        // one answering only errors for long enough is caught all the same
        assert!(stale(&seen, &failing, 100 << 20, now + Duration::from_secs(20 + 90), INTERIM_STALE).is_some());
    }
}
