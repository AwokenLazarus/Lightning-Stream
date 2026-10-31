//! The metering arithmetic both sides share, checked over many random cases: what a body, a
//! WebSocket or a tunnel is charged is a function of its bytes (and started seconds) and the
//! listed price alone, however the bytes are cut into chunks, whenever the seller signs an interim
//! receipt, and whether the buyer or the seller works it out.
//!
//! - the buyer's price (`xbt_signer::ticket_http::Price`) and the seller's (`xbt_gateway::price::Price`)
//!   give the same number for every body;
//! - the seller's `Meter`, fed any chunking with seconds charged in between, has charged exactly the
//!   price of what it sent at every step: no gap, no double charge;
//! - paid before it is sent, a chunk at a time from a balance refilled one ticket at a time, a body
//!   is charged its whole price and the balance never goes below zero or holds more than a ticket's
//!   worth past what was needed;
//! - an honest seller's interim receipts, signed at any moment of a two-way stream, are taken by
//!   the wallet's check without a fault, never fall, and the last one is the price of every byte;
//!   a seller that stops counting is not a fault to that check (it charges less), so the lab's
//!   usage-times-price check is what finds it.
//!
//! No property-testing crate: a seeded generator, so a failure names its seed and case.

use xbt_gateway::price::{Meter, Price as SellerPrice};
use xbt_signer::ticket_http::{Price as BuyerPrice, Receipt};
use xbt_signer::ticket_interim::{check, Seen};

/// xorshift64*: small, deterministic, good enough to pick cases.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// In `lo..=hi`.
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }
    fn chance(&mut self, one_in: u64) -> bool {
        self.next().is_multiple_of(one_in)
    }
}

const CASES: u64 = 400;
const SEED: u64 = 0x005E_ED0F_3E7E_2026;

/// A listed price as a seller writes one: per byte over a unit of 1 byte to 1 GiB, per second, and
/// a price per request, each sometimes zero.
fn listed(g: &mut Rng) -> (u64, u64, u64, u64) {
    let per_bytes = match g.range(0, 4) {
        0 => 1,
        1 => 1024,
        2 => 1 << 20,
        3 => 1 << 30,
        _ => g.range(1, 10_000_000),
    };
    let byte_msat = if g.chance(5) { 0 } else { g.range(1, 2_000_000) };
    let second_msat = if g.chance(2) { 0 } else { g.range(1, 50_000) };
    let request_msat = if g.chance(3) { 0 } else { g.range(1, 10_000) };
    (request_msat, byte_msat, per_bytes, second_msat)
}

fn seller(p: (u64, u64, u64, u64)) -> SellerPrice {
    SellerPrice { request_msat: p.0, byte_msat: p.1, per_bytes: p.2, second_msat: p.3, tokens: Default::default() }
}

fn buyer(p: (u64, u64, u64, u64)) -> BuyerPrice {
    BuyerPrice { tokens: Default::default(), request_msat: p.0, byte_msat: p.1, per_bytes: p.2, second_msat: p.3 }
}

/// A chunk length as the wire cuts bodies: single bytes, odd sizes, the 16 and 64 KiB of the
/// gateway's and the service's buffers, and a few MiB at once.
fn chunk(g: &mut Rng) -> u64 {
    match g.range(0, 5) {
        0 => 1,
        1 => g.range(1, 999),
        2 => 16 << 10,
        3 => 64 << 10,
        4 => g.range(1, 256 << 10),
        _ => g.range(1, 4 << 20),
    }
}

#[test]
fn the_buyer_and_the_seller_price_every_body_the_same() {
    let mut g = Rng(SEED);
    for case in 0..CASES * 10 {
        let p = listed(&mut g);
        let (s, b) = (seller(p), buyer(p));
        let bytes = match g.range(0, 3) {
            0 => g.range(0, 1 << 20),
            1 => g.range(0, 10 << 30),
            2 => g.range(0, 1 << 40),
            _ => (g.range(0, 100) << 20) + g.range(0, 2),
        };
        let seconds = g.range(0, 100_000);
        assert_eq!(s.for_bytes(bytes), b.for_bytes(bytes), "case {case}: {p:?}, {bytes} bytes");
        assert_eq!(s.for_seconds(seconds), b.for_seconds(seconds), "case {case}: {p:?}, {seconds} s");
        // the whole price of an answer: its request, its bytes and its seconds
        let whole = s.for_bytes(bytes).and_then(|x| x.checked_add(s.for_seconds(seconds)?)).and_then(|x| x.checked_add(p.0));
        assert_eq!(b.cost(bytes, seconds), whole, "case {case}: {p:?}");
        // ceil(bytes * byte_msat / per_bytes), worked out here the long way
        if let Some(c) = s.for_bytes(bytes) {
            let exact = (u128::from(bytes) * u128::from(p.1)).div_ceil(u128::from(p.2));
            assert_eq!(u128::from(c), exact, "case {case}");
        }
    }
}

#[test]
fn a_body_cut_into_any_chunks_with_seconds_charged_between_is_charged_its_price_at_every_step() {
    let mut g = Rng(SEED ^ 1);
    for case in 0..CASES {
        let p = listed(&mut g);
        let price = seller(p);
        let mut m = Meter::new(price);
        let total = g.range(0, 120 << 20);
        let (mut sent, mut elapsed_ms, mut seconds) = (0u64, 0u64, 0u64);
        while sent < total {
            let n = chunk(&mut g).min(total - sent);
            let due = m.bytes_due(n).expect("fits");
            m.sent(n, due);
            sent += n;
            // now and then a second (or several) starts while the body runs
            if g.chance(3) {
                elapsed_ms += g.range(0, 3_000);
                let (new, due) = m.seconds_due(elapsed_ms).expect("fits");
                m.seconds_charged(new, due);
                seconds += new;
            }
            assert_eq!(m.bytes(), sent);
            assert_eq!(m.charged(), price.for_bytes(sent).unwrap() + price.for_seconds(seconds).unwrap(), "case {case}: {p:?} after {sent} bytes, {seconds} s");
        }
        assert_eq!(seconds, if seconds == 0 { 0 } else { elapsed_ms / 1000 + 1 }, "case {case}: every started second, once");
    }
}

#[test]
fn a_body_paid_for_before_it_is_sent_from_tickets_is_charged_its_price_and_holds_at_most_a_ticket() {
    let mut g = Rng(SEED ^ 2);
    for case in 0..CASES {
        let (_, _, per_bytes, _) = listed(&mut g);
        let ticket = g.range(10_000, 5_000_000);
        // a byte never costs more than a ticket, or no ticket could pay for it
        let byte_msat = g.range(1, 2_000_000).min(ticket.saturating_mul(per_bytes) / 2).max(1);
        let price = SellerPrice { request_msat: 0, byte_msat, per_bytes, second_msat: 0, tokens: Default::default() };
        // at most some 20,000 tickets' worth, so a case stays quick
        let total = g.range(1, 80 << 20).min(price.bytes_for(20_000 * ticket)).max(1);
        let mut m = Meter::new(price);
        let (mut balance, mut released, mut sent) = (0u64, 0u64, 0u64);
        // as the gateway's pay_bytes: as many of the chunk's bytes as the balance pays for; when it
        // pays for none, the wallet releases the next ticket
        while sent < total {
            let want = chunk(&mut g).min(total - sent);
            let take = m.affordable(want, balance);
            if take == 0 {
                released += 1;
                balance += ticket;
                continue;
            }
            let due = m.bytes_due(take).unwrap();
            assert!(due <= balance, "case {case}: {take} bytes cost {due}, more than the {balance} the balance holds");
            balance -= due;
            m.sent(take, due);
            sent += take;
        }
        let charged = m.charged();
        assert_eq!(charged, price.for_bytes(total).unwrap(), "case {case}");
        assert_eq!(released * ticket, charged + balance, "case {case}: every msat released is charged or left");
        // a ticket is released only when the balance does not pay for the next byte: what is left is under a ticket
        assert!(balance < ticket, "case {case}: {balance} left of tickets of {ticket}");
        assert_eq!(released, charged.div_ceil(ticket), "case {case}: no ticket released before it was needed");
    }
}

fn interim(part: u64, up: u64, down: u64, charged: u64) -> Receipt {
    Receipt {
        seq: 7,
        released_msat: u64::MAX / 2,
        spent_msat: charged,
        charged,
        status: 101,
        req: "d".into(),
        body_hash: xbt402::ticket::interim_body_hash(part, up, down),
        raw: serde_json::Value::Null,
    }
}

/// A two-way paid stream as the gateway carries one: each chunk paid for before it is written,
/// counted after; an interim receipt signed now and then for `min(paid, price of counted)`; the
/// wallet reading the seller's latest at any moment with its own counts (bytes it sent, bytes
/// that reached it: a little behind the seller's count of what it wrote). `count_up_to`: a seller
/// that stops counting past that many bytes. Returns the receipts' last charge, the true price of
/// every byte, and what the wallet holds.
fn two_way(g: &mut Rng, price: &SellerPrice, head: u64, total: u64, count_up_to: u64) -> (u64, u64, Option<Seen>) {
    let buyer_price = BuyerPrice { tokens: Default::default(), request_msat: head, byte_msat: price.byte_msat, per_bytes: price.per_bytes, second_msat: 0 };
    let step = price.for_bytes(1 << 20).unwrap().max(1);
    let mut meter = Meter::new(*price);
    let (mut up, mut down, mut counted_up, mut counted_down) = (0u64, 0u64, 0u64, 0u64);
    let (mut part, mut signed, mut last_seen) = (0u64, head, None::<Seen>);
    let mut latest: Option<Receipt> = None;
    while up + down < total {
        let n = chunk(g).min(16 << 10).min(total - up - down);
        let from_service = !g.chance(5);
        let due = meter.bytes_due(n).unwrap();
        meter.sent(n, due);
        if from_service {
            down += n;
        } else {
            up += n;
        }
        // counted once written; a seller whose meter stops counts no further
        let counting = |x: u64, done: u64| if done >= count_up_to { 0 } else { x.min(count_up_to - done) };
        if from_service {
            counted_down += counting(n, counted_up + counted_down);
        } else {
            counted_up += counting(n, counted_up + counted_down);
        }
        let paid = head + meter.charged();
        let charged = paid.min(head + price.for_bytes(counted_up + counted_down).unwrap());
        if charged > signed && (charged - signed >= step || g.chance(40)) {
            part += 1;
            signed = charged;
            latest = Some(interim(part, counted_up, counted_down, charged));
        }
        // the wallet polls now and then: it has sent every up byte, and received the down bytes
        // but for a few chunks still on their way
        if g.chance(25) {
            if let Some(r) = &latest {
                let on_the_way = g.range(0, 4) * (16 << 10);
                let own_down = down.saturating_sub(on_the_way);
                let got = check(r, 7, "d", 101, up, own_down, &buyer_price, u64::MAX, &mut last_seen);
                assert!(got.is_ok(), "an honest count was taken for a fault: {got:?}");
                if let (Ok(true), Some(s)) = (&got, &last_seen) {
                    assert!(s.charged <= head + price.for_bytes(up + down).unwrap() + price.for_bytes(32 << 10).unwrap());
                }
            }
        }
    }
    let last = head + price.for_bytes(counted_up + counted_down).unwrap().min(meter.charged());
    // the wallet's view at the end, its counts all in
    let final_r = interim(part + 1, counted_up, counted_down, last);
    if last > signed {
        assert!(check(&final_r, 7, "d", 101, up, down, &buyer_price, u64::MAX, &mut last_seen).is_ok());
    }
    (last, head + price.for_bytes(up + down).unwrap(), last_seen)
}

#[test]
fn an_honest_sellers_interim_receipts_signed_at_any_moment_are_taken_and_the_last_is_the_price_of_every_byte() {
    let mut g = Rng(SEED ^ 3);
    for case in 0..CASES / 4 {
        let per_bytes = [1024, 1 << 20, 1 << 30][g.range(0, 2) as usize];
        let price = SellerPrice { request_msat: 0, byte_msat: g.range(1, 600_000_000.min(per_bytes * 1000)), per_bytes, second_msat: 0, tokens: Default::default() };
        let head = g.range(0, 5_000);
        let total = g.range(1 << 20, 24 << 20);
        let (last, truth, _) = two_way(&mut g, &price, head, total, u64::MAX);
        assert_eq!(last, truth, "case {case}: the last count is every byte at the listed price");
    }
}

/// The VPN shortfall's shape (a seller whose meter stops counting after about 1 MiB): the wallet's
/// interim check takes it, since a seller counting too little charges the buyer less, not more;
/// only the charge set against usage times the listed price finds it, which is what the lab's vpn
/// check asserts.
#[test]
fn a_seller_that_stops_counting_is_no_fault_to_the_interim_check_and_usage_times_price_finds_it() {
    let mut g = Rng(SEED ^ 4);
    let price = SellerPrice { request_msat: 0, byte_msat: 500_000_000, per_bytes: 1 << 30, second_msat: 0, tokens: Default::default() };
    // two_way asserts every poll of the wallet's check was no fault
    let (last, truth, seen) = two_way(&mut g, &price, 0, 64 << 20, 1 << 20);
    assert!(seen.is_some(), "the wallet took the seller's count");
    assert!(last < truth / 10, "charged {last}, while every byte at the listed price costs {truth}");
}
