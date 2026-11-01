//! How a slice is paid: Lightning Stream's held tickets, one per slice.
//!
//! The hashtaker makes each ticket's preimage and sends its payment hash (`lock`) before the slice
//! is mined; the hashmaker's node holds the hashtaker's payment to that hash (a hold invoice) without
//! being able to settle it. When the slice is done the hashtaker releases the preimage (`pay`) and
//! the hashmaker settles. A ticket never released is cancelled and its payment returns to the hashtaker.
//! So the hashtaker risks at most the slice in progress and the hashmaker at most the work done past
//! the last released ticket.
//!
//! [`HashtakerRail`] and [`SellerRail`] are where the wallet's ticket machinery plugs in: the hashtaker's
//! signer pays the hold invoice for each locked hash under the wallet's policy and budgets (a
//! "hashrate" task), and the hashmaker's node makes and settles the hold invoices. [`LabHashtaker`] and
//! [`LabSeller`] stand in for both in the lab: they check the preimages and keep a ledger, and
//! move no money.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub type Hash = [u8; 32];

pub fn sha256(b: &[u8]) -> Hash {
    Sha256::digest(b).into()
}

pub trait HashtakerRail: Send {
    /// Lock the ticket for `slice` at `price_msat`: returns its payment hash. (For a real ticket,
    /// the signer pays the hashmaker's hold invoice for this hash before returning.)
    fn lock(&mut self, slice: u64, price_msat: u64) -> Result<Hash, String>;
    /// Release the ticket for a finished slice: returns its preimage.
    fn release(&mut self, slice: u64) -> Result<[u8; 32], String>;
    /// Give up a ticket never released (its held payment goes back to the hashtaker).
    fn cancel(&mut self, slice: u64);
}

pub trait SellerRail: Send {
    /// Is the hashtaker's payment to `hash` held by the hashmaker's node?
    fn held(&mut self, slice: u64, hash: &Hash, price_msat: u64) -> bool;
    /// Settle a released ticket. `preimage` has already been checked against the hash.
    fn settle(&mut self, slice: u64, preimage: &[u8; 32]) -> Result<(), String>;
}

/// The lab's hashtaker: fresh preimages, a ledger of locks, releases and cancels.
#[derive(Default)]
pub struct LabHashtaker {
    pre: BTreeMap<u64, [u8; 32]>,
    pub locked_msat: u64,
    pub released_msat: u64,
    pub cancelled_msat: u64,
    price: BTreeMap<u64, u64>,
}

impl HashtakerRail for LabHashtaker {
    fn lock(&mut self, slice: u64, price_msat: u64) -> Result<Hash, String> {
        let mut p = [0u8; 32];
        getrandom::getrandom(&mut p).map_err(|e| e.to_string())?;
        self.pre.insert(slice, p);
        self.price.insert(slice, price_msat);
        self.locked_msat += price_msat;
        Ok(sha256(&p))
    }

    fn release(&mut self, slice: u64) -> Result<[u8; 32], String> {
        let p = self.pre.remove(&slice).ok_or("no ticket locked for that slice")?;
        self.released_msat += self.price.remove(&slice).unwrap_or(0);
        Ok(p)
    }

    fn cancel(&mut self, slice: u64) {
        if self.pre.remove(&slice).is_some() {
            self.cancelled_msat += self.price.remove(&slice).unwrap_or(0);
        }
    }
}

/// The hashtaker's slices paid through the wallet: each finished slice is one paid request to the
/// hashmaker's gateway (`POST <url>/<rental>/<slice>`, the signed work receipt as the body), made by
/// the wallet's signer with `xbt402_pay`. The signer keeps the owner's policy (the task's budget,
/// the seller tied to its node, the caps on locked funds), chooses the rail (held tickets, else
/// prepaid ones), locks tickets ahead and releases them; the gateway charges the slice's price
/// only when the hashmaker's app answers that it counted the slice. Nothing here holds a key.
/// A ticket is a whole payment that cannot be recalled, so tickets are sized to the step the rental has
/// earned ([`crate::order`], [`SignerPayer::caps_for`]).
///
/// The `price_ceiling` of a rental at `price_msat` a slice: the offer's price per slice and nothing by
/// the byte, second or token (a slice's answer is priced by the request alone).
pub fn slice_ceiling(price_msat: u64) -> serde_json::Value {
    // the fields of xbt402::listing::price_ceiling, every one named: none left to mean "any"
    serde_json::json!({"request_msat": price_msat, "gib_msat": 0, "second_msat": 0, "input_per_1k_msat": 0, "output_per_1k_msat": 0})
}

pub struct SignerPayer {
    pub sock: std::path::PathBuf,
    pub url: String,
    pub task: String,
    price_msat: u64,
    /// What may leave the wallet for the next slice's payment: set by [`SignerPayer::caps_for`].
    pub max_sats: u64,
    /// The most that payment may be charged, which is also the ticket the wallet asks a shop for
    /// where it lets the wallet choose ([`caps_at`]). A slice is never charged more than its price
    /// whatever this says: the signer holds a receipt to the route's price, and `ceiling` holds the
    /// route's price to the offer.
    pub max_charge_sats: Option<u64>,
    /// The rental's budget: tickets are sized inside what is left of it.
    pub budget_sats: Option<u64>,
    /// The most any one payment may move, however large a step is earned (`--max-sats`).
    pub most_sats: Option<u64>,
    /// What this rental's slices were charged, and the credit the shop holds by its last answer:
    /// with the budget, what the next ticket may come to.
    charged_msat: u64,
    credit_msat: u64,
    pub session: Option<String>,
    /// The most the hashmaker's signed offer said a slice costs, as the wallet's `price_ceiling`: a
    /// shop whose terms ask more than the offer it was rented from is paid nothing.
    pub ceiling: Option<serde_json::Value>,
    /// How long a slice's payment waits for a signer whose socket is not there (a wallet that
    /// starts again): within the hashmaker's grace, so the slice is still paid in time.
    pub wait_for_signer: std::time::Duration,
}

/// The start of a refused payment's reason where a shop sells nothing small enough for what may leave
/// the wallet now. The wallet's Hashrate page shows reasons that start with these as they stand.
pub const BIG_TICKETS_ONLY: &str = "This hashmaker's smallest ticket is";
/// Where what is left of the rental's budget is less than the shop's smallest ticket.
pub const BUDGET_TOO_SHORT: &str = "What is left of this rental's budget";
/// Where one of the owner's rules refused the payment.
pub const WALLET_RULES: &str = "Your wallet's rules stopped this payment";
/// Where the wallet refused the rental's terms to this connection (`ticket_rental_payer`, `ticket_rental_route`): a
/// renter set up by hand on the wallet's own socket, or on a route that isn't a rental's piece of work. No limit
/// of the owner's is at issue, so the words don't send the owner to the rules page.
pub const RENTER_SOCKET: &str = "The wallet pays a rental only through the renter's own connection";

/// Whether a refusal left everything where it was: nothing booked for the call and nothing released.
fn moved_nothing(v: &serde_json::Value) -> bool {
    let none = |k: &str| v.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0) == 0;
    none("charged_sats") && none("tickets_released")
}

/// The rules of the owner's that can refuse a slice's payment.
const WALLET_RULE_NAMES: [&str; 11] = ["ticket_cap", "ticket_task_budget", "ticket_seller_cap", "ticket_rate_limit", "daily_budget", "weekly_budget", "per_counterparty",
                                       "per_counterparty_daily", "max_per_tx", "human_threshold", "velocity"];
/// The wallet's refusals of the rental's terms to a connection or a route that isn't the renter's ([`RENTER_SOCKET`]).
const RENTER_SOCKET_RULES: [&str; 2] = ["ticket_rental_payer", "ticket_rental_route"];

/// Room for a ticket's routing-fee limit, in sats, by the wallet's default limit (10 sat and 0.5%:
/// `xbt_signer::ln::LnPolicy`). An owner who raised that limit is told so by the signer's refusal.
fn fee_room_sats(ticket_sats: u64) -> u64 {
    10u64.saturating_add(ticket_sats.div_ceil(200))
}

/// What may leave the wallet for a payment and what it may be charged (`max_sats`,
/// `max_charge_sats`), for a ticket of `ticket_msat` ([`crate::order::Standing::ticket_msat`] says what
/// is worth buying), `left_msat` of the rental's budget not yet charged or held as credit, and
/// `most_sats` the most one payment may move.
///
/// The charge cap is the ticket the signer sizes to; it is never below a slice, which the rental's
/// own count pays only when the budget has it. `max_sats` is that and its routing-fee room, so
/// the budget bounds the tickets and routing fees come on top of it, as they always did. A price of
/// nothing sets no charge cap: the wallet takes none of 0, and its price ceiling refuses any price.
pub fn caps_at(ticket_msat: u64, price_msat: u64, left_msat: Option<u64>, most_sats: Option<u64>) -> (u64, Option<u64>) {
    let price = price_msat.div_ceil(1000);
    let most = most_sats.unwrap_or(u64::MAX);
    if price == 0 {
        return (fee_room_sats(0).min(most), None);
    }
    let left = left_msat.map_or(u64::MAX, |m| m / 1000);
    let ticket = ticket_msat.div_ceil(1000).min(left).max(price);
    (ticket.saturating_add(fee_room_sats(ticket)).min(most), Some(ticket.min(most)))
}

/// Whether a failed [`signer_call`] never reached the signer: its socket was missing or refused
/// the connection, so nothing was asked and the call may be made again without asking twice.
pub fn signer_unreached(why: &str) -> bool {
    why.starts_with("signer socket ")
}

/// One call on the signer's socket.
pub fn signer_call(sock: &std::path::Path, method: &str, params: &serde_json::Value) -> Result<serde_json::Value, String> {
    use std::io::{BufRead, BufReader, Write};
    let mut s = std::os::unix::net::UnixStream::connect(sock).map_err(|e| format!("signer socket {}: {e}", sock.display()))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(200))).map_err(|e| e.to_string())?;
    let req = serde_json::json!({"id": 1, "method": method, "params": params});
    s.write_all(format!("{req}\n").as_bytes()).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).map_err(|e| format!("signer: {e}"))?;
    let v: serde_json::Value = serde_json::from_str(&line).map_err(|_| "signer: not JSON".to_string())?;
    match v.get("error").filter(|e| !e.is_null()) {
        Some(e) => Err(format!("signer: {e}")),
        None => Ok(v.get("result").cloned().unwrap_or_default()),
    }
}

impl SignerPayer {
    /// A payer for a rental at `price_msat` a slice, its caps those of the first step until
    /// [`SignerPayer::caps_for`] says otherwise. The offer's price is its ceiling. `budget_sats`,
    /// `most_sats`: [`SignerPayer`].
    pub fn new(sock: std::path::PathBuf, url: String, task: String, price_msat: u64, budget_sats: Option<u64>, most_sats: Option<u64>,
               wait_for_signer: std::time::Duration) -> Self {
        let mut p = Self { sock, url, task, price_msat, max_sats: 0, max_charge_sats: None, budget_sats, most_sats, charged_msat: 0, credit_msat: 0, session: None,
                           ceiling: Some(slice_ceiling(price_msat)), wait_for_signer };
        p.caps_for(crate::order::FIRST_STEP_MSAT);
        p
    }

    /// What the rental's budget has left, in msat, by what its slices were charged and what the shop holds.
    fn left_msat(&self) -> Option<u64> {
        self.budget_sats.map(|b| b.saturating_mul(1000).saturating_sub(self.charged_msat).saturating_sub(self.credit_msat))
    }

    /// Set what the next [`SignerPayer::pay`] may move and be charged, for a ticket of `ticket_msat`
    /// ([`crate::order::Standing::ticket_msat`]), the budget still the ceiling. Call it before each
    /// payment. Never called, a rental stays on tickets of the first step.
    pub fn caps_for(&mut self, ticket_msat: u64) {
        (self.max_sats, self.max_charge_sats) = caps_at(ticket_msat, self.price_msat, self.left_msat(), self.most_sats);
    }

    /// Pay one slice. `Ok` carries what the signer said (without the seller's body); `Err` why not.
    pub fn pay(&mut self, rental: &str, slice: u64, receipt: &serde_json::Value) -> Result<serde_json::Value, String> {
        let mut params = serde_json::json!({
            "url": format!("{}/{rental}/{slice}", self.url.trim_end_matches('/')), "method": "POST",
            "body": receipt.to_string(), "max_sats": self.max_sats, "task": self.task,
        });
        if let Some(c) = &self.ceiling {
            params["price_ceiling"] = c.clone();
        }
        if let Some(c) = self.max_charge_sats {
            params["max_charge_sats"] = c.into();
        }
        // a signer that is starting again is waited for, with growing pauses, as long as the call never
        // reached it: a call that reached it is never made a second time
        let start = std::time::Instant::now();
        let mut pause = std::time::Duration::from_millis(250);
        let mut asked_again = false;
        let mut r = loop {
            match signer_call(&self.sock, "xbt402_pay", &params) {
                Err(why) if signer_unreached(&why) && start.elapsed() + pause < self.wait_for_signer => {
                    std::thread::sleep(pause);
                    pause = (pause * 2).min(std::time::Duration::from_secs(4));
                }
                // the seller forgot a session with nothing in it (a slice longer than its idle limit, with the wallet's
                // watcher away): nothing was released or booked, and the next call opens another
                Ok(v) if !asked_again && v.get("rule").and_then(serde_json::Value::as_str) == Some("ticket_session_ended") && moved_nothing(&v) => asked_again = true,
                other => break other?,
            }
        };
        if let Some(o) = r.as_object_mut() {
            o.remove("untrusted_provider_response");
        }
        if let Some(s) = r.get("session").and_then(serde_json::Value::as_str) {
            self.session = Some(s.to_string());
        }
        let paid = r.get("status").and_then(serde_json::Value::as_u64) == Some(200) && r.get("verdict").and_then(serde_json::Value::as_str) == Some("allow");
        if paid {
            let msat = |k: &str| r.get(k).and_then(serde_json::Value::as_str).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            self.charged_msat = self.charged_msat.saturating_add(msat("price_msat"));
            self.credit_msat = msat("balance_msat");
            return Ok(r);
        }
        // what the signer says to a caller that could ask again with more is no use to a renter
        let rule = r.get("rule").and_then(serde_json::Value::as_str).unwrap_or("");
        let face = r.get("ticket_sats").and_then(serde_json::Value::as_u64);
        match (rule, face) {
            ("max_sats", Some(face)) if moved_nothing(&r) => {
                let left = self.left_msat().map(|m| m / 1000);
                Err(match left.filter(|l| *l < face) {
                    Some(left) => format!("{BUDGET_TOO_SHORT} ({left} sats) is less than this hashmaker's smallest ticket ({face} sats). Nothing was paid for this piece of work."),
                    None => format!("{BIG_TICKETS_ONLY} {face} sats, and {} sats may leave your wallet for this payment. Nothing was paid for this piece of work. \
                                     Rent from a hashmaker that sells smaller tickets, or ask this one to update its app.", self.max_sats),
                })
            }
            (rule, _) if WALLET_RULE_NAMES.contains(&rule) => {
                let why = r.get("reason").and_then(serde_json::Value::as_str).unwrap_or(rule);
                Err(format!("{WALLET_RULES}: {why}. Nothing more was paid. Your limits are on the wallet's rules page."))
            }
            (rule, _) if RENTER_SOCKET_RULES.contains(&rule) => {
                let why = r.get("reason").and_then(serde_json::Value::as_str).unwrap_or(rule);
                Err(format!("{RENTER_SOCKET}: {why}. The app's renter is set up that way; a renter set up by hand needs the wallet's renter socket \
                             (run/rental/signer.sock, B2_RENTAL_SOCK), and an app whose parts are of different versions needs updating."))
            }
            _ => Err(r.to_string()),
        }
    }

    /// End the wallet's session with the hashmaker's gateway: its unused tickets are cancelled.
    pub fn stop(&mut self) -> Option<serde_json::Value> {
        let s = self.session.take()?;
        Some(signer_call(&self.sock, "ticket_stop", &serde_json::json!({"session": s})).unwrap_or_else(|e| serde_json::json!({"error": e})))
    }
}

/// What pays a rental's slices, one at a time, off the relay's path: the wallet's signer ([`SignerPayer`]), or a test's.
pub trait Payer: Send {
    /// The ticket the next payment may buy ([`crate::order::Standing::ticket_msat`]).
    fn caps_for(&mut self, ticket_msat: u64);
    /// Pay one slice: `Ok` with what the wallet said (`charged_sats` above 0 when it bought a ticket), `Err` why not.
    fn pay(&mut self, rental: &str, slice: u64, receipt: &serde_json::Value) -> Result<serde_json::Value, String>;
    /// End the wallet's session with the seller.
    fn stop(&mut self) -> Option<serde_json::Value>;
}

impl Payer for SignerPayer {
    fn caps_for(&mut self, ticket_msat: u64) {
        SignerPayer::caps_for(self, ticket_msat)
    }

    fn pay(&mut self, rental: &str, slice: u64, receipt: &serde_json::Value) -> Result<serde_json::Value, String> {
        SignerPayer::pay(self, rental, slice, receipt)
    }

    fn stop(&mut self) -> Option<serde_json::Value> {
        SignerPayer::stop(self)
    }
}

/// The lab's seller: every lock is held; settles are counted.
#[derive(Default)]
pub struct LabSeller {
    pub settled_msat: u64,
    pub settled: u64,
    price: BTreeMap<u64, u64>,
}

impl SellerRail for LabSeller {
    fn held(&mut self, slice: u64, _hash: &Hash, price_msat: u64) -> bool {
        self.price.insert(slice, price_msat);
        true
    }

    fn settle(&mut self, slice: u64, _preimage: &[u8; 32]) -> Result<(), String> {
        self.settled_msat += self.price.remove(&slice).ok_or("settle of a ticket never held")?;
        self.settled += 1;
        Ok(())
    }
}

#[cfg(test)]
mod signer_wait_tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::time::{Duration, Instant};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("xbt-hashlink-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A signer that is starting again (its socket not there yet) is waited for: the slice is
    /// paid once it is back, and asked of it exactly once.
    #[test]
    fn a_slice_waits_for_a_signer_that_starts_again_and_is_asked_once() {
        let dir = scratch("wait");
        let sock = dir.join("signer.sock");
        let asked = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (s2, a2) = (sock.clone(), asked.clone());
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(1500));
            let l = UnixListener::bind(&s2).unwrap();
            for c in l.incoming() {
                let Ok(c) = c else { continue };
                let mut line = String::new();
                BufReader::new(c.try_clone().unwrap()).read_line(&mut line).unwrap();
                a2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut w = c;
                writeln!(w, "{}", serde_json::json!({"id": 1, "result": {"verdict": "allow", "status": 200, "session": "s1"}})).unwrap();
            }
        });
        let mut p = SignerPayer::new(sock, "https://x/hashrate".into(), "hashrate".into(), 5_000, None, None, Duration::from_secs(10));
        let t0 = Instant::now();
        let r = p.pay("r1", 0, &serde_json::json!({}));
        assert!(r.is_ok(), "{r:?}");
        assert!(t0.elapsed() >= Duration::from_millis(1400));
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// A stand-in signer that answers every call with what `answer` holds, and counts the calls.
    fn answering(sock: &std::path::Path, answer: serde_json::Value) -> (std::sync::Arc<std::sync::Mutex<serde_json::Value>>, std::sync::Arc<std::sync::Mutex<serde_json::Value>>) {
        let l = UnixListener::bind(sock).unwrap();
        let (a, seen) = (std::sync::Arc::new(std::sync::Mutex::new(answer)), std::sync::Arc::new(std::sync::Mutex::new(serde_json::Value::Null)));
        let (a2, s2) = (a.clone(), seen.clone());
        std::thread::spawn(move || {
            for c in l.incoming() {
                let Ok(c) = c else { continue };
                let mut line = String::new();
                BufReader::new(c.try_clone().unwrap()).read_line(&mut line).unwrap();
                *s2.lock().unwrap() = serde_json::from_str(&line).unwrap();
                let mut w = c;
                writeln!(w, "{}", serde_json::json!({"id": 1, "result": *a2.lock().unwrap()})).unwrap();
            }
        });
        (a, seen)
    }

    /// The offer's price per slice goes with each payment as the wallet's `price_ceiling`, so a
    /// shop whose terms ask more than the offer it was rented from is refused before it is paid;
    /// and the caps of the step go with it.
    #[test]
    fn each_slice_is_paid_with_the_offers_price_as_its_ceiling_and_the_steps_caps() {
        let dir = scratch("ceiling");
        let sock = dir.join("signer.sock");
        let (_, seen) = answering(&sock, serde_json::json!({"verdict": "deny", "rule": "price_ceiling"}));
        let mut p = SignerPayer::new(sock, "https://x/hashrate".into(), "hashrate".into(), 404_250, Some(200_000), None, Duration::from_secs(2));
        let _ = p.pay("r1", 0, &serde_json::json!({}));
        let v = seen.lock().unwrap().clone();
        assert_eq!(v["params"]["price_ceiling"]["request_msat"], 404_250, "{v}");
        assert_eq!((v["params"]["max_sats"].as_u64(), v["params"]["max_charge_sats"].as_u64()), (Some(546 + 13), Some(546)), "the first step, its fee room beside it: {v}");
        p.caps_for(1_377_000);
        let _ = p.pay("r1", 0, &serde_json::json!({}));
        let v = seen.lock().unwrap().clone();
        assert_eq!((v["params"]["max_sats"].as_u64(), v["params"]["max_charge_sats"].as_u64()), (Some(1_377 + 17), Some(1_377)), "{v}");
    }

    #[test]
    fn caps_come_from_the_ticket_inside_the_budget_and_never_below_a_slice() {
        const P: u64 = 404_250;
        assert_eq!(caps_at(546_000, P, None, None), (559, Some(546)));
        assert_eq!(caps_at(34_440_000, P, None, None), (34_440 + 183, Some(34_440)));
        // a part of a sat rounds up: the charge cap holds the slice's price
        assert_eq!(caps_at(1_000, P, None, None).1, Some(405));
        // the budget: the ticket is what is left of it
        assert_eq!(caps_at(1_377_000, P, Some(800_000), None), (800 + 14, Some(800)));
        // every ticket inside what is left, once that holds a slice
        for left in (P..3_000_000).step_by(7_001) {
            for t in [546_000, 1_377_000, 34_440_000] {
                assert!(caps_at(t, P, Some(left), None).1.unwrap() * 1000 <= left.max(405_000), "{t} of {left}");
            }
        }
        assert_eq!(caps_at(546_000, P, Some(0), None).1, Some(405), "nothing left: the rental's own count stops it");
        // the most one payment may move holds whatever the step
        assert_eq!(caps_at(34_440_000, P, None, Some(2_000)), (2_000, Some(2_000)));
        // a price of nothing sets no charge cap, which the wallet would refuse as 0
        assert_eq!(caps_at(546_000, 0, None, None), (10, None));
    }

    /// The payer counts what its slices were charged and what the shop holds: with those and the
    /// budget, the next ticket is no more than the rental can use.
    #[test]
    fn the_next_ticket_is_sized_inside_what_the_budget_has_left() {
        let dir = scratch("left");
        let sock = dir.join("signer.sock");
        answering(&sock, serde_json::json!({"verdict": "allow", "status": 200, "price_msat": "404250", "balance_msat": "141750"}));
        let mut p = SignerPayer::new(sock, "https://x/hashrate".into(), "hashrate".into(), 404_250, Some(1_000), None, Duration::from_secs(2));
        p.caps_for(5_000_000);
        assert_eq!(p.max_charge_sats, Some(1_000), "nothing charged yet");
        p.pay("r1", 1, &serde_json::json!({})).unwrap();
        p.caps_for(5_000_000);
        assert_eq!(p.max_charge_sats, Some(454), "404.25 charged, 141.75 held as credit");
    }

    /// Refusals a renter can read: a shop that sells nothing small enough, a budget too short for its
    /// smallest, and one of the owner's rules. Any other stays as the signer gave it.
    #[test]
    fn refusals_read_plainly() {
        let dir = scratch("big");
        let sock = dir.join("signer.sock");
        let (answer, _) = answering(&sock, serde_json::Value::Null);
        let mut p = SignerPayer::new(sock, "https://x/hashrate".into(), "hashrate".into(), 404_250, Some(200_000), None, Duration::from_secs(2));
        *answer.lock().unwrap() = serde_json::json!({"verdict": "deny", "rule": "max_sats", "reason": "call again with max_sats of at least 913", "ticket_sats": 900, "charged_sats": 0});
        let why = p.pay("r1", 1, &serde_json::json!({})).unwrap_err();
        assert!(why.starts_with(BIG_TICKETS_ONLY) && why.contains("900 sats") && why.contains("559 sats") && why.contains("Nothing was paid") && !why.contains("max_sats"), "{why}");
        p.budget_sats = Some(500);
        p.caps_for(546_000);
        let why = p.pay("r1", 1, &serde_json::json!({})).unwrap_err();
        assert!(why.starts_with(BUDGET_TOO_SHORT) && why.contains("500 sats"), "{why}");
        *answer.lock().unwrap() = serde_json::json!({"verdict": "deny", "rule": "ticket_task_budget", "reason": "with this ticket's 559 sats, 5101 would be above the task's budget_sats (5000)", "charged_sats": 0});
        let why = p.pay("r1", 1, &serde_json::json!({})).unwrap_err();
        assert!(why.starts_with(WALLET_RULES) && why.contains("budget_sats (5000)"), "{why}");
        *answer.lock().unwrap() = serde_json::json!({"verdict": "deny", "rule": "price_ceiling", "charged_sats": 0});
        assert!(p.pay("r1", 1, &serde_json::json!({})).unwrap_err().contains("price_ceiling"));
    }

    /// A session the seller forgot is asked again once, and only where nothing moved: not twice, and
    /// not after a release.
    #[test]
    fn a_forgotten_session_is_asked_again_once_where_nothing_moved() {
        let dir = scratch("again");
        let sock = dir.join("signer.sock");
        let l = UnixListener::bind(&sock).unwrap();
        let asked = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let a2 = asked.clone();
        let answer = std::sync::Arc::new(std::sync::Mutex::new(serde_json::json!({"verdict": "deny", "rule": "ticket_session_ended", "charged_sats": 0, "tickets_released": 0})));
        let a3 = answer.clone();
        std::thread::spawn(move || {
            for c in l.incoming() {
                let Ok(c) = c else { continue };
                let mut line = String::new();
                BufReader::new(c.try_clone().unwrap()).read_line(&mut line).unwrap();
                a2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut w = c;
                writeln!(w, "{}", serde_json::json!({"id": 1, "result": *a3.lock().unwrap()})).unwrap();
            }
        });
        let mut p = SignerPayer::new(sock, "https://x/hashrate".into(), "hashrate".into(), 404_250, None, None, Duration::from_secs(2));
        assert!(p.pay("r1", 1, &serde_json::json!({})).is_err());
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 2, "once again, and no more");
        asked.store(0, std::sync::atomic::Ordering::SeqCst);
        *answer.lock().unwrap() = serde_json::json!({"verdict": "deny", "rule": "ticket_session_ended", "charged_sats": 559, "tickets_released": 1});
        assert!(p.pay("r1", 2, &serde_json::json!({})).is_err());
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1, "money moved: never again");
    }

    /// Past the wait, the payment fails plainly: a signer that does not come back is not waited for
    /// beyond the hashmaker's grace.
    #[test]
    fn a_signer_that_does_not_come_back_is_not_waited_for_beyond_the_wait() {
        let dir = scratch("gone");
        let mut p = SignerPayer::new(dir.join("none.sock"), "https://x/hashrate".into(), "hashrate".into(), 5_000, None, None, Duration::from_millis(800));
        let t0 = Instant::now();
        let r = p.pay("r1", 0, &serde_json::json!({}));
        assert!(r.as_ref().is_err_and(|e| signer_unreached(e)), "{r:?}");
        assert!(t0.elapsed() < Duration::from_secs(2));
    }
}
