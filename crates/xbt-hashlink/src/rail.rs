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
    /// What the hashtaker added to that budget while the rental goes on.
    pub added: Option<std::sync::Arc<crate::hashtaker::Added>>,
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
    /// How long a slice's payment keeps asking a signer it could not send the call to (a wallet that
    /// starts again, a socket busy for a moment): within the hashmaker's grace, so the slice is still
    /// paid in time.
    pub wait_for_signer: std::time::Duration,
    /// How long a slice's payment waits for the signer's answer once sent ([`PAY_WAIT`]): the signer bounds the
    /// call itself, and past this one that's stuck is taken as an answer lost.
    pub pay_wait: std::time::Duration,
    /// The call on the signer's socket: [`signer_call_waiting`], or a test's stand-in.
    pub call: SignerCall,
}

/// A call on the signer's socket, as [`signer_call_waiting`] makes it.
pub type SignerCall = fn(&std::path::Path, &str, &serde_json::Value, Option<std::time::Duration>) -> Result<serde_json::Value, (bool, String)>;

/// How long a slice's payment waits for the signer's answer: far past any payment the signer bounds itself, short of
/// a rental hung for good on a signer that's stuck.
pub const PAY_WAIT: std::time::Duration = std::time::Duration::from_secs(600);

/// The start of a refused payment's reason where a shop sells nothing small enough for what may leave
/// the wallet now. The wallet's Hashrate page shows reasons that start with these as they stand.
pub const BIG_TICKETS_ONLY: &str = "This hashmaker's smallest ticket is";
/// Where what is left of the rental's budget is less than the shop's smallest ticket.
pub const BUDGET_TOO_SHORT: &str = "What is left of this rental's budget";
/// Where one of the owner's rules refused the payment.
pub const WALLET_RULES: &str = "Your wallet's rules stopped this payment";
/// Where the wallet refused the rental's terms to this connection (`ticket_rental_payer`): a renter set up by hand
/// on the wallet's own socket, or an app whose parts are of different versions. No limit of the owner's is at
/// issue, so the words don't send the owner to the rules page.
pub const RENTER_SOCKET: &str = "The wallet pays a rental only through the renter's own connection";
/// Where the renter's own socket refused what the renter asked of it (`ticket_rental_route`): a payment that isn't
/// a piece of work of its rental (`POST <pay url>/hashrate/<rental>/<slice>`), or a stop without a session.
pub const RENTER_ROUTE: &str = "The renter asked to pay something that isn't a piece of work of its rental";

/// Whether a refusal left everything where it was: nothing booked for the call and nothing released.
fn moved_nothing(v: &serde_json::Value) -> bool {
    let none = |k: &str| v.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0) == 0;
    none("charged_sats") && none("tickets_released")
}

/// The rules of the owner's that can refuse a slice's payment.
const WALLET_RULE_NAMES: [&str; 11] = ["ticket_cap", "ticket_task_budget", "ticket_seller_cap", "ticket_rate_limit", "daily_budget", "weekly_budget", "per_counterparty",
                                       "per_counterparty_daily", "max_per_tx", "human_threshold", "velocity"];

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

/// How long any signer call but a paying one waits for its answer.
pub const SIGNER_WAIT: std::time::Duration = std::time::Duration::from_secs(200);

/// How long writing a call to the signer may block. A call is a few hundred bytes and a working signer reads it at
/// once; a socket that takes none of it for this long is busy, and a payment asks again on a new connection
/// ([`SignerPayer::pay`]) well within its `wait_for_signer`. Waited for as long as [`SIGNER_WAIT`], the one `EAGAIN`
/// would come only after the hashmaker's grace was gone, too late to ask again.
pub const SIGNER_WRITE_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// One call on the signer's socket.
pub fn signer_call(sock: &std::path::Path, method: &str, params: &serde_json::Value) -> Result<serde_json::Value, String> {
    signer_call_waiting(sock, method, params, Some(SIGNER_WAIT)).map_err(|(_, e)| e)
}

/// [`signer_call`], its answer waited for `answer_wait` (`None`: as long as the signer takes). The error says whether
/// the call had been sent: an answer lost after that leaves the call's effect unknown.
pub fn signer_call_waiting(sock: &std::path::Path, method: &str, params: &serde_json::Value, answer_wait: Option<std::time::Duration>)
                           -> Result<serde_json::Value, (bool, String)> {
    use std::io::{BufRead, BufReader};
    let mut s = std::os::unix::net::UnixStream::connect(sock).map_err(|e| (false, format!("signer socket {}: {e}", sock.display())))?;
    s.set_write_timeout(Some(SIGNER_WRITE_WAIT)).map_err(|e| (false, e.to_string()))?;
    let req = serde_json::json!({"id": 1, "method": method, "params": params});
    send_request(&mut s, format!("{req}\n").as_bytes())?;
    s.set_read_timeout(answer_wait).map_err(|e| (true, e.to_string()))?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).map_err(|e| (true, format!("signer: {e}")))?;
    if line.trim().is_empty() {
        return Err((true, "signer: closed without an answer".into()));
    }
    let v: serde_json::Value = serde_json::from_str(&line).map_err(|_| (true, "signer: not JSON".to_string()))?;
    match v.get("error").filter(|e| !e.is_null()) {
        Some(e) => Err((true, format!("signer error: {e}"))),
        None => Ok(v.get("result").cloned().unwrap_or_default()),
    }
}

/// Write a call to the signer. It was sent once any of it is out: the signer may have read it whole. A write that
/// fails before that (the socket busy for a moment, `EAGAIN`, or gone) asked nothing, and may be made again.
fn send_request(w: &mut impl std::io::Write, buf: &[u8]) -> Result<(), (bool, String)> {
    let mut out = 0;
    while out < buf.len() {
        match w.write(&buf[out..]) {
            Ok(0) => return Err((out > 0, "signer: closed before the call was written".into())),
            Ok(n) => out += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err((out > 0, e.to_string())),
        }
    }
    Ok(())
}

impl SignerPayer {
    /// A payer for a rental at `price_msat` a slice, its caps those of the first step until
    /// [`SignerPayer::caps_for`] says otherwise. The offer's price is its ceiling. `budget_sats`,
    /// `most_sats`: [`SignerPayer`].
    pub fn new(sock: std::path::PathBuf, url: String, task: String, price_msat: u64, budget_sats: Option<u64>, most_sats: Option<u64>,
               wait_for_signer: std::time::Duration) -> Self {
        let mut p = Self { sock, url, task, price_msat, max_sats: 0, max_charge_sats: None, budget_sats, added: None, most_sats, charged_msat: 0, credit_msat: 0, session: None,
                           ceiling: Some(slice_ceiling(price_msat)), wait_for_signer, pay_wait: PAY_WAIT, call: signer_call_waiting };
        p.caps_for(crate::order::FIRST_STEP_MSAT);
        p
    }

    /// What the rental's budget has left, in msat, by what its slices were charged and what the shop holds.
    fn left_msat(&self) -> Option<u64> {
        let added = self.added.as_ref().map_or(0, |a| a.msat());
        self.budget_sats.map(|b| b.saturating_mul(1000).saturating_add(added).saturating_sub(self.charged_msat).saturating_sub(self.credit_msat))
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
        // a signer that is starting again, or whose socket could not take the call for a moment, is asked again, with
        // growing pauses, as long as the call never reached it: a call that reached it is never made a second time
        let start = std::time::Instant::now();
        let mut pause = std::time::Duration::from_millis(250);
        let mut asked_again = false;
        let mut r = loop {
            // the signer answers once the slice is paid, and bounds the call itself: its answer is waited for as long as
            // it takes. One lost after the call was sent leaves the payment unknown: never paid again, never said unpaid
            let called = match (self.call)(&self.sock, "xbt402_pay", &params, Some(self.pay_wait)) {
                Err((true, why)) if !why.starts_with("signer error:") => return Ok(self.lost_answer(&why)),
                other => other,
            };
            match called {
                Err((false, _)) if start.elapsed() + pause < self.wait_for_signer => {
                    std::thread::sleep(pause);
                    pause = (pause * 2).min(std::time::Duration::from_secs(4));
                }
                // the seller forgot a session with nothing in it (a slice longer than its idle limit, with the wallet's
                // watcher away): nothing was released or booked, and the next call opens another
                Ok(v) if !asked_again && v.get("rule").and_then(serde_json::Value::as_str) == Some("ticket_session_ended") && moved_nothing(&v) => asked_again = true,
                other => break other.map_err(|(_, e)| e)?,
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
            // (a stop without a session is refused the same way, but a stop's answer is never read as a payment's)
            ("ticket_rental_route", _) => Err(format!("{RENTER_ROUTE} (POST <pay url>/hashrate/<rental>/<slice>): nothing was paid.")),
            ("ticket_rental_payer", _) => {
                let why = r.get("reason").and_then(serde_json::Value::as_str).unwrap_or("ticket_rental_payer");
                Err(format!("{RENTER_SOCKET}: {why}. The app's own renter pays that way; a renter set up by hand needs the wallet's renter socket \
                             (run/rental/signer.sock, B2_RENTAL_SOCK), and an app whose parts are of different versions needs updating."))
            }
            _ => Err(r.to_string()),
        }
    }

    /// A payment whose answer was lost after it was sent: it may have been paid, in part or in full. The wallet's
    /// session is looked at for the credit it holds now; the slice is neither paid again nor called unpaid here (the
    /// hashmaker knows whether it arrived, and ends the rental if it didn't).
    fn lost_answer(&mut self, why: &str) -> serde_json::Value {
        let status = self.session.clone().and_then(|s| signer_call(&self.sock, "ticket_status", &serde_json::json!({"session": s})).ok());
        // the wallet's own count of what this session's seller holds: its entry in `paying`
        let mine = status.as_ref().and_then(|v| v.get("paying")).and_then(serde_json::Value::as_array)
            .and_then(|p| p.iter().find(|e| e.get("session").and_then(serde_json::Value::as_str) == self.session.as_deref()));
        if let Some(b) = mine.and_then(|e| e.get("balance_msat")).and_then(serde_json::Value::as_str).and_then(|s| s.parse::<u64>().ok()) {
            self.credit_msat = b;
        }
        // it may have been charged: counted as if it was, so what the budget has left is never overstated
        self.charged_msat = self.charged_msat.saturating_add(self.price_msat);
        serde_json::json!({"verdict": "unknown", "rule": "signer_no_answer", "request_sent": true, "charged_sats": 0,
                           "reason": format!("the wallet's signer took the payment and its answer was lost ({why}): it may have paid"),
                           "ticket_status": status})
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
    /// The credit the seller holds for this rental and what is left of its budget, both in msat, as the wallet last
    /// said. The renter sizes each ticket, and pays ahead, by it: a payer that kept no credit says 0.
    fn held(&self) -> (u64, Option<u64>);
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

    fn held(&self) -> (u64, Option<u64>) {
        (self.credit_msat, self.left_msat())
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

    /// A fake signer that answers each call as `answer` says for its method, in order: `Some(v)` after `delay`, `None`
    /// read and closed without an answer. The methods it was asked for are kept.
    fn scripted(sock: &std::path::Path, delay: Duration, mut answers: Vec<(&'static str, Option<serde_json::Value>)>)
                -> std::sync::Arc<std::sync::Mutex<Vec<String>>> {
        let l = UnixListener::bind(sock).unwrap();
        let seen: std::sync::Arc<std::sync::Mutex<Vec<String>>> = std::sync::Arc::default();
        let s2 = seen.clone();
        answers.reverse();
        std::thread::spawn(move || {
            for c in l.incoming() {
                let Ok(c) = c else { continue };
                let mut line = String::new();
                BufReader::new(c.try_clone().unwrap()).read_line(&mut line).unwrap();
                let req: serde_json::Value = serde_json::from_str(&line).unwrap();
                let method = req["method"].as_str().unwrap_or("").to_string();
                s2.lock().unwrap().push(method.clone());
                let Some((want, answer)) = answers.pop() else { continue };
                assert_eq!(want, method);
                std::thread::sleep(delay);
                if let Some(a) = answer {
                    let mut w = c;
                    let _ = writeln!(w, "{}", serde_json::json!({"id": 1, "result": a}));
                }
            }
        });
        seen
    }

    /// A slice's payment waits for the signer as long as it works: past the time any other call waits.
    #[test]
    fn a_slice_payment_waits_for_a_slow_signer() {
        let dir = scratch("slow");
        let sock = dir.join("signer.sock");
        let paid = serde_json::json!({"verdict": "allow", "status": 200, "price_msat": "404250", "balance_msat": "141750", "session": "s1"});
        let seen = scripted(&sock, Duration::from_millis(1500), vec![("xbt402_pay", Some(paid.clone())), ("xbt402_pay", Some(paid))]);
        // a call that waits a second for its answer gives up on this signer
        let e = signer_call_waiting(&sock, "xbt402_pay", &serde_json::json!({}), Some(Duration::from_secs(1))).unwrap_err();
        assert!(e.0, "it was sent: {e:?}");
        // the payment waits for it
        let mut p = SignerPayer::new(sock, "https://x/hashrate".into(), "hashrate".into(), 404_250, None, None, Duration::from_secs(2));
        let v = p.pay("r1", 1, &serde_json::json!({})).unwrap();
        assert_eq!(v["verdict"], "allow", "{v}");
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    /// A signer that takes the payment and never answers doesn't hang the rental: past the payment's wait it's taken
    /// as an answer lost, and the session is looked at as for one.
    #[test]
    fn a_payment_to_a_stuck_signer_ends_as_unknown_after_its_wait() {
        let dir = scratch("stuck");
        let sock = dir.join("signer.sock");
        let l = UnixListener::bind(&sock).unwrap();
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            for c in l.incoming() {
                let Ok(c) = c else { continue };
                let mut line = String::new();
                BufReader::new(c.try_clone().unwrap()).read_line(&mut line).unwrap();
                // the payment is held open, unanswered; anything else is answered
                if line.contains("xbt402_pay") {
                    kept.push(c);
                } else {
                    let mut w = c;
                    let _ = writeln!(w, "{}", serde_json::json!({"id": 1, "result": {"paying": []}}));
                }
            }
        });
        let mut p = SignerPayer::new(sock, "https://x/hashrate".into(), "hashrate".into(), 404_250, None, None, Duration::from_secs(2));
        p.pay_wait = Duration::from_secs(1);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(p.pay("r1", 1, &serde_json::json!({})));
        });
        let v = rx.recv_timeout(Duration::from_secs(10)).expect("the payment gave up on the stuck signer").unwrap();
        assert_eq!((v["verdict"].as_str(), v["rule"].as_str()), (Some("unknown"), Some("signer_no_answer")), "{v}");
    }

    /// A payment whose answer is lost after it was sent may have paid: it is said to be unknown, the wallet's session
    /// is looked at for its credit, and it is never paid a second time here.
    #[test]
    fn a_payment_whose_answer_is_lost_is_unknown_and_never_paid_again() {
        let dir = scratch("lost");
        let sock = dir.join("signer.sock");
        let paid = serde_json::json!({"verdict": "allow", "status": 200, "price_msat": "404250", "balance_msat": "141750", "session": "s1"});
        // ticket_status as the signer answers it: each HTTP session's count under `paying`
        let status = serde_json::json!({"paying": [{"session": "other", "balance_msat": "999000"}, {"session": "s1", "balance_msat": "123000", "spent_msat": "808500"}]});
        let seen = scripted(&sock, Duration::ZERO, vec![("xbt402_pay", Some(paid)), ("xbt402_pay", None), ("ticket_status", Some(status))]);
        let mut p = SignerPayer::new(sock, "https://x/hashrate".into(), "hashrate".into(), 404_250, Some(2_000), None, Duration::from_secs(2));
        assert_eq!(p.pay("r1", 1, &serde_json::json!({})).unwrap()["verdict"], "allow");
        let v = p.pay("r1", 2, &serde_json::json!({})).unwrap();
        assert_eq!((v["verdict"].as_str(), v["rule"].as_str(), v["request_sent"].as_bool()), (Some("unknown"), Some("signer_no_answer"), Some(true)), "{v}");
        assert_eq!(*seen.lock().unwrap(), vec!["xbt402_pay", "xbt402_pay", "ticket_status"], "looked at, not paid again");
        // the credit this session's seller holds now, and the slice counted as charged: the budget left is never overstated
        assert_eq!(Payer::held(&p), (123_000, Some(2_000_000 - 2 * 404_250 - 123_000)));
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
        // budget the hashtaker added while the rental goes on counts with the rest
        let added = std::sync::Arc::new(crate::hashtaker::Added::default());
        p.added = Some(added.clone());
        added.msat.store(300_000, std::sync::atomic::Ordering::Relaxed);
        p.caps_for(546_000);
        assert_eq!(p.max_charge_sats, Some(546), "500 + 300 left: the ticket of the step");
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

    /// A writer that fails as a socket does when it can't take a write for a moment, after letting `ok` bytes out.
    struct Busy {
        ok: usize,
        interrupted: bool,
    }

    impl Write for Busy {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if std::mem::take(&mut self.interrupted) {
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            match self.ok.min(b.len()) {
                0 => Err(std::io::Error::from_raw_os_error(11)),
                n => {
                    self.ok -= n;
                    Ok(n)
                }
            }
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A call the socket took none of was not sent, and may be made again; one it took any of may have been read
    /// whole, so it was sent. An interrupted write is written again.
    #[test]
    fn a_call_is_sent_once_any_of_it_is_out() {
        let e = send_request(&mut Busy { ok: 0, interrupted: false }, b"{}\n").unwrap_err();
        assert_eq!(e, (false, "Resource temporarily unavailable (os error 11)".to_string()));
        assert!(send_request(&mut Busy { ok: 2, interrupted: false }, b"{}\n").unwrap_err().0, "part of it out: sent");
        assert!(send_request(&mut Busy { ok: 3, interrupted: true }, b"{}\n").is_ok());
    }

    /// A real socket that takes part of a call and then no more (a signer that accepted it and stopped reading): the
    /// write gives up after [`SIGNER_WRITE_WAIT`] with some of it out, so the call counts as sent. Its payment is an
    /// answer lost (`verdict: "unknown"`), never made again, though the wait for the signer has time left.
    #[test]
    fn a_call_written_in_part_is_never_made_again() {
        let dir = scratch("part");
        let sock = dir.join("signer.sock");
        let l = UnixListener::bind(&sock).unwrap();
        let conns = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let c2 = conns.clone();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                c2.lock().unwrap().push(c); // held open, never read
            }
        });
        let mut p = SignerPayer::new(sock, "https://x/hashrate".into(), "hashrate".into(), 5_000, None, None, Duration::from_secs(60));
        // a body far past any socket buffer, so the write stops part way
        let big = serde_json::json!({"pad": "x".repeat(16 << 20)});
        let t0 = Instant::now();
        let v = p.pay("r1", 1, &big).unwrap();
        assert_eq!(v["verdict"], "unknown", "{v}");
        assert_eq!(v["request_sent"], true, "{v}");
        assert!(t0.elapsed() < SIGNER_WRITE_WAIT * 2 + Duration::from_secs(5), "{:?}", t0.elapsed());
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(conns.lock().unwrap().len(), 1, "the signer was asked once");
    }

    /// A stand-in whose call got out in part and then failed as a busy socket does: sent, so never made again.
    #[test]
    fn a_pay_whose_call_got_out_in_part_is_an_answer_lost_and_asked_once() {
        static TRIES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        fn part_out(_: &std::path::Path, _: &str, _: &serde_json::Value, _: Option<Duration>) -> Result<serde_json::Value, (bool, String)> {
            TRIES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err((true, std::io::Error::from_raw_os_error(11).to_string()))
        }
        let dir = scratch("partstand");
        let mut p = SignerPayer::new(dir.join("signer.sock"), "https://x/hashrate".into(), "hashrate".into(), 5_000, None, None, Duration::from_secs(5));
        p.call = part_out;
        let v = p.pay("r1", 1, &serde_json::json!({})).unwrap();
        assert_eq!((v["verdict"].as_str(), v["request_sent"].as_bool()), (Some("unknown"), Some(true)), "{v}");
        assert_eq!(TRIES.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// The `xbt402_pay`s a stand-in socket fails before any of the call is out (as `EAGAIN` does), by number from 1:
    /// one test's at a time.
    static BUSY_PAYS: std::sync::Mutex<(usize, Vec<usize>)> = std::sync::Mutex::new((0, Vec::new()));

    fn busy_now_and_then(sock: &std::path::Path, method: &str, params: &serde_json::Value, wait: Option<Duration>) -> Result<serde_json::Value, (bool, String)> {
        let mut g = BUSY_PAYS.lock().unwrap_or_else(|p| p.into_inner());
        g.0 += 1;
        if g.1.contains(&g.0) {
            return Err((false, std::io::Error::from_raw_os_error(11).to_string()));
        }
        drop(g);
        signer_call_waiting(sock, method, params, wait)
    }

    /// A socket that could not take the call for a moment (the renter's `EAGAIN`): nothing was asked, so the call is
    /// made again within the wait and the slice is paid, asked of the signer once. One that stays so fails plainly
    /// at the end of the wait, and the signer is never asked.
    #[test]
    fn a_call_the_socket_could_not_take_is_made_again_and_paid_once() {
        let dir = scratch("busy");
        let sock = dir.join("signer.sock");
        let seen = scripted(&sock, Duration::ZERO, vec![("xbt402_pay", Some(serde_json::json!({"verdict": "allow", "status": 200, "session": "s1"})))]);
        let mut p = SignerPayer::new(sock.clone(), "https://x/hashrate".into(), "hashrate".into(), 5_000, None, None, Duration::from_secs(5));
        p.call = busy_now_and_then;
        *BUSY_PAYS.lock().unwrap() = (0, vec![1, 2]);
        let v = p.pay("r1", 1, &serde_json::json!({})).unwrap();
        assert_eq!(v["verdict"], "allow", "{v}");
        assert_eq!((BUSY_PAYS.lock().unwrap().0, seen.lock().unwrap().len()), (3, 1), "tried three times, asked once");
        // busy for good: not past the wait, and nothing asked
        *BUSY_PAYS.lock().unwrap() = (0, (1..1000).collect());
        p.wait_for_signer = Duration::from_millis(800);
        let t0 = Instant::now();
        let why = p.pay("r1", 2, &serde_json::json!({})).unwrap_err();
        assert_eq!(why, "Resource temporarily unavailable (os error 11)");
        assert!(t0.elapsed() < Duration::from_secs(2) && BUSY_PAYS.lock().unwrap().0 > 1, "asked again within the wait, and no longer");
        assert_eq!(seen.lock().unwrap().len(), 1);
    }
}
