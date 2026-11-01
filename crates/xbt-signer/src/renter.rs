//! The renter's socket: the one way to a task's rental terms.
//!
//! A task the owner gave rental terms (`tickets.tasks.<task>.rental`, [`crate::ticket::TaskRental`]) pays
//! outside the wallet's limits for one payment, a day, a week and one seller: only its own budget bounds
//! it. That is the owner's word for the app's hashrate renter, which pays a rented miner's work seconds at
//! a time. A task's name is any caller's to give (`task` in `xbt402_pay`, a free string in the MCP tool),
//! so the name alone grants nothing. The grant goes with the socket a request comes on ([`Caller`]):
//!
//! * the wallet's socket (`B2_SIGNER_SOCK`: the MCP, the UI, the connector, an agent) is answered as
//!   always, except that nothing on it is paid, opened, locked or released under a task with rental
//!   terms;
//! * the renter's socket (`B2_RENTAL_SOCK`, `run/rental/signer.sock`) answers the renter's three
//!   methods only, and pays only a rental's pieces of work: `POST <pay url>/<rental>/<slice>`, where
//!   the pay URL is the hashmaker's hashrate route (`…/hashrate`). Under a task with rental terms they
//!   are paid on those terms; under one without (an older wallet whose owner signed no rental terms),
//!   as on the wallet's socket, under the wallet's own limits: the socket grants nothing by itself.
//!
//! The renter's socket is reached by file permissions, not by anything a caller says: its dir is the
//! signer's, with the hashrate services' group (the renter and the UI), and the MCP is not in that group
//! (`xbt_svc::layout::SHARED_DIRS`). The signer binds it only where that dir was made for it (`xbt-init`).
use serde_json::Value;

use crate::pyjson::str_or_empty;
use crate::signer::{deny, with, Signer};
use crate::ticket::TicketPolicy;

/// Who a request came from, by the socket it came on ([`crate::server`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    /// The wallet's socket: every method, and every task but one with rental terms.
    Wallet,
    /// The renter's socket: a rental's pieces of work and nothing else, on the task's rental terms where it has them.
    Renter,
}

/// What the renter's socket answers: a piece of work paid, its session stopped, and whether the signer is up.
pub const RENTER_METHODS: [&str; 3] = ["xbt402_pay", "ticket_stop", "health"];

/// Whether `url` is a rental's piece of work as the renter pays it (xbt-hashlink's `SignerPayer`):
/// `POST <pay url>/<rental>/<slice>`, the pay URL ending in the hashmaker's hashrate route (`/hashrate`), the
/// slice a number, and nothing after it.
pub fn rental_route(method: &str, url: &str) -> bool {
    if !method.eq_ignore_ascii_case("POST") {
        return false;
    }
    let Ok(u) = url::Url::parse(url) else { return false };
    if u.query().is_some() || u.fragment().is_some() {
        return false;
    }
    let segs: Vec<&str> = u.path_segments().map(|s| s.collect()).unwrap_or_default();
    matches!(segs.as_slice(), [.., "hashrate", rental, slice] if !rental.is_empty() && !slice.is_empty() && slice.bytes().all(|b| b.is_ascii_digit()))
}

fn refused(rule: &str, reason: String) -> Value {
    with(deny(rule, reason), serde_json::json!({"charged_sats": 0}))
}

/// The refusal of a task's rental terms to a caller on the wallet's socket.
pub(crate) fn not_the_renter(task: &str) -> Value {
    refused("ticket_rental_payer", format!("task {task:?} has the owner's rental terms (tickets.tasks.{task}.rental), which only this app's hashrate renter \
                                            pays under, through its own socket: nothing was paid"))
}

/// Whether `xbt402_pay` may go on for `caller`, under `task` (as the call resolved it), to `url` by `method`.
/// `Some`: the refusal, before anything is asked of the seller.
pub(crate) fn pay_gate(caller: Caller, tp: &TicketPolicy, task: Option<&str>, method: &str, url: &str) -> Option<Value> {
    let rental = task.filter(|t| tp.is_rental(t));
    match (caller, rental) {
        (Caller::Wallet, Some(t)) => Some(not_the_renter(t)),
        (Caller::Wallet, None) => None,
        (Caller::Renter, _) if !rental_route(method, url) => {
            Some(refused("ticket_rental_route", "the renter's socket pays only a rental's pieces of work (POST <pay url>/hashrate/<rental>/<slice>): nothing was paid".into()))
        }
        // a task without rental terms is paid as on the wallet's socket, under the wallet's own limits
        (Caller::Renter, _) => None,
    }
}

impl Signer {
    /// The rental terms of the methods that name a task or a session outright (`ticket_open`, `ticket_offer`,
    /// `ticket_lock`, `ticket_release`, `ticket_stop`): `Some` is the refusal. `xbt402_pay` decides its own
    /// ([`pay_gate`], with the task as it resolves it).
    pub(crate) fn renter_gate(&self, caller: Caller, method: &str, p: &Value) -> Option<Value> {
        let tp = self.ticket_policy();
        let sid = str_or_empty(p.get("session"));
        let task = match method {
            "ticket_open" => Some(str_or_empty(p.get("task"))),
            "ticket_offer" | "ticket_lock" | "ticket_release" | "ticket_stop" if !sid.is_empty() => self.ticket_session(&sid).map(|s| s.task),
            _ => None,
        };
        let rental = task.as_deref().filter(|t| tp.is_rental(t));
        match (caller, method) {
            // a caller on the wallet's socket may stop a rental's session (it spends nothing), and nothing more
            (Caller::Wallet, "ticket_stop") => None,
            (Caller::Wallet, _) => rental.map(not_the_renter),
            // the renter stops its own sessions, by their ids
            (Caller::Renter, "ticket_stop") if sid.is_empty() => {
                Some(refused("ticket_rental_route", "the renter's socket stops a session by its id, not a seller's every session".into()))
            }
            (Caller::Renter, _) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rentals_piece_of_work_and_nothing_else() {
        for ok in ["https://shop.example/hashrate/r1/0", "https://shop.example/base/hashrate/rt-a1/120", "http://127.0.0.1:8402/hashrate/abc/7"] {
            assert!(rental_route("POST", ok), "{ok}");
        }
        assert!(!rental_route("GET", "https://shop.example/hashrate/r1/0"));
        for no in ["https://shop.example/page/10", "https://shop.example/hashrate/r1", "https://shop.example/hashrate/r1/x", "https://shop.example/hashrate/r1/0/",
                   "https://shop.example/hashrate/r1/0?x=1", "https://shop.example/hashrate//0", "https://shop.example/page/hashrate", "not a url",
                   "https://shop.example/hashrate/r1/0/extra"] {
            assert!(!rental_route("POST", no), "{no}");
        }
    }
}
