//! Payment by BOLT 12 offer (`docs/TICKETS.md`, section 15): prepaid tickets and lottery wins paid
//! to one offer of the seller's node, each payment bound to its session by the payer's note.
//!
//! The gateway makes one offer at the start, with no amount ([`Node::create_offer`]), and names it
//! in the terms of its prepaid tickets and of its lottery (`extra.offer`). A buyer fetches an
//! invoice from that offer for the exact amount and puts a note in its request
//! ([`xbt402::offer`]): the session, what is paid (a ticket, or the win of a draw), the amount, a
//! nonce, and a MAC by the session key over all of them. The seller's node repeats the note in the
//! invoice it signs. The gateway credits a paid invoice ([`Node::offer_invoices`]) only:
//!
//! 1. **paid**: the node shows it settled, for at least the amount the note names, which is the
//!    session's ticket size or win size exactly;
//! 2. **bound**: the note names a session this gateway has, and its MAC holds under that
//!    session's key: only the buyer and the seller have the key, so nobody can name another's
//!    session on a payment of theirs, or change the amount or purpose after the fact;
//! 3. **once**: neither the invoice's payment hash nor the note (its session, purpose and nonce)
//!    has been credited before. Both are written to this journal, and synced, before the credit
//!    is made: a crash between the two loses that one credit and never makes two;
//! 4. **recent**: the invoice was issued within [`CREDIT_WINDOW_SECS`], so that the journal of what
//!    was credited can be bounded ([`KEEP_SECS`]).
//!
//! A note that fails any of these is not credited, and the payment is not looked at again. The
//! payment proof stays what it is for any prepaid ticket: the invoice's preimage, which the
//! buyer's node learns when it pays and presents in `release` as it would a prepaid ticket's.
use std::collections::{HashMap, HashSet};
use std::path::Path;

use xbt402::offer::{self, Purpose};

use super::*;
use crate::node::{NodeOffer, OfferInvoice};

/// What was credited by offer, beside the tickets' journal in the state directory.
pub const JOURNAL: &str = "offers.jsonl";
/// An offer invoice issued longer ago than this is not credited (a day).
pub const CREDIT_WINDOW_SECS: u64 = 86_400;
/// What was credited is remembered this long: past the window, with a day's margin.
pub const KEEP_SECS: u64 = 2 * CREDIT_WINDOW_SECS;
/// The janitor asks the node for the offer's invoices no more often than this.
const LIST_EVERY: Duration = Duration::from_secs(2);
/// A release that names a payment the gateway has not seen asks the node at once, but no more
/// often than this.
const LIST_AT_MOST: Duration = Duration::from_millis(200);

/// One payment credited by offer: its payment hash, its note's id, the session it was credited to
/// and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credited {
    pub hash: Hash,
    pub note: String,
    pub session: String,
    pub at: u64,
}

impl crate::store::Record for Credited {
    fn to_json(&self) -> Value {
        json!({"t": "credited", "hash": hex::encode(self.hash), "note": self.note, "session": self.session, "at": self.at})
    }

    fn from_json(v: &Value) -> Option<Self> {
        if v.get("t")?.as_str()? != "credited" {
            return None;
        }
        Some(Self {
            hash: hex32(v.get("hash")?.as_str()?)?,
            note: v.get("note")?.as_str()?.to_string(),
            session: v.get("session")?.as_str()?.to_string(),
            at: v.get("at")?.as_u64()?,
        })
    }
}

struct State {
    store: Store<Credited>,
    /// What was credited, by payment hash, and whether its preimage has been presented since the
    /// start (a second presentation is `ticket_used`).
    credited: HashMap<Hash, (Credited, bool)>,
    notes: HashSet<String>,
    /// Paid invoices that will never be credited (a note that is not good): not looked at again.
    passed: HashSet<Hash>,
    listed: Option<Instant>,
}

pub(super) struct Offers {
    pub(super) offer: NodeOffer,
    state: Mutex<State>,
    /// One look at the node's invoices at a time: two would each find a payment new.
    sweeping: Mutex<()>,
}

impl Offers {
    /// The offer, and what its journal in `dir` says was credited, at `now`.
    pub(super) fn open(offer: NodeOffer, dir: &Path, now: u64) -> Result<Self, Error> {
        let (mut store, recs) = Store::<Credited>::open_beside(dir, JOURNAL).map_err(|e| Error::Journal(format!("{JOURNAL}: {e}")))?;
        let kept: Vec<Credited> = recs.into_iter().filter(|c| now.saturating_sub(c.at) <= KEEP_SECS).collect();
        store.compact(&kept).map_err(|e| Error::Journal(format!("{JOURNAL}: {e}")))?;
        let notes = kept.iter().map(|c| c.note.clone()).collect();
        let credited = kept.into_iter().map(|c| (c.hash, (c, false))).collect();
        Ok(Self { offer, state: Mutex::new(State { store, credited, notes, passed: HashSet::new(), listed: None }), sweeping: Mutex::new(()) })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(super) fn close(&self) {
        self.lock().store.close();
    }
}

/// What a paid offer invoice comes to.
enum Verdict {
    Ticket(String, offer::Note),
    Win(String, u64, offer::Note),
    /// Not to be credited, ever.
    Pass,
}

impl Gateway {
    /// The offer the terms name, if the runner turned payment by offer on.
    pub(super) fn offer_text(&self) -> Option<&str> {
        self.offers.as_ref().map(|o| o.offer.bolt12.as_str())
    }

    /// Make the node's offer at the start: an offer the node will not make is a config that does
    /// not work, and nothing starts on it.
    pub(super) fn make_offer(node: &dyn Node, cfg: &Config, now: u64) -> Result<Option<Offers>, Error> {
        let Some(o) = &cfg.offers else { return Ok(None) };
        let offer = node.create_offer(&o.description).map_err(|e| Error::Start(format!("offers: the node made no BOLT 12 offer: {e}")))?;
        Offers::open(offer, &cfg.state_dir, now).map(Some)
    }

    /// Look at the node's invoices for the offer, and credit each one that is newly paid and
    /// whose note holds. `force`: a buyer has just named a payment the gateway has not seen.
    /// False: the node gave no list.
    pub(super) fn offer_sweep(&self, force: bool) -> bool {
        let Some(o) = &self.offers else { return true };
        let _one = o.sweeping.lock().unwrap_or_else(|p| p.into_inner());
        // the janitor looks now and then; a buyer that names a payment is answered on a fresh list,
        // waiting for it if the last was a moment ago
        let wait = {
            let st = o.lock();
            match st.listed.map(|t| t.elapsed()) {
                Some(e) if !force && e < LIST_EVERY => return true,
                Some(e) if force => LIST_AT_MOST.saturating_sub(e),
                _ => Duration::ZERO,
            }
        };
        std::thread::sleep(wait);
        o.lock().listed = Some(Instant::now());
        let list = match self.node.offer_invoices(&o.offer.id) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("xbt-gateway: the node's invoices for the offer could not be read: {e}");
                return false;
            }
        };
        let now = self.now();
        for inv in list.iter().filter(|i| i.state == Some(InvoiceState::Settled)) {
            {
                let st = o.lock();
                if st.credited.contains_key(&inv.payment_hash) || st.passed.contains(&inv.payment_hash) {
                    continue;
                }
            }
            let verdict = self.offer_verdict(o, inv, now);
            match verdict {
                Verdict::Pass => {
                    o.lock().passed.insert(inv.payment_hash);
                }
                Verdict::Ticket(session, note) => {
                    if !self.offer_record(o, inv, &note, &session, now) {
                        continue;
                    }
                    let mut st = self.lock();
                    match st.book.credit_offer(&session, &inv.payment_hash, self.cfg.caps.ticket_msat, now) {
                        Ok(recs) => {
                            self.journal(&mut st, &recs);
                            drop(st);
                            self.credited.notify_all();
                        }
                        Err(why) => eprintln!("xbt-gateway: a prepaid ticket paid by offer could not be credited ({}): its payment is kept as seen", why.code()),
                    }
                }
                Verdict::Win(session, draw, note) => {
                    if !self.offer_record(o, inv, &note, &session, now) {
                        continue;
                    }
                    let Some(l) = &self.lottery else { continue };
                    let old = l.lock().win_paid_by_offer(&session, draw);
                    l.changed.notify_all();
                    // the win's BOLT 11 invoice, if it had one, can no longer be paid for it
                    if let Some(Some(h)) = old {
                        drop(self.node.cancel(&h));
                    }
                }
            }
        }
        true
    }

    /// Whether a paid offer invoice is to be credited, and to what (the rules of this module).
    fn offer_verdict(&self, o: &Offers, inv: &OfferInvoice, now: u64) -> Verdict {
        if inv.created_at > 0 && inv.created_at.saturating_add(CREDIT_WINDOW_SECS) < now {
            return Verdict::Pass;
        }
        let Some(note) = inv.payer_note.as_deref().and_then(offer::parse) else { return Verdict::Pass };
        if o.lock().notes.contains(&note.id()) {
            return Verdict::Pass;
        }
        match note.purpose {
            Purpose::Ticket => {
                let ticket = self.cfg.caps.ticket_msat;
                let ok = self.cfg.prepaid
                    && note.amount_msat == ticket
                    && inv.paid_msat >= ticket
                    && self.lock().book.session(&note.session).is_some_and(|s| note.verify(&s.key));
                if ok { Verdict::Ticket(note.session.clone(), note) } else { Verdict::Pass }
            }
            Purpose::Win(draw) => {
                let Some(l) = &self.lottery else { return Verdict::Pass };
                let ok = l.lock().session(&note.session).is_some_and(|s| {
                    note.verify(&s.key) && note.amount_msat == s.win_msat && inv.paid_msat >= s.win_msat && s.unpaid.iter().any(|w| w.draw == draw)
                });
                if ok { Verdict::Win(note.session.clone(), draw, note) } else { Verdict::Pass }
            }
        }
    }

    /// The payment and its note into the journal, on disk, before the credit. False: it could
    /// not be written, and nothing is credited now (the next look tries again).
    fn offer_record(&self, o: &Offers, inv: &OfferInvoice, note: &offer::Note, session: &str, now: u64) -> bool {
        let c = Credited { hash: inv.payment_hash, note: note.id(), session: session.to_string(), at: now };
        let file = {
            let mut st = o.lock();
            if st.store.is_closed() {
                return false;
            }
            if let Err(e) = st.store.append(std::slice::from_ref(&c)) {
                eprintln!("xbt-gateway: the offers' journal could not be written: {e}");
                return false;
            }
            st.store.handle()
        };
        if !self.sync(&file) {
            return false;
        }
        let mut st = o.lock();
        st.notes.insert(c.note.clone());
        st.credited.insert(c.hash, (c, false));
        true
    }

    /// A preimage presented in `release` that names no ticket of the book: a prepaid ticket paid
    /// by offer, if the node shows it paid with a good note for this session. Its credit was made
    /// when the payment was seen (here, or by the janitor); presenting it answers for it once.
    pub(super) fn take_offer_secret(&self, session: &str, secret: &[u8; 32]) -> Result<Hash, Refusal> {
        let Some(o) = &self.offers else { return Err(Refusal::TicketUnknown) };
        let hash = ticket::ticket_hash(secret);
        let answer = |o: &Offers| -> Option<Result<Hash, Refusal>> {
            let mut st = o.lock();
            let (c, presented) = st.credited.get_mut(&hash)?;
            Some(if c.session != session {
                Err(Refusal::TicketUnknown)
            } else if *presented {
                Err(Refusal::TicketUsed)
            } else {
                *presented = true;
                Ok(hash)
            })
        };
        if let Some(a) = answer(o) {
            return a;
        }
        if !self.offer_sweep(true) {
            return Err(Refusal::HeightUnknown);
        }
        answer(o).unwrap_or(Err(Refusal::TicketUnknown))
    }

    /// `lock` with `"by": "offer"`: no invoice is issued. A first one makes the session (its id and
    /// key, on disk before the answer leaves), bounded as a first lock is; a later one is a request
    /// of its session, authenticated as one. Either answer names the offer.
    pub(super) fn lock_by_offer(&self, req: &Request, pay: Option<&Pay>, named: Option<&Value>) -> Response {
        let offer = self.offer_text().unwrap_or_default().to_string();
        match (pay, named) {
            (None, None) => {
                let mut entropy = [0u8; 48];
                entropy.copy_from_slice(&xbt_svc::random_bytes(48));
                let addr = addr_name(self.client_ip(req));
                let opened = {
                    let mut st = self.lock();
                    st.book.open_session(&addr, &entropy, self.now()).map(|g| {
                        let written = self.journal(&mut st, &g.recs);
                        (g, written, st.store.handle())
                    })
                };
                match opened {
                    Ok((g, true, file)) if self.sync(&file) => json_response(
                        200,
                        &json!({"session": g.session, "key": g.key.map(hex::encode), "tickets": [], "refused": [], "offer": offer}),
                    ),
                    Ok((g, _, _)) => {
                        self.lock().book.forget_unused(&g.session);
                        error(500, "journal", "the gateway could not record the session")
                    }
                    Err(why) => json_response(402, &json!({"error": why.code()})),
                }
            }
            (Some(p), named) if named.is_none_or(|s| s.as_str() == Some(p.session.as_str())) => match self.authenticate(req, p, None) {
                Ok(a) => {
                    let out = json!({"session": a.session, "tickets": [], "refused": [], "offer": offer});
                    self.answered(&a, json_response(200, &out), 0)
                }
                Err(r) => r,
            },
            _ => error(400, "bad_request", "a lock for an existing session carries its PAYMENT-SIGNATURE; a first lock names no session"),
        }
    }

    /// The janitor's look at the offer, and the journal kept short.
    pub(super) fn offer_tick(&self) {
        let Some(o) = &self.offers else { return };
        self.offer_sweep(false);
        let now = self.now();
        let mut st = o.lock();
        // what is past the window is credited never again: its payment and its note are let go
        let old: Vec<Hash> = st.credited.iter().filter(|(_, (c, _))| now.saturating_sub(c.at) > KEEP_SECS).map(|(h, _)| *h).collect();
        for h in old {
            if let Some((c, _)) = st.credited.remove(&h) {
                st.notes.remove(&c.note);
            }
        }
        if st.store.lines() > COMPACT_AT {
            let kept: Vec<Credited> = st.credited.values().map(|(c, _)| c.clone()).filter(|c| now.saturating_sub(c.at) <= KEEP_SECS).collect();
            if let Err(e) = st.store.compact(&kept) {
                eprintln!("xbt-gateway: the offers' journal could not be rewritten: {e}");
            }
        }
    }
}
