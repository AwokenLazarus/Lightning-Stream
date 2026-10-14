//! The gateway's book: sessions, their tickets and their balances. No IO and no clock: every call
//! is given the time, the block height and the node's view, so every rule is tested on in-memory
//! data.
//!
//! The rules, one sentence each:
//!
//! - **Locked.** A secret is taken only for a ticket this process has seen `ACCEPTED` on the node,
//!   for the full ticket amount, in the session that locked it.
//! - **Once.** A ticket is credited once: crediting removes it from the book.
//! - **Margin.** A secret is taken only while more than [`Caps::margin_blocks`] blocks are left
//!   before the ticket's HTLC expires, by a height the caller vouches for.
//! - **Paid first.** A charge is taken only from what has been released and not spent (on a route
//!   the runner marked checkable, from one pledged ticket as well).
//! - **Bounded.** Sessions, sessions per address and unreleased tickets are capped, and what a cap
//!   refuses is refused before anything is asked of the node.
//! - **Half the slots.** Held tickets, all sessions together, are at most [`Caps::max_held`]: half
//!   of the pending payments one inbound channel carries unless the runner said more. A lock beyond
//!   it is refused as `slots_short` with a time to wait, and makes no session.
//! - **Prepaid is paid, then credited once.** A ticket settled on arrival holds no slot and is not
//!   counted as held; it is credited when the node shows its invoice settled, and only then.
//!
//! What the node shows is the record of money: a ticket's state here is the last one the node
//! reported, and a restart reads every unfinished ticket from the node again before it is used.
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use serde_json::{json, Value};
use xbt402::ticket::{hex32, ticket_hash};

use crate::node::{Hash, Invoice, InvoiceState};
use crate::Error;

/// The caps and the times. `Config` fills this from the runner's file; the defaults are there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caps {
    pub ticket_msat: u64,
    /// Unreleased tickets one session may hold (unpaid ones included), and as many tickets settled
    /// on arrival that it may have issued and not yet paid: the two are counted apart, so that
    /// held tickets whose payment found no slot do not keep the session from buying a prepaid one.
    pub max_tickets: u32,
    /// Sessions with a ticket locked or a response open, at once.
    pub max_sessions: u32,
    /// Such sessions from one client address; 0 is no cap per address.
    pub sessions_per_address: u32,
    /// Sessions in all, those that only keep a paid balance included.
    pub max_kept_sessions: u32,
    /// Held tickets in all (tickets settled on arrival hold nothing and are not counted).
    pub max_held: u32,
    /// What a buyer refused for lack of a slot is told to wait, in seconds.
    pub slots_retry_secs: u64,
    pub margin_blocks: u32,
    /// An unpaid ticket is given up this many seconds after it was issued.
    pub unpaid_secs: u64,
    /// A session that has never released a secret is closed after this many seconds.
    pub first_use_secs: u64,
    /// A session's tickets are cancelled after this many seconds without a paid request.
    pub idle_secs: u64,
    /// A session with nothing locked is forgotten, its unused balance with it, after this long.
    pub keep_secs: u64,
}

/// Why a request is not served. The wire names are the draft's (`docs/TICKETS.md`, section 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    SessionUnknown,
    BadAuth,
    /// Not the next `seq`; the one expected.
    BadSeq(u64),
    TicketUnknown,
    TicketNotLocked,
    TicketUsed,
    TicketExpiring,
    BalanceShort,
    TooManyTickets,
    TooManySessions,
    /// The cap on held tickets, all sessions together, is reached; the seconds to wait.
    SlotsShort(u64),
    /// The block height is not known, so no ticket's margin can be shown.
    HeightUnknown,
    /// A ticket is already pledged, or the session owes for a piece it was served.
    PledgeOutstanding,
}

impl Refusal {
    pub fn code(self) -> &'static str {
        match self {
            Self::SessionUnknown => "session_unknown",
            Self::BadAuth => "bad_auth",
            Self::BadSeq(_) => "bad_seq",
            Self::TicketUnknown => "ticket_unknown",
            Self::TicketNotLocked => "ticket_not_locked",
            Self::TicketUsed => "ticket_used",
            Self::TicketExpiring => "ticket_expiring",
            Self::BalanceShort => "balance_short",
            Self::TooManyTickets => "too_many_tickets",
            Self::TooManySessions => "too_many_sessions",
            Self::SlotsShort(_) => "slots_short",
            Self::HeightUnknown => "node_unavailable",
            Self::PledgeOutstanding => "pledge_outstanding",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketState {
    /// Issued (or being issued) on the node, not seen paid.
    Open,
    /// The node holds the payment.
    Accepted,
    /// A settle call for it is on its way to the node.
    Settling,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub session: String,
    pub state: TicketState,
    pub paid_msat: u64,
    pub expiry_height: Option<u32>,
    pub issued_at: u64,
    /// Settled on arrival: an ordinary invoice, which holds no slot. It stays `Open` until the
    /// node shows it settled, and is then credited and gone.
    pub prepaid: bool,
}

/// How many used hashes a session remembers, to answer `ticket_used` instead of `ticket_unknown`.
/// Safety does not rest on it: a used ticket is no longer in the book either way.
const USED_KEPT: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub key: [u8; 32],
    pub addr: String,
    pub next_seq: u64,
    /// The sum of this session's settled tickets. Only rises.
    pub released_msat: u64,
    /// The running total of what was served. Refunds of a charge that bought nothing aside, only rises.
    pub spent_msat: u64,
    /// The ticket pledged for a piece served before its secret (a checkable route).
    pub pledge: Option<Hash>,
    pub last_paid: u64,
    /// Responses being metered right now: the session is not idle while one is open.
    pub open_responses: u32,
    live: u32,
    used: VecDeque<Hash>,
}

impl Session {
    /// What is released and not spent.
    pub fn balance_msat(&self) -> u64 {
        self.released_msat.saturating_sub(self.spent_msat)
    }

    /// What was served beyond what was released (only ever on a pledge).
    pub fn owed_msat(&self) -> u64 {
        self.spent_msat.saturating_sub(self.released_msat)
    }

    pub fn live(&self) -> u32 {
        self.live
    }
}

/// One line of the journal: what must outlast the process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rec {
    Session {
        id: String,
        key: [u8; 32],
        addr: String,
    },
    Ticket {
        hash: Hash,
        session: String,
        /// Settled on arrival. Written only when true, so a journal from before reads as held.
        prepaid: bool,
    },
    /// The ticket is finished and paid nothing.
    Gone {
        hash: Hash,
    },
    /// The ticket was settled and credited.
    Released {
        hash: Hash,
        msat: u64,
    },
    /// A session's counters, whole.
    Mark {
        session: String,
        next_seq: u64,
        spent_msat: u64,
        pledge: Option<Hash>,
    },
    Drop {
        session: String,
    },
}

impl Rec {
    pub fn to_json(&self) -> Value {
        match self {
            Self::Session { id, key, addr } => {
                json!({"t": "session", "id": id, "key": hex::encode(key), "addr": addr})
            }
            Self::Ticket {
                hash,
                session,
                prepaid,
            } => {
                let mut v = json!({"t": "ticket", "hash": hex::encode(hash), "session": session});
                if *prepaid {
                    v["prepaid"] = true.into();
                }
                v
            }
            Self::Gone { hash } => json!({"t": "gone", "hash": hex::encode(hash)}),
            Self::Released { hash, msat } => {
                json!({"t": "released", "hash": hex::encode(hash), "msat": msat})
            }
            Self::Mark {
                session,
                next_seq,
                spent_msat,
                pledge,
            } => {
                json!({"t": "mark", "session": session, "seq": next_seq, "spent": spent_msat, "pledge": pledge.map(hex::encode)})
            }
            Self::Drop { session } => json!({"t": "drop", "session": session}),
        }
    }

    /// `None`: not a record this version writes. A journal with such a line is not loaded.
    pub fn from_json(v: &Value) -> Option<Self> {
        let s = |k: &str| v.get(k).and_then(Value::as_str);
        let h = |k: &str| s(k).and_then(hex32);
        let n = |k: &str| v.get(k).and_then(Value::as_u64);
        Some(match s("t")? {
            "session" => Self::Session {
                id: s("id")?.to_string(),
                key: h("key")?,
                addr: s("addr")?.to_string(),
            },
            "ticket" => Self::Ticket {
                hash: h("hash")?,
                session: s("session")?.to_string(),
                prepaid: match v.get("prepaid") {
                    None => false,
                    Some(Value::Bool(b)) => *b,
                    Some(_) => return None,
                },
            },
            "gone" => Self::Gone { hash: h("hash")? },
            "released" => Self::Released {
                hash: h("hash")?,
                msat: n("msat")?,
            },
            "mark" => Self::Mark {
                session: s("session")?.to_string(),
                next_seq: n("seq")?,
                spent_msat: n("spent")?,
                pledge: match v.get("pledge")? {
                    Value::Null => None,
                    Value::String(p) => Some(hex32(p)?),
                    _ => return None,
                },
            },
            "drop" => Self::Drop {
                session: s("session")?.to_string(),
            },
            _ => return None,
        })
    }
}

/// What a lock request was granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Granted {
    pub session: String,
    /// The session key, when this request made the session.
    pub key: Option<[u8; 32]>,
    /// The hashes to issue on the node, in the order asked. Each is in the book as `Open`, and
    /// [`Book::issued`] must be called for each.
    pub issue: Vec<Hash>,
    /// To write and sync before the node is asked for anything.
    pub recs: Vec<Rec>,
}

/// What the janitor must do on the node, and what it dropped.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Sweep {
    /// Tickets to cancel on the node: unpaid too long, too close to expiry, or of a quiet session.
    pub cancel: Vec<Hash>,
    pub recs: Vec<Rec>,
}

#[derive(Debug)]
pub struct Book {
    caps: Caps,
    sessions: BTreeMap<String, Session>,
    tickets: HashMap<Hash, Ticket>,
    dirty: HashSet<String>,
}

impl Book {
    pub fn new(caps: Caps) -> Self {
        Self {
            caps,
            sessions: BTreeMap::new(),
            tickets: HashMap::new(),
            dirty: HashSet::new(),
        }
    }

    pub fn caps(&self) -> &Caps {
        &self.caps
    }

    pub fn session(&self, id: &str) -> Option<&Session> {
        self.sessions.get(id)
    }

    pub fn ticket(&self, hash: &Hash) -> Option<&Ticket> {
        self.tickets.get(hash)
    }

    pub fn sessions(&self) -> usize {
        self.sessions.len()
    }

    /// Sessions that hold a ticket or have a response open: the ones the cap counts.
    pub fn active_sessions(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| s.live > 0 || s.open_responses > 0)
            .count()
    }

    /// Held tickets in all, unpaid ones included: what the cap on held tickets counts. A ticket
    /// settled on arrival is not one.
    pub fn held(&self) -> usize {
        self.tickets.values().filter(|t| !t.prepaid).count()
    }

    /// Tickets settled on arrival that are issued and not yet credited.
    pub fn prepaid_open(&self) -> usize {
        self.tickets.values().filter(|t| t.prepaid).count()
    }

    /// Set the cap on held tickets (a gateway that reads its node's channels sizes itself). What is
    /// held already stays; nothing more is issued above the cap.
    pub fn set_max_held(&mut self, max_held: u32) {
        self.caps.max_held = max_held;
    }

    /// The tickets of one session, in hash order.
    pub fn tickets_of(&self, session: &str) -> Vec<(Hash, Ticket)> {
        let mut v: Vec<_> = self
            .tickets
            .iter()
            .filter(|(_, t)| t.session == session)
            .map(|(h, t)| (*h, t.clone()))
            .collect();
        v.sort_by_key(|(h, _)| *h);
        v
    }

    /// Every unfinished ticket: what a restart reads from the node again.
    pub fn unfinished(&self) -> Vec<Hash> {
        let mut v: Vec<_> = self.tickets.keys().copied().collect();
        v.sort();
        v
    }

    // --- lock -----------------------------------------------------------------------------------

    /// A lock request: `session` None makes a session (its id and key from `entropy`), else the
    /// caller has authenticated it. Grants as many of `hashes` as the caps allow, in order; a hash
    /// already in the book is skipped. `prepaid`: the tickets are settled on arrival, hold no slot
    /// and are bounded by the session's own cap only. A held lock that the cap on held tickets
    /// leaves no room for is `slots_short`, checked before a session is made. Bounded: nothing
    /// here asks the node.
    pub fn lock(
        &mut self,
        addr: &str,
        session: Option<&str>,
        hashes: &[Hash],
        prepaid: bool,
        entropy: &[u8; 48],
        now: u64,
    ) -> Result<Granted, Refusal> {
        let mut recs = vec![];
        let room_session = self.lock_room(addr, session, prepaid)?;
        let (id, key) = match session {
            Some(id) => (id.to_string(), None),
            None => {
                let id = hex::encode(&entropy[..16]);
                let mut key = [0u8; 32];
                key.copy_from_slice(&entropy[16..]);
                if self.sessions.contains_key(&id) {
                    return Err(Refusal::TooManySessions);
                }
                (id, Some(key))
            }
        };
        let room_total = if prepaid {
            usize::MAX
        } else {
            (self.caps.max_held as usize).saturating_sub(self.held())
        };
        // the session's own cap first: a buyer at it gains nothing by waiting for another's slots
        if room_session > 0 && room_total == 0 {
            return Err(Refusal::SlotsShort(self.caps.slots_retry_secs));
        }
        let mut issue: Vec<Hash> = vec![];
        for h in hashes {
            if issue.len() >= room_session.min(room_total) {
                break;
            }
            if self.tickets.contains_key(h) || issue.contains(h) {
                continue;
            }
            issue.push(*h);
        }
        if issue.is_empty() {
            return Err(Refusal::TooManyTickets);
        }
        if let Some(key) = key {
            self.sessions.insert(
                id.clone(),
                Session {
                    key,
                    addr: addr.to_string(),
                    next_seq: 0,
                    released_msat: 0,
                    spent_msat: 0,
                    pledge: None,
                    last_paid: now,
                    open_responses: 0,
                    live: 0,
                    used: VecDeque::new(),
                },
            );
            recs.push(Rec::Session {
                id: id.clone(),
                key,
                addr: addr.to_string(),
            });
        }
        for h in &issue {
            self.tickets.insert(
                *h,
                Ticket {
                    session: id.clone(),
                    state: TicketState::Open,
                    paid_msat: 0,
                    expiry_height: None,
                    issued_at: now,
                    prepaid,
                },
            );
            recs.push(Rec::Ticket {
                hash: *h,
                session: id.clone(),
                prepaid,
            });
        }
        if let Some(s) = self.sessions.get_mut(&id) {
            s.live += issue.len() as u32;
        }
        Ok(Granted {
            session: id,
            key,
            issue,
            recs,
        })
    }

    /// The caps on sessions and on a session's own tickets, for a lock from `addr` (`session`
    /// None: a first lock, which would make a session): the tickets the session may still be
    /// issued, or why the lock is refused. Everything [`Book::lock`] refuses that does not turn
    /// on the cap on held tickets, which a gateway that reads its node's channels has to ask the
    /// node about: so this is asked first, and a lock these caps refuse costs the node nothing.
    pub fn lock_room(&self, addr: &str, session: Option<&str>, prepaid: bool) -> Result<usize, Refusal> {
        // a session takes one of the capped places while it holds a ticket or a response; one that
        // only keeps a balance it paid for does not, or a few paid tickets would hold every place
        let active = |s: &Session| s.live > 0 || s.open_responses > 0;
        let places_taken = || {
            let all = self.sessions.values().filter(|s| active(s)).count();
            let here = self
                .sessions
                .values()
                .filter(|s| active(s) && s.addr == addr)
                .count();
            all >= self.caps.max_sessions as usize
                || self.caps.sessions_per_address > 0
                    && here >= self.caps.sessions_per_address as usize
        };
        let live = match session {
            Some(id) => {
                let s = self.sessions.get(id).ok_or(Refusal::SessionUnknown)?;
                if !active(s) && places_taken() {
                    return Err(Refusal::TooManySessions);
                }
                self.tickets
                    .values()
                    .filter(|t| t.session == id && t.prepaid == prepaid)
                    .count()
            }
            None => {
                if places_taken() || self.sessions.len() >= self.caps.max_kept_sessions as usize {
                    return Err(Refusal::TooManySessions);
                }
                0
            }
        };
        match (self.caps.max_tickets as usize).saturating_sub(live) {
            0 => Err(Refusal::TooManyTickets),
            room => Ok(room),
        }
    }

    /// The node's answer to issuing `hash`: not issued, the ticket leaves the book.
    pub fn issued(&mut self, hash: &Hash, ok: bool) -> Option<Rec> {
        if ok {
            return None;
        }
        self.remove(hash, false)
            .then_some(Rec::Gone { hash: *hash })
    }

    /// A session whose first lock issued nothing never existed: it has no ticket and its key was
    /// told to nobody who could use it.
    pub fn forget_unused(&mut self, session: &str) -> Option<Rec> {
        let s = self.sessions.get(session)?;
        if s.live > 0 || s.released_msat > 0 || s.next_seq > 0 {
            return None;
        }
        self.sessions.remove(session);
        self.dirty.remove(session);
        Some(Rec::Drop {
            session: session.to_string(),
        })
    }

    // --- a request --------------------------------------------------------------------------------

    /// Step 1 of a request: the session exists, `verify` accepts its key, `seq` is the next one.
    /// A `seq` is used up by any request that passes here, served or not.
    pub fn authenticate(
        &mut self,
        session: &str,
        seq: u64,
        verify: impl FnOnce(&[u8; 32]) -> bool,
    ) -> Result<(), Refusal> {
        let s = self
            .sessions
            .get_mut(session)
            .ok_or(Refusal::SessionUnknown)?;
        if !verify(&s.key) {
            return Err(Refusal::BadAuth);
        }
        if seq != s.next_seq {
            return Err(Refusal::BadSeq(s.next_seq));
        }
        s.next_seq = s
            .next_seq
            .checked_add(1)
            .ok_or(Refusal::BadSeq(s.next_seq))?;
        self.dirty.insert(session.to_string());
        Ok(())
    }

    /// Step 2: the secret names a ticket of this session that is locked, whole, unused and outside
    /// its margin at `height`. It is marked as being settled before this returns, so a second
    /// request with the same secret is refused while the first is at the node.
    pub fn present(
        &mut self,
        session: &str,
        secret: &[u8; 32],
        height: Option<u32>,
    ) -> Result<Hash, Refusal> {
        let hash = ticket_hash(secret);
        let s = self.sessions.get(session).ok_or(Refusal::SessionUnknown)?;
        let used = s.used.contains(&hash);
        let caps = &self.caps;
        let t = match self.tickets.get_mut(&hash) {
            Some(t) if t.session == session => t,
            _ if used => return Err(Refusal::TicketUsed),
            _ => return Err(Refusal::TicketUnknown),
        };
        // a ticket settled on arrival is never settled by a secret: the node's word credits it
        if t.prepaid {
            return Err(Refusal::TicketNotLocked);
        }
        match t.state {
            TicketState::Open => return Err(Refusal::TicketNotLocked),
            TicketState::Settling => return Err(Refusal::TicketUsed),
            TicketState::Accepted => {}
        }
        if t.paid_msat < caps.ticket_msat {
            return Err(Refusal::TicketNotLocked);
        }
        Self::outside_margin(caps, t, height)?;
        t.state = TicketState::Settling;
        Ok(hash)
    }

    /// What a presented preimage names in `session`: `Ok(true)` a ticket settled on arrival that is
    /// not credited yet (the node is then asked whether it was paid), `Ok(false)` a held ticket.
    /// `Err`: none of this session's, or one credited before.
    pub fn presented_kind(&self, session: &str, secret: &[u8; 32]) -> Result<bool, Refusal> {
        let hash = ticket_hash(secret);
        let s = self.sessions.get(session).ok_or(Refusal::SessionUnknown)?;
        match self.tickets.get(&hash) {
            Some(t) if t.session == session => Ok(t.prepaid),
            _ if s.used.contains(&hash) => Err(Refusal::TicketUsed),
            _ => Err(Refusal::TicketUnknown),
        }
    }

    fn outside_margin(caps: &Caps, t: &Ticket, height: Option<u32>) -> Result<(), Refusal> {
        let height = height.ok_or(Refusal::HeightUnknown)?;
        let expiry = t.expiry_height.ok_or(Refusal::TicketNotLocked)?;
        match expiry.checked_sub(height) {
            Some(left) if left > caps.margin_blocks => Ok(()),
            _ => Err(Refusal::TicketExpiring),
        }
    }

    /// Step 3 succeeded, or the node reports the ticket settled: credit it, once. False: it was
    /// credited before, or is not in the book.
    pub fn settled(&mut self, hash: &Hash, paid_msat: Option<u64>) -> Option<Rec> {
        let t = self.tickets.get(hash)?;
        let msat = paid_msat.unwrap_or(t.paid_msat).min(self.caps.ticket_msat);
        // a ticket settled on arrival that arrived short is no ticket: the session is not
        // credited a part, and the invoice is finished on the node either way
        if t.prepaid && msat < self.caps.ticket_msat {
            return self
                .remove(hash, false)
                .then_some(Rec::Gone { hash: *hash });
        }
        let session = t.session.clone();
        self.remove(hash, true);
        let s = self.sessions.get_mut(&session)?;
        s.released_msat = s.released_msat.saturating_add(msat);
        self.dirty.insert(session);
        Some(Rec::Released { hash: *hash, msat })
    }

    /// The settle call got no answer to act on: the ticket is as it was before the call, and the
    /// node's next report decides.
    pub fn settle_unanswered(&mut self, hash: &Hash) {
        if let Some(t) = self.tickets.get_mut(hash) {
            if t.state == TicketState::Settling {
                t.state = TicketState::Accepted;
            }
        }
    }

    /// The node's view of a ticket, from its stream or a lookup. A final state finishes the ticket.
    pub fn node_update(&mut self, hash: &Hash, inv: &Invoice) -> Option<Rec> {
        let t = self.tickets.get_mut(hash)?;
        match inv.state {
            InvoiceState::Open => {
                if t.state == TicketState::Accepted {
                    // the node no longer holds it: not usable until it says so again
                    t.state = TicketState::Open;
                }
                None
            }
            // an ordinary invoice is never held: a moment between arrival and settle changes nothing
            InvoiceState::Accepted if t.prepaid => None,
            InvoiceState::Accepted => {
                t.paid_msat = inv.paid_msat;
                t.expiry_height = inv.expiry_height;
                if t.state == TicketState::Open {
                    t.state = TicketState::Accepted;
                }
                None
            }
            InvoiceState::Settled => self.settled(hash, Some(inv.paid_msat)),
            InvoiceState::Canceled => self
                .remove(hash, false)
                .then_some(Rec::Gone { hash: *hash }),
        }
    }

    /// The node has no such invoice (a lookup said so): the ticket is finished and paid nothing.
    pub fn node_has_none(&mut self, hash: &Hash) -> Option<Rec> {
        self.remove(hash, false)
            .then_some(Rec::Gone { hash: *hash })
    }

    fn remove(&mut self, hash: &Hash, used: bool) -> bool {
        let Some(t) = self.tickets.remove(hash) else {
            return false;
        };
        if let Some(s) = self.sessions.get_mut(&t.session) {
            s.live = s.live.saturating_sub(1);
            if s.pledge == Some(*hash) {
                s.pledge = None;
                self.dirty.insert(t.session.clone());
            }
            if used {
                if s.used.len() >= USED_KEPT {
                    s.used.pop_front();
                }
                s.used.push_back(*hash);
            }
        }
        true
    }

    /// A checkable route: pledge a locked ticket for a piece served before its secret. One at a
    /// time, and only by a session that owes nothing.
    pub fn pledge(
        &mut self,
        session: &str,
        hash: &Hash,
        height: Option<u32>,
    ) -> Result<(), Refusal> {
        let s = self.sessions.get(session).ok_or(Refusal::SessionUnknown)?;
        if s.pledge == Some(*hash) {
            return Ok(());
        }
        if s.pledge.is_some() || s.owed_msat() > 0 {
            return Err(Refusal::PledgeOutstanding);
        }
        let t = match self.tickets.get(hash) {
            Some(t) if t.session == session => t,
            _ if s.used.contains(hash) => return Err(Refusal::TicketUsed),
            _ => return Err(Refusal::TicketUnknown),
        };
        if t.state != TicketState::Accepted || t.paid_msat < self.caps.ticket_msat {
            return Err(Refusal::TicketNotLocked);
        }
        Self::outside_margin(&self.caps, t, height)?;
        if let Some(s) = self.sessions.get_mut(session) {
            s.pledge = Some(*hash);
        }
        self.dirty.insert(session.to_string());
        Ok(())
    }

    /// What `session` can be charged now: its balance, and on a checkable route what is left of
    /// one pledged ticket.
    pub fn chargeable(&self, session: &str, on_pledge: bool) -> u64 {
        let Some(s) = self.sessions.get(session) else {
            return 0;
        };
        let credit = if on_pledge && s.pledge.is_some() {
            self.caps.ticket_msat
        } else {
            0
        };
        s.released_msat
            .saturating_add(credit)
            .saturating_sub(s.spent_msat)
    }

    /// Take `msat` for a piece about to be served. Nothing is taken when it is not all there.
    pub fn charge(
        &mut self,
        session: &str,
        msat: u64,
        on_pledge: bool,
        now: u64,
    ) -> Result<(), Refusal> {
        if msat > self.chargeable(session, on_pledge) {
            return Err(Refusal::BalanceShort);
        }
        let s = self
            .sessions
            .get_mut(session)
            .ok_or(Refusal::SessionUnknown)?;
        s.spent_msat = s
            .spent_msat
            .checked_add(msat)
            .ok_or(Refusal::BalanceShort)?;
        s.last_paid = now;
        if msat > 0 {
            self.dirty.insert(session.to_string());
        }
        Ok(())
    }

    /// Give back a charge that bought nothing (the upstream failed, the write failed).
    pub fn refund(&mut self, session: &str, msat: u64) {
        if let Some(s) = self.sessions.get_mut(session) {
            s.spent_msat = s.spent_msat.saturating_sub(msat);
            if msat > 0 {
                self.dirty.insert(session.to_string());
            }
        }
    }

    /// A metered response opens (+1) or ends (-1): the session is not idle in between.
    pub fn response(&mut self, session: &str, open: bool, now: u64) {
        if let Some(s) = self.sessions.get_mut(session) {
            s.open_responses = if open {
                s.open_responses.saturating_add(1)
            } else {
                s.open_responses.saturating_sub(1)
            };
            s.last_paid = now;
        }
    }

    // --- cancel, and the janitor ------------------------------------------------------------------

    /// The tickets of `session` the buyer may have cancelled: those named (all when `None`), not
    /// being settled, and not the pledge of a piece that is still owed.
    pub fn cancellable(&self, session: &str, which: Option<&[Hash]>) -> Vec<Hash> {
        let Some(s) = self.sessions.get(session) else {
            return vec![];
        };
        let owed = s.owed_msat() > 0;
        let mut v: Vec<Hash> = self
            .tickets
            .iter()
            .filter(|(h, t)| {
                t.session == session
                    && t.state != TicketState::Settling
                    && !(owed && s.pledge == Some(**h))
            })
            .filter(|(h, _)| which.is_none_or(|w| w.contains(h)))
            .map(|(h, _)| *h)
            .collect();
        v.sort();
        v
    }

    /// What the passing of time and blocks asks for: tickets to cancel, sessions to forget.
    pub fn sweep(&mut self, now: u64, height: Option<u32>) -> Sweep {
        let caps = self.caps.clone();
        let mut out = Sweep::default();
        let quiet = |s: &Session| {
            let limit = if s.released_msat == 0 {
                caps.first_use_secs
            } else {
                caps.idle_secs
            };
            s.open_responses == 0 && now.saturating_sub(s.last_paid) > limit
        };
        for (h, t) in &self.tickets {
            if t.state == TicketState::Settling {
                continue;
            }
            let unpaid =
                t.state == TicketState::Open && now.saturating_sub(t.issued_at) > caps.unpaid_secs;
            let expiring = t.state == TicketState::Accepted
                && height.is_some()
                && Self::outside_margin(&caps, t, height).is_err();
            let idle = self.sessions.get(&t.session).is_none_or(quiet);
            if unpaid || expiring || idle {
                out.cancel.push(*h);
            }
        }
        out.cancel.sort();
        let gone: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| {
                s.live == 0
                    && quiet(s)
                    && (s.balance_msat() == 0 || now.saturating_sub(s.last_paid) > caps.keep_secs)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in gone {
            self.sessions.remove(&id);
            self.dirty.remove(&id);
            out.recs.push(Rec::Drop { session: id });
        }
        out
    }

    // --- the journal ------------------------------------------------------------------------------

    /// The counters of every session that changed since the last call.
    pub fn take_marks(&mut self) -> Vec<Rec> {
        let mut ids: Vec<String> = self.dirty.drain().collect();
        ids.sort();
        ids.iter().filter_map(|id| self.mark(id)).collect()
    }

    fn mark(&self, id: &str) -> Option<Rec> {
        let s = self.sessions.get(id)?;
        Some(Rec::Mark {
            session: id.to_string(),
            next_seq: s.next_seq,
            spent_msat: s.spent_msat,
            pledge: s.pledge,
        })
    }

    /// The whole book as records: what a compacted journal holds.
    pub fn snapshot(&self) -> Vec<Rec> {
        let mut out = vec![];
        for (id, s) in &self.sessions {
            out.push(Rec::Session {
                id: id.clone(),
                key: s.key,
                addr: s.addr.clone(),
            });
        }
        // a session's released sum is carried as one finished ticket under a name of its own
        for (id, s) in &self.sessions {
            if s.released_msat > 0 {
                out.push(Rec::Ticket {
                    hash: carry_hash(id),
                    session: id.clone(),
                    prepaid: false,
                });
                out.push(Rec::Released {
                    hash: carry_hash(id),
                    msat: s.released_msat,
                });
            }
        }
        for h in self.unfinished() {
            out.push(Rec::Ticket {
                hash: h,
                session: self.tickets[&h].session.clone(),
                prepaid: self.tickets[&h].prepaid,
            });
        }
        for id in self.sessions.keys() {
            out.extend(self.mark(id));
        }
        out
    }

    /// The book a journal describes. Every unfinished ticket comes back `Open`: only the node can
    /// say it is locked. `Err`: the journal does not hold together, and nothing is served on it.
    pub fn restore(caps: Caps, recs: &[Rec], now: u64) -> Result<Self, Error> {
        Self::replay(caps, recs, now).map_err(Error::Journal)
    }

    fn replay(caps: Caps, recs: &[Rec], now: u64) -> Result<Self, String> {
        let mut b = Self::new(caps);
        for r in recs {
            match r {
                Rec::Session { id, key, addr } => {
                    b.sessions.insert(
                        id.clone(),
                        Session {
                            key: *key,
                            addr: addr.clone(),
                            next_seq: 0,
                            released_msat: 0,
                            spent_msat: 0,
                            pledge: None,
                            last_paid: now,
                            open_responses: 0,
                            live: 0,
                            used: VecDeque::new(),
                        },
                    );
                }
                Rec::Ticket {
                    hash,
                    session,
                    prepaid,
                } => {
                    let s = b
                        .sessions
                        .get_mut(session)
                        .ok_or_else(|| format!("a ticket of unknown session {session}"))?;
                    if b.tickets
                        .insert(
                            *hash,
                            Ticket {
                                session: session.clone(),
                                state: TicketState::Open,
                                paid_msat: 0,
                                expiry_height: None,
                                issued_at: now,
                                prepaid: *prepaid,
                            },
                        )
                        .is_none()
                    {
                        s.live += 1;
                    }
                }
                Rec::Gone { hash } => {
                    b.remove(hash, false);
                }
                Rec::Released { hash, msat } => {
                    // a ticket whose session was dropped since is dropped with it
                    if let Some(t) = b.tickets.get(hash) {
                        let session = t.session.clone();
                        b.remove(hash, true);
                        if let Some(s) = b.sessions.get_mut(&session) {
                            s.released_msat = s
                                .released_msat
                                .checked_add(*msat)
                                .ok_or("released sum overflows")?;
                        }
                    }
                }
                Rec::Mark {
                    session,
                    next_seq,
                    spent_msat,
                    pledge,
                } => {
                    if let Some(s) = b.sessions.get_mut(session) {
                        s.next_seq = *next_seq;
                        s.spent_msat = *spent_msat;
                        s.pledge = pledge
                            .filter(|p| b.tickets.get(p).is_some_and(|t| &t.session == session));
                    }
                }
                Rec::Drop { session } => {
                    b.sessions.remove(session);
                    b.tickets.retain(|_, t| &t.session != session);
                }
            }
        }
        for s in b.sessions.values_mut() {
            s.used.clear();
        }
        b.dirty.clear();
        Ok(b)
    }
}

/// The name under which a snapshot carries a session's released sum: not a payment hash anyone can
/// lock (it would need a preimage of a value fixed by the session id), and never sent to the node.
fn carry_hash(session: &str) -> Hash {
    xbt_primitives::hash::tagged_hash("xbt-gateway/carry", session.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn caps() -> Caps {
        Caps {
            ticket_msat: 1_000_000,
            max_tickets: 8,
            max_sessions: 4,
            sessions_per_address: 2,
            max_kept_sessions: 6,
            max_held: 20,
            slots_retry_secs: 30,
            margin_blocks: 24,
            unpaid_secs: 75,
            first_use_secs: 60,
            idle_secs: 300,
            keep_secs: 86_400,
        }
    }

    fn secret(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn hash(n: u8) -> Hash {
        ticket_hash(&secret(n))
    }

    fn ent(n: u8) -> [u8; 48] {
        [n; 48]
    }

    fn held(expiry: u32) -> Invoice {
        Invoice {
            state: InvoiceState::Accepted,
            paid_msat: 1_000_000,
            expiry_height: Some(expiry),
            accept_height: Some(expiry - 43),
        }
    }

    /// A session with tickets `ns` locked at expiry 200.
    fn open(b: &mut Book, e: u8, ns: &[u8]) -> String {
        let hashes: Vec<Hash> = ns.iter().map(|n| hash(*n)).collect();
        let g = b.lock("a", None, &hashes, false, &ent(e), 0).unwrap();
        for h in &g.issue {
            assert_eq!(b.issued(h, true), None);
            b.node_update(h, &held(200));
        }
        g.session
    }

    #[test]
    fn a_secret_is_taken_only_for_a_ticket_seen_accepted_in_its_own_session() {
        let mut b = Book::new(caps());
        let g = b
            .lock("a", None, &[hash(1), hash(2)], false, &ent(1), 0)
            .unwrap();
        let s = g.session.clone();
        assert_eq!(g.key, Some([1u8; 32]));
        assert_eq!(g.issue, vec![hash(1), hash(2)]);
        // issued, not paid
        assert_eq!(
            b.present(&s, &secret(1), Some(100)),
            Err(Refusal::TicketNotLocked)
        );
        // the node holds less than the ticket
        b.node_update(
            &hash(1),
            &Invoice {
                paid_msat: 999_999,
                ..held(200)
            },
        );
        assert_eq!(
            b.present(&s, &secret(1), Some(100)),
            Err(Refusal::TicketNotLocked)
        );
        b.node_update(&hash(1), &held(200));
        // no ticket of this session: unknown, also when another session holds it
        let other = open(&mut b, 2, &[3]);
        assert_eq!(
            b.present(&s, &secret(3), Some(100)),
            Err(Refusal::TicketUnknown)
        );
        assert_eq!(
            b.present(&other, &secret(1), Some(100)),
            Err(Refusal::TicketUnknown)
        );
        assert_eq!(
            b.present(&s, &secret(9), Some(100)),
            Err(Refusal::TicketUnknown)
        );
        assert_eq!(
            b.present("nobody", &secret(1), Some(100)),
            Err(Refusal::SessionUnknown)
        );
        // locked, whole, in its session
        assert_eq!(b.present(&s, &secret(1), Some(100)), Ok(hash(1)));
        // the node stops holding one that was accepted: no longer usable
        b.node_update(
            &hash(3),
            &Invoice {
                state: InvoiceState::Open,
                paid_msat: 0,
                expiry_height: None,
                accept_height: None,
            },
        );
        assert_eq!(
            b.present(&other, &secret(3), Some(100)),
            Err(Refusal::TicketNotLocked)
        );
    }

    #[test]
    fn a_ticket_is_credited_once_however_the_news_arrives() {
        let mut b = Book::new(caps());
        let s = open(&mut b, 1, &[1, 2]);
        assert_eq!(b.present(&s, &secret(1), Some(100)), Ok(hash(1)));
        // two requests with one secret: the second is refused while the first is at the node
        assert_eq!(
            b.present(&s, &secret(1), Some(100)),
            Err(Refusal::TicketUsed)
        );
        assert_eq!(
            b.settled(&hash(1), None),
            Some(Rec::Released {
                hash: hash(1),
                msat: 1_000_000
            })
        );
        // the call's success and the node's stream both report it: one credit
        assert_eq!(b.settled(&hash(1), None), None);
        assert_eq!(
            b.node_update(
                &hash(1),
                &Invoice {
                    state: InvoiceState::Settled,
                    ..held(200)
                }
            ),
            None
        );
        assert_eq!(b.session(&s).unwrap().released_msat, 1_000_000);
        assert_eq!(
            b.present(&s, &secret(1), Some(100)),
            Err(Refusal::TicketUsed)
        );
        // the stream alone (a settle whose answer was lost, or a restart): credited, once
        assert!(b
            .node_update(
                &hash(2),
                &Invoice {
                    state: InvoiceState::Settled,
                    ..held(200)
                }
            )
            .is_some());
        assert!(b
            .node_update(
                &hash(2),
                &Invoice {
                    state: InvoiceState::Settled,
                    ..held(200)
                }
            )
            .is_none());
        assert_eq!(b.session(&s).unwrap().released_msat, 2_000_000);
        assert_eq!(b.session(&s).unwrap().live(), 0);
        assert_eq!(b.held(), 0);
        // an overpaid ticket is one ticket
        let t = open(&mut b, 2, &[5]);
        b.node_update(
            &hash(5),
            &Invoice {
                state: InvoiceState::Settled,
                paid_msat: 1_900_000,
                expiry_height: Some(200),
                accept_height: None,
            },
        );
        assert_eq!(b.session(&t).unwrap().released_msat, 1_000_000);
    }

    #[test]
    fn a_settle_with_no_answer_leaves_the_ticket_for_the_node_to_decide() {
        let mut b = Book::new(caps());
        let s = open(&mut b, 1, &[1]);
        b.present(&s, &secret(1), Some(100)).unwrap();
        b.settle_unanswered(&hash(1));
        assert_eq!(b.session(&s).unwrap().released_msat, 0);
        // the buyer may present it again
        assert_eq!(b.present(&s, &secret(1), Some(100)), Ok(hash(1)));
        b.settle_unanswered(&hash(1));
        // or the node cancels it: no credit
        assert_eq!(
            b.node_update(
                &hash(1),
                &Invoice {
                    state: InvoiceState::Canceled,
                    paid_msat: 0,
                    expiry_height: None,
                    accept_height: None
                }
            ),
            Some(Rec::Gone { hash: hash(1) })
        );
        assert_eq!(
            b.present(&s, &secret(1), Some(100)),
            Err(Refusal::TicketUnknown)
        );
        assert_eq!(b.session(&s).unwrap().released_msat, 0);
    }

    #[test]
    fn a_secret_is_taken_only_outside_the_margin_at_a_known_height() {
        let mut b = Book::new(caps());
        let s = open(&mut b, 1, &[1, 2, 3, 4]);
        assert_eq!(b.present(&s, &secret(1), None), Err(Refusal::HeightUnknown));
        // expiry 200, margin 24: usable while more than 24 blocks are left
        assert_eq!(
            b.present(&s, &secret(1), Some(176)),
            Err(Refusal::TicketExpiring)
        );
        assert_eq!(
            b.present(&s, &secret(1), Some(200)),
            Err(Refusal::TicketExpiring)
        );
        assert_eq!(
            b.present(&s, &secret(1), Some(201)),
            Err(Refusal::TicketExpiring)
        );
        assert_eq!(
            b.present(&s, &secret(1), Some(u32::MAX)),
            Err(Refusal::TicketExpiring)
        );
        assert_eq!(b.present(&s, &secret(1), Some(175)), Ok(hash(1)));
        // a refusal marks nothing: the ticket is still there for a cancel
        let mut rest = vec![hash(2), hash(3), hash(4)];
        rest.sort();
        assert_eq!(b.cancellable(&s, None), rest);
    }

    #[test]
    fn a_charge_is_taken_only_from_what_was_released() {
        let mut b = Book::new(caps());
        let s = open(&mut b, 1, &[1]);
        assert_eq!(b.charge(&s, 1, false, 5), Err(Refusal::BalanceShort));
        assert_eq!(b.charge(&s, 0, false, 5), Ok(()));
        b.present(&s, &secret(1), Some(100)).unwrap();
        b.settled(&hash(1), None);
        assert_eq!(b.charge(&s, 600_000, false, 5), Ok(()));
        assert_eq!(b.charge(&s, 400_001, false, 5), Err(Refusal::BalanceShort));
        assert_eq!(
            b.session(&s).unwrap().spent_msat,
            600_000,
            "a refused charge takes nothing"
        );
        assert_eq!(b.charge(&s, 400_000, false, 5), Ok(()));
        assert_eq!(b.chargeable(&s, false), 0);
        b.refund(&s, 2500);
        assert_eq!(b.chargeable(&s, false), 2500);
        assert_eq!(b.charge(&s, u64::MAX, false, 5), Err(Refusal::BalanceShort));
        assert_eq!(b.charge("nobody", 1, false, 5), Err(Refusal::BalanceShort));
    }

    #[test]
    fn a_checkable_route_serves_on_one_pledged_ticket_and_no_more() {
        let mut b = Book::new(caps());
        let s = open(&mut b, 1, &[1, 2]);
        // a pledge is a locked ticket of this session, outside its margin
        assert_eq!(
            b.pledge(&s, &hash(9), Some(100)),
            Err(Refusal::TicketUnknown)
        );
        assert_eq!(
            b.pledge(&s, &hash(1), Some(180)),
            Err(Refusal::TicketExpiring)
        );
        assert_eq!(b.pledge(&s, &hash(1), None), Err(Refusal::HeightUnknown));
        assert_eq!(b.pledge(&s, &hash(1), Some(100)), Ok(()));
        // it is credit on a checkable route only
        assert_eq!(b.chargeable(&s, false), 0);
        assert_eq!(b.charge(&s, 1, false, 5), Err(Refusal::BalanceShort));
        assert_eq!(b.charge(&s, 700_000, true, 5), Ok(()));
        assert_eq!(
            b.charge(&s, 300_001, true, 5),
            Err(Refusal::BalanceShort),
            "one ticket, no more"
        );
        // no second pledge while a piece is owed, and the pledged ticket cannot be cancelled away
        assert_eq!(
            b.pledge(&s, &hash(2), Some(100)),
            Err(Refusal::PledgeOutstanding)
        );
        assert_eq!(b.cancellable(&s, None), vec![hash(2)]);
        // the secret arrives: the debt is paid from the ticket
        b.present(&s, &secret(1), Some(100)).unwrap();
        b.settled(&hash(1), None);
        let sess = b.session(&s).unwrap();
        assert_eq!(
            (sess.pledge, sess.owed_msat(), sess.balance_msat()),
            (None, 0, 300_000)
        );
        // a pledged ticket that is cancelled leaves the debt: nothing more on credit until it is paid
        assert_eq!(b.pledge(&s, &hash(2), Some(100)), Ok(()));
        assert_eq!(b.charge(&s, 1_200_000, true, 5), Ok(()));
        b.node_update(
            &hash(2),
            &Invoice {
                state: InvoiceState::Canceled,
                paid_msat: 0,
                expiry_height: None,
                accept_height: None,
            },
        );
        let sess = b.session(&s).unwrap();
        assert_eq!((sess.pledge, sess.owed_msat()), (None, 900_000));
        assert_eq!(b.charge(&s, 1, true, 5), Err(Refusal::BalanceShort));
        let g = b
            .lock("a", Some(&s), &[hash(3)], false, &ent(0), 0)
            .unwrap();
        b.node_update(&g.issue[0], &held(200));
        assert_eq!(
            b.pledge(&s, &hash(3), Some(100)),
            Err(Refusal::PledgeOutstanding)
        );
    }

    #[test]
    fn requests_are_authenticated_and_in_order() {
        let mut b = Book::new(caps());
        let s = open(&mut b, 1, &[1]);
        assert_eq!(
            b.authenticate("nobody", 0, |_| true),
            Err(Refusal::SessionUnknown)
        );
        assert_eq!(b.authenticate(&s, 0, |_| false), Err(Refusal::BadAuth));
        assert_eq!(b.authenticate(&s, 1, |_| true), Err(Refusal::BadSeq(0)));
        assert_eq!(b.authenticate(&s, 0, |k| k == &[1u8; 32]), Ok(()));
        // a replay of the same request
        assert_eq!(b.authenticate(&s, 0, |_| true), Err(Refusal::BadSeq(1)));
        assert_eq!(b.authenticate(&s, 1, |_| true), Ok(()));
        // a bad MAC uses up nothing
        assert_eq!(b.authenticate(&s, 2, |_| false), Err(Refusal::BadAuth));
        assert_eq!(b.session(&s).unwrap().next_seq, 2);
    }

    #[test]
    fn locks_are_bounded_per_session_per_address_and_in_all() {
        let mut b = Book::new(caps());
        let many: Vec<Hash> = (1..=20).map(hash).collect();
        // per session: 8 of 20, in order
        let g = b.lock("a", None, &many, false, &ent(1), 0).unwrap();
        assert_eq!(g.issue, many[..8].to_vec());
        assert_eq!(
            b.lock("a", Some(&g.session), &many[8..], false, &ent(0), 0),
            Err(Refusal::TooManyTickets)
        );
        // a hash already in the book is skipped, in any session
        assert_eq!(
            b.lock("a", None, &many[..8], false, &ent(2), 0),
            Err(Refusal::TooManyTickets)
        );
        assert_eq!(
            b.sessions(),
            1,
            "a session that was granted nothing is not made"
        );
        // a ticket that finishes frees its place
        b.node_update(
            &many[0],
            &Invoice {
                state: InvoiceState::Canceled,
                paid_msat: 0,
                expiry_height: None,
                accept_height: None,
            },
        );
        assert_eq!(
            b.lock(
                "a",
                Some(&g.session),
                &[hash(30), hash(31)],
                false,
                &ent(0),
                0
            )
            .unwrap()
            .issue,
            vec![hash(30)]
        );
        // per address: 2 sessions
        let g2 = b
            .lock(
                "a",
                None,
                &[hash(40), hash(40), hash(41)],
                false,
                &ent(2),
                0,
            )
            .unwrap();
        assert_eq!(
            g2.issue,
            vec![hash(40), hash(41)],
            "a hash named twice is one ticket"
        );
        assert_eq!(
            b.lock("a", None, &[hash(50)], false, &ent(3), 0),
            Err(Refusal::TooManySessions)
        );
        // in all: 20 held (8 + 2 so far)
        let g3 = b
            .lock(
                "b",
                None,
                &(60..80).map(hash).collect::<Vec<_>>(),
                false,
                &ent(3),
                0,
            )
            .unwrap();
        assert_eq!(g3.issue.len(), 8);
        let g4 = b
            .lock(
                "b",
                None,
                &(80..100).map(hash).collect::<Vec<_>>(),
                false,
                &ent(4),
                0,
            )
            .unwrap();
        assert_eq!(g4.issue.len(), 2, "20 in all");
        assert_eq!(b.held(), 20);
        // sessions in all: 4
        assert_eq!(
            b.lock("c", None, &[hash(100)], false, &ent(5), 0),
            Err(Refusal::TooManySessions)
        );
        // a refill of an existing session at the total cap: a wait, not a fault of the session
        assert_eq!(
            b.lock("b", Some(&g4.session), &[hash(101)], false, &ent(0), 0),
            Err(Refusal::SlotsShort(30))
        );
        // a session at its own cap is told that, whatever the total is
        assert_eq!(
            b.lock("b", Some(&g3.session), &[hash(101)], false, &ent(0), 0),
            Err(Refusal::TooManyTickets)
        );
        assert_eq!(
            b.lock("b", Some("nobody"), &[hash(101)], false, &ent(0), 0),
            Err(Refusal::SessionUnknown)
        );
        // a ticket the node would not issue leaves the book, and a session left with none was never made
        assert_eq!(
            b.issued(&g4.issue[0], false),
            Some(Rec::Gone { hash: g4.issue[0] })
        );
        assert_eq!(b.held(), 19);
        assert_eq!(b.issued(&g4.issue[0], false), None);
        assert_eq!(b.forget_unused(&g4.session), None, "it still has a ticket");
        b.issued(&g4.issue[1], false);
        assert_eq!(
            b.forget_unused(&g4.session),
            Some(Rec::Drop {
                session: g4.session.clone()
            })
        );
        assert_eq!(b.sessions(), 3);
        assert_eq!(b.forget_unused(&g3.session), None);
        // a session that only keeps a balance takes no place, until it locks again
        let mut k = Book::new(Caps {
            max_sessions: 1,
            sessions_per_address: 0,
            ..caps()
        });
        let first = open(&mut k, 1, &[1]);
        assert_eq!(
            k.lock("a", None, &[hash(2)], false, &ent(2), 0),
            Err(Refusal::TooManySessions)
        );
        k.present(&first, &secret(1), Some(100)).unwrap();
        k.settled(&hash(1), None);
        let second = k
            .lock("a", None, &[hash(2)], false, &ent(2), 0)
            .unwrap()
            .session;
        assert_eq!(
            k.lock("a", Some(&first), &[hash(3)], false, &ent(0), 0),
            Err(Refusal::TooManySessions),
            "the place is taken now"
        );
        k.node_update(
            &hash(2),
            &Invoice {
                state: InvoiceState::Canceled,
                paid_msat: 0,
                expiry_height: None,
                accept_height: None,
            },
        );
        assert_eq!(
            k.lock("a", Some(&first), &[hash(3)], false, &ent(0), 0)
                .unwrap()
                .issue,
            vec![hash(3)]
        );
        assert_eq!(
            k.lock("a", Some(&second), &[hash(4)], false, &ent(0), 0),
            Err(Refusal::TooManySessions)
        );
        // and sessions in all are bounded too
        let mut all = Book::new(Caps {
            max_sessions: 1,
            sessions_per_address: 0,
            max_kept_sessions: 2,
            ..caps()
        });
        for n in 1..=2u8 {
            let s = open(&mut all, n, &[n]);
            all.present(&s, &secret(n), Some(100)).unwrap();
            all.settled(&hash(n), None);
        }
        assert_eq!(
            all.lock("a", None, &[hash(9)], false, &ent(9), 0),
            Err(Refusal::TooManySessions)
        );
        // no cap per address when it is 0
        let mut open_house = Book::new(Caps {
            sessions_per_address: 0,
            ..caps()
        });
        for n in 0..4 {
            open_house
                .lock("a", None, &[hash(n)], false, &ent(n + 1), 0)
                .unwrap();
        }
    }

    #[test]
    fn the_janitor_cancels_what_can_no_longer_be_used_and_forgets_quiet_sessions() {
        let none = Invoice {
            state: InvoiceState::Canceled,
            paid_msat: 0,
            expiry_height: None,
            accept_height: None,
        };
        let mut b = Book::new(caps());
        // s releases one ticket at t=5 and keeps one locked
        let s = open(&mut b, 1, &[1, 2]);
        b.present(&s, &secret(1), Some(100)).unwrap();
        b.settled(&hash(1), None);
        b.charge(&s, 1, false, 5).unwrap();
        let g = b
            .lock("a", Some(&s), &[hash(3)], false, &ent(0), 10)
            .unwrap();
        assert_eq!(g.issue, vec![hash(3)]);
        assert_eq!(b.sweep(20, Some(100)), Sweep::default());
        // unpaid for longer than the invoice lives
        assert_eq!(b.sweep(85, Some(100)).cancel, Vec::<Hash>::new());
        assert_eq!(b.sweep(86, Some(100)).cancel, vec![hash(3)]);
        b.node_update(&hash(3), &none);
        // inside the margin: no longer usable, so given back
        assert_eq!(b.sweep(90, Some(175)).cancel, Vec::<Hash>::new());
        assert_eq!(b.sweep(90, Some(176)).cancel, vec![hash(2)]);
        assert_eq!(
            b.sweep(90, None).cancel,
            Vec::<Hash>::new(),
            "an unknown height cancels nothing on its own"
        );
        // t never releases anything: its tickets are given back after first_use_secs
        let g = b.lock("b", None, &[hash(7)], false, &ent(2), 100).unwrap();
        let t = g.session;
        b.node_update(&hash(7), &held(200));
        assert_eq!(b.sweep(160, Some(100)).cancel, Vec::<Hash>::new());
        assert_eq!(b.sweep(161, Some(100)).cancel, vec![hash(7)]);
        // a ticket being settled is left alone
        b.present(&t, &secret(7), Some(100)).unwrap();
        assert_eq!(b.sweep(161, Some(190)).cancel, vec![hash(2)]);
        b.settle_unanswered(&hash(7));
        // s has released: idle after idle_secs from its last paid request, unless a response is open
        assert!(!b.sweep(305, Some(100)).cancel.contains(&hash(2)));
        assert!(b.sweep(306, Some(100)).cancel.contains(&hash(2)));
        b.response(&s, true, 306);
        assert!(!b.sweep(10_000, Some(100)).cancel.contains(&hash(2)));
        b.response(&s, false, 10_000);
        assert!(b.sweep(10_301, Some(100)).cancel.contains(&hash(2)));
        // forgotten: nothing locked, quiet, and no balance; with a balance, after keep_secs
        b.node_update(&hash(7), &none);
        b.node_update(&hash(2), &none);
        let sw = b.sweep(10_400, Some(100));
        assert_eq!(sw.recs, vec![Rec::Drop { session: t.clone() }]);
        assert!(b.session(&s).is_some(), "a balance is kept");
        assert_eq!(b.sweep(10_000 + 86_400, Some(100)).recs, vec![]);
        let sw = b.sweep(10_000 + 86_401, Some(100));
        assert_eq!(sw.recs, vec![Rec::Drop { session: s.clone() }]);
        assert_eq!(b.sessions(), 0);
        assert_eq!(
            b.take_marks(),
            vec![],
            "a forgotten session leaves no counters to write"
        );
    }

    #[test]
    fn a_restart_keeps_sessions_counters_and_tickets_and_trusts_only_the_node_for_locked() {
        let mut b = Book::new(caps());
        let mut journal: Vec<Rec> = vec![];
        let g = b
            .lock("a", None, &[hash(1), hash(2), hash(3)], false, &ent(1), 0)
            .unwrap();
        journal.extend(g.recs.clone());
        let s = g.session;
        for h in &g.issue {
            b.node_update(h, &held(200));
        }
        b.authenticate(&s, 0, |_| true).unwrap();
        b.present(&s, &secret(1), Some(100)).unwrap();
        journal.extend(b.settled(&hash(1), None));
        b.charge(&s, 2500, false, 5).unwrap();
        b.pledge(&s, &hash(2), Some(100)).unwrap();
        journal.extend(b.take_marks());
        assert_eq!(b.take_marks(), vec![], "nothing changed since");
        // through JSON, as the file holds it
        let lines: Vec<Rec> = journal
            .iter()
            .map(|r| Rec::from_json(&r.to_json()).unwrap())
            .collect();
        assert_eq!(lines, journal);
        for (label, recs) in [("journal", lines), ("snapshot", b.snapshot())] {
            let r = Book::restore(caps(), &recs, 1000).unwrap();
            let sess = r.session(&s).unwrap();
            assert_eq!(
                (
                    sess.key,
                    sess.next_seq,
                    sess.released_msat,
                    sess.spent_msat,
                    sess.pledge,
                    sess.live()
                ),
                ([1u8; 32], 1, 1_000_000, 2500, Some(hash(2)), 2),
                "{label}"
            );
            assert_eq!(r.unfinished(), b.unfinished(), "{label}");
            // locked before the restart, but only the node can say so now
            let mut r = r;
            assert_eq!(
                r.present(&s, &secret(2), Some(100)),
                Err(Refusal::TicketNotLocked),
                "{label}"
            );
            r.node_update(&hash(2), &held(200));
            assert_eq!(r.present(&s, &secret(2), Some(100)), Ok(hash(2)), "{label}");
            // settled while the gateway was away: credited from the node's word
            assert!(r
                .node_update(
                    &hash(3),
                    &Invoice {
                        state: InvoiceState::Settled,
                        ..held(200)
                    }
                )
                .is_some());
            assert_eq!(r.session(&s).unwrap().released_msat, 2_000_000, "{label}");
            // the node has no such invoice: finished, nothing paid
            let g = r
                .lock("a", Some(&s), &[hash(8)], false, &ent(0), 0)
                .unwrap();
            assert_eq!(
                r.node_has_none(&g.issue[0]),
                Some(Rec::Gone { hash: hash(8) }),
                "{label}"
            );
        }
        // an older journal (a restore from backup): the node's word still decides what was released
        let old: Vec<Rec> = g.recs.clone();
        let mut r = Book::restore(caps(), &old, 1000).unwrap();
        assert_eq!(r.session(&s).unwrap().next_seq, 0);
        r.node_update(
            &hash(1),
            &Invoice {
                state: InvoiceState::Settled,
                ..held(200)
            },
        );
        assert_eq!(r.session(&s).unwrap().released_msat, 1_000_000);
        assert_eq!(
            r.present(&s, &secret(1), Some(100)),
            Err(Refusal::TicketUsed)
        );
        // a journal that does not hold together is not loaded
        assert!(Book::restore(
            caps(),
            &[Rec::Ticket {
                hash: hash(1),
                session: "nobody".into(),
                prepaid: false,
            }],
            0
        )
        .is_err());
        assert_eq!(Rec::from_json(&json!({"t": "future"})), None);
        assert_eq!(
            Rec::from_json(&json!({"t": "mark", "session": "s", "seq": 1, "spent": "2"})),
            None
        );
    }

    fn node_says(state: InvoiceState, paid_msat: u64) -> Invoice {
        Invoice {
            state,
            paid_msat,
            expiry_height: None,
            accept_height: None,
        }
    }

    #[test]
    fn held_tickets_stop_at_the_cap_and_the_next_buyer_is_told_to_wait() {
        // the shipped shape: 2 a session, 15 in all (half of a 30-slot channel)
        let mut b = Book::new(Caps {
            max_tickets: 2,
            max_sessions: 30,
            sessions_per_address: 0,
            max_kept_sessions: 100,
            max_held: 15,
            ..caps()
        });
        let mut n = 0u8;
        let mut two = || {
            n += 2;
            [hash(n - 1), hash(n)]
        };
        let mut sessions = vec![];
        for e in 1..=7u8 {
            let g = b.lock("a", None, &two(), false, &ent(e), 0).unwrap();
            assert_eq!(g.issue.len(), 2);
            sessions.push(g.session);
        }
        assert_eq!(b.held(), 14, "7 buyers at 2 each");
        // the eighth gets the one place that is left, the ninth none and no session
        let g8 = b.lock("a", None, &two(), false, &ent(8), 0).unwrap();
        assert_eq!((g8.issue.len(), b.held()), (1, 15));
        assert_eq!(
            b.lock("a", None, &two(), false, &ent(9), 0),
            Err(Refusal::SlotsShort(30))
        );
        assert_eq!(b.sessions(), 8, "a buyer told to wait has no session");
        assert_eq!(Refusal::SlotsShort(30).code(), "slots_short");
        // a ticket that is released or cancelled frees its place
        b.node_update(&hash(1), &node_says(InvoiceState::Canceled, 0));
        assert_eq!(
            b.lock("a", None, &two(), false, &ent(9), 0)
                .unwrap()
                .issue
                .len(),
            1
        );
        // the cap can be moved while the gateway runs: what is held stays, nothing more is issued
        b.set_max_held(4);
        assert_eq!(b.held(), 15);
        assert_eq!(
            b.lock("a", Some(&sessions[0]), &two(), false, &ent(0), 0),
            Err(Refusal::SlotsShort(30))
        );
    }

    #[test]
    fn a_prepaid_ticket_holds_no_slot_and_is_credited_once_when_the_node_shows_it_paid() {
        let mut b = Book::new(Caps {
            max_tickets: 2,
            max_held: 1,
            ..caps()
        });
        // the one held place is taken
        let held_session = open(&mut b, 1, &[1]);
        assert_eq!(
            b.lock("b", None, &[hash(2)], false, &ent(2), 0),
            Err(Refusal::SlotsShort(30))
        );
        // a prepaid ticket is issued all the same, and is not counted as held
        let g = b.lock("b", None, &[hash(2)], true, &ent(2), 0).unwrap();
        assert_eq!(
            g.recs.last(),
            Some(&Rec::Ticket {
                hash: hash(2),
                session: g.session.clone(),
                prepaid: true
            })
        );
        assert_eq!((b.held(), b.prepaid_open()), (1, 1));
        assert_eq!(b.presented_kind(&g.session, &secret(2)), Ok(true));
        assert_eq!(b.presented_kind(&held_session, &secret(1)), Ok(false));
        assert_eq!(
            b.presented_kind(&held_session, &secret(2)),
            Err(Refusal::TicketUnknown),
            "another session's ticket"
        );
        // a preimage is no settle order for it: only the node's word credits
        assert_eq!(
            b.present(&g.session, &secret(2), Some(100)),
            Err(Refusal::TicketNotLocked)
        );
        // unpaid, or in the moment between arrival and settle: nothing
        assert_eq!(
            b.node_update(&hash(2), &node_says(InvoiceState::Open, 0)),
            None
        );
        assert_eq!(
            b.node_update(&hash(2), &node_says(InvoiceState::Accepted, 1_000_000)),
            None
        );
        assert_eq!(b.session(&g.session).unwrap().released_msat, 0);
        assert_eq!(b.ticket(&hash(2)).unwrap().state, TicketState::Open);
        // paid: credited, and gone from the book
        assert_eq!(
            b.node_update(&hash(2), &node_says(InvoiceState::Settled, 1_000_000)),
            Some(Rec::Released {
                hash: hash(2),
                msat: 1_000_000
            })
        );
        assert_eq!(b.session(&g.session).unwrap().balance_msat(), 1_000_000);
        assert_eq!(
            b.node_update(&hash(2), &node_says(InvoiceState::Settled, 1_000_000)),
            None,
            "once"
        );
        assert_eq!(
            b.presented_kind(&g.session, &secret(2)),
            Err(Refusal::TicketUsed)
        );
        // held tickets of the session do not use up its prepaid ones, nor the other way round
        let mixed = b.lock("b", Some(&g.session), &[hash(20)], false, &ent(0), 0);
        assert_eq!(
            mixed,
            Err(Refusal::SlotsShort(30)),
            "the one held place is another session's"
        );
        // the session's own cap bounds what it can have issued and not paid
        let g2 = b
            .lock(
                "b",
                Some(&g.session),
                &[hash(3), hash(4), hash(5)],
                true,
                &ent(0),
                0,
            )
            .unwrap();
        assert_eq!(g2.issue.len(), 2);
        assert_eq!(
            b.lock("b", Some(&g.session), &[hash(6)], true, &ent(0), 0),
            Err(Refusal::TooManyTickets)
        );
        // one that arrived short is no ticket and credits nothing
        assert_eq!(
            b.node_update(&hash(3), &node_says(InvoiceState::Settled, 999_999)),
            Some(Rec::Gone { hash: hash(3) })
        );
        assert_eq!(b.session(&g.session).unwrap().released_msat, 1_000_000);
        // an unpaid one is given up by the janitor like any unpaid ticket
        let sweep = b.sweep(76, Some(100));
        assert!(sweep.cancel.contains(&hash(4)));
        // a restart keeps which tickets are prepaid, and a journal from before reads as held
        let r = Book::restore(b.caps().clone(), &b.snapshot(), 0).unwrap();
        assert!(r.ticket(&hash(4)).unwrap().prepaid && !r.ticket(&hash(1)).unwrap().prepaid);
        let old = json!({"t": "ticket", "hash": hex::encode(hash(9)), "session": "s"});
        assert_eq!(
            Rec::from_json(&old),
            Some(Rec::Ticket {
                hash: hash(9),
                session: "s".into(),
                prepaid: false
            })
        );
        let rec = Rec::Ticket {
            hash: hash(9),
            session: "s".into(),
            prepaid: true,
        };
        assert_eq!(Rec::from_json(&rec.to_json()), Some(rec));
        let mut bent = old.clone();
        bent["prepaid"] = "yes".into();
        assert_eq!(Rec::from_json(&bent), None);
    }
}
