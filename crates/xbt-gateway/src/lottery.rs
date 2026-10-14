//! The lottery, the seller's side (`docs/TICKETS.md`, section 9): what a session of draws is, what
//! the runner may set, and when a buyer is served no further. No IO and no clock: the gateway
//! (`crate::gateway`) brings the node, the service and the time.
//!
//! A buyer in a lottery session locks nothing. Every piece it is served is a draw
//! ([`xbt402::lottery`]): most pay nothing, and a win is paid at once by an ordinary invoice. So
//! the seller goes first, and these are the rules that bound what going first can cost it:
//!
//! | Rule | Kept by | Who could break it, and the bound |
//! |---|---|---|
//! | A piece is served only inside the window. | [`Book::blocked`], and again at the moment a piece is marked ([`Book::serve`]): the pieces a session was served and gave no value for, the open ones and the voided ones together, are fewer than `window`. | A buyer that sends no values, or voids every piece: `window` pieces a session. |
//! | A win is paid within the grace or the buyer is served nothing more. | [`Book::blocked`]: no win unpaid for more than `grace_seconds`, or once `grace_pieces` pieces were served since it was drawn, and at most `max_unpaid_wins` unpaid at once. Paid is the node's word ([`Book::win_paid`]), never the buyer's. | A buyer that never pays: what it was served up to its first win, and the grace. |
//! | A void closes a piece and frees no place. | [`Book::blocked`]: a voided piece counts against the window for the rest of its session, and more than `max_voids` voids end the session. | A buyer that voids every piece: no more than one that sends nothing. |
//! | A route is drawn for only if its dearest piece is a small part of a win. | [`LotteryConfig::offers`], kept by the 402 and by every request ([`crate::gateway`]): the dearest piece times `max_odds_den` is at most the win. | A runner that prices a piece near a whole win: the window is then worth `window` wins to a buyer that gives no value. |
//! | Sessions are capped in all and per address, and a quiet one is forgotten. | [`Book::open`], [`Book::sweep`]. A session costs its chain: `chain_draws` hashes to make, and one value in every 1,024 and the block last read to keep (34 KiB at the default length). | Anyone, since opening a session needs no payment: `max_sessions` chains. |
//! | Closing a session does not give its place back while it owes. | [`Book::close`]: a session closed with pieces it gave no value for, or with wins unpaid, serves nothing more and keeps its place until it has been quiet for `first_use_secs`. | A buyer that opens, takes the window and closes, again and again: the same as one that never closes. |
//! | A chain is for one session. | [`Book::open`] makes each chain from fresh random bytes it is given, and keeps its seed nowhere but in the session and the lottery's journal. | Whoever can read the gateway's state directory: it can work out every draw to come. |
//! | A session outlives a restart, and no draw it revealed for is taken twice. | Every change is a record of the journal ([`Rec`], [`Book::take_log`]), written in the order it was made; the draws a reveal covers are on disk before the reveal leaves, and a win's invoice is on disk, by its hash, before the node is asked for it ([`crate::gateway`]). [`Book::restore`] makes the sessions again from it. | A power cut can lose what was written since the last sync: never a draw that was revealed for, nor a win's invoice the node was asked for. |
use std::collections::{HashMap, VecDeque};

use serde_json::{json, Map, Value};
use xbt402::lottery::{Chain, DrawError, Kind, Piece, PieceId, Seller, Taken, DEFAULT_CHAIN_DRAWS, MAX_CHAIN_DRAWS};
use xbt402::ticket::hex32;

use crate::config::{num, num32, obj};
use crate::node::Hash;
use crate::price::Price;

/// Final receipts of streamed answers kept per session, for `status`.
const FINALS_KEPT: usize = 8;
/// The values and the voids one `draw` request may carry.
pub const MAX_BATCH: usize = 64;

/// What the runner sets of the lottery (`lottery` in the config file). Absent: no lottery entry
/// is offered and the session endpoints answer 404.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LotteryConfig {
    /// What one win pays unless the buyer asks for less, and the least it may ask for.
    pub win_msat: u64,
    pub min_win_msat: u64,
    /// The final CLTV delta of a win's invoice.
    pub win_blocks: u32,
    /// Pieces served beyond the last one with a value or a void.
    pub window: u32,
    pub grace_seconds: u32,
    pub grace_pieces: u32,
    pub max_unpaid_wins: u32,
    /// How long an answer that is being sent stands still for a win's payment before it is cut
    /// short, in seconds, and never beyond that win's grace. An answer that stands still holds a
    /// connection and one of the server's threads.
    pub pay_wait_secs: u32,
    pub chain_draws: u32,
    /// The bytes of an answer that make one piece.
    pub piece_bytes: u64,
    pub max_sessions: u32,
    /// Sessions from one client address; 0 is no cap per address.
    pub sessions_per_address: u32,
    /// Pieces one session may void before it is served nothing more. A void never makes room
    /// in the window, so this is not what bounds the pieces a buyer gets for no value (`window`
    /// is): it is where a session whose window has narrowed is ended and another opened.
    pub max_voids: u32,
    /// A route is drawn for only if its dearest piece wins at most 1 time in this many: the
    /// piece's price times this is at most `win_msat`. The wallet's owner has the same cap.
    pub max_odds_den: u32,
    /// A session is forgotten after this many seconds without a request.
    pub idle_secs: u64,
    /// A session that has never given a value is forgotten after this many seconds.
    pub first_use_secs: u64,
    /// A win's invoice can be paid for this many seconds; an unpaid win gets a new one after. At
    /// most `grace_seconds` (5 where the grace is shorter): a buyer whose payment failed does not
    /// pay that invoice again, and waits for the next one, which must come before the grace ends.
    pub invoice_secs: u32,
}

impl LotteryConfig {
    /// `lottery` of the config file, read strictly: a key that is not known is an error.
    pub fn parse(v: &Value, ticket_blocks: u32) -> Result<Self, String> {
        let m = obj(
            v,
            "lottery",
            &[
                "win_msat",
                "min_win_msat",
                "win_blocks",
                "window",
                "grace_seconds",
                "grace_pieces",
                "max_unpaid_wins",
                "pay_wait_secs",
                "chain_draws",
                "piece_bytes",
                "max_sessions",
                "sessions_per_address",
                "max_voids",
                "max_odds_den",
                "idle_secs",
                "first_use_secs",
                "invoice_secs",
            ],
        )?;
        let c = Self::read(m, ticket_blocks)?;
        if !(1000..=100_000_000_000).contains(&c.win_msat) {
            return Err("lottery.win_msat is from 1000 (a node takes nothing below 1 sat) to 100000000000".into());
        }
        if !(1000..=c.win_msat).contains(&c.min_win_msat) {
            return Err("lottery.min_win_msat is from 1000 to lottery.win_msat".into());
        }
        if !(18..=2016).contains(&c.win_blocks) {
            return Err("lottery.win_blocks is from 18 to 2016".into());
        }
        if !(1..=1024).contains(&c.window) {
            return Err("lottery.window is from 1 to 1024: the pieces served before any value has come".into());
        }
        if c.max_unpaid_wins == 0 {
            return Err("lottery.max_unpaid_wins is at least 1: a win is unpaid for the moment its payment takes".into());
        }
        if c.chain_draws == 0 || c.chain_draws > MAX_CHAIN_DRAWS {
            return Err(format!("lottery.chain_draws is from 1 to {MAX_CHAIN_DRAWS}"));
        }
        if c.piece_bytes == 0 {
            return Err("lottery.piece_bytes is at least 1".into());
        }
        if c.max_sessions == 0 {
            return Err("lottery.max_sessions is at least 1".into());
        }
        if !(1..=1_000_000).contains(&c.max_odds_den) {
            return Err("lottery.max_odds_den is from 1 to 1000000: a route is drawn for only if its dearest piece costs at most win_msat divided by it".into());
        }
        if !(5..=3600).contains(&c.invoice_secs) {
            return Err("lottery.invoice_secs is from 5 to 3600".into());
        }
        if c.invoice_secs > c.grace_seconds.max(5) {
            return Err(format!("lottery.invoice_secs {} is more than lottery.grace_seconds {}: a buyer whose payment of a win failed waits for that win's next invoice, which comes only when the first has lapsed, and the session would be refused win_unpaid in between", c.invoice_secs, c.grace_seconds));
        }
        Ok(c)
    }

    fn read(m: &Map<String, Value>, ticket_blocks: u32) -> Result<Self, String> {
        let win_msat = num(m, "win_msat", 64_000)?;
        let grace_seconds = num32(m, "grace_seconds", 30)?;
        Ok(Self {
            win_msat,
            min_win_msat: num(m, "min_win_msat", win_msat.min(16_000))?,
            win_blocks: num32(m, "win_blocks", ticket_blocks)?,
            window: num32(m, "window", 8)?,
            // a wallet pays 8 wins at a time (a channel may carry 30 pending payments): with 100 sellers of one
            // buyer winning at once the last of them waited 13 s on the lab, and 10 s cut that seller's answer
            grace_seconds,
            grace_pieces: num32(m, "grace_pieces", 64)?,
            max_unpaid_wins: num32(m, "max_unpaid_wins", 2)?,
            pay_wait_secs: num32(m, "pay_wait_secs", 10)?,
            chain_draws: num32(m, "chain_draws", DEFAULT_CHAIN_DRAWS)?,
            piece_bytes: num(m, "piece_bytes", 262_144)?,
            max_sessions: num32(m, "max_sessions", 64)?,
            sessions_per_address: num32(m, "sessions_per_address", 4)?,
            // half of the default window. An answer that is cut leaves the pieces that were on their
            // way, one to a few and the window at the most, and each void narrows the window by one
            // for the rest of the session: past half of it the buyer is better served by a new session
            max_voids: num32(m, "max_voids", 4)?,
            max_odds_den: num32(m, "max_odds_den", 4)?,
            idle_secs: num(m, "idle_secs", 300)?,
            first_use_secs: num(m, "first_use_secs", 60)?,
            // the grace: an invoice that lapses unpaid is replaced by the time the grace ends
            invoice_secs: num32(m, "invoice_secs", grace_seconds.clamp(5, 3600))?,
        })
    }

    /// The price of the bytes `[from, to)` of a body.
    pub fn bytes_amount(price: &Price, from: u64, to: u64) -> Option<u64> {
        xbt402::lottery::bytes_amount(|n| price.for_bytes(n), from, to)
    }

    /// What the dearest piece of a route costs: its request, one second, or one full piece of bytes.
    pub fn dearest_piece(&self, price: &Price) -> Option<u64> {
        let bytes = Self::bytes_amount(price, 0, self.piece_bytes)?;
        Some(price.request_msat.max(price.second_msat).max(bytes))
    }

    /// Whether a route is offered by lottery: its dearest piece wins at most 1 time in
    /// `max_odds_den` at the largest win (and always costs less than a win). A route with a
    /// dearer piece is paid with tickets: its 402 has no lottery entry, and a request that names
    /// the lottery for it is refused. The seller serves `window` pieces before any value has
    /// come, so this is what bounds, in wins, what a buyer that gives none is served.
    pub fn offers(&self, price: &Price) -> bool {
        let small = |d: u64| d < self.win_msat && u128::from(d) * u128::from(self.max_odds_den) <= u128::from(self.win_msat);
        !price.is_free() && self.dearest_piece(price).is_some_and(small)
    }
}

/// Why a request of a lottery session is not served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    SessionUnknown,
    BadAuth,
    /// Not the next `seq`; the one expected.
    BadSeq(u64),
    TooManySessions,
    /// The win size asked for is outside what the terms allow.
    WinSize,
    /// A win has been unpaid for longer than the grace allows.
    WinUnpaid,
    /// The window is full: pieces were served and no value or void has come for them.
    ValueMissing,
    TooManyVoids,
    Draw(DrawError),
}

impl Refusal {
    pub fn code(self) -> &'static str {
        match self {
            Self::SessionUnknown => "session_unknown",
            Self::BadAuth => "bad_auth",
            Self::BadSeq(_) => "bad_seq",
            Self::TooManySessions => "too_many_sessions",
            Self::WinSize => "win_size",
            Self::WinUnpaid => "win_unpaid",
            Self::ValueMissing => "value_missing",
            Self::TooManyVoids => "too_many_voids",
            Self::Draw(e) => e.code(),
        }
    }
}

/// The invoice of a win: its payment hash, which is written down before the node is asked to make
/// it, and the invoice once the node has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinInvoice {
    pub hash: Hash,
    /// The BOLT 11 invoice the buyer is sent. None: the node was asked and its answer is not
    /// known here, because it is being asked now, gave no answer, or the gateway stopped in
    /// between. Such an invoice may exist on the node with nobody but perhaps the buyer
    /// knowing it, so it is cancelled before another is made.
    pub text: Option<String>,
    /// When the node was asked.
    pub at: u64,
}

/// A win that is not paid yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Win {
    pub draw: u64,
    /// The invoice that pays it. None until the node is asked for one.
    pub invoice: Option<WinInvoice>,
    /// A request is asking the node for this win's invoice now: no other one does.
    pub issuing: bool,
    /// When the win was drawn, and the pieces served to its session since.
    pub drawn_at: u64,
    pub pieces_since: u32,
}

/// The seed of a session's chain. It is in the lottery's journal, so that a session outlives a
/// restart, and is never printed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Seed(pub [u8; 32]);

impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Seed(..)")
    }
}

/// One buyer's session.
#[derive(Debug)]
pub struct Session {
    pub key: [u8; 32],
    seller: Seller,
    seed: Seed,
    chain_draws: u32,
    pub win_msat: u64,
    pub next_seq: u64,
    pub addr: String,
    pub opened: u64,
    pub active: u64,
    /// The price of every piece served, the number of wins drawn and of wins the node shows paid.
    pub served_msat: u64,
    pub wins: u64,
    pub paid_wins: u64,
    pub unpaid: Vec<Win>,
    pub voids: u32,
    /// Answers of this session that are still being sent.
    pub open_responses: u32,
    pub finals: VecDeque<Value>,
    /// When the buyer closed it, if it did while it owed: it serves nothing more and keeps its
    /// place in the caps until it has been quiet for `first_use_secs`.
    pub closed: Option<u64>,
}

impl Session {
    pub fn drawn(&self) -> u64 {
        self.seller.drawn()
    }

    pub fn pending(&self) -> usize {
        self.seller.pending_count()
    }

    /// The pieces this session was served and gave no value for: the open ones and the voided
    /// ones. What the window counts.
    pub fn unvalued(&self) -> usize {
        self.seller.pending_count().saturating_add(self.voids as usize)
    }

    pub fn won_msat(&self) -> u64 {
        self.wins.saturating_mul(self.win_msat)
    }

    pub fn paid_msat(&self) -> u64 {
        self.paid_wins.saturating_mul(self.win_msat)
    }
}

/// What a `draw` request did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drawn {
    /// The last draw taken and its chain value: None before the first.
    pub reveal: Option<(u64, [u8; 32])>,
    pub taken: Vec<Taken>,
    /// The first value that was refused, and why; the values after it were not looked at.
    pub refused: Option<(u64, DrawError)>,
}

/// One value of a `draw` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Value32 {
    pub draw: u64,
    pub piece: PieceId,
    pub amount_msat: u64,
    pub value: [u8; 32],
}

/// The totals of every session there has been, forgotten ones included: what an operator reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Totals {
    pub opened: u64,
    pub served_msat: u64,
    pub drawn: u64,
    pub wins: u64,
    pub paid_wins: u64,
    pub won_msat: u64,
    pub paid_msat: u64,
}

pub struct Book {
    cfg: LotteryConfig,
    sessions: HashMap<String, Session>,
    totals: Totals,
    /// What changed since the last [`Book::take_log`], in the order it changed.
    log: Vec<Rec>,
}

impl Book {
    pub fn new(cfg: LotteryConfig) -> Self {
        Self { cfg, sessions: HashMap::new(), totals: Totals::default(), log: vec![] }
    }

    /// The records of every change since the last call, in order: what the journal appends.
    pub fn take_log(&mut self) -> Vec<Rec> {
        std::mem::take(&mut self.log)
    }

    pub fn cfg(&self) -> &LotteryConfig {
        &self.cfg
    }

    pub fn session(&self, id: &str) -> Option<&Session> {
        self.sessions.get(id)
    }

    pub fn sessions(&self) -> usize {
        self.sessions.len()
    }

    /// The ids of every session, in order.
    pub fn ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.sessions.keys().cloned().collect();
        v.sort();
        v
    }

    pub fn totals(&self) -> Totals {
        self.totals
    }

    /// Whether a new session from `addr` is inside the caps: asked before the chain is made, so
    /// that a request the caps refuse costs no hashing.
    pub fn room(&self, addr: &str) -> Result<(), Refusal> {
        if self.sessions.len() >= self.cfg.max_sessions as usize {
            return Err(Refusal::TooManySessions);
        }
        let per = self.cfg.sessions_per_address as usize;
        if per > 0 && self.sessions.values().filter(|s| s.addr == addr).count() >= per {
            return Err(Refusal::TooManySessions);
        }
        Ok(())
    }

    /// The win size a session gets: the one asked for, inside the terms, or the terms' own.
    pub fn win_size(&self, asked: Option<u64>) -> Result<u64, Refusal> {
        match asked {
            None => Ok(self.cfg.win_msat),
            Some(w) if (self.cfg.min_win_msat..=self.cfg.win_msat).contains(&w) => Ok(w),
            Some(_) => Err(Refusal::WinSize),
        }
    }

    /// A new session: its id and key from `entropy` (16 and 32 fresh random bytes), its chain
    /// `chain`, made by the caller from `seed`, 32 more that are used for nothing else. Returns the id.
    pub fn open(&mut self, entropy: &[u8; 48], seed: [u8; 32], chain: Chain, addr: &str, win_msat: u64, now: u64) -> Result<String, Refusal> {
        self.room(addr)?;
        let id = hex::encode(&entropy[..16]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&entropy[16..]);
        if self.sessions.contains_key(&id) {
            return Err(Refusal::TooManySessions);
        }
        let chain_draws = chain.len();
        let seller = Seller::new(&id, win_msat, chain).map_err(Refusal::Draw)?;
        self.sessions.insert(
            id.clone(),
            Session {
                key,
                seller,
                seed: Seed(seed),
                chain_draws,
                win_msat,
                next_seq: 0,
                addr: addr.into(),
                opened: now,
                active: now,
                served_msat: 0,
                wins: 0,
                paid_wins: 0,
                unpaid: vec![],
                voids: 0,
                open_responses: 0,
                finals: VecDeque::new(),
                closed: None,
            },
        );
        self.totals.opened += 1;
        if let Some(s) = self.sessions.get(&id) {
            self.log.push(Rec::Session(Box::new(Opened::of(&id, s))));
        }
        Ok(id)
    }

    pub fn anchor(&self, id: &str) -> Option<[u8; 32]> {
        self.sessions.get(id).map(|s| s.seller.anchor())
    }

    /// The session exists, `verify` accepts its key, `seq` is the next one. A `seq` is used up by
    /// any request that passes here, served or not.
    pub fn authenticate(&mut self, session: &str, seq: u64, now: u64, verify: impl FnOnce(&[u8; 32]) -> bool) -> Result<(), Refusal> {
        // a session its buyer closed is known to nobody, whatever place it still keeps
        let s = self.sessions.get_mut(session).filter(|s| s.closed.is_none()).ok_or(Refusal::SessionUnknown)?;
        if !verify(&s.key) {
            return Err(Refusal::BadAuth);
        }
        if seq != s.next_seq {
            return Err(Refusal::BadSeq(s.next_seq));
        }
        s.next_seq = s.next_seq.checked_add(1).ok_or(Refusal::BadSeq(s.next_seq))?;
        s.active = now;
        // a buyer names no piece of a request older than the ones still open
        s.seller.forget_before(seq);
        // a seq is used up for good: a restart that took it again would let a buyer's answered
        // request be served twice, and name a piece twice
        self.log.push(Rec::Seq { session: session.into(), next_seq: s.next_seq });
        Ok(())
    }

    /// Why this session is served no further piece now, if it is not.
    pub fn blocked(&self, session: &str, now: u64) -> Option<Refusal> {
        let Some(s) = self.sessions.get(session).filter(|s| s.closed.is_none()) else { return Some(Refusal::SessionUnknown) };
        if s.voids > self.cfg.max_voids {
            return Some(Refusal::TooManyVoids);
        }
        let late = |w: &Win| now.saturating_sub(w.drawn_at) > u64::from(self.cfg.grace_seconds) || w.pieces_since >= self.cfg.grace_pieces;
        if s.unpaid.len() > self.cfg.max_unpaid_wins as usize || s.unpaid.iter().any(late) {
            return Some(Refusal::WinUnpaid);
        }
        Self::window_full(&self.cfg, s)
    }

    /// The window: a session is served no piece while the pieces it gave no value for, open and
    /// voided together, are `window` or more. A value for an open piece makes room; a void makes
    /// none, or a buyer that voids every piece is served without end and without a draw. With
    /// nothing open no value can make room: the session is over (`too_many_voids`).
    fn window_full(cfg: &LotteryConfig, s: &Session) -> Option<Refusal> {
        if s.unvalued() < cfg.window as usize {
            return None;
        }
        Some(if s.seller.pending_count() > 0 { Refusal::ValueMissing } else { Refusal::TooManyVoids })
    }

    /// How long an answer that is being sent may stand still for the session's oldest unpaid win,
    /// in seconds: what is left of `grace_seconds` since it was drawn, and `pay_wait_secs` at the
    /// most. 0: none is unpaid, or the time is up.
    pub fn grace_left(&self, session: &str, now: u64) -> u64 {
        let Some(s) = self.sessions.get(session) else { return 0 };
        let left = s.unpaid.iter().map(|w| w.drawn_at).min().map_or(0, |at| (at + u64::from(self.cfg.grace_seconds)).saturating_sub(now));
        left.min(u64::from(self.cfg.pay_wait_secs))
    }

    /// A piece is about to leave for the buyer: it is marked, or refused because the window is
    /// full. The window is asked again here, in the same step that marks the piece, because
    /// [`Book::blocked`] was asked before the service was: several requests of one session that
    /// arrive together would each have found room for the same place. A piece with no price is
    /// not a piece.
    pub fn serve(&mut self, session: &str, piece: Piece) -> Result<(), Refusal> {
        let s = self.sessions.get_mut(session).filter(|s| s.closed.is_none()).ok_or(Refusal::SessionUnknown)?;
        if piece.amount_msat == 0 {
            return Ok(());
        }
        if let Some(full) = Self::window_full(&self.cfg, s) {
            return Err(full);
        }
        s.seller.serve(piece).map_err(Refusal::Draw)?;
        self.log.push(Rec::Piece { session: session.into(), piece, open: false });
        s.served_msat = s.served_msat.saturating_add(piece.amount_msat);
        self.totals.served_msat = self.totals.served_msat.saturating_add(piece.amount_msat);
        for w in &mut s.unpaid {
            w.pieces_since = w.pieces_since.saturating_add(1);
        }
        Ok(())
    }

    /// The request named `seq`'s piece of `kind` number `k`: what a draw binds, by the seller's count.
    pub fn piece(seq: u64, req: [u8; 32], kind: Kind, k: u64, amount_msat: u64) -> Piece {
        Piece { id: PieceId { seq, kind, k }, req, amount_msat }
    }

    /// Take a `draw` request: the voids, then the values in order, stopping at the first one
    /// refused. A win is listed unpaid from here, with no invoice yet.
    pub fn draw(&mut self, session: &str, values: &[Value32], voids: &[PieceId], now: u64) -> Result<Drawn, Refusal> {
        let s = self.sessions.get_mut(session).filter(|s| s.closed.is_none()).ok_or(Refusal::SessionUnknown)?;
        for id in voids {
            if s.seller.void(*id) {
                s.voids = s.voids.saturating_add(1);
                self.log.push(Rec::Void { session: session.into(), id: *id });
            }
        }
        let mut out = Drawn { reveal: None, taken: vec![], refused: None };
        for v in values {
            match s.seller.take(v.draw, v.piece, v.amount_msat, &v.value) {
                Ok(t) => {
                    if !t.repeated {
                        self.log.push(Rec::Take { session: session.into(), draw: t.draw, id: v.piece, amount_msat: v.amount_msat, value: v.value, at: now });
                        self.totals.drawn += 1;
                        if t.won {
                            s.wins += 1;
                            self.totals.wins += 1;
                            self.totals.won_msat = self.totals.won_msat.saturating_add(s.win_msat);
                            s.unpaid.push(Win { draw: t.draw, invoice: None, issuing: false, drawn_at: now, pieces_since: 0 });
                        }
                    }
                    out.taken.push(t);
                }
                Err(e) => {
                    out.refused = Some((v.draw, e));
                    break;
                }
            }
        }
        out.reveal = s.seller.reveal();
        Ok(out)
    }

    /// Take it on to ask the node for an invoice for an unpaid win whose invoice is `old` (None:
    /// it has none yet), with payment hash `hash`. False: the win is gone, has another invoice by
    /// now, or someone else is asking. Two answers of one session look at its wins at the same
    /// moment, and a win with two invoices could be paid on the one the book has forgotten. On
    /// true the new invoice is the win's from here, by its hash alone, and is in the log: the
    /// caller has it on disk before the node is asked.
    pub fn claim_invoice(&mut self, session: &str, draw: u64, old: Option<&Hash>, hash: Hash, now: u64) -> bool {
        match self.sessions.get_mut(session).and_then(|s| s.unpaid.iter_mut().find(|w| w.draw == draw)) {
            Some(w) if !w.issuing && w.invoice.as_ref().map(|i| &i.hash) == old => {
                w.issuing = true;
                w.invoice = Some(WinInvoice { hash, text: None, at: now });
                self.log.push(Rec::Invoice { session: session.into(), draw, hash, at: now });
                true
            }
            _ => false,
        }
    }

    /// The node's answer to a claimed invoice `hash`: the invoice, or None when the answer is not
    /// known (the next look at the win finds out what the node has).
    pub fn win_invoiced(&mut self, session: &str, draw: u64, hash: &Hash, text: Option<String>) {
        if let Some(w) = self.sessions.get_mut(session).and_then(|s| s.unpaid.iter_mut().find(|w| w.draw == draw)) {
            w.issuing = false;
            if let (Some(inv), Some(text)) = (w.invoice.as_mut().filter(|i| &i.hash == hash), text) {
                self.log.push(Rec::Invoiced { session: session.into(), draw, hash: *hash, text: text.clone() });
                inv.text = Some(text);
            }
        }
    }

    /// The node shows the invoice `hash` of a win paid in full. True if that win was unpaid.
    pub fn win_paid(&mut self, session: &str, hash: &Hash) -> bool {
        let Some(s) = self.sessions.get_mut(session) else { return false };
        let before = s.unpaid.len();
        s.unpaid.retain(|w| w.invoice.as_ref().is_none_or(|i| &i.hash != hash));
        let paid = (before - s.unpaid.len()) as u64;
        s.paid_wins += paid;
        self.totals.paid_wins += paid;
        self.totals.paid_msat = self.totals.paid_msat.saturating_add(paid.saturating_mul(s.win_msat));
        if paid > 0 {
            self.log.push(Rec::Paid { session: session.into(), hash: *hash });
        }
        paid > 0
    }

    /// An answer of the session started (`open`) or ended.
    pub fn response(&mut self, session: &str, open: bool, now: u64) {
        if let Some(s) = self.sessions.get_mut(session) {
            s.open_responses = if open { s.open_responses.saturating_add(1) } else { s.open_responses.saturating_sub(1) };
            s.active = now;
        }
    }

    /// Keep the last receipt of a streamed answer for `status`.
    pub fn keep_final(&mut self, session: &str, receipt: Value) {
        if let Some(s) = self.sessions.get_mut(session) {
            if s.finals.len() >= FINALS_KEPT {
                s.finals.pop_front();
            }
            s.finals.push_back(receipt);
        }
    }

    /// The buyer closed its session: it is served nothing more. One that owes nothing is
    /// forgotten at once. One that was served pieces it gave no value for, or has a win unpaid,
    /// keeps its place in the caps until [`Book::sweep`] takes it: closing must not be a way to
    /// take the window again and again from one address.
    pub fn close(&mut self, session: &str, now: u64) -> bool {
        let Some(s) = self.sessions.get_mut(session).filter(|s| s.closed.is_none()) else { return false };
        if s.unvalued() == 0 && s.unpaid.is_empty() {
            self.sessions.remove(session);
            self.log.push(Rec::Drop { session: session.into() });
        } else {
            s.closed = Some(now);
            self.log.push(Rec::Closed { session: session.into(), at: now });
        }
        true
    }

    /// Forget a session at once, whatever it owes: one whose next draw could not be written down.
    pub fn forget(&mut self, session: &str) {
        if self.sessions.remove(session).is_some() {
            self.log.push(Rec::Drop { session: session.into() });
        }
    }

    /// The sessions [`Book::sweep`] would forget at `now`.
    pub fn due(&self, now: u64) -> Vec<String> {
        let mut v: Vec<String> = self.sessions.iter().filter(|(_, s)| self.gone(s, now)).map(|(id, _)| id.clone()).collect();
        v.sort();
        v
    }

    fn gone(&self, s: &Session, now: u64) -> bool {
        let cfg = &self.cfg;
        let quiet = now.saturating_sub(s.active);
        let unused = s.seller.drawn() == 0 && now.saturating_sub(s.opened) > cfg.first_use_secs && quiet > cfg.first_use_secs;
        // a closed one waits as long as one that never drew, whatever it drew: no longer, or a
        // buyer whose answers are cut would be kept out by its own closed sessions
        let closed = s.closed.is_some_and(|at| now.saturating_sub(at) > cfg.first_use_secs);
        s.open_responses == 0 && (quiet > cfg.idle_secs || unused || closed)
    }

    /// Forget the sessions that have gone quiet: none with an answer still being sent. Returns
    /// how many went.
    pub fn sweep(&mut self, now: u64) -> usize {
        let due = self.due(now);
        for id in &due {
            self.sessions.remove(id);
            self.log.push(Rec::Drop { session: id.clone() });
        }
        due.len()
    }

    // --- the journal ------------------------------------------------------------------------------

    /// Every session as records, as a compacted journal holds them: each session's counters, its
    /// open pieces, the last draws it took and its unpaid wins.
    pub fn snapshot(&self) -> Vec<Rec> {
        let mut ids: Vec<&String> = self.sessions.keys().collect();
        ids.sort();
        let mut out = vec![];
        for id in ids {
            let s = &self.sessions[id];
            out.push(Rec::Session(Box::new(Opened::of(id, s))));
            out.extend(s.seller.pending().map(|p| Rec::Piece { session: id.clone(), piece: *p, open: true }));
            out.extend(s.seller.recent().map(|t| Rec::Took { session: id.clone(), taken: *t }));
            out.extend(s.unpaid.iter().map(|w| Rec::Win { session: id.clone(), win: Win { issuing: false, ..w.clone() } }));
        }
        out
    }

    /// The book a journal describes, at `now`: every session it holds, its chain made again from
    /// its seed and its draws where they were. A session whose records do not hold together is
    /// left out, and named with the reason: it is forgotten, as every session was before the
    /// lottery had a journal, and no draw of it can be taken again. The operator's totals start
    /// again from nothing.
    pub fn restore(cfg: LotteryConfig, recs: &[Rec], now: u64) -> (Self, Vec<String>) {
        let mut b = Self::new(cfg);
        let mut bad: HashMap<String, String> = HashMap::new();
        for r in recs {
            let id = r.session();
            if bad.contains_key(id) && !matches!(r, Rec::Session(_)) {
                continue;
            }
            if let Err(why) = b.replay(r, now) {
                b.sessions.remove(id);
                bad.insert(id.to_string(), why);
            } else if matches!(r, Rec::Session(_)) {
                bad.remove(id);
            }
        }
        b.log.clear();
        let mut problems: Vec<String> = bad.into_iter().map(|(id, why)| format!("lottery session {id}: {why}")).collect();
        problems.sort();
        (b, problems)
    }

    fn replay(&mut self, r: &Rec, now: u64) -> Result<(), String> {
        let draw_err = |e: DrawError| e.to_string();
        if let Rec::Session(o) = r {
            let chain = Chain::new(o.seed.0, o.chain_draws).map_err(draw_err)?;
            let seller = Seller::resume(&o.id, o.win_msat, chain, o.drawn).map_err(draw_err)?;
            self.sessions.insert(
                o.id.clone(),
                Session {
                    key: o.key,
                    seller,
                    seed: o.seed,
                    chain_draws: o.chain_draws,
                    win_msat: o.win_msat,
                    next_seq: o.next_seq,
                    addr: o.addr.clone(),
                    opened: o.opened,
                    active: now,
                    served_msat: o.served_msat,
                    wins: o.wins,
                    paid_wins: o.paid_wins,
                    unpaid: vec![],
                    voids: o.voids,
                    open_responses: 0,
                    finals: VecDeque::new(),
                    closed: o.closed,
                },
            );
            return Ok(());
        }
        // a record of a session that is not here was dropped since, or its first record was lost
        // with a power cut: nothing to do
        let Some(s) = self.sessions.get_mut(r.session()) else { return Ok(()) };
        match r {
            Rec::Session(_) => {}
            Rec::Seq { next_seq, .. } => s.next_seq = s.next_seq.max(*next_seq),
            Rec::Piece { piece, open, .. } => {
                s.seller.serve(*piece).map_err(draw_err)?;
                if !open {
                    s.served_msat = s.served_msat.saturating_add(piece.amount_msat);
                    for w in &mut s.unpaid {
                        w.pieces_since = w.pieces_since.saturating_add(1);
                    }
                }
            }
            Rec::Void { id, .. } => {
                if s.seller.void(*id) {
                    s.voids = s.voids.saturating_add(1);
                }
            }
            Rec::Take { draw, id, amount_msat, value, at, .. } => {
                let t = s.seller.take(*draw, *id, *amount_msat, value).map_err(draw_err)?;
                if !t.repeated && t.won {
                    s.wins += 1;
                    s.unpaid.push(Win { draw: t.draw, invoice: None, issuing: false, drawn_at: *at, pieces_since: 0 });
                }
            }
            Rec::Took { taken, .. } => {
                if !s.seller.remember(*taken) {
                    return Err(format!("draw {} is not one the session has taken", taken.draw));
                }
            }
            Rec::Win { win, .. } => s.unpaid.push(win.clone()),
            Rec::Invoice { draw, hash, at, .. } => {
                if let Some(w) = s.unpaid.iter_mut().find(|w| w.draw == *draw) {
                    w.invoice = Some(WinInvoice { hash: *hash, text: None, at: *at });
                }
            }
            Rec::Invoiced { draw, hash, text, .. } => {
                if let Some(inv) = s.unpaid.iter_mut().find(|w| w.draw == *draw).and_then(|w| w.invoice.as_mut()).filter(|i| &i.hash == hash) {
                    inv.text = Some(text.clone());
                }
            }
            Rec::Paid { hash, .. } => {
                let before = s.unpaid.len();
                s.unpaid.retain(|w| w.invoice.as_ref().is_none_or(|i| &i.hash != hash));
                s.paid_wins += (before - s.unpaid.len()) as u64;
            }
            Rec::Closed { at, .. } => s.closed = Some(*at),
            Rec::Drop { session } => {
                self.sessions.remove(session);
            }
        }
        Ok(())
    }
}

/// A session as one record: what it is made from, and its counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub id: String,
    pub key: [u8; 32],
    pub addr: String,
    pub win_msat: u64,
    pub seed: Seed,
    pub chain_draws: u32,
    pub opened: u64,
    pub next_seq: u64,
    pub drawn: u64,
    pub served_msat: u64,
    pub wins: u64,
    pub paid_wins: u64,
    pub voids: u32,
    pub closed: Option<u64>,
}

impl Opened {
    fn of(id: &str, s: &Session) -> Self {
        Self {
            id: id.into(),
            key: s.key,
            addr: s.addr.clone(),
            win_msat: s.win_msat,
            seed: s.seed,
            chain_draws: s.chain_draws,
            opened: s.opened,
            next_seq: s.next_seq,
            drawn: s.seller.drawn(),
            served_msat: s.served_msat,
            wins: s.wins,
            paid_wins: s.paid_wins,
            voids: s.voids,
            closed: s.closed,
        }
    }
}

/// One line of the lottery's journal (`lottery.jsonl` in the state directory). The events are
/// written as they happen; `Session` with counters, `Piece` with `open`, `Took` and `Win` are
/// what a snapshot is made of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rec {
    /// A session: at its open (every counter nothing) and in a snapshot.
    Session(Box<Opened>),
    /// A request's `seq` was used up; the next one is this.
    Seq { session: String, next_seq: u64 },
    /// A piece was served (`open`: a snapshot's open piece, which its session's counters have already).
    Piece { session: String, piece: Piece, open: bool },
    Void { session: String, id: PieceId },
    /// A value was taken for a draw, at `at`.
    Take { session: String, draw: u64, id: PieceId, amount_msat: u64, value: [u8; 32], at: u64 },
    /// A snapshot's draw taken before: what a repeated message is answered with.
    Took { session: String, taken: Taken },
    /// A snapshot's unpaid win.
    Win { session: String, win: Win },
    /// The node is about to be asked for a win's invoice with this payment hash.
    Invoice { session: String, draw: u64, hash: Hash, at: u64 },
    /// The node made it.
    Invoiced { session: String, draw: u64, hash: Hash, text: String },
    /// The node shows the invoice `hash` paid in full.
    Paid { session: String, hash: Hash },
    Closed { session: String, at: u64 },
    Drop { session: String },
}

impl Rec {
    pub fn session(&self) -> &str {
        match self {
            Self::Session(o) => &o.id,
            Self::Seq { session, .. }
            | Self::Piece { session, .. }
            | Self::Void { session, .. }
            | Self::Take { session, .. }
            | Self::Took { session, .. }
            | Self::Win { session, .. }
            | Self::Invoice { session, .. }
            | Self::Invoiced { session, .. }
            | Self::Paid { session, .. }
            | Self::Closed { session, .. }
            | Self::Drop { session } => session,
        }
    }
}

fn piece_json(p: &Piece) -> Value {
    json!({"seq": p.id.seq, "kind": p.id.kind.name(), "k": p.id.k, "req": hex::encode(p.req), "amount": p.amount_msat})
}

fn id_json(id: &PieceId) -> Value {
    json!({"seq": id.seq, "kind": id.kind.name(), "k": id.k})
}

fn id_of(v: &Value) -> Option<PieceId> {
    Some(PieceId { seq: v.get("seq")?.as_u64()?, kind: Kind::parse(v.get("kind")?.as_str()?)?, k: v.get("k")?.as_u64()? })
}

fn piece_of(v: &Value) -> Option<Piece> {
    Some(Piece { id: id_of(v)?, req: hex32(v.get("req")?.as_str()?)?, amount_msat: v.get("amount")?.as_u64()? })
}

impl crate::store::Record for Rec {
    fn to_json(&self) -> Value {
        match self {
            Self::Session(o) => json!({"t": "session", "id": o.id, "key": hex::encode(o.key), "addr": o.addr, "win": o.win_msat, "seed": hex::encode(o.seed.0),
                                       "chain": o.chain_draws, "opened": o.opened, "seq": o.next_seq, "drawn": o.drawn, "served": o.served_msat,
                                       "wins": o.wins, "paid": o.paid_wins, "voids": o.voids, "closed": o.closed}),
            Self::Seq { session, next_seq } => json!({"t": "seq", "session": session, "seq": next_seq}),
            Self::Piece { session, piece, open } => json!({"t": "piece", "session": session, "piece": piece_json(piece), "open": open}),
            Self::Void { session, id } => json!({"t": "void", "session": session, "piece": id_json(id)}),
            Self::Take { session, draw, id, amount_msat, value, at } => {
                json!({"t": "take", "session": session, "draw": draw, "piece": id_json(id), "amount": amount_msat, "value": hex::encode(value), "at": at})
            }
            Self::Took { session, taken } => {
                json!({"t": "took", "session": session, "draw": taken.draw, "piece": piece_json(&taken.piece), "value": hex::encode(taken.value), "won": taken.won})
            }
            Self::Win { session, win } => json!({"t": "win", "session": session, "draw": win.draw, "drawn_at": win.drawn_at, "since": win.pieces_since,
                                                 "invoice": win.invoice.as_ref().map(|i| json!({"hash": hex::encode(i.hash), "text": i.text, "at": i.at}))}),
            Self::Invoice { session, draw, hash, at } => json!({"t": "invoice", "session": session, "draw": draw, "hash": hex::encode(hash), "at": at}),
            Self::Invoiced { session, draw, hash, text } => json!({"t": "invoiced", "session": session, "draw": draw, "hash": hex::encode(hash), "text": text}),
            Self::Paid { session, hash } => json!({"t": "paid", "session": session, "hash": hex::encode(hash)}),
            Self::Closed { session, at } => json!({"t": "closed", "session": session, "at": at}),
            Self::Drop { session } => json!({"t": "drop", "session": session}),
        }
    }

    fn from_json(v: &Value) -> Option<Self> {
        let s = |k: &str| v.get(k).and_then(Value::as_str);
        let n = |k: &str| v.get(k).and_then(Value::as_u64);
        let h = |k: &str| s(k).and_then(hex32);
        let session = || s("session").map(str::to_string);
        Some(match s("t")? {
            "session" => Self::Session(Box::new(Opened {
                id: s("id")?.to_string(),
                key: h("key")?,
                addr: s("addr")?.to_string(),
                win_msat: n("win")?,
                seed: Seed(h("seed")?),
                chain_draws: u32::try_from(n("chain")?).ok()?,
                opened: n("opened")?,
                next_seq: n("seq")?,
                drawn: n("drawn")?,
                served_msat: n("served")?,
                wins: n("wins")?,
                paid_wins: n("paid")?,
                voids: u32::try_from(n("voids")?).ok()?,
                closed: match v.get("closed")? {
                    Value::Null => None,
                    c => Some(c.as_u64()?),
                },
            })),
            "seq" => Self::Seq { session: session()?, next_seq: n("seq")? },
            "piece" => Self::Piece { session: session()?, piece: piece_of(v.get("piece")?)?, open: v.get("open")?.as_bool()? },
            "void" => Self::Void { session: session()?, id: id_of(v.get("piece")?)? },
            "take" => Self::Take { session: session()?, draw: n("draw")?, id: id_of(v.get("piece")?)?, amount_msat: n("amount")?, value: h("value")?, at: n("at")? },
            "took" => Self::Took {
                session: session()?,
                taken: Taken { draw: n("draw")?, piece: piece_of(v.get("piece")?)?, value: h("value")?, won: v.get("won")?.as_bool()?, repeated: false },
            },
            "win" => Self::Win {
                session: session()?,
                win: Win {
                    draw: n("draw")?,
                    invoice: match v.get("invoice")? {
                        Value::Null => None,
                        i => Some(WinInvoice {
                            hash: i.get("hash")?.as_str().and_then(hex32)?,
                            text: match i.get("text")? {
                                Value::Null => None,
                                t => Some(t.as_str()?.to_string()),
                            },
                            at: i.get("at")?.as_u64()?,
                        }),
                    },
                    issuing: false,
                    drawn_at: n("drawn_at")?,
                    pieces_since: u32::try_from(n("since")?).ok()?,
                },
            },
            "invoice" => Self::Invoice { session: session()?, draw: n("draw")?, hash: h("hash")?, at: n("at")? },
            "invoiced" => Self::Invoiced { session: session()?, draw: n("draw")?, hash: h("hash")?, text: s("text")?.to_string() },
            "paid" => Self::Paid { session: session()?, hash: h("hash")? },
            "closed" => Self::Closed { session: session()?, at: n("at")? },
            "drop" => Self::Drop { session: session()? },
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg() -> LotteryConfig {
        LotteryConfig::parse(&json!({"window": 3, "grace_pieces": 4, "grace_seconds": 10, "max_sessions": 3, "sessions_per_address": 2, "max_voids": 2, "chain_draws": 4096}), 40).unwrap()
    }

    fn open(b: &mut Book, n: u8, addr: &str) -> Result<String, Refusal> {
        let mut e = [n; 48];
        e[0] = n;
        let win = b.cfg().win_msat;
        b.open(&e, [n; 32], Chain::new([n; 32], b.cfg().chain_draws).unwrap(), addr, win, 1000)
    }

    fn bytes(seq: u64, k: u64, amount: u64) -> Piece {
        Book::piece(seq, [seq as u8; 32], Kind::Bytes, k, amount)
    }

    fn value(draw: u64, p: &Piece, n: u8) -> Value32 {
        let mut v = [n; 32];
        v[..8].copy_from_slice(&draw.to_be_bytes());
        Value32 { draw, piece: p.id, amount_msat: p.amount_msat, value: v }
    }

    /// Draw for pieces until one wins: the draws taken, the last of them the win.
    fn until_win(b: &mut Book, id: &str, from_draw: u64, amount: u64, now: u64) -> u64 {
        let mut d = from_draw;
        loop {
            let p = bytes(9, d, amount);
            b.serve(id, p).unwrap();
            let out = b.draw(id, &[value(d, &p, 7)], &[], now).unwrap();
            assert_eq!(out.refused, None);
            if out.taken[0].won {
                return d;
            }
            d += 1;
        }
    }

    #[test]
    fn the_defaults_are_the_drafts_numbers_and_a_wrong_file_is_refused() {
        let c = LotteryConfig::parse(&json!({}), 40).unwrap();
        assert_eq!((c.win_msat, c.min_win_msat, c.win_blocks, c.window), (64_000, 16_000, 40, 8));
        assert_eq!((c.grace_seconds, c.grace_pieces, c.max_unpaid_wins, c.chain_draws), (30, 64, 2, 65_536));
        assert_eq!((c.piece_bytes, c.max_sessions, c.sessions_per_address, c.max_voids, c.max_odds_den), (262_144, 64, 4, 4, 4));
        assert_eq!((c.idle_secs, c.first_use_secs, c.invoice_secs, c.pay_wait_secs), (300, 60, 30, 10));
        // a win's invoice lives no longer than the grace, unless the grace is shorter than 5 s
        for (grace, invoice) in [(10, 10), (3, 5), (0, 5), (100, 100), (7200, 3600)] {
            assert_eq!(LotteryConfig::parse(&json!({"grace_seconds": grace}), 40).unwrap().invoice_secs, invoice, "{grace}");
        }
        assert!(LotteryConfig::parse(&json!({"grace_seconds": 30, "invoice_secs": 31}), 40).unwrap_err().contains("win_unpaid"));
        assert_eq!(LotteryConfig::parse(&json!({"grace_seconds": 3, "invoice_secs": 5}), 40).unwrap().invoice_secs, 5);
        assert_eq!(LotteryConfig::parse(&json!({"win_msat": 8000}), 40).unwrap().min_win_msat, 8000);
        for bad in [
            json!({"win_msat": 999}),
            json!({"min_win_msat": 64_001}),
            json!({"min_win_msat": 999}),
            json!({"window": 0}),
            json!({"window": 1025}),
            json!({"max_unpaid_wins": 0}),
            json!({"chain_draws": 0}),
            json!({"chain_draws": 1_048_577}),
            json!({"piece_bytes": 0}),
            json!({"max_sessions": 0}),
            json!({"win_blocks": 17}),
            json!({"invoice_secs": 4}),
            json!({"max_odds_den": 0}),
            json!({"window": "8"}),
            json!({"windows": 8}),
            json!([]),
        ] {
            assert!(LotteryConfig::parse(&bad, 40).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_route_is_offered_by_lottery_only_if_its_dearest_piece_is_a_quarter_of_a_win_or_less() {
        let c = LotteryConfig::parse(&json!({}), 40).unwrap();
        let p = |request_msat, byte_msat, per_bytes, second_msat| Price { request_msat, byte_msat, per_bytes, second_msat };
        assert!(c.offers(&p(100, 0, 1, 0)) && !c.offers(&p(0, 0, 1, 0)), "a free route has nothing to draw for");
        // a quarter of the 64-sat win is offered, one msat more is not: for a request, a second and a piece of bytes
        assert!(c.offers(&p(16_000, 0, 1, 0)) && !c.offers(&p(16_001, 0, 1, 0)));
        assert!(c.offers(&p(0, 0, 1, 16_000)) && !c.offers(&p(0, 0, 1, 16_001)));
        assert!(c.offers(&p(0, 16_000, 262_144, 0)) && !c.offers(&p(0, 16_001, 262_144, 0)));
        // the dearest of the three decides
        assert!(!c.offers(&p(100, 100, 262_144, 16_001)));
        assert!(!c.offers(&p(0, u64::MAX, 1, 0)), "a price that does not fit is no offer");
        assert_eq!(c.dearest_piece(&p(5, 100, 262_144, 7)), Some(100));
        // the runner's own number: 1 is every piece below a whole win, and never a whole win
        let any = LotteryConfig::parse(&json!({"max_odds_den": 1}), 40).unwrap();
        assert!(any.offers(&p(63_999, 0, 1, 0)) && !any.offers(&p(64_000, 0, 1, 0)));
        let strict = LotteryConfig::parse(&json!({"max_odds_den": 640}), 40).unwrap();
        assert!(strict.offers(&p(0, 100, 262_144, 0)) && !strict.offers(&p(0, 101, 262_144, 0)));
        // what the rule bounds: the window, in wins. 8 pieces of a quarter of a win at the most
        assert!(u64::from(c.window) * 16_000 <= 2 * c.win_msat);
    }

    #[test]
    fn sessions_are_capped_in_all_and_per_address_and_a_quiet_one_is_forgotten() {
        let mut b = Book::new(cfg());
        let a = open(&mut b, 1, "v4:1.1.1.1").unwrap();
        open(&mut b, 2, "v4:1.1.1.1").unwrap();
        assert_eq!(open(&mut b, 3, "v4:1.1.1.1").unwrap_err(), Refusal::TooManySessions, "two from one address");
        open(&mut b, 3, "v4:2.2.2.2").unwrap();
        assert_eq!(open(&mut b, 4, "v4:3.3.3.3").unwrap_err(), Refusal::TooManySessions, "three in all");
        assert_eq!(b.room("v4:3.3.3.3").unwrap_err(), Refusal::TooManySessions);
        assert_eq!((b.win_size(None), b.win_size(Some(16_000)), b.win_size(Some(15_999)), b.win_size(Some(64_001))), (Ok(64_000), Ok(16_000), Err(Refusal::WinSize), Err(Refusal::WinSize)));
        // session `a` draws once and stays; the two that never drew go after first_use_secs
        let p = bytes(0, 0, 100);
        b.serve(&a, p).unwrap();
        b.draw(&a, &[value(1, &p, 1)], &[], 1001).unwrap();
        assert_eq!(b.sweep(1060), 0);
        assert_eq!(b.sweep(1061), 2);
        assert!(b.session(&a).is_some());
        // an answer still being sent keeps a session whatever the clock says
        b.response(&a, true, 1061);
        assert_eq!(b.sweep(9999), 0);
        b.response(&a, false, 9999);
        assert_eq!((b.sweep(9999 + 300), b.sweep(9999 + 301)), (0, 1));
        assert_eq!(b.totals().opened, 3);
    }

    #[test]
    fn requests_are_authenticated_and_in_order() {
        let mut b = Book::new(cfg());
        let id = open(&mut b, 1, "a").unwrap();
        assert_eq!(b.authenticate("nobody", 0, 1, |_| true).unwrap_err(), Refusal::SessionUnknown);
        assert_eq!(b.authenticate(&id, 0, 1, |_| false).unwrap_err(), Refusal::BadAuth);
        assert_eq!(b.authenticate(&id, 1, 1, |_| true).unwrap_err(), Refusal::BadSeq(0));
        assert_eq!(b.authenticate(&id, 0, 1, |k| *k == [1u8; 32]), Ok(()));
        assert_eq!(b.authenticate(&id, 0, 1, |_| true).unwrap_err(), Refusal::BadSeq(1));
    }

    #[test]
    fn a_buyer_that_sends_no_values_gets_the_window_and_no_more() {
        let mut b = Book::new(cfg());
        let id = open(&mut b, 1, "a").unwrap();
        let ps: Vec<Piece> = (0..3).map(|k| bytes(0, k, 100)).collect();
        for p in &ps {
            assert_eq!(b.blocked(&id, 1000), None);
            b.serve(&id, *p).unwrap();
        }
        assert_eq!(b.blocked(&id, 1000), Some(Refusal::ValueMissing));
        // the window is kept where a piece is marked too: a request that found room a moment ago,
        // beside another that took it, marks nothing
        assert_eq!(b.serve(&id, bytes(0, 3, 100)).unwrap_err(), Refusal::ValueMissing);
        assert_eq!((b.session(&id).unwrap().pending(), b.session(&id).unwrap().served_msat), (3, 300));
        // one value makes room for one piece
        b.draw(&id, &[value(1, &ps[1], 1)], &[], 1000).unwrap();
        assert_eq!(b.blocked(&id, 1000), None);
        b.serve(&id, bytes(0, 3, 100)).unwrap();
        assert_eq!(b.blocked(&id, 1000), Some(Refusal::ValueMissing));
        // a piece with no price is not a piece: nothing waits for a value, and a full window does not refuse it
        b.serve(&id, bytes(0, 9, 0)).unwrap();
        assert_eq!(b.session(&id).unwrap().pending(), 3);
        assert_eq!(b.session(&id).unwrap().served_msat, 400);
    }

    #[test]
    fn a_void_makes_no_room_so_a_buyer_that_voids_every_piece_gets_the_window_and_no_more() {
        // whatever the cap on voids: 2 (below the window of 3), and one far above it
        for max_voids in [2u32, 1000] {
            let mut c = cfg();
            c.max_voids = max_voids;
            let mut b = Book::new(c);
            let id = open(&mut b, 1, "a").unwrap();
            let mut served = 0;
            for k in 0..50 {
                if b.blocked(&id, 1000).is_some() {
                    break;
                }
                let p = bytes(0, k, 100);
                b.serve(&id, p).unwrap();
                served += 1;
                // a void for a piece that is not open counts for nothing
                b.draw(&id, &[], &[p.id, p.id, bytes(5, 5, 1).id], 1000).unwrap();
            }
            assert_eq!((served, b.session(&id).unwrap().voids), (3, 3), "max_voids {max_voids}");
            // nothing is open, so no value can make room: the session is over, and says so
            assert_eq!(b.blocked(&id, 1000), Some(Refusal::TooManyVoids));
            assert_eq!(b.serve(&id, bytes(0, 99, 100)).unwrap_err(), Refusal::TooManyVoids);
        }
        // voids and silence mixed: still the window. One void, then two pieces left open
        let mut b = Book::new(cfg());
        let id = open(&mut b, 1, "a").unwrap();
        let p0 = bytes(0, 0, 100);
        b.serve(&id, p0).unwrap();
        b.draw(&id, &[], &[p0.id], 1000).unwrap();
        let (p1, p2) = (bytes(0, 1, 100), bytes(0, 2, 100));
        b.serve(&id, p1).unwrap();
        b.serve(&id, p2).unwrap();
        assert_eq!(b.blocked(&id, 1000), Some(Refusal::ValueMissing), "values for the open pieces would make room");
        // an honest buyer whose answer was cut once: it voided one piece and draws for the rest. Its
        // window is one narrower from then on, and it is served
        b.draw(&id, &[value(1, &p1, 1), value(2, &p2, 2)], &[], 1000).unwrap();
        assert_eq!((b.blocked(&id, 1000), b.session(&id).unwrap().unvalued()), (None, 1));
        for k in 3..5 {
            b.serve(&id, bytes(0, k, 100)).unwrap();
        }
        assert_eq!(b.blocked(&id, 1000), Some(Refusal::ValueMissing), "two open and one voided of three");
        // and past max_voids (2) the session ends, with room or without
        let mut b = Book::new(LotteryConfig::parse(&json!({"window": 8, "max_voids": 2, "chain_draws": 4096}), 40).unwrap());
        let id = open(&mut b, 1, "a").unwrap();
        for k in 0..3 {
            assert_eq!(b.blocked(&id, 1000), None);
            let p = bytes(0, k, 100);
            b.serve(&id, p).unwrap();
            b.draw(&id, &[], &[p.id], 1000).unwrap();
        }
        assert_eq!(b.blocked(&id, 1000), Some(Refusal::TooManyVoids));
    }

    #[test]
    fn a_session_closed_while_it_owes_keeps_its_place_and_one_that_owes_nothing_is_forgotten() {
        let mut b = Book::new(cfg());
        // owes nothing: every piece it was served has its value
        let clean = open(&mut b, 1, "v4:1.1.1.1").unwrap();
        let p = bytes(0, 0, 1);
        b.serve(&clean, p).unwrap();
        b.draw(&clean, &[value(1, &p, 1)], &[], 1000).unwrap();
        assert!(b.session(&clean).unwrap().unpaid.is_empty(), "1 msat on a 64-sat win does not win with this value");
        assert!(b.close(&clean, 1000) && b.session(&clean).is_none() && !b.close(&clean, 1000));
        // took the window and closed: served nothing more, known to nobody, and still in its place
        let a = open(&mut b, 2, "v4:1.1.1.1").unwrap();
        let c = open(&mut b, 3, "v4:1.1.1.1").unwrap();
        for id in [&a, &c] {
            for k in 0..3 {
                b.serve(id, bytes(0, k, 100)).unwrap();
            }
            assert!(b.close(id, 1000));
            assert_eq!(b.blocked(id, 1000), Some(Refusal::SessionUnknown));
            assert_eq!(b.authenticate(id, 0, 1000, |_| true).unwrap_err(), Refusal::SessionUnknown);
            assert_eq!(b.serve(id, bytes(1, 0, 100)).unwrap_err(), Refusal::SessionUnknown);
            assert_eq!(b.draw(id, &[], &[], 1000).unwrap_err(), Refusal::SessionUnknown);
        }
        assert_eq!(open(&mut b, 4, "v4:1.1.1.1").unwrap_err(), Refusal::TooManySessions, "two from one address, closed or not");
        assert_eq!(b.sessions(), 2);
        // until they have been quiet for first_use_secs (60), as a session that never drew is
        assert_eq!(b.sweep(1060), 0);
        assert_eq!(b.sweep(1061), 2);
        open(&mut b, 4, "v4:1.1.1.1").unwrap();
        // one void is a debt too
        let v = open(&mut b, 5, "v4:1.1.1.1").unwrap();
        let p = bytes(0, 0, 100);
        b.serve(&v, p).unwrap();
        b.draw(&v, &[], &[p.id], 2000).unwrap();
        assert!(b.close(&v, 2000) && b.session(&v).is_some_and(|s| s.closed == Some(2000)));
    }

    #[test]
    fn a_win_is_unpaid_until_the_node_says_so_and_the_grace_ends_by_time_by_pieces_and_by_count() {
        let mut b = Book::new(cfg());
        let id = open(&mut b, 1, "a").unwrap();
        // 3 in 4 odds, so a win comes at once
        until_win(&mut b, &id, 1, 48_000, 2000);
        assert_eq!((b.session(&id).unwrap().unpaid.len(), b.session(&id).unwrap().wins), (1, 1));
        assert_eq!(b.blocked(&id, 2000), None, "served on while the payment is on its way");
        assert_eq!(b.blocked(&id, 2010), None);
        assert_eq!(b.blocked(&id, 2011), Some(Refusal::WinUnpaid), "grace_seconds");
        assert_eq!((b.grace_left(&id, 2000), b.grace_left(&id, 2004), b.grace_left(&id, 2010), b.grace_left(&id, 2999), b.grace_left("nobody", 0)), (10, 6, 0, 0, 0));
        // an answer stands still for pay_wait_secs at the most, however long the grace
        let mut patient = Book::new(LotteryConfig::parse(&json!({"grace_seconds": 300, "pay_wait_secs": 7, "chain_draws": 4096}), 40).unwrap());
        let pid = open(&mut patient, 1, "a").unwrap();
        until_win(&mut patient, &pid, 1, 48_000, 2000);
        assert_eq!((patient.grace_left(&pid, 2000), patient.grace_left(&pid, 2296), patient.grace_left(&pid, 2300)), (7, 4, 0));
        // by pieces, on a fresh session: four more may be served and drawn for, the fifth is not
        let mut b = Book::new(cfg());
        let id = open(&mut b, 1, "a").unwrap();
        let d1b = until_win(&mut b, &id, 1, 48_000, 2000);
        let mut d = d1b;
        for k in 0..4u64 {
            assert_eq!(b.blocked(&id, 2000), None, "{k} pieces since the win");
            let p = bytes(1, k, 1);
            b.serve(&id, p).unwrap();
            d += 1;
            // amount 1 of 64,000: these do not win
            assert!(!b.draw(&id, &[value(d, &p, 3)], &[], 2000).unwrap().taken[0].won);
        }
        assert_eq!(b.blocked(&id, 2000), Some(Refusal::WinUnpaid), "grace_pieces");
        // the buyer's word pays nothing: only the hash of the win's own invoice does
        assert!(b.claim_invoice(&id, d1b, None, [3; 32], 2000) && !b.claim_invoice(&id, d1b, None, [4; 32], 2000), "one request asks the node for a win's invoice");
        assert_eq!(b.session(&id).unwrap().unpaid[0].invoice, Some(WinInvoice { hash: [3; 32], text: None, at: 2000 }), "the hash is the win's before the node is asked");
        b.win_invoiced(&id, d1b, &[3; 32], None);
        assert!(!b.claim_invoice(&id, d1b, None, [4; 32], 2000), "the node's answer is not known: that invoice is looked at first");
        assert!(b.claim_invoice(&id, d1b, Some(&[3; 32]), [5; 32], 2000), "and replaced when it is shown dead");
        b.win_invoiced(&id, d1b, &[5; 32], Some("lnbcrt1win".into()));
        assert!(!b.claim_invoice(&id, d1b, None, [6; 32], 2000) && !b.claim_invoice(&id, d1b, Some(&[4; 32]), [6; 32], 2000), "it has an invoice, and not that one");
        assert!(b.claim_invoice(&id, d1b, Some(&[5; 32]), [7; 32], 2000), "the one it has lapsed");
        b.win_invoiced(&id, d1b, &[6; 32], Some("lnbcrt1other".into()));
        assert_eq!(b.session(&id).unwrap().unpaid[0].invoice.as_ref().map(|i| (i.hash, i.text.clone())), Some(([7; 32], None)), "an answer for another hash moves nothing");
        b.win_invoiced(&id, d1b, &[7; 32], Some("lnbcrt1win".into()));
        assert!(!b.win_paid(&id, &[6; 32]) && !b.win_paid(&id, &[5; 32]));
        assert_eq!(b.blocked(&id, 2000), Some(Refusal::WinUnpaid));
        assert!(b.win_paid(&id, &[7; 32]) && !b.win_paid(&id, &[7; 32]));
        assert_eq!(b.blocked(&id, 2000), None);
        let s = b.session(&id).unwrap();
        assert_eq!((s.wins, s.paid_wins, s.won_msat(), s.paid_msat(), s.unpaid.len()), (1, 1, 64_000, 64_000, 0));
        // by count: two unpaid wins are borne, a third is not
        let mut at = d;
        for n in 1..=3 {
            assert_eq!(b.blocked(&id, 2000), None, "{n}");
            at = until_win(&mut b, &id, at + 1, 48_000, 2000);
            // each loss on the way counts as a piece since the earlier wins: keep them inside grace_pieces
            for w in &mut b.sessions.get_mut(&id).unwrap().unpaid {
                w.pieces_since = 0;
            }
        }
        assert_eq!(b.blocked(&id, 2000), Some(Refusal::WinUnpaid), "max_unpaid_wins");
        let t = b.totals();
        assert_eq!((t.wins, t.paid_wins, t.won_msat, t.paid_msat), (4, 1, 256_000, 64_000));
    }

    /// What a session shows of itself, to compare a book with the book a journal makes again.
    fn seen(b: &Book, id: &str) -> Value {
        let s = b.session(id).unwrap();
        json!({"seq": s.next_seq, "drawn": s.drawn(), "pending": s.pending(), "served": s.served_msat, "wins": s.wins, "paid": s.paid_wins,
               "voids": s.voids, "closed": s.closed, "addr": s.addr, "win": s.win_msat,
               "unpaid": s.unpaid.iter().map(|w| json!([w.draw, w.drawn_at, w.pieces_since, w.invoice.as_ref().map(|i| (hex::encode(i.hash), i.text.clone(), i.at))])).collect::<Vec<_>>()})
    }

    #[test]
    fn a_session_is_made_again_from_its_journal_or_its_snapshot_as_it_was() {
        use crate::store::Record;
        let mut b = Book::new(cfg());
        let id = open(&mut b, 1, "v4:192.0.2.1").unwrap();
        let other = open(&mut b, 2, "v4:192.0.2.2").unwrap();
        // requests, pieces, a void, draws until a win, its invoice asked for and made, and a second win whose invoice the node has not answered for
        b.authenticate(&id, 0, 1000, |_| true).unwrap();
        let p = bytes(0, 0, 100);
        b.serve(&id, p).unwrap();
        b.draw(&id, &[], &[p.id], 1000).unwrap();
        let w1 = until_win(&mut b, &id, 1, 48_000, 1500);
        assert!(b.claim_invoice(&id, w1, None, [5; 32], 1500));
        b.win_invoiced(&id, w1, &[5; 32], Some("lnbcrt1first".into()));
        let w2 = until_win(&mut b, &id, w1 + 1, 48_000, 1600);
        assert!(b.claim_invoice(&id, w2, None, [6; 32], 1600));
        // an open piece, and a closed session beside
        let open_piece = bytes(4, 0, 100);
        b.serve(&id, open_piece).unwrap();
        b.serve(&other, bytes(0, 0, 100)).unwrap();
        assert!(b.close(&other, 1700));
        let log = b.take_log();
        assert!(b.take_log().is_empty(), "taken once");
        // every record reads back as itself
        for r in &log {
            assert_eq!(Rec::from_json(&r.to_json()).as_ref(), Some(r), "{}", r.to_json());
        }
        assert!(!format!("{log:?}").contains(&hex::encode([1u8; 32])) && format!("{log:?}").contains("Seed(..)"), "a seed is never printed");
        let snap = b.snapshot();
        for (label, recs) in [("journal", &log), ("snapshot", &snap)] {
            let (r, problems) = Book::restore(cfg(), recs, 5000);
            assert!(problems.is_empty(), "{label}: {problems:?}");
            for s in [&id, &other] {
                assert_eq!(seen(&r, s), seen(&b, s), "{label}");
            }
            assert_eq!(r.session(&id).unwrap().active, 5000, "{label}: a session comes back with its full time to go quiet");
            // the same chain: what is revealed is what was revealed, and a repeated message is answered as before
            let mut r = r;
            let last = b.sessions.get_mut(&id).unwrap().seller.reveal();
            assert_eq!(r.sessions.get_mut(&id).unwrap().seller.reveal(), last, "{label}");
            let t = *b.session(&id).unwrap().seller.recent().last().unwrap();
            let again = r.draw(&id, &[Value32 { draw: t.draw, piece: t.piece.id, amount_msat: t.piece.amount_msat, value: t.value }], &[], 5000).unwrap();
            assert!(again.taken[0].repeated && again.refused.is_none(), "{label}");
            let other_value = Value32 { draw: t.draw, piece: t.piece.id, amount_msat: t.piece.amount_msat, value: [0xee; 32] };
            assert_eq!(r.draw(&id, &[other_value], &[], 5000).unwrap().refused, Some((t.draw, DrawError::ValueConflict)), "{label}: no second value");
            // and goes on: the open piece is the next draw
            let d = r.session(&id).unwrap().drawn() + 1;
            assert!(r.draw(&id, &[value(d, &open_piece, 9)], &[], 5000).unwrap().refused.is_none(), "{label}");
            assert!(r.blocked(&other, 5000).is_some() && r.authenticate(&other, 0, 5000, |_| true).is_err(), "{label}: a closed session stays closed");
        }
        // every prefix of the journal is a book: what a kill at any write leaves behind
        let mut drawn = 0;
        for n in 0..=log.len() {
            let (r, problems) = Book::restore(cfg(), &log[..n], 5000);
            assert!(problems.is_empty(), "{n}: {problems:?}");
            let now = r.session(&id).map_or(0, |s| s.drawn());
            assert!(now >= drawn, "{n}: the draws taken only grow with the journal");
            drawn = now;
        }
        // a session whose records do not hold together is left out, and named; the others come back
        let mut broken = log.clone();
        let at = broken.iter().position(|r| matches!(r, Rec::Take { session, .. } if session == &id)).unwrap();
        if let Rec::Take { value, .. } = &mut broken[at] {
            value[0] ^= 1;
        }
        broken.insert(at, Rec::Took { session: id.clone(), taken: Taken { draw: 999, piece: p, value: [0; 32], won: false, repeated: false } });
        let (r, problems) = Book::restore(cfg(), &broken, 5000);
        assert!(r.session(&id).is_none() && r.session(&other).is_some());
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains(&id), "{problems:?}");
    }

    #[test]
    fn every_code_a_buyer_can_be_answered_with_is_one_the_wallet_names() {
        // a wallet repeats a seller's error only as one of the codes it knows (`xbt402::ticket::PROTOCOL_CODES`):
        // every refusal of this module, and every refusal of a value, is on that list
        let draws = [DrawError::AmountNotBelowWin, DrawError::ChainSpent, DrawError::PieceUnknown, DrawError::AmountMismatch, DrawError::DrawOutOfOrder,
                     DrawError::DrawUsed, DrawError::ValueConflict, DrawError::ValueReused];
        let all = [Refusal::SessionUnknown, Refusal::BadAuth, Refusal::BadSeq(0), Refusal::TooManySessions, Refusal::WinSize, Refusal::WinUnpaid, Refusal::ValueMissing,
                   Refusal::TooManyVoids].into_iter().chain(draws.into_iter().map(Refusal::Draw));
        for r in all {
            assert!(xbt402::ticket::PROTOCOL_CODES.contains(&r.code()), "{}", r.code());
            assert_eq!(xbt402::ticket::protocol_code(Some(&json!(r.code()))), r.code());
        }
    }

    #[test]
    fn a_draw_request_stops_at_the_first_value_it_refuses_and_reveals_for_what_it_took() {
        let mut b = Book::new(cfg());
        let id = open(&mut b, 1, "a").unwrap();
        let (p1, p2, p3) = (bytes(0, 0, 100), bytes(0, 1, 100), bytes(0, 2, 100));
        for p in [p1, p2, p3] {
            b.serve(&id, p).unwrap();
        }
        assert_eq!(b.draw(&id, &[], &[], 1000).unwrap().reveal, None, "nothing is revealed before a value");
        let wrong = Value32 { amount_msat: 99, ..value(2, &p2, 1) };
        let out = b.draw(&id, &[value(1, &p1, 1), wrong, value(3, &p3, 1)], &[], 1000).unwrap();
        assert_eq!((out.taken.len(), out.refused), (1, Some((2, DrawError::AmountMismatch))));
        assert_eq!(out.reveal.unwrap().0, 1);
        assert_eq!(b.session(&id).unwrap().drawn(), 1);
        // the same request again: the first value is answered as before, and nothing is drawn twice
        let again = b.draw(&id, &[value(1, &p1, 1), value(2, &p2, 1)], &[], 1000).unwrap();
        assert!(again.taken[0].repeated && !again.taken[1].repeated);
        assert_eq!((again.reveal.unwrap().0, b.totals().drawn), (2, 2));
        assert_eq!(b.draw("nobody", &[], &[], 1000).unwrap_err(), Refusal::SessionUnknown);
    }
}
