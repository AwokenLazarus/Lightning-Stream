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
//! | A piece is served only inside the window. | [`Book::blocked`]: no more than `window` pieces are open (served, with neither a value nor a void). | A buyer that sends no values: `window` pieces a session. |
//! | A win is paid within the grace or the buyer is served nothing more. | [`Book::blocked`]: no win unpaid for more than `grace_seconds`, or once `grace_pieces` pieces were served since it was drawn, and at most `max_unpaid_wins` unpaid at once. Paid is the node's word ([`Book::win_paid`]), never the buyer's. | A buyer that never pays: what it was served up to its first win, and the grace. |
//! | A piece is voided by a buyer that knows no result, and not without end. | [`Book::draw`]: more than `max_voids` voids stop the session. | A buyer that voids every piece: `max_voids` pieces a session. |
//! | Sessions are capped in all and per address, and a quiet one is forgotten. | [`Book::open`], [`Book::sweep`]. A session costs its chain: `chain_draws` hashes to make, and one value in every 1,024 and the block last read to keep (34 KiB at the default length). | Anyone, since opening a session needs no payment: `max_sessions` chains. |
//! | A chain is for one session. | [`Book::open`] makes each chain from fresh random bytes it is given and keeps it nowhere else. A session does not outlive the gateway's process: a restart forgets the chain with the values it revealed for. | Nobody. |
use std::collections::{HashMap, VecDeque};

use serde_json::{Map, Value};
use xbt402::lottery::{Chain, DrawError, Kind, Piece, PieceId, Seller, Taken, DEFAULT_CHAIN_DRAWS, MAX_CHAIN_DRAWS};

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
    pub chain_draws: u32,
    /// The bytes of an answer that make one piece.
    pub piece_bytes: u64,
    pub max_sessions: u32,
    /// Sessions from one client address; 0 is no cap per address.
    pub sessions_per_address: u32,
    /// Pieces one session may void before it is served nothing more.
    pub max_voids: u32,
    /// A session is forgotten after this many seconds without a request.
    pub idle_secs: u64,
    /// A session that has never given a value is forgotten after this many seconds.
    pub first_use_secs: u64,
    /// A win's invoice can be paid for this many seconds; an unpaid win gets a new one after.
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
                "chain_draws",
                "piece_bytes",
                "max_sessions",
                "sessions_per_address",
                "max_voids",
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
        if !(5..=3600).contains(&c.invoice_secs) {
            return Err("lottery.invoice_secs is from 5 to 3600".into());
        }
        Ok(c)
    }

    fn read(m: &Map<String, Value>, ticket_blocks: u32) -> Result<Self, String> {
        let win_msat = num(m, "win_msat", 64_000)?;
        Ok(Self {
            win_msat,
            min_win_msat: num(m, "min_win_msat", win_msat.min(16_000))?,
            win_blocks: num32(m, "win_blocks", ticket_blocks)?,
            window: num32(m, "window", 8)?,
            // a wallet pays 8 wins at a time (a channel may carry 30 pending payments): with 100 sellers of one
            // buyer winning at once the last of them waited 13 s on the lab, and 10 s cut that seller's answer
            grace_seconds: num32(m, "grace_seconds", 30)?,
            grace_pieces: num32(m, "grace_pieces", 64)?,
            max_unpaid_wins: num32(m, "max_unpaid_wins", 2)?,
            chain_draws: num32(m, "chain_draws", DEFAULT_CHAIN_DRAWS)?,
            piece_bytes: num(m, "piece_bytes", 262_144)?,
            max_sessions: num32(m, "max_sessions", 64)?,
            sessions_per_address: num32(m, "sessions_per_address", 4)?,
            max_voids: num32(m, "max_voids", 16)?,
            idle_secs: num(m, "idle_secs", 300)?,
            first_use_secs: num(m, "first_use_secs", 60)?,
            invoice_secs: num32(m, "invoice_secs", 60)?,
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

    /// Whether a route is offered by lottery: every piece of it costs less than the largest win.
    /// A route with a dearer piece is paid with tickets, and its 402 has no lottery entry.
    pub fn offers(&self, price: &Price) -> bool {
        !price.is_free() && self.dearest_piece(price).is_some_and(|d| d < self.win_msat)
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

/// A win that is not paid yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Win {
    pub draw: u64,
    /// The invoice the buyer was sent for it, with its payment hash and when it was issued. None
    /// until the node has made one.
    pub invoice: Option<(Hash, String, u64)>,
    /// A request is asking the node for this win's invoice now: no other one does.
    pub issuing: bool,
    /// When the win was drawn, and the pieces served to its session since.
    pub drawn_at: u64,
    pub pieces_since: u32,
}

/// One buyer's session.
#[derive(Debug)]
pub struct Session {
    pub key: [u8; 32],
    seller: Seller,
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
}

impl Session {
    pub fn drawn(&self) -> u64 {
        self.seller.drawn()
    }

    pub fn pending(&self) -> usize {
        self.seller.pending_count()
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
}

impl Book {
    pub fn new(cfg: LotteryConfig) -> Self {
        Self { cfg, sessions: HashMap::new(), totals: Totals::default() }
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
    /// `chain`, made by the caller from 32 more that are used for nothing else. Returns the id.
    pub fn open(&mut self, entropy: &[u8; 48], chain: Chain, addr: &str, win_msat: u64, now: u64) -> Result<String, Refusal> {
        self.room(addr)?;
        let id = hex::encode(&entropy[..16]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&entropy[16..]);
        if self.sessions.contains_key(&id) {
            return Err(Refusal::TooManySessions);
        }
        let seller = Seller::new(&id, win_msat, chain).map_err(Refusal::Draw)?;
        self.sessions.insert(
            id.clone(),
            Session {
                key,
                seller,
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
            },
        );
        self.totals.opened += 1;
        Ok(id)
    }

    pub fn anchor(&self, id: &str) -> Option<[u8; 32]> {
        self.sessions.get(id).map(|s| s.seller.anchor())
    }

    /// The session exists, `verify` accepts its key, `seq` is the next one. A `seq` is used up by
    /// any request that passes here, served or not.
    pub fn authenticate(&mut self, session: &str, seq: u64, now: u64, verify: impl FnOnce(&[u8; 32]) -> bool) -> Result<(), Refusal> {
        let s = self.sessions.get_mut(session).ok_or(Refusal::SessionUnknown)?;
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
        Ok(())
    }

    /// Why this session is served no further piece now, if it is not.
    pub fn blocked(&self, session: &str, now: u64) -> Option<Refusal> {
        let Some(s) = self.sessions.get(session) else { return Some(Refusal::SessionUnknown) };
        if s.voids > self.cfg.max_voids {
            return Some(Refusal::TooManyVoids);
        }
        let late = |w: &Win| now.saturating_sub(w.drawn_at) > u64::from(self.cfg.grace_seconds) || w.pieces_since >= self.cfg.grace_pieces;
        if s.unpaid.len() > self.cfg.max_unpaid_wins as usize || s.unpaid.iter().any(late) {
            return Some(Refusal::WinUnpaid);
        }
        if s.seller.pending_count() >= self.cfg.window as usize {
            return Some(Refusal::ValueMissing);
        }
        None
    }

    /// A piece has left for the buyer. A piece with no price is not a piece.
    pub fn serve(&mut self, session: &str, piece: Piece) -> Result<(), Refusal> {
        let s = self.sessions.get_mut(session).ok_or(Refusal::SessionUnknown)?;
        if piece.amount_msat == 0 {
            return Ok(());
        }
        s.seller.serve(piece).map_err(Refusal::Draw)?;
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
        let s = self.sessions.get_mut(session).ok_or(Refusal::SessionUnknown)?;
        for id in voids {
            if s.seller.void(*id) {
                s.voids = s.voids.saturating_add(1);
            }
        }
        let mut out = Drawn { reveal: None, taken: vec![], refused: None };
        for v in values {
            match s.seller.take(v.draw, v.piece, v.amount_msat, &v.value) {
                Ok(t) => {
                    if !t.repeated {
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
    /// it has none yet). False: the win is gone, has another invoice by now, or someone else is
    /// asking. Two answers of one session look at its wins at the same moment, and a win with two
    /// invoices could be paid on the one the book has forgotten.
    pub fn claim_invoice(&mut self, session: &str, draw: u64, old: Option<&Hash>) -> bool {
        match self.sessions.get_mut(session).and_then(|s| s.unpaid.iter_mut().find(|w| w.draw == draw)) {
            Some(w) if !w.issuing && w.invoice.as_ref().map(|(h, _, _)| h) == old => {
                w.issuing = true;
                true
            }
            _ => false,
        }
    }

    /// The node's answer to a claimed invoice: the invoice, or None when it made none.
    pub fn win_invoiced(&mut self, session: &str, draw: u64, made: Option<(Hash, String)>, now: u64) {
        if let Some(w) = self.sessions.get_mut(session).and_then(|s| s.unpaid.iter_mut().find(|w| w.draw == draw)) {
            w.issuing = false;
            if let Some((hash, invoice)) = made {
                w.invoice = Some((hash, invoice, now));
            }
        }
    }

    /// The node shows the invoice `hash` of a win paid in full. True if that win was unpaid.
    pub fn win_paid(&mut self, session: &str, hash: &Hash) -> bool {
        let Some(s) = self.sessions.get_mut(session) else { return false };
        let before = s.unpaid.len();
        s.unpaid.retain(|w| w.invoice.as_ref().is_none_or(|(h, _, _)| h != hash));
        let paid = (before - s.unpaid.len()) as u64;
        s.paid_wins += paid;
        self.totals.paid_wins += paid;
        self.totals.paid_msat = self.totals.paid_msat.saturating_add(paid.saturating_mul(s.win_msat));
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

    /// Forget a session the buyer closed. Its unpaid wins go with it: their invoices lapse.
    pub fn close(&mut self, session: &str) -> bool {
        self.sessions.remove(session).is_some()
    }

    /// Forget the sessions that have gone quiet: none with an answer still being sent. Returns
    /// how many went.
    pub fn sweep(&mut self, now: u64) -> usize {
        let cfg = &self.cfg;
        let before = self.sessions.len();
        self.sessions.retain(|_, s| {
            let quiet = now.saturating_sub(s.active);
            let unused = s.seller.drawn() == 0 && now.saturating_sub(s.opened) > cfg.first_use_secs && quiet > cfg.first_use_secs;
            s.open_responses > 0 || !(quiet > cfg.idle_secs || unused)
        });
        before - self.sessions.len()
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
        b.open(&e, Chain::new([n; 32], b.cfg().chain_draws).unwrap(), addr, win, 1000)
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
        assert_eq!((c.piece_bytes, c.max_sessions, c.sessions_per_address, c.max_voids), (262_144, 64, 4, 16));
        assert_eq!((c.idle_secs, c.first_use_secs, c.invoice_secs), (300, 60, 60));
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
            json!({"window": "8"}),
            json!({"windows": 8}),
            json!([]),
        ] {
            assert!(LotteryConfig::parse(&bad, 40).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_route_is_offered_by_lottery_only_if_every_piece_costs_less_than_a_win() {
        let c = LotteryConfig::parse(&json!({}), 40).unwrap();
        let p = |request_msat, byte_msat, per_bytes, second_msat| Price { request_msat, byte_msat, per_bytes, second_msat };
        assert!(c.offers(&p(100, 0, 1, 0)) && !c.offers(&p(0, 0, 1, 0)), "a free route has nothing to draw for");
        assert!(c.offers(&p(63_999, 0, 1, 0)) && !c.offers(&p(64_000, 0, 1, 0)));
        assert!(c.offers(&p(0, 0, 1, 63_999)) && !c.offers(&p(0, 0, 1, 64_000)));
        // 100 msat for a piece of 256 KiB; and a price at which one piece is a whole win
        assert!(c.offers(&p(0, 100, 262_144, 0)));
        assert!(!c.offers(&p(0, 64_000, 262_144, 0)) && c.offers(&p(0, 63_999, 262_144, 0)));
        assert!(!c.offers(&p(0, u64::MAX, 1, 0)), "a price that does not fit is no offer");
        assert_eq!(c.dearest_piece(&p(5, 100, 262_144, 7)), Some(100));
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
        // one value, or one void, makes room for one piece
        b.draw(&id, &[value(1, &ps[1], 1)], &[], 1000).unwrap();
        assert_eq!(b.blocked(&id, 1000), None);
        b.serve(&id, bytes(0, 3, 100)).unwrap();
        assert_eq!(b.blocked(&id, 1000), Some(Refusal::ValueMissing));
        b.draw(&id, &[], &[ps[0].id], 1000).unwrap();
        assert_eq!((b.blocked(&id, 1000), b.session(&id).unwrap().voids), (None, 1));
        // a piece with no price is not a piece: nothing waits for a value
        b.serve(&id, bytes(0, 9, 0)).unwrap();
        assert_eq!(b.session(&id).unwrap().pending(), 2);
        assert_eq!(b.session(&id).unwrap().served_msat, 400);
    }

    #[test]
    fn a_buyer_that_voids_every_piece_is_stopped() {
        let mut b = Book::new(cfg());
        let id = open(&mut b, 1, "a").unwrap();
        for k in 0..3 {
            let p = bytes(0, k, 100);
            b.serve(&id, p).unwrap();
            // a void for a piece that is not open counts for nothing
            b.draw(&id, &[], &[p.id, p.id, bytes(5, 5, 1).id], 1000).unwrap();
        }
        assert_eq!((b.session(&id).unwrap().voids, b.blocked(&id, 1000)), (3, Some(Refusal::TooManyVoids)));
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
        assert!(b.claim_invoice(&id, d1b, None) && !b.claim_invoice(&id, d1b, None), "one request asks the node for a win's invoice");
        b.win_invoiced(&id, d1b, None, 2000);
        assert!(b.claim_invoice(&id, d1b, None), "the node made none: the next request asks again");
        b.win_invoiced(&id, d1b, Some(([5; 32], "lnbcrt1win".into())), 2000);
        assert!(!b.claim_invoice(&id, d1b, None) && !b.claim_invoice(&id, d1b, Some(&[4; 32])), "it has an invoice, and not that one");
        assert!(b.claim_invoice(&id, d1b, Some(&[5; 32])), "the one it has lapsed");
        b.win_invoiced(&id, d1b, Some(([5; 32], "lnbcrt1win".into())), 2000);
        assert!(!b.win_paid(&id, &[6; 32]));
        assert_eq!(b.blocked(&id, 2000), Some(Refusal::WinUnpaid));
        assert!(b.win_paid(&id, &[5; 32]) && !b.win_paid(&id, &[5; 32]));
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
