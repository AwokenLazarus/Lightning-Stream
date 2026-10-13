//! The lottery, pay after a win (`docs/TICKETS.md`, section 9): a piece priced below one payment is
//! paid by a fair draw that wins a payment of one fixed size with probability price ÷ that size.
//! This module is the draw and the two sides' bookkeeping of it. No IO, no clock and no random
//! source: the seller's gateway (`xbt-gateway`) and the wallet's signer both build on it, and each
//! brings its own.
//!
//! ```text
//! c[n]  = the seller's seed;  c[i-1] = SHA256(c[i]);  c[0] is the anchor, sent when a session opens
//! piece = SHA256("lottery/0/piece" ‖ seq:8 ‖ req:32 ‖ kind:1 ‖ k:8 ‖ amount_msat:8 ‖ win_msat:8)
//! d     = SHA256("lottery/0/draw" ‖ len(session):1 ‖ session ‖ i:8 ‖ c[i]:32 ‖ b:32 ‖ piece:32)
//! win   = uint64(d[0..8]) < floor(2^64 × amount_msat / win_msat)
//! ```
//!
//! Integers are big-endian. `i` is the number of the draw in its session, from 1: the buyer gives
//! its value `b` for draw `i` only after it has the piece, and draws are numbered in the order the
//! buyer gives values, with no gaps. The seller reveals `c[i]` only when it holds the value of draw
//! `i`, so it never discloses a chain value below a draw that is still open.
//!
//! **The fairness argument is this project's own and has not been reviewed.** It takes SHA-256 as
//! a random function. The seller fixed `c[i]` with the anchor before it saw any value of the
//! buyer's; the buyer picks `b` holding `c[i-1]` at most, and `c[i]` is a preimage of that. So `d`
//! is uniform to each side when it commits, and a draw wins with probability
//! `floor(2^64 × amount / win) / 2^64`: the price over the win size, short by less than 2^-64.
//!
//! **Each rule, the check that names it, and who could break it:**
//!
//! | Rule | Kept by | Broken by |
//! |---|---|---|
//! | A chain value is the one the anchor fixed. | [`Buyer::absorb`]: the reveal hashed down to the last value held, in exactly `drawn − verified` steps ([`DrawError::RevealNotOnChain`]). | A seller that reveals another value, or the right value for another index. |
//! | A reveal costs bounded work. | [`MAX_REVEAL_STEPS`] ([`DrawError::RevealTooFar`]); a buyer gives at most `ahead` values beyond its last checked reveal ([`DrawError::RevealWithheld`]). | A seller that sends a far index, or that takes values and reveals nothing. |
//! | Reveals only go forward. | [`DrawError::RevealBehind`], [`DrawError::RevealAhead`]. | A seller that reveals out of order, or a value for a draw the buyer gave nothing for. |
//! | A win is one the buyer worked out. | [`Buyer::absorb`] computes every draw up to the reveal itself, and only it makes a [`Win`]. | A seller that claims a win for a losing draw or for a piece it never served. |
//! | One value per draw, in order. | [`Seller::take`]: the next index only ([`DrawError::DrawOutOfOrder`]); a second, different value for an index is [`DrawError::ValueConflict`]. | A buyer that waits for a reveal and then picks a losing value. |
//! | A value is used once in a session. | [`Seller::take`] and [`Buyer::issue`] ([`DrawError::ValueReused`]). | A buyer whose values repeat: they are not random, and a seller that could predict them could pick a chain that wins. |
//! | A draw is for a piece that was served, at its price. | [`Seller::take`]: the piece is one of [`Seller::serve`] with no value yet ([`DrawError::PieceUnknown`]), at the same amount ([`DrawError::AmountMismatch`]); both are inside `d`. | A buyer that names a cheaper piece, or draws twice for one. |
//! | A piece below one win only. | [`Odds::new`] ([`DrawError::AmountNotBelowWin`]). | Terms that price a piece at a whole win or more: those are paid with tickets. |
//! | A chain is for one session and ends. | The caller makes one [`Chain`] per [`Seller`]; [`DrawError::ChainSpent`]. | A seller that reuses a chain lets two buyers know values ahead: its own loss. |
use std::collections::{BTreeMap, HashSet, VecDeque};

use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::json::py_str;
use crate::ticket::{ASSET, FEATURE_BLAKE2B};
use crate::wire::{put_field, tagged};

pub const SCHEME: &str = "lottery";
pub const VERSION: &str = "lottery/0";
/// Where the session endpoints live on the seller's origin unless its terms say otherwise.
pub const SESSION_PATH: &str = "/x402/lottery";
pub const RECEIPT_TAG: &str = "xbt402/lottery-receipt/v0";
/// `pay` in the terms: a win is paid by an ordinary invoice the seller sends with it. The one way
/// built; a later way (a win paid from a locked ticket) takes another name here.
pub const PAY_ON_WIN: &str = "on-win";
/// `release` in the terms: the route's pieces can be checked one by one, and a buyer gives its
/// value for a piece after the piece checked out.
pub const RELEASE_AFTER_VERIFY: &str = "after-verify";
/// `release` in the terms: a value follows any answer.
pub const RELEASE_AFTER_ANSWER: &str = "after-answer";
const DRAW_TAG: &[u8] = b"lottery/0/draw";
const PIECE_TAG: &[u8] = b"lottery/0/piece";
/// A reveal further than this past the last one is refused, so that a wrong value costs a bounded
/// number of hashes.
pub const MAX_REVEAL_STEPS: u64 = 4096;
/// The draws one chain covers unless the terms say otherwise, and the most they may say.
pub const DEFAULT_CHAIN_DRAWS: u32 = 65_536;
pub const MAX_CHAIN_DRAWS: u32 = 1 << 20;
/// The seller keeps one chain value in this many and rebuilds a block at a time.
const CHECKPOINT_EVERY: u32 = 1024;
/// The draws a seller can still answer a repeated message for.
const RECENT_DRAWS: usize = 64;
/// A session id is at most this long: its length is one byte of the draw.
pub const MAX_SESSION_LEN: usize = 64;

/// What a check of this module refuses, each by the name of the rule it keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DrawError {
    #[error("a piece priced at one win or more is not paid by a draw")]
    AmountNotBelowWin,
    #[error("a piece with no price has no draw")]
    NothingToDraw,
    #[error("the session's chain has no value left")]
    ChainSpent,
    #[error("the chain length is outside 1 to 1,048,576")]
    ChainLength,
    #[error("the session id is empty or longer than 64 bytes")]
    SessionName,
    #[error("this piece has had a value or a void already")]
    PieceRepeated,
    #[error("no piece of that name was served and is still open")]
    PieceUnknown,
    #[error("the amount is not the price of that piece")]
    AmountMismatch,
    #[error("a draw is taken only as the next one of its session")]
    DrawOutOfOrder,
    #[error("that draw was taken too long ago to answer again")]
    DrawUsed,
    #[error("a second, different value for a draw that has one")]
    ValueConflict,
    #[error("a value this session has used before")]
    ValueReused,
    #[error("the reveal is for a draw at or before one already checked")]
    RevealBehind,
    #[error("the reveal is for a draw the buyer gave no value for")]
    RevealAhead,
    #[error("the reveal is more than 4,096 draws past the last one checked")]
    RevealTooFar,
    #[error("the reveal does not hash down to the last chain value held")]
    RevealNotOnChain,
    #[error("the seller holds values it has not revealed for")]
    RevealWithheld,
}

impl DrawError {
    /// The code a seller answers with, for the refusals a buyer can cause.
    pub fn code(self) -> &'static str {
        match self {
            Self::AmountNotBelowWin => "amount_not_below_win",
            Self::NothingToDraw => "nothing_to_draw",
            Self::ChainSpent => "chain_spent",
            Self::ChainLength => "chain_length",
            Self::SessionName => "session_name",
            Self::PieceRepeated => "piece_repeated",
            Self::PieceUnknown => "piece_unknown",
            Self::AmountMismatch => "amount_mismatch",
            Self::DrawOutOfOrder => "draw_out_of_order",
            Self::DrawUsed => "draw_used",
            Self::ValueConflict => "value_conflict",
            Self::ValueReused => "value_reused",
            Self::RevealBehind => "reveal_behind",
            Self::RevealAhead => "reveal_ahead",
            Self::RevealTooFar => "reveal_too_far",
            Self::RevealNotOnChain => "reveal_not_on_chain",
            Self::RevealWithheld => "reveal_withheld",
        }
    }
}

fn sha(x: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(x).into()
}

/// `v` hashed `steps` times: `c[i - steps]` from `c[i]`.
pub fn hash_down(v: &[u8; 32], steps: u64) -> [u8; 32] {
    let mut out = *v;
    for _ in 0..steps {
        out = sha(&out);
    }
    out
}

/// The odds of one draw as an exact ratio: a piece priced `amount_msat` wins `win_msat` with
/// probability `amount_msat / win_msat`. Kept as the two integers, never as a rounded "1 in N".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Odds {
    amount_msat: u64,
    win_msat: u64,
}

impl Odds {
    /// A price below the win size, and not nothing.
    pub fn new(amount_msat: u64, win_msat: u64) -> Result<Self, DrawError> {
        if amount_msat == 0 {
            return Err(DrawError::NothingToDraw);
        }
        if amount_msat >= win_msat {
            return Err(DrawError::AmountNotBelowWin);
        }
        Ok(Self { amount_msat, win_msat })
    }

    /// `floor(2^64 × amount / win)`: the win test's limit. Below 2^64 since the amount is below the
    /// win, and what the floor drops is less than one part in 2^64 of a draw.
    pub fn threshold(self) -> u64 {
        ((u128::from(self.amount_msat) << 64) / u128::from(self.win_msat)) as u64
    }

    /// Whether these odds are at most `num` in `den` (the owner's cap), in exact arithmetic.
    pub fn at_most(self, num: u64, den: u64) -> bool {
        u128::from(self.amount_msat) * u128::from(den) <= u128::from(self.win_msat) * u128::from(num)
    }
}

/// What a piece is a piece of: the request's own price, a run of the answer's bytes, or one
/// second the answer was open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Request,
    Bytes,
    Second,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Bytes => "bytes",
            Self::Second => "second",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [Self::Request, Self::Bytes, Self::Second].into_iter().find(|k| k.name() == s)
    }

    fn byte(self) -> u8 {
        match self {
            Self::Request => 0,
            Self::Bytes => 1,
            Self::Second => 2,
        }
    }
}

/// The name of a piece in its session: the request's `seq`, what kind of piece, and which one of
/// that kind in that request (from 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PieceId {
    pub seq: u64,
    pub kind: Kind,
    pub k: u64,
}

/// A piece as a draw binds it: its name, the digest of its request (`request_digest_v2`) and its
/// price.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Piece {
    pub id: PieceId,
    pub req: [u8; 32],
    pub amount_msat: u64,
}

impl Piece {
    /// What goes into the draw for this piece: every field at a fixed width, and the win size, so
    /// that both sides drew at the same odds or got different results.
    pub fn digest(&self, win_msat: u64) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(PIECE_TAG);
        h.update(self.id.seq.to_be_bytes());
        h.update(self.req);
        h.update([self.id.kind.byte()]);
        h.update(self.id.k.to_be_bytes());
        h.update(self.amount_msat.to_be_bytes());
        h.update(win_msat.to_be_bytes());
        h.finalize().into()
    }
}

fn session_ok(session: &str) -> Result<(), DrawError> {
    if session.is_empty() || session.len() > MAX_SESSION_LEN {
        return Err(DrawError::SessionName);
    }
    Ok(())
}

/// `d` for draw `draw` of `session` (a name [`Seller::new`] or [`Buyer::new`] accepted).
pub fn draw_digest(session: &str, draw: u64, chain_value: &[u8; 32], value: &[u8; 32], piece: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DRAW_TAG);
    h.update([session.len() as u8]);
    h.update(session.as_bytes());
    h.update(draw.to_be_bytes());
    h.update(chain_value);
    h.update(value);
    h.update(piece);
    h.finalize().into()
}

/// The win test on `d`.
pub fn wins(d: &[u8; 32], odds: Odds) -> bool {
    let mut first = [0u8; 8];
    first.copy_from_slice(&d[..8]);
    u64::from_be_bytes(first) < odds.threshold()
}

fn outcome(session: &str, win_msat: u64, draw: u64, chain_value: &[u8; 32], value: &[u8; 32], piece: &Piece) -> Result<bool, DrawError> {
    let odds = Odds::new(piece.amount_msat, win_msat)?;
    Ok(wins(&draw_digest(session, draw, chain_value, value, &piece.digest(win_msat)), odds))
}

/// The first 8 bytes of a value, which is what a session remembers of it. Two random values share
/// them with probability 2^-64.
fn prefix(value: &[u8; 32]) -> u64 {
    let mut first = [0u8; 8];
    first.copy_from_slice(&value[..8]);
    u64::from_be_bytes(first)
}

/// The seller's chain: `len` values hashed down from a seed. It keeps one value in 1,024 and the
/// block it last read from, 64 KiB for the longest chain and 34 KiB for the default.
pub struct Chain {
    len: u32,
    /// `checkpoints[k] = c[k × 1024]`, and the seed last when `len` is no multiple of 1,024.
    checkpoints: Vec<[u8; 32]>,
    seed: [u8; 32],
    /// `block[j] = c[block_base + j]`, read downwards from a checkpoint.
    block: Vec<[u8; 32]>,
    block_base: u32,
}

impl std::fmt::Debug for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Chain({} draws)", self.len)
    }
}

impl Chain {
    /// The chain of `len` draws under `seed`, which must be fresh random bytes used for no other
    /// chain: `len` hashes.
    pub fn new(seed: [u8; 32], len: u32) -> Result<Self, DrawError> {
        if len == 0 || len > MAX_CHAIN_DRAWS {
            return Err(DrawError::ChainLength);
        }
        let mut down = vec![];
        let mut v = seed;
        for i in (0..len).rev() {
            v = sha(&v);
            if i % CHECKPOINT_EVERY == 0 {
                down.push(v);
            }
        }
        down.reverse();
        Ok(Self { len, checkpoints: down, seed, block: vec![], block_base: 0 })
    }

    pub fn len(&self) -> u32 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// `c[0]`: what the seller commits to before the session.
    pub fn anchor(&self) -> [u8; 32] {
        self.checkpoints[0]
    }

    /// `c[i]` for `1 ≤ i ≤ len`: at most 1,023 hashes, and none for an index in the block last read.
    pub fn value(&mut self, i: u32) -> Option<[u8; 32]> {
        if i == 0 || i > self.len {
            return None;
        }
        if i == self.len {
            return Some(self.seed);
        }
        let base = i - i % CHECKPOINT_EVERY;
        if self.block.is_empty() || self.block_base != base {
            // the block [base, top): read down from the checkpoint above it, or from the seed
            let top = base.saturating_add(CHECKPOINT_EVERY).min(self.len);
            let mut v = if top == self.len { self.seed } else { self.checkpoints[(top / CHECKPOINT_EVERY) as usize] };
            let mut block = vec![[0u8; 32]; (top - base) as usize];
            for j in (base..top).rev() {
                v = sha(&v);
                block[(j - base) as usize] = v;
            }
            self.block = block;
            self.block_base = base;
        }
        Some(self.block[(i - self.block_base) as usize])
    }
}

/// One draw as the seller took it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Taken {
    pub draw: u64,
    pub piece: Piece,
    pub value: [u8; 32],
    pub won: bool,
    /// The same message had been taken before: nothing changed, and this is the first answer.
    pub repeated: bool,
}

/// The seller's side of one session's draws: the chain, the pieces served that have no value
/// yet, and the draws taken. Bounds: `pending` is what the caller serves ahead (its window),
/// `recent` is [`RECENT_DRAWS`], and `seen` is 8 bytes per draw of a chain of at most
/// [`MAX_CHAIN_DRAWS`].
#[derive(Debug)]
pub struct Seller {
    session: String,
    win_msat: u64,
    chain: Chain,
    drawn: u64,
    pending: BTreeMap<PieceId, Piece>,
    recent: VecDeque<Taken>,
    seen: HashSet<u64>,
    served: HashSet<PieceId>,
}

impl Seller {
    pub fn new(session: &str, win_msat: u64, chain: Chain) -> Result<Self, DrawError> {
        session_ok(session)?;
        Ok(Self { session: session.into(), win_msat, chain, drawn: 0, pending: BTreeMap::new(), recent: VecDeque::new(), seen: HashSet::new(), served: HashSet::new() })
    }

    pub fn anchor(&self) -> [u8; 32] {
        self.chain.anchor()
    }

    /// The draws taken so far: the index of the last one.
    pub fn drawn(&self) -> u64 {
        self.drawn
    }

    /// The draws the chain has left.
    pub fn left(&self) -> u64 {
        u64::from(self.chain.len()).saturating_sub(self.drawn)
    }

    /// The pieces served that have neither a value nor a void, oldest first.
    pub fn pending(&self) -> impl Iterator<Item = &Piece> {
        self.pending.values()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// A piece was served: it waits for the buyer's value. The seller calls this when the piece
    /// has left, never before, so that a value can only follow the work it pays for.
    pub fn serve(&mut self, piece: Piece) -> Result<(), DrawError> {
        Odds::new(piece.amount_msat, self.win_msat)?;
        if self.pending.len() as u64 >= self.left() {
            return Err(DrawError::ChainSpent);
        }
        if !self.served.insert(piece.id) {
            return Err(DrawError::PieceRepeated);
        }
        self.pending.insert(piece.id, piece);
        Ok(())
    }

    /// The buyer says this piece will get no value (it never arrived, or failed its check). True
    /// if it was open. The buyer knows no result when it says so.
    pub fn void(&mut self, id: PieceId) -> bool {
        self.pending.remove(&id).is_some()
    }

    /// Forget which pieces of requests before `seq` were served: a buyer names no piece of a
    /// request older than the ones still open. Keeps `served` to the requests in flight.
    pub fn forget_before(&mut self, seq: u64) {
        let keep = self.pending.keys().next().map_or(seq, |p| p.seq.min(seq));
        self.served.retain(|p| p.seq >= keep);
    }

    /// Take the buyer's value for draw `draw`, which it says is for piece `id` at `amount_msat`.
    /// On `Ok` the draw is used and its chain value may be revealed ([`Self::reveal`]); the caller
    /// MUST have this on disk before the reveal leaves, or a restart forgets a value it has
    /// revealed for and takes another.
    pub fn take(&mut self, draw: u64, id: PieceId, amount_msat: u64, value: &[u8; 32]) -> Result<Taken, DrawError> {
        if draw <= self.drawn {
            return match self.recent.iter().find(|t| t.draw == draw) {
                Some(t) if t.value == *value && t.piece.id == id && t.piece.amount_msat == amount_msat => Ok(Taken { repeated: true, ..*t }),
                Some(_) => Err(DrawError::ValueConflict),
                None => Err(DrawError::DrawUsed),
            };
        }
        if draw != self.drawn + 1 {
            return Err(DrawError::DrawOutOfOrder);
        }
        let i = u32::try_from(draw).map_err(|_| DrawError::ChainSpent)?;
        let piece = *self.pending.get(&id).ok_or(DrawError::PieceUnknown)?;
        if piece.amount_msat != amount_msat {
            return Err(DrawError::AmountMismatch);
        }
        if self.seen.contains(&prefix(value)) {
            return Err(DrawError::ValueReused);
        }
        let c = self.chain.value(i).ok_or(DrawError::ChainSpent)?;
        let won = outcome(&self.session, self.win_msat, draw, &c, value, &piece)?;
        self.pending.remove(&id);
        self.seen.insert(prefix(value));
        self.drawn = draw;
        let taken = Taken { draw, piece, value: *value, won, repeated: false };
        if self.recent.len() == RECENT_DRAWS {
            self.recent.pop_front();
        }
        self.recent.push_back(taken);
        Ok(taken)
    }

    /// The last draw taken and its chain value: what a seller reveals. Every draw up to it has
    /// its value, since draws are taken in order, so the reveal discloses nothing still open.
    pub fn reveal(&mut self) -> Option<(u64, [u8; 32])> {
        let i = u32::try_from(self.drawn).ok()?;
        self.chain.value(i).map(|c| (self.drawn, c))
    }
}

/// A draw the buyer worked out and found to be a win. Only [`Buyer::absorb`] makes one, so a
/// function that takes a `Win` pays nothing a seller, or a caller, merely says was won.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Win {
    session: String,
    draw: u64,
    piece: Piece,
    win_msat: u64,
}

impl Win {
    pub fn session(&self) -> &str {
        &self.session
    }

    pub fn draw(&self) -> u64 {
        self.draw
    }

    pub fn piece(&self) -> &Piece {
        &self.piece
    }

    /// What the win pays: the session's win size.
    pub fn win_msat(&self) -> u64 {
        self.win_msat
    }
}

/// One draw as the buyer worked it out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub draw: u64,
    pub piece: Piece,
    pub win: Option<Win>,
}

/// The buyer's side of one session's draws: the last chain value it checked, and the values it
/// gave that no reveal covers yet. Bounds: `open` is at most the `ahead` the caller issues with;
/// `pieces` and `values` hold one entry per draw of a chain of at most [`MAX_CHAIN_DRAWS`].
#[derive(Debug)]
pub struct Buyer {
    session: String,
    win_msat: u64,
    chain_draws: u32,
    last: [u8; 32],
    verified: u64,
    issued: u64,
    open: BTreeMap<u64, (Piece, [u8; 32])>,
    pieces: HashSet<PieceId>,
    values: HashSet<u64>,
}

impl Buyer {
    /// A session whose seller committed to `anchor` for a chain of `chain_draws` before any value.
    pub fn new(session: &str, win_msat: u64, anchor: [u8; 32], chain_draws: u32) -> Result<Self, DrawError> {
        session_ok(session)?;
        if chain_draws == 0 || chain_draws > MAX_CHAIN_DRAWS {
            return Err(DrawError::ChainLength);
        }
        Ok(Self { session: session.into(), win_msat, chain_draws, last: anchor, verified: 0, issued: 0, open: BTreeMap::new(), pieces: HashSet::new(), values: HashSet::new() })
    }

    /// The last draw a checked reveal covers, and the last one a value was given for.
    pub fn verified(&self) -> u64 {
        self.verified
    }

    pub fn issued(&self) -> u64 {
        self.issued
    }

    /// The values given that no checked reveal covers, oldest first: what a repeated message
    /// carries, unchanged.
    pub fn open(&self) -> impl Iterator<Item = (u64, &Piece, &[u8; 32])> {
        self.open.iter().map(|(d, (p, v))| (*d, p, v))
    }

    /// Give `value` for `piece`, which the caller has received (and, where it can, checked): the
    /// draw it becomes. `value` MUST be fresh random bytes from the buyer's own source, never
    /// derived from anything the seller has seen. Refused while `ahead` values or more wait for a
    /// reveal: a seller that takes values and reveals nothing gets no more of them.
    pub fn issue(&mut self, piece: Piece, value: [u8; 32], ahead: u64) -> Result<u64, DrawError> {
        Odds::new(piece.amount_msat, self.win_msat)?;
        if self.issued >= u64::from(self.chain_draws) {
            return Err(DrawError::ChainSpent);
        }
        if self.open.len() as u64 >= ahead.max(1) {
            return Err(DrawError::RevealWithheld);
        }
        if self.pieces.contains(&piece.id) {
            return Err(DrawError::PieceRepeated);
        }
        if !self.values.insert(prefix(&value)) {
            return Err(DrawError::ValueReused);
        }
        self.pieces.insert(piece.id);
        self.issued += 1;
        self.open.insert(self.issued, (piece, value));
        Ok(self.issued)
    }

    /// This piece gets no value, ever. False if it has had one or a void.
    pub fn void(&mut self, id: PieceId) -> bool {
        self.pieces.insert(id)
    }

    /// Check the seller's reveal of `c[drawn]` and work out every draw it covers. An error
    /// changes nothing. A reveal of the draw already checked, with the value already held, is
    /// the answer to a repeated message and covers nothing new.
    pub fn absorb(&mut self, drawn: u64, reveal: &[u8; 32]) -> Result<Vec<Outcome>, DrawError> {
        if drawn == self.verified && drawn > 0 {
            return if *reveal == self.last { Ok(vec![]) } else { Err(DrawError::RevealNotOnChain) };
        }
        if drawn <= self.verified {
            return Err(DrawError::RevealBehind);
        }
        if drawn > self.issued {
            return Err(DrawError::RevealAhead);
        }
        let steps = drawn - self.verified;
        if steps > MAX_REVEAL_STEPS {
            return Err(DrawError::RevealTooFar);
        }
        // c[drawn], c[drawn-1], …, c[verified+1]; one more hash must give the value held
        let mut chain = Vec::with_capacity(steps as usize);
        let mut v = *reveal;
        for _ in 0..steps {
            chain.push(v);
            v = sha(&v);
        }
        if v != self.last {
            return Err(DrawError::RevealNotOnChain);
        }
        let mut out = Vec::with_capacity(steps as usize);
        for (draw, c) in (self.verified + 1..=drawn).zip(chain.iter().rev()) {
            // every draw up to `issued` is open: values are given in order and removed only here
            let Some((piece, value)) = self.open.get(&draw) else { return Err(DrawError::RevealAhead) };
            let won = outcome(&self.session, self.win_msat, draw, c, value, piece)?;
            let win = won.then(|| Win { session: self.session.clone(), draw, piece: *piece, win_msat: self.win_msat });
            out.push(Outcome { draw, piece: *piece, win });
        }
        for o in &out {
            self.open.remove(&o.draw);
        }
        self.last = *reveal;
        self.verified = drawn;
        Ok(out)
    }
}

/// The message `payload.auth` MACs for a request of a lottery session.
pub fn auth_message(session: &str, seq: u64, req: &str) -> String {
    ["lottery/auth", session, &seq.to_string(), req].join("|")
}

/// `payload.auth`, hex: binds one request to the session, a fresh `seq` and the request digest,
/// which covers the body and so the values a `draw` carries.
pub fn request_auth(key: &[u8; 32], session: &str, seq: u64, req: &str) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(auth_message(session, seq, req).as_bytes());
    hex::encode(m.finalize().into_bytes())
}

/// The fields a lottery receipt signs, in order. `drawn` is the last draw taken, `servedMsat` the
/// price of every piece served, `wonMsat` what the wins so far pay and `paidMsat` what the
/// seller's node shows paid of them.
pub const RECEIPT_FIELDS: [&str; 11] = ["scheme", "session", "seq", "drawn", "servedMsat", "wonMsat", "paidMsat", "charged", "req", "status", "bodyHash"];

/// What `receiptKey` signs: each of [`RECEIPT_FIELDS`] formatted as the channel wire formats its
/// own, length-prefixed, under [`RECEIPT_TAG`].
pub fn receipt_message(r: &Value) -> [u8; 32] {
    let mut h = tagged(RECEIPT_TAG);
    for k in RECEIPT_FIELDS {
        put_field(&mut h, py_str(r.get(k)).as_bytes());
    }
    h.finalize().into()
}

/// What a seller's terms say about the lottery: the `extra` of its `accepts` entry.
#[derive(Debug, Clone, PartialEq)]
pub struct Terms {
    /// `lightning:<32 hex>`.
    pub network: String,
    /// The seller's Lightning node id, 33 bytes hex: the payee of every win's invoice.
    pub pay_to: String,
    /// What one win pays, and the smallest size a buyer may ask for instead.
    pub win_msat: u64,
    pub min_win_msat: u64,
    /// The final CLTV delta of every win's invoice.
    pub win_blocks: u32,
    /// How many pieces the seller serves beyond the last one it holds a value or a void for.
    pub window: u32,
    /// How long, how many pieces and how many wins the seller serves on while a win is unpaid.
    pub grace_seconds: u32,
    pub grace_pieces: u32,
    pub max_unpaid_wins: u32,
    pub chain_draws: u32,
    /// The bytes of an answer that make one piece.
    pub piece_bytes: u64,
    /// The key that signs receipts, 33 bytes hex.
    pub receipt_key: String,
    /// Path of the session endpoints.
    pub session: String,
}

impl Terms {
    /// The `accepts` entry for a request priced at `amount_msat`, with the route's price rule and
    /// its `release` ([`RELEASE_AFTER_VERIFY`] or [`RELEASE_AFTER_ANSWER`]).
    pub fn accepts(&self, amount_msat: u64, release: &str, price: &Value) -> Value {
        let mut extra = Map::new();
        extra.insert("version".into(), VERSION.into());
        extra.insert("features".into(), Value::Array(vec![FEATURE_BLAKE2B.into()]));
        extra.insert("winMsat".into(), self.win_msat.to_string().into());
        extra.insert("minWinMsat".into(), self.min_win_msat.to_string().into());
        extra.insert("winBlocks".into(), self.win_blocks.into());
        extra.insert("pay".into(), PAY_ON_WIN.into());
        extra.insert("release".into(), release.into());
        extra.insert("window".into(), self.window.into());
        extra.insert("graceSeconds".into(), self.grace_seconds.into());
        extra.insert("gracePieces".into(), self.grace_pieces.into());
        extra.insert("maxUnpaidWins".into(), self.max_unpaid_wins.into());
        extra.insert("chainDraws".into(), self.chain_draws.into());
        extra.insert("pieceBytes".into(), self.piece_bytes.to_string().into());
        extra.insert("receiptKey".into(), self.receipt_key.clone().into());
        extra.insert("session".into(), self.session.clone().into());
        extra.insert("price".into(), price.clone());
        let mut m = Map::new();
        m.insert("scheme".into(), SCHEME.into());
        m.insert("network".into(), self.network.clone().into());
        m.insert("asset".into(), ASSET.into());
        m.insert("amount".into(), amount_msat.to_string().into());
        m.insert("payTo".into(), self.pay_to.clone().into());
        m.insert("extra".into(), Value::Object(extra));
        Value::Object(m)
    }
}

/// The price of the bytes `[from, to)` of an answer whose first `n` bytes cost `cum(n)`: the
/// difference, so that the pieces of a body add up to the price of the body exactly. `None` where
/// the price rule gives none.
pub fn bytes_amount(cum: impl Fn(u64) -> Option<u64>, from: u64, to: u64) -> Option<u64> {
    cum(to)?.checked_sub(cum(from)?)
}

/// What a session may pay before its buyer stops asking for more: the expected price `expect_msat`,
/// `z_tenths / 10` standard deviations of the wins a session of that price draws, and one win.
/// With 31 (3.1 deviations) an honest session stays below it about 999 times in 1,000. The
/// number of wins is close to Poisson with mean `expect / win`, so the deviation of what is paid
/// is `sqrt(expect × win)`.
pub fn luck_cap_msat(expect_msat: u64, win_msat: u64, z_tenths: u64) -> u64 {
    let spread = (u128::from(expect_msat) * u128::from(win_msat)).isqrt();
    let luck = spread.saturating_mul(u128::from(z_tenths)) / 10;
    u64::try_from(u128::from(expect_msat).saturating_add(luck).saturating_add(u128::from(win_msat))).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// SplitMix64: the tests' only random source, seeded, so every run is the same run.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn bytes(&mut self) -> [u8; 32] {
            let mut out = [0u8; 32];
            for c in out.chunks_mut(8) {
                c.copy_from_slice(&self.next().to_be_bytes());
            }
            out
        }
    }

    fn piece(seq: u64, k: u64, amount_msat: u64) -> Piece {
        Piece { id: PieceId { seq, kind: Kind::Bytes, k }, req: [seq as u8; 32], amount_msat }
    }

    const WIN: u64 = 64_000;

    fn pair(rng: &mut Rng, len: u32) -> (Seller, Buyer) {
        let chain = Chain::new(rng.bytes(), len).unwrap();
        let seller = Seller::new("s1", WIN, chain).unwrap();
        let buyer = Buyer::new("s1", WIN, seller.anchor(), len).unwrap();
        (seller, buyer)
    }

    #[test]
    fn the_vectors_file_is_what_this_module_computes() {
        let v: Value = serde_json::from_str(include_str!("../../../vectors/lottery_vectors.json")).unwrap();
        let h32 = |x: &Value| crate::ticket::hex32(x.as_str().unwrap()).unwrap();
        let n = |x: &Value| x.as_str().unwrap().parse::<u64>().unwrap();
        for c in v["chains"].as_array().unwrap() {
            let mut chain = Chain::new(h32(&c["seed"]), c["len"].as_u64().unwrap() as u32).unwrap();
            assert_eq!(hex::encode(chain.anchor()), c["anchor"].as_str().unwrap());
            for (i, want) in c["values"].as_object().unwrap() {
                assert_eq!(hex::encode(chain.value(i.parse().unwrap()).unwrap()), want.as_str().unwrap(), "c[{i}]");
            }
        }
        for t in v["thresholds"].as_array().unwrap() {
            assert_eq!(Odds::new(n(&t["amountMsat"]), n(&t["winMsat"])).unwrap().threshold().to_string(), t["threshold"].as_str().unwrap());
        }
        let draws = v["draws"].as_array().unwrap();
        assert!(draws.iter().any(|d| d["win"] == true) && draws.iter().any(|d| d["win"] == false));
        for d in draws {
            let p = Piece { id: PieceId { seq: d["seq"].as_u64().unwrap(), kind: Kind::parse(d["kind"].as_str().unwrap()).unwrap(), k: d["k"].as_u64().unwrap() },
                            req: h32(&d["req"]), amount_msat: n(&d["amountMsat"]) };
            let win = n(&d["winMsat"]);
            assert_eq!(hex::encode(p.digest(win)), d["piece"].as_str().unwrap());
            let dg = draw_digest(d["session"].as_str().unwrap(), d["draw"].as_u64().unwrap(), &h32(&d["chainValue"]), &h32(&d["value"]), &p.digest(win));
            assert_eq!(hex::encode(dg), d["d"].as_str().unwrap());
            assert_eq!(wins(&dg, Odds::new(p.amount_msat, win).unwrap()), d["win"].as_bool().unwrap());
        }
        let a = &v["auth"];
        assert_eq!(request_auth(&h32(&a["key"]), a["session"].as_str().unwrap(), a["seq"].as_u64().unwrap(), a["req"].as_str().unwrap()), a["auth"].as_str().unwrap());
        assert_eq!(hex::encode(receipt_message(&v["receipt"]["fields"])), v["receipt"]["message"].as_str().unwrap());
    }

    #[test]
    fn a_chain_is_its_seed_hashed_down_whatever_block_is_read() {
        let mut rng = Rng(1);
        for len in [1u32, 2, 1023, 1024, 1025, 3000, 4096] {
            let seed = rng.bytes();
            let mut chain = Chain::new(seed, len).unwrap();
            assert_eq!(chain.anchor(), hash_down(&seed, u64::from(len)), "{len}");
            assert_eq!((chain.value(0), chain.value(len + 1)), (None, None));
            // out of order on purpose: the block cache must not matter
            for i in [len, 1, len.div_ceil(2), 1.max(len.saturating_sub(1)), 1024.min(len), 1025.min(len), 1] {
                assert_eq!(chain.value(i), Some(hash_down(&seed, u64::from(len - i))), "c[{i}] of {len}");
            }
        }
        assert_eq!(Chain::new([0; 32], 0).unwrap_err(), DrawError::ChainLength);
        assert_eq!(Chain::new([0; 32], MAX_CHAIN_DRAWS + 1).unwrap_err(), DrawError::ChainLength);
        assert_eq!(format!("{:?}", Chain::new([7; 32], 5).unwrap()), "Chain(5 draws)", "a chain does not print its seed");
    }

    #[test]
    fn odds_are_an_exact_ratio_and_the_floor_drops_less_than_one_part_in_2_64() {
        assert_eq!(Odds::new(0, 64).unwrap_err(), DrawError::NothingToDraw);
        assert_eq!(Odds::new(64, 64).unwrap_err(), DrawError::AmountNotBelowWin);
        assert_eq!(Odds::new(65, 64).unwrap_err(), DrawError::AmountNotBelowWin);
        assert_eq!(Odds::new(1, 2).unwrap().threshold(), 1 << 63);
        assert_eq!(Odds::new(1, 4).unwrap().threshold(), 1 << 62);
        assert_eq!(Odds::new(u64::MAX - 1, u64::MAX).unwrap().threshold(), u64::MAX - 1);
        let mut rng = Rng(2);
        for _ in 0..20_000 {
            let win = 2 + rng.next() % (1 << (1 + rng.next() % 62));
            let amount = 1 + rng.next() % (win - 1);
            let t = u128::from(Odds::new(amount, win).unwrap().threshold());
            // t/2^64 ≤ amount/win < (t+1)/2^64
            assert!(t * u128::from(win) <= u128::from(amount) << 64 && (t + 1) * u128::from(win) > u128::from(amount) << 64, "{amount}/{win}");
        }
        let o = Odds::new(250, 1000).unwrap();
        assert!(o.at_most(1, 4) && !o.at_most(1, 5) && o.at_most(1, 2));
        assert!(Odds::new(u64::MAX - 1, u64::MAX).unwrap().at_most(u64::MAX, u64::MAX), "the comparison does not wrap");
    }

    #[test]
    fn a_draw_binds_every_field_of_itself_and_of_its_piece() {
        let p = piece(3, 1, 100);
        let (c, b) = ([1u8; 32], [2u8; 32]);
        let base = draw_digest("ab", 5, &c, &b, &p.digest(WIN));
        let others = [
            draw_digest("ac", 5, &c, &b, &p.digest(WIN)),
            draw_digest("ab", 6, &c, &b, &p.digest(WIN)),
            draw_digest("ab", 5, &[3; 32], &b, &p.digest(WIN)),
            draw_digest("ab", 5, &c, &[3; 32], &p.digest(WIN)),
            draw_digest("ab", 5, &c, &b, &p.digest(WIN + 1)),
            draw_digest("ab", 5, &c, &b, &piece(4, 1, 100).digest(WIN)),
            draw_digest("ab", 5, &c, &b, &piece(3, 2, 100).digest(WIN)),
            draw_digest("ab", 5, &c, &b, &piece(3, 1, 101).digest(WIN)),
            draw_digest("ab", 5, &c, &b, &Piece { req: [9; 32], ..p }.digest(WIN)),
            draw_digest("ab", 5, &c, &b, &Piece { id: PieceId { kind: Kind::Second, ..p.id }, ..p }.digest(WIN)),
            // a session name does not run into the draw's number
            draw_digest("a", 0x6200_0000_0000_0005, &c, &b, &p.digest(WIN)),
        ];
        for (i, o) in others.iter().enumerate() {
            assert_ne!(base, *o, "{i}");
        }
        for k in [Kind::Request, Kind::Bytes, Kind::Second] {
            assert_eq!(Kind::parse(k.name()), Some(k));
        }
        assert_eq!(Kind::parse("Bytes"), None);
    }

    /// The honest exchange: each piece is served, then valued, then revealed for, `batch` at a time.
    fn play(seller: &mut Seller, buyer: &mut Buyer, rng: &mut Rng, pieces: u64, amount: u64, batch: u64) -> u64 {
        let mut won = 0;
        let mut k = 0;
        while k < pieces {
            let n = batch.min(pieces - k);
            for j in k..k + n {
                let p = piece(j / 100, j, amount);
                seller.serve(p).unwrap();
                let value = rng.bytes();
                let draw = buyer.issue(p, value, batch).unwrap();
                let t = seller.take(draw, p.id, amount, &value).unwrap();
                assert!(!t.repeated);
            }
            let (drawn, reveal) = seller.reveal().unwrap();
            let out = buyer.absorb(drawn, &reveal).unwrap();
            assert_eq!(out.len() as u64, n);
            won += out.iter().filter(|o| o.win.is_some()).count() as u64;
            k += n;
        }
        assert_eq!((seller.drawn(), buyer.verified(), seller.pending_count()), (pieces, pieces, 0));
        won
    }

    #[test]
    fn over_a_million_draws_at_three_odds_the_win_rate_is_within_the_binomial_bound() {
        // 1 in 640 (a torrent piece at 0.1 sat on a 64-sat win), 1 in 32 and 3 in 8
        const N: u64 = 1_000_000;
        let mut rng = Rng(131);
        for amount in [100u64, 2_000, 24_000] {
            let (mut seller, mut buyer) = pair(&mut rng, MAX_CHAIN_DRAWS);
            let won = play(&mut seller, &mut buyer, &mut rng, N, amount, 8);
            let p = amount as f64 / WIN as f64;
            let (mean, sd) = (N as f64 * p, (N as f64 * p * (1.0 - p)).sqrt());
            // five deviations: an honest draw is outside about once in 1,700,000 runs
            assert!((won as f64 - mean).abs() <= 5.0 * sd, "{amount}/{WIN}: {won} wins, {mean:.0} expected, sd {sd:.1}");
            // and both sides agree on every one of them: what was won is what the chain says
            assert_eq!(seller.left(), u64::from(MAX_CHAIN_DRAWS) - N);
        }
    }

    #[test]
    fn both_sides_work_out_the_same_wins_and_the_seller_may_skip_reveals() {
        let mut rng = Rng(3);
        let (mut seller, mut buyer) = pair(&mut rng, 4096);
        let mut sellers = vec![];
        let mut buyers = vec![];
        // the seller reveals only after every 7th value: the draws in between are worked out from that one reveal
        for j in 0..700u64 {
            let p = piece(1, j, 16_000);
            seller.serve(p).unwrap();
            let value = rng.bytes();
            let draw = buyer.issue(p, value, 7).unwrap();
            if seller.take(draw, p.id, p.amount_msat, &value).unwrap().won {
                sellers.push(draw);
            }
            if draw % 7 == 0 {
                let (drawn, reveal) = seller.reveal().unwrap();
                buyers.extend(buyer.absorb(drawn, &reveal).unwrap().into_iter().filter_map(|o| o.win).map(|w| w.draw()));
            }
        }
        assert!(sellers.len() > 100, "a quarter of 700 draws win");
        assert_eq!(sellers, buyers);
    }

    #[test]
    fn a_seller_that_cheats_is_caught_by_the_check_that_names_it() {
        let mut rng = Rng(4);
        let (mut seller, mut buyer) = pair(&mut rng, 8192);
        let mut seed_chain = vec![];
        for j in 0..6u64 {
            let p = piece(1, j, 8_000);
            seller.serve(p).unwrap();
            let value = rng.bytes();
            let draw = buyer.issue(p, value, 16).unwrap();
            seller.take(draw, p.id, p.amount_msat, &value).unwrap();
            seed_chain.push(seller.reveal().unwrap().1);
        }
        let c = |i: usize| seed_chain[i - 1];
        // a value that is not on the chain, and the right value under another index
        assert_eq!(buyer.absorb(3, &[9; 32]).unwrap_err(), DrawError::RevealNotOnChain);
        assert_eq!(buyer.absorb(3, &c(4)).unwrap_err(), DrawError::RevealNotOnChain);
        assert_eq!(buyer.absorb(4, &c(3)).unwrap_err(), DrawError::RevealNotOnChain);
        assert_eq!(buyer.verified(), 0, "a refused reveal changes nothing");
        // out of order: draw 4 is revealed, then 2
        assert_eq!(buyer.absorb(4, &c(4)).unwrap().len(), 4);
        assert_eq!(buyer.absorb(2, &c(2)).unwrap_err(), DrawError::RevealBehind);
        assert_eq!(buyer.absorb(0, &seller.anchor()).unwrap_err(), DrawError::RevealBehind);
        // the same reveal again is the answer to a repeated message; another value under its index is not
        assert_eq!(buyer.absorb(4, &c(4)).unwrap(), vec![]);
        assert_eq!(buyer.absorb(4, &c(5)).unwrap_err(), DrawError::RevealNotOnChain);
        // a reveal for a draw the buyer gave no value for: a win claimed for a piece that was never served
        let ahead = { let mut ch = Chain::new(rng.bytes(), 8).unwrap(); ch.value(7).unwrap() };
        assert_eq!(buyer.absorb(7, &ahead).unwrap_err(), DrawError::RevealAhead);
        // reused: a chain value revealed once is not the value of a later draw
        assert_eq!(buyer.absorb(6, &c(4)).unwrap_err(), DrawError::RevealNotOnChain);
        // withheld: the seller takes values and reveals for none of them; the buyer gives 16 and no more
        for j in 6..20u64 {
            let p = piece(2, j, 8_000);
            buyer.issue(p, rng.bytes(), 16).unwrap();
        }
        assert_eq!(buyer.issue(piece(2, 20, 8_000), rng.bytes(), 16).unwrap_err(), DrawError::RevealWithheld);
        // far: a reveal that would cost more than 4,096 hashes is refused before any is done
        let (_, mut far) = pair(&mut rng, MAX_CHAIN_DRAWS);
        for j in 0..=MAX_REVEAL_STEPS {
            far.issue(piece(1, j, 8_000), rng.bytes(), u64::MAX).unwrap();
        }
        assert_eq!(far.absorb(MAX_REVEAL_STEPS + 1, &[0; 32]).unwrap_err(), DrawError::RevealTooFar);
        assert_eq!(far.absorb(MAX_REVEAL_STEPS, &[0; 32]).unwrap_err(), DrawError::RevealNotOnChain);
    }

    #[test]
    fn a_seller_cannot_turn_a_losing_draw_into_a_win() {
        // whatever the seller sends as a reveal, the buyer makes a Win only for a draw that wins on the committed chain
        let mut rng = Rng(5);
        let (mut seller, mut buyer) = pair(&mut rng, 4096);
        let mut honest = 0;
        for j in 0..2000u64 {
            let p = piece(1, j, 640);
            seller.serve(p).unwrap();
            let value = rng.bytes();
            let draw = buyer.issue(p, value, 4).unwrap();
            let t = seller.take(draw, p.id, p.amount_msat, &value).unwrap();
            // the seller tries 8 other values first, each of which it would like to be c[draw]
            for _ in 0..8 {
                assert_eq!(buyer.absorb(draw, &rng.bytes()).unwrap_err(), DrawError::RevealNotOnChain);
            }
            let (drawn, reveal) = seller.reveal().unwrap();
            let out = buyer.absorb(drawn, &reveal).unwrap();
            assert_eq!(out[0].win.is_some(), t.won);
            honest += u64::from(t.won);
        }
        // 1 in 100: about 20 wins, and none beyond what the chain gave
        assert!((5..=45).contains(&honest), "{honest}");
    }

    #[test]
    fn a_buyer_that_cheats_is_caught_by_the_check_that_names_it() {
        let mut rng = Rng(6);
        let (mut seller, _) = pair(&mut rng, 4096);
        let (p1, p2, p3) = (piece(1, 0, 8_000), piece(1, 1, 8_000), piece(1, 2, 9_000));
        for p in [p1, p2, p3] {
            seller.serve(p).unwrap();
        }
        assert_eq!(seller.serve(p1).unwrap_err(), DrawError::PieceRepeated);
        let (v1, v2) = (rng.bytes(), rng.bytes());
        // out of order: the first value must be for draw 1
        assert_eq!(seller.take(2, p1.id, 8_000, &v1).unwrap_err(), DrawError::DrawOutOfOrder);
        assert_eq!(seller.take(0, p1.id, 8_000, &v1).unwrap_err(), DrawError::DrawUsed);
        assert!(seller.reveal().is_none(), "nothing is revealed before a value is held");
        let first = seller.take(1, p1.id, 8_000, &v1).unwrap();
        let (_, c1) = seller.reveal().unwrap();
        // the buyer has seen c[1] and now picks another value for draw 1: refused, and the result stands
        assert_eq!(seller.take(1, p1.id, 8_000, &v2).unwrap_err(), DrawError::ValueConflict);
        assert_eq!(seller.take(1, p2.id, 8_000, &v1).unwrap_err(), DrawError::ValueConflict);
        // the same message again gets the same answer and no second draw
        let again = seller.take(1, p1.id, 8_000, &v1).unwrap();
        assert!(again.repeated && again.won == first.won && seller.drawn() == 1 && seller.reveal().unwrap().1 == c1);
        // a value used before in this session
        assert_eq!(seller.take(2, p2.id, 8_000, &v1).unwrap_err(), DrawError::ValueReused);
        // a piece that was not served, a piece that has been drawn for, and a cheaper price for a piece
        assert_eq!(seller.take(2, piece(1, 9, 8_000).id, 8_000, &v2).unwrap_err(), DrawError::PieceUnknown);
        assert_eq!(seller.take(2, p1.id, 8_000, &v2).unwrap_err(), DrawError::PieceUnknown);
        assert_eq!(seller.take(2, p3.id, 8_000, &v2).unwrap_err(), DrawError::AmountMismatch);
        assert_eq!(seller.drawn(), 1, "a refused value uses no draw");
        // a void closes a piece: no value is taken for it afterwards
        assert!(seller.void(p2.id) && !seller.void(p2.id));
        assert_eq!(seller.take(2, p2.id, 8_000, &v2).unwrap_err(), DrawError::PieceUnknown);
        assert!(seller.take(2, p3.id, 9_000, &v2).is_ok());
        // the buyer's own side refuses to give a second value for a piece, or a value twice
        let (_, mut buyer) = pair(&mut rng, 16);
        buyer.issue(p1, v1, 4).unwrap();
        assert_eq!(buyer.issue(p1, v2, 4).unwrap_err(), DrawError::PieceRepeated);
        assert_eq!(buyer.issue(p2, v1, 4).unwrap_err(), DrawError::ValueReused);
        assert!(buyer.void(p3.id) && !buyer.void(p3.id) && !buyer.void(p1.id));
        assert_eq!(buyer.issue(p3, v2, 4).unwrap_err(), DrawError::PieceRepeated, "a voided piece gets no value");
    }

    #[test]
    fn a_buyer_cannot_steer_a_draw_by_its_choice_of_value_or_of_piece() {
        // a buyer that knows everything a real one knows (the anchor and every earlier reveal) and picks
        // the "best" of 16 candidate values by any rule of its own wins as often as one that picks blindly
        let mut rng = Rng(7);
        let (mut seller, mut buyer) = pair(&mut rng, 16_384);
        let mut won = 0u64;
        let mut last = seller.anchor();
        const N: u64 = 12_000;
        for j in 0..N {
            let p = piece(1, j, 16_000);
            seller.serve(p).unwrap();
            // its rule: the candidate whose draw would lose if the chain value were the last one it saw
            let value = (0..16).map(|_| rng.bytes()).find(|v| !wins(&draw_digest("s1", j + 1, &last, v, &p.digest(WIN)), Odds::new(16_000, WIN).unwrap()))
                .unwrap_or_else(|| rng.bytes());
            let draw = buyer.issue(p, value, 1).unwrap();
            won += u64::from(seller.take(draw, p.id, p.amount_msat, &value).unwrap().won);
            let (drawn, reveal) = seller.reveal().unwrap();
            buyer.absorb(drawn, &reveal).unwrap();
            last = reveal;
        }
        let (mean, sd) = (N as f64 * 0.25, (N as f64 * 0.25 * 0.75).sqrt());
        assert!((won as f64 - mean).abs() <= 5.0 * sd, "{won} wins of {N}, {mean:.0} expected");
    }

    #[test]
    fn a_seller_cannot_steer_a_draw_by_its_choice_of_seed() {
        // a seller that tries 64 seeds and keeps the chain that wins most against the values it guesses
        // (it cannot know them) wins against the buyer's real values as often as any other chain
        let mut rng = Rng(8);
        const N: u64 = 400;
        let guess: Vec<[u8; 32]> = (0..N).map(|_| rng.bytes()).collect();
        let score = |chain: &mut Chain, values: &[[u8; 32]]| -> u64 {
            (0..N).filter(|j| {
                let p = piece(1, *j, 16_000);
                wins(&draw_digest("s1", j + 1, &chain.value((j + 1) as u32).unwrap(), &values[*j as usize], &p.digest(WIN)), Odds::new(16_000, WIN).unwrap())
            }).count() as u64
        };
        let mut total = 0;
        const ROUNDS: u64 = 40;
        for _ in 0..ROUNDS {
            let best = (0..64).map(|_| rng.bytes()).max_by_key(|s| score(&mut Chain::new(*s, N as u32).unwrap(), &guess)).unwrap();
            let real: Vec<[u8; 32]> = (0..N).map(|_| rng.bytes()).collect();
            total += score(&mut Chain::new(best, N as u32).unwrap(), &real);
        }
        let n = (N * ROUNDS) as f64;
        let (mean, sd) = (n * 0.25, (n * 0.25 * 0.75).sqrt());
        assert!((total as f64 - mean).abs() <= 5.0 * sd, "{total} wins of {n}, {mean:.0} expected");
    }

    #[test]
    fn a_chain_ends_and_a_piece_is_priced_below_one_win() {
        let mut rng = Rng(9);
        let (mut seller, mut buyer) = pair(&mut rng, 3);
        assert_eq!(seller.serve(piece(1, 0, WIN)).unwrap_err(), DrawError::AmountNotBelowWin);
        assert_eq!(seller.serve(piece(1, 0, 0)).unwrap_err(), DrawError::NothingToDraw);
        assert_eq!(buyer.issue(piece(1, 0, WIN), rng.bytes(), 8).unwrap_err(), DrawError::AmountNotBelowWin);
        for j in 0..3 {
            let p = piece(1, j, 100);
            seller.serve(p).unwrap();
            let v = rng.bytes();
            let d = buyer.issue(p, v, 8).unwrap();
            seller.take(d, p.id, 100, &v).unwrap();
        }
        // the last value of the chain is its seed: it is revealed like any other
        let (drawn, reveal) = seller.reveal().unwrap();
        assert_eq!(buyer.absorb(drawn, &reveal).unwrap().len(), 3);
        assert_eq!(seller.serve(piece(1, 3, 100)).unwrap_err(), DrawError::ChainSpent);
        assert_eq!(buyer.issue(piece(1, 3, 100), rng.bytes(), 8).unwrap_err(), DrawError::ChainSpent);
        assert_eq!(Seller::new("", WIN, Chain::new([1; 32], 2).unwrap()).unwrap_err(), DrawError::SessionName);
        assert_eq!(Buyer::new(&"x".repeat(65), WIN, [0; 32], 2).unwrap_err(), DrawError::SessionName);
        assert_eq!(Buyer::new("x", WIN, [0; 32], 0).unwrap_err(), DrawError::ChainLength);
    }

    #[test]
    fn a_seller_forgets_served_pieces_only_behind_the_requests_still_open() {
        let mut rng = Rng(10);
        let (mut seller, _) = pair(&mut rng, 64);
        seller.serve(piece(1, 0, 100)).unwrap();
        seller.serve(piece(2, 0, 100)).unwrap();
        seller.take(1, piece(2, 0, 100).id, 100, &rng.bytes()).unwrap();
        seller.forget_before(3);
        // request 1 still has a piece open, so nothing at or after it is forgotten
        assert_eq!(seller.serve(piece(2, 0, 100)).unwrap_err(), DrawError::PieceRepeated);
        assert!(seller.void(piece(1, 0, 100).id));
        seller.forget_before(3);
        assert_eq!(seller.served.len(), 0);
    }

    #[test]
    fn the_pieces_of_a_body_cost_what_the_body_costs() {
        // 7 msat for every started 1,000 bytes: pieces of 2,500 bytes over a body of 9,001
        let cum = |n: u64| Some(n.div_ceil(1000) * 7);
        let total = 9_001u64;
        let mut sum = 0;
        let mut from = 0;
        while from < total {
            let to = (from + 2_500).min(total);
            sum += bytes_amount(cum, from, to).unwrap();
            from = to;
        }
        assert_eq!(sum, cum(total).unwrap());
        assert_eq!(bytes_amount(|_| None::<u64>, 0, 1), None);
    }

    #[test]
    fn the_luck_cap_is_the_price_three_deviations_and_one_win() {
        // the design note's download: 1,638 sat on 64-sat wins is 25.6 expected wins; its simulated budget
        // to finish 999 times in 1,000 was 2,795 sat with fees of 1.6%
        let cap = luck_cap_msat(1_638_000, 64_000, 31);
        assert!((2_650_000..=2_750_000).contains(&cap), "{cap}");
        assert_eq!(luck_cap_msat(0, 64_000, 31), 64_000);
        assert_eq!(luck_cap_msat(u64::MAX, u64::MAX, 31), u64::MAX, "it saturates");
        // against a simulation: sessions of 100 expected wins stay under the cap all but a few times in 1,000
        let mut rng = Rng(11);
        let cap = luck_cap_msat(100 * WIN, WIN, 31);
        let over = (0..2000).filter(|_| (0..6400).filter(|_| rng.next().is_multiple_of(64)).count() as u64 * WIN > cap).count();
        assert!(over <= 8, "{over} of 2,000 sessions went over the cap");
    }

    #[test]
    fn auth_and_the_receipt_bind_their_fields_and_are_not_a_tickets() {
        let key = [7u8; 32];
        assert_eq!(auth_message("s", 3, "d"), "lottery/auth|s|3|d");
        let base = request_auth(&key, "s", 3, "d");
        for other in [request_auth(&[8u8; 32], "s", 3, "d"), request_auth(&key, "t", 3, "d"), request_auth(&key, "s", 4, "d"), request_auth(&key, "s", 3, "e"),
                      crate::ticket::request_auth(&key, "s", 3, "", "", "d")] {
            assert_ne!(base, other);
        }
        let r = json!({"scheme": "lottery", "session": "ab", "seq": 2, "drawn": 9, "servedMsat": "900", "wonMsat": "64000", "paidMsat": "0", "charged": "100",
                       "req": "00", "status": 200, "bodyHash": "ff"});
        let m = receipt_message(&r);
        for k in RECEIPT_FIELDS {
            let mut other = r.clone();
            other[k] = "x".into();
            assert_ne!(m, receipt_message(&other), "{k}");
        }
        assert_ne!(m, crate::ticket::receipt_message(&r));
    }

    #[test]
    fn the_accepts_entry_is_the_one_the_draft_shows() {
        let t = Terms { network: "lightning:0000000000000050c1e5f69672f45929".into(), pay_to: "02".repeat(33), win_msat: 64_000, min_win_msat: 16_000, win_blocks: 40,
                        window: 8, grace_seconds: 10, grace_pieces: 64, max_unpaid_wins: 2, chain_draws: DEFAULT_CHAIN_DRAWS, piece_bytes: 262_144,
                        receipt_key: "03".repeat(33), session: SESSION_PATH.into() };
        let a = t.accepts(100, RELEASE_AFTER_ANSWER, &json!({"requestMsat": "100"}));
        assert_eq!((a["scheme"].as_str(), a["amount"].as_str(), a["asset"].as_str()), (Some("lottery"), Some("100"), Some("XBT:msat")));
        let e = &a["extra"];
        assert_eq!((e["version"].as_str(), e["winMsat"].as_str(), e["minWinMsat"].as_str(), e["pay"].as_str()), (Some("lottery/0"), Some("64000"), Some("16000"), Some("on-win")));
        assert_eq!((e["window"].as_u64(), e["graceSeconds"].as_u64(), e["gracePieces"].as_u64(), e["maxUnpaidWins"].as_u64()), (Some(8), Some(10), Some(64), Some(2)));
        assert_eq!((e["chainDraws"].as_u64(), e["pieceBytes"].as_str(), e["session"].as_str()), (Some(65_536), Some("262144"), Some("/x402/lottery")));
        assert_eq!(e["features"], json!([512]));
    }
}
