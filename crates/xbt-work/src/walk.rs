//! The audit walk: every block, in height order, through [`WorkProvider::audit_chain`] (review P4).
//! It is the loop `xbt-work-provider` runs, kept here so it can be tested on in-memory data.
//!
//! The rule (AGP-091): **no answer of the Prime's stops the walk.** The provider's own node is
//! the only thing it waits for. A statement fetch that fails (an error status, a body that is no
//! statement, no connection) leaves that block as one with no statement
//! ([`Statement::Unavailable`]: no verdict, and nothing it paid covers credit), the walk goes on to
//! the next block, and the block is asked for again on later passes, less and less often, until it
//! lies [`SETTLE_DEPTH`] below the walk. Before, the walk stopped at such a block and tried it for
//! ever, so a Prime that answered 500 for one height was never audited again.
//!
//! The position is kept in the provider's state ([`WorkProvider::set_audit_position`]), so a
//! provider that was down starts where it stopped, not at a fixed distance below the tip. The
//! blocks still being asked for are kept in memory only: after a restart those deeper than the
//! start of the walk stay blocks with no statement.
use std::collections::BTreeMap;

use crate::chain::ChainBlock;
use crate::error::Result;
use crate::provider::{ServedStatement, Statement, WorkProvider, SETTLE_DEPTH};

/// Where the walk reads from: the provider's node and the Prime's statements.
pub trait AuditSource {
    /// The block at `height` as the provider's own node has it.
    fn block(&self, height: u32) -> Result<ChainBlock>;
    /// The Prime's statement for the block at `height`: None when the Prime answers that it has
    /// none; an error for every other answer that is not a statement.
    fn statement(&self, height: u32) -> Result<Option<ServedStatement>>;
    /// The hash of the block the node has at `height` now, None when it has none there: what an
    /// audit on record is checked against before a statement is held to it
    /// ([`WorkProvider::audit_chain_on`]).
    fn hash_at(&self, height: u32) -> Result<Option<String>> {
        self.block(height).map(|b| Some(b.hash))
    }
}

/// The most passes between two fetches of one statement the Prime keeps failing to serve, as a
/// power of two (64 passes: about two minutes at the binary's 2 s).
const MAX_BACKOFF: u32 = 6;

#[derive(Debug, Clone, Copy)]
struct Wait {
    tries: u32,
    /// The pass at which it is asked for again.
    due: u64,
}

/// The walk's position and the blocks whose statement it still asks for.
#[derive(Debug)]
pub struct Walk {
    next: u32,
    waiting: BTreeMap<u32, Wait>,
    pass: u64,
}

/// What one pass did.
#[derive(Debug, Default)]
pub struct Pass {
    /// (height, passed) of every block that got a verdict.
    pub verdicts: Vec<(u32, bool)>,
    /// (height, why) of every statement fetch that failed in this pass.
    pub unavailable: Vec<(u32, String)>,
    /// The pass stopped here: the node, or the provider's own state, failed. Retried next pass.
    pub stopped: Option<(u32, String)>,
}

enum Step {
    Done(Option<bool>),
    Unavailable(String),
    Stop(String),
}

impl Walk {
    /// A walk that audits `next` first.
    pub fn new(next: u32) -> Self {
        Self { next, waiting: BTreeMap::new(), pass: 0 }
    }

    /// The next height the walk has not passed.
    pub fn next(&self) -> u32 {
        self.next
    }

    /// Heights whose statement is still asked for.
    pub fn waiting(&self) -> Vec<u32> {
        self.waiting.keys().copied().collect()
    }

    /// The chain changed from `height` up (a reorg): walk those heights again.
    pub fn rewind(&mut self, height: u32) {
        self.next = self.next.min(height);
        self.waiting.retain(|h, _| *h < height);
    }

    fn step(wp: &WorkProvider, src: &dyn AuditSource, height: u32) -> Step {
        let block = match src.block(height) {
            Ok(b) => b,
            Err(e) => return Step::Stop(format!("node: {e}")),
        };
        let (served, why) = match src.statement(height) {
            Ok(s) => (s, None),
            Err(e) => (None, Some(e.to_string())),
        };
        let stmt = match (&served, &why) {
            (Some((sw, deferred, _)), _) => Statement::Found(sw, deferred),
            (None, None) => Statement::Missing,
            (None, Some(_)) => Statement::Unavailable,
        };
        match (wp.audit_chain_on(&block, stmt, &|h| src.hash_at(h)), why) {
            (Err(e), _) => Step::Stop(e.to_string()),
            (Ok(_), Some(why)) => Step::Unavailable(why),
            (Ok(o), None) => Step::Done(o.map(|o| o.ok)),
        }
    }

    /// Audit every block up to `to`, and ask again for the statements that are due.
    pub fn pass(&mut self, wp: &WorkProvider, src: &dyn AuditSource, to: u32) -> Pass {
        self.pass += 1;
        let mut out = Pass::default();
        // an audit undone because its block left the chain: over that height again
        if let Some(low) = wp.undone() {
            self.rewind(low);
        }
        // deeper than any reorg the walk expects: it stays a block with no statement
        self.waiting.retain(|h, _| h.saturating_add(SETTLE_DEPTH) > to);
        let due: Vec<u32> = self.waiting.iter().filter(|(_, w)| w.due <= self.pass).map(|(h, _)| *h).collect();
        for h in due {
            match Self::step(wp, src, h) {
                Step::Done(v) => {
                    self.waiting.remove(&h);
                    out.verdicts.extend(v.map(|ok| (h, ok)));
                }
                Step::Unavailable(why) => {
                    if let Some(w) = self.waiting.get_mut(&h) {
                        w.tries = w.tries.saturating_add(1);
                        w.due = self.pass + (1u64 << w.tries.min(MAX_BACKOFF));
                    }
                    out.unavailable.push((h, why));
                }
                // the node: this height keeps its turn, the walk below decides whether to stop
                Step::Stop(_) => {}
            }
        }
        while self.next <= to {
            let h = self.next;
            match Self::step(wp, src, h) {
                Step::Done(v) => out.verdicts.extend(v.map(|ok| (h, ok))),
                Step::Unavailable(why) => {
                    self.waiting.insert(h, Wait { tries: 0, due: self.pass + 1 });
                    out.unavailable.push((h, why));
                }
                Step::Stop(why) => {
                    out.stopped = Some((h, why));
                    break;
                }
            }
            self.next = h.saturating_add(1);
            if h == u32::MAX {
                break;
            }
        }
        if let Err(e) = wp.set_audit_position(self.next) {
            out.stopped.get_or_insert((self.next, e.to_string()));
        }
        out
    }
}
