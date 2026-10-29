//! Bytes an exit carries for one buyer, each way: what payment is reckoned from.
//!
//! The meter counts sizes and nothing else. It has no field for an address or a port, so a seller
//! who keeps no logs keeps nothing about where a buyer went.

use std::sync::atomic::{AtomicU64, Ordering};

/// The counts at one moment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// IP bytes from the buyer to the internet.
    pub up_bytes: u64,
    /// IP bytes from the internet to the buyer.
    pub down_bytes: u64,
    /// Flows or packets refused by the exit's policy or too big for the tunnel.
    pub dropped: u64,
    /// Flows a filtered exit refused for its operator's blocklist. A count only: what was blocked,
    /// and for whom, is never kept.
    pub blocked: u64,
}

impl Counts {
    /// Both directions: what a price per GB applies to.
    pub fn total_bytes(&self) -> u64 {
        self.up_bytes + self.down_bytes
    }
}

/// Counts for one buyer, shared between the tasks that carry its packets.
#[derive(Debug, Default)]
pub struct Meter {
    up: AtomicU64,
    down: AtomicU64,
    dropped: AtomicU64,
    blocked: AtomicU64,
}

impl Meter {
    pub fn up(&self, bytes: usize) {
        self.up.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn down(&self, bytes: usize) {
        self.down.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn drop_one(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn block_one(&self) {
        self.blocked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn counts(&self) -> Counts {
        Counts {
            up_bytes: self.up.load(Ordering::Relaxed),
            down_bytes: self.down.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_each_way_and_in_total() {
        let m = Meter::default();
        m.up(1200);
        m.up(80);
        m.down(1280);
        m.drop_one();
        let c = m.counts();
        assert_eq!(c, Counts { up_bytes: 1280, down_bytes: 1280, dropped: 1, blocked: 0 });
        assert_eq!(c.total_bytes(), 2560);
    }
}
