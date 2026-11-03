//! A made-up group of testers from a stated mix, to see what the plan would say before there are
//! testers. The mix is a guess, and its output is an illustration, never a measurement.

use crate::{Gpu, LinkResult, Record, Report, SCHEMA};

/// Regions testers are spread over, evenly: within one 20 ms round trip, between two 100 ms.
const REGIONS: u64 = 4;
const RTT_WITHIN_MS: f64 = 20.0;
const RTT_ACROSS_MS: f64 = 100.0;
/// Share of pairs that connect directly (a guess: both must not sit behind a strict NAT).
const DIRECT_PCT: u64 = 60;
const MBIT: f64 = 100.0;

/// (percent of testers, card GiB, memory GiB). A guess at who runs a node and would lend a machine.
pub const MIX: [(u64, f64, f64); 5] = [(45, 0.0, 16.0), (20, 8.0, 32.0), (20, 16.0, 32.0), (12, 24.0, 64.0), (3, 32.0, 128.0)];

struct Rng(u64);

impl Rng {
    /// xorshift64*: repeatable from a seed, which is all an illustration needs.
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x9E37_79B9_7F4A_7C15)
    }
}

/// `n` testers and every pair's link between them.
pub fn testers(n: usize, seed: u64) -> Vec<Record> {
    let mut rng = Rng(seed.max(1));
    let mut out = Vec::new();
    let mut region = Vec::with_capacity(n);
    let id = |i: usize| format!("sim{i:05}");
    for i in 0..n {
        let roll = rng.next() % 100;
        let mut acc = 0;
        let &(_, vram, ram) = MIX.iter().find(|(pct, _, _)| { acc += pct; roll < acc }).unwrap_or(&MIX[0]);
        let gpus = if vram > 0.0 { vec![Gpu { vendor: "nvidia".into(), name: "simulated".into(), vram_gib: vram }] } else { Vec::new() };
        region.push(rng.next() % REGIONS);
        out.push(Record::Report(Report { schema: SCHEMA, id: id(i), arch: "simulated".into(), cores: 8, ram_total_gib: ram, ram_available_gib: ram, gpus, disk_free_gib: 500.0, ..Report::default() }));
    }
    for a in 0..n {
        for b in a + 1..n {
            let rtt = if region[a] == region[b] { RTT_WITHIN_MS } else { RTT_ACROSS_MS };
            out.push(Record::Link(LinkResult { from: id(a), to: id(b), direct: rng.next() % 100 < DIRECT_PCT, rtt_ms: rtt, up_mbit_s: MBIT, down_mbit_s: MBIT }));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{plan, Group, CATALOG};

    #[test]
    fn the_same_seed_gives_the_same_group_and_the_mix_adds_up() {
        assert_eq!(testers(20, 7), testers(20, 7));
        assert_ne!(testers(20, 7), testers(20, 8));
        assert_eq!(MIX.iter().map(|m| m.0).sum::<u64>(), 100);
    }

    #[test]
    fn more_testers_never_make_the_largest_model_harder() {
        let ready = |n| {
            let mut g = Group::default();
            testers(n, 3).into_iter().for_each(|r| g.add(r));
            plan(&g, &CATALOG)[2].chains.len()
        };
        assert!(ready(300) >= ready(10));
    }
}
