//! Which models a group of testers could run together, from what they reported and measured.
//!
//! The answer is an upper bound before compute: it says the memory is there and the links allow
//! it, not that the model will reach this speed. Only a run measures that. The shape it plans is a
//! chain of machines, each holding a range of layers, with one pass crossing every machine in turn.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::{LinkResult, Record, Report};

/// The lines of the distributed plan: at least this many tokens a second for one user, and the
/// first token of a 1,000-token prompt within this many seconds.
pub const LINE_TOK_S: f64 = 5.0;
pub const LINE_FIRST_TOKEN_S: f64 = 5.0;
/// Tokens one pass yields: without drafting that goes well, and with (measured 2.03 to 3.5).
pub const TOKENS_PER_PASS: (f64, f64) = (2.0, 3.5);
/// Share of a card's memory a chain may plan on, and of a machine's available memory.
const VRAM_USABLE: f64 = 0.9;
const RAM_USABLE: f64 = 0.8;
/// Memory a machine keeps for itself.
const RAM_KEPT_GIB: f64 = 4.0;
/// A file needs a little more than its size once loaded.
const LOAD_FACTOR: f64 = 1.05;
/// The longest chain planned. Past this the delay alone rules a model out.
const MAX_CHAIN: usize = 64;
/// The round trips tried, ms: the same metro, a region, a continent.
pub const RTT_TIERS_MS: [f64; 3] = [10.0, 40.0, 100.0];
/// A home for a whole model on its own disk needs at least this much (the smallest GPU box InferSSD
/// reports running a 748B model on).
const NVME_MIN_VRAM_GIB: f64 = 16.0;
const NVME_MIN_RAM_GIB: f64 = 8.0;

/// A model of the alpha. Sizes come from the source named; a width no source states is assumed, and
/// `assumed` says so.
#[derive(Clone, Debug, Serialize)]
pub struct Model {
    pub name: &'static str,
    /// Size of the file, GiB.
    pub file_gib: f64,
    /// Bytes of one row between machines, kB: 4 bytes per width.
    pub row_kb: f64,
    pub source: &'static str,
    pub assumed: bool,
    /// Whether the whole model must sit on cards to meet the lines. Measured: 30B meets them on a
    /// CPU (10.3 tok/s). 235B with most layers on CPUs reached 5.37 tok/s and a 26 s first token.
    pub cards_only: bool,
}

/// The models the alpha climbs through, smallest first.
pub const CATALOG: [Model; 4] = [
    Model { name: "Qwen3-30B-A3B Q4_K_M", file_gib: 18.6, row_kb: 8.0, source: "18.6 GB in use on one card, measured", assumed: false, cards_only: false },
    Model { name: "Qwen3-235B-A22B IQ2_S", file_gib: 61.5, row_kb: 16.0, source: "file and row size, measured", assumed: false, cards_only: true },
    Model { name: "DeepSeek-V4.1-Flash 748B", file_gib: 473.0, row_kb: 28.7, source: "file as reported for InferSSD; row width assumed as DeepSeek-V3's 7168", assumed: true, cards_only: true },
    Model { name: "Kimi-K3 2.8T Q2_K", file_gib: 940.0, row_kb: 28.7, source: "file as reported for SGLang (1,009.51 GB); row width assumed", assumed: true, cards_only: true },
];

/// The chain that best fits one model at one round-trip tier.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Chain {
    pub rtt_tier_ms: f64,
    pub machines: usize,
    /// Share of the model that would sit on cards rather than in main memory, percent.
    pub on_cards_pct: f64,
    /// Time for one pass to go round, from the measured links, ms.
    pub pass_ms: f64,
    /// Tokens a second the delay allows, at the two tokens-per-pass figures, before compute.
    pub ceiling_tok_s: (f64, f64),
    /// Time for a 1,000-token prompt to cross the slowest link, before compute. `None`: a chain of
    /// one, or no throughput was measured.
    pub prompt_s: Option<f64>,
    pub meets_lines: bool,
}

/// The answer for one model.
#[derive(Clone, Debug, Serialize)]
pub struct Answer {
    pub model: Model,
    /// The fastest chain the group can form, tier by tier, on the memory this model needs. Empty: none.
    pub chains: Vec<Chain>,
    /// For a model that needs cards: a chain that also uses main memory, at the widest tier. It
    /// could run, but slowly: it does not count toward the lines.
    pub slow_chain: Option<Chain>,
    /// Machines that could hold the whole model in fast memory alone.
    pub whole_in_memory: usize,
    /// Machines that could try it from their own NVMe, with experts on disk.
    pub nvme_candidates: usize,
    /// What is short: empty when a chain meets the lines.
    pub missing: String,
}

/// Everything a collector's file says, read safely: a tester's bad number is dropped, not trusted.
#[derive(Clone, Debug, Default)]
pub struct Group {
    pub reports: BTreeMap<String, Report>,
    /// The best measurement between each pair, keyed lowest id first.
    pub links: BTreeMap<(String, String), LinkResult>,
}

impl Group {
    /// Reads the lines of a collector's file; a line it cannot read is counted and left out.
    pub fn from_jsonl(text: &str) -> (Group, usize) {
        let (mut g, mut bad) = (Group::default(), 0);
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            match serde_json::from_str::<Record>(line) {
                Ok(r) => g.add(r),
                Err(_) => bad += 1,
            }
        }
        (g, bad)
    }

    /// Adds one record. Implausible numbers are left out, so one wrong report cannot make a model
    /// look ready.
    pub fn add(&mut self, r: Record) {
        match r {
            Record::Report(mut r) => {
                let plausible = |v: f64, most: f64| v.is_finite() && (0.0..=most).contains(&v);
                r.gpus.retain(|g| plausible(g.vram_gib, 4096.0));
                if plausible(r.ram_available_gib, 65536.0) && plausible(r.disk_free_gib, 1e7) {
                    self.reports.insert(r.id.clone(), r);
                }
            }
            Record::Link(l) => {
                let plausible = |v: f64| v.is_finite() && v >= 0.0;
                if l.from == l.to || !plausible(l.rtt_ms) || !plausible(l.up_mbit_s) || !plausible(l.down_mbit_s) {
                    return;
                }
                let key = if l.from < l.to { (l.from.clone(), l.to.clone()) } else { (l.to.clone(), l.from.clone()) };
                // a direct path, if either side saw one; then the shorter round trip
                let better = self.links.get(&key).is_none_or(|old| (l.direct && !old.direct) || (l.direct == old.direct && l.rtt_ms < old.rtt_ms));
                if better {
                    self.links.insert(key, l);
                }
            }
        }
    }

    fn link(&self, a: &str, b: &str) -> Option<&LinkResult> {
        let key = if a < b { (a.to_string(), b.to_string()) } else { (b.to_string(), a.to_string()) };
        self.links.get(&key)
    }
}

fn card_gib(r: &Report) -> f64 {
    r.gpus.iter().fold(0.0, |sum, g| sum + g.vram_gib * VRAM_USABLE)
}

fn ram_gib(r: &Report) -> f64 {
    (r.ram_available_gib - RAM_KEPT_GIB).max(0.0) * RAM_USABLE
}

/// One machine's share of a model: cards first, then main memory.
fn fast_gib(r: &Report) -> f64 {
    card_gib(r) + ram_gib(r)
}

/// The answer for every model in `models`.
pub fn plan(group: &Group, models: &[Model]) -> Vec<Answer> {
    models.iter().map(|m| answer(group, m)).collect()
}

fn answer(group: &Group, model: &Model) -> Answer {
    let need = model.file_gib * LOAD_FACTOR;
    let usable = |r: &Report| if model.cards_only { card_gib(r) } else { fast_gib(r) };
    let whole_in_memory = group.reports.values().filter(|r| usable(r) >= need).count();
    let nvme_candidates = group.reports.values()
        .filter(|r| fast_gib(r) < need && r.disk_free_gib >= need && card_gib(r) / VRAM_USABLE >= NVME_MIN_VRAM_GIB && r.ram_total_gib >= NVME_MIN_RAM_GIB)
        .count();
    let chains: Vec<Chain> = RTT_TIERS_MS.iter().filter_map(|&tier| best_chain(group, model, need, tier, &usable)).collect();
    let slow_chain = if model.cards_only && chains.is_empty() { RTT_TIERS_MS.last().and_then(|&tier| best_chain(group, model, need, tier, &fast_gib)) } else { None };
    let missing = if chains.iter().any(|c| c.meets_lines) { String::new() } else { missing(group, need, &chains, &usable, model.cards_only) };
    Answer { model: model.clone(), chains, slow_chain, whole_in_memory, nvme_candidates, missing }
}

/// The best chain at a tier. From each seed it walks to the biggest machine with a direct link
/// within the tier, so that there are few hops. Only neighbours in the chain need a direct link, and
/// the last machine must reach the first, which keeps the buyer out of the loop for each token.
fn best_chain(group: &Group, model: &Model, need: f64, tier: f64, usable: &dyn Fn(&Report) -> f64) -> Option<Chain> {
    let near = |a: &str, b: &str| group.link(a, b).is_some_and(|l| l.direct && l.rtt_ms <= tier);
    let mut by_size: Vec<&Report> = group.reports.values().filter(|r| usable(r) > 0.0).collect();
    by_size.sort_by(|a, b| usable(b).total_cmp(&usable(a)).then(a.id.cmp(&b.id)));
    let mut best: Option<Chain> = None;
    for seed in &by_size {
        let mut members: Vec<&Report> = vec![seed];
        let mut have = usable(seed);
        while have < need && members.len() < MAX_CHAIN {
            let last = members[members.len() - 1];
            let next = by_size.iter().find(|r| {
                !members.iter().any(|m| m.id == r.id) && near(&last.id, &r.id) && (have + usable(r) < need || near(&r.id, &seed.id))
            });
            let Some(next) = next else { break };
            have += usable(next);
            members.push(next);
        }
        if have < need {
            continue;
        }
        let chain = chain_of(group, model, need, tier, &members);
        let is_better = best.as_ref().is_none_or(|b| (chain.ceiling_tok_s.0, chain.on_cards_pct) > (b.ceiling_tok_s.0, b.on_cards_pct));
        if is_better {
            best = Some(chain);
        }
    }
    best
}

fn chain_of(group: &Group, model: &Model, need: f64, tier: f64, members: &[&Report]) -> Chain {
    let cards = members.iter().fold(0.0, |sum, r| sum + card_gib(r));
    let on_cards_pct = (cards / need).min(1.0) * 100.0;
    let n = members.len();
    let mut pass_ms = 0.0;
    let mut slowest: Option<f64> = None;
    if n > 1 {
        for i in 0..n {
            let (a, b) = (&members[i].id, &members[(i + 1) % n].id);
            if let Some(l) = group.link(a, b) {
                pass_ms += l.rtt_ms / 2.0;
                let speed = l.up_mbit_s.min(l.down_mbit_s);
                if speed > 0.0 {
                    slowest = Some(slowest.map_or(speed, |s: f64| s.min(speed)));
                }
            }
        }
    }
    let ceiling = |tokens: f64| if pass_ms > 0.0 { tokens / (pass_ms / 1000.0) } else { f64::INFINITY };
    let ceiling_tok_s = (ceiling(TOKENS_PER_PASS.0), ceiling(TOKENS_PER_PASS.1));
    let prompt_s = slowest.filter(|_| n > 1).map(|mbit| 1000.0 * model.row_kb * 8.0 / 1000.0 / mbit);
    let meets_lines = ceiling_tok_s.0 >= LINE_TOK_S && prompt_s.is_none_or(|p| p <= LINE_FIRST_TOKEN_S);
    Chain { rtt_tier_ms: tier, machines: n, on_cards_pct, pass_ms, ceiling_tok_s, prompt_s, meets_lines }
}

fn missing(group: &Group, need: f64, chains: &[Chain], usable: &dyn Fn(&Report) -> f64, cards_only: bool) -> String {
    let what = if cards_only { "on cards" } else { "of cards and memory" };
    if group.reports.is_empty() {
        return format!("no testers yet; {need:.0} GiB {what} are needed");
    }
    if let Some(c) = chains.first() {
        return format!("a chain of {} forms, but its links miss the lines: ceiling {:.1} tok/s, prompt crossing {}",
            c.machines, c.ceiling_tok_s.0, c.prompt_s.map_or("unmeasured".to_string(), |p| format!("{p:.1} s")));
    }
    let tier = RTT_TIERS_MS[RTT_TIERS_MS.len() - 1];
    format!("the largest group within {tier:.0} ms holds {:.0} of {need:.0} GiB {what}", largest_group(group, tier, usable))
}

/// The most memory any one machine and its direct neighbours within `tier` hold.
fn largest_group(group: &Group, tier: f64, usable: &dyn Fn(&Report) -> f64) -> f64 {
    group.reports.values().map(|seed| {
        let near: BTreeSet<&String> = group.reports.keys()
            .filter(|id| **id == seed.id || group.link(&seed.id, id).is_some_and(|l| l.direct && l.rtt_ms <= tier))
            .collect();
        near.iter().filter_map(|id| group.reports.get(*id)).fold(0.0, |sum, r| sum + usable(r))
    }).fold(0.0, f64::max)
}

/// The answers, for a person.
pub fn render(group: &Group, answers: &[Answer]) -> String {
    let (cards, ram): (f64, f64) = group.reports.values().fold((0.0, 0.0), |(c, r), m| (c + card_gib(m), r + ram_gib(m)));
    let direct = group.links.values().filter(|l| l.direct).count();
    let mut out = format!("{} machines, {:.0} GiB on cards, {:.0} GiB of main memory usable, {} of {} measured pairs direct.\n\
                           Ceilings are before compute: they say the network allows it, not that a model reaches it.\n\n",
        group.reports.len(), cards, ram, direct, group.links.len());
    for a in answers {
        let verdict = if a.chains.iter().any(|c| c.meets_lines) { "worth a run" } else if a.whole_in_memory > 0 { "one machine could hold it" } else { "not yet" };
        out += &format!("{} ({:.0} GiB): {verdict}\n", a.model.name, a.model.file_gib);
        if a.model.assumed {
            out += &format!("  note: {}\n", a.model.source);
        }
        let line = |c: &Chain| {
            if c.machines == 1 {
                return format!("one machine holds it, {:.0}% on cards, no network in the chain\n", c.on_cards_pct);
            }
            let prompt = c.prompt_s.map_or("not measured".to_string(), |p| format!("{p:.1} s"));
            format!("{} machines, {:.0}% on cards, ceiling {:.1} to {:.1} tok/s, a 1,000-token prompt crosses in {prompt}\n", c.machines, c.on_cards_pct, c.ceiling_tok_s.0, c.ceiling_tok_s.1)
        };
        if a.chains.iter().all(|c| c.machines == 1) {
            if let Some(c) = a.chains.first() {
                out += &format!("  {}", line(c));
            }
        } else {
            for c in &a.chains {
                out += &format!("  within {:.0} ms: {}", c.rtt_tier_ms, line(c));
            }
        }
        if let Some(c) = &a.slow_chain {
            out += &format!("  slowly, with main memory too: {}", line(c));
        }
        out += &format!("  whole in one machine's memory: {}; could try from its own NVMe: {}\n", a.whole_in_memory, a.nvme_candidates);
        if !a.missing.is_empty() {
            out += &format!("  short of: {}\n", a.missing);
        }
        out += "\n";
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Gpu, SCHEMA};

    fn box_with(id: &str, vram: f64, ram: f64) -> Record {
        let gpus = if vram > 0.0 { vec![Gpu { vendor: "nvidia".into(), name: "card".into(), vram_gib: vram }] } else { vec![] };
        Record::Report(Report { schema: SCHEMA, id: id.into(), ram_total_gib: ram, ram_available_gib: ram, gpus, disk_free_gib: 100.0, ..Report::default() })
    }

    fn link(a: &str, b: &str, direct: bool, rtt: f64, mbit: f64) -> Record {
        Record::Link(LinkResult { from: a.into(), to: b.into(), direct, rtt_ms: rtt, up_mbit_s: mbit, down_mbit_s: mbit })
    }

    fn group(records: Vec<Record>) -> Group {
        let mut g = Group::default();
        records.into_iter().for_each(|r| g.add(r));
        g
    }

    fn model(file_gib: f64) -> Model {
        Model { name: "m", file_gib, row_kb: 16.0, source: "", assumed: false, cards_only: false }
    }

    fn full_mesh(ids: &[&str], rtt: f64, mbit: f64) -> Vec<Record> {
        let mut out = Vec::new();
        for (i, a) in ids.iter().enumerate() {
            for b in &ids[i + 1..] {
                out.push(link(a, b, true, rtt, mbit));
            }
        }
        out
    }

    #[test]
    fn nobody_means_not_yet_and_says_how_much_is_needed() {
        let a = &plan(&Group::default(), &[model(100.0)])[0];
        assert!(a.chains.is_empty() && a.missing.contains("no testers"), "{a:?}");
    }

    #[test]
    fn four_24gb_cards_in_a_region_hold_a_61_gib_model_and_clear_the_network_lines() {
        let mut r: Vec<Record> = ["a", "b", "c", "d"].iter().map(|id| box_with(id, 24.0, 4.0)).collect();
        r.extend(full_mesh(&["a", "b", "c", "d"], 20.0, 200.0));
        let a = &plan(&group(r), &[model(61.5)])[0];
        let c = a.chains.iter().find(|c| c.rtt_tier_ms == 40.0).unwrap();
        // 61.5 x 1.05 = 64.6 GiB; 21.6 GiB usable per card: three machines hold it
        assert_eq!(c.machines, 3);
        assert_eq!(c.on_cards_pct, 100.0);
        // three links at 10 ms one way
        assert_eq!(c.pass_ms, 30.0);
        assert!((c.ceiling_tok_s.0 - 66.7).abs() < 0.1);
        // 16 MB over 200 Mbit/s
        assert!((c.prompt_s.unwrap() - 0.64).abs() < 0.001);
        assert!(c.meets_lines && a.missing.is_empty());
        // too far apart for the 10 ms tier
        assert!(a.chains.iter().all(|c| c.rtt_tier_ms != 10.0));
    }

    #[test]
    fn a_link_too_slow_for_the_first_token_line_fails_the_chain() {
        let mut r: Vec<Record> = ["a", "b", "c"].iter().map(|id| box_with(id, 24.0, 4.0)).collect();
        r.extend(full_mesh(&["a", "b", "c"], 20.0, 20.0));
        let a = &plan(&group(r), &[model(61.5)])[0];
        let c = &a.chains[0];
        assert!((c.prompt_s.unwrap() - 6.4).abs() < 0.001, "{c:?}");
        assert!(!c.meets_lines && a.missing.contains("miss the lines"), "{a:?}");
    }

    #[test]
    fn relayed_pairs_do_not_count_as_a_chain() {
        let mut r: Vec<Record> = ["a", "b"].iter().map(|id| box_with(id, 24.0, 4.0)).collect();
        r.push(link("a", "b", false, 5.0, 200.0));
        let a = &plan(&group(r), &[model(30.0)])[0];
        assert!(a.chains.is_empty(), "{a:?}");
        assert!(a.missing.contains("holds 22"), "{}", a.missing);
    }

    #[test]
    fn one_big_machine_is_a_chain_of_one_with_no_network() {
        let g = group(vec![box_with("a", 0.0, 128.0)]);
        let a = &plan(&g, &[model(61.5)])[0];
        assert_eq!(a.whole_in_memory, 1);
        let c = &a.chains[0];
        assert_eq!((c.machines, c.on_cards_pct), (1, 0.0));
        assert!(c.ceiling_tok_s.0.is_infinite() && c.prompt_s.is_none() && c.meets_lines);
    }

    #[test]
    fn a_small_ram_machine_with_a_big_disk_and_card_can_try_nvme() {
        let mut r = box_with("a", 16.0, 8.0);
        if let Record::Report(rep) = &mut r {
            rep.disk_free_gib = 600.0;
        }
        let a = &plan(&group(vec![r]), &[model(473.0)])[0];
        assert_eq!((a.nvme_candidates, a.whole_in_memory), (1, 0));
    }

    #[test]
    fn a_model_that_needs_cards_does_not_count_main_memory_toward_the_lines() {
        let m = Model { cards_only: true, ..model(61.5) };
        let mut r = vec![box_with("a", 0.0, 128.0), box_with("b", 24.0, 8.0), box_with("c", 24.0, 8.0)];
        r.extend(full_mesh(&["a", "b", "c"], 20.0, 200.0));
        let a = &plan(&group(r), &[m])[0];
        assert!(a.chains.is_empty() && a.whole_in_memory == 0, "{a:?}");
        assert!(a.missing.contains("on cards"), "{}", a.missing);
        assert_eq!(a.slow_chain.as_ref().map(|c| c.machines), Some(1));
    }

    #[test]
    fn only_neighbours_in_the_chain_need_a_direct_link_and_the_chain_must_close() {
        // a-b-c-d in a ring; a-c and b-d are relayed
        let mut r: Vec<Record> = ["a", "b", "c", "d"].iter().map(|id| box_with(id, 24.0, 4.0)).collect();
        r.extend([link("a", "b", true, 20.0, 200.0), link("b", "c", true, 20.0, 200.0), link("c", "d", true, 20.0, 200.0), link("d", "a", true, 20.0, 200.0),
                  link("a", "c", false, 20.0, 200.0), link("b", "d", false, 20.0, 200.0)]);
        let a = &plan(&group(r.clone()), &[model(80.0)])[0];
        let c = a.chains.iter().find(|c| c.rtt_tier_ms == 40.0).unwrap_or_else(|| panic!("{a:?}"));
        assert_eq!((c.machines, c.pass_ms), (4, 40.0));
        // without the closing link there is no ring of four
        r.retain(|x| !matches!(x, Record::Link(l) if l.from == "d" && l.to == "a"));
        assert!(plan(&group(r), &[model(80.0)])[0].chains.is_empty());
    }

    #[test]
    fn implausible_numbers_and_bad_lines_cannot_make_a_model_look_ready() {
        let line = serde_json::to_string(&box_with("a", 1e9, 16.0)).unwrap();
        let bad_ram = serde_json::to_string(&box_with("b", 24.0, 1e9)).unwrap();
        let (g, bad) = Group::from_jsonl(&format!("{line}\n{bad_ram}\nnot json\n"));
        assert_eq!(bad, 1);
        assert!(g.reports["a"].gpus.is_empty());
        assert!(!g.reports.contains_key("b"));
    }

    #[test]
    fn a_direct_measurement_beats_a_relayed_one_of_the_same_pair() {
        let g = group(vec![link("a", "b", false, 5.0, 100.0), link("b", "a", true, 30.0, 100.0), link("a", "b", false, 1.0, 100.0)]);
        let l = g.link("a", "b").unwrap();
        assert!(l.direct && l.rtt_ms == 30.0);
    }

    #[test]
    fn the_real_catalog_renders_with_its_assumptions_marked() {
        let g = group(vec![box_with("a", 24.0, 32.0)]);
        let text = render(&g, &plan(&g, &CATALOG));
        assert!(text.contains("1 machines") && text.contains("row width assumed"), "{text}");
    }
}
