//! Which exit a new flow goes to.
//!
//! A buyer may have several exits in the region it chose. The router decides for **new** flows only:
//! a flow stays on its exit until it ends (the public address changes with the exit, so moving a
//! live connection would break it), unless that exit fails.
//!
//! - **Best:** new flows go to the best exit by measured throughput, latency, price and health. When
//!   a better exit appears, new flows move to it; live ones stay.
//! - **Sticky:** all traffic stays on one exit while it is healthy.
//! - **Spread:** flows are spread over the region's exits, by score and load.
//!
//! In every mode a destination keeps the exit it was given while it is in use (destination
//! stickiness), so a site sees one address from the buyer. Each exit meters its own bytes, so
//! spreading costs the same per GB, and no single exit sees all of a buyer's traffic.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// What the buyer knows about one exit.
#[derive(Clone, Debug, PartialEq)]
pub struct ExitInfo {
    pub id: String,
    /// The region (country code) the exit's egress was verified to be in.
    pub region: String,
    pub price_msat_per_gb: u64,
    /// Measured round trip through the exit.
    pub rtt_ms: Option<f64>,
    /// Measured throughput through the exit.
    pub mbit_s: Option<f64>,
    pub healthy: bool,
    /// A filtered exit (its operator's blocklist applies, and it sees site names); else private.
    pub filtered: bool,
    /// What a filtered exit says it blocks ("adult", "gambling", "malware"…).
    pub categories: Vec<String>,
}

/// Which kind of exit the buyer wants.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Want {
    /// Private exits only: what a buyer gets unless they choose otherwise.
    #[default]
    Private,
    /// Filtered exits that block at least these categories (none: any filtered exit).
    Filtered(Vec<String>),
    /// Either kind.
    Any,
}

impl Want {
    fn allows(&self, e: &ExitInfo) -> bool {
        match self {
            Want::Private => !e.filtered,
            Want::Filtered(cats) => e.filtered && cats.iter().all(|c| e.categories.iter().any(|x| x.eq_ignore_ascii_case(c))),
            Want::Any => true,
        }
    }
}

/// How flows are given exits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Best,
    Sticky,
    Spread,
}

/// How long a destination keeps its exit after its last flow started.
pub const DEST_TTL: Duration = Duration::from_secs(600);

/// An exit's score: higher is better. Throughput counts most (a VPN is mostly bulk traffic), then
/// latency, then price; an unmeasured exit gets middling values so it is tried.
pub fn score(e: &ExitInfo) -> f64 {
    let mbit = e.mbit_s.unwrap_or(20.0).max(0.1);
    let rtt = e.rtt_ms.unwrap_or(100.0).max(1.0);
    let price = (e.price_msat_per_gb as f64 / 1000.0).max(1.0);
    mbit.ln() * 3.0 - rtt.ln() - price.ln() * 0.5
}

/// The router's state.
#[derive(Debug)]
pub struct Router {
    exits: Vec<ExitInfo>,
    mode: Mode,
    region: Option<String>,
    want: Want,
    sticky: Option<String>,
    dests: HashMap<IpAddr, (String, Instant)>,
    load: HashMap<String, u64>,
}

impl Router {
    pub fn new(mode: Mode, region: Option<String>) -> Router {
        Router { exits: Vec::new(), mode, region, want: Want::Private, sticky: None, dests: HashMap::new(), load: HashMap::new() }
    }

    /// Which kind of exit to use (private by default).
    pub fn want(mut self, want: Want) -> Router {
        self.want = want;
        self
    }

    /// The kind of exit in use: a private exit's buyer resolves names itself.
    pub fn wants(&self) -> &Want {
        &self.want
    }

    /// Adds an exit, or replaces what is known about it (a new measurement, a health change).
    pub fn upsert(&mut self, e: ExitInfo) {
        match self.exits.iter_mut().find(|x| x.id == e.id) {
            Some(x) => *x = e,
            None => self.exits.push(e),
        }
    }

    /// Marks an exit failed: no new flows go to it, and destinations it had are given again.
    pub fn fail(&mut self, id: &str) {
        if let Some(x) = self.exits.iter_mut().find(|x| x.id == id) {
            x.healthy = false;
        }
        self.dests.retain(|_, (e, _)| e != id);
        if self.sticky.as_deref() == Some(id) {
            self.sticky = None;
        }
    }

    fn usable(&self) -> impl Iterator<Item = &ExitInfo> {
        self.exits.iter().filter(|e| e.healthy && self.want.allows(e) && self.region.as_ref().is_none_or(|r| &e.region == r))
    }

    fn best(&self) -> Option<&ExitInfo> {
        self.usable().max_by(|a, b| score(a).total_cmp(&score(b)))
    }

    fn is_usable(&self, id: &str) -> bool {
        self.usable().any(|e| e.id == id)
    }

    /// The exit for a new flow to `dst`, or `None` if no exit is usable: then the flow is refused,
    /// never sent outside the tunnel.
    pub fn pick(&mut self, dst: IpAddr, now: Instant) -> Option<String> {
        if let Some((id, at)) = self.dests.get(&dst).cloned() {
            if now.duration_since(at) < DEST_TTL && self.is_usable(&id) && (self.mode != Mode::Sticky || self.sticky.as_deref() == Some(&id)) {
                self.dests.insert(dst, (id.clone(), now));
                *self.load.entry(id.clone()).or_default() += 1;
                return Some(id);
            }
        }
        let id = match self.mode {
            Mode::Sticky => {
                if !self.sticky.as_deref().is_some_and(|s| self.is_usable(s)) {
                    self.sticky = self.best().map(|e| e.id.clone());
                }
                self.sticky.clone()?
            }
            Mode::Best => self.best()?.id.clone(),
            Mode::Spread => {
                let load = &self.load;
                self.usable()
                    .max_by(|a, b| {
                        let la = *load.get(&a.id).unwrap_or(&0) as f64;
                        let lb = *load.get(&b.id).unwrap_or(&0) as f64;
                        (score(a) - (1.0 + la).ln()).total_cmp(&(score(b) - (1.0 + lb).ln()))
                    })?
                    .id
                    .clone()
            }
        };
        self.dests.insert(dst, (id.clone(), now));
        *self.load.entry(id.clone()).or_default() += 1;
        Some(id)
    }

    /// A flow on `exit` ended.
    pub fn flow_ended(&mut self, exit: &str) {
        if let Some(n) = self.load.get_mut(exit) {
            *n = n.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exit(id: &str, region: &str, mbit: f64, rtt: f64) -> ExitInfo {
        ExitInfo { id: id.into(), region: region.into(), price_msat_per_gb: 2000, rtt_ms: Some(rtt), mbit_s: Some(mbit), healthy: true, filtered: false, categories: Vec::new() }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn best_mode_moves_new_flows_and_leaves_live_destinations() {
        let mut r = Router::new(Mode::Best, None);
        let t = Instant::now();
        r.upsert(exit("a", "US", 50.0, 40.0));
        assert_eq!(r.pick(ip("1.1.1.1"), t).as_deref(), Some("a"));
        // a better exit appears: a new destination goes to it, the one in use stays where it is
        r.upsert(exit("b", "US", 200.0, 20.0));
        assert_eq!(r.pick(ip("8.8.8.8"), t).as_deref(), Some("b"));
        assert_eq!(r.pick(ip("1.1.1.1"), t).as_deref(), Some("a"));
        // after the destination has been idle past its time, it goes to the best one too
        assert_eq!(r.pick(ip("1.1.1.1"), t + DEST_TTL + Duration::from_secs(1)).as_deref(), Some("b"));
    }

    #[test]
    fn sticky_mode_keeps_everything_on_one_exit_until_it_fails() {
        let mut r = Router::new(Mode::Sticky, None);
        let t = Instant::now();
        r.upsert(exit("a", "US", 50.0, 40.0));
        assert_eq!(r.pick(ip("1.1.1.1"), t).as_deref(), Some("a"));
        r.upsert(exit("b", "US", 500.0, 5.0));
        assert_eq!(r.pick(ip("8.8.8.8"), t).as_deref(), Some("a"), "sticky ignores a better exit");
        r.fail("a");
        assert_eq!(r.pick(ip("8.8.8.8"), t).as_deref(), Some("b"));
        assert_eq!(r.pick(ip("1.1.1.1"), t).as_deref(), Some("b"), "the failed exit's destinations move");
    }

    #[test]
    fn spread_mode_uses_several_exits_and_keeps_each_destination_on_one() {
        let mut r = Router::new(Mode::Spread, None);
        let t = Instant::now();
        for id in ["a", "b", "c"] {
            r.upsert(exit(id, "DE", 100.0, 30.0));
        }
        let mut used = std::collections::HashSet::new();
        let mut first = HashMap::new();
        for i in 0..30u8 {
            let d = IpAddr::from([93, 184, 0, i]);
            let e = r.pick(d, t).unwrap();
            used.insert(e.clone());
            first.insert(d, e);
        }
        assert_eq!(used.len(), 3, "flows spread over every exit");
        for (d, e) in &first {
            assert_eq!(&r.pick(*d, t).unwrap(), e, "a destination keeps its exit");
        }
    }

    #[test]
    fn only_the_chosen_region_and_never_without_an_exit() {
        let mut r = Router::new(Mode::Best, Some("DE".into()));
        let t = Instant::now();
        r.upsert(exit("us", "US", 900.0, 5.0));
        assert_eq!(r.pick(ip("1.1.1.1"), t), None, "no exit in the region: the flow is refused");
        r.upsert(exit("de", "DE", 10.0, 80.0));
        assert_eq!(r.pick(ip("1.1.1.1"), t).as_deref(), Some("de"));
        r.fail("de");
        assert_eq!(r.pick(ip("9.9.9.9"), t), None);
    }

    #[test]
    fn private_exits_by_default_and_filtered_ones_only_when_asked() {
        let t = Instant::now();
        let filtered = ExitInfo { filtered: true, categories: vec!["adult".into(), "malware".into()], ..exit("f", "US", 900.0, 5.0) };
        let mut r = Router::new(Mode::Best, None);
        r.upsert(filtered.clone());
        assert_eq!(r.pick(ip("1.1.1.1"), t), None, "a buyer gets private exits unless they choose otherwise");
        r.upsert(exit("p", "US", 10.0, 90.0));
        assert_eq!(r.pick(ip("1.1.1.1"), t).as_deref(), Some("p"));

        let mut r = Router::new(Mode::Best, None).want(Want::Filtered(vec!["Adult".into()]));
        r.upsert(exit("p", "US", 900.0, 5.0));
        r.upsert(filtered.clone());
        assert_eq!(r.pick(ip("1.1.1.1"), t).as_deref(), Some("f"));
        let mut r = Router::new(Mode::Best, None).want(Want::Filtered(vec!["gambling".into()]));
        r.upsert(filtered);
        assert_eq!(r.pick(ip("1.1.1.1"), t), None, "an exit that does not block what the buyer asked for is not used");
    }

    #[test]
    fn throughput_outweighs_a_small_price_difference() {
        let fast = ExitInfo { price_msat_per_gb: 3000, ..exit("fast", "US", 300.0, 30.0) };
        let slow = ExitInfo { price_msat_per_gb: 2000, ..exit("slow", "US", 20.0, 30.0) };
        assert!(score(&fast) > score(&slow));
        let unhealthy_score_irrelevant = ExitInfo { healthy: false, ..fast.clone() };
        let mut r = Router::new(Mode::Best, None);
        r.upsert(unhealthy_score_irrelevant);
        r.upsert(slow);
        assert_eq!(r.pick(ip("1.1.1.1"), Instant::now()).as_deref(), Some("slow"));
    }
}
