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
//!
//! **The buyer's requirements are strict** ([`Requirements`]): every choice, automatic switching and
//! spreading included, is made only among exits that meet all of them. If none does, nothing is
//! relaxed: the flow is refused (the kill switch) and [`Router::unmet`] says, in plain words, which
//! requirement has no exit.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// What the buyer knows about one exit, from its listing and the buyer's own measurements.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ExitInfo {
    pub id: String,
    /// Who runs the exit (their Nostr key): several exits may share an operator.
    pub operator: String,
    /// The region (country code) the exit announces.
    pub region: String,
    /// Whether the buyer's own check confirmed it ([`crate::region`]).
    pub region_verified: bool,
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
    /// Whether the exit says it keeps logs of buyers' destinations.
    pub logs: bool,
    /// Ports the exit refuses.
    pub blocked_ports: Vec<u16>,
    /// Whether the exit accepts buyers through a first hop (two hops).
    pub two_hop: bool,
}

/// A relay a buyer can go through before an exit, so the exit never learns the buyer's address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirstHop {
    pub id: String,
    pub operator: String,
}

/// What a buyer requires of an exit. Every field must hold; nothing is relaxed.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Requirements {
    pub kind: Want,
    /// The country the exit's egress must be verified to be in.
    pub region: Option<String>,
    /// Through a first hop run by a different operator from the exit.
    pub two_hop: bool,
    pub max_price_msat_per_gb: Option<u64>,
    /// Measured, not claimed.
    pub min_mbit_s: Option<f64>,
    pub must_not_log: bool,
    pub must_allow_ports: Vec<u16>,
    /// Exit ids or operators never used.
    pub exclude: Vec<String>,
    /// Exit ids or operators chosen first among those that qualify.
    pub prefer: Vec<String>,
    /// Flows may be spread over several exits.
    pub spread: bool,
    /// All traffic stays on one exit while it qualifies.
    pub sticky: bool,
}

/// The requirement no exit meets, in plain words for the app to show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unmet(pub String);

impl Requirements {
    /// The exits that meet every requirement, or the first requirement that leaves none.
    pub fn eligible<'a>(&self, exits: &'a [ExitInfo], hops: &[FirstHop]) -> Result<Vec<&'a ExitInfo>, Unmet> {
        let mut c: Vec<&ExitInfo> = exits.iter().collect();
        let step = |c: &mut Vec<&'a ExitInfo>, keep: &dyn Fn(&ExitInfo) -> bool, why: String| -> Result<(), Unmet> {
            c.retain(|e| keep(e));
            if c.is_empty() { Err(Unmet(why)) } else { Ok(()) }
        };
        if c.is_empty() {
            return Err(Unmet("No exit is listed yet.".into()));
        }
        let kind = match &self.kind {
            Want::Private => "private".to_string(),
            Want::Filtered(cats) if cats.is_empty() => "filtered".to_string(),
            Want::Filtered(cats) => format!("filtered, blocking {}", cats.join(" and ")),
            Want::Any => "any".to_string(),
        };
        step(&mut c, &|e| self.kind.allows(e), format!("No {kind} exit is available."))?;
        step(&mut c, &|e| !self.exclude.iter().any(|x| x == &e.id || x == &e.operator), "Every exit that fits is one you excluded.".into())?;
        if let Some(r) = &self.region {
            step(&mut c, &|e| e.region.eq_ignore_ascii_case(r) && e.region_verified, format!("No exit is verified to be in {r}."))?;
        }
        if let Some(p) = self.max_price_msat_per_gb {
            step(&mut c, &|e| e.price_msat_per_gb <= p, format!("No exit costs {} per GB or less.", sats(p / 1000)))?;
        }
        if let Some(m) = self.min_mbit_s {
            step(&mut c, &|e| e.mbit_s.is_some_and(|x| x >= m), format!("No exit has been measured at {m} Mbit/s or faster."))?;
        }
        if self.must_not_log {
            step(&mut c, &|e| !e.logs, "No exit that keeps no logs is available.".into())?;
        }
        if !self.must_allow_ports.is_empty() {
            let ports: Vec<String> = self.must_allow_ports.iter().map(|p| p.to_string()).collect();
            step(&mut c, &|e| self.must_allow_ports.iter().all(|p| !e.blocked_ports.contains(p)), format!("No exit allows port {}.", ports.join(", ")))?;
        }
        if self.two_hop {
            step(&mut c, &|e| e.two_hop && first_hop(e, hops).is_some(), "No exit can be reached through a first hop run by someone else.".into())?;
        }
        // last, so the message says which exits are down: the ones that meet every rule
        let n = c.len();
        let down = if n == 1 {
            "The exit that meets these rules isn't answering right now. Stream keeps trying it.".to_string()
        } else {
            format!("The {n} exits that meet these rules aren't answering right now. Stream keeps trying them.")
        };
        step(&mut c, &|e| e.healthy, down)?;
        Ok(c)
    }
}

fn sats(n: u64) -> String {
    if n == 1 { "1 sat".into() } else { format!("{n} sats") }
}

/// A first hop for `exit` run by a different operator, so no one operator sees both ends.
pub fn first_hop<'a>(exit: &ExitInfo, hops: &'a [FirstHop]) -> Option<&'a FirstHop> {
    hops.iter().find(|h| h.operator != exit.operator && h.id != exit.id)
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
    pub fn allows(&self, e: &ExitInfo) -> bool {
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
    hops: Vec<FirstHop>,
    mode: Mode,
    req: Requirements,
    sticky: Option<String>,
    dests: HashMap<IpAddr, (String, Instant)>,
    load: HashMap<String, u64>,
}

impl Router {
    /// A router choosing in `mode` among exits in `region` (if given), with the region taken as
    /// verified elsewhere. [`Router::with_requirements`] is the full form.
    pub fn new(mode: Mode, region: Option<String>) -> Router {
        let mut r = Router::with_requirements(Requirements { region, ..Requirements::default() });
        r.mode = mode;
        r
    }

    /// A router held to the buyer's requirements: sticky or spread as they say, best otherwise.
    pub fn with_requirements(req: Requirements) -> Router {
        let mode = if req.sticky { Mode::Sticky } else if req.spread { Mode::Spread } else { Mode::Best };
        Router { exits: Vec::new(), hops: Vec::new(), mode, req, sticky: None, dests: HashMap::new(), load: HashMap::new() }
    }

    /// Which kind of exit to use (private by default).
    pub fn want(mut self, want: Want) -> Router {
        self.req.kind = want;
        self
    }

    /// The kind of exit in use: a private exit's buyer resolves names itself.
    pub fn wants(&self) -> &Want {
        &self.req.kind
    }

    pub fn requirements(&self) -> &Requirements {
        &self.req
    }

    /// New requirements: new flows follow them at once. Destinations whose exit no longer qualifies
    /// are given again; returns the exits that no longer qualify, whose live flows the caller ends.
    pub fn set_requirements(&mut self, req: Requirements) -> Vec<String> {
        self.mode = if req.sticky { Mode::Sticky } else if req.spread { Mode::Spread } else { Mode::Best };
        self.req = req;
        let ok: Vec<String> = self.req.eligible(&self.exits, &self.hops).map(|v| v.iter().map(|e| e.id.clone()).collect()).unwrap_or_default();
        let gone: Vec<String> = self.exits.iter().filter(|e| !ok.contains(&e.id)).map(|e| e.id.clone()).collect();
        self.dests.retain(|_, (id, _)| ok.contains(id));
        if self.sticky.as_ref().is_some_and(|s| !ok.contains(s)) {
            self.sticky = None;
        }
        gone
    }

    /// The relays the buyer can go through before an exit.
    pub fn set_first_hops(&mut self, hops: Vec<FirstHop>) {
        self.hops = hops;
    }

    /// The first hop to use for this exit, when the requirements ask for two hops.
    pub fn first_hop_for(&self, exit: &str) -> Option<FirstHop> {
        let e = self.exits.iter().find(|e| e.id == exit)?;
        self.req.two_hop.then(|| first_hop(e, &self.hops).cloned()).flatten()
    }

    /// Why no exit qualifies, if none does: for the app to say plainly.
    pub fn unmet(&self) -> Option<Unmet> {
        self.req.eligible(&self.exits, &self.hops).err()
    }

    /// The exits the router knows.
    pub fn exits(&self) -> &[ExitInfo] {
        &self.exits
    }

    /// Whether this exit meets the requirements now.
    pub fn qualifies(&self, exit: &str) -> bool {
        self.is_usable(exit)
    }

    /// Adds an exit, or replaces what is known about it (a new measurement, a health change).
    pub fn upsert(&mut self, e: ExitInfo) {
        match self.exits.iter_mut().find(|x| x.id == e.id) {
            Some(x) => *x = e,
            None => self.exits.push(e),
        }
    }

    /// Marks an exit answering again after it failed: new flows may go to it.
    pub fn recover(&mut self, id: &str) {
        if let Some(x) = self.exits.iter_mut().find(|x| x.id == id) {
            x.healthy = true;
        }
    }

    /// The exits marked failed.
    pub fn failed(&self) -> Vec<String> {
        self.exits.iter().filter(|e| !e.healthy).map(|e| e.id.clone()).collect()
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
        self.req.eligible(&self.exits, &self.hops).unwrap_or_default().into_iter()
    }

    /// A preferred exit counts for more than any measurement.
    fn preference(&self, e: &ExitInfo) -> f64 {
        if self.req.prefer.iter().any(|p| p == &e.id || p == &e.operator) { 1000.0 } else { 0.0 }
    }

    fn best(&self) -> Option<&ExitInfo> {
        self.usable().max_by(|a, b| (score(a) + self.preference(a)).total_cmp(&(score(b) + self.preference(b))))
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
                        (score(a) + self.preference(a) - (1.0 + la).ln()).total_cmp(&(score(b) + self.preference(b) - (1.0 + lb).ln()))
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
        ExitInfo { id: id.into(), operator: format!("op-{id}"), region: region.into(), region_verified: true, price_msat_per_gb: 2000, rtt_ms: Some(rtt), mbit_s: Some(mbit), healthy: true, ..ExitInfo::default() }
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
        assert_eq!(r.unmet().map(|u| u.0).as_deref(), Some("The exit that meets these rules isn't answering right now. Stream keeps trying it."));
        r.recover("de");
        assert_eq!(r.pick(ip("9.9.9.9"), t).as_deref(), Some("de"), "a recovered exit is used again");
        assert!(r.failed().is_empty());
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

    fn req() -> Requirements {
        Requirements { region: Some("DE".into()), ..Requirements::default() }
    }

    #[test]
    fn a_policy_that_matches_uses_only_exits_meeting_all_of_it() {
        let t = Instant::now();
        let mut r = Router::with_requirements(Requirements { max_price_msat_per_gb: Some(3000), min_mbit_s: Some(50.0), must_not_log: true, must_allow_ports: vec![22], ..req() });
        r.upsert(exit("cheap-fast", "DE", 100.0, 30.0));
        r.upsert(ExitInfo { price_msat_per_gb: 9000, ..exit("dear", "DE", 900.0, 5.0) });
        r.upsert(ExitInfo { logs: true, ..exit("logs", "DE", 900.0, 5.0) });
        r.upsert(ExitInfo { blocked_ports: vec![22], ..exit("no-ssh", "DE", 900.0, 5.0) });
        r.upsert(exit("slow", "DE", 10.0, 5.0));
        r.upsert(ExitInfo { mbit_s: None, ..exit("unmeasured", "DE", 0.0, 5.0) });
        r.upsert(exit("us", "US", 900.0, 5.0));
        for i in 0..10u8 {
            assert_eq!(r.pick(IpAddr::from([1, 1, 1, i]), t).as_deref(), Some("cheap-fast"));
        }
        assert_eq!(r.unmet(), None);
    }

    #[test]
    fn a_policy_that_matches_nothing_blocks_and_says_which_requirement() {
        let t = Instant::now();
        let mut r = Router::with_requirements(Requirements { max_price_msat_per_gb: Some(1000), ..req() });
        r.upsert(exit("de", "DE", 100.0, 30.0)); // 2000 msat a GB
        assert_eq!(r.pick(ip("1.1.1.1"), t), None, "nothing is relaxed: the flow is refused");
        assert_eq!(r.unmet(), Some(Unmet("No exit costs 1 sat per GB or less.".into())));
        let mut r = Router::with_requirements(req());
        r.upsert(exit("fr", "FR", 100.0, 30.0));
        assert_eq!(r.unmet(), Some(Unmet("No exit is verified to be in DE.".into())));
    }

    #[test]
    fn an_unverified_region_does_not_count() {
        let t = Instant::now();
        let mut r = Router::with_requirements(req());
        r.upsert(ExitInfo { region_verified: false, ..exit("claims-de", "DE", 900.0, 5.0) });
        assert_eq!(r.pick(ip("1.1.1.1"), t), None);
        assert_eq!(r.unmet(), Some(Unmet("No exit is verified to be in DE.".into())));
    }

    #[test]
    fn two_hops_need_a_first_hop_run_by_someone_other_than_the_exit() {
        let t = Instant::now();
        let mut r = Router::with_requirements(Requirements { two_hop: true, ..req() });
        r.upsert(ExitInfo { two_hop: true, operator: "alice".into(), ..exit("de", "DE", 100.0, 30.0) });
        // the only relay is alice's own: that is one operator seeing both ends
        r.set_first_hops(vec![FirstHop { id: "relay-a".into(), operator: "alice".into() }]);
        assert_eq!(r.pick(ip("1.1.1.1"), t), None);
        assert!(r.unmet().unwrap().0.contains("first hop"));
        r.set_first_hops(vec![FirstHop { id: "relay-a".into(), operator: "alice".into() }, FirstHop { id: "relay-b".into(), operator: "bob".into() }]);
        assert_eq!(r.pick(ip("1.1.1.1"), t).as_deref(), Some("de"));
        assert_eq!(r.first_hop_for("de").map(|h| h.operator), Some("bob".into()));
    }

    #[test]
    fn a_policy_change_applies_to_new_flows_and_names_exits_that_no_longer_qualify() {
        let t = Instant::now();
        let mut r = Router::with_requirements(Requirements::default());
        r.upsert(exit("de", "DE", 100.0, 30.0));
        r.upsert(exit("fr", "FR", 200.0, 30.0));
        assert_eq!(r.pick(ip("1.1.1.1"), t).as_deref(), Some("fr"));
        let gone = r.set_requirements(req());
        assert_eq!(gone, vec!["fr".to_string()], "the caller ends live flows on fr");
        assert!(!r.qualifies("fr"));
        assert_eq!(r.pick(ip("1.1.1.1"), t).as_deref(), Some("de"), "even a destination that had fr moves");
    }

    #[test]
    fn excluded_and_preferred_exits_and_operators() {
        let t = Instant::now();
        let mut r = Router::with_requirements(Requirements { exclude: vec!["op-fast".into()], prefer: vec!["slow".into()], ..req() });
        r.upsert(exit("fast", "DE", 900.0, 5.0));
        r.upsert(exit("mid", "DE", 300.0, 10.0));
        r.upsert(exit("slow", "DE", 20.0, 50.0));
        assert_eq!(r.pick(ip("1.1.1.1"), t).as_deref(), Some("slow"), "preferred, among those that qualify");
        r.set_requirements(Requirements { exclude: vec!["op-fast".into()], ..req() });
        assert_eq!(r.pick(ip("8.8.8.8"), t).as_deref(), Some("mid"), "the excluded operator's exit is never used");
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
