//! Three testers and a collector on one machine, over real iroh links with no relay.

use std::sync::Arc;
use std::time::Duration;

use xbt_compute_check::plan::{plan, Group, Model};
use xbt_compute_check::probe::{self, Collector, Limits, Peer, ALPN_CHECK};
use xbt_compute_check::{hardware, Gpu};
use xbt_iroh_link::{Hints, Link, Options, Relays};

fn link() -> Arc<Link> {
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).unwrap();
    Link::start_alpn(secret, Options { relays: Relays::None, serving: true, private: false, lookup: None }, ALPN_CHECK).unwrap()
}

#[test]
fn testers_measure_each_other_and_the_file_answers_the_plan() {
    let dir = std::env::temp_dir().join(format!("compute-check-group-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("records.jsonl");

    let collector = link();
    probe::serve(&collector, Some(Collector::open(&file).unwrap()));
    let collector_id = collector.endpoint_id();
    let collector_addrs = collector.hints(Duration::from_secs(2)).direct;
    assert!(!collector_addrs.is_empty());

    let limits = Limits { pings: 4, ping_every: Duration::from_millis(20), test_bytes: 1 << 20, test_time: Duration::from_secs(20), connect_time: Duration::from_secs(10) };
    let handles: Vec<_> = (0..3).map(|_| {
        let (collector_id, collector_addrs, limits) = (collector_id.clone(), collector_addrs.clone(), limits.clone());
        std::thread::spawn(move || {
            let t = link();
            probe::serve(&t, None);
            let id = t.endpoint_id();
            let hints = t.hints(Duration::from_secs(2));
            t.learn(&collector_id, Hints { relays: Vec::new(), direct: collector_addrs }).unwrap();
            let mut report = hardware::read(&id, "test", &std::env::temp_dir()).unwrap();
            // the same card on each, so that the plan's arithmetic does not depend on this machine
            report.gpus = vec![Gpu { vendor: "nvidia".into(), name: "test".into(), vram_gib: 24.0 }];
            report.ram_available_gib = 4.0;
            let me = Peer { id, relays: Vec::new(), direct: hints.direct };
            let rt = t.runtime();
            let out = rt.block_on(probe::run_tester(t.clone(), &collector_id, report, me, limits, Duration::from_secs(4), Duration::from_secs(1))).unwrap();
            // keeps answering while the others finish
            std::thread::sleep(Duration::from_secs(4));
            out
        })
    }).collect();
    let outs: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    assert!(outs.iter().all(|o| o.failed.is_empty()), "{outs:?}");
    let total: usize = outs.iter().map(|o| o.links.len()).sum();
    assert!(total >= 3, "every pair is measured by at least one side: {outs:?}");
    for l in outs.iter().flat_map(|o| &o.links) {
        assert!(l.direct && l.rtt_ms < 200.0 && l.up_mbit_s > 0.0 && l.down_mbit_s > 0.0, "{l:?}");
    }

    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(!text.contains("127.0.0.1"), "the collector writes no addresses");
    let (group, bad) = Group::from_jsonl(&text);
    assert_eq!((group.reports.len(), bad), (3, 0));
    assert_eq!(group.links.len(), 3, "each of the three pairs");

    // 61.5 GiB x 1.05 = 64.6; three cards at 21.6 usable hold 64.8
    let model = Model { name: "m", file_gib: 61.5, row_kb: 16.0, source: "", assumed: false, cards_only: true };
    let a = &plan(&group, &[model])[0];
    let c = a.chains.first().unwrap_or_else(|| panic!("{a:?}"));
    assert_eq!(c.machines, 3);
    assert_eq!(c.on_cards_pct, 100.0);
}
