//! `stream-compute-check`: see `lib.rs`.

use std::collections::{BTreeMap, HashSet};
use std::io::{BufRead, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use xbt_compute_check::plan::{plan, render, Group, CATALOG};
use xbt_compute_check::probe::{self, Collector, Limits, Peer, ALPN_CHECK};
use xbt_compute_check::chain::{self, Card, Counters, Machines, ALPN_CHAIN};
use xbt_compute_check::{hardware, simulate};
use xbt_iroh_link::{Hints, Link, Options, Relays, DEFAULT_RELAY};

const USAGE: &str = "\
stream-compute-check: what this machine has and how well testers reach each other.

  check --collector KEY [--region TEXT] [--minutes 5] [--disk-test-gib 0] [--disk-dir DIR]
        [--relay-only] [--yes]
      Shows what would be sent and asks first. Then reports to the collector, and measures
      other testers for the given minutes. Run it on the machine you would lend, not in a container.
  report [--disk-test-gib 0] [--disk-dir DIR]
      Prints this machine's report. Nothing leaves the machine.
  collect --out FILE
      Runs a collector, and prints the key testers need.
  plan FILE
      Which models the testers in a collector's file could run together.
  simulate --testers N [--seed 1]
      Prints a made-up group of testers, in a collector's format. An illustration only.
  sweep [--seeds 5]
      What the plan says of made-up groups of 10 to 500 testers. An illustration only.
  link --card FILE [--serve IP:PORT] [--peers FILE --ports FILE] [--report FILE] [--key FILE]
      Carries a compute chain over iroh. Serves IP:PORT, this machine's chain port, to the chain's
      other machines, and writes this machine's card. Once the chain's cards are gathered in
      --peers, opens a loopback port for each other machine that serves and writes them to
      --ports. Only the chain's keys are let in. Runs until stopped. Without --key, a new key.

Lab flags: --no-relay, and --collector-addr IP:PORT with check.";

/// The flags of one command: `--name value`, or `--name` alone for the switches.
struct Flags(Vec<String>);

impl Flags {
    fn value(&self, name: &str) -> Option<String> {
        self.0.iter().position(|a| a == name).and_then(|i| self.0.get(i + 1)).cloned()
    }
    fn has(&self, name: &str) -> bool {
        self.0.iter().any(|a| a == name)
    }
    fn number<T: std::str::FromStr>(&self, name: &str, default: T) -> Result<T, String> {
        match self.value(name) {
            Some(v) => v.parse().map_err(|_| format!("{name}: not a number: {v}")),
            None => Ok(default),
        }
    }
}

fn start_link(no_relay: bool, relay_only: bool) -> Result<Arc<Link>, String> {
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).map_err(|e| e.to_string())?;
    let relays = if no_relay { Relays::None } else { Relays::OursThenPublic(vec![DEFAULT_RELAY.into()]) };
    Link::start_alpn(secret, Options { relays, serving: true, private: relay_only, lookup: None }, ALPN_CHECK).map_err(|e| format!("cannot start the link: {e}"))
}

/// Writes `data` to `path` whole: a reader never sees half a file.
fn write_whole(path: &str, data: &[u8]) -> Result<(), String> {
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, data).and_then(|()| std::fs::rename(&tmp, path)).map_err(|e| format!("{path}: {e}"))
}

/// The link's key from `path`, made there (readable by its owner only) the first time.
fn key_file(path: &str) -> Result<[u8; 32], String> {
    use std::os::unix::fs::OpenOptionsExt;
    if let Ok(text) = std::fs::read_to_string(path) {
        let bytes = hex::decode(text.trim()).map_err(|_| format!("{path}: not a key"))?;
        return bytes.try_into().map_err(|_| format!("{path}: not a key"));
    }
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).map_err(|e| e.to_string())?;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(|e| format!("{path}: {e}"))?;
    f.write_all(hex::encode(secret).as_bytes()).map_err(|e| format!("{path}: {e}"))?;
    Ok(secret)
}

fn link(flags: &Flags) -> Result<(), String> {
    let card_path = flags.value("--card").ok_or("--card FILE is needed")?;
    let serving: Option<SocketAddr> = flags.value("--serve").map(|a| a.parse().map_err(|_| format!("--serve: not an address: {a}"))).transpose()?;
    let peers_path = flags.value("--peers");
    let ports_path = flags.value("--ports");
    if peers_path.is_some() != ports_path.is_some() {
        return Err("--peers and --ports go together".into());
    }
    if serving.is_some() && peers_path.is_none() {
        return Err("--serve needs --peers: only the chain's keys are let in".into());
    }
    let no_relay = flags.has("--no-relay");
    let secret = match flags.value("--key") {
        Some(path) => key_file(&path)?,
        None => {
            let mut s = [0u8; 32];
            getrandom::getrandom(&mut s).map_err(|e| e.to_string())?;
            s
        }
    };
    let relays = if no_relay { Relays::None } else { Relays::OursThenPublic(vec![DEFAULT_RELAY.into()]) };
    let link = Link::start_alpn(secret, Options { relays, serving: true, private: false, lookup: None }, ALPN_CHAIN).map_err(|e| format!("cannot start the link: {e}"))?;
    let me = link.endpoint_id();
    let allowed = Arc::new(RwLock::new(HashSet::new()));
    let counters = Arc::new(Counters::default());
    if let Some(up) = serving {
        chain::serve(&link, up, allowed.clone(), Duration::from_secs(120), counters.clone());
    }
    // with no relay, the card carries this machine's addresses, so wait until there are some
    let mut hints = link.hints(Duration::from_secs(if no_relay { 1 } else { 10 }));
    let deadline = Instant::now() + Duration::from_secs(10);
    while no_relay && hints.direct.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
        hints = link.hints(Duration::ZERO);
    }
    let card = Card { peer: Peer { id: me.clone(), relays: hints.relays, direct: if no_relay { hints.direct } else { Vec::new() } }, serves: serving.is_some() };
    write_whole(&card_path, &serde_json::to_vec_pretty(&card).map_err(|e| e.to_string())?)?;
    let mut chain = Machines::default();
    let mut ports = BTreeMap::new();
    if let (Some(peers_path), Some(ports_path)) = (peers_path, ports_path) {
        let deadline = Instant::now() + Duration::from_secs(600);
        let text = loop {
            if let Ok(text) = std::fs::read_to_string(&peers_path) {
                break text;
            }
            if Instant::now() >= deadline {
                return Err(format!("{peers_path} did not appear in 10 minutes"));
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        chain = serde_json::from_str(&text).map_err(|e| format!("{peers_path}: {e}"))?;
        if let Ok(mut a) = allowed.write() {
            a.extend(chain.machines.values().map(|c| c.peer.id.clone()));
        }
        ports = chain::forward_all(&link, &me, &chain).map_err(|e| e.to_string())?;
        let shown: BTreeMap<&String, String> = ports.iter().map(|(n, a)| (n, a.to_string())).collect();
        write_whole(&ports_path, &serde_json::to_vec_pretty(&shown).map_err(|e| e.to_string())?)?;
    }
    eprintln!("link {me}: {} machines in the chain, {} ports", chain.machines.len(), ports.len());
    let report_path = flags.value("--report");
    loop {
        if let Some(path) = &report_path {
            let r = chain::report(&link, serving, &counters, &chain, &ports);
            write_whole(path, &serde_json::to_vec_pretty(&r).map_err(|e| e.to_string())?)?;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn disk_dir(flags: &Flags) -> PathBuf {
    flags.value("--disk-dir").map_or_else(|| std::env::current_dir().unwrap_or_else(|_| ".".into()), PathBuf::from)
}

fn read_report(flags: &Flags, id: &str) -> Result<xbt_compute_check::Report, String> {
    let dir = disk_dir(flags);
    let mut report = hardware::read(id, &flags.value("--region").unwrap_or_default(), &dir)?;
    let gib: u64 = flags.number("--disk-test-gib", 0)?;
    if gib > 0 {
        eprintln!("Testing the disk: writing {gib} GiB in {}, reading it back, removing it.", dir.display());
        report.disk_read_mb_s = Some(hardware::disk_read_test(&dir, gib)?);
    }
    Ok(report)
}

fn check(flags: &Flags) -> Result<(), String> {
    let collector = flags.value("--collector").ok_or("--collector KEY is needed: ask whoever runs the test")?;
    let minutes: u64 = flags.number("--minutes", 5)?;
    let relay_only = flags.has("--relay-only");
    let no_relay = flags.has("--no-relay");
    let link = start_link(no_relay, relay_only)?;
    let id = link.endpoint_id();
    let report = read_report(flags, &id)?;
    let limits = Limits::default();
    println!("This is what would be sent to the collector, and nothing else about this machine:\n");
    println!("{}\n", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);
    println!("The key above was made for this run. No model runs and no sats move.");
    println!("For {minutes} minutes this also measures other testers: at most {} peers, {} MiB each way per peer.", 32, limits.test_bytes >> 20);
    if relay_only {
        println!("Relay only: other testers do not learn this machine's address. The relay does, and direct links cannot be measured.");
    } else {
        println!("Where a direct path forms, the other tester's machine sees this machine's internet address, and this one sees theirs. Use --relay-only to avoid that.");
    }
    if !flags.has("--yes") {
        print!("\nSend this and start? [y/N] ");
        std::io::stdout().flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line).map_err(|e| e.to_string())?;
        if !matches!(line.trim(), "y" | "Y" | "yes") {
            println!("Nothing was sent.");
            return Ok(());
        }
    }
    let hints = link.hints(Duration::from_secs(10));
    let me = Peer { id: id.clone(), relays: hints.relays, direct: if no_relay { hints.direct } else { Vec::new() } };
    if let Some(addr) = flags.value("--collector-addr") {
        let addr = addr.parse().map_err(|_| format!("--collector-addr: not an address: {addr}"))?;
        link.learn(&collector, Hints { relays: Vec::new(), direct: vec![addr] }).map_err(|e| e.to_string())?;
    } else {
        link.learn(&collector, Hints { relays: vec![DEFAULT_RELAY.to_string()], direct: Vec::new() }).map_err(|e| e.to_string())?;
    }
    probe::serve(&link, None);
    let rt = link.runtime();
    let outcome = rt.block_on(probe::run_tester(link.clone(), &collector, report, me, limits, Duration::from_secs(minutes * 60), Duration::from_secs(30)))
        .map_err(|e| format!("the collector could not be reached: {e}"))?;
    println!("\nMeasured {} testers; {} could not be reached.", outcome.links.len(), outcome.failed.len());
    for l in &outcome.links {
        println!("  {}: {}, {:.0} ms, {:.0} Mbit/s up, {:.0} down", &l.to[..8.min(l.to.len())], if l.direct { "direct" } else { "relay" }, l.rtt_ms, l.up_mbit_s, l.down_mbit_s);
    }
    println!("Done, thank you.");
    Ok(())
}

fn collect(flags: &Flags) -> Result<(), String> {
    let out = flags.value("--out").ok_or("--out FILE is needed")?;
    let collector = Collector::open(std::path::Path::new(&out)).map_err(|e| format!("{out}: {e}"))?;
    let link = start_link(flags.has("--no-relay"), false)?;
    probe::serve(&link, Some(collector));
    let hints = link.hints(Duration::from_secs(10));
    println!("key {}", link.endpoint_id());
    if flags.has("--no-relay") {
        for a in &hints.direct {
            println!("direct {a}");
        }
    } else {
        println!("relay {}", hints.relays.join(" "));
    }
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn sweep(flags: &Flags) -> Result<(), String> {
    let seeds: u64 = flags.number("--seeds", 5)?;
    println!("An illustration, not a measurement: made-up testers, 4 regions, 60% of pairs direct, 100 Mbit/s. Mix (share, card, memory):");
    for (pct, card, ram) in simulate::MIX {
        println!("  {pct:>3}%  {card:>3.0} GiB card, {ram:>3.0} GiB memory");
    }
    println!("Each cell: share of {seeds} made-up groups with a chain inside the lines (network only), and its usual length.\n");
    print!("{:>8}", "testers");
    for m in &CATALOG {
        print!("  {:>26}", m.name);
    }
    println!();
    for n in [10, 25, 50, 100, 200, 500] {
        print!("{n:>8}");
        let mut cells = vec![(0u64, Vec::new()); CATALOG.len()];
        for seed in 1..=seeds {
            let mut g = Group::default();
            simulate::testers(n, seed * 7919).into_iter().for_each(|r| g.add(r));
            for (cell, a) in cells.iter_mut().zip(plan(&g, &CATALOG)) {
                if let Some(c) = a.chains.iter().find(|c| c.meets_lines) {
                    cell.0 += 1;
                    cell.1.push(c.machines);
                }
            }
        }
        for (hits, mut lengths) in cells {
            lengths.sort();
            let cell = match lengths.get(lengths.len() / 2) {
                Some(len) => format!("{hits}/{seeds}, {len} machines"),
                None => format!("0/{seeds}"),
            };
            print!("  {cell:>26}");
        }
        println!();
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_default();
    let flags = Flags(args.collect());
    match command.as_str() {
        "check" => check(&flags),
        "report" => {
            let report = read_report(&flags, "")?;
            println!("{}", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);
            Ok(())
        }
        "collect" => collect(&flags),
        "plan" => {
            let file = flags.0.first().ok_or("plan FILE")?;
            let text = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
            let (group, bad) = Group::from_jsonl(&text);
            if bad > 0 {
                eprintln!("{bad} lines could not be read and were left out.");
            }
            print!("{}", render(&group, &plan(&group, &CATALOG)));
            Ok(())
        }
        "simulate" => {
            let n: usize = flags.number("--testers", 0)?;
            for r in simulate::testers(n, flags.number("--seed", 1)?) {
                println!("{}", serde_json::to_string(&r).map_err(|e| e.to_string())?);
            }
            Ok(())
        }
        "sweep" => sweep(&flags),
        "link" => link(&flags),
        _ => {
            println!("{USAGE}");
            Ok(())
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("stream-compute-check: {e}");
        std::process::exit(1);
    }
}
