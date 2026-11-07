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
  link --card FILE [--serve IP:PORT] [--peers FILE --ports FILE [--to NAME,...]] [--report FILE]
       [--key FILE]
      Carries a compute chain over iroh. Serves IP:PORT, this machine's chain port, to the chain's
      other machines, and writes this machine's card. Once the chain's cards are gathered in
      --peers, opens a loopback port for each other machine that serves, or only for those named
      in --to (a user's machine: the relay), and writes them to --ports. Only the chain's keys are
      let in. Runs until stopped. Without --key, a new key.

  payout --config FILE [--once]
      Splits what this box's gateway earns from one model among the machines of its Mesh-LLM split,
      by the work each does, and pays each lender's BOLT 12 offer through the owner's wallet. See
      docs/COMPUTE-ALPHA.md. Paid is what the wallet says settled; a run that was killed is safe to
      start again.
  shares --gguf FILE [--stages 0-7,7-28]
      What each stage of a split does per token, from the model's header, as the payout pays by it.
  invite --config FILE --name NAME --out FILE --build-file F --build-url U --model-file F --model-url U
         [--relay URL] [--max-vram GB]
      Writes an invite to lend to this box's split, by the terms of its payout config and its gateway.
  lend --invite FILE --node-rest URL --node-macaroon FILE [--node-cert FILE] [--name NAME] [--dir DIR]
       [--model FILE] [--credit-sats N] [--slack-ppm N] [--port-base N] [--bind-ip IP] [--interval-s N]
       [--max-vram GB] [--rejoin-wait-s N] [--allow-build SHA256] [--yes]
      Lends this machine: shows what it will do and asks, fetches the build and model, makes an offer
      on your Lightning node, serves, and prints a card to give the operator. It counts your own work
      and stops serving if you are owed more than --credit-sats by that count. See docs/COMPUTE-ALPHA.md.
  lender-add --config FILE --card CARD [--lock FILE] [--replace]
      Adds a lender to the payout. With --lock, also writes a lock with the stages even across
      your machines and theirs: restart your Mesh-LLM node on it.

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
        // a writer that does not write the file whole is waited for, not misread
        let deadline = Instant::now() + Duration::from_secs(600);
        chain = loop {
            match std::fs::read_to_string(&peers_path).map(|t| serde_json::from_str::<Machines>(&t)) {
                Ok(Ok(chain)) => break chain,
                Ok(Err(e)) if Instant::now() >= deadline => return Err(format!("{peers_path}: {e}")),
                _ if Instant::now() >= deadline => return Err(format!("{peers_path} did not appear in 10 minutes")),
                _ => std::thread::sleep(Duration::from_millis(100)),
            }
        };
        if let Ok(mut a) = allowed.write() {
            a.extend(chain.machines.values().map(|c| c.peer.id.clone()));
        }
        let to: Option<HashSet<String>> = flags.value("--to").map(|t| t.split(',').filter(|n| !n.is_empty()).map(String::from).collect());
        if let Some(missing) = to.iter().flatten().find(|n| !chain.machines.contains_key(*n)) {
            return Err(format!("--to {missing}: no such machine in {peers_path}"));
        }
        ports = chain::forward_all(&link, &me, &chain, to.as_ref()).map_err(|e| e.to_string())?;
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

static LEND_ENDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn lend_end(_: libc::c_int) {
    LEND_ENDING.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// The lender's Mesh-LLM, in a session of its own: it runs on if `lend` is killed, and the next `lend`
/// takes it up again, so that a crash of the watch does not take a stage out of a split.
struct Mesh {
    bin: PathBuf,
    home: PathBuf,
    args: Vec<String>,
    log: PathBuf,
    pidfile: PathBuf,
    child: Option<std::process::Child>,
    pid: Option<i32>,
}

impl Mesh {
    /// Whether `pid` is running this very build: its path is the program's, or the script's it runs.
    fn is_ours(&self, pid: i32) -> bool {
        let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else { return false };
        let bin = self.bin.as_os_str().as_encoded_bytes();
        cmdline.split(|b| *b == 0).take(2).any(|arg| arg == bin)
    }

    fn take_up(&mut self) {
        let was = std::fs::read_to_string(&self.pidfile).ok().and_then(|p| p.trim().parse::<i32>().ok());
        self.pid = was.filter(|p| self.is_ours(*p));
    }

    fn alive(&mut self) -> bool {
        if let Some(c) = &mut self.child {
            return matches!(c.try_wait(), Ok(None));
        }
        self.pid.is_some_and(|p| self.is_ours(p))
    }

    fn start(&mut self) -> Result<(), String> {
        use std::os::unix::process::CommandExt;
        let say = |e: std::io::Error| format!("{}: {e}", self.log.display());
        let out = std::fs::OpenOptions::new().create(true).append(true).open(&self.log).map_err(say)?;
        let err = out.try_clone().map_err(say)?;
        let config_dir = self.home.join(".mesh-llm");
        std::fs::create_dir_all(&config_dir).map_err(say)?;
        let config = config_dir.join("config.toml");
        if let Some(text) = xbt_compute_check::lend::mesh_config(std::fs::read_to_string(&config).ok().as_deref()) {
            std::fs::write(&config, text).map_err(|e| format!("{}: {e}", config.display()))?;
        }
        let mut cmd = std::process::Command::new(&self.bin);
        cmd.args(&self.args).env("HOME", &self.home).env("MESH_LLM_ANALYTICS", "0").env("DO_NOT_TRACK", "1").stdin(std::process::Stdio::null()).stdout(out).stderr(err);
        // SAFETY: setsid is async-signal-safe, and it is all the child does before exec.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let child = cmd.spawn().map_err(|e| format!("{}: {e}", self.bin.display()))?;
        self.pid = Some(child.id() as i32);
        write_whole(&self.pidfile.to_string_lossy(), child.id().to_string().as_bytes())?;
        self.child = Some(child);
        Ok(())
    }

    fn stop(&mut self) {
        let Some(pid) = self.pid else { return };
        // SAFETY: signals to the session this process started, checked to be ours.
        if self.alive() {
            unsafe { libc::kill(-pid, libc::SIGTERM) };
            for _ in 0..40 {
                if !self.alive() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            if self.alive() {
                unsafe { libc::kill(-pid, libc::SIGKILL) };
            }
        }
        if let Some(c) = &mut self.child {
            let _ = c.wait();
        }
        self.child = None;
        self.pid = None;
        let _ = std::fs::remove_file(&self.pidfile);
    }
}

fn lend(flags: &Flags) -> Result<(), String> {
    use xbt_compute_check::lend::{build_allowed, decide, fetch_checked, floor_msat, load_watch, matches, may_rejoin, mesh_args, node_id_of_token, own_stages, save_watch, terms_text, Action, Card, Invite, Stop, REJOIN_WAIT_S};
    use xbt_compute_check::meter::Work;
    use xbt_compute_check::payout::http_json;
    use xbt_gateway::node::{InvoiceState, LndRest, Node};
    let invite_path = flags.value("--invite").ok_or("--invite FILE is needed")?;
    let invite = Invite::parse(&std::fs::read_to_string(&invite_path).map_err(|e| format!("{invite_path}: {e}"))?)?;
    // what is refused is refused before the owner is asked anything
    build_allowed(&invite.build.sha256, flags.value("--allow-build").as_deref())?;
    let rest = flags.value("--node-rest").ok_or("--node-rest URL is needed: your Lightning node, where you are paid")?;
    let macaroon_path = flags.value("--node-macaroon").ok_or("--node-macaroon FILE is needed, with invoices:read and invoices:write")?;
    let dir = flags.value("--dir").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".local/share/stream-lend"));
    let credit_sats: u64 = flags.number("--credit-sats", invite.terms.min_payout_sats.saturating_mul(3))?;
    let slack_ppm: u32 = flags.number("--slack-ppm", 100_000)?;
    let interval: u64 = flags.number("--interval-s", 30)?;
    let port_base: u16 = flags.number("--port-base", 34911)?;
    let vram: u32 = flags.number("--max-vram", invite.max_vram_gb)?;
    let rejoin_wait: u64 = flags.number("--rejoin-wait-s", REJOIN_WAIT_S)?;
    print!("{}", terms_text(&invite, &dir, credit_sats));
    if !flags.has("--yes") {
        use std::io::Write;
        print!("\nType yes to go on: ");
        std::io::stdout().flush().map_err(|e| e.to_string())?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer).map_err(|e| e.to_string())?;
        if answer.trim() != "yes" {
            println!("Nothing was fetched or started.");
            return Ok(());
        }
    }
    let say = |e: std::io::Error| format!("{}: {e}", dir.display());
    std::fs::create_dir_all(&dir).map_err(say)?;
    let tag = &invite.build.sha256[..16];
    let archive = dir.join(format!("build-{tag}.tar.gz"));
    let unpacked = dir.join(format!("build-{tag}"));
    let model_path = flags.value("--model").map(PathBuf::from);
    let model_at = model_path.clone().unwrap_or_else(|| dir.join("model.gguf"));
    // the room for what is still to come
    let mut needed = xbt_compute_check::lend::DISK_MARGIN_BYTES;
    if !matches(&archive, &invite.build)? {
        needed += invite.build.bytes.saturating_mul(2);
    }
    if !matches(&model_at, &invite.model)? {
        if model_path.is_some() {
            return Err(format!("{} is not the model the invite names", model_at.display()));
        }
        needed += invite.model.bytes;
    }
    let free = free_bytes(&dir)?;
    if free < needed {
        return Err(format!("{} has {free} bytes free and this needs {needed}", dir.display()));
    }
    // the node first: there is no use in a download with nowhere to be paid
    let macaroon = std::fs::read(&macaroon_path).map_err(|e| format!("{macaroon_path}: {e}"))?;
    let cert = flags.value("--node-cert").map(PathBuf::from);
    let node = LndRest::new(&rest, &macaroon, &macaroon, cert.as_deref()).map_err(|e| format!("your Lightning node: {e}"))?;
    let offer = node.create_offer(&format!("Compute lent to {}", invite.operator)).map_err(|e| format!("an offer on your Lightning node: {e}"))?;
    if fetch_checked(&invite.build, &archive)? {
        println!("Fetched the build: {} bytes, sha256 checked.", invite.build.bytes);
    }
    if !unpacked.is_dir() {
        std::fs::create_dir_all(&unpacked).map_err(say)?;
        let st = std::process::Command::new("tar").arg("-xzf").arg(&archive).arg("--no-same-owner").arg("-C").arg(&unpacked).status().map_err(|e| format!("tar: {e}"))?;
        if !st.success() {
            let _ = std::fs::remove_dir_all(&unpacked);
            return Err(format!("tar could not unpack {}", archive.display()));
        }
    }
    let bin = [unpacked.join("mesh-llm"), unpacked.join("mesh-bundle/mesh-llm")].into_iter().find(|p| p.is_file()).ok_or("the build holds no mesh-llm")?;
    if model_path.is_none() && fetch_checked(&invite.model, &model_at)? {
        println!("Fetched the model: {} bytes, sha256 checked.", invite.model.bytes);
    }
    let header = xbt_compute_check::gguf::read(&model_at).map_err(|e| format!("{}: {e}", model_at.display()))?;
    let work = Work::from_header(&header).map_err(|e| format!("{}: {e}", model_at.display()))?;

    // SAFETY: the handler only stores to an atomic.
    unsafe {
        libc::signal(libc::SIGTERM, lend_end as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, lend_end as *const () as libc::sighandler_t);
    }
    let ports = (port_base, port_base + 1, port_base + 2);
    let console = format!("http://127.0.0.1:{}", ports.1);
    let mut mesh = Mesh {
        bin: bin.clone(),
        home: dir.join("home"),
        args: mesh_args(&invite, &model_at, ports, flags.value("--bind-ip").as_deref(), vram),
        log: dir.join("mesh.log"),
        pidfile: dir.join("mesh.pid"),
        child: None,
        pid: None,
    };
    mesh.take_up();
    let watch_path = dir.join("watch.json");
    let mut watch = load_watch(&watch_path)?;
    let credit = credit_sats.saturating_mul(1000);
    let name = flags.value("--name").unwrap_or_else(|| "a lender".to_string());
    let mut me: Option<String> = None;
    let mut last_line = String::new();
    while !LEND_ENDING.load(std::sync::atomic::Ordering::SeqCst) {
        let mut notes: Vec<String> = vec![];
        let clock = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs_f64();
        if mesh.alive() {
            watch.mesh_seen_ts = clock;
        } else if watch.stopped.is_none() {
            if may_rejoin(watch.mesh_seen_ts, clock, rejoin_wait) {
                mesh.start()?;
                watch.mesh_seen_ts = clock;
            } else {
                notes.push(format!("waiting to join again, so that the split plans this machine in anew: {:.0} s", watch.mesh_seen_ts + rejoin_wait as f64 - clock));
            }
        }
        if me.is_none() {
            let token = http_json(&format!("{console}/api/status"), None).ok().and_then(|v| v.get("token").and_then(serde_json::Value::as_str).map(String::from));
            if let Some(id) = token.and_then(|t| node_id_of_token(&t).ok()) {
                let card = Card { node: id.clone(), name: name.clone(), offer: offer.bolt12.clone() }.encode();
                write_whole(&dir.join("card.txt").to_string_lossy(), card.as_bytes())?;
                println!("\nYour machine has joined. Give the operator this card, to be paid:\n\n{card}\n");
                me = Some(id);
            }
        }
        if let Some(id) = &me {
            match http_json(&format!("{console}/api/runtime/stages"), None).and_then(|v| own_stages(&v, id)) {
                Ok(stages) => watch.observe(&stages),
                Err(e) if watch.stopped.is_none() => notes.push(format!("this round's count could not be read: {e}")),
                Err(_) => {}
            }
        }
        let received = node.offer_invoices(&offer.id).map(|l| l.iter().filter(|i| i.state == Some(InvoiceState::Settled)).map(|i| i.paid_msat).sum::<u64>());
        let due = watch.due_msat(&invite.terms, &work)?;
        let floor = floor_msat(due, slack_ppm);
        let serving = watch.stopped.is_none();
        // a node that does not answer says nothing either way, and the owner is told
        let got = match received {
            Ok(m) => Some(m),
            Err(e) => {
                notes.push(format!("your Lightning node could not be read: {e}"));
                None
            }
        };
        if let Some(m) = got {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs_f64();
            match decide(floor, m, credit, serving) {
                Action::Stop => {
                    mesh.stop();
                    watch.mesh_seen_ts = now;
                    watch.stopped = Some(Stop { due_at_least_msat: floor, received_msat: m, ts: now });
                    println!("You are due at least {floor} msat by your own count and have received {m}. Past your limit of {credit_sats} sats: stopped serving until you are paid.");
                }
                Action::Resume => {
                    watch.stopped = None;
                    println!("You have been paid: {m} msat received of at least {floor} due. Serving again.");
                }
                Action::Serve | Action::StayStopped => {}
            }
        }
        save_watch(&watch_path, &watch)?;
        let shares: serde_json::Map<String, serde_json::Value> = watch.tokens.keys().filter_map(|k| {
            let (a, b) = k.split_once('-')?;
            let active = work.stage(a.parse().ok()?, b.parse().ok()?);
            Some((k.clone(), serde_json::json!({"active_params": active.to_string(), "total_params": work.total().to_string()})))
        }).collect();
        let report = serde_json::json!({"node": me, "offer": offer.bolt12, "serving": watch.stopped.is_none(), "tokens": watch.tokens, "total_tokens": watch.total_tokens(), "shares": shares,
                                        "due_msat": due, "due_at_least_msat": floor, "received_msat": got, "credit_msat": credit, "slack_ppm": slack_ppm, "stopped": watch.stopped, "pid": mesh.pid, "notes": notes});
        write_whole(&dir.join("report.json").to_string_lossy(), &serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?)?;
        let line = format!("{} tokens, due at least {floor} msat, received {}", watch.total_tokens(), got.map_or("?".to_string(), |m| m.to_string()));
        if line != last_line {
            println!("{line}");
            last_line = line;
        }
        notes.iter().for_each(|n| eprintln!("lend: {n}"));
        for _ in 0..interval.max(1) {
            if LEND_ENDING.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    println!("Stopping: this machine leaves the split.");
    mesh.stop();
    Ok(())
}

fn free_bytes(dir: &std::path::Path) -> Result<u64, String> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    // SAFETY: statvfs writes only to the zeroed struct given, and the path is a valid C string.
    unsafe {
        let mut s: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(path.as_ptr(), &mut s) != 0 {
            return Err(format!("{}: {}", dir.display(), std::io::Error::last_os_error()));
        }
        Ok(s.f_bavail as u64 * s.f_frsize as u64)
    }
}

fn invite(flags: &Flags) -> Result<(), String> {
    use xbt_compute_check::lend::{describe_file, Invite, Terms};
    use xbt_compute_check::payout::{http_json, load_config};
    let path = flags.value("--config").ok_or("--config FILE is needed")?;
    let cfg = load_config(std::path::Path::new(&path))?;
    let need = |flag: &str| flags.value(flag).ok_or(format!("{flag} is needed"));
    let status = http_json(&format!("{}/api/status", cfg.mesh_console_url.trim_end_matches('/')), None)?;
    let token = status.get("token").and_then(serde_json::Value::as_str).ok_or("your Mesh-LLM node gives no token")?.to_string();
    let services = http_json(&format!("{}/services", cfg.gateway_url.trim_end_matches('/')), None)?;
    let price = services.get("routes").and_then(serde_json::Value::as_array).into_iter().flatten()
        .find_map(|r| r.get("price").filter(|p| p.get("outputPer1kMsat").is_some())).ok_or("your gateway sells nothing by the token")?;
    let rate = |k: &str| price.get(k).and_then(serde_json::Value::as_str).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let invite = Invite {
        version: 1,
        operator: need("--name")?,
        mesh_token: token,
        relay: flags.value("--relay"),
        terms: Terms { per_1k_input_msat: rate("inputPer1kMsat"), per_1k_output_msat: rate("outputPer1kMsat"), operator_cut_ppm: cfg.operator_cut_ppm, min_payout_sats: cfg.min_payout_sats },
        build: describe_file(std::path::Path::new(&need("--build-file")?), &need("--build-url")?)?,
        model: describe_file(std::path::Path::new(&need("--model-file")?), &need("--model-url")?)?,
        max_vram_gb: flags.number("--max-vram", 4)?,
    };
    let text = serde_json::to_string_pretty(&invite).map_err(|e| e.to_string())?;
    Invite::parse(&text)?;
    write_whole(&need("--out")?, text.as_bytes())?;
    println!("Wrote the invite. It holds your mesh's join token: give it only to people you are inviting.");
    Ok(())
}

fn lender_add(flags: &Flags) -> Result<(), String> {
    use serde_json::{json, Value};
    use xbt_compute_check::lend::{even_stages, Card};
    use xbt_compute_check::meter::Work;
    use xbt_compute_check::payout::{http_json, load_config};
    let path = flags.value("--config").ok_or("--config FILE is needed")?;
    let card = Card::decode(&flags.value("--card").ok_or("--card CARD is needed")?)?;
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
    let mut v: Value = serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
    let lenders = v.as_object_mut().ok_or("the config is not an object")?.entry("lenders").or_insert_with(|| json!({}));
    // a card is someone's word: it does not move an existing lender's pay on its own
    if let Some(had) = lenders.get(&card.node).and_then(|l| l.get("offer")).and_then(Value::as_str) {
        if had != card.offer && !flags.has("--replace") {
            return Err(format!("{} is already paid to another offer. If this is that lender's new offer, add --replace", card.node));
        }
    }
    lenders[&card.node] = json!({"name": card.name, "offer": card.offer});
    write_whole(&path, &serde_json::to_vec_pretty(&v).map_err(|e| e.to_string())?)?;
    let cfg = load_config(std::path::Path::new(&path))?;
    println!("Added {} ({}). The payout takes it up on its next round.", card.name, card.node);
    let Some(lock_path) = flags.value("--lock") else { return Ok(()) };
    let header = xbt_compute_check::gguf::read(&cfg.gguf).map_err(|e| format!("{}: {e}", cfg.gguf.display()))?;
    let layers = Work::from_header(&header).map_err(|e| format!("{}: {e}", cfg.gguf.display()))?.layers.len() as u32;
    let mut lock: Value = match std::fs::read_to_string(&lock_path) {
        Ok(t) => serde_json::from_str(&t).map_err(|e| format!("{lock_path}: {e}"))?,
        Err(_) => {
            // no lock yet: this model's identity, from the split the lender's joining started
            let stages = http_json(&format!("{}/api/runtime/stages", cfg.mesh_console_url.trim_end_matches('/')), None)?;
            let t = stages.get("topologies").and_then(Value::as_array).and_then(|a| a.first()).ok_or("your Mesh-LLM node has no split yet: wait for the lender to join")?;
            json!({"version": 1, "model": t.get("model_id"), "manifest_sha256": t.get("manifest_sha256"), "stages": []})
        }
    };
    let mut nodes: Vec<String> = lock.get("stages").and_then(Value::as_array).into_iter().flatten().filter_map(|s| s.get("node").and_then(Value::as_str).map(String::from)).collect();
    if nodes.is_empty() {
        nodes = cfg.own_nodes.clone();
    }
    if nodes.is_empty() {
        return Err("name your own machine in the config's own_nodes, by its full id: it leads the split".into());
    }
    if !nodes.contains(&card.node) {
        nodes.push(card.node.clone());
    }
    lock["stages"] = even_stages(&nodes, layers).into_iter().map(|(node, a, b)| json!({"node": node, "layer_start": a, "layer_end": b})).collect();
    write_whole(&lock_path, &serde_json::to_vec_pretty(&lock).map_err(|e| e.to_string())?)?;
    println!("Wrote {lock_path}. Restart your Mesh-LLM node with --split-topology-lock {lock_path}, on the same home directory: the lender stays joined.");
    Ok(())
}

fn payout(flags: &Flags) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    use xbt_compute_check::meter::Work;
    use xbt_compute_check::payout::{load_config, load_ledger, report, save_ledger, tick, Live};
    let path = flags.value("--config").ok_or("--config FILE is needed")?;
    let mut cfg = load_config(std::path::Path::new(&path))?;
    let header = xbt_compute_check::gguf::read(&cfg.gguf).map_err(|e| format!("{}: {e}", cfg.gguf.display()))?;
    let work = Work::from_header(&header).map_err(|e| format!("{}: {e}", cfg.gguf.display()))?;
    // two runs on one ledger could each pay what the other has not yet noted
    let lock_path = cfg.ledger.with_extension("lock");
    let lock = std::fs::File::create(&lock_path).map_err(|e| format!("{}: {e}", lock_path.display()))?;
    // SAFETY: flock on a descriptor this function owns for as long as it runs.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(format!("another payout holds {}", lock_path.display()));
    }
    let ledger_path = cfg.ledger.clone();
    let mut led = load_ledger(&ledger_path)?;
    // a note left by a run that was killed: what it sent has this long to reach the wallet's spend lock
    // before this run asks for that lock
    if led.intent.is_some() {
        std::thread::sleep(Duration::from_secs(2));
    }
    loop {
        // a lender added since the last round; a config that does not read leaves the last one in force
        let mut changed = None;
        match load_config(std::path::Path::new(&path)) {
            Ok(new) => cfg = new,
            Err(e) => changed = Some(format!("the config could not be read, the last one stays: {e}")),
        }
        let live = Live { cfg: cfg.clone() };
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs_f64();
        let mut notes = tick(&cfg, &work, &mut led, &live, &mut |l| save_ledger(&ledger_path, l), now)?;
        notes.extend(changed);
        notes.iter().for_each(|n| eprintln!("payout: {n}"));
        if let Some(r) = &cfg.report {
            let text = serde_json::to_vec_pretty(&report(&cfg, &led, &notes)).map_err(|e| e.to_string())?;
            write_whole(&r.to_string_lossy(), &text)?;
        }
        if flags.has("--once") {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(cfg.interval_s.max(1)));
    }
}

fn shares(flags: &Flags) -> Result<(), String> {
    use xbt_compute_check::meter::Work;
    let path = flags.value("--gguf").ok_or("--gguf FILE is needed")?;
    let header = xbt_compute_check::gguf::read(std::path::Path::new(&path)).map_err(|e| format!("{path}: {e}"))?;
    let work = Work::from_header(&header).map_err(|e| format!("{path}: {e}"))?;
    let n = work.layers.len() as u32;
    let stages = flags.value("--stages").unwrap_or_else(|| format!("0-{n}"));
    let mut rows = vec![];
    for s in stages.split(',') {
        let (a, b) = s.split_once('-').ok_or_else(|| format!("stage {s}: FIRST-END"))?;
        let (a, b): (u32, u32) = (a.parse().map_err(|_| format!("stage {s}"))?, b.parse().map_err(|_| format!("stage {s}"))?);
        if a >= b || b > n {
            return Err(format!("stage {s} of a model with {n} layers"));
        }
        let active = work.stage(a, b);
        rows.push(serde_json::json!({"layers": s, "active_params": active.to_string(), "share_ppm": (active * 1_000_000 / work.total()) as u64}));
    }
    let all: u128 = header.tensors.iter().map(|t| t.dims.iter().map(|d| *d as u128).product::<u128>()).sum();
    let out = serde_json::json!({"layers": n, "embed_row": work.embed.to_string(), "head": work.head.to_string(), "total": work.total().to_string(),
                                 "all_tensors": all.to_string(), "stages": rows});
    println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
    Ok(())
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
        "payout" => payout(&flags),
        "shares" => shares(&flags),
        "invite" => invite(&flags),
        "lend" => lend(&flags),
        "lender-add" => lender_add(&flags),
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
