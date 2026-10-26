//! xbt-hashlink: the p2p-hash link's sides, and the lab's stand-ins.
//!
//! ```text
//! xbt-hashlink keygen KEYFILE                      make a key (prints its public key)
//! xbt-hashlink pubkey KEYFILE
//! xbt-hashlink hasher --key F --miners ADDR --link ADDR --slice-work W --price-msat P [--grace-ms G] [--report F]
//!                     [--slices ADDR]              paid slices come from the hasher's gateway (else: the lab's rail)
//!                     [--relays URL,URL --nostr-key F --name N --link-public ADDR --pay-url URL --pay-node HEX
//!                      --hashrate-hs N [--listing-out F]]    publish the hashrate listing first
//!                     [--fallback ADDR [--rentable N] [--control ADDR [--control-token-file F]] [--config F]
//!                      [--gateway URL] [--miners-public ADDR]]
//!                         keep serving: miners not rented hash at the fallback, any number of rentals,
//!                         a control page for the app (GET /status, POST /stop/RENTAL), settings read
//!                         from F as they change; without --fallback and --config: one rental, then exit
//! xbt-hashlink renter --key F --control ADDR [--control-token-file F] --upstream ADDR|auto --user U --relays URL,URL
//!                     [--signer SOCK --task T] [--expect-node HEX] [--datum-candidates ADDR,ADDR] [--state DIR]
//!                         rent from the app: GET /status, GET /offers, POST /rent, POST /cut, POST /datum
//! xbt-hashlink buyer  --key F --upstream ADDR --user U [--idle-s S] [--duration-s S] [--stop-paying-after N]
//!                     [--rental ID] [--report F] [--miners N] [--budget-sats N]
//!                     ( --hasher ADDR --hasher-key HEX --slice-work W --price-msat P [--grace-ms G]
//!                     | --find URL,URL [--expect-node HEX] [--max-price-msat P] [--found-out F] )
//!                     [--signer SOCK --task T --max-sats N [--pay-url URL]]   pay through the wallet
//! xbt-hashlink relay  --listen ADDR                 a stand-in Nostr relay (in memory, for a lab or a rehearsal)
//! xbt-hashlink standin-pool  --listen ADDR --diff D [--job-ms MS] [--report F]
//! xbt-hashlink standin-miner --pool ADDR --user U [--rate SHARES_PER_S] [--bad-every N] [--duration-s S]
//!                            [--reconnect 1] [--extranonce-subscribe 1]
//! ```

use secp256k1::{PublicKey, SecretKey};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use xbt_hashlink::listing::{self, Capacity, Hashrate};
use xbt_hashlink::msg::Terms;
use xbt_hashlink::rail::{LabBuyer, LabSeller, SignerPayer};
use xbt_hashlink::{buyer, hasher, noise, standin};

#[path = "hashlink/http.rs"]
mod http;
#[path = "hashlink/renter.rs"]
mod renter;
#[path = "hashlink/service.rs"]
mod service;

fn flags(args: &[String]) -> Result<HashMap<String, String>, String> {
    let mut m = HashMap::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let k = a.strip_prefix("--").ok_or_else(|| format!("unexpected argument {a}"))?;
        let v = it.next().ok_or_else(|| format!("--{k} needs a value"))?;
        m.insert(k.to_string(), v.clone());
    }
    Ok(m)
}

pub(crate) fn need<'a>(f: &'a HashMap<String, String>, k: &str) -> Result<&'a str, String> {
    f.get(k).map(String::as_str).ok_or_else(|| format!("--{k} is required"))
}

pub(crate) fn num<T: std::str::FromStr>(f: &HashMap<String, String>, k: &str, default: Option<T>) -> Result<T, String> {
    match f.get(k) {
        Some(v) => v.parse().map_err(|_| format!("--{k}: not a number: {v}")),
        None => default.ok_or_else(|| format!("--{k} is required")),
    }
}

pub(crate) fn read_key(path: &str) -> Result<SecretKey, String> {
    let s = std::fs::read_to_string(path).map_err(|e| format!("key {path}: {e}"))?;
    let b = hex::decode(s.trim()).map_err(|_| format!("key {path}: not hex"))?;
    SecretKey::from_slice(&b).map_err(|_| format!("key {path}: not a secp256k1 key"))
}

fn pubkey(k: &SecretKey) -> PublicKey {
    PublicKey::from_secret_key(secp256k1::SECP256K1, k)
}

fn terms(f: &HashMap<String, String>) -> Result<Terms, String> {
    Ok(Terms {
        slice_work: num(f, "slice-work", None)?,
        price_msat: num(f, "price-msat", None)?,
        grace_ms: num(f, "grace-ms", Some(3000))?,
    })
}

pub(crate) fn relays(s: &str) -> Vec<String> {
    s.split(',').map(str::trim).filter(|r| !r.is_empty()).map(str::to_string).collect()
}

fn write_json(path: Option<&String>, v: &serde_json::Value) {
    if let Some(p) = path {
        let _ = std::fs::write(p, serde_json::to_vec_pretty(v).unwrap_or_default());
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        eprintln!("xbt-hashlink: {e}");
        std::process::exit(1);
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let (cmd, rest) = args.split_first().ok_or("usage: xbt-hashlink keygen|pubkey|hasher|buyer|relay|standin-pool|standin-miner ...")?;
    match cmd.as_str() {
        "keygen" => {
            let path = rest.first().ok_or("keygen KEYFILE")?;
            let k = noise::fresh_key();
            write_secret(path, &hex::encode(k.secret_bytes()))?;
            println!("{}", hex::encode(pubkey(&k).serialize()));
            Ok(())
        }
        "pubkey" => {
            let k = read_key(rest.first().ok_or("pubkey KEYFILE")?)?;
            println!("{}", hex::encode(pubkey(&k).serialize()));
            Ok(())
        }
        "hasher" => hasher_cmd(&flags(rest)?),
        "buyer" => buyer_cmd(&flags(rest)?),
        "renter" => renter::run(&flags(rest)?),
        "relay" => {
            let f = flags(rest)?;
            let r = xbt_nostr::standin::StandinRelay::start_on(need(&f, "listen")?).map_err(|e| e.to_string())?;
            eprintln!("relay: {}", r.url);
            loop {
                std::thread::sleep(Duration::from_secs(3600));
            }
        }
        "standin-pool" => {
            let f = flags(rest)?;
            standin::pool(standin::PoolConfig {
                listen: need(&f, "listen")?.into(),
                diff: num(&f, "diff", None)?,
                job_every: Duration::from_millis(num(&f, "job-ms", Some(5000))?),
                report: f.get("report").map(PathBuf::from),
            })
        }
        "standin-miner" => {
            let f = flags(rest)?;
            let r = standin::miner(standin::MinerConfig {
                pool: need(&f, "pool")?.into(),
                user: need(&f, "user")?.into(),
                max_rate: num(&f, "rate", Some(20.0))?,
                bad_every: num(&f, "bad-every", Some(0))?,
                duration: f.get("duration-s").map(|v| v.parse().map(Duration::from_secs)).transpose().map_err(|_| "--duration-s")?,
                reconnect: num(&f, "reconnect", Some(0u8))? == 1,
                extranonce_subscribe: num(&f, "extranonce-subscribe", Some(0u8))? == 1,
            })?;
            eprintln!(
                "miner: submitted {}, accepted {}, rejected {}, sessions {}, extranonce changes {}, longest gap {} ms",
                r.submitted, r.accepted, r.rejected, r.sessions, r.extranonce_changes, r.max_gap_ms
            );
            Ok(())
        }
        c => Err(format!("unknown command {c}")),
    }
}

fn hasher_cmd(f: &HashMap<String, String>) -> Result<(), String> {
    if f.contains_key("fallback") || f.contains_key("config") {
        let key = service::key_file(need(f, "key")?)?;
        return service::run(f, key);
    }
    let key = read_key(need(f, "key")?)?;
    let t = terms(f)?;
    if let Some(r) = f.get("relays") {
        let h = listing_of(f, &key, &t, Capacity::default())?;
        publish(f, r, &key, &h)?;
    }
    let cfg = hasher::Config {
        miners: need(f, "miners")?.into(),
        link: need(f, "link")?.into(),
        key,
        terms: t,
        report: f.get("report").map(PathBuf::from),
        slices: f.get("slices").cloned(),
        fallback: None,
        rentable: None,
    };
    let r = hasher::run(cfg, Box::<LabSeller>::default())?;
    eprintln!("hasher: done: {}", r["stopped"]);
    Ok(())
}

pub(crate) fn listing_of(f: &HashMap<String, String>, key: &SecretKey, t: &Terms, capacity: Capacity) -> Result<Hashrate, String> {
    Ok(Hashrate {
        name: need(f, "name")?.into(),
        algorithm: "blake2b".into(),
        hashrate_hs: num(f, "hashrate-hs", Some(capacity.free_hs))?,
        link_addr: need(f, "link-public")?.into(),
        link_key: pubkey(key),
        pay_url: need(f, "pay-url")?.into(),
        pay_node: need(f, "pay-node")?.into(),
        terms: t.clone(),
        capacity,
    })
}

pub(crate) fn publish(f: &HashMap<String, String>, relays_s: &str, key: &SecretKey, h: &Hashrate) -> Result<(), String> {
    let nostr = xbt_nostr::event::Keys::new(read_key(need(f, "nostr-key")?)?);
    let ev = h.event(key, &nostr, xbt_nostr::now())?;
    let said = listing::publish(&relays(relays_s), &ev);
    eprintln!("hasher: listing {} published: {}", ev.id, serde_json::Value::from(said.clone()));
    write_json(f.get("listing-out"), &serde_json::json!({"event": ev.to_value(), "relays": said}));
    if !said.iter().any(|s| s["ok"] == true) {
        return Err("no relay took the listing".into());
    }
    Ok(())
}

fn buyer_cmd(f: &HashMap<String, String>) -> Result<(), String> {
    let (hasher, hasher_key, t, found_pay_url) = match f.get("find") {
        Some(r) => {
            let (found, refused) = listing::find(&relays(r), xbt_nostr::now());
            let max_price: u64 = num(f, "max-price-msat", Some(u64::MAX))?;
            let pick = found.into_iter().find(|(h, _)| {
                h.algorithm == "blake2b" && h.terms.price_msat <= max_price && f.get("expect-node").is_none_or(|n| *n == h.pay_node)
            });
            let (h, ev) = pick.ok_or(format!("no hashrate listing on the relays fits ({refused} refused)"))?;
            eprintln!("buyer: found {} ({}) at {}, event {}", h.name, hex::encode(h.link_key.serialize()), h.link_addr, ev.id);
            write_json(f.get("found-out"), &serde_json::json!({"listing": h.to_json(), "event": ev.id, "author": ev.pubkey, "refused": refused}));
            (h.link_addr.clone(), h.link_key, h.terms.clone(), Some(h.pay_url.clone()))
        }
        None => {
            let hk = hex::decode(need(f, "hasher-key")?).map_err(|_| "--hasher-key: not hex")?;
            (need(f, "hasher")?.to_string(), PublicKey::from_slice(&hk).map_err(|_| "--hasher-key: not a public key")?, terms(f)?, None)
        }
    };
    let payer = match f.get("signer") {
        Some(sock) => Some(SignerPayer {
            sock: PathBuf::from(sock),
            url: f.get("pay-url").cloned().or(found_pay_url).ok_or("--pay-url is required with --signer")?,
            task: need(f, "task")?.into(),
            max_sats: num(f, "max-sats", None)?,
            session: None,
        }),
        None => None,
    };
    let cfg = buyer::Config {
        miners: num(f, "miners", Some(0))?,
        budget_msat: f.get("budget-sats").map(|v| v.parse::<u64>().map(|s| s * 1000)).transpose().map_err(|_| "--budget-sats")?,
        cut: None,
        live: None,
        hasher,
        hasher_key,
        key: read_key(need(f, "key")?)?,
        upstream: need(f, "upstream")?.into(),
        user: need(f, "user")?.into(),
        terms: t,
        rental: f.get("rental").cloned().unwrap_or_else(|| format!("r{}", xbt_hashlink::now_ms())),
        listing: f.get("listing").cloned().unwrap_or_else(|| "lab".into()),
        stop_paying_after: f.get("stop-paying-after").map(|v| v.parse()).transpose().map_err(|_| "--stop-paying-after")?,
        idle: Duration::from_secs(num(f, "idle-s", Some(60))?),
        duration: f.get("duration-s").map(|v| v.parse().map(Duration::from_secs)).transpose().map_err(|_| "--duration-s")?,
        report: f.get("report").map(PathBuf::from),
        payer,
    };
    let r = buyer::run(cfg, Box::<LabBuyer>::default())?;
    eprintln!("buyer: done: released {} slices, {}", r["released"], r["closed"]);
    Ok(())
}

pub(crate) fn write_secret(path: &str, s: &str) -> Result<(), String> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    o.mode(0o600);
    let mut f = o.open(path).map_err(|e| format!("{path}: {e}"))?;
    f.write_all(s.as_bytes()).map_err(|e| e.to_string())
}
