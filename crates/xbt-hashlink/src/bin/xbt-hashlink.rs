//! xbt-hashlink: the p2p-hash link's sides, and the lab's stand-ins.
//!
//! ```text
//! xbt-hashlink keygen KEYFILE                      make a link key (prints its public key)
//! xbt-hashlink hasher --key F --miners ADDR --link ADDR --slice-work W --price-msat P [--grace-ms G] [--report F]
//! xbt-hashlink buyer  --key F --hasher ADDR --hasher-key HEX --upstream ADDR --user U --slice-work W --price-msat P
//!                     [--grace-ms G] [--rental ID] [--listing ID] [--idle-s S] [--duration-s S] [--stop-paying-after N] [--report F]
//! xbt-hashlink standin-pool  --listen ADDR --diff D [--job-ms MS] [--report F]
//! xbt-hashlink standin-miner --pool ADDR --user U [--rate SHARES_PER_S] [--bad-every N] [--duration-s S]
//! ```
//!
//! Tickets: this build uses the lab's stand-in rails (no money moves). See the crate's `rail`.

use secp256k1::{PublicKey, SecretKey};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use xbt_hashlink::msg::Terms;
use xbt_hashlink::rail::{LabBuyer, LabSeller};
use xbt_hashlink::{buyer, hasher, noise, standin};

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

fn need<'a>(f: &'a HashMap<String, String>, k: &str) -> Result<&'a str, String> {
    f.get(k).map(String::as_str).ok_or_else(|| format!("--{k} is required"))
}

fn num<T: std::str::FromStr>(f: &HashMap<String, String>, k: &str, default: Option<T>) -> Result<T, String> {
    match f.get(k) {
        Some(v) => v.parse().map_err(|_| format!("--{k}: not a number: {v}")),
        None => default.ok_or_else(|| format!("--{k} is required")),
    }
}

fn read_key(path: &str) -> Result<SecretKey, String> {
    let s = std::fs::read_to_string(path).map_err(|e| format!("key {path}: {e}"))?;
    let b = hex::decode(s.trim()).map_err(|_| format!("key {path}: not hex"))?;
    SecretKey::from_slice(&b).map_err(|_| format!("key {path}: not a secp256k1 key"))
}

fn terms(f: &HashMap<String, String>) -> Result<Terms, String> {
    Ok(Terms {
        slice_work: num(f, "slice-work", None)?,
        price_msat: num(f, "price-msat", None)?,
        grace_ms: num(f, "grace-ms", Some(3000))?,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        eprintln!("xbt-hashlink: {e}");
        std::process::exit(1);
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let (cmd, rest) = args.split_first().ok_or("usage: xbt-hashlink keygen|hasher|buyer|standin-pool|standin-miner ...")?;
    match cmd.as_str() {
        "keygen" => {
            let path = rest.first().ok_or("keygen KEYFILE")?;
            let k = noise::fresh_key();
            write_secret(path, &hex::encode(k.secret_bytes()))?;
            println!("{}", hex::encode(PublicKey::from_secret_key(secp256k1::SECP256K1, &k).serialize()));
            Ok(())
        }
        "pubkey" => {
            let k = read_key(rest.first().ok_or("pubkey KEYFILE")?)?;
            println!("{}", hex::encode(PublicKey::from_secret_key(secp256k1::SECP256K1, &k).serialize()));
            Ok(())
        }
        "hasher" => {
            let f = flags(rest)?;
            let cfg = hasher::Config {
                miners: need(&f, "miners")?.into(),
                link: need(&f, "link")?.into(),
                key: read_key(need(&f, "key")?)?,
                terms: terms(&f)?,
                report: f.get("report").map(PathBuf::from),
            };
            let r = hasher::run(cfg, Box::<LabSeller>::default())?;
            eprintln!("hasher: done: {}", r["stopped"]);
            Ok(())
        }
        "buyer" => {
            let f = flags(rest)?;
            let hk = hex::decode(need(&f, "hasher-key")?).map_err(|_| "--hasher-key: not hex")?;
            let cfg = buyer::Config {
                hasher: need(&f, "hasher")?.into(),
                hasher_key: PublicKey::from_slice(&hk).map_err(|_| "--hasher-key: not a public key")?,
                key: read_key(need(&f, "key")?)?,
                upstream: need(&f, "upstream")?.into(),
                user: need(&f, "user")?.into(),
                terms: terms(&f)?,
                rental: f.get("rental").cloned().unwrap_or_else(|| format!("r{}", xbt_hashlink::now_ms())),
                listing: f.get("listing").cloned().unwrap_or_else(|| "lab".into()),
                stop_paying_after: f.get("stop-paying-after").map(|v| v.parse()).transpose().map_err(|_| "--stop-paying-after")?,
                idle: Duration::from_secs(num(&f, "idle-s", Some(60))?),
                duration: f.get("duration-s").map(|v| v.parse().map(Duration::from_secs)).transpose().map_err(|_| "--duration-s")?,
                report: f.get("report").map(PathBuf::from),
            };
            let r = buyer::run(cfg, Box::<LabBuyer>::default())?;
            eprintln!("buyer: done: released {} slices, {}", r["released"], r["closed"]);
            Ok(())
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
            let (sent, ok, bad) = standin::miner(standin::MinerConfig {
                pool: need(&f, "pool")?.into(),
                user: need(&f, "user")?.into(),
                max_rate: num(&f, "rate", Some(20.0))?,
                bad_every: num(&f, "bad-every", Some(0))?,
                duration: f.get("duration-s").map(|v| v.parse().map(Duration::from_secs)).transpose().map_err(|_| "--duration-s")?,
            })?;
            eprintln!("miner: submitted {sent}, accepted {ok}, rejected {bad}");
            Ok(())
        }
        c => Err(format!("unknown command {c}")),
    }
}

fn write_secret(path: &str, s: &str) -> Result<(), String> {
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
