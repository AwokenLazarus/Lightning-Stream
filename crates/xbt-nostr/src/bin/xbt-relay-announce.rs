//! Announce a Stream relay on Nostr, so apps can find it (`docs/RUN-A-RELAY.md`).
//!
//! ```text
//! xbt-relay-announce --relay https://relay.example.com --region eu-central \
//!     --nostr wss://relay.lazarus-xbt.xyz --nostr wss://nos.lol \
//!     [--capacity-mbit 500] [--udp] [--contact ops@example.com] [--note "…"] \
//!     [--ttl-days 30] [--key-file ~/.config/stream-relay/nostr.key] [--dry-run] \
//!     [--price-msat-per-gb 2000 --credit https://shop.example.com/stream-relay]
//! ```
//!
//! `--price-msat-per-gb` and `--credit` announce a paid relay (`docs/PAID-RELAYS.md`): its price per
//! GB in msat, and the priced route on the operator's shop where credit is bought. Both or neither.
//!
//! The announcement is signed with the key in `--key-file` (64 hex characters), made there with
//! mode 600 the first time. It lives `--ttl-days` (at most 30): run this again, by hand or from a
//! timer, before then. `--dry-run` prints the signed event and publishes nothing.
use std::path::PathBuf;
use std::time::Duration;

use xbt_nostr::event::Keys;
use xbt_nostr::relays::{self, Offer};

fn usage() -> ! {
    eprintln!("usage: xbt-relay-announce --relay https://HOST --region REGION --nostr wss://… [--nostr …] \
               [--capacity-mbit N] [--udp] [--contact TEXT] [--note TEXT] [--ttl-days N] [--key-file PATH] [--dry-run] \
               [--price-msat-per-gb N --credit https://…]");
    std::process::exit(2)
}

fn key(path: &PathBuf) -> Result<Keys, String> {
    match std::fs::read_to_string(path) {
        Ok(s) => Keys::from_hex(s.trim()).ok_or_else(|| format!("{}: not a key (64 hex characters)", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let k = Keys::generate();
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            }
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
            let mut f = o.open(path).map_err(|e| format!("{}: {e}", path.display()))?;
            std::io::Write::write_all(&mut f, format!("{}\n", k.secret_hex()).as_bytes()).map_err(|e| format!("{}: {e}", path.display()))?;
            eprintln!("made a new announcing key in {} (keep it: it is how you update this announcement)", path.display());
            Ok(k)
        }
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn main() {
    let mut a = std::env::args().skip(1);
    let (mut relay, mut region, mut contact, mut note) = (None, None, String::new(), String::new());
    let (mut capacity, mut udp, mut ttl_days, mut dry) = (None, false, 30u64, false);
    let mut nostr = Vec::new();
    let (mut price, mut credit): (Option<u64>, Option<String>) = (None, None);
    let mut key_file = std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config/stream-relay/nostr.key")).unwrap_or_else(|| "nostr.key".into());
    while let Some(arg) = a.next() {
        let mut val = || a.next().unwrap_or_else(|| usage());
        match arg.as_str() {
            "--relay" => relay = Some(val()),
            "--region" => region = Some(val()),
            "--nostr" => nostr.push(val()),
            "--capacity-mbit" => capacity = Some(val().parse::<u32>().unwrap_or_else(|_| usage())),
            "--udp" => udp = true,
            "--contact" => contact = val(),
            "--note" => note = val(),
            "--ttl-days" => ttl_days = val().parse::<u64>().unwrap_or_else(|_| usage()),
            "--key-file" => key_file = PathBuf::from(val()),
            "--dry-run" => dry = true,
            "--price-msat-per-gb" => price = Some(val().parse::<u64>().unwrap_or_else(|_| usage())),
            "--credit" => credit = Some(val()),
            "-h" | "--help" => usage(),
            _ => usage(),
        }
    }
    let (Some(relay), Some(region)) = (relay, region) else { usage() };
    let price = match (price, credit) {
        (Some(msat_per_gb), Some(credit)) => Some(relays::RelayPrice { msat_per_gb, credit }),
        (None, None) => None,
        _ => usage(),
    };
    if nostr.is_empty() && !dry {
        eprintln!("name at least one Nostr relay with --nostr");
        std::process::exit(2);
    }
    let run = || -> Result<(), String> {
        let keys = key(&key_file)?;
        let offer = Offer { relay, region, capacity_mbit: capacity, udp, contact, note, ttl_s: ttl_days.saturating_mul(86_400), price };
        let ev = relays::announcement_event(&keys, &offer, xbt_nostr::now())?;
        if dry {
            println!("{}", ev.to_value());
            return Ok(());
        }
        let outcomes = xbt_nostr::oneshot::publish(&nostr, &ev, Duration::from_secs(10));
        let ok = outcomes.iter().filter(|o| o.result.is_ok()).count();
        for o in &outcomes {
            match &o.result {
                Ok(()) => println!("{}: accepted", o.relay),
                Err(e) => println!("{}: {e}", o.relay),
            }
        }
        if ok == 0 {
            return Err("no Nostr relay accepted the announcement".into());
        }
        println!("announced {} by {} on {ok} of {} relays", relays::canonical_relay(&offer.relay)?, keys.public_hex(), outcomes.len());
        Ok(())
    };
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
