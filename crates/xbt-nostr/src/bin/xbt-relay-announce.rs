//! Announce a Stream relay on Nostr, so apps can find it (`docs/RUN-A-RELAY.md`).
//!
//! ```text
//! xbt-relay-announce --relay https://relay.example.com --region eu-central \
//!     --nostr wss://relay.lazarus-xbt.xyz --nostr wss://nos.lol \
//!     [--capacity-mbit 500] [--udp] [--contact ops@example.com] [--note "…"] \
//!     [--ttl-days 7] [--every-hours 24] [--key-file ~/.config/stream-relay/nostr.key] [--dry-run]
//! ```
//!
//! The announcement is signed with the key in `--key-file` (64 hex characters), made there with
//! mode 600 the first time. It lives `--ttl-days` (7 by default, at most 30). With `--every-hours`
//! the tool keeps running and announces again that often, which must be well within the TTL (at
//! most a third of it); without it, it announces once: run it again, by hand or from a timer,
//! before the TTL is up. `--dry-run` prints the signed event and publishes nothing.
use std::path::PathBuf;
use std::time::Duration;

use xbt_nostr::event::Keys;
use xbt_nostr::relays::{self, Offer};

fn usage() -> ! {
    eprintln!("usage: xbt-relay-announce --relay https://HOST --region REGION --nostr wss://… [--nostr …] \
               [--capacity-mbit N] [--udp] [--contact TEXT] [--note TEXT] [--ttl-days N] [--every-hours N] [--key-file PATH] [--dry-run]");
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
    let (mut capacity, mut udp, mut ttl_days, mut dry) = (None, false, 7u64, false);
    let mut every_hours: Option<u64> = None;
    let mut nostr = Vec::new();
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
            "--every-hours" => every_hours = Some(val().parse::<u64>().ok().filter(|h| *h > 0).unwrap_or_else(|| usage())),
            "--key-file" => key_file = PathBuf::from(val()),
            "--dry-run" => dry = true,
            "-h" | "--help" => usage(),
            _ => usage(),
        }
    }
    let (Some(relay), Some(region)) = (relay, region) else { usage() };
    if nostr.is_empty() && !dry {
        eprintln!("name at least one Nostr relay with --nostr");
        std::process::exit(2);
    }
    if let Err(e) = every_ok(every_hours, ttl_days) {
        eprintln!("{e}");
        std::process::exit(2);
    }
    let run = || -> Result<(), String> {
        let keys = key(&key_file)?;
        let offer = Offer { relay: relay.clone(), region: region.clone(), capacity_mbit: capacity, udp, contact: contact.clone(), note: note.clone(),
                            ttl_s: ttl_days.saturating_mul(86_400) };
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
    let Some(hours) = every_hours.filter(|_| !dry) else {
        if let Err(e) = run() {
            eprintln!("{e}");
            std::process::exit(1);
        }
        return;
    };
    // kept running: a round no relay took is tried again at the next, which is still well within the TTL
    loop {
        if let Err(e) = run() {
            eprintln!("{e}");
        }
        std::thread::sleep(Duration::from_secs(hours.saturating_mul(3600)));
    }
}

/// `--every-hours` is well within the announcement's life: at most a third of `--ttl-days`, so a
/// round or two that no relay takes does not let it lapse.
fn every_ok(every_hours: Option<u64>, ttl_days: u64) -> Result<(), String> {
    let ttl_h = ttl_days.clamp(1, relays::MAX_TTL_S / 86_400) * 24;
    match every_hours {
        Some(h) if h.saturating_mul(3) > ttl_h => Err(format!("--every-hours {h} is too long for --ttl-days {ttl_days}: at most {} hours", ttl_h / 3)),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::every_ok;

    #[test]
    fn announcing_again_is_well_within_the_ttl() {
        assert!(every_ok(None, 7).is_ok());
        assert!(every_ok(Some(24), 7).is_ok());
        assert!(every_ok(Some(56), 7).is_ok());
        assert!(every_ok(Some(57), 7).unwrap_err().contains("at most 56 hours"));
        assert!(every_ok(Some(240), 30).is_ok());
        assert!(every_ok(Some(241), 30).is_err());
    }
}
