//! A seller's local HTTP service, reached by key over an iroh link, for trials and measurement.
//!
//! ```text
//! xbt-iroh-link serve <upstream host:port> [--relays none|public|URL[,URL]] [--private] [--secret-file F]
//! xbt-iroh-link dial  <endpoint id> <listen host:port> [--relays ...] [--private]
//!                     [--hint-relay URL]... [--hint-direct host:port]...
//! ```
//!
//! `serve` prints one JSON line: the key, the relays and direct addresses it can be reached at.
//! `dial` serves `listen` and carries every connection to the seller over the link.

use std::time::Duration;

use xbt_iroh_link::{Hints, Link, Options, Relays};

fn usage() -> ! {
    eprintln!("usage: xbt-iroh-link serve <upstream> [--relays none|public|URL[,URL]] [--private] [--secret-file F]");
    eprintln!("       xbt-iroh-link dial <endpoint id> <listen> [--relays ...] [--private] [--hint-relay URL]... [--hint-direct ADDR]...");
    std::process::exit(2)
}

fn secret(path: Option<&str>) -> [u8; 32] {
    if let Some(p) = path {
        if let Ok(b) = std::fs::read(p) {
            if let Ok(s) = <[u8; 32]>::try_from(b.as_slice()) {
                return s;
            }
        }
    }
    let mut s = [0u8; 32];
    std::fs::File::open("/dev/urandom").and_then(|mut f| std::io::Read::read_exact(&mut f, &mut s)).expect("random bytes");
    if let Some(p) = path {
        let _ = std::fs::write(p, s);
    }
    s
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        usage();
    }
    let (mut relays, mut private, mut secret_file) = (Relays::Public, false, None);
    let (mut hint_relays, mut hint_direct) = (vec![], vec![]);
    let mut pos = vec![];
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--relays" => {
                relays = match it.next().map(String::as_str) {
                    Some("none") => Relays::None,
                    Some("public") => Relays::Public,
                    Some(list) => Relays::Ours(list.split(',').map(str::to_string).collect()),
                    None => usage(),
                }
            }
            "--private" => private = true,
            "--secret-file" => secret_file = it.next().cloned(),
            "--hint-relay" => hint_relays.push(it.next().cloned().unwrap_or_else(|| usage())),
            "--hint-direct" => hint_direct.push(it.next().and_then(|s| s.parse().ok()).unwrap_or_else(|| usage())),
            _ => pos.push(a.clone()),
        }
    }
    match args[0].as_str() {
        "serve" => {
            let upstream = pos.first().and_then(|s| s.parse().ok()).unwrap_or_else(|| usage());
            let link = Link::start_with(secret(secret_file.as_deref()), Options { relays, serving: true, private }).expect("the link starts");
            link.serve(upstream);
            let h = link.hints(Duration::from_secs(10));
            println!(
                "{{\"endpoint_id\":\"{}\",\"relays\":{:?},\"direct\":{:?}}}",
                link.endpoint_id(),
                h.relays,
                h.direct.iter().map(|a| a.to_string()).collect::<Vec<_>>()
            );
            loop {
                std::thread::sleep(Duration::from_secs(3600));
            }
        }
        "dial" => {
            let (Some(id), Some(listen)) = (pos.first(), pos.get(1).and_then(|s| s.parse().ok())) else { usage() };
            let link = Link::start_with(secret(secret_file.as_deref()), Options { relays, serving: false, private }).expect("the link starts");
            link.learn(id, Hints { relays: hint_relays, direct: hint_direct }).expect("a seller key");
            let bound = link.forward(id, listen).expect("listen");
            eprintln!("dial: {bound} leads to {}", &id[..12]);
            loop {
                std::thread::sleep(Duration::from_secs(30));
                if let Some(p) = link.path(id) {
                    eprintln!("path: {p}");
                }
            }
        }
        _ => usage(),
    }
}
