//! The signature-log anchor witness (B2 `python -m agentwallet.anchor`), protocol and store compatible:
//!   xbt-anchor-witness serve --store DIR --sock PATH [--sock-mode 660]
//!   xbt-anchor-witness check --store DIR --log signatures.jsonl
//! Run it as its own user, with a store directory the signer's user cannot write.
use std::path::PathBuf;

use xbt_signer::anchor::{serve_witness, AnchorStore};
use xbt_signer::sigaudit::check_chain;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let store = arg(&args, "--store").map(PathBuf::from);
    match (args.first().map(String::as_str), store) {
        (Some("serve"), Some(store)) => {
            let sock = PathBuf::from(arg(&args, "--sock").unwrap_or_else(|| { eprintln!("--sock required"); std::process::exit(2) }));
            let mode = u32::from_str_radix(&arg(&args, "--sock-mode").unwrap_or_else(|| "660".into()), 8).unwrap_or(0o660);
            match serve_witness(&store, &sock, mode) {
                Ok(w) => {
                    println!("anchor witness on {}, store {}, latest {}", sock.display(), store.display(), w.store.latest());
                    loop {
                        std::thread::park();
                    }
                }
                Err(e) => {
                    eprintln!("xbt-anchor-witness: {}", e.msg);
                    std::process::exit(1);
                }
            }
        }
        (Some("check"), Some(store)) => {
            let log = PathBuf::from(arg(&args, "--log").unwrap_or_default());
            let latest = match AnchorStore::open(&store) {
                Ok(s) => s.latest(),
                Err(e) => {
                    eprintln!("{}", e.msg);
                    std::process::exit(1);
                }
            };
            let res = check_chain(&log, Some(&latest));
            println!("{res}");
            std::process::exit(if res["ok"] == true { 0 } else { 1 });
        }
        _ => {
            eprintln!("usage: xbt-anchor-witness serve --store DIR --sock PATH | check --store DIR --log FILE");
            std::process::exit(2);
        }
    }
}
