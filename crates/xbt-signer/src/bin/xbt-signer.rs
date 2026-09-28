//! The B2 signer in Rust: `xbt-signer [--root DIR] [--check]`.
//!
//! Environment as B2's signer: `B2_ROOT` (policy.json, `.run/`), `B2_DATADIR`, `B2_RPCPORT`,
//! `B2_WALLET`, `B2_CHAIN`, `B2_SIGNER_SOCK` (a path, or `tcp://127.0.0.1:PORT`), `B2_HOT_KEYFILE` /
//! `B2_HOT_PASSPHRASE`, `B2_ANCHOR_SOCK`, `B2_WATCH_INTERVAL`, `B2_HOT_SCAN`. `--check` builds the
//! signer (every start-up check: chain, P3, keys, anchor) and exits.
use std::path::PathBuf;

use xbt_signer::signer::{Signer, SignerOptions};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut root = std::env::var("B2_ROOT").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."));
    let mut check = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--root" => {
                i += 1;
                root = PathBuf::from(args.get(i).cloned().unwrap_or_default());
            }
            "--check" => check = true,
            "-h" | "--help" => {
                println!("usage: xbt-signer [--root DIR] [--check]");
                return;
            }
            other => {
                eprintln!("xbt-signer: unknown argument {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }
    let signer = match Signer::new(&root, SignerOptions::default()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("xbt-signer: refusing to start: {}: {}", e.code, e.msg);
            std::process::exit(1);
        }
    };
    if check {
        match signer.handle("health", &serde_json::json!({})) {
            Ok(h) => println!("{h}"),
            Err(e) => {
                eprintln!("xbt-signer: {}", e.msg);
                std::process::exit(1);
            }
        }
        return;
    }
    if let Err(e) = xbt_signer::server::serve(signer) {
        eprintln!("xbt-signer: {}", e.msg);
        std::process::exit(1);
    }
}
