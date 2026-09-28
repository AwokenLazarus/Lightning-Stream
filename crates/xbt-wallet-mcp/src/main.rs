//! `xbt-wallet-mcp`: the agent wallet's MCP server.
//!
//!   xbt-wallet-mcp                      stdio (Claude Code, Hermes, OpenClaw)
//!   xbt-wallet-mcp --http 127.0.0.1:33510 [--path /mcp] [--http-allow-remote]
//!   xbt-wallet-mcp --check              ask the signer for `health`, print it, exit 0 if reachable
//!   xbt-wallet-mcp --list-tools         print the tool list (JSON) and exit
//!
//! Environment (B2's): `B2_SIGNER_SOCK` (a socket path or `tcp://127.0.0.1:PORT`) or `B2_ROOT`
//! (socket `$B2_ROOT/.run/signer.sock`), `B2_SIGNER_TIMEOUT`, `B2_BODY_CAP`. Ours: `XBT_MCP_PAYER`
//! (`signer`, the default, or `local`; see the README), `XBT_MCP_NETWORK` and the other `XBT_MCP_*`
//! payer settings, `XBT_MCP_HTTP_TOKEN` (a bearer token for HTTP).
use std::sync::Arc;

use xbt_wallet_mcp::mcp::{tools, Server};
use xbt_wallet_mcp::transport::{serve_http, serve_stdio, HttpConfig};
use xbt_wallet_mcp::wallet::Wallet;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn die(msg: &str) -> ! {
    eprintln!("xbt-wallet-mcp: {msg}");
    std::process::exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{}", include_str!("main.rs").lines().take_while(|l| l.starts_with("//!")).map(|l| l.trim_start_matches("//!").trim_start_matches(' ')).collect::<Vec<_>>().join("\n"));
        return;
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("xbt-wallet-mcp {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args.iter().any(|a| a == "--list-tools") {
        println!("{}", serde_json::to_string_pretty(&tools()).unwrap_or_default());
        return;
    }
    let wallet = Wallet::from_env().unwrap_or_else(|e| die(&e));
    if args.iter().any(|a| a == "--check") {
        match wallet.signer("health", &serde_json::json!({})) {
            Ok(v) => {
                println!("{}", xbt_wallet_mcp::wallet::pack(v).unwrap_or_else(|e| die(&e)));
                return;
            }
            Err(e) => die(&e),
        }
    }
    let server = Arc::new(Server::new(Arc::new(wallet)));
    match arg(&args, "--http") {
        Some(addr) => {
            let cfg = HttpConfig { addr, path: arg(&args, "--path").unwrap_or_else(|| "/mcp".into()),
                                   token: std::env::var("XBT_MCP_HTTP_TOKEN").ok().filter(|t| !t.is_empty()),
                                   allow_remote: args.iter().any(|a| a == "--http-allow-remote") };
            if let Err(e) = serve_http(server, cfg) {
                die(&e);
            }
        }
        None => serve_stdio(server),
    }
}
