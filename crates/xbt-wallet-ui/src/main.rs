//! `xbt-wallet-ui`: the agent wallet's web UI (AGP-039).
//!
//!   xbt-wallet-ui [serve]                       serve (configuration from the environment: see `config`)
//!   xbt-wallet-ui sign --key FILE --message-hex HEX
//!                                               sign a message shown by the UI with an approval key file
//!                                               (32 raw bytes or 64 hex; the UI's backup), on another device
//!   xbt-wallet-ui pubkey --key FILE             the key file's public key (for enrolment)
//!   xbt-wallet-ui healthcheck [--ready]         GET /healthz (or /readyz) on XBT_UI_BIND: the image's
//!                                               HEALTHCHECK (it has no shell or curl); exit 0 on 200
//!   xbt-wallet-ui node-keys                     make the app's narrow macaroons through the box's own
//!                                               Lightning node (`node_keys`), retrying until the node
//!                                               answers; exit 0 once every key is there
//!
//! `serve` stops on SIGTERM or SIGINT: no new connection, the requests in flight get 5 s, exit 0.
use std::io::Read;

fn key_from(path: &str) -> Result<[u8; 32], String> {
    let mut raw = Vec::new();
    std::fs::File::open(path).and_then(|mut f| f.read_to_end(&mut raw)).map_err(|e| format!("{path}: {e}"))?;
    if raw.len() == 32 {
        return Ok(raw.try_into().expect("32"));
    }
    let t = String::from_utf8_lossy(&raw).trim().to_string();
    hex::decode(&t).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| format!("{path}: not 32 raw bytes or 64 hex characters"))
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        None | Some("serve") => serve(),
        Some("healthcheck") => healthcheck(args.iter().any(|a| a == "--ready")),
        Some("node-keys") => node_keys(),
        Some("sign") | Some("pubkey") => match offline(&args) {
            Ok(out) => {
                println!("{out}");
                0
            }
            Err(e) => {
                eprintln!("xbt-wallet-ui: {e}");
                2
            }
        },
        Some("-h") | Some("--help") => {
            println!("usage: xbt-wallet-ui [serve] | sign --key FILE --message-hex HEX | pubkey --key FILE | healthcheck [--ready] | node-keys\n\
                      serve reads XBT_UI_BIND, XBT_UI_SIGNER_SOCK, XBT_UI_DATA_DIR, XBT_UI_PASSWORD_FILE, XBT_UI_BASE_PATH, ... (README)");
            0
        }
        Some(o) => {
            eprintln!("xbt-wallet-ui: unknown command {o} (try --help)");
            2
        }
    };
    std::process::exit(code);
}

fn offline(args: &[String]) -> Result<String, String> {
    let key = key_from(&arg(args, "--key").ok_or("--key FILE is required")?)?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&key);
    if args[0] == "pubkey" {
        return Ok(hex::encode(sk.verifying_key().to_bytes()));
    }
    let m = hex::decode(arg(args, "--message-hex").ok_or("--message-hex HEX is required")?.trim()).map_err(|_| "--message-hex is not hex")?;
    Ok(hex::encode(ed25519_dalek::Signer::sign(&sk, &m).to_bytes()))
}

/// Until every key is there: a node that is starting, or whose wallet is still locked, is asked again
/// (5 s, doubling to 5 min). A setting that is missing is not retried.
fn node_keys() -> i32 {
    // a box that gives the app no Lightning node: nothing to make (the owner can still paste keys)
    if std::env::var("XBT_KEYS_NODE_REST").map(|v| v.trim().is_empty()).unwrap_or(true) {
        eprintln!("xbt-wallet-ui node-keys: this box gave no Lightning node; nothing to make");
        return 0;
    }
    let s = match xbt_wallet_ui::node_keys::Settings::from_env() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("xbt-wallet-ui node-keys: {e}");
            return 2;
        }
    };
    let mut wait = std::time::Duration::from_secs(5);
    loop {
        match xbt_wallet_ui::node_keys::run(&s) {
            Ok(o) if o.made.is_empty() => {
                eprintln!("xbt-wallet-ui node-keys: the app's keys were already there; nothing made");
                return 0;
            }
            Ok(o) => {
                eprintln!("xbt-wallet-ui node-keys: made {} through the box's Lightning node (each with a root key of its own)", o.made.join(", "));
                return 0;
            }
            Err(e) => {
                eprintln!("xbt-wallet-ui node-keys: not yet: {e}; asking again in {} s", wait.as_secs());
                std::thread::sleep(wait);
                wait = (wait * 2).min(std::time::Duration::from_secs(300));
            }
        }
    }
}

fn healthcheck(ready: bool) -> i32 {
    let bind = std::env::var("XBT_UI_BIND").ok().filter(|b| !b.trim().is_empty()).unwrap_or_else(|| "127.0.0.1:8480".into());
    let addr = match bind.rsplit_once(':') {
        Some(("0.0.0.0", p)) => format!("127.0.0.1:{p}"),
        Some(("[::]", p)) => format!("[::1]:{p}"),
        _ => bind,
    };
    let path = if ready { "/readyz" } else { "/healthz" };
    match xbt_wallet_ui::app::http_get(&format!("http://{addr}{path}")) {
        Ok((200, _)) => 0,
        Ok((code, body)) => {
            eprintln!("xbt-wallet-ui healthcheck: {path} {code} {}", body.trim());
            1
        }
        Err(e) => {
            eprintln!("xbt-wallet-ui healthcheck: {path}: {e}");
            1
        }
    }
}

fn serve() -> i32 {
    // SIGTERM and SIGINT before the first thread: a stop is answered at once, also as PID 1
    let signals = match xbt_svc::shutdown::listen() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("xbt-wallet-ui: signals: {e}");
            return 2;
        }
    };
    let cfg = match xbt_wallet_ui::config::Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("xbt-wallet-ui: {e}");
            return 2;
        }
    };
    match xbt_wallet_ui::setup::follow_node(&cfg.gw) {
        Ok(true) => eprintln!("xbt-wallet-ui: the gateway's config now names the node at {}", cfg.gw.node_rest.as_deref().unwrap_or("")),
        Ok(false) => {}
        Err(e) => eprintln!("xbt-wallet-ui: the gateway's config was left as it was: {e}"),
    }
    let app = match xbt_wallet_ui::app::App::new(cfg) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("xbt-wallet-ui: {e}");
            return 2;
        }
    };
    if app.cfg.sell {
        let app = app.clone();
        std::thread::spawn(move || {
            // the signer may still be starting: ask for up to two minutes
            for _ in 0..24 {
                match app.refresh_shop_config() {
                    Some("written") => eprintln!("xbt-wallet-ui: the gateway's config was written again for this version"),
                    Some(_) => {}
                    None => {
                        std::thread::sleep(std::time::Duration::from_secs(5));
                        continue;
                    }
                }
                return;
            }
        });
    }
    match xbt_wallet_ui::server::spawn(app.clone()) {
        Ok(r) => {
            eprintln!("xbt-wallet-ui listening on http://{}{} (signer {})", r.addr, app.cfg.base_path, app.cfg.signer_sock.display());
            let sig = signals.wait();
            xbt_svc::shutdown::say_stopping("xbt-wallet-ui", sig);
            let drained = r.finish(xbt_svc::shutdown::DRAIN);
            xbt_svc::shutdown::say_stopped("xbt-wallet-ui", drained);
            0
        }
        Err(e) => {
            eprintln!("xbt-wallet-ui: {e}");
            2
        }
    }
}
