//! The B2 signer in Rust.
//!
//!   xbt-signer [--root DIR] [--check]       serve (or, with --check, run every start-up check and exit)
//!   xbt-signer healthcheck [--ready]        the image's HEALTHCHECK: the readiness file is fresh (and ok)
//!   xbt-signer call METHOD [PARAMS_JSON]    one socket request (operator tool), the result on stdout
//!   xbt-signer pin-reset [--root DIR]       a forgotten PIN, with the signer stopped (simple mode, `xbt_signer::pin`)
//!
//! Environment as B2's signer: `B2_ROOT` (policy.json, `.run/`), `B2_DATADIR`, `B2_RPCPORT`, `B2_RPCHOST`,
//! `B2_RPCCOOKIE`, `B2_WALLET`, `B2_CHAIN`, `B2_SIGNER_SOCK` (a path, or `tcp://127.0.0.1:PORT`),
//! `B2_SIGNER_SOCK_MODE`, `B2_HOT_KEYFILE` / `B2_HOT_PASSPHRASE`, `B2_ANCHOR_SOCK`, `B2_WATCH_INTERVAL`,
//! `B2_HOT_SCAN`, and `B2_RENTAL_SOCK`: the hashrate renter's own socket, the only one that pays under a
//! task's rental terms (`xbt_signer::renter`; unset: no caller does).
//!
//! Container mode (AGP-038, `docs/CONTAINER.md`): with `XBT_DATA_DIR` set and neither `--root` nor
//! `B2_ROOT`, the root is `$XBT_DATA_DIR/signer`; the socket is `run/signer/signer.sock` (mode 660), the
//! witness `run/anchor/anchor.sock` (`XBT_ANCHOR=off` to run without one); the policy comes from
//! `XBT_SIGNER_POLICY` (JSON) or `XBT_SIGNER_POLICY_FILE`, else the existing `policy.json`, else a
//! default that pays nobody; the node is `XBT_NODE_RPC_HOST`/`XBT_NODE_RPC_PORT`/`XBT_CHAIN` with
//! the secret `node-rpc-auth`; the wrapping key is the secret `signer-passphrase`, else
//! `signer-wrap-key` (32 bytes, generated 0600 on first run). The signer writes its readiness to
//! `run/signer/ready.json` every `XBT_READY_INTERVAL` seconds (default 5). Where `xbt-init` made
//! `run/rental/` (the hashrate services are installed), the renter's socket is `run/rental/signer.sock`.
//!
//! SIGTERM or SIGINT stops it: no new request, the ones running and the watcher's tick get 5 s to
//! finish, the socket is removed, exit 0.
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use xbt_signer::anchor::AnchorClient;
use xbt_signer::client::SignerClient;
use xbt_signer::keystore::KeyStore;
use xbt_signer::signer::{Signer, SignerOptions};
use xbt_svc::{env, health, DataDir, Mode, Secrets};

fn die(code: i32, msg: impl std::fmt::Display) -> ! {
    eprintln!("xbt-signer: {msg}");
    std::process::exit(code)
}

fn set_default(k: &str, v: impl AsRef<std::ffi::OsStr>) {
    if std::env::var_os(k).is_none() {
        std::env::set_var(k, v);
    }
}

fn ready_interval() -> f64 {
    env("XBT_READY_INTERVAL").and_then(|v| v.parse().ok()).filter(|v: &f64| *v > 0.0).unwrap_or(5.0)
}

fn ready_file() -> Option<PathBuf> {
    env("XBT_SIGNER_READY_FILE").map(PathBuf::from).or_else(|| DataDir::from_env().map(|d| d.signer_ready()))
}

fn sock_path() -> PathBuf {
    env("B2_SIGNER_SOCK").map(PathBuf::from)
        .or_else(|| DataDir::from_env().map(|d| d.signer_sock()))
        .unwrap_or_else(|| PathBuf::from(env("B2_ROOT").unwrap_or_else(|| ".".into())).join(".run").join("signer.sock"))
}

/// A policy that pays nobody until the operator writes one: every limit at B2's defaults, an empty
/// allowlist, never mines.
fn default_policy(anchor_on: bool) -> Value {
    json!({"allowlist": [], "regtest_mine": false, "anchor_required": anchor_on})
}

/// Container mode: the root, the environment defaults, the keystore from the secret source.
fn container_setup(data: &DataDir, mode: Mode) -> Result<(PathBuf, Option<Arc<KeyStore>>), String> {
    let root = data.component(xbt_svc::SIGNER);
    xbt_svc::ensure_dir(&root, 0o700).map_err(|e| format!("{}: {e}", root.display()))?;
    let run = data.run(xbt_svc::RUN_SIGNER);
    xbt_svc::ensure_dir(&run, 0o750).map_err(|e| format!("{}: {e}", run.display()))?;
    set_default("B2_SIGNER_SOCK", data.signer_sock());
    set_default("B2_SIGNER_SOCK_MODE", "660");
    // the hashrate renter's socket, in the dir xbt-init made for it (its group keeps every other caller out): only
    // where that dir is there and closed to everyone else, never one made here (a bind mount's host folder that
    // no init made its own is root's, 0755)
    // (an operator's own B2_RENTAL_SOCK stands, and is said where it is bound)
    let renter_dir = data.run(xbt_svc::RUN_RENTAL);
    if env("B2_RENTAL_SOCK").is_some() || renter_dir_closed(&renter_dir) {
        set_default("B2_RENTAL_SOCK", data.rental_sock());
    } else if renter_dir.exists() {
        eprintln!("xbt-signer: no hashrate renter's socket: {} is not a directory closed to other users (xbt-init makes it 0750): \
                   rentals are refused until it is", renter_dir.display());
    } else {
        eprintln!("xbt-signer: no hashrate renter's socket: {} is missing (xbt-init makes it where the hashrate services are installed): \
                   rentals are refused", renter_dir.display());
    }
    let anchor_on = !matches!(env("XBT_ANCHOR").map(|v| v.to_ascii_lowercase()).as_deref(), Some("off" | "0" | "false" | "no"));
    if anchor_on {
        set_default("B2_ANCHOR_SOCK", data.anchor_sock());
    }
    for (from, to) in [("XBT_NODE_RPC_HOST", "B2_RPCHOST"), ("XBT_NODE_RPC_PORT", "B2_RPCPORT"), ("XBT_CHAIN", "B2_CHAIN"),
                       ("XBT_NODE_WALLET", "B2_WALLET")] {
        if let Some(v) = env(from) {
            set_default(to, v);
        }
    }
    // the policy: env JSON (authoritative, rewritten when it changes), a file, the existing one, a default
    let policy_path = root.join("policy.json");
    let given = match (env("XBT_SIGNER_POLICY"), env("XBT_SIGNER_POLICY_FILE")) {
        (Some(j), _) => Some(j),
        (None, Some(f)) => Some(std::fs::read_to_string(&f).map_err(|e| format!("XBT_SIGNER_POLICY_FILE {f}: {e}"))?),
        (None, None) => None,
    };
    let policy = match given {
        Some(text) => {
            let v: Value = serde_json::from_str(&text).map_err(|e| format!("XBT_SIGNER_POLICY: {e}"))?;
            v.is_object().then_some(v).ok_or("XBT_SIGNER_POLICY: not a JSON object")?
        }
        None if policy_path.exists() => Value::Null,
        None => default_policy(anchor_on),
    };
    if !policy.is_null() {
        let text = serde_json::to_string_pretty(&policy).unwrap_or_default();
        if std::fs::read_to_string(&policy_path).ok().as_deref() != Some(text.as_str()) {
            xbt_svc::write_atomic(&policy_path, text.as_bytes(), 0o600).map_err(|e| format!("{}: {e}", policy_path.display()))?;
            eprintln!("xbt-signer: wrote {}", policy_path.display());
        }
    }
    let secrets = Secrets::for_component(Some(data), xbt_svc::SIGNER, mode);
    if env("B2_RPCCOOKIE").is_none() {
        if let Some(s) = secrets.get("node-rpc-auth")? {
            let p = s.origin.path().ok_or("secret node-rpc-auth must be a file (it is read on every RPC call)")?;
            std::env::set_var("B2_RPCCOOKIE", p);
        }
    }
    keystore(&secrets).map(|k| (root, k))
}

/// Whether `dir` is a directory the world can't enter: the renter's socket dir as xbt-init leaves it (0750).
fn renter_dir_closed(dir: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir() && m.permissions().mode() & 0o007 == 0)
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        false
    }
}

/// The wrapping key: `B2_HOT_KEYFILE` (a path) as before; else the secret `signer-passphrase`; else
/// `signer-wrap-key`, generated on first run. Production refuses a passphrase or plaintext by env.
fn keystore(secrets: &Secrets) -> Result<Option<Arc<KeyStore>>, String> {
    if env("B2_HOT_KEYFILE").is_some() || env("B2_HOT_PASSPHRASE").is_some() {
        return Ok(None);
    }
    if let Some(pw) = secrets.get("signer-passphrase")? {
        eprintln!("xbt-signer: wrapping key from the passphrase ({})", pw.origin);
        return Ok(Some(Arc::new(KeyStore::with_passphrase(pw.text()?.as_bytes()))));
    }
    let k = secrets.get_or_create("signer-wrap-key", || xbt_svc::random_bytes(32))?;
    let key: [u8; 32] = match k.bytes.len() {
        32 => k.bytes.as_slice().try_into().map_err(|_| "signer-wrap-key")?,
        _ => {
            let t = k.text()?;
            let b: Vec<u8> = (0..t.len()).step_by(2).filter_map(|i| t.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok())).collect();
            b.as_slice().try_into().ok().filter(|_| t.len() == 64)
                .ok_or_else(|| format!("signer-wrap-key ({}) must hold 32 bytes (raw or 64 hex chars)", k.origin))?
        }
    };
    eprintln!("xbt-signer: wrapping key from {}", k.origin);
    Ok(Some(Arc::new(KeyStore::with_key(key))))
}

/// What the readiness document says of the node and the witness, as last asked. Asked on a thread of its own
/// ([`probe`]): a node slow to answer (a sync on a slow disk keeps `getblockchaininfo` waiting past the
/// RPC timeout) must not keep the document from being written, or the file goes stale and the platform takes the
/// signer for dead and restarts everything that waits on it (StartOS did, every 30 s, for a whole sync).
#[derive(Clone)]
struct Probed {
    node: Value,
    witness: Value,
    at: std::time::Instant,
}

fn probe(signer: &Signer) -> Probed {
    let node = health::node_status(signer.node.call("getblockchaininfo", json!([])).map_err(|e| e.msg));
    let witness = match env("B2_ANCHOR_SOCK") {
        Some(p) => match AnchorClient::new(Path::new(&p)).latest() {
            Ok(_) => json!({"enabled": true, "reachable": true}),
            Err(e) => json!({"enabled": true, "reachable": false, "error": e.msg}),
        },
        None => json!({"enabled": false, "reachable": false}),
    };
    Probed { node, witness, at: std::time::Instant::now() }
}

/// The node and witness as the document says them: the last answer, or, when it is older than `max_age` (the
/// node has not answered since), not reachable, with how long it has been. None asked yet: not reachable either.
fn probed_now(last: Option<&Probed>, max_age: Duration) -> (Value, Value) {
    match last {
        Some(p) if p.at.elapsed() <= max_age => (p.node.clone(), p.witness.clone()),
        Some(p) => {
            let secs = p.at.elapsed().as_secs();
            (json!({"reachable": false, "synced": false, "sync_pct": p.node["sync_pct"].clone(),
                    "error": format!("the node has not answered for {secs} s (it may be busy syncing)")}), p.witness.clone())
        }
        None => (json!({"reachable": false, "synced": false, "sync_pct": 0.0, "error": "the node has not answered yet"}),
                 json!({"enabled": env("B2_ANCHOR_SOCK").is_some(), "reachable": false})),
    }
}

/// The readiness document: node reachable and synced, keys unlocked, witness reachable (when
/// anchoring is on), the socket answering. The node and witness come from the probe thread's last answer.
fn readiness(signer: &Signer, sock: &Path, node: Value, witness: Value) -> Value {
    // the socket's own health answer needs no node; a short timeout keeps a wedged server from holding the writer
    let mut client = SignerClient::new(sock);
    client.timeout = Duration::from_secs(3);
    let socket = client.call("health", json!({})).map(|h| h["ok"] == true).unwrap_or(false);
    // the signer only starts with its keys opened (sealed hot key, channel keys)
    let unlocked = signer.keystore.is_some() || KeyStore::plaintext_allowed();
    let ok = node["reachable"] == true && node["synced"] == true && unlocked && socket
        && (witness["enabled"] == false || witness["reachable"] == true);
    json!({"ok": ok, "service": "xbt-signer", "node": node, "unlocked": unlocked,
           "keystore": signer.keystore.as_ref().map(|k| k.kind()).unwrap_or("plaintext"), "witness": witness, "socket": socket,
           "chain": signer.chain, "pid": std::process::id()})
}

fn healthcheck(args: &[String]) -> ! {
    let Some(path) = ready_file() else { die(2, "no readiness file: set XBT_DATA_DIR or XBT_SIGNER_READY_FILE") };
    match health::read_ready(&path, Duration::from_secs_f64(ready_interval() * 3.0 + 5.0)) {
        Ok(v) => {
            println!("{v}");
            let want_ready = args.iter().any(|a| a == "--ready");
            std::process::exit(if !want_ready || v["ok"] == true { 0 } else { 1 })
        }
        Err(e) => die(1, e),
    }
}

fn call(args: &[String]) -> ! {
    let Some(method) = args.first() else { die(2, "usage: xbt-signer call METHOD [PARAMS_JSON]") };
    let params: Value = match args.get(1) {
        Some(p) => serde_json::from_str(p).unwrap_or_else(|e| die(2, format!("params: {e}"))),
        None => json!({}),
    };
    match SignerClient::new(&sock_path()).call(method, params) {
        Ok(v) => {
            println!("{v}");
            std::process::exit(0)
        }
        Err(e) => die(1, format!("{}: {}", e.code, e.msg)),
    }
}

/// `xbt-signer pin-reset [--root DIR]`: a forgotten PIN, reset on the box with the signer stopped
/// ([`xbt_signer::pin::reset_offline`]); the next start shows a new enrolment code to set a new PIN with.
fn pin_reset(args: &[String]) -> ! {
    let root = match args {
        [flag, r] if flag == "--root" => PathBuf::from(r),
        [] => env("B2_ROOT").map(PathBuf::from).or_else(|| DataDir::from_env().map(|d| d.component(xbt_svc::SIGNER)))
            .unwrap_or_else(|| die(2, "usage: xbt-signer pin-reset [--root DIR] (or set B2_ROOT or XBT_DATA_DIR)")),
        _ => die(2, "usage: xbt-signer pin-reset [--root DIR]"),
    };
    match xbt_signer::pin::reset_offline(&root, &root.join(".run")) {
        Ok(said) => {
            println!("{said}");
            std::process::exit(0)
        }
        Err(e) => die(1, format!("{}: {}", e.code, e.msg)),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("healthcheck") => healthcheck(&args[1..]),
        Some("call") => call(&args[1..]),
        Some("pin-reset") => pin_reset(&args[1..]),
        _ => {}
    }
    let mut root = env("B2_ROOT").map(PathBuf::from);
    let mut check = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--root" => {
                i += 1;
                root = Some(PathBuf::from(args.get(i).cloned().unwrap_or_default()));
            }
            "--check" => check = true,
            "-h" | "--help" => {
                println!("{}", include_str!("xbt-signer.rs").lines().take_while(|l| l.starts_with("//!"))
                    .map(|l| l.trim_start_matches("//!").trim_start_matches(' ')).collect::<Vec<_>>().join("\n"));
                return;
            }
            other => die(2, format!("unknown argument {other}")),
        }
        i += 1;
    }
    let mode = Mode::from_env().unwrap_or_else(|e| die(2, e));
    if mode.is_production() {
        if env("B2_HOT_PASSPHRASE").is_some() {
            die(1, "refusing to start: B2_HOT_PASSPHRASE is a plain env secret, refused in production mode: use the secret \
                    signer-passphrase (XBT_SECRET_SIGNER_PASSPHRASE_FILE, $CREDENTIALS_DIRECTORY or the data dir)");
        }
        if KeyStore::plaintext_allowed() {
            die(1, "refusing to start: B2_HOT_ALLOW_PLAINTEXT is for tests, refused in production mode");
        }
    }
    // SIGTERM and SIGINT before the first thread (the signer starts some as it opens): a stop is
    // answered at once, also as PID 1 (xbt_svc::shutdown)
    let signals = if check { xbt_svc::shutdown::Signals::none() } else { xbt_svc::shutdown::listen().unwrap_or_else(|e| die(1, format!("signals: {e}"))) };
    let data = DataDir::from_env();
    let mut opts = SignerOptions::default();
    let root = match (root, &data) {
        (Some(r), _) => r,
        (None, Some(d)) => {
            let (r, ks) = container_setup(d, mode).unwrap_or_else(|e| die(1, format!("refusing to start: {e}")));
            opts.keystore = ks;
            r
        }
        (None, None) => PathBuf::from("."),
    };
    let signer = match Signer::new(&root, opts) {
        Ok(s) => s,
        Err(e) => die(1, format!("refusing to start: {}: {}", e.code, e.msg)),
    };
    if check {
        match signer.handle("health", &json!({})) {
            Ok(h) => println!("{h}"),
            Err(e) => die(1, e.msg),
        }
        return;
    }
    if let Some(path) = ready_file() {
        let (s, sock) = (signer.clone(), signer.sock_path.clone());
        let every = Duration::from_secs_f64(ready_interval());
        let last: Arc<std::sync::Mutex<Option<Probed>>> = Arc::default();
        // the node and the witness, asked on their own thread: the writer below never waits for them
        let (ps, pl) = (signer.clone(), last.clone());
        std::thread::Builder::new().name("readiness-probe".into()).spawn(move || loop {
            let p = probe(&ps);
            *pl.lock().unwrap_or_else(|e| e.into_inner()) = Some(p);
            std::thread::sleep(every);
        }).unwrap_or_else(|e| die(1, e));
        // an answer older than this is no answer: the same age at which a reader takes the file for stale
        let max_age = Duration::from_secs_f64(ready_interval() * 3.0 + 5.0);
        std::thread::Builder::new().name("readiness".into()).spawn(move || loop {
            // the socket binds right after this thread starts: give it a moment on the first round
            std::thread::sleep(Duration::from_millis(200));
            let held = last.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let (node, witness) = probed_now(held.as_ref(), max_age);
            if let Err(e) = health::write_ready(&path, &readiness(&s, &sock, node, witness)) {
                eprintln!("xbt-signer: readiness file {}: {e}", path.display());
            }
            std::thread::sleep(every);
        }).unwrap_or_else(|e| die(1, e));
    }
    if let Err(e) = xbt_signer::server::serve(signer, signals) {
        die(1, e.msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probed(age: Duration) -> Probed {
        let at = std::time::Instant::now().checked_sub(age).expect("a monotonic clock that old");
        Probed { node: json!({"reachable": true, "synced": false, "sync_pct": 41.5, "blocks": 400_000}),
                 witness: json!({"enabled": false, "reachable": false}), at }
    }

    #[test]
    fn a_fresh_answer_is_said_as_it_came() {
        let (node, witness) = probed_now(Some(&probed(Duration::from_secs(2))), Duration::from_secs(20));
        assert_eq!(node["reachable"], true);
        assert_eq!(node["blocks"], 400_000);
        assert_eq!(witness["enabled"], false);
    }

    #[test]
    fn a_node_that_stopped_answering_is_not_reachable_but_the_document_is_still_written() {
        // a sync on a slow disk: the last answer is 45 s old, past the 20 s a reader allows
        let (node, _) = probed_now(Some(&probed(Duration::from_secs(45))), Duration::from_secs(20));
        assert_eq!(node["reachable"], false);
        assert_eq!(node["synced"], false);
        assert_eq!(node["sync_pct"], 41.5, "the last progress known is kept");
        assert!(node["error"].as_str().unwrap().contains("has not answered for 45 s"), "{node}");
    }

    #[test]
    fn no_answer_yet_is_not_reachable() {
        let (node, _) = probed_now(None, Duration::from_secs(20));
        assert_eq!(node["reachable"], false);
        assert_eq!(node["error"], "the node has not answered yet");
    }
}
