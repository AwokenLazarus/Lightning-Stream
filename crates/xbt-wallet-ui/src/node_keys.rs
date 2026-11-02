//! `xbt-wallet-ui node-keys`: connect the app to the box's own Lightning node with no step by the owner.
//!
//! On a box whose platform gives the app its Lightning node (Umbrel: the Lightning app's data,
//! mounted read-only into this one-shot service only), the node's admin macaroon is read once and
//! used for exactly one kind of call: asking the node to bake the narrow macaroons this app runs
//! with, each under a root key of its own (revocable alone in the node's app). Those are written
//! where the owner's pasted ones would go; the admin macaroon is never written anywhere, and no
//! other service of the app mounts the node's data.
//!
//! | for | permissions | file |
//! |---|---|---|
//! | the wallet's payments | [`RAIL_OPS`] | `<rail dir>/rail.macaroon` |
//! | the gateway, invoices | [`INVOICE_OPS`] | `<gateway dir>/invoices.macaroon` |
//! | the gateway, height | [`INFO_OPS`] | `<gateway dir>/info.macaroon` |
//!
//! Where no platform hands the app the node's data (a plain Linux machine), `XBT_KEYS_ADMIN=-` takes
//! the admin macaroon on standard input instead, read once into memory ([`read_admin`]): the install
//! script pipes the owner's file in, so no file of it is made and no service mounts it.
//!
//! Where the node's own package grants the app its keys (StartOS: Lightning Fork bakes one when the
//! owner approves the app's request, under a root key of its own, and shares it read-only in
//! `apps/<app>/`: `XBT_KEYS_GRANT_DIR`), it is copied from there and no admin macaroon is read:
//!
//! | granted file | becomes |
//! |---|---|
//! | [`GRANT_ACCESS`] (the app's one grant: the wallet's permissions only) | `<rail dir>/rail.macaroon` |
//! | [`GRANT_GATEWAY`] (where the node grants the selling side a key of its own) | `<gateway dir>/invoices.macaroon` and `info.macaroon` |
//!
//! The one grant is never given to the gateway: it can pay, and only the signer may. A granted key the
//! node replaces is copied again; one the owner revoked (its file gone) is removed here too, and the
//! pages say so. With `XBT_KEYS_WATCH_S` the tool keeps watching the grant folder, so a grant the owner
//! approves later is taken without a restart. With neither a grant nor an admin macaroon nothing is
//! made, and the owner pastes the keys on the app's pages.
//!
//! Where the node's data can be read only by the node app's own user (Umbrel: Lightning Fork's
//! directories are its user's alone, 0700, and a missing admin macaroon cannot be mounted as a file
//! before the owner has made the wallet), the work is split in two, and either can start first:
//!
//! * `node-keys-bake` runs as that user (`XBT_KEYS_BAKE_TO`): it waits until the node's admin
//!   macaroon exists, has the node bake the keys missing from the app's dirs (which it reads, never
//!   writes; the sign key too, which a box set up by 0.1.19 lacks), writes them, with their record
//!   first, to a hand-over folder only it and the UI share, and exits;
//! * `node-keys` runs as the UI (`XBT_KEYS_TAKE_FROM`, with `XBT_KEYS_WATCH_S`, no network): it moves
//!   each key from the hand-over folder into its dir, with its root key id, and removes it there. The
//!   hand-over is the node app's user's to write, so a link there is never followed, nothing past
//!   64 KiB is read, and a key moves only with exactly the permissions its file name says. It stops
//!   once every key is in place, or turned off, or one the node would not bake (the baker says so).
//!
//! A key that is already there (the owner's own, or one made before) is left alone. Beside the keys,
//! `auto-keys.json` says they came from the box and names their root key ids (no secret), so the
//! pages can say "connected automatically" and how to revoke them.
use std::path::{Path, PathBuf};

use serde_json::json;
use xbt_gateway::node::{bake_macaroon, checked_macaroon, INFO_OPS, INVOICE_OPS};

use crate::setup::{write_shared, GW_INFO, GW_INVOICES, GW_SIGN, RAIL_MACAROON, RAIL_OPS};

/// What the gateway's sign key holds: lnd's SignMessage and no other call (a URI permission), so it
/// can sign the statement that vouches for its link key and nothing that moves coins.
pub const SIGN_OPS: [&str; 1] = ["uri:/lnrpc.Lightning/SignMessage"];
/// The same key as lnd's entity permission: `message:write` allows SignMessage and no other call. A
/// node app that bakes no URI permissions (Lightning Fork's) makes this one; the Sell page takes either.
pub const SIGN_ENTITY_OPS: [&str; 1] = ["message:write"];

/// The file beside the keys that says they were made by this tool.
pub const AUTO_KEYS: &str = "auto-keys.json";

/// The app's one grant (Lightning Fork's `grant-app-access`): the wallet's key.
pub const GRANT_ACCESS: &str = "access.macaroon";
/// The gateway's own key (invoices and node info), where the node grants one.
pub const GRANT_GATEWAY: &str = "gateway.macaroon";

/// Where to find the node and where the keys go (from the environment: [`Settings::from_env`]).
#[derive(Debug, Clone)]
pub struct Settings {
    /// The node's REST address, `https://host:port`.
    pub rest: String,
    pub tls_cert: Option<PathBuf>,
    /// The node's admin macaroon, or a directory to look for one in (the node's `data/chain`), or
    /// `-`: standard input ([`Settings::admin_on_stdin`]). Empty: none (with a grant dir only).
    pub admin: PathBuf,
    /// The folder the node's package shares granted keys in, read-only; `None`: no grant.
    pub grant: Option<PathBuf>,
    /// The wallet's key dir (`run/ln`); `None`: no wallet key is made.
    pub rail_dir: Option<PathBuf>,
    /// The gateway's key dir (`run/gateway`); `None`: no gateway keys are made.
    pub gw_dir: Option<PathBuf>,
    /// Bake into this hand-over folder rather than into `rail_dir` and `gw_dir`, which are then only
    /// read (what is there, what the owner turned off). `None`: bake into the dirs themselves.
    pub bake_to: Option<PathBuf>,
    /// Take the keys baked into this hand-over folder (moved: removed there once in place); nothing
    /// is baked. `None`: no hand-over.
    pub take_from: Option<PathBuf>,
}

impl Settings {
    /// `XBT_KEYS_NODE_REST`, `XBT_KEYS_TLS_CERT`, `XBT_KEYS_ADMIN` (a file or a dir), `XBT_KEYS_RAIL_DIR`,
    /// `XBT_KEYS_GW_DIR`, `XBT_KEYS_GRANT_DIR` or `XBT_KEYS_TAKE_FROM` (with either, `XBT_KEYS_ADMIN`
    /// may be left out), `XBT_KEYS_BAKE_TO` (with `XBT_KEYS_ADMIN`).
    pub fn from_env() -> Result<Self, String> {
        let get = |k: &str| std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let rest = get("XBT_KEYS_NODE_REST").ok_or("XBT_KEYS_NODE_REST is not set: this box did not say where its Lightning node is")?;
        let grant = get("XBT_KEYS_GRANT_DIR").map(PathBuf::from);
        let bake_to = get("XBT_KEYS_BAKE_TO").map(PathBuf::from);
        let take_from = get("XBT_KEYS_TAKE_FROM").map(PathBuf::from);
        if bake_to.is_some() && (take_from.is_some() || grant.is_some()) {
            return Err("XBT_KEYS_BAKE_TO goes with neither XBT_KEYS_TAKE_FROM nor XBT_KEYS_GRANT_DIR: the baker and the taker are two services".into());
        }
        let admin = match get("XBT_KEYS_ADMIN") {
            Some(_) if take_from.is_some() => return Err("XBT_KEYS_TAKE_FROM reads no admin macaroon: leave XBT_KEYS_ADMIN out".into()),
            Some(a) => a,
            None if grant.is_some() || take_from.is_some() => String::new(),
            None => return Err("XBT_KEYS_ADMIN is not set: this box gave no node data to read".into()),
        };
        let s = Self {
            rest,
            tls_cert: get("XBT_KEYS_TLS_CERT").map(PathBuf::from),
            admin: PathBuf::from(admin),
            grant,
            rail_dir: get("XBT_KEYS_RAIL_DIR").map(PathBuf::from),
            gw_dir: get("XBT_KEYS_GW_DIR").map(PathBuf::from),
            bake_to,
            take_from,
        };
        if s.rail_dir.is_none() && s.gw_dir.is_none() {
            return Err("neither XBT_KEYS_RAIL_DIR nor XBT_KEYS_GW_DIR is set: nothing to make".into());
        }
        Ok(s)
    }
}

impl Settings {
    /// Whether the admin macaroon comes on standard input (`XBT_KEYS_ADMIN=-`).
    pub fn admin_on_stdin(&self) -> bool {
        self.admin.as_os_str() == "-"
    }
}

/// The admin macaroon as it came on standard input: the file's bytes, or the same as hex (what
/// `xxd -p` or a node's dashboard shows), surrounding whitespace ignored.
pub fn read_admin(mut input: impl std::io::Read) -> Result<Vec<u8>, String> {
    let mut b = Vec::new();
    input.read_to_end(&mut b).map_err(|e| format!("standard input: {e}"))?;
    let text = std::str::from_utf8(&b).ok().map(|t| t.split_whitespace().collect::<String>());
    if text.as_deref() == Some("") {
        return Err("no admin macaroon on standard input".into());
    }
    let b = match text.as_deref().map(hex::decode) {
        Some(Ok(h)) if !h.is_empty() => h,
        _ => b,
    };
    if b.is_empty() {
        return Err("no admin macaroon on standard input".into());
    }
    Ok(b)
}

/// The node's admin macaroon: `path` itself, or the one `admin.macaroon` under `path` (searched a
/// few levels down, as lnd keeps it in `data/chain/<chain>/<network>/`). Several networks: the
/// mainnet one; otherwise more than one is an error rather than a guess.
pub fn find_admin(path: &Path) -> Result<PathBuf, String> {
    if path.is_file() {
        return Ok(path.to_path_buf());
    }
    let mut found = vec![];
    let mut dirs = vec![(path.to_path_buf(), 0)];
    while let Some((d, depth)) = dirs.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() && depth < 4 {
                dirs.push((p, depth + 1));
            } else if p.file_name().is_some_and(|n| n == "admin.macaroon") {
                found.push(p);
            }
        }
    }
    found.sort();
    match found.len() {
        0 => Err(format!("no admin.macaroon under {} yet: create your Lightning wallet in Lightning Fork first (Lightning Stream picks it up automatically)", path.display())),
        1 => Ok(found.remove(0)),
        _ => found
            .iter()
            .find(|p| p.components().any(|c| c.as_os_str() == "mainnet"))
            .cloned()
            .ok_or_else(|| format!("several admin.macaroon under {} and none is mainnet's", path.display())),
    }
}

/// A root key id of its own for each key: random, never lnd's default 0.
fn root_key_id() -> u64 {
    u64::from_be_bytes(crate::random_bytes::<8>()) | (1 << 62)
}

/// Asks the node for a macaroon with these permissions under this root key id.
pub type Bake<'a> = dyn FnMut(&[&str], u64) -> Result<Vec<u8>, String> + 'a;

/// [`Bake`] with the node's admin macaroon given (what [`run_with`] does with the one it read).
type BakeWith<'a> = dyn FnMut(&[u8], &[&str], u64) -> Result<Vec<u8>, String> + 'a;

/// A key dir and the files made in it, each with its permissions.
type Group<'a> = (&'a Option<PathBuf>, &'a [(&'a str, &'a [&'a str])]);

/// What one run did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// The files made, by name.
    pub made: Vec<String>,
    /// The files that were there and were left alone.
    pub kept: Vec<String>,
    /// The granted files removed because the node revoked them.
    pub revoked: Vec<String>,
    /// Keys the app can do without that the node would not bake, each with the node's reason: the
    /// app runs without them and the next run asks again.
    pub skipped: Vec<(String, String)>,
}

/// Add `file`'s root key id and permissions to `dir`'s record of the keys this tool made.
fn record(dir: &Path, file: &str, id: u64, ops: &[&str]) -> Result<(), String> {
    let mut rec = read_record(dir);
    rec[file] = json!({"root_key_id": id.to_string(), "permissions": ops,
                       "made_at": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)});
    rec["made_by"] = json!("the app, from this box's own Lightning node");
    write_shared(dir, AUTO_KEYS, format!("{rec:#}\n").as_bytes())
}

/// Make every missing key in each dir, with `bake` (the node's, in [`run`]). Each key is recorded
/// as soon as it is written, so a run stopped half way leaves a true record.
pub fn make_keys(s: &Settings, bake: &mut Bake) -> Result<Outcome, String> {
    let mut out = Outcome::default();
    let groups: [Group; 2] = [
        (&s.rail_dir, &[(RAIL_MACAROON, &RAIL_OPS)]),
        (&s.gw_dir, &[(GW_INVOICES, &INVOICE_OPS), (GW_INFO, &INFO_OPS), (GW_SIGN, &SIGN_OPS)]),
    ];
    for (dir, files) in groups {
        let Some(dir) = dir else { continue };
        if is_off(dir) {
            continue;
        }
        for (file, ops) in files {
            // baked before and not taken yet: the hand-over holds it
            if dir.join(file).is_file() || s.bake_to.as_ref().is_some_and(|h| h.join(file).is_file()) {
                out.kept.push(file.to_string());
                continue;
            }
            let id = root_key_id();
            // the sign key only lets a seller offer a direct link: a node that will not bake it (an
            // older lnd, a node that refuses URI permissions) must not stop the keys the app needs
            let mac = match bake(ops, id) {
                Err(e) if *file == GW_SIGN => {
                    // said in the hand-over too, so the taker does not wait for it forever
                    if let Some(h) = &s.bake_to {
                        let mut r = read_record(h);
                        r[*file] = json!({"skipped": &e});
                        write_shared(h, AUTO_KEYS, format!("{r:#}\n").as_bytes())?;
                    }
                    out.skipped.push((file.to_string(), e));
                    continue;
                }
                r => r?,
            };
            match &s.bake_to {
                // the record first: the taker never finds a key without its root key id
                Some(h) => {
                    record(h, file, id, ops)?;
                    write_shared(h, file, &mac)?;
                }
                None => {
                    write_shared(dir, file, &mac)?;
                    record(dir, file, id, ops)?;
                }
            }
            out.made.push(file.to_string());
        }
    }
    Ok(out)
}

/// The keys each dir takes from the hand-over folder, by name, each with the permissions it must hold.
const HANDED: [(bool, &str, &[&str]); 4] =
    [(true, RAIL_MACAROON, &RAIL_OPS), (false, GW_INVOICES, &INVOICE_OPS), (false, GW_INFO, &INFO_OPS), (false, GW_SIGN, &SIGN_OPS)];

/// Move the keys baked into the hand-over folder ([`Settings::take_from`]) into their dirs, each with
/// its record (root key id, permissions), and remove them there. A dir that already has the key (the
/// owner's own) or that the owner turned off keeps what it has: the baked one is removed, and its
/// root key id is said, so it can be revoked on the node.
///
/// The hand-over is written by the node app's user, so what is there is checked before it moves: a
/// link is never followed (it is removed), and a key moves only with exactly its permissions.
pub fn take_handover(s: &Settings, out: &mut Outcome) -> Result<(), String> {
    let Some(h) = &s.take_from else { return Ok(()) };
    let gone = |src: &Path| std::fs::remove_file(src).map_err(|e| format!("{}: {e}", src.display()));
    for (rail, file, ops) in HANDED {
        let src = h.join(file);
        let Ok(md) = std::fs::symlink_metadata(&src) else { continue };
        if !md.file_type().is_file() {
            gone(src.as_path())?;
            out.skipped.push((file.to_string(), "not a plain file in the hand-over: removed".into()));
            continue;
        }
        // read after the key is seen: the baker writes the record first, so it is there
        let from = read_record(h);
        let dir = if rail { &s.rail_dir } else { &s.gw_dir };
        let mac = match read_nofollow(&src) {
            Ok(m) => m,
            Err(e) => {
                gone(src.as_path())?;
                out.skipped.push((file.to_string(), format!("unreadable, removed: {e}")));
                continue;
            }
        };
        let Some(dir) = dir.as_ref().filter(|d| !is_off(d) && !d.join(file).is_file()) else {
            gone(src.as_path())?;
            // the very key already in place (moved before, its copy left): nothing to revoke
            let same = dir.as_ref().and_then(|d| read_nofollow(&d.join(file)).ok()).is_some_and(|k| k == mac);
            out.skipped.push((file.to_string(), if same { "already in place".into() }
                                                else { format!("not needed here; revoke {} on the node", rec_line(&from, file)) }));
            continue;
        };
        if mac.is_empty() {
            // being written: the next look takes it
            continue;
        }
        // strict on every chain, as the pages are: never the admin key, nor one wider than this file's
        if let Err(e) = checked_macaroon(&mac, file, ops, true) {
            gone(src.as_path())?;
            out.skipped.push((file.to_string(), format!("refused and removed: {e}")));
            continue;
        }
        // the record before the key: a dir never holds a key without its root key id
        let mut rec = read_record(dir);
        rec[file] = from.get(file).cloned().unwrap_or_else(|| json!({}));
        rec["made_by"] = json!("the app, from this box's own Lightning node");
        write_shared(dir, AUTO_KEYS, format!("{rec:#}\n").as_bytes())?;
        write_shared(dir, file, &mac)?;
        gone(src.as_path())?;
        // the owner turned this dir off while the key moved: it does not stay
        if is_off(dir) {
            let _ = std::fs::remove_file(dir.join(file));
            out.skipped.push((file.to_string(), format!("turned off meanwhile: removed; revoke {} on the node", rec_line(&from, file))));
            continue;
        }
        out.made.push(file.to_string());
    }
    Ok(())
}

/// The most a key or a record may hold: lnd's macaroons and these records are far smaller.
const MOST: u64 = 64 << 10;

/// A file of the hand-over or a key dir, read without following a link in its last component, and
/// refused past [`MOST`] bytes.
#[cfg(unix)]
fn read_nofollow(p: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let ctx = |e: std::io::Error| format!("{}: {e}", p.display());
    let f = xbt_svc::layout::open_nofollow(p, false).map_err(ctx)?;
    if !f.metadata().map_err(ctx)?.is_file() {
        return Err(format!("{}: not a plain file", p.display()));
    }
    let mut v = vec![];
    f.take(MOST + 1).read_to_end(&mut v).map_err(ctx)?;
    if v.len() as u64 > MOST {
        return Err(format!("{}: longer than {MOST} bytes", p.display()));
    }
    Ok(v)
}

#[cfg(not(unix))]
fn read_nofollow(p: &Path) -> Result<Vec<u8>, String> {
    let v = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
    if v.len() as u64 > MOST {
        return Err(format!("{}: longer than {MOST} bytes", p.display()));
    }
    Ok(v)
}

/// Whether a dir still lacks a key the hand-over could bring (the taker stops watching once none does).
/// A key the node would not bake (the baker says so in the hand-over's record) is not waited for.
pub fn handover_wanted(s: &Settings) -> bool {
    let said = s.take_from.as_deref().map(read_record).unwrap_or_else(|| json!({}));
    HANDED.iter().any(|(rail, file, _)| {
        let dir = if *rail { &s.rail_dir } else { &s.gw_dir };
        dir.as_ref().is_some_and(|d| !is_off(d) && !d.join(file).is_file()) && said[*file]["skipped"].is_null()
    })
}

fn rec_line(rec: &serde_json::Value, file: &str) -> String {
    match rec[file]["root_key_id"].as_str() {
        Some(id) => format!("root key id {id}"),
        None => "its key (root key id not recorded)".into(),
    }
}

/// Copy the keys the node granted into place: a missing key, or one copied from a grant before
/// that the node has since replaced. A key copied from a grant whose file is gone (the owner revoked
/// it in the node's app) is removed and the record says so. A key the owner pasted or the tool baked
/// is left alone.
pub fn take_grants(s: &Settings, out: &mut Outcome) -> Result<(), String> {
    let Some(grant) = &s.grant else { return Ok(()) };
    let groups: [(&Option<PathBuf>, &str, &[&str]); 2] = [(&s.rail_dir, GRANT_ACCESS, &[RAIL_MACAROON]), (&s.gw_dir, GRANT_GATEWAY, &[GW_INVOICES, GW_INFO])];
    for (dir, name, files) in groups {
        let Some(dir) = dir else { continue };
        if is_off(dir) {
            continue;
        }
        let src = grant.join(name);
        let mac = if src.is_file() { std::fs::read(&src).map_err(|e| format!("{}: {e}", src.display()))? } else { vec![] };
        for file in files {
            let here = dir.join(file);
            let granted_before = read_record(dir)[*file]["source"] == "grant";
            if mac.is_empty() {
                // revoked: the node took its grant back
                if granted_before && here.is_file() {
                    std::fs::remove_file(&here).map_err(|e| format!("{}: {e}", here.display()))?;
                    let mut rec = read_record(dir);
                    rec[*file]["revoked"] = json!(true);
                    write_shared(dir, AUTO_KEYS, format!("{rec:#}\n").as_bytes())?;
                    out.revoked.push(file.to_string());
                }
                continue;
            }
            if here.is_file() && !(granted_before && std::fs::read(&here).ok().as_deref() != Some(&mac[..])) {
                continue;
            }
            write_shared(dir, file, &mac)?;
            let mut rec = read_record(dir);
            rec[*file] = json!({"source": "grant", "from": name,
                                "made_at": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)});
            rec["made_by"] = json!("the Lightning node's own app, granted by the owner");
            write_shared(dir, AUTO_KEYS, format!("{rec:#}\n").as_bytes())?;
            out.made.push(file.to_string());
        }
    }
    Ok(())
}

/// Whether the owner revoked the key the node had granted for `file` in `dir` (for the pages).
pub fn grant_revoked(dir: &Path, file: &str) -> bool {
    read_record(dir)[file]["revoked"] == true && !dir.join(file).is_file()
}

/// Read the admin macaroon and make the missing keys through the node.
pub fn run(s: &Settings) -> Result<Outcome, String> {
    run_with(s, None)
}

/// [`run`], with the admin macaroon given (read from standard input) rather than read from `s.admin`.
pub fn run_with(s: &Settings, given: Option<&[u8]>) -> Result<Outcome, String> {
    run_baking(s, given, &mut |admin, ops, id| bake_macaroon(&s.rest, s.tls_cert.as_deref(), admin, ops, id))
}

/// [`run_with`], the node's bake given (with the admin macaroon read): tests stand in for the node.
fn run_baking(s: &Settings, given: Option<&[u8]>, bake: &mut BakeWith) -> Result<Outcome, String> {
    // the node's own grant first: then no admin macaroon is read for what it gave
    let mut granted = Outcome::default();
    take_grants(s, &mut granted)?;
    take_handover(s, &mut granted)?;
    // nothing to make: the node is not asked and its admin macaroon is not read (a key baked into the
    // hand-over and not taken yet counts as there)
    let there = |d: &Path, f: &str| d.join(f).is_file() || s.bake_to.as_ref().is_some_and(|h| h.join(f).is_file());
    let missing = s.rail_dir.as_ref().is_some_and(|d| !is_off(d) && !there(d, RAIL_MACAROON))
        // the sign key too: a box set up before it existed (0.1.19) has the other two, and its shop's
        // direct link is vouched for only with it
        || s.gw_dir.as_ref().is_some_and(|d| !is_off(d) && [GW_INVOICES, GW_INFO, GW_SIGN].iter().any(|f| !there(d, f)));
    if !missing {
        return Ok(if granted.made.is_empty() && granted.revoked.is_empty() && granted.skipped.is_empty() { Outcome { kept: vec!["all".into()], ..Outcome::default() } } else { granted });
    }
    // no admin macaroon given (a grant or a hand-over only): what is still missing is the owner's to
    // paste, or the baker's to bring
    if given.is_none() && s.admin.as_os_str().is_empty() {
        return Ok(granted);
    }
    let read;
    let admin = match given {
        Some(a) => a,
        None => {
            let path = find_admin(&s.admin)?;
            read = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            &read
        }
    };
    let mut out = make_keys(s, &mut |ops, id| bake(admin, ops, id))?;
    out.made.splice(0..0, granted.made);
    out.revoked = granted.revoked;
    Ok(out)
}

/// A record (`auto-keys.json`): read without following a link and at most [`MOST`] bytes; one that is
/// not there, too long or not a JSON object reads as empty.
fn read_record(dir: &Path) -> serde_json::Value {
    read_nofollow(&dir.join(AUTO_KEYS)).ok()
        .and_then(|t| serde_json::from_slice::<serde_json::Value>(&t).ok())
        .filter(|v| v.is_object()).unwrap_or_else(|| json!({}))
}

/// Whether `dir`'s keys were made by this tool (for the pages).
pub fn made_by_box(dir: &Path) -> bool {
    let r = read_record(dir);
    r.as_object().is_some_and(|o| o.keys().any(|k| k.ends_with(".macaroon"))) && r["off"] != true
}

/// The owner disconnected a key the app made: the next start does not make one again.
pub fn turn_off(dir: &Path) -> Result<(), String> {
    if !dir.join(AUTO_KEYS).is_file() {
        return Ok(());
    }
    let mut r = read_record(dir);
    r["off"] = json!(true);
    write_shared(dir, AUTO_KEYS, format!("{r:#}\n").as_bytes())
}

fn is_off(dir: &Path) -> bool {
    read_record(dir)["off"] == true
}

/// Whether the owner disconnected a key the app made here (for the pages).
pub fn turned_off(dir: &Path) -> bool {
    is_off(dir)
}

/// The owner asks the app to make its key again: the next start makes it (undoes [`turn_off`]).
pub fn turn_on(dir: &Path) -> Result<(), String> {
    let mut r = read_record(dir);
    let Some(o) = r.as_object_mut() else { return Ok(()) };
    if o.remove("off").is_none() {
        return Ok(());
    }
    write_shared(dir, AUTO_KEYS, format!("{r:#}\n").as_bytes())
}

/// The owner removed the key on a box that makes its own (with no record of one made here): the page
/// then says the app makes one at its next start, not "within a minute".
pub fn note_removed(dir: &Path) -> Result<(), String> {
    let mut r = read_record(dir);
    r["removed"] = json!(true);
    write_shared(dir, AUTO_KEYS, format!("{r:#}\n").as_bytes())
}

/// Whether the owner removed a key here (see [`note_removed`]).
pub fn removed(dir: &Path) -> bool {
    read_record(dir)["removed"] == true
}

/// Whether keys were made here before (by this tool), whatever is there now.
pub fn made_before(dir: &Path) -> bool {
    read_record(dir).as_object().is_some_and(|o| o.keys().any(|k| k.ends_with(".macaroon")))
}

/// The root key ids of every key this tool made in `dir` (no secret): what to revoke on the node
/// when the app is uninstalled.
pub fn root_key_ids(dir: &Path) -> Vec<String> {
    let rec = read_record(dir);
    let mut ids: Vec<String> = rec.as_object().into_iter().flatten()
        .filter_map(|(_, v)| v.get("root_key_id").and_then(serde_json::Value::as_str).map(str::to_string)).collect();
    ids.sort();
    ids
}

/// "root key id N", for revoking `file`'s key in the node's app, or a plain word when unknown.
pub fn root_key_line(dir: &Path, file: &str) -> String {
    match read_record(dir)[file]["root_key_id"].as_str() {
        Some(id) => format!("root key id {id}"),
        None => "its root key id is not recorded".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared_dir(root: &Path, name: &str) -> PathBuf {
        let d = root.join(name);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A macaroon lnd would bake with exactly these permissions (`entity:action`, a URI one too).
    fn mac_of(ops: &[&str]) -> Vec<u8> {
        let mut by: Vec<(&str, Vec<&str>)> = vec![];
        for (e, a) in ops.iter().map(|o| o.split_once(':').unwrap()) {
            match by.iter_mut().find(|(x, _)| *x == e) {
                Some((_, v)) => v.push(a),
                None => by.push((e, vec![a])),
            }
        }
        let pairs: Vec<(&str, &[&str])> = by.iter().map(|(e, v)| (*e, v.as_slice())).collect();
        xbt402::macaroon::lnd_macaroon_for_tests(&pairs, &[])
    }

    #[test]
    fn the_admin_macaroon_on_standard_input_is_its_bytes_or_their_hex() {
        assert_eq!(read_admin(&[0x02u8, 0x01, 0xff][..]).unwrap(), vec![0x02, 0x01, 0xff]);
        assert_eq!(read_admin(&b"0201ff\n"[..]).unwrap(), vec![0x02, 0x01, 0xff]);
        assert_eq!(read_admin(&b"  02 01\nff "[..]).unwrap(), vec![0x02, 0x01, 0xff]);
        assert!(read_admin(&b""[..]).is_err());
        assert!(read_admin(&b"\n"[..]).is_err());
    }

    #[test]
    fn the_admin_macaroon_is_found_under_the_nodes_data() {
        let t = tempfile::tempdir().unwrap();
        assert!(find_admin(t.path()).is_err());
        let main = t.path().join("bitcoin/mainnet");
        std::fs::create_dir_all(&main).unwrap();
        std::fs::write(main.join("admin.macaroon"), b"x").unwrap();
        assert_eq!(find_admin(t.path()).unwrap(), main.join("admin.macaroon"));
        let reg = t.path().join("bitcoin/regtest");
        std::fs::create_dir_all(&reg).unwrap();
        std::fs::write(reg.join("admin.macaroon"), b"x").unwrap();
        // two networks: mainnet's
        assert_eq!(find_admin(t.path()).unwrap(), main.join("admin.macaroon"));
        std::fs::remove_file(main.join("admin.macaroon")).unwrap();
        std::fs::write(t.path().join("bitcoin/regtest2.macaroon"), b"x").unwrap();
        assert_eq!(find_admin(t.path()).unwrap(), reg.join("admin.macaroon"));
        // a file is taken as it is
        assert_eq!(find_admin(&reg.join("admin.macaroon")).unwrap(), reg.join("admin.macaroon"));
    }

    #[test]
    fn missing_keys_are_made_each_with_its_own_root_key_and_present_ones_kept() {
        let t = tempfile::tempdir().unwrap();
        let rail = shared_dir(t.path(), "ln");
        let gw = shared_dir(t.path(), "gateway");
        let s = Settings { rest: "https://node:8080".into(), tls_cert: None, admin: t.path().join("none"), grant: None, bake_to: None, take_from: None, rail_dir: Some(rail.clone()), gw_dir: Some(gw.clone()) };
        let mut asked: Vec<(Vec<String>, u64)> = vec![];
        let out = make_keys(&s, &mut |ops, id| {
            asked.push((ops.iter().map(|o| o.to_string()).collect(), id));
            Ok(mac_of(ops))
        }).unwrap();
        assert_eq!(out.made, vec![RAIL_MACAROON, GW_INVOICES, GW_INFO, GW_SIGN]);
        assert_eq!(asked.iter().map(|(o, _)| o.join(" ")).collect::<Vec<_>>(),
                   vec![RAIL_OPS.join(" "), INVOICE_OPS.join(" "), INFO_OPS.join(" "), SIGN_OPS.join(" ")]);
        let ids: std::collections::HashSet<u64> = asked.iter().map(|(_, id)| *id).collect();
        assert_eq!(ids.len(), 4, "a root key each");
        assert!(ids.iter().all(|id| *id != 0));
        assert_eq!(std::fs::read(rail.join(RAIL_MACAROON)).unwrap(), mac_of(&RAIL_OPS));
        assert!(made_by_box(&rail) && made_by_box(&gw));
        let rec: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(gw.join(AUTO_KEYS)).unwrap()).unwrap();
        assert_eq!(rec[GW_INVOICES]["permissions"], json!(INVOICE_OPS));
        assert!(!std::fs::read_to_string(gw.join(AUTO_KEYS)).unwrap().contains("mac:"), "the record holds no key");
        // a second run: nothing asked, everything kept
        let out = make_keys(&s, &mut |_, _| panic!("asked again")).unwrap();
        assert!(out.made.is_empty());
        assert_eq!(out.kept.len(), 4);
    }

    #[test]
    fn an_owners_own_key_is_never_replaced() {
        let t = tempfile::tempdir().unwrap();
        let rail = shared_dir(t.path(), "ln");
        std::fs::write(rail.join(RAIL_MACAROON), b"owner's").unwrap();
        let s = Settings { rest: "https://node:8080".into(), tls_cert: None, admin: t.path().join("none"), grant: None, bake_to: None, take_from: None, rail_dir: Some(rail.clone()), gw_dir: None };
        // nothing missing: the admin macaroon is not even looked for
        assert_eq!(run(&s).unwrap().made, Vec::<String>::new());
        assert_eq!(std::fs::read(rail.join(RAIL_MACAROON)).unwrap(), b"owner's");
        assert!(!made_by_box(&rail));
    }

    #[test]
    fn a_key_the_owner_disconnected_is_not_made_again() {
        let t = tempfile::tempdir().unwrap();
        let rail = shared_dir(t.path(), "ln");
        let s = Settings { rest: "https://node:8080".into(), tls_cert: None, admin: t.path().join("none"), grant: None, bake_to: None, take_from: None, rail_dir: Some(rail.clone()), gw_dir: None };
        make_keys(&s, &mut |_, _| Ok(b"k".to_vec())).unwrap();
        assert!(made_by_box(&rail));
        assert!(root_key_line(&rail, RAIL_MACAROON).starts_with("root key id "));
        std::fs::remove_file(rail.join(RAIL_MACAROON)).unwrap();
        turn_off(&rail).unwrap();
        assert!(!made_by_box(&rail));
        // not asked: the admin macaroon is not even looked for
        assert_eq!(run(&s).unwrap().made, Vec::<String>::new());
        assert!(!rail.join(RAIL_MACAROON).is_file());
    }

    #[test]
    fn the_granted_key_is_the_wallets_only_and_no_admin_macaroon_is_read() {
        let t = tempfile::tempdir().unwrap();
        let rail = shared_dir(t.path(), "ln");
        let gw = shared_dir(t.path(), "gateway");
        let grant = shared_dir(t.path(), "grant");
        let s = Settings { rest: "https://node:8080".into(), tls_cert: None, admin: PathBuf::new(), grant: Some(grant.clone()), bake_to: None, take_from: None,
                           rail_dir: Some(rail.clone()), gw_dir: Some(gw.clone()) };
        // no grant yet and no admin macaroon: nothing made, nothing refused (the owner approves, or pastes)
        assert_eq!(run(&s).unwrap(), Outcome::default());
        std::fs::write(grant.join(GRANT_ACCESS), b"w1").unwrap();
        assert_eq!(run(&s).unwrap().made, vec![RAIL_MACAROON]);
        assert_eq!(std::fs::read(rail.join(RAIL_MACAROON)).unwrap(), b"w1");
        assert!(!gw.join(GW_INVOICES).exists() && !gw.join(GW_INFO).exists(), "the grant can pay: never the gateway's");
        assert!(made_by_box(&rail));
        assert!(root_key_ids(&rail).is_empty(), "a granted key is revoked in the node's own app, not by root key id");
        // the node replaces it (a new grant): copied again; an unchanged one is kept
        std::fs::write(grant.join(GRANT_ACCESS), b"w2").unwrap();
        assert_eq!(run(&s).unwrap().made, vec![RAIL_MACAROON]);
        assert_eq!(std::fs::read(rail.join(RAIL_MACAROON)).unwrap(), b"w2");
        assert!(run(&s).unwrap().made.is_empty());
        // a gateway key of its own, where the node grants one
        std::fs::write(grant.join(GRANT_GATEWAY), b"g1").unwrap();
        assert_eq!(run(&s).unwrap().made, vec![GW_INVOICES, GW_INFO]);
        // the owner revokes it in the node's app: removed here, and the pages can say so
        std::fs::remove_file(grant.join(GRANT_ACCESS)).unwrap();
        assert_eq!(run(&s).unwrap().revoked, vec![RAIL_MACAROON]);
        assert!(!rail.join(RAIL_MACAROON).exists() && grant_revoked(&rail, RAIL_MACAROON));
        // approved again: taken, no longer revoked
        std::fs::write(grant.join(GRANT_ACCESS), b"w3").unwrap();
        assert_eq!(run(&s).unwrap().made, vec![RAIL_MACAROON]);
        assert!(!grant_revoked(&rail, RAIL_MACAROON));
    }

    #[test]
    fn an_owners_own_key_stays_beside_a_grant() {
        let t = tempfile::tempdir().unwrap();
        let rail = shared_dir(t.path(), "ln");
        let grant = shared_dir(t.path(), "grant");
        std::fs::write(rail.join(RAIL_MACAROON), b"owner's").unwrap();
        std::fs::write(grant.join(GRANT_ACCESS), b"granted").unwrap();
        let s = Settings { rest: "https://node:8080".into(), tls_cert: None, admin: PathBuf::new(), grant: Some(grant.clone()), bake_to: None, take_from: None,
                           rail_dir: Some(rail.clone()), gw_dir: None };
        assert!(run(&s).unwrap().made.is_empty());
        assert_eq!(std::fs::read(rail.join(RAIL_MACAROON)).unwrap(), b"owner's");
        // and it is not removed when there is no grant
        std::fs::remove_file(grant.join(GRANT_ACCESS)).unwrap();
        assert!(run(&s).unwrap().revoked.is_empty());
        assert_eq!(std::fs::read(rail.join(RAIL_MACAROON)).unwrap(), b"owner's");
    }

    #[test]
    fn a_refused_bake_writes_nothing() {
        let t = tempfile::tempdir().unwrap();
        let gw = shared_dir(t.path(), "gateway");
        let s = Settings { rest: "https://node:8080".into(), tls_cert: None, admin: t.path().join("none"), grant: None, bake_to: None, take_from: None, rail_dir: None, gw_dir: Some(gw.clone()) };
        let mut n = 0;
        let e = make_keys(&s, &mut |ops, _| {
            if ops == SIGN_OPS {
                return Ok(b"sign".to_vec());
            }
            n += 1;
            if n == 1 { Ok(b"first".to_vec()) } else { Err("permission denied".into()) }
        }).unwrap_err();
        assert!(e.contains("permission denied"));
        assert!(gw.join(GW_INVOICES).is_file());
        assert!(!gw.join(GW_INFO).is_file());
        // the key that was made is recorded; the next run makes only the missing one
        let rec: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(gw.join(AUTO_KEYS)).unwrap()).unwrap();
        assert!(rec.get(GW_INVOICES).is_some() && rec.get(GW_INFO).is_none());
        let out = make_keys(&s, &mut |_, _| Ok(b"second".to_vec())).unwrap();
        assert_eq!(out.made, vec![GW_INFO, GW_SIGN]);
        assert_eq!(out.kept, vec![GW_INVOICES]);
        let rec: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(gw.join(AUTO_KEYS)).unwrap()).unwrap();
        assert!(rec.get(GW_INVOICES).is_some() && rec.get(GW_INFO).is_some());
    }

    #[test]
    fn a_node_that_will_not_bake_the_sign_key_still_gets_the_keys_the_app_needs() {
        let t = tempfile::tempdir().unwrap();
        let gw = shared_dir(t.path(), "gateway");
        let s = Settings { rest: "https://node:8080".into(), tls_cert: None, admin: t.path().join("none"), grant: None, bake_to: None, take_from: None, rail_dir: None, gw_dir: Some(gw.clone()) };
        let out = make_keys(&s, &mut |ops, _| if ops == SIGN_OPS { Err("unknown permission".into()) } else { Ok(b"k".to_vec()) }).unwrap();
        assert_eq!(out.made, vec![GW_INVOICES, GW_INFO]);
        assert_eq!(out.skipped, vec![(GW_SIGN.to_string(), "unknown permission".to_string())]);
        assert!(!gw.join(GW_SIGN).exists());
        // the next run asks again
        let out = make_keys(&s, &mut |_, _| Ok(b"k".to_vec())).unwrap();
        assert_eq!(out.made, vec![GW_SIGN]);
    }

    /// Umbrel: the baker (Lightning Fork's user) writes only the hand-over; the taker (the UI) moves each
    /// key into its dir with its root key id, and the hand-over is left empty.
    #[test]
    fn keys_baked_into_the_hand_over_are_moved_into_place_with_their_record() {
        let t = tempfile::tempdir().unwrap();
        let rail = shared_dir(t.path(), "ln");
        let gw = shared_dir(t.path(), "gateway");
        let h = shared_dir(t.path(), "node-keys");
        let baker = Settings { rest: "https://node:8080".into(), tls_cert: None, admin: t.path().join("node/data/chain"), grant: None,
                               rail_dir: Some(rail.clone()), gw_dir: Some(gw.clone()), bake_to: Some(h.clone()), take_from: None };
        let taker = Settings { admin: PathBuf::new(), bake_to: None, take_from: Some(h.clone()), ..baker.clone() };
        // no wallet yet: the baker says what to do, the taker still wants every key
        let e = run(&baker).unwrap_err();
        assert!(e.contains("create your Lightning wallet in Lightning Fork first"), "{e}");
        assert!(handover_wanted(&taker));
        let mut ids = vec![];
        let out = make_keys(&baker, &mut |ops, id| {
            ids.push(id);
            Ok(mac_of(ops))
        }).unwrap();
        assert_eq!(out.made, vec![RAIL_MACAROON, GW_INVOICES, GW_INFO, GW_SIGN]);
        for f in [RAIL_MACAROON, GW_INVOICES, GW_INFO, GW_SIGN] {
            assert!(h.join(f).is_file() && !rail.join(f).exists() && !gw.join(f).exists(), "{f}: the hand-over only");
        }
        // baked and not taken yet: not baked again, and the admin macaroon is not even looked for
        assert!(make_keys(&baker, &mut |_, _| panic!("baked again")).unwrap().made.is_empty());
        assert_eq!(run(&baker).unwrap().kept, vec!["all"]);
        let mut o = Outcome::default();
        take_handover(&taker, &mut o).unwrap();
        assert_eq!(o.made, vec![RAIL_MACAROON, GW_INVOICES, GW_INFO, GW_SIGN]);
        assert_eq!(std::fs::read(rail.join(RAIL_MACAROON)).unwrap(), mac_of(&RAIL_OPS));
        assert_eq!(std::fs::read(gw.join(GW_SIGN)).unwrap(), mac_of(&SIGN_OPS));
        assert!([RAIL_MACAROON, GW_INVOICES, GW_INFO, GW_SIGN].iter().all(|f| !h.join(f).exists()), "moved, not copied");
        assert!(made_by_box(&rail) && made_by_box(&gw));
        assert_eq!(root_key_line(&rail, RAIL_MACAROON), format!("root key id {}", ids[0]));
        assert_eq!(root_key_ids(&gw), { let mut v: Vec<String> = ids[1..].iter().map(u64::to_string).collect(); v.sort(); v });
        assert!(!handover_wanted(&taker));
        // every key there: the baker has nothing to do
        assert_eq!(run(&baker).unwrap().kept, vec!["all"]);
    }

    /// The owner's own key, or a dir the owner turned off, is never replaced by a baked one: the baker
    /// does not bake it, and one found in the hand-over anyway is removed, with its root key id said.
    #[test]
    fn the_hand_over_never_replaces_an_owners_key_or_a_key_turned_off() {
        let t = tempfile::tempdir().unwrap();
        let rail = shared_dir(t.path(), "ln");
        let gw = shared_dir(t.path(), "gateway");
        let h = shared_dir(t.path(), "node-keys");
        std::fs::write(rail.join(RAIL_MACAROON), b"owner's").unwrap();
        let baker = Settings { rest: "https://node:8080".into(), tls_cert: None, admin: t.path().join("none"), grant: None,
                               rail_dir: Some(rail.clone()), gw_dir: Some(gw.clone()), bake_to: Some(h.clone()), take_from: None };
        let taker = Settings { admin: PathBuf::new(), bake_to: None, take_from: Some(h.clone()), ..baker.clone() };
        let out = make_keys(&baker, &mut |_, _| Ok(b"k".to_vec())).unwrap();
        assert_eq!(out.made, vec![GW_INVOICES, GW_INFO, GW_SIGN]);
        assert!(!h.join(RAIL_MACAROON).exists());
        // one there anyway (made before the owner pasted theirs): removed, the owner's kept
        record(&h, RAIL_MACAROON, 77, &RAIL_OPS).unwrap();
        std::fs::write(h.join(RAIL_MACAROON), b"baked").unwrap();
        // the owner turns the gateway's keys off before they are taken
        write_shared(&gw, AUTO_KEYS, b"{\"off\": true}\n").unwrap();
        let mut o = Outcome::default();
        take_handover(&taker, &mut o).unwrap();
        assert!(o.made.is_empty(), "{o:?}");
        assert_eq!(std::fs::read(rail.join(RAIL_MACAROON)).unwrap(), b"owner's");
        assert!(!gw.join(GW_INVOICES).exists());
        assert_eq!(o.skipped.len(), 4);
        assert!(o.skipped[0].1.contains("root key id 77"), "{:?}", o.skipped);
        assert!(std::fs::read_dir(&h).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().ends_with(".macaroon")), "no key left behind");
        assert!(!handover_wanted(&taker));
    }

    /// The hand-over is written by the node app's user: a link there is removed, never followed (it
    /// could name one of the UI's own files), and a key moves only with exactly its permissions.
    #[cfg(unix)]
    #[test]
    fn the_taker_follows_no_link_and_moves_only_a_narrow_key() {
        let t = tempfile::tempdir().unwrap();
        let rail = shared_dir(t.path(), "ln");
        let gw = shared_dir(t.path(), "gateway");
        let h = shared_dir(t.path(), "node-keys");
        let secret = t.path().join("ui-secret");
        std::fs::write(&secret, b"the UI's own secret").unwrap();
        std::os::unix::fs::symlink(&secret, h.join(RAIL_MACAROON)).unwrap();
        // the node's admin key, or one wider than the file's name says
        std::fs::write(h.join(GW_INVOICES), mac_of(&["invoices:read", "invoices:write", "offchain:write"])).unwrap();
        std::fs::write(h.join(GW_INFO), mac_of(&INFO_OPS)).unwrap();
        let taker = Settings { rest: "https://node:8080".into(), tls_cert: None, admin: PathBuf::new(), grant: None,
                               rail_dir: Some(rail.clone()), gw_dir: Some(gw.clone()), bake_to: None, take_from: Some(h.clone()) };
        let mut o = Outcome::default();
        take_handover(&taker, &mut o).unwrap();
        assert_eq!(o.made, vec![GW_INFO]);
        assert!(!rail.join(RAIL_MACAROON).exists() && !gw.join(GW_INVOICES).exists(), "{o:?}");
        assert_eq!(std::fs::read(&secret).unwrap(), b"the UI's own secret", "the link's target is untouched");
        assert!(std::fs::symlink_metadata(h.join(RAIL_MACAROON)).is_err() && !h.join(GW_INVOICES).exists(), "both removed");
        let why: Vec<&str> = o.skipped.iter().map(|(f, w)| { assert!(f == RAIL_MACAROON || f == GW_INVOICES); w.as_str() }).collect();
        assert!(why.iter().any(|w| w.contains("not a plain file")) && why.iter().any(|w| w.contains("offchain:write")), "{why:?}");
    }

    /// A node that will not bake the sign key: the baker says so in the hand-over, and the taker stops
    /// waiting for it once the other keys are in place.
    #[test]
    fn a_sign_key_the_node_will_not_bake_is_not_waited_for() {
        let t = tempfile::tempdir().unwrap();
        let rail = shared_dir(t.path(), "ln");
        let gw = shared_dir(t.path(), "gateway");
        let h = shared_dir(t.path(), "node-keys");
        let baker = Settings { rest: "https://node:8080".into(), tls_cert: None, admin: t.path().join("none"), grant: None,
                               rail_dir: Some(rail.clone()), gw_dir: Some(gw.clone()), bake_to: Some(h.clone()), take_from: None };
        let taker = Settings { admin: PathBuf::new(), bake_to: None, take_from: Some(h.clone()), ..baker.clone() };
        let out = make_keys(&baker, &mut |ops, _| if ops == SIGN_OPS { Err("unknown permission".into()) } else { Ok(mac_of(ops)) }).unwrap();
        assert_eq!(out.made, vec![RAIL_MACAROON, GW_INVOICES, GW_INFO]);
        let mut o = Outcome::default();
        take_handover(&taker, &mut o).unwrap();
        assert_eq!(o.made, vec![RAIL_MACAROON, GW_INVOICES, GW_INFO]);
        assert!(!gw.join(GW_SIGN).exists());
        assert!(!handover_wanted(&taker), "the taker would watch forever for a key that never comes");
        // a node that bakes it later (the baker's next start): taken then, the skip forgotten
        make_keys(&baker, &mut |ops, _| Ok(mac_of(ops))).unwrap();
        let mut o = Outcome::default();
        take_handover(&taker, &mut o).unwrap();
        assert_eq!(o.made, vec![GW_SIGN]);
    }

    /// A box set up by 0.1.19 has the gateway's invoices and info keys but no sign key: the baker's
    /// start makes the sign key (before, it said "kept all" while the taker waited forever), and the
    /// taker then stops waiting.
    #[test]
    fn an_upgraded_box_without_the_sign_key_gets_one() {
        let t = tempfile::tempdir().unwrap();
        let rail = shared_dir(t.path(), "ln");
        let gw = shared_dir(t.path(), "gateway");
        let h = shared_dir(t.path(), "node-keys");
        let chain = shared_dir(t.path(), "node/data/chain/bitcoin/mainnet");
        std::fs::write(chain.join("admin.macaroon"), b"admin").unwrap();
        // 0.1.19's keys: the rail's and the gateway's two, made by the box
        for (d, f, ops) in [(&rail, RAIL_MACAROON, &RAIL_OPS[..]), (&gw, GW_INVOICES, &INVOICE_OPS[..]), (&gw, GW_INFO, &INFO_OPS[..])] {
            write_shared(d, f, &mac_of(ops)).unwrap();
            record(d, f, 7, ops).unwrap();
        }
        let baker = Settings { rest: "https://node:8080".into(), tls_cert: None, admin: t.path().join("node/data/chain"), grant: None,
                               rail_dir: Some(rail.clone()), gw_dir: Some(gw.clone()), bake_to: Some(h.clone()), take_from: None };
        let taker = Settings { admin: PathBuf::new(), bake_to: None, take_from: Some(h.clone()), ..baker.clone() };
        assert!(handover_wanted(&taker));
        let mut asked: Vec<Vec<String>> = vec![];
        let out = run_baking(&baker, None, &mut |admin, ops, _| {
            assert_eq!(admin, b"admin");
            asked.push(ops.iter().map(|o| o.to_string()).collect());
            Ok(mac_of(ops))
        }).unwrap();
        assert_eq!(out.made, vec![GW_SIGN]);
        assert_eq!(asked, vec![SIGN_OPS.iter().map(|o| o.to_string()).collect::<Vec<_>>()], "only the sign key is baked");
        let mut o = Outcome::default();
        take_handover(&taker, &mut o).unwrap();
        assert_eq!(o.made, vec![GW_SIGN]);
        assert!(!handover_wanted(&taker));
        // and the next start has nothing to make
        assert_eq!(run_baking(&baker, None, &mut |_, _, _| panic!("baked again")).unwrap().kept, vec!["all"]);
    }

    /// A record that is a link, too long, or not JSON reads as empty; the key it sits beside is still
    /// checked and moved, and a key already in place is not called one to revoke.
    #[cfg(unix)]
    #[test]
    fn a_bad_record_reads_as_empty_and_a_key_in_place_is_not_revoked() {
        let t = tempfile::tempdir().unwrap();
        let rail = shared_dir(t.path(), "ln");
        let gw = shared_dir(t.path(), "gateway");
        let h = shared_dir(t.path(), "node-keys");
        std::os::unix::fs::symlink(t.path().join("elsewhere.json"), h.join(AUTO_KEYS)).unwrap();
        std::fs::write(t.path().join("elsewhere.json"), b"{\"rail.macaroon\": {\"root_key_id\": \"1\"}}").unwrap();
        assert_eq!(read_record(&h), json!({}), "a link is not followed");
        std::fs::remove_file(h.join(AUTO_KEYS)).unwrap();
        std::fs::write(h.join(AUTO_KEYS), vec![b' '; (MOST + 1) as usize]).unwrap();
        assert_eq!(read_record(&h), json!({}), "too long");
        let taker = Settings { rest: "https://node:8080".into(), tls_cert: None, admin: PathBuf::new(), grant: None,
                               rail_dir: Some(rail.clone()), gw_dir: Some(gw.clone()), bake_to: None, take_from: Some(h.clone()) };
        let key = mac_of(&RAIL_OPS);
        std::fs::write(h.join(RAIL_MACAROON), &key).unwrap();
        let mut o = Outcome::default();
        take_handover(&taker, &mut o).unwrap();
        assert_eq!(o.made, vec![RAIL_MACAROON]);
        // the same key left in the hand-over again (a move whose removal failed): not one to revoke
        std::fs::write(h.join(RAIL_MACAROON), &key).unwrap();
        let mut o = Outcome::default();
        take_handover(&taker, &mut o).unwrap();
        assert_eq!(o.skipped, vec![(RAIL_MACAROON.to_string(), "already in place".to_string())]);
        assert!(!h.join(RAIL_MACAROON).exists());
    }
}
