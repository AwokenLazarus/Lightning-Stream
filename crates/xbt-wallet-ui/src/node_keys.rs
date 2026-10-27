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
//! A key that is already there (the owner's own, or one made before) is left alone. Beside the keys,
//! `auto-keys.json` says they came from the box and names their root key ids (no secret), so the
//! pages can say "connected automatically" and how to revoke them.
use std::path::{Path, PathBuf};

use serde_json::json;
use xbt_gateway::node::{bake_macaroon, INFO_OPS, INVOICE_OPS};

use crate::setup::{write_shared, GW_INFO, GW_INVOICES, RAIL_MACAROON, RAIL_OPS};

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
}

impl Settings {
    /// `XBT_KEYS_NODE_REST`, `XBT_KEYS_TLS_CERT`, `XBT_KEYS_ADMIN` (a file or a dir), `XBT_KEYS_RAIL_DIR`,
    /// `XBT_KEYS_GW_DIR`, `XBT_KEYS_GRANT_DIR` (with it, `XBT_KEYS_ADMIN` may be left out).
    pub fn from_env() -> Result<Self, String> {
        let get = |k: &str| std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let rest = get("XBT_KEYS_NODE_REST").ok_or("XBT_KEYS_NODE_REST is not set: this box did not say where its Lightning node is")?;
        let grant = get("XBT_KEYS_GRANT_DIR").map(PathBuf::from);
        let admin = match get("XBT_KEYS_ADMIN") {
            Some(a) => a,
            None if grant.is_some() => String::new(),
            None => return Err("XBT_KEYS_ADMIN is not set: this box gave no node data to read".into()),
        };
        let s = Self {
            rest,
            tls_cert: get("XBT_KEYS_TLS_CERT").map(PathBuf::from),
            admin: PathBuf::from(admin),
            grant,
            rail_dir: get("XBT_KEYS_RAIL_DIR").map(PathBuf::from),
            gw_dir: get("XBT_KEYS_GW_DIR").map(PathBuf::from),
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
        0 => Err(format!("no admin.macaroon under {} yet (is the Lightning node's wallet made and unlocked?)", path.display())),
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
        (&s.gw_dir, &[(GW_INVOICES, &INVOICE_OPS), (GW_INFO, &INFO_OPS)]),
    ];
    for (dir, files) in groups {
        let Some(dir) = dir else { continue };
        if is_off(dir) {
            continue;
        }
        for (file, ops) in files {
            if dir.join(file).is_file() {
                out.kept.push(file.to_string());
                continue;
            }
            let id = root_key_id();
            let mac = bake(ops, id)?;
            write_shared(dir, file, &mac)?;
            record(dir, file, id, ops)?;
            out.made.push(file.to_string());
        }
    }
    Ok(out)
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
    // the node's own grant first: then no admin macaroon is read for what it gave
    let mut granted = Outcome::default();
    take_grants(s, &mut granted)?;
    // nothing to make: the node is not asked and its admin macaroon is not read
    let missing = s.rail_dir.as_ref().is_some_and(|d| !is_off(d) && !d.join(RAIL_MACAROON).is_file())
        || s.gw_dir.as_ref().is_some_and(|d| !is_off(d) && (!d.join(GW_INVOICES).is_file() || !d.join(GW_INFO).is_file()));
    if !missing {
        return Ok(if granted.made.is_empty() && granted.revoked.is_empty() { Outcome { kept: vec!["all".into()], ..Outcome::default() } } else { granted });
    }
    // no admin macaroon given (a grant only): what is still missing is the owner's to paste
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
    let mut out = make_keys(s, &mut |ops, id| bake_macaroon(&s.rest, s.tls_cert.as_deref(), admin, ops, id))?;
    out.made.splice(0..0, granted.made);
    out.revoked = granted.revoked;
    Ok(out)
}

fn read_record(dir: &Path) -> serde_json::Value {
    std::fs::read_to_string(dir.join(AUTO_KEYS)).ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
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
        let s = Settings { rest: "https://node:8080".into(), tls_cert: None, admin: t.path().join("none"), grant: None, rail_dir: Some(rail.clone()), gw_dir: Some(gw.clone()) };
        let mut asked: Vec<(Vec<String>, u64)> = vec![];
        let out = make_keys(&s, &mut |ops, id| {
            asked.push((ops.iter().map(|o| o.to_string()).collect(), id));
            Ok(format!("mac:{}", ops.join(",")).into_bytes())
        }).unwrap();
        assert_eq!(out.made, vec![RAIL_MACAROON, GW_INVOICES, GW_INFO]);
        assert_eq!(asked.iter().map(|(o, _)| o.join(" ")).collect::<Vec<_>>(),
                   vec![RAIL_OPS.join(" "), INVOICE_OPS.join(" "), INFO_OPS.join(" ")]);
        let ids: std::collections::HashSet<u64> = asked.iter().map(|(_, id)| *id).collect();
        assert_eq!(ids.len(), 3, "a root key each");
        assert!(ids.iter().all(|id| *id != 0));
        assert_eq!(std::fs::read(rail.join(RAIL_MACAROON)).unwrap(), format!("mac:{}", RAIL_OPS.join(",")).into_bytes());
        assert!(made_by_box(&rail) && made_by_box(&gw));
        let rec: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(gw.join(AUTO_KEYS)).unwrap()).unwrap();
        assert_eq!(rec[GW_INVOICES]["permissions"], json!(INVOICE_OPS));
        assert!(!std::fs::read_to_string(gw.join(AUTO_KEYS)).unwrap().contains("mac:"), "the record holds no key");
        // a second run: nothing asked, everything kept
        let out = make_keys(&s, &mut |_, _| panic!("asked again")).unwrap();
        assert!(out.made.is_empty());
        assert_eq!(out.kept.len(), 3);
    }

    #[test]
    fn an_owners_own_key_is_never_replaced() {
        let t = tempfile::tempdir().unwrap();
        let rail = shared_dir(t.path(), "ln");
        std::fs::write(rail.join(RAIL_MACAROON), b"owner's").unwrap();
        let s = Settings { rest: "https://node:8080".into(), tls_cert: None, admin: t.path().join("none"), grant: None, rail_dir: Some(rail.clone()), gw_dir: None };
        // nothing missing: the admin macaroon is not even looked for
        assert_eq!(run(&s).unwrap().made, Vec::<String>::new());
        assert_eq!(std::fs::read(rail.join(RAIL_MACAROON)).unwrap(), b"owner's");
        assert!(!made_by_box(&rail));
    }

    #[test]
    fn a_key_the_owner_disconnected_is_not_made_again() {
        let t = tempfile::tempdir().unwrap();
        let rail = shared_dir(t.path(), "ln");
        let s = Settings { rest: "https://node:8080".into(), tls_cert: None, admin: t.path().join("none"), grant: None, rail_dir: Some(rail.clone()), gw_dir: None };
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
        let s = Settings { rest: "https://node:8080".into(), tls_cert: None, admin: PathBuf::new(), grant: Some(grant.clone()),
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
        let s = Settings { rest: "https://node:8080".into(), tls_cert: None, admin: PathBuf::new(), grant: Some(grant.clone()),
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
        let s = Settings { rest: "https://node:8080".into(), tls_cert: None, admin: t.path().join("none"), grant: None, rail_dir: None, gw_dir: Some(gw.clone()) };
        let mut n = 0;
        let e = make_keys(&s, &mut |_, _| {
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
        assert_eq!(out.made, vec![GW_INFO]);
        assert_eq!(out.kept, vec![GW_INVOICES]);
        let rec: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(gw.join(AUTO_KEYS)).unwrap()).unwrap();
        assert!(rec.get(GW_INVOICES).is_some() && rec.get(GW_INFO).is_some());
    }
}
