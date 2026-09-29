//! The data dir's owners and modes (docs/CONTAINER.md §1), and `xbt-init`, the one-shot that makes a
//! data dir match them (AGP-040).
//!
//! A Docker named volume takes its owners from the images' `/data` skeleton. A bind mount does not: an
//! Umbrel `${APP_DATA_DIR}` arrives owned by the box user (1000), and a StartOS volume arrives owned by
//! root. `xbt-init` runs once before the services, as root with only `CHOWN`, `FOWNER` and
//! `DAC_OVERRIDE`, no network, and:
//!
//! * creates `<data>/<component>/` and `<component>/secrets/` (0700) and the socket dirs `run/signer/`
//!   and `run/anchor/` (0750), owned by each component's uid (the same uid as its group);
//! * when a component dir had another owner (a fresh bind mount, or a box that ran everything as 1000),
//!   gives it and everything under it to the component. It never follows a symlink (`lchown`, no descent);
//! * provisions the secrets a box's installer holds: `node-rpc-auth` into `signer/` and `hub/`, the UI
//!   password into `ui/`, and the MCP bearer token, generated once, into `mcp/` and a copy into `ui/`
//!   (the UI's Agents page shows it to the owner). A secret is rewritten only when its value changes;
//!   a generated one never is.
//!
//! It reports what it did as JSON (names, owners and modes; never a secret's value).
use serde_json::{json, Value};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// A component: its sub-dir of the data dir and its uid (= gid).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Component {
    pub name: &'static str,
    pub user: &'static str,
    pub uid: u32,
}

/// agentpay's components (the cmp rows of the table are cmp's to create).
pub const COMPONENTS: &[Component] = &[
    Component { name: crate::SIGNER, user: "xbt-signer", uid: 10001 },
    Component { name: crate::WITNESS, user: "xbt-anchor-witness", uid: 10002 },
    Component { name: crate::MCP, user: "xbt-wallet-mcp", uid: 10003 },
    Component { name: crate::HUB, user: "xbt402-hub", uid: 10004 },
    Component { name: crate::UI, user: "xbt-wallet-ui", uid: 10005 },
];

/// The socket dirs: (dir under `run/`, the component that serves it).
pub const RUN_DIRS: &[(&str, &str)] = &[(crate::RUN_SIGNER, crate::SIGNER), (crate::RUN_ANCHOR, crate::WITNESS)];

pub fn component(name: &str) -> Option<&'static Component> {
    COMPONENTS.iter().find(|c| c.name == name)
}

/// Where each provisioned secret comes from (`xbt-init`'s environment, set by the box's installer).
#[derive(Default, Clone)]
pub struct Provision {
    /// `node-rpc-auth` (`user:password`).
    pub node_rpc_auth: Option<String>,
    /// The UI's login password.
    pub ui_password: Option<String>,
}

impl std::fmt::Debug for Provision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Provision(node_rpc_auth: {}, ui_password: {})", self.node_rpc_auth.is_some(), self.ui_password.is_some())
    }
}

fn file_or_env(file_var: &str, var: &str) -> Result<Option<String>, String> {
    if let Some(p) = crate::env(file_var) {
        let t = std::fs::read_to_string(&p).map_err(|e| format!("{file_var} {p}: {e}"))?;
        return Ok(Some(t.trim_end_matches(['\r', '\n']).to_string()).filter(|t| !t.is_empty()));
    }
    Ok(crate::env(var))
}

impl Provision {
    /// `XBT_INIT_NODE_RPC_AUTH_FILE` / `XBT_INIT_NODE_RPC_AUTH` (`user:password`), or
    /// `XBT_INIT_NODE_RPC_USER` + `XBT_INIT_NODE_RPC_PASS` (Umbrel: a dependency's exports);
    /// `XBT_INIT_UI_PASSWORD_FILE` / `XBT_INIT_UI_PASSWORD` (Umbrel: `${APP_PASSWORD}`).
    ///
    /// These are plain env values on purpose: `xbt-init` is the installer's step, it exits before any
    /// service starts, and the services themselves still read only files (production mode).
    pub fn from_env() -> Result<Self, String> {
        let mut node_rpc_auth = file_or_env("XBT_INIT_NODE_RPC_AUTH_FILE", "XBT_INIT_NODE_RPC_AUTH")?;
        if node_rpc_auth.is_none() {
            if let (Some(u), Some(p)) = (crate::env("XBT_INIT_NODE_RPC_USER"), crate::env("XBT_INIT_NODE_RPC_PASS")) {
                node_rpc_auth = Some(format!("{u}:{p}"));
            }
        }
        if let Some(a) = &node_rpc_auth {
            if !a.contains(':') {
                return Err("the node RPC credentials must be user:password".into());
            }
        }
        let ui_password = file_or_env("XBT_INIT_UI_PASSWORD_FILE", "XBT_INIT_UI_PASSWORD")?;
        if ui_password.as_deref().is_some_and(|p| p.chars().count() < 8) {
            return Err("the UI password is shorter than 8 characters".into());
        }
        Ok(Self { node_rpc_auth, ui_password })
    }
}

#[cfg(unix)]
fn owner_mode(p: &Path) -> io::Result<(u32, u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(p)?;
    Ok((m.uid(), m.gid(), m.mode() & 0o7777))
}

#[cfg(unix)]
fn lchown(p: &Path, uid: u32) -> io::Result<()> {
    std::os::unix::fs::lchown(p, Some(uid), Some(uid))
}

/// Give `dir` and everything under it to `uid`, never following a symlink.
#[cfg(unix)]
fn chown_tree(dir: &Path, uid: u32, changed: &mut u64) -> io::Result<()> {
    let md = std::fs::symlink_metadata(dir)?;
    use std::os::unix::fs::MetadataExt;
    if md.uid() != uid || md.gid() != uid {
        lchown(dir, uid)?;
        *changed += 1;
    }
    if md.file_type().is_dir() {
        for e in std::fs::read_dir(dir)? {
            chown_tree(&e?.path(), uid, changed)?;
        }
    }
    Ok(())
}

/// A directory owned by `uid` with `mode`; created if missing. When its owner was another uid, its
/// contents change owner too (the bind-mount case). Returns a report row.
#[cfg(unix)]
fn own_dir(dir: &Path, uid: u32, mode: u32, recurse: bool) -> Result<Value, String> {
    let ctx = |e: io::Error| format!("{}: {e}", dir.display());
    let created = !dir.exists();
    if created {
        std::fs::create_dir_all(dir).map_err(ctx)?;
    }
    let (u0, g0, m0) = owner_mode(dir).map_err(ctx)?;
    if std::fs::symlink_metadata(dir).map_err(ctx)?.file_type().is_symlink() {
        return Err(format!("{}: is a symlink; refusing", dir.display()));
    }
    let mut changed = 0u64;
    if u0 != uid || g0 != uid {
        if recurse {
            chown_tree(dir, uid, &mut changed).map_err(ctx)?;
        } else {
            lchown(dir, uid).map_err(ctx)?;
            changed = 1;
        }
    }
    if m0 != mode {
        crate::set_mode(dir, mode).map_err(ctx)?;
    }
    Ok(json!({"path": dir.display().to_string(), "uid": uid, "mode": format!("{mode:o}"), "created": created,
              "was": {"uid": u0, "gid": g0, "mode": format!("{m0:o}")}, "chowned": changed}))
}

/// Write a secret owned by `uid`, 0600, only when its value differs. The temp file is created
/// exclusively (never through a symlink a service may have planted) and renamed over the target.
#[cfg(unix)]
fn put_secret(path: &Path, value: &[u8], uid: u32) -> Result<&'static str, String> {
    let ctx = |e: io::Error| format!("{}: {e}", path.display());
    if let Ok(md) = std::fs::symlink_metadata(path) {
        if md.file_type().is_file() && std::fs::read(path).map(|b| b == value).unwrap_or(false) {
            let (u, g, m) = owner_mode(path).map_err(ctx)?;
            if (u, g, m) != (uid, uid, 0o600) {
                lchown(path, uid).map_err(ctx)?;
                crate::set_mode(path, 0o600).map_err(ctx)?;
                return Ok("fixed");
            }
            return Ok("unchanged");
        }
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".xbt-init");
    let tmp = PathBuf::from(tmp);
    let _ = std::fs::remove_file(&tmp);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o.open(&tmp).map_err(ctx)?;
    std::os::unix::fs::fchown(&f, Some(uid), Some(uid)).map_err(ctx)?;
    f.write_all(value).and_then(|_| f.sync_all()).map_err(ctx)?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(ctx)?;
    Ok("written")
}

/// Read a secret file if it is a regular file (not a symlink).
fn read_regular(path: &Path) -> Option<Vec<u8>> {
    let md = std::fs::symlink_metadata(path).ok()?;
    if !md.file_type().is_file() {
        return None;
    }
    std::fs::read(path).ok().filter(|b| !b.is_empty())
}

/// Make `root` match the layout for `names` (component names) and provision the secrets.
#[cfg(unix)]
pub fn init(root: &Path, names: &[String], prov: &Provision) -> Result<Value, String> {
    init_with(root, names, prov, &|c: &Component| c.uid)
}

/// [`init`] with the uids from `uid_of` (tests run it as their own uid).
#[cfg(unix)]
fn init_with(root: &Path, names: &[String], prov: &Provision, uid_of: &dyn Fn(&Component) -> u32) -> Result<Value, String> {
    let comps: Vec<&Component> = names.iter().map(|n| component(n).ok_or_else(|| format!("unknown component {n}"))).collect::<Result<_, _>>()?;
    let has = |n: &str| comps.iter().any(|c| c.name == n);
    if !root.is_dir() {
        std::fs::create_dir_all(root).map_err(|e| format!("{}: {e}", root.display()))?;
    }
    let mut dirs = vec![];
    for c in &comps {
        let d = root.join(c.name);
        dirs.push(own_dir(&d, uid_of(c), 0o700, true)?);
        dirs.push(own_dir(&d.join("secrets"), uid_of(c), 0o700, true)?);
    }
    let run = root.join("run");
    if !run.is_dir() {
        std::fs::create_dir_all(&run).map_err(|e| format!("{}: {e}", run.display()))?;
        crate::set_mode(&run, 0o755).map_err(|e| format!("{}: {e}", run.display()))?;
    }
    for (dir, server) in RUN_DIRS {
        if let Some(c) = comps.iter().find(|c| c.name == *server) {
            dirs.push(own_dir(&run.join(dir), uid_of(c), 0o750, true)?);
        }
    }
    let mut secrets = vec![];
    let mut put = |comp: &str, name: &str, value: &[u8]| -> Result<(), String> {
        let c = component(comp).expect("known");
        let r = put_secret(&root.join(comp).join("secrets").join(name), value, uid_of(c))?;
        secrets.push(json!({"component": comp, "name": name, "result": r}));
        Ok(())
    };
    if let Some(a) = &prov.node_rpc_auth {
        for comp in [crate::SIGNER, crate::HUB] {
            if has(comp) {
                put(comp, "node-rpc-auth", a.as_bytes())?;
            }
        }
    }
    if has(crate::UI) {
        if let Some(p) = &prov.ui_password {
            put(crate::UI, "xbt-ui-password", p.as_bytes())?;
        }
    }
    if has(crate::MCP) {
        let tp = root.join(crate::MCP).join("secrets").join("mcp-http-token");
        let token = match read_regular(&tp) {
            Some(t) => {
                put(crate::MCP, "mcp-http-token", &t)?; // owner and mode only; the value stays
                t
            }
            None => {
                let t = crate::to_hex(&crate::random_bytes(32)).into_bytes();
                put(crate::MCP, "mcp-http-token", &t)?;
                t
            }
        };
        if has(crate::UI) {
            put(crate::UI, "mcp-http-token", &token)?;
        }
    }
    Ok(json!({"ok": true, "root": root.display().to_string(), "dirs": dirs, "secrets": secrets}))
}

/// Check `root` against the layout without changing anything: every component dir and socket dir has
/// its owner and mode, and every file under `secrets/` is 0600 and owned by the component.
#[cfg(unix)]
pub fn check(root: &Path, names: &[String]) -> Value {
    let mut problems = vec![];
    let mut rows = vec![];
    let mut want = |p: PathBuf, uid: u32, mode: u32, problems: &mut Vec<String>| match owner_mode(&p) {
        Ok((u, g, m)) => {
            rows.push(json!({"path": p.display().to_string(), "uid": u, "gid": g, "mode": format!("{m:o}")}));
            if (u, g, m) != (uid, uid, mode) {
                problems.push(format!("{}: {u}:{g} {m:o}, want {uid}:{uid} {mode:o}", p.display()));
            }
        }
        Err(e) => problems.push(format!("{}: {e}", p.display())),
    };
    for n in names {
        let Some(c) = component(n) else {
            problems.push(format!("unknown component {n}"));
            continue;
        };
        let mut want = |p, uid, mode| want(p, uid, mode, &mut problems);
        let d = root.join(c.name);
        want(d.clone(), c.uid, 0o700);
        want(d.join("secrets"), c.uid, 0o700);
        if let Ok(rd) = std::fs::read_dir(d.join("secrets")) {
            for e in rd.flatten() {
                want(e.path(), c.uid, 0o600);
            }
        }
        for (dir, server) in RUN_DIRS {
            if *server == c.name {
                want(root.join("run").join(dir), c.uid, 0o750);
            }
        }
    }
    json!({"ok": problems.is_empty(), "problems": problems, "paths": rows})
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn me() -> u32 {
        std::fs::metadata("/proc/self").map(|m| m.uid()).unwrap_or(0)
    }

    #[test]
    fn table_matches_container_md() {
        let t: Vec<_> = COMPONENTS.iter().map(|c| (c.name, c.uid)).collect();
        assert_eq!(t, vec![("signer", 10001), ("witness", 10002), ("mcp", 10003), ("hub", 10004), ("ui", 10005)]);
    }

    #[test]
    fn provision_needs_user_password() {
        std::env::set_var("XBT_INIT_NODE_RPC_AUTH", "nocolon");
        assert!(Provision::from_env().is_err());
        std::env::remove_var("XBT_INIT_NODE_RPC_AUTH");
        std::env::set_var("XBT_INIT_NODE_RPC_USER", "u");
        std::env::set_var("XBT_INIT_NODE_RPC_PASS", "p");
        assert_eq!(Provision::from_env().unwrap().node_rpc_auth.as_deref(), Some("u:p"));
        std::env::remove_var("XBT_INIT_NODE_RPC_USER");
        std::env::remove_var("XBT_INIT_NODE_RPC_PASS");
        assert!(!format!("{:?}", Provision { node_rpc_auth: Some("u:secret".into()), ui_password: None }).contains("secret"));
    }

    /// As an unprivileged user the chown steps only succeed for our own uid, so run the whole flow as
    /// "every component is me": dirs and modes, secrets, the token copy, idempotence, symlink refusal.
    /// (The real uids are exercised as root by the container tests.)
    #[test]
    fn init_flow_as_own_uid() {
        let uid = me();
        if uid == 0 {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("data");
        // stand-in: the code path is the same with every uid = ours
        let names: Vec<String> = ["signer", "mcp", "ui"].iter().map(|s| s.to_string()).collect();
        let prov = Provision { node_rpc_auth: Some("xbt:pw".into()), ui_password: Some("correct horse".into()) };
        let r = init_as(&root, &names, &prov, uid).unwrap();
        assert_eq!(r["ok"], true);
        let tok = std::fs::read_to_string(root.join("mcp/secrets/mcp-http-token")).unwrap();
        assert_eq!(tok.len(), 64);
        assert_eq!(std::fs::read_to_string(root.join("ui/secrets/mcp-http-token")).unwrap(), tok);
        assert_eq!(std::fs::read_to_string(root.join("signer/secrets/node-rpc-auth")).unwrap(), "xbt:pw");
        assert!(!root.join("hub").exists(), "only the listed components");
        for p in ["signer/secrets/node-rpc-auth", "ui/secrets/xbt-ui-password", "mcp/secrets/mcp-http-token"] {
            assert_eq!(std::fs::metadata(root.join(p)).unwrap().mode() & 0o777, 0o600, "{p}");
        }
        assert_eq!(std::fs::metadata(root.join("run/signer")).unwrap().mode() & 0o777, 0o750);
        // a second run keeps the token and rewrites nothing
        let r2 = init_as(&root, &names, &prov, uid).unwrap();
        assert!(r2["secrets"].as_array().unwrap().iter().all(|s| s["result"] == "unchanged"), "{r2}");
        assert_eq!(std::fs::read_to_string(root.join("mcp/secrets/mcp-http-token")).unwrap(), tok);
        // a changed node password is rewritten; a planted symlink at the temp path is not followed
        let victim = t.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        std::os::unix::fs::symlink(&victim, root.join("signer/secrets/node-rpc-auth.xbt-init")).unwrap();
        let prov2 = Provision { node_rpc_auth: Some("xbt:new".into()), ..prov.clone() };
        init_as(&root, &names, &prov2, uid).unwrap();
        assert_eq!(std::fs::read_to_string(root.join("signer/secrets/node-rpc-auth")).unwrap(), "xbt:new");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        // a component dir that is a symlink is refused
        std::fs::create_dir_all(t.path().join("elsewhere")).unwrap();
        let root2 = t.path().join("data2");
        std::fs::create_dir_all(&root2).unwrap();
        std::os::unix::fs::symlink(t.path().join("elsewhere"), root2.join("signer")).unwrap();
        assert!(init_as(&root2, &["signer".to_string()], &Provision::default(), uid).is_err());
    }

    fn init_as(root: &Path, names: &[String], prov: &Provision, uid: u32) -> Result<Value, String> {
        init_with(root, names, prov, &|_| uid)
    }

    #[test]
    fn check_reports_problems() {
        let t = tempfile::tempdir().unwrap();
        let v = check(t.path(), &["signer".to_string()]);
        assert_eq!(v["ok"], false);
    }
}
