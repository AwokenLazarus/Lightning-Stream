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
//! * provisions the secrets a box's installer holds: `node-rpc-auth` into `signer/`, the UI
//!   password into `ui/`, and the MCP bearer token, generated once. With the UI (a box), the token is
//!   `run/ui/mcp-http-token`: owned by the UI (uid 10005), 0640, in `run/ui/` (0750), and the MCP reads it
//!   through the `xbt-wallet-ui` group. Only the UI can replace it (the Agents page rotates it); the MCP
//!   has no way to (AGP-042). An older layout's copies (`mcp/secrets/`, `ui/secrets/`) are moved there
//!   once and removed. Without the UI, the token stays `mcp/secrets/mcp-http-token`. A secret is
//!   rewritten only when its value changes; a generated one never is.
//!
//! * with the Stream Gateway (`datum`) and the UI: writes the node's RPC credentials to
//!   `run/datum/rpc.cookie` (`user:password`, no newline, 0600, the gateway's), which its config names as
//!   `bitcoind.rpccookiefile`, and makes `datum/submitblocks/`. The config the UI writes beside it holds no secret.
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

/// agentpay's components (the cmp rows of the table are cmp's to create). uid 10004 was the
/// retired hub's and is not given to another component.
pub const COMPONENTS: &[Component] = &[
    Component { name: crate::SIGNER, user: "xbt-signer", uid: 10001 },
    Component { name: crate::WITNESS, user: "xbt-anchor-witness", uid: 10002 },
    Component { name: crate::MCP, user: "xbt-wallet-mcp", uid: 10003 },
    Component { name: crate::UI, user: "xbt-wallet-ui", uid: 10005 },
    Component { name: crate::RELAY, user: "xbt-work-relay", uid: 10006 },
    Component { name: crate::GATEWAY, user: "xbt-gateway", uid: 10007 },
    Component { name: crate::HASHRATE, user: "xbt-hashrate", uid: 10010 },
    Component { name: crate::STREAM_RELAY, user: "xbt-stream-relay", uid: STREAM_RELAY_UID },
    Component { name: crate::VPN, user: "xbt-vpn", uid: VPN_UID },
    Component { name: crate::DATUM, user: "xbt-datum", uid: DATUM_UID },
];

/// The group of the wallet's Lightning rail files (`run/ln/`): the signer is its only member, so the
/// MCP (in the signer's and the UI's groups) cannot read the rail macaroon.
pub const LN_RAIL_GID: u32 = 10008;
/// The group of the enrolment code's copy (`run/enroll/`): the signer and the UI, never the MCP.
pub const ENROLL_GID: u32 = 10009;

/// A dir under `run/` that one component writes and another reads by group, made only when both are
/// in the layout. The writer is a member of the group too (the images' /etc/group) and gives each
/// file it writes there the dir's group. No setgid bit: `xbt-init` has no CAP_FSETID, and the kernel
/// clears that bit when such a process sets the mode of a dir whose group it is not in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedDir {
    pub dir: &'static str,
    /// The component that writes (owner).
    pub writer: &'static str,
    /// The component that reads, by group.
    pub reader: &'static str,
    pub gid: u32,
    pub mode: u32,
}

/// The UI's setup pages write here: the wallet's rail macaroon for the signer (`run/ln/`), and the
/// gateway's config and macaroons for the gateway (`run/gateway/`). The signer writes the copy of
/// its enrolment code for the UI in `run/enroll/`.
pub const SHARED_DIRS: &[SharedDir] = &[
    SharedDir { dir: crate::RUN_LN, writer: crate::UI, reader: crate::SIGNER, gid: LN_RAIL_GID, mode: 0o750 },
    SharedDir { dir: crate::RUN_GATEWAY, writer: crate::UI, reader: crate::GATEWAY, gid: 10007, mode: 0o750 },
    SharedDir { dir: crate::RUN_ENROLL, writer: crate::SIGNER, reader: crate::UI, gid: ENROLL_GID, mode: 0o750 },
    SharedDir { dir: crate::RUN_HASHRATE, writer: crate::UI, reader: crate::HASHRATE, gid: HASHRATE_GID, mode: 0o750 },
    // the signer's socket for the hashrate renter alone: the one way to a task's rental terms. The hashrate
    // services' group (the renter, and the UI) reaches it; the MCP, in the signer's group, does not
    SharedDir { dir: crate::RUN_RENTAL, writer: crate::SIGNER, reader: crate::HASHRATE, gid: HASHRATE_GID, mode: 0o750 },
    // public data only (receipt keys, signed transport documents): read by the signer's group
    SharedDir { dir: crate::RUN_SHOPS, writer: crate::UI, reader: crate::SIGNER, gid: SHOPS_GID, mode: 0o750 },
    // the built-in Stream relay: the owner's settings in, its status out
    SharedDir { dir: crate::RUN_RELAY, writer: crate::UI, reader: crate::STREAM_RELAY, gid: STREAM_RELAY_UID, mode: 0o750 },
    SharedDir { dir: crate::RUN_RELAY_STATUS, writer: crate::STREAM_RELAY, reader: crate::UI, gid: RELAY_STATUS_GID, mode: 0o750 },
    // the VPN service: the devices and exit the owner sets in, its status out
    SharedDir { dir: crate::RUN_VPN, writer: crate::UI, reader: crate::VPN, gid: VPN_UID, mode: 0o750 },
    SharedDir { dir: crate::RUN_VPN_STATUS, writer: crate::VPN, reader: crate::UI, gid: VPN_STATUS_GID, mode: 0o750 },
    // both write here: the credential store is booked by the endpoint and edited by the UI's AI page
    SharedDir { dir: crate::RUN_AI, writer: crate::UI, reader: crate::SIGNER, gid: AI_GID, mode: 0o770 },
    // the stream sockets: the VPN service makes the socket each paid tunnel is streamed to here, and the
    // signer (whose dir it is) connects to it. Only where the VPN is installed; else the signer's alone (0750)
    SharedDir { dir: crate::RUN_STREAMS, writer: crate::SIGNER, reader: crate::VPN, gid: STREAMS_GID, mode: 0o770 },
    // the Stream Gateway: its config the UI's Hashrate page writes (no secret in it), and the node's RPC
    // cookie init writes there (the gateway's own, 0600)
    SharedDir { dir: crate::RUN_DATUM, writer: crate::UI, reader: crate::DATUM, gid: DATUM_UID, mode: 0o750 },
];

/// A group only: the signer and the VPN service, for the stream sockets' dir (`run/signer/streams`).
pub const STREAMS_GID: u32 = 10020;

/// Whether `dir` is a shared dir with both its writer and its reader installed (its owners and mode
/// are then the shared dir's, not a socket dir's).
fn shared_here(dir: &str, has: &dyn Fn(&str) -> bool) -> bool {
    SHARED_DIRS.iter().any(|sd| sd.dir == dir && has(sd.writer) && has(sd.reader))
}

/// The built-in Stream relay's user and group (10011 to 10013 are xbt-compute's, 10014 is the AI
/// endpoint's group).
pub const STREAM_RELAY_UID: u32 = 10016;
/// A group only: the relay and the UI, for the relay's status file.
pub const RELAY_STATUS_GID: u32 = 10017;
/// The VPN service's user and group.
pub const VPN_UID: u32 = 10018;
/// A group only: the VPN service and the UI, for the service's status files.
pub const VPN_STATUS_GID: u32 = 10019;
/// The Stream Gateway's user and group (10020 is reserved for cmp's knots-xbt).
pub const DATUM_UID: u32 = 10021;
/// The node RPC cookie's mode: the gateway's alone.
pub const DATUM_COOKIE_MODE: u32 = 0o600;

/// The group `run/shops/` is read by: the signer's own, whose user the connector runs as and whose
/// group the MCP is in.
pub const SHOPS_GID: u32 = 10001;

/// The AI endpoint's group (a group only): the UI and the signer's user, which the connector runs as.
pub const AI_GID: u32 = 10014;

/// The hashrate services' group: the settings the UI writes in `run/hashrate/`, and their control token.
pub const HASHRATE_GID: u32 = 10010;
/// The control token of the hashrate services, in `run/hashrate/`: the UI owns it and calls them with
/// it; they read it by group (0640). Made once by init.
pub const HASHRATE_TOKEN: &str = "control-token";

/// The socket dirs: (dir under `run/`, the component that serves it).
/// `signer/streams` comes after `signer`: a platform that mounts it on its own (to share it with the
/// connector) makes it owned by root before init runs, and init gives it back to the signer.
pub const RUN_DIRS: &[(&str, &str)] =
    &[(crate::RUN_SIGNER, crate::SIGNER), (crate::RUN_STREAMS, crate::SIGNER), (crate::RUN_ANCHOR, crate::WITNESS), (crate::RUN_UI, crate::UI)];

/// The shared MCP token's mode: the UI reads and writes it, the MCP (in the UI's group) reads it.
pub const MCP_TOKEN_MODE: u32 = 0o640;

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
    /// Umbrel: the Lightning app's uid, which owns `run/node-keys/` (the hand-over of the keys its
    /// node bakes, shared with the UI by group, 0770). `None`: no hand-over folder.
    pub node_keys_uid: Option<u32>,
}

impl std::fmt::Debug for Provision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Provision(node_rpc_auth: {}, ui_password: {}, node_keys_uid: {:?})", self.node_rpc_auth.is_some(), self.ui_password.is_some(), self.node_keys_uid)
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
    /// `XBT_INIT_UI_PASSWORD_FILE` / `XBT_INIT_UI_PASSWORD` (Umbrel: `${APP_PASSWORD}`);
    /// `XBT_INIT_NODE_KEYS_UID` (Umbrel: the Lightning app's user, 1000).
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
        let node_keys_uid = match crate::env("XBT_INIT_NODE_KEYS_UID") {
            Some(u) => Some(u.parse::<u32>().ok().filter(|u| *u != 0).ok_or("XBT_INIT_NODE_KEYS_UID must be a uid other than root's")?),
            None => None,
        };
        Ok(Self { node_rpc_auth, ui_password, node_keys_uid })
    }
}

#[cfg(unix)]
fn owner_mode(p: &Path) -> io::Result<(u32, u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(p)?;
    Ok((m.uid(), m.gid(), m.mode() & 0o7777))
}

#[cfg(unix)]
fn lchown(p: &Path, uid: u32, gid: u32) -> io::Result<()> {
    std::os::unix::fs::lchown(p, Some(uid), Some(gid))
}

/// Open `p` itself: O_NOFOLLOW refuses a symlink in its last component (ELOOP), O_NONBLOCK keeps
/// a FIFO from blocking. AGP-063 K1: owner and mode then change through this fd, never by path.
#[cfg(unix)]
pub fn open_nofollow(p: &Path, dir: bool) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let flags = libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK | if dir { libc::O_DIRECTORY } else { 0 };
    std::fs::OpenOptions::new().read(true).custom_flags(flags).open(p)
}

/// Where the entries of the directory open as `d` (at `path`) are named: through the fd on Linux
/// (`/proc/self/fd/N`), so a parent swapped for a symlink after it was opened is never followed.
#[cfg(unix)]
fn entries_of(d: &std::fs::File, path: &Path) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let proc = PathBuf::from(format!("/proc/self/fd/{}", d.as_raw_fd()));
        if proc.exists() {
            return proc;
        }
    }
    let _ = d;
    path.to_path_buf()
}

/// Give the directory open as `d` (at `path`) and everything under it to `uid`. Directories are
/// opened O_NOFOLLOW relative to their parent's fd and chowned through their own fd; anything else
/// is lchowned in place, so no symlink is ever followed, even one swapped in during the walk.
#[cfg(unix)]
fn chown_tree(d: &std::fs::File, path: &Path, uid: u32, gid: u32, changed: &mut u64) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let md = d.metadata()?;
    if md.uid() != uid || md.gid() != gid {
        std::os::unix::fs::fchown(d, Some(uid), Some(gid))?;
        *changed += 1;
    }
    if !md.file_type().is_dir() {
        return Ok(());
    }
    let base = entries_of(d, path);
    for e in std::fs::read_dir(&base)? {
        let name = e?.file_name();
        let p = base.join(&name);
        let m = std::fs::symlink_metadata(&p)?;
        if m.file_type().is_dir() {
            match open_nofollow(&p, true) {
                Ok(c) => chown_tree(&c, &path.join(&name), uid, gid, changed)?,
                Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) => {
                    lchown(&p, uid, gid)?;
                    *changed += 1;
                }
                Err(e) => return Err(e),
            }
        } else if m.uid() != uid || m.gid() != gid {
            lchown(&p, uid, gid)?;
            *changed += 1;
        }
    }
    Ok(())
}

/// A directory owned by `uid` with `mode`; created if missing. When its owner was another uid, its
/// contents change owner too (the bind-mount case). Returns a report row.
#[cfg(unix)]
fn own_dir(dir: &Path, uid: u32, mode: u32, recurse: bool) -> Result<Value, String> {
    own_dir_gid(dir, uid, uid, mode, recurse)
}

/// [`own_dir`] with a group other than the owner's own.
#[cfg(unix)]
fn own_dir_gid(dir: &Path, uid: u32, gid: u32, mode: u32, recurse: bool) -> Result<Value, String> {
    let ctx = |e: io::Error| format!("{}: {e}", dir.display());
    let created = !dir.exists();
    if created {
        std::fs::create_dir_all(dir).map_err(ctx)?;
    }
    let f = match open_nofollow(dir, true) {
        Ok(f) => f,
        Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) => {
            return Err(format!("{}: is a symlink or not a directory; refusing", dir.display()));
        }
        Err(e) => return Err(ctx(e)),
    };
    let (u0, g0, m0) = {
        use std::os::unix::fs::MetadataExt;
        let m = f.metadata().map_err(ctx)?;
        (m.uid(), m.gid(), m.mode() & 0o7777)
    };
    let mut changed = 0u64;
    if u0 != uid || g0 != gid {
        if recurse {
            chown_tree(&f, dir, uid, gid, &mut changed).map_err(ctx)?;
        } else {
            std::os::unix::fs::fchown(&f, Some(uid), Some(gid)).map_err(ctx)?;
            changed = 1;
        }
    }
    if m0 != mode {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(mode)).map_err(ctx)?;
    }
    Ok(json!({"path": dir.display().to_string(), "uid": uid, "gid": gid, "mode": format!("{mode:o}"), "created": created,
              "was": {"uid": u0, "gid": g0, "mode": format!("{m0:o}")}, "chowned": changed}))
}

/// Write a secret owned by `uid` with `mode` (0600, or 0640 for the shared MCP token), only when its value differs. The temp file is created
/// exclusively (never through a symlink a service may have planted) and renamed over the target.
#[cfg(unix)]
fn put_secret(path: &Path, value: &[u8], uid: u32, mode: u32) -> Result<&'static str, String> {
    put_secret_gid(path, value, uid, uid, mode)
}

/// [`put_secret`] with a group of its own (a shared dir's, so its reader reads it by group).
#[cfg(unix)]
fn put_secret_gid(path: &Path, value: &[u8], uid: u32, gid: u32, mode: u32) -> Result<&'static str, String> {
    let ctx = |e: io::Error| format!("{}: {e}", path.display());
    if let Ok(mut f) = open_nofollow(path, false) {
        use std::os::unix::fs::MetadataExt;
        let md = f.metadata().map_err(ctx)?;
        let mut cur = vec![];
        if md.file_type().is_file() && std::io::Read::read_to_end(&mut f, &mut cur).is_ok() && cur == value {
            if (md.uid(), md.gid(), md.mode() & 0o7777) != (uid, gid, mode) {
                use std::os::unix::fs::PermissionsExt;
                std::os::unix::fs::fchown(&f, Some(uid), Some(gid)).map_err(ctx)?;
                f.set_permissions(std::fs::Permissions::from_mode(mode)).map_err(ctx)?;
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
    std::os::unix::fs::fchown(&f, Some(uid), Some(gid)).map_err(ctx)?;
    f.write_all(value).and_then(|_| f.sync_all()).map_err(ctx)?;
    if mode != 0o600 {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(mode)).and_then(|_| f.sync_all()).map_err(ctx)?;
    }
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
            // made here either way (a socket dir's parent first); a shared one gets its group and mode below
            dirs.push(own_dir(&run.join(dir), uid_of(c), 0o750, true)?);
        }
    }
    for sd in SHARED_DIRS {
        if let (Some(w), true) = (comps.iter().find(|c| c.name == sd.writer), has(sd.reader)) {
            // tests run every component as their own uid: the group is then theirs too
            let gid = if uid_of(w) == w.uid { sd.gid } else { uid_of(w) };
            dirs.push(own_dir_gid(&run.join(sd.dir), uid_of(w), gid, sd.mode, true)?);
        }
    }
    // Umbrel: the hand-over of the keys the Lightning app's user has its node bake: that user writes,
    // the UI takes them (and removes them) by group
    if let (Some(u), Some(ui)) = (prov.node_keys_uid, comps.iter().find(|c| c.name == crate::UI)) {
        dirs.push(own_dir_gid(&run.join(crate::RUN_NODE_KEYS), u, uid_of(ui), 0o770, true)?);
    }
    let mut secrets = vec![];
    let mut put = |comp: &str, name: &str, value: &[u8]| -> Result<(), String> {
        let c = component(comp).expect("known");
        let r = put_secret(&root.join(comp).join("secrets").join(name), value, uid_of(c), 0o600)?;
        secrets.push(json!({"component": comp, "name": name, "result": r}));
        Ok(())
    };
    if let Some(a) = &prov.node_rpc_auth {
        if has(crate::SIGNER) {
            put(crate::SIGNER, "node-rpc-auth", a.as_bytes())?;
        }
    }
    if has(crate::UI) {
        if let Some(p) = &prov.ui_password {
            put(crate::UI, "xbt-ui-password", p.as_bytes())?;
        }
    }
    if has(crate::MCP) {
        let tp = root.join(crate::MCP).join("secrets").join(crate::MCP_TOKEN);
        let ui_copy = root.join(crate::UI).join("secrets").join(crate::MCP_TOKEN);
        let shared = root.join("run").join(crate::RUN_UI).join(crate::MCP_TOKEN);
        let fresh = || crate::to_hex(&crate::random_bytes(32)).into_bytes();
        if has(crate::UI) {
            // the UI owns the token (it rotates it); the MCP only reads it. The first run of this layout
            // keeps an older layout's token, so agents keep working across the upgrade.
            let token = read_regular(&shared).or_else(|| read_regular(&tp)).unwrap_or_else(fresh);
            let r = put_secret(&shared, &token, uid_of(component(crate::UI).expect("known")), MCP_TOKEN_MODE)?;
            secrets.push(json!({"component": crate::UI, "name": format!("run/{}/{}", crate::RUN_UI, crate::MCP_TOKEN), "result": r}));
            for (comp, old) in [(crate::MCP, &tp), (crate::UI, &ui_copy)] {
                if std::fs::symlink_metadata(old).is_ok() {
                    std::fs::remove_file(old).map_err(|e| format!("{}: {e}", old.display()))?;
                    secrets.push(json!({"component": comp, "name": crate::MCP_TOKEN, "result": "removed"}));
                }
            }
        } else {
            // an existing value stays (owner and mode only)
            put(crate::MCP, crate::MCP_TOKEN, &read_regular(&tp).unwrap_or_else(fresh))?;
        }
    }
    if has(crate::UI) && has(crate::HASHRATE) {
        let path = root.join("run").join(crate::RUN_HASHRATE).join(HASHRATE_TOKEN);
        let token = read_regular(&path).unwrap_or_else(|| crate::to_hex(&crate::random_bytes(32)).into_bytes());
        let ui = uid_of(component(crate::UI).expect("known"));
        // tests run every component as their own uid: the group is then theirs too
        let gid = if ui == component(crate::UI).expect("known").uid { HASHRATE_GID } else { ui };
        let r = put_secret_gid(&path, &token, ui, gid, MCP_TOKEN_MODE)?;
        secrets.push(json!({"component": crate::UI, "name": format!("run/{}/{HASHRATE_TOKEN}", crate::RUN_HASHRATE), "result": r}));
    }
    if let Some(d) = comps.iter().find(|c| c.name == crate::DATUM) {
        // the blocks it submits, kept on the volume for a resubmit if the node's submitblock fails
        dirs.push(own_dir(&root.join(crate::DATUM).join("submitblocks"), uid_of(d), 0o700, true)?);
        // the node's RPC credentials as a cookie file (`bitcoind.rpccookiefile`): the gateway's config, which the
        // UI writes, never holds them. No newline: the gateway takes the file's first line as it is, newline and all
        if let (Some(a), true) = (&prov.node_rpc_auth, has(crate::UI)) {
            let path = root.join("run").join(crate::RUN_DATUM).join(crate::DATUM_RPC_COOKIE);
            let r = put_secret(&path, a.as_bytes(), uid_of(d), DATUM_COOKIE_MODE)?;
            secrets.push(json!({"component": crate::DATUM, "name": format!("run/{}/{}", crate::RUN_DATUM, crate::DATUM_RPC_COOKIE), "result": r}));
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
    let mut want_gid = |p: PathBuf, uid: u32, gid: u32, mode: u32, problems: &mut Vec<String>| match owner_mode(&p) {
        Ok((u, g, m)) => {
            rows.push(json!({"path": p.display().to_string(), "uid": u, "gid": g, "mode": format!("{m:o}")}));
            if (u, g, m) != (uid, gid, mode) {
                problems.push(format!("{}: {u}:{g} {m:o}, want {uid}:{gid} {mode:o}", p.display()));
            }
        }
        Err(e) => problems.push(format!("{}: {e}", p.display())),
    };
    for sd in SHARED_DIRS {
        if let (Some(w), true) = (component(sd.writer), names.iter().any(|n| n == sd.writer) && names.iter().any(|n| n == sd.reader)) {
            want_gid(root.join("run").join(sd.dir), w.uid, sd.gid, sd.mode, &mut problems);
        }
    }
    let mut want = |p: PathBuf, uid: u32, mode: u32, problems: &mut Vec<String>| want_gid(p, uid, uid, mode, problems);
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
            if *server == c.name && !shared_here(dir, &|n: &str| names.iter().any(|x| x == n)) {
                want(root.join("run").join(dir), c.uid, 0o750);
            }
        }
        if c.name == crate::UI && names.iter().any(|n| n == crate::MCP) {
            want(root.join("run").join(crate::RUN_UI).join(crate::MCP_TOKEN), c.uid, MCP_TOKEN_MODE);
        }
        if c.name == crate::DATUM {
            want(d.join("submitblocks"), c.uid, 0o700);
            let cookie = root.join("run").join(crate::RUN_DATUM).join(crate::DATUM_RPC_COOKIE);
            if std::fs::symlink_metadata(&cookie).is_ok() {
                want(cookie, c.uid, DATUM_COOKIE_MODE);
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
        assert_eq!(t, vec![("signer", 10001), ("witness", 10002), ("mcp", 10003), ("ui", 10005), ("relay", 10006), ("gateway", 10007), ("hashrate", 10010), ("stream-relay", 10016), ("vpn", 10018), ("datum", 10021)]);
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
        // the hand-over's owner: a uid, never root's (in this test: the environment is the process's)
        std::env::set_var("XBT_INIT_NODE_KEYS_UID", "0");
        assert!(Provision::from_env().is_err());
        std::env::set_var("XBT_INIT_NODE_KEYS_UID", "1000");
        assert_eq!(Provision::from_env().unwrap().node_keys_uid, Some(1000));
        std::env::remove_var("XBT_INIT_NODE_KEYS_UID");
        assert!(!format!("{:?}", Provision { node_rpc_auth: Some("u:secret".into()), ui_password: None, node_keys_uid: None }).contains("secret"));
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
        let prov = Provision { node_rpc_auth: Some("xbt:pw".into()), ui_password: Some("correct horse".into()), node_keys_uid: None };
        let r = init_as(&root, &names, &prov, uid).unwrap();
        assert_eq!(r["ok"], true);
        // AGP-042: with the UI, the token is the UI's run/ui/mcp-http-token (0640, the MCP reads it by group)
        let tok = std::fs::read_to_string(root.join("run/ui/mcp-http-token")).unwrap();
        assert_eq!(tok.len(), 64);
        assert!(!root.join("mcp/secrets/mcp-http-token").exists() && !root.join("ui/secrets/mcp-http-token").exists());
        assert_eq!(std::fs::metadata(root.join("run/ui/mcp-http-token")).unwrap().mode() & 0o777, 0o640);
        assert_eq!(std::fs::metadata(root.join("run/ui")).unwrap().mode() & 0o777, 0o750);
        assert_eq!(std::fs::read_to_string(root.join("signer/secrets/node-rpc-auth")).unwrap(), "xbt:pw");
        assert!(!root.join("witness").exists(), "only the listed components");
        for p in ["signer/secrets/node-rpc-auth", "ui/secrets/xbt-ui-password"] {
            assert_eq!(std::fs::metadata(root.join(p)).unwrap().mode() & 0o777, 0o600, "{p}");
        }
        assert_eq!(std::fs::metadata(root.join("run/signer")).unwrap().mode() & 0o777, 0o750);
        assert_eq!(std::fs::metadata(root.join("run/signer/streams")).unwrap().mode() & 0o777, 0o750, "the stream sockets' dir, the signer's");
        // with the VPN service installed, it makes its paid tunnels' sockets there too: the dir is the
        // signer's and the stream group's (the signer and the VPN service only)
        let with_vpn: Vec<String> = ["signer", "mcp", "ui", "vpn"].iter().map(|s| s.to_string()).collect();
        let rv = init_as(&root, &with_vpn, &prov, uid).unwrap();
        assert_eq!(rv["ok"], true, "{rv}");
        assert_eq!(std::fs::metadata(root.join("run/signer/streams")).unwrap().mode() & 0o777, 0o770);
        assert_eq!(std::fs::metadata(root.join("run/signer")).unwrap().mode() & 0o777, 0o750, "the signer's socket dir stays its own");
        init_as(&root, &names, &prov, uid).unwrap();
        // a second run keeps the token and rewrites nothing
        let r2 = init_as(&root, &names, &prov, uid).unwrap();
        assert!(r2["secrets"].as_array().unwrap().iter().all(|s| s["result"] == "unchanged"), "{r2}");
        assert_eq!(std::fs::read_to_string(root.join("run/ui/mcp-http-token")).unwrap(), tok);
        // a rotated token (the UI replaced it) survives a restart's init
        crate::replace_secret_file(&root.join("run/ui/mcp-http-token"), b"rotated", 0o640).unwrap();
        init_as(&root, &names, &prov, uid).unwrap();
        assert_eq!(std::fs::read_to_string(root.join("run/ui/mcp-http-token")).unwrap(), "rotated");
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

    /// Umbrel: the hand-over of the node's baked keys is the Lightning app user's, shared with the UI by
    /// group (0770); without that user, or without the UI, there is none.
    #[test]
    fn the_node_keys_hand_over_is_made_only_with_its_owner_and_the_ui() {
        let uid = me();
        if uid == 0 {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("data");
        let names: Vec<String> = ["signer", "ui"].iter().map(|s| s.to_string()).collect();
        init_as(&root, &names, &Provision::default(), uid).unwrap();
        assert!(!root.join("run/node-keys").exists(), "no hand-over without its owner");
        let prov = Provision { node_keys_uid: Some(uid), ..Provision::default() };
        init_as(&root, &["signer".to_string()], &prov, uid).unwrap();
        assert!(!root.join("run/node-keys").exists(), "no hand-over without the UI");
        let r = init_as(&root, &names, &prov, uid).unwrap();
        assert_eq!(r["ok"], true, "{r}");
        let md = std::fs::metadata(root.join("run/node-keys")).unwrap();
        assert_eq!((md.uid(), md.mode() & 0o7777), (uid, 0o770));
    }

    /// An AGP-040 data dir (the token in mcp/secrets and a copy in ui/secrets) upgrades with the same token;
    /// without the UI the token stays the MCP's own secret.
    #[test]
    fn mcp_token_upgrade_and_mcp_only() {
        let uid = me();
        if uid == 0 {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("data");
        let mcp_only: Vec<String> = ["signer", "mcp"].iter().map(|s| s.to_string()).collect();
        init_as(&root, &mcp_only, &Provision::default(), uid).unwrap();
        let old = std::fs::read_to_string(root.join("mcp/secrets/mcp-http-token")).unwrap();
        assert_eq!(std::fs::metadata(root.join("mcp/secrets/mcp-http-token")).unwrap().mode() & 0o777, 0o600);
        assert!(!root.join("run/ui").exists());
        std::fs::create_dir_all(root.join("ui/secrets")).unwrap();
        std::fs::write(root.join("ui/secrets/mcp-http-token"), &old).unwrap();
        let all: Vec<String> = ["signer", "mcp", "ui"].iter().map(|s| s.to_string()).collect();
        let r = init_as(&root, &all, &Provision::default(), uid).unwrap();
        assert_eq!(std::fs::read_to_string(root.join("run/ui/mcp-http-token")).unwrap(), old, "agents keep their token");
        assert!(!root.join("mcp/secrets/mcp-http-token").exists() && !root.join("ui/secrets/mcp-http-token").exists(), "{r}");
        assert!(!r.to_string().contains(&old), "the report never holds a secret");
    }

    /// AGP-063 K1: the walk regroups everything under the tree and nothing a symlink in it points at.
    #[test]
    fn k1_chown_tree_regroups_the_tree_and_never_follows_a_symlink() {
        let uid = me();
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let other = status.lines().find_map(|l| l.strip_prefix("Groups:")).into_iter()
            .flat_map(|g| g.split_whitespace().filter_map(|x| x.parse::<u32>().ok()).collect::<Vec<_>>()).find(|&g| g != uid);
        let Some(g) = other else { return };
        if uid == 0 {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let (tree, outside) = (t.path().join("tree"), t.path().join("outside"));
        std::fs::create_dir_all(tree.join("a")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(tree.join("a/f"), "x").unwrap();
        std::fs::write(outside.join("v"), "x").unwrap();
        std::os::unix::fs::symlink(&outside, tree.join("link")).unwrap();
        for p in [tree.join("a/f"), outside.join("v"), outside.clone()] {
            std::os::unix::fs::chown(&p, None, Some(g)).unwrap();
        }
        let mut changed = 0;
        chown_tree(&open_nofollow(&tree, true).unwrap(), &tree, uid, uid, &mut changed).unwrap();
        assert_eq!(std::fs::metadata(tree.join("a/f")).unwrap().gid(), uid);
        assert_eq!(std::fs::metadata(outside.join("v")).unwrap().gid(), g);
        assert_eq!(std::fs::metadata(&outside).unwrap().gid(), g);
        assert!(changed >= 1);
        assert!(open_nofollow(&tree.join("link"), true).is_err());
    }

    fn init_as(root: &Path, names: &[String], prov: &Provision, uid: u32) -> Result<Value, String> {
        init_with(root, names, prov, &|_| uid)
    }

    /// The setup pages' dirs: made only when both the writer and the reader are in the layout.
    #[test]
    fn shared_dirs_follow_the_components() {
        let uid = me();
        if uid == 0 {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("data");
        let names: Vec<String> = ["signer", "ui", "gateway"].iter().map(|s| s.to_string()).collect();
        init_as(&root, &names, &Provision::default(), uid).unwrap();
        for d in ["run/ln", "run/gateway"] {
            assert_eq!(std::fs::metadata(root.join(d)).unwrap().mode() & 0o7777, 0o750, "{d}");
        }
        // the AI endpoint's files: the UI and the signer's user (the connector) both write there
        assert_eq!(std::fs::metadata(root.join("run/ai")).unwrap().mode() & 0o7777, 0o770);
        assert_eq!(std::fs::metadata(root.join("gateway")).unwrap().mode() & 0o777, 0o700);
        let root2 = t.path().join("wallet-only");
        let names: Vec<String> = ["signer", "mcp"].iter().map(|s| s.to_string()).collect();
        init_as(&root2, &names, &Provision::default(), uid).unwrap();
        assert!(!root2.join("run/ln").exists() && !root2.join("run/gateway").exists() && !root2.join("run/ai").exists());
        // with the hashrate services: their settings dir, and one control token the UI owns and
        // they read by group, made once and kept across restarts
        let root3 = t.path().join("hashrate");
        let names: Vec<String> = ["signer", "ui", "hashrate"].iter().map(|s| s.to_string()).collect();
        init_as(&root3, &names, &Provision::default(), uid).unwrap();
        assert_eq!(std::fs::metadata(root3.join("run/hashrate")).unwrap().mode() & 0o7777, 0o750);
        let tok = root3.join("run/hashrate").join(HASHRATE_TOKEN);
        let first = std::fs::read(&tok).unwrap();
        assert_eq!(first.len(), 64);
        assert_eq!(std::fs::metadata(&tok).unwrap().mode() & 0o7777, 0o640);
        init_as(&root3, &names, &Provision::default(), uid).unwrap();
        assert_eq!(std::fs::read(&tok).unwrap(), first, "the token survives a restart");
        assert!(!root.join("run/hashrate").exists(), "no hashrate dir without the hashrate component");
        // the renter's socket dir: the signer's, reached by the hashrate group alone (here, every component is this uid)
        let md = std::fs::metadata(root3.join("run/rental")).unwrap();
        assert_eq!((md.uid(), md.mode() & 0o7777), (uid, 0o750));
        assert!(!root.join("run/rental").exists() && !root2.join("run/rental").exists(), "no renter's socket without the hashrate component");
    }

    /// The Stream Gateway: its config dir is the UI's (it writes config.json) and the gateway's by group; the node's
    /// RPC credentials go to its cookie file alone, 0600, without a newline (the gateway would send the newline as
    /// part of the password), and only with both the gateway and the UI installed.
    #[test]
    fn the_stream_gateways_cookie_is_its_own_and_its_config_dir_is_shared() {
        let uid = me();
        if uid == 0 {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("data");
        let names: Vec<String> = ["signer", "ui", "hashrate", "datum"].iter().map(|s| s.to_string()).collect();
        let prov = Provision { node_rpc_auth: Some("xbt:pw-secret".into()), ..Provision::default() };
        let r = init_as(&root, &names, &prov, uid).unwrap();
        assert_eq!(r["ok"], true, "{r}");
        assert!(!r.to_string().contains("pw-secret"), "the report never holds a secret");
        let cookie = root.join("run/datum/rpc.cookie");
        assert_eq!(std::fs::read(&cookie).unwrap(), b"xbt:pw-secret", "user:password, no newline");
        assert_eq!(std::fs::metadata(&cookie).unwrap().mode() & 0o7777, 0o600);
        assert_eq!(std::fs::metadata(root.join("run/datum")).unwrap().mode() & 0o7777, 0o750);
        assert_eq!(std::fs::metadata(root.join("datum")).unwrap().mode() & 0o7777, 0o700);
        assert_eq!(std::fs::metadata(root.join("datum/submitblocks")).unwrap().mode() & 0o7777, 0o700);
        // the node's password changed (StartOS: the node-connection action): rewritten, and so the gateway restarts
        let prov2 = Provision { node_rpc_auth: Some("xbt:new".into()), ..Provision::default() };
        let r2 = init_as(&root, &names, &prov2, uid).unwrap();
        assert!(r2["secrets"].as_array().unwrap().iter().any(|s| s["name"] == "run/datum/rpc.cookie" && s["result"] == "written"), "{r2}");
        assert_eq!(std::fs::read(&cookie).unwrap(), b"xbt:new");
        // a cookie whose mode drifted is put back
        std::fs::set_permissions(&cookie, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
        init_as(&root, &names, &prov2, uid).unwrap();
        assert_eq!(std::fs::metadata(&cookie).unwrap().mode() & 0o7777, 0o600);
        // no UI, no gateway config dir and no cookie
        let root2 = t.path().join("no-ui");
        let names2: Vec<String> = ["signer", "datum"].iter().map(|s| s.to_string()).collect();
        init_as(&root2, &names2, &prov, uid).unwrap();
        assert!(!root2.join("run/datum").exists());
        // no gateway, no cookie
        let root3 = t.path().join("no-datum");
        init_as(&root3, &["signer".to_string(), "ui".to_string()], &prov, uid).unwrap();
        assert!(!root3.join("run/datum").exists());
    }

    #[test]
    fn check_reports_problems() {
        let t = tempfile::tempdir().unwrap();
        let v = check(t.path(), &["signer".to_string()]);
        assert_eq!(v["ok"], false);
    }
}
