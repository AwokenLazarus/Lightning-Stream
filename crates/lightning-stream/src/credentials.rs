//! The owner's credentials for programs on their own network: local links (an address any browser
//! or app can use as a bought service) and AI keys (for the OpenAI-compatible endpoint). One store
//! and one page for both, so the owner manages everything that can spend on their behalf in one
//! place.
//!
//! Each entry has a secret: 128 random bits as 22 base64url characters. The secret is shown to the
//! owner once, when it is made, and kept only as its SHA-256, so a copy of the file does not give
//! it away. An entry has a limit in sats (and optionally one per day). It pauses when it reaches
//! the limit and resumes when the owner raises it, and it can be revoked at once.
//!
//! The file is JSON, written whole to a temporary file and renamed over the old one ([`write_file`]):
//! mode 600, or 660 in a directory shared by group with the endpoint.
//! Never log a secret: [`redact`] takes them out of a line that carries a path.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// What an entry is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An address on the owner's network that opens a seller's web app (`base`).
    Link,
    /// A key for the AI endpoint (`Authorization: Bearer sk-stream-…`).
    AiKey,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Link => "link",
            Kind::AiKey => "ai-key",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "link" => Some(Kind::Link),
            "ai-key" => Some(Kind::AiKey),
            _ => None,
        }
    }
}

/// The prefix of an AI key, so a key is recognised for what it is in a client's settings.
pub const AI_KEY_PREFIX: &str = "sk-stream-";

/// One credential.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    /// A short id for the page and the log (not the secret, and not derived from it).
    pub id: String,
    pub kind: Kind,
    pub name: String,
    /// SHA-256 of the secret, hex.
    pub secret_sha256: String,
    /// Seconds since the epoch.
    pub created: u64,
    pub revoked: bool,
    pub limit_sats: u64,
    /// The most it may spend in one UTC day, if the owner set one.
    pub per_day_sats: Option<u64>,
    /// What it has spent, in msat (msat, so a call priced by the token is counted exactly).
    pub spent_msat: u64,
    /// The UTC day (days since the epoch) `day_msat` counts, and what was spent on it.
    pub day: u64,
    pub day_msat: u64,
    /// Reached a limit: nothing more is paid until the owner raises it.
    pub paused: bool,
    /// For a link, the seller URL it opens, ending in `/`.
    pub base: Option<String>,
}

impl Entry {
    fn to_json(&self) -> Value {
        json!({"id": self.id, "kind": self.kind.as_str(), "name": self.name, "secret_sha256": self.secret_sha256,
               "created": self.created, "revoked": self.revoked, "limit_sats": self.limit_sats, "per_day_sats": self.per_day_sats,
               "spent_msat": self.spent_msat.to_string(), "day": self.day, "day_msat": self.day_msat.to_string(),
               "paused": self.paused, "base": self.base})
    }

    fn from_json(v: &Value) -> Option<Self> {
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        let n = |k: &str| v.get(k).and_then(|x| x.as_u64().or_else(|| x.as_str().and_then(|t| t.parse().ok())));
        Some(Self {
            id: s("id")?,
            kind: Kind::parse(v.get("kind")?.as_str()?)?,
            name: s("name").unwrap_or_default(),
            secret_sha256: s("secret_sha256").filter(|h| h.len() == 64)?,
            created: n("created").unwrap_or(0),
            revoked: v.get("revoked").and_then(Value::as_bool).unwrap_or(false),
            limit_sats: n("limit_sats").unwrap_or(0),
            per_day_sats: n("per_day_sats"),
            spent_msat: n("spent_msat").unwrap_or(0),
            day: n("day").unwrap_or(0),
            day_msat: n("day_msat").unwrap_or(0),
            paused: v.get("paused").and_then(Value::as_bool).unwrap_or(false),
            base: s("base"),
        })
    }

    fn day_left_msat(&self, today: u64) -> Option<u64> {
        let spent_today = if self.day == today { self.day_msat } else { 0 };
        self.per_day_sats.map(|d| d.saturating_mul(1000).saturating_sub(spent_today))
    }

    /// What it may still spend now, in msat: the lesser of the total and the day's remainder.
    pub fn left_msat(&self, today: u64) -> u64 {
        let total = self.limit_sats.saturating_mul(1000).saturating_sub(self.spent_msat);
        self.day_left_msat(today).map_or(total, |d| d.min(total))
    }
}

/// Why a credential may not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// No such secret for this kind, or revoked.
    Unknown,
    /// At its limit (total or for the day): paused until the owner raises it.
    Paused { limit_sats: u64 },
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// 128 random bits as 22 base64url characters.
pub fn new_secret() -> String {
    use base64::Engine as _;
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("the system's random source");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn new_id() -> String {
    let mut b = [0u8; 6];
    getrandom::getrandom(&mut b).expect("the system's random source");
    hex::encode(b)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Seconds since the epoch.
pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Takes secrets out of a line: anything that looks like a 22-character token after `/l/` or an
/// AI key is replaced with `…`.
pub fn redact(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    loop {
        let at = [rest.find("/l/").map(|i| (i, 3)), rest.find(AI_KEY_PREFIX).map(|i| (i, AI_KEY_PREFIX.len()))]
            .into_iter().flatten().min_by_key(|(i, _)| *i);
        let Some((i, skip)) = at else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..i + skip]);
        let tail = &rest[i + skip..];
        let n = tail.bytes().take_while(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_').count();
        out.push('…');
        rest = &tail[n..];
    }
}

/// The store: the entries and the file they live in.
#[derive(Debug)]
pub struct Store {
    path: PathBuf,
    pub entries: Vec<Entry>,
}

impl Store {
    /// Reads the store at `path`; a missing file is an empty store. A file that cannot be read or
    /// parsed is an error, never an empty store, so a damaged file is never written over.
    pub fn open(path: &Path) -> io::Result<Self> {
        let entries = match fs::read(path) {
            Ok(b) => {
                let v: Value = serde_json::from_slice(&b).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", path.display())))?;
                v.get("entries").and_then(Value::as_array).into_iter().flatten().filter_map(Entry::from_json).collect()
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => vec![],
            Err(e) => return Err(e),
        };
        Ok(Self { path: path.to_path_buf(), entries })
    }

    /// Writes the store with [`write_file`]: the app and the endpoint both book in it, so in a dir
    /// shared by group it is group-writable (0660), and otherwise the owner's alone (0600).
    pub fn save(&self) -> io::Result<()> {
        let body = serde_json::to_vec_pretty(&json!({"version": 1, "entries": self.entries.iter().map(Entry::to_json).collect::<Vec<_>>()}))?;
        write_file(&self.path, &body, true)
    }

    /// Makes an entry. Returns its id and its secret (an AI key carries [`AI_KEY_PREFIX`]); the
    /// secret is shown once and kept only as its hash.
    pub fn make(&mut self, kind: Kind, name: &str, limit_sats: u64, per_day_sats: Option<u64>, base: Option<&str>) -> (String, String) {
        let secret = match kind {
            Kind::Link => new_secret(),
            Kind::AiKey => format!("{AI_KEY_PREFIX}{}", new_secret()),
        };
        let id = new_id();
        self.entries.push(Entry {
            id: id.clone(), kind, name: name.to_string(), secret_sha256: sha256_hex(secret.as_bytes()), created: now(), revoked: false,
            limit_sats, per_day_sats, spent_msat: 0, day: 0, day_msat: 0, paused: false, base: base.map(str::to_string),
        });
        (id, secret)
    }

    /// The entry of `kind` whose secret is `secret`, if it is not revoked. Paused or not: the
    /// caller asks [`Store::may_spend`] before paying.
    pub fn check(&self, kind: Kind, secret: &str) -> Result<&Entry, Refusal> {
        if secret.is_empty() {
            return Err(Refusal::Unknown);
        }
        let h = sha256_hex(secret.as_bytes());
        self.entries.iter().find(|e| e.kind == kind && !e.revoked && ct_eq(e.secret_sha256.as_bytes(), h.as_bytes())).ok_or(Refusal::Unknown)
    }

    /// Whether entry `id` may spend `need_msat` more today (`today` in days since the epoch).
    pub fn may_spend(&self, id: &str, need_msat: u64, today: u64) -> Result<u64, Refusal> {
        let e = self.entries.iter().find(|e| e.id == id && !e.revoked).ok_or(Refusal::Unknown)?;
        let left = e.left_msat(today);
        if e.paused || need_msat > left {
            return Err(Refusal::Paused { limit_sats: e.limit_sats });
        }
        Ok(left)
    }

    /// Books spend against entry `id`, in msat.
    pub fn add_spend(&mut self, id: &str, msat: u64, today: u64) {
        if let Some(e) = self.entries.iter_mut().find(|e| e.id == id) {
            e.spent_msat = e.spent_msat.saturating_add(msat);
            if e.day != today {
                e.day = today;
                e.day_msat = 0;
            }
            e.day_msat = e.day_msat.saturating_add(msat);
        }
    }

    /// Pauses entry `id` when it has nothing left (in total, or today). Returns whether it is paused.
    pub fn pause_if_over(&mut self, id: &str, today: u64) -> bool {
        match self.entries.iter_mut().find(|e| e.id == id) {
            Some(e) => {
                if e.left_msat(today) == 0 {
                    e.paused = true;
                }
                e.paused
            }
            None => false,
        }
    }

    /// Raises (or lowers) the limits of `id`; an entry with room again resumes.
    pub fn set_limits(&mut self, id: &str, limit_sats: u64, per_day_sats: Option<u64>, today: u64) {
        if let Some(e) = self.entries.iter_mut().find(|e| e.id == id) {
            e.limit_sats = limit_sats;
            e.per_day_sats = per_day_sats;
            if e.left_msat(today) > 0 {
                e.paused = false;
            }
        }
    }

    pub fn revoke(&mut self, id: &str) {
        if let Some(e) = self.entries.iter_mut().find(|e| e.id == id) {
            e.revoked = true;
        }
    }
}

/// Writes `body` to `path` whole: a temporary file beside it, then a rename over the old one, so a
/// reader never sees half a file. The file's mode and group follow its directory: in a directory
/// another service shares by group (group-searchable, as `run/ai/` on a box, 0770), the file takes
/// the directory's group, readable by it (0640), or writable too (0660) with `group_write`; in any
/// other directory it is the owner's alone (0600).
pub fn write_file(path: &Path, body: &[u8], group_write: bool) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let dm = fs::metadata(dir)?;
    let shared = dm.mode() & 0o010 != 0;
    let mode = match (shared, group_write && dm.mode() & 0o020 != 0) {
        (false, _) => 0o600,
        (true, false) => 0o640,
        (true, true) => 0o660,
    };
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(body)?;
        f.sync_all()?;
    }
    if shared && fs::metadata(&tmp)?.gid() != dm.gid() {
        std::os::unix::fs::chown(&tmp, None, Some(dm.gid()))?;
    }
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    fs::rename(&tmp, path)
}

/// The UTC day of `secs`.
pub fn day_of(secs: u64) -> u64 {
    secs / 86_400
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_is_kept_hashed_checked_by_kind_and_revoked() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("credentials.json");
        let mut s = Store::open(&path).unwrap();
        let (id, key) = s.make(Kind::AiKey, "Open WebUI", 100, None, None);
        let (_, link) = s.make(Kind::Link, "TV", 500, Some(50), Some("https://shop.example/jellyfin/"));
        assert!(key.starts_with(AI_KEY_PREFIX) && key.len() == AI_KEY_PREFIX.len() + 22 && link.len() == 22);
        s.save().unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&key[AI_KEY_PREFIX.len()..]) && !text.contains(&link), "a secret is not written");
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let s = Store::open(&path).unwrap();
        assert_eq!(s.check(Kind::AiKey, &key).unwrap().id, id);
        assert_eq!(s.check(Kind::Link, &key), Err(Refusal::Unknown), "a key is not a link");
        assert_eq!(s.check(Kind::Link, &link).unwrap().base.as_deref(), Some("https://shop.example/jellyfin/"));
        assert_eq!(s.check(Kind::AiKey, "sk-stream-wrong"), Err(Refusal::Unknown));
        let mut s = s;
        s.revoke(&id);
        assert_eq!(s.check(Kind::AiKey, &key), Err(Refusal::Unknown));
    }

    #[test]
    fn spend_pauses_at_the_limit_and_the_day_and_resumes_when_raised() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::open(&dir.path().join("c.json")).unwrap();
        let (id, _) = s.make(Kind::Link, "TV", 100, Some(30), None);
        assert_eq!(s.may_spend(&id, 30_000, 10), Ok(30_000));
        s.add_spend(&id, 30_000, 10);
        assert!(s.pause_if_over(&id, 10), "the day's 30 sats are spent");
        assert_eq!(s.may_spend(&id, 1, 10), Err(Refusal::Paused { limit_sats: 100 }));
        // a new day does not lift a pause by itself: the owner raises the limit
        s.set_limits(&id, 100, Some(30), 11);
        assert_eq!(s.may_spend(&id, 30_000, 11), Ok(30_000));
        s.add_spend(&id, 30_000, 11);
        s.add_spend(&id, 30_000, 12);
        s.add_spend(&id, 10_000, 13);
        assert!(s.pause_if_over(&id, 13), "the 100 sats in all are spent");
        s.set_limits(&id, 200, None, 13);
        assert_eq!(s.may_spend(&id, 100_000, 13), Ok(100_000));
    }

    #[test]
    fn a_file_in_a_dir_shared_by_group_is_the_groups_to_read_or_write() {
        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o770)).unwrap();
        write_file(&shared.join("a.json"), b"{}", true).unwrap();
        write_file(&shared.join("b.json"), b"{}", false).unwrap();
        write_file(&dir.path().join("c.json"), b"{}", true).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!((mode(&shared.join("a.json")), mode(&shared.join("b.json"))), (0o660, 0o640));
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        write_file(&dir.path().join("c.json"), b"{}", true).unwrap();
        assert_eq!(mode(&dir.path().join("c.json")), 0o600);
    }

    #[test]
    fn a_damaged_file_is_an_error_not_an_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        fs::write(&path, b"{not json").unwrap();
        assert!(Store::open(&path).is_err());
    }

    #[test]
    fn secrets_are_taken_out_of_a_logged_line() {
        assert_eq!(redact("GET /l/Xr7abcDEF012345678-_9a/web/index.html 200"), "GET /l/…/web/index.html 200");
        assert_eq!(redact("auth Bearer sk-stream-Xr7abcDEF012345678-_9a ok"), "auth Bearer sk-stream-… ok");
        assert_eq!(redact("nothing here"), "nothing here");
    }
}
