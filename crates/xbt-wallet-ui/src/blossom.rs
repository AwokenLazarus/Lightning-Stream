//! Blossom by hash (BUD-01) on a Files service's folder: `GET`/`HEAD /<sha256>[.ext]`.
//!
//! Off by default (`XBT_UI_FILES_BLOSSOM=1` turns it on; `docs/NWC-BLOSSOM.md`). When it is on, the
//! folder's server ([`crate::files::Server`]) also answers a file by the SHA-256 of its content, as a
//! Blossom server does, so a Blossom client (or a buyer who has only the hash) can ask the shop for it.
//! The shop's gateway route in front of the folder is unchanged: `/files/<sha256>.mkv` is sold by the
//! same per-byte meter as `/files/Sintel.mkv`.
//!
//! * The hashes are kept in an [`Index`] of the listed files ([`crate::files::list`]), each with the
//!   size and modification time it was hashed at. A file whose size or time has changed since is not
//!   answered by its old hash.
//! * Hashing a folder of films takes a while, so it is done on a thread of its own: once when the
//!   server starts, and again (at most every [`REFRESH_EVERY`]) when a hash is asked for that the
//!   index does not have. A request never waits for it.
//! * A whole-file answer is hashed again as it is sent. If the bytes sent are not the hash's (the file
//!   was changed in place without its size or time changing), the body ends short of its length, so
//!   the client sees a cut answer and not a whole wrong one, and the file is hashed again.
//! * A file is served by hash only if it is still one the folder serves by name: no hidden name, no
//!   link leading out of the folder.
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use sha2::{Digest, Sha256};

/// A missed hash starts a new hashing of the folder at most this often.
pub const REFRESH_EVERY: Duration = Duration::from_secs(30);

/// The hash a BUD-01 path names: `/<64 hex>` with at most one extension (`.mkv`), lower-cased.
pub fn hash_of_path(path: &str) -> Option<String> {
    let p = path.strip_prefix('/')?;
    let (h, ext) = match p.split_once('.') {
        Some((h, e)) => (h, Some(e)),
        None => (p, None),
    };
    if let Some(e) = ext {
        if e.is_empty() || e.len() > 10 || !e.bytes().all(|c| c.is_ascii_alphanumeric()) {
            return None;
        }
    }
    (h.len() == 64 && h.bytes().all(|c| c.is_ascii_hexdigit())).then(|| h.to_ascii_lowercase())
}

/// SHA-256 of a file's content, in lower-case hex.
pub fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 256 << 10];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    hash: String,
    len: u64,
    mtime: Option<SystemTime>,
}

fn stamp(path: &Path) -> Option<(u64, Option<SystemTime>)> {
    let m = std::fs::metadata(path).ok()?;
    m.is_file().then(|| (m.len(), m.modified().ok()))
}

#[derive(Default)]
struct Inner {
    /// By the file's path relative to the folder.
    by_rel: HashMap<String, Entry>,
    /// The folder the entries are of: a new choice of folder starts the index again.
    dir: Option<PathBuf>,
    last: Option<Instant>,
}

/// The hashes of the folder's listed files.
#[derive(Default)]
pub struct Index {
    inner: Mutex<Inner>,
    busy: AtomicBool,
}

impl Index {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Hashes what is new or changed in `dir` and forgets what is gone. A file is read outside the lock.
    pub fn refresh(&self, dir: &Path) {
        let known: HashMap<String, Entry> = {
            let mut g = self.lock();
            if g.dir.as_deref() != Some(dir) {
                g.by_rel.clear();
                g.dir = Some(dir.to_path_buf());
            }
            g.by_rel.clone()
        };
        let mut next = HashMap::new();
        for (rel, _) in crate::files::list(dir) {
            let p = dir.join(&rel);
            let Some((len, mtime)) = stamp(&p) else { continue };
            let e = match known.get(&rel) {
                Some(e) if e.len == len && e.mtime == mtime => e.clone(),
                _ => match hash_file(&p) {
                    // a file changed while it was read is left for the next round
                    Ok(hash) if stamp(&p) == Some((len, mtime)) => Entry { hash, len, mtime },
                    _ => continue,
                },
            };
            next.insert(rel, e);
        }
        let mut g = self.lock();
        if g.dir.as_deref() == Some(dir) {
            g.by_rel = next;
            g.last = Some(Instant::now());
        }
    }

    /// Starts [`Self::refresh`] on a thread of its own, unless one is running or one ran within
    /// [`REFRESH_EVERY`] (`force` skips that wait: the server's start).
    pub fn refresh_soon(self: &Arc<Self>, dir: PathBuf, force: bool) {
        if !force && self.lock().last.is_some_and(|t| t.elapsed() < REFRESH_EVERY) {
            return;
        }
        if self.busy.swap(true, Ordering::AcqRel) {
            return;
        }
        let me = self.clone();
        let spawned = std::thread::Builder::new().name("files-blossom".into()).spawn(move || {
            me.refresh(&dir);
            me.busy.store(false, Ordering::Release);
        });
        if spawned.is_err() {
            self.busy.store(false, Ordering::Release);
        }
    }

    /// The file in `dir` whose content hashed to `hash`, while its size and time are still those it
    /// was hashed at and it is still one the folder serves by name.
    pub fn lookup(&self, dir: &Path, hash: &str) -> Option<PathBuf> {
        let (rel, e) = {
            let g = self.lock();
            if g.dir.as_deref() != Some(dir) {
                return None;
            }
            g.by_rel.iter().find(|(_, e)| e.hash == hash).map(|(r, e)| (r.clone(), e.clone()))?
        };
        let p = crate::files::resolve(dir, &format!("/{}", crate::files::url_path(&rel)))?;
        (stamp(&p) == Some((e.len, e.mtime))).then_some(p)
    }

    /// Forgets `path`'s hash: the bytes sent under it were not its.
    pub fn forget(&self, dir: &Path, path: &Path) {
        let mut g = self.lock();
        if g.dir.as_deref() == Some(dir) {
            if let Ok(rel) = path.strip_prefix(dir) {
                let rel = rel.to_string_lossy().replace('\\', "/");
                g.by_rel.remove(&rel);
                g.last = None;
            }
        }
    }

    /// How many files are hashed (for the tests and the Sell page).
    pub fn len(&self) -> usize {
        self.lock().by_rel.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What a whole-file answer by hash checks as it is sent: the bytes' SHA-256 against the one asked for.
pub struct Check {
    pub want: String,
    pub hasher: Sha256,
}

impl Check {
    pub fn new(want: &str) -> Self {
        Self { want: want.to_string(), hasher: Sha256::new() }
    }

    pub fn ok(self) -> bool {
        hex::encode(self.hasher.finalize()) == self.want
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    #[test]
    fn a_bud01_path_is_64_hex_with_at_most_one_extension() {
        let h = sha(b"x");
        assert_eq!(hash_of_path(&format!("/{h}")), Some(h.clone()));
        assert_eq!(hash_of_path(&format!("/{h}.mkv")), Some(h.clone()));
        assert_eq!(hash_of_path(&format!("/{}.PDF", h.to_uppercase())), Some(h.clone()));
        for bad in [format!("{h}"), format!("/{h}."), format!("/{h}.tar.gz"), format!("/{h}.m/v"), format!("/{}", &h[1..]),
                    format!("/{h}0"), format!("/x{}", &h[1..]), "/Sintel.mkv".into(), format!("/a/{h}"), format!("/{h}.%2e")] {
            assert_eq!(hash_of_path(&bad), None, "{bad}");
        }
    }

    #[test]
    fn the_index_finds_a_file_by_its_content_and_not_once_it_changed_or_left() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("Films")).unwrap();
        std::fs::write(d.path().join("Films/Sintel.mkv"), b"film bytes").unwrap();
        std::fs::write(d.path().join("book.pdf"), b"pdf").unwrap();
        std::fs::write(d.path().join(".hidden"), b"secret").unwrap();
        let out = tempfile::tempdir().unwrap();
        std::fs::write(out.path().join("wallet.dat"), b"outside").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(out.path().join("wallet.dat"), d.path().join("link.dat")).unwrap();

        let ix = Index::default();
        assert_eq!(ix.lookup(d.path(), &sha(b"film bytes")), None, "nothing before the first hashing");
        ix.refresh(d.path());
        assert_eq!(ix.len(), 2);
        assert_eq!(ix.lookup(d.path(), &sha(b"film bytes")), Some(d.path().join("Films/Sintel.mkv")));
        assert_eq!(ix.lookup(d.path(), &sha(b"pdf")), Some(d.path().join("book.pdf")));
        assert_eq!(ix.lookup(d.path(), &sha(b"secret")), None, "a hidden file has no hash here");
        assert_eq!(ix.lookup(d.path(), &sha(b"outside")), None, "nor a link out of the folder");
        let other = tempfile::tempdir().unwrap();
        assert_eq!(ix.lookup(other.path(), &sha(b"pdf")), None, "another folder is not this index's");

        // changed: its old hash is not answered, even before the next hashing
        std::fs::write(d.path().join("book.pdf"), b"pdf, longer").unwrap();
        assert_eq!(ix.lookup(d.path(), &sha(b"pdf")), None);
        ix.refresh(d.path());
        assert_eq!(ix.lookup(d.path(), &sha(b"pdf, longer")), Some(d.path().join("book.pdf")));
        // gone
        std::fs::remove_file(d.path().join("Films/Sintel.mkv")).unwrap();
        assert_eq!(ix.lookup(d.path(), &sha(b"film bytes")), None);
        ix.refresh(d.path());
        assert_eq!(ix.len(), 1);
        ix.forget(d.path(), &d.path().join("book.pdf"));
        assert!(ix.is_empty());
    }

    #[test]
    fn a_refresh_on_its_own_thread_runs_once_at_a_time_and_not_too_often() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("a.bin"), b"a").unwrap();
        let ix = Arc::new(Index::default());
        ix.refresh_soon(d.path().to_path_buf(), true);
        let t = Instant::now();
        while ix.is_empty() && t.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(ix.lookup(d.path(), &sha(b"a")), Some(d.path().join("a.bin")));
        // a new file within REFRESH_EVERY is not looked for unless forced
        std::fs::write(d.path().join("b.bin"), b"b").unwrap();
        while ix.busy.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(10));
        }
        ix.refresh_soon(d.path().to_path_buf(), false);
        assert!(!ix.busy.load(Ordering::Acquire), "no new round so soon");
        assert_eq!(ix.lookup(d.path(), &sha(b"b")), None);
    }
}
