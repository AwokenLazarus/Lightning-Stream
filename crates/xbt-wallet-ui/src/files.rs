//! Files: a folder the owner shares (Sell, "Files"), served to the shop's gateway only.
//!
//! Lightning Stream sells what a service on the box answers; a folder is not a service. So the UI
//! serves the folder itself (`XBT_UI_FILES_DIR`) on its own address (`XBT_UI_FILES_BIND`), which the
//! gateway is the client of (`XBT_UI_FILES_UPSTREAM`, how the gateway's container reaches it). Every
//! request needs the files key (`x-stream-files-key`, kept in the UI's secrets): the gateway's route
//! adds it ([`crate::sell`]), so another program on the box's network reads nothing for free.
//!
//! * `GET`/`HEAD` of a file's path: the file, with one plain byte range (`206`), `Accept-Ranges`, and
//!   a type from its extension, so a player that seeks pays for what it reads.
//! * Only regular files under the folder: no `..`, no hidden names, no link that leads out of it.
//! * `GET /`: `204`, for the Sell page's "can it be reached" check.
//!
//! * On Umbrel the box shares its Downloads folder with the app, read-only (`XBT_UI_FILES_ROOT`): the
//!   owner chooses a folder under it on the Sell page ([`folders`], [`choose`]), kept in
//!   `<data dir>/files-folder`, and the server reads that choice for every request ([`shared_dir`]).
//!   The choice is held to the shared folder as the files are: no `..`, no hidden names, and no link
//!   that leads out of it.
//!
//! The listing names each file ([`list`]) with its size; buyers download a file, or open it in their
//! own player (VLC, mpv, a TV app) through a link the wallet app makes ([`crate::relay`]).
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use xbt_svc::http::{Reply, Request, Response, Streamed};

/// The header the gateway's route adds, and the server asks for.
pub const KEY_HEADER: &str = "x-stream-files-key";
/// At most this many files are listed (the listing's own limit is 400 items a service).
pub const MAX_FILES: usize = 400;
/// Folders deeper than this are not looked into.
const MAX_DEPTH: usize = 4;

/// The files under `dir`, as `(path relative to dir with '/', size in bytes)`, sorted by path. Hidden
/// names and anything that is not a regular file are left out.
pub fn list(dir: &Path) -> Vec<(String, u64)> {
    fn walk(base: &Path, at: &Path, depth: usize, out: &mut Vec<(String, u64)>) {
        let Ok(rd) = std::fs::read_dir(at) else { return };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            if out.len() >= MAX_FILES {
                return;
            }
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            let Ok(meta) = std::fs::metadata(e.path()) else { continue };
            let Some(rel) = inside(base, &e.path()) else { continue };
            if meta.is_dir() && depth < MAX_DEPTH {
                walk(base, &e.path(), depth + 1, out);
            } else if meta.is_file() {
                out.push((rel, meta.len()));
            }
        }
    }
    let mut out = vec![];
    walk(dir, dir, 0, &mut out);
    out
}

/// `path` relative to `base` with `/`, when it is under `base` once links are followed.
fn inside(base: &Path, path: &Path) -> Option<String> {
    let (b, p) = (std::fs::canonicalize(base).ok()?, std::fs::canonicalize(path).ok()?);
    let rel = p.strip_prefix(&b).ok()?;
    let parts: Vec<String> = rel.components().map(|c| c.as_os_str().to_string_lossy().to_string()).collect();
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// A file's size in plain words: `850 KB`, `1.4 GB`.
pub fn size_words(n: u64) -> String {
    let (v, unit) = match n {
        n if n >= 1_000_000_000 => (n as f64 / 1e9, "GB"),
        n if n >= 1_000_000 => (n as f64 / 1e6, "MB"),
        n if n >= 1_000 => (n as f64 / 1e3, "KB"),
        n => return format!("{n} bytes"),
    };
    if v >= 100.0 { format!("{v:.0} {unit}") } else { format!("{v:.1} {unit}") }
}

/// The most bytes a size worded by [`size_words`] can stand for: `1.4 GB` is at most 1.45 GB, and
/// `276 MB` at most 276.5 MB. `None`: not a size in those words.
pub fn size_most(words: &str) -> Option<u64> {
    let (n, unit) = words.trim().split_once(' ')?;
    let mult: f64 = match unit {
        "bytes" => return n.parse().ok(),
        "KB" => 1e3,
        "MB" => 1e6,
        "GB" => 1e9,
        _ => return None,
    };
    let v: f64 = n.parse().ok().filter(|v: &f64| v.is_finite() && *v >= 0.0)?;
    // half of the last digit shown: one decimal below 100, whole units from 100
    let half = if n.contains('.') { 0.05 } else { 0.5 };
    Some(((v + half) * mult).ceil() as u64)
}

/// The URL path of a listed file: each part percent-encoded.
pub fn url_path(rel: &str) -> String {
    rel.split('/').map(crate::services::urlenc).collect::<Vec<_>>().join("/")
}

fn decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The file a request path names, if it is a listed one: a regular file under `dir`.
pub fn resolve(dir: &Path, path: &str) -> Option<PathBuf> {
    let rel = decode(path.trim_start_matches('/'))?;
    if rel.is_empty() || rel.split('/').any(|p| p.is_empty() || p.starts_with('.') || p.contains('\\') || p.contains('\0')) {
        return None;
    }
    let p = dir.join(&rel);
    let name = inside(dir, &p)?;
    (name == rel && std::fs::metadata(&p).ok()?.is_file()).then_some(p)
}

/// At most this many folders are offered to choose from.
pub const MAX_FOLDERS: usize = 200;

/// The folders under `root` the owner may choose to share, relative with `/`, sorted; `""` (the whole
/// of `root`) first. Hidden names and links that lead out of `root` are left out.
pub fn folders(root: &Path) -> Vec<String> {
    fn walk(base: &Path, at: &Path, depth: usize, out: &mut Vec<String>) {
        let Ok(rd) = std::fs::read_dir(at) else { return };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            if out.len() >= MAX_FOLDERS {
                return;
            }
            if e.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            if !std::fs::metadata(e.path()).map(|m| m.is_dir()).unwrap_or(false) {
                continue;
            }
            // a folder is offered by its own name: a link to another folder under the root is not
            // offered again, and one that leads out of the root is not offered at all
            let named = match at.strip_prefix(base).ok().and_then(|p| p.to_str()) {
                Some("") | None => e.file_name().to_string_lossy().to_string(),
                Some(p) => format!("{p}/{}", e.file_name().to_string_lossy()),
            };
            let Some(rel) = inside(base, &e.path()) else { continue };
            if rel != named {
                continue;
            }
            out.push(rel);
            if depth + 1 < MAX_DEPTH {
                walk(base, &e.path(), depth + 1, out);
            }
        }
    }
    if !root.is_dir() {
        return vec![];
    }
    let mut out = vec![String::new()];
    walk(root, root, 0, &mut out);
    out
}

/// The folder `rel` names under `root`, when it is one the owner may choose: `""` is `root` itself;
/// otherwise plain names joined by `/` (no `..`, no hidden names, nothing absolute), naming a folder
/// that is under `root` once links are followed.
pub fn choose(root: &Path, rel: &str) -> Option<PathBuf> {
    let rel = rel.trim().trim_matches('/');
    if rel.is_empty() {
        return root.is_dir().then(|| root.to_path_buf());
    }
    if rel.split('/').any(|p| p.is_empty() || p.starts_with('.') || p.contains('\\') || p.contains('\0')) {
        return None;
    }
    let p = root.join(rel);
    (inside(root, &p)? == rel && std::fs::metadata(&p).ok()?.is_dir()).then_some(p)
}

/// The folder a Files service shares now: the owner's choice under [`crate::config::FilesSetup::root`]
/// when the box shares one with the app, else `dir`. `None`: the choice is not a folder it may share
/// (gone, or leading out of the root), so nothing is served or listed.
pub fn shared_dir(setup: &crate::config::FilesSetup) -> Option<PathBuf> {
    match &setup.root {
        None => Some(setup.dir.clone()),
        Some(root) => choose(root, &std::fs::read_to_string(&setup.choice).unwrap_or_default()),
    }
}

/// Keeps the owner's choice of folder, once [`choose`] allows it.
pub fn save_choice(setup: &crate::config::FilesSetup, rel: &str) -> Result<(), String> {
    let root = setup.root.as_ref().ok_or("This box has no shared folder to choose from.")?;
    let rel = rel.trim().trim_matches('/');
    choose(root, rel).ok_or("That folder can't be shared: choose one from the list.")?;
    if let Some(d) = setup.choice.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    std::fs::write(&setup.choice, format!("{rel}\n")).map_err(|e| format!("{}: {e}", setup.choice.display()))
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase).as_deref() {
        Some("mp4" | "m4v") => "video/mp4",
        Some("mkv") => "video/x-matroska",
        Some("webm") => "video/webm",
        Some("mov") => "video/quicktime",
        Some("avi") => "video/x-msvideo",
        Some("mp3") => "audio/mpeg",
        Some("m4a") => "audio/mp4",
        Some("flac") => "audio/flac",
        Some("ogg" | "oga") => "audio/ogg",
        Some("wav") => "audio/wav",
        Some("pdf") => "application/pdf",
        Some("epub") => "application/epub+zip",
        Some("zip") => "application/zip",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("srt") => "application/x-subrip",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// One plain byte range of a file of `len` bytes: `bytes=N-`, `bytes=N-M` or `bytes=-N`.
/// `Some(Err)`: a range that cannot be served (`416`).
fn range_of(h: Option<&str>, len: u64) -> Option<Result<(u64, u64), ()>> {
    let spec = h?.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None; // several ranges: the whole file
    }
    let (a, b) = spec.split_once('-')?;
    let (a, b) = (a.trim(), b.trim());
    let r = if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        if n == 0 || len == 0 { return Some(Err(())) }
        (len.saturating_sub(n), len - 1)
    } else {
        let s: u64 = a.parse().ok()?;
        let e = if b.is_empty() { len.saturating_sub(1) } else { b.parse::<u64>().ok()?.min(len.saturating_sub(1)) };
        if s >= len || e < s { return Some(Err(())) }
        (s, e)
    };
    Some(Ok(r))
}

/// The folder's server.
pub struct Server {
    /// Where the shared folder is: read for every request, so a new choice applies at once.
    pub setup: crate::config::FilesSetup,
    pub key: String,
    /// Blossom by hash (`XBT_UI_FILES_BLOSSOM=1`, [`crate::blossom`]): `None`, off.
    pub blossom: Option<std::sync::Arc<crate::blossom::Index>>,
}

impl Server {
    /// The server, with its Blossom index started when [`crate::config::FilesSetup::blossom`] is on.
    pub fn new(setup: crate::config::FilesSetup, key: String) -> Self {
        let blossom = setup.blossom.then(|| std::sync::Arc::new(crate::blossom::Index::default()));
        if let (Some(ix), Some(dir)) = (&blossom, shared_dir(&setup)) {
            ix.refresh_soon(dir, true);
        }
        Self { setup, key, blossom }
    }
}

impl xbt_svc::http::Handler for Server {
    fn body_limit(&self, _: &str, _: &str) -> usize {
        0
    }

    fn handle(&self, _: Request) -> Response {
        Response::text(405, "text/plain", "method not allowed")
    }

    fn reply(&self, req: Request) -> Reply {
        let method = req.method.to_ascii_uppercase();
        if method != "GET" && method != "HEAD" {
            return Reply::Whole(Response::text(405, "text/plain", "method not allowed"));
        }
        if req.path() == "/" {
            return Reply::Whole(Response::new(204, vec![], vec![]));
        }
        let given = req.header(KEY_HEADER).unwrap_or("");
        if self.key.is_empty() || !crate::ct_eq(given.as_bytes(), self.key.as_bytes()) {
            return Reply::Whole(Response::text(403, "text/plain", "forbidden"));
        }
        let Some(dir) = shared_dir(&self.setup) else {
            return Reply::Whole(Response::text(404, "text/plain", "no such file"));
        };
        // a file by its name first, as before; then, with Blossom on, by the hash of its content
        let mut by_hash = None;
        let path = match resolve(&dir, req.path()) {
            Some(p) => p,
            None => match (&self.blossom, crate::blossom::hash_of_path(req.path())) {
                (Some(ix), Some(h)) => match ix.lookup(&dir, &h) {
                    Some(p) => {
                        by_hash = Some((ix.clone(), h));
                        p
                    }
                    None => {
                        ix.refresh_soon(dir.clone(), false);
                        return Reply::Whole(Response::new(404, vec![("Access-Control-Allow-Origin".into(), "*".into()),
                                                                    ("X-Reason".into(), "no blob with that hash here".into())],
                                                          b"no such blob".to_vec()));
                    }
                },
                _ => return Reply::Whole(Response::text(404, "text/plain", "no such file")),
            },
        };
        let Ok(mut f) = std::fs::File::open(&path) else {
            return Reply::Whole(Response::text(404, "text/plain", "no such file"));
        };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        let mut headers = vec![("Content-Type".to_string(), content_type(&path).to_string()), ("Accept-Ranges".into(), "bytes".into())];
        if by_hash.is_some() {
            // BUD-01: every answer may be read from any origin
            headers.push(("Access-Control-Allow-Origin".into(), "*".into()));
        }
        let (status, start, end) = match range_of(req.header("range"), len) {
            Some(Ok((s, e))) => {
                headers.push(("Content-Range".into(), format!("bytes {s}-{e}/{len}")));
                (206, s, e)
            }
            Some(Err(())) => {
                return Reply::Whole(Response::new(416, vec![("Content-Range".into(), format!("bytes */{len}"))], vec![]));
            }
            None => (200, 0, len.saturating_sub(1)),
        };
        let length = if len == 0 { 0 } else { end - start + 1 };
        if f.seek(SeekFrom::Start(start)).is_err() {
            return Reply::Whole(Response::text(500, "text/plain", "could not read the file"));
        }
        // a whole file sent by hash is hashed again as it goes: bytes that are not the hash's end short
        let mut check = by_hash.filter(|_| status == 200 && method == "GET").map(|(ix, h)| (ix, crate::blossom::Check::new(&h), dir, path.clone()));
        Reply::Stream(Streamed {
            status,
            headers,
            length: Some(length),
            body: Box::new(move |out: &mut dyn xbt_svc::http::BodyWriter| {
                let mut left = length;
                let mut buf = vec![0u8; 64 << 10];
                while left > 0 {
                    let want = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
                    let n = f.read(&mut buf[..want])?;
                    if n == 0 {
                        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "the file got shorter"));
                    }
                    if let Some((_, c, _, _)) = check.as_mut() {
                        sha2::Digest::update(&mut c.hasher, &buf[..n]);
                    }
                    if left == n as u64 {
                        if let Some((ix, c, dir, path)) = check.take() {
                            if !c.ok() {
                                ix.forget(&dir, &path);
                                // the last bytes are held back: the client sees a cut answer, not a wrong whole one
                                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "the file no longer has the hash it was asked by"));
                            }
                        }
                    }
                    out.send(&buf[..n])?;
                    left -= n as u64;
                }
                Ok(())
            }),
        })
    }
}

/// The files key in `secrets` (made once, kept), for the server and the gateway's route.
pub fn key(secrets: &Path) -> Result<String, String> {
    let p = secrets.join("files-key");
    if let Ok(k) = std::fs::read_to_string(&p) {
        let k = k.trim().to_string();
        if k.len() >= 32 {
            return Ok(k);
        }
    }
    std::fs::create_dir_all(secrets).map_err(|e| format!("{}: {e}", secrets.display()))?;
    let k = hex::encode(crate::random_bytes::<32>());
    xbt_svc::replace_secret_file(&p, format!("{k}\n").as_bytes(), 0o600).map_err(|e| format!("{}: {e}", p.display()))?;
    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_regular_visible_files_under_the_folder_are_listed_and_served() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("Sintel.mp4"), b"0123456789").unwrap();
        std::fs::create_dir(d.path().join("Books")).unwrap();
        std::fs::write(d.path().join("Books/a b.pdf"), b"pdf").unwrap();
        std::fs::write(d.path().join(".secret"), b"no").unwrap();
        let out = tempfile::tempdir().unwrap();
        std::fs::write(out.path().join("outside.txt"), b"no").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(out.path().join("outside.txt"), d.path().join("link.txt")).unwrap();
        assert_eq!(list(d.path()), [("Books/a b.pdf".to_string(), 3), ("Sintel.mp4".to_string(), 10)]);
        assert!(resolve(d.path(), "/Books/a%20b.pdf").is_some());
        for bad in ["/../x", "/.secret", "/link.txt", "/Books", "/Books/../Sintel.mp4", "/", "/%2e%2e/x", "/Books//a%20b.pdf"] {
            assert!(resolve(d.path(), bad).is_none(), "{bad}");
        }
        assert_eq!(url_path("Books/a b.pdf"), "Books/a%20b.pdf");
    }

    fn setup(root: &Path, choice: &Path) -> crate::config::FilesSetup {
        crate::config::FilesSetup { dir: PathBuf::from("/nonexistent"), root: Some(root.to_path_buf()), choice: choice.to_path_buf(), ..Default::default() }
    }

    #[test]
    fn the_owner_chooses_only_a_folder_under_the_shared_root() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("Films/4K")).unwrap();
        std::fs::create_dir(root.path().join(".hidden")).unwrap();
        std::fs::write(root.path().join("Films/4K/Sintel.mkv"), b"film").unwrap();
        std::fs::write(root.path().join("notes.txt"), b"x").unwrap();
        let out = tempfile::tempdir().unwrap();
        std::fs::create_dir(out.path().join("private")).unwrap();
        std::fs::write(out.path().join("private/wallet.dat"), b"secret").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(out.path().join("private"), root.path().join("escape")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.path().join("Films"), root.path().join("alias")).unwrap();

        // what the picker offers: the whole root, its folders, never a hidden one or a link out of it
        let offered = folders(root.path());
        assert_eq!(offered[0], "");
        assert!(offered.contains(&"Films".to_string()) && offered.contains(&"Films/4K".to_string()), "{offered:?}");
        assert!(!offered.iter().any(|f| f.contains("escape") || f.contains(".hidden") || f.contains("private") || f.contains("alias")), "{offered:?}");
        assert_eq!(offered.iter().filter(|f| *f == "Films").count(), 1, "a link to a folder is not offered twice");
        assert!(!offered.iter().any(|f| f == "notes.txt"), "files are not folders");

        assert_eq!(choose(root.path(), "Films/4K"), Some(root.path().join("Films/4K")));
        assert_eq!(choose(root.path(), "/Films/"), Some(root.path().join("Films")));
        assert_eq!(choose(root.path(), ""), Some(root.path().to_path_buf()));
        for bad in ["escape", "escape/..", "..", "../x", "Films/../..", ".hidden", "Films//4K", "notes.txt", "Missing", "alias",
                    "/etc", "Films\\4K", "Films/\0"] {
            assert_eq!(choose(root.path(), bad), None, "{bad}");
        }
    }

    #[test]
    fn the_server_serves_the_chosen_folder_and_nothing_once_the_choice_leads_out() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("Films")).unwrap();
        std::fs::write(root.path().join("Films/Sintel.mkv"), b"film").unwrap();
        std::fs::write(root.path().join("top.txt"), b"top").unwrap();
        let out = tempfile::tempdir().unwrap();
        std::fs::write(out.path().join("wallet.dat"), b"secret").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(out.path(), root.path().join("escape")).unwrap();
        let data = tempfile::tempdir().unwrap();
        let s = setup(root.path(), &data.path().join("files-folder"));

        // no choice yet: the whole shared root
        assert_eq!(shared_dir(&s), Some(root.path().to_path_buf()));
        save_choice(&s, "Films").unwrap();
        let dir = shared_dir(&s).unwrap();
        assert_eq!(list(&dir), [("Sintel.mkv".to_string(), 4)]);
        assert!(resolve(&dir, "/../top.txt").is_none(), "nothing above the chosen folder");

        // a choice that leads out is refused, and one written behind the page's back shares nothing
        assert!(save_choice(&s, "escape").is_err());
        assert!(save_choice(&s, "../").is_err());
        std::fs::write(&s.choice, "escape\n").unwrap();
        assert_eq!(shared_dir(&s), None);
        std::fs::write(&s.choice, "../../\n").unwrap();
        assert_eq!(shared_dir(&s), None);
        // without a shared root the owner has nothing to choose
        let plain = crate::config::FilesSetup { dir: root.path().to_path_buf(), ..Default::default() };
        assert!(save_choice(&plain, "Films").is_err());
        assert_eq!(shared_dir(&plain), Some(root.path().to_path_buf()));
    }

    #[test]
    fn ranges_are_one_plain_byte_range_or_the_whole_file() {
        assert_eq!(range_of(Some("bytes=2-"), 10), Some(Ok((2, 9))));
        assert_eq!(range_of(Some("bytes=2-4"), 10), Some(Ok((2, 4))));
        assert_eq!(range_of(Some("bytes=-3"), 10), Some(Ok((7, 9))));
        assert_eq!(range_of(Some("bytes=5-100"), 10), Some(Ok((5, 9))));
        assert_eq!(range_of(Some("bytes=10-"), 10), Some(Err(())));
        assert_eq!(range_of(Some("bytes=0-1,4-5"), 10), None);
        assert_eq!(range_of(None, 10), None);
        assert_eq!((size_words(850), size_words(1_400_000_000), size_words(2_500_000)), ("850 bytes".into(), "1.4 GB".into(), "2.5 MB".into()));
        // the most each wording can stand for is never below the size it was made from
        for n in [0u64, 850, 999, 1_000, 1_449, 99_949_999, 276_499_999, 1_449_999_999, 123_456_789_012] {
            let most = size_most(&size_words(n)).unwrap();
            assert!(most >= n && most <= n + n / 20 + 1_000, "{n} -> {most}");
        }
        assert_eq!(size_most("1.4 GB"), Some(1_450_000_000));
        assert_eq!(size_most("276 MB"), Some(276_500_000));
        assert_eq!(size_most("plenty"), None);
    }

    /// Blossom on: a file is served by the SHA-256 of its content as well as by its name, with the
    /// same key; a hash it does not have is a 404 with a reason; a file changed in place behind the
    /// index's back is cut short, never sent whole under a hash that is not its. Off: no hash path.
    #[test]
    fn with_blossom_on_a_file_is_served_by_its_hash_and_never_whole_under_a_wrong_one() {
        use sha2::Digest;
        use xbt_svc::http::Handler;
        struct Out(Vec<u8>);
        impl xbt_svc::http::BodyWriter for Out {
            fn send(&mut self, b: &[u8]) -> std::io::Result<()> {
                self.0.extend_from_slice(b);
                Ok(())
            }
        }
        let get = |s: &Server, method: &str, target: &str, key: &str, range: Option<&str>| {
            let mut headers = vec![(KEY_HEADER.to_string(), key.to_string())];
            if let Some(r) = range {
                headers.push(("Range".into(), r.into()));
            }
            match s.reply(Request { method: method.into(), target: target.into(), headers, body: vec![], peer: None }) {
                Reply::Whole(r) => (r.status, r.headers, Ok(r.body)),
                Reply::Stream(st) => {
                    let mut out = Out(vec![]);
                    let r = (st.body)(&mut out);
                    (st.status, st.headers, r.map(|_| out.0))
                }
            }
        };
        let hdr = |h: &[(String, String)], k: &str| h.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.clone());
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("Sintel.mkv"), b"0123456789").unwrap();
        let h = hex::encode(sha2::Sha256::digest(b"0123456789"));
        let setup = crate::config::FilesSetup { dir: d.path().to_path_buf(), blossom: true, ..Default::default() };
        let s = Server { setup: setup.clone(), key: "k".repeat(32), blossom: Some(std::sync::Arc::new(crate::blossom::Index::default())) };
        s.blossom.as_ref().unwrap().refresh(d.path());
        let key = "k".repeat(32);

        let (st, hs, body) = get(&s, "GET", &format!("/{h}.mkv"), &key, None);
        assert_eq!((st, body.unwrap()), (200, b"0123456789".to_vec()));
        assert_eq!(hdr(&hs, "content-type").as_deref(), Some("video/x-matroska"), "the type is the file's");
        assert_eq!(hdr(&hs, "access-control-allow-origin").as_deref(), Some("*"));
        let (st, _, body) = get(&s, "GET", &format!("/{h}"), &key, Some("bytes=2-4"));
        assert_eq!((st, body.unwrap()), (206, b"234".to_vec()), "ranges as by name");
        assert_eq!(get(&s, "HEAD", &format!("/{h}"), &key, None).0, 200);
        assert_eq!(get(&s, "GET", "/Sintel.mkv", &key, None).0, 200, "by name as before");
        assert_eq!(get(&s, "GET", &format!("/{h}"), "wrong", None).0, 403, "the files key is still needed");
        let (st, hs, _) = get(&s, "GET", &format!("/{}", "0".repeat(64)), &key, None);
        assert_eq!(st, 404);
        assert!(hdr(&hs, "x-reason").is_some());

        // changed in place, keeping its size and time: the index still names it, the bytes are not the hash's
        let mtime = std::fs::metadata(d.path().join("Sintel.mkv")).unwrap().modified().unwrap();
        std::fs::write(d.path().join("Sintel.mkv"), b"9876543210").unwrap();
        std::fs::File::options().write(true).open(d.path().join("Sintel.mkv")).unwrap().set_modified(mtime).unwrap();
        let (st, _, body) = get(&s, "GET", &format!("/{h}"), &key, None);
        assert_eq!(st, 200);
        assert!(body.is_err(), "cut short, not a whole wrong file");
        assert_eq!(get(&s, "GET", &format!("/{h}"), &key, None).0, 404, "and the hash is forgotten");

        // off (the default): a hash path is just a name no file has
        let off = Server::new(crate::config::FilesSetup { blossom: false, ..setup }, key.clone());
        assert!(off.blossom.is_none());
        let h2 = hex::encode(sha2::Sha256::digest(b"9876543210"));
        let (st, hs, _) = get(&off, "GET", &format!("/{h2}"), &key, None);
        assert_eq!(st, 404);
        assert!(hdr(&hs, "x-reason").is_none());
    }
}
