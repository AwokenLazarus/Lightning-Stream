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
    pub dir: PathBuf,
    pub key: String,
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
        let Some(path) = resolve(&self.dir, req.path()) else {
            return Reply::Whole(Response::text(404, "text/plain", "no such file"));
        };
        let Ok(mut f) = std::fs::File::open(&path) else {
            return Reply::Whole(Response::text(404, "text/plain", "no such file"));
        };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        let mut headers = vec![("Content-Type".to_string(), content_type(&path).to_string()), ("Accept-Ranges".into(), "bytes".into())];
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
    }
}
