//! Category blocklists a filtered exit's operator can tick, kept up to date while the exit runs.
//!
//! Each category is one public list of domain names, fetched over HTTPS, saved next to the exit's
//! other files, and loaded into the exit's [`LiveLists`]. The exit checks for a newer copy once a day
//! (`If-Modified-Since`), and keeps the last good copy if a fetch fails, so a list host being down
//! never turns filtering off. A saved copy is used at start, before any fetch.
//!
//! Sources and licences are recorded with each category ([`CATEGORIES`]): an operator, and buyers
//! reading an exit's listing, can see where a block comes from.

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::content::{DomainSet, LiveLists};

/// One category an operator can block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Category {
    /// What an exit's listing announces ("adult", "gambling"…).
    pub id: &'static str,
    /// In plain words, for the Sell page.
    pub name: &'static str,
    pub url: &'static str,
    /// Who keeps the list.
    pub source: &'static str,
    /// The list's licence, as its publisher states it.
    pub licence: &'static str,
}

const BLP: &str = "The Block List Project (github.com/blocklistproject/Lists)";
const BLP_LICENCE: &str = "The Unlicense (repository); the list files' headers say MIT";

/// The categories an operator can choose from.
pub const CATEGORIES: &[Category] = &[
    Category { id: "adult", name: "Adult content", url: "https://blocklistproject.github.io/Lists/alt-version/porn-nl.txt", source: BLP, licence: BLP_LICENCE },
    Category { id: "gambling", name: "Gambling", url: "https://blocklistproject.github.io/Lists/alt-version/gambling-nl.txt", source: BLP, licence: BLP_LICENCE },
    Category { id: "malware", name: "Malware", url: "https://blocklistproject.github.io/Lists/alt-version/malware-nl.txt", source: BLP, licence: BLP_LICENCE },
    Category { id: "phishing", name: "Phishing", url: "https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt", source: BLP, licence: BLP_LICENCE },
    Category { id: "scam", name: "Scams", url: "https://blocklistproject.github.io/Lists/alt-version/scam-nl.txt", source: BLP, licence: BLP_LICENCE },
];

/// How often an exit looks for newer lists.
pub const UPDATE_EVERY: Duration = Duration::from_secs(24 * 60 * 60);
/// The largest list an exit downloads.
const MAX_LIST_BYTES: u64 = 96 * 1024 * 1024;

pub fn category(id: &str) -> Option<&'static Category> {
    CATEGORIES.iter().find(|c| c.id == id)
}

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

fn list_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.txt"))
}

fn stamp_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.last-modified"))
}

/// What a fetch did.
#[derive(Debug, PartialEq, Eq)]
pub enum Fetched {
    /// A new copy was saved.
    Updated,
    /// The saved copy is current.
    Unchanged,
}

/// Fetches one list from `url` into `dir`, only if it changed since the saved copy. HTTPS only
/// (plain HTTP to this machine, for tests). The saved copy is replaced whole, never half-written.
pub fn fetch(id: &str, url: &str, dir: &Path) -> io::Result<Fetched> {
    let local = url.starts_with("http://127.0.0.1") || url.starts_with("http://localhost");
    if !url.starts_with("https://") && !local {
        return Err(io_err("a list is fetched over HTTPS only"));
    }
    std::fs::create_dir_all(dir)?;
    let mut req = ureq::get(url).timeout(Duration::from_secs(120));
    let stamp = std::fs::read_to_string(stamp_path(dir, id)).ok();
    if let Some(s) = stamp.as_deref().filter(|_| list_path(dir, id).exists()) {
        req = req.set("If-Modified-Since", s.trim());
    }
    let resp = match req.call() {
        Ok(r) => r,
        Err(ureq::Error::Status(304, _)) => return Ok(Fetched::Unchanged),
        Err(e) => return Err(io_err(e)),
    };
    if resp.status() == 304 {
        return Ok(Fetched::Unchanged);
    }
    let modified = resp.header("Last-Modified").map(str::to_string);
    let mut body = Vec::new();
    resp.into_reader().take(MAX_LIST_BYTES + 1).read_to_end(&mut body)?;
    if body.len() as u64 > MAX_LIST_BYTES {
        return Err(io_err("a list larger than an exit takes"));
    }
    let tmp = dir.join(format!(".{id}.txt.part"));
    std::fs::write(&tmp, &body)?;
    std::fs::rename(&tmp, list_path(dir, id))?;
    match modified {
        Some(m) => std::fs::write(stamp_path(dir, id), m)?,
        None => {
            let _ = std::fs::remove_file(stamp_path(dir, id));
        }
    }
    Ok(Fetched::Updated)
}

/// The names of the saved copies of these categories (a missing copy adds nothing).
pub fn load(ids: &[String], dir: &Path) -> DomainSet {
    let mut d = DomainSet::default();
    for id in ids {
        if let Ok(text) = std::fs::read_to_string(list_path(dir, id)) {
            d.add_list(&text);
        }
    }
    d
}

/// Keeps `lists` filled with these categories: loads the saved copies at once, then fetches newer
/// ones now and every [`UPDATE_EVERY`], loading again after any update. Runs on its own thread for
/// the life of the exit. `url_for` gives each category's address (the catalogue's, or a test's).
pub fn keep_updated(ids: Vec<String>, dir: PathBuf, lists: LiveLists, every: Duration, url_for: fn(&str) -> Option<String>) -> std::thread::JoinHandle<()> {
    lists.replace(load(&ids, &dir));
    std::thread::Builder::new()
        .name("vpn-lists".into())
        .spawn(move || loop {
            let mut updated = false;
            for id in &ids {
                if let Some(url) = url_for(id) {
                    // a failed fetch keeps the last good copy: filtering never turns off by itself
                    if matches!(fetch(id, &url, &dir), Ok(Fetched::Updated)) {
                        updated = true;
                    }
                }
            }
            if updated {
                lists.replace(load(&ids, &dir));
            }
            std::thread::sleep(every);
        })
        .expect("a thread for the lists")
}

/// The catalogue's address for a category.
pub fn catalogue_url(id: &str) -> Option<String> {
    category(id).map(|c| c.url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    /// A server that answers every request with `body` and a Last-Modified, or 304 when asked
    /// If-Modified-Since.
    fn server(body: &'static str) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut c in l.incoming().flatten() {
                let mut buf = [0u8; 4096];
                let n = c.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                let resp = if req.contains("if-modified-since") {
                    "HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                } else {
                    format!("HTTP/1.1 200 OK\r\nLast-Modified: Thu, 29 Oct 2026 00:00:00 GMT\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                };
                let _ = c.write_all(resp.as_bytes());
            }
        });
        format!("http://127.0.0.1:{port}/list.txt")
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("xbt-vpn-lists-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn every_category_names_its_source_and_licence() {
        for c in CATEGORIES {
            assert!(c.url.starts_with("https://") && !c.source.is_empty() && !c.licence.is_empty(), "{}", c.id);
        }
        assert_eq!(category("adult").map(|c| c.name), Some("Adult content"));
        assert!(category("nope").is_none());
    }

    #[test]
    fn a_list_is_fetched_once_then_only_when_it_changed() {
        let dir = tmpdir("fetch");
        let url = server("# a list\nbad.example\n0.0.0.0 worse.example\n");
        assert_eq!(fetch("adult", &url, &dir).unwrap(), Fetched::Updated);
        assert_eq!(fetch("adult", &url, &dir).unwrap(), Fetched::Unchanged);
        let d = load(&["adult".into()], &dir);
        assert!(d.matches("www.bad.example") && d.matches("worse.example") && !d.matches("fine.example"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_https_lists_are_fetched() {
        assert!(fetch("adult", "http://lists.example/porn.txt", &tmpdir("https")).is_err());
    }

    #[test]
    fn a_failed_fetch_keeps_the_last_good_copy() {
        let dir = tmpdir("keep");
        let url = server("kept.example\n");
        fetch("gambling", &url, &dir).unwrap();
        // the list host is gone: the fetch fails, the saved copy stays and still blocks
        assert!(fetch("gambling", "http://127.0.0.1:9/list.txt", &dir).is_err());
        assert!(load(&["gambling".into()], &dir).matches("kept.example"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_updater_fills_the_live_lists() {
        let dir = tmpdir("live");
        static URL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        URL.get_or_init(|| server("live.example\n"));
        let lists = LiveLists::default();
        let _t = keep_updated(vec!["scam".into()], dir.clone(), lists.clone(), Duration::from_secs(3600), |_| URL.get().cloned());
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !lists.matches("live.example") && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(lists.matches("a.live.example"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
