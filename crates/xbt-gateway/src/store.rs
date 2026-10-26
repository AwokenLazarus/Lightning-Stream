//! The journal: one JSON record per line, appended. What must be on disk before the gateway goes
//! on is synced by the caller ([`Store::handle`]); everything else is synced by the janitor, so a
//! paid request writes nothing. A journal is rewritten whole (a snapshot) at start and when it has
//! grown, never edited in place.
//!
//! Two journals share a state directory: the tickets' (`journal.jsonl`, [`crate::book::Rec`]),
//! whose store holds the directory's lock, and the lottery's (`lottery.jsonl`,
//! [`crate::lottery::Rec`]), opened beside it.
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::Value;

/// One line of a journal.
pub trait Record: Sized {
    fn to_json(&self) -> Value;
    /// `None`: not a record this version writes. A journal with such a line is not loaded.
    fn from_json(v: &Value) -> Option<Self>;
}

pub struct Store<R: Record = crate::book::Rec> {
    path: PathBuf,
    file: Arc<File>,
    /// Held for the life of the process by the tickets' store: one gateway per state directory.
    lock: Option<File>,
    /// Closed: nothing more is written.
    closed: bool,
    lines: u64,
    records: PhantomData<fn() -> R>,
}

/// A journal longer than this many records is rewritten as a snapshot at the next tick.
pub const COMPACT_AT: u64 = 50_000;

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

impl Store<crate::book::Rec> {
    /// Open the tickets' journal in `dir` (made when missing, private to its owner), take the
    /// directory's lock, and read it.
    pub fn open(dir: &Path) -> io::Result<(Self, Vec<crate::book::Rec>)> {
        xbt_svc::ensure_dir(dir, 0o700)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("lock"))?;
        lock.try_lock().map_err(|_| {
            invalid(format!(
                "{}: another gateway is running on this state directory",
                dir.display()
            ))
        })?;
        Self::read(dir.join("journal.jsonl"), Some(lock))
    }
}

impl<R: Record> Store<R> {
    /// Open another journal of a state directory whose lock this process holds already (the
    /// tickets' store took it), and read it.
    pub fn open_beside(dir: &Path, name: &str) -> io::Result<(Self, Vec<R>)> {
        Self::read(dir.join(name), None)
    }

    /// Read a journal and open it for appending. A last line with no newline is a write the
    /// process did not finish, and is dropped; any other line that is not a record is an error:
    /// nothing is served on a journal that cannot be read whole.
    fn read(path: PathBuf, lock: Option<File>) -> io::Result<(Self, Vec<R>)> {
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e),
        };
        let whole = match text.rfind('\n') {
            Some(i) => &text[..=i],
            None => "",
        };
        let mut recs = vec![];
        for (i, line) in whole.lines().enumerate() {
            let rec = serde_json::from_str(line)
                .ok()
                .and_then(|v| R::from_json(&v));
            recs.push(rec.ok_or_else(|| {
                invalid(format!(
                    "{}: line {} is not a record",
                    path.display(),
                    i + 1
                ))
            })?);
        }
        let file = Arc::new(Self::append_handle(&path)?);
        Ok((
            Self {
                path,
                file,
                lock,
                closed: false,
                lines: recs.len() as u64,
                records: PhantomData,
            },
            recs,
        ))
    }

    fn append_handle(path: &Path) -> io::Result<File> {
        let mut o = OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        o.open(path)
    }

    /// Give the state directory up: nothing more is written, and another gateway may open it.
    pub fn close(&mut self) {
        self.closed = true;
        self.lock = None;
    }

    /// Append records. They are in the file's page cache when this returns, not yet on disk.
    pub fn append(&mut self, recs: &[R]) -> io::Result<()> {
        if recs.is_empty() {
            return Ok(());
        }
        if self.closed {
            return Err(invalid("the journal is closed".into()));
        }
        let mut out = String::new();
        for r in recs {
            out.push_str(&r.to_json().to_string());
            out.push('\n');
        }
        (&*self.file).write_all(out.as_bytes())?;
        self.lines += recs.len() as u64;
        Ok(())
    }

    /// The journal's file, to sync without holding whatever guards the store: `sync_data` on it
    /// puts every record appended so far on disk.
    pub fn handle(&self) -> Arc<File> {
        self.file.clone()
    }

    pub fn lines(&self) -> u64 {
        self.lines
    }

    /// Closed by [`Store::close`]: the gateway is stopping, and nothing more is written.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Replace the journal by `recs`, whole and synced, then append to the new file.
    pub fn compact(&mut self, recs: &[R]) -> io::Result<()> {
        if self.closed {
            return Err(invalid("the journal is closed".into()));
        }
        let mut out = String::new();
        for r in recs {
            out.push_str(&r.to_json().to_string());
            out.push('\n');
        }
        xbt_svc::write_atomic(&self.path, out.as_bytes(), 0o600)?;
        // the rename itself must outlast a power cut, or later appends go to a file no name leads to
        if let Some(dir) = self.path.parent() {
            File::open(dir)?.sync_all()?;
        }
        self.file = Arc::new(Self::append_handle(&self.path)?);
        self.lines = recs.len() as u64;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::book::Rec;

    #[test]
    fn a_journal_is_read_back_whole_and_a_torn_last_line_is_dropped() {
        let d = tempfile::tempdir().unwrap();
        let recs = vec![
            Rec::Session {
                id: "ab".into(),
                key: [1; 32],
                addr: "v4:192.0.2.1".into(),
            },
            Rec::Ticket {
                hash: [2; 32],
                session: "ab".into(),
                prepaid: false,
                msat: None,
            },
        ];
        {
            let (mut s, old) = Store::open(d.path()).unwrap();
            assert!(old.is_empty());
            // one gateway per state directory
            assert!(Store::open(d.path())
                .err()
                .unwrap()
                .to_string()
                .contains("another gateway"));
            s.append(&recs).unwrap();
            s.handle().sync_data().unwrap();
            assert_eq!(s.lines(), 2);
        }
        let path = d.path().join("journal.jsonl");
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"t\": \"gone\", \"hash\": \"02").unwrap();
        drop(f);
        {
            let (mut s, back) = Store::open(d.path()).unwrap();
            assert_eq!(back, recs);
            s.compact(&back[..1]).unwrap();
            s.append(&[Rec::Drop {
                session: "ab".into(),
            }])
            .unwrap();
        }
        let (_, back) = Store::open(d.path()).unwrap();
        assert_eq!(
            back,
            vec![
                recs[0].clone(),
                Rec::Drop {
                    session: "ab".into()
                }
            ]
        );
        #[cfg(unix)]
        assert_eq!(xbt_svc::mode_of(&path) & 0o777, 0o600);
    }

    #[test]
    fn a_journal_with_a_line_that_is_not_a_record_is_not_loaded() {
        for bad in [
            "not json\n",
            "{\"t\": \"future\"}\n",
            "{\"t\": \"gone\", \"hash\": \"zz\"}\n{\"t\": \"drop\", \"session\": \"a\"}\n",
        ] {
            let d = tempfile::tempdir().unwrap();
            std::fs::write(d.path().join("journal.jsonl"), bad).unwrap();
            let e = Store::open(d.path()).err().unwrap();
            assert!(e.to_string().contains("is not a record"), "{bad:?}: {e}");
        }
    }
}
