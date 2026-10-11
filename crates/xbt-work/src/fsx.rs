//! Durable, private state files: write a temporary file (mode 0600 on Unix), fsync it, rename it
//! over the old one. The provider records every debit this way before its handler runs (§9.2).
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

/// The rule (AGP-097): **the file is the operator's alone whatever was in the directory.** The
/// temporary file is always made by this call: one that is already there (left by a copy or a
/// restore, or put there by whoever can write to the directory) is removed first and the new one is
/// opened exclusively, so its mode is 0600 and it is no link to another file. Before, a temporary
/// file that was already there was written into as it was and renamed into place with its mode.
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)
}

/// Whether others than the owner can read or write `path` (always false where there are no modes).
pub fn open_to_others(path: &Path) -> std::io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(fs::metadata(path)?.permissions().mode() & 0o077 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(false)
    }
}
