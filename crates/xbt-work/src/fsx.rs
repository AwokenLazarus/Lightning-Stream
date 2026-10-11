//! Durable, private state files: write a temporary file (mode 0600 on Unix), fsync it, rename it
//! over the old one, fsync the directory. The provider records every debit this way before its
//! handler runs (§9.2).
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
    fs::rename(&tmp, path)?;
    sync_dir(path)
}

/// fsync the directory holding `path`, so the rename stays after a power loss (AGP-106; the step
/// `xbt-signer`'s `fsx` has). Before, the file was synced and its new name was not: a power loss
/// could bring back the state of a few seconds earlier, and the calls served since were not
/// debited. An error here is the write's error although the new file is in place: its caller must
/// not take the state for durable. Unix only: elsewhere a directory cannot be opened for this.
fn sync_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let dir = match path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        fs::File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// The directory sync can only be shown by a power cut; this pins that the step does not break
    /// the write: the file is there, whole and private, and replaced by the next write.
    #[test]
    fn a_private_write_lands_whole_and_private_with_the_directory_synced() {
        let dir = std::env::temp_dir().join(format!("xbt-work-agp106-fsx-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        for body in [&b"one"[..], &b"two"[..]] {
            write_private(&path, body).unwrap();
            assert_eq!(fs::read(&path).unwrap(), body);
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            assert!(!path.with_extension("tmp").exists());
        }
        assert!(write_private(&dir.join("missing").join("state.json"), b"x").is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
