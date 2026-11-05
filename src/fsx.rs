//! File helpers: atomic writes and directory creation.
//!
//! R37: every state transition is a file written by atomic rename (or a
//! kernel lock released on process death), so a process killed at any point
//! leaves either the old file or the new one, never a partial one.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// A name part that is unique in this process and very likely across processes:
/// `<pid>-<unix nanos>-<sequence>`.
#[must_use]
pub fn unique_suffix() -> String {
    format!(
        "{}-{}-{}",
        std::process::id(),
        unix_nanos(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// Nanoseconds since the Unix epoch (0 when the clock is before it).
#[must_use]
pub fn unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// Creates `dir` and its parents.
pub fn ensure_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)
}

/// The temporary sibling path used by [`write_atomic`] for `path`.
fn temp_sibling(path: &Path) -> io::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("no file name in {}", path.display()),
        )
    })?;
    let mut tmp = std::ffi::OsString::from(".");
    tmp.push(name);
    tmp.push(".tmp-");
    tmp.push(unique_suffix());
    Ok(path.with_file_name(tmp))
}

/// Writes `bytes` to `path` by writing a temporary sibling, syncing it and
/// renaming it over `path`; then syncs the directory. Creates the parent dir.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    ensure_dir(parent)?;
    let tmp = temp_sibling(path)?;
    let result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        // The rename is durable only after the directory entry is synced.
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Reads `path`; `Ok(None)` when it does not exist.
pub fn read_optional(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_creates_parents_and_replaces() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("a/b/c.json");
        write_atomic(&path, b"one").unwrap();
        write_atomic(&path, b"two").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        // No temporary files stay behind.
        let names: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("c.json")]);
    }

    #[test]
    fn read_optional_maps_missing_to_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(read_optional(&tmp.path().join("nope")).unwrap(), None);
        fs::write(tmp.path().join("yes"), b"x").unwrap();
        assert_eq!(
            read_optional(&tmp.path().join("yes")).unwrap(),
            Some(b"x".to_vec())
        );
    }

    #[test]
    fn unique_suffixes_differ() {
        assert_ne!(unique_suffix(), unique_suffix());
    }
}
