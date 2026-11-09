//! The Claude Code settings file, resolved once (L10, item 29).
//!
//! `install` and `uninstall` show a diff of the file and write it after a
//! person at the terminal confirms. Between the two, a script can swap the
//! path: a symlink to another file, another file renamed over it, an edit
//! in place. So the path is resolved once: its parent dir is opened and
//! kept, the file is opened in that dir with `O_NOFOLLOW` (a symlink there
//! now is refused), and its device and inode are kept with the bytes read.
//! The backup is the bytes read, written new (`O_EXCL`, mode 0600) in the
//! same dir. The write goes to a new file in the same dir and replaces the
//! settings by `renameat` only while the name still holds the same inode
//! with the same bytes; a file that did not exist is created by `linkat`,
//! which fails when something appeared at the name meanwhile.
//!
//! Limit: no POSIX call renames only when the target is still a given
//! inode, so a swap in the microseconds between the last check and the
//! rename is not seen. The window the person's answer opened is closed.

use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use crate::fsx;

/// The settings file as read once, with the handles every later step
/// uses.
#[derive(Debug)]
pub struct SettingsFile {
    /// The path as named (settings path, or the recorded one).
    path: PathBuf,
    /// The file it led to when it was resolved (canonical dir + name).
    real: PathBuf,
    /// The parent dir, opened once.
    dir: OwnedFd,
    /// The file name in `dir`.
    name: CString,
    /// The file as opened, with its device and inode; `None` when no file
    /// was there.
    file: Option<(File, (u64, u64))>,
    /// Mode bits of the file (0600 for a new one).
    mode: u32,
    /// The bytes read.
    bytes: Vec<u8>,
}

fn c_name(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| io::Error::other("a NUL in a file name"))
}

/// `openat(dir, name, flags | O_CLOEXEC | O_NOCTTY, mode)`.
fn open_at(dir: &OwnedFd, name: &CStr, flags: libc::c_int, mode: u32) -> io::Result<File> {
    // SAFETY: `name` is NUL-terminated; `dir` is an open fd owned by the
    // caller; the returned fd is owned by the File only.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOCTTY,
            libc::c_uint::from(mode),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just opened and is owned here only.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Opens `name` in `dir` for reading, never through a symlink (`ELOOP`)
/// and never blocking on a FIFO. `None` when nothing is there.
fn open_existing(dir: &OwnedFd, name: &CStr) -> io::Result<Option<File>> {
    match open_at(
        dir,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0,
    ) {
        Ok(f) => Ok(Some(f)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn identity(f: &File) -> io::Result<(u64, u64)> {
    let m = f.metadata()?;
    Ok((m.dev(), m.ino()))
}

fn cvt(r: libc::c_int) -> io::Result<()> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Reads all of `f` from offset 0 (the cursor is not used).
fn read_all_at(f: &File, limit: u64) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    let mut off = 0u64;
    loop {
        let n = f.read_at(&mut buf, off)?;
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&buf[..n]);
        off += n as u64;
        if off > limit {
            return Ok(out);
        }
    }
}

impl SettingsFile {
    /// Resolves `path` once and reads it. A missing file reads as empty;
    /// a symlink that leads nowhere, a file that is not regular, or a
    /// parent dir that does not exist are refused.
    pub fn open(path: &Path) -> Result<Self, String> {
        let shown = path.display();
        let real = match std::fs::canonicalize(path) {
            Ok(p) => p,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if path.symlink_metadata().is_ok() {
                    return Err(format!(
                        "{shown} is a symlink to a file that does not exist; fix it by hand"
                    ));
                }
                let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
                    return Err(format!("{shown}: not a file path"));
                };
                std::fs::canonicalize(dir)
                    .map_err(|e| format!("{}: {e} (the settings dir must exist)", dir.display()))?
                    .join(name)
            }
            Err(e) => return Err(format!("{shown}: {e}")),
        };
        let (Some(dir_path), Some(name)) = (real.parent(), real.file_name()) else {
            return Err(format!("{shown}: not a file path"));
        };
        let err = |e: &dyn std::fmt::Display| format!("{shown}: {e}");
        let dir_c = c_name(dir_path.as_os_str()).map_err(|e| err(&e))?;
        // SAFETY: `dir_c` is NUL-terminated; the fd is owned below only.
        let dfd = unsafe {
            libc::open(
                dir_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if dfd < 0 {
            return Err(format!(
                "{}: {}",
                dir_path.display(),
                io::Error::last_os_error()
            ));
        }
        // SAFETY: `dfd` was just opened and is owned here only.
        let dir = unsafe { OwnedFd::from_raw_fd(dfd) };
        let name = c_name(name).map_err(|e| err(&e))?;
        let mut sf = Self {
            path: path.to_owned(),
            real: real.clone(),
            dir,
            name,
            file: None,
            mode: 0o600,
            bytes: Vec::new(),
        };
        match open_existing(&sf.dir, &sf.name) {
            Ok(None) => {}
            Ok(Some(mut f)) => {
                let m = f.metadata().map_err(|e| err(&e))?;
                if !m.file_type().is_file() {
                    return Err(format!("{}: not a regular file", real.display()));
                }
                f.read_to_end(&mut sf.bytes).map_err(|e| err(&e))?;
                sf.mode = m.permissions().mode() & 0o7777;
                sf.file = Some((f, (m.dev(), m.ino())));
            }
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
                return Err(format!(
                    "{} became a symlink while it was resolved; run again",
                    real.display()
                ));
            }
            Err(e) => return Err(err(&e)),
        }
        Ok(sf)
    }

    /// The path as named.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// How to name the file to a person: the path, and where it leads when
    /// that differs.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.real == self.path {
            self.path.display().to_string()
        } else {
            format!("{} (-> {})", self.path.display(), self.real.display())
        }
    }

    /// The file the path led to when it was resolved.
    #[must_use]
    pub fn real(&self) -> &Path {
        &self.real
    }

    /// The text read, invalid UTF-8 replaced.
    #[must_use]
    pub fn text_lossy(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }

    /// Reads the backup at `path`, never through a symlink: through the
    /// same dir when it sits next to the file.
    pub fn read_backup(&self, path: &Path) -> Result<String, String> {
        let err = |e: &dyn std::fmt::Display| {
            format!("the backup {} cannot be read: {e}", path.display())
        };
        let f = match (path.parent(), path.file_name()) {
            (Some(d), Some(n)) if Some(d) == self.real.parent() => {
                open_existing(&self.dir, &c_name(n).map_err(|e| err(&e))?)
            }
            _ => {
                use std::os::unix::fs::OpenOptionsExt as _;
                std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
                    .open(path)
                    .map(Some)
            }
        };
        let Some(mut f) = f.map_err(|e| err(&e))? else {
            return Err(err(&"it does not exist"));
        };
        if !f.metadata().is_ok_and(|m| m.file_type().is_file()) {
            return Err(err(&"not a regular file"));
        }
        let mut s = String::new();
        f.read_to_string(&mut s).map_err(|e| err(&e))?;
        Ok(s)
    }

    /// Whether a file was there when it was read.
    #[must_use]
    pub fn existed(&self) -> bool {
        self.file.is_some()
    }

    /// The text read.
    pub fn text(&self) -> Result<&str, String> {
        std::str::from_utf8(&self.bytes)
            .map_err(|e| format!("{}: not UTF-8: {e}", self.real.display()))
    }

    /// Fails unless the name in the dir still holds the file read, with the
    /// bytes read (or still holds nothing, for a file that did not exist).
    pub fn check_unchanged(&self) -> Result<(), String> {
        let changed = |why: &str| {
            Err(format!(
                "{} changed since it was read ({why}; L10, item 29); nothing written; run again",
                self.real.display()
            ))
        };
        let now = match open_existing(&self.dir, &self.name) {
            Ok(f) => f,
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return changed("now a symlink"),
            Err(e) => return changed(&e.to_string()),
        };
        match (&self.file, now) {
            (None, None) => Ok(()),
            (None, Some(_)) => changed("a file appeared"),
            (Some(_), None) => changed("removed"),
            (Some((f, id)), Some(now)) => {
                if identity(&now).ok() != Some(*id) {
                    return changed("another file");
                }
                let limit = self.bytes.len() as u64;
                match read_all_at(f, limit) {
                    Ok(b) if b == self.bytes => Ok(()),
                    Ok(_) => changed("edited"),
                    Err(e) => changed(&e.to_string()),
                }
            }
        }
    }

    /// Writes the bytes read to `name` in the same dir as a new file
    /// (`O_EXCL`, never through a symlink, mode 0600: the settings may hold
    /// secrets in `env`). A regular file already there (the backup of an
    /// earlier install) is kept as it is; anything else there is refused.
    pub fn write_backup(&self, name: &OsStr) -> Result<(), String> {
        let shown = self.real.with_file_name(name);
        let err = |e: &dyn std::fmt::Display| format!("backup {}: {e}", shown.display());
        let c = c_name(name).map_err(|e| err(&e))?;
        match open_existing(&self.dir, &c) {
            Ok(Some(f)) if f.metadata().is_ok_and(|m| m.file_type().is_file()) => return Ok(()),
            Ok(None) => {}
            Ok(Some(_)) | Err(_) => {
                return Err(err(
                    &"something other than a regular file is there; remove it and run again",
                ));
            }
        }
        let mut f = open_at(
            &self.dir,
            &c,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o600,
        )
        .map_err(|e| err(&e))?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .and_then(|()| f.write_all(&self.bytes))
            .and_then(|()| f.sync_all())
            .map_err(|e| err(&e))
    }

    /// Replaces the file read with `text`, keeping its mode (0600 for a
    /// new file), after [`Self::check_unchanged`] (before and after the
    /// new file is written).
    pub fn replace(&self, text: &str) -> Result<(), String> {
        self.check_unchanged()?;
        let err = |e: &dyn std::fmt::Display| format!("{}: {e}", self.real.display());
        let tmp = format!(
            ".{}.tollgate-new-{}",
            String::from_utf8_lossy(self.name.as_bytes()),
            fsx::unique_suffix()
        );
        let tmp = CString::new(tmp).map_err(|e| err(&e))?;
        let mut f = open_at(
            &self.dir,
            &tmp,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o600,
        )
        .map_err(|e| err(&e))?;
        let result = (|| {
            f.set_permissions(std::fs::Permissions::from_mode(self.mode))
                .and_then(|()| f.write_all(text.as_bytes()))
                .and_then(|()| f.sync_all())
                .map_err(|e| err(&e))?;
            drop(f);
            self.check_unchanged()?;
            let d = self.dir.as_raw_fd();
            if self.file.is_some() {
                // SAFETY: both names are NUL-terminated; `d` is open.
                cvt(unsafe { libc::renameat(d, tmp.as_ptr(), d, self.name.as_ptr()) })
                    .map_err(|e| err(&e))?;
            } else {
                // SAFETY: as above; flags 0 never follows a symlink at
                // `tmp` and fails with EEXIST when the name is taken.
                cvt(unsafe { libc::linkat(d, tmp.as_ptr(), d, self.name.as_ptr(), 0) }).map_err(
                    |e| {
                        if e.kind() == io::ErrorKind::AlreadyExists {
                            format!(
                                "{} changed since it was read (a file appeared; L10, item 29); nothing written; run again",
                                self.real.display()
                            )
                        } else {
                            err(&e)
                        }
                    },
                )?;
                // SAFETY: as above.
                let _ = unsafe { libc::unlinkat(d, tmp.as_ptr(), 0) };
            }
            // SAFETY: `d` is open; the rename is durable once the dir is.
            cvt(unsafe { libc::fsync(d) }).map_err(|e| err(&e))
        })();
        if result.is_err() {
            // SAFETY: as above; a name that is gone is fine.
            let _ = unsafe { libc::unlinkat(self.dir.as_raw_fd(), tmp.as_ptr(), 0) };
        }
        result
    }

    /// The text the name holds now, read through the same dir and never
    /// through a symlink; `None` when nothing is there.
    pub fn read_now(&self) -> Result<Option<String>, String> {
        let err = |e: &dyn std::fmt::Display| format!("{}: {e}", self.real.display());
        let Some(mut f) = open_existing(&self.dir, &self.name).map_err(|e| err(&e))? else {
            return Ok(None);
        };
        if !f.metadata().is_ok_and(|m| m.file_type().is_file()) {
            return Err(err(&"not a regular file"));
        }
        let mut s = String::new();
        f.read_to_string(&mut s).map_err(|e| err(&e))?;
        Ok(Some(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> (tempfile::TempDir, PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().canonicalize().unwrap();
        (t, d)
    }

    /// Item 29: a swap between the read and the write leaves every file
    /// as it was: a symlink to another file, a file renamed over it, an
    /// edit in place, a removal, a file appearing where none was.
    #[test]
    fn a_swap_after_the_read_writes_nothing_item29() {
        let (_t, d) = dir();
        let p = d.join("settings.json");
        let victim = d.join("victim");
        type Swap = fn(&Path, &Path);
        let swaps: [(&str, Swap); 4] = [
            ("symlink", |p, v| {
                std::fs::remove_file(p).unwrap();
                std::os::unix::fs::symlink(v, p).unwrap();
            }),
            ("rename", |p, _| {
                let o = p.with_file_name("o");
                std::fs::write(&o, "{\"o\":1}").unwrap();
                std::fs::rename(&o, p).unwrap();
            }),
            ("in place", |p, _| {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(p)
                    .unwrap()
                    .write_all(b"{\"x\":2}")
                    .unwrap();
            }),
            ("removed", |p, _| std::fs::remove_file(p).unwrap()),
        ];
        for (what, swap) in swaps {
            std::fs::write(&p, "{\"a\":1}").unwrap();
            std::fs::write(&victim, "victim").unwrap();
            let sf = SettingsFile::open(&p).unwrap();
            assert_eq!(sf.text().unwrap(), "{\"a\":1}");
            swap(&p, &victim);
            let before = std::fs::read(&p).ok();
            let e = sf.replace("NEW").unwrap_err();
            assert!(e.contains("changed since it was read"), "{what}: {e}");
            assert_eq!(
                std::fs::read_to_string(&victim).unwrap(),
                "victim",
                "{what}"
            );
            assert_eq!(std::fs::read(&p).ok(), before, "{what}");
            let _ = std::fs::remove_file(&p);
        }
        // A file appearing where none was read.
        let sf = SettingsFile::open(&p).unwrap();
        assert!(!sf.existed());
        std::fs::write(&p, "theirs").unwrap();
        assert!(sf.replace("NEW").is_err());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "theirs");
        // No temp file is left behind.
        let left: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains("tollgate-new"))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    /// The parent dir is resolved once: a dir renamed away and replaced
    /// by a symlink to another dir after the read is not written; the
    /// write goes to the file that was read and shown.
    #[test]
    fn the_dir_is_resolved_once_item29() {
        let (_t, d) = dir();
        let cfg = d.join("cfg");
        let other = d.join("other");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(cfg.join("settings.json"), "{}").unwrap();
        std::fs::write(other.join("settings.json"), "other").unwrap();
        let sf = SettingsFile::open(&cfg.join("settings.json")).unwrap();
        std::fs::rename(&cfg, d.join("moved")).unwrap();
        std::os::unix::fs::symlink(&other, &cfg).unwrap();
        sf.replace("NEW").unwrap();
        assert_eq!(
            std::fs::read_to_string(other.join("settings.json")).unwrap(),
            "other"
        );
        assert_eq!(
            std::fs::read_to_string(d.join("moved/settings.json")).unwrap(),
            "NEW"
        );
    }

    /// A symlinked settings file (a dotfiles checkout) is resolved once
    /// and its target written; the link stays. Mode is kept; a new file is
    /// 0600; a dangling link, a FIFO and a missing dir are refused.
    #[test]
    fn links_modes_and_odd_files_item29() {
        let (_t, d) = dir();
        let target = d.join("dotfiles.json");
        std::fs::write(&target, "{}").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        let link = d.join("settings.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let sf = SettingsFile::open(&link).unwrap();
        assert!(sf.describe().contains("-> "), "{}", sf.describe());
        sf.replace("NEW").unwrap();
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "NEW");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o640
        );
        // New file.
        let fresh = d.join("fresh.json");
        let sf = SettingsFile::open(&fresh).unwrap();
        sf.replace("{}").unwrap();
        assert_eq!(
            std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // Dangling link, FIFO, missing dir.
        let dangling = d.join("dangling.json");
        std::os::unix::fs::symlink(d.join("nowhere"), &dangling).unwrap();
        assert!(SettingsFile::open(&dangling).is_err());
        let fifo = d.join("fifo.json");
        let c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is NUL-terminated.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(SettingsFile::open(&fifo).is_err());
        assert!(SettingsFile::open(&d.join("no/such/settings.json")).is_err());
    }

    /// R95, item 10: the backup is the bytes read, new, 0600, never
    /// written through a symlink; an earlier backup is kept as it is.
    #[test]
    fn the_backup_is_the_bytes_read_private_and_follows_no_link_r95() {
        let (_t, d) = dir();
        let p = d.join("settings.json");
        std::fs::write(&p, "{\"env\":{\"TOKEN\":\"x\"}}").unwrap();
        let sf = SettingsFile::open(&p).unwrap();
        // The path is edited after the read: the backup still holds what
        // was read and shown.
        std::fs::write(&p, "later").unwrap();
        sf.write_backup(OsStr::new("settings.json.bak-1")).unwrap();
        let b = d.join("settings.json.bak-1");
        assert_eq!(
            std::fs::read_to_string(&b).unwrap(),
            "{\"env\":{\"TOKEN\":\"x\"}}"
        );
        assert_eq!(
            std::fs::metadata(&b).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::write(&p, "{}").unwrap();
        let sf = SettingsFile::open(&p).unwrap();
        sf.write_backup(OsStr::new("settings.json.bak-1")).unwrap();
        assert!(std::fs::read_to_string(&b).unwrap().contains("TOKEN"));
        let target = d.join("elsewhere");
        std::os::unix::fs::symlink(&target, d.join("bak-2")).unwrap();
        assert!(sf.write_backup(OsStr::new("bak-2")).is_err());
        assert!(!target.exists());
        std::fs::write(&target, "mine").unwrap();
        std::os::unix::fs::symlink(&target, d.join("bak-3")).unwrap();
        assert!(sf.write_backup(OsStr::new("bak-3")).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "mine");
    }
}
