//! Which trusted remotes each repo had (item 33, R4, L2).
//!
//! With no trusted remote, the policy anchor falls back to the local full
//! refs (L2), which anything in the repo can move. So once a repo had a
//! trusted remote, losing it must not make that fallback: a script that
//! removes `origin`, or points it at another repo, would otherwise choose
//! the policy that checks its own commits.
//!
//! `<state>/trusted-remotes/<repo key>.json` lists each remote that was
//! trusted in the repo: its name then, its fetch URL as git used it, and
//! when it was first seen. The URL is stored as git used it and compared
//! by [`url_identity`], computed when read, so a change of the URL parser
//! applies to old records too and never makes them read as lost. A remote
//! is lost when no trusted remote of the repo has a URL with its identity
//! now (removed, set to another URL, or no longer trusted by
//! `scope.remotes`); a rename keeps the URL and is not a loss.
//!
//! A lost remote, or a record that cannot be read, parsed or written,
//! denies (no policy anchor) and keeps the repo in scope: this is fail
//! closed. Victor accepts the change with `tollgate remotes forget` at a
//! terminal, which removes the record; the next gated command records the
//! trusted remotes the repo has then.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::trust::url_identity;
use crate::dirs::Dirs;
use crate::fsx;
use crate::ids::RepoKey;
use crate::locks::LockFile;
use crate::remote_refs::TrustedRemote;

const VERSION: u32 = 1;

/// How long a writer waits for another writer of the same record. Writes
/// take milliseconds; a lock held longer (a process that holds it on
/// purpose) denies instead of hanging the hook.
const LOCK_WAIT: Duration = Duration::from_secs(2);

/// A remote seen trusted in one repo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeenRemote {
    /// Its name then.
    pub name: String,
    /// Its fetch URL as git used it.
    pub url: String,
    /// When it was first seen trusted.
    pub since: jiff::Timestamp,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordFile {
    version: u32,
    remotes: Vec<SeenRemote>,
}

/// What the record says about the repo now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Every recorded remote is still trusted.
    Kept,
    /// These recorded remotes are gone.
    Lost(Vec<SeenRemote>),
    /// The record cannot be read, parsed or written (why).
    Broken(String),
}

/// The record of one repo, checked against its trusted remotes now.
#[derive(Debug, Clone)]
pub struct Checked {
    /// The record file.
    pub file: PathBuf,
    /// What it says.
    pub status: Status,
}

impl Checked {
    /// Why the policy must deny (no anchor), or `None`.
    #[must_use]
    pub fn deny_message(&self) -> Option<String> {
        let file = self.file.display();
        match &self.status {
            Status::Kept => None,
            Status::Lost(lost) => {
                let all: Vec<String> = lost
                    .iter()
                    .map(|r| format!("{} ({})", r.name, r.url))
                    .collect();
                let first = &lost[0];
                Some(format!(
                    "no policy anchor (L2, item 33): this repo had the trusted remote {} and no trusted remote has that URL now, so the policy anchor would fall back to local refs; put it back (git remote add {} {}, or git remote set-url {} {}), or, to accept the change, run tollgate remotes forget in this repo from your own terminal (record: {file})",
                    all.join(", "),
                    first.name,
                    first.url,
                    first.name,
                    first.url,
                ))
            }
            Status::Broken(why) => Some(format!(
                "no policy anchor (L2, item 33): the record of this repo's trusted remotes is unusable ({why}), so a lost trusted remote cannot be told apart; run tollgate remotes forget in this repo from your own terminal to start a new record (record: {file})"
            )),
        }
    }

    /// True when the policy must deny.
    #[must_use]
    pub fn denies(&self) -> bool {
        self.status != Status::Kept
    }
}

/// `<state>/trusted-remotes/<repo key>.json`.
#[must_use]
pub fn file(dirs: &Dirs, repo: &RepoKey) -> PathBuf {
    dirs.state_dir()
        .join("trusted-remotes")
        .join(format!("{}.json", repo.as_str()))
}

fn lock_path(file: &Path) -> PathBuf {
    file.with_extension("lock")
}

/// The recorded remotes; empty when there is no record.
pub fn read(file: &Path) -> Result<Vec<SeenRemote>, String> {
    let Some(bytes) = fsx::read_optional(file).map_err(|e| format!("cannot read it: {e}"))? else {
        return Ok(Vec::new());
    };
    let r: RecordFile =
        serde_json::from_slice(&bytes).map_err(|e| format!("cannot parse it: {e}"))?;
    if r.version != VERSION {
        return Err(format!("unknown version {}", r.version));
    }
    Ok(r.remotes)
}

fn write(file: &Path, remotes: Vec<SeenRemote>) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(&RecordFile {
        version: VERSION,
        remotes,
    })
    .map_err(|e| format!("cannot write it: {e}"))?;
    fsx::write_atomic(file, &json).map_err(|e| format!("cannot write it: {e}"))
}

fn lock(file: &Path) -> Result<LockFile, String> {
    let path = lock_path(file);
    if let Some(dir) = path.parent() {
        fsx::ensure_dir(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    let start = Instant::now();
    let mut pause = Duration::from_millis(1);
    loop {
        match LockFile::try_acquire(&path) {
            Ok(Some(l)) => return Ok(l),
            Ok(None) if start.elapsed() < LOCK_WAIT => {
                std::thread::sleep(pause);
                pause = (pause * 2).min(Duration::from_millis(100));
            }
            Ok(None) => {
                return Err(format!(
                    "{} is held for more than {} s",
                    path.display(),
                    LOCK_WAIT.as_secs()
                ));
            }
            Err(e) => return Err(format!("cannot lock {}: {e}", path.display())),
        }
    }
}

fn has(seen: &[SeenRemote], id: &str) -> bool {
    seen.iter().any(|s| url_identity(&s.url) == id)
}

/// Checks the record of `repo` against `trusted` (its trusted remotes
/// now) and adds those not recorded yet. One small file read when nothing
/// is new; a lock, a read and a write when something is.
#[must_use]
pub fn check(dirs: &Dirs, repo: &RepoKey, trusted: &[TrustedRemote]) -> Checked {
    let file = file(dirs, repo);
    let status = check_file(&file, trusted);
    Checked { file, status }
}

fn check_file(file: &Path, trusted: &[TrustedRemote]) -> Status {
    let ids: Vec<String> = trusted.iter().map(|t| url_identity(&t.url)).collect();
    let mut seen = match read(file) {
        Ok(s) => s,
        Err(e) => return Status::Broken(e),
    };
    if ids.iter().any(|id| !has(&seen, id)) {
        // Another hook may be adding too: merge under the lock with what
        // is there now, so neither drops what the other added.
        let _held = match lock(file) {
            Ok(l) => l,
            Err(e) => return Status::Broken(e),
        };
        seen = match read(file) {
            Ok(s) => s,
            Err(e) => return Status::Broken(e),
        };
        let now = jiff::Timestamp::now();
        for (t, id) in trusted.iter().zip(&ids) {
            if !has(&seen, id) {
                seen.push(SeenRemote {
                    name: t.name.clone(),
                    url: t.url.clone(),
                    since: now,
                });
            }
        }
        if let Err(e) = write(file, seen.clone()) {
            return Status::Broken(e);
        }
    }
    let lost: Vec<SeenRemote> = seen
        .into_iter()
        .filter(|s| !ids.contains(&url_identity(&s.url)))
        .collect();
    if lost.is_empty() {
        Status::Kept
    } else {
        Status::Lost(lost)
    }
}

/// `tollgate remotes forget`: removes the record of `repo`, a broken one
/// too. Returns what it held (empty when unreadable), `None` when there
/// was no record.
pub fn forget(dirs: &Dirs, repo: &RepoKey) -> io::Result<Option<Vec<SeenRemote>>> {
    let file = file(dirs, repo);
    let held = lock(&file).map_err(io::Error::other)?;
    let before = read(&file).ok();
    match std::fs::remove_file(&file) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    }
    drop(held);
    Ok(Some(before.unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tr(name: &str, url: &str) -> TrustedRemote {
        TrustedRemote {
            name: name.to_owned(),
            url: url.to_owned(),
        }
    }

    fn lost_names(s: &Status) -> Vec<String> {
        match s {
            Status::Lost(l) => l.iter().map(|r| r.name.clone()).collect(),
            other => panic!("not lost: {other:?}"),
        }
    }

    /// Item 33: the record keeps every trusted remote once seen; a remote
    /// whose URL identity no trusted remote has now is lost. A rename or
    /// another spelling of the same URL is not a loss; another URL is.
    #[test]
    fn a_recorded_remote_is_lost_only_when_its_url_is_gone_item33() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("trusted-remotes/k.json");
        let gl = "https://gitlab.com/victorkwak/r.git";
        assert_eq!(check_file(&f, &[]), Status::Kept);
        assert!(!f.exists(), "nothing to record: no file");
        assert_eq!(check_file(&f, &[tr("origin", gl)]), Status::Kept);
        // Renamed, and spelled another way: kept.
        assert_eq!(
            check_file(&f, &[tr("upstream", "https://GitLab.com/victorkwak/r")]),
            Status::Kept
        );
        // Gone, or only another trusted remote left: lost.
        assert_eq!(lost_names(&check_file(&f, &[])), ["origin"]);
        let other = tr("mirror", "git@gitlab.com:victorkwak/other.git");
        assert_eq!(
            lost_names(&check_file(&f, std::slice::from_ref(&other))),
            ["origin"]
        );
        // The other one is recorded too, and both back is kept.
        assert_eq!(
            check_file(&f, &[tr("origin", gl), other.clone()]),
            Status::Kept
        );
        assert_eq!(lost_names(&check_file(&f, &[tr("o", gl)])), ["mirror"]);
        // The record stores URLs as git used them, once per identity.
        let r = read(&f).unwrap();
        assert_eq!(
            r.iter().map(|s| s.url.as_str()).collect::<Vec<_>>(),
            [gl, other.url.as_str()]
        );
    }

    /// Item 33, fail closed: a record that cannot be parsed or read, has
    /// another version, or cannot be written denies; it is never taken as
    /// "no record".
    #[test]
    fn an_unusable_record_denies_item33() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("trusted-remotes");
        std::fs::create_dir_all(&dir).unwrap();
        let gl = [tr("origin", "https://gitlab.com/victorkwak/r.git")];
        let broken = |s: Status| matches!(s, Status::Broken(_));
        let f = dir.join("a.json");
        for text in [
            "{not json",
            "",
            "[]",
            r#"{"version":2,"remotes":[]}"#,
            r#"{"version":1,"remotes":[],"x":1}"#,
        ] {
            std::fs::write(&f, text).unwrap();
            assert!(broken(check_file(&f, &[])), "{text:?}");
            assert!(broken(check_file(&f, &gl)), "{text:?}");
        }
        // A dir where the file should be: unreadable.
        let d = dir.join("b.json");
        std::fs::create_dir(&d).unwrap();
        assert!(broken(check_file(&d, &gl)));
        // Cannot be written: the record's dir is a file.
        let blocked = tmp.path().join("file");
        std::fs::write(&blocked, "x").unwrap();
        assert!(broken(check_file(&blocked.join("c.json"), &gl)));
        // Not even readable (not a dir): denies with nothing to record too.
        assert!(broken(check_file(&blocked.join("c.json"), &[])));
    }

    /// Item 33: a writer that holds the record's lock longer than
    /// [`LOCK_WAIT`] makes the check deny, not hang.
    #[test]
    fn a_held_record_lock_denies_after_a_bounded_wait_item33() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("trusted-remotes/k.json");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        let held = LockFile::acquire(&lock_path(&f)).unwrap();
        let start = Instant::now();
        let s = check_file(&f, &[tr("origin", "/srv/r.git")]);
        assert!(
            matches!(s, Status::Broken(ref w) if w.contains("held")),
            "{s:?}"
        );
        assert!(start.elapsed() < LOCK_WAIT + Duration::from_secs(1));
        drop(held);
        assert_eq!(check_file(&f, &[tr("origin", "/srv/r.git")]), Status::Kept);
    }

    /// Item 33: concurrent writers that add different remotes keep both.
    #[test]
    fn concurrent_writers_keep_every_remote_item33() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("trusted-remotes/k.json");
        std::thread::scope(|s| {
            for i in 0..8 {
                let f = &f;
                s.spawn(move || {
                    let r = tr(&format!("r{i}"), &format!("/srv/r{i}.git"));
                    let _ = check_file(f, &[r]);
                });
            }
        });
        let mut names: Vec<String> = read(&f).unwrap().into_iter().map(|r| r.name).collect();
        names.sort();
        assert_eq!(names, (0..8).map(|i| format!("r{i}")).collect::<Vec<_>>());
    }
}
