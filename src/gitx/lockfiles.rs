//! Git lock files that may be stale (R39).
//!
//! A lock is reported as stale only when it is older than 2 minutes and no
//! live git process works in the repo (`doctor --repo`), or, in a hook's
//! deny report, when the parent git does not hold it open. Nothing here
//! removes a lock: a printed `rm` taught agents to delete live locks.
//! The process checks read `/proc` on Linux; on macOS they answer
//! "unknown" (L13).

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// A git lock file in a repo that may be stale (R39).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockFile {
    /// Path.
    pub path: PathBuf,
    /// Age.
    pub age: Duration,
}

/// Lock files of the repo older than `min_age`: `index.lock`, `HEAD.lock`,
/// `packed-refs.lock`, `refs/**/*.lock`, and the same per worktree.
#[must_use]
pub fn old_locks(common_dir: &Path, min_age: Duration) -> Vec<LockFile> {
    let mut found = Vec::new();
    let now = SystemTime::now();
    let mut consider = |p: PathBuf| {
        if let Ok(md) = std::fs::symlink_metadata(&p)
            && let Ok(m) = md.modified()
            && let Ok(age) = now.duration_since(m)
            && age >= min_age
        {
            found.push(LockFile { path: p, age });
        }
    };
    let mut git_dirs = vec![common_dir.to_owned()];
    if let Ok(rd) = std::fs::read_dir(common_dir.join("worktrees")) {
        git_dirs.extend(rd.flatten().map(|e| e.path()));
    }
    for d in &git_dirs {
        for name in ["index.lock", "HEAD.lock", "packed-refs.lock", "config.lock"] {
            consider(d.join(name));
        }
    }
    let mut stack = vec![common_dir.join("refs")];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "lock") {
                consider(p);
            }
        }
    }
    found
}

/// Linux: true when a live `git` process has its cwd inside one of `dirs`
/// (R39: such a lock may be live). macOS: unknown (`None`).
#[must_use]
pub fn git_running_in(dirs: &[PathBuf]) -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        let rd = std::fs::read_dir("/proc").ok()?;
        for e in rd.flatten() {
            let name = e.file_name();
            if !name.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let comm = std::fs::read_to_string(e.path().join("comm")).unwrap_or_default();
            if !comm.trim().starts_with("git") {
                continue;
            }
            if let Ok(cwd) = std::fs::read_link(e.path().join("cwd"))
                && dirs.iter().any(|d| cwd.starts_with(d))
            {
                return Some(true);
            }
        }
        Some(false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = dirs;
        None
    }
}

/// Linux: true when process `pid` has `path` open (R39: the hook's parent
/// git owns its own locks).
#[must_use]
pub fn holds_open(pid: u32, path: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(rd) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            return false;
        };
        rd.flatten()
            .filter_map(|e| std::fs::read_link(e.path()).ok())
            .any(|t| t == path)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, path);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_locks_finds_aged_lock_files_r39() {
        let tmp = tempfile::tempdir().unwrap();
        let gd = tmp.path();
        std::fs::create_dir_all(gd.join("refs/heads/x")).unwrap();
        std::fs::create_dir_all(gd.join("worktrees/w")).unwrap();
        for f in [
            "index.lock",
            "refs/heads/x/y.lock",
            "worktrees/w/index.lock",
            "refs/heads/main",
        ] {
            std::fs::write(gd.join(f), b"").unwrap();
        }
        assert!(old_locks(gd, Duration::from_secs(120)).is_empty());
        let found = old_locks(gd, Duration::ZERO);
        assert_eq!(found.len(), 3, "{found:?}");
    }

    #[test]
    fn a_process_holds_its_open_files_r39() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().canonicalize().unwrap().join("x.lock");
        let f = std::fs::File::create(&p).unwrap();
        if cfg!(target_os = "linux") {
            assert!(holds_open(std::process::id(), &p));
        }
        drop(f);
        assert!(!holds_open(std::process::id(), &p));
    }
}
