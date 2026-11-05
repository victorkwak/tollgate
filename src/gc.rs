//! `tollgate gc [--all]` (R48).
//!
//! - records older than 90 days;
//! - job dirs that no record or stored step pass references, 14 days
//!   after they ended; bulky files (step logs, `tmp/`) of referenced jobs
//!   after 14 days, keeping `report.json` and the JUnit files as long as
//!   the record (R82);
//! - stored step passes (L16) older than 90 days or whose job is gone;
//! - verify checkouts whose repo is gone (L15);
//! - lock tickets, waiter files, queue markers and dedupe locks older than
//!   1 day that no live process holds.
//!
//! `--all` removes every record, job, step pass, verify checkout and cache
//! that is not in use (a running job is kept).

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::cache::step::StoredStep;
use crate::cache::store::RecordStore;
use crate::config::HostConfig;
use crate::dirs::Dirs;
use crate::env::EnvSnapshot;
use crate::gitx::Git;
use crate::ids::JobId;
use crate::locks::{self, LockFile};
use crate::runner::checkout::{self, CheckoutMeta};
use crate::sched::JobStore;

const DAY: u64 = 86_400;
/// R48: records live this long.
pub const RECORD_DAYS: u64 = 90;
/// R48: bulky step logs live this long.
pub const LOG_DAYS: u64 = 14;

/// What gc removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcReport {
    /// Records.
    pub records: usize,
    /// Whole job dirs.
    pub jobs: usize,
    /// Bulky files of kept jobs.
    pub logs: usize,
    /// Stored step passes.
    pub steps: usize,
    /// Verify checkouts.
    pub checkouts: usize,
    /// Tickets, waiters, markers, dedupe locks.
    pub tickets: usize,
}

fn older_than(path: &Path, age: Duration, now: SystemTime) -> bool {
    path.symlink_metadata()
        .and_then(|m| m.modified())
        .is_ok_and(|t| now.duration_since(t).unwrap_or_default() > age)
}

fn files(dir: &Path) -> Vec<std::path::PathBuf> {
    fs::read_dir(dir)
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default()
}

/// Removes `path` (file) when no live process holds a lock on it.
fn remove_unheld(path: &Path) -> bool {
    match locks::is_held(path) {
        Ok(false) => fs::remove_file(path).is_ok(),
        _ => false,
    }
}

/// Runs gc. `env` is used for git calls when removing checkouts.
#[must_use]
pub fn gc(dirs: &Dirs, host: &HostConfig, env: &EnvSnapshot, all: bool) -> GcReport {
    let now = SystemTime::now();
    let mut rep = GcReport::default();
    let store = RecordStore::new(dirs);
    let jobs = JobStore::new(dirs);
    let record_age = if all {
        Duration::ZERO
    } else {
        Duration::from_secs(RECORD_DAYS * DAY)
    };
    let log_age = if all {
        Duration::ZERO
    } else {
        Duration::from_secs(LOG_DAYS * DAY)
    };
    let ticket_age = if all {
        Duration::ZERO
    } else {
        Duration::from_secs(DAY)
    };

    // Records.
    let mut referenced: BTreeSet<JobId> = BTreeSet::new();
    for r in store.list().unwrap_or_default() {
        let age = jiff::Timestamp::now()
            .duration_since(r.finished)
            .unsigned_abs();
        if all || age > record_age {
            if store.remove(&r.key).unwrap_or(false) {
                rep.records += 1;
            }
        } else {
            referenced.insert(r.job_id.clone());
        }
    }

    // Stored step passes (L16).
    for shard in files(&dirs.step_results_dir()) {
        for f in files(&shard) {
            let stored: Option<StoredStep> = fs::read(&f)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok());
            let keep = !all
                && stored.as_ref().is_some_and(|s| {
                    dirs.job_report(&s.job).is_file()
                        && jiff::Timestamp::now()
                            .duration_since(s.finished)
                            .unsigned_abs()
                            <= Duration::from_secs(RECORD_DAYS * DAY)
                });
            if keep {
                if let Some(s) = stored {
                    referenced.insert(s.job);
                }
            } else if fs::remove_file(&f).is_ok() {
                rep.steps += 1;
            }
        }
        let _ = fs::remove_dir(&shard);
    }

    // Job dirs.
    for meta in jobs.list().unwrap_or_default() {
        let dir = dirs.job_dir(&meta.id);
        if !meta.state.is_terminal() {
            continue;
        }
        if !older_than(&dir.join("job.json"), log_age, now) {
            continue;
        }
        if referenced.contains(&meta.id) {
            for f in files(&dir) {
                let name = f.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let keep = matches!(name, "report.json" | "job.json" | "spec.json")
                    || name.ends_with(".junit.xml")
                    || name == "waiters"
                    || name == "state.lock";
                if keep {
                    continue;
                }
                let gone = if f.is_dir() {
                    fs::remove_dir_all(&f).is_ok()
                } else {
                    fs::remove_file(&f).is_ok()
                };
                if gone {
                    rep.logs += 1;
                }
            }
        } else if fs::remove_dir_all(&dir).is_ok() {
            rep.jobs += 1;
        }
    }

    // Verify checkouts (L15): repo gone, or --all.
    let root = host.verify.root(dirs);
    for repo_dir in files(&root) {
        for tier_dir in files(&repo_dir) {
            for meta_path in files(&tier_dir) {
                if meta_path.extension().is_none_or(|e| e != "json") {
                    continue;
                }
                let meta = CheckoutMeta::read(&meta_path);
                let gone = meta.as_ref().is_none_or(|m| !m.common_dir.is_dir());
                if !(gone || all) {
                    continue;
                }
                let lock = meta_path.with_extension("lock");
                let Ok(Some(held)) = LockFile::try_acquire(&lock) else {
                    continue;
                };
                let checkout = meta_path.with_extension("");
                match meta.filter(|m| m.common_dir.is_dir()) {
                    Some(m) => {
                        checkout::remove(&Git::scrubbed(env, &m.common_dir), &checkout, &meta_path)
                    }
                    None => {
                        let _ = fs::remove_dir_all(&checkout);
                        let _ = fs::remove_file(&meta_path);
                    }
                }
                drop(held);
                let _ = fs::remove_file(&lock);
                rep.checkouts += 1;
            }
            let _ = fs::remove_dir(&tier_dir);
        }
        let _ = fs::remove_dir(&repo_dir);
    }

    // Tickets, waiters, markers, dedupe locks.
    for res in files(&dirs.locks_dir()) {
        for t in files(&res.join("queue")) {
            if older_than(&t, ticket_age, now) && remove_unheld(&t) {
                rep.tickets += 1;
            }
        }
    }
    for origin in files(&dirs.job_queue_dir()) {
        for m in files(&origin) {
            if older_than(&m, ticket_age, now) && fs::remove_file(&m).is_ok() {
                rep.tickets += 1;
            }
        }
        let _ = fs::remove_dir(&origin);
    }
    for l in files(&dirs.jobs_dir().join("by-key")) {
        if older_than(&l, ticket_age, now) && remove_unheld(&l) {
            rep.tickets += 1;
        }
    }
    for job in files(&dirs.jobs_dir()) {
        for w in files(&job.join("waiters")) {
            if older_than(&w, ticket_age, now) && remove_unheld(&w) {
                rep.tickets += 1;
            }
        }
    }
    if all {
        let _ = fs::remove_file(dirs.toolcache_file());
        let _ = fs::remove_file(dirs.flaky_log());
    }
    rep
}
