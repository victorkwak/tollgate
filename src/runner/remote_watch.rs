//! R112: a job that `pre-push` started for push candidates (R111) asks
//! the trusted server during its run whether its candidates can still be
//! pushed.
//!
//! Every `[push] remote_check` a thread of the runner reads the candidates
//! whose job is this job ([`push_lane::of_job`]) and asks the server of
//! each for the current value of its ref (`git ls-remote --heads` through
//! [`RemoteRefs::server_heads`]: the clean environment of R14 and X1, the
//! answer kept in `remote-refs.json`). A candidate is lost when the value
//! is not zero and the candidate commit does not contain it: the value is
//! not in the repo, or it is not an ancestor of the commit. A failed query
//! or a doubt about the repo keeps the candidate. When every candidate is
//! lost, the thread removes the entries and cancels the job with the
//! reason ([`JobStore::request_cancel_with`]); the runner ends it as
//! cancelled at its next look at the cancel request, and writes no record.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::config::repo::branch_name;
use crate::dirs::Dirs;
use crate::env::EnvSnapshot;
use crate::gitx::{Git, Oid};
use crate::ids::JobId;
use crate::push_lane::{self, Candidate};
use crate::remote_refs::{RemoteRefs, TrustedRemote};
use crate::sched::{CancelNote, JobStore};

/// The `cause` of the metrics line of a job R112 ended.
pub const CAUSE_BEHIND: &str = "behind";

/// Stops the watch thread when dropped.
#[derive(Debug)]
pub struct Watch {
    stop: Arc<AtomicBool>,
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// What the thread needs.
#[derive(Debug, Clone)]
pub struct WatchInput {
    /// Dirs.
    pub dirs: Dirs,
    /// The job.
    pub job: JobId,
    /// The repo's common dir (the candidate commits are in it).
    pub common_dir: std::path::PathBuf,
    /// The runner's environment (credentials for the query, X1).
    pub env: EnvSnapshot,
    /// `job.path_prepend` of the host config (X1).
    pub path_prepend: Vec<String>,
    /// `[push] remote_check`.
    pub every: Duration,
}

/// Starts the watch thread; it ends when the returned [`Watch`] is dropped
/// or when it cancelled the job.
#[must_use]
pub fn start(input: WatchInput) -> Watch {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let _ = std::thread::Builder::new()
        .name("remote-check".into())
        .spawn(move || watch(&input, &flag));
    Watch { stop }
}

/// Sleeps `d` in short slices; false when `stop` was set meanwhile.
fn pause(d: Duration, stop: &AtomicBool) -> bool {
    let end = Instant::now() + d;
    while Instant::now() < end {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50).min(end - Instant::now()));
    }
    !stop.load(Ordering::Relaxed)
}

fn watch(input: &WatchInput, stop: &AtomicBool) {
    while pause(input.every, stop) {
        let cands = push_lane::of_job(&input.dirs, &input.job);
        if cands.is_empty() {
            continue;
        }
        let Some(note) = all_lost(input, &cands) else {
            continue;
        };
        if stop.load(Ordering::Relaxed) {
            return;
        }
        push_lane::remove_job(&input.dirs, &input.job);
        let _ = JobStore::new(&input.dirs).request_cancel_with(&input.job, Some(&note));
        return;
    }
}

/// The value of `remote_ref` on the trusted server of `c`, asked now;
/// `None` when the query failed. `Some(None)`: the server has no such
/// branch (zero).
fn server_value(input: &WatchInput, c: &Candidate, remote_ref: &str) -> Option<Option<Oid>> {
    let remote = TrustedRemote {
        name: c.remote.clone(),
        url: c.url.clone(),
    };
    // A new RemoteRefs per look: one asks each URL once per instance.
    let refs = RemoteRefs::new(
        &input.dirs,
        &input.env,
        &input.path_prepend,
        vec![remote.clone()],
    );
    let heads = refs.server_heads(&remote).ok()?;
    Some(heads.get(remote_ref).cloned())
}

/// True when `value` is lost for `commit`: not in the repo, or not an
/// ancestor of it. `None` on a doubt (a git error).
fn lost(git: &Git, value: &Oid, commit: &Oid) -> Option<bool> {
    match git.rev_parse_verify(&format!("{value}^{{commit}}")).ok()? {
        None => Some(true),
        Some(_) => {
            let out = git
                .output([
                    "merge-base",
                    "--is-ancestor",
                    value.as_str(),
                    commit.as_str(),
                ])
                .ok()?;
            match out.status.code() {
                Some(0) => Some(false),
                Some(1) => Some(true),
                _ => None,
            }
        }
    }
}

/// The cancel note when every candidate is lost; `None` when one is not,
/// or on any doubt.
fn all_lost(input: &WatchInput, cands: &[(String, Candidate)]) -> Option<CancelNote> {
    let git = Git::scrubbed(&input.env, &input.common_dir);
    let mut first: Option<CancelNote> = None;
    for (remote_ref, c) in cands {
        let value = server_value(input, c, remote_ref)??;
        if value.is_zero() || !lost(&git, &value, &c.commit)? {
            return None;
        }
        first.get_or_insert_with(|| CancelNote {
            reason: reason(remote_ref, &c.remote, &value),
            cause: Some(CAUSE_BEHIND.to_owned()),
        });
    }
    first
}

/// R112: the reason of the cancel.
#[must_use]
pub fn reason(remote_ref: &str, remote: &str, value: &Oid) -> String {
    format!(
        "{remote_ref} on {remote} moved to {} during the run; this commit can no longer be pushed there (R112). Run: git fetch {} {} && git merge FETCH_HEAD, then push again.",
        value.short(12),
        crate::hook::argv::shell_quote(remote),
        crate::hook::argv::shell_quote(branch_name(remote_ref)),
    )
}
