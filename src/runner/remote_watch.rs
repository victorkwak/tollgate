//! R112: the remote check of a job that `pre-push` created for a push
//! candidate (R111).
//!
//! `pre-push` starts `tollgate __watch-push <job>` next to the runner
//! ([`crate::runner::spawn::spawn_watch`]): its own session, never a
//! descendant of the runner, whose step ends treat every descendant as
//! part of the step (R35). The watcher looks at the job every half second
//! and exits when it ended, its dir is gone, its runner is gone
//! ([`sched::runner_alive`]), or after [`MAX_LIFETIME`]. Every `[push]
//! remote_check` it reads the candidates whose job is this job
//! ([`push_lane::of_job`]) and asks the server of each for the current
//! value of its ref (`git ls-remote --heads` through
//! [`RemoteRefs::server_heads`]: the clean environment of R14 and X1, the
//! answer kept in `remote-refs.json`). A candidate is lost when the value
//! is not zero and the candidate commit does not contain it: the value is
//! not in the repo, or it is not an ancestor of the commit. A failed query
//! or a doubt about the repo keeps the candidate. When every candidate is
//! lost, and the job has no `keep` marker (something that is not a
//! candidate push also waits for its result), the watcher cancels the job
//! with the reason ([`JobStore::request_cancel_with`]) and then removes the
//! entries, only when the cancel took (a job that just passed keeps its
//! entries and its hold). The runner ends the job as cancelled at its next
//! look at the cancel request and writes no record.

use std::time::{Duration, Instant};

use crate::config::repo::branch_name;
use crate::dirs::Dirs;
use crate::env::EnvSnapshot;
use crate::exit;
use crate::gitx::{Git, Oid};
use crate::ids::JobId;
use crate::push_lane::{self, Candidate};
use crate::remote_refs::{RemoteRefs, TrustedRemote};
use crate::runner::job::JobSpec;
use crate::sched::{self, CancelNote, CancelOutcome, JobStore};

/// The `cause` of the metrics line of a job R112 ended.
pub const CAUSE_BEHIND: &str = "behind";

/// A watcher never lives longer than this.
pub const MAX_LIFETIME: Duration = Duration::from_secs(24 * 3600);

/// How often the watcher looks at the job's state.
const LOOK: Duration = Duration::from_millis(500);

/// What one remote check needs.
#[derive(Debug, Clone)]
pub struct WatchInput {
    /// Dirs.
    pub dirs: Dirs,
    /// The job.
    pub job: JobId,
    /// The repo's common dir (the candidate commits are in it).
    pub common_dir: std::path::PathBuf,
    /// The watcher's environment (credentials for the query, X1).
    pub env: EnvSnapshot,
    /// `job.path_prepend` of the host config (X1).
    pub path_prepend: Vec<String>,
}

/// `tollgate __watch-push <job>`: watches until the job ends. Exit 0.
pub fn run(dirs: &Dirs, id: &JobId, env: &EnvSnapshot) -> u8 {
    let spec = match JobSpec::read(dirs, id) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tollgate watch: {e}");
            return exit::OK;
        }
    };
    let Some(every) = spec.host.push.remote_check.interval() else {
        return exit::OK;
    };
    let input = WatchInput {
        dirs: dirs.clone(),
        job: id.clone(),
        common_dir: spec.common_dir.clone(),
        env: env.clone(),
        path_prepend: spec.host.job.path_prepend.clone(),
    };
    let store = JobStore::new(dirs);
    let started = Instant::now();
    let mut next = started + every;
    while started.elapsed() < MAX_LIFETIME {
        let Ok(meta) = store.read(id) else {
            return exit::OK;
        };
        if meta.state.is_terminal() || !sched::runner_alive(dirs, &meta) {
            return exit::OK;
        }
        if Instant::now() >= next {
            next = Instant::now() + every;
            if store.keep_requested(id) {
                // Never ended now; nothing more to watch for.
                return exit::OK;
            }
            if let Some(note) = check(&input) {
                if let Ok(CancelOutcome::Cancelled | CancelOutcome::Requested) =
                    store.request_cancel_with(id, Some(&note))
                {
                    push_lane::remove_job(dirs, id);
                    eprintln!("tollgate watch: {}", note.reason);
                }
                return exit::OK;
            }
        }
        std::thread::sleep(
            LOOK.min(next.saturating_duration_since(Instant::now()))
                .max(Duration::from_millis(10)),
        );
    }
    exit::OK
}

/// One remote check: the cancel note when every candidate of the job is
/// lost; `None` when one is not, when there are none, or on any doubt.
#[must_use]
pub fn check(input: &WatchInput) -> Option<CancelNote> {
    let cands = push_lane::of_job(&input.dirs, &input.job);
    if cands.is_empty() {
        return None;
    }
    all_lost(input, &cands)
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
