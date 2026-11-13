//! Job scheduling primitives (R88, R89): the per-key dedupe lock, waiter
//! locks, job state with guarded transitions, supersession and cancel.
//!
//! - `jobs/by-key/<key>.lock` (R88): the job that owns a key holds an
//!   exclusive `flock` on it from creation (queued) to the end; the file
//!   holds the job id. A hook that finds it held attaches to that job.
//!   [`JobClaim::into_file`] hands the locked file to the detached runner.
//! - `jobs/<id>/waiters/<pid>-<nanos>-<seq>` (R89): each waiting hook holds a
//!   `flock` on its own file; liveness is the lock, not the pid.
//! - `jobs/<id>/job.json`: [`JobMeta`], changed only under
//!   `jobs/<id>/state.lock` by [`JobStore::transition`].
//! - `jobs/queue/<origin hash>/<nanos>-<id>`: one marker per queued job, for
//!   supersession by origin.
//! - `jobs/<id>/cancel`: cancel request for a running job.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::cache::record::Verdict;
use crate::config::Tier;
use crate::dirs::Dirs;
use crate::fsx;
use crate::gitx::Oid;
use crate::ids::{JobId, RecordKey};
use crate::locks::{LockFile, Priority};

/// Error from the job store.
#[derive(Debug, thiserror::Error)]
pub enum SchedError {
    /// File system error.
    #[error("{path}: {source}")]
    Io {
        /// Path.
        path: PathBuf,
        /// Cause.
        #[source]
        source: io::Error,
    },
    /// `job.json` does not parse.
    #[error("{path}: corrupt job file: {message}")]
    Corrupt {
        /// Path.
        path: PathBuf,
        /// Parser message.
        message: String,
    },
}

fn io_at(path: &Path) -> impl FnOnce(io::Error) -> SchedError + '_ {
    move |source| SchedError::Io {
        path: path.to_owned(),
        source,
    }
}

/// Result of [`claim_job`].
#[derive(Debug)]
pub enum Claim {
    /// This caller owns the key: it creates and runs the job.
    Owner(JobClaim),
    /// Another job owns the key; attach to it. `None` when its id could not
    /// be read yet.
    Running(Option<JobId>),
}

/// The held dedupe lock of one key (R88).
#[derive(Debug)]
pub struct JobClaim {
    lock: LockFile,
    job: JobId,
}

impl JobClaim {
    /// The job that owns the key.
    #[must_use]
    pub fn job(&self) -> &JobId {
        &self.job
    }

    /// The locked file, to pass to the detached runner: the lock lasts while
    /// any copy of the open file lives.
    #[must_use]
    pub fn into_file(self) -> File {
        self.lock.into_file()
    }
}

/// Claims `key` for `job`, or names the job that holds it (R88).
///
/// A held lock whose file names a job that already ended is not a running
/// job: its runner is on its way out, or another process (a waiter's
/// [`running_job`] probe, gc) holds the lock for a moment. The claim tries
/// again for up to a second before it names that job.
pub fn claim_job(dirs: &Dirs, key: &RecordKey, job: &JobId) -> Result<Claim, SchedError> {
    let path = dirs.job_dedupe_lock(key);
    let store = JobStore::new(dirs);
    let mut last = None;
    for _ in 0..200 {
        if let Some(lock) = LockFile::try_acquire(&path).map_err(io_at(&path))? {
            let f = lock.file();
            f.set_len(0).map_err(io_at(&path))?;
            f.write_all_at(job.as_str().as_bytes(), 0)
                .map_err(io_at(&path))?;
            f.sync_data().map_err(io_at(&path))?;
            return Ok(Claim::Owner(JobClaim {
                lock,
                job: job.clone(),
            }));
        }
        // The owner writes its id right after it takes the lock, and its
        // job.json right after that.
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(io_at(&path)(e)),
        };
        if let Ok(id) = JobId::parse(text.trim()) {
            match store.read(&id) {
                Ok(meta) if meta.state.is_terminal() => last = Some(id),
                _ => return Ok(Claim::Running(Some(id))),
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(Claim::Running(last))
}

/// The job that holds `key` now, if any.
pub fn running_job(dirs: &Dirs, key: &RecordKey) -> Result<Option<JobId>, SchedError> {
    let path = dirs.job_dedupe_lock(key);
    if !crate::locks::is_held(&path).map_err(io_at(&path))? {
        return Ok(None);
    }
    let text = fs::read_to_string(&path).map_err(io_at(&path))?;
    Ok(JobId::parse(text.trim()).ok())
}

/// R35, R85: a job that has not ended and whose runner no longer holds its
/// key lock (SIGKILL, OOM) is lost. Its leftover processes (found by the
/// job's `TMPDIR` entry, R52) are killed, which releases the resource slots
/// and checkout lock they inherited, and the job is marked `lost`. Returns
/// true when this call marked it.
pub fn reap_if_lost(dirs: &Dirs, id: &JobId) -> Result<bool, SchedError> {
    let store = JobStore::new(dirs);
    let meta = store.read(id)?;
    if meta.state.is_terminal() || running_job(dirs, &meta.key)?.as_ref() == Some(id) {
        return Ok(false);
    }
    // Item 49: the recorded step leaders, on every platform (the only way
    // on macOS), then (Linux) every process with the job's TMPDIR.
    let records = crate::procs::StepRecord::read_all(&dirs.job_steps_dir(id));
    let (by_record, left_record) = crate::procs::kill_recorded(&records, Duration::from_secs(10));
    let mut marker = b"TMPDIR=".to_vec();
    marker.extend_from_slice(dirs.job_dir(id).join("tmp").as_os_str().as_encoded_bytes());
    let (by_marker, left_marker) = crate::procs::kill_marked(&marker, Duration::from_secs(10));
    let (killed, left) = (by_record + by_marker, left_record.max(left_marker));
    let reason = format!(
        "its runner died; {killed} leftover process(es) killed{}",
        if left > 0 {
            format!(", {left} still alive")
        } else {
            String::new()
        }
    );
    let done = store.transition(
        id,
        &[StateKind::Queued, StateKind::Running],
        JobState::Lost { reason },
    )?;
    let Transition::Done(meta) = done else {
        return Ok(false);
    };
    lost_metrics(dirs, &meta);
    Ok(true)
}

/// The lost job's line in the metrics log (item 50). Its runner died
/// before it wrote one; without it, a cap refusal of the job would stay
/// open in `tollgate stats`. Its run time is not known: only the time
/// until the reap, which `stats` keeps out of the wall and queue samples.
fn lost_metrics(dirs: &Dirs, meta: &JobMeta) {
    let now = jiff::Timestamp::now();
    let repo = crate::runner::job::JobSpec::read(dirs, &meta.id).map_or_else(
        |_| "?".to_owned(),
        |s| crate::metrics::repo_name(&s.common_dir),
    );
    let event = crate::metrics::JobEvent {
        t: now,
        job: meta.id.clone(),
        repo,
        tier: meta.tier,
        by: match meta.priority {
            Priority::Hook => "hook".into(),
            Priority::Prewarm => "prewarm".into(),
        },
        verdict: crate::metrics::LOST.into(),
        wall_ms: crate::metrics::ms_between(meta.created, now),
        job_queue_ms: 0,
        slot_queue_ms: 0,
        checkout_wait_ms: 0,
        steps: 0,
        steps_reused: 0,
        steps_fresh: 0,
        flaky: 0,
        quarantined: 0,
        step_ms: None,
        branch: None,
    };
    crate::metrics::record(dirs, &[crate::metrics::Event::Job(event)]);
}

/// A waiting hook's registration (R89). Removed on drop or process death.
#[derive(Debug)]
pub struct Waiter {
    path: PathBuf,
    _file: File,
}

impl Drop for Waiter {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Registers the calling process as a waiter of the job in `job_dir`.
/// Fails while the job dir does not exist yet.
pub fn register_waiter(job_dir: &Path) -> Result<Waiter, SchedError> {
    let dir = job_dir.join("waiters");
    // Never makes the job dir itself: it appears whole, by one rename (R82).
    // Job dirs made before `waiters/` was part of them get it here.
    match fs::create_dir(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(io_at(&dir)(e)),
    }
    let name = fsx::unique_suffix();
    let hidden = dir.join(format!(".tmp-{name}"));
    let visible = dir.join(&name);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&hidden)
        .map_err(io_at(&hidden))?;
    if file.try_lock().is_err() {
        let _ = fs::remove_file(&hidden);
        return Err(SchedError::Io {
            path: hidden,
            source: io::Error::other("fresh waiter file is locked"),
        });
    }
    fs::rename(&hidden, &visible).map_err(io_at(&visible))?;
    Ok(Waiter {
        path: visible,
        _file: file,
    })
}

/// True when a live process waits for the job in `job_dir`. Files of dead
/// waiters are removed.
pub fn has_live_waiter(job_dir: &Path) -> Result<bool, SchedError> {
    let dir = job_dir.join("waiters");
    let rd = match fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(io_at(&dir)(e)),
    };
    let mut live = false;
    for entry in rd {
        let entry = entry.map_err(io_at(&dir))?;
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let path = entry.path();
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(io_at(&path)(e)),
        };
        match file.try_lock() {
            Ok(()) => {
                let _ = fs::remove_file(&path);
            }
            Err(fs::TryLockError::WouldBlock) => live = true,
            Err(fs::TryLockError::Error(e)) => return Err(io_at(&path)(e)),
        }
    }
    Ok(live)
}

/// Where a job came from: the worktree and ref of the hook or check (R89).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Origin {
    /// Worktree path.
    pub worktree: PathBuf,
    /// Ref name (`refs/heads/x`, or `HEAD` for a detached check).
    pub refname: String,
}

impl Origin {
    /// Directory name for the queue markers of this origin.
    #[must_use]
    pub fn hash(&self) -> String {
        let mut h = blake3::Hasher::new();
        h.update(self.worktree.as_os_str().as_encoded_bytes());
        h.update(b"\0");
        h.update(self.refname.as_bytes());
        h.finalize().to_hex()[..16].to_owned()
    }
}

/// A job's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum JobState {
    /// Waiting for a verify slot and resources.
    Queued,
    /// Steps are running.
    Running {
        /// First step start (R33).
        started: jiff::Timestamp,
        /// Runner pid, for reports.
        pid: u32,
    },
    /// Ended with a verdict (a record may exist).
    Finished {
        /// The verdict.
        verdict: Verdict,
    },
    /// Replaced by a newer job from the same origin (R89). No record.
    Superseded,
    /// Cancelled (R89). No record.
    Cancelled,
    /// Queue budget or disk (R33, R44). No record.
    Deferred {
        /// Why.
        reason: String,
    },
    /// Its runner died before the job ended (R35): no record.
    Lost {
        /// What was found and done.
        reason: String,
    },
}

/// [`JobState`] without data, for transition guards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateKind {
    /// Queued.
    Queued,
    /// Running.
    Running,
    /// Finished.
    Finished,
    /// Superseded.
    Superseded,
    /// Cancelled.
    Cancelled,
    /// Deferred.
    Deferred,
    /// Lost.
    Lost,
}

impl JobState {
    /// The kind.
    #[must_use]
    pub fn kind(&self) -> StateKind {
        match self {
            Self::Queued => StateKind::Queued,
            Self::Running { .. } => StateKind::Running,
            Self::Finished { .. } => StateKind::Finished,
            Self::Superseded => StateKind::Superseded,
            Self::Cancelled => StateKind::Cancelled,
            Self::Deferred { .. } => StateKind::Deferred,
            Self::Lost { .. } => StateKind::Lost,
        }
    }

    /// True when the job will not change any more.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Queued | Self::Running { .. })
    }
}

/// `jobs/<id>/job.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobMeta {
    /// Job id.
    pub id: JobId,
    /// Record key.
    pub key: RecordKey,
    /// Tree under check.
    pub tree: Oid,
    /// Tier.
    pub tier: Tier,
    /// Where it came from.
    pub origin: Origin,
    /// Queue rank.
    pub priority: Priority,
    /// Creation time.
    pub created: jiff::Timestamp,
    /// Current state.
    #[serde(flatten)]
    pub state: JobState,
}

/// Result of [`JobStore::transition`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    /// The state changed; the new metadata.
    Done(JobMeta),
    /// The current state was not one of the allowed ones; unchanged.
    Refused(JobMeta),
}

/// Result of [`JobStore::request_cancel`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelOutcome {
    /// A queued job is now cancelled.
    Cancelled,
    /// A running job got a cancel request; its runner kills the steps (R35).
    Requested,
    /// The job had already ended in this state.
    AlreadyEnded(JobState),
}

/// The job dirs under the state dir.
#[derive(Debug, Clone)]
pub struct JobStore {
    dirs: Dirs,
}

impl JobStore {
    /// The store of `dirs`.
    #[must_use]
    pub fn new(dirs: &Dirs) -> Self {
        Self { dirs: dirs.clone() }
    }

    fn meta_path(&self, id: &JobId) -> PathBuf {
        self.dirs.job_dir(id).join("job.json")
    }

    fn marker(&self, meta: &JobMeta) -> PathBuf {
        self.dirs
            .job_queue_dir()
            .join(meta.origin.hash())
            .join(format!(
                "{:020}-{}",
                meta.created.as_nanosecond().max(0),
                meta.id
            ))
    }

    fn write_meta(&self, meta: &JobMeta) -> Result<(), SchedError> {
        let path = self.meta_path(&meta.id);
        let json = serde_json::to_vec_pretty(meta).map_err(|e| SchedError::Corrupt {
            path: path.clone(),
            message: e.to_string(),
        })?;
        fsx::write_atomic(&path, &json).map_err(io_at(&path))
    }

    /// Creates the job dir with `meta` (and its queue marker when queued).
    pub fn create(&self, meta: &JobMeta) -> Result<(), SchedError> {
        self.create_with(meta, &[])
    }

    /// Creates the job dir with `job.json`, `files` (name, contents) and an
    /// empty `waiters/` in one rename (R82): a process killed at any point
    /// leaves no job dir or a whole one. Then writes the queue marker when
    /// queued.
    pub fn create_with(&self, meta: &JobMeta, files: &[(&str, &[u8])]) -> Result<(), SchedError> {
        let dir = self.dirs.job_dir(&meta.id);
        let json = serde_json::to_vec_pretty(meta).map_err(|e| SchedError::Corrupt {
            path: self.meta_path(&meta.id),
            message: e.to_string(),
        })?;
        let mut all: Vec<(&str, &[u8])> = vec![("job.json", &json)];
        all.extend_from_slice(files);
        fsx::publish_dir(&dir, &all, &["waiters"]).map_err(io_at(&dir))?;
        if meta.state == JobState::Queued {
            let marker = self.marker(meta);
            fsx::write_atomic(&marker, b"").map_err(io_at(&marker))?;
        }
        Ok(())
    }

    /// Reads a job.
    pub fn read(&self, id: &JobId) -> Result<JobMeta, SchedError> {
        let path = self.meta_path(id);
        let bytes = fs::read(&path).map_err(io_at(&path))?;
        serde_json::from_slice(&bytes).map_err(|e| SchedError::Corrupt {
            path,
            message: e.to_string(),
        })
    }

    /// Changes the state to `to` when the current state is one of `from`,
    /// under the job's state lock.
    pub fn transition(
        &self,
        id: &JobId,
        from: &[StateKind],
        to: JobState,
    ) -> Result<Transition, SchedError> {
        let lock_path = self.dirs.job_dir(id).join("state.lock");
        let _lock = LockFile::acquire(&lock_path).map_err(io_at(&lock_path))?;
        let mut meta = self.read(id)?;
        if !from.contains(&meta.state.kind()) {
            return Ok(Transition::Refused(meta));
        }
        let was_queued = meta.state == JobState::Queued;
        meta.state = to;
        self.write_meta(&meta)?;
        if was_queued && meta.state != JobState::Queued {
            let marker = self.marker(&meta);
            match fs::remove_file(&marker) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(io_at(&marker)(e)),
            }
        }
        Ok(Transition::Done(meta))
    }

    /// R89: a queued job with no live waiter is stale when a newer queued
    /// job from the same origin exists. A newer job for the same tree at a
    /// lower tier does not make it stale (a `full` pre-warm of the current
    /// tree stays useful next to a `fast` hook job).
    pub fn is_stale(&self, id: &JobId) -> Result<bool, SchedError> {
        let me = self.read(id)?;
        if me.state != JobState::Queued || has_live_waiter(&self.dirs.job_dir(id))? {
            return Ok(false);
        }
        let my_marker = self.marker(&me);
        let dir = my_marker.parent().unwrap_or(&my_marker).to_owned();
        let my_name = my_marker.file_name().map(|n| n.to_owned());
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(io_at(&dir)(e)),
        };
        for entry in rd {
            let entry = entry.map_err(io_at(&dir))?;
            let name = entry.file_name();
            if Some(&name) <= my_name.as_ref() {
                continue;
            }
            let Some(other_id) = name
                .to_str()
                .and_then(|n| n.split_once('-'))
                .and_then(|(_, id)| JobId::parse(id).ok())
            else {
                continue;
            };
            let Ok(other) = self.read(&other_id) else {
                continue;
            };
            let newer_covers = other.tree != me.tree || other.tier >= me.tier;
            if other.state == JobState::Queued && other.origin == me.origin && newer_covers {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Marks the job superseded when [`JobStore::is_stale`]; true when it did.
    pub fn supersede_if_stale(&self, id: &JobId) -> Result<bool, SchedError> {
        if !self.is_stale(id)? {
            return Ok(false);
        }
        Ok(matches!(
            self.transition(id, &[StateKind::Queued], JobState::Superseded)?,
            Transition::Done(_)
        ))
    }

    /// `tollgate cancel <job>` (R89): a queued job ends now; a running job
    /// gets a request its runner acts on.
    pub fn request_cancel(&self, id: &JobId) -> Result<CancelOutcome, SchedError> {
        match self.transition(id, &[StateKind::Queued], JobState::Cancelled)? {
            Transition::Done(_) => Ok(CancelOutcome::Cancelled),
            Transition::Refused(meta) if meta.state.kind() == StateKind::Running => {
                let path = self.dirs.job_dir(id).join("cancel");
                fsx::write_atomic(&path, b"").map_err(io_at(&path))?;
                Ok(CancelOutcome::Requested)
            }
            Transition::Refused(meta) => Ok(CancelOutcome::AlreadyEnded(meta.state)),
        }
    }

    /// True when a cancel was requested for a running job.
    #[must_use]
    pub fn cancel_requested(&self, id: &JobId) -> bool {
        self.dirs.job_dir(id).join("cancel").exists()
    }

    /// Every readable job, oldest first.
    pub fn list(&self) -> Result<Vec<JobMeta>, SchedError> {
        let root = self.dirs.jobs_dir();
        let rd = match fs::read_dir(&root) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io_at(&root)(e)),
        };
        let mut out = Vec::new();
        for entry in rd {
            let entry = entry.map_err(io_at(&root))?;
            if let Some(id) = entry
                .file_name()
                .to_str()
                .and_then(|n| JobId::parse(n).ok())
                && let Ok(meta) = self.read(&id)
            {
                out.push(meta);
            }
        }
        out.sort_by(|a, b| (a.created, &a.id).cmp(&(b.created, &b.id)));
        Ok(out)
    }
}
