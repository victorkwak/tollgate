//! The local metrics log and `tollgate stats` (item 50).
//!
//! `metrics.jsonl` in the state dir holds one JSON object per line:
//!
//! - `guard`: a PreToolUse decision (`allow`, `ask`, `deny`), the rule id
//!   ([`crate::guard::rules::Reason::rule`]), whether the input was
//!   rewritten (R28), the guard's own time in µs, and for an ask or deny
//!   a keyed hash of the command (or file path), so the review can count
//!   distinct commands per rule. Never the text: a command can hold a
//!   secret.
//!   The key is `metrics.key` (32 random bytes, 0600); without it the hash
//!   is left out, never computed without a key.
//! - `hook`: one gate check of a gate hook: `cache_hit`, `passed` (a job
//!   ended inside the inline budget), `remote_verified`, `refused_cap`
//!   (no result at the inline cap, with the job id), `failed`, `error`.
//!   `stats` counts an allow that is the first check after a refusal of
//!   the same job as a retry, not a hit (see [`RepoTier::cap_retries`]).
//! - `chained`: one run of a chained (non-gate) hook that exited 0: its
//!   time in µs from the hook process's start (L19 budget 5 ms), the repo
//!   hook's share, and the exit it took ([`ChainedExit`]): `chain` for a
//!   hook that only chains; for `post-commit` and `post-merge` (item 17)
//!   a cheap exit of item 37 (`marker`, `squash`, `sequencer`,
//!   `fast_forward`, `tree_passed`) or the full check after `Gate::open`
//!   (`full`, `recorded`).
//! - `job`: a finished job's wall time, its queue time before the first
//!   step and in step slots, steps reused, flaky and quarantined tests,
//!   the time of the steps that ran and the branch (R109, [`cost`]).
//!   The reap of a job whose runner died writes its line, verdict
//!   [`LOST`], without run times; a cap refusal of it gets no wait sample.
//!
//! The log is append-only, 0600, and bounded: past [`MAX_BYTES`] the
//! writer that holds `metrics.lock` renames it to `metrics.jsonl.1` (and
//! `.1` to `.2`, up to [`KEEP`]). Writing never fails or stalls its
//! caller: every error is dropped, the file opens with `O_NOFOLLOW` and
//! `O_NONBLOCK` (a planted symlink or FIFO is skipped), and a panic is
//! caught. One `write` with `O_APPEND` per call: lines of concurrent
//! writers do not mix.
//!
//! Measured cost on the guard path (item 50): see `docs/operations.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::Tier;
use crate::dirs::Dirs;
use crate::ids::JobId;

pub mod cost;

/// Size at which the log rotates.
pub const MAX_BYTES: u64 = 8 << 20;

/// Rotated files kept (`metrics.jsonl.1` ... `.KEEP`).
pub const KEEP: u32 = 3;

const KEY_LEN: usize = 32;

/// The verdict of the `job` line that the reap of a lost job writes
/// ([`crate::sched::reap_if_lost`]): its runner died before its own line.
pub const LOST: &str = "lost";

/// A guard decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Exit 0, no `permissionDecision`.
    Allow,
    /// `permissionDecision: "ask"`.
    Ask,
    /// Exit 2.
    Deny,
}

/// How one gate check of a hook ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookOutcome {
    /// A stored pass allowed without a job.
    CacheHit,
    /// A job ended with a pass inside the inline budget.
    Passed,
    /// R14(2): a trusted remote already has it.
    RemoteVerified,
    /// No result at the inline cap; the job went on detached.
    RefusedCap,
    /// A verdict other than pass, stored or new.
    Failed,
    /// Plan, store or job error.
    Error,
    /// R102: the remote branch has commits that the push does not
    /// contain, so git would reject it; refused before any plan or job.
    Behind,
}

/// One line of the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Event {
    /// A PreToolUse decision.
    Guard(GuardEvent),
    /// A gate check of a hook.
    Hook(HookEvent),
    /// A finished job.
    Job(JobEvent),
    /// A chained hook run (L19, item 37).
    Chained(ChainedEvent),
}

impl Event {
    /// When it happened.
    #[must_use]
    pub fn time(&self) -> jiff::Timestamp {
        match self {
            Self::Guard(e) => e.t,
            Self::Hook(e) => e.t,
            Self::Job(e) => e.t,
            Self::Chained(e) => e.t,
        }
    }
}

/// A guard decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardEvent {
    /// When.
    pub t: jiff::Timestamp,
    /// Tool name (`Bash`, `Write`, ...).
    pub tool: String,
    /// The decision.
    pub decision: Decision,
    /// The rule that asked or denied.
    #[serde(default)]
    pub rule: Option<String>,
    /// R28: the input was rewritten.
    #[serde(default)]
    pub rewrite: bool,
    /// The guard's own time, µs.
    pub us: u64,
    /// Keyed hash of the command or file path (16 hex digits).
    #[serde(default)]
    pub cmd: Option<String>,
}

/// A gate check of a hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookEvent {
    /// When the hook decided.
    pub t: jiff::Timestamp,
    /// Hook name.
    pub hook: String,
    /// Repo name (see [`repo_name`]).
    pub repo: String,
    /// Tier; absent on an R102 `behind` refusal, which resolves no
    /// policy and so no tier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,
    /// How it ended.
    pub outcome: HookOutcome,
    /// The job, when one ran or runs.
    #[serde(default)]
    pub job: Option<JobId>,
    /// The hook's time until its decision, ms, from the hook process's
    /// start; the same on every check of one hook run. It holds
    /// `repo_hook_ms`.
    pub ms: u64,
    /// The repo's own hook's (R7) share of `ms`, when the repo has one.
    /// `stats` leaves it out of the hook time: it is not tollgate's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_hook_ms: Option<u64>,
    /// The hook run (8 hex digits), shared by its checks, so `stats` takes
    /// one time sample per run. Absent on lines written before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
}

/// How a chained hook run ended. Only `post-commit` and `post-merge` look
/// for a commit made without the gate (item 17); their exits are in cost
/// order: the cheap checks of item 37 first, [`Self::Full`] and
/// [`Self::Recorded`] after `Gate::open` (host config, scope, remotes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainedExit {
    /// A hook that only chains to the repo hook.
    Chain,
    /// A gate hook of the same git process allowed the commit.
    Marker,
    /// `post-merge` after a squash merge, which makes no commit.
    Squash,
    /// A sequencer operation (L1).
    Sequencer,
    /// `post-merge` after a fast-forward, which makes no commit.
    FastForward,
    /// `HEAD`'s tree passed: one `rev-parse`.
    TreePassed,
    /// The full check: nothing recorded (out of scope, a trusted remote
    /// has it, or the config did not load).
    Full,
    /// The full check recorded an unverified commit.
    Recorded,
}

impl ChainedExit {
    /// The name in the log.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Chain => "chain",
            Self::Marker => "marker",
            Self::Squash => "squash",
            Self::Sequencer => "sequencer",
            Self::FastForward => "fast_forward",
            Self::TreePassed => "tree_passed",
            Self::Full => "full",
            Self::Recorded => "recorded",
        }
    }
}

/// A chained (non-gate) hook run that exited 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainedEvent {
    /// When it ended.
    pub t: jiff::Timestamp,
    /// Hook name.
    pub hook: String,
    /// Repo name (see [`repo_name`]).
    pub repo: String,
    /// How it ended.
    pub exit: ChainedExit,
    /// The hook's time, µs, from the hook process's start (L19 budgets
    /// it at 5 ms). It holds `repo_hook_us`.
    pub us: u64,
    /// The repo's own hook's (R7) share of `us`, when the repo has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_hook_us: Option<u64>,
}

/// A finished job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobEvent {
    /// When it ended.
    pub t: jiff::Timestamp,
    /// Job id.
    pub job: JobId,
    /// Repo name.
    pub repo: String,
    /// Tier.
    pub tier: Tier,
    /// `hook`, `prewarm` or `step` (`tollgate run <step>`, R105).
    pub by: String,
    /// `pass`, `fail`, ..., or how it ended ([`LOST`]: its runner died).
    pub verdict: String,
    /// Creation to end, ms; for a [`LOST`] job, to the reap.
    pub wall_ms: u64,
    /// Creation to first step, ms (verify slot, resources, checkout).
    pub job_queue_ms: u64,
    /// Step slot waits, ms.
    pub slot_queue_ms: u64,
    /// Checkout lock wait, ms (part of `job_queue_ms`).
    #[serde(default)]
    pub checkout_wait_ms: u64,
    /// Steps.
    pub steps: u32,
    /// Steps reused from a stored pass (L16).
    pub steps_reused: u32,
    /// Steps taken from a job that ran them on the same tree (R101); they
    /// did not run either.
    #[serde(default)]
    pub steps_fresh: u32,
    /// Tests that passed on retry.
    pub flaky: u32,
    /// Quarantined failures.
    pub quarantined: u32,
    /// Sum of `duration_ms` of the steps that ran in this job: not
    /// skipped, not reused (R109). Absent on lines from before it and on a
    /// [`LOST`] line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_ms: Option<u64>,
    /// The job's origin ref without `refs/heads/` (R109). Absent as
    /// `step_ms`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
}

/// R109: the summed time of the steps of `steps` that ran (not skipped,
/// not reused from a stored pass).
#[must_use]
pub fn ran_step_ms(steps: &[crate::report::StepReport]) -> u64 {
    steps
        .iter()
        .filter(|s| {
            s.status != crate::cache::record::StepStatus::Skipped
                && s.reused_from.is_none()
                && s.fresh_from.is_none()
        })
        .map(|s| s.duration_ms)
        .sum()
}

/// R109: a job's origin ref as a branch name (`refs/heads/` removed).
#[must_use]
pub fn branch_of(refname: &str) -> String {
    refname
        .strip_prefix("refs/heads/")
        .unwrap_or(refname)
        .to_owned()
}

/// The display name of the repo whose common dir is `common_dir`: the
/// main worktree's dir name, or a bare repo's name without `.git`.
#[must_use]
pub fn repo_name(common_dir: &Path) -> String {
    let name = |p: &Path| p.file_name().map(|n| n.to_string_lossy().into_owned());
    match name(common_dir) {
        Some(n) if n == ".git" => common_dir
            .parent()
            .and_then(name)
            .unwrap_or_else(|| "?".into()),
        Some(n) => n.strip_suffix(".git").map(str::to_owned).unwrap_or(n),
        None => "?".into(),
    }
}

/// Milliseconds from `a` to `b`, 0 when `b` is earlier.
#[must_use]
pub fn ms_between(a: jiff::Timestamp, b: jiff::Timestamp) -> u64 {
    u64::try_from(b.duration_since(a).as_millis()).unwrap_or(0)
}

/// Appends `events`; drops every error and catches a panic, so a broken
/// log never changes what its caller does.
pub fn record(dirs: &Dirs, events: &[Event]) {
    if events.is_empty() {
        return;
    }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = append(dirs, events, MAX_BYTES, KEEP);
    }));
}

/// The keyed hash of `text` (16 hex digits), or `None` without a key.
/// Creates the key on first use. Never fails its caller.
#[must_use]
pub fn keyed_hash(dirs: &Dirs, text: &str) -> Option<String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let key = load_key(dirs)?;
        Some(blake3::keyed_hash(&key, text.as_bytes()).to_hex()[..16].to_owned())
    }))
    .ok()
    .flatten()
}

fn open_flags() -> i32 {
    libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC
}

/// The error [`open_regular`] gives for a path that opens but is not a
/// regular file (a dir, a FIFO, a device).
#[derive(Debug)]
struct NotRegular;

impl std::fmt::Display for NotRegular {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("not a regular file")
    }
}

impl std::error::Error for NotRegular {}

/// Opens a regular file for reading, refusing links and special files.
fn open_regular(path: &Path) -> io::Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(open_flags())
        .open(path)?;
    if !f.metadata()?.file_type().is_file() {
        return Err(io::Error::other(NotRegular));
    }
    Ok(f)
}

/// True when `open_regular` refused `e`'s path for what it is (a link, a
/// dir, a special file, no read access) rather than for an I/O failure.
fn is_unusable(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|r| r.is::<NotRegular>())
        || e.kind() == io::ErrorKind::PermissionDenied
        || matches!(
            e.raw_os_error(),
            Some(libc::ELOOP | libc::ENOTDIR | libc::EISDIR | libc::ENXIO | libc::EACCES)
        )
}

fn load_key(dirs: &Dirs) -> Option<[u8; KEY_LEN]> {
    let path = dirs.metrics_key();
    match read_key(&path) {
        Ok(k) => return Some(k),
        Err(e) if e.kind() != io::ErrorKind::NotFound => return None,
        Err(_) => {}
    }
    // First use: write a fresh key beside it, then link it into place;
    // a concurrent first use that wins the link wins, and both read it.
    let mut key = [0u8; KEY_LEN];
    open_regular(Path::new("/dev/urandom"))
        .or_else(|_| File::open("/dev/urandom"))
        .and_then(|mut f| f.read_exact(&mut key))
        .ok()?;
    let parent = path.parent()?;
    crate::fsx::ensure_dir(parent).ok()?;
    let tmp = parent.join(format!(".metrics.key.{}", crate::fsx::unique_suffix()));
    let made = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(open_flags())
        .open(&tmp)
        .and_then(|mut f| f.write_all(&key));
    let linked = made.and_then(|()| std::fs::hard_link(&tmp, &path));
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Ok(()) => Some(key),
        Err(_) => read_key(&path).ok(),
    }
}

fn read_key(path: &Path) -> io::Result<[u8; KEY_LEN]> {
    let mut f = open_regular(path)?;
    let md = f.metadata()?;
    if md.mode() & 0o077 != 0 || md.len() != KEY_LEN as u64 {
        return Err(io::Error::other("metrics.key: not a 0600 32-byte file"));
    }
    let mut key = [0u8; KEY_LEN];
    f.read_exact(&mut key)?;
    Ok(key)
}

/// Appends `events` to the log at `dirs`, rotating past `max` bytes.
pub fn append(dirs: &Dirs, events: &[Event], max: u64, keep: u32) -> io::Result<()> {
    let mut text = String::new();
    for e in events {
        text.push_str(&serde_json::to_string(e).map_err(io::Error::other)?);
        text.push('\n');
    }
    let path = dirs.metrics_log();
    let open = || {
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(open_flags())
            .open(&path)
    };
    let mut f = match open() {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            crate::fsx::ensure_dir(&dirs.state_dir())?;
            open()?
        }
        Err(e) => return Err(e),
    };
    let md = f.metadata()?;
    if !md.file_type().is_file() {
        return Err(io::Error::other("metrics.jsonl: not a regular file"));
    }
    if md.mode() & 0o077 != 0 {
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(text.as_bytes())?;
    if md.len() + text.len() as u64 > max {
        rotate(dirs, max, keep);
    }
    Ok(())
}

/// Renames the full log away under `metrics.lock`; a writer that does not
/// get the lock at once leaves it to the one that has it.
fn rotate(dirs: &Dirs, max: u64, keep: u32) {
    let Ok(lock) = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(open_flags())
        .open(dirs.metrics_lock())
    else {
        return;
    };
    if lock.try_lock().is_err() {
        return;
    }
    let path = dirs.metrics_log();
    // Another writer may have rotated between our write and the lock.
    let full = std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file() && m.len() > max);
    if full {
        for i in (1..keep).rev() {
            let _ = std::fs::rename(rotated(&path, i), rotated(&path, i + 1));
        }
        let _ = std::fs::rename(&path, rotated(&path, 1));
    }
    let _ = lock.unlock();
}

fn rotated(path: &Path, i: u32) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(format!(".{i}"));
    PathBuf::from(s)
}

/// What [`read`] found in the log.
#[derive(Debug, Default)]
pub struct Log {
    /// Every event at or after `since`, oldest file first.
    pub events: Vec<Event>,
    /// One line per log path that was skipped because it is not a
    /// readable regular file (a dir, a symlink, a special file). Rotation
    /// never clears such a path, so it must not make the whole log unreadable.
    pub skipped: Vec<String>,
}

/// Every event at or after `since`, oldest file first. Lines that do not
/// parse are skipped, and so is a log path that is not a readable regular
/// file (symlinks are never followed). A read error on a regular file is
/// an error.
pub fn read(dirs: &Dirs, since: Option<jiff::Timestamp>) -> io::Result<Log> {
    let path = dirs.metrics_log();
    let mut files: Vec<PathBuf> = (1..=KEEP).rev().map(|i| rotated(&path, i)).collect();
    files.push(path);
    let mut out = Log::default();
    for p in files {
        let mut f = match open_regular(&p) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) if is_unusable(&e) => {
                out.skipped.push(format!("{}: skipped: {e}", p.display()));
                continue;
            }
            Err(e) => return Err(io::Error::new(e.kind(), format!("{}: {e}", p.display()))),
        };
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", p.display())))?;
        out.events.extend(
            String::from_utf8_lossy(&bytes)
                .lines()
                .filter_map(|l| serde_json::from_str::<Event>(l).ok())
                .filter(|e| since.is_none_or(|s| e.time() >= s)),
        );
    }
    Ok(out)
}

/// Nearest-rank p50 and p90.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Pct {
    /// Median.
    pub p50: u64,
    /// 90th percentile.
    pub p90: u64,
    /// Sample count.
    pub n: usize,
}

impl Pct {
    /// `None` for no samples.
    #[must_use]
    pub fn of(mut v: Vec<u64>) -> Option<Self> {
        if v.is_empty() {
            return None;
        }
        v.sort_unstable();
        let rank = |p: usize| v[(v.len() * p).div_ceil(100).max(1) - 1];
        Some(Self {
            p50: rank(50),
            p90: rank(90),
            n: v.len(),
        })
    }
}

/// `tollgate stats` for one repo and tier.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RepoTier {
    /// Repo name.
    pub repo: String,
    /// Tier.
    pub tier: String,
    /// Gate checks by hooks, without [`Self::cap_retries`].
    pub checks: u32,
    /// Allowed from a stored pass.
    pub cache_hits: u32,
    /// `cache_hits / checks`.
    pub cache_hit_rate: Option<f64>,
    /// A job passed inside the inline budget.
    pub passed_inline: u32,
    /// R14(2) allows.
    pub remote_verified: u32,
    /// Refused at the inline cap.
    pub cap_refusals: u32,
    /// Push refs refused because the remote branch has commits that the
    /// push does not contain (R102). No job ran; not in [`Self::checks`].
    pub behind: u32,
    /// Refusals whose job has no `job` line yet: it still runs, or its
    /// line was rotated out. A job lost to a dead runner gets its line
    /// from the reap ([`LOST`]).
    pub cap_refusals_open: u32,
    /// Refusals whose job's runner died ([`LOST`]). Closed, but not in
    /// `refusal_wait_ms`: the lost line's time is the reap (the next
    /// `tollgate wait`, `cancel`, `gc` or job of the same key), which can
    /// come hours after the runner died.
    pub cap_refusals_lost: u32,
    /// Allows that ended a refused commit: the first check after a cap
    /// refusal with the same job, when it allowed (the `tollgate wait
    /// <job> && git commit` retry, or a retry that joined the job). It
    /// saved no time, so it is not in `checks`, `cache_hits` or
    /// `passed_inline`. A retry that denies stays a check: the agent
    /// must act on it.
    pub cap_retries: u32,
    /// From a refusal to its job's end, ms. The hook takes its time after
    /// all settles, so a job can end just before it: 0 then.
    pub refusal_wait_ms: Option<Pct>,
    /// Non-pass verdicts.
    pub failed: u32,
    /// Errors.
    pub errors: u32,
    /// The hook's time until its decision, ms, without the repo hook.
    pub hook_ms: Option<Pct>,
    /// Finished jobs.
    pub jobs: u32,
    /// Jobs a hook waited for.
    pub jobs_by_hook: u32,
    /// Pre-warm jobs.
    pub jobs_prewarm: u32,
    /// `tollgate run <step>` jobs (R105).
    pub jobs_step: u32,
    /// Jobs whose verdict is not pass.
    pub jobs_not_pass: u32,
    /// Job wall time, ms.
    pub wall_ms: Option<Pct>,
    /// Job queue before the first step plus step slot waits, ms.
    pub queue_ms: Option<Pct>,
    /// Steps.
    pub steps: u32,
    /// Steps reused (L16).
    pub steps_reused: u32,
    /// Steps taken from a job on the same tree (R101).
    pub steps_fresh: u32,
    /// Flaky tests (passed on retry).
    pub flaky: u32,
    /// Jobs with a flaky test.
    pub jobs_flaky: u32,
    /// Quarantined failures.
    pub quarantined: u32,
}

/// Guard counts for one rule.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RuleCount {
    /// Denies.
    pub deny: u32,
    /// Asks.
    pub ask: u32,
    /// Distinct commands (keyed hashes).
    pub distinct: u32,
    /// The last time.
    pub last: Option<jiff::Timestamp>,
}

/// Guard summary.
#[derive(Debug, Clone, Default, Serialize)]
pub struct GuardStats {
    /// Calls.
    pub calls: u32,
    /// Allows.
    pub allow: u32,
    /// Asks.
    pub ask: u32,
    /// Denies.
    pub deny: u32,
    /// R28 rewrites.
    pub rewrite: u32,
    /// The guard's own time, µs.
    pub us: Option<Pct>,
    /// Asks and denies by rule id.
    pub rules: BTreeMap<String, RuleCount>,
}

/// `tollgate stats`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Stats {
    /// `--since`.
    pub since: Option<jiff::Timestamp>,
    /// Events read.
    pub events: usize,
    /// The first event.
    pub first: Option<jiff::Timestamp>,
    /// The last event.
    pub last: Option<jiff::Timestamp>,
    /// By repo and tier.
    pub repos: Vec<RepoTier>,
    /// Guard.
    pub guard: GuardStats,
    /// Chained hooks, by hook name.
    pub chained: Vec<ChainedStats>,
}

/// `tollgate stats` for one chained hook.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ChainedStats {
    /// Hook name.
    pub hook: String,
    /// Runs.
    pub runs: u32,
    /// tollgate's own time, µs: from the hook process's start, without
    /// the repo hook (L19 budget: 5 ms).
    pub us: Option<Pct>,
    /// Runs by exit.
    pub exits: BTreeMap<ChainedExit, u32>,
}

#[derive(Default)]
struct Acc {
    row: RepoTier,
    refusal_wait: Vec<u64>,
    hook_ms: Vec<u64>,
    /// Hook runs already sampled in `hook_ms`: hook, time, ms, run id.
    /// One run writes one `t` and one `ms` on all its checks, so lines
    /// from before the run id still group by them.
    hook_runs: BTreeSet<(String, jiff::Timestamp, u64, Option<String>)>,
    wall: Vec<u64>,
    queue: Vec<u64>,
}

/// The row of `repo` and `tier` (`-` for none).
fn acc<'a>(
    by: &'a mut BTreeMap<(String, String), Acc>,
    repo: &str,
    tier: Option<Tier>,
) -> &'a mut Acc {
    let tier = tier.map_or_else(
        || "-".to_owned(),
        |t| {
            serde_json::to_value(t)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default()
        },
    );
    let a = by.entry((repo.to_owned(), tier.clone())).or_default();
    a.row.repo = repo.to_owned();
    a.row.tier = tier;
    a
}

/// Sums `events` (all after `since`).
#[must_use]
pub fn stats(events: &[Event], since: Option<jiff::Timestamp>) -> Stats {
    let mut by: BTreeMap<(String, String), Acc> = BTreeMap::new();
    // A job's first line counts. A second one is a reap's [`LOST`] line
    // for a runner killed between its own line and its final state.
    // `None`: the first line is [`LOST`], so its time is the reap's, not
    // the job's end.
    let mut ends: BTreeMap<&JobId, Option<jiff::Timestamp>> = BTreeMap::new();
    for e in events {
        if let Event::Job(j) = e {
            ends.entry(&j.job)
                .or_insert((j.verdict != LOST).then_some(j.t));
        }
    }
    let mut counted: BTreeSet<&JobId> = BTreeSet::new();
    let mut g = GuardStats::default();
    let mut us = Vec::new();
    let mut hashes: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    // Jobs refused at the cap whose commit has not been checked again.
    let mut refused: BTreeSet<&JobId> = BTreeSet::new();
    let mut chained: BTreeMap<&str, (ChainedStats, Vec<u64>)> = BTreeMap::new();
    for e in events {
        match e {
            Event::Chained(c) => {
                let (row, us) = chained.entry(&c.hook).or_default();
                row.runs += 1;
                *row.exits.entry(c.exit).or_default() += 1;
                us.push(c.us.saturating_sub(c.repo_hook_us.unwrap_or(0)));
            }
            Event::Guard(x) => {
                g.calls += 1;
                us.push(x.us);
                g.rewrite += u32::from(x.rewrite);
                match x.decision {
                    Decision::Allow => g.allow += 1,
                    Decision::Ask => g.ask += 1,
                    Decision::Deny => g.deny += 1,
                }
                if x.decision != Decision::Allow {
                    let rule = x.rule.clone().unwrap_or_else(|| "?".into());
                    let r = g.rules.entry(rule.clone()).or_default();
                    if x.decision == Decision::Deny {
                        r.deny += 1;
                    } else {
                        r.ask += 1;
                    }
                    r.last = r.last.max(Some(x.t));
                    if let Some(h) = &x.cmd {
                        hashes.entry(rule).or_default().insert(h);
                    }
                }
            }
            // R102: a refusal before any check; not a check, no hook time
            // sample.
            Event::Hook(h) if h.outcome == HookOutcome::Behind => {
                acc(&mut by, &h.repo, h.tier).row.behind += 1;
            }
            Event::Hook(h) => {
                let a = acc(&mut by, &h.repo, h.tier);
                // One time sample per hook run (and row): a push of five
                // refs is one wait, not five.
                if a.hook_runs
                    .insert((h.hook.clone(), h.t, h.ms, h.run.clone()))
                {
                    a.hook_ms
                        .push(h.ms.saturating_sub(h.repo_hook_ms.unwrap_or(0)));
                }
                let retry = h.outcome != HookOutcome::RefusedCap
                    && h.job.as_ref().is_some_and(|j| refused.remove(j));
                if retry && matches!(h.outcome, HookOutcome::CacheHit | HookOutcome::Passed) {
                    a.row.cap_retries += 1;
                    continue;
                }
                a.row.checks += 1;
                match h.outcome {
                    HookOutcome::CacheHit => a.row.cache_hits += 1,
                    HookOutcome::Passed => a.row.passed_inline += 1,
                    HookOutcome::RemoteVerified => a.row.remote_verified += 1,
                    HookOutcome::Failed => a.row.failed += 1,
                    HookOutcome::Error => a.row.errors += 1,
                    // Counted above, outside `checks`.
                    HookOutcome::Behind => {}
                    HookOutcome::RefusedCap => {
                        a.row.cap_refusals += 1;
                        if let Some(j) = &h.job {
                            refused.insert(j);
                        }
                        // The job was running when the hook refused, so
                        // any line of it is its end.
                        match h.job.as_ref().and_then(|j| ends.get(j)) {
                            Some(Some(end)) => a.refusal_wait.push(ms_between(h.t, *end)),
                            Some(None) => a.row.cap_refusals_lost += 1,
                            None => a.row.cap_refusals_open += 1,
                        }
                    }
                }
            }
            Event::Job(j) => {
                if !counted.insert(&j.job) {
                    continue;
                }
                let a = acc(&mut by, &j.repo, Some(j.tier));
                a.row.jobs += 1;
                match j.by.as_str() {
                    "hook" => a.row.jobs_by_hook += 1,
                    "step" => a.row.jobs_step += 1,
                    _ => a.row.jobs_prewarm += 1,
                }
                a.row.jobs_not_pass += u32::from(j.verdict != "pass");
                if j.verdict != LOST {
                    a.wall.push(j.wall_ms);
                    a.queue.push(j.job_queue_ms + j.slot_queue_ms);
                }
                a.row.steps += j.steps;
                a.row.steps_reused += j.steps_reused;
                a.row.steps_fresh += j.steps_fresh;
                a.row.flaky += j.flaky;
                a.row.jobs_flaky += u32::from(j.flaky > 0);
                a.row.quarantined += j.quarantined;
            }
        }
    }
    for (rule, set) in hashes {
        if let Some(r) = g.rules.get_mut(&rule) {
            r.distinct = u32::try_from(set.len()).unwrap_or(u32::MAX);
        }
    }
    g.us = Pct::of(us);
    let repos = by
        .into_values()
        .map(|a| {
            let mut row = a.row;
            row.cache_hit_rate =
                (row.checks > 0).then(|| f64::from(row.cache_hits) / f64::from(row.checks));
            row.refusal_wait_ms = Pct::of(a.refusal_wait);
            row.hook_ms = Pct::of(a.hook_ms);
            row.wall_ms = Pct::of(a.wall);
            row.queue_ms = Pct::of(a.queue);
            row
        })
        .collect();
    Stats {
        since,
        events: events.len(),
        first: events.iter().map(Event::time).min(),
        last: events.iter().map(Event::time).max(),
        repos,
        guard: g,
        chained: chained
            .into_iter()
            .map(|(hook, (row, us))| ChainedStats {
                hook: hook.to_owned(),
                us: Pct::of(us),
                ..row
            })
            .collect(),
    }
}

/// `1.2s`, `340ms`, `4m05s`, `1h02m`.
#[must_use]
pub fn fmt_ms(ms: u64) -> String {
    match ms {
        0..1_000 => format!("{ms}ms"),
        1_000..60_000 => format!("{:.1}s", ms as f64 / 1000.0),
        60_000..3_600_000 => format!("{}m{:02}s", ms / 60_000, ms / 1000 % 60),
        _ => format!("{}h{:02}m", ms / 3_600_000, ms / 60_000 % 60),
    }
}

fn pair(p: Option<Pct>, f: impl Fn(u64) -> String) -> String {
    p.map_or_else(|| "-".into(), |p| format!("{}/{}", f(p.p50), f(p.p90)))
}

/// The `cap` cell: refusals, then those still open and those lost.
fn cap_cell(r: &RepoTier) -> String {
    let notes: Vec<String> = [(r.cap_refusals_open, "open"), (r.cap_refusals_lost, "lost")]
        .into_iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, what)| format!("{n} {what}"))
        .collect();
    if notes.is_empty() {
        r.cap_refusals.to_string()
    } else {
        format!("{} ({})", r.cap_refusals, notes.join(", "))
    }
}

fn rate(n: u32, of: u32) -> String {
    if of == 0 {
        "-".into()
    } else {
        format!("{:.0}%", f64::from(n) * 100.0 / f64::from(of))
    }
}

/// The human summary.
#[must_use]
pub fn render(s: &Stats) -> Vec<String> {
    let when = |t: Option<jiff::Timestamp>| {
        t.map_or_else(
            || "-".into(),
            |t| {
                t.to_zoned(jiff::tz::TimeZone::system())
                    .strftime("%Y-%m-%d %H:%M")
                    .to_string()
            },
        )
    };
    let mut out = vec![format!(
        "tollgate stats: {} events, {} .. {}",
        s.events,
        when(s.first),
        when(s.last)
    )];
    if !s.repos.is_empty() {
        let mut rows: Vec<Vec<String>> = vec![
            [
                "repo",
                "tier",
                "checks",
                "hit",
                "inline",
                "remote",
                "cap",
                "cap->end",
                "behind",
                "retry",
                "failed",
                "hook p50/p90",
                "jobs",
                "wall p50/p90",
                "queue p50/p90",
                "reuse",
                "flaky",
            ]
            .map(str::to_owned)
            .to_vec(),
        ];
        for r in &s.repos {
            rows.push(vec![
                r.repo.clone(),
                r.tier.clone(),
                r.checks.to_string(),
                rate(r.cache_hits, r.checks),
                r.passed_inline.to_string(),
                r.remote_verified.to_string(),
                cap_cell(r),
                pair(r.refusal_wait_ms, fmt_ms),
                r.behind.to_string(),
                r.cap_retries.to_string(),
                (r.failed + r.errors).to_string(),
                pair(r.hook_ms, fmt_ms),
                r.jobs.to_string(),
                pair(r.wall_ms, fmt_ms),
                pair(r.queue_ms, fmt_ms),
                // Steps that did not run: L16 reuse and R101 same tree.
                rate(r.steps_reused + r.steps_fresh, r.steps),
                r.flaky.to_string(),
            ]);
        }
        out.extend(table(&rows));
    }
    let g = &s.guard;
    out.push(format!(
        "guard: {} calls: {} allow ({} rewritten), {} ask, {} deny; own time p50/p90 {}",
        g.calls,
        g.allow,
        g.rewrite,
        g.ask,
        g.deny,
        pair(g.us, fmt_us),
    ));
    if !g.rules.is_empty() {
        out.push("asks and denies by rule (review for false denies):".into());
        let mut rules: Vec<(&String, &RuleCount)> = g.rules.iter().collect();
        rules.sort_by_key(|(id, r)| (std::cmp::Reverse(r.deny + r.ask), (*id).clone()));
        let mut rows = vec![
            ["rule", "deny", "ask", "distinct", "last"]
                .map(str::to_owned)
                .to_vec(),
        ];
        for (id, r) in rules {
            rows.push(vec![
                id.clone(),
                r.deny.to_string(),
                r.ask.to_string(),
                r.distinct.to_string(),
                when(r.last),
            ]);
        }
        out.extend(table(&rows).into_iter().map(|l| format!("  {l}")));
    }
    if !s.chained.is_empty() {
        out.push("chained hooks (L19 budget 5ms, tollgate's own time):".into());
        let mut rows = vec![
            ["hook", "runs", "p50/p90", "exits"]
                .map(str::to_owned)
                .to_vec(),
        ];
        for c in &s.chained {
            let exits: Vec<String> = c
                .exits
                .iter()
                .map(|(x, n)| format!("{} {n}", x.as_str()))
                .collect();
            rows.push(vec![
                c.hook.clone(),
                c.runs.to_string(),
                pair(c.us, fmt_us),
                exits.join(", "),
            ]);
        }
        out.extend(table(&rows).into_iter().map(|l| format!("  {l}")));
    }
    out
}

fn fmt_us(us: u64) -> String {
    format!("{:.1}ms", us as f64 / 1000.0)
}

fn table(rows: &[Vec<String>]) -> Vec<String> {
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    let width: Vec<usize> = (0..cols)
        .map(|c| {
            rows.iter()
                .filter_map(|r| r.get(c))
                .map(|s| s.chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    rows.iter()
        .map(|r| {
            r.iter()
                .enumerate()
                .map(|(c, s)| format!("{s:<w$}", w = width[c]))
                .collect::<Vec<_>>()
                .join("  ")
                .trim_end()
                .to_owned()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::EnvSnapshot;

    fn dirs(root: &Path) -> Dirs {
        Dirs::from_env(&EnvSnapshot::from_pairs([("HOME", root.as_os_str())])).unwrap()
    }

    fn guard_event(rule: &str) -> Event {
        Event::Guard(GuardEvent {
            t: jiff::Timestamp::now(),
            tool: "Bash".into(),
            decision: Decision::Deny,
            rule: Some(rule.into()),
            rewrite: false,
            us: 100,
            cmd: Some("0123456789abcdef".into()),
        })
    }

    #[test]
    fn the_log_rotates_and_stays_bounded() {
        let tmp = tempfile::tempdir().unwrap();
        let d = dirs(tmp.path());
        // One event, so every line has the same length: a timestamp of
        // `now` drops trailing zeros of its fraction, and a shorter line
        // could move a rotation onto the last append, which leaves no live
        // log until the next write (the test failed about 1 run in 25).
        let event = guard_event("r");
        let line = serde_json::to_string(&event).unwrap().len() as u64 + 1;
        let max = line * 10;
        for _ in 0..200 {
            append(&d, std::slice::from_ref(&event), max, 2).unwrap();
        }
        let log = d.metrics_log();
        let sizes: Vec<u64> = [log.clone(), rotated(&log, 1), rotated(&log, 2)]
            .iter()
            .map(|p| std::fs::metadata(p).unwrap().len())
            .collect();
        assert!(sizes.iter().all(|s| *s <= max + line), "{sizes:?}");
        assert!(!rotated(&log, 3).exists());
        // Every kept line still parses.
        let lines: usize = [log.clone(), rotated(&log, 1), rotated(&log, 2)]
            .iter()
            .map(|p| std::fs::read_to_string(p).unwrap().lines().count())
            .sum();
        assert_eq!(read(&d, None).unwrap().events.len(), lines);
        assert!(lines >= 20, "{lines}");
    }

    #[test]
    fn a_wide_mode_is_narrowed_and_bad_lines_are_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let d = dirs(tmp.path());
        crate::fsx::ensure_dir(&d.state_dir()).unwrap();
        std::fs::write(d.metrics_log(), "garbage\n{\"kind\":\"other\"}\n").unwrap();
        std::fs::set_permissions(d.metrics_log(), std::fs::Permissions::from_mode(0o644)).unwrap();
        record(&d, &[guard_event("x")]);
        let mode = std::fs::metadata(d.metrics_log()).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(read(&d, None).unwrap().events.len(), 1);
    }

    #[test]
    fn unusable_rotated_paths_are_skipped_not_fatal() {
        let tmp = tempfile::tempdir().unwrap();
        let d = dirs(tmp.path());
        record(&d, &[guard_event("live")]);
        let log = d.metrics_log();
        let elsewhere = tmp.path().join("elsewhere.jsonl");
        std::fs::write(
            &elsewhere,
            format!(
                "{}\n",
                serde_json::to_string(&guard_event("followed")).unwrap()
            ),
        )
        .unwrap();
        let fifo = std::ffi::CString::new(rotated(&log, 1).as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        std::fs::create_dir(rotated(&log, 2)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, rotated(&log, 3)).unwrap();
        let got = read(&d, None).unwrap();
        assert_eq!(got.events.len(), 1, "{got:?}");
        assert_eq!(got.skipped.len(), 3, "{got:?}");
        // The symlink was not followed, and the live log stays readable.
        assert!(
            got.events
                .iter()
                .all(|e| matches!(e, Event::Guard(g) if g.rule.as_deref() == Some("live")))
        );

        // A rotated file without read access is skipped too.
        std::fs::remove_file(rotated(&log, 3)).unwrap();
        std::fs::write(rotated(&log, 3), "").unwrap();
        std::fs::set_permissions(rotated(&log, 3), std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(rotated(&log, 3)).is_err() {
            let got = read(&d, None).unwrap();
            assert_eq!((got.events.len(), got.skipped.len()), (1, 3), "{got:?}");
        }
    }

    #[test]
    fn the_key_is_made_once_and_hashes_are_keyed() {
        let tmp = tempfile::tempdir().unwrap();
        let d = dirs(tmp.path());
        let a = keyed_hash(&d, "git status").unwrap();
        assert_eq!(keyed_hash(&d, "git status").unwrap(), a);
        assert_ne!(keyed_hash(&d, "git log").unwrap(), a);
        assert_ne!(
            a,
            blake3::hash(b"git status").to_hex()[..16].to_owned(),
            "unkeyed"
        );
        // A key file with a wide mode is not trusted: no hash.
        std::fs::set_permissions(d.metrics_key(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(keyed_hash(&d, "git status"), None);
    }

    /// One hook run per call: each gets its own `t`, since `stats` takes
    /// one time sample per (hook, `t`, `ms`, run). Two calls can read the
    /// same clock value (macOS has microsecond resolution), which would
    /// make them one run.
    fn hook_event(outcome: HookOutcome, job: Option<&str>) -> Event {
        static RUN: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
        let n = RUN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Event::Hook(HookEvent {
            t: jiff::Timestamp::now() + jiff::SignedDuration::from_millis(n),
            hook: "pre-commit".into(),
            repo: "r".into(),
            tier: Some(Tier::Fast),
            outcome,
            job: job.map(|j| JobId::parse(j).unwrap()),
            ms: 5,
            repo_hook_ms: None,
            run: None,
        })
    }

    #[test]
    fn an_allow_after_a_cap_refusal_is_a_retry_not_a_hit() {
        // `tollgate wait <job> && git commit` checks the refused commit a
        // second time; that hit saved no time and is not cache value.
        let a = "20261109-120000-aaaaaaaa";
        let b = "20261109-120000-bbbbbbbb";
        let c = "20261109-120000-cccccccc";
        let d = "20261109-120000-dddddddd";
        let events = [
            // Refused twice (a commit run again before the job ended),
            // then the wait-and-retry: one retry.
            hook_event(HookOutcome::RefusedCap, Some(a)),
            hook_event(HookOutcome::RefusedCap, Some(a)),
            hook_event(HookOutcome::CacheHit, Some(a)),
            // The same tree later (an amend): real cache value.
            hook_event(HookOutcome::CacheHit, Some(a)),
            // A hit with no refusal before it.
            hook_event(HookOutcome::CacheHit, Some(b)),
            // Retried before the job ended: the hook joins it and passes
            // inline; still the refused commit's second check.
            hook_event(HookOutcome::RefusedCap, Some(c)),
            hook_event(HookOutcome::Passed, Some(c)),
            // The refused job failed: the retry is a deny the agent must
            // act on, so it stays a check and a failure.
            hook_event(HookOutcome::RefusedCap, Some(d)),
            hook_event(HookOutcome::Failed, Some(d)),
            hook_event(HookOutcome::CacheHit, Some(d)),
        ];
        let s = stats(&events, None);
        let r = &s.repos[0];
        assert_eq!(r.cap_retries, 2, "{r:#?}");
        assert_eq!(r.cap_refusals, 4, "{r:#?}");
        assert_eq!(r.cache_hits, 3, "{r:#?}");
        assert_eq!(r.passed_inline, 0, "{r:#?}");
        assert_eq!(r.failed, 1, "{r:#?}");
        assert_eq!(r.checks, 8, "{r:#?}");
        assert_eq!(
            r.checks,
            r.cache_hits
                + r.passed_inline
                + r.remote_verified
                + r.cap_refusals
                + r.failed
                + r.errors
        );
        assert_eq!(r.cache_hit_rate, Some(3.0 / 8.0));
        // Every hook run still counts in the hook's time.
        assert_eq!(r.hook_ms.map(|p| p.n), Some(10));
        let out = render(&s).join("\n");
        assert!(out.contains("retry"), "{out}");
    }

    fn hook_run(run: Option<&str>, t: jiff::Timestamp, tier: Tier, ms: u64) -> Event {
        Event::Hook(HookEvent {
            t,
            tier: Some(tier),
            ms,
            run: run.map(str::to_owned),
            ..match hook_event(HookOutcome::CacheHit, None) {
                Event::Hook(h) => h,
                _ => unreachable!(),
            }
        })
    }

    /// R102: a push refused because the remote branch moved is counted as
    /// `behind`, not as a check, and has no tier. Lines written before R102
    /// (with a tier, no `behind`) still read.
    #[test]
    fn behind_refusals_count_apart_from_checks_r102() {
        let old = r#"{"kind":"hook","t":"2026-11-09T12:00:00Z","hook":"pre-push","repo":"r","tier":"full","outcome":"cache_hit","job":null,"ms":5}"#;
        let new = r#"{"kind":"hook","t":"2026-11-09T12:00:01Z","hook":"pre-push","repo":"r","outcome":"behind","ms":3,"run":"aaaaaaaa"}"#;
        let events: Vec<Event> = [old, new, new]
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let Event::Hook(h) = &events[1] else {
            panic!("{events:?}")
        };
        assert_eq!((h.tier, h.outcome), (None, HookOutcome::Behind));
        // It writes back with no tier key.
        let text = serde_json::to_string(&events[1]).unwrap();
        assert!(!text.contains("tier"), "{text}");
        let s = stats(&events, None);
        let full = s.repos.iter().find(|r| r.tier == "full").unwrap();
        assert_eq!((full.checks, full.cache_hits, full.behind), (1, 1, 0));
        let none = s.repos.iter().find(|r| r.tier == "-").unwrap();
        assert_eq!((none.checks, none.behind), (0, 2), "{none:#?}");
        assert_eq!(none.hook_ms, None, "{none:#?}");
        let out = render(&s).join("\n");
        assert!(out.contains("behind"), "{out}");
    }

    #[test]
    fn hook_time_is_one_sample_per_hook_run_not_per_check() {
        // A pre-push of 5 refs that waited 30 s is one 30 s wait, as long
        // as a commit's one check; per-check samples weighted it 5 to 1.
        let t0 = jiff::Timestamp::now();
        let t1 = t0 + jiff::SignedDuration::from_secs(1);
        let mut events: Vec<Event> = (0..5)
            .map(|_| hook_run(Some("aaaaaaaa"), t0, Tier::Fast, 30_000))
            .collect();
        events.push(hook_run(Some("bbbbbbbb"), t1, Tier::Fast, 100));
        let s = stats(&events, None);
        let r = &s.repos[0];
        assert_eq!(r.checks, 6, "outcome counts stay per check: {r:#?}");
        assert_eq!(r.cache_hits, 6, "{r:#?}");
        let p = r.hook_ms.unwrap();
        assert_eq!((p.n, p.p50, p.p90), (2, 100, 30_000), "{p:?}");
    }

    #[test]
    fn a_hook_run_over_two_tiers_counts_once_in_each_row() {
        let t = jiff::Timestamp::now();
        let events = [
            hook_run(Some("aaaaaaaa"), t, Tier::Fast, 700),
            hook_run(Some("aaaaaaaa"), t, Tier::Full, 700),
            hook_run(Some("aaaaaaaa"), t, Tier::Full, 700),
        ];
        let s = stats(&events, None);
        let n: Vec<_> = s.repos.iter().map(|r| r.hook_ms.map(|p| p.n)).collect();
        assert_eq!(n, [Some(1), Some(1)], "{s:#?}");
    }

    #[test]
    fn old_lines_with_no_run_id_group_by_their_shared_time() {
        // Before `run`, one hook run wrote one `t` and one `ms` on every
        // check; lines from different runs never share the instant.
        let t0 = jiff::Timestamp::now();
        let t1 = t0 + jiff::SignedDuration::from_millis(1);
        let events = [
            hook_run(None, t0, Tier::Fast, 9_000),
            hook_run(None, t0, Tier::Fast, 9_000),
            hook_run(None, t0, Tier::Fast, 9_000),
            hook_run(None, t1, Tier::Fast, 9_000),
        ];
        let s = stats(&events, None);
        assert_eq!(s.repos[0].hook_ms.map(|p| p.n), Some(2), "{s:#?}");
        // Old lines still parse.
        let line = r#"{"kind":"hook","t":"2026-11-09T12:00:00Z","hook":"pre-push","repo":"r","tier":"fast","outcome":"cache_hit","ms":3}"#;
        assert!(serde_json::from_str::<Event>(line).is_ok());
    }

    #[test]
    fn percentiles_are_nearest_rank() {
        assert_eq!(Pct::of(vec![]), None);
        let p = Pct::of((1..=10).collect()).unwrap();
        assert_eq!((p.p50, p.p90, p.n), (5, 9, 10));
        let p = Pct::of(vec![7]).unwrap();
        assert_eq!((p.p50, p.p90), (7, 7));
    }

    #[test]
    fn repo_names() {
        assert_eq!(repo_name(Path::new("/r/acme/.git")), "acme");
        assert_eq!(repo_name(Path::new("/srv/x.git")), "x");
        assert_eq!(repo_name(Path::new("/srv/plain")), "plain");
    }

    #[test]
    fn logging_cost_is_small_against_the_guard() {
        // Item 50: measured, not assumed. 500 appends with the key read
        // and the hash, as the guard does them.
        let tmp = tempfile::tempdir().unwrap();
        let d = dirs(tmp.path());
        let start = std::time::Instant::now();
        for _ in 0..500 {
            let _ = keyed_hash(&d, "cargo test --workspace");
            record(&d, &[guard_event("r")]);
        }
        let per = start.elapsed() / 500;
        eprintln!("metrics: {per:?} per guard event");
        assert!(per < std::time::Duration::from_millis(2), "{per:?}");
    }

    fn job_end(job: &str, t: jiff::Timestamp, verdict: &str) -> Event {
        Event::Job(JobEvent {
            t,
            job: JobId::parse(job).unwrap(),
            repo: "r".into(),
            tier: Tier::Fast,
            by: "hook".into(),
            verdict: verdict.into(),
            wall_ms: 9_000,
            job_queue_ms: 10,
            slot_queue_ms: 0,
            checkout_wait_ms: 0,
            steps: 1,
            steps_reused: 0,
            steps_fresh: 0,
            flaky: 0,
            quarantined: 0,
            step_ms: None,
            branch: None,
        })
    }

    fn refusal_at(job: &str, t: jiff::Timestamp) -> Event {
        match hook_event(HookOutcome::RefusedCap, Some(job)) {
            Event::Hook(h) => Event::Hook(HookEvent { t, ..h }),
            _ => unreachable!(),
        }
    }

    #[test]
    fn a_refusal_is_open_only_while_its_job_has_no_end_line() {
        let t = jiff::Timestamp::now();
        let ms = |n: i64| jiff::SignedDuration::from_millis(n);
        let a = "20261109-120000-aaaaaaaa";
        let b = "20261109-120000-bbbbbbbb";
        let c = "20261109-120000-cccccccc";
        let d = "20261109-120000-dddddddd";
        let events = [
            // The hook takes its time after the settles and its stderr
            // lines; a job that ended in that gap has an end before it.
            refusal_at(a, t),
            job_end(a, t - ms(40), "pass"),
            // Ended later: the wait counts.
            refusal_at(b, t),
            job_end(b, t + ms(3_000), "pass"),
            // Its runner died between its line and its final state: the
            // reap's second line is not a second job.
            job_end(b, t + ms(9_000), "lost"),
            // Lost to a dead runner: the reap's line closes it. Its run
            // time is unknown and the reap can come hours later, so no
            // wall, queue or wait sample.
            refusal_at(c, t),
            job_end(c, t + ms(5_000), "lost"),
            // No end line: open.
            refusal_at(d, t),
        ];
        let s = stats(&events, None);
        let r = &s.repos[0];
        assert_eq!(r.cap_refusals, 4, "{r:#?}");
        assert_eq!(r.cap_refusals_open, 1, "{r:#?}");
        assert_eq!(r.cap_refusals_lost, 1, "{r:#?}");
        let w = r.refusal_wait_ms.unwrap();
        assert_eq!((w.n, w.p50, w.p90), (2, 0, 3_000), "{r:#?}");
        assert!(
            render(&s).iter().any(|l| l.contains("4 (1 open, 1 lost)")),
            "{:#?}",
            render(&s)
        );
        assert_eq!((r.jobs, r.jobs_not_pass), (3, 1), "{r:#?}");
        assert_eq!(r.wall_ms.map(|p| p.n), Some(2), "{r:#?}");
        assert_eq!(r.queue_ms.map(|p| p.n), Some(2), "{r:#?}");
    }

    #[test]
    fn chained_stats_count_exits_and_leave_out_the_repo_hook_l19() {
        let line = r#"{"kind":"chained","t":"2026-11-09T12:00:00Z","hook":"post-commit","repo":"r","exit":"marker","us":900}"#;
        let first: Event = serde_json::from_str(line).unwrap();
        let second = Event::Chained(ChainedEvent {
            t: first.time(),
            hook: "post-commit".into(),
            repo: "r".into(),
            exit: ChainedExit::Full,
            us: 400_000,
            repo_hook_us: Some(397_000),
        });
        let third = Event::Chained(ChainedEvent {
            hook: "post-checkout".into(),
            exit: ChainedExit::Chain,
            us: 700,
            repo_hook_us: None,
            ..match &second {
                Event::Chained(c) => c.clone(),
                _ => unreachable!(),
            }
        });
        let s = stats(&[first, second, third], None);
        assert!(s.repos.is_empty(), "{s:#?}");
        let hooks: Vec<&str> = s.chained.iter().map(|c| c.hook.as_str()).collect();
        assert_eq!(hooks, ["post-checkout", "post-commit"]);
        let pc = &s.chained[1];
        assert_eq!(pc.runs, 2);
        assert_eq!(
            pc.exits.iter().map(|(x, n)| (*x, *n)).collect::<Vec<_>>(),
            [(ChainedExit::Marker, 1), (ChainedExit::Full, 1)]
        );
        // The repo hook's 397 ms are not tollgate's.
        assert_eq!(pc.us.map(|p| (p.p50, p.p90)), Some((900, 3000)));
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["chained"][1]["exits"]["full"], 1, "{json:#}");
        let out = render(&s).join("\n");
        assert!(out.contains("marker 1, full 1"), "{out}");
        assert!(out.contains("0.9ms/3.0ms"), "{out}");
    }
}
