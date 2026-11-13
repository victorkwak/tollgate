//! The detached job runner (R33-R35, R38, R40-R46, R49, R50, R54-R58,
//! R64, R76, R81, R91-R93, L15, L16).
//!
//! A front end (`tollgate check`, the hooks) plans a job, writes
//! `jobs/<id>/spec.json` and starts `tollgate __run-job <id>` detached
//! ([`super::spawn`]). The runner:
//!
//! 1. waits for the sticky verify checkout lock within the queue budget,
//!    giving up when cancelled or superseded (R33, R87, R89);
//! 2. defers on low disk (R44), then updates the checkout to `T` (R42) and
//!    runs setup steps (R45);
//! 3. reads `cargo metadata` in the checkout (R50) and selects (R55-R58);
//! 4. re-checks the record store with the exact selection (a covering pass
//!    may exist), then runs each step under its resource slots (R85) and
//!    process control (R35), reusing stored step passes where allowed
//!    (L16);
//! 5. checks that tracked files are unchanged (R42), writes
//!    `report.json`, then the record (R81), the flaky log (R93) and the
//!    final job state.
//!
//! The job's time limit counts from the first step start and excludes the
//! time spent waiting for resource slots (R33).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::checkout::{self, Checkout, LockWait, Place, PrepareInput};
use super::env::{EnvFile, JobEnv};
use super::exec::{self, ExecEnd, ExecSpec};
use super::probe::ToolProbe;
use super::setup::{self, SetupResult};
use crate::cache::record::{
    ENVIRONMENTAL_TTL, ErrorCause, Needed, Record, Selection, StepResult, StepStatus, Verdict,
};
use crate::cache::step::{self as step_store, StoredStep};
use crate::cache::store::{Lookup, LookupRequest, RecordStore};
use crate::cache::{Fingerprint, RECORD_SCHEMA};
use crate::config::host::{Budgets, HostConfig};
use crate::config::repo::{RepoConfig, StepKind, ValidationContext};
use crate::config::{Platform, Tier};
use crate::dirs::Dirs;
use crate::env::EnvSnapshot;
use crate::fsx;
use crate::gitx::{Git, Oid, TreeEntry};
use crate::ids::{JobId, RecordKey, RepoKey};
use crate::locks::{self, AcquireError, AcquireOptions, Priority, Semaphore};
use crate::policy::ConfigSource;
use crate::report::{self, FlakyEntry, JobReport, Outcome, StepReport};
use crate::sched::{JobState, JobStore, Origin, StateKind, Transition};
use crate::select::{self, WorkspaceMap, detect};
use crate::steps::junit::{self, QuarantineHit};
use crate::steps::{self, Decision, InvocationCtx, PlannedStep, Scope, nextest};

/// Version of `spec.json`.
pub const SPEC_SCHEMA: u32 = 1;

/// The policy part of a job spec (L2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicySpec {
    /// Policy commit.
    pub commit: Option<Oid>,
    /// Anchor ref.
    pub anchor: Option<String>,
    /// Committer date of the policy commit (R69).
    pub committer_date: Option<jiff::civil::Date>,
    /// The effective config.
    pub config: RepoConfig,
    /// Its source.
    pub source: ConfigSource,
    /// Detection notes.
    pub notes: Vec<String>,
    /// nextest configs of the policy commit by Rust root (R49).
    pub nextest_configs: BTreeMap<PathBuf, String>,
    /// The `POLICY:` line.
    pub line: Option<String>,
    /// R71: tool configs the checkout must hold in the policy commit's
    /// version.
    #[serde(default)]
    pub overlay: BTreeMap<PathBuf, crate::policy::OverlayFile>,
    /// R94: the policy commit's Python baseline files by path.
    #[serde(default)]
    pub baselines: BTreeMap<PathBuf, String>,
}

impl PolicySpec {
    /// From a resolved policy.
    #[must_use]
    pub fn from_policy(p: &crate::policy::Policy) -> Self {
        Self {
            commit: p.base.commit.clone(),
            anchor: p.base.anchor.clone(),
            committer_date: p.base.committer_date,
            config: p.config.clone(),
            source: p.source.clone(),
            notes: p.notes.clone(),
            nextest_configs: p.nextest_configs.clone(),
            line: p.line(),
            overlay: p.overlay.clone(),
            baselines: p.baselines.clone(),
        }
    }
}

/// `jobs/<id>/spec.json`: everything the runner needs, planned by the
/// front end.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobSpec {
    /// [`SPEC_SCHEMA`].
    pub schema: u32,
    /// Job id.
    pub id: JobId,
    /// Record key (R74).
    pub key: RecordKey,
    /// The tree to check (R40).
    pub tree: Oid,
    /// Tier.
    pub tier: Tier,
    /// Fingerprint (R74).
    pub fingerprint: Fingerprint,
    /// The repo's common dir.
    pub common_dir: PathBuf,
    /// Repo key (R41).
    pub repo_key: RepoKey,
    /// Origin: the agent worktree (realpath) and ref (L15, R89).
    pub origin: Origin,
    /// Base tree of the selection (R55).
    pub base_tree: Option<Oid>,
    /// False when selection is disabled: `full`, no base, untrusted base
    /// or an empty diff (R54, R56).
    pub select: bool,
    /// Why selection is disabled, for the report.
    pub select_note: Option<String>,
    /// The policy (L2).
    pub policy: PolicySpec,
    /// The host config (its hash is in the fingerprint).
    pub host: HostConfig,
    /// Budgets with the repo overrides (R33).
    pub budgets: Budgets,
    /// The base job environment (R52).
    pub job_env: Vec<(String, String)>,
    /// L16: stored step passes may be reused.
    pub allow_reuse: bool,
    /// `check --rerun`: no covering record shortcut, no reuse.
    pub rerun: bool,
    /// R101: take the steps that already ran and passed on this tree,
    /// tier and fingerprint (`check --rerun --all` turns it off).
    #[serde(default = "yes")]
    pub carry: bool,
    /// Queue rank (R89).
    pub priority: Priority,
    /// Creation time.
    pub created: jiff::Timestamp,
    /// R105: a `tollgate run <step>` job. Its `key` is then the claim key
    /// of the run (R88), not a record key: the job writes no tree record
    /// and makes no record lookup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_run: Option<StepRun>,
    /// R112: `pre-push` created the job. Only such a job is ended when the
    /// remote moves past every candidate it checks; specs written before
    /// the field read as false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub for_push: bool,
}

/// What a `tollgate run <step>` job runs (R105).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepRun {
    /// The step name.
    pub step: String,
    /// Arguments that narrow the step (after `--`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// The record key of the tree, tier and fingerprint: where a pass
    /// without arguments goes in the same-tree store (R101).
    pub record_key: RecordKey,
    /// The key the pass is stored under: the step key, or the run key of
    /// the arguments ([`step_store::run_key`]).
    pub run_key: crate::ids::StepKey,
}

impl StepRun {
    /// The claim key of the run (R88): derived from the run key, in its
    /// own domain, so it is never the record key of a tier job.
    #[must_use]
    pub fn claim_key(run_key: &crate::ids::StepKey) -> RecordKey {
        let mut h = blake3::Hasher::new();
        h.update(b"tollgate step run claim\0");
        h.update(run_key.as_str().as_bytes());
        RecordKey::from_hash(&h.finalize())
    }

    /// True when arguments narrow the step.
    #[must_use]
    pub fn narrowed(&self) -> bool {
        !self.args.is_empty()
    }
}

/// The `run` text of a `command` step with `args` appended, each quoted
/// for `sh` (R105).
#[must_use]
pub fn with_args(run: &str, args: &[String]) -> String {
    let mut out = run.to_owned();
    for a in args {
        out.push(' ');
        out.push('\'');
        out.push_str(&a.replace('\'', "'\\''"));
        out.push('\'');
    }
    out
}

fn yes() -> bool {
    true
}

impl JobSpec {
    /// `jobs/<id>/spec.json`.
    #[must_use]
    pub fn path(dirs: &Dirs, id: &JobId) -> PathBuf {
        dirs.job_dir(id).join("spec.json")
    }

    /// Reads a spec.
    pub fn read(dirs: &Dirs, id: &JobId) -> Result<Self, String> {
        let path = Self::path(dirs, id);
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let spec: Self =
            serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        if spec.schema != SPEC_SCHEMA || &spec.id != id {
            return Err(format!("{}: wrong schema or job id", path.display()));
        }
        Ok(spec)
    }

    /// The spec as `spec.json` bytes. It is written with `job.json` when the
    /// job dir is made ([`JobStore::create_with`]).
    pub fn to_json(&self) -> std::io::Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(std::io::Error::other)
    }

    /// The base job environment.
    #[must_use]
    pub fn env(&self) -> JobEnv {
        JobEnv::from_vars(self.job_env.iter().map(|(k, v)| (k.clone(), v.clone())))
    }
}

/// The host name for records (R76).
#[must_use]
pub fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is writable for its length; gethostname NUL-terminates
    // when the name fits.
    let r = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if r != 0 {
        return "unknown".into();
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// How the job ends.
enum End {
    Verdict(Verdict, Option<ErrorCause>, Option<String>),
    NoRecord(ErrorCause, String),
    Cancelled,
    Superseded,
}

/// The error text for R71 probe findings at a job's start or after setup.
fn probe_message(found: &[String]) -> String {
    format!(
        "tool config check (R71: a tool config must be a regular file in the tree): {}",
        found.join("; ")
    )
}

fn error(cause: ErrorCause, msg: impl Into<String>) -> End {
    let msg = msg.into();
    if cause.writes_record() {
        End::Verdict(Verdict::Error, Some(cause), Some(msg))
    } else {
        End::NoRecord(cause, msg)
    }
}

struct Runner<'a> {
    dirs: &'a Dirs,
    spec: JobSpec,
    store: JobStore,
    job_dir: PathBuf,
    report: JobReport,
    env: JobEnv,
    repo_git: Git,
    log: PathBuf,
    started: Option<Instant>,
    run_time: Duration,
    record_selection: Selection,
    step_results: Vec<StepResult>,
    known_tests_full: Option<BTreeSet<String>>,
    /// L16 step passes of this job, stored only when the job ends with a
    /// verdict of `pass` or `fail` (never after a config, checkout or
    /// environmental end, R42).
    pending_steps: Vec<StoredStep>,
    /// L16: at least one step result was reused, so this job did not run
    /// every step fresh.
    reused: bool,
    /// Lock fds every process of the job inherits: the checkout lock (R35,
    /// R87), so a step that outlives a dead runner keeps the checkout from
    /// the next job until it is reaped.
    inherit: Vec<std::os::fd::RawFd>,
    /// Workspace maps of this job's Rust roots (R44 after the job).
    maps: BTreeMap<PathBuf, Option<WorkspaceMap>>,
    /// `run --here` (R47): no checkout, no record, report in this dir.
    here: bool,
    /// Take resource slots (R85; `run --here --no-host-locks` turns it off).
    use_locks: bool,
    /// This binary, for `tollgate __step` (R94).
    tollgate: PathBuf,
    /// R71 tool-config probe of the verify checkout (none for `--here`).
    probe: Option<ToolProbe>,
}

/// The runner entry point (`tollgate __run-job <id>`). Returns the exit
/// code: 0 when the job ended with a verdict or no-record outcome, 1 when
/// it could not even start.
pub fn run_job(dirs: &Dirs, id: &JobId, runner_env: &EnvSnapshot) -> u8 {
    let spec = match JobSpec::read(dirs, id) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tollgate runner: {e}");
            return 1;
        }
    };
    // R35: orphans of steps reparent to the runner.
    if let Err(e) = crate::procs::become_subreaper() {
        eprintln!("tollgate runner: cannot become subreaper: {e}");
    }
    let job_dir = dirs.job_dir(id);
    let mut r = Runner::new(dirs, spec, job_dir, runner_env, false, true);
    let end = r.run();
    r.finish(end);
    0
}

/// `tollgate run --here` (R47): runs `spec`'s steps in `workdir` with no
/// verify checkout and no result cache, writing `report.json` and the
/// logs to `out`. Returns the report.
pub fn run_here(
    dirs: &Dirs,
    spec: JobSpec,
    workdir: &Path,
    out: &Path,
    runner_env: &EnvSnapshot,
    use_locks: bool,
) -> JobReport {
    let mut r = Runner::new(dirs, spec, out.to_owned(), runner_env, true, use_locks);
    let config = r.spec.policy.config.clone();
    let end = match fsx::ensure_dir(&out.join("tmp")) {
        Ok(()) => r
            .validate(&config)
            .or_else(|| r.setup_here(workdir, &config))
            .unwrap_or_else(|| r.check_tree(workdir, None, &config, &[])),
        Err(e) => error(ErrorCause::Internal, e.to_string()),
    };
    r.finish(end);
    r.report
}

fn skeleton(spec: &JobSpec) -> JobReport {
    let now = jiff::Timestamp::now();
    JobReport {
        schema: report::REPORT_SCHEMA,
        job_id: spec.id.clone(),
        tree: spec.tree.clone(),
        tier: spec.tier,
        outcome: Outcome::Verdict,
        verdict: None,
        cause: None,
        message: None,
        origin: spec.origin.clone(),
        base_tree: spec.base_tree.clone(),
        policy_commit: spec.policy.commit.clone(),
        policy_line: spec.policy.line.clone(),
        warnings: spec.policy.notes.clone(),
        selection: None,
        steps: Vec::new(),
        flaky: Vec::new(),
        quarantined: Vec::new(),
        covered_by: None,
        record_written: false,
        created: spec.created,
        started: None,
        checkout_wait_ms: None,
        finished: now,
        host: hostname(),
        tollgate_version: crate::VERSION.to_owned(),
    }
}

impl<'a> Runner<'a> {
    fn new(
        dirs: &'a Dirs,
        spec: JobSpec,
        job_dir: PathBuf,
        runner_env: &EnvSnapshot,
        here: bool,
        use_locks: bool,
    ) -> Self {
        Self {
            dirs,
            env: spec.env(),
            repo_git: Git::scrubbed(runner_env, &spec.common_dir),
            store: JobStore::new(dirs),
            log: job_dir.join("job.log"),
            job_dir,
            report: skeleton(&spec),
            spec,
            started: None,
            run_time: Duration::ZERO,
            record_selection: Selection::All,
            step_results: Vec::new(),
            known_tests_full: None,
            pending_steps: Vec::new(),
            reused: false,
            inherit: Vec::new(),
            probe: None,
            maps: BTreeMap::new(),
            here,
            use_locks,
            tollgate: tollgate_exe(),
        }
    }
}

/// The running tollgate binary. On Linux a binary replaced while the runner
/// runs (`tollgate install` after `cargo install`) shows as `<path>
/// (deleted)`; `/proc/self/exe` still execs it from the forked step.
fn tollgate_exe() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("tollgate"));
    #[cfg(target_os = "linux")]
    if exe.to_string_lossy().ends_with(" (deleted)") || !exe.is_file() {
        return PathBuf::from("/proc/self/exe");
    }
    exe
}

impl Runner<'_> {
    fn say(&self, line: &str) {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
        {
            let _ = writeln!(f, "{} {line}", jiff::Timestamp::now());
        }
    }

    fn queue_deadline(&self) -> Instant {
        let waited = jiff::Timestamp::now()
            .duration_since(self.spec.created)
            .unsigned_abs();
        let budget = self.spec.budgets.queue.get();
        Instant::now() + budget.saturating_sub(waited)
    }

    fn run(&mut self) -> End {
        let config = self.spec.policy.config.clone();
        if let Some(end) = self.validate(&config) {
            return end;
        }
        if let Some(end) = self.docs_only_shortcut() {
            return end;
        }
        let place = Place::new(
            &self.spec.host.verify.root(self.dirs),
            &self.spec.repo_key,
            self.spec.tier,
            &self.spec.origin.worktree,
        );
        // Queue: the sticky checkout lock (R87), within the queue budget. A
        // lock held by the leftover steps of a job whose runner died is
        // freed by reaping that job (R35).
        let store = self.store.clone();
        let id = self.spec.id.clone();
        let dirs = self.dirs.clone();
        let lock_path = place.lock.clone();
        let mut abort = || {
            reap_holder(&dirs, &lock_path, &id);
            queued_abort(&store, &id)
        };
        let asked = Instant::now();
        let lock = match checkout::lock(&place, self.queue_deadline(), &mut abort) {
            Ok(l) => {
                let _ = l.set_holder(self.spec.id.as_str());
                self.report.checkout_wait_ms = Some(millis(asked.elapsed()));
                l
            }
            Err(LockWait::Deadline) => {
                return error(
                    ErrorCause::Deferred,
                    "the queue budget ran out waiting for the verify checkout",
                );
            }
            Err(LockWait::Aborted(r)) if r == "superseded" => return End::Superseded,
            Err(LockWait::Aborted(_)) => return End::Cancelled,
            Err(LockWait::Io(e)) => return error(ErrorCause::Internal, e.to_string()),
        };
        // R44: defer on low disk.
        let root = self.spec.host.verify.root(self.dirs);
        if let Err(e) = fsx::ensure_dir(&root) {
            return error(ErrorCause::Disk, format!("{}: {e}", root.display()));
        }
        match checkout::free_bytes(&root) {
            Ok(free) if free < self.spec.host.verify.min_free.bytes() => {
                return error(
                    ErrorCause::Disk,
                    format!(
                        "{} has {} MiB free, below verify.min_free {}",
                        root.display(),
                        free >> 20,
                        self.spec.host.verify.min_free
                    ),
                );
            }
            Ok(_) => {}
            Err(e) => return error(ErrorCause::Disk, format!("{}: {e}", root.display())),
        }
        match self.store.transition(
            &self.spec.id,
            &[StateKind::Queued],
            JobState::Running {
                started: jiff::Timestamp::now(),
                pid: std::process::id(),
            },
        ) {
            Ok(Transition::Done(_)) => {}
            Ok(Transition::Refused(meta)) => {
                return match meta.state {
                    JobState::Superseded => End::Superseded,
                    _ => End::Cancelled,
                };
            }
            Err(e) => return error(ErrorCause::Internal, e.to_string()),
        }
        let tmp = self.job_dir.join("tmp");
        if let Err(e) = fsx::ensure_dir(&tmp) {
            return error(ErrorCause::Internal, e.to_string());
        }
        let co = match checkout::prepare(
            &PrepareInput {
                repo_git: &self.repo_git,
                common_dir: &self.spec.common_dir,
                origin: &self.spec.origin.worktree,
                tier: self.spec.tier,
                max_checkouts: self.spec.host.verify.max_checkouts(self.spec.tier),
            },
            &place,
            lock,
        ) {
            Ok(c) => c,
            Err(e) => return error(ErrorCause::Checkout, e.to_string()),
        };
        self.inherit = vec![co.lock_fd()];
        let end = self.in_checkout(&co);
        self.max_target(&co);
        end
    }

    fn in_checkout(&mut self, co: &Checkout) -> End {
        let config = self.spec.policy.config.clone();
        let cache_dirs: Vec<String> = config
            .steps
            .iter()
            .flat_map(|s| s.cache_dirs.iter().cloned())
            .collect();
        if let Err(e) = co.update(&self.env, &self.spec.tree, &cache_dirs) {
            return error(ErrorCause::Checkout, e.to_string());
        }
        // R71: the policy commit's tool configs, never the branch's own,
        // and none reached through a symlink.
        if let Err(e) = co.apply_overlay(&self.spec.policy.overlay) {
            return error(ErrorCause::Checkout, e.to_string());
        }
        let entries = match self.repo_git.ls_tree(&self.spec.tree) {
            Ok(e) => e,
            Err(e) => return error(ErrorCause::Internal, e.to_string()),
        };
        // R71, item 35: the tool-config probe before setup (a leftover
        // above the checkout, a dangling or outside link), and again after
        // every setup step and step.
        let probe = ToolProbe::new(
            &co.path,
            &entries,
            &self.spec.policy.overlay,
            config
                .setup
                .iter()
                .filter_map(|s| s.cwd.as_deref())
                .chain(config.steps.iter().filter_map(|s| s.cwd.as_deref())),
            &self.env,
            &self.spec.host.job.host_tool_configs,
        );
        let found = probe.findings();
        self.probe = Some(probe);
        if !found.is_empty() {
            return error(ErrorCause::Checkout, probe_message(&found));
        }
        self.say(&format!(
            "checkout {} holds {}",
            co.path.display(),
            self.spec.tree
        ));
        if let Some(end) = self.setup(co, &config, &entries) {
            return end;
        }
        let workdir = co.path.clone();
        self.check_tree(&workdir, Some(co), &config, &entries)
    }

    /// R64 per-job validation that needs no test list, before anything
    /// else of the job (R31): a config error ends every job, the docs-only
    /// shortcut included. R69: the quarantine cap counts from the policy
    /// commit's committer date, but never from a date after today (a commit
    /// can carry any date), and from today when there is no policy commit.
    fn validate(&mut self, config: &RepoConfig) -> Option<End> {
        let today = jiff::Zoned::now().date();
        let date = self
            .spec
            .policy
            .committer_date
            .map_or(today, |d| d.min(today));
        let v = config.validate_with(&ValidationContext {
            workspace_packages: None,
            known_tests: None,
            policy_commit_date: Some(date),
            host: Some(&self.spec.host),
        });
        self.report
            .warnings
            .extend(v.validation.warnings.iter().map(|w| format!("WARN {w}")));
        if v.validation.is_ok() {
            return None;
        }
        let errs: Vec<String> = v
            .validation
            .errors
            .iter()
            .map(ToString::to_string)
            .collect();
        Some(error(ErrorCause::Config, errs.join("; ")))
    }

    /// Selection, planning and steps in `workdir` (the checkout, or the
    /// current dir for `run --here`).
    fn check_tree(
        &mut self,
        workdir: &Path,
        co: Option<&Checkout>,
        config: &RepoConfig,
        entries: &[TreeEntry],
    ) -> End {
        let platform = Platform::current();
        let rust_roots = steps::rust_roots(config, self.spec.tier, platform);
        let maps: BTreeMap<PathBuf, Option<WorkspaceMap>> = rust_roots
            .iter()
            .map(|root| (root.clone(), self.metadata(workdir, root, entries)))
            .collect();
        self.maps.clone_from(&maps);
        let fast = match self.select(config, entries, &maps) {
            Ok(p) => p,
            Err(end) => return end,
        };
        let (picked, mut plan) = match fast {
            Some(f) => {
                self.record_selection = f.selection;
                (Some(f.picked), f.plan)
            }
            None => (None, steps::plan(config, self.spec.tier, None, platform)),
        };
        // R105: a step run runs that one step, narrowed by its arguments.
        if let Some(run) = &self.spec.step_run {
            plan.retain(|p| p.step.name == run.step);
            let Some(p) = plan.first_mut() else {
                return error(
                    ErrorCause::Config,
                    format!("step {:?} is not in the policy for this tier", run.step),
                );
            };
            if run.narrowed()
                && p.step.kind == StepKind::Command
                && let Some(r) = &p.step.run
            {
                p.step.run = Some(with_args(r, &run.args));
            }
        }
        if let Some(p) = plan
            .iter()
            .find(|p| matches!(p.decision, Decision::Run(_)) && !steps::is_built(p.step.kind))
        {
            return error(
                ErrorCause::Config,
                format!(
                    "step {:?}: kind {} is not built in this version",
                    p.step.name,
                    serde_json::to_string(&p.step.kind).unwrap_or_default()
                ),
            );
        }
        self.report.selection = Some(self.record_selection.clone());
        if let Some(p) = &picked {
            self.report.warnings.extend(p.warnings.iter().cloned());
            if p.code_paths.is_empty() {
                self.say("docs-only change (R61): no steps run");
            }
        }
        if !self.spec.rerun
            && self.spec.step_run.is_none()
            && let Some(end) = self.covered()
        {
            return end;
        }
        self.run_steps(workdir, co, config, &plan, &maps, entries)
    }

    /// Runs `[[setup]]` steps (R45).
    fn setup(&mut self, co: &Checkout, config: &RepoConfig, entries: &[TreeEntry]) -> Option<End> {
        let meta = co.meta().unwrap_or_else(|| unreachable_meta(co));
        for s in &config.setup {
            let hash = match setup::input_hash(s, entries) {
                Ok(h) => h,
                Err(e) => return Some(error(ErrorCause::Config, e)),
            };
            let log = self
                .job_dir
                .join(format!("setup-{}.log", report::slug(&s.name)));
            let store = self.store.clone();
            let id = self.spec.id.clone();
            let mut abort = || running_abort(&store, &id);
            match setup::run(
                s,
                &hash,
                meta.setup.get(&s.name).map(String::as_str),
                &co.path,
                &self.env,
                &log,
                &self.job_dir.join(crate::dirs::JOB_STEPS_DIR),
                None,
                &mut abort,
                &self.inherit,
            ) {
                SetupResult::UpToDate => self.say(&format!("setup {:?}: up to date", s.name)),
                SetupResult::Ran(d) => {
                    self.say(&format!(
                        "setup {:?}: ran in {:.1}s",
                        s.name,
                        d.as_secs_f64()
                    ));
                    // R71: before its result is kept as up to date.
                    let found = self.probe.as_ref().map_or_else(
                        || vec!["the tool-config probe is missing".to_owned()],
                        ToolProbe::findings,
                    );
                    if !found.is_empty() {
                        return Some(error(
                            ErrorCause::Checkout,
                            format!("setup {:?}: {}", s.name, probe_message(&found)),
                        ));
                    }
                    let name = s.name.clone();
                    let _ = co.update_meta(|m| {
                        m.setup.insert(name, hash);
                    });
                }
                SetupResult::Failed(m) => {
                    return Some(error(
                        ErrorCause::Setup,
                        format!(
                            "{m}; tollgate log {} setup-{}",
                            self.spec.id,
                            report::slug(&s.name)
                        ),
                    ));
                }
                SetupResult::Aborted(_) => return Some(End::Cancelled),
            }
        }
        None
    }

    /// `run --here` (R45, R47): every `[[setup]]` step runs in the work
    /// dir (a CI clone has no `node_modules` or `.venv`; there is no
    /// checkout meta to say what is up to date).
    fn setup_here(&mut self, workdir: &Path, config: &RepoConfig) -> Option<End> {
        for s in &config.setup {
            let log = self
                .job_dir
                .join(format!("setup-{}.log", report::slug(&s.name)));
            let mut never = || None;
            match setup::run(
                s,
                "",
                None,
                workdir,
                &self.env,
                &log,
                &self.job_dir.join(crate::dirs::JOB_STEPS_DIR),
                None,
                &mut never,
                &[],
            ) {
                SetupResult::Ran(d) => self.say(&format!(
                    "setup {:?}: ran in {:.1}s",
                    s.name,
                    d.as_secs_f64()
                )),
                SetupResult::UpToDate => {}
                SetupResult::Failed(m) => {
                    return Some(error(
                        ErrorCause::Setup,
                        format!("{m}; log: {}", log.display()),
                    ));
                }
                SetupResult::Aborted(_) => return Some(End::Cancelled),
            }
        }
        None
    }

    /// `cargo metadata` in the checkout (R50); `None` (and a warning) on
    /// failure, which makes the workspace whole (R58).
    fn metadata(
        &mut self,
        workdir: &Path,
        root: &Path,
        entries: &[TreeEntry],
    ) -> Option<WorkspaceMap> {
        let out_file = self.job_dir.join(format!(
            "metadata-{}.json",
            report::slug(&root.display().to_string())
        ));
        let store = self.store.clone();
        let id = self.spec.id.clone();
        let mut abort = || running_abort(&store, &id);
        let cwd = workdir.join(root);
        let env = self.target_env(&self.env, workdir, root);
        let out = exec::run(ExecSpec {
            program: "cargo".into(),
            arg0: None,
            args: vec!["metadata".into(), "--format-version".into(), "1".into()],
            cwd: &cwd,
            env: &env,
            log: &self.job_dir.join("metadata.log"),
            stdout: Some(&out_file),
            deadline: Some(Instant::now() + Duration::from_secs(600)),
            grace: Duration::from_secs(10),
            abort: &mut abort,
            inherit: &self.inherit,
            records: &self.job_dir.join(crate::dirs::JOB_STEPS_DIR),
        });
        let parsed = if out.success() {
            std::fs::read_to_string(&out_file)
                .map_err(|e| e.to_string())
                .and_then(|json| WorkspaceMap::from_metadata_json(&json, workdir, root))
        } else {
            Err(format!("cargo metadata: {:?}", out.end))
        };
        let _ = std::fs::remove_file(&out_file);
        match parsed {
            Ok(m) => {
                if !self.here
                    && let Some(key) = select::rust::map_key(entries, root, &self.spec.fingerprint)
                {
                    let _ = select::rust::store_cached(self.dirs, &key, &m);
                }
                Some(m)
            }
            Err(e) => {
                self.report.warnings.push(format!(
                    "WARN metadata for {}: {e}; selecting the whole workspace (R58)",
                    if root.as_os_str().is_empty() {
                        ".".into()
                    } else {
                        root.display().to_string()
                    }
                ));
                None
            }
        }
    }

    /// The fast selection (R55-R58); `Ok(None)` when selection is disabled.
    fn select(
        &mut self,
        config: &RepoConfig,
        entries: &[TreeEntry],
        maps: &BTreeMap<PathBuf, Option<WorkspaceMap>>,
    ) -> Result<Option<steps::FastPlan>, End> {
        if self.spec.tier == Tier::Full || !self.spec.select {
            if let Some(n) = &self.spec.select_note {
                self.say(&format!("selection disabled: {n}"));
            }
            return Ok(None);
        }
        let Some(base) = self.spec.base_tree.clone() else {
            return Ok(None);
        };
        let changes = select::changed_paths(&self.repo_git, &base, &self.spec.tree)
            .map_err(|e| error(ErrorCause::Internal, e.to_string()))?;
        if changes.is_empty() {
            // R56: an empty diff selects everything.
            return Ok(None);
        }
        let other = detect::roots_from_tree(entries).other();
        steps::fast_plan(config, &base, &changes, maps, &other, Platform::current())
            .map(Some)
            .map_err(|e| error(ErrorCause::Config, e))
    }

    /// R61 without a checkout: when the workspace maps of `T`'s manifests
    /// are cached and every change is docs-only, the job passes with zero
    /// steps at once (no checkout lock, no cargo).
    fn docs_only_shortcut(&mut self) -> Option<End> {
        if self.spec.tier != Tier::Fast || !self.spec.select {
            return None;
        }
        let base = self.spec.base_tree.clone()?;
        let entries = self.repo_git.ls_tree(&self.spec.tree).ok()?;
        let changes = select::changed_paths(&self.repo_git, &base, &self.spec.tree).ok()?;
        if changes.is_empty() {
            return None;
        }
        let config = self.spec.policy.config.clone();
        let platform = Platform::current();
        let mut maps = BTreeMap::new();
        for root in steps::rust_roots(&config, Tier::Fast, platform) {
            let key = select::rust::map_key(&entries, &root, &self.spec.fingerprint)?;
            maps.insert(root, Some(select::rust::load_cached(self.dirs, &key)?));
        }
        let other = detect::roots_from_tree(&entries).other();
        let fast = steps::fast_plan(&config, &base, &changes, &maps, &other, platform).ok()?;
        if !fast.picked.docs_only(&changes) {
            return None;
        }
        // R89: a cancelled or superseded job writes no pass, here as on the
        // checkout path.
        if let Some(r) = queued_abort(&self.store, &self.spec.id) {
            return Some(if r == "superseded" {
                End::Superseded
            } else {
                End::Cancelled
            });
        }
        match self.store.transition(
            &self.spec.id,
            &[StateKind::Queued],
            JobState::Running {
                started: jiff::Timestamp::now(),
                pid: std::process::id(),
            },
        ) {
            Ok(Transition::Done(_)) => {}
            Ok(Transition::Refused(meta)) => {
                return Some(match meta.state {
                    JobState::Superseded => End::Superseded,
                    _ => End::Cancelled,
                });
            }
            Err(e) => return Some(error(ErrorCause::Internal, e.to_string())),
        }
        self.say("docs-only change (R61): no steps run, no checkout needed");
        self.record_selection = fast.selection;
        self.report.selection = Some(self.record_selection.clone());
        for p in &fast.plan {
            let why = match &p.decision {
                Decision::Skip(w) => w.clone(),
                Decision::Run(_) => return None,
            };
            self.report
                .steps
                .push(StepReport::skipped(&p.step.name, p.step.kind, &why));
            self.step_results.push(StepResult {
                name: p.step.name.clone(),
                status: StepStatus::Skipped,
                duration_ms: 0,
                exit: None,
                log: None,
                failing: Vec::new(),
            });
        }
        Some(End::Verdict(Verdict::Pass, None, None))
    }

    /// A pass that covers the exact selection exists already (another job
    /// finished first).
    fn covered(&mut self) -> Option<End> {
        let store = RecordStore::new(self.dirs);
        let found = store
            .lookup(&LookupRequest {
                tree: &self.spec.tree,
                tier: self.spec.tier,
                fingerprint: &self.spec.fingerprint,
                needed: &Needed::Exact(self.record_selection.clone()),
                now: jiff::Timestamp::now(),
                // L16: a full job that may not reuse accepts only a fresh
                // full pass.
                fresh_only: self.spec.tier == Tier::Full && !self.spec.allow_reuse,
            })
            .ok()?;
        match found {
            Lookup::Pass(r) if r.job_id != self.spec.id => {
                self.report.covered_by = Some(r.job_id.clone());
                Some(End::Verdict(Verdict::Pass, None, None))
            }
            _ => None,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn run_steps(
        &mut self,
        workdir: &Path,
        co: Option<&Checkout>,
        config: &RepoConfig,
        plan: &[PlannedStep],
        maps: &BTreeMap<PathBuf, Option<WorkspaceMap>>,
        entries: &[TreeEntry],
    ) -> End {
        let today = jiff::Zoned::now().date();
        let mut used_logs: BTreeSet<String> = BTreeSet::new();
        let mut verdict = Verdict::Pass;
        let mut error_end: Option<End> = None;
        // R42: what the checkout holds before the first step (setup and
        // `cargo metadata` may add untracked files such as `Cargo.lock`).
        // R71: after each step, each overlaid tool config must still hold
        // what the overlay wrote (setup steps included, as the first
        // check runs after them).
        let cache_dirs: Vec<String> = config
            .steps
            .iter()
            .flat_map(|s| s.cache_dirs.iter().cloned())
            .collect();
        let before = match co.map(|c| c.untracked(&self.env, &cache_dirs)).transpose() {
            Ok(b) => b.unwrap_or_default(),
            Err(e) => return error(ErrorCause::Checkout, e.to_string()),
        };
        for ps in plan {
            let s = &ps.step;
            let scope = match &ps.decision {
                Decision::Skip(why) => {
                    self.report
                        .steps
                        .push(StepReport::skipped(&s.name, s.kind, why));
                    self.step_results.push(StepResult {
                        name: s.name.clone(),
                        status: StepStatus::Skipped,
                        duration_ms: 0,
                        exit: None,
                        log: None,
                        failing: Vec::new(),
                    });
                    continue;
                }
                Decision::Run(scope) => scope.clone(),
            };
            let root = steps::step_root(s);
            let map = maps.get(&root).and_then(Option::as_ref);
            let key = step_store::step_key(s, self.spec.tier, &self.spec.fingerprint, entries).ok();
            // R101: the step already ran and passed on this tree, tier and
            // fingerprint. That is a fresh result for this tree, so it also
            // holds where L16 reuse does not (a full ref, `--rerun`).
            if self.spec.carry
                && !self.here
                && let Some(k) = &key
                && let Some(fresh) =
                    step_store::read_fresh(self.dirs, &self.spec.key, &self.spec.fingerprint, k)
                && fresh.job != self.spec.id
                && fresh.scope.covers(&scope)
            {
                let mut rep = StepReport::skipped(&s.name, s.kind, "fresh");
                rep.status = StepStatus::Pass;
                rep.message = None;
                rep.scope = Some(fresh.scope.clone());
                rep.fresh_from = Some(fresh.job.clone());
                self.report.steps.push(rep);
                self.step_results.push(StepResult {
                    name: s.name.clone(),
                    status: StepStatus::Pass,
                    duration_ms: 0,
                    exit: None,
                    log: None,
                    failing: Vec::new(),
                });
                continue;
            }
            // L16: reuse a stored pass of the same step key.
            if self.spec.allow_reuse
                && !self.spec.rerun
                && let Some(k) = &key
                && let Some(stored) = step_store::read_stored(self.dirs, k)
                && stored.scope.covers(&scope)
            {
                let mut rep = StepReport::skipped(&s.name, s.kind, "reused");
                rep.status = StepStatus::Pass;
                rep.message = None;
                rep.scope = Some(stored.scope.clone());
                rep.reused_from = Some(stored.job.clone());
                self.reused = true;
                self.report.steps.push(rep);
                self.step_results.push(StepResult {
                    name: s.name.clone(),
                    status: StepStatus::Pass,
                    duration_ms: 0,
                    exit: None,
                    log: None,
                    failing: Vec::new(),
                });
                continue;
            }
            if steps::is_rust(s.kind)
                && let Some(missing) = self.missing_tool(s.kind)
            {
                error_end = Some(error(
                    ErrorCause::Setup,
                    format!("{missing} is not on the job PATH (R46)"),
                ));
                break;
            }
            let env = match self.step_env(s) {
                Ok(e) if steps::is_rust(s.kind) => self.target_env(&e, workdir, &root),
                Ok(e) => e,
                Err(end) => {
                    error_end = Some(end);
                    break;
                }
            };
            let mut slug = report::slug(&s.name);
            if !used_logs.insert(slug.clone()) {
                slug = format!("{slug}-{}", used_logs.len());
                used_logs.insert(slug.clone());
            }
            let log = self.job_dir.join(format!("{slug}.log"));
            let nextest_cfg = self.job_dir.join(format!("{slug}.nextest.toml"));
            let tool_config = self.job_dir.join(format!("{slug}.nextest-tool.toml"));
            let junit = self.job_dir.join(format!("{slug}.junit.xml"));
            let findings = self.job_dir.join(format!("{slug}.findings.json"));
            let _ = std::fs::remove_file(&findings);
            // R49, R94: the baseline of the policy commit, never the tree's.
            let baseline_kind = match s.kind {
                StepKind::PyrightBaseline => Some(steps::baseline::Kind::Pyright),
                StepKind::PytestBaseline => Some(steps::baseline::Kind::Pytest),
                _ => None,
            };
            let baseline_file = self.job_dir.join(format!("{slug}.baseline.json"));
            let baseline = match baseline_kind
                .and_then(|k| self.spec.policy.baselines.get(&root.join(k.file())))
            {
                Some(text) => match std::fs::write(&baseline_file, text) {
                    Ok(()) => Some(baseline_file.as_path()),
                    Err(e) => {
                        error_end = Some(error(ErrorCause::Internal, e.to_string()));
                        break;
                    }
                },
                None => None,
            };
            let root_dir = workdir.join(&root);
            let lang_ctx = steps::lang::LangCtx {
                root_dir: &root_dir,
                top: workdir,
                path: env.get("PATH"),
                tollgate: &self.tollgate,
                baseline,
                findings: &findings,
            };
            if (steps::lang::is_ts(s.kind) || steps::lang::is_python(s.kind))
                && let Some(missing) = steps::lang::missing_tool(s.kind, &lang_ctx)
            {
                let mut rep = StepReport::skipped(&s.name, s.kind, &missing);
                rep.status = StepStatus::Error;
                self.report.steps.push(rep);
                error_end = Some(error(
                    ErrorCause::Setup,
                    format!("step {:?}: {missing}", s.name),
                ));
                break;
            }
            if s.kind == StepKind::Nextest {
                // R49: the policy commit's nextest config (empty when it has
                // none, so the tree's own file is not read); R72: the tool
                // config with this step's JUnit path.
                let text = self
                    .spec
                    .policy
                    .nextest_configs
                    .get(&root)
                    .cloned()
                    .unwrap_or_default();
                let tool = nextest::tool_config(
                    &self.spec.host.nextest,
                    &config.select.fast.pg_tests,
                    &junit,
                    Some((self.step_limit(s), s.grace())),
                );
                let _ = std::fs::remove_file(&junit);
                if let Err(e) = std::fs::write(&nextest_cfg, text)
                    .and_then(|()| std::fs::write(&tool_config, tool))
                {
                    error_end = Some(error(ErrorCause::Internal, e.to_string()));
                    break;
                }
            }
            let inv = match steps::invocation(
                s,
                &scope,
                &InvocationCtx {
                    tier: self.spec.tier,
                    fast_tests: config.select.fast.tests,
                    nextest_config: &nextest_cfg,
                    tool_config: &tool_config,
                    map,
                    lang: Some(lang_ctx),
                },
            ) {
                Ok(Some(i)) => i,
                Ok(None) => {
                    let why = if s.kind == StepKind::CargoDoctest {
                        "no library target"
                    } else {
                        "no changed file left to lint"
                    };
                    let mut rep = StepReport::skipped(&s.name, s.kind, why);
                    rep.status = StepStatus::Pass;
                    self.report.steps.push(rep);
                    self.step_results.push(StepResult {
                        name: s.name.clone(),
                        status: StepStatus::Pass,
                        duration_ms: 0,
                        exit: None,
                        log: None,
                        failing: Vec::new(),
                    });
                    continue;
                }
                Err(e) => {
                    error_end = Some(error(ErrorCause::Config, e));
                    break;
                }
            };
            // R105: the arguments of a narrowed step run (a `command`
            // step has them in its `run` text already).
            let mut inv = inv;
            if let Some(run) = &self.spec.step_run
                && s.kind != StepKind::Command
            {
                inv.args.extend(run.args.iter().map(Into::into));
            }
            // Resources: canonical order, all or nothing, within the queue
            // budget (R85, R86, R33).
            let sems: Vec<Semaphore> = if self.use_locks {
                s.resources
                    .iter()
                    .map(|r| Semaphore::resource(self.dirs, r, self.spec.host.resource_slots(r)))
                    .collect()
            } else {
                Vec::new()
            };
            let store = self.store.clone();
            let id = self.spec.id.clone();
            let dirs = self.dirs.clone();
            let slot_paths: Vec<PathBuf> = sems
                .iter()
                .flat_map(|s| s.slot_paths().iter().cloned())
                .collect();
            let mut abort_wait = || {
                // Slots held by the leftovers of a dead runner (R35, R85).
                for p in &slot_paths {
                    reap_holder(&dirs, p, &id);
                }
                running_abort(&store, &id)
            };
            let asked = Instant::now();
            let held = match locks::acquire(
                &sems,
                AcquireOptions {
                    priority: self.spec.priority,
                    deadline: Some(Instant::now() + self.spec.budgets.queue.get()),
                    abort: Some(&mut abort_wait),
                    holder: Some(self.spec.id.as_str()),
                    ..AcquireOptions::default()
                },
            ) {
                Ok(h) => h,
                Err(AcquireError::Deadline) => {
                    error_end = Some(error(
                        ErrorCause::Deferred,
                        format!("the queue budget ran out waiting for {:?}", s.resources),
                    ));
                    break;
                }
                Err(AcquireError::Aborted(_)) => {
                    error_end = Some(End::Cancelled);
                    break;
                }
                Err(AcquireError::Io(e)) => {
                    error_end = Some(error(ErrorCause::Internal, e.to_string()));
                    break;
                }
            };
            let queue_ms = (!sems.is_empty()).then(|| millis(asked.elapsed()));
            if self.started.is_none() {
                self.started = Some(Instant::now());
                self.report.started = Some(jiff::Timestamp::now());
            }
            let step_limit = self.step_limit(s);
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log)
            {
                let _ = writeln!(f, "$ {}", inv.display());
            }
            let cancel_store = self.store.clone();
            let cancel_id = self.spec.id.clone();
            let mut abort = || running_abort(&cancel_store, &cancel_id);
            let cwd = workdir.join(&root);
            let quarantined_before = self.report.quarantined.len();
            // R85: the step's processes hold its slots (and the checkout)
            // while they live, also after a runner death.
            let inherit: Vec<std::os::fd::RawFd> = self
                .inherit
                .iter()
                .copied()
                .chain(held.slots().iter().map(|h| {
                    use std::os::fd::AsRawFd as _;
                    h.lock().file().as_raw_fd()
                }))
                .collect();
            let out = exec::run(ExecSpec {
                program: inv.program.clone(),
                arg0: inv.arg0.clone(),
                args: inv.args.clone(),
                cwd: &cwd,
                env: &env,
                log: &log,
                stdout: None,
                deadline: Some(Instant::now() + step_limit),
                grace: s.grace(),
                abort: &mut abort,
                inherit: &inherit,
                records: &self.job_dir.join(crate::dirs::JOB_STEPS_DIR),
            });
            drop(held);
            self.run_time += out.duration;
            let mut rep = StepReport {
                name: s.name.clone(),
                kind: s.kind,
                status: StepStatus::Pass,
                duration_ms: millis(out.duration),
                exit: out.exit_code(),
                log: Some(format!("{slug}.log")),
                command: Some(inv.display()),
                scope: Some(scope.clone()),
                reused_from: None,
                fresh_from: None,
                artifacts: None,
                resources: s.resources.iter().map(|r| r.as_str().to_owned()).collect(),
                queue_ms,
                message: None,
                failing: Vec::new(),
                items: Vec::new(),
                rerun: Vec::new(),
                tail: Vec::new(),
            };
            let mut stop = false;
            match &out.end {
                ExecEnd::SpawnFailed(e) => {
                    rep.status = StepStatus::Error;
                    rep.message = Some(format!("could not start {}: {e} (R46)", inv.display()));
                    error_end = Some(error(
                        ErrorCause::Setup,
                        format!("step {:?} could not start: {e}", s.name),
                    ));
                    stop = true;
                }
                ExecEnd::TimedOut => {
                    rep.status = StepStatus::Timeout;
                    rep.message = Some(format!(
                        "killed after {}s (step or job limit, R33)",
                        step_limit.as_secs()
                    ));
                    rep.tail = report::tail(&log, report::TAIL_LINES);
                    verdict = Verdict::Timeout;
                    stop = true;
                }
                ExecEnd::Aborted(_) => {
                    error_end = Some(End::Cancelled);
                    stop = true;
                }
                ExecEnd::Exited(status) => {
                    if baseline_kind.is_some() {
                        Self::baseline_result(&mut rep, status.success(), &findings, &log);
                    } else if s.kind == StepKind::Nextest {
                        self.nextest_result(
                            &mut rep,
                            status.code(),
                            &junit,
                            &slug,
                            &scope,
                            config,
                            today,
                        );
                    } else if !status.success() {
                        rep.status = StepStatus::Fail;
                        rep.tail = report::tail(&log, report::TAIL_LINES);
                    }
                }
            }
            // R106: artefacts of a step that ran to an end (pass, fail,
            // timeout), before the next step can change them.
            if !s.artifacts.is_empty() && matches!(out.end, ExecEnd::Exited(_) | ExecEnd::TimedOut)
            {
                self.keep_artifacts(s, workdir, &slug, &mut rep);
            }
            // R42 after every step that ran, so a step that changes the tree
            // is named and its pass is never stored for reuse (L16).
            if !stop && let Some(co) = co {
                let changes = match self.probe.as_ref() {
                    Some(probe) => co.changes(
                        &self.env,
                        &self.spec.tree,
                        &cache_dirs,
                        &before,
                        &self.spec.policy.overlay,
                        probe,
                    ),
                    None => Ok(vec!["the tool-config probe is missing".to_owned()]),
                };
                match changes {
                    Ok(changed) if !changed.is_empty() => {
                        rep.status = StepStatus::Error;
                        rep.message = Some(format!(
                            "changed the checkout (R42): {}",
                            changed.join(", ")
                        ));
                        error_end = Some(error(
                            ErrorCause::Checkout,
                            format!(
                                "step {:?} changed the checkout: {}",
                                s.name,
                                changed.join(", ")
                            ),
                        ));
                        stop = true;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        rep.status = StepStatus::Error;
                        error_end = Some(error(ErrorCause::Checkout, e.to_string()));
                        stop = true;
                    }
                }
            }
            if rep.status == StepStatus::Fail && verdict == Verdict::Pass {
                verdict = Verdict::Fail;
            }
            // A pass that relied on a quarantine is not reused: the entry
            // expires, the stored pass would not.
            let quarantined_here = self.report.quarantined.len() > quarantined_before;
            if rep.status == StepStatus::Pass
                && !quarantined_here
                && let Some(k) = key
            {
                self.pending_steps.push(StoredStep {
                    key: k,
                    step: s.name.clone(),
                    job: self.spec.id.clone(),
                    scope: scope.clone(),
                    finished: jiff::Timestamp::now(),
                });
            }
            self.step_results.push(StepResult {
                name: rep.name.clone(),
                status: rep.status,
                duration_ms: rep.duration_ms,
                exit: rep.exit,
                log: rep.log.clone(),
                failing: rep
                    .failing
                    .iter()
                    .map(|f| format!("{} {} {}", f.package, f.binary_id, f.name))
                    .chain(rep.items.iter().cloned())
                    .collect(),
            });
            self.report.steps.push(rep);
            if stop {
                break;
            }
        }
        if let Some(end) = error_end {
            return end;
        }
        // R64: quarantine entries must name a listed test.
        if let Some(known) = &self.known_tests_full {
            let unknown: Vec<&str> = config
                .quarantine
                .iter()
                .filter(|q| !known.contains(&q.test))
                .map(|q| q.test.as_str())
                .collect();
            if !unknown.is_empty() {
                return error(
                    ErrorCause::Config,
                    format!(
                        "quarantine entries name no listed test (R64): {}",
                        unknown.join(", ")
                    ),
                );
            }
        }
        End::Verdict(verdict, None, None)
    }

    /// R106: copies the step's artefacts into `artifacts/<slug>/` of the
    /// job dir and names that dir in its report line. Over the limit or on
    /// an error, the step's message says so; the verdict does not change.
    fn keep_artifacts(
        &self,
        s: &crate::config::repo::Step,
        workdir: &Path,
        slug: &str,
        rep: &mut StepReport,
    ) {
        let dest = self.job_dir.join("artifacts").join(slug);
        let limit = self.spec.host.job.artifacts_limit();
        let note = match super::artifacts::copy(workdir, &s.artifacts, &dest, limit) {
            Ok(c) => {
                if c.files > 0 {
                    let abs = std::path::absolute(&dest).unwrap_or(dest.clone());
                    rep.artifacts = Some(abs.display().to_string());
                }
                self.say(&format!(
                    "step {:?}: {} artefact file(s), {} bytes",
                    s.name, c.files, c.bytes
                ));
                let mut notes = Vec::new();
                for r in &c.refused {
                    notes.push(format!("artifacts: {r}; nothing copied from it (R106)"));
                }
                if c.walk_stopped {
                    notes.push(format!(
                        "artifacts: the walk stopped after {} entries; narrow the paths (R106)",
                        super::artifacts::MAX_VISITS
                    ));
                }
                if c.over_limit > 0 {
                    notes.push(format!(
                        "artifacts: {} file(s) not kept, over the limit of {} bytes (R106)",
                        c.over_limit, limit
                    ));
                }
                (!notes.is_empty()).then(|| notes.join("; "))
            }
            Err(e) => Some(format!("artifacts: copy failed: {e} (R106)")),
        };
        if let Some(n) = note {
            rep.message = Some(match rep.message.take() {
                Some(m) => format!("{m}; {n}"),
                None => n,
            });
        }
    }

    /// What is left of the job limit (R33; slot waits do not count), and
    /// at most the step's own timeout.
    fn step_limit(&self, s: &crate::config::repo::Step) -> Duration {
        let job_left = self
            .spec
            .budgets
            .job_limit(self.spec.tier)
            .saturating_sub(self.run_time);
        s.timeout
            .as_ref()
            .map_or(job_left, |t| t.get().min(job_left))
    }

    fn missing_tool(&self, kind: StepKind) -> Option<&'static str> {
        let absent = |k: &str| self.spec.fingerprint.get(k) == Some("absent");
        if absent("cargo") {
            return Some("cargo");
        }
        if kind == StepKind::Nextest && absent("cargo-nextest") {
            return Some("cargo-nextest");
        }
        None
    }

    /// The step's environment: the job's, the kind's own variables, then
    /// the step's `env` and `env_file` (R52).
    fn step_env(&self, s: &crate::config::repo::Step) -> Result<JobEnv, End> {
        let file = match &s.env_file {
            Some(p) => {
                let path = self.dirs.expand_tilde(p);
                let f =
                    EnvFile::read(&path).map_err(|e| error(ErrorCause::Config, e.to_string()))?;
                let key = format!("env-file:{}", path.display());
                if self.spec.fingerprint.get(&key) != Some(f.hash.as_str()) {
                    return Err(error(
                        ErrorCause::Config,
                        format!(
                            "env_file {} changed since the job was planned",
                            path.display()
                        ),
                    ));
                }
                Some(f)
            }
            None => None,
        };
        self.env
            .for_step(&steps::lang::step_env(s.kind), None)
            .and_then(|e| e.for_step(&s.env, file.as_ref()))
            .map_err(|e| error(ErrorCause::Config, e.to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    fn nextest_result(
        &mut self,
        rep: &mut StepReport,
        code: Option<i32>,
        junit_src: &Path,
        slug: &str,
        scope: &Scope,
        config: &RepoConfig,
        today: jiff::civil::Date,
    ) {
        let parsed = std::fs::read_to_string(junit_src)
            .ok()
            .map(|xml| junit::parse(&xml));
        let summary = match parsed {
            Some(Ok(cases)) => Some(junit::summarize(
                &cases,
                &config.quarantine,
                today,
                self.spec.tier,
            )),
            Some(Err(e)) => {
                rep.message = Some(format!("JUnit report unreadable: {e}"));
                None
            }
            None => None,
        };
        if let Some(sum) = &summary {
            if *scope == Scope::All && !self.spec.step_run.as_ref().is_some_and(StepRun::narrowed) {
                self.known_tests_full = Some(sum.known.clone());
            }
            self.report.flaky.extend(sum.flaky.iter().cloned());
            self.report
                .quarantined
                .extend(sum.quarantined.iter().cloned());
            rep.failing.clone_from(&sum.failing);
            rep.rerun = junit::rerun_commands(&sum.failing);
        }
        let only_quarantined = summary
            .as_ref()
            .is_some_and(|s| s.failing.is_empty() && !s.quarantined.is_empty());
        rep.status = match code {
            Some(0) => StepStatus::Pass,
            // 100: test failures; all of them quarantined passes (R93).
            Some(100) if only_quarantined => StepStatus::Pass,
            _ => StepStatus::Fail,
        };
        if rep.status == StepStatus::Fail && rep.failing.is_empty() {
            rep.tail = report::tail(
                &self.job_dir.join(format!("{slug}.log")),
                report::TAIL_LINES,
            );
        }
    }

    /// The report of a baseline step (R91, R94): what `tollgate __step`
    /// wrote to `findings`, else the log tail.
    fn baseline_result(rep: &mut StepReport, passed: bool, findings: &Path, log: &Path) {
        let found: Option<steps::baseline::Findings> = std::fs::read(findings)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
        if passed {
            if let Some(f) = found.filter(|f| !f.notes.is_empty()) {
                rep.message = Some(f.notes.join(" "));
            }
            return;
        }
        rep.status = StepStatus::Fail;
        match found {
            Some(f) => {
                rep.message = f.summary;
                rep.items = f.items;
                rep.rerun = f.rerun;
                if rep.items.is_empty() {
                    rep.tail = report::tail(log, report::TAIL_LINES);
                }
            }
            None => rep.tail = report::tail(log, report::TAIL_LINES),
        }
    }

    /// R43: in a verify checkout, cargo builds into the checkout's own
    /// `target/`, whatever a cargo config says, so it never shares a target
    /// dir with an agent checkout or the other tier. `run --here` keeps the
    /// CI's own setting.
    fn target_env(&self, env: &JobEnv, workdir: &Path, root: &Path) -> JobEnv {
        if self.here {
            return env.clone();
        }
        let target = workdir.join(root).join("target");
        let extra: BTreeMap<String, String> = [(
            "CARGO_TARGET_DIR".to_owned(),
            target.to_string_lossy().into_owned(),
        )]
        .into();
        env.for_step(&extra, None).unwrap_or_else(|_| env.clone())
    }

    /// R44: a target dir above `verify.max_target` is cleaned after the job.
    fn max_target(&self, co: &Checkout) {
        let max = self.spec.host.verify.max_target.bytes();
        let roots: BTreeSet<PathBuf> = self
            .spec
            .policy
            .config
            .steps
            .iter()
            .filter(|s| steps::is_rust(s.kind))
            .map(steps::step_root)
            .collect();
        for root in roots {
            let target = co.path.join(&root).join("target");
            if !target.is_dir() || checkout::dir_size(&target) <= max {
                continue;
            }
            // First the outputs of packages no longer in the workspace's
            // graph; a full clean only when that is not enough (L15: keep
            // the warm build).
            if let Some(Some(map)) = self.maps.get(&root)
                && !map.all_packages.is_empty()
            {
                let gone = checkout::clean_stale(&target, &map.all_packages);
                if !gone.is_empty() {
                    self.say(&format!(
                        "target {} is above verify.max_target: removed outputs of {} package(s) no longer in the workspace: {}",
                        target.display(),
                        gone.len(),
                        gone.iter().cloned().collect::<Vec<_>>().join(", ")
                    ));
                }
                if checkout::dir_size(&target) <= max {
                    continue;
                }
            }
            self.say(&format!(
                "target {} is above verify.max_target: cargo clean",
                target.display()
            ));
            let mut never = || None;
            let env = self.target_env(&self.env, &co.path, &root);
            let _ = exec::run(ExecSpec {
                program: "cargo".into(),
                arg0: None,
                args: vec!["clean".into()],
                cwd: &co.path.join(&root),
                env: &env,
                log: &self.log,
                stdout: None,
                deadline: Some(Instant::now() + Duration::from_secs(600)),
                grace: Duration::from_secs(10),
                abort: &mut never,
                inherit: &self.inherit,
                records: &self.job_dir.join(crate::dirs::JOB_STEPS_DIR),
            });
        }
    }

    fn finish(&mut self, end: End) {
        let now = jiff::Timestamp::now();
        self.report.finished = now;
        let state = match end {
            End::Verdict(v, cause, msg) => {
                self.report.outcome = Outcome::Verdict;
                self.report.verdict = Some(v);
                self.report.cause = cause;
                self.report.message = msg;
                JobState::Finished { verdict: v }
            }
            End::NoRecord(cause, msg) => {
                self.report.outcome = Outcome::Deferred;
                self.report.verdict = Some(Verdict::Error);
                self.report.cause = Some(cause);
                self.report.message = Some(msg.clone());
                JobState::Deferred { reason: msg }
            }
            End::Cancelled => {
                self.report.outcome = Outcome::Cancelled;
                // R112: the reason of a cancel that gave one (the cancel
                // file, or the state of a job cancelled while queued).
                let reason = self
                    .store
                    .cancel_note(&self.spec.id)
                    .map(|n| n.reason)
                    .or_else(|| match self.store.read(&self.spec.id).map(|m| m.state) {
                        Ok(JobState::Cancelled { reason }) => reason,
                        _ => None,
                    });
                self.report.message.clone_from(&reason);
                JobState::Cancelled { reason }
            }
            End::Superseded => {
                self.report.outcome = Outcome::Superseded;
                JobState::Superseded
            }
        };
        if self.here {
            if let Err(e) = self.report.write_to(&self.job_dir.join("report.json")) {
                eprintln!("tollgate: cannot write report.json: {e}");
            }
            return;
        }
        if let Err(e) = self.report.write(self.dirs) {
            self.say(&format!("cannot write report.json: {e}"));
        }
        // R105: a step run is not a tier pass: no tree record.
        if let JobState::Finished { verdict } = &state
            && self.report.covered_by.is_none()
            && self.spec.step_run.is_none()
        {
            self.write_record(*verdict, now);
        }
        // L16, R42: step passes only from a job that ended with a verdict
        // its steps decided.
        if matches!(
            &state,
            JobState::Finished {
                verdict: Verdict::Pass | Verdict::Fail
            }
        ) && self.report.cause.is_none()
        {
            for p in std::mem::take(&mut self.pending_steps) {
                match &self.spec.step_run {
                    // R105: a narrowed pass answers only the same call.
                    Some(run) if run.narrowed() => {
                        let _ = step_store::write_run(
                            self.dirs,
                            &StoredStep {
                                key: run.run_key.clone(),
                                ..p
                            },
                        );
                    }
                    run => {
                        // R101: the same pass, as a result of this tree
                        // (a step run's spec key is its claim key).
                        let record = run.as_ref().map_or(&self.spec.key, |r| &r.record_key);
                        let _ =
                            step_store::write_fresh(self.dirs, record, &self.spec.fingerprint, &p);
                        let _ = step_store::write_stored(self.dirs, &p);
                    }
                }
            }
        }
        self.flaky_log(now);
        self.metrics(now);
        let from = [StateKind::Queued, StateKind::Running];
        if let Err(e) = self.store.transition(&self.spec.id, &from, state) {
            self.say(&format!("cannot write the final job state: {e}"));
        }
        self.say(&format!("done: {}", self.report.verdict_text()));
    }

    fn write_record(&mut self, verdict: Verdict, now: jiff::Timestamp) {
        let started = self.report.started.unwrap_or(self.report.created);
        let record = Record {
            schema: RECORD_SCHEMA,
            key: self.spec.key.clone(),
            tree: self.spec.tree.clone(),
            tier: self.spec.tier,
            verdict,
            verdict_class: verdict.class(),
            cause: self.report.cause,
            ttl_secs: (verdict.class() == crate::cache::record::VerdictClass::Environmental)
                .then_some(ENVIRONMENTAL_TTL.as_secs()),
            fingerprint: self.spec.fingerprint.clone(),
            policy_commit: self.spec.policy.commit.clone(),
            base_tree: self.spec.base_tree.clone(),
            selection: if self.spec.tier == Tier::Full {
                Selection::All
            } else {
                self.record_selection.clone()
            },
            started,
            finished: now,
            duration_ms: u64::try_from(now.duration_since(started).as_millis().max(0)).unwrap_or(0),
            host: self.report.host.clone(),
            tollgate_version: crate::VERSION.to_owned(),
            job_id: self.spec.id.clone(),
            steps: self.step_results.clone(),
            flaky: self.report.flaky.iter().map(|f| f.test.clone()).collect(),
            quarantine_hits: self
                .report
                .quarantined
                .iter()
                .map(|q: &QuarantineHit| q.test.clone())
                .collect(),
            reused: self.reused,
        };
        match RecordStore::new(self.dirs).write(&record) {
            Ok(_) => {
                self.report.record_written = true;
                let _ = self.report.write(self.dirs);
            }
            Err(e) => self.say(&format!("record not written: {e}")),
        }
    }

    /// The job's line in the metrics log (item 50).
    fn metrics(&self, now: jiff::Timestamp) {
        let r = &self.report;
        let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        let event = crate::metrics::JobEvent {
            t: now,
            job: self.spec.id.clone(),
            repo: crate::metrics::repo_name(&self.spec.common_dir),
            tier: self.spec.tier,
            by: match (&self.spec.step_run, self.spec.priority) {
                (Some(_), _) => "step".into(),
                (None, Priority::Hook) => "hook".into(),
                (None, Priority::Prewarm) => "prewarm".into(),
            },
            verdict: r.verdict_text(),
            wall_ms: crate::metrics::ms_between(r.created, now),
            job_queue_ms: crate::metrics::ms_between(r.created, r.started.unwrap_or(now)),
            slot_queue_ms: r.steps.iter().filter_map(|s| s.queue_ms).sum(),
            checkout_wait_ms: r.checkout_wait_ms.unwrap_or(0),
            steps: count(r.steps.len()),
            steps_reused: count(r.steps.iter().filter(|s| s.reused_from.is_some()).count()),
            steps_fresh: count(r.steps.iter().filter(|s| s.fresh_from.is_some()).count()),
            // A step whose command ran has a log; skipped, reused and
            // same-tree steps have none (R109).
            steps_ran: Some(count(r.steps.iter().filter(|s| s.log.is_some()).count())),
            flaky: count(r.flaky.len()),
            quarantined: count(r.quarantined.len()),
            step_ms: Some(crate::metrics::ran_step_ms(&r.steps)),
            branch: Some(crate::metrics::branch_of(&self.spec.origin.refname)),
            // R112: `behind` for a job ended because the remote moved.
            cause: (r.outcome == Outcome::Cancelled && !self.here)
                .then(|| self.store.cancel_note(&self.spec.id).and_then(|n| n.cause))
                .flatten(),
        };
        crate::metrics::record(self.dirs, &[crate::metrics::Event::Job(event)]);
    }

    fn flaky_log(&self, now: jiff::Timestamp) {
        let quarantined: BTreeSet<&str> = self
            .report
            .quarantined
            .iter()
            .map(|q| q.test.as_str())
            .collect();
        let entries: Vec<FlakyEntry> = self
            .report
            .flaky
            .iter()
            .map(|f| FlakyEntry {
                time: now,
                test: f.test.clone(),
                passed_on_try: f.passed_on_try,
                result: if quarantined.contains(f.test.as_str()) {
                    "quarantined".into()
                } else if f.failed_job {
                    "fail".into()
                } else {
                    "pass".into()
                },
                tier: self.spec.tier,
                job: self.spec.id.clone(),
                worktree: self.spec.origin.worktree.clone(),
            })
            .collect();
        let _ = report::append_flaky(self.dirs, &entries);
    }
}

fn unreachable_meta(co: &Checkout) -> checkout::CheckoutMeta {
    let now = jiff::Timestamp::now();
    checkout::CheckoutMeta {
        origin: co.path.clone(),
        common_dir: PathBuf::new(),
        tier: Tier::Fast,
        created: now,
        last_used: now,
        setup: BTreeMap::new(),
    }
}

/// A duration in whole milliseconds for a report.
fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// While queued: cancelled (state) or superseded (R89).
fn queued_abort(store: &JobStore, id: &JobId) -> Option<String> {
    match store.read(id).map(|m| m.state) {
        Ok(JobState::Cancelled { .. }) => return Some("cancelled".into()),
        Ok(JobState::Superseded) => return Some("superseded".into()),
        _ => {}
    }
    if store.supersede_if_stale(id).unwrap_or(false) {
        return Some("superseded".into());
    }
    None
}

/// R35: when the lock file at `lock` names another job whose runner died,
/// stop that job's leftover processes (they hold the lock through inherited
/// fds) and mark it lost.
fn reap_holder(dirs: &Dirs, lock: &Path, me: &JobId) {
    if let Some(holder) = locks::holder(lock).and_then(|h| JobId::parse(&h).ok())
        && &holder != me
    {
        let _ = crate::sched::reap_if_lost(dirs, &holder);
    }
}

/// While running: `tollgate cancel` (R89).
fn running_abort(store: &JobStore, id: &JobId) -> Option<String> {
    store.cancel_requested(id).then(|| "cancelled".to_owned())
}
