//! What `tollgate bench` reports (L20): per-attempt data, job data, the
//! summaries built from them, and the text form.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Serialize;

use super::sample::{CpuSample, PgSamples};
use crate::cache::record::StepStatus;
use crate::report::{JobReport, Outcome as ReportOutcome};
use crate::sched::{JobMeta, JobState};

/// Version of the JSON report.
pub const BENCH_SCHEMA: u32 = 1;

/// `linux` ms, else `macos` ms on macOS. L19: budgets are per OS, because
/// starting a process costs much more on macOS; the macOS values are the
/// ones `tests/latency.rs` asserts there.
const fn per_os(linux: f64, macos: f64) -> f64 {
    if cfg!(target_os = "macos") {
        macos
    } else {
        linux
    }
}

/// L19 budgets the bench measures under load, in milliseconds.
pub const BUDGET_PRE_COMMIT_HIT_MS: f64 = per_os(200.0, 800.0);
/// L19: `pre-commit` on a docs-only tree.
pub const BUDGET_PRE_COMMIT_DOCS_MS: f64 = per_os(200.0, 800.0);
/// L19: a chained non-gate hook.
pub const BUDGET_CHAINED_MS: f64 = per_os(5.0, 20.0);
/// L19: fast job overhead beyond the steps.
pub const BUDGET_JOB_OVERHEAD_MS: f64 = 3000.0;

/// p50, p95, max and mean of some durations (nearest rank).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Summary {
    /// Number of values.
    pub n: usize,
    /// Median.
    pub p50_ms: f64,
    /// 95th percentile.
    pub p95_ms: f64,
    /// Largest.
    pub max_ms: f64,
    /// Mean.
    pub mean_ms: f64,
}

/// Milliseconds to three decimals (microseconds).
#[must_use]
pub fn round_ms(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

/// The summary of `values`; `None` when empty.
#[must_use]
pub fn summary(values: &[f64]) -> Option<Summary> {
    if values.is_empty() {
        return None;
    }
    let mut v = values.to_vec();
    v.sort_by(f64::total_cmp);
    let n = v.len();
    let rank = |p: usize| v[(n * p).div_ceil(100).max(1) - 1];
    Some(Summary {
        n,
        p50_ms: round_ms(rank(50)),
        p95_ms: round_ms(rank(95)),
        max_ms: round_ms(v[n - 1]),
        mean_ms: round_ms(v.iter().sum::<f64>() / n as f64),
    })
}

/// A first commit of a tree, or a commit of the same tree again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AttemptKind {
    /// The scenario's commit.
    Commit,
    /// The same tree again: `commit --amend --no-edit` after an allow, or
    /// `tollgate wait <job>` and the same command after a deny (L17).
    Retry,
}

/// What the `pre-commit` gate did, from its stderr lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookOutcome {
    /// Allowed on a stored record (cache hit).
    Hit,
    /// Allowed when a job this hook started passed.
    Job,
    /// Allowed when a running job it attached to passed (R88).
    Attached,
    /// Denied at the inline budget; the job runs on (R32).
    Running,
    /// Denied for another reason.
    Denied,
    /// git committed with no gate decision: the repo was not in scope.
    Ungated,
    /// git failed before or without the gate (nothing to commit, ...).
    GitError,
}

impl HookOutcome {
    /// True for the outcomes that allowed the commit.
    #[must_use]
    pub fn allowed(self) -> bool {
        matches!(self, Self::Hit | Self::Job | Self::Attached)
    }
}

/// The word after `pat` in `line`, without trailing `)` or `,`.
fn word_after(line: &str, pat: &str) -> Option<String> {
    let rest = &line[line.find(pat)? + pat.len()..];
    let w = rest
        .split_whitespace()
        .next()?
        .trim_end_matches([')', ',', ':']);
    (!w.is_empty()).then(|| w.to_owned())
}

/// Classifies a `git commit` by its exit and the gate's stderr lines
/// (`src/hook/gate.rs`). Returns the outcome, the job and the line that
/// explains a deny or error.
#[must_use]
pub fn classify(exit_ok: bool, stderr: &str) -> (HookOutcome, Option<String>, Option<String>) {
    let mut pass: Option<HookOutcome> = None;
    let mut job: Option<String> = None;
    let mut attached = false;
    let mut deny: Option<&str> = None;
    for line in stderr.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("tollgate: pass pre-commit ") {
            if let Some(j) = word_after(rest, "(record of job ") {
                pass = Some(HookOutcome::Hit);
                job = Some(j);
            } else {
                pass = Some(HookOutcome::Job);
                if let Some(j) = word_after(rest, "(job ") {
                    job = Some(j);
                }
            }
        } else if line.starts_with("tollgate: pre-commit ")
            && let Some(j) = word_after(line, ": attached to running job ")
        {
            attached = true;
            job.get_or_insert(j);
        } else if line.starts_with("tollgate: DENIED pre-commit") && deny.is_none() {
            deny = Some(line);
            if let Some(j) = word_after(line, " job ") {
                job = Some(j);
            }
        }
    }
    let last_line = || {
        stderr
            .lines()
            .rev()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .map(str::to_owned)
    };
    if exit_ok {
        return match pass {
            Some(HookOutcome::Job) if attached => (HookOutcome::Attached, job, None),
            Some(o) => (o, job, None),
            None => (HookOutcome::Ungated, None, None),
        };
    }
    match deny {
        Some(line) if word_after(line, " verdict ").as_deref() == Some("running") => {
            (HookOutcome::Running, job, Some(line.to_owned()))
        }
        Some(line) => (HookOutcome::Denied, job, Some(line.to_owned())),
        None => (HookOutcome::GitError, None, last_line()),
    }
}

/// One `git commit`.
#[derive(Debug, Clone, Serialize)]
pub struct Attempt {
    /// Worktree index.
    pub worktree: u32,
    /// Scenario name.
    pub scenario: String,
    /// Round index.
    pub round: u32,
    /// First commit or retry.
    pub kind: AttemptKind,
    /// Milliseconds from the start of the commit phase to this commit.
    pub start_ms: f64,
    /// git's exit code.
    pub exit: Option<i32>,
    /// What the gate did.
    pub outcome: HookOutcome,
    /// The job that decided it.
    pub job: Option<String>,
    /// The job passed with zero steps: every change was docs-only (R61).
    pub docs_only: bool,
    /// `pre-commit` start to exit as git measured it (trace2).
    pub hook_ms: Option<f64>,
    /// The whole `git commit`.
    pub wall_ms: f64,
    /// Every hook git ran, start to exit.
    pub hooks: BTreeMap<String, f64>,
    /// `tollgate wait <job>` before a retry (L17).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_ms: Option<f64>,
    /// The deny or error line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// The warm-up check of the start commit.
#[derive(Debug, Clone, Serialize)]
pub struct Warm {
    /// `tollgate check` exit code.
    pub exit: Option<i32>,
    /// Its duration.
    pub ms: f64,
    /// Its job.
    pub job: Option<String>,
}

/// One step of a job.
#[derive(Debug, Clone, Serialize)]
pub struct StepRow {
    /// Step name.
    pub name: String,
    /// Status.
    pub status: StepStatus,
    /// Run time.
    pub duration_ms: u64,
    /// Wait for its resources (R85).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_ms: Option<u64>,
    /// Its resources.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
    /// L16: the job whose pass it reused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reused_from: Option<String>,
    /// R101: the job that ran it on the same tree.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fresh_from: Option<String>,
}

/// One job of the bench's state dir.
#[derive(Debug, Clone, Serialize)]
pub struct JobRow {
    /// Job id.
    pub id: String,
    /// The warm-up job.
    pub warm: bool,
    /// Tier.
    pub tier: String,
    /// State at the end (`finished`, `cancelled`, ...).
    pub state: String,
    /// Verdict or outcome from its report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    /// Created to first step start.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_first_step_ms: Option<f64>,
    /// Wait for the verify checkout (R87).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkout_wait_ms: Option<u64>,
    /// Created to finished.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_ms: Option<f64>,
    /// `total_ms` minus step run time and every queue wait (L19).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overhead_ms: Option<f64>,
    /// Zero steps ran: docs-only (R61).
    pub docs_only: bool,
    /// Steps.
    pub steps: Vec<StepRow>,
}

fn ms_between(a: jiff::Timestamp, b: jiff::Timestamp) -> f64 {
    round_ms(b.duration_since(a).as_secs_f64() * 1000.0)
}

impl JobRow {
    /// Builds the row of a job from its metadata and report.
    #[must_use]
    pub fn new(meta: &JobMeta, report: Option<&JobReport>, warm: bool) -> Self {
        let state = match &meta.state {
            JobState::Queued => "queued",
            JobState::Running { .. } => "running",
            JobState::Finished { .. } => "finished",
            JobState::Superseded => "superseded",
            JobState::Cancelled { .. } => "cancelled",
            JobState::Deferred { .. } => "deferred",
            JobState::Lost { .. } => "lost",
        };
        let steps: Vec<StepRow> = report
            .map(|r| {
                r.steps
                    .iter()
                    .map(|s| StepRow {
                        name: s.name.clone(),
                        status: s.status,
                        duration_ms: s.duration_ms,
                        queue_ms: s.queue_ms,
                        resources: s.resources.clone(),
                        reused_from: s.reused_from.as_ref().map(ToString::to_string),
                        fresh_from: s.fresh_from.as_ref().map(ToString::to_string),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let docs_only = report.is_some_and(|r| {
            r.passed()
                && !r.steps.is_empty()
                && r.steps.iter().all(|s| {
                    s.status == StepStatus::Skipped
                        && s.message.as_deref() == Some(crate::steps::DOCS_ONLY_SKIP)
                })
        });
        let with_verdict = report.filter(|r| r.outcome == ReportOutcome::Verdict);
        let total_ms = with_verdict.map(|r| ms_between(r.created, r.finished));
        let overhead_ms = with_verdict.zip(total_ms).map(|(r, total)| {
            let steps: u64 = r
                .steps
                .iter()
                .filter(|s| s.reused_from.is_none() && s.fresh_from.is_none())
                .map(|s| s.duration_ms + s.queue_ms.unwrap_or(0))
                .sum();
            let waits = r.checkout_wait_ms.unwrap_or(0) + steps;
            round_ms((total - waits as f64).max(0.0))
        });
        Self {
            id: meta.id.to_string(),
            warm,
            tier: meta.tier.to_string(),
            state: state.to_owned(),
            verdict: report.map(JobReport::verdict_text),
            to_first_step_ms: report.and_then(|r| r.started.map(|s| ms_between(r.created, s))),
            checkout_wait_ms: report.and_then(|r| r.checkout_wait_ms),
            total_ms,
            overhead_ms,
            docs_only,
            steps,
        }
    }
}

/// `pre-commit` latency, hook start to allow.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PreCommit {
    /// Every allowed commit.
    pub all: Option<Summary>,
    /// Allowed on a record (cache hit).
    pub hit: Option<Summary>,
    /// Allowed after a job (started or attached).
    pub job: Option<Summary>,
    /// Allowed after a docs-only job.
    pub docs_only: Option<Summary>,
    /// Denied commits, start to deny.
    pub denied: Option<Summary>,
    /// Allowed commits per scenario.
    pub by_scenario: BTreeMap<String, Summary>,
    /// Allowed commits per round.
    pub by_round: BTreeMap<u32, Summary>,
}

/// Latency summaries.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Latency {
    /// The gate hook.
    pub pre_commit: PreCommit,
    /// The other hooks git ran (chained, R7).
    pub hooks: BTreeMap<String, Summary>,
    /// Whole `git commit` wall time.
    pub commit_wall: Option<Summary>,
}

/// Step counts of the measured jobs (L16).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Reuse {
    /// Steps whose stored pass was reused.
    pub steps_reused: usize,
    /// Steps taken from a job that ran them on the same tree (R101).
    pub steps_fresh: usize,
    /// Steps that ran.
    pub steps_run: usize,
    /// Steps skipped (selection or docs-only).
    pub steps_skipped: usize,
}

/// One L19 budget against what the bench measured.
#[derive(Debug, Clone, Serialize)]
pub struct Budget {
    /// What is measured.
    pub name: String,
    /// Measured p95.
    pub p95_ms: f64,
    /// The budget.
    pub budget_ms: f64,
    /// Under the budget.
    pub ok: bool,
}

/// CPU load during the commit phase.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CpuReport {
    /// The samples.
    pub samples: Vec<CpuSample>,
    /// Highest one-minute load.
    pub load1_max: Option<f64>,
    /// Highest busy share.
    pub busy_max_pct: Option<f64>,
    /// Mean busy share.
    pub busy_mean_pct: Option<f64>,
}

/// Peak Postgres connections.
#[derive(Debug, Clone, Serialize)]
pub struct PgReport {
    /// Highest connection count seen.
    pub peak: Option<u64>,
    /// The samples and errors.
    #[serde(flatten)]
    pub samples: PgSamples,
}

/// What cleanup found and did.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Cleanup {
    /// Jobs still queued or running at the end, cancelled (R89).
    pub cancelled: Vec<String>,
    /// Processes killed after the cancel wait (runners, by environment).
    pub killed: usize,
    /// Jobs that did not end even then.
    pub leftover: Vec<String>,
    /// Removing the scratch dir failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The whole report.
#[derive(Debug, Clone, Serialize)]
pub struct BenchReport {
    /// [`BENCH_SCHEMA`].
    pub schema: u32,
    /// The source repo (its common dir; never written).
    pub repo: PathBuf,
    /// The commit every worktree started from.
    pub head: String,
    /// The scratch dir.
    pub scratch: PathBuf,
    /// The scratch dir was removed.
    pub scratch_removed: bool,
    /// Worktrees.
    pub worktrees: u32,
    /// Commit rounds per worktree.
    pub rounds: u32,
    /// Resource slots and `pg_max_threads` of the bench's host config.
    pub resources: BTreeMap<String, u32>,
    /// A signal stopped the run early.
    pub interrupted: bool,
    /// The warm-up check of the start commit.
    pub warm: Option<Warm>,
    /// Every commit.
    pub attempts: Vec<Attempt>,
    /// Latency summaries.
    pub latency: Latency,
    /// Every job.
    pub jobs: Vec<JobRow>,
    /// Wait for resource slots per resource, over the steps that took one.
    pub queue_wait: BTreeMap<String, Summary>,
    /// Wait for the verify checkout (R87).
    pub checkout_wait: Option<Summary>,
    /// Fast job overhead beyond the steps (L19).
    pub job_overhead: Option<Summary>,
    /// Step reuse (L16).
    pub reuse: Reuse,
    /// Commits allowed on a stored record.
    pub cache_hits: usize,
    /// L19 budgets.
    pub budgets: Vec<Budget>,
    /// CPU load.
    pub cpu: CpuReport,
    /// Postgres connections, when a URL was given.
    pub postgres: Option<PgReport>,
    /// Cleanup.
    pub cleanup: Cleanup,
}

/// Everything the run collected, before the summaries.
#[derive(Debug, Clone)]
pub struct Collected {
    /// See [`BenchReport::repo`].
    pub repo: PathBuf,
    /// See [`BenchReport::head`].
    pub head: String,
    /// See [`BenchReport::scratch`].
    pub scratch: PathBuf,
    /// See [`BenchReport::scratch_removed`].
    pub scratch_removed: bool,
    /// See [`BenchReport::worktrees`].
    pub worktrees: u32,
    /// See [`BenchReport::rounds`].
    pub rounds: u32,
    /// See [`BenchReport::resources`].
    pub resources: BTreeMap<String, u32>,
    /// See [`BenchReport::interrupted`].
    pub interrupted: bool,
    /// See [`BenchReport::warm`].
    pub warm: Option<Warm>,
    /// See [`BenchReport::attempts`].
    pub attempts: Vec<Attempt>,
    /// See [`BenchReport::jobs`].
    pub jobs: Vec<JobRow>,
    /// CPU samples.
    pub cpu: Vec<CpuSample>,
    /// Postgres samples.
    pub pg: Option<PgSamples>,
    /// See [`BenchReport::cleanup`].
    pub cleanup: Cleanup,
}

fn group<K: Ord>(items: impl Iterator<Item = (K, f64)>) -> BTreeMap<K, Summary> {
    let mut m: BTreeMap<K, Vec<f64>> = BTreeMap::new();
    for (k, v) in items {
        m.entry(k).or_default().push(v);
    }
    m.into_iter()
        .filter_map(|(k, v)| summary(&v).map(|s| (k, s)))
        .collect()
}

fn budget(name: &str, s: Option<&Summary>, budget_ms: f64) -> Option<Budget> {
    s.map(|s| Budget {
        name: name.to_owned(),
        p95_ms: s.p95_ms,
        budget_ms,
        ok: s.p95_ms < budget_ms,
    })
}

impl BenchReport {
    /// Builds the summaries from what the run collected. Attempts learn
    /// from their job whether it was docs-only.
    #[must_use]
    pub fn build(mut c: Collected) -> Self {
        let docs_jobs: std::collections::BTreeSet<&str> = c
            .jobs
            .iter()
            .filter(|j| j.docs_only)
            .map(|j| j.id.as_str())
            .collect();
        for a in &mut c.attempts {
            a.docs_only = matches!(a.outcome, HookOutcome::Job | HookOutcome::Attached)
                && a.job.as_deref().is_some_and(|j| docs_jobs.contains(j));
        }
        let allowed: Vec<&Attempt> = c
            .attempts
            .iter()
            .filter(|a| a.outcome.allowed() && a.hook_ms.is_some())
            .collect();
        let hook = |a: &&Attempt| a.hook_ms.unwrap_or_default();
        let pick = |f: &dyn Fn(&Attempt) -> bool| {
            summary(
                &allowed
                    .iter()
                    .filter(|a| f(a))
                    .map(hook)
                    .collect::<Vec<_>>(),
            )
        };
        let pre_commit = PreCommit {
            all: summary(&allowed.iter().map(hook).collect::<Vec<_>>()),
            hit: pick(&|a| a.outcome == HookOutcome::Hit),
            job: pick(&|a| matches!(a.outcome, HookOutcome::Job | HookOutcome::Attached)),
            docs_only: pick(&|a| a.docs_only),
            denied: summary(
                &c.attempts
                    .iter()
                    .filter(|a| matches!(a.outcome, HookOutcome::Running | HookOutcome::Denied))
                    .filter_map(|a| a.hook_ms)
                    .collect::<Vec<_>>(),
            ),
            by_scenario: group(allowed.iter().map(|a| (a.scenario.clone(), hook(a)))),
            by_round: group(allowed.iter().map(|a| (a.round, hook(a)))),
        };
        let hooks = group(c.attempts.iter().flat_map(|a| {
            a.hooks
                .iter()
                .filter(|(h, _)| h.as_str() != "pre-commit")
                .map(|(h, ms)| (h.clone(), *ms))
        }));
        let latency = Latency {
            pre_commit,
            hooks,
            commit_wall: summary(&c.attempts.iter().map(|a| a.wall_ms).collect::<Vec<_>>()),
        };
        let measured: Vec<&JobRow> = c.jobs.iter().filter(|j| !j.warm).collect();
        let queue_wait = group(measured.iter().flat_map(|j| {
            j.steps.iter().flat_map(|s| {
                s.queue_ms
                    .into_iter()
                    .flat_map(|q| s.resources.iter().map(move |r| (r.clone(), q as f64)))
            })
        }));
        let checkout_wait = summary(
            &measured
                .iter()
                .filter_map(|j| j.checkout_wait_ms.map(|w| w as f64))
                .collect::<Vec<_>>(),
        );
        let job_overhead = summary(
            &measured
                .iter()
                .filter_map(|j| j.overhead_ms)
                .collect::<Vec<_>>(),
        );
        let mut reuse = Reuse::default();
        for s in measured.iter().flat_map(|j| &j.steps) {
            if s.reused_from.is_some() {
                reuse.steps_reused += 1;
            } else if s.fresh_from.is_some() {
                reuse.steps_fresh += 1;
            } else if s.status == StepStatus::Skipped {
                reuse.steps_skipped += 1;
            } else {
                reuse.steps_run += 1;
            }
        }
        let cache_hits = c
            .attempts
            .iter()
            .filter(|a| a.outcome == HookOutcome::Hit)
            .count();
        let budgets = [
            budget(
                "pre-commit cache hit",
                latency.pre_commit.hit.as_ref(),
                BUDGET_PRE_COMMIT_HIT_MS,
            ),
            budget(
                "pre-commit docs-only",
                latency.pre_commit.docs_only.as_ref(),
                BUDGET_PRE_COMMIT_DOCS_MS,
            ),
            budget(
                "chained hook post-commit",
                latency.hooks.get("post-commit"),
                BUDGET_CHAINED_MS,
            ),
            budget(
                "fast job overhead",
                job_overhead.as_ref(),
                BUDGET_JOB_OVERHEAD_MS,
            ),
        ]
        .into_iter()
        .flatten()
        .collect();
        let busy: Vec<f64> = c.cpu.iter().filter_map(|s| s.busy_pct).collect();
        let cpu = CpuReport {
            load1_max: c.cpu.iter().map(|s| s.load1).reduce(f64::max),
            busy_max_pct: busy.iter().copied().reduce(f64::max),
            busy_mean_pct: (!busy.is_empty())
                .then(|| (busy.iter().sum::<f64>() / busy.len() as f64 * 10.0).round() / 10.0),
            samples: c.cpu,
        };
        let postgres = c.pg.map(|samples| PgReport {
            peak: samples.samples.iter().map(|s| s.connections).max(),
            samples,
        });
        Self {
            schema: BENCH_SCHEMA,
            repo: c.repo,
            head: c.head,
            scratch: c.scratch,
            scratch_removed: c.scratch_removed,
            worktrees: c.worktrees,
            rounds: c.rounds,
            resources: c.resources,
            interrupted: c.interrupted,
            warm: c.warm,
            attempts: c.attempts,
            latency,
            jobs: c.jobs,
            queue_wait,
            checkout_wait,
            job_overhead,
            reuse,
            cache_hits,
            budgets,
            cpu,
            postgres,
            cleanup: c.cleanup,
        }
    }

    /// The text form.
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        let mut out = Vec::new();
        let plural = |n: u32, one: &str| {
            if n == 1 {
                format!("{n} {one}")
            } else {
                format!("{n} {one}s")
            }
        };
        out.push(format!(
            "tollgate bench: {} x {} from {} at {}",
            plural(self.worktrees, "worktree"),
            plural(self.rounds, "round"),
            self.repo.display(),
            self.head.get(..12).unwrap_or(&self.head)
        ));
        let slots: Vec<String> = self
            .resources
            .iter()
            .map(|(k, v)| format!("{k} {v}"))
            .collect();
        out.push(format!("host config: {}", slots.join(", ")));
        if self.interrupted {
            out.push("INTERRUPTED: the run stopped early".into());
        }
        match &self.warm {
            Some(w) => out.push(format!(
                "warm-up: start commit checked in {} (exit {}, job {})",
                secs(w.ms),
                w.exit.map_or("none".into(), |c| c.to_string()),
                w.job.as_deref().unwrap_or("none")
            )),
            None => out.push("warm-up: skipped".into()),
        }
        let p = &self.latency.pre_commit;
        out.push("pre-commit, hook start to allow (ms):".into());
        let mut row = |label: &str, s: Option<&Summary>, note: &str| {
            if let Some(s) = s {
                out.push(format!("  {label:<14} {}{note}", line(s)));
            }
        };
        row("all", p.all.as_ref(), "");
        row("hit", p.hit.as_ref(), "");
        row("job", p.job.as_ref(), "");
        row("docs-only", p.docs_only.as_ref(), "");
        for (name, s) in &p.by_scenario {
            row(&format!("scenario {name}"), Some(s), "");
        }
        if self.rounds > 1 {
            for (r, s) in &p.by_round {
                row(&format!("round {r}"), Some(s), "");
            }
        }
        let denied: Vec<&Attempt> = self
            .attempts
            .iter()
            .filter(|a| !a.outcome.allowed())
            .collect();
        let running = denied
            .iter()
            .filter(|a| a.outcome == HookOutcome::Running)
            .count();
        out.push(format!(
            "denied: {} (at the inline budget {running})",
            denied.len()
        ));
        for a in &denied {
            out.push(format!(
                "  worktree {} {} {:?}: {}",
                a.worktree,
                a.scenario,
                a.outcome,
                a.message.as_deref().unwrap_or("")
            ));
        }
        for (h, s) in &self.latency.hooks {
            out.push(format!("hook {h} (ms): {}", line(s)));
        }
        if let Some(s) = &self.latency.commit_wall {
            out.push(format!("git commit wall time (ms): {}", line(s)));
        }
        let measured = self.jobs.iter().filter(|j| !j.warm).count();
        let pass = self
            .jobs
            .iter()
            .filter(|j| !j.warm && j.verdict.as_deref() == Some("pass"))
            .count();
        out.push(format!("jobs: {measured} (pass {pass})"));
        if let Some(s) = &self.job_overhead {
            out.push(format!("job overhead beyond steps (ms): {}", line(s)));
        }
        if self.queue_wait.is_empty() && self.checkout_wait.is_none() {
            out.push("queue wait: no step took a resource".into());
        } else {
            out.push("queue wait (ms):".into());
            for (r, s) in &self.queue_wait {
                out.push(format!("  {r:<14} {}", line(s)));
            }
            if let Some(s) = &self.checkout_wait {
                out.push(format!("  {:<14} {}", "checkout", line(s)));
            }
        }
        out.push(format!(
            "step reuse: {} reused, {} same tree, {} run, {} skipped",
            self.reuse.steps_reused,
            self.reuse.steps_fresh,
            self.reuse.steps_run,
            self.reuse.steps_skipped
        ));
        out.push(format!(
            "cache hits: {} of {} commits",
            self.cache_hits,
            self.attempts.len()
        ));
        for b in &self.budgets {
            out.push(format!(
                "L19 {}: p95 {:.1} ms, budget {:.0} ms: {}",
                b.name,
                b.p95_ms,
                b.budget_ms,
                if b.ok { "ok" } else { "OVER" }
            ));
        }
        out.push(format!(
            "cpu: load1 max {}, busy max {} mean {} ({} samples)",
            self.cpu
                .load1_max
                .map_or("n/a".into(), |l| format!("{l:.2}")),
            self.cpu
                .busy_max_pct
                .map_or("n/a".into(), |b| format!("{b:.0}%")),
            self.cpu
                .busy_mean_pct
                .map_or("n/a".into(), |b| format!("{b:.0}%")),
            self.cpu.samples.len()
        ));
        match &self.postgres {
            Some(pg) => out.push(format!(
                "postgres: peak {} connections ({} samples, {} errors{})",
                pg.peak.map_or("n/a".into(), |p| p.to_string()),
                pg.samples.samples.len(),
                pg.samples.errors,
                pg.samples
                    .last_error
                    .as_deref()
                    .map(|e| format!(": {e}"))
                    .unwrap_or_default()
            )),
            None => out.push("postgres: not sampled (no --pg-url)".into()),
        }
        out.push(format!(
            "cleanup: {} job(s) cancelled, {} process(es) killed, {} left{}",
            self.cleanup.cancelled.len(),
            self.cleanup.killed,
            self.cleanup.leftover.len(),
            if self.scratch_removed {
                "; scratch removed".to_owned()
            } else {
                format!("; scratch kept at {}", self.scratch.display())
            }
        ));
        if let Some(e) = &self.cleanup.error {
            out.push(format!("cleanup error: {e}"));
        }
        out
    }
}

fn line(s: &Summary) -> String {
    format!(
        "n={} p50 {:.1} p95 {:.1} max {:.1}",
        s.n, s.p50_ms, s.p95_ms, s.max_ms
    )
}

fn secs(ms: f64) -> String {
    format!("{:.1}s", ms / 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_rank_percentiles_l20() {
        assert_eq!(summary(&[]), None);
        let one = summary(&[4.0]).unwrap();
        assert_eq!(
            (one.n, one.p50_ms, one.p95_ms, one.max_ms),
            (1, 4.0, 4.0, 4.0)
        );
        let v: Vec<f64> = (1..=20).rev().map(f64::from).collect();
        let s = summary(&v).unwrap();
        assert_eq!(
            (s.p50_ms, s.p95_ms, s.max_ms, s.mean_ms),
            (10.0, 19.0, 20.0, 10.5)
        );
    }

    /// L19: the bench budgets are per OS; the macOS values are the ones
    /// `tests/latency.rs` asserts there. The job overhead is the same.
    #[test]
    fn the_bench_budgets_are_per_os_l19() {
        let hook_budgets = [
            BUDGET_PRE_COMMIT_HIT_MS,
            BUDGET_PRE_COMMIT_DOCS_MS,
            BUDGET_CHAINED_MS,
        ];
        if cfg!(target_os = "macos") {
            assert_eq!(hook_budgets, [800.0, 800.0, 20.0]);
        } else {
            assert_eq!(hook_budgets, [200.0, 200.0, 5.0]);
        }
        assert_eq!(BUDGET_JOB_OVERHEAD_MS, 3000.0);
    }

    #[test]
    fn classify_reads_the_gate_lines_l20() {
        let hit = "tollgate: pass pre-commit refs/heads/x tree abc tier fast (record of job 20261105-010203-0123abcd)\n";
        assert_eq!(
            classify(true, hit),
            (
                HookOutcome::Hit,
                Some("20261105-010203-0123abcd".into()),
                None
            )
        );
        let job = "tollgate: pre-commit refs/heads/x: job J1 started: tier fast tree abc\ntollgate: pass pre-commit refs/heads/x tree abc tier fast (job J1)\n";
        assert_eq!(
            classify(true, job),
            (HookOutcome::Job, Some("J1".into()), None)
        );
        let attached = "tollgate: pre-commit refs/heads/x: attached to running job J2\ntollgate: pass pre-commit refs/heads/x tree abc tier fast (job J2)\n";
        assert_eq!(
            classify(true, attached),
            (HookOutcome::Attached, Some("J2".into()), None)
        );
        let running = "tollgate: pre-commit refs/heads/x: job J3 started: tier fast tree abc\ntollgate: DENIED pre-commit refs/heads/x tree abc tier fast verdict running job J3\ntollgate: no result inside the inline budget of 1s (R32); the job continues detached.\n";
        let (o, j, m) = classify(false, running);
        assert_eq!((o, j.as_deref()), (HookOutcome::Running, Some("J3")));
        assert!(m.unwrap().contains("verdict running"));
        let fail =
            "tollgate: DENIED pre-commit refs/heads/x tree abc tier fast verdict fail job J4\n";
        assert_eq!(classify(false, fail).0, HookOutcome::Denied);
        assert_eq!(classify(true, "").0, HookOutcome::Ungated);
        let (o, _, m) = classify(false, "nothing added to commit\n\n");
        assert_eq!(o, HookOutcome::GitError);
        assert_eq!(m.as_deref(), Some("nothing added to commit"));
    }
}
