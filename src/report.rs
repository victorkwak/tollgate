//! Job reports, their human form, and the flaky log (R91-R93).
//!
//! `jobs/<id>/report.json` is written by the runner before the record
//! (R81). [`render`] prints it in at most about 80 lines (R91): the header,
//! the `POLICY:` line (L2), warnings, reused steps (L16), flaky and
//! quarantined tests (R93), then per failed step its exit, duration, failing
//! tests with rerun commands (nextest) or the last 30 log lines, and the
//! `tollgate log` command.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::cache::record::{ErrorCause, Selection, StepStatus, Verdict};
use crate::config::Tier;
use crate::config::repo::StepKind;
use crate::dirs::Dirs;
use crate::fsx;
use crate::gitx::Oid;
use crate::ids::JobId;
use crate::sched::Origin;
use crate::steps::Scope;
use crate::steps::junit::{FailingTest, FlakyTest, QuarantineHit};

/// Version of `report.json`.
pub const REPORT_SCHEMA: u32 = 1;

/// R91: about this many lines at most.
pub const MAX_LINES: usize = 80;

/// R91: log lines shown for a failed step that is not nextest.
pub const TAIL_LINES: usize = 30;

/// How a job ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// It has a verdict.
    Verdict,
    /// Queue budget or disk (R33, R44): no record.
    Deferred,
    /// `tollgate cancel` (R89): no record.
    Cancelled,
    /// A newer job from the same origin replaced it (R89): no record.
    Superseded,
}

/// One step in a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepReport {
    /// Step name.
    pub name: String,
    /// Kind.
    pub kind: StepKind,
    /// Outcome.
    pub status: StepStatus,
    /// Wall time in milliseconds.
    pub duration_ms: u64,
    /// Exit code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<i32>,
    /// Log file name in the job dir.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
    /// The command line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// What it checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    /// L16: the job whose pass was reused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reused_from: Option<JobId>,
    /// Why it did not run or what went wrong.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// nextest failures (R91).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failing: Vec<FailingTest>,
    /// New pyright diagnostics or failing pytest node ids (R91, R94).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<String>,
    /// One rerun command per binary (R91).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rerun: Vec<String>,
    /// Last log lines of a failed step without parsed items.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tail: Vec<String>,
}

impl StepReport {
    /// A report line for a step that did not run.
    #[must_use]
    pub fn skipped(name: &str, kind: StepKind, why: &str) -> Self {
        Self {
            name: name.to_owned(),
            kind,
            status: StepStatus::Skipped,
            duration_ms: 0,
            exit: None,
            log: None,
            command: None,
            scope: None,
            reused_from: None,
            message: Some(why.to_owned()),
            failing: Vec::new(),
            items: Vec::new(),
            rerun: Vec::new(),
            tail: Vec::new(),
        }
    }
}

/// `jobs/<id>/report.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobReport {
    /// [`REPORT_SCHEMA`].
    pub schema: u32,
    /// Job id.
    pub job_id: JobId,
    /// Checked tree.
    pub tree: Oid,
    /// Tier.
    pub tier: Tier,
    /// How it ended.
    pub outcome: Outcome,
    /// The verdict when `outcome` is `verdict`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    /// Cause of an `error` or a deferral.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<ErrorCause>,
    /// What went wrong, for errors and deferrals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Where the job came from.
    pub origin: Origin,
    /// Base tree of the selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_tree: Option<Oid>,
    /// Policy commit (L2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_commit: Option<Oid>,
    /// L2 `POLICY:` line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_line: Option<String>,
    /// `WARN` lines (R57b, R64, metadata failures).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// What was checked (R80).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection: Option<Selection>,
    /// Steps in config order.
    #[serde(default)]
    pub steps: Vec<StepReport>,
    /// Tests that passed on retry (R93).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flaky: Vec<FlakyTest>,
    /// Quarantined failures (R93).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quarantined: Vec<QuarantineHit>,
    /// A record of a covering pass made this job unnecessary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered_by: Option<JobId>,
    /// True when a record was written.
    pub record_written: bool,
    /// Job creation.
    pub created: jiff::Timestamp,
    /// First step start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started: Option<jiff::Timestamp>,
    /// End.
    pub finished: jiff::Timestamp,
    /// Host name.
    pub host: String,
    /// tollgate version.
    pub tollgate_version: String,
}

impl JobReport {
    /// The verdict text: `pass`, `fail`, ..., or the outcome.
    #[must_use]
    pub fn verdict_text(&self) -> String {
        match (self.outcome, self.verdict) {
            (Outcome::Verdict, Some(v)) => serde_json::to_value(v)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default(),
            (o, _) => serde_json::to_value(o)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default(),
        }
    }

    /// True for a `pass` verdict.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.outcome == Outcome::Verdict && self.verdict == Some(Verdict::Pass)
    }

    /// Reads `jobs/<id>/report.json`.
    pub fn read(dirs: &Dirs, id: &JobId) -> io::Result<Option<Self>> {
        let Some(bytes) = fsx::read_optional(&dirs.job_report(id))? else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Writes `jobs/<id>/report.json` by atomic rename (R37).
    pub fn write(&self, dirs: &Dirs) -> io::Result<()> {
        self.write_to(&dirs.job_report(&self.job_id))
    }

    /// Writes the report to `path` by atomic rename.
    pub fn write_to(&self, path: &Path) -> io::Result<()> {
        let json = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        fsx::write_atomic(path, &json)
    }
}

/// A step name as a file name: `[A-Za-z0-9._-]`, others become `_`.
#[must_use]
pub fn slug(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let s = s.trim_start_matches('.').to_owned();
    if s.is_empty() { "step".into() } else { s }
}

/// The last `n` lines of a log file.
#[must_use]
pub fn tail(path: &Path, n: usize) -> Vec<String> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(n)..]
        .iter()
        .map(|l| (*l).to_owned())
        .collect()
}

fn ms(d: u64) -> String {
    if d < 10_000 {
        format!("{:.1}s", d as f64 / 1000.0)
    } else {
        format!("{}s", d / 1000)
    }
}

fn step_ref(name: &str) -> String {
    if name.contains([' ', '\'', '"']) {
        format!("'{}'", name.replace('\'', "'\\''"))
    } else {
        name.to_owned()
    }
}

/// The human report (R91). `header` is the first line, for example
/// `tollgate: DENIED pre-commit refs/heads/x tree ... verdict fail job ...`.
#[must_use]
pub fn render(r: &JobReport, header: &str) -> Vec<String> {
    let mut head = vec![header.to_owned()];
    head.extend(r.policy_line.iter().cloned());
    head.extend(r.warnings.iter().cloned());
    if let Some(job) = &r.covered_by {
        head.push(format!("COVERED by the pass of job {job}"));
    }
    for s in &r.steps {
        if let Some(job) = &s.reused_from {
            head.push(format!("REUSED {} from {job}", s.name));
        }
    }
    for f in &r.flaky {
        head.push(format!(
            "FLAKY {} (passed on try {}){}",
            f.test,
            f.passed_on_try,
            if f.failed_job {
                "; fails the full tier"
            } else {
                ""
            }
        ));
    }
    for q in &r.quarantined {
        head.push(format!(
            "QUARANTINED {} until {} ({})",
            q.test, q.until, q.issue
        ));
    }
    if let Some(m) = &r.message {
        let cause = r
            .cause
            .and_then(|c| serde_json::to_value(c).ok())
            .and_then(|v| v.as_str().map(str::to_owned))
            .map(|c| format!(" (cause {c})"))
            .unwrap_or_default();
        head.push(format!("error{cause}: {m}"));
    }
    let mut foot = vec![format!("tollgate report {}", r.job_id)];
    if r.outcome == Outcome::Verdict && !r.passed() {
        foot.push("tollgate check --rerun".into());
    }
    let mut body = Vec::new();
    for s in r.steps.iter().filter(|s| {
        matches!(
            s.status,
            StepStatus::Fail | StepStatus::Timeout | StepStatus::Error
        )
    }) {
        let status = serde_json::to_value(s.status)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        let exit = s.exit.map(|e| format!(" exit {e}")).unwrap_or_default();
        body.push(format!(
            "step {}: {status}{exit} after {}",
            s.name,
            ms(s.duration_ms)
        ));
        if let Some(m) = &s.message {
            body.push(format!("  {m}"));
        }
        for f in s.failing.iter().take(20) {
            body.push(format!("  FAIL {} {} {}", f.package, f.binary_id, f.name));
        }
        if s.failing.len() > 20 {
            body.push(format!("  ... {} more failing tests", s.failing.len() - 20));
        }
        for i in &s.items {
            body.push(format!("  - {i}"));
        }
        for c in &s.rerun {
            body.push(format!("  rerun: {c}"));
        }
        for l in &s.tail {
            body.push(format!("  | {l}"));
        }
        body.push(format!("  tollgate log {} {}", r.job_id, step_ref(&s.name)));
    }
    let room = MAX_LINES.saturating_sub(head.len() + foot.len());
    if body.len() > room {
        let cut = body.len() - room + 1;
        body.truncate(room.saturating_sub(1));
        body.push(format!(
            "... {cut} more lines: tollgate report {}",
            r.job_id
        ));
    }
    head.into_iter().chain(body).chain(foot).collect()
}

/// One line of `flaky.jsonl` (R93).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlakyEntry {
    /// When.
    pub time: jiff::Timestamp,
    /// `<binary-id> <test>`.
    pub test: String,
    /// The try that passed.
    pub passed_on_try: u32,
    /// `pass` (fast), `fail` (full), `quarantined`.
    pub result: String,
    /// Tier.
    pub tier: Tier,
    /// Job.
    pub job: JobId,
    /// Origin worktree.
    pub worktree: PathBuf,
}

/// Appends entries to `flaky.jsonl` (R93).
pub fn append_flaky(dirs: &Dirs, entries: &[FlakyEntry]) -> io::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let path = dirs.flaky_log();
    if let Some(d) = path.parent() {
        fsx::ensure_dir(d)?;
    }
    let mut text = String::new();
    for e in entries {
        text.push_str(&serde_json::to_string(e).map_err(io::Error::other)?);
        text.push('\n');
    }
    // One write with O_APPEND: lines from concurrent jobs do not mix.
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?
        .write_all(text.as_bytes())
}

/// Per test: (count, last seen) in the last `days` days (`tollgate flaky`).
pub fn flaky_counts(
    dirs: &Dirs,
    days: u32,
    now: jiff::Timestamp,
) -> io::Result<Vec<(String, u32, jiff::Timestamp)>> {
    let Some(bytes) = fsx::read_optional(&dirs.flaky_log())? else {
        return Ok(Vec::new());
    };
    let since = now.as_second() - i64::from(days) * 86_400;
    let mut by: BTreeMap<String, (u32, jiff::Timestamp)> = BTreeMap::new();
    for line in String::from_utf8_lossy(&bytes).lines() {
        let Ok(e) = serde_json::from_str::<FlakyEntry>(line) else {
            continue;
        };
        if e.time.as_second() < since {
            continue;
        }
        let slot = by.entry(e.test).or_insert((0, e.time));
        slot.0 += 1;
        slot.1 = slot.1.max(e.time);
    }
    let mut out: Vec<_> = by.into_iter().map(|(t, (n, last))| (t, n, last)).collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> JobReport {
        let now = jiff::Timestamp::now();
        JobReport {
            schema: REPORT_SCHEMA,
            job_id: JobId::parse("20261105-010203-0123abcd").unwrap(),
            tree: Oid::parse(&"ab".repeat(20)).unwrap(),
            tier: Tier::Fast,
            outcome: Outcome::Verdict,
            verdict: Some(Verdict::Fail),
            cause: None,
            message: None,
            origin: Origin {
                worktree: "/w".into(),
                refname: "refs/heads/x".into(),
            },
            base_tree: None,
            policy_commit: None,
            policy_line: Some("POLICY: x".into()),
            warnings: vec!["WARN owners: unknown package p".into()],
            selection: None,
            steps: Vec::new(),
            flaky: vec![FlakyTest {
                test: "a tests::flaky".into(),
                passed_on_try: 2,
                failed_job: false,
            }],
            quarantined: Vec::new(),
            covered_by: None,
            record_written: true,
            created: now,
            started: Some(now),
            finished: now,
            host: "h".into(),
            tollgate_version: "0".into(),
        }
    }

    fn failed_step(name: &str, failing: usize, tail: usize) -> StepReport {
        StepReport {
            status: StepStatus::Fail,
            exit: Some(100),
            log: Some(format!("{}.log", slug(name))),
            failing: (0..failing)
                .map(|i| FailingTest {
                    package: "b".into(),
                    binary_id: "b".into(),
                    name: format!("t{i}"),
                })
                .collect(),
            rerun: vec!["cargo nextest run -p b -E 'x'".into()],
            tail: (0..tail).map(|i| format!("line {i}")).collect(),
            duration_ms: 1234,
            ..StepReport::skipped(name, StepKind::Nextest, "")
        }
    }

    #[test]
    fn render_lists_failures_rerun_and_log_r91_t40() {
        let mut r = report();
        r.steps.push(failed_step("tests", 1, 0));
        let lines = render(&r, "tollgate: FAIL");
        let text = lines.join("\n");
        for needle in [
            "POLICY: x",
            "WARN owners",
            "FLAKY a tests::flaky (passed on try 2)",
            "step tests: fail exit 100 after 1.2s",
            "FAIL b b t0",
            "rerun: cargo nextest run -p b",
            "tollgate log 20261105-010203-0123abcd tests",
            "tollgate report 20261105-010203-0123abcd",
            "tollgate check --rerun",
        ] {
            assert!(text.contains(needle), "{needle:?} in\n{text}");
        }
    }

    #[test]
    fn render_stays_under_80_lines_r91() {
        let mut r = report();
        for i in 0..5 {
            r.steps
                .push(failed_step(&format!("dashboard check {i}"), 30, 30));
        }
        let lines = render(&r, "h");
        assert!(lines.len() <= MAX_LINES, "{}", lines.len());
        assert!(lines.iter().any(|l| l.contains("more lines")));
        assert_eq!(lines.last().unwrap(), "tollgate check --rerun");
        assert!(
            lines
                .join("\n")
                .contains("tollgate log 20261105-010203-0123abcd 'dashboard check 0'")
        );
    }

    #[test]
    fn slugs_are_file_names() {
        assert_eq!(slug("dashboard check"), "dashboard_check");
        assert_eq!(slug("../x"), "_x");
        assert_eq!(slug(""), "step");
    }

    #[test]
    fn flaky_log_counts_per_test_r93() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = Dirs::from_env(&crate::env::EnvSnapshot::from_pairs([(
            "HOME",
            tmp.path().as_os_str(),
        )]))
        .unwrap();
        let now = jiff::Timestamp::now();
        let e = |test: &str, days_ago: i64| FlakyEntry {
            time: jiff::Timestamp::from_second(now.as_second() - days_ago * 86_400).unwrap(),
            test: test.into(),
            passed_on_try: 2,
            result: "pass".into(),
            tier: Tier::Fast,
            job: JobId::parse("20261105-010203-0123abcd").unwrap(),
            worktree: "/w".into(),
        };
        append_flaky(&dirs, &[e("a x", 1), e("a x", 2), e("b y", 0)]).unwrap();
        append_flaky(&dirs, &[e("a x", 30)]).unwrap();
        let counts = flaky_counts(&dirs, 14, now).unwrap();
        assert_eq!(
            counts
                .iter()
                .map(|(t, n, _)| (t.as_str(), *n))
                .collect::<Vec<_>>(),
            [("a x", 2), ("b y", 1)]
        );
    }
}
