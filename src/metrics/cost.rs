//! `tollgate cost` (R109): gate time per repo and local day, from the
//! `job` lines of the metrics log.
//!
//! A job counts once, by its first line (a reap can add a second, [`LOST`]
//! line), on the local day of that line's time. Its step time is the
//! line's `step_ms`. A line from an older binary has none: then the job's
//! `report.json`, when it still exists, gives the sum and the origin ref;
//! else the step time is estimated as wall time minus queue times, the
//! branch is `?`, and the cell is marked estimated. A [`LOST`] line with
//! no report counts 0 (estimated): its wall time runs to the reap, which
//! can come hours after the runner died. The `by` field is not read, so a
//! job of any origin counts.

use std::collections::{BTreeMap, BTreeSet};

use jiff::tz::TimeZone;
use serde::Serialize;

use super::{Event, LOST};
use crate::dirs::Dirs;
use crate::ids::JobId;

/// Branches listed per repo in the top-branches table.
pub const TOP_BRANCHES: usize = 10;

/// One day, repo and tier (or the day's total, repo `total`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CostRow {
    /// Local day, `YYYY-MM-DD`.
    pub day: String,
    /// Repo name as the log has it.
    pub repo: String,
    /// Tier (`-` on a total row).
    pub tier: String,
    /// Jobs.
    pub jobs: u32,
    /// Jobs whose verdict is `pass`.
    pub passed: u32,
    /// Time of the steps that ran, ms.
    pub step_ms: u64,
    /// Job wall time, ms.
    pub wall_ms: u64,
    /// Steps that were not reused.
    pub steps_run: u32,
    /// Steps reused from a stored pass (L16): not run.
    pub steps_reused: u32,
    /// Some step time is estimated (an older line with no report).
    pub estimated: bool,
}

/// One local day.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CostDay {
    /// `YYYY-MM-DD`.
    pub day: String,
    /// Per repo and tier.
    pub rows: Vec<CostRow>,
    /// Their sum.
    pub total: CostRow,
}

/// Step time of one branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BranchCost {
    /// Branch (`?` when unknown).
    pub branch: String,
    /// Jobs.
    pub jobs: u32,
    /// Time of the steps that ran, ms.
    pub step_ms: u64,
    /// Some step time is estimated.
    pub estimated: bool,
}

/// The top branches of one repo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RepoBranches {
    /// Repo name.
    pub repo: String,
    /// At most [`TOP_BRANCHES`], most step time first.
    pub branches: Vec<BranchCost>,
}

/// `tollgate cost`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Cost {
    /// `--since`.
    pub since: Option<jiff::Timestamp>,
    /// The time zone of the days.
    pub time_zone: String,
    /// `--repo`.
    pub repo: Option<String>,
    /// Jobs counted.
    pub jobs: u32,
    /// Newest day first.
    pub days: Vec<CostDay>,
    /// Per repo.
    pub top_branches: Vec<RepoBranches>,
}

/// What a job's `report.json` says: step time of the steps that ran and
/// the branch.
pub type ReportLookup<'a> = &'a dyn Fn(&JobId) -> Option<(u64, String)>;

/// [`ReportLookup`] over the job dirs of `dirs`.
pub fn from_reports(dirs: &Dirs) -> impl Fn(&JobId) -> Option<(u64, String)> + '_ {
    move |id| {
        crate::report::JobReport::read(dirs, id)
            .ok()
            .flatten()
            .map(|r| {
                (
                    super::ran_step_ms(&r.steps),
                    super::branch_of(&r.origin.refname),
                )
            })
    }
}

fn add(to: &mut CostRow, from: &CostRow) {
    to.jobs += from.jobs;
    to.passed += from.passed;
    to.step_ms += from.step_ms;
    to.wall_ms += from.wall_ms;
    to.steps_run += from.steps_run;
    to.steps_reused += from.steps_reused;
    to.estimated |= from.estimated;
}

/// Sums the `job` lines of `events` (all after `since`) per local day of
/// `tz`, repo and tier, and per branch; `repo` keeps only that repo.
#[must_use]
pub fn cost(
    events: &[Event],
    since: Option<jiff::Timestamp>,
    tz: &TimeZone,
    repo: Option<&str>,
    report: ReportLookup<'_>,
) -> Cost {
    let mut seen: BTreeSet<&JobId> = BTreeSet::new();
    let mut rows: BTreeMap<(String, String, String), CostRow> = BTreeMap::new();
    let mut branches: BTreeMap<String, BTreeMap<String, BranchCost>> = BTreeMap::new();
    let mut jobs = 0;
    for e in events {
        let Event::Job(j) = e else { continue };
        if repo.is_some_and(|r| r != j.repo) || !seen.insert(&j.job) {
            continue;
        }
        jobs += 1;
        let (step_ms, branch, estimated) = match j.step_ms {
            Some(ms) => (ms, j.branch.clone().unwrap_or_else(|| "?".into()), false),
            None => match report(&j.job) {
                Some((ms, b)) => (ms, b, false),
                None if j.verdict == LOST => (0, "?".into(), true),
                None => (
                    j.wall_ms
                        .saturating_sub(j.job_queue_ms)
                        .saturating_sub(j.slot_queue_ms),
                    "?".into(),
                    true,
                ),
            },
        };
        let day = j.t.to_zoned(tz.clone()).date().to_string();
        let tier = serde_json::to_value(j.tier)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        let one = CostRow {
            day: day.clone(),
            repo: j.repo.clone(),
            tier: tier.clone(),
            jobs: 1,
            passed: u32::from(j.verdict == "pass"),
            step_ms,
            wall_ms: j.wall_ms,
            // The job's own count (R109); for older lines, every step
            // that was not reused by inputs (L16) or taken from a job on
            // the same tree (R101), which also counts skipped steps.
            steps_run: j
                .steps_ran
                .unwrap_or_else(|| j.steps.saturating_sub(j.steps_reused + j.steps_fresh)),
            steps_reused: j.steps_reused + j.steps_fresh,
            estimated,
        };
        let row = rows
            .entry((day, j.repo.clone(), tier))
            .or_insert_with(|| CostRow {
                jobs: 0,
                passed: 0,
                step_ms: 0,
                wall_ms: 0,
                steps_run: 0,
                steps_reused: 0,
                estimated: false,
                ..one.clone()
            });
        add(row, &one);
        let b = branches
            .entry(j.repo.clone())
            .or_default()
            .entry(branch.clone())
            .or_insert_with(|| BranchCost {
                branch,
                jobs: 0,
                step_ms: 0,
                estimated: false,
            });
        b.jobs += 1;
        b.step_ms += step_ms;
        b.estimated |= estimated;
    }
    let mut days: Vec<CostDay> = Vec::new();
    for ((day, _, _), row) in rows {
        if days.last().is_none_or(|d| d.day != day) {
            days.push(CostDay {
                day: day.clone(),
                rows: Vec::new(),
                total: CostRow {
                    day,
                    repo: "total".into(),
                    tier: "-".into(),
                    ..CostRow::default()
                },
            });
        }
        let d = days.last_mut().expect("pushed above");
        add(&mut d.total, &row);
        d.rows.push(row);
    }
    days.reverse();
    let top_branches = branches
        .into_iter()
        .map(|(repo, by)| {
            let mut v: Vec<BranchCost> = by.into_values().collect();
            v.sort_by(|a, b| {
                b.step_ms
                    .cmp(&a.step_ms)
                    .then_with(|| a.branch.cmp(&b.branch))
            });
            v.truncate(TOP_BRANCHES);
            RepoBranches { repo, branches: v }
        })
        .collect();
    Cost {
        since,
        time_zone: tz.iana_name().unwrap_or("system").to_owned(),
        repo: repo.map(str::to_owned),
        jobs,
        days,
        top_branches,
    }
}

/// `h:mm`, rounded to the minute.
#[must_use]
pub fn hmm(ms: u64) -> String {
    let min = ms.saturating_add(30_000) / 60_000;
    format!("{}:{:02}", min / 60, min % 60)
}

fn step_cell(ms: u64, estimated: bool) -> String {
    format!("{}{}", if estimated { "~" } else { "" }, hmm(ms))
}

/// The human tables.
#[must_use]
pub fn render(c: &Cost) -> Vec<String> {
    let since = c.since.map_or_else(
        || "the start of the log".to_owned(),
        |t| t.strftime("%Y-%m-%d %H:%M UTC").to_string(),
    );
    let mut out = vec![format!(
        "tollgate cost: {} jobs since {since}; days in {}; ~ = estimated (an older log line with no report)",
        c.jobs, c.time_zone
    )];
    if c.days.is_empty() {
        return out;
    }
    let mut rows: Vec<Vec<String>> = vec![
        [
            "day",
            "repo",
            "tier",
            "jobs",
            "passed",
            "step",
            "wall",
            "steps run",
            "not run (reused)",
        ]
        .map(str::to_owned)
        .to_vec(),
    ];
    for d in &c.days {
        for r in d.rows.iter().chain(std::iter::once(&d.total)) {
            rows.push(vec![
                r.day.clone(),
                r.repo.clone(),
                r.tier.clone(),
                r.jobs.to_string(),
                r.passed.to_string(),
                step_cell(r.step_ms, r.estimated),
                hmm(r.wall_ms),
                r.steps_run.to_string(),
                r.steps_reused.to_string(),
            ]);
        }
    }
    out.extend(super::table(&rows));
    out.push(String::new());
    out.push(format!(
        "top branches (step time, at most {TOP_BRANCHES} per repo)"
    ));
    let mut rows: Vec<Vec<String>> = vec![
        ["repo", "branch", "jobs", "step"]
            .map(str::to_owned)
            .to_vec(),
    ];
    for r in &c.top_branches {
        for b in &r.branches {
            rows.push(vec![
                r.repo.clone(),
                b.branch.clone(),
                b.jobs.to_string(),
                step_cell(b.step_ms, b.estimated),
            ]);
        }
    }
    out.extend(super::table(&rows));
    out
}

#[cfg(test)]
mod tests {
    use super::super::JobEvent;
    use super::*;
    use crate::config::Tier;

    fn chicago() -> TimeZone {
        TimeZone::get("America/Chicago").unwrap()
    }

    fn ts(s: &str) -> jiff::Timestamp {
        s.parse().unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn job(
        n: u32,
        t: &str,
        repo: &str,
        tier: Tier,
        verdict: &str,
        step_ms: Option<u64>,
        branch: Option<&str>,
    ) -> Event {
        Event::Job(JobEvent {
            t: ts(t),
            job: JobId::parse(&format!("20261109-120000-{n:08x}")).unwrap(),
            repo: repo.into(),
            tier,
            by: "hook".into(),
            verdict: verdict.into(),
            wall_ms: 600_000,
            job_queue_ms: 60_000,
            slot_queue_ms: 30_000,
            checkout_wait_ms: 0,
            steps: 4,
            steps_reused: 1,
            steps_fresh: 0,
            steps_ran: None,
            flaky: 0,
            quarantined: 0,
            step_ms,
            branch: branch.map(str::to_owned),
        })
    }

    fn none(_: &JobId) -> Option<(u64, String)> {
        None
    }

    /// R109: days are local days; two jobs 10 minutes apart on both sides
    /// of midnight in Chicago (UTC-6 in November) fall on two days, newest
    /// first, each with a total row.
    #[test]
    fn days_are_local_days_newest_first_r109() {
        let events = [
            job(
                1,
                "2026-11-10T05:55:00Z",
                "r",
                Tier::Fast,
                "pass",
                Some(60_000),
                Some("a"),
            ),
            job(
                2,
                "2026-11-10T06:05:00Z",
                "r",
                Tier::Fast,
                "pass",
                Some(120_000),
                Some("a"),
            ),
        ];
        let c = cost(&events, None, &chicago(), None, &none);
        let days: Vec<(&str, u64)> = c
            .days
            .iter()
            .map(|d| (d.day.as_str(), d.total.step_ms))
            .collect();
        assert_eq!(days, [("2026-11-10", 120_000), ("2026-11-09", 60_000)]);
        // In UTC both are on 2026-11-10.
        let c = cost(&events, None, &TimeZone::UTC, None, &none);
        assert_eq!(c.days.len(), 1, "{c:#?}");
        assert_eq!(c.time_zone, "UTC");
    }

    /// R109: sums per repo and tier, the day's total, steps run and not
    /// run, passed; a job's second line (a reap) does not count again; a
    /// `by` this code does not know counts like the others.
    #[test]
    fn sums_per_repo_and_tier_r109() {
        let mut step = job(
            5,
            "2026-11-10T19:00:00Z",
            "a",
            Tier::Full,
            "pass",
            Some(1),
            Some("x"),
        );
        if let Event::Job(j) = &mut step {
            j.by = "step".into();
            // A newer line: its own count of steps that ran.
            j.steps_ran = Some(1);
        }
        let events = [
            job(
                1,
                "2026-11-10T18:00:00Z",
                "a",
                Tier::Fast,
                "pass",
                Some(60_000),
                Some("x"),
            ),
            job(
                2,
                "2026-11-10T18:10:00Z",
                "a",
                Tier::Fast,
                "fail",
                Some(30_000),
                Some("x"),
            ),
            job(
                3,
                "2026-11-10T18:20:00Z",
                "a",
                Tier::Full,
                "pass",
                Some(3_600_000),
                Some("main"),
            ),
            job(
                4,
                "2026-11-10T18:30:00Z",
                "b",
                Tier::Fast,
                "pass",
                Some(10_000),
                Some("y"),
            ),
            // A reap's line for job 3: not a second job.
            job(3, "2026-11-10T20:00:00Z", "a", Tier::Full, LOST, None, None),
            step,
        ];
        let c = cost(&events, None, &TimeZone::UTC, None, &none);
        assert_eq!(c.jobs, 5);
        let d = &c.days[0];
        let got: Vec<(&str, &str, u32, u32, u64)> = d
            .rows
            .iter()
            .map(|r| {
                (
                    r.repo.as_str(),
                    r.tier.as_str(),
                    r.jobs,
                    r.passed,
                    r.step_ms,
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                ("a", "fast", 2, 1, 90_000),
                ("a", "full", 2, 2, 3_600_001),
                ("b", "fast", 1, 1, 10_000),
            ]
        );
        assert_eq!(
            (
                d.total.jobs,
                d.total.passed,
                d.total.step_ms,
                d.total.wall_ms
            ),
            (5, 4, 3_700_001, 3_000_000)
        );
        // Four older lines estimate 4 - 1 = 3 each; the step job's line
        // says 1.
        assert_eq!((d.total.steps_run, d.total.steps_reused), (13, 5));
        assert!(!d.total.estimated);
        // --repo
        let c = cost(&events, None, &TimeZone::UTC, Some("b"), &none);
        assert_eq!(c.jobs, 1);
        assert_eq!(c.days[0].rows.len(), 1);
        assert_eq!(c.top_branches.len(), 1);
        assert_eq!(c.top_branches[0].repo, "b");
        assert_eq!(c.repo.as_deref(), Some("b"));
    }

    /// R109: per repo, the branches with the most step time first, at most
    /// ten; ties by name.
    #[test]
    fn top_branches_by_step_time_r109() {
        let mut events: Vec<Event> = (0..12u32)
            .map(|n| {
                job(
                    n,
                    "2026-11-10T18:00:00Z",
                    "r",
                    Tier::Fast,
                    "pass",
                    Some(u64::from(n) * 1000),
                    Some(&format!("b{n:02}")),
                )
            })
            .collect();
        events.push(job(
            20,
            "2026-11-10T18:00:00Z",
            "r",
            Tier::Full,
            "pass",
            Some(5_000),
            Some("b01"),
        ));
        events.push(job(
            21,
            "2026-11-10T18:00:00Z",
            "r",
            Tier::Fast,
            "pass",
            Some(11_000),
            Some("a"),
        ));
        let c = cost(&events, None, &TimeZone::UTC, None, &none);
        let b: Vec<(&str, u32, u64)> = c.top_branches[0]
            .branches
            .iter()
            .map(|b| (b.branch.as_str(), b.jobs, b.step_ms))
            .collect();
        assert_eq!(b.len(), TOP_BRANCHES);
        assert_eq!(
            &b[..4],
            [
                ("a", 1, 11_000),
                ("b11", 1, 11_000),
                ("b10", 1, 10_000),
                ("b09", 1, 9_000)
            ]
        );
        assert!(b.contains(&("b01", 2, 6_000)), "{b:?}");
        assert!(!b.iter().any(|x| x.0 == "b00"), "{b:?}");
    }

    /// R109: a line from before `step_ms` takes the sum and the branch
    /// from its report; with no report the step time is wall minus queues,
    /// the branch `?`, marked estimated; a lost line with no report counts
    /// 0, estimated.
    #[test]
    fn old_lines_use_the_report_or_an_estimate_r109() {
        let events = [
            job(
                1,
                "2026-11-10T18:00:00Z",
                "r",
                Tier::Fast,
                "pass",
                None,
                None,
            ),
            job(
                2,
                "2026-11-10T18:00:00Z",
                "r",
                Tier::Fast,
                "pass",
                None,
                None,
            ),
            job(3, "2026-11-10T18:00:00Z", "r", Tier::Fast, LOST, None, None),
        ];
        let has = |id: &JobId| (id.as_str().ends_with('1')).then(|| (42_000, "feat".to_owned()));
        let c = cost(&events, None, &TimeZone::UTC, None, &has);
        let d = &c.days[0];
        assert_eq!(d.total.step_ms, 42_000 + 510_000);
        assert!(d.total.estimated);
        let b = &c.top_branches[0].branches;
        assert_eq!(
            b.iter()
                .map(|b| (b.branch.as_str(), b.jobs, b.step_ms, b.estimated))
                .collect::<Vec<_>>(),
            [("?", 2, 510_000, true), ("feat", 1, 42_000, false)]
        );
        let text = render(&c).join("\n");
        assert!(text.contains("~0:09"), "{text}");
        // Only the report-backed job: not estimated, no `~` in its rows.
        let c = cost(&events[..1], None, &TimeZone::UTC, None, &has);
        assert!(!c.days[0].total.estimated);
        let lines = render(&c);
        assert!(lines[2..].iter().all(|l| !l.contains('~')), "{lines:#?}");
    }

    #[test]
    fn times_are_hours_and_minutes() {
        assert_eq!(hmm(0), "0:00");
        assert_eq!(hmm(29_999), "0:00");
        assert_eq!(hmm(30_000), "0:01");
        assert_eq!(hmm(9 * 3_600_000 + 5 * 60_000), "9:05");
        assert_eq!(hmm(110 * 3_600_000), "110:00");
    }
}
