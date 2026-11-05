//! nextest JUnit reports (R91, R93).
//!
//! nextest writes one `<testsuite name="<binary-id>">` per test binary and
//! one `<testcase name="<test>">` per test. A failed test has `<failure>`
//! (and `<rerunFailure>` per retry); a test that passed on retry has
//! `<flakyFailure>` children; with `--flaky-result fail` it also has
//! `<failure type="flaky failure">`.

use std::collections::BTreeSet;

use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use serde::{Deserialize, Serialize};

use crate::config::Tier;
use crate::config::repo::Quarantine;

/// The outcome of one test case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseOutcome {
    /// Passed (perhaps on retry).
    Passed,
    /// Failed every try.
    Failed,
    /// Passed on retry, failed by `--flaky-result fail`.
    FlakyFailed,
    /// Not run.
    Skipped,
}

/// One test case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestCase {
    /// nextest binary id: `<package>` or `<package>::<binary>`.
    pub binary_id: String,
    /// Test name.
    pub name: String,
    /// Outcome.
    pub outcome: CaseOutcome,
    /// Failed tries before the pass (flaky).
    pub flaky_failures: u32,
}

impl TestCase {
    /// `<binary-id> <test>`: the quarantine form (R63).
    #[must_use]
    pub fn id(&self) -> String {
        format!("{} {}", self.binary_id, self.name)
    }

    /// The package of the binary id.
    #[must_use]
    pub fn package(&self) -> &str {
        self.binary_id
            .split_once("::")
            .map_or(self.binary_id.as_str(), |(p, _)| p)
    }
}

fn attr(e: &BytesStart<'_>, name: &str) -> Option<String> {
    e.try_get_attribute(name)
        .ok()
        .flatten()
        .and_then(|a| a.normalized_value(XmlVersion::Implicit1_0).ok())
        .map(std::borrow::Cow::into_owned)
}

/// Parses a nextest JUnit report.
pub fn parse(xml: &str) -> Result<Vec<TestCase>, String> {
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut suite = String::new();
    let mut current: Option<TestCase> = None;
    let mut out = Vec::new();
    loop {
        let event = reader
            .read_event()
            .map_err(|e| format!("JUnit XML at byte {}: {e}", reader.buffer_position()))?;
        let empty = matches!(event, Event::Empty(_));
        match event {
            Event::Start(e) | Event::Empty(e) => match e.name().as_ref() {
                "testsuite" => suite = attr(&e, "name").unwrap_or_default(),
                "testcase" => {
                    let case = TestCase {
                        binary_id: suite.clone(),
                        name: attr(&e, "name").unwrap_or_default(),
                        outcome: CaseOutcome::Passed,
                        flaky_failures: 0,
                    };
                    if empty {
                        out.push(case);
                    } else {
                        current = Some(case);
                    }
                }
                "failure" | "error" => {
                    if let Some(c) = current.as_mut() {
                        c.outcome = if attr(&e, "type").as_deref() == Some("flaky failure") {
                            CaseOutcome::FlakyFailed
                        } else {
                            CaseOutcome::Failed
                        };
                    }
                }
                "flakyFailure" => {
                    if let Some(c) = current.as_mut() {
                        c.flaky_failures += 1;
                    }
                }
                "skipped" => {
                    if let Some(c) = current.as_mut()
                        && c.outcome == CaseOutcome::Passed
                    {
                        c.outcome = CaseOutcome::Skipped;
                    }
                }
                _ => {}
            },
            Event::End(e) if e.name().as_ref() == "testcase" => {
                if let Some(c) = current.take() {
                    out.push(c);
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(out)
}

/// A test that passed on retry (R93).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlakyTest {
    /// `<binary-id> <test>`.
    pub test: String,
    /// The try that passed.
    pub passed_on_try: u32,
    /// True when `--flaky-result fail` failed it (`full`).
    pub failed_job: bool,
}

/// A failure turned into `QUARANTINED` (R93).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineHit {
    /// `<binary-id> <test>`.
    pub test: String,
    /// Last day of the quarantine.
    pub until: String,
    /// Where it is tracked.
    pub issue: String,
}

/// A failing test for the report and rerun commands (R91).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailingTest {
    /// Package.
    pub package: String,
    /// nextest binary id.
    pub binary_id: String,
    /// Test name.
    pub name: String,
}

/// What a nextest run means for the job (R91, R93).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    /// Failures that count.
    pub failing: Vec<FailingTest>,
    /// Tests that passed on retry.
    pub flaky: Vec<FlakyTest>,
    /// Failures of quarantined tests.
    pub quarantined: Vec<QuarantineHit>,
    /// Every test id in the report (R64 quarantine check).
    pub known: BTreeSet<String>,
}

/// Applies the flaky and quarantine policy (R93) to `cases`. A quarantine
/// entry covers only a flaky failure in `full` (a test that passed on retry
/// and failed through `--flaky-result fail`), while `until >= today`. A test
/// that failed every try always fails, quarantined or not.
#[must_use]
pub fn summarize(
    cases: &[TestCase],
    quarantine: &[Quarantine],
    today: jiff::civil::Date,
    tier: Tier,
) -> Summary {
    let mut s = Summary::default();
    for c in cases {
        let id = c.id();
        s.known.insert(id.clone());
        if c.flaky_failures > 0 {
            s.flaky.push(FlakyTest {
                test: id.clone(),
                passed_on_try: c.flaky_failures + 1,
                failed_job: c.outcome == CaseOutcome::FlakyFailed,
            });
        }
        if !matches!(c.outcome, CaseOutcome::Failed | CaseOutcome::FlakyFailed) {
            continue;
        }
        let entry = (tier == Tier::Full && c.outcome == CaseOutcome::FlakyFailed)
            .then(|| quarantine.iter().find(|q| q.test == id && q.until >= today))
            .flatten();
        match entry {
            Some(q) => s.quarantined.push(QuarantineHit {
                test: id,
                until: q.until.to_string(),
                issue: q.issue.clone(),
            }),
            None => s.failing.push(FailingTest {
                package: c.package().to_owned(),
                binary_id: c.binary_id.clone(),
                name: c.name.clone(),
            }),
        }
    }
    s
}

/// R91: one rerun command per binary.
#[must_use]
pub fn rerun_commands(failing: &[FailingTest]) -> Vec<String> {
    let mut by_binary: std::collections::BTreeMap<(&str, &str), Vec<&str>> =
        std::collections::BTreeMap::new();
    for f in failing {
        by_binary
            .entry((f.package.as_str(), f.binary_id.as_str()))
            .or_default()
            .push(f.name.as_str());
    }
    by_binary
        .into_iter()
        .map(|((package, binary), names)| {
            let tests: Vec<String> = names.iter().map(|n| format!("test(={n})")).collect();
            format!(
                "cargo nextest run -p {package} -E 'binary_id(={binary}) & ({})'",
                tests.join(" | ")
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trimmed from a real nextest 0.9.150 report (retries = 2).
    const REPORT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="nextest-run" tests="5" failures="2" errors="0">
    <testsuite name="a" tests="3" skipped="1" errors="0" failures="1">
        <testcase name="tests::ok" classname="a" time="0.004"/>
        <testcase name="tests::flaky" classname="a" time="0.004">
            <flakyFailure message="thread &apos;tests::flaky&apos; panicked" type="test failure with exit code 101">first try fails
                <system-out>x</system-out>
            </flakyFailure>
        </testcase>
        <testcase name="tests::flaky_full" classname="a" time="0.004">
            <failure message="test passed on attempt 2/3 but is configured to fail when flaky" type="flaky failure"/>
            <flakyFailure message="m" type="test failure with exit code 101">x</flakyFailure>
        </testcase>
        <testcase name="tests::ignored" classname="a"><skipped/></testcase>
    </testsuite>
    <testsuite name="b::it" tests="1" errors="0" failures="0">
        <testcase name="integration" classname="b::it" time="0.004"/>
    </testsuite>
    <testsuite name="b" tests="1" errors="0" failures="1">
        <testcase name="tests::fails" classname="b" time="0.004">
            <failure message="thread &apos;tests::fails&apos; panicked" type="test failure with exit code 101">left: 2</failure>
            <rerunFailure message="m" type="t">x<system-out>y</system-out></rerunFailure>
            <rerunFailure message="m" type="t">x</rerunFailure>
            <system-out>z</system-out>
        </testcase>
    </testsuite>
</testsuites>"#;

    #[test]
    fn parses_outcomes_and_retries() {
        let cases = parse(REPORT).unwrap();
        let by = |id: &str| cases.iter().find(|c| c.id() == id).unwrap();
        assert_eq!(cases.len(), 6);
        assert_eq!(by("a tests::ok").outcome, CaseOutcome::Passed);
        assert_eq!(by("a tests::flaky").flaky_failures, 1);
        assert_eq!(by("a tests::flaky").outcome, CaseOutcome::Passed);
        assert_eq!(by("a tests::flaky_full").outcome, CaseOutcome::FlakyFailed);
        assert_eq!(by("a tests::ignored").outcome, CaseOutcome::Skipped);
        assert_eq!(by("b::it integration").package(), "b");
        assert_eq!(by("b tests::fails").outcome, CaseOutcome::Failed);
        assert!(parse("<testsuites><testsuite name=\"x\">").is_ok());
        assert!(parse("<a></b>").is_err());
    }

    #[test]
    fn flaky_and_quarantine_policy_r93_t41() {
        let cases = parse(REPORT).unwrap();
        let today = jiff::civil::date(2026, 11, 5);
        let s = summarize(&cases, &[], today, Tier::Full);
        assert_eq!(s.failing.len(), 2);
        assert_eq!(s.flaky.len(), 2);
        assert_eq!(s.flaky[0].passed_on_try, 2);
        assert!(!s.flaky[0].failed_job && s.flaky[1].failed_job);
        assert!(s.known.contains("a tests::ignored"));
        let q = |until| Quarantine {
            test: "a tests::flaky_full".into(),
            until,
            issue: "Issues/open/x".into(),
        };
        let valid = summarize(&cases, &[q(today)], today, Tier::Full);
        assert_eq!(valid.failing.len(), 1, "{valid:?}");
        assert_eq!(valid.quarantined[0].until, "2026-11-05");
        let expired = summarize(
            &cases,
            &[q(jiff::civil::date(2026, 11, 4))],
            today,
            Tier::Full,
        );
        assert_eq!(expired.failing.len(), 2);
        assert!(expired.quarantined.is_empty());
        // A test that fails every try is never quarantined, in either tier.
        let broken = Quarantine {
            test: "b tests::fails".into(),
            until: today,
            issue: "Issues/open/x".into(),
        };
        for tier in [Tier::Full, Tier::Fast] {
            let s = summarize(&cases, std::slice::from_ref(&broken), today, tier);
            assert!(
                s.failing.iter().any(|f| f.name == "tests::fails") && s.quarantined.is_empty(),
                "{tier}: {s:?}"
            );
        }
        // Quarantine is a full-tier rule (R93): fast has no flaky failures.
        let fast = summarize(&cases, &[q(today)], today, Tier::Fast);
        assert!(fast.quarantined.is_empty(), "{fast:?}");
    }

    #[test]
    fn rerun_commands_group_by_binary_r91() {
        let f = |p: &str, b: &str, n: &str| FailingTest {
            package: p.into(),
            binary_id: b.into(),
            name: n.into(),
        };
        let cmds = rerun_commands(&[f("b", "b", "x"), f("b", "b", "y"), f("b", "b::it", "z")]);
        assert_eq!(
            cmds,
            [
                "cargo nextest run -p b -E 'binary_id(=b) & (test(=x) | test(=y))'",
                "cargo nextest run -p b -E 'binary_id(=b::it) & (test(=z))'",
            ]
        );
    }
}
