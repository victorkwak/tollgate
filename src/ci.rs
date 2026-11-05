//! CI integration (R47, R73): the GitLab job that `tollgate ci-snippet
//! --gitlab` prints, and the JUnit report of `tollgate run --here --report
//! junit`.
//!
//! `tollgate-report/junit.xml` holds one `<testsuite name="tollgate">` with
//! one test case per step (so a failing `pytest-baseline` or `tsc` shows in
//! GitLab's test report like a failing test), followed by the test suites
//! of every nextest step's own JUnit file.

use std::path::Path;

use quick_xml::escape::escape;
use quick_xml::events::Event;

use crate::cache::record::StepStatus;
use crate::report::JobReport;

/// The `.gitlab-ci.yml` job (R73). `out` is the `run --here` report dir.
#[must_use]
pub fn gitlab_snippet(out: &str) -> String {
    format!(
        "\
# tollgate full tier in CI (R47, R73). Add this job to .gitlab-ci.yml.
# The runner needs tollgate on PATH: cargo install --git <the tollgate repo> --locked tollgate
# On a runner that shares this machine's test services (the shell runner on
# the workstation) the job takes the host resource slots (R85); on hosted
# runners, add --no-host-locks.
tollgate:
  stage: test
  script:
    - tollgate run --tier full --here --report junit
  artifacts:
    when: always
    paths:
      - {out}/
    reports:
      junit: {out}/junit.xml
"
    )
}

/// `tollgate ci-snippet --gitlab`.
pub fn ci_snippet_cmd() -> u8 {
    print!("{}", gitlab_snippet(crate::cli::HERE_OUT));
    crate::exit::OK
}

/// Text that XML 1.0 can hold: control characters other than tab and
/// newline (ANSI colors in logs) are dropped.
fn xml_text(s: &str) -> String {
    let kept: String = s
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect();
    escape(kept).into_owned()
}

/// The test suites inside the `<testsuites>` root of a JUnit file, as XML
/// text; `None` when the file cannot be read or parsed.
fn inner_suites(xml: &str) -> Option<String> {
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut writer = quick_xml::Writer::new(Vec::new());
    let mut depth = 0usize;
    loop {
        match reader.read_event().ok()? {
            Event::Eof => break,
            Event::Start(e) => {
                if depth >= 1 {
                    writer.write_event(Event::Start(e)).ok()?;
                }
                depth += 1;
            }
            Event::End(e) => {
                depth = depth.checked_sub(1)?;
                if depth >= 1 {
                    writer.write_event(Event::End(e)).ok()?;
                }
            }
            Event::Decl(_) | Event::DocType(_) | Event::PI(_) => {}
            other if depth >= 1 => writer.write_event(other).ok()?,
            _ => {}
        }
    }
    String::from_utf8(writer.into_inner()).ok()
}

/// `junit.xml` for a `run --here` report whose logs and nextest JUnit files
/// are in `out`.
#[must_use]
pub fn junit(report: &JobReport, out: &Path) -> String {
    let mut cases = String::new();
    let (mut failures, mut errors, mut skipped, mut total_ms) = (0, 0, 0, 0u64);
    for s in &report.steps {
        total_ms += s.duration_ms;
        let time = format!("{:.3}", s.duration_ms as f64 / 1000.0);
        let name = xml_text(&s.name);
        let mut detail: Vec<String> = Vec::new();
        detail.extend(
            s.failing
                .iter()
                .map(|f| format!("FAIL {} {} {}", f.package, f.binary_id, f.name)),
        );
        detail.extend(s.items.iter().map(|i| format!("- {i}")));
        detail.extend(s.rerun.iter().map(|r| format!("rerun: {r}")));
        detail.extend(s.tail.iter().cloned());
        let message = xml_text(s.message.as_deref().unwrap_or(""));
        let body = xml_text(&detail.join("\n"));
        let inner = match s.status {
            StepStatus::Pass => String::new(),
            StepStatus::Skipped => {
                skipped += 1;
                format!("<skipped message=\"{message}\"/>")
            }
            StepStatus::Fail => {
                failures += 1;
                format!("<failure message=\"{message}\">{body}</failure>")
            }
            StepStatus::Timeout | StepStatus::Error => {
                errors += 1;
                format!("<error message=\"{message}\">{body}</error>")
            }
        };
        cases.push_str(&format!(
            "    <testcase name=\"{name}\" classname=\"tollgate\" time=\"{time}\">{inner}</testcase>\n"
        ));
    }
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites name=\"tollgate\">\n  <testsuite name=\"tollgate\" tests=\"{}\" failures=\"{failures}\" errors=\"{errors}\" skipped=\"{skipped}\" time=\"{:.3}\">\n{cases}  </testsuite>\n",
        report.steps.len(),
        total_ms as f64 / 1000.0
    );
    for s in report
        .steps
        .iter()
        .filter(|s| s.kind == crate::config::repo::StepKind::Nextest)
    {
        let Some(log) = &s.log else { continue };
        let file = out.join(log.replace(".log", ".junit.xml"));
        if let Some(suites) = std::fs::read_to_string(&file)
            .ok()
            .and_then(|x| inner_suites(&x))
        {
            xml.push_str(&suites);
            xml.push('\n');
        }
    }
    xml.push_str("</testsuites>\n");
    xml
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::repo::StepKind;
    use crate::report::StepReport;

    #[test]
    fn snippet_runs_the_full_tier_and_publishes_junit_r73() {
        let s = gitlab_snippet("tollgate-report");
        assert!(s.contains("    - tollgate run --tier full --here --report junit\n"));
        assert!(s.contains("      junit: tollgate-report/junit.xml\n"));
        assert!(s.contains("    when: always\n"));
        assert!(
            s.lines()
                .filter(|l| !l.starts_with('#') && !l.is_empty())
                .all(|l| !l.contains('\t')),
            "YAML has no tabs"
        );
    }

    #[test]
    fn junit_has_a_case_per_step_and_the_nextest_suites_r47() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("tests.junit.xml"),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites name=\"nextest-run\" tests=\"1\">\n    <testsuite name=\"b\" tests=\"1\" failures=\"1\">\n        <testcase name=\"tests::fails\" classname=\"b\"><failure message=\"a &lt; b\">x</failure></testcase>\n    </testsuite>\n</testsuites>\n",
        )
        .unwrap();
        let step = |name: &str, kind, status| StepReport {
            status,
            log: Some(format!("{name}.log")),
            duration_ms: 1500,
            ..StepReport::skipped(name, kind, "")
        };
        let mut pytest = step("pytest", StepKind::PytestBaseline, StepStatus::Fail);
        pytest.message = Some("1 new failing test(s) <here>".into());
        pytest.items = vec!["t.py::a  [reproduced in isolation]".into()];
        let mut tsc = step("tsc", StepKind::Tsc, StepStatus::Error);
        tsc.tail = vec!["\u{1b}[31merror\u{1b}[0m".into()];
        let mut skip = step("biome", StepKind::Biome, StepStatus::Skipped);
        skip.message = Some("no change under its root".into());
        let report = JobReport {
            steps: vec![
                step("tests", StepKind::Nextest, StepStatus::Fail),
                pytest,
                tsc,
                skip,
            ],
            ..crate::report::tests::report()
        };
        let xml = junit(&report, tmp.path());
        assert!(xml.contains("<testsuite name=\"tollgate\" tests=\"4\" failures=\"2\" errors=\"1\" skipped=\"1\" time=\"6.000\">"), "{xml}");
        assert!(xml.contains("<failure message=\"1 new failing test(s) &lt;here&gt;\">- t.py::a  [reproduced in isolation]</failure>"), "{xml}");
        assert!(
            xml.contains("<error message=\"\">[31merror[0m</error>"),
            "{xml}"
        );
        assert!(xml.contains("<skipped message=\"no change under its root\"/>"));
        assert!(
            xml.contains("<testsuite name=\"b\" tests=\"1\" failures=\"1\">"),
            "{xml}"
        );
        assert!(
            xml.contains("<failure message=\"a &lt; b\">x</failure>"),
            "{xml}"
        );
        // The result parses as JUnit, with the nextest case found again.
        let cases = crate::steps::junit::parse(&xml).unwrap();
        assert!(cases.iter().any(|c| c.name == "tests::fails"));
        assert!(cases.iter().any(|c| c.name == "pytest"));
    }
}
