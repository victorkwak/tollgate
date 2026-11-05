//! Rust jobs end to end: real cargo, clippy, nextest and doctests on a
//! generated two-crate workspace (T30, T40, T41, R58, R72, R91-R93, L2).

mod support;

use std::path::Path;

use support::{Sandbox, Scratch, job_id};

fn host(sb: &Sandbox) {
    let counter = sb.root().join("flaky-counter");
    sb.host_config(&format!(
        "[verify]\nmin_free = \"1M\"\n[job.env]\nFLAKY_COUNTER = \"{}\"\n",
        counter.display()
    ));
}

fn step_status(report: &serde_json::Value, name: &str) -> String {
    report["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| panic!("no step {name} in {report}"))["status"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn failing_test_report_log_wait_and_flaky_t40_t41_r91_r92() {
    let sb = Sandbox::new();
    host(&sb);
    let repo = sb.rust_repo("ws", Scratch { failing: true });
    // A cargo config that points every build at one shared target dir must
    // not reach the verify checkout (R43).
    let shared = sb.root().join("shared-target");
    sb.commit_file(
        &repo,
        ".cargo/config.toml",
        &format!("[build]\ntarget-dir = \"{}\"\n", shared.display()),
        "shared target",
    );
    let r = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    let job = job_id(&r.out);
    for needle in [
        "FAIL b b tests::fails",
        "rerun: cargo nextest run -p b -E 'binary_id(=b) & (test(=tests::fails))'",
        "FLAKY a tests::flaky (passed on try 2)",
        &format!("tollgate log {job} tests"),
        &format!("tollgate report {job}"),
        "tollgate check --rerun",
    ] {
        assert!(r.out.contains(needle), "{needle:?} in\n{}", r.out);
    }
    assert!(r.out.lines().count() <= 82, "R91: {}", r.out);
    let report = sb.report(&job);
    assert_eq!(report["verdict"], "fail");
    for (step, want) in [
        ("fmt", "pass"),
        ("clippy", "pass"),
        ("tests", "fail"),
        ("doctests", "pass"),
    ] {
        assert_eq!(step_status(&report, step), want, "{report}");
    }
    assert!(
        sb.state()
            .join("jobs")
            .join(&job)
            .join("tests.junit.xml")
            .is_file(),
        "R82 JUnit kept"
    );
    assert!(
        !shared.exists(),
        "R43: the checkout builds in its own target/"
    );

    let log = sb.tollgate(&repo, &["log", &job, "tests"]);
    assert_eq!(log.code, Some(0));
    assert!(log.out.contains("tests::fails"), "{}", log.out);
    let tail = sb.tollgate(&repo, &["log", &job, "tests", "--tail", "1"]);
    assert_eq!(tail.out.lines().count(), 1, "{}", tail.out);

    let w = sb.tollgate(&repo, &["wait", &job]);
    assert_eq!(w.code, Some(1), "{}", w.out);
    assert!(w.out.contains("FAIL b b tests::fails"));

    let f = sb.tollgate(&repo, &["flaky"]);
    assert!(f.out.contains("a tests::flaky"), "{}", f.out);
    let a = sb.tollgate(&repo, &["audit"]);
    assert!(
        a.out.contains(&job) && a.out.contains(" fail "),
        "{}",
        a.out
    );
    let s = sb.tollgate(&repo, &["status"]);
    assert!(s.out.contains("fast fail"), "{}", s.out);
    let by_tree = sb.tollgate(&repo, &["report", "HEAD", "--json"]);
    assert_eq!(by_tree.code, Some(1));
    assert!(by_tree.out.contains(&job), "{}", by_tree.out);

    // CI mode in the agent checkout itself, with a JUnit report (R47).
    let here = sb.tollgate(
        &repo,
        &["run", "--tier", "full", "--here", "--report", "junit"],
    );
    assert_eq!(here.code, Some(1), "{}", here.out);
    assert!(here.out.contains("FAIL b b tests::fails"), "{}", here.out);
    let junit = std::fs::read_to_string(repo.join("tollgate-report/junit.xml")).unwrap();
    assert!(junit.contains("tests::fails"), "{junit}");
}

fn policy(quarantine: &str) -> String {
    format!(
        r#"version = 1
[[step]]
name = "fmt"
kind = "cargo-fmt"
[[step]]
name = "clippy"
kind = "cargo-clippy"
resources = ["cpu"]
[[step]]
name = "tests"
kind = "nextest"
resources = ["cpu"]
[[step]]
name = "doctests"
kind = "cargo-doctest"
{quarantine}"#
    )
}

fn quarantine(until: jiff::civil::Date) -> String {
    format!(
        "[[quarantine]]\ntest = \"a tests::flaky\"\nuntil = \"{until}\"\nissue = \"Issues/open/flaky\"\n"
    )
}

fn commit_policy(sb: &Sandbox, repo: &Path, text: &str, msg: &str) {
    sb.commit_file(repo, "tollgate.toml", text, msg);
}

#[test]
fn full_tier_flaky_quarantine_and_fast_selection_t41_t30_l2() {
    let sb = Sandbox::new();
    host(&sb);
    let repo = sb.rust_repo("ws", Scratch::default());
    commit_policy(&sb, &repo, &policy(""), "policy");

    // full: a flaky test fails the job (R93).
    let r = sb.tollgate(
        &repo,
        &["check", "--tier", "full", "--rev", "HEAD", "--wait"],
    );
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(
        r.out
            .contains("FLAKY a tests::flaky (passed on try 2); fails the full tier"),
        "{}",
        r.out
    );
    assert!(r.out.contains("FAIL a a tests::flaky"), "{}", r.out);

    // A valid quarantine from the policy commit turns it into QUARANTINED.
    let today = jiff::Zoned::now().date();
    let valid = today.checked_add(jiff::Span::new().days(10)).unwrap();
    commit_policy(&sb, &repo, &policy(&quarantine(valid)), "quarantine");
    let r = sb.tollgate(
        &repo,
        &["check", "--tier", "full", "--rev", "HEAD", "--wait"],
    );
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        r.out.contains(&format!(
            "QUARANTINED a tests::flaky until {valid} (Issues/open/flaky)"
        )),
        "{}",
        r.out
    );

    // fast selection relative to a checked base (R56): a change in `a`
    // selects only `a`; a change in `b` selects `b` and its dev-dependent
    // `a` (L6).
    std::fs::write(
        repo.join("crates/a/src/extra.rs"),
        "/// Extra.\npub fn extra() {}\n",
    )
    .unwrap();
    sb.git(&repo, &["add", "-A"]);
    let r = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let rep = sb.report(&job_id(&r.out));
    assert_eq!(
        rep["selection"]["subset"]["packages"],
        serde_json::json!(["a"]),
        "{rep}"
    );
    sb.git(&repo, &["reset", "-q", "--hard"]);
    std::fs::write(repo.join("crates/b/src/more.rs"), "").unwrap();
    sb.git(&repo, &["add", "-A"]);
    let r = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let rep = sb.report(&job_id(&r.out));
    assert_eq!(
        rep["selection"]["subset"]["packages"],
        serde_json::json!(["a", "b"]),
        "{rep}"
    );
    let cmd = rep["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "tests")
        .unwrap()["command"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        cmd.contains("-p a -p b -E '(rdeps(=b))'") && cmd.contains("--profile tollgate-fast"),
        "{cmd}"
    );
    sb.git(&repo, &["reset", "-q", "--hard"]);

    // Docs-only with cached workspace maps: the runner passes at once, with
    // no checkout and no cargo (R61, L19).
    std::fs::write(repo.join("NOTES.md"), "notes\n").unwrap();
    sb.git(&repo, &["add", "NOTES.md"]);
    let r = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let docs_job = job_id(&r.out);
    let log =
        std::fs::read_to_string(sb.state().join("jobs").join(&docs_job).join("job.log")).unwrap();
    assert!(log.contains("no checkout needed"), "{log}");
    sb.git(&repo, &["reset", "-q", "--hard"]);

    // An expired quarantine no longer applies.
    let expired = today.checked_sub(jiff::Span::new().days(1)).unwrap();
    commit_policy(&sb, &repo, &policy(&quarantine(expired)), "expired");
    let r = sb.tollgate(
        &repo,
        &["check", "--tier", "full", "--rev", "HEAD", "--wait"],
    );
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(!r.out.contains("QUARANTINED"), "{}", r.out);
    assert!(r.out.contains("FAIL a a tests::flaky"), "{}", r.out);

    // R64: a quarantine entry must name a listed test.
    let bogus =
        format!("[[quarantine]]\ntest = \"a tests::nope\"\nuntil = \"{valid}\"\nissue = \"i\"\n");
    commit_policy(&sb, &repo, &policy(&bogus), "bogus quarantine");
    let r = sb.tollgate(
        &repo,
        &["check", "--tier", "full", "--rev", "HEAD", "--wait"],
    );
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(
        r.out.contains("cause config") && r.out.contains("a tests::nope"),
        "{}",
        r.out
    );
    commit_policy(&sb, &repo, &policy(&quarantine(expired)), "expired again");

    // A branch that weakens the policy still gets main's (L2).
    sb.git(&repo, &["checkout", "-q", "-b", "feat"]);
    commit_policy(&sb, &repo, "version = 1\n", "weaken");
    let r = sb.tollgate(
        &repo,
        &["check", "--tier", "full", "--rev", "HEAD", "--wait"],
    );
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(
        r.out.contains("POLICY: this branch changes tollgate.toml"),
        "{}",
        r.out
    );
}

#[test]
fn a_branch_cargo_config_does_not_reach_the_steps_r71() {
    let sb = Sandbox::new();
    host(&sb);
    let repo = sb.rust_repo("ws", Scratch { failing: true });
    commit_policy(
        &sb,
        &repo,
        "version = 1\n[[step]]\nname = \"tests\"\nkind = \"nextest\"\n",
        "policy",
    );
    // A target runner of `true` makes every test binary "pass" (and list no
    // tests). The branch's own cargo config must not apply before it
    // merges (L2); the policy commit's (none here) does.
    sb.git(&repo, &["checkout", "-q", "-b", "feat"]);
    sb.commit_file(
        &repo,
        ".cargo/config.toml",
        "[target.'cfg(all())']\nrunner = \"true\"\n",
        "runner",
    );
    let r = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(r.out.contains("FAIL b b tests::fails"), "{}", r.out);
    assert!(
        r.out
            .contains("POLICY: this branch changes .cargo/config.toml"),
        "{}",
        r.out
    );
}

#[test]
fn a_record_covers_only_the_integration_tests_it_ran_r79_r80() {
    let sb = Sandbox::new();
    host(&sb);
    let repo = sb.rust_repo("ws", Scratch::default());
    // `a` dev-depends on `b` (like an api crate on its core crate).
    let four = |n: u32| {
        std::fs::write(
            repo.join("crates/b/src/four.rs"),
            format!("/// Four.\npub fn four() -> u32 {{\n    {n}\n}}\n"),
        )
        .unwrap();
    };
    let lib = std::fs::read_to_string(repo.join("crates/b/src/lib.rs")).unwrap();
    std::fs::write(
        repo.join("crates/b/src/lib.rs"),
        format!("mod four;\npub use four::four;\n{lib}"),
    )
    .unwrap();
    four(4);
    sb.git(&repo, &["add", "-A"]);
    sb.git(&repo, &["commit", "-q", "--no-verify", "-m", "four"]);
    commit_policy(
        &sb,
        &repo,
        "version = 1\n[select.fast]\ntests = \"rdeps-unit+changed-integration\"\n[[step]]\nname = \"tests\"\nkind = \"nextest\"\n",
        "policy",
    );
    let c0 = sb.git(&repo, &["rev-parse", "HEAD"]);
    let ok = |r: &support::Run| assert_eq!(r.code, Some(0), "{}", r.out);
    ok(&sb.tollgate(&repo, &["check", "--rev", "HEAD", "--wait"]));
    // Commit 1 changes `a` (its integration test runs and passes).
    sb.commit_file(
        &repo,
        "crates/a/tests/ait.rs",
        "#[test]\nfn four_is_four() {\n    assert_eq!(b::four(), 4);\n}\n",
        "a: integration test",
    );
    ok(&sb.tollgate(&repo, &["check", "--rev", "HEAD", "--wait"]));
    // Commit 2 changes only `b`: marked {b}, affected {a, b}; `a`'s
    // integration test does not run, and it would fail.
    four(5);
    sb.git(&repo, &["add", "-A"]);
    sb.git(
        &repo,
        &["commit", "-q", "--no-verify", "-m", "b: four is five"],
    );
    ok(&sb.tollgate(&repo, &["check", "--rev", "HEAD", "--wait"]));
    // Squashed onto c0, the same tree marks {a, b}: the record of the
    // narrower run must not answer; `a`'s integration test fails.
    sb.git(&repo, &["reset", "-q", "--soft", &c0]);
    let r = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(r.out.contains("FAIL a a::ait four_is_four"), "{}", r.out);
}

#[test]
fn quarantine_never_hides_a_test_that_fails_every_try_r93() {
    let sb = Sandbox::new();
    host(&sb);
    let repo = sb.rust_repo("ws", Scratch { failing: true });
    let valid = jiff::Zoned::now()
        .date()
        .checked_add(jiff::Span::new().days(10))
        .unwrap();
    commit_policy(
        &sb,
        &repo,
        &format!(
            "version = 1\n[[step]]\nname = \"tests\"\nkind = \"nextest\"\n[[quarantine]]\ntest = \"b tests::fails\"\nuntil = \"{valid}\"\nissue = \"i\"\n"
        ),
        "policy",
    );
    for tier in ["full", "fast"] {
        let r = sb.tollgate(&repo, &["check", "--tier", tier, "--rev", "HEAD", "--wait"]);
        assert_eq!(r.code, Some(1), "{tier}: {}", r.out);
        assert!(r.out.contains("FAIL b b tests::fails"), "{tier}: {}", r.out);
        assert!(!r.out.contains("QUARANTINED"), "{tier}: {}", r.out);
    }
}
