//! L19 latency budgets, in a test binary of their own so the other suites'
//! parallel tests do not load the machine while they are measured.

mod support;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use support::{Sandbox, test_hooks_dir};

const PASS: &str = "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n";

fn repo_with(sb: &Sandbox, name: &str, toml: &str) -> PathBuf {
    let repo = sb.repo(name);
    sb.commit_file(&repo, "tollgate.toml", toml, "policy");
    repo
}

fn stage(sb: &Sandbox, repo: &Path, path: &str, content: &str) {
    std::fs::write(repo.join(path), content).unwrap();
    sb.git(repo, &["add", path]);
}

/// p95 of `runs` timings of `f`; the best of three rounds, so a busy
/// moment of the parallel test run does not fail the budget.
fn p95(rounds: usize, runs: usize, mut f: impl FnMut()) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..rounds {
        let mut t: Vec<Duration> = (0..runs)
            .map(|_| {
                let s = Instant::now();
                f();
                s.elapsed()
            })
            .collect();
        t.sort();
        best = best.min(t[(runs * 95 / 100).min(runs - 1)]);
    }
    best
}

#[test]
fn hook_latency_budgets_l19() {
    let sb = Sandbox::new();
    sb.scoped_host("");
    let repo = repo_with(&sb, "r", PASS);
    // Chained hook with no repo hook: under 5 ms (L19). The env as on a
    // real machine: git's system config path comes from the tool cache.
    let mut sys_env = sb.env();
    sys_env.remove("GIT_CONFIG_NOSYSTEM");
    let mut cmd_env: Vec<(String, String)> = sys_env
        .iter()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.to_string_lossy().into_owned(),
            )
        })
        .collect();
    cmd_env.extend(
        sb.injection()
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_string_lossy().into_owned())),
    );
    let chained = || {
        let mut cmd = std::process::Command::new(test_hooks_dir().join("post-commit"));
        cmd.env_clear()
            .current_dir(&repo)
            .stdin(std::process::Stdio::null());
        for (k, v) in &cmd_env {
            cmd.env(k, v);
        }
        assert!(cmd.status().unwrap().success());
    };
    chained();
    let t = p95(3, 40, chained);
    assert!(
        t < Duration::from_millis(5),
        "chained hook p95 {t:?} (L19: 5 ms)"
    );

    // pre-commit on a cache hit: under 200 ms.
    stage(&sb, &repo, "a.txt", "1\n");
    assert_eq!(sb.hooked(&repo, &["commit", "-m", "a"]).code, Some(0));
    stage(&sb, &repo, "b.txt", "1\n");
    let first = sb.run_hook(&repo, "pre-commit", &[]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let t = p95(3, 10, || {
        let o = sb.run_hook(&repo, "pre-commit", &[]);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    });
    assert!(
        t < Duration::from_millis(200),
        "pre-commit cache hit p95 {t:?} (L19: 200 ms)"
    );

    // pre-commit on a docs-only tree: under 200 ms, a new tree each time.
    assert_eq!(sb.hooked(&repo, &["commit", "-m", "b"]).code, Some(0));
    let mut n = 0;
    let t = p95(3, 5, || {
        n += 1;
        std::fs::write(repo.join("NOTES.md"), format!("note {n}\n")).unwrap();
        sb.git(&repo, &["add", "NOTES.md"]);
        let o = sb.run_hook(&repo, "pre-commit", &[]);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    });
    assert!(
        t < Duration::from_millis(200),
        "docs-only pre-commit p95 {t:?} (L19: 200 ms)"
    );
}
