//! L19 latency budgets, asserted on CPU time: user + system time of the
//! hook and of every process it starts, the detached runner included on
//! Linux (`support::cpu`). Wall-clock time depends on how busy the host is,
//! and a gate verdict must depend on the tree only. This work is
//! sequential, so its CPU time is a lower bound of its wall-clock time: a
//! CPU time over the budget is a breach on any host. The wall-clock p95 is
//! printed next to it; `tollgate bench --enforce-budgets` (L20) asserts it
//! under real concurrent commits.

mod support;

use std::path::{Path, PathBuf};
use std::time::Duration;

use support::cpu::{CpuMeter, Sample};
use support::{Armed, Sandbox, test_hooks_dir};

const PASS: &str = "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n";

/// A docs-only `pre-commit` (L19 budget 200 ms) waits for a job of a few
/// ms; item 41: the hook sees its end near its run time, not at the next
/// 100 ms poll (wall p95 before: 128 ms; after: 42 ms alone, 47-55 ms
/// during the whole parallel suite). Asserted on CPU time like every
/// budget here (measured 34 ms at load 14): tighter than L19, so a hook
/// that does more work fails well before the 200 ms budget.
const DOCS_ONLY: Duration = Duration::from_millis(90);

/// [`DOCS_ONLY`] with detected Bun and Python roots (R65 detection runs on
/// the hook path; wall p95 before: 151 ms; after: 69 ms alone, 71-77 ms
/// during the whole suite). CPU measured: 49 ms at load 14.
const DOCS_ONLY_DETECTED: Duration = Duration::from_millis(120);

fn repo_with(sb: &Sandbox, name: &str, toml: &str) -> PathBuf {
    let repo = sb.repo(name);
    sb.commit_file(&repo, "tollgate.toml", toml, "policy");
    repo
}

fn stage(sb: &Sandbox, repo: &Path, path: &str, content: &str) {
    std::fs::write(repo.join(path), content).unwrap();
    sb.git(repo, &["add", path]);
}

/// p95 of the wall and CPU times of some samples (nearest rank).
#[derive(Debug, Clone, Copy)]
struct P95 {
    wall: Duration,
    cpu: Duration,
}

impl P95 {
    fn of(samples: &[Sample]) -> Self {
        let rank = |mut v: Vec<Duration>| {
            v.sort();
            v[(v.len() * 95 / 100).min(v.len() - 1)]
        };
        Self {
            wall: rank(samples.iter().map(|s| s.wall).collect()),
            cpu: rank(samples.iter().map(|s| s.cpu).collect()),
        }
    }
}

/// Prints the measured p95 (CPU and wall) next to its L19 budget, then
/// asserts the CPU p95. The line goes to the process's stderr, past the
/// test harness's capture, so every `cargo test` run shows the numbers.
fn within_budget(what: &str, p: P95, budget: Duration) {
    use std::io::Write as _;
    let _ = writeln!(
        std::io::stderr().lock(),
        "L19 {what}: p95 cpu {:.2} ms, wall {:.2} ms (budget {} ms, asserted on cpu)",
        p.cpu.as_secs_f64() * 1000.0,
        p.wall.as_secs_f64() * 1000.0,
        budget.as_millis()
    );
    assert!(
        p.cpu < budget,
        "{what}: p95 CPU time {:?} (L19: {budget:?}; wall {:?})",
        p.cpu,
        p.wall
    );
}

/// p95 of `runs` measurements of `f`: the round with the lowest CPU p95 of
/// `rounds`, so one round with cold caches does not fail the budget.
fn p95(meter: &CpuMeter, rounds: usize, runs: usize, mut f: impl FnMut()) -> P95 {
    let mut best: Option<P95> = None;
    for _ in 0..rounds {
        let t: Vec<Sample> = (0..runs).map(|_| meter.measure(&mut f)).collect();
        let p = P95::of(&t);
        if best.is_none_or(|b| p.cpu < b.cpu) {
            best = Some(p);
        }
    }
    best.unwrap()
}

#[test]
fn hook_latency_budgets_l19() {
    let meter = CpuMeter::new();
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
    let hook = |name: &str| {
        let mut cmd = std::process::Command::new(test_hooks_dir().join(name));
        cmd.env_clear()
            .current_dir(&repo)
            .stdin(std::process::Stdio::null());
        for (k, v) in &cmd_env {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    };
    let chained = || {
        hook("post-checkout");
    };
    chained();
    let t = p95(&meter, 3, 40, chained);
    within_budget("chained hook (post-checkout)", t, Duration::from_millis(5));
    // post-commit after a gate hook of the same git process allowed the
    // commit (item 17): it takes the marker, no subprocess, same budget.
    // The test process stands in for that git process.
    let dirs = tollgate::dirs::Dirs::from_env(&sb.env()).unwrap();
    let me = i32::try_from(std::process::id()).unwrap();
    let mut best: Option<P95> = None;
    for _ in 0..3 {
        let t: Vec<Sample> = (0..40)
            .map(|_| {
                tollgate::hook::unverified::mark_gate_run_of(&dirs, me);
                let mut out = None;
                let s = meter.measure(|| out = Some(hook("post-commit")));
                let out = out.unwrap();
                assert!(
                    out.stderr.is_empty(),
                    "{}",
                    String::from_utf8_lossy(&out.stderr)
                );
                s
            })
            .collect();
        let p = P95::of(&t);
        if best.is_none_or(|b| p.cpu < b.cpu) {
            best = Some(p);
        }
    }
    within_budget(
        "chained hook (post-commit, gate marker)",
        best.unwrap(),
        Duration::from_millis(5),
    );

    // post-merge after a fast-forward (a `git pull`): no gate hook ran, so
    // no marker; the new HEAD is the tip of another ref, so the merge made
    // no commit and item 17 has nothing to record. Cheap checks only, no
    // Gate::open (item 37), same budget.
    sb.git(&repo, &["checkout", "-q", "-b", "ff"]);
    sb.commit_file(&repo, "ff.txt", "1\n", "ff");
    sb.git(&repo, &["checkout", "-q", "main"]);
    sb.git(&repo, &["merge", "-q", "--ff-only", "ff"]);
    let t = p95(&meter, 3, 40, || {
        let out = hook("post-merge");
        assert!(
            out.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    });
    within_budget(
        "chained hook (post-merge after a fast-forward)",
        t,
        Duration::from_millis(5),
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
    let t = p95(&meter, 3, 10, || {
        let o = sb.run_hook(&repo, "pre-commit", &[]);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    });
    within_budget("pre-commit cache hit", t, Duration::from_millis(200));

    // pre-commit on a docs-only tree: under 200 ms, a new tree each time.
    assert_eq!(sb.hooked(&repo, &["commit", "-m", "b"]).code, Some(0));
    let mut n = 0;
    let t = p95(&meter, 3, 5, || {
        n += 1;
        std::fs::write(repo.join("NOTES.md"), format!("note {n}\n")).unwrap();
        sb.git(&repo, &["add", "NOTES.md"]);
        let o = sb.run_hook(&repo, "pre-commit", &[]);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    });
    within_budget("pre-commit docs-only", t, DOCS_ONLY);
}

#[test]
fn the_guard_answers_in_under_10_ms_l19() {
    let meter = CpuMeter::new();
    let a = Armed::new();
    let input = serde_json::json!({
        "cwd": a.sb.root(),
        "tool_name": "Bash",
        "tool_input": {"command": "cd r && git commit -m 'msg' && git push origin feat"},
    })
    .to_string();
    let t = p95(&meter, 3, 200, || {
        let (code, _, err) = a.guard_raw(&input, &[]);
        assert_eq!(code, Some(0), "{err}");
    });
    within_budget("guard", t, Duration::from_millis(10));
}

/// Item 22, secreview note 7: a push or fetch whose refspecs can move an
/// anchor reads the repo's config files and resolves the repository
/// argument (no subprocess); the guard stays in budget.
#[test]
fn the_guard_reads_push_and_fetch_targets_in_under_10_ms_l19_item22() {
    let meter = CpuMeter::new();
    let a = Armed::new();
    let repo = a.sb.repo("r");
    a.sb.git(
        &repo,
        &["remote", "add", "origin", "git@gitlab.com:v/r.git"],
    );
    a.sb.git(&repo, &["config", "url.git@gitlab.com:.insteadOf", "gl:"]);
    let input = serde_json::json!({
        "cwd": repo,
        "tool_name": "Bash",
        "tool_input": {"command": "git push origin main && git push && git fetch origin main:main && git push . HEAD:feat && git pull gl:v/r main"},
    })
    .to_string();
    let t = p95(&meter, 3, 200, || {
        let (code, _, err) = a.guard_raw(&input, &[]);
        assert_eq!(code, Some(0), "{err}");
    });
    within_budget(
        "guard on push and fetch targets",
        t,
        Duration::from_millis(10),
    );
}

/// Item 21/20 (review G2): shell, interpreter and wrapper words of a
/// program the guard does not know are walked as the command it may run
/// (a `PATH` lookup for a script name, once per word list, at most 4
/// programs deep); the guard stays in budget, also for 100 such words
/// (a walk per word would be exponential in their number).
#[test]
fn the_guard_walks_words_of_unknown_programs_in_under_10_ms_l19_item21_20() {
    let meter = CpuMeter::new();
    let a = Armed::new();
    let many = format!("frobnicate {}-c 'print(1)'", "python3 ".repeat(100));
    for (what, command, code) in [
        (
            "guard on words of unknown programs",
            "cargo test bash -- --nocapture && frobnicate sh -c 'git status && echo hi' && pytest -k sh tests/ && prlimit -n4096 cargo build".to_owned(),
            Some(0),
        ),
        ("guard on 100 interpreter words", many, Some(2)),
    ] {
        let input = serde_json::json!({
            "cwd": a.sb.root(),
            "tool_name": "Bash",
            "tool_input": {"command": command},
        })
        .to_string();
        let t = p95(&meter, 3, 100, || {
            let (c, _, err) = a.guard_raw(&input, &[]);
            assert_eq!(c, code, "{err}");
        });
        within_budget(what, t, Duration::from_millis(10));
    }
}

/// Detection runs on the `pre-commit` path when the policy commit has no
/// `tollgate.toml` (one `git cat-file` per TypeScript root, R65). A
/// docs-only commit next to detected Bun and Python roots stays in the
/// docs-only budget (L19, R61).
#[test]
fn docs_only_pre_commit_with_detected_roots_stays_in_budget_l19_r61_r65() {
    let meter = CpuMeter::new();
    let sb = Sandbox::new();
    sb.scoped_host(&format!(
        "trusted_paths = [\"{}\"]",
        sb.root().join("remotes/trusted.git").display()
    ));
    let repo = sb.repo("r");
    for (path, text) in [
        (
            "web/package.json",
            "{\"name\":\"web\",\"scripts\":{\"test\":\"bun test\"}}\n",
        ),
        ("web/bun.lock", "{}\n"),
        ("py/pyproject.toml", "[project]\nname = \"py\"\n"),
        ("py/uv.lock", "version = 1\n"),
    ] {
        std::fs::create_dir_all(repo.join(path).parent().unwrap()).unwrap();
        std::fs::write(repo.join(path), text).unwrap();
    }
    sb.git(&repo, &["add", "-A"]);
    sb.git(&repo, &["commit", "-q", "-m", "roots"]);
    // A trusted remote has the base, so selection is on (R56); the server
    // confirms the fetched value once, then the record of its answer does.
    let url = sb.root().join("remotes/trusted.git");
    sb.git(&sb.root(), &["init", "-q", "--bare", url.to_str().unwrap()]);
    sb.git(&repo, &["remote", "add", "origin", url.to_str().unwrap()]);
    sb.git(&repo, &["push", "-q", "origin", "main"]);
    sb.git(&repo, &["fetch", "-q", "origin"]);
    let effective = sb.tollgate(&repo, &["config", "--effective"]);
    for step in ["web bun test", "py pytest"] {
        assert!(effective.out.contains(step), "{step:?}: {}", effective.out);
    }
    let mut n = 0;
    let t = p95(&meter, 3, 5, || {
        n += 1;
        std::fs::write(repo.join("NOTES.md"), format!("note {n}\n")).unwrap();
        sb.git(&repo, &["add", "NOTES.md"]);
        let o = sb.run_hook(&repo, "pre-commit", &[]);
        let err = String::from_utf8_lossy(&o.stderr);
        assert!(o.status.success(), "{err}");
        assert!(err.contains("tollgate: pass pre-commit"), "{err}");
    });
    within_budget(
        "pre-commit docs-only (detected Bun and Python roots)",
        t,
        DOCS_ONLY_DETECTED,
    );
    // Each run was docs-only: no job ran a step.
    let jobs = sb.jobs();
    assert_eq!(jobs.len(), 15, "one job per run: {jobs:?}");
    for job in jobs {
        let report = sb.report(&job);
        assert_eq!(report["verdict"], "pass", "{report}");
        assert!(
            report["steps"]
                .as_array()
                .unwrap()
                .iter()
                .all(|s| s["status"] == "skipped"),
            "{report}"
        );
    }
}

/// Item 33: with a trusted remote, every `Gate::open` reads the record of
/// the repo's trusted remotes (one small file; a lock and a write only
/// when a remote is new). A `pre-commit` cache hit stays in its budget.
#[test]
fn pre_commit_cache_hit_with_a_trusted_remote_l19_item33() {
    let meter = CpuMeter::new();
    let sb = Sandbox::new();
    let url = sb.root().join("remotes/trusted.git");
    sb.scoped_host(&format!("trusted_paths = [\"{}\"]", url.display()));
    let repo = repo_with(&sb, "r", PASS);
    sb.git(&sb.root(), &["init", "-q", "--bare", url.to_str().unwrap()]);
    sb.git(&repo, &["remote", "add", "origin", url.to_str().unwrap()]);
    sb.git(&repo, &["push", "-q", "origin", "main"]);
    sb.git(&repo, &["fetch", "-q", "origin"]);
    stage(&sb, &repo, "a.txt", "1\n");
    let first = sb.run_hook(&repo, "pre-commit", &[]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(sb.state().join("trusted-remotes").is_dir());
    let t = p95(&meter, 3, 20, || {
        let o = sb.run_hook(&repo, "pre-commit", &[]);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    });
    within_budget(
        "pre-commit cache hit (trusted remote)",
        t,
        Duration::from_millis(200),
    );
}

/// Item 33, secreview note 2: a repo with no recorded trusted remote is
/// looked up in the index of repos that had one (one `git cat-file` of
/// their root commits) on every `Gate::open`, to tell a copy or a move.
/// With 300 indexed repos of 2 roots each, a `pre-commit` cache hit of a
/// repo with no remote stays in its budget.
#[test]
fn pre_commit_cache_hit_with_a_full_remote_index_l19_item33() {
    let meter = CpuMeter::new();
    let sb = Sandbox::new();
    sb.scoped_host("");
    let repo = repo_with(&sb, "r", PASS);
    stage(&sb, &repo, "a.txt", "1\n");
    let run = || {
        let o = sb.run_hook(&repo, "pre-commit", &[]);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    };
    run();
    let empty = p95(&meter, 3, 20, run);
    let dir = sb.state().join("trusted-remotes");
    std::fs::create_dir_all(&dir).unwrap();
    let mut repos = serde_json::Map::new();
    for i in 0..300u32 {
        let commits: Vec<String> = (0..2u32)
            .map(|j| format!("{:040x}", i * 2 + j + 1))
            .collect();
        repos.insert(
            format!("{i:016x}"),
            serde_json::json!({"dir": format!("/r/{i}"), "commits": commits}),
        );
    }
    std::fs::write(
        dir.join("index.json"),
        serde_json::json!({"version": 1, "repos": repos}).to_string(),
    )
    .unwrap();
    let t = p95(&meter, 3, 20, run);
    eprintln!(
        "  index of 300 repos adds {:?} p95 cpu",
        t.cpu.saturating_sub(empty.cpu)
    );
    within_budget(
        "pre-commit cache hit (no remote, full index)",
        t,
        Duration::from_millis(200),
    );
}
