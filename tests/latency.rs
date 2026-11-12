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

use support::cpu::{CpuMeter, GUARD_BUDGET, Sample};
use support::{Armed, Sandbox, test_hooks_dir};

const PASS: &str = "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n";

/// A docs-only `pre-commit` (L19 budget 200 ms) waits for a job of a few
/// ms; item 41: the hook sees its end near its run time, not at the next
/// 100 ms poll (wall p95 before: 128 ms; after: 42 ms alone, 47-55 ms
/// during the whole parallel suite). Asserted on CPU time like every
/// budget here (measured 34 ms at load 14). On Linux this is tighter than
/// L19, so a hook that does more work fails well before the 200 ms
/// budget. On macOS it is 550 ms, about 2 times the worst CPU p95 measured
/// in 10 full-tier runs at load 18-72 (267.5 ms; earlier, 229 ms at load
/// 80-210): a hook that does twice its work fails, and Linux is still the
/// tight detector. `tollgate bench --enforce-budgets` checks docs-only on
/// macOS against 2000 ms of wall time with 6 commits at once, which
/// measures another thing (spec L19).
const DOCS_ONLY: Duration = per_os(90, 550);

/// [`DOCS_ONLY`] with detected Bun and Python roots (R65 detection runs on
/// the hook path; wall p95 before: 151 ms; after: 69 ms alone, 71-77 ms
/// during the whole suite). CPU measured: 49 ms at load 14. On macOS it
/// stays 1000 ms: worst CPU p95 in the same 10 full-tier runs, 408 ms.
const DOCS_ONLY_DETECTED: Duration = per_os(120, 1000);

/// L19 chained (non-gate) hook: 5 ms (macOS: 20 ms).
const CHAINED: Duration = per_os(5, 20);

/// L19 `pre-commit` on a cache hit: 200 ms (macOS: 800 ms).
const CACHE_HIT: Duration = per_os(200, 800);

/// `linux` ms, else `macos` ms on macOS (L19: budgets are per OS).
///
/// Starting a process costs much more CPU time on macOS. Measured
/// 2026-11-11 on an 8-core Apple Silicon Mac, per call: `/usr/bin/true`
/// 1.2 ms, Xcode's git 4.3 ms, the Command Line Tools' git 7.1 ms (the
/// `/usr/bin/git` xcrun shim 9.7-13.1 ms), the debug tollgate 3 ms. At load 8-10 a debug
/// chained hook's p95 was 5.4-5.5 ms and a pre-commit that makes 14 git
/// calls 220-490 ms. Under load (the gate runs the whole suite in
/// parallel; other sessions run iOS simulators) work moves to the
/// efficiency cores and the same work costs more CPU time: at load
/// 80-210, chained 7.8-10.7 ms, docs-only 229 ms, cache hit (full
/// index) 356-367 ms, cache hit (trusted remote) 393-413 ms, docs-only
/// with detected roots 467-539 ms; at load 550, docs-only with detected
/// roots 776 ms. Each macOS budget is about 1.3-3.5x the worst of those,
/// so a hook that does several times its work still fails. On macOS the
/// detached runner is not counted (no subreaper), so the macOS numbers
/// are the hook's own cost only.
const fn per_os(linux: u64, macos: u64) -> Duration {
    if cfg!(target_os = "macos") {
        Duration::from_millis(macos)
    } else {
        Duration::from_millis(linux)
    }
}

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

/// Two measures taken in the same rounds, run by run in turn (`a`, `b`,
/// `a`, `b`, ...), so a change of host load moves both alike.
#[derive(Debug, Clone, Copy)]
struct Paired {
    /// The best p95 of `a` over the rounds (as [`p95`]).
    a: P95,
    /// The best p95 of `b` over the rounds.
    b: P95,
    /// The lowest per-round ratio of the CPU p95s, `b / a`.
    ratio: f64,
}

/// [`Paired`] over `rounds` rounds of `runs` runs of each of `a` and `b`.
/// A ratio from separate bursts compares two host loads; a ratio inside
/// one round of runs in turn compares the two programs.
fn paired(
    meter: &CpuMeter,
    rounds: usize,
    runs: usize,
    mut a: impl FnMut(),
    mut b: impl FnMut(),
) -> Paired {
    let mut best: Option<Paired> = None;
    for _ in 0..rounds {
        let mut sa = Vec::with_capacity(runs);
        let mut sb = Vec::with_capacity(runs);
        for _ in 0..runs {
            sa.push(meter.measure(&mut a));
            sb.push(meter.measure(&mut b));
        }
        let (pa, pb) = (P95::of(&sa), P95::of(&sb));
        let ratio = pb.cpu.as_secs_f64() / pa.cpu.as_secs_f64();
        best = Some(match best {
            None => Paired {
                a: pa,
                b: pb,
                ratio,
            },
            Some(p) => Paired {
                a: if pa.cpu < p.a.cpu { pa } else { p.a },
                b: if pb.cpu < p.b.cpu { pb } else { p.b },
                ratio: ratio.min(p.ratio),
            },
        });
    }
    best.unwrap()
}

/// The env of a hook as on a real machine: the sandbox env and the
/// injection, with git's system config path from the tool cache.
fn hook_env(sb: &Sandbox) -> Vec<(String, String)> {
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
    cmd_env
}

/// Runs hook link `name` in `repo` with `env` alone; asserts it exits 0.
fn run_hook(env: &[(String, String)], repo: &Path, name: &str) -> std::process::Output {
    let mut cmd = std::process::Command::new(test_hooks_dir().join(name));
    cmd.env_clear()
        .current_dir(repo)
        .stdin(std::process::Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

#[test]
fn hook_latency_budgets_l19() {
    let meter = CpuMeter::new();
    let sb = Sandbox::new();
    sb.scoped_host("");
    let repo = repo_with(&sb, "r", PASS);
    // Chained hook with no repo hook: under 5 ms (L19).
    let cmd_env = hook_env(&sb);
    let hook = |name: &str| run_hook(&cmd_env, &repo, name);
    let chained = || {
        hook("post-checkout");
    };
    chained();
    let t = p95(&meter, 3, 40, chained);
    within_budget("chained hook (post-checkout)", t, CHAINED);
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
        CHAINED,
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
    within_budget("pre-commit cache hit", t, CACHE_HIT);

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

/// post-merge after a `git pull`, a fast-forward to the tip of a trusted
/// remote's ref: no gate hook ran, so no marker; the merge made no commit
/// and brought only what the trusted remote has, so item 17 has nothing
/// to record. Cheap checks only (item 37): the ref files, the host config
/// and one `git remote get-url`, no Gate::open. Same 5 ms budget as every
/// chained hook (L19), asserted in a release build: that one subprocess
/// costs about 1.5 ms of CPU from a debug hook, which itself starts in
/// about 2 ms, so a debug build measures 4.4-4.9 ms (release 2.6-2.8 ms)
/// and an absolute assert there would fail on a busy host. Every build
/// asserts that it costs well under the full check (post-merge after a
/// fast-forward to a local branch at a commit no gate checked, security
/// review note 1). Before that note any other ref at `HEAD` counted, with
/// no host config and no subprocess: release p95 cpu 1.1 ms, debug 2.4 ms.
#[test]
fn post_merge_after_a_trusted_fast_forward_stays_in_budget_l19_item37() {
    let meter = CpuMeter::new();
    let sb = Sandbox::new();
    sb.scoped_host(&format!(
        "trusted_paths = [\"{}\"]",
        sb.root().join("remotes/trusted.git").display()
    ));
    let repo = repo_with(&sb, "r", PASS);
    let bare = sb.root().join("remotes/trusted.git");
    std::fs::create_dir_all(&bare).unwrap();
    sb.git(&bare, &["init", "-q", "--bare"]);
    sb.git(&repo, &["remote", "add", "origin", bare.to_str().unwrap()]);
    sb.git(&repo, &["push", "-q", "origin", "main"]);
    sb.git(&repo, &["checkout", "-q", "-b", "up"]);
    sb.commit_file(&repo, "ff.txt", "1\n", "ff");
    sb.git(&repo, &["push", "-q", "origin", "up"]);
    sb.git(&repo, &["checkout", "-q", "main"]);
    sb.git(&repo, &["branch", "-q", "-D", "up"]);
    sb.git(&repo, &["merge", "-q", "--ff-only", "origin/up"]);
    // The full check in a clone of the same remote: a fast-forward to a
    // local branch at a commit no gate checked (Gate::open, which records
    // the commit). Both states exist at once, so their runs alternate.
    let local = sb.root().join("local");
    sb.git(
        &sb.root(),
        &[
            "clone",
            "-q",
            bare.to_str().unwrap(),
            local.to_str().unwrap(),
        ],
    );
    sb.git(&local, &["checkout", "-q", "-b", "side"]);
    let side = sb.commit_file(&local, "s.txt", "1\n", "side");
    sb.git(&local, &["checkout", "-q", "main"]);
    sb.git(&local, &["merge", "-q", "--ff-only", "side"]);
    let env = hook_env(&sb);
    let Paired {
        a: full,
        b: fast,
        ratio,
    } = paired(
        &meter,
        3,
        20,
        || {
            let out = run_hook(&env, &local, "post-merge");
            assert!(
                String::from_utf8_lossy(&out.stderr).contains(&side[..12]),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        },
        || {
            let out = run_hook(&env, &repo, "post-merge");
            assert!(
                out.stderr.is_empty(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        },
    );
    {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr().lock(),
            "L19 post-merge full check (local fast-forward, records): p95 cpu {:.2} ms, wall {:.2} ms (no budget); trusted fast-forward / full: {ratio:.2}",
            full.cpu.as_secs_f64() * 1000.0,
            full.wall.as_secs_f64() * 1000.0
        );
    }
    assert!(
        ratio < 0.5,
        "the trusted fast-forward ({fast:?}) does not skip the full check ({full:?}): best round ratio {ratio:.2}"
    );
    if cfg!(debug_assertions) {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr().lock(),
            "L19 chained hook (post-merge after a trusted fast-forward): p95 cpu {:.2} ms, wall {:.2} ms (debug build: 5 ms asserted in release)",
            fast.cpu.as_secs_f64() * 1000.0,
            fast.wall.as_secs_f64() * 1000.0
        );
    } else {
        within_budget(
            "chained hook (post-merge after a trusted fast-forward)",
            fast,
            CHAINED,
        );
    }
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
    within_budget("guard", t, GUARD_BUDGET);

    // A deny has more work than an allow: the keyed hash of the command
    // for the metrics log (item 50), which reads `metrics.key`.
    let deny = serde_json::json!({
        "cwd": a.sb.root(),
        "tool_name": "Bash",
        "tool_input": {"command": "git commit --no-verify -m x"},
    })
    .to_string();
    let denied = || {
        let (code, _, err) = a.guard_raw(&deny, &[]);
        assert_eq!(code, Some(2), "{err}");
    };
    denied();
    let key = a.sb.state().join("metrics.key");
    assert!(key.is_file(), "the first deny creates the key");
    let t = p95(&meter, 3, 200, denied);
    within_budget("guard deny", t, GUARD_BUDGET);

    // The first deny also creates the key: random bytes from /dev/urandom,
    // a 0600 file and a hard link into place.
    let mut best: Option<P95> = None;
    for _ in 0..3 {
        let t: Vec<Sample> = (0..50)
            .map(|_| {
                std::fs::remove_file(&key).unwrap();
                let s = meter.measure(denied);
                assert!(key.is_file());
                s
            })
            .collect();
        let p = P95::of(&t);
        if best.is_none_or(|b| p.cpu < b.cpu) {
            best = Some(p);
        }
    }
    within_budget(
        "guard deny that creates metrics.key",
        best.unwrap(),
        GUARD_BUDGET,
    );
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
    within_budget("guard on push and fetch targets", t, GUARD_BUDGET);
}

/// R26, `unclassified` case 5: the words of a program the guard does not
/// know are read once as a command, from the first one that names git,
/// tollgate or a shell; the guard stays in budget, also for 100 shell
/// words and for 100 unknown programs in a row (a walk per word would be
/// quadratic or worse in their number).
#[test]
fn the_guard_walks_words_of_unknown_programs_in_under_10_ms_l19_item21_20() {
    let meter = CpuMeter::new();
    let a = Armed::new();
    let many = format!("frobnicate {}-c 'echo 1'", "sh ".repeat(100));
    let chain = format!("{}git commit -n -m x", "frobnicate ".repeat(100));
    for (what, command, code) in [
        (
            "guard on words of unknown programs",
            "cargo test bash -- --nocapture && frobnicate sh -c 'git status && echo hi' && pytest -k sh tests/ && prlimit -n4096 cargo build".to_owned(),
            Some(0),
        ),
        ("guard on 100 shell words", many, Some(0)),
        ("guard on 100 unknown programs", chain, Some(0)),
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
        within_budget(what, t, GUARD_BUDGET);
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
    within_budget("pre-commit cache hit (trusted remote)", t, CACHE_HIT);
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
    within_budget("pre-commit cache hit (no remote, full index)", t, CACHE_HIT);
}

/// A 100 KB heredoc costs the guard about what reading the command costs
/// (the same heredoc fed to `cat` next to a git command). Interpreter
/// code is data: a python program is allowed next to git and alone, and
/// the guard does not scan its text, so both stay within 1.6x of `cat`,
/// and a release build answers in the guard's 10 ms budget. A debug
/// build reads any 100 KB command, `cat`'s too, in tens of ms, so there
/// only the ratio holds. `cat` and python run in turn in each round, so
/// host load moves both alike, and the best round's ratio counts.
#[test]
fn large_python_heredocs_cost_little_more_than_reading_them_l19() {
    let meter = CpuMeter::new();
    let a = Armed::new();
    let input = |head: &str, body: &str, tail: &str| {
        serde_json::json!({
            "cwd": a.sb.root(),
            "tool_name": "Bash",
            "tool_input": {"command": format!("{head} <<'EOF'\n{body}EOF{tail}")},
        })
        .to_string()
    };
    // Every case is allowed.
    let run = |input: &str| {
        let (got, out, err) = a.guard_raw(input, &[]);
        assert_eq!(got, Some(0), "{out}{err}");
    };
    for (what, line) in [
        (
            "code lines",
            "total = sum(x * 2 for x in range(10))  # Doubles: a.B\n",
        ),
        ("dotted words", "a.\n"),
    ] {
        let body = line.repeat(100 * 1024 / line.len());
        let cat = input("cat", &body, "\ngit status");
        for (case, tail) in [("next to git", "\ngit status"), ("no git", "")] {
            let python = input("python3 -", &body, tail);
            let Paired {
                a: cat_p95,
                b: python_p95,
                ratio,
            } = paired(&meter, 3, 30, || run(&cat), || run(&python));
            let what = format!("guard, 100 KB python heredoc of {what}, {case} ({ratio:.2}x cat)");
            if cfg!(debug_assertions) {
                use std::io::Write as _;
                let _ = writeln!(
                    std::io::stderr().lock(),
                    "L19 {what}: p95 cpu {:.2} ms (debug build: ratio asserted)",
                    python_p95.cpu.as_secs_f64() * 1000.0
                );
            } else {
                within_budget(&what, python_p95, GUARD_BUDGET);
            }
            assert!(
                ratio < 1.6,
                "{what}: python {python_p95:?}, cat {cat_p95:?}"
            );
        }
    }
}
