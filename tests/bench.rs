//! `tollgate bench` (L20) end to end: the real binary clones a generated
//! workspace into its own scratch dir, commits concurrently from N
//! worktrees through the real hooks with its own state and host config,
//! reports latency, queue wait, reuse, cache hits and load, and leaves no
//! worktree, job or process behind.

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use support::{BIN, Sandbox, eventually, write_exe};

/// Runs `tollgate bench` with the sandbox env; returns (exit, stdout,
/// stderr).
fn bench(sb: &Sandbox, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(BIN);
    cmd.env_clear()
        .current_dir(sb.root())
        .arg("bench")
        .args(args)
        .stdin(Stdio::null());
    for (k, v) in sb.env().iter() {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A scratch parent on the binary's file system, so the bench hard-links
/// its hook binary instead of copying it.
fn scratch_parent() -> tempfile::TempDir {
    tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap()
}

/// A repo whose `tollgate.toml` has a `core` step (takes `cpu`) and an
/// `api` step (takes `cpu` and `pg`), each reading only its own dir, plus
/// a docs dir.
fn workspace(sb: &Sandbox, extra_steps: &str) -> PathBuf {
    let repo = sb.repo("src-repo");
    let toml = format!(
        "version = 1\n\
         [[step]]\nname = \"core\"\nkind = \"command\"\nresources = [\"cpu\"]\ninputs = [\"core/**\"]\nrun = \"sleep 0.3\"\n\
         [[step]]\nname = \"api\"\nkind = \"command\"\nresources = [\"cpu\", \"pg\"]\ninputs = [\"api/**\"]\nrun = \"true\"\n\
         {extra_steps}"
    );
    for (path, text) in [
        ("tollgate.toml", toml.as_str()),
        ("core/lib.sh", "core\n"),
        ("api/handler.sh", "api\n"),
        ("docs/guide.md", "# Guide\n"),
    ] {
        let p = repo.join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }
    sb.git(&repo, &["add", "-A"]);
    sb.git(&repo, &["commit", "-q", "--no-verify", "-m", "workspace"]);
    repo
}

/// What must not change in the source repo.
fn repo_state(sb: &Sandbox, repo: &Path) -> String {
    [
        sb.git(repo, &["worktree", "list", "--porcelain"]),
        sb.git(repo, &["for-each-ref"]),
        sb.git(repo, &["status", "--porcelain", "--ignored"]),
        sb.git(repo, &["rev-parse", "HEAD"]),
    ]
    .join("\n")
}

/// Processes whose environment names the bench's state dir (Linux): its
/// runners. Killed here so a failing test leaves none behind.
fn bench_processes(scratch: &str) -> usize {
    let marker = format!("XDG_STATE_HOME={scratch}/state");
    let Ok(table) = tollgate::procs::ProcTable::snapshot() else {
        return 0;
    };
    let found = tollgate::procs::marked(&table, marker.as_bytes());
    for pid in &found {
        let _ = tollgate::procs::signal(*pid, libc::SIGKILL);
    }
    found.len()
}

fn attempt<'a>(report: &'a serde_json::Value, scenario: &str, kind: &str) -> &'a serde_json::Value {
    report["attempts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["scenario"] == scenario && a["kind"] == kind)
        .unwrap_or_else(|| panic!("no {kind} attempt of {scenario}: {report:#}"))
}

#[test]
fn bench_replays_concurrent_commits_through_the_hooks_l20() {
    let sb = Sandbox::new();
    let repo = workspace(&sb, "");
    let before = repo_state(&sb, &repo);
    let scenarios = sb.root().join("scenarios.toml");
    std::fs::write(
        &scenarios,
        r##"
[[scenario]]
name = "core"
worktrees = 1
edit = [{ path = "core/lib.sh", append = "change {worktree}.{round} of {scenario}\n" }]

[[scenario]]
name = "api"
worktrees = 1
retries = 1
edit = [{ path = "api/handler.sh", append = "change {worktree}.{round}\n" }]

[[scenario]]
name = "docs"
worktrees = 1
edit = [{ path = "docs/guide.md", write = "# Guide {worktree}\n" }]
"##,
    )
    .unwrap();
    // No Postgres runs here and the shared containers are off limits: a
    // stand-in psql prints a connection count per call (3, 7, 3, ...) and
    // logs its arguments.
    let psql = sb.root().join("bin/psql");
    let psql_log = sb.root().join("psql.log");
    write_exe(
        &psql,
        &format!(
            "#!/bin/sh\necho \"$@\" >> '{log}'\nn=$(cat '{log}.n' 2>/dev/null || echo 0)\nn=$((n + 1))\necho $n > '{log}.n'\nif [ $n -eq 2 ]; then echo 7; else echo 3; fi\n",
            log = psql_log.display()
        ),
    );
    let parent = scratch_parent();
    let out_file = sb.root().join("bench.json");
    let url = "postgres://bench@127.0.0.1:1/bench";
    let (code, stdout, stderr) = bench(
        &sb,
        &[
            repo.to_str().unwrap(),
            "--scenarios",
            scenarios.to_str().unwrap(),
            "--worktrees",
            "3",
            "--cpu",
            "1",
            "--pg",
            "1",
            "--pg-max-threads",
            "4",
            "--min-free",
            "1M",
            "--scratch",
            parent.path().to_str().unwrap(),
            "--pg-url",
            url,
            "--psql",
            psql.to_str().unwrap(),
            "--sample-ms",
            "50",
            "--out",
            out_file.to_str().unwrap(),
            "--enforce-budgets",
        ],
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&out_file).unwrap_or_default()).unwrap_or_default();
    let scratch = report["scratch"].as_str().unwrap_or_default().to_owned();
    let leftover = if scratch.is_empty() {
        0
    } else {
        bench_processes(&scratch)
    };
    // --enforce-budgets: exit 1 exactly when a measured wall-clock budget
    // is over (L19). Whether one is over depends on the host's load, so the
    // test checks that the exit code and the message follow the report.
    let over: Vec<&str> = report["budgets"]
        .as_array()
        .map(|bs| {
            bs.iter()
                .filter(|b| b["ok"] == false)
                .filter_map(|b| b["name"].as_str())
                .collect()
        })
        .unwrap_or_default();
    if over.is_empty() {
        assert_eq!(code, Some(0), "{stdout}\n{stderr}");
        assert!(!stderr.contains("budget(s) over"), "{stderr}");
    } else {
        assert_eq!(code, Some(1), "{stdout}\n{stderr}");
        let line = format!("tollgate bench: L19 budget(s) over: {}", over.join(", "));
        assert!(stderr.contains(&line), "{line:?} in:\n{stderr}");
    }
    assert_eq!(leftover, 0, "bench processes left running");

    // Text on stdout.
    for needle in [
        "tollgate bench: 3 worktrees",
        "pre-commit, hook start to allow",
        "p50",
        "p95",
        "queue wait",
        "step reuse",
        "cache hits: 1 of 4",
        "postgres: peak 7",
    ] {
        assert!(stdout.contains(needle), "{needle:?} in:\n{stdout}");
    }

    // One commit per worktree plus the retry, each through the gate.
    assert_eq!(report["worktrees"], 3, "{report:#}");
    assert_eq!(report["rounds"], 1, "{report:#}");
    let attempts = report["attempts"].as_array().unwrap();
    assert_eq!(attempts.len(), 4, "{report:#}");
    for a in attempts {
        assert_eq!(a["exit"], 0, "{a:#}");
        let hook = a["hook_ms"].as_f64().expect("hook_ms");
        let wall = a["wall_ms"].as_f64().unwrap();
        assert!(hook > 0.0 && hook <= wall, "{a:#}");
        assert!(a["hooks"]["post-commit"].as_f64().is_some(), "{a:#}");
    }
    assert_eq!(attempt(&report, "core", "commit")["outcome"], "job");
    assert_eq!(attempt(&report, "api", "commit")["outcome"], "job");
    let retry = attempt(&report, "api", "retry");
    assert_eq!(retry["outcome"], "hit", "{retry:#}");
    assert_eq!(retry["job"], attempt(&report, "api", "commit")["job"]);
    let docs = attempt(&report, "docs", "commit");
    assert_eq!(docs["outcome"], "job", "{docs:#}");
    assert_eq!(docs["docs_only"], true, "{docs:#}");

    // Latency: hook start to allow, from git's own trace of the hook.
    let pre = &report["latency"]["pre_commit"];
    assert_eq!(pre["all"]["n"], 4, "{pre:#}");
    let (p50, p95, max) = (
        pre["all"]["p50_ms"].as_f64().unwrap(),
        pre["all"]["p95_ms"].as_f64().unwrap(),
        pre["all"]["max_ms"].as_f64().unwrap(),
    );
    assert!(0.0 < p50 && p50 <= p95 && p95 <= max, "{pre:#}");
    assert_eq!(pre["hit"]["n"], 1, "{pre:#}");
    assert_eq!(pre["docs_only"]["n"], 1, "{pre:#}");
    assert_eq!(pre["by_scenario"]["api"]["n"], 2, "{pre:#}");
    assert_eq!(report["latency"]["hooks"]["post-commit"]["n"], 4);
    assert_eq!(report["latency"]["commit_wall"]["n"], 4);

    // Jobs: the warm-up of HEAD, then one per new tree; all pass.
    let jobs = report["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 4, "{report:#}");
    let warm: Vec<_> = jobs.iter().filter(|j| j["warm"] == true).collect();
    assert_eq!(warm.len(), 1, "{report:#}");
    assert_eq!(report["warm"]["job"], warm[0]["id"], "{report:#}");
    assert!(jobs.iter().all(|j| j["verdict"] == "pass"), "{report:#}");

    // Queue wait per resource: each step that ran took its slots once.
    let queue = &report["queue_wait"];
    assert_eq!(queue["cpu"]["n"], 2, "{queue:#}");
    assert_eq!(queue["pg"]["n"], 1, "{queue:#}");
    assert!(queue["cpu"]["max_ms"].as_f64().is_some(), "{queue:#}");
    // The docs-only job needs no checkout.
    assert_eq!(report["checkout_wait"]["n"], 2, "{report:#}");
    assert_eq!(report["job_overhead"]["n"], 3, "{report:#}");

    // Step reuse (L16): each code change reuses the other step's pass
    // from the warm-up job.
    assert_eq!(report["reuse"]["steps_reused"], 2, "{report:#}");
    assert_eq!(report["reuse"]["steps_run"], 2, "{report:#}");
    for j in jobs.iter().filter(|j| j["warm"] == false) {
        for s in j["steps"].as_array().unwrap() {
            if let Some(from) = s.get("reused_from") {
                assert_eq!(from, &warm[0]["id"], "{j:#}");
            }
        }
    }
    assert_eq!(report["cache_hits"], 1, "{report:#}");

    // Samples.
    let cpu = report["cpu"]["samples"].as_array().unwrap();
    assert!(!cpu.is_empty(), "{report:#}");
    assert!(cpu.iter().all(|s| s["load1"].as_f64().unwrap() >= 0.0));
    assert_eq!(report["postgres"]["peak"], 7, "{report:#}");
    let args = std::fs::read_to_string(&psql_log).unwrap();
    assert!(args.lines().count() >= 2, "{args}");
    assert!(
        args.contains(url) && args.contains("pg_stat_activity"),
        "{args}"
    );

    // Clean up: nothing left running, scratch gone, source untouched, and
    // the caller's own state dir never used.
    assert_eq!(report["cleanup"]["cancelled"], serde_json::json!([]));
    assert_eq!(report["scratch_removed"], true, "{report:#}");
    assert!(!Path::new(&scratch).exists(), "{scratch}");
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
    assert_eq!(repo_state(&sb, &repo), before);
    assert!(
        !sb.state().exists(),
        "the bench used the caller's state dir"
    );
}

#[test]
fn bench_cancels_the_jobs_it_leaves_running_and_removes_its_scratch_l20() {
    let sb = Sandbox::new();
    let pid_file = sb.root().join("slow.pid");
    let repo = workspace(
        &sb,
        &format!(
            "[[step]]\nname = \"slow\"\nkind = \"command\"\nrun = \"test -e slow/go || exit 0; echo $$ > '{}'; exec sleep 30\"\n",
            pid_file.display()
        ),
    );
    let scenarios = sb.root().join("scenarios.toml");
    std::fs::write(
        &scenarios,
        "[[scenario]]\nname = \"slow\"\nworktrees = 1\nedit = [{ path = \"slow/go\", write = \"go\\n\" }]\n",
    )
    .unwrap();
    let parent = scratch_parent();
    let out_file = sb.root().join("bench.json");
    let (code, stdout, stderr) = bench(
        &sb,
        &[
            repo.to_str().unwrap(),
            "--scenarios",
            scenarios.to_str().unwrap(),
            "--no-warm",
            // The hook denies at this cap and cleanup then cancels the job.
            // The step must have started by then: at load 70 the runner
            // took more than 1 s to reach it, so the cap leaves 10 s.
            "--inline-cap",
            "10",
            "--min-free",
            "1M",
            "--scratch",
            parent.path().to_str().unwrap(),
            "--out",
            out_file.to_str().unwrap(),
        ],
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&out_file).unwrap_or_default()).unwrap_or_default();
    let scratch = report["scratch"].as_str().unwrap_or_default().to_owned();
    let leftover = if scratch.is_empty() {
        0
    } else {
        bench_processes(&scratch)
    };
    let step_pid: Option<i32> = std::fs::read_to_string(&pid_file)
        .ok()
        .and_then(|t| t.trim().parse().ok());
    if let Some(pid) = step_pid {
        let gone = eventually(10, || {
            !tollgate::procs::ProcTable::snapshot().unwrap().alive(pid)
        });
        if !gone {
            let _ = tollgate::procs::signal(pid, libc::SIGKILL);
        }
        assert!(gone, "the slow step outlived the bench");
    }
    assert_eq!(code, Some(0), "{stdout}\n{stderr}");
    assert_eq!(leftover, 0, "bench processes left running");
    assert!(step_pid.is_some(), "the slow step never ran: {report:#}");

    // The hook denied at the inline budget; the job was still running.
    let a = attempt(&report, "slow", "commit");
    assert_eq!(a["outcome"], "running", "{a:#}");
    assert_ne!(a["exit"], 0, "{a:#}");
    assert!(stdout.contains("denied: 1"), "{stdout}");
    // Cleanup cancelled it and removed every worktree with the scratch dir.
    assert_eq!(
        report["cleanup"]["cancelled"],
        serde_json::json!([a["job"].clone()]),
        "{report:#}"
    );
    assert_eq!(report["cleanup"]["leftover"], serde_json::json!([]));
    assert_eq!(report["scratch_removed"], true, "{report:#}");
    assert!(!Path::new(&scratch).exists(), "{scratch}");
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[test]
fn bench_refuses_bad_scenarios_before_it_creates_anything_l20() {
    let sb = Sandbox::new();
    let repo = workspace(&sb, "");
    let parent = scratch_parent();
    let run = |text: &str, n: &str| {
        let scenarios = sb.root().join("bad.toml");
        std::fs::write(&scenarios, text).unwrap();
        bench(
            &sb,
            &[
                repo.to_str().unwrap(),
                "--scenarios",
                scenarios.to_str().unwrap(),
                "--worktrees",
                n,
                "--scratch",
                parent.path().to_str().unwrap(),
            ],
        )
    };
    let one =
        "[[scenario]]\nname = \"a\"\nworktrees = 2\nedit = [{ path = \"x\", append = \"1\" }]\n";
    let (code, _, err) = run(one, "3");
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("3") && err.contains("2 worktrees"), "{err}");
    for (bad, why) in [
        ("../x", "path"),
        ("/etc/x", "path"),
        (".git/config", "path"),
    ] {
        let text = format!(
            "[[scenario]]\nname = \"a\"\nworktrees = 1\nedit = [{{ path = \"{bad}\", append = \"1\" }}]\n"
        );
        let (code, _, err) = run(&text, "1");
        assert_eq!(code, Some(2), "{bad}: {err}");
        assert!(err.contains(why), "{bad}: {err}");
    }
    let (code, _, err) = run(
        "[[scenario]]\nname = \"a\"\nworktrees = 1\nedit = [{ path = \"x\", append = \"1\", write = \"2\" }]\n",
        "1",
    );
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("exactly one of append, write"), "{err}");
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
    // A scratch dir inside the source repo would write it.
    let scenarios = sb.root().join("ok.toml");
    std::fs::write(&scenarios, one).unwrap();
    let (code, _, err) = bench(
        &sb,
        &[
            repo.to_str().unwrap(),
            "--scenarios",
            scenarios.to_str().unwrap(),
            "--scratch",
            repo.join("core").to_str().unwrap(),
        ],
    );
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("inside the source repo"), "{err}");
    assert_eq!(sb.git(&repo, &["status", "--porcelain", "--ignored"]), "");
    assert!(!sb.state().exists());
}

#[test]
fn a_signal_stops_the_bench_and_it_still_cleans_up_l20() {
    let sb = Sandbox::new();
    let pid_file = sb.root().join("slow.pid");
    let repo = workspace(
        &sb,
        &format!(
            "[[step]]\nname = \"slow\"\nkind = \"command\"\nrun = \"test -e slow/go || exit 0; echo $$ > '{}'; exec sleep 30\"\n",
            pid_file.display()
        ),
    );
    let scenarios = sb.root().join("scenarios.toml");
    std::fs::write(
        &scenarios,
        "[[scenario]]\nname = \"slow\"\nworktrees = 1\nedit = [{ path = \"slow/go\", write = \"go\\n\" }]\n",
    )
    .unwrap();
    let parent = scratch_parent();
    let out_file = sb.root().join("bench.json");
    // The default inline budget (100 s): the commit waits on the job.
    let mut cmd = Command::new(BIN);
    cmd.env_clear()
        .current_dir(sb.root())
        .args(["bench", repo.to_str().unwrap(), "--scenarios"])
        .arg(&scenarios)
        .args(["--no-warm", "--min-free", "1M", "--scratch"])
        .arg(parent.path())
        .arg("--out")
        .arg(&out_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (k, v) in sb.env().iter() {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let started = eventually(20, || pid_file.exists());
    let pid = i32::try_from(child.id()).unwrap();
    tollgate::procs::signal(pid, libc::SIGTERM).unwrap();
    let mut status = None;
    let exited = eventually(20, || {
        status = child.try_wait().unwrap();
        status.is_some()
    });
    if !exited {
        let _ = child.kill();
        let _ = child.wait();
    }
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&out_file).unwrap_or_default()).unwrap_or_default();
    let scratch = report["scratch"].as_str().unwrap_or_default().to_owned();
    let leftover = if scratch.is_empty() {
        0
    } else {
        bench_processes(&scratch)
    };
    let step_pid: Option<i32> = std::fs::read_to_string(&pid_file)
        .ok()
        .and_then(|t| t.trim().parse().ok());
    let step_gone = step_pid.is_none_or(|p| {
        let gone = eventually(10, || {
            !tollgate::procs::ProcTable::snapshot().unwrap().alive(p)
        });
        if !gone {
            let _ = tollgate::procs::signal(p, libc::SIGKILL);
        }
        gone
    });
    assert!(started, "the slow step never started");
    assert!(exited, "the bench did not stop on SIGTERM");
    assert_eq!(status.unwrap().code(), Some(1), "{report:#}");
    assert!(step_gone, "the slow step outlived the bench");
    assert_eq!(leftover, 0, "bench processes left running");
    assert_eq!(report["interrupted"], true, "{report:#}");
    assert_eq!(report["cleanup"]["cancelled"].as_array().unwrap().len(), 1);
    assert_eq!(report["cleanup"]["leftover"], serde_json::json!([]));
    assert_eq!(report["scratch_removed"], true, "{report:#}");
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
}
