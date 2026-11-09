//! Item 50: the local metrics log and `tollgate stats`. Guard decisions
//! and gate hook outcomes are logged without the command text; a broken
//! log never changes a guard answer or a hook verdict.

mod support;

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::Value;
use support::{Armed, Sandbox, job_id};

fn events(state: &Path) -> Vec<Value> {
    let text = std::fs::read_to_string(state.join("metrics.jsonl")).unwrap_or_default();
    text.lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}")))
        .collect()
}

fn of_kind(all: &[Value], kind: &str) -> Vec<Value> {
    all.iter().filter(|e| e["kind"] == kind).cloned().collect()
}

#[test]
fn guard_decisions_are_logged_with_a_keyed_hash_not_the_text() {
    let a = Armed::new();
    assert_eq!(a.bash("ls /tmp/s3cr3t-token-value").0, Some(0));
    let secret = "git commit --no-verify -m s3cr3t-token-value";
    assert_eq!(a.bash(secret).0, Some(2));
    assert_eq!(a.bash(secret).0, Some(2));
    assert_eq!(a.bash("git commit --no-verify -m other").0, Some(2));
    let (code, out, _) = a.bash("git -c url.a.insteadOf=b fetch");
    assert_eq!(code, Some(0));
    assert!(out.contains("\"ask\""), "{out}");
    let (code, out, _) = a.bash("cd r && git commit -m x");
    assert_eq!(code, Some(0));
    assert!(out.contains("updatedInput"), "{out}");
    let (code, out, _) = a.write(".git/config");
    assert_eq!(code, Some(0));
    assert!(out.contains("\"ask\""), "{out}");

    let state = a.sb.state();
    let log = state.join("metrics.jsonl");
    let mode = std::fs::metadata(&log).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{mode:o}");
    let key = state.join("metrics.key");
    let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{mode:o}");
    let text = std::fs::read_to_string(&log).unwrap();
    for raw in [
        "s3cr3t",
        "other",
        "no-verify -m",
        "insteadOf",
        ".git/config",
    ] {
        assert!(!text.contains(raw), "{raw} in the log:\n{text}");
    }
    let g = of_kind(&events(&state), "guard");
    let got: Vec<(&str, &str, Option<&str>)> = g
        .iter()
        .map(|e| {
            (
                e["tool"].as_str().unwrap(),
                e["decision"].as_str().unwrap(),
                e["rule"].as_str(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            ("Bash", "allow", None),
            ("Bash", "deny", Some("no-verify")),
            ("Bash", "deny", Some("no-verify")),
            ("Bash", "deny", Some("no-verify")),
            ("Bash", "ask", Some("git-c-url")),
            ("Bash", "allow", None),
            ("Write", "ask", Some("git-dir-write")),
        ],
        "{g:#?}"
    );
    assert_eq!(g[5]["rewrite"], true, "{:?}", g[5]);
    // Asks and denies carry the hash: same text, same hash; other text,
    // other hash; 16 hex digits. Allows carry none.
    for i in [0, 5] {
        assert!(g[i]["cmd"].is_null(), "{:?}", g[i]);
    }
    let h: Vec<&str> = [1, 2, 3, 4, 6]
        .iter()
        .map(|&i| g[i]["cmd"].as_str().unwrap())
        .collect();
    assert_eq!(h[0], h[1]);
    assert_ne!(h[0], h[2]);
    assert!(
        h.iter()
            .all(|x| x.len() == 16 && x.bytes().all(|b| b.is_ascii_hexdigit()))
    );
    assert!(g.iter().all(|e| e["us"].as_u64().is_some_and(|us| us > 0)));

    // stats: denies by rule.
    let r = a.sb.tollgate(&a.sb.root(), &["stats", "--json"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let v: Value = serde_json::from_str(&r.out).unwrap();
    assert_eq!(v["guard"]["calls"], 7, "{v:#}");
    assert_eq!(v["guard"]["deny"], 3, "{v:#}");
    assert_eq!(v["guard"]["ask"], 2, "{v:#}");
    assert_eq!(v["guard"]["rewrite"], 1, "{v:#}");
    assert_eq!(v["guard"]["rules"]["no-verify"]["deny"], 3, "{v:#}");
    assert_eq!(v["guard"]["rules"]["no-verify"]["distinct"], 2, "{v:#}");
    assert_eq!(v["guard"]["rules"]["git-c-url"]["ask"], 1, "{v:#}");
    let r = a.sb.tollgate(&a.sb.root(), &["stats"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(r.out.contains("no-verify"), "{}", r.out);
}

/// What sits at the log path in place of a file.
fn plant(state: &Path, what: &str) -> PathBuf {
    let log = state.join("metrics.jsonl");
    let _ = std::fs::remove_file(&log);
    let _ = std::fs::remove_dir_all(&log);
    match what {
        "dir" => std::fs::create_dir_all(&log).unwrap(),
        "fifo" => {
            let st = std::process::Command::new("mkfifo")
                .arg(&log)
                .status()
                .unwrap();
            assert!(st.success());
        }
        "symlink" => {
            let target = state.join("../elsewhere.txt");
            std::fs::write(&target, "keep\n").unwrap();
            std::os::unix::fs::symlink(&target, &log).unwrap();
            return target;
        }
        _ => unreachable!(),
    }
    log
}

#[test]
fn a_broken_log_never_changes_or_stalls_a_guard_answer() {
    let a = Armed::new();
    let state = a.sb.state();
    for what in ["dir", "fifo", "symlink"] {
        let planted = plant(&state, what);
        let start = Instant::now();
        let (code, out, err) = a.bash("ls -la");
        assert_eq!(
            (code, out.as_str(), err.as_str()),
            (Some(0), "", ""),
            "{what}"
        );
        let (code, _, err) = a.bash("git commit --no-verify -m x");
        assert_eq!(code, Some(2), "{what}: {err}");
        assert!(err.starts_with("tollgate guard: denied:"), "{what}: {err}");
        assert!(start.elapsed() < Duration::from_secs(5), "{what} stalled");
        if what == "symlink" {
            assert_eq!(std::fs::read_to_string(&planted).unwrap(), "keep\n");
        }
    }
    // A key file that is not a key: no hash, never the text, never a deny.
    let _ = std::fs::remove_file(state.join("metrics.jsonl"));
    std::fs::write(state.join("metrics.key"), b"short").unwrap();
    assert_eq!(a.bash("git commit --no-verify -m s3cr3t").0, Some(2));
    let text = std::fs::read_to_string(state.join("metrics.jsonl")).unwrap();
    assert!(!text.contains("s3cr3t"), "{text}");
    let g = of_kind(&events(&state), "guard");
    assert_eq!(g.len(), 1, "{g:?}");
    assert!(g[0]["cmd"].is_null(), "{:?}", g[0]);
}

#[test]
fn hook_outcomes_and_job_times_reach_stats() {
    let sb = Sandbox::new();
    sb.scoped_host("");
    let repo = sb.repo("r");
    sb.commit_file(
        &repo,
        "tollgate.toml",
        "version = 1\n[[step]]\nname = \"slow\"\nkind = \"command\"\nrun = \"sleep 2; test ! -f bad\"\n",
        "policy",
    );
    std::fs::write(repo.join("a.txt"), "1\n").unwrap();
    sb.git(&repo, &["add", "a.txt"]);
    // Refused at the inline cap, then the job ends, then a cache hit.
    let r = sb.hooked_with(
        &repo,
        &["commit", "-m", "a"],
        &[("TOLLGATE_INLINE_CAP", "1")],
    );
    assert_eq!(r.code, Some(1), "{}", r.out);
    let job = job_id(&r.out);
    let w = sb.tollgate(&repo, &["wait", &job, "--timeout", "30s"]);
    assert_eq!(w.code, Some(0), "{}", w.out);
    let r = sb.hooked(&repo, &["commit", "-m", "a"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    // The same tree again: a hit with real cache value.
    let r = sb.hooked(&repo, &["commit", "--amend", "--no-edit"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    // A failing tree: a job that fails inline, then a stored fail.
    std::fs::write(repo.join("bad"), "x\n").unwrap();
    sb.git(&repo, &["add", "bad"]);
    let r = sb.hooked(&repo, &["commit", "-m", "bad"]);
    assert_eq!(r.code, Some(1), "{}", r.out);

    let all = events(&sb.state());
    let hooks = of_kind(&all, "hook");
    let outcomes: Vec<&str> = hooks
        .iter()
        .map(|e| e["outcome"].as_str().unwrap())
        .collect();
    assert_eq!(
        outcomes,
        ["refused_cap", "cache_hit", "cache_hit", "failed"],
        "{hooks:#?}"
    );
    assert!(
        hooks
            .iter()
            .all(|e| e["repo"] == "r" && e["tier"] == "fast")
    );
    assert_eq!(hooks[0]["job"], job.as_str());
    assert_eq!(hooks[0]["hook"], "pre-commit");
    let jobs = of_kind(&all, "job");
    assert_eq!(jobs.len(), 2, "{jobs:#?}");
    assert_eq!(jobs[0]["job"], job.as_str());
    assert_eq!(jobs[0]["verdict"], "pass");
    assert_eq!(jobs[0]["by"], "hook");
    assert!(
        jobs[0]["wall_ms"].as_u64().unwrap() >= 2000,
        "{:?}",
        jobs[0]
    );
    assert_eq!(jobs[1]["verdict"], "fail");

    let r = sb.tollgate(&repo, &["stats", "--json"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let v: Value = serde_json::from_str(&r.out).unwrap();
    let row = v["repos"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["repo"] == "r" && x["tier"] == "fast")
        .unwrap_or_else(|| panic!("{v:#}"))
        .clone();
    // The wait-and-retry is the refused commit's second check, not a
    // cache hit: only the amend counts as one.
    assert_eq!(row["checks"], 3, "{row:#}");
    assert_eq!(row["cap_refusals"], 1, "{row:#}");
    assert_eq!(row["cap_retries"], 1, "{row:#}");
    assert_eq!(row["cache_hits"], 1, "{row:#}");
    assert_eq!(row["failed"], 1, "{row:#}");
    assert_eq!(row["jobs"], 2, "{row:#}");
    assert!(row["wall_ms"]["p50"].as_u64().unwrap() >= 2000, "{row:#}");
    assert!(row["queue_ms"]["p90"].as_u64().is_some(), "{row:#}");
    // The refused commit's job ended about a second after the refusal.
    let after = row["refusal_wait_ms"]["p50"].as_u64().unwrap();
    assert!((100..30_000).contains(&after), "{row:#}");
    let r = sb.tollgate(&repo, &["stats"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(r.out.contains("fast"), "{}", r.out);
}

#[test]
fn hook_time_is_sampled_once_per_hook_run() {
    // A pre-push of three refs is one wait for Victor: three checks in
    // the outcome counts, one sample in `hook_ms`.
    let sb = Sandbox::new();
    sb.scoped_host("remotes = [\"*/remotes/trusted*\"]");
    let repo = sb.repo("r");
    sb.commit_file(
        &repo,
        "tollgate.toml",
        "version = 1\n[push]\nfast_refs = [\"*\"]\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n",
        "policy",
    );
    let bare = sb.root().join("remotes/trusted.git");
    std::fs::create_dir_all(&bare).unwrap();
    sb.git(&bare, &["init", "-q", "--bare"]);
    sb.git(&repo, &["remote", "add", "origin", bare.to_str().unwrap()]);
    sb.git(&repo, &["push", "-q", "origin", "main"]);
    sb.git(&repo, &["fetch", "-q", "origin"]);
    sb.git(&repo, &["checkout", "-q", "-b", "a"]);
    std::fs::write(repo.join("a.txt"), "1\n").unwrap();
    sb.git(&repo, &["add", "a.txt"]);
    let r = sb.hooked(&repo, &["commit", "-m", "a"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    sb.git(&repo, &["branch", "b"]);
    sb.git(&repo, &["branch", "c"]);
    let r = sb.hooked(&repo, &["push", "-q", "origin", "a", "b", "c"]);
    assert_eq!(r.code, Some(0), "{}", r.out);

    let hooks = of_kind(&events(&sb.state()), "hook");
    let runs: Vec<(&str, &str)> = hooks
        .iter()
        .map(|e| (e["hook"].as_str().unwrap(), e["run"].as_str().unwrap()))
        .collect();
    assert_eq!(runs.len(), 4, "{hooks:#?}");
    assert_eq!(runs[0].0, "pre-commit");
    assert!(runs[1..].iter().all(|r| *r == runs[1]), "{hooks:#?}");
    assert_ne!(runs[0].1, runs[1].1, "{hooks:#?}");

    let r = sb.tollgate(&repo, &["stats", "--json"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let v: Value = serde_json::from_str(&r.out).unwrap();
    let row = &v["repos"][0];
    assert_eq!(row["checks"], 4, "{v:#}");
    assert_eq!(row["hook_ms"]["n"], 2, "{v:#}");
}

#[test]
fn stats_since_leaves_out_older_events() {
    let sb = Sandbox::new();
    let state = sb.state();
    std::fs::create_dir_all(&state).unwrap();
    let ts = |ago_days: i64| -> String {
        let t = jiff::Timestamp::now() - jiff::SignedDuration::from_hours(24 * ago_days);
        t.to_string()
    };
    let line = |ago: i64, rule: &str| {
        format!(
            "{{\"kind\":\"guard\",\"t\":\"{}\",\"tool\":\"Bash\",\"decision\":\"deny\",\"rule\":\"{rule}\",\"rewrite\":false,\"us\":900,\"cmd\":null}}\n",
            ts(ago)
        )
    };
    let text = format!(
        "{}not json\n{}{}",
        line(30, "old-rule"),
        line(1, "new-rule"),
        line(0, "new-rule")
    );
    std::fs::write(state.join("metrics.jsonl"), text).unwrap();
    let r = sb.tollgate(&sb.root(), &["stats", "--json"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let v: Value = serde_json::from_str(&r.out).unwrap();
    assert_eq!(v["guard"]["deny"], 3, "{v:#}");
    let r = sb.tollgate(&sb.root(), &["stats", "--json", "--since", "7d"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let v: Value = serde_json::from_str(&r.out).unwrap();
    assert_eq!(v["guard"]["deny"], 2, "{v:#}");
    assert_eq!(v["guard"]["rules"]["new-rule"]["deny"], 2, "{v:#}");
    assert!(v["guard"]["rules"].get("old-rule").is_none(), "{v:#}");
    let r = sb.tollgate(&sb.root(), &["stats", "--since", "bogus"]);
    assert_ne!(r.code, Some(0), "{}", r.out);
}

#[test]
fn stats_skips_rotated_paths_that_are_not_regular_files() {
    // A dir or a symlink at a rotated name used to fail `stats` outright,
    // and rotation never clears it. Such a path is skipped with a warning;
    // a symlink is still never followed.
    let sb = Sandbox::new();
    let state = sb.state();
    std::fs::create_dir_all(&state).unwrap();
    let line = |rule: &str| {
        format!(
            "{{\"kind\":\"guard\",\"t\":\"{}\",\"tool\":\"Bash\",\"decision\":\"deny\",\"rule\":\"{rule}\",\"rewrite\":false,\"us\":900,\"cmd\":null}}\n",
            jiff::Timestamp::now()
        )
    };
    std::fs::write(state.join("metrics.jsonl"), line("live")).unwrap();
    std::fs::write(state.join("metrics.jsonl.1"), line("rotated")).unwrap();
    std::fs::create_dir(state.join("metrics.jsonl.2")).unwrap();
    let elsewhere = sb.root().join("elsewhere.jsonl");
    std::fs::write(&elsewhere, line("followed")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, state.join("metrics.jsonl.3")).unwrap();
    let r = sb.tollgate(&sb.root(), &["stats", "--json"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let v: Value = serde_json::Deserializer::from_str(&r.out)
        .into_iter::<Value>()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(v["guard"]["deny"], 2, "{v:#}");
    assert!(v["guard"]["rules"].get("followed").is_none(), "{v:#}");
    assert!(r.out.contains("metrics.jsonl.2: skipped"), "{}", r.out);
    assert!(r.out.contains("metrics.jsonl.3: skipped"), "{}", r.out);
    let r = sb.tollgate(&sb.root(), &["stats"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
}

#[test]
fn a_refusal_whose_runner_died_is_closed_by_the_lost_job_line() {
    // A job lost to a dead runner ends without the runner's own `job`
    // line; the reap writes one, so its refusal does not stay open.
    let sb = Sandbox::new();
    sb.scoped_host("");
    let repo = sb.repo("r");
    sb.commit_file(
        &repo,
        "tollgate.toml",
        "version = 1\n[[step]]\nname = \"slow\"\nkind = \"command\"\nrun = \"sleep 30\"\n",
        "policy",
    );
    std::fs::write(repo.join("a.txt"), "1\n").unwrap();
    sb.git(&repo, &["add", "a.txt"]);
    let r = sb.hooked_with(
        &repo,
        &["commit", "-m", "a"],
        &[("TOLLGATE_INLINE_CAP", "1")],
    );
    assert_eq!(r.code, Some(1), "{}", r.out);
    let job = job_id(&r.out);
    let pid_file = sb.state().join("jobs").join(&job).join("runner.pid");
    let pid = || -> Option<i32> {
        std::fs::read_to_string(&pid_file)
            .ok()
            .and_then(|t| t.trim().parse().ok())
    };
    assert!(support::eventually(20, || pid().is_some()));
    tollgate::procs::signal(pid().unwrap(), libc::SIGKILL).unwrap();
    let w = sb.tollgate(&repo, &["wait", &job, "--timeout", "20s"]);
    assert_eq!(w.code, Some(1), "{}", w.out);
    assert!(
        w.out.contains("lost") || w.out.contains("runner is gone"),
        "{}",
        w.out
    );

    let jobs = of_kind(&events(&sb.state()), "job");
    assert_eq!(jobs.len(), 1, "{jobs:#?}");
    assert_eq!(jobs[0]["job"], job.as_str());
    assert_eq!(jobs[0]["verdict"], "lost");
    assert_eq!(jobs[0]["repo"], "r");
    assert_eq!(jobs[0]["tier"], "fast");
    assert_eq!(jobs[0]["by"], "hook");

    let r = sb.tollgate(&repo, &["stats", "--json"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let v: Value = serde_json::from_str(&r.out).unwrap();
    let row = v["repos"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["repo"] == "r" && x["tier"] == "fast")
        .unwrap_or_else(|| panic!("{v:#}"))
        .clone();
    assert_eq!(row["cap_refusals"], 1, "{row:#}");
    assert_eq!(row["cap_refusals_open"], 0, "{row:#}");
    // Closed by the lost line, but its time is the reap's (here the
    // `tollgate wait`), not the runner's death: no wait sample.
    assert_eq!(row["cap_refusals_lost"], 1, "{row:#}");
    assert!(row["refusal_wait_ms"].is_null(), "{row:#}");
    assert_eq!(row["jobs"], 1, "{row:#}");
    assert_eq!(row["jobs_not_pass"], 1, "{row:#}");
    // Its run time is not known: no wall or queue sample.
    assert!(row["wall_ms"].is_null(), "{row:#}");
    assert!(row["queue_ms"].is_null(), "{row:#}");
}

#[test]
fn hook_time_runs_from_the_hook_process_start() {
    // The logged `ms` is the hook's time to its decision: it starts when
    // the hook process starts, so the repo's own hook, config, scope and
    // remote loading (`Gate::open`) and the staged-tree work are in it,
    // not only `decide`. The repo hook's share is logged on its own, and
    // `stats` leaves it out: it is not tollgate's time.
    let sb = Sandbox::new();
    sb.scoped_host("");
    let repo = sb.repo("r");
    sb.commit_file(
        &repo,
        "tollgate.toml",
        "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n",
        "policy",
    );
    support::write_exe(&repo.join(".githooks/pre-commit"), "#!/bin/sh\nsleep 0.4\n");
    sb.git(&repo, &["config", "core.hooksPath", ".githooks"]);
    std::fs::write(repo.join("a.txt"), "1\n").unwrap();
    sb.git(&repo, &["add", "a.txt"]);
    let t0 = Instant::now();
    let r = sb.hooked(&repo, &["commit", "-m", "a"]);
    let wall = t0.elapsed();
    assert_eq!(r.code, Some(0), "{}", r.out);

    let hooks = of_kind(&events(&sb.state()), "hook");
    assert_eq!(hooks.len(), 1, "{hooks:#?}");
    let ms = hooks[0]["ms"].as_u64().unwrap();
    assert!(
        ms >= 400,
        "the repo hook's 400 ms are not in it: {hooks:#?}"
    );
    let repo_ms = hooks[0]["repo_hook_ms"].as_u64().expect("repo_hook_ms");
    assert!(repo_ms >= 400, "{hooks:#?}");
    assert!(ms >= repo_ms, "{hooks:#?}");
    assert!(
        u128::from(ms) <= wall.as_millis(),
        "{hooks:#?} wall {wall:?}"
    );

    let r = sb.tollgate(&repo, &["stats", "--json"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let v: Value = serde_json::from_str(&r.out).unwrap();
    assert_eq!(v["repos"][0]["hook_ms"]["p50"], ms - repo_ms, "{v:#}");
}

/// The `exit` of every `chained` line of `hook`, in order.
fn chained_exits(state: &Path, hook: &str) -> Vec<String> {
    of_kind(&events(state), "chained")
        .iter()
        .filter(|e| e["hook"] == hook)
        .map(|e| e["exit"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn chained_hooks_log_their_time_and_which_exit_they_took_l19_item37() {
    // L19 budgets a chained hook at 5 ms. Every chained hook logs its own
    // time from the hook process's start, and post-commit and post-merge
    // log which item 17/37 exit they took, so `stats` shows how often the
    // cheap exits spare the full check (Gate::open).
    let sb = Sandbox::new();
    sb.scoped_host("remotes = [\"*/remotes/trusted*\"]");
    let repo = sb.repo("r");
    sb.commit_file(
        &repo,
        "tollgate.toml",
        "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n",
        "policy",
    );
    let bare = sb.root().join("remotes/trusted.git");
    std::fs::create_dir_all(&bare).unwrap();
    sb.git(&bare, &["init", "-q", "--bare"]);
    sb.git(&repo, &["remote", "add", "origin", bare.to_str().unwrap()]);
    sb.git(&repo, &["push", "-q", "origin", "main"]);
    let state = sb.state();
    // A gated commit: pre-commit allows and leaves the marker.
    std::fs::write(repo.join("a.txt"), "1\n").unwrap();
    sb.git(&repo, &["add", "a.txt"]);
    let r = sb.hooked(&repo, &["commit", "-m", "a"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(chained_exits(&state, "post-commit"), ["marker"]);
    // Hooks with nothing to detect only chain.
    assert_eq!(chained_exits(&state, "commit-msg"), ["chain"]);
    // The same HEAD again, no marker: its tree passed (one rev-parse).
    let o = sb.run_hook(&repo, "post-commit", &[]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(
        chained_exits(&state, "post-commit"),
        ["marker", "tree_passed"]
    );
    // A switch: post-checkout chains.
    let r = sb.hooked(&repo, &["checkout", "-q", "-b", "side"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(chained_exits(&state, "post-checkout"), ["chain"]);
    sb.commit_file(&repo, "s.txt", "1\n", "side");
    sb.git(&repo, &["push", "-q", "origin", "side"]);
    sb.git(&repo, &["checkout", "-q", "main"]);
    // A fast-forward to a trusted remote's ref makes no commit and brings
    // only what that remote has (item 37).
    let r = sb.hooked(&repo, &["merge", "-q", "--ff-only", "origin/side"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(chained_exits(&state, "post-merge"), ["fast_forward"]);
    // A squash merge makes no commit either.
    sb.git(&repo, &["checkout", "-q", "-b", "sq"]);
    sb.commit_file(&repo, "q.txt", "1\n", "sq");
    sb.git(&repo, &["checkout", "-q", "main"]);
    let r = sb.hooked(&repo, &["merge", "-q", "--squash", "sq"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(
        chained_exits(&state, "post-merge"),
        ["fast_forward", "squash"]
    );
    sb.git(&repo, &["reset", "-q", "--hard"]);
    // A fast-forward to a local branch at a commit no gate checked: the
    // full check, which records it (security review note 1).
    sb.git(&repo, &["checkout", "-q", "-b", "local"]);
    sb.commit_file(&repo, "l.txt", "1\n", "local");
    sb.git(&repo, &["checkout", "-q", "main"]);
    let r = sb.hooked(&repo, &["merge", "-q", "--ff-only", "local"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(r.out.contains("without the gate"), "{}", r.out);
    assert_eq!(
        chained_exits(&state, "post-merge"),
        ["fast_forward", "squash", "recorded"]
    );
    // A cherry-pick runs post-commit without pre-commit (L1).
    let r = sb.hooked(&repo, &["cherry-pick", "sq"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(
        chained_exits(&state, "post-commit")[2..],
        ["sequencer"],
        "{}",
        r.out
    );
    // A commit without the gate: the full check, which records it.
    std::fs::write(repo.join("n.txt"), "1\n").unwrap();
    sb.git(&repo, &["add", "n.txt"]);
    let r = sb.hooked(&repo, &["commit", "-q", "--no-verify", "-m", "n"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(r.out.contains("without the gate"), "{}", r.out);
    assert_eq!(chained_exits(&state, "post-commit")[3..], ["recorded"]);

    let chained = of_kind(&events(&state), "chained");
    assert!(
        chained
            .iter()
            .all(|e| e["repo"] == "r" && e["us"].as_u64().is_some_and(|us| us > 0)),
        "{chained:#?}"
    );

    let r = sb.tollgate(&repo, &["stats", "--json"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let v: Value = serde_json::from_str(&r.out).unwrap();
    let pc = v["chained"]
        .as_array()
        .unwrap_or_else(|| panic!("{v:#}"))
        .iter()
        .find(|x| x["hook"] == "post-commit")
        .unwrap_or_else(|| panic!("{v:#}"))
        .clone();
    assert_eq!(pc["runs"], 4, "{pc:#}");
    assert_eq!(pc["exits"]["marker"], 1, "{pc:#}");
    assert_eq!(pc["exits"]["tree_passed"], 1, "{pc:#}");
    assert_eq!(pc["exits"]["sequencer"], 1, "{pc:#}");
    assert_eq!(pc["exits"]["recorded"], 1, "{pc:#}");
    assert!(pc["us"]["p90"].as_u64().is_some(), "{pc:#}");
    let r = sb.tollgate(&repo, &["stats"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(r.out.contains("chained hooks"), "{}", r.out);
    assert!(r.out.contains("fast_forward 1"), "{}", r.out);
}

#[test]
fn an_out_of_scope_post_commit_logs_the_full_check_item37() {
    // No marker and a tree that never passed: Gate::open runs, finds the
    // repo out of scope and records nothing. That is the costly exit.
    let sb = Sandbox::new();
    sb.host_config("[verify]\nmin_free = \"1M\"\n");
    let repo = sb.repo("r");
    sb.commit_file(&repo, "a.txt", "1\n", "a");
    let o = sb.run_hook(&repo, "post-commit", &[]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(chained_exits(&sb.state(), "post-commit"), ["full"]);
}
