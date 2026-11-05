//! Jobs end to end through the real binary with `command` steps: detach,
//! budgets, verdict classes, process control, verify checkouts, the job
//! environment, cancel and step reuse (T19-T21, T23, T26, T28, T39, L15,
//! L16).

mod support;

use std::path::Path;
use std::time::{Duration, Instant};

use support::{Sandbox, eventually, job_id};

/// A repo with `tollgate.toml` (from `steps`) committed on `main`.
fn repo_with(sb: &Sandbox, name: &str, toml: &str) -> std::path::PathBuf {
    let repo = sb.repo(name);
    sb.commit_file(&repo, "tollgate.toml", toml, "policy");
    repo
}

/// Host config with a tiny disk floor (tests run in /tmp).
fn host(sb: &Sandbox, extra: &str) {
    sb.host_config(&format!("[verify]\nmin_free = \"1M\"\n{extra}"));
}

fn alive(pid: i32) -> bool {
    tollgate::procs::ProcTable::snapshot().unwrap().alive(pid)
}

fn pids(path: &Path) -> Vec<i32> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect()
}

#[test]
fn inline_budget_denies_then_wait_and_cache_hit_t19_r32_l17() {
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[budget]\ninline = \"1s\"\n[[step]]\nname = \"slow\"\nkind = \"command\"\nrun = \"sleep 2\"\n",
    );
    let start = Instant::now();
    let r = sb.tollgate(&repo, &["check"]);
    assert_eq!(r.code, Some(3), "{}", r.out);
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "{:?}",
        start.elapsed()
    );
    assert!(r.out.contains("tollgate wait"), "{}", r.out);
    let job = job_id(&r.out);
    // A second request for the same tree attaches to the running job, or
    // hits its record when it already finished (R88, T39).
    let d = sb.tollgate(&repo, &["check", "--detach"]);
    assert_eq!(d.code, Some(0), "{}", d.out);
    assert!(
        d.out.contains(&format!("attached to running job {job}")) || d.out.contains("PASS"),
        "{}",
        d.out
    );
    let w = sb.tollgate(&repo, &["wait", &job, "--timeout", "30s"]);
    assert_eq!(w.code, Some(0), "{}", w.out);
    assert!(w.out.contains("PASS"), "{}", w.out);
    // The retry is a cache hit: no new job.
    let again = sb.tollgate(&repo, &["check"]);
    assert_eq!(again.code, Some(0), "{}", again.out);
    assert_eq!(sb.jobs().len(), 1);
    // A detached pre-warm of the same tree is a hit too.
    let d = sb.tollgate(&repo, &["check", "--detach"]);
    assert_eq!(d.code, Some(0), "{}", d.out);
    assert_eq!(sb.jobs().len(), 1);
}

#[test]
fn fail_is_cached_until_rerun_and_disk_defers_t21_r34_r44() {
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"lint\"\nkind = \"command\"\nrun = \"echo bad thing; exit 4\"\n",
    );
    let r = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(r.out.contains("step lint: fail exit 4"), "{}", r.out);
    assert!(r.out.contains("| bad thing"), "R91 log tail: {}", r.out);
    let again = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(again.code, Some(1));
    assert!(again.out.contains("stored fail"), "{}", again.out);
    assert_eq!(sb.jobs().len(), 1, "a fail is not re-run (R34)");
    let rerun = sb.tollgate(&repo, &["check", "--wait", "--rerun"]);
    assert_eq!(rerun.code, Some(1), "{}", rerun.out);
    assert_eq!(sb.jobs().len(), 2);

    // R44: below min_free the job is deferred and writes no record.
    let sb = Sandbox::new();
    sb.host_config("[verify]\nmin_free = \"1000000T\"\n");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n",
    );
    let r = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(
        r.out.contains("cause disk") && r.out.contains("verify.min_free"),
        "{}",
        r.out
    );
    assert_eq!(sb.record_count(), 0);
    let job = job_id(&r.out);
    assert_eq!(sb.report(&job)["outcome"], "deferred");
}

#[test]
fn timeout_kills_the_whole_step_tree_t20_r33_r35() {
    let sb = Sandbox::new();
    host(&sb, "");
    // The step's child ignores SIGTERM; its grandchild left the group with
    // setsid. Both must be gone after the grace.
    let script = r#"sh -c 'trap "" TERM; setsid sh -c "trap \"\" TERM; echo \$\$ >> $TMPDIR/../pids; exec sleep 60" & echo $$ >> $TMPDIR/../pids; sleep 60' & echo $$ >> $TMPDIR/../pids; wait"#;
    let repo = repo_with(
        &sb,
        "r",
        &format!(
            "version = 1\n[[step]]\nname = \"hang\"\nkind = \"command\"\nrun = '''{script}'''\ntimeout = \"1s\"\ngrace = \"1s\"\n"
        ),
    );
    let start = Instant::now();
    let r = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(
        r.out.contains("TIMEOUT") && r.out.contains("step hang: timeout"),
        "{}",
        r.out
    );
    assert!(start.elapsed() < Duration::from_secs(20));
    let job = job_id(&r.out);
    let pid_file = sb.state().join("jobs").join(&job).join("pids");
    let all = pids(&pid_file);
    assert_eq!(all.len(), 3, "leader, child, setsid grandchild: {all:?}");
    for p in &all {
        assert!(!alive(*p), "pid {p} survived");
    }
    // R34: a timeout is cached for its TTL; no new job.
    let again = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(again.code, Some(1), "{}", again.out);
    assert!(again.out.contains("--rerun"), "{}", again.out);
    assert_eq!(sb.jobs().len(), 1);
}

#[test]
fn cancel_kills_a_running_job_and_writes_no_record_t39_r89() {
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"long\"\nkind = \"command\"\nrun = \"echo $$ > $TMPDIR/../pid; exec sleep 60\"\n",
    );
    let r = sb.tollgate(&repo, &["check", "--detach"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let job = job_id(&r.out);
    let pid_file = sb.state().join("jobs").join(&job).join("pid");
    assert!(
        eventually(20, || !pids(&pid_file).is_empty()),
        "step never started"
    );
    let step = pids(&pid_file)[0];
    let c = sb.tollgate(&repo, &["cancel", &job]);
    assert_eq!(c.code, Some(0), "{}", c.out);
    let w = sb.tollgate(&repo, &["wait", &job, "--timeout", "30s"]);
    assert_eq!(w.code, Some(1), "{}", w.out);
    assert!(w.out.contains("CANCELLED"), "{}", w.out);
    assert!(!alive(step));
    assert_eq!(sb.record_count(), 0);
}

#[test]
fn checkout_holds_the_exact_tree_and_keeps_build_dirs_t23_r42() {
    let sb = Sandbox::new();
    host(&sb, "");
    let steps = r#"version = 1
[[step]]
name = "probe"
kind = "command"
run = '''
test -f a.txt && test ! -f junk.txt && test ! -f unstaged.txt || exit 9
if test -f target/marker; then echo kept >> "$TMPDIR/../seen"; fi
mkdir -p target && touch target/marker junk.txt
'''
"#;
    let repo = repo_with(&sb, "r", steps);
    sb.commit_file(&repo, "a.txt", "1\n", "a");
    // Unstaged and untracked files in the agent checkout are not checked.
    std::fs::write(repo.join("unstaged.txt"), "x").unwrap();
    std::fs::write(repo.join("a.txt"), "dirty\n").unwrap();
    let first = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(first.code, Some(0), "{}", first.out);
    // Second job on a new tree: junk.txt is cleaned, target/ survives.
    sb.git(&repo, &["checkout", "--", "a.txt"]);
    sb.commit_file(&repo, "b.txt", "2\n", "b");
    let second = sb.tollgate(&repo, &["check", "--wait", "--tier", "fast"]);
    assert_eq!(second.code, Some(0), "{}", second.out);
    let job = job_id(&second.out);
    assert_eq!(
        std::fs::read_to_string(sb.state().join("jobs").join(&job).join("seen")).unwrap(),
        "kept\n"
    );
    // R41: a registered, locked worktree of the repo.
    let list = sb.git(&repo, &["worktree", "list", "--porcelain"]);
    assert!(list.contains("locked tollgate"), "{list}");
    assert!(list.contains("/tollgate/verify/"), "{list}");

    // A step that edits a tracked file makes verdict error (R42).
    let sb2 = Sandbox::new();
    host(&sb2, "");
    let repo = repo_with(
        &sb2,
        "r",
        "version = 1\n[[step]]\nname = \"edit\"\nkind = \"command\"\nrun = \"echo x >> README\"\n",
    );
    let r = sb2.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(
        r.out.contains("cause checkout") && r.out.contains("README"),
        "{}",
        r.out
    );
}

#[test]
fn unborn_repo_and_lru_eviction_r41_l15() {
    let sb = Sandbox::new();
    host(&sb, "max_checkouts = 1\n");
    let repo = sb.root().join("u");
    std::fs::create_dir_all(&repo).unwrap();
    sb.git(&repo, &["init", "-q"]);
    std::fs::write(
        repo.join("tollgate.toml"),
        "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"test -f tollgate.toml\"\n",
    )
    .unwrap();
    sb.git(&repo, &["add", "-A"]);
    let r = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(r.code, Some(0), "unborn: {}", r.out);
    sb.git(&repo, &["commit", "-q", "--no-verify", "-m", "c"]);
    // A second worktree gets its own sticky checkout; max 1 evicts the first.
    let wt = sb.root().join("u-wt");
    sb.git(
        &repo,
        &["worktree", "add", "-q", "-b", "w", wt.to_str().unwrap()],
    );
    std::fs::write(wt.join("x.txt"), "x").unwrap();
    sb.git(&wt, &["add", "x.txt"]);
    let r = sb.tollgate(&wt, &["check", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let list = sb.git(&repo, &["worktree", "list", "--porcelain"]);
    assert_eq!(
        list.matches("locked tollgate").count(),
        1,
        "LRU keeps max_checkouts: {list}"
    );
}

#[test]
fn job_env_is_built_not_inherited_t26_r52() {
    let sb = Sandbox::new();
    host(&sb, "[job.env]\nSQLX_OFFLINE = \"true\"\n");
    let repo = repo_with(
        &sb,
        "r",
        r#"version = 1
[[step]]
name = "env"
kind = "command"
run = '''
env | sort > "$TMPDIR/../env.txt"
cd "$TMPDIR" && git init -q t && cd t && git -c user.name=x -c user.email=x@x commit -q --allow-empty -m x
'''
"#,
    );
    let hooks = sb.root().join("hooks");
    support::write_exe(&hooks.join("pre-commit"), "#!/bin/sh\nexit 1\n");
    let r = sb.tollgate_with(
        &repo,
        &["check", "--wait"],
        &[
            ("GIT_CONFIG_COUNT", "1"),
            ("GIT_CONFIG_KEY_0", "core.hooksPath"),
            ("GIT_CONFIG_VALUE_0", hooks.to_str().unwrap()),
            ("GUARD_EVAL_ONLY", "1"),
        ],
    );
    assert_eq!(
        r.code,
        Some(0),
        "the injection must not reach steps: {}",
        r.out
    );
    let job = job_id(&r.out);
    let env = std::fs::read_to_string(sb.state().join("jobs").join(&job).join("env.txt")).unwrap();
    assert!(!env.lines().any(|l| l.starts_with("GIT_")), "{env}");
    assert!(!env.contains("GUARD_EVAL_ONLY"), "{env}");
    for want in ["CI=1", "TOLLGATE=1", "TERM=dumb", "SQLX_OFFLINE=true"] {
        assert!(env.lines().any(|l| l == want), "{want} in {env}");
    }
}

#[test]
fn step_reuse_by_inputs_l16() {
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        r#"version = 1
[[step]]
name = "ios"
kind = "command"
run = "true"
inputs = ["ios/**"]
[[step]]
name = "all"
kind = "command"
run = "true"
"#,
    );
    sb.commit_file(&repo, "ios/App.swift", "1\n", "ios");
    let first = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
    assert_eq!(first.code, Some(0), "{}", first.out);
    let first_job = job_id(&first.out);
    sb.commit_file(&repo, "core.sh", "2\n", "core");
    let second = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
    assert_eq!(second.code, Some(0), "{}", second.out);
    assert!(
        second.out.contains(&format!("REUSED ios from {first_job}")),
        "{}",
        second.out
    );
    assert!(!second.out.contains("REUSED all"), "{}", second.out);
    // --rerun runs everything fresh.
    let third = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD", "--rerun"]);
    assert_eq!(third.code, Some(0), "{}", third.out);
    assert!(!third.out.contains("REUSED"), "{}", third.out);
    // A docs-only change passes with zero steps (R61).
    sb.commit_file(&repo, "README.md", "docs\n", "docs");
    let docs = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
    assert_eq!(docs.code, Some(0), "{}", docs.out);
    let rep = sb.report(&job_id(&docs.out));
    assert!(
        rep["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["status"] == "skipped" && s["message"] == "docs-only change (R61)"),
        "{rep}"
    );
}

#[test]
fn a_queued_job_without_waiters_is_superseded_r89_t39() {
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"long\"\nkind = \"command\"\nrun = \"touch $TMPDIR/../started; exec sleep 60\"\n",
    );
    let started = |job: &str| sb.state().join("jobs").join(job).join("started").exists();
    let first = job_id(&sb.tollgate(&repo, &["check", "--detach"]).out);
    assert!(eventually(20, || started(&first)));
    // Two newer trees from the same worktree queue behind the sticky
    // checkout; the older queued one has no waiter and is superseded.
    std::fs::write(repo.join("a.sh"), "1").unwrap();
    sb.git(&repo, &["add", "a.sh"]);
    let second = job_id(&sb.tollgate(&repo, &["check", "--detach"]).out);
    std::fs::write(repo.join("a.sh"), "2").unwrap();
    sb.git(&repo, &["add", "a.sh"]);
    let third = job_id(&sb.tollgate(&repo, &["check", "--detach"]).out);
    assert!(second != third && first != second);
    // Not `tollgate wait`: a waiter keeps a queued job alive (R89).
    let state = |job: &str| {
        let text = std::fs::read_to_string(sb.state().join("jobs").join(job).join("job.json"))
            .unwrap_or_default();
        serde_json::from_str::<serde_json::Value>(&text).map_or(String::new(), |v| {
            v["state"].as_str().unwrap_or_default().to_owned()
        })
    };
    assert!(
        eventually(20, || state(&second) == "superseded"),
        "second: {}",
        state(&second)
    );
    assert_eq!(state(&third), "queued");
    let report = sb.state().join("jobs").join(&second).join("report.json");
    assert!(eventually(10, || report.is_file()));
    assert_eq!(sb.report(&second)["outcome"], "superseded");
    for job in [&first, &third] {
        let _ = sb.tollgate(&repo, &["cancel", job]);
    }
    for job in [&first, &third] {
        let w = sb.tollgate(&repo, &["wait", job, "--timeout", "30s"]);
        assert_eq!(w.code, Some(1), "{}", w.out);
        assert!(w.out.contains("CANCELLED"), "{}", w.out);
    }
    assert_eq!(sb.record_count(), 0);
}
