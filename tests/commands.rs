//! CLI commands around jobs: `run --here` (T27, R47), `status` with the L1
//! unchecked line (R92), `config --effective|init` (R65), `gc` (R48).

mod support;

use std::path::Path;
use std::process::{Command, Stdio};

use support::{BIN, Sandbox, eventually, job_id};
use tollgate::dirs::Dirs;
use tollgate::ids::ResourceName;
use tollgate::locks::Semaphore;

#[test]
fn run_here_reports_and_holds_host_slots_t27_r47() {
    let sb = Sandbox::new();
    let mark = sb.root().join("mark");
    sb.host_config(&format!(
        "[resources]\ncpu = 1\n[job.env]\nMARK = \"{}\"\n",
        mark.display()
    ));
    let repo = sb.repo("r");
    sb.commit_file(
        &repo,
        "tollgate.toml",
        "version = 1\n[[step]]\nname = \"hold\"\nkind = \"command\"\nrun = \"touch \\\"$MARK\\\"; sleep 1\"\nresources = [\"cpu\"]\n",
        "policy",
    );
    let dirs = Dirs::from_env(&sb.env()).unwrap();
    let cpu = Semaphore::resource(&dirs, &ResourceName::parse("cpu").unwrap(), 1);
    let held_while_running = |extra: &[&str]| -> (bool, Option<i32>) {
        let _ = std::fs::remove_file(&mark);
        let mut cmd = Command::new(BIN);
        cmd.env_clear()
            .current_dir(&repo)
            .args(["run", "--tier", "fast", "--here"])
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (k, v) in sb.env().iter() {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().unwrap();
        assert!(eventually(20, || mark.exists()), "step did not start");
        let held = cpu.held_count().unwrap() == 1;
        let code = child.wait().unwrap().code();
        (held, code)
    };
    let (held, code) = held_while_running(&[]);
    assert!(held, "run --here takes the host cpu slot (R47)");
    assert_eq!(code, Some(0));
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(repo.join("tollgate-report/report.json")).unwrap())
            .unwrap();
    assert_eq!(report["verdict"], "pass");
    assert_eq!(report["record_written"], false);
    assert_eq!(sb.record_count(), 0, "no result cache in CI mode");
    let (held, code) = held_while_running(&["--no-host-locks"]);
    assert!(!held, "--no-host-locks takes no slot");
    assert_eq!(code, Some(0));

    sb.commit_file(
        &repo,
        "tollgate.toml",
        "version = 1\n[[step]]\nname = \"bad\"\nkind = \"command\"\nrun = \"exit 3\"\n",
        "bad",
    );
    let r = sb.tollgate(&repo, &["run", "--tier", "full", "--here"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(r.out.contains("step bad: fail exit 3"), "{}", r.out);
}

#[test]
fn status_shows_records_and_unchecked_commits_l1_r92() {
    let sb = Sandbox::new();
    sb.host_config("[verify]\nmin_free = \"1M\"\n");
    let repo = sb.repo("r");
    sb.commit_file(
        &repo,
        "tollgate.toml",
        "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n",
        "policy",
    );
    let checked = sb.git(&repo, &["rev-parse", "HEAD"]);
    let r = sb.tollgate(&repo, &["check", "--rev", "HEAD", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let job = job_id(&r.out);
    let s = sb.tollgate(&repo, &["status"]);
    assert!(
        s.out.contains(&format!("fast pass (job {job})")),
        "{}",
        s.out
    );
    assert!(s.out.contains("unchecked: none"), "{}", s.out);
    sb.commit_file(&repo, "x.sh", "1\n", "x");
    sb.commit_file(&repo, "y.sh", "2\n", "y");
    let s = sb.tollgate(&repo, &["status"]);
    assert!(
        s.out
            .contains(&format!("unchecked: 2 commit(s) above {}", &checked[..12])),
        "{}",
        s.out
    );
    assert!(s.out.contains("fast none"), "{}", s.out);
    let j = sb.tollgate(&repo, &["status", "--json"]);
    assert_eq!(j.code, Some(0), "{}", j.out);
    let v: serde_json::Value = serde_json::from_str(&j.out).unwrap();
    assert_eq!(v["unchecked"]["above"], 2);
    assert_eq!(v["unchecked"]["newest_checked"], checked.as_str());
    assert_eq!(v["refname"], "refs/heads/main");
}

#[test]
fn config_effective_and_init_use_detection_r65() {
    let sb = Sandbox::new();
    let repo = sb.rust_repo("ws", support::Scratch::default());
    let e = sb.tollgate(&repo, &["config", "--effective"]);
    assert_eq!(e.code, Some(0), "{}", e.out);
    assert!(e.out.contains("# source: detection"), "{}", e.out);
    assert!(e.out.contains("kind = \"nextest\""), "{}", e.out);
    let c = sb.tollgate(&repo, &["config", "--check"]);
    assert_eq!(c.code, Some(0), "{}", c.out);
    assert!(c.out.contains("detection (R65): 4 step(s)"), "{}", c.out);
    let i = sb.tollgate(&repo, &["config", "init", "--nextest"]);
    assert_eq!(i.code, Some(0), "{}", i.out);
    let written = std::fs::read_to_string(repo.join("tollgate.toml")).unwrap();
    assert!(written.contains("name = \"clippy\""), "{written}");
    assert!(repo.join(".config/nextest.toml").is_file());
    let c = sb.tollgate(&repo, &["config", "--check"]);
    assert_eq!(c.code, Some(0), "the written config validates: {}", c.out);
    let again = sb.tollgate(&repo, &["config", "init"]);
    assert_eq!(again.code, Some(2), "{}", again.out);
    assert!(again.out.contains("not overwritten"), "{}", again.out);
}

#[test]
fn gc_removes_checkouts_of_gone_repos_and_all_state_r48() {
    let sb = Sandbox::new();
    sb.host_config("[verify]\nmin_free = \"1M\"\n");
    let repo = sb.repo("r");
    sb.commit_file(
        &repo,
        "tollgate.toml",
        "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n",
        "policy",
    );
    let r = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let kept = sb.tollgate(&sb.root(), &["gc"]);
    assert!(kept.out.contains("0 verify checkout(s)"), "{}", kept.out);
    assert_eq!(sb.record_count(), 1);
    std::fs::remove_dir_all(&repo).unwrap();
    let g = sb.tollgate(&sb.root(), &["gc"]);
    assert_eq!(g.code, Some(0), "{}", g.out);
    assert!(g.out.contains("1 verify checkout(s)"), "{}", g.out);
    let all = sb.tollgate(&sb.root(), &["gc", "--all"]);
    assert!(
        all.out.contains("removed 1 record(s), 1 job dir(s)"),
        "{}",
        all.out
    );
    assert_eq!(sb.record_count(), 0);
    assert!(sb.jobs().is_empty());
}

/// `fresh/<shard>/<record key>/<step key>.json` files (R101).
fn fresh_entries(sb: &Sandbox) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let ls = |p: &Path| -> Vec<std::path::PathBuf> {
        std::fs::read_dir(p)
            .map(|rd| rd.flatten().map(|e| e.path()).collect())
            .unwrap_or_default()
    };
    for shard in ls(&sb.state().join("fresh")) {
        for record in ls(&shard) {
            out.extend(ls(&record));
        }
    }
    out.sort();
    out
}

/// R48, R101: gc removes same-tree step entries like stored step passes
/// (job report gone, older than the record age, `--all`) and keeps the job
/// dir that a kept entry names.
#[test]
fn gc_removes_fresh_step_entries_and_keeps_their_jobs_r48_r101() {
    let sb = Sandbox::new();
    sb.host_config("[verify]\nmin_free = \"1M\"\n");
    let repo = sb.repo("r");
    sb.commit_file(
        &repo,
        "tollgate.toml",
        "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n",
        "policy",
    );
    let r = sb.tollgate(&repo, &["check", "--rev", "HEAD", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let kept_job = job_id(&r.out);
    sb.commit_file(&repo, "x.sh", "1\n", "x");
    let r = sb.tollgate(&repo, &["check", "--rev", "HEAD", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let gone_job = job_id(&r.out);
    let entries = fresh_entries(&sb);
    assert_eq!(entries.len(), 2, "{entries:?}");
    // Only the fresh entries reference the jobs now, and the jobs ended
    // more than 14 days ago.
    std::fs::remove_dir_all(sb.state().join("results")).unwrap();
    std::fs::remove_dir_all(sb.state().join("steps")).unwrap();
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(15 * 86_400);
    for job in [&kept_job, &gone_job] {
        let f = std::fs::File::open(sb.state().join("jobs").join(job).join("job.json")).unwrap();
        f.set_modified(old).unwrap();
    }
    std::fs::remove_file(sb.state().join("jobs").join(&gone_job).join("report.json")).unwrap();
    let g = sb.tollgate(&sb.root(), &["gc"]);
    assert_eq!(g.code, Some(0), "{}", g.out);
    assert!(g.out.contains("1 step pass(es)"), "{}", g.out);
    let left = fresh_entries(&sb);
    assert_eq!(left.len(), 1, "{left:?}");
    let entry: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&left[0]).unwrap()).unwrap();
    assert_eq!(entry["job"], kept_job.as_str());
    assert_eq!(sb.jobs(), vec![kept_job.clone()], "{}", g.out);
    assert!(
        sb.state()
            .join("jobs")
            .join(&kept_job)
            .join("report.json")
            .is_file()
    );
    // An entry older than the record age goes, and then its job.
    let mut aged = entry.clone();
    aged["finished"] = serde_json::json!(
        (jiff::Timestamp::now() - jiff::SignedDuration::from_hours(91 * 24)).to_string()
    );
    std::fs::write(&left[0], aged.to_string()).unwrap();
    let g = sb.tollgate(&sb.root(), &["gc"]);
    assert!(g.out.contains("1 step pass(es)"), "{}", g.out);
    assert!(fresh_entries(&sb).is_empty());
    assert!(sb.jobs().is_empty(), "{}", g.out);
    // `--all` removes every entry.
    sb.commit_file(&repo, "y.sh", "1\n", "y");
    let r = sb.tollgate(&repo, &["check", "--rev", "HEAD", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(fresh_entries(&sb).len(), 1);
    let g = sb.tollgate(&sb.root(), &["gc", "--all"]);
    assert_eq!(g.code, Some(0), "{}", g.out);
    assert!(fresh_entries(&sb).is_empty(), "{}", g.out);
}

#[test]
fn ci_snippet_prints_a_gitlab_job_with_junit_r73() {
    let sb = Sandbox::new();
    let r = sb.tollgate(&sb.root(), &["ci-snippet", "--gitlab"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    for needle in [
        "tollgate:\n  stage: test\n",
        "    - tollgate run --tier full --here --report junit\n",
        "      - tollgate-report/\n",
        "      junit: tollgate-report/junit.xml\n",
    ] {
        assert!(r.out.contains(needle), "{needle:?} in\n{}", r.out);
    }
    let usage = sb.tollgate(&sb.root(), &["ci-snippet"]);
    assert_eq!(
        usage.code,
        Some(2),
        "--gitlab is the only format: {}",
        usage.out
    );
}
