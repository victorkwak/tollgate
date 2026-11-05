//! Git hooks end to end: real git runs the hard-linked binary through the
//! `core.hooksPath` injection (T2-T4, T13, T14, T18, T19, R1, R2, R5-R7,
//! R14, R17, R20, R22, R31, R32, R37, R99, L1, L4, L17).

mod support;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use support::{HOOK_NAMES, Sandbox, eventually, job_id, test_hooks_dir, write_exe};

const PASS: &str = "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n";

/// A repo with `tollgate.toml` committed on `main` (no hooks ran).
fn repo_with(sb: &Sandbox, name: &str, toml: &str) -> PathBuf {
    let repo = sb.repo(name);
    sb.commit_file(&repo, "tollgate.toml", toml, "policy");
    repo
}

fn stage(sb: &Sandbox, repo: &Path, path: &str, content: &str) {
    let p = repo.join(path);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, content).unwrap();
    sb.git(repo, &["add", path]);
}

fn head(sb: &Sandbox, repo: &Path) -> String {
    sb.git(repo, &["rev-parse", "HEAD"])
}

/// Tiers of the jobs in creation order (job ids sort by second only).
fn tiers_of_jobs(sb: &Sandbox) -> Vec<String> {
    let mut specs: Vec<serde_json::Value> = sb
        .jobs()
        .iter()
        .map(|j| {
            serde_json::from_slice(
                &std::fs::read(sb.state().join("jobs").join(j).join("spec.json")).unwrap(),
            )
            .unwrap()
        })
        .collect();
    specs.sort_by_key(|s| {
        s["created"]
            .as_str()
            .unwrap()
            .parse::<jiff::Timestamp>()
            .unwrap()
    });
    specs
        .iter()
        .map(|s| s["tier"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn a_commit_runs_the_installed_hooks_and_chains_each_repo_hook_t2_t3_r1_r2_r7() {
    let sb = Sandbox::new();
    sb.scoped_host("");
    let repo = repo_with(&sb, "r", PASS);
    // A repo hook for every installed name logs its name, args and stdin.
    let log = sb.root().join("hooks.log");
    for name in HOOK_NAMES {
        write_exe(
            &repo.join(".githooks").join(name),
            &format!(
                "#!/bin/sh\necho \"{name} [$*] $(pwd)\" >> '{}'\nif [ {name} = post-rewrite ] || [ {name} = pre-push ]; then cat >> '{}'; fi\nexit 0\n",
                log.display(),
                log.display()
            ),
        );
    }
    sb.git(&repo, &["config", "core.hooksPath", ".githooks"]);
    stage(&sb, &repo, "a.txt", "1\n");
    let r = sb.hooked(&repo, &["commit", "-m", "a"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        r.out.contains("tollgate: pass pre-commit refs/heads/main"),
        "{}",
        r.out
    );
    assert_eq!(sb.jobs().len(), 1, "pre-commit gated the commit (R17)");
    sb.hooked(&repo, &["commit", "--amend", "-m", "a2"]);
    sb.hooked(&repo, &["checkout", "-q", "-b", "feat"]);
    let text = std::fs::read_to_string(&log).unwrap();
    let repo_s = repo.display().to_string();
    for want in [
        format!("pre-commit [] {repo_s}"),
        format!("prepare-commit-msg [.git/COMMIT_EDITMSG message] {repo_s}"),
        format!("commit-msg [.git/COMMIT_EDITMSG] {repo_s}"),
        format!("post-commit [] {repo_s}"),
        "post-rewrite [amend]".to_owned(),
        "post-checkout [".to_owned(),
    ] {
        assert!(text.contains(&want), "missing {want:?} in:\n{text}");
    }
    // post-rewrite got git's stdin: `<old> <new>` (R7).
    let amended = head(&sb, &repo);
    assert!(
        text.lines().any(|l| l.ends_with(&amended) && l.len() == 81),
        "{text}"
    );
    // pre-push: the repo hook gets the remote args and the same stdin.
    let plain = sb.root().join("plain.git");
    sb.git(
        &sb.root(),
        &["init", "-q", "--bare", plain.to_str().unwrap()],
    );
    let r = sb.hooked(&repo, &["push", "-q", plain.to_str().unwrap(), "feat"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let text = std::fs::read_to_string(&log).unwrap();
    let zero = "0".repeat(40);
    let line = format!("refs/heads/feat {amended} refs/heads/feat {zero}");
    assert!(text.contains(&line), "no {line:?} in:\n{text}");
    let args = format!("pre-push [{} {}]", plain.display(), plain.display());
    assert!(text.contains(&args), "{text}");
    // R1: every hook in the dir is a hard link to the binary.
    use std::os::unix::fs::MetadataExt;
    let bin = std::fs::metadata(support::BIN).unwrap().ino();
    for name in HOOK_NAMES {
        assert_eq!(
            std::fs::metadata(test_hooks_dir().join(name))
                .unwrap()
                .ino(),
            bin,
            "{name}"
        );
    }
}

#[test]
fn the_repo_hook_runs_first_and_its_failure_aborts_t3_r7() {
    let sb = Sandbox::new();
    sb.scoped_host("");
    let repo = repo_with(&sb, "r", PASS);
    write_exe(
        &repo.join(".githooks/pre-commit"),
        "#!/bin/sh\necho repo-pre-commit-ran >&2\nexit 7\n",
    );
    sb.git(&repo, &["config", "core.hooksPath", ".githooks"]);
    stage(&sb, &repo, "a.txt", "1\n");
    let before = head(&sb, &repo);
    let r = sb.hooked(&repo, &["commit", "-m", "a"]);
    assert_ne!(r.code, Some(0), "{}", r.out);
    assert!(r.out.contains("repo-pre-commit-ran"), "{}", r.out);
    assert_eq!(head(&sb, &repo), before);
    assert!(
        sb.jobs().is_empty(),
        "the gate runs after the repo hook passes"
    );
    // The default hooks dir counts too when core.hooksPath is unset.
    sb.git(&repo, &["config", "--unset", "core.hooksPath"]);
    write_exe(
        &repo.join(".git/hooks/commit-msg"),
        "#!/bin/sh\ngrep -q ok \"$1\" || { echo bad-msg >&2; exit 1; }\n",
    );
    let r = sb.hooked(&repo, &["commit", "-m", "nope"]);
    assert_ne!(r.code, Some(0), "{}", r.out);
    assert!(r.out.contains("bad-msg"), "{}", r.out);
    let r = sb.hooked(&repo, &["commit", "-m", "ok"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
}

#[test]
fn a_failing_tree_is_denied_with_the_report_r15_r91() {
    let sb = Sandbox::new();
    sb.scoped_host("");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"lint\"\nkind = \"command\"\nrun = \"test ! -f bad || { echo found bad; exit 3; }\"\n",
    );
    stage(&sb, &repo, "bad", "x\n");
    let before = head(&sb, &repo);
    let r = sb.hooked(&repo, &["commit", "-m", "bad"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(
        r.out.contains("DENIED pre-commit refs/heads/main tree"),
        "{}",
        r.out
    );
    assert!(r.out.contains("verdict fail job"), "{}", r.out);
    assert!(r.out.contains("| found bad"), "{}", r.out);
    assert_eq!(head(&sb, &repo), before);
    // R34: the stored fail denies again without a new job.
    let r = sb.hooked(&repo, &["commit", "-m", "bad"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(r.out.contains("stored fail"), "{}", r.out);
    assert_eq!(sb.jobs().len(), 1);
    // R39 (T22): an old lock the parent git does not hold is named with
    // `tollgate doctor --repo .`; no output names `rm`.
    let lock = repo.join(".git/refs/heads/other.lock");
    std::fs::write(&lock, b"").unwrap();
    let st = std::process::Command::new("touch")
        .args(["-d", "5 minutes ago"])
        .arg(&lock)
        .status()
        .unwrap();
    assert!(st.success());
    let r = sb.hooked(&repo, &["commit", "-m", "bad"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(
        r.out
            .contains("other.lock); check it with: tollgate doctor --repo ."),
        "{}",
        r.out
    );
    assert!(!r.out.contains("rm "), "{}", r.out);
}

#[test]
fn scope_by_path_depth_and_by_push_url_t4_r4_r5_l4() {
    let sb = Sandbox::new();
    std::fs::create_dir_all(sb.root().join("repos")).unwrap();
    sb.host_config(&format!(
        "[scope]\nroots = [\"{}\"]\nremotes = [\"*/remotes/trusted*\"]\n[verify]\nmin_free = \"1M\"\n",
        sb.root().join("repos").display()
    ));
    // A nested repo (a test fixture inside a checkout) is out of scope.
    let outer = sb.root().join("repos/outer");
    std::fs::create_dir_all(&outer).unwrap();
    sb.git(&outer, &["init", "-q"]);
    let inner = outer.join("target/fixture");
    std::fs::create_dir_all(&inner).unwrap();
    sb.git(&inner, &["init", "-q"]);
    stage(&sb, &inner, "t.txt", "1\n");
    let r = sb.hooked(&inner, &["commit", "-m", "fixture"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(sb.jobs().is_empty(), "nested repo gated: {}", r.out);

    // A clone outside the roots is out of scope for commits...
    let src = repo_with(&sb, "src", PASS);
    let clone = sb.root().join("elsewhere/renamed");
    std::fs::create_dir_all(clone.parent().unwrap()).unwrap();
    sb.git(
        &sb.root(),
        &[
            "clone",
            "-q",
            src.to_str().unwrap(),
            clone.to_str().unwrap(),
        ],
    );
    sb.git(&clone, &["checkout", "-q", "-b", "feat"]);
    stage(&sb, &clone, "f.txt", "1\n");
    let r = sb.hooked(&clone, &["commit", "-m", "f"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(sb.jobs().is_empty(), "out-of-scope commit gated: {}", r.out);
    // ...but its push to a trusted URL is gated, at full (R5, R20).
    let bare = sb.root().join("remotes/trusted.git");
    std::fs::create_dir_all(&bare).unwrap();
    sb.git(&bare, &["init", "-q", "--bare"]);
    let r = sb.hooked(&clone, &["push", "-q", bare.to_str().unwrap(), "feat"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        r.out.contains("tollgate: pass pre-push refs/heads/feat"),
        "{}",
        r.out
    );
    assert_eq!(tiers_of_jobs(&sb), ["full"]);
    // A push to an untrusted URL from an out-of-scope repo is not gated.
    let other = sb.root().join("elsewhere/other.git");
    sb.git(
        &sb.root(),
        &["init", "-q", "--bare", other.to_str().unwrap()],
    );
    sb.git(
        &clone,
        &["commit", "-q", "--no-verify", "--allow-empty", "-m", "e"],
    );
    let r = sb.hooked(&clone, &["push", "-q", other.to_str().unwrap(), "feat"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(sb.jobs().len(), 1);
}

/// A repo `r` whose origin is a trusted bare remote holding `main` (pushed
/// without hooks, as Victor's first push would be) and fetched (L2 anchor).
fn trusted_repo(sb: &Sandbox, toml: &str) -> (PathBuf, PathBuf) {
    sb.scoped_host("remotes = [\"*/remotes/trusted*\"]");
    let repo = repo_with(sb, "r", toml);
    let bare = sb.root().join("remotes/trusted.git");
    std::fs::create_dir_all(&bare).unwrap();
    sb.git(&bare, &["init", "-q", "--bare"]);
    sb.git(&repo, &["remote", "add", "origin", bare.to_str().unwrap()]);
    sb.git(&repo, &["push", "-q", "origin", "main"]);
    sb.git(&repo, &["fetch", "-q", "origin"]);
    (repo, bare)
}

#[test]
fn push_tiers_tags_and_deletions_t13_r20_r22() {
    let sb = Sandbox::new();
    let (repo, _bare) = trusted_repo(
        &sb,
        "version = 1\n[push]\nfast_refs = [\"wip/*\"]\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n",
    );
    sb.hooked(&repo, &["checkout", "-q", "-b", "feat"]);
    stage(&sb, &repo, "f.txt", "1\n");
    let r = sb.hooked(&repo, &["commit", "-m", "f"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(tiers_of_jobs(&sb), ["fast"]);
    // A feature branch to a trusted remote needs full (R20, L7).
    let r = sb.hooked(&repo, &["push", "-q", "origin", "feat"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(tiers_of_jobs(&sb), ["fast", "full"]);
    // wip/* needs only fast. A new branch has no remote tree, so its base
    // is the empty tree and the fast job checks everything (R55, R56).
    sb.hooked(&repo, &["checkout", "-q", "-b", "wip/x"]);
    stage(&sb, &repo, "w.txt", "1\n");
    assert_eq!(sb.hooked(&repo, &["commit", "-m", "w"]).code, Some(0));
    let r = sb.hooked(&repo, &["push", "-q", "origin", "wip/x"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        r.out.contains("pre-push refs/heads/wip/x") && r.out.contains("tier fast"),
        "{}",
        r.out
    );
    assert_eq!(tiers_of_jobs(&sb), ["fast", "full", "fast", "fast"]);
    // The next push has the remote tip as its base: the commit's own fast
    // record (same base) allows it, no job.
    stage(&sb, &repo, "w2.txt", "1\n");
    assert_eq!(sb.hooked(&repo, &["commit", "-m", "w2"]).code, Some(0));
    let jobs = sb.jobs().len();
    let r = sb.hooked(&repo, &["push", "-q", "origin", "wip/x"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(r.out.contains("record of job"), "{}", r.out);
    assert_eq!(sb.jobs().len(), jobs, "fast record reused");
    // Tags and deletions are not gated (R22).
    sb.git(&repo, &["tag", "v1"]);
    let r = sb.hooked(&repo, &["push", "-q", "origin", "v1"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let r = sb.hooked(&repo, &["push", "-q", "--delete", "origin", "feat"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(sb.jobs().len(), jobs);
    // wip/x pushed onto main needs full: a new full job.
    let r = sb.hooked(&repo, &["push", "-q", "origin", "wip/x:main"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(sb.jobs().len(), jobs + 1);
    assert_eq!(tiers_of_jobs(&sb).last().map(String::as_str), Some("full"));
}

#[test]
fn a_full_push_miss_is_allowed_for_the_trusted_remote_tip_r14() {
    let sb = Sandbox::new();
    let (repo, bare) = trusted_repo(&sb, PASS);
    // Another clone advances the trusted main without hooks (CI-protected
    // in real life).
    let other = sb.root().join("other");
    sb.git(
        &sb.root(),
        &[
            "clone",
            "-q",
            bare.to_str().unwrap(),
            other.to_str().unwrap(),
        ],
    );
    sb.commit_file(&other, "o.txt", "1\n", "o");
    sb.git(&other, &["push", "-q", "origin", "main"]);
    sb.git(&repo, &["pull", "-q", "--ff-only", "origin", "main"]);
    // Handoff of main to an untrusted remote: main needs full; the tip is
    // the trusted remote's main, so ls-remote verifies it (no job).
    let mac = sb.root().join("mac.git");
    sb.git(&sb.root(), &["init", "-q", "--bare", mac.to_str().unwrap()]);
    sb.git(&repo, &["remote", "add", "mac", mac.to_str().unwrap()]);
    let jobs = sb.jobs().len();
    let r = sb.hooked(&repo, &["push", "-q", "mac", "main"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(r.out.contains("remote-verified (R14)"), "{}", r.out);
    assert_eq!(sb.jobs().len(), jobs);
    // A local commit the trusted remote does not have needs a full job.
    sb.commit_file(&repo, "l.txt", "1\n", "local");
    let r = sb.hooked(&repo, &["push", "-q", "mac", "main"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(!r.out.contains("remote-verified"), "{}", r.out);
    assert_eq!(sb.jobs().len(), jobs + 1);
}

#[test]
fn partial_commit_in_a_linked_worktree_checks_the_commit_tree_t14_r17_r52() {
    let sb = Sandbox::new();
    sb.scoped_host("");
    let repo = repo_with(&sb, "r", PASS);
    sb.commit_file(&repo, "c.txt", "c\n", "c");
    let wt = sb.root().join("wt");
    sb.git(
        &repo,
        &["worktree", "add", "-q", "-b", "side", wt.to_str().unwrap()],
    );
    stage(&sb, &wt, "a.txt", "a\n");
    stage(&sb, &wt, "b.txt", "b\n");
    std::fs::write(wt.join("c.txt"), "unstaged\n").unwrap();
    let r = sb.hooked(&wt, &["commit", "-m", "only a", "--", "a.txt"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let job = job_id(&r.out);
    let commit_tree = sb.git(&wt, &["rev-parse", "HEAD^{tree}"]);
    assert_eq!(sb.report(&job)["tree"], commit_tree.as_str());
    // b.txt is still staged and c.txt still dirty: not in the commit.
    assert_eq!(sb.git(&wt, &["diff", "--cached", "--name-only"]), "b.txt");
    assert_eq!(sb.git(&wt, &["diff", "--name-only"]), "c.txt");
    // The hook's private index copies are gone.
    let tmp = sb.state().join("tmp");
    assert!(std::fs::read_dir(&tmp).map(|d| d.count()).unwrap_or(0) == 0);
}

/// The agent's index and lock files: the main git dir's top-level files
/// and the linked worktree's admin dir (not the verify checkouts' own).
fn agent_files(repo: &Path, wt_name: &str) -> Vec<(PathBuf, Vec<u8>)> {
    let gd = repo.join(".git");
    let mut out = Vec::new();
    for dir in [gd.clone(), gd.join("worktrees").join(wt_name)] {
        for e in std::fs::read_dir(&dir).unwrap().flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().into_owned();
            if p.is_file()
                && (name == "index" || name.ends_with(".lock") || name.starts_with("next-index"))
            {
                out.push((p.clone(), std::fs::read(&p).unwrap()));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn the_hook_and_a_slow_job_leave_the_agents_index_and_locks_alone_t14_r52() {
    let sb = Sandbox::new();
    sb.scoped_host("");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[budget]\ninline = \"1s\"\n[[step]]\nname = \"slow\"\nkind = \"command\"\nrun = \"sleep 2\"\n",
    );
    let wt = sb.root().join("wt");
    sb.git(
        &repo,
        &["worktree", "add", "-q", "-b", "side", wt.to_str().unwrap()],
    );
    stage(&sb, &wt, "a.txt", "a\n");
    std::fs::write(wt.join("README"), "dirty\n").unwrap();
    // The hook as git runs it in a linked worktree: GIT_DIR and an absolute
    // GIT_INDEX_FILE. git's own index writes happen before the hook.
    let gd = repo.join(".git/worktrees/wt");
    let gd_s = gd.to_str().unwrap().to_owned();
    let idx = gd.join("index");
    let idx_s = idx.to_str().unwrap().to_owned();
    let before = agent_files(&repo, "wt");
    let o = sb.run_hook(
        &wt,
        "pre-commit",
        &[("GIT_DIR", &gd_s), ("GIT_INDEX_FILE", &idx_s)],
    );
    let err = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(
        o.status.code(),
        Some(1),
        "denied at the inline budget: {err}"
    );
    let job = job_id(&err);
    let w = sb.tollgate(&wt, &["wait", &job, "--timeout", "30s"]);
    assert_eq!(w.code, Some(0), "{}", w.out);
    assert_eq!(
        agent_files(&repo, "wt"),
        before,
        "index or lock files changed"
    );
    // The checked tree is the index tree.
    let index_tree = sb.git(&wt, &["write-tree"]);
    assert_eq!(sb.report(&job)["tree"], index_tree.as_str());
}

#[test]
fn the_inline_budget_denies_with_the_job_and_a_retry_command_t19_r32_l17() {
    let sb = Sandbox::new();
    sb.scoped_host("");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"slow\"\nkind = \"command\"\nrun = \"sleep 3\"\n",
    );
    stage(&sb, &repo, "a.txt", "1\n");
    let before = head(&sb, &repo);
    let start = Instant::now();
    let r = sb.hooked_with(
        &repo,
        &["commit", "-m", "two words"],
        &[("TOLLGATE_INLINE_CAP", "1")],
    );
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "{:?}",
        start.elapsed()
    );
    let job = job_id(&r.out);
    assert!(r.out.contains("verdict running"), "{}", r.out);
    let retry = format!("tollgate wait {job} && git commit -m 'two words'");
    assert!(r.out.contains(&retry), "no {retry:?} in:\n{}", r.out);
    assert_eq!(head(&sb, &repo), before);
    // The printed command works: wait, then the same commit hits the record.
    let w = sb.tollgate(&repo, &["wait", &job, "--timeout", "30s"]);
    assert_eq!(w.code, Some(0), "{}", w.out);
    let r = sb.hooked(&repo, &["commit", "-m", "two words"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(r.out.contains(&format!("record of job {job}")), "{}", r.out);
    assert_eq!(sb.jobs().len(), 1);
}

/// The pid of the hook process `name` under git process `git`.
fn hook_pid(git: u32, name: &str) -> Option<i32> {
    let table = tollgate::procs::ProcTable::snapshot().ok()?;
    table
        .descendants(i32::try_from(git).ok()?)
        .into_iter()
        .find(|p| {
            std::fs::read(format!("/proc/{p}/cmdline"))
                .ok()
                .and_then(|c| {
                    c.split(|b| *b == 0)
                        .next()
                        .map(|a| a.ends_with(name.as_bytes()))
                })
                .unwrap_or(false)
        })
}

#[test]
fn a_killed_hook_leaves_no_commit_and_no_record_t18_r31_r37() {
    for signal in [libc::SIGKILL, libc::SIGTERM] {
        let sb = Sandbox::new();
        sb.scoped_host("");
        let repo = repo_with(
            &sb,
            "r",
            "version = 1\n[[step]]\nname = \"slow\"\nkind = \"command\"\nrun = \"sleep 30\"\n",
        );
        stage(&sb, &repo, "a.txt", "1\n");
        let before = head(&sb, &repo);
        let mut cmd = std::process::Command::new("git");
        cmd.env_clear()
            .current_dir(&repo)
            .args(["commit", "-m", "a"]);
        for (k, v) in sb.env().iter() {
            cmd.env(k, v);
        }
        for (k, v) in sb.injection() {
            cmd.env(k, v);
        }
        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let mut git = cmd.spawn().unwrap();
        let mut pid = None;
        assert!(
            eventually(20, || {
                pid = hook_pid(git.id(), "pre-commit");
                pid.is_some() && !sb.jobs().is_empty()
            }),
            "the hook never started a job"
        );
        tollgate::procs::signal(pid.unwrap(), signal).unwrap();
        let status = git.wait().unwrap();
        assert!(
            !status.success(),
            "git committed after the hook died ({signal})"
        );
        assert_eq!(head(&sb, &repo), before);
        assert_eq!(sb.record_count(), 0);
        let job = sb.jobs()[0].clone();
        assert_eq!(sb.tollgate(&repo, &["cancel", &job]).code, Some(0));
        let w = sb.tollgate(&repo, &["wait", &job, "--timeout", "30s"]);
        assert_eq!(w.code, Some(1), "{}", w.out);
        assert_eq!(sb.record_count(), 0);
    }
}

#[test]
fn merges_into_a_full_ref_need_full_r17_r99() {
    let sb = Sandbox::new();
    sb.scoped_host("");
    let repo = repo_with(&sb, "r", PASS);
    for b in ["feat", "feat2"] {
        sb.git(&repo, &["checkout", "-q", "-b", b, "main"]);
        sb.commit_file(&repo, &format!("{b}.txt"), "1\n", b);
    }
    sb.git(&repo, &["checkout", "-q", "main"]);
    // An automatic merge commit: pre-merge-commit at main's tier.
    let r = sb.hooked(&repo, &["merge", "--no-ff", "--no-edit", "feat"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        r.out.contains("pass pre-merge-commit refs/heads/main") && r.out.contains("tier full"),
        "{}",
        r.out
    );
    assert_eq!(tiers_of_jobs(&sb), ["full"]);
    // A merge concluded by `git commit` runs pre-commit, still at full.
    let r = sb.hooked(&repo, &["merge", "--no-ff", "--no-commit", "feat2"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let r = sb.hooked(&repo, &["commit", "--no-edit"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        r.out.contains("pass pre-commit refs/heads/main") && r.out.contains("tier full"),
        "{}",
        r.out
    );
    assert_eq!(tiers_of_jobs(&sb), ["full", "full"]);
    // A merge into a fast branch is fast.
    sb.git(&repo, &["checkout", "-q", "-b", "topic", "feat"]);
    let r = sb.hooked(&repo, &["merge", "--no-ff", "--no-edit", "main"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        r.out.contains("pass pre-merge-commit refs/heads/topic") && r.out.contains("tier fast"),
        "{}",
        r.out
    );
}

#[test]
fn a_denied_merge_stays_in_progress_and_git_commit_completes_it_r99_l17() {
    let sb = Sandbox::new();
    sb.scoped_host("");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"slow\"\nkind = \"command\"\nrun = \"sleep 2\"\n",
    );
    sb.git(&repo, &["checkout", "-q", "-b", "feat"]);
    sb.commit_file(&repo, "f.txt", "1\n", "f");
    sb.git(&repo, &["checkout", "-q", "main"]);
    let r = sb.hooked_with(
        &repo,
        &["merge", "--no-ff", "--no-edit", "feat"],
        &[("TOLLGATE_INLINE_CAP", "0")],
    );
    assert_ne!(r.code, Some(0), "{}", r.out);
    let job = job_id(&r.out);
    assert!(
        r.out
            .contains(&format!("tollgate wait {job} && git commit --no-edit")),
        "{}",
        r.out
    );
    assert!(
        repo.join(".git/MERGE_HEAD").exists(),
        "git keeps the merge in progress"
    );
    assert_eq!(
        sb.tollgate(&repo, &["wait", &job, "--timeout", "30s"]).code,
        Some(0)
    );
    let r = sb.hooked(&repo, &["commit", "--no-edit"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(
        sb.git(&repo, &["rev-list", "--count", "--merges", "HEAD"]),
        "1"
    );
    assert_eq!(sb.jobs().len(), 1);
}

#[test]
fn tollgate_merge_checks_full_then_commits_or_aborts_r99() {
    let sb = Sandbox::new();
    sb.scoped_host("");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"lint\"\nkind = \"command\"\nrun = \"test ! -f bad\"\n",
    );
    sb.git(&repo, &["checkout", "-q", "-b", "good"]);
    sb.commit_file(&repo, "g.txt", "1\n", "g");
    sb.git(&repo, &["checkout", "-q", "-b", "broken", "main"]);
    sb.commit_file(&repo, "bad", "1\n", "b");
    sb.git(&repo, &["checkout", "-q", "main"]);
    let inj = sb.injection();
    let extra: Vec<(&str, String)> = inj
        .iter()
        .map(|(k, v)| (*k, v.to_string_lossy().into_owned()))
        .collect();
    let extra: Vec<(&str, &str)> = extra.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let r = sb.tollgate_with(&repo, &["merge", "good"], &extra);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        r.out.contains("pass pre-commit refs/heads/main") && r.out.contains("record of job"),
        "{}",
        r.out
    );
    assert_eq!(
        sb.git(&repo, &["rev-list", "--count", "--merges", "HEAD"]),
        "1"
    );
    assert_eq!(tiers_of_jobs(&sb), ["full"]);
    let before = head(&sb, &repo);
    let r = sb.tollgate_with(&repo, &["merge", "broken"], &extra);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(r.out.contains("merge is aborted"), "{}", r.out);
    assert_eq!(head(&sb, &repo), before);
    assert!(!repo.join(".git/MERGE_HEAD").exists());
}
