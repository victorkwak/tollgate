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
        "version = 1\n[budget]\ninline = \"1s\"\n[[step]]\nname = \"slow\"\nkind = \"command\"\nrun = \"sleep 4\"\n",
    );
    let start = Instant::now();
    let r = sb.tollgate(&repo, &["check"]);
    assert_eq!(r.code, Some(3), "{}", r.out);
    // Back at the 1 s budget, well before the 4 s job ends. The margin
    // holds at a load of 47 on 16 cores, where the old 2 s job and bound
    // failed three tries in a row (1.2-1.6 s of start-up and plan).
    assert!(
        start.elapsed() < Duration::from_secs(4),
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
    // macOS has no setsid(1).
    let script = if cfg!(target_os = "macos") {
        script.replace("setsid", r#"perl -MPOSIX -e "POSIX::setsid(); exec @ARGV""#)
    } else {
        script.to_owned()
    };
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
    // An ignored file a step leaves behind is not a change (R42), and the
    // next job's `clean -x` removes it.
    sb.commit_file(&repo, ".gitignore", "junk.txt\n", "ignore");
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

/// R71, item 3: after the checkout, a tool config reached through a
/// symlink is refused (even one the policy commit has: its target can
/// change on any branch), and so is a symlink to a dir outside the
/// checkout (its files are not in the tree).
#[test]
fn tool_configs_reached_through_symlinks_are_refused_r71() {
    let outside = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(outside.path().join("deep/er")).unwrap();
    std::fs::write(outside.path().join("deep/er/rustfmt.toml"), "\n").unwrap();
    for (name, link, target, extra) in [
        (
            ".cargo dir",
            ".cargo",
            "cfg",
            Some(("cfg/config.toml", "[alias]\nx = \"y\"\n")),
        ),
        (
            "clippy.toml file",
            "clippy.toml",
            "shared.toml",
            Some(("shared.toml", "\n")),
        ),
        (
            "dir outside with a tool config",
            "ext",
            outside.path().to_str().unwrap(),
            None,
        ),
    ] {
        let sb = Sandbox::new();
        host(&sb, "");
        let repo = repo_with(&sb, "r", PASS_POLICY);
        if let Some((p, text)) = extra {
            sb.commit_file(&repo, p, text, "target");
        }
        std::os::unix::fs::symlink(target, repo.join(link)).unwrap();
        sb.git(&repo, &["add", link]);
        sb.git(&repo, &["commit", "-q", "--no-verify", "-m", "link"]);
        let r = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
        assert_eq!(r.code, Some(1), "{name}: {}", r.out);
        assert!(
            r.out.contains("cause checkout") && r.out.contains(&format!("{link} ")),
            "{name}: {}",
            r.out
        );
    }
    // A link into a kept dir (`target/` survives `git clean`): an earlier
    // job's step wrote a tool config there.
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"w\"\nkind = \"command\"\nrun = \"mkdir -p target/x && touch target/x/clippy.toml\"\n",
    );
    let r = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    std::os::unix::fs::symlink("target/x", repo.join("lint")).unwrap();
    sb.git(&repo, &["add", "lint"]);
    sb.git(&repo, &["commit", "-q", "--no-verify", "-m", "link"]);
    let r = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(
        r.out.contains("cause checkout") && r.out.contains("lint links to"),
        "{}",
        r.out
    );
    // A symlink to a file or dir of the tree is fine.
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = repo_with(&sb, "r", PASS_POLICY);
    sb.commit_file(&repo, "docs/a.md", "a\n", "docs");
    sb.commit_file(&repo, "docs/clippy.toml", "\n", "tree config");
    std::os::unix::fs::symlink("docs", repo.join("doc")).unwrap();
    std::os::unix::fs::symlink("docs/a.md", repo.join("a.md")).unwrap();
    sb.git(&repo, &["add", "doc", "a.md"]);
    sb.git(&repo, &["commit", "-q", "--no-verify", "-m", "links"]);
    let r = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    // A dir link out of the checkout (a local wheel index) is fine while
    // nothing under or above its target is a tool config. Item 24: the
    // check runs again after every step, so a step that writes one there
    // is an error.
    let wheels = tempfile::tempdir().unwrap();
    std::fs::write(wheels.path().join("x.whl"), "w").unwrap();
    std::os::unix::fs::symlink(wheels.path(), repo.join("wheels")).unwrap();
    sb.git(&repo, &["add", "wheels"]);
    sb.git(&repo, &["commit", "-q", "--no-verify", "-m", "wheels"]);
    let r = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    sb.commit_file(
        &repo,
        "tollgate.toml",
        "version = 1\n[[step]]\nname = \"w\"\nkind = \"command\"\nrun = \"mkdir -p wheels/sub && touch wheels/sub/rustfmt.toml\"\n",
        "write through the link",
    );
    let r = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(
        r.out.contains("cause checkout")
            && r.out.contains("wheels links to")
            && r.out.contains("sub/rustfmt.toml"),
        "{}",
        r.out
    );
}

/// R71, R42, item 5: the overlaid tool configs are exempt from the
/// tracked-change check (the job wrote them), so after each step each one
/// must still hold the policy commit's version, or still be absent.
#[test]
fn a_step_that_rewrites_an_overlaid_tool_config_is_an_error_r71_r42() {
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"rewrite\"\nkind = \"command\"\nrun = \"echo y > rustfmt.toml; touch clippy.toml\"\n[[step]]\nname = \"after\"\nkind = \"command\"\nrun = \"true\"\n",
    );
    sb.commit_file(&repo, "rustfmt.toml", "max_width = 100\n", "fmt");
    sb.git(&repo, &["checkout", "-q", "-b", "feat"]);
    sb.commit_file(&repo, "rustfmt.toml", "max_width = 80\n", "weaken");
    sb.commit_file(&repo, "clippy.toml", "\n", "lint");
    let r = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(
        r.out.contains("cause checkout")
            && r.out.contains("\"rewrite\" changed")
            && r.out.contains("clippy.toml")
            && r.out.contains("rustfmt.toml"),
        "{}",
        r.out
    );
}

/// R42, R71, item 6: a branch's `.gitignore` must not hide a tool config
/// that a step writes (a `build.rs` writing `.cargo/config.toml`). Other
/// ignored files a step leaves (caches) still do not count.
#[test]
fn an_ignored_tool_config_written_by_a_step_is_an_error_r42_r71() {
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"build\"\nkind = \"command\"\nrun = \"mkdir -p .cargo dist/sub __pycache__ && echo x > .cargo/config.toml && touch dist/sub/out.js __pycache__/m.pyc\"\n[[step]]\nname = \"after\"\nkind = \"command\"\nrun = \"true\"\n",
    );
    sb.git(&repo, &["checkout", "-q", "-b", "feat"]);
    sb.commit_file(
        &repo,
        ".gitignore",
        ".cargo/\ndist/\n__pycache__/\n",
        "hide",
    );
    let r = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(
        r.out.contains("cause checkout")
            && r.out
                .contains("\"build\" changed the checkout: .cargo/config.toml")
            && !r.out.contains("out.js")
            && !r.out.contains("m.pyc"),
        "{}",
        r.out
    );
    // The same caches without the config pass.
    sb.git(&repo, &["checkout", "-q", "main"]);
    sb.commit_file(
        &repo,
        "tollgate.toml",
        "version = 1\n[[step]]\nname = \"build\"\nkind = \"command\"\nrun = \"mkdir -p dist/sub __pycache__ && touch dist/sub/out.js __pycache__/m.pyc\"\n",
        "no config",
    );
    sb.commit_file(&repo, ".gitignore", "dist/\n__pycache__/\n", "ignore");
    let r = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
}

/// Gives every dir under `root` mode 0755 again (a step made one
/// unreadable), so the sandbox can be removed.
fn unlock_dirs(root: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.symlink_metadata().is_ok_and(|m| m.is_dir()) {
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755));
            unlock_dirs(&p);
        }
    }
}

/// R71, item 35: no walk of ignored output, so no entry budget: a step
/// that leaves 25k ignored files (a `.mypy_cache`, `dist`) passes.
#[test]
fn a_large_ignored_output_dir_passes_item35() {
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"build\"\nkind = \"command\"\nrun = \"mkdir -p dist/a && cd dist/a && seq 1 25000 | xargs touch\"\n",
    );
    sb.commit_file(&repo, ".gitignore", "dist/\n", "ignore");
    let r = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
}

/// One probe case: name, policy, files to commit, a link to commit (name,
/// target), text the error names.
type ProbeCase<'a> = (
    &'a str,
    String,
    Vec<(&'a str, &'a str)>,
    Option<(&'a str, &'a str)>,
    &'a str,
);

/// R71, items 24-27, 35: after every step (and before the first), each
/// dir of the checked tree, each ancestor of the checkout and each step
/// cwd holds no tool config that the tree and the overlay do not account
/// for, and none can hide behind a symlink or a dir it cannot read. Each
/// case is one way a step (the branch's code) leaves config for the next
/// step.
#[test]
fn tool_configs_a_step_leaves_anywhere_a_tool_looks_are_errors_items_24_27_35() {
    let outside = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(outside.path().join(".cargo")).unwrap();
    std::fs::write(
        outside.path().join(".cargo/config.toml"),
        "[alias]\nx = \"y\"\n",
    )
    .unwrap();
    let outside = outside.path().to_str().unwrap().to_owned();
    let cases: Vec<ProbeCase<'_>> = vec![
        (
            // Item 24: a dangling `.cargo` link (the policy commit's own)
            // whose target a setup step creates.
            "dangling .cargo link",
            "version = 1\n[[setup]]\nname = \"gen\"\nrun = \"mkdir -p cfg && printf '[alias]\\\\nx = \\\"y\\\"\\\\n' > cfg/config.toml\"\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n".to_owned(),
            vec![],
            Some((".cargo", "cfg")),
            ".cargo is a symlink that does not resolve",
        ),
        (
            // Item 25: a tracked dir named like a kept dir is tree content.
            "tracked target dir",
            "version = 1\n[[step]]\nname = \"w\"\nkind = \"command\"\nrun = \"mkdir -p src/target/.cargo && echo x > src/target/.cargo/config.toml\"\n".to_owned(),
            vec![("src/target/lib.rs", "\n")],
            None,
            "src/target/.cargo/config.toml: a tool config that is not in the tree",
        ),
        (
            // Item 26: an ignored `.cargo` the step makes unreadable.
            "unreadable .cargo",
            "version = 1\n[[step]]\nname = \"w\"\nkind = \"command\"\nrun = \"mkdir -p .cargo && echo x > .cargo/config.toml && chmod 000 .cargo\"\n".to_owned(),
            vec![(".gitignore", ".cargo/\n")],
            None,
            ": .cargo: a tool config that is not in the tree",
        ),
        (
            // Item 26: a tree dir the step makes unreadable.
            "unreadable tree dir",
            "version = 1\n[[step]]\nname = \"w\"\nkind = \"command\"\nrun = \"mkdir -p sub/.cargo && echo x > sub/.cargo/config.toml && chmod 000 sub\"\n".to_owned(),
            vec![("sub/a.txt", "a\n")],
            None,
            "sub/clippy.toml: cannot check for a tool config",
        ),
        (
            // Item 27: a step-created dir symlink that the next step's cwd
            // goes through (cargo reads the physical cwd's ancestors).
            "step-created dir symlink",
            format!(
                "version = 1\n[[step]]\nname = \"link\"\nkind = \"command\"\nrun = \"ln -s {outside} gen\"\n[[step]]\nname = \"in gen\"\nkind = \"command\"\ncwd = \"gen\"\nrun = \"true\"\n"
            ),
            vec![(".gitignore", "gen\n")],
            None,
            "gen: a step cwd that resolves to",
        ),
        (
            // Item 35: config written above the checkout root, which cargo,
            // clippy and rustfmt all read.
            "config above the checkout root",
            "version = 1\n[[step]]\nname = \"w\"\nkind = \"command\"\nrun = \"mkdir -p ../.cargo && echo x > ../.cargo/config.toml\"\n".to_owned(),
            vec![],
            None,
            "/.cargo/config.toml: a tool config above the checkout",
        ),
    ];
    let mut bad = Vec::new();
    for (name, policy, files, link, want) in cases {
        let sb = Sandbox::new();
        host(&sb, "");
        let repo = repo_with(&sb, "r", &policy);
        for (p, text) in files {
            sb.commit_file(&repo, p, text, "file");
        }
        if let Some((l, target)) = link {
            std::os::unix::fs::symlink(target, repo.join(l)).unwrap();
            sb.git(&repo, &["add", l]);
            sb.git(&repo, &["commit", "-q", "--no-verify", "-m", "link"]);
        }
        let r = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
        unlock_dirs(&sb.state());
        if r.code != Some(1) || !r.out.contains("cause checkout") || !r.out.contains(want) {
            bad.push(format!("{name}: {}", r.out));
            continue;
        }
        if name == "config above the checkout root" {
            // It stays there: the next job refuses it before any step.
            sb.commit_file(
                &repo,
                "tollgate.toml",
                "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n",
                "plain",
            );
            let r = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
            assert_eq!(r.code, Some(1), "{name}, next job: {}", r.out);
            assert!(
                r.out.contains("cause checkout") && r.out.contains(want),
                "{name}, next job: {}",
                r.out
            );
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
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
    let second_job = job_id(&second.out);
    // --rerun reuses no pass of another tree: `ios` runs. `all` ran on
    // this tree in the second job and is taken from there (R101).
    let third = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD", "--rerun"]);
    assert_eq!(third.code, Some(0), "{}", third.out);
    assert!(!third.out.contains("REUSED"), "{}", third.out);
    assert!(
        third
            .out
            .contains(&format!("FRESH all from {second_job} (same tree)")),
        "{}",
        third.out
    );
    assert!(!third.out.contains("FRESH ios"), "{}", third.out);
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

#[test]
fn setup_runs_when_its_inputs_change_r45_r46() {
    let sb = Sandbox::new();
    let count = sb.root().join("setup-runs");
    host(
        &sb,
        &format!("[job.env]\nCOUNT = \"{}\"\n", count.display()),
    );
    let repo = repo_with(
        &sb,
        "r",
        r#"version = 1
[[setup]]
name = "deps"
run = "echo ran >> \"$COUNT\" && test -f deps.txt"
when = ["deps.txt"]
[[step]]
name = "ok"
kind = "command"
run = "true"
"#,
    );
    sb.commit_file(&repo, "deps.txt", "1\n", "deps");
    let runs = || {
        std::fs::read_to_string(&count)
            .unwrap_or_default()
            .lines()
            .count()
    };
    let r = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(runs(), 1);
    sb.commit_file(&repo, "other.sh", "x\n", "other");
    let r = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(runs(), 1, "deps.txt unchanged: setup is up to date");
    sb.commit_file(&repo, "deps.txt", "2\n", "deps2");
    let r = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(runs(), 2);

    // A failing setup is verdict error, cause setup.
    sb.commit_file(
        &repo,
        "tollgate.toml",
        "version = 1\n[[setup]]\nname = \"broken\"\nrun = \"exit 3\"\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n",
        "broken setup",
    );
    let r = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(
        r.out.contains("cause setup") && r.out.contains("broken"),
        "{}",
        r.out
    );
}

#[test]
fn quarantine_beyond_30_days_of_the_policy_commit_is_a_config_error_r69_t34() {
    let sb = Sandbox::new();
    host(&sb, "");
    let until = jiff::Zoned::now()
        .date()
        .checked_add(jiff::Span::new().days(31))
        .unwrap();
    let repo = repo_with(
        &sb,
        "r",
        &format!(
            "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n[[quarantine]]\ntest = \"a tests::x\"\nuntil = \"{until}\"\nissue = \"i\"\n"
        ),
    );
    let r = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(
        r.out.contains("cause config") && r.out.contains("more than 30 days"),
        "{}",
        r.out
    );
}

#[test]
fn exact_selection_hits_a_covering_record_of_another_base_r79_t35() {
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        r#"version = 1
[[step]]
name = "s1"
kind = "command"
run = "true"
when = ["a/**"]
[[step]]
name = "s2"
kind = "command"
run = "true"
when = ["b/**"]
"#,
    );
    let r = sb.tollgate(&repo, &["check", "--rev", "HEAD", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    std::fs::create_dir_all(repo.join("a")).unwrap();
    std::fs::create_dir_all(repo.join("b")).unwrap();
    std::fs::write(repo.join("a/x.sh"), "1").unwrap();
    std::fs::write(repo.join("b/y.sh"), "1").unwrap();
    sb.git(&repo, &["add", "-A"]);
    let both = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(both.code, Some(0), "{}", both.out);
    let rep = sb.report(&job_id(&both.out));
    assert_eq!(
        rep["selection"]["subset"]["steps"],
        serde_json::json!(["s1", "s2"]),
        "{rep}"
    );
    // Commit only a/; the index tree stays the same (b/ still staged).
    sb.git(
        &repo,
        &["commit", "-q", "--no-verify", "-m", "a", "--", "a/x.sh"],
    );
    let r = sb.tollgate(&repo, &["check", "--rev", "HEAD", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let jobs = sb.jobs().len();
    // Relative to the new base only s2 is needed; the record of the same
    // tree from the older base covers it: no job.
    let hit = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(hit.code, Some(0), "{}", hit.out);
    assert_eq!(sb.jobs().len(), jobs, "{}", hit.out);
}

#[test]
fn steps_must_leave_the_checkout_as_read_and_are_not_reused_r42_l16() {
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"writes\"\nkind = \"command\"\nrun = \"echo rewritten > src/a.rs\"\ninputs = [\"src/**\"]\n",
    );
    sb.commit_file(&repo, "src/a.rs", "orig\n", "src");
    sb.commit_file(&repo, "other.cfg", "1\n", "cfg");
    std::fs::write(repo.join("other.cfg"), "2\n").unwrap();
    sb.git(&repo, &["add", "other.cfg"]);
    let first = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(first.code, Some(1), "{}", first.out);
    assert!(
        first.out.contains("cause checkout")
            && first
                .out
                .contains("\"writes\" changed the checkout: src/a.rs"),
        "{}",
        first.out
    );
    // A tree that differs only outside the step's inputs must run the step
    // again, not reuse a pass the R42 check never accepted.
    std::fs::write(repo.join("other.cfg"), "3\n").unwrap();
    sb.git(&repo, &["add", "other.cfg"]);
    let second = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(second.code, Some(1), "{}", second.out);
    assert!(!second.out.contains("REUSED"), "{}", second.out);
    assert!(second.out.contains("cause checkout"), "{}", second.out);
    for store in ["steps", "fresh"] {
        assert!(
            !sb.state().join(store).exists()
                || std::fs::read_dir(sb.state().join(store)).unwrap().count() == 0,
            "no stored step pass in {store}/ (L16, R101)"
        );
    }
    sb.git(&repo, &["reset", "-q", "--hard"]);

    // An untracked file and an index change count too (R42: `git status
    // --porcelain` empty, `write-tree` equal to T).
    for (run, needle) in [
        ("touch new.txt", "new.txt"),
        ("echo x >> README && git add README", "README"),
    ] {
        sb.commit_file(
            &repo,
            "tollgate.toml",
            &format!("version = 1\n[[step]]\nname = \"s\"\nkind = \"command\"\nrun = '{run}'\n"),
            run,
        );
        let r = sb.tollgate(&repo, &["check", "--wait"]);
        assert_eq!(r.code, Some(1), "{run}: {}", r.out);
        assert!(
            r.out.contains("cause checkout") && r.out.contains(needle),
            "{run}: {}",
            r.out
        );
    }
}

#[test]
fn a_full_ref_never_takes_a_full_pass_with_reused_steps_l16() {
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"t\"\nkind = \"command\"\nrun = \"test ! -e b/bad\"\ninputs = [\"a/**\"]\n",
    );
    sb.commit_file(&repo, "a/x", "1\n", "a");
    sb.git(&repo, &["checkout", "-q", "-b", "feat"]);
    sb.commit_file(&repo, "a/x", "2\n", "c1");
    let r = sb.tollgate(
        &repo,
        &["check", "--tier", "full", "--rev", "HEAD", "--wait"],
    );
    assert_eq!(r.code, Some(0), "{}", r.out);
    // c2 changes nothing under the step's inputs (a wrong inputs list): a
    // feature branch's full job may reuse the pass (L16).
    sb.commit_file(&repo, "b/bad", "x\n", "c2 adds b/bad");
    let r = sb.tollgate(
        &repo,
        &["check", "--tier", "full", "--rev", "HEAD", "--wait"],
    );
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(r.out.contains("REUSED t"), "{}", r.out);
    let reused_job = job_id(&r.out);
    // On main the same tree needs every step fresh: no hit, no attach to
    // the reused record; the step runs and fails.
    sb.git(&repo, &["checkout", "-q", "main"]);
    sb.git(&repo, &["merge", "-q", "--no-verify", "--ff-only", "feat"]);
    let r = sb.tollgate(
        &repo,
        &["check", "--tier", "full", "--rev", "main", "--wait"],
    );
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(!r.out.contains("REUSED"), "{}", r.out);
    assert!(!r.out.contains(&reused_job), "{}", r.out);
    assert!(r.out.contains("step t: fail"), "{}", r.out);
}

/// Lines of the run counter file that equal `name`.
fn runs(counter: &Path, name: &str) -> usize {
    std::fs::read_to_string(counter)
        .unwrap_or_default()
        .lines()
        .filter(|l| *l == name)
        .count()
}

/// R101: a job that needs every step fresh takes the steps that already
/// ran fresh on the same tree, tier and fingerprint, and runs only the
/// others. The case: a full pass on a branch reused one step; the same
/// tree on `main` then ran every step again.
#[test]
fn a_fresh_job_runs_only_the_steps_that_were_not_fresh_on_the_tree_r101() {
    let sb = Sandbox::new();
    let counter = sb.root().join("count");
    host(
        &sb,
        &format!("[job.env]\nCOUNT = \"{}\"\n", counter.display()),
    );
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"narrow\"\nkind = \"command\"\nrun = \"echo narrow >> \\\"$COUNT\\\"\"\ninputs = [\"a/**\"]\n[[step]]\nname = \"wide\"\nkind = \"command\"\nrun = \"echo wide >> \\\"$COUNT\\\"\"\n",
    );
    sb.commit_file(&repo, "a/x", "1\n", "a");
    sb.git(&repo, &["checkout", "-q", "-b", "feat"]);
    sb.commit_file(&repo, "a/x", "2\n", "c1");
    let full = ["check", "--tier", "full", "--rev", "HEAD", "--wait"];
    let r = sb.tollgate(&repo, &full);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!((runs(&counter, "narrow"), runs(&counter, "wide")), (1, 1));
    // c2 is outside the inputs of `narrow`: the branch job reuses it and
    // runs `wide` fresh on the new tree.
    sb.commit_file(&repo, "b/y", "1\n", "c2");
    let r = sb.tollgate(&repo, &full);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(r.out.contains("REUSED narrow"), "{}", r.out);
    let branch_job = job_id(&r.out);
    assert_eq!((runs(&counter, "narrow"), runs(&counter, "wide")), (1, 2));
    // The same tree on main: `narrow` was not fresh on it and runs;
    // `wide` was, and does not run again.
    sb.git(&repo, &["checkout", "-q", "main"]);
    sb.git(&repo, &["merge", "-q", "--no-verify", "--ff-only", "feat"]);
    let r = sb.tollgate(&repo, &full);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        r.out
            .contains(&format!("FRESH wide from {branch_job} (same tree)")),
        "{}",
        r.out
    );
    assert!(!r.out.contains("REUSED"), "{}", r.out);
    assert_eq!((runs(&counter, "narrow"), runs(&counter, "wide")), (2, 2));
    // That job's record is a fresh full pass: the next check is a hit.
    let jobs = sb.jobs().len();
    let r = sb.tollgate(&repo, &full);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(sb.jobs().len(), jobs, "{}", r.out);
}

/// R101: `check --rerun` runs the steps that did not pass on the tree;
/// `--rerun --all` runs every step.
#[test]
fn rerun_runs_only_the_steps_that_did_not_pass_r101() {
    let sb = Sandbox::new();
    let counter = sb.root().join("count");
    let mark = sb.root().join("mark");
    host(
        &sb,
        &format!(
            "[job.env]\nCOUNT = \"{}\"\nMARK = \"{}\"\n",
            counter.display(),
            mark.display()
        ),
    );
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"steady\"\nkind = \"command\"\nrun = \"echo steady >> \\\"$COUNT\\\"\"\n[[step]]\nname = \"once\"\nkind = \"command\"\nrun = \"echo once >> \\\"$COUNT\\\"; test -e \\\"$MARK\\\" || {{ touch \\\"$MARK\\\"; exit 1; }}\"\n"
            .replace("{{", "{")
            .replace("}}", "}")
            .as_str(),
    );
    sb.commit_file(&repo, "x", "1\n", "x");
    let full = ["check", "--tier", "full", "--rev", "HEAD", "--wait"];
    let r = sb.tollgate(&repo, &full);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(r.out.contains("step once: fail"), "{}", r.out);
    let failed_job = job_id(&r.out);
    let rerun = [
        "check", "--tier", "full", "--rev", "HEAD", "--wait", "--rerun",
    ];
    let r = sb.tollgate(&repo, &rerun);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        r.out
            .contains(&format!("FRESH steady from {failed_job} (same tree)")),
        "{}",
        r.out
    );
    assert_eq!((runs(&counter, "steady"), runs(&counter, "once")), (1, 2));
    let all = [
        "check", "--tier", "full", "--rev", "HEAD", "--wait", "--rerun", "--all",
    ];
    let r = sb.tollgate(&repo, &all);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(!r.out.contains("FRESH"), "{}", r.out);
    assert_eq!((runs(&counter, "steady"), runs(&counter, "once")), (2, 3));
}

#[test]
fn an_attached_check_with_another_selection_runs_its_own_job_r79_r88() {
    let sb = Sandbox::new();
    let go = sb.root().join("go");
    host(
        &sb,
        &format!(
            "[scope]\ntrusted_paths = [\"{}\"]\n[job.env]\nGO = \"{}\"\n",
            sb.root().join("remotes/trusted.git").display(),
            go.display()
        ),
    );
    let repo = sb.root().join("r");
    std::fs::create_dir_all(&repo).unwrap();
    sb.git(&repo, &["init", "-q"]);
    sb.commit_file(
        &repo,
        "tollgate.toml",
        r#"version = 1
[[step]]
name = "stepA"
kind = "command"
run = "touch $TMPDIR/../a-started; while [ ! -e $GO ]; do sleep 0.05; done"
when = ["a/**"]
[[step]]
name = "stepB"
kind = "command"
run = "! grep -q bad b/y"
when = ["b/**"]
"#,
        "policy",
    );
    sb.commit_file(&repo, "a/x", "a1\n", "a");
    sb.commit_file(&repo, "b/y", "b1\n", "R0");
    let r0 = sb.git(&repo, &["rev-parse", "HEAD"]);
    let bare = trusted_bare(&sb, &repo);
    // X: b broken; W: a changed. Both are on the trusted remote, so each
    // is a trusted base (R56).
    let x = sb.commit_file(&repo, "b/y", "bad\n", "X");
    sb.git(&repo, &["checkout", "-q", &r0]);
    let w = sb.commit_file(&repo, "a/x", "a2\n", "W");
    for (oid, branch) in [(&r0, "main"), (&x, "x"), (&w, "w")] {
        sb.git(
            &repo,
            &[
                "push",
                "-q",
                "origin",
                &format!("{oid}:refs/heads/{branch}"),
            ],
        );
    }
    sb.git(
        &repo,
        &[
            "fetch",
            "-q",
            bare.to_str().unwrap(),
            "+refs/heads/*:refs/remotes/origin/*",
        ],
    );
    // wt1: HEAD X, index T (only a/ changed: stepA). wt2: HEAD W, index T
    // (only b/ changed: stepB, which fails on T).
    sb.git(&repo, &["checkout", "-q", &x]);
    std::fs::write(repo.join("a/x"), "a2\n").unwrap();
    sb.git(&repo, &["add", "-A"]);
    let wt2 = sb.root().join("wt2");
    sb.git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            "--detach",
            wt2.to_str().unwrap(),
            &w,
        ],
    );
    std::fs::write(wt2.join("b/y"), "bad\n").unwrap();
    sb.git(&wt2, &["add", "-A"]);
    assert_eq!(
        sb.git(&repo, &["write-tree"]),
        sb.git(&wt2, &["write-tree"])
    );

    let first = sb.tollgate(&repo, &["check", "--detach"]);
    assert_eq!(first.code, Some(0), "{}", first.out);
    let job1 = job_id(&first.out);
    let job_dir = sb.state().join("jobs").join(&job1);
    assert!(eventually(20, || job_dir.join("a-started").exists()));
    std::thread::scope(|s| {
        let second = s.spawn(|| sb.tollgate(&wt2, &["check", "--wait"]));
        let waiting = || {
            std::fs::read_dir(job_dir.join("waiters"))
                .map(|rd| {
                    rd.flatten()
                        .any(|e| !e.file_name().to_string_lossy().starts_with('.'))
                })
                .unwrap_or(false)
        };
        assert!(eventually(20, waiting), "wt2 never attached");
        std::fs::write(&go, "").unwrap();
        let r = second.join().unwrap();
        assert!(
            r.out.contains(&format!("attached to running job {job1}")),
            "{}",
            r.out
        );
        assert_eq!(r.code, Some(1), "wt2 needs stepB, which fails: {}", r.out);
        assert!(r.out.contains("step stepB: fail"), "{}", r.out);
    });
    let w1 = sb.tollgate(&repo, &["wait", &job1, "--timeout", "30s"]);
    assert_eq!(w1.code, Some(0), "wt1 needs only stepA: {}", w1.out);
}

/// A bare repo at `<root>/remotes/trusted.git` (named in
/// `scope.trusted_paths`, item 34) as `origin` of `repo`.
fn trusted_bare(sb: &Sandbox, repo: &Path) -> std::path::PathBuf {
    let bare = sb.root().join("remotes/trusted.git");
    sb.git(
        &sb.root(),
        &["init", "-q", "--bare", bare.to_str().unwrap()],
    );
    sb.git(repo, &["remote", "add", "origin", bare.to_str().unwrap()]);
    bare
}

/// A repo whose `main` is also `origin/main` of a trusted remote, so every
/// commit on it is a trusted base (R56) without a record.
fn trusted_repo(sb: &Sandbox, policy: &str) -> std::path::PathBuf {
    host(
        sb,
        &format!(
            "[scope]\ntrusted_paths = [\"{}\"]\n",
            sb.root().join("remotes/trusted.git").display()
        ),
    );
    let repo = repo_with(sb, "r", policy);
    trusted_bare(sb, &repo);
    sb.git(&repo, &["push", "-q", "origin", "main"]);
    sb.git(&repo, &["fetch", "-q", "origin"]);
    repo
}

/// R56, X1: a base counts as trusted through a remote-tracking ref only
/// when the trusted server reported that ref's value; `update-ref` or
/// `fetch .` into `refs/remotes/origin/*` does not turn selection on.
#[test]
fn a_forged_tracking_ref_does_not_trust_a_base_r56() {
    use tollgate::plan::{Base, PlanRequest};

    let sb = Sandbox::new();
    let repo = trusted_repo(&sb, PASS_POLICY);
    let main = sb.git(&repo, &["rev-parse", "HEAD"]);
    sb.commit_file(&repo, "x.txt", "1\n", "X, never pushed");
    let x = sb.git(&repo, &["rev-parse", "HEAD"]);
    sb.git(&repo, &["update-ref", "refs/remotes/origin/x", &x]);
    sb.git(&repo, &["fetch", "-q", ".", "+HEAD:refs/remotes/origin/y"]);
    sb.commit_file(&repo, "y.txt", "1\n", "Y");
    let env = sb.env();
    let dirs = tollgate::dirs::Dirs::from_env(&env).unwrap();
    let host = tollgate::config::HostConfig::load(&dirs).unwrap();
    let git = tollgate::gitx::Git::scrubbed(&env, &repo);
    let layout = tollgate::gitx::RepoLayout::discover(&git).unwrap();
    let oid = |r: &str| tollgate::gitx::Oid::parse(&sb.git(&repo, &["rev-parse", r])).unwrap();
    let plan_on = |base: &str| {
        tollgate::plan::plan(&PlanRequest {
            env: &env,
            dirs: &dirs,
            host: &host,
            layout: &layout,
            git: &git,
            tree: oid("HEAD^{tree}"),
            tier: tollgate::config::Tier::Fast,
            tip: Some(oid("HEAD")),
            base: Some(Base {
                tree: oid(&format!("{base}^{{tree}}")),
                commit: Some(oid(base)),
            }),
            refname: "refs/heads/main".into(),
            allow_reuse: true,
            priority: tollgate::locks::Priority::Hook,
            rerun: false,
        })
        .unwrap()
    };
    let forged = plan_on(&x);
    assert!(!forged.spec.select, "{:?}", forged.spec.select_note);
    assert!(
        forged
            .spec
            .select_note
            .as_deref()
            .is_some_and(|n| n.contains("R56")),
        "{:?}",
        forged.spec.select_note
    );
    // The fetched main is on the server: selection on.
    assert!(plan_on(&main).spec.select);
}

const PASS_POLICY: &str =
    "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n";

#[test]
fn a_docs_only_change_still_needs_a_valid_policy_r64_r61() {
    let sb = Sandbox::new();
    let until = jiff::Zoned::now()
        .date()
        .checked_add(jiff::Span::new().days(60))
        .unwrap();
    let repo = trusted_repo(
        &sb,
        &format!(
            "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n[[quarantine]]\ntest = \"a tests::x\"\nuntil = \"{until}\"\nissue = \"i\"\n"
        ),
    );
    sb.commit_file(&repo, "NOTES.md", "docs\n", "docs");
    let r = sb.tollgate(&repo, &["check", "--rev", "HEAD", "--wait"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(
        r.out.contains("cause config") && r.out.contains("more than 30 days"),
        "{}",
        r.out
    );
    assert_eq!(sb.record_count(), 1, "only the config error record");
}

#[test]
fn a_cancelled_docs_only_job_writes_no_pass_r89_r61() {
    use tollgate::plan::{Base, PlanRequest};
    use tollgate::sched::{CancelOutcome, JobMeta, JobState, JobStore};

    let sb = Sandbox::new();
    let repo = trusted_repo(
        &sb,
        "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n",
    );
    sb.commit_file(&repo, "NOTES.md", "docs\n", "docs");
    let env = sb.env();
    let dirs = tollgate::dirs::Dirs::from_env(&env).unwrap();
    let host = tollgate::config::HostConfig::load(&dirs).unwrap();
    let git = tollgate::gitx::Git::scrubbed(&env, &repo);
    let layout = tollgate::gitx::RepoLayout::discover(&git).unwrap();
    let oid = |r: &str| tollgate::gitx::Oid::parse(&sb.git(&repo, &["rev-parse", r])).unwrap();
    let plan = tollgate::plan::plan(&PlanRequest {
        env: &env,
        dirs: &dirs,
        host: &host,
        layout: &layout,
        git: &git,
        tree: oid("HEAD^{tree}"),
        tier: tollgate::config::Tier::Fast,
        tip: Some(oid("HEAD")),
        base: Some(Base {
            tree: oid("HEAD~1^{tree}"),
            commit: Some(oid("HEAD~1")),
        }),
        refname: "refs/heads/main".into(),
        allow_reuse: true,
        priority: tollgate::locks::Priority::Hook,
        rerun: false,
    })
    .unwrap();
    // A queued job (as plan::start makes it), cancelled before its runner
    // gets to run.
    let spec = &plan.spec;
    let spec_json = spec.to_json().unwrap();
    let store = JobStore::new(&dirs);
    store
        .create_with(
            &JobMeta {
                id: spec.id.clone(),
                key: spec.key.clone(),
                tree: spec.tree.clone(),
                tier: spec.tier,
                origin: spec.origin.clone(),
                priority: spec.priority,
                created: spec.created,
                state: JobState::Queued,
            },
            &[("spec.json", &spec_json)],
        )
        .unwrap();
    assert_eq!(
        store.request_cancel(&spec.id).unwrap(),
        CancelOutcome::Cancelled
    );
    let r = sb.tollgate(&repo, &["__run-job", spec.id.as_str()]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(sb.record_count(), 0, "a cancelled job writes no record");
    assert_eq!(sb.report(spec.id.as_str())["outcome"], "cancelled");
}

#[test]
fn ci_mode_caps_quarantine_like_jobs_do_r69_r47() {
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n[[quarantine]]\ntest = \"a tests::x\"\nuntil = \"2099-01-01\"\nissue = \"i\"\n",
    );
    let r = sb.tollgate(&repo, &["run", "--tier", "full", "--here"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(
        r.out.contains("cause config") && r.out.contains("more than 30 days"),
        "{}",
        r.out
    );
    // A commit dated in the future does not move the cap.
    sb.commit_file(&repo, "x.txt", "x\n", "plain");
    let until = jiff::Zoned::now()
        .date()
        .checked_add(jiff::Span::new().days(40))
        .unwrap();
    let file = repo.join("tollgate.toml");
    std::fs::write(
        &file,
        format!("version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n[[quarantine]]\ntest = \"a tests::x\"\nuntil = \"{until}\"\nissue = \"i\"\n"),
    )
    .unwrap();
    sb.git(&repo, &["add", "tollgate.toml"]);
    sb.git_with(
        &repo,
        &["commit", "-q", "--no-verify", "-m", "future"],
        &[(
            "GIT_COMMITTER_DATE",
            std::ffi::OsStr::new("2099-01-01T00:00:00Z"),
        )],
    );
    let r = sb.tollgate(&repo, &["run", "--tier", "full", "--here"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(r.out.contains("more than 30 days"), "{}", r.out);
}

#[test]
fn tool_probes_see_the_trees_toolchain_not_the_worktrees_r74_r51() {
    let sb = Sandbox::new();
    let bin = sb.root().join("fakebin");
    let log = sb.root().join("probe-cwds");
    // A rustup stand-in: proxies dispatch on argv[0] and pick the channel
    // from the nearest rust-toolchain.toml above the working dir.
    support::write_exe(
        &bin.join("rustup"),
        &format!(
            r#"#!/bin/sh
echo "$PWD" >> "{}"
d=$PWD; ch=default
while :; do
  if [ -f "$d/rust-toolchain.toml" ]; then ch=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$d/rust-toolchain.toml"); break; fi
  [ "$d" = / ] && break
  d=$(dirname "$d")
done
echo "$(basename "$0") $ch"
"#,
            log.display()
        ),
    );
    for name in ["rustc", "cargo", "cargo-nextest"] {
        std::os::unix::fs::symlink("rustup", bin.join(name)).unwrap();
    }
    host(
        &sb,
        &format!("[job]\npath_prepend = [\"{}\"]\n", bin.display()),
    );
    // Only command steps: the detected Rust root still puts the toolchain
    // into the fingerprint (R74).
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n",
    );
    sb.commit_file(&repo, "Cargo.toml", "[workspace]\n", "cargo");
    // An untracked toolchain file in the agent's checkout is not T's.
    std::fs::write(
        repo.join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.85\"\n",
    )
    .unwrap();
    let rustc = |r: &support::Run| {
        assert_eq!(r.code, Some(0), "{}", r.out);
        let spec = std::fs::read(
            sb.state()
                .join("jobs")
                .join(job_id(&r.out))
                .join("spec.json"),
        )
        .unwrap();
        let spec: serde_json::Value = serde_json::from_slice(&spec).unwrap();
        spec["fingerprint"]["rustc"]
            .as_str()
            .unwrap_or("none")
            .to_owned()
    };
    let first = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
    assert_eq!(rustc(&first), "rustc default");
    std::fs::remove_file(repo.join("rust-toolchain.toml")).unwrap();
    sb.commit_file(
        &repo,
        "rust-toolchain.toml",
        "[toolchain]\nchannel = \"1.90\"\n",
        "toolchain",
    );
    let pinned = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
    assert_eq!(rustc(&pinned), "rustc 1.90");
    // Another rev gets its own tree's toolchain, not the checkout's.
    let older = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD~1", "--rerun"]);
    assert_eq!(rustc(&older), "rustc default");
    // R51: no probe ran in the agent's checkout.
    let cwds = std::fs::read_to_string(&log).unwrap();
    assert!(
        !cwds
            .lines()
            .any(|l| std::path::Path::new(l).starts_with(&repo)),
        "{cwds}"
    );
}

/// R51, item 7: the version probe of the plan (hook context) never runs a
/// tool that the tree chooses. A toolchain file with `path = ...` makes
/// rustup run `<path>/bin/rustc`: refused. A symlinked toolchain file is
/// written as the regular file it names in the same tree; one that leaves
/// the tree is refused. The probe dir never holds a symlink.
#[test]
fn the_toolchain_probe_runs_no_tool_the_tree_chooses_r51_r74() {
    let sb = Sandbox::new();
    let bin = sb.root().join("fakebin");
    // A rustup stand-in that honors `path` and `channel` as rustup does.
    support::write_exe(
        &bin.join("rustup"),
        r#"#!/bin/sh
d=$PWD; ch=default
while :; do
  f="$d/rust-toolchain.toml"
  if [ -f "$f" ]; then
    p=$(sed -n 's/^path *= *"\(.*\)"/\1/p' "$f")
    [ -n "$p" ] && exec "$p/bin/$(basename "$0")" "$@"
    ch=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$f"); break
  fi
  [ "$d" = / ] && break
  d=$(dirname "$d")
done
echo "$(basename "$0") $ch"
"#,
    );
    for name in ["rustc", "cargo", "cargo-nextest"] {
        std::os::unix::fs::symlink("rustup", bin.join(name)).unwrap();
    }
    host(
        &sb,
        &format!("[job]\npath_prepend = [\"{}\"]\n", bin.display()),
    );
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n",
    );
    sb.commit_file(&repo, "Cargo.toml", "[workspace]\n", "cargo");
    // A "toolchain" whose rustc only leaves a mark.
    let evil = sb.root().join("evil");
    let mark = sb.root().join("evil-ran");
    for name in ["rustc", "cargo", "cargo-nextest"] {
        support::write_exe(
            &evil.join("bin").join(name),
            &format!("#!/bin/sh\ntouch '{}'\necho {name} evil\n", mark.display()),
        );
    }
    let fp = |r: &support::Run| -> String {
        let spec = std::fs::read(
            sb.state()
                .join("jobs")
                .join(job_id(&r.out))
                .join("spec.json"),
        )
        .unwrap();
        let spec: serde_json::Value = serde_json::from_slice(&spec).unwrap();
        spec["fingerprint"]["rustc"]
            .as_str()
            .unwrap_or("none")
            .to_owned()
    };
    sb.commit_file(
        &repo,
        "rust-toolchain.toml",
        &format!("[toolchain]\npath = \"{}\"\n", evil.display()),
        "path toolchain",
    );
    let r = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
    assert_ne!(r.code, Some(0), "{}", r.out);
    assert!(r.out.contains("path"), "{}", r.out);
    assert!(!mark.exists(), "the plan ran the tree's toolchain");
    // Item 28: only plain shapes are read; a key tollgate does not know
    // and a legacy file of several lines are refused.
    for (file, text, why) in [
        (
            "rust-toolchain.toml",
            "[toolchain]\nchannel = \"1.91\"\nfoo = \"x\"\n",
            "toolchain.foo",
        ),
        ("rust-toolchain", "stable\nnightly\n", "several lines"),
    ] {
        let _ = std::fs::remove_file(repo.join("rust-toolchain.toml"));
        sb.commit_file(&repo, file, text, "odd toolchain");
        let r = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
        assert_ne!(r.code, Some(0), "{}", r.out);
        assert!(
            r.out.contains(why) && r.out.contains("item 28"),
            "{}",
            r.out
        );
        sb.git(&repo, &["rm", "-q", file]);
        sb.git(&repo, &["commit", "-q", "--no-verify", "-m", "rm"]);
    }
    // A link out of the tree is refused.
    let outside = sb.root().join("outside.toml");
    std::fs::write(&outside, "[toolchain]\nchannel = \"outside\"\n").unwrap();
    std::os::unix::fs::symlink(&outside, repo.join("rust-toolchain.toml")).unwrap();
    sb.git(&repo, &["add", "rust-toolchain.toml"]);
    sb.git(&repo, &["commit", "-q", "--no-verify", "-m", "link out"]);
    let r = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
    assert_ne!(r.code, Some(0), "{}", r.out);
    assert!(r.out.contains("rust-toolchain.toml"), "{}", r.out);
    // A link to a file of the same tree reads as that file.
    sb.commit_file(
        &repo,
        "tools/tc.toml",
        "[toolchain]\nchannel = \"1.91\"\n",
        "tc",
    );
    std::fs::remove_file(repo.join("rust-toolchain.toml")).unwrap();
    std::os::unix::fs::symlink("tools/tc.toml", repo.join("rust-toolchain.toml")).unwrap();
    sb.git(&repo, &["add", "rust-toolchain.toml"]);
    sb.git(&repo, &["commit", "-q", "--no-verify", "-m", "link in"]);
    let r = sb.tollgate(&repo, &["check", "--wait", "--rev", "HEAD"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(fp(&r), "rustc 1.91");
    assert!(!mark.exists());
    for e in std::fs::read_dir(sb.state().join("probe"))
        .unwrap()
        .flatten()
    {
        for f in std::fs::read_dir(e.path()).into_iter().flatten().flatten() {
            assert!(
                !f.file_type().unwrap().is_symlink(),
                "{}",
                f.path().display()
            );
        }
    }
}

#[test]
fn a_dead_runner_leaves_no_step_and_no_free_slot_behind_r35_r85() {
    let sb = Sandbox::new();
    host(&sb, "[resources]\ncpu = 1\n");
    // The leader shell and a child that stays: the child must keep the
    // slot (and the checkout) until it is reaped.
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"s\"\nkind = \"command\"\nresources = [\"cpu\"]\nrun = '''\ntest -e a.txt && exit 0\necho $$ > $TMPDIR/../leader\nsh -c 'echo $$ > $TMPDIR/../child; exec sleep 30' &\nwait\n'''\n",
    );
    let r = sb.tollgate(&repo, &["check", "--detach"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let job = job_id(&r.out);
    let dir = sb.state().join("jobs").join(&job);
    assert!(eventually(20, || !pids(&dir.join("child")).is_empty()));
    let leader = pids(&dir.join("leader"))[0];
    let child = pids(&dir.join("child"))[0];
    let runner = pids(&dir.join("runner.pid"))[0];
    tollgate::procs::signal(runner, libc::SIGKILL).unwrap();
    // R35: the leader dies with the runner (parent-death signal).
    assert!(
        eventually(10, || !alive(leader)),
        "leader survived the runner"
    );
    assert!(alive(child));
    // R85: the slot stays taken while a step process lives.
    let slot = sb.state().join("locks/cpu/slot-0");
    assert!(tollgate::locks::is_held(&slot).unwrap(), "slot freed early");

    // The next job of this worktree finds the checkout held by the dead
    // job's leftover and reaps it.
    std::fs::write(repo.join("a.txt"), "x").unwrap();
    sb.git(&repo, &["add", "a.txt"]);
    let next = sb.tollgate(&repo, &["check", "--wait"]);
    assert_eq!(next.code, Some(0), "{}", next.out);
    assert!(eventually(10, || !alive(child)), "leftover not reaped");
    assert!(!tollgate::locks::is_held(&slot).unwrap());
    let w = sb.tollgate(&repo, &["wait", &job, "--timeout", "10s"]);
    assert_eq!(w.code, Some(1), "{}", w.out);
    assert!(w.out.contains("lost"), "{}", w.out);
}

#[test]
fn waiting_on_a_dead_runner_reaps_its_steps_r35() {
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"s\"\nkind = \"command\"\nrun = '''\nsh -c 'echo $$ > $TMPDIR/../child; exec sleep 30' &\nwait\n'''\n",
    );
    let r = sb.tollgate(&repo, &["check", "--detach"]);
    let job = job_id(&r.out);
    let dir = sb.state().join("jobs").join(&job);
    assert!(eventually(20, || !pids(&dir.join("child")).is_empty()));
    let child = pids(&dir.join("child"))[0];
    tollgate::procs::signal(pids(&dir.join("runner.pid"))[0], libc::SIGKILL).unwrap();
    let w = sb.tollgate(&repo, &["wait", &job, "--timeout", "20s"]);
    assert_eq!(w.code, Some(1), "{}", w.out);
    assert!(
        w.out.contains("runner is gone") && w.out.contains("killed"),
        "{}",
        w.out
    );
    assert!(eventually(10, || !alive(child)));
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("job.json")).unwrap()).unwrap();
    assert_eq!(meta["state"], "lost", "{meta}");
    // cancel on a lost job only reports.
    let c = sb.tollgate(&repo, &["cancel", &job]);
    assert_eq!(c.code, Some(0), "{}", c.out);
}

/// Item 49 (R35): a step process that drops the job's `TMPDIR` and stays
/// in the step's group carries no marker. When the runner dies, the
/// leader dies with it (Linux) and the group has no marked member, so the
/// marker alone finds nothing; the step record (leader pid, start time,
/// group) still names the group. This is how a dead runner's steps are
/// found on macOS, which has no parent-death signal and no environment
/// of other processes.
#[test]
fn a_dead_runners_unmarked_step_process_is_reaped_by_its_step_record_r35() {
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"s\"\nkind = \"command\"\nrun = '''\nd=$TMPDIR/..\nenv -u TMPDIR sh -c 'echo $$ > \"$0\"/child; exec sleep 30' \"$d\" &\nwait\n'''\n",
    );
    let r = sb.tollgate(&repo, &["check", "--detach"]);
    let job = job_id(&r.out);
    let dir = sb.state().join("jobs").join(&job);
    assert!(eventually(20, || !pids(&dir.join("child")).is_empty()));
    let child = pids(&dir.join("child"))[0];
    tollgate::procs::signal(pids(&dir.join("runner.pid"))[0], libc::SIGKILL).unwrap();
    let w = sb.tollgate(&repo, &["wait", &job, "--timeout", "20s"]);
    let gone = eventually(10, || !alive(child));
    if !gone {
        let _ = tollgate::procs::signal(child, libc::SIGKILL);
    }
    assert_eq!(w.code, Some(1), "{}", w.out);
    assert!(
        gone,
        "the unmarked step process outlived its dead runner: {}",
        w.out
    );
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("job.json")).unwrap()).unwrap();
    assert_eq!(meta["state"], "lost", "{meta}");
}

#[test]
fn an_unchecked_or_empty_base_disables_selection_r56() {
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = sb.root().join("r");
    std::fs::create_dir_all(&repo).unwrap();
    sb.git(&repo, &["init", "-q"]);
    sb.commit_file(
        &repo,
        "tollgate.toml",
        "version = 1\n[[step]]\nname = \"b-only\"\nkind = \"command\"\nrun = \"true\"\nwhen = [\"b/**\"]\n",
        "root: policy",
    );
    sb.commit_file(&repo, "README", "x\n", "unchecked");
    let status = |out: &str| {
        let rep = sb.report(&job_id(out));
        let s = rep["steps"].as_array().unwrap()[0]["status"]
            .as_str()
            .unwrap()
            .to_owned();
        let log =
            std::fs::read_to_string(sb.state().join("jobs").join(job_id(out)).join("job.log"))
                .unwrap_or_default();
        (s, log)
    };
    // Root commit: the base is the empty tree; selection off, the step runs.
    let root = sb.git(&repo, &["rev-list", "--max-parents=0", "HEAD"]);
    let r = sb.tollgate(&repo, &["check", "--rev", &root, "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let (s, log) = status(&r.out);
    assert_eq!(s, "pass", "{log}");
    assert!(log.contains("the base is the empty tree (R56)"), "{log}");
    // The root commit is checked now; HEAD is not. A change in a/ on top
    // of the unchecked HEAD runs the step too.
    sb.commit_file(&repo, "a/x", "1\n", "a on top of an unchecked base");
    let r = sb.tollgate(&repo, &["check", "--rev", "HEAD", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let (s, log) = status(&r.out);
    assert_eq!(s, "pass", "{log}");
    assert!(log.contains("the base has no record"), "{log}");
    // On a checked base, the same kind of change skips the step.
    sb.commit_file(&repo, "a/x", "2\n", "a on top of a checked base");
    let r = sb.tollgate(&repo, &["check", "--rev", "HEAD", "--wait"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let (s, log) = status(&r.out);
    assert_eq!(s, "skipped", "{log}");
}

/// L20: a report names the resources each step took and how long it
/// waited for them (R85), and how long the job waited for its verify
/// checkout (R87), so `tollgate bench` can report queue wait per resource.
#[test]
fn reports_record_queue_wait_per_resource_and_for_the_checkout_r85_r87_l20() {
    let sb = Sandbox::new();
    host(&sb, "[resources]\ncpu = 1\n");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"busy\"\nkind = \"command\"\nresources = [\"cpu\"]\nrun = \"true\"\n[[step]]\nname = \"free\"\nkind = \"command\"\nrun = \"true\"\n",
    );
    // This test holds the only cpu slot until the job waits in its queue.
    let lock_dir = sb.state().join("locks/cpu");
    std::fs::create_dir_all(&lock_dir).unwrap();
    let held = tollgate::locks::LockFile::try_acquire(&lock_dir.join("slot-0"))
        .unwrap()
        .expect("the slot is free");
    let r = sb.tollgate(&repo, &["check", "--detach"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let job = job_id(&r.out);
    let waiting = || {
        std::fs::read_dir(lock_dir.join("queue")).is_ok_and(|rd| {
            rd.flatten()
                .any(|e| !e.file_name().to_string_lossy().starts_with('.'))
        })
    };
    assert!(eventually(20, waiting), "the job never queued for cpu");
    std::thread::sleep(Duration::from_millis(300));
    drop(held);
    let w = sb.tollgate(&repo, &["wait", &job, "--timeout", "30s"]);
    assert_eq!(w.code, Some(0), "{}", w.out);
    let rep = sb.report(&job);
    let busy = &rep["steps"][0];
    assert_eq!(busy["name"], "busy", "{rep}");
    assert_eq!(busy["resources"], serde_json::json!(["cpu"]), "{rep}");
    let waited = busy["queue_ms"].as_u64().expect("queue_ms");
    assert!(waited >= 300, "waited {waited} ms: {rep}");
    // A step that takes no resource has no queue entry.
    let free = &rep["steps"][1];
    assert_eq!(free["name"], "free", "{rep}");
    assert!(free.get("resources").is_none(), "{rep}");
    assert!(free.get("queue_ms").is_none(), "{rep}");
    // Nobody else held the checkout.
    let checkout = rep["checkout_wait_ms"].as_u64().expect("checkout_wait_ms");
    assert!(checkout < 300, "checkout wait {checkout} ms: {rep}");
}

/// The R104 refusal, line by line.
const R104_LINES: [&str; 3] = [
    "tollgate: check --tier full is not started by hand in an agent session (R104).",
    "tollgate: a push of, or a merge into, a full ref (main) starts the full tier and reuses its result; a branch push needs only fast (R107). Results so far: tollgate status.",
    "tollgate: after a stored fail: tollgate check --tier full --rev HEAD --rerun (runs only the steps that did not pass).",
];

const SESSION: &[(&str, &str)] = &[("CLAUDECODE", "1")];

fn refused_r104(r: &support::Run) {
    assert_eq!(r.code, Some(2), "{}", r.out);
    for line in R104_LINES {
        assert!(r.out.contains(line), "{line:?} in {}", r.out);
    }
}

/// R104: in an agent session `check --tier full` creates no job (also
/// `--detach`, and `--rerun` with a stored pass); outside a session it
/// runs; a stored full pass still answers; `check` (fast) runs.
#[test]
fn a_session_does_not_start_the_full_tier_by_hand_r104() {
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = repo_with(&sb, "r", PASS_TOML);
    let full = ["check", "--tier", "full", "--rev", "HEAD", "--wait"];
    let r = sb.tollgate_with(&repo, &full, SESSION);
    refused_r104(&r);
    let detach = ["check", "--tier", "full", "--rev", "HEAD", "--detach"];
    refused_r104(&sb.tollgate_with(&repo, &detach, SESSION));
    refused_r104(&sb.tollgate_with(&repo, &full, &[("CLAUDE_CODE_ENTRYPOINT", "cli")]));
    // Without --rev the hint keeps a placeholder.
    let r = sb.tollgate_with(&repo, &["check", "--tier", "full", "--wait"], SESSION);
    assert!(
        r.out.contains("--tier full --rev <rev> --rerun"),
        "{}",
        r.out
    );
    assert!(sb.jobs().is_empty(), "{:?}", sb.jobs());
    // `fast` in a session runs.
    let r = sb.tollgate_with(&repo, &["check", "--rev", "HEAD", "--wait"], SESSION);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(sb.jobs().len(), 1);
    // Outside a session the full check runs.
    let r = sb.tollgate(&repo, &full);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(sb.jobs().len(), 2);
    // Its stored pass answers in a session, with no job.
    let r = sb.tollgate_with(&repo, &full, SESSION);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(r.out.contains("PASS"), "{}", r.out);
    // `--rerun` of a stored pass is refused; the record stays.
    let rerun = [
        "check", "--tier", "full", "--rev", "HEAD", "--wait", "--rerun",
    ];
    refused_r104(&sb.tollgate_with(&repo, &rerun, SESSION));
    assert_eq!(sb.jobs().len(), 2);
    assert_eq!(sb.record_count(), 2);
}

const PASS_TOML: &str =
    "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n";

/// R104: after a stored full fail, a session may `--rerun` (the command
/// the hook's deny gives); without `--rerun` it gets the stored fail.
#[test]
fn a_session_may_rerun_a_stored_full_fail_r104() {
    let sb = Sandbox::new();
    let mark = sb.root().join("mark");
    host(&sb, &format!("[job.env]\nMARK = \"{}\"\n", mark.display()));
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"once\"\nkind = \"command\"\nrun = 'test -e \"$MARK\" || { touch \"$MARK\"; exit 1; }'\n",
    );
    let full = ["check", "--tier", "full", "--rev", "HEAD", "--wait"];
    let r = sb.tollgate(&repo, &full);
    assert_eq!(r.code, Some(1), "{}", r.out);
    let r = sb.tollgate_with(&repo, &full, SESSION);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(r.out.contains("stored fail"), "{}", r.out);
    assert_eq!(sb.jobs().len(), 1);
    let rerun = [
        "check", "--tier", "full", "--rev", "HEAD", "--wait", "--rerun",
    ];
    let r = sb.tollgate_with(&repo, &rerun, SESSION);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(sb.jobs().len(), 2);
}

/// R104: a session attaches to a full job that already runs for the key
/// and waits for it.
#[test]
fn a_session_attaches_to_a_running_full_job_r104() {
    let sb = Sandbox::new();
    host(&sb, "");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"slow\"\nkind = \"command\"\nrun = \"sleep 2\"\n",
    );
    let r = sb.tollgate(
        &repo,
        &["check", "--tier", "full", "--rev", "HEAD", "--detach"],
    );
    assert_eq!(r.code, Some(0), "{}", r.out);
    let job = job_id(&r.out);
    let r = sb.tollgate_with(
        &repo,
        &["check", "--tier", "full", "--rev", "HEAD", "--wait"],
        SESSION,
    );
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        r.out.contains(&format!("attached to running job {job}")),
        "{}",
        r.out
    );
    assert_eq!(sb.jobs(), vec![job]);
}

/// R104: host `[session] full_check = "allow"` lets a session start it.
#[test]
fn the_host_config_can_allow_full_checks_in_a_session_r104() {
    let sb = Sandbox::new();
    host(&sb, "[session]\nfull_check = \"allow\"\n");
    let repo = repo_with(&sb, "r", PASS_TOML);
    let r = sb.tollgate_with(
        &repo,
        &["check", "--tier", "full", "--rev", "HEAD", "--wait"],
        SESSION,
    );
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(sb.jobs().len(), 1);
}

/// R74, R103: the fingerprint holds what a job reads from `tollgate.toml`
/// (its effective config), not the file's blob. A comment or an
/// `[[expensive]]` entry in the policy file keeps the record key (the next
/// check of the same tree is a record hit); a changed step `run` and a
/// changed other policy file (`.config/nextest.toml`) still give a new key.
#[test]
fn only_what_jobs_read_from_the_policy_file_is_in_the_key_r74_r103() {
    let sb = Sandbox::new();
    host(&sb, "");
    let policy = "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n";
    let repo = repo_with(&sb, "r", policy);
    sb.commit_file(&repo, "x", "1\n", "x");
    let tree = sb.git(&repo, &["rev-parse", "HEAD^{tree}"]);
    // `--tree T` at a HEAD whose own policy (no anchor: the tip's) moves.
    let check = ["check", "--tier", "full", "--tree", &tree, "--wait"];
    let r = sb.tollgate(&repo, &check);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let hit = |what: &str| {
        let jobs = sb.jobs().len();
        let r = sb.tollgate(&repo, &check);
        assert_eq!(r.code, Some(0), "{what}: {}", r.out);
        sb.jobs().len() == jobs
    };
    sb.commit_file(
        &repo,
        "tollgate.toml",
        &format!("# a comment\n{policy}"),
        "comment",
    );
    assert!(hit("comment"), "a comment keeps the key");
    sb.commit_file(
        &repo,
        "tollgate.toml",
        &format!(
            "# a comment\n{policy}[[expensive]]\nname = \"suite\"\nprogram = \"scripts/e2e.sh\"\nhint = \"scripts/e2e.sh <file>\"\n"
        ),
        "expensive",
    );
    assert!(hit("expensive"), "an [[expensive]] entry keeps the key");
    sb.commit_file(
        &repo,
        "tollgate.toml",
        &policy.replace("run = \"true\"", "run = \"true \""),
        "run",
    );
    assert!(!hit("run"), "a changed step run gives a new key");
    sb.commit_file(
        &repo,
        ".config/nextest.toml",
        "[profile.default]\n",
        "nextest",
    );
    assert!(!hit("nextest"), "another policy file gives a new key");
}

/// R101: `check --rerun --all` that attaches to a running job which may
/// take steps from the same tree does not take its report: it waits, then
/// runs its own job with every step.
#[test]
fn rerun_all_does_not_take_an_attached_carrying_job_r101() {
    let sb = Sandbox::new();
    let counter = sb.root().join("count");
    host(
        &sb,
        &format!("[job.env]\nCOUNT = \"{}\"\n", counter.display()),
    );
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"slow\"\nkind = \"command\"\nrun = 'sleep 2; echo slow >> \"$COUNT\"'\n",
    );
    let r = sb.tollgate(
        &repo,
        &["check", "--tier", "full", "--rev", "HEAD", "--detach"],
    );
    assert_eq!(r.code, Some(0), "{}", r.out);
    let first = job_id(&r.out);
    let r = sb.tollgate(
        &repo,
        &[
            "check", "--tier", "full", "--rev", "HEAD", "--wait", "--rerun", "--all",
        ],
    );
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        r.out.contains(&format!("attached to running job {first}")),
        "{}",
        r.out
    );
    assert_eq!(sb.jobs().len(), 2, "{}", r.out);
    assert_eq!(runs(&counter, "slow"), 2, "{}", r.out);
}

/// R104: a stored full fail of the tree under another key (here another
/// host config, so another fingerprint) still allows a session's
/// `--rerun`, which the hook's deny names (with no non-pass at all it is
/// refused: `a_session_does_not_start_the_full_tier_by_hand_r104`).
#[test]
fn a_session_may_rerun_a_full_fail_stored_under_another_key_r104() {
    let sb = Sandbox::new();
    let mark = sb.root().join("mark");
    let host_a = format!("[job.env]\nMARK = \"{}\"\n", mark.display());
    host(&sb, &host_a);
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"once\"\nkind = \"command\"\nrun = 'test -e \"$MARK\" || { touch \"$MARK\"; exit 1; }'\n",
    );
    let full = ["check", "--tier", "full", "--rev", "HEAD", "--wait"];
    let r = sb.tollgate(&repo, &full);
    assert_eq!(r.code, Some(1), "{}", r.out);
    // Another host config: another key for the same tree, with no record.
    host(&sb, &format!("# changed\n{host_a}"));
    let rerun = [
        "check", "--tier", "full", "--rev", "HEAD", "--wait", "--rerun",
    ];
    let r = sb.tollgate_with(&repo, &rerun, SESSION);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(sb.jobs().len(), 2);
}
