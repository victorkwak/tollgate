//! Git hooks end to end: real git runs the hard-linked binary through the
//! `core.hooksPath` injection (T2-T4, T13, T14, T18, T19, R1, R2, R5-R7,
//! R14, R17, R20, R22, R31, R32, R37, R99, L1, L4, L17).

mod support;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use support::{Armed, HOOK_NAMES, Sandbox, eventually, job_id, test_hooks_dir, write_exe};

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

/// T3 variant (R7): git runs an executable hook with no `#!` line through
/// /bin/sh; tollgate's chaining must too, with the same args and stdin.
#[test]
fn a_repo_hook_without_a_shebang_runs_through_sh_t3_r7() {
    let sb = Sandbox::new();
    let (repo, _bare) = trusted_repo(&sb, PASS);
    for name in ["pre-commit", "post-commit", "commit-msg"] {
        write_exe(
            &repo.join(".githooks").join(name),
            &format!("echo REPO-{name} \"$#\" >&2\n"),
        );
    }
    write_exe(
        &repo.join(".githooks/pre-push"),
        "echo REPO-pre-push \"$1\" >&2\nwhile read l; do echo \"STDIN $l\" >&2; done\n",
    );
    sb.git(&repo, &["config", "core.hooksPath", ".githooks"]);
    stage(&sb, &repo, "a.txt", "1\n");
    let r = sb.hooked(&repo, &["commit", "-m", "a"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    for want in [
        "REPO-pre-commit 0",
        "REPO-commit-msg 1",
        "REPO-post-commit 0",
        "tollgate: pass pre-commit",
    ] {
        assert!(r.out.contains(want), "no {want:?} in:\n{}", r.out);
    }
    assert!(!r.out.contains("Exec format error"), "{}", r.out);
    let r = sb.hooked(&repo, &["push", "-q", "origin", "main"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(r.out.contains("REPO-pre-push origin"), "{}", r.out);
    assert!(r.out.contains("STDIN refs/heads/main "), "{}", r.out);
    // Its failure is the hook's failure (R7).
    write_exe(
        &repo.join(".githooks/pre-commit"),
        "echo REPO-NO >&2\nexit 4\n",
    );
    stage(&sb, &repo, "b.txt", "1\n");
    let before = head(&sb, &repo);
    let r = sb.hooked(&repo, &["commit", "-m", "b"]);
    assert_ne!(r.code, Some(0), "{}", r.out);
    assert!(r.out.contains("REPO-NO"), "{}", r.out);
    assert_eq!(head(&sb, &repo), before);
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
    support::backdate(&lock, 300);
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
    sb.scoped_host(&format!(
        "trusted_paths = [\"{}\"]",
        sb.root().join("remotes/trusted.git").display()
    ));
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

/// Item 33 (R4): once a repo had a trusted remote, losing it (removed, or
/// its URL changed to one that is not trusted) denies: anchors never fall
/// back to the local `main`, which an agent can move. A rename keeps the
/// URL and stays trusted; emptying the record (`tollgate remotes forget`,
/// from your own terminal) accepts the change.
#[test]
fn a_lost_trusted_remote_denies_instead_of_local_anchors_item33() {
    let sb = Sandbox::new();
    let (repo, bare) = trusted_repo(&sb, PASS);
    let commit = |name: &str| {
        stage(&sb, &repo, &format!("{name}.txt"), "1\n");
        sb.hooked(&repo, &["commit", "-m", name])
    };
    // A gated commit records origin as trusted for this repo.
    let r = commit("a");
    assert_eq!(r.code, Some(0), "{}", r.out);
    // Renamed: same URL, still trusted.
    sb.git(&repo, &["remote", "rename", "origin", "upstream"]);
    sb.git(&repo, &["fetch", "-q", "upstream"]);
    let r = commit("b");
    assert_eq!(r.code, Some(0), "{}", r.out);
    // Its URL changed to a repo that is not trusted.
    let other = sb.root().join("other.git");
    sb.git(
        &sb.root(),
        &["init", "-q", "--bare", other.to_str().unwrap()],
    );
    sb.git(
        &repo,
        &["remote", "set-url", "upstream", other.to_str().unwrap()],
    );
    let r = commit("c");
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(
        r.out.contains("item 33") && r.out.contains(bare.to_str().unwrap()),
        "{}",
        r.out
    );
    // Removed: the same.
    sb.git(&repo, &["remote", "remove", "upstream"]);
    let r = commit("c");
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(r.out.contains("item 33"), "{}", r.out);
    // Back with its URL: allowed again.
    sb.git(&repo, &["remote", "add", "origin", bare.to_str().unwrap()]);
    sb.git(&repo, &["fetch", "-q", "origin"]);
    let r = commit("c");
    assert_eq!(r.code, Some(0), "{}", r.out);
    // Removed again; `tollgate remotes forget` accepts it, at a terminal
    // only: without one (an agent's Bash) it refuses and nothing changes.
    sb.git(&repo, &["remote", "remove", "origin"]);
    let r = sb.tollgate(&repo, &["remotes", "forget"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(r.out.contains("interactive terminal"), "{}", r.out);
    let r = commit("d");
    assert_eq!(r.code, Some(1), "{}", r.out);
    // At a terminal (util-linux `script` gives one): "n" keeps the
    // record, "y" removes it and local anchors count again.
    if cfg!(target_os = "linux") && Path::new("/usr/bin/script").exists() {
        let at_terminal_with = |answer: &str, extra: &[(&str, &str)]| {
            let mut cmd = std::process::Command::new("/usr/bin/script");
            cmd.env_clear()
                .current_dir(&repo)
                .args([
                    "-qec",
                    &format!("{} remotes forget", support::BIN),
                    "/dev/null",
                ])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            for (k, v) in sb.env().iter() {
                cmd.env(k, v);
            }
            for (k, v) in extra {
                cmd.env(k, v);
            }
            let mut child = cmd.spawn().unwrap();
            std::io::Write::write_all(child.stdin.as_mut().unwrap(), answer.as_bytes()).unwrap();
            let out = child.wait_with_output().unwrap();
            (
                out.status.code(),
                String::from_utf8_lossy(&out.stdout).into_owned(),
            )
        };
        let at_terminal = |answer: &str| at_terminal_with(answer, &[]);
        // A terminal an agent made (script here, dtach or faketty in a
        // session) inside a Claude Code session: refused, the record
        // stays (review note 1).
        let (code, out) = at_terminal_with("y\n", &[("CLAUDECODE", "1")]);
        assert_eq!(code, Some(1), "{out}");
        assert!(out.contains("Claude Code session"), "{out}");
        assert_eq!(commit("d").code, Some(1));
        let (code, out) = at_terminal("n\n");
        assert_eq!(code, Some(2), "{out}");
        assert!(out.contains(bare.to_str().unwrap()), "{out}");
        assert_eq!(commit("d").code, Some(1));
        let (code, out) = at_terminal("y\n");
        assert_eq!(code, Some(0), "{out}");
        let r = commit("d");
        assert_eq!(r.code, Some(0), "{}", r.out);
    }
}

#[test]
fn a_full_miss_is_allowed_for_the_trusted_remote_tip_r14() {
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
    sb.git(&repo, &["fetch", "-q", "origin"]);
    // A merge commit on main whose tree is the trusted main's tree: no job
    // (R14 outcome 2 for merges, L1).
    let r = sb.hooked(&repo, &["merge", "--no-ff", "--no-edit", "origin/main"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        r.out.contains("pre-merge-commit refs/heads/main")
            && r.out.contains("remote-verified (R14)"),
        "{}",
        r.out
    );
    assert!(sb.jobs().is_empty());
    // Handoff of the trusted main to an untrusted remote: main needs full;
    // the pushed commit is the trusted remote's main (ls-remote), no job.
    let mac = sb.root().join("mac.git");
    sb.git(&sb.root(), &["init", "-q", "--bare", mac.to_str().unwrap()]);
    sb.git(&repo, &["remote", "add", "mac", mac.to_str().unwrap()]);
    let r = sb.hooked(&repo, &["push", "-q", "mac", "origin/main:refs/heads/main"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        r.out.contains("pre-push refs/heads/main") && r.out.contains("remote-verified (R14)"),
        "{}",
        r.out
    );
    assert!(sb.jobs().is_empty());
    // The local merge commit is not on the trusted remote: a full job.
    let r = sb.hooked(&repo, &["push", "-q", "mac", "main"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(!r.out.contains("remote-verified"), "{}", r.out);
    assert_eq!(tiers_of_jobs(&sb), ["full"]);
    // A forged remote-tracking ref is only a hint: ls-remote decides.
    sb.commit_file(&repo, "l.txt", "1\n", "local");
    let local = head(&sb, &repo);
    sb.git(&repo, &["update-ref", "refs/remotes/origin/main", &local]);
    let r = sb.hooked(&repo, &["push", "-q", "mac", "main"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(!r.out.contains("remote-verified"), "{}", r.out);
    assert_eq!(tiers_of_jobs(&sb), ["full", "full"]);
}

/// R14(2), R5, R20: trust follows the URL git really uses. A local
/// `url.<x>.insteadOf` that sends the trusted origin to a repo the agent
/// controls must not make `ls-remote` vouch for a failing main, and a
/// `pushInsteadOf` must not turn a push to the trusted origin into a push
/// that needs only `fast`.
#[test]
fn url_rewrites_do_not_move_remote_trust_r14_r5_r20() {
    let sb = Sandbox::new();
    let (repo, bare) = trusted_repo(
        &sb,
        "version = 1\n[push]\nfast_refs = []\n[[step]]\nname = \"lint\"\nkind = \"command\"\nrun = \"test ! -f bad\"\n",
    );
    let bare_s = bare.to_str().unwrap();
    // A failing main made without hooks (as Victor's terminal could).
    sb.commit_file(&repo, "bad", "x\n", "bad");
    let fake = sb.root().join("fake.git");
    sb.git(
        &sb.root(),
        &["init", "-q", "--bare", fake.to_str().unwrap()],
    );
    sb.git(&fake, &["fetch", "-q", repo.to_str().unwrap(), "main:main"]);
    sb.git(
        &repo,
        &[
            "config",
            &format!("url.{}.insteadOf", fake.display()),
            bare_s,
        ],
    );
    sb.git(&repo, &["fetch", "-q", "origin"]);
    let mac = sb.root().join("mac.git");
    sb.git(&sb.root(), &["init", "-q", "--bare", mac.to_str().unwrap()]);
    sb.git(&repo, &["remote", "add", "mac", mac.to_str().unwrap()]);
    let r = sb.hooked(&repo, &["push", "-q", "mac", "main"]);
    assert_ne!(r.code, Some(0), "{}", r.out);
    assert!(!r.out.contains("remote-verified"), "{}", r.out);
    assert!(
        r.out.contains("remote origin") && r.out.contains("insteadOf"),
        "{}",
        r.out
    );
    assert_eq!(
        sb.git_output(
            &mac,
            &["rev-parse", "-q", "--verify", "refs/heads/main"],
            &[]
        )
        .status
        .code(),
        Some(1),
        "main reached mac"
    );
    // A rewrite that keeps the URL inside scope.remotes is fine.
    sb.git(
        &repo,
        &[
            "config",
            "--unset",
            &format!("url.{}.insteadOf", fake.display()),
        ],
    );
    sb.git(
        &repo,
        &["fetch", "-q", "origin", "+main:refs/remotes/origin/main"],
    );
    sb.git(&repo, &["reset", "-q", "--hard", "origin/main"]);
    // pushInsteadOf: the push to origin goes to another URL, but it is
    // still a push to the trusted remote: full, not fast (R5, R20).
    let elsewhere = sb.root().join("elsewhere.git");
    sb.git(
        &sb.root(),
        &["init", "-q", "--bare", elsewhere.to_str().unwrap()],
    );
    sb.git(
        &repo,
        &[
            "config",
            &format!("url.{}.pushInsteadOf", elsewhere.display()),
            bare_s,
        ],
    );
    sb.git(&repo, &["checkout", "-q", "-b", "feat"]);
    sb.commit_file(&repo, "f.txt", "1\n", "f");
    let r = sb.hooked(&repo, &["push", "-q", "origin", "feat"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        r.out.contains("pre-push refs/heads/feat") && r.out.contains("tier full"),
        "{}",
        r.out
    );
}

/// R14, R5, L2: remote URLs are read NUL-separated, never from
/// `git remote -v` lines. A URL with a newline and a tab could add a fake
/// `origin <trusted URL> (fetch)` line, so the remote would count as
/// trusted while git fetches it from the first line's path. Such a URL,
/// and a trusted remote with more than one fetch URL, deny.
#[test]
fn remote_urls_with_control_characters_or_two_fetch_urls_deny_r14_l2() {
    let sb = Sandbox::new();
    let (repo, bare) = trusted_repo(&sb, PASS);
    let fake = sb.root().join("fake.git");
    let injected = format!("{}\norigin\t{}", fake.display(), bare.display());
    sb.git(&repo, &["config", "remote.origin.url", &injected]);
    let git = tollgate::gitx::Git::scrubbed(&sb.env(), &repo);
    let scope = tollgate::config::CompiledScope::new(
        &tollgate::config::HostConfig::from_toml(&format!(
            "[scope]\ntrusted_paths = [\"{}\"]\n",
            bare.display()
        ))
        .unwrap()
        .scope,
        &tollgate::dirs::Dirs::from_env(&sb.env()).unwrap(),
    )
    .unwrap();
    let err = tollgate::plan::remote_trust(&git, &scope).expect_err("a newline in a URL");
    assert!(
        err.to_string().contains("remote origin") && err.to_string().contains("control"),
        "{err}"
    );
    stage(&sb, &repo, "a.txt", "1\n");
    let before = head(&sb, &repo);
    let r = sb.hooked(&repo, &["commit", "-m", "a"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(r.out.contains("control character"), "{}", r.out);
    assert_eq!(head(&sb, &repo), before);

    // Two fetch URLs: git fetches the first only, ls-remote too; which
    // one counts is not worth guessing.
    sb.git(
        &repo,
        &["config", "remote.origin.url", bare.to_str().unwrap()],
    );
    sb.git(
        &repo,
        &[
            "config",
            "--add",
            "remote.origin.url",
            fake.to_str().unwrap(),
        ],
    );
    let err = tollgate::plan::remote_trust(&git, &scope).expect_err("two fetch URLs");
    assert!(err.to_string().contains("more than one fetch URL"), "{err}");
    let r = sb.hooked(&repo, &["commit", "-m", "a"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert_eq!(head(&sb, &repo), before);
    // One URL again: the commit passes.
    sb.git(
        &repo,
        &[
            "config",
            "--unset",
            "remote.origin.url",
            fake.to_str().unwrap(),
        ],
    );
    let r = sb.hooked(&repo, &["commit", "-m", "a"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
}

/// R14(2), item 11: `ls-remote <name>` reads the repo's own config, so
/// `remote.<name>.uploadpack` (or `core.sshCommand`) could make another
/// repo answer for the trusted server. tollgate asks the trusted URL from
/// outside the repo.
#[test]
fn remote_verification_ignores_the_repos_own_transport_config_r14() {
    let sb = Sandbox::new();
    let (repo, _bare) = trusted_repo(
        &sb,
        "version = 1\n[[step]]\nname = \"lint\"\nkind = \"command\"\nrun = \"test ! -f bad\"\n",
    );
    // A failing main made without hooks, and a fake repo that says the
    // trusted main is that commit.
    sb.commit_file(&repo, "bad", "x\n", "bad");
    let bad = head(&sb, &repo);
    let fake = sb.root().join("fake.git");
    sb.git(
        &sb.root(),
        &["init", "-q", "--bare", fake.to_str().unwrap()],
    );
    sb.git(&fake, &["fetch", "-q", repo.to_str().unwrap(), "main:main"]);
    let script = sb.root().join("fake-upload-pack");
    write_exe(
        &script,
        &format!("#!/bin/sh\nexec git-upload-pack '{}'\n", fake.display()),
    );
    sb.git(
        &repo,
        &[
            "config",
            "remote.origin.uploadpack",
            script.to_str().unwrap(),
        ],
    );
    sb.git(&repo, &["update-ref", "refs/remotes/origin/main", &bad]);
    let mac = sb.root().join("mac.git");
    sb.git(&sb.root(), &["init", "-q", "--bare", mac.to_str().unwrap()]);
    sb.git(&repo, &["remote", "add", "mac", mac.to_str().unwrap()]);
    let r = sb.hooked(&repo, &["push", "-q", "mac", "main"]);
    assert_ne!(r.code, Some(0), "{}", r.out);
    assert!(!r.out.contains("remote-verified"), "{}", r.out);
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

/// T19, R32, L17: a check longer than the inline cap denies with the job
/// and a retry command, and leaves the job running. The step ends only
/// when the test releases it after the hook answered, so a deny with
/// `verdict running` proves the hook did not wait for the job, whatever
/// the host's speed (runner T19 owns the wall-clock bound). Unreleased,
/// the step fails after 30 s: a hook that waits for the job then reports
/// a fail, not a running job.
#[test]
fn the_inline_budget_denies_with_the_job_and_a_retry_command_t19_r32_l17() {
    let sb = Sandbox::new();
    sb.scoped_host("");
    let release = sb.root().join("release");
    let repo = repo_with(
        &sb,
        "r",
        &format!(
            "version = 1\n[[step]]\nname = \"slow\"\nkind = \"command\"\nrun = \"for i in $(seq 600); do [ -e '{}' ] && exit 0; sleep 0.05; done; exit 1\"\n",
            release.display()
        ),
    );
    stage(&sb, &repo, "a.txt", "1\n");
    let before = head(&sb, &repo);
    let r = sb.hooked_with(
        &repo,
        &["commit", "-m", "two words"],
        &[("TOLLGATE_INLINE_CAP", "1")],
    );
    assert_eq!(r.code, Some(1), "{}", r.out);
    let job = job_id(&r.out);
    assert!(r.out.contains("verdict running"), "{}", r.out);
    let retry = format!("tollgate wait {job} && git commit -m 'two words'");
    assert!(r.out.contains(&retry), "no {retry:?} in:\n{}", r.out);
    assert_eq!(head(&sb, &repo), before);
    // The printed command works: wait, then the same commit hits the record.
    std::fs::write(&release, "").unwrap();
    let w = sb.tollgate(&repo, &["wait", &job, "--timeout", "30s"]);
    assert_eq!(w.code, Some(0), "{}", w.out);
    let r = sb.hooked(&repo, &["commit", "-m", "two words"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(r.out.contains(&format!("record of job {job}")), "{}", r.out);
    assert_eq!(sb.jobs().len(), 1);
}

/// An empty argument is an argument: the retry of `git commit
/// --allow-empty-message -m ''` keeps the `''`, or the printed command
/// would take the next flag as the message (L17, item 43).
#[test]
fn the_retry_command_keeps_an_empty_argument_l17() {
    let sb = Sandbox::new();
    sb.scoped_host("");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"slow\"\nkind = \"command\"\nrun = \"sleep 3\"\n",
    );
    stage(&sb, &repo, "a.txt", "1\n");
    let r = sb.hooked_with(
        &repo,
        &["commit", "-m", "", "--allow-empty-message"],
        &[("TOLLGATE_INLINE_CAP", "1")],
    );
    assert_eq!(r.code, Some(1), "{}", r.out);
    let job = job_id(&r.out);
    let retry = format!("tollgate wait {job} && git commit -m '' --allow-empty-message");
    assert!(r.out.contains(&retry), "no {retry:?} in:\n{}", r.out);
    let w = sb.tollgate(&repo, &["wait", &job, "--timeout", "30s"]);
    assert_eq!(w.code, Some(0), "{}", w.out);
}

/// The pid of the hook process `name` under git process `git`.
fn hook_pid(git: u32, name: &str) -> Option<i32> {
    let table = tollgate::procs::ProcTable::snapshot().ok()?;
    table
        .descendants(i32::try_from(git).ok()?)
        .into_iter()
        .find(|p| {
            tollgate::procs::argv(*p).is_some_and(|argv| {
                argv.first()
                    .is_some_and(|a| a.as_encoded_bytes().ends_with(name.as_bytes()))
            })
        })
}

/// T18, security regression S8: SIGKILL or SIGTERM of the `pre-commit`
/// hook while its job runs: git aborts, no commit, no record, and the
/// cancelled job writes none either (R31, R37).
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
        // Signal the hook only once its job runs: the job dir appears
        // before the runner starts, and a busy host can stretch that window
        // past the first poll.
        let mut pid = None;
        assert!(
            eventually(60, || {
                pid = hook_pid(git.id(), "pre-commit");
                pid.is_some() && sb.first_job_running()
            }),
            "the hook never started a running job"
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

/// R82: a hook killed at any point while it makes its job leaves either no
/// job dir or a whole one (`spec.json` and `job.json`), never a half-made
/// dir that `tollgate cancel` and gc cannot read. The test kills the hook as
/// soon as anything appears under `jobs/`, many times, so most kills land
/// inside job creation.
#[test]
fn a_hook_killed_while_it_makes_its_job_leaves_no_half_made_job_r82() {
    let sb = Sandbox::new();
    sb.scoped_host("");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"slow\"\nkind = \"command\"\nrun = \"sleep 30\"\n",
    );
    let jobs = sb.state().join("jobs");
    let entries = || -> Vec<String> {
        std::fs::read_dir(&jobs)
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| e.file_name().to_str().map(str::to_owned))
                    .filter(|n| n != "by-key" && n != "queue")
                    .collect()
            })
            .unwrap_or_default()
    };
    for round in 0..15 {
        stage(&sb, &repo, "a.txt", &format!("{round}\n"));
        let before = entries().len();
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
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut pid = None;
        while Instant::now() < deadline {
            pid = pid.or_else(|| hook_pid(git.id(), "pre-commit"));
            if pid.is_some() && entries().len() > before {
                break;
            }
        }
        let pid = pid.expect("the hook never started");
        let _ = tollgate::procs::signal(pid, libc::SIGKILL);
        let _ = git.wait().unwrap();
    }
    for name in entries() {
        let dir = jobs.join(&name);
        if name.starts_with('.') {
            continue; // a staging dir no reader looks at; gc removes it
        }
        assert!(
            dir.join("job.json").is_file() && dir.join("spec.json").is_file(),
            "half-made job dir {name}: {:?}",
            std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .map(|e| e.file_name())
                .collect::<Vec<_>>()
        );
        let c = sb.tollgate(&repo, &["cancel", &name]);
        assert_eq!(c.code, Some(0), "cancel {name}: {}", c.out);
    }
    // A half-made job dir as older versions left it: `spec.json` only.
    let legacy = jobs.join("20261105-000000-deadbeef");
    std::fs::create_dir(&legacy).unwrap();
    std::fs::write(legacy.join("spec.json"), b"{}").unwrap();
    let g = sb.tollgate(&repo, &["gc", "--all"]);
    assert_eq!(g.code, Some(0), "{}", g.out);
    let left: Vec<String> = entries()
        .into_iter()
        .filter(|n| n.starts_with('.'))
        .collect();
    assert!(left.is_empty(), "gc left staging dirs: {left:?}");
    assert!(!legacy.exists(), "gc left a job dir without job.json");
}

/// Item 17 (detection only): `--no-verify` skips `pre-commit` and
/// `pre-merge-commit`, but `post-commit` and `post-merge` still run. A
/// commit no gate hook of the same git process allowed, whose tree has no
/// pass and that no trusted remote has, is recorded as unverified with a
/// loud warning; `tollgate status` and later denies show it. Cherry-picks
/// and reverts are the known L1 gap, not flagged. Nothing is undone.
#[test]
fn commits_made_without_the_gate_are_recorded_as_unverified_item17() {
    let sb = Sandbox::new();
    sb.scoped_host("");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"lint\"\nkind = \"command\"\nrun = \"test ! -f bad\"\n",
    );
    // A gated commit: no warning, nothing unverified.
    stage(&sb, &repo, "a.txt", "1\n");
    let r = sb.hooked(&repo, &["commit", "-m", "a"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(!r.out.contains("unverified"), "{}", r.out);
    let st = sb.tollgate(&repo, &["status"]);
    assert!(st.out.contains("unverified: none"), "{}", st.out);
    // --no-verify: the commit stays (no undo), with a warning.
    stage(&sb, &repo, "b.txt", "1\n");
    let r = sb.hooked(&repo, &["commit", "--no-verify", "-m", "b"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let skipped = head(&sb, &repo);
    assert!(
        r.out.contains("WARNING") && r.out.contains(&skipped[..12]) && r.out.contains("unverified"),
        "{}",
        r.out
    );
    let st = sb.tollgate(&repo, &["status"]);
    assert!(
        st.out
            .contains("unverified: 1 commit(s) made without the gate")
            && st.out.contains(&skipped[..12]),
        "{}",
        st.out
    );
    // A later deny names it too.
    stage(&sb, &repo, "bad", "x\n");
    let r = sb.hooked(&repo, &["commit", "-m", "bad"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(
        r.out.contains("made without the gate") && r.out.contains(&skipped[..12]),
        "{}",
        r.out
    );
    sb.git(&repo, &["rm", "-q", "--cached", "bad"]);
    std::fs::remove_file(repo.join("bad")).unwrap();
    // A merge with --no-verify: post-merge records it.
    sb.git(&repo, &["checkout", "-q", "-b", "side", "HEAD~1"]);
    sb.commit_file(&repo, "s.txt", "1\n", "side");
    sb.git(&repo, &["checkout", "-q", "main"]);
    let r = sb.hooked(
        &repo,
        &["merge", "--no-ff", "--no-verify", "--no-edit", "side"],
    );
    assert_eq!(r.code, Some(0), "{}", r.out);
    let merge = head(&sb, &repo);
    assert!(r.out.contains(&merge[..12]), "{}", r.out);
    // A cherry-pick and a revert (L1 gap): no warning.
    sb.git(&repo, &["checkout", "-q", "-b", "pick", "HEAD~1"]);
    sb.commit_file(&repo, "p.txt", "1\n", "pick me");
    let pick = head(&sb, &repo);
    sb.git(&repo, &["checkout", "-q", "main"]);
    let r = sb.hooked(&repo, &["cherry-pick", &pick]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(!r.out.contains("WARNING"), "{}", r.out);
    let r = sb.hooked(&repo, &["revert", "--no-edit", "HEAD"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(!r.out.contains("WARNING"), "{}", r.out);
    let st = sb.tollgate(&repo, &["status"]);
    assert!(
        st.out
            .contains("unverified: 2 commit(s) made without the gate"),
        "{}",
        st.out
    );
    // Once the tree passes a check, the commit no longer counts.
    let r = sb.tollgate(&repo, &["check", "--wait", "--rev", &skipped]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let st = sb.tollgate(&repo, &["status"]);
    assert!(
        st.out.contains("unverified: 1 commit(s)")
            && st.out.contains(&format!("  {} ", &merge[..12]))
            && !st.out.contains(&format!("  {} ", &skipped[..12])),
        "{}",
        st.out
    );
    let json = sb.tollgate(&repo, &["status", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&json.out).unwrap();
    assert_eq!(v["unverified"][0]["commit"], merge, "{v}");
    // Security review note 1 (item 37): a fast-forward to a local branch
    // made outside the hooks brings a commit no gate checked onto main; it
    // is recorded like a commit made with --no-verify. Only the tip of a
    // trusted remote's ref skips the record
    // (fast_forwards_skip_the_record_only_for_a_trusted_remote_ref_item37).
    sb.git(&repo, &["checkout", "-q", "-b", "up", "main"]);
    let up = sb.commit_file(&repo, "u.txt", "1\n", "upstream");
    sb.git(&repo, &["checkout", "-q", "main"]);
    let r = sb.hooked(&repo, &["merge", "--ff-only", "up"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(head(&sb, &repo), up);
    assert!(
        r.out.contains("WARNING") && r.out.contains(&up[..12]),
        "{}",
        r.out
    );
    // The same branch, merged without a fast-forward and without the gate,
    // is still recorded: the merge commit is the tip of main only.
    sb.git(&repo, &["checkout", "-q", "-b", "up2", "HEAD~1"]);
    sb.commit_file(&repo, "u2.txt", "1\n", "upstream 2");
    sb.git(&repo, &["checkout", "-q", "main"]);
    let r = sb.hooked(
        &repo,
        &["merge", "--no-ff", "--no-verify", "--no-edit", "up2"],
    );
    assert_eq!(r.code, Some(0), "{}", r.out);
    let merge2 = head(&sb, &repo);
    assert!(
        r.out.contains("WARNING") && r.out.contains(&merge2[..12]),
        "{}",
        r.out
    );
    // Detached HEAD: a --no-verify merge is recorded too.
    sb.git(&repo, &["checkout", "-q", "--detach", "HEAD~1"]);
    let r = sb.hooked(
        &repo,
        &["merge", "--no-ff", "--no-verify", "--no-edit", "up2"],
    );
    assert_eq!(r.code, Some(0), "{}", r.out);
    let merge3 = head(&sb, &repo);
    assert!(
        r.out.contains("WARNING") && r.out.contains(&merge3[..12]),
        "{}",
        r.out
    );
    sb.git(&repo, &["checkout", "-q", "main"]);
}

/// Item 37, security review note 1: `post-merge` skips the item 17 record
/// for a fast-forward only when the new `HEAD` is the tip of a
/// remote-tracking ref of a trusted remote, which the full check accepts
/// too (a trusted remote has the commit). A local branch, a tag or a ref
/// of an untrusted remote made at a commit no gate checked is recorded.
#[test]
fn fast_forwards_skip_the_record_only_for_a_trusted_remote_ref_item37() {
    let sb = Sandbox::new();
    let (repo, _bare) = trusted_repo(&sb, PASS);
    let recorded = |commit: &str| {
        let st = sb.tollgate(&repo, &["status"]);
        st.out.contains(&format!("  {} ", &commit[..12]))
    };
    // Fetched from the trusted remote (`git pull`): nothing recorded,
    // although no gate checked the commit here.
    let other = sb.root().join("other-clone");
    sb.git(
        sb.root().as_path(),
        &[
            "clone",
            "-q",
            sb.root().join("remotes/trusted.git").to_str().unwrap(),
            other.to_str().unwrap(),
        ],
    );
    let pulled = sb.commit_file(&other, "p.txt", "1\n", "from another machine");
    sb.git(&other, &["push", "-q", "origin", "main"]);
    let r = sb.hooked(&repo, &["pull", "-q", "--ff-only", "origin", "main"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(head(&sb, &repo), pulled);
    assert!(!r.out.contains("WARNING"), "{}", r.out);
    assert!(
        !recorded(&pulled),
        "{}",
        sb.tollgate(&repo, &["status"]).out
    );
    // A local branch made at a commit no gate checked.
    sb.git(&repo, &["checkout", "-q", "-b", "side", "main"]);
    let side = sb.commit_file(&repo, "s.txt", "1\n", "side");
    sb.git(&repo, &["checkout", "-q", "main"]);
    let r = sb.hooked(&repo, &["merge", "--ff-only", "side"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(head(&sb, &repo), side);
    assert!(
        r.out.contains("WARNING") && r.out.contains(&side[..12]),
        "{}",
        r.out
    );
    assert!(recorded(&side));
    // A tag at such a commit, with no branch at it.
    sb.git(&repo, &["checkout", "-q", "--detach", "main"]);
    let tagged = sb.commit_file(&repo, "t.txt", "1\n", "tagged");
    sb.git(&repo, &["tag", "v1"]);
    sb.git(&repo, &["checkout", "-q", "main"]);
    let r = sb.hooked(&repo, &["merge", "--ff-only", "v1"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(head(&sb, &repo), tagged);
    assert!(r.out.contains(&tagged[..12]), "{}", r.out);
    assert!(recorded(&tagged));
    // The ref of a remote that scope.remotes does not trust.
    let untrusted = sb.root().join("remotes/other.git");
    std::fs::create_dir_all(&untrusted).unwrap();
    sb.git(&untrusted, &["init", "-q", "--bare"]);
    sb.git(
        &repo,
        &["remote", "add", "other", untrusted.to_str().unwrap()],
    );
    sb.git(&repo, &["checkout", "-q", "-b", "x", "main"]);
    let foreign = sb.commit_file(&repo, "x.txt", "1\n", "foreign");
    sb.git(&repo, &["push", "-q", "other", "x"]);
    sb.git(&repo, &["checkout", "-q", "main"]);
    sb.git(&repo, &["branch", "-q", "-D", "x"]);
    let r = sb.hooked(&repo, &["merge", "--ff-only", "other/x"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(head(&sb, &repo), foreign);
    assert!(r.out.contains(&foreign[..12]), "{}", r.out);
    assert!(recorded(&foreign));
}

/// Item 30: the unverified record keeps the git subcommand and a fixed
/// list of flag names only: never `-c` values (a credential header), URLs
/// (a token in `user:token@`) or message text. Neither the state file nor
/// the warning, `status` or a later deny shows them.
#[test]
fn unverified_records_keep_no_values_of_the_git_command_item30() {
    let sb = Sandbox::new();
    sb.scoped_host("");
    let repo = repo_with(
        &sb,
        "r",
        "version = 1\n[[step]]\nname = \"lint\"\nkind = \"command\"\nrun = \"test ! -f bad\"\n",
    );
    stage(&sb, &repo, "b.txt", "1\n");
    let r = sb.hooked(
        &repo,
        &[
            "-c",
            "http.extraHeader=Authorization: Bearer SECRET-HEADER",
            "-c",
            "remote.mirror.url=https://user:SECRET-TOKEN@example.invalid/r.git",
            "commit",
            "-a",
            "--no-verify",
            "-m",
            "SECRET-MESSAGE",
        ],
    );
    assert_eq!(r.code, Some(0), "{}", r.out);
    let stored: String = std::fs::read_dir(sb.state().join("unverified"))
        .unwrap()
        .flatten()
        .map(|e| std::fs::read_to_string(e.path()).unwrap())
        .collect();
    assert!(stored.contains("commit"), "{stored}");
    // git itself prints the message ("[main <c>] ..."); tollgate's lines
    // must not.
    let warning: String = r.out.lines().filter(|l| l.contains("tollgate")).collect();
    assert!(warning.contains("WARNING"), "{}", r.out);
    let shown = format!("{warning}{stored}{}", sb.tollgate(&repo, &["status"]).out);
    stage(&sb, &repo, "bad", "x\n");
    let deny = sb.hooked(&repo, &["commit", "-m", "bad"]);
    assert_eq!(deny.code, Some(1), "{}", deny.out);
    assert!(deny.out.contains("made without the gate"), "{}", deny.out);
    for secret in ["SECRET-HEADER", "SECRET-TOKEN", "SECRET-MESSAGE", "Bearer"] {
        assert!(
            !shown.contains(secret) && !deny.out.contains(secret),
            "{secret} kept:\n{shown}\n{}",
            deny.out
        );
    }
    // What is kept: git, the subcommand, the allowlisted flags.
    assert!(stored.contains("git commit -a --no-verify"), "{stored}");
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

#[test]
fn a_chained_hook_runs_no_git_subprocess_on_a_warm_cache_t2_r7_r75() {
    let sb = Sandbox::new();
    sb.scoped_host("");
    let repo = repo_with(&sb, "r", PASS);
    // As on a real machine: git's system config counts, so its compiled-in
    // path is needed once (`git var`), then comes from the tool cache.
    let trace = sb.root().join("trace");
    let trace_s = trace.to_str().unwrap().to_owned();
    let run_hook = |name: &str, traced: bool| {
        let mut cmd = std::process::Command::new(test_hooks_dir().join(name));
        cmd.env_clear().current_dir(&repo);
        for (k, v) in sb.env().iter() {
            if k != "GIT_CONFIG_NOSYSTEM" {
                cmd.env(k, v);
            }
        }
        if traced {
            cmd.env("GIT_TRACE", &trace_s);
        }
        assert!(cmd.status().unwrap().success());
    };
    let run = |traced: bool| run_hook("post-checkout", traced);
    run(false);
    run(true);
    let text = std::fs::read_to_string(&trace).unwrap_or_default();
    assert!(text.is_empty(), "a git subprocess ran:\n{text}");
    // post-commit after a gate hook of the same git process allowed the
    // commit (item 17; the test process stands in for that git): none
    // either.
    let dirs = tollgate::dirs::Dirs::from_env(&sb.env()).unwrap();
    tollgate::hook::unverified::mark_gate_run_of(&dirs, i32::try_from(std::process::id()).unwrap());
    run_hook("post-commit", true);
    let text = std::fs::read_to_string(&trace).unwrap_or_default();
    assert!(text.is_empty(), "a git subprocess ran:\n{text}");
    // A cold cache asks git once (the trace sees it).
    std::fs::remove_file(sb.state().join("toolcache.json")).unwrap();
    run(true);
    let text = std::fs::read_to_string(&trace).unwrap_or_default();
    assert!(text.contains("GIT_CONFIG_SYSTEM"), "{text}");
}

/// git through the installed hooks (`tollgate install` in the sandbox) in
/// `repo`, with `extra` on top of the sandbox env and the injection.
fn installed_git(a: &Armed, repo: &Path, args: &[&str], extra: &[(&str, &str)]) -> support::Run {
    let ident = [
        ("GIT_AUTHOR_NAME", "a"),
        ("GIT_AUTHOR_EMAIL", "a@example.invalid"),
        ("GIT_COMMITTER_NAME", "a"),
        ("GIT_COMMITTER_EMAIL", "a@example.invalid"),
    ];
    let mut all: Vec<(&str, &str)> = ident.to_vec();
    all.extend_from_slice(extra);
    let out = a
        .cmd(Path::new("git"), args, &all)
        .current_dir(repo)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    support::Run {
        code: out.status.code(),
        out: format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    }
}

/// R8, L4, R5: the installed hooks take their dirs from install.json, so a
/// HOME or XDG value on the git command line neither turns the gate off
/// (no host config, `~/Repos` against another home, so out of scope) nor
/// points it at another state dir.
#[test]
fn hook_dirs_come_from_the_install_not_from_git_env_r8_l4() {
    let a = Armed::new();
    a.sb.scoped_host("");
    let repo = repo_with(
        &a.sb,
        "r",
        "version = 1\n[[step]]\nname = \"lint\"\nkind = \"command\"\nrun = \"exit 1\"\n",
    );
    stage(&a.sb, &repo, "a.txt", "1\n");
    let before = head(&a.sb, &repo);
    let r = installed_git(&a, &repo, &["commit", "-m", "x"], &[]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(r.out.contains("verdict fail"), "{}", r.out);
    let fake = a.sb.root().join("fakehome");
    std::fs::create_dir_all(&fake).unwrap();
    let fake_s = fake.to_str().unwrap();
    let other_state = a.sb.root().join("other-state");
    let other_s = other_state.to_str().unwrap();
    for extra in [
        vec![
            ("HOME", fake_s),
            ("XDG_CONFIG_HOME", ""),
            ("XDG_STATE_HOME", ""),
            ("XDG_DATA_HOME", ""),
        ],
        vec![("HOME", fake_s)],
        vec![("XDG_CONFIG_HOME", fake_s)],
        vec![("XDG_STATE_HOME", other_s)],
    ] {
        let r = installed_git(&a, &repo, &["commit", "-m", "x"], &extra);
        assert_eq!(r.code, Some(1), "{extra:?}: {}", r.out);
        assert!(
            r.out.contains("DENIED pre-commit") && r.out.contains("stored fail"),
            "{extra:?}: {}",
            r.out
        );
        assert_eq!(head(&a.sb, &repo), before, "{extra:?}");
    }
    assert!(
        !other_state.exists(),
        "the hook used the state dir from git's env"
    );
    assert_eq!(a.sb.jobs().len(), 1);
    // A record without dirs (an older install) fails closed: the gate
    // denies and the guard is not armed until install runs again.
    let rec_path = a.data().join("install.json");
    let mut rec: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&rec_path).unwrap()).unwrap();
    rec.as_object_mut().unwrap().remove("dirs");
    std::fs::write(&rec_path, serde_json::to_vec_pretty(&rec).unwrap()).unwrap();
    let r = installed_git(&a, &repo, &["commit", "-m", "x"], &[]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(
        r.out.contains("records no dirs") && r.out.contains("run: tollgate install"),
        "{}",
        r.out
    );
    let (code, _, err) = a.bash("ls");
    assert_eq!(code, Some(2), "{err}");
    assert!(
        err.contains("gate not armed (install.json records no dirs"),
        "{err}"
    );
    assert_eq!(a.install().0, Some(0));
    assert_eq!(a.bash("ls").0, Some(0));
    let r = installed_git(&a, &repo, &["commit", "-m", "x"], &[]);
    assert!(r.out.contains("stored fail"), "{}", r.out);
}
