//! Security regression suite (S1-S42): one test per bypass, each run the
//! way a Claude Code session runs git.
//!
//! The lab: the binary from this build installed by `tollgate install` at
//! a pty (item 29) into a sandbox (its own HOME, XDG dirs and settings
//! file), the session environment taken from the `env` that install wrote to that
//! settings file (`GIT_CONFIG_*` -> `core.hooksPath` = the installed hooks
//! dir), a host config whose `scope.remotes` matches a local bare repo
//! (the trusted remote), and a repo holding the scratch Rust workspace
//! (`a`, `b`) pushed to that remote. "Bad" trees are the ones a check must
//! refuse: `b`'s unit test `tests::fails` made to fail, or a file named
//! `bad` for labs whose policy is a command step.
//!
//! A session command goes through the installed guard first, exactly as
//! Claude Code runs it (PreToolUse JSON on stdin, exit 2 denies, an
//! `updatedInput` replaces the command), then runs in `bash -c` with the
//! session environment. Each test asserts the promise: the guard denies,
//! or the commit or push is refused and no pass record appears for a bad
//! tree.

mod support;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use support::{Armed, Run, Sandbox, Scratch, eventually, job_id, pty, write_b, write_exe};

/// Base policy: the Rust tests step.
const RUST_POLICY: &str = "version = 1\n[[step]]\nname = \"tests\"\nkind = \"nextest\"\n";

/// Base policy: a command step that refuses any tree holding `bad`.
const BAD_FILE_POLICY: &str =
    "version = 1\n[[step]]\nname = \"lint\"\nkind = \"command\"\nrun = \"test ! -f bad\"\n";

/// What the guard said about a Bash command.
#[derive(Debug)]
enum Guarded {
    /// Exit 2.
    Denied(String),
    /// `permissionDecision: ask`: a person decides, never automatic.
    Asked(String),
    /// Allowed; the command that runs (after any `updatedInput`).
    Allowed(String),
}

/// A session command: stopped by the guard, or run.
#[derive(Debug)]
enum Session {
    Stopped(Guarded),
    Ran(Run),
}

impl Session {
    /// True when the guard denied it with its one-line reason (R23).
    fn denied(&self) -> bool {
        matches!(self, Self::Stopped(Guarded::Denied(why))
            if why.starts_with("tollgate") && why.trim().lines().count() == 1)
    }

    /// The guard's deny reason.
    fn deny_reason(&self) -> &str {
        match self {
            Self::Stopped(Guarded::Denied(why)) => why,
            other => panic!("not denied: {other:?}"),
        }
    }

    /// Exit code of the command that ran (`None`: the guard stopped it).
    fn code(&self) -> Option<i32> {
        match self {
            Self::Ran(r) => r.code,
            Self::Stopped(_) => None,
        }
    }

    /// Output of the command that ran.
    fn out(&self) -> &str {
        match self {
            Self::Ran(r) => &r.out,
            Self::Stopped(g) => panic!("the guard stopped it: {g:?}"),
        }
    }
}

/// The installed sandbox, its session env, the trusted remote and the
/// agent's repo.
struct Lab {
    a: Armed,
    /// `env` of the sandbox settings file, as install wrote it.
    session: Vec<(String, String)>,
    repo: PathBuf,
    bare: PathBuf,
    /// The tier whose pass a bad tree must never get (`None`: any). The
    /// S6/S7 policy refuses `bad` only in `full`.
    guarded_tier: Option<&'static str>,
}

impl Lab {
    /// A lab whose `main` holds the scratch workspace (all tests pass) and
    /// `tollgate.toml` = `policy`, pushed to the trusted remote and
    /// fetched.
    fn new(policy: &str) -> Self {
        let a = Armed::new();
        let sb = &a.sb;
        // Item 34: a local bare repo is trusted by its exact path only.
        sb.host_config(&format!(
            "[scope]\ntrusted_paths = [\"{}\"]\n[verify]\nmin_free = \"1M\"\n",
            sb.root().join("remotes/trusted.git").display()
        ));
        // `tollgate` on the session PATH is the installed copy.
        std::os::unix::fs::symlink(a.bin(), sb.root().join("bin/tollgate")).unwrap();
        let settings: serde_json::Value =
            serde_json::from_slice(&std::fs::read(sb.home.join(".claude/settings.json")).unwrap())
                .unwrap();
        let session: Vec<(String, String)> = settings["env"]
            .as_object()
            .expect("install wrote an env object")
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
            .collect();
        assert!(
            session
                .iter()
                .any(|(k, v)| k == "GIT_CONFIG_KEY_0" && v == "core.hooksPath"),
            "{session:?}"
        );
        let repo = sb.rust_repo("ws", Scratch::default());
        sb.commit_file(&repo, "README", "scratch workspace\n", "readme");
        sb.commit_file(&repo, "tollgate.toml", policy, "policy");
        let bare = sb.root().join("remotes/trusted.git");
        std::fs::create_dir_all(&bare).unwrap();
        sb.git(&bare, &["init", "-q", "--bare"]);
        sb.git(&repo, &["remote", "add", "origin", bare.to_str().unwrap()]);
        sb.git(&repo, &["push", "-q", "origin", "main"]);
        sb.git(&repo, &["fetch", "-q", "origin"]);
        Self {
            a,
            session,
            repo,
            bare,
            guarded_tier: None,
        }
    }

    fn sb(&self) -> &Sandbox {
        &self.a.sb
    }

    fn root(&self) -> PathBuf {
        self.sb().root()
    }

    /// `program` with the session environment, in `dir`.
    fn cmd(&self, program: impl AsRef<std::ffi::OsStr>, dir: &Path) -> Command {
        let mut c = Command::new(program);
        c.env_clear().current_dir(dir).stdin(Stdio::null());
        for (k, v) in self.sb().env().iter() {
            c.env(k, v);
        }
        c.env("PATH", &self.a.path).env("TMPDIR", self.root());
        for (k, v) in &self.session {
            c.env(k, v);
        }
        c
    }

    /// The installed guard on Bash `command` with cwd `dir`.
    fn guard_in(&self, dir: &Path, command: &str) -> Guarded {
        let input = serde_json::json!({
            "session_id": "s",
            "hook_event_name": "PreToolUse",
            "cwd": dir,
            "tool_name": "Bash",
            "tool_input": {"command": command, "description": "d"},
        });
        self.guard_json(&input)
    }

    fn guard_json(&self, input: &serde_json::Value) -> Guarded {
        let mut child = self
            .cmd(self.a.bin(), &self.repo)
            .arg("guard")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let original = input["tool_input"]["command"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        match out.status.code() {
            Some(2) => Guarded::Denied(stderr),
            Some(0) if stdout.trim().is_empty() => Guarded::Allowed(original),
            Some(0) => {
                let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
                let h = &v["hookSpecificOutput"];
                if h["permissionDecision"] == "ask" {
                    return Guarded::Asked(h["permissionDecisionReason"].to_string());
                }
                Guarded::Allowed(
                    h["updatedInput"]["command"]
                        .as_str()
                        .map_or(original, str::to_owned),
                )
            }
            other => panic!("guard exit {other:?}: {stdout}{stderr}"),
        }
    }

    fn guard(&self, command: &str) -> Guarded {
        self.guard_in(&self.repo, command)
    }

    /// A Bash call of the session in `dir`: the guard, then `bash -c`.
    fn session_in(&self, dir: &Path, command: &str) -> Session {
        match self.guard_in(dir, command) {
            Guarded::Allowed(c) => {
                let out = self.cmd("bash", dir).args(["-c", &c]).output().unwrap();
                Session::Ran(Run {
                    code: out.status.code(),
                    out: format!(
                        "{}{}",
                        String::from_utf8_lossy(&out.stdout),
                        String::from_utf8_lossy(&out.stderr)
                    ),
                })
            }
            g => Session::Stopped(g),
        }
    }

    fn session(&self, command: &str) -> Session {
        self.session_in(&self.repo, command)
    }

    /// git with the session environment but not through the guard (a
    /// script file the agent wrote and ran).
    fn direct(&self, args: &[&str]) -> Run {
        self.direct_with(args, &[])
    }

    /// [`Self::direct`] with `extra` variables set for git.
    fn direct_with(&self, args: &[&str], extra: &[(&str, &str)]) -> Run {
        let mut cmd = self.cmd("git", &self.repo);
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let out = cmd.args(args).output().unwrap();
        Run {
            code: out.status.code(),
            out: format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        }
    }

    /// git with no injection: Victor's terminal, no hooks.
    fn plain(&self, args: &[&str]) -> String {
        self.sb().git(&self.repo, args)
    }

    fn plain_in(&self, dir: &Path, args: &[&str]) -> String {
        self.sb().git(dir, args)
    }

    /// Every ref and its value in `dir`.
    fn refs_in(&self, dir: &Path) -> String {
        self.plain_in(dir, &["for-each-ref", "--format=%(refname) %(objectname)"])
    }

    fn refs(&self) -> String {
        self.refs_in(&self.repo)
    }

    /// Stages `b`'s failing unit test.
    fn stage_failing_test(&self) {
        write_b(&self.repo, 3);
        self.plain(&["add", "crates/b/src/lib.rs"]);
    }

    /// Stages a file `bad` holding `content`.
    fn stage_bad_file(&self, content: &str) {
        std::fs::write(self.repo.join("bad"), content).unwrap();
        self.plain(&["add", "bad"]);
    }

    /// Stages a code change (a comment in `a`), which no docs-only rule
    /// (R61) skips.
    fn stage_code_change(&self, note: &str) {
        let lib = self.repo.join("crates/a/src/lib.rs");
        let text = std::fs::read_to_string(&lib).unwrap();
        std::fs::write(&lib, format!("{text}// {note}\n")).unwrap();
        self.plain(&["add", "crates/a/src/lib.rs"]);
    }

    /// Runs each of `cmds` in the session; returns those that the guard
    /// did not deny or that moved a ref (each moved ref is put back).
    fn not_denied(&self, cmds: &[String]) -> Vec<String> {
        let mut bad = Vec::new();
        for cmd in cmds {
            let before = self.refs();
            let s = self.session(cmd);
            if self.refs() != before {
                for line in before.lines() {
                    let (r, v) = line.split_once(' ').unwrap();
                    self.plain(&["update-ref", r, v]);
                }
                bad.push(format!("{cmd}  => a ref moved: {s:?}"));
            } else if !s.denied() {
                bad.push(format!("{cmd}  => not denied: {s:?}"));
            }
        }
        self.assert_no_bad_pass();
        bad
    }

    /// True when `tree` must not pass: it holds `bad`, or `b`'s failing
    /// test.
    fn is_bad_tree(&self, tree: &str) -> bool {
        let has = |path: &str| {
            !self
                .plain(&["ls-tree", "--name-only", tree, "--", path])
                .is_empty()
        };
        if has("bad") {
            return true;
        }
        has("crates/b/src/lib.rs")
            && self
                .plain(&["show", &format!("{tree}:crates/b/src/lib.rs")])
                .contains("assert_eq!(super::two(), 3)")
    }

    /// Every record file as JSON.
    fn records(&self) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        let Ok(shards) = std::fs::read_dir(self.sb().state().join("results")) else {
            return out;
        };
        for shard in shards.flatten() {
            for f in std::fs::read_dir(shard.path()).unwrap().flatten() {
                if let Ok(v) = serde_json::from_slice(&std::fs::read(f.path()).unwrap()) {
                    out.push(v);
                }
            }
        }
        out
    }

    /// Trees of pass records of `tier` (any tier when `None`).
    fn pass_trees(&self, tier: Option<&str>) -> Vec<String> {
        self.records()
            .iter()
            .filter(|r| r["verdict"] == "pass" && tier.is_none_or(|t| r["tier"] == t))
            .map(|r| r["tree"].as_str().unwrap().to_owned())
            .collect()
    }

    /// No pass record (of `tier`) for a bad tree.
    fn assert_no_bad_pass_of(&self, tier: Option<&str>) {
        for t in self.pass_trees(tier) {
            assert!(!self.is_bad_tree(&t), "a pass record for bad tree {t}");
        }
    }

    fn assert_no_bad_pass(&self) {
        self.assert_no_bad_pass_of(self.guarded_tier);
    }

    /// The trusted remote's refs are still `before`.
    fn assert_remote_is(&self, before: &str) {
        assert_eq!(self.refs_in(&self.bare), before, "the trusted remote moved");
    }

    /// Runs `command` in the session and asserts the promise: no ref of
    /// the repo moved and no bad tree got a pass record.
    fn refused(&self, command: &str) -> Session {
        let before = self.refs();
        let s = self.session(command);
        assert_eq!(self.refs(), before, "{command}: a ref moved: {s:?}");
        self.assert_no_bad_pass();
        s
    }

    fn head(&self) -> String {
        self.plain(&["rev-parse", "HEAD"])
    }
}

/// The 12-hex tree a gate line (`... tree <t> tier ...`) names.
fn gated_tree(out: &str) -> String {
    let line = out
        .lines()
        .find(|l| l.contains(" tree ") && l.contains("tollgate:"))
        .unwrap_or_else(|| panic!("no gate line in:\n{out}"));
    line.split_whitespace()
        .skip_while(|w| *w != "tree")
        .nth(1)
        .unwrap()
        .to_owned()
}

/// The pid of hook `name` among the descendants of `root`.
fn hook_pid(root: u32, name: &str) -> Option<i32> {
    let table = tollgate::procs::ProcTable::snapshot().ok()?;
    table
        .descendants(i32::try_from(root).ok()?)
        .into_iter()
        .find(|p| {
            tollgate::procs::argv(*p).is_some_and(|argv| {
                argv.first()
                    .is_some_and(|a| a.as_encoded_bytes().ends_with(name.as_bytes()))
            })
        })
}

/// Waits for `child` up to `secs`; kills it and panics after that.
fn wait_or_kill(child: &mut std::process::Child, secs: u64) -> std::process::ExitStatus {
    let end = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            return st;
        }
        if Instant::now() > end {
            let _ = child.kill();
            let _ = child.wait();
            panic!("still running after {secs} s");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// S1: `--no-verify` and every spelling git takes for it (unique
/// prefixes, `-n` alone and in clusters, quoted pieces, ANSI-C quoting,
/// inside `bash -c`) never reach git through the guard.
#[test]
fn s1_no_verify_and_every_abbreviation_through_the_guard() {
    let lab = Lab::new(BAD_FILE_POLICY);
    lab.stage_bad_file("1");
    let mut cmds: Vec<String> = Vec::new();
    for n in "--no-v".len()..="--no-verify".len() {
        let flag = &"--no-verify"[..n];
        cmds.push(format!("git commit {flag} -m x"));
        cmds.push(format!("git commit -m x {flag}"));
        cmds.push(format!("git commit -a {flag} -m x"));
    }
    cmds.extend(
        [
            "git commit -n -m x",
            "git commit -nm x",
            "git commit -anm x",
            "git commit -a -n -m x",
            "git commit -qn -m x",
            "git commit --amend -n --no-edit",
            "git -C . commit -n -m x",
            "git commit --no-\"verify\" -m x",
            "git commit '--no-verify' -m x",
            "git commit --no-ver\\ify -m x",
            "git commit -\"n\" -m x",
            "git commit $'--no-verify' -m x",
            "git commit $'\\x2d-no-verify' -m x",
            "git commit $'\\055-no-verify' -m x",
            "git commit $'\\x2dn' -m x",
            "bash -c 'git commit --no-verify -m x'",
            "sh -c \"git commit -n -m x\"",
            "cd . && git commit --no-veri -m x",
            "git merge --no-verify --no-edit main",
            // `\c\\` is one character in bash; a decoder that took one
            // backslash read the rest as part of the quote (item 31).
            "echo $'\\c\\\\' ; git commit -n -m x",
            "git commit $'\\c\\\\' -n -m x",
            // Text a shell reads from stdin (item 31).
            "sh <<'EOF'\ngit commit -n -m x\nEOF",
            "echo 'git commit -n -m x' | bash",
        ]
        .map(str::to_owned),
    );
    let bad = lab.not_denied(&cmds);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    // The commit itself, through the guard, is gated and refused.
    let s = lab.refused("git commit -m x");
    assert!(s.out().contains("DENIED pre-commit"), "{s:?}");
}

/// S2: every way to drop or override the hooks path on the command line
/// (`-c`, `--config-env`, `GIT_CONFIG_*` variables, `env -i`, `env -u`)
/// is denied by the guard.
#[test]
fn s2_hooks_path_overrides_through_the_guard() {
    let lab = Lab::new(BAD_FILE_POLICY);
    lab.stage_bad_file("1");
    let cmds = [
        "git -c core.hooksPath=/dev/null commit -m x",
        "git -c core.hookspath= commit -m x",
        "git -c CORE.HOOKSPATH=/tmp commit -m x",
        "git -c 'core.hooksPath=/dev/null' commit -m x",
        "git -c include.path=/tmp/x commit -m x",
        "git -c includeIf.onbranch:main.path=/tmp/x commit -m x",
        "git --config-env=core.hooksPath=HOME commit -m x",
        "git --config-env core.hooksPath=HOME commit -m x",
        "git -c core.hooksPath=/dev/null push origin main",
        "GIT_CONFIG_COUNT=0 git commit -m x",
        "GIT_CONFIG_VALUE_0=/dev/null git commit -m x",
        "GIT_CONFIG_KEY_0=x.y git commit -m x",
        "export GIT_CONFIG_COUNT=0; git commit -m x",
        "unset GIT_CONFIG_COUNT; git commit -m x",
        "GIT_CONFIG_PARAMETERS=\"'core.hooksPath'='/dev/null'\" git commit -m x",
        "git -c core.hooksPath commit -m x",
        "env -i PATH=/usr/bin git commit -m x",
        "env --ignore-environment PATH=/usr/bin git commit -m x",
        "env - PATH=/usr/bin git commit -m x",
        "env -iv PATH=/usr/bin git commit -m x",
        "env -u GIT_CONFIG_COUNT git commit -m x",
        "env -uGIT_CONFIG_COUNT git commit -m x",
        "env --unset=GIT_CONFIG_COUNT git commit -m x",
        "env --unset GIT_CONFIG_COUNT git commit -m x",
        "env -v -i PATH=/usr/bin git commit -m x",
        "/usr/bin/env -i PATH=/usr/bin git commit -m x",
        "env -u GIT_CONFIG_KEY_0 -u GIT_CONFIG_VALUE_0 git commit -m x",
        "env -S '-i git commit -m x'",
        "exec -c git commit -m x",
        "bash -c 'env -i git commit -m x'",
        // ANSI-C quoting hides the names from a plain text match.
        "git -c $'core.hooks\\x50ath=/dev/null' commit -m x",
        "env -u $'\\x47IT_CONFIG_COUNT' git commit -m x",
        "unset $'\\x47IT_CONFIG_COUNT'; git commit -m x",
        "export $'\\x47IT_CONFIG_COUNT=0'; git commit -m x",
        "bash -c $'git commit \\x2dn -m x'",
    ]
    .map(str::to_owned);
    let bad = lab.not_denied(&cmds);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// S3: git reached by its absolute path, from a script file, through
/// `bash -c` and other wrappers still runs the injected hooks.
#[test]
fn s3_hooks_run_for_any_way_git_is_started() {
    let lab = Lab::new(RUST_POLICY);
    lab.stage_failing_test();
    let script = lab.root().join("do-commit.sh");
    write_exe(&script, "#!/bin/sh\nexec git commit -m \"from a script\"\n");
    let py = lab.root().join("do-commit.py");
    std::fs::write(
        &py,
        "import subprocess, sys\nsys.exit(subprocess.run(['git', 'commit', '-m', 'py']).returncode)\n",
    )
    .unwrap();
    for cmd in [
        "/usr/bin/git commit -m abs".to_owned(),
        script.display().to_string(),
        format!("sh {}", script.display()),
        "bash -c 'git commit -m bashc'".to_owned(),
        "sh -c 'cd . && /usr/bin/git commit -m shc'".to_owned(),
        "env git commit -m env".to_owned(),
        "command git commit -m command".to_owned(),
        "(git commit -m subshell)".to_owned(),
        "nohup git commit -m nohup".to_owned(),
        format!("python3 {}", py.display()),
    ] {
        let s = lab.refused(&cmd);
        assert!(
            s.out()
                .contains("tollgate: DENIED pre-commit refs/heads/main"),
            "{cmd}: the hook did not run: {s:?}"
        );
    }
    // The closed grammar denies these in the session (G1, G2a); run
    // anyway (a script file), the hooks still gate them.
    for cmd in [
        "echo x | xargs git commit -m",
        "$(command -v git) commit -m which",
    ] {
        assert!(lab.refused(cmd).denied(), "{cmd}");
        let before = lab.refs();
        let out = lab
            .cmd("bash", &lab.repo)
            .args(["-c", cmd])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success() && text.contains("tollgate: DENIED pre-commit refs/heads/main"),
            "{cmd}: the hook did not run: {text}"
        );
        assert_eq!(lab.refs(), before, "{cmd}: a ref moved");
    }
    lab.assert_no_bad_pass();
    assert_eq!(lab.sb().jobs().len(), 1, "one job; the rest hit its fail");
}

/// S4: `commit -a` and partial commits with dirty and untracked files: the
/// tree the gate checks is the tree the commit gets, never the working
/// tree.
#[test]
fn s4_the_checked_tree_is_the_committed_tree() {
    let lab = Lab::new(RUST_POLICY);
    std::fs::write(lab.repo.join("untracked.txt"), "not in any commit\n").unwrap();
    // A failing index with a fixed (unstaged) working tree: the index is
    // what gets committed, so it is refused.
    lab.stage_failing_test();
    write_b(&lab.repo, 2);
    let index_tree = lab.plain(&["write-tree"]);
    let s = lab.refused("git commit -m staged");
    assert!(s.out().contains("verdict fail"), "{s:?}");
    assert!(index_tree.starts_with(&gated_tree(s.out())), "{s:?}");
    // `commit -a` takes the dirty tracked file (failing) but not the
    // untracked one.
    lab.plain(&["reset", "-q"]);
    write_b(&lab.repo, 3);
    std::fs::write(lab.repo.join("README"), "staged change\n").unwrap();
    lab.plain(&["add", "README"]);
    let s = lab.refused("git commit -a -m all");
    assert!(s.out().contains("verdict fail"), "{s:?}");
    lab.plain(&["add", "-u"]);
    let all_tree = lab.plain(&["write-tree"]);
    assert!(all_tree.starts_with(&gated_tree(s.out())), "{s:?}");
    assert!(
        lab.plain(&["ls-tree", "--name-only", &all_tree, "--", "untracked.txt"])
            .is_empty()
    );
    // A partial commit of the README only: the failing `b` stays staged
    // and dirty, outside the commit, so it passes, and the checked tree
    // is the new commit's tree.
    lab.plain(&["reset", "-q"]);
    lab.plain(&["add", "crates/b/src/lib.rs"]);
    std::fs::write(lab.repo.join("README"), "partial\n").unwrap();
    let s = lab.session("git commit -m partial -- README");
    assert!(s.out().contains("tollgate: pass pre-commit"), "{s:?}");
    let committed = lab.plain(&["rev-parse", "HEAD^{tree}"]);
    assert!(committed.starts_with(&gated_tree(s.out())), "{s:?}");
    assert!(!lab.is_bad_tree(&committed));
    assert_eq!(
        lab.plain(&["diff", "--cached", "--name-only"]),
        "crates/b/src/lib.rs"
    );
    // A partial commit of the failing file with a dirty README: refused,
    // and the checked tree is HEAD plus that file only.
    std::fs::write(lab.repo.join("README"), "dirty again\n").unwrap();
    let s = lab.refused("git commit -m only-b -- crates/b/src/lib.rs");
    assert!(s.out().contains("verdict fail"), "{s:?}");
    let job = job_id(s.out());
    let checked = lab.sb().report(&job)["tree"].as_str().unwrap().to_owned();
    assert!(lab.is_bad_tree(&checked));
    assert_eq!(
        lab.plain(&["diff", "--name-only", "HEAD", &checked]),
        "crates/b/src/lib.rs"
    );
}

/// S5: `commit --amend` runs the gate on the amended tree.
#[test]
fn s5_amend_is_gated() {
    let lab = Lab::new(RUST_POLICY);
    lab.stage_failing_test();
    let s = lab.refused("git commit --amend --no-edit");
    assert!(
        s.out().contains("DENIED pre-commit") && s.out().contains("FAIL b"),
        "{s:?}"
    );
    let s = lab.refused("git commit --amend -a -m reworded");
    assert!(s.out().contains("DENIED pre-commit"), "{s:?}");
    // A message-only amend (`--only`) leaves the staged failing file out:
    // its tree is HEAD's and it passes.
    let tree = lab.plain(&["rev-parse", "HEAD^{tree}"]);
    let s = lab.session("git commit --amend --only -m 'new message'");
    assert!(s.out().contains("tollgate: pass pre-commit"), "{s:?}");
    assert_eq!(lab.plain(&["rev-parse", "HEAD^{tree}"]), tree);
    lab.assert_no_bad_pass();
}

/// The S6/S7 policy: `deep` refuses `bad` only in tier `full`, so a
/// branch can hold a tree that passes `fast` and fails `full`.
const DEEP_POLICY: &str = "version = 1\n[[step]]\nname = \"quick\"\nkind = \"command\"\nrun = \"true\"\n[[step]]\nname = \"deep\"\nkind = \"command\"\nrun = \"test ! -f bad\"\ntiers = [\"full\"]\n";

/// S6: `merge --no-ff` into `main` needs `full`; a fast-forward merge runs
/// no gate hook (the L1 gap), so the push of `main` needs `full`.
#[test]
fn s6_merges_into_main_and_the_push_need_full() {
    let mut lab = Lab::new(DEEP_POLICY);
    lab.guarded_tier = Some("full");
    let remote = lab.refs_in(&lab.bare);
    lab.plain(&["checkout", "-q", "-b", "feat"]);
    lab.stage_bad_file("1");
    // `fast` passes on the branch: allowed by the policy.
    let s = lab.session("git commit -m feat");
    assert!(
        s.out().contains("pass pre-commit refs/heads/feat") && s.out().contains("tier fast"),
        "{s:?}"
    );
    lab.plain(&["checkout", "-q", "main"]);
    let main = lab.head();
    let s = lab.refused("git merge --no-ff --no-edit feat");
    assert!(
        s.out().contains("DENIED pre-merge-commit refs/heads/main")
            && s.out().contains("tier full"),
        "{s:?}"
    );
    lab.plain(&["merge", "--abort"]);
    // The fast-forward moves the local main (no hook can stop it, L1)...
    let s = lab.session("git merge --ff-only feat");
    assert_ne!(lab.head(), main, "{s:?}");
    // ...and the push of main needs full: refused, the remote unchanged.
    let s = lab.refused("git push origin main");
    assert!(
        s.out().contains("DENIED pre-push refs/heads/main") && s.out().contains("tier full"),
        "{s:?}"
    );
    let s = lab.refused("git push origin feat");
    assert!(
        s.out().contains("DENIED pre-push refs/heads/feat") && s.out().contains("tier full"),
        "{s:?}"
    );
    lab.assert_remote_is(&remote);
}

/// S7: a branch tip made by `cherry-pick` (no `pre-commit`, the L1 gap)
/// is caught by the push gate.
#[test]
fn s7_a_cherry_picked_tip_is_caught_at_push() {
    let mut lab = Lab::new(DEEP_POLICY);
    lab.guarded_tier = Some("full");
    let remote = lab.refs_in(&lab.bare);
    lab.plain(&["checkout", "-q", "-b", "src"]);
    lab.stage_bad_file("1");
    lab.plain(&["commit", "-q", "--no-verify", "-m", "bad"]);
    lab.plain(&["checkout", "-q", "main"]);
    let s = lab.session("git checkout -q -b feat && git cherry-pick src");
    assert!(!s.out().contains("DENIED"), "{s:?}");
    assert!(lab.is_bad_tree(&lab.plain(&["rev-parse", "feat^{tree}"])));
    let s = lab.refused("git push origin feat");
    assert!(
        s.out().contains("DENIED pre-push refs/heads/feat") && s.out().contains("tier full"),
        "{s:?}"
    );
    lab.assert_remote_is(&remote);
}

/// S8: SIGKILL of the hook while its job runs: git aborts, no commit, no
/// record.
#[test]
fn s8_a_killed_hook_leaves_no_commit_and_no_record() {
    let lab = Lab::new(
        "version = 1\n[[step]]\nname = \"slow\"\nkind = \"command\"\nrun = \"sleep 30\"\n",
    );
    // A code change (a docs-only change would skip the step, R61).
    lab.stage_code_change("changed");
    let before = lab.refs();
    let Guarded::Allowed(cmd) = lab.guard("git commit -m a") else {
        panic!("the guard stopped a plain commit");
    };
    let mut child = lab
        .cmd("bash", &lab.repo)
        .args(["-c", &cmd])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Kill the hook only once its job runs ("while its job runs"): the job
    // dir appears before the runner starts.
    let mut pid = None;
    assert!(
        eventually(60, || {
            pid = hook_pid(child.id(), "pre-commit");
            pid.is_some() && lab.sb().first_job_running()
        }),
        "the hook never started a running job"
    );
    tollgate::procs::signal(pid.unwrap(), libc::SIGKILL).unwrap();
    let st = wait_or_kill(&mut child, 20);
    assert!(!st.success(), "git committed after its hook was killed");
    assert_eq!(lab.refs(), before);
    assert_eq!(lab.sb().record_count(), 0, "{:?}", lab.records());
    let job = lab.sb().jobs()[0].clone();
    let s = lab.session(&format!("tollgate cancel {job}"));
    assert!(s.out().contains("cancel"), "{s:?}");
    let s = lab.session(&format!("tollgate wait {job} --timeout 30s"));
    assert!(matches!(s.code(), Some(c) if c != 0), "{s:?}");
    assert_eq!(lab.sb().record_count(), 0);
    assert_eq!(lab.refs(), before);
}

/// S9: a check slower than the inline budget denies with the job id and a
/// wait-then-commit command; no record exists until the job ends, and
/// only a pass lets the same commit through.
#[test]
fn s9_a_slow_check_denies_with_a_job_and_no_record_until_it_passes() {
    let lab = Lab::new(
        "version = 1\n[budget]\ninline = \"1s\"\n[[step]]\nname = \"slow\"\nkind = \"command\"\nrun = \"sleep 2 && test ! -f bad\"\n",
    );
    lab.stage_bad_file("1");
    // The session's cap (540 s, L17) is longer than this test may take; a
    // shorter cap is the agent's to choose and stands for a check slower
    // than the budget.
    let s = lab.refused("TOLLGATE_INLINE_CAP=1 git commit -m 'slow bad'");
    let job = job_id(s.out());
    assert!(s.out().contains("verdict running"), "{s:?}");
    assert_eq!(lab.sb().record_count(), 0, "a record before the job ended");
    let retry = format!("tollgate wait {job} && git commit -m 'slow bad'");
    assert!(s.out().contains(&retry), "no {retry:?} in {s:?}");
    // The printed command waits, sees the fail and does not commit.
    let s = lab.refused(&retry);
    assert_eq!(s.code(), Some(1), "{s:?}");
    assert!(s.out().contains("fail"), "{s:?}");
    assert!(lab.pass_trees(None).is_empty());
    // A good tree: denied while running, no record, then the printed
    // command commits it.
    lab.plain(&["rm", "-q", "--cached", "bad"]);
    std::fs::remove_file(lab.repo.join("bad")).unwrap();
    lab.stage_code_change("good");
    let records = lab.sb().record_count();
    let s = lab.refused("TOLLGATE_INLINE_CAP=1 git commit -m good");
    assert!(s.out().contains("verdict running"), "{s:?}");
    let job = job_id(s.out());
    assert_eq!(lab.sb().record_count(), records);
    let head = lab.head();
    let s = lab.session(&format!("tollgate wait {job} && git commit -m good"));
    assert!(s.out().contains(&format!("record of job {job}")), "{s:?}");
    assert_ne!(lab.head(), head);
    lab.assert_no_bad_pass();
}

/// S10: a missing hooks dir or a dangling hook link would let git commit
/// with no hooks at all. The guard repairs them before the call (and the
/// commit is then gated), or denies when it cannot.
#[test]
fn s10_missing_hooks_are_repaired_or_the_guard_denies() {
    use std::os::unix::fs::PermissionsExt as _;
    let lab = Lab::new(BAD_FILE_POLICY);
    let hooks = lab.a.data().join("hooks");
    lab.stage_bad_file("1");
    // The missing dir: repaired, then the commit is gated.
    std::fs::remove_dir_all(&hooks).unwrap();
    let s = lab.refused("git commit -m x");
    assert!(s.out().contains("DENIED pre-commit"), "{s:?}");
    // A dangling link in place of the gate hook.
    std::fs::remove_file(hooks.join("pre-commit")).unwrap();
    std::os::unix::fs::symlink("/nonexistent/tollgate", hooks.join("pre-commit")).unwrap();
    let s = lab.refused("git commit -m x");
    assert!(s.out().contains("DENIED pre-commit"), "{s:?}");
    let log = std::fs::read_to_string(lab.sb().state().join("repairs.log")).unwrap();
    assert_eq!(log.lines().count(), 2, "{log}");
    // A hook file that is not the installed copy: deny every call.
    std::fs::remove_file(hooks.join("pre-commit")).unwrap();
    write_exe(&hooks.join("pre-commit"), "#!/bin/sh\nexit 0\n");
    for cmd in ["git commit -m x", "ls"] {
        let s = lab.refused(cmd);
        assert!(
            s.deny_reason().contains("gate not armed") && s.deny_reason().contains("pre-commit"),
            "{s:?}"
        );
    }
    // The dir cannot be made again (data dir read-only): deny.
    std::fs::remove_dir_all(&hooks).unwrap();
    let data = lab.a.data();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o555)).unwrap();
    let s = lab.refused("git commit -m x");
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        s.denied() && s.deny_reason().contains("repair failed"),
        "a failed repair must deny: {s:?}"
    );
    // Repaired again on the next call.
    let s = lab.refused("git commit -m x");
    assert!(s.out().contains("DENIED pre-commit"), "{s:?}");
}

/// S11: records are tollgate's to write. The guard denies a write into the
/// state dir; a forged record file (written by other means) does not let
/// a failing tree through: one whose job has no `report.json`, one whose
/// verdict was changed to pass, and a pass record of another tree copied
/// to this tree's key.
#[test]
fn s11_forged_records_do_not_pass() {
    let lab = Lab::new(BAD_FILE_POLICY);
    let results = lab.sb().state().join("results");
    for cmd in [
        format!("echo '{{}}' > {}/ab/x.json", results.display()),
        format!("cp /etc/hostname {}/ab/x.json", results.display()),
        format!("echo x | tee {}/ab/x.json", results.display()),
        "echo x > $XDG_STATE_HOME/tollgate/results/ab/x.json".to_owned(),
        format!("sed -i s/fail/pass/ {}/ab/x.json", results.display()),
    ] {
        let s = lab.refused(&cmd);
        assert!(s.deny_reason().contains("tollgate's dir"), "{cmd}: {s:?}");
    }
    let write = serde_json::json!({
        "tool_name": "Write",
        "cwd": lab.repo,
        "tool_input": {"file_path": results.join("ab/x.json"), "content": "{}"},
    });
    assert!(
        matches!(lab.guard_json(&write), Guarded::Denied(why) if why.contains("tollgate's dir")),
        "the Write tool into the state dir"
    );
    // A genuine full pass of a good branch, and a full fail of a bad one.
    let remote = lab.refs_in(&lab.bare);
    lab.plain(&["checkout", "-q", "-b", "good"]);
    lab.stage_code_change("good");
    lab.plain(&["commit", "-q", "--no-verify", "-m", "good"]);
    lab.plain(&["checkout", "-q", "-b", "feat", "main"]);
    lab.stage_bad_file("1");
    lab.plain(&["commit", "-q", "--no-verify", "-m", "bad"]);
    let s = lab.session("git push -q origin good");
    assert!(s.out().contains("pass pre-push refs/heads/good"), "{s:?}");
    let remote_good = lab.refs_in(&lab.bare);
    let s = lab.refused("git push -q origin feat");
    assert!(s.out().contains("verdict fail"), "{s:?}");
    let full_record = |branch: &str| -> (PathBuf, serde_json::Value) {
        let tree = lab.plain(&["rev-parse", &format!("{branch}^{{tree}}")]);
        std::fs::read_dir(&results)
            .unwrap()
            .flatten()
            .flat_map(|d| std::fs::read_dir(d.path()).unwrap().flatten())
            .map(|f| {
                let v: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(f.path()).unwrap()).unwrap();
                (f.path(), v)
            })
            .find(|(_, v)| v["tree"] == tree.as_str() && v["tier"] == "full")
            .unwrap_or_else(|| panic!("no full record of {branch}"))
    };
    let (fail_path, fail) = full_record("feat");
    let (_, pass) = full_record("good");
    assert_eq!(
        (fail["verdict"].as_str(), pass["verdict"].as_str()),
        (Some("fail"), Some("pass"))
    );
    let forge = |v: &serde_json::Value| {
        std::fs::write(&fail_path, serde_json::to_vec_pretty(v).unwrap()).unwrap();
    };
    let push_refused = |what: &str| {
        let s = lab.refused("git push -q origin feat");
        assert!(
            s.out().contains("DENIED pre-push refs/heads/feat"),
            "{what}: {s:?}"
        );
        assert_ne!(lab.refs_in(&lab.bare), remote, "{what}");
        assert_eq!(
            lab.refs_in(&lab.bare),
            remote_good,
            "{what}: feat reached the remote"
        );
    };
    // 1. A pass whose job has no report.json.
    let mut f1 = fail.clone();
    f1["verdict"] = "pass".into();
    f1["job_id"] = "20260101-000000-deadbeef".into();
    forge(&f1);
    push_refused("no report.json");
    // 2. The genuine fail record with its verdict changed to pass (its
    // job's report.json says fail).
    let mut f2 = fail.clone();
    f2["verdict"] = "pass".into();
    forge(&f2);
    push_refused("verdict changed");
    // 3. The good tree's pass record copied to the bad tree's key.
    forge(&pass);
    push_refused("copied pass record");
}

/// S12: a branch that drops the tests step from `tollgate.toml`, or
/// quarantines the failing test, is still checked with `main`'s policy.
#[test]
fn s12_a_branch_cannot_weaken_its_own_policy() {
    let lab = Lab::new(RUST_POLICY);
    lab.plain(&["checkout", "-q", "-b", "feat"]);
    let until = jiff::Zoned::now()
        .date()
        .checked_add(jiff::Span::new().days(10))
        .unwrap();
    for weak in [
        "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n".to_owned(),
        format!(
            "{RUST_POLICY}[[quarantine]]\ntest = \"b tests::fails\"\nuntil = \"{until}\"\nissue = \"Issues/open/x\"\n"
        ),
    ] {
        lab.plain(&["reset", "-q", "--hard", "main"]);
        std::fs::write(lab.repo.join("tollgate.toml"), &weak).unwrap();
        lab.plain(&["add", "tollgate.toml"]);
        lab.stage_failing_test();
        let s = lab.refused("git commit -m weaken");
        assert!(
            s.out()
                .contains("POLICY: this branch changes tollgate.toml")
                && s.out().contains("FAIL b"),
            "{s:?}"
        );
        // Also when the weakened policy is already on the branch.
        lab.plain(&[
            "commit",
            "-q",
            "--no-verify",
            "-m",
            "weak policy",
            "--",
            "tollgate.toml",
        ]);
        let s = lab.refused("git commit -m after-weaken");
        assert!(
            s.out()
                .contains("POLICY: this branch changes tollgate.toml")
                && s.out().contains("FAIL b"),
            "{s:?}"
        );
    }
}

/// S13: a branch that adds `.cargo/config.toml` with `runner = "true"`
/// (test binaries then never run), directly, as the legacy `.cargo/config`
/// or through a symlinked `.cargo` dir: the failing test still fails.
#[test]
fn s13_a_branch_cargo_runner_cannot_hide_a_failing_test() {
    let lab = Lab::new(RUST_POLICY);
    lab.plain(&["checkout", "-q", "-b", "feat"]);
    let runner = "[target.'cfg(all())']\nrunner = \"true\"\n";
    let setups: [&dyn Fn(&Path); 3] = [
        &|r: &Path| {
            std::fs::create_dir_all(r.join(".cargo")).unwrap();
            std::fs::write(r.join(".cargo/config.toml"), runner).unwrap();
        },
        &|r: &Path| {
            std::fs::create_dir_all(r.join(".cargo")).unwrap();
            std::fs::write(r.join(".cargo/config"), runner).unwrap();
        },
        &|r: &Path| {
            std::fs::create_dir_all(r.join("tools/cargo-cfg")).unwrap();
            std::fs::write(r.join("tools/cargo-cfg/config.toml"), runner).unwrap();
            std::os::unix::fs::symlink("tools/cargo-cfg", r.join(".cargo")).unwrap();
        },
    ];
    for (i, setup) in setups.iter().enumerate() {
        lab.plain(&["reset", "-q", "--hard", "main"]);
        let _ = std::fs::remove_dir_all(lab.repo.join(".cargo"));
        let _ = std::fs::remove_file(lab.repo.join(".cargo"));
        setup(&lab.repo);
        lab.plain(&["add", "-A"]);
        lab.stage_failing_test();
        let s = lab.refused("git commit -m runner");
        assert!(s.out().contains("DENIED pre-commit"), "variant {i}: {s:?}");
        let job = job_id(s.out());
        let report = lab.sb().report(&job);
        // The test binaries ran (the runner did not replace them): the
        // failing test fails.
        assert_eq!(report["verdict"], "fail", "variant {i}: {report}");
        assert!(
            s.out().contains("FAIL b b tests::fails"),
            "variant {i}: {s:?}"
        );
    }
}

/// S14: a remote-tracking `main` written by `update-ref` or by a fetch
/// refspec into `refs/remotes` is not trusted: the branch does not become
/// its own policy commit, and the push gate does not call a forged value
/// remote-verified.
#[test]
fn s14_forged_remote_tracking_anchors_are_not_trusted() {
    let lab = Lab::new(BAD_FILE_POLICY);
    // The guard denies the plain forgery...
    assert!(
        lab.refused("git update-ref refs/remotes/origin/main HEAD")
            .denied()
    );
    // ...and tollgate does not trust it when it happens anyway.
    lab.plain(&["checkout", "-q", "-b", "feat"]);
    std::fs::write(
        lab.repo.join("tollgate.toml"),
        "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n",
    )
    .unwrap();
    lab.plain(&["commit", "-q", "--no-verify", "-am", "weaken"]);
    let fake = lab.root().join("fake.git");
    lab.plain_in(
        &lab.root(),
        &["init", "-q", "--bare", fake.to_str().unwrap()],
    );
    lab.plain(&["push", "-q", fake.to_str().unwrap(), "feat:main"]);
    let forgeries: [&[&str]; 4] = [
        &["update-ref", "refs/remotes/origin/main", "feat"],
        &[
            "update-ref",
            "-m",
            "fetch: fast-forward",
            "refs/remotes/origin/main",
            "feat",
        ],
        &["fetch", "-q", ".", "+feat:refs/remotes/origin/main"],
        &[
            "fetch",
            "-q",
            fake.to_str().unwrap(),
            "+main:refs/remotes/origin/main",
        ],
    ];
    for (i, forge) in forgeries.iter().enumerate() {
        lab.plain(&["fetch", "-q", "origin"]);
        lab.plain(forge);
        assert_eq!(
            lab.plain(&["rev-parse", "origin/main"]),
            lab.plain(&["rev-parse", "feat"])
        );
        lab.stage_bad_file(&i.to_string());
        let s = lab.refused("git commit -m bad");
        assert!(
            s.out().contains("DENIED pre-commit refs/heads/feat"),
            "{forge:?}: {s:?}"
        );
    }
    // R14(2): a forged origin/main equal to a failing main is not
    // remote-verified for a push elsewhere.
    lab.plain(&["checkout", "-q", "-f", "main"]);
    lab.stage_bad_file("main");
    lab.plain(&["commit", "-q", "--no-verify", "-m", "bad main"]);
    lab.plain(&["update-ref", "refs/remotes/origin/main", "main"]);
    let mac = lab.root().join("mac.git");
    lab.plain_in(
        &lab.root(),
        &["init", "-q", "--bare", mac.to_str().unwrap()],
    );
    lab.plain(&["remote", "add", "mac", mac.to_str().unwrap()]);
    let s = lab.refused("git push mac main");
    assert!(
        s.out().contains("DENIED pre-push refs/heads/main") && !s.out().contains("remote-verified"),
        "{s:?}"
    );
    assert_eq!(lab.refs_in(&mac), "");
}

/// S15: `url.<x>.insteadOf` that sends the trusted remote's URL to
/// another repo: the guard asks before the write, and the redirected
/// remote vouches for nothing (policy anchor, R14(2)).
#[test]
fn s15_an_insteadof_redirect_is_not_trusted() {
    let lab = Lab::new(BAD_FILE_POLICY);
    let bare = lab.bare.to_str().unwrap().to_owned();
    let fake = lab.root().join("fake.git");
    let fake_s = fake.to_str().unwrap().to_owned();
    lab.plain_in(&lab.root(), &["init", "-q", "--bare", &fake_s]);
    let key = format!("url.{fake_s}.insteadOf");
    assert!(matches!(
        lab.guard(&format!("git config {key} {bare}")),
        Guarded::Asked(why) if why.contains("git config writes url.")
    ));
    // The fake server's main: a weakened policy, then a failing tree.
    lab.plain(&["checkout", "-q", "-b", "weak"]);
    std::fs::write(
        lab.repo.join("tollgate.toml"),
        "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n",
    )
    .unwrap();
    lab.plain(&["commit", "-q", "--no-verify", "-am", "weaken"]);
    lab.plain(&["push", "-q", &fake_s, "weak:main"]);
    lab.plain(&["config", &key, &bare]);
    lab.plain(&["fetch", "-q", "origin"]);
    assert_eq!(
        lab.plain(&["rev-parse", "origin/main"]),
        lab.plain(&["rev-parse", "weak"])
    );
    // A bad commit on a branch of the weakened main: main's own policy.
    lab.stage_bad_file("1");
    let s = lab.refused("git commit -m bad");
    assert!(s.out().contains("DENIED pre-commit"), "{s:?}");
    // R14(2): the redirected origin reports a failing main; a push of
    // that main elsewhere is not remote-verified.
    lab.plain(&["commit", "-q", "--no-verify", "-m", "bad"]);
    lab.plain(&["push", "-q", "-f", &fake_s, "weak:main"]);
    lab.plain(&["fetch", "-q", "origin"]);
    lab.plain(&["branch", "-f", "main", "weak"]);
    let mac = lab.root().join("mac.git");
    lab.plain_in(
        &lab.root(),
        &["init", "-q", "--bare", mac.to_str().unwrap()],
    );
    lab.plain(&["remote", "add", "mac", mac.to_str().unwrap()]);
    let s = lab.refused("git push mac main");
    assert!(
        s.out().contains("DENIED pre-push") && !s.out().contains("remote-verified"),
        "{s:?}"
    );
    assert_eq!(lab.refs_in(&mac), "");
}

/// S16: a remote URL with a newline (which could fake a second
/// `git remote -v` line) denies every gated commit and push.
#[test]
fn s16_a_remote_url_with_a_newline_denies() {
    let lab = Lab::new(BAD_FILE_POLICY);
    let fake = lab.root().join("fake.git");
    lab.plain_in(
        &lab.root(),
        &["init", "-q", "--bare", fake.to_str().unwrap()],
    );
    let injected = format!("{}\norigin\t{} (fetch)", fake.display(), lab.bare.display());
    lab.plain(&["config", "remote.origin.url", &injected]);
    lab.stage_bad_file("1");
    let s = lab.refused("git commit -m bad");
    assert!(
        s.out().contains("DENIED pre-commit") && s.out().contains("control character"),
        "{s:?}"
    );
    // Fail closed: a good tree too.
    lab.plain(&["rm", "-q", "--cached", "bad"]);
    std::fs::write(lab.repo.join("ok.txt"), "1\n").unwrap();
    lab.plain(&["add", "ok.txt"]);
    let s = lab.refused("git commit -m ok");
    assert!(s.out().contains("control character"), "{s:?}");
    lab.plain(&["commit", "-q", "--no-verify", "-m", "ok"]);
    let mac = lab.root().join("mac.git");
    lab.plain_in(
        &lab.root(),
        &["init", "-q", "--bare", mac.to_str().unwrap()],
    );
    let s = lab.refused(&format!("git push {} main", mac.display()));
    assert!(s.out().contains("DENIED pre-push"), "{s:?}");
    assert_eq!(lab.refs_in(&mac), "");
}

/// A sandbox for `install` (S17, S41): a fake `claude`, a host config and
/// the settings file `<home>/.claude/settings.json` holding `text`.
struct InstallLab {
    sb: Sandbox,
    path: String,
}

impl InstallLab {
    fn new(text: &str) -> Self {
        let sb = Sandbox::new();
        let bin_dir = sb.root().join("bin");
        write_exe(
            &bin_dir.join("claude"),
            "#!/bin/sh\necho '2.1.317 (Claude Code)'\n",
        );
        sb.host_config("[verify]\nmin_free = \"1M\"\n");
        std::fs::create_dir_all(sb.home.join(".claude")).unwrap();
        std::fs::write(sb.home.join(".claude/settings.json"), text).unwrap();
        let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap());
        Self { sb, path }
    }

    fn settings(&self) -> PathBuf {
        self.sb.home.join(".claude/settings.json")
    }

    fn data(&self) -> PathBuf {
        self.sb.root().join("data/tollgate")
    }

    /// `program args` with the sandbox env, the fake claude on PATH and
    /// `extra`; no stdio set.
    fn cmd(&self, program: &Path, args: &[&str], extra: &[(&str, &std::ffi::OsStr)]) -> Command {
        let mut cmd = Command::new(program);
        cmd.env_clear().current_dir(self.sb.root()).args(args);
        for (k, v) in self.sb.env().iter() {
            cmd.env(k, v);
        }
        cmd.env("PATH", &self.path);
        for (k, v) in extra {
            cmd.env(k, v);
        }
        cmd
    }
}

/// S17 (L10, items 9 and 29): `install` and `uninstall` change settings
/// only for a person at an interactive terminal (stdin and stdout).
/// Without one nothing is written, whatever names the file: the sandbox
/// home, `--yes`, `CLAUDE_CONFIG_DIR` at the active config (Claude Code's
/// config dir can be anywhere), the item 9 `TMPDIR` trick, a settings
/// file that is a symlink to another. A terminal on stdin alone is not
/// enough either.
#[test]
fn s17_install_and_uninstall_need_an_interactive_terminal() {
    let original = "{\n  \"env\": {\n    \"KEEP\": \"1\"\n  }\n}\n";
    let lab = InstallLab::new(original);
    let real = lab.sb.home.join(".claude");
    let active = lab.sb.root().join("active");
    std::fs::create_dir_all(&active).unwrap();
    std::fs::write(active.join("settings.json"), original).unwrap();
    let linked = lab.sb.root().join("linked");
    std::fs::create_dir_all(&linked).unwrap();
    std::os::unix::fs::symlink(real.join("settings.json"), linked.join("settings.json")).unwrap();
    let unchanged = |what: &str, r: &Run| {
        assert_ne!(r.code, Some(0), "{what}: {}", r.out);
        for f in [real.join("settings.json"), active.join("settings.json")] {
            assert_eq!(
                std::fs::read_to_string(&f).unwrap(),
                original,
                "{what}: {} changed: {}",
                f.display(),
                r.out
            );
        }
        assert!(
            !lab.data().exists(),
            "{what}: the data dir was made: {}",
            r.out
        );
    };
    let extras: [Vec<(&str, &std::ffi::OsStr)>; 5] = [
        vec![],
        vec![("CLAUDE_CONFIG_DIR", active.as_os_str())],
        vec![("TMPDIR", real.as_os_str())],
        vec![
            ("TMPDIR", real.as_os_str()),
            ("TOLLGATE_TEST_INSTALL", "1".as_ref()),
        ],
        vec![("CLAUDE_CONFIG_DIR", linked.as_os_str())],
    ];
    for args in [
        &["install"][..],
        &["install", "--yes"],
        &["uninstall"],
        &["uninstall", "--yes"],
    ] {
        for extra in &extras {
            let what = format!("{args:?} {extra:?}");
            let out = lab
                .cmd(Path::new(support::BIN), args, extra)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            let r = Run {
                code: out.status.code(),
                out: format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                ),
            };
            unchanged(&format!("no terminal, {what}"), &r);
            let r = pty::run(
                lab.cmd(Path::new(support::BIN), args, extra),
                pty::Streams::StdinOnly,
                &["y"],
            );
            unchanged(&format!("a terminal on stdin only, {what}"), &r);
        }
    }
    // Control: at a terminal, after a yes, install edits the active
    // config; uninstall without a terminal leaves it, at one removes it.
    let at_active = [("CLAUDE_CONFIG_DIR", active.as_os_str())];
    let r = pty::run(
        lab.cmd(Path::new(support::BIN), &["install"], &at_active),
        pty::Streams::All,
        &["y"],
    );
    assert_eq!(r.code, Some(0), "{}", r.out);
    let installed = std::fs::read_to_string(active.join("settings.json")).unwrap();
    assert!(installed.contains("core.hooksPath"), "{installed}");
    let bin = lab.data().join("bin/tollgate");
    let out = lab
        .cmd(&bin, &["uninstall"], &at_active)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
    assert_eq!(
        std::fs::read_to_string(active.join("settings.json")).unwrap(),
        installed
    );
    assert!(bin.exists());
    let r = pty::run(
        lab.cmd(&bin, &["uninstall"], &at_active),
        pty::Streams::All,
        &["y"],
    );
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        !std::fs::read_to_string(active.join("settings.json"))
            .unwrap()
            .contains("core.hooksPath")
    );
    assert!(!lab.data().exists());

    // A session cannot make the terminal: a pty wrapper would give one
    // and type the yes, so the guard denies install and uninstall in a
    // session in any form (R25).
    let lab = Lab::new(BAD_FILE_POLICY);
    let bad = lab.not_denied(&owned(&[
        "tollgate install",
        "tollgate uninstall",
        "printf 'y\\n' | script -qec 'tollgate install' /dev/null",
        "yes | script -qc 'tollgate uninstall' /dev/null",
        "unbuffer tollgate install",
        "socat - EXEC:'tollgate install',pty",
        "python3 -c \"import pty; pty.spawn(['tollgate', 'install'])\"",
        "expect -c 'spawn tollgate install; send y\\r; expect eof'",
    ]));
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// S18: a docs-only commit gets no pass when the base policy is invalid
/// (a config error ends every job, the docs-only shortcut included) or
/// when its job is cancelled.
#[test]
fn s18_docs_only_commits_without_a_valid_policy_or_a_finished_job_get_no_pass() {
    let until = jiff::Zoned::now()
        .date()
        .checked_add(jiff::Span::new().days(60))
        .unwrap();
    for policy in [
        format!(
            "{BAD_FILE_POLICY}[[quarantine]]\ntest = \"a tests::ok\"\nuntil = \"{until}\"\nissue = \"Issues/open/x\"\n"
        ),
        "version = 1\n[[step]]\nname = \"x\"\nkind = \"no-such-kind\"\n".to_owned(),
        "version = 1\n[[step]\n".to_owned(),
    ] {
        let lab = Lab::new(&policy);
        std::fs::write(lab.repo.join("NOTES.md"), "docs\n").unwrap();
        lab.plain(&["add", "NOTES.md"]);
        let s = lab.refused("git commit -m docs");
        assert!(s.out().contains("DENIED pre-commit"), "{policy}: {s:?}");
        assert!(lab.pass_trees(None).is_empty(), "{policy}");
    }

    // Cancelled: the job waits for its checkout (the test holds the lock,
    // as another job would), the commit waits on the job, and the agent
    // cancels it.
    let lab = Lab::new(RUST_POLICY);
    std::fs::write(lab.repo.join("NOTES.md"), "docs\n").unwrap();
    lab.plain(&["add", "NOTES.md"]);
    let env = lab.sb().env();
    let dirs = tollgate::dirs::Dirs::from_env(&env).unwrap();
    let host = tollgate::config::HostConfig::load(&dirs).unwrap();
    let git = tollgate::gitx::Git::scrubbed(&env, &lab.repo);
    let layout = tollgate::gitx::RepoLayout::discover(&git).unwrap();
    let place = tollgate::runner::checkout::Place::new(
        &host.config.verify.root(&dirs),
        &layout.repo_key(),
        tollgate::config::Tier::Fast,
        &lab.repo,
    );
    let held = tollgate::locks::LockFile::try_acquire(&place.lock)
        .unwrap()
        .expect("the checkout lock is free");
    let before = lab.refs();
    let Guarded::Allowed(cmd) = lab.guard("git commit -m docs") else {
        panic!("the guard stopped a plain commit");
    };
    let child = lab
        .cmd("bash", &lab.repo)
        .args(["-c", &cmd])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    assert!(eventually(20, || !lab.sb().jobs().is_empty()), "no job");
    let job = lab.sb().jobs()[0].clone();
    let s = lab.session(&format!("tollgate cancel {job}"));
    assert!(s.out().contains("cancel"), "{s:?}");
    let waiter = std::thread::spawn(move || child.wait_with_output().unwrap());
    let end = Instant::now() + Duration::from_secs(30);
    while !waiter.is_finished() {
        assert!(Instant::now() < end, "the commit still waits after cancel");
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = waiter.join().unwrap();
    drop(held);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("DENIED pre-commit"), "{text}");
    assert_eq!(lab.refs(), before);
    let w = lab.session(&format!("tollgate wait {job} --timeout 30s"));
    assert!(matches!(w.code(), Some(c) if c != 0), "{w:?}");
    assert_eq!(lab.sb().record_count(), 0, "a cancelled job wrote a record");
    assert_eq!(lab.sb().report(&job)["outcome"], "cancelled");
}

/// S19: a commit made with `--no-verify` straight through git (not
/// through the guard, as a script would) still runs `post-commit`, which
/// records it as unverified; `tollgate status` shows it, and its push is
/// refused.
#[test]
fn s19_a_no_verify_commit_outside_the_guard_is_marked_unverified() {
    let lab = Lab::new(BAD_FILE_POLICY);
    let remote = lab.refs_in(&lab.bare);
    lab.plain(&["checkout", "-q", "-b", "feat"]);
    lab.stage_bad_file("1");
    let r = lab.direct(&["commit", "--no-verify", "-m", "skip the gate"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let skipped = lab.head();
    assert!(
        r.out.contains("WARNING") && r.out.contains("unverified") && r.out.contains(&skipped[..12]),
        "{}",
        r.out
    );
    let s = lab.session("tollgate status");
    assert!(
        s.out()
            .contains("unverified: 1 commit(s) made without the gate")
            && s.out().contains(&skipped[..12]),
        "{s:?}"
    );
    let s = lab.refused("git push origin feat");
    assert!(
        s.out().contains("DENIED pre-push") && s.out().contains("made without the gate"),
        "{s:?}"
    );
    lab.assert_remote_is(&remote);
}

/// S20's trusted server over ssh: an ssh that runs the requested command
/// on this machine, as the server's sshd would.
const HONEST_SSH: &str = "#!/bin/sh\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    -o|-p|-l|-i|-F|-J) shift 2 ;;\n    -*) shift ;;\n    *) break ;;\n  esac\ndone\nshift\nexec sh -c \"$*\"\n";

/// A policy that lets every tree pass.
const WEAK_POLICY: &str =
    "version = 1\n[[step]]\nname = \"ok\"\nkind = \"command\"\nrun = \"true\"\n";

/// S20: what the trusted server reports (L2 anchors, R56 bases, R14(2))
/// comes from the trusted server only. A fake ssh (named by
/// `GIT_SSH_COMMAND`, `GIT_SSH`, a global `core.sshCommand` or a dir first
/// on the agent's PATH) and a global `url.<x>.insteadOf` never answer for
/// it: the guard denies the variables and asks before the config writes,
/// and when they reach git anyway (a script file), tollgate asks the real
/// server and keeps no forged value.
#[test]
fn s20_a_fake_ssh_or_a_global_rewrite_never_answers_for_the_trusted_server() {
    let lab = Lab::new(BAD_FILE_POLICY);
    let root = lab.root();
    let bin = root.join("bin");
    let honest = bin.join("ssh");
    write_exe(&honest, HONEST_SSH);
    // tollgate finds ssh on the job PATH (`job.path_prepend`, then the
    // system dirs), never on the agent's PATH.
    lab.sb().host_config(&format!(
        "[scope]\nremotes = [\"ssh://localhost{}\"]\n[job]\npath_prepend = [\"{}\"]\n[verify]\nmin_free = \"1M\"\n",
        lab.bare.display(),
        bin.display()
    ));
    let url = format!("ssh://localhost{}", lab.bare.display());
    let honest_ssh = format!("core.sshCommand={}", honest.display());
    lab.plain(&["remote", "set-url", "origin", &url]);
    lab.plain(&["-c", &honest_ssh, "fetch", "-q", "origin"]);
    // The fake server's main: a branch that weakens the policy.
    lab.plain(&["checkout", "-q", "-b", "feat"]);
    std::fs::write(lab.repo.join("tollgate.toml"), WEAK_POLICY).unwrap();
    lab.plain(&["commit", "-q", "--no-verify", "-am", "weaken"]);
    let fake = root.join("fake.git");
    let fake_s = fake.to_str().unwrap().to_owned();
    lab.plain_in(&root, &["init", "-q", "--bare", &fake_s]);
    lab.plain(&["push", "-q", &fake_s, "feat:main"]);
    let forged = lab.plain(&["rev-parse", "feat"]);
    let forger_dir = root.join("forger");
    let forger = forger_dir.join("ssh");
    let forger_s = forger.to_str().unwrap().to_owned();
    write_exe(
        &forger,
        &format!("#!/bin/sh\nexec git-upload-pack '{fake_s}'\n"),
    );
    let store = lab.sb().state().join("remote-refs.json");
    let assert_not_kept = |oid: &str, how: &str| {
        let text = std::fs::read_to_string(&store).unwrap_or_default();
        assert!(
            !text.contains(oid),
            "{how}: remote-refs.json keeps the forged {oid}:\n{text}"
        );
    };
    // Main's policy decides, from what the real server reports.
    let main_policy_denies = |code: Option<i32>, out: &str, how: &str| {
        assert!(
            code != Some(0)
                && out.contains("DENIED pre-commit refs/heads/feat")
                && !out.contains("no policy anchor"),
            "{how}: {out}"
        );
        assert_not_kept(&forged, how);
    };

    // Control: the real server answers through the honest ssh, so a good
    // commit on feat runs main's policy and passes.
    std::fs::write(lab.repo.join("ok.txt"), "1\n").unwrap();
    lab.plain(&["add", "ok.txt"]);
    let s = lab.session("git commit -q -m ok");
    assert_eq!(s.code(), Some(0), "{s:?}");

    // origin/main forged to feat, as a fetch through the fake ssh would.
    lab.plain(&["update-ref", "refs/remotes/origin/main", "feat"]);
    for var in ["GIT_SSH_COMMAND", "GIT_SSH"] {
        lab.stage_bad_file(var);
        let before = lab.refs();
        let r = lab.direct_with(&["commit", "-m", "bad"], &[(var, &forger_s)]);
        main_policy_denies(r.code, &r.out, var);
        assert_eq!(lab.refs(), before, "{var}: a ref moved");
        let cmd = format!("{var}={forger_s} git commit -m bad");
        assert!(lab.refused(&cmd).denied(), "{cmd}");
        let cmd = format!("export {var}={forger_s}; git commit -m bad");
        assert!(lab.refused(&cmd).denied(), "{cmd}");
    }
    lab.stage_bad_file("PATH");
    // G4: only listed variables go in front of a gated git command, so the
    // guard denies a PATH prefix; set anyway (a script file), the fake ssh
    // first on PATH still does not answer.
    let cmd = format!("PATH={}:$PATH git commit -m bad", forger_dir.display());
    assert!(lab.refused(&cmd).denied(), "{cmd}");
    let path = format!("{}:{}", forger_dir.display(), lab.a.path);
    let before = lab.refs();
    let r = lab.direct_with(&["commit", "-m", "bad"], &[("PATH", &path)]);
    main_policy_denies(r.code, &r.out, &cmd);
    assert_eq!(lab.refs(), before, "PATH: a ref moved");

    // A global core.sshCommand: the guard asks; set anyway, tollgate does
    // not read it.
    let cmd = format!("git config --global core.sshCommand {forger_s}");
    assert!(
        matches!(lab.guard(&cmd), Guarded::Asked(ref why) if why.contains("core.sshCommand")),
        "{cmd}"
    );
    lab.plain(&["config", "--global", "core.sshCommand", &forger_s]);
    lab.stage_bad_file("core.sshCommand");
    let s = lab.refused("git commit -m bad");
    main_policy_denies(s.code(), s.out(), "global core.sshCommand");
    lab.plain(&["config", "--global", "--unset", "core.sshCommand"]);

    // A global rewrite of the trusted URL to the fake repo, with origin
    // set to an alias that another rewrite turns into the trusted URL:
    // the repo's remote is trusted, and only the server query would follow
    // the second rewrite.
    lab.plain(&[
        "config",
        "--global",
        &format!("url.{url}.insteadOf"),
        "tg-alias:",
    ]);
    lab.plain(&[
        "config",
        "--global",
        &format!("url.{fake_s}.insteadOf"),
        &url,
    ]);
    lab.plain(&["remote", "set-url", "origin", "tg-alias:"]);
    assert_eq!(lab.plain(&["remote", "get-url", "origin"]), url);
    lab.stage_bad_file("insteadOf");
    let s = lab.refused("git commit -m bad");
    main_policy_denies(s.code(), s.out(), "global insteadOf");
    lab.plain(&["remote", "set-url", "origin", &url]);
    lab.plain(&[
        "config",
        "--global",
        "--remove-section",
        &format!("url.{url}"),
    ]);
    lab.plain(&[
        "config",
        "--global",
        "--remove-section",
        &format!("url.{fake_s}"),
    ]);

    // Nothing forged was kept: a later commit with no fake ssh is still
    // checked under main's policy.
    lab.stage_bad_file("later");
    let s = lab.refused("git commit -m bad");
    main_policy_denies(s.code(), s.out(), "later");

    // R14(2): a failing main that the fake ssh reports as the server's
    // main is not remote-verified for a push elsewhere.
    lab.plain(&["checkout", "-q", "-f", "main"]);
    lab.stage_bad_file("main");
    lab.plain(&["commit", "-q", "--no-verify", "-m", "bad main"]);
    let bad_main = lab.head();
    lab.plain(&["push", "-q", "-f", &fake_s, "main:main"]);
    lab.plain(&["update-ref", "refs/remotes/origin/main", "main"]);
    let mac = root.join("mac.git");
    lab.plain_in(&root, &["init", "-q", "--bare", mac.to_str().unwrap()]);
    lab.plain(&["remote", "add", "mac", mac.to_str().unwrap()]);
    let r = lab.direct_with(&["push", "mac", "main"], &[("GIT_SSH_COMMAND", &forger_s)]);
    assert!(
        r.code != Some(0)
            && r.out.contains("DENIED pre-push refs/heads/main")
            && !r.out.contains("remote-verified"),
        "{}",
        r.out
    );
    assert_eq!(lab.refs_in(&mac), "");
    assert_not_kept(&bad_main, "R14(2)");
}

/// S32 (item 38): `CARGO_HOME` (and `RUSTUP_HOME`) set for one git command
/// outside the guard (a script file) does not reach the job: its `bin`
/// would come first on the job PATH, and a fake cargo there could add a
/// runner that never runs the test binaries. The job takes both from the
/// host config or the install's home, so the failing test still fails and
/// the fake never runs.
#[test]
fn s32_cargo_home_from_the_hook_environment_never_reaches_the_job() {
    let lab = Lab::new(RUST_POLICY);
    let root = lab.root();
    let fake_home = root.join("fake-cargo-home");
    let mark = root.join("fake-cargo-ran");
    // The cargo the job would find without the fake (never the fake
    // itself: that would exec itself forever).
    let real_cargo = ["/usr/local/bin/cargo", "/usr/bin/cargo"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .or_else(|| support::tools::which("cargo"))
        .expect("cargo");
    write_exe(
        &fake_home.join("bin/cargo"),
        &format!(
            "#!/bin/sh\ntouch '{}'\nexec '{}' --config \"target.'cfg(all())'.runner = 'true'\" \"$@\"\n",
            mark.display(),
            real_cargo.display()
        ),
    );
    let fake_rustup = root.join("fake-rustup-home");
    std::fs::create_dir_all(&fake_rustup).unwrap();
    lab.stage_failing_test();
    let before = lab.refs();
    let r = lab.direct_with(
        &["commit", "-m", "fake cargo"],
        &[
            ("CARGO_HOME", fake_home.to_str().unwrap()),
            ("RUSTUP_HOME", fake_rustup.to_str().unwrap()),
        ],
    );
    assert_ne!(r.code, Some(0), "{}", r.out);
    assert!(
        r.out.contains("DENIED pre-commit") && r.out.contains("FAIL b b tests::fails"),
        "{}",
        r.out
    );
    assert_eq!(lab.refs(), before);
    assert!(!mark.exists(), "the job ran the fake cargo");
    let spec: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            lab.sb()
                .state()
                .join("jobs")
                .join(job_id(&r.out))
                .join("spec.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let text = spec.to_string();
    assert!(
        !text.contains("fake-cargo-home") && !text.contains("fake-rustup-home"),
        "{spec:#}"
    );
    lab.assert_no_bad_pass();
}

/// S33 (item 39): `GIT_EXEC_PATH` set for one git command outside the
/// guard (a script file) goes first on the hooks' `PATH`, so a `git`
/// there would answer tollgate's own git calls in the hook and the job
/// (here: one that logs each call and then runs the real git). tollgate
/// runs git by the absolute path install recorded and removes
/// `GIT_EXEC_PATH` from every git it starts: the fake never runs, and the
/// failing test still fails.
#[test]
fn s33_git_exec_path_never_picks_the_git_tollgate_runs() {
    let lab = Lab::new(BAD_FILE_POLICY);
    let root = lab.root();
    // install.json names the git the hooks run.
    let rec: serde_json::Value =
        serde_json::from_slice(&std::fs::read(lab.a.data().join("install.json")).unwrap()).unwrap();
    let git = PathBuf::from(rec["git"].as_str().expect("install.json records git"));
    assert!(git.is_absolute() && git.is_file(), "{rec:#}");
    let exec = lab
        .plain_in(&root, &["--exec-path"])
        .lines()
        .next()
        .unwrap()
        .to_owned();
    let fake = root.join("fake-exec");
    let log = root.join("fake-git.log");
    std::fs::create_dir_all(&fake).unwrap();
    // The fake dir holds git's own helpers too (so the commit works) and a
    // `git` that logs.
    for e in std::fs::read_dir(&exec).unwrap().flatten() {
        if e.file_name() != "git" {
            std::os::unix::fs::symlink(e.path(), fake.join(e.file_name())).unwrap();
        }
    }
    write_exe(
        &fake.join("git"),
        &format!(
            "#!/bin/sh\necho \"$*\" >> '{}'\nexec '{}' \"$@\"\n",
            log.display(),
            git.display()
        ),
    );
    lab.stage_bad_file("exec path");
    let before = lab.refs();
    let r = lab.direct_with(
        &["commit", "-m", "fake git"],
        &[("GIT_EXEC_PATH", fake.to_str().unwrap())],
    );
    assert_ne!(r.code, Some(0), "{}", r.out);
    assert!(r.out.contains("DENIED pre-commit"), "{}", r.out);
    assert_eq!(lab.refs(), before);
    assert!(
        !log.exists(),
        "tollgate ran the fake git: {}",
        std::fs::read_to_string(&log).unwrap_or_default()
    );
    lab.assert_no_bad_pass();
    // doctor names the recorded git.
    let out = lab
        .cmd(lab.a.bin(), &lab.repo)
        .arg("doctor")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("ok   git: ") && text.contains(git.to_str().unwrap()),
        "{text}"
    );
}

/// S30 (item 34, X5): a `scope.remotes` pattern trusts only the server it
/// names. A local bare repo whose path spells `gitlab.com/victorkwak/...`
/// matches the loose glob (the repo stays in scope and its pushes are
/// gated) but is never trusted: its `main`, which drops the checks, does
/// not become the policy anchor, so a bad commit is still refused.
#[test]
fn s30_a_look_alike_remote_path_is_never_trusted() {
    let lab = Lab::new(BAD_FILE_POLICY);
    let sb = lab.sb();
    let root = lab.root();
    sb.host_config(
        "[scope]\nremotes = [\"*gitlab.com:victorkwak/*\", \"*gitlab.com/victorkwak/*\"]\n[verify]\nmin_free = \"1M\"\n",
    );
    // The look-alike "server": its main has a policy with no checks.
    let evil = root.join("evil/gitlab.com/victorkwak/ws.git");
    std::fs::create_dir_all(&evil).unwrap();
    lab.plain_in(&evil, &["init", "-q", "--bare"]);
    lab.plain(&["checkout", "-q", "-b", "weak"]);
    std::fs::write(lab.repo.join("tollgate.toml"), WEAK_POLICY).unwrap();
    lab.plain(&["commit", "-q", "--no-verify", "-am", "weaken"]);
    lab.plain(&["push", "-q", evil.to_str().unwrap(), "weak:main"]);
    lab.plain(&["checkout", "-q", "main"]);
    lab.plain(&["branch", "-q", "-D", "weak"]);
    // origin now names it (a script file, outside the guard's ask).
    lab.plain(&["remote", "set-url", "origin", evil.to_str().unwrap()]);
    lab.plain(&["fetch", "-q", "origin"]);
    // A branch on the look-alike's main: if it were trusted, that main
    // would be the policy commit (the merge-base).
    lab.plain(&["checkout", "-q", "-b", "feat", "origin/main"]);
    lab.stage_bad_file("look-alike");
    let s = lab.refused("git commit -m bad");
    assert!(
        s.out().contains("DENIED pre-commit") && s.out().contains("step lint: fail"),
        "{s:?}"
    );
    // Still in scope by the loose match: its push is gated at full.
    lab.plain(&["commit", "-q", "--no-verify", "-m", "bad"]);
    let s = lab.session("git push origin feat");
    assert!(
        s.out().contains("DENIED pre-push") && s.out().contains("tier full"),
        "{s:?}"
    );
    assert!(lab.refs_in(&evil).contains("refs/heads/main"));
    assert!(!lab.refs_in(&evil).contains("refs/heads/feat"));
}

/// S34 (item 33, R4): with its trusted remote gone, a repo never falls
/// back to the local `main` as the policy anchor, which a script file can
/// move. The attack: after a gated commit recorded `origin` as trusted, a
/// script removes `origin` (or points it at another repo, or breaks the
/// record) and moves the local `main` to a commit with a weaker policy; a
/// bad commit on a branch from it must still be refused, with a message
/// that names the lost remote.
#[test]
fn s34_a_lost_trusted_remote_never_makes_local_main_the_anchor() {
    let lab = Lab::new(BAD_FILE_POLICY);
    let root = lab.root();
    let bare = lab.bare.to_str().unwrap().to_owned();
    // A gated commit: tollgate records origin as trusted for this repo.
    std::fs::write(lab.repo.join("ok.txt"), "1\n").unwrap();
    lab.plain(&["add", "ok.txt"]);
    let s = lab.session("git commit -q -m ok");
    assert_eq!(s.code(), Some(0), "{s:?}");
    // The local main gets a policy with no checks (a script file).
    std::fs::write(lab.repo.join("tollgate.toml"), WEAK_POLICY).unwrap();
    lab.plain(&["commit", "-q", "--no-verify", "-am", "weaken"]);
    let weak = lab.head();
    lab.plain(&["checkout", "-q", "-b", "feat"]);
    let attack = |label: &str| {
        lab.stage_bad_file(label);
        let s = lab.refused("git commit -m bad");
        assert!(
            s.out().contains("DENIED pre-commit") && s.out().contains("item 33"),
            "{label}: {s:?}"
        );
        assert!(s.out().contains(&bare), "{label}: {s:?}");
        lab.plain(&["rm", "-q", "--cached", "bad"]);
        std::fs::remove_file(lab.repo.join("bad")).unwrap();
    };
    // 1. origin removed.
    lab.plain(&["remote", "remove", "origin"]);
    attack("removed");
    // 2. origin back, but on another repo that holds the weak main.
    let other = root.join("other.git");
    lab.plain_in(&root, &["init", "-q", "--bare", other.to_str().unwrap()]);
    lab.plain(&[
        "push",
        "-q",
        other.to_str().unwrap(),
        &format!("{weak}:refs/heads/main"),
    ]);
    lab.plain(&["remote", "add", "origin", other.to_str().unwrap()]);
    lab.plain(&["fetch", "-q", "origin"]);
    attack("set to another repo");
    // 3. the same with the record broken (not JSON): still refused.
    let records = lab.sb().state().join("trusted-remotes");
    for e in std::fs::read_dir(&records).unwrap().flatten() {
        if e.path().extension().is_some_and(|x| x == "json") {
            std::fs::write(e.path(), "{not json").unwrap();
        }
    }
    lab.stage_bad_file("broken record");
    let s = lab.refused("git commit -m bad");
    assert!(
        s.out().contains("DENIED pre-commit") && s.out().contains("item 33"),
        "broken record: {s:?}"
    );
}

/// S48 (item 33, secreview notes 2 and 3): the record of a repo's trusted
/// remotes follows the repo, not its path. The attack: after a gated
/// commit recorded `origin`, the repo is copied (`cp -a`) or moved (`mv`),
/// and `origin` is removed in the new path before any gated command runs
/// there (the guard asks; an approved ask is what the record catches).
/// With a key by path only, the new path had no record, so local `main`
/// (weakened by a script) became the policy anchor, or the repo left the
/// gate. It must be refused, naming the lost remote. A deleted record of
/// a known repo denies too (never "no record").
#[test]
fn s48_a_copied_moved_or_unrecorded_repo_keeps_its_lost_trusted_remote() {
    let lab = Lab::new(BAD_FILE_POLICY);
    let root = lab.root();
    let bare = lab.bare.to_str().unwrap().to_owned();
    std::fs::write(lab.repo.join("ok.txt"), "1\n").unwrap();
    lab.plain(&["add", "ok.txt"]);
    let s = lab.session("git commit -q -m ok");
    assert_eq!(s.code(), Some(0), "{s:?}");
    std::fs::write(lab.repo.join("tollgate.toml"), WEAK_POLICY).unwrap();
    lab.plain(&["commit", "-q", "--no-verify", "-am", "weaken"]);
    lab.plain(&["checkout", "-q", "-b", "feat"]);
    let commit = |dir: &Path, file: &str| {
        std::fs::write(dir.join(file), "x\n").unwrap();
        lab.plain_in(dir, &["add", file]);
        let before = lab.refs_in(dir);
        let tree = lab.plain_in(dir, &["write-tree"]);
        let s = lab.session_in(dir, &format!("git commit -q -m {file}"));
        if s.code() != Some(0) {
            assert_eq!(lab.refs_in(dir), before, "{file}: a ref moved: {s:?}");
            assert!(
                !lab.pass_trees(None).contains(&tree.trim().to_owned()),
                "{file}: its tree got a pass"
            );
            lab.plain_in(dir, &["rm", "-q", "--cached", file]);
            std::fs::remove_file(dir.join(file)).unwrap();
        }
        s
    };
    let refused = |dir: &Path, label: &str, names_remote: bool| {
        let s = commit(dir, "bad");
        assert!(
            s.out().contains("DENIED pre-commit") && s.out().contains("item 33"),
            "{label}: {s:?}"
        );
        if names_remote {
            assert!(s.out().contains(&bare), "{label}: {s:?}");
        }
    };
    let cp = |to: &Path| {
        let st = Command::new("cp")
            .arg("-a")
            .arg(&lab.repo)
            .arg(to)
            .status()
            .unwrap();
        assert!(st.success());
    };
    // 1. A copy keeps origin: a good commit is allowed, a bad one refused
    // by the trusted policy.
    let kept = root.join("ws-kept");
    cp(&kept);
    assert_eq!(commit(&kept, "ok2.txt").code(), Some(0));
    // 2. A copy whose origin is removed before its first gated command.
    let copy = root.join("ws-copy");
    cp(&copy);
    lab.plain_in(&copy, &["remote", "remove", "origin"]);
    refused(&copy, "copied", true);
    // 3. The repo itself moved, origin removed in the new path.
    let moved = root.join("ws-moved");
    std::fs::rename(&lab.repo, &moved).unwrap();
    // The guard runs from the old path (an empty dir now).
    std::fs::create_dir(&lab.repo).unwrap();
    lab.plain_in(&moved, &["remote", "remove", "origin"]);
    refused(&moved, "moved", true);
    // 4. Origin back: allowed; then its record is deleted (a script file)
    // and origin removed again: a known repo with no record denies.
    lab.plain_in(&moved, &["remote", "add", "origin", &bare]);
    lab.plain_in(&moved, &["fetch", "-q", "origin"]);
    let s = commit(&moved, "ok3.txt");
    assert_eq!(s.code(), Some(0), "{s:?}");
    let key = tollgate::ids::RepoKey::of_realpath(&moved.join(".git").canonicalize().unwrap());
    let record = lab
        .sb()
        .state()
        .join(format!("trusted-remotes/{}.json", key.as_str()));
    std::fs::remove_file(&record).unwrap();
    lab.plain_in(&moved, &["remote", "remove", "origin"]);
    refused(&moved, "record deleted", false);
    // 5. Victor accepts the copy's change at his own terminal (util-linux
    // `script` gives one): the confirmation names the remote and the repo
    // it was recorded in; then the copy commits on its own policy.
    if cfg!(target_os = "linux") && Path::new("/usr/bin/script").exists() {
        let mut cmd = Command::new("/usr/bin/script");
        cmd.env_clear()
            .current_dir(&copy)
            .args([
                "-qec",
                &format!("{} remotes forget", support::BIN),
                "/dev/null",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in lab.sb().env().iter() {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().unwrap();
        child.stdin.as_mut().unwrap().write_all(b"y\n").unwrap();
        let out = child.wait_with_output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{text}");
        assert!(
            text.contains(&bare) && text.contains("recorded in") && text.contains("forgot"),
            "{text}"
        );
        assert_eq!(commit(&copy, "ok4.txt").code(), Some(0));
    }
}

/// S35 (item 47, X5): a URL whose authority ends at `?` or `#` names the
/// host before it: `https://evil.invalid?@gitlab.com/...` is a request to
/// `evil.invalid` for curl and git. A real `url.<x>.insteadOf` turns the
/// trusted origin URL into such a URL; trust reads the URL git uses
/// (after the rewrite), never parses `gitlab.com` out of it, and so
/// refuses the commit as a redirected trusted remote.
#[test]
fn s35_a_query_or_fragment_before_the_at_never_trusts_the_host_after_it() {
    let lab = Lab::new(BAD_FILE_POLICY);
    lab.sb().host_config(
        "[scope]\nremotes = [\"*gitlab.com:victorkwak/*\", \"*gitlab.com/victorkwak/*\"]\n[verify]\nmin_free = \"1M\"\n",
    );
    for (configured, base, evil) in [
        (
            "https://gitlab.com/victorkwak/ws.git",
            "https://gitlab.com/",
            "https://evil.invalid?@gitlab.com/",
        ),
        (
            "https://gitlab.com/victorkwak/ws.git",
            "https://gitlab.com/",
            "https://evil.invalid#@gitlab.com/",
        ),
        (
            "git@gitlab.com:victorkwak/ws.git",
            "git@gitlab.com:",
            "evil.invalid?@gitlab.com:",
        ),
    ] {
        lab.plain(&["remote", "set-url", "origin", configured]);
        let key = format!("url.{evil}.insteadOf");
        lab.plain(&["config", &key, base]);
        let fetch = lab.plain(&["remote", "get-url", "--all", "origin"]);
        assert!(fetch.starts_with(evil), "{fetch}");
        lab.stage_bad_file(evil);
        let s = lab.refused("git commit -m bad");
        assert!(
            s.out().contains("DENIED pre-commit")
                && s.out().contains(&format!("git fetches it from {evil}")),
            "{evil}: {s:?}"
        );
        lab.plain(&["rm", "-q", "--cached", "bad"]);
        std::fs::remove_file(lab.repo.join("bad")).unwrap();
        lab.plain(&["config", "--unset", &key]);
    }
}

/// S45 (item 47, review note 4): git reads a leading `[` in the
/// authority as a bracketed host, so `ssh://[evil.invalid]x@gitlab.com/`
/// and the scp-like `[evil.invalid]x@gitlab.com:` connect to
/// `evil.invalid`. A real `url.<x>.insteadOf` turns the trusted origin
/// URL into such a URL (git's own reading is checked first); trust never
/// takes `gitlab.com` from it, so the commit is refused as a redirected
/// trusted remote.
#[test]
fn s45_a_bracket_in_the_userinfo_never_trusts_the_host_after_it() {
    let lab = Lab::new(BAD_FILE_POLICY);
    lab.sb().host_config(
        "[scope]\nremotes = [\"*gitlab.com:victorkwak/*\", \"*gitlab.com/victorkwak/*\"]\n[verify]\nmin_free = \"1M\"\n",
    );
    for (configured, base, evil) in [
        (
            "ssh://git@gitlab.com/victorkwak/ws.git",
            "ssh://git@gitlab.com/",
            "ssh://[evil.invalid]x@gitlab.com/",
        ),
        (
            "ssh://git@gitlab.com/victorkwak/ws.git",
            "ssh://git@gitlab.com/",
            "git+ssh://[evil.invalid]@gitlab.com/",
        ),
        (
            "git@gitlab.com:victorkwak/ws.git",
            "git@gitlab.com:",
            "[evil.invalid]x@gitlab.com:",
        ),
    ] {
        lab.plain(&["remote", "set-url", "origin", configured]);
        let key = format!("url.{evil}.insteadOf");
        lab.plain(&["config", &key, base]);
        let fetch = lab.plain(&["remote", "get-url", "--all", "origin"]);
        assert!(fetch.starts_with(evil), "{fetch}");
        let diag = lab.plain(&["fetch-pack", "--diag-url", fetch.trim()]);
        assert!(diag.contains("userandhost=evil.invalid\n"), "{diag}");
        lab.stage_bad_file(evil);
        let s = lab.refused("git commit -m bad");
        assert!(
            s.out().contains("DENIED pre-commit")
                && s.out().contains(&format!("git fetches it from {evil}")),
            "{evil}: {s:?}"
        );
        lab.plain(&["rm", "-q", "--cached", "bad"]);
        std::fs::remove_file(lab.repo.join("bad")).unwrap();
        lab.plain(&["config", "--unset", &key]);
    }
}

/// S46 (item 35, review note 12): cargo reads `$CARGO_HOME/config.toml`
/// (the job's is `<home>/.cargo`) and the job PATH starts with
/// `$CARGO_HOME/bin` and `~/.local/bin`, so a session that writes a
/// runner into that config, or a fake cargo into those dirs, would make
/// the next gated commit run every test binary through `true`. The guard
/// asks a person before a Bash or Write call writes there. A host config
/// written anyway (interpreter code the guard does not read) fails every
/// job until the host config approves its exact content
/// (`[job.host_tool_configs]`, which the guard also asks for).
#[test]
fn s46_a_host_tool_config_the_session_writes_never_passes() {
    let lab = Lab::new(RUST_POLICY);
    let home = lab.sb().home.clone();
    let mut not_asked = Vec::new();
    for c in [
        "printf '[target.x86_64-unknown-linux-gnu]\\nrunner = \"true\"\\n' >> ~/.cargo/config.toml",
        "printf '[build]\\n' > $HOME/.cargo/config",
        "cp /bin/true ~/.cargo/bin/cargo",
        "install -m 755 /bin/true ~/.cargo/bin/cargo-nextest",
        "ln -sf /bin/true ~/.local/bin/cargo",
        "cd ~/.local/bin && ln -sf /bin/true uv",
        "mv /tmp/x ~/.bun/bin/bun",
        "echo 'max_width = 1' | tee ~/.rustfmt.toml",
        "sed -i s/a/b/ ~/.config/rustfmt/rustfmt.toml",
        "cp -r /tmp/evil/. ~/.local",
        "chmod +x ~/.local/bin/x",
        "cp /tmp/x ~/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/rustc",
        "cp /tmp/x ~/.cargo/registry/src/index/serde-1.0.0/src/lib.rs",
    ] {
        if !matches!(lab.guard(c), Guarded::Asked(_)) {
            not_asked.push(c);
        }
    }
    assert!(not_asked.is_empty(), "not asked: {not_asked:?}");
    for c in [
        "rm -rf ~/.cargo/registry/cache",
        "cat ~/.cargo/config.toml",
        "ls ~/.local/bin > /tmp/list",
    ] {
        assert!(matches!(lab.guard(c), Guarded::Allowed(_)), "{c}");
    }
    for f in [".cargo/config.toml", ".local/bin/cargo", ".rustfmt.toml"] {
        let write = serde_json::json!({
            "tool_name": "Write",
            "cwd": lab.repo,
            "tool_input": {"file_path": home.join(f), "content": "x"},
        });
        assert!(matches!(lab.guard_json(&write), Guarded::Asked(_)), "{f}");
    }

    let config = home.join(".cargo/config.toml");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(&config, "[target.'cfg(all())']\nrunner = \"true\"\n").unwrap();
    lab.stage_failing_test();
    let s = lab.refused("git commit -m x");
    assert!(
        s.out().contains("DENIED pre-commit")
            && s.out().contains(".cargo/config.toml")
            && s.out().contains("not approved"),
        "{s:?}"
    );
    lab.assert_no_bad_pass_of(None);

    // A reviewed config that the host config approves passes; the
    // failing test still fails under it.
    let benign = "[net]\nretry = 3\n";
    std::fs::write(&config, benign).unwrap();
    lab.sb().host_config(&format!(
        "[scope]\ntrusted_paths = [\"{}\"]\n[verify]\nmin_free = \"1M\"\n[job.host_tool_configs]\n\"~/.cargo/config.toml\" = \"{}\"\n",
        lab.bare.display(),
        blake3::hash(benign.as_bytes()).to_hex()
    ));
    let s = lab.refused("git commit -m y");
    assert!(
        s.out().contains("DENIED pre-commit") && s.out().contains("FAIL b b tests::fails"),
        "{s:?}"
    );
    write_b(&lab.repo, 2);
    lab.plain(&["add", "crates/b/src/lib.rs"]);
    lab.stage_code_change("approved");
    let s = lab.session("git commit -q -m z");
    assert_eq!(s.code(), Some(0), "{s:?}");
}

/// S36 (item 12): the guard checks the command as it came and Bash runs
/// the whole of it, so the rewrite never drops client text. A client
/// `export TOLLGATE_INLINE_CAP=...; ` prefix whose value is a quote that
/// hides a second command used to be cut at its first `; ` after the
/// check, which turned the hidden text into a command. Input that
/// already starts with the guard's prefix is denied; any other command
/// gets the prefix in front of its exact text.
#[test]
fn s36_the_inline_cap_rewrite_never_drops_checked_text() {
    let lab = Lab::new(BAD_FILE_POLICY);
    lab.stage_bad_file("1");
    let state = lab.sb().state();
    let bad = lab.not_denied(&[
        "export TOLLGATE_INLINE_CAP=\"; git commit -n -m x; #\"; git commit -m y".to_owned(),
        format!(
            "export TOLLGATE_INLINE_CAP=\"; rm -rf {}; #\"; git commit -m y",
            state.display()
        ),
        "export TOLLGATE_INLINE_CAP=540; git commit -m y".to_owned(),
        "  export TOLLGATE_INLINE_CAP=1; git push".to_owned(),
    ]);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    assert!(state.is_dir(), "the state dir is gone");
    for cmd in [
        "git commit -m \"a; b\"",
        "cd . && git commit -m 'x; #' # \"; git commit -n",
    ] {
        let Guarded::Allowed(c) = lab.guard(cmd) else {
            panic!("{cmd}: not allowed");
        };
        assert_eq!(c, format!("export TOLLGATE_INLINE_CAP=540; {cmd}"));
    }
}

// ---- The closed grammar of the guard (G1-G8), S21-S29 -------------------

/// `cmds` as owned strings.
fn owned(cmds: &[&str]) -> Vec<String> {
    cmds.iter().map(|c| (*c).to_owned()).collect()
}

/// S21 (G1, item 40): a command name bash builds at run time (a variable,
/// a substitution, ANSI-C quoting, a glob, brace expansion) is denied in
/// every simple command, so no spelling of git escapes the rules.
#[test]
fn s21_command_names_bash_builds_at_run_time_are_denied() {
    let lab = Lab::new(BAD_FILE_POLICY);
    lab.stage_bad_file("1");
    let bad = lab.not_denied(&owned(&[
        "G=git; $G commit -n -m x",
        "x=gi; ${x}t commit -n -m x",
        "G=git; \"$G\" commit -n -m x",
        "$(command -v git) commit -n -m x",
        "`command -v git` commit --no-verify -m x",
        "$'\\x67it' commit -n -m x",
        "/usr/bin/g?t commit -n -m x",
        "{git,} commit -n -m x",
        "echo $(G=git; $G commit -n -m x)",
    ]));
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// S22 (G2a, item 40): xargs, find -exec and parallel take arguments from
/// elsewhere, so they may not run a gated git command, tollgate, a shell
/// or an interpreter; their safe uses still run.
#[test]
fn s22_xargs_find_and_parallel_cannot_run_gated_git() {
    let lab = Lab::new(BAD_FILE_POLICY);
    lab.stage_bad_file("1");
    let bad = lab.not_denied(&owned(&[
        "echo commit | xargs git",
        "printf -- '-n\\n-m\\nx\\n' | xargs git commit",
        "echo x | xargs git commit -n -m",
        "echo x | xargs env git commit -n -m",
        "echo x | xargs -I{} sh -c 'git commit -n -m {}'",
        "find . -maxdepth 0 -exec git commit -n -m x \\;",
        "find . -maxdepth 0 -exec bash -c 'git commit -n -m x' \\;",
        "parallel git commit -n -m ::: x",
    ]));
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    std::fs::write(lab.repo.join("extra.txt"), "1\n").unwrap();
    let s = lab.session("printf 'extra.txt\\n' | xargs git add");
    assert_eq!(s.code(), Some(0), "{s:?}");
}

/// S23 (G2b, item 20): launchers that leave the session's environment or
/// machine may not run git, tollgate, a shell or an interpreter; other
/// launches stay allowed.
#[test]
fn s23_launchers_cannot_run_git_tollgate_or_a_shell() {
    let lab = Lab::new(BAD_FILE_POLICY);
    lab.stage_bad_file("1");
    let bad = lab.not_denied(&owned(&[
        "sudo git commit -n -m x",
        "su -c 'git commit -n -m x' nobody",
        "script -qc 'git commit -n -m x' /dev/null",
        "setpriv git commit -n -m x",
        "systemd-run --user --pipe git commit -n -m x",
        "ssh localhost 'git commit -n -m x'",
        "docker exec c git commit -m x",
        "tmux send-keys -t s 'git commit -n -m x' Enter",
        "env -i PATH=/usr/bin git commit -m x",
        "exec -c git commit -m x",
        "script -q /dev/null",
        "at now <<< 'git commit -n -m x'",
    ]));
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    for cmd in [
        "ssh prodhost 'journalctl -u app --since \"1 hour ago\"'",
        "docker exec pg psql -U postgres -c 'select 1'",
        "docker ps",
    ] {
        assert!(matches!(lab.guard(cmd), Guarded::Allowed(_)), "{cmd}");
    }
}

/// S24 (G3): code in arguments (`sh -c`, `eval`) and script files are
/// checked as if typed; code the guard cannot read (a variable, a process
/// substitution, a script written in the same call, one nested in a
/// script) is denied. A clean script runs, and the hook gates its commit.
#[test]
fn s24_code_in_arguments_and_script_files_is_checked() {
    let lab = Lab::new(BAD_FILE_POLICY);
    lab.stage_bad_file("1");
    let root = lab.root();
    write_exe(
        &root.join("bad.sh"),
        "#!/bin/sh\ngit commit --no-verify -m bad\n",
    );
    write_exe(
        &root.join("ok.sh"),
        "#!/bin/sh\ngit commit -m from-script\n",
    );
    write_exe(
        &root.join("nested.sh"),
        &format!("#!/bin/sh\nsh {}\n", root.join("ok.sh").display()),
    );
    let bad_sh = root.join("bad.sh").display().to_string();
    let bad = lab.not_denied(&[
        "bash -c 'git commit -n -m x'".to_owned(),
        "sh -c 'cd . && git commit --no-verify -m x'".to_owned(),
        "eval 'git commit -n -m x'".to_owned(),
        "C='git commit -n -m x'; eval \"$C\"".to_owned(),
        "bash -c \"$(printf 'git commit -n -m x')\"".to_owned(),
        "bash <(printf 'git commit -n -m x')".to_owned(),
        "source <(printf 'git commit -n -m x')".to_owned(),
        format!("bash {bad_sh}"),
        bad_sh.clone(),
        format!("source {bad_sh}"),
        format!("sh {}", root.join("nested.sh").display()),
        "printf 'git commit -n -m x\\n' > w.sh && sh w.sh".to_owned(),
        "trap 'git commit -n -m x' EXIT".to_owned(),
    ]);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    let s = lab.refused(&format!("sh {}", root.join("ok.sh").display()));
    assert!(s.out().contains("DENIED pre-commit"), "{s:?}");
}

/// S25 (G3, item 31): a program on stdin: a literal heredoc or
/// here-string to a shell is parsed and checked; a pipe or file into a
/// shell is denied; interpreter code with a process call is denied, other
/// interpreter code runs.
#[test]
fn s25_programs_on_stdin_and_interpreter_code_are_checked() {
    let lab = Lab::new(BAD_FILE_POLICY);
    lab.stage_bad_file("1");
    std::fs::write(lab.root().join("cmds.sh"), "git commit -m x\n").unwrap();
    let cmds_sh = lab.root().join("cmds.sh").display().to_string();
    let bad = lab.not_denied(&[
        "sh <<'EOF'\ngit commit -n -m x\nEOF".to_owned(),
        "bash <<< 'git commit --no-verify -m x'".to_owned(),
        "bash <<EOF\ngit commit $(printf -- -n) -m x\nEOF".to_owned(),
        "echo 'git commit -m x' | bash".to_owned(),
        format!("bash < {cmds_sh}"),
        "python3 -c 'import subprocess; subprocess.run([\"git\",\"commit\",\"-n\",\"-m\",\"x\"])'"
            .to_owned(),
        "perl -e 'system(\"git commit -n -m x\")'".to_owned(),
        "python3 - <<'EOF'\nimport os\nos.system('git commit -n -m x')\nEOF".to_owned(),
        "awk 'BEGIN { system(\"git commit -n -m x\") }'".to_owned(),
        "git ls-files | python3".to_owned(),
    ]);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    let s = lab.refused("bash <<'EOF'\ngit commit -m heredoc\nEOF");
    assert!(s.out().contains("DENIED pre-commit"), "{s:?}");
    let s = lab.session("python3 -c 'import json; print(json.dumps({\"ok\": 1}))'");
    assert_eq!(s.code(), Some(0), "{s:?}");
}

/// S26 (G4, items 13b and 42): gated git commands use the closed shape.
/// Variables, `-c` keys and global options outside the lists, a word bash
/// builds at run time, an unknown cwd and code-running options are
/// denied; a message that names --no-verify is not a flag, so that commit
/// reaches the hook, which gates it.
#[test]
fn s26_gated_git_uses_the_closed_shape() {
    let lab = Lab::new(BAD_FILE_POLICY);
    lab.stage_bad_file("1");
    let bad = lab.not_denied(&owned(&[
        "PATH=/tmp:$PATH git commit -m x",
        "LD_PRELOAD= git commit -m x",
        "GIT_TRACE=1 git commit -m x",
        "git --git-dir=.git commit -m x",
        "git --work-tree=. commit -m x",
        "git -c user.signingkey=x commit -m x",
        "git -c core.hooksPath=/dev/null commit -m x",
        "git -C \"$PWD\" commit -m x",
        "cd \"$X\" && git commit -m x",
        "cd -- \"$X\" && git commit -m x",
        "git commit -m x -- *",
        "git commit -m x $(printf -- --no-verify)",
        "git commit --no-ve -m x",
        "git commit -m x --no-verify=",
        "git push --receive-pack=/tmp/x origin main",
        "GIT_EDITOR='git commit -n -m y' git commit --amend",
        "git ci -m x",
    ]));
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    for cmd in [
        "git commit -m \"docs: mention --no-verify in README\"",
        "git commit -m 'Fix env' -m 'Names GIT_CONFIG_COUNT and core.hooksPath'",
        "git commit -m \"$(cat <<'EOF'\nSubject --no-verify\n\nCo-Authored-By: Name <noreply@example.com>\nEOF\n)\"",
        "GIT_AUTHOR_NAME=x LC_ALL=C git -c user.email=y commit -m x",
    ] {
        let s = lab.refused(cmd);
        assert!(s.out().contains("DENIED pre-commit"), "{cmd}: {s:?}");
    }
}

/// S27 (G5, G6, item 12, X2): sensitive variables are denied in every
/// write position (each form below would change the injection or the
/// transport for the git that follows), and a client inline-cap prefix
/// hides nothing after it.
#[test]
fn s27_variable_writes_and_the_inline_cap() {
    let lab = Lab::new(BAD_FILE_POLICY);
    lab.stage_bad_file("1");
    let bad = lab.not_denied(&owned(&[
        "TOLLGATE_INLINE_CAP=1 git commit --no-verify -m x; ls",
        "export TOLLGATE_INLINE_CAP=540; git commit --no-verify -m x; ls",
        "export TOLLGATE_INLINE_CAP=1; git commit -m x",
        "printf -v GIT_CONFIG_COUNT 0; git commit -m x",
        "read GIT_CONFIG_COUNT <<< 0; git commit -m x",
        "mapfile -t GIT_CONFIG_COUNT <<< 0; git commit -m x",
        "declare -n r=GIT_CONFIG_COUNT; r=0; git commit -m x",
        "for GIT_CONFIG_COUNT in 0; do git commit -m x; done",
        "(( GIT_CONFIG_COUNT = 0 )); git commit -m x",
        ": ${GIT_CONFIG_KEY_0:=x}; git commit -m x",
        "export -n GIT_CONFIG_COUNT; git commit -m x",
        "export HOME=/tmp; git commit -m x",
        "printf -v GIT_SSH_COMMAND /tmp/f; git push origin main",
    ]));
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    // The guard's own prefix goes in front of the command as it was.
    let Guarded::Allowed(c) = lab.guard("TOLLGATE_INLINE_CAP=1 git commit -m x; ls") else {
        panic!("a lower client cap in front of git is allowed (G6)");
    };
    assert_eq!(
        c,
        "export TOLLGATE_INLINE_CAP=540; TOLLGATE_INLINE_CAP=1 git commit -m x; ls"
    );
}

/// S28 (G7, items 2 and 22, review R4): remote identity changes ask; ref
/// writes into refs/remotes/* and moves of main deny in every form, through
/// git and through files.
#[test]
fn s28_remote_identity_and_ref_writes() {
    let lab = Lab::new(BAD_FILE_POLICY);
    let fake = lab.root().join("fake.git");
    for cmd in [
        format!("git remote set-url origin {}", fake.display()),
        format!("git remote add evil {}", fake.display()),
        format!("git config remote.origin.url {}", fake.display()),
        "git config --remove-section remote.origin".to_owned(),
        "git remote rename origin old".to_owned(),
    ] {
        assert!(matches!(lab.guard(&cmd), Guarded::Asked(_)), "{cmd}");
    }
    lab.plain(&["checkout", "-q", "-b", "feat"]);
    lab.stage_code_change("feat");
    lab.plain(&["commit", "-q", "--no-verify", "-m", "feat"]);
    let bad = lab.not_denied(&owned(&[
        "git update-ref refs/remotes/origin/main feat",
        "git update-ref --stdin <<'EOF'\nupdate refs/remotes/origin/main feat\nEOF",
        "printf 'update refs/heads/main feat\\n' | git update-ref --stdin",
        "git fetch . feat:refs/remotes/origin/main",
        "git update-ref refs/heads/main feat",
        "git branch -f main feat",
        "git branch -C feat main",
        "git push . feat:main",
        "git fetch . feat:main",
        "git checkout -B main feat",
        // Item 22, secreview note 5: groups, glued names, abbreviations.
        "git switch -fC main feat",
        "git checkout -qB main feat",
        "git checkout -fBmain feat",
        "git worktree add -fB main ../wt feat",
        "git switch --force-c main feat",
        "git branch --forc main feat",
        "git branch -f --sor refname main feat",
        "B=-Bmain; git checkout \"$B\" feat",
        "git rev-parse feat > .git/refs/heads/main",
        "git rev-parse feat | tee .git/refs/remotes/origin/main",
        "cp .git/refs/heads/feat .git/refs/heads/main",
        "printf '[remote \"origin\"]\\n\\turl = /tmp/x\\n' >> .git/config",
    ]));
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    // Item 22, secreview note 7: the local repo in every spelling git
    // reads as it, destinations in every spelling git expands, and pushes
    // whose refspecs come from config.
    let repo = lab.repo.display().to_string();
    lab.plain(&["remote", "add", "self", &repo]);
    lab.plain(&["branch", "-q", "--set-upstream-to=main"]);
    let mut spellings: Vec<String> = [
        "git push ./ feat:main",
        "git push .git feat:main",
        "git push {r} feat:main",
        "git push {r}/crates/.. feat:main",
        "git push file://{r} feat:main",
        "git push self feat:main",
        "git push . feat:heads/main",
        "git push . feat:origin/main",
        "git push . feat:remotes/origin/main",
        "git push --recurse-submodules no . feat:main",
        "git config push.default upstream && git push",
        "git push --repo=. --force",
        "git fetch .git feat:main",
        "git fetch self feat:main",
        "git fetch . feat:heads/main",
        "git fetch . feat:remotes/origin/main",
        "git fetch --refm=refs/heads/feat:refs/heads/main . feat",
        "git pull . feat:main",
        "cd crates && git push . feat:main",
    ]
    .iter()
    .map(|s| s.replace("{r}", &repo))
    .collect();
    spellings.push(format!(
        "ln -s {repo} {0}/l && git push {0}/l feat:main",
        lab.root().display()
    ));
    let bad = lab.not_denied(&spellings);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    let write = serde_json::json!({
        "tool_name": "Write",
        "cwd": lab.repo,
        "tool_input": {"file_path": lab.repo.join(".git/refs/heads/main"), "content": "x"},
    });
    assert!(matches!(lab.guard_json(&write), Guarded::Denied(_)));
    let s = lab.session("git branch -f other feat");
    assert_eq!(s.code(), Some(0), "{s:?}");
}

/// S29 (G8, item 15): cwd tracking follows cd, pushd and popd; after a
/// change the guard cannot follow, relative writes deny; symlinks into
/// tollgate's dirs do not hide them.
#[test]
fn s29_cwd_tracking_protects_tollgate_dirs() {
    let lab = Lab::new(BAD_FILE_POLICY);
    let state = lab.sb().state();
    let sentinel = state.join("results/00/sentinel.json");
    std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
    std::fs::write(&sentinel, "{}").unwrap();
    let s = state.display().to_string();
    let parent = state.parent().unwrap().display().to_string();
    let link = lab.root().join("lnk");
    std::os::unix::fs::symlink(&state, &link).unwrap();
    for cmd in [
        format!("cd {s} && rm -rf results"),
        format!("cd -- {s} && rm -rf results"),
        format!("pushd {s} && rm -rf results"),
        format!("cd {s}; cd /tmp; cd - && rm -rf results"),
        format!("D={s}; cd \"$(echo $D)\" && rm -rf results"),
        format!("cd {parent}/x/.. && rm -rf tollgate/results"),
        format!("rm -rf {}/results", link.display()),
        format!("cd {} && rm -f results/00/sentinel.json", link.display()),
        format!("ln -sfn {s} here && rm -rf here/results"),
        "cd \"$X\" && rm -rf results".to_owned(),
    ] {
        let r = lab.refused(&cmd);
        assert!(r.denied(), "{cmd}: {r:?}");
        assert!(sentinel.exists(), "{cmd}: the sentinel is gone");
    }
    let s2 = lab.session(&format!("cd {s} && ls results"));
    assert_eq!(s2.code(), Some(0), "{s2:?}");
}

/// S37 (G1, G3): `break`, `continue` and a `return` from a sourced file
/// skip the rest of a loop body or file, so the values at the jump reach
/// the code after it. The walk follows those jumps: a name set to git
/// just before one stays unknown after the loop. A program written earlier
/// in the call runs only when a literal heredoc wrote it whole, once, with
/// the real `cat`, and its text passes the same checks as inline code.
#[test]
fn s37_jumps_and_programs_written_in_the_call_are_followed() {
    let lab = Lab::new(BAD_FILE_POLICY);
    lab.stage_bad_file("1");
    let root = lab.root();
    std::fs::write(root.join("ret.sh"), "G=git\n[ -d / ] && return\nG=echo\n").unwrap();
    let ret = root.join("ret.sh").display().to_string();
    let py = root.join("w.py").display().to_string();
    let bad = lab.not_denied(&[
        "G=echo; for i in 1 2; do G=git; [ -d / ] && continue; G=echo; done; $G commit -n -m x"
            .to_owned(),
        "G=echo; for i in 1 2; do G=git; [ -d / ] && break; G=echo; done; $G commit -n -m x"
            .to_owned(),
        "G=echo; while :; do G=git; [ -d / ] && break; G=echo; break; done; $G commit -n -m x"
            .to_owned(),
        "G=echo; until false; do G=git; break; G=echo; done; $G commit -n -m x".to_owned(),
        "G=echo; for a in 1; do for b in 1; do G=git; break 2; done; G=echo; done; $G commit -n -m x"
            .to_owned(),
        "G=echo; for a in 1; do for b in 1; do G=git; continue 2; done; G=echo; done; $G commit -n -m x"
            .to_owned(),
        format!("G=echo; . {ret}; $G commit -n -m x"),
        format!("G=echo; source {ret}; $G commit -n -m x"),
        format!(
            "printf 'import subprocess\\nsubprocess.run([\"git\",\"commit\",\"-n\",\"-m\",\"x\"])\\n' > {py}; python3 {py}"
        ),
        format!(
            "cat > {py} <<'EOF'\nimport os\nos.system('git commit -n -m x')\nEOF\npython3 -I {py}"
        ),
        // Two writes: the guard cannot tell which text runs.
        format!(
            "if [ -d / ]; then cat > {py} <<'A'\nimport os\nos.system('git commit -n -m x')\nA\nelse cat > {py} <<'B'\nprint(1)\nB\nfi; python3 {py}"
        ),
        format!(
            "cat > {py} <<'EOF'\nprint(1)\nEOF\nprintf 'import os\\nos.system(\"git commit -n -m x\")\\n' >> {py}; python3 {py}"
        ),
        "cat > w.sh <<'EOF'\ngit commit -n -m x\nEOF\nbash w.sh".to_owned(),
        "cat > w.sh <<'EOF'\ngit commit -n -m x\nEOF\nchmod +x w.sh && ./w.sh".to_owned(),
        // A dir written first: what is in it is unknown.
        "mkdir -p d && printf 'import os\\nos.system(\"git commit -n -m x\")\\n' > d/w.py; cp -r d e && python3 e/w.py"
            .to_owned(),
        // A `cat` other than the real one.
        format!(
            "mkdir -p b && cat > b/cat <<'EOF'\n#!/bin/sh\necho 'import os; os.system(\"git commit -n -m x\")'\nEOF\nchmod +x b/cat && export PATH=$PWD/b:$PATH; cat > {py} <<'EOF'\nprint(1)\nEOF\npython3 {py}"
        ),
        format!(
            "cat() {{ printf 'import os\\nos.system(\"git commit -n -m x\")\\n'; }}; cat > {py} <<'EOF'\nprint(1)\nEOF\npython3 {py}"
        ),
    ]);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    // A loop without jumps keeps what it knows.
    let s = lab.session("G=echo; for i in 1 2; do G=echo; done; $G ok");
    assert_eq!(s.code(), Some(0), "{s:?}");
    // A program a literal heredoc wrote runs, checked as that text.
    for cmd in [
        format!("cat > {py} <<'EOF'\nprint('ok')\nEOF\npython3 {py}"),
        "cat > ok.sh <<'EOF'\necho ok\nEOF\nchmod +x ok.sh && ./ok.sh && bash ok.sh".to_owned(),
    ] {
        let s = lab.session(&cmd);
        assert_eq!(s.code(), Some(0), "{cmd}: {s:?}");
    }
}

/// S38 (G3, G7): programs whose own arguments run commands or write files:
/// sed's `e` command and `e` flag, sed `w` into git's refs, tar's
/// program options, `rg --pre`, `less +!`, an editor's command options.
/// Plain edits with sed still run.
#[test]
fn s38_program_arguments_that_run_commands_are_denied() {
    let lab = Lab::new(BAD_FILE_POLICY);
    lab.stage_bad_file("1");
    let f = lab.root().join("f.sh");
    write_exe(
        &f,
        "#!/bin/sh\ngit commit -n -m x >/dev/null 2>&1\ncat \"$1\"\n",
    );
    let f = f.display().to_string();
    let bad = lab.not_denied(&[
        "echo x | sed '1e git commit -n -m x'".to_owned(),
        "echo x | sed 's/x/git commit -n -m x/e'".to_owned(),
        "echo x | sed -n --e='1e git commit -n -m x' -e p".to_owned(),
        "echo x | sed -ne '1e git commit -n -m x'".to_owned(),
        "git rev-parse HEAD~0 | sed 'w .git/refs/heads/evil'".to_owned(),
        "tar -cf /dev/null --to-command='git commit -n -m x' .".to_owned(),
        "tar -cf /dev/null --checkpoint=1 --checkpoint-act=exec='git commit -n -m x' .".to_owned(),
        format!("rg --pre {f} x ."),
        "less +'!git commit -n -m x' bad".to_owned(),
        // Item 29: socat program addresses and Tcl (macOS ships tclsh
        // and expect).
        "socat - SYSTEM:'git commit -n -m x'".to_owned(),
        "socat -u /dev/null EXEC:'git commit -n -m x'".to_owned(),
        "echo 'exec git commit -n -m x' | tclsh".to_owned(),
        "expect -c 'spawn git commit -n -m x; expect eof'".to_owned(),
        "vim -es -c '!git commit -n -m x' -c q bad".to_owned(),
        "S='1e git commit -n -m x'; echo x | sed \"$S\"".to_owned(),
        "for s in p '1e git commit -n -m x'; do echo x | sed \"$s\"; done".to_owned(),
        "LESSOPEN='|git commit -n -m x >/dev/null; cat %s' less bad".to_owned(),
    ]);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    let s = lab.session("printf 'a\\n' > t.txt && sed -i 's/a/b/' t.txt && sed -n '1p' t.txt");
    assert_eq!(s.code(), Some(0), "{s:?}");
}

/// S39 (G3): bash evaluates a variable's value as an arithmetic
/// expression wherever its name is used in one (`$((x))`, `(( x ))`,
/// `[[ $x -eq 1 ]]`, `let`, `declare -i`, array subscripts, substring
/// offsets), and a value like `a[$(cmd)]` runs `cmd`. Arithmetic may read
/// only names whose value is a number (set by arithmetic, a literal, or a
/// command that prints only numbers) or the session's own. Prompt
/// expansion (`PS4` under `set -x`, `${x@P}`) runs substitutions as well.
#[test]
fn s39_arithmetic_never_runs_code_from_a_value() {
    let lab = Lab::new(BAD_FILE_POLICY);
    lab.stage_bad_file("1");
    let x = "x=$(printf 'a[$(git commit -n -m x >&2)]')";
    let bad = lab.not_denied(&[
        format!("{x}; echo $((x+1))"),
        format!("{x}; (( x )) || true"),
        format!("{x}; [[ $x -eq 1 ]] || true"),
        format!("{x}; declare -i y=x"),
        format!("{x}; echo ${{a[x]}}"),
        format!("{x}; s=abc; echo ${{s:x}}"),
        format!("{x}; let y=x"),
        format!("{x}; a[x]=1"),
        format!("{x}; y=x; echo $((y))"),
        format!("{x}; for ((i=x; i<1; i++)); do :; done"),
        "read x <<< 'a[$(git commit -n -m x >&2)]'; echo $((x))".to_owned(),
        "v=$(printf 'a[$(git commit -n -m x >&2)]'); let \"$v\"".to_owned(),
        "[[ 'a[$(git commit -n -m x >&2)]' -eq 1 ]] || true".to_owned(),
        "echo $(( $(printf 'a[$(git commit -n -m x >&2)]') ))".to_owned(),
        "f(){ echo $(( $1 + 1 )); }; f 'a[$(git commit -n -m x >&2)]'".to_owned(),
        // Prompt expansion runs command substitutions too.
        "PS4='$(git commit -n -m x >&2)'; set -x; true".to_owned(),
        "export PS4='$(git commit -n -m x >&2)'; bash -xc true".to_owned(),
        "x='$(git commit -n -m x >&2)'; echo ${x@P}".to_owned(),
    ]);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    for cmd in [
        "i=0; while [ $i -lt 3 ]; do i=$((i+1)); done; echo $i",
        "for ((i=0; i<3; i++)); do echo $((i*2)); done",
        "n=$(git rev-list --count HEAD); echo $((n+1))",
        "start=$(date +%s); echo $(( $(date +%s) - start ))",
        "for i in $(seq 1 3); do echo $((i*15)); done",
    ] {
        let s = lab.session(cmd);
        assert_eq!(s.code(), Some(0), "{cmd}: {s:?}");
    }
}

/// S40 (G3): interpreter code that reaches a process call without naming
/// one: Python's object graph (`__subclasses__`, `__globals__`), code
/// built from strings (`eval`, `Function`, a constructor), a module name
/// built at run time (`require(x)`), Ruby's `send`, PHP variable
/// functions, Perl symbolic calls, Lua `load`.
#[test]
fn s40_interpreter_code_cannot_reach_a_process_call_by_a_string() {
    let lab = Lab::new(BAD_FILE_POLICY);
    lab.stage_bad_file("1");
    let bad = lab.not_denied(&owned(&[
        "python3 - <<'EOF'\nfor c in ().__class__.__base__.__subclasses__():\n    if c.__name__ == '_wrap_close':\n        c.__init__.__globals__['sys' + 'tem']('git commit -n -m x')\nEOF",
        "python3 -c \"import sys; sys._getframe().f_globals['__builtins__']\"",
        "node -e \"require('child_' + 'process')['exec' + 'Sync']('git commit -n -m x')\"",
        "node -e \"eval('require(\\\"child_\\\" + \\\"process\\\")')\"",
        "node -e \"''.constructor.constructor('return process')().mainModule\"",
        "node -e \"const m = 'child_' + 'process'; import(m)\"",
        "ruby -e \"Kernel.send(('sys' + 'tem').to_sym, 'git commit -n -m x')\"",
        "perl -e '&{\"CORE::sys\" . \"tem\"}(\"git commit -n -m x\")'",
        "perl -e 'eval \"sys\" . \"tem q(git commit -n -m x)\"'",
        "lua -e \"load('os.exe' .. 'cute(\\\"git commit -n -m x\\\")')()\"",
        "php -r '$f = \"sys\" . \"tem\"; $f(\"git commit -n -m x\");'",
    ]));
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    let s = lab.session("python3 -c 'import json; print(json.dumps([1]))' && node -e 'console.log(require(\"path\").join(\"a\", \"b\"))'");
    assert_eq!(s.code(), Some(0), "{s:?}");
}

/// S41 (item 29): the settings file is resolved once. What install and
/// uninstall show and the person confirms is the file they write; when it
/// is swapped while the question waits (a symlink to another file, a file
/// renamed over it, an edit in place) nothing is written, and the file it
/// was swapped for is never written.
#[test]
fn s41_a_settings_file_swapped_before_the_answer_is_never_written() {
    let original = "{\n  \"env\": {\n    \"KEEP\": \"1\"\n  }\n}\n";
    type Swap = fn(&Path, &Path) -> String;
    // Each swap gets the settings file and a victim; it returns the text
    // the settings path must still read after the refused write.
    let swaps: [(&str, Swap); 3] = [
        ("symlink", |settings, victim| {
            std::fs::remove_file(settings).unwrap();
            std::os::unix::fs::symlink(victim, settings).unwrap();
            std::fs::read_to_string(victim).unwrap()
        }),
        ("rename", |settings, _| {
            let other = settings.with_file_name("other.json");
            std::fs::write(&other, "{\"other\": 1}\n").unwrap();
            std::fs::rename(&other, settings).unwrap();
            "{\"other\": 1}\n".to_owned()
        }),
        ("in place", |settings, _| {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(settings)
                .unwrap();
            f.write_all(b"{\"edited\": 1}\n").unwrap();
            "{\"edited\": 1}\n".to_owned()
        }),
    ];
    let victim_text = "{\"victim\": true}\n";
    for (name, swap) in swaps {
        // Install.
        let lab = InstallLab::new(original);
        let victim = lab.sb.root().join("victim.json");
        std::fs::write(&victim, victim_text).unwrap();
        let mut s = pty::Session::spawn(
            lab.cmd(Path::new(support::BIN), &["install"], &[]),
            pty::Streams::All,
        );
        assert!(s.wait_for(pty::PROMPT, 1), "{name}: {}", s.output());
        let want = swap(&lab.settings(), &victim);
        s.send("y\n");
        let r = s.finish();
        assert_ne!(r.code, Some(0), "install, {name}: {}", r.out);
        assert!(r.out.contains("changed"), "install, {name}: {}", r.out);
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            victim_text,
            "install, {name}"
        );
        assert_eq!(
            std::fs::read_to_string(lab.settings()).unwrap(),
            want,
            "install, {name}"
        );

        // Uninstall, after an install that went through.
        let lab = InstallLab::new(original);
        let victim = lab.sb.root().join("victim.json");
        std::fs::write(&victim, victim_text).unwrap();
        let r = pty::run(
            lab.cmd(Path::new(support::BIN), &["install"], &[]),
            pty::Streams::All,
            &["y"],
        );
        assert_eq!(r.code, Some(0), "{}", r.out);
        let bin = lab.data().join("bin/tollgate");
        let mut s = pty::Session::spawn(lab.cmd(&bin, &["uninstall"], &[]), pty::Streams::All);
        assert!(s.wait_for(pty::PROMPT, 1), "{name}: {}", s.output());
        let want = swap(&lab.settings(), &victim);
        s.send("y\n");
        let r = s.finish();
        assert_ne!(r.code, Some(0), "uninstall, {name}: {}", r.out);
        assert!(r.out.contains("changed"), "uninstall, {name}: {}", r.out);
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            victim_text,
            "uninstall, {name}"
        );
        assert_eq!(
            std::fs::read_to_string(lab.settings()).unwrap(),
            want,
            "uninstall, {name}"
        );
        assert!(bin.exists(), "uninstall, {name}: the data dir stays");
    }
}

/// S42 (items 24-27, 35): a branch's build script writes cargo config
/// above the verify checkout (`<tier dir>/.cargo/config.toml`, which cargo
/// reads from every checkout below it) with a target runner that runs no
/// test. The job that wrote it is an error; the next job, on another
/// tree, refuses the leftover before its first step instead of running
/// the tests through it.
#[test]
fn s42_cargo_config_written_above_the_checkout_does_not_pass() {
    let lab = Lab::new(RUST_POLICY);
    std::fs::write(
        lab.repo.join("crates/b/build.rs"),
        r#"fn main() {
    let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let above = manifest.ancestors().nth(3).unwrap().join(".cargo");
    std::fs::create_dir_all(&above).unwrap();
    std::fs::write(
        above.join("config.toml"),
        format!("[target.{}]\nrunner = \"true\"\n", std::env::var("TARGET").unwrap()),
    )
    .unwrap();
}
"#,
    )
    .unwrap();
    lab.plain(&["add", "crates/b/build.rs"]);
    lab.stage_failing_test();
    let s = lab.refused("git commit -m x");
    assert!(s.out().contains("DENIED pre-commit"), "{s:?}");
    lab.stage_code_change("again");
    let s = lab.refused("git commit -m y");
    assert!(
        s.out().contains("DENIED pre-commit") && s.out().contains(".cargo/config.toml"),
        "{s:?}"
    );
    lab.assert_no_bad_pass_of(None);
}

/// Puts back every ref in `before` (a [`Lab::refs`] listing).
fn put_back(lab: &Lab, before: &str) {
    for line in before.lines() {
        let (r, v) = line.split_once(' ').unwrap();
        lab.plain(&["update-ref", r, v]);
    }
}

/// S43 (item 21, review note 8): git runs the value of many config keys,
/// variables and options as a program or as shell code, on commands that
/// move no ref themselves: `diff.external`, textconv and filter drivers,
/// credential helpers, askpass, `gpg.program`, `gpg.ssh.defaultKeyCommand`,
/// config hooks (`hook.*`), the `ext::` transport, `difftool -x`,
/// `grep -O`, `clone -u`, `archive --exec`, `for-each-repo`. Each is
/// read as code or denied on every git command, so none of them runs
/// `git commit -n`. Pagers run only on a terminal, so those are run on a
/// pty here as well, to show what the guard stops.
#[test]
fn s43_values_git_runs_are_read_as_code_on_every_git_command() {
    let lab = Lab::new(BAD_FILE_POLICY);
    lab.stage_bad_file("1");
    std::fs::write(
        lab.repo.join(".gitattributes"),
        "bad diff=x\nbad2 filter=y\n",
    )
    .unwrap();
    std::fs::write(lab.repo.join("bad2"), "2\n").unwrap();
    let repo = lab.repo.display().to_string();
    let bare = lab.bare.display().to_string();
    let root = lab.root().display().to_string();
    let p = format!("git -C {repo} commit -n -q -m x >/dev/null 2>&1");
    let f = lab.root().join("f.sh");
    write_exe(
        &f,
        &format!("#!/bin/sh\nunset GIT_INDEX_FILE GIT_DIR GIT_WORK_TREE\n{p}\n"),
    );
    let f = f.display().to_string();
    let ext = format!("git -C {repo} commit -n -q -m x").replace(' ', "% ");
    let fill = "credential fill <<'EOF'\nprotocol=https\nhost=x.invalid\n\nEOF";
    let bad = lab.not_denied(&[
        format!("git -c diff.external='{p}; true #' diff HEAD"),
        format!("GIT_EXTERNAL_DIFF='{p}; true #' git diff HEAD"),
        format!("export GIT_EXTERNAL_DIFF='{p}; true #'; git diff HEAD"),
        format!("env GIT_EXTERNAL_DIFF='{p}; true #' git diff HEAD"),
        format!("printf '#!/bin/sh\\n{p}\\n' > e.sh && chmod +x e.sh && GIT_EXTERNAL_DIFF=./e.sh git diff HEAD"),
        format!("git -c diff.x.textconv='{p}; cat #' diff HEAD"),
        format!("git -c filter.y.clean='{p}; cat #' hash-object bad2"),
        format!("git -c credential.helper='!{p}; true #' {fill}"),
        format!("git -c core.askpass={f} {fill}"),
        format!("GIT_ASKPASS={f} git {fill}"),
        format!("git -c gpg.program={f} -c user.signingkey=x commit-tree -S -m x HEAD:"),
        format!("git -c gpg.format=ssh -c gpg.ssh.defaultKeyCommand='git -C {repo} commit -n -q -m x' commit-tree -S -m x HEAD:"),
        format!("git -c hook.x.event=post-checkout -c hook.x.command={f} checkout -q HEAD"),
        format!("git -c protocol.ext.allow=always fetch 'ext::sh -c {ext}'"),
        format!("git -c protocol.allow=always ls-remote 'ext::sh -c {ext}'"),
        format!("git difftool -y -x '{p}; true #' HEAD"),
        format!("git -c diff.tool=t -c difftool.t.cmd='{p}' difftool -y HEAD"),
        format!("git grep -O'{p}; true #' -e scratch"),
        format!("git clone -q -u '{p}; false #' {bare} {root}/c-u"),
        format!("git ls-remote --upload-pack='{p}; false #' {bare}"),
        format!("git archive --remote={bare} --exec='{p}; false #' HEAD"),
        format!("git -c x.r={repo} for-each-repo --config=x.r commit -n -q -m x"),
        format!("printf '[diff]\\n\\texternal = \"{p}; true #\"\\n' >> ~/.gitconfig && git diff HEAD"),
    ]);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    for cmd in [
        format!("git -c pager.log='{p}; cat >/dev/null #' log -1"),
        format!("GIT_PAGER='{p}; cat >/dev/null #' git log -1"),
        format!("PAGER='{p}; cat >/dev/null #' git log -1"),
    ] {
        let s = lab.session(&cmd);
        assert!(s.denied(), "{cmd}: {s:?}");
        // What it does when it runs, on a terminal.
        let before = lab.refs();
        let mut c = lab.cmd("bash", &lab.repo);
        c.args(["-c", &cmd]);
        let r = pty::run(c, pty::Streams::All, &[]);
        let moved = lab.refs() != before;
        put_back(&lab, &before);
        assert!(moved, "{cmd} moved no ref on a terminal: {r:?}");
    }
    // less runs `+!cmd` from LESS, then waits for a key.
    let s = lab.session(&format!("GIT_PAGER=less LESS='+!{p}' git log -1"));
    assert!(s.denied(), "{s:?}");
    for cmd in [
        "git -c core.pager=cat log -1 --oneline".to_owned(),
        "GIT_PAGER=cat git log -1 --oneline".to_owned(),
        format!("git -c credential.helper= -c protocol.file.allow=always ls-remote {bare}"),
        "git -c diff.x.textconv=cat diff HEAD --stat".to_owned(),
        "git grep -n scratch".to_owned(),
    ] {
        let s = lab.session(&cmd);
        assert_eq!(s.code(), Some(0), "{cmd}: {s:?}");
    }
}

/// S44 (G2, G3, item 20, review note 9): a launcher that drops or
/// replaces the session environment (`env -i`, `env -`, `exec -c`) runs
/// git without the hook injection, so nothing of tollgate runs, not even
/// the post-commit unverified record. A script it runs is a shell or an
/// interpreter the guard does not read there, whether it is named by a
/// path, through a symlink, written earlier in the call, or found on a
/// `PATH` the command sets. The same holds for `exec -a` and the other
/// launchers. A binary still runs (the residual risk of 21d).
#[test]
fn s44_launchers_never_run_an_unread_script() {
    let lab = Lab::new(BAD_FILE_POLICY);
    lab.stage_bad_file("1");
    let root = lab.root();
    let body = "git -c user.name=a -c user.email=a@b.invalid commit -n -q -m x\n";
    write_exe(&lab.repo.join("e2.sh"), &format!("#!/bin/sh\n{body}"));
    write_exe(&lab.repo.join("e3"), body);
    write_exe(&root.join("bin/e4"), &format!("#!/bin/sh\n{body}"));
    write_exe(&lab.repo.join("sub/e5.sh"), &format!("#!/bin/sh\n{body}"));
    std::os::unix::fs::symlink("e2.sh", lab.repo.join("l")).unwrap();
    std::fs::copy("/usr/bin/true", lab.repo.join("t")).unwrap();
    // Text with no `#!` and no x bit: a chmod in the call makes it run.
    std::fs::write(lab.repo.join("e7"), body).unwrap();
    // Executable but unreadable: the guard cannot tell what it is.
    write_exe(&lab.repo.join("e8"), &format!("#!/bin/sh\n{body}"));
    let mode = std::os::unix::fs::PermissionsExt::from_mode(0o111);
    std::fs::set_permissions(lab.repo.join("e8"), mode).unwrap();
    std::fs::write(lab.repo.join("notes.txt"), "data\n").unwrap();
    let e2 = lab.repo.join("e2.sh").display().to_string();
    let bin = root.join("bin").display().to_string();
    let bad = lab.not_denied(&[
        "printf 'git commit -n -m x\\n' > e.sh && chmod +x e.sh && env -i ./e.sh".to_owned(),
        format!("printf '#!/bin/sh\\n{body}' > e.sh && chmod +x e.sh && env -i ./e.sh"),
        format!("printf '#!/bin/sh\\n{body}' > e.sh && chmod +x e.sh && exec -c ./e.sh"),
        "env -i ./e2.sh".to_owned(),
        "env -i ./e3".to_owned(),
        "env -i ./l".to_owned(),
        format!("env -i {e2}"),
        "env --ignore-environment ./e2.sh".to_owned(),
        "env --ignore-env ./e2.sh".to_owned(),
        "env - ./e2.sh".to_owned(),
        "env -i X=1 ./e2.sh".to_owned(),
        "env -iC . ./e2.sh".to_owned(),
        "env -S '-i ./e2.sh'".to_owned(),
        "env -i -S ./e2.sh".to_owned(),
        "exec -c ./e2.sh".to_owned(),
        "exec -c -- ./e2.sh".to_owned(),
        "exec -cl ./e2.sh".to_owned(),
        "exec -a x ./e2.sh".to_owned(),
        "command exec -c ./e2.sh".to_owned(),
        "nohup env -i ./e2.sh >/dev/null 2>&1".to_owned(),
        "env -u HOME ./e2.sh".to_owned(),
        // Found on a PATH the command sets.
        "env -i PATH=. e2.sh".to_owned(),
        "env -i PATH=.:/usr/bin e3".to_owned(),
        format!("env -i PATH={bin} e4"),
        format!("env -i PATH=/usr/bin:{bin} e4"),
        "env -i PATH=$PWD e2.sh".to_owned(),
        "env -S '-i PATH=. e2.sh'".to_owned(),
        format!("PATH={bin}:$PATH; exec -c e4"),
        format!("export PATH={bin}:$PATH; exec -c e4"),
        "PATH=. exec -c e2.sh".to_owned(),
        // Spellings, dirs, copies, links and modes.
        "env -i $'./e2.sh'".to_owned(),
        "env -i \"./e2\".sh".to_owned(),
        "env -i .//e2.sh".to_owned(),
        "env -iC sub ./e5.sh".to_owned(),
        "env -i --chdir=sub ./e5.sh".to_owned(),
        "env -S \"'P'ATH=. e2.sh\"".to_owned(),
        "env -S '-C sub ./e5.sh'".to_owned(),
        "cp e2.sh n && env -i ./n".to_owned(),
        "ln -s e2.sh m && env -i ./m".to_owned(),
        "chmod +x e7 && env -i ./e7".to_owned(),
        "chmod +x e7 && setpriv --nnp ./e7".to_owned(),
        "env -i ./e8".to_owned(),
        "xargs env -i ./e2.sh </dev/null".to_owned(),
        "env -i sudo -n ./e2.sh".to_owned(),
        // Another launcher.
        "setpriv --nnp ./e2.sh".to_owned(),
    ]);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    for cmd in [
        "env -i ./t",
        "env -i /usr/bin/true",
        "env -i true",
        "env -i PATH=/usr/bin:/bin true",
        "env -u FOO true",
        "exec -c ./t",
        "exec -a x true",
        "env -i",
        "setpriv --nnp cat ./notes.txt",
    ] {
        let s = lab.session(cmd);
        assert_eq!(s.code(), Some(0), "{cmd}: {s:?}");
    }
}

/// S47 (G2, item 40, review notes 11 and 1): programs that run the
/// command in their arguments are walked or held to the launcher rule,
/// whatever they are: pty runners (which also give a TTY-only command
/// the terminal it checks for), tracers, package runners, terminals,
/// supervisors and environment changers. A program the guard does not
/// know still may not take git with a gated subcommand, or tollgate with
/// a subcommand for a person only, as separate words. Only the guard
/// runs here: an allowed terminal would open a window.
#[test]
fn s47_programs_that_run_their_arguments_are_followed() {
    let lab = Lab::new(BAD_FILE_POLICY);
    let not_denied = |cmds: &[&str]| -> Vec<String> {
        cmds.iter()
            .filter_map(|c| match lab.guard(c) {
                Guarded::Denied(_) => None,
                g => Some(format!("{c}  => {g:?}")),
            })
            .collect()
    };
    let bad = not_denied(&[
        // pty runners; the second step types into the first.
        "dtach -n /tmp/s git commit -n -m x",
        "dtach -n /tmp/s tollgate remotes forget",
        "printf 'y\\n' | dtach -p /tmp/s",
        "dtach -p /tmp/s < answers.txt",
        "abduco -n s git commit -n -m x",
        "printf 'y\\n' | abduco -a s",
        "empty -f tollgate remotes forget",
        "empty -s -o in 'tollgate remotes forget'",
        "faketty tollgate install",
        "ttyd bash",
        // Tracers and debuggers.
        "strace -f git commit -n -m x",
        "strace -f -o /tmp/t -- git commit -n -m x",
        "ltrace git commit -n -m x",
        "valgrind --trace-children=yes git commit -n -m x",
        "perf stat -- git commit -n -m x",
        "perf record -o /tmp/p git commit -n -m x",
        "catchsegv git commit -n -m x",
        "gdb --args git commit -n -m x",
        // Package runners.
        "uv run -- git commit -n -m x",
        "uv run git commit -n -m x",
        "uv run --with rich env git commit -n -m x",
        "uv run bash -c 'echo hi'",
        "uv run python -c 'import subprocess; subprocess.run([\"ls\"])'",
        "uv run -m pip --version && uv run --env-file .env cargo build",
        "uvx git commit -n -m x",
        "bunx git commit -n -m x",
        "bun x git commit -n -m x",
        "npx git commit -n -m x",
        "npx -c 'git commit -n -m x'",
        "npm exec -- git commit -n -m x",
        "pnpm dlx tollgate remotes forget",
        "cargo run -- remotes forget",
        "cargo run -q --bin tollgate -- install",
        "cargo r -- uninstall",
        // Session and environment changers.
        "rlwrap git commit -n -m x",
        "chronic git commit -n -m x",
        "fakeroot git commit -n -m x",
        "printf 'git commit -n -m x\\n' | fakeroot",
        "printf 'git commit -n -m x\\n' | newgrp users",
        "ssh-agent git commit -n -m x",
        "dbus-run-session -- git commit -n -m x",
        "xvfb-run git commit -n -m x",
        "systemd-inhibit git commit -n -m x",
        "systemd-cat git commit -n -m x",
        "envdir ./e git commit -m x",
        "faketime yesterday git commit -m x",
        "run0 git commit -n -m x",
        // Terminals and what types into them.
        "konsole -e git commit -n -m x",
        "xterm -e git commit -n -m x",
        "alacritty -e git commit -n -m x",
        "zellij run -- git commit -n -m x",
        "zellij action write-chars 'tollgate remotes forget'",
        "wtype 'tollgate remotes forget'",
        "ydotool type 'git commit -n -m x'",
        "qdbus org.kde.konsole /Sessions/1 runCommand 'tollgate remotes forget'",
        // Supervisors and file watchers.
        "tini -- git commit -n -m x",
        "dumb-init git commit -n -m x",
        "daemonize /usr/bin/git commit -n -m x",
        "chpst git commit -n -m x",
        "start-stop-daemon --start --exec /usr/bin/git -- commit -n -m x",
        "watchexec -- git commit -n -m x",
        "echo a | entr git commit -n -m x",
        "hyperfine 'git commit -n -m x'",
        // Programs the guard does not know.
        "frobnicate git commit -n -m x",
        "frobnicate --opt git -C . commit -n -m x",
        "frobnicate /usr/bin/git push -f origin main",
        "frobnicate git-commit -n -m x",
        "frobnicate tollgate install",
        "frobnicate --x /usr/bin/tollgate remotes forget",
        "frobnicate TOLLGATE uninstall",
        "G=git; frobnicate $G commit -n -m x",
        // Spellings and nesting.
        "STRACE -f git commit -n -m x",
        "strace -f env git commit -n -m x",
        "nohup uv run git commit -n -m x",
        "timeout 9 dtach -n /tmp/s git commit -n -m x",
        "uv run -- sh -c 'echo hi'",
        "uv run python3 -c 'import os; os.system(\"ls\")'",
        "npx --registry=https://r.example git commit -n -m x",
        "strace -E GIT_CONFIG_COUNT=0 cargo build",
        "bunx --cwd /tmp ./x.sh",
        "cargo run --release -- REMOTES forget",
        "frobnicate --exec=git commit -n -m x",
        "frobnicate --exec=/usr/bin/tollgate install",
        // Words from elsewhere.
        "echo commit | xargs strace git",
        "echo commit | xargs frobnicate git",
        "echo install | xargs frobnicate tollgate",
        "find . -maxdepth 0 -exec uv run git commit -n -m x \\;",
        // Options before the run subcommand.
        "uv --env-file .env run cargo build",
        "npm --prefix /x exec -c 'git commit -n -m x'",
        "bun --env-file .env x git commit -n -m x",
        "uv --directory sub run ./x.sh",
    ]);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    // Everyday uses stay allowed.
    for cmd in [
        "uv run pytest -q",
        "uv run python -c 'print(1)'",
        "uv run -- python -m pytest -q",
        "uv run --with requests python -c 'print(2)'",
        "uv run -m pytest -q",
        "uv run python -c 'print(\"git commit\")'",
        "uvx ruff check .",
        "bunx tsc --noEmit",
        "bun x tsc --noEmit",
        "npx prettier --check .",
        "strace -f -o /tmp/t ls",
        "valgrind --leak-check=full ls",
        "perf stat -e cycles cargo build",
        "xvfb-run -a bun test",
        "systemd-inhibit --why=bench cargo bench",
        "chronic cargo build",
        "cargo run -- status",
        "cargo run --release -p x -- --help",
        "echo git commit -n",
        "grep -rn 'git commit' src",
        "gh pr create --title x --body 'run git commit -n here'",
        "frobnicate --verbose build",
        "konsole --version",
        "faketty cargo test",
        "pacman -Qi git",
        "brew install git gh",
        "yay -S git lfs",
        "kubectl exec pod -- git status",
        "cargo test -p tollgate",
        "notesmd-cli search-content 'tollgate install'",
        "uv pip install python-dotenv",
        "uv python install 3.12",
        "npm install",
        "perf report -i perf.data",
    ] {
        let g = lab.guard(cmd);
        assert!(matches!(g, Guarded::Allowed(_)), "{cmd}: {g:?}");
    }
}
