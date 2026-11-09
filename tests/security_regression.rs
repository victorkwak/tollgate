//! Security regression suite (S1-S20): one test per bypass, each run the
//! way a Claude Code session runs git.
//!
//! The lab: the binary from this build installed by `tollgate install
//! --yes` into a sandbox (its own HOME, XDG dirs and settings file), the
//! session environment taken from the `env` that install wrote to that
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

use support::{Armed, Run, Sandbox, Scratch, eventually, job_id, write_b, write_exe};

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
        "echo x | xargs git commit -m".to_owned(),
        "nohup git commit -m nohup".to_owned(),
        "$(command -v git) commit -m which".to_owned(),
        format!("python3 {}", py.display()),
    ] {
        let s = lab.refused(&cmd);
        assert!(
            s.out()
                .contains("tollgate: DENIED pre-commit refs/heads/main"),
            "{cmd}: the hook did not run: {s:?}"
        );
    }
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

/// S17: `install --yes` without a TTY never edits the account's real
/// settings. The test makes the sandbox home the passwd home (a user and
/// mount namespace with a bind-mounted /etc/passwd) and tries the real
/// settings path directly, through `TMPDIR` (the old test switch) and
/// through symlinks.
#[cfg(target_os = "linux")]
#[test]
fn s17_install_yes_without_a_tty_never_edits_the_real_settings() {
    let probe = Command::new("unshare")
        .args(["-rm", "true"])
        .stderr(Stdio::null())
        .status();
    if !probe.is_ok_and(|s| s.success()) {
        support::tools::skip(
            "s17_install_yes_without_a_tty_never_edits_the_real_settings",
            "no unprivileged user namespaces",
        );
        return;
    }
    let sb = Sandbox::new();
    let bin_dir = sb.root().join("bin");
    write_exe(
        &bin_dir.join("claude"),
        "#!/bin/sh\necho '2.1.317 (Claude Code)'\n",
    );
    sb.host_config("[verify]\nmin_free = \"1M\"\n");
    let real = sb.home.join(".claude");
    std::fs::create_dir_all(&real).unwrap();
    let original = "{\n  \"env\": {\n    \"KEEP\": \"1\"\n  }\n}\n";
    std::fs::write(real.join("settings.json"), original).unwrap();
    // The passwd entry the namespace sees for its uid 0.
    let passwd = sb.root().join("passwd");
    std::fs::write(
        &passwd,
        format!("root:x:0:0:test:{}:/bin/sh\n", sb.home.display()),
    )
    .unwrap();
    let path = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap());
    let install = |extra: &[(&str, &std::ffi::OsStr)]| -> Run {
        let mut cmd = Command::new("unshare");
        cmd.args([
            "-rm",
            "sh",
            "-c",
            "mount --bind \"$1\" /etc/passwd && shift && exec \"$@\"",
            "sh",
        ])
        .arg(&passwd)
        .args([support::BIN, "install", "--yes"])
        .env_clear()
        .current_dir(sb.root())
        .stdin(Stdio::null());
        for (k, v) in sb.env().iter() {
            cmd.env(k, v);
        }
        cmd.env("PATH", &path);
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        Run {
            code: out.status.code(),
            out: format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        }
    };
    let unchanged = || {
        assert_eq!(
            std::fs::read_to_string(real.join("settings.json")).unwrap(),
            original
        );
    };
    // Control: another home's settings are edited (the namespace works,
    // and --yes is not refused for every file).
    let other = sb.root().join("other");
    std::fs::create_dir_all(other.join(".claude")).unwrap();
    std::fs::write(other.join(".claude/settings.json"), "{}\n").unwrap();
    let r = install(&[("HOME", other.as_os_str())]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        std::fs::read_to_string(other.join(".claude/settings.json"))
            .unwrap()
            .contains("core.hooksPath"),
        "{}",
        r.out
    );
    let refused = |r: &Run| {
        assert!(
            r.out.contains("L10") && r.out.contains("the account's real settings"),
            "{}",
            r.out
        );
        unchanged();
    };
    // The real path.
    refused(&install(&[("HOME", sb.home.as_os_str())]));
    // The item 9 trick: TMPDIR at the real config dir.
    refused(&install(&[
        ("HOME", sb.home.as_os_str()),
        ("TMPDIR", real.as_os_str()),
    ]));
    refused(&install(&[
        ("HOME", sb.home.as_os_str()),
        ("TMPDIR", real.as_os_str()),
        ("TOLLGATE_TEST_INSTALL", "1".as_ref()),
    ]));
    // A settings file that is a symlink to the real one.
    let linked = sb.root().join("linked");
    std::fs::create_dir_all(linked.join(".claude")).unwrap();
    std::os::unix::fs::symlink(
        real.join("settings.json"),
        linked.join(".claude/settings.json"),
    )
    .unwrap();
    refused(&install(&[("HOME", linked.as_os_str())]));
    // A config dir that is a symlink to the real one, by HOME and by
    // CLAUDE_CONFIG_DIR, and TMPDIR through it.
    let dir_link = sb.root().join("dirlink");
    std::fs::create_dir_all(&dir_link).unwrap();
    std::os::unix::fs::symlink(&real, dir_link.join(".claude")).unwrap();
    let linked_dir = dir_link.join(".claude");
    refused(&install(&[("HOME", dir_link.as_os_str())]));
    refused(&install(&[
        ("HOME", other.as_os_str()),
        ("CLAUDE_CONFIG_DIR", linked_dir.as_os_str()),
    ]));
    refused(&install(&[
        ("HOME", dir_link.as_os_str()),
        ("TMPDIR", linked_dir.as_os_str()),
    ]));
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
    let cmd = format!("PATH={}:$PATH git commit -m bad", forger_dir.display());
    let s = lab.refused(&cmd);
    main_policy_denies(s.code(), s.out(), &cmd);

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
