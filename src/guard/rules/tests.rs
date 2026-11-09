//! Unit tests of the closed grammar (G1-G8): one test per follow-up item
//! with the forms that item names, then the grammar's groups.

use std::path::{Path, PathBuf};

use super::*;
use crate::config::glob::{self, GlobOpts};

fn ctx_at(cwd: &Path, home: &Path) -> Context {
    let h = home.to_path_buf();
    Context {
        cwd: cwd.to_owned(),
        home: h.clone(),
        vars: vec![
            ("HOME".into(), h.display().to_string()),
            (
                "XDG_STATE_HOME".into(),
                h.join(".local/state").display().to_string(),
            ),
            ("TMPDIR".into(), "/tmp".into()),
        ],
        protected: vec![
            h.join(".local/state/tollgate"),
            h.join(".local/share/tollgate"),
            h.join(".config/tollgate"),
        ],
        host_config: h.join(".config/tollgate/config.toml"),
        tool_paths: [
            ".local/bin",
            ".bun/bin",
            ".cargo/config.toml",
            ".cargo/config",
            ".rustfmt.toml",
            "rustfmt.toml",
            ".config/rustfmt/rustfmt.toml",
            ".config/rustfmt/.rustfmt.toml",
            ".cargo",
            ".rustup",
            ".bun",
            ".cache/uv",
            ".local/share/uv",
        ]
        .iter()
        .map(|p| h.join(p))
        .collect(),
        full_refs: glob::compile(
            &["main", "master", "integration/*"],
            GlobOpts {
                case_insensitive: true,
                literal_separator: false,
            },
        )
        .unwrap(),
        tollgate_names: vec![
            h.join(".local/share/tollgate/bin/tollgate")
                .display()
                .to_string(),
        ],
        inline_cap: 540,
        git_env: crate::env::EnvSnapshot::default(),
    }
}

fn ctx() -> Context {
    ctx_at(Path::new("/w/repo"), Path::new("/h"))
}

fn ruling(cmd: &str) -> Ruling {
    bash_ruling(&ctx(), cmd)
}

#[track_caller]
fn denied(cmds: &[&str]) {
    let c = ctx();
    denied_in(&c, cmds);
}

#[track_caller]
fn denied_in(c: &Context, cmds: &[&str]) {
    for cmd in cmds {
        assert!(
            matches!(bash_ruling(c, cmd), Ruling::Deny(_)),
            "not denied: {cmd:?} -> {:?}",
            bash_ruling(c, cmd)
        );
    }
}

#[track_caller]
fn allowed(cmds: &[&str]) {
    let c = ctx();
    allowed_in(&c, cmds);
}

#[track_caller]
fn allowed_in(c: &Context, cmds: &[&str]) {
    for cmd in cmds {
        assert_eq!(bash_ruling(c, cmd), Ruling::Allow, "{cmd:?}");
    }
}

#[track_caller]
fn asked(cmds: &[&str]) {
    for cmd in cmds {
        assert!(
            matches!(ruling(cmd), Ruling::Ask(_)),
            "not asked: {cmd:?} -> {:?}",
            ruling(cmd)
        );
    }
}

fn reason(cmd: &str) -> String {
    match ruling(cmd) {
        Ruling::Deny(why) | Ruling::Ask(why) => why,
        Ruling::Allow => String::new(),
    }
}

// ---- one test per follow-up item ------------------------------------------

/// Item 12: the whole command is checked as received; a client cap prefix
/// hides nothing, and a client TOLLGATE_INLINE_CAP is only a literal
/// number up to the session cap in front of git or tollgate (G6).
#[test]
fn item_12_the_inline_cap_prefix_hides_nothing() {
    denied(&[
        "TOLLGATE_INLINE_CAP=1 git commit --no-verify -m x; ls",
        "export TOLLGATE_INLINE_CAP=540; git commit --no-verify -m x; ls",
        "export TOLLGATE_INLINE_CAP=1; git commit -m x",
        "TOLLGATE_INLINE_CAP=999 git commit -m x",
        "TOLLGATE_INLINE_CAP=1 cargo test",
        "TOLLGATE_INLINE_CAP=1 bash -c 'git commit -m x'",
        "env TOLLGATE_INLINE_CAP=1 git commit -m x",
        "TOLLGATE_INLINE_CAP=$N git commit -m x",
        "TOLLGATE_INLINE_CAP=1x git commit -m x",
        "unset TOLLGATE_INLINE_CAP",
        "read TOLLGATE_INLINE_CAP < f",
    ]);
    allowed(&[
        "TOLLGATE_INLINE_CAP=1 git commit -m x",
        "TOLLGATE_INLINE_CAP=540 tollgate check",
        "echo $TOLLGATE_INLINE_CAP",
        "grep -rn TOLLGATE_INLINE_CAP src",
    ]);
}

/// Item 13b (with 13 and 16): flags are matched on the words bash passes,
/// by option position: every abbreviation of --no-verify from --no-v on,
/// `=` forms, quoting splits, `-n` where it means no-verify; a word bash
/// builds at run time in a gated command fails closed.
#[test]
fn item_13b_no_verify_by_option_position() {
    let mut cmds: Vec<String> = Vec::new();
    for n in "--no-v".len()..="--no-verify".len() {
        let flag = &"--no-verify"[..n];
        cmds.push(format!("git commit {flag} -m x"));
        cmds.push(format!("git commit -m x {flag}"));
        cmds.push(format!("git push {flag} origin feat"));
        cmds.push(format!("git am {flag} a.patch"));
        cmds.push(format!("git merge {flag} feat"));
        cmds.push(format!("git rebase {flag} main"));
        cmds.push(format!("git pull {flag}"));
    }
    let refs: Vec<&str> = cmds.iter().map(String::as_str).collect();
    denied(&refs);
    denied(&[
        "git commit --no-verify=1 -m x",
        "git commit --no-\"v\"erify -m x",
        "git commit --no-ver\\ify -m x",
        "git commit -n -m x",
        "git commit -anm x",
        "git commit -qn -m x",
        "git commit -un -n -m x",
        "git am -kn a.patch",
        "git push -n origin feat",
        "git commit --no-v$x -m y",
        "git commit \"$F\" -m y",
        "git commit $'--no-verify' -m x",
        "git commit `echo -n` -m x",
        "git commit $(echo --no-verify) -m x",
        "git commit -m x {--no-verify,}",
        "git commit -m x --no-verif*",
        "git -c core.hooksPath=/dev/null commit -m x",
        "git --config-env=core.hooksPath=X commit -m x",
        "git --config-e=core.hooksPath=X commit -m x",
    ]);
    allowed(&[
        "git commit --no-verbose -m x",
        "git commit --no-edit --amend",
        "git commit -m --no-verify",
        "git commit -m -n",
        "git commit -mn",
        "git commit -F --no-verify",
        "git commit -uno -m x",
        "git commit -Snone -m x",
        "git merge -n feat",
        "git cherry-pick -n abc1234",
        "git rebase -n main",
        "git pull -n",
        "git merge --no-verify-signatures feat",
    ]);
}

/// Item 15: cwd tracking follows `cd`, `cd --`, `cd -`, `pushd` and
/// `popd`; after a change it cannot follow, relative writes deny; paths are
/// resolved through symlinks; `ln` into a protected dir denies.
#[test]
fn item_15_cwd_tracking_and_symlinks() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("h");
    let state = home.join(".local/state/tollgate");
    std::fs::create_dir_all(state.join("results")).unwrap();
    std::fs::create_dir_all(tmp.path().join("w/repo")).unwrap();
    std::os::unix::fs::symlink(&state, tmp.path().join("link")).unwrap();
    let c = ctx_at(&tmp.path().join("w/repo"), &home);
    let s = state.display().to_string();
    let link = tmp.path().join("link").display().to_string();
    let parent = home.join(".local/state").display().to_string();
    denied_in(
        &c,
        &[
            &format!("cd {s} && rm -rf results"),
            &format!("cd -- {s} && rm -rf results"),
            &format!("pushd {s} && rm -rf results"),
            &format!("cd {s}; cd /tmp; cd - && rm -rf results"),
            &format!("pushd {s}; pushd /tmp; popd; rm -rf results"),
            &format!("cd {parent} && rm -rf tollgate"),
            &format!("cd {parent}/x/.. && rm -rf tollgate"),
            &format!("rm -rf {link}/results"),
            &format!("echo x > {link}/results/a.json"),
            &format!("cd {link} && rm -rf results"),
            &format!("ln -s {s} /tmp/s"),
            &format!("ln -s /tmp/x {s}/results/a.json"),
            "cd \"$X\" && rm -rf results",
            "cd $(cat dir.txt); rm -rf results",
            "pushd +1 && rm -rf results",
            "cd \"$X\"; echo x > results/a.json",
            &format!("(cd {s}; rm -rf results)"),
            &format!("f() {{ cd {s}; }}; f; rm -rf results"),
        ],
    );
    allowed_in(
        &c,
        &[
            &format!("cd {s} && ls results"),
            &format!("cat {s}/jobs/J/report.json"),
            "cd \"$X\" && cargo build",
            "cd \"$X\" && cargo build > /tmp/b.log",
            &format!("(cd {s}); rm -rf build"),
            "cd /tmp/new-dir && rm -rf x",
            "ln -s /tmp/a /tmp/b",
        ],
    );
}

/// Item 18: `env -S` has its own splitting rules; the guard reads only a
/// literal string with none of env's escapes or variables, and it may not
/// run git, tollgate, a shell or an interpreter.
#[test]
fn item_18_env_split_string() {
    denied(&[
        "env -S 'git commit -n -m x'",
        "env -S'git commit -m x'",
        "env --split-string='-i git commit -m x'",
        "env -S 'git\\_commit\\_-n'",
        "env -S '${G} commit'",
        "env -S \"$S\"",
        "env -vS'bash -c x'",
    ]);
    allowed(&["env -S 'echo hi'", "env FOO=1 cargo test"]);
}

/// Item 19: writes of sensitive variables through `printf -v`, `read`,
/// `mapfile`/`readarray`, `declare -n` and `source` deny by position;
/// mentions as data stay allowed.
#[test]
fn item_19_variable_writes_by_position() {
    denied(&[
        "printf -v GIT_DIR /tmp/x; git commit -m x",
        "printf -vGIT_DIR /tmp/x; git status",
        "printf -v XDG_STATE_HOME /tmp/x; tollgate status",
        "printf -v HOME /tmp/x; git commit -m x",
        "declare -n h=HOME; h=/tmp; git commit -m x",
        "printf -v \"$N\" x",
        "read GIT_DIR <<< /tmp/x; git commit -m x",
        "read -r -a GIT_CONFIG_COUNT < f",
        "read \"$N\" < f",
        "mapfile GIT_CONFIG_COUNT < f",
        "readarray -t TOLLGATE_X < f",
        "mapfile -C 'git commit -n' arr < f",
        "declare -n r=GIT_DIR; r=/tmp/x; git status",
        "f() { local -n r=XDG_STATE_HOME; r=/x; }; f; tollgate check",
        "declare \"$N\"=1",
        "export -n GIT_CONFIG_COUNT",
        "typeset -x GIT_WORK_TREE=/tmp; git commit -m x",
        "getopts ab GIT_DIR; git status",
        "let GIT_CONFIG_COUNT=0",
        "(( GIT_CONFIG_COUNT = 0 ))",
        "echo ${GIT_DIR:=/tmp/x}; git status",
        "for GIT_DIR in /tmp/x; do git status; done",
        "exec {GIT_CONFIG_COUNT}>/dev/null",
        "source <(echo export GIT_DIR=/x)",
        "source <(echo export X=1)",
        ". /dev/stdin <<< 'export GIT_DIR=/x'",
    ]);
    allowed(&[
        "grep -rn GIT_DIR src",
        "echo $GIT_DIR",
        "printf '%s\\n' GIT_CONFIG_COUNT",
        "read -r line < f",
        "mapfile -t lines < f",
        "declare -p",
        "export FOO=bar && cargo build",
        "export PATH=\"$HOME/.cargo/bin:$PATH\"",
        // Scoped variables (G5): only with git or tollgate in the command.
        "printf -v GIT_DIR /tmp/x",
        "declare -n r=GIT_DIR; r=/tmp/x",
        "export XDG_STATE_HOME=/tmp/s; cargo test",
        "export XDG_STATE_HOME=/tmp/s && git init -q && git status",
        "GIT_INDEX_FILE=/tmp/i git read-tree HEAD && GIT_INDEX_FILE=/tmp/i git write-tree",
    ]);
}

/// Item 20: environment-losing launchers in front of git or tollgate deny
/// (G2b).
#[test]
fn item_20_environment_losing_launchers() {
    denied(&[
        "sudo git commit -m x",
        "sudo -u me git push origin feat",
        "doas git push",
        "su -c 'git commit -n -m x' me",
        "su me",
        "runuser -u me -- git commit -m x",
        "setpriv --reuid=1000 git commit -m x",
        "systemd-run --user git commit -m x",
        "systemd-run --user --shell",
        "pkexec tollgate install",
        "sudo -s",
        "sudo -i",
    ]);
    allowed(&["sudo systemctl status sshd", "sudo -n true"]);
}

/// Item 22 and review R4 (guard part): remote identity changes ask; ref
/// writes into refs/remotes/* deny in every form; moves of main, master
/// and the policy anchors deny; writes into .git/refs, packed-refs, config
/// and hooks deny.
#[test]
fn item_22_r4_remote_identity_and_ref_writes() {
    asked(&[
        "git remote add evil /tmp/x",
        "git remote set-url origin /tmp/x",
        "git remote rename origin x",
        "git remote remove origin",
        "git remote rm origin",
        "git config remote.origin.url /tmp/x",
        "git config remote.origin.pushurl /tmp/x",
        "git config remote.origin.fetch '+refs/heads/*:refs/remotes/origin/*'",
        "git config --replace-all remote.origin.receivepack x",
        "git config --remove-section remote.origin",
        "git -c remote.origin.url=/tmp/x fetch origin",
        "git --config-env=remote.origin.url=V fetch origin",
        "git config url./tmp/x.insteadOf git@h:r.git",
    ]);
    denied(&[
        "git update-ref refs/remotes/origin/main HEAD",
        "git update-ref -m 'fetch: x' refs/remotes/origin/main HEAD",
        "git update-ref -d refs/remotes/origin/main",
        "git update-ref --stdin <<< 'update refs/remotes/origin/main abc'",
        "git update-ref --stdin <<'EOF'\nupdate refs/heads/main abc\nEOF",
        "echo 'update refs/heads/x abc' | git update-ref --stdin",
        "git update-ref --stdin < cmds.txt",
        "git update-ref refs/heads/main HEAD~1",
        "git update-ref refs/heads/MAIN HEAD~1",
        "git update-ref \"$R\" HEAD",
        "git fetch . feat:refs/remotes/origin/main",
        "git fetch /tmp/fake +main:refs/remotes/origin/main",
        "git fetch origin main:refs/remotes/origin/main",
        "git fetch . feat:main",
        "git fetch /tmp/fake feat:refs/heads/master",
        "git push . feat:main",
        "git push . HEAD:refs/remotes/origin/main",
        "git branch -f main feat",
        "git branch -M feat main",
        "git branch -C feat master",
        "git checkout -B main feat",
        "git switch -C main",
        "git worktree add -B main ../wt feat",
        "echo x > .git/refs/heads/main",
        "printf x > /w/repo/.git/packed-refs",
        "cp x .git/packed-refs",
        "tee .git/config < x",
        "sed -i s/a/b/ .git/config",
        "mv x .git/hooks/pre-commit",
        "ln -s x .git/refs/heads/main",
        "truncate -s0 .git/packed-refs",
        "dd if=x of=.git/refs/heads/main",
    ]);
    allowed(&[
        "git branch -f feat HEAD~1",
        "git fetch origin",
        "git fetch -q origin",
        "git fetch origin main:main",
        "git push . feat:other",
        "git remote -v",
        "git update-ref refs/heads/feat HEAD",
        "cat .git/config",
        "git config --get remote.origin.url",
    ]);
    // The repo's policy anchors are anchors too.
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("r");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::write(
        repo.join("tollgate.toml"),
        "version = 1\n[policy]\nanchors = [\"trunk\"]\n",
    )
    .unwrap();
    let c = ctx_at(&repo, Path::new("/h"));
    denied_in(
        &c,
        &[
            "git branch -f trunk feat",
            "git update-ref refs/heads/trunk HEAD",
            "git push . HEAD:trunk",
        ],
    );
    // `update-ref HEAD` moves the branch HEAD names.
    std::fs::write(repo.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    denied_in(&c, &["git update-ref HEAD abc1234"]);
    std::fs::write(repo.join(".git/HEAD"), "ref: refs/heads/feat\n").unwrap();
    allowed_in(&c, &["git update-ref HEAD abc1234"]);
}

/// Item 22, secreview note 5: the options that create or reset a branch
/// count in every spelling git takes: a short option inside a group, the
/// branch name glued to the letter, and a long option abbreviated to a
/// prefix. Options that take a value hide the letters after them; words
/// after `--` and values are not options.
#[test]
fn item_22_force_create_in_every_spelling() {
    let c = ctx();
    let open: Vec<&str> = [
        "git switch -fC main HEAD~3",
        "git switch -qfCmain HEAD~3",
        "git switch --force-c main HEAD~3",
        "git switch --force-create=main HEAD~3",
        "git switch --force-cr=main HEAD~3",
        "git switch --forc main HEAD~3",
        "git switch -f --force-c main HEAD~3",
        "git switch feat -C main",
        "git checkout -qB main HEAD~3",
        "git checkout -fBmain HEAD~3",
        "git checkout -Bmain HEAD~3",
        "git checkout -tqB main HEAD~3",
        "git checkout HEAD~3 -B main",
        "git checkout -b x -B main HEAD~3",
        "git checkout -U3 -B main HEAD~3",
        "git worktree add -fB main ../wt HEAD~3",
        "git worktree add -Bmain ../wt HEAD~3",
        "git worktree add -qfB main ../wt HEAD~3",
        "git worktree add ../wt -B main HEAD~3",
        "git branch --forc main HEAD~3",
        "git branch --forc=x main HEAD~3",
        "git branch --fo main HEAD~3",
        "git branch -qf main HEAD~3",
        "git branch -f --sor refname main HEAD~3",
        "git branch -f --sort refname main HEAD~3",
        "git branch -f --forma x main HEAD~3",
        "git branch -f --points x main HEAD~3",
        "git branch -f --no-con x main HEAD~3",
        "git branch -fu origin/x main HEAD~3",
        "git branch --mo --forc feat main",
        "git branch --cop -f feat main",
        "git branch -fqM feat main",
        "git branch -f -- main HEAD~3",
        "git branch -f \"$X\" main HEAD~3",
        "git checkout \"$X\" main HEAD~3",
        "git checkout $X main HEAD~3",
        "git switch \"$X\" main HEAD~3",
        "git worktree add \"$X\" main ../wt HEAD~3",
        "git checkout \"$BRANCH\"",
        "git switch \"$BRANCH\"",
        "git worktree add ../wt \"$B\"",
        "git worktree \"$X\" -B main ../wt",
        "git checkout -B*",
        "git checkout *",
        "git checkout {-B,main}",
        "git checkout -b x$Y HEAD~3",
        "git checkout -B \"$N\" HEAD~3",
        "git checkout $'-Bmain' HEAD~3",
        "git checkout \"-\"B main HEAD~3",
        "git -C . switch -fC MAIN HEAD~3",
    ]
    .into_iter()
    .filter(|cmd| !matches!(bash_ruling(&c, cmd), Ruling::Deny(_)))
    .collect();
    assert!(open.is_empty(), "not denied:\n{}", open.join("\n"));
    allowed_in(
        &c,
        &[
            "git switch -c feat2 main",
            "git switch -f main",
            "git switch --force main",
            "git switch --no-force-create main",
            "git switch -C feat2 main",
            "git switch --force-create=feat2 main",
            "git switch -c=-C main",
            "git checkout -b B main",
            "git checkout -bB main",
            "git checkout -b x main",
            "git checkout -B feat2 main",
            "git checkout -fBfeat2 main",
            "git checkout -U5 main",
            "git checkout --conflict -B",
            "git checkout --orphan -B",
            "git checkout main -- -Bmain",
            "git checkout -- -B main",
            "git checkout --end-of-options \"$BRANCH\"",
            "B=feat; git checkout \"$B\"",
            "git checkout feat/\"$N\"",
            "git checkout -b \"$NEW\" main",
            "git checkout -- *.rs",
            "git switch --end-of-options \"$BRANCH\"",
            "git worktree add -b B ../wt main",
            "git worktree add -bB ../wt main",
            "git worktree add -fB feat2 ../wt main",
            "git worktree add --reason -B ../wt main",
            "git worktree add --end-of-options ../wt \"$B\"",
            "git worktree list \"$X\"",
            "git branch -f feat main",
            "git branch --forc feat main",
            "git branch -f --sort refname feat main",
            "git branch -f --sor=refname feat main",
            "git branch --list main",
            "git branch -f -- feat main",
            "git branch main",
        ],
    );
}

/// Item 31: ANSI-C quoting, `\c`, and text fed to a shell are never
/// decoded where they matter: `$'...'` is not literal, so a gated command
/// holding one denies; a here-string or literal heredoc fed to a shell is
/// parsed and checked like `sh -c` code (G3).
#[test]
fn item_31_hidden_text() {
    denied(&[
        r"echo $'\c\\' ; git commit $'\x2dn' -m x",
        r"git commit $'\c-\c-no-verify' -m x",
        r"echo $'\c\\' ; git commit -n -m x",
        "bash <<< \"git commit --no-verify -m x\"",
        "sh <<'EOF'\ngit commit -n -m x\nEOF",
        "sh <<EOF\ngit commit $F -m x\nEOF",
        "cat <<EOF | bash\ngit commit -m x\nEOF",
        "echo 'git commit -m x' | sh",
        "python3 - <<'EOF'\nimport os; os.system('git commit -n -m x')\nEOF",
        "perl <<< 'system(\"git commit -n\")'",
    ]);
    allowed(&[
        "bash <<'EOF'\ngit status\nEOF",
        r"printf %s $'\c\\x'",
        "git commit -F - <<'EOF'\nsubject\n\nbody with --no-verify\nEOF",
        "cat <<'EOF' > notes.md\ngit commit --no-verify is denied\nEOF",
    ]);
}

/// Item 40: non-literal command words, arguments xargs reads from a pipe,
/// and a process substitution run as a shell script.
#[test]
fn item_40_command_words_xargs_and_process_substitution() {
    denied(&[
        "${x}t commit -n -m y",
        "$G commit -m y",
        "\"$G\" commit -m y",
        "$(command -v git) commit -m x",
        "`which git` commit -m x",
        "g\"i\"t$x commit",
        "xargs git",
        "echo commit | xargs git",
        "printf -- '--no-verify\\n' | xargs git commit -m x",
        "echo x | xargs -I{} git {} -m x",
        "echo x | xargs env git commit",
        "find . -maxdepth 0 -exec git commit -n -m x \\;",
        "find . -exec sh -c 'git commit' \\;",
        "parallel git commit -m {} ::: a",
        "bash <(printf 'git commit -n -m x')",
        "source <(printf 'git commit -n -m x')",
    ]);
    allowed(&[
        "git ls-files -m | xargs git add",
        "find . -name '*.orig' -exec rm {} +",
        "echo a b | xargs -n1 echo",
        "rg -l foo | xargs sed -i s/foo/bar/g",
    ]);
}

/// Item 42: rules look at parsed positions, never at message text or data:
/// agents can grep, cat and commit text that names the denied flags and
/// variables.
#[test]
fn item_42_no_false_denies_from_text() {
    allowed(&[
        "git commit -m \"docs: mention --no-verify in README\"",
        "git commit -m 'Fix env' -i src/a.rs",
        "git commit -m \"Guard: deny no-verify abbreviations\" -m \"Names GIT_CONFIG_COUNT, core.hooksPath and --no-verify in prose\"",
        "grep -rn \"GIT_CONFIG_COUNT\\|core.hooksPath\\|--no-verify\" src docs",
        "rg -- '--no-verify' docs",
        "cat docs/spec.md | grep -n GIT_CONFIG",
        "echo 'export GIT_CONFIG_COUNT=0'",
        "git log --grep=--no-verify",
        "sed -n 1,40p src/guard/rules.rs",
        "git commit -m \"$(cat <<'EOF'\nGuard: env -i and unset GIT_CONFIG_COUNT\n\nCo-Authored-By: Name <noreply@example.com>\nEOF\n)\"",
    ]);
}

/// Item 29: install and uninstall are for a person at a terminal. A
/// session has none, but a pty wrapper (`script -c`, `unbuffer`, `socat`)
/// makes one and can type the yes; so the guard denies them in a session
/// (R25), like `remotes forget`, in any spelling. When the gate is not
/// armed, the L8 repair rule still lets the plain command through; it then
/// refuses for want of a terminal.
#[test]
fn item_29_install_and_uninstall_are_not_for_sessions() {
    denied(&[
        "tollgate install",
        "tollgate uninstall",
        "tollgate INSTALL",
        "printf 'y\\n' | script -qec 'tollgate install' /dev/null",
        "yes | script -qc 'tollgate uninstall' /dev/null",
        "script -q -c 'tollgate install' /dev/null < answers",
        "unbuffer tollgate install",
        "echo y | tollgate install",
        "python3 -c \"import pty; pty.spawn(['tollgate', 'install'])\"",
        "socat - EXEC:'tollgate install',pty",
        "socat - exec:tollgate\\ install,pty,stderr",
        "socat -d -d STDIO SYSTEM:'tollgate install',pty",
        "socat - -!!Shell:'tollgate install'",
        "expect -c 'spawn tollgate install; send y\\r; interact'",
        "echo 'spawn tollgate install' | expect",
        "tclsh8.6 x.tcl",
        "env wish x.tcl",
        "timeout 5 expect x.exp",
        "tmux new-session -d 'tollgate install'",
        "screen -dm tollgate install",
        "setsid -w tollgate install",
    ]);
    // socat that runs no program is data to the guard.
    allowed(&[
        "socat - TCP:localhost:5432",
        "socat -u FILE:a,rdonly STDOUT",
    ]);
    allowed(&["tollgate doctor", "tollgate status"]);
}

/// Item 44: the raw-text rule for the old install test switch is gone;
/// setting the variable is still a TOLLGATE_* write (G5).
#[test]
fn item_44_no_raw_text_rule_for_the_old_switch() {
    allowed(&["grep -rn tollgate_test_install src"]);
    denied(&["TOLLGATE_TEST_INSTALL=1 tollgate install --yes"]);
}

/// X2 (as read here: the X1 transport and exec-path variables in every
/// write position, G5): denied in front of any command, through env,
/// export, declare, printf -v, read, for and arithmetic.
#[test]
fn x2_transport_variables_in_every_write_position() {
    denied(&[
        "GIT_SSH_COMMAND=/tmp/f git fetch origin",
        "GIT_SSH_COMMAND=/tmp/f cargo test",
        "env GIT_SSH=/tmp/f git push origin feat",
        "export GIT_PROXY_COMMAND=/tmp/p",
        "declare -x GIT_EXEC_PATH=/tmp/x && git push",
        "printf -v GIT_SSH_COMMAND /tmp/f",
        "read GIT_SSH_VARIANT < f",
        "for GIT_SSH in /tmp/f; do git fetch; done",
        "bash -c 'GIT_SSH=/tmp/f git push origin feat'",
        "unset GIT_SSH_COMMAND",
    ]);
    allowed(&["echo $GIT_SSH_COMMAND", "git config --get core.sshCommand"]);
}

/// Item 21 (review note 8): every git config key, variable and option
/// whose value git runs as a program or as shell code is read as code
/// (G3) on every git command, not only on gated ones, or denied; the
/// program variables are read in front of any command and in every write
/// position; `ext::` transports stay off.
#[test]
fn item_21_program_values_are_code_on_every_command() {
    denied(&[
        // Config keys git runs through a shell.
        "git -c diff.external='git commit -n -m x #' diff HEAD~1",
        "git -c Diff.External='git commit -n -m x #' diff",
        "git -c diff.x.command='git commit -n #' diff",
        "git -c diff.x.textconv='git commit -n #' diff",
        "git -c filter.x.clean='git commit -n #' add .",
        "git -c filter.x.smudge='git commit -n #' checkout -- f",
        "git -c filter.x.process='git commit -n #' status",
        "git -c merge.x.driver='git commit -n #' merge-tree --write-tree a b",
        "git -c mergetool.x.cmd='git commit -n' mergetool -t x",
        "git -c difftool.x.cmd='git commit -n' difftool -t x HEAD",
        "git -c interactive.diffFilter='git commit -n' add -p",
        "git -c credential.helper='!git commit -n -m x #' fetch origin",
        "git -c credential.https://x.helper='!git commit -n #' fetch origin",
        "git -c credential.helper='x; git commit -n -m x' fetch origin",
        "git -c pager.log='git commit -n -m x #' log",
        "git -c imap.tunnel='git commit -n' imap-send",
        "git -c submodule.s.update='!git commit -n -m x' submodule update",
        "git -c gpg.ssh.defaultKeyCommand='git commit -n -m x' log",
        // Config keys git runs as one program: a path with no shell text.
        "git -c core.askpass='git commit -n -m x #' fetch origin",
        "git -c gpg.program='git commit -n -m x #' log --show-signature",
        "git -c gpg.ssh.program='git commit -n' log --show-signature",
        "git -c difftool.x.path='/usr/bin/git commit -n' difftool -t x",
        // Keys no session needs.
        "git -c uploadpack.packObjectsHook='git commit -n #' fetch origin",
        "git -c core.alternateRefsCommand=/tmp/x fetch origin",
        "git -c hook.x.command='git commit -n' -c hook.x.event=post-checkout checkout main",
        "git -c protocol.ext.allow=always fetch 'ext::sh -c git% commit% -n% -m% x'",
        "git -c protocol.EXT.allow=user ls-remote origin",
        "git -c protocol.allow=always ls-remote origin",
        "git ls-remote 'ext::sh -c git% commit% -n'",
        "git clone EXT::sh x",
        "GIT_ALLOW_PROTOCOL=ext git ls-remote origin",
        "export GIT_ALLOW_PROTOCOL=file:ext",
        "git --config-env=diff.external=X diff",
        "git --config-env pager.log=X log",
        // Program variables, in front of any command and in every write.
        "GIT_PAGER='git commit -n -m x #' git log",
        "PAGER='git commit -n #' git log",
        "PAGER='git commit -n #' man ls",
        "MANPAGER='git commit -n #' man ls",
        "EDITOR='git commit -n #' crontab -e",
        "VISUAL='git commit -n #' crontab -e",
        "GIT_ASKPASS='git commit -n -m x' git fetch origin",
        "SSH_ASKPASS=/tmp/x/../a.sh git fetch origin",
        "GIT_EXTERNAL_DIFF='git commit -n #' git diff",
        "GIT_EXTERNAL_DIFF=\"$X\" git diff",
        "env GIT_PAGER='git commit -n #' git log",
        "export GIT_PAGER='git commit -n #'; git log",
        "GIT_PAGER='git commit -n #'; git log",
        "declare -x GIT_EXTERNAL_DIFF='git commit -n #'; git diff",
        "export GIT_EXTERNAL_DIFF=\"$(cat f)\"; git diff",
        "P='git commit -n #'; GIT_PAGER=$P git log",
        "GIT_PAGER+=' ; git commit -n' git log",
        "read GIT_PAGER < f; git log",
        "printf -v GIT_EDITOR x; git commit --amend",
        "for GIT_EXTERNAL_DIFF in x; do git diff; done",
        "bash -c \"GIT_PAGER='git commit -n #' git log\"",
        "printf 'git commit -n -m x\\n' > e.sh; chmod +x e.sh; GIT_EXTERNAL_DIFF=./e.sh git diff",
        // git's other config files, written in the same call.
        "printf '[diff]\\n\\texternal = git commit -n #\\n' >> ~/.gitconfig; git diff",
        "cp x /h/.gitconfig",
        "echo x | tee -a /h/.config/git/config",
        "mv x ~/.config/git",
        "printf '[diff]\\n\\texternal = x\\n' >> .git/config.worktree; git diff",
        "cat > /w/repo/.git/worktrees/w/config.worktree <<'EOF'\n[diff]\nexternal = x\nEOF",
        // less runs commands from LESS and from a lesskey file.
        "LESS='+!git commit -n -m x' git log",
        "LESS='-R +|xgit commit -n' less f",
        "export LESS='-k/tmp/keys'",
        "LESS='--lesskey-file=/tmp/k' git log",
        "LESS=\"$L\" git log",
        "LESSKEYIN=/tmp/k git log",
        // Options whose value git runs.
        "git difftool -x 'git commit -n -m x #' HEAD~1",
        "git difftool --extcmd='git commit -n' HEAD",
        "git difftool --ext 'git commit -n' HEAD",
        "git difftool -yx 'git commit -n' HEAD",
        "git difftool $X HEAD",
        "git grep -O'git commit -n -m x #' foo",
        "git grep -iO'git commit -n' foo",
        "git grep --open-files-in-pager='git commit -n' foo",
        "git grep --open='git commit -n' foo",
        "git grep \"$X\" foo",
        "git grep -n x $(cat f)",
        "S='*'; git grep x $S",
        "git grep x *",
        "X=-O./e.sh; git grep \"$X\" foo",
        "X='-Ogit commit -n #'; git grep \"$X\" foo",
        "git -c diff.external=env diff",
        "git -c diff.external=sh diff",
        "git -c core.editor='x=' commit --amend",
        "git -c core.editor=./e.sh commit --amend",
        "git clone -u 'git commit -n #' /tmp/x y",
        "git clone -qu 'git commit -n #' /tmp/x y",
        "git clone --upload-pack='git commit -n #' /tmp/x y",
        "git clone --upl='git commit -n #' /tmp/x y",
        "git clone -c core.fsmonitor=/tmp/x /tmp/x y",
        "git clone \"$U\" y",
        "git ls-remote --upload-pack='git commit -n #' /tmp/x",
        "git ls-remote --upl='git commit -n #' /tmp/x",
        "git fetch-pack --upload-pack='git commit -n #' /tmp/x",
        "git fetch-pack --exec='git commit -n #' /tmp/x",
        "git archive --remote=/tmp/x --exec='git commit -n #' HEAD",
        "git archive --ex='git commit -n #' --remote /tmp/x HEAD",
        "git filter-branch --tree-filter 'git commit -n -m x' HEAD",
        "git filter-branch --msg-filter cat HEAD",
        "git -c x.r=/w/repo for-each-repo --config=x.r commit -n -m x",
        "git send-email --to-cmd='git commit -n #' x.patch",
        "git instaweb --httpd='git commit -n'",
        // A value written to a config file is code as well (item 21
        // review): it runs on every later git command.
        "git config diff.external 'git commit -n #'",
        "git config --global core.pager 'git commit -n; cat #'",
        "git config set --global credential.helper '!git commit -n #'",
        "git config --file /h/.gitconfig core.editor 'git commit -n #'",
        "git config -f/h/.gitconfig core.editor 'git commit -n #'",
        "git config --system diff.external 'git commit -n #'",
        "git config core.askpass /tmp/missing-askpass",
        "git config protocol.ext.allow always",
        "git config --file \"$F\" a.b c",
        "git config --file /h/.local/state/tollgate/x a.b c",
    ]);
    asked(&[
        "git config diff.external difft",
        "git config --global credential.helper '!x'",
        "git config core.askpass /usr/bin/true",
        "git config pager.log x",
        "git config hook.x.command y",
        "git config protocol.ext.allow never",
        "git config --file /h/.claude/settings.json a.b c",
        "git clone -c diff.external=x /tmp/x y",
    ]);
    allowed(&[
        "git -c core.pager=cat log",
        "git -c pager.log=false log",
        "git -c pager.diff='less -R' diff",
        "git --no-pager log -5",
        "GIT_PAGER=cat git log -5",
        "PAGER=cat git log",
        "GIT_PAGER= git log",
        "LESS=-R git log",
        "LESS=FRX git log",
        "git -c credential.helper= ls-remote origin",
        "git -c credential.helper=store fetch origin",
        "git -c credential.helper='store --file=/tmp/c' fetch origin",
        "git -c credential.helper=libsecret fetch origin",
        "git -c credential.helper=/usr/lib/git-core/git-credential-libsecret fetch origin",
        "git -c credential.helper='!f() { echo password=x; }; f' fetch origin",
        "git -c protocol.file.allow=always submodule update --init",
        "git -c protocol.ext.allow=never fetch origin",
        "git -c diff.external= diff",
        "git -c diff.x.textconv=cat diff",
        "git -c gpg.program=gpg2 log --show-signature",
        "GIT_ASKPASS=/usr/bin/true git fetch origin",
        "GIT_EDITOR=true git rebase --continue",
        "GIT_SEQUENCE_EDITOR=\"sed -i -e 's/^pick/fixup/'\" git rebase -i HEAD~3",
        "git difftool --tool-help",
        "git difftool -y -t meld HEAD",
        "git grep -n foo",
        "git grep -O foo",
        "git grep -e \"$X\" foo",
        "S=abc123; git grep -n x $S -- src",
        "git grep -n x --end-of-options $(git rev-parse HEAD)",
        "for f in 'fn a' 'fn b'; do git grep -n \"$f\"; done",
        "D=/tmp/x; git clone $D/orig y",
        "X=-Ocat; git grep \"$X\" foo",
        "git clone https://example.com/x.git y",
        "git clone -c core.autocrlf=false https://example.com/x.git",
        "git ls-remote origin",
        "git archive -o x.tar HEAD",
        "export GIT_PAGER=cat; git log",
        "unset GIT_PAGER; git log",
        "echo $GIT_PAGER",
        "cat ~/.gitconfig",
        "touch ~/.gitconfig",
        "mkdir -p ~/.config/git",
        "echo x > ~/.config/gitk",
    ]);
}

// ---- the grammar's groups ------------------------------------------------

/// G1: the command name of every simple command is literal, nested ones
/// included.
#[test]
fn g1_literal_command_words() {
    denied(&[
        "$CARGO test",
        "ls; $X",
        "echo $($Y)",
        "g*t status",
        "{ls,} -la",
        "$'\\x6cs'",
        "echo \"$(${CMD} x)\"",
        "for f in $LIST; do $f; done",
        "for f in a*; do $f; done",
        // A loop variable over literal items is known, and git named by it
        // is still a word bash builds (G4).
        "for g in git; do $g commit -m x; done",
        "for g in echo git; do $g commit -n -m x; done",
    ]);
    allowed(&[
        "ls -la",
        "\"ls\" -la",
        "\\ls",
        "/bin/ls -la",
        "[ -f x ] && echo y",
        "for f in ls pwd; do $f; done",
    ]);
    denied(&["~/bin/not-there x"]);
}

/// G2a: pass-through wrappers are unwrapped with their own options; an
/// option the guard does not know denies.
#[test]
fn g2a_wrappers() {
    denied(&[
        "nohup git commit -n -m x",
        "timeout 600 git commit --no-verify -m x",
        "timeout -s KILL 10 git commit -n -m x",
        "nice -n 5 git push -n origin x",
        "stdbuf -oL git commit -n -m x",
        "setsid -f git commit -n -m x",
        "flock /tmp/l git commit -n -m x",
        "flock /tmp/l -c 'git commit -n -m x'",
        "command git commit -n -m x",
        "exec git commit -n -m x",
        "exec -c git commit -m x",
        "exec -a name git commit -m x",
        "env -i PATH=/usr/bin git commit -m x",
        "env -u GIT_CONFIG_COUNT git commit -m x",
        "env --unset=FOO git commit -m x",
        "env -C /tmp git commit -n -m x",
        "timeout --bogus 1 git commit -m x",
        "taskset -c 1 git commit -n -m x",
        "\\time -o /h/.local/state/tollgate/x ls",
        "/usr/bin/time -o /h/.local/state/tollgate/x ls",
    ]);
    allowed(&[
        "timeout 600 cargo test",
        "nice cargo build",
        "command -v git",
        "env FOO=1 cargo test",
        "env -i PATH=/usr/bin cargo test",
        "nohup git status",
        "timeout 600 git commit -m x",
    ]);
}

/// G2b: launchers may not run git, tollgate, a shell or an interpreter;
/// other launches stay allowed.
#[test]
fn g2b_launchers() {
    denied(&[
        "ssh host 'git commit -n -m x'",
        "ssh host",
        "ssh host bash -s < script.sh",
        "docker exec c git commit -m x",
        "docker run --rm img sh -c 'echo hi'",
        "podman exec -it c bash",
        "tmux send-keys -t x 'echo hi' Enter",
        "tmux new-session -d 'git commit -m x'",
        "screen -S x -X stuff 'ls'",
        "kitty @ send-text hi",
        "script -q /dev/null",
        "script -qc 'git commit -n -m x' /dev/null",
        "at now <<< 'git commit -n -m x'",
        "echo ls | at now",
        "nsenter -t 1 -m git status",
        "unshare -r bash",
        "chroot /x python3",
        "bwrap --bind / / git commit -m x",
        "firejail tollgate check",
        "flatpak-spawn --host git commit -m x",
        "machinectl shell me@",
        "watch 'git commit -n -m x'",
        "ssh \"$HOST\" uptime",
    ]);
    allowed(&[
        "ssh prodhost 'journalctl -u app --since \"1 hour ago\"'",
        "ssh -N -L 5432:localhost:5432 host",
        "docker ps",
        "docker exec pg psql -U postgres -c 'select 1'",
        "docker logs -f api",
        "at now <<< 'echo hi'",
        "tmux ls",
        "watch -n1 ls",
    ]);
}

/// G3: code in arguments and on stdin is literal and checked; script
/// files are read one level deep; interpreter code with a process call
/// denies.
#[test]
fn g3_code_scripts_and_interpreters() {
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    std::fs::write(
        d.join("ok.sh"),
        "#!/bin/sh\nset -e\ncargo test\ngit commit -m ok\n",
    )
    .unwrap();
    std::fs::write(
        d.join("bad.sh"),
        "#!/usr/bin/env bash\ngit commit --no-verify -m bad\n",
    )
    .unwrap();
    std::fs::write(d.join("nested.sh"), "#!/bin/sh\nsh ok.sh\n").unwrap();
    std::fs::write(d.join("noshebang"), "git push -n origin x\n").unwrap();
    std::fs::write(d.join("tool.py"), "#!/usr/bin/env python3\nprint(1)\n").unwrap();
    std::fs::write(d.join("broken.sh"), "echo 'unterminated\n").unwrap();
    std::fs::write(d.join("big.sh"), "#".repeat(2 << 20)).unwrap();
    for f in ["ok.sh", "bad.sh", "nested.sh", "noshebang", "tool.py"] {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(d.join(f), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let c = ctx_at(d, Path::new("/h"));
    denied_in(
        &c,
        &[
            "bash -c 'git commit -n -m x'",
            "bash -c \"$CODE\"",
            "sh -c 'sh -c \"git push --no-verify origin x\"'",
            "eval 'git commit -n -m x'",
            "eval \"$CMD\"",
            "eval $(ssh-agent)",
            "bash bad.sh",
            "sh ./bad.sh",
            "./bad.sh",
            "./noshebang",
            "source bad.sh",
            ". ./bad.sh",
            "bash nested.sh",
            "bash broken.sh",
            "bash big.sh",
            "bash missing.sh",
            "./missing.sh",
            "source ok.sh2",
            "printf 'git commit -n' > x.sh && bash x.sh",
            "cp bad.sh ok2.sh; ./ok2.sh",
            "cat ok.sh | bash",
            "bash < ok.sh",
            "zsh -c '=git commit -n -m x'",
            "fish -c 'git commit \\'x\\''",
            "python3 -c 'import os; os.system(\"git commit -n\")'",
            "python3 -c \"$PY\"",
            "perl -e 'system(\"git commit -n\")'",
            "perl -ne 'print `id`'",
            "ruby -e '`git commit -n`'",
            "node -e 'require(\"child_process\").execSync(\"git commit -n\")'",
            "bun -e 'Bun.spawn([\"git\"])'",
            "deno eval 'new Deno.Command(\"git\")'",
            "php -r 'shell_exec(\"git commit -n\");'",
            "lua -e 'os.execute(\"git commit -n\")'",
            "awk 'BEGIN { system(\"git commit -n\") }'",
            "awk '{ print | \"sh\" }' f",
            "git ls-files | python3",
            "trap 'git commit -n -m x' EXIT",
            "git rebase -x 'git commit --amend --no-verify --no-edit' main",
            "git -c core.editor='git commit -n -m x' rebase --continue",
            "GIT_EDITOR='git commit -n' git rebase --continue",
            "git submodule foreach 'git commit -n -m x'",
            "git bisect run sh -c 'git commit -n'",
        ],
    );
    allowed_in(
        &c,
        &[
            "bash -c 'cargo test && git commit -m x'",
            "bash -lc 'echo hi'",
            "bash -o pipefail -c 'cargo test | tail'",
            "eval 'echo hi'",
            "bash ok.sh",
            "./ok.sh",
            "source ok.sh",
            "./tool.py",
            "python3 tool.py",
            "python3 -c 'import json,sys; print(json.load(sys.stdin)[\"x\"])' < f.json",
            "python3 -m pytest -q",
            "awk -F: '{print $1}' /etc/passwd",
            "perl -pi -e 's/a/b/' f.txt",
            "node -e 'console.log(1)'",
            "bun test",
            "bash <<'EOF'\ncargo test\nEOF",
            "trap 'rm -f /tmp/x' EXIT",
            "GIT_EDITOR=true git rebase --continue",
            "git -c core.editor=true rebase --continue",
        ],
    );
}

/// G4: gated git commands use the closed shape.
#[test]
fn g4_gated_git_shape() {
    denied(&[
        "git -c user.signingkey=x commit -m x",
        "git -c core.sshCommand=/tmp/f push origin x",
        "git -c alias.ci=commit ci -m x",
        "git ci -m x",
        "git --git-dir=/tmp/x commit -m x",
        "git --work-tree /tmp commit -m x",
        "git --exec-path=/tmp/x commit -m x",
        "git --namespace x push origin x",
        "git -C \"$D\" commit -m x",
        "cd \"$D\" && git commit -m x",
        "PATH=/tmp/x:$PATH git commit -m x",
        "LD_PRELOAD=/tmp/x.so git commit -m x",
        "GIT_TRACE=1 git commit -m x",
        "GIT_AUTHOR_NAME=\"$N\" git commit -m x",
        "HOME=/tmp/x git commit -m x",
        "CARGO_TERM_COLOR=always bash -c 'git commit -m x'",
        "git send-pack origin main",
        "git push --receive-pack=/tmp/x origin feat",
        "git push --exec=/tmp/x origin feat",
        "git pull --upload-pack=/tmp/x",
        "git commit -m x <<EOF\n$X\nEOF",
        "git commit -F <(echo x)",
        "git commit -m x -- *.rs",
        "git receive-pack .",
        "git replace abc def",
        "git symbolic-ref refs/heads/alias refs/heads/src",
        "tollgate waive --tree x",
        "tollgate policy approve HEAD",
        "tollgate baseline record pyright",
        "tollgate check \"$T\"",
        "XDG_STATE_HOME=/tmp/s tollgate check",
    ]);
    allowed(&[
        "git -c user.name=x -c user.email=y commit -m x",
        "git -c commit.gpgsign=false -c color.ui=never commit -m x",
        "git -c advice.detachedHead=false cherry-pick abc1234",
        "git -c pull.rebase=true pull --ff-only",
        "GIT_AUTHOR_NAME=x GIT_AUTHOR_EMAIL=y GIT_AUTHOR_DATE=2026-01-01 git commit -m x",
        "LC_ALL=C TZ=UTC git commit -m x",
        "GIT_TERMINAL_PROMPT=0 git push origin feat",
        "git -C /w/other commit -m x",
        "/usr/bin/git commit -m x",
        "git --no-pager -P commit -m x",
        "git commit --amend --no-edit",
        "git merge --no-ff feature -m 'Merge feature'",
        "git push --force-with-lease origin feature",
        "git push origin HEAD:refs/heads/feat",
        "git push origin --delete feat",
        "tollgate status",
        "tollgate log 20261105-120000-abcd1234 tests",
        "tollgate wait 20261105-120000-abcd1234 && git commit -m s",
    ]);
}

/// G5: sensitive variables are denied in every write position; HOME only
/// in a command that runs git or tollgate.
#[test]
fn g5_sensitive_variables() {
    denied(&[
        "GIT_CONFIG_COUNT=0 git commit -m x",
        "GIT_CONFIG_PARAMETERS=\"'core.hooksPath'='/dev/null'\" git commit -m x",
        "export GIT_CONFIG_COUNT=0; git commit -m x",
        "unset GIT_CONFIG_KEY_0; git commit -m x",
        "GIT_DIR=/tmp/x git status",
        "GIT_WORK_TREE=/tmp/x git commit -m x",
        "GIT_COMMON_DIR=/tmp/x git status",
        "XDG_CONFIG_HOME=/tmp/c git status",
        "XDG_STATE_HOME=/tmp/s tollgate status",
        "export XDG_DATA_HOME=/tmp/d; tollgate check",
        "GIT_CONFIG_GLOBAL=/tmp/g git commit -m x",
        "export GIT_CONFIG_NOSYSTEM=1; git status",
        "export HOME=/tmp/x; git commit -m x",
        "HOME=/tmp/x; git status",
        "HOME=/tmp/x bash -c 'git commit -m x'",
        "bash -c 'export HOME=/tmp/x; git commit -m x'",
        "read HOME < f; git status",
        "export $V=1",
    ]);
    allowed(&[
        "HOME=/tmp/x cargo test",
        "GIT_INDEX_FILE=/tmp/i git status",
        "GIT_INDEX_FILE=/tmp/i git commit -m x",
        "XDG_CONFIG_HOME=/tmp/c cargo test",
        "XDG_STATE_HOME=/tmp/s git status",
        "GIT_DIR=/tmp/x make",
        "export HOME=/tmp/x && cargo test",
        "GIT_AUTHOR_NAME=a git status",
        "export HOME",
        "CARGO_TARGET_DIR=/tmp/t cargo build",
    ]);
}

/// Writes into tollgate's dirs deny; reads stay open (R25).
#[test]
fn r25_tollgate_dirs() {
    denied(&[
        "tee > ~/.local/state/tollgate/results/aa/x.json",
        "echo x > $HOME/.local/state/tollgate/x",
        "echo x >> ${XDG_STATE_HOME}/tollgate/x",
        "rm -rf ~/.local/state/tollgate",
        "rm -rf ~/.local/state",
        "mv ~/.local/share/tollgate/hooks /tmp/x",
        "cp evil ~/.local/share/tollgate/bin/tollgate",
        "sed -i s/a/b/ ~/.config/tollgate/config.toml",
        "truncate -s 0 /h/.local/state/tollgate/toolcache.json",
        "cd /h/.local/state && rm -rf tollgate",
        "find ~/.local/state/tollgate -name '*.json' -delete",
        "find ~/.local/state/tollgate -exec rm {} +",
        "echo x > \"$OUT\"",
    ]);
    allowed(&[
        "grep FAIL ~/.local/state/tollgate/jobs/J/tests.log",
        "cat /h/.local/state/tollgate/jobs/x/report.json | head",
        "tail -n 50 ~/.local/state/tollgate/jobs/J/clippy.log",
        "cp ~/.local/state/tollgate/jobs/J/report.json /tmp/r.json",
        "find ~/.local/state/tollgate -name '*.json' -exec cat {} +",
        "OUT=/tmp/o.log; cargo test > \"$OUT\"",
        "cargo test > \"$TMPDIR/x.log\" 2>&1",
    ]);
    assert!(reason("rm -rf ~/.local/state/tollgate").contains("tollgate's dir"));
}

/// Ask rules that stay (R26).
#[test]
fn r26_asks() {
    asked(&[
        "git config core.hooksPath .githooks",
        "git config --global alias.ci commit",
        "git config set include.path /x",
        "git config --unset core.hooksPath",
        "git branch -m old new",
        "git branch -C a b",
        "rm .git/index.lock",
        "rm -f /w/repo/.git/worktrees/x/index.lock",
        "git config --global url.x.pushInsteadOf y",
        "git config --global core.sshCommand /tmp/f",
        "git config core.gitProxy /tmp/p",
        "git config ssh.variant simple",
        "git config --remove-section ssh",
    ]);
    allowed(&[
        "git config --get core.hooksPath",
        "git config core.hooksPath",
        "git config user.name x",
    ]);
}

/// Input the parser does not accept denies with a message (the grammar is
/// closed); the message is one line.
#[test]
fn unparseable_input_denies() {
    for cmd in ["echo 'x", "coproc cat", "echo a(b)", "if true; then echo"] {
        let why = reason(cmd);
        assert!(why.contains("cannot parse"), "{cmd}: {why}");
    }
    assert!(reason("$G commit").contains("(G1)"));
    assert!(reason("git commit -m x -- *.rs").contains("cd /abs/repo && git"));
}

#[test]
fn long_timeout_trigger_r28() {
    let c = ctx();
    for cmd in [
        "git commit -m x",
        "cd r && git push origin feat",
        "git -C r rebase main",
        "tollgate check --wait",
        "/h/.local/share/tollgate/bin/tollgate merge feat",
        "git cherry-pick abc",
        "bash -c 'git reset --hard'",
    ] {
        assert!(needs_long_timeout(&c, cmd), "{cmd}");
    }
    for cmd in [
        "ls",
        "git status",
        "git log",
        "tollgate status",
        "echo git commit",
    ] {
        assert!(!needs_long_timeout(&c, cmd), "{cmd}");
    }
}

#[test]
fn repair_commands_l8() {
    let c = ctx();
    assert!(is_repair_command(&c, "tollgate install"));
    assert!(is_repair_command(&c, "tollgate doctor --injection"));
    assert!(is_repair_command(
        &c,
        "~/.local/share/tollgate/bin/tollgate status"
    ));
    assert!(!is_repair_command(&c, "tollgate install; git commit -m x"));
    assert!(!is_repair_command(&c, "tollgate check"));
    assert!(!is_repair_command(&c, "cd x && tollgate doctor"));
    assert!(!is_repair_command(&c, "tollgate doctor $(git commit -n)"));
    assert!(!is_repair_command(&c, "git status"));
}

#[test]
fn file_rules_r26_g7() {
    let c = ctx();
    let deny = |f: &str| matches!(file_ruling(&c, f), Ruling::Deny(_));
    let ask = |f: &str| matches!(file_ruling(&c, f), Ruling::Ask(_));
    assert!(deny("/h/.local/state/tollgate/results/x.json"));
    assert!(deny("/h/.local/share/tollgate/install.json"));
    assert!(ask("/h/.config/tollgate/config.toml"));
    assert!(ask("/h/.claude/settings.json"));
    assert!(ask("/w/repo/.claude/settings.local.json"));
    for f in [
        ".git/config",
        ".git/refs/heads/main",
        "/w/repo/.git/packed-refs",
        ".git/hooks/pre-commit",
    ] {
        assert!(deny(f), "{f}");
    }
    assert!(deny(".git/config.worktree"));
    assert!(ask(".git/info/exclude"));
    // Item 21: git's global config files.
    assert!(ask("~/.gitconfig"));
    assert!(ask("/h/.config/git/config"));
    assert_eq!(file_ruling(&c, "/h/.config/gitk"), Ruling::Allow);
    assert!(ask(".githooks/pre-commit"));
    assert_eq!(file_ruling(&c, "src/main.rs"), Ruling::Allow);
    let _ = PathBuf::new();
}

/// Values bash may or may not have set: an assignment or cd in an `if`,
/// a loop, a `case` arm or after `&&`/`||` leaves the value unknown
/// after it, so neither a path nor a command name hides behind the arm
/// the guard saw last.
#[test]
fn conditional_values_are_unknown_after_the_branch() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("h");
    let state = home.join(".local/state/tollgate");
    std::fs::create_dir_all(state.join("results")).unwrap();
    std::fs::create_dir_all(tmp.path().join("w/repo")).unwrap();
    let c = ctx_at(&tmp.path().join("w/repo"), &home);
    let s = state.display().to_string();
    denied_in(
        &c,
        &[
            &format!("if true; then S={s}; else S=/tmp/x; fi; rm -rf $S"),
            &format!("S={s}; true || S=/tmp/x; rm -rf $S"),
            &format!("S={s}; false && S=/tmp/x; rm -rf $S"),
            &format!("case a in a) S={s};; b) S=/tmp/x;; esac; rm -rf $S"),
            &format!("for i in 1; do S={s}; done; S2=$S; rm -rf $S2"),
            &format!("cd {s}; true || cd /tmp; rm -rf results"),
            &format!("cd {s} && true || cd /tmp; rm -rf results"),
            &format!("cd {s} && grep -q x f || cd /tmp; rm -rf results"),
            "if true; then G=git; else G=echo; fi; $G commit -n -m x",
            "G=echo; grep -q x f || G=git; $G commit -n -m x",
            "G=echo; true && G=git; $G commit -n -m x",
            "G=git; false && G=echo; $G commit -n -m x",
        ],
    );
    allowed_in(
        &c,
        &[
            "S=/tmp/x; true && echo ok; rm -rf $S",
            "if true; then S=/tmp/a; else S=/tmp/a; fi; rm -rf $S",
        ],
    );
}

/// Values the walk can know (G1, G8): a command name or path from a
/// variable this command set literally, and a `mktemp` result; everything
/// that can change a variable behind the walk's back makes it unknown:
/// function calls and bodies, namerefs, `mapfile`, `read -a`, `printf -v`,
/// traps, `IFS`. A shell that would run startup code is denied.
#[test]
fn literal_values_and_what_unknowns_them() {
    use std::os::unix::fs::PermissionsExt as _;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("h");
    let state = home.join(".local/state/tollgate");
    std::fs::create_dir_all(state.join("results")).unwrap();
    let repo = tmp.path().join("w/repo");
    std::fs::create_dir_all(&repo).unwrap();
    let script = tmp.path().join("run.sh");
    std::fs::write(&script, "#!/bin/sh\necho ok\n").unwrap();
    let c = ctx_at(&repo, &home);
    let s = state.display().to_string();
    let t = tmp.path().display().to_string();
    allowed_in(
        &c,
        &[
            &format!("S={t}; $S/run.sh"),
            &format!("S={t}; \"$S/run.sh\" a b"),
            "B=/usr/bin/true; $B",
            "T=$(mktemp -d) && echo x > $T/a && rm -rf \"$T\"",
            "tmp=$(mktemp); trap 'rm -f \"$tmp\"' EXIT; echo x > \"$tmp\"",
            "T=\"$(mktemp -d -t x.XXXX)\"; cp a \"$T/\"; rm -rf \"$T\"",
            "unset X; echo $X",
        ],
    );
    let np = tmp.path().join("np");
    std::fs::create_dir_all(&np).unwrap();
    std::fs::set_permissions(&np, std::fs::Permissions::from_mode(0o000)).unwrap();
    let in_state = ctx_at(&state, &home);
    let mut cmds = vec![
        "G=git; $G commit -n -m x".to_owned(),
        "G=gi; ${G}t commit -n -m x".to_owned(),
        "IFS=/; S=/a/b; rm -rf $S".to_owned(),
        format!("T=$(mktemp -d -p {s}) && rm -rf $T/../results"),
        format!("T=$(mktemp -d --tmpdir={s}) && rm -rf $T"),
        format!("TMPDIR={s}; T=$(mktemp -d); rm -rf $T/../results"),
        format!("T=$(TMPDIR={s} mktemp -d); rm -rf $T/../results"),
        format!("S=/tmp/x; trap 'rm -rf $S' EXIT; S={s}"),
        format!("S=/tmp/x; trap 'rm -rf $S' EXIT; f() {{ :; }}; f"),
        format!("trap 'S={s}' DEBUG; S=/tmp/x; rm -rf $S"),
        format!("f() {{ S={s}; }}; S=/tmp/x; f; rm -rf $S"),
        format!("S=/tmp/x; f() {{ rm -rf $S; }}; S={s}; f"),
        "S=/tmp/x; mapfile S < f; rm -rf $S".to_owned(),
        "S=/tmp/x; read -a S <<< y; rm -rf $S".to_owned(),
        format!("S=/tmp/x; declare -n r=S; r={s}; rm -rf $S"),
        format!("S=/tmp/x; printf -v S %s {s}; rm -rf $S"),
        "S=/tmp/x; (( S = 1 )); rm -rf $S".to_owned(),
        "BASH_ENV=/tmp/e.sh bash -c true".to_owned(),
        "export BASH_ENV=/tmp/e.sh".to_owned(),
        "ENV=/tmp/e.sh sh -i".to_owned(),
    ];
    denied_in(&c, &cmds.iter().map(String::as_str).collect::<Vec<_>>());
    cmds.clear();
    // `cd` into a dir it cannot search fails, and the shell stays where
    // it was (root can search any dir).
    if unsafe { libc::geteuid() } != 0 {
        cmds.push(format!("cd {}; rm -rf results", np.display()));
        cmds.push(format!("cd {} || true; rm -rf results", np.display()));
    }
    denied_in(
        &in_state,
        &cmds.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    std::fs::set_permissions(&np, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn tmp_probe() {
    for cmd in [
        "W=/usr/bin/true; $W catalog | grep x",
        "W=/usr/bin/true; $W check",
        "cd /tmp && W=/usr/bin/true; $W check",
        "cd /tmp && W=/usr/bin/true && $W check",
    ] {
        eprintln!("{cmd} -> {:?}", bash_ruling(&ctx(), cmd));
    }
}

/// Item 35, review note 12: a Bash or Write call that changes what gate
/// jobs run or read as host tool config asks a person, in every write
/// form the guard knows; reads, removals and new dirs do not.
#[test]
fn tool_writes_ask_item35() {
    asked(&[
        "printf '[target.x86_64-unknown-linux-gnu]\\nrunner = \"true\"\\n' >> ~/.cargo/config.toml",
        "printf x > \"$HOME\"/.cargo/config",
        "echo x >| /h/.cargo/config.toml",
        "cp /bin/true ~/.cargo/bin/cargo",
        "cp -t ~/.cargo/bin /bin/true",
        "install -m 755 /bin/true /h/.cargo/bin/cargo-nextest",
        "ln -sf /bin/true ~/.local/bin/cargo",
        "ln -s ~/.cargo /tmp/c",
        "cd ~/.local/bin && ln -sf /bin/true uv",
        "cd /h/.local && cp /bin/true bin/bun",
        "mv /tmp/x ~/.bun/bin/bun",
        "mv ~/.cargo ~/.cargo.bak",
        "echo x | tee -a ~/.rustfmt.toml",
        "sed -i s/a/b/ ~/.config/rustfmt/rustfmt.toml",
        "truncate -s 0 ~/rustfmt.toml",
        "cp -r /tmp/evil/. ~/.local",
        "cp -r /tmp/.cargo ~",
        "chmod +x ~/.local/bin/x",
        "cp x ~/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/rustc",
        "cp x ~/.rustup/settings.toml",
        "cp x ~/.cargo/registry/src/index/serde-1.0.0/src/lib.rs",
        "cp x ~/.cache/uv/archive-v0/a/b.py",
        "cp x ~/.local/share/uv/python/cpython/bin/python3",
        "cp x ~/.LOCAL/bin/cargo",
    ]);
    for ok in [
        "cat ~/.cargo/config.toml",
        "ls ~/.local/bin > /tmp/list",
        "rm -rf ~/.cargo/registry/cache",
        "rm ~/.local/bin/old-tool",
        "mkdir -p ~/.local/bin",
        "touch ~/.cargo/config.toml",
        "cp x ~/.local/share/applications/x.desktop",
        "cp x ~/.config/kitty/kitty.conf",
        "echo x > ~/notes.txt",
    ] {
        assert_eq!(ruling(ok), Ruling::Allow, "{ok}");
    }
    assert!(reason("cp /bin/true ~/.cargo/bin/cargo").contains("gate jobs run"));
    let c = ctx();
    for f in [
        "~/.cargo/config.toml",
        "/h/.cargo/bin/cargo",
        "/h/.local/bin/cargo",
        "/h/.rustfmt.toml",
        "/h/.config/rustfmt/rustfmt.toml",
        "/h/.rustup/settings.toml",
    ] {
        assert!(matches!(file_ruling(&c, f), Ruling::Ask(_)), "{f}");
    }
    assert_eq!(
        file_ruling(&c, "/h/.config/kitty/kitty.conf"),
        Ruling::Allow
    );
}

/// git in `dir` with no user or system config.
fn git_in(dir: &Path, args: &[&str]) {
    let out = std::process::Command::new("git")
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(["-c", "user.name=t", "-c", "user.email=t@t"])
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {out:?}");
}

/// Item 22, secreview note 7: a fetch or push reaches the local repo in
/// every spelling git reads as it: `./`, `.git`, `..` from a subdir, the
/// absolute path, a `file://` URL, a symlink, another worktree, a path
/// that is not a remote name, and a remote, `insteadOf` or `pushurl`
/// that points there. Destinations count in every spelling git expands
/// (`heads/main`, `remotes/origin/main`, `origin/main`, globs, full names
/// of full refs), and so do pushes whose refspecs come from config.
#[test]
fn item_22_local_repo_in_every_spelling() {
    let tmp = tempfile::tempdir().unwrap();
    let w = std::fs::canonicalize(tmp.path()).unwrap().join("w");
    let repo = w.join("repo");
    let other = w.join("other");
    std::fs::create_dir_all(repo.join("sub")).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    let r = repo.display().to_string();
    let wd = w.display().to_string();
    git_in(&repo, &["init", "-q", "-b", "feat"]);
    git_in(&repo, &["commit", "-q", "--allow-empty", "-m", "x"]);
    let oid = std::fs::read_to_string(repo.join(".git/refs/heads/feat")).unwrap();
    std::fs::create_dir_all(repo.join(".git/refs/remotes/origin")).unwrap();
    std::fs::write(repo.join(".git/refs/remotes/origin/main"), &oid).unwrap();
    git_in(
        &repo,
        &["remote", "add", "origin", "git@gitlab.com:v/r.git"],
    );
    git_in(&repo, &["remote", "add", "mirror", &r]);
    git_in(
        &repo,
        &["config", "remote.pl.url", "git@gitlab.com:v/r.git"],
    );
    git_in(&repo, &["config", "remote.pl.pushurl", "."]);
    git_in(&repo, &["config", &format!("url.{wd}/.insteadOf"), "gl:"]);
    git_in(
        &repo,
        &["config", &format!("url.{wd}/.pushInsteadOf"), "gp:"],
    );
    git_in(&repo, &["config", "branch.feat.remote", "."]);
    git_in(&repo, &["config", "branch.feat.merge", "refs/heads/main"]);
    git_in(
        &repo,
        &["worktree", "add", "-q", "-b", "wtb", &format!("{wd}/wt")],
    );
    std::os::unix::fs::symlink(&repo, w.join("link")).unwrap();
    git_in(&other, &["init", "-q", "-b", "feat"]);
    git_in(
        &other,
        &["remote", "add", "origin", "git@gitlab.com:v/o.git"],
    );
    git_in(&other, &["config", "branch.feat.remote", "origin"]);
    git_in(&other, &["config", "branch.feat.merge", "refs/heads/main"]);

    let home = w.join("h");
    let mut c = ctx_at(&repo, &home);
    c.git_env = crate::env::EnvSnapshot::from_pairs([
        ("HOME", home.display().to_string()),
        ("GIT_CONFIG_NOSYSTEM", "1".to_owned()),
    ]);
    let open = |c: &Context, cmds: &[String]| -> Vec<String> {
        cmds.iter()
            .filter(|cmd| !matches!(bash_ruling(c, cmd), Ruling::Deny(_)))
            .map(|cmd| format!("{cmd} -> {:?}", bash_ruling(c, cmd)))
            .collect()
    };
    let deny: Vec<String> = [
        "git push ./ x:main",
        "git push {r} x:main",
        "git push {r}/ x:main",
        "git push {r}/.git x:main",
        "git push {r}/sub/.. x:main",
        "git push .git HEAD:main",
        "git push sub/.. HEAD:main",
        "git push file://{r} x:main",
        "git push file://{w}/%72epo x:main",
        "git push {w}/link x:main",
        "git push {w}/wt x:main",
        "git push {w}/new x:main",
        "ln -s {r} {w}/new && git push {w}/new x:main",
        "mv {w}/other {w}/o2 && ln -s {r} {w}/other && git push {w}/other x:main",
        "git push {w}/./repo x:main",
        "git push {w}/other/../repo x:main",
        "git push ~/../repo x:main",
        "git push ~bob/repo x:main",
        "git push fd::3 x:main",
        "git push repo2 x:main",
        "git push mirror x:main",
        "git push pl x:main",
        "git push gl:repo x:main",
        "git push gp:repo x:main",
        "git push --rep origin . x:main",
        "git push --recurse-submodules origin . x:main",
        "git push --bogus origin . x:main",
        "git push -d . main",
        "git push . main",
        "git push . heads/main",
        "git push . x:heads/main",
        "git push . x:remotes/origin/main",
        "git push . x:origin/main",
        "git push . x:origin",
        "git push . 'refs/heads/x-*:refs/heads/*'",
        "git push . x:refs/heads/integration/a",
        "git push . x:INTEGRATION/a",
        "git push --all .",
        "git push --branches .",
        "git push --mirror ./",
        "git push .",
        "git push --repo=.",
        "git push",
        "git fetch .git x:main",
        "git fetch repo2 x:main",
        "git fetch file://{r} x:main",
        "git fetch mirror x:main",
        "git fetch gl:repo x:main",
        "git fetch . x:heads/main",
        "git fetch . x:remotes/origin/main",
        "git fetch origin x:remotes/origin/main",
        "git fetch . 'refs/tags/*:refs/heads/*'",
        "git fetch . x:refs/heads/integration/a",
        "git fetch --refm=refs/heads/x:refs/heads/main . x",
        "git fetch --stdin . <<< x:main",
        "git fetch --depth 1 . x:main",
        "git pull . x:main",
        "git pull .git x:main",
        "git pull --refmap=refs/heads/x:refs/heads/main . x",
    ]
    .iter()
    .map(|s| s.replace("{r}", &r).replace("{w}", &wd))
    .collect();
    let bad = open(&c, &deny);
    assert!(bad.is_empty(), "not denied:\n{}", bad.join("\n"));
    // Denied for what the push or fetch writes, not for a step before it.
    let other_reason: Vec<String> = deny
        .iter()
        .filter(|cmd| !cmd.contains("<<<"))
        .filter_map(|cmd| match bash_ruling(&c, cmd) {
            Ruling::Deny(m)
                if m.contains("git push") || m.contains("git fetch") || m.contains("git pull") =>
            {
                None
            }
            r => Some(format!("{cmd} -> {r:?}")),
        })
        .collect();
    assert!(other_reason.is_empty(), "{}", other_reason.join("\n"));
    let sub = ctx_at(&repo.join("sub"), &home);
    let sub = Context {
        git_env: c.git_env.clone(),
        ..sub
    };
    let bad = open(
        &sub,
        &[
            "git push .. HEAD:main".to_owned(),
            "git -C .. push . HEAD:main".to_owned(),
            "git -C .. fetch repo x:main".to_owned(),
            "git fetch ../.git x:main".to_owned(),
        ],
    );
    assert!(bad.is_empty(), "not denied:\n{}", bad.join("\n"));

    let allow: Vec<String> = [
        "git push origin main",
        "git push origin feat:main",
        "git push origin x:refs/heads/main",
        "git push -u origin feat",
        "git push origin",
        "git push origin 'refs/heads/*:refs/heads/*'",
        "git push {w}/other main",
        "git push . feat:other",
        "git push . x:feat/a",
        "git push mirror feat:other",
        "git fetch origin",
        "git fetch origin main:main",
        "git fetch pl x:main",
        "git fetch gp:repo x:main",
        "git fetch . x:feat",
        "git fetch repo2 x:feat",
        "git pull origin main",
        "git pull --ff-only",
    ]
    .iter()
    .map(|s| s.replace("{r}", &r).replace("{w}", &wd))
    .collect();
    for cmd in &allow {
        assert_eq!(bash_ruling(&c, cmd), Ruling::Allow, "{cmd}");
    }
    let o = Context {
        git_env: c.git_env.clone(),
        ..ctx_at(&other, &home)
    };
    allowed_in(&o, &["git push", "git push origin"]);

    // Packed remote-tracking refs count as loose ones do.
    git_in(&other, &["commit", "-q", "--allow-empty", "-m", "x"]);
    git_in(&other, &["update-ref", "refs/remotes/up/x", "HEAD"]);
    git_in(&other, &["pack-refs", "--all"]);
    denied_in(&o, &["git push . HEAD:up/y", "git push . HEAD:up/x"]);
    allowed_in(&o, &["git push . HEAD:feat/y"]);

    // A config the guard cannot read without git (an include): a remote
    // name may point here, so only refspecs that move no anchor pass.
    std::fs::write(
        repo.join(".git/config"),
        format!(
            "{}[include]\n\tpath = more\n",
            std::fs::read_to_string(repo.join(".git/config")).unwrap()
        ),
    )
    .unwrap();
    denied_in(&c, &["git push origin main", "git push", "git push origin"]);
    allowed_in(&c, &["git push origin feat", "git push origin feat:other"]);
}

/// Item 21 review (R26): Bash writes of Claude Code settings ask, as
/// Write/Edit does, in the user dir (`~/.claude`, `$CLAUDE_CONFIG_DIR`)
/// and in a project's `.claude`; globs and braces there deny (G8).
#[test]
fn item_21_review_settings_writes_ask_r26() {
    let mut c = ctx();
    c.vars.push(("CLAUDE_CONFIG_DIR".into(), "/cfg".into()));
    for cmd in [
        "printf x > /cfg/settings.json",
        "printf x > $CLAUDE_CONFIG_DIR/settings.local.json",
        "rm -rf /cfg",
        "cp -r x/. /cfg",
        "mv /cfg /x",
        "printf x > /h/.claude/settings.local.json",
        "printf x > ~/.CLAUDE/Settings.JSON",
        "printf x > /w/repo/.claude/settings.json",
        "cd sub/.. && printf x > .claude/settings.local.json",
        "mv /h/.claude /tmp/c",
        "cd /h && cp -r /tmp/x/. .",
        "chmod 000 /h/.claude/settings.json",
        "git config --file .claude/settings.json a.b c",
        "git -C /h config --file .claude/settings.json a.b c",
    ] {
        assert!(
            matches!(bash_ruling(&c, cmd), Ruling::Ask(_)),
            "not asked: {cmd:?} -> {:?}",
            bash_ruling(&c, cmd)
        );
    }
    for f in [
        "/cfg/settings.json",
        "/cfg/settings.local.json",
        ".claude/settings.local.json",
        "~/.claude/settings.json",
    ] {
        assert!(matches!(file_ruling(&c, f), Ruling::Ask(_)), "{f}");
    }
    denied_in(
        &c,
        &[
            "printf x > ~/.claude/setting?.json",
            "cp x ~/.claude/{settings,a}.json",
            "rm ~/.claude/*",
        ],
    );
    allowed_in(
        &c,
        &[
            "printf x > /cfg/notes.md",
            "cat /cfg/settings.json /h/.claude/settings.json",
            "mkdir -p /w/repo/.claude /cfg",
            "touch /h/.claude/settings.json",
            "printf x > /w/repo/settings.json",
            "printf x > /w/repo/.claude/commands.md",
        ],
    );
}
