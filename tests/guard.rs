//! The PreToolUse guard as Claude Code runs it: the installed copy, JSON on
//! stdin, exit 0 or 2 (T5, T15-T17, R23-R28, L8, L17-L19).

mod support;

use std::io::Write as _;
use std::path::Path;
use std::process::Stdio;

use support::{Armed, BIN, write_exe};

#[test]
fn deny_patterns_exit_2_and_reads_stay_open_t15_r23_r25() {
    let a = Armed::new();
    let state = a.sb.root().join("state/tollgate");
    for cmd in [
        "git commit --no-verify -m x".to_owned(),
        "git -c core.hookspath=/dev/null commit -m x".to_owned(),
        "git -c include.path=/tmp/x commit".to_owned(),
        "git --config-env=core.hooksPath=X commit".to_owned(),
        "git send-pack origin main".to_owned(),
        "git branch -M x main".to_owned(),
        "tollgate waive --tree x".to_owned(),
        format!("echo x | tee > {}/jobs/J/report.json", state.display()),
        "echo x > $XDG_STATE_HOME/tollgate/x".to_owned(),
        "rm -rf ~/../state/tollgate".to_owned(),
        "cd x && git commit -n -m y".to_owned(),
        // git takes unambiguous prefixes of long options (R25).
        "git commit --no-verif -m x".to_owned(),
        "git push --no-ver origin feat".to_owned(),
        "git am --no-v a.patch".to_owned(),
        // Every way to start git with an empty environment (R25).
        "env --ignore-environment PATH=/usr/bin git commit -m x".to_owned(),
        "env - PATH=/usr/bin git commit -m x".to_owned(),
        "env -S '-i git commit -m x'".to_owned(),
        "exec -c git commit -m x".to_owned(),
        // HOME and XDG decide where tollgate finds its config (R8).
        "HOME=/tmp/x git commit -m x".to_owned(),
        "XDG_CONFIG_HOME=/tmp/c git commit -m x".to_owned(),
        // In-place edits and git config --file write the file (R25).
        "perl -pi -e 's/a/b/' $XDG_STATE_HOME/tollgate/x".to_owned(),
        "gawk -i inplace 1 $XDG_STATE_HOME/tollgate/x".to_owned(),
        "git config --file $XDG_STATE_HOME/tollgate/x a.b c".to_owned(),
        "git config --file \"$F\" a.b c".to_owned(),
    ] {
        let (code, out, err) = a.bash(&cmd);
        assert_eq!(code, Some(2), "{cmd}: {out}{err}");
        assert!(err.starts_with("tollgate guard: denied:"), "{cmd}: {err}");
        assert_eq!(err.trim().lines().count(), 1, "one line: {err}");
    }
    for cmd in [
        format!("grep FAIL {}/jobs/J/tests.log", state.display()),
        "grep FAIL $XDG_STATE_HOME/tollgate/jobs/J/tests.log".to_owned(),
        "ls -la".to_owned(),
    ] {
        let (code, out, err) = a.bash(&cmd);
        assert_eq!((code, out.as_str()), (Some(0), ""), "{cmd}: {err}");
    }
    // Values glued to -u and -S are not -n: allowed, with the R28 rewrite.
    for cmd in ["git commit -uno -m x", "git commit -Snone -m x"] {
        let (code, out, err) = a.bash(cmd);
        assert_eq!(code, Some(0), "{cmd}: {err}");
        assert!(out.contains("updatedInput"), "{cmd}: {out}");
        assert!(!out.contains("permissionDecision"), "{cmd}: {out}");
    }
    // Malformed input and a forced panic block (R23).
    for input in [
        "not json",
        "{}",
        "{\"tool_name\": \"Bash\", \"tool_input\": {}}",
    ] {
        assert_eq!(a.guard_raw(input, &[]).0, Some(2), "{input}");
    }
    let (code, _, err) = a.bash_with("ls", &[("TOLLGATE_TEST_PANIC", "guard")]);
    assert_eq!(code, Some(2), "{err}");
}

#[test]
fn ask_rules_return_an_ask_decision_t16_r26() {
    let a = Armed::new();
    let repo = a.sb.repo("r");
    let ask = |out: &str| {
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap_or_default();
        v["hookSpecificOutput"]["permissionDecision"] == "ask"
    };
    for cmd in [
        "git config core.hooksPath .githooks",
        "rm .git/index.lock",
        "git branch -m a b",
        "git config url./tmp/fake.git.insteadOf git@gitlab.example:v/r.git",
    ] {
        let (code, out, err) = a.bash(cmd);
        assert_eq!(code, Some(0), "{cmd}: {err}");
        assert!(ask(&out), "{cmd}: {out}");
    }
    for file in [
        repo.join("tollgate.toml"),
        repo.join(".config/nextest.toml"),
        a.sb.home.join(".claude/settings.json"),
        repo.join(".git/info/exclude"),
        a.sb.root().join("config/tollgate/config.toml"),
    ] {
        let (code, out, err) = a.write(file.to_str().unwrap());
        assert_eq!(code, Some(0), "{}: {err}", file.display());
        assert!(ask(&out), "{}: {out}", file.display());
    }
    // G7: refs, remote config and hooks under .git deny.
    for file in [
        repo.join(".git/config"),
        repo.join(".git/refs/heads/main"),
        repo.join(".git/hooks/pre-commit"),
    ] {
        let (code, _, err) = a.write(file.to_str().unwrap());
        assert_eq!(code, Some(2), "{}: {err}", file.display());
    }
    let (code, _, err) = a.write(
        a.sb.root()
            .join("state/tollgate/results/x.json")
            .to_str()
            .unwrap(),
    );
    assert_eq!(code, Some(2), "{err}");
    let (code, out, _) = a.write(repo.join("src/lib.rs").to_str().unwrap());
    assert_eq!((code, out.as_str()), (Some(0), ""));
}

#[test]
fn waiting_commands_get_the_long_timeout_and_the_cap_t17_r28_l17() {
    let a = Armed::new();
    let (code, out, err) = a.bash("cd r && git commit -m x");
    assert_eq!(code, Some(0), "{err}");
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    let u = &v["hookSpecificOutput"]["updatedInput"];
    assert_eq!(u["timeout"], 600_000);
    assert_eq!(
        u["command"],
        "export TOLLGATE_INLINE_CAP=540; cd r && git commit -m x"
    );
    assert_eq!(u["description"], "d");
    assert!(
        v["hookSpecificOutput"].get("permissionDecision").is_none(),
        "{v}"
    );
    // In the background: the fast budget.
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {"command": "tollgate check --wait", "run_in_background": true},
    });
    let (_, out, _) = a.guard_raw(&input.to_string(), &[]);
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(
        v["hookSpecificOutput"]["updatedInput"]["command"],
        "export TOLLGATE_INLINE_CAP=1200; tollgate check --wait"
    );
    let (code, out, _) = a.bash("ls");
    assert_eq!((code, out.as_str()), (Some(0), ""));
}

#[test]
fn an_unarmed_gate_denies_every_bash_call_and_repairs_links_t5_r24_l8_l18() {
    let a = Armed::new();
    assert_eq!(a.bash("ls").0, Some(0));
    let hooks = a.data().join("hooks");
    let log = a.sb.root().join("state/tollgate/repairs.log");
    // L18: a missing link and a missing hooks dir are repaired.
    std::fs::remove_file(hooks.join("pre-push")).unwrap();
    assert_eq!(a.bash("ls").0, Some(0));
    assert!(hooks.join("pre-push").exists());
    std::fs::remove_dir_all(&hooks).unwrap();
    assert_eq!(a.bash("ls").0, Some(0));
    assert!(hooks.join("pre-commit").exists());
    let lines = std::fs::read_to_string(&log).unwrap();
    assert_eq!(lines.lines().count(), 2, "{lines}");
    // A dangling symlink is repaired too.
    std::fs::remove_file(hooks.join("post-merge")).unwrap();
    std::os::unix::fs::symlink("/nonexistent/tollgate", hooks.join("post-merge")).unwrap();
    assert_eq!(a.bash("ls").0, Some(0));
    // A hook with another inode is not ours to replace: deny every call.
    std::fs::remove_file(hooks.join("post-merge")).unwrap();
    write_exe(&hooks.join("post-merge"), "#!/bin/sh\nexit 0\n");
    let (code, _, err) = a.bash("ls");
    assert_eq!(code, Some(2), "{err}");
    assert!(
        err.contains("gate not armed") && err.contains("post-merge"),
        "{err}"
    );
    // L8: the repair commands still run.
    assert_eq!(a.bash("tollgate doctor").0, Some(0));
    assert_eq!(a.bash(&format!("{} install", a.bin().display())).0, Some(0));
    assert_eq!(a.bash("tollgate doctor; rm -rf x").0, Some(2));
    // `tollgate install` fixes it.
    assert_eq!(a.install().0, Some(0));
    assert_eq!(a.bash("ls").0, Some(0));
    // A wrong injection value in the session env denies (no repair).
    let (code, _, err) = a.bash_with("ls", &[("GIT_CONFIG_VALUE_0", "/elsewhere")]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("GIT_CONFIG_VALUE_0"), "{err}");
    let input =
        serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "ls"}}).to_string();
    let mut child = a
        .cmd(&a.bin(), &["guard"], &[])
        .env_remove("GIT_CONFIG_COUNT")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    assert_eq!(child.wait_with_output().unwrap().status.code(), Some(2));
    // A guard that is not the installed copy denies.
    let mut child = a
        .cmd(Path::new(BIN), &["guard"], &[])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    assert_eq!(child.wait_with_output().unwrap().status.code(), Some(2));
    // No install record at all: deny.
    std::fs::remove_file(a.data().join("install.json")).unwrap();
    assert_eq!(a.bash("ls").0, Some(2));
}
