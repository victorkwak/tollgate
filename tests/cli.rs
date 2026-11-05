//! The binary's dispatch and exit codes, run as a real process.

mod support;

use std::path::Path;
use std::process::{Command, Output};

use support::Sandbox;

const BIN: &str = env!("CARGO_BIN_EXE_tollgate");

/// Runs `program` with an empty environment except PATH and a temp HOME/XDG,
/// so nothing can reach the real ~/.config, ~/.local or ~/.claude.
fn run(program: &Path, args: &[&str], home: &Path) -> Output {
    Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env("XDG_DATA_HOME", home.join("data"))
        .output()
        .expect("run tollgate")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn hook_hard_link_dispatches_on_argv0_and_denies_until_built_r1_r31() {
    // Hard links need the same filesystem as the binary.
    let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let link = tmp.path().join("pre-commit");
    std::fs::hard_link(BIN, &link).unwrap();
    let out = run(&link, &[], tmp.path());
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("DENIED pre-commit"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn hook_subcommand_dispatches_by_name() {
    let tmp = tempfile::tempdir().unwrap();
    let out = run(
        Path::new(BIN),
        &["hook", "pre-push", "origin", "url"],
        tmp.path(),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("DENIED pre-push"), "{}", stderr(&out));
}

#[test]
fn reference_transaction_is_not_a_known_hook_l1() {
    let tmp = tempfile::tempdir().unwrap();
    let out = run(
        Path::new(BIN),
        &["hook", "reference-transaction", "prepared"],
        tmp.path(),
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("unknown hook"), "{}", stderr(&out));
}

#[test]
fn guard_blocks_until_built_r23() {
    let tmp = tempfile::tempdir().unwrap();
    let out = run(Path::new(BIN), &["guard"], tmp.path());
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn cut_commands_do_not_exist_l14() {
    let tmp = tempfile::tempdir().unwrap();
    for cut in ["pick", "waive", "policy"] {
        let out = run(Path::new(BIN), &[cut], tmp.path());
        assert_eq!(out.status.code(), Some(2), "{cut}");
        assert!(stderr(&out).contains("unrecognized subcommand"), "{cut}");
    }
}

#[test]
fn version_and_help_exit_zero() {
    let tmp = tempfile::tempdir().unwrap();
    for args in [&["--version"][..], &["--help"][..]] {
        let out = run(Path::new(BIN), args, tmp.path());
        assert_eq!(out.status.code(), Some(0), "{args:?}");
    }
}

/// Runs the binary in `cwd` with the sandbox environment only.
fn run_in(sb: &Sandbox, cwd: &Path, args: &[&str]) -> (Option<i32>, String) {
    let mut cmd = Command::new(BIN);
    cmd.env_clear().current_dir(cwd).args(args);
    for (k, v) in sb.env().iter() {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code(), text)
}

#[test]
fn config_check_validates_repo_and_host_config_r64() {
    let sb = Sandbox::new();
    let repo = sb.repo("r");
    std::fs::create_dir_all(repo.join("sub")).unwrap();

    let (code, text) = run_in(&sb, &repo.join("sub"), &["config", "--check"]);
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains("absent: defaults") && text.contains("no tollgate.toml"),
        "{text}"
    );

    std::fs::write(
        repo.join("tollgate.toml"),
        "version = 1\n[[step]]\nname = \"tests\"\nkind = \"nextest\"\nresources = [\"cpu\", \"minio\"]\n",
    )
    .unwrap();
    let (code, text) = run_in(&sb, &repo, &["config", "--check"]);
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains("warning: tollgate.toml") && text.contains("resource minio"),
        "{text}"
    );
    assert!(text.trim_end().ends_with("ok"), "{text}");

    std::fs::write(
        repo.join("tollgate.toml"),
        "version = 1\n[[step]]\nname = \"a\"\nkind = \"command\"\n",
    )
    .unwrap();
    let (code, text) = run_in(&sb, &repo, &["config", "--check"]);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("needs run"), "{text}");

    std::fs::write(repo.join("tollgate.toml"), "version = 1\nbogus = 1\n").unwrap();
    let (code, text) = run_in(&sb, &repo, &["config", "--check"]);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("bogus"), "{text}");

    std::fs::remove_file(repo.join("tollgate.toml")).unwrap();
    let host = sb.root().join("config/tollgate/config.toml");
    std::fs::create_dir_all(host.parent().unwrap()).unwrap();
    std::fs::write(&host, "[verify]\nslots = { fast = 0 }\n").unwrap();
    let (code, text) = run_in(&sb, &repo, &["config", "--check"]);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("error: host config: verify.slots"), "{text}");

    let (code, text) = run_in(&sb, &sb.root(), &["config", "--check"]);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("not in a git repository"), "{text}");
}
