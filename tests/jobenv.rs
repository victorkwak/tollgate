//! T26 (R52): a step process sees the allowlist only, run as a real process.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use tollgate::config::host::JobConfig;
use tollgate::dirs::Dirs;
use tollgate::env::EnvSnapshot;
use tollgate::runner::env::{BaseInputs, JobEnv};

#[test]
fn step_process_sees_only_the_allowlist_r52_t26() {
    let tmp = tempfile::tempdir().unwrap();
    // The hook's environment as an agent shell would leave it.
    let hook_env = EnvSnapshot::capture()
        .with("HOME", tmp.path())
        .with("GIT_DIR", "/agent/.git")
        .with("GIT_INDEX_FILE", "/agent/.git/index.lock")
        .with("GIT_CONFIG_COUNT", "1")
        .with("GIT_CONFIG_KEY_0", "core.hooksPath")
        .with("GIT_CONFIG_VALUE_0", "/hooks")
        .with("GIT_CONFIG_PARAMETERS", "'core.hookspath'='/x'")
        .with("GUARD_EVAL_ONLY", "1")
        .with("GATEHOUSE_MODE", "eval");
    let dirs = Dirs::from_env(&hook_env).unwrap();
    let job = JobConfig::default();
    let tmpdir = tmp.path().join("jobs/j/tmp");
    std::fs::create_dir_all(&tmpdir).unwrap();
    let env = JobEnv::base(&BaseInputs {
        env: &hook_env,
        dirs: &dirs,
        job: &job,
        tmpdir: &tmpdir,
    })
    .unwrap();

    let mut cmd = Command::new("env");
    env.apply(&mut cmd).current_dir(Path::new("/"));
    let out = cmd.output().expect("run env");
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let seen: BTreeSet<&str> = text
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, _)| k))
        .collect();
    let expected: BTreeSet<&str> = env.iter().map(|(k, _)| k.to_str().unwrap()).collect();
    assert_eq!(seen, expected, "env output:\n{text}");
    assert!(!seen.iter().any(|k| k.starts_with("GIT_")), "{text}");
    assert!(!seen.contains("GUARD_EVAL_ONLY") && !seen.contains("GATEHOUSE_MODE"));
    // cargo sets CARGO_* for the test process; none may leak.
    assert!(!seen.contains("CARGO_MANIFEST_DIR"));
    assert!(text.contains("TOLLGATE=1"));
    assert!(text.contains(&format!("TMPDIR={}", tmpdir.display())));
}
