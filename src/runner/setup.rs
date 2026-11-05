//! Setup steps (R45, R46, R70).
//!
//! A `[[setup]]` step runs in the verify checkout after R42 when the blob
//! ids of its `when` paths (or its command, cwd or env) differ from its last
//! successful run in this checkout, kept in the checkout's meta file. A
//! failed setup is verdict `error`, cause `setup`.
//!
//! Setup outputs must live in dirs `git clean` keeps (`node_modules`,
//! `.venv`, `target`, the steps' `cache_dirs`, R42): anything else is
//! removed before the next job while the setup counts as up to date.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::config::glob::{self, GlobOpts};
use crate::config::repo::SetupStep;
use crate::gitx::TreeEntry;
use crate::runner::env::JobEnv;
use crate::runner::exec::{self, ExecEnd, ExecSpec};

/// The hash that decides a re-run: the step definition and the `(path,
/// blob)` of the tree entries its `when` globs match.
pub fn input_hash(step: &SetupStep, entries: &[TreeEntry]) -> Result<String, String> {
    let when = glob::compile(
        &step.when,
        GlobOpts {
            case_insensitive: false,
            literal_separator: false,
        },
    )?;
    let mut h = blake3::Hasher::new();
    h.update(&serde_json::to_vec(step).map_err(|e| e.to_string())?);
    for e in entries.iter().filter(|e| when.is_match(&e.path)) {
        h.update(e.path.as_os_str().as_encoded_bytes());
        h.update(b"\0");
        h.update(e.oid.as_str().as_bytes());
        h.update(b"\0");
    }
    Ok(h.finalize().to_hex().to_string())
}

/// One setup step's result.
#[derive(Debug)]
pub enum SetupResult {
    /// Inputs unchanged since the last success: not run.
    UpToDate,
    /// Ran and passed.
    Ran(Duration),
    /// Failed: the message for the report.
    Failed(String),
    /// The abort callback stopped it.
    Aborted(String),
}

/// Runs `step` in `checkout` unless `last` equals `hash`.
#[allow(clippy::too_many_arguments)]
pub fn run(
    step: &SetupStep,
    hash: &str,
    last: Option<&str>,
    checkout: &Path,
    env: &JobEnv,
    log: &Path,
    deadline: Option<Instant>,
    abort: &mut dyn FnMut() -> Option<String>,
    inherit: &[std::os::fd::RawFd],
) -> SetupResult {
    if last == Some(hash) {
        return SetupResult::UpToDate;
    }
    let env = match env.for_step(&step.env, None) {
        Ok(e) => e,
        Err(e) => return SetupResult::Failed(e.to_string()),
    };
    let cwd = checkout.join(step.cwd.as_deref().unwrap_or(""));
    let limit = Instant::now() + step.timeout();
    let deadline = Some(deadline.map_or(limit, |d| d.min(limit)));
    let out = exec::run(ExecSpec {
        program: "sh".into(),
        args: vec!["-c".into(), step.run.clone().into()],
        cwd: &cwd,
        env: &env,
        log,
        stdout: None,
        deadline,
        grace: Duration::from_secs(10),
        abort,
        inherit,
    });
    match out.end {
        ExecEnd::Exited(s) if s.success() => SetupResult::Ran(out.duration),
        ExecEnd::Exited(s) => SetupResult::Failed(format!("setup {:?} failed ({s})", step.name)),
        ExecEnd::TimedOut => SetupResult::Failed(format!(
            "setup {:?} hit its {}s limit",
            step.name,
            step.timeout().as_secs()
        )),
        ExecEnd::Aborted(r) => SetupResult::Aborted(r),
        ExecEnd::SpawnFailed(e) => {
            SetupResult::Failed(format!("setup {:?} could not start: {e}", step.name))
        }
    }
}
