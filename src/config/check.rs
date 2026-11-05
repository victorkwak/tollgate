//! `tollgate config --check` (R64): validates the working tree's
//! `tollgate.toml` and the host config.
//!
//! The per-job checks that need `cargo metadata`, the nextest test list and
//! the policy commit (unknown owners and quarantine tests, the 30-day cap)
//! run in jobs; this command reports what can be checked locally. Without
//! a `tollgate.toml` it reports what detection (R65) gives.

use std::path::Path;

use super::host::HostConfig;
use super::repo::{RepoConfig, ValidationContext};
use super::{Issue, Validation};
use crate::dirs::Dirs;
use crate::env::EnvSnapshot;
use crate::gitx::{Git, RepoLayout};

/// The repo config file name (R63).
pub const REPO_CONFIG_FILE: &str = "tollgate.toml";

/// What `config --check` found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckReport {
    /// Lines for the user, in order.
    pub lines: Vec<String>,
    /// True when no error was found.
    pub ok: bool,
}

fn add(report: &mut CheckReport, what: &str, v: &Validation) {
    let line = |kind: &str, i: &Issue| format!("{kind}: {what}: {i}");
    report
        .lines
        .extend(v.errors.iter().map(|i| line("error", i)));
    report
        .lines
        .extend(v.warnings.iter().map(|i| line("warning", i)));
    if !v.is_ok() {
        report.ok = false;
    }
}

/// Runs the check for the repo that contains `cwd`.
#[must_use]
pub fn check(cwd: &Path, env: &EnvSnapshot) -> CheckReport {
    let mut report = CheckReport {
        lines: Vec::new(),
        ok: true,
    };
    let fail = |report: &mut CheckReport, msg: String| {
        report.lines.push(format!("error: {msg}"));
        report.ok = false;
    };

    let host = match Dirs::from_env(env) {
        Err(e) => {
            fail(&mut report, e.to_string());
            None
        }
        Ok(dirs) => match HostConfig::load(&dirs) {
            Err(e) => {
                fail(&mut report, e.to_string());
                None
            }
            Ok(loaded) => {
                report.lines.push(format!(
                    "host config: {}{}",
                    loaded.path.display(),
                    if loaded.exists {
                        ""
                    } else {
                        " (absent: defaults)"
                    }
                ));
                add(&mut report, "host config", &loaded.config.validate());
                Some(loaded.config)
            }
        },
    };

    let layout = match RepoLayout::discover(&Git::scrubbed(env, cwd)) {
        Ok(l) => l,
        Err(e) => {
            fail(&mut report, format!("not in a git repository: {e}"));
            return report;
        }
    };
    let Some(worktree) = layout.worktree else {
        fail(
            &mut report,
            "bare repository: no tollgate.toml to check".into(),
        );
        return report;
    };
    let path = worktree.join(REPO_CONFIG_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let detected = crate::select::detect::roots_from_dir(&worktree)
                .map(|r| crate::select::detect::detected_config(&r));
            match detected {
                Ok((config, notes)) => {
                    report.lines.push(format!(
                        "repo config: no {REPO_CONFIG_FILE} in {}; jobs use detection (R65): {} step(s); see tollgate config --effective",
                        worktree.display(),
                        config.steps.len()
                    ));
                    report
                        .lines
                        .extend(notes.into_iter().map(|n| format!("note: {n}")));
                }
                Err(e) => fail(&mut report, format!("detection: {e}")),
            }
            return report;
        }
        Err(e) => {
            fail(&mut report, format!("{}: {e}", path.display()));
            return report;
        }
    };
    report
        .lines
        .push(format!("repo config: {}", path.display()));
    match RepoConfig::from_toml(&text) {
        Err(e) => fail(&mut report, format!("{}: {e}", path.display())),
        Ok(config) => {
            let ctx = ValidationContext {
                host: host.as_ref(),
                ..ValidationContext::default()
            };
            add(
                &mut report,
                REPO_CONFIG_FILE,
                &config.validate_with(&ctx).validation,
            );
        }
    }
    report
        .lines
        .push(if report.ok { "ok" } else { "invalid" }.into());
    report
}
