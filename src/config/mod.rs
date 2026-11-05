//! Repo config `tollgate.toml` (R63-R65), host config (R84), validation (R64).
//!
//! Detection without a `tollgate.toml` (R65) needs the selection roots and is
//! built with the `select` module.

pub mod check;
pub mod glob;
pub mod host;
pub mod repo;
pub mod units;

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub use host::{Budgets, CompiledScope, HostConfig, LoadedHost};
pub use repo::{RefRules, RepoConfig, ValidationContext};

/// One validation finding, located by a config path such as `step[2] "tests"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    /// Where in the config.
    pub at: String,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.at, self.message)
    }
}

/// Errors make a config unusable (a job ends with verdict `error`, cause
/// `config`); warnings are printed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Validation {
    /// Blocking findings.
    pub errors: Vec<Issue>,
    /// Printed findings.
    pub warnings: Vec<Issue>,
}

impl Validation {
    /// True when there is no error.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }

    fn error(&mut self, at: impl Into<String>, message: impl Into<String>) {
        self.errors.push(Issue {
            at: at.into(),
            message: message.into(),
        });
    }

    fn warn(&mut self, at: impl Into<String>, message: impl Into<String>) {
        self.warnings.push(Issue {
            at: at.into(),
            message: message.into(),
        });
    }
}

/// Environment variable names that config may not set (R52): `GIT_*` (the
/// injection must not reach test suites), `TOLLGATE` and `TMPDIR` (set by
/// the runner).
pub fn check_env_key(key: &str) -> Result<(), String> {
    let b = key.as_bytes();
    let valid = !b.is_empty()
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_');
    if !valid {
        return Err(format!("env name {key:?} is not a valid variable name"));
    }
    if key.starts_with("GIT_") {
        return Err(format!(
            "env {key}: GIT_* variables are never passed to jobs (R52)"
        ));
    }
    if key == "TOLLGATE" || key == "TMPDIR" {
        return Err(format!("env {key} is set by the runner (R52)"));
    }
    Ok(())
}

/// A check tier (R54). `Full` passes imply `Fast` (R53).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Affected packages only, on every commit.
    Fast,
    /// Whole workspace, at push, merge into a full ref, and in CI.
    Full,
}

impl Tier {
    /// The lowercase name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Full => "full",
        }
    }

    /// R53: a record of tier `self` satisfies a lookup for `required` when it
    /// is the same tier or higher.
    #[must_use]
    pub fn satisfies(self, required: Tier) -> bool {
        self >= required
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Tier {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "fast" => Ok(Self::Fast),
            "full" => Ok(Self::Full),
            other => Err(format!("unknown tier {other:?} (expected fast or full)")),
        }
    }
}

/// An operating system a step may be limited to (`only_on`, R63).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// Linux.
    Linux,
    /// macOS.
    Macos,
}

impl Platform {
    /// The platform this binary runs on.
    #[must_use]
    pub const fn current() -> Self {
        #[cfg(target_os = "macos")]
        {
            Self::Macos
        }
        #[cfg(not(target_os = "macos"))]
        {
            Self::Linux
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_satisfies_fast_but_not_the_reverse_r53() {
        assert!(Tier::Full.satisfies(Tier::Fast));
        assert!(Tier::Full.satisfies(Tier::Full));
        assert!(Tier::Fast.satisfies(Tier::Fast));
        assert!(!Tier::Fast.satisfies(Tier::Full));
    }

    #[test]
    fn tier_text_round_trips() {
        for t in [Tier::Fast, Tier::Full] {
            assert_eq!(t.as_str().parse::<Tier>().unwrap(), t);
            assert_eq!(serde_json::to_string(&t).unwrap(), format!("\"{t}\""));
        }
        assert!("FULL".parse::<Tier>().is_err());
    }
}
