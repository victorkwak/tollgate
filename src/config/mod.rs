//! Repo config `tollgate.toml` (R63-R65), host config (R84), validation (R64).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

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
