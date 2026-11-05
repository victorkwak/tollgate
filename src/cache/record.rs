//! The record of one tier on one tree (R76, R80, R34).

use std::collections::BTreeSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::Fingerprint;
use crate::config::Tier;
use crate::gitx::Oid;
use crate::ids::{JobId, RecordKey};

/// R34: TTL of `timeout` and `error` records.
pub const ENVIRONMENTAL_TTL: Duration = Duration::from_secs(15 * 60);

/// The verdict of a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Every step passed.
    Pass,
    /// A step that ran to completion failed.
    Fail,
    /// The job or a step hit its limit.
    Timeout,
    /// The job could not run correctly.
    Error,
}

/// R34 verdict classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerdictClass {
    /// `pass`, `fail`: the same key gives the same result.
    Deterministic,
    /// `timeout`, `error`: kept for a TTL only.
    Environmental,
}

impl Verdict {
    /// The class of the verdict (R34).
    #[must_use]
    pub fn class(self) -> VerdictClass {
        match self {
            Self::Pass | Self::Fail => VerdictClass::Deterministic,
            Self::Timeout | Self::Error => VerdictClass::Environmental,
        }
    }
}

/// Why a job ended in `error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCause {
    /// A setup step or tool is missing or failed (R45, R46).
    Setup,
    /// The config is invalid (R64).
    Config,
    /// The verify checkout does not match the tree, or a step changed
    /// tracked files (R42).
    Checkout,
    /// tollgate itself failed.
    Internal,
    /// Not enough free disk (R44). Writes no record.
    Disk,
    /// Docker is not usable. Writes no record.
    Docker,
    /// The queue budget ran out (R33). Writes no record.
    Deferred,
}

impl ErrorCause {
    /// R34: `disk`, `docker` and `deferred` write no record.
    #[must_use]
    pub fn writes_record(self) -> bool {
        !matches!(self, Self::Disk | Self::Docker | Self::Deferred)
    }
}

/// What a `fast` job checked (R80).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Selection {
    /// Every step on the whole workspace (always for `full`, R54).
    All,
    /// A subset relative to a base tree.
    Subset(SubsetSelection),
}

/// The subset of a `fast` selection (R80).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubsetSelection {
    /// Base tree of the diff (R55).
    pub base: Oid,
    /// Selected Rust packages.
    pub packages: BTreeSet<String>,
    /// Selected TS and Python roots.
    pub roots: BTreeSet<String>,
    /// Steps that ran.
    pub steps: BTreeSet<String>,
}

impl Selection {
    /// True when this selection checked at least everything `needed` does
    /// (R79). A same-base selection is the same selection (same tree, base
    /// and policy, which the fingerprint covers), so the superset rule also
    /// covers R79's base-equality clause.
    #[must_use]
    pub fn covers(&self, needed: &Selection) -> bool {
        match (self, needed) {
            (Self::All, _) => true,
            (Self::Subset(_), Self::All) => false,
            (Self::Subset(have), Self::Subset(need)) => {
                have.packages.is_superset(&need.packages)
                    && have.roots.is_superset(&need.roots)
                    && have.steps.is_superset(&need.steps)
            }
        }
    }
}

/// The selection a lookup needs (R79).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Needed {
    /// Known exactly: the runner after `cargo metadata`, or `All`.
    Exact(Selection),
    /// Not known (a hook runs no `cargo`, R51): only a record of the same
    /// base tree is known to hold the same selection (same tree, base and
    /// policy; the fingerprint covers the rest), or an `All` record.
    SameBase(Oid),
    /// R56: an empty diff (the tree equals its base): any pass of the tree
    /// covers it; with no pass, the job runs everything.
    Any,
}

impl Needed {
    /// True when a pass on `have` covers what is needed (R79).
    #[must_use]
    pub fn covered_by(&self, have: &Selection) -> bool {
        match (self, have) {
            (Self::Exact(need), _) => have.covers(need),
            (Self::SameBase(_) | Self::Any, Selection::All) | (Self::Any, _) => true,
            (Self::SameBase(base), Selection::Subset(s)) => &s.base == base,
        }
    }

    /// True when a fail or live timeout/error on `have` would run again as
    /// is: what is needed contains it.
    #[must_use]
    pub fn contains(&self, have: &Selection) -> bool {
        match (self, have) {
            (Self::Exact(need), _) => need.covers(have),
            (Self::SameBase(base), Selection::Subset(s)) => &s.base == base,
            (Self::SameBase(_), Selection::All) => false,
            (Self::Any, _) => true,
        }
    }
}

/// One step's outcome (R76).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepResult {
    /// Step name.
    pub name: String,
    /// Outcome.
    pub status: StepStatus,
    /// Wall time in milliseconds.
    pub duration_ms: u64,
    /// Exit code, when the step exited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<i32>,
    /// Log path relative to the job dir.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
    /// Failing items (tests, diagnostics) for the report (R91).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failing: Vec<String>,
}

/// A step's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StepStatus {
    /// Passed.
    Pass,
    /// Failed.
    Fail,
    /// Hit its limit.
    Timeout,
    /// Could not run.
    Error,
    /// Not selected.
    Skipped,
}

/// A stored result (R76).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// [`super::RECORD_SCHEMA`].
    pub schema: u32,
    /// Key of `(tree, tier, fingerprint)`.
    pub key: RecordKey,
    /// The checked tree.
    pub tree: Oid,
    /// The tier.
    pub tier: Tier,
    /// The verdict.
    pub verdict: Verdict,
    /// Its class (R34).
    pub verdict_class: VerdictClass,
    /// Cause of an `error`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<ErrorCause>,
    /// TTL in seconds for environmental verdicts (R34).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// The fingerprint (R74).
    pub fingerprint: Fingerprint,
    /// The policy commit (L2).
    #[serde(default)]
    pub policy_commit: Option<Oid>,
    /// The base tree of the selection (R55).
    #[serde(default)]
    pub base_tree: Option<Oid>,
    /// What was checked (R80).
    pub selection: Selection,
    /// First step start (R33).
    pub started: jiff::Timestamp,
    /// End of the job.
    pub finished: jiff::Timestamp,
    /// Wall time in milliseconds.
    pub duration_ms: u64,
    /// Host name.
    pub host: String,
    /// tollgate version that ran the job.
    pub tollgate_version: String,
    /// The job (R82).
    pub job_id: JobId,
    /// Steps (R76).
    pub steps: Vec<StepResult>,
    /// Tests that passed on retry (R93).
    #[serde(default)]
    pub flaky: Vec<String>,
    /// Quarantined tests that failed (R93).
    #[serde(default)]
    pub quarantine_hits: Vec<String>,
}

impl Record {
    /// True when the environmental TTL has run out at `now` (R34).
    #[must_use]
    pub fn expired(&self, now: jiff::Timestamp) -> bool {
        match self.verdict_class {
            VerdictClass::Deterministic => false,
            VerdictClass::Environmental => {
                let ttl = self.ttl_secs.unwrap_or(ENVIRONMENTAL_TTL.as_secs());
                let age = now.as_second().saturating_sub(self.finished.as_second());
                age < 0 || u64::try_from(age).unwrap_or(u64::MAX) >= ttl
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subset(packages: &[&str], steps: &[&str]) -> Selection {
        Selection::Subset(SubsetSelection {
            base: Oid::parse(&"0".repeat(40)).unwrap(),
            packages: packages.iter().map(|s| (*s).to_owned()).collect(),
            roots: BTreeSet::new(),
            steps: steps.iter().map(|s| (*s).to_owned()).collect(),
        })
    }

    #[test]
    fn covers_is_a_superset_rule_r79() {
        let a = subset(&["a"], &["clippy", "tests"]);
        let ab = subset(&["a", "b"], &["clippy", "tests"]);
        assert!(Selection::All.covers(&Selection::All));
        assert!(Selection::All.covers(&ab));
        assert!(!ab.covers(&Selection::All));
        assert!(ab.covers(&a));
        assert!(
            !a.covers(&ab),
            "T35: one-crate record must not hit a two-crate diff"
        );
        assert!(!subset(&["a", "b"], &["tests"]).covers(&a));
    }

    #[test]
    fn needed_without_metadata_r79_r56() {
        let base = Oid::parse(&"0".repeat(40)).unwrap();
        let other = Oid::parse(&"1".repeat(40)).unwrap();
        let mut a = subset(&["a"], &["t"]);
        let same = Needed::SameBase(base.clone());
        assert!(same.covered_by(&a));
        assert!(same.covered_by(&Selection::All));
        assert!(same.contains(&a));
        assert!(!same.contains(&Selection::All));
        if let Selection::Subset(s) = &mut a {
            s.base = other.clone();
        }
        assert!(!same.covered_by(&a), "another base may need more");
        assert!(Needed::Any.covered_by(&a));
        assert!(Needed::Any.contains(&a));
        let exact = Needed::Exact(subset(&["a", "b"], &["t"]));
        assert!(!exact.covered_by(&subset(&["a"], &["t"])));
        assert!(exact.contains(&subset(&["a"], &["t"])));
    }

    #[test]
    fn verdict_classes_and_causes_r34() {
        assert_eq!(Verdict::Fail.class(), VerdictClass::Deterministic);
        assert_eq!(Verdict::Timeout.class(), VerdictClass::Environmental);
        assert!(ErrorCause::Setup.writes_record());
        for c in [ErrorCause::Disk, ErrorCause::Docker, ErrorCause::Deferred] {
            assert!(!c.writes_record(), "{c:?}");
        }
        assert_eq!(
            serde_json::to_string(&ErrorCause::Deferred).unwrap(),
            "\"deferred\""
        );
    }

    #[test]
    fn selection_json_form_r80() {
        assert_eq!(serde_json::to_string(&Selection::All).unwrap(), "\"all\"");
        let json = serde_json::to_string(&subset(&["a"], &["t"])).unwrap();
        assert!(json.starts_with("{\"subset\":{\"base\":"), "{json}");
    }
}
