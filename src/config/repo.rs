//! `tollgate.toml`, the repo config (R63), its defaults (L6, L7, L9) and its
//! validation (R64, R69).
//!
//! Unknown keys are errors: a typo such as `resouces = ["pg"]` must not
//! silently drop a resource slot.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};
use std::time::Duration;

use globset::GlobSet;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::glob::{self, GlobOpts};
use super::host::HostConfig;
use super::units::DurationSpec;
use super::{Platform, Tier, Validation, check_env_key};
use crate::ids::ResourceName;

/// The only schema version (R63).
pub const SCHEMA_VERSION: u32 = 1;

/// R69: quarantine `until` may be at most this many days after the policy
/// commit's committer date.
pub const QUARANTINE_MAX_DAYS: i32 = 30;

/// The repo config file (R63).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoConfig {
    /// Must be 1.
    pub version: u32,
    /// Full refs (R27).
    #[serde(default)]
    pub tiers: TiersConfig,
    /// Push rules (R20).
    #[serde(default)]
    pub push: PushConfig,
    /// Budget overrides of the host `[budget]` (R33).
    #[serde(default)]
    pub budget: BudgetOverrides,
    /// Extra policy files (R71).
    #[serde(default)]
    pub policy: PolicyConfig,
    /// Selection rules (R57, R61).
    #[serde(default)]
    pub select: SelectConfig,
    /// Setup steps (R45, R70).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub setup: Vec<SetupStep>,
    /// Steps (R63).
    #[serde(default, rename = "step", skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
    /// Quarantined flaky tests (R93).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quarantine: Vec<Quarantine>,
    /// Commands whose wide form only the gate runs (R103). Not part of
    /// [`RepoConfig::effective_hash`]: the guard reads them, no job does.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expensive: Vec<Expensive>,
}

impl Default for RepoConfig {
    fn default() -> Self {
        Self {
            version: SCHEMA_VERSION,
            tiers: TiersConfig::default(),
            push: PushConfig::default(),
            budget: BudgetOverrides::default(),
            policy: PolicyConfig::default(),
            select: SelectConfig::default(),
            setup: Vec::new(),
            steps: Vec::new(),
            quarantine: Vec::new(),
            expensive: Vec::new(),
        }
    }
}

/// `[[expensive]]` (R103): a command whose wide form runs a whole suite.
/// The guard refuses the wide form in a session and prints `hint`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expensive {
    /// Label in the refusal and in stats.
    pub name: String,
    /// Without `/`: a glob on the basename of the command name. With `/`:
    /// a glob on the repo-relative path of the command word made absolute
    /// against the command's cwd (`*` stops at `/`).
    pub program: String,
    /// Words that must all be among the literal argument words.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub with: Vec<String>,
    /// Globs on whole argument words; one match makes the call narrow.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub narrow: Vec<String>,
    /// The rule applies only in this repo dir or below.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// The narrow form, printed with the refusal.
    pub hint: String,
    /// The gate step that runs the wide form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<String>,
}

impl Expensive {
    /// Glob options of `program` with a `/`: case-sensitive, `*` stops at
    /// `/`.
    pub const PATH_GLOB: GlobOpts = GlobOpts {
        case_insensitive: false,
        literal_separator: true,
    };
    /// Glob options of `narrow` and of a basename `program`:
    /// case-sensitive, `*` crosses `/` (`*.spec.ts` matches
    /// `web/a.spec.ts`).
    pub const WORD_GLOB: GlobOpts = GlobOpts {
        case_insensitive: false,
        literal_separator: false,
    };
}

/// `[tiers]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TiersConfig {
    /// Branch globs that need `full` on merge and push; case-insensitive (R27).
    #[serde(default = "default_full_refs")]
    pub full_refs: Vec<String>,
}

/// L7: `main`, `master`, `integration/*`.
fn default_full_refs() -> Vec<String> {
    vec!["main".into(), "master".into(), "integration/*".into()]
}

impl Default for TiersConfig {
    fn default() -> Self {
        Self {
            full_refs: default_full_refs(),
        }
    }
}

/// `[push]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushConfig {
    /// No effect since R107 (2026-11-12): a branch push to a trusted
    /// remote needs `fast` unless it is a full ref or matches
    /// [`Self::full_refs`]. Still parsed, because existing policy files
    /// set it and the table denies unknown fields.
    #[serde(default)]
    pub fast_refs: Vec<String>,
    /// Branch globs whose pushes to trusted remotes need `full`, besides
    /// the full refs (R107). Exact case; `*` stops at `/`, `**` crosses.
    /// Left out of the serialized config when empty, so a config without
    /// it keeps its effective hash (R74).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub full_refs: Vec<String>,
}

/// `[budget]` in the repo: each value overrides the host value (R33).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetOverrides {
    /// Hook wait.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline: Option<DurationSpec>,
    /// Wait for a verify slot and resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<DurationSpec>,
    /// `fast` job limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fast: Option<DurationSpec>,
    /// `full` job limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full: Option<DurationSpec>,
}

/// `[policy]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Extra files (globs) treated as policy (R71).
    #[serde(default)]
    pub files: Vec<String>,
    /// Branch names whose tips anchor the policy commit (L2), in priority
    /// order: exact and case-sensitive, no globs. `integration/*` and other
    /// full refs are not anchors: an agent can create such a branch at its
    /// own tip.
    #[serde(default = "default_anchors")]
    pub anchors: Vec<String>,
}

/// L2: `main`, then `master`.
fn default_anchors() -> Vec<String> {
    vec!["main".into(), "master".into()]
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            files: Vec::new(),
            anchors: default_anchors(),
        }
    }
}

/// True when `name` is a plain branch name usable as a policy anchor: no
/// glob characters, no `refs/` prefix, no `..`, no spaces or control
/// characters (`git check-ref-format` rules that matter here).
#[must_use]
pub fn valid_anchor(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with("refs/")
        && !name.starts_with('-')
        && !name.starts_with('/')
        && !name.ends_with('/')
        && !name.ends_with(".lock")
        && !name.contains("..")
        && !name.contains("//")
        && !name.contains("@{")
        && !name
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "*?[]\\~^:".contains(c))
}

/// `[select]` (R57, R61).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectConfig {
    /// Globs that mark the whole workspace (R57a).
    #[serde(default)]
    pub global: Vec<String>,
    /// Globs that are docs-only (R61).
    #[serde(default)]
    pub docs_only: Vec<String>,
    /// Glob -> packages it belongs to (R57b).
    #[serde(default)]
    pub owners: BTreeMap<String, Vec<String>>,
    /// Fast-tier test selection (R58).
    #[serde(default)]
    pub fast: SelectFast,
}

/// `[select.fast]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectFast {
    /// Test filterset mode (R58, L6).
    #[serde(default)]
    pub tests: FastTests,
    /// Tests in the nextest `pg` group (R72).
    #[serde(default)]
    pub pg_tests: Vec<String>,
}

/// Fast-tier nextest filterset mode (R58).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum FastTests {
    /// `(rdeps(a)|...) & !kind(test) | (package(a)|...) & kind(test)`.
    #[serde(rename = "rdeps-unit+changed-integration")]
    RdepsUnitChangedIntegration,
    /// `rdeps(a)|...`. L6 default: errs toward running more.
    #[default]
    #[serde(rename = "rdeps-all")]
    RdepsAll,
}

/// `[[setup]]` (R70).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupStep {
    /// Unique name.
    pub name: String,
    /// Shell command.
    pub run: String,
    /// Directory relative to the repo root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Paths whose blob oids decide a re-run (R45).
    #[serde(default)]
    pub when: Vec<String>,
    /// Extra environment (R52).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Limit; default 10 minutes (R70).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<DurationSpec>,
}

impl SetupStep {
    /// The time limit (R70: default 10 m).
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
            .as_ref()
            .map_or(Duration::from_secs(600), DurationSpec::get)
    }
}

/// Built-in step kinds (R58-R60, R94) and `command`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StepKind {
    /// `cargo fmt --all --check`.
    CargoFmt,
    /// `cargo clippy ... -D warnings`.
    CargoClippy,
    /// `cargo nextest run`.
    Nextest,
    /// `cargo test --doc`.
    CargoDoctest,
    /// `biome check`.
    Biome,
    /// `tsc`.
    Tsc,
    /// `svelte-check`.
    SvelteCheck,
    /// `bun run test`.
    BunTest,
    /// `ruff check` and `ruff format --check`.
    Ruff,
    /// pyright against a baseline.
    PyrightBaseline,
    /// pytest against a baseline.
    PytestBaseline,
    /// A shell command from `run`.
    Command,
}

/// `[[step]]` (R63).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// Unique name.
    pub name: String,
    /// What runs.
    pub kind: StepKind,
    /// Shell command; only for `kind = "command"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    /// Directory relative to the repo root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Tiers the step runs in (R54; default both, L9).
    #[serde(default = "both_tiers")]
    pub tiers: Vec<Tier>,
    /// Run only when a changed path matches (empty: always).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub when: Vec<String>,
    /// Host resources held while the step runs (R85).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<ResourceName>,
    /// Step time limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<DurationSpec>,
    /// SIGTERM-to-SIGKILL wait (R35).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace: Option<DurationSpec>,
    /// Platforms the step runs on (empty: all).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub only_on: Vec<Platform>,
    /// Extra environment (R52).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Env file outside the tree, hashed into the key (R63, R74).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_file: Option<String>,
    /// Dirs kept by `git clean` in the verify checkout (R42).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cache_dirs: Vec<String>,
    /// Repo-relative globs of the tree entries the step's result depends on
    /// (L16; default everything). Matching is broad: `*` also crosses `/`.
    #[serde(default = "all_inputs")]
    pub inputs: Vec<String>,
    /// Globs removed from `inputs` (L16). Matching is narrow: `*` stops at
    /// `/`, only `**` crosses dirs, so an exclusion never reaches further
    /// than written.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_inputs: Vec<String>,
    /// Repo-relative paths or globs the runner copies out of the checkout
    /// after the step ends (R106): test reports, screenshots. Left out of
    /// the serialized step when empty, so existing step keys and config
    /// hashes stay the same.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<String>,
}

fn both_tiers() -> Vec<Tier> {
    vec![Tier::Fast, Tier::Full]
}

fn all_inputs() -> Vec<String> {
    vec!["**".into()]
}

/// Which tree paths are a step's inputs (L16).
#[derive(Debug, Clone)]
pub struct InputMatcher {
    include: GlobSet,
    exclude: GlobSet,
}

impl InputMatcher {
    /// True when `path` (repo-relative) is an input.
    #[must_use]
    pub fn matches(&self, path: &Path) -> bool {
        self.include.is_match(path) && !self.exclude.is_match(path)
    }
}

impl Step {
    /// True when the step runs in `tier` (R54).
    #[must_use]
    pub fn runs_in(&self, tier: Tier) -> bool {
        self.tiers.contains(&tier)
    }

    /// True when the step runs on `platform` (`only_on`).
    #[must_use]
    pub fn runs_on(&self, platform: Platform) -> bool {
        self.only_on.is_empty() || self.only_on.contains(&platform)
    }

    /// The step's input matcher (L16).
    pub fn input_matcher(&self) -> Result<InputMatcher, String> {
        Ok(InputMatcher {
            include: glob::compile(
                &self.inputs,
                GlobOpts {
                    case_insensitive: false,
                    literal_separator: false,
                },
            )?,
            exclude: glob::compile(
                &self.exclude_inputs,
                GlobOpts {
                    case_insensitive: false,
                    literal_separator: true,
                },
            )?,
        })
    }

    /// R35: 60 s for `nextest` (it forwards SIGTERM to its tests), else 10 s.
    #[must_use]
    pub fn grace(&self) -> Duration {
        self.grace.as_ref().map_or_else(
            || match self.kind {
                StepKind::Nextest => Duration::from_secs(60),
                _ => Duration::from_secs(10),
            },
            DurationSpec::get,
        )
    }
}

/// `[[quarantine]]` (R93).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quarantine {
    /// `<binary-id> <test>`, exact: `<package>::<binary> <test>`, or
    /// `<package> <test>` for a library's unit tests (nextest binary ids).
    pub test: String,
    /// Last day the quarantine applies (R69: at most 30 days after the policy
    /// commit).
    #[serde(serialize_with = "ser_date", deserialize_with = "de_date")]
    pub until: jiff::civil::Date,
    /// Where the flake is tracked.
    pub issue: String,
}

fn ser_date<S: Serializer>(date: &jiff::civil::Date, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(date)
}

/// Accepts `"2026-12-01"` and the TOML local date `2026-12-01`.
fn de_date<'de, D: Deserializer<'de>>(d: D) -> Result<jiff::civil::Date, D::Error> {
    struct DateVisitor;
    impl<'de> Visitor<'de> for DateVisitor {
        type Value = jiff::civil::Date;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a date YYYY-MM-DD")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            v.parse()
                .map_err(|e| E::custom(format!("invalid date {v:?}: {e}")))
        }

        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
            let dt =
                toml::value::Datetime::deserialize(de::value::MapAccessDeserializer::new(map))?;
            match (dt.date, dt.time, dt.offset) {
                (Some(d), None, None) => jiff::civil::Date::new(
                    i16::try_from(d.year).map_err(de::Error::custom)?,
                    i8::try_from(d.month).map_err(de::Error::custom)?,
                    i8::try_from(d.day).map_err(de::Error::custom)?,
                )
                .map_err(de::Error::custom),
                _ => Err(de::Error::custom(format!(
                    "expected a date without time, got {dt}"
                ))),
            }
        }
    }
    d.deserialize_any(DateVisitor)
}

/// Inputs for the per-job validation of R64.
#[derive(Debug, Clone, Copy, Default)]
pub struct ValidationContext<'a> {
    /// Package names in `cargo metadata` of `T` (R57b).
    pub workspace_packages: Option<&'a BTreeSet<String>>,
    /// Tests listed by nextest, as `<binary-id> <test>` (R64).
    pub known_tests: Option<&'a BTreeSet<String>>,
    /// Committer date of the policy commit (R69, L2).
    pub policy_commit_date: Option<jiff::civil::Date>,
    /// The host config, for resource names.
    pub host: Option<&'a HostConfig>,
}

/// Result of [`RepoConfig::validate_with`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextReport {
    /// Errors and warnings.
    pub validation: Validation,
    /// `owners` packages not in the workspace: selection marks the whole
    /// workspace (R57b).
    pub unknown_owner_packages: BTreeSet<String>,
}

/// Compiled ref rules (R20, R27, R107).
#[derive(Debug, Clone)]
pub struct RefRules {
    full: GlobSet,
    push_full: GlobSet,
}

/// The branch name of a ref: strips `refs/heads/` or `refs/remotes/<remote>/`
/// (R27). Other refs are returned unchanged.
#[must_use]
pub fn branch_name(refname: &str) -> &str {
    if let Some(b) = refname.strip_prefix("refs/heads/") {
        return b;
    }
    if let Some(rest) = refname.strip_prefix("refs/remotes/") {
        return rest.split_once('/').map_or(rest, |(_, b)| b);
    }
    refname
}

impl RefRules {
    /// `tier_for_ref` (R27): `full` when the branch name matches a
    /// `full_refs` glob, case-insensitively, else `fast`. `*` also crosses
    /// `/`, so `integration/*` covers `integration/a/b`; both choices err
    /// toward the higher tier.
    #[must_use]
    pub fn tier_for_ref(&self, refname: &str) -> Tier {
        if self.full.is_match(branch_name(refname)) {
            Tier::Full
        } else {
            Tier::Fast
        }
    }

    /// The tier a push needs (R20, R107). To a trusted remote: `full` for a
    /// full ref or a branch that matches `push.full_refs`, else `fast`. To
    /// other remotes: `tier_for_ref`. `push.full_refs` match exactly in
    /// case and `*` stops at `/` (`**` crosses), as `fast_refs` did.
    #[must_use]
    pub fn push_tier(&self, remote_ref: &str, trusted_remote: bool) -> Tier {
        let tier = self.tier_for_ref(remote_ref);
        if !trusted_remote || tier == Tier::Full {
            return tier;
        }
        if self.push_full.is_match(branch_name(remote_ref)) {
            Tier::Full
        } else {
            Tier::Fast
        }
    }
}

impl RepoConfig {
    /// Parses TOML text. Call [`RepoConfig::validate`] next.
    pub fn from_toml(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// The effective config as TOML (for `config --effective`).
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string(self)
    }

    /// blake3 of the canonical JSON of the effective config: part of the
    /// fingerprint (R65, R74). `[[expensive]]` is left out (R103): it
    /// changes what the guard refuses, not what a job checks, and a
    /// config without it hashes as before R103.
    #[must_use]
    pub fn effective_hash(&self) -> String {
        let json = if self.expensive.is_empty() {
            serde_json::to_vec(self)
        } else {
            serde_json::to_vec(&Self {
                expensive: Vec::new(),
                ..self.clone()
            })
        }
        .expect("RepoConfig serializes to JSON");
        blake3::hash(&json).to_hex().to_string()
    }

    /// Compiles the ref rules (R20, R27, R107). `push.fast_refs` is still
    /// compiled, so a bad pattern there stays a config error.
    pub fn ref_rules(&self) -> Result<RefRules, String> {
        let strict = GlobOpts {
            case_insensitive: false,
            literal_separator: true,
        };
        glob::compile(&self.push.fast_refs, strict)?;
        Ok(RefRules {
            full: glob::compile(
                &self.tiers.full_refs,
                GlobOpts {
                    case_insensitive: true,
                    literal_separator: false,
                },
            )?,
            push_full: glob::compile(&self.push.full_refs, strict)?,
        })
    }

    /// Checks everything that needs no workspace metadata (R63, R64).
    #[must_use]
    pub fn validate(&self) -> Validation {
        let mut v = Validation::default();
        if self.version != SCHEMA_VERSION {
            v.error(
                "version",
                format!(
                    "unsupported version {} (expected {SCHEMA_VERSION})",
                    self.version
                ),
            );
        }
        if let Err(e) = self.ref_rules() {
            v.error("tiers/push", e);
        }
        globs(&mut v, "policy.files", &self.policy.files);
        if self.policy.anchors.is_empty() {
            v.error("policy.anchors", "needs at least one branch name (L2)");
        }
        for a in &self.policy.anchors {
            if !valid_anchor(a) {
                v.error(
                    "policy.anchors",
                    format!("{a:?} is not a plain branch name (exact, no globs)"),
                );
            }
        }
        globs(&mut v, "select.global", &self.select.global);
        globs(&mut v, "select.docs_only", &self.select.docs_only);
        for (pattern, packages) in &self.select.owners {
            let at = format!("select.owners.{pattern:?}");
            globs(&mut v, &at, std::slice::from_ref(pattern));
            if packages.is_empty() || packages.iter().any(|p| p.trim().is_empty()) {
                v.error(&at, "needs at least one non-empty package name");
            }
        }
        for t in &self.select.fast.pg_tests {
            if t.trim().is_empty() {
                v.error("select.fast.pg_tests", "empty pattern");
            }
        }
        if let Some(b) = &self.budget.inline
            && b.get() > super::host::DEFAULT_INLINE_CAP
        {
            v.warn(
                "budget.inline",
                "above 100 s: without TOLLGATE_INLINE_CAP a hook waits at most 100 s (R28, L17)",
            );
        }

        let mut names = BTreeSet::new();
        for (i, s) in self.setup.iter().enumerate() {
            let at = format!("setup[{i}] {:?}", s.name);
            if s.name.trim().is_empty() {
                v.error(&at, "empty name");
            } else if !names.insert(s.name.as_str()) {
                v.error(&at, "duplicate setup name");
            }
            if s.run.trim().is_empty() {
                v.error(&at, "empty run");
            }
            rel_path(&mut v, &at, "cwd", s.cwd.as_deref());
            globs(&mut v, &format!("{at}.when"), &s.when);
            env_map(&mut v, &at, &s.env);
        }

        let mut names = BTreeSet::new();
        for (i, s) in self.steps.iter().enumerate() {
            let at = format!("step[{i}] {:?}", s.name);
            if s.name.trim().is_empty() {
                v.error(&at, "empty name");
            } else if !names.insert(s.name.as_str()) {
                v.error(&at, "duplicate step name");
            }
            match (s.kind, &s.run) {
                (StepKind::Command, None) => v.error(&at, "kind \"command\" needs run"),
                (StepKind::Command, Some(r)) if r.trim().is_empty() => v.error(&at, "empty run"),
                (StepKind::Command, Some(_)) => {}
                (_, Some(_)) => v.error(&at, "run is only for kind \"command\""),
                (_, None) => {}
            }
            if s.tiers.is_empty() {
                v.error(&at, "tiers is empty: the step never runs");
            }
            let unique: BTreeSet<_> = s.tiers.iter().collect();
            if unique.len() != s.tiers.len() {
                v.error(&at, "duplicate tier");
            }
            let unique: BTreeSet<_> = s.resources.iter().collect();
            if unique.len() != s.resources.len() {
                v.error(&at, "duplicate resource");
            }
            rel_path(&mut v, &at, "cwd", s.cwd.as_deref());
            for d in &s.cache_dirs {
                rel_path(&mut v, &at, "cache_dirs", Some(d));
            }
            globs(&mut v, &format!("{at}.when"), &s.when);
            globs(&mut v, &format!("{at}.inputs"), &s.inputs);
            globs(&mut v, &format!("{at}.exclude_inputs"), &s.exclude_inputs);
            // R106: inside the checkout, no `..`.
            for a in &s.artifacts {
                rel_path(&mut v, &at, "artifacts", Some(a));
            }
            globs(&mut v, &format!("{at}.artifacts"), &s.artifacts);
            if s.inputs.is_empty() {
                v.error(
                    &at,
                    "inputs is empty: use [\"**\"] for the whole tree (L16)",
                );
            }
            env_map(&mut v, &at, &s.env);
            if let Some(f) = &s.env_file
                && !(f.starts_with('/') || f.starts_with("~/"))
            {
                v.error(
                    &at,
                    format!("env_file {f:?} must be absolute or start with ~/ (outside the tree)"),
                );
            }
        }

        for (i, q) in self.quarantine.iter().enumerate() {
            let at = format!("quarantine[{i}] {:?}", q.test);
            if let Err(e) = check_quarantine_test(&q.test) {
                v.error(&at, e);
            }
            if q.issue.trim().is_empty() {
                v.error(&at, "empty issue");
            }
        }

        for (i, e) in self.expensive.iter().enumerate() {
            let at = format!("expensive[{i}] {:?}", e.name);
            for (field, value) in [
                ("name", &e.name),
                ("program", &e.program),
                ("hint", &e.hint),
            ] {
                if value.trim().is_empty() {
                    v.error(&at, format!("empty {field}"));
                }
            }
            let opts = if e.program.contains('/') {
                Expensive::PATH_GLOB
            } else {
                Expensive::WORD_GLOB
            };
            if let Err(err) = glob::compile(std::slice::from_ref(&e.program), opts) {
                v.error(&at, format!("program: {err}"));
            }
            if let Err(err) = glob::compile(&e.narrow, Expensive::WORD_GLOB) {
                v.error(&at, format!("narrow: {err}"));
            }
            if e.with.iter().any(|w| w.trim().is_empty()) {
                v.error(&at, "empty word in with");
            }
            rel_path(&mut v, &at, "cwd", e.cwd.as_deref());
            if e.step.as_ref().is_some_and(|s| s.trim().is_empty()) {
                v.error(&at, "empty step");
            }
        }
        v
    }

    /// The per-job checks of R64 that need data from the tree under test and
    /// the policy commit. Includes [`RepoConfig::validate`].
    #[must_use]
    pub fn validate_with(&self, ctx: &ValidationContext<'_>) -> ContextReport {
        let mut report = ContextReport {
            validation: self.validate(),
            ..ContextReport::default()
        };
        let v = &mut report.validation;
        if let Some(packages) = ctx.workspace_packages {
            for owned in self.select.owners.values().flatten() {
                if !packages.contains(owned) {
                    report.unknown_owner_packages.insert(owned.clone());
                }
            }
            for name in &report.unknown_owner_packages {
                v.warn("select.owners", format!("unknown package {name}"));
            }
        }
        for (i, q) in self.quarantine.iter().enumerate() {
            let at = format!("quarantine[{i}] {:?}", q.test);
            if let Some(tests) = ctx.known_tests
                && !tests.contains(&q.test)
            {
                v.error(
                    &at,
                    "no such test: the entry must name a listed test exactly",
                );
            }
            if let Some(date) = ctx.policy_commit_date {
                let cap = date
                    .checked_add(jiff::Span::new().days(QUARANTINE_MAX_DAYS))
                    .unwrap_or(jiff::civil::Date::MAX);
                if q.until > cap {
                    v.error(
                        &at,
                        format!(
                            "until {} is more than {QUARANTINE_MAX_DAYS} days after the policy commit ({date}); latest allowed {cap}",
                            q.until
                        ),
                    );
                }
            }
        }
        if let Some(host) = ctx.host {
            let mut seen = BTreeSet::new();
            for s in &self.steps {
                for r in &s.resources {
                    if !host.resource_defined(r) && seen.insert(r) {
                        v.warn(
                            format!("step {:?}", s.name),
                            format!("resource {r} is not in the host config; it gets 1 slot"),
                        );
                    }
                }
            }
        }
        report
    }
}

fn globs(v: &mut Validation, at: &str, patterns: &[String]) {
    for p in patterns {
        if let Err(e) = glob::check(p) {
            v.error(at, e);
        }
    }
}

/// A relative path that stays inside the tree: no root, no `..`.
fn rel_path(v: &mut Validation, at: &str, field: &str, path: Option<&str>) {
    let Some(p) = path else { return };
    let ok = !p.is_empty()
        && Path::new(p)
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
    if !ok {
        v.error(
            at,
            format!("{field} {p:?} must be a relative path inside the repo"),
        );
    }
}

fn env_map(v: &mut Validation, at: &str, env: &BTreeMap<String, String>) {
    for (k, val) in env {
        if let Err(e) = check_env_key(k) {
            v.error(at, e);
        }
        if val.contains('\0') {
            v.error(at, format!("env {k}: value contains NUL"));
        }
    }
}

/// Checks the `<binary-id> <test>` form of a quarantine entry.
fn check_quarantine_test(test: &str) -> Result<(), String> {
    const FORM: &str = "expected \"<package>::<binary> <test>\" or \"<package> <test>\"";
    let (binary, name) = test.split_once(' ').ok_or(FORM)?;
    if name.is_empty() || name.contains(char::is_whitespace) {
        return Err(FORM.into());
    }
    let (package, bin) = binary.split_once("::").unwrap_or((binary, "x"));
    if package.is_empty() || bin.is_empty() {
        return Err(FORM.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The R63 example, with the `ios lint` step and a quarantine entry.
    const SPEC_EXAMPLE: &str = r#"
version = 1

[tiers]
full_refs = ["main", "integration/*"]

[push]
fast_refs = ["wip/*"]

[budget]
inline = "100s"
fast = "20m"
full = "2h"

[policy]
files = ["prompts/guard_policy.md"]

[select]
global = [".sqlx/**", "prompts/**"]
docs_only = ["docs/**", "*.md"]
[select.owners]
"migrations/**" = ["gatehouse-core"]
[select.fast]
tests = "rdeps-unit+changed-integration"
pg_tests = ["gatehouse-api::*", "gatehouse-core::*", "gatehouse-agent::*"]

[[setup]]
name = "bun install"
run = "bun install --frozen-lockfile"
cwd = "dashboard"
when = ["dashboard/bun.lock", "dashboard/package.json"]

[[step]]
name = "fmt"
kind = "cargo-fmt"
[[step]]
name = "clippy"
kind = "cargo-clippy"
resources = ["cpu"]
[[step]]
name = "tests"
kind = "nextest"
resources = ["cpu", "pg", "minio"]
[[step]]
name = "doctests"
kind = "cargo-doctest"
resources = ["cpu"]
[[step]]
name = "dashboard check"
kind = "svelte-check"
cwd = "dashboard"
[[step]]
name = "ios lint"
kind = "command"
run = "swiftlint lint --strict"
cwd = "ios"
only_on = ["macos"]
tiers = ["full"]
when = ["ios/**"]
resources = ["cpu"]
timeout = "10m"
cache_dirs = ["ios/.build"]

[[quarantine]]
test = "gatehouse-api::sessions test_concurrent_cancel"
until = "2026-12-01"
issue = "Issues/open/myapp-cancel-flake"
"#;

    fn parse(text: &str) -> RepoConfig {
        RepoConfig::from_toml(text).unwrap()
    }

    fn errors(c: &RepoConfig) -> Vec<String> {
        c.validate()
            .errors
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn spec_example_parses_and_validates_r63() {
        let c = parse(SPEC_EXAMPLE);
        assert!(c.validate().is_ok(), "{:?}", c.validate());
        assert_eq!(c.steps.len(), 6);
        assert_eq!(c.select.fast.tests, FastTests::RdepsUnitChangedIntegration);
        let ios = &c.steps[5];
        assert_eq!(ios.tiers, vec![Tier::Full]);
        assert!(ios.runs_on(Platform::Macos));
        assert!(!ios.runs_on(Platform::Linux));
        assert_eq!(ios.timeout.as_ref().unwrap().get().as_secs(), 600);
        assert_eq!(c.quarantine[0].until.to_string(), "2026-12-01");
        assert_eq!(c.setup[0].timeout().as_secs(), 600);
    }

    #[test]
    fn defaults_l6_l7_l9() {
        let c = parse("version = 1\n[[step]]\nname = \"py\"\nkind = \"pytest-baseline\"\n");
        assert_eq!(c.tiers.full_refs, ["main", "master", "integration/*"]);
        assert!(c.push.fast_refs.is_empty());
        assert_eq!(c.select.fast.tests, FastTests::RdepsAll);
        // L9: pytest-baseline runs in fast too (steps default to both tiers).
        assert!(c.steps[0].runs_in(Tier::Fast) && c.steps[0].runs_in(Tier::Full));
        assert_eq!(
            c,
            RepoConfig {
                steps: c.steps.clone(),
                ..RepoConfig::default()
            }
        );
    }

    #[test]
    fn step_inputs_l16() {
        let c = parse(
            "version = 1\n[[step]]\nname = \"all\"\nkind = \"cargo-fmt\"\n[[step]]\nname = \"ios\"\nkind = \"command\"\nrun = \"x\"\ninputs = [\"ios/**\", \"*.yml\"]\nexclude_inputs = [\"ios/docs/**\", \"*.md\"]\n",
        );
        assert!(c.validate().is_ok(), "{:?}", c.validate());
        let all = c.steps[0].input_matcher().unwrap();
        assert_eq!(c.steps[0].inputs, ["**"]);
        assert!(all.matches(Path::new("crates/a/src/lib.rs")));
        assert!(all.matches(Path::new("README.md")));
        let ios = c.steps[1].input_matcher().unwrap();
        assert!(ios.matches(Path::new("ios/App/main.swift")));
        assert!(
            ios.matches(Path::new(".github/ci.yml")),
            "inputs: * crosses /"
        );
        assert!(!ios.matches(Path::new("crates/a/src/lib.rs")));
        assert!(!ios.matches(Path::new("ios/docs/x.swift")));
        // exclude `*.md` is root-level only: it does not reach into ios/.
        assert!(ios.matches(Path::new("ios/README.md")));
        let empty =
            parse("version = 1\n[[step]]\nname = \"x\"\nkind = \"cargo-fmt\"\ninputs = []\n");
        assert!(errors(&empty).join("\n").contains("inputs is empty"));
    }

    #[test]
    fn grace_defaults_r35() {
        let c = parse(
            "version = 1\n[[step]]\nname = \"t\"\nkind = \"nextest\"\n[[step]]\nname = \"c\"\nkind = \"command\"\nrun = \"true\"\ngrace = \"3s\"\n[[step]]\nname = \"f\"\nkind = \"cargo-fmt\"\n",
        );
        assert_eq!(c.steps[0].grace().as_secs(), 60);
        assert_eq!(c.steps[1].grace().as_secs(), 3);
        assert_eq!(c.steps[2].grace().as_secs(), 10);
    }

    #[test]
    fn unknown_keys_and_kinds_are_parse_errors() {
        assert!(
            RepoConfig::from_toml(
                "version = 1\n[[step]]\nname = \"t\"\nkind = \"nextest\"\nresouces = [\"pg\"]\n"
            )
            .is_err()
        );
        assert!(
            RepoConfig::from_toml("version = 1\n[[step]]\nname = \"t\"\nkind = \"make\"\n")
                .is_err()
        );
        assert!(RepoConfig::from_toml("version = 1\nextra = 2\n").is_err());
        assert!(
            RepoConfig::from_toml("[tiers]\n").is_err(),
            "version is required"
        );
        // A resource name is a lock dir name: no path characters.
        assert!(
            RepoConfig::from_toml(
                "version = 1\n[[step]]\nname = \"t\"\nkind = \"nextest\"\nresources = [\"../x\"]\n"
            )
            .is_err()
        );
    }

    #[test]
    fn toml_local_dates_are_accepted() {
        let c = parse(
            "version = 1\n[[quarantine]]\ntest = \"p t\"\nuntil = 2026-12-01\nissue = \"i\"\n",
        );
        assert_eq!(c.quarantine[0].until, jiff::civil::date(2026, 12, 1));
        assert!(RepoConfig::from_toml("version = 1\n[[quarantine]]\ntest = \"p t\"\nuntil = 2026-12-01T10:00:00\nissue = \"i\"\n").is_err());
    }

    #[test]
    fn static_validation_r64() {
        let c = parse(
            r#"version = 2
[tiers]
full_refs = ["ma[in"]
[[step]]
name = "a"
kind = "command"
[[step]]
name = "a"
kind = "cargo-fmt"
run = "x"
cwd = "../up"
tiers = []
env = { GIT_DIR = "x", TOLLGATE = "0", "bad key" = "v" }
env_file = "rel/.env"
cache_dirs = ["/abs"]
[[setup]]
name = "s"
run = " "
[[quarantine]]
test = "nospace"
until = "2026-12-01"
issue = ""
"#,
        );
        let errs = errors(&c).join("\n");
        for needle in [
            "unsupported version 2",
            "ma[in",
            "needs run",
            "duplicate step name",
            "run is only for kind",
            "cwd \"../up\"",
            "tiers is empty",
            "GIT_DIR",
            "TOLLGATE",
            "bad key",
            "env_file \"rel/.env\"",
            "cache_dirs \"/abs\"",
            "empty run",
            "expected \"<package>::<binary> <test>\"",
            "empty issue",
        ] {
            assert!(errs.contains(needle), "missing {needle:?} in:\n{errs}");
        }
    }

    #[test]
    fn quarantine_test_forms() {
        assert!(check_quarantine_test("gatehouse-api::sessions test_concurrent_cancel").is_ok());
        assert!(check_quarantine_test("myapp-core tests::it_works").is_ok());
        for bad in ["", "pkg", "pkg ", " t", "::bin t", "pkg:: t", "pkg t extra"] {
            assert!(check_quarantine_test(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn context_validation_r64_r69_r57b() {
        let c = parse(SPEC_EXAMPLE);
        let packages: BTreeSet<String> = ["gatehouse-api".to_owned()].into();
        let tests: BTreeSet<String> =
            ["gatehouse-api::sessions test_concurrent_cancel".to_owned()].into();

        // Policy commit 2026-11-05: until 2026-12-01 is 26 days later: allowed.
        let ok = c.validate_with(&ValidationContext {
            workspace_packages: Some(&packages),
            known_tests: Some(&tests),
            policy_commit_date: Some(jiff::civil::date(2026, 11, 5)),
            host: None,
        });
        assert!(ok.validation.errors.is_empty(), "{:?}", ok.validation);
        // R57b: unknown owner package -> warning plus whole workspace.
        assert_eq!(
            ok.unknown_owner_packages,
            ["gatehouse-core".to_owned()].into()
        );
        assert!(
            ok.validation.warnings[0]
                .to_string()
                .contains("unknown package gatehouse-core")
        );

        // R69: 2026-12-01 is 31 days after 2026-10-31.
        let late = c.validate_with(&ValidationContext {
            policy_commit_date: Some(jiff::civil::date(2026, 10, 31)),
            ..ValidationContext::default()
        });
        assert!(
            late.validation.errors[0]
                .to_string()
                .contains("more than 30 days"),
            "{:?}",
            late.validation
        );
        // Exactly 30 days is allowed.
        let edge = c.validate_with(&ValidationContext {
            policy_commit_date: Some(jiff::civil::date(2026, 11, 1)),
            ..ValidationContext::default()
        });
        assert!(edge.validation.errors.is_empty(), "{:?}", edge.validation);

        // R64: an unknown quarantine test is an error.
        let none = BTreeSet::new();
        let unknown = c.validate_with(&ValidationContext {
            known_tests: Some(&none),
            ..ValidationContext::default()
        });
        assert!(
            unknown.validation.errors[0]
                .to_string()
                .contains("no such test")
        );
    }

    #[test]
    fn policy_anchors_are_exact_branch_names_l2() {
        assert_eq!(
            RepoConfig::default().policy.anchors,
            ["main".to_owned(), "master".to_owned()]
        );
        let c = parse("version = 1\n[policy]\nanchors = [\"trunk\", \"release/1\"]\n");
        assert!(c.validate().is_ok());
        for bad in ["integration/*", "refs/heads/main", "", "a..b", "x y"] {
            let c = parse(&format!("version = 1\n[policy]\nanchors = [{bad:?}]\n"));
            assert!(!c.validate().is_ok(), "{bad:?} must be refused");
        }
        let empty = parse("version = 1\n[policy]\nanchors = []\n");
        assert!(!empty.validate().is_ok());
    }

    #[test]
    fn undefined_resources_warn() {
        let c = parse(
            "version = 1\n[[step]]\nname = \"t\"\nkind = \"nextest\"\nresources = [\"cpu\", \"minio\"]\n",
        );
        let host = HostConfig::default();
        let r = c.validate_with(&ValidationContext {
            host: Some(&host),
            ..ValidationContext::default()
        });
        let warnings: Vec<String> = r
            .validation
            .warnings
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("resource minio"), "{warnings:?}");
    }

    #[test]
    fn tier_for_ref_is_case_insensitive_r27() {
        let rules = RepoConfig::default().ref_rules().unwrap();
        for full in [
            "refs/heads/main",
            "refs/heads/MAIN",
            "refs/heads/Master",
            "refs/remotes/origin/main",
            "refs/heads/integration/batch-3",
            "refs/heads/integration/a/b",
            "main",
        ] {
            assert_eq!(rules.tier_for_ref(full), Tier::Full, "{full}");
        }
        for fast in [
            "refs/heads/feat",
            "refs/heads/mainline",
            "refs/heads/x/main",
            "refs/remotes/origin/feat",
        ] {
            assert_eq!(rules.tier_for_ref(fast), Tier::Fast, "{fast}");
        }
    }

    /// R107 (replaces the L7 rule "full for every branch" of R20): a push
    /// to a trusted remote needs `full` for a full ref (`tiers.full_refs`)
    /// or a `push.full_refs` match, else `fast`. Other remotes:
    /// `tier_for_ref`.
    #[test]
    fn push_tier_r107() {
        let default = RepoConfig::default().ref_rules().unwrap();
        for (r, want) in [
            ("refs/heads/feat", Tier::Fast),
            ("refs/heads/wip/x", Tier::Fast),
            ("refs/heads/release/x", Tier::Fast),
            ("refs/heads/main", Tier::Full),
            ("refs/heads/MAIN", Tier::Full),
            ("refs/heads/master", Tier::Full),
            ("refs/heads/integration/a/b", Tier::Full),
        ] {
            assert_eq!(default.push_tier(r, true), want, "trusted {r}");
            // Other remotes: tier_for_ref, the same table by default.
            assert_eq!(default.push_tier(r, false), want, "other {r}");
        }
        // push.full_refs: exact case, `*` stops at `/`, `**` crosses.
        let rel = parse("version = 1\n[push]\nfull_refs = [\"release/*\", \"hot/**\"]\n")
            .ref_rules()
            .unwrap();
        for (r, want) in [
            ("refs/heads/release/x", Tier::Full),
            ("refs/heads/release/a/b", Tier::Fast),
            ("refs/heads/Release/x", Tier::Fast),
            ("refs/heads/hot/a/b", Tier::Full),
            ("refs/heads/feat", Tier::Fast),
            ("refs/heads/main", Tier::Full),
        ] {
            assert_eq!(rel.push_tier(r, true), want, "trusted {r}");
        }
        // push.full_refs counts for trusted remotes only.
        assert_eq!(rel.push_tier("refs/heads/release/x", false), Tier::Fast);
        // `**` makes every branch push need full.
        let all = parse("version = 1\n[push]\nfull_refs = [\"**\"]\n")
            .ref_rules()
            .unwrap();
        assert_eq!(all.push_tier("refs/heads/a/b/c", true), Tier::Full);
        // push.fast_refs still parses and has no effect: never below the
        // table above, and a full ref stays full.
        let fast =
            parse("version = 1\n[push]\nfast_refs = [\"*\", \"**\"]\nfull_refs = [\"wip/*\"]\n")
                .ref_rules()
                .unwrap();
        assert_eq!(fast.push_tier("refs/heads/wip/x", true), Tier::Full);
        assert_eq!(fast.push_tier("refs/heads/main", true), Tier::Full);
        assert_eq!(fast.push_tier("refs/heads/feat", true), Tier::Fast);
        // A bad glob is a config error.
        assert!(
            parse("version = 1\n[push]\nfull_refs = [\"a[\"]\n")
                .ref_rules()
                .is_err()
        );
    }

    #[test]
    fn effective_hash_tracks_content_r65() {
        let a = RepoConfig::default();
        let mut b = RepoConfig::default();
        assert_eq!(a.effective_hash(), b.effective_hash());
        b.push.fast_refs.push("wip/*".into());
        assert_ne!(a.effective_hash(), b.effective_hash());
    }

    const EXPENSIVE: &str = r#"
[[expensive]]
name = "browser suite"
program = "scripts/e2e*.sh"
narrow = ["*.spec.ts", "-g", "--grep*"]
hint = "scripts/e2e.sh <suite> <file>.spec.ts"
step = "e2e main"

[[expensive]]
name = "web tests"
program = "playwright"
with = ["test"]
cwd = "web"
hint = "bunx playwright test <file>.spec.ts"
"#;

    #[test]
    fn expensive_entries_parse_and_validate_r103() {
        let c = parse(&format!("version = 1\n{EXPENSIVE}"));
        assert!(c.validate().is_ok(), "{:?}", c.validate());
        assert_eq!(c.expensive.len(), 2);
        assert_eq!(c.expensive[0].narrow, ["*.spec.ts", "-g", "--grep*"]);
        assert_eq!(c.expensive[0].step.as_deref(), Some("e2e main"));
        assert_eq!(c.expensive[1].with, ["test"]);
        assert_eq!(c.expensive[1].cwd.as_deref(), Some("web"));
        // `config --effective` prints them.
        let toml = c.to_toml().unwrap();
        assert!(toml.contains("[[expensive]]"), "{toml}");
        assert_eq!(RepoConfig::from_toml(&toml).unwrap(), c);
        // Unknown keys and missing required keys are parse errors.
        for bad in [
            "[[expensive]]\nname = \"x\"\nprogram = \"y\"\nhint = \"z\"\nnarow = []\n",
            "[[expensive]]\nname = \"x\"\nprogram = \"y\"\n",
            "[[expensive]]\nprogram = \"y\"\nhint = \"z\"\n",
        ] {
            assert!(
                RepoConfig::from_toml(&format!("version = 1\n{bad}")).is_err(),
                "{bad}"
            );
        }
        let c = parse(
            r#"version = 1
[[expensive]]
name = " "
program = ""
hint = ""
narrow = ["a["]
with = [""]
cwd = "../up"
step = ""
[[expensive]]
name = "bad program"
program = "scripts/[x"
hint = "h"
"#,
        );
        let errs = errors(&c).join("\n");
        for needle in [
            "expensive[0] \" \": empty name",
            "empty program",
            "empty hint",
            "narrow: invalid glob \"a[\"",
            "empty word in with",
            "cwd \"../up\"",
            "empty step",
            "expensive[1] \"bad program\": program: invalid glob \"scripts/[x\"",
        ] {
            assert!(errs.contains(needle), "missing {needle:?} in:\n{errs}");
        }
    }

    /// The table only feeds the guard: no job checks differently, so it
    /// must not change the effective hash (R65, R74, R103). The record key
    /// also leaves the blob of `tollgate.toml` out of the policy-file hash;
    /// `tests/runner.rs::only_what_jobs_read_from_the_policy_file_is_in_the_key_r74_r103`
    /// proves that end to end.
    #[test]
    fn expensive_entries_do_not_change_the_effective_hash_r103() {
        let base = parse(SPEC_EXAMPLE);
        // A config without the table hashes as the serialization without
        // the field (as before R103).
        let json = serde_json::to_string(&base).unwrap();
        assert!(!json.contains("expensive"), "{json}");
        assert_eq!(
            base.effective_hash(),
            blake3::hash(json.as_bytes()).to_hex().to_string()
        );
        let with = parse(&format!("{SPEC_EXAMPLE}\n{EXPENSIVE}"));
        assert_eq!(with.expensive.len(), 2);
        assert_eq!(base.effective_hash(), with.effective_hash());
        let mut changed = with.clone();
        changed.expensive[0].narrow.push("--project*".into());
        changed.expensive.pop();
        assert_eq!(base.effective_hash(), changed.effective_hash());
    }

    /// R107: `push.full_refs` is new, and the effective hash is in every
    /// record's fingerprint (R74). A config that does not set it hashes as
    /// before (values from the code before R107), so no record goes stale.
    #[test]
    fn effective_hash_is_unchanged_without_push_full_refs_r107_r74() {
        assert_eq!(
            RepoConfig::default().effective_hash(),
            "abf725995f5f90284baa2aa6f5f405e49d954759b38802c3b9095901255a272b"
        );
        assert_eq!(
            parse(SPEC_EXAMPLE).effective_hash(),
            "210f87fca7b7887299e1d296ea76a15f8aebafa0c2bfcf6a53956ab856ae7d34"
        );
        assert_eq!(
            parse("version = 1\n[push]\nfast_refs = [\"wip/*\"]\n").effective_hash(),
            "3ba812900a88932873de579af9b887e96f23a2461bb8920d03771ca6603200c0"
        );
        // An empty list is the same as none; a set list changes the hash.
        assert_eq!(
            parse("version = 1\n[push]\nfull_refs = []\n").effective_hash(),
            RepoConfig::default().effective_hash()
        );
        assert_ne!(
            parse("version = 1\n[push]\nfull_refs = [\"release/*\"]\n").effective_hash(),
            RepoConfig::default().effective_hash()
        );
    }

    #[test]
    fn to_toml_round_trips() {
        let c = parse(SPEC_EXAMPLE);
        let again = RepoConfig::from_toml(&c.to_toml().unwrap()).unwrap();
        assert_eq!(c, again);
    }

    #[test]
    fn branch_name_strips_known_prefixes() {
        assert_eq!(branch_name("refs/heads/a/b"), "a/b");
        assert_eq!(branch_name("refs/remotes/origin/a/b"), "a/b");
        assert_eq!(branch_name("refs/tags/v1"), "refs/tags/v1");
    }
}
