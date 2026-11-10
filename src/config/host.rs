//! Host config `$XDG_CONFIG_HOME/tollgate/config.toml` (R84), its defaults
//! (L5, L9), scope (L4) and budgets (R28, R33).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use globset::GlobSet;
use serde::{Deserialize, Serialize};

use super::glob::{self, GlobOpts};
use super::repo::BudgetOverrides;
use super::units::{DurationSpec, SizeSpec};
use super::{Platform, Tier, Validation, check_env_key};
use crate::dirs::Dirs;
use crate::fsx;
use crate::ids::ResourceName;

/// The host config (R84). Every section and key is optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    /// Which repos are gated (L4).
    #[serde(default)]
    pub scope: ScopeConfig,
    /// Resource semaphores (R85). Missing `cpu`/`pg` get the L5 defaults.
    #[serde(default)]
    pub resources: BTreeMap<ResourceName, ResourceSpec>,
    /// nextest tool config (R72, R93).
    #[serde(default)]
    pub nextest: NextestHost,
    /// Verify checkouts (R41, R44).
    #[serde(default)]
    pub verify: VerifyConfig,
    /// Budgets (R33).
    #[serde(default)]
    pub budget: Budgets,
    /// Job environment (R52).
    #[serde(default)]
    pub job: JobConfig,
}

/// `[scope]` (L4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeConfig {
    /// Dirs whose direct children are in scope.
    #[serde(default = "default_roots")]
    pub roots: Vec<String>,
    /// Remote URL globs of trusted remotes (R5, R20). Scope and push
    /// gating match them loosely; trust parses them (item 34,
    /// [`crate::config::trust`]).
    #[serde(default)]
    pub remotes: Vec<String>,
    /// Exact canonical absolute paths of local repos trusted as remotes
    /// (mirrors, tests); a pattern never trusts a local path (item 34).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_paths: Vec<String>,
    /// Basename globs allowed (rollout).
    #[serde(default = "default_include")]
    pub include: Vec<String>,
    /// Basename globs excluded.
    #[serde(default)]
    pub exclude: Vec<String>,
}

fn default_roots() -> Vec<String> {
    vec!["~/Repos".into()]
}

fn default_include() -> Vec<String> {
    vec!["*".into()]
}

impl Default for ScopeConfig {
    fn default() -> Self {
        Self {
            roots: default_roots(),
            remotes: Vec::new(),
            trusted_paths: Vec::new(),
            include: default_include(),
            exclude: Vec::new(),
        }
    }
}

/// A resource: a slot count, or a table with an image (R74, R84).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResourceSpec {
    /// `cpu = 3`.
    Slots(u32),
    /// `pg = { slots = 2, image = "postgres:16" }`.
    Table {
        /// Slot count.
        slots: u32,
        /// Docker image whose id goes into the fingerprint (R74).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        image: Option<String>,
    },
}

impl ResourceSpec {
    /// The slot count.
    #[must_use]
    pub fn slots(&self) -> u32 {
        match self {
            Self::Slots(n) | Self::Table { slots: n, .. } => *n,
        }
    }

    /// The image, when set.
    #[must_use]
    pub fn image(&self) -> Option<&str> {
        match self {
            Self::Slots(_) => None,
            Self::Table { image, .. } => image.as_deref(),
        }
    }
}

/// L5 resource defaults, used when the host config does not name them.
pub const DEFAULT_RESOURCES: &[(&str, u32)] = &[("cpu", 3), ("pg", 2)];

/// Slots of a resource that neither the config nor [`DEFAULT_RESOURCES`]
/// names. One slot errs toward serializing.
pub const UNDEFINED_RESOURCE_SLOTS: u32 = 1;

/// `[nextest]` (R72, R93).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NextestHost {
    /// Max threads of the `pg` test group; L5: 12.
    #[serde(default = "default_pg_max_threads")]
    pub pg_max_threads: u32,
    /// Test retries; L9: 2.
    #[serde(default = "default_retries")]
    pub retries: u32,
    /// Slow-timeout period.
    #[serde(default = "default_slow_timeout")]
    pub slow_timeout: DurationSpec,
    /// Slow periods before a test is killed.
    #[serde(default = "default_terminate_after")]
    pub terminate_after: u32,
    /// nextest global timeout in `fast`.
    #[serde(default = "default_global_fast")]
    pub global_timeout_fast: DurationSpec,
    /// nextest global timeout in `full`.
    #[serde(default = "default_global_full")]
    pub global_timeout_full: DurationSpec,
}

fn dur(s: &str) -> DurationSpec {
    DurationSpec::parse(s).expect("built-in duration")
}

fn default_pg_max_threads() -> u32 {
    12
}
fn default_retries() -> u32 {
    2
}
fn default_slow_timeout() -> DurationSpec {
    dur("120s")
}
fn default_terminate_after() -> u32 {
    2
}
fn default_global_fast() -> DurationSpec {
    dur("15m")
}
fn default_global_full() -> DurationSpec {
    dur("100m")
}

impl Default for NextestHost {
    fn default() -> Self {
        Self {
            pg_max_threads: default_pg_max_threads(),
            retries: default_retries(),
            slow_timeout: default_slow_timeout(),
            terminate_after: default_terminate_after(),
            global_timeout_fast: default_global_fast(),
            global_timeout_full: default_global_full(),
        }
    }
}

/// `[verify]` (R41, R44, L5, L15).
///
/// L15: verify checkouts are sticky, one per agent worktree and tier, with
/// LRU eviction above the limits below. `verify.slots` (R41) is CUT:
/// resource slots (R85) limit concurrency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyConfig {
    /// Verify root; default `$XDG_STATE_HOME/tollgate/verify` (R41). The
    /// Arch box sets `/mnt/devdisk/tollgate/verify` in its file (L5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// `fast` checkouts kept per repo clone (L15: 12).
    #[serde(default = "default_max_checkouts")]
    pub max_checkouts: u32,
    /// `full` checkouts kept per repo clone (L15: 4).
    #[serde(default = "default_max_full_checkouts")]
    pub max_full_checkouts: u32,
    /// Below this free space a job is deferred (R44).
    #[serde(default = "default_min_free")]
    pub min_free: SizeSpec,
    /// Above this a checkout's target dir is cleaned (R44).
    #[serde(default = "default_max_target")]
    pub max_target: SizeSpec,
}

fn default_max_checkouts() -> u32 {
    12
}
fn default_max_full_checkouts() -> u32 {
    4
}
fn default_min_free() -> SizeSpec {
    SizeSpec::parse("30G").expect("built-in size")
}
fn default_max_target() -> SizeSpec {
    SizeSpec::parse("40G").expect("built-in size")
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            root: None,
            max_checkouts: default_max_checkouts(),
            max_full_checkouts: default_max_full_checkouts(),
            min_free: default_min_free(),
            max_target: default_max_target(),
        }
    }
}

impl VerifyConfig {
    /// The verify root with `~` expanded.
    #[must_use]
    pub fn root(&self, dirs: &Dirs) -> PathBuf {
        self.root
            .as_deref()
            .map_or_else(|| dirs.default_verify_root(), |r| dirs.expand_tilde(r))
    }

    /// Checkouts kept per repo clone for `tier` before LRU eviction (L15).
    #[must_use]
    pub fn max_checkouts(&self, tier: Tier) -> u32 {
        match tier {
            Tier::Fast => self.max_checkouts,
            Tier::Full => self.max_full_checkouts,
        }
    }
}

/// `[budget]` (R33).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budgets {
    /// How long a hook waits for a job (R32).
    #[serde(default = "default_inline")]
    pub inline: DurationSpec,
    /// How long a job may wait for a slot and resources.
    #[serde(default = "default_queue")]
    pub queue: DurationSpec,
    /// `fast` job limit from the first step start.
    #[serde(default = "default_fast")]
    pub fast: DurationSpec,
    /// `full` job limit from the first step start.
    #[serde(default = "default_full")]
    pub full: DurationSpec,
}

fn default_inline() -> DurationSpec {
    dur("100s")
}
fn default_queue() -> DurationSpec {
    dur("30m")
}
fn default_fast() -> DurationSpec {
    dur("20m")
}
fn default_full() -> DurationSpec {
    dur("2h")
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            inline: default_inline(),
            queue: default_queue(),
            fast: default_fast(),
            full: default_full(),
        }
    }
}

/// R28: without `TOLLGATE_INLINE_CAP` a hook waits at most this long, so a
/// `git commit` returns under the 120 s Bash default timeout.
pub const DEFAULT_INLINE_CAP: Duration = Duration::from_secs(100);

/// L17: the cap the guard sets for a foreground Bash call (its timeout is
/// raised to 600 s).
pub const FOREGROUND_INLINE_CAP: Duration = Duration::from_secs(540);

impl Budgets {
    /// The host budgets with the repo's overrides applied (R33).
    #[must_use]
    pub fn with_overrides(&self, repo: &BudgetOverrides) -> Self {
        Self {
            inline: repo.inline.clone().unwrap_or_else(|| self.inline.clone()),
            queue: repo.queue.clone().unwrap_or_else(|| self.queue.clone()),
            fast: repo.fast.clone().unwrap_or_else(|| self.fast.clone()),
            full: repo.full.clone().unwrap_or_else(|| self.full.clone()),
        }
    }

    /// The wall-clock limit of a job of `tier` (R33).
    #[must_use]
    pub fn job_limit(&self, tier: Tier) -> Duration {
        match tier {
            Tier::Fast => self.fast.get(),
            Tier::Full => self.full.get(),
        }
    }

    /// The inline budget of a hook for a job of `tier` (R28 as changed by
    /// L17).
    ///
    /// - `TOLLGATE_INLINE_CAP` set (the guard sets 540 s for a foreground
    ///   Bash call, the `fast` budget for `run_in_background`): that many
    ///   seconds, at most the tier's job budget. The env value can lengthen
    ///   the wait only up to a config value, and shorten it at will.
    /// - Not set, or not a number: `budget.inline`, at most 100 s, so the hook
    ///   returns before the 120 s Bash default timeout.
    #[must_use]
    pub fn inline_for_hook(&self, inline_cap_env: Option<&str>, tier: Tier) -> Duration {
        match inline_cap_env.and_then(|v| v.trim().parse::<u64>().ok()) {
            Some(secs) => Duration::from_secs(secs).min(self.job_limit(tier)),
            None => self.inline.get().min(DEFAULT_INLINE_CAP),
        }
    }
}

/// `[job]` (R52).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobConfig {
    /// Dirs put before the built-in PATH.
    #[serde(default)]
    pub path_prepend: Vec<String>,
    /// Pass `SSH_AUTH_SOCK` to jobs.
    #[serde(default)]
    pub allow_ssh_agent: bool,
    /// Extra job environment.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// `CARGO_HOME` of jobs (`~` expands); default `<home>/.cargo`. Never
    /// taken from the environment that started the job (item 38).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cargo_home: Option<String>,
    /// `RUSTUP_HOME` of jobs (`~` expands); default `<home>/.rustup`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rustup_home: Option<String>,
    /// The host tool configs jobs may read (`$CARGO_HOME/config.toml`,
    /// rustfmt's home and config dir files; `~` expands), each with the
    /// blake3 of the content a person approved. Any other host tool
    /// config fails the job (item 35, review note 12).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub host_tool_configs: BTreeMap<String, String>,
}

/// Error when the host config cannot be read or parsed.
#[derive(Debug, thiserror::Error)]
pub enum HostConfigError {
    /// Read failed.
    #[error("cannot read {path}: {source}")]
    Io {
        /// File.
        path: PathBuf,
        /// Cause.
        #[source]
        source: std::io::Error,
    },
    /// TOML or schema error.
    #[error("{path}: {message}")]
    Parse {
        /// File.
        path: PathBuf,
        /// Parser message with line and column.
        message: String,
    },
}

/// A loaded host config and what the fingerprint needs from it.
#[derive(Debug, Clone)]
pub struct LoadedHost {
    /// The config (defaults when the file is absent).
    pub config: HostConfig,
    /// blake3 of the file bytes, or of nothing when absent (R74).
    pub hash: String,
    /// The file path.
    pub path: PathBuf,
    /// True when the file exists.
    pub exists: bool,
}

impl HostConfig {
    /// Parses TOML text.
    pub fn from_toml(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// Reads the host config file; defaults when it does not exist.
    pub fn load(dirs: &Dirs) -> Result<LoadedHost, HostConfigError> {
        let path = dirs.host_config_file();
        let bytes = fsx::read_optional(&path).map_err(|source| HostConfigError::Io {
            path: path.clone(),
            source,
        })?;
        let exists = bytes.is_some();
        let bytes = bytes.unwrap_or_default();
        let text = String::from_utf8(bytes.clone()).map_err(|e| HostConfigError::Parse {
            path: path.clone(),
            message: format!("not UTF-8: {e}"),
        })?;
        let config = Self::from_toml(&text).map_err(|e| HostConfigError::Parse {
            path: path.clone(),
            message: e.to_string(),
        })?;
        Ok(LoadedHost {
            config,
            hash: blake3::hash(&bytes).to_hex().to_string(),
            path,
            exists,
        })
    }

    /// True when the config or the L5 defaults name `resource`.
    #[must_use]
    pub fn resource_defined(&self, resource: &ResourceName) -> bool {
        self.resources.contains_key(resource)
            || DEFAULT_RESOURCES
                .iter()
                .any(|(n, _)| *n == resource.as_str())
    }

    /// Slots of `resource`: the config value, else the L5 default, else 1.
    #[must_use]
    pub fn resource_slots(&self, resource: &ResourceName) -> u32 {
        if let Some(spec) = self.resources.get(resource) {
            return spec.slots();
        }
        DEFAULT_RESOURCES
            .iter()
            .find(|(n, _)| *n == resource.as_str())
            .map_or(UNDEFINED_RESOURCE_SLOTS, |(_, n)| *n)
    }

    /// The image of `resource`, when configured (R74).
    #[must_use]
    pub fn resource_image(&self, resource: &ResourceName) -> Option<&str> {
        self.resources.get(resource).and_then(ResourceSpec::image)
    }

    /// Checks values the schema cannot express.
    #[must_use]
    pub fn validate(&self) -> Validation {
        let mut v = Validation::default();
        for (field, pats) in [
            ("scope.remotes", &self.scope.remotes),
            ("scope.include", &self.scope.include),
            ("scope.exclude", &self.scope.exclude),
        ] {
            for p in pats {
                if let Err(e) = glob::check(p) {
                    v.error(field, e);
                }
            }
        }
        for (field, home) in [
            ("job.cargo_home", &self.job.cargo_home),
            ("job.rustup_home", &self.job.rustup_home),
        ] {
            if let Some(h) = home
                && !(h.starts_with('/') || h == "~" || h.starts_with("~/"))
            {
                v.error(field, format!("{h:?} must be absolute or start with ~/"));
            }
        }
        for (p, hash) in &self.job.host_tool_configs {
            if !(p.starts_with('/') || p.starts_with("~/")) {
                v.error(
                    "job.host_tool_configs",
                    format!("{p:?} must be absolute or start with ~/"),
                );
            }
            if hash.len() != 64 || !hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                v.error(
                    "job.host_tool_configs",
                    format!("{p:?}: {hash:?} is not a blake3 digest (64 lowercase hex)"),
                );
            }
        }
        for p in &self.scope.trusted_paths {
            if !p.starts_with('/') {
                v.error(
                    "scope.trusted_paths",
                    format!("{p:?} must be an absolute path (item 34)"),
                );
            }
        }
        for r in &self.scope.roots {
            if !(r.starts_with('/') || r == "~" || r.starts_with("~/")) {
                v.error(
                    "scope.roots",
                    format!("{r:?} must be absolute or start with ~/"),
                );
            }
        }
        for (name, spec) in &self.resources {
            if spec.slots() == 0 {
                v.error(format!("resources.{name}"), "slots must be at least 1");
            }
            if spec.image().is_some_and(|i| i.trim().is_empty()) {
                v.error(format!("resources.{name}"), "empty image");
            }
        }
        if self.nextest.pg_max_threads == 0 {
            v.error("nextest.pg_max_threads", "must be at least 1");
        }
        if self.nextest.terminate_after == 0 {
            v.error("nextest.terminate_after", "must be at least 1");
        }
        if self.verify.max_checkouts == 0 || self.verify.max_full_checkouts == 0 {
            v.error(
                "verify.max_checkouts",
                "max_checkouts and max_full_checkouts must be at least 1",
            );
        }
        if let Some(r) = &self.verify.root
            && !(r.starts_with('/') || r.starts_with("~/"))
        {
            v.error(
                "verify.root",
                format!("{r:?} must be absolute or start with ~/"),
            );
        }
        for p in &self.job.path_prepend {
            if !(p.starts_with('/') || p.starts_with("~/")) {
                v.error(
                    "job.path_prepend",
                    format!("{p:?} must be absolute or start with ~/"),
                );
            }
            if p.contains(':') {
                v.error("job.path_prepend", format!("{p:?} contains ':'"));
            }
        }
        for (k, val) in &self.job.env {
            if let Err(e) = check_env_key(k) {
                v.error("job.env", e);
            }
            if val.contains('\0') {
                v.error("job.env", format!("{k}: value contains NUL"));
            }
        }
        v
    }

    /// The host config `install` writes when none exists (R95d). It names no
    /// user's repos or disks: `scope.remotes` and `scope.include` start empty
    /// (no repo is gated until the user names one) and the verify root is the
    /// default under the state dir (R41). The slot counts are the L5 values.
    /// On macOS Homebrew is on the job PATH.
    #[must_use]
    pub fn template(platform: Platform) -> String {
        let (path_prepend, resources) = match platform {
            Platform::Linux => ("path_prepend = []", "cpu = 3\npg = { slots = 2 }\n"),
            Platform::Macos => (
                "path_prepend = [\"/opt/homebrew/bin\"]",
                "# Q13: Mac values not decided; L5 values below.\ncpu = 3\npg = { slots = 2 }\n",
            ),
        };
        format!(
            r#"# tollgate host config (R84). Written by `tollgate install` when absent.

[scope]
roots = ["~/Repos"]   # repos directly under these dirs can be gated
# Trusted remotes: pushes to them run the full tier, and policy comes from
# their main. Example: ["*github.com:you/*", "*github.com/you/*"]
remotes = []
# Repo names to gate. Start with one repo (["myapp"]); ["*"] gates all.
include = []
exclude = []

[resources]
{resources}
[nextest]
pg_max_threads = 12   # test threads per pg slot
retries = 2
slow_timeout = "120s"
terminate_after = 2
global_timeout_fast = "15m"
global_timeout_full = "100m"

[verify]
# root defaults to ~/.local/state/tollgate/verify. Put it on a fast disk
# with room for build dirs: root = "/path/to/ssd/tollgate/verify"
max_checkouts = 12       # L15: sticky fast checkouts per repo clone, LRU
max_full_checkouts = 4
min_free = "30G"
max_target = "40G"

[budget]
inline = "100s"
queue = "30m"
fast = "20m"
full = "2h"

[job]
{path_prepend}
allow_ssh_agent = false
# cargo_home = "~/.cargo"     # item 38: jobs never take these from the hook's env
# rustup_home = "~/.rustup"
# Host tool configs jobs may read (cargo, rustfmt, bun, uv user configs),
# each with the blake3 of its reviewed content (`tollgate doctor` prints
# it); any other one fails every job.
# host_tool_configs = {{ "~/.cargo/config.toml" = "<blake3>" }}
[job.env]
# Variables every step gets, for example SQLX_OFFLINE = "true"
"#
        )
    }
}

/// The trusted remotes of `[scope]` (item 34, R14(2), R56, L2 anchors): a
/// parsed https or ssh URL that a `scope.remotes` pattern names exactly
/// (host, port, path by segment), or a local path or `file://` URL that is
/// one of `scope.trusted_paths`. [`CompiledScope::remote_trusted`] and the
/// post hook's cheap check (item 37) read trust through this one type, so
/// they never disagree on a URL.
#[derive(Debug, Clone)]
pub struct TrustedUrls {
    trust: Vec<super::trust::TrustPattern>,
    trusted_paths: Vec<PathBuf>,
}

impl TrustedUrls {
    /// Compiles the trust part of `scope` alone, without the rest of it
    /// (item 37: a post hook needs only this).
    pub fn new(scope: &ScopeConfig) -> Result<Self, String> {
        Ok(Self {
            trust: scope
                .remotes
                .iter()
                .filter_map(|p| super::trust::TrustPattern::parse(p))
                .collect(),
            // Item 48: a trusted path that does not exist, or is not its own
            // canonical path (a symlink part could be moved), trusts nothing.
            trusted_paths: scope
                .trusted_paths
                .iter()
                .filter(|p| !p.starts_with("file:"))
                .filter_map(|p| super::trust::local_path(p))
                .collect(),
        })
    }

    /// True when `url` is a trusted remote.
    #[must_use]
    pub fn matches(&self, url: &str) -> bool {
        if let Some(u) = super::trust::parse_url(url) {
            return self.trust.iter().any(|p| p.matches(&u));
        }
        super::trust::local_path(url).is_some_and(|p| self.trusted_paths.contains(&p))
    }
}

/// `[scope]` compiled for matching (L4).
#[derive(Debug, Clone)]
pub struct CompiledScope {
    roots: Vec<PathBuf>,
    remotes: GlobSet,
    trusted: TrustedUrls,
    noncanonical_paths: Vec<(String, PathBuf)>,
    include: GlobSet,
    exclude: GlobSet,
}

impl CompiledScope {
    /// Compiles the scope. Roots are canonicalized; a root that does not
    /// exist is skipped.
    pub fn new(scope: &ScopeConfig, dirs: &Dirs) -> Result<Self, String> {
        let roots = scope
            .roots
            .iter()
            .filter_map(|r| std::fs::canonicalize(dirs.expand_tilde(r)).ok())
            .collect();
        // Remote URLs: case-insensitive and `*` crosses `/`, so a URL spelled
        // differently still counts as in scope (errs toward gating).
        let loose_ci = GlobOpts {
            case_insensitive: true,
            literal_separator: false,
        };
        let names = GlobOpts {
            case_insensitive: false,
            literal_separator: false,
        };
        Ok(Self {
            roots,
            remotes: glob::compile(&scope.remotes, loose_ci)?,
            trusted: TrustedUrls::new(scope)?,
            noncanonical_paths: scope
                .trusted_paths
                .iter()
                .filter(|p| !p.starts_with("file:"))
                .filter(|p| super::trust::local_path(p).is_none())
                .filter_map(|p| Some((p.clone(), super::trust::canonical_local(p)?)))
                .collect(),
            include: glob::compile(&scope.include, names)?,
            exclude: glob::compile(&scope.exclude, names)?,
        })
    }

    /// Item 48: a local remote URL that names a `scope.trusted_paths` dir
    /// by another spelling (a symlink part, `..`, a trailing `/`), so it
    /// is not trusted: the canonical path to use instead.
    #[must_use]
    pub fn trusted_path_respelled(&self, url: &str) -> Option<PathBuf> {
        if super::trust::local_path(url).is_some() {
            return None;
        }
        super::trust::canonical_local(url).filter(|c| self.trusted.trusted_paths.contains(c))
    }

    /// Item 48: `scope.trusted_paths` entries that exist but are not their
    /// canonical path (they trust nothing), with that path.
    #[must_use]
    pub fn noncanonical_trusted_paths(&self) -> Vec<(String, PathBuf)> {
        self.noncanonical_paths.clone()
    }

    /// Item 34: `url` is a trusted remote ([`TrustedUrls`]).
    #[must_use]
    pub fn remote_trusted(&self, url: &str) -> bool {
        self.trusted.matches(url)
    }

    /// `url` puts a repo in scope and gates pushes to it (L4, R5, R20):
    /// the loose `scope.remotes` match (case-insensitive, `*` crosses
    /// `/`: look-alikes are gated too) or [`Self::remote_trusted`].
    #[must_use]
    pub fn remote_in_scope(&self, url: &str) -> bool {
        self.remotes.is_match(url) || self.remote_trusted(url)
    }

    /// True when `include`/`exclude` allow the repo name `name`.
    #[must_use]
    pub fn name_allowed(&self, name: &str) -> bool {
        self.include.is_match(name) && !self.exclude.is_match(name)
    }

    /// L4: in scope when a remote URL is trusted or `repo_dir` (realpath of
    /// the parent of the common dir) is a direct child of a root, and the
    /// basename passes `include`/`exclude`. A trusted remote also counts
    /// when its project name (the URL's last path part without `.git`)
    /// passes them: a clone renamed during rollout (R98 step 1) stays in
    /// scope (R4 reason, R5).
    #[must_use]
    pub fn contains(&self, repo_dir: &Path, remote_urls: &[String]) -> bool {
        let base = repo_dir.file_name().and_then(|n| n.to_str());
        let by_project = remote_urls.iter().any(|u| {
            self.remote_in_scope(u) && remote_project_name(u).is_some_and(|n| self.name_allowed(n))
        });
        if by_project {
            return true;
        }
        let Some(base) = base else {
            return false;
        };
        if !self.name_allowed(base) {
            return false;
        }
        remote_urls.iter().any(|u| self.remote_in_scope(u))
            || repo_dir
                .parent()
                .is_some_and(|p| self.roots.iter().any(|r| r == p))
    }
}

/// The project name of a remote URL: its last path part without `.git`
/// (`git@host:group/proj.git` -> `proj`).
#[must_use]
pub fn remote_project_name(url: &str) -> Option<&str> {
    let trimmed = url.trim_end_matches('/');
    let last = trimmed.rsplit(['/', ':']).next()?;
    let name = last.strip_suffix(".git").unwrap_or(last);
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::EnvSnapshot;

    fn rn(s: &str) -> ResourceName {
        ResourceName::parse(s).unwrap()
    }

    #[test]
    fn empty_file_gives_l5_defaults() {
        let c = HostConfig::from_toml("").unwrap();
        assert_eq!(c, HostConfig::default());
        assert_eq!(c.verify.max_checkouts(Tier::Fast), 12);
        assert_eq!(c.verify.max_checkouts(Tier::Full), 4);
        assert_eq!(c.resource_slots(&rn("cpu")), 3);
        assert_eq!(c.resource_slots(&rn("pg")), 2);
        assert_eq!(c.resource_slots(&rn("minio")), 1);
        assert!(!c.resource_defined(&rn("minio")));
        assert_eq!(c.nextest.pg_max_threads, 12);
        assert_eq!(c.nextest.retries, 2);
        assert_eq!(c.budget.inline.get().as_secs(), 100);
        assert_eq!(c.budget.queue.get().as_secs(), 1800);
        assert_eq!(c.verify.min_free.bytes(), 30 << 30);
        assert_eq!(c.scope.roots, ["~/Repos"]);
        assert_eq!(c.scope.include, ["*"]);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn r84_example_parses() {
        let c = HostConfig::from_toml(
            r#"
[scope]
roots = ["~/Repos"]
remotes = ["*gitlab.com:example-org/*", "*gitlab.com/example-org/*"]
include = ["example-repo", "other-repo"]
exclude = ["agent_v"]

[resources]
cpu = 2
pg = { slots = 1, image = "postgres:16" }
minio = { slots = 1, image = "minio/minio" }

[nextest]
pg_max_threads = 8
retries = 2
slow_timeout = "120s"
terminate_after = 2
global_timeout_fast = "15m"
global_timeout_full = "100m"

[verify]
root = "/mnt/data1/tollgate/verify"
max_checkouts = 6
max_full_checkouts = 2
min_free = "30G"
max_target = "40G"

[budget]
inline = "100s"
queue = "30m"
fast = "20m"
full = "2h"

[job]
path_prepend = []
allow_ssh_agent = false
[job.env]
SQLX_OFFLINE = "true"
"#,
        )
        .unwrap();
        assert!(c.validate().is_ok(), "{:?}", c.validate());
        assert_eq!(c.resource_slots(&rn("cpu")), 2);
        assert_eq!(c.resource_slots(&rn("pg")), 1);
        assert_eq!(c.resource_image(&rn("pg")), Some("postgres:16"));
        assert_eq!(c.resource_image(&rn("cpu")), None);
        assert_eq!(c.verify.max_checkouts(Tier::Full), 2);
        assert_eq!(c.job.env["SQLX_OFFLINE"], "true");
    }

    #[test]
    fn templates_parse_validate_and_carry_l5() {
        for p in [Platform::Linux, Platform::Macos] {
            let text = HostConfig::template(p);
            let c = HostConfig::from_toml(&text).unwrap_or_else(|e| panic!("{p:?}: {e}\n{text}"));
            assert!(c.validate().is_ok(), "{p:?}: {:?}", c.validate());
            assert_eq!(c.verify.max_checkouts(Tier::Fast), 12);
            assert_eq!(c.verify.max_checkouts(Tier::Full), 4);
            assert_eq!(c.resource_slots(&rn("cpu")), 3);
            assert_eq!(c.resource_slots(&rn("pg")), 2);
            assert_eq!(c.nextest.pg_max_threads, 12);
            // Neutral: no user's repos, remotes, disks or env.
            assert!(c.scope.include.is_empty());
            assert!(c.scope.remotes.is_empty());
            assert_eq!(c.verify.root, None);
            assert!(c.job.env.is_empty());
        }
        let mac = HostConfig::from_toml(&HostConfig::template(Platform::Macos)).unwrap();
        assert_eq!(mac.verify.root, None);
        assert_eq!(mac.job.path_prepend, ["/opt/homebrew/bin"]);
    }

    #[test]
    fn unknown_keys_and_bad_values_fail() {
        assert!(HostConfig::from_toml("[verify]\nslotz = 2\n").is_err());
        // L15: verify.slots is CUT.
        assert!(HostConfig::from_toml("[verify]\nslots = { fast = 3, full = 2 }\n").is_err());
        assert!(HostConfig::from_toml("[budget]\ninline = \"0s\"\n").is_err());
        assert!(HostConfig::from_toml("[resources]\n\"../x\" = 1\n").is_err());
        let c = HostConfig::from_toml(
            "[resources]\ncpu = 0\n[verify]\nroot = \"rel\"\nmax_checkouts = 0\n[job]\npath_prepend = [\"bin\"]\nenv = { GIT_DIR = \"x\" }\n[scope]\nroots = [\"Repos\"]\n",
        )
        .unwrap();
        let errs: Vec<String> = c
            .validate()
            .errors
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(errs.len(), 6, "{errs:?}");
        // Item 35: approved host tool configs name a path and a digest.
        let good = "a".repeat(64);
        let c = HostConfig::from_toml(&format!(
            "[job.host_tool_configs]\n\"~/.cargo/config.toml\" = \"{good}\"\n\".rustfmt.toml\" = \"{good}\"\n\"/h/x\" = \"{}\"\n",
            "A".repeat(64)
        ))
        .unwrap();
        let errs: Vec<String> = c
            .validate()
            .errors
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(errs.len(), 2, "{errs:?}");
    }

    #[test]
    fn repo_budgets_override_host_r33() {
        let host = Budgets::default();
        let repo = BudgetOverrides {
            full: Some(DurationSpec::parse("3h").unwrap()),
            ..BudgetOverrides::default()
        };
        let b = host.with_overrides(&repo);
        assert_eq!(b.job_limit(Tier::Full).as_secs(), 3 * 3600);
        assert_eq!(b.job_limit(Tier::Fast).as_secs(), 20 * 60);
    }

    #[test]
    fn inline_budget_r28_l17() {
        let mut b = Budgets::default();
        assert_eq!(b.inline_for_hook(None, Tier::Fast).as_secs(), 100);
        assert_eq!(b.inline_for_hook(Some("junk"), Tier::Fast).as_secs(), 100);
        assert_eq!(b.inline_for_hook(Some("2"), Tier::Fast).as_secs(), 2);
        // Foreground Bash call: the guard's 540 s.
        assert_eq!(
            b.inline_for_hook(Some("540"), Tier::Fast),
            FOREGROUND_INLINE_CAP
        );
        // Background Bash call: up to the fast budget, never beyond the
        // tier's job budget.
        assert_eq!(b.inline_for_hook(Some("1200"), Tier::Fast).as_secs(), 1200);
        assert_eq!(b.inline_for_hook(Some("99999"), Tier::Fast).as_secs(), 1200);
        assert_eq!(b.inline_for_hook(Some("99999"), Tier::Full).as_secs(), 7200);
        // Without the cap, budget.inline above 100 s still waits 100 s.
        b.inline = DurationSpec::parse("600s").unwrap();
        assert_eq!(b.inline_for_hook(None, Tier::Fast).as_secs(), 100);
        b.inline = DurationSpec::parse("30s").unwrap();
        assert_eq!(b.inline_for_hook(None, Tier::Fast).as_secs(), 30);
    }

    #[test]
    fn load_hashes_the_file_and_defaults_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = Dirs::from_env(&EnvSnapshot::from_pairs([
            ("HOME", tmp.path().as_os_str()),
            ("XDG_CONFIG_HOME", tmp.path().join("cfg").as_os_str()),
        ]))
        .unwrap();
        let absent = HostConfig::load(&dirs).unwrap();
        assert!(!absent.exists);
        assert_eq!(absent.config, HostConfig::default());
        fsx::write_atomic(&dirs.host_config_file(), b"[resources]\ncpu = 5\n").unwrap();
        let present = HostConfig::load(&dirs).unwrap();
        assert!(present.exists);
        assert_eq!(present.config.resource_slots(&rn("cpu")), 5);
        assert_ne!(absent.hash, present.hash);
        fsx::write_atomic(&dirs.host_config_file(), b"[resources\n").unwrap();
        let err = HostConfig::load(&dirs).unwrap_err().to_string();
        assert!(err.contains("config.toml"), "{err}");
    }

    /// Item 34 (X5): trust parses the URL: allowed schemes (https, ssh,
    /// scp-like), the exact host, the path per segment (`*` never crosses
    /// `/`). Local paths and `file://` never match a pattern; only
    /// `scope.trusted_paths` names them. Scope stays loose (more gating).
    #[test]
    fn trust_parses_urls_scope_stays_loose_item34() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().canonicalize().unwrap();
        let mirror = home.join("mirror/r.git");
        std::fs::create_dir_all(&mirror).unwrap();
        let dirs = Dirs::from_env(&EnvSnapshot::from_pairs([("HOME", home.as_os_str())])).unwrap();
        let scope = ScopeConfig {
            remotes: vec![
                "*gitlab.com:example-org/*".into(),
                "*gitlab.com/example-org/*".into(),
            ],
            trusted_paths: vec![mirror.to_str().unwrap().to_owned()],
            ..ScopeConfig::default()
        };
        let s = CompiledScope::new(&scope, &dirs).unwrap();
        for url in [
            "git@gitlab.com:example-org/example-repo.git",
            "gitlab.com:example-org/example-repo",
            "ssh://git@gitlab.com/example-org/example-repo.git",
            "git+ssh://git@gitlab.com/example-org/example-repo.git",
            "https://gitlab.com/example-org/example-repo.git",
            "https://oauth2:token@GitLab.COM/example-org/example-repo",
            "https://gitlab.com/example-org/example-repo.git/",
        ] {
            assert!(s.remote_trusted(url), "{url} not trusted");
            assert!(s.remote_in_scope(url), "{url} not in scope");
        }
        for url in [
            // Local paths and file URLs that spell the host in a dir name.
            "/tmp/x/gitlab.com/example-org/r.git",
            "file:///tmp/x/gitlab.com/example-org/r.git",
            "../gitlab.com/example-org/r.git",
            // Another host with the trusted one in its path or name.
            "https://evil.example/gitlab.com/example-org/r",
            "https://gitlab.com.evil.example/example-org/r",
            "https://evilgitlab.com/example-org/r",
            "git@evil.example:gitlab.com/example-org/r",
            // Schemes without server authentication, a port, deeper paths.
            "http://gitlab.com/example-org/r.git",
            "git://gitlab.com/example-org/r.git",
            "ssh://git@gitlab.com:2222/example-org/r.git",
            "https://gitlab.com/example-org/group/r.git",
            "https://gitlab.com/example-org/../evil/r.git",
            "https://gitlab.com/example-org/%2e%2e",
            "https://gitlab.com//example-org/r.git",
            "https://gitlab.com/VictorKwak/r.git",
        ] {
            assert!(!s.remote_trusted(url), "{url} trusted");
        }
        // Loose matching still puts the look-alikes in scope.
        assert!(s.remote_in_scope("/tmp/x/gitlab.com/example-org/r.git"));
        assert!(s.remote_in_scope("https://evil.example/gitlab.com/example-org/r"));
        // trusted_paths: the exact canonical path, as a path or file URL.
        assert!(s.remote_trusted(mirror.to_str().unwrap()));
        assert!(s.remote_trusted(&format!("file://{}", mirror.display())));
        assert!(s.remote_in_scope(mirror.to_str().unwrap()));
        assert!(!s.remote_trusted(home.join("mirror").to_str().unwrap()));
        assert!(!s.remote_trusted(home.join("mirror/r.git/sub").to_str().unwrap()));
        // A relative trusted path is a config error.
        let bad = HostConfig::from_toml("[scope]\ntrusted_paths = [\"x/r.git\"]\n").unwrap();
        assert!(!bad.validate().is_ok());
    }

    /// Item 48: git uses the URL as spelled, so a symlink in it can point
    /// elsewhere by the time git reads it. A local URL is trusted only
    /// when it already is the canonical path (no symlink part, `.`, `..`,
    /// repeated or trailing `/`, `%`), and a `scope.trusted_paths` entry
    /// counts only when it is canonical itself. The other spellings
    /// report the canonical path to use.
    #[test]
    fn trusted_paths_need_the_canonical_spelling_item48() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().canonicalize().unwrap();
        let mirror = home.join("mirror/r.git");
        let other = home.join("other/o.git");
        std::fs::create_dir_all(&mirror).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let linked = home.join("link.git");
        std::os::unix::fs::symlink(&mirror, &linked).unwrap();
        std::os::unix::fs::symlink(home.join("mirror"), home.join("dirlink")).unwrap();
        std::os::unix::fs::symlink(&other, home.join("olink.git")).unwrap();
        let dirs = Dirs::from_env(&EnvSnapshot::from_pairs([("HOME", home.as_os_str())])).unwrap();
        let m = mirror.display();
        let scope = ScopeConfig {
            trusted_paths: vec![
                m.to_string(),
                // Not canonical: trusts nothing, not even its target.
                home.join("olink.git").display().to_string(),
            ],
            ..ScopeConfig::default()
        };
        let s = CompiledScope::new(&scope, &dirs).unwrap();
        assert!(s.remote_trusted(&m.to_string()));
        assert!(s.remote_trusted(&format!("file://{m}")));
        assert_eq!(s.trusted_path_respelled(&m.to_string()), None);
        for url in [
            linked.display().to_string(),
            format!("file://{}", linked.display()),
            home.join("dirlink/r.git").display().to_string(),
            format!("{m}/"),
            format!("file://{m}/"),
            format!("{}/./mirror/r.git", home.display()),
            format!("{}/mirror/../mirror/r.git", home.display()),
            format!("{}//mirror/r.git", home.display()),
            format!("file:///{m}"),
        ] {
            assert!(!s.remote_trusted(&url), "{url} trusted");
            assert_eq!(
                s.trusted_path_respelled(&url),
                Some(mirror.clone()),
                "{url}"
            );
        }
        // git decodes `%` in a file URL (`%41` is `A`), not in a path; it
        // runs `FILE://` through a helper on PATH.
        let pct = home.join("pct%41.git");
        std::fs::create_dir_all(&pct).unwrap();
        let scope2 = ScopeConfig {
            trusted_paths: vec![m.to_string(), pct.display().to_string()],
            ..ScopeConfig::default()
        };
        let s2 = CompiledScope::new(&scope2, &dirs).unwrap();
        assert!(s2.remote_trusted(&pct.display().to_string()));
        for url in [
            format!("file://{}", pct.display()),
            format!("FILE://{m}"),
            format!("file://localhost{m}"),
        ] {
            assert!(!s2.remote_trusted(&url), "{url} trusted");
        }
        for url in [
            other.display().to_string(),
            home.join("olink.git").display().to_string(),
        ] {
            assert!(!s.remote_trusted(&url), "{url} trusted");
        }
        assert_eq!(
            s.noncanonical_trusted_paths(),
            vec![(home.join("olink.git").display().to_string(), other.clone())]
        );
    }

    #[test]
    fn scope_l4_depth_one_remotes_include_exclude() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().canonicalize().unwrap();
        std::fs::create_dir_all(home.join("Repos/example-repo/target/fixture")).unwrap();
        std::fs::create_dir_all(home.join("Repos/agent_v")).unwrap();
        std::fs::create_dir_all(home.join("elsewhere/clone")).unwrap();
        let dirs = Dirs::from_env(&EnvSnapshot::from_pairs([("HOME", home.as_os_str())])).unwrap();
        let scope = ScopeConfig {
            roots: vec!["~/Repos".into(), "~/missing".into()],
            remotes: vec!["*gitlab.com:example-org/*".into()],
            trusted_paths: Vec::new(),
            include: vec!["*".into()],
            exclude: vec!["agent_v".into()],
        };
        let s = CompiledScope::new(&scope, &dirs).unwrap();
        let none: [String; 0] = [];
        assert!(s.contains(&home.join("Repos/example-repo"), &none));
        // Depth exactly 1: a fixture repo nested in a checkout is out.
        assert!(!s.contains(&home.join("Repos/example-repo/target/fixture"), &none));
        assert!(!s.contains(&home.join("Repos/agent_v"), &none));
        assert!(!s.contains(&home.join("elsewhere/clone"), &none));
        // A trusted remote puts a clone anywhere in scope (R5).
        let remote = ["git@GitLab.com:example-org/example-repo.git".to_owned()];
        assert!(s.contains(&home.join("elsewhere/clone"), &remote));
        assert!(s.remote_in_scope("git@gitlab.com:example-org/a/b.git"));
        assert!(
            !s.remote_trusted("git@gitlab.com:example-org/a/b.git"),
            "item 34"
        );
        assert!(s.remote_trusted("git@gitlab.com:example-org/b.git"));
        assert!(!s.remote_in_scope("git@github.com:example-org/example-repo.git"));
        // include/exclude still apply to remote matches: by the local name
        // or the project name; an excluded project in an excluded dir is
        // out, a clone of an allowed project is in whatever its dir name.
        assert!(s.contains(&home.join("elsewhere/agent_v"), &remote));
        let excluded = ["git@gitlab.com:example-org/agent_v.git".to_owned()];
        assert!(!s.contains(&home.join("elsewhere/agent_v"), &excluded));
        // Rollout: a renamed clone of an included project stays in scope by
        // its trusted remote's project name.
        let only = ScopeConfig {
            include: vec!["example-repo".into()],
            ..scope
        };
        let s = CompiledScope::new(&only, &dirs).unwrap();
        assert!(s.contains(&home.join("elsewhere/clone"), &remote));
        assert!(!s.contains(&home.join("elsewhere/clone"), &excluded));
        assert_eq!(
            remote_project_name("https://gitlab.com/a/b.git/"),
            Some("b")
        );
        assert_eq!(remote_project_name("git@gitlab.com:a/b"), Some("b"));
        assert_eq!(remote_project_name("/srv/repo.git"), Some("repo"));
    }
}
