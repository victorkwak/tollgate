//! Policy files and the policy commit (R49, R64, R69-R71, L2).
//!
//! L2: the policy commit is `git merge-base N <anchors>`. Anchors are the
//! trusted remotes' full refs (`refs/remotes/<trusted>/main`, ...); when
//! there are none, the local full refs; with no anchor at all, `N` itself.
//! Policy files (R71) come from that commit, so a branch cannot weaken the
//! checks that judge it: its own policy changes take effect after it merges
//! to a full ref. The approval flow and union rule are CUT (L2).
//!
//! Full refs for anchor discovery come from the built-in defaults first,
//! then from the `tollgate.toml` of the commit found that way (it sits on a
//! protected ref, so its `full_refs` can be trusted).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use globset::GlobSet;

use crate::config::glob::{self, GlobOpts};
use crate::config::repo::{RefRules, RepoConfig};
use crate::gitx::{Git, GitError, Oid, TreeEntry};
use crate::select::detect;

/// The repo config file (R63).
pub const CONFIG_FILE: &str = "tollgate.toml";

/// Built-in policy files (R71). `.config/nextest.toml` also one level down,
/// for a Rust root there; baselines at any depth.
const BUILTIN: &[&str] = &[
    "tollgate.toml",
    ".config/nextest.toml",
    "*/.config/nextest.toml",
    "**/.pyright-baseline.json",
    "**/.pytest-baseline.json",
];

/// Error while resolving the policy.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// A git call failed.
    #[error(transparent)]
    Git(#[from] GitError),
    /// The policy commit's `tollgate.toml` is unusable (R64).
    #[error("{0}")]
    Config(String),
}

/// Matches policy files (R71).
#[derive(Debug, Clone)]
pub struct PolicyMatcher {
    builtin: GlobSet,
    extra: GlobSet,
}

impl PolicyMatcher {
    /// The built-in policy files plus `policy.files` of `config`.
    pub fn new(config: &RepoConfig) -> Result<Self, String> {
        Ok(Self {
            builtin: glob::compile(
                BUILTIN,
                GlobOpts {
                    case_insensitive: false,
                    literal_separator: true,
                },
            )?,
            extra: glob::compile(
                &config.policy.files,
                GlobOpts {
                    case_insensitive: false,
                    literal_separator: false,
                },
            )?,
        })
    }

    /// True when `path` is a policy file.
    #[must_use]
    pub fn is_policy_file(&self, path: &Path) -> bool {
        self.builtin.is_match(path) || self.extra.is_match(path)
    }
}

/// The commit whose policy applies (L2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBase {
    /// The policy commit; `None` when there is no commit at all (unborn
    /// branch): the tree's own files apply.
    pub commit: Option<Oid>,
    /// The anchor ref, for the `POLICY:` line.
    pub anchor: Option<String>,
    /// Committer date of the policy commit (R69).
    pub committer_date: Option<jiff::civil::Date>,
}

/// The refs that anchor the policy (L2): full refs of trusted remotes, else
/// local full refs.
pub fn anchors(git: &Git, trusted: &[String], rules: &RefRules) -> Result<Vec<String>, GitError> {
    let full = |text: &[u8]| -> Vec<String> {
        String::from_utf8_lossy(text)
            .lines()
            .filter(|r| rules.tier_for_ref(r) == crate::config::Tier::Full)
            .map(str::to_owned)
            .collect()
    };
    if !trusted.is_empty() {
        let mut args = vec!["for-each-ref".to_owned(), "--format=%(refname)".to_owned()];
        args.extend(trusted.iter().map(|r| format!("refs/remotes/{r}/")));
        let remote = full(&git.run(&args)?);
        if !remote.is_empty() {
            return Ok(remote);
        }
    }
    Ok(full(&git.run([
        "for-each-ref",
        "--format=%(refname)",
        "refs/heads/",
    ])?))
}

/// The policy commit for new commit `tip` (L2).
pub fn policy_base(
    git: &Git,
    tip: Option<&Oid>,
    trusted: &[String],
    rules: &RefRules,
) -> Result<PolicyBase, GitError> {
    let Some(tip) = tip else {
        return Ok(PolicyBase {
            commit: None,
            anchor: None,
            committer_date: None,
        });
    };
    let anchors = anchors(git, trusted, rules)?;
    let (commit, anchor) = if anchors.is_empty() {
        (tip.clone(), None)
    } else {
        let mut args = vec!["merge-base".to_owned(), tip.to_string()];
        args.extend(anchors.iter().cloned());
        let out = git.output(&args)?;
        let commit = if out.status.success() {
            Oid::parse(String::from_utf8_lossy(&out.stdout).trim()).map_err(|detail| {
                GitError::Output {
                    args: "merge-base".into(),
                    detail,
                }
            })?
        } else {
            // No common history: the anchor's own policy applies, never the
            // branch's.
            git.rev_parse_verify(&format!("{}^{{commit}}", anchors[0]))?
                .ok_or_else(|| GitError::Output {
                    args: "rev-parse".into(),
                    detail: format!("anchor {} does not resolve", anchors[0]),
                })?
        };
        (commit, Some(anchors[0].clone()))
    };
    let date = git.run_line(["log", "-1", "--format=%cs", commit.as_str()])?;
    Ok(PolicyBase {
        committer_date: date.parse().ok(),
        commit: Some(commit),
        anchor,
    })
}

/// Where the effective config came from.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase", tag = "kind")]
pub enum ConfigSource {
    /// `tollgate.toml` of the policy commit (or of the tree with no commit).
    File {
        /// Blob id of the file.
        blob: Oid,
    },
    /// Detection (R65).
    Detected,
}

/// The resolved policy of one job.
#[derive(Debug, Clone)]
pub struct Policy {
    /// The policy commit.
    pub base: PolicyBase,
    /// The effective repo config.
    pub config: RepoConfig,
    /// Its source.
    pub source: ConfigSource,
    /// Notes from detection.
    pub notes: Vec<String>,
    /// Policy files of the policy commit: path -> blob.
    pub files: BTreeMap<PathBuf, Oid>,
    /// `.config/nextest.toml` contents of the policy commit by Rust root
    /// dir (R49).
    pub nextest_configs: BTreeMap<PathBuf, String>,
    /// Policy files that differ between the tree and the policy commit.
    pub changed: Vec<PathBuf>,
}

impl Policy {
    /// blake3 of the policy files' (path, blob) list: part of the
    /// fingerprint, so a policy change voids records (R74).
    #[must_use]
    pub fn files_hash(&self) -> String {
        let mut h = blake3::Hasher::new();
        for (p, oid) in &self.files {
            h.update(p.as_os_str().as_encoded_bytes());
            h.update(b"\0");
            h.update(oid.as_str().as_bytes());
            h.update(b"\0");
        }
        h.finalize().to_hex().to_string()
    }

    /// L2: the `POLICY:` line when the tree changes policy files.
    #[must_use]
    pub fn line(&self) -> Option<String> {
        if self.changed.is_empty() {
            return None;
        }
        let files: Vec<String> = self
            .changed
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        let commit = self
            .base
            .commit
            .as_ref()
            .map_or_else(|| "the tree".to_owned(), |c| c.short(12).to_owned());
        let target = self.base.anchor.as_deref().map_or_else(
            || "a full ref".to_owned(),
            |a| {
                a.strip_prefix("refs/remotes/")
                    .or_else(|| a.strip_prefix("refs/heads/"))
                    .unwrap_or(a)
                    .to_owned()
            },
        );
        Some(format!(
            "POLICY: this branch changes {}; checks use the policy of {commit} until it merges to {target}",
            files.join(", ")
        ))
    }
}

fn policy_entries(entries: &[TreeEntry], m: &PolicyMatcher) -> BTreeMap<PathBuf, Oid> {
    entries
        .iter()
        .filter(|e| e.kind == "blob" && m.is_policy_file(&e.path))
        .map(|e| (e.path.clone(), e.oid.clone()))
        .collect()
}

fn read_blob(git: &Git, oid: &Oid) -> Result<String, PolicyError> {
    let bytes = git.run(["cat-file", "blob", oid.as_str()])?;
    String::from_utf8(bytes).map_err(|e| PolicyError::Config(format!("blob {oid}: not UTF-8: {e}")))
}

fn config_at(git: &Git, entries: &[TreeEntry]) -> Result<Option<(Oid, RepoConfig)>, PolicyError> {
    let Some(e) = entries
        .iter()
        .find(|e| e.path == Path::new(CONFIG_FILE) && e.kind == "blob")
    else {
        return Ok(None);
    };
    let text = read_blob(git, &e.oid)?;
    let config = RepoConfig::from_toml(&text)
        .map_err(|err| PolicyError::Config(format!("{CONFIG_FILE} at the policy commit: {err}")))?;
    Ok(Some((e.oid.clone(), config)))
}

/// Resolves the policy of a job on tree `tree_entries` whose new commit is
/// `tip` (L2, R49, R65, R71).
pub fn resolve(
    git: &Git,
    tree_entries: &[TreeEntry],
    tip: Option<&Oid>,
    trusted: &[String],
) -> Result<Policy, PolicyError> {
    let default_rules = RepoConfig::default()
        .ref_rules()
        .map_err(PolicyError::Config)?;
    let mut base = policy_base(git, tip, trusted, &default_rules)?;
    let mut base_entries = match &base.commit {
        Some(c) => git.ls_tree(c)?,
        None => tree_entries.to_vec(),
    };
    let mut found = config_at(git, &base_entries)?;
    if let Some((_, c)) = &found
        && c.tiers.full_refs != RepoConfig::default().tiers.full_refs
    {
        let rules = c.ref_rules().map_err(PolicyError::Config)?;
        let again = policy_base(git, tip, trusted, &rules)?;
        if again.commit != base.commit {
            base = again;
            base_entries = match &base.commit {
                Some(c) => git.ls_tree(c)?,
                None => tree_entries.to_vec(),
            };
            found = config_at(git, &base_entries)?;
        }
    }
    let (config, source, notes) = match found {
        Some((blob, c)) => (c, ConfigSource::File { blob }, Vec::new()),
        None => {
            let (c, notes) = detect::detected_config(&detect::roots_from_tree(tree_entries));
            (c, ConfigSource::Detected, notes)
        }
    };
    let matcher = PolicyMatcher::new(&config).map_err(PolicyError::Config)?;
    let files = policy_entries(&base_entries, &matcher);
    let mine = policy_entries(tree_entries, &matcher);
    let mut changed: Vec<PathBuf> = files
        .iter()
        .filter(|(p, oid)| mine.get(*p) != Some(*oid))
        .map(|(p, _)| p.clone())
        .chain(mine.keys().filter(|p| !files.contains_key(*p)).cloned())
        .collect();
    changed.sort();
    changed.dedup();
    let mut nextest_configs = BTreeMap::new();
    for (p, oid) in &files {
        if p.ends_with(".config/nextest.toml") {
            let root = p
                .parent()
                .and_then(Path::parent)
                .map(Path::to_owned)
                .unwrap_or_default();
            nextest_configs.insert(root, read_blob(git, oid)?);
        }
    }
    Ok(Policy {
        base,
        config,
        source,
        notes,
        files,
        nextest_configs,
        changed,
    })
}
