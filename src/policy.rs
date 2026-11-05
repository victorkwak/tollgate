//! Policy files and the policy commit (R49, R64, R69-R71, L2).
//!
//! L2: the policy commit is `git merge-base N <anchor>` for the first
//! usable anchor in priority order. Anchors are exact, case-sensitive
//! branch names (`policy.anchors`, default `main`, `master`; never
//! `integration/*`): the trusted remotes' `refs/remotes/<r>/<name>` first;
//! only when no trusted remote is configured, the local `refs/heads/<name>`.
//! The job's own ref is never an anchor, and a local anchor that already
//! contains `N` is skipped. Trusted remotes with none of their anchor refs
//! fetched deny (no local fallback). With no usable anchor, `N` itself.
//! Policy files (R71) come from that commit, so a branch cannot weaken the
//! checks that judge it: its own policy changes take effect after it merges
//! to a full ref. The approval flow and union rule are CUT (L2).
//!
//! Anchor names come from the built-in defaults first, then from the
//! `tollgate.toml` of the commit found that way (it sits on a protected
//! ref, so its `policy.anchors` can be trusted).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use globset::GlobSet;

use crate::config::glob::{self, GlobOpts};
use crate::config::repo::RepoConfig;
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
    /// Trusted remotes are configured but none of their anchor refs exists
    /// locally (L2): deny until they are fetched.
    #[error("{0}")]
    NoAnchor(String),
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

/// One candidate anchor ref and its tip.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Anchor {
    refname: String,
    tip: Oid,
    /// A local branch: the agent can move it, so it must not contain the
    /// job's tip.
    local: bool,
}

/// Existing refs among `wanted`, in `wanted` order, matched exactly and
/// case-sensitively (`for-each-ref` patterns also match prefixes, and a
/// case-insensitive file system can fold loose ref names).
fn existing_refs(git: &Git, wanted: &[String]) -> Result<Vec<(String, Oid)>, GitError> {
    if wanted.is_empty() {
        return Ok(Vec::new());
    }
    let mut args = vec![
        "for-each-ref".to_owned(),
        "--format=%(objectname) %(refname)".to_owned(),
    ];
    args.extend(wanted.iter().cloned());
    let text = git.run(&args)?;
    let mut found: BTreeMap<String, Oid> = BTreeMap::new();
    for line in String::from_utf8_lossy(&text).lines() {
        if let Some((oid, name)) = line.split_once(' ')
            && let Ok(oid) = Oid::parse(oid)
        {
            found.insert(name.to_owned(), oid);
        }
    }
    Ok(wanted
        .iter()
        .filter_map(|w| found.get(w).map(|o| (w.clone(), o.clone())))
        .collect())
}

/// The anchor candidates of L2 in priority order: each trusted remote's
/// anchor branches (`refs/remotes/<r>/main`, then `.../master`), or, only
/// when no trusted remote is configured, the local anchor branches. The
/// job's own ref is never an anchor. Errors when trusted remotes are
/// configured but none of their anchor refs exists locally: falling back
/// to local refs would let an agent pick its own policy by deleting the
/// remote-tracking refs.
fn anchors(
    git: &Git,
    trusted: &[String],
    names: &[String],
    own_ref: Option<&str>,
) -> Result<Vec<Anchor>, PolicyError> {
    let names: Vec<&String> = names
        .iter()
        .filter(|n| crate::config::repo::valid_anchor(n))
        .collect();
    if !trusted.is_empty() {
        let wanted: Vec<String> = trusted
            .iter()
            .flat_map(|r| names.iter().map(move |n| format!("refs/remotes/{r}/{n}")))
            .collect();
        let found = existing_refs(git, &wanted)?;
        if found.is_empty() {
            return Err(PolicyError::NoAnchor(format!(
                "no policy anchor (L2): none of {} exists locally; fetch the trusted remote (git fetch {}), or push its first branch from your own terminal",
                wanted.join(", "),
                trusted[0]
            )));
        }
        return Ok(found
            .into_iter()
            .map(|(refname, tip)| Anchor {
                refname,
                tip,
                local: false,
            })
            .collect());
    }
    let wanted: Vec<String> = names.iter().map(|n| format!("refs/heads/{n}")).collect();
    Ok(existing_refs(git, &wanted)?
        .into_iter()
        .filter(|(r, _)| Some(r.as_str()) != own_ref)
        .map(|(refname, tip)| Anchor {
            refname,
            tip,
            local: true,
        })
        .collect())
}

/// True when `ancestor` is reachable from `descendant`.
fn is_ancestor(git: &Git, ancestor: &Oid, descendant: &Oid) -> Result<bool, GitError> {
    let out = git.output([
        "merge-base",
        "--is-ancestor",
        ancestor.as_str(),
        descendant.as_str(),
    ])?;
    match out.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(GitError::Output {
            args: "merge-base --is-ancestor".into(),
            detail: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        }),
    }
}

/// The policy commit for new commit `tip` on `own_ref` (L2).
///
/// The first usable anchor in priority order decides: its merge-base with
/// `tip`, or the anchor's own tip when the histories are unrelated. A
/// local anchor that already contains `tip` is skipped (its merge-base
/// would be `tip` itself, so a branch created or moved at the agent's own
/// tip would anchor the agent's own policy). With no usable anchor, `tip`
/// itself.
pub fn policy_base(
    git: &Git,
    tip: Option<&Oid>,
    trusted: &[String],
    anchor_names: &[String],
    own_ref: Option<&str>,
) -> Result<PolicyBase, PolicyError> {
    let Some(tip) = tip else {
        return Ok(PolicyBase {
            commit: None,
            anchor: None,
            committer_date: None,
        });
    };
    let mut chosen = None;
    for a in anchors(git, trusted, anchor_names, own_ref)? {
        if a.local && is_ancestor(git, tip, &a.tip)? {
            continue;
        }
        let out = git.output(["merge-base", tip.as_str(), a.tip.as_str()])?;
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
            a.tip.clone()
        };
        chosen = Some((commit, a.refname));
        break;
    }
    let (commit, anchor) = match chosen {
        Some((c, a)) => (c, Some(a)),
        None => (tip.clone(), None),
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
/// `tip` on ref `own_ref` (L2, R49, R65, R71).
pub fn resolve(
    git: &Git,
    tree_entries: &[TreeEntry],
    tip: Option<&Oid>,
    trusted: &[String],
    own_ref: Option<&str>,
) -> Result<Policy, PolicyError> {
    let default_anchors = RepoConfig::default().policy.anchors;
    let mut base = policy_base(git, tip, trusted, &default_anchors, own_ref)?;
    let mut base_entries = match &base.commit {
        Some(c) => git.ls_tree(c)?,
        None => tree_entries.to_vec(),
    };
    let mut found = config_at(git, &base_entries)?;
    // The anchor commit's own config may name other anchors; it sits on a
    // protected ref, so its list can be trusted.
    if base.anchor.is_some()
        && let Some((_, c)) = &found
        && c.policy.anchors != default_anchors
    {
        let again = policy_base(git, tip, trusted, &c.policy.anchors, own_ref)?;
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
