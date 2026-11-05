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
//!
//! A remote-tracking anchor is a local file anyone can move (`fetch .`,
//! `update-ref`), so its commit is the newest value the trusted server
//! reported for the branch ([`crate::remote_refs`]); when the server
//! confirms none that the repo has, the anchor is unusable, and with no
//! usable remote anchor left the policy denies.
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
use crate::remote_refs::RemoteRefs;
use crate::select::detect;

/// The repo config file (R63).
pub const CONFIG_FILE: &str = "tollgate.toml";

/// Built-in policy files (R71). `.config/nextest.toml` also one level down,
/// for a Rust root there; baselines and [`TOOL_CONFIGS`] at any depth.
const BUILTIN: &[&str] = &[
    "tollgate.toml",
    ".config/nextest.toml",
    "*/.config/nextest.toml",
    "**/.pyright-baseline.json",
    "**/.pytest-baseline.json",
    "**/.cargo/config.toml",
    "**/.cargo/config",
    "**/clippy.toml",
    "**/.clippy.toml",
    "**/rustfmt.toml",
    "**/.rustfmt.toml",
];

/// Tool configs that steps read from the checkout itself (R71): cargo
/// config (target runners, aliases, rustflags, env) and clippy and rustfmt
/// config. A branch could weaken every check with one of them, so a job
/// replaces each in the verify checkout with the policy commit's version
/// ([`Policy::overlay`]); cargo reads config from the step's dir and its
/// parents, clippy and rustfmt from package and source dirs, so any depth.
const TOOL_CONFIGS: &[&str] = &[
    "**/.cargo/config.toml",
    "**/.cargo/config",
    "**/clippy.toml",
    "**/.clippy.toml",
    "**/rustfmt.toml",
    "**/.rustfmt.toml",
];

/// What the verify checkout must hold at one tool-config path (R71): the
/// policy commit's version, or nothing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase", tag = "kind")]
pub enum OverlayFile {
    /// The policy commit has no file there: remove the tree's.
    Absent,
    /// A regular file with this content.
    File {
        /// Content.
        text: String,
        /// Mode 100755.
        executable: bool,
    },
    /// A symlink with this target.
    Symlink {
        /// Link target.
        target: String,
    },
}

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
/// configured but none of their anchor refs exists locally, or the
/// trusted server confirms none of them: falling back to local refs would
/// let an agent pick its own policy by deleting or forging the
/// remote-tracking refs.
fn anchors(
    git: &Git,
    remotes: &RemoteRefs,
    names: &[String],
    own_ref: Option<&str>,
) -> Result<Vec<Anchor>, PolicyError> {
    let names: Vec<&String> = names
        .iter()
        .filter(|n| crate::config::repo::valid_anchor(n))
        .collect();
    if !remotes.is_empty() {
        let pairs: Vec<(&crate::remote_refs::TrustedRemote, &String)> = remotes
            .remotes()
            .iter()
            .flat_map(|r| names.iter().map(move |n| (r, *n)))
            .collect();
        let wanted: Vec<String> = pairs
            .iter()
            .map(|(r, n)| format!("refs/remotes/{}/{n}", r.name))
            .collect();
        let found: BTreeMap<String, Oid> = existing_refs(git, &wanted)?.into_iter().collect();
        if found.is_empty() {
            return Err(PolicyError::NoAnchor(format!(
                "no policy anchor (L2): none of {} exists locally; fetch the trusted remote (git fetch {}), or push its first branch from your own terminal",
                wanted.join(", "),
                remotes.remotes()[0].name
            )));
        }
        let mut out = Vec::new();
        let mut unconfirmed = Vec::new();
        for ((remote, name), refname) in pairs.iter().zip(&wanted) {
            let Some(local) = found.get(refname) else {
                continue;
            };
            match remotes.anchor_tip(git, remote, name, local)? {
                Ok(tip) => out.push(Anchor {
                    refname: refname.clone(),
                    tip,
                    local: false,
                }),
                Err(why) => unconfirmed.push(format!("{refname} ({why})")),
            }
        }
        if out.is_empty() {
            return Err(PolicyError::NoAnchor(format!(
                "no policy anchor (L2): the trusted server confirms no value of {}; fetch it again (git fetch {}) and check that its server answers",
                unconfirmed.join(", "),
                remotes.remotes()[0].name
            )));
        }
        return Ok(out);
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
    remotes: &RemoteRefs,
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
    for a in anchors(git, remotes, anchor_names, own_ref)? {
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
    /// Policy files of the policy commit: path -> (mode, blob).
    pub files: BTreeMap<PathBuf, (String, Oid)>,
    /// `.config/nextest.toml` contents of the policy commit by Rust root
    /// dir (R49).
    pub nextest_configs: BTreeMap<PathBuf, String>,
    /// Python baseline files of the policy commit by path (R49, R94):
    /// `pyright-baseline` and `pytest-baseline` compare with these, never
    /// with the tree's own.
    pub baselines: BTreeMap<PathBuf, String>,
    /// Policy files that differ between the tree and the policy commit.
    pub changed: Vec<PathBuf>,
    /// Tool configs (R71) whose tree version differs from the policy
    /// commit's: the job writes the policy commit's version (or removes the
    /// file) in the verify checkout before setup and steps.
    pub overlay: BTreeMap<PathBuf, OverlayFile>,
}

impl Policy {
    /// blake3 of the policy files' (path, blob) list: part of the
    /// fingerprint, so a policy change voids records (R74).
    #[must_use]
    pub fn files_hash(&self) -> String {
        let mut h = blake3::Hasher::new();
        for (p, (mode, oid)) in &self.files {
            h.update(p.as_os_str().as_encoded_bytes());
            h.update(b"\0");
            h.update(mode.as_bytes());
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

fn policy_entries(
    entries: &[TreeEntry],
    m: impl Fn(&Path) -> bool,
) -> BTreeMap<PathBuf, (String, Oid)> {
    entries
        .iter()
        .filter(|e| e.kind == "blob" && m(&e.path))
        .map(|e| (e.path.clone(), (e.mode.clone(), e.oid.clone())))
        .collect()
}

/// R71: the tool configs whose tree version differs from the policy
/// commit's, with what the checkout must hold instead.
fn overlay(
    git: &Git,
    base: &[TreeEntry],
    tree: &[TreeEntry],
) -> Result<BTreeMap<PathBuf, OverlayFile>, PolicyError> {
    let tools = glob::compile(
        TOOL_CONFIGS,
        GlobOpts {
            case_insensitive: false,
            literal_separator: true,
        },
    )
    .map_err(PolicyError::Config)?;
    // Gitlinks and trees cannot be tool configs; a tree entry of another
    // kind at the same path still has to go.
    let pick = |entries: &[TreeEntry]| -> BTreeMap<PathBuf, (String, Oid)> {
        entries
            .iter()
            .filter(|e| tools.is_match(&e.path))
            .map(|e| (e.path.clone(), (e.mode.clone(), e.oid.clone())))
            .collect()
    };
    let (want, have) = (pick(base), pick(tree));
    let mut out = BTreeMap::new();
    for path in want.keys().chain(have.keys()) {
        let w = want.get(path);
        if w == have.get(path) || out.contains_key(path) {
            continue;
        }
        let file = match w {
            None => OverlayFile::Absent,
            Some((mode, oid)) if mode == "120000" => OverlayFile::Symlink {
                target: read_blob(git, oid)?,
            },
            Some((mode, oid)) if mode == "100644" || mode == "100755" => OverlayFile::File {
                text: read_blob(git, oid)?,
                executable: mode == "100755",
            },
            Some((mode, _)) => {
                return Err(PolicyError::Config(format!(
                    "{} at the policy commit has mode {mode}; a tool config must be a file",
                    path.display()
                )));
            }
        };
        out.insert(path.clone(), file);
    }
    Ok(out)
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
    remotes: &RemoteRefs,
    own_ref: Option<&str>,
) -> Result<Policy, PolicyError> {
    let default_anchors = RepoConfig::default().policy.anchors;
    let mut base = policy_base(git, tip, remotes, &default_anchors, own_ref)?;
    let mut base_entries = match &base.commit {
        Some(c) => git.ls_tree(c)?,
        None => tree_entries.to_vec(),
    };
    let mut found = config_at(git, &base_entries)?;
    // The anchor commit's own config may name other anchors; it sits on a
    // protected ref, so its list can be trusted. The second pass counts
    // only when it found one of them: with none, `policy_base` falls back
    // to the tip itself, the branch's own policy, so the first pass stays.
    if base.anchor.is_some()
        && let Some((_, c)) = &found
        && c.policy.anchors != default_anchors
    {
        let again = policy_base(git, tip, remotes, &c.policy.anchors, own_ref)?;
        if again.anchor.is_some() && again.commit != base.commit {
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
            let (mut c, mut notes) = detect::detect_tree(git, tree_entries);
            // L2, D5: the policy commit's detected steps stay, so a branch
            // cannot drop them by deleting what detection keys on.
            if base.commit.is_some() && base_entries != tree_entries {
                let (from_base, _) = detect::detect_tree(git, &base_entries);
                detect::keep_policy_steps(&mut c, from_base, &mut notes);
            }
            (c, ConfigSource::Detected, notes)
        }
    };
    let matcher = PolicyMatcher::new(&config).map_err(PolicyError::Config)?;
    let files = policy_entries(&base_entries, |p| matcher.is_policy_file(p));
    let mine = policy_entries(tree_entries, |p| matcher.is_policy_file(p));
    let mut changed: Vec<PathBuf> = files
        .iter()
        .filter(|(p, oid)| mine.get(*p) != Some(*oid))
        .map(|(p, _)| p.clone())
        .chain(mine.keys().filter(|p| !files.contains_key(*p)).cloned())
        .collect();
    changed.sort();
    changed.dedup();
    let mut nextest_configs = BTreeMap::new();
    let mut baselines = BTreeMap::new();
    for (p, (_, oid)) in &files {
        let name = p.file_name().and_then(std::ffi::OsStr::to_str);
        if matches!(
            name,
            Some(crate::steps::baseline::PYRIGHT_FILE | crate::steps::baseline::PYTEST_FILE)
        ) {
            baselines.insert(p.clone(), read_blob(git, oid)?);
        }
        if p.ends_with(".config/nextest.toml") {
            let root = p
                .parent()
                .and_then(Path::parent)
                .map(Path::to_owned)
                .unwrap_or_default();
            nextest_configs.insert(root, read_blob(git, oid)?);
        }
    }
    let overlay = overlay(git, &base_entries, tree_entries)?;
    Ok(Policy {
        base,
        config,
        source,
        notes,
        files,
        nextest_configs,
        baselines,
        changed,
        overlay,
    })
}
