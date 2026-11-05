//! The repo's own hooks dir, for chaining (R7).
//!
//! The injection (`GIT_CONFIG_*` -> `core.hooksPath`) replaces the repo's
//! hooks path, so tollgate runs the repo's own hook itself. The path is
//! `core.hooksPath` from the config files git reads (system, global, local,
//! worktree; last one wins), else `<common dir>/hooks`. The files are parsed
//! here without a subprocess. When a file has `include`/`includeIf`, cannot
//! be parsed, or the value needs git's own path expansion, git is asked:
//! `git rev-parse --path-format=absolute --git-path hooks` with the
//! injection removed (scrubbed env).

use std::path::{Path, PathBuf};

use super::config_file::{self, ParseError};
use super::{Git, GitError, RepoLayout};
use crate::env::EnvSnapshot;

/// The repo's own hooks location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoHooks {
    /// Hooks live in this dir (it may not exist).
    Dir(PathBuf),
    /// `core.hooksPath` is empty: git runs no hooks.
    Disabled,
}

/// Why the config files alone cannot decide; git is asked instead.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NeedsGit {
    /// The file has `include.path` or `includeIf.*.path`.
    #[error("{0} has include or includeIf")]
    Include(PathBuf),
    /// The file has a syntax error.
    #[error("{path}: {error}")]
    Syntax {
        /// File.
        path: PathBuf,
        /// Parser error.
        error: ParseError,
    },
    /// The file exists but cannot be read.
    #[error("cannot read {path}: {message}")]
    Unreadable {
        /// File.
        path: PathBuf,
        /// Cause.
        message: String,
    },
    /// The value needs git's path interpolation (`~user/`, `%(prefix)/`,
    /// `:(optional)`, no `HOME`) or is a bare key.
    #[error("core.hooksPath {0:?} needs git's own interpretation")]
    Value(String),
    /// An environment variable has a value this code does not interpret.
    #[error("{0} has a value git must interpret")]
    Env(&'static str),
}

/// The config files git reads for this repository, in order (later wins).
///
/// `system_default` is git's compiled-in system file
/// ([`Git::system_config_default`]); `GIT_CONFIG_NOSYSTEM` and
/// `GIT_CONFIG_SYSTEM` are applied here. Global files follow
/// `GIT_CONFIG_GLOBAL`, else `$XDG_CONFIG_HOME/git/config` (or
/// `~/.config/git/config`) then `~/.gitconfig`. The worktree file counts only
/// with `extensions.worktreeConfig` in the local file.
pub fn config_files(
    layout: &RepoLayout,
    env: &EnvSnapshot,
    system_default: Option<&Path>,
) -> Result<Vec<PathBuf>, NeedsGit> {
    let cwd = layout.hooks_cwd();
    let abs = |p: &Path| {
        if p.is_absolute() {
            p.to_owned()
        } else {
            cwd.join(p)
        }
    };
    let mut files = Vec::new();

    let nosystem = match env.get("GIT_CONFIG_NOSYSTEM") {
        None => false,
        Some(v) => config_file::parse_bool(Some(
            v.to_str().ok_or(NeedsGit::Env("GIT_CONFIG_NOSYSTEM"))?,
        ))
        .ok_or(NeedsGit::Env("GIT_CONFIG_NOSYSTEM"))?,
    };
    if !nosystem {
        match env.get("GIT_CONFIG_SYSTEM") {
            // An empty value names no readable file: git reads none.
            Some(v) if v.is_empty() => {}
            Some(v) => files.push(abs(Path::new(v))),
            None => files.extend(system_default.map(Path::to_owned)),
        }
    }

    match env.get("GIT_CONFIG_GLOBAL") {
        Some(v) if v.is_empty() => {}
        Some(v) => files.push(abs(Path::new(v))),
        None => {
            let home = env.get_nonempty("HOME").map(Path::new);
            match env.get_nonempty("XDG_CONFIG_HOME") {
                Some(x) => files.push(abs(&Path::new(x).join("git/config"))),
                None => files.extend(home.map(|h| h.join(".config/git/config"))),
            }
            files.extend(home.map(|h| h.join(".gitconfig")));
        }
    }

    let local = layout.local_config();
    let local_entries = read_entries(&local)?.unwrap_or_default();
    files.push(local);
    let worktree_config = config_file::last(&local_entries, "extensions", "worktreeconfig")
        .map(|e| config_file::parse_bool(e.value.as_deref()))
        .unwrap_or(Some(false))
        .ok_or_else(|| NeedsGit::Value("extensions.worktreeConfig".into()))?;
    if worktree_config {
        files.push(layout.worktree_config());
    }
    Ok(files)
}

fn read_entries(path: &Path) -> Result<Option<Vec<config_file::Entry>>, NeedsGit> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::IsADirectory => return Ok(None),
        Err(e) => {
            return Err(NeedsGit::Unreadable {
                path: path.to_owned(),
                message: e.to_string(),
            });
        }
    };
    let entries = config_file::parse(&bytes).map_err(|error| NeedsGit::Syntax {
        path: path.to_owned(),
        error,
    })?;
    if entries.iter().any(config_file::Entry::is_include) {
        return Err(NeedsGit::Include(path.to_owned()));
    }
    Ok(Some(entries))
}

/// The hooks dir from the config files alone, with no subprocess.
pub fn parse_hooks_path(
    layout: &RepoLayout,
    env: &EnvSnapshot,
    system_default: Option<&Path>,
) -> Result<RepoHooks, NeedsGit> {
    let mut value: Option<Option<String>> = None;
    for file in config_files(layout, env, system_default)? {
        if let Some(entries) = read_entries(&file)?
            && let Some(e) = config_file::last(&entries, "core", "hookspath")
        {
            value = Some(e.value.clone());
        }
    }
    let Some(value) = value else {
        return Ok(RepoHooks::Dir(layout.default_hooks_dir()));
    };
    let Some(value) = value else {
        return Err(NeedsGit::Value("<bare key>".into()));
    };
    if value.is_empty() {
        return Ok(RepoHooks::Disabled);
    }
    if value.starts_with("%(") || value.starts_with(":(") {
        return Err(NeedsGit::Value(value));
    }
    let path = if value == "~" || value.starts_with("~/") {
        let home = env
            .get_nonempty("HOME")
            .ok_or_else(|| NeedsGit::Value(value.clone()))?;
        Path::new(home).join(value.trim_start_matches('~').trim_start_matches('/'))
    } else if value.starts_with('~') {
        return Err(NeedsGit::Value(value));
    } else {
        layout.hooks_cwd().join(&value)
    };
    Ok(RepoHooks::Dir(path))
}

/// The hooks dir as git reports it, with the injection removed.
pub fn hooks_path_via_git(git: &Git, layout: &RepoLayout) -> Result<RepoHooks, GitError> {
    let git = git.clone().in_dir(layout.hooks_cwd());
    match git.run_line(["rev-parse", "--path-format=absolute", "--git-path", "hooks"]) {
        Ok(p) => Ok(RepoHooks::Dir(PathBuf::from(p))),
        Err(err) => {
            // git refuses to print an empty path; an empty value disables hooks.
            let out = git.output(["config", "--get", "core.hooksPath"])?;
            if out.status.success() && out.stdout.iter().all(|b| *b == b'\n') {
                Ok(RepoHooks::Disabled)
            } else {
                Err(err)
            }
        }
    }
}

/// How [`repo_hooks`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The hooks location.
    pub hooks: RepoHooks,
    /// Why git was asked, when it was.
    pub asked_git: Option<NeedsGit>,
}

/// The repo's own hooks dir (R7): the config files, else git.
pub fn repo_hooks(
    layout: &RepoLayout,
    env: &EnvSnapshot,
    system_default: Option<&Path>,
    git: &Git,
) -> Result<Resolved, GitError> {
    match parse_hooks_path(layout, env, system_default) {
        Ok(hooks) => Ok(Resolved {
            hooks,
            asked_git: None,
        }),
        Err(reason) => Ok(Resolved {
            hooks: hooks_path_via_git(git, layout)?,
            asked_git: Some(reason),
        }),
    }
}
