//! Where a repository's git dir, common dir and worktree are.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use super::{Git, GitError};
use crate::env::EnvSnapshot;
use crate::ids::RepoKey;

/// The dirs of one worktree of a repository. All paths are canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoLayout {
    /// `$GIT_DIR`: `.git`, or `.git/worktrees/<name>` for a linked worktree.
    pub git_dir: PathBuf,
    /// The common dir shared by all worktrees.
    pub common_dir: PathBuf,
    /// The worktree root; `None` in a bare repository.
    pub worktree: Option<PathBuf>,
}

fn canonical(p: &Path) -> Result<PathBuf, GitError> {
    fs::canonicalize(p).map_err(|e| GitError::Output {
        args: "rev-parse".into(),
        detail: format!("{}: {e}", p.display()),
    })
}

impl RepoLayout {
    /// Asks git for the layout of the repository at `git.dir()`.
    pub fn discover(git: &Git) -> Result<Self, GitError> {
        let args = [
            "rev-parse",
            "--path-format=absolute",
            "--git-dir",
            "--git-common-dir",
            "--is-bare-repository",
        ];
        let text = git.run_line(args)?;
        let lines: Vec<&str> = text.lines().collect();
        let [git_dir, common_dir, bare] = lines[..] else {
            return Err(GitError::Output {
                args: args.join(" "),
                detail: format!("expected 3 lines, got {text:?}"),
            });
        };
        let worktree = if bare == "true" {
            None
        } else {
            match git.run_line(["rev-parse", "--show-toplevel"]) {
                Ok(top) if !top.is_empty() => Some(canonical(Path::new(&top))?),
                // Inside the git dir of a non-bare repo there is no toplevel.
                _ => None,
            }
        };
        Ok(Self {
            git_dir: canonical(Path::new(git_dir))?,
            common_dir: canonical(Path::new(common_dir))?,
            worktree,
        })
    }

    /// The layout from a hook's cwd and environment, with no subprocess.
    ///
    /// git runs hooks in the worktree root (the git dir in a bare repo) and
    /// sets `GIT_DIR` for linked worktrees. `None` when the layout cannot be
    /// read this way; the caller then uses [`RepoLayout::discover`].
    #[must_use]
    pub fn for_hook(cwd: &Path, env: &EnvSnapshot) -> Option<Self> {
        let abs = |p: &OsStr| {
            let p = Path::new(p);
            if p.is_absolute() {
                p.to_owned()
            } else {
                cwd.join(p)
            }
        };
        let (git_dir, worktree) = if let Some(gd) = env.get_nonempty("GIT_DIR") {
            let gd = fs::canonicalize(abs(gd)).ok()?;
            let wt = match env.get_nonempty("GIT_WORK_TREE") {
                Some(w) => Some(abs(w)),
                None if gd == fs::canonicalize(cwd).ok()? => None,
                None => Some(cwd.to_owned()),
            };
            (gd, wt)
        } else {
            let dotgit = cwd.join(".git");
            match fs::metadata(&dotgit) {
                Ok(md) if md.is_dir() => (dotgit, Some(cwd.to_owned())),
                Ok(md) if md.is_file() => {
                    let text = fs::read_to_string(&dotgit).ok()?;
                    let target = text.strip_prefix("gitdir:")?.trim();
                    (abs(OsStr::new(target)), Some(cwd.to_owned()))
                }
                _ if is_git_dir(cwd) => (cwd.to_owned(), None),
                _ => return None,
            }
        };
        if !is_git_dir(&git_dir) {
            return None;
        }
        let common_dir = match fs::read_to_string(git_dir.join("commondir")) {
            Ok(c) => {
                let c = Path::new(c.trim());
                if c.is_absolute() {
                    c.to_owned()
                } else {
                    git_dir.join(c)
                }
            }
            Err(_) => git_dir.clone(),
        };
        Some(Self {
            git_dir: fs::canonicalize(&git_dir).ok()?,
            common_dir: fs::canonicalize(&common_dir).ok()?,
            worktree: match worktree {
                Some(w) => Some(fs::canonicalize(w).ok()?),
                None => None,
            },
        })
    }

    /// True in a bare repository.
    #[must_use]
    pub fn is_bare(&self) -> bool {
        self.worktree.is_none()
    }

    /// The repo's identity dir for scope (L4): the parent of the common dir
    /// when that is a `.git` dir, else the common dir itself (bare repos).
    #[must_use]
    pub fn repo_dir(&self) -> PathBuf {
        if self.common_dir.file_name() == Some(OsStr::new(".git")) {
            self.common_dir
                .parent()
                .map_or_else(|| self.common_dir.clone(), Path::to_owned)
        } else {
            self.common_dir.clone()
        }
    }

    /// The repo key (R29, R41).
    #[must_use]
    pub fn repo_key(&self) -> RepoKey {
        RepoKey::of_realpath(&self.common_dir)
    }

    /// `<common dir>/config`.
    #[must_use]
    pub fn local_config(&self) -> PathBuf {
        self.common_dir.join("config")
    }

    /// `<git dir>/config.worktree` (read when `extensions.worktreeConfig`).
    #[must_use]
    pub fn worktree_config(&self) -> PathBuf {
        self.git_dir.join("config.worktree")
    }

    /// `<common dir>/hooks`: the hooks dir when `core.hooksPath` is unset.
    #[must_use]
    pub fn default_hooks_dir(&self) -> PathBuf {
        self.common_dir.join("hooks")
    }

    /// Where hooks run, and the base of a relative `core.hooksPath`.
    #[must_use]
    pub fn hooks_cwd(&self) -> &Path {
        self.worktree.as_deref().unwrap_or(&self.git_dir)
    }
}

fn is_git_dir(p: &Path) -> bool {
    p.join("HEAD").is_file() && (p.join("objects").is_dir() || p.join("commondir").is_file())
}
