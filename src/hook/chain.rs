//! Chaining to the repo's own hook (R7).
//!
//! The injection (`GIT_CONFIG_*` -> `core.hooksPath`) replaces the repo's
//! hooks path, so tollgate runs `<repo hooks path>/<name>` itself when it is
//! executable: same arguments, same stdin content, same cwd, same
//! environment. The repo hook's non-zero exit is the hook's exit.
//!
//! The hooks path comes from the config files (no subprocess, R7). git's
//! compiled-in system config path needs `git var GIT_CONFIG_SYSTEM` once per
//! git binary; the answer is kept in the tool cache (R75), so a chained hook
//! with no repo hook runs no subprocess (L19: under 5 ms).

use std::ffi::OsString;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::cache::toolcache::{self, BinaryIdentity, ToolCache};
use crate::dirs::Dirs;
use crate::env::EnvSnapshot;
use crate::gitx::config_file;
use crate::gitx::hooks_path::{self, RepoHooks};
use crate::gitx::{Git, RepoLayout};
use crate::runner::env::JobEnv;

/// Tool cache id of git's compiled-in system config path.
const SYSTEM_CONFIG_PROBE: &str = "git var GIT_CONFIG_SYSTEM";

/// True when git reads no system config file whatever its compiled-in
/// default (R7 applies `GIT_CONFIG_NOSYSTEM` and `GIT_CONFIG_SYSTEM`).
fn system_default_unused(env: &EnvSnapshot) -> bool {
    let nosystem = env
        .get("GIT_CONFIG_NOSYSTEM")
        .and_then(|v| v.to_str())
        .and_then(|v| config_file::parse_bool(Some(v)))
        .unwrap_or(false);
    nosystem || env.get("GIT_CONFIG_SYSTEM").is_some()
}

/// git's compiled-in system config path, from the tool cache when the git
/// binary is unchanged (R75). `Err` when `git var` cannot tell (git older
/// than 2.42): the caller asks git for the hooks path instead.
fn system_default(
    env: &EnvSnapshot,
    dirs: Option<&Dirs>,
    cwd: &Path,
) -> Result<Option<PathBuf>, ()> {
    let git = Git::scrubbed(env, cwd);
    let probe = || {
        git.system_config_default()
            .map(|p| {
                p.map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default()
            })
            .map_err(|_| ())
    };
    let identity = toolcache::which("git", env.get("PATH")).and_then(|p| {
        BinaryIdentity::of(&p, "git", &JobEnv::from_vars::<_, &str, &str>([]), cwd).ok()
    });
    let text = match (identity, dirs) {
        (Some(id), Some(dirs)) => {
            let mut cache = ToolCache::load(&dirs.toolcache_file());
            let out = cache.cached(SYSTEM_CONFIG_PROBE, id, probe)?;
            if cache.stats().runs > 0 {
                let _ = cache.save();
            }
            out
        }
        _ => probe()?,
    };
    Ok((!text.is_empty()).then(|| PathBuf::from(text)))
}

/// The repo's own hooks dir (R7), or `None` when git would run no hooks.
pub fn repo_hooks_dir(
    layout: &RepoLayout,
    env: &EnvSnapshot,
    dirs: Option<&Dirs>,
) -> Result<Option<PathBuf>, String> {
    let cwd = layout.hooks_cwd();
    let git = Git::scrubbed(env, cwd);
    let resolved = if system_default_unused(env) {
        hooks_path::repo_hooks(layout, env, None, &git)
    } else {
        match system_default(env, dirs, cwd) {
            Ok(sys) => hooks_path::repo_hooks(layout, env, sys.as_deref(), &git),
            Err(()) => {
                hooks_path::hooks_path_via_git(&git, layout).map(|hooks| hooks_path::Resolved {
                    hooks,
                    asked_git: None,
                })
            }
        }
    }
    .map_err(|e| format!("cannot find the repo's hooks dir (R7): {e}"))?;
    Ok(match resolved.hooks {
        RepoHooks::Dir(d) => Some(d),
        RepoHooks::Disabled => None,
    })
}

/// True when `path` is the running binary or a hard link to it.
fn is_self(path: &Path, exe: &Path) -> bool {
    match (std::fs::metadata(path), std::fs::metadata(exe)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// The repo's own hook `name`, when git would run it: an executable file
/// in the repo hooks dir that is not tollgate itself (a repo whose own
/// `core.hooksPath` names tollgate's hooks dir must not recurse).
pub fn repo_hook(
    name: &str,
    layout: &RepoLayout,
    env: &EnvSnapshot,
    dirs: Option<&Dirs>,
    exe: &Path,
) -> Result<Option<PathBuf>, String> {
    let Some(dir) = repo_hooks_dir(layout, env, dirs)? else {
        return Ok(None);
    };
    let path = dir.join(name);
    let Ok(md) = std::fs::metadata(&path) else {
        return Ok(None);
    };
    if !md.is_file() || md.permissions().mode() & 0o111 == 0 {
        return Ok(None);
    }
    if is_self(&path, exe)
        || dirs.is_some_and(|d| {
            match (
                std::fs::canonicalize(&dir),
                std::fs::canonicalize(d.hooks_dir()),
            ) {
                (Ok(a), Ok(b)) => a == b,
                _ => false,
            }
        })
    {
        return Ok(None);
    }
    Ok(Some(path))
}

/// The stdin a chained hook gets.
#[derive(Debug, Clone, Copy)]
pub enum Input<'a> {
    /// tollgate did not read stdin: the hook inherits it.
    Inherit,
    /// tollgate read stdin (`pre-push`): it is replayed.
    Replay(&'a [u8]),
}

/// Where a hook runs.
#[derive(Debug, Clone, Copy)]
pub struct Site<'a> {
    /// The repo.
    pub layout: &'a RepoLayout,
    /// The hook's cwd.
    pub cwd: &'a Path,
    /// The hook's environment, passed on unchanged.
    pub env: &'a EnvSnapshot,
    /// tollgate's dirs (tool cache, own hooks dir), when `HOME` is usable.
    pub dirs: Option<&'a Dirs>,
    /// The running binary.
    pub exe: &'a Path,
}

/// Runs the repo's own hook `name` (R7) and returns its exit code; 0 when
/// there is none. The hook runs directly, as git runs an executable hook
/// file, on macOS and Linux alike.
pub fn run(
    name: &str,
    args: &[OsString],
    input: Input<'_>,
    site: &Site<'_>,
) -> Result<i32, String> {
    let Some(hook) = repo_hook(name, site.layout, site.env, site.dirs, site.exe)? else {
        return Ok(0);
    };
    let mut cmd = Command::new(&hook);
    cmd.args(args).current_dir(site.cwd).env_clear();
    for (k, v) in site.env.iter() {
        cmd.env(k, v);
    }
    match input {
        Input::Inherit => {
            cmd.stdin(Stdio::inherit());
        }
        Input::Replay(_) => {
            cmd.stdin(Stdio::piped());
        }
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot run the repo hook {}: {e}", hook.display()))?;
    if let (Input::Replay(bytes), Some(mut stdin)) = (input, child.stdin.take()) {
        // A hook that does not read its stdin closes the pipe early; git
        // ignores that too.
        let _ = stdin.write_all(bytes);
    }
    let status = child
        .wait()
        .map_err(|e| format!("repo hook {}: {e}", hook.display()))?;
    Ok(status.code().unwrap_or(1))
}
