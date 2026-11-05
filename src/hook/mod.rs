//! Git hook entry points (R1, R2, R6, R7, R17, R20).
//!
//! Every installed hook name is a hard link to the installed binary, which
//! dispatches on the basename of argv\[0\] (R1). [`run`] first chains to
//! the repo's own hook (R7; repo hook first for `pre-*` and message hooks);
//! a gate hook then decides when the repo is in scope (L4, R5, R6).
//! `reference-transaction` is not installed (L1).

pub mod argv;
pub mod chain;
pub mod commit;
pub mod gate;
pub mod push;
pub mod unverified;

use std::ffi::{OsStr, OsString};
use std::io::Read as _;
use std::path::{Path, PathBuf};

use crate::dirs::Dirs;
use crate::env::EnvSnapshot;
use crate::exit;
use crate::gitx::{Git, RepoLayout};
use crate::install::InstallRecord;

/// Hooks that gate (R17, R20). `reference-transaction` is CUT (L1).
pub const GATE_HOOKS: &[&str] = &["pre-commit", "pre-merge-commit", "pre-push"];

/// Hooks that only chain to the repo's own hook (R2, R7).
pub const CHAINED_HOOKS: &[&str] = &[
    "applypatch-msg",
    "pre-applypatch",
    "post-applypatch",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "pre-rebase",
    "post-checkout",
    "post-merge",
    "post-rewrite",
    "pre-auto-gc",
];

/// Every hook name `install` links (R2 minus `reference-transaction`, L1).
pub fn installed_hook_names() -> impl Iterator<Item = &'static str> {
    GATE_HOOKS.iter().chain(CHAINED_HOOKS).copied()
}

/// The installed hook name equal to `name`, if any.
#[must_use]
pub fn hook_name(name: &str) -> Option<&'static str> {
    installed_hook_names().find(|h| *h == name)
}

/// The hook to run when the binary is started through a hook link: the
/// basename of argv\[0\] (R1).
#[must_use]
pub fn dispatch_name(argv0: &OsStr) -> Option<&'static str> {
    let base = Path::new(argv0).file_name()?.to_str()?;
    hook_name(base)
}

/// What a hook process got from git.
#[derive(Debug, Clone)]
pub struct HookCtx {
    /// The hook's environment.
    pub env: EnvSnapshot,
    /// The hook's cwd (git runs hooks in the worktree root, or the git dir
    /// of a bare repo).
    pub cwd: PathBuf,
    /// The running binary (a hook link).
    pub exe: PathBuf,
}

/// tollgate's dirs for a hook running as `exe` (R8).
///
/// The hooks of an install are `<data dir>/hooks/<name>` (and `tollgate
/// hook` runs `<data dir>/bin/tollgate`), and `<data dir>/install.json`
/// records the dirs install used. They are taken from there, so no `HOME`
/// or `XDG_*` value in git's environment decides which host config, scope
/// roots and records apply. A binary outside an install (a test or dev
/// build, the PATH binary) has no record beside it and uses the
/// environment: whoever points `core.hooksPath` at such a binary decides
/// what runs as a hook anyway, and the guard denies that (R25).
pub fn hook_dirs(exe: &Path, env: &EnvSnapshot) -> Result<Dirs, String> {
    let Some(data_dir) = exe.parent().and_then(Path::parent) else {
        return Dirs::from_env(env).map_err(|e| e.to_string());
    };
    let record = data_dir.join("install.json");
    match std::fs::symlink_metadata(&record) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Dirs::from_env(env).map_err(|e| e.to_string());
        }
        Err(e) => return Err(format!("{}: {e}", record.display())),
        Ok(_) => {}
    }
    let rec = InstallRecord::read_at(&record)?;
    let dirs = rec.dirs.ok_or_else(|| {
        format!(
            "{} records no dirs (an older install); run: tollgate install",
            record.display()
        )
    })?;
    let same = |a: &Path, b: &Path| match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    };
    if !same(&dirs.data_dir(), data_dir) {
        return Err(format!(
            "{} records the data dir {}, not the dir it is in; run: tollgate install",
            record.display(),
            dirs.data_dir().display()
        ));
    }
    Ok(dirs)
}

/// Hooks whose stdin tollgate reads itself; the repo hook gets it replayed
/// (R7). Other hooks pass stdin through untouched.
const READS_STDIN: &[&str] = &["pre-push"];

/// Runs hook `name` with git's arguments; returns the exit code.
pub fn run(name: &'static str, args: &[OsString], ctx: &HookCtx) -> u8 {
    // Item 39: never a `git` that `GIT_EXEC_PATH` put first on PATH.
    crate::gitx::init_program(&ctx.exe, &ctx.env);
    let gate_hook = GATE_HOOKS.contains(&name);
    let stdin = if READS_STDIN.contains(&name) {
        let mut buf = Vec::new();
        if let Err(e) = std::io::stdin().read_to_end(&mut buf) {
            eprintln!("tollgate: DENIED {name}: cannot read stdin: {e}");
            return exit::FAIL;
        }
        Some(buf)
    } else {
        None
    };
    let layout = RepoLayout::for_hook(&ctx.cwd, &ctx.env)
        .or_else(|| RepoLayout::discover(&Git::scrubbed(&ctx.env, &ctx.cwd)).ok());
    let Some(layout) = layout else {
        if gate_hook {
            eprintln!(
                "tollgate: DENIED {name}: {} is not in a git repository",
                ctx.cwd.display()
            );
            return exit::FAIL;
        }
        return exit::OK;
    };
    let dirs = hook_dirs(&ctx.exe, &ctx.env);
    let site = chain::Site {
        layout: &layout,
        cwd: &ctx.cwd,
        env: &ctx.env,
        dirs: dirs.as_ref().ok(),
        exe: &ctx.exe,
    };
    let input = stdin
        .as_deref()
        .map_or(chain::Input::Inherit, chain::Input::Replay);
    match chain::run(name, args, input, &site) {
        Ok(0) => {}
        Ok(code) => return u8::try_from(code).unwrap_or(exit::FAIL),
        Err(e) => {
            eprintln!("tollgate: {name}: {e}");
            return exit::FAIL;
        }
    }
    if !gate_hook {
        // Item 17: a commit no gate hook of this git command allowed.
        if let (true, Ok(d)) = (matches!(name, "post-commit" | "post-merge"), &dirs) {
            unverified::detect(
                &unverified::PostHook {
                    name,
                    args,
                    layout: &layout,
                    env: &ctx.env,
                    exe: &ctx.exe,
                },
                d,
            );
        }
        return exit::OK;
    }
    // R31: from here every path is an explicit allow or deny.
    let dirs = match dirs {
        Ok(d) => d,
        Err(e) => {
            eprintln!("tollgate: DENIED {name}: {e}");
            return exit::FAIL;
        }
    };
    // R8: git calls and the runner see the install's dirs, not git's env.
    let env = dirs.env_for(&ctx.env);
    let gate = match gate::Gate::open(name, &env, &ctx.exe, layout, dirs) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("tollgate: DENIED {name}: {e}");
            return exit::FAIL;
        }
    };
    let code = match name {
        "pre-commit" => commit::run(&gate, commit::Kind::Commit, &ctx.cwd),
        "pre-merge-commit" => commit::run(&gate, commit::Kind::MergeCommit, &ctx.cwd),
        "pre-push" => push::run(&gate, args, stdin.as_deref().unwrap_or_default()),
        other => {
            eprintln!("tollgate: DENIED {other}: no gate for this hook");
            exit::FAIL
        }
    };
    // Item 17: the post hook of this git command sees that a gate hook
    // allowed its commit.
    if code == exit::OK && matches!(name, "pre-commit" | "pre-merge-commit") {
        unverified::mark_gate_run(&gate.dirs);
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv0_basename_selects_the_hook_r1() {
        assert_eq!(
            dispatch_name(OsStr::new("/x/hooks/pre-commit")),
            Some("pre-commit")
        );
        assert_eq!(
            dispatch_name(OsStr::new("post-rewrite")),
            Some("post-rewrite")
        );
        assert_eq!(dispatch_name(OsStr::new("/x/bin/tollgate")), None);
    }

    #[test]
    fn reference_transaction_is_not_installed_l1() {
        assert_eq!(hook_name("reference-transaction"), None);
        assert_eq!(installed_hook_names().count(), 14);
    }
}
