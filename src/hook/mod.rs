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

use std::ffi::{OsStr, OsString};
use std::io::Read as _;
use std::path::{Path, PathBuf};

use crate::dirs::Dirs;
use crate::env::EnvSnapshot;
use crate::exit;
use crate::gitx::{Git, RepoLayout};

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

/// Hooks whose stdin tollgate reads itself; the repo hook gets it replayed
/// (R7). Other hooks pass stdin through untouched.
const READS_STDIN: &[&str] = &["pre-push"];

/// Runs hook `name` with git's arguments; returns the exit code.
pub fn run(name: &'static str, args: &[OsString], ctx: &HookCtx) -> u8 {
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
    let dirs = Dirs::from_env(&ctx.env).ok();
    let site = chain::Site {
        layout: &layout,
        cwd: &ctx.cwd,
        env: &ctx.env,
        dirs: dirs.as_ref(),
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
        return exit::OK;
    }
    // R31: from here every path is an explicit allow or deny.
    let gate = match gate::Gate::open(name, &ctx.env, &ctx.exe, layout) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("tollgate: DENIED {name}: {e}");
            return exit::FAIL;
        }
    };
    match name {
        "pre-commit" => commit::run(&gate, commit::Kind::Commit, &ctx.cwd),
        "pre-merge-commit" => commit::run(&gate, commit::Kind::MergeCommit, &ctx.cwd),
        "pre-push" => push::run(&gate, args, stdin.as_deref().unwrap_or_default()),
        other => {
            eprintln!("tollgate: DENIED {other}: no gate for this hook");
            exit::FAIL
        }
    }
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
