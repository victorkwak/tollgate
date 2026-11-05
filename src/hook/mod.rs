//! Git hook entry points (R1, R2, R6, R7, R17, R20).
//!
//! Phase 1 holds the hook names and argv\[0\] dispatch. `reference-transaction`
//! is not installed (L1).

use std::ffi::OsStr;
use std::path::Path;

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
