//! `pre-commit` and `pre-merge-commit` (R17, R14 outcome 2 for merges).
//!
//! `T` = `git write-tree` of the index git gave the hook (`GIT_INDEX_FILE`;
//! a temporary index for partial commits and `commit -a`). Base =
//! `HEAD^{tree}`, or the empty tree on an unborn branch. Tier: `fast` for
//! `pre-commit`; `tier_for_ref(current branch)` for `pre-merge-commit`.
//!
//! A merge commit made by `git commit` (after `merge --no-commit`, a
//! conflict, or a denied `pre-merge-commit`) runs `pre-commit`, not
//! `pre-merge-commit` (checked with git 2.56). So `pre-commit` with
//! `MERGE_HEAD` present gates like `pre-merge-commit`: otherwise
//! `git merge --no-commit feat && git commit` would put a `fast`-only tree
//! on a full ref.

use super::gate::{self, Check, Gate, RemoteVerify};
use crate::config::Tier;
use crate::config::repo::branch_name;
use crate::exit;

/// Which hook runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `pre-commit`.
    Commit,
    /// `pre-merge-commit`.
    MergeCommit,
}

fn deny(gate: &Gate<'_>, refname: &str, msg: &str) -> u8 {
    eprintln!("tollgate: DENIED {} {refname}: {msg}", gate.hook);
    exit::FAIL
}

/// Gates the commit the hook is about to make.
pub fn run(gate: &Gate<'_>, kind: Kind, cwd: &std::path::Path) -> u8 {
    if !gate.in_scope() {
        return exit::OK;
    }
    let refname = gate.head_ref();
    let merging = kind == Kind::MergeCommit || gate.layout.git_dir.join("MERGE_HEAD").is_file();
    let index = gate::hook_index_file(gate.env, cwd, &gate.layout);
    let tree = match gate::write_tree(gate, &index) {
        Ok(t) => t,
        Err(e) => return deny(gate, &refname, &e),
    };
    let (head, base) = match gate.head_base() {
        Ok(x) => x,
        Err(e) => return deny(gate, &refname, &e),
    };
    let tier = if merging {
        match gate.ref_rules(&tree, head.as_ref(), &refname) {
            Ok(rules) => rules.tier_for_ref(&refname),
            Err(e) => return deny(gate, &refname, &e),
        }
    } else {
        Tier::Fast
    };
    let remote_verify =
        (merging && tier == Tier::Full && refname.starts_with("refs/heads/")).then(|| {
            RemoteVerify::Tree {
                branch: branch_name(&refname).to_owned(),
            }
        });
    let rerun_hint = format!("tollgate check --tier {tier} --tree {tree} --rerun");
    let check = Check {
        tree,
        tier,
        tip: head,
        base: Some(base),
        refname,
        remote_verify,
        rerun_hint,
    };
    // After a denied pre-merge-commit git keeps the merge in progress:
    // `git commit` concludes it (and runs pre-commit, which finds the
    // record). A plain commit repeats its own command line.
    let retry = match kind {
        Kind::MergeCommit => "git commit --no-edit".to_owned(),
        Kind::Commit => gate::retry_command("git commit <same arguments>"),
    };
    gate::decide(gate, &[check], &retry, &gate.trusted)
}
