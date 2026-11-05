//! `pre-push` (R5, R14, R20, R22).
//!
//! git gives the remote name and URL as arguments and one line per ref on
//! stdin: `<local ref> <local oid> <remote ref> <remote oid>`. Per line:
//! a remote ref outside `refs/heads/` (tags, notes) is allowed (R22); a
//! deletion (zero local oid) is allowed; otherwise the tree of the local
//! commit needs a record at the push tier (R20): to a trusted remote
//! `full`, or `fast` for `push.fast_refs`; to other remotes
//! `tier_for_ref(remote ref)`. A `full` miss is allowed when the commit is
//! a trusted remote's current tip of that branch (R14 outcome 2, kept for
//! `pre-push` by L1).
//!
//! Scope (R5): a push to a trusted URL is gated whatever the local path of
//! the repo; other pushes only from in-scope repos (L4).

use std::ffi::OsString;

use super::gate::{self, Check, Gate, RemoteVerify};
use crate::config::Tier;
use crate::config::repo::branch_name;
use crate::exit;
use crate::gitx::Oid;
use crate::plan::Base;

/// One stdin line of `pre-push`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushLine {
    /// Local ref (`(delete)` for a deletion).
    pub local_ref: String,
    /// Local commit; zero for a deletion.
    pub local_oid: Oid,
    /// Remote ref.
    pub remote_ref: String,
    /// The remote's current value; zero when the ref is new.
    pub remote_oid: Oid,
}

/// Parses `pre-push` stdin.
pub fn parse_lines(stdin: &[u8]) -> Result<Vec<PushLine>, String> {
    let text =
        std::str::from_utf8(stdin).map_err(|e| format!("pre-push input is not UTF-8: {e}"))?;
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let parts: Vec<&str> = l.split(' ').collect();
            let [local_ref, local_oid, remote_ref, remote_oid] = parts[..] else {
                return Err(format!("unexpected pre-push line {l:?}"));
            };
            Ok(PushLine {
                local_ref: local_ref.to_owned(),
                local_oid: Oid::parse(local_oid)?,
                remote_ref: remote_ref.to_owned(),
                remote_oid: Oid::parse(remote_oid)?,
            })
        })
        .collect()
}

fn deny(gate: &Gate<'_>, what: &str, msg: &str) -> u8 {
    eprintln!("tollgate: DENIED {} {what}: {msg}", gate.hook);
    exit::FAIL
}

/// Gates a push.
pub fn run(gate: &Gate<'_>, args: &[OsString], stdin: &[u8]) -> u8 {
    let remote = args
        .first()
        .map(|a| a.to_string_lossy().into_owned())
        .unwrap_or_default();
    let url = args
        .get(1)
        .map(|a| a.to_string_lossy().into_owned())
        .unwrap_or_else(|| remote.clone());
    let push_trusted = gate.scope.remote_trusted(&url);
    let in_scope = gate.in_scope()
        || gate
            .scope
            .contains(&gate.layout.repo_dir(), std::slice::from_ref(&url));
    if !in_scope {
        return exit::OK;
    }
    let lines = match parse_lines(stdin) {
        Ok(l) => l,
        Err(e) => return deny(gate, &remote, &e),
    };
    let mut checks = Vec::new();
    for line in &lines {
        // R22: tags and other non-branch refs; deletions.
        if !line.remote_ref.starts_with("refs/heads/") || line.local_oid.is_zero() {
            continue;
        }
        let what = &line.remote_ref;
        let tree = match gate.git.tree_of(&format!("{}^{{commit}}", line.local_oid)) {
            Ok(Some(t)) => t,
            Ok(None) => {
                return deny(
                    gate,
                    what,
                    &format!("{} is not a local commit", line.local_oid),
                );
            }
            Err(e) => return deny(gate, what, &e.to_string()),
        };
        let tier = match gate.ref_rules(&tree, Some(&line.local_oid), &line.remote_ref) {
            Ok(rules) => rules.push_tier(&line.remote_ref, push_trusted),
            Err(e) => return deny(gate, what, &e),
        };
        // R55: the remote's current tree when it is present locally, else
        // the empty tree.
        let base = if line.remote_oid.is_zero() {
            None
        } else {
            gate.git
                .tree_of(&format!("{}^{{commit}}", line.remote_oid))
                .ok()
                .flatten()
                .map(|t| Base {
                    tree: t,
                    commit: Some(line.remote_oid.clone()),
                })
        };
        let base = match base {
            Some(b) => b,
            None => match gate.git.object_format() {
                Ok(f) => Base {
                    tree: f.empty_tree(),
                    commit: None,
                },
                Err(e) => return deny(gate, what, &e.to_string()),
            },
        };
        let remote_verify = (tier == Tier::Full).then(|| RemoteVerify::Commit {
            oid: line.local_oid.clone(),
            branch: branch_name(&line.remote_ref).to_owned(),
        });
        let rerun_hint = format!(
            "tollgate check --tier {tier} --rev {} --rerun",
            line.local_oid
        );
        checks.push(Check {
            tree,
            tier,
            tip: Some(line.local_oid.clone()),
            base: Some(base),
            refname: line.remote_ref.clone(),
            remote_verify,
            rerun_hint,
        });
    }
    if checks.is_empty() {
        return exit::OK;
    }
    // R14(2) asks the trusted remotes other than the destination: the
    // destination's current value is already on stdin, and git pushes only
    // refs it does not have.
    let ask: Vec<String> = gate
        .trusted
        .iter()
        .filter(|r| **r != remote)
        .cloned()
        .collect();
    let retry = gate::retry_command("git push <same arguments>");
    gate::decide(gate, &checks, &retry, &ask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_push_lines_parse_r20() {
        let z = "0".repeat(40);
        let a = "a".repeat(40);
        let input = format!("refs/heads/x {a} refs/heads/x {z}\n(delete) {z} refs/heads/y {a}\n");
        let lines = parse_lines(input.as_bytes()).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].remote_ref, "refs/heads/x");
        assert!(lines[0].remote_oid.is_zero());
        assert!(lines[1].local_oid.is_zero());
        assert!(parse_lines(b"bad line\n").is_err());
        assert!(parse_lines(b"").unwrap().is_empty());
    }
}
