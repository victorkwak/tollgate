//! `pre-push` (R5, R14, R20, R22, R102, R107, R108).
//!
//! git gives the remote name and URL as arguments and one line per ref on
//! stdin: `<local ref> <local oid> <remote ref> <remote oid>`, where the
//! remote oid is the remote's current value from this push's ref
//! advertisement. First, R102: a branch the remote has moved past what
//! the push contains is refused before any plan or job, unless the push
//! is forced (git would reject it anyway). Then per line: a remote ref
//! outside `refs/heads/` (tags, notes) is allowed (R22); a deletion (zero
//! local oid) is allowed; otherwise the tree of the local commit needs a
//! record at the push tier (R20, R107): to a trusted remote `full` for a
//! full ref or a `push.full_refs` match, else `fast`; to other remotes
//! `tier_for_ref(remote ref)`. A `full` miss is allowed when the commit is
//! a trusted remote's current tip of that branch (R14 outcome 2, kept for
//! `pre-push` by L1).
//!
//! Scope (R5): a push to a trusted URL is gated whatever the local path of
//! the repo; other pushes only from in-scope repos (L4).

use std::ffi::OsString;

use super::gate::{self, Check, Gate, PushFacts, RemoteVerify};
use crate::config::Tier;
use crate::config::repo::branch_name;
use crate::exit;
use crate::gitx::Oid;
use crate::metrics::HookOutcome;
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

/// R102: true when the remote's current value of a branch is not in the
/// pushed commit: the remote commit is not in the local repo, or it is not
/// an ancestor of the local commit. A git error counts as false: this rule
/// only saves time, so it never refuses on a doubt.
fn remote_ahead(gate: &Gate<'_>, line: &PushLine) -> bool {
    match gate
        .git
        .rev_parse_verify(&format!("{}^{{commit}}", line.remote_oid))
    {
        Ok(None) => true,
        Ok(Some(_)) => gate
            .git
            .output([
                "merge-base",
                "--is-ancestor",
                line.remote_oid.as_str(),
                line.local_oid.as_str(),
            ])
            .is_ok_and(|o| o.status.code() == Some(1)),
        Err(_) => false,
    }
}

/// git global options that take the next argument as their value.
const GIT_VALUE_OPTIONS: &[&str] = &[
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--config-env",
    "--super-prefix",
    "--attr-source",
];

/// `git push` options that take the next argument as their value.
const PUSH_VALUE_OPTIONS: &[&str] = &["--repo", "--receive-pack", "--exec", "--push-option"];

/// `git push` options that force a non-fast-forward update (R102). An
/// abbreviation (any prefix git accepts) counts too.
const PUSH_FORCE_OPTIONS: &[&str] = &["force", "force-with-lease", "force-if-includes", "mirror"];

/// True when config `key` is `remote.<remote>.<var>` (section and variable
/// without regard to case, the remote name exact).
fn is_remote_key(key: &str, remote: &str, var: &str) -> bool {
    let Some((section, rest)) = key.split_once('.') else {
        return false;
    };
    let Some((name, v)) = rest.rsplit_once('.') else {
        return false;
    };
    section.eq_ignore_ascii_case("remote") && name == remote && v.eq_ignore_ascii_case(var)
}

/// R102: whether the arguments of the parent `git` force the push to
/// `remote`. `None` when they are not a `git push` this can read (an
/// alias, another command): the caller then must not refuse. Command-line
/// config (`-c remote.<remote>.mirror`, `-c remote.<remote>.push=+...`)
/// counts; `--config-env` for those keys counts as forced, since its value
/// is not on the command line.
#[must_use]
pub fn args_force_push(args: &[OsString], remote: &str) -> Option<bool> {
    let mut forced = false;
    let mut i = 0;
    // Global options before the subcommand.
    let sub = loop {
        let a = args.get(i)?.to_string_lossy();
        i += 1;
        if !a.starts_with('-') {
            break a;
        }
        let (name, inline) = match a.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n.to_owned(), Some(v.to_owned())),
            _ => (a.clone().into_owned(), None),
        };
        if !GIT_VALUE_OPTIONS.contains(&name.as_str()) {
            continue;
        }
        let value = match inline {
            Some(v) => v,
            None => {
                let v = args.get(i)?.to_string_lossy().into_owned();
                i += 1;
                v
            }
        };
        let (key, val) = match value.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (value.as_str(), None),
        };
        let push_key = is_remote_key(key, remote, "push");
        let mirror_key = is_remote_key(key, remote, "mirror");
        if name == "--config-env" {
            forced |= push_key || mirror_key;
        } else if name == "-c" {
            forced |= push_key && val.is_some_and(|v| v.starts_with('+'));
            forced |= mirror_key
                && !val.is_some_and(|v| {
                    ["false", "no", "off", "0", ""].contains(&v.to_ascii_lowercase().as_str())
                });
        }
    };
    if sub != "push" {
        return None;
    }
    let mut positional_only = false;
    while let Some(a) = args.get(i) {
        let a = a.to_string_lossy();
        i += 1;
        if positional_only || !a.starts_with('-') || a == "-" {
            // A `+` refspec forces its ref.
            forced |= a.starts_with('+');
            continue;
        }
        if a == "--" {
            positional_only = true;
            continue;
        }
        if let Some(long) = a.strip_prefix("--") {
            let name = long.split_once('=').map_or(long, |(n, _)| n);
            if name.starts_with("no-") {
                continue;
            }
            forced |= !name.is_empty() && PUSH_FORCE_OPTIONS.iter().any(|o| o.starts_with(name));
            if name == long && PUSH_VALUE_OPTIONS.contains(&a.as_ref()) {
                i += 1;
            }
            continue;
        }
        // A short cluster: `-f`, `-uf`; `-o` takes the rest or the next
        // argument as its value.
        let cluster: Vec<char> = a[1..].chars().collect();
        for (n, c) in cluster.iter().enumerate() {
            if *c == 'f' {
                forced = true;
            }
            if *c == 'o' {
                if n + 1 == cluster.len() {
                    i += 1;
                }
                break;
            }
        }
    }
    Some(forced)
}

/// R102: whether `remote`'s own config forces its pushes:
/// `remote.<remote>.mirror` true, or a `remote.<remote>.push` refspec that
/// starts with `+`. A config read that fails counts as forced.
fn config_forces_push(gate: &Gate<'_>, remote: &str) -> bool {
    let get = |args: &[&str]| match gate.git.output(args) {
        Ok(o) if o.status.code() == Some(0) => {
            Some(String::from_utf8_lossy(&o.stdout).into_owned())
        }
        Ok(o) if o.status.code() == Some(1) => Some(String::new()),
        _ => None,
    };
    let mirror = format!("remote.{remote}.mirror");
    let push = format!("remote.{remote}.push");
    let (Some(mirror), Some(push)) = (
        get(&["config", "--type=bool", "--get", &mirror]),
        get(&["config", "--get-all", &push]),
    ) else {
        return true;
    };
    mirror.trim() == "true" || push.lines().any(|l| l.trim_start().starts_with('+'))
}

/// R102: the push is forced, or whether it is cannot be told.
fn push_forced(gate: &Gate<'_>, remote: &str) -> bool {
    let Some(args) = super::argv::parent_git_args() else {
        return true;
    };
    args_force_push(&args, remote).is_none_or(|f| f) || config_forces_push(gate, remote)
}

/// R102: refuses, before any plan, lookup or job, the push of branches
/// whose remote value is not in the pushed commit, unless the push is
/// forced. git rejects such a push after the hook, so a check would be
/// wasted. Returns the exit code when it refuses.
fn refuse_behind(gate: &Gate<'_>, remote: &str, lines: &[PushLine]) -> Option<u8> {
    let behind: Vec<&PushLine> = lines
        .iter()
        .filter(|l| {
            l.remote_ref.starts_with("refs/heads/")
                && !l.local_oid.is_zero()
                && !l.remote_oid.is_zero()
        })
        .filter(|l| remote_ahead(gate, l))
        .collect();
    if behind.is_empty() || push_forced(gate, remote) {
        return None;
    }
    let shown = super::argv::shell_quote(remote);
    for l in &behind {
        eprintln!(
            "tollgate: DENIED {} {}: {remote} has commits that this push does not contain (remote at {}). No check was started (R102).",
            gate.hook,
            l.remote_ref,
            l.remote_oid.short(12)
        );
        eprintln!(
            "tollgate: run: git fetch {shown} {} && git merge FETCH_HEAD   (or rebase), then push again.",
            super::argv::shell_quote(branch_name(&l.remote_ref))
        );
    }
    let metric: Vec<(Option<Tier>, HookOutcome, Option<&crate::ids::JobId>)> = behind
        .iter()
        .map(|_| (None, HookOutcome::Behind, None))
        .collect();
    gate::record_hook_lines(gate, &metric);
    Some(exit::FAIL)
}

/// R55, R108: the selection base of a pushed branch. The remote's current
/// commit when the repo has it. Else (a new branch, or a remote commit not
/// in the repo) the policy commit of the pushed commit (L2), when it is
/// not the pushed commit itself; else the empty tree.
fn push_base(
    gate: &Gate<'_>,
    line: &PushLine,
    policy_commit: Option<&Oid>,
) -> Result<Base, String> {
    let remote = if line.remote_oid.is_zero() {
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
    if let Some(b) = remote {
        return Ok(b);
    }
    if let Some(c) = policy_commit.filter(|c| **c != line.local_oid)
        && let Some(tree) = gate.git.tree_of(c.as_str()).map_err(|e| e.to_string())?
    {
        return Ok(Base {
            tree,
            commit: Some(c.clone()),
        });
    }
    Ok(Base {
        tree: gate
            .git
            .object_format()
            .map_err(|e| e.to_string())?
            .empty_tree(),
        commit: None,
    })
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
    // R5, R20: git gives the URL it pushes to (after rewrites); a push to
    // a remote with a trusted URL counts too, wherever pushInsteadOf sends
    // it. Gating takes the loose match too (item 34: a look-alike URL
    // gets the trusted push table, R107, which is never below
    // `tier_for_ref`; it is never trusted for anything that grants).
    let push_trusted = gate.scope.remote_in_scope(&url) || gate.push_trusted.contains(&remote);
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
    if let Some(code) = refuse_behind(gate, &remote, &lines) {
        return code;
    }
    let mut checks = Vec::new();
    // R111: only a push that is not forced has candidates; asked once.
    let mut forced: Option<bool> = None;
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
        let policy = match gate.policy(&tree, Some(&line.local_oid), &line.remote_ref) {
            Ok(p) => p,
            Err(e) => return deny(gate, what, &e),
        };
        let tier = match policy.config.ref_rules() {
            Ok(rules) => rules.push_tier(&line.remote_ref, push_trusted),
            Err(e) => return deny(gate, what, &e),
        };
        let base = match push_base(gate, line, policy.base.commit.as_ref()) {
            Ok(b) => b,
            Err(e) => return deny(gate, what, &e),
        };
        let remote_verify = (tier == Tier::Full).then(|| RemoteVerify::Commit {
            oid: line.local_oid.clone(),
            branch: branch_name(&line.remote_ref).to_owned(),
        });
        let rerun_hint = format!(
            "tollgate check --tier {tier} --rev {} --rerun",
            line.local_oid
        );
        // R111: a candidate is a `full` line to a trusted remote (one whose
        // server R112 can ask) in a push that is not forced.
        let candidate = match gate.remote_refs.get(&remote) {
            Some(trusted) if tier == Tier::Full => {
                let f = *forced.get_or_insert_with(|| push_forced(gate, &remote));
                (!f).then(|| trusted.url.clone())
            }
            _ => None,
        };
        checks.push(Check {
            tree,
            tier,
            tip: Some(line.local_oid.clone()),
            base: Some(base),
            refname: line.remote_ref.clone(),
            remote_verify,
            rerun_hint,
            push: Some(PushFacts {
                remote: remote.clone(),
                remote_ref: line.remote_ref.clone(),
                local_ref: line.local_ref.clone(),
                commit: line.local_oid.clone(),
                remote_oid: line.remote_oid.clone(),
                candidate,
            }),
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

    fn force(cmd: &str) -> Option<bool> {
        let args: Vec<OsString> = cmd.split_whitespace().map(OsString::from).collect();
        args_force_push(&args, "origin")
    }

    /// R102: which parent `git` command lines force the push.
    #[test]
    fn forced_push_arguments_r102() {
        for cmd in [
            "push --force origin feat",
            "push -f origin feat",
            "push -uf origin feat",
            "push -fu origin feat",
            "push --force-with-lease origin feat",
            "push --force-with-lease=feat:abc origin feat",
            "push --force-if-includes origin feat",
            "push --mirror origin",
            "push --forc origin feat",
            "push origin +feat",
            "push origin main +refs/heads/feat:refs/heads/feat",
            "push origin -- +feat",
            "-C /x -c core.x=1 push --force origin feat",
            "-c remote.origin.push=+refs/heads/*:refs/heads/* push origin",
            "-c remote.origin.mirror push origin",
            "-c Remote.origin.Mirror=yes push origin",
            "--config-env=remote.origin.push=X push origin",
            "--git-dir=/x/.git push -f",
        ] {
            assert_eq!(force(cmd), Some(true), "{cmd}");
        }
        for cmd in [
            "push origin feat",
            "push -u origin feat",
            "push --no-force-with-lease origin feat",
            "push -o ci.skip origin feat",
            "push -ofoo origin feat",
            "push --push-option -f origin feat",
            "push --follow-tags origin feat",
            "push origin feat:+x",
            "-c remote.origin.mirror=false push origin",
            "-c remote.other.mirror=true push origin",
            "-c remote.origin.push=refs/heads/a push origin",
            "-C +dir push origin feat",
        ] {
            assert_eq!(force(cmd), Some(false), "{cmd}");
        }
        // Not a push it can read (an alias, a truncated line): unknown.
        for cmd in ["pf origin feat", "-C", "", "-c"] {
            assert_eq!(force(cmd), None, "{cmd}");
        }
    }
}
