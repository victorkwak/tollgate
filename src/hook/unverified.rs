//! Commits made without the gate (item 17): detection only.
//!
//! `git commit --no-verify` and `git merge --no-verify` skip `pre-commit`
//! and `pre-merge-commit`; the guard is then the only control. But
//! `post-commit` and `post-merge` still run, so they can tell:
//!
//! - A gate hook that allows its commit leaves a marker named by its
//!   parent git process (pid and start time, so a reused pid never
//!   matches): `<state>/gate-runs/<pid>-<start>`. The post hook of the same
//!   git process takes it. That is the common path, with no subprocess
//!   (L19).
//! - Without a marker, outside a sequencer operation (`CHERRY_PICK_HEAD`,
//!   `REVERT_HEAD`, `rebase-*`, `sequencer`, or a parent git running
//!   `cherry-pick`, `revert`, `rebase` or `am`: the known gap of L1), in an
//!   in-scope repo: a `HEAD` whose tree never passed a job or a gate hook
//!   ([`crate::cache::store::RecordStore::tree_passed`]) and that no
//!   trusted remote-tracking ref
//!   contains is recorded in `<state>/unverified/<repo key>.json`, with a
//!   loud warning.
//!
//! `tollgate status` lists them, and every deny names them. Nothing is
//! undone (a `reset` from a hook could lose work); the push gate, CI and
//! GitLab protection of `main` still check every tree that leaves.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::dirs::Dirs;
use crate::fsx;
use crate::gitx::{Git, Oid, RepoLayout};

/// Entries kept per repo.
const KEEP: usize = 200;

/// One commit made without the gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnverifiedCommit {
    /// The commit.
    pub commit: Oid,
    /// Its tree.
    pub tree: Oid,
    /// The ref `HEAD` named (`refs/heads/x`, or `HEAD` when detached).
    pub refname: String,
    /// `post-commit` or `post-merge`.
    pub hook: String,
    /// The git command as `git <subcommand> [flags]`, when it could be
    /// read: only [`KEPT_FLAGS`], never a value (item 30). Records of older
    /// builds stored the whole command line under `command`; that key is
    /// not read, and [`recorded`] rewrites such a file without it.
    #[serde(
        default,
        rename = "git_command",
        skip_serializing_if = "Option::is_none"
    )]
    pub command: Option<String>,
    /// When it was seen.
    pub at: jiff::Timestamp,
}

/// The marker of git process `pid`.
fn gate_run_file(dirs: &Dirs, pid: i32) -> Option<PathBuf> {
    let start = crate::procs::start_time(pid)?;
    Some(dirs.gate_runs_dir().join(format!("{pid}-{start}")))
}

fn parent_pid() -> i32 {
    i32::try_from(std::os::unix::process::parent_id()).unwrap_or(0)
}

/// Marks that a gate hook of git process `pid` allowed its commit.
pub fn mark_gate_run_of(dirs: &Dirs, pid: i32) {
    if let Some(f) = gate_run_file(dirs, pid) {
        let _ = fsx::ensure_dir(&dirs.gate_runs_dir()).and_then(|()| std::fs::write(&f, b""));
    }
}

/// Marks that this gate hook allowed the commit of its parent git.
pub fn mark_gate_run(dirs: &Dirs) {
    mark_gate_run_of(dirs, parent_pid());
}

/// Takes the marker of the parent git: true when a gate hook of the same
/// git process allowed this commit.
fn take_gate_run(dirs: &Dirs) -> bool {
    gate_run_file(dirs, parent_pid()).is_some_and(|f| std::fs::remove_file(f).is_ok())
}

/// True when `tree` passed a job or a gate hook allowed it.
fn tree_passed(dirs: &Dirs, tree: &Oid) -> bool {
    crate::cache::store::RecordStore::new(dirs).tree_passed(tree)
}

fn file(dirs: &Dirs, layout: &RepoLayout) -> PathBuf {
    dirs.unverified_dir()
        .join(format!("{}.json", layout.repo_key().as_str()))
}

/// Every commit recorded for the repo, oldest first. A file of an older
/// build that kept whole command lines (item 30: they can hold `-c`
/// secrets and URLs with tokens) is rewritten without them.
#[must_use]
pub fn recorded(dirs: &Dirs, layout: &RepoLayout) -> Vec<UnverifiedCommit> {
    let path = file(dirs, layout);
    let Some(bytes) = fsx::read_optional(&path).ok().flatten() else {
        return Vec::new();
    };
    let all: Vec<UnverifiedCommit> = serde_json::from_slice(&bytes).unwrap_or_default();
    let old_key = serde_json::from_slice::<Vec<serde_json::Value>>(&bytes)
        .is_ok_and(|v| v.iter().any(|e| e.get("command").is_some()));
    if old_key && let Ok(json) = serde_json::to_vec_pretty(&all) {
        let _ = fsx::write_atomic(&path, &json);
    }
    all
}

/// The recorded commits whose tree has not passed since (`passed` adds a
/// check by record, for trees a job passed before the tree index).
pub fn pending(
    dirs: &Dirs,
    layout: &RepoLayout,
    passed: impl Fn(&Oid) -> bool,
) -> Vec<UnverifiedCommit> {
    recorded(dirs, layout)
        .into_iter()
        .filter(|u| !tree_passed(dirs, &u.tree) && !passed(&u.tree))
        .collect()
}

fn add(dirs: &Dirs, layout: &RepoLayout, entry: UnverifiedCommit) {
    let mut all = recorded(dirs, layout);
    if all.iter().any(|u| u.commit == entry.commit) {
        return;
    }
    all.push(entry);
    let drop = all.len().saturating_sub(KEEP);
    all.drain(..drop);
    if let Ok(json) = serde_json::to_vec_pretty(&all) {
        let _ = fsx::write_atomic(&file(dirs, layout), &json);
    }
}

/// One line per pending commit, for a deny (item 17).
#[must_use]
pub fn deny_note(dirs: &Dirs, layout: &RepoLayout) -> Vec<String> {
    let p = pending(dirs, layout, |_| false);
    if p.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![format!(
        "tollgate: note: {} commit(s) in this repo were made without the gate (unverified; tollgate status lists them):",
        p.len()
    )];
    lines.extend(p.iter().rev().take(5).map(|u| {
        format!(
            "tollgate:   {} on {} ({}){}",
            u.commit.short(12),
            u.refname,
            u.hook,
            u.command
                .as_deref()
                .map(|c| format!(": {c}"))
                .unwrap_or_default()
        )
    }));
    lines
}

/// Git dir entries that mean a sequencer operation is under way.
const SEQUENCER_STATE: &[&str] = &[
    "CHERRY_PICK_HEAD",
    "REVERT_HEAD",
    "rebase-merge",
    "rebase-apply",
    "sequencer",
];

/// Parent git subcommands that make commits without `pre-commit` (L1).
const SEQUENCER_COMMANDS: &[&str] = &["cherry-pick", "revert", "rebase", "am"];

/// The git subcommand in `args` (after global options).
fn subcommand(args: &[std::ffi::OsString]) -> Option<String> {
    let mut it = args.iter().map(|a| a.to_string_lossy());
    while let Some(a) = it.next() {
        match a.as_ref() {
            "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace" | "--exec-path"
            | "--config-env" => {
                it.next();
            }
            s if s.starts_with('-') => {}
            s => return Some(s.to_owned()),
        }
    }
    None
}

/// Flag names an unverified record keeps (item 30): what says how the
/// commit skipped the gate. Everything else of the command line (`-c` and
/// `--config-env` contents, URLs, messages, paths, branch names) can hold
/// secrets or private text and is dropped.
const KEPT_FLAGS: &[&str] = &["--no-verify", "-n", "--amend", "--no-ff", "-a"];

/// Short options that take no value, in a cluster such as `-an`: the
/// letters after the first one that is not here may be a glued value
/// (`-am<message>`), so they are not read.
const FLAG_LETTERS: &[u8] = b"anqvesiopz";

/// `git <subcommand> [kept flags]` from git's argv (item 30): the
/// subcommand after the global options, then each of [`KEPT_FLAGS`] the
/// command used, in order (a unique abbreviation of `--no-verify` counts
/// as it). No value of any option is kept.
fn redacted_command(args: &[std::ffi::OsString]) -> Option<String> {
    let sub = subcommand(args)?;
    let mut it = args.iter().map(|a| a.to_string_lossy());
    for a in it.by_ref() {
        if a == sub {
            break;
        }
    }
    let mut flags: Vec<&'static str> = Vec::new();
    let mut keep = |f: &'static str| {
        if !flags.contains(&f) {
            flags.push(f);
        }
    };
    for a in it {
        if a == "--" {
            break;
        }
        if let Some(long) = a.strip_prefix("--") {
            let name = long.split_once('=').map_or(long, |(n, _)| n);
            if name.len() >= 4 && "no-verify".starts_with(name) {
                keep("--no-verify");
            } else if let Some(f) = KEPT_FLAGS
                .iter()
                .find(|f| f.strip_prefix("--") == Some(name))
            {
                keep(f);
            }
        } else if let Some(cluster) = a.strip_prefix('-') {
            for b in cluster.bytes() {
                if !FLAG_LETTERS.contains(&b) {
                    break;
                }
                match b {
                    b'a' => keep("-a"),
                    b'n' => keep("-n"),
                    _ => {}
                }
            }
        }
    }
    let mut out = format!("git {}", super::argv::shell_quote(&sub));
    for f in flags {
        out.push(' ');
        out.push_str(f);
    }
    Some(out)
}

/// What a post hook needs.
#[derive(Debug)]
pub struct PostHook<'a> {
    /// `post-commit` or `post-merge`.
    pub name: &'static str,
    /// git's arguments to the hook (`post-merge <squash flag>`).
    pub args: &'a [std::ffi::OsString],
    /// The repo.
    pub layout: &'a RepoLayout,
    /// The hook's environment.
    pub env: &'a crate::env::EnvSnapshot,
    /// The running binary.
    pub exe: &'a Path,
}

/// Item 17 in `post-commit` and `post-merge`; prints a warning when it
/// records a commit. Never fails the hook.
pub fn detect(hook: &PostHook<'_>, dirs: &Dirs) {
    if take_gate_run(dirs) {
        return;
    }
    // `post-merge 1` follows a squash merge, which makes no commit.
    if hook.name == "post-merge" && hook.args.first().is_some_and(|a| a == "1") {
        return;
    }
    let gd = &hook.layout.git_dir;
    if SEQUENCER_STATE.iter().any(|f| gd.join(f).exists()) {
        return;
    }
    let parent = super::argv::parent_git_args();
    if let Some(sub) = parent.as_deref().and_then(subcommand)
        && SEQUENCER_COMMANDS.contains(&sub.as_str())
    {
        return;
    }
    // Item 37: cheap checks before Gate::open (L19, 5 ms). A fast-forward
    // merge (a `git pull`) makes no commit: its new HEAD is the tip of
    // another ref. Read from the git dir files, no subprocess.
    if hook.name == "post-merge" && fast_forward(hook.layout) {
        return;
    }
    let env = dirs.env_for(hook.env);
    // A HEAD whose tree passed has nothing to record: one rev-parse.
    if let Ok(Some(tree)) = Git::scrubbed(&env, hook.layout.hooks_cwd()).tree_of("HEAD")
        && tree_passed(dirs, &tree)
    {
        return;
    }
    let Ok(gate) =
        super::gate::Gate::open(hook.name, &env, hook.exe, hook.layout.clone(), dirs.clone())
    else {
        return;
    };
    if !gate.in_scope() {
        return;
    }
    let Some(entry) = unverified_head(&gate.git, dirs, &gate.trusted) else {
        return;
    };
    eprintln!(
        "tollgate: WARNING: commit {} on {} was made without the gate ({} ran, but no pre-commit or pre-merge-commit of this git command allowed it: --no-verify?). It is recorded as unverified; tollgate status lists it. Check it with: tollgate check --rev {}",
        entry.commit.short(12),
        entry.refname,
        hook.name,
        entry.commit
    );
    add(
        dirs,
        hook.layout,
        UnverifiedCommit {
            hook: hook.name.to_owned(),
            command: parent.as_deref().and_then(redacted_command),
            ..entry
        },
    );
}

/// Item 37: `HEAD` is the tip of a ref other than its own branch, so the
/// merge before this `post-merge` was a fast-forward and made no commit.
/// False when the git dir files cannot tell (the caller then checks).
fn fast_forward(layout: &RepoLayout) -> bool {
    use crate::gitx::ref_files::{self, Head};
    let (oid, own) = match ref_files::head(layout) {
        Some(Head::Symbolic(r)) => match ref_files::resolve(layout, &r) {
            Some(oid) => (oid, Some(r)),
            None => return false,
        },
        Some(Head::Detached(oid)) => (oid, None),
        None => return false,
    };
    ref_files::other_ref_points_at(layout, &oid, own.as_deref()) == Some(true)
}

/// `HEAD` when its tree never passed and no trusted remote-tracking ref
/// contains it.
fn unverified_head(git: &Git, dirs: &Dirs, trusted: &[String]) -> Option<UnverifiedCommit> {
    let commit = git.rev_parse_verify("HEAD^{commit}").ok().flatten()?;
    let tree = git.tree_of(commit.as_str()).ok().flatten()?;
    if tree_passed(dirs, &tree) {
        return None;
    }
    if !trusted.is_empty() {
        let mut args = vec![
            "for-each-ref".to_owned(),
            "--count=1".to_owned(),
            format!("--contains={commit}"),
            "--format=%(refname)".to_owned(),
        ];
        args.extend(trusted.iter().map(|r| format!("refs/remotes/{r}/")));
        if git.run(&args).is_ok_and(|out| !out.trim_ascii().is_empty()) {
            return None;
        }
    }
    let refname = git
        .run_line(["symbolic-ref", "-q", "HEAD"])
        .ok()
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| "HEAD".to_owned());
    Some(UnverifiedCommit {
        commit,
        tree,
        refname,
        hook: String::new(),
        command: None,
        at: jiff::Timestamp::now(),
    })
}

/// gc: markers of git processes that are gone and older than `age`.
pub fn gc_gate_runs(dirs: &Dirs, age: std::time::Duration) -> usize {
    let mut n = 0;
    for e in std::fs::read_dir(dirs.gate_runs_dir())
        .into_iter()
        .flatten()
        .flatten()
    {
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|d| d >= age);
        let name = e.file_name().to_string_lossy().into_owned();
        let live = name
            .split_once('-')
            .and_then(|(pid, start)| Some((pid.parse::<i32>().ok()?, start.parse::<u64>().ok()?)))
            .is_some_and(|(pid, start)| crate::procs::start_time(pid) == Some(start));
        if old && !live && std::fs::remove_file(e.path()).is_ok() {
            n += 1;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subcommands_skip_global_options_item17() {
        let a = |v: &[&str]| -> Vec<std::ffi::OsString> { v.iter().map(Into::into).collect() };
        assert_eq!(
            subcommand(&a(&["-C", "x", "-c", "a=b", "revert", "HEAD"])).as_deref(),
            Some("revert")
        );
        assert_eq!(
            subcommand(&a(&["--no-pager", "commit"])).as_deref(),
            Some("commit")
        );
        assert_eq!(subcommand(&a(&[])), None);
    }

    /// Item 30: only the subcommand and the flag names of [`KEPT_FLAGS`].
    #[test]
    fn commands_keep_no_values_item30() {
        let a = |v: &[&str]| -> Vec<std::ffi::OsString> { v.iter().map(Into::into).collect() };
        let r = |v: &[&str]| redacted_command(&a(v));
        assert_eq!(
            r(&[
                "-c",
                "http.extraHeader=Authorization: Bearer x",
                "--config-env=core.sshCommand=SECRET",
                "commit",
                "-am",
                "token: x",
                "--no-verif",
                "--amend",
                "--author=me <a@b>",
                "--",
                "-n",
            ])
            .as_deref(),
            Some("git commit -a --no-verify --amend")
        );
        assert_eq!(
            r(&[
                "merge",
                "--no-ff",
                "-n",
                "--no-edit",
                "https://u:tok@h/r",
                "side"
            ])
            .as_deref(),
            Some("git merge --no-ff -n")
        );
        assert_eq!(r(&["commit", "-mn"]).as_deref(), Some("git commit"));
        assert_eq!(r(&["-c", "a=b"]), None);
    }

    #[test]
    fn a_gate_run_marker_names_one_process_item17() {
        let tmp = tempfile::tempdir().unwrap();
        let env = crate::env::EnvSnapshot::from_pairs([("HOME", tmp.path().as_os_str())]);
        let dirs = Dirs::from_env(&env).unwrap();
        let me = i32::try_from(std::process::id()).unwrap();
        mark_gate_run_of(&dirs, me);
        let f = gate_run_file(&dirs, me).unwrap();
        assert!(f.exists());
        // A live process's marker survives gc; a dead one's goes.
        assert_eq!(gc_gate_runs(&dirs, std::time::Duration::ZERO), 0);
        std::fs::write(dirs.gate_runs_dir().join("1-1"), b"").unwrap();
        assert_eq!(gc_gate_runs(&dirs, std::time::Duration::ZERO), 1);
        assert!(f.exists());
    }
}
