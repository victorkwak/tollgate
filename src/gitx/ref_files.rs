//! Reading refs from the git dir files, with no subprocess (L19, item 37).
//!
//! Used only where an answer is an optimization: every function returns
//! `None` when the files do not answer for sure (a reftable repo, a ref
//! file that is not a plain value, too many loose refs), and the caller
//! then asks git.

use std::fs;
use std::path::Path;

use super::{Oid, RepoLayout};

/// Loose ref files [`remote_refs_at`] reads before it gives up.
const LOOSE_BUDGET: usize = 4096;

/// What `HEAD` holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Head {
    /// `ref: <refname>`.
    Symbolic(String),
    /// A commit id (detached `HEAD`).
    Detached(Oid),
}

/// True when the repo stores refs in a reftable, which these files do not
/// show.
fn reftable(layout: &RepoLayout) -> bool {
    layout.common_dir.join("reftable").exists()
}

/// `HEAD` of the worktree of `layout`.
#[must_use]
pub fn head(layout: &RepoLayout) -> Option<Head> {
    if reftable(layout) {
        return None;
    }
    let text = fs::read_to_string(layout.git_dir.join("HEAD")).ok()?;
    let text = text.trim_end_matches('\n');
    match text.strip_prefix("ref: ") {
        Some(r) if r.starts_with("refs/") => Some(Head::Symbolic(r.to_owned())),
        Some(_) => None,
        None => Oid::parse(text).ok().map(Head::Detached),
    }
}

/// The value of the loose ref file at `path`: `None` for a missing file,
/// `Some(None)` for a file that is not a plain value (a symref, garbage).
fn loose_value(path: &Path) -> Option<Option<Oid>> {
    let text = fs::read_to_string(path).ok()?;
    Some(Oid::parse(text.trim_end_matches('\n')).ok())
}

/// `<common dir>/packed-refs` as (refname, value) pairs; a peeled line
/// (`^<oid>`, the commit an annotated tag names) counts as a value of the
/// tag before it. `Some(empty)` when there is no such file.
fn packed(layout: &RepoLayout) -> Option<Vec<(String, Oid)>> {
    let text = match fs::read_to_string(layout.common_dir.join("packed-refs")) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(Vec::new()),
        Err(_) => return None,
    };
    let mut out: Vec<(String, Oid)> = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(peeled) = line.strip_prefix('^') {
            let name = out.last()?.0.clone();
            out.push((name, Oid::parse(peeled).ok()?));
            continue;
        }
        let (oid, name) = line.split_once(' ')?;
        out.push((name.to_owned(), Oid::parse(oid).ok()?));
    }
    Some(out)
}

/// The value of branch-like ref `refname` (`refs/...`).
#[must_use]
pub fn resolve(layout: &RepoLayout, refname: &str) -> Option<Oid> {
    if reftable(layout) || !refname.starts_with("refs/") || refname.contains("..") {
        return None;
    }
    match loose_value(&layout.common_dir.join(refname)) {
        Some(v) => v,
        None => packed(layout)?
            .into_iter()
            .find(|(n, _)| n == refname)
            .map(|(_, o)| o),
    }
}

/// True when `name` is a ref name git reads as written: ASCII letters,
/// digits and `-_.+/` only, no empty part, no part that starts with `.`
/// or ends with `.lock`, no `..`. Narrower than `git check-ref-format`;
/// a file whose name git would refuse (git ignores it) never counts.
fn plain_ref_name(name: &str) -> bool {
    !name.contains("..")
        && name.split('/').all(|part| {
            !part.is_empty()
                && !part.starts_with('.')
                && !part.ends_with(".lock")
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+'))
        })
}

/// The remote-tracking refs (`refs/remotes/...`, in the common dir) whose
/// value is `oid`: loose files, and packed values no loose file
/// overrides. A file that is not a plain value (the symref
/// `refs/remotes/origin/HEAD`) and a name git would not read do not
/// count. `None` when the files cannot say for sure.
#[must_use]
pub fn remote_refs_at(layout: &RepoLayout, oid: &Oid) -> Option<Vec<String>> {
    if reftable(layout) {
        return None;
    }
    let mut found = Vec::new();
    let mut loose = std::collections::BTreeSet::new();
    let mut budget = LOOSE_BUDGET;
    let mut stack = vec![layout.common_dir.join("refs/remotes")];
    while let Some(dir) = stack.pop() {
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        for e in rd {
            let e = e.ok()?;
            budget = budget.checked_sub(1)?;
            let path = e.path();
            // Not followed: a symlink (a legacy symref, or a dir elsewhere)
            // makes the answer git's.
            let ft = e.file_type().ok()?;
            if ft.is_dir() {
                stack.push(path);
                continue;
            }
            if !ft.is_file() {
                return None;
            }
            let rel = path.strip_prefix(&layout.common_dir).ok()?;
            let name = rel.to_str()?.to_owned();
            if name.ends_with(".lock") {
                continue;
            }
            if loose_value(&path).flatten().as_ref() == Some(oid) && plain_ref_name(&name) {
                found.push(name.clone());
            }
            loose.insert(name);
        }
    }
    found.extend(
        packed(layout)?
            .into_iter()
            .filter(|(n, o)| {
                o == oid
                    && n.starts_with("refs/remotes/")
                    && !loose.contains(n)
                    && plain_ref_name(n)
            })
            .map(|(n, _)| n),
    );
    found.sort();
    found.dedup();
    Some(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn git(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@e.invalid")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@e.invalid")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "{args:?}: {out:?}");
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    #[test]
    fn refs_from_files_match_git_item37() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().canonicalize().unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);
        git(&repo, &["commit", "-q", "--allow-empty", "-m", "a"]);
        let a = Oid::parse(&git(&repo, &["rev-parse", "HEAD"])).unwrap();
        let layout = RepoLayout {
            git_dir: repo.join(".git"),
            common_dir: repo.join(".git"),
            worktree: Some(repo.clone()),
        };
        assert_eq!(
            head(&layout),
            Some(Head::Symbolic("refs/heads/main".into()))
        );
        assert_eq!(resolve(&layout, "refs/heads/main"), Some(a.clone()));
        // A local branch or a tag at a is not a remote-tracking ref.
        git(&repo, &["branch", "side"]);
        git(&repo, &["tag", "t1"]);
        assert_eq!(remote_refs_at(&layout, &a), Some(vec![]));
        git(
            &repo,
            &["update-ref", "refs/remotes/origin/main", a.as_str()],
        );
        git(
            &repo,
            &[
                "symbolic-ref",
                "refs/remotes/origin/HEAD",
                "refs/remotes/origin/main",
            ],
        );
        let origin_main = vec!["refs/remotes/origin/main".to_owned()];
        assert_eq!(remote_refs_at(&layout, &a), Some(origin_main.clone()));
        // Packed: the packed value counts, unless a loose file overrides it.
        git(&repo, &["pack-refs", "--all"]);
        assert_eq!(resolve(&layout, "refs/heads/main"), Some(a.clone()));
        assert_eq!(remote_refs_at(&layout, &a), Some(origin_main.clone()));
        git(&repo, &["commit", "-q", "--allow-empty", "-m", "b"]);
        let b = Oid::parse(&git(&repo, &["rev-parse", "HEAD"])).unwrap();
        git(
            &repo,
            &["update-ref", "refs/remotes/origin/main", b.as_str()],
        );
        assert_eq!(
            remote_refs_at(&layout, &a),
            Some(vec![]),
            "origin/main's packed value is stale"
        );
        assert_eq!(remote_refs_at(&layout, &b), Some(origin_main));
        // A symlink: git's answer, not the files'.
        std::os::unix::fs::symlink(
            "../../heads/side",
            repo.join(".git/refs/remotes/origin/link"),
        )
        .unwrap();
        assert_eq!(remote_refs_at(&layout, &a), None);
        std::fs::remove_file(repo.join(".git/refs/remotes/origin/link")).unwrap();
        // A name git would not read does not count.
        std::fs::write(
            repo.join(".git/refs/remotes/origin/.hidden"),
            format!("{a}\n"),
        )
        .unwrap();
        assert_eq!(remote_refs_at(&layout, &a), Some(vec![]));
        git(&repo, &["checkout", "-q", "--detach", a.as_str()]);
        assert_eq!(head(&layout), Some(Head::Detached(a)));
    }
}
