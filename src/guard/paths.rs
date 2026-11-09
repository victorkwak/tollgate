//! Paths for the guard's write rules (R25, G7, G8, item 15).
//!
//! A path a command writes is made absolute against the tracked cwd,
//! `.` and `..` are applied, and the longest existing prefix is resolved
//! through symlinks, so a link into tollgate's dirs or into `.git` does
//! not hide the target.

use std::path::{Component, Path, PathBuf};

use super::rules::Context;

/// `path` made absolute against `cwd`, with `.` and `..` removed
/// lexically.
#[must_use]
pub fn lexical(cwd: &Path, path: &Path) -> PathBuf {
    let abs = if path.is_absolute() {
        path.to_owned()
    } else {
        cwd.join(path)
    };
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

/// `path` (absolute) with symlinks resolved as the kernel resolves them:
/// each `..` applies to the resolved dir before it, and the longest
/// existing prefix of the result is canonical. The rest is kept as
/// written.
#[must_use]
pub fn canon(path: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    for c in path.components() {
        match c {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                if let Ok(r) = std::fs::canonicalize(&out) {
                    out = r;
                }
                out.pop();
            }
            Component::Normal(n) => out.push(n),
        }
    }
    let mut tail = Vec::new();
    let mut cur = out.clone();
    loop {
        if let Ok(mut r) = std::fs::canonicalize(&cur) {
            for t in tail.iter().rev() {
                r.push(t);
            }
            return r;
        }
        match cur.file_name() {
            Some(n) => {
                tail.push(n.to_owned());
                cur.pop();
            }
            None => return out,
        }
    }
}

/// Lowercase text of a path (APFS is case-insensitive).
#[must_use]
pub fn lower(p: &Path) -> String {
    p.to_string_lossy().to_lowercase()
}

/// True when `path` is inside `dir`, or (for removals) `dir` is inside
/// `path`. Case-insensitive.
fn touches(path: &Path, dir: &Path, removal: bool) -> bool {
    let p = lower(path);
    let d = lower(dir);
    let inside = |a: &str, b: &str| a == b || a.starts_with(&format!("{b}/"));
    inside(&p, &d) || (removal && inside(&d, &p))
}

/// The tollgate dir (state, data, config) that a write of `path` touches.
#[must_use]
pub fn tollgate_dir<'a>(ctx: &'a Context, path: &Path, removal: bool) -> Option<&'a PathBuf> {
    ctx.protected.iter().find(|d| touches(path, d, removal))
}

/// G7: `.git/refs`, `.git/packed-refs`, `.git/config` or `.git/hooks`
/// (also inside them, and with `.git` of any case) when `path` is or is
/// under one of them, or a worktree's `config.worktree` under `.git`
/// (item 21); the name.
#[must_use]
pub fn git_internal(path: &Path) -> Option<&'static str> {
    let comps: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
        .collect();
    let in_git = comps.iter().position(|c| c == ".git");
    if in_git.is_some_and(|k| comps[k + 1..].iter().any(|c| c == "config.worktree")) {
        return Some(".git/config.worktree");
    }
    comps.windows(2).find_map(|w| {
        if w[0] != ".git" {
            return None;
        }
        match w[1].as_str() {
            "refs" => Some(".git/refs"),
            "packed-refs" => Some(".git/packed-refs"),
            "config" => Some(".git/config"),
            "hooks" => Some(".git/hooks"),
            _ => None,
        }
    })
}

/// Item 21: git's global config files (`~/.gitconfig`,
/// `$XDG_CONFIG_HOME/git/config`), which every git command reads and
/// whose program keys it runs, when a write of `path` replaces one: the
/// file itself, or a dir above it inside the home dir (`mv x
/// ~/.config/git`). The file's name.
#[must_use]
pub fn git_global_config(ctx: &Context, path: &Path) -> Option<PathBuf> {
    let xdg = ctx
        .var("XDG_CONFIG_HOME")
        .filter(|v| v.starts_with('/'))
        .map_or_else(|| ctx.home.join(".config"), PathBuf::from);
    let home = lower(&canon(&ctx.home));
    let p = lower(path);
    [ctx.home.join(".gitconfig"), xdg.join("git/config")]
        .into_iter()
        .find(|f| {
            let f = lower(&canon(f));
            p == f || (f.starts_with(&format!("{p}/")) && p.starts_with(&format!("{home}/")))
        })
}

/// G7 for a removal: `rm -rf .git` (or a dir above it) removes the refs
/// with it.
#[must_use]
pub fn holds_git_internals(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|n| n.eq_ignore_ascii_case(".git"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexical_and_canonical_paths() {
        assert_eq!(
            lexical(Path::new("/w/r"), Path::new("../x/./y")),
            PathBuf::from("/w/x/y")
        );
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, tmp.path().join("link")).unwrap();
        let c = canon(&tmp.path().join("link/new/file"));
        assert_eq!(c, std::fs::canonicalize(&real).unwrap().join("new/file"));
        // `..` after a symlink applies to the link's target.
        let c = canon(&tmp.path().join("link/../real/z"));
        assert_eq!(c, std::fs::canonicalize(&real).unwrap().join("z"));
    }

    #[test]
    fn git_internals_g7() {
        for p in [
            "/r/.git/refs/heads/main",
            "/r/.git/packed-refs",
            "/r/.git/config",
            "/r/.git/hooks/pre-commit",
            "/r/.GIT/refs/remotes/origin/main",
            "/r/.git/refs",
            "/r/.git/config.worktree",
            "/r/.git/worktrees/w/config.worktree",
        ] {
            assert!(git_internal(Path::new(p)).is_some(), "{p}");
        }
        for p in [
            "/r/.git/index.lock",
            "/r/.gitignore",
            "/r/refs/x",
            "/r/.git",
        ] {
            assert!(git_internal(Path::new(p)).is_none(), "{p}");
        }
    }
}
