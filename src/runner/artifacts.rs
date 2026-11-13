//! Step artefacts (R106): after a step ends, the files that match its
//! `artifacts` paths or globs are copied out of the checkout into the job
//! dir, keeping their repo-relative paths. Symlinks are neither followed
//! nor copied, and copying stops at a byte limit per step.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::config::glob::{self, GlobOpts};

/// What [`copy`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Copied {
    /// Files copied.
    pub files: usize,
    /// Bytes copied.
    pub bytes: u64,
    /// Matching files left out because the limit was reached.
    pub over_limit: usize,
    /// Symlinks left out.
    pub links: usize,
}

fn has_glob(p: &str) -> bool {
    p.contains(['*', '?', '[', '{'])
}

/// The leading components of `pattern` that hold no glob character: the
/// dir to walk.
fn literal_prefix(pattern: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for c in Path::new(pattern).components() {
        match c {
            Component::Normal(n) if !has_glob(&n.to_string_lossy()) => out.push(n),
            Component::CurDir => {}
            _ => break,
        }
    }
    out
}

/// Every regular file under `rel` (a file or a dir, relative to `root`),
/// without following symlinks. Symlinks are counted in `links`.
fn walk(root: &Path, rel: &Path, out: &mut BTreeSet<PathBuf>, links: &mut usize) {
    let Ok(meta) = fs::symlink_metadata(root.join(rel)) else {
        return;
    };
    let kind = meta.file_type();
    if kind.is_symlink() {
        *links += 1;
    } else if kind.is_file() {
        out.insert(rel.to_owned());
    } else if kind.is_dir() {
        let Ok(rd) = fs::read_dir(root.join(rel)) else {
            return;
        };
        let mut names: Vec<_> = rd.flatten().map(|e| e.file_name()).collect();
        names.sort();
        for n in names {
            walk(root, &rel.join(n), out, links);
        }
    }
}

/// The files under `workdir` that `patterns` name: a plain path names a
/// file or every file under a dir; a glob names the files it matches and
/// every file under a dir it matches.
fn matching(workdir: &Path, patterns: &[String], links: &mut usize) -> BTreeSet<PathBuf> {
    let mut found = BTreeSet::new();
    for p in patterns {
        if !has_glob(p) {
            walk(workdir, Path::new(p), &mut found, links);
            continue;
        }
        let Ok(set) = glob::compile(
            &[p],
            GlobOpts {
                case_insensitive: false,
                literal_separator: true,
            },
        ) else {
            continue;
        };
        let mut under = BTreeSet::new();
        let mut walked_links = 0;
        walk(workdir, &literal_prefix(p), &mut under, &mut walked_links);
        *links += walked_links;
        for f in under {
            if f.ancestors()
                .any(|a| !a.as_os_str().is_empty() && set.is_match(a))
            {
                found.insert(f);
            }
        }
    }
    found
}

/// Copies the regular file `src` to `to`; `O_NOFOLLOW` refuses a
/// symlink put in its place after the walk.
fn copy_no_follow(src: &Path, to: &Path) -> io::Result<u64> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut from = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(src)?;
    let mut out = fs::File::create(to)?;
    io::copy(&mut from, &mut out)
}

/// Copies what `patterns` name from `workdir` into `dest`, at most
/// `limit` bytes. Files go in path order; the first file that would pass
/// the limit stops the copy.
pub fn copy(workdir: &Path, patterns: &[String], dest: &Path, limit: u64) -> io::Result<Copied> {
    let mut c = Copied::default();
    let files = matching(workdir, patterns, &mut c.links);
    let mut it = files.iter();
    for rel in it.by_ref() {
        let src = workdir.join(rel);
        // Checked again: the walk and the copy are apart in time.
        let Ok(meta) = fs::symlink_metadata(&src) else {
            continue;
        };
        if !meta.file_type().is_file() {
            continue;
        }
        if c.bytes + meta.len() > limit {
            c.over_limit += 1;
            break;
        }
        let to = dest.join(rel);
        if let Some(d) = to.parent() {
            fs::create_dir_all(d)?;
        }
        c.bytes += copy_no_follow(&src, &to)?;
        c.files += 1;
    }
    c.over_limit += it.count();
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_prefix_stops_at_the_first_glob_r106() {
        assert_eq!(
            literal_prefix("web/test-results"),
            Path::new("web/test-results")
        );
        assert_eq!(literal_prefix("shots/*.png"), Path::new("shots"));
        assert_eq!(literal_prefix("**/*.png"), Path::new(""));
    }
}
