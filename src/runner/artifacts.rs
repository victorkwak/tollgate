//! Step artefacts (R106): after a step ends, the files that match its
//! `artifacts` paths or globs are copied out of the checkout into the job
//! dir, keeping their repo-relative paths. Symlinks are neither followed
//! nor copied, and copying stops at a byte limit per step.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::config::glob::{self, GlobOpts};

/// R106: most entries one step's artefact walk visits. Like the 20k
/// entries of the R71 probe's one walk: a glob with a short literal prefix
/// (`**/*.png`) would otherwise read all of `target/` and `node_modules`
/// on every run of the step.
pub const MAX_VISITS: usize = 20_000;

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
    /// Patterns refused, with why: a component of their path under the
    /// checkout is a symlink.
    pub refused: Vec<String>,
    /// The walk stopped at the entry bound ([`MAX_VISITS`]).
    pub walk_stopped: bool,
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

/// The first component of `rel` under `root`, from the root down, that is
/// a symlink. A path through one can leave the checkout (`web -> ..`).
fn symlink_in(root: &Path, rel: &Path) -> Option<PathBuf> {
    let mut at = PathBuf::new();
    for c in rel.components() {
        if let Component::Normal(n) = c {
            at.push(n);
            if fs::symlink_metadata(root.join(&at)).is_ok_and(|m| m.file_type().is_symlink()) {
                return Some(at);
            }
        }
    }
    None
}

/// One walk under the checkout: what matched and how much it visited.
struct Walk<'a> {
    root: &'a Path,
    /// `None`: every file counts (a plain path).
    glob: Option<&'a globset::GlobSet>,
    found: &'a mut BTreeSet<PathBuf>,
    links: &'a mut usize,
    visits: &'a mut usize,
    max: usize,
    stopped: bool,
}

impl Walk<'_> {
    /// The regular files under `rel` that match, filtered while walking,
    /// never descending into a symlink. `inside` is true under a dir that
    /// matched already.
    fn walk(&mut self, rel: &Path, inside: bool) {
        if self.stopped {
            return;
        }
        if *self.visits >= self.max {
            self.stopped = true;
            return;
        }
        *self.visits += 1;
        let Ok(meta) = fs::symlink_metadata(self.root.join(rel)) else {
            return;
        };
        let matched = inside
            || self
                .glob
                .is_none_or(|g| !rel.as_os_str().is_empty() && g.is_match(rel));
        let kind = meta.file_type();
        if kind.is_symlink() {
            *self.links += 1;
        } else if kind.is_file() {
            if matched {
                self.found.insert(rel.to_owned());
            }
        } else if kind.is_dir() {
            let Ok(rd) = fs::read_dir(self.root.join(rel)) else {
                return;
            };
            let mut names: Vec<_> = rd.flatten().map(|e| e.file_name()).collect();
            names.sort();
            for n in names {
                self.walk(&rel.join(n), matched);
            }
        }
    }
}

/// The files under `workdir` that `patterns` name: a plain path names a
/// file or every file under a dir; a glob names the files it matches and
/// every file under a dir it matches. At most `max` entries are visited
/// over all patterns.
fn matching(workdir: &Path, patterns: &[String], max: usize, c: &mut Copied) -> BTreeSet<PathBuf> {
    let mut found = BTreeSet::new();
    let mut visits = 0;
    for p in patterns {
        let glob = if has_glob(p) {
            match glob::compile(
                &[p],
                GlobOpts {
                    case_insensitive: false,
                    literal_separator: true,
                },
            ) {
                Ok(g) => Some(g),
                Err(_) => continue,
            }
        } else {
            None
        };
        let start = if glob.is_some() {
            literal_prefix(p)
        } else {
            PathBuf::from(p)
        };
        if let Some(link) = symlink_in(workdir, &start) {
            c.refused
                .push(format!("{p:?} goes through the symlink {}", link.display()));
            continue;
        }
        let mut w = Walk {
            root: workdir,
            glob: glob.as_ref(),
            found: &mut found,
            links: &mut c.links,
            visits: &mut visits,
            max,
            stopped: false,
        };
        w.walk(&start, false);
        if w.stopped {
            c.walk_stopped = true;
            break;
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
/// `limit` bytes and [`MAX_VISITS`] walked entries. Files go in path
/// order; the first file that would pass the limit stops the copy.
pub fn copy(workdir: &Path, patterns: &[String], dest: &Path, limit: u64) -> io::Result<Copied> {
    copy_bounded(workdir, patterns, dest, limit, MAX_VISITS)
}

/// [`copy`] with the walk bound as a parameter (tests use a small one).
pub fn copy_bounded(
    workdir: &Path,
    patterns: &[String],
    dest: &Path,
    limit: u64,
    max_visits: usize,
) -> io::Result<Copied> {
    let mut c = Copied::default();
    let files = matching(workdir, patterns, max_visits, &mut c);
    let mut it = files.iter();
    for rel in it.by_ref() {
        let src = workdir.join(rel);
        // Checked again: the walk and the copy are apart in time, and a
        // dir may have become a symlink.
        if symlink_in(workdir, rel).is_some() {
            c.links += 1;
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&src) else {
            continue;
        };
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

    /// A tree of `n` dirs with one file each, plus `keep/x.png`.
    fn tree(n: usize) -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        for i in 0..n {
            let d = t.path().join(format!("d{i:03}"));
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("f.txt"), "x").unwrap();
        }
        fs::create_dir_all(t.path().join("keep")).unwrap();
        fs::write(t.path().join("keep/x.png"), "p").unwrap();
        t
    }

    #[test]
    fn the_walk_filters_as_it_goes_and_stops_at_its_bound_r106() {
        let t = tree(50);
        let dest = tempfile::tempdir().unwrap();
        let pats = vec!["**/*.png".to_owned()];
        let c = copy_bounded(t.path(), &pats, dest.path(), 1 << 20, 1000).unwrap();
        assert_eq!((c.files, c.walk_stopped), (1, false), "{c:?}");
        assert!(dest.path().join("keep/x.png").is_file());
        // Root, 50 dirs and their files: past 30 entries, before `keep`.
        let dest = tempfile::tempdir().unwrap();
        let c = copy_bounded(t.path(), &pats, dest.path(), 1 << 20, 30).unwrap();
        assert_eq!((c.files, c.walk_stopped), (0, true), "{c:?}");
    }

    #[test]
    fn a_path_through_a_symlinked_dir_is_refused_r106() {
        let t = tree(1);
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir_all(outside.path().join("res")).unwrap();
        fs::write(outside.path().join("res/secret.txt"), "s").unwrap();
        std::os::unix::fs::symlink(outside.path(), t.path().join("web")).unwrap();
        let dest = tempfile::tempdir().unwrap();
        let pats = vec!["web/res".to_owned(), "web/*/*.txt".to_owned()];
        let c = copy(t.path(), &pats, dest.path(), 1 << 20).unwrap();
        assert_eq!(c.files, 0, "{c:?}");
        assert_eq!(c.refused.len(), 2, "{c:?}");
        assert!(c.refused[0].contains("symlink web"), "{c:?}");
    }
}
