//! R71 tool-config probe (items 24-27, 35).
//!
//! cargo, clippy and rustfmt find their config by fixed names
//! ([`TOOL_CONFIG_NAMES`], [`CARGO_DIR`]/[`CARGO_CONFIG_NAMES`]) in the
//! ancestors of their cwd and of the source files, and in a few host
//! places (`$CARGO_HOME`, rustfmt's home and config dirs). So instead of
//! walking every untracked or ignored dir (which needs an entry budget and
//! still misses links, unreadable dirs and the dirs above the checkout),
//! the probe looks up each of those names, with `symlink_metadata` and no
//! listing, in:
//!
//! - every dir of the checked tree (from `ls-tree`) and every dir the
//!   overlay writes into: a tool-config name the tree and the overlay do
//!   not account for is a finding, and so is a tree dir that is no longer
//!   a real dir (a symlink, a file, gone) or one whose names cannot be
//!   looked up (no search permission);
//! - every step cwd, lexically and physically: a cwd that resolves through
//!   a symlink to anything but a tree dir is a finding;
//! - every tree or overlay symlink: a dangling one, a symlinked tool
//!   config, a dir link into the checkout whose target is not a dir of the
//!   checked tree, a `.cargo` link out of the checkout or to a dir that
//!   holds cargo config, and a dir link out of the checkout whose target
//!   has a tool config under it or above it are findings. Link targets out
//!   of the checkout (a vendored package, a local wheel index) are the one
//!   walk left, bounded per run;
//! - every ancestor of the checkout root up to `/`: any tool config there
//!   is a finding (a step can write `../.cargo/config.toml`, and it would
//!   apply to every later job), except the host's own config;
//! - the host's own config (`$CARGO_HOME/config.toml`, rustfmt's home and
//!   config dir files, bun's global bunfig and uv's user config, review
//!   note 20): one whose content the host config does not
//!   approve (`[job.host_tool_configs]`), or that is not a plain file, is
//!   a finding from the start (the session can write it, item 35, review
//!   note 12), and so is a change since the job started.
//!
//! A job runs the probe after the overlay (before setup) and after every
//! setup step and step. Each run is a few stats per dir of the tree.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use crate::gitx::TreeEntry;
use crate::policy::{
    CARGO_CONFIG_NAMES, CARGO_DIR, OverlayFile, TOOL_CONFIG_NAMES, is_tool_config,
};
use crate::runner::env::{JobEnv, host_tool_configs};

/// What a host config path was when the job started.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Stamp {
    /// Not there (or a parent is not a dir).
    Absent,
    /// `lstat` and, through a link, `stat`.
    Present(Meta, Option<Meta>),
    /// Any other lookup error.
    Error(io::ErrorKind),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Meta {
    dev: u64,
    ino: u64,
    mode: u32,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl Meta {
    fn of(m: &std::fs::Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            mode: m.mode(),
            size: m.size(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        }
    }
}

fn stamp(path: &Path) -> Stamp {
    match path.symlink_metadata() {
        Ok(m) => {
            let through = m
                .file_type()
                .is_symlink()
                .then(|| path.metadata().ok().map(|t| Meta::of(&t)))
                .flatten();
            Stamp::Present(Meta::of(&m), through)
        }
        Err(e) if absent(&e) => Stamp::Absent,
        Err(e) => Stamp::Error(e.kind()),
    }
}

/// Why `path` counts as a tool config found there: present, or not
/// checkable (fail closed). `None`: absent.
fn present(path: &Path) -> Option<String> {
    match path.symlink_metadata() {
        Err(e) if absent(&e) => None,
        Ok(_) => Some("a tool config".to_owned()),
        Err(e) => Some(format!("cannot check for a tool config ({e})")),
    }
}

/// Not found, or a parent that is not a dir: no tool reads a file there.
fn absent(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

/// `rel` with `.` dropped; `None` when it has any other non-normal part.
fn normal(rel: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for c in rel.components() {
        match c {
            Component::Normal(n) => out.push(n),
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(out)
}

/// The R71 probe of one job's checkout.
#[derive(Debug, Clone)]
pub struct ToolProbe {
    /// Canonical checkout root.
    root: PathBuf,
    /// Dirs (relative) that must be real dirs: the tree's and the ones
    /// the overlay writes into. `""` is the root.
    dirs: BTreeSet<PathBuf>,
    /// Paths the tree (files, links, submodules) or the overlay account
    /// for; other checks own them (R42 tracked changes, overlay changes).
    known: BTreeSet<PathBuf>,
    /// Dirs (relative) whose tool-config names are looked up: `dirs` and
    /// each step cwd with its parents.
    probe_dirs: BTreeSet<PathBuf>,
    /// Step and setup cwds (relative, normal).
    cwds: BTreeSet<PathBuf>,
    /// Tree and overlay symlinks (relative).
    links: BTreeSet<PathBuf>,
    /// Paths above the checkout that must not exist.
    above: Vec<PathBuf>,
    /// Host config paths with what they were at job start and why a job
    /// may not read them (not approved).
    host: Vec<(PathBuf, Stamp, Option<String>)>,
    /// The same paths, as spelled and with canonical dirs.
    host_paths: BTreeSet<PathBuf>,
}

/// Entries [`ToolProbe::findings`] reads under link targets outside the
/// checkout in one run before it gives up (a finding).
const OUTSIDE_WALK_BUDGET: usize = 20_000;

/// One run's walk of link targets outside the checkout.
struct Walk {
    budget: usize,
    seen: BTreeSet<PathBuf>,
}

/// The tool-config paths in each ancestor of `dir` (not `dir` itself),
/// except the host's own config (`~/.cargo` as `CARGO_HOME`,
/// `~/.rustfmt.toml`), which must be approved instead. `dir` is canonical,
/// so its ancestors are; a path is exempt only when it is a host config
/// path as spelled or with its dir resolved, never because a `.cargo`
/// there links to the host's dir (review note 12).
fn ancestor_configs(dir: &Path, host_paths: &BTreeSet<PathBuf>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for a in dir.ancestors().skip(1) {
        let names = TOOL_CONFIG_NAMES
            .iter()
            .map(|n| a.join(n))
            .chain(CARGO_CONFIG_NAMES.iter().map(|n| a.join(CARGO_DIR).join(n)));
        out.extend(names.filter(|p| !host_paths.contains(p)));
    }
    out
}

/// `path` with its dir resolved through symlinks (when it resolves).
fn canon_dir(path: &Path) -> PathBuf {
    match (path.parent(), path.file_name()) {
        (Some(d), Some(n)) => {
            std::fs::canonicalize(d).map_or_else(|_| path.to_owned(), |d| d.join(n))
        }
        _ => path.to_owned(),
    }
}

/// Largest host tool config the probe reads.
const HOST_CONFIG_MAX: u64 = 1 << 20;

/// Why the host tool config at `path` (stamped `st` just before) may not
/// be read by a job, or `None` when it is absent or its content is the
/// approved one (`approved`: canonical-dir path -> blake3 hex).
fn unapproved(path: &Path, st: &Stamp, approved: &BTreeMap<PathBuf, String>) -> Option<String> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    match st {
        Stamp::Absent => return None,
        Stamp::Error(k) => return Some(format!("cannot be checked ({k})")),
        Stamp::Present(..) => {}
    }
    // Never block on a FIFO or a device: open without waiting, then
    // read only a regular file.
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if absent(&e) => {
            return Some("is a dangling link (a step could create its target)".to_owned());
        }
        Err(e) => return Some(format!("cannot be read ({e})")),
    };
    match file.metadata() {
        Ok(m) if m.is_file() && m.len() <= HOST_CONFIG_MAX => {}
        Ok(m) if m.is_file() => return Some(format!("is too large to check ({} bytes)", m.len())),
        Ok(_) => return Some("is not a regular file".to_owned()),
        Err(e) => return Some(format!("cannot be read ({e})")),
    }
    let mut bytes = Vec::new();
    if let Err(e) = file.take(HOST_CONFIG_MAX + 1).read_to_end(&mut bytes) {
        return Some(format!("cannot be read ({e})"));
    }
    let hash = blake3::hash(&bytes).to_hex().to_string();
    if approved.get(&canon_dir(path)) == Some(&hash) {
        return None;
    }
    Some(format!(
        "is not approved (blake3 {hash}); review it, then approve that content in the host config `[job.host_tool_configs]`"
    ))
}

/// One host tool config: its path, what it was when the job started, and
/// why a job may not read it (`None`: absent or approved).
type HostEntry = (PathBuf, Stamp, Option<String>);

/// The host tool configs of a job with environment `env`, stamped and
/// checked against `approved` (`~` is the job's `HOME`), and the set of
/// their paths as spelled and with canonical dirs.
fn host_entries(
    env: &JobEnv,
    approved: &BTreeMap<String, String>,
) -> (Vec<HostEntry>, BTreeSet<PathBuf>) {
    let get = |k: &str| env.get(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    let home = get("HOME");
    let cargo_home = get("CARGO_HOME").or_else(|| home.as_ref().map(|h| h.join(".cargo")));
    let config_home = get("XDG_CONFIG_HOME").or_else(|| home.as_ref().map(|h| h.join(".config")));
    let host_list: Vec<PathBuf> = match (&home, &cargo_home, &config_home) {
        (Some(h), Some(c), Some(x)) => host_tool_configs(h, c, x),
        _ => cargo_home
            .iter()
            .flat_map(|c| CARGO_CONFIG_NAMES.iter().map(move |n| c.join(n)))
            .collect(),
    };
    let approved: BTreeMap<PathBuf, String> = approved
        .iter()
        .filter_map(|(k, v)| {
            let p = match k.strip_prefix("~/") {
                Some(rest) => home.as_ref()?.join(rest),
                None => PathBuf::from(k),
            };
            Some((canon_dir(&p), v.clone()))
        })
        .collect();
    let mut host_paths: BTreeSet<PathBuf> = BTreeSet::new();
    let mut host = Vec::new();
    for p in host_list {
        if !host_paths.insert(p.clone()) {
            continue;
        }
        host_paths.insert(canon_dir(&p));
        let st = stamp(&p);
        let why = unapproved(&p, &st, &approved);
        host.push((p, st, why));
    }
    (host, host_paths)
}

/// Each host tool config a job with environment `env` would find, with
/// why it may not read it (`None`: approved); absent ones are left out
/// (`tollgate doctor`, item 35).
#[must_use]
pub fn host_tool_config_report(
    env: &JobEnv,
    approved: &BTreeMap<String, String>,
) -> Vec<(PathBuf, Option<String>)> {
    host_entries(env, approved)
        .0
        .into_iter()
        .filter(|(_, st, _)| *st != Stamp::Absent)
        .map(|(p, _, why)| (p, why))
        .collect()
}

impl ToolProbe {
    /// The probe for a checkout at canonical `root` holding `tree` with
    /// `overlay` applied, for steps run in `cwds` with job environment
    /// `env`. Takes the host config's stamps now and checks each present
    /// one against `approved` (host `[job.host_tool_configs]`: path, `~`
    /// for the job's `HOME`, -> blake3 hex); call it before setup.
    #[must_use]
    pub fn new<'c>(
        root: &Path,
        tree: &[TreeEntry],
        overlay: &BTreeMap<PathBuf, OverlayFile>,
        cwds: impl IntoIterator<Item = &'c str>,
        env: &JobEnv,
        approved: &BTreeMap<String, String>,
    ) -> Self {
        let mut dirs = BTreeSet::from([PathBuf::new()]);
        let mut known = BTreeSet::new();
        let mut links = BTreeSet::new();
        let add_parents = |p: &Path, dirs: &mut BTreeSet<PathBuf>| {
            for a in p.ancestors().skip(1) {
                if !dirs.insert(a.to_owned()) {
                    break;
                }
            }
        };
        for e in tree {
            known.insert(e.path.clone());
            add_parents(&e.path, &mut dirs);
            if e.mode == "120000" {
                links.insert(e.path.clone());
            }
        }
        for (p, f) in overlay {
            known.insert(p.clone());
            match f {
                OverlayFile::Absent => {}
                OverlayFile::File { .. } => add_parents(p, &mut dirs),
                OverlayFile::Symlink { .. } => {
                    add_parents(p, &mut dirs);
                    links.insert(p.clone());
                }
            }
        }
        // A path that is both a tree dir and accounted for (a `.cargo`
        // file in the tree whose overlay is a dir's file) is decided by
        // the other checks.
        let mut probe_dirs = dirs.clone();
        let mut cwd_set = BTreeSet::new();
        for c in cwds {
            // Config validation refuses other forms (R64); a cwd that
            // still has one is probed as the root.
            let rel = normal(Path::new(c)).unwrap_or_default();
            for a in rel.ancestors() {
                probe_dirs.insert(a.to_owned());
            }
            cwd_set.insert(rel);
        }
        cwd_set.insert(PathBuf::new());

        let (host, host_paths) = host_entries(env, approved);
        let above = ancestor_configs(root, &host_paths);
        Self {
            root: root.to_owned(),
            dirs,
            known,
            probe_dirs,
            cwds: cwd_set,
            links,
            above,
            host,
            host_paths,
        }
    }

    /// Number of dirs whose names each run looks up.
    #[must_use]
    pub fn dir_count(&self) -> usize {
        self.probe_dirs.len()
    }

    /// Everything the probe finds now, one line each (empty: nothing).
    #[must_use]
    pub fn findings(&self) -> Vec<String> {
        let mut out = Vec::new();
        for d in &self.probe_dirs {
            self.probe_dir(d, &mut out);
        }
        for c in &self.cwds {
            self.probe_cwd(c, &mut out);
        }
        let mut walk = Walk {
            budget: OUTSIDE_WALK_BUDGET,
            seen: BTreeSet::new(),
        };
        for l in &self.links {
            self.probe_link(l, &mut walk, &mut out);
        }
        for p in &self.above {
            if let Some(why) = present(p) {
                out.push(format!("{}: {why} above the checkout", p.display()));
            }
        }
        for (p, was, why) in &self.host {
            if let Some(why) = why {
                out.push(format!("{}: host tool config {why}", p.display()));
            } else if stamp(p) != *was {
                out.push(format!(
                    "{}: host tool config changed during the job",
                    p.display()
                ));
            }
        }
        out
    }

    fn rel_display(rel: &Path) -> String {
        if rel.as_os_str().is_empty() {
            ".".to_owned()
        } else {
            rel.to_string_lossy().into_owned()
        }
    }

    /// One dir inside the checkout.
    fn probe_dir(&self, rel: &Path, out: &mut Vec<String>) {
        let abs = self.root.join(rel);
        // A cwd dir (not of the tree) reached through a symlink: the cwd
        // check decides (a tree dir is probed as itself; anything else is
        // a finding there).
        if !self.dirs.contains(rel) && std::fs::canonicalize(&abs).is_ok_and(|c| c != abs) {
            return;
        }
        if self.dirs.contains(rel) && !rel.as_os_str().is_empty() {
            match abs.symlink_metadata() {
                Ok(m) if m.is_dir() => {}
                Ok(m) if m.file_type().is_symlink() => {
                    out.push(format!(
                        "{}: a dir of the tree is a symlink now",
                        Self::rel_display(rel)
                    ));
                    return;
                }
                Ok(_) => {
                    out.push(format!(
                        "{}: a dir of the tree is not a dir now",
                        Self::rel_display(rel)
                    ));
                    return;
                }
                Err(e) => {
                    out.push(format!(
                        "{}: a dir of the tree cannot be checked: {e}",
                        Self::rel_display(rel)
                    ));
                    return;
                }
            }
        }
        for n in TOOL_CONFIG_NAMES.iter().chain([&CARGO_DIR]) {
            let p = rel.join(n);
            if self.known.contains(&p) {
                continue;
            }
            if self.dirs.contains(&p) {
                // A `.cargo` dir of the tree (or the overlay's): its config
                // files are known or must be absent.
                match self.root.join(&p).symlink_metadata() {
                    Ok(m) if m.is_dir() => {}
                    Ok(_) => {
                        out.push(format!(
                            "{}: a dir of the tree is not a dir now",
                            p.display()
                        ));
                        continue;
                    }
                    Err(e) => {
                        out.push(format!(
                            "{}: a dir of the tree cannot be checked: {e}",
                            p.display()
                        ));
                        continue;
                    }
                }
                for c in CARGO_CONFIG_NAMES {
                    let q = p.join(c);
                    if !self.known.contains(&q) {
                        self.expect_absent(&q, out);
                    }
                }
            } else {
                self.expect_absent(&p, out);
            }
        }
    }

    fn expect_absent(&self, rel: &Path, out: &mut Vec<String>) {
        match self.root.join(rel).symlink_metadata() {
            Err(e) if absent(&e) => {}
            // Name the cargo config a `.cargo` holds, when it holds one
            // (the `.cargo` itself counts either way).
            Ok(_)
                if rel.file_name() == Some(OsStr::new(CARGO_DIR))
                    && CARGO_CONFIG_NAMES
                        .iter()
                        .any(|c| self.root.join(rel).join(c).symlink_metadata().is_ok()) =>
            {
                for c in CARGO_CONFIG_NAMES {
                    if self.root.join(rel).join(c).symlink_metadata().is_ok() {
                        out.push(format!(
                            "{}: a tool config that is not in the tree",
                            rel.join(c).display()
                        ));
                    }
                }
            }
            Ok(_) => out.push(format!(
                "{}: a tool config that is not in the tree",
                rel.display()
            )),
            Err(e) => out.push(format!(
                "{}: cannot check for a tool config: {e}",
                rel.display()
            )),
        }
    }

    /// A step cwd must resolve to itself or to a dir of the tree (tools
    /// look up config from the physical cwd).
    fn probe_cwd(&self, rel: &Path, out: &mut Vec<String>) {
        let lexical = self.root.join(rel);
        match std::fs::canonicalize(&lexical) {
            Ok(c) if c == lexical => {}
            Ok(c) => {
                let in_tree = c
                    .strip_prefix(&self.root)
                    .is_ok_and(|r| self.dirs.contains(r));
                if !in_tree {
                    out.push(format!(
                        "{}: a step cwd that resolves to {}, which is not a dir of the tree",
                        Self::rel_display(rel),
                        c.display()
                    ));
                }
            }
            // A cwd that does not exist runs no tool.
            Err(e) if absent(&e) => {}
            Err(e) => out.push(format!(
                "{}: a step cwd that cannot be checked: {e}",
                Self::rel_display(rel)
            )),
        }
    }

    /// A tree or overlay symlink.
    fn probe_link(&self, rel: &Path, walk: &mut Walk, out: &mut Vec<String>) {
        let p = self.root.join(rel);
        if !p
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            // Removed by the overlay, or replaced: the tracked-change and
            // overlay checks decide.
            return;
        }
        let cargo_dir = rel.file_name() == Some(OsStr::new(CARGO_DIR));
        if is_tool_config(rel) && !cargo_dir {
            out.push(format!("{} is a symlink", rel.display()));
            return;
        }
        let target = match std::fs::canonicalize(&p) {
            Ok(t) => t,
            Err(e) => {
                out.push(format!(
                    "{} is a symlink that does not resolve: {e}",
                    rel.display()
                ));
                return;
            }
        };
        if !target.is_dir() {
            return;
        }
        match target.strip_prefix(&self.root) {
            Ok(r) if self.dirs.contains(r) => {}
            // A kept dir (`target/`), an untracked or ignored dir: a step
            // can write there, and the probe does not walk it.
            Ok(_) => {
                out.push(format!(
                    "{} links to {}, which is not a dir of the tree",
                    rel.display(),
                    target.display()
                ));
                return;
            }
            // Outside the checkout (a vendored package, a local wheel
            // index): no tool config under it, nor in its ancestors.
            Err(_) => {
                if cargo_dir {
                    out.push(format!(
                        "{} links to {}, outside the checkout",
                        rel.display(),
                        target.display()
                    ));
                } else if let Some(found) = self.outside_config(&target, walk) {
                    out.push(format!(
                        "{} links to {}, which is not tree content and holds {found}",
                        rel.display(),
                        target.display()
                    ));
                }
                return;
            }
        }
        if cargo_dir
            && CARGO_CONFIG_NAMES
                .iter()
                .any(|c| target.join(c).symlink_metadata().is_ok())
        {
            out.push(format!(
                "{} links to a dir that holds cargo config",
                rel.display()
            ));
        }
    }
}

impl ToolProbe {
    /// The first tool config under or above `dir` (outside the checkout),
    /// following nested dir links; an unreadable dir or a walk over the
    /// budget counts too (fail closed).
    fn outside_config(&self, dir: &Path, walk: &mut Walk) -> Option<String> {
        if !walk.seen.insert(dir.to_owned()) {
            return None;
        }
        for p in ancestor_configs(dir, &self.host_paths) {
            if let Some(why) = present(&p) {
                return Some(format!("{why}: {}", p.display()));
            }
        }
        let mut stack = vec![dir.to_owned()];
        while let Some(d) = stack.pop() {
            let rd = match std::fs::read_dir(&d) {
                Ok(rd) => rd,
                Err(e) => return Some(format!("a dir it cannot read: {} ({e})", d.display())),
            };
            for e in rd {
                let e = match e {
                    Ok(e) => e,
                    Err(e) => return Some(format!("a dir it cannot read: {} ({e})", d.display())),
                };
                if walk.budget == 0 {
                    return Some(format!("too many files to check: {}", d.display()));
                }
                walk.budget -= 1;
                let p = e.path();
                let name = e.file_name();
                if is_tool_config(Path::new(&name)) {
                    return Some(format!("a tool config: {}", p.display()));
                }
                let md = match p.symlink_metadata() {
                    Ok(m) => m,
                    Err(e) => {
                        return Some(format!("a file it cannot check: {} ({e})", p.display()));
                    }
                };
                if md.is_dir() {
                    stack.push(p);
                } else if md.file_type().is_symlink() {
                    match std::fs::canonicalize(&p) {
                        Ok(t) if t.is_dir() => {
                            if t.starts_with(&self.root) {
                                return Some(format!(
                                    "a link back into the checkout: {}",
                                    p.display()
                                ));
                            }
                            if let Some(f) = self.outside_config(&t, walk) {
                                return Some(f);
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            return Some(format!(
                                "a link that does not resolve: {} ({e})",
                                p.display()
                            ));
                        }
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The probed names are exactly the tool configs of R71.
    #[test]
    fn probed_names_are_the_tool_configs() {
        for n in TOOL_CONFIG_NAMES {
            assert!(is_tool_config(Path::new(n)), "{n}");
            assert!(is_tool_config(&Path::new("a/b").join(n)), "{n}");
        }
        assert!(is_tool_config(Path::new(CARGO_DIR)));
        for n in CARGO_CONFIG_NAMES {
            assert!(is_tool_config(&Path::new(CARGO_DIR).join(n)), "{n}");
        }
        for not in [
            "Cargo.toml",
            "a/config.toml",
            "clippy.toml.bak",
            "x/.cargo/credentials.toml",
        ] {
            assert!(!is_tool_config(Path::new(not)), "{not}");
        }
    }

    fn entry(path: &str) -> TreeEntry {
        TreeEntry {
            mode: "100644".into(),
            kind: "blob".into(),
            oid: crate::gitx::Oid::parse(&"a".repeat(40)).unwrap(),
            path: path.into(),
        }
    }

    fn approve(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(p, c)| {
                (
                    (*p).to_owned(),
                    blake3::hash(c.as_bytes()).to_hex().to_string(),
                )
            })
            .collect()
    }

    /// The host's own config (`$CARGO_HOME/config.toml`, `~/.rustfmt.toml`)
    /// may sit above the checkout when the host config approves its
    /// content; a change during the job counts. Any other tool config
    /// above the checkout counts as it is.
    #[test]
    fn host_config_counts_when_it_changes_other_config_above_always() {
        let t = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(t.path()).unwrap().join("home");
        let root = home.join("state/verify/r/fast/w");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(home.join(".cargo")).unwrap();
        std::fs::write(home.join(".cargo/config.toml"), "[alias]\n").unwrap();
        std::fs::write(home.join(".rustfmt.toml"), "\n").unwrap();
        let env = JobEnv::from_vars([
            ("HOME", home.as_os_str()),
            ("CARGO_HOME", home.join(".cargo").as_os_str()),
        ]);
        let ok = approve(&[
            ("~/.cargo/config.toml", "[alias]\n"),
            (home.join(".rustfmt.toml").to_str().unwrap(), "\n"),
        ]);
        let probe = ToolProbe::new(
            &root,
            &[entry("src/lib.rs")],
            &BTreeMap::new(),
            [],
            &env,
            &ok,
        );
        assert_eq!(probe.findings(), Vec::<String>::new());
        std::fs::write(home.join(".cargo/config.toml"), "[alias]\nx = \"y\"\n").unwrap();
        std::fs::write(home.join("state/clippy.toml"), "\n").unwrap();
        let found = probe.findings();
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found[0].ends_with("state/clippy.toml: a tool config above the checkout"));
        assert!(found[1].ends_with(".cargo/config.toml: host tool config changed during the job"));
        // `~/clippy.toml` is no host config: clippy has none.
        std::fs::remove_file(home.join("state/clippy.toml")).unwrap();
        std::fs::write(home.join("clippy.toml"), "\n").unwrap();
        std::fs::write(home.join(".cargo/config.toml"), "[alias]\n").unwrap();
        let probe = ToolProbe::new(
            &root,
            &[entry("src/lib.rs")],
            &BTreeMap::new(),
            [],
            &env,
            &ok,
        );
        let found = probe.findings();
        assert!(
            found.len() == 1
                && found[0].ends_with("home/clippy.toml: a tool config above the checkout"),
            "{found:?}"
        );
    }

    /// Review note 12: a host tool config the host config does not approve
    /// (absent from it, other content, another path) fails the job before
    /// its first step, and so does one the probe cannot read as a plain
    /// file: a dangling link, a FIFO (never waited on), a dir.
    #[test]
    fn an_unapproved_host_tool_config_counts() {
        let t = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(t.path()).unwrap().join("home");
        let root = home.join("state/verify/r/fast/w");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(home.join(".cargo")).unwrap();
        std::fs::create_dir_all(home.join(".config/rustfmt")).unwrap();
        let runner = "[target.'cfg(all())']\nrunner = \"true\"\n";
        let config = home.join(".cargo/config.toml");
        std::fs::write(&config, runner).unwrap();
        let env = JobEnv::from_vars([
            ("HOME", home.as_os_str()),
            ("CARGO_HOME", home.join(".cargo").as_os_str()),
        ]);
        let run = |approved: &BTreeMap<String, String>| {
            ToolProbe::new(
                &root,
                &[entry("src/lib.rs")],
                &BTreeMap::new(),
                [],
                &env,
                approved,
            )
            .findings()
        };
        let not_approved = |found: &[String], path: &str| {
            found.len() == 1
                && found[0].ends_with(&format!(
                    "{path}: host tool config is not approved (blake3 {}); review it, then approve that content in the host config `[job.host_tool_configs]`",
                    blake3::hash(runner.as_bytes()).to_hex()
                ))
        };
        let found = run(&BTreeMap::new());
        assert!(not_approved(&found, ".cargo/config.toml"), "{found:?}");
        let found = run(&approve(&[("~/.cargo/config.toml", "[alias]\n")]));
        assert!(not_approved(&found, ".cargo/config.toml"), "{found:?}");
        let found = run(&approve(&[("~/.cargo/config", runner)]));
        assert!(not_approved(&found, ".cargo/config.toml"), "{found:?}");
        assert_eq!(
            run(&approve(&[("~/.cargo/config.toml", runner)])),
            Vec::<String>::new()
        );
        // Through a link: the content counts, wherever it lives.
        std::fs::remove_file(&config).unwrap();
        std::fs::write(home.join("dotfile"), runner).unwrap();
        std::os::unix::fs::symlink(home.join("dotfile"), &config).unwrap();
        assert_eq!(
            run(&approve(&[("~/.cargo/config.toml", runner)])),
            Vec::<String>::new()
        );
        std::fs::remove_file(home.join("dotfile")).unwrap();
        let found = run(&BTreeMap::new());
        assert!(
            found.len() == 1 && found[0].ends_with("config.toml: host tool config is a dangling link (a step could create its target)"),
            "{found:?}"
        );
        std::fs::remove_file(&config).unwrap();
        assert_eq!(run(&BTreeMap::new()), Vec::<String>::new());
        let fifo = home.join(".config/rustfmt/rustfmt.toml");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let found = run(&BTreeMap::new());
        assert!(
            found.len() == 1
                && found[0]
                    .ends_with("rustfmt/rustfmt.toml: host tool config is not a regular file"),
            "{found:?}"
        );
        std::fs::remove_file(&fifo).unwrap();
        std::fs::create_dir(home.join(".rustfmt.toml")).unwrap();
        let found = run(&BTreeMap::new());
        assert!(
            found.len() == 1
                && found[0].ends_with(".rustfmt.toml: host tool config is not a regular file"),
            "{found:?}"
        );
    }

    /// Review note 20: bun's global bunfig and uv's user config count
    /// like cargo's: a present one must be approved, an absent one costs
    /// nothing, and `XDG_CONFIG_HOME` moves the config-dir ones.
    #[test]
    fn unapproved_bun_and_uv_user_configs_count_note20() {
        let t = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(t.path()).unwrap().join("home");
        let root = home.join("state/verify/r/fast/w");
        std::fs::create_dir_all(root.join("src")).unwrap();
        let xdg = home.join("xdg");
        std::fs::create_dir_all(xdg.join("uv")).unwrap();
        let env = JobEnv::from_vars([
            ("HOME", home.as_os_str()),
            ("CARGO_HOME", home.join(".cargo").as_os_str()),
            ("XDG_CONFIG_HOME", xdg.as_os_str()),
        ]);
        let run = |approved: &BTreeMap<String, String>| {
            ToolProbe::new(
                &root,
                &[entry("src/lib.rs")],
                &BTreeMap::new(),
                [],
                &env,
                approved,
            )
            .findings()
        };
        assert_eq!(run(&BTreeMap::new()), Vec::<String>::new());
        let text = "[install]\nregistry = \"https://registry.example\"\n";
        std::fs::write(home.join(".bunfig.toml"), text).unwrap();
        std::fs::write(xdg.join(".bunfig.toml"), text).unwrap();
        std::fs::write(
            xdg.join("uv/uv.toml"),
            "index-url = \"https://index.example\"\n",
        )
        .unwrap();
        let found = run(&BTreeMap::new());
        assert_eq!(found.len(), 3, "{found:?}");
        assert!(
            found
                .iter()
                .all(|f| f.contains("host tool config is not approved"))
        );
        let ok = approve(&[("~/.bunfig.toml", text), ("~/xdg/.bunfig.toml", text)]);
        let found = run(&ok);
        assert!(
            found.len() == 1
                && found[0].contains("xdg/uv/uv.toml: host tool config is not approved"),
            "{found:?}"
        );
    }

    /// Review note 12: only the host config's own path is exempt above the
    /// checkout, not another `.cargo` that links to the host's dir (cargo
    /// reads it as one more ancestor config).
    #[test]
    fn an_ancestor_link_to_the_host_cargo_dir_counts() {
        let t = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(t.path()).unwrap().join("home");
        let root = home.join("state/verify/r/fast/w");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(home.join(".cargo")).unwrap();
        std::fs::write(home.join(".cargo/config.toml"), "[alias]\n").unwrap();
        std::os::unix::fs::symlink(home.join(".cargo"), home.join("state/.cargo")).unwrap();
        let env = JobEnv::from_vars([
            ("HOME", home.as_os_str()),
            ("CARGO_HOME", home.join(".cargo").as_os_str()),
        ]);
        let probe = ToolProbe::new(
            &root,
            &[entry("src/lib.rs")],
            &BTreeMap::new(),
            [],
            &env,
            &BTreeMap::new(),
        );
        let found = probe.findings();
        assert!(
            found
                .iter()
                .any(|f| f.ends_with("state/.cargo/config.toml: a tool config above the checkout")),
            "{found:?}"
        );
    }

    /// A step cwd through a tree link to a tree dir is that dir; through a
    /// link to anything else it is a finding, and so is a `.cargo` link a
    /// step leaves in a tree dir, dangling or not.
    #[test]
    fn cwd_links_and_step_links() {
        let t = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(t.path()).unwrap().join("co");
        std::fs::create_dir_all(root.join("real/app")).unwrap();
        std::fs::write(root.join("real/clippy.toml"), "\n").unwrap();
        std::os::unix::fs::symlink("real", root.join("lnk")).unwrap();
        let mut link = entry("lnk");
        link.mode = "120000".into();
        let tree = [entry("real/app/main.rs"), entry("real/clippy.toml"), link];
        let env = JobEnv::from_vars([("HOME", "/nonexistent")]);
        let probe = ToolProbe::new(
            &root,
            &tree,
            &BTreeMap::new(),
            ["lnk/app", "./real"],
            &env,
            &BTreeMap::new(),
        );
        assert_eq!(probe.findings(), Vec::<String>::new());
        std::fs::remove_file(root.join("lnk")).unwrap();
        std::fs::create_dir_all(t.path().join("out/app")).unwrap();
        std::fs::write(t.path().join("out/app/rustfmt.toml"), "\n").unwrap();
        std::os::unix::fs::symlink(t.path().join("out"), root.join("lnk")).unwrap();
        let found = probe.findings();
        assert!(
            found
                .iter()
                .any(|f| f.starts_with("lnk/app: a step cwd that resolves to"))
                && found.iter().any(|f| f.starts_with("lnk links to")),
            "{found:?}"
        );
        std::fs::remove_file(root.join("lnk")).unwrap();
        std::os::unix::fs::symlink("real", root.join("lnk")).unwrap();
        std::os::unix::fs::symlink("nowhere", root.join("real/app/.cargo")).unwrap();
        assert_eq!(
            probe.findings(),
            ["real/app/.cargo: a tool config that is not in the tree"]
        );
    }

    /// Process CPU time (user + system), which load does not move much.
    fn cpu_time() -> std::time::Duration {
        let mut ru = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        // SAFETY: getrusage fills the struct it is given.
        let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, ru.as_mut_ptr()) };
        assert_eq!(rc, 0, "getrusage: {}", io::Error::last_os_error());
        // SAFETY: getrusage returned 0, so the struct is filled.
        let ru = unsafe { ru.assume_init() };
        let tv = |t: libc::timeval| {
            std::time::Duration::from_secs(u64::try_from(t.tv_sec).unwrap_or(0))
                + std::time::Duration::from_micros(u64::try_from(t.tv_usec).unwrap_or(0))
        };
        tv(ru.ru_utime) + tv(ru.ru_stime)
    }

    /// Job overhead after each step, not the hook path. A tree the size of
    /// webapp's (222 dirs, 1958 files on 2026-11-09) costs about 1500
    /// `lstat` calls per run: 9 ms wall at load 31 on the dev host, the same
    /// as a Python loop over the same calls (it is all syscalls). The CPU
    /// bound only catches a walk coming back.
    #[test]
    fn a_probe_run_on_a_webapp_sized_tree_is_cheap() {
        let t = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(t.path()).unwrap();
        let mut entries = Vec::new();
        for d in 0..222 {
            let dir = format!("d{}/e{d}", d % 20);
            std::fs::create_dir_all(root.join(&dir)).unwrap();
            for f in 0..9 {
                entries.push(entry(&format!("{dir}/f{f}.rs")));
            }
        }
        let env = JobEnv::from_vars([("HOME", "/nonexistent")]);
        let probe = ToolProbe::new(
            &root,
            &entries,
            &BTreeMap::new(),
            ["d1/e1"],
            &env,
            &BTreeMap::new(),
        );
        assert!(probe.dir_count() > 222, "{}", probe.dir_count());
        let runs = 20;
        let (wall, cpu) = (std::time::Instant::now(), cpu_time());
        for _ in 0..runs {
            assert_eq!(probe.findings(), Vec::<String>::new());
        }
        let (wall, cpu) = (wall.elapsed() / runs, (cpu_time() - cpu) / runs);
        eprintln!(
            "probe: {} dirs, per run {cpu:?} CPU, {wall:?} wall",
            probe.dir_count()
        );
        assert!(cpu < std::time::Duration::from_millis(50), "{cpu:?}");
    }
}
